//! Audit-consensus hardening tests (2026-10-14 report) for `src/consensus.rs`.
//!
//! NEW file — shared test files are never edited per mission rules. Each test
//! pins one finding's fix (or fail-closed behavior) in the consensus domain:
//! lock paths (F7 newest-wins), schedule ordering (F8), quorum curve (F4),
//! hash-slot edge cases, QC assemble/verify power parity, round-sync caps,
//! the deadlock-reset QC gate (F3), and µQC envelope decode (F9).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{
    decode_pq_micro_envelope, derive_sortition_committee, encode_pq_micro_envelope,
    pq_micro_quorum_power, register_validator_pq_key, HeightConsensus, PqMicroCertificate,
    QuorumCertificate, ValidatorSet, Vote, VoteKind, MAX_COMMIT_CERT_SIGNERS, ROUND_LOOKBACK,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};

// --- fixtures ----------------------------------------------------------------

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset1(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

const A_BLK: [u8; 32] = [42u8; 32];
const B_BLK: [u8; 32] = [43u8; 32];
const H: u64 = 92079;

// --- F7: polka unlock is newest-wins ------------------------------------------

fn falcon_for_keys(tag: u8) -> Vec<FalconKeypair> {
    (0..4)
        .map(|i| FalconKeypair::generate_from_seed(tag.wrapping_add(i as u8)))
        .collect()
}

fn fvote(
    sk: &SigningKey,
    fk: &FalconKeypair,
    height: u64,
    round: u32,
    kind: VoteKind,
    bh: Option<[u8; 32]>,
) -> Vote {
    Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
}

/// PQ twin of `hc_locked_4`: same powers/topology, Falcon-registered set.
/// Returns (hc, ks, fks).
fn hc_locked_4_pq(
    a: [u8; 32],
    locked_round: u32,
    at_round: u32,
    tag: u8,
) -> (HeightConsensus, Vec<SigningKey>, Vec<FalconKeypair>) {
    let ks = keys(4);
    let vs = vset1(&ks);
    let fks = falcon_for_keys(tag);
    for (sk, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            sk.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
    }
    let mut hc = HeightConsensus::new(H, vs);
    hc.locked = Some((a, locked_round));
    hc.round = at_round;
    (hc, ks, fks)
}

/// Quorum (3/4) of prevotes for `target` at `round` (Falcon-signed).
fn polka(
    hc: &mut HeightConsensus,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    round: u32,
    target: Option<[u8; 32]>,
) {
    for (k, fk) in ks.iter().zip(fks.iter()).take(3) {
        hc.add_prevote(fvote(k, fk, H, round, VoteKind::Prevote, target))
            .unwrap();
    }
}

#[test]
fn f7_older_conflict_does_not_unlock_past_newer_confirmation() {
    // Lock A@5. Older polka B@6 (conflicting) + newer polka A@7 (confirming).
    // Old code unlocked on round 6 while scanning; newest-wins keeps the lock.
    let (mut hc, ks, fks) = hc_locked_4_pq(A_BLK, 5, 7, 0x70);
    polka(&mut hc, &ks, &fks, 6, Some(B_BLK));
    polka(&mut hc, &ks, &fks, 7, Some(A_BLK));
    let found = hc.try_prevote_quorum_at();
    assert_eq!(found, Some((7, Some(A_BLK))), "newest polka wins");
    assert_eq!(
        hc.locked,
        Some((A_BLK, 5)),
        "F7: older conflicting polka must not unlock past a newer confirmation"
    );
}

#[test]
fn f7_newer_conflicting_polka_still_unlocks() {
    // Lock A@5, only polka is B@7 → unlock (liveness escape preserved).
    let (mut hc, ks, fks) = hc_locked_4_pq(A_BLK, 5, 7, 0x71);
    polka(&mut hc, &ks, &fks, 7, Some(B_BLK));
    let found = hc.try_prevote_quorum_at();
    assert_eq!(found, Some((7, Some(B_BLK))));
    assert_eq!(hc.locked, None, "newest conflicting polka must unlock");
}

#[test]
fn f7_newer_nil_polka_never_unlocks() {
    // F-01 FIX: Nil polka forms on timeouts and must NEVER unlock a locked block
    // (otherwise honest nodes drop locks and finalize conflicting blocks).
    let (mut hc, ks, fks) = hc_locked_4_pq(A_BLK, 5, 7, 0x72);
    polka(&mut hc, &ks, &fks, 7, None);
    hc.try_prevote_quorum_at();
    assert_eq!(
        hc.locked,
        Some((A_BLK, 5)),
        "nil polka must NEVER unlock (BFT safety)"
    );
}

#[test]
fn f02_forged_single_validator_committee_size_rejected() {
    // F-02: A certificate claiming committee_size = 1 on a 4-validator network
    // must be rejected outright, preventing 1-validator forgery attacks.
    let ks = keys(4);
    let vs = vset1(&ks);
    let bh = Some([0xAA; 32]);
    let mut qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: bh,
        signatures: vec![],
    };
    let uqc = stellereum::consensus::PqMicroCertificate {
        scheme: stellereum::post_quantum::PqScheme::Falcon512,
        height: 1,
        round: 0,
        committee_size: 1, // FORGED committee size! Real size must be 4.min(16) = 4.
        signers_bitmask: vec![1],
        signatures: vec![vec![0x77; 666]],
        sortition_parent: [0u8; 32],
    };
    qc.attach_pq_micro_certificate(&uqc);
    assert!(
        !qc.verify(&vs),
        "forged committee_size = 1 on 4-validator set must be rejected"
    );
}

#[test]
fn f7_same_round_polka_never_unlocks() {
    // Polka at exactly the locked round for another value: `round >
    // locked_round` is false → lock stays (unchanged semantics).
    let (mut hc, ks, fks) = hc_locked_4_pq(A_BLK, 5, 5, 0x73);
    polka(&mut hc, &ks, &fks, 5, Some(B_BLK));
    hc.try_prevote_quorum_at();
    assert_eq!(hc.locked, Some((A_BLK, 5)));
}

// --- F8: explicit canonical ordering ------------------------------------------

#[test]
fn f8_proposer_schedule_identical_across_insertion_orders() {
    // Same members, different insertion orders → identical schedule everywhere.
    let ks = keys(4);
    let mut fwd = ValidatorSet::new();
    for k in &ks {
        fwd.add(id(k), 1 + (id(k)[0] % 3) as u64);
    }
    let mut rev = ValidatorSet::new();
    for k in ks.iter().rev() {
        rev.add(id(k), 1 + (id(k)[0] % 3) as u64);
    }
    for h in [1u64, 7, 95154] {
        for r in [0u32, 1, 5, 100] {
            assert_eq!(
                fwd.proposer_for(h, r),
                rev.proposer_for(h, r),
                "schedule must not depend on insertion order (h={h} r={r})"
            );
        }
    }
}

#[test]
fn f8_btreemap_iteration_is_sorted_canonical_order() {
    // The invariant the explicit sorts rely on: BTreeMap iteration IS sorted.
    let ks = keys(5);
    let vs = vset1(&ks);
    let iterated: Vec<[u8; 32]> = vs.validators.keys().copied().collect();
    let mut sorted = iterated.clone();
    sorted.sort_unstable();
    assert_eq!(
        iterated, sorted,
        "BTreeMap iteration must be canonical sorted order"
    );
}

// --- F4: quorum curve ----------------------------------------------------------

#[test]
fn f4_quorum_curve_pins_live_powers_and_fail_closed_empty() {
    // Live powers from the code comment: 1874531430003 / 2e12 / 2e12.
    let total = 1874531430003u64 + 2_000_000_000_000 + 2_000_000_000_000;
    assert_eq!(total, 5874531430003);
    assert_eq!(
        stellereum::consensus::consensus_quorum_min(total),
        3916354286669
    );
    // A+B alone cannot reach classical quorum (short by ~42e9).
    let a_plus_b = 1874531430003u64 + 2_000_000_000_000;
    assert!(
        a_plus_b < 3916354286669,
        "A+B must be below quorum (F4 arithmetic)"
    );
    // Empty / zero-power sets never reach quorum.
    assert_eq!(ValidatorSet::new().quorum_power(), u64::MAX);
    let mut zero = ValidatorSet::new();
    zero.add([9u8; 32], 0);
    assert!(zero.is_empty(), "zero power must be filtered at add");
    assert_eq!(zero.quorum_power(), u64::MAX);
    assert_eq!(pq_micro_quorum_power(0), u64::MAX);
}

// --- Hash-slot edge cases -------------------------------------------------------

#[test]
fn hash_slot_empty_set_returns_none() {
    assert_eq!(ValidatorSet::new().proposer_for(1, 0), None);
}

#[test]
fn hash_slot_single_validator_always_itself() {
    let ks = keys(1);
    let mut vs = ValidatorSet::new();
    vs.add(id(&ks[0]), 5_000_000_000_000);
    for h in [1u64, 2, 95154, 10_000_000] {
        for r in [0u32, 1, 33] {
            assert_eq!(vs.proposer_for(h, r), Some(id(&ks[0])));
        }
    }
}

#[test]
fn hash_slot_zero_power_members_never_propose() {
    let ks = keys(3);
    let mut vs = ValidatorSet::new();
    vs.add(id(&ks[0]), 100);
    vs.add(id(&ks[1]), 100);
    vs.add(id(&ks[2]), 0); // filtered at add
    assert_eq!(vs.len(), 2);
    for r in 0..64u32 {
        let p = vs.proposer_for(1, r).unwrap();
        assert_ne!(p, id(&ks[2]), "zero-power member must never own a slot");
    }
}

#[test]
fn hash_slot_deterministic_across_instances() {
    // Two independently built sets with the same members agree on every slot.
    let ks = keys(3);
    let mk = || {
        let mut vs = ValidatorSet::new();
        vs.add(id(&ks[0]), 1874531430003);
        vs.add(id(&ks[1]), 2_000_000_000_000);
        vs.add(id(&ks[2]), 2_000_000_000_000);
        vs
    };
    let (a, b) = (mk(), mk());
    for h in [1u64, 95154] {
        for r in 0..32u32 {
            assert_eq!(a.proposer_for(h, r), b.proposer_for(h, r));
        }
    }
}

#[test]
fn hash_slot_small_stake_member_not_starved() {
    // 1%-power stakeholder over 5000 draws: mean 50, sd ~7. Bounds 15..95 are
    // ~5 sigma — a fail means the schedule is broken, not bad luck.
    // (Audit: P(no slot in 100 rounds) = 36.6% is NORMAL — this test asserts
    // the long-run rate, never short-window presence.)
    let ks = keys(2);
    let (mine, theirs) = (id(&ks[0]), id(&ks[1]));
    let vs = ValidatorSet::from_list(vec![(mine, 1), (theirs, 99)]);
    let mut owned = 0usize;
    for i in 0..5000u64 {
        if vs.proposer_for(i, (i % 7) as u32) == Some(mine) {
            owned += 1;
        }
    }
    assert!(
        (15..=95).contains(&owned),
        "1% member must hold ~50/5000 slots, got {owned}"
    );
}

// --- QC assemble/verify power parity -------------------------------------------

fn skewed_falcon_set() -> (ValidatorSet, Vec<SigningKey>, Vec<FalconKeypair>) {
    let powers = [2000u64, 2000, 1000];
    let mut vs = ValidatorSet::new();
    let mut sks = Vec::new();
    let mut fks = Vec::new();
    for (i, p) in powers.iter().enumerate() {
        let sk = SigningKey::generate(&mut OsRng);
        let fk = FalconKeypair::generate_from_seed(0xA0 + i as u8);
        let ident = sk.verifying_key().to_bytes();
        vs.add(ident, *p);
        register_validator_pq_key(ident, PqScheme::Falcon512, fk.public_key().to_vec());
        sks.push(sk);
        fks.push(fk);
    }
    (vs, sks, fks)
}

#[test]
fn qc_power_parity_two_heavy_assembles_and_verifies() {
    // Assembler and verifier apply the SAME power rule: 2 heavy Falcon votes
    // (4000 ≥ 3334) compile a µQC that verifies — the fragile-unanimous fix.
    const HH: u64 = 12;
    const RR: u32 = 0;
    let (vs, sks, fks) = skewed_falcon_set();
    let target = Some([0xCDu8; 32]);
    let mut set = stellereum::consensus::VoteSet::new();
    for i in 0..2 {
        set.add(
            Vote::sign_with_falcon(&sks[i], &fks[i], HH, RR, VoteKind::Precommit, target),
            &vs,
            HH,
            RR,
            VoteKind::Precommit,
        )
        .unwrap();
    }
    let parent = [0x6Bu8; 32];
    let qc = set
        .certificate(target, &vs, &parent)
        .expect("4000 ≥ 3334 must form");
    assert!(qc.verify(&vs), "assembled power-QC must verify (parity)");
    let uqc = qc
        .pq_micro_certificate()
        .expect("µQC must compile from 2 heavy");
    let committee = derive_sortition_committee(&vs, HH, RR, uqc.committee_size, &parent);
    assert_eq!(uqc.signed_power(&committee, &vs), 4000);
}

#[test]
fn qc_power_parity_single_heavy_neither_assembles_nor_verifies() {
    // Below-quorum power fails on BOTH sides: no µQC attached, and a
    // hand-built 1-signer envelope does not verify.
    const HH: u64 = 13;
    const RR: u32 = 0;
    let (vs, sks, fks) = skewed_falcon_set();
    let target = Some([0xCEu8; 32]);
    let mut set = stellereum::consensus::VoteSet::new();
    set.add(
        Vote::sign_with_falcon(&sks[0], &fks[0], HH, RR, VoteKind::Precommit, target),
        &vs,
        HH,
        RR,
        VoteKind::Precommit,
    )
    .unwrap();
    assert!(
        set.certificate(target, &vs, &[0x6Bu8; 32]).is_none(),
        "2000 < 3334 must not form"
    );
    // Hand-built envelope with a single heavy signer still fails verification.
    let committee = derive_sortition_committee(&vs, HH, RR, 3, &[0x6Bu8; 32]);
    assert_eq!(committee.len(), 3);
    let heavy_idx = committee.iter().position(|x| *x == id(&sks[0])).unwrap();
    let mut bitmask = vec![0u8; 1];
    bitmask[heavy_idx / 8] |= 1 << (heavy_idx % 8);
    let msg = stellereum::consensus::vote_sign_bytes(HH, RR, VoteKind::Precommit, &target);
    let lone = PqMicroCertificate {
        scheme: PqScheme::Falcon512,
        height: HH,
        round: RR,
        committee_size: 3,
        signers_bitmask: bitmask,
        signatures: vec![fks[0].sign(&msg)],
        sortition_parent: [0x6Bu8; 32],
    };
    let mut qc = stellereum::consensus::QuorumCertificate {
        height: HH,
        round: RR,
        kind: VoteKind::Precommit,
        block_hash: target,
        signatures: vec![(sks[1].verifying_key().to_bytes(), vec![0u8; 64])],
    };
    qc.attach_pq_micro_certificate(&lone);
    assert!(!qc.verify(&vs), "single-heavy µQC must not verify (parity)");
}

// --- Round-sync caps ------------------------------------------------------------

#[test]
fn round_sync_single_jump_capped_at_lookback() {
    let ks = keys(2);
    let mut hc = HeightConsensus::new(H, vset1(&ks));
    hc.sync_round_to(1000);
    assert_eq!(hc.round, ROUND_LOOKBACK, "one sync may move at most +8");
}

#[test]
fn round_advance_single_message_moves_at_most_one() {
    let ks = keys(2);
    let mut hc = HeightConsensus::new(H, vset1(&ks));
    hc.advance_to_round(500);
    assert_eq!(hc.round, 1, "one message moves at most one round");
}

#[test]
fn far_ahead_votes_rejected_from_voteset() {
    let ks = keys(2);
    let mut hc = HeightConsensus::new(H, vset1(&ks));
    let bad = Vote::sign(&ks[0], H, 1001, VoteKind::Prevote, Some(A_BLK));
    assert!(
        hc.add_prevote(bad).is_err(),
        "round > +1000 must be dropped"
    );
    let bad_c = Vote::sign(&ks[0], H, 1001, VoteKind::Precommit, Some(A_BLK));
    assert!(hc.add_precommit(bad_c).is_err());
}

// --- F3 reset gate ---------------------------------------------------------------

#[test]
fn f3_nil_precommit_quorum_is_not_qc_observed() {
    // A nil quorum proves nothing certifiable: the gate passes and a bodyless
    // lock still drops (liveness preserved where no fork is possible).
    let ks = keys(4);
    let fks = falcon_for_keys(0x74);
    let mut hc = HeightConsensus::new(H, vset1(&ks));
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
    }
    hc.round = 412;
    hc.locked = Some((A_BLK, 400));
    for (k, fk) in ks.iter().zip(fks.iter()).take(3) {
        hc.add_precommit(fvote(k, fk, H, 412, VoteKind::Precommit, None))
            .unwrap();
    }
    assert!(
        !hc.precommit_qc_observed(),
        "nil quorum must not count as an observed precommit QC"
    );
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(hc.locked, None);
    // The re-phase NEVER rewinds the round: re-entering a round this node
    // already voted in at this height is a self-equivocation (slashable).
    // It advances instead, and widens the quorum-scan window so the round
    // the network is actually in becomes committable.
    assert_eq!(
        hc.round, 413,
        "the re-phase must move FORWARD, never rewind"
    );
    assert_eq!(
        hc.scan_lookback,
        stellereum::consensus::REPHASE_SCAN_WINDOW,
        "the re-phase must widen the quorum-scan window"
    );
}

#[test]
fn f3_banked_qc_survives_vote_set_pruning() {
    // The banked-QC half of the gate: after deciding (QC banked), even if the
    // vote sets are pruned away, the lock survives the reset.
    let ks = keys(4);
    let fks = falcon_for_keys(0x75);
    let mut hc = HeightConsensus::new(H, vset1(&ks));
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
    }
    hc.round = 5; // decide AT round 5 (the lookback scan only inspects ≤ round)
    for (k, fk) in ks.iter().zip(fks.iter()).take(3) {
        hc.add_prevote(fvote(k, fk, H, 5, VoteKind::Prevote, Some(A_BLK)))
            .unwrap();
        hc.add_precommit(fvote(k, fk, H, 5, VoteKind::Precommit, Some(A_BLK)))
            .unwrap();
    }
    assert_eq!(hc.try_precommit_quorum(), Some(A_BLK));
    hc.round = 412; // stall far above the decided round
    assert!(hc.precommit_qc_observed());
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(hc.locked, Some((A_BLK, 5)), "banked-QC lock must survive");
    assert_eq!(hc.decided, Some(A_BLK), "reset never clears decided");
}

// --- F9: envelope decode fail-closed ----------------------------------------------

#[test]
fn f9_decode_rejects_malformed_envelopes() {
    assert!(decode_pq_micro_envelope(&[]).is_none());
    assert!(decode_pq_micro_envelope(&[0u8; 40]).is_none());
    assert!(
        decode_pq_micro_envelope(&[0xFFu8; 64]).is_none(),
        "bad magic"
    );
    // Truncated canonical header.
    let cert = PqMicroCertificate {
        scheme: PqScheme::Falcon512,
        height: 1,
        round: 0,
        committee_size: 3,
        signers_bitmask: vec![0b101],
        signatures: vec![vec![1u8; 8], vec![2u8; 8]],
        sortition_parent: [0x6Bu8; 32],
    };
    let good = encode_pq_micro_envelope(&cert);
    assert!(
        decode_pq_micro_envelope(&good).is_some(),
        "canonical must decode"
    );
    assert!(
        decode_pq_micro_envelope(&good[..good.len() - 3]).is_none(),
        "truncated must not"
    );
    // Bloated signer list.
    let mut evil = cert.clone();
    evil.signatures = vec![vec![0u8; 1]; MAX_COMMIT_CERT_SIGNERS + 1];
    assert!(
        decode_pq_micro_envelope(&encode_pq_micro_envelope(&evil)).is_none(),
        "over-cap signer list must be refused at decode"
    );
}
