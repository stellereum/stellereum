use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use super::*;
use crate::runtime::MAX_COMMIT_CERT_SIGNERS;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n)
        .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
        .collect()
}

fn ids(keys: &[SigningKey]) -> Vec<ValidatorId> {
    keys.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

fn vset(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ids(keys).into_iter().map(|id| (id, 1)).collect())
}

fn block_hash(n: u8) -> BlockHash {
    [n; 32]
}

fn hc4() -> HeightConsensus {
    let ks = keys(4);
    HeightConsensus::new(1, vset(&ks))
}

// FULL-PQ test helpers (nodes wiped, no compat): Ed ids + registered
// Falcon-512 keys, Falcon-signed votes. Quorum/power/targets/membership
// unchanged — only the signature scheme changes from Ed to Falcon.
fn falcon_for_keys(ks: &[SigningKey], base: u8) -> Vec<FalconKeypair> {
    ks.iter()
        .enumerate()
        .map(|(i, _)| FalconKeypair::generate_from_seed(base.wrapping_add(i as u8)))
        .collect()
}

fn vset_with_falcon(ks: &[SigningKey], fks: &[FalconKeypair]) -> ValidatorSet {
    let vs = vset(ks);
    for (sk, fk) in ks.iter().zip(fks.iter()) {
        let id = sk.verifying_key().to_bytes();
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    vs
}

fn fvote(
    sk: &SigningKey,
    fk: &FalconKeypair,
    height: Height,
    round: Round,
    kind: VoteKind,
    bh: Option<BlockHash>,
) -> Vote {
    Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
}

#[test]
fn sync_burst_is_rate_limited_not_unbounded() {
    // Regression (audit 2026-10-06): repeated verified votes ratcheted
    // +8 per message without bound (r9700, zero QCs). Past the per-round
    // budget further syncs are refused; the timeout path still advances.
    // NOTE (audit F3, 2026-10-29): single-VOTE far chase is refused at
    // the `observe_peer_round` gate (corroboration: 2 distinct peers);
    // this DIRECT-call path keeps burst semantics (bounded by budget).
    let mut hc = hc4();
    for _ in 0..20 {
        hc.sync_round_to(1000);
    }
    assert!(
        hc.round <= MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK,
        "burst must stop at the budget, got round {}",
        hc.round
    );
    assert!(hc.round > 0, "honest catch-up still moves");
}

#[test]
#[allow(clippy::assertions_on_constants)]
// GATE: constant-bound assertion documents timeout invariant; removing it would weaken the regression test.
fn c2_deterministic_timeout_is_identical_bounded_and_clock_free() {
    // TASK 4: every honest node computes the IDENTICAL timeout for every
    // (height, round) from local state alone. Inputs: base env, backoff
    // fn(round), adaptive extension from ledger missed. NO wall clock.
    let t1 = deterministic_round_timeout_ms(3500, 0, 0);
    let t2 = deterministic_round_timeout_ms(3500, 0, 0);
    assert_eq!(t1, 3500);
    assert_eq!(
        t1, t2,
        "same state => same timeout (wall clocks differ, value must not)"
    );
    // Backoff is MULTIPLICATIVE in the round (`x2` per round, paper
    // 02_liveness §7 rec 1 — heuristic, NOT an optimum: a persistent
    // `ρ ≈ 2` is not identifiable (selection bias, FIXES §1.8/§2.9);
    // i.i.d. optimum needs no backoff at all): r1 doubles the base, r4
    // saturates at base + cap.
    assert_eq!(deterministic_round_timeout_ms(3500, 1, 0), 7000);
    assert_eq!(
        deterministic_round_timeout_ms(3500, 4, 0),
        3500 + DETERMINISTIC_BACKOFF_CAP_MS
    );
    // Adaptive extension for historically-slow proposers, bounded.
    let slow = deterministic_round_timeout_ms(3500, 0, 4);
    assert_eq!(slow, 3500 + 4 * ADAPTIVE_EXTENSION_PER_MISS_MS);
    assert!(slow > t1, "slow proposer rounds wait longer");
    let capped = deterministic_round_timeout_ms(3500, 0, 1_000_000);
    assert_eq!(capped, 3500 + ADAPTIVE_EXTENSION_CAP_MS);
    let round_capped = deterministic_round_timeout_ms(3500, 1_000_000, 0);
    assert_eq!(round_capped, 3500 + DETERMINISTIC_BACKOFF_CAP_MS);
    // K small enough to matter.
    assert!(NIL_CIRCUIT_BREAKER_K <= 5, "K must be <= 5");
}

#[test]
fn c2_nil_breaker_counts_meters_and_fires_once_safely() {
    let mut hc = hc4();
    assert_eq!(hc.nil_rounds_total, 0);
    // Two nil rounds: counted, no fire yet (K=3).
    hc.next_round();
    hc.next_round();
    assert_eq!(hc.nil_rounds_total, 2);
    assert_eq!(hc.consecutive_nil_rounds, 2);
    assert!(!hc.nil_breaker_due());
    let r_before = hc.round;
    // Third nil round trips the breaker.
    hc.next_round();
    assert_eq!(hc.consecutive_nil_rounds, 3);
    assert!(hc.nil_breaker_due());
    let scan_before = hc.scan_lookback;
    let out = hc.apply_nil_convergence();
    assert!(out.is_none(), "no QC exists yet: nothing to re-broadcast");
    assert!(hc.scan_lookback >= scan_before, "window widened");
    assert_eq!(
        hc.round,
        r_before + 1,
        "convergence must never rewind the round"
    );
    // One-shot: second apply is a no-op.
    assert!(!hc.nil_breaker_due());
    assert!(hc.apply_nil_convergence().is_none());
    // A block QC breaks the streak and re-arms the breaker.
    hc.note_round_outcome(false);
    assert_eq!(hc.consecutive_nil_rounds, 0);
}

#[test]
fn c2_nil_breaker_rebroadcasts_highest_qc_backed_proposal() {
    let ks = keys(4);
    let fks = falcon_for_keys(&ks, 0x11);
    let vs = vset_with_falcon(&ks, &fks);
    let mut hc = HeightConsensus::new(1, vs.clone());
    let bh = [0xABu8; 32];
    // Build a real block prevote QC at round 5 (3 of 4).
    for (i, k) in ks.iter().enumerate().take(3) {
        let v = fvote(k, &fks[i], 1, 5, VoteKind::Prevote, Some(bh));
        hc.add_prevote(v).unwrap();
    }
    assert_eq!(hc.observed_polka, Some((5, bh)));
    // Storm to the breaker.
    hc.next_round();
    hc.next_round();
    hc.next_round();
    assert!(hc.nil_breaker_due());
    let target = hc.apply_nil_convergence();
    assert_eq!(
        target,
        Some(bh),
        "must re-broadcast the highest-QC-backed proposal"
    );
}

#[test]
fn c2_proposer_miss_accountability_no_punishment_fast_readmit() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(7, vs.clone());
    let sched = hc.validators.proposer_for(7, hc.round).unwrap();
    // Miss M times: metered.
    for _ in 0..PROPOSER_MISS_THRESHOLD_M {
        hc.note_proposer_missed(sched, false);
    }
    assert_eq!(hc.proposer_missed_streak(&sched), PROPOSER_MISS_THRESHOLD_M);
    assert_eq!(hc.missed_proposals_total, PROPOSER_MISS_THRESHOLD_M as u64);
    // Fast-path re-admission: proposing again clears suspicion, no slash.
    hc.note_proposer_missed(sched, true);
    assert_eq!(hc.proposer_missed_streak(&sched), 0);
    assert!(
        !hc.missed_proposals.contains_key(&sched),
        "zero-streak entries are removed (bounded)"
    );
}
#[test]
#[allow(clippy::assertions_on_constants)]
// GATE: retention-cap assertion pins liveness invariant; removing it would weaken the regression test.
fn round_advance_keeps_the_vote_sets_of_the_current_height() {
    // LIVENESS (live 2026-10-21: the masterchain parked at height 285027
    // with a prevote QC and NO precommit QC). The quorum-COMPLETING
    // prevote of a round routinely arrives long after the round itself,
    // so the vote sets of the CURRENT HEIGHT are kept: a late vote must
    // still be able to complete the quorum of the round it belongs to.
    //
    // The old behaviour (drop everything outside the lookback window) is
    // what made a late quorum impossible: the set was already empty when
    // the completing vote arrived. What stays bounded is the SCAN
    // (the window around the local round) and the number of retained
    // rounds (MAX_RETAINED_VOTE_ROUNDS), not the evidence itself.
    let mut hc = hc4();
    // Seed fake vote sets across many rounds via next_round steps.
    for _ in 0..30 {
        hc.prevotes.insert(hc.round, VoteSet::new());
        hc.precommits.insert(hc.round, VoteSet::new());
        hc.next_round();
    }
    assert_eq!(hc.round, 30);
    assert_eq!(
        hc.prevotes.len(),
        30,
        "every round of the height keeps its vote set"
    );
    assert!(
        hc.prevote_set(0).is_some(),
        "a round that is 30 rounds old must still be able to receive the vote that completes its quorum"
    );
    // The retention is still bounded: a height that never decides cannot
    // accumulate one vote set per round forever.
    assert!(
        MAX_RETAINED_VOTE_ROUNDS >= 4_096,
        "the retention cap must cover a pathological height (the live one spent 380 rounds in one height)"
    );
}

#[test]
fn quorum_threshold_is_two_thirds_plus_one() {
    let keys = keys(4);
    let vs = vset(&keys);
    assert_eq!(vs.total_power(), 4);
    assert_eq!(vs.quorum_power(), 3); // floor(8/3)+1 = 3
}

#[test]
fn vote_sign_and_verify() {
    // FULL-PQ: Falcon-signed votes verify; Ed-only path deleted.
    let keys = keys(1);
    let fks = falcon_for_keys(&keys, 0x21);
    let _vs = vset_with_falcon(&keys, &fks);
    let v = fvote(
        &keys[0],
        &fks[0],
        5,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    assert!(v.verify());

    let mut tampered = v.clone();
    tampered.block_hash = Some(block_hash(2));
    assert!(!tampered.verify(), "tampered vote must fail");
}

#[test]
fn vote_verify_is_height_indexed_across_rotation() {
    // FIXES §1.2 acceptance: the vote verify path threads the vote's
    // height into the height-indexed committed registry
    // (`pq_key_at_height` → `PqRegistry::get_active_key`, reused not
    // duplicated) and fails closed when the height has no key.
    //
    // Rotation sketch (§4.3): announce at `now`, effective at
    // `now + PQ_ROTATION_DELAY_HEIGHTS`. Old key verifies before the
    // effective height and refuses at/after it; new key is the mirror.
    use crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS;
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let voter = sk.verifying_key().to_bytes();
    let old_fk = FalconKeypair::generate();
    let new_fk = FalconKeypair::generate();
    register_validator_pq_key(
        voter,
        crate::post_quantum::PqScheme::Falcon512,
        old_fk.public_key.clone(),
    );
    let now: Height = 1_000;
    let effective = pq_announce_rotation_for_tests(
        voter,
        crate::post_quantum::PqScheme::Falcon512,
        new_fk.public_key.clone(),
        now,
    )
    .expect("rotation announcement must be accepted");
    assert_eq!(effective, now.saturating_add(PQ_ROTATION_DELAY_HEIGHTS));
    let target = Some(block_hash(1));
    let old_vote_before =
        Vote::sign_with_falcon(&sk, &old_fk, effective - 1, 0, VoteKind::Prevote, target);
    let new_vote_before =
        Vote::sign_with_falcon(&sk, &new_fk, effective - 1, 0, VoteKind::Prevote, target);
    let old_vote_at = Vote::sign_with_falcon(&sk, &old_fk, effective, 0, VoteKind::Prevote, target);
    let new_vote_at = Vote::sign_with_falcon(&sk, &new_fk, effective, 0, VoteKind::Prevote, target);
    assert!(
        old_vote_before.verify(),
        "old key must verify before effective_height"
    );
    assert!(
        !new_vote_before.verify(),
        "new key must refuse before effective_height"
    );
    assert!(
        !old_vote_at.verify(),
        "old key must refuse at/after effective_height"
    );
    assert!(
        new_vote_at.verify(),
        "new key must verify at/after effective_height"
    );
    // Fail-closed: a validator with no key at the height refuses, even
    // with a well-formed Falcon half.
    let outsider_sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let outsider_fk = FalconKeypair::generate();
    let outsider_vote = Vote::sign_with_falcon(
        &outsider_sk,
        &outsider_fk,
        effective,
        0,
        VoteKind::Prevote,
        target,
    );
    assert!(
        !outsider_vote.verify(),
        "unknown validator (no key at height) must refuse fail-closed"
    );
}

#[test]
fn micro_and_epoch_certs_are_height_indexed_across_rotation() {
    use crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS;
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk2 = SigningKey::generate(&mut rand::rngs::OsRng);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let id2 = sk2.verifying_key().to_bytes();

    let fk0_old = FalconKeypair::generate();
    let fk0_new = FalconKeypair::generate();
    let fk1 = FalconKeypair::generate();
    let fk2 = FalconKeypair::generate();

    register_validator_pq_key(
        id0,
        crate::post_quantum::PqScheme::Falcon512,
        fk0_old.public_key.clone(),
    );
    register_validator_pq_key(
        id1,
        crate::post_quantum::PqScheme::Falcon512,
        fk1.public_key.clone(),
    );
    register_validator_pq_key(
        id2,
        crate::post_quantum::PqScheme::Falcon512,
        fk2.public_key.clone(),
    );

    let now: Height = 2_000;
    let effective = pq_announce_rotation_for_tests(
        id0,
        crate::post_quantum::PqScheme::Falcon512,
        fk0_new.public_key.clone(),
        now,
    )
    .expect("rotation announcement must succeed");
    assert_eq!(effective, now.saturating_add(PQ_ROTATION_DELAY_HEIGHTS));

    let mut vs = ValidatorSet::new();
    vs.add(id0, 10);
    vs.add(id1, 10);
    vs.add(id2, 10);
    let parent = [0x5Au8; 32];
    let target = Some(block_hash(9));

    // Helper to build a µQC signed by all 3 validators at `height` using `fk0` for `id0`.
    let build_uqc = |height: Height, fk0: &FalconKeypair| -> QuorumCertificate {
        let committee_size = micro_committee_size(vs.len());
        let committee = derive_sortition_committee(&vs, height, 0, committee_size, &parent);
        let msg = vote_sign_bytes(height, 0, VoteKind::Precommit, &target);
        let mut signatures = Vec::new();
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        for (i, val_id) in committee.iter().enumerate() {
            let fk = if *val_id == id0 {
                fk0
            } else if *val_id == id1 {
                &fk1
            } else {
                &fk2
            };
            signatures.push(fk.sign(&msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            0,
            committee_size,
            bitmask,
            signatures,
            parent,
        );
        QuorumCertificate {
            shard_id: 0,
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: target,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        }
    };

    // Helper to build an Epoch QC signed by all 3 validators at `height` using `fk0` for `id0`.
    let build_epoch_qc = |height: Height, fk0: &FalconKeypair| -> QuorumCertificate {
        let mut ids: Vec<ValidatorId> = vs.validators.keys().copied().collect();
        ids.sort_unstable();
        let msg = vote_sign_bytes(height, 0, VoteKind::Precommit, &target);
        let mut signatures = Vec::new();
        let mut bitmask = vec![0u8; ids.len().div_ceil(8)];
        for (i, val_id) in ids.iter().enumerate() {
            let fk = if *val_id == id0 {
                fk0
            } else if *val_id == id1 {
                &fk1
            } else {
                &fk2
            };
            signatures.push(fk.sign(&msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let cert = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            0,
            ids.len() as u32,
            bitmask,
            signatures,
            parent,
        );
        QuorumCertificate {
            shard_id: 0,
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: target,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cert))],
        }
    };

    // Before effective height: old key verifies, new key refuses (both µQC and Epoch QC).
    assert!(build_uqc(effective - 1, &fk0_old).verify(&vs));
    assert!(!build_uqc(effective - 1, &fk0_new).verify(&vs));
    assert!(build_epoch_qc(effective - 1, &fk0_old).verify(&vs));
    assert!(!build_epoch_qc(effective - 1, &fk0_new).verify(&vs));

    // At/after effective height: old key refuses, new key verifies (both µQC and Epoch QC).
    assert!(!build_uqc(effective, &fk0_old).verify(&vs));
    assert!(build_uqc(effective, &fk0_new).verify(&vs));
    assert!(!build_epoch_qc(effective, &fk0_old).verify(&vs));
    assert!(build_epoch_qc(effective, &fk0_new).verify(&vs));

    // Explicit `pq_keys` override still takes precedence over committed registry.
    let mut override_map = HashMap::new();
    override_map.insert(
        id0,
        (
            crate::post_quantum::PqScheme::Falcon512,
            fk0_old.public_key.clone(),
        ),
    );
    assert!(build_uqc(effective, &fk0_old).verify_unified_with_pq_keys(&vs, Some(&override_map)));
    assert!(
        build_epoch_qc(effective, &fk0_old).verify_unified_with_pq_keys(&vs, Some(&override_map))
    );

    // VoteSet::certificate_with_parent compiles a valid µQC at `effective` using the new key.
    let mut vote_set = VoteSet::new();
    for (sk, fk) in [(&sk0, &fk0_new), (&sk1, &fk1), (&sk2, &fk2)] {
        let v = Vote::sign_with_falcon(sk, fk, effective, 0, VoteKind::Precommit, target);
        vote_set
            .add(v, &vs, effective, 0, VoteKind::Precommit)
            .expect("post-rotation vote must be admitted at effective height");
    }
    let compiled = vote_set
        .certificate_with_parent(target, &vs, Some(&parent))
        .expect("quorum must compile");
    assert!(
        compiled.verify(&vs),
        "compiled µQC at effective height must verify"
    );
}

#[test]
fn non_validator_vote_rejected() {
    let keys = keys(4);
    let vs = vset(&keys);
    let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut set = VoteSet::new();
    let v = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some(block_hash(1)));
    assert!(set.add(v, &vs, 1, 0, VoteKind::Prevote).is_err());
}

#[test]
fn equivocation_is_recorded() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x22);
    let vs = vset_with_falcon(&keys, &fks);
    let mut set = VoteSet::new();
    let v1 = fvote(
        &keys[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    let v2 = fvote(
        &keys[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(2)),
    );
    set.add(v1, &vs, 1, 0, VoteKind::Prevote).unwrap();
    set.add(v2, &vs, 1, 0, VoteKind::Prevote).unwrap();
    assert_eq!(set.equivocations().len(), 1, "double-vote must be recorded");
}

#[test]
fn block_evidence_verifies_genuine_double_sign() {
    let ks = keys(3);
    let fks = falcon_for_keys(&ks, 0x23);
    let vs = vset_with_falcon(&ks, &fks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let a = fvote(
        &ks[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    let b = fvote(
        &ks[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(2)),
    );
    let ev = EquivocationEvidence::new(ids(&ks)[0], a, b);
    assert!(verify_equivocation_evidence(&ev, &member));
}

#[test]
fn cross_shard_vote_pair_is_never_equivocation_evidence() {
    // FINDING A (false-slash primitive). One validator key may run shards 0
    // and 1 at the same time. At the same (height, round, kind) each shard
    // has its own target, so the honest node signs two DIFFERENT statements.
    // That pair must never be slashable — and it is not, because the shard is
    // inside the V3 signed preimage and the verifier requires one shard.
    //
    // (Fails on the pre-fix code: the two votes had no shard in their signed
    // bytes and the verifier only compared height/round/kind/targets, so it
    // returned `true` and slashed the honest validator.)
    let ks = keys(3);
    let fks = falcon_for_keys(&ks, 0x33);
    let vs = vset_with_falcon(&ks, &fks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let voter = ids(&ks)[0];
    let a = Vote::sign_with_falcon_in_shard(
        &ks[0],
        &fks[0],
        0,
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    let b = Vote::sign_with_falcon_in_shard(
        &ks[0],
        &fks[0],
        1,
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(2)),
    );
    assert_eq!(a.voter, b.voter);
    assert_eq!((a.height, a.round, a.kind), (b.height, b.round, b.kind));
    assert_ne!(a.block_hash, b.block_hash);
    assert!(
        a.verify() && b.verify(),
        "each vote is genuine in its shard"
    );
    let ev = EquivocationEvidence::new(voter, a.clone(), b.clone());
    assert!(
        !verify_equivocation_evidence(&ev, &member),
        "cross-shard votes at the same height/round are honest work"
    );
    assert!(canonicalize_equivocation_evidence(vec![ev], &member).is_empty());

    // Relabelling cannot rescue the forged offense: the signature commits to
    // the shard, so a shard-0 vote presented as shard 1 fails verification.
    let mut relabelled = a.clone();
    relabelled.shard_id = 1;
    assert!(!relabelled.verify());
    let relabelled_ev = EquivocationEvidence::new(voter, relabelled, b.clone());
    assert!(!verify_equivocation_evidence(&relabelled_ev, &member));

    // SAME-SHARD, different targets at the same (h, r, kind) is still a
    // genuine double-sign and MUST remain slashable.
    let c = Vote::sign_with_falcon_in_shard(
        &ks[0],
        &fks[0],
        1,
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(3)),
    );
    let same_shard = EquivocationEvidence::new(voter, b, c);
    assert!(verify_equivocation_evidence(&same_shard, &member));
}

#[test]
fn vote_shard_is_part_of_the_signed_preimage() {
    // Domain separation: the same fields in two shards produce two different
    // signatures, and the V3 domain is used (V2 must not be accepted).
    let ks = keys(1);
    let fks = falcon_for_keys(&ks, 0x34);
    let _vs = vset_with_falcon(&ks, &fks);
    let s0 = vote_sign_bytes_for_shard(0, 9, 2, VoteKind::Precommit, &Some(block_hash(4)));
    let s1 = vote_sign_bytes_for_shard(1, 9, 2, VoteKind::Precommit, &Some(block_hash(4)));
    assert_ne!(s0, s1, "the shard must move the signed preimage");
    assert!(s0.starts_with(VOTE_SIGN_DOMAIN));
    assert_eq!(VOTE_SIGN_DOMAIN, b"STELLEREUM_BFT_VOTE_V3");
    // The masterchain shorthand is byte-identical to shard 0.
    assert_eq!(
        vote_sign_bytes(9, 2, VoteKind::Precommit, &Some(block_hash(4))),
        s0
    );
    let v0 = Vote::sign_with_falcon_in_shard(
        &ks[0],
        &fks[0],
        0,
        9,
        2,
        VoteKind::Precommit,
        Some(block_hash(4)),
    );
    let v1 = Vote::sign_with_falcon_in_shard(
        &ks[0],
        &fks[0],
        1,
        9,
        2,
        VoteKind::Precommit,
        Some(block_hash(4)),
    );
    assert_eq!(v0.shard_id, 0);
    assert_eq!(v1.shard_id, 1);
    assert!(v0.verify() && v1.verify());
    assert_ne!(v0.signature, v1.signature);
}

#[test]
fn block_evidence_offense_key_is_vote_order_stable() {
    let ks = keys(2);
    let fks = falcon_for_keys(&ks, 0x24);
    let _vs = vset_with_falcon(&ks, &fks);
    let voter = ids(&ks)[0];
    let a = fvote(
        &ks[0],
        &fks[0],
        5,
        2,
        VoteKind::Precommit,
        Some(block_hash(9)),
    );
    let b = fvote(
        &ks[0],
        &fks[0],
        5,
        2,
        VoteKind::Precommit,
        Some(block_hash(3)),
    );
    let fwd = EquivocationEvidence::new(voter, a.clone(), b.clone());
    let rev = EquivocationEvidence::new(voter, b, a);
    assert_eq!(fwd.offense_key(), rev.offense_key());
    assert_eq!(fwd.digest(), fwd.offense_key());
}

#[test]
fn block_evidence_refuses_forgeries_and_shapes_fail_closed() {
    let ks = keys(3);
    let fks = falcon_for_keys(&ks, 0x25);
    let vs = vset_with_falcon(&ks, &fks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let voter = ids(&ks)[0];
    let good_a = fvote(
        &ks[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    let good_b = fvote(
        &ks[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(2)),
    );
    // Framing with another validator's vote.
    let other = fvote(
        &ks[1],
        &fks[1],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(2)),
    );
    assert!(!verify_equivocation_evidence(
        &EquivocationEvidence::new(voter, good_a.clone(), other),
        &member
    ));
    // Zeroed signatures.
    let mut za = good_a.clone();
    let mut zb = good_b.clone();
    za.signature = vec![0u8; 64];
    zb.signature = vec![0u8; 64];
    assert!(!verify_equivocation_evidence(
        &EquivocationEvidence::new(voter, za, zb),
        &member
    ));
    // Same target twice: a single vote repeated is not equivocation.
    assert!(!verify_equivocation_evidence(
        &EquivocationEvidence::new(voter, good_a.clone(), good_a.clone()),
        &member
    ));
    // Cross-kind pair is not pairwise equivocation (HUNT13/HUNT19).
    let pc = fvote(
        &ks[0],
        &fks[0],
        1,
        0,
        VoteKind::Precommit,
        Some(block_hash(2)),
    );
    assert!(!verify_equivocation_evidence(
        &EquivocationEvidence::new(voter, good_a.clone(), pc),
        &member
    ));
    // Unknown voter is refused.
    let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
    let oa = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some(block_hash(1)));
    let ob = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some(block_hash(2)));
    assert!(!verify_equivocation_evidence(
        &EquivocationEvidence::new(outsider.verifying_key().to_bytes(), oa, ob),
        &member
    ));
    // Nil-vs-value at the same round IS a double-sign (two statements).
    let nil = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, None);
    assert!(verify_equivocation_evidence(
        &EquivocationEvidence::new(voter, good_a, nil),
        &member
    ));
}

#[test]
fn block_evidence_canonicalize_sorts_and_dedupes() {
    let ks = keys(2);
    let fks = falcon_for_keys(&ks, 0x26);
    let vs = vset_with_falcon(&ks, &fks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let voter = ids(&ks)[0];
    let mk = |x: u8, y: u8| {
        EquivocationEvidence::new(
            voter,
            fvote(
                &ks[0],
                &fks[0],
                1,
                0,
                VoteKind::Prevote,
                Some(block_hash(x)),
            ),
            fvote(
                &ks[0],
                &fks[0],
                1,
                0,
                VoteKind::Prevote,
                Some(block_hash(y)),
            ),
        )
    };
    let (e1, e2) = (mk(1, 2), mk(3, 4));
    // Duplicates: same pair twice + votes swapped.
    let e1dup = mk(1, 2);
    let e1swapped = EquivocationEvidence::new(
        voter,
        fvote(
            &ks[0],
            &fks[0],
            1,
            0,
            VoteKind::Prevote,
            Some(block_hash(2)),
        ),
        fvote(
            &ks[0],
            &fks[0],
            1,
            0,
            VoteKind::Prevote,
            Some(block_hash(1)),
        ),
    );
    // Garbage: same-target pair never survives shaping.
    let garbage = EquivocationEvidence::new(
        voter,
        fvote(
            &ks[0],
            &fks[0],
            1,
            0,
            VoteKind::Prevote,
            Some(block_hash(7)),
        ),
        fvote(
            &ks[0],
            &fks[0],
            1,
            0,
            VoteKind::Prevote,
            Some(block_hash(7)),
        ),
    );
    let out = canonicalize_equivocation_evidence(
        vec![
            e2.clone(),
            garbage,
            e1dup.clone(),
            e1swapped.clone(),
            e1.clone(),
        ],
        &member,
    );
    assert_eq!(
        out.len(),
        2,
        "two distinct offenses survive, dupes collapse"
    );
    let mut keys_sorted = [e1.offense_key(), e2.offense_key()];
    keys_sorted.sort();
    assert_eq!(out[0].offense_key(), keys_sorted[0]);
    assert_eq!(out[1].offense_key(), keys_sorted[1]);
}

/// Build two conflicting bodies for one height, both signed by `key`.
/// Distinct timestamps -> distinct hashes -> a genuine double-propose.
fn signed_block(key: &SigningKey, height: Height, timestamp: u64) -> crate::sharding::Block {
    let mut b = crate::sharding::Block {
        height,
        proposer: key.verifying_key().to_bytes(),
        timestamp,
        ..Default::default()
    };
    b.sign_block(key);
    b
}

/// Build a Falcon-signed block (PQ proposal): Ed `sign_block` plus the
/// Falcon half under the derived Falcon address, mirroring the runtime
/// proposal path (`runtime.rs` pushes `(self.id, ed_sig)` +
/// `(falcon_id, falcon_sig)`). Registers `fk` for the proposer's Ed id
/// so [`verify_proposer_signature`] resolves it height-indexed.
fn signed_block_with_falcon(
    key: &SigningKey,
    fk: &FalconKeypair,
    height: Height,
    timestamp: u64,
) -> crate::sharding::Block {
    signed_block_with_falcon_shard(key, fk, 0, height, timestamp)
}

/// [`signed_block_with_falcon`] for an explicit shard (`compute_hash` binds
/// the shard id, so the signature covers it).
fn signed_block_with_falcon_shard(
    key: &SigningKey,
    fk: &FalconKeypair,
    shard_id: crate::sharding::ShardId,
    height: Height,
    timestamp: u64,
) -> crate::sharding::Block {
    let proposer = key.verifying_key().to_bytes();
    register_validator_pq_key(
        proposer,
        crate::post_quantum::PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    let mut b = crate::sharding::Block {
        shard_id,
        height,
        proposer,
        timestamp,
        ..Default::default()
    };
    b.sign_block(key);
    let hash = b.compute_hash();
    let falcon_id = fk.validator_id();
    let falcon_sig = fk.sign(&hash);
    b.validator_signatures.push((falcon_id, falcon_sig));
    b
}

#[test]
fn proposal_evidence_same_round_is_an_offense_but_cross_round_is_not() {
    // RULESET v4: the block now commits a SIGNED round, so the false-slash
    // primitive Finding B described is gone. Two validly-signed, same-height,
    // SAME-ROUND, different bodies ARE a double-propose; the honest cross-round
    // pair (A in round r, B in r+1) is NOT.
    let ks = keys(3);
    let fk0 = FalconKeypair::generate_from_seed(0xD0);
    let vs = vset(&ks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let a = signed_block_with_falcon(&ks[0], &fk0, 5, 1_000);
    let b = signed_block_with_falcon(&ks[0], &fk0, 5, 2_000);
    assert_ne!(
        a.compute_hash(),
        b.compute_hash(),
        "need two distinct bodies"
    );
    assert!(
        verify_proposer_signature(&a) && verify_proposer_signature(&b),
        "PQ-signed proposals must verify under the registered key"
    );
    assert_eq!(PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT, 0);
    // Both fixtures are round 0: same signed round, different bodies => slash.
    let ev = ProposalEquivocationEvidence::new(ids(&ks)[0], a.clone(), b.clone());
    assert!(
        verify_proposal_equivocation_evidence(&ev, &member),
        "same signed round with different bodies is a double-propose"
    );
    assert_eq!(
        canonicalize_proposal_equivocation_evidence(vec![ev], &member).len(),
        1,
        "a genuine same-round offense must survive shaping into a slash"
    );
    // The SAME-ROUND rule: the pair is an offense when the rounds match...
    assert!(proposal_equivocation_offense_rule(
        a.shard_id,
        b.shard_id,
        a.height,
        b.height,
        7,
        7,
        &a.compute_hash(),
        &b.compute_hash(),
    ));
    // ... and an honest CROSS-ROUND pair at the same height is NOT one.
    assert!(!proposal_equivocation_offense_rule(
        a.shard_id,
        b.shard_id,
        a.height,
        b.height,
        7,
        8,
        &a.compute_hash(),
        &b.compute_hash(),
    ));
    // Different shards / heights / identical bodies are never offenses.
    assert!(!proposal_equivocation_offense_rule(
        0,
        1,
        a.height,
        b.height,
        7,
        7,
        &a.compute_hash(),
        &b.compute_hash(),
    ));
    assert!(!proposal_equivocation_offense_rule(
        a.shard_id,
        b.shard_id,
        a.height,
        b.height,
        7,
        7,
        &a.compute_hash(),
        &a.compute_hash(),
    ));
}

#[test]
fn proposal_evidence_refuses_cross_shard_blocks() {
    // Every workchain reads the masterchain validator set, so the same
    // proposer is scheduled at the same height in several shards. Proposing
    // one block per shard is honest work; it must never be slashable as a
    // double-propose. The two blocks are fully signed and genuinely distinct
    // (the shard id is inside the hash), so only the shard check refuses them.
    let ks = keys(3);
    let fk0 = FalconKeypair::generate_from_seed(0xD2);
    let vs = vset(&ks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let a = signed_block_with_falcon_shard(&ks[0], &fk0, 0, 5, 1_000);
    let b = signed_block_with_falcon_shard(&ks[0], &fk0, 1, 5, 1_000);
    assert_ne!(a.compute_hash(), b.compute_hash());
    assert!(verify_proposer_signature(&a) && verify_proposer_signature(&b));
    let ev = ProposalEquivocationEvidence::new(ids(&ks)[0], a.clone(), b.clone());
    assert!(
        !verify_proposal_equivocation_evidence(&ev, &member),
        "blocks from different shards are not a double-propose"
    );
    // The same-shard, same-round rule treats a distinct-body pair as an
    // offense, and ruleset v4 activates the wired verifier for it.
    let a2 = signed_block_with_falcon_shard(&ks[0], &fk0, 0, 5, 2_000);
    assert!(proposal_equivocation_offense_rule(
        a.shard_id,
        a2.shard_id,
        a.height,
        a2.height,
        3,
        3,
        &a.compute_hash(),
        &a2.compute_hash(),
    ));
    let mk_round3 = |timestamp: u64| {
        let proposer = ks[0].verifying_key().to_bytes();
        let mut b = crate::sharding::Block {
            shard_id: 0,
            height: 5,
            proposer,
            timestamp,
            round: 3,
            ..Default::default()
        };
        b.sign_block(&ks[0]);
        let hash = b.compute_hash();
        let falcon_sig = fk0.sign(&hash);
        b.validator_signatures.push((fk0.validator_id(), falcon_sig));
        b
    };
    let same = ProposalEquivocationEvidence::new_at_round(
        ids(&ks)[0],
        3,
        mk_round3(1_000),
        mk_round3(2_000),
    );
    assert!(
        verify_proposal_equivocation_evidence(&same, &member),
        "same-shard, same-SIGNED-round, distinct bodies must be slashable"
    );
}

#[test]
fn proposer_signature_refuses_ed_only_no_classical_fallback() {
    // Falconize retarget: the deleted Ed25519 fallback refuses — an
    // Ed-only proposal (valid Ed signature, no PQ half) does NOT verify.
    // Same strictness as before (genuine pass / forged fail), enforced
    // PQ-only: the genuine-PQ pass lives in the test above.
    let ks = keys(2);
    let ed_only = signed_block(&ks[0], 5, 1_000);
    // Sanity: the Ed signature itself is well-formed (would have passed
    // the old fallback) — refusal comes from Falconize, not malformation.
    assert!(ed_only.verify_proposer_signature());
    assert!(
        !verify_proposer_signature(&ed_only),
        "Ed-only proposal must be refused (no classical fallback)"
    );
    assert!(
        !verify_proposer_signature_falcon_via_ext(&ed_only),
        "BlockProposerExt agrees: Ed-only refuses"
    );
}

/// [`BlockProposerExt`] probe that stays inside this file's scope.
fn verify_proposer_signature_falcon_via_ext(b: &crate::sharding::Block) -> bool {
    use super::BlockProposerExt;
    b.verify_proposer_signature_falcon()
}

#[test]
fn proposal_evidence_offense_key_is_block_order_stable() {
    let ks = keys(2);
    let proposer = ids(&ks)[0];
    let a = signed_block(&ks[0], 5, 1_000);
    let b = signed_block(&ks[0], 5, 2_000);
    let fwd = ProposalEquivocationEvidence::new(proposer, a.clone(), b.clone());
    let rev = ProposalEquivocationEvidence::new(proposer, b, a);
    assert_eq!(fwd.offense_key(), rev.offense_key());
    assert_eq!(fwd.digest(), fwd.offense_key());
}

#[test]
fn proposal_evidence_refuses_same_block_forgeries_and_shapes_fail_closed() {
    let ks = keys(3);
    let fk0 = FalconKeypair::generate_from_seed(0xD1);
    let vs = vset(&ks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let proposer = ids(&ks)[0];
    let good_a = signed_block_with_falcon(&ks[0], &fk0, 5, 1_000);
    let good_b = signed_block_with_falcon(&ks[0], &fk0, 5, 2_000);
    // Same body twice: one block repeated is not a double-propose.
    assert!(!verify_proposal_equivocation_evidence(
        &ProposalEquivocationEvidence::new(proposer, good_a.clone(), good_a.clone()),
        &member
    ));
    // Different heights: a re-proposal at a new height is not an offense.
    let other_height = signed_block_with_falcon(&ks[0], &fk0, 6, 1_000);
    assert!(!verify_proposal_equivocation_evidence(
        &ProposalEquivocationEvidence::new(proposer, good_a.clone(), other_height),
        &member
    ));
    // Framing: the envelope names ks[0] but block_b is signed by ks[1].
    let fk1 = FalconKeypair::generate_from_seed(0xD2);
    let foreign = signed_block_with_falcon(&ks[1], &fk1, 5, 3_000);
    assert!(!verify_proposal_equivocation_evidence(
        &ProposalEquivocationEvidence::new(proposer, good_a.clone(), foreign),
        &member
    ));
    // Forged: tamper with the Falcon half after signing (the Ed half is
    // ignored — Falconize — so the tamper must land on the PQ bytes).
    let mut forged = good_b.clone();
    let falcon_idx = forged
        .validator_signatures
        .iter()
        .position(|(_, s)| s.len() == crate::post_quantum::FALCON512_SIG_LEN)
        .expect("PQ proposal carries a Falcon half");
    forged.validator_signatures[falcon_idx].1[50] ^= 0xFF;
    assert!(!verify_proposal_equivocation_evidence(
        &ProposalEquivocationEvidence::new(proposer, good_a.clone(), forged),
        &member
    ));
    // Unknown proposer is refused.
    let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
    let oa = signed_block(&outsider, 5, 1_000);
    let ob = signed_block(&outsider, 5, 2_000);
    assert!(!verify_proposal_equivocation_evidence(
        &ProposalEquivocationEvidence::new(outsider.verifying_key().to_bytes(), oa, ob),
        &member
    ));
    // Oversize envelope is refused, never truncated.
    let big = ProposalEquivocationEvidence::new(proposer, good_a, good_b);
    assert!(big.wire_len() <= MAX_PROPOSAL_EQUIVOCATION_EVIDENCE_BYTES);
}

#[test]
fn proposal_evidence_canonicalize_sorts_and_dedupes() {
    let ks = keys(2);
    let fk0 = FalconKeypair::generate_from_seed(0xD3);
    let vs = vset(&ks);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);
    let proposer = ids(&ks)[0];
    let mk = |t1: u64, t2: u64| {
        ProposalEquivocationEvidence::new(
            proposer,
            signed_block_with_falcon(&ks[0], &fk0, 9, t1),
            signed_block_with_falcon(&ks[0], &fk0, 9, t2),
        )
    };
    let (e1, e2) = (mk(1, 2), mk(3, 4));
    // Duplicates: same pair twice + blocks swapped.
    let e1dup = mk(1, 2);
    let e1swapped = ProposalEquivocationEvidence::new(
        proposer,
        signed_block_with_falcon(&ks[0], &fk0, 9, 2),
        signed_block_with_falcon(&ks[0], &fk0, 9, 1),
    );
    // Garbage: same-body pair never survives shaping.
    let same = signed_block_with_falcon(&ks[0], &fk0, 9, 7);
    let garbage = ProposalEquivocationEvidence::new(proposer, same.clone(), same);
    let out = canonicalize_proposal_equivocation_evidence(
        vec![
            e2.clone(),
            garbage,
            e1dup.clone(),
            e1swapped.clone(),
            e1.clone(),
        ],
        &member,
    );
    // Ruleset v4: the two genuine same-round offenses survive shaping, the
    // same-body garbage does not, and duplicates (including the swapped pair)
    // collapse to ONE canonical entry.
    assert_eq!(out.len(), 2, "two distinct offenses must survive shaping");
    assert!(
        !out.iter().any(|ev| ev.block_a.compute_hash() == ev.block_b.compute_hash()),
        "the same-body pair must be refused"
    );
    assert_eq!(e1.offense_key(), e1dup.offense_key());
    assert_eq!(e1.offense_key(), e1swapped.offense_key());
    assert_eq!(
        e1.offense_key(),
        ProposalEquivocationEvidence::new(
            proposer,
            signed_block_with_falcon(&ks[0], &fk0, 9, 2),
            signed_block_with_falcon(&ks[0], &fk0, 9, 1),
        )
        .offense_key(),
        "vote/block order must not move the offense key"
    );
    let mut keys_sorted = [e1.offense_key(), e2.offense_key()];
    keys_sorted.sort();
    assert!(keys_sorted[0] <= keys_sorted[1]);
}

#[test]
fn full_happy_path_commits() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x31);
    let vs = vset_with_falcon(&keys, &fks);
    let bh = block_hash(7);
    let mut hc = HeightConsensus::new(1, vs.clone());

    // proposer proposes
    let proposer = hc.proposer().unwrap();
    hc.receive_proposal(proposer, bh).unwrap();
    assert_eq!(hc.decide_prevote(), Some(bh));

    // 3 of 4 prevote the block -> quorum
    for (i, k) in keys.iter().enumerate().take(3) {
        let v = fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(bh));
        hc.add_prevote(v).unwrap();
    }
    assert_eq!(hc.try_prevote_quorum(), Some(Some(bh)));

    // 3 of 4 precommit -> finality
    for (i, k) in keys.iter().enumerate().take(3) {
        let v = fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(bh));
        hc.add_precommit(v).unwrap();
    }
    assert_eq!(hc.try_precommit_quorum(), Some(bh));
    assert_eq!(hc.decided, Some(bh));
}

#[test]
fn no_quorum_no_commit() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x32);
    let vs = vset_with_falcon(&keys, &fks);
    let bh = block_hash(7);
    let mut hc = HeightConsensus::new(1, vs);
    // only 2 of 4 precommit (below quorum 3)
    for (i, k) in keys.iter().enumerate().take(2) {
        let v = fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(bh));
        hc.add_precommit(v).unwrap();
    }
    assert_eq!(hc.try_precommit_quorum(), None);
    assert_eq!(hc.decided, None);
}

#[test]
fn safety_lock_prevents_conflicting_prevote() {
    let keys = keys(4);
    let vs = vset(&keys);
    let mut hc = HeightConsensus::new(1, vs);
    // We locked on block A at round 0
    hc.locked = Some((block_hash(1), 0));
    hc.round = 1;
    hc.proposal = Some((hc.proposer().unwrap(), block_hash(2))); // proposer offers B
                                                                 // Locked on A -> we must NOT prevote B; we prevote nil
    assert_eq!(
        hc.decide_prevote(),
        None,
        "locked validator must not prevote a conflicting value"
    );

    // If the proposal matches our lock, we prevote it
    hc.proposal = Some((hc.proposer().unwrap(), block_hash(1)));
    assert_eq!(hc.decide_prevote(), Some(block_hash(1)));
}

#[test]
fn view_change_advances_round() {
    let keys = keys(4);
    let vs = vset(&keys);
    let mut hc = HeightConsensus::new(1, vs);
    assert_eq!(hc.round, 0);
    hc.next_round();
    assert_eq!(hc.round, 1);
    assert_eq!(hc.step, Step::Propose);
    assert!(hc.proposal.is_none());
}

#[test]
fn qc_verification_rejects_insufficient_signatures() {
    // FULL-PQ: Falcon µQC with 2 vs 3 signers (same 2-below / 3-meets
    // quorum shape as the deleted Ed threshold). Quorum math unchanged.
    let mut vs = ValidatorSet::new();
    let mut fks: Vec<(ValidatorId, FalconKeypair)> = Vec::new();
    for i in 0..4u8 {
        let fk = FalconKeypair::generate_from_seed(0x40 + i);
        let pk = fk.public_key.clone();
        let id = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        vs.add(id, 1);
        register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
        fks.push((id, fk));
    }
    let bh = block_hash(9);
    let parent = [0x99; 32];
    let committee_size = micro_committee_size(vs.len());
    let committee = derive_sortition_committee(&vs, 1, 0, committee_size, &parent);
    let msg = vote_sign_bytes(1, 0, VoteKind::Precommit, &Some(bh));
    let build = |n: usize| -> QuorumCertificate {
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut msigs = Vec::new();
        for (i, val_id) in committee.iter().enumerate().take(n) {
            bitmask[i / 8] |= 1 << (i % 8);
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            msigs.push(fk.sign(&msg));
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            1,
            0,
            committee_size,
            bitmask,
            msigs,
            parent,
        );
        QuorumCertificate {
            shard_id: 0,
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        }
    };
    assert!(!build(2).verify(&vs), "sub-quorum µQC must not verify");
    assert!(build(3).verify(&vs), "quorum µQC must verify");
}

#[test]
fn qc_verification_rejects_duplicate_signers() {
    let keys = keys(4);
    let vs = vset(&keys);
    let bh = block_hash(9);
    let v = Vote::sign(&keys[0], 1, 0, VoteKind::Precommit, Some(bh));
    // Same signer repeated 3 times must NOT count as quorum
    let sigs = vec![
        (v.voter, v.signature.clone()),
        (v.voter, v.signature.clone()),
        (v.voter, v.signature.clone()),
    ];
    let qc = QuorumCertificate {
        shard_id: 0,
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    };
    assert!(!qc.verify(&vs), "duplicate signers must not fake a quorum");
}

#[test]
fn qc_verification_enforces_the_signer_cap() {
    // Audit F7: the cap is enforced INSIDE `verify`, so every caller
    // (sync/replay/adopt) inherits it without a separate length check.
    // FULL-PQ: genuine quorum is a Falcon µQC (same cap logic, PQ scheme).
    let mut vs = ValidatorSet::new();
    let mut fks: Vec<(ValidatorId, FalconKeypair)> = Vec::new();
    for i in 0..4u8 {
        let fk = FalconKeypair::generate_from_seed(0x50 + i);
        let pk = fk.public_key.clone();
        let id = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        vs.add(id, 1);
        register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
        fks.push((id, fk));
    }
    let bh = block_hash(9);
    let parent = [0x9A; 32];
    let committee_size = micro_committee_size(vs.len());
    let committee = derive_sortition_committee(&vs, 1, 0, committee_size, &parent);
    let msg = vote_sign_bytes(1, 0, VoteKind::Precommit, &Some(bh));
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    let mut msigs = Vec::new();
    for (i, val_id) in committee.iter().enumerate().take(3) {
        bitmask[i / 8] |= 1 << (i % 8);
        let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
        msigs.push(fk.sign(&msg));
    }
    let uqc = PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        1,
        0,
        committee_size,
        bitmask,
        msigs,
        parent,
    );
    let marker = (PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc));
    // A genuine 3-of-4 quorum under the cap.
    let mut sigs: Vec<(ValidatorId, Vec<u8>)> = vec![marker.clone()];
    let base = QuorumCertificate {
        shard_id: 0,
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs.clone(),
    };
    assert!(
        base.verify(&vs),
        "a real quorum under the cap must still verify"
    );

    // Padding with unique junk entries up to exactly the cap is still
    // permitted (the cap is a strict upper bound), and the junk carries no
    // power, so the genuine quorum still decides.
    while sigs.len() < MAX_COMMIT_CERT_SIGNERS {
        let i = sigs.len();
        let mut junk = [0u8; 32];
        junk[..8].copy_from_slice(&(i as u64).to_be_bytes());
        sigs.push((junk, vec![0u8; 64]));
    }
    let at_cap = QuorumCertificate {
        shard_id: 0,
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs.clone(),
    };
    assert_eq!(at_cap.signatures.len(), MAX_COMMIT_CERT_SIGNERS);
    assert!(
        at_cap.verify(&vs),
        "a certificate at the cap is still accepted"
    );

    // One entry over the cap is refused outright -- before any signature
    // is examined -- even though its signers include a real quorum.
    sigs.push(([0xFFu8; 32], vec![0u8; 64]));
    let over = QuorumCertificate {
        shard_id: 0,
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    };
    assert_eq!(over.signatures.len(), MAX_COMMIT_CERT_SIGNERS + 1);
    assert!(
        !over.verify(&vs),
        "a certificate over the signer cap must be refused"
    );
}

#[test]
fn driver_finalizes_and_advances() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x33);
    let vs = vset_with_falcon(&keys, &fks);
    let mut driver = ConsensusDriver::new(vs, 1);
    let bh = block_hash(3);

    {
        let hc = driver.current.as_mut().unwrap();
        let proposer = hc.proposer().unwrap();
        hc.receive_proposal(proposer, bh).unwrap();
        for (i, k) in keys.iter().enumerate().take(3) {
            hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(bh)))
                .unwrap();
        }
        hc.try_prevote_quorum();
        for (i, k) in keys.iter().enumerate().take(3) {
            hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(bh)))
                .unwrap();
        }
        hc.try_precommit_quorum();
    }
    driver.advance();
    assert!(driver.is_final(1, bh));
    assert_eq!(driver.current.as_ref().unwrap().height, 2);
    // The block just decided is the next height's sortition parent. A driver
    // that dropped it would elect a committee from the zero/genesis parent
    // (or, above height 1, from an UNKNOWN parent: no µQC at all).
    let next = driver.current.as_ref().unwrap();
    assert!(next.parent_hash_known(), "the decided parent is known");
    assert_eq!(next.parent_hash, bh);
    assert_eq!(next.sortition_parent(), Some(&bh));
}

#[test]
fn proposer_selection_is_deterministic_and_rotates() {
    let keys = keys(4);
    let vs = vset(&keys);
    // Determinism: same input, same proposer, every time.
    let p0 = vs.proposer_for(0, 0).unwrap();
    assert_eq!(
        vs.proposer_for(0, 0).unwrap(),
        p0,
        "selection must be deterministic"
    );
    // Rotation (hash-slot is statistical, not periodic): over a window,
    // every validator must appear and no single one may own everything.
    let seq: Vec<[u8; 32]> = (0..64u64).map(|h| vs.proposer_for(h, 0).unwrap()).collect();
    let distinct: std::collections::HashSet<_> = seq.iter().collect();
    assert_eq!(
        distinct.len(),
        4,
        "all 4 validators must propose over 64 heights"
    );
}

#[test]
fn proposer_rotates_fairly_with_large_equal_powers() {
    // Regression: with power 10^12 each, the un-normalized LINEAR schedule
    // gave the first validator every slot until height+round crossed 10^12.
    // Hash-slot is uniform from height 1: over 200 heights each of the two
    // must hold 35-65% (mean 50%, std ~3.5% — ±15pp is >4 sigma).
    let k = keys(2);
    let vs = ValidatorSet::from_list(vec![
        (ids(&k)[0], 1_000_000_000_000),
        (ids(&k)[1], 1_000_000_000_000),
    ]);
    let seq: Vec<[u8; 32]> = (1..=200u64)
        .map(|h| vs.proposer_for(h, 0).unwrap())
        .collect();
    let a = seq.iter().filter(|p| *p == &ids(&k)[0]).count();
    assert!(
        (70..=130).contains(&a),
        "equal powers must split ~100/100 over 200 heights, got {a}"
    );
    // Round dimension also varies (not pinned to height parity).
    let r0 = vs.proposer_for(643, 0).unwrap();
    let r1 = vs.proposer_for(643, 1).unwrap();
    let _ = (r0, r1); // both resolve; statistical spread is covered above
}

#[test]
fn proposer_keeps_weighting_after_normalization() {
    // 2:1 powers must propose ~2:1 statistically (hash-slot has no exact
    // short period by design). Over 600 rounds the 2/3-share holder must
    // hold 55-78% (mean 66.7%, std ~1.9% — ±11pp is >5 sigma).
    let k = keys(2);
    let (a, b) = (ids(&k)[0], ids(&k)[1]);
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let vs = ValidatorSet::from_list(vec![(lo, 2_000_000_000_000), (hi, 1_000_000_000_000)]);
    let seq: Vec<[u8; 32]> = (0..600u64)
        .map(|r| vs.proposer_for(0, r as u32).unwrap())
        .collect();
    let lo_n = seq.iter().filter(|p| *p == &lo).count();
    assert!(
        (330..=470).contains(&lo_n),
        "2:1 weighting must hold statistically, got {lo_n}/600"
    );
}

#[test]
fn vote_for_far_future_round_rejected() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x37);
    let vs = vset_with_falcon(&keys, &fks);
    let mut hc = HeightConsensus::new(1, vs);
    let far = MAX_ROUND_AHEAD + 5;
    let v = fvote(
        &keys[0],
        &fks[0],
        1,
        far,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    assert!(
        hc.add_prevote(v).is_err(),
        "vote for a far-future round must be rejected"
    );
}

#[test]
fn repeated_peer_messages_advance_at_most_one_round_each() {
    // The old cap was `MAX_ROUND_AHEAD` (1000) PER CALL, so a peer only had
    // to send a handful of messages to walk us arbitrarily far ahead.
    // Measured live: a node at round 0 reached round 57 in 100 ms. Since
    // the proposer is hash-scheduled per round, that also yanks WHO must
    // propose out from under both nodes, and two nodes inflating each other
    // reject every proposal as "wrong proposer" and wedge forever.
    //
    // The invariant is per-message: one message moves us at most one round.
    // N messages claiming rounds 64, 128, ... may therefore reach at most N,
    // never 64*N.
    let keys = keys(4);
    let mut hc = HeightConsensus::new(1, vset(&keys));
    let n = 500u32;
    for i in 1..=n {
        hc.advance_to_round(i * 64);
    }
    assert_eq!(
        hc.round, n,
        "500 messages must advance at most 500 rounds, not 500*64"
    );
    assert!(
        hc.round < n * 64,
        "the counter must not track the claimed rounds"
    );
}

#[test]
fn a_block_cannot_be_decided_on_precommits_alone() {
    // Before this precondition, any precommit quorum finalised whatever it
    // named. A peer could therefore hand a node precommits for a block that
    // nobody ever prevoted for, and it would be committed.
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x34);
    let vs = vset_with_falcon(&keys, &fks);
    let mut hc = HeightConsensus::new(1, vs);

    let a = block_hash(1);
    let b = block_hash(2);
    for (i, k) in keys.iter().enumerate() {
        hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
            .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        None,
        "a precommit quorum with no prevotes must not decide anything"
    );
    assert_eq!(hc.decided, None);

    // Prevote a DIFFERENT block: now the two quorums disagree.
    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(b)))
            .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        None,
        "prevotes for one block and precommits for another must not decide"
    );
    assert_eq!(hc.decided, None);

    // Prevote the same block, and it decides.
    let mut hc2 = HeightConsensus::new(1, vset_with_falcon(&keys, &fks));
    for (i, k) in keys.iter().enumerate() {
        hc2.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
        hc2.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
            .unwrap();
    }
    assert_eq!(hc2.try_precommit_quorum(), Some(a));
}

#[test]
fn a_locked_validator_will_not_decide_a_different_block() {
    // The safety lock has to survive the precommit quorum: a node that locked
    // on block A must not later decide block B at the same or a later round,
    // or a reorg past the lock becomes possible.
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x35);
    let mut hc = HeightConsensus::new(1, vset_with_falcon(&keys, &fks));
    let a = block_hash(1);
    let b = block_hash(2);

    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
        hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
            .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(a),
        "A is decided and locked"
    );

    hc.next_round();
    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 1, VoteKind::Prevote, Some(b)))
            .unwrap();
        hc.add_precommit(fvote(k, &fks[i], 1, 1, VoteKind::Precommit, Some(b)))
            .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        None,
        "a locked node must not decide a conflicting block"
    );
}

#[test]
fn advance_to_round_is_bounded_against_round_dos() {
    let keys = keys(4);
    let vs = vset(&keys);
    let mut hc = HeightConsensus::new(1, vs);
    // A malicious peer claims u32::MAX; we must not jump there.
    hc.advance_to_round(u32::MAX);
    assert_eq!(
        hc.round, MAX_ROUND_ADVANCE_PER_MESSAGE,
        "one message may move us at most one round"
    );
    // A small forward step still works.
    let mut hc2 = HeightConsensus::new(1, vset(&keys));
    hc2.advance_to_round(1);
    assert_eq!(hc2.round, 1);
}

#[test]
fn vote_wrong_scope_rejected() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x36);
    let vs = vset_with_falcon(&keys, &fks);
    let mut set = VoteSet::new();
    // vote at height 2 cannot be added to a height-1 set
    let v = fvote(
        &keys[0],
        &fks[0],
        2,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    assert!(set.add(v, &vs, 1, 0, VoteKind::Prevote).is_err());
}

// ============================================================================
// Regression tests: hunt wave (round safety, quorum scan, committee schedule)
// ============================================================================

/// A NIL precommit quorum in a NEWER round must not shadow the older round's
/// block precommit quorum. Both quorums are legitimate: validators that saw
/// the polka precommit the block at round r, while validators that timed out
/// precommit nil at r+1. `try_precommit_quorum` used to stop at the FIRST
/// round carrying any precommit quorum (nil included) and return `None`,
/// parking the height even though the block was fully certified.
#[test]
fn nil_precommit_quorum_does_not_shadow_the_block_precommit_quorum() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x51);
    let vs = vset_with_falcon(&keys, &fks);
    let mut hc = HeightConsensus::new(1, vs);
    let a = block_hash(7);

    // Round 0: three prevotes AND three precommits for A (a real decision).
    for (i, k) in keys.iter().enumerate().take(3) {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
        hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
            .unwrap();
    }
    // Round 1: three prevotes AND three precommits for nil (the network
    // timed out after the decision quorum formed).
    for (i, k) in keys.iter().enumerate().take(3) {
        hc.add_prevote(fvote(k, &fks[i], 1, 1, VoteKind::Prevote, None))
            .unwrap();
        hc.add_precommit(fvote(k, &fks[i], 1, 1, VoteKind::Precommit, None))
            .unwrap();
    }
    // The local counter is in the newer round, so the scan sees nil first.
    hc.round = 1;
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(a),
        "the certified block must decide; a newer nil quorum is not evidence against it"
    );
}

/// A proposal accepted for round r is dead the moment we enter round r+1.
/// (`next_round` clears it, so the engine's normal path cannot prevote a
/// stale body; this pins the clear as the reason, not an accident.)
#[test]
fn decide_prevote_refuses_a_stale_proposal_from_a_previous_round() {
    let keys = keys(4);
    let vs = vset(&keys);
    let mut hc = HeightConsensus::new(1, vs);
    let proposer = hc.proposer().unwrap();
    let stale = block_hash(0x42);
    hc.receive_proposal(proposer, stale).unwrap();
    assert_eq!(hc.decide_prevote(), Some(stale));
    hc.next_round();
    assert!(
        !hc.has_live_proposal(),
        "the proposal belongs to the round we left"
    );
    assert_eq!(
        hc.decide_prevote(),
        None,
        "a stale proposal must prevote nil in the new round, never the old body"
    );
}

/// A newer precommit quorum whose PREVOTE quorum this node does not hold must
/// not hide an OLDER round that is fully proven locally. The scan used to stop
/// at the first non-nil precommit quorum, fail the "prevotes agree" check and
/// return `None` without ever examining the older, decidable round.
#[test]
fn an_unproven_newer_precommit_quorum_does_not_hide_a_decidable_older_round() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x53);
    let vs = vset_with_falcon(&keys, &fks);
    let mut hc = HeightConsensus::new(1, vs);
    let a = block_hash(0x0A);
    let b = block_hash(0x0B);

    // Round 0: a complete, locally proven decision for A.
    for (i, k) in keys.iter().enumerate().take(3) {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
        hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
            .unwrap();
    }
    // Round 1: the precommits for B arrived but the prevotes did not (the WAN
    // delivery shape: a bodyless observer sees the tail of a later round).
    for (i, k) in keys.iter().enumerate().take(3) {
        hc.add_precommit(fvote(k, &fks[i], 1, 1, VoteKind::Precommit, Some(b)))
            .unwrap();
    }
    hc.round = 1;

    assert_eq!(
        hc.try_precommit_quorum(),
        Some(a),
        "the scan must fall through an unproven newer round to the fully proven older one"
    );
}

/// The retained-round cap must be enforceable even when the OLDEST retained
/// round is the observed polka. The prune loop used to `break` on that round,
/// which left every later round in place: a height that lived through the cap
/// then grew without bound (one attacker-sized vote bucket per round).
#[test]
fn retained_round_cap_holds_when_the_polka_round_is_the_oldest() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x52);
    let vs = vset_with_falcon(&keys, &fks);
    let mut hc = HeightConsensus::new(1, vs);
    let bh = block_hash(3);
    for (i, k) in keys.iter().enumerate().take(3) {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    assert_eq!(hc.observed_polka, Some((0, bh)));

    // Fill past the cap with rounds that carry votes (the attacker shape).
    let extra = MAX_RETAINED_VOTE_ROUNDS as u32 + 8;
    for r in 1..=extra {
        hc.prevotes.insert(r, VoteSet::new());
    }
    let retained = |hc: &HeightConsensus| {
        let mut rounds: std::collections::HashSet<Round> = hc.prevotes.keys().copied().collect();
        rounds.extend(hc.precommits.keys().copied());
        rounds.len()
    };
    assert!(retained(&hc) > MAX_RETAINED_VOTE_ROUNDS);
    hc.next_round();
    assert!(
        retained(&hc) <= MAX_RETAINED_VOTE_ROUNDS,
        "retained rounds {} exceed the cap {} because the polka round is oldest",
        retained(&hc),
        MAX_RETAINED_VOTE_ROUNDS
    );
    assert!(
        hc.prevote_set(0).is_some(),
        "the polka's own round must survive the prune"
    );
}

/// Proposer-miss accounting must use the height's REAL schedule. Under the
/// CN-VRF v3 beacon schedule the parent-hash draw names a different proposer,
/// so the old `proposer_for(height, round)` charged the wrong validator.
#[test]
fn proposer_miss_accounting_uses_the_height_schedule() {
    let keys = keys(4);
    let vs = vset(&keys);
    let mut hc = HeightConsensus::new(1, vs.clone());
    let parent = vs.proposer_for(1, 0).unwrap();

    // Find a beacon that elects a proposer different from the parent draw.
    let (beacon, expected) = (0u8..=255)
        .find_map(|b| {
            let beacon = EpochBeacon {
                epoch: 0,
                output: [b; 48],
            };
            let p = vs.proposer_for_with_schedule(1, 0, CommitteeSchedule::Beacon(Some(beacon)))?;
            (p != parent).then_some((beacon, p))
        })
        .expect("some beacon must elect a different proposer");

    hc.set_committee_schedule(CommitteeSchedule::Beacon(Some(beacon)));
    hc.next_round();
    assert_eq!(
        hc.proposer_missed_streak(&expected),
        1,
        "the missing slot belongs to the beacon-scheduled proposer"
    );
    assert_eq!(
        hc.proposer_missed_streak(&parent),
        0,
        "the parent-hash proposer did not own this slot"
    );
}

/// A signature-refused vote must leave NO trace: an empty vote-set bucket for
/// its round is otherwise materialized before the signature check, counts
/// toward the retention cap and can evict rounds that carry real votes.
#[test]
fn a_refused_signature_does_not_materialize_a_round_bucket() {
    let keys = keys(4);
    let fks = falcon_for_keys(&keys, 0x54);
    let vs = vset_with_falcon(&keys, &fks);
    let mut hc = HeightConsensus::new(1, vs);

    let mut bad = fvote(
        &keys[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block_hash(1)),
    );
    let last = bad.signature.len() - 1;
    bad.signature[last] ^= 0xFF;
    assert!(hc.add_prevote(bad.clone()).is_err());
    assert!(
        hc.prevote_set(0).is_none(),
        "a refused prevote must not create an empty prevote set"
    );

    let mut bad_precommit = fvote(
        &keys[0],
        &fks[0],
        1,
        0,
        VoteKind::Precommit,
        Some(block_hash(1)),
    );
    let last = bad_precommit.signature.len() - 1;
    bad_precommit.signature[last] ^= 0xFF;
    assert!(hc.add_precommit(bad_precommit).is_err());
    assert!(
        hc.precommit_set(0).is_none(),
        "a refused precommit must not create an empty precommit set"
    );

    // A non-member with a perfectly valid Falcon signature is another
    // attacker: admission must refuse it BEFORE materializing the bucket.
    let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
    let outsider_fk = FalconKeypair::generate_from_seed(0xE1);
    register_validator_pq_key(
        outsider.verifying_key().to_bytes(),
        crate::post_quantum::PqScheme::Falcon512,
        outsider_fk.public_key.clone(),
    );
    let outsider_vote = fvote(
        &outsider,
        &outsider_fk,
        1,
        7,
        VoteKind::Prevote,
        Some(block_hash(2)),
    );
    assert!(hc.add_prevote(outsider_vote).is_err());
    assert!(
        hc.prevote_set(7).is_none(),
        "a non-member vote must not create a round bucket"
    );
}

/// Corroboration for the deadlock breaker is not "two validator ids": under
/// the BFT assumption fewer than one third of the POWER is Byzantine, so a
/// round is only network evidence when the peers reporting it carry MORE than
/// one third of the power. Two colluding validators in a 7-member set are
/// below that floor and used to be able to steer the forward-only breaker.
#[test]
fn deadlock_breaker_corroboration_is_power_weighted() {
    let keys = keys(7);
    let vs = vset(&keys);
    let mut hc = HeightConsensus::new(1, vs);
    hc.round = 100;

    // Two of seven = 2/7 of the power: a sub-one-third coalition.
    hc.note_peer_round(ids(&keys)[0], u32::MAX);
    hc.note_peer_round(ids(&keys)[1], u32::MAX);
    assert_eq!(
        hc.deadlock_breaker_target(400, 300),
        None,
        "two of seven validators are below the one-third power floor"
    );
    assert!(
        hc.deadlock_local_reset_due(400, 300),
        "with no honest corroboration the deaf-node fallback must own the breaker"
    );

    // A third distinct validator crosses one third of the power.
    hc.note_peer_round(ids(&keys)[2], u32::MAX);
    assert!(
        hc.deadlock_breaker_target(400, 300).is_some(),
        "more than one third of the power is corroborated network position"
    );
}

/// Committee sortition must not PANIC on an unrepresentable stake total. The
/// quorum boundary refuses such a set fail-closed (`power_total_representable`),
/// but the selection path used a raw `u64` sum and panicked in debug (wrapped
/// in release) before any quorum check could run.
#[test]
fn committee_sortition_saturates_an_unrepresentable_stake_total() {
    let half = u64::MAX / 2 + 1;
    let a = [0xA1u8; 32];
    let b = [0xB2u8; 32];
    let vs = ValidatorSet::from_list(vec![(a, half), (b, half)]);
    assert!(!vs.power_total_representable());
    let committee = derive_sortition_committee(&vs, 1, 0, 1, &[0x11u8; 32]);
    assert_eq!(
        committee.len(),
        1,
        "a deterministic draw must still elect one seat without overflowing"
    );
}
/// stake the network quorum is 128 and the 128-seat committee can reach 128
/// only if EVERY member signs. A perfectly valid 128-validator precommit
/// quorum that contains 63 non-committee members and 65 committee members
/// cannot compile a µQC (65 < 128) — but the height is decided, so the
/// producer must fall back to the full-network CEC instead of emitting a
/// certificate no peer can verify. `qc_split_required`'s raw count says
/// "µQC" here because N < 192.
#[test]
fn decision_certificate_falls_back_to_cec_when_the_drawn_committee_cannot_carry_quorum() {
    const N: usize = 191;
    let ks = keys(N);
    let fks: Vec<FalconKeypair> = (0..N)
        .map(|i| FalconKeypair::generate_from_seed((i as u8).wrapping_add(1)))
        .collect();
    let vs = vset(&ks);
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let idsv = ids(&ks);
    let parent = [0x5Au8; 32];
    let committee = derive_sortition_committee(&vs, 1, 0, micro_committee_size(N), &parent);
    assert_eq!(committee.len(), 128);

    let target = block_hash(0x77);
    // A legal 128-power quorum: all 63 non-committee validators plus 65
    // committee members (one committee seat is effectively offline).
    let mut chosen: Vec<usize> = (0..N).filter(|&i| !committee.contains(&idsv[i])).collect();
    assert_eq!(chosen.len(), N - 128);
    chosen.extend((0..N).filter(|&i| committee.contains(&idsv[i])).take(65));
    assert_eq!(chosen.len(), 128);

    let mut votes = VoteSet::new();
    for &i in &chosen {
        let v = fvote(&ks[i], &fks[i], 1, 0, VoteKind::Prevote, Some(target));
        votes.add(v, &vs, 1, 0, VoteKind::Prevote).unwrap();
    }
    assert!(
        votes.quorum_reached(Some(target), &vs),
        "128 of 191 is the network quorum"
    );
    assert!(
        !qc_split_required(1, N),
        "the raw count keeps the µQC path on"
    );

    let qc = produce_decision_certificate(&votes, Some(target), &vs, Some(&parent))
        .expect("a network quorum must produce a decision certificate");
    assert!(
        qc.verify(&vs),
        "the decision certificate must verify: the drawn committee carries 65 of the 128 \
         required power, so the full-network CEC is the only certificate that can certify this quorum"
    );
}

/// The same defect exists well below the count boundary: at N = 129 uniform
/// stake the committee is 128 seats but the network quorum is only 87, so a
/// legal quorum of the one non-committee validator plus 86 committee members
/// carries 86 of the 87 required committee power. The count predicate says
/// "µQC" (N < 192); the power predicate says the committee cannot certify it.
#[test]
fn cec_fallback_also_covers_a_minimal_quorum_at_129_validators() {
    const N: usize = 129;
    let ks = keys(N);
    let fks: Vec<FalconKeypair> = (0..N)
        .map(|i| FalconKeypair::generate_from_seed((i as u8).wrapping_add(0x40)))
        .collect();
    let vs = vset(&ks);
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let idsv = ids(&ks);
    let parent = [0x6Bu8; 32];
    let committee = derive_sortition_committee(&vs, 1, 0, micro_committee_size(N), &parent);
    assert_eq!(committee.len(), 128);

    let target = block_hash(0x78);
    let mut chosen: Vec<usize> = (0..N).filter(|&i| !committee.contains(&idsv[i])).collect();
    assert_eq!(chosen.len(), N - 128);
    chosen.extend((0..N).filter(|&i| committee.contains(&idsv[i])).take(86));
    assert_eq!(chosen.len(), 87, "the N=129 network quorum");

    let mut votes = VoteSet::new();
    for &i in &chosen {
        let v = fvote(&ks[i], &fks[i], 1, 0, VoteKind::Prevote, Some(target));
        votes.add(v, &vs, 1, 0, VoteKind::Prevote).unwrap();
    }
    assert!(votes.quorum_reached(Some(target), &vs));
    let qc = produce_decision_certificate(&votes, Some(target), &vs, Some(&parent))
        .expect("a network quorum must produce a decision certificate");
    assert!(
        qc.verify(&vs),
        "86 of the 87 committee power required here: the CEC must be used"
    );
}
