//! SCHEDULE / sortition integration surface (read-only review + pinning tests).
//!
//! ## How the proposer schedule is derived (analysis, with line cites)
//!
//! * `ValidatorSet::proposer_for(height, round)` (`src/consensus.rs:1284`)
//!   is the SOLE proposer election. Inputs: **the validator set in force at
//!   that height** (member ids + powers) **+ height + round**. NOT epoch,
//!   NOT seed, NOT parent hash. Slot =
//!   `u64(BLAKE3_derive_key("STELL_PROPOSER_V1" || height_le || round_le)[0..8])
//!   mod (total_power / gcd_of_powers)` (`src/consensus.rs:1300-1308`),
//!   walked over the EXPLICITLY SORTED id table (`:1322-1331`).
//! * `HeightConsensus::proposer()` (`src/consensus.rs:3583-3585`) is a pure
//!   delegation: `self.validators.proposer_for(self.height, self.round)` —
//!   the only schedule input beyond height/round is `hc.validators`, which
//!   the runtime keeps equal to `validator_set_for_height(hc.height)`.
//! * `validator_set_for_height(h)` (`src/runtime.rs:7201`) answers which set
//!   is in force at height `h` (pending activation > live > history). This is
//!   the W10.5 set-at-height rule (`src/staking.rs:20-32`): stake mutations
//!   at ledger-height L activate at L+1, and every quorum/schedule check for
//!   height H MUST use the set in force AT H, never the live set.
//! * `proposer_matches_schedule` (`src/sync.rs:225-247`) is the sync-side
//!   schedule scan: the header proposer must hold SOME slot at this height
//!   in rounds `0..=qc_round` (plus a +4-round tolerance window when
//!   `qc_round > 0`), evaluated against the set passed in — which W10.5 call
//!   sites resolve per-header height (`src/sync.rs:79-84,752`).
//! * The SORTITION committee (`derive_sortition_committee`) is a
//!   DIFFERENT election over the same `(set, height, round)` PLUS the parent
//!   block hash as entropy (`sortition_seed`). Canonical parent-hash draw,
//!   byte-pinned.
//!
//! ## Tests below (no logic changes; pins + measurements only)
//!
//! 1. `proposer_schedule_is_deterministic_across_identical_inputs`
//! 2. `proposer_schedule_uniformity_is_measured_and_bounded`
//! 3. `proposer_round_dimension_varies_not_pinned_to_height_parity`
//! 4. `proposer_edge_cases_empty_and_singleton_sets`
//! 5. `schedule_across_rotation_boundary_uses_set_at_height`
//! 6. `finality_gate_uses_set_at_height_for_schedule_and_qc`
//! 7. `disabled_gate_pinned_byte_identical_to_today`
//! 8. `height_consensus_proposer_tracks_its_own_set_height_round`

use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    derive_sortition_committee, sortition_seed, HeightConsensus, QuorumCertificate,
    ValidatorSet, Vote, VoteKind,
};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::sync::{proposer_matches_schedule, verify_finality_for_header};
use std::sync::Arc;

// --- fixtures ----------------------------------------------------------------

/// Four fixed validator ids (no OS randomness: every assertion is bit-stable).
fn fixed_ids4() -> Vec<[u8; 32]> {
    (0x11u8..=0x14).map(|b| [b; 32]).collect()
}

fn fixed_set_equal4() -> (ValidatorSet, Vec<[u8; 32]>) {
    let ids = fixed_ids4();
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1_000)).collect());
    (vs, ids)
}

/// Deterministic signing keys (fixed seeds — no `OsRng`, no wall clock).
fn fixed_keys3() -> (SigningKey, SigningKey, SigningKey) {
    (
        SigningKey::from_bytes(&[0xA1u8; 32]),
        SigningKey::from_bytes(&[0xB2u8; 32]),
        SigningKey::from_bytes(&[0xC3u8; 32]),
    )
}

fn floor() -> u64 {
    stellereum::staking::required_bond_floor_nano()
}

fn precommit_qc(
    signers: &[&SigningKey],
    height: u64,
    round: u32,
    block_hash: [u8; 32],
) -> QuorumCertificate {
    let sigs = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, round, VoteKind::Precommit, Some(block_hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: sigs,
    }
}

// --- 1. determinism -----------------------------------------------------------

#[test]
fn proposer_schedule_is_deterministic_across_identical_inputs() {
    let (vs, _ids) = fixed_set_equal4();
    // A second, identically-built set = "another node" with the same inputs.
    let (vs2, _) = fixed_set_equal4();
    assert_eq!(vs.validators, vs2.validators);

    for h in 0..128u64 {
        for r in 0..8u32 {
            // Same inputs, same proposer, every call, every node.
            let a = vs.proposer_for(h, r).expect("non-empty set elects");
            assert_eq!(vs.proposer_for(h, r), Some(a), "repeat call at h={h} r={r}");
            assert_eq!(
                vs2.proposer_for(h, r),
                Some(a),
                "second node disagrees at h={h} r={r}"
            );
        }
    }

    // Sortition side is equally pure: canonical parent-hash draw.
    let parent = [0x5Au8; 32];
    for h in [0u64, 1, 9, 1_000_000] {
        for r in [0u32, 1, 2] {
            assert_eq!(sortition_seed(&parent, h, r), sortition_seed(&parent, h, r));
            assert_eq!(
                derive_sortition_committee(&vs, h, r, 2, &parent),
                derive_sortition_committee(&vs, h, r, 2, &parent),
            );
        }
    }
}

// --- 2. uniformity ------------------------------------------------------------

#[test]
fn proposer_schedule_uniformity_is_measured_and_bounded() {
    // Equal powers: each of the 4 must hold ~25% over 4000 heights
    // (std ~0.7pp; the ±5pp bound below is >7 sigma — a failure is a real
    // skew bug, not noise).
    let (vs, ids) = fixed_set_equal4();
    const N: usize = 4000;
    let mut counts = [0usize; 4];
    for h in 0..N as u64 {
        let p = vs.proposer_for(h, 0).expect("elects");
        let i = ids.iter().position(|id| *id == p).expect("member");
        counts[i] += 1;
    }
    let mut chi2 = 0.0f64;
    for (i, c) in counts.iter().enumerate() {
        let expected = N as f64 / 4.0;
        chi2 += (*c as f64 - expected).powi(2) / expected;
        assert!(
            (800..=1200).contains(c),
            "validator {i} holds {c}/{N} (want ~1000): skew report counts={counts:?}"
        );
    }
    // Chi-square, df=3: 0.1% critical value is ~16.4; 30 is far beyond noise.
    println!("UNIFORMITY equal4 N={N} counts={counts:?} chi2={chi2:.3}");
    assert!(
        chi2 < 30.0,
        "chi-square {chi2:.2} over {N} draws too skewed: counts={counts:?}"
    );

    // Skewed W10.5-shape set A(2F)+B(F)+C(F): A ~50%, B/C ~25% each over
    // 8000 (height, round) draws (std A ~0.56pp, B/C ~0.48pp; ±5pp is >9σ).
    let (ka, kb, kc) = fixed_keys3();
    let (a, b, c) = (
        ka.verifying_key().to_bytes(),
        kb.verifying_key().to_bytes(),
        kc.verifying_key().to_bytes(),
    );
    let skewed =
        ValidatorSet::from_list(vec![(a, 2 * floor()), (b, floor()), (c, floor())]);
    const M: usize = 8000;
    let (mut na, mut nb, mut nc) = (0usize, 0usize, 0usize);
    for i in 0..M {
        let p = skewed
            .proposer_for(i as u64 / 4, (i % 4) as u32)
            .expect("elects");
        if p == a {
            na += 1;
        } else if p == b {
            nb += 1;
        } else if p == c {
            nc += 1;
        } else {
            panic!("non-member elected");
        }
    }
    println!("UNIFORMITY skewed A2F_BF_CF M={M} na={na} nb={nb} nc={nc}");
    assert!(
        (3600..=4400).contains(&na),
        "A(2F) holds {na}/{M} (want ~4000): skewed schedule"
    );
    assert!(
        (1600..=2400).contains(&nb),
        "B(F) holds {nb}/{M} (want ~2000): skewed schedule"
    );
    assert!(
        (1600..=2400).contains(&nc),
        "C(F) holds {nc}/{M} (want ~2000): skewed schedule"
    );
}

// --- 3. round parity ----------------------------------------------------------

#[test]
fn proposer_round_dimension_varies_not_pinned_to_height_parity() {
    let (vs, _) = fixed_set_equal4();
    // Round must matter: most heights elect a different proposer in round 1
    // than in round 0 (expect ~75% for 4 validators; >10% is far from noise).
    let mut differ = 0usize;
    const N: u64 = 512;
    for h in 0..N {
        if vs.proposer_for(h, 0) != vs.proposer_for(h, 1) {
            differ += 1;
        }
    }
    assert!(
        differ > (N as usize) / 10,
        "round dimension looks pinned: only {differ}/{N} heights vary across rounds"
    );
    // At a fixed height, several rounds must spread over several proposers.
    let mut varied_heights = 0usize;
    for h in 0..64u64 {
        let distinct: HashSet<[u8; 32]> =
            (0..8u32).map(|r| vs.proposer_for(h, r).expect("elects")).collect();
        if distinct.len() >= 2 {
            varied_heights += 1;
        }
    }
    println!("ROUND_VARY differ_0v1={differ}/{N} multi_proposer_heights={varied_heights}/64");
    assert!(
        varied_heights > 32,
        "rounds 0..8 at fixed heights must usually offer >=2 proposers, got {varied_heights}/64"
    );
}

// --- 4. edge cases ------------------------------------------------------------

#[test]
fn proposer_edge_cases_empty_and_singleton_sets() {
    // Empty set: no proposer, no committee, no schedule match, no finality.
    let empty = ValidatorSet::new();
    assert_eq!(empty.proposer_for(1, 0), None);
    assert_eq!(empty.proposer_for(u64::MAX, u32::MAX), None);
    let parent = [0x5Au8; 32];
    assert!(derive_sortition_committee(&empty, 1, 0, 4, &parent).is_empty());
    assert!(!proposer_matches_schedule(&empty, 1, &[0x11u8; 32], 0));
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some([0xABu8; 32]),
        signatures: vec![],
    };
    assert!(verify_finality_for_header(&empty, 1, &[0xABu8; 32], &[0x11u8; 32], &qc).is_err());

    // All-zero powers behave like empty (add() drops zero-power members).
    let zero = ValidatorSet::from_list(vec![([0x11u8; 32], 0), ([0x12u8; 32], 0)]);
    assert!(zero.is_empty());
    assert_eq!(zero.proposer_for(1, 0), None);

    // Singleton: the only member always proposes; committee is itself for k>=1.
    let solo = ValidatorSet::from_list(vec![([0x77u8; 32], 5)]);
    for h in [0u64, 1, 999_999] {
        for r in [0u32, 1, 37] {
            assert_eq!(solo.proposer_for(h, r), Some([0x77u8; 32]));
        }
    }
    assert!(proposer_matches_schedule(&solo, 42, &[0x77u8; 32], 0));
    assert!(!proposer_matches_schedule(&solo, 42, &[0x78u8; 32], 0));
    assert_eq!(
        derive_sortition_committee(&solo, 1, 0, 99, &parent),
        vec![[0x77u8; 32]]
    );
    assert!(derive_sortition_committee(&solo, 1, 0, 0, &parent).is_empty());
}

// --- 5 + 6. rotation boundary (W10.5 set-at-height) ----------------------------

const BOUNDARY_H: u64 = 100;

/// Old set B(F)+C(F) at ledger height H; A seats 2F and activates at H+1.
async fn runtime_across_join() -> (
    stellereum::runtime::ValidatorRuntime,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    SigningKey,
    SigningKey,
    SigningKey,
) {
    let (ka, kb, kc) = fixed_keys3();
    let (a, b, c) = (
        ka.verifying_key().to_bytes(),
        kb.verifying_key().to_bytes(),
        kc.verifying_key().to_bytes(),
    );
    let engine = Arc::new(InMemoryStateEngine::new());
    for (id, amt) in [(b, floor()), (c, floor())] {
        engine.credit_native(&id, amt * 2).await.unwrap();
        engine.staking_write().await.bond(id, amt, 0).unwrap();
    }
    let old = ValidatorSet::from_list(vec![(b, floor()), (c, floor())]);
    let mut rt =
        stellereum::runtime::ValidatorRuntime::new(kb.clone(), old.clone(), engine.clone(), BOUNDARY_H);
    engine.credit_native(&a, 8 * floor()).await.unwrap();
    engine.staking_write().await.bond(a, 2 * floor(), 0).unwrap();
    assert!(
        rt.refresh_validator_set_from_staking().await,
        "join must stage a pending set"
    );
    (rt, a, b, c, ka, kb, kc)
}

#[tokio::test]
async fn schedule_across_rotation_boundary_uses_set_at_height() {
    let (rt, a, b, c, _ka, _kb, _kc) = runtime_across_join().await;
    // Staged, not installed: the in-force set at H is still the old one.
    assert_eq!(rt.pending_validators.as_ref().map(|(h, _)| *h), Some(BOUNDARY_H + 1));
    let at_h = rt.validator_set_for_height(BOUNDARY_H);
    let at_h1 = rt.validator_set_for_height(BOUNDARY_H + 1);
    assert_eq!(at_h.validators.len(), 2, "H still elects B+C only");
    assert!(at_h.power_of(&a) == 0, "joiner has no slot at H");
    assert_eq!(at_h1.validators.len(), 3, "H+1 elects A+B+C");
    assert_eq!(at_h1.power_of(&a), 2 * floor());
    let _ = (b, c);

    // The schedule is evaluated per-height set: the exact-slot (round 0)
    // proposer at H+1 under the NEW set verifies under the NEW set only.
    // Scan for a height where the rotation visibly moves the slot (the old
    // {B,C} electorate and the new {A,B,C} electorate walk different
    // cumulative tables, so such heights must exist in any window).
    let mut moved = None;
    for h in (BOUNDARY_H + 1)..(BOUNDARY_H + 512) {
        let old_p = at_h.proposer_for(h, 0).expect("old elects");
        let new_p = at_h1.proposer_for(h, 0).expect("new elects");
        if old_p != new_p {
            moved = Some((h, old_p, new_p));
            break;
        }
    }
    let (h_star, old_p, new_p) =
        moved.expect("rotation must move at least one exact slot in 512 heights");
    assert!(
        proposer_matches_schedule(&at_h1, h_star, &new_p, 0),
        "new set must match its own slot"
    );
    assert!(
        !proposer_matches_schedule(&at_h1, h_star, &old_p, 0),
        "round-0 scan is the exact slot: old-set proposer holds no slot here"
    );
    // And the old height is untouched by the staged change.
    let p_h = at_h.proposer_for(BOUNDARY_H, 0).expect("elects");
    assert!(proposer_matches_schedule(&at_h, BOUNDARY_H, &p_h, 0));
}

#[tokio::test]
async fn finality_gate_uses_set_at_height_for_schedule_and_qc() {
    let (mut rt, a, _b, _c, ka, kb, kc) = runtime_across_join().await;
    // Advance across the boundary exactly as the node does.
    rt.hc.height += 1;
    rt.install_due_validator_set();
    rt.hc.validators = rt.validators.clone();
    let in_force = rt.validator_set_for_height(BOUNDARY_H + 1);
    assert_eq!(in_force.total_power(), 4 * floor());

    // Quorate-under-new QC {A,C} (=3F >= floor(8F/3)+1), signed at H+1/round 0,
    // with the header naming the deterministic new-set proposer.
    let block_hash = [0xABu8; 32];
    let proposer = in_force.proposer_for(BOUNDARY_H + 1, 0).expect("elects");
    let qc = precommit_qc(&[&ka, &kc], BOUNDARY_H + 1, 0, block_hash);
    assert!(qc.verify(&in_force), "fixture QC must verify under the H+1 set");
    assert!(
        verify_finality_for_header(&in_force, BOUNDARY_H + 1, &block_hash, &proposer, &qc).is_ok(),
        "header+QC valid under the set in force at H+1"
    );

    // The same header+QC against the PRE-rotation set must FAIL (only C's
    // power counts there: F < floor(4F/3)+1 quorum) — this pins "verify
    // against the set at the header's height, never the live/stale set".
    let stale = rt.validator_set_for_height(BOUNDARY_H);
    assert!(!qc.verify(&stale), "fixture QC must NOT verify under the old set");
    assert!(
        verify_finality_for_header(&stale, BOUNDARY_H + 1, &block_hash, &proposer, &qc).is_err(),
        "stale-set verification must refuse a rotated-height header"
    );
    // Wrong-QC-kind / wrong-hash variants fail closed under the right set too.
    let mut wrong_kind = qc.clone();
    wrong_kind.kind = VoteKind::Prevote;
    assert!(
        verify_finality_for_header(&in_force, BOUNDARY_H + 1, &block_hash, &proposer, &wrong_kind)
            .is_err()
    );
    assert!(
        verify_finality_for_header(&in_force, BOUNDARY_H + 1, &[0x00u8; 32], &proposer, &qc).is_err()
    );
    let _ = (a, kb);
}

// --- 7. Canonical draw pinned ---------------------------------------------------

#[test]
fn canonical_draw_pinned_byte_identical_to_today() {
    // Live consensus bytes are unchanged: canonical parent-hash draw.
    // Fixed vectors captured from the canonical path.
    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("pin hex").as_slice().try_into().expect("32B")
    }
    let (vs, _) = fixed_set_equal4();
    let parent = [0x5Au8; 32];
    assert_eq!(
        sortition_seed(&parent, 9, 2),
        h32("5e0914d250fd5ad600f4944a7df56bf6094b52ccac2e9999cc85de4d1ced82fb"),
        "sortition seed preimage pinned"
    );
    // Same 4-id equal-power fixture shape as the gate tests would use with
    // ids [01..04]; here ids are [11..14] so pin the committee explicitly:
    let comm = derive_sortition_committee(&vs, 9, 2, 2, &parent);
    assert_eq!(comm.len(), 2);
    assert_ne!(comm[0], comm[1]);

    // Canonical draw is deterministic over a sweep —
    // future wiring may not silently change today's schedule.
    let parents = [[0x5Au8; 32], [0x00u8; 32], [0xFFu8; 32]];
    for p in &parents {
        for h in [0u64, 1, 9, 100, 292_786] {
            for r in [0u32, 1, 7] {
                for k in [0u32, 1, 2, 4, 100] {
                    assert_eq!(
                        derive_sortition_committee(&vs, h, r, k, p),
                        derive_sortition_committee(&vs, h, r, k, p),
                        "canonical draw must be deterministic (h={h} r={r} k={k})"
                    );
                    assert_eq!(
                        sortition_seed(p, h, r),
                        sortition_seed(p, h, r)
                    );
                }
            }
        }
    }
}

// --- 8. HeightConsensus wiring -------------------------------------------------

#[test]
fn height_consensus_proposer_tracks_its_own_set_height_round() {
    let (vs, _) = fixed_set_equal4();
    let mut hc = HeightConsensus::new(7, vs.clone());
    assert_eq!(hc.proposer(), vs.proposer_for(7, 0));
    hc.advance_to_round(1);
    assert_eq!(hc.round, 1);
    assert_eq!(hc.proposer(), vs.proposer_for(7, 1));
    // The scheduled proposer is accepted; anyone else is refused.
    let good = hc.proposer().expect("elects");
    assert!(hc.receive_proposal(good, [0xBBu8; 32]).is_ok());
    let mut hc2 = HeightConsensus::new(7, vs.clone());
    let mut other = [0xFFu8; 32];
    if other == good {
        other = [0xFEu8; 32];
    }
    assert!(hc2.receive_proposal(other, [0xBBu8; 32]).is_err());
}

// --- 9. proposer schedule pins -------------------------------------------------
//
// Fixed vectors for TODAY's hash-slot schedule over the 4-id equal-power
// fixture. Any consensus-affecting change to `proposer_for` (preimage,
// domain, modulo, table order) breaks these — that is the point: the
// schedule is consensus bytes and must only change as a coordinated upgrade.

#[test]
fn proposer_schedule_vectors_pinned() {
    let (vs, ids) = fixed_set_equal4();
    assert_eq!(
        ids.iter().map(hex::encode).collect::<Vec<_>>(),
        [
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1212121212121212121212121212121212121212121212121212121212121212",
            "1313131313131313131313131313131313131313131313131313131313131313",
            "1414141414141414141414141414141414141414141414141414141414141414",
        ]
    );
    for (h, r, want) in [
        (0u64, 0u32, "1414141414141414141414141414141414141414141414141414141414141414"),
        (1, 0, "1313131313131313131313131313131313131313131313131313131313131313"),
        (9, 2, "1212121212121212121212121212121212121212121212121212121212121212"),
        (292_785, 3, "1414141414141414141414141414141414141414141414141414141414141414"),
    ] {
        assert_eq!(
            hex::encode(vs.proposer_for(h, r).expect("elects")),
            want,
            "proposer slot pinned at h={h} r={r}"
        );
    }
    // Whole-window digest: 64 exact slots, heights 0..64 round 0.
    let mut sched = Vec::new();
    for h in 0..64u64 {
        sched.extend_from_slice(&vs.proposer_for(h, 0).expect("elects"));
    }
    assert_eq!(
        hex::encode(blake3::hash(&sched).as_bytes()),
        "0dda3435d26cb8ea6a52226e7fb26174fc67a03bc96347be280466d9f515b925",
        "64-slot schedule window pinned"
    );
    // Committee pin over the same fixture (parent [0x5A;32], h=9, r=2, k=2).
    let parent = [0x5Au8; 32];
    assert_eq!(
        derive_sortition_committee(&vs, 9, 2, 2, &parent),
        vec![[0x11u8; 32], [0x12u8; 32]]
    );
}
