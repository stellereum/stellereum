//! Regression tests for section-1 proposal refire spam observed live:
//! the SAME proposal hash broadcast 3-7x per round (~100-500ms apart), each a
//! full request_to round trip multiplying consensus traffic.
//!
//! Root cause (see `ValidatorRuntime::propose` in src/runtime.rs): the section-1
//! gate in main.rs (`is_proposer && !has_live_proposal && pacing`) is supposed
//! to fire once because `propose()` self-records via `receive_proposal`. But
//! only the FRESH path self-records. The LOCKED re-proposal path and the
//! DEMANDED (lock-hint rescue) path return `Some(body)` WITHOUT recording, so
//! `has_live_proposal()` stays false and the gate refires every loop tick
//! (~100ms) until the round changes -- one broadcast per tick, identical hash.
//!
//! Audit of every writer of `hc.proposal / hc.proposal_round` (src/consensus.rs):
//!   * set: only `receive_proposal` (called from fresh `propose` + `on_proposal`)
//!   * cleared: only `sync_round_to` / `next_round` / `advance_to_round`,
//!     ALL of which advance `round` first. Nothing clears within a round.
//!     So candidates (a) "cleared without round change" and (b) "propose returns
//!     None after logging" are excluded by inspection; (c) "local round vs hc.round
//!     skew" cannot happen either (no message handling runs between the gate check
//!     and `propose()`'s record). The refire is the two unrecorded `Some` paths.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{ValidatorSet, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;

/// Single validator: always the proposer at every round, so `propose()` is
/// always eligible and any refire is purely a gating failure.
fn single_node() -> ValidatorRuntime {
    let key = SigningKey::generate(&mut OsRng);
    let id = key.verifying_key().to_bytes();
    let vset = ValidatorSet::from_list(vec![(id, 1)]);
    let state = Arc::new(InMemoryStateEngine::new());
    ValidatorRuntime::new(key, vset, state, 1)
}

/// The section-1 gate predicate from main.rs (minus pacing, which only admits
/// MORE ticks over time, never fewer).
fn section1_gate(rt: &ValidatorRuntime) -> bool {
    rt.is_proposer() && !rt.hc.has_live_proposal()
}

/// Drive the gate the way the consensus loop does for `ticks` iterations and
/// count broadcasts. Healthy: exactly 1 per round.
async fn drive_gate_ticks(rt: &mut ValidatorRuntime, ticks: usize) -> Vec<[u8; 32]> {
    let mut broadcasts = Vec::new();
    for _ in 0..ticks {
        if section1_gate(rt) {
            if let Some(block) = rt.propose(1_000).await {
                broadcasts.push(block.compute_hash());
            }
        }
    }
    broadcasts
}

// ============================================================================
// 1. Fresh path: the control case. Self-records, gate fires exactly once.
// ============================================================================

#[tokio::test]
async fn fresh_propose_self_records_and_gate_fires_once() {
    let mut rt = single_node();
    assert!(rt.is_proposer());

    let b1 = rt.propose(1_000).await.expect("fresh propose must succeed");
    assert!(
        rt.hc.has_live_proposal(),
        "fresh propose must self-record a live proposal"
    );

    // Second call same round without clearing: identical hash or None.
    let b2 = rt.propose(1_000).await;
    if let Some(b) = b2 {
        assert_eq!(
            b.compute_hash(),
            b1.compute_hash(),
            "repeat propose must be identical, never a new block"
        )
    }

    let broadcasts = drive_gate_ticks(&mut rt, 5).await;
    assert!(
        broadcasts.is_empty(),
        "gate must stay closed after a fresh propose, got {} extra broadcast(s)",
        broadcasts.len()
    );
}

// ============================================================================
// 2. LOCKED path refire (the live bug): lock, view-change, re-propose.
// ============================================================================

#[tokio::test]
async fn locked_reproposal_records_live_proposal_and_broadcasts_once() {
    let mut rt = single_node();

    // Round 0: fresh proposal, hash H.
    let b0 = rt.propose(1_000).await.expect("fresh propose must succeed");
    let h = b0.compute_hash();

    // Lock on H (as `make_precommit` would), then view-change to round 1.
    // We still own round 1 (single validator).
    rt.hc.locked = Some((h, 0));
    rt.next_round();
    assert_eq!(rt.hc.round, 1);
    assert!(rt.is_proposer());
    assert!(
        !rt.hc.has_live_proposal(),
        "precondition: view change clears the round-0 proposal"
    );

    // Round 1: locked re-proposal serves the identical body...
    let b1 = rt
        .propose(1_000)
        .await
        .expect("locked re-proposal must succeed");
    assert_eq!(
        b1.compute_hash(),
        h,
        "locked re-proposal must serve the identical locked body"
    );
    // ...AND must close the gate (this is the assertion that fails pre-fix:
    // the locked path returned Some without receive_proposal, so the gate
    // stayed open and every 100ms tick rebroadcast the identical hash).
    assert!(
        rt.hc.has_live_proposal(),
        "BUG: locked re-proposal did not record a live proposal -- \
         section-1 gate refires every tick (identical-hash spam)"
    );

    // Repeat call same round: identical or None, never a novel block.
    if let Some(b) = rt.propose(1_000).await {
        assert_eq!(b.compute_hash(), h)
    }

    // Full gate simulation: 7 ticks (one round at 100ms/tick with pacing
    // saturated) must yield ZERO further broadcasts, not 7x identical hash.
    let broadcasts = drive_gate_ticks(&mut rt, 7).await;
    assert!(
        broadcasts.is_empty(),
        "gate must stay closed after locked re-proposal, got {} identical rebroadcast(s)",
        broadcasts.len()
    );
}

// ============================================================================
// 3. DEMANDED (lock-hint rescue) path refire: same shape, same bug.
// ============================================================================

#[tokio::test]
async fn demanded_reproposal_records_live_proposal_and_broadcasts_once() {
    let mut rt = single_node();

    // Round 0: fresh proposal so we own a body a peer could be locked on.
    let b0 = rt.propose(1_000).await.expect("fresh propose must succeed");
    let h = b0.compute_hash();

    // View-change to round 1, then a nil-prevote lock hint demanding OUR body.
    rt.next_round();
    assert_eq!(rt.hc.round, 1);
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(h));

    // Round 1: demanded path serves our body verbatim...
    let b1 = rt
        .propose(1_000)
        .await
        .expect("demanded re-proposal must succeed");
    assert_eq!(
        b1.compute_hash(),
        h,
        "demanded re-proposal must serve the identical demanded body"
    );
    // ...AND must close the gate (fails pre-fix for the same reason).
    assert!(
        rt.hc.has_live_proposal(),
        "BUG: demanded re-proposal did not record a live proposal -- \
         section-1 gate refires every tick (identical-hash spam)"
    );

    let broadcasts = drive_gate_ticks(&mut rt, 7).await;
    assert!(
        broadcasts.is_empty(),
        "gate must stay closed after demanded re-proposal, got {} identical rebroadcast(s)",
        broadcasts.len()
    );
}

// ============================================================================
// 4. End-to-end spam shape: locked round broadcasts exactly once per round.
// ============================================================================

#[tokio::test]
async fn locked_round_broadcasts_exactly_once_not_once_per_tick() {
    let mut rt = single_node();
    let b0 = rt.propose(1_000).await.expect("fresh propose must succeed");
    let h = b0.compute_hash();
    rt.hc.locked = Some((h, 0));
    rt.next_round();

    // Simulate one full round of the main loop at 100ms/tick with pacing
    // already saturated (worst case for spam: gate evaluated every tick).
    let broadcasts = drive_gate_ticks(&mut rt, 30).await;
    assert_eq!(
        broadcasts.len(),
        1,
        "one round must produce exactly 1 broadcast, got {} (all identical: {})",
        broadcasts.len(),
        broadcasts.iter().all(|b| *b == h),
    );
    assert_eq!(broadcasts[0], h);
}

// ============================================================================
// 5. Candidate triggers that must NOT refire (exclusion evidence):
//    (a) no writer clears proposal without advancing the round;
//    (c) the gate reopens exactly once after a round change (a round nudge is
//        allowed to reopen it -- that is a NEW round, not a refire).
// ============================================================================

#[tokio::test]
async fn round_nudge_reopens_gate_once_not_per_tick() {
    let mut rt = single_node();
    rt.propose(1_000).await.expect("fresh propose must succeed");
    assert!(rt.hc.has_live_proposal());

    // A verified peer one round ahead PULLS us there (deliberate: two honest
    // nodes must be able to meet in one round to form a same-round QC;
    // suppressing 1..3-round sync left a permanent 1-round offset that made
    // every height burn ~10 rounds on the live stand). The jump is what
    // reopens the gate -- and it reopens ONCE.
    let moved = rt.note_peer_vote_round(rt.hc.height, rt.hc.round + 1);
    assert!(moved, "verified near-peer vote must follow into its round");
    assert!(
        !rt.hc.has_live_proposal(),
        "the nudge is a new round: old proposal retired"
    );

    // The gate itself drives the single broadcast for the new round; 30 further
    // ticks must not produce a second one.
    let broadcasts = drive_gate_ticks(&mut rt, 30).await;
    assert_eq!(
        broadcasts.len(),
        1,
        "a reopened gate must fire exactly once, got {} (identical: {})",
        broadcasts.len(),
        broadcasts.iter().all(|b| *b == broadcasts[0]),
    );

    // Syncing to our OWN round is a no-op and never clears anything.
    rt.hc.sync_round_to(rt.hc.round);
    assert!(
        rt.hc.has_live_proposal(),
        "sync to the same round must not clear the proposal"
    );
}

#[tokio::test]
async fn new_round_reopens_gate_for_a_new_proposal() {
    let mut rt = single_node();
    let b0 = rt.propose(1_000).await.expect("fresh propose must succeed");
    let h0 = b0.compute_hash();

    // Fresh round with no lock: gate reopens (round advanced, old proposal
    // cleared) and proposing again is allowed -- liveness preserved.
    rt.next_round();
    assert!(section1_gate(&rt), "gate must reopen after a view change");
    let b1 = rt
        .propose(2_000)
        .await
        .expect("must propose in the new round");
    assert!(rt.hc.has_live_proposal());
    let _ = (h0, b1);
}
