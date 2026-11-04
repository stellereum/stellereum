//! Deadlock breaker regression: live 2026-10-14 A r1550 vs B r318 at h92078.
//!
//! The wedge: `sync_round_to` (+8, 4/sec) + `MAX_ROUND_AHEAD` (1000) made
//! convergence impossible — A dropped B's votes as stale, B dropped A's as
//! absurd (+1000), the gap grew (~0.1 rounds/s) with no self-healing.
//! Fixed by (a) stale votes feeding the peer-round counter (no voting) and
//! (b) a circuit breaker: no finalization for N minutes
//! (`STELL_DEADLOCK_TIMEOUT_SECS`, default 300) with live peers => one
//! bounded forward-only jump to max(peer rounds), at most once per window.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stellereum::consensus::{
    HeightConsensus, ValidatorSet, Vote, VoteKind, MAX_SYNC_JUMPS_PER_ROUND, ROUND_LOOKBACK,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

fn rt_at(ks: &[SigningKey], me: usize, height: u64) -> ValidatorRuntime {
    let vs = vset(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    ValidatorRuntime::new(ks[me].clone(), vs, st, height)
}

#[test]
fn stale_vote_feeds_round_counter_without_voting() {
    let ks = keys(2);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(92078, vs.clone());
    hc.round = 318;

    // Peer's far-ahead vote: absurd (>1000) so `add_prevote` rejects it.
    let far = Vote::sign(&ks[0], 92078, 1550, VoteKind::Prevote, Some([1u8; 32]));
    assert!(hc.add_prevote(far.clone()).is_err());
    // ...but the verified round still lands in the counter (no voting).
    assert!(far.verify());
    let moved = hc.observe_peer_round(far.voter, far.round);
    // F3 corroboration (72bcfd8 2026-10-30): a SINGLE far-future vote is one
    // peer's claim, not the network's position -- it feeds the counter but no
    // longer moves the round (trickle-drag: one dribbled vote per timeout
    // would ratchet +8/timeout and silence us).
    assert!(
        !moved,
        "single uncorroborated far vote must feed the counter but not move us"
    );
    assert_eq!(hc.round, 318, "no chase on an uncorroborated far round");
    assert_eq!(hc.max_peer_round(), Some(1550));
    // A SECOND distinct validator vouching for the same far round is the
    // network's real position: corroboration re-opens the bounded chase.
    let corroborator = Vote::sign(&ks[1], 92078, 1550, VoteKind::Prevote, Some([1u8; 32]));
    assert!(corroborator.verify());
    let moved2 = hc.observe_peer_round(id(&ks[1]), corroborator.round);
    assert!(moved2, "corroborated far round must chase");
    // Bounded chase: +8 per message, NOT a jump to 1550.
    assert_eq!(hc.round, 318 + 8, "stale sync stays capped at +8");
    // The far vote formed no quorum.
    assert_eq!(hc.try_prevote_quorum(), None);
}

#[test]
fn stale_behind_vote_never_drags_ahead_backwards() {
    let ks = keys(2);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(92078, vs.clone());
    hc.round = 1550;

    let behind = Vote::sign(&ks[1], 92078, 318, VoteKind::Prevote, Some([2u8; 32]));
    // Stored under its own round bucket, but far outside the 8-round
    // finalization window — so it can never vote or form a quorum here...
    let _ = hc.add_prevote(behind.clone());
    assert_eq!(hc.try_prevote_quorum(), None);
    // ...and observing it records the counter but never moves backwards.
    assert!(!hc.observe_peer_round(behind.voter, behind.round));
    assert_eq!(hc.round, 1550);
    assert_eq!(hc.max_peer_round(), Some(318));
    assert_eq!(
        hc.deadlock_breaker_target(10_000, 300),
        None,
        "ahead node has nothing to jump to"
    );
}

#[test]
fn breaker_decision_is_pure_and_forward_only() {
    let ks = keys(2);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(92078, vs.clone());
    hc.round = 318;
    hc.observe_peer_round(id(&ks[0]), 1550);

    assert_eq!(
        hc.deadlock_breaker_target(299, 300),
        None,
        "no fire before timeout"
    );
    assert_eq!(hc.deadlock_breaker_target(300, 300), Some(1550));
    assert!(hc.apply_deadlock_jump(1550));
    assert_eq!(hc.round, 1550);
    assert!(!hc.apply_deadlock_jump(1550), "same round is a no-op");
    assert!(!hc.apply_deadlock_jump(100), "never backwards");
}

#[test]
fn deadlock_timeout_defaults_to_300s() {
    let saved = std::env::var("STELL_DEADLOCK_TIMEOUT_SECS").ok();
    // SAFETY: single test in this file touches this var; restored below.
    unsafe { std::env::remove_var("STELL_DEADLOCK_TIMEOUT_SECS") };
    assert_eq!(HeightConsensus::deadlock_timeout_secs(), 300);
    unsafe { std::env::set_var("STELL_DEADLOCK_TIMEOUT_SECS", "60") };
    assert_eq!(HeightConsensus::deadlock_timeout_secs(), 60);
    unsafe {
        match saved {
            Some(v) => std::env::set_var("STELL_DEADLOCK_TIMEOUT_SECS", v),
            None => std::env::remove_var("STELL_DEADLOCK_TIMEOUT_SECS"),
        }
    };
}

#[tokio::test]
async fn two_nodes_with_1200_round_desync_converge_without_restart() {
    let ks = keys(2);
    const H: u64 = 92078;
    let mut a = rt_at(&ks, 0, H);
    let mut b = rt_at(&ks, 1, H);
    // Live shape: A r1550, B r318 (gap 1232 > MAX_ROUND_AHEAD=1000).
    a.hc.round = 1550;
    b.hc.round = 318;

    // Both have been stuck: backdate progress past the default 300s timeout.
    a.last_progress_at = Instant::now() - Duration::from_secs(400);
    b.last_progress_at = Instant::now() - Duration::from_secs(400);

    // The network delivers A's vote to B. Old code dropped it as absurd and
    // learned nothing; now `on_prevote` rejects the VOTE but records the
    // peer round (counter only) with a budget-bounded chase toward it (the
    // future-round rule: converge within the per-round jump budget, never
    // teleport -- the corroborated breaker below still owns the huge jump).
    let a_vote = Vote::sign(&ks[0], H, 1550, VoteKind::Prevote, Some([7u8; 32]));
    assert!(
        b.on_prevote(a_vote.clone()).is_err(),
        "far-ahead vote must not count as a vote"
    );
    assert_eq!(
        b.hc.max_peer_round(),
        Some(1550),
        "stale vote must feed the counter"
    );
    assert!(
        b.hc.round > 318 && b.hc.round <= 318 + MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK,
        "budget-bounded chase only, got r{}",
        b.hc.round
    );

    // And B's stale vote to A records without dragging A backwards.
    let b_vote = Vote::sign(&ks[1], H, 318, VoteKind::Prevote, Some([7u8; 32]));
    let _ = a.on_prevote(b_vote);
    assert_eq!(a.hc.round, 1550, "ahead node never moves backwards");

    // Circuit breaker: B has had no progress for >timeout with a live peer
    // ahead => one bounded jump straight to max(peer rounds).
    let jumped = b.check_deadlock_breaker();
    assert_eq!(
        jumped,
        Some(1550),
        "breaker must jump B to max(peer rounds)"
    );
    assert_eq!(b.hc.round, 1550);
    assert_eq!(
        a.hc.round, 1550,
        "both nodes now share the round, no restart"
    );

    // Rate limit: a second immediate call must not jump again.
    assert_eq!(
        b.check_deadlock_breaker(),
        None,
        "breaker fires at most once per window"
    );

    // Same objects, no restart: both can now form quorums at the joined round.
    let bh = [9u8; 32];
    for k in &ks {
        let v = Vote::sign(k, H, 1550, VoteKind::Prevote, Some(bh));
        let _ = a.on_prevote(v.clone());
        let _ = b.on_prevote(v);
    }
    assert!(a.hc.try_prevote_quorum().is_some());
    assert!(b.hc.try_prevote_quorum().is_some());
    for k in &ks {
        let v = Vote::sign(k, H, 1550, VoteKind::Precommit, Some(bh));
        let _ = a.on_precommit(v.clone());
        let _ = b.on_precommit(v);
    }
    assert_eq!(a.hc.try_precommit_quorum(), Some(bh));
    assert_eq!(b.hc.try_precommit_quorum(), Some(bh));
    assert_eq!(a.hc.decided, Some(bh));
    assert_eq!(b.hc.decided, Some(bh));
}

// --- Pure no-progress fallback (live: A r1595 vs B r412, EMPTY peer rounds).
//
// Per-vote round-sync is capped (+8/4s) and stale/absurd votes are dropped,
// so with no processed votes both nodes sit deaf forever and the jump breaker
// (`deadlock_breaker_target` -> max(peer rounds)) never fires. The local
// reset below fires on the same no-finality timer with zero/default peer
// rounds: bounded re-entry to round 0 of the SAME height, dropping only a
// bodyless lock. Local policy only, no wire change.

#[test]
fn breaker_fires_with_empty_peer_set() {
    let ks = keys(2);
    let vs = vset(&ks);
    // Live shape: high round, zero verified peer votes (empty counter).
    let mut hc = HeightConsensus::new(92079, vs.clone());
    hc.round = 412;
    hc.locked = Some(([42u8; 32], 400)); // body never received -> bodyless
    assert_eq!(hc.max_peer_round(), None);
    // Jump path cannot fire with no peers (the observed deadlock).
    assert_eq!(hc.deadlock_breaker_target(400, 300), None);
    // ...but the no-progress local reset is due on the same timer.
    assert!(hc.deadlock_local_reset_due(400, 300));
    assert!(
        !hc.deadlock_local_reset_due(299, 300),
        "no fire before timeout"
    );
    // Gate precondition for the drop below: bodyless AND no precommit QC
    // observed anywhere (no votes at all here). Had a QC been observed, the
    // lock would survive (see breaker_local_reset_keeps_bodyless_lock_when_...).
    assert!(
        !hc.precommit_qc_observed(),
        "empty vote sets => gate passes"
    );
    // Bodyless lock with no QC behind it is dropped, the round ADVANCES (it is
    // never rewound: re-voting an already-used round is a self-equivocation),
    // and the quorum-scan window is widened so the round the network is
    // actually in becomes committable. Height untouched.
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(
        hc.round, 413,
        "the re-phase must move FORWARD, never rewind"
    );
    assert_eq!(hc.locked, None);
    assert_eq!(hc.height, 92079);
    assert_eq!(hc.decided, None);
    assert_eq!(
        hc.scan_lookback,
        stellereum::consensus::REPHASE_SCAN_WINDOW,
        "the re-phase must widen the quorum-scan window"
    );
    // Idempotent: nothing left to do, so the caller skips stamping/logging.
    assert!(!hc.apply_deadlock_local_reset(false));
    assert_eq!(hc.round, 413);
    assert_eq!(hc.height, 92079);
}

#[test]
fn breaker_local_reset_keeps_bodyless_lock_when_precommit_qc_observed() {
    // Fork-hardening (audit-consensus): a bodyless lock backed by an observed
    // precommit QC MUST survive the reset — dropping it lets this node finalize
    // B at round 0 while QC holders finalize A. Fixture: precommit quorum for
    // A observed (votes seen, body missing), no prevote QC run, so nothing is
    // decided and the no-progress reset is still due.
    const H: u64 = 92079;
    let ks = keys(4);
    let vs = vset(&ks);
    let a = [42u8; 32];
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 412;
    hc.locked = Some((a, 400)); // bodyless: `blocks` has no `a`
                                // 3-of-4 precommits for A at the current round: QC observable, but no
                                // prevote QC, so `try_precommit_quorum` could never decide (not called).
    for k in ks.iter().take(3) {
        let v = Vote::sign(k, H, 412, VoteKind::Precommit, Some(a));
        hc.add_precommit(v).unwrap();
    }
    assert!(
        hc.precommit_qc_observed(),
        "quorum of precommits must be observable"
    );
    assert_eq!(hc.decided, None, "no prevote QC => nothing decided");
    assert!(
        hc.deadlock_local_reset_due(400, 300),
        "no peer ahead => reset path owns it"
    );
    // Reset still advances the round and prunes — but the lock survives.
    assert!(
        hc.apply_deadlock_local_reset(false),
        "round advance still happens"
    );
    assert_eq!(
        hc.round, 413,
        "the re-phase must move FORWARD, never rewind"
    );
    assert_eq!(
        hc.locked,
        Some((a, 400)),
        "QC-backed bodyless lock must survive"
    );
    assert_eq!(hc.height, H);
    assert_eq!(hc.decided, None);
    // Steady state afterwards: keeping a non-droppable lock at pristine round 0
    // is a no-op, so the caller rate-limit path skips stamping/logging.
    assert!(!hc.apply_deadlock_local_reset(false));
    assert_eq!(hc.locked, Some((a, 400)));
}

#[test]
fn breaker_local_reset_keeps_lock_when_deciding_qc_banked() {
    // Same rule via the banked-QC half of the gate: once `precommit_qc` is set,
    // no reset drops the lock even with empty vote sets (e.g. post-prune).
    const H: u64 = 92079;
    let ks = keys(4);
    let vs = vset(&ks);
    let a = [7u8; 32];
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 5;
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, H, 5, VoteKind::Prevote, Some(a)))
            .unwrap();
        hc.add_precommit(Vote::sign(k, H, 5, VoteKind::Precommit, Some(a)))
            .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(a),
        "A decides and banks its QC"
    );
    // Simulate "decided but never executed" (body missing): progress never
    // stamped, so the timer lapses with no peer ahead.
    hc.round = 412;
    assert!(hc.precommit_qc_observed());
    assert!(hc.deadlock_local_reset_due(400, 300));
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(
        hc.round, 413,
        "the re-phase must move FORWARD, never rewind"
    );
    assert_eq!(hc.locked, Some((a, 5)), "banked-QC lock must survive");
    assert_eq!(hc.decided, Some(a), "reset never clears decided");
    assert_eq!(hc.height, H);
}

#[test]
fn breaker_local_reset_keeps_lock_whose_body_we_hold() {
    let ks = keys(2);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(92079, vs.clone());
    hc.round = 1595;
    hc.locked = Some(([7u8; 32], 1500)); // body IS in our store
    assert!(hc.deadlock_local_reset_due(10_000, 300));
    assert!(
        hc.apply_deadlock_local_reset(true),
        "bodied lock: still advances the round"
    );
    assert_eq!(
        hc.round, 1596,
        "the re-phase must move FORWARD, never rewind"
    );
    assert_eq!(
        hc.locked,
        Some(([7u8; 32], 1500)),
        "bodied lock must survive"
    );
    assert_eq!(hc.height, 92079);
}

#[test]
fn breaker_peer_ahead_path_still_owns_the_jump() {
    // Existing behavior unchanged: with a verified peer ahead, the jump path
    // fires and the local reset defers to it.
    let ks = keys(2);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(92078, vs.clone());
    hc.round = 318;
    hc.observe_peer_round(id(&ks[0]), 1550);
    assert_eq!(hc.deadlock_breaker_target(400, 300), Some(1550));
    assert!(
        !hc.deadlock_local_reset_due(400, 300),
        "peer-ahead => jump path owns it"
    );
}

#[test]
fn breaker_does_not_fire_when_finality_progresses() {
    let ks = keys(2);
    const H: u64 = 92079;
    // Consensus-level: fresh progress => neither path is due.
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 412;
    assert!(!hc.deadlock_local_reset_due(10, 300));
    assert_eq!(hc.deadlock_breaker_target(10, 300), None);
    // Runtime-level: a node at a high round with EMPTY peers but RECENT
    // finality must not reset (round preserved).
    let mut rt = rt_at(&ks, 1, H);
    rt.hc.round = 412;
    // `rt_at` stamps progress at construction => no-progress window not met.
    assert_eq!(rt.check_deadlock_breaker(), None);
    assert!(!rt.hc.deadlock_local_reset_due(
        rt.last_progress_at.elapsed().as_secs(),
        HeightConsensus::deadlock_timeout_secs(),
    ));
    assert_eq!(rt.hc.round, 412, "recent progress must preserve the round");
    // Same after an explicit progress stamp on a backdated node.
    rt.last_progress_at = Instant::now() - Duration::from_secs(400);
    rt.record_progress();
    assert!(!rt.hc.deadlock_local_reset_due(
        rt.last_progress_at.elapsed().as_secs(),
        HeightConsensus::deadlock_timeout_secs(),
    ));
    assert_eq!(rt.hc.round, 412);
}

#[test]
fn breaker_never_moves_height_backward() {
    let ks = keys(2);
    const H: u64 = 92079;
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 1595;
    hc.locked = Some(([9u8; 32], 1500));
    // A live proposal from the stuck round is cleared, never carried over.
    hc.proposal = Some((id(&ks[0]), [9u8; 32]));
    hc.proposal_round = Some(1595);
    assert!(hc.deadlock_local_reset_due(600, 300));
    assert!(hc.apply_deadlock_local_reset(true));
    assert_eq!(hc.height, H, "reset must never change height");
    assert_eq!(
        hc.round, 1596,
        "the re-phase must move FORWARD, never rewind"
    );
    assert_eq!(hc.decided, None);
    // Repeated resets (once per window, as the caller rate-limits) never
    // drift the height either.
    assert!(
        !hc.apply_deadlock_local_reset(true),
        "second reset is a no-op"
    );
    assert_eq!(hc.height, H);
    assert_eq!(hc.round, 1596);
    // And the jump path still never moves backwards.
    assert!(!hc.apply_deadlock_jump(0));
    assert_eq!(hc.height, H);
}
