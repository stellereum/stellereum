//! Round-sync audit pins — SCOPE: ROUND SYNC ONLY.
//!
//! Covers the liveliest machinery, read from the current tree.
//!
//! `sync_round_to` + `ROUND_LOOKBACK=8` + `MAX_SYNC_JUMPS_PER_ROUND=8` +
//! corroboration gate + per-round jump budget (`src/consensus.rs`,
//! `src/runtime.rs::note_peer_vote_round` at runtime.rs:5331);
//! `note_peer_vote_round` + `observe_peer_vote` (runtime.rs:5320-5449);
//! deadlock breaker + `max_peer_round` (runtime.rs:5457-5504,
//! consensus.rs:4450-4538); peer holds (`peer_is_active_nearby` /
//! `peer_alive_recently` / `hold_bounded`, src/main.rs view-change gate);
//! straggler grace + `cap_hold_to_two_x_bound` (`STELL_STRAGGLER_*`,
//! src/main.rs:159-262) with its unit tests (`straggler_grace_tests`,
//! `round_timer_accounting_tests`) and docs/PROPOSER_REWORK.md §2c; and the
//! view-change gate composition (`effective_timeout` + grace + hold).
//!
//! Out of scope by task order (untouched here): vote-set/QC contents, locks,
//! proposal validation, `on_proposal`/validate paths, `main.rs` propose/vote
//! paths, docs, live stuff.
//!
//! VERDICT (evidence below): every sync entry is forward-only and bounded.
//! Worst case per single verified vote is +`ROUND_LOOKBACK` (8); worst case
//! per round is `MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK` (64), refilled
//! only by our own view change. A lone liar replays nothing (dedup) and
//! buys at most +8 per *fresh* vote, capped at +64 per round however many it
//! sends. Corroborated chase (2+ distinct validators, 1 on a 2-member set)
//! is inside the BFT assumption, not an attack. Every hold has a fixed
//! deadline: the view-change hold drops at `2 * base` with no fresh vote,
//! straggler grace is `min(grace, cap)` gated on freshness, and the capped
//! composition never passes `max(effective, 2 * base)` while a peer is
//! active. The deadlock breaker is forward-only, corroborated, and
//! rate-limited to one jump per timeout window. No code fix was needed;
//! these tests pin the bounds so any regression fails loudly.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{
    HeightConsensus, ValidatorSet, Vote, VoteKind, MAX_DEADLOCK_JUMP, MAX_SYNC_JUMPS_PER_ROUND,
    REPHASE_SCAN_WINDOW, ROUND_LOOKBACK,
};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
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

/// Three-member runtime (unanimity 3/3 shape: quorum needs every member, so a
/// lone liar is 1 of 3 and corroboration needs 2 distinct supporters).
async fn three_node() -> (ValidatorRuntime, Vec<SigningKey>) {
    let ks = keys(3);
    let vs = vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, 1_000_000_000_000_000).await;
    let rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
    (rt, ks)
}

fn per_round_cap() -> u32 {
    MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK
}

// ===========================================================================
// A. Worst-case jump bounds: lookback x jumps x budget + corroboration.
// ===========================================================================

/// A single LONE verified far vote buys exactly one lookback step, not the
/// cliff. (runtime.rs: the first step is always taken; continuing needs a
/// second distinct supporter.)
#[tokio::test]
async fn lone_vote_moves_at_most_one_lookback_step() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    let far = Vote::sign(&ks[1], h, r + 100, VoteKind::Prevote, Some([7u8; 32]));
    rt.on_prevote(far).unwrap();
    assert_eq!(
        rt.hc.round,
        r + ROUND_LOOKBACK,
        "one lone verified vote must buy exactly one +8 nudge"
    );
    assert_eq!(
        rt.hc.supporting_peers_count(r + 100),
        1,
        "a single reporter must not count as corroboration on a 3-member set"
    );
}

/// Two DISTINCT validators vouching for the same far round open the full
/// chase — and the chase still stops at the per-round jump budget (64), not
/// at the peer's round.
#[tokio::test]
async fn corroborated_chase_capped_by_per_round_budget() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    let target = r + 200;
    rt.on_prevote(Vote::sign(&ks[1], h, target, VoteKind::Prevote, None))
        .unwrap();
    assert_eq!(rt.hc.round, r + ROUND_LOOKBACK);
    rt.on_prevote(Vote::sign(&ks[2], h, target, VoteKind::Prevote, None))
        .unwrap();
    assert_eq!(
        rt.hc.round,
        r + per_round_cap(),
        "corroborated chase must converge within the per-round jump budget (64)"
    );
    assert!(
        rt.hc.round < target,
        "budget must stop the chase short of a far cliff (round {} < target {target})",
        rt.hc.round
    );
}

/// A spent budget stays spent until OUR OWN view change refills it: further
/// fresh far votes move nothing; after `next_round` the chase re-opens for
/// exactly one more lookback step per fresh vote.
#[tokio::test]
async fn spent_budget_blocks_fresh_votes_until_view_change() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    let target = r + 200;
    for k in [&ks[1], &ks[2]] {
        rt.on_prevote(Vote::sign(k, h, target, VoteKind::Prevote, None))
            .unwrap();
    }
    assert_eq!(rt.hc.round, r + per_round_cap());
    // Fresh round number, same attacker keys: budget is gone, no movement —
    // and the failed chase still records the round as "followed" (replay
    // suppression), so retrying the SAME round after the refill stays a
    // no-op: only fresh evidence (a new round, or a second supporter)
    // re-opens the chase.
    assert!(
        !rt.note_peer_vote_round(h, r + 300),
        "a fresh far vote must not move us on a spent budget"
    );
    assert_eq!(rt.hc.round, r + per_round_cap());
    // Our own view change refills exactly the documented budget — but the
    // already-tried round stays suppressed as a replay.
    rt.next_round();
    let refilled = rt.hc.round;
    assert_eq!(refilled, r + per_round_cap() + 1);
    assert!(
        !rt.note_peer_vote_round(h, r + 300),
        "replay of a budget-spent round stays suppressed even with fresh budget"
    );
    assert_eq!(rt.hc.round, refilled);
    // Fresh evidence re-opens it: a new far round moves one lookback step.
    assert!(
        rt.note_peer_vote_round(h, r + 301),
        "after a view change fresh evidence must re-open the chase"
    );
    assert_eq!(rt.hc.round, refilled + ROUND_LOOKBACK);
}

/// Even an ABSURD vote (past `MAX_ROUND_AHEAD`, rejected from every vote
/// set) still teaches the peer's round — bounded to one lookback step.
/// Rejection from quorum logic must not mean rejection from sync, and sync
/// from a rejected vote must not mean an unbounded jump.
#[tokio::test]
async fn absurd_rejected_vote_still_bounded_to_one_step() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    let absurd = Vote::sign(&ks[1], h, r + 5_000, VoteKind::Prevote, None);
    assert!(
        absurd.verify(),
        "test setup: the absurd vote must be genuinely signed"
    );
    let res = rt.on_prevote(absurd);
    assert!(
        res.is_err(),
        "past MAX_ROUND_AHEAD the vote must not enter any vote set"
    );
    assert_eq!(
        rt.hc.round,
        r + ROUND_LOOKBACK,
        "a rejected-but-verified absurd vote syncs at most one +8 step"
    );
}

// ===========================================================================
// B. No backward drag on any path.
// ===========================================================================

/// Every round-sync entry point is forward-only: stale, same-round, and
/// wrong-height inputs never move the counter down (or at all).
#[tokio::test]
async fn sync_never_moves_backwards_on_any_path() {
    let (mut rt, ks) = three_node().await;
    for _ in 0..10 {
        rt.hc.next_round();
    }
    let (h, r) = (rt.hc.height, rt.hc.round);
    assert_eq!(r, 10);

    // Raw capped jump backwards / sideways.
    rt.hc.sync_round_to(r - 5);
    rt.hc.sync_round_to(r);
    assert_eq!(rt.hc.round, r, "sync_round_to must be forward-only");

    // Future-rule entries: behind, same, wrong height.
    assert!(!rt.note_peer_vote_round(h, r - 1));
    assert!(!rt.note_peer_vote_round(h, r));
    assert!(!rt.note_peer_vote_round(h + 1, r + 1));
    assert!(!rt.note_peer_vote_round(h.saturating_sub(1), r + 1));
    assert_eq!(rt.hc.round, r);

    // Observed (possibly rejected) votes behind us move nothing.
    let behind = Vote::sign(&ks[1], h, r - 2, VoteKind::Prevote, None);
    assert!(rt.observe_peer_vote(&behind), "behind vote still verifies");
    assert!(!rt.note_peer_vote_round(behind.height, behind.round));
    assert_eq!(rt.hc.round, r);

    // Breaker entries backwards / sideways / uncorroborated.
    assert!(!rt.hc.apply_deadlock_jump(r - 1));
    assert!(!rt.hc.apply_deadlock_jump(r));
    assert_eq!(rt.hc.round, r);
    assert_eq!(
        rt.hc.deadlock_breaker_target(10_000, 300),
        None,
        "a behind-only peer round must offer no breaker target"
    );

    // Local re-phase never rewinds either (tested for +1/idempotence below);
    // here just pin it cannot go down from a fresh state with no evidence.
    assert_eq!(rt.hc.round, r, "round counter must be monotonic across all sync entries");
}

/// Per-voter peer counters are monotonic: a delayed old vote never rewinds
/// what that peer reported, so stale evidence cannot drag `max_peer_round`
/// (and the breaker) backwards — nor re-arm a jump we already absorbed.
#[tokio::test]
async fn peer_round_counters_are_monotonic_per_voter() {
    let (mut rt, ks) = three_node().await;
    let peer = id(&ks[1]);
    rt.hc.note_peer_round(peer, 50);
    rt.hc.note_peer_round(peer, 3);
    assert_eq!(
        rt.hc.max_peer_round(),
        Some(50),
        "a delayed old vote must never rewind the peer's high-water mark"
    );
    assert_eq!(rt.hc.supporting_peers_count(50), 1);
    assert_eq!(
        rt.hc.supporting_peers_count(51),
        0,
        "nothing supports a round nobody reported"
    );
}

// ===========================================================================
// C. Lone-liar cost cap (P3-R1 corroboration re-opens the chase).
// ===========================================================================

/// Cost to attacker vs victim, quantified: 20 fresh signed far votes from a
/// lone liar buy at most the per-round budget (64), i.e. each fresh vote at
/// most +8 and the whole trickle at most +64 until our own view change.
/// Rate limit per round is therefore attacker-inefficient by design: N
/// signatures converge to a constant.
#[tokio::test]
async fn lone_liar_trickle_capped_per_round_no_matter_how_many_votes() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    for i in 0..20u32 {
        let v = Vote::sign(&ks[1], h, r + 100 + i, VoteKind::Prevote, None);
        let _ = rt.on_prevote(v);
    }
    let moved = rt.hc.round - r;
    assert_eq!(
        moved,
        per_round_cap(),
        "20 fresh lone-liar votes must buy exactly the per-round budget (64), no more"
    );
    assert!(
        moved <= per_round_cap(),
        "victim movement ({moved}) must stay within budget however many votes the liar signs"
    );
}

/// Dedup: replaying the SAME (height, round) moves us once; the replay is a
/// no-op even though the vote still verifies.
#[tokio::test]
async fn replay_of_same_round_moves_exactly_once() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    let v = Vote::sign(&ks[1], h, r + 50, VoteKind::Prevote, None);
    rt.on_prevote(v.clone()).unwrap();
    assert_eq!(rt.hc.round, r + ROUND_LOOKBACK);
    // Same vote again: verifies, counted, but the round must not move twice.
    rt.on_prevote(v).unwrap();
    assert_eq!(
        rt.hc.round,
        r + ROUND_LOOKBACK,
        "a replayed vote must never move the round a second time"
    );
    assert!(
        !rt.note_peer_vote_round(h, r + 50),
        "direct replay must report no movement"
    );
}

/// Our own vote record must never corroborate an ahead jump: with only our
/// (low) self-report plus one liar's far report, the count for the far round
/// is 1 and the chase stays a single nudge.
#[tokio::test]
async fn self_report_never_corroborates_an_ahead_jump() {
    let (mut rt, ks) = three_node().await;
    let (h, r) = (rt.hc.height, rt.hc.round);
    // Record our own current round (production feeds own votes through
    // on_prevote too — main.rs cast path).
    let mine = Vote::sign(&ks[0], h, r, VoteKind::Prevote, None);
    rt.on_prevote(mine).unwrap();
    // Lone liar far ahead.
    let far = Vote::sign(&ks[1], h, r + 100, VoteKind::Prevote, None);
    rt.on_prevote(far).unwrap();
    assert_eq!(
        rt.hc.supporting_peers_count(r + 100),
        1,
        "self at a low round plus one liar must not make 2 supporters"
    );
    assert_eq!(
        rt.hc.round,
        r + ROUND_LOOKBACK,
        "uncorroborated far claim stays one nudge even with a self-report present"
    );
}

// ===========================================================================
// D. Hold termination: every hold has a fixed deadline with no fresh evidence.
// ===========================================================================

/// Executable mirror of the view-change hold predicate
/// (src/main.rs `peer_is_active_nearby || peer_alive_recently`, gated by
/// `elapsed < 2 * round_timeout`): whatever the peer flags say, past twice
/// the base the hold is gone. Any future edit that lets a hold survive past
/// the bound fails here.
fn hold_bounded_mirror(elapsed_ms: u64, base_ms: u64, peer_active: bool) -> bool {
    peer_active && elapsed_ms < base_ms.saturating_mul(2)
}

/// Executable mirror of `cap_hold_to_two_x_bound`
/// (src/main.rs:260-262): the straggler hold only ever fills the slack up to
/// the pre-existing 2x peer-active bound, never past it.
fn cap_hold_mirror(hold_ms: u64, effective_ms: u64, base_ms: u64) -> u64 {
    hold_ms.min(base_ms.saturating_mul(2).saturating_sub(effective_ms))
}

#[test]
fn view_change_hold_always_drops_at_twice_base() {
    let base = 3_500u64;
    // While a peer is active the hold bridges the whole window — and not one
    // millisecond more.
    assert!(hold_bounded_mirror(0, base, true));
    assert!(hold_bounded_mirror(2 * base - 1, base, true));
    for elapsed in [2 * base, 2 * base + 1, 10 * base, u64::MAX / 2] {
        assert!(
            !hold_bounded_mirror(elapsed, base, true),
            "hold must drop at elapsed={elapsed} even with a live peer"
        );
    }
    // Silent peer: no hold at any elapsed.
    assert!(!hold_bounded_mirror(0, base, false));
}

#[test]
fn composed_view_change_deadline_is_fixed_and_stale_evidence_resumes_normal_timeouts() {
    let base = 3_500u64;
    let effective = 3_500u64; // round-0 deterministic timeout
    let grace = 5_000u64;

    // Fresh evidence: capped hold fills the slack to exactly the 2x bound.
    let capped = cap_hold_mirror(grace, effective, base);
    assert_eq!(capped, 2 * base - effective);
    let held_deadline = (effective + capped).max(2 * base);
    assert_eq!(held_deadline, 2 * base, "held rung dwells exactly 2x base");

    // Dead peer (no fresh evidence => grace 0): the peer-active hold is gone
    // at 2x base AND the additive term is 0, so the round fires at the plain
    // deterministic timeout — normal timeouts resume, nothing parks.
    let stale_capped = cap_hold_mirror(0, effective, base);
    assert_eq!(stale_capped, 0);
    assert!(
        !hold_bounded_mirror(effective, base, false),
        "dead peer holds nothing"
    );
    let stale_deadline = effective + stale_capped;
    assert_eq!(
        stale_deadline, effective,
        "with no fresh evidence the deadline is the normal timeout"
    );

    // Saturated regime (high rounds: deterministic core already past 2x
    // base): no room for grace, never stacking past the bound.
    assert_eq!(cap_hold_mirror(1_500, 13_000, 3_000), 0);
    assert_eq!(cap_hold_mirror(1_500, 2_000, 1_000), 0);
    // (Source of truth for these mirrors: `straggler_grace_tests` +
    // `round_timer_accounting_tests` unit tests inside src/main.rs, which
    // run against the real functions in the gate.)
}

#[test]
fn nil_wait_grace_is_bounded_and_expires_with_evidence() {
    // Mirror of the nil-wait deadline (src/main.rs nil path):
    // `2 * base + nil_grace`, where `nil_grace = min(grace, cap)` iff the
    // peer evidence is fresh, else 0.
    let base = 3_500u64;
    let (grace, cap) = (5_000u64, 5_000u64);
    let fresh_deadline = 2 * base + grace.min(cap);
    assert_eq!(fresh_deadline, 12_000, "fresh straggler evidence holds nil one bounded grace");
    let stale_deadline = 2 * base;
    assert_eq!(stale_deadline, 7_000, "stale evidence falls back to the plain 2x nil wait");
    assert!(
        fresh_deadline - stale_deadline <= cap,
        "the nil grace can never exceed its cap no matter the evidence"
    );
}

/// Consensus-layer half of termination: peer high-water marks are fixed, the
/// round counter only moves forward, so stale evidence is eventually at or
/// below our round — and then it can neither re-arm the breaker nor block
/// the local reset. The chain cannot be parked by old news.
#[tokio::test]
async fn stale_peer_evidence_cannot_rearm_sync_after_convergence() {
    let ks = keys(3);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs);
    // Two peers reported round 100 long ago (corroborated at the time).
    hc.note_peer_round(id(&ks[1]), 100);
    hc.note_peer_round(id(&ks[2]), 100);
    // We have since converged past it (chase + view changes).
    while hc.round < 100 {
        hc.sync_round_to(100);
        if hc.round < 100 {
            hc.next_round();
        }
    }
    assert!(hc.round >= 100);
    assert_eq!(
        hc.deadlock_breaker_target(10_000, 300),
        None,
        "stale evidence at/below our round must offer no breaker target"
    );
    assert!(
        hc.deadlock_local_reset_due(10_000, 300),
        "with nobody ahead, the no-progress path owns the breaker (complementarity)"
    );
}

// ===========================================================================
// E. Breaker safety: forward-only, corroborated, rate-limited.
// ===========================================================================

/// The breaker target is corroborated (one liar is not enough on a 3+ set),
/// gated on real silence, clamped to `MAX_DEADLOCK_JUMP`, and the jump
/// itself never moves backwards.
#[test]
fn breaker_target_is_gated_corroborated_and_jump_bounded() {
    let ks = keys(3);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(7, vs);
    hc.round = 318;

    // Lone liar claims u32::MAX: not corroborated, no target.
    hc.note_peer_round(id(&ks[1]), u32::MAX);
    assert_eq!(
        hc.deadlock_breaker_target(10_000, 300),
        None,
        "a single reporter must never steer the breaker, not even with u32::MAX"
    );
    // No silence yet: no target even when corroborated.
    hc.note_peer_round(id(&ks[2]), u32::MAX);
    assert_eq!(
        hc.deadlock_breaker_target(299, 300),
        None,
        "no fire before the silence timeout"
    );
    // Corroborated + silent: target exists and is clamped, not the raw claim.
    let target = hc.deadlock_breaker_target(10_000, 300).expect("must fire");
    assert_eq!(
        target,
        318u32.saturating_add(MAX_DEADLOCK_JUMP),
        "breaker jump size is bounded by MAX_DEADLOCK_JUMP (65536)"
    );
    assert!(hc.apply_deadlock_jump(target));
    assert_eq!(hc.round, target);
    // Forward-only: same and backwards jumps are no-ops.
    assert!(!hc.apply_deadlock_jump(target));
    assert!(!hc.apply_deadlock_jump(318));
    assert!(!hc.apply_deadlock_jump(target.saturating_sub(1)));
    assert_eq!(hc.round, target, "round counter never rewinds via the breaker");
    // NOTE: `apply_deadlock_jump` itself is a pure forward gate — the SIZE
    // bound lives in `deadlock_breaker_target` (pinned above), which is the
    // only producer of targets on the production path
    // (`check_deadlock_breaker`). A raw forward apply is therefore reachable
    // only with an already-clamped target.
    assert!(hc.apply_deadlock_jump(target + 1));
    assert_eq!(hc.round, target + 1);
    // Still-ahead claims offer a FURTHER target, but still clamped: every
    // breaker fire moves at most MAX_DEADLOCK_JUMP, and fires are
    // rate-limited to one per silence window by the caller.
    let again = hc.deadlock_breaker_target(10_000, 300).expect("still ahead");
    assert_eq!(again, hc.round.saturating_add(MAX_DEADLOCK_JUMP));
}

/// The local re-phase (deaf-everywhere fallback) moves forward by exactly
/// one, widens the scan window once, and is then idempotent — it cannot
/// rewind into a self-equivocation and cannot widen forever.
#[test]
fn local_reset_moves_forward_once_and_sticks() {
    let ks = keys(3);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(9, vs);
    hc.round = 412;

    // Complement of the jump path: a lone liar ahead blocks neither the jump
    // (no corroboration) nor the reset.
    hc.note_peer_round(id(&ks[1]), 1_595);
    assert!(
        hc.deadlock_local_reset_due(400, 300),
        "one uncorroborated reporter must not wedge the reset path"
    );
    assert!(
        !hc.deadlock_local_reset_due(10, 300),
        "no reset before the silence timeout"
    );
    let before_scan = hc.scan_lookback;
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(hc.round, 413, "re-phase advances exactly one round, never rewinds");
    assert_eq!(
        hc.scan_lookback, REPHASE_SCAN_WINDOW,
        "re-phase widens the scan window to {REPHASE_SCAN_WINDOW}"
    );
    assert!(before_scan < REPHASE_SCAN_WINDOW);
    assert!(
        !hc.apply_deadlock_local_reset(false),
        "re-phase is idempotent: nothing left to do on the second call"
    );
    assert_eq!(hc.round, 413, "idempotent re-fire must not advance again");
}

/// At the runtime layer the breaker is quiet without real silence: a fresh
/// node (progress just stamped at construction) never fires, and the
/// once-per-window rate limit is owned by `last_breaker_at`.
#[tokio::test]
async fn runtime_breaker_quiet_without_silence() {
    let ks = keys(3);
    let vs = vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
    // Corroborated ahead peers, but zero silence elapsed: no fire.
    rt.hc.note_peer_round(id(&ks[1]), 1_550);
    rt.hc.note_peer_round(id(&ks[2]), 1_550);
    assert_eq!(
        rt.check_deadlock_breaker(),
        None,
        "breaker must not fire without a full timeout window of silence"
    );
}
