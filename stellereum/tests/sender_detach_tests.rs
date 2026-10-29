//! Sender-detach regressions (dead-peer flush stall).
//!
//! Live symptom (B's log, every ~5s): `broadcast to ba7f... transport-err ...
//! no session key`. `send_payload_with_skip` spawned one task per peer and then
//! JOINED every handle, so one dead peer's ~1.5s join stalled the whole flush;
//! worse, any batch containing a `Committed` message bypassed the
//! failure-cooldown skip, so votes batched with retro-Commits inherited the
//! dead-peer tax every few seconds.
//!
//! What this pins (local transport policy only — no wire format, no
//! QC/schedule/set changes):
//! * join-detach: the flush returns on the join budget even when a peer is
//!   slow; the slow task still runs to completion (tested through the same
//!   [`join_with_timeout`](stellereum::consensus_net::join_with_timeout) the
//!   broadcast path uses, with synthetic fast/slow peers);
//! * exempt-detach: a cooldown peer is [`SendPlan::Skipped`](stellereum::consensus_net::SendPlan)
//!   on normal payloads but [`SendPlan::Detached`](stellereum::consensus_net::SendPlan)
//!   on exempt (Committed catch-up) payloads — attempted, never joined;
//! * the failure-cooldown skip path itself is untouched (votes still skip;
//!   the 3-fails/60s rule still lives in the lib unit test
//!   `peer_cooldown_skips_only_inside_the_window`, which must keep passing);
//! * probe eviction needs N CONSECUTIVE probe timeouts
//!   (`STELL_PROBE_EVICT_AFTER`, default 3): a single timeout records and
//!   moves on.
//!
//! All policy is time-injected and deterministic except the join-detach test,
//! which uses real (generous-margin) sleeps: fast ~10ms, slow 500ms, budget
//! 50ms, asserted well under the slow duration.

use std::time::Duration;
use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
use stellereum::consensus_net::{
    broadcast_join_timeout_ms, committed_bypasses_skip, join_with_timeout,
    parse_broadcast_join_timeout_ms, parse_probe_evict_after, plan_peer_send, probe_evict_after,
    probe_timeout_should_evict, ConsensusMsg, SendPlan, BROADCAST_JOIN_TIMEOUT_MS_DEFAULT,
    PROBE_EVICT_AFTER_DEFAULT,
};
use stellereum::sharding::Block;

fn sample_block() -> Block {
    Block {
        shard_id: 0,
        height: 9,
        prev_hash: [1u8; 32],
        state_root: [2u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 123,
        proposer: [3u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

fn sample_commit() -> ConsensusMsg {
    ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: QuorumCertificate {
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    }
}

fn sample_vote() -> ConsensusMsg {
    ConsensusMsg::Vote {
        vote: Vote {
            height: 9,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: None,
            voter: [7u8; 32],
            signature: vec![0u8; 64],
        },
        locked: None,
    }
}

// ==================== 1. join-detach ====================

#[tokio::test]
async fn join_detach_slow_peer_does_not_delay_flush() {
    // One fast peer (~10ms) and one dead peer (500ms — stands in for the live
    // 1.5s "no session key" stall, scaled down so the suite stays fast).
    let fast = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        7u32
    });
    let slow = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        9u32
    });
    let t = std::time::Instant::now();
    let (done, detached) = join_with_timeout(vec![fast, slow], Duration::from_millis(50)).await;
    let took = t.elapsed();
    // The fast peer's outcome is observed; the slow one detaches ...
    assert_eq!(done, vec![7u32], "fast peer outcome must be collected");
    assert_eq!(detached, 1, "slow peer must detach, not stall");
    // ... and the waiter returns on the budget, an order of magnitude under
    // the slow peer's latency. Margin is 5x the budget: flakes only if the
    // CI host stalls a 50ms timer past 250ms.
    assert!(
        took < Duration::from_millis(250),
        "flush must return on the join budget, took {took:?}"
    );
}

#[tokio::test]
async fn join_all_fast_peers_collects_everything() {
    let a = tokio::spawn(async { 1u32 });
    let b = tokio::spawn(async { 2u32 });
    let (mut done, detached) = join_with_timeout(vec![a, b], Duration::from_secs(2)).await;
    done.sort_unstable();
    assert_eq!(done, vec![1u32, 2u32]);
    assert_eq!(detached, 0, "healthy flush detaches nothing");
}

#[tokio::test]
async fn join_empty_set_returns_immediately() {
    let (done, detached): (Vec<u32>, usize) =
        join_with_timeout(Vec::new(), Duration::from_millis(50)).await;
    assert!(done.is_empty());
    assert_eq!(detached, 0);
}

// ==================== 2. exempt-detach ====================

#[test]
fn exempt_detach_dead_peer_attempted_but_not_joined() {
    // Live peer: joined on both paths (joined set = live peers only).
    assert_eq!(plan_peer_send(false, false), SendPlan::Joined);
    assert_eq!(plan_peer_send(false, true), SendPlan::Joined);
    // Dead (cooldown) peer, normal vote payload: skipped entirely — no dial,
    // no 1.5s join tax.
    assert_eq!(plan_peer_send(true, false), SendPlan::Skipped);
    // Dead peer, EXEMPT (Committed catch-up) payload: still attempted so a
    // returning node catches up, but DETACHED from the start — never joined.
    assert_eq!(plan_peer_send(true, true), SendPlan::Detached);
    // Hard pin: a cooldown peer is never in the joined set, exempt or not.
    for exempt in [false, true] {
        assert_ne!(
            plan_peer_send(true, exempt),
            SendPlan::Joined,
            "cooldown peer must never join (exempt={exempt})"
        );
    }
}

#[test]
fn exempt_trigger_feeds_detach_for_commits_only() {
    // The exempt flag comes from `committed_bypasses_skip`: Committed (and
    // only Committed) lifts the skip — and lifting the skip now means
    // DETACHED, not "join the dead peer".
    assert!(committed_bypasses_skip(&sample_commit()));
    assert!(!committed_bypasses_skip(&sample_vote()));
    assert_eq!(
        plan_peer_send(true, committed_bypasses_skip(&sample_commit())),
        SendPlan::Detached,
        "dead peer + Commit payload: attempt detached"
    );
    assert_eq!(
        plan_peer_send(true, committed_bypasses_skip(&sample_vote())),
        SendPlan::Skipped,
        "dead peer + vote payload: skip entirely (cooldown intact)"
    );
}

// ==================== 3. join budget parsing ====================

#[test]
fn join_budget_default_is_500ms_and_parsing_clamps() {
    assert_eq!(BROADCAST_JOIN_TIMEOUT_MS_DEFAULT, 500);
    assert_eq!(parse_broadcast_join_timeout_ms(None), 500);
    assert_eq!(parse_broadcast_join_timeout_ms(Some("".into())), 500);
    assert_eq!(parse_broadcast_join_timeout_ms(Some("nope".into())), 500);
    assert_eq!(parse_broadcast_join_timeout_ms(Some("0".into())), 500);
    assert_eq!(parse_broadcast_join_timeout_ms(Some("50".into())), 50);
    assert_eq!(parse_broadcast_join_timeout_ms(Some(" 200 ".into())), 200);
    // The live reader agrees with the parser for whatever the environment
    // currently holds (robust with or without the env var set).
    assert_eq!(
        broadcast_join_timeout_ms(),
        parse_broadcast_join_timeout_ms(std::env::var("STELL_BROADCAST_JOIN_MS").ok())
    );
}

// ==================== 4. probe-evict-N ====================

#[test]
fn probe_evicts_only_after_n_consecutive_timeouts() {
    assert_eq!(PROBE_EVICT_AFTER_DEFAULT, 3);
    assert_eq!(parse_probe_evict_after(None), 3);
    assert_eq!(parse_probe_evict_after(Some("nope".into())), 3);
    assert_eq!(parse_probe_evict_after(Some("0".into())), 3);
    assert_eq!(parse_probe_evict_after(Some("1".into())), 1);
    assert_eq!(parse_probe_evict_after(Some("5".into())), 5);
    assert_eq!(
        probe_evict_after(),
        parse_probe_evict_after(std::env::var("STELL_PROBE_EVICT_AFTER").ok())
    );

    // The decision: sub-threshold streaks keep the connection ...
    assert!(!probe_timeout_should_evict(0, 3));
    assert!(
        !probe_timeout_should_evict(1, 3),
        "single timeout must never evict"
    );
    assert!(!probe_timeout_should_evict(2, 3));
    // ... the Nth consecutive timeout evicts, and the streak staying red
    // keeps evicting (the peer is still dead).
    assert!(probe_timeout_should_evict(3, 3));
    assert!(probe_timeout_should_evict(4, 3));
    assert!(probe_timeout_should_evict(100, 3));
    // A threshold of 1 preserves the old immediate-evict shape for anyone
    // who explicitly configures it.
    assert!(probe_timeout_should_evict(1, 1));
    assert!(!probe_timeout_should_evict(0, 1));
}
