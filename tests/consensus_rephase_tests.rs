//! Regression tests for the deadlock RE-PHASE and the deadlock BREAKER
//! (audit W6.4b, consensus layer).
//!
//! Two defects are pinned here:
//!
//! 1. The breaker target was clamped to `self.round + MAX_ROUND_AHEAD`
//!    (1000). The breaker's whole job is to close a desync LARGER than the
//!    vote-acceptance window (live 2026-10-14: A r1550 vs B r318 — a gap of
//!    1232). With that clamp the breaker could never close the very gap it
//!    was built for, and the node stayed stuck forever.
//!
//! 2. The local re-phase used to ADVANCE the round by one and call it a
//!    day. That is a no-op: the round timer advances the round anyway, so a
//!    node that fell out of phase with the network stayed out of phase. The
//!    re-phase now also WIDENS the quorum-scan / vote-history window, so the
//!    node can find — and COMMIT — the quorum the network formed in the
//!    round the network is actually in. The round counter still only ever
//!    moves FORWARD (rewinding would be a self-equivocation).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{
    HeightConsensus, ValidatorSet, Vote, VoteKind, MAX_DEADLOCK_JUMP, MAX_ROUND_AHEAD,
    REPHASE_SCAN_WINDOW, ROUND_LOOKBACK,
};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

const H: u64 = 92_079;

/// --- 1. The breaker closes a gap larger than MAX_ROUND_AHEAD --------------

#[test]
fn breaker_closes_a_gap_larger_than_the_vote_acceptance_window() {
    // The live shape: A r1550 vs B r318 — a gap of 1232, which is LARGER
    // than MAX_ROUND_AHEAD (1000). A breaker that clamps its target to
    // `self.round + MAX_ROUND_AHEAD` lands on r1318 and is still 232 rounds
    // short: the desync never collapses.
    let ks = keys(2);
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 318;
    hc.observe_peer_round(id(&ks[0]), 1550);

    let target = hc
        .deadlock_breaker_target(400, 300)
        .expect("the breaker must fire: a verified peer is ahead");
    assert_eq!(
        target, 1550,
        "the breaker must jump straight to the peer's round, not to a clamped one"
    );
    assert!(
        target > hc.round + MAX_ROUND_AHEAD,
        "the regression this pins: the old clamp made the target unreachable"
    );
    assert!(hc.apply_deadlock_jump(target));
    assert_eq!(hc.round, 1550);
}

#[test]
fn breaker_needs_a_second_peer_to_corroborate_the_round() {
    // `peer_rounds` records what each peer CLAIMED. A Byzantine validator
    // can claim any round — including u32::MAX — and the round counter only
    // moves forward, so a node that jumped to a bogus round could never come
    // back. The breaker therefore requires the target round to be reported
    // by MORE THAN ONE validator.
    let ks = keys(4);
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 100;
    // One liar claims the far future.
    hc.observe_peer_round(id(&ks[0]), u32::MAX);
    assert_eq!(
        hc.deadlock_breaker_target(400, 300),
        None,
        "a single Byzantine peer must not be able to steer the breaker"
    );
    // An honest second peer at the same round corroborates it.
    hc.observe_peer_round(id(&ks[1]), u32::MAX);
    let target = hc
        .deadlock_breaker_target(400, 300)
        .expect("two independent peers corroborating the round is the bar");
    assert!(
        target > hc.round && target <= hc.round + MAX_DEADLOCK_JUMP,
        "the jump must be forward and bounded, got {target} at round {}",
        hc.round
    );
}

#[test]
fn breaker_never_fires_before_the_timeout_or_without_a_peer() {
    let ks = keys(3);
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 100;
    assert_eq!(
        hc.deadlock_breaker_target(299, 300),
        None,
        "no fire before timeout"
    );
    assert_eq!(
        hc.deadlock_breaker_target(400, 300),
        None,
        "no peer ahead => the local re-phase owns the breaker"
    );
}

// --- 2. The local re-phase actually re-converges --------------------------

#[test]
fn rephase_widens_the_scan_window_and_never_rewinds() {
    let ks = keys(4);
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 412;
    hc.locked = Some(([7u8; 32], 400));
    assert_eq!(
        hc.scan_lookback, ROUND_LOOKBACK,
        "the normal window is narrow"
    );

    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(
        hc.round, 413,
        "the re-phase must move FORWARD: rewinding re-votes an already-used round"
    );
    assert_eq!(hc.scan_lookback, REPHASE_SCAN_WINDOW);
    assert_eq!(
        hc.locked, None,
        "a bodyless lock with no QC behind it is dropped"
    );
    assert_eq!(hc.height, H, "the re-phase never moves the height");
}

#[test]
fn rephase_lets_a_stuck_node_commit_the_quorum_the_network_formed() {
    // THE regression this pins. The node's round counter wandered to 500
    // while the network is really at round 412. It already HOLDS the
    // network's prevote and precommit quorums for round 412 — but the
    // 8-round scan window never looks there, so the node can never decide
    // and never converges. The re-phase widens the window, and the node
    // COMMITS the old round's quorum (the Tendermint rule: a node must
    // still commit a round it has left if the quorum turns up).
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 500;
    let block = [0x42u8; 32];
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, H, 412, VoteKind::Prevote, Some(block)))
            .unwrap();
        hc.add_precommit(Vote::sign(k, H, 412, VoteKind::Precommit, Some(block)))
            .unwrap();
    }
    // The POLKA LEDGER sees the quorum even before the re-phase: the moment
    // the quorum-completing prevote is admitted, the polka EXISTS (the
    // live liveness fix), so the node does not have to wait for the scan
    // window to reach round 412.
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(block),
        "the polka ledger must find — and commit — the quorum the network formed"
    );
    assert_eq!(hc.decided, Some(block));

    // The re-phase still works (it is the fallback for a node that has NOT
    // seen the quorum), and it moves forward, never backwards.
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 500;
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, H, 412, VoteKind::Prevote, Some(block)))
            .unwrap();
        hc.add_precommit(Vote::sign(k, H, 412, VoteKind::Precommit, Some(block)))
            .unwrap();
    }
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(
        hc.round, 501,
        "the re-phase moves forward, it never rewinds into round 412"
    );
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(block),
        "the widened window must find — and commit — the quorum the network formed"
    );
    assert_eq!(hc.decided, Some(block));
}

#[test]
fn rephase_retains_the_old_rounds_the_quorum_lives_in() {
    // The re-phase must not only WIDEN the scan: the votes themselves have
    // to survive the prune, or the quorum is gone before it is looked for.
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 500;
    let block = [0x42u8; 32];
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, H, 412, VoteKind::Prevote, Some(block)))
            .unwrap();
        hc.add_precommit(Vote::sign(k, H, 412, VoteKind::Precommit, Some(block)))
            .unwrap();
    }
    assert!(hc.apply_deadlock_local_reset(false));
    // The round-412 vote sets are still there.
    assert!(
        hc.prevote_set(412).is_some() && hc.precommit_set(412).is_some(),
        "the widened window must RETAIN the old rounds, not just look at them"
    );
}

#[test]
fn rephase_is_idempotent_per_height() {
    // The re-phase widens the window and clears a stale lock — both happen
    // ONCE. Re-firing it every timeout window would advance the round by one
    // (which the round timer does anyway) and change nothing else.
    let ks = keys(4);
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 412;
    hc.locked = Some(([7u8; 32], 400));
    assert!(hc.apply_deadlock_local_reset(false));
    let after = hc.round;
    assert!(
        !hc.apply_deadlock_local_reset(false),
        "the second re-phase is a no-op"
    );
    assert_eq!(hc.round, after, "a no-op must not move the round");
}

#[test]
fn rephase_never_touches_height_decided_or_the_qc() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 5;
    let block = [0x11u8; 32];
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, H, 5, VoteKind::Prevote, Some(block)))
            .unwrap();
        hc.add_precommit(Vote::sign(k, H, 5, VoteKind::Precommit, Some(block)))
            .unwrap();
    }
    assert_eq!(hc.try_precommit_quorum(), Some(block));
    let qc = hc.precommit_qc.clone();
    hc.round = 412;
    assert!(hc.apply_deadlock_local_reset(false));
    assert_eq!(hc.height, H);
    assert_eq!(
        hc.decided,
        Some(block),
        "the re-phase never clears a decision"
    );
    assert_eq!(
        hc.precommit_qc, qc,
        "the re-phase never clears the deciding QC"
    );
    assert_eq!(
        hc.locked,
        Some((block, 5)),
        "a QC-backed lock must survive the re-phase (dropping it is the fork primitive)"
    );
}

#[test]
fn the_narrow_window_still_bounds_the_scan_in_the_normal_case() {
    // The widened window is installed by the re-phase ONLY. A node that has
    // not re-phased must keep the narrow window, or a peer could make it
    // scan an unbounded number of rounds per tick.
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.round = 500;
    let block = [0x42u8; 32];
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, H, 412, VoteKind::Prevote, Some(block)))
            .unwrap();
    }
    assert_eq!(hc.scan_lookback, ROUND_LOOKBACK);
    assert_eq!(hc.try_prevote_quorum(), None, "no re-phase => no wide scan");
}

#[test]
fn a_lone_byzantine_peer_cannot_wedge_the_node() {
    // The two deadlock paths must agree on what "a peer is ahead" means.
    // If the breaker demands corroboration but the local re-phase trusts a
    // SINGLE peer, a lone liar that claims a huge round keeps BOTH paths
    // from firing: the breaker sees no corroborated round, the re-phase sees
    // a peer ahead. The node would then wedge with no way out.
    let ks = keys(4);
    let mut hc = HeightConsensus::new(H, vset(&ks));
    hc.round = 100;
    // One liar claims the far future.
    hc.observe_peer_round(id(&ks[0]), u32::MAX);
    assert_eq!(
        hc.deadlock_breaker_target(400, 300),
        None,
        "the breaker must not follow a single uncorroborated claim"
    );
    assert!(
        hc.deadlock_local_reset_due(400, 300),
        "the local re-phase must still fire: an uncorroborated claim is not 'a peer ahead'"
    );
    // An honest second peer at the same round re-enables the breaker.
    hc.observe_peer_round(id(&ks[1]), u32::MAX);
    assert!(
        hc.deadlock_breaker_target(400, 300).is_some(),
        "a corroborated round re-enables the breaker"
    );
}
