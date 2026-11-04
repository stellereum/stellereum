//! Regression tests for the post-restart chase livelock observed live:
//! nodeA accepted 223 proposals, rejected 0, broadcast 0 votes; nodeB proposed
//! every round alone; both sat at height #362 forever with every check green.
//!
//! Two interlocking mechanisms caused it:
//!   1. WIPE-CHASE: a signed vote for a newer round made the follower
//!      `sync_round_to` it, which clears the accepted-but-unvoted proposal, so
//!      the follower never votes as long as the leader votes every round.
//!   2. MISS-CHASE: a proposal arriving while the follower is one round behind
//!      was rejected as "wrong proposer" (the envelope round is unsigned and
//!      cannot be trusted for syncing), and by the time the vote synced the
//!      follower forward the proposal was already consumed.
//!
//! The fixes under test: `on_proposal` phase-aligns to the earliest
//! proposer-owned near round AFTER proving the block genuine, and
//! `note_peer_vote_round` refuses to abandon a live round for a near peer.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Two validators, shared genesis state, height 1. Returns (us, us_key, peer_key).
async fn two_node() -> (ValidatorRuntime, SigningKey, SigningKey) {
    let ks = keys(2);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let rt = ValidatorRuntime::new(ks[0].clone(), vset, state, 1);
    (rt, ks[0].clone(), ks[1].clone())
}

/// A block genuinely built by `proposer_key` on top of `rt`'s current state.
/// Blocks carry no round, so this is valid for whatever round the proposer owns.
async fn genuine_block(rt: &ValidatorRuntime, proposer_key: &SigningKey) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: rt.hc.height,
        prev_hash: [0u8; 32],
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: id(proposer_key),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(proposer_key);
    b
}

// ===========================================================================
// 1. A proposal for the NEXT round is accepted (phase-align), not rejected.
//    This is the exact stand interleaving: follower at R, leader's R+1 block.
// ===========================================================================

#[tokio::test]
async fn proposal_phase_align_accepts_next_round_and_votes() {
    let (mut rt, us, peer) = two_node().await;
    // Find a round WE own where the peer owns R+1. Under hash-slot scheduling
    // consecutive rounds are independent draws (no round-robin alternation),
    // so search forward (P(miss in 64 tries) ~ 2^-64).
    let mut tries = 0;
    while !(rt.hc.proposer().unwrap() == id(&us)
        && rt
            .validators
            .proposer_for(rt.hc.height, rt.hc.round + 1)
            .unwrap()
            == id(&peer))
    {
        rt.hc.next_round();
        tries += 1;
        assert!(
            tries < 64,
            "schedule must hand us a round followed by the peer's"
        );
    }
    let r = rt.hc.round;
    assert_ne!(rt.hc.proposer().unwrap(), id(&peer));

    let block = genuine_block(&rt, &peer).await;
    let bh = block.compute_hash();
    let res = rt.on_proposal(id(&peer), block, r + 1).await;
    assert!(
        res.is_ok(),
        "genuine next-round proposal must align, not reject: {res:?}"
    );
    assert_eq!(res.unwrap(), bh);
    assert_eq!(
        rt.hc.round,
        r + 1,
        "must have phase-aligned to the peer's round"
    );
    assert!(rt.hc.proposal.is_some(), "proposal must be held for voting");

    // And the whole point: the follower now VOTES instead of chasing.
    let v = rt.make_prevote();
    assert!(v.is_some(), "must prevote the aligned proposal");
    let v = v.unwrap();
    assert_eq!(v.round, r + 1);
    assert_eq!(v.block_hash, Some(bh));
}

// ===========================================================================
// 2. A verified peer vote pulls us up, even by one round.
//
// Suppressing 1..3-round sync left a PERSISTENT offset between two honest
// nodes: both prevoted the SAME value at r15 and r16, so no same-round QC
// could form and every height burned ~10 rounds (30s+) on the live stand.
// The behind node must follow; junk cannot forge this (F2 verifies first)
// and the jump is budget-bounded (test 3), so no round explosion.
// ===========================================================================

#[tokio::test]
async fn near_verified_vote_pulls_us_up() {
    let (mut rt, _us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&peer) {
        rt.hc.next_round();
    }
    let r = rt.hc.round;

    // One round of verified lead is enough to follow.
    assert!(rt.note_peer_vote_round(rt.hc.height, r + 1));
    assert_eq!(rt.hc.round, r + 1, "we follow the peer into its round");

    // Same round or behind: forward-only, never dragged backwards.
    assert!(!rt.note_peer_vote_round(rt.hc.height, rt.hc.round));
    assert!(!rt.note_peer_vote_round(rt.hc.height, rt.hc.round.saturating_sub(1)));

    // A jump past a live proposal is acceptable: that proposal cannot reach a
    // QC (the peer already moved on), so voting the new round is the only
    // live choice.
    assert!(rt.note_peer_vote_round(rt.hc.height, rt.hc.round + 2));
    assert!(rt.hc.proposal.is_none());
    assert_eq!(rt.hc.round, r + 3);

    // Wrong height never moves us.
    assert!(!rt.note_peer_vote_round(rt.hc.height + 1, rt.hc.round + 1));
}

// ===========================================================================
// 3. A FAR peer still yanks us forward even with a live proposal (its round
//    is dead -- the peer left long ago), bounded against round-DoS.
//
// The bound is the per-round jump BUDGET (MAX_SYNC_JUMPS_PER_ROUND capped
// jumps of ROUND_LOOKBACK rounds each), not a single cap-step: one verified
// vote converges us to the peer's round (the Tendermint future-round rule),
// and a second far vote then moves nothing until our own view change refills
// the budget. Junk still moves nothing (test 5 / hunt_round_dos F2).
// ===========================================================================

#[tokio::test]
async fn far_vote_syncs_despite_live_proposal() {
    use stellereum::consensus::{MAX_SYNC_JUMPS_PER_ROUND, ROUND_LOOKBACK};
    let (mut rt, _us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&peer) {
        rt.hc.next_round();
    }
    let r = rt.hc.round;
    let block = genuine_block(&rt, &peer).await;
    let er = rt.hc.round;
    assert!(rt.on_proposal(id(&peer), block, er).await.is_ok());

    let budget_cap = MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK;
    // Through the real vote path: the verified far vote records the peer's
    // round (observe_peer_vote) and then chases it (note_peer_vote_round).
    // Past the first +8 step the chase needs corroboration (P3-R1); here the
    // vote's own record corroborates (2-member set: one reporter suffices),
    // so one verified far vote still converges within the per-round budget.
    let far = stellereum::consensus::Vote::sign(
        &peer,
        rt.hc.height,
        r + 100,
        stellereum::consensus::VoteKind::Prevote,
        Some([0xF0; 32]),
    );
    assert!(rt.on_prevote(far).is_ok(), "peer far vote must verify");
    assert_eq!(
        rt.hc.round,
        r + budget_cap,
        "one verified far vote converges within the per-round jump budget"
    );
    assert!(
        rt.hc.proposal.is_none(),
        "dead proposal must be dropped on a far jump"
    );
    // The budget is spent: a further far vote moves nothing until our own
    // view change refills it (this is the round-DoS bound).
    assert!(!rt.note_peer_vote_round(rt.hc.height, r + 200));
    assert_eq!(rt.hc.round, r + budget_cap);
}

// ===========================================================================
// 4. Forgery gate: an unsigned envelope never moves our round, even when the
//    claimed proposer would own a near round (round-DoS via fake proposals).
// ===========================================================================

#[tokio::test]
async fn forged_proposal_never_moves_round() {
    let (mut rt, us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    let r = rt.hc.round;

    // Garbage naming the peer (who owns R+1) but signed by NOBODY.
    let mut bad = genuine_block(&rt, &peer).await;
    bad.validator_signatures.clear();
    let er = rt.hc.round;
    assert!(rt.on_proposal(id(&peer), bad, er).await.is_err());
    assert_eq!(rt.hc.round, r, "forgery must not move our round");
    assert!(rt.hc.proposal.is_none());

    // Wrong-height votes are ignored too.
    assert!(!rt.note_peer_vote_round(rt.hc.height + 1, r + 1));
    assert_eq!(rt.hc.round, r);
}

// ===========================================================================
// 5. Asymmetric lock (the #563 stall): A locked X after seeing a prevote QC
//    the peer missed (one lost vote). A locked proposer must re-propose X --
//    building fresh is nilled by the locked nodes and voted by the unlocked
//    ones, no quorum either way, forever.
// ===========================================================================

/// Drive `rt` to lock `bh` at its current round: both prevotes, then precommit.
async fn lock_on(rt: &mut ValidatorRuntime, us: &SigningKey, peer: &SigningKey, bh: [u8; 32]) {
    let h = rt.hc.height;
    let r = rt.hc.round;
    let mine = stellereum::consensus::Vote::sign(
        us,
        h,
        r,
        stellereum::consensus::VoteKind::Prevote,
        Some(bh),
    );
    let theirs = stellereum::consensus::Vote::sign(
        peer,
        h,
        r,
        stellereum::consensus::VoteKind::Prevote,
        Some(bh),
    );
    rt.on_prevote(mine).unwrap();
    rt.on_prevote(theirs).unwrap();
    let qc = rt.hc.try_prevote_quorum();
    assert_eq!(qc, Some(Some(bh)), "prevote QC must form");
    let pc = rt.make_precommit();
    assert!(pc.is_some(), "must precommit on QC");
    // Production records the node's own precommit via on_precommit right
    // after make_precommit (main loop); mirror that here.
    rt.on_precommit(pc.unwrap()).unwrap();
    assert_eq!(
        rt.hc.locked.map(|(b, _)| b),
        Some(bh),
        "must lock on precommit"
    );
}

#[tokio::test]
async fn locked_proposer_reproposes_locked_value() {
    let (mut rt, us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    // Propose fresh X and lock it (peer "saw" it too -- then its vote is lost).
    let x = rt.propose(1).await.expect("proposer must propose");
    let xh = x.compute_hash();
    lock_on(&mut rt, &us, &peer, xh).await;

    // Next round, still our proposer turn eventually: we must re-propose X,
    // not build something the network (and we) can never agree on.
    rt.hc.next_round();
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    let again = rt
        .propose(1)
        .await
        .expect("locked proposer must still propose");
    assert_eq!(
        again.compute_hash(),
        xh,
        "locked proposer must re-propose the locked body byte-for-byte"
    );

    // And a node locked on X votes X when X is re-proposed (the escape: the
    // unlocked peer votes X too, QC forms, finalize).
    rt.hc.proposal = None;
    let er = rt.hc.round;
    rt.on_proposal(id(&us), again, er)
        .await
        .expect("own re-proposal must be accepted");
    let v = rt.make_prevote().expect("must vote");
    assert_eq!(v.block_hash, Some(xh), "locked node votes its locked value");
}

#[tokio::test]
async fn polka_for_other_value_at_higher_round_unlocks() {
    let (mut rt, us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    let x = rt.propose(1).await.expect("proposer must propose");
    let xh = x.compute_hash();
    let r = rt.hc.round;
    lock_on(&mut rt, &us, &peer, xh).await;

    // A quorum for a DIFFERENT value at a higher round proves the network
    // moved on: unlock so we can follow it.
    let yh = [9u8; 32];
    rt.hc.next_round();
    assert_eq!(rt.hc.round, r + 1);
    let h = rt.hc.height;
    for k in [&us, &peer] {
        let v = stellereum::consensus::Vote::sign(
            k,
            h,
            r + 1,
            stellereum::consensus::VoteKind::Prevote,
            Some(yh),
        );
        rt.on_prevote(v).unwrap();
    }
    let qc = rt.hc.try_prevote_quorum();
    assert_eq!(qc, Some(Some(yh)));
    assert!(
        rt.hc.locked.is_none(),
        "higher-round polka for another value must unlock"
    );

    // A quorum for NIL at a higher round must NOT unlock (audit F-01).
    //
    // SAFETY, not liveness: a locked validator in this protocol prevotes NIL
    // on every later round it has no matching proposal for (`decide_prevote`),
    // so the very nodes that locked on A at round 0 produce the 2/3 NIL
    // polka at round 1 themselves. Unlocking on it lets them prevote a
    // DIFFERENT block at round 2 — and A (committed at round 0) and that
    // block (committed at round 2) then both finalize, with ZERO Byzantine
    // validators. A nil polka is a TIMEOUT, not a decision: only a non-nil
    // polka for another value supersedes a lock.
    rt.hc.next_round();
    lock_on(&mut rt, &us, &peer, xh).await;
    rt.hc.next_round();
    let h = rt.hc.height;
    let r2 = rt.hc.round;
    for k in [&us, &peer] {
        let v = stellereum::consensus::Vote::sign(
            k,
            h,
            r2,
            stellereum::consensus::VoteKind::Prevote,
            None,
        );
        rt.on_prevote(v).unwrap();
    }
    assert_eq!(rt.hc.try_prevote_quorum(), Some(None));
    assert!(
        rt.hc.locked.is_some(),
        "a higher-round NIL polka must NOT unlock: it is a timeout, not a decision"
    );

    // A quorum for our OWN value keeps the lock.
    rt.hc.next_round();
    lock_on(&mut rt, &us, &peer, xh).await;
    rt.hc.next_round();
    let h = rt.hc.height;
    let r3 = rt.hc.round;
    for k in [&us, &peer] {
        let v = stellereum::consensus::Vote::sign(
            k,
            h,
            r3,
            stellereum::consensus::VoteKind::Prevote,
            Some(xh),
        );
        rt.on_prevote(v).unwrap();
    }
    assert_eq!(rt.hc.try_prevote_quorum(), Some(Some(xh)));
    assert!(
        rt.hc.locked.is_some(),
        "polka for our own value must keep the lock"
    );
}

// ===========================================================================
// 7. Stale bodies are refused even when genuine: a block delayed in transit
//    must not be adopted as the current round's value (observed live: nodes
//    voting different stale bodies at the same round for hundreds of rounds).
//    The envelope round is only a freshness hint (unsigned) consulted AFTER
//    authentication, so forgeries still die in pre-validation.
// ===========================================================================

#[tokio::test]
async fn stale_envelope_is_rejected_but_timely_aligns() {
    let (mut rt, _us, peer) = two_node().await;
    while rt
        .validators
        .proposer_for(rt.hc.height, rt.hc.round)
        .unwrap()
        != id(&peer)
    {
        rt.hc.next_round();
    }
    let r = rt.hc.round;
    // Timely envelope for our round: accepted.
    let er = rt.hc.round;
    assert!(rt
        .on_proposal(id(&peer), genuine_block(&rt, &peer).await, er)
        .await
        .is_ok());
    assert!(rt.hc.has_live_proposal());

    // Same genuine body re-presented with an OLD envelope (delayed duplicate):
    // refused, and our live proposal survives the attempt.
    rt.hc.next_round();
    assert_eq!(rt.hc.round, r + 1);
    let err = rt
        .on_proposal(id(&peer), genuine_block(&rt, &peer).await, r)
        .await
        .expect_err("stale envelope must be rejected");
    assert!(
        err.contains("stale round"),
        "must name the reason, got: {err}"
    );
    assert!(!rt.hc.has_live_proposal(), "round advanced, nothing live");

    // Liveness gate still retires nothing early: timely accept, then a FAR
    // vote still syncs (stale holds never pin).
    let er = rt.hc.round;
    assert!(rt
        .on_proposal(id(&peer), genuine_block(&rt, &peer).await, er)
        .await
        .is_ok());
    assert!(rt.note_peer_vote_round(rt.hc.height, r + 100));
}

// ===========================================================================
// 7b. DOCUMENTED NON-GOAL (3-racer cascade): sit-while-armed was tried and
//     reverted. Refusing near jumps while armed deadlocks two armed nodes on
//     different rounds and breaks test `round_nudge_reopens_gate_once_not_per
//     _tick` convergence. The 3-member WAN leapfrog cascade (r769+, zero QCs)
//     stays open; the fix is quorum-gated jumps (≥2 distinct voters), to be
//     built when a third validator actually joins (see TO_100 P0 validators).
// ===========================================================================

// ===========================================================================
// 8. Lock-hint rescue (the #1070 stall): A locked on B's body, B oblivious.
//    A's nil prevotes carry the locked hash; B re-proposes its own body
//    verbatim at its own slot; A votes it (lock match); QC can form.
// ===========================================================================

#[tokio::test]
async fn lock_hint_rescue_converges() {
    use stellereum::consensus::{Vote, VoteKind};

    let ks = keys(2);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut a = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state.clone(), 1);
    let mut b = ValidatorRuntime::new(ks[1].clone(), vset.clone(), state.clone(), 1);
    let (_aid, bid) = (id(&ks[0]), id(&ks[1]));

    // B proposes X at its own slot; A accepts (aligning if behind) and locks
    // it after seeing both prevotes -- while B misses A's vote (one loss).
    while b.hc.proposer().unwrap() != bid {
        b.hc.next_round();
    }
    let x = b.propose(1).await.expect("B must propose at its slot");
    let xh = x.compute_hash();
    let era = a.hc.round;
    let ea = a.hc.round;
    a.on_proposal(bid, x, ea)
        .await
        .expect("A accepts B's block");
    assert!(a.hc.round >= era, "A aligns forward to the proposal");
    let ra = a.hc.round;
    for k in [&ks[0], &ks[1]] {
        a.on_prevote(Vote::sign(k, 1, ra, VoteKind::Prevote, Some(xh)))
            .unwrap();
    }
    assert_eq!(a.hc.try_prevote_quorum(), Some(Some(xh)));
    assert!(a.make_precommit().is_some());
    assert_eq!(a.hc.locked.map(|(h, _)| h), Some(xh), "A locked X");

    // B never saw A's vote: unlocked, proposes fresh Y at its next slot, and
    // A nils it (locked). Stall -- unless the hint path fires.
    b.hc.next_round();
    while b.hc.proposer().unwrap() != bid {
        b.hc.next_round();
    }
    let y = b.propose(2).await.expect("B proposes fresh");
    assert_ne!(y.compute_hash(), xh, "fresh block differs");
    let _eb = b.hc.round;
    // A is at ra still (no progress); move A to B's round to hear Y.
    while a.hc.round < b.hc.round {
        a.hc.next_round();
    }
    let ea2 = a.hc.round;
    a.on_proposal(bid, y, ea2)
        .await
        .expect("A accepts Y structurally");
    let nil = a.make_prevote().expect("A votes");
    assert_eq!(nil.block_hash, None, "locked A nils the fresh block");

    // The rescue: B learns the demand from A's nil hint and re-proposes X
    // verbatim at its own slot.
    b.note_lock_hint(1, VoteKind::Prevote, None, Some(xh));
    // F1 one-proposal-per-round (72bcfd8 2026-10-30): B already proposed Y in
    // its current round, so serving X in the SAME round would overwrite Y --
    // an equivocation the guard refuses (the demand stays queued). The rescue
    // must go out at B's NEXT slot, which is always a fresh round.
    b.hc.next_round();
    while b.hc.proposer().unwrap() != bid {
        b.hc.next_round();
    }
    let rescue = b.propose(1).await.expect("B must serve the demand");
    assert_eq!(rescue.compute_hash(), xh, "re-proposal is byte-identical");

    // A votes its locked value when it is re-proposed: QC can now form.
    while a.hc.round < b.hc.round {
        a.hc.next_round();
    }
    let ea3 = a.hc.round;
    a.on_proposal(bid, rescue, ea3)
        .await
        .expect("A accepts re-proposal");
    let v = a.make_prevote().expect("A votes");
    assert_eq!(
        v.block_hash,
        Some(xh),
        "locked A votes the re-proposed lock"
    );
}

#[tokio::test]
async fn lock_hint_ignores_foreign_and_missing_bodies() {
    use stellereum::consensus::VoteKind;

    let (mut rt, us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    let mine = rt.propose(1).await.expect("propose");
    let mh = mine.compute_hash();

    // Hint for an unknown hash: ignored, fresh proposal still built.
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some([7u8; 32]));
    // Hint for a body WE did not author: ignored too.
    let mut foreign = genuine_block(&rt, &peer).await;
    foreign.proposer = id(&peer);
    let fh = foreign.compute_hash();
    rt.blocks.insert(fh, foreign);
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(fh));
    // Demands for OUR body are kept; the rest never-generic.
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(mh));
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(mh)); // dedup
                                                                        // Wrong height / block-vote / precommit hints: ignored.
    rt.note_lock_hint(rt.hc.height + 1, VoteKind::Prevote, None, Some(mh));
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, Some(mh), Some(mh));
    rt.note_lock_hint(rt.hc.height, VoteKind::Precommit, None, Some(mh));

    // Our slot, unlocked: serves OUR demanded body, not foreign/missing.
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    let served = rt.propose(1).await.expect("must propose");
    assert_eq!(
        served.compute_hash(),
        mh,
        "serves our demanded body verbatim"
    );
}

// ===========================================================================
// 9. The commit broadcast must actually fire: try_finalize stashes the
//    decision proof because it resets `hc` (reading `hc.precommit_qc`
//    afterwards finds None and lagging peers never learn outcomes).
// ===========================================================================

#[tokio::test]
async fn finalize_stashes_decision_proof_for_broadcast() {
    use stellereum::consensus::{Vote, VoteKind};

    let (mut rt, us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    assert!(rt.last_decision.is_none());
    let b = rt.propose(1).await.expect("propose");
    let bh = b.compute_hash();
    lock_on(&mut rt, &us, &peer, bh).await;
    // Peer precommit completes the QC.
    let h = rt.hc.height;
    let r = rt.hc.round;
    rt.on_precommit(Vote::sign(&peer, h, r, VoteKind::Precommit, Some(bh)))
        .unwrap();
    let done = rt.try_finalize().await;
    assert_eq!(done, Some(bh), "must finalize with both precommits");
    let (dh, block, cert) = rt.last_decision.clone().expect("decision must be stashed");
    assert_eq!(dh, h);
    assert_eq!(block.compute_hash(), bh);
    assert_eq!(cert.kind, VoteKind::Precommit);
    assert_eq!(cert.block_hash, Some(bh));
    assert_eq!(cert.height, h);
}

// ===========================================================================
// 10b. P3-H4 batch: a Batch carrying [prevote, precommit] from the peer is
//      flattened in sender order and both votes count (QC can form).
// ===========================================================================

#[tokio::test]
async fn batch_of_peer_votes_counts_in_order() {
    use stellereum::consensus::{Vote, VoteKind};
    use stellereum::consensus_net::ConsensusMsg;

    let (mut rt, us, peer) = two_node().await;
    while rt.hc.proposer().unwrap() != id(&us) {
        rt.hc.next_round();
    }
    let b = rt.propose(1).await.expect("propose");
    let bh = b.compute_hash();
    let h = rt.hc.height;
    let r = rt.hc.round;
    let bytes = ConsensusMsg::batch_encode(&[
        ConsensusMsg::Vote {
            vote: Vote::sign(&peer, h, r, VoteKind::Prevote, Some(bh)),
            locked: None,
        },
        ConsensusMsg::Vote {
            vote: Vote::sign(&peer, h, r, VoteKind::Precommit, Some(bh)),
            locked: None,
        },
    ])
    .unwrap();
    let decoded = ConsensusMsg::decode(&bytes).unwrap();
    let inners = match decoded {
        ConsensusMsg::Batch(items) => items,
        _ => panic!("must decode as Batch"),
    };
    assert_eq!(inners.len(), 2);
    // Sender order preserved: prevote first, precommit second.
    assert!(matches!(
        &inners[0],
        ConsensusMsg::Vote { vote, .. } if vote.kind == VoteKind::Prevote
    ));
    assert!(matches!(
        &inners[1],
        ConsensusMsg::Vote { vote, .. } if vote.kind == VoteKind::Precommit
    ));
    // Each inner applies in isolation, exactly like the drain.
    for inner in inners {
        match inner {
            ConsensusMsg::Vote { vote: v, locked } => {
                rt.note_lock_hint(v.height, v.kind, v.block_hash, locked);
                match v.kind {
                    VoteKind::Prevote => {
                        rt.on_prevote(v).unwrap();
                    }
                    VoteKind::Precommit => {
                        rt.on_precommit(v).unwrap();
                    }
                }
            }
            _ => panic!("unexpected inner"),
        }
    }
    // Our own prevote + the peer's: QC forms on the proposed value.
    let mine = Vote::sign(&us, h, r, VoteKind::Prevote, Some(bh));
    rt.on_prevote(mine).unwrap();
    assert_eq!(rt.hc.try_prevote_quorum(), Some(Some(bh)));
}

// ===========================================================================
// 10c. P3-H4 batch: a Batch carrying [vote, proposal] accepts the proposal
//      (ordering: vote-then-proposal), and a batched nil hint is recorded.
// ===========================================================================

#[tokio::test]
async fn batch_vote_then_proposal_accepts_and_hints_recorded() {
    use stellereum::consensus::{Vote, VoteKind};
    use stellereum::consensus_net::ConsensusMsg;

    let ks = keys(2);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset, state, 1);
    let (aid, bid) = (id(&ks[0]), id(&ks[1]));
    // Our own body, so a nil hint naming it is demand we must serve.
    while rt.hc.proposer().unwrap() != aid {
        rt.hc.next_round();
    }
    let ours = rt.propose(1).await.expect("propose");
    let ours_h = ours.compute_hash();
    // Peer's round now: the batch below is built for the CURRENT round.
    while rt.hc.proposer().unwrap() != bid {
        rt.hc.next_round();
    }
    let peer_block = genuine_block(&rt, &ks[1]).await;
    let h = rt.hc.height;
    let r = rt.hc.round;
    let peer_nil = Vote::sign(&ks[1], h, r, VoteKind::Prevote, None);
    let bytes = ConsensusMsg::batch_encode(&[
        ConsensusMsg::Vote {
            vote: peer_nil,
            locked: Some(ours_h),
        },
        ConsensusMsg::Proposal {
            height: h,
            round: r,
            block: peer_block,
        },
    ])
    .unwrap();
    let decoded = ConsensusMsg::decode(&bytes).unwrap();
    let inners = match decoded {
        ConsensusMsg::Batch(items) => items,
        _ => panic!("must decode as Batch"),
    };
    let mut accepted = false;
    for inner in inners {
        match inner {
            ConsensusMsg::Vote { vote: v, locked } => {
                rt.note_lock_hint(v.height, v.kind, v.block_hash, locked);
                let _ = rt.on_prevote(v);
            }
            ConsensusMsg::Proposal { block, .. } => {
                let er = rt.hc.round;
                if rt.on_proposal(bid, block, er).await.is_ok() {
                    accepted = true;
                }
            }
            ConsensusMsg::Batch(_) => panic!("flatten must never yield Batch"),
            ConsensusMsg::Committed { .. } => {}
        }
    }
    assert!(
        accepted,
        "vote-then-proposal batch must accept the proposal"
    );
    // And the batched nil hint was recorded as demand for OUR body.
    while rt.hc.proposer().unwrap() != aid {
        rt.hc.next_round();
    }
    let served = rt.propose(1).await.expect("must serve the demand");
    assert_eq!(
        served.compute_hash(),
        ours_h,
        "batched nil hint must be recorded"
    );
}

// ===========================================================================
// 10. A refused proposal still teaches the head: height/round mismatches must
//     not blind catch-up (observed live: 1-height lag with neither side
//     learning, both spinning in view changes at their own heights forever).
// ===========================================================================

#[tokio::test]
async fn refused_proposal_still_records_peer_head() {
    let (mut rt, _us, peer) = two_node().await;
    assert!(rt.peer_hint.is_none());
    // A genuine proposal for a height above ours: we must refuse it (wrong
    // height) AND still learn finalized height-1 from its prev_hash.
    let mut high = genuine_block(&rt, &peer).await;
    high.height = rt.hc.height + 5;
    high.sign_block(&peer);
    let r = rt.hc.round;
    let res = rt.on_proposal(id(&peer), high.clone(), r).await;
    assert!(res.is_err(), "must refuse the wrong height, got {res:?}");
    assert_eq!(
        rt.peer_hint,
        Some((high.height - 1, high.prev_hash)),
        "refusal must still record the peer head"
    );
    // A LOWER (stale or maliciously rewound) claim never moves the hint back.
    let mut low = genuine_block(&rt, &peer).await;
    low.height = rt.hc.height; // timely height...
    low.sign_block(&peer);
    let _ = rt.on_proposal(id(&peer), low, r).await;
    assert!(rt.peer_hint.unwrap().0 >= high.height - 1);
}
