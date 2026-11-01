//! Proposal-validation pipeline audit tests.
//!
//! Scope: the gate every proposal passes before voting — `on_proposal`
//! (apply-in-flight deferral, proposer-signature attribution, peer hint,
//! `validate_proposal_timed` + `note_validation_timing`, actor cap,
//! stale-round freshness, near-future phase alignment bounded by
//! `PROPOSAL_ALIGN_WINDOW_ROUNDS`, wrong-proposer refusal),
//! `validate_proposal_unaligned` / `validate_proposal_timed` internals,
//! `check_last_qc_evidence` (downtime QC for the parent height), and
//! `receive_proposal` (one value per round, step/schedule gates).
//!
//! What these tests pin:
//!  * no validation bypass: every seated proposal passed the full checks
//!    (forgery / wrong height / bad evidence / over-cap / equivocation all
//!    refuse, and refusal seats nothing);
//!  * stale-acceptance: a late envelope never seats; near-future alignment is
//!    bounded by the window and composes with the `sync_round_to` caps
//!    (far claims refuse without moving the round);
//!  * evidence: `None` is accepted exactly when this node knows no parent
//!    decision and refused when it does; weak / wrong-height / wrong-hash /
//!    wrong-kind QCs all refuse;
//!  * actor cap: exactly `MAX_ACTOR_MSGS_PER_BLOCK` static sends are
//!    accepted, one more is refused (fail-closed, deterministic);
//!  * equivocation: a second distinct body is refused at both layers
//!    (`on_proposal` and `receive_proposal`), while a rebroadcast of the
//!    identical body stays idempotent-Ok.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{
    count_block_actor_sends, fund_genesis, ValidatorRuntime, PROPOSAL_ALIGN_WINDOW_ROUNDS,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{InMemoryStateEngine, MAX_ACTOR_MSGS_PER_BLOCK};
use stellereum::svm::OpCode;

const BAL: u64 = 1_000_000_000_000_000;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

async fn runtime_for(ks: &[SigningKey], idx: usize) -> ValidatorRuntime {
    let vs = vset(ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, BAL).await;
    ValidatorRuntime::new(ks[idx].clone(), vs, state, 1)
}

/// The scheduled proposer for `(height, round)` resolved to one of our keys.
fn sched_key(rt: &ValidatorRuntime, ks: &[SigningKey], h: u64, r: u32) -> SigningKey {
    let want = rt
        .validators
        .proposer_for(h, r)
        .expect("non-empty set always schedules a proposer");
    ks.iter()
        .find(|k| id(k) == want)
        .expect("schedule proposer is one of our keys")
        .clone()
}

/// An empty-body block by `proposer` for `(height, prev)` with the caller's
/// evidence. The order commitment is derived by the constructor; the evidence
/// is set BEFORE signing because it is mixed into the signed hash.
async fn genuine(
    rt: &ValidatorRuntime,
    proposer: &SigningKey,
    height: u64,
    prev: [u8; 32],
    ts: u64,
    last_qc: Option<QuorumCertificate>,
) -> Block {
    let mut b = Block::new_for_test(
        MASTERCHAIN_SHARD,
        height,
        prev,
        rt.state.get_state_root().await,
        vec![],
    );
    b.timestamp = ts;
    b.proposer = id(proposer);
    b.last_qc = last_qc;
    b.sign_block(proposer);
    b
}

/// A precommit/prevote QC over `bh` at `(h, r)` signed by `ks[idx]`.
fn qc_over(
    ks: &[SigningKey],
    idx: &[usize],
    h: u64,
    r: u32,
    kind: VoteKind,
    bh: Option<[u8; 32]>,
) -> QuorumCertificate {
    QuorumCertificate {
        height: h,
        round: r,
        kind,
        block_hash: bh,
        signatures: idx
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], h, r, kind, bh);
                (v.voter, v.signature)
            })
            .collect(),
    }
}

fn actor_send() -> OpCode {
    OpCode::SysCallActorSend {
        recipient: [0u8; 32],
        value: 0,
        body: vec![],
        bounce: false,
        gas_budget: 0,
    }
}

fn actor_tx(from: &SigningKey, n_top: usize) -> Transaction {
    let payload: Vec<OpCode> = (0..n_top).map(|_| actor_send()).collect();
    Transaction::sign_with_payload(
        from,
        [9u8; 32],
        0,
        1_000_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
    )
}

async fn actor_block(
    rt: &ValidatorRuntime,
    proposer: &SigningKey,
    txs: Vec<Transaction>,
) -> Block {
    let mut b = Block::new_for_test(
        MASTERCHAIN_SHARD,
        rt.hc.height,
        [0u8; 32],
        rt.state.get_state_root().await,
        txs,
    );
    b.timestamp = 1_000;
    b.proposer = id(proposer);
    b.sign_block(proposer);
    b
}

// ============================================================================
// 1. Stale envelopes never seat; timely envelopes do (control).
// ============================================================================

#[tokio::test]
async fn stale_envelope_refused_and_seats_nothing() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, rt.hc.height, r);
    let sid = id(&sched);

    // Timely control: the current round's envelope seats the genuine body.
    let block = genuine(&rt, &sched, rt.hc.height, [0u8; 32], 1_000, None).await;
    let bh = block.compute_hash();
    assert_eq!(
        rt.on_proposal(sid, block, r).await.expect("timely must seat"),
        bh
    );
    assert!(rt.hc.has_live_proposal());

    // Advance one round, then replay a (still genuine) body with the OLD
    // envelope: refused as stale, and the new round seats nothing.
    rt.hc.next_round();
    assert_eq!(rt.hc.round, r + 1);
    let late = genuine(&rt, &sched, rt.hc.height, [0u8; 32], 1_001, None).await;
    let err = rt
        .on_proposal(sid, late, r)
        .await
        .expect_err("stale envelope must be refused");
    assert!(
        err.contains("stale round"),
        "must name the reason, got: {err}"
    );
    assert!(
        !rt.hc.has_live_proposal(),
        "a stale envelope must seat nothing"
    );
    assert_eq!(rt.hc.round, r + 1, "refusal must not move our round");
}

// ============================================================================
// 2. Near-future envelopes align (bounded); far-future envelopes refuse.
// ============================================================================

#[tokio::test]
async fn future_envelope_within_window_aligns_and_accepts() {
    assert_eq!(
        PROPOSAL_ALIGN_WINDOW_ROUNDS, 8,
        "widening the align window must be a deliberate spec change"
    );
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let peer = ks[1].clone();
    let peer_id = id(&peer);

    // Find a base round we can stand on where the peer owns a near slot.
    let mut found = None;
    for _ in 0..256 {
        let r = rt.hc.round;
        if rt.validators.proposer_for(rt.hc.height, r) != Some(peer_id) {
            if let Some(t) = ((r + 1)..=(r + PROPOSAL_ALIGN_WINDOW_ROUNDS))
                .find(|t| rt.validators.proposer_for(rt.hc.height, *t) == Some(peer_id))
            {
                found = Some((r, t));
                break;
            }
        }
        rt.hc.next_round();
    }
    let (r, t) = found.expect("schedule must offer a near-future peer slot");
    assert_eq!(rt.hc.round, r);

    let block = genuine(&rt, &peer, rt.hc.height, [0u8; 32], 1_000, None).await;
    let bh = block.compute_hash();
    assert_eq!(
        rt.on_proposal(peer_id, block, t)
            .await
            .expect("near-future genuine proposal must align, not reject"),
        bh
    );
    assert_eq!(rt.hc.round, t, "must land exactly on the peer's round");
    assert!(
        (t - r) <= PROPOSAL_ALIGN_WINDOW_ROUNDS,
        "one align step is bounded by the window"
    );
    assert!(rt.hc.has_live_proposal());
}

#[tokio::test]
async fn far_future_envelope_beyond_window_refused_without_moving() {
    let ks = keys(2);
    let vs = vset(&ks);
    let peer_id = id(&ks[1]);

    // An ISOLATED far slot: the peer owns r0+9 but nothing in r0+1..=r0+8
    // and nothing at r0 itself, so the align scan cannot find it nearby.
    // (Hash-slot draws are independent; ~1/1024 rounds qualify.)
    let mut found = None;
    for r0 in 0..20_000u32 {
        if vs.proposer_for(1, r0) == Some(peer_id) {
            continue;
        }
        if ((r0 + 1)..=(r0 + PROPOSAL_ALIGN_WINDOW_ROUNDS))
            .any(|t| vs.proposer_for(1, t) == Some(peer_id))
        {
            continue;
        }
        if vs.proposer_for(1, r0 + 9) != Some(peer_id) {
            continue;
        }
        found = Some(r0);
        break;
    }
    let r0 = found.expect("schedule must offer an isolated far slot");

    let mut rt = runtime_for(&ks, 0).await;
    rt.hc.round = r0;
    assert!(rt.hc.proposal.is_none());

    let block = genuine(&rt, &ks[1], 1, [0u8; 32], 1_000, None).await;
    let err = rt
        .on_proposal(peer_id, block, r0 + 9)
        .await
        .expect_err("far-future envelope beyond the window must be refused");
    assert!(
        err.contains("wrong proposer"),
        "must name the reason, got: {err}"
    );
    assert_eq!(
        rt.hc.round, r0,
        "a far claim must not move our round (align-window abuse is bounded)"
    );
    assert!(
        rt.hc.proposal.is_none(),
        "a far claim must seat nothing"
    );
}

// ============================================================================
// 3. Forgery and non-membership never move the round, even with a near slot.
// ============================================================================

#[tokio::test]
async fn forged_future_envelope_never_moves_round() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let peer = ks[1].clone();
    let peer_id = id(&peer);

    // Stand on a round where the peer owns the NEXT slot ...
    let mut tries = 0;
    while !(rt.validators.proposer_for(rt.hc.height, rt.hc.round) != Some(peer_id)
        && rt.validators.proposer_for(rt.hc.height, rt.hc.round + 1) == Some(peer_id))
    {
        rt.hc.next_round();
        tries += 1;
        assert!(tries < 256, "schedule must hand us a peer-next round");
    }
    let r = rt.hc.round;

    // ... then hand it a near-future envelope on an UNSIGNED body.
    let mut bad = genuine(&rt, &peer, rt.hc.height, [0u8; 32], 1_000, None).await;
    bad.validator_signatures.clear();
    let err = rt
        .on_proposal(peer_id, bad, r + 1)
        .await
        .expect_err("unsigned body must die before any align");
    assert!(
        err.contains("proposer signature"),
        "must name the reason, got: {err}"
    );
    assert_eq!(rt.hc.round, r, "forgery must not move our round");
    assert!(rt.hc.proposal.is_none());
}

#[tokio::test]
async fn non_member_proposal_refused_as_wrong_proposer() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let outsider = SigningKey::generate(&mut OsRng);
    let oid = id(&outsider);
    assert_eq!(rt.validators.power_of(&oid), 0);

    // Self-signed, so the signature check passes; membership fails later at
    // the proposer-slot check (the outsider owns no slot, near or far).
    let block = genuine(&rt, &outsider, rt.hc.height, [0u8; 32], 1_000, None).await;
    let r = rt.hc.round;
    let err = rt
        .on_proposal(oid, block, r)
        .await
        .expect_err("non-member proposal must be refused");
    assert!(
        err.contains("wrong proposer"),
        "must name the reason, got: {err}"
    );
    assert_eq!(rt.hc.round, r);
    assert!(rt.hc.proposal.is_none());
}

// ============================================================================
// 4. Downtime-evidence matrix (`check_last_qc_evidence`).
//    Height 1 blocks name parent 0 (`prev_hash` zero); height 2 blocks name a
//    real parent. Four validators at power 1 => quorum is 3.
// ============================================================================

#[tokio::test]
async fn evidence_none_accepted_when_node_knows_no_parent() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;
    assert!(rt.last_decision.is_none());
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, 1, r);
    let sid = id(&sched);
    let block = genuine(&rt, &sched, 1, [0u8; 32], 1_000, None).await;
    rt.on_proposal(sid, block, r)
        .await
        .expect("None must be accepted when this node knows no parent decision");
}

#[tokio::test]
async fn evidence_none_refused_when_node_knows_parent() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;

    // Parent at height 1, proposed by its scheduled proposer.
    let r = rt.hc.round;
    let p_sched = sched_key(&rt, &ks, 1, r);
    let parent = genuine(&rt, &p_sched, 1, [0u8; 32], 1_000, None).await;
    let ph = parent.compute_hash();
    let parent_qc = qc_over(&ks, &[0, 1, 2], 1, 0, VoteKind::Precommit, Some(ph));

    // We HAVE finalized the parent: its decision is recorded locally.
    rt.blocks.insert(ph, parent.clone());
    rt.finalized = vec![(1, ph)];
    rt.hc.height = 2;
    rt.last_decision = Some((1, parent, parent_qc));

    // A child that omits the evidence this node KNOWS exists must be refused:
    // accepting it would silently suppress one height of downtime accounting.
    let c_sched = sched_key(&rt, &ks, 2, rt.hc.round);
    let cid = id(&c_sched);
    let root = rt.state.get_state_root().await;
    let mut child = Block::new_for_test(MASTERCHAIN_SHARD, 2, ph, root, vec![]);
    child.timestamp = 1_001;
    child.proposer = cid;
    child.last_qc = None;
    child.sign_block(&c_sched);
    let err = rt
        .on_proposal(cid, child, rt.hc.round)
        .await
        .expect_err("None must be refused when this node knows the parent decision");
    assert!(
        err.contains("omits the downtime evidence"),
        "must name the reason, got: {err}"
    );
    assert!(rt.hc.proposal.is_none());
    // The refusal still teaches the head: the genuine child proves H-1.
    assert_eq!(rt.peer_hint, Some((1, ph)));
}

#[tokio::test]
async fn evidence_good_qc_accepted() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, 1, r);
    let sid = id(&sched);
    // 3-of-4 precommit QC for parent 0 naming the zero prev_hash: quorum.
    let good = qc_over(&ks, &[0, 1, 2], 0, 0, VoteKind::Precommit, Some([0u8; 32]));
    let block = genuine(&rt, &sched, 1, [0u8; 32], 1_000, Some(good)).await;
    rt.on_proposal(sid, block, r)
        .await
        .expect("a genuine quorum QC for the parent must be accepted");
}

#[tokio::test]
async fn evidence_weak_qc_refused() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, 1, r);
    let sid = id(&sched);
    // 2-of-4 carries power 2 < quorum 3: an attacker QC subset.
    let weak = qc_over(&ks, &[0, 1], 0, 0, VoteKind::Precommit, Some([0u8; 32]));
    let block = genuine(&rt, &sched, 1, [0u8; 32], 1_000, Some(weak)).await;
    let err = rt
        .on_proposal(sid, block, r)
        .await
        .expect_err("a sub-quorum evidence QC must be refused");
    assert!(
        err.contains("downtime evidence"),
        "must name the reason, got: {err}"
    );
    assert!(rt.hc.proposal.is_none());
}

#[tokio::test]
async fn evidence_wrong_height_refused() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, 1, r);
    let sid = id(&sched);
    // Names height 1, but the parent of a height-1 block is height 0.
    let wrong_h = qc_over(&ks, &[0, 1, 2], 1, 0, VoteKind::Precommit, Some([0u8; 32]));
    let block = genuine(&rt, &sched, 1, [0u8; 32], 1_000, Some(wrong_h)).await;
    let err = rt
        .on_proposal(sid, block, r)
        .await
        .expect_err("evidence for the wrong height must be refused");
    assert!(
        err.contains("not parent"),
        "must name the reason, got: {err}"
    );
    assert!(rt.hc.proposal.is_none());
}

#[tokio::test]
async fn evidence_wrong_hash_refused() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, 1, r);
    let sid = id(&sched);
    // Right height, but names a parent block that is not our prev_hash.
    let wrong_bh = qc_over(&ks, &[0, 1, 2], 0, 0, VoteKind::Precommit, Some([7u8; 32]));
    let block = genuine(&rt, &sched, 1, [0u8; 32], 1_000, Some(wrong_bh)).await;
    let err = rt
        .on_proposal(sid, block, r)
        .await
        .expect_err("evidence naming another parent must be refused");
    assert!(
        err.contains("different parent"),
        "must name the reason, got: {err}"
    );
    assert!(rt.hc.proposal.is_none());
}

#[tokio::test]
async fn evidence_wrong_kind_prevote_refused() {
    let ks = keys(4);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, 1, r);
    let sid = id(&sched);
    // Prevotes never prove finality: only a precommit QC is evidence.
    let prevote = qc_over(&ks, &[0, 1, 2], 0, 0, VoteKind::Prevote, Some([0u8; 32]));
    let block = genuine(&rt, &sched, 1, [0u8; 32], 1_000, Some(prevote)).await;
    let err = rt
        .on_proposal(sid, block, r)
        .await
        .expect_err("a prevote QC must never pass as downtime evidence");
    assert!(
        err.contains("not a precommit quorum"),
        "must name the reason, got: {err}"
    );
    assert!(rt.hc.proposal.is_none());
}

// ============================================================================
// 5. Actor-mailbox cap boundaries: exactly at cap seats, one over refuses.
// ============================================================================

#[tokio::test]
async fn actor_cap_exact_boundary_accepted() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, rt.hc.height, r);
    let sid = id(&sched);

    let tx = actor_tx(&sched, MAX_ACTOR_MSGS_PER_BLOCK);
    let probe = Block::new_for_test(
        MASTERCHAIN_SHARD,
        rt.hc.height,
        [0u8; 32],
        rt.state.get_state_root().await,
        vec![tx],
    );
    assert_eq!(
        count_block_actor_sends(&probe),
        MAX_ACTOR_MSGS_PER_BLOCK,
        "precondition: the probe carries exactly cap sends"
    );
    let block = actor_block(&rt, &sched, probe.transactions.clone()).await;
    rt.on_proposal(sid, block, r)
        .await
        .expect("a block with exactly cap sends must be accepted");
}

#[tokio::test]
async fn actor_cap_one_over_refused() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, rt.hc.height, r);
    let sid = id(&sched);

    let tx = actor_tx(&sched, MAX_ACTOR_MSGS_PER_BLOCK + 1);
    let probe = Block::new_for_test(
        MASTERCHAIN_SHARD,
        rt.hc.height,
        [0u8; 32],
        rt.state.get_state_root().await,
        vec![tx],
    );
    assert_eq!(
        count_block_actor_sends(&probe),
        MAX_ACTOR_MSGS_PER_BLOCK + 1,
        "precondition: the probe carries cap+1 sends"
    );
    let block = actor_block(&rt, &sched, probe.transactions.clone()).await;
    let err = rt
        .on_proposal(sid, block, r)
        .await
        .expect_err("a block with cap+1 sends must be refused fail-closed");
    assert!(
        err.contains("mailbox") || err.contains("actor"),
        "must name the reason, got: {err}"
    );
    assert!(rt.hc.proposal.is_none());
}

#[tokio::test]
async fn actor_send_count_is_transitive_over_nested_bodies() {
    // One top-level send whose body carries two more: the block's static
    // load is 3, not 1 (delivery of the outer body enqueues the inner two).
    let from = SigningKey::generate(&mut OsRng);
    let inner = vec![actor_send(), actor_send()];
    let outer = OpCode::SysCallActorSend {
        recipient: [1u8; 32],
        value: 0,
        body: inner,
        bounce: false,
        gas_budget: 0,
    };
    let tx = Transaction::sign_with_payload(
        &from,
        [9u8; 32],
        0,
        1_000_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![outer],
    );
    let b = Block::new_for_test(MASTERCHAIN_SHARD, 1, [0u8; 32], [0u8; 32], vec![tx]);
    assert_eq!(count_block_actor_sends(&b), 3);
}

// ============================================================================
// 6. Equivocation: second distinct body refused at both layers; identical
//    rebroadcast stays idempotent-Ok.
// ============================================================================

#[tokio::test]
async fn equivocating_proposer_second_distinct_body_refused() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, rt.hc.height, r);
    let sid = id(&sched);

    // First body seats.
    let first = genuine(&rt, &sched, rt.hc.height, [0u8; 32], 1_000, None).await;
    let h1 = first.compute_hash();
    assert_eq!(rt.on_proposal(sid, first, r).await.expect("first must seat"), h1);

    // Second DISTINCT body (different timestamp => different hash, still
    // otherwise valid) is refused, and the first seating survives.
    let second = genuine(&rt, &sched, rt.hc.height, [0u8; 32], 1_001, None).await;
    let h2 = second.compute_hash();
    assert_ne!(h2, h1, "precondition: distinct bodies hash distinctly");
    let err = rt
        .on_proposal(sid, second, r)
        .await
        .expect_err("equivocation must be refused");
    assert!(
        err.contains("already recorded"),
        "must name the reason, got: {err}"
    );
    assert_eq!(
        rt.hc.proposal,
        Some((sid, h1)),
        "the first seating must survive the equivocation attempt"
    );

    // The lower layer refuses it too: direct `receive_proposal` for the
    // second hash errors while the first stays idempotent-Ok.
    assert!(rt.hc.receive_proposal(sid, h1).is_ok());
    assert!(rt.hc.receive_proposal(sid, h2).is_err());
}

#[tokio::test]
async fn identical_rebroadcast_is_idempotent_ok() {
    let ks = keys(2);
    let mut rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, rt.hc.height, r);
    let sid = id(&sched);

    let block = genuine(&rt, &sched, rt.hc.height, [0u8; 32], 1_000, None).await;
    let bh = block.compute_hash();
    assert_eq!(rt.on_proposal(sid, block.clone(), r).await.expect("first must seat"), bh);
    // Delayed duplicate of the SAME body: accepted again, same hash, same round.
    assert_eq!(
        rt.on_proposal(sid, block, r)
            .await
            .expect("identical rebroadcast must be idempotent-Ok"),
        bh
    );
    assert_eq!(rt.hc.proposal, Some((sid, bh)));
}

// ============================================================================
// 7. Timed validation reports the same verdict with per-stage attribution.
// ============================================================================

#[tokio::test]
async fn timed_validation_matches_untimed_verdict_with_stages() {
    let ks = keys(2);
    let rt = runtime_for(&ks, 0).await;
    let r = rt.hc.round;
    let sched = sched_key(&rt, &ks, rt.hc.height, r);
    let root = rt.state.get_state_root().await;

    let good = genuine(&rt, &sched, rt.hc.height, [0u8; 32], 1_000, None).await;
    assert!(rt.validate_proposal(&good, root).is_ok());
    let (timed, stages) = rt.validate_proposal_timed(&good, root);
    assert!(timed.is_ok(), "timed path must agree on the good block");
    assert_eq!(stages.len(), 6, "must attribute all six expensive stages");
    let names: Vec<&str> = stages.iter().map(|(s, _)| s.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "proposer_sig_verify",
            "state_root_check",
            "order_commit",
            "tx_batch_verify",
            "fee_floor_mempool",
            "header_checks",
        ]
    );

    // A bad block (wrong prev_hash: not chained to the finalized head)
    // fails identically on both paths — the timed wrapper never softens the
    // verdict, it only attributes it.
    let bad = genuine(&rt, &sched, rt.hc.height, [9u8; 32], 1_000, None).await;
    let untimed_err = rt
        .validate_proposal(&bad, root)
        .expect_err("wrong prev_hash must fail");
    let (timed_res, _) = rt.validate_proposal_timed(&bad, root);
    let timed_err = timed_res.expect_err("timed path must fail identically");
    assert_eq!(untimed_err, timed_err);
}
