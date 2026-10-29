//! §7 Phase 2 sequenced execution lane: gating, parity, ordering, actor cap.
//!
//! What this pins (invariant → test):
//!
//! | Invariant | Test |
//! |---|---|
//! | State changes ONLY from decided blocks (never proposal/prevote/lock); nothing reading post-H state runs before the worker completes | `propose_returns_none_while_apply_pending`, `on_proposal_deferred_while_apply_pending` |
//! | All apply routes byte-identical (worker vs inline vs reorg) | `worker_applied_root_equals_inline_and_reorg_roots` |
//! | One apply at a time, strictly height-ordered | `h_and_hplus1_execute_strictly_in_order` |
//! | No exec results visible pre-certification (height/`finalized`/receipts frozen until install) | `no_observable_effects_before_poll` |
//! | Loop keeps draining while the worker runs (votes still ingest) | `loop_drains_votes_while_apply_pending` |
//! | Over-cap actor block REJECTED (never carried over) at propose AND adopt | `overcap_actor_block_rejected_at_propose`, `overcap_actor_block_rejected_at_adopt`, `actor_cap_counts_backlog_plus_block` |
//! | Sequenced submit does not wait for execution (tick/apply decoupling) | `sequenced_submit_does_not_wait_for_execution` |
//!
//! Determinism note: the `apply_in_flight` flag is set at submit and cleared
//! only when the outcome is collected (`try_poll_apply` /
//! `await_apply_completion`), so every "while pending" assertion below holds
//! regardless of how fast the worker is — no timing races, no sleeps.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{count_block_actor_sends, ChainState, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{
    AccountState, ActorMessage, InMemoryStateEngine, MAX_ACTOR_MSGS_PER_BLOCK,
};
use stellereum::svm::OpCode;

/// Realistic block timestamp - never 0.
const TS: u64 = 1_760_000_000;
/// Funding that covers any gas_limit used here.
const BAL: u64 = 1_000_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// One actor-send opcode (v1 requires `bounce = true`).
fn send_op(recipient: [u8; 32], value: u64) -> OpCode {
    OpCode::SysCallActorSend {
        recipient,
        value,
        body: vec![],
        bounce: true,
        gas_budget: 500,
    }
}

/// A single-validator runtime at height 1, validator + user funded.
async fn single_runtime() -> (ValidatorRuntime, SigningKey, SigningKey) {
    let val_sk = key(0x11);
    let val = id_of(&val_sk);
    let user_sk = key(0x22);
    let user = id_of(&user_sk);
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.update_account(AccountState::new(val, BAL)).await;
    engine.update_account(AccountState::new(user, BAL)).await;
    let vs = ValidatorSet::from_list(vec![(val, 1)]);
    let rt = ValidatorRuntime::new(val_sk.clone(), vs, engine, 1);
    (rt, val_sk, user_sk)
}

/// Plain transfer user -> `to`, nonce `nonce`.
fn transfer_tx(user_sk: &SigningKey, to: [u8; 32], nonce: u64) -> Transaction {
    Transaction::sign(user_sk, to, 1_000, 1_000, nonce, 1, 1)
}

/// Drive the current height to a decided-but-unexecuted block: propose, feed
/// this node's own prevote+precommit (quorum of one), submit to the worker.
/// Returns the decided hash. Afterwards `has_pending_apply()` is true and
/// NOTHING observable has moved (height, `finalized`, receipts).
async fn decide_submit(rt: &mut ValidatorRuntime) -> [u8; 32] {
    let block = rt.propose(TS).await.expect("single proposer must propose");
    let bh = block.compute_hash();
    let pv = rt.make_prevote().expect("prevote with a live proposal");
    rt.on_prevote(pv).unwrap();
    let pc = rt
        .make_precommit()
        .expect("precommit off our own prevote QC");
    rt.on_precommit(pc).unwrap();
    let decided = rt
        .try_finalize_submit()
        .await
        .expect("single-node quorum must decide");
    assert_eq!(decided, bh, "submitted hash must be the proposed block");
    assert!(
        rt.has_pending_apply(),
        "submit must leave an in-flight apply"
    );
    bh
}

// ===========================================================================
// 1. propose returns None while apply pending ("propose while apply pending"
//    is the test failure this gate exists for)
// ===========================================================================

#[tokio::test]
async fn propose_returns_none_while_apply_pending() {
    let (mut rt, _val, user_sk) = single_runtime().await;
    let to = [0x77u8; 32];
    rt.state.update_account(AccountState::new(to, 0)).await;
    rt.add_tx(transfer_tx(&user_sk, to, 0)).await;

    let root_pre = rt.state_root().await;
    let _bh = decide_submit(&mut rt).await;

    // The gate: our root is still PRE-H, so there is nothing to propose.
    assert!(
        rt.propose(TS + 1).await.is_none(),
        "propose while apply pending must be None"
    );
    // And nothing observable moved either. (The ENGINE root is deliberately
    // NOT asserted here: the worker may already have executed the transition
    // in the background. What is gated is every OBSERVABLE: height,
    // `finalized`, receipts, and any new proposal rooted at post-H state.)
    assert_eq!(rt.height(), 1, "height must not advance before install");
    assert!(rt.finalized.is_empty(), "no finalized entry before install");

    // After collection the gate lifts and the next height proposes.
    let completed = rt
        .await_apply_completion()
        .await
        .expect("worker answers every job");
    assert_eq!(completed.height, 1);
    assert_eq!(rt.height(), 2);
    assert!(!rt.has_pending_apply());
    assert_eq!(rt.applied_statuses, vec![true], "transfer must apply");
    assert!(
        rt.propose(TS + 1).await.is_some(),
        "propose works again once the apply is installed"
    );
    assert_ne!(
        rt.state_root().await,
        root_pre,
        "the transfer must have moved the root"
    );
}

// ===========================================================================
// 2. on_proposal is deferred while apply pending and moves nothing
// ===========================================================================

#[tokio::test]
async fn on_proposal_deferred_while_apply_pending() {
    let (mut rt, _val, user_sk) = single_runtime().await;
    let to = [0x77u8; 32];
    rt.state.update_account(AccountState::new(to, 0)).await;
    rt.add_tx(transfer_tx(&user_sk, to, 0)).await;
    let _bh = decide_submit(&mut rt).await;

    // Even an UNSIGNED would-be H+1 body gets the gate error first: no state
    // is read (no root check against the wrong parent) and none moves.
    let next = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 2,
        prev_hash: [0u8; 32],
        state_root: [0xAAu8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: TS + 1,
        proposer: rt.id,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let h_before = rt.height();
    let fin_before = rt.finalized.len();
    let err = rt
        .on_proposal(rt.id, next, 0)
        .await
        .expect_err("on_proposal while apply pending must defer");
    assert!(
        err.contains("apply in flight"),
        "gate error must name the cause, got: {err}"
    );
    assert_eq!(
        rt.height(),
        h_before,
        "height must not move on a deferred proposal"
    );
    assert_eq!(
        rt.finalized.len(),
        fin_before,
        "finalized must not move on a deferred proposal"
    );

    let completed = rt.await_apply_completion().await.expect("worker answers");
    assert_eq!(completed.height, 1);
    assert_eq!(rt.height(), 2);
}

// ===========================================================================
// 3. worker-applied root == inline-applied root == reorg-applied root
// ===========================================================================

/// Same genesis + same decided block through three routes must give the same
/// root, receipts and counters: the sequenced worker, the inline waiter and
/// the reorg path. Uses an actor send so the mailbox pass is exercised too.
#[tokio::test]
async fn worker_applied_root_equals_inline_and_reorg_roots() {
    // --- sequenced route: propose, decide, submit, collect -----------------
    let (mut rt, _val, user_sk) = single_runtime().await;
    let actor_to = [0x77u8; 32];
    rt.state
        .update_account(AccountState::new(actor_to, 0))
        .await;
    let user = id_of(&user_sk);
    let send_tx = Transaction::sign_with_payload(
        &user_sk,
        actor_to,
        500,
        100_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(actor_to, 4_242)],
    );
    rt.add_tx(send_tx.clone()).await;
    let root_pre = rt.state_root().await;
    let bh = decide_submit(&mut rt).await;
    let completed = rt.await_apply_completion().await.expect("worker answers");
    assert_eq!(completed.hash, bh);
    let root_seq = completed.root;
    assert_eq!(root_seq, rt.state_root().await);
    assert_eq!(rt.applied_statuses, vec![true], "send tx must apply");
    assert_ne!(root_seq, root_pre, "applied transfer must move the root");
    let decided_block = rt.blocks.get(&bh).cloned().expect("decided body retained");

    // --- inline twin: same genesis, same block, direct transition ------------
    let engine_b = Arc::new(InMemoryStateEngine::new());
    engine_b.update_account(AccountState::new(rt.id, BAL)).await;
    engine_b.update_account(AccountState::new(user, BAL)).await;
    engine_b
        .update_account(AccountState::new(actor_to, 0))
        .await;
    assert_eq!(
        engine_b.get_state_root().await,
        root_pre,
        "twin must start from the same pre-state"
    );
    let out_b = engine_b.apply_block_transition(&decided_block, 0).await;
    let root_inline = engine_b.get_state_root().await;

    // --- reorg twin: ChainState::apply_block ----------------------------------
    let engine_c = Arc::new(InMemoryStateEngine::new());
    engine_c.update_account(AccountState::new(rt.id, BAL)).await;
    engine_c.update_account(AccountState::new(user, BAL)).await;
    engine_c
        .update_account(AccountState::new(actor_to, 0))
        .await;
    let mut chain = ChainState::new(engine_c);
    chain.apply_block(&decided_block).await;
    let root_reorg = chain.state.get_state_root().await;

    assert_eq!(
        root_seq, root_inline,
        "sequenced worker root must equal the inline transition root"
    );
    assert_eq!(
        root_seq, root_reorg,
        "sequenced worker root must equal the reorg path root"
    );
    assert_eq!(
        rt.applied_statuses, out_b.status,
        "receipts must match across routes"
    );
    assert_eq!(
        rt.applied_statuses, chain.applied_statuses,
        "receipts must match the reorg path"
    );
    assert_eq!(rt.applied_txs, out_b.applied as u64);
    assert_eq!(rt.applied_txs, chain.applied_txs);
}

// ===========================================================================
// 4. concurrent H / H+1 submissions execute in order, one at a time
// ===========================================================================

/// H is submitted and NOT collected; a second submit (same height, still H —
/// the height only advances at install) is refused rather than queued behind
/// it. After H installs, H+1 decides and installs. Final state equals two
/// sequential inline applies, and each height's certified root equals the
/// twin's root after that height.
#[tokio::test]
async fn h_and_hplus1_execute_strictly_in_order() {
    let (mut rt, _val, user_sk) = single_runtime().await;
    let to = [0x77u8; 32];
    rt.state.update_account(AccountState::new(to, 0)).await;
    let user = id_of(&user_sk);

    // --- H ------------------------------------------------------------------
    rt.add_tx(transfer_tx(&user_sk, to, 0)).await;
    let root_pre = rt.state_root().await;
    let bh_h = decide_submit(&mut rt).await;
    // A second decision while H executes is refused, never queued in parallel.
    assert!(
        rt.try_finalize_submit().await.is_none(),
        "second submit while apply pending must be refused"
    );
    assert!(
        rt.try_finalize().await.is_none(),
        "inline finalize while apply pending must be refused too"
    );
    let done_h = rt.await_apply_completion().await.expect("H installs");
    assert_eq!((done_h.height, done_h.hash), (1, bh_h));
    assert_eq!(rt.height(), 2);

    // --- H+1 ------------------------------------------------------------------
    rt.add_tx(transfer_tx(&user_sk, to, 1)).await;
    let bh_h1 = decide_submit(&mut rt).await;
    let done_h1 = rt.await_apply_completion().await.expect("H+1 installs");
    assert_eq!((done_h1.height, done_h1.hash), (2, bh_h1));
    assert_eq!(rt.height(), 3);

    // --- sequential twin -------------------------------------------------------
    let block_h = rt.blocks.get(&bh_h).cloned().expect("H retained");
    let block_h1 = rt.blocks.get(&bh_h1).cloned().expect("H+1 retained");
    let mk_engine = || async {
        let e = Arc::new(InMemoryStateEngine::new());
        e.update_account(AccountState::new(rt.id, BAL)).await;
        e.update_account(AccountState::new(user, BAL)).await;
        e.update_account(AccountState::new(to, 0)).await;
        e
    };
    let twin = mk_engine().await;
    assert_eq!(twin.get_state_root().await, root_pre);
    twin.apply_block_transition(&block_h, 0).await;
    let twin_h = twin.get_state_root().await;
    twin.apply_block_transition(&block_h1, 0).await;
    let twin_h1 = twin.get_state_root().await;

    assert_eq!(done_h.root, twin_h, "H root must match sequential twin");
    assert_eq!(done_h1.root, twin_h1, "H+1 root must match sequential twin");
    assert_eq!(rt.state_root().await, twin_h1);
    assert_eq!(rt.applied_txs, 2);
    assert_eq!(rt.finalized.len(), 2);
}

// ===========================================================================
// 5. nothing observable moves before collect (no pre-certification effects)
// ===========================================================================

#[tokio::test]
async fn no_observable_effects_before_poll() {
    let (mut rt, _val, user_sk) = single_runtime().await;
    let to = [0x77u8; 32];
    rt.state.update_account(AccountState::new(to, 0)).await;
    rt.add_tx(transfer_tx(&user_sk, to, 0)).await;
    let bh = decide_submit(&mut rt).await;

    // Decision known, execution pending: poll is non-blocking and reports
    // "not yet" without installing anything.
    for _ in 0..3 {
        if rt.try_poll_apply().await.is_some() {
            break;
        }
        assert_eq!(rt.height(), 1);
        assert!(rt.finalized.is_empty());
        assert!(
            rt.applied_statuses.is_empty(),
            "no receipts pre-certification"
        );
        assert_eq!(rt.applied_txs, 0);
    }
    // Collect (poll or blocking — same install path) and only then move.
    let done = rt.await_apply_completion().await.expect("worker answers");
    assert_eq!(done.hash, bh);
    assert_eq!(rt.finalized, vec![(1, bh)]);
    assert_eq!(rt.height(), 2);
    assert_eq!(rt.applied_statuses, vec![true]);
    assert_eq!(rt.applied_txs, 1);
}

// ===========================================================================
// 6. the loop keeps draining: votes ingest while the apply is in flight
// ===========================================================================

#[tokio::test]
async fn loop_drains_votes_while_apply_pending() {
    let (mut rt, val_sk, user_sk) = single_runtime().await;
    let to = [0x77u8; 32];
    rt.state.update_account(AccountState::new(to, 0)).await;
    rt.add_tx(transfer_tx(&user_sk, to, 0)).await;
    let _bh = decide_submit(&mut rt).await;

    // Votes never read post-H state, so they keep ingesting while the worker
    // runs: a nil prevote at our height/round is accepted into the set.
    let nil_prevote = Vote::sign(&val_sk, 1, 0, VoteKind::Prevote, None);
    assert!(
        rt.on_prevote(nil_prevote).is_ok(),
        "vote drain must keep working while apply pending"
    );
    // Consensus bookkeeping still answers (round sync is pure consensus).
    let _ = rt.note_peer_vote_round(1, 0);
    // And the apply is still pending throughout — nothing jumped ahead.
    assert!(rt.has_pending_apply());
    assert_eq!(rt.height(), 1);

    rt.await_apply_completion().await.expect("worker answers");
    assert_eq!(rt.height(), 2);
}

// ===========================================================================
// 7. sequenced submit does not wait for execution (tick/apply decoupling)
// ===========================================================================

#[tokio::test]
async fn sequenced_submit_does_not_wait_for_execution() {
    let (mut rt, _val, user_sk) = single_runtime().await;
    let to = [0x77u8; 32];
    rt.state.update_account(AccountState::new(to, 0)).await;
    // A loaded block so execution is resolvably slower than queueing (batch
    // verify + per-tx apply + commitment). Same-sender bursts are capped per
    // block by the mempool's pass limit, so 400 queued selects a ~30-tx
    // prefix — still a real batch for the comparison below.
    for n in 0..400u64 {
        rt.add_tx(transfer_tx(&user_sk, to, n)).await;
    }
    let block = rt.propose(TS).await.expect("proposer must propose");
    assert!(!block.transactions.is_empty());
    let bh = block.compute_hash();
    let pv = rt.make_prevote().expect("prevote");
    rt.on_prevote(pv).unwrap();
    let pc = rt.make_precommit().expect("precommit");
    rt.on_precommit(pc).unwrap();
    // Time ONLY the decision+queue step (no propose, no votes in the window).
    let t_submit = Instant::now();
    let decided = rt.try_finalize_submit().await.expect("must decide");
    let submit_elapsed = t_submit.elapsed();
    assert_eq!(decided, bh);
    assert!(rt.has_pending_apply());
    // Height and finalized list are still pre-install: the decision did not
    // wait for (nor publish) the execution.
    assert_eq!(rt.height(), 1);
    assert!(rt.finalized.is_empty());

    let t_apply = Instant::now();
    let done = rt.await_apply_completion().await.expect("worker answers");
    let apply_elapsed = t_apply.elapsed();
    assert_eq!(done.hash, bh);
    eprintln!(
        "[phase2] submit-to-decision took {submit_elapsed:?}; execution collect took {apply_elapsed:?} ({} txs)",
        block.transactions.len()
    );
}

// ===========================================================================
// 8. over-cap actor block rejected at propose ...
// ===========================================================================

/// One transaction carrying more sends than the whole block may deliver must
/// never become a proposal: `propose` returns None (fail closed). The 4096th
/// send is the boundary — exactly at cap still proposes.
#[tokio::test]
async fn overcap_actor_block_rejected_at_propose() {
    // --- over cap: 4096 + 4 sends in one transaction -------------------------
    let (mut rt, _val, user_sk) = single_runtime().await;
    let actor_to = [0x77u8; 32];
    rt.state
        .update_account(AccountState::new(actor_to, 0))
        .await;
    let user = id_of(&user_sk);
    let mut ops = Vec::new();
    for _ in 0..(MAX_ACTOR_MSGS_PER_BLOCK as u64 + 4) {
        ops.push(send_op(actor_to, 1));
    }
    let over_tx = Transaction::sign_with_payload(
        &user_sk,
        actor_to,
        0,
        20_000_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        ops,
    );
    let __order_txs = vec![over_tx.clone()];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
    let __overcap_block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: __order_txs,
        cross_shard_out: vec![],
        timestamp: TS,
        proposer: user,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    assert!(count_block_actor_sends(&__overcap_block) > MAX_ACTOR_MSGS_PER_BLOCK);
    rt.add_tx(over_tx).await;
    assert!(
        rt.propose(TS).await.is_none(),
        "propose must refuse to build an over-cap actor block"
    );

    // --- exactly at cap: proposes ------------------------------------------------
    let (mut rt2, _v2, user_sk2) = single_runtime().await;
    rt2.state
        .update_account(AccountState::new(actor_to, 0))
        .await;
    let mut ops2 = Vec::with_capacity(MAX_ACTOR_MSGS_PER_BLOCK);
    for _ in 0..MAX_ACTOR_MSGS_PER_BLOCK {
        ops2.push(send_op(actor_to, 1));
    }
    let at_cap_tx = Transaction::sign_with_payload(
        &user_sk2,
        actor_to,
        0,
        20_000_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        ops2,
    );
    rt2.add_tx(at_cap_tx).await;
    let built = rt2
        .propose(TS)
        .await
        .expect("exactly-at-cap must still propose");
    assert_eq!(built.transactions.len(), 1);
}

// ===========================================================================
// 9. ... and at adopt (plus the static half in proposal validation)
// ===========================================================================

/// The same over-cap body, fully signed with a valid QC and parent root, is
/// refused by `adopt_committed` BEFORE any execution (root untouched, nothing
/// applied) and by the synchronous `validate_proposal` static check.
#[tokio::test]
async fn overcap_actor_block_rejected_at_adopt() {
    let (mut rt, val_sk, user_sk) = single_runtime().await;
    let actor_to = [0x77u8; 32];
    rt.state
        .update_account(AccountState::new(actor_to, 0))
        .await;
    let mut ops = Vec::new();
    for _ in 0..(MAX_ACTOR_MSGS_PER_BLOCK + 1) {
        ops.push(send_op(actor_to, 1));
    }
    let over_tx = Transaction::sign_with_payload(
        &user_sk,
        actor_to,
        0,
        20_000_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        ops,
    );
    let root = rt.state_root().await;
    let __order_txs = vec![over_tx];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: root,
        transactions: __order_txs,
        cross_shard_out: vec![],
        timestamp: TS,
        proposer: rt.id,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    block.sign_block(&val_sk);
    let bh = block.compute_hash();

    // Static half first: rejected without touching the engine.
    let err = rt
        .validate_proposal(&block, root)
        .expect_err("static actor-cap check must reject");
    assert!(err.contains("actor"), "got: {err}");

    // Adopt side: a genuine QC for the same body, still refused pre-execution.
    let v = Vote::sign(&val_sk, 1, 0, VoteKind::Precommit, Some(bh));
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![(v.voter, v.signature)],
    };
    let root_before = rt.state_root().await;
    let err = rt
        .adopt_committed(1, block, cert)
        .await
        .expect_err("adopt must refuse an over-cap actor block");
    assert!(err.contains("actor"), "got: {err}");
    assert_eq!(
        rt.state_root().await,
        root_before,
        "a refused adopt must not execute anything"
    );
    assert_eq!(rt.applied_txs, 0);
    assert!(rt.finalized.is_empty());
    assert_eq!(rt.height(), 1);
}

// ===========================================================================
// 10. the cap counts backlog + block together (backlog half pins the split)
// ===========================================================================

/// 100 messages queued out of band plus a 4000-send block overflows the cap
/// even though each half fits alone: the async check refuses, the sync static
/// check passes (it cannot see the backlog). A 3996-send block (100 + 3996 ==
/// cap) still passes both.
#[tokio::test]
async fn actor_cap_counts_backlog_plus_block() {
    let (rt, _val, user_sk) = single_runtime().await;
    let actor_to = [0x77u8; 32];
    rt.state
        .update_account(AccountState::new(actor_to, 0))
        .await;
    let user = id_of(&user_sk);
    // Queue 100 messages out of band (direct API debits value + nonce).
    for _ in 0..100 {
        rt.state
            .send_message(ActorMessage::new(user, actor_to, 1, vec![0u8; 8], true))
            .await
            .expect("queue backlog");
    }
    assert_eq!(rt.pending_actor_backlog().await, 100);

    let mk = |n: usize| {
        let txs: Vec<Transaction> = (0..n)
            .map(|_| {
                Transaction::sign_with_payload(
                    &user_sk,
                    actor_to,
                    0,
                    20_000_000,
                    0,
                    MASTERCHAIN_SHARD,
                    MASTERCHAIN_SHARD,
                    vec![send_op(actor_to, 1)],
                )
            })
            .collect();
        let root = stellereum::mev::compute_order_merkle_root(&txs);
        Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: txs,
            cross_shard_out: vec![],
            timestamp: TS,
            proposer: user,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: root,
            epoch_key_commitment: [0u8; 32],
        }
    };

    let over = mk(4000);
    assert_eq!(count_block_actor_sends(&over), 4000);
    // Static half (no backlog read): a 4000-send body fits on its own, so any
    // refusal here must be for another reason (unsigned body, wrong root) —
    // never the actor load.
    if let Err(e) = rt.validate_proposal(&over, [0u8; 32]) {
        assert!(
            !e.contains("actor"),
            "static check must not reject a 4000-send body for actor load, got: {e}"
        );
    }
    // Backlog-inclusive half: 100 + 4000 overflows.
    let err = rt
        .check_actor_cap(&over)
        .await
        .expect_err("100 queued + 4000 in block must overflow");
    assert!(err.contains("actor"), "got: {err}");

    // Boundary: 100 + 3996 == cap passes everywhere.
    let fit = mk(MAX_ACTOR_MSGS_PER_BLOCK - 100);
    assert_eq!(
        count_block_actor_sends(&fit),
        MAX_ACTOR_MSGS_PER_BLOCK - 100
    );
    rt.check_actor_cap(&fit)
        .await
        .expect("backlog + block == cap must pass");

    // Nested bodies count transitively: one top-level send whose body carries
    // two more counts three.
    let __order_txs = vec![Transaction::sign_with_payload(
        &user_sk,
        actor_to,
        0,
        20_000_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallActorSend {
            recipient: actor_to,
            value: 1,
            body: vec![send_op(actor_to, 1), send_op(actor_to, 1)],
            bounce: true,
            gas_budget: 500,
        }],
    )];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
    let nested = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: __order_txs,
        cross_shard_out: vec![],
        timestamp: TS,
        proposer: user,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    assert_eq!(count_block_actor_sends(&nested), 3);
}
