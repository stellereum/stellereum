//! §1 ACTOR MAILBOX on the LIVE BLOCK PATH.
//!
//! Nothing in the tree drove an actor send through `apply_block_transition`
//! before this: `step_actor_execution` (the old mailbox step, HashMap-order
//! and crediting blindly) is called only from tests and must never touch the
//! live path. These tests pin the new deterministic pass instead:
//!
//!  * the transactions step ENQUEUES a send into the recipient's inbox, and
//!    the mailbox pass - called once per block between the transactions step
//!    and the fee credit - DELIVERS it (credit, or bounce back to sender);
//!  * value conservation: sender debited at settlement, recipient credited at
//!    delivery, a bounce returns the value EXACTLY once, and the fees a block
//!    collects are the only other movement;
//!  * a failed body leaves NO partial effect (credit, transfer and queue all
//!    roll back before the bounce);
//!  * delivery order is deterministic in ADDRESS order, independent of the
//!    order accounts were inserted into the engine's HashMap - the exact
//!    nondeterminism `step_actor_execution` had;
//!  * a rejected transaction enqueues nothing and moves nothing;
//!  * session-key scope: a payload with an actor send needs the actor bit,
//!    and the recorded message sender is `tx.from` (the MASTER address), not
//!    the session key that signed;
//!  * a cross-shard actor send is refused (v1 is single-shard);
//!  * the live consensus path and the reorg path apply the same actor block
//!    to the same root.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ChainState, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, ActorSendBody, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_ACTOR_DELIVER, GAS_ACTOR_SEND, GAS_BASIC_TRANSFER};
use stellereum::zkml::{SessionKeyAuthorization, SCOPE_ACTOR_SEND, SCOPE_ALL, SCOPE_SVM_PAYLOAD};

/// Realistic block timestamp - never 0 (0 is exactly the hardcoded-clock bug
/// the block path already fixed once).
const TS: u64 = 1_760_000_000;
/// Chain id the default engine enforces; a grant must be minted for it.
const CHAIN_ID: u64 = 5757;
/// A non-master shard id, for the cross-shard refusal test.
const OTHER_SHARD: u32 = 1;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

/// True when NO account on this engine holds a queued message.
async fn mailbox_is_empty(e: &InMemoryStateEngine) -> bool {
    let map = e.accounts.read().await;
    map.values().all(|a| a.inbox.is_empty())
}

/// The declared gas for a payload of `sends` actor sends whose bodies get
/// `body_gas_budget` each. The block path charges the DECLARED limit as the
/// fee, so tests that assert balances must use exactly this number.
fn gas_for(sends: u64, body_gas_budget: u64) -> u64 {
    sends * (GAS_ACTOR_SEND + GAS_ACTOR_DELIVER + body_gas_budget) + 1_000
}

/// A bounce-enabled actor send (v1 requires `bounce = true`; the VM reverts
/// otherwise, so every send in these tests carries it).
fn send_op(recipient: [u8; 32], value: u64, body: Vec<OpCode>, gas_budget: u64) -> OpCode {
    OpCode::SysCallActorSend {
        recipient,
        value,
        body,
        bounce: true,
        gas_budget,
    }
}

fn mk_block(height: u64, ts: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: ts,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

// ===========================================================================
// 1. The queue: a send reaches the recipient's inbox via the block's
//    transactions step, and the pass then delivers it
// ===========================================================================

/// The two halves of the mailbox, pinned in order. `apply_block_parallel_fees`
/// is exactly the transactions step `apply_block_transition` runs (step 1);
/// `apply_actor_messages_at` is the pass it runs next (step 1b). Before the
/// pass, the message is OBSERVABLY queued with the right sender, recipient,
/// value and body; after it, the inbox is empty and the value landed.
#[tokio::test]
async fn send_reaches_the_inbox_from_the_block_transaction_step_then_the_pass_delivers() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x31);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x77u8; 32];
    engine
        .update_account(AccountState::new(sender, 10_000_000))
        .await;
    engine.update_account(AccountState::new(recipient, 0)).await;

    let gas = gas_for(1, 500);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        recipient,
        500, // plain amount, to the same recipient
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(recipient, 4_242, vec![], 500)],
    );

    // --- step 1: the transactions step only -------------------------------
    let (applied, failed, _fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), TS)
        .await;
    assert_eq!((applied, failed), (1, 0), "the send transaction applies");
    assert_eq!(status, vec![true]);

    // THE queue observation: the message is in the recipient's inbox, before
    // any delivery happened.
    let acc = engine
        .get_account(&recipient)
        .await
        .expect("recipient exists");
    assert_eq!(
        acc.inbox.len(),
        1,
        "the send must be queued, not delivered yet"
    );
    let msg = acc.inbox.front().expect("one message").clone();
    assert_eq!(msg.sender, sender, "the recorded sender is tx.from");
    assert_eq!(msg.recipient, recipient);
    assert_eq!(msg.value, 4_242);
    assert!(!msg.bounced, "a fresh send is not a bounce");
    assert!(msg.bounce, "v1 sends are always bounceable");
    let body: ActorSendBody = bincode::deserialize(&msg.body).expect("body decodes");
    assert!(body.program.is_empty(), "empty program");
    assert_eq!(body.gas_budget, 500);

    // Settlement already debited the value (delivery credits later) ...
    assert_eq!(
        balance(&engine, &sender).await,
        10_000_000 - 500 - gas - 4_242,
        "sender paid amount + fee + message value at settlement"
    );
    assert_eq!(
        balance(&engine, &recipient).await,
        500,
        "before the pass, the recipient holds only the plain amount - the \
         message value (4_242) is NOT credited yet"
    );

    // --- step 1b: the mailbox pass ---------------------------------------
    let blk = mk_block(1, TS, vec![], sender);
    let delivered = engine.apply_actor_messages_at(&blk).await;
    assert_eq!(delivered, 1, "exactly one message was delivered");

    let acc = engine
        .get_account(&recipient)
        .await
        .expect("recipient exists");
    assert!(
        acc.inbox.is_empty(),
        "drain-to-empty: the queue is empty after"
    );
    assert_eq!(
        acc.balance,
        500 + 4_242,
        "delivery adds the message value on top of the plain amount"
    );
    assert!(
        mailbox_is_empty(&engine).await,
        "no account holds a message"
    );
}

// ===========================================================================
// 2. Delivery credits the recipient and value is conserved
// ===========================================================================

#[tokio::test]
async fn delivery_credits_the_recipient_and_conserves_value() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x32);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x78u8; 32];
    let proposer = [0x99u8; 32];
    let start = 10_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;
    engine.update_account(AccountState::new(recipient, 0)).await;
    engine.update_account(AccountState::new(proposer, 0)).await;

    let gas = gas_for(1, 500);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        recipient, // tx.to == recipient: the plain amount lands there too
        777,
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(recipient, 4_242, vec![], 500)],
    );

    let out = engine
        .apply_block_transition(&mk_block(1, TS, vec![tx], proposer), 0)
        .await;
    assert_eq!(out.status, vec![true]);

    assert_eq!(
        balance(&engine, &recipient).await,
        777 + 4_242,
        "recipient got the plain amount AND the delivered message value"
    );
    assert_eq!(
        balance(&engine, &sender).await,
        start - 777 - gas - 4_242,
        "sender paid amount + declared fee + message value"
    );
    assert_eq!(
        balance(&engine, &proposer).await,
        gas,
        "the declared gas is the proposer's fee"
    );
    // Conservation: nothing minted, nothing destroyed.
    assert_eq!(
        balance(&engine, &sender).await
            + balance(&engine, &recipient).await
            + balance(&engine, &proposer).await,
        start
    );
    assert!(
        mailbox_is_empty(&engine).await,
        "queues empty at the block boundary"
    );
}

// ===========================================================================
// 3. Bounce returns the value EXACTLY once
// ===========================================================================

/// Send to an address that has no account: the settlement bounces it
/// immediately (the value is already debited), the pass delivers the bounce,
/// and the sender ends up down ONLY the fee - not down the value (lost), not
/// up (double credit) - with no phantom account created for the dead address.
#[tokio::test]
async fn bounce_returns_the_value_exactly_once() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x33);
    let sender = sender_sk.verifying_key().to_bytes();
    let mut missing = [0u8; 32];
    missing[0] = 0xDE;
    missing[1] = 0xAD;
    let proposer = [0x99u8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;
    engine.update_account(AccountState::new(proposer, 0)).await;

    let gas = gas_for(1, 0);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        sender, // plain amount back to self: only the fee and the value move
        0,
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(missing, 9_999, vec![], 0)],
    );

    let out = engine
        .apply_block_transition(&mk_block(1, TS, vec![tx], proposer), 0)
        .await;
    assert_eq!(out.status, vec![true], "the send itself applies");

    assert_eq!(
        balance(&engine, &sender).await,
        start - gas,
        "value came back exactly once: sender is down ONLY the fee - not down \
         9_999 (lost) and not up 9_999 (credited twice)"
    );
    assert_eq!(balance(&engine, &proposer).await, gas);
    assert!(
        engine.get_account(&missing).await.is_none(),
        "a bounce must not create the dead recipient's account"
    );
    assert!(
        mailbox_is_empty(&engine).await,
        "the bounce was consumed by the same block's pass"
    );
}

// ===========================================================================
// 4. A failed body leaves no partial effect
// ===========================================================================

/// The body transfers more than the delivered value + the recipient holds, so
/// the VM reverts: the recipient's credit, the attempted transfer to a third
/// party and the queue entry must ALL be gone, and the value returns to the
/// sender through the bounce.
#[tokio::test]
async fn failed_body_has_no_partial_effect() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x34);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x79u8; 32];
    let bystander = [0xC0u8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;
    engine.update_account(AccountState::new(recipient, 0)).await;
    engine.update_account(AccountState::new(bystander, 0)).await;

    // Body: pay the bystander 1_000 - unaffordable, because the delivery only
    // credits 100 first (the body runs against the recipient's balance).
    let body = vec![OpCode::Transfer {
        recipient: bystander,
        amount: 1_000,
    }];
    let gas = gas_for(1, 5_000);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        sender,
        0,
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(recipient, 100, body, 5_000)],
    );

    // Proposer == sender: the declared fee is credited straight back, so the
    // assertion below isolates the message value round-trip.
    let out = engine
        .apply_block_transition(&mk_block(1, TS, vec![tx], sender), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "the SEND applies; its body failed later, at delivery"
    );

    assert_eq!(
        balance(&engine, &recipient).await,
        0,
        "the failed body's delivery credit must be rolled back"
    );
    assert_eq!(
        balance(&engine, &bystander).await,
        0,
        "the body's transfer must not survive its revert"
    );
    assert_eq!(
        balance(&engine, &sender).await,
        start,
        "the value bounced back exactly once and the fee came back as the \
         proposer credit - so the sender is whole, and nobody else gained"
    );
    assert!(
        mailbox_is_empty(&engine).await,
        "bounce and queue both drained"
    );
}

// ===========================================================================
// 5. Deterministic delivery order, independent of insertion order
// ===========================================================================

/// Two messages whose bodies INTERACT: the outcome depends on which recipient
/// is delivered first, so this is a real probe for order nondeterminism - not
/// just an equality check that could pass by accident.
///
///   * A first: A's body pays B, then B's body pays A -> A ends with 100.
///   * B first: B's body reverts (B holds 0) and B bounces; A's body pays B
///     -> B ends with 100.
///
/// The delivery order is ADDRESS order (sorted), so both engines - which
/// insert the accounts in OPPOSITE orders, giving their HashMaps different
/// iteration orders - must agree on the final balances AND on the root. A
/// pass that iterated the HashMap directly would agree only by luck.
#[tokio::test]
async fn delivery_order_is_deterministic_independent_of_insertion_order() {
    let sender_sk = key(0x35);
    let sender = sender_sk.verifying_key().to_bytes();
    let a = [0xA1u8; 32];
    let b = [0xB1u8; 32];
    // Funds the sender's declared gas (two sends prepaid inside one tx).
    let start = 2_000_000u64;

    // Two engines with byte-identical state, built in opposite insertion order.
    let e1 = InMemoryStateEngine::new();
    e1.update_account(AccountState::new(a, 0)).await;
    e1.update_account(AccountState::new(b, 0)).await;
    e1.update_account(AccountState::new(sender, start)).await;

    let e2 = InMemoryStateEngine::new();
    e2.update_account(AccountState::new(sender, start)).await;
    e2.update_account(AccountState::new(b, 0)).await;
    e2.update_account(AccountState::new(a, 0)).await;

    assert_eq!(
        e1.get_state_root().await,
        e2.get_state_root().await,
        "precondition: identical state, regardless of insertion order"
    );

    let payload = vec![
        send_op(
            a,
            100,
            vec![OpCode::Transfer {
                recipient: b,
                amount: 100,
            }],
            500_000,
        ),
        send_op(
            b,
            0,
            vec![OpCode::Transfer {
                recipient: a,
                amount: 100,
            }],
            500_000,
        ),
    ];
    let gas = gas_for(2, 500_000);
    // Built ONCE and cloned: both engines apply the byte-identical block.
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        sender,
        0,
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
    );
    let blk = mk_block(1, TS, vec![tx], sender);

    let out1 = e1.apply_block_transition(&blk, 0).await;
    let out2 = e2.apply_block_transition(&blk, 0).await;
    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);

    let (a1, b1) = (balance(&e1, &a).await, balance(&e1, &b).await);
    let (a2, b2) = (balance(&e2, &a).await, balance(&e2, &b).await);
    assert_eq!(
        (a1, b1),
        (a2, b2),
        "insertion order must not change the outcome"
    );
    assert_eq!(
        e1.get_state_root().await,
        e2.get_state_root().await,
        "same block + same state => same root, whatever order the accounts \
         were inserted in"
    );

    // The outcome is PINNED, not merely equal: address order decides it, and
    // the addresses are part of the block's inputs.
    let (want_a, want_b) = if a < b { (100, 0) } else { (0, 100) };
    assert_eq!((a1, b1), (want_a, want_b), "delivery runs in address order");
    assert_eq!(
        a1 + b1,
        100,
        "the interacting bodies conserve the 100 nano-STELL in circulation"
    );
    assert!(mailbox_is_empty(&e1).await && mailbox_is_empty(&e2).await);
}

// ===========================================================================
// 6. A rejected transaction enqueues nothing
// ===========================================================================

#[tokio::test]
async fn rejected_transaction_enqueues_nothing_and_moves_nothing() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x36);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x7Au8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;
    engine.update_account(AccountState::new(recipient, 0)).await;
    let before = engine.get_state_root().await;

    // Valid signature, WRONG nonce: admitted nowhere, payload never runs.
    let gas = gas_for(1, 500);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        recipient,
        500,
        gas,
        7, // nonce 0 expected
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(recipient, 4_242, vec![], 500)],
    );

    let out = engine
        .apply_block_transition(&mk_block(1, TS, vec![tx], sender), 0)
        .await;
    assert_eq!(out.status, vec![false], "the transaction must be refused");
    assert_eq!(
        balance(&engine, &sender).await,
        start,
        "a rejected transaction moves no coins"
    );
    assert_eq!(balance(&engine, &recipient).await, 0);
    assert!(
        mailbox_is_empty(&engine).await,
        "a rejected transaction enqueues NOTHING - no message may ever be \
         delivered for a payload that never applied"
    );
    assert_eq!(
        engine.get_state_root().await,
        before,
        "a refused block body moves nothing at all"
    );
}

// ===========================================================================
// 7. Session-key scope + the recorded sender is the MASTER
// ===========================================================================

fn grant(master: &SigningKey, session: &SigningKey, scope: u64) -> SessionKeyAuthorization {
    SessionKeyAuthorization::sign_delegation(
        master,
        session.verifying_key().to_bytes(),
        2_000_000_000, // valid_until (well past TS)
        1_000_000,     // max_gas_spend
        scope,
        u64::MAX, // max_value_per_tx
        CHAIN_ID,
    )
}

/// Scope, both directions: a payload carrying `SysCallActorSend` needs the
/// ACTOR bit, and (like every payload) the payload bit - a grant holding only
/// one of the two is refused. With `SCOPE_ALL` the send applies, and the
/// message recorded in the inbox is sent by `tx.from` (the MASTER address),
/// never by the session key that produced the signature: `sign_with_session`
/// keeps the master as the sender precisely so the mailbox debits and records
/// the account the master authorized.
#[tokio::test]
async fn session_scope_gates_actor_sends_and_records_the_master_as_sender() {
    let master = key(0x37);
    let session = key(0x38);
    let master_pub = master.verifying_key().to_bytes();
    let recipient = [0x7Bu8; 32];
    let gas = gas_for(1, 500);

    let session_tx = |scope: u64| {
        Transaction::sign_with_session(
            &session,
            grant(&master, &session, scope),
            recipient,
            0,
            gas,
            0,
            MASTERCHAIN_SHARD,
            MASTERCHAIN_SHARD,
            vec![send_op(recipient, 4_242, vec![], 500)],
        )
    };

    // Refused: payload bit but no actor bit.
    let state = InMemoryStateEngine::new();
    state
        .update_account(AccountState::new(master_pub, 10_000_000))
        .await;
    state.update_account(AccountState::new(recipient, 0)).await;
    let err = state
        .apply_transaction(&session_tx(SCOPE_SVM_PAYLOAD), TS)
        .await
        .expect_err("an actor send needs the actor scope bit");
    assert!(
        err.contains("scope"),
        "the refusal must name the scope: {err}"
    );
    assert!(mailbox_is_empty(&state).await);

    // Refused: actor bit but no payload bit - the ACTOR bit must not be a
    // substitute for the payload capability it layers on top of.
    let err = state
        .apply_transaction(&session_tx(SCOPE_ACTOR_SEND), TS)
        .await
        .expect_err("the actor bit alone must not authorize a payload");
    assert!(
        err.contains("scope"),
        "the refusal must name the scope: {err}"
    );
    assert!(mailbox_is_empty(&state).await);
    assert_eq!(
        balance(&state, &master_pub).await,
        10_000_000,
        "a refused session transaction moves nothing"
    );

    // Accepted: everything is in scope (SCOPE_ALL carries both bits).
    state
        .apply_transaction(&session_tx(SCOPE_ALL), TS)
        .await
        .expect("SCOPE_ALL covers an actor send");

    let acc = state
        .get_account(&recipient)
        .await
        .expect("recipient exists");
    assert_eq!(acc.inbox.len(), 1, "the send is queued");
    let msg = acc.inbox.front().expect("one message");
    assert_eq!(
        msg.sender, master_pub,
        "the recorded message sender is tx.from - the MASTER - not the session \
         key that signed the transaction"
    );
    assert_ne!(
        msg.sender,
        session.verifying_key().to_bytes(),
        "the session key must never appear as the message sender"
    );
    assert_eq!(msg.value, 4_242);
}

// ===========================================================================
// 8. Cross-shard actor sends are refused (v1 is single-shard)
// ===========================================================================

#[tokio::test]
async fn cross_shard_actor_send_is_refused() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x39);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x7Cu8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;
    let before = engine.get_state_root().await;

    let gas = gas_for(1, 500);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        recipient,
        0,
        gas,
        0,
        MASTERCHAIN_SHARD, // source
        OTHER_SHARD,       // target: outbound cross-shard
        vec![send_op(recipient, 4_242, vec![], 500)],
    );

    let out = engine
        .apply_block_transition(&mk_block(1, TS, vec![tx], sender), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "v1 refuses an actor send inside a cross-shard transaction"
    );
    assert_eq!(
        balance(&engine, &sender).await,
        start,
        "the refused transaction moved nothing"
    );
    assert!(mailbox_is_empty(&engine).await, "nothing was queued");

    // The refused transaction moved NO value and queued NO message. The only
    // state it may touch is the sender's NONCE: a failed transaction must
    // still advance the nonce (anti-replay, SEC-07 - a free-failure tx that
    // could be replayed forever was a DoS vector). So the precise assertion
    // is "the tree equals a control engine whose only difference is the
    // sender's nonce".
    let control = InMemoryStateEngine::new();
    let mut control_sender = AccountState::new(sender, start);
    control_sender.nonce = 1;
    control.update_account(control_sender).await;
    assert_eq!(
        engine.get_state_root().await,
        control.get_state_root().await,
        "the refused transaction touched nothing but the sender's nonce"
    );
    let _ = before;
}

// ===========================================================================
// 9. Live vs reorg parity for an actor block
// ===========================================================================

/// Drive a genuine precommit quorum for `blk` through the live runtime and
/// attach the certificate the block body must carry (the shape
/// `tests/block_apply_parity_tests.rs` uses - both paths must apply the SAME
/// bytes, certificate included, or the comparison means nothing).
async fn certify(live: &mut ValidatorRuntime, ks: &[SigningKey], blk: &mut Block) -> [u8; 32] {
    let bh = blk.compute_hash();
    let height = blk.height;
    for k in ks.iter().take(3) {
        live.on_prevote(Vote::sign(k, height, 0, VoteKind::Prevote, Some(bh)))
            .expect("prevote accepted");
        live.on_precommit(Vote::sign(k, height, 0, VoteKind::Precommit, Some(bh)))
            .expect("precommit accepted");
    }
    assert_eq!(
        live.hc.try_precommit_quorum(),
        Some(bh),
        "precondition: a quorum must form at height {height}"
    );
    let cert = live.hc.precommit_qc.clone().expect("QC exists");
    blk.precommit_qc = Some(cert);
    bh
}

/// The SAME actor block, applied through the live consensus path
/// (`ValidatorRuntime::try_finalize` -> `apply_block_transition`) and through
/// the reorg path (`ChainState::apply_block` -> the same transition), on two
/// engines with byte-identical pre-state: same state root, same receipts, and
/// the message delivered on both.
#[tokio::test]
async fn live_and_reorg_paths_agree_on_an_actor_block() {
    const REWARD: u64 = 1_000_000_000;
    const BAL: u64 = 10_000 * 1_000_000_000;

    let ks: Vec<SigningKey> = (0..4u8)
        .map(|i| SigningKey::from_bytes(&[0x60 + i; 32]))
        .collect();
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );

    let sender_sk = key(0x3A);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x7Du8; 32];

    let mut engines = Vec::new();
    for _ in 0..2 {
        let e = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&e, &vs, BAL).await;
        e.update_account(AccountState::new(sender, 1_000_000)).await;
        e.update_account(AccountState::new(recipient, 0)).await;
        engines.push(e);
    }
    let engine_live = engines.remove(0);
    let engine_reorg = engines.remove(0);
    assert_eq!(
        engine_live.get_state_root().await,
        engine_reorg.get_state_root().await,
        "precondition: the engines start byte-identical"
    );

    let mut live = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine_live.clone(), 1)
        .with_block_reward(REWARD);
    let mut reorg = ChainState::new(engine_reorg.clone()).with_block_reward(REWARD);

    let gas = gas_for(1, 500);
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        sender,
        0,
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![send_op(recipient, 4_242, vec![], 500)],
    );

    let height = 1u64;
    let root = engine_live.get_state_root().await;
    let __order_txs = vec![tx];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
    let mut blk = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: root,
        transactions: __order_txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: ks[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    let bh = certify(&mut live, &ks, &mut blk).await;

    // ---- LIVE ----
    live.blocks.insert(bh, blk.clone());
    assert_eq!(
        live.try_finalize().await,
        Some(bh),
        "the live path must finalize height {height}"
    );
    // ---- REORG ----
    reorg.apply_block(&blk).await;

    assert_eq!(
        engine_live.get_state_root().await,
        engine_reorg.get_state_root().await,
        "STATE ROOT DIVERGED: a reorg over an actor block would fork here"
    );
    assert_eq!(
        live.applied_statuses, reorg.applied_statuses,
        "RECEIPTS DIVERGED"
    );
    assert_eq!(live.applied_statuses, vec![true]);
    for e in [&engine_live, &engine_reorg] {
        assert_eq!(
            balance(e, &recipient).await,
            4_242,
            "the message was delivered on this path"
        );
        let map = e.accounts.read().await;
        assert!(
            map.values().all(|a| a.inbox.is_empty()),
            "both paths drain the mailbox"
        );
    }
}

/// An actor send sharing a payload with an ordinary `Transfer`: the pass runs
/// AFTER the transactions step, so it must not disturb the settlement the two
/// already share (both movements land, and both are paid by the sender).
#[tokio::test]
async fn actor_send_coexists_with_a_plain_payload_transfer() {
    let engine = InMemoryStateEngine::new();
    let sender_sk = key(0x3B);
    let sender = sender_sk.verifying_key().to_bytes();
    let recipient = [0x7Eu8; 32];
    let transfer_to = [0xC1u8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;
    engine.update_account(AccountState::new(recipient, 0)).await;

    let gas = gas_for(1, 500) + GAS_BASIC_TRANSFER;
    let tx = Transaction::sign_with_payload(
        &sender_sk,
        sender,
        0,
        gas,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![
            OpCode::Transfer {
                recipient: transfer_to,
                amount: 1_000,
            },
            send_op(recipient, 2_000, vec![], 500),
        ],
    );

    let out = engine
        .apply_block_transition(&mk_block(1, TS, vec![tx], sender), 0)
        .await;
    assert_eq!(out.status, vec![true]);
    assert_eq!(balance(&engine, &transfer_to).await, 1_000);
    assert_eq!(balance(&engine, &recipient).await, 2_000);
    assert_eq!(
        balance(&engine, &sender).await,
        start - 1_000 - 2_000,
        "the transfer and the message value leave the sender; the declared \
         fee comes straight back because the sender IS the proposer"
    );
    assert!(mailbox_is_empty(&engine).await);
}
