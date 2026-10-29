//! §1 ACTOR MAILBOX: state-root discipline.
//!
//! The mailbox must obey the same root contract as every other consensus
//! effect: the committed root moves ONLY when a BLOCK applies it, two nodes
//! applying the same block derive the same root, and holding a signed
//! transaction (or reading state) moves nothing.
//!
//! Phase 1's drain-to-empty policy is what keeps this simple: an applied
//! block leaves NO queued messages behind, so there is no mailbox state to
//! commit, no new account encoding, and the genesis KAT's root cannot drift
//! on a chain that never carried an actor send.

use ed25519_dalek::SigningKey;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

/// Realistic block timestamp - never 0.
const TS: u64 = 1_760_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn actor_tx(sk: &SigningKey, recipient: [u8; 32], value: u64) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        recipient,
        0,
        30_000, // declared gas: covers the send's gas + delivery prepay
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallActorSend {
            recipient,
            value,
            body: vec![],
            bounce: true,
            gas_budget: 500,
        }],
    )
}

fn mk_block(height: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
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

async fn funded(seed: u8) -> (InMemoryStateEngine, SigningKey, [u8; 32]) {
    let sk = key(seed);
    let addr = sk.verifying_key().to_bytes();
    let e = InMemoryStateEngine::new();
    e.update_account(AccountState::new(addr, 10_000_000)).await;
    (e, sk, addr)
}

// ===========================================================================
// 1. Holding a signed transaction moves nothing
// ===========================================================================

/// Signing, verifying, hashing and policy-checking a transaction are all
/// read-only: none of them may touch the committed root. Only applying a
/// block does.
#[tokio::test]
async fn holding_a_signed_tx_moves_nothing() {
    let (e, sk, sender) = funded(0x41).await;
    let recipient = [0x88u8; 32];
    let root0 = e.get_state_root().await;

    // Build the transaction (this is what a node in the mempool would hold).
    let tx = actor_tx(&sk, recipient, 4_242);
    assert!(tx.verify_signature(), "sanity: it is a valid transaction");
    assert!(
        tx.check_session_policy(TS).is_ok(),
        "sanity: legacy passes policy"
    );
    let _hash = tx.compute_tx_hash();
    let _bytes = bincode::serialize(&tx).expect("serializes");

    // ...and every read of engine state afterwards is still read-only.
    let acct = e.get_account(&sender).await.expect("sender exists");
    assert_eq!(acct.balance, 10_000_000);
    let root1 = e.get_state_root().await;
    assert_eq!(
        root0, root1,
        "holding a signed transaction must not move the state root"
    );
    assert!(
        e.get_account(&recipient).await.is_none(),
        "holding a tx must not create the recipient"
    );
}

// ===========================================================================
// 2. The root moves only when the block applies
// ===========================================================================

#[tokio::test]
async fn root_moves_only_when_the_block_applies() {
    let (e, sk, _sender) = funded(0x42).await;
    let recipient = [0x89u8; 32];
    e.update_account(AccountState::new(recipient, 0)).await;
    let root0 = e.get_state_root().await;

    // Build (but do not apply) the transaction: no movement.
    let tx = actor_tx(&sk, recipient, 4_242);
    let held = e.get_state_root().await;
    assert_eq!(root0, held, "building the tx moved nothing");

    // Apply the block: the send is settled, delivered by the pass, and the
    // fee moves to the proposer - the root moves exactly once, here.
    let proposer = [0x99u8; 32];
    let out = e
        .apply_block_transition(&mk_block(1, vec![tx], proposer), 0)
        .await;
    assert_eq!(out.status, vec![true]);
    let root1 = e.get_state_root().await;
    assert_ne!(root1, root0, "the applied block must move the root");

    // An empty follow-up block (the mailbox is drained) must NOT move it
    // again: Phase 1 leaves no queued work behind.
    let out2 = e
        .apply_block_transition(&mk_block(2, vec![], proposer), 0)
        .await;
    assert_eq!(out2.applied, 0);
    assert_eq!(
        e.get_state_root().await,
        root1,
        "an empty block after delivery moves nothing - queues are empty at \
         the boundary"
    );
}

// ===========================================================================
// 3. The same block yields the same root on two engines
// ===========================================================================

/// Two engines funded with byte-identical state but DIFFERENT insertion
/// orders (which is what gives their HashMaps different iteration orders),
/// applying the byte-identical block: same root. The block - not the node -
/// determines the state.
#[tokio::test]
async fn same_block_produces_the_same_root_on_two_engines() {
    let sk = key(0x43);
    let sender = sk.verifying_key().to_bytes();
    let recipient = [0x8Au8; 32];

    let e1 = InMemoryStateEngine::new();
    e1.update_account(AccountState::new(sender, 10_000_000))
        .await;
    e1.update_account(AccountState::new(recipient, 0)).await;

    let e2 = InMemoryStateEngine::new();
    e2.update_account(AccountState::new(recipient, 0)).await;
    e2.update_account(AccountState::new(sender, 10_000_000))
        .await;

    let root0_1 = e1.get_state_root().await;
    let root0_2 = e2.get_state_root().await;
    assert_eq!(
        root0_1, root0_2,
        "precondition: identical state => identical pre-root"
    );

    let tx = actor_tx(&sk, recipient, 4_242);
    let blk = mk_block(1, vec![tx], sender);

    let out1 = e1.apply_block_transition(&blk, 0).await;
    let out2 = e2.apply_block_transition(&blk, 0).await;
    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);

    let root1_1 = e1.get_state_root().await;
    let root1_2 = e2.get_state_root().await;
    assert_eq!(
        root1_1, root1_2,
        "the same block on the same state must derive the same root - \
         otherwise every reorg and every replay would fork"
    );
    assert_ne!(
        root1_1, root0_1,
        "and the block did move it (sanity: the pass is not a no-op)"
    );
}
