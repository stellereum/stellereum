//! Sharding milestone M2: atomic, deterministic cross-shard value transfer.
//!
//! M1 proved two shards can run in one process. M2 proves value can move
//! between them:
//!
//!  1. A transaction whose `target_shard` differs from its `source_shard` is
//!     admitted to the SOURCE shard's mempool. When the source block finalizes,
//!     the transaction is applied there (sender debited), an outbound
//!     `CrossShardMessage` is committed into `Block.cross_shard_out`, and the
//!     value leaves the source exactly once.
//!  2. The target shard, producing its next block, pulls inbound messages from
//!     the node-local KV, commits a consumption record (the same
//!     `cross_shard_out` field), and credits the recipient.
//!  3. A consumed message can never be credited twice, and a caught-up node
//!     replays the same chain to the same state root.
//!
//! Everything is gated on `ShardRegistry::is_sharded()`, and `Block` /
//! `Transaction` gain NO new fields (`cross_shard_out` is pre-existing and is
//! already hashed into block identity), so every pre-sharding test is
//! untouched.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::{Cluster, ShardedCluster};
use stellereum::sharding::{
    Block, CrossShardKey, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL,
    MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

/// A fresh shard pair sharing one node-local cross-shard transport.
async fn sharded_pair(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard1_funding {
        s1.update_account(AccountState::new(*addr, *bal)).await;
    }
    ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    )
}

async fn balance(cluster: &Cluster, addr: &[u8; 32]) -> u64 {
    cluster.nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// The value transfer at the heart of M2.
#[tokio::test]
async fn cross_shard_transfer_debits_source_credits_target_and_conserves_supply() {
    let validator = key(1);
    let sender = key(2);
    let recipient = key(3);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();
    let validator_addr = validator.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let supply_before = balance(sc.shard(SHARD0), &sender_addr).await
        + balance(sc.shard(SHARD0), &validator_addr).await
        + balance(sc.shard(SHARD1), &recipient_addr).await;

    let amount = 100u64;
    let gas = 10u64;
    let tx = Transaction::sign(&sender, recipient_addr, amount, gas, 0, SHARD0, SHARD1);

    // Admitted to the SOURCE shard's mempool. The destination rejects it (its
    // sender has no balance there), which is exactly the single-source rule.
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx.clone()).await;

    // 1. Source block: debit + emit the committed outbound message.
    let src_bh = sc.run_height(SHARD0, 1).await;
    let src_block = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .cloned()
        .expect("source block body retained");

    assert_eq!(src_block.shard_id, SHARD0);
    assert!(
        src_block
            .transactions
            .iter()
            .any(|t| t.compute_tx_hash() == tx.compute_tx_hash()),
        "the cross-shard tx must be applied on its source shard"
    );
    assert_eq!(
        src_block.cross_shard_out.len(),
        1,
        "source must emit one outbound message"
    );
    let msg = src_block.cross_shard_out[0].clone();
    assert!(msg.is_outbound_for(SHARD0));
    assert!(
        !msg.trusted,
        "a block-carried message must never be locally trusted"
    );

    // Sender debited amount + gas; the amount is burned off-source; the gas is
    // the proposer fee. The recipient does NOT exist on the source shard.
    assert_eq!(
        balance(sc.shard(SHARD0), &sender_addr).await,
        1_000 - amount - gas
    );
    assert_eq!(balance(sc.shard(SHARD0), &validator_addr).await, gas);
    assert!(sc.shard(SHARD0).nodes[0]
        .state
        .get_account(&recipient_addr)
        .await
        .is_none());

    // 2. Target block: consume the inbound message and credit the recipient.
    let tgt_bh = sc.run_height(SHARD1, 2).await;
    let tgt_block = sc.shard(SHARD1).nodes[0]
        .blocks
        .get(&tgt_bh)
        .cloned()
        .expect("target block body retained");

    assert_eq!(tgt_block.shard_id, SHARD1);
    assert!(
        tgt_block.transactions.is_empty(),
        "the destination must not re-apply the transaction as a normal tx"
    );
    assert!(
        tgt_block
            .cross_shard_out
            .iter()
            .any(|m| m.msg_id == msg.msg_id && m.is_inbound_for(SHARD1)),
        "the target block must commit the consumption record"
    );
    assert_eq!(
        balance(sc.shard(SHARD1), &recipient_addr).await,
        amount,
        "the recipient must be credited exactly once on the target shard"
    );

    // Supply across BOTH shards is conserved.
    let supply_after = balance(sc.shard(SHARD0), &sender_addr).await
        + balance(sc.shard(SHARD0), &validator_addr).await
        + balance(sc.shard(SHARD1), &recipient_addr).await;
    assert_eq!(
        supply_after, supply_before,
        "cross-shard transfer must conserve supply"
    );

    // Determinism: a block's cross-shard records are bound into its identity.
    let mut tampered = tgt_block.clone();
    tampered.cross_shard_out.clear();
    tampered.validator_signatures.clear();
    tampered.sign_block(&validator);
    assert_ne!(
        tampered.compute_hash(),
        tgt_bh,
        "dropping a consumption record must change the target block hash"
    );
}

/// The replay proof, at the state-engine level: applying the SAME inbound
/// message twice credits exactly once and never mints a second time. This is
/// the guard that makes a rebuilding/caught-up shard deterministic.
#[tokio::test]
async fn replaying_a_consumed_message_is_credited_only_once() {
    let validator = key(10);
    let sender = key(11);
    let recipient = key(12);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    // Produce one genuine, proof-carrying message by running the source shard.
    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, 250, 5, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx).await;
    let src_bh = sc.run_height(SHARD0, 1).await;
    let msg = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .unwrap()
        .cross_shard_out[0]
        .clone();
    assert!(
        msg.verify_inclusion_strict(),
        "the emitted message must carry a valid proof"
    );

    // A pristine target engine (what a rebuilding node starts from).
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();
    let block = Block {
        shard_id: SHARD1,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: engine.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![msg.clone()],
        timestamp: 1,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };

    let first = engine.apply_cross_shard_consumptions(&block).await;
    assert_eq!(first, 1, "the first application must credit");
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        250
    );

    // Replaying the identical consumption record (as a Byzantine proposer
    // might) must be a no-op.
    let second = engine.apply_cross_shard_consumptions(&block).await;
    assert_eq!(second, 0, "a replayed message must be rejected");
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        250,
        "replay must not mint a second time"
    );
    assert_eq!(engine.cross_shard_consumed_len().await, 1);
    assert!(
        engine
            .is_cross_shard_consumed(&CrossShardKey::of(&msg))
            .await
    );
}

/// The runtime-level replay proof: a duplicate lingering in the KV is filtered
/// out of the next target block, and `validate_proposal` refuses a forged
/// proposal that re-includes it.
#[tokio::test]
async fn target_filters_and_rejects_a_replayed_inbound_message() {
    let validator = key(20);
    let sender = key(21);
    let recipient = key(22);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, 300, 5, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx).await;
    let src_bh = sc.run_height(SHARD0, 1).await;
    let msg = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .unwrap()
        .cross_shard_out[0]
        .clone();

    // First target height consumes it.
    sc.run_height(SHARD1, 2).await;
    assert_eq!(balance(sc.shard(SHARD1), &recipient_addr).await, 300);

    // Re-publish the SAME message (a stale KV entry) and run another height:
    // the target must skip it rather than credit twice.
    sc.transport.broadcast_cross_shard(&msg).await.unwrap();
    let bh2 = sc.run_height(SHARD1, 3).await;
    let block2 = sc.shard(SHARD1).nodes[0].blocks.get(&bh2).cloned().unwrap();
    assert!(
        block2
            .cross_shard_out
            .iter()
            .all(|m| m.msg_id != msg.msg_id),
        "a consumed message must not be re-included"
    );
    assert_eq!(balance(sc.shard(SHARD1), &recipient_addr).await, 300);

    // A forged proposal that re-includes the consumed message is refused by
    // validation, even though its proof is cryptographically valid: the replay
    // key was already credited on this chain.
    let node = &sc.shard(SHARD1).nodes[0];
    let height = node.height();
    let prev = node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD1,
        height,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![msg.clone()],
        timestamp: 4,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    forged.sign_block(&validator);
    let err = node
        .validate_proposal(&forged, root)
        .expect_err("a replayed consumption must be refused");
    assert!(err.contains("replayed"), "{err}");
}

/// Two independently-built target shards, given the SAME committed message,
/// derive the SAME state root. This is the determinism guarantee requirement 3
/// asks for: state moves only from a block, and the block is the same bytes.
#[tokio::test]
async fn two_independent_target_shards_derive_the_same_root() {
    let validator = key(30);
    let sender = key(31);
    let recipient = key(32);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    // One source shard, to produce a genuine proof-carrying message.
    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, 123, 7, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx).await;
    let src_bh = sc.run_height(SHARD0, 1).await;
    let msg = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .unwrap()
        .cross_shard_out[0]
        .clone();

    // Two independent target shards with identical genesis. Each gets its own
    // node-local transport seeded with the SAME message.
    let mut roots = Vec::new();
    for _ in 0..2 {
        let engine = Arc::new(InMemoryStateEngine::new());
        // Identical genesis on both: one unrelated funded account so the root
        // is not the empty-trie root.
        engine
            .update_account(AccountState::new([0xAAu8; 32], 777))
            .await;
        let transport = CrossShardTransport::local();
        transport.broadcast_cross_shard(&msg).await.unwrap();
        let mut cluster = Cluster::new_sharded_with_transport(
            vec![(validator.clone(), engine)],
            SHARD1,
            sharded(),
            transport,
        );
        cluster.run_height(1).await;
        roots.push(cluster.nodes[0].state_root().await);
    }

    assert_eq!(
        roots[0], roots[1],
        "two independently-built target shards must derive the same state root"
    );
}

/// A caught-up / rebuilding target shard replays the SAME committed records and
/// reaches the SAME state root as the node that originally applied them.
///
/// The live target applies block H and credits the recipient; a second target
/// starts from identical genesis and applies an equivalent block carrying the
/// same message. State moves only from the block, so the roots must agree —
/// and a replay of the record on the rebuilt engine must then be a no-op.
#[tokio::test]
async fn a_rebuilding_target_reproduces_the_same_root_and_rejects_replay() {
    let validator = key(40);
    let sender = key(41);
    let recipient = key(42);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();
    let proposer = validator.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, 400, 5, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx).await;
    let src_bh = sc.run_height(SHARD0, 1).await;
    let _msg = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .unwrap()
        .cross_shard_out[0]
        .clone();

    // Live target: consume it through the runtime.
    let tgt_bh = sc.run_height(SHARD1, 2).await;
    let live_root = sc.shard(SHARD1).nodes[0].state_root().await;
    let live_block = sc.shard(SHARD1).nodes[0]
        .blocks
        .get(&tgt_bh)
        .cloned()
        .unwrap();
    assert_eq!(
        sc.shard(SHARD1).nodes[0]
            .state
            .get_account(&recipient_addr)
            .await
            .unwrap()
            .balance,
        400
    );

    // Rebuilding target: identical genesis, applies the SAME committed record.
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();
    let rebuild_block = Block {
        shard_id: SHARD1,
        height: live_block.height,
        prev_hash: live_block.prev_hash,
        state_root: engine.get_state_root().await,
        transactions: vec![],
        cross_shard_out: live_block.cross_shard_out.clone(),
        timestamp: live_block.timestamp,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    engine.apply_block_transition(&rebuild_block, 0).await;
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        400
    );
    assert_eq!(
        engine.get_state_root().await,
        live_root,
        "a rebuilding target must derive the state root the live target committed"
    );

    // Replaying the same committed record on the rebuilt engine is refused.
    let again = engine.apply_cross_shard_consumptions(&rebuild_block).await;
    assert_eq!(again, 0, "replay must credit nothing");
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        400
    );
}
