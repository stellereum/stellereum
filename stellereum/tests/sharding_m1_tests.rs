//! Sharding milestone M1: two shards in one process.
//!
//! M1 keeps cross-shard message flow OUT of the picture and proves only the
//! foundation: a `ValidatorRuntime` can be scoped to a shard, its producer
//! stamps the block with that shard's id and selects only transactions that
//! target it, and two independently-built nodes compute the same shard state
//! root. The shard-aware checks are all gated on `ShardRegistry::is_sharded()`,
//! so the default single-shard registry leaves every pre-existing path alone.
//!
//! This mirrors the in-process `Cluster` harness in `src/runtime.rs`.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::runtime::{fund_shard_genesis, Cluster};
use stellereum::sharding::{tx_targets_shard, ShardRegistry, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD1: u32 = 1;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Best-effort subscriber so `--nocapture` shows the producer's
/// `propose h=.. shard=1` line (M1 evidence). The first test to start wins;
/// later calls are no-ops.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

/// A process that runs masterchain + one workchain.
fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1])
}

/// A one-validator cluster whose chain is shard 1. Genesis funds ONLY the dev
/// account; the staking ledger is left empty so the validator set stays the
/// config-defined set (no workchain-local staking).
async fn shard1_cluster(validator: &SigningKey, dev: [u8; 32]) -> Cluster {
    let engine = Arc::new(InMemoryStateEngine::new());
    fund_shard_genesis(&engine, dev, 1_000_000_000).await;
    assert!(
        engine.staking_read().await.to_validator_set().is_empty(),
        "workchain genesis must not seed a staking ledger"
    );
    Cluster::new_sharded(vec![(validator.clone(), engine)], SHARD1, sharded())
}

#[tokio::test]
async fn shard1_transaction_lands_in_a_shard1_block() {
    init_tracing();
    let validator = key(1);
    let user = key(2);
    let from = user.verifying_key().to_bytes();
    let mut cluster = shard1_cluster(&validator, from).await;

    let genesis_root = cluster.nodes[0].state_root().await;
    let tx = Transaction::sign(&user, [9u8; 32], 100, 1_000, 0, 1, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx).await;

    let bh = cluster.run_height(1).await;
    let block = cluster.nodes[0]
        .blocks
        .get(&bh)
        .cloned()
        .expect("proposed block body must be retained");

    assert_eq!(block.shard_id, SHARD1, "block must be stamped with shard 1");
    assert!(
        block
            .transactions
            .iter()
            .any(|t| t.compute_tx_hash() == tx_hash),
        "the shard-1 transaction must be included in the shard-1 block"
    );

    // The transaction actually executed: the recipient was credited.
    let recipient = cluster.nodes[0]
        .state
        .get_account(&[9u8; 32])
        .await
        .expect("recipient account must exist after the transfer");
    assert_eq!(recipient.balance, 100);
    assert_ne!(
        cluster.nodes[0].state_root().await,
        genesis_root,
        "applying the shard-1 block must move the shard-1 state root"
    );
}

#[tokio::test]
async fn shard0_chain_is_untouched_by_a_shard1_transaction() {
    let validator = key(3);
    let user = key(4);
    let from = user.verifying_key().to_bytes();

    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new(from, 1_000_000))
        .await;
    let mut cluster = Cluster::new_sharded(vec![(validator, engine)], MASTERCHAIN_SHARD, sharded());

    let genesis_root = cluster.nodes[0].state_root().await;
    // Targeted at shard 1: in a sharded process it must NOT enter shard 0.
    cluster
        .broadcast_tx(Transaction::sign(
            &user, [8u8; 32], 100, 1_000, 0, 1, SHARD1,
        ))
        .await;

    let bh = cluster.run_height(1).await;
    let block = cluster.nodes[0].blocks.get(&bh).cloned().unwrap();

    assert_eq!(block.shard_id, MASTERCHAIN_SHARD);
    assert!(
        block.transactions.is_empty(),
        "shard 0 must not include a transaction targeted at shard 1"
    );
    assert!(block
        .transactions
        .iter()
        .all(|t| tx_targets_shard(t, MASTERCHAIN_SHARD)));
    assert_eq!(
        cluster.nodes[0].state_root().await,
        genesis_root,
        "a shard-1 transaction must leave shard-0 state untouched"
    );
}

#[tokio::test]
async fn two_independent_shard1_nodes_compute_the_same_root() {
    let user = key(20);
    let from = user.verifying_key().to_bytes();

    // Same validator identity and config, two independent state engines: this
    // is what two separately-started nodes for the same shard look like.
    let validator = key(10);
    let mut roots = Vec::new();
    for _ in 0..2 {
        let mut cluster = shard1_cluster(&validator, from).await;
        let tx = Transaction::sign(&user, [42u8; 32], 1_234, 1_000, 0, 1, SHARD1);
        cluster.broadcast_tx(tx).await;
        let _ = cluster.run_height(77).await;
        roots.push(cluster.nodes[0].state_root().await);
    }

    assert_eq!(
        roots[0], roots[1],
        "two independently-built shard-1 nodes must derive the same state root"
    );
}

#[tokio::test]
async fn sharded_node_rejects_a_proposal_for_the_wrong_shard() {
    let validator = key(30);
    let user = key(31);
    let from = user.verifying_key().to_bytes();
    let mut cluster = shard1_cluster(&validator, from).await;

    let mut block = cluster.nodes[0]
        .propose(5)
        .await
        .expect("single-validator proposer must build a block");
    let root = cluster.nodes[0].state_root().await;
    assert!(cluster.nodes[0].validate_proposal(&block, root).is_ok());

    // A shard-0 sibling block is not a valid proposal on the shard-1 chain.
    block.shard_id = MASTERCHAIN_SHARD;
    block.validator_signatures.clear();
    block.sign_block(&validator);
    let err = cluster.nodes[0]
        .validate_proposal(&block, root)
        .expect_err("wrong-shard proposal must be rejected");
    assert!(err.contains("wrong shard"), "{err}");

    // A shard-1 block carrying a shard-0-targeted transaction is refused too.
    let mut block2 = cluster.nodes[0].blocks.values().next().cloned().unwrap();
    block2.shard_id = SHARD1;
    block2.transactions = vec![Transaction::sign(
        &user,
        [1u8; 32],
        1,
        1_000,
        0,
        0,
        MASTERCHAIN_SHARD,
    )];
    block2.validator_signatures.clear();
    block2.sign_block(&validator);
    let err = cluster.nodes[0]
        .validate_proposal(&block2, root)
        .expect_err("cross-target transaction must be rejected");
    assert!(err.contains("targets shard"), "{err}");
}
