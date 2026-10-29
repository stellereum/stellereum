//! Audit F1 (HIGH): cross-shard replay sets vs snapshot install.
//!
//! The snapshot install used to clear the consumed set and silently treat an
//! absent `cross_shard` blob as empty, while the produced/consumed/completed
//! sets were deliberately excluded from the state digest. A synced/restarted
//! node therefore re-opened every consumed inbound for a second credit, and
//! no root comparison could catch it.
//!
//! These tests pin the fail-closed fix:
//!   1. the replay sets (consumed keys, produced `(tx hash, height)` pairs,
//!      completed tx hashes) move the commitment digest - any divergence is a
//!      root mismatch, not a silent split; empty sets contribute zero bytes
//!      (single-shard chains root identically to before);
//!   2. a snapshot that omits the `cross_shard` blob is REFUSED when the
//!      target holds replay state, and accepted for a replay-empty target
//!      (the never-cross-sharded chain keeps fast-syncing);
//!   3. a snapshot whose replay set covers the target installs (fast-forward);
//!      one that does not - missing keys, or a conflicting produce height -
//!      is refused before touching the target;
//!   4. after a covering install, re-applying the same consumed receipt
//!      credits nothing (no double mint), with the root unmoved.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardReplaySnapshot, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::fast_sync_state;

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_760_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

async fn funded(addr: [u8; 32], balance: u64) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.update_account(AccountState::new(addr, balance)).await;
    e
}

fn fabric_key(a: u8, b: u8) -> CrossShardKey {
    CrossShardKey {
        source_shard: SHARD0,
        finalized_in_block: [a; 32],
        msg_id: [b; 32],
    }
}

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

/// Drive a single transfer SHARD0 -> SHARD1 to full consumption. Returns the
/// consumed message (as committed in the target block) for later replay.
async fn consume_one(
    sc: &mut ShardedCluster,
    sender: &SigningKey,
    recipient_addr: [u8; 32],
    amount: u64,
) -> stellereum::sharding::CrossShardMessage {
    let tx = Transaction::sign(sender, recipient_addr, amount, 10, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx.clone()).await;
    let _ = sc.run_height(SHARD0, TS).await;
    let tbh = sc.run_height(SHARD1, TS + 1).await;
    sc.shard(SHARD1).nodes[0]
        .blocks
        .get(&tbh)
        .cloned()
        .expect("target block retained")
        .cross_shard_out
        .into_iter()
        .find(|m| m.is_inbound_for(SHARD1))
        .expect("target block carries the consumption record")
}

// ===========================================================================
// 1. The replay sets move the commitment digest.
// ===========================================================================

#[tokio::test]
async fn replay_sets_move_the_commitment_digest() {
    let addr = [0xF1; 32];
    let base = funded(addr, 1_000_000).await.get_state_root().await;

    // Consumed alone moves the root.
    let e1 = funded(addr, 1_000_000).await;
    e1.restore_cross_shard_consumed(&[fabric_key(0xA1, 0xB1)])
        .await;
    let d_consumed = e1.get_state_root().await;
    assert_ne!(d_consumed, base, "a consumed key must move the root");

    // Produced alone moves the root, to a different value.
    let e2 = funded(addr, 1_000_000).await;
    let tx = Transaction::sign(&key(90), [0x99; 32], 50, 10, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    e2.restore_cross_shard_replay(&CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![(tx_hash, tx, 7)],
        completed: vec![],
        xpc: vec![],
    })
    .await;
    let d_produced = e2.get_state_root().await;
    assert_ne!(d_produced, base, "a produced entry must move the root");
    assert_ne!(
        d_produced, d_consumed,
        "different replay states must not alias"
    );

    // Produced heights are committed, not just hashes: same tx hash at two
    // heights must root differently (the height decides bounce linkage).
    let e2b = funded(addr, 1_000_000).await;
    let tx2 = Transaction::sign(&key(90), [0x99; 32], 50, 10, 0, SHARD0, SHARD1);
    assert_eq!(tx2.compute_tx_hash(), tx_hash);
    e2b.restore_cross_shard_replay(&CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![(tx_hash, tx2, 9)],
        completed: vec![],
        xpc: vec![],
    })
    .await;
    assert_ne!(
        e2b.get_state_root().await,
        d_produced,
        "produce height decides linkage, so it must be committed"
    );

    // Completed alone moves the root.
    let e3 = funded(addr, 1_000_000).await;
    e3.restore_cross_shard_replay(&CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![],
        completed: vec![[0xC3; 32]],
        xpc: vec![],
    })
    .await;
    let d_completed = e3.get_state_root().await;
    assert_ne!(d_completed, base, "a completed entry must move the root");

    // Empty sets contribute zero bytes: the conditional contract that keeps
    // single-shard chains (and every genesis KAT) byte-identical.
    let e4 = funded(addr, 1_000_000).await;
    e4.restore_cross_shard_replay(&CrossShardReplaySnapshot::default())
        .await;
    assert_eq!(
        e4.get_state_root().await,
        base,
        "restoring empty replay sets must not move the root"
    );

    // Order independence: insertion order must not fork the digest.
    let a = funded(addr, 1_000_000).await;
    a.restore_cross_shard_consumed(&[fabric_key(1, 2)]).await;
    a.restore_cross_shard_consumed(&[fabric_key(3, 4)]).await;
    let b = funded(addr, 1_000_000).await;
    b.restore_cross_shard_consumed(&[fabric_key(3, 4)]).await;
    b.restore_cross_shard_consumed(&[fabric_key(1, 2)]).await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical replay sets must digest identically regardless of order"
    );
}

// ===========================================================================
// 2. Missing blob: refused when replay state exists, accepted when empty.
// ===========================================================================

#[tokio::test]
async fn snapshot_install_with_missing_blob_is_refused() {
    let user = [0x55u8; 32];
    let source = funded(user, 777_000).await;
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;

    // Target holds replay state the snapshot cannot account for.
    let target = funded(user, 777_000).await;
    target
        .restore_cross_shard_consumed(&[fabric_key(0xD1, 0xD2)])
        .await;
    let target_root_before = target.get_state_root().await;
    assert_ne!(
        target_root_before, root,
        "precondition: replay state moves the target root"
    );

    let res = fast_sync_state(
        &target,
        root,
        || async { Some(snap.clone()) },
        |_| async { None },
    )
    .await;
    let err = res.expect_err("a snapshot without the cross_shard blob must be refused");
    assert!(
        err.contains("cross_shard") || err.contains("cross-shard"),
        "refusal must name the missing replay domain: {err}"
    );
    // Fail-closed means untouched: accounts AND the local replay set survive.
    assert_eq!(
        target.get_account(&user).await.unwrap().balance,
        777_000,
        "refused install must not touch accounts"
    );
    assert_eq!(
        target.cross_shard_consumed_len().await,
        1,
        "refused install must not drop local replay state"
    );
    assert_eq!(
        target.get_state_root().await,
        target_root_before,
        "refused install must not move the target root"
    );

    // Control: a replay-empty target still fast-syncs without the blob (the
    // never-cross-sharded chain is unaffected by the gate).
    let clean = funded(user, 777_000).await;
    fast_sync_state(
        &clean,
        root,
        || async { Some(snap.clone()) },
        |_| async { None },
    )
    .await
    .expect("replay-empty target must sync without the blob");
    assert_eq!(clean.get_state_root().await, root);
}

// ===========================================================================
// 3. Covering set installs; short or conflicting sets are refused.
// ===========================================================================

struct CoveringFixture {
    root: [u8; 32],
    snap_bytes: Vec<u8>,
    blob: Vec<u8>,
    consumed_key: CrossShardKey,
    tx_hash: [u8; 32],
    tx: Transaction,
    produce_height: u64,
    completed_hash: [u8; 32],
}

async fn covering_fixture() -> CoveringFixture {
    let user = [0x66u8; 32];
    let source = funded(user, 1_000_000).await;
    let consumed_key = fabric_key(0xE1, 0xE2);
    let tx = Transaction::sign(&key(91), [0x98; 32], 50, 10, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    let replay = CrossShardReplaySnapshot {
        engine_consumed: vec![consumed_key],
        runtime_consumed: vec![consumed_key],
        produced: vec![(tx_hash, tx.clone(), 7)],
        completed: vec![[0xC7; 32]],
        xpc: vec![],
    };
    source.restore_cross_shard_replay(&replay).await;
    let root = source.get_state_root().await;
    let snap_bytes = source.create_snapshot().await;
    let blob = bincode::serialize(&replay).expect("replay blob encodes");
    CoveringFixture {
        root,
        snap_bytes,
        blob,
        consumed_key,
        tx_hash,
        tx,
        produce_height: 7,
        completed_hash: [0xC7; 32],
    }
}

async fn sync_with_blob(
    target: &InMemoryStateEngine,
    fx: &CoveringFixture,
    blob_override: Option<Vec<u8>>,
) -> Result<(), String> {
    let blob = blob_override.unwrap_or_else(|| fx.blob.clone());
    fast_sync_state(
        target,
        fx.root,
        || async { Some(fx.snap_bytes.clone()) },
        |kind: &'static str| {
            let blob = blob.clone();
            async move {
                if kind == "cross_shard" {
                    Some(blob)
                } else {
                    None
                }
            }
        },
    )
    .await
}

#[tokio::test]
async fn snapshot_install_with_covering_set_is_accepted() {
    let fx = covering_fixture().await;

    // Empty target: full fast-forward.
    let target = funded([0x66u8; 32], 1_000_000).await;
    sync_with_blob(&target, &fx, None)
        .await
        .expect("covering set must install");
    assert_eq!(target.get_state_root().await, fx.root);
    assert!(target.is_cross_shard_consumed(&fx.consumed_key).await);
    assert_eq!(target.cross_shard_consumed_len().await, 1);
    assert_eq!(target.cross_shard_produced_len().await, 1);
    assert_eq!(target.cross_shard_completed_len().await, 1);
    assert!(target.is_cross_shard_completed(&fx.completed_hash).await);

    // Subset target: local state is older but covered - fast-forward accepts.
    let subset = funded([0x66u8; 32], 1_000_000).await;
    subset
        .restore_cross_shard_consumed(&[fx.consumed_key])
        .await;
    sync_with_blob(&subset, &fx, None)
        .await
        .expect("covered subset must fast-forward");
    assert_eq!(subset.get_state_root().await, fx.root);
    assert_eq!(subset.cross_shard_produced_len().await, 1);
}

#[tokio::test]
async fn snapshot_install_with_short_set_is_refused() {
    let fx = covering_fixture().await;

    // Target holds a consumed key the snapshot lacks: refuse, untouched.
    let target = funded([0x66u8; 32], 1_000_000).await;
    let extra = fabric_key(0xF0, 0xF1);
    target.restore_cross_shard_consumed(&[extra]).await;
    let before = target.get_state_root().await;
    let err = sync_with_blob(&target, &fx, None)
        .await
        .expect_err("short incoming set must be refused");
    assert!(
        err.contains("cross_shard"),
        "refusal must name the domain: {err}"
    );
    assert_eq!(target.cross_shard_consumed_len().await, 1);
    assert!(target.is_cross_shard_consumed(&extra).await);
    assert_eq!(target.get_state_root().await, before);

    // Same tx hash but a conflicting produce height: the two sides applied
    // different chains - refuse, even though the key sets match.
    let conflicted = funded([0x66u8; 32], 1_000_000).await;
    conflicted
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            engine_consumed: vec![fx.consumed_key],
            runtime_consumed: vec![fx.consumed_key],
            produced: vec![(fx.tx_hash, fx.tx.clone(), fx.produce_height + 100)],
            completed: vec![fx.completed_hash],
            xpc: vec![],
        })
        .await;
    let err = sync_with_blob(&conflicted, &fx, None)
        .await
        .expect_err("conflicting produce height must be refused");
    assert!(
        err.contains("cross_shard"),
        "refusal must name the domain: {err}"
    );

    // Corrupt blob: fail closed, never installed as empty.
    let corrupt_target = funded([0x66u8; 32], 1_000_000).await;
    let err = sync_with_blob(&corrupt_target, &fx, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]))
        .await
        .expect_err("corrupt replay blob must be refused");
    assert!(
        err.contains("cross-shard"),
        "refusal must name the domain: {err}"
    );
    assert_eq!(corrupt_target.cross_shard_consumed_len().await, 0);
}

// ===========================================================================
// 4. After a covering install, the same receipt cannot credit twice.
// ===========================================================================

#[tokio::test]
async fn double_apply_refused_after_snapshot_install() {
    let validator = key(1);
    let sender = key(2);
    let recipient_addr = key(3).verifying_key().to_bytes();
    let sender_addr = sender.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    let consumed_msg = consume_one(&mut sc, &sender, recipient_addr, 100).await;
    let consumed_key = CrossShardKey::of(&consumed_msg);

    // Publish-path artifacts: the accounts snapshot plus the runtime's replay
    // blob (the real wire format, produced/completed included).
    let src_engine = &sc.shard(SHARD1).nodes[0].state;
    let source_root = src_engine.get_state_root().await;
    let snap_bytes = src_engine.create_snapshot().await;
    let replay = sc.shard(SHARD1).nodes[0]
        .cross_shard_replay_snapshot()
        .await;
    assert!(replay.engine_consumed.contains(&consumed_key));
    let blob = bincode::serialize(&replay).expect("replay blob encodes");

    // Fresh node installs via snapshot-sync.
    let fresh = InMemoryStateEngine::new();
    fresh.enable_cross_shard();
    fast_sync_state(
        &fresh,
        source_root,
        || async { Some(snap_bytes.clone()) },
        |kind: &'static str| {
            let blob = blob.clone();
            async move {
                if kind == "cross_shard" {
                    Some(blob)
                } else {
                    None
                }
            }
        },
    )
    .await
    .expect("covering install must succeed");
    assert_eq!(fresh.get_state_root().await, source_root);
    assert!(fresh.is_cross_shard_consumed(&consumed_key).await);
    assert_eq!(
        fresh.cross_shard_consumed_len().await,
        src_engine.cross_shard_consumed_len().await
    );
    // The installed replay state is exactly the source's: balances agree.
    let credited_balance = fresh
        .get_account(&recipient_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(credited_balance, 100);

    // Re-applying the SAME (proof-valid) receipt credits nothing: the gate
    // fires on the installed set, not on a missing proof.
    let carrier = Block {
        shard_id: SHARD1,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: fresh.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![consumed_msg],
        timestamp: TS + 500,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let credited = fresh.apply_cross_shard_consumptions(&carrier).await;
    assert_eq!(credited, 0, "replayed receipt must credit nothing");
    assert_eq!(
        fresh.cross_shard_consumed_len().await,
        src_engine.cross_shard_consumed_len().await,
        "replay must not insert a second key"
    );
    assert_eq!(
        fresh
            .get_account(&recipient_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0),
        100,
        "no double mint"
    );
    assert_eq!(
        fresh.get_state_root().await,
        source_root,
        "replay must not move the root"
    );
}
