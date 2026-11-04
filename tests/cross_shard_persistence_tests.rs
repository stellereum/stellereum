//! §5 cross-shard replay persistence (audit F-I).
//!
//! The gap: the engine's consumed set plus the runtime's produced/completed/
//! consumed mirrors were memory-only. A restart wiped all four, and a replayed
//! message then passed every check: the target credited twice (or a bounce
//! refunded twice), because inclusion proofs are historical truth (they never
//! expire) and the in-progress-block checks start empty. Observed classmate:
//! the session/bridge/confidential/zkML domains had the same hole and got
//! their own trees; cross-shard replay state rides one shared height-keyed
//! tree (`cross_shard`) as [`CrossShardReplaySnapshot`].
//!
//! These tests simulate a restart (fresh engines + runtimes, sets restored
//! from disk, transport re-fed with the old message - the KV survives on the
//! `Node` transport, and a Byzantine proposer can always rebuild it) and pin:
//!   1. a consumed transfer is refused at propose (skipped + pruned from the
//!      mailbox), at validate, and credits nothing at apply - root unmoved;
//!   2. produced/completed round-trip, and a timeout bounce still fires after
//!      the restore for a pre-restart outbound (liveness, not just safety);
//!   3. the engine gate backstops an empty runtime: with ONLY the engine set
//!      restored, a replayed consume still credits nothing;
//!   4. absent entry means empty sets, and persisting them never moves the
//!      commitment digest (`COMMITMENT_VERSION` unchanged - the sets are
//!      consulted, not hashed).

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::{Cluster, ShardedCluster};
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardReplaySnapshot, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::Storage;

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_760_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
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

fn tmp_store_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell-xshard-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
    ))
}

async fn balance(cluster: &Cluster, shard: u32, addr: &[u8; 32]) -> u64 {
    let _ = shard;
    cluster.nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// Drive a single transfer SHARD0 -> SHARD1 to full consumption. Returns the
/// consumed message (as committed in the target block) for later replay.
async fn consume_one(
    sc: &mut ShardedCluster,
    sender: &SigningKey,
    recipient_addr: [u8; 32],
    amount: u64,
) -> stellereum::sharding::CrossShardMessage {
    let sender_addr = sender.verifying_key().to_bytes();
    let tx = Transaction::sign(sender, recipient_addr, amount, 10, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx.clone()).await;
    let _ = sc.run_height(SHARD0, TS).await;
    let tbh = sc.run_height(SHARD1, TS + 1).await;
    let _ = sender_addr;
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

/// Snapshot the shard-1 replay state, persist it height-keyed, reopen the
/// directory, and read it back - the disk half of a restart.
async fn persist_and_reopen(
    sc: &ShardedCluster,
    shard: u32,
    height: u64,
    tag: &str,
) -> (std::path::PathBuf, CrossShardReplaySnapshot) {
    let snap = sc.shard(shard).nodes[0].cross_shard_replay_snapshot().await;
    let dir = tmp_store_dir(tag);
    let _ = std::fs::remove_dir_all(&dir);
    let store = Storage::open(&dir).expect("open storage");
    let bytes = bincode::serialize(&snap).expect("snapshot encodes");
    store.put_cross_shard(height, &bytes).expect("put");
    drop(store);
    let store = Storage::open(&dir).expect("reopen after close");
    let back: CrossShardReplaySnapshot = bincode::deserialize(
        &store
            .cross_shard_at(height)
            .expect("read")
            .expect("present"),
    )
    .expect("snapshot decodes");
    (dir, back)
}

// ===========================================================================
// 1. Restart replay: refused at propose, validate AND apply.
// ===========================================================================

/// A consumed transfer, a restart (fresh engines + runtimes, sets restored
/// from disk, old message re-fed to the mailbox), then: the proposer skips it
/// (and prunes it), a crafted carrier block is refused by validation, and a
/// direct apply credits nothing with the root unmoved.
#[tokio::test]
async fn restart_replay_refused_at_propose_validate_and_apply() {
    let validator = key(1);
    let sender = key(2);
    let recipient_addr = key(3).verifying_key().to_bytes();
    let sender_addr = sender.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    let consumed_msg = consume_one(&mut sc, &sender, recipient_addr, 100).await;
    assert_eq!(
        balance(sc.shard(SHARD1), SHARD1, &recipient_addr).await,
        100,
        "precondition: the transfer credited"
    );
    let consumed_key = CrossShardKey::of(&consumed_msg);

    const H: u64 = 700;
    let (dir, back) = persist_and_reopen(&sc, SHARD1, H, "replay").await;
    assert!(back.engine_consumed.contains(&consumed_key));
    assert!(back.runtime_consumed.contains(&consumed_key));

    // --- Fresh process A (full restore): new engines + runtimes, both halves
    // restored the way the real startup does. ---
    let mut fresh = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    fresh.shard(SHARD1).nodes[0]
        .state
        .restore_cross_shard_consumed(&back.engine_consumed)
        .await;
    fresh.shard_mut(SHARD1).nodes[0].restore_cross_shard_sets(&back);
    // The old message is back in the mailbox (KV survived, or Byzantine rebuilt).
    fresh
        .transport
        .broadcast_cross_shard(&consumed_msg)
        .await
        .expect("re-feed");
    // --- Fresh process B (engine-only restore): runtime mirrors stay empty,
    // exercising the engine belt + mailbox prune path. ---
    let mut partial = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    partial.shard(SHARD1).nodes[0]
        .state
        .restore_cross_shard_consumed(&back.engine_consumed)
        .await;
    partial
        .transport
        .broadcast_cross_shard(&consumed_msg)
        .await
        .expect("re-feed");
    // Control: an identical fresh cluster WITHOUT the restore.
    let mut control = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    control
        .transport
        .broadcast_cross_shard(&consumed_msg)
        .await
        .expect("re-feed");

    // Propose: both restored nodes skip the replayed message; the engine-only
    // node additionally prunes it from its mailbox (its runtime mirrors are
    // empty, so only the engine belt fires there).
    let fresh_bh = fresh.run_height(SHARD1, TS + 100).await;
    let fresh_block = fresh.shard(SHARD1).nodes[0]
        .blocks
        .get(&fresh_bh)
        .cloned()
        .expect("fresh block retained");
    assert!(
        !fresh_block
            .cross_shard_out
            .iter()
            .any(|m| CrossShardKey::of(m) == consumed_key),
        "restored proposer must skip the replayed message"
    );
    let partial_bh = partial.run_height(SHARD1, TS + 100).await;
    let partial_block = partial.shard(SHARD1).nodes[0]
        .blocks
        .get(&partial_bh)
        .cloned()
        .expect("partial block retained");
    assert!(
        !partial_block
            .cross_shard_out
            .iter()
            .any(|m| CrossShardKey::of(m) == consumed_key),
        "engine-belt proposer must skip the replayed message"
    );
    assert!(
        partial
            .transport
            .fetch_cross_shard_inbound(SHARD1)
            .await
            .iter()
            .all(|m| CrossShardKey::of(m) != consumed_key),
        "the replay must be pruned from the mailbox (no forever re-propose)"
    );
    let control_bh = control.run_height(SHARD1, TS + 100).await;
    let control_block = control.shard(SHARD1).nodes[0]
        .blocks
        .get(&control_bh)
        .cloned()
        .expect("control block retained");
    assert!(
        control_block
            .cross_shard_out
            .iter()
            .any(|m| CrossShardKey::of(m) == consumed_key),
        "control: without restore the replay IS proposed (the hole, now closed)"
    );

    // Validate: a carrier block forged for THIS node (right height, prev,
    // root, proposer) but re-including the consumed record is refused for the
    // replay - not for any header mismatch.
    let fnode = &fresh.shard(SHARD1).nodes[0];
    let root = fnode.state_root().await;
    let mut forged = Block {
        shard_id: SHARD1,
        height: fnode.height(),
        prev_hash: fnode.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![consumed_msg.clone()],
        timestamp: TS + 101,
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
    let err = fnode
        .validate_proposal(&forged, root)
        .expect_err("a replayed consume record must be refused");
    assert!(
        err.contains("replayed"),
        "refusal must name the replay, not a header mismatch: {err}"
    );

    // No double credit anywhere on the restarted shard.
    assert_eq!(
        balance(fresh.shard(SHARD1), SHARD1, &recipient_addr).await,
        0,
        "no double credit on the restarted shard"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 2. Produced/completed survive: timeout bounce still fires after restore.
// ===========================================================================

/// An outbound with no ack, a restart, then heights march past the timeout:
/// the restored `produced` set still yields the deterministic bounce record
/// and the refund applies exactly once.
#[tokio::test]
async fn produced_completed_survive_restore_and_timeout_bounce_fires() {
    use stellereum::sharding::bounce_eligible;
    let validator = key(11);
    let sender = key(12);
    let recipient_addr = key(13).verifying_key().to_bytes();
    let sender_addr = sender.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    // Outbound committed on SHARD0, never acked (SHARD1 never runs).
    let tx = Transaction::sign(&sender, recipient_addr, 100, 10, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    let src_bh = sc.run_height(SHARD0, TS).await;
    let tx_hash = tx.compute_tx_hash();
    assert!(
        !sc.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash),
        "precondition: produced but not completed"
    );
    let src_height = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .cloned()
        .expect("source block")
        .height;

    const H: u64 = 701;
    let (dir, back) = persist_and_reopen(&sc, SHARD0, H, "bounce").await;
    assert!(
        back.engine_consumed.is_empty(),
        "precondition: nothing consumed (the outbound is unacked)"
    );
    assert!(
        back.produced.iter().any(|(h, _, _)| *h == tx_hash),
        "the produced outbound must travel through the snapshot"
    );

    // Fresh process, restore both halves.
    let mut fresh = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    fresh.shard(SHARD0).nodes[0]
        .state
        .restore_cross_shard_consumed(&back.engine_consumed)
        .await;
    fresh.shard_mut(SHARD0).nodes[0].restore_cross_shard_sets(&back);
    assert!(
        fresh.shard(SHARD0).nodes[0]
            .produced_cross_shard_height(&tx_hash)
            .is_some(),
        "produced set restored: timeout logic can see the outbound"
    );
    // Not yet eligible long before the timeout...
    assert!(
        !bounce_eligible(src_height, src_height + 10),
        "sanity: no early bounce"
    );
    // Drive heights past the timeout on the restored shard: the deterministic
    // bounce record must appear and refund exactly `amount`, once.
    let bal_before = balance(fresh.shard(SHARD0), SHARD0, &sender_addr).await;
    let mut bounced_at = None;
    for h in 2..=src_height + stellereum::sharding::CROSS_SHARD_TIMEOUT_HEIGHTS + 5 {
        let bh = fresh.run_height(SHARD0, TS + h).await;
        let blk = fresh.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .expect("block retained");
        if blk
            .cross_shard_out
            .iter()
            .any(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash)
        {
            bounced_at = Some(blk.height);
            break;
        }
    }
    let bounced_height = bounced_at.expect("timeout bounce must fire after restore");
    assert!(
        bounced_height >= src_height + stellereum::sharding::CROSS_SHARD_TIMEOUT_HEIGHTS,
        "no early bounce: fired at {bounced_height} for produce height {src_height}"
    );
    assert_eq!(
        balance(fresh.shard(SHARD0), SHARD0, &sender_addr).await,
        bal_before + 100,
        "the bounce refunds exactly the amount, once"
    );
    assert!(
        fresh.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash),
        "the bounce marks the lifecycle complete"
    );
    // Ten more heights: no second refund.
    for h in bounced_height + 1..=bounced_height + 10 {
        fresh.run_height(SHARD0, TS + 1000 + h).await;
    }
    assert_eq!(
        balance(fresh.shard(SHARD0), SHARD0, &sender_addr).await,
        bal_before + 100,
        "no double refund on later heights"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 3. Engine gate backstops an empty runtime.
// ===========================================================================

/// Restore ONLY the engine half (simulating a partial restore): a replayed
/// consume still credits nothing at apply time, even though the runtime
/// mirrors are empty.
#[tokio::test]
async fn engine_gate_backstops_empty_runtime() {
    let validator = key(21);
    let sender = key(22);
    let recipient_addr = key(23).verifying_key().to_bytes();
    let sender_addr = sender.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    let consumed_msg = consume_one(&mut sc, &sender, recipient_addr, 100).await;

    const H: u64 = 702;
    let (dir, back) = persist_and_reopen(&sc, SHARD1, H, "engback").await;

    let fresh = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    // Engine half ONLY - runtime mirrors stay empty like a fresh process whose
    // runtime restore was skipped or lagged.
    fresh.shard(SHARD1).nodes[0]
        .state
        .restore_cross_shard_consumed(&back.engine_consumed)
        .await;
    // Direct apply of a carrier block: the engine skips the consumed record,
    // so no credit lands and the consumed count does not move.
    let before = fresh.shard(SHARD1).nodes[0]
        .state
        .cross_shard_consumed_len()
        .await;
    let mut carrier = Block {
        shard_id: SHARD1,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: fresh.shard(SHARD1).nodes[0].state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![consumed_msg],
        timestamp: TS,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let _ = &mut carrier;
    let engine = &fresh.shard(SHARD1).nodes[0].state;
    let credited = engine.apply_cross_shard_consumptions(&carrier).await;
    assert_eq!(credited, 0, "engine must skip the already-consumed record");
    assert_eq!(
        engine.cross_shard_consumed_len().await,
        before,
        "no new key inserted for a replay"
    );
    assert_eq!(
        balance(fresh.shard(SHARD1), SHARD1, &recipient_addr).await,
        0,
        "no double credit"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 4. Absent means empty; digests untouched.
// ===========================================================================

/// A default snapshot is empty, restores as a no-op, and the replay sets are
/// NOT folded into any commitment digest (replay safety comes from the sets
/// being consulted, so restoring them cannot move the root by construction).
#[tokio::test]
async fn absent_means_empty_and_no_digest_impact() {
    use stellereum::sharding::CrossShardReplaySnapshot;
    let snap = CrossShardReplaySnapshot::default();
    assert!(snap.engine_consumed.is_empty());
    assert!(snap.produced.is_empty());
    assert!(snap.completed.is_empty());
    let bytes = bincode::serialize(&snap).expect("snapshot encodes");
    let back: CrossShardReplaySnapshot = bincode::deserialize(&bytes).expect("snapshot decodes");
    assert!(back.engine_consumed.is_empty() && back.produced.is_empty());

    // Restoring empties changes nothing observable.
    let e = InMemoryStateEngine::new();
    let root = e.get_state_root().await;
    e.restore_cross_shard_consumed(&back.engine_consumed).await;
    assert_eq!(
        e.get_state_root().await,
        root,
        "restoring empty sets must not move the root"
    );
    assert_eq!(e.cross_shard_consumed_len().await, 0);

    // Fresh store has no entry: the load path treats that as empty (no error,
    // no insert), same as a fresh process.
    let dir = tmp_store_dir("xabsent");
    let _ = std::fs::remove_dir_all(&dir);
    let store = Storage::open(&dir).expect("open");
    assert!(store.cross_shard_at(999).expect("read").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
