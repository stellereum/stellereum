//! Restart hydration must import the NEWEST receipts, not a tx-hash prefix.
//!
//! THE FAILURE THIS EXISTS FOR (contract D1): `receipts_v1` is keyed by the
//! transaction hash, so a capped scan of that tree (`all_receipts_capped`)
//! returns an arbitrary lexicographic slice of hashes. Once a store held more
//! than `MAX_RECEIPTS` (50 000) receipts, `hydrate_rpc_from_store` filled the
//! in-memory index from that slice, so the newest heights were missing — and
//! `rebuild_evm_indexes_from_blocks`, which only replays transactions with a
//! `success == true` receipt, silently lost their EVM bindings.
//!
//! WHAT IS PINNED HERE:
//!   1. hashes are `blake3(height)`, so lexicographic hash order does NOT match
//!      height order (the test first proves the old 50k hash slice misses
//!      newest heights);
//!   2. after reopening `Storage`, `latest_receipts_capped(50_000)` contains
//!      exactly heights 5 001..=55 000;
//!   3. `hydrate_rpc_from_store` (the real restart path) imports every one of
//!      those heights and nothing older;
//!   4. `prune_receipts_below` removes stale rows from the tip index too;
//!   5. opening a pre-upgrade directory (receipts present, index absent)
//!      backfills the index instead of silently serving an empty window.

use std::collections::HashSet;
use std::sync::Arc;

use stellereum::mempool::Mempool;
use stellereum::rpc::{hydrate_rpc_from_store, ReceiptIndex, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{Storage, StoredReceipt};
use tokio::sync::RwLock;

/// Total receipts filed before the restart.
const TOTAL: u64 = 55_000;
/// The RPC/durable hydration window (`rpc::state` MAX_RECEIPTS).
const CAP: usize = 50_000;
/// Oldest height that fits in the 50k window (55_000 - 50_000 + 1).
const FIRST_KEPT_HEIGHT: u64 = TOTAL - CAP as u64 + 1;

fn tx_hash(height: u64) -> [u8; 32] {
    // Deliberately NOT ordered by height: a lexicographic slice of these hashes
    // is the bug's trigger.
    *blake3::hash(&height.to_be_bytes()).as_bytes()
}

fn block_hash(height: u64) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(13);
    bytes.extend_from_slice(b"block");
    bytes.extend_from_slice(&height.to_be_bytes());
    *blake3::hash(&bytes).as_bytes()
}

fn receipt(height: u64) -> StoredReceipt {
    StoredReceipt {
        tx_hash: tx_hash(height),
        height,
        block_hash: block_hash(height),
        index: 0,
        success: true,
        gas_limit: 21_000,
        fee_charged: 21_000,
        events: Vec::new(),
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "stell_receipt_restart_order_{tag}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn fresh_rpc_state() -> RpcState {
    RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:receipt-restart-order-test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    }
}

#[tokio::test]
async fn restart_hydrates_newest_receipts_not_a_hash_prefix() {
    let dir = temp_dir("restart");

    {
        let st = Storage::open(&dir).expect("open store");
        for height in 1..=TOTAL {
            st.put_receipt(&receipt(height)).expect("file receipt");
        }
        st.flush().expect("flush");
    }

    // Precondition (the "before" picture): the first 50k entries in tx-hash
    // order are NOT the newest 50k heights, so the old `all_receipts_capped`
    // path would have dropped some of 5 001..=55 000.
    let mut by_hash: Vec<([u8; 32], u64)> = (1..=TOTAL).map(|h| (tx_hash(h), h)).collect();
    by_hash.sort_by(|a, b| a.0.cmp(&b.0));
    let hash_prefix: HashSet<u64> = by_hash[..CAP].iter().map(|(_, h)| *h).collect();
    let missed_by_old_scan = (FIRST_KEPT_HEIGHT..=TOTAL)
        .filter(|h| !hash_prefix.contains(h))
        .count();
    assert!(
        missed_by_old_scan > 0,
        "test precondition: blake3(height) order must not equal height order \
         (the old hash-prefix scan would otherwise pass vacuously)"
    );

    // Restart: reopen the store and read the tip window.
    let st = Storage::open(&dir).expect("reopen store");
    let latest = st.latest_receipts_capped(CAP).expect("latest receipts");
    assert_eq!(latest.len(), CAP, "a full 50k tip window");
    assert_eq!(
        latest.first().map(|r| r.height),
        Some(TOTAL),
        "newest receipt first"
    );
    assert_eq!(
        latest.last().map(|r| r.height),
        Some(FIRST_KEPT_HEIGHT),
        "window ends exactly at the 50k boundary"
    );
    let present: HashSet<u64> = latest.iter().map(|r| r.height).collect();
    for height in FIRST_KEPT_HEIGHT..=TOTAL {
        assert!(
            present.contains(&height),
            "receipt at height {height} missing from latest_receipts_capped"
        );
    }

    // Real restart path: hydrate the RPC index from the durable store.
    let rpc = fresh_rpc_state();
    hydrate_rpc_from_store(&rpc, &st).await;
    let index = rpc.receipts.read().await;
    assert_eq!(index.len(), CAP, "hydrated index holds the full window");
    assert_eq!(
        index.for_height(FIRST_KEPT_HEIGHT - 1).len(),
        0,
        "nothing older than the window is imported"
    );
    for height in FIRST_KEPT_HEIGHT..=TOTAL {
        assert_eq!(
            index.for_height(height).len(),
            1,
            "hydrated index lost height {height}"
        );
    }
    drop(index);

    drop(st);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prune_removes_receipts_from_the_tip_index() {
    let dir = temp_dir("prune");
    let st = Storage::open(&dir).expect("open store");
    for height in 1..=200u64 {
        st.put_receipt(&receipt(height)).expect("file receipt");
    }

    let removed = st.prune_receipts_below(101).expect("prune receipts");
    assert_eq!(removed, 100, "heights 1..=100 pruned");
    assert_eq!(st.receipt_count().expect("count"), 100);

    let latest = st.latest_receipts_capped(10_000).expect("latest receipts");
    assert_eq!(latest.len(), 100);
    assert!(
        latest.iter().all(|r| r.height >= 101),
        "pruned heights are gone from the tip window"
    );

    let index = st.receipts_by_height_tree_for_test();
    assert_eq!(index.len(), 100, "the index shrank with the bodies");
    for kv in index.iter() {
        let (key, _) = kv.expect("index row");
        assert_eq!(key.len(), 44, "fixed-width index key");
        let height = u64::from_be_bytes(key[0..8].try_into().expect("height"));
        assert!(height >= 101, "stale index row left at height {height}");
    }
    drop(index);
    st.flush().expect("flush");
    drop(st);

    // The invariant survives a restart.
    let st = Storage::open(&dir).expect("reopen store");
    assert_eq!(
        st.latest_receipts_capped(10_000).expect("latest").len(),
        100
    );
    drop(st);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_backfills_tip_index_for_a_pre_upgrade_store() {
    let dir = temp_dir("backfill");

    {
        let st = Storage::open(&dir).expect("open store");
        // Simulate a pre-upgrade directory: bodies exist, the derived index was
        // never written, and the completeness marker is absent.
        let bodies = st.receipts_tree_for_test();
        for height in 1..=64u64 {
            let r = receipt(height);
            bodies
                .insert(r.tx_hash, bincode::serialize(&r).expect("serialize"))
                .expect("body");
        }
        drop(bodies);
        st.set_receipt_index_ready_for_test(false)
            .expect("clear marker");
        assert_eq!(
            st.receipts_by_height_tree_for_test().len(),
            0,
            "index absent before the upgrade open"
        );
        st.flush().expect("flush");
        drop(st);
    }

    let st = Storage::open(&dir).expect("reopen store");
    assert_eq!(
        st.receipts_by_height_tree_for_test().len(),
        64,
        "open backfilled every body into the tip index"
    );
    let latest = st.latest_receipts_capped(100).expect("latest receipts");
    assert_eq!(latest.len(), 64);
    assert_eq!(latest.first().map(|r| r.height), Some(64));
    assert_eq!(latest.last().map(|r| r.height), Some(1));
    drop(st);
    std::fs::remove_dir_all(&dir).ok();
}
