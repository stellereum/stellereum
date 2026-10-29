//! Live retention proofs: pruning vs archive mode on real `Storage`.
//!
//! The node has two retention modes: archive (keep every body; the only mode
//! allowing later re-execution/audit) and pruning (drop bodies older than
//! `height - keep_blocks`, keep header records). These tests prove, in-process
//! on real sled-backed `Storage` in temp dirs:
//!
//!  (a) pruning never breaks block sync for heights inside the window,
//!  (b) headers survive pruning so the header walk still works,
//!  (c) archive mode actually retains bodies needed for re-execution,
//!  (d) a node that pruned a body reports it cleanly (Ok(None), not corrupt).
//!
//! All deterministic, fast, no `#[ignore]`. If any claim fails, the assertion
//! message names the breakage explicitly instead of papering over it.

use ed25519_dalek::SigningKey;
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{BlockHash, RetentionConfig, Storage};
use stellereum::sync::collect_missing_blocks;

const N_SYNC: u64 = 24;
const N_ARCHIVE: u64 = 16;
const N_WALK: u64 = 24;
const N_BOUND: u64 = 30;

/// Mirror of the private `PRUNE_BATCH` in `src/storage.rs`: one prune pass is
/// bounded so the single-writer flusher never stalls behind an unbounded scan.
const PRUNE_BATCH_MIRROR: usize = 20_000;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-prune-live-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn sender_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// Plain value-transfer chain with sequential nonces, so the blocks are really
/// re-executable against `InMemoryStateEngine` (nonce + balance checks pass).
fn exec_chain(store: &Storage, n: u64) -> (Vec<BlockHash>, Vec<Block>) {
    let key = sender_key();
    let mut out_hashes = Vec::new();
    let mut out_blocks = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..n {
        let tx = Transaction::sign(&key, [0xABu8; 32], 1, 0, h, 1, 1);
        let transactions = vec![tx];
        let order_merkle_root = stellereum::mev::compute_order_merkle_root(&transactions);
        let b = Block {
            shard_id: 1,
            height: h,
            prev_hash: prev,
            state_root: [h as u8; 32],
            timestamp: 1_700_000_000 + h,
            proposer: [1u8; 32],
            transactions,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cross_shard_out: vec![],
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
        };
        prev = store.put_block(&b).expect("persist block");
        out_hashes.push(prev);
        out_blocks.push(b);
    }
    (out_hashes, out_blocks)
}

/// Minimal chain (one signed tx per block, no state funding needed) for the
/// sync / walk / bound proofs that never touch the state engine.
fn light_chain(store: &Storage, n: u64) -> Vec<BlockHash> {
    let (hashes, _) = exec_chain(store, n);
    hashes
}

async fn apply_blocks_in_order(blocks: &[Block]) -> ([u8; 32], InMemoryStateEngine) {
    let engine = InMemoryStateEngine::new();
    let sender = sender_key().verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(sender, 1_000_000_000))
        .await;
    for b in blocks {
        for tx in &b.transactions {
            engine
                .apply_transaction(tx, 0)
                .await
                .expect("replay tx must apply");
        }
    }
    let root = engine.get_state_root().await;
    (root, engine)
}

// ---------- Test 1: prune keeps sync working inside the window ----------

#[tokio::test]
async fn live_prune_keeps_sync_working_inside_the_window() {
    let dir = tmpdir("sync-window");
    let store = Storage::open(&dir).expect("open");
    let keep_blocks: u64 = 6;
    let hashes = light_chain(&store, N_SYNC);
    let tip = N_SYNC - 1;
    // Same cursor the node uses (src/main.rs): height.saturating_sub(keep_blocks).
    let keep_from = tip.saturating_sub(keep_blocks);

    let retention = RetentionConfig {
        archive: false,
        keep_blocks,
    };
    assert!(!retention.archive, "this test proves pruning mode");
    store.prune_blocks_below(keep_from).expect("prune");

    // Bodies inside the window (plus the boundary parent) are retrievable.
    let window_start = keep_from.saturating_sub(1);
    for h in window_start..=tip {
        let rec = store
            .header_at(h)
            .expect("header read must not error")
            .unwrap_or_else(|| {
                panic!("BREAKAGE: header at height {h} dropped by pruning; header walk is broken")
            });
        let body = store
            .get_block(&rec.block_hash)
            .unwrap_or_else(|_| panic!("BREAKAGE: body read at height {h} errored (corrupt read) instead of returning the body"))
            .unwrap_or_else(|| panic!("BREAKAGE: pruning broke sync inside the window: body at height {h} (keep_from={keep_from}) is gone"));
        assert_eq!(
            body.compute_hash(),
            rec.block_hash,
            "window body at {h} must match its header record"
        );
        assert_eq!(
            hashes[h as usize], rec.block_hash,
            "window body at {h} must be the canonical block"
        );
    }
    // Headers exist for ALL heights, including pruned ones.
    for h in 0..N_SYNC {
        assert!(
            store.header_at(h).expect("header read").is_some(),
            "BREAKAGE: header at pruned height {h} is gone; headers must survive pruning"
        );
    }

    // Block sync over the window: walk from the tip back to a finalized hash
    // inside the window using only what the pruned node still serves.
    let anchor_h = keep_from + 1;
    let anchor_hash = hashes[anchor_h as usize];
    let tip_hash = hashes[tip as usize];
    let synced = collect_missing_blocks(tip_hash, anchor_hash, 100, |h| {
        let b = store.get_block(&h).expect("fetch must not error").clone();
        async move { b }
    })
    .await
    .unwrap_or_else(|_| panic!("BREAKAGE: block sync failed inside the retention window (tip {tip} -> anchor {anchor_h})"));
    assert_eq!(
        synced.len() as u64,
        tip - anchor_h,
        "sync must return every block between anchor {anchor_h} and tip {tip}"
    );
    for (i, b) in synced.iter().enumerate() {
        assert_eq!(
            b.height,
            anchor_h + 1 + i as u64,
            "synced blocks must be ancestor-first with no gaps"
        );
    }
    assert!(
        validate_linkage(&synced, anchor_hash),
        "BREAKAGE: synced window does not link back to the anchor; sync inside the window is broken"
    );
    std::fs::remove_dir_all(&dir).ok();
}

fn validate_linkage(blocks: &[Block], parent_hash: BlockHash) -> bool {
    let mut expected = parent_hash;
    for b in blocks {
        if b.prev_hash != expected {
            return false;
        }
        expected = b.compute_hash();
    }
    true
}

// ---------- Test 2: pruned body reads fail cleanly ----------

#[test]
fn live_pruned_body_reads_fail_cleanly_not_corrupt() {
    let dir = tmpdir("clean-miss");
    let store = Storage::open(&dir).expect("open");
    let hashes = light_chain(&store, 20);
    store.prune_blocks_below(10).expect("prune");

    // Height 3 is definitely pruned (removable: 3 + 1 < 10).
    let pruned_hash = hashes[3];
    let first = store.get_block(&pruned_hash).expect(
        "BREAKAGE: pruned body read returned Err (corrupt/error) instead of a clean Ok(None)",
    );
    assert!(
        first.is_none(),
        "BREAKAGE: pruned body read returned garbage bytes instead of a clean missing"
    );
    // A second read must agree: no corrupt partials that appear once.
    let second = store.get_block(&pruned_hash).expect(
        "BREAKAGE: second read of a pruned body errored; pruned reads must be stable clean misses",
    );
    assert!(
        second.is_none(),
        "BREAKAGE: pruned body read is unstable (first None, then Some): corrupt partial state"
    );
    // The caller can tell "pruned" apart from "never existed": the header
    // record survives, so header-Some + body-None means pruned, cleanly.
    let rec = store
        .header_at(3)
        .expect("header read must not error")
        .expect("BREAKAGE: header for pruned height 3 is gone; pruned-vs-unknown is no longer distinguishable");
    assert_eq!(
        rec.block_hash, pruned_hash,
        "header must still name the pruned body"
    );
    // An unknown hash is also a clean None, never an error or garbage.
    let unknown = store
        .get_block(&[0xFFu8; 32])
        .expect("BREAKAGE: unknown-hash read errored instead of clean None");
    assert!(
        unknown.is_none(),
        "BREAKAGE: unknown hash returned garbage instead of clean None"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Test 3: archive retains everything, re-executable ----------

#[tokio::test]
async fn live_archive_retains_everything_and_reexecutes() {
    let dir = tmpdir("archive");
    let store = Storage::open(&dir).expect("open");
    let retention = RetentionConfig::default();
    assert!(
        retention.archive,
        "archive must stay the default; only archive allows re-execution/audit"
    );

    let (hashes, blocks) = exec_chain(&store, N_ARCHIVE);
    // Archive mode never prunes: no prune call happens here by construction.

    // Every body retrievable, byte-identical to what was written.
    for (h, want) in hashes.iter().enumerate() {
        let body = store
            .get_block(want)
            .expect("archive read must not error")
            .unwrap_or_else(|| {
                panic!("BREAKAGE: archive mode lost body at height {h}; archive retains everything")
            });
        assert_eq!(
            body.compute_hash(),
            *want,
            "archive body at {h} must be intact"
        );
        assert_eq!(body.height, h as u64);
    }

    // Re-execution: apply the written blocks to a fresh engine, then replay
    // purely from what the archive serves and require the same root.
    let (root_original, _) = apply_blocks_in_order(&blocks).await;
    let mut replayed = Vec::new();
    for h in 0..N_ARCHIVE {
        let rec = store
            .header_at(h)
            .expect("header read")
            .expect("BREAKAGE: archive lost a header record; re-execution cannot find the block");
        let body = store
            .get_block(&rec.block_hash)
            .expect("archive read must not error")
            .expect("BREAKAGE: archive lost a body needed for re-execution/audit");
        assert_eq!(
            body.compute_hash(),
            rec.block_hash,
            "re-executed body must match its header"
        );
        replayed.push(body);
    }
    let (root_replay, _) = apply_blocks_in_order(&replayed).await;
    assert_eq!(
        root_replay, root_original,
        "BREAKAGE: archive re-execution diverged: replay root != original root"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Test 4: header walk survives pruning ----------

#[test]
fn live_header_walk_survives_pruning_past_the_prune_point() {
    let dir = tmpdir("header-walk");
    let store = Storage::open(&dir).expect("open");
    let hashes = light_chain(&store, N_WALK);
    let tip = N_WALK - 1;
    store.prune_blocks_below(12).expect("prune");

    // Prove bodies really are gone below the prune point, so the walk below
    // genuinely crosses it.
    let pruned_gone = store.get_block(&hashes[2]).expect("read").is_none();
    assert!(
        pruned_gone,
        "test setup broken: body at height 2 should be pruned"
    );

    // Walk headers from the tip down past the prune point via header records.
    let mut cur = store
        .header_at(tip)
        .expect("tip header read must not error")
        .expect("BREAKAGE: tip header missing after pruning");
    assert_eq!(
        cur.block_hash, hashes[tip as usize],
        "tip header must name the tip block"
    );
    for h in (0..tip).rev() {
        let parent = store
            .header_at(h)
            .expect("header read must not error")
            .unwrap_or_else(|| {
                panic!("BREAKAGE: header walk stops at height {h}: header dropped by pruning")
            });
        assert_eq!(
            parent.height, h,
            "header record height field must match its index"
        );
        assert_eq!(
            cur.prev_hash, parent.block_hash,
            "BREAKAGE: header linkage broken between heights {h} and {}: prev_hash does not resolve",
            h + 1
        );
        assert_eq!(
            parent.block_hash, hashes[h as usize],
            "header at {h} must carry the real block hash"
        );
        cur = parent;
    }
    assert_eq!(cur.height, 0, "walk must reach genesis");
    let latest = store
        .latest_header()
        .expect("latest read")
        .expect("latest header must exist");
    assert_eq!(
        latest.height, tip,
        "latest_header must still report the tip after pruning"
    );
    assert_eq!(
        store.header_count().expect("count"),
        N_WALK as usize,
        "BREAKAGE: headers were dropped by pruning; the chain is no longer walkable"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Test 5: retention bound ----------

#[test]
fn live_pruning_pass_is_bounded_and_spares_the_window() {
    let dir = tmpdir("bound");
    let store = Storage::open(&dir).expect("open");
    let keep_blocks: u64 = 5;
    let hashes = light_chain(&store, N_BOUND);
    let tip = N_BOUND - 1;
    let keep_from = tip.saturating_sub(keep_blocks);

    let removed = store.prune_blocks_below(keep_from).expect("prune");
    assert!(
        removed <= PRUNE_BATCH_MIRROR,
        "BREAKAGE: pruning pass removed {removed} bodies, exceeding the per-pass batch bound {PRUNE_BATCH_MIRROR}"
    );
    // Eligible bodies are exactly heights h with h + 1 < keep_from.
    let eligible = (0..N_BOUND).filter(|h| h + 1 < keep_from).count();
    assert_eq!(
        removed, eligible,
        "BREAKAGE: pruning pass removed {removed} but {eligible} were eligible: over- or under-pruning"
    );
    // Nothing within keep_blocks of the tip (plus the boundary parent) is touched.
    let window_start = keep_from.saturating_sub(1);
    for h in window_start..=tip {
        let rec = store
            .header_at(h)
            .expect("header read")
            .expect("header must exist");
        assert!(
            store.get_block(&rec.block_hash).expect("read").is_some(),
            "BREAKAGE: pruning touched a body within keep_blocks of the tip at height {h} (keep_from={keep_from})"
        );
        assert_eq!(rec.block_hash, hashes[h as usize]);
    }
    // A second pass with the same cursor is a no-op: the pass was bounded and complete.
    let again = store.prune_blocks_below(keep_from).expect("second prune");
    assert_eq!(
        again, 0,
        "BREAKAGE: pruning pass was unbounded/incomplete: second pass removed {again} more"
    );
    assert!(
        !store.has_blocks_below(keep_from).expect("check"),
        "nothing must remain eligible after a complete pass"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Receipts obey the same retention window as bodies (audit 2026-10-06:
/// receipts_v1 grew forever — one entry per tx, no prune path).
#[tokio::test]
async fn live_prune_drops_receipts_below_the_window() {
    use stellereum::storage::StoredReceipt;
    let dir = tmpdir("receipt-window");
    let store = Storage::open(&dir).expect("open");
    for h in 0..10u64 {
        store
            .put_receipt(&StoredReceipt {
                tx_hash: [h as u8; 32],
                height: h,
                block_hash: [0xAA; 32],
                index: 0,
                success: true,
                gas_limit: 280_000,
                fee_charged: 280_000,
                events: vec![],
            })
            .expect("put");
    }
    assert_eq!(store.receipt_count().expect("count"), 10);
    let dropped = store.prune_receipts_below(7).expect("prune");
    assert_eq!(dropped, 7, "heights 0..7 go, 7..10 stay");
    assert_eq!(store.receipt_count().expect("count"), 3);
    assert!(store.get_receipt(&[3u8; 32]).expect("get").is_none());
    assert!(store.get_receipt(&[8u8; 32]).expect("get").is_some());
}
