//! Phase-1 memory-bound tests: every new cap has a test.
//!
//! * insert over cap → evicted, size bounded;
//! * disk fallback serves evicted entries (fail-open reads);
//! * vote history pruned to current-2 with lock info kept, never across heights;
//! * snapshot chunks round-trip with bounded peak.
//!
//! Env-sensitive tests serialize on `ENV_LOCK` because `std::env` is
//! process-global and `cargo test` runs tests on threads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use stellereum::post_quantum::{derive_pq_address, PqScheme};
use stellereum::state_engine::memory_bounds::{
    accounts_memory_warn_threshold, accounts_over_watermark, estimate_accounts_bytes,
    max_cached_blocks, max_pq_fallback_entries, BlockBodyCache, VoteRoundHistory,
};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{self, Storage};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("stell_mem_{}_{}_{}", std::process::id(), tag, n))
}

fn addr_from_u64(i: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&i.to_le_bytes());
    a
}

// ---------- block / body cache ----------

#[test]
fn block_cache_evicts_coldest_and_bounds_size() {
    let mut c = BlockBodyCache::new(4);
    for i in 0u8..6 {
        c.insert([i; 32], vec![i; 16]);
    }
    assert_eq!(c.len(), 4, "size must stay at cap");
    assert!(!c.contains(&[0u8; 32]), "oldest must be evicted");
    assert!(!c.contains(&[1u8; 32]), "second-oldest must be evicted");
    assert!(c.contains(&[5u8; 32]), "newest must be kept");
    assert_eq!(c.evictions(), 2);
}

#[test]
fn block_cache_touch_keeps_hot_entry() {
    let mut c = BlockBodyCache::new(2);
    c.insert([1u8; 32], vec![1]);
    c.insert([2u8; 32], vec![2]);
    // Touch [1]: it becomes hot, so [2] is the coldest next.
    let got: Option<Vec<u8>> = c.get_or_load_block([1u8; 32], |_| Ok::<_, String>(None));
    assert_eq!(got, Some(vec![1]));
    c.insert([3u8; 32], vec![3]);
    assert!(c.contains(&[1u8; 32]), "touched entry must survive");
    assert!(!c.contains(&[2u8; 32]), "untouched cold entry must go");
}

#[test]
fn block_cache_disk_fallback_serves_evicted_entry() {
    // Simulated disk: the loader closure stands in for `Storage::get_block`.
    let mut disk: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    for i in 0u8..3 {
        disk.insert([i; 32], vec![i; 32]);
    }
    let mut c = BlockBodyCache::new(2);
    for i in 0u8..3 {
        let h = [i; 32];
        let body = disk[&h].clone();
        c.insert(h, body);
    }
    assert!(!c.contains(&[0u8; 32]), "fixture: oldest must be evicted");

    // A lookup the disk can serve never fails just because it was evicted.
    let mut loads = 0u32;
    let got = c.get_or_load_block([0u8; 32], |k| {
        loads += 1;
        Ok::<_, String>(disk.get(k).cloned())
    });
    assert_eq!(got, Some(vec![0u8; 32]));
    assert_eq!(loads, 1, "evicted entry must come back via the loader");

    // Disk miss → None (fail-open, never an error).
    let got = c.get_or_load_block([9u8; 32], |_| Ok::<_, String>(None));
    assert_eq!(got, None);

    // Disk error → None as well (fail-open for reads, never fail-closed).
    let got = c.get_or_load_block([9u8; 32], |_| {
        Err::<Option<Vec<u8>>, String>("disk down".into())
    });
    assert_eq!(got, None);
}

#[test]
fn block_cache_cap_is_env_overridable() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("STELL_MAX_CACHED_BLOCKS", "8");
    assert_eq!(max_cached_blocks(), 8);
    assert_eq!(BlockBodyCache::with_env().cap(), 8);
    std::env::set_var("STELL_MAX_CACHED_BLOCKS", "not-a-number");
    assert_eq!(max_cached_blocks(), 2048, "bad value falls back to default");
    std::env::set_var("STELL_MAX_CACHED_BLOCKS", "0");
    assert_eq!(
        max_cached_blocks(),
        2048,
        "zero must not mean store-nothing"
    );
    std::env::remove_var("STELL_MAX_CACHED_BLOCKS");
}

// ---------- PQ-key fallback ----------

#[allow(clippy::await_holding_lock)]
// GATE: test holds a serializing env-var guard across awaits to keep env-var mutation hermetic; lock is test-only and never contended in production.
#[tokio::test]
async fn pq_fallback_is_bounded_without_disk() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("STELL_MAX_PQ_FALLBACK_ENTRIES", "16");
    assert_eq!(max_pq_fallback_entries(), 16);
    let engine = InMemoryStateEngine::new();
    let salt = [7u8; 16];
    for i in 0u64..24 {
        let mut pk = [0u8; 32];
        pk[..8].copy_from_slice(&i.to_le_bytes());
        let addr = derive_pq_address(PqScheme::Ed25519, &pk, &salt);
        engine
            .pin_pubkey(addr, PqScheme::Ed25519, &pk, &salt)
            .await
            .unwrap();
    }
    assert_eq!(engine.pq_fallback_len(), 16, "fallback must stay at cap");
    assert!(
        engine.pq_fallback_evictions() >= 8,
        "insert-over-cap must evict loudly (got {})",
        engine.pq_fallback_evictions()
    );
    std::env::remove_var("STELL_MAX_PQ_FALLBACK_ENTRIES");
}

#[allow(clippy::await_holding_lock)]
// GATE: test holds a serializing env-var guard across awaits to keep env-var mutation hermetic; lock is test-only and never contended in production.
#[tokio::test]
async fn pq_disk_serves_entries_skipped_by_fallback() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("STELL_MAX_PQ_FALLBACK_ENTRIES", "4");
    let dir = unique_dir("pqdisk");
    let storage = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    engine.attach_pq_tree(storage.pq_keys.clone());

    // With disk attached the fallback is skipped entirely (reads prefer disk).
    let salt = [9u8; 16];
    let mut pinned = Vec::new();
    for i in 0u64..6 {
        let mut pk = [0xABu8; 32];
        pk[..8].copy_from_slice(&i.to_le_bytes());
        let addr = derive_pq_address(PqScheme::Ed25519, &pk, &salt);
        engine
            .pin_pubkey(addr, PqScheme::Ed25519, &pk, &salt)
            .await
            .unwrap();
        pinned.push((addr, pk));
    }
    assert_eq!(engine.pq_fallback_len(), 0, "disk-attached pins skip RAM");
    assert_eq!(engine.pq_fallback_evictions(), 0);
    for (addr, pk) in &pinned {
        let got = engine.get_pinned_pubkey(addr);
        assert_eq!(
            got,
            Some((PqScheme::Ed25519, pk.to_vec())),
            "disk serves all"
        );
    }
    std::env::remove_var("STELL_MAX_PQ_FALLBACK_ENTRIES");
}

// ---------- vote / round history ----------

#[test]
fn vote_history_prunes_to_current_minus_two_and_keeps_lock() {
    let mut h = VoteRoundHistory::<Vec<u64>>::new();
    h.set_lock([0xAA; 32], 8);
    for r in 0u64..10 {
        assert!(h.insert(r, vec![r]), "in-window insert must be kept");
    }
    assert_eq!(h.len(), 3, "only current-2..=current survive");
    assert_eq!(h.oldest(), Some(7));
    assert!(h.get(6).is_none());
    assert_eq!(h.get(9), Some(&vec![9]));
    assert_eq!(
        h.lock_info(),
        Some(([0xAA; 32], 8)),
        "locking info survives the prune"
    );
    // Late insert for a pruned round is dropped, never grown back.
    assert!(!h.insert(0, vec![0]));
    assert_eq!(h.len(), 3);
    // New height: no accumulation across heights, lock record kept for caller.
    h.reset_for_height();
    assert_eq!(h.len(), 0);
    assert_eq!(h.current(), 0);
    assert_eq!(h.lock_info(), Some(([0xAA; 32], 8)));
    assert!(h.insert(0, vec![0]));
}

// ---------- snapshot chunking ----------

#[tokio::test]
async fn snapshot_chunks_round_trip_with_bounded_peak() {
    let e1 = InMemoryStateEngine::new();
    for i in 0u64..25 {
        e1.credit_native(&addr_from_u64(i), 1000 + i).await.unwrap();
    }
    let full = e1.create_snapshot().await;
    let chunks = e1.create_snapshot_chunked(Some(8)).await;
    assert_eq!(chunks.len(), 4, "25 accounts at 8/chunk → 4 chunks");
    for ch in &chunks {
        assert!(
            ch.len() < full.len(),
            "each chunk must be far smaller than the monolith"
        );
    }
    let e2 = InMemoryStateEngine::new();
    e2.restore_snapshot_chunked(&chunks).await.unwrap();
    for i in 0u64..25 {
        let a = e2.get_account(&addr_from_u64(i)).await.unwrap();
        assert_eq!(a.balance, 1000 + i);
    }
    assert_eq!(
        e1.get_state_root().await,
        e2.get_state_root().await,
        "chunked restore must root identically"
    );
}

// ---------- sled tunables ----------

#[test]
fn sled_config_tunables_are_safe_and_effective() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var("STELL_SLED_CACHE_BYTES");
    std::env::remove_var("STELL_SLED_FLUSH_MS");
    std::env::remove_var("STELL_SLED_COMPRESSION");
    assert_eq!(storage::sled_cache_capacity_bytes(), 1024 * 1024 * 1024);
    assert_eq!(storage::sled_flush_every_ms(), 500);
    assert!(!storage::sled_use_compression());

    std::env::set_var("STELL_SLED_CACHE_BYTES", "33554432");
    std::env::set_var("STELL_SLED_FLUSH_MS", "100");
    std::env::set_var("STELL_SLED_COMPRESSION", "1");
    assert_eq!(storage::sled_cache_capacity_bytes(), 33_554_432);
    assert_eq!(storage::sled_flush_every_ms(), 100);
    assert!(storage::sled_use_compression());

    // The tuned config must open and round-trip (small cache, fast flush).
    // NOTE: compression is parsed but deliberately NOT applied: this build
    // compiles sled without its `compression` cargo feature, so requesting it
    // fails `open` with `Unsupported` (that failure is the assertion here —
    // it proves the knob cannot silently corrupt data dirs).
    let dir = unique_dir("sledcfg");
    let db = storage::sled_config_for(&dir).open().unwrap();
    db.insert(b"mem-bound", b"ok").unwrap();
    db.flush().unwrap();
    assert_eq!(&db.get(b"mem-bound").unwrap().unwrap()[..], b"ok");
    drop(db);
    let dir_c = unique_dir("sledcfg-compress");
    let err = storage::sled_config_for(&dir_c)
        .use_compression(true)
        .open()
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("compression"),
        "compression must fail LOUD without the cargo feature, never half-apply: {err:?}"
    );

    // And the real `Storage::open` path honors the same config.
    let dir2 = unique_dir("storageopen");
    let _st = Storage::open(&dir2).unwrap();

    std::env::remove_var("STELL_SLED_CACHE_BYTES");
    std::env::remove_var("STELL_SLED_FLUSH_MS");
    std::env::remove_var("STELL_SLED_COMPRESSION");
}

// ---------- account watermark accounting ----------

#[test]
fn account_watermark_accounting_is_env_overridable() {
    let _g = ENV_LOCK.lock().unwrap();
    assert_eq!(estimate_accounts_bytes(10_000_000), 3_840_000_000);
    assert_eq!(
        estimate_accounts_bytes(u64::MAX),
        u64::MAX.saturating_mul(384)
    );

    std::env::remove_var("STELL_MAX_ACCOUNTS_WARN");
    assert_eq!(accounts_memory_warn_threshold(), 5_000_000);
    assert!(!accounts_over_watermark(4_999_999));
    assert!(accounts_over_watermark(5_000_000));

    std::env::set_var("STELL_MAX_ACCOUNTS_WARN", "10");
    assert!(accounts_over_watermark(10));
    assert!(!accounts_over_watermark(9));
    std::env::remove_var("STELL_MAX_ACCOUNTS_WARN");
}

#[tokio::test]
async fn watermark_check_reports_count_without_evicting() {
    let e = InMemoryStateEngine::new();
    assert_eq!(e.check_accounts_watermark().await, 0);
    e.credit_native(&addr_from_u64(1), 5).await.unwrap();
    assert_eq!(e.check_accounts_watermark().await, 1);
    assert!(
        e.get_account(&addr_from_u64(1)).await.is_some(),
        "watermark must never evict consensus state"
    );
}
