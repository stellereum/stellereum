//! Equivalence and anti-collision tests for RPC optimizations:
//! - `ReceiptIndex::for_height` secondary `by_height` index vs full linear scan
//!   across 60,000 inserts (eviction past `MAX_RECEIPTS = 50_000`, multi-receipt
//!   heights, out-of-order index insertion, in-place & cross-height updates, clear).
//! - `FinalizedReadCache` streaming BLAKE3 params hashing and `&'static str`
//!   method keys: byte-identical hash equivalence and zero collisions across
//!   methods, heights, and empty/nested/string params.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use stellereum::rpc::{
    finalized_read_cache_evict_epoch_roots, finalized_read_cache_evict_height,
    finalized_read_cache_get, finalized_read_cache_len, finalized_read_cache_params_hash,
    finalized_read_cache_put, ReceiptIndex, TxReceipt, FINALIZED_READ_CACHE_CAP, MAX_RECEIPTS,
};

static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn make_tx_hash(height: u64, slot: u32, salt: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(&slot.to_le_bytes());
    hasher.update(&[salt]);
    *hasher.finalize().as_bytes()
}

fn make_block_hash(height: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&height.to_be_bytes());
    h[31] = 0xA5;
    h
}

fn make_receipt(tx_hash: [u8; 32], height: u64, index: u32, fee_charged: u64) -> TxReceipt {
    TxReceipt {
        tx_hash,
        height,
        block_hash: make_block_hash(height),
        index,
        success: index.is_multiple_of(2),
        gas_limit: 50_000,
        fee_charged,
        ..Default::default()
    }
}

fn reference_for_height(idx: &ReceiptIndex, height: u64) -> Vec<&TxReceipt> {
    let mut rows: Vec<&TxReceipt> = idx.values().filter(|r| r.height == height).collect();
    rows.sort_by_key(|r| r.index);
    rows
}

fn receipt_tuple(r: &TxReceipt) -> (u64, u32, [u8; 32], u64, [u8; 32], bool) {
    (
        r.height,
        r.index,
        r.tx_hash,
        r.fee_charged,
        r.block_hash,
        r.success,
    )
}

#[test]
fn receipt_index_for_height_equivalence_60k_eviction_and_updates() {
    let mut idx = ReceiptIndex::default();

    // 12,000 heights * 5 receipts/height = 60,000 inserts (> MAX_RECEIPTS = 50,000).
    // Insert per-height indices out of order so `for_height` must sort by `index`.
    const TOTAL_HEIGHTS: u64 = 12_000;
    const PER_HEIGHT: u32 = 5;
    const INSERT_INDEX_ORDER: [u32; 5] = [4, 1, 3, 0, 2];

    for h in 1..=TOTAL_HEIGHTS {
        for &slot in &INSERT_INDEX_ORDER {
            let hash = make_tx_hash(h, slot, 0);
            idx.insert(make_receipt(hash, h, slot, 21_000 + u64::from(slot)));
        }
    }

    assert_eq!(idx.len(), MAX_RECEIPTS);
    let evicted_until = TOTAL_HEIGHTS - (MAX_RECEIPTS as u64 / u64::from(PER_HEIGHT));
    assert_eq!(evicted_until, 2_000);

    // Build a single-pass reference map from `idx.values()` to check all 12,000 heights.
    let mut reference_by_height: HashMap<u64, Vec<&TxReceipt>> = HashMap::new();
    for r in idx.values() {
        reference_by_height.entry(r.height).or_default().push(r);
    }
    for rows in reference_by_height.values_mut() {
        rows.sort_by_key(|r| r.index);
    }

    let mut total_indexed = 0usize;
    for h in 1..=TOTAL_HEIGHTS {
        let actual: Vec<_> = idx.for_height(h).into_iter().map(receipt_tuple).collect();
        let expected: Vec<_> = reference_by_height
            .get(&h)
            .map(|rows| rows.iter().copied().map(receipt_tuple).collect())
            .unwrap_or_default();
        assert_eq!(
            actual, expected,
            "for_height mismatch at height {h} after 60k inserts"
        );
        if h <= evicted_until {
            assert!(actual.is_empty(), "evicted height {h} must be empty");
        } else {
            assert_eq!(actual.len(), PER_HEIGHT as usize);
            total_indexed += actual.len();
        }
    }
    assert_eq!(total_indexed, MAX_RECEIPTS);

    // Also verify directly against the standalone linear-scan reference on boundary heights.
    for &h in &[1, 1_000, 2_000, 2_001, 2_002, 5_000, 6_000, 11_999, 12_000] {
        let actual: Vec<_> = idx.for_height(h).into_iter().map(receipt_tuple).collect();
        let expected: Vec<_> = reference_for_height(&idx, h)
            .into_iter()
            .map(receipt_tuple)
            .collect();
        assert_eq!(actual, expected, "direct scan mismatch at height {h}");
    }

    // Same-height replacement (same tx_hash, same height, updated index and fee):
    // must not duplicate entries in `order` or `by_height`.
    let same_height_hash = make_tx_hash(5_000, 4, 0);
    idx.insert(make_receipt(same_height_hash, 5_000, 10, 99_999));
    assert_eq!(idx.len(), MAX_RECEIPTS);
    let actual_5000: Vec<_> = idx
        .for_height(5_000)
        .into_iter()
        .map(receipt_tuple)
        .collect();
    let expected_5000: Vec<_> = reference_for_height(&idx, 5_000)
        .into_iter()
        .map(receipt_tuple)
        .collect();
    assert_eq!(actual_5000.len(), 5);
    assert_eq!(actual_5000, expected_5000);
    assert_eq!(actual_5000.last().map(|t| (t.1, t.3)), Some((10, 99_999)));

    // Cross-height replacement (same tx_hash moved from height 6_000 to height 99_999):
    // must be removed from old height bucket and inserted into new height bucket.
    let moved_hash = make_tx_hash(6_000, 2, 0);
    idx.insert(make_receipt(moved_hash, 99_999, 0, 77_777));
    assert_eq!(idx.len(), MAX_RECEIPTS);
    let actual_6000: Vec<_> = idx
        .for_height(6_000)
        .into_iter()
        .map(receipt_tuple)
        .collect();
    let expected_6000: Vec<_> = reference_for_height(&idx, 6_000)
        .into_iter()
        .map(receipt_tuple)
        .collect();
    assert_eq!(actual_6000.len(), 4);
    assert_eq!(actual_6000, expected_6000);

    let actual_moved: Vec<_> = idx
        .for_height(99_999)
        .into_iter()
        .map(receipt_tuple)
        .collect();
    let expected_moved: Vec<_> = reference_for_height(&idx, 99_999)
        .into_iter()
        .map(receipt_tuple)
        .collect();
    assert_eq!(actual_moved.len(), 1);
    assert_eq!(actual_moved, expected_moved);

    // One more new receipt triggers eviction of the oldest surviving receipt (height 2_001).
    let tip_hash = make_tx_hash(12_001, 0, 1);
    idx.insert(make_receipt(tip_hash, 12_001, 0, 12_345));
    assert_eq!(idx.len(), MAX_RECEIPTS);
    for &h in &[2_001, 2_002, 12_001] {
        let actual: Vec<_> = idx.for_height(h).into_iter().map(receipt_tuple).collect();
        let expected: Vec<_> = reference_for_height(&idx, h)
            .into_iter()
            .map(receipt_tuple)
            .collect();
        assert_eq!(actual, expected, "post-eviction mismatch at height {h}");
    }

    // Clear resets all indices consistently.
    idx.clear();
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
    assert!(idx.for_height(12_001).is_empty());
    assert!(idx.for_height(99_999).is_empty());
}

#[test]
fn finalized_read_cache_params_hash_matches_reference_to_vec() {
    let samples: Vec<Value> = vec![
        json!(null),
        json!(true),
        json!(false),
        json!(0),
        json!(1),
        json!(-1),
        json!(""),
        json!("0"),
        json!("stell_getBlock"),
        json!("line1\nline2\t\"quoted\"\\slash"),
        json!("[\"stell_getBlock\"]"),
        json!("unicode-тест-ключ"),
        json!([]),
        json!({}),
        json!(["a", "bc"]),
        json!(["ab", "c"]),
        json!(["ab"]),
        json!({ "a": "bc" }),
        json!({ "ab": "c" }),
        json!({ "a": 1 }),
        json!({ "a": "1" }),
        json!({ "height": 42 }),
        json!({ "height": 42, "include_txs": true }),
        json!({
            "height": 42,
            "nested": {
                "arr": [1, 2, true, null, "x", { "deep": ["y", "z"] }],
                "empty_obj": {},
                "empty_arr": []
            }
        }),
    ];

    let mut seen_hashes = HashSet::new();
    for (i, params) in samples.iter().enumerate() {
        let actual = finalized_read_cache_params_hash(params);
        let serialized = serde_json::to_vec(params).expect("serde_json::to_vec");
        let expected: [u8; 32] = *blake3::hash(&serialized).as_bytes();
        assert_eq!(
            actual, expected,
            "streaming params hash mismatch on sample #{i}: {params}"
        );
        assert!(
            seen_hashes.insert(actual),
            "unexpected params hash collision on sample #{i}: {params}"
        );
    }

    // Object key order in serde_json::Value (BTreeMap) normalizes identically.
    let obj_ab = json!({ "a": 1, "b": { "x": "1", "y": [2, 3] } });
    let obj_ba = json!({ "b": { "y": [2, 3], "x": "1" }, "a": 1 });
    assert_eq!(
        finalized_read_cache_params_hash(&obj_ab),
        finalized_read_cache_params_hash(&obj_ba)
    );
}

#[test]
fn finalized_read_cache_no_collisions_across_methods_and_params() {
    let _guard = CACHE_TEST_LOCK.lock().expect("cache test lock");

    let methods = [
        "stell_getBlock",
        "stell_getBlockTransactions",
        "stell_getFinalizedHeader",
        "stell_getEpochRoot",
    ];

    let param_cases: Vec<Value> = vec![
        json!(null),
        json!(""),
        json!([]),
        json!({}),
        json!("simple_string"),
        json!("[\"stell_getBlock\",\"x\"]"),
        json!(["stell_getBlock", "x"]),
        json!(["stell_getBlockx"]),
        json!({ "a": "bc" }),
        json!({ "ab": "c" }),
        json!({ "height": 900_001u64 }),
        json!({
            "height": 900_001u64,
            "nested": {
                "flags": [true, false, null],
                "label": "inner\"escaped"
            }
        }),
    ];

    let tip = 1_000_000u64;
    let h1 = 900_001u64;
    let h2 = 900_002u64;

    // Populate distinct responses for every (method, height, params) tuple.
    for (m_idx, &method) in methods.iter().enumerate() {
        for (p_idx, params) in param_cases.iter().enumerate() {
            let v1 = json!({ "m": method, "m_idx": m_idx, "p_idx": p_idx, "h": h1 });
            let v2 = json!({ "m": method, "m_idx": m_idx, "p_idx": p_idx, "h": h2 });
            finalized_read_cache_put(method, h1, params, tip, v1);
            finalized_read_cache_put(method, h2, params, tip, v2);
        }
    }

    // Every tuple retrieves its own exact value with zero cross-method,
    // cross-height, or cross-param collisions.
    for (m_idx, &method) in methods.iter().enumerate() {
        for (p_idx, params) in param_cases.iter().enumerate() {
            let expected1 = json!({ "m": method, "m_idx": m_idx, "p_idx": p_idx, "h": h1 });
            let expected2 = json!({ "m": method, "m_idx": m_idx, "p_idx": p_idx, "h": h2 });
            assert_eq!(
                finalized_read_cache_get(method, h1, params, tip),
                Some(expected1),
                "cache mismatch for ({method}, h1, case {p_idx})"
            );
            assert_eq!(
                finalized_read_cache_get(method, h2, params, tip),
                Some(expected2),
                "cache mismatch for ({method}, h2, case {p_idx})"
            );
        }
    }

    // Non-cacheable methods must bypass cleanly without colliding with cached entries.
    finalized_read_cache_put(
        "stell_getBalance",
        h1,
        &param_cases[0],
        tip,
        json!({ "bad": true }),
    );
    assert_eq!(
        finalized_read_cache_get("stell_getBalance", h1, &param_cases[0], tip),
        None
    );

    // Height eviction removes only the evicted height.
    finalized_read_cache_evict_height(h1);
    for &method in &methods {
        assert_eq!(
            finalized_read_cache_get(method, h1, &param_cases[0], tip),
            None
        );
        assert!(finalized_read_cache_get(method, h2, &param_cases[0], tip).is_some());
    }

    // Epoch-root eviction removes only `stell_getEpochRoot`, leaving other methods intact.
    finalized_read_cache_evict_epoch_roots();
    assert_eq!(
        finalized_read_cache_get("stell_getEpochRoot", h2, &param_cases[0], tip),
        None
    );
    assert!(finalized_read_cache_get("stell_getBlock", h2, &param_cases[0], tip).is_some());

    // Bounded capacity eviction stays <= FINALIZED_READ_CACHE_CAP and works with Copy keys.
    for offset in 0..(FINALIZED_READ_CACHE_CAP as u64 + 64) {
        let h = 910_000 + offset;
        let p = json!({ "height": h });
        finalized_read_cache_put("stell_getBlock", h, &p, tip, json!({ "height": h }));
    }
    assert!(finalized_read_cache_len() <= FINALIZED_READ_CACHE_CAP);

    // Clean up test heights from global cache.
    finalized_read_cache_evict_height(h2);
    for offset in 0..(FINALIZED_READ_CACHE_CAP as u64 + 64) {
        finalized_read_cache_evict_height(910_000 + offset);
    }
}
