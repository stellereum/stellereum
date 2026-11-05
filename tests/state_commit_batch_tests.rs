//! Differential old-vs-new tests for the state COMMIT/WRITE paths.
//!
//! The `put_receipts_for_block_with_events` path must produce EXACTLY the
//! observable state the pre-batch per-key loop produces (a `sled::Batch`
//! candidate was measured 0.06x-1.23x at N=428 — never faster — and reverted,
//! so both sides now run the loop; the tests pin that the API keeps exact
//! single-key semantics incl. duplicate-tx last-wins). Prune paths likewise
//! stay per-key (batched prune measured 0.6-1.2x and reverted); the tests
//! pin remaining-set equality. Crash-recovery pairs (drop + reopen the same
//! directory) and state-root equality across a snapshot round-trip complete
//! the post-commit equivalence proof. No timing asserts here.

use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{ConsensusCheckpoint, Storage};

fn det32(seed: u8, i: u64) -> [u8; 32] {
    let mut b = [seed; 32];
    b[..8].copy_from_slice(&i.to_be_bytes());
    b
}

fn det_tx(i: u64) -> Transaction {
    Transaction {
        from: det32(0x11, i),
        to: det32(0x22, i),
        amount: 1000 + i,
        gas_limit: 280_000,
        nonce: i,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: vec![0xABu8; 64],
        payload: vec![],
        priority_fee_per_gas: 0,
    }
}

fn det_block(height: u64, ntx: usize) -> Block {
    let txs: Vec<Transaction> = (0..ntx as u64).map(|i| det_tx(height * 1000 + i)).collect();
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: det32(0x99, height.saturating_sub(1)),
        state_root: det32(0x77, height),
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: det32(0x55, 7),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
    }
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell_state_commit_diff_{tag}_{}_{}",
        std::process::id(),
        rand_suffix()
    ))
}

fn rand_suffix() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        .wrapping_add(h.finish() as u32)
}

/// OLD reference path: the pre-batch per-key receipt loop, replicated with
/// the retained single-key `put_receipt` API.
fn old_put_receipts_seq(
    st: &Storage,
    height: u64,
    block_hash: &[u8; 32],
    txs: &[Transaction],
    statuses: &[bool],
    fees: &[u64],
) -> usize {
    let mut n = 0;
    for (i, tx) in txs.iter().enumerate() {
        let success = statuses.get(i).copied().unwrap_or(false);
        let fee_charged = fees
            .get(i)
            .copied()
            .unwrap_or(if success { tx.gas_limit } else { 0 });
        st.put_receipt(&stellereum::storage::StoredReceipt {
            tx_hash: tx.compute_tx_hash(),
            height,
            block_hash: *block_hash,
            index: i as u32,
            success,
            gas_limit: tx.gas_limit,
            fee_charged,
            events: vec![],
        })
        .unwrap();
        n += 1;
    }
    n
}

/// Receipt batch == old sequential puts, read-for-read (incl. dup-tx last-wins).
#[test]
fn receipts_batch_matches_single_puts() {
    let dir_new = tmpdir("rcpt_new");
    let dir_old = tmpdir("rcpt_old");
    let new_st = Storage::open(&dir_new).unwrap();
    let old_st = Storage::open(&dir_old).unwrap();
    // 64 txs, one duplicate (tx 5 repeats at index 60) to pin last-wins.
    let mut txs: Vec<Transaction> = (0..64u64).map(det_tx).collect();
    txs[60] = txs[5].clone();
    let statuses: Vec<bool> = (0..64).map(|i| i % 3 != 0).collect();
    let fees: Vec<u64> = (0..64).map(|i| 1000 + i as u64).collect();
    let bh = det32(0xBE, 11);

    let n_new = new_st
        .put_receipts_for_block_with_events(11, &bh, &txs, &statuses, &fees, &[])
        .unwrap();
    let n_old = old_put_receipts_seq(&old_st, 11, &bh, &txs, &statuses, &fees);
    assert_eq!(n_new, n_old);
    assert_eq!(n_new, 64);
    assert_eq!(
        new_st.receipt_count().unwrap(),
        old_st.receipt_count().unwrap()
    );
    for tx in &txs {
        let h = tx.compute_tx_hash();
        let a = new_st.get_receipt(&h).unwrap().expect("new must hold it");
        let b = old_st.get_receipt(&h).unwrap().expect("old must hold it");
        assert_eq!(a.tx_hash, b.tx_hash, "tx_hash {h:02x?}");
        assert_eq!(a.height, b.height);
        assert_eq!(a.block_hash, b.block_hash);
        assert_eq!(a.index, b.index);
        assert_eq!(a.success, b.success);
        assert_eq!(a.gas_limit, b.gas_limit);
        assert_eq!(a.fee_charged, b.fee_charged);
        assert_eq!(a.events.len(), b.events.len());
    }
    // Dup pin: tx 5's hash files at the LAST index (60), in both stores.
    let dup_h = txs[5].compute_tx_hash();
    assert_eq!(new_st.get_receipt(&dup_h).unwrap().unwrap().index, 60);
    assert_eq!(old_st.get_receipt(&dup_h).unwrap().unwrap().index, 60);
    std::fs::remove_dir_all(&dir_new).ok();
    std::fs::remove_dir_all(&dir_old).ok();
}

/// Crash-recovery pair: batched writes + flush, then reopen, reads identical.
#[test]
fn batched_writes_survive_reopen() {
    let dir = tmpdir("reopen");
    let bh_final: [u8; 32];
    let rcpt_hash: [u8; 32];
    {
        let st = Storage::open(&dir).unwrap();
        let b = det_block(3, 8);
        let bh = st.put_block(&b).unwrap();
        bh_final = bh;
        st.set_finalized(3, &bh).unwrap();
        st.set_consensus(&ConsensusCheckpoint {
            height: 4,
            round: 0,
            locked_hash: None,
            locked_round: 0,
            finalized_height: 3,
            finalized_hash: bh,
        })
        .unwrap();
        let txs: Vec<Transaction> = (0..8u64).map(det_tx).collect();
        rcpt_hash = txs[2].compute_tx_hash();
        let n = st
            .put_receipts_for_block_with_events(3, &bh, &txs, &[true; 8], &[9; 8], &[])
            .unwrap();
        assert_eq!(n, 8);
        st.flush().unwrap();
        // `st` dropped here without further writes: the reopen below must
        // see everything the flush barrier covered.
    }
    {
        let st = Storage::open(&dir).unwrap();
        let got = st.get_block(&bh_final).unwrap().expect("body survives");
        assert_eq!(got.height, 3);
        assert_eq!(st.finalized().unwrap().unwrap(), (3, bh_final));
        assert_eq!(st.consensus().unwrap().unwrap().finalized_height, 3);
        let r = st.get_receipt(&rcpt_hash).unwrap().expect("receipt survives");
        assert_eq!(r.height, 3);
        assert_eq!(r.block_hash, bh_final);
        assert_eq!(r.index, 2);
        assert!(r.success);
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// Prune batch == old sequential removes, remaining-set identical.
#[test]
fn prune_batch_matches_sequential() {
    let dir_new = tmpdir("prune_new");
    let dir_old = tmpdir("prune_old");
    let new_st = Storage::open(&dir_new).unwrap();
    let old_st = Storage::open(&dir_old).unwrap();
    for h in 0..200u64 {
        new_st.put_block(&det_block(h, 0)).unwrap();
        old_st.put_block(&det_block(h, 0)).unwrap();
    }
    // OLD reference: the pre-batch per-key loop, replicated inline.
    let mut old_removed = 0;
    let old_keys: Vec<sled::IVec> = old_st
        .by_height_tree_for_test()
        .iter()
        .keys()
        .filter_map(|k| k.ok())
        .take(20_000)
        .filter(|k| k.len() == 40)
        .filter(|k| {
            let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
            h + 1 < 150
        })
        .collect();
    for hk in old_keys {
        if let Some(hash) = old_st.by_height_tree_for_test().remove(&hk).unwrap() {
            old_st.blocks_tree_for_test().remove(hash).unwrap();
        }
        old_removed += 1;
    }
    let new_removed = new_st.prune_blocks_below(150).unwrap();
    assert_eq!(new_removed, old_removed);
    assert_eq!(new_removed, 149); // heights 0..=148 (h+1 < 150)
    for h in [0u64, 1, 100, 148, 149, 150, 199] {
        assert_eq!(
            new_st.hashes_at_height(h).unwrap(),
            old_st.hashes_at_height(h).unwrap(),
            "height {h}"
        );
    }
    assert_eq!(
        new_st.block_count().unwrap(),
        old_st.block_count().unwrap()
    );
    std::fs::remove_dir_all(&dir_new).ok();
    std::fs::remove_dir_all(&dir_old).ok();
}

/// Receipts prune batch == sequential removes, remaining-set identical.
#[test]
fn receipts_prune_batch_matches_sequential() {
    let dir_new = tmpdir("rprune_new");
    let dir_old = tmpdir("rprune_old");
    let new_st = Storage::open(&dir_new).unwrap();
    let old_st = Storage::open(&dir_old).unwrap();
    for h in 0..10u64 {
        let txs: Vec<Transaction> = (0..20u64).map(|i| det_tx(h * 100 + i)).collect();
        let bh = det32(0xC0, h);
        new_st
            .put_receipts_for_block_with_events(h, &bh, &txs, &[true; 20], &[1; 20], &[])
            .unwrap();
        old_put_receipts_seq(&old_st, h, &bh, &txs, &[true; 20], &[1; 20]);
    }
    assert_eq!(new_st.receipt_count().unwrap(), 200);
    let new_removed = new_st.prune_receipts_below(6).unwrap();
    // OLD reference: sequential per-key removes.
    let stale: Vec<sled::IVec> = old_st
        .receipts_tree_for_test()
        .iter()
        .filter_map(|kv| kv.ok())
        .filter_map(|(k, v)| {
            let r: stellereum::storage::StoredReceipt =
                bincode::deserialize(&v).ok()?;
            (r.height < 6).then_some(k)
        })
        .collect();
    let mut old_removed = 0;
    for k in stale {
        old_st.receipts_tree_for_test().remove(k).unwrap();
        old_removed += 1;
    }
    assert_eq!(new_removed, old_removed);
    assert_eq!(new_removed, 120); // heights 0..=5 x 20 txs
    assert_eq!(
        new_st.receipt_count().unwrap(),
        old_st.receipt_count().unwrap()
    );
    // Spot-check surviving + pruned reads match.
    for (h, i) in [(6u64, 0u64), (9, 19)] {
        let hh = det_tx(h * 100 + i).compute_tx_hash();
        assert_eq!(
            new_st.get_receipt(&hh).unwrap().is_some(),
            old_st.get_receipt(&hh).unwrap().is_some()
        );
    }
    let gone = det_tx(0).compute_tx_hash();
    assert!(new_st.get_receipt(&gone).unwrap().is_none());
    assert!(old_st.get_receipt(&gone).unwrap().is_none());
    std::fs::remove_dir_all(&dir_new).ok();
    std::fs::remove_dir_all(&dir_old).ok();
}

/// Fixed-fixture state roots: live root == snapshot-restored root ==
/// storage-round-tripped root (post-commit equivalence + restore equality).
#[tokio::test]
async fn state_root_survives_snapshot_and_storage_roundtrip() {
    let eng = InMemoryStateEngine::new();
    for i in 0..16u64 {
        eng.update_account(AccountState::new(det32(0xA0, i), 1_000_000 + i))
            .await;
    }
    let root_live = eng.get_state_root().await;

    // In-memory snapshot round-trip.
    let snap = eng.create_snapshot().await;
    let eng2 = InMemoryStateEngine::new();
    eng2.restore_snapshot(&snap).await.expect("restore");
    assert_eq!(eng2.get_state_root().await, root_live);

    // Storage round-trip with a reopened store (crash-recovery pair).
    let dir = tmpdir("stateroot");
    {
        let st = Storage::open(&dir).unwrap();
        st.put_state(42, &snap).unwrap();
        st.flush().unwrap();
    }
    {
        let st = Storage::open(&dir).unwrap();
        let (_, bytes) = st.latest_state().unwrap().expect("snapshot survives");
        assert_eq!(bytes, snap);
        let eng3 = InMemoryStateEngine::new();
        eng3.restore_snapshot(&bytes).await.expect("restore");
        assert_eq!(eng3.get_state_root().await, root_live);
    }
    std::fs::remove_dir_all(&dir).ok();
}
