//! State COMMIT/WRITE path bench (storage flusher/persist/put paths).
//!
//! Fixed deterministic fixtures, no randomness in the timer. Run in RELEASE:
//!     cargo test --release --bench state_commit -- --nocapture
//! Report lines are `[bench][state_commit] ...`. No timing asserts (reports,
//! not gates); correctness asserts pin exact equivalence separately in
//! `tests/state_commit_batch_tests.rs`.

use std::time::Instant;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::storage::{ConsensusCheckpoint, Storage};

/// Deterministic 32-byte key: first 8 bytes = i (BE), rest = seed fill.
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
        signature: vec![0xAB; 64],
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

fn tmpdir(tag: &str, rep: usize) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell_state_commit_{tag}_{}_{rep}",
        std::process::id()
    ))
}

fn rm(p: &std::path::Path) {
    std::fs::remove_dir_all(p).ok();
}

/// Per-height finalize trio: put_block + set_finalized + set_consensus.
/// This is what the background writer does for every finalized height.
#[test]
fn bench_height_trio() {
    const HEIGHTS: u64 = 200;
    for rep in 0..3 {
        let dir = tmpdir("trio", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        let t0 = Instant::now();
        for h in 0..HEIGHTS {
            let b = det_block(h, 4);
            let bh = st.put_block(&b).unwrap();
            st.set_finalized(h, &bh).unwrap();
            st.set_consensus(&ConsensusCheckpoint {
                height: h + 1,
                round: 0,
                locked_hash: None,
                locked_round: 0,
                finalized_height: h,
                finalized_hash: bh,
            })
            .unwrap();
        }
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!(
            "[bench][state_commit] height_trio heights={HEIGHTS} rep={rep} total_ms={ms:.2} per_height_us={:.1}",
            ms * 1000.0 / HEIGHTS as f64
        );
        rm(&dir);
    }
}

/// Receipt batch for one applied block (n=428, the packing-bench width).
#[test]
fn bench_receipts_428() {
    const N: usize = 428;
    for rep in 0..3 {
        let dir = tmpdir("rcpt", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        let txs: Vec<Transaction> = (0..N as u64).map(det_tx).collect();
        let statuses = vec![true; N];
        let fees = vec![280_000u64; N];
        let bh = det32(0xBE, 11);
        let t0 = Instant::now();
        let n = st
            .put_receipts_for_block_with_events(11, &bh, &txs, &statuses, &fees, &[])
            .unwrap();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(n, N);
        println!("[bench][state_commit] receipts_428 rep={rep} total_ms={ms:.2}");
        rm(&dir);
    }
}

/// OLD vs NEW: the single-`sled::Batch` candidate vs the kept per-tx loop
/// (the exact pre-batch algorithm, via the retained single-key API) on the
/// identical fixed fixture. VERDICT (9 release reps, N=428): 0.06x–1.23x,
/// median ~0.3x — the batch is never faster (batch machinery exceeds
/// 428 x ~4us pagecache inserts), so the batch was REVERTED and this test
/// pins the kept loop against the single-key reference (expect ~1.0x).
#[test]
fn bench_receipts_old_vs_new() {
    const N: usize = 428;
    let txs: Vec<Transaction> = (0..N as u64).map(det_tx).collect();
    let statuses = vec![true; N];
    let fees = vec![280_000u64; N];
    let bh = det32(0xBE, 11);
    for rep in 0..3 {
        // OLD (pre-batch reference).
        let dir = tmpdir("rcpt_old", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        let t0 = Instant::now();
        for (i, tx) in txs.iter().enumerate() {
            st.put_receipt(&stellereum::storage::StoredReceipt {
                tx_hash: tx.compute_tx_hash(),
                height: 11,
                block_hash: bh,
                index: i as u32,
                success: true,
                gas_limit: tx.gas_limit,
                fee_charged: 280_000,
                events: vec![],
            })
            .unwrap();
        }
        let old_ms = t0.elapsed().as_secs_f64() * 1000.0;
        rm(&dir);
        // NEW (kept path: `put_receipts_for_block_with_events`, reverted to
        // the per-tx loop after the batch measured slower — expect ~1.0x).
        let dir = tmpdir("rcpt_new", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        let t0 = Instant::now();
        let n = st
            .put_receipts_for_block_with_events(11, &bh, &txs, &statuses, &fees, &[])
            .unwrap();
        let new_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(n, N);
        println!(
            "[bench][state_commit] receipts_old_vs_new rep={rep} old_ms={old_ms:.2} new_ms={new_ms:.2} speedup={:.2}x",
            old_ms / new_ms.max(1e-9)
        );
        rm(&dir);
    }
}

/// Durability barrier after 25 heights of trio writes (the live cadence).
/// NOTE: the pre-change barrier did one extra `pq_keys.flush()` on the same
/// shared pagecache; it cannot be timed post-hoc (no public API flushes one
/// tree), so this reports the AFTER number only — the win is one fewer fsync
/// per barrier with an identical guarantee (see `Storage::flush` docs).
#[test]
fn bench_flush_barrier() {
    for rep in 0..3 {
        let dir = tmpdir("flush", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        for h in 0..25u64 {
            let b = det_block(h, 4);
            let bh = st.put_block(&b).unwrap();
            st.set_finalized(h, &bh).unwrap();
        }
        let t0 = Instant::now();
        st.flush().unwrap();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("[bench][state_commit] flush_barrier rep={rep} total_ms={ms:.2}");
        rm(&dir);
    }
}

/// Snapshot pair write: state + 5 domain-tree blobs (the snapshot-job shape).
#[test]
fn bench_snapshot_pair() {
    let blob = vec![0xA5u8; 262_144]; // 256 KiB per tree
    for rep in 0..3 {
        let dir = tmpdir("snap", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        let t0 = Instant::now();
        st.put_state(100, &blob).unwrap();
        st.put_domains(100, &blob).unwrap();
        st.put_session_keys(100, &blob).unwrap();
        st.put_bridge(100, &blob).unwrap();
        st.put_zkml_models(100, &blob).unwrap();
        st.put_cross_shard(100, &blob).unwrap();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("[bench][state_commit] snapshot_pair rep={rep} total_ms={ms:.2}");
        rm(&dir);
    }
}

/// Prune pass over 3000 seeded heights (bounded single pass, reporter only:
/// the batched-prune variant was measured 0.6-1.2x (never faster, scan
/// dominates) and reverted — per-key removes stand).
#[test]
fn bench_prune_blocks() {
    for rep in 0..3 {
        let dir = tmpdir("prune", rep);
        rm(&dir);
        let st = Storage::open(&dir).unwrap();
        for h in 0..3000u64 {
            st.put_block(&det_block(h, 0)).unwrap();
        }
        let t0 = Instant::now();
        let removed = st.prune_blocks_below(2500).unwrap();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!(
            "[bench][state_commit] prune_blocks removed={removed} rep={rep} total_ms={ms:.2}"
        );
        rm(&dir);
    }
}
