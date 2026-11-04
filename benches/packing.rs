//! Packing + apply benchmarks for the 1k-TPS recipe (std-only; no criterion).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench packing -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][packing]` lines.
//! These are REPORTS, not gates: there are no timing asserts, only
//! correctness asserts — a slow machine must still be green.
//!
//! What is measured, and why it is honest:
//! * `packing_plain_*` — `Mempool::select_for_block_multi` wall time over
//!   synthetic pools of 428 / 1_000 / 10_000 plain transfers under the REAL
//!   producer caps (`MAX_BLOCK_TXS`, `MAX_BLOCK_GAS` = 500M). Every tx
//!   declares `GAS_BASIC_TRANSFER` (280k), so the gas cap binds at 1785 and
//!   the count cap does not bind before it — the point is selection TIME vs
//!   pool size plus the pinned packed count, not a bigger block.
//! * `transfer2_verify_32_vs_64` — the exact live-path predicate
//!   (`ConfidentialTransfer::verify_balanced_with_ranges`, called by the
//!   `SysCallConfidentialTransfer2` handler BEFORE anything mutates) for a
//!   1-in/1-out transfer at 32-bit vs 64-bit proof widths. Same committed
//!   values, only the width differs, so the delta isolates proof-size cost.
//!   Proving is setup-only (outside the timer).
//! * `apply_mixed_*` — `InMemoryStateEngine::apply_block_parallel_fees`
//!   (THE live consensus apply path) over blocks of N mixed txs (3/4 plain
//!   value transfers + 1/4 single-`Transfer`-syscall payloads), N = 100 /
//!   428 / 1_000. Reports wall ms and tx/s; asserts every tx applies.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use std::time::Instant;
use stellereum::crypto_privacy::{ConfidentialTransfer, PedersenCommitment, RangeProof};
use stellereum::mempool::Mempool;
use stellereum::runtime::{MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;
const RECIPIENT: [u8; 32] = [9u8; 32];

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn medal(nanos: f64) -> String {
    if nanos >= 1_000_000.0 {
        format!("{:.3} ms/op", nanos / 1_000_000.0)
    } else if nanos >= 1_000.0 {
        format!("{:.3} us/op", nanos / 1_000.0)
    } else {
        format!("{:.1} ns/op", nanos)
    }
}

/// Median-of-repeats timing of `f`, reported as ns per `per_op` units.
fn time_ns_per_op(per_op: usize, repeats: usize, warmup: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..warmup {
        f();
    }
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos() as f64 / per_op as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

/// Fill a pool with `n` distinct-sender plain transfers (nonce 0, gas =
/// `GAS_BASIC_TRANSFER`), the unit the 1785-packing math is stated in.
fn fill_plain(n: usize) -> Mempool {
    let mut pool = Mempool::new(n.max(1024) + 128, 10_000);
    for i in 0..n as u64 {
        let sk = det_key(300_000 + i);
        let tx = Transaction::sign(&sk, RECIPIENT, 1, GAS_BASIC_TRANSFER, 0, 1, 1);
        pool.add_checked(tx, BAL)
            .expect("funded admission must succeed");
    }
    assert_eq!(pool.len(), n);
    pool
}

fn bench_packing_row(pool_size: usize) {
    // 500M / 280k = 1785.71…: the gas cap binds before the 10k count cap.
    // (Raised from the 120M cap, which bound at 428 — see the
    // MAX_BLOCK_GAS doc comment and docs/PERF_1K.md.)
    let gas_cap_txs = (MAX_BLOCK_GAS / GAS_BASIC_TRANSFER) as usize;
    assert_eq!(gas_cap_txs, 1785, "recipe math assumes 1785 plain/block");
    let pool = fill_plain(pool_size);
    let mut packed = 0usize;
    // Fewer repeats at 10k so debug-profile runs stay usable; the median
    // still washes out scheduling noise for a report.
    let repeats = if pool_size >= 10_000 { 5 } else { 10 };
    let ns = time_ns_per_op(1, repeats, 1, || {
        let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |_| true);
        packed = sel.len();
    });
    assert_eq!(
        packed,
        gas_cap_txs.min(pool_size),
        "gas cap binds at {gas_cap_txs} plain txs"
    );
    println!(
        "[bench][packing][select_multi_plain] pool={pool_size:>5} packed={packed:>4} time={} total",
        medal(ns),
    );
}

#[test]
fn packing_plain_428() {
    bench_packing_row(428);
}

#[test]
fn packing_plain_1000() {
    bench_packing_row(1_000);
}

#[test]
fn packing_plain_10000() {
    bench_packing_row(10_000);
}

/// One balanced 1-in/1-out transfer with explicit proof width: input commits
/// value+fee, output commits value, same blinding (mirrors the live
/// confidential-tx test helper).
fn transfer2_pair(
    value: u64,
    fee: u64,
    bits: u8,
) -> (ConfidentialTransfer, Vec<RangeProof>, Vec<RangeProof>) {
    let r = Scalar::from(0x5EED_u64);
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    let t = ConfidentialTransfer::new(vec![c_in], vec![c_out], fee);
    let in_ranges = vec![RangeProof::prove(&c_in, value + fee, &r, bits)];
    let out_ranges = vec![RangeProof::prove(&c_out, value, &r, bits)];
    assert!(t.verify_balanced_with_ranges(&in_ranges, &out_ranges));
    (t, in_ranges, out_ranges)
}

#[test]
fn transfer2_verify_32_vs_64() {
    // Same values (fit 32 bits); only the proof width differs, so the delta
    // is pure width cost on the exact live-path predicate.
    for bits in [32u8, 64u8] {
        let (t, in_ranges, out_ranges) = transfer2_pair(1_480, 20, bits);
        let repeats = if bits == 64 { 5 } else { 10 };
        let ns = time_ns_per_op(1, repeats, 1, || {
            assert!(t.verify_balanced_with_ranges(&in_ranges, &out_ranges));
        });
        println!(
            "[bench][packing][transfer2_verify_1in1out_{bits}bit] time={} per verify",
            medal(ns),
        );
    }
}

/// N mixed txs from N distinct funded senders: 3/4 plain value transfers,
/// 1/4 single-`Transfer`-syscall payloads (exercises the VM + transfer
/// channel on the live path). Returns the txs; funding is the caller's job.
fn mixed_txs(n: usize) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| {
            let sk = det_key(600_000 + i);
            let payload = if i % 4 == 3 {
                vec![OpCode::Transfer {
                    recipient: RECIPIENT,
                    amount: 1,
                }]
            } else {
                Vec::new()
            };
            Transaction::sign_with_payload(&sk, RECIPIENT, 1, GAS_BASIC_TRANSFER, 0, 1, 1, payload)
        })
        .collect()
}

fn rt_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds")
        .block_on(f)
}

fn bench_apply_row(n: usize) {
    let txs = mixed_txs(n);
    let fresh_engine = || {
        rt_block_on(async {
            let e = InMemoryStateEngine::new();
            for i in 0..n as u64 {
                let from = det_key(600_000 + i).verifying_key().to_bytes();
                e.update_account(AccountState::new(from, BAL)).await;
            }
            e.update_account(AccountState::new(RECIPIENT, 0)).await;
            e
        })
    };
    // Correctness first: the whole mixed block must apply clean.
    {
        let e = fresh_engine();
        let (applied, failed, _, _, _) = rt_block_on(e.apply_block_parallel_fees(&txs, TS));
        assert_eq!(applied, n, "all mixed txs must apply");
        assert_eq!(failed, 0);
    }
    // Each timed iteration applies to a FRESH funded engine (built outside
    // the timer): nonces always start at 0, so every sample measures the
    // honest full-apply path, never the replay-reject path.
    let repeats = if n >= 1000 { 3 } else { 5 };
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let e = fresh_engine();
        let t = Instant::now();
        let (applied, failed, _, _, _) = rt_block_on(e.apply_block_parallel_fees(&txs, TS));
        samples.push(t.elapsed().as_secs_f64());
        assert_eq!((applied, failed), (n, 0));
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let secs = samples[samples.len() / 2];
    println!(
        "[bench][packing][apply_mixed] n={n:>5} wall={:.3} ms ({:.0} tx/s)",
        secs * 1_000.0,
        n as f64 / secs.max(1e-9),
    );
}

#[test]
fn apply_mixed_100() {
    bench_apply_row(100);
}

#[test]
fn apply_mixed_428() {
    bench_apply_row(428);
}

#[test]
fn apply_mixed_1000() {
    bench_apply_row(1_000);
}
