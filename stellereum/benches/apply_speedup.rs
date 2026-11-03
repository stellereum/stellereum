//! Parallel-apply speedup curve + plan-chunk sensitivity (std-only; no criterion).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench apply_speedup -- --nocapture
//! The single test prints `[bench][apply_speedup]` lines. These are REPORTS,
//! not gates: there are no timing asserts, only correctness asserts - a slow
//! machine must still be green.
//!
//! What is measured: `InMemoryStateEngine::apply_block_parallel_fees` (THE
//! live consensus apply path) over fixed disjoint-plain fixtures shaped so
//! every block is ONE wave of N mutually-disjoint transfers, i.e. the
//! `apply_plain_wave` concurrent path (snapshot -> rayon plan -> CAS merge)
//! end to end. Signatures are verified once (the correctness-first run
//! attests every fixture transaction into the verify-once cache), so the
//! timed samples run the attested path and the timer isolates apply+fees:
//! intake crypto is excluded by design. Engine funding happens OUTSIDE the
//! timer.
//!
//! Two reports:
//!   * curve: N in {100, 428, 1000, 2000} x {serial, 1, 2, 4, 8 threads} -
//!     wall ms + speedup vs the serial sample on the SAME box. Thread counts
//!     run on dedicated rayon pools (`ThreadPoolBuilder::install`), so one
//!     binary sweeps all counts without re-exec.
//!   * chunk: `STELL_PARALLEL_PLAN_CHUNK` in {1, 8, 32, 128, 512, 2048} at
//!     N=2000 / 8 threads - wall ms per chunk size, naming the best stable
//!     value (the default the engine ships when the env is unset).

use ed25519_dalek::SigningKey;
use rayon::ThreadPoolBuilder;
use std::time::Instant;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::GAS_BASIC_TRANSFER;

const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_001_013;
const NS: [usize; 4] = [100, 428, 1000, 2000];
const THREADS: [usize; 4] = [1, 2, 4, 8];
const CHUNKS: [usize; 6] = [1, 8, 32, 128, 512, 2048];
const REPEATS: usize = 5;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0x3Du8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed[8..16].copy_from_slice(&0xA0_9Fu64.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn addr_of(i: u64) -> [u8; 32] {
    det_key(i).verifying_key().to_bytes()
}

/// N mutually-disjoint plain transfers: sender `base+i` -> fresh recipient
/// `base+N+i`. Distinct senders AND distinct recipients, so the scheduler
/// puts the whole block in ONE wave of N (the concurrent shape).
fn disjoint_txs(n: usize, base: u64) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| {
            Transaction::sign(
                &det_key(base + i),
                addr_of(base + n as u64 + i),
                1,
                GAS_BASIC_TRANSFER,
                0,
                1,
                1,
            )
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

fn fresh_engine(base: u64, n: usize, parallel: bool) -> InMemoryStateEngine {
    rt_block_on(async {
        let e = InMemoryStateEngine::new();
        e.set_parallel_exec(parallel);
        for i in 0..n as u64 {
            e.update_account(AccountState::new(addr_of(base + i), BAL))
                .await;
        }
        e
    })
}

/// Median wall seconds of applying `txs` to a FRESH funded engine per sample
/// (nonces always start at 0: every sample is the honest full-apply path).
/// Asserts the exact expected verdicts and fee total - correctness, not timing.
fn median_apply_secs(
    txs: &[Transaction],
    base: u64,
    parallel: bool,
    pool: Option<&rayon::ThreadPool>,
) -> f64 {
    let expect_fees = txs.len() as u64 * GAS_BASIC_TRANSFER;
    let run_once = || {
        let e = fresh_engine(base, txs.len(), parallel);
        let t = Instant::now();
        let (applied, failed, fees, _, _) = match pool {
            Some(p) => p.install(|| rt_block_on(e.apply_block_parallel_fees(txs, TS))),
            None => rt_block_on(e.apply_block_parallel_fees(txs, TS)),
        };
        let secs = t.elapsed().as_secs_f64();
        assert_eq!((applied, failed), (txs.len(), 0));
        assert_eq!(fees, expect_fees);
        secs
    };
    let mut samples: Vec<f64> = (0..REPEATS).map(|_| run_once()).collect();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

#[test]
fn apply_speedup_matrix() {
    // Correctness-first + attestation: every fixture transaction is verified
    // once here (verify-once cache), so all timed samples below run the
    // attested path and the timer isolates apply+fees.
    let mut fixtures: Vec<(usize, u64, Vec<Transaction>)> = Vec::new();
    for (row, &n) in NS.iter().enumerate() {
        let base = 40_000_000u64 + row as u64 * 10_000;
        let txs = disjoint_txs(n, base);
        let e = fresh_engine(base, n, true);
        let (applied, failed, fees, _, _) = rt_block_on(e.apply_block_parallel_fees(&txs, TS));
        assert_eq!((applied, failed), (n, 0));
        assert_eq!(fees, n as u64 * GAS_BASIC_TRANSFER);
        fixtures.push((n, base, txs));
    }

    // --- curve: serial baseline, then 1/2/4/8 threads, same box ----------
    for (n, base, txs) in &fixtures {
        let serial = median_apply_secs(txs, *base, false, None);
        println!(
            "[bench][apply_speedup][curve] n={n} threads=serial wall={:.3} ms ({:.0} ns/tx) speedup_vs_serial=1.00x",
            serial * 1_000.0,
            serial * 1e9 / *n as f64,
        );
        for &t in &THREADS {
            let pool = ThreadPoolBuilder::new()
                .num_threads(t)
                .build()
                .expect("pool builds");
            let wall = median_apply_secs(txs, *base, true, Some(&pool));
            println!(
                "[bench][apply_speedup][curve] n={n} threads={t} wall={:.3} ms ({:.0} ns/tx) speedup_vs_serial={:.2}x",
                wall * 1_000.0,
                wall * 1e9 / *n as f64,
                serial / wall.max(1e-9),
            );
        }
    }

    // --- chunk sensitivity: fixed N=2000, fixed 8 threads -----------------
    let (n, base, txs) = fixtures.last().expect("N=2000 fixture");
    assert_eq!(*n, 2000);
    let pool = ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .expect("pool builds");
    let mut best = (0usize, f64::INFINITY);
    for &c in &CHUNKS {
        std::env::set_var("STELL_PARALLEL_PLAN_CHUNK", c.to_string());
        let wall = median_apply_secs(txs, *base, true, Some(&pool));
        println!(
            "[bench][apply_speedup][chunk] n={n} threads=8 plan_chunk={c} wall={:.3} ms ({:.0} ns/tx)",
            wall * 1_000.0,
            wall * 1e9 / *n as f64,
        );
        if wall < best.1 {
            best = (c, wall);
        }
    }
    std::env::remove_var("STELL_PARALLEL_PLAN_CHUNK");
    println!(
        "[bench][apply_speedup][chunk] verdict: best_stable_chunk={} wall={:.3} ms",
        best.0,
        best.1 * 1_000.0,
    );
}
