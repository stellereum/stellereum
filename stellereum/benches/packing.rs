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
//! * `apply_mixed_*` — `InMemoryStateEngine::apply_block_parallel_fees`
//!   (THE live consensus apply path) over blocks of N mixed txs (3/4 plain
//!   value transfers + 1/4 single-`Transfer`-syscall payloads), N = 100 /
//!   428 / 1_000. Reports wall ms and tx/s; asserts every tx applies.
//!
//! FIXTURE NOTE (FULL-PQ): the transactions are Falcon-512 implicit-envelope
//! transactions signed by deterministically seeded keypairs. The old fixture
//! signed classical Ed25519 transactions, which FULL-PQ admission refuses
//! (`Malformed("Pure PQ mode: ...")`), so the rows could not run at all. The
//! pool SHAPE is unchanged: distinct senders, nonce 0, `GAS_BASIC_TRANSFER`,
//! no priority bid — the same selection workload, only in an admissible
//! envelope. Keypairs are generated once per process and reused by all rows.

use rayon::prelude::*;
use std::sync::OnceLock;
use std::time::Instant;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::runtime::{MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;
const RECIPIENT: [u8; 32] = [9u8; 32];
/// Distinct senders the fixture can draw on (max row size + slack).
const SENDERS: usize = 10_128;

fn pq_seed(i: u64) -> [u8; 32] {
    let mut seed = [0x61u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed
}

struct PqSender {
    kp: FalconKeypair,
    from: [u8; 32],
}

/// One deterministic Falcon-512 sender per index, keyed and registered in the
/// process-global implicit registry once (keygen is the expensive part).
fn senders() -> &'static [PqSender] {
    static SENDERS_ONCE: OnceLock<Vec<PqSender>> = OnceLock::new();
    SENDERS_ONCE.get_or_init(|| {
        (0..SENDERS as u64)
            .into_par_iter()
            .map(|i| {
                let kp = FalconKeypair::generate_from_seed_bytes(&pq_seed(i));
                let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
                let _ = Transaction::global_implicit_registry().register(
                    from,
                    PqScheme::Falcon512,
                    &kp.public_key,
                    &DEFAULT_SALT,
                );
                PqSender { kp, from }
            })
            .collect()
    })
}

/// Falcon-signed implicit-envelope transfer for sender `idx`, nonce 0, no
/// priority bid, with an optional syscall payload.
fn pq_tx(idx: usize, payload: Vec<OpCode>) -> Transaction {
    let s = &senders()[idx];
    let skeleton = Transaction {
        from: s.from,
        to: RECIPIENT,
        amount: 1,
        gas_limit: GAS_BASIC_TRANSFER,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: payload.clone(),
        priority_fee_per_gas: 0,
    };
    let msg = skeleton.signing_message();
    let sig = s.kp.sign_with_seed(&msg, &pq_seed(9_000_000 + idx as u64));
    Transaction::new_pq_implicit(
        s.from,
        PqScheme::Falcon512,
        sig,
        RECIPIENT,
        1,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        payload,
    )
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

/// Median and BEST (minimum) of `repeats` samples of `f`, in ns per
/// `per_op` units.
///
/// The median is the headline on an idle machine; the minimum is the robust
/// estimator on a SHARED one (this box runs other builds/nodes): a sample
/// that was descheduled can only be slower than the real cost, never faster,
/// so the best sample is the closest honest estimate of the op itself.
fn time_ns_per_op(per_op: usize, repeats: usize, warmup: usize, mut f: impl FnMut()) -> (f64, f64) {
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
    (samples[samples.len() / 2], samples[0])
}

/// Fill a pool with `n` distinct-sender plain transfers (nonce 0, gas =
/// `GAS_BASIC_TRANSFER`), the unit the 1785-packing math is stated in.
fn fill_plain(n: usize) -> Mempool {
    let txs: Vec<Transaction> = (0..n)
        .into_par_iter()
        .map(|i| pq_tx(i, Vec::new()))
        .collect();
    let mut pool = Mempool::new(n.max(1024) + 128, 10_000);
    for tx in txs {
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
    // Best-of-N is reported alongside the median: on a shared host the
    // median absorbs whatever else was running, the minimum does not.
    let repeats = 25;
    let (ns, best) = time_ns_per_op(1, repeats, 2, || {
        let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |_| true);
        packed = sel.len();
    });
    assert_eq!(
        packed,
        gas_cap_txs.min(pool_size),
        "gas cap binds at {gas_cap_txs} plain txs"
    );
    println!(
        "[bench][packing][select_multi_plain] pool={pool_size:>5} packed={packed:>4} time={} median, {} best-of-{repeats}",
        medal(ns),
        medal(best),
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

/// N mixed txs from N distinct funded senders: 3/4 plain value transfers,
/// 1/4 single-`Transfer`-syscall payloads (exercises the VM + transfer
/// channel on the live path). Returns the txs; funding is the caller's job.
fn mixed_txs(n: usize) -> Vec<Transaction> {
    (0..n)
        .into_par_iter()
        .map(|i| {
            let payload = if i % 4 == 3 {
                vec![OpCode::Transfer {
                    recipient: RECIPIENT,
                    amount: 1,
                }]
            } else {
                Vec::new()
            };
            pq_tx(i, payload)
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
            for i in 0..n {
                e.update_account(AccountState::new(senders()[i].from, BAL))
                    .await;
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
