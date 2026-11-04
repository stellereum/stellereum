//! Fee-path timing harness for the apply-FEE optimization (std-only; no criterion).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench fee_path -- --nocapture
//! Each test prints `[bench][fee]` lines. These are REPORTS, not gates:
//! there are no timing asserts, only correctness asserts — a slow machine
//! must still be green.
//!
//! What is measured: `InMemoryStateEngine::apply_block_parallel_fees` (THE
//! live consensus apply path) over fixed 428-tx fixtures shaped to isolate
//! the per-transaction FEE overhead (floor evaluation + failure-fee debit)
//! from signature verification and VM execution. Four rows: `fee_plain_seq`
//! (428 plain transfers, sequential loop — every tx through the commit fee
//! prefix), `fee_mixed_seq` (3/4 plain + 1/4 `Transfer`-syscall payloads,
//! sequential loop — fee prefix + one VM transfer per payload tx),
//! `fee_oom_fail` (428 attributable out-of-gas failures — every tx through
//! the `fail_with_floor!` failure-fee path), and `fee_plain_wave` (428 plain
//! transfers with parallel wave execution on — the `apply_plain_wave`
//! concurrent path).
//! Signatures are verified once (the correctness-first run attests every
//! fixture transaction into the verify-once cache, whose 65k cap holds all
//! rows at once), so the timed samples run the attested path and the timer
//! isolates apply+fees: intake crypto is excluded by design — see
//! packing/tempo_probe for the verification costs. Engine funding happens
//! OUTSIDE the timer.

use ed25519_dalek::SigningKey;
use std::time::Instant;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

const N: usize = 428;
const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;
const RECIPIENT: [u8; 32] = [9u8; 32];
const OOM_GAS: u64 = 100;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn addr_of(i: u64) -> [u8; 32] {
    det_key(i).verifying_key().to_bytes()
}

fn plain_txs(n: usize, key_base: u64) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| {
            Transaction::sign(
                &det_key(key_base + i),
                RECIPIENT,
                1,
                GAS_BASIC_TRANSFER,
                0,
                1,
                1,
            )
        })
        .collect()
}

fn mixed_txs(n: usize, key_base: u64) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| {
            let payload = if i % 4 == 3 {
                vec![OpCode::Transfer {
                    recipient: RECIPIENT,
                    amount: 1,
                }]
            } else {
                Vec::new()
            };
            Transaction::sign_with_payload(
                &det_key(key_base + i),
                RECIPIENT,
                1,
                GAS_BASIC_TRANSFER,
                0,
                1,
                1,
                payload,
            )
        })
        .collect()
}

fn oom_txs(n: usize, key_base: u64) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| {
            Transaction::sign_with_payload(
                &det_key(key_base + i),
                RECIPIENT,
                1,
                OOM_GAS,
                0,
                1,
                1,
                vec![OpCode::Transfer {
                    recipient: RECIPIENT,
                    amount: 1,
                }],
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

fn fresh_engine(from_keys: u64, parallel: bool) -> InMemoryStateEngine {
    rt_block_on(async {
        let e = InMemoryStateEngine::new();
        e.set_parallel_exec(parallel);
        for i in 0..N as u64 {
            e.update_account(AccountState::new(addr_of(from_keys + i), BAL))
                .await;
        }
        e.update_account(AccountState::new(RECIPIENT, 0)).await;
        e
    })
}

/// Median-of-`repeats` wall time of applying `txs` to a FRESH funded engine
/// per sample (nonces always start at 0: every sample is the honest
/// full-apply path, never the replay-reject path). Asserts the exact
/// expected verdict counts and fee total — correctness, not timing.
fn bench_fee_row(
    name: &str,
    txs: &[Transaction],
    key_base: u64,
    parallel: bool,
    expect_applied: usize,
    expect_failed: usize,
    expect_fees: u64,
) {
    // Correctness first on a throwaway engine (also attests every fixture
    // transaction into the verify-once cache, so timed samples below run
    // the attested path and the timer isolates apply+fees).
    {
        let e = fresh_engine(key_base, parallel);
        let (applied, failed, fees, _, _) =
            rt_block_on(e.apply_block_parallel_fees(txs, TS));
        assert_eq!((applied, failed), (expect_applied, expect_failed), "{name}");
        assert_eq!(fees, expect_fees, "{name} fees_collected");
    }
    let repeats = 5usize;
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let e = fresh_engine(key_base, parallel);
        let t = Instant::now();
        let (applied, failed, fees, _, _) =
            rt_block_on(e.apply_block_parallel_fees(txs, TS));
        samples.push(t.elapsed().as_secs_f64());
        assert_eq!((applied, failed), (expect_applied, expect_failed), "{name}");
        assert_eq!(fees, expect_fees, "{name} fees_collected");
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let secs = samples[samples.len() / 2];
    println!(
        "[bench][fee][{name}] n={N} wall={:.3} ms ({:.1} ns/tx) fees_collected={expect_fees}",
        secs * 1_000.0,
        secs * 1e9 / N as f64,
    );
}

#[test]
fn fee_plain_seq_428() {
    let txs = plain_txs(N, 700_000);
    bench_fee_row(
        "plain_seq",
        &txs,
        700_000,
        false,
        N,
        0,
        N as u64 * GAS_BASIC_TRANSFER,
    );
}

#[test]
fn fee_mixed_seq_428() {
    let txs = mixed_txs(N, 800_000);
    bench_fee_row(
        "mixed_seq",
        &txs,
        800_000,
        false,
        N,
        0,
        N as u64 * GAS_BASIC_TRANSFER,
    );
}

#[test]
fn fee_oom_fail_428() {
    let txs = oom_txs(N, 900_000);
    bench_fee_row("oom_fail", &txs, 900_000, false, 0, N, N as u64 * OOM_GAS);
}

#[test]
fn fee_plain_wave_428() {
    let txs = plain_txs(N, 1_000_000);
    bench_fee_row(
        "plain_wave",
        &txs,
        1_000_000,
        true,
        N,
        0,
        N as u64 * GAS_BASIC_TRANSFER,
    );
}
