//! Per-height CPU budget bench (0.6s/block program, measurement only).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench block_cpu_budget -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][cpu-budget]` lines.
//! This is a REPORT, not a tight gate: there are no timing asserts, only
//! correctness asserts — a slow machine must still be green. The generous
//! 150ms regression bound lives in `tests/cpu_budget_tests.rs`.
//!
//! Stages per height on fixed fixtures (N = 100 / 428 / 1000 txs):
//! mempool-select, propose-build, intake-verify, QC-assemble, QC-verify,
//! apply, commit, snapshot-amortized (full `create_snapshot` / 50).
//! Method: fixed seeds, median-of-5 per stage.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::SigningKey;

use stellereum::consensus::{ValidatorSet, Vote, VoteKind, VoteSet};
use stellereum::mempool::Mempool;
use stellereum::runtime::{ValidatorRuntime, MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::Storage;
use stellereum::svm::GAS_BASIC_TRANSFER;

const TS: u64 = 9_000_000_007;
const BAL: u64 = 1_000_000_000_000;
const RECIPIENT: [u8; 32] = [9u8; 32];
const REPS: usize = 5;
const SNAPSHOT_INTERVAL: u64 = 50;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    v[v.len() / 2]
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn rt_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds")
        .block_on(f)
}

fn build_txs(n: usize) -> (Vec<Transaction>, Vec<[u8; 32]>) {
    let mut txs = Vec::with_capacity(n);
    let mut senders = Vec::with_capacity(n);
    for i in 0..n as u64 {
        let sk = det_key(1000 + i);
        senders.push(sk.verifying_key().to_bytes());
        txs.push(Transaction::sign(
            &sk,
            RECIPIENT,
            1,
            GAS_BASIC_TRANSFER,
            0,
            1,
            1,
        ));
    }
    (txs, senders)
}

async fn funded_engine(senders: &[[u8; 32]], val: [u8; 32]) -> Arc<InMemoryStateEngine> {
    let e = Arc::new(InMemoryStateEngine::new());
    e.update_account(AccountState::new(val, BAL)).await;
    for s in senders {
        e.update_account(AccountState::new(*s, BAL)).await;
    }
    e.update_account(AccountState::new(RECIPIENT, 0)).await;
    e
}

fn val_key() -> SigningKey {
    det_key(42_000_000)
}

async fn runtime_with_txs(txs: &[Transaction], senders: &[[u8; 32]]) -> ValidatorRuntime {
    let val_sk = val_key();
    let val = val_sk.verifying_key().to_bytes();
    let engine = funded_engine(senders, val).await;
    let vs = ValidatorSet::from_list(vec![(val, 1)]);
    let mut pool = Mempool::new(20_000, 10_000);
    for t in txs {
        pool.add(t.clone()).expect("pool add must succeed");
    }
    ValidatorRuntime::new(val_sk, vs, engine, 1)
        .with_mempool(Arc::new(tokio::sync::RwLock::new(pool)))
}

#[allow(clippy::too_many_lines)]
fn bench_row(n: usize) {
    rt_block_on(async {
        let (txs, senders) = build_txs(n);

        let mut pool = Mempool::new(20_000, 10_000);
        for t in &txs {
            pool.add(t.clone()).expect("pool add must succeed");
        }
        let mut select = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let t = Instant::now();
            let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |_| true);
            let d = ms(t.elapsed());
            assert_eq!(sel.len(), n);
            black_box(sel);
            select.push(d);
        }

        let mut propose = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let mut rt = runtime_with_txs(&txs, &senders).await;
            let t = Instant::now();
            let block = rt.propose(TS).await.expect("pool must propose");
            let d = ms(t.elapsed());
            assert_eq!(block.transactions.len(), n);
            black_box(block);
            propose.push(d);
        }

        let mut rt = runtime_with_txs(&txs, &senders).await;
        let block = rt.propose(TS).await.expect("pool must propose");
        let block_hash = block.compute_hash();

        let mut intake = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let t = Instant::now();
            let ok = Transaction::verify_signatures_batch_parallel(black_box(&txs));
            let d = ms(t.elapsed());
            assert!(ok);
            intake.push(d);
        }

        let vkeys: Vec<SigningKey> = (0..4u64).map(|i| det_key(800_000 + i)).collect();
        let vids: Vec<[u8; 32]> =
            vkeys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let vs = ValidatorSet::from_list(vids.iter().map(|id| (*id, 1)).collect());
        let mut qc_asm = Vec::with_capacity(REPS);
        let mut qc_ver = Vec::with_capacity(REPS);
        for r in 0..REPS {
            let votes: Vec<Vote> = vkeys
                .iter()
                .map(|k| Vote::sign(k, 1, r as u32, VoteKind::Precommit, Some(block_hash)))
                .collect();
            let t = Instant::now();
            let mut set = VoteSet::new();
            for v in &votes {
                set.add(v.clone(), &vs, 1, r as u32, VoteKind::Precommit)
                    .expect("honest vote must be admitted");
            }
            let qc = set
                .certificate(Some(block_hash), &vs, &[0u8; 32])
                .expect("quorum of 4x1 must certify");
            qc_asm.push(ms(t.elapsed()));
            let t = Instant::now();
            let ok = black_box(&qc).verify(&vs);
            qc_ver.push(ms(t.elapsed()));
            assert!(ok);
        }

        let val = val_key().verifying_key().to_bytes();
        let mut apply = Vec::with_capacity(REPS);
        let mut last_engine: Option<Arc<InMemoryStateEngine>> = None;
        for _ in 0..REPS {
            let e = funded_engine(&senders, val).await;
            let t = Instant::now();
            let out = e.apply_block_transition(black_box(&block), 0).await;
            let d = ms(t.elapsed());
            assert_eq!(out.applied, n);
            assert_eq!(out.failed, 0);
            last_engine = Some(e);
            apply.push(d);
        }

        let dir = std::env::temp_dir()
            .join(format!("stell_bench_cpu_{n}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Storage::open(&dir).expect("temp storage opens");
        let mut commit = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let t = Instant::now();
            store.put_block(black_box(&block)).expect("put_block");
            store.flush().expect("flush");
            commit.push(ms(t.elapsed()));
        }
        let _ = std::fs::remove_dir_all(&dir);

        let engine = last_engine.expect("apply ran");
        let mut snap = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let t = Instant::now();
            let bytes = engine.create_snapshot().await;
            let d = ms(t.elapsed());
            assert!(!bytes.is_empty());
            black_box(bytes);
            snap.push(d);
        }
        let snap_each = median(snap) / SNAPSHOT_INTERVAL as f64;

        let (select_ms, propose_ms, intake_ms, qc_asm_ms, qc_ver_ms, apply_ms, commit_ms) = (
            median(select),
            median(propose),
            median(intake),
            median(qc_asm),
            median(qc_ver),
            median(apply),
            median(commit),
        );
        let total =
            select_ms + propose_ms + intake_ms + qc_asm_ms + qc_ver_ms + apply_ms + commit_ms + snap_each;
        println!(
            "[bench][cpu-budget] n={n:>4} select={select_ms:8.2}ms propose={propose_ms:8.2}ms intake={intake_ms:8.2}ms qc_asm={qc_asm_ms:8.2}ms qc_ver={qc_ver_ms:8.2}ms apply={apply_ms:8.2}ms commit={commit_ms:8.2}ms snap/50={snap_each:8.2}ms TOTAL={total:8.2}ms (median-of-5)"
        );
    });
}

#[test]
fn block_cpu_budget_100() {
    bench_row(100);
}

#[test]
fn block_cpu_budget_428() {
    bench_row(428);
}

#[test]
fn block_cpu_budget_1000() {
    bench_row(1000);
}
