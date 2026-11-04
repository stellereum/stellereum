//! Per-height CPU budget proof (0.6s/block program, safety-first, measurement only).
//!
//! Stages timed per height on fixed fixtures (N = 100 / 428 / 1000 txs):
//! mempool-select, propose-build, intake-verify, QC-assemble, QC-verify,
//! apply, commit, snapshot-amortized (full `create_snapshot` cost spread over
//! the minimum snapshot interval of 50 heights).
//!
//! Method: fixed seeds (no OsRng, no wall clock in fixtures), median-of-5 per
//! stage, correctness asserted (selection count, signature verdicts, applied
//! count) but NO tight asserts on noisy per-stage rows. The single regression
//! gate is `TOTAL_428 <= BOUND_428_MS` (150ms generous bound: ~10x above the
//! measured release total, fails only on a blowup — not a tight wall gate).
//! Per-stage sub-budgets (propose 20 / verify 10 / QC 15 / apply 60 /
//! commit 20 / snapshot-amortized 10 / select 15, all ms) are REPORTED only
//! (`OVER-BUDGET` lines); they never fail the test — measurement only.
//!
//! The gate applies on release builds; debug builds report the table without
//! gating (dev-profile crypto is unoptimized for our own crate).

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
/// Minimum snapshot interval: a full snapshot every 50 heights, so each
/// height pays 1/50 of one.
const SNAPSHOT_INTERVAL: u64 = 50;
/// Generous regression bound: fails only on a ~10x blowup of the measured
/// release total. Must stay <= 150ms (4x headroom to the 0.6s program).
const BOUND_428_MS: f64 = 150.0;
// Sub-budgets (ms) — REPORT only, never gated.
const SUB_PROPOSE_MS: f64 = 20.0;
const SUB_VERIFY_MS: f64 = 10.0;
const SUB_QC_MS: f64 = 15.0;
const SUB_APPLY_MS: f64 = 60.0;
const SUB_COMMIT_MS: f64 = 20.0;
const SUB_SNAP_EACH_MS: f64 = 10.0;
const SUB_SELECT_MS: f64 = 15.0;

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

/// N distinct funded senders, nonce 0, cheapest real gas price.
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

/// Fresh single-validator runtime whose pool holds exactly `txs`.
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

struct BudgetRow {
    select_ms: f64,
    propose_ms: f64,
    intake_ms: f64,
    qc_asm_ms: f64,
    qc_ver_ms: f64,
    apply_ms: f64,
    commit_ms: f64,
    snap_each_ms: f64,
    total_ms: f64,
}

async fn measure_n(n: usize) -> BudgetRow {
    let (txs, senders) = build_txs(n);

    // mempool-select: pure selection over a pre-filled pool.
    let mut pool = Mempool::new(20_000, 10_000);
    for t in &txs {
        pool.add(t.clone()).expect("pool add must succeed");
    }
    let mut select = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let t = Instant::now();
        let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |_| true);
        let d = ms(t.elapsed());
        assert_eq!(sel.len(), n, "select must return all {n} txs");
        black_box(sel);
        select.push(d);
    }

    // propose-build: full block proposal, fresh runtime per rep.
    let mut propose = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let mut rt = runtime_with_txs(&txs, &senders).await;
        let t = Instant::now();
        let block = rt.propose(TS).await.expect("pool must propose");
        let d = ms(t.elapsed());
        assert_eq!(block.transactions.len(), n, "propose must pack all {n}");
        black_box(block);
        propose.push(d);
    }

    // Canonical block under test (same bytes every rep).
    let mut rt = runtime_with_txs(&txs, &senders).await;
    let block = rt.propose(TS).await.expect("pool must propose");
    let block_hash = block.compute_hash();

    // intake-verify: stateless batch signature check over the block's txs.
    let mut intake = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let t = Instant::now();
        let ok = Transaction::verify_signatures_batch_parallel(black_box(&txs));
        let d = ms(t.elapsed());
        assert!(ok, "fixture signatures must verify");
        intake.push(d);
    }

    // QC-assemble + QC-verify: 4-validator committee, fresh votes per rep
    // (fresh signatures defeat the verified-vote cache, so every rep pays
    // real crypto). Assembly = admit + certify; verification = full QC check.
    let vkeys: Vec<SigningKey> = (0..4u64).map(|i| det_key(800_000 + i)).collect();
    let vids: Vec<[u8; 32]> = vkeys.iter().map(|k| k.verifying_key().to_bytes()).collect();
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
        assert!(ok, "assembled QC must verify");
    }

    // apply: full block transition on a fresh funded engine per rep.
    let val = val_key().verifying_key().to_bytes();
    let mut apply = Vec::with_capacity(REPS);
    let mut last_engine: Option<Arc<InMemoryStateEngine>> = None;
    for _ in 0..REPS {
        let e = funded_engine(&senders, val).await;
        let t = Instant::now();
        let out = e.apply_block_transition(black_box(&block), 0).await;
        let d = ms(t.elapsed());
        assert_eq!(out.applied, n, "apply must apply all {n}");
        assert_eq!(out.failed, 0, "apply must fail none");
        last_engine = Some(e);
        apply.push(d);
    }

    // commit: block persist + flush to a temp sled store.
    let dir = std::env::temp_dir().join(format!("stell_cpu_budget_{n}_{}", std::process::id()));
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

    // snapshot-amortized: full snapshot of post-apply state, spread over 50.
    let engine = last_engine.expect("apply ran");
    let mut snap = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let t = Instant::now();
        let bytes = engine.create_snapshot().await;
        let d = ms(t.elapsed());
        assert!(!bytes.is_empty(), "snapshot must serialize");
        black_box(bytes);
        snap.push(d);
    }
    let snap_each = median(snap) / SNAPSHOT_INTERVAL as f64;

    let row = BudgetRow {
        select_ms: median(select),
        propose_ms: median(propose),
        intake_ms: median(intake),
        qc_asm_ms: median(qc_asm),
        qc_ver_ms: median(qc_ver),
        apply_ms: median(apply),
        commit_ms: median(commit),
        snap_each_ms: snap_each,
        total_ms: 0.0,
    };
    let total = row.select_ms
        + row.propose_ms
        + row.intake_ms
        + row.qc_asm_ms
        + row.qc_ver_ms
        + row.apply_ms
        + row.commit_ms
        + row.snap_each_ms;
    BudgetRow { total_ms: total, ..row }
}

#[allow(clippy::assertions_on_constants)] // GATE: bound pin is a spec-ceiling check, const-true by design; guards future bound edits.
#[tokio::test]
async fn cpu_budget_per_height() {
    let mut rows = Vec::new();
    for n in [100usize, 428, 1000] {
        rows.push(measure_n(n).await);
    }
    println!("stage            |   N=100 |   N=428 |  N=1000  (median-of-5 ms)");
    let cell = |v: f64| format!("{v:8.2}");
    let line = |name: &str, f: fn(&BudgetRow) -> f64| {
        format!(
            "{name:16} | {} | {} | {}",
            cell(f(&rows[0])),
            cell(f(&rows[1])),
            cell(f(&rows[2]))
        )
    };
    println!("{}", line("mempool-select  ", |r| r.select_ms));
    println!("{}", line("propose-build   ", |r| r.propose_ms));
    println!("{}", line("intake-verify   ", |r| r.intake_ms));
    println!("{}", line("qc-assemble     ", |r| r.qc_asm_ms));
    println!("{}", line("qc-verify       ", |r| r.qc_ver_ms));
    println!("{}", line("apply           ", |r| r.apply_ms));
    println!("{}", line("commit          ", |r| r.commit_ms));
    println!("{}", line("snapshot/50     ", |r| r.snap_each_ms));
    println!("{}", line("TOTAL           ", |r| r.total_ms));
    let r428 = &rows[1];
    let qc_428 = r428.qc_asm_ms + r428.qc_ver_ms;
    println!(
        "TOTAL@428 = {:.2}ms  BOUND = {:.2}ms (propose {:.2} / verify {:.2} / qc {:.2} / apply {:.2} / commit {:.2} / snap/50 {:.2} / select {:.2})",
        r428.total_ms,
        BOUND_428_MS,
        r428.propose_ms,
        r428.intake_ms,
        qc_428,
        r428.apply_ms,
        r428.commit_ms,
        r428.snap_each_ms,
        r428.select_ms
    );
    // Sub-budget report only (measurement, never gated).
    let checks = [
        ("propose", r428.propose_ms, SUB_PROPOSE_MS),
        ("intake-verify", r428.intake_ms, SUB_VERIFY_MS),
        ("qc-assemble+verify", qc_428, SUB_QC_MS),
        ("apply", r428.apply_ms, SUB_APPLY_MS),
        ("commit", r428.commit_ms, SUB_COMMIT_MS),
        ("snapshot-amortized", r428.snap_each_ms, SUB_SNAP_EACH_MS),
        ("mempool-select", r428.select_ms, SUB_SELECT_MS),
    ];
    let mut over = Vec::new();
    for (name, got, sub) in checks {
        if got > sub {
            println!("OVER-BUDGET: {name} {got:.2}ms > sub-budget {sub:.2}ms @428");
            over.push(name);
        }
    }
    if over.is_empty() {
        println!("sub-budgets: all stages within budget @428");
    }

    // The bound itself must keep 4x headroom to the 0.6s program.
    assert!(
        BOUND_428_MS <= 150.0,
        "budget bound {BOUND_428_MS} exceeds the 150ms ceiling"
    );
    // Regression gate: release only (debug reports without gating).
    if !cfg!(debug_assertions) {
        assert!(
            r428.total_ms <= BOUND_428_MS,
            "CPU budget blown: TOTAL@428 {:.2}ms > bound {:.2}ms",
            r428.total_ms,
            BOUND_428_MS
        );
    } else {
        println!("debug build: table reported, release gate not applied");
    }
}
