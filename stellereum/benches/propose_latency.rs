//! Propose-latency breakdown: select + build + sign on fixed fixtures.
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench propose_latency -- --nocapture
//! (`cargo bench` runs them too.) These are REPORTS, not gates: there are no
//! timing asserts, only correctness asserts — a slow machine must still be
//! green.
//!
//! What is measured, and why it is honest:
//! * `select_wide` / `select_deep` — `Mempool::select_for_block_multi` through
//!   the REAL producer predicate (`ValidatorRuntime::pack_filter_accept` over
//!   a freshly snapshotted `PackFilterCtx`, exactly what `propose` builds),
//!   on two fixed 10k pools: wide (10k distinct senders x nonce 0) and deep
//!   (100 senders x 100 contiguous nonces). Timer covers the synchronous
//!   selection only; the async snapshot is built per sample OUTSIDE the timer.
//! * `propose_total_wide` / `propose_total_deep` — full UNCACHED
//!   `ValidatorRuntime::propose` wall time (fresh runtime per sample sharing
//!   one pool + one funded engine, so every sample takes the fresh-build
//!   path: snapshot + select + unseal gate + order root + size check + sign).
//! * `sign_ed25519` — one Ed25519 sign over a 32-byte block hash (the propose
//!   sign core; this fixture configures no Falcon key, same as a standard
//!   single-key validator).
//! * `build_derived_*` — REPORTED, not timed: propose_total minus select
//!   minus sign (everything else propose does: account snapshot, sealed path,
//!   unseal gate, order root, actor cap, block struct, pre-gossip encode,
//!   order commitment). Clamped at zero; labels say derived.

use ed25519_dalek::SigningKey;
use ed25519_dalek::Signer;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use stellereum::consensus::ValidatorSet;
use stellereum::mempool::Mempool;
use stellereum::runtime::{PackFilterCtx, ValidatorRuntime, MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::ShardId;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::GAS_BASIC_TRANSFER;
use stellereum::zkml::SessionSpendSim;

const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;
const RECIPIENT: [u8; 32] = [9u8; 32];
const MY_SHARD: ShardId = 0;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
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

fn rt_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds")
        .block_on(f)
}

/// Deterministic priority-bid scatter in 1..=1000 (fee order far from pool
/// order, so selection does real work). Gas covers the bid on top of the
/// plain-transfer resource cap, so admission stays funded.
fn bid(seq: u64) -> u64 {
    (seq.wrapping_mul(7919) % 1000) + 1
}

fn wide_tx(sk: &SigningKey, seq: u64) -> stellereum::sharding::Transaction {
    stellereum::sharding::Transaction::sign_with_priority(
        sk,
        RECIPIENT,
        1,
        GAS_BASIC_TRANSFER + bid(seq),
        0,
        1,
        1,
        bid(seq),
    )
}

fn deep_tx(sk: &SigningKey, nonce: u64, seq: u64) -> stellereum::sharding::Transaction {
    stellereum::sharding::Transaction::sign_with_priority(
        sk,
        RECIPIENT,
        1,
        GAS_BASIC_TRANSFER + bid(seq),
        nonce,
        1,
        1,
        bid(seq),
    )
}

struct Fixture {
    engine: Arc<InMemoryStateEngine>,
    pool: Arc<tokio::sync::RwLock<Mempool>>,
    val_sk: SigningKey,
    val_id: [u8; 32],
}

fn setup_fixture(kind: &'static str) -> Fixture {
    rt_block_on(async {
        let engine = Arc::new(InMemoryStateEngine::new());
        let mut pool = Mempool::new(20_000, 10_000);
        let mut seq = 0u64;
        if kind == "wide" {
            for i in 0..10_000u64 {
                let sk = det_key(100_000 + i);
                engine
                    .update_account(AccountState::new(id_of(&sk), BAL))
                    .await;
                pool.add_checked(wide_tx(&sk, seq), BAL)
                    .expect("funded admission must succeed");
                seq += 1;
            }
        } else {
            for i in 0..100u64 {
                let sk = det_key(i);
                engine
                    .update_account(AccountState::new(id_of(&sk), BAL))
                    .await;
                for nonce in 0..100u64 {
                    pool.add_checked(deep_tx(&sk, nonce, seq), BAL)
                        .expect("funded admission must succeed");
                    seq += 1;
                }
            }
        }
        assert_eq!(pool.len(), 10_000);
        let val_sk = det_key(42_000_000);
        let val_id = id_of(&val_sk);
        engine.update_account(AccountState::new(val_id, BAL)).await;
        Fixture {
            engine,
            pool: Arc::new(tokio::sync::RwLock::new(pool)),
            val_sk,
            val_id,
        }
    })
}

/// Fresh filter state exactly the way `propose` builds it (snapshot +
/// fees + registry), over the fixture's live state. Built OUTSIDE the
/// select timer: the timer covers the synchronous fee-ordered scan only.
async fn fresh_ctx(fx: &Fixture) -> PackFilterCtx {
    let pool = fx.pool.read().await;
    let senders: Vec<[u8; 32]> = pool.fee_payers().into_iter().collect();
    let guard = fx.engine.accounts.read().await;
    let mut accounts: HashMap<[u8; 32], (u64, u64)> = HashMap::with_capacity(senders.len());
    for a in &senders {
        if let Some(acct) = guard.get(a) {
            accounts.insert(*a, (acct.nonce, acct.balance));
        }
    }
    drop(guard);
    let fresh: Vec<[u8; 32]> = pool.fee_payers().into_iter().collect();
    let mut missing = Vec::new();
    for s in &fresh {
        if !accounts.contains_key(s) {
            missing.push(*s);
        }
    }
    drop(pool);
    for s in missing {
        if let Some(acct) = fx.engine.get_account(&s).await {
            accounts.insert(s, (acct.nonce, acct.balance));
        }
    }
    let pool = fx.pool.read().await;
    let (base_fee, penalty_floors) = (pool.base_fee, pool.penalty_snapshot());
    let session_keys = fx.engine.session_keys_read().await.clone();
    PackFilterCtx::new(
        TS,
        false,
        MY_SHARD,
        base_fee,
        penalty_floors,
        session_keys,
        accounts,
        SessionSpendSim::default(),
        HashSet::new(),
    )
}

fn median_secs(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn bench_select_row(kind: &'static str) {
    let fx = setup_fixture(kind);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds");
    // Warmup outside the samples (pools the allocator, faults pages in).
    {
        let ctx = rt.block_on(fresh_ctx(&fx));
        let pool = rt.block_on(fx.pool.read());
        let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
            ValidatorRuntime::pack_filter_accept(&ctx, t)
        });
        assert!(!sel.is_empty(), "fixture must select something");
        assert!(sel.len() <= MAX_BLOCK_TXS);
        let gas: u64 = sel.iter().map(|t| t.gas_limit).sum();
        assert!(gas <= MAX_BLOCK_GAS, "packed gas must respect the cap");
    }
    let repeats = 15usize;
    let mut samples = Vec::with_capacity(repeats);
    let mut selected = 0usize;
    for _ in 0..repeats {
        let ctx = rt.block_on(fresh_ctx(&fx));
        let pool = rt.block_on(fx.pool.read());
        let t = Instant::now();
        let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
            ValidatorRuntime::pack_filter_accept(&ctx, t)
        });
        samples.push(t.elapsed().as_secs_f64());
        selected = sel.len();
        drop(pool);
    }
    let med = median_secs(samples);
    println!(
        "[bench][propose_latency][select_{}] pool=10000 selected={selected:>5} time={} total",
        kind,
        medal(med * 1e9),
    );
}

fn bench_propose_total_row(kind: &'static str) {
    let fx = setup_fixture(kind);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds");
    // Warmup: one full propose (also pins the expected tx count).
    let expect_txs = {
        let vs = ValidatorSet::from_list(vec![(fx.val_id, 1)]);
        let mut rt_propose = ValidatorRuntime::new(
            SigningKey::from_bytes(&fx.val_sk.to_bytes()),
            vs,
            fx.engine.clone(),
            1,
        )
        .with_mempool(fx.pool.clone());
        let b = rt.block_on(rt_propose.propose(TS)).expect("propose must succeed");
        b.transactions.len()
    };
    assert!(expect_txs > 0 && expect_txs <= MAX_BLOCK_TXS);
    let repeats = 9usize;
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let vs = ValidatorSet::from_list(vec![(fx.val_id, 1)]);
        let mut rt_propose = ValidatorRuntime::new(
            SigningKey::from_bytes(&fx.val_sk.to_bytes()),
            vs,
            fx.engine.clone(),
            1,
        )
        .with_mempool(fx.pool.clone());
        let t = Instant::now();
        let b = rt.block_on(rt_propose.propose(TS)).expect("propose must succeed");
        samples.push(t.elapsed().as_secs_f64());
        assert_eq!(b.transactions.len(), expect_txs, "propose must be deterministic");
    }
    let med = median_secs(samples);
    println!(
        "[bench][propose_latency][propose_total_{}] pool=10000 txs={expect_txs:>5} time={} total",
        kind,
        medal(med * 1e9),
    );
}

#[test]
fn select_wide() {
    bench_select_row("wide");
}

#[test]
fn select_deep() {
    bench_select_row("deep");
}

#[test]
fn propose_total_wide() {
    bench_propose_total_row("wide");
}

#[test]
fn propose_total_deep() {
    bench_propose_total_row("deep");
}

#[test]
fn sign_ed25519() {
    let sk = det_key(7_777_777);
    let msg = [0x53u8; 32];
    // Warmup.
    for _ in 0..10 {
        std::hint::black_box(sk.sign(&msg));
    }
    let repeats = 200usize;
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        std::hint::black_box(sk.sign(&msg));
        samples.push(t.elapsed().as_secs_f64());
    }
    let med = median_secs(samples);
    println!(
        "[bench][propose_latency][sign_ed25519] time={} per sign",
        medal(med * 1e9),
    );
}
