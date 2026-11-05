//! PQ path end-to-end bench (M-06, measurement only).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench pq_end_to_end -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][pq-e2e]` lines.
//! REPORT, not a gate: correctness asserts only (signature verdicts,
//! pack/apply counts, envelope roundtrips) — a slow machine must still be
//! green. No timing asserts of any kind here.
//!
//! Rows mirror `tests/pq_end_to_end_tests.rs`: envelope sizes by scheme,
//! propose -> intake-verify -> apply on fully-PQ-signed blocks @100/428/1000
//! (pure-PQ enforced via `set_pure_pq_override`), and Falcon uQC sizes
//! @N=4/7/16/64 vs Ed25519 QC.

use std::hint::black_box;
use std::sync::Mutex;
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};

use stellereum::consensus::{
    encode_pq_micro_envelope, vote_sign_bytes, PQ_UQC_MARKER_ID, PqMicroCertificate,
    QuorumCertificate, ValidatorSet, VoteKind,
};
use stellereum::mempool::{Mempool, PQ_ACTIVATION_SURCHARGE_GAS};
use stellereum::post_quantum::{
    derive_pq_address, is_pure_pq_enforced, set_pure_pq_override, FalconKeypair, PqScheme,
    DEFAULT_SALT,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::GAS_BASIC_TRANSFER;

const TS: u64 = 9_000_000_007;
const BAL: u64 = 1_000_000_000_000;
const RECIPIENT: [u8; 32] = [9u8; 32];
const REPS: usize = 5;
const PQ_GAS: u64 = GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS;

static SERIAL: Mutex<()> = Mutex::new(());

struct PqGuard {
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl PqGuard {
    fn enforce() -> Self {
        let guard = SERIAL.lock().expect("pq-e2e-bench serial mutex poisoned");
        set_pure_pq_override(Some(true));
        assert!(is_pure_pq_enforced(), "pure-PQ override must be visible");
        Self { _serial: guard }
    }

    fn observe() -> Self {
        let guard = SERIAL.lock().expect("pq-e2e-bench serial mutex poisoned");
        set_pure_pq_override(None);
        Self { _serial: guard }
    }
}

impl Drop for PqGuard {
    fn drop(&mut self) {
        set_pure_pq_override(None);
    }
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

fn pq_seed(i: u64) -> [u8; 32] {
    let mut s = [0x51u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

fn skeleton_tx(from: [u8; 32]) -> Transaction {
    Transaction {
        from,
        to: RECIPIENT,
        amount: 1,
        gas_limit: PQ_GAS,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

fn build_pq_tx(i: u64) -> (Transaction, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed_bytes(&pq_seed(50_000 + i));
    let pk = kp.public_key.clone();
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let msg = skeleton_tx(from).signing_message();
    let sig = kp.sign_with_seed(&msg, &pq_seed(90_000 + i));
    let tx = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        RECIPIENT,
        1,
        PQ_GAS,
        0,
        1,
        1,
        Vec::new(),
        &DEFAULT_SALT,
    );
    assert!(tx.verify_signature());
    (tx, from)
}

async fn funded_engine(senders: &[[u8; 32]], val: [u8; 32]) -> std::sync::Arc<InMemoryStateEngine> {
    let e = std::sync::Arc::new(InMemoryStateEngine::new());
    e.update_account(AccountState::new(val, BAL)).await;
    for s in senders {
        e.update_account(AccountState::new(*s, BAL)).await;
    }
    e.update_account(AccountState::new(RECIPIENT, 0)).await;
    e
}

fn val_key() -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&42_000_000u64.to_le_bytes());
    SigningKey::from_bytes(&seed)
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
        .with_mempool(std::sync::Arc::new(tokio::sync::RwLock::new(pool)))
}

fn bench_row(n: usize) {
    let _guard = PqGuard::enforce();
    rt_block_on(async {
        let mut txs = Vec::with_capacity(n);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n as u64 {
            let (tx, from) = build_pq_tx(i);
            txs.push(tx);
            senders.push(from);
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

        let mut intake = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let t = Instant::now();
            let ok = Transaction::verify_signatures_batch_parallel(black_box(&txs));
            let d = ms(t.elapsed());
            assert!(ok);
            intake.push(d);
        }

        let val = val_key().verifying_key().to_bytes();
        let mut apply = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let e = funded_engine(&senders, val).await;
            let t = Instant::now();
            let out = e.apply_block_transition(black_box(&block), 0).await;
            let d = ms(t.elapsed());
            assert_eq!(out.applied, n);
            assert_eq!(out.failed, 0);
            apply.push(d);
        }

        let (propose_ms, intake_ms, apply_ms) = (median(propose), median(intake), median(apply));
        let total = propose_ms + intake_ms + apply_ms;
        let per_tx_ns = total * 1_000_000.0 / (n as f64);
        println!(
            "[bench][pq-e2e] n={n:>4} propose={propose_ms:8.2}ms intake={intake_ms:8.2}ms apply={apply_ms:8.2}ms TOTAL={total:8.2}ms per-tx={per_tx_ns:.0}ns (median-of-5, fully-PQ-signed)"
        );
    });
}

fn bench_qc_row(n: usize) {
    let _guard = PqGuard::observe();
    let mut vs = ValidatorSet::new();
    let mut fkeys: Vec<([u8; 32], FalconKeypair)> = Vec::with_capacity(n);
    for i in 0..n {
        let fk = FalconKeypair::generate_from_seed_bytes(&pq_seed(80_000 + n as u64 * 1000 + i as u64));
        let id = derive_pq_address(PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT);
        vs.add(id, 10);
        stellereum::consensus::register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());
        fkeys.push((id, fk));
    }
    let height = 42u64;
    let round = 1u32;
    let parent = [0x9u8; 32];
    let committee_size = stellereum::consensus::micro_committee_size(vs.len());
    assert_eq!(committee_size as usize, n);
    let committee =
        stellereum::consensus::derive_sortition_committee(&vs, height, round, committee_size, &parent);
    let kind = VoteKind::Precommit;
    let block_hash = Some([0xBBu8; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);
    let mut signatures = Vec::with_capacity(n);
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    for (i, val_id) in committee.iter().enumerate() {
        let (_, fk) = fkeys.iter().find(|(id, _)| id == val_id).expect("member key");
        signatures.push(fk.sign_with_seed(&msg, &pq_seed(88_000 + n as u64 * 1000 + i as u64)));
        bitmask[i / 8] |= 1 << (i % 8);
    }
    let uqc = PqMicroCertificate::new(
        PqScheme::Falcon512,
        height,
        round,
        committee_size,
        bitmask,
        signatures,
        parent,
    );
    let payload = encode_pq_micro_envelope(&uqc);
    let pq_qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, payload.clone())],
    };
    assert!(pq_qc.verify_unified(&vs));

    let mut cvs = ValidatorSet::new();
    let mut csigs = Vec::with_capacity(n);
    for i in 0..n {
        let mut seed = [i as u8; 32];
        seed[0] = seed[0].wrapping_add(n as u8);
        let sk = SigningKey::from_bytes(&seed);
        let id = sk.verifying_key().to_bytes();
        cvs.add(id, 10);
        csigs.push((id, sk.sign(&msg).to_bytes().to_vec()));
    }
    let cqc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: csigs,
    };
    assert!(cqc.verify_unified(&cvs));
    let cqc_bin = bincode::serialize(&cqc).expect("serialize").len();
    println!(
        "[bench][pq-e2e-qc] N={n:>2} falcon-uqc={}B ed-qc={cqc_bin}B falcon-per-signer={}B",
        payload.len(),
        payload.len() / n
    );
}

#[test]
fn pq_e2e_sizes() {
    let _guard = PqGuard::observe();
    let ed_tx = Transaction::sign(
        &SigningKey::from_bytes(&[0xA5u8; 32]),
        RECIPIENT,
        1,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
    );
    let (falcon_exp_tx, _) = build_pq_tx(7);
    let kp = FalconKeypair::generate_from_seed_bytes(&pq_seed(61_001));
    let pk = kp.public_key.clone();
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let msg = skeleton_tx(from).signing_message();
    let sig = kp.sign_with_seed(&msg, &pq_seed(61_002));
    let falcon_imp_tx =
        Transaction::new_pq_implicit(from, PqScheme::Falcon512, sig, RECIPIENT, 1, PQ_GAS, 0, 1, 1, Vec::new());
    println!(
        "[bench][pq-e2e-size] ed={}B falcon-implicit={}B falcon-explicit={}B hybrid-implicit=739B hybrid-explicit=1684B",
        ed_tx.signature.len(),
        falcon_imp_tx.signature.len(),
        falcon_exp_tx.signature.len()
    );
    assert_eq!(ed_tx.signature.len(), 64);
    assert_eq!(falcon_imp_tx.signature.len(), 3 + 1 + 1 + 2 + 2 + 666);
    assert_eq!(falcon_exp_tx.signature.len(), 3 + 1 + 1 + 2 + 897 + 16 + 2 + 666);
}

#[test]
fn pq_e2e_qc_4() {
    bench_qc_row(4);
}

#[test]
fn pq_e2e_qc_7() {
    bench_qc_row(7);
}

#[test]
fn pq_e2e_qc_16() {
    bench_qc_row(16);
}

#[test]
fn pq_e2e_qc_64() {
    bench_qc_row(64);
}

#[test]
fn pq_e2e_100() {
    bench_row(100);
}

#[test]
fn pq_e2e_428() {
    bench_row(428);
}

#[test]
fn pq_e2e_1000() {
    bench_row(1000);
}
