//! PQ path end-to-end measurement (M-06): numbers only.
//!
//! (1) tx envelope sizes by scheme (Ed25519 / Falcon-implicit /
//!     Falcon-explicit / Hybrid): measured bytes, REPORT table.
//! (2) block times @100/428/1000 tx FULLY-PQ-signed blocks through
//!     propose -> intake-verify -> apply, pure-PQ enforced in-test via
//!     `set_pure_pq_override` (the same thread-override idiom the PQ tests
//!     use); fixed fixtures, median-of-`REPS` per stage (the
//!     `cpu_budget_tests.rs` idiom); REPORT ms + per-tx ns.
//! (3) QC sizes @N=4/7/16/64 with Falcon (measured bytes, vs Ed25519 QC).
//! (4) verdict table vs the 0.6s program: headroom or gap, reported honestly.
//!
//! Method: deterministic seeds (no OsRng, no wall clock in fixtures),
//! correctness asserted (signature verdicts, pack/apply counts, envelope
//! roundtrips) but NO tight wall-clock asserts. The single time bound is a
//! generous hang guard (`BOUND_PQ_428_MS`, ~3 orders above the measured
//! release total); per-stage 0.6s-program comparisons are REPORTED only.
//! Falcon sizes (897/666) and envelope paths are READ here, never modified.

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
/// PQ explicit txs pay the activation surcharge on top of the basic transfer.
const PQ_GAS: u64 = GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS;
/// Generous hang guard only: fails on a blowup/hang, never a tight wall gate.
/// PQ Falcon verify is ~100x Ed25519, so this sits far above the 150ms
/// classical regression bound by design.
const BOUND_PQ_428_MS: f64 = 10_000.0;
/// The 0.6s/block program reference. REPORT comparisons only, never gated.
const PROGRAM_06S_MS: f64 = 600.0;

/// Serializes every test in this binary: the pure-PQ override is a
/// process-wide atomic in integration builds, and the implicit/validator key
/// registries are process-global, so tests must never interleave.
static SERIAL: Mutex<()> = Mutex::new(());

/// Holds `SERIAL` for the whole test and resets the pure-PQ override on drop
/// so a panicking assertion cannot leak enforcement into the next test.
struct PqGuard {
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl PqGuard {
    fn enforce() -> Self {
        let guard = SERIAL.lock().expect("pq-e2e serial mutex poisoned");
        set_pure_pq_override(Some(true));
        assert!(
            is_pure_pq_enforced(),
            "pure-PQ override must be visible on this thread"
        );
        Self { _serial: guard }
    }

    fn observe() -> Self {
        let guard = SERIAL.lock().expect("pq-e2e serial mutex poisoned");
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

/// Deterministic Falcon seed domain (block fixtures live at 50_000+).
fn pq_seed(i: u64) -> [u8; 32] {
    let mut s = [0x51u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

/// Deterministic Ed25519 seed domain (Hybrid ed halves live at 70_000+).
fn ed_seed(i: u64) -> [u8; 32] {
    let mut s = [0x5Au8; 32];
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

/// Fully-PQ-signed explicit Falcon-512 tx with deterministic key + signature.
/// Verifies standalone (explicit key travels in the envelope).
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
    assert!(tx.verify_signature(), "PQ fixture tx {i} must verify");
    assert!(tx.is_pq_activation(), "PQ fixture tx {i} must be explicit");
    (tx, from)
}

fn det_ed_key(i: u64) -> SigningKey {
    SigningKey::from_bytes(&ed_seed(i))
}

#[test]
fn pq_envelope_sizes_by_scheme() {
    let _guard = PqGuard::observe();

    // Falcon canonical sizes, pinned read-only (post_quantum.rs:109/115).
    assert_eq!(PqScheme::Falcon512.pubkey_size(), 897);
    assert_eq!(PqScheme::Falcon512.signature_size(), 666);
    assert_eq!(PqScheme::Hybrid.pubkey_size(), 929);
    assert_eq!(PqScheme::Hybrid.signature_size(), 730);

    // Ed25519 legacy: bare 64-byte signature, no PQ1 envelope.
    let ed_tx = Transaction::sign(&det_ed_key(1), RECIPIENT, 1, GAS_BASIC_TRANSFER, 0, 1, 1);
    assert!(!ed_tx.is_pq());
    let ed_sig_len = ed_tx.signature.len();
    assert_eq!(ed_sig_len, 64);

    // Falcon explicit.
    let (falcon_exp_tx, _) = build_pq_tx(1);
    let falcon_exp_len = falcon_exp_tx.signature.len();
    let falcon_exp_formula = 3 + 1 + 1 + 2 + 897 + 16 + 2 + 666;
    assert_eq!(falcon_exp_len, falcon_exp_formula);
    assert!(falcon_exp_tx.pq_envelope().is_some(), "envelope must roundtrip");

    // Falcon implicit (key omitted from the wire).
    let kp = FalconKeypair::generate_from_seed_bytes(&pq_seed(61_001));
    let pk = kp.public_key.clone();
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let msg = skeleton_tx(from).signing_message();
    let sig = kp.sign_with_seed(&msg, &pq_seed(61_002));
    let falcon_imp_tx =
        Transaction::new_pq_implicit(from, PqScheme::Falcon512, sig, RECIPIENT, 1, PQ_GAS, 0, 1, 1, Vec::new());
    let falcon_imp_len = falcon_imp_tx.signature.len();
    let falcon_imp_formula = 3 + 1 + 1 + 2 + 2 + 666;
    assert_eq!(falcon_imp_len, falcon_imp_formula);
    assert!(falcon_imp_tx.is_pq_implicit());
    assert!(falcon_imp_tx.pq_envelope().is_some(), "envelope must roundtrip");

    // Hybrid explicit: ed sig || falcon sig over the same message.
    let hed_sk = det_ed_key(71_001);
    let hkp = FalconKeypair::generate_from_seed_bytes(&pq_seed(71_002));
    let hybrid_pk = [hed_sk.verifying_key().to_bytes().as_slice(), hkp.public_key.as_slice()].concat();
    assert_eq!(hybrid_pk.len(), 929);
    let hfrom = derive_pq_address(PqScheme::Hybrid, &hybrid_pk, &DEFAULT_SALT);
    let hmsg = skeleton_tx(hfrom).signing_message();
    let mut hybrid_sig = hed_sk.sign(&hmsg).to_bytes().to_vec();
    hybrid_sig.extend_from_slice(&hkp.sign_with_seed(&hmsg, &pq_seed(71_003)));
    assert_eq!(hybrid_sig.len(), 730);
    let hybrid_exp_tx = Transaction::new_pq_explicit(
        PqScheme::Hybrid,
        hybrid_pk,
        hybrid_sig,
        RECIPIENT,
        1,
        PQ_GAS,
        0,
        1,
        1,
        Vec::new(),
        &DEFAULT_SALT,
    );
    assert!(hybrid_exp_tx.verify_signature(), "Hybrid fixture must verify");
    let hybrid_exp_len = hybrid_exp_tx.signature.len();
    let hybrid_exp_formula = 3 + 1 + 1 + 2 + 929 + 16 + 2 + 730;
    assert_eq!(hybrid_exp_len, hybrid_exp_formula);

    // Hybrid implicit: formula only (no registry roundtrip needed for a size).
    let hybrid_imp_formula = 3 + 1 + 1 + 2 + 2 + 730;

    println!("scheme              | sig-wire bytes");
    println!("Ed25519 legacy      | {ed_sig_len:>14}");
    println!("Falcon-512 implicit | {falcon_imp_len:>14}");
    println!("Falcon-512 explicit | {falcon_exp_len:>14}");
    println!("Hybrid implicit     | {hybrid_imp_formula:>14} (formula, key omitted)");
    println!("Hybrid explicit     | {hybrid_exp_len:>14}");
    println!(
        "explicit overhead vs legacy: Falcon +{} B, Hybrid +{} B",
        falcon_exp_len - ed_sig_len,
        hybrid_exp_len - ed_sig_len
    );
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

struct PqRow {
    propose_ms: f64,
    intake_ms: f64,
    apply_ms: f64,
    total_ms: f64,
}

async fn measure_pq_n(txs: &[Transaction], senders: &[[u8; 32]]) -> PqRow {
    let n = txs.len();
    assert!(is_pure_pq_enforced(), "PQ block timing must run under pure-PQ");

    let mut propose = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let mut rt = runtime_with_txs(txs, senders).await;
        let t = Instant::now();
        let block = rt.propose(TS).await.expect("pool must propose");
        let d = ms(t.elapsed());
        assert_eq!(block.transactions.len(), n, "propose must pack all {n}");
        assert!(
            block.transactions.iter().all(|t| t.is_pq()),
            "every packed tx must be PQ"
        );
        black_box(block);
        propose.push(d);
    }

    let mut rt = runtime_with_txs(txs, senders).await;
    let block = rt.propose(TS).await.expect("pool must propose");

    let mut intake = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let t = Instant::now();
        let ok = Transaction::verify_signatures_batch_parallel(black_box(txs));
        let d = ms(t.elapsed());
        assert!(ok, "PQ fixture signatures must verify");
        intake.push(d);
    }

    let val = val_key().verifying_key().to_bytes();
    let mut apply = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let e = funded_engine(senders, val).await;
        let t = Instant::now();
        let out = e.apply_block_transition(black_box(&block), 0).await;
        let d = ms(t.elapsed());
        assert_eq!(out.applied, n, "apply must apply all {n}");
        assert_eq!(out.failed, 0, "apply must fail none");
        apply.push(d);
    }

    let row = PqRow {
        propose_ms: median(propose),
        intake_ms: median(intake),
        apply_ms: median(apply),
        total_ms: 0.0,
    };
    let total = row.propose_ms + row.intake_ms + row.apply_ms;
    PqRow { total_ms: total, ..row }
}

#[tokio::test]
async fn pq_block_times_propose_verify_apply() {
    let _guard = PqGuard::enforce();

    // Shared fixtures (keygen/sign untimed): 1000 distinct PQ senders.
    let t_fix = Instant::now();
    let mut txs_all = Vec::with_capacity(1000);
    let mut senders_all = Vec::with_capacity(1000);
    for i in 0..1000u64 {
        let (tx, from) = build_pq_tx(i);
        txs_all.push(tx);
        senders_all.push(from);
    }
    println!("pq fixture build (1000 keygen+sign, untimed): {:.2}ms", ms(t_fix.elapsed()));

    let mut rows = Vec::new();
    for n in [100usize, 428, 1000] {
        rows.push(measure_pq_n(&txs_all[..n], &senders_all[..n]).await);
    }
    println!("stage            |   N=100 |   N=428 |  N=1000  (median-of-5 ms, fully-PQ-signed)");
    let cell = |v: f64| format!("{v:8.2}");
    let line = |name: &str, f: fn(&PqRow) -> f64| {
        format!(
            "{name:16} | {} | {} | {}",
            cell(f(&rows[0])),
            cell(f(&rows[1])),
            cell(f(&rows[2]))
        )
    };
    println!("{}", line("propose-build   ", |r| r.propose_ms));
    println!("{}", line("intake-verify   ", |r| r.intake_ms));
    println!("{}", line("apply           ", |r| r.apply_ms));
    println!("{}", line("TOTAL           ", |r| r.total_ms));
    for (k, n) in [100usize, 428, 1000].iter().enumerate() {
        let per_tx_ns = rows[k].total_ms * 1_000_000.0 / (*n as f64);
        println!("per-tx @N={n:<4} = {per_tx_ns:.0} ns (TOTAL {:.2}ms / {n})", rows[k].total_ms);
    }
    let r428 = &rows[1];
    let headroom = PROGRAM_06S_MS - r428.total_ms;
    if headroom >= 0.0 {
        println!(
            "BUDGET-VERDICT: TOTAL@428 = {:.2}ms vs 600ms program -> HEADROOM {headroom:.2}ms",
            r428.total_ms
        );
    } else {
        println!(
            "BUDGET-VERDICT: TOTAL@428 = {:.2}ms vs 600ms program -> OVER by {:.2}ms (FINDING: PQ path exceeds 0.6s @428)",
            r428.total_ms,
            -headroom
        );
    }
    for (k, n) in [100usize, 428, 1000].iter().enumerate() {
        let verdict = if rows[k].total_ms <= PROGRAM_06S_MS {
            "within 0.6s"
        } else {
            "OVER 0.6s (finding)"
        };
        println!("N={n:<4} TOTAL {:.2}ms -> {verdict}", rows[k].total_ms);
    }
    // Hang guard only: fails on a blowup/hang, never a tight wall gate.
    assert!(
        r428.total_ms <= BOUND_PQ_428_MS,
        "PQ hang guard tripped: TOTAL@428 {:.2}ms > {:.2}ms",
        r428.total_ms,
        BOUND_PQ_428_MS
    );
}

#[test]
fn pq_qc_sizes_vs_classical() {
    let _guard = PqGuard::observe();

    println!("qc @N          | Falcon-uQC env B | Falcon QC bincode B | Ed25519 QC bincode B | Falcon/signer B");
    for n in [4usize, 7, 16, 64] {
        // Falcon µQC: N validators, whole-set committee (min(N,64) == N),
        // every member signs with a genuine Falcon key.
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
        assert_eq!(committee_size as usize, n, "committee must be the whole set for N<=64");
        let committee =
            stellereum::consensus::derive_sortition_committee(&vs, height, round, committee_size, &parent);
        assert_eq!(committee.len(), n);
        let kind = VoteKind::Precommit;
        let block_hash = Some([0xBBu8; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);
        let mut signatures = Vec::with_capacity(n);
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        for (i, val_id) in committee.iter().enumerate() {
            let (_, fk) = fkeys.iter().find(|(id, _)| id == val_id).expect("committee member must have a key");
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
        // Deterministic envelope formula: 73 B header + bitmask + N*(4+666).
        let bitmask_len = (committee_size as usize).div_ceil(8);
        let formula = 73 + bitmask_len + n * (4 + 666);
        assert_eq!(payload.len(), formula, "uQC envelope must match the pinned formula");
        let pq_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, payload.clone())],
        };
        assert!(pq_qc.verify_unified(&vs), "Falcon uQC @N={n} must verify");
        assert!(pq_qc.verify(&vs), "Falcon uQC @N={n} must pass verify()");
        let pq_qc_bin = bincode::serialize(&pq_qc).expect("QC must serialize").len();

        // Classical Ed25519 QC: N voters x (32 B id + 64 B sig).
        let mut cvs = ValidatorSet::new();
        let mut csigs = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [i as u8; 32];
            seed[0] = seed[0].wrapping_add(n as u8);
            let sk = SigningKey::from_bytes(&seed);
            let id = sk.verifying_key().to_bytes();
            cvs.add(id, 10);
            let sig = sk.sign(&msg).to_bytes().to_vec();
            csigs.push((id, sig));
        }
        let cqc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: csigs,
        };
        assert!(cqc.verify_unified(&cvs), "classical QC @N={n} must verify");
        let cqc_bin = bincode::serialize(&cqc).expect("QC must serialize").len();

        println!(
            "N={n:<4}        | {:>15} | {:>19} | {:>20} | {:>15}",
            payload.len(),
            pq_qc_bin,
            cqc_bin,
            payload.len() / n
        );
    }
}
