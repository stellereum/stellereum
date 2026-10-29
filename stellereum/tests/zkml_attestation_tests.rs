//! §2 zkML, ATTESTATION half: PQ-STARK-BLAKE3 (`STELLEREUM_PQ_STARK_BLAKE3_V1`)
//! trace attestations on the live block path (Groth16/arkworks were replaced;
//! there is no succinct ZK here — see `zkml_capabilities()`).
//!
//! Companion to `tests/zkml_live_tests.rs` (the re-execution half). What this
//! file pins end to end:
//!
//! * off-chain setup (`snark::model_spec_test_only`, deterministic) -> on-chain VK
//!   attach (`SysCallRegisterZkMlSpec`, discriminant 37) -> off-chain prove
//!   (`snark::prove_attestation`) -> on-chain verify
//!   (`SysCallVerifyZkMlAttestation`, discriminant 38);
//! * the verify handler's binding checks (model hash, VK hash, I/O shape,
//!   input range) and its cryptographic core (BLAKE3 Merkle-trace recompute,
//!   NOT `ark_groth16::verify`);
//! * the constrained-format gate (i8 weights / u16 inputs / bounded
//!   accumulator): legacy unbounded models keep the re-execution path but
//!   are refused a VK;
//! * ceremony honesty: test-only deterministic setup is marked as such, a
//!   tampered VK fails, an empty attestation is refused;
//! * the same consensus properties as the re-execution half: clone-commit,
//!   two-node determinism, conditional commitment (version stays 4, genesis
//!   KAT green), appended discriminants, gas metering.
//!
//! What is deliberately NOT asserted: wall-clock proving/verifying times
//! (machine-dependent; `benches/zkml_snark.rs` REPORTS them, and the
//! measurement test below prints them with `--nocapture`).

use ed25519_dalek::SigningKey;
use stellereum::commitment::{
    commitment_digest, commitment_digest_with_zkml, zkml_vks_digest, COMMITMENT_VERSION,
};
use stellereum::mempool::Mempool;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    attestation_verify_gas, opcode_gas, spec_register_gas, OpCode,
    GAS_ATTESTATION_PER_PUBLIC_INPUT, GAS_ATTESTATION_VERIFY_BASE, GAS_ZKML_PROOF_PER_BYTE,
    GAS_ZKML_REEXEC_PER_PARAM, GAS_ZKML_SPEC_PER_BYTE, GAS_ZKML_SPEC_REGISTER_BASE,
};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, ZkMlProof};
use stellereum::zkml_attestation::{
    model_spec_test_only, model_spec_with_attestation, prove_attestation, verify_attestation,
    AttestationProof, ModelSpec, ATTEST_MAX_INPUT, ATTEST_PROOF_BYTES, TEST_SETUP_ATTESTATION,
};

const BLOCK_TS: u64 = 1_760_000_000;
const GAS: u64 = 5_000_000;
const ATTEST_TEST_SEED: u64 = 0x534E41524B;
const MODEL_A: [u8; 32] = [0x51; 32];
const MODEL_B: [u8; 32] = [0x52; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Same fixture as the re-execution tests: [3,4] -> [11,7]. Weights fit i8,
/// inputs fit u16, worst-case accumulator is tiny: this model IS
/// SNARK-compatible (the common case must stay provable).
fn tiny_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
}

fn other_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![1, 1, 1, 1],
        vec![0, 0],
    )])
}

/// Legacy-format model: unbounded i64 weights. Registers and re-executes
/// fine (old format keeps working), but is NOT SNARK-compatible.
fn legacy_big_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![1_000_000_000_000, -1, 1, 3],
        vec![1, -2],
    )])
}

async fn funded() -> (InMemoryStateEngine, SigningKey, [u8; 32]) {
    let e = InMemoryStateEngine::new();
    let sk = key(0x71);
    let addr = sk.verifying_key().to_bytes();
    e.update_account(AccountState::new(addr, 1_000_000_000_000))
        .await;
    (e, sk, addr)
}

fn register_model_tx(
    sk: &SigningKey,
    to: [u8; 32],
    nonce: u64,
    id: [u8; 32],
    m: &QuantizedLinearModel,
) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        to,
        0,
        GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallRegisterZkMlModel {
            model_id: id,
            model: Box::new(m.clone()),
        }],
    )
}

fn register_vk_tx(
    sk: &SigningKey,
    to: [u8; 32],
    nonce: u64,
    id: [u8; 32],
    vk: &ModelSpec,
) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        to,
        0,
        GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallRegisterZkMlSpec {
            model_id: id,
            spec: Box::new(vk.clone()),
        }],
    )
}

fn verify_snark_tx(
    sk: &SigningKey,
    to: [u8; 32],
    nonce: u64,
    id: [u8; 32],
    p: &AttestationProof,
) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        to,
        0,
        GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallVerifyZkMlAttestation {
            model_id: id,
            proof: Box::new(p.clone()),
        }],
    )
}

/// Production setup for tests that register on-chain (F2: test-prefixed
/// attestations are deterministically refused by consensus, so on-chain
/// tests must use a production attestation; proving keys stay local).
fn test_setup(m: &QuantizedLinearModel, seed: u64) -> (Vec<u8>, ModelSpec) {
    let _ = seed;
    model_spec_with_attestation(&m.attestation_view(), b"test-harness-production".to_vec())
        .expect("production setup must succeed for compatible model")
}

/// Register model + VK on the engine; returns proving key bytes + VK.
async fn register_model_and_vk(
    e: &InMemoryStateEngine,
    sk: &SigningKey,
    addr: [u8; 32],
    id: [u8; 32],
    m: &QuantizedLinearModel,
    seed: u64,
    nonce0: u64,
) -> (Vec<u8>, ModelSpec) {
    let (pk_bytes, vk) = test_setup(m, seed);
    let rtx = register_model_tx(sk, addr, nonce0, id, m);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (1, 0), "model registration must apply");
    let vtx = register_vk_tx(sk, addr, nonce0 + 1, id, &vk);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (1, 0), "VK registration must apply");
    (pk_bytes, vk)
}

fn prove_for(
    m: &QuantizedLinearModel,
    inputs: &[i64],
    pk: &[u8],
    vk: &ModelSpec,
) -> (Vec<i64>, AttestationProof) {
    prove_attestation(
        &m.attestation_view(),
        m.compute_model_hash(),
        inputs,
        pk,
        vk.spec_hash,
    )
    .expect("honest prove must succeed")
}

// ---------------------------------------------------------------------------
// 1. Honest proof verifies end to end; sizes + constraint count reported.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_honest_proof_verifies_end_to_end() {
    let m = tiny_model();
    assert!(m.is_attestation_compatible());
    let (e, sk, addr) = funded().await;
    let (pk_bytes, vk) =
        register_model_and_vk(&e, &sk, addr, MODEL_A, &m, ATTEST_TEST_SEED, 0).await;

    let (out, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    assert_eq!(
        out,
        vec![11, 7],
        "SNARK outputs must match the forward pass"
    );
    assert!(
        !proof.proof_bytes.is_empty()
            && proof.proof_bytes.len() <= stellereum::zkml_attestation::MAX_ATTESTATION_PROOF_BYTES
    );
    assert!(
        verify_attestation(&vk.spec_bytes, &proof),
        "must verify off chain"
    );

    let vtx = verify_snark_tx(&sk, addr, 2, MODEL_A, &proof);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (1, 0),
        "honest SNARK proof must apply on the live path"
    );
    assert_eq!(s, vec![true]);
}

#[test]
fn snark_ref_model_measurements() {
    use stellereum::zkml_attestation::InferenceCostModel;
    let m = tiny_model();
    let view = m.attestation_view();
    let n = InferenceCostModel::constraint_count_for(&view).expect("countable");
    println!("[measure][snark] ref model constraints: {n}");
    assert!(
        n > 0 && n < 100_000,
        "ref model must be a small circuit, got {n}"
    );

    let t0 = std::time::Instant::now();
    let (pk_bytes, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let setup_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t0 = std::time::Instant::now();
    let (out, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(out, vec![11, 7]);

    let t0 = std::time::Instant::now();
    assert!(verify_attestation(&vk.spec_bytes, &proof));
    let verify_ms = t0.elapsed().as_secs_f64() * 1000.0;

    println!(
        "[measure][snark] setup={setup_ms:.1}ms prove={prove_ms:.1}ms verify={verify_ms:.3}ms \
         proof_bytes={} spec_bytes={} pk_bytes={} n_public={}",
        proof.proof_bytes.len(),
        vk.spec_bytes.len(),
        pk_bytes.len(),
        vk.n_public_inputs,
    );
    assert!(
        !proof.proof_bytes.is_empty()
            && proof.proof_bytes.len() <= stellereum::zkml_attestation::MAX_ATTESTATION_PROOF_BYTES
    );
}

// ---------------------------------------------------------------------------
// 2. Forged traces rejected by the SNARK path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_forged_trace_proof_rejected() {
    let m = tiny_model();
    let (e, sk, addr) = funded().await;
    let (pk_bytes, vk) =
        register_model_and_vk(&e, &sk, addr, MODEL_A, &m, ATTEST_TEST_SEED, 0).await;

    // (a) The legacy forgery (ReLU-consistent invented trace, lying outputs)
    // repackaged as SNARK proof bytes: not even parseable as Groth16.
    let forged_legacy = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[999, 999]);
    let bogus = AttestationProof {
        model_hash: m.compute_model_hash(),
        spec_hash: vk.spec_hash,
        public_inputs: vec![3, 4],
        public_outputs: vec![999, 999],
        proof_bytes: forged_legacy.proof_bytes.clone(),
    };
    assert!(!verify_attestation(&vk.spec_bytes, &bogus));
    let vtx = verify_snark_tx(&sk, addr, 2, MODEL_A, &bogus);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "legacy-forgery bytes must NOT apply as a SNARK proof"
    );
    assert_eq!(s, vec![false]);

    // (b) A REAL proof with a tampered claimed output: the pairing check
    // fails (this is the forgery the soundness rests on). Nonce stays 2:
    // the bogus verify above reverted without advancing it.
    let (_, mut proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    proof.public_outputs[0] = 999;
    assert!(!verify_attestation(&vk.spec_bytes, &proof));
    let vtx = verify_snark_tx(&sk, addr, 2, MODEL_A, &proof);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "tampered outputs must NOT apply");
    assert_eq!(s, vec![false]);

    // (c) A real proof for DIFFERENT inputs is valid for THOSE inputs (the
    // statement is what it is), but mutating its inputs post-prove voids it.
    let (_, mut proof2) = prove_for(&m, &[5, 6], &pk_bytes, &vk);
    assert!(verify_attestation(&vk.spec_bytes, &proof2));
    proof2.public_inputs[0] = 3;
    assert!(!verify_attestation(&vk.spec_bytes, &proof2));
}

// ---------------------------------------------------------------------------
// 3. Wrong model / VK / shape / input rejected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_wrong_model_vk_shape_input_rejected() {
    let m = tiny_model();
    let other = other_model();
    let (e, sk, addr) = funded().await;
    let (pk_a, vk_a) = register_model_and_vk(&e, &sk, addr, MODEL_A, &m, ATTEST_TEST_SEED, 0).await;
    let (pk_b, vk_b) = test_setup(&other, ATTEST_TEST_SEED + 1);
    // Register `other` under MODEL_B (with its own VK) for cross-checks.
    {
        let rtx = register_model_tx(&sk, addr, 2, MODEL_B, &other);
        assert_eq!(
            e.apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
                .await
                .0,
            1
        );
        let vtx = register_vk_tx(&sk, addr, 3, MODEL_B, &vk_b);
        assert_eq!(
            e.apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
                .await
                .0,
            1
        );
    }

    // F-01 (fail-closed fee floor): admitted txs that FAIL at apply now PAY
    // the failure fee (and consume nonce) instead of failing free. The fee is
    // `max(declared gas limit, consensus floor)`: the DECLARED limit binds
    // here (GAS = 5_000_000) unless the D2 penalty floor is higher. The floor
    // itself is the D2 penalty mirror (`Mempool::effective_floor_for_tx` with
    // governed base 0 and no PQ surcharge): 0 for the first failure, then one
    // step per failed block, cleared by a success. Paid failures therefore
    // advance the nonce, so each failing verify below uses the current head
    // nonce (a stale nonce would fail on the nonce gate instead of the SNARK
    // check under test). Every failure must still NOT APPLY (a==0); the fee
    // assertions pin the economics (fee == max(declared, floor), balance delta
    // == that fee, nonce advanced by one, root moved by the fee debit).
    let mut floor_mirror = Mempool::new(10_000, 256);
    // Mirror the four registering successes (penalty stays 0, but keep the
    // mirror in lockstep with the engine's success-clear rule).
    for _ in 0..4 {
        floor_mirror.note_apply_feedback(&[], &[addr]);
    }
    let mut nonce = 4u64;
    assert_eq!(
        e.get_account(&addr).await.unwrap().nonce,
        4,
        "MODEL_A (0,1) + MODEL_B (2,3) applied, nonce must be 4"
    );
    // Proof for `other` (valid under vk_b) presented under MODEL_A: both
    // registry bindings refuse it.
    let (_, proof_b) = prove_for(&other, &[3, 4], &pk_b, &vk_b);
    assert!(verify_attestation(&vk_b.spec_bytes, &proof_b));
    let vtx = verify_snark_tx(&sk, addr, nonce, MODEL_A, &proof_b);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "proof for another model must NOT apply under MODEL_A"
    );
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
    floor_mirror.note_apply_feedback(&[addr], &[]);
    nonce = e.get_account(&addr).await.unwrap().nonce;

    // Honest proof for A, but the VK hash field is swapped to B's.
    let (_, mut proof_a) = prove_for(&m, &[3, 4], &pk_a, &vk_a);
    proof_a.spec_hash = vk_b.spec_hash;
    let vtx = verify_snark_tx(&sk, addr, nonce, MODEL_A, &proof_a);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "wrong VK hash must NOT apply");
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
    floor_mirror.note_apply_feedback(&[addr], &[]);
    nonce = e.get_account(&addr).await.unwrap().nonce;

    // Honest proof, wrong model hash claim.
    let (_, mut proof_a2) = prove_for(&m, &[3, 4], &pk_a, &vk_a);
    proof_a2.model_hash = other.compute_model_hash();
    let vtx = verify_snark_tx(&sk, addr, nonce, MODEL_A, &proof_a2);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "wrong model hash must NOT apply");
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
    floor_mirror.note_apply_feedback(&[addr], &[]);
    nonce = e.get_account(&addr).await.unwrap().nonce;

    // Shape mismatch: truncated outputs.
    let (_, mut proof_a3) = prove_for(&m, &[3, 4], &pk_a, &vk_a);
    proof_a3.public_outputs.pop();
    let vtx = verify_snark_tx(&sk, addr, nonce, MODEL_A, &proof_a3);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "shape mismatch must NOT apply");
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
    floor_mirror.note_apply_feedback(&[addr], &[]);
    nonce = e.get_account(&addr).await.unwrap().nonce;

    // Input outside u16: refused with a named error before pairing.
    let (_, mut proof_a4) = prove_for(&m, &[3, 4], &pk_a, &vk_a);
    proof_a4.public_inputs[0] = ATTEST_MAX_INPUT + 1;
    let vtx = verify_snark_tx(&sk, addr, nonce, MODEL_A, &proof_a4);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "out-of-range input must NOT apply");
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
    floor_mirror.note_apply_feedback(&[addr], &[]);
    nonce = e.get_account(&addr).await.unwrap().nonce;

    // No VK registered: verify under an id whose model has none. The model
    // registration below is a success (pays GAS, clears the D2 penalty), so
    // the two failing verifies after it start again from floor 0.
    let no_vk_id = [0x53; 32];
    let rtx = register_model_tx(&sk, addr, nonce, no_vk_id, &m);
    let expected_floor = floor_mirror.effective_floor_for_tx(&rtx);
    assert!(
        GAS >= expected_floor,
        "registration declares above the floor"
    );
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (1, 0), "model registration must apply");
    assert_eq!(s, vec![true]);
    assert_eq!(
        fees,
        vec![GAS],
        "success pays the declared gas (floor does not bind here)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - GAS,
        "success balance delta == declared gas"
    );
    assert_eq!(acct.nonce, nonce + 1);
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "registration is committed"
    );
    floor_mirror.note_apply_feedback(&[], &[addr]);
    nonce = acct.nonce;
    let (_, proof_nvk) = prove_for(&m, &[3, 4], &pk_a, &vk_a);
    let vtx = verify_snark_tx(&sk, addr, nonce, no_vk_id, &proof_nvk);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "verify without a registered VK must NOT apply"
    );
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
    floor_mirror.note_apply_feedback(&[addr], &[]);
    nonce = e.get_account(&addr).await.unwrap().nonce;

    // Unknown model id.
    let vtx = verify_snark_tx(&sk, addr, nonce, [0x99; 32], &proof_nvk);
    let expected_floor = floor_mirror.effective_floor_for_tx(&vtx);
    // PINNED POLICY (SEC-07 / F-01): the failure fee is
    // `max(declared gas limit, consensus floor)` - the DECLARED limit binds
    // unless the D2 penalty floor is higher. A failure is NEVER free.
    let expected_fee = GAS.max(expected_floor);
    let bal_before = e.get_account(&addr).await.unwrap().balance;
    let nonce_before = e.get_account(&addr).await.unwrap().nonce;
    let root_before = e.get_state_root().await;
    let (a, f, _, s, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "unknown model must NOT apply");
    assert_eq!(s, vec![false]);
    assert_eq!(
        fees,
        vec![expected_fee],
        "failed tx must pay max(declared, floor)"
    );
    let acct = e.get_account(&addr).await.unwrap();
    assert_eq!(
        acct.balance,
        bal_before - expected_fee,
        "balance delta == the failure fee"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "a paid failure consumes its nonce"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a paid failure moves root via fee"
    );
}

// ---------------------------------------------------------------------------
// 4. Tampered VK rejected (registration AND verification).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_tampered_vk_rejected() {
    let m = tiny_model();
    let (_, honest_vk) = test_setup(&m, ATTEST_TEST_SEED);

    // (a) Flip a byte, recompute the hash (attacker re-binds): the bytes no
    // longer parse as a verifying key -> registration refuses.
    let mut tampered = honest_vk.clone();
    tampered.spec_bytes[10] ^= 0xFF;
    tampered.spec_hash = stellereum::zkml_attestation::spec_hash_of(&tampered.spec_bytes);
    assert!(stellereum::zkml::ZkMlModelRegistry::default()
        .models
        .is_empty());
    {
        let mut reg = stellereum::zkml::ZkMlModelRegistry::default();
        reg.register(MODEL_A, m.clone()).unwrap();
        assert!(reg.register_spec(MODEL_A, tampered.clone()).is_err());
        // And the crypto core refuses it too.
        let (_, proof) = prove_for(
            &m,
            &[3, 4],
            &model_spec_test_only(&m.attestation_view(), ATTEST_TEST_SEED)
                .unwrap()
                .0,
            &honest_vk,
        );
        assert!(!verify_attestation(&tampered.spec_bytes, &proof));
    }

    // (b) Flip a byte, keep the original hash: hash mismatch -> refused.
    let mut mismatched = honest_vk.clone();
    mismatched.spec_bytes[20] ^= 0x01;
    {
        let mut reg = stellereum::zkml::ZkMlModelRegistry::default();
        reg.register(MODEL_A, m.clone()).unwrap();
        assert!(reg.register_spec(MODEL_A, mismatched).is_err());
    }

    // (c) Tampered PROOF byte with a valid hash binding: pairing fails.
    let (e, sk, addr) = funded().await;
    let (pk_bytes, vk) =
        register_model_and_vk(&e, &sk, addr, MODEL_A, &m, ATTEST_TEST_SEED, 0).await;
    let (_, mut proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    proof.proof_bytes[0] ^= 0x01;
    assert!(!verify_attestation(&vk.spec_bytes, &proof));
    let vtx = verify_snark_tx(&sk, addr, 2, MODEL_A, &proof);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "tampered proof bytes must NOT apply");
    assert_eq!(s, vec![false]);

    // (d) Empty attestation refused at registration (ceremony honesty: every
    // key carries its setup story).
    let mut no_att = honest_vk.clone();
    no_att.setup_attestation = vec![];
    {
        let mut reg = stellereum::zkml::ZkMlModelRegistry::default();
        reg.register(MODEL_A, m.clone()).unwrap();
        assert!(reg.register_spec(MODEL_A, no_att).is_err());
    }
    // The helper now produces production attestations (F2: test-prefixed
    // keys are refused on-chain, so on-chain tests must not use them).
    assert!(
        !honest_vk
            .setup_attestation
            .starts_with(TEST_SETUP_ATTESTATION),
        "on-chain test VKs must carry production attestations"
    );
}

// ---------------------------------------------------------------------------
// 5. Registry rules: append-only VK, unknown id, clone-commit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_vk_registry_is_append_only_and_clone_committed() {
    let m = tiny_model();
    let (e, sk, addr) = funded().await;
    let (_, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (_, vk_other_seed) = test_setup(&m, ATTEST_TEST_SEED + 77);

    // Nonces advance on EVERY applied-or-refused transaction: a reverted
    // payload is an ATTRIBUTABLE failure (SEC-07), so it pays the failure fee
    // and CONSUMES ITS NONCE. Every transaction below is therefore signed with
    // the CURRENT head nonce; getting this wrong would fail txs on the nonce
    // gate instead of the SNARK check under test.
    // VK for an unknown id reverts (and burns nonce 0 -> the nonce is 1).
    let vtx = register_vk_tx(&sk, addr, 0, MODEL_A, &vk);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "VK for unknown model must revert");
    assert_eq!(e.get_account(&addr).await.unwrap().nonce, 1);

    // Register model, then VK: applies (nonces 1, 2).
    let rtx = register_model_tx(&sk, addr, 1, MODEL_A, &m);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
            .await
            .0,
        1
    );
    let vtx = register_vk_tx(&sk, addr, 2, MODEL_A, &vk);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
            .await
            .0,
        1
    );

    // Second VK under the same id reverts (first writer wins - no rebinding
    // the weights a proof is checked against; the refusal burns nonce 3).
    let vtx2 = register_vk_tx(&sk, addr, 3, MODEL_A, &vk_other_seed);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx2), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "re-registering a VK must revert (append-only)"
    );
    assert_eq!(s, vec![false]);
    assert_eq!(e.get_account(&addr).await.unwrap().nonce, 4);
    assert_eq!(
        e.zkml_models_read()
            .await
            .get(&MODEL_A)
            .unwrap()
            .spec
            .as_ref()
            .unwrap(),
        &vk
    );

    // Clone-commit: a VK registration in a transaction that later reverts
    // leaves nothing behind. Payload = [register VK under MODEL_B's model,
    // ...] - build directly: register MODEL_B + its VK, then a failing
    // SNARK verify in the same payload.
    let rtx_b = register_model_tx(&sk, addr, 4, MODEL_B, &m);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&rtx_b), BLOCK_TS)
            .await
            .0,
        1
    );
    let (_, vk_b) = test_setup(&m, ATTEST_TEST_SEED + 5);
    let (_, proof_for_b) = {
        let (pk_b, _) = test_setup(&m, ATTEST_TEST_SEED + 5);
        prove_for(&m, &[3, 4], &pk_b, &vk_b)
    };
    let mut bad_proof = proof_for_b.clone();
    bad_proof.public_outputs[1] = 123456; // void it
    let both = Transaction::sign_with_payload(
        &sk,
        addr,
        0,
        GAS,
        5,
        1,
        1,
        vec![
            OpCode::SysCallRegisterZkMlSpec {
                model_id: MODEL_B,
                spec: Box::new(vk_b),
            },
            OpCode::SysCallVerifyZkMlAttestation {
                model_id: MODEL_B,
                proof: Box::new(bad_proof),
            },
        ],
    );
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&both), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "the void verify reverts the whole tx");
    assert_eq!(s, vec![false]);
    assert!(
        e.zkml_models_read()
            .await
            .get(&MODEL_B)
            .unwrap()
            .spec
            .is_none(),
        "revert discards the VK registration"
    );
}

// ---------------------------------------------------------------------------
// 6. Gas: schedule shape + exhaustion reverts.
// ---------------------------------------------------------------------------

#[test]
fn snark_gas_schedule_shape() {
    let m = tiny_model();
    let (_, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (_, proof) = prove_for(&m, &[3, 4], &test_setup(&m, ATTEST_TEST_SEED).0, &vk);
    let n = proof.public_inputs.len() + proof.public_outputs.len();
    let op = OpCode::SysCallVerifyZkMlAttestation {
        model_id: MODEL_A,
        proof: Box::new(proof.clone()),
    };
    let want = GAS_ATTESTATION_VERIFY_BASE
        + (n as u64) * GAS_ATTESTATION_PER_PUBLIC_INPUT
        + (proof.wire_len() as u64) * GAS_ZKML_PROOF_PER_BYTE;
    assert_eq!(
        opcode_gas(&op),
        want,
        "verify gas = base + inputs + wire bytes"
    );
    assert_eq!(opcode_gas(&op), attestation_verify_gas(n, proof.wire_len()));

    // A bigger statement costs more than a small one.
    let big = AttestationProof {
        model_hash: proof.model_hash,
        spec_hash: proof.spec_hash,
        public_inputs: vec![1; 64],
        public_outputs: vec![2; 64],
        proof_bytes: vec![0u8; ATTEST_PROOF_BYTES],
    };
    let big_op = OpCode::SysCallVerifyZkMlAttestation {
        model_id: MODEL_A,
        proof: Box::new(big),
    };
    assert!(opcode_gas(&big_op) > opcode_gas(&op));

    // VK registration scales with the bytes stored.
    let rsmall = OpCode::SysCallRegisterZkMlSpec {
        model_id: MODEL_A,
        spec: Box::new(vk.clone()),
    };
    assert_eq!(
        opcode_gas(&rsmall),
        GAS_ZKML_SPEC_REGISTER_BASE
            + ((vk.spec_bytes.len() + vk.setup_attestation.len()) as u64) * GAS_ZKML_SPEC_PER_BYTE
    );
    assert_eq!(opcode_gas(&rsmall), spec_register_gas(&vk));
}

#[tokio::test]
async fn snark_gas_exhaustion_reverts() {
    let m = tiny_model();
    let (e, sk, addr) = funded().await;
    let (pk_bytes, vk) =
        register_model_and_vk(&e, &sk, addr, MODEL_A, &m, ATTEST_TEST_SEED, 0).await;
    let (_, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    let n = proof.public_inputs.len() + proof.public_outputs.len();
    // The attestation path RE-EXECUTES the registered model (audit W8.3), so
    // its real price is the table price PLUS the model-sized re-execution
    // charge the handler adds — exactly like the re-execution path.
    let reexec = (m.param_count() as u64) * GAS_ZKML_REEXEC_PER_PARAM;
    let cost = attestation_verify_gas(n, proof.wire_len()) + reexec;
    assert!(cost > GAS_ATTESTATION_VERIFY_BASE);

    // One unit short of the verify price: out-of-gas, transaction fails.
    // PINNED POLICY (SEC-07): the starvation is an ATTRIBUTABLE failure, so
    // it pays the failure fee and CONSUMES ITS NONCE (the nonce is 3
    // afterwards) - a free failure would be a free DoS.
    let starved = Transaction::sign_with_payload(
        &sk,
        addr,
        0,
        cost - 1,
        2,
        1,
        1,
        vec![OpCode::SysCallVerifyZkMlAttestation {
            model_id: MODEL_A,
            proof: Box::new(proof.clone()),
        }],
    );
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&starved), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "gas-starved SNARK verify must fail");
    assert_eq!(s, vec![false]);
    assert_eq!(
        e.get_account(&addr).await.unwrap().nonce,
        3,
        "the starved verify consumed its nonce (SEC-07)"
    );

    // Exact price applies (proves the shortfall above is really the gas:
    // the block path charges exactly the table for this payload). It is
    // signed with the NEXT nonce (3), because the refusal above burned 2.
    let exact = Transaction::sign_with_payload(
        &sk,
        addr,
        0,
        cost,
        3,
        1,
        1,
        vec![OpCode::SysCallVerifyZkMlAttestation {
            model_id: MODEL_A,
            proof: Box::new(proof),
        }],
    );
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&exact), BLOCK_TS)
        .await;
    assert_eq!((a, f), (1, 0), "exact-fuel SNARK verify must apply");
    assert_eq!(s, vec![true]);
}

// ---------------------------------------------------------------------------
// 7. Determinism across two nodes; verify is read-only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_two_nodes_agree_and_verify_is_read_only() {
    let m = tiny_model();
    let (a, ska, addra) = funded().await;
    let (b, _, _) = funded().await;
    let skb = key(0x71);
    assert_eq!(addra, skb.verifying_key().to_bytes());

    // Identical setup artifacts on both (same seed = same VK/PK bytes).
    let (pk_bytes, vk) = test_setup(&m, ATTEST_TEST_SEED);
    for engine in [&a, &b] {
        let rtx = register_model_tx(&ska, addra, 0, MODEL_A, &m);
        assert_eq!(
            engine
                .apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
                .await
                .0,
            1
        );
        let vtx = register_vk_tx(&ska, addra, 1, MODEL_A, &vk);
        assert_eq!(
            engine
                .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
                .await
                .0,
            1
        );
    }
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "same VK payload, same root"
    );

    // One proof, applied on both: same verdict, same root.
    let (_, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    let before_a = zkml_vks_digest(&a.zkml_models_read().await.clone());
    for (engine, nonce) in [(&a, 2u64), (&b, 2u64)] {
        let vtx = verify_snark_tx(&ska, addra, nonce, MODEL_A, &proof);
        assert_eq!(
            engine
                .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
                .await
                .0,
            1
        );
    }
    let after_a = zkml_vks_digest(&a.zkml_models_read().await.clone());
    assert_eq!(before_a, after_a, "verify does not mutate the key set");
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "same verify payload, same root"
    );
}

// ---------------------------------------------------------------------------
// 8. Bit-width edges (fuzz the constrained-format boundary).
// ---------------------------------------------------------------------------

#[test]
fn snark_bit_width_edges() {
    // Weight boundary: +/-127 fine, +/-128 refused.
    let w_ok = QuantizedLinearModel::new(vec![QuantizedLayer::new(1, 1, vec![127], vec![0])]);
    assert!(w_ok.is_attestation_compatible());
    let w_neg_ok = QuantizedLinearModel::new(vec![QuantizedLayer::new(1, 1, vec![-128], vec![0])]);
    assert!(w_neg_ok.is_attestation_compatible());
    for w in [128i64, -129, 1_000_000] {
        let bad = QuantizedLinearModel::new(vec![QuantizedLayer::new(1, 1, vec![w], vec![0])]);
        assert!(
            bad.validate(),
            "legacy validate stays permissive (old format works)"
        );
        assert!(
            !bad.is_attestation_compatible(),
            "weight {w} must be refused by the SNARK gate"
        );
        assert!(!bad.layers[0].validate_constrained_bounds());
    }
    assert!(tiny_model().layers[0].validate_constrained_bounds());

    // Prove-time input boundary: 0 and 65535 prove, 65536 and negatives fail.
    let m1 = QuantizedLinearModel::new(vec![QuantizedLayer::new(1, 1, vec![1], vec![0])]);
    let (pk1, vk1) = test_setup(&m1, ATTEST_TEST_SEED + 9);
    for good in [0i64, 1, 65_535] {
        let (out, proof) = prove_attestation(
            &m1.attestation_view(),
            m1.compute_model_hash(),
            &[good],
            &pk1,
            vk1.spec_hash,
        )
        .expect("boundary input must prove");
        assert_eq!(out, vec![good]);
        assert!(verify_attestation(&vk1.spec_bytes, &proof));
    }
    for bad_in in [-1i64, 65_536, i64::MAX] {
        assert!(
            prove_attestation(
                &m1.attestation_view(),
                m1.compute_model_hash(),
                &[bad_in],
                &pk1,
                vk1.spec_hash
            )
            .is_err(),
            "input {bad_in} must fail closed at prove time"
        );
    }

    // Accumulator overflow model: a single layer can never overflow the
    // 32-bit gadget with u16 inputs and i8 weights (65535*128*128 < 2^31),
    // so the overflow case is DEPTH: two 8-wide layers of 127s propagate
    // 67M hidden activations into a 68G second-layer accumulator.
    let deep = QuantizedLinearModel::new(vec![
        QuantizedLayer::new(8, 8, vec![127; 64], vec![0; 8]),
        QuantizedLayer::new(8, 1, vec![127; 8], vec![0]),
    ]);
    assert!(deep.validate());
    assert!(
        !deep.is_attestation_compatible(),
        "accumulator-blowing model must be refused"
    );
    {
        let mut reg = stellereum::zkml::ZkMlModelRegistry::default();
        reg.register(MODEL_A, deep).unwrap();
        let (_, vk_deep) = test_setup(&tiny_model(), ATTEST_TEST_SEED + 11);
        // Even a well-formed key for ANOTHER shape is refused (shape pin);
        // and the model itself can never complete setup-gating.
        assert!(reg.register_spec(MODEL_A, vk_deep).is_err());
    }

    // A small two-layer model whose propagated bound DOES fit is compatible,
    // and its circuit proves/verifies (depth works, blowup does not).
    let deep_ok = QuantizedLinearModel::new(vec![
        QuantizedLayer::new(1, 1, vec![0], vec![7]),
        QuantizedLayer::new(1, 1, vec![3], vec![-2]),
    ]);
    assert!(deep_ok.is_attestation_compatible());
    {
        let (pk_d, vk_d) = test_setup(&deep_ok, ATTEST_TEST_SEED + 12);
        let (out_d, proof_d) = prove_for(&deep_ok, &[10], &pk_d, &vk_d);
        assert_eq!(out_d, vec![19]); // L1: 7 (ReLU), L2: 3*7-2 = 19
        assert!(verify_attestation(&vk_d.spec_bytes, &proof_d));
    }

    // Dim caps: 129-wide refused by the cap even though its accumulator
    // (all ones) would fit.
    let too_wide =
        QuantizedLinearModel::new(vec![QuantizedLayer::new(129, 1, vec![1; 129], vec![0])]);
    assert!(!too_wide.is_attestation_compatible());

    // Empty / degenerate models refused (but legacy validate already does).
    assert!(!QuantizedLinearModel::new(vec![]).is_attestation_compatible());
}

// ---------------------------------------------------------------------------
// 9. Legacy path untouched: big models re-execute, never SNARK.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_legacy_big_model_keeps_reexec_but_refuses_vk() {
    let big = legacy_big_model();
    assert!(big.validate(), "legacy model registers as before");
    assert!(!big.is_attestation_compatible(), "but takes no VK");

    // Unit level: registration of a VK for it fails.
    {
        let mut reg = stellereum::zkml::ZkMlModelRegistry::default();
        reg.register(MODEL_A, big.clone()).unwrap();
        let (_, vk) = test_setup(&tiny_model(), ATTEST_TEST_SEED + 13);
        assert!(reg.register_spec(MODEL_A, vk).is_err());
    }

    // Live level: re-execution path works, VK attach reverts.
    let (e, sk, addr) = funded().await;
    let rtx = register_model_tx(&sk, addr, 0, MODEL_A, &big);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
            .await
            .0,
        1
    );
    let (_, legacy_proof) = ZkMlProof::prove_reexec(&big, &[3, 4]);
    assert!(legacy_proof.verify_inference_against(&big));
    let vtx = Transaction::sign_with_payload(
        &sk,
        addr,
        0,
        GAS,
        1,
        1,
        1,
        vec![OpCode::SysCallVerifyZkMlReexec {
            model_id: MODEL_A,
            proof: Box::new(legacy_proof),
        }],
    );
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (1, 0),
        "legacy re-execution path unchanged for big models"
    );

    let (_, vk) = test_setup(&tiny_model(), ATTEST_TEST_SEED + 13);
    let kvtx = register_vk_tx(&sk, addr, 2, MODEL_A, &vk);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&kvtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "VK attach to a non-compatible model must revert"
    );
}

// ---------------------------------------------------------------------------
// 10. Wire compat: 37/38 appended, legacy encodings unchanged, pre-node
//     fails closed; tx hash commits the SNARK proof.
// ---------------------------------------------------------------------------

#[test]
fn snark_discriminants_appended_legacy_encodings_unchanged() {
    let m = tiny_model();
    let (_, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (_, proof) = prove_for(&m, &[3, 4], &test_setup(&m, ATTEST_TEST_SEED).0, &vk);

    let reg = OpCode::SysCallRegisterZkMlSpec {
        model_id: MODEL_A,
        spec: Box::new(vk),
    };
    let ver = OpCode::SysCallVerifyZkMlAttestation {
        model_id: MODEL_A,
        proof: Box::new(proof),
    };
    for (op, want) in [(reg, 37u32), (ver, 38u32)] {
        let bytes = bincode::serialize(&op).expect("opcode serializes");
        let got = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(
            got, want,
            "new opcode discriminant must be appended, got {got}"
        );
    }
    // Spot-check the pinned prefix did not move.
    for (op, want) in [
        (OpCode::Push(42), 1u32),
        (OpCode::Halt, 26u32),
        (OpCode::SysCallVerifyZkMl, 11u32),
    ] {
        let bytes = bincode::serialize(&op).unwrap();
        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), want);
    }
}

#[test]
fn snark_pre_node_fails_closed_on_new_discriminant() {
    // A pre-SNARK node knows discriminants 0..=36 (re-execution wave). The
    // new payloads carry 37/38: outside its range, so it fails closed
    // instead of misreading them. Modelled structurally: extract the leading
    // discriminant and assert it is unknown to the old range.
    const PRE_SNARK_MAX: u32 = 36;
    let m = tiny_model();
    let (_, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (_, proof) = prove_for(&m, &[3, 4], &test_setup(&m, ATTEST_TEST_SEED).0, &vk);
    for payload in [
        vec![OpCode::SysCallRegisterZkMlSpec {
            model_id: MODEL_A,
            spec: Box::new(vk.clone()),
        }],
        vec![OpCode::SysCallVerifyZkMlAttestation {
            model_id: MODEL_A,
            proof: Box::new(proof.clone()),
        }],
    ] {
        let bytes = bincode::serialize(&payload).unwrap();
        let first = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert!(
            first > PRE_SNARK_MAX,
            "new opcode {first} must be unknown to a pre-SNARK decoder (0..=36)"
        );
        // ...while today's node decodes it fine (roundtrip).
        let round: Vec<OpCode> = bincode::deserialize(&bytes).expect("decodes today");
        assert_eq!(round.len(), 1);
    }
}

#[test]
fn snark_tx_hash_commits_the_proof() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let recipient = [0xABu8; 32];
    let m = tiny_model();
    let (pk_bytes, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (_, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    let mut other_proof = proof.clone();
    other_proof.public_outputs[0] += 1;

    let mk = |p: &AttestationProof| {
        Transaction::sign_with_payload(
            &sk,
            recipient,
            0,
            50_000,
            0,
            1,
            1,
            vec![OpCode::SysCallVerifyZkMlAttestation {
                model_id: MODEL_A,
                proof: Box::new(p.clone()),
            }],
        )
    };
    let a = mk(&proof);
    let b = mk(&other_proof);
    assert_ne!(
        a.compute_tx_hash(),
        b.compute_tx_hash(),
        "different proofs, different txs"
    );
    assert_ne!(a.signing_message(), b.signing_message());
    let mut tampered = a.clone();
    tampered.payload = vec![OpCode::SysCallVerifyZkMlAttestation {
        model_id: MODEL_A,
        proof: Box::new(other_proof),
    }];
    assert!(
        !tampered.verify_signature(),
        "payload (hence proof) is signed"
    );
}

// ---------------------------------------------------------------------------
// 11. Commitment: VK domain conditional, version pinned at 4.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_vk_domain_is_conditional_and_version_stays_4() {
    use std::collections::HashMap;
    use stellereum::bridge::BridgeState;
    use stellereum::contract::ContractRegistry;
    use stellereum::governance::Governance;
    use stellereum::oracle::OracleState;
    use stellereum::orderbook::OrderbookManager;
    use stellereum::pmm::PrimaryMarketMaker;
    use stellereum::staking::StakingLedger;
    use stellereum::token::TokenRegistry;
    use stellereum::zkml::{SessionKeyRegistry, ZkMlModelRegistry};

    assert_eq!(COMMITMENT_VERSION, 5, "Genesis v5 version");
    let snap = stellereum::commitment::CommitmentSnapshot {
        tokens: TokenRegistry::default(),
        staking: StakingLedger::default(),
        orderbooks: OrderbookManager::default(),
        order_escrow: HashMap::new(),
        pmm: PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: ContractRegistry::default(),
        governance: Governance::default(),
        oracle: OracleState::default(),
        session_keys: SessionKeyRegistry::default(),
        bridge: BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    };
    // Empty registry: the zkML-aware digest is byte-identical to the base
    // (genesis KAT property - no version bump).
    let empty = ZkMlModelRegistry::default();
    assert!(!empty.has_any_spec());
    assert_eq!(
        commitment_digest_with_zkml(&snap, &empty),
        commitment_digest(&snap)
    );

    // Models but no VK: the VK domain still writes zero bytes (keys, not
    // models, gate it) - the domain digest equals the empty preimage.
    let mut models_only = ZkMlModelRegistry::default();
    models_only.register(MODEL_A, tiny_model()).unwrap();
    assert!(!models_only.has_any_spec());
    assert_eq!(
        zkml_vks_digest(&models_only),
        zkml_vks_digest(&ZkMlModelRegistry::default())
    );

    // One VK moves the full digest relative to the same models without it
    // (isolates the VK domain's contribution from the models domain's).
    let (_, vk) = test_setup(&tiny_model(), ATTEST_TEST_SEED);
    let mut one = models_only.clone();
    one.register_spec(MODEL_A, vk.clone()).unwrap();
    assert!(one.has_any_spec());
    assert_ne!(
        commitment_digest_with_zkml(&snap, &one),
        commitment_digest_with_zkml(&snap, &models_only),
        "a registered VK must move the digest"
    );
    let mut two = one.clone();
    two.register(MODEL_B, other_model()).unwrap();
    let (_, vk_b) = test_setup(&other_model(), ATTEST_TEST_SEED + 21);
    two.register_spec(MODEL_B, vk_b).unwrap();
    assert_ne!(
        commitment_digest_with_zkml(&snap, &two),
        commitment_digest_with_zkml(&snap, &one),
        "a second VK must move the digest again"
    );

    // And through the engine: VK registration moves the live root.
    let (e, sk, addr) = funded().await;
    let before = e.get_state_root().await;
    let rtx = register_model_tx(&sk, addr, 0, MODEL_A, &tiny_model());
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
            .await
            .0,
        1
    );
    let kvtx = register_vk_tx(&sk, addr, 1, MODEL_A, &vk);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&kvtx), BLOCK_TS)
            .await
            .0,
        1
    );
    assert_ne!(
        e.get_state_root().await,
        before,
        "VK set is consensus state"
    );
}

// ---------------------------------------------------------------------------
// 12. Direct VM without a registry fails closed; production setup helper.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snark_direct_vm_without_registry_fails_closed() {
    use stellereum::svm::{Svm, VmContext};
    let m = tiny_model();
    let (pk_bytes, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (_, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);

    let mut ctx = VmContext {
        sender: [0u8; 32],
        balance: 0,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: 0,
        trades: vec![],
        transfers: vec![],
        token_registry: None,
        token_events: vec![],
        contracts: None,
        staking: None,
        pmm: None,
        min_validator_bond: 0,
        default_commission_bps: 0,
        payouts: vec![],
        oracle: None,
    };
    let r = Svm::execute(
        &[OpCode::SysCallRegisterZkMlSpec {
            model_id: MODEL_A,
            spec: Box::new(vk),
        }],
        10_000_000,
        &mut ctx,
    );
    assert!(matches!(r, stellereum::svm::VmExecutionResult::Reverted(_)));

    let mut ctx2 = VmContext {
        sender: [0u8; 32],
        balance: 0,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: 0,
        trades: vec![],
        transfers: vec![],
        token_registry: None,
        token_events: vec![],
        contracts: None,
        staking: None,
        pmm: None,
        min_validator_bond: 0,
        default_commission_bps: 0,
        payouts: vec![],
        oracle: None,
    };
    let r = Svm::execute(
        &[OpCode::SysCallVerifyZkMlAttestation {
            model_id: MODEL_A,
            proof: Box::new(proof),
        }],
        10_000_000,
        &mut ctx2,
    );
    assert!(matches!(r, stellereum::svm::VmExecutionResult::Reverted(_)));
}

#[test]
fn snark_production_single_party_setup_marks_attestation() {
    // The production helper runs on OS entropy with a caller-supplied
    // attestation (here: a ceremony-transcript-style pointer). It must verify
    // like any other setup - the DIFFERENCE from the test path is the waste
    // handling story (documented in `snark`, pinned here by the attestation
    // bytes, which must NOT carry the test-only tag).
    let m = tiny_model();
    let attestation =
        b"ceremony:powers-of-tau/AleO-test-transcript-sha256=deadbeef:participants=1:DESTROY-WASTE"
            .to_vec();
    let (pk_bytes, vk) = model_spec_with_attestation(&m.attestation_view(), attestation.clone())
        .expect("setup works");
    assert_eq!(vk.setup_attestation, attestation);
    assert!(!vk.setup_attestation.starts_with(TEST_SETUP_ATTESTATION));
    let (_, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    assert!(verify_attestation(&vk.spec_bytes, &proof));

    // Empty attestation refused even on the production path.
    assert!(model_spec_with_attestation(&m.attestation_view(), vec![]).is_err());
}

#[test]
fn snark_proof_leaves_inputs_and_outputs_public_no_hiding() {
    // LIMIT pin ("NOT zero-knowledge, NOT hiding"): the attestation proof
    // carries the public inputs AND outputs IN THE CLEAR — anyone holding the
    // proof reads them. If a future change encrypted or removed them, this
    // fails; the honest name stays "re-execution attestation".
    let m = tiny_model();
    let (pk_bytes, vk) = test_setup(&m, ATTEST_TEST_SEED);
    let (out, proof) = prove_for(&m, &[3, 4], &pk_bytes, &vk);
    assert_eq!(
        proof.public_inputs,
        vec![3u64, 4],
        "inputs ride in the clear"
    );
    assert_eq!(
        proof.public_outputs,
        out.iter().map(|&x| x as u64).collect::<Vec<_>>(),
        "outputs ride in the clear"
    );
    assert_eq!(
        proof.public_outputs,
        vec![11u64, 7],
        "outputs are the forward pass"
    );
    // And the machine-readable statement agrees: sound, but neither
    // zero-knowledge nor succinct nor hiding.
    let caps = stellereum::zkml::zkml_capabilities();
    assert!(caps.sound);
    assert!(!caps.zero_knowledge && !caps.succinct && !caps.hiding);
    assert!(caps.protocol.contains("re-execution"));
}
