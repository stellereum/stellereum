//! Pure-PQ enforcement gate for the Ristretto privacy module.
//!
//! Scope: `stellereum/src/crypto_privacy.rs` is LIVE (not experimental) —
//! proof: `svm.rs` `SysCallConfidentialTransfer2`/`Shield`/`Unshield`
//! handlers, `state_engine.rs` shielded state + parallel preverify,
//! `commitment.rs` confidential domain, `mempool.rs` proof-unit accounting,
//! `native_api.rs` shield/stealth builders, `wallet.rs` stealth fields,
//! `sharding.rs:3497` stealth-sig fallback. Under
//! `set_pure_pq_override(Some(true))` every fallible Ristretto op refuses
//! fail-closed with no silent classical fallback; with the gate off behavior
//! is byte-identical to before (existing privacy suites pin it).
//!
//! Discipline: `set_pure_pq_override` is process-wide in integration builds,
//! so every test in this binary serializes on `SERIAL` and resets to `None`
//! on guard drop (same pattern as `tests/faucet_pq_tests.rs`).

use std::sync::Mutex;
use stellereum::crypto_privacy::{
    BitProof, ConfidentialError, ConfidentialState, ConfidentialTransfer, PedersenCommitment,
    RangeProof, StealthAddress, ViewingKey, privacy_pq_refused,
};
use stellereum::post_quantum::{is_pure_pq_enforced, set_pure_pq_override};

/// Serializes every test in this binary: the pure-PQ override is a
/// process-wide atomic in integration builds, so two tests must never hold
/// different modes at once.
static SERIAL: Mutex<()> = Mutex::new(());

/// Fail-safe pure-PQ override: resets to `None` on drop so a panicking
/// assertion cannot leak enforcement into the next test.
struct PqGuard {
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl PqGuard {
    fn enforced() -> Self {
        let guard = SERIAL.lock().expect("privacy-pq serial mutex poisoned");
        set_pure_pq_override(Some(true));
        assert!(
            is_pure_pq_enforced(),
            "pure-PQ override must be visible on this thread"
        );
        assert!(privacy_pq_refused(), "module flag must mirror enforcement");
        Self { _serial: guard }
    }

    fn disabled() -> Self {
        let guard = SERIAL.lock().expect("privacy-pq serial mutex poisoned");
        set_pure_pq_override(None);
        std::env::remove_var("STELL_PURE_PQ");
        assert!(
            !is_pure_pq_enforced(),
            "default mode must be classical (no override, no env)"
        );
        assert!(!privacy_pq_refused());
        Self { _serial: guard }
    }
}

impl Drop for PqGuard {
    fn drop(&mut self) {
        set_pure_pq_override(None);
        std::env::remove_var("STELL_PURE_PQ");
    }
}

/// Build an honest funded fixture with the gate OFF (constructors stay
/// available offline); callers flip to enforced before asserting refusal.
fn honest_fixture() -> (
    [u8; 32],
    [u8; 32],
    ConfidentialTransfer,
    Vec<RangeProof>,
    Vec<RangeProof>,
    ConfidentialState,
) {
    let sender = [0x11u8; 32];
    let recipient = [0x22u8; 32];
    let b_in = curve25519_dalek::scalar::Scalar::from(7u64);
    let c_in = PedersenCommitment::commit(1_000, &b_in);
    let b_out = curve25519_dalek::scalar::Scalar::from(7u64);
    let c_out = PedersenCommitment::commit(990, &b_out);
    let transfer = ConfidentialTransfer::new(vec![c_in], vec![c_out], 10);
    let in_ranges = vec![RangeProof::prove(&c_in, 1_000, &b_in, 32)];
    let out_ranges = vec![RangeProof::prove(&c_out, 990, &b_out, 32)];
    let mut state = ConfidentialState::new();
    // Fund the input as sender-owned (shield entry records ownership).
    state.note_shielded_output(&sender, c_in.commitment);
    (sender, recipient, transfer, in_ranges, out_ranges, state)
}

// 1. Default behavior is UNCHANGED: the honest shielded flow verifies and
//    applies exactly as before (no flag day when the gate is off).
#[test]
fn default_mode_honest_flow_unchanged() {
    let _guard = PqGuard::disabled();
    let (sender, recipient, transfer, in_ranges, out_ranges, mut state) = honest_fixture();

    assert!(transfer.verify_balance_conservation());
    assert!(transfer.verify_balanced_with_ranges(&in_ranges, &out_ranges));
    assert!(transfer.verify_ranges(&in_ranges, &out_ranges).is_ok());
    assert!(
        ConfidentialState::verify_opening(
            &transfer.input_commitments[0].commitment,
            1_000,
            &curve25519_dalek::scalar::Scalar::from(7u64).to_bytes()
        )
    );
    state
        .apply_transfer_with_ranges(&sender, &recipient, &transfer, &in_ranges, &out_ranges)
        .expect("honest transfer must apply in default mode");
    assert_eq!(state.total_fees, 10);

    // Stealth + viewing lifecycle still works with the gate off.
    let vk = ViewingKey::derive_from_seed(&[0x42u8; 32]);
    let (spend_priv, spend_pub) = ViewingKey::derive_spend_key(&[0x42u8; 32]);
    let stealth =
        StealthAddress::generate(&vk.view_pub, &spend_pub).expect("generate works by default");
    assert_eq!(
        stealth.is_for_recipient(&vk.private_scalar(), &spend_pub),
        Some(true)
    );
    let one_time = stealth
        .derive_one_time_private_key(&vk.private_scalar(), &spend_priv)
        .expect("derivation works by default");
    let msg = b"pq gate default pin";
    let sig = stealth.sign(&one_time, msg);
    assert!(stealth.verify_signature(msg, &sig));

    // Auditor encrypt/decrypt round-trips by default.
    let blinding = PedersenCommitment::random_blinding();
    let payload = ViewingKey::encrypt_amount_for_auditor(&vk.view_pub, 1234, &blinding)
        .expect("encrypt works by default");
    let (value, _) = vk.decrypt_amount(&payload).expect("decrypt works by default");
    assert_eq!(value, 1234);
}

// 2. Enforced mode: every fallible Ristretto verifier/applier refuses
//    fail-closed — no silent fallback, no classical verification succeeding.
#[test]
fn enforced_mode_refuses_all_fallible_ristretto_ops() {
    // Build fixtures with the gate off, then flip enforcement on.
    let (sender, recipient, transfer, in_ranges, out_ranges, mut state) = {
        let _off = PqGuard::disabled();
        honest_fixture()
    };
    let (c, r, proof, bit_proof, vk, spend_priv, spend_pub, stealth, msg, sig, payload) = {
        let _off = PqGuard::disabled();
        let r = PedersenCommitment::random_blinding();
        let c = PedersenCommitment::commit(42, &r);
        let proof = RangeProof::prove(&c, 42, &r, 32);
        let bit_proof = BitProof::prove(&c, false, &PedersenCommitment::random_blinding());
        let vk = ViewingKey::derive_from_seed(&[0x77u8; 32]);
        let (spend_priv, spend_pub) = ViewingKey::derive_spend_key(&[0x77u8; 32]);
        let stealth = StealthAddress::generate(&vk.view_pub, &spend_pub).unwrap();
        let msg = b"enforced refusal pin";
        let one_time = stealth
            .derive_one_time_private_key(&vk.private_scalar(), &spend_priv)
            .unwrap();
        let sig = stealth.sign(&one_time, msg);
        let payload =
            ViewingKey::encrypt_amount_for_auditor(&vk.view_pub, 42, &r).expect("fixture encrypt");
        (
            c, r, proof, bit_proof, vk, spend_priv, spend_pub, stealth, msg, sig, payload,
        )
    };

    let _guard = PqGuard::enforced();

    // Commitments: verify false, arithmetic None, batch all-false.
    assert!(!c.verify(42, &r));
    assert!(c.add(&c).is_none());
    assert!(c.sub(&c).is_none());
    assert_eq!(
        PedersenCommitment::batch_verify(&[(c, 42, r)]),
        vec![false]
    );

    // Range/bit proofs: every verifier false, batches all-false.
    assert!(!RangeProof::verify(&c, &proof));
    assert_eq!(
        RangeProof::batch_verify(&[(&c, &proof)]),
        vec![false]
    );
    assert!(!BitProof::verify(&c, &bit_proof));
    assert!(!BitProof::verify_scalar(&c, &bit_proof));

    // Transfers: equation, ranged, and per-item gates all refuse.
    assert!(!transfer.verify_balance_conservation());
    assert!(!transfer.verify_balanced_with_ranges(&in_ranges, &out_ranges));
    assert_eq!(
        transfer.verify_ranges(&in_ranges, &out_ranges),
        Err(ConfidentialError::PurePqRefused)
    );
    assert_eq!(
        ConfidentialTransfer::batch_verify_balance_conservation(std::slice::from_ref(&transfer)),
        vec![false]
    );
    assert_eq!(
        ConfidentialTransfer::batch_verify_balanced_with_ranges(&[(
            &transfer,
            in_ranges.as_slice(),
            out_ranges.as_slice()
        )]),
        vec![false]
    );

    // Shielded state: every money-moving entry point refuses.
    assert!(!ConfidentialState::verify_opening(
        &transfer.input_commitments[0].commitment,
        1_000,
        &curve25519_dalek::scalar::Scalar::from(7u64).to_bytes()
    ));
    assert_eq!(
        state.apply_transfer(&sender, &recipient, &transfer),
        Err(ConfidentialError::PurePqRefused)
    );
    assert_eq!(
        state.verify_transfer_with_ranges(&sender, &transfer, &in_ranges, &out_ranges),
        Err(ConfidentialError::PurePqRefused)
    );
    assert_eq!(
        state.apply_transfer_with_ranges(&sender, &recipient, &transfer, &in_ranges, &out_ranges),
        Err(ConfidentialError::PurePqRefused)
    );

    // Stealth auth: generation/discovery/derivation None, signatures false.
    assert!(StealthAddress::generate(&vk.view_pub, &spend_pub).is_none());
    assert!(
        stealth
            .is_for_recipient(&vk.private_scalar(), &spend_pub)
            .is_none()
    );
    assert!(
        stealth
            .derive_one_time_private_key(&vk.private_scalar(), &spend_priv)
            .is_none()
    );
    assert!(!StealthAddress::verify_one_time_signature(
        &stealth.one_time_pub,
        msg,
        &sig
    ));
    assert!(!stealth.verify_signature(msg, &sig));
    assert!(!stealth.verify(msg, &sig));
    assert!(!stellereum::crypto_privacy::verify_stealth_signature(
        &stealth.one_time_pub,
        msg,
        &sig
    ));
    assert!(vk.is_for_recipient(&stealth, &spend_pub).is_none());
    assert!(vk.derive_one_time_private_key(&stealth, &spend_priv).is_none());

    // Auditor channel: static refusal, never a decrypted value.
    assert!(ViewingKey::encrypt_amount_for_auditor(&vk.view_pub, 42, &r).is_err());
    assert!(vk.decrypt_amount(&payload).is_err());
}

// 3. No sensitive leakage in refusal errors: the refusal carries no
//    commitment bytes, blindings, or view keys — static text only.
#[test]
fn enforced_refusal_errors_carry_no_secrets() {
    let _guard = PqGuard::disabled();
    let blinding = PedersenCommitment::random_blinding();
    let blinding_hex = hex::encode(blinding.to_bytes());
    let c = PedersenCommitment::commit(999, &blinding);
    let commitment_hex = hex::encode(c.commitment);
    let vk = ViewingKey::derive_from_seed(&[0xABu8; 32]);
    let view_priv_hex = hex::encode(vk.view_priv);

    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced());

    let err = ConfidentialError::PurePqRefused;
    let shown = format!("{err}");
    let dbg = format!("{err:?}");
    for secret in [&blinding_hex, &commitment_hex, &view_priv_hex] {
        assert!(!shown.contains(secret.as_str()), "refusal leaks a secret: {shown}");
        assert!(!dbg.contains(secret.as_str()), "refusal Debug leaks a secret");
    }
    // The refusal names the cause without hex payloads.
    assert!(shown.contains("STELL_PURE_PQ=1"), "refusal must name the gate: {shown}");

    // State-transition refusal is the same static error (not InvalidCommitment
    // echoing bytes): assert the variant, then check its text is secret-free.
    let mut state = ConfidentialState::new();
    let sender = [0x11u8; 32];
    let recipient = [0x22u8; 32];
    let tx = ConfidentialTransfer::new(vec![c], vec![c], 0);
    let perr = state
        .apply_transfer(&sender, &recipient, &tx)
        .expect_err("must refuse under pure-PQ");
    assert_eq!(perr, ConfidentialError::PurePqRefused);
    let pshown = format!("{perr}");
    for secret in [&blinding_hex, &commitment_hex] {
        assert!(
            !pshown.contains(secret.as_str()),
            "state refusal leaks a secret: {pshown}"
        );
    }

    // Auditor-channel refusals are static strings with no payload bytes.
    let enc_err =
        ViewingKey::encrypt_amount_for_auditor(&vk.view_pub, 999, &blinding).expect_err("refuse");
    assert!(!enc_err.contains(&blinding_hex));
    assert!(!enc_err.contains(&commitment_hex));
    assert!(enc_err.contains("STELL_PURE_PQ=1"));
}
