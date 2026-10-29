//! Audit closure: confidential gates C1/C2 (range/spent/ownership on every
//! pool entry + handler-shape vs atomic equivalence), stealth hygiene C3,
//! viewing-key leakage, session-key scope/expiry/cap enforcement, zkML model
//! registry access.
//!
//! NEW file — never edits shared tests. Pure unit tests (no engine).

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::crypto_privacy::{
    ConfidentialError, ConfidentialState, ConfidentialTransfer, PedersenCommitment, RangeProof,
    StealthAddress, UnshieldInput, ViewingKey,
};
use stellereum::zkml::{
    QuantizedLayer, QuantizedLinearModel, SessionKeyAuthorization, SessionKeyRecord,
    SessionKeyRegistry, SessionSpendSim, MAX_ZKML_MODEL_PARAMS, SCOPE_ACTOR_SEND,
    SCOPE_SVM_PAYLOAD, SCOPE_TRANSFER,
};

fn funded(sender: [u8; 32], value: u64, blind: &Scalar) -> (ConfidentialState, PedersenCommitment) {
    let mut st = ConfidentialState::new();
    let c = PedersenCommitment::commit(value, blind);
    st.note_shielded_output(&sender, c.commitment);
    (st, c)
}

/// A conservation-sound transfer: v_in = v_out + fee, blindings conserved.
fn sound_tx(
    c_in: &PedersenCommitment,
    v_in: u64,
    r_in: &Scalar,
    v_out: u64,
    fee: u64,
) -> (ConfidentialTransfer, Vec<RangeProof>, Vec<RangeProof>) {
    assert_eq!(v_in, v_out + fee);
    let c_out = PedersenCommitment::commit(v_out, r_in);
    let tx = ConfidentialTransfer::new(vec![*c_in], vec![c_out], fee);
    let in_ranges = vec![RangeProof::prove(c_in, v_in, r_in, 32)];
    let out_ranges = vec![RangeProof::prove(&c_out, v_out, r_in, 32)];
    (tx, in_ranges, out_ranges)
}

// ===========================================================================
// C1/C2: atomic gate coverage on every pool entry
// ===========================================================================

#[test]
fn atomic_accepts_a_sound_transfer_and_moves_ownership() {
    let sender = [0xA1u8; 32];
    let recipient = [0xB2u8; 32];
    let r = Scalar::from(0x5EEDu64);
    let (mut st, c_in) = funded(sender, 1_000, &r);
    let (tx, in_r, out_r) = sound_tx(&c_in, 1_000, &r, 980, 20);
    st.apply_transfer_with_ranges(&sender, &recipient, &tx, &in_r, &out_r)
        .expect("sound transfer applies atomically");
    assert!(st.is_spent(&c_in.commitment));
    assert!(!st.is_owned(&c_in.commitment));
    assert!(st.is_owned(&tx.output_commitments[0].commitment));
    assert_eq!(st.total_fees, 20);
}

#[test]
fn atomic_rejects_missing_proof_with_no_state_change() {
    let sender = [0xA1u8; 32];
    let recipient = [0xB2u8; 32];
    let r = Scalar::from(7u64);
    let (mut st, c_in) = funded(sender, 1_000, &r);
    let (tx, _in_r, out_r) = sound_tx(&c_in, 1_000, &r, 980, 20);
    let before = st.clone();
    let err = st
        .apply_transfer_with_ranges(&sender, &recipient, &tx, &[], &out_r)
        .expect_err("count mismatch must fail closed");
    assert_eq!(err, ConfidentialError::MissingRangeProof);
    assert_eq!(st, before, "fail-closed: no partial mutation");
}

#[test]
fn atomic_rejects_failed_proof_with_no_state_change() {
    let sender = [0xA1u8; 32];
    let recipient = [0xB2u8; 32];
    let r = Scalar::from(7u64);
    let (mut st, c_in) = funded(sender, 1_000, &r);
    let (tx, _in_r, out_r) = sound_tx(&c_in, 1_000, &r, 980, 20);
    // A proof for a DIFFERENT commitment: reconstruction fails deterministically.
    let wrong_c = PedersenCommitment::commit(1_001, &r);
    let wrong_proof = RangeProof::prove(&wrong_c, 1_001, &r, 32);
    let before = st.clone();
    let err = st
        .apply_transfer_with_ranges(&sender, &recipient, &tx, &[wrong_proof], &out_r)
        .expect_err("wrong proof must fail closed");
    assert_eq!(err, ConfidentialError::InvalidRangeProof(c_in.commitment));
    assert_eq!(st, before);
}

#[test]
fn atomic_rejects_unowned_spent_duplicate_and_unbalanced() {
    let sender = [0xA1u8; 32];
    let recipient = [0xB2u8; 32];
    let stranger = [0xC3u8; 32];
    let r = Scalar::from(9u64);
    let (mut st, c_in) = funded(sender, 1_000, &r);
    let (tx, in_r, out_r) = sound_tx(&c_in, 1_000, &r, 980, 20);

    // NotOwner: stranger spends sender's coin.
    assert_eq!(
        st.verify_transfer_with_ranges(&stranger, &tx, &in_r, &out_r),
        Err(ConfidentialError::NotOwner(c_in.commitment))
    );
    // Duplicate input inside one transfer.
    let dup = ConfidentialTransfer::new(vec![c_in, c_in], vec![tx.output_commitments[0]], 20);
    let dup_in = vec![
        RangeProof::prove(&c_in, 1_000, &r, 32),
        RangeProof::prove(&c_in, 1_000, &r, 32),
    ];
    assert_eq!(
        st.verify_transfer_with_ranges(&sender, &dup, &dup_in, &out_r),
        Err(ConfidentialError::DuplicateInput(c_in.commitment))
    );
    // Conservation violated (fee mismatch).
    let bad_fee = ConfidentialTransfer::new(vec![c_in], vec![tx.output_commitments[0]], 21);
    assert_eq!(
        st.verify_transfer_with_ranges(&sender, &bad_fee, &in_r, &out_r),
        Err(ConfidentialError::ConservationViolated)
    );
    // Spend once, then double-spend.
    st.apply_transfer_with_ranges(&sender, &recipient, &tx, &in_r, &out_r)
        .expect("first spend applies");
    assert_eq!(
        st.verify_transfer_with_ranges(&sender, &tx, &in_r, &out_r),
        Err(ConfidentialError::DoubleSpend(c_in.commitment))
    );
}

#[test]
fn atomic_rejects_fee_overflow() {
    let sender = [0xA1u8; 32];
    let _recipient = [0xB2u8; 32];
    let r = Scalar::from(11u64);
    let (mut st, c_in) = funded(sender, 1_000, &r);
    let (tx, in_r, out_r) = sound_tx(&c_in, 1_000, &r, 999, 1);
    st.total_fees = u64::MAX;
    assert_eq!(
        st.verify_transfer_with_ranges(&sender, &tx, &in_r, &out_r),
        Err(ConfidentialError::FeeOverflow)
    );
}

#[test]
fn handler_shape_matches_atomic_on_a_battery_of_inputs() {
    // Pins the C1 equivalence: handler two-step
    // (verify_balanced_with_ranges && apply_transfer) == atomic, always.
    let sender = [0xA1u8; 32];
    let recipient = [0xB2u8; 32];
    let stranger = [0xC3u8; 32];
    let r = Scalar::from(13u64);
    let (base, c_in) = funded(sender, 1_000, &r);
    let (good, good_in, good_out) = sound_tx(&c_in, 1_000, &r, 980, 20);
    let wrong_c = PedersenCommitment::commit(5, &r);
    let wrong_proof = RangeProof::prove(&wrong_c, 5, &r, 32);
    let unbalanced = ConfidentialTransfer::new(vec![c_in], vec![good.output_commitments[0]], 999);
    #[allow(clippy::type_complexity)]
    // GATE: table-driven test cases enumerate full mutator/case tuples inline for readability.
    let cases: Vec<(
        ConfidentialTransfer,
        Vec<RangeProof>,
        Vec<RangeProof>,
        [u8; 32],
    )> = vec![
        (good.clone(), good_in.clone(), good_out.clone(), sender),
        (good.clone(), vec![], good_out.clone(), sender),
        (
            good.clone(),
            vec![wrong_proof.clone()],
            good_out.clone(),
            sender,
        ),
        (good.clone(), good_in.clone(), good_out.clone(), stranger),
        (unbalanced, good_in.clone(), good_out.clone(), sender),
    ];
    for (tx, in_r, out_r, who) in &cases {
        let mut a = base.clone();
        let handler_ok = tx.verify_balanced_with_ranges(in_r, out_r)
            && a.apply_transfer(who, &recipient, tx).is_ok();
        let mut b = base.clone();
        let atomic_ok = b
            .apply_transfer_with_ranges(who, &recipient, tx, in_r, out_r)
            .is_ok();
        assert_eq!(handler_ok, atomic_ok, "handler shape must equal atomic");
        if atomic_ok {
            assert_eq!(a, b, "on accept both reach identical state");
        }
    }
}

#[test]
fn unshield_entry_is_fully_gated() {
    let sender = [0xA1u8; 32];
    let r = Scalar::from(17u64);
    let (mut st, c) = funded(sender, 400, &r);
    let opening = |amount: u64| UnshieldInput {
        commitment: c.commitment,
        amount,
        blinding: r.to_bytes(),
    };
    // Bad opening (wrong amount) fails before any state read.
    assert_eq!(
        st.retire_for_unshield(&sender, &[opening(399)]),
        Err(ConfidentialError::BadOpening(c.commitment))
    );
    // Duplicate listing of one coin would double-pay: refused.
    assert_eq!(
        st.retire_for_unshield(&sender, &[opening(400), opening(400)]),
        Err(ConfidentialError::DuplicateInput(c.commitment))
    );
    // Unowned coin unspendable.
    assert_eq!(
        st.retire_for_unshield(&[0xFFu8; 32], &[opening(400)]),
        Err(ConfidentialError::NotOwner(c.commitment))
    );
    // Honest exit retires exactly once.
    assert_eq!(st.retire_for_unshield(&sender, &[opening(400)]), Ok(400));
    // Re-retire: the coin left `owned` at exit, so ownership fails first
    // (spent-set order after it is defensive) — still fail-closed.
    assert_eq!(
        st.retire_for_unshield(&sender, &[opening(400)]),
        Err(ConfidentialError::NotOwner(c.commitment))
    );
    // Empty input set refused.
    assert_eq!(
        st.retire_for_unshield(&sender, &[]),
        Err(ConfidentialError::EmptyTransfer)
    );
}

// ===========================================================================
// C3: stealth hygiene + viewing-key leakage
// ===========================================================================

#[test]
fn stealth_addresses_are_single_use_and_owner_checked() {
    let mut rng = OsRng;
    let view_priv = Scalar::random(&mut rng);
    let view_pub = (curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * view_priv)
        .compress()
        .to_bytes();
    let spend_priv = Scalar::random(&mut rng);
    let spend_pub = (curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * spend_priv)
        .compress()
        .to_bytes();
    let other_spend = Scalar::random(&mut rng);
    let other_pub = (curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * other_spend)
        .compress()
        .to_bytes();

    let a = StealthAddress::generate(&view_pub, &spend_pub).expect("generate");
    let b = StealthAddress::generate(&view_pub, &spend_pub).expect("generate");
    assert_ne!(
        a.one_time_pub, b.one_time_pub,
        "fresh randomness per address: no one-time-key reuse"
    );
    assert_eq!(a.is_for_recipient(&view_priv, &spend_pub), Some(true));
    assert_eq!(a.is_for_recipient(&view_priv, &other_pub), Some(false));
    let one_time = a
        .derive_one_time_private_key(&view_priv, &spend_priv)
        .expect("derive");
    let msg = b"audit closure stealth authorization";
    let sig = a.sign(&one_time, msg);
    assert!(a.verify_signature(msg, &sig));
    assert!(!a.verify_signature(b"forged", &sig));
    let mut bad = sig;
    bad[0] ^= 0xFF;
    assert!(!a.verify_signature(msg, &bad));
}

#[test]
fn committed_transfer_bytes_carry_no_openings() {
    // The committed representation (encode/digest) must reveal nothing about
    // values or blindings: only points, order and fee.
    let r = Scalar::from(0xC10Au64);
    let c_in = PedersenCommitment::commit(1_000, &r);
    let c_out = PedersenCommitment::commit(980, &r);
    let tx = ConfidentialTransfer::new(vec![c_in], vec![c_out], 20);
    let enc = tx.encode();
    assert_eq!(enc.len(), 8 + 32 + 8 + 32 + 8, "length-framed, exact size");
    assert!(
        !enc.windows(32).any(|w| w == r.to_bytes()),
        "blinding factor must not appear in committed bytes"
    );
    assert_eq!(tx.digest(), tx.digest(), "digest deterministic");
    let mut tampered = tx.clone();
    tampered.fee = 21;
    assert_ne!(tx.digest(), tampered.digest(), "fee mutates the digest");
}

#[test]
fn viewing_key_audit_is_opt_in_and_key_bound() {
    let auditor = ViewingKey::generate();
    let stranger = ViewingKey::generate();
    let r = Scalar::random(&mut OsRng);
    let payload =
        ViewingKey::encrypt_amount_for_auditor(&auditor.view_pub, 12_345, &r).expect("encrypt");
    let (v, b) = auditor.decrypt_amount(&payload).expect("decrypt");
    assert_eq!(v, 12_345);
    assert_eq!(b, r);
    assert!(
        stranger.decrypt_amount(&payload).is_err(),
        "a non-auditor key opens nothing"
    );
    assert!(
        ViewingKey::encrypt_amount_for_auditor(&[0xFFu8; 32], 1, &r).is_err(),
        "garbage auditor key refused"
    );
}

// ===========================================================================
// Session keys: scope / expiry / cap enforcement (registry half)
// ===========================================================================

fn test_grant(
    scope: u64,
    max_gas: u64,
    max_value: u64,
    valid_until: u64,
) -> (SigningKey, SessionKeyAuthorization, [u8; 32]) {
    let master = SigningKey::from_bytes(&[0x11u8; 32]);
    let session = SigningKey::from_bytes(&[0x22u8; 32]);
    let spk = session.verifying_key().to_bytes();
    let g = SessionKeyAuthorization::sign_delegation(
        &master,
        spk,
        valid_until,
        max_gas,
        scope,
        max_value,
        5757,
    );
    (session, g, spk)
}

#[test]
fn session_grant_scope_expiry_and_signature_are_enforced() {
    let (_sess, g, _spk) = test_grant(SCOPE_TRANSFER, 1_000, 50, 10_000);
    assert!(g.grants_scope(SCOPE_TRANSFER));
    assert!(
        !g.grants_scope(SCOPE_SVM_PAYLOAD),
        "transfer-only grant covers no payload"
    );
    assert!(!g.grants_scope(SCOPE_TRANSFER | SCOPE_SVM_PAYLOAD));
    assert!(!g.grants_scope(SCOPE_ACTOR_SEND));
    assert!(g.verify_at(10_000), "valid at the boundary");
    assert!(!g.verify_at(10_001), "expired one second later");
    assert_eq!(g.remaining_gas(), 1_000);
    // Any covered-field tamper breaks the master's signature.
    let mut tampered = g.clone();
    tampered.scope = SCOPE_TRANSFER | SCOPE_SVM_PAYLOAD;
    assert!(!tampered.verify_signature());
    let mut tampered = g.clone();
    tampered.chain_id = 9999;
    assert!(!tampered.verify_signature());
    let mut tampered = g.clone();
    tampered.max_value_per_tx = u64::MAX;
    assert!(!tampered.verify_signature());
}

#[test]
fn session_gas_budget_is_capped_and_saturating() {
    let (_sess, mut g, _spk) = test_grant(SCOPE_TRANSFER, 100, 50, 10_000);
    g.verify_and_spend_gas(60, 1).expect("within budget");
    assert_eq!(g.remaining_gas(), 40);
    assert!(
        g.verify_and_spend_gas(41, 1).is_err(),
        "over budget refused"
    );
    g.verify_and_spend_gas(40, 1).expect("exact remainder ok");
    assert_eq!(g.remaining_gas(), 0);
    assert!(
        g.verify_and_spend_gas(1, 1).is_err(),
        "empty budget refuses"
    );
    assert!(
        g.verify_and_spend_gas(1, 99_999).is_err(),
        "expiry checked with block time"
    );
}

#[test]
fn session_registry_enforces_every_dimension() {
    let (_sess, g, _spk) = test_grant(SCOPE_TRANSFER, 100, 50, 10_000);
    let reg = SessionKeyRegistry::default();
    let mut sim = SessionSpendSim::default();
    // Lazy first use: the carried grant is the ceiling, in-flight sim counts.
    reg.check(&g, 10, 60, SCOPE_TRANSFER, 1, &mut sim)
        .expect("first use ok");
    assert!(
        reg.check(&g, 10, 41, SCOPE_TRANSFER, 1, &mut sim).is_err(),
        "sim accumulates: 60+41 > 100"
    );
}

#[test]
fn session_registry_record_never_widens_and_flags_terminal_states() {
    use stellereum::zkml::SessionRegistryError;
    let (_sess, g, spk) = test_grant(SCOPE_TRANSFER, 100, 50, 10_000);
    let mut reg = SessionKeyRegistry::default();
    reg.note_applied(&g, 30);
    let rec: SessionKeyRecord = reg.get(&spk).expect("registered").clone();
    assert_eq!((rec.gas_spent, rec.max_gas_spend), (30, 100));
    // A re-presented grant with BIGGER ceilings cannot widen the record —
    // only gas_spent moves after registration.
    let (_s2, big, _p2) = test_grant(u64::MAX, 10_000, u64::MAX, 99_999);
    let mut big = big;
    big.session_pubkey = spk;
    reg.note_applied(&big, 10);
    let rec2 = reg.get(&spk).expect("still registered");
    assert_eq!(rec2.max_gas_spend, 100, "ceilings frozen at registration");
    assert_eq!(rec2.scope, SCOPE_TRANSFER);
    assert_eq!(rec2.gas_spent, 40, "only spend accumulates");

    let mut sim = SessionSpendSim::default();
    assert_eq!(
        reg.check(&g, 10, 61, SCOPE_TRANSFER, 1, &mut sim),
        Err(SessionRegistryError::BudgetExhausted),
        "30 spent + 61 > 100"
    );
    assert_eq!(
        reg.check(&g, 10, 10, SCOPE_SVM_PAYLOAD, 1, &mut sim),
        Err(SessionRegistryError::OutOfScope)
    );
    assert_eq!(
        reg.check(&g, 51, 10, SCOPE_TRANSFER, 1, &mut sim),
        Err(SessionRegistryError::OutOfScope),
        "over the per-tx value cap"
    );
    assert_eq!(
        reg.check(&g, 10, 10, SCOPE_TRANSFER, 10_001, &mut sim),
        Err(SessionRegistryError::Expired)
    );
    // Master binding: another master's grant for the same session key.
    let other_master = SigningKey::from_bytes(&[0x33u8; 32]);
    let mut foreign = SessionKeyAuthorization::sign_delegation(
        &other_master,
        spk,
        10_000,
        100,
        SCOPE_TRANSFER,
        50,
        5757,
    );
    let _ = &mut foreign;
    assert_eq!(
        reg.check(&foreign, 10, 10, SCOPE_TRANSFER, 1, &mut sim),
        Err(SessionRegistryError::MasterMismatch)
    );
    // Terminal revocation via tombstone on a fresh registry.
    let mut reg2 = SessionKeyRegistry::default();
    reg2.note_tombstone(spk, g.master_address);
    assert!(reg2.is_revoked(&spk));
    assert_eq!(
        reg2.check(
            &g,
            10,
            10,
            SCOPE_TRANSFER,
            1,
            &mut SessionSpendSim::default()
        ),
        Err(SessionRegistryError::Revoked)
    );
    // Tombstones never overwrite an existing record.
    let mut reg3 = SessionKeyRegistry::default();
    reg3.note_applied(&g, 0);
    reg3.note_tombstone(spk, [0x99u8; 32]);
    assert_eq!(reg3.get(&spk).unwrap().master, g.master_address);
    assert!(!reg3.is_revoked(&spk));
}

// ===========================================================================
// Model registry access: permissionless but append-only, validated, bounded
// ===========================================================================

fn tiny_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
}

#[test]
fn model_registry_is_first_wins_validated_and_bounded() {
    use stellereum::zkml::ZkMlModelRegistry;
    let mut reg = ZkMlModelRegistry::default();
    // Anyone (no auth parameter) with a sound model registers.
    let h = reg
        .register([0x01u8; 32], tiny_model())
        .expect("first writer wins");
    assert_eq!(reg.get(&[0x01u8; 32]).unwrap().model_hash, h);
    // Second writer for the same id is refused — weights cannot be swapped.
    assert!(reg.register([0x01u8; 32], tiny_model()).is_err());
    // Malformed models never join: re-execution only ever sees valid shapes.
    assert!(reg
        .register([0x02u8; 32], QuantizedLinearModel::new(vec![]))
        .is_err());
    // Oversize models are refused (param cap), even when well-formed.
    let big = QuantizedLinearModel::new(vec![QuantizedLayer::new(
        200,
        100,
        vec![1i64; 200 * 100],
        vec![0i64; 100],
    )]);
    assert!(big.validate(), "shape-valid but too large");
    assert!(big.param_count() > MAX_ZKML_MODEL_PARAMS);
    assert!(reg.register([0x03u8; 32], big).is_err());
    // Proofs bind by hash: a forgery against the registered model fails.
    let rec = reg.get(&[0x01u8; 32]).unwrap();
    let forged =
        stellereum::zkml::ZkMlProof::forge_structural_proof(&tiny_model(), &[3, 4], &[999, 999]);
    assert!(
        forged.verify_inference(),
        "premise: structural check fooled"
    );
    assert!(!forged.verify_inference_against(&rec.model));
    let (_out, honest) = stellereum::zkml::ZkMlProof::prove_reexec(&tiny_model(), &[3, 4]);
    assert!(honest.verify_inference_against(&rec.model));
}
