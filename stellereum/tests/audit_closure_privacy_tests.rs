//! Audit closure: session-key scope/expiry/cap enforcement, zkML model
//! registry access.
//!
//! Pure unit tests (no engine). The confidential-gate (C1/C2), stealth
//! hygiene (C3) and viewing-key sections were deleted with the shielded
//! protocol removal: the opcodes, curves and state they covered no longer
//! exist.

use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::zkml::{
    QuantizedLayer, QuantizedLinearModel, SessionKeyAuthorization, SessionKeyRecord,
    SessionKeyRegistry, SessionSpendSim, MAX_ZKML_MODEL_PARAMS, SCOPE_ACTOR_SEND,
    SCOPE_SVM_PAYLOAD, SCOPE_TRANSFER,
};

// ===========================================================================
// Session keys: scope / expiry / cap enforcement (registry half)
// ===========================================================================

fn test_grant(
    scope: u64,
    max_gas: u64,
    max_value: u64,
    valid_until: u64,
) -> (FalconKeypair, SessionKeyAuthorization, [u8; 32]) {
    // FULL-PQ: grants verify through the post-quantum API only (classical
    // Ed25519 master/session schemes are refused), so both halves are Falcon.
    let master = FalconKeypair::generate_from_seed(0x11);
    let session = FalconKeypair::generate_from_seed(0x22);
    let session_pk = session.public_key.clone();
    let spk = derive_pq_address(PqScheme::Falcon512, &session_pk, &DEFAULT_SALT);
    let g = SessionKeyAuthorization::sign_delegation_falcon512(
        &master,
        PqScheme::Falcon512,
        &session_pk,
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
    let (sess, g, spk) = test_grant(SCOPE_TRANSFER, 100, 50, 10_000);
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
    let other_master = FalconKeypair::generate_from_seed(0x33);
    let mut foreign = SessionKeyAuthorization::sign_delegation_falcon512(
        &other_master,
        PqScheme::Falcon512,
        &sess.public_key,
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
    // Re-registering the BYTE-IDENTICAL model is an idempotent no-op (it
    // returns the same hash and leaves the record alone), so a retried
    // admission cannot bump a generation or rebuild the committed preimage.
    assert_eq!(
        reg.register([0x01u8; 32], tiny_model())
            .expect("byte-identical re-registration is idempotent"),
        h
    );
    // A DIFFERENT model under a taken id is still refused — weights cannot be
    // swapped under an existing id.
    let swapped = QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![1, 0, -1, 2],
        vec![0, -1],
    )]);
    assert!(
        reg.register([0x01u8; 32], swapped).is_err(),
        "different weights under a taken id must be refused"
    );
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
