//! Fail-closed Teleport zk-proof gate (audit W1).
//!
//! `TeleportBridgeEngine::process_deposit` used to accept deposits whose
//! optional proof passed the STRUCTURAL-only `verify_inference` — the exact
//! check the codebase proves is forgeable (`zkml` regression
//! `forged_proof_passes_structural_but_fails_sound_check`: the forgery PASSES
//! structural, FAILS `verify_inference_against`). The gate now verifies
//! proof-carrying deposits with the SOUND check against the model registered
//! for the deposit's route, and fails closed on unknown routes.
//!
//! These tests run the offline engine directly (the only path that can carry
//! a `zk_proof`: live `BridgeIntent::Deposit` sets `zk_proof: None`).

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{SupportedChain, TeleportBridgeEngine, TeleportDepositEvent};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, ZkMlProof};

/// Same model as the `zkml` forgery regression test.
fn model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
}

fn keys() -> Vec<SigningKey> {
    vec![
        SigningKey::from_bytes(&[0x11; 32]),
        SigningKey::from_bytes(&[0x22; 32]),
        SigningKey::from_bytes(&[0x33; 32]),
    ]
}

fn engine_with_quorum() -> (TeleportBridgeEngine, Vec<SigningKey>) {
    let ks = keys();
    let pubs = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    (TeleportBridgeEngine::new(pubs), ks)
}

/// A quorum-passing deposit event (2-of-3 DISTINCT signers), proof attached
/// by the caller. Fresh `source_tx_hash` per event so replay never fires.
fn event_with_proof(
    signers: &[SigningKey],
    tx: [u8; 32],
    asset: &str,
    amount: u64,
    proof: Option<ZkMlProof>,
) -> TeleportDepositEvent {
    let draft = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: tx,
        recipient: [8u8; 32],
        asset: asset.to_string(),
        amount,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = TeleportBridgeEngine::deposit_signing_message(&draft);
    // First two signers: DISTINCT, reaches the n=3 quorum of 2.
    let sigs = signers[..2]
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    TeleportDepositEvent {
        validator_signatures: sigs,
        zk_proof: proof,
        ..draft
    }
}

#[test]
fn forged_proof_rejected_on_the_bridge_money_path() {
    let (mut engine, signers) = engine_with_quorum();
    let m = model();
    engine
        .register_teleport_zk_model(SupportedChain::Ton, "USDT", m.clone())
        .expect("register the route model");

    // The codebase's own forgery fixture: structurally consistent,
    // Fiat-Shamir-bound, claiming outputs the model never produces.
    let forged = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[999, 999]);
    // Pin the premise: the OLD gate (structural-only) would have ACCEPTED this.
    assert!(
        forged.verify_inference(),
        "premise: the forgery passes the weak structural check"
    );
    assert!(
        !forged.verify_inference_against(&m),
        "premise: the forgery fails the sound check"
    );

    let ev = event_with_proof(&signers, [0xA1; 32], "USDT", 1_000, Some(forged));
    let err = engine
        .process_deposit(&ev)
        .expect_err("forged proof must be REJECTED on the money path");
    assert!(
        err.contains("zk-proof"),
        "rejection must name the zk-proof gate, got: {err}"
    );
    // Fail-closed = no state change: the tx hash must NOT be marked processed,
    // so it cannot poison a later honest retry.
    assert!(!engine.processed_source_txs.contains_key(&[0xA1; 32]));
}

#[test]
fn valid_proof_against_registered_model_accepted() {
    let (mut engine, signers) = engine_with_quorum();
    let m = model();
    engine
        .register_teleport_zk_model(SupportedChain::Ton, "USDT", m.clone())
        .expect("register the route model");

    let (_out, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
    let ev = event_with_proof(&signers, [0xB2; 32], "USDT", 5_000, Some(proof));
    assert_eq!(
        engine.process_deposit(&ev).expect("honest proof accepted"),
        5_000
    );
}

#[test]
fn proof_for_unknown_route_rejected_fail_closed() {
    let (mut engine, signers) = engine_with_quorum();
    let m = model();
    // Register ONLY the USDT route; the deposit below claims BTC.
    engine
        .register_teleport_zk_model(SupportedChain::Ton, "USDT", m.clone())
        .expect("register the USDT route");
    // Even a fully HONEST proof for another asset's route must fail closed:
    // no registered model for the claimed route, no mint.
    let (_out, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
    let mut ev = event_with_proof(&signers, [0xC3; 32], "BTC", 5_000, Some(proof));
    // Signatures must cover the actual claimed asset: rebuild them over the
    // BTC draft (the helper signs Ton/USDT-shaped drafts only for the default
    // asset; here re-sign explicitly).
    let msg = TeleportBridgeEngine::deposit_signing_message(&TeleportDepositEvent {
        validator_signatures: vec![],
        zk_proof: None,
        ..ev.clone()
    });
    ev.validator_signatures = signers[..2]
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let err = engine
        .process_deposit(&ev)
        .expect_err("unknown route must fail CLOSED");
    assert!(
        err.contains("no registered model"),
        "unknown-route rejection must say so, got: {err}"
    );
    assert!(!engine.processed_source_txs.contains_key(&[0xC3; 32]));
}

#[test]
fn proof_with_no_registered_model_anywhere_rejected() {
    // Empty registry: ANY proof-carrying deposit fails closed.
    let (mut engine, signers) = engine_with_quorum();
    let m = model();
    let (_out, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
    let ev = event_with_proof(&signers, [0xD4; 32], "USDT", 5_000, Some(proof));
    let err = engine
        .process_deposit(&ev)
        .expect_err("proof with empty registry must fail CLOSED");
    assert!(err.contains("no registered model"), "got: {err}");
}

#[test]
fn no_proof_deposit_behavior_unchanged() {
    // No zk-proof attached: the gate is skipped entirely. Quorum decides,
    // exactly as before the hardening — with AND without registry entries.
    let (mut engine, signers) = engine_with_quorum();
    let ev = event_with_proof(&signers, [0xE5; 32], "USDT", 1_000, None);
    assert_eq!(
        engine
            .process_deposit(&ev)
            .expect("no-proof + quorum still mints"),
        1_000
    );
    // Replay still rejected.
    assert!(
        engine.process_deposit(&ev).is_err(),
        "replay still rejected"
    );

    // Registering models must not change the no-proof path.
    let (mut engine2, signers2) = engine_with_quorum();
    engine2
        .register_teleport_zk_model(SupportedChain::Ton, "USDT", model())
        .expect("register");
    let ev2 = event_with_proof(&signers2, [0xE5; 32], "USDT", 1_000, None);
    assert_eq!(
        engine2
            .process_deposit(&ev2)
            .expect("no-proof + quorum still mints after registration"),
        1_000
    );

    // Sub-quorum no-proof deposits still fail on the QUORUM error, not the
    // zk gate (the zk gate must be unreachable without a proof).
    let (mut engine3, signers3) = engine_with_quorum();
    let draft = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: [0xF6; 32],
        recipient: [8u8; 32],
        asset: "USDT".to_string(),
        amount: 1_000,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = TeleportBridgeEngine::deposit_signing_message(&draft);
    let one_sig = vec![(
        signers3[0].verifying_key().to_bytes(),
        signers3[0].sign(&msg).to_vec(),
    )];
    let ev3 = TeleportDepositEvent {
        validator_signatures: one_sig,
        ..draft
    };
    let err = engine3
        .process_deposit(&ev3)
        .expect_err("sub-quorum must still fail");
    assert!(err.contains("quorum"), "quorum error preserved, got: {err}");
}

#[test]
fn route_id_is_pinned_and_exact() {
    // `<chain-discriminant>:<asset>`: Ton = 0. Exact match — case and
    // whitespace are significant (fail closed on near-misses).
    assert_eq!(
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ton, "USDT"),
        "0:USDT"
    );
    assert_ne!(
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ton, "usdt"),
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ton, "USDT"),
    );
    assert_ne!(
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ethereum, "USDT"),
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ton, "USDT"),
    );
}

#[test]
fn malformed_model_registration_refused() {
    let (mut engine, _) = engine_with_quorum();
    let bad = QuantizedLinearModel::new(vec![]);
    assert!(engine
        .register_teleport_zk_model(SupportedChain::Ton, "USDT", bad)
        .is_err());
}
