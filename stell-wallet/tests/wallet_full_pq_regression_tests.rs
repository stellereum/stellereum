//! Offline regression coverage for FULL-PQ wallet signing boundaries.

#[allow(dead_code)] // GATE: these modules are shared with the CLI.
#[path = "../src/client.rs"]
mod client;
#[allow(dead_code)] // GATE: these modules are shared with the CLI.
#[path = "../src/pq.rs"]
mod pq;
#[allow(dead_code)] // GATE: these modules are shared with the CLI.
#[path = "../src/rpc.rs"]
mod rpc;

#[test]
fn standard_signing_refuses_legacy_and_falcon_round_trips() {
    let seed = [42; 32];
    for scheme in [pq::WalletScheme::Ed25519, pq::WalletScheme::Hybrid] {
        assert!(pq::wallet_standard_signing_key(&seed, scheme).is_err());
    }
    let key = pq::wallet_standard_signing_key(&seed, pq::WalletScheme::Falcon512).unwrap();
    let signature = key.sign_message(5757, b"full-pq").unwrap();
    assert!(stellereum::wallet_signing::verify_message(
        &key.address(),
        5757,
        b"full-pq",
        &signature
    ));
    assert!(!stellereum::wallet_signing::verify_message(
        &key.address(),
        5758,
        b"full-pq",
        &signature
    ));
}

#[test]
fn consensus_builder_refuses_legacy_key_and_accepts_falcon() {
    let legacy = pq::PqKeyPair::from_seed(pq::PqScheme::Hybrid, &[7; 32]);
    assert!(client::LightClient::build_pq_transfer_tx_bound(
        &legacy, [1; 32], 1, 500_000, 0, 0, 0, true, 5757,
    )
    .is_err());
    let key = pq::PqKeyPair::from_seed(pq::PqScheme::Falcon512, &[7; 32]);
    let tx = client::LightClient::build_pq_transfer_tx_bound(
        &key, [1; 32], 1, 500_000, 0, 0, 0, true, 5757,
    )
    .expect("Falcon-512 transfer build");
    assert!(tx.verify_signature_for_chain(5757, true));
    assert!(!tx.verify_signature_for_chain(5758, true));
}
