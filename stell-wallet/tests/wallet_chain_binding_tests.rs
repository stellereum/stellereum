//! A14 chain-binding rollout: the wallet defaults to BOUND envelopes.
//!
//! Pins:
//! - `build_pq_transfer_tx_bound` / `build_pq_payload_tx_bound` produce
//!   chain-bound PQ envelopes that verify on their own chain and fail a
//!   strict check on any other chain (testnet signatures never replay).
//! - the legacy builders stay UNBOUND (verifying, but strict-refused) —
//!   the `--unbound-legacy` escape hatch, metered by the node.
//! - `Transaction::sign_with_chain_id` parity for the classical path is
//!   pinned in the `stellereum` lib (`wallet::tests`); this file pins the
//!   wallet-crate builders that the CLI actually calls.

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/pq.rs"]
mod pq;

use client::LightClient;
use pq::{generate_sample_keypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::Transaction;

const CHAIN: u64 = 5757;
const OTHER_CHAIN: u64 = 9999;

#[test]
fn bound_pq_transfer_verifies_only_on_its_chain() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let to = [0x55u8; 32];
    let tx = LightClient::build_pq_transfer_tx_bound(
        &kp,
        to,
        10_000_000_000,
        500_000,
        0,
        0,
        0,
        true,
        CHAIN,
    );
    let from_addr = kp.derive_address(&DEFAULT_SALT);
    assert_eq!(tx.from, from_addr);
    assert_eq!(tx.chain_id(), Some(CHAIN), "the bound builder must bind");
    assert!(tx.verify_signature(), "a bound PQ tx must verify on its chain");
    assert!(
        tx.verify_signature_for_chain(CHAIN, true),
        "strict check passes on the bound chain"
    );
    assert!(
        !tx.verify_signature_for_chain(OTHER_CHAIN, true),
        "a bound signature must never verify on another chain"
    );
}

#[test]
fn bound_pq_payload_carries_stake_and_binds() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let val = kp.derive_address(&DEFAULT_SALT);
    let payload = vec![stellereum::svm::OpCode::SysCallStake {
        validator: val,
        amount: 2_000_000_000_000,
    }];
    let tx = LightClient::build_pq_payload_tx_bound(
        &kp, val, 0, 500_000, 3, 0, 0, true, payload, CHAIN,
    );
    assert_eq!(tx.chain_id(), Some(CHAIN));
    assert!(tx.verify_signature());
    assert!(tx.verify_signature_for_chain(CHAIN, true));
    assert!(!tx.verify_signature_for_chain(OTHER_CHAIN, true));
}

#[test]
fn legacy_pq_builders_stay_unbound_but_verifying() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let legacy = LightClient::build_pq_transfer_tx(&kp, [0x55u8; 32], 1_000, 0, 0, true);
    assert_eq!(
        legacy.chain_id(),
        None,
        "the legacy builder must stay unbound (--unbound-legacy)"
    );
    assert!(
        legacy.verify_signature(),
        "unbound transactions still verify (replayable)"
    );
    assert!(
        !legacy.verify_signature_for_chain(CHAIN, true),
        "strict admission refuses the legacy envelope"
    );

    // The implicit steady-state envelope binds the same way.
    let steady = LightClient::build_pq_transfer_tx_bound(
        &kp,
        [0x55u8; 32],
        1_000,
        500_000,
        1,
        0,
        0,
        false,
        CHAIN,
    );
    assert_eq!(steady.chain_id(), Some(CHAIN));
    assert!(steady.verify_signature());
    assert!(!steady.verify_signature_for_chain(OTHER_CHAIN, true));
}

#[test]
fn transaction_chain_parity_between_paths() {
    // Classical parity (the CLI's ed25519 path) is pinned here at the seam:
    // bound verifies strictly on its chain only; unbound verifies loosely.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0xABu8; 32]);
    let to = [0x11u8; 32];
    let bound = Transaction::sign_with_chain_id(&sk, to, 1, 100_000, 0, 0, 0, CHAIN);
    assert!(bound.verify_signature_for_chain(CHAIN, true));
    assert!(!bound.verify_signature_for_chain(OTHER_CHAIN, true));
    let unbound = Transaction::sign(&sk, to, 1, 100_000, 0, 0, 0);
    assert!(unbound.verify_signature());
    assert!(!unbound.verify_signature_for_chain(CHAIN, true));
}
