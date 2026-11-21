//! CLI chain-binding regression (contract D3).
//!
//! The CLI is a binary-only module, so the builders are included by path —
//! exactly like `liveness_alarm_tests.rs` includes `src/liveness_alarm.rs`.
//! These tests pin two properties the faucet/explorer contract requires:
//!
//! 1. every chain-aware CLI builder produces a transaction whose envelope
//!    commits to the requested chain id (`tx.chain_id() == Some(id)`), whose
//!    signature verifies in that domain, and which the height-gated admission
//!    verifier accepts after activation;
//! 2. when no `--chain-id` is supplied and the RPC cannot answer
//!    `stell_chainId`, a scheduled chain-binding activation turns that into a
//!    hard error BEFORE any transaction is built (fail-closed), while the
//!    unbound pre-activation fallback is preserved when binding is inactive.

#[allow(dead_code)]
#[path = "../src/cli/tx_builders.rs"]
mod tx_builders;

use std::sync::Mutex;

use stellereum::chain_binding::{
    ChainBindingActivation, CHAIN_BINDING_ACTIVATION_ENV, CHAIN_BINDING_NEVER,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::Transaction;

const ACTIVATION_HEIGHT: u64 = 10_000;
/// Nothing listens on port 1, so `ureq` fails deterministically and fast.
const OFFLINE_RPC: &str = "http://127.0.0.1:1";

/// Process-global env marker: `ChainBindingActivation::from_chain_spec` reads
/// it, so env-touching tests must not interleave.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct ActivationEnv {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ActivationEnv {
    fn arm(height: u64) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(CHAIN_BINDING_ACTIVATION_ENV, height.to_string());
        Self { _lock: lock }
    }

    fn disarm() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
        assert_eq!(
            ChainBindingActivation::from_chain_spec().height,
            CHAIN_BINDING_NEVER,
            "debug-build activation env must be unset for the legacy-shape check"
        );
        Self { _lock: lock }
    }
}

impl Drop for ActivationEnv {
    fn drop(&mut self) {
        std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
    }
}

/// The chain id this process actually verifies against (`STELL_CHAIN_ID`
/// override included), so the test is not pinned to the default deployment.
fn chain_id() -> u64 {
    stellereum::consensus::consensus_chain_id()
}

fn assert_bound(tx: &Transaction, cid: u64) {
    assert_eq!(
        tx.chain_id(),
        Some(cid),
        "CLI-built transaction must carry the chain id in its PQ envelope"
    );
    assert!(
        tx.verify_signature(),
        "bound CLI transaction must verify against its own signing message"
    );
    assert!(
        tx.verify_signature_for_chain(cid, true),
        "bound CLI transaction must verify in the requested chain domain"
    );
    assert!(
        !tx.verify_signature_for_chain(cid + 1, true),
        "bound CLI transaction must NOT verify on another chain id"
    );
    let activation = ChainBindingActivation::at_height(ACTIVATION_HEIGHT);
    // The real height-gated verifier used by mempool/block admission.
    let admitted = stellereum::consensus::verify_transaction_envelope_at_height_with_activation(
        tx,
        ACTIVATION_HEIGHT,
        &activation,
    );
    assert!(
        admitted.is_ok(),
        "height-gated envelope admission must accept the bound CLI transaction: {admitted:?}"
    );
}

#[test]
fn every_chain_aware_cli_builder_binds_the_envelope() {
    let cid = chain_id();
    let keypair = FalconKeypair::generate_from_seed(0x71);
    let sender = tx_builders::falcon_pq_address(&keypair);
    let validator = sender;

    assert_bound(
        &tx_builders::sign_pq_explicit_transfer_with_chain(
            &keypair, sender, 1, 21_000, 1, 0, 0, cid,
        ),
        cid,
    );

    assert_bound(
        &tx_builders::build_place_order_tx_with_chain(&keypair, 1, true, 250_000, 10, 2, cid),
        cid,
    );
    assert_bound(
        &tx_builders::build_cancel_order_tx_with_chain(&keypair, 9, 3, cid),
        cid,
    );
    assert_bound(
        &tx_builders::build_unjail_tx_with_chain(&keypair, validator, None, 4, cid),
        cid,
    );

    let session_kp = FalconKeypair::generate_from_seed(0x72);
    let session_pub = session_kp.public_key.clone();
    let grant = stellereum::zkml::SessionKeyAuthorization::sign_delegation_falcon512(
        &keypair,
        PqScheme::Falcon512,
        &session_pub,
        u64::MAX / 2,
        50_000,
        u64::MAX,
        u64::MAX,
        cid,
    );
    assert_bound(
        &tx_builders::build_session_grant_tx_with_chain(&keypair, &grant, 5, cid),
        cid,
    );

    let withdraw = stellereum::bridge::BridgeIntent::Withdraw {
        chain: stellereum::bridge::SupportedChain::Arbitrum,
        target_address: "0xabc".to_string(),
        amount: 1_000,
    };
    assert_bound(
        &tx_builders::build_bridge_intent_tx_with_chain(
            &keypair,
            std::slice::from_ref(&withdraw),
            6,
            cid,
        ),
        cid,
    );
}

#[test]
fn no_chain_id_and_unreachable_rpc_fails_closed_when_binding_is_scheduled() {
    let _env = ActivationEnv::arm(ACTIVATION_HEIGHT);

    let err = tx_builders::resolve_chain_id(OFFLINE_RPC, None)
        .expect_err("unresolvable chain id must fail closed once binding is scheduled");
    let msg = err.to_string();
    assert!(
        msg.contains("--chain-id"),
        "refusal must tell the operator how to fix it: {msg}"
    );

    // Model the command body: it must abort at resolution, never constructing
    // a transaction. The closure returning `Transaction` is the builder path.
    let keypair = FalconKeypair::generate_from_seed(0x73);
    let built: anyhow::Result<Transaction> = (|| {
        let cid = tx_builders::resolve_chain_id(OFFLINE_RPC, None)?.ok_or_else(|| {
            anyhow::anyhow!("chain id unresolved without an RPC; pass --chain-id")
        })?;
        Ok(tx_builders::build_unjail_tx_with_chain(
            &keypair,
            tx_builders::falcon_pq_address(&keypair),
            None,
            1,
            cid,
        ))
    })();
    assert!(
        built.is_err(),
        "a failing chain-id lookup must not produce a transaction"
    );
}

#[test]
fn explicit_chain_id_wins_without_any_rpc() {
    let _env = ActivationEnv::arm(ACTIVATION_HEIGHT);
    let cid = chain_id();
    let resolved = tx_builders::resolve_chain_id(OFFLINE_RPC, Some(cid))
        .expect("--chain-id must not require a reachable node");
    assert_eq!(resolved, Some(cid));
}

#[test]
fn pre_activation_offline_fallback_keeps_the_unbound_shape() {
    let _env = ActivationEnv::disarm();
    let resolved = tx_builders::resolve_chain_id(OFFLINE_RPC, None)
        .expect("binding inactive: an unreachable RPC must keep the legacy path");
    assert_eq!(resolved, None);
}
