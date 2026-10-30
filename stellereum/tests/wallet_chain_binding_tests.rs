//! PLAN-BINDING rollout-gap regression tests (phase-3 enforcement, in-scope
//! wiring): legacy unbound envelopes are REFUSED at/after the activation
//! height and verified under the old rules before it.
//!
//! Covers the four rollout cases through the height-gated consensus verify
//! path (`consensus::verify_transaction_envelope_at_height_with_activation`)
//! and the wallet-side envelope pre-check
//! (`WalletAccount::check_envelope_binding_at_height`), both fed by the
//! wallet constructors:
//!
//! 1. bound envelope verifies (same chain, pre- AND post-activation);
//! 2. unbound pre-activation verifies (history compat);
//! 3. unbound post-activation refuses (pinned refusal prefix);
//! 4. cross-chain replay (envelope bound to another chain) refuses at EVERY
//!    height, pre- and post-activation.
//!
//! Activation is explicit (`ChainBindingActivation::at_height`) — never the
//! ambient environment — and default-OFF (`never()`) admits unbound at any
//! height, so no unilateral activation. No wire-format assertions on bound
//! envelopes beyond the existing constructor vectors (untouched).

use stellereum::chain_binding::{ChainBindingActivation, UNBOUND_REFUSED_ERR_PREFIX};
use stellereum::consensus::{
    set_consensus_chain_id_for_tests, verify_transaction_envelope_at_height_with_activation,
};
use stellereum::wallet::WalletAccount;

const TEST_CHAIN_ID: u64 = 5757;
const OTHER_CHAIN_ID: u64 = 9999;
const ACTIVATION_HEIGHT: u64 = 10_000;

/// Pin this test binary's thread to the test chain id (thread-local: no
/// effect on other tests) and return a guard value restoring the default.
fn pin_test_chain() -> ChainGuard {
    set_consensus_chain_id_for_tests(TEST_CHAIN_ID);
    ChainGuard
}

struct ChainGuard;

impl Drop for ChainGuard {
    fn drop(&mut self) {
        set_consensus_chain_id_for_tests(0);
    }
}

fn wallet() -> WalletAccount {
    WalletAccount::from_seed(&[0xA1u8; 32])
}

#[test]
fn bound_envelope_verifies_before_and_after_activation() {
    let _guard = pin_test_chain();
    let activation = ChainBindingActivation::at_height(ACTIVATION_HEIGHT);
    let w = wallet();
    let tx = w.create_bound_transaction([0x99u8; 32], 1_000, 5, 0, 0, TEST_CHAIN_ID);
    assert!(tx.chain_id().is_some(), "bound fixture must carry chain id");
    assert!(
        verify_transaction_envelope_at_height_with_activation(&tx, ACTIVATION_HEIGHT - 1, &activation)
            .is_ok(),
        "bound envelope must verify pre-activation"
    );
    assert!(
        verify_transaction_envelope_at_height_with_activation(&tx, ACTIVATION_HEIGHT, &activation)
            .is_ok(),
        "bound envelope must verify at activation"
    );
    assert!(
        verify_transaction_envelope_at_height_with_activation(&tx, ACTIVATION_HEIGHT + 1, &activation)
            .is_ok(),
        "bound envelope must verify post-activation"
    );
    // Wallet-side pre-check agrees at every height.
    for height in [0, ACTIVATION_HEIGHT - 1, ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 1] {
        assert!(
            WalletAccount::check_envelope_binding_at_height(&tx, height, &activation, TEST_CHAIN_ID)
                .is_ok(),
            "wallet pre-check must pass bound envelope at height {height}"
        );
    }
}

#[test]
fn unbound_pre_activation_verifies_compat() {
    let _guard = pin_test_chain();
    let activation = ChainBindingActivation::at_height(ACTIVATION_HEIGHT);
    let w = wallet();
    let tx = w.unbound_legacy_transfer([0x99u8; 32], 1_000, 5, 0, 0);
    assert_eq!(tx.chain_id(), None, "legacy fixture must stay unbound");
    assert!(
        verify_transaction_envelope_at_height_with_activation(&tx, ACTIVATION_HEIGHT - 1, &activation)
            .is_ok(),
        "unbound envelope must verify pre-activation (history compat)"
    );
    assert!(
        WalletAccount::check_envelope_binding_at_height(
            &tx,
            ACTIVATION_HEIGHT - 1,
            &activation,
            TEST_CHAIN_ID
        )
        .is_ok(),
        "wallet pre-check must pass unbound envelope pre-activation"
    );
}

#[test]
fn unbound_post_activation_refuses_with_pinned_prefix() {
    let _guard = pin_test_chain();
    let activation = ChainBindingActivation::at_height(ACTIVATION_HEIGHT);
    let w = wallet();
    let tx = w.unbound_legacy_transfer([0x99u8; 32], 1_000, 5, 0, 0);
    for height in [ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 1] {
        let err = verify_transaction_envelope_at_height_with_activation(&tx, height, &activation)
            .expect_err("unbound envelope must be refused at/after activation");
        assert!(
            err.starts_with(UNBOUND_REFUSED_ERR_PREFIX),
            "refusal must carry the pinned prefix, got: {err}"
        );
        assert!(
            err.contains(&ACTIVATION_HEIGHT.to_string()),
            "refusal must name the activation height, got: {err}"
        );
        assert!(
            err.contains(&TEST_CHAIN_ID.to_string()),
            "refusal must name the chain id to bind, got: {err}"
        );
        let werr = WalletAccount::check_envelope_binding_at_height(&tx, height, &activation, TEST_CHAIN_ID)
            .expect_err("wallet pre-check must refuse unbound post-activation");
        assert!(
            werr.starts_with(UNBOUND_REFUSED_ERR_PREFIX),
            "wallet refusal must carry the pinned prefix, got: {werr}"
        );
    }
}

#[test]
fn cross_chain_replay_refuses_at_every_height() {
    let _guard = pin_test_chain();
    let activation = ChainBindingActivation::at_height(ACTIVATION_HEIGHT);
    let w = wallet();
    // Signed bound to ANOTHER chain, verified on this one: the replay.
    let tx = w.create_bound_transaction([0x99u8; 32], 1_000, 5, 0, 0, OTHER_CHAIN_ID);
    assert_eq!(tx.chain_id(), Some(OTHER_CHAIN_ID));
    for height in [0, ACTIVATION_HEIGHT - 1, ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 1] {
        assert!(
            verify_transaction_envelope_at_height_with_activation(&tx, height, &activation).is_err(),
            "cross-chain replay must refuse at height {height}"
        );
    }
}

#[test]
fn default_off_never_activates_unilaterally() {
    let _guard = pin_test_chain();
    let never = ChainBindingActivation::never();
    let w = wallet();
    let unbound = w.unbound_legacy_transfer([0x99u8; 32], 1_000, 5, 0, 0);
    // Even at the top of the height range, the default admits unbound:
    // enforcement requires an explicitly configured height.
    assert!(
        verify_transaction_envelope_at_height_with_activation(&unbound, u64::MAX - 1, &never).is_ok(),
        "default-off activation must admit unbound at any height"
    );
    assert!(
        WalletAccount::check_envelope_binding_at_height(&unbound, u64::MAX - 1, &never, TEST_CHAIN_ID)
            .is_ok(),
        "wallet pre-check must admit unbound while activation is unset"
    );
}
