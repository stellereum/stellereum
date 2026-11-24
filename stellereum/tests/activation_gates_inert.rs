//! Pins the activation debt: three protocol gates exist in code but must NOT
//! be armed yet.
//!
//! WHY A TEST: `chain_spec` constants are easy to lower in a feature branch, and
//! arming one of these without its end-to-end proof changes consensus-visible
//! behaviour (contracts suddenly read `host.block_hash`, bridge releases hit a
//! new cap, cross-shard transfers demand an escrow). The Wave 2 rule is "no gate
//! without a test"; `feature_gates` already refuses a LIVE gate that names no
//! test, and this file refuses to let the three known-incomplete ones drift to a
//! concrete height by accident.
//!
//! When a gate is genuinely ready: add its e2e test, set the height, and update
//! both this file and `docs/feature_gates.yaml` (`stellereum gates --yaml`).

use stellereum::chain_spec;
use stellereum::feature_gates;

/// `u64::MAX` is the codebase's sentinel for "never": every gate site compares
/// `height >= CONSTANT`, and no consensus height reaches `u64::MAX`.
fn never_armed_at(height: u64, gate: u64) -> bool {
    if gate == u64::MAX {
        return false;
    }
    height >= gate
}

#[test]
fn the_three_incomplete_gates_are_still_inert() {
    assert_eq!(
        chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT,
        u64::MAX,
        "host.block_hash needs the parent-hash plumbing + a cross-node equality e2e"
    );
    assert_eq!(
        chain_spec::BRIDGE_TARGET_ADDRESS_CAP_HEIGHT,
        u64::MAX,
        "the 128-byte bridge target cap needs a release-path e2e and replay proof"
    );
    assert_eq!(
        chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT,
        u64::MAX,
        "bounce escrow needs the {0,1} shard prerequisites and a fresh-genesis decision"
    );
}

#[test]
fn inert_means_disabled_at_every_reachable_height() {
    // A spread that covers genesis, the live tip neighbourhood and far-future
    // heights, so a mis-set sentinel (0, 1, a recent height) is caught.
    for height in [0u64, 1, 1_000, 253_000, 10_000_000, u64::MAX - 1] {
        assert!(!never_armed_at(
            height,
            chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT
        ));
        assert!(!never_armed_at(
            height,
            chain_spec::BRIDGE_TARGET_ADDRESS_CAP_HEIGHT
        ));
        assert!(!never_armed_at(
            height,
            chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT
        ));
    }
}

#[test]
fn the_gate_manifest_agrees_with_the_constants() {
    let table = feature_gates::table();
    for (id, symbol, value) in [
        (
            "contract-block-hash",
            "CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT",
            chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT,
        ),
        (
            "bridge-target-address-cap",
            "BRIDGE_TARGET_ADDRESS_CAP_HEIGHT",
            chain_spec::BRIDGE_TARGET_ADDRESS_CAP_HEIGHT,
        ),
        (
            "xshard-bounce-escrow",
            "XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT",
            chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT,
        ),
    ] {
        let gate = table
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("{id} missing from the gate manifest"));
        assert_eq!(gate.symbol, symbol);
        assert_eq!(gate.value, value, "{id}: manifest drifted from chain_spec");
        assert_eq!(gate.status(), "INERT", "{id} is no longer inert");
        assert!(
            gate.test.is_none(),
            "{id} is inert, so it must not claim a proving test"
        );
    }
}
