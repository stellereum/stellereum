//! S9 / S6-4: bounded bridge withdrawal `target_address`.
//!
//! `TeleportWithdrawalRequest.target_address` used to be checked only
//! non-empty and was committed into `pending_withdrawals`, while the bridge
//! rate limit counted AMOUNT only — an attacker could park arbitrarily large
//! strings for free and grow consensus state without bound.
//!
//! The fix is height-gated by
//! `chain_spec::BRIDGE_TARGET_ADDRESS_CAP_HEIGHT`, compiled `u64::MAX`
//! (disabled) so the live `{0}` chain and every historical replay are
//! byte-identical:
//!  * below the gate a 1 MiB address is still accepted (compatibility proof);
//!  * at/above the gate it is refused with an error naming the limit;
//!  * a normal on-chain address still parks at/above the gate;
//!  * the cap is exactly `MAX_BRIDGE_TARGET_ADDRESS_BYTES` (edge accepted,
//!    one byte over refused).

use stellereum::bridge::{
    validate_bridge_target_address_len, BridgeEffect, BridgeIntent, BridgePlan, BridgeState,
    PreV2ConsensusLookup, SupportedChain, MAX_BRIDGE_TARGET_ADDRESS_BYTES,
};
use stellereum::chain_spec::{
    bridge_target_address_cap_active_at, set_bridge_target_address_cap_override,
    BRIDGE_TARGET_ADDRESS_CAP_HEIGHT,
};

const ONE_MIB: usize = 1024 * 1024;
const PAYER: [u8; 32] = [0x51; 32];
const NOW: u64 = 1_760_000_000;
const AMOUNT: u64 = 1_000_000_000;

/// Clear the thread-local activation override even when an assertion panics.
struct CapGate;

impl Drop for CapGate {
    fn drop(&mut self) {
        set_bridge_target_address_cap_override(None);
    }
}

fn withdraw_intent(target_address: &str) -> BridgeIntent {
    BridgeIntent::Withdraw {
        chain: SupportedChain::Ton,
        target_address: target_address.to_string(),
        amount: AMOUNT,
    }
}

fn plan_withdraw_at(target_address: &str, block_height: u64) -> Result<BridgePlan, String> {
    BridgeState::default().plan_at_height(
        &[withdraw_intent(target_address)],
        &[],
        PAYER,
        NOW,
        block_height,
        11,
        &PreV2ConsensusLookup,
    )
}

#[test]
fn h9_below_gate_accepts_a_one_mib_target_address() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(None);

    // Compiled state: the cap is DISABLED, so no live height is at/above it.
    assert_eq!(BRIDGE_TARGET_ADDRESS_CAP_HEIGHT, u64::MAX);
    assert!(!bridge_target_address_cap_active_at(0));
    assert!(!bridge_target_address_cap_active_at(u64::MAX));

    let huge = "a".repeat(ONE_MIB);
    let intent = withdraw_intent(&huge);
    // VM-level (height-less) validation keeps the historical verdict too.
    assert!(
        intent.validate().is_ok(),
        "below the disabled gate the height-less validate() must not change"
    );

    let plan = plan_withdraw_at(&huge, 1)
        .expect("below the gate the historical acceptance must be byte-identical");
    let parked = plan
        .state
        .pending_withdrawals
        .get(&0)
        .expect("the withdrawal must be parked exactly as before");
    assert_eq!(parked.target_address.len(), ONE_MIB);
    assert_eq!(parked.target_address, huge);
    assert_eq!(plan.state.next_withdrawal_id, 1);
    assert_eq!(plan.effects, vec![BridgeEffect::Park { amount: AMOUNT }]);

    // The pure helper is a no-op below the gate at every reachable height.
    assert!(validate_bridge_target_address_len(&huge, u64::MAX - 1).is_ok());
}

#[test]
fn h9_below_gate_with_scheduled_activation_still_accepts() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(Some(100));

    let huge = "b".repeat(ONE_MIB);
    assert!(!bridge_target_address_cap_active_at(99));
    assert!(bridge_target_address_cap_active_at(100));

    let plan = plan_withdraw_at(&huge, 99)
        .expect("one height below the gate must keep the historical acceptance");
    assert_eq!(
        plan.state.pending_withdrawals[&0].target_address.len(),
        ONE_MIB
    );
}

#[test]
fn h9_at_or_above_gate_refuses_the_one_mib_address_and_names_the_limit() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(Some(100));

    let huge = "c".repeat(ONE_MIB);
    for height in [100, 101, u64::MAX] {
        let err = plan_withdraw_at(&huge, height)
            .expect_err("at/above the gate an over-long target address must be refused");
        assert!(
            err.contains("MAX_BRIDGE_TARGET_ADDRESS_BYTES"),
            "error must name the limit, got: {err}"
        );
        assert!(
            err.contains(&MAX_BRIDGE_TARGET_ADDRESS_BYTES.to_string()),
            "error must name the numeric cap, got: {err}"
        );
        assert!(
            err.contains(&ONE_MIB.to_string()),
            "error must report the offending length, got: {err}"
        );
        assert!(
            err.starts_with("bridge withdrawal rejected:"),
            "the settlement path must attribute the refusal, got: {err}"
        );
    }
}

#[test]
fn h9_intent_validation_is_height_indexed_and_names_the_limit() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(Some(500));

    let huge = "d".repeat(MAX_BRIDGE_TARGET_ADDRESS_BYTES + 1);
    let intent = withdraw_intent(&huge);
    assert!(
        intent.validate_at_height(499).is_ok(),
        "below the gate the height-indexed verdict is the historical one"
    );
    let err = intent
        .validate_at_height(500)
        .expect_err("at the gate the over-long address must be refused");
    assert!(
        err.contains("MAX_BRIDGE_TARGET_ADDRESS_BYTES (128)"),
        "the error must name the limit and its value, got: {err}"
    );

    // Exactly at the byte cap is still accepted.
    let edge = "e".repeat(MAX_BRIDGE_TARGET_ADDRESS_BYTES);
    assert!(withdraw_intent(&edge).validate_at_height(500).is_ok());
    assert!(validate_bridge_target_address_len(&edge, 500).is_ok());
    assert!(validate_bridge_target_address_len(&huge, 500).is_err());
}

#[test]
fn h9_a_normal_address_still_works_at_and_above_the_gate() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(Some(0));

    // A real TON friendly address shape; every supported chain fits well
    // inside the cap.
    let normal = "EQD4FPq-PRDieyQKkKZ085";
    assert!(normal.len() < MAX_BRIDGE_TARGET_ADDRESS_BYTES);

    for height in [0, 1, 42] {
        let plan = plan_withdraw_at(normal, height)
            .unwrap_or_else(|e| panic!("a normal address must park at height {height}: {e}"));
        assert_eq!(plan.state.pending_withdrawals[&0].target_address, normal);
        assert_eq!(plan.effects, vec![BridgeEffect::Park { amount: AMOUNT }]);
    }

    // The height-less entry point also sees a gate active from genesis.
    assert!(withdraw_intent(normal).validate().is_ok());
}
