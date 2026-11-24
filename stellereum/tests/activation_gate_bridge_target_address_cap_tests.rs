//! PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test
//! deliberately.
//!
//! `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` is compiled `u64::MAX` (INERT). The
//! 128-byte cap on `BridgeIntent::Withdraw.target_address` is therefore a no-op
//! at every height: a 1 MiB address is parked and committed exactly like a
//! normal one, and the request can still be refunded/released later.
//!
//! Enforcement lives in `BridgeIntent::validate_at_height` and in
//! `BridgeState::plan_at_height` (the settlement path). It is NOT a release
//! rule: `Release`/`Refund` never inspect the address length, so a long address
//! parked below the gate must remain finalizable after activation unless a
//! migration says otherwise.
//!
//! If the constant is lowered, `assert_cap_inert` fails in every test in this
//! file, so arming the gate cannot silently keep these assertions. The
//! post-activation block-path e2e is still missing; see
//! `docs/ACTIVATION_GATES.md`.

use stellereum::bridge::{
    validate_bridge_target_address_len, BridgeEffect, BridgeIntent, BridgePlan, BridgeState,
    PreV2ConsensusLookup, SupportedChain, MAX_BRIDGE_TARGET_ADDRESS_BYTES, REFUND_GRACE_SECS,
};
use stellereum::chain_spec::{
    bridge_target_address_cap_active_at, bridge_target_address_cap_height,
    set_bridge_target_address_cap_override, BRIDGE_TARGET_ADDRESS_CAP_HEIGHT,
};

const ONE_MIB: usize = 1024 * 1024;
const PAYER: [u8; 32] = [0x51u8; 32];
const NOW: u64 = 1_760_000_000;
const AMOUNT: u64 = 1_000_000_000;

/// Clears the thread-local override on drop so a panicking assertion cannot
/// leak a test activation into another test on the same worker thread.
struct CapGate;

impl Drop for CapGate {
    fn drop(&mut self) {
        set_bridge_target_address_cap_override(None);
    }
}

fn assert_cap_inert() {
    assert_eq!(
        BRIDGE_TARGET_ADDRESS_CAP_HEIGHT,
        u64::MAX,
        "the bridge target-address cap was armed; this file pins the pre-activation \
         acceptance and must be updated with a post-activation block-path e2e"
    );
    assert_eq!(bridge_target_address_cap_height(), u64::MAX);
    for height in [0u64, 1, 1_000, 253_000, 10_000_000, u64::MAX - 1, u64::MAX] {
        assert!(
            !bridge_target_address_cap_active_at(height),
            "the compiled cap must be inactive at every height, including {height}"
        );
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

fn assert_parked(plan: &BridgePlan, address: &str) {
    let parked = plan
        .state
        .pending_withdrawals
        .get(&0)
        .expect("the withdrawal must be parked exactly as before the gate existed");
    assert_eq!(parked.target_address, address);
    assert_eq!(parked.target_address.len(), address.len());
    assert_eq!(plan.state.next_withdrawal_id, 1);
    assert_eq!(plan.effects, vec![BridgeEffect::Park { amount: AMOUNT }]);
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[test]
fn pins_pre_activation_accepts_a_one_mib_target_address() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(None);
    assert_cap_inert();

    let huge = "a".repeat(ONE_MIB);
    let intent = withdraw_intent(&huge);

    // Both the pure helper and the height-indexed intent verdict keep the
    // historical acceptance at every reachable height.
    for height in [0u64, 1, 253_000, u64::MAX - 1, u64::MAX] {
        assert!(
            validate_bridge_target_address_len(&huge, height).is_ok(),
            "the cap helper must be a no-op at height {height}"
        );
        assert!(
            intent.validate_at_height(height).is_ok(),
            "an over-long withdrawal must still validate at height {height}"
        );
    }
    assert!(
        intent.validate().is_ok(),
        "the height-less VM check must keep the historical verdict"
    );

    let plan = plan_withdraw_at(&huge, 1)
        .expect("below the inert gate the historical acceptance must be byte-identical");
    assert_parked(&plan, &huge);
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[test]
fn pins_pre_activation_accepts_just_over_the_future_cap() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(None);
    assert_cap_inert();

    let over_by_one = "b".repeat(MAX_BRIDGE_TARGET_ADDRESS_BYTES + 1);
    assert_eq!(over_by_one.len(), MAX_BRIDGE_TARGET_ADDRESS_BYTES + 1);

    let plan = plan_withdraw_at(&over_by_one, 42)
        .expect("pre-activation, one byte over the future cap is still accepted");
    assert_parked(&plan, &over_by_one);

    // The exact future boundary is accepted too, so the post-activation test
    // can differ ONLY on the over-by-one case.
    let at_cap = "c".repeat(MAX_BRIDGE_TARGET_ADDRESS_BYTES);
    let boundary = plan_withdraw_at(&at_cap, 42)
        .expect("pre-activation, an address at the future cap is accepted");
    assert_parked(&boundary, &at_cap);
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[test]
fn pins_pre_activation_long_address_can_still_be_refunded() {
    let _gate = CapGate;
    set_bridge_target_address_cap_override(None);
    assert_cap_inert();

    let huge = "d".repeat(ONE_MIB);
    let parked = plan_withdraw_at(&huge, 1).expect("the long request is parked while inert");
    assert_parked(&parked, &huge);

    // Release/Refund never consult the address cap. A long address parked
    // before the gate must remain finalizable after it; this pins that the cap
    // is a Withdraw-time rule, not a release-time rule.
    for height in [0u64, 1, 42, u64::MAX - 1] {
        assert!(
            BridgeIntent::Release { req_id: 0 }
                .validate_at_height(height)
                .is_ok(),
            "Release must not gain a target-address length check at height {height}"
        );
        assert!(
            BridgeIntent::Refund { req_id: 0 }
                .validate_at_height(height)
                .is_ok(),
            "Refund must not gain a target-address length check at height {height}"
        );
    }

    // Refund after the grace window: the long-target request is fully
    // finalizable with the cap inert.
    let refund_at = NOW + REFUND_GRACE_SECS + 1;
    let refunded = parked
        .state
        .plan_at_height(
            &[BridgeIntent::Refund { req_id: 0 }],
            &[],
            PAYER,
            refund_at,
            2,
            11,
            &PreV2ConsensusLookup,
        )
        .expect("a long-target withdrawal parked while inert must remain refundable");
    assert_eq!(
        refunded.effects,
        vec![BridgeEffect::Unpark {
            recipient: PAYER,
            amount: AMOUNT,
        }]
    );
    assert!(
        refunded.state.pending_withdrawals.is_empty(),
        "the refund removes the parked request"
    );
    assert!(
        refunded.state.refunded_withdrawals.contains(&0),
        "the refund tombstone is written exactly as for any other request"
    );
}
