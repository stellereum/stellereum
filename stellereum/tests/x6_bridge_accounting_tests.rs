//! S6 / x6 — bridge rate-window accounting regressions.
//!
//! The hourly withdrawal window is a SOLVENCY control: `hourly_withdrawn` is
//! the sum of the withdrawals parked inside the CURRENT window
//! ([`BridgeState::last_rate_limit_reset`], `+3600 s` of block time). A refund
//! un-parks value that never left, so it should release exactly the headroom
//! that request occupied — and only while that request still belongs to the
//! current window.
//!
//! The pre-fix code always did `hourly_withdrawn -= amount`, so refunding a
//! request parked in an EARLIER window subtracted an amount the current window
//! never counted. `saturating_sub` then wiped the current window's real usage
//! (and could be repeated with several pre-parked requests), letting more than
//! `HOURLY_RATE_LIMIT_NANO` leave in one hour: a rate-limit bypass worth one
//! extra full-window withdrawal per pre-parked request.
//!
//! These tests drive the pure policy (`BridgeState::plan_at_height`) and the
//! offline engine twin (`TeleportBridgeEngine::refund_withdrawal`), which share
//! the rule.

use std::collections::BTreeMap;

use stellereum::bridge::{
    set_bridge_v2_activation_override, BridgeIntent, BridgeState, PreV2ConsensusLookup,
    SupportedChain, TeleportBridgeEngine, TeleportWithdrawalRequest, HOURLY_RATE_LIMIT_NANO,
    REFUND_GRACE_SECS,
};

const STELL: u64 = 1_000_000_000;

/// Thread-local activation override: pin BRIDGE-FIX-FULL at genesis for this
/// test thread and clear it on drop (also on panic), like the sibling suites.
struct BridgeV2Gate;

impl BridgeV2Gate {
    fn active() -> Self {
        set_bridge_v2_activation_override(Some(0));
        Self
    }
}

impl Drop for BridgeV2Gate {
    fn drop(&mut self) {
        set_bridge_v2_activation_override(None);
    }
}

fn parked(
    req_id: u64,
    sender: [u8; 32],
    amount: u64,
    requested_at: u64,
    unlock_at: u64,
) -> TeleportWithdrawalRequest {
    TeleportWithdrawalRequest {
        req_id,
        sender,
        target_chain: SupportedChain::Ethereum,
        target_address: "0xdeadbeef".to_string(),
        amount,
        requested_at,
        unlock_at,
        executed: false,
    }
}

/// The refund becomes available this many seconds after parking (block clock).
fn refund_at(unlock_at: u64) -> u64 {
    unlock_at.saturating_add(REFUND_GRACE_SECS)
}

/// CONFIRMED BUG (pre-fix): refunding a request parked in an EARLIER rate
/// window must not erase the current window's usage.
///
/// Layout: 400k was parked 10 s ago (current window, still counted); 500k was
/// parked long ago (earlier window, outside the current window). At `now` the
/// sender refunds the old 500k request (legal: `now >= refund_at`) and tries a
/// fresh 500k withdrawal.
///
/// Correct verdict: the refund releases NO current-window headroom, so
/// 400k + 500k breaches the 500k cap and the whole payload is refused.
/// Pre-fix, the refund zeroed `hourly_withdrawn` and the 500k withdrawal was
/// admitted — 900k parked in one window against a 500k limit.
#[test]
fn refund_of_an_out_of_window_withdrawal_cannot_free_current_hour_headroom() {
    let _gate = BridgeV2Gate::active();
    let sender = [0x51u8; 32];
    let now = 100_000u64;
    // The current window opened 10 s before `now`, so it has NOT rolled over.
    let window_start = now - 10;
    assert!(
        now - window_start < 3600,
        "precondition: the current rate window must still be open"
    );

    let old_amount = 400_000 * STELL;
    let fresh_amount = 300_000 * STELL;
    assert!(
        fresh_amount + old_amount > HOURLY_RATE_LIMIT_NANO,
        "precondition: together they breach the hourly cap"
    );

    let state = BridgeState {
        pending_withdrawals: BTreeMap::from([
            // Parked at height/timestamp 0 => an EARLIER window.
            (0u64, parked(0, sender, old_amount, 0, 0)),
            // Parked inside the current window and already counted.
            (
                1u64,
                parked(1, sender, fresh_amount, window_start, window_start),
            ),
        ]),
        next_withdrawal_id: 2,
        hourly_withdrawn: fresh_amount,
        last_rate_limit_reset: window_start,
        ..BridgeState::default()
    };
    assert!(
        now >= refund_at(0),
        "precondition: the old request is refundable now"
    );

    let plan = state.plan_at_height(
        &[
            BridgeIntent::Refund { req_id: 0 },
            BridgeIntent::Withdraw {
                chain: SupportedChain::Ethereum,
                target_address: "0xfeed".to_string(),
                amount: old_amount,
            },
        ],
        &[],
        sender,
        now,
        0,
        11,
        &PreV2ConsensusLookup,
    );

    assert!(
        plan.is_err(),
        "a refund of an out-of-window withdrawal must not free current-window \
         headroom: 400k + 500k > 500k must be refused (got {plan:?})"
    );
}

/// Control: a refund of a request that WAS counted in the current window
/// accounting still releases exactly its own amount (the fix must not turn the
/// un-park into a no-op).
///
/// Note the window can only be "current" here because no withdrawal rolled it
/// for >24 h: a refund needs `unlock_at + REFUND_GRACE_SECS`, so an in-window
/// request can never be refunded while its one-hour window is still live. The
/// point of this case is the COUNTER, observed on the planned state.
#[test]
fn refund_of_a_counted_withdrawal_releases_exactly_its_own_amount() {
    let _gate = BridgeV2Gate::active();
    let sender = [0x52u8; 32];
    let now = 90_000u64;
    let window_start = 0u64;

    let refunded_amount = 100 * STELL;
    let other_amount = 400 * STELL;
    let state = BridgeState {
        pending_withdrawals: BTreeMap::from([(
            0u64,
            parked(0, sender, refunded_amount, window_start, window_start),
        )]),
        next_withdrawal_id: 1,
        hourly_withdrawn: refunded_amount + other_amount,
        last_rate_limit_reset: window_start,
        ..BridgeState::default()
    };
    assert!(
        now >= refund_at(window_start),
        "precondition: the request is refundable at `now`"
    );

    let plan = state
        .plan_at_height(
            &[BridgeIntent::Refund { req_id: 0 }],
            &[],
            sender,
            now,
            0,
            11,
            &PreV2ConsensusLookup,
        )
        .expect("the refund applies");

    assert_eq!(
        plan.state.hourly_withdrawn, other_amount,
        "the refund of a counted request must subtract exactly its amount, \
         leaving every other counted withdrawal in place"
    );
    assert!(!plan.state.pending_withdrawals.contains_key(&0));
}

/// The offline engine twin (`TeleportBridgeEngine::refund_withdrawal`, the
/// pre-activation path) must follow the same window rule.
#[test]
fn engine_refund_keeps_current_window_usage_for_an_older_request() {
    let sender = [0x53u8; 32];
    let now = refund_at(0) + 100;
    let window_start = now - 10;

    // Out-of-window request: must NOT release current-window headroom.
    let mut engine = TeleportBridgeEngine::new(vec![[1u8; 32]]);
    engine.last_rate_limit_reset = window_start;
    engine.hourly_withdrawn = 400 * STELL;
    let _ = engine
        .pending_withdrawals
        .insert(0, parked(0, sender, 500 * STELL, 0, 0)); // earlier window
    let refunded = engine
        .refund_withdrawal(0, sender, now)
        .expect("the sender may refund after the grace period");
    assert_eq!(refunded, 500 * STELL);
    assert_eq!(
        engine.hourly_withdrawn,
        400 * STELL,
        "an earlier-window refund must not erase the current window's usage"
    );

    // Counted request: DOES release exactly its own amount.
    let mut engine = TeleportBridgeEngine::new(vec![[1u8; 32]]);
    engine.last_rate_limit_reset = 0;
    engine.hourly_withdrawn = 500 * STELL;
    let _ = engine
        .pending_withdrawals
        .insert(0, parked(0, sender, 100 * STELL, 0, 0));
    assert_eq!(
        engine
            .refund_withdrawal(0, sender, 90_000)
            .expect("in-window refund"),
        100 * STELL
    );
    assert_eq!(
        engine.hourly_withdrawn,
        400 * STELL,
        "a counted refund subtracts exactly its own amount"
    );
}
