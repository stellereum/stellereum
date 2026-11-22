//! P1 regression: liquidity-pool `withdraw` floored payouts, burning shares
//! for ~nothing. 1 share of (10_000 A / 40_000 B, 25_000 total) redeemed
//! 0 A + 1 B: the A-leg stayed in the pool while the share was still burned.
//! Fixed by refusing dust redemptions with `ERR_INVALID_ARGUMENT` (the same
//! fail-closed convention as zero-share `deposit` and zero-amount swaps),
//! leaving shares and reserves untouched.
//! Invariant: every executed redemption pays >0 of each non-empty reserve.

use liquidity_pool::{
    deposit, get_reserve_a, get_reserve_b, get_total_shares, init, shares_of, withdraw,
};
use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT,
};

#[test]
fn poc_p1_dust_withdraw_refused_without_burn() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    // CT-P0: deposit/withdraw bind user_id to host.caller — authenticate.
    set_mock_caller(id_to_caller(1));
    let dep = 10_000_000_000 + 10_000 * 100_000 + 40_000;
    assert_eq!(deposit(dep), 25_000);
    // Dust: floor(1*10_000/25_000) = 0 of reserve A -> refused, nothing moves.
    assert_eq!(withdraw(1_000_000 + 1), ERR_INVALID_ARGUMENT);
    assert_eq!(shares_of(1), 25_000, "dust refusal must not burn shares");
    assert_eq!(get_total_shares(0), 25_000);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);
    // Normal flows untouched: exact proportional payout (5k/25k of 10_165 A
    // after the lifecycle swaps would be 2_033; here reserves are intact).
    assert_eq!(withdraw(1_000_000 + 5_000), 2_000);
    assert_eq!(shares_of(1), 20_000);
    assert_eq!(get_total_shares(0), 20_000);
    assert_eq!(get_reserve_a(0), 10_000 - 2_000);
    assert_eq!(get_reserve_b(0), 40_000 - 8_000);
}
