//! P1 PoC: liquidity-pool `withdraw` floors payouts, burning shares for ~nothing.
//! 1 share of (10_000 A / 40_000 B, 25_000 total) redeems 0 A + 1 B:
//! the A-leg is kept by the pool while the share is still burned.
//! Invariant: every redeemed share must pay >0 of each non-empty reserve.

use liquidity_pool::{deposit, init, withdraw};
use stellereum_contract_sdk::reset_mock_state;

#[test]
fn poc_p1_withdraw_dust_burns_shares_for_zero() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    let dep = 10_000_000_000 + 10_000 * 100_000 + 40_000;
    assert_eq!(deposit(dep), 25_000);
    // Redeem a single share: floor(1*10_000/25_000) = 0 of reserve A.
    let payout_a = withdraw(1_000_000 + 1);
    assert!(
        payout_a > 0,
        "1-share withdraw paid 0 of reserve A but burned the share (P1)"
    );
}
