//! W7 regression (W6-A4-5): `liquidity-pool` `swap_quote` and
//! `swap_quote_b_for_a` use checked `u128` arithmetic and return
//! `ERR_OVERFLOW` cleanly instead of trapping/panicking on huge reserves/inputs.

use liquidity_pool::{
    get_reserve_a, get_reserve_b, init, swap_a_for_b, swap_b_for_a, swap_quote, swap_quote_b_for_a,
};
use stellereum_contract_sdk::{reset_mock_state, sstore, ERR_OVERFLOW};

#[test]
fn w7_swap_quote_overflow_returns_err_overflow_without_panic() {
    reset_mock_state();
    assert_eq!(init(30), 30);

    // Seed huge reserves (slot 2 = reserve A, slot 3 = reserve B) near i64::MAX
    // so `y * dx * multiplier` exceeds u128::MAX.
    sstore(2, i64::MAX - 1);
    sstore(3, i64::MAX - 1);

    assert_eq!(swap_quote(i64::MAX), ERR_OVERFLOW);
    assert_eq!(swap_quote_b_for_a(i64::MAX), ERR_OVERFLOW);

    // Swap entry points propagate ERR_OVERFLOW and leave reserves untouched.
    assert_eq!(swap_a_for_b(i64::MAX), ERR_OVERFLOW);
    assert_eq!(swap_b_for_a(i64::MAX), ERR_OVERFLOW);
    assert_eq!(get_reserve_a(0), i64::MAX - 1);
    assert_eq!(get_reserve_b(0), i64::MAX - 1);
}
