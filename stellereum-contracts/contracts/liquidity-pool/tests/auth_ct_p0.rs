//! CT-P0 auth matrix for liquidity-pool (audit KI-38, same spoof class as
//! the poc_p0_* family): a forged user_id with the zero-address caller is
//! refused with the exact error code; the authenticated owner deposits and
//! withdraws normally.

use liquidity_pool::{deposit, get_reserve_a, init, shares_of, withdraw};
use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller, ERR_UNAUTHORIZED};

#[test]
fn ct_p0_forged_deposit_and_withdraw_refused_exact() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    // Stranger mints shares to victim id 1: refused, no shares created.
    let dep = 10_000_000_000 + 10_000 * 100_000 + 40_000;
    assert_eq!(deposit(dep), ERR_UNAUTHORIZED);
    assert_eq!(shares_of(1), 0);
    assert_eq!(get_reserve_a(0), 0);
    // Owner deposits, then a stranger drains the owner's shares: refused.
    set_mock_caller(id_to_caller(1));
    assert_eq!(deposit(dep), 25_000);
    set_mock_caller(id_to_caller(99));
    assert_eq!(withdraw(1_000_000 + 5_000), ERR_UNAUTHORIZED);
    assert_eq!(shares_of(1), 25_000);
    // Owner withdraws a fifth: succeeds (5k/25k of 10_000 reserve A).
    set_mock_caller(id_to_caller(1));
    assert_eq!(withdraw(1_000_000 + 5_000), 2_000);
    assert_eq!(shares_of(1), 20_000);
}
