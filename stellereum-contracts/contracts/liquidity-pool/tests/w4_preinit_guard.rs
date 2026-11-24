//! W4 regression: `liquidity-pool` must reject `deposit`, `withdraw`,
//! `swap_a_for_b`, and `swap_b_for_a` before `init()` sets `SLOT_INITIALIZED`.

use liquidity_pool::{
    deposit, get_reserve_a, get_reserve_b, get_total_shares, init, shares_of, swap_a_for_b,
    swap_b_for_a, withdraw,
};
use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INSUFFICIENT_BALANCE, ERR_UNAUTHORIZED,
};

fn dep_pack(user: i64, a: i64, b: i64) -> i64 {
    user * 10_000_000_000 + a * 100_000 + b
}

fn wd_pack(user: i64, shares: i64) -> i64 {
    user * 1_000_000 + shares
}

#[test]
fn w4_preinit_deposit_and_swaps_rejected_no_share_inflation() {
    reset_mock_state();

    // Attacker attempts pre-init deposit and swaps before `init(30)` runs.
    set_mock_caller(id_to_caller(7));
    assert_eq!(deposit(dep_pack(7, 1, 1)), ERR_UNAUTHORIZED);
    assert_eq!(shares_of(7), 0);
    assert_eq!(get_total_shares(0), 0);
    assert_eq!(get_reserve_a(0), 0);
    assert_eq!(get_reserve_b(0), 0);

    assert_eq!(swap_a_for_b(1_000), ERR_UNAUTHORIZED);
    assert_eq!(swap_b_for_a(1_000), ERR_UNAUTHORIZED);
    assert_eq!(withdraw(wd_pack(7, 1)), ERR_UNAUTHORIZED);

    // Initialize pool and perform legitimate victim deposit.
    assert_eq!(init(30), 30);
    set_mock_caller(id_to_caller(1));
    assert_eq!(deposit(dep_pack(1, 10_000, 40_000)), 25_000);
    assert_eq!(shares_of(1), 25_000);

    // Attacker has zero shares and cannot withdraw victim liquidity.
    set_mock_caller(id_to_caller(7));
    assert_eq!(shares_of(7), 0);
    assert_eq!(withdraw(wd_pack(7, 1)), ERR_INSUFFICIENT_BALANCE);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);
    assert_eq!(get_total_shares(0), 25_000);
}
