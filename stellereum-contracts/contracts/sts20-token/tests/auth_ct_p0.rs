//! CT-P0 auth matrix for STS-20 (audit KI-38): stranger refused with the
//! exact error code and balances untouched; authenticated admin/owner flows
//! succeed; allowance replay beyond grant is refused.

use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller, ERR_UNAUTHORIZED};
use sts20_token::{
    allowance, approve, balance_of, burn, init, mint, total_supply, transfer, transfer_from,
};

#[test]
fn ct_p0_stranger_transfer_refused_exact_and_untouched() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Stranger (mock caller = zero address) forges from=admin(1).
    let packed = 100_000_000 + 99 * 100_000 + 10_000;
    assert_eq!(transfer(packed), ERR_UNAUTHORIZED);
    assert_eq!(balance_of(1), 1_000_000);
    assert_eq!(balance_of(99), 0);
}

#[test]
fn ct_p0_admin_transfer_succeeds_with_fee() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    set_mock_caller(id_to_caller(1));
    let packed = 100_000_000 + 2 * 100_000 + 10_000;
    assert_eq!(transfer(packed), 1);
    assert_eq!(balance_of(2), 9_950);
    assert_eq!(balance_of(99), 50);
    assert_eq!(balance_of(1), 990_000);
}

#[test]
fn ct_p0_forged_burn_and_mint_refused_exact() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Forged admin_id with zero-address caller.
    assert_eq!(burn(10_000_000_000 + 40_000), ERR_UNAUTHORIZED);
    assert_eq!(mint(10_000_000_000 + 50_000), ERR_UNAUTHORIZED);
    assert_eq!(balance_of(1), 1_000_000);
    assert_eq!(total_supply(0), 1_000_000);
    // Authenticated admin burns and mints fine.
    set_mock_caller(id_to_caller(1));
    assert_eq!(burn(40_000), 960_000);
    assert_eq!(mint(50_000), 1_010_000);
}

#[test]
fn ct_p0_forged_approve_and_transfer_from_refused() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Stranger grants themselves an allowance on admin funds: refused.
    let forged_approve = 10_000_000_000 + 5 * 100_000 + 2_000;
    assert_eq!(approve(forged_approve), ERR_UNAUTHORIZED);
    assert_eq!(allowance(1_000_000 + 5), 0);
    // Owner grants, stranger (not spender 5) tries to spend: refused.
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(forged_approve), 1);
    set_mock_caller(id_to_caller(99));
    let tf = 5 * 100_000_000_000 + 10_000_000 + 3 * 100_000 + 1_000;
    assert_eq!(transfer_from(tf), ERR_UNAUTHORIZED);
    // Real spender spends within grant, then replay beyond grant is refused.
    set_mock_caller(id_to_caller(5));
    assert_eq!(transfer_from(tf), 1);
    assert_eq!(allowance(1_000_000 + 5), 1_000);
    assert_eq!(transfer_from(tf), 1);
    assert_eq!(allowance(1_000_000 + 5), 0);
    assert_eq!(transfer_from(tf), ERR_UNAUTHORIZED);
    assert_eq!(allowance(1_000_000 + 5), 0);
}
