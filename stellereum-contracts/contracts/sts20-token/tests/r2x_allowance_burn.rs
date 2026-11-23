//! R2-X regression: a FAILED delegated transfer must not consume the grant.
//!
//! `transfer_from` used to debit the allowance before calling
//! `execute_transfer`. `execute_transfer` can still refuse (insufficient
//! owner balance, fee dust with `net == 0`, an overflowing credit) and host
//! storage writes are immediate, so a refusal left the owner's allowance at
//! zero while no token moved. The live path now spends the grant only after
//! `execute_transfer` returns success.

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INSUFFICIENT_BALANCE,
    ERR_INVALID_ARGUMENT, SUCCESS,
};
use sts20_token::{allowance, approve, balance_of, burn, init, transfer_from};

fn approve_arg(owner: i64, spender: i64, amount: i64) -> i64 {
    owner * 10_000_000_000 + spender * 100_000 + amount
}

fn transfer_from_arg(spender: i64, from: i64, to: i64, amount: i64) -> i64 {
    spender * 100_000_000_000 + from * 10_000_000 + to * 100_000 + amount
}

fn allowance_arg(owner: i64, spender: i64) -> i64 {
    owner * 1_000_000 + spender
}

#[test]
fn r2x_insufficient_balance_does_not_burn_the_allowance() {
    reset_mock_state();
    assert_eq!(init(1_000_000), SUCCESS);
    assert_eq!(balance_of(1), 1_000_000);

    // Owner 1 grants spender 5 an allowance of 2,000.
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(approve_arg(1, 5, 2_000)), 1);
    assert_eq!(allowance(allowance_arg(1, 5)), 2_000);

    // The owner then burns most of the balance away (the grant stays 2,000).
    // `burn` with a raw (< 10^10) argument burns from the stored admin (1).
    assert_eq!(burn(999_000), 1_000);
    assert_eq!(balance_of(1), 1_000, "owner can no longer cover the grant");

    // The spender asks for the full grant: the owner cannot pay, so the
    // transfer must refuse AND leave the grant intact.
    set_mock_caller(id_to_caller(5));
    assert_eq!(
        transfer_from(transfer_from_arg(5, 1, 3, 2_000)),
        ERR_INSUFFICIENT_BALANCE
    );
    assert_eq!(
        allowance(allowance_arg(1, 5)),
        2_000,
        "a failed delegated transfer must not consume the allowance"
    );
    assert_eq!(balance_of(1), 1_000);
    assert_eq!(balance_of(3), 0);
}

#[test]
fn r2x_dust_refusal_does_not_burn_the_allowance() {
    reset_mock_state();
    assert_eq!(init(1_000_000), SUCCESS);

    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(approve_arg(1, 5, 10)), 1);

    // amount == 1 leaves net == 0 after the ceiling fee, which
    // `execute_transfer` refuses. The grant must survive.
    set_mock_caller(id_to_caller(5));
    assert_eq!(
        transfer_from(transfer_from_arg(5, 1, 3, 1)),
        ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        allowance(allowance_arg(1, 5)),
        10,
        "a refused dust transfer must not consume the allowance"
    );

    // A payable amount still spends exactly `amount` from the grant.
    assert_eq!(transfer_from(transfer_from_arg(5, 1, 3, 4)), 1);
    assert_eq!(allowance(allowance_arg(1, 5)), 6);
}
