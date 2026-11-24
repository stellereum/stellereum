//! W4 regression: `execute_transfer` must check recipient and treasury
//! overflow BEFORE writing any storage slot, and `transfer_from` must leave
//! balances, treasury, and allowance untouched on `ERR_OVERFLOW`.

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, sstore, ERR_OVERFLOW, SUCCESS,
};
use sts20_token::{allowance, approve, balance_of, init, transfer, transfer_from};

fn approve_arg(owner: i64, spender: i64, amount: i64) -> i64 {
    owner * 10_000_000_000 + spender * 100_000 + amount
}

fn transfer_arg(from: i64, to: i64, amount: i64) -> i64 {
    from * 100_000_000 + to * 100_000 + amount
}

fn transfer_from_arg(spender: i64, from: i64, to: i64, amount: i64) -> i64 {
    spender * 100_000_000_000 + from * 10_000_000 + to * 100_000 + amount
}

fn allowance_arg(owner: i64, spender: i64) -> i64 {
    owner * 1_000_000 + spender
}

#[test]
fn w4_treasury_overflow_is_atomic_and_preserves_allowance() {
    reset_mock_state();
    assert_eq!(init(1_000_000), SUCCESS);

    // Seed treasury (account 99, balance slot 1_000_000 + 99) near i64::MAX.
    sstore(1_000_099, i64::MAX - 1);

    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(approve_arg(1, 5, 5_000)), 1);

    // Delegated transfer of 1,000 incurs fee 5 -> treasury overflows i64::MAX.
    set_mock_caller(id_to_caller(5));
    assert_eq!(
        transfer_from(transfer_from_arg(5, 1, 3, 1_000)),
        ERR_OVERFLOW
    );

    // Zero mutation across sender, recipient, treasury, and allowance.
    assert_eq!(balance_of(1), 1_000_000);
    assert_eq!(balance_of(3), 0);
    assert_eq!(balance_of(99), i64::MAX - 1);
    assert_eq!(allowance(allowance_arg(1, 5)), 5_000);
}

#[test]
fn w4_to_treasury_aliasing_overflow_is_atomic() {
    reset_mock_state();
    assert_eq!(init(1_000_000), SUCCESS);

    // When `to == treasury` (99), total credit is `net + fee = amount`.
    // Seed 99 at `i64::MAX - 999`: `to + net` fits, `to + net + fee` overflows.
    sstore(1_000_099, i64::MAX - 999);

    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(approve_arg(1, 5, 2_000)), 1);

    set_mock_caller(id_to_caller(5));
    assert_eq!(
        transfer_from(transfer_from_arg(5, 1, 99, 1_000)),
        ERR_OVERFLOW
    );
    assert_eq!(balance_of(1), 1_000_000);
    assert_eq!(balance_of(99), i64::MAX - 999);
    assert_eq!(allowance(allowance_arg(1, 5)), 2_000);

    // Exact boundary (`i64::MAX - 1_000`) succeeds cleanly and lands at i64::MAX.
    sstore(1_000_099, i64::MAX - 1_000);
    assert_eq!(transfer_from(transfer_from_arg(5, 1, 99, 1_000)), 1);
    assert_eq!(balance_of(1), 999_000);
    assert_eq!(balance_of(99), i64::MAX);
    assert_eq!(allowance(allowance_arg(1, 5)), 1_000);
}

#[test]
fn w4_self_transfer_atomic_on_treasury_overflow() {
    reset_mock_state();
    assert_eq!(init(1_000_000), SUCCESS);

    set_mock_caller(id_to_caller(1));
    assert_eq!(transfer(transfer_arg(1, 1, 1_000)), 1);
    assert_eq!(balance_of(1), 999_995);
    assert_eq!(balance_of(99), 5);

    sstore(1_000_099, i64::MAX - 1);
    assert_eq!(transfer(transfer_arg(1, 1, 1_000)), ERR_OVERFLOW);
    assert_eq!(balance_of(1), 999_995);
    assert_eq!(balance_of(99), i64::MAX - 1);
}
