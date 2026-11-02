//! Audit 6.0->8.0 regression pins for STS-20.
//!
//! - `transfer_from` validates `from`/`to`/`amount` BEFORE touching the
//!   allowance (a failed transfer must not burn the grant).
//! - CT-P1 dust: a transfer whose fee consumes the whole amount (net == 0)
//!   is refused fail-closed with funds untouched.
//! - `mint` overflows fail closed with `ERR_OVERFLOW` (white-box supply
//!   seed: the mock shares storage with the contract; slot 0 is the
//!   contract-internal total-supply slot, pinned here).

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, sstore, ERR_INVALID_ARGUMENT, ERR_OVERFLOW,
};
use sts20_token::{
    allowance, approve, balance_of, init, mint, total_supply, transfer, transfer_from,
};

#[test]
#[allow(clippy::identity_op)] // GATE: `id * BASE + ...` names packed fields; `+ 0` pins the zero-amount leg.
#[allow(clippy::erasing_op)] // GATE: `0 * BASE` documents the erased from-field in the invalid-from pin.
fn transfer_from_validates_before_burning_allowance() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Owner grants spender 5 an allowance of 2,000.
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(10_000_000_000 + 5 * 100_000 + 2_000), 1);
    assert_eq!(allowance(1_000_000 + 5), 2_000);

    set_mock_caller(id_to_caller(5));
    // Invalid `from` (0): refused, grant intact.
    let bad_from = 5 * 100_000_000_000 + 0 * 10_000_000 + 3 * 100_000 + 1_000;
    assert_eq!(transfer_from(bad_from), ERR_INVALID_ARGUMENT);
    assert_eq!(allowance(1_000_000 + 5), 2_000);
    // Zero amount: refused, grant intact.
    let zero_amt = 5 * 100_000_000_000 + 10_000_000 + 3 * 100_000 + 0;
    assert_eq!(transfer_from(zero_amt), ERR_INVALID_ARGUMENT);
    assert_eq!(allowance(1_000_000 + 5), 2_000);
    // Negative packed arg: refused, grant intact.
    assert_eq!(transfer_from(-1), ERR_INVALID_ARGUMENT);
    assert_eq!(allowance(1_000_000 + 5), 2_000);

    // Valid delegated transfer still works: 1,000 from 1 to 3 (fee 5).
    let ok = 5 * 100_000_000_000 + 10_000_000 + 3 * 100_000 + 1_000;
    assert_eq!(transfer_from(ok), 1);
    assert_eq!(allowance(1_000_000 + 5), 1_000);
    assert_eq!(balance_of(3), 995);
}

#[test]
fn dust_transfer_with_zero_net_refused() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    set_mock_caller(id_to_caller(1));
    // amount=1: fee=(1*50+9999)/10000=1, net=0 -> refused, nothing moves.
    let dust = 100_000_000 + 2 * 100_000 + 1;
    assert_eq!(transfer(dust), ERR_INVALID_ARGUMENT);
    assert_eq!(balance_of(1), 1_000_000);
    assert_eq!(balance_of(2), 0);
    assert_eq!(balance_of(99), 0);
    // amount=2 still works: fee=1, net=1.
    let tiny = 100_000_000 + 2 * 100_000 + 2;
    assert_eq!(transfer(tiny), 1);
    assert_eq!(balance_of(2), 1);
    assert_eq!(balance_of(99), 1);
    assert_eq!(balance_of(1), 1_000_000 - 2);
}

#[test]
fn mint_overflow_fails_closed() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Drive supply near i64::MAX; the next mint must refuse, not trap/wrap.
    sstore(0, i64::MAX - 10);
    set_mock_caller(id_to_caller(1));
    assert_eq!(mint(20), ERR_OVERFLOW);
    assert_eq!(total_supply(0), i64::MAX - 10);
    assert_eq!(balance_of(1), 1_000_000);
}
