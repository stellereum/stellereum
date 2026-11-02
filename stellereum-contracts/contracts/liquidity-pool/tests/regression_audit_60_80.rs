//! Audit 6.0->8.0 regression pins for liquidity-pool.
//!
//! - Unbounded swap inputs (`dx`/`dy` are raw caller-supplied i64s) must not
//!   wrap reserve math: a giant input fails closed with `ERR_OVERFLOW` and
//!   reserves are untouched. The quote itself uses u128 and stays exact.
//! - Deposit amounts are packing-bounded (<100_000 per leg), so deposit
//!   overflow is unreachable via the wire format; the checked close-out is
//!   pinned by the dust-withdraw harness.

use liquidity_pool::{
    deposit, get_reserve_a, get_reserve_b, init, shares_of, swap_a_for_b, swap_b_for_a,
};
use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller, ERR_OVERFLOW};

#[test]
fn giant_swap_inputs_fail_closed_without_touching_reserves() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    set_mock_caller(id_to_caller(1));
    let dep = 10_000_000_000 + 10_000 * 100_000 + 40_000;
    assert_eq!(deposit(dep), 25_000);

    // A->B with i64::MAX: quote is bounded, but x+dx would wrap i64.
    assert_eq!(swap_a_for_b(i64::MAX), ERR_OVERFLOW);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);
    assert_eq!(shares_of(1), 25_000);

    // B->A leg mirrors the guard.
    assert_eq!(swap_b_for_a(i64::MAX), ERR_OVERFLOW);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);

    // Normal flow still works afterwards: 1,000 A -> 3,626 B.
    assert_eq!(swap_a_for_b(1_000), 3_626);
    assert_eq!(get_reserve_a(0), 11_000);
    assert_eq!(get_reserve_b(0), 40_000 - 3_626);
}
