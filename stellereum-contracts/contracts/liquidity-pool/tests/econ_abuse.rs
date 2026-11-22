//! HDAE economic-abuse pentest for liquidity-pool (read-only vs programs).
//! Each attack is executed; outcome is DEFEATED (asserted) or FINDING.
//! Result: all DEFEATED — no free value, no theft, fail-closed edges.

use liquidity_pool::{
    deposit, get_reserve_a, get_reserve_b, get_total_shares, init, shares_of, swap_a_for_b,
    swap_b_for_a, swap_quote, swap_quote_b_for_a, withdraw,
};
use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT, ERR_OVERFLOW,
};

fn dep_pack(user: i64, a: i64, b: i64) -> i64 {
    user * 10_000_000_000 + a * 100_000 + b
}
fn wd_pack(user: i64, shares: i64) -> i64 {
    user * 1_000_000 + shares
}

fn setup_pool() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    set_mock_caller(id_to_caller(1));
    assert_eq!(deposit(dep_pack(1, 10_000, 40_000)), 25_000);
}

/// (1a) First-depositor inflation: minimal first deposit, then a large
/// balanced second deposit. Second depositor redeems exactly what they put
/// in (pro-rata) — no theft either direction. DEFEATED.
#[test]
fn first_depositor_minimal_then_whale_no_theft() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    set_mock_caller(id_to_caller(1));
    // Minimal first deposit (1,1) -> (1+1)/2 = 1 share.
    assert_eq!(deposit(dep_pack(1, 1, 1)), 1);
    assert_eq!(shares_of(1), 1);

    set_mock_caller(id_to_caller(2));
    // Balanced whale (90000,90000): min(90000*1/1, 90000*1/1) = 90000.
    let minted = deposit(dep_pack(2, 90_000, 90_000));
    assert_eq!(minted, 90_000);
    assert_eq!(get_total_shares(0), 90_001);
    // Whale exits fully: pro-rata payout equals deposit (floored).
    let ra_before = get_reserve_a(0);
    let rb_before = get_reserve_b(0);
    assert_eq!(ra_before, 90_001);
    assert_eq!(rb_before, 90_001);
    set_mock_caller(id_to_caller(2));
    let out_a = withdraw(wd_pack(2, 90_000));
    // floor(90000*90001/90001) = 90000 exact.
    assert_eq!(out_a, 90_000);
    assert_eq!(get_reserve_a(0), 1);
    assert_eq!(get_reserve_b(0), 1);
    assert_eq!(shares_of(1), 1, "first depositor untouched");
    assert_eq!(shares_of(2), 0);
}

/// (1b) Imbalanced second deposit DONATES to the pool (min-leg rule):
/// attacker overpays and redeems less — griefing self, enriching LPs.
/// No inflation profit for the attacker. DEFEATED.
#[test]
fn imbalanced_deposit_donates_attacker_loses() {
    reset_mock_state();
    assert_eq!(init(30), 30);
    set_mock_caller(id_to_caller(1));
    assert_eq!(deposit(dep_pack(1, 1, 1)), 1);

    set_mock_caller(id_to_caller(2));
    // (99000 A, 1 B): share = min(99000, 1) = 1.
    assert_eq!(deposit(dep_pack(2, 99_000, 1)), 1);
    assert_eq!(get_total_shares(0), 2);
    // Attacker exits: floor(1*99001/2)=49500 A, floor(1*2/2)=1 B.
    // Deposited 99000 A, gets back 49500 A: net loss of 49500 A.
    let out = withdraw(wd_pack(2, 1));
    assert_eq!(out, 49_500);
    assert_eq!(get_reserve_b(0), 2 - 1);
    // Victim LP (first depositor) gains the donation — protocol takes from
    // the imbalanced party, never mints free value.
    set_mock_caller(id_to_caller(1));
    let victim_out = withdraw(wd_pack(1, 1));
    assert_eq!(victim_out, 49_501);
}

/// (1c) Sandwich-shaped sequences never print value: A->B then B->A
/// roundtrip loses to the fee leg (k grows monotonically). DEFEATED.
#[test]
fn sandwich_roundtrip_never_profits() {
    setup_pool();
    let k0 = get_reserve_a(0) as u128 * get_reserve_b(0) as u128;
    // Attacker leg 1: big A->B swap.
    let dy = swap_a_for_b(5_000);
    assert!(dy > 0);
    let k1 = get_reserve_a(0) as u128 * get_reserve_b(0) as u128;
    assert!(k1 > k0, "fee leg must grow k");
    // Victim-style reversal: sell the proceeds back.
    let dx_back = swap_b_for_a(dy);
    assert!(dx_back > 0);
    assert!(
        dx_back < 5_000,
        "roundtrip must return less than input (fee), got {dx_back}"
    );
    let k2 = get_reserve_a(0) as u128 * get_reserve_b(0) as u128;
    assert!(k2 >= k1, "k never shrinks across fee swaps");
    assert_eq!(get_total_shares(0), 25_000, "swaps must not mint shares");
}

/// (1d) Giant / imbalanced swap inputs fail closed, reserves untouched.
/// Imbalanced here means huge one-sided dx. DEFEATED.
#[test]
fn giant_swap_inputs_fail_closed() {
    setup_pool();
    assert_eq!(swap_a_for_b(i64::MAX), ERR_OVERFLOW);
    assert_eq!(swap_b_for_a(i64::MAX), ERR_OVERFLOW);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);
    // Zero/negative legs refused, nothing moves.
    assert_eq!(swap_a_for_b(0), ERR_INVALID_ARGUMENT);
    assert_eq!(swap_b_for_a(-5), ERR_INVALID_ARGUMENT);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);
    // Quotes stay exact (u128): giant quote bounded, small quotes pinned
    // on fresh (10_000, 40_000) reserves.
    assert_eq!(swap_quote(1_000), 3_626);
    assert_eq!(swap_quote_b_for_a(3_000), 695);
    assert!(swap_quote(i64::MAX) >= 0);
}

/// (1e) Dust withdrawal refused without burning shares (net-zero path).
/// DEFEATED (re-pin of P1 fix).
#[test]
fn dust_withdraw_refused_no_burn() {
    setup_pool();
    set_mock_caller(id_to_caller(1));
    assert_eq!(withdraw(wd_pack(1, 1)), ERR_INVALID_ARGUMENT);
    assert_eq!(shares_of(1), 25_000);
    assert_eq!(get_total_shares(0), 25_000);
    assert_eq!(get_reserve_a(0), 10_000);
    assert_eq!(get_reserve_b(0), 40_000);
}

/// (5) Overflow edges on pool: i64::MAX swap dx/dy -> ERR (never wrap).
/// DEFEATED.
#[test]
fn overflow_edges_fail_closed() {
    setup_pool();
    // Deposit packing bounds legs <100000 so wire-level overflow is
    // unreachable; the unbounded swap legs are the overflow surface.
    assert_eq!(swap_a_for_b(i64::MAX - 7), ERR_OVERFLOW);
    assert_eq!(swap_b_for_a(i64::MAX - 7), ERR_OVERFLOW);
    assert_eq!(get_total_shares(0), 25_000);
}
