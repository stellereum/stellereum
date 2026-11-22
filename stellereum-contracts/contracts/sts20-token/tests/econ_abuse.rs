//! HDAE economic-abuse pentest for STS-20 (read-only vs program).
//! All attacks DEFEATED: no allowance race, no dust credit, fail-closed edges.

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT, ERR_OVERFLOW,
    ERR_UNAUTHORIZED,
};
use sts20_token::{
    allowance, approve, balance_of, init, mint, total_supply, transfer, transfer_from,
};

fn ap(owner: i64, spender: i64, amount: i64) -> i64 {
    owner * 10_000_000_000 + spender * 100_000 + amount
}
fn tf(from: i64, to: i64, amount: i64) -> i64 {
    from * 100_000_000 + to * 100_000 + amount
}
fn tfr(spender: i64, from: i64, to: i64, amount: i64) -> i64 {
    spender * 100_000_000_000 + from * 10_000_000 + to * 100_000 + amount
}
fn al(owner: i64, spender: i64) -> i64 {
    owner * 1_000_000 + spender
}

/// (2a) Allowance race: grant -> partial spend -> re-grant lower.
/// Spender can never exceed the LATEST grant; old grant is dead. DEFEATED.
#[test]
fn allowance_race_never_exceeds_latest_grant() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(ap(1, 5, 2_000)), 1);
    assert_eq!(allowance(al(1, 5)), 2_000);

    // Spender uses 1,500 of 2,000 (front-run leg interleaved before re-grant).
    set_mock_caller(id_to_caller(5));
    assert_eq!(transfer_from(tfr(5, 1, 3, 1_500)), 1);
    assert_eq!(allowance(al(1, 5)), 500);

    // Owner re-grants LOWER (500): overwrite, not additive.
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(ap(1, 5, 500)), 1);
    assert_eq!(allowance(al(1, 5)), 500);

    // Spender tries the OLD 2,000-grant amount: refused.
    set_mock_caller(id_to_caller(5));
    assert_eq!(transfer_from(tfr(5, 1, 3, 2_000)), ERR_UNAUTHORIZED);
    assert_eq!(transfer_from(tfr(5, 1, 3, 501)), ERR_UNAUTHORIZED);
    assert_eq!(allowance(al(1, 5)), 500, "failed spends burn nothing");
    // Exact latest grant still works.
    assert_eq!(transfer_from(tfr(5, 1, 3, 500)), 1);
    assert_eq!(allowance(al(1, 5)), 0);
}

/// (2b) Approve overwrites (no additive inflation): re-approve replaces.
/// DEFEATED.
#[test]
fn approve_overwrites_not_additive() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(ap(1, 5, 2_000)), 1);
    assert_eq!(approve(ap(1, 5, 300)), 1);
    assert_eq!(allowance(al(1, 5)), 300, "second grant replaces first");
    // Revoke-to-zero works and blocks all spending.
    assert_eq!(approve(ap(1, 5, 0)), 1);
    assert_eq!(allowance(al(1, 5)), 0);
    set_mock_caller(id_to_caller(5));
    assert_eq!(transfer_from(tfr(5, 1, 3, 1)), ERR_UNAUTHORIZED);
}

/// (4) Fee/dust fuzz: amounts 1..=5 (and fee sweep) — either full refusal
/// with zero state change, or exact debit = net + fee. No
/// credit-without-debit. DEFEATED.
/// Note: amount=0 trips the `transfer` bounds trap (fail-closed panic, not
/// a return code) and `extern "C"` cannot be caught in-process, so the
/// zero leg is pinned via `transfer_from` (returns ERR, grant intact) in
/// the regression suite; here we fuzz the live 1..=5 range.
#[test]
fn dust_fuzz_no_credit_without_debit() {
    for amount in 1..=5i64 {
        reset_mock_state();
        assert_eq!(init(1_000_000), 0);
        set_mock_caller(id_to_caller(1));
        let s1 = balance_of(1);
        let rc = transfer(tf(1, 2, amount));
        // fee = ceil(amount*50/10000); amounts 0,1 refused (net<=0 / bounds).
        let fee = (amount * 50 + 10_000 - 1) / 10_000;
        let net = amount - fee;
        if net <= 0 {
            assert_eq!(rc, ERR_INVALID_ARGUMENT, "amount={amount} must refuse");
            assert_eq!(balance_of(1), s1, "amount={amount}: sender untouched");
            assert_eq!(balance_of(2), 0, "amount={amount}: no credit");
            assert_eq!(balance_of(99), 0, "amount={amount}: no fee credit");
        } else {
            assert_eq!(rc, 1, "amount={amount} must succeed");
            assert_eq!(balance_of(1), s1 - amount);
            assert_eq!(balance_of(2), net);
            assert_eq!(balance_of(99), fee);
            assert_eq!(
                balance_of(1) + balance_of(2) + balance_of(99),
                s1,
                "conservation amount={amount}"
            );
        }
    }
    // Sweep of small live amounts keeps conservation (sender debit ==
    // recipient net + treasury fee).
    for amount in [2i64, 3, 10, 199, 200, 1_000, 99_999] {
        reset_mock_state();
        assert_eq!(init(1_000_000), 0);
        set_mock_caller(id_to_caller(1));
        assert_eq!(transfer(tf(1, 2, amount)), 1);
        let fee = (amount * 50 + 10_000 - 1) / 10_000;
        assert_eq!(balance_of(2), amount - fee);
        assert_eq!(balance_of(99), fee);
        assert_eq!(balance_of(1), 1_000_000 - amount);
    }
}

/// (5) Overflow edges: mint near i64::MAX fails closed; allowance untouched.
/// transfer_from with oversized amount never burns grant. DEFEATED.
#[test]
fn overflow_edges_fail_closed() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(ap(1, 5, 2_000)), 1);
    // Grant far below any huge amount: refused as unauthorized, grant intact.
    set_mock_caller(id_to_caller(5));
    assert_eq!(transfer_from(tfr(5, 1, 3, 99_999)), ERR_UNAUTHORIZED);
    assert_eq!(allowance(al(1, 5)), 2_000);

    // Mint overflow: drive supply near max via mock seed (regression idiom).
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    stellereum_contract_sdk::sstore(0, i64::MAX - 10);
    set_mock_caller(id_to_caller(1));
    assert_eq!(mint(20), ERR_OVERFLOW);
    assert_eq!(total_supply(0), i64::MAX - 10);
    assert_eq!(balance_of(1), 1_000_000);
}
