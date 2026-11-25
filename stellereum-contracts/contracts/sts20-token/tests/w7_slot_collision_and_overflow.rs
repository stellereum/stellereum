//! W7 regression (W6-A4-5): STS-20 `balance_slot` and `allowance_slot`
//! namespaces are completely disjoint and `balance_of` guards against
//! `i64` overflow on extreme account IDs.

use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller, SUCCESS};
use sts20_token::{allowance, approve, balance_of, init, transfer};

#[test]
fn w7_balance_and_allowance_slots_never_collide_and_balance_of_is_overflow_safe() {
    reset_mock_state();
    assert_eq!(init(1_000_000), SUCCESS);

    // Extreme account IDs must never overflow BALANCE_OFFSET + account.
    assert_eq!(balance_of(i64::MAX), 0);
    assert_eq!(balance_of(i64::MIN), 0);
    assert_eq!(balance_of(1_000_000_000_000), 0);
    assert_eq!(balance_of(0), 0);
    assert_eq!(balance_of(-1), 0);

    // Grant allowance from owner 1 to spender 5.
    set_mock_caller(id_to_caller(1));
    assert_eq!(approve(10_000_000_000 + 5 * 100_000 + 50_000), 1);
    assert_eq!(allowance(1_000_000 + 5), 50_000);

    // A high account id that previously landed inside [10_000_000..278_435_455]
    // cannot collide with any allowance slot or observe allowance values.
    for probe_id in [9_000_000_i64, 10_000_000, 150_000_000, 278_435_455] {
        assert_eq!(balance_of(probe_id), 0);
    }

    // Large valid `from` account in transfer (>= 10_000_000) cannot collide with
    // allowance slots even if it has balance.
    let big_sender: i64 = 10_000_000;
    set_mock_caller(id_to_caller(big_sender));
    assert_eq!(
        transfer(big_sender * 100_000_000 + 2 * 100_000 + 1_000),
        stellereum_contract_sdk::ERR_INSUFFICIENT_BALANCE
    );
    assert_eq!(allowance(1_000_000 + 5), 50_000);
}
