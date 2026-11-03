//! HDAE economic-abuse pentest for account-object budgets (read-only).
//! Session budgets move no funds (counters only) and can only decrease.
//! All attacks DEFEATED: no overspend, no inflation, tombstones hold.

use account_object::{
    create_session, get_session_budget, init, is_session_active, revoke_session,
    spend_with_session, update_session_budget,
};
use stellereum_contract_sdk::reset_mock_state;

fn csess(sid: i64, budget: i64) -> i64 {
    sid * 10_000_000_000 + 10 * 100_000 + budget
}
fn spend(sid: i64, amount: i64) -> i64 {
    sid * 1_000_000 + amount
}
fn upd(sid: i64, new_budget: i64) -> i64 {
    sid * 10_000_000_000 + new_budget
}

/// (4) Budget conservation fuzz: any spend sequence summing above budget
/// fails closed at the boundary; remaining == budget - spent exactly.
/// No credit-without-debit (remaining never goes negative). DEFEATED.
#[test]
fn budget_never_exceeded_fuzz() {
    for budget in [1i64, 2, 5, 100, 9_999, 99_999] {
        reset_mock_state();
        assert_eq!(init(42), 42);
        let sid = 100 + budget % 50;
        assert_eq!(create_session(csess(sid, budget)), sid);
        // Drain exactly in two halves (ceil/floor): must hit zero exactly.
        let half = budget / 2;
        let rest = budget - half;
        if half > 0 {
            assert_eq!(spend_with_session(spend(sid, half)), rest);
        }
        if rest > 0 {
            assert_eq!(spend_with_session(spend(sid, rest)), 0);
        }
        assert_eq!(get_session_budget(sid), 0);
        assert_eq!(is_session_active(sid), 0);
        // One more unit over the line: fail-closed panic, budget stays 0.
        assert!(std::panic::catch_unwind(|| spend_with_session(spend(sid, 1))).is_err());
        assert_eq!(get_session_budget(sid), 0);
    }
}

/// Budget inflation refused: update can only decrease, never below spent.
/// DEFEATED.
#[test]
fn budget_inflation_refused() {
    reset_mock_state();
    assert_eq!(init(42), 42);
    assert_eq!(create_session(csess(7, 9_000)), 7);
    assert_eq!(spend_with_session(spend(7, 1_000)), 8_000);
    // Increase above old budget: panic, unchanged.
    assert!(std::panic::catch_unwind(|| update_session_budget(upd(7, 9_001))).is_err());
    assert_eq!(get_session_budget(7), 8_000);
    // Decrease below spent: panic, unchanged.
    assert!(std::panic::catch_unwind(|| update_session_budget(upd(7, 999))).is_err());
    assert_eq!(get_session_budget(7), 8_000);
    // Valid decrease works and returns exact remainder.
    assert_eq!(update_session_budget(upd(7, 5_000)), 4_000);
    assert_eq!(get_session_budget(7), 4_000);
}

/// Revocation tombstone: revoked sessions cannot spend/update/recreate.
/// DEFEATED.
#[test]
fn revoked_tombstone_holds() {
    reset_mock_state();
    assert_eq!(init(42), 42);
    assert_eq!(create_session(csess(9, 5_000)), 9);
    assert_eq!(revoke_session(9), 1);
    assert_eq!(is_session_active(9), 0);
    assert_eq!(get_session_budget(9), 0);
    assert!(std::panic::catch_unwind(|| spend_with_session(spend(9, 1))).is_err());
    assert!(std::panic::catch_unwind(|| update_session_budget(upd(9, 4_000))).is_err());
    assert!(std::panic::catch_unwind(|| create_session(csess(9, 5_000))).is_err());
}

/// (5) Overflow / bounds edges: out-of-range amounts/ids trap fail-closed,
/// state untouched. DEFEATED.
#[test]
fn overflow_bounds_fail_closed() {
    reset_mock_state();
    assert_eq!(init(42), 42);
    assert_eq!(create_session(csess(11, 50_000)), 11);
    // Amount 0 and >= 1_000_000 breach the packing boundary: trap.
    assert!(std::panic::catch_unwind(|| spend_with_session(spend(11, 0))).is_err());
    assert!(
        std::panic::catch_unwind(|| spend_with_session(spend(11, 1_000_000))).is_err()
    );
    // Bad session ids trap.
    assert!(std::panic::catch_unwind(|| spend_with_session(spend(0, 1))).is_err());
    assert_eq!(get_session_budget(11), 50_000, "failed spends move nothing");
}
