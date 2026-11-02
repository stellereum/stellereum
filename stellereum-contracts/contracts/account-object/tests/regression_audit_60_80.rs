//! Audit 6.0->8.0 residual pin for account-object sessions (wire-frozen).
//!
//! Session `create`/`spend`/`update`/`revoke` carry NO caller field in the
//! packed wire format, so per-session authentication cannot be added without
//! changing the L1 wire format (forbidden in scope). The entries are bearer
//! by design: no funds move (budget counters only), budgets can only
//! decrease, and revoked sessions are tombstoned. This test pins the
//! residual instead of faking coverage:
//! - anyone can create/spend a session id (first-come id-squatting exists),
//! - the owner retains availability via fresh ids,
//! - re-creating a live id fails (exists guard).

use account_object::{
    create_session, get_session_budget, init, is_session_active, spend_with_session,
};
use stellereum_contract_sdk::reset_mock_state;

#[test]
fn bearer_sessions_permissionless_but_scoped_residual() {
    reset_mock_state();
    assert_eq!(init(42), 42);

    // Stranger (no auth field on the wire) creates session 7: succeeds.
    let s = 7 * 10_000_000_000 + 10 * 100_000 + 9_000;
    assert_eq!(create_session(s), 7);
    assert_eq!(is_session_active(7), 1);
    // Bearer spend drops the budget; no value moves anywhere.
    assert_eq!(spend_with_session(7 * 1_000_000 + 1_000), 8_000);
    assert_eq!(get_session_budget(7), 8_000);

    // Owner availability via a fresh id is unaffected.
    let s2 = 8 * 10_000_000_000 + 10 * 100_000 + 5_000;
    assert_eq!(create_session(s2), 8);
    assert_eq!(get_session_budget(8), 5_000);

    // Id-squat guard: re-creating a live id fails, so squatting only denies
    // that one id — the owner picks another.
    assert!(std::panic::catch_unwind(|| create_session(s)).is_err());
    assert_eq!(get_session_budget(8), 5_000);
}
