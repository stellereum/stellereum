//! CT-P0 auth matrix for account-object (audit KI-38): spoofed owner /
//! guardian / tenant ids (public, replayed with the zero-address caller) trap
//! and change nothing; the authenticated owner/guardian flows succeed.

use account_object::{
    cancel_recovery, get_owner, get_pending_owner, init, initiate_recovery, revoke_rental,
    rotate_guardian, set_tenant, transfer_ownership,
};
use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};

#[test]
fn ct_p0_spoofed_takeover_guardian_and_tenant_trap() {
    reset_mock_state();
    assert_eq!(init(42), 42);
    // Spoofed owner id with unauthenticated caller: must trap, owner kept.
    let spoofed = 42 * 10_000_000_000 + 999;
    assert!(std::panic::catch_unwind(|| transfer_ownership(spoofed)).is_err());
    assert_eq!(get_owner(0), 42);
    // Spoofed guardian rotation and tenant grant trap the same way.
    assert!(std::panic::catch_unwind(|| rotate_guardian(42 * 10_000_000_000 + 777)).is_err());
    assert!(
        std::panic::catch_unwind(|| set_tenant(42 * 10_000_000_000 + 555 * 10_000 + 72)).is_err()
    );
    assert_eq!(get_owner(0), 42);
}

#[test]
fn ct_p0_owner_and_guardian_flows_succeed() {
    reset_mock_state();
    assert_eq!(init(42), 42);
    set_mock_caller(id_to_caller(42));
    assert_eq!(rotate_guardian(42 * 10_000_000_000 + 777), 777);
    set_mock_caller(id_to_caller(777));
    assert_eq!(initiate_recovery(777 * 10_000_000_000 + 888), 888);
    assert_eq!(get_pending_owner(0), 888);
    // Rogue recovery by a non-guardian traps even with a live caller.
    set_mock_caller(id_to_caller(888));
    assert!(std::panic::catch_unwind(|| initiate_recovery(888 * 10_000_000_000 + 1)).is_err());
    assert_eq!(get_pending_owner(0), 888);
    // Owner veto and rental revoke authenticate as the owner.
    set_mock_caller(id_to_caller(42));
    assert_eq!(cancel_recovery(42), 0);
    assert_eq!(get_pending_owner(0), 0);
    assert_eq!(set_tenant(42 * 10_000_000_000 + 555 * 10_000 + 72), 555);
    assert_eq!(revoke_rental(42), 0);
    // Ownership handover to the new owner works once.
    assert_eq!(transfer_ownership(42 * 10_000_000_000 + 999), 999);
    assert_eq!(get_owner(0), 999);
}
