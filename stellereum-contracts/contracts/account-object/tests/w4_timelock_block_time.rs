//! W4 regression: `account-object` recovery timelock and rental deadline must
//! use the trusted host `block_time()`, never hardcoded epochs or caller-supplied
//! timestamps.

use account_object::{
    finalize_recovery, get_active_tenant, get_owner, get_pending_owner, init, initiate_recovery,
    is_rental_active, rotate_guardian, set_tenant,
};
use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_block_time, set_mock_caller,
};

#[test]
fn w4_recovery_timelock_enforced_by_host_block_time() {
    reset_mock_state();
    assert_eq!(init(42), 42);

    set_mock_caller(id_to_caller(42));
    assert_eq!(rotate_guardian(42 * 10_000_000_000 + 777), 777);

    // Initiate recovery at block_time = 1_750_000_000.
    set_mock_block_time(1_750_000_000);
    set_mock_caller(id_to_caller(777));
    assert_eq!(initiate_recovery(777 * 10_000_000_000 + 888), 888);
    assert_eq!(get_pending_owner(0), 888);

    // Immediate finalize at block_time = 1_750_000_001 must fail even with spoofed arg.
    set_mock_block_time(1_750_000_001);
    assert!(std::panic::catch_unwind(|| finalize_recovery(1_750_000_001)).is_err());
    assert!(std::panic::catch_unwind(|| finalize_recovery(i64::MAX)).is_err());
    assert_eq!(get_owner(0), 42);
    assert_eq!(get_pending_owner(0), 888);

    // One second before the 72-hour timelock (1_750_259_200) still fails.
    set_mock_block_time(1_750_259_199);
    assert!(std::panic::catch_unwind(|| finalize_recovery(i64::MAX)).is_err());
    assert_eq!(get_owner(0), 42);

    // At block_time >= 1_750_259_200, finalization succeeds regardless of arg.
    set_mock_block_time(1_750_259_200);
    assert_eq!(finalize_recovery(0), 888);
    assert_eq!(get_owner(0), 888);
    assert_eq!(get_pending_owner(0), 0);
}

#[test]
fn w4_rental_expiry_enforced_by_host_block_time() {
    reset_mock_state();
    assert_eq!(init(42), 42);

    set_mock_block_time(1_750_000_000);
    set_mock_caller(id_to_caller(42));
    assert_eq!(set_tenant(42 * 10_000_000_000 + 555 * 10_000 + 1), 555);

    // Before deadline (1_750_003_600), caller-supplied i64::MAX cannot fake expiry.
    set_mock_block_time(1_750_001_000);
    assert_eq!(get_active_tenant(i64::MAX), 555);
    assert_eq!(is_rental_active(i64::MAX), 1);

    // At deadline, rental expires even if caller supplies 0.
    set_mock_block_time(1_750_003_600);
    assert_eq!(get_active_tenant(0), 0);
    assert_eq!(is_rental_active(0), 0);
}
