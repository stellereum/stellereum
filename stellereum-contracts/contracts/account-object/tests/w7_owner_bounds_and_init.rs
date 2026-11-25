//! W7 regression (W6-A4-5): `account-object` validates `owner > 0 && owner <= 922_337_203`
//! in `init`, `transfer_ownership`, and `initiate_recovery`, and guards `init` / pre-init
//! session creation cleanly.

use account_object::{
    create_session, get_owner, get_pending_owner, init, initiate_recovery, rotate_guardian,
    transfer_ownership,
};
use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_block_time, set_mock_caller, ERR_INVALID_ARGUMENT,
};

const MAX_OWNER_ID: i64 = 922_337_203;

#[test]
fn w7_owner_bounds_and_init_guards() {
    reset_mock_state();

    // Pre-init create_session must fail closed.
    assert!(
        std::panic::catch_unwind(|| create_session(10_000_000_000 + 10 * 100_000 + 5_000)).is_err()
    );

    // Out-of-range owners in init return ERR_INVALID_ARGUMENT and leave SLOT_INITIALIZED == 0.
    for bad in [0i64, -1, MAX_OWNER_ID + 1, i64::MAX] {
        assert_eq!(init(bad), ERR_INVALID_ARGUMENT);
        assert_eq!(get_owner(0), 0);
    }

    // Valid max owner still initializes cleanly.
    assert_eq!(init(42), 42);
    assert_eq!(get_owner(0), 42);

    // Re-init always panics.
    assert!(std::panic::catch_unwind(|| init(42)).is_err());
    assert!(std::panic::catch_unwind(|| init(MAX_OWNER_ID + 1)).is_err());

    // transfer_ownership rejects new_owner > MAX_OWNER_ID.
    set_mock_caller(id_to_caller(42));
    assert!(std::panic::catch_unwind(|| transfer_ownership(
        42 * 10_000_000_000 + (MAX_OWNER_ID + 1)
    ))
    .is_err());
    assert_eq!(get_owner(0), 42);

    // initiate_recovery rejects new_owner > MAX_OWNER_ID.
    assert_eq!(rotate_guardian(42 * 10_000_000_000 + 777), 777);
    set_mock_block_time(1_750_000_000);
    set_mock_caller(id_to_caller(777));
    assert!(std::panic::catch_unwind(|| initiate_recovery(
        777 * 10_000_000_000 + (MAX_OWNER_ID + 1)
    ))
    .is_err());
    assert_eq!(get_pending_owner(0), 0);

    // Max valid owner (922_337_203) works across transfer_ownership and remains operable.
    set_mock_caller(id_to_caller(42));
    assert_eq!(
        transfer_ownership(42 * 10_000_000_000 + MAX_OWNER_ID),
        MAX_OWNER_ID
    );
    assert_eq!(get_owner(0), MAX_OWNER_ID);
    set_mock_caller(id_to_caller(MAX_OWNER_ID));
    assert_eq!(rotate_guardian(MAX_OWNER_ID * 10_000_000_000 + 555), 555);
}
