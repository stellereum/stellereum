//! W7 regression (W6-A4-5): `stl-dns` validates `treasury > 0 && treasury < 100_000`
//! in `init` and rejects pre-init auction/transfer operations cleanly.

use stellereum_contract_sdk::address::DOMAIN_VAULT;
use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT, ERR_UNAUTHORIZED,
    SUCCESS,
};
use stl_dns::{finalize_auction, init, place_bid, resolve, set_target, start_auction, transfer};

#[test]
fn w7_treasury_bounds_and_preinit_guards() {
    reset_mock_state();

    // Pre-init operations fail closed with ERR_UNAUTHORIZED.
    assert_eq!(
        start_auction(10_000_000_000 + 10 * 100_000 + 4),
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        place_bid(10_000_000_000 + 20 * 10_000 + 1),
        ERR_UNAUTHORIZED
    );
    assert_eq!(finalize_auction(1), ERR_UNAUTHORIZED);
    assert_eq!(
        set_target(10_000_000_000 + 10 * 100_000 + 20),
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        transfer(10_000_000_000 + 10 * 100_000 + 20),
        ERR_UNAUTHORIZED
    );

    // Out-of-range treasury IDs return ERR_INVALID_ARGUMENT and leave contract uninitialized.
    for bad_treasury in [0i64, -1, 100_000, 100_001, i64::MAX] {
        assert_eq!(init(bad_treasury), ERR_INVALID_ARGUMENT);
        assert_eq!(resolve(DOMAIN_VAULT), 0);
    }

    // Max valid treasury (99_999) succeeds and retains full control over protocol domains.
    assert_eq!(init(99_999), SUCCESS);
    assert_eq!(resolve(DOMAIN_VAULT), 99_999);

    set_mock_caller(id_to_caller(99_999));
    assert_eq!(
        transfer(DOMAIN_VAULT * 10_000_000_000 + 99_999 * 100_000 + 42),
        SUCCESS
    );
    assert_eq!(resolve(DOMAIN_VAULT), 42);
}
