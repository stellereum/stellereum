//! Audit 6.0->8.0 regression pins for STL-DNS.
//!
//! - `transfer` to `new_owner = 0` is refused: owner 0 is the black hole and
//!   no caller ever authenticates as id 0 (`caller_is(0)` is false), so a
//!   zero-owner transfer would lock the domain forever with no recovery.
//! - Zero-domain guards on `transfer`/`set_target` (defense in depth).

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT, SUCCESS,
};
use stl_dns::{finalize_auction, init, resolve, set_target, start_auction, transfer};

#[test]
#[allow(clippy::identity_op)] // GATE: `id * BASE + ...` names the packed leading field; `0 *` pins the zero-domain guard.
#[allow(clippy::erasing_op)] // GATE: `0 * BASE` documents the erased domain field in the zero-domain pin.
fn transfer_to_zero_owner_and_zero_domain_refused() {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 2002;
    assert_eq!(
        start_auction(domain * 10_000_000_000 + 10 * 100_000 + 4),
        domain
    );
    assert_eq!(finalize_auction(domain), 1);
    assert_eq!(resolve(domain), 10);

    set_mock_caller(id_to_caller(10));
    // new_owner = 0 would burn the domain into the unauthenticatable hole.
    assert_eq!(
        transfer(domain * 10_000_000_000 + 10 * 100_000 + 0),
        ERR_INVALID_ARGUMENT
    );
    assert_eq!(resolve(domain), 10);
    // Zero-domain guards on both value-adjacent entries.
    assert_eq!(
        transfer(0 * 10_000_000_000 + 10 * 100_000 + 20),
        ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        set_target(0 * 10_000_000_000 + 10 * 100_000 + 20),
        ERR_INVALID_ARGUMENT
    );
    assert_eq!(resolve(domain), 10);
    // Legit transfer still works.
    assert_eq!(
        transfer(domain * 10_000_000_000 + 10 * 100_000 + 20),
        SUCCESS
    );
    assert_eq!(resolve(domain), 20);
}
