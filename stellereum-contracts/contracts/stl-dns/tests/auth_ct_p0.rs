//! CT-P0 auth matrix for STL-DNS (audit KI-38): forged owner/treasury ids
//! (public, replayed with the zero-address caller) are refused with the exact
//! error code and the domain is untouched; authenticated owner/treasury flows
//! succeed.

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_UNAUTHORIZED, SUCCESS,
};
use stl_dns::{finalize_auction, init, resolve, set_target, start_auction, transfer};

fn auctioned_domain() -> i64 {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 1001;
    assert_eq!(
        start_auction(domain * 10_000_000_000 + 10 * 100_000 + 4),
        domain
    );
    assert_eq!(finalize_auction(domain), 1);
    assert_eq!(resolve(domain), 10);
    domain
}

#[test]
fn ct_p0_spoofed_transfer_and_target_refused_exact() {
    let domain = auctioned_domain();
    // Attacker replays the public owner id 10 with no authenticated sender.
    let spoofed = domain * 10_000_000_000 + 10 * 100_000 + 999;
    assert_eq!(transfer(spoofed), ERR_UNAUTHORIZED);
    assert_eq!(resolve(domain), 10);
    assert_eq!(
        set_target(domain * 10_000_000_000 + 10 * 100_000 + 777),
        ERR_UNAUTHORIZED
    );
    assert_eq!(resolve(domain), 10);
    // Wrong (non-owner) id is refused too.
    assert_eq!(
        transfer(domain * 10_000_000_000 + 999 * 100_000 + 999),
        ERR_UNAUTHORIZED
    );
    assert_eq!(resolve(domain), 10);
}

#[test]
fn ct_p0_owner_and_treasury_flows_succeed() {
    let domain = auctioned_domain();
    set_mock_caller(id_to_caller(10));
    assert_eq!(
        set_target(domain * 10_000_000_000 + 10 * 100_000 + 555),
        SUCCESS
    );
    assert_eq!(resolve(domain), 555);
    assert_eq!(
        transfer(domain * 10_000_000_000 + 10 * 100_000 + 20),
        SUCCESS
    );
    assert_eq!(resolve(domain), 20);
    // Repeat transfer by the previous owner is now refused (no replay).
    assert_eq!(
        transfer(domain * 10_000_000_000 + 10 * 100_000 + 30),
        ERR_UNAUTHORIZED
    );
    assert_eq!(resolve(domain), 20);
}
