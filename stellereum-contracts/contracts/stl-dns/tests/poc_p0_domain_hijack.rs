//! P0 PoC (fixed by CT-P0 auth, kept as regression pin): STL-DNS
//! `transfer`/`set_target` used to trust a caller-supplied `caller_id`.
//! The owner id is public (via resolve), so anyone could forge it and steal.
//! Invariant: transfer forged with the owner's public id must fail.

use stl_dns::{finalize_auction, init, resolve, start_auction, transfer};
use stellereum_contract_sdk::reset_mock_state;

#[test]
fn poc_p0_dns_transfer_spoof_must_fail() {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 1001;
    assert_eq!(start_auction(domain * 10_000_000_000 + 10 * 100_000 + 4), domain);
    assert_eq!(finalize_auction(domain), 1);
    assert_eq!(resolve(domain), 10);
    // Attacker (999) forges caller_id = 10 (public owner) to steal the domain.
    let spoofed = domain * 10_000_000_000 + 10 * 100_000 + 999;
    let rc = transfer(spoofed);
    assert_ne!(rc, 0, "spoofed domain transfer succeeded (P0)");
    assert_eq!(resolve(domain), 10, "domain hijacked via caller spoof (P0)");
}
