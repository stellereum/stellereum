//! P0 PoC (fixed by CT-P0 auth, kept as regression pin): account-object
//! ownership used to be a caller-supplied `caller_id`.
//! `get_owner` is public, so anyone could replay it and seize the account.
//! Invariant: takeover forged with public owner id must fail.

use account_object::{get_owner, init, transfer_ownership};
use stellereum_contract_sdk::reset_mock_state;

#[test]
fn poc_p0_account_takeover_spoof_must_fail() {
    reset_mock_state();
    assert_eq!(init(42), 42);
    assert_eq!(get_owner(0), 42);
    // Attacker reads public owner id (42) and replays it as caller_id.
    let spoofed = 42 * 10_000_000_000 + 999;
    let rc = std::panic::catch_unwind(|| transfer_ownership(spoofed));
    let ok = rc.is_ok();
    assert!(!ok, "spoofed transfer_ownership succeeded (P0)");
    assert_eq!(get_owner(0), 42, "account seized via caller spoof (P0)");
}
