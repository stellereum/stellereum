//! P0 PoC (fixed by CT-P0 auth, kept as regression pin): STS-20 `transfer`
//! used to move funds without any caller/allowance check.
//! Security invariant: a stranger (user 99, no approval) must NOT be able
//! to move tokens out of admin (user 1).

use sts20_token::{balance_of, init, transfer};
use stellereum_contract_sdk::reset_mock_state;

#[test]
fn poc_p0_unauth_transfer_must_fail() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Attacker crafts a transfer FROM admin(1) TO attacker(99) for 10_000.
    // Legit `transfer` has no spender/caller field at all.
    let packed = 100_000_000 + 99 * 100_000 + 10_000;
    let rc = transfer(packed);
    // Secure contract: must reject (ERR_UNAUTHORIZED / ERR_INVALID_ARGUMENT).
    assert_ne!(rc, 1, "unauthenticated transfer from admin succeeded (P0)");
    // Balances must be untouched.
    assert_eq!(balance_of(1), 1_000_000, "admin drained without auth (P0)");
    assert_eq!(balance_of(99), 0);
}
