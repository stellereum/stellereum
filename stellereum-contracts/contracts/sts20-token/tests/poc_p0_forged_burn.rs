//! P0 PoC (fixed by CT-P0 auth, kept as regression pin): STS-20 `burn`/`mint`
//! used to authorize via a caller-supplied `admin_id`.
//! Anyone who knows the public admin id (1) could burn admin funds.
//! Invariant: forged burn must fail and leave balances intact.

use sts20_token::{balance_of, burn, init};
use stellereum_contract_sdk::reset_mock_state;

#[test]
fn poc_p0_forged_admin_burn_must_fail() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);
    // Attacker is NOT admin but passes admin_id = 1 (public default).
    let forged = 10_000_000_000 + 40_000;
    let rc = burn(forged);
    assert!(
        rc < 0,
        "forged burn with spoofed admin_id succeeded (P0), rc={rc}"
    );
    assert_eq!(balance_of(1), 1_000_000, "admin balance burned by stranger");
}
