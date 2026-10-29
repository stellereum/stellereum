//! Quorum-safety (fragile-set) detector — урок ночи C.
//!
//! Three equal stakes need 3/3 for quorum (`floor(2T/3)+1` over power), so
//! ANY single halt stops the chain. The detector
//! ([`stellereum::staking::validator_powers_fragility`], surfaced per-ledger
//! as [`stellereum::staking::StakingLedger::quorum_fragility`] and over RPC
//! as the `fragile` flag of `stell_getValidators`) must flag that shape and
//! stay silent for a skewed set that survives one fault:
//!
//! * 3xfloor (equal)         -> fragile
//! * 9000 / 9000 / floor     -> NOT fragile (losing the small leg leaves 18000 of
//!   quorum ~12734)

use stellereum::staking::{
    validator_powers_fragility, StakingLedger, DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND,
    STELL_MIN_BOND_BUFFER,
};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Bond floor all ledger stakes in this file must clear: bare-MIN bonds are
/// refused, so the fragility fixtures bond at MIN+buffer.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}

fn ledger_of(stakes: &[u64]) -> StakingLedger {
    let mut l = StakingLedger::new();
    for (i, s) in stakes.iter().enumerate() {
        l.bond(vid(i as u8 + 1), *s, DEFAULT_COMMISSION_BPS)
            .expect("bond must succeed at/above the minimum");
    }
    l
}

#[test]
fn three_equal_stakes_are_fragile() {
    let powers = [floor(), floor(), floor()];
    let reason = validator_powers_fragility(&powers);
    assert!(
        reason.is_some(),
        "3xfloor must be flagged fragile (quorum needs 3/3)"
    );
    let text = reason.unwrap();
    assert!(
        text.contains("N=3"),
        "the N=3 equal-power shape deserves its own explanation, got: {text}"
    );

    // Same verdict through the ledger, the exact path `stell_getValidators`
    // derives its `fragile` flag from.
    let ledger = ledger_of(&powers);
    assert!(
        ledger.quorum_fragility().is_some(),
        "ledger 3xfloor must be flagged fragile"
    );
}

#[test]
fn skewed_three_set_is_not_fragile() {
    let powers = [stell(9000), stell(9000), floor()];
    assert_eq!(
        validator_powers_fragility(&powers),
        None,
        "9000/9000/floor survives losing the small leg (18000 left of quorum)"
    );

    let ledger = ledger_of(&powers);
    assert_eq!(
        ledger.quorum_fragility(),
        None,
        "ledger 9000/9000/floor must NOT be flagged fragile"
    );
}
