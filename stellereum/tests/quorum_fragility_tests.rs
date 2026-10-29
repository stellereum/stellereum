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
//!
//! LIVE PIN: the detector verdict is cross-checked against real consensus
//! behavior on the deterministic `consensus_cluster` harness — a single
//! Byzantine NIL voter must STALL the fragile equal-three set and must NOT
//! stop the skewed set that the detector clears.

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ConsensusCluster, NodeProfile};
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

/// Byzantine NIL-voter grind, live on the harness: the SAME single-fault
/// attack stalls the detector-flagged equal-three set and is absorbed by the
/// skewed set the detector clears.
///
/// Attack model — byzantine voter (nil grind): one validator prevotes NIL at
/// every (height, round) with a valid signature instead of following the
/// proposal. It never double-votes, so slashing/evidence paths stay quiet;
/// the damage is pure quorum arithmetic — the honest remainder must still
/// reach `floor(2T/3)+1` alone.
///
/// * fragile  [1,1,1]: quorum 3, honest remainder 2 < 3 → NO polka, no
///   precommit QC, `best_height` stays 0. If quorum accounting ever weakened
///   (signature count instead of power, off-by-one floor), this cluster would
///   finalize and the stall assert would catch it.
/// * skewed   [4,4,1]: quorum 7, the NIL leg is the power-1 minnow, honest
///   remainder 8 ≥ 7 → the chain finalizes. If the nil vote ever stole or
///   blocked the value quorum, the liveness assert would catch it.
///
/// Would-FAIL-on-regression cases: (a) detector stops flagging equal-three
/// or starts flagging [4,4,1]; (b) quorum math drifts so 2/3 passes; (c) the
/// NIL path double-votes or forges (caught by the no-equivocation asserts);
/// (d) either height finalizes two hashes (fork).
#[tokio::test]
async fn fragile_equal_three_halts_on_single_byzantine_nil_voter_while_skewed_set_survives() {
    // The detector must agree with the live experiment below: equal-three is
    // fragile, [4,4,1] survives losing its smallest leg (8 of quorum 7 left).
    assert!(
        validator_powers_fragility(&[1, 1, 1]).is_some(),
        "equal-three must be flagged fragile"
    );
    assert_eq!(
        validator_powers_fragility(&[4, 4, 1]),
        None,
        "[4,4,1] survives losing the power-1 leg and must NOT be flagged"
    );

    // --- Fragile set under attack: 3x power-1, node 2 grinds NIL. ---
    let fragile_profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().byzantine(Byzantine::NilPrevote),
    ];
    let mut fragile = ConsensusCluster::with_profiles(3, fragile_profiles);
    fragile.seed_transactions(2).await;
    let stalled = fragile.run_for(30_000).await;
    assert_eq!(
        stalled.best_height, 0,
        "fragile 1/1/1 with one NIL grinder must finalize NOTHING (quorum 3 needs all three):\n{}",
        stalled.diagnostics()
    );
    assert_eq!(
        stalled.common_height, 0,
        "no up node may advance past the stall:\n{}",
        stalled.diagnostics()
    );
    assert!(
        stalled
            .nodes
            .iter()
            .all(|n| n.precommit_qc_round.is_none()),
        "no precommit QC may form without a value polka:\n{}",
        stalled.diagnostics()
    );
    assert!(
        stalled.double_votes(&[]).is_empty(),
        "the NIL grind is one vote per (height, round): never an equivocation"
    );
    for (height, entries) in stalled.finalized_by_height() {
        let mut hashes: Vec<[u8; 32]> = entries.iter().map(|(_, h)| *h).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "stalled height {height} must never carry two hashes"
        );
    }

    // --- Skewed set under the SAME attack on its small leg: must live. ---
    let skewed_profiles = vec![
        NodeProfile::default().with_power(4),
        NodeProfile::default().with_power(4),
        NodeProfile::default()
            .with_power(1)
            .byzantine(Byzantine::NilPrevote),
    ];
    let mut skewed = ConsensusCluster::with_profiles(3, skewed_profiles);
    skewed.seed_transactions(2).await;
    let live = skewed.run_until(2, 120_000).await;
    assert!(
        live.common_height >= 2,
        "skewed 4/4/1 must finalize despite the power-1 NIL grinder (8 of quorum 7 remain):\n{}",
        live.diagnostics()
    );
    assert!(
        live.double_votes(&[]).is_empty(),
        "the surviving run must contain no equivocation either"
    );
    for (height, entries) in live.finalized_by_height() {
        let mut hashes: Vec<[u8; 32]> = entries.iter().map(|(_, h)| *h).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "finalized height {height} must never carry two hashes"
        );
    }
}
