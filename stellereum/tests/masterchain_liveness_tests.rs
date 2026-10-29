//! # MASTERCHAIN LIVENESS — the regression suite for the parked chain.
//!
//! THE INCIDENT (live 4-node WAN stand, parked at height 285027 since
//! 2026-10-19):
//!
//! * all four nodes agreed on the state root — so it was NOT a state
//!   divergence, it was a LIVENESS failure;
//! * a full 3.5-STELL **prevote** quorum formed (A+B+C prevoted the same
//!   block hash at the same round) but **at most one** validator ever cast a
//!   **precommit**, so no precommit quorum formed and the height was never
//!   decided;
//! * the height then sat in a view-change storm (rounds 350…380) with ZERO
//!   finalizations for 45 minutes, while the workchain (shard 1) kept
//!   finalizing normally.
//!
//! The rig is `tests/support/live_stand.rs`: real `ValidatorRuntime`s on a
//! virtual clock, driven through the production phase order of `src/main.rs`.
//!
//! EVERY SCENARIO HERE MUST FINALIZE. A scenario that cannot finalize is a
//! regression, not a "known issue".

mod support;

use support::live_stand::{dump, Cluster, Profile};

/// The live shape: three validators (1500/1000/1000 STELL) and one observer,
/// started 26 s and 32 s apart, on a 400 ms WAN link, with a 3.5 s round
/// timeout.
///
/// The power split matters: with 3500 total power the quorum is 2334, so the
/// 1500-STELL validator is a member of EVERY quorum (1500 alone is not a
/// quorum and 1000+1000 is not either) — one non-participating validator
/// stalls the whole chain, which is exactly the live shape.
#[tokio::test]
async fn live_wan_stand_finalizes() {
    let mut c = Cluster::new(&[
        Profile::validator(1500),
        Profile::validator(1000).start(26_000),
        Profile::validator(1000).start(32_000),
        Profile::observer().start(5_000),
    ])
    .await;
    let report = c.run(300_000).await;
    assert!(
        report.common_finalized() > 20,
        "the live stand must keep finalizing\n{}{}",
        dump(&report),
        c.diagnose()
    );
    assert!(
        report.heights.windows(2).all(|w| w[0] == w[1]),
        "every node must be at the same height\n{}",
        dump(&report)
    );
}

/// The same shape with EQUAL power — the "3-racer leapfrog" case the code
/// documents as a known open issue. It must finalize too.
#[tokio::test]
async fn equal_power_wan_stand_finalizes() {
    let mut c = Cluster::new(&[
        Profile::validator(1000),
        Profile::validator(1000).start(26_000),
        Profile::validator(1000).start(32_000),
    ])
    .await;
    let report = c.run(300_000).await;
    assert!(
        report.common_finalized() > 20,
        "the equal-power stand must keep finalizing\n{}{}",
        dump(&report),
        c.diagnose()
    );
}

/// A FOUR-validator set (the live cluster had four nodes) must converge too.
#[tokio::test]
async fn four_validator_wan_stand_finalizes() {
    let mut c = Cluster::new(&[
        Profile::validator(1500),
        Profile::validator(1000).start(26_000),
        Profile::validator(1000).start(32_000),
        Profile::validator(1000).start(5_000),
    ])
    .await;
    let report = c.run(300_000).await;
    assert!(
        report.common_finalized() > 20,
        "the four-validator stand must keep finalizing\n{}{}",
        dump(&report),
        c.diagnose()
    );
}

/// A node that is 30 ROUNDS behind the others (the live round drift) must
/// catch up and the chain must keep finalizing.
#[tokio::test]
async fn thirty_round_skew_converges() {
    let mut c = Cluster::new(&[
        Profile::validator(1000),
        Profile::validator(1000),
        Profile::validator(1000).late(30),
    ])
    .await;
    let report = c.run(300_000).await;
    assert!(
        report.common_finalized() > 20,
        "a 30-round skew must converge\n{}{}",
        dump(&report),
        c.diagnose()
    );
}

// ===========================================================================
// THE LIVE FAILURE: a polka that arrives LATE.
// ===========================================================================

/// **THE REGRESSION.** A quorum of prevotes that reaches a node AFTER the
/// network has moved on by more than the scan window must still make that
/// node precommit — the Tendermint rule "if you see a polka, precommit it".
///
/// THE SHAPE (this is the live one): the prevotes of one round reach one
/// validator twenty seconds late (a stalled WAN path), by which time that
/// validator has raced thirty rounds ahead of the network. The other two
/// validators saw the polka in time and precommitted — but the stalled
/// validator is the 1500-STELL one, and 1000+1000 is BELOW the 2334 quorum:
/// without its precommit the height can never be decided. The stalled
/// validator itself cannot find the polka any more: the quorum scan only
/// looks at a window of rounds around the LOCAL round, and the polka's round
/// is 30 rounds in the past.
///
/// WITHOUT THE FIX this test fails: the height stays parked forever.
#[tokio::test]
async fn a_late_polka_is_still_precommitted() {
    let mut c = Cluster::new(&[
        // The stalled node: 1500 STELL (in EVERY quorum) with a forty-second
        // stall on the votes it receives. It races eleven rounds ahead of the
        // network while it is deaf, and the quorum-completing prevotes of
        // round 0 only reach it long after it left that round.
        Profile::validator(1500).vote_delay(40_000),
        Profile::validator(1000),
        Profile::validator(1000),
    ])
    .await;
    c.diagnose_finalize = true;
    let report = c.run(300_000).await;
    assert!(
        report.common_finalized() > 2,
        "a polka that arrives late must still be precommitted (the height must not be parked)\n{}{}",
        dump(&report),
        c.diagnose()
    );
}

/// The same shape with a FOUR-validator set: the late polka must be
/// precommitted there too.
#[tokio::test]
async fn a_late_polka_is_still_precommitted_four_validators() {
    let mut c = Cluster::new(&[
        // The 1500-STELL validator is in EVERY quorum of this set (three
        // 1000-STELL validators are 3000, one short of the 3001 quorum), so
        // the stalled node is the one the chain NEEDS: its late precommit is
        // the difference between a decided height and a parked one.
        Profile::validator(1500).vote_delay(40_000),
        Profile::validator(1000),
        Profile::validator(1000),
        Profile::validator(1000),
    ])
    .await;
    c.diagnose_finalize = true;
    let report = c.run(300_000).await;
    assert!(
        report.common_finalized() > 2,
        "a late polka must be precommitted with four validators too\n{}{}",
        dump(&report),
        c.diagnose()
    );
}
