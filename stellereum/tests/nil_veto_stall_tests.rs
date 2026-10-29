//! # The live-stall shape: largest-power validator voting nil.
//!
//! REVIEW DIMENSIONS 2 + 7 (enterprise-testnet consensus review).
//!
//! The live chain stalled with the largest-power validator voting nil at a
//! high round while the rest tried to converge. The mechanism
//! (`HeightConsensus::decide_prevote` → nil on lock-mismatch / no live
//! proposal, `consensus.rs`): on a skewed set any holder of more than a
//! third of the power single-handedly vetoes every prevote quorum, so the
//! polka that would unlock it never forms and the height parks while the
//! round counter climbs on timeouts.
//!
//! These scenarios run that EXACT shape on the deterministic harness
//! (`tests/support/consensus_cluster.rs`, extended with
//! `Byzantine::NilPrevote`): powers [2,1,1] (total 4, quorum 3 — the
//! 1500/1000/1000 live arithmetic at small scale), the power-2 node voting
//! nil every round.
//!
//! * `largest_power_nil_voter_stalls_the_height` — the stall, pinned: no
//!   height finalizes within the budget, rounds still advance (the
//!   high-round shape: votes flow, timeouts fire, nothing decides), the
//!   nil-voter's ballot is all-nil, no precommit QC forms anywhere, and —
//!   the safety half — no fork (no conflicting finalizations, no
//!   equivocation).
//! * `skewed_honest_cluster_finalizes_control` — the control: the SAME
//!   powers with an honest largest node finalize, isolating the nil vote
//!   (not the skew) as the cause.
//! * `byzantine_plus_slow_honest_two_thirds_still_finalize` — the
//!   adversarial resilience half: one Byzantine (double-prevote) + one slow
//!   honest (5x timeout, 300 ms inbound delay, 10% vote loss) + WAN-style
//!   jitter, and the honest 2/3 still finalize (the first vote is kept, so
//!   the double-vote never displaces the honest value).

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ConsensusCluster, NodeProfile};

/// Virtual budget for a scenario: long enough for dozens of timeout-driven
/// rounds (the high-round stall shape needs room to show itself), short
/// enough that a stall reports instead of hanging.
const STALL_BUDGET_MS: u64 = 60_000;
const CONTROL_BUDGET_MS: u64 = 240_000;

/// Skewed powers [2,1,1]: total 4, quorum floor(2*4/3)+1 = 3. The power-2
/// holder alone is below quorum (2 < 3) but its nil alone vetoes every
/// value-quorum (the remaining 2 < 3) — the live veto arithmetic.
fn skewed_nil_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default()
            .with_power(2)
            .byzantine(Byzantine::NilPrevote),
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
    ]
}

#[tokio::test]
async fn largest_power_nil_voter_stalls_the_height() {
    let mut c = ConsensusCluster::with_profiles(3, skewed_nil_profiles());
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 4);

    let report = c.run_until(2, STALL_BUDGET_MS).await;

    // LIVENESS: nothing finalizes — the height is parked.
    assert_eq!(
        report.best_height,
        0,
        "no node may finalize while the power-2 holder nils every round.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        0,
        "the common head must not move.\n{}",
        report.diagnostics()
    );
    // …while the round counter climbs on timeouts: votes flow, view changes
    // fire, nothing decides. THIS is the "stalled at a high round" shape —
    // a silent pair would sit at round 0, not round 20+.
    for n in &report.nodes {
        assert!(
            n.round >= 5,
            "node {} must have burned view changes (round {}), not sat silent.\n{}",
            n.index,
            n.round,
            report.diagnostics()
        );
        assert_eq!(
            n.precommit_qc_round,
            None,
            "node {}: no precommit QC may form without a polka.\n{}",
            n.index,
            report.diagnostics()
        );
    }
    // The nil-voter's ballot is all-nil prevotes (one per round it lived
    // through), and it never equivocates: nil every round is one vote per
    // (height, round), not two votes in one round.
    let nil_voter = &report.nodes[0];
    assert!(
        nil_voter.prevotes_cast >= 5,
        "the nil-voter must have voted nil round after round.\n{}",
        report.diagnostics()
    );
    assert!(
        nil_voter.cast_votes.iter().all(|v| v.target.is_none()),
        "every vote the power-2 holder cast must be nil.\n{}",
        report.diagnostics()
    );
    assert!(
        report.double_votes(&[]).is_empty(),
        "nil-every-round is not an equivocation.\n{}",
        report.diagnostics()
    );
    // SAFETY: no fork — nothing finalized anywhere, so nothing conflicts.
    assert!(
        report.finalized_by_height().is_empty(),
        "a stalled height finalizes nothing, hence conflicts with nothing.\n{}",
        report.diagnostics()
    );
    // State roots still agree (no divergence hiding behind the stall).
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "stalled nodes must not diverge.\n{}",
        report.diagnostics()
    );
}

#[tokio::test]
async fn skewed_honest_cluster_finalizes_control() {
    let profiles = vec![
        NodeProfile::default().with_power(2),
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
    ];
    let mut c = ConsensusCluster::with_profiles(3, profiles);
    let report = c.run_until(2, CONTROL_BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "the SAME [2,1,1] powers with an honest largest node must finalize: \
         the stall above is caused by the nil vote, not the skew.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    assert!(
        report.double_votes(&[]).is_empty(),
        "no honest node may double-vote.\n{}",
        report.diagnostics()
    );
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block"
        );
    }
}

/// One Byzantine (double-prevote) + one slow honest (5x round timeout,
/// 300 ms inbound delay, 10% vote loss) + jitter: the honest 2/3 still
/// finalize. The vote set keeps the FIRST vote, so the Byzantine's second
/// (conflicting) vote is recorded as evidence and never displaces the
/// honest value the quorum forms around.
#[tokio::test]
async fn byzantine_plus_slow_honest_two_thirds_still_finalize() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default()
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(300)
            .losing_votes(100),
        NodeProfile::default().byzantine(Byzantine::DoublePrevote),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    let report = c.run_until(2, CONTROL_BUDGET_MS).await;

    assert!(
        report.common_height >= 2,
        "one Byzantine + one slow honest must not stop the honest 2/3.\n{}",
        report.diagnostics()
    );
    // The Byzantine is exempt from the double-vote invariant (that IS its
    // fault); everyone else must be clean.
    assert!(
        report.double_votes(&[3]).is_empty(),
        "no HONEST node may double-vote.\n{}",
        report.diagnostics()
    );
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block"
        );
    }
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}
