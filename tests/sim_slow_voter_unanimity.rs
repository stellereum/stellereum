//! # SIM-SLOW-VOTER-UNANIMITY: one slow voter under a unanimity quorum.
//!
//! LIVE COUPLING (see also `tests/unanimity3_slow_voter_tests.rs`, which pins
//! the timeout-vs-link discriminator: generous base finalizes, tight base
//! stalls): under unanimity EVERY vote is load-bearing, so a slow voter
//! decides liveness. This scenario does NOT re-pin that discriminator — it
//! pins what generous-timeout liveness LOOKS like from the votes:
//!
//! * finals flow with the slow voter inside the round (liveness);
//! * no honest node ever casts a NIL prevote (no timeout fired before the
//!   proposal arrived — votes are fresh, never timeout-nil);
//! * every post-transient height is decided in its FIRST round (no
//!   stale-round QC ever carries a decision: `decide_rounds` deltas are 0
//!   past height 1, whose t=0 proposals are refused until virtual t>=1s);
//! * no fork, no double-votes, state roots agree (safety).
//!
//! DETERMINISM: fixed [`SEED`], virtual clock only.
//!
//! ```text
//! cargo test --test sim_slow_voter_unanimity -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};
use stellereum::consensus::VoteKind;

/// Fixed seed for the whole scenario. Any change moves every number below.
const SEED: u64 = 0xC10C_0002;
const TICK_MS: u64 = 100;
/// Generous base: comfortably above the slow link, so the slow voter's
/// messages still arrive inside the round (the production coupling:
/// timeouts must cover the slowest honest link).
const GENEROUS_BASE_MS: u64 = 10_000;
/// Slow-link delay, both directions (inbound TO the slow node via
/// `inbound_delay_ms`, outbound FROM it via `propose_delay_ms`).
/// Incident-scale (the live stand ran on 250ms+ links): comfortably inside
/// the generous base AND inside the 650ms round-0 proposal-wait cap, so the
/// slow voter's messages still arrive inside round 0 and every height is
/// decided in its first round. (A multi-SECOND link would trip the 650ms
/// round-0 cap instead of the base timeout — a different, harsher coupling
/// than the incident this scenario mirrors; the timeout-vs-link
/// discriminator itself is pinned in `unanimity3_slow_voter_tests.rs`.)
const SLOW_LINK_MS: u64 = 250;
const TARGET_HEIGHT: u64 = 3;
const BUDGET_MS: u64 = 240_000;

fn slow_unanimity_cluster() -> ConsensusCluster {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default()
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_LINK_MS),
    ];
    ConsensusCluster::build(3, profiles, SEED, TICK_MS, GENEROUS_BASE_MS)
}

#[tokio::test]
async fn slow_voter_unanimity_finalizes_with_fresh_votes() {
    let mut c = slow_unanimity_cluster();
    // Powers [1,1,1]: total 3, quorum 3 = unanimity. Any single missing
    // voter vetoes every QC.
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET_HEIGHT, BUDGET_MS).await;

    println!(
        "[sim][slow-unanimity] seed=0x{:x} virtual_ms={} ticks={} best={} common={} decide_rounds={:?}",
        SEED,
        report.virtual_ms,
        report.ticks,
        report.best_height,
        report.common_height,
        report.nodes.iter().map(|n| n.decide_rounds.clone()).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS: unanimity still finalizes when the timeout covers the link.
    assert!(
        report.best_height >= TARGET_HEIGHT,
        "generous timeout must absorb the slow voter.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    // VOTE FRESHNESS 1: no honest node ever timeout-nils. A NIL prevote
    // means "twice the round timeout passed with no live proposal" — under
    // a covering timeout the proposal always arrives first, so every honest
    // prevote names a value.
    for n in &report.nodes {
        let nils = n
            .cast_votes
            .iter()
            .filter(|v| v.kind == VoteKind::Prevote && v.target.is_none())
            .count();
        assert_eq!(
            nils, 0,
            "node {} cast {nils} NIL prevotes: its votes went stale \
             (proposal arrived after 2x timeout).\n{}",
            n.index,
            report.diagnostics()
        );
    }
    // VOTE FRESHNESS 2: no stale-round QC ever carries a decision. Past the
    // height-1 genesis transient, every height is decided in the FIRST round
    // it is proposed in (decide delta 0 = the precommit QC formed at the
    // polka's own round, not a round carried over).
    for n in &report.nodes {
        for (k, d) in n.decide_rounds.iter().enumerate().skip(1) {
            assert_eq!(
                *d, 0,
                "node {} decided height {} in round +{d}: a stale round \
                 carried the decision.\n{}",
                n.index,
                k + 1,
                report.diagnostics()
            );
        }
    }
    // SAFETY: no fork — exactly one decided block per height.
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 1, "height {h} must have exactly one decided block");
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "slow-but-honest voters never double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}
