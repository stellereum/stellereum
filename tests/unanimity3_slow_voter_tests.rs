//! # Unanimity-3 slow-voter liveness: timeout/latency coupling.
//!
//! Live incident (4-validator BFT testnet, quorum `(2n/3)+1`): slow voters on
//! 250ms+ links with a tight round timeout (3.5s base) fell a round behind,
//! their votes went stale, and no QC could form under 3/3 unanimity.
//! Widening `STELL_ROUND_TIMEOUT_MS` to 10s restored liveness. Timeouts MUST
//! match on all validators (documented invariant).
//!
//! These scenarios pin that coupling on the deterministic harness
//! (`tests/support/consensus_cluster.rs`) at small scale: powers [1,1,1]
//! (total 3, quorum 3 = unanimity), one honest slow node (5x round-timeout
//! factor, multi-second inbound + propose delay — the slowest honest profile
//! the harness expresses, mirroring the existing slow profile in
//! `tests/nil_veto_stall_tests.rs` scaled to WAN latency).
//!
//! * `unanimity3_slow_honest_finalizes_with_generous_timeout` — generous base
//!   timeout: the slow voter's messages still arrive inside the round, QCs
//!   form, heights finalize, no fork.
//! * `unanimity3_tight_timeout_stalls_with_slow_voter` — tight base timeout:
//!   the same slow voter is always a round late, every round's votes go
//!   stale, 0 finalizations while rounds still advance (the stall shape).

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};

/// Virtual budget for the stall shape: dozens of timeout-driven rounds, short
/// enough that a stall reports instead of hanging.
const STALL_BUDGET_MS: u64 = 60_000;
/// Virtual budget for the liveness control: unanimity + a 65s slow link
/// needs room for several slow rounds (~one link delay per height).
const CONTROL_BUDGET_MS: u64 = 360_000;

/// Virtual tick quantum (matches the harness default).
const TICK_MS: u64 = 100;
/// Deterministic cluster seed (matches the harness default).
const SEED: u64 = 0x5741_5220_4C49_5645u64;
/// Tight base round timeout: the slow voter's ~3s link always exceeds it.
const TIGHT_BASE_MS: u64 = 1_000;
/// Generous base round timeout: comfortably above the slow link.
const GENEROUS_BASE_MS: u64 = 10_000;
/// Slow-link delay applied both inbound (proposals/votes TO the slow node)
/// and outbound (proposals FROM the slow node), so neither direction can
/// finalize without the slow voter. 65s exceeds the whole 60s stall budget:
/// under the tight 1s base the slow voter's first message arrives after the
/// budget is spent (rounds spin ~60x without it, votes stay split value/nil,
/// no unanimous QC), while the generous 10s base still absorbs the same link
/// (each height costs ~one delay, 3 heights fit in 240s). The discriminator
/// is the TIMEOUT, not the link — the production coupling.
const SLOW_LINK_MS: u64 = 65_000;

/// Powers [1,1,1]: total 3, quorum floor(2*3/3)+1 = 3 (unanimity). Any single
/// missing voter vetoes every QC.
fn unanimity3_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default()
            .with_power(1)
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_LINK_MS),
    ]
}

#[tokio::test]
async fn unanimity3_slow_honest_finalizes_with_generous_timeout() {
    let profiles = unanimity3_profiles();
    let mut c = ConsensusCluster::build(3, profiles, SEED, TICK_MS, GENEROUS_BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);

    let report = c.run_until(3, CONTROL_BUDGET_MS).await;

    // LIVENESS: unanimity still finalizes when the timeout covers the link.
    assert!(
        report.best_height >= 3,
        "generous timeout must absorb the slow voter.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    // SAFETY: no fork — exactly one decided block per height.
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 1, "height {h} must have exactly one decided block");
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "no honest node may double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}

#[tokio::test]
async fn unanimity3_tight_timeout_stalls_with_slow_voter() {
    let profiles = unanimity3_profiles();
    let mut c = ConsensusCluster::build(3, profiles, SEED, TICK_MS, TIGHT_BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);

    let report = c.run_until(2, STALL_BUDGET_MS).await;

    // LIVENESS: nothing finalizes — every round's votes go stale before the
    // slow voter can join them.
    assert_eq!(
        report.best_height, 0,
        "no node may finalize under unanimity while one voter is always late.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, 0,
        "the common head must not move.\n{}",
        report.diagnostics()
    );
    // ...while the round counter climbs on timeouts: votes flow, view changes
    // fire, nothing decides.
    for n in &report.nodes {
        assert!(
            n.round >= 5,
            "node {} must have burned view changes (round {}), not sat silent.\n{}",
            n.index,
            n.round,
            report.diagnostics()
        );
        assert_eq!(
            n.precommit_qc_round, None,
            "node {}: no precommit QC may form without unanimity.\n{}",
            n.index,
            report.diagnostics()
        );
    }
    // SAFETY: no fork — nothing finalized anywhere, so nothing conflicts.
    assert!(
        report.finalized_by_height().is_empty(),
        "a stalled height finalizes nothing, hence conflicts with nothing.\n{}",
        report.diagnostics()
    );
    assert!(
        report.double_votes(&[]).is_empty(),
        "slow-but-honest voters never double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "stalled nodes must not diverge.\n{}",
        report.diagnostics()
    );
}
