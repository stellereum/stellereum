//! # Consensus 9.5 adversarial sim battery (N=7).
//!
//! Four deterministic virtual-clock scenarios on the real consensus path
//! (`tests/support/consensus_cluster.rs`): equivocating leader, slow-leader
//! rotation, vote-withholding minority, and a combined fault. N=7 everywhere
//! (quorum 5); every test pins liveness (rate > 0), no-fork, and evidence
//! presence — never exact timing counts.
//!
//! ```text
//! cargo test --test consensus_byzantine_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ConsensusCluster, NodeProfile};

const TICK_MS: u64 = 100;
const ROUND_TIMEOUT_MS: u64 = 1_000;
/// N used by every test in this battery.
const N: usize = 7;
/// Equal-power quorum for N=7: floor(2*7/3)+1 = 5.
const QUORUM_7: u64 = 5;

fn honest7() -> Vec<NodeProfile> {
    (0..N).map(|_| NodeProfile::default()).collect()
}

fn assert_no_fork(report: &consensus_cluster::ClusterReport) {
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block.\n{}",
            report.diagnostics()
        );
    }
}

fn finalize_rate_per_sec(report: &consensus_cluster::ClusterReport) -> f64 {
    if report.virtual_ms == 0 {
        return 0.0;
    }
    report.best_height as f64 / (report.virtual_ms as f64 / 1000.0)
}

/// (a) Equivocating leader: node 6 double-proposes whenever it holds the
/// slot. Honest supermajority must finalize exactly one fork; the refused
/// second bodies prove the attack ran.
#[tokio::test]
async fn equivocating_leader_finalizes_single_fork() {
    const SEED: u64 = 0xB92A_0001;
    const TARGET: u64 = 4;
    const BUDGET_MS: u64 = 240_000;
    let mut profiles = honest7();
    profiles[6] = NodeProfile::default().byzantine(Byzantine::DoubleProposal);
    let mut c = ConsensusCluster::build(N, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    assert_eq!(c.validators().quorum_power(), QUORUM_7);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;
    let refused: u64 = report.nodes.iter().map(|n| n.proposals_refused).sum();
    let rate = finalize_rate_per_sec(&report);
    println!(
        "[byz][equiv-leader] N={N} seed=0x{SEED:x} virtual_ms={} best={} common={} refused={refused} rate={rate:.4}/s",
        report.virtual_ms, report.best_height, report.common_height,
    );
    println!("{}", report.diagnostics());
    assert!(
        report.best_height >= TARGET,
        "honest supermajority must finalize despite the equivocating leader.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same head.\n{}",
        report.diagnostics()
    );
    assert!(
        refused > 0,
        "equivocation must be observed (honest refusals of the second body).\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report);
    assert!(
        report.double_votes(&[]).is_empty(),
        "proposer equivocation must not become vote equivocation.\n{}",
        report.diagnostics()
    );
    assert!(rate > 0.0, "finalization rate must be positive");
}

/// (b) Slow-leader rotation: nodes 1/3/5 run 3x/4x/5x round timeouts, so slow
/// proposers regularly hold the slot. Finals must keep moving; the degraded
/// rate is recorded (bounded: rate > 0, no exact-count pin).
#[tokio::test]
async fn slow_leader_rotation_keeps_finalizing() {
    const SEED: u64 = 0xB92A_0002;
    const TARGET: u64 = 3;
    const BUDGET_MS: u64 = 240_000;
    let mut profiles = honest7();
    profiles[1] = NodeProfile::default().with_round_timeout_factor(3);
    profiles[3] = NodeProfile::default().with_round_timeout_factor(4);
    profiles[5] = NodeProfile::default().with_round_timeout_factor(5);
    let mut c = ConsensusCluster::build(N, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    assert_eq!(c.validators().quorum_power(), QUORUM_7);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;
    let rate = finalize_rate_per_sec(&report);
    println!(
        "[byz][slow-rotation] N={N} seed=0x{SEED:x} virtual_ms={} best={} common={} rate={rate:.4}/s decide={:?}",
        report.virtual_ms,
        report.best_height,
        report.common_height,
        report.nodes.iter().map(|n| n.decide_rounds.clone()).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());
    assert!(
        report.best_height >= TARGET,
        "chain must keep finalizing through slow-leader slots.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same head.\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report);
    assert!(
        report.double_votes(&[]).is_empty(),
        "no node may double-vote.\n{}",
        report.diagnostics()
    );
    assert!(rate > 0.0, "degraded finalization rate must stay positive");
}

/// (c) Vote-withholding minority: f=2 of 7 silent (down). Quorum 5 of 5-up
/// still holds, so the chain must not stall.
#[tokio::test]
async fn vote_withholding_minority_no_stall() {
    const SEED: u64 = 0xB92A_0003;
    const TARGET: u64 = 3;
    const BUDGET_MS: u64 = 240_000;
    let mut profiles = honest7();
    profiles[5] = NodeProfile::default().down();
    profiles[6] = NodeProfile::default().down();
    let mut c = ConsensusCluster::build(N, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    assert_eq!(c.validators().quorum_power(), QUORUM_7);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;
    let rate = finalize_rate_per_sec(&report);
    println!(
        "[byz][withhold] N={N} f=2 silent seed=0x{SEED:x} virtual_ms={} best={} common={} rate={rate:.4}/s",
        report.virtual_ms, report.best_height, report.common_height,
    );
    println!("{}", report.diagnostics());
    assert!(
        report.best_height >= TARGET,
        "5-of-7 up must still reach quorum without the 2 silent nodes.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every UP node must reach the same head.\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report);
    for n in report.nodes.iter().filter(|n| n.index < 5) {
        assert!(
            n.prevotes_cast > 0 && n.precommits_cast > 0,
            "up node {} must keep voting.\n{}",
            n.index,
            report.diagnostics()
        );
    }
    assert!(rate > 0.0, "finalization rate must be positive");
}

/// (d) Combined: 1 equivocator (node 4) + 1 slow 5x node (node 5) + 1 down
/// node (node 6). The 4 fast-honest plus the slow/equivocating voters still
/// clear quorum 5; the chain stays live with refusal evidence recorded.
#[tokio::test]
async fn combined_equivocator_slow_down_stays_live() {
    const SEED: u64 = 0xB92A_0004;
    const TARGET: u64 = 3;
    const BUDGET_MS: u64 = 240_000;
    let mut profiles = honest7();
    profiles[4] = NodeProfile::default().byzantine(Byzantine::DoubleProposal);
    profiles[5] = NodeProfile::default().with_round_timeout_factor(5);
    profiles[6] = NodeProfile::default().down();
    let mut c = ConsensusCluster::build(N, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    assert_eq!(c.validators().quorum_power(), QUORUM_7);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;
    let refused: u64 = report.nodes.iter().map(|n| n.proposals_refused).sum();
    let rate = finalize_rate_per_sec(&report);
    println!(
        "[byz][combined] N={N} evil=4 slow=5 down=6 seed=0x{SEED:x} virtual_ms={} best={} common={} refused={refused} rate={rate:.4}/s",
        report.virtual_ms, report.best_height, report.common_height,
    );
    println!("{}", report.diagnostics());
    assert!(
        report.best_height >= TARGET,
        "chain must stay live on 4/7 fast-honest + slow + equivocating voters.\n{}",
        report.diagnostics()
    );
    let up_common = report
        .nodes
        .iter()
        .filter(|n| n.index != 6)
        .map(|n| n.finalized_height)
        .min()
        .unwrap_or(0);
    assert_eq!(
        up_common, report.best_height,
        "every UP node must reach the same head.\n{}",
        report.diagnostics()
    );
    assert!(
        refused > 0,
        "equivocation evidence (refused second bodies) must be recorded.\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report);
    assert!(
        report.double_votes(&[]).is_empty(),
        "no vote equivocation allowed.\n{}",
        report.diagnostics()
    );
    assert!(rate > 0.0, "finalization rate must be positive");
}
