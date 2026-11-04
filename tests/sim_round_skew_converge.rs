//! # SIM-ROUND-SKEW-CONVERGE: staggered round clocks reconverge.
//!
//! The single-late-node case (30 rounds behind) is pinned in
//! `tests/consensus_liveness_harness.rs` (scenario 2) and is NOT repeated
//! here. What that file does NOT cover is a STAGGERED cluster — several
//! nodes behind by DIFFERENT amounts at once — which is the live shape (the
//! 4-node WAN stand drifted apart gradually, not by one node teleporting 30
//! rounds back).
//!
//! WHAT IT PINS on 4 equal-power nodes: two members start behind by
//! different offsets (6 and 12 rounds, via `NodeProfile::late_by`), the
//! network starts at the highest offset, and the whole cluster reconverges:
//! every node finalizes every height, the late nodes consume the
//! future-rule round-jump path (`sync_jumps > 0` — the phase-alignment that
//! pulls a behind node into the network's round), no fork forms, and state
//! roots agree.
//!
//! DETERMINISM: fixed [`SEED`], virtual clock only.
//!
//! ```text
//! cargo test --test sim_round_skew_converge -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};

/// Fixed seed for the whole scenario. Any change moves every number below.
const SEED: u64 = 0xC10C_0005;
const TICK_MS: u64 = 100;
const ROUND_TIMEOUT_MS: u64 = 1_000;
const TARGET_HEIGHT: u64 = 3;
const BUDGET_MS: u64 = 240_000;

#[tokio::test]
async fn staggered_round_offsets_reconverge() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().late_by(6),
        NodeProfile::default().late_by(12),
    ];
    let mut c = ConsensusCluster::build(4, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    c.seed_transactions(3).await;

    // The network starts at the highest offset; the staggered nodes behind.
    assert_eq!(c.base_round(), 12, "the network must start at round 12");
    assert_eq!(c.runtime(0).hc.round, 12);
    assert_eq!(c.runtime(2).hc.round, 6, "the 6-late node starts at round 6");
    assert_eq!(c.runtime(3).hc.round, 0, "the 12-late node starts at round 0");

    let report = c.run_until(TARGET_HEIGHT, BUDGET_MS).await;

    println!(
        "[sim][skew] seed=0x{:x} virtual_ms={} ticks={} best={} common={} decide_rounds={:?} \
         sync_jumps={:?}",
        SEED,
        report.virtual_ms,
        report.ticks,
        report.best_height,
        report.common_height,
        report.nodes.iter().map(|n| n.decide_rounds.clone()).collect::<Vec<_>>(),
        report.nodes.iter().map(|n| n.sync_jumps).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS: the staggered cluster reconverges — every node finalizes.
    assert!(
        report.best_height >= TARGET_HEIGHT,
        "staggered round offsets must NOT stop finalization.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "the late nodes must catch up and finalize with the rest.\n{}",
        report.diagnostics()
    );
    // The reconvergence mechanism REALLY ran: both late nodes consumed the
    // future-rule round-jump path (peer votes pulling them into the
    // network's round). A passing test with zero jumps would mean the skew
    // never actually separated the nodes.
    for i in [2, 3] {
        assert!(
            report.nodes[i].sync_jumps > 0,
            "late node {i} must have used the round-alignment path.\n{}",
            report.diagnostics()
        );
    }
    // Convergence is FAST: past the height-1 genesis transient no height
    // costs the cluster more than a handful of rounds (the jumps refill per
    // view change, so a 12-round gap cannot stall a height for long).
    for n in &report.nodes {
        for (k, d) in n.decide_rounds.iter().enumerate().skip(1) {
            assert!(
                *d <= 16,
                "node {} decided height {} in round +{d}: reconvergence too slow.\n{}",
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
        "no honest node may double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "reconverged nodes must agree on state.\n{}",
        report.diagnostics()
    );
}
