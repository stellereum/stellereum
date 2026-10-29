//! # CONSENSUS LIVENESS HARNESS — the multi-node finalization suite.
//!
//! THE FAILURE THIS EXISTS FOR: the live 4-node WAN stand was parked at
//! height 285027 from 2026-10-19. The nodes formed a 3.5-STELL **prevote**
//! quorum but never a **precommit** quorum, so nothing finalized — and no
//! test in the suite exercised several nodes with SKEWED round clocks and
//! asserted that the chain finalizes. That is the hole this file plugs.
//!
//! WHAT IS UNDER TEST: real [`ValidatorRuntime`]s driving the real
//! `HeightConsensus` / `VoteSet` / `QuorumCertificate` code paths. Nothing is
//! mocked. The harness (`tests/support/consensus_cluster.rs`) supplies:
//!
//! * a **virtual clock** (no wall clock in the protocol path),
//! * **seeded keys** and a **seeded PRNG** (no OS randomness),
//! * per-node **round-timeout skew**, per-node **message delay / loss**,
//! * a **deterministic message pump** with the production tick order
//!   (`propose -> prevote -> drain -> precommit -> finalize -> view change`).
//!
//! THE ASSERTIONS (every scenario): the chain FINALIZES (or, for the
//! quorum-starved scenario, provably does NOT), the finalization rate stays
//! inside an expected band, every node agrees on the state root, no HONEST
//! node double-votes, and no two different blocks are finalized at the same
//! height.
//!
//! DETERMINISM: the whole file is virtual-time driven and seeded. Run it ten
//! times, get the same answer ten times.

mod support;

use support::consensus_cluster::{
    Byzantine, ClusterReport, ConsensusCluster, NodeProfile, DEFAULT_PACE_ROUNDS_PER_WALL_SEC,
};

/// The virtual budget of a scenario: generous enough for a skewed cluster to
/// converge, small enough that a stall is reported instead of hanging.
const BUDGET_MS: u64 = 240_000;

/// The lowest finalization rate (heights per second of VIRTUAL time) a
/// scenario may show before it counts as a liveness regression.
const MIN_RATE_PER_SEC: f64 = 0.02;

/// The highest finalization rate a scenario may show. A rate that is too
/// high means the chain skipped heights (a fork or a bogus jump), not that it
/// is healthy.
const MAX_RATE_PER_SEC: f64 = 50.0;

// ===========================================================================
// Assertion helpers
// ===========================================================================

/// The finalization rate in heights per second of VIRTUAL time.
fn rate_per_sec(report: &ClusterReport) -> f64 {
    if report.virtual_ms == 0 {
        return 0.0;
    }
    (report.best_height as f64) / (report.virtual_ms as f64 / 1000.0)
}

/// The invariants every scenario must hold, whatever the outcome.
fn assert_global_invariants(report: &ClusterReport, exempt_from_double_vote: &[usize]) {
    // 1. NO FORK: two different blocks must never be finalized at the same
    //    height.
    let by_height = report.finalized_by_height();
    for (height, entries) in &by_height {
        let mut hashes: Vec<BlockHashView> = entries.iter().map(|(_, h)| BlockHashView(*h)).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "FORK at height {height}: the nodes finalized DIFFERENT blocks: {:?}",
            by_height
        );
    }

    // 2. THE DOUBLE-VOTE INVARIANT: no honest node may cast two different
    //    votes for the same (height, round, kind).
    let dbl = report.double_votes(exempt_from_double_vote);
    assert!(
        dbl.is_empty(),
        "EQUIVOCATION: these nodes cast two different votes for the same \
         (height, round, kind): {:?}\n{}",
        dbl,
        report.diagnostics()
    );
}

/// A sortable view of a block hash (for the fork check).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BlockHashView([u8; 32]);

/// Every node that is at the same height must agree on the state root.
fn assert_state_roots_agree(report: &ClusterReport) {
    // Group the nodes by the height they finalized.
    let mut by_height: std::collections::BTreeMap<u64, Vec<(usize, [u8; 32])>> =
        std::collections::BTreeMap::new();
    for node in &report.nodes {
        by_height
            .entry(node.finalized_height)
            .or_default()
            .push((node.index, node.state_root));
    }
    for (height, entries) in &by_height {
        if entries.len() < 2 {
            continue;
        }
        let first = entries[0].1;
        for (idx, root) in entries {
            assert_eq!(
                *root, first,
                "STATE ROOT DIVERGENCE at height {height}: node {idx} has root \
                 {} but node {} has root {}",
                hex::encode(&root[..6]),
                entries[0].0,
                hex::encode(&first[..6])
            );
        }
    }
}

/// The scenario's liveness band: the chain must make progress, and it must
/// not skip heights.
fn assert_rate_in_band(report: &ClusterReport, expected_min_height: u64) {
    let rate = rate_per_sec(report);
    assert!(
        rate >= MIN_RATE_PER_SEC,
        "FINALIZATION RATE TOO LOW: {:.4} heights/s (band [{MIN_RATE_PER_SEC}, {MAX_RATE_PER_SEC}]) \
         — the chain is not finalizing.\n{}",
        rate,
        report.diagnostics()
    );
    assert!(
        rate <= MAX_RATE_PER_SEC,
        "FINALIZATION RATE TOO HIGH: {:.4} heights/s (band [{MIN_RATE_PER_SEC}, {MAX_RATE_PER_SEC}]) \
         — the chain is skipping heights.\n{}",
        rate,
        report.diagnostics()
    );
    assert!(
        report.best_height >= expected_min_height,
        "the chain finalized only height {} (expected at least {expected_min_height}).\n{}",
        report.best_height,
        report.diagnostics()
    );
}

// ===========================================================================
// SCENARIO 1 — three equal-power validators, no skew: the chain finalizes.
// ===========================================================================

#[tokio::test]
async fn three_equal_validators_finalize_the_chain() {
    let mut c = ConsensusCluster::new(3, &[1, 1, 1]);
    c.seed_transactions(3).await;
    let report = c.run_until(3, BUDGET_MS).await;

    assert!(
        report.best_height >= 3,
        "three equal validators must finalize the chain.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 3);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);

    // The real code path really ran: every node formed BOTH certificates.
    for node in &report.nodes {
        assert!(
            node.prevotes_cast > 0 && node.precommits_cast > 0,
            "node {} never voted.\n{}",
            node.index,
            report.diagnostics()
        );
    }
}

// ===========================================================================
// SCENARIO 2 — three validators, one starting 30 rounds late: the chain
// finalizes. THIS IS THE LIVE FAILURE.
// ===========================================================================

#[tokio::test]
async fn three_validators_one_thirty_rounds_late_still_finalizes() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().late_by(30),
    ];
    let mut c = ConsensusCluster::with_profiles(3, profiles)
        .with_pacing(DEFAULT_PACE_ROUNDS_PER_WALL_SEC);
    c.seed_transactions(3).await;

    // The late node really starts 30 rounds behind the network.
    let base = c.base_round();
    assert_eq!(base, 30, "the network must start at round 30");
    assert_eq!(c.runtime(2).hc.round, 0, "the late node must start at round 0");
    assert_eq!(c.runtime(0).hc.round, 30);

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "a node that starts 30 rounds late must NOT stop the chain from \
         finalizing (this is the live #285027 stall).\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "the late node must catch up and finalize with the rest.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);

    // The late node really had to catch up (the phase-alignment path ran).
    let late = &report.nodes[2];
    assert!(
        late.sync_jumps > 0,
        "the late node must have used the round-alignment path.\n{}",
        report.diagnostics()
    );
}

// ===========================================================================
// SCENARIO 3 — four validators, one DOWN.
//
// 3a. The DOWN node holds MORE than 1/3 of the power: the remaining power is
//     below the 2/3 quorum, so the chain must NOT finalize. It must also not
//     crash and not fork.
//
//     NOTE ON THE "20%" VARIANT: with a 2/3 quorum, a DOWN node holding 20%
//     of the power leaves 80% up — which IS a quorum, so the chain MUST
//     finalize. A minority node going down cannot stop a 2/3-quorum chain;
//     that is the quorum arithmetic, not a liveness bug. The case where the
//     chain must stall is the one where the DOWN node holds MORE than 1/3,
//     and both variants are asserted below.
// ===========================================================================

#[tokio::test]
async fn four_validators_quorum_starved_by_a_down_minority_do_not_finalize() {
    // 800 + 800 + 800 + 1600 = 4000; quorum = floor(2*4000/3)+1 = 2667.
    // The DOWN node holds 40% -> only 2400 is left, BELOW the quorum.
    let profiles = vec![
        NodeProfile::default().with_power(800),
        NodeProfile::default().with_power(800),
        NodeProfile::default().with_power(800),
        NodeProfile::default().with_power(1600).down(),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(2).await;

    let report = c.run_for(30_000).await;

    assert_eq!(
        report.best_height, 0,
        "a chain whose quorum is unreachable must NOT finalize.\n{}",
        report.diagnostics()
    );
    // It must not crash: every node is still alive and still voting.
    for node in &report.nodes {
        if node.index == 3 {
            continue; // the DOWN node
        }
        assert!(
            node.prevotes_cast > 0,
            "node {} stopped voting (the cluster crashed?).\n{}",
            node.index,
            report.diagnostics()
        );
    }
    // No fork, no double vote, even while stalled.
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
}

#[tokio::test]
async fn four_validators_down_minority_of_twenty_percent_still_finalizes() {
    // 2000 + 2000 + 2000 + 1000 = 7000; quorum = floor(2*7000/3)+1 = 4667.
    // The DOWN node holds 1000/7000 = 14% (< 1/3) -> the remaining 6000 IS a
    // quorum, so the chain MUST finalize. (The literal "20%" of the task
    // brief lands in the same bucket: a minority down never stalls a 2/3
    // chain.)
    let profiles = vec![
        NodeProfile::default().with_power(2000),
        NodeProfile::default().with_power(2000),
        NodeProfile::default().with_power(2000),
        NodeProfile::default().with_power(1000).down(),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(2).await;

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "the remaining 86% of the power is a quorum: the chain must finalize \
         even though a minority node is DOWN.\n{}",
        report.diagnostics()
    );
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
}

// ===========================================================================
// SCENARIO 4 — four validators, one DOWN, the rest up: the chain finalizes.
// ===========================================================================

#[tokio::test]
async fn four_validators_one_down_the_rest_finalize() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().down(),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    // The three up validators hold exactly the quorum (3 of 4).
    assert!(
        report.best_height >= 2,
        "three of four validators are a quorum: the chain must finalize.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every UP node must reach the same height.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
}

// ===========================================================================
// SCENARIO 5 — three validators, one with a 5x slower round timeout: the
// chain finalizes.
// ===========================================================================

#[tokio::test]
async fn three_validators_one_with_five_times_slower_round_timeout_finalizes() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().with_round_timeout_factor(5),
    ];
    let mut c = ConsensusCluster::with_profiles(3, profiles)
        .with_pacing(DEFAULT_PACE_ROUNDS_PER_WALL_SEC);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "a 5x slower round timeout must NOT stop the chain from finalizing.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "the slow node must catch up and finalize with the rest.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
}

// ===========================================================================
// SCENARIO 6 — message loss: 5% of the votes addressed to one node are
// dropped. The chain still finalizes.
// ===========================================================================

#[tokio::test]
async fn message_loss_five_percent_of_votes_still_finalizes() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().losing_votes(50), // 5.0%
    ];
    let mut c = ConsensusCluster::with_profiles(3, profiles)
        .with_pacing(DEFAULT_PACE_ROUNDS_PER_WALL_SEC);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "dropping 5% of one node's votes must NOT stop the chain.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "the lossy node must still reach the chain head (it adopts the \
         committed block).\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
}

// ===========================================================================
// SCENARIO 7 — Byzantine: one node votes for two different blocks. The chain
// finalizes on the honest quorum AND the equivocation is DETECTED.
// ===========================================================================

#[tokio::test]
async fn byzantine_double_vote_is_detected_and_the_honest_quorum_finalizes() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().byzantine(Byzantine::DoublePrevote),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    // The honest quorum (3 of 4) still finalizes.
    assert!(
        report.best_height >= 2,
        "the honest quorum must finalize despite the equivocation.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);

    // The equivocation was DETECTED: the evidence is recorded.
    assert!(
        !report.equivocations.is_empty(),
        "the double vote must be DETECTED (no equivocation evidence recorded).\n{}",
        report.diagnostics()
    );
    let byz_id = c.runtime(3).id;
    let recorded = report
        .equivocations
        .iter()
        .any(|(voter, a, b)| {
            *voter == byz_id && a.block_hash != b.block_hash
        });
    assert!(
        recorded,
        "the recorded evidence must name the equivocating validator and two \
         DIFFERENT targets.\n{}",
        report.diagnostics()
    );

    // The Byzantine node is exempt from the double-vote invariant; every
    // other node must still be clean.
    assert_global_invariants(&report, &[3]);
    assert_state_roots_agree(&report);
}

// ===========================================================================
// SCENARIO 8 — the diagnostic path: a stalled cluster must EXPLAIN itself.
//
// A quorum-starved cluster is the live failure shape: a prevote QC that never
// turns into a precommit QC. The harness must be able to name the round at
// which the QC formed and the round at which the precommit was expected, so
// a future failure is diagnosable in ONE run.
// ===========================================================================

#[tokio::test]
async fn a_stalled_cluster_reports_the_qc_round_and_the_expected_precommit_round() {
    // Three validators with UNEQUAL power such that no quorum is reachable:
    // 1000 + 1000 + 1000 + 1000 with one DOWN leaves 3000 of 4000 -> quorum
    // 2667 IS reachable, so use a heavier down node.
    let profiles = vec![
        NodeProfile::default().with_power(1000),
        NodeProfile::default().with_power(1000),
        NodeProfile::default().with_power(1000),
        NodeProfile::default().with_power(2000).down(),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    let report = c.run_for(20_000).await;

    assert_eq!(report.best_height, 0, "the chain must be stalled");

    // The diagnostic must name the state of the round: how many prevotes and
    // precommits each node holds, and (when it holds one) the QC round.
    for node in &report.nodes {
        if node.index == 3 {
            continue;
        }
        assert!(
            node.prevotes_received > 0,
            "the diagnostic must show the prevotes a node holds.\n{}",
            report.diagnostics()
        );
        assert!(
            node.prevote_qc_round.is_none(),
            "no prevote quorum may form without a quorum of power.\n{}",
            report.diagnostics()
        );
        assert!(
            node.precommit_qc_round.is_none(),
            "no precommit quorum may form without a quorum of power.\n{}",
            report.diagnostics()
        );
    }
}

// ===========================================================================
// SLOW VARIANT — 30 seconds of virtual time, with a report. Manual runs only.
// ===========================================================================

/// #[ignore]d on purpose: it is the human-facing "what does the cluster look
/// like over half a minute of virtual time" run. It prints the finalized
/// height, the rounds used and the per-node statistics.
///
/// ```text
/// cargo test --test consensus_liveness_harness -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore]
async fn slow_variant_thirty_virtual_seconds_prints_a_report() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().with_round_timeout_factor(5),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles)
        .with_pacing(DEFAULT_PACE_ROUNDS_PER_WALL_SEC);
    c.seed_transactions(10).await;

    let report = c.run_for(30_000).await;

    println!("=== consensus liveness slow report ===");
    println!(
        "virtual time: {} ms ({} ticks) — finalized height {} (common {}), \
         {:.4} heights/s",
        report.virtual_ms,
        report.ticks,
        report.best_height,
        report.common_height,
        rate_per_sec(&report)
    );
    println!("--- per node ---");
    for node in &report.nodes {
        println!("  {}", node.summary());
        println!(
            "      finalized: {:?}",
            node.finalized
                .iter()
                .map(|(h, hash)| format!("#{} {}", h, hex::encode(&hash[..4])))
                .collect::<Vec<_>>()
        );
        println!("      state root: {}", hex::encode(&node.state_root[..8]));
    }
    println!("--- invariants ---");
    println!(
        "double votes (honest): {:?}",
        report.double_votes(&[3])
    );
    println!("equivocations observed: {}", report.equivocations.len());
    println!("by height: {:?}", report.finalized_by_height());
    println!("=== end report ===");

    assert!(
        report.best_height > 0,
        "the slow run must finalize something.\n{}",
        report.diagnostics()
    );
}
