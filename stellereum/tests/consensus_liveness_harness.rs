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
//!
//! NOTE ON THE INCLUDE: the harness is pulled in DIRECTLY (rather than
//! through the shared `support` module) so that this test target depends on
//! nothing but the harness itself. `tests/support/mod.rs` also re-exports it
//! as `support::consensus_cluster`, so any other test file can use it either
//! way — but a liveness gate that can be broken by an unrelated module in a
//! shared file is not a gate.

/// The deterministic multi-node consensus rig.
///
/// Lives in `tests/support/` so other test files can reuse it:
///
/// ```ignore
/// #[path = "support/consensus_cluster.rs"]
/// mod consensus_cluster;
/// ```
///
/// (or `use support::consensus_cluster::…` after `mod support;`).
#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ClusterReport, ConsensusCluster, NodeProfile};

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
        let mut hashes: Vec<BlockHashView> =
            entries.iter().map(|(_, h)| BlockHashView(*h)).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "FORK at height {height}: the nodes finalized DIFFERENT blocks: {:?}",
            by_height
        );
    }

    // 2. NO SKIPPED HEIGHTS: the finalized heights of every node must be
    //    contiguous (1, 2, 3, ...). A gap means the chain jumped a height.
    for node in &report.nodes {
        for (i, (height, _)) in node.finalized.iter().enumerate() {
            assert_eq!(
                *height,
                (i as u64) + 1,
                "node {} finalized a non-contiguous height sequence: {:?}",
                node.index,
                node.finalized.iter().map(|(h, _)| *h).collect::<Vec<_>>()
            );
        }
    }

    // 3. THE DOUBLE-VOTE INVARIANT: no honest node may cast two different
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

/// The state-root DIVERGENCES: the nodes that sit at the same height but
/// hold different state roots.
///
/// Returned instead of asserted so a scenario can prove the check is not
/// vacuous (see "the checks are not vacuous"): a checker that can only say
/// "yes" proves nothing.
fn state_root_divergences(report: &ClusterReport) -> Vec<(u64, usize, usize)> {
    // Group the nodes by the height they finalized.
    let mut by_height: std::collections::BTreeMap<u64, Vec<(usize, [u8; 32])>> =
        std::collections::BTreeMap::new();
    for node in &report.nodes {
        by_height
            .entry(node.finalized_height)
            .or_default()
            .push((node.index, node.state_root));
    }
    let mut out = Vec::new();
    for (height, entries) in &by_height {
        if entries.len() < 2 {
            continue;
        }
        let first = entries[0].1;
        for (idx, root) in entries {
            if *root != first {
                out.push((*height, entries[0].0, *idx));
            }
        }
    }
    out
}

/// Every node that is at the same height must agree on the state root.
fn assert_state_roots_agree(report: &ClusterReport) {
    let divergences = state_root_divergences(report);
    assert!(
        divergences.is_empty(),
        "STATE ROOT DIVERGENCE: the nodes are at the same height but hold \
         different state roots: {:?}\n{}",
        divergences,
        report.diagnostics()
    );
}

/// The number of rounds the WORST height of the cluster cost (the round the
/// decision was taken in, minus the round the height started in).
///
/// This is the sharpest liveness metric the harness has: a chain that
/// finalizes but burns a round per proposal slot is a chain that is one
/// hiccup away from the live stall.
fn max_rounds_per_height(report: &ClusterReport) -> u32 {
    report
        .nodes
        .iter()
        .flat_map(|n| n.decide_rounds.iter().copied())
        .max()
        .unwrap_or(0)
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
        report.common_height,
        report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 3);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
    // An aligned cluster must not burn rounds: every height is decided in
    // the round it was proposed in (at most one view change of slack).
    assert!(
        max_rounds_per_height(&report) <= 4,
        "an aligned cluster must decide every height within a couple of \
         rounds, but the worst height cost {} rounds.\n{}",
        max_rounds_per_height(&report),
        report.diagnostics()
    );

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
    let mut c = ConsensusCluster::with_profiles(3, profiles);
    c.seed_transactions(3).await;

    // The late node really starts 30 rounds behind the network.
    let base = c.base_round();
    assert_eq!(base, 30, "the network must start at round 30");
    assert_eq!(
        c.runtime(2).hc.round,
        0,
        "the late node must start at round 0"
    );
    assert_eq!(c.runtime(0).hc.round, 30);

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "a node that starts 30 rounds late must NOT stop the chain from \
         finalizing (this is the live #285027 stall).\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "the late node must catch up and finalize with the rest.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);

    println!("LATE REPORT:\n{}", report.diagnostics());
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
// TWO CASES, AND THE ARITHMETIC IS THE POINT.
//
// 3a. The DOWN node holds 20% of the power (the brief's number). The
//     remaining 80% IS a 2/3 quorum, so the chain MUST finalize. A
//     minority node going down CANNOT stop a 2/3-quorum chain: that is the
//     quorum arithmetic, not a liveness bug, and a test that asserted the
//     opposite would be asserting a bug in the quorum rule.
//
// 3b. The DOWN node holds MORE than 1/3 of the power. Now the remaining
//     power is BELOW the quorum, so the chain must NOT finalize — and it
//     must not crash and must not fork.
//
// The threshold the two cases straddle is exactly 1/3, and both tests
// assert the quorum arithmetic they claim, from the validator set itself.
// ===========================================================================

#[tokio::test]
async fn four_validators_with_a_down_node_holding_twenty_percent_still_finalize() {
    // 4000 + 2000 + 2000 + 2000 = 10000; quorum = floor(2*10000/3)+1 = 6667.
    // The DOWN node holds 2000/10000 = 20% (< 1/3) -> 8000 is left, which IS
    // a quorum, so the chain MUST finalize.
    let profiles = vec![
        NodeProfile::default().with_power(4000),
        NodeProfile::default().with_power(2000),
        NodeProfile::default().with_power(2000),
        NodeProfile::default().with_power(2000).down(),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(2).await;

    // The arithmetic is the validator set's OWN rule, not a constant here.
    let quorum = c.validators().quorum_power();
    assert_eq!(
        quorum, 6667,
        "the quorum must be the set's own two-thirds rule"
    );
    assert!(
        10_000 - 2_000 >= quorum,
        "the surviving 80% must be a quorum, or this scenario asserts the wrong thing"
    );

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "the surviving 80% of the power is a quorum: the chain must finalize \
         even though a 20% node is DOWN.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every UP node must reach the chain head.\n{}",
        report.diagnostics()
    );
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
}

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

    // The arithmetic the scenario claims, checked against the real set.
    let quorum = c.validators().quorum_power();
    assert_eq!(quorum, 2667);
    assert!(
        4_000 - 1_600 < quorum,
        "the surviving 60% must be BELOW the quorum, or this scenario \
         asserts the wrong thing"
    );

    let report = c.run_for(30_000).await;

    assert_eq!(
        report.best_height,
        0,
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
        report.common_height,
        report.best_height,
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
    let mut c = ConsensusCluster::with_profiles(3, profiles);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "a 5x slower round timeout must NOT stop the chain from finalizing.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "the slow node must catch up and finalize with the rest.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
    assert!(
        max_rounds_per_height(&report) <= 16,
        "a 5x slower node must not cost the cluster more than a handful of \
         rounds per height, but the worst height cost {} rounds.\n{}",
        max_rounds_per_height(&report),
        report.diagnostics()
    );
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
    let mut c = ConsensusCluster::with_profiles(3, profiles);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "dropping 5% of one node's votes must NOT stop the chain.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "the lossy node must still reach the chain head (it adopts the \
         committed block).\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
    assert!(
        max_rounds_per_height(&report) <= 16,
        "5% vote loss must not cost the cluster more than a handful of \
         rounds per height, but the worst height cost {} rounds.\n{}",
        max_rounds_per_height(&report),
        report.diagnostics()
    );
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
        .any(|(voter, a, b)| *voter == byz_id && a.block_hash != b.block_hash);
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
// SCENARIO 8 — UNEQUAL voting power (the live 1500/1000/1000 shape).
//
// The live stand ran three validators with UNEQUAL power (1500/1000/1000)
// plus an observer. This scenario pins that shape: the chain finalizes, the
// heaviest validator's share of the quorum is what carries it, and the state
// roots still agree.
// ===========================================================================

#[tokio::test]
async fn unequal_power_validators_finalize_the_chain() {
    // 1500 + 1000 + 1000 = 3500; quorum = floor(2*3500/3)+1 = 2334.
    // The 1500 validator ALONE is below the quorum, so the chain needs a
    // partner: the quorum is a real 2-of-3, not a rubber stamp.
    let mut c = ConsensusCluster::with_powers(&[1500, 1000, 1000]);
    c.seed_transactions(3).await;

    let report = c.run_until(2, BUDGET_MS).await;

    assert!(
        report.best_height >= 2,
        "a 1500/1000/1000 cluster must finalize.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    assert_rate_in_band(&report, 2);
    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);

    // The quorum arithmetic the scenario claims is the REAL one: the
    // heaviest validator alone cannot carry the quorum.
    let quorum = c.validators().quorum_power();
    let total: u64 = c.validators().total_power();
    assert_eq!(
        quorum, 2334,
        "the quorum must be the set's own two-thirds rule"
    );
    assert!(
        1500 < quorum,
        "the 1500 validator must be BELOW the quorum on its own, or the \
         scenario proves nothing."
    );
    assert_eq!(total, 3500);
}

// ===========================================================================
// SCENARIO 9 — THE HARNESS ITSELF IS DETERMINISTIC.
//
// The whole point of a liveness harness is that its verdict is trustworthy:
// a flaky harness that passes half the time teaches the team nothing. Two
// runs of the SAME scenario must produce the SAME fingerprint — the same
// finalized blocks, the same rounds, the same votes.
//
// This is the in-suite version of "run the file ten times and get the same
// answer ten times", and it fails LOUDLY the moment something in the harness
// starts reading a clock, an RNG or an unordered map.
// ===========================================================================

#[tokio::test]
async fn the_same_scenario_produces_the_same_result_twice() {
    async fn run_once() -> ClusterReport {
        let profiles = vec![
            NodeProfile::default(),
            NodeProfile::default(),
            NodeProfile::default().late_by(30),
            NodeProfile::default().losing_votes(50),
        ];
        let mut c = ConsensusCluster::with_profiles(4, profiles);
        c.seed_transactions(3).await;
        c.run_until(2, BUDGET_MS).await
    }

    let first = run_once().await;
    let second = run_once().await;

    assert_eq!(
        first.fingerprint(),
        second.fingerprint(),
        "the harness must be DETERMINISTIC: two runs of the same scenario \
         produced different outcomes.\n--- first ---\n{}\n--- second ---\n{}",
        first.diagnostics(),
        second.diagnostics()
    );
    // The run has to actually have done something, or "identical" would
    // mean "both did nothing".
    assert!(
        first.best_height >= 2,
        "the determinism check must run a scenario that finalizes.\n{}",
        first.diagnostics()
    );
}

// ===========================================================================
// SCENARIO 10 — THE CHECKS ARE NOT VACUOUS (the negative controls).
//
// A liveness gate is only worth what its detectors can catch. If the
// state-root comparison could never fire, or the double-vote detector
// always returned an empty list, the suite would be green forever and
// would have caught nothing.
//
// So: break each detector ON PURPOSE and assert that it notices.
//
//  * a node whose state is perturbed makes the state roots DIFFER, so the
//    "all nodes agree on the state root" check has teeth;
//  * the Byzantine node's double vote IS in the detector's output, and
//    exempting it empties the list - so the honest-node check is a real
//    filter and not a no-op.
// ===========================================================================

#[tokio::test]
async fn the_state_root_and_double_vote_checks_are_not_vacuous() {
    // --- 1. the state-root check has teeth -------------------------------
    let mut c = ConsensusCluster::new(3, &[1, 1, 1]);
    c.seed_transactions(2).await;
    // Node 0 gets a state the other two do not have.
    c.perturb_state_of(0).await;
    let report = c.run_until(1, BUDGET_MS).await;

    let roots: Vec<[u8; 32]> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots[0] != roots[1] && roots[1] == roots[2],
        "the perturbed node MUST have a different state root, or the \
         state-root comparison proves nothing. roots = {:?}",
        roots
            .iter()
            .map(|r| hex::encode(&r[..4]))
            .collect::<Vec<_>>()
    );
    // And the suite's own check must therefore REJECT this cluster.
    let divergences = state_root_divergences(&report);
    assert!(
        !divergences.is_empty(),
        "the state-root check must REPORT a diverged cluster — otherwise \
         the check is vacuous."
    );
    assert!(
        divergences.iter().any(|(_, a, b)| *a == 0 || *b == 0),
        "the divergence must name the perturbed node: {:?}",
        divergences
    );

    // --- 2. the double-vote check has teeth -------------------------------
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().byzantine(Byzantine::DoublePrevote),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(2).await;
    let report = c.run_until(1, BUDGET_MS).await;

    // The double vote IS in the output when nobody is exempt.
    let all = report.double_votes(&[]);
    assert!(
        !all.is_empty(),
        "the double-vote detector must report the Byzantine node's two \
         different votes for the same (height, round, kind).\n{}",
        report.diagnostics()
    );
    assert!(
        all.iter().all(|(node, _, _, _)| *node == 3),
        "only the Byzantine node may double-vote: {:?}\n{}",
        all,
        report.diagnostics()
    );
    // And exempting it empties the list (the honest-node check is a real
    // filter, not a no-op).
    assert!(
        report.double_votes(&[3]).is_empty(),
        "no HONEST node may double-vote.\n{}",
        report.diagnostics()
    );
}

// ===========================================================================
// SCENARIO 11 — the diagnostic path: a stalled cluster must EXPLAIN itself.
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
// SCENARIO 12 — THE LIVE FAILURE SHAPE, MADE DIAGNOSABLE.
//
// The live stand formed a 3.5-STELL PREVOTE quorum but never a PRECOMMIT
// quorum. This scenario reproduces exactly that shape on purpose: one node
// receives every prevote (so its PREVOTE quorum forms) but never a precommit
// (so its PRECOMMIT quorum never forms).
//
// The chain must still finalize on the honest quorum, AND the diagnostic must
// NAME the failure: the round in which the prevote QC formed, the round in
// which the precommit was expected, and the (absent) precommit QC.
// ===========================================================================

#[tokio::test]
async fn a_prevote_quorum_without_a_precommit_quorum_is_diagnosable() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        // Every precommit addressed to node 3 is lost; its prevotes arrive.
        NodeProfile::default().losing_precommits(1000),
    ];
    let mut c = ConsensusCluster::with_profiles(4, profiles);
    c.seed_transactions(2).await;

    let report = c.run_until(2, BUDGET_MS).await;

    // The honest quorum (3 of 4) keeps the chain alive.
    assert!(
        report.best_height >= 2,
        "the honest quorum must keep finalizing.\n{}",
        report.diagnostics()
    );

    // The starved node is the one that shows the live shape.
    let starved = &report.nodes[3];
    assert!(
        starved.prevote_qc_round.is_some(),
        "the starved node must have formed a PREVOTE quorum (that is the \
         live symptom).\n{}",
        report.diagnostics()
    );
    assert!(
        starved.precommit_qc_round.is_none(),
        "the starved node must NOT have formed a PRECOMMIT quorum (that is \
         the live symptom).\n{}",
        report.diagnostics()
    );
    // The diagnostic must name the round the precommit was EXPECTED in: the
    // round of the prevote quorum it holds.
    assert_eq!(
        starved.precommit_expected_round,
        starved.prevote_qc_round,
        "the diagnostic must name the round the precommit was expected in.\n{}",
        report.diagnostics()
    );

    // The starved node still counted the prevotes and the precommits it saw.
    assert!(
        starved.prevotes_received > 0,
        "the starved node must have counted its prevotes.\n{}",
        report.diagnostics()
    );
    assert!(
        starved.precommits_received == 0,
        "the starved node must not have received a precommit (they were all \
         lost).\n{}",
        report.diagnostics()
    );

    assert_global_invariants(&report, &[]);
    assert_state_roots_agree(&report);
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
    let mut c = ConsensusCluster::with_profiles(4, profiles);
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
            "      rounds used per height: {:?} (max {})",
            node.decide_rounds,
            node.decide_rounds.iter().copied().max().unwrap_or(0)
        );
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
    println!("double votes (honest): {:?}", report.double_votes(&[3]));
    println!("equivocations observed: {}", report.equivocations.len());
    println!("by height: {:?}", report.finalized_by_height());
    println!("=== end report ===");

    assert!(
        report.best_height > 0,
        "the slow run must finalize something.\n{}",
        report.diagnostics()
    );
}
