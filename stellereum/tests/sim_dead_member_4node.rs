//! # SIM-DEAD-MEMBER-4NODE: kill a member mid-scenario, watch the quorum.
//!
//! The static-DOWN cases (dead from genesis) are pinned in
//! `tests/consensus_liveness_harness.rs` (scenarios 3a/3b/4) and are NOT
//! repeated here. What was NOT expressible until the harness grew
//! [`ConsensusCluster::set_down`] is a kill AT TIME T — after the chain has
//! established liveness — which is the live shape (a validator dying
//! mid-epoch, not a set that boots short).
//!
//! * `four_nodes_kill_one_mid_run_slack_absorbs`: 4 equal-power nodes (quorum
//!   3), liveness established to height 2, then node 3 is killed. The
//!   remaining 3/4 ARE a quorum, so finalization continues; the dead node's
//!   finalized head stays frozen at the kill height.
//! * `three_node_unanimity_kill_one_mid_run_halts`: 3 nodes, powers [1,1,1]
//!   (quorum 3 = unanimity). Killing one leaves 2/3 < quorum: nothing new
//!   ever finalizes — WHILE ROUNDS KEEP ADVANCING on timeouts (the stall
//!   shape: votes flow, view changes fire, nothing decides). This is why a
//!   C-death under unanimity halts the chain.
//!
//! DETERMINISM: fixed [`SEED_*`] per test, virtual clock only. The kill time
//! T is itself deterministic (the virtual ms at which height 2 finalizes)
//! and is printed with every run.
//!
//! ```text
//! cargo test --test sim_dead_member_4node -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};

const SEED_A: u64 = 0xC10C_0003;
const SEED_B: u64 = 0xC10C_0004;
const TICK_MS: u64 = 100;
const ROUND_TIMEOUT_MS: u64 = 1_000;
/// Liveness-establishment phase: finalize this height BEFORE the kill.
const PRE_KILL_HEIGHT: u64 = 2;
const PRE_KILL_BUDGET_MS: u64 = 120_000;
/// Post-kill phase for the 4-node case (slack absorbs: keep finalizing).
const POST_KILL_TARGET: u64 = 5;
const POST_KILL_BUDGET_MS: u64 = 120_000;
/// Post-kill phase for the unanimity case (stall: rounds must still advance).
const STALL_MS: u64 = 60_000;

#[tokio::test]
async fn four_nodes_kill_one_mid_run_slack_absorbs() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
    ];
    // Quorum for equal power 4 = floor(2*4/3)+1 = 3.
    let mut c = ConsensusCluster::build(4, profiles, SEED_A, TICK_MS, ROUND_TIMEOUT_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;

    // Phase 1: establish liveness with all four up.
    let pre = c.run_until(PRE_KILL_HEIGHT, PRE_KILL_BUDGET_MS).await;
    assert!(
        pre.common_height >= PRE_KILL_HEIGHT,
        "liveness must be established before the kill.\n{}",
        pre.diagnostics()
    );
    // Phase 2: kill node 3 at time T.
    let kill_at = c.now_ms();
    c.set_down(3, true);
    let report = c.run_until(POST_KILL_TARGET, kill_at + POST_KILL_BUDGET_MS).await;

    println!(
        "[sim][dead-4node][slack] seed=0x{:x} kill_at={} virtual_ms={} best={} common={} \
         dead_finalized={} decide_rounds={:?}",
        SEED_A,
        kill_at,
        report.virtual_ms,
        report.best_height,
        report.common_height,
        report.nodes[3].finalized_height,
        report.nodes.iter().map(|n| n.decide_rounds.clone()).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS: 3/4 remaining ARE a quorum — finalization continues.
    assert!(
        report.common_height >= POST_KILL_TARGET,
        "three of four remaining must keep finalizing.\n{}",
        report.diagnostics()
    );
    // The dead node's head is frozen at the kill height (it finalizes
    // nothing while down; `common_height` excludes it by construction).
    assert_eq!(
        report.nodes[3].finalized_height, PRE_KILL_HEIGHT,
        "the killed node must not finalize past the kill.\n{}",
        report.diagnostics()
    );
    // SAFETY among the living: no fork, no double-votes, state agrees.
    let live: Vec<usize> = vec![0, 1, 2];
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries
            .iter()
            .filter(|(i, _)| live.contains(i))
            .map(|(_, x)| *x)
            .collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block among live nodes"
        );
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "no node may double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = live.iter().map(|i| report.nodes[*i].state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "live nodes must agree on state.\n{}",
        report.diagnostics()
    );
}

#[tokio::test]
async fn three_node_unanimity_kill_one_mid_run_halts() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
    ];
    // Powers [1,1,1]: quorum 3 = unanimity. Any single missing voter vetoes
    // every QC.
    let mut c = ConsensusCluster::build(3, profiles, SEED_B, TICK_MS, ROUND_TIMEOUT_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;

    // Phase 1: establish liveness with all three up.
    let pre = c.run_until(PRE_KILL_HEIGHT, PRE_KILL_BUDGET_MS).await;
    assert!(
        pre.common_height >= PRE_KILL_HEIGHT,
        "liveness must be established before the kill.\n{}",
        pre.diagnostics()
    );
    // Phase 2: kill node 2 at time T — 2/3 remain, quorum needs 3.
    let kill_at = c.now_ms();
    c.set_down(2, true);
    let report = c.run_for(STALL_MS).await;

    println!(
        "[sim][dead-4node][unanimity-halt] seed=0x{:x} kill_at={} virtual_ms={} best={} common={} \
         rounds={:?}",
        SEED_B,
        kill_at,
        report.virtual_ms,
        report.best_height,
        report.common_height,
        report.nodes.iter().map(|n| n.round).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS LOST: nothing new finalizes — 2/3 can never reach quorum 3.
    assert_eq!(
        report.best_height, PRE_KILL_HEIGHT,
        "no node may finalize past the kill under unanimity.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, PRE_KILL_HEIGHT,
        "the common head must not move.\n{}",
        report.diagnostics()
    );
    // ...WHILE ROUNDS KEEP ADVANCING on timeouts: votes flow, view changes
    // fire, nothing decides. THIS is the stall shape — a silent pair would
    // sit at round 0, not round 50+.
    for i in 0..2 {
        let n = &report.nodes[i];
        assert!(
            n.round >= 5,
            "live node {} must have burned view changes (round {}), not sat silent.\n{}",
            n.index,
            n.round,
            report.diagnostics()
        );
        // NOTHING DECIDED SINCE THE KILL: the decide rounds are frozen at
        // their pre-kill values (no new precommit QC anywhere). Note
        // `finalize_blockers()` is deliberately NOT asserted here: it only
        // names a blocker once a precommit QC exists, and quorum starvation
        // means none ever forms — the frozen decide rounds ARE the
        // diagnosis (`ConsensusCluster::report` also keeps the stale
        // `prevote_qc_round`, so a naive "a QC exists" read would lie).
        assert_eq!(
            n.decide_rounds, pre.nodes[i].decide_rounds,
            "live node {} decided something after the kill.\n{}",
            n.index,
            report.diagnostics()
        );
        // ...WHILE VOTES KEPT FLOWING: more prevotes cast than before the
        // kill proves the nodes are voting round after round, not wedged.
        assert!(
            n.prevotes_cast > pre.nodes[i].prevotes_cast,
            "live node {} stopped voting after the kill ({} prevotes, was {}).\n{}",
            n.index,
            n.prevotes_cast,
            pre.nodes[i].prevotes_cast,
            report.diagnostics()
        );
    }
    // SAFETY: a stalled height finalizes nothing, hence conflicts with
    // nothing — and nobody equivocates on the way down.
    for (h, entries) in report.finalized_by_height() {
        assert!(
            h <= PRE_KILL_HEIGHT,
            "nothing past the kill height may appear in any finalized chain (height {h})"
        );
        let _ = entries;
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "quorum starvation must not produce double-votes.\n{}",
        report.diagnostics()
    );
}
