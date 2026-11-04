//! # SIM-BYZANTINE-EVICT: an equivocating PROPOSER cannot fork the chain.
//!
//! The vote-equivocation half is pinned elsewhere and is NOT repeated here:
//! `tests/nil_veto_stall_tests.rs` (`byzantine_plus_slow_honest_...` — a
//! double-PREVOTE voter plus a slow honest still finalizes) and
//! `tests/consensus_liveness_harness.rs` (scenario 7 — the double-vote is
//! detected as evidence and the honest quorum finalizes). What NEITHER file
//! covers is equivocation one level up: a PROPOSER signing two DIFFERENT
//! bodies for the SAME (height, round).
//!
//! WHAT IT PINS on 4 equal-power nodes with node 3 running
//! [`Byzantine::DoubleProposal`]: every time node 3 holds the proposal slot
//! it broadcasts its honest block AND a conflicting re-signed copy
//! (timestamp +1s, different hash). The production one-value rule
//! (`HeightConsensus::receive_proposal` keeps the FIRST body and refuses
//! "proposal already recorded for this round") contains it: honest nodes
//! vote the first body and refuse the second, so the chain keeps finalizing
//! with no fork. The refusals (`proposals_refused > 0` on honest nodes) are
//! the proof the attack actually ran in-sim — a green test with zero
//! refusals would mean the Byzantine never held the slot.
//!
//! NOTE on the invariant: proposer equivocation is NOT vote equivocation, so
//! `double_votes(&[])` — with NO exemption — must be empty: every vote every
//! node cast is still one vote per (height, round, kind).
//!
//! DETERMINISM: fixed [`SEED`], virtual clock only.
//!
//! ```text
//! cargo test --test sim_byzantine_evict -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ConsensusCluster, NodeProfile};

/// Fixed seed for the whole scenario. Any change moves every number below.
const SEED: u64 = 0xC10C_0006;
const TICK_MS: u64 = 100;
const ROUND_TIMEOUT_MS: u64 = 1_000;
const TARGET_HEIGHT: u64 = 5;
const BUDGET_MS: u64 = 240_000;
/// Index of the equivocating proposer.
const EVIL: usize = 3;

#[tokio::test]
async fn equivocating_proposer_cannot_fork_the_chain() {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().byzantine(Byzantine::DoubleProposal),
    ];
    let mut c = ConsensusCluster::build(4, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    // Quorum for equal power 4 = floor(2*4/3)+1 = 3: the three honest nodes
    // alone are a quorum, so the chain must not need the equivocator.
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET_HEIGHT, BUDGET_MS).await;

    let refused: u64 = report.nodes.iter().map(|n| n.proposals_refused).sum();
    println!(
        "[sim][byz-evict] seed=0x{:x} virtual_ms={} ticks={} best={} common={} decide_rounds={:?} \
         proposals_refused_total={} per_node={:?}",
        SEED,
        report.virtual_ms,
        report.ticks,
        report.best_height,
        report.common_height,
        report.nodes.iter().map(|n| n.decide_rounds.clone()).collect::<Vec<_>>(),
        refused,
        report.nodes.iter().map(|n| n.proposals_refused).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS: the honest 3/4 keep finalizing without the equivocator.
    assert!(
        report.best_height >= TARGET_HEIGHT,
        "an equivocating proposer must NOT stop finalization.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    // THE ATTACK RAN AND WAS CONTAINED: honest nodes saw the second body
    // and refused it (first-value rule). Zero refusals would mean the
    // Byzantine never held a proposal slot and the test proved nothing.
    assert!(
        refused > 0,
        "honest nodes must have refused the conflicting proposal.\n{}",
        report.diagnostics()
    );
    // The equivocator itself stays on the same chain (it votes honestly;
    // only its proposals equivocate), so it finalizes with everyone else.
    assert_eq!(
        report.nodes[EVIL].finalized_height, report.best_height,
        "the equivocating proposer must still finalize the decided chain.\n{}",
        report.diagnostics()
    );
    // SAFETY: no fork — exactly one decided block per height, even though
    // two bodies circulated for the same slots.
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block despite the equivocating proposer"
        );
    }
    // Proposer equivocation is not vote equivocation: with NO exemption,
    // every vote every node cast is one vote per (height, round, kind).
    assert!(
        report.double_votes(&[]).is_empty(),
        "the equivocating proposer must not double-VOTE.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}
