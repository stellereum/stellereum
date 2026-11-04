//! # SIM-HAPPY3: the sanity baseline — 3 honest equal-power validators.
//!
//! Every other scenario in `docs/SIMULATOR.md` is read AGAINST this one: if
//! this file ever goes red, the harness itself (or the consensus code it
//! drives) regressed — not the scenario under test.
//!
//! WHAT IT PINS: three honest validators with equal power finalize steadily
//! on the deterministic harness (`tests/support/consensus_cluster.rs`):
//! every height is decided within a round or two of proposal, every node
//! holds the same finalized chain and state root, and nobody double-votes.
//!
//! DETERMINISM: fixed [`SEED`], virtual clock only, no OS randomness. The
//! replay test runs the identical scenario twice and demands byte-identical
//! fingerprints.
//!
//! ```text
//! cargo test --test sim_happy3 -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};

/// Fixed seed for the whole scenario (harness PRNG + deterministic keys).
/// Any change to this constant changes every number below.
const SEED: u64 = 0xC10C_0001;
/// Virtual tick quantum (matches the harness default).
const TICK_MS: u64 = 100;
/// Base round timeout (matches the harness default).
const ROUND_TIMEOUT_MS: u64 = 1_000;
/// Heights to finalize: past the height-1 genesis transient (the virtual
/// clock starts at t=0, so height-1 blocks carry timestamp 0 and are refused
/// until virtual t>=1s) into steady state.
const TARGET_HEIGHT: u64 = 5;
/// Virtual budget: steady finalization needs seconds, not minutes.
const BUDGET_MS: u64 = 120_000;

fn happy3_cluster() -> ConsensusCluster {
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
    ];
    ConsensusCluster::build(3, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS)
}

#[tokio::test]
async fn happy3_steady_finalization() {
    let mut c = happy3_cluster();
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET_HEIGHT, BUDGET_MS).await;

    println!(
        "[sim][happy3] seed=0x{:x} virtual_ms={} ticks={} best={} common={} decide_rounds={:?}",
        SEED,
        report.virtual_ms,
        report.ticks,
        report.best_height,
        report.common_height,
        report.nodes.iter().map(|n| n.decide_rounds.clone()).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS: steady finalization.
    assert!(
        report.best_height >= TARGET_HEIGHT,
        "three honest validators must finalize.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    // An aligned cluster must not burn rounds: past the height-1 genesis
    // transient (the virtual clock starts at t=0, so height-1 proposals
    // carry timestamp 0 and are refused until virtual t>=1s — measured +2),
    // every height is decided in the FIRST round it is proposed in.
    for n in &report.nodes {
        for (k, d) in n.decide_rounds.iter().enumerate() {
            if k == 0 {
                assert!(
                    *d <= 4,
                    "node {} decided the height-1 transient in round +{d} (expected <= 4).\n{}",
                    n.index,
                    report.diagnostics()
                );
            } else {
                assert_eq!(
                    *d, 0,
                    "node {} decided height {} in round +{d} (expected 0).\n{}",
                    n.index,
                    k + 1,
                    report.diagnostics()
                );
            }
        }
        // Every node voted every height it finalized.
        assert!(
            n.prevotes_cast > 0 && n.precommits_cast > 0,
            "node {} never voted.\n{}",
            n.index,
            report.diagnostics()
        );
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
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}

/// The same scenario twice must produce the same result: seeded keys, seeded
/// PRNG, virtual clock — no wall clock, no OS randomness anywhere.
#[tokio::test]
async fn happy3_deterministic_replay() {
    async fn run_once() -> String {
        let mut c = happy3_cluster();
        c.seed_transactions(3).await;
        c.run_until(TARGET_HEIGHT, BUDGET_MS).await.fingerprint()
    }
    let (a, b) = (run_once().await, run_once().await);
    assert_eq!(a, b, "two identical runs must fingerprint identically");
    println!("[sim][happy3][replay] fingerprint stable ({a})");
}
