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

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)]
// GATE: replay test uses only `fvote_deterministic`; `fvote` stays for other suites.
mod falcon_votes;

use consensus_cluster::{ConsensusCluster, NodeProfile};
use stellereum::consensus::VoteKind;

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
        report
            .nodes
            .iter()
            .map(|n| n.decide_rounds.clone())
            .collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS: steady finalization.
    assert!(
        report.best_height >= TARGET_HEIGHT,
        "three honest validators must finalize.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
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
                    *d,
                    0,
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
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block"
        );
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
///
/// NOTE (Falcon W4.1): production vote signing draws fresh OS randomness per
/// signature (REQUIRED — a deterministic signer leaks the key), and block
/// hashes commit `last_qc` sig bytes, so two runs can never be byte-identical
/// past h1. The replay therefore compares the consensus-deterministic
/// projection (liveness, safety, state — everything that MUST match) via
/// `run_once` below, not the raw `fingerprint()` (which commits fresh
/// randomness). The TEST-ONLY `fvote_deterministic` canary pins that the
/// deterministic vote path itself is stable across the two runs.
#[tokio::test]
async fn happy3_deterministic_replay() {
    async fn run_once() -> String {
        // Canary: same vote contents must sign to the same bytes across runs
        // (second run hits the process-global cache — see `fvote_deterministic`).
        let (cks, cfks) = falcon_votes::falcon_set(1);
        let canary = falcon_votes::fvote_deterministic(
            0,
            &cks[0],
            &cfks[0],
            1,
            0,
            VoteKind::Prevote,
            Some([7u8; 32]),
        );
        let mut c = happy3_cluster();
        c.seed_transactions(3).await;
        let r = c.run_until(TARGET_HEIGHT, BUDGET_MS).await;
        // Deterministic projection: excludes finalized block hashes and vote
        // targets (both commit fresh Falcon randomness via `last_qc`).
        let mut out = format!(
            "run(vm={},ticks={},best={},common={})|canary={:?}",
            r.virtual_ms, r.ticks, r.best_height, r.common_height, canary.signature,
        );
        for n in &r.nodes {
            out.push_str(&format!(
                "|n{}(h={},r={},fh={},pc={},pp={},cc={},cp={},pr={},pf={},pvqc={:?},pcqc={:?},sr={:?},sj={},dr={:?})",
                n.index,
                n.height,
                n.round,
                n.finalized_height,
                n.prevotes_cast,
                n.prevotes_received,
                n.precommits_cast,
                n.precommits_received,
                n.proposals_received,
                n.proposals_refused,
                n.prevote_qc_round,
                n.precommit_qc_round,
                n.state_root,
                n.sync_jumps,
                n.decide_rounds,
            ));
            // Voting PATTERN only: targets are block-hash prefixes (random).
            for v in &n.cast_votes {
                let kind = match v.kind {
                    VoteKind::Prevote => "p",
                    VoteKind::Precommit => "c",
                };
                out.push_str(&format!("v{}/{}/{} ", v.height, v.round, kind));
            }
        }
        out
    }
    let (a, b) = (run_once().await, run_once().await);
    assert_eq!(a, b, "two identical runs must fingerprint identically");
    println!("[sim][happy3][replay] fingerprint stable ({a})");
}
