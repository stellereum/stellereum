//! # TEMPO-RECIPE validation (SIM ONLY, no live touch).
//!
//! GOAL: validate the 0.6s/block recipe in SIM on a 3-member instant-link
//! cluster with recipe-class timeouts: 650ms round timeout + straggler grace
//! via the harness-supported mechanism (`StragglerPolicy`).
//!
//! RECIPE UNDER TEST (production env names; sim mapping in §Mapping):
//! ```text
//! STELL_ROUND_TIMEOUT_MS=650
//! STELL_STRAGGLER_GRACE_MS=1500
//! STELL_STRAGGLER_GRACE_CAP_MS=1500
//! STELL_STRAGGLER_FRESHNESS_MS=3000
//! # STELL_ROUND_ZERO_TIMEOUT_MS left at default (650)
//! # STELL_TICK_MS left at default (50)
//! ```
//!
//! ## Mapping (env knob → harness-native param)
//!
//! | recipe knob | sim param | note |
//! |---|---|---|
//! | `STELL_ROUND_TIMEOUT_MS=650` | `ConsensusCluster::build(3, profiles, seed, 50, 650)` base | 1 virtual ms = 1 wall ms on every timeout/delay path |
//! | `STELL_STRAGGLER_{GRACE,CAP,FRESHNESS}_MS=1500/1500/3000` | `.with_straggler_policy(StragglerPolicy::fixed(1500, 1500, 3000))` | harness-supported mechanism; production mapping is a bounded additive hold outside the deterministic core (see `docs/PROPOSER_REWORK.md` §2c) |
//! | `STELL_ROUND_ZERO_TIMEOUT_MS=650` (default) | harness round-0 cap `min(base*factor, 650)` | automatic in `step_round_timeout`; no knob to set |
//! | `STELL_TICK_MS=50` (default) | `tick_ms=50` | production default |
//! | instant link (loopback, zero delay) | `inbound_delay_ms=0`, `propose_delay_ms=0` on all members | contrasts the 250ms-link cell of `sim_tempo_target06_tests.rs`; matches `scripts/local-cluster.sh` loopback topology but NOT its hardcoded `10000/2000/8000` timeouts (no env passthrough there — see `docs/TEMPO_LOCAL_EVIDENCE.md` §2) |
//! | `STELL_BROADCAST_JOIN_MS` / `STELL_CATCHUP_BUDGET_MS` | NOT modeled in-sim | WAN-only remainder, listed in `docs/TEMPO_RECIPE_VALIDATION.md` |
//!
//! WHAT THIS ASSERTS (all virtual-clock, deterministic seeds):
//! * sustained finals rate: p50 per-height block < 1000 virtual ms, mean <= 800 virtual ms.
//! * no stalls: max per-height dt <= 5000 virtual ms; `best - common <= 1`.
//! * no forks: one hash per height, no double votes, state roots agree.
//!
//! WHAT THIS DOES NOT PROVE: WAN behaviour, CPU/apply cost (~0 virtual ms in
//! the harness; signatures really verify but virtual time does not advance),
//! join/catchup-budget effects. Listed honestly in the validation doc.
//!
//! ```text
//! cargo test --test tempo_recipe_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile, StragglerPolicy};

/// Production tick default (50ms).
const TICK_MS: u64 = 50;
/// Recipe base round timeout (ms).
const BASE_MS: u64 = 650;
/// Recipe straggler grace (ms).
const GRACE_MS: u64 = 1_500;
/// Recipe per-round cap (ms).
const CAP_MS: u64 = 1_500;
/// Recipe freshness window (ms).
const FRESHNESS_MS: u64 = 3_000;

/// Sustained-rate seed (deterministic, CLOC series).
const SEED_A: u64 = 0xC10C_0007;
/// Window/stall seeds (deterministic).
const SEED_B: u64 = 0xC10C_0008;
const SEED_C: u64 = 0xC10C_0009;

/// Heights measured after the t=0 genesis transient (height 1).
const HEIGHTS_A: u64 = 80;
/// Virtual budget per run_until step (abundant; run stops at target height).
const STEP_BUDGET_MS: u64 = 1_000_000;
/// Fixed virtual window for the no-stall test.
const WINDOW_MS: u64 = 60_000;
/// Stall bound (virtual ms): any single height slower than this fails.
const STALL_BOUND_MS: u64 = 5_000;

fn instant_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
    ]
}

fn recipe_cluster(seed: u64) -> ConsensusCluster {
    ConsensusCluster::build(3, instant_profiles(), seed, TICK_MS, BASE_MS)
        .with_straggler_policy(StragglerPolicy::fixed(GRACE_MS, CAP_MS, FRESHNESS_MS))
}

/// Median + nearest-rank p99 over virtual-ms per-height deltas.
fn stats(mut dts: Vec<u64>) -> (f64, u64, u64, u64) {
    dts.sort_unstable();
    let n = dts.len();
    let mean = dts.iter().sum::<u64>() as f64 / n as f64;
    let p50 = dts[n / 2];
    let p99 = dts[((n as f64 * 0.99).ceil() as usize).max(1) - 1];
    let max = dts[n - 1];
    (mean, p50, p99, max)
}

fn assert_no_fork(report: &consensus_cluster::ClusterReport, ctx: &str) {
    for (h, entries) in report.finalized_by_height() {
        let mut hs: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hs.sort();
        hs.dedup();
        assert_eq!(hs.len(), 1, "{ctx}: FORK at height {h}");
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "{ctx}: double vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "{ctx}: state divergence.\n{}",
        report.diagnostics()
    );
}

/// Sustained-rate validation: 80 consecutive heights on the instant-link
/// recipe cluster; p50 < 1s virtual, mean <= 0.8s virtual, no height slower
/// than the 5s stall bound, no fork.
#[tokio::test]
async fn tempo_recipe_sustained_p50_and_rate() {
    let mut c = recipe_cluster(SEED_A);
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;

    // Warmup: height 1 is the virtual-t=0 genesis transient (timestamp-0
    // proposals refused until t>=1s); measure heights 2..=HEIGHTS_A+1.
    let warm = c.run_until(1, STEP_BUDGET_MS).await;
    assert_eq!(warm.common_height, 1, "warmup stall:\n{}", warm.diagnostics());
    let mut prev = warm.virtual_ms;
    let mut dts: Vec<u64> = Vec::with_capacity(HEIGHTS_A as usize);
    for h in 2..=(HEIGHTS_A + 1) {
        let r = c.run_until(h, STEP_BUDGET_MS).await;
        assert!(
            r.common_height >= h,
            "stall at height {h}:\n{}",
            r.diagnostics()
        );
        dts.push(r.virtual_ms - prev);
        prev = r.virtual_ms;
    }
    let report = c.run_until(HEIGHTS_A + 1, STEP_BUDGET_MS).await;
    let (mean, p50, p99, max) = stats(dts);
    let per_hour = report.common_height * 3_600_000 / report.virtual_ms.max(1);
    let total_vc: u64 = report.nodes.iter().map(|n| n.view_changes).sum();
    let vc_per_final = total_vc as f64 / report.common_height.max(1) as f64;
    let total_grace: u64 = report.nodes.iter().map(|n| n.grace_extends).sum();
    println!(
        "[sim][tempo-recipe][sustained] seed=0x{SEED_A:x} heights={HEIGHTS_A} tick={TICK_MS} base={BASE_MS} grace={GRACE_MS}/{CAP_MS}/{FRESHNESS_MS}"
    );
    println!(
        "[sim][tempo-recipe][sustained] virtual_total={}ms mean={mean:.1}ms p50={p50}ms p99={p99}ms max={max}ms per_hour={per_hour} vc/final={vc_per_final:.2} grace={total_grace}",
        report.virtual_ms
    );
    println!("{}", report.diagnostics());

    assert!(
        p50 < 1_000,
        "p50 {p50}ms exceeds 1s virtual budget.\n{}",
        report.diagnostics()
    );
    assert!(
        mean <= 800.0,
        "mean {mean:.1}ms exceeds 0.8s virtual budget.\n{}",
        report.diagnostics()
    );
    assert!(
        max <= STALL_BOUND_MS,
        "stall: a height took {max}ms (> {STALL_BOUND_MS}ms bound).\n{}",
        report.diagnostics()
    );
    assert!(
        per_hour >= 4_500,
        "rate {per_hour}/h below 0.8s/block bar.\n{}",
        report.diagnostics()
    );
    assert!(
        report.best_height - report.common_height <= 1,
        "member trails by more than one height.\n{}",
        report.diagnostics()
    );
    assert!(
        vc_per_final <= 3.0,
        "view-change storm: {vc_per_final:.2}/final.\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report, "sustained");
}

/// Fixed-window no-stall + determinism validation: 60 virtual seconds must
/// finalize steadily with no height gap above the stall bound (checked via a
/// second per-height pass on another seed), no fork, and a rerun must be
/// fingerprint-identical.
#[tokio::test]
async fn tempo_recipe_window_no_stall_deterministic() {
    let mut c = recipe_cluster(SEED_B);
    c.seed_transactions(3).await;
    let report = c.run_for(WINDOW_MS).await;
    let finals = report.common_height;
    let per_hour = finals * 3_600_000 / WINDOW_MS;
    let mean_ms = if finals > 0 { WINDOW_MS / finals } else { u64::MAX };
    let total_vc: u64 = report.nodes.iter().map(|n| n.view_changes).sum();
    let vc_per_final = total_vc as f64 / finals.max(1) as f64;
    println!(
        "[sim][tempo-recipe][window] seed=0x{SEED_B:x} finals={finals} per_hour={per_hour} mean_ms={mean_ms} vc/final={vc_per_final:.2}"
    );
    println!("{}", report.diagnostics());

    assert!(
        finals >= 50,
        "window finalized only {finals} heights in {WINDOW_MS}ms virtual.\n{}",
        report.diagnostics()
    );
    assert!(
        per_hour >= 3_000,
        "window rate {per_hour}/h below 1.2s/block floor.\n{}",
        report.diagnostics()
    );
    assert!(
        report.best_height - report.common_height <= 1,
        "member trails by more than one height.\n{}",
        report.diagnostics()
    );
    assert!(
        vc_per_final <= 3.0,
        "view-change storm: {vc_per_final:.2}/final.\n{}",
        report.diagnostics()
    );
    for n in &report.nodes {
        assert!(
            n.wasted_share() < 0.10,
            "node {} wasted share {:.3}.\n{}",
            n.index,
            n.wasted_share(),
            report.diagnostics()
        );
    }
    assert_no_fork(&report, "window");

    // Determinism: identical rerun prints the identical fingerprint.
    let mut c2 = recipe_cluster(SEED_B);
    c2.seed_transactions(3).await;
    let r2 = c2.run_for(WINDOW_MS).await;
    assert_eq!(
        report.fingerprint(),
        r2.fingerprint(),
        "recipe run must be deterministic"
    );

    // Third seed, per-height stall pass (short): every height under the bound.
    let mut c3 = recipe_cluster(SEED_C);
    c3.seed_transactions(3).await;
    let warm = c3.run_until(1, STEP_BUDGET_MS).await;
    assert_eq!(warm.common_height, 1);
    let mut prev = warm.virtual_ms;
    let mut max_dt = 0u64;
    for h in 2..=21 {
        let r = c3.run_until(h, STEP_BUDGET_MS).await;
        assert!(r.common_height >= h, "seed_C stall at {h}:\n{}", r.diagnostics());
        max_dt = max_dt.max(r.virtual_ms - prev);
        prev = r.virtual_ms;
    }
    println!("[sim][tempo-recipe][seedC] heights=20 max_dt={max_dt}ms bound={STALL_BOUND_MS}ms");
    assert!(
        max_dt <= STALL_BOUND_MS,
        "seed 0x{SEED_C:x}: stall {max_dt}ms.\n{}",
        c3.run_until(21, STEP_BUDGET_MS).await.diagnostics()
    );
}
