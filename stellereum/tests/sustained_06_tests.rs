//! # SUSTAINED-06 (SIM ONLY, no live touch).
//!
//! GOAL: 0.6s/block sustained proof in sim — virtual clock, deterministic seeds.
//! 3-member instant-link cluster with the fast (650ms-class) recipe runs 100+
//! heights asserting p50 block interval, zero stalls, no forks, degraded bound
//! with one slow member, and determinism.
//!
//! ## Mapping (env knob → harness-native param)
//!
//! | recipe knob | sim param | note |
//! |---|---|---|
//! | `STELL_ROUND_TIMEOUT_MS=650` | `ConsensusCluster::build(3, profiles, seed, 50, 650)` base | 1 virtual ms = 1 wall ms on every timeout/delay path |
//! | `STELL_STRAGGLER_{GRACE,CAP,FRESHNESS}_MS=1500/1500/3000` | `.with_straggler_policy(StragglerPolicy::fixed(1500, 1500, 3000))` | harness-supported mechanism; production mapping is a bounded additive hold outside the deterministic core |
//! | `STELL_ROUND_ZERO_TIMEOUT_MS=650` (default) | harness round-0 cap `min(base*factor, 650)` | automatic in `step_round_timeout`; no knob to set |
//! | `STELL_TICK_MS=50` (default) | `tick_ms=50` | production default |
//! | instant link (loopback, zero delay) | `inbound_delay_ms=0`, `propose_delay_ms=0` on all members | contrasts the 250ms-link cell of `sim_tempo_target06_tests.rs` |
//! | degraded: 1 slow member (5x timeouts) | third profile `.with_round_timeout_factor(5)` | same recipe cluster, one member 5x slower; link stays instant |
//! | `STELL_BROADCAST_JOIN_MS` / `STELL_CATCHUP_BUDGET_MS` | NOT modeled in-sim | WAN-only remainder |
//!
//! WHAT THIS ASSERTS (all virtual-clock, deterministic seeds; NO wall-clock asserts):
//! * fast: 100 measured heights, p50 per-height block ≤ 600 virtual ms
//!   (records p50/p95/max), ZERO stalls > 2000 virtual ms, no fork.
//! * degraded: same recipe + one 5x member, 100 measured heights,
//!   p50 ≤ 1500 virtual ms + finals advance in every 5s virtual window.
//! * determinism: identical rerun ⇒ identical fingerprint.
//!
//! WHAT THIS DOES NOT PROVE: WAN behaviour, CPU/apply cost (~0 virtual ms in
//! the harness; signatures really verify but virtual time does not advance),
//! join/catchup-budget effects.
//!
//! ```text
//! cargo test --test sustained_06_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile, StragglerPolicy};

/// Production tick default (ms).
const TICK_MS: u64 = 50;
/// Recipe base round timeout (ms).
const BASE_MS: u64 = 650;
/// Recipe straggler grace (ms).
const GRACE_MS: u64 = 1_500;
/// Recipe per-round cap (ms).
const CAP_MS: u64 = 1_500;
/// Recipe freshness window (ms).
const FRESHNESS_MS: u64 = 3_000;

/// Fast-path seed (deterministic, CLOC series).
const SEED_FAST: u64 = 0xC10C_0007;
/// Degraded-path seed (deterministic).
const SEED_SLOW: u64 = 0xC10C_0008;
/// Determinism rerun seed (deterministic).
const SEED_DET: u64 = 0xC10C_0009;

/// Measured heights after the t=0 genesis transient (height 1).
const HEIGHTS: u64 = 100;
/// Virtual budget per run_until step (abundant; run stops at target height).
const STEP_BUDGET_MS: u64 = 1_000_000;
/// Fast stall bound (virtual ms): any single height slower than this fails.
const STALL_BOUND_MS: u64 = 2_000;
/// Fast p50 bound (virtual ms).
const P50_BOUND_MS: u64 = 600;
/// Degraded p50 bound (virtual ms) with one 5x member.
const DEGRADED_P50_BOUND_MS: u64 = 1_500;
/// Degraded window: finals must advance in every window of this size.
const DEGRADED_WINDOW_MS: u64 = 5_000;
/// Degraded per-height stall bound (virtual ms).
const DEGRADED_STALL_BOUND_MS: u64 = 5_000;
/// Number of consecutive degraded windows that must each advance.
const DEGRADED_WINDOWS: u64 = 6;

fn instant_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
    ]
}

fn degraded_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default()
            .with_power(1)
            .with_round_timeout_factor(5),
    ]
}

fn recipe_cluster(profiles: Vec<NodeProfile>, seed: u64) -> ConsensusCluster {
    ConsensusCluster::build(3, profiles, seed, TICK_MS, BASE_MS)
        .with_straggler_policy(StragglerPolicy::fixed(GRACE_MS, CAP_MS, FRESHNESS_MS))
}

/// Mean + p50 + p95 + max over virtual-ms per-height deltas.
fn stats(mut dts: Vec<u64>) -> (f64, u64, u64, u64) {
    dts.sort_unstable();
    let n = dts.len();
    let mean = dts.iter().sum::<u64>() as f64 / n as f64;
    let p50 = dts[n / 2];
    let p95 = dts[((n as f64 * 0.95).ceil() as usize).max(1) - 1];
    let max = dts[n - 1];
    (mean, p50, p95, max)
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

/// Fast path: 100 measured heights on the instant-link recipe cluster;
/// p50 ≤ 0.6s virtual, zero stalls > 2s virtual, no fork.
#[tokio::test]
async fn sustained_fast_p50_no_stall_no_fork() {
    let mut c = recipe_cluster(instant_profiles(), SEED_FAST);
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;

    // Warmup: height 1 is the virtual-t=0 genesis transient; measure 2..=HEIGHTS+1.
    let warm = c.run_until(1, STEP_BUDGET_MS).await;
    assert_eq!(warm.common_height, 1, "warmup stall:\n{}", warm.diagnostics());
    let mut prev = warm.virtual_ms;
    let mut dts: Vec<u64> = Vec::with_capacity(HEIGHTS as usize);
    for h in 2..=(HEIGHTS + 1) {
        let r = c.run_until(h, STEP_BUDGET_MS).await;
        assert!(
            r.common_height >= h,
            "stall at height {h}:\n{}",
            r.diagnostics()
        );
        dts.push(r.virtual_ms - prev);
        prev = r.virtual_ms;
    }
    let report = c.run_until(HEIGHTS + 1, STEP_BUDGET_MS).await;
    let (mean, p50, p95, max) = stats(dts);
    println!(
        "[sim][sustained06][fast] seed=0x{SEED_FAST:x} heights={HEIGHTS} tick={TICK_MS} base={BASE_MS} grace={GRACE_MS}/{CAP_MS}/{FRESHNESS_MS}"
    );
    println!(
        "[sim][sustained06][fast] virtual_total={}ms mean={mean:.1}ms p50={p50}ms p95={p95}ms max={max}ms",
        report.virtual_ms
    );
    println!("{}", report.diagnostics());

    assert!(
        p50 <= P50_BOUND_MS,
        "p50 {p50}ms exceeds {P50_BOUND_MS}ms virtual budget.\n{}",
        report.diagnostics()
    );
    assert!(
        max <= STALL_BOUND_MS,
        "stall: a height took {max}ms (> {STALL_BOUND_MS}ms bound).\n{}",
        report.diagnostics()
    );
    assert!(
        report.best_height - report.common_height <= 1,
        "member trails by more than one height.\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report, "fast");
}

/// Degraded path: same recipe + one 5x-timeout member; p50 ≤ 1.5s virtual,
/// every height under the 5s stall bound, and finals advance in every
/// consecutive 5s virtual window; no fork.
#[tokio::test]
async fn sustained_degraded_slow_member_bounded() {
    let mut c = recipe_cluster(degraded_profiles(), SEED_SLOW);
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;

    let warm = c.run_until(1, STEP_BUDGET_MS).await;
    assert_eq!(warm.common_height, 1, "warmup stall:\n{}", warm.diagnostics());
    let mut prev = warm.virtual_ms;
    let mut dts: Vec<u64> = Vec::with_capacity(HEIGHTS as usize);
    for h in 2..=(HEIGHTS + 1) {
        let r = c.run_until(h, STEP_BUDGET_MS).await;
        assert!(
            r.common_height >= h,
            "degraded stall at height {h}:\n{}",
            r.diagnostics()
        );
        dts.push(r.virtual_ms - prev);
        prev = r.virtual_ms;
    }
    let report = c.run_until(HEIGHTS + 1, STEP_BUDGET_MS).await;
    let (mean, p50, p95, max) = stats(dts);
    println!(
        "[sim][sustained06][degraded] seed=0x{SEED_SLOW:x} heights={HEIGHTS} tick={TICK_MS} base={BASE_MS} grace={GRACE_MS}/{CAP_MS}/{FRESHNESS_MS} slow=5x"
    );
    println!(
        "[sim][sustained06][degraded] virtual_total={}ms mean={mean:.1}ms p50={p50}ms p95={p95}ms max={max}ms",
        report.virtual_ms
    );
    println!("{}", report.diagnostics());

    assert!(
        p50 <= DEGRADED_P50_BOUND_MS,
        "degraded p50 {p50}ms exceeds {DEGRADED_P50_BOUND_MS}ms virtual budget.\n{}",
        report.diagnostics()
    );
    assert!(
        max <= DEGRADED_STALL_BOUND_MS,
        "degraded stall: a height took {max}ms (> {DEGRADED_STALL_BOUND_MS}ms bound).\n{}",
        report.diagnostics()
    );
    assert_no_fork(&report, "degraded");

    // Windowed liveness on a fresh cluster: every consecutive 5s virtual
    // window must advance the common head.
    let mut w = recipe_cluster(degraded_profiles(), SEED_SLOW);
    w.seed_transactions(3).await;
    let mut prev_common = 0u64;
    for i in 0..DEGRADED_WINDOWS {
        let r = w.run_for(DEGRADED_WINDOW_MS).await;
        println!(
            "[sim][sustained06][degraded-window] window={i} common={} best={} virtual={}ms",
            r.common_height, r.best_height, r.virtual_ms
        );
        assert!(
            r.common_height > prev_common,
            "degraded window {i}: no finals in {DEGRADED_WINDOW_MS}ms virtual.\n{}",
            r.diagnostics()
        );
        prev_common = r.common_height;
    }
    let wreport = w.run_for(1).await;
    assert_no_fork(&wreport, "degraded-window");
}

/// Determinism: identical seed + identical recipe ⇒ identical fingerprint.
#[tokio::test]
async fn sustained_determinism_fingerprint_identical() {
    async fn run_once() -> consensus_cluster::ClusterReport {
        let mut c = recipe_cluster(instant_profiles(), SEED_DET);
        c.seed_transactions(3).await;
        c.run_until(HEIGHTS + 1, STEP_BUDGET_MS).await
    }

    let first = run_once().await;
    let second = run_once().await;
    println!(
        "[sim][sustained06][determinism] seed=0x{SEED_DET:x} heights={} common={} virtual={}ms",
        HEIGHTS, first.common_height, first.virtual_ms
    );
    assert!(
        first.common_height > HEIGHTS,
        "determinism run finalized only {} heights.\n{}",
        first.common_height,
        first.diagnostics()
    );
    assert_eq!(
        first.fingerprint(),
        second.fingerprint(),
        "recipe run must be deterministic.\n--- first ---\n{}\n--- second ---\n{}",
        first.diagnostics(),
        second.diagnostics()
    );
}
