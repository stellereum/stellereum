//! # Tick x down-proposer tuning sweep (SIM ONLY, virtual clock).
//!
//! GOAL (0.6s/block, safety-first): tune tick / down-proposer fast-path in SIM
//! without touching prod consts. Read-only prod pins under test:
//! * `TICK_MS = 50` (`src/main.rs`): prod tick quantum.
//! * `DOWN_PROPOSER_TIMEOUT_DEFAULT_MS = 800` (`src/main.rs`): down-proposer
//!   fast-path timeout (effective `min(backoff, down_timeout)`).
//! * `NIL_CIRCUIT_BREAKER_K` + `ROUND_LOOKBACK` (`src/consensus.rs`): breaker
//!   bounds (see `tests/liveness_breaker_tests.rs` idiom).
//!
//! HARNESS MAPPING (the sim has no down-proposer path, so it is emulated):
//! * `tick_ms` injects directly (`ConsensusCluster::build` tick param).
//! * down-proposer injects by scaling the harness round base proportionally:
//!   `harness_base = round(650 * down_ms / 800)`, where 650ms is the production
//!   round-0 proposal-wait cap the harness mirrors (`eff.min(650)` in
//!   `tests/support/consensus_cluster.rs`). Cells:
//!   `800 -> 650ms`, `400 -> 325ms`, `300 -> 244ms` (244 = round(650*300/800)).
//!   Tick grid `{50, 20, 10}ms` x down grid `{800, 400, 300}ms` = 9 cells.
//!   Smaller down-proposer => smaller base => faster round turnover in-sim,
//!   which is exactly the direction the prod fast path moves.
//!
//! WHAT EACH CELL MEASURES (virtual time only, no wall-clock asserts):
//! * healthy soak (3 equal nodes): per-height block intervals collected by
//!   incremental `run_until(h)`; reported p50 + mean; false positives counted
//!   as (nil-breaker due on any node) + (nil prevotes cast) + (scan window
//!   widened); ALL must be 0 (asserted).
//! * slow-member run (4 nodes, one 5x + 100ms symmetric delay): no starvation
//!   (`common == best`, slow trails by <= 1); safety everywhere (no fork, no
//!   honest double votes, roots agree).
//!
//! RECOMMENDATION is printed by the test (`[tick-tuning][recommend]`) as the
//! fastest (lowest p50, mean tiebreak) zero-false-positive cell, and pinned to
//! the 600ms bar (`recommended p50 <= 600ms virtual`).
//!
//! ```text
//! cargo test --test tick_tuning_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};
use stellereum::consensus::{NIL_CIRCUIT_BREAKER_K, ROUND_LOOKBACK, VoteKind};

/// Tick grid under test (harness-injected directly).
const TICKS: [u64; 3] = [50, 20, 10];
/// Down-proposer grid under test (emulated via base scaling, see mapping).
const DOWNS: [u64; 3] = [800, 400, 300];
/// Reference round-0 cap the mapping scales from (production parity).
const REF_BASE_MS: u64 = 650;
/// Reference down-proposer default (production parity).
const REF_DOWN_MS: u64 = 800;
/// Fixed seed base (each cell mixes in its tick/down tag).
const SEED: u64 = 0x71C0_0007u64;
/// Healthy heights per cell (enough for a stable p50, cheap in virtual time).
const HEALTHY_H: u64 = 12;
/// Slow-member heights per cell.
const SLOW_H: u64 = 6;
/// Virtual budget per run (20x headroom over the ~6s a healthy cell needs).
const BUDGET_MS: u64 = 120_000;
/// 0.6s/block goal in virtual ms.
const GOAL_MS: u64 = 600;

/// Emulated harness base for a down-proposer setting (rounded).
fn harness_base_for(down_ms: u64) -> u64 {
    (REF_BASE_MS * down_ms + REF_DOWN_MS / 2) / REF_DOWN_MS
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn healthy_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
    ]
}

fn slow_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default()
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(100)
            .with_propose_delay_ms(100),
    ]
}

/// Safety shape shared by every run: no fork, no honest double votes,
/// agreeing state roots among finalizing nodes.
fn assert_safe(tag: &str, report: &consensus_cluster::ClusterReport, exempt: &[usize]) {
    for (h, entries) in report.finalized_by_height() {
        let mut hs: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hs.sort();
        hs.dedup();
        assert_eq!(hs.len(), 1, "[{tag}] height {h} must have one decided block");
    }
    assert!(
        report.double_votes(exempt).is_empty(),
        "[{tag}] honest voters never double-vote.\n{}",
        report.diagnostics()
    );
    let live_roots: Vec<_> = report
        .nodes
        .iter()
        .filter(|n| n.finalized_height > 0)
        .map(|n| n.state_root)
        .collect();
    if !live_roots.is_empty() {
        assert!(
            live_roots.windows(2).all(|w| w[0] == w[1]),
            "[{tag}] finalizing nodes must agree on state.\n{}",
            report.diagnostics()
        );
    }
}

#[tokio::test]
async fn tick_downproposer_sweep_reports_p50_and_zero_false_positives() {
    assert_eq!(harness_base_for(800), 650);
    assert_eq!(harness_base_for(400), 325);
    assert_eq!(harness_base_for(300), 244);

    println!(
        "[tick-tuning][map] prod tick=50ms down=800ms; harness tick=tick_ms, base=round(650*down/800): \
         800->650 400->325 300->244; K={NIL_CIRCUIT_BREAKER_K} lookback={ROUND_LOOKBACK}"
    );
    println!(
        "[tick-tuning][sweep] {:>8} | {:>8} | {:>8} | {:>9} | {:>9} | {:>6} | {:>6} | {:>8}",
        "tick_ms", "down_ms", "base_ms", "p50_ms", "mean_ms", "fp_brk", "fp_nil", "slow_gap"
    );

    let mut best: Option<(u64, u64, u64, u64)> = None; // (p50, mean, tick, down)

    for &tick in &TICKS {
        for &down in &DOWNS {
            let base = harness_base_for(down);
            let tag = tick.wrapping_mul(1_000).wrapping_add(down);

            // --- Healthy soak: incremental run_until for per-height intervals.
            let mut c = ConsensusCluster::build(3, healthy_profiles(), SEED ^ tag, tick, base);
            c.seed_transactions(3).await;
            let mut stamps: Vec<u64> = Vec::new();
            for h in 1..=HEALTHY_H {
                let report = c.run_until(h, BUDGET_MS).await;
                assert!(
                    report.best_height >= h,
                    "[tick={tick} down={down}] healthy stalled at height {h}.\n{}",
                    report.diagnostics()
                );
                stamps.push(c.now_ms());
            }
            let report = c.report().await;
            let mut intervals: Vec<u64> = stamps
                .windows(2)
                .map(|w| w[1].saturating_sub(w[0]))
                .collect();
            if intervals.is_empty() {
                intervals.push(stamps[0]);
            }
            let p50 = median(intervals.clone());
            let mean = report.virtual_ms / report.best_height.max(1);

            // False positives: breaker due / nil prevotes / widened window.
            let mut fp_breaker: u64 = 0;
            let mut widened: u64 = 0;
            for i in 0..3 {
                let hc = &c.runtime(i).hc;
                if hc.nil_breaker_due() {
                    fp_breaker += 1;
                }
                if hc.consecutive_nil_rounds >= NIL_CIRCUIT_BREAKER_K {
                    fp_breaker += 1;
                }
                if hc.nil_breaker_fired_this_streak {
                    fp_breaker += 1;
                }
                if hc.scan_lookback != ROUND_LOOKBACK {
                    widened += 1;
                }
            }
            let fp_nil: u64 = report
                .nodes
                .iter()
                .flat_map(|n| n.cast_votes.iter())
                .filter(|v| v.kind == VoteKind::Prevote && v.target.is_none())
                .count() as u64;
            let fp_total = fp_breaker + fp_nil + widened;
            assert_safe(&format!("healthy tick={tick} down={down}"), &report, &[]);
            assert!(
                report.common_height == report.best_height && report.best_height >= HEALTHY_H,
                "[tick={tick} down={down}] healthy must converge.\n{}",
                report.diagnostics()
            );
            assert_eq!(
                fp_total, 0,
                "[tick={tick} down={down}] false positives must be 0 \
                 (breaker={fp_breaker} nil={fp_nil} widened={widened}).\n{}",
                report.diagnostics()
            );

            // --- Slow member: 4 nodes, one slow; no starvation.
            let mut s =
                ConsensusCluster::build(4, slow_profiles(), (SEED ^ tag).wrapping_add(0x5_100), tick, base);
            s.seed_transactions(3).await;
            let slow_report = s.run_until(SLOW_H, BUDGET_MS).await;
            assert_safe(&format!("slow tick={tick} down={down}"), &slow_report, &[]);
            assert!(
                slow_report.best_height >= SLOW_H && slow_report.common_height >= SLOW_H,
                "[tick={tick} down={down}] slow run must finalize on all UP nodes.\n{}",
                slow_report.diagnostics()
            );
            // No starvation: at the instant every UP node reaches the target,
            // fast nodes may already hold the next commit broadcast, so allow
            // one height of tick-quantization skew (same bar as the 0.6s pin:
            // `best - common <= 1`).
            let head_gap = slow_report
                .best_height
                .saturating_sub(slow_report.common_height);
            assert!(
                head_gap <= 1,
                "[tick={tick} down={down}] head spread {head_gap} (no starvation).\n{}",
                slow_report.diagnostics()
            );
            let slow_gap =
                slow_report.best_height.saturating_sub(slow_report.nodes[3].finalized_height);
            assert!(
                slow_gap <= 1,
                "[tick={tick} down={down}] slow member trails by {slow_gap}.\n{}",
                slow_report.diagnostics()
            );

            println!(
                "[tick-tuning][sweep] {tick:>8} | {down:>8} | {base:>8} | {p50:>9} | {mean:>9} | \
                 {fp_breaker:>6} | {fp_nil:>6} | {slow_gap:>8}"
            );

            if fp_total == 0 {
                let cand = (p50, mean, tick, down);
                best = Some(match best {
                    None => cand,
                    Some(b) => if (cand.0, cand.1) < (b.0, b.1) { cand } else { b },
                });
            }
        }
    }

    let (p50, mean, tick, down) = best.expect("at least one zero-FP cell");
    println!(
        "[tick-tuning][recommend] tick={tick}ms down={down}ms \
         (base={}ms) p50={p50}ms mean={mean}ms fp=0",
        harness_base_for(down)
    );
    assert!(
        p50 <= GOAL_MS,
        "recommended cell p50={p50}ms exceeds {GOAL_MS}ms goal"
    );
}
