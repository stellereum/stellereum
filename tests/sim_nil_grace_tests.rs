//! # SIM-NIL-GRACE: is the additive NIL wait safe to subsume into the 2x bound?
//!
//! CONTEXT: the view-change straggler grace was subsumed into the pre-existing
//! 2x peer-active hold bound (`cap_hold_to_two_x_bound`, `src/main.rs:260-262`;
//! the gate fires at `max(effective, 2 * base)` while a peer is active, so the
//! grace only fills the slack to the bound it already waits on). The NIL wait
//! is still additive (`2 * round_timeout + nil_grace`, `src/main.rs` NIL gate):
//! total NIL deadline `2 * base + min(grace, cap)`.
//!
//! QUESTION: subsume the NIL grace the same way (cap the total NIL deadline at
//! 2x base)? For the NIL path the "effective" deadline IS the 2x bound itself,
//! so subsumption zeroes the grace outright:
//! `capped = min(grace, 2*base - 2*base) = 0` (pinned by
//! `nil_capped_deadline_is_the_plain_two_x_bound` below). The production
//! question is therefore whether DELETING the NIL grace is safe.
//!
//! WHAT THIS PINS, on the deterministic harness
//! (`tests/support/consensus_cluster.rs`), same seed with/without the
//! (additive, production-today) grace:
//!
//! * `dead_proposer_still_advances` — 4 nodes, one DOWN from genesis
//!   (dead-proposer (height, round-0) slots occur naturally via the
//!   `proposer_for` rotation): the chain advances past dead-proposer heights
//!   with and without the grace (no liveness loss, no added dead rounds).
//! * `slow_proposer_waits_churn_down` — 3 nodes, unanimity, slow proposer
//!   build (1700ms, delivered ~1800ms: past the 2x NIL bound at 1600ms but
//!   inside the additive deadline at 3100ms): WITH the grace the slow heights
//!   decide in round 0 (the wait covers the build); WITHOUT it every slow
//!   height burns an extra round. Same finals, fewer view changes (churn
//!   down), zero NIL burn.
//! * `nil_capped_deadline_is_the_plain_two_x_bound` (+ gap-window arithmetic)
//!   — the pure mirror: capping zeroes the NIL grace, and the slow-build
//!   arrival above (1800ms) lands strictly inside the gap window
//!   `(2*base, 2*base+grace]` the cap would delete. Under a capped NIL the
//!   covered slow heights would NIL at 1600ms BEFORE the proposal lands —
//!   burning the round's prevote (one NIL kills the round-0 value polka at
//!   unanimity) — turning observed round-0 decisions into round-1+ decisions
//!   with MORE nils and MORE view changes. Churn UP, the opposite of the grace
//!   goal.
//!
//! VERDICT (documented-why-not): do NOT subsume the NIL grace. The sim shows
//! the additive wait carries real slow-proposer decisions (Test 2) while dead
//! rounds advance either way (Test 1); the cap deletes exactly the window that
//! carries them (Test 3). Production (`src/main.rs` NIL gate) is left
//! untouched — additive, by design. The honest-NIL path never binds in this
//! harness at low rounds (the view change at `eff < 2*base` always outruns the
//! NIL wait, so honest sim NIL counts are 0 in every run — the gap-window
//! hazard is established by the arrival-vs-deadline arithmetic, which is what
//! Test 3 pins), hence INCONCLUSIVE-as-empirical-proof for high-round
//! production NILs and UNSAFE-by-construction for the covered slow heights.
//!
//! MEASURED (seed-pinned, virtual ms):
//! * dead (4 nodes, 1 down, 12 heights): control 5200ms / 2 view-changes per
//!   live node, graced 5900ms / 1 per live node; both decide 11x round 0 +
//!   1x past-round-0, zero honest NILs either way, no fork, state agrees.
//! * slow (unanimity, 1700ms build, 12 heights): control 8 round-0 + 4
//!   past-round-0 decisions at 8 view-changes/node; graced 11 round-0 + 1
//!   past-round-0 at 5-6 view-changes/node, zero NILs (all value votes).
//! * gap window: capped NIL 1600ms < earliest slow arrival 1800ms <=
//!   additive NIL 3100ms — the cap would NIL-burn the covered heights.
//!
//! DETERMINISM: fixed seeds, virtual clock only, no OS randomness.
//!
//! ```text
//! cargo test --test sim_nil_grace_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile, StragglerPolicy};
use stellereum::consensus::VoteKind;

// ---------------------------------------------------------------------------
// Shared knobs (same sizing as `sim_round_hold_accounting`, so the arrival
// windows compose with the established dwell numbers).
// ---------------------------------------------------------------------------

/// Virtual tick quantum (matches the harness default).
const TICK_MS: u64 = 100;
/// Base round timeout. The 2x NIL bound is 1600ms; the round-0 view-change cap
/// is 650ms (production parity inside the harness).
const BASE_MS: u64 = 800;
/// SIM-ONLY grace, sized as in `sim_proposer_straggler` (covers the slow round
/// trip with headroom).
const GRACE_MS: u64 = 1_500;
/// Freshness window: a peer silent longer than this stops stretching rounds.
const FRESHNESS_MS: u64 = 3_000;
/// Heights to finalize per run (enough dead/slow-proposer slots at the chosen
/// seeds; the assertions pin the observed minimums, not exact counts).
const TARGET_HEIGHTS: u64 = 12;
/// Virtual budget: generous (slow heights cost ~2.5s each); a stall must
/// REPORT, not hang.
const BUDGET_MS: u64 = 600_000;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Total NIL prevotes cast across the cluster (value votes excluded).
fn total_nils(report: &consensus_cluster::ClusterReport) -> u64 {
    report
        .nodes
        .iter()
        .map(|n| {
            n.cast_votes
                .iter()
                .filter(|v| v.kind == VoteKind::Prevote && v.target.is_none())
                .count() as u64
        })
        .sum()
}

/// Total view changes across the cluster.
fn total_view_changes(report: &consensus_cluster::ClusterReport) -> u64 {
    report.nodes.iter().map(|n| n.view_changes).sum()
}

/// Shared metrics line (mirrors `sim_proposer_straggler` / accounting).
fn metrics_line(tag: &str, report: &consensus_cluster::ClusterReport) -> String {
    let mut out = format!(
        "[sim][nil-grace][{tag}] virtual_ms={} ticks={} best={} common={}",
        report.virtual_ms, report.ticks, report.best_height, report.common_height
    );
    for n in &report.nodes {
        let nils = n
            .cast_votes
            .iter()
            .filter(|v| v.kind == VoteKind::Prevote && v.target.is_none())
            .count();
        let total_prevotes = n
            .cast_votes
            .iter()
            .filter(|v| v.kind == VoteKind::Prevote)
            .count();
        out.push_str(&format!(
            " | node{}(h={} r={} fh={} decide0={} decide1p={} nil={}/{} \
              grace={} jumps={} view_changes={})",
            n.index,
            n.height,
            n.round,
            n.finalized_height,
            n.decide_rounds.iter().filter(|d| **d == 0).count(),
            n.decide_rounds.iter().filter(|d| **d >= 1).count(),
            nils,
            total_prevotes,
            n.grace_extends,
            n.sync_jumps,
            n.view_changes,
        ));
    }
    out
}

/// Safety shape shared by every run: no fork, no double-votes, agreeing state.
fn assert_safe(tag: &str, report: &consensus_cluster::ClusterReport) {
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 1, "[{tag}] height {h} must have exactly one decided block");
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "[{tag}] honest voters never double-vote.\n{}",
        report.diagnostics()
    );
    // State agreement among nodes that actually finalized (a DOWN member
    // keeps its genesis state and must not poison the comparison).
    let live_roots: Vec<_> = report
        .nodes
        .iter()
        .filter(|n| n.finalized_height > 0)
        .map(|n| n.state_root)
        .collect();
    assert!(
        !live_roots.is_empty(),
        "[{tag}] at least one node must have finalized.\n{}",
        report.diagnostics()
    );
    assert!(
        live_roots.windows(2).all(|w| w[0] == w[1]),
        "[{tag}] finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}

// ------------------------------------------------------------------
// Test 1: dead proposer — the NIL vote must still fire / the chain must
// still advance when genuinely proposalless, with and without the grace.
// ------------------------------------------------------------------

/// Fixed seed for the dead-proposer scenario. Both runs share it: the ONLY
/// difference between them is the straggler policy.
const DEAD_SEED: u64 = 0xDEAD_6000_0001;

fn dead_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1).down(),
    ]
}

#[tokio::test]
async fn dead_proposer_still_advances_with_and_without_nil_grace() {
    // Control: policy disabled = exact old harness behaviour (NIL at the
    // plain 2x bound, view change at the deterministic timeout).
    let mut control = ConsensusCluster::build(dead_profiles().len(), dead_profiles(), DEAD_SEED, TICK_MS, BASE_MS);
    control.seed_transactions(3).await;
    let control_report = control.run_until(TARGET_HEIGHTS, BUDGET_MS).await;
    println!("{}", metrics_line("dead-control", &control_report));

    // Fix-candidate regime (production today): additive grace on both the
    // view change and the NIL wait.
    let mut graced = ConsensusCluster::build(dead_profiles().len(), dead_profiles(), DEAD_SEED, TICK_MS, BASE_MS)
        .with_straggler_policy(StragglerPolicy::fixed(GRACE_MS, GRACE_MS, FRESHNESS_MS));
    graced.seed_transactions(3).await;
    let graced_report = graced.run_until(TARGET_HEIGHTS, BUDGET_MS).await;
    println!("{}", metrics_line("dead-graced", &graced_report));

    // LIVENESS (no loss): BOTH runs finalize every height despite the dead
    // member holding ~1/4 of the (height, round-0) proposer slots. The dead
    // heights cost exactly the view-change + next-round decide; the grace
    // never parks them.
    for (tag, report) in [("dead-control", &control_report), ("dead-graced", &graced_report)] {
        assert_eq!(
            report.common_height, TARGET_HEIGHTS,
            "[{tag}] must finalize all {TARGET_HEIGHTS} heights with one member down.\n{}",
            report.diagnostics()
        );
        assert_safe(tag, report);
    }

    // Dead-proposer slots really occurred: at least one height decided past
    // round 0 in each run (a down proposer cannot decide round 0 — the value
    // arrives never — so any all-round-0 run would prove nothing about dead
    // rounds).
    for (tag, report) in [("dead-control", &control_report), ("dead-graced", &graced_report)] {
        let past_zero = report.nodes[0]
            .decide_rounds
            .iter()
            .filter(|d| **d >= 1)
            .count();
        assert!(
            past_zero >= 1,
            "[{tag}] need at least one past-round-0 decision for the dead-proposer claim \
             (decide_rounds {:?}).\n{}",
            report.nodes[0].decide_rounds,
            report.diagnostics()
        );
    }

    // NO ADDED DEAD ROUNDS: the grace run must burn no MORE view changes
    // than control on dead heights (a longer proposalless dwell still ends
    // in the same next-round decide; here it ends one round sooner — the
    // longer dwell lets the live next-round proposal land in-round instead
    // of mid-chase — but the pin is only "never worse", never "identical":
    // grace timing legitimately shifts round trajectories).
    let control_changes = total_view_changes(&control_report);
    let graced_changes = total_view_changes(&graced_report);
    assert!(
        graced_changes <= control_changes,
        "grace must not add dead rounds (graced {graced_changes} vs control {control_changes}).\n{}\n{}",
        control_report.diagnostics(),
        graced_report.diagnostics()
    );

    // DOCUMENTED HARNESS PROPERTY: at low rounds the view change
    // (`eff <= base < 2*base`) always outruns the NIL wait, so honest sim
    // NIL counts are 0 in both runs. The production NIL path (high rounds,
    // where `effective >= 2*base` lets the NIL fire first) is outside what
    // this harness exhibits — one reason the verdict below stays
    // inconclusive-as-empirical-proof for that path.
    for (tag, report) in [("dead-control", &control_report), ("dead-graced", &graced_report)] {
        assert_eq!(
            total_nils(report), 0,
            "[{tag}] honest sim NILs must be 0 (view change outruns the NIL wait at low rounds).\n{}",
            report.diagnostics()
        );
    }
}

// ------------------------------------------------------------------
// Test 2: slow proposer — the additive wait covers the build (churn down).
// ------------------------------------------------------------------

/// Fixed seed for the slow-proposer scenario. Both runs share it: the ONLY
/// difference between them is the straggler policy.
const SLOW_SEED: u64 = 0x5100_01CE_0002;

/// Slow proposal build: delivered at ~SLOW_BUILD_MS + one tick (~1800ms) —
/// past the plain 2x NIL bound (1600ms) but inside the additive deadline
/// (1600 + 1500 = 3100ms) AND inside the additive round-0 view-change dwell
/// (650 + 1500 = 2150ms). The covered window, exactly.
const SLOW_BUILD_MS: u64 = 1_700;

fn slow_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default()
            .with_power(1)
            .with_propose_delay_ms(SLOW_BUILD_MS),
    ]
}

#[tokio::test]
async fn slow_proposer_waits_churn_down() {
    // Fast-forward OFF: the harness fast-forward would zero the slow
    // proposal build (same-tick prebuilt propose), hiding the trigger this
    // scenario measures. Identical in both runs.
    let mut control = ConsensusCluster::build(slow_profiles().len(), slow_profiles(), SLOW_SEED, TICK_MS, BASE_MS)
        .with_fast_forward(false);
    control.seed_transactions(3).await;
    let control_report = control.run_until(TARGET_HEIGHTS, BUDGET_MS).await;
    println!("{}", metrics_line("slow-control", &control_report));

    let mut graced = ConsensusCluster::build(slow_profiles().len(), slow_profiles(), SLOW_SEED, TICK_MS, BASE_MS)
        .with_fast_forward(false)
        .with_straggler_policy(StragglerPolicy::fixed(GRACE_MS, GRACE_MS, FRESHNESS_MS));
    graced.seed_transactions(3).await;
    let graced_report = graced.run_until(TARGET_HEIGHTS, BUDGET_MS).await;
    println!("{}", metrics_line("slow-grained", &graced_report));

    // LIVENESS: both finalize everything; safety in both.
    for (tag, report) in [("slow-control", &control_report), ("slow-grained", &graced_report)] {
        assert_eq!(
            report.common_height, TARGET_HEIGHTS,
            "[{tag}] must finalize all {TARGET_HEIGHTS} heights.\n{}",
            report.diagnostics()
        );
        assert_eq!(
            report.best_height, TARGET_HEIGHTS,
            "[{tag}] no node may trail at the end.\n{}",
            report.diagnostics()
        );
        assert_safe(tag, report);
    }

    // THE WAIT: slow-proposer heights decide in round 0 under the grace
    // (the 2150ms round-0 dwell covers the ~1800ms build), so the graced run
    // decides (nearly) everything first-round ...
    let graced_r0 = graced_report.nodes[0]
        .decide_rounds
        .iter()
        .filter(|d| **d == 0)
        .count() as u64;
    assert!(
        graced_r0 >= TARGET_HEIGHTS - 1,
        "[slow-grained] the grace must cover the slow builds: at least {} of {TARGET_HEIGHTS} \
         heights decide in round 0 (decide_rounds {:?}).\n{}",
        TARGET_HEIGHTS - 1,
        graced_report.nodes[0].decide_rounds,
        graced_report.diagnostics()
    );
    // ... while control (round-0 dwell 650ms < 1800ms build) burns an extra
    // round on every slow-proposer height.
    let control_extra = control_report.nodes[0]
        .decide_rounds
        .iter()
        .filter(|d| **d >= 1)
        .count() as u64;
    assert!(
        control_extra >= 2,
        "[slow-control] need several past-round-0 decisions for the wait claim \
         (decide_rounds {:?}).\n{}",
        control_report.nodes[0].decide_rounds,
        control_report.diagnostics()
    );

    // CHURN DOWN: same finals, strictly fewer view changes under the grace.
    // (No NIL burn in either run: the graced NIL waits past the arrival, and
    // control view-changes out of round 0 before its 1600ms NIL binds.)
    let control_changes = total_view_changes(&control_report);
    let graced_changes = total_view_changes(&graced_report);
    assert!(
        graced_changes + 2 <= control_changes,
        "graced run must burn clearly fewer view changes for the same finals \
         (graced {graced_changes} vs control {control_changes}).\n{}\n{}",
        control_report.diagnostics(),
        graced_report.diagnostics()
    );
    assert_eq!(
        total_nils(&graced_report), 0,
        "graced slow heights vote VALUE, never NIL (the wait covers the build).\n{}",
        graced_report.diagnostics()
    );

    // MECHANISM: the grace engaged in the graced run and never in control.
    let graced_extends: u64 = graced_report.nodes.iter().map(|n| n.grace_extends).sum();
    assert!(
        graced_extends > 0,
        "grace never engaged: the comparison is vacuous.\n{}",
        graced_report.diagnostics()
    );
    let control_extends: u64 = control_report.nodes.iter().map(|n| n.grace_extends).sum();
    assert_eq!(control_extends, 0, "control must not extend (policy disabled).");
}

// ------------------------------------------------------------------
// Test 3: the pure mirror — capping the NIL grace zeroes it, deleting the
// window Test 2 proves load-bearing. Verdict: keep additive.
// ------------------------------------------------------------------

/// Executable mirror of `cap_hold_to_two_x_bound` (`src/main.rs:260-262`).
fn cap_hold_mirror(hold_ms: u64, effective_ms: u64, base_ms: u64) -> u64 {
    hold_ms.min(base_ms.saturating_mul(2).saturating_sub(effective_ms))
}

#[test]
fn nil_capped_deadline_is_the_plain_two_x_bound() {
    let base = BASE_MS; // 800
    let (grace, cap) = (GRACE_MS, GRACE_MS); // 1500 / 1500

    // Production today (additive): 2*base + min(grace, cap).
    let additive_deadline = 2 * base + grace.min(cap);
    assert_eq!(additive_deadline, 3_100);

    // Subsumed ("cap total NIL deadline at 2x base"): the NIL path's
    // effective deadline IS the 2x bound, so the slack is 2*base - 2*base
    // = 0 and the capped hold is 0 for EVERY input — the grace is deleted,
    // not subsumed.
    for hold in [0, 1, 500, grace, 100_000] {
        assert_eq!(
            cap_hold_mirror(hold, 2 * base, base), 0,
            "NIL slack is 2*base - 2*base = 0: any hold caps to 0"
        );
    }
    let capped_deadline = 2 * base + cap_hold_mirror(grace.min(cap), 2 * base, base);
    assert_eq!(capped_deadline, 2 * base, "capped NIL deadline is the plain 2x bound");
    assert_eq!(capped_deadline, 1_600);

    // THE GAP WINDOW (Test 2's slow build, lower-bounded): the proposal is
    // broadcast the tick after the height starts and suffers at least one
    // tick of network latency on top of the build, so it lands at
    // SLOW_BUILD_MS + TICK_MS or later — strictly inside (1600, 3100].
    let arrival_earliest = SLOW_BUILD_MS + TICK_MS;
    assert!(
        capped_deadline < arrival_earliest && arrival_earliest <= additive_deadline,
        "slow arrival {arrival_earliest}ms must land strictly past the capped NIL deadline \
         ({capped_deadline}ms) and within the additive one ({additive_deadline}ms)"
    );

    // Consequence (read with Test 2's observation — graced slow heights
    // decide round 0 with ZERO nils): under the cap, those same heights
    // would NIL at 1600ms BEFORE the ~1800ms proposal lands. The round's
    // prevote is then spent (one NIL kills the round-0 value polka at
    // 3/3 unanimity), so covered slow heights flip from round-0 decisions
    // to round-1+ decisions with MORE nils and MORE view changes — churn UP,
    // the opposite of the grace goal. The cap is UNSAFE for the grace's
    // stated purpose (and merely inconclusive as empirical proof for
    // high-round production NILs, which this harness never exhibits:
    // `dead_proposer_still_advances_with_and_without_nil_grace` pins 0
    // honest sim NILs in every run). Keep the NIL wait additive.
}
