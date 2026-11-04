//! # SIM-ROUND-HOLD-ACCOUNTING: grace stacking vs subsumption, same seed.
//!
//! ROUND-TIMER ACCOUNTING (see docs/TEMPO_PROFILE.md §5.3 + the unit proof in
//! `round_timer_accounting_tests`): the production view-change gate fires at
//! `max(effective_timeout, 2 * base)` while a peer is active, so an UNSUBSUMED
//! straggler grace stacks PAST the pre-existing 2× peer-active hold bound
//! (rung dwell up to `effective + grace`). The fix subsumes the grace into
//! that bound (`deadline = effective + min(grace, 2 * base - effective)`):
//! the hold still holds, the timeout still times out, and with grace unset
//! the deadline is byte-identical.
//!
//! WHAT THIS PINS, on the deterministic harness
//! (`tests/support/consensus_cluster.rs`) at small scale: powers [1,1,1]
//! (total 3, quorum 3 = unanimity), a slow member (5x round-timeout factor,
//! 250ms inbound delay — the live 250ms+ WAN link shape) whose PROPOSAL build
//! takes 2300ms (past BOTH compositions' round-0 deadlines, so the failing
//! rung is entered in both), base 800ms (round-0 proposalless wait capped at
//! 650ms by production parity), grace 1500ms / cap 1500ms / freshness 3000ms
//! (the proposer-rework sizing).
//!
//! * stacked (production-today): failing round-0 dwells
//!   `650 + 1500 = 2150ms` before the view change.
//! * subsumed (fix): the same failing round-0 dwells
//!   `650 + min(1500, 2*800 - 650) = 1600ms` — the grace fills the slack to
//!   the 2× bound instead of stacking past it.
//!
//! Both decide the SAME rounds (round 0 on fast-proposer heights, round 1 on
//! slow-proposer heights — the extension still covers the slow round trip),
//! burn the SAME view changes, finalize the SAME heights — but the subsumed
//! run converges ~550ms sooner per slow-proposer height: rung dwell drops,
//! finals rate is preserved (improved, never harmed).
//!
//! HARNESS FIDELITY (read before reusing): the harness models no peer-active
//! hold — the comparison is faithful anyway because the scenario operates in
//! the SATURATED regime (`grace >= 2 * base - effective`): there the
//! production hold is masked in both compositions, so the harness deadlines
//! above equal the production deadlines exactly. The unsaturated regime and
//! the grace-off identity are pinned by the production unit tests
//! (`round_timer_accounting_tests`), not here.
//!
//! DETERMINISM: fixed [`SEED`], virtual clock only, no OS randomness.
//!
//! ```text
//! cargo test --test sim_round_hold_accounting -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile, StragglerPolicy};
use stellereum::consensus::VoteKind;

/// Fixed seed for the whole scenario. Any change moves every number below.
/// Both compositions share it: the ONLY difference between the two runs is
/// the grace accounting.
const SEED: u64 = 0xACC0067119u64;
/// Virtual tick quantum (matches the harness default).
const TICK_MS: u64 = 100;
/// Base round timeout: comfortably above the fast round trip (~600ms: instant
/// proposal, 250ms slow vote leg each way) so fast-proposer heights decide in
/// round 0, but below the slow proposal build so slow-proposer heights burn
/// exactly one extended round-0 rung in both compositions.
const BASE_MS: u64 = 800;
/// Slow-link delay inbound TO the slow node (the live 250ms+ WAN link shape).
const SLOW_LINK_MS: u64 = 250;
/// Slow proposal build: past BOTH round-0 deadlines (stacked 2150ms,
/// subsumed 1600ms — see header), so round 0 fails identically and round 1
/// (fast proposer, instant proposal) decides in both.
const SLOW_BUILD_MS: u64 = 2_300;
/// SIM-ONLY grace, sized as in `sim_proposer_straggler` (covers the slow
/// round trip with headroom in both compositions).
const GRACE_MS: u64 = 1_500;
/// Freshness window: a peer silent longer than this stops stretching rounds.
const FRESHNESS_MS: u64 = 3_000;
/// Heights to finalize: enough slow-proposer heights (~1/3) for the ~550ms
/// per-height dwell gap to dominate tick quantization.
const TARGET_HEIGHTS: u64 = 45;
/// Virtual budget: generous (slow heights cost ~2.5s each); a stall must
/// REPORT, not hang.
const BUDGET_MS: u64 = 600_000;

fn accounting_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default()
            .with_power(1)
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_BUILD_MS),
    ]
}

fn build_stacked() -> ConsensusCluster {
    // Fast-forward OFF: the harness fast-forward would zero the slow
    // proposal build (same-tick prebuilt propose), hiding the trigger this
    // scenario measures. With it off, `SLOW_BUILD_MS` applies on every
    // slow-proposer height (production-faithful slow build, harness-only
    // switch, identical in both runs).
    ConsensusCluster::build(3, accounting_profiles(), SEED, TICK_MS, BASE_MS)
        .with_fast_forward(false)
        .with_straggler_policy(StragglerPolicy::fixed(GRACE_MS, GRACE_MS, FRESHNESS_MS))
}

fn build_subsumed() -> ConsensusCluster {
    ConsensusCluster::build(3, accounting_profiles(), SEED, TICK_MS, BASE_MS)
        .with_fast_forward(false)
        .with_straggler_policy(StragglerPolicy::fixed_subsumed(GRACE_MS, GRACE_MS, FRESHNESS_MS))
}

/// Shared metrics line (mirrors `sim_proposer_straggler`).
fn metrics_line(tag: &str, report: &consensus_cluster::ClusterReport) -> String {
    let mut out = format!(
        "[sim][hold-accounting][{tag}] seed=0x{SEED:x} virtual_ms={} ticks={} best={} common={}",
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
            " | node{}(h={} r={} fh={} decide0={} decide1={} nil={}/{} \
              grace={} jumps={} view_changes={})",
            n.index,
            n.height,
            n.round,
            n.finalized_height,
            n.decide_rounds.iter().filter(|d| **d == 0).count(),
            n.decide_rounds.iter().filter(|d| **d == 1).count(),
            nils,
            total_prevotes,
            n.grace_extends,
            n.sync_jumps,
            n.view_changes,
        ));
    }
    out
}

#[tokio::test]
async fn subsumed_grace_holds_dwell_down_finals_steady() {
    let mut stacked = build_stacked();
    assert_eq!(stacked.validators().quorum_power(), 3);
    stacked.seed_transactions(3).await;
    let stacked_report = stacked.run_until(TARGET_HEIGHTS, BUDGET_MS).await;
    println!("{}", metrics_line("stacked", &stacked_report));
    println!("{}", stacked_report.diagnostics());

    let mut subsumed = build_subsumed();
    assert_eq!(subsumed.validators().quorum_power(), 3);
    subsumed.seed_transactions(3).await;
    let subsumed_report = subsumed.run_until(TARGET_HEIGHTS, BUDGET_MS).await;
    println!("{}", metrics_line("subsumed", &subsumed_report));
    println!("{}", subsumed_report.diagnostics());

    // LIVENESS (same finals rate): BOTH compositions finalize every height —
    // the grace still covers the slow round trip in the subsumed run. The
    // fix must never cost a final.
    for (tag, report) in [("stacked", &stacked_report), ("subsumed", &subsumed_report)] {
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
    }

    // SAME FINALS SHAPE: identical deciding rounds height-by-height on every
    // node — the subsumed grace decides in the same rounds (round 1 on
    // slow-proposer heights, round 0 elsewhere), it only waits less getting
    // there. Any divergence means the fix changed WHAT decides, not just
    // how long failures dwell.
    for (i, (a, b)) in stacked_report
        .nodes
        .iter()
        .zip(subsumed_report.nodes.iter())
        .enumerate()
    {
        assert_eq!(
            a.decide_rounds, b.decide_rounds,
            "node {i}: deciding rounds must match exactly \
             (stacked {:?} vs subsumed {:?}).\n{}\n{}",
            a.decide_rounds, b.decide_rounds,
            stacked_report.diagnostics(), subsumed_report.diagnostics()
        );
    }
    // Both compositions must actually USE the failing rung (otherwise the
    // scenario proves nothing): slow-proposer heights decide in round 1.
    let slow_heights = stacked_report.nodes[0]
        .decide_rounds
        .iter()
        .filter(|d| **d == 1)
        .count() as u64;
    assert!(
        slow_heights >= 5,
        "need several round-1 heights for the dwell gap to matter \
         (decide_rounds {:?}).\n{}",
        stacked_report.nodes[0].decide_rounds,
        stacked_report.diagnostics()
    );

    // SAME ROUNDS BURNED: the fix shortens failing rungs, it must not add or
    // remove view changes (identical round trajectories).
    let stacked_changes: u64 = stacked_report.nodes.iter().map(|n| n.view_changes).sum();
    let subsumed_changes: u64 = subsumed_report.nodes.iter().map(|n| n.view_changes).sum();
    assert_eq!(
        stacked_changes, subsumed_changes,
        "view-change counts must match (same trajectories).\n{}\n{}",
        stacked_report.diagnostics(),
        subsumed_report.diagnostics()
    );

    // RUNG DWELL DROP: fewer virtual ms for the same heights in the same
    // rounds. Mechanism, pinned structurally: fast nodes never jump
    // (`jumps == 0` both runs — asserted below), and no round-0 QC is
    // possible on slow-proposer heights (the proposal lands at ~2400ms,
    // past BOTH round-0 deadlines), so every failing round-0 exits by
    // timeout at its deadline — 2150ms stacked (`650` round-0 cap + `1500`
    // grace) vs 1600ms subsumed (`650 + min(1500, 2*800 - 650)`): exactly
    // 550ms saved per failing round-0, i.e. per round-1 height. Later-round
    // QC alignment can absorb at most ~1 tick per height, hence the floor
    // `550 − 100 = 450`. (Multi-round slow heights save MORE — their
    // round-1+ deadlines shrink too, 2300→1600 — so this is a lower bound.)
    assert!(
        subsumed_report.virtual_ms < stacked_report.virtual_ms,
        "subsumed run must converge sooner (dwell drop).\n{}\n{}",
        stacked_report.diagnostics(),
        subsumed_report.diagnostics()
    );
    for (tag, report) in [("stacked", &stacked_report), ("subsumed", &subsumed_report)] {
        for n in &report.nodes {
            if n.index < 2 {
                assert_eq!(
                    n.sync_jumps, 0,
                    "[{tag}] fast nodes must never jump (else round-0 exits \
                     are not all deadline timeouts).\n{}",
                    report.diagnostics()
                );
            }
        }
    }
    let gap_ms = stacked_report.virtual_ms - subsumed_report.virtual_ms;
    assert!(
        gap_ms >= 450 * slow_heights.max(1),
        "dwell gap {gap_ms}ms over {slow_heights} round-1 heights must clear \
         the 450ms/height floor (550ms deadline gap minus 1 tick of QC \
         jitter).\n{}\n{}",
        stacked_report.diagnostics(),
        subsumed_report.diagnostics()
    );

    // MECHANISM: the grace engaged in both runs (otherwise the comparison is
    // vacuous — without extension both would be identical trivially).
    for (tag, report) in [("stacked", &stacked_report), ("subsumed", &subsumed_report)] {
        let total_grace: u64 = report.nodes.iter().map(|n| n.grace_extends).sum();
        assert!(
            total_grace > 0,
            "[{tag}] grace never engaged: the comparison is vacuous.\n{}",
            report.diagnostics()
        );
    }

    // SAFETY: no fork — exactly one decided block per height, in both runs.
    for (tag, report) in [("stacked", &stacked_report), ("subsumed", &subsumed_report)] {
        for (h, entries) in report.finalized_by_height() {
            let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
            hashes.sort();
            hashes.dedup();
            assert_eq!(hashes.len(), 1, "[{tag}] height {h} must have exactly one decided block");
        }
        assert!(
            report.double_votes(&[]).is_empty(),
            "[{tag}] slow-but-honest voters never double-vote.\n{}",
            report.diagnostics()
        );
    }
    for report in [&stacked_report, &subsumed_report] {
        let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "finalizing nodes must agree on state.\n{}",
            report.diagnostics()
        );
    }
}
