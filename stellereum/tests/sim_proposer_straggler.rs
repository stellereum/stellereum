//! # SIM-PROPOSER-STRAGGLER: stale-chase under unanimity, control vs. fix.
//!
//! LIVE COUPLING (see task context: 3 validators, unanimity 3/3, one member on
//! a 250ms+ link, one on 1-vCPU slow ticks, 20s effective round timeouts):
//! proposals and votes demonstrably flow in ALL directions and verify, yet
//! QCs form ~1 per 5 minutes. Rounds advance on timeouts; votes constantly
//! arrive "one round stale" and are absorbed into old buckets; everyone
//! self-proposes in own slots; nil-votes interleave on dead slots. No single
//! component is broken — the COMBINATION under unanimity never converges:
//! whoever is 1 round behind votes stale forever (their vote never counts),
//! and the leader pair (any 2/3 < quorum) cannot decide alone.
//!
//! WHAT THIS PINS: the stale-chase SHAPE on the deterministic harness
//! (`tests/support/consensus_cluster.rs`) at small scale — powers [1,1,1]
//! (total 3, quorum 3 = unanimity), one slow member (5x round-timeout factor,
//! 250ms inbound + propose delay: the live 250ms+ WAN link, exact), a tight
//! 100ms base the slow link always outruns (the compressed analogue of the
//! live coupling where the 3.5s base could not cover the slow link) — and the
//! collapse of that shape under the SIM-ONLY straggler-aware round extension
//! ([`StragglerPolicy`], harness-only test code, NOT a production change):
//!
//! * `proposer_stale_chase_control_stalls` — control (policy disabled, exact
//!   old harness): the chase runs with ~zero finals while most vote arrivals
//!   land one round stale and rounds burn by the thousand (voting without
//!   deciding).
//! * `proposer_straggler_grace_finalizes` — SAME seed, policy enabled: finals
//!   flow steadily, the WASTED-vote share collapses (arrivals in buckets that
//!   never decide anything), every post-transient height is decided in its FIRST round, the grace is shown
//!   to have engaged (`grace_extends > 0`), and safety holds (no fork, no
//!   double-votes, state roots agree).
//!
//! HARNESS EXTENSION (see `docs/SIMULATOR.md`, section 3.5): four primitives the harness did not have, all SIM-ONLY. First, a per-node round-timeout
//! grace gated on fresh straggler evidence (`StragglerPolicy`,
//! `with_straggler_policy`, per-peer vote sightings). Second, the same grace
//! applied to the nil-vote wait (don't nil a round whose scheduled value may
//! still be in flight). Third, arrival counters (`vote_arrivals` /
//! `vote_arrivals_stale`, the incident's "one round stale" signature) plus the
//! `grace_extends` engagement pin and a `view_changes` counter (the "rounds
//! used" half of the metric). Fourth, waste accounting (`arrivals_by_bucket`
//! plus absolute deciding rounds into `vote_wasted`): arrivals in buckets that
//! never decided anything. That is the load-bearing half of "stale", since the
//! late-quorum path can still absorb and count a merely late arrival.
//!
//! All four are passive or policy-gated: control behaviour is bit-identical
//! to the old harness.
//!
//! DETERMINISM: fixed [`SEED`], virtual clock only, no OS randomness.
//!
//! ```text
//! cargo test --test sim_proposer_straggler -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile, StragglerPolicy};
use stellereum::consensus::VoteKind;

/// Fixed seed for the whole scenario (CLOC series). Any change moves every
/// number below. Control and fix share it: the ONLY difference between the
/// two tests is the straggler policy.
const SEED: u64 = 0xC10C_0007;
/// Virtual tick quantum (matches the harness default).
const TICK_MS: u64 = 100;
/// Tight base round timeout: the slow member's 250ms link delay always exceeds
/// it, so the slow vote/proposal arrives after the fast pair has left the
/// round (the stale-chase coupling; the compressed analogue of the live 3.5s
/// base outrun by the slow link + slow ticks).
const BASE_MS: u64 = 100;
/// Slow-link delay, both directions (inbound TO the slow node via
/// `inbound_delay_ms`, outbound FROM it via `propose_delay_ms`): the live
/// 250ms+ WAN link, exact. Proposal latency slow->fast is inbound + propose
/// (~500ms + one tick); fast->slow vote latency is one tick.
const SLOW_LINK_MS: u64 = 250;
/// Virtual budget: twenty virtual minutes. A stall must REPORT (rounds burned
/// by the thousand), not hang; the fix finalizes hundreds of heights in the
/// same window. "Finals per virtual hour" is the raw count scaled x3.
const BUDGET_MS: u64 = 1_200_000;
/// SIM-ONLY grace: extra round time on fresh straggler evidence, bounded by
/// the same cap. Sized to cover the slow round trip (proposal out ~600ms,
/// votes back) with headroom, far below the freshness window so evidence
/// never goes stale mid-chase.
const GRACE_MS: u64 = 1_500;
/// Freshness window: a peer silent longer than this stops stretching rounds
/// (a dead peer must not park the chain — only a live-but-slow one buys
/// extra time).
const FRESHNESS_MS: u64 = 3_000;

fn stale_chase_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default().with_power(1),
        NodeProfile::default().with_power(1),
        NodeProfile::default()
            .with_power(1)
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_LINK_MS),
    ]
}

fn build_control() -> ConsensusCluster {
    // Powers [1,1,1]: total 3, quorum 3 = unanimity. Policy disabled = exact
    // old harness behaviour.
    ConsensusCluster::build(3, stale_chase_profiles(), SEED, TICK_MS, BASE_MS)
}

fn build_fixed() -> ConsensusCluster {
    build_control()
        .with_straggler_policy(StragglerPolicy::fixed(GRACE_MS, GRACE_MS, FRESHNESS_MS))
}

/// Shared metrics line: finals per budget window (scaled to a virtual hour in
/// the design doc), stale-arrival share, wasted-vote share, view changes
/// ("rounds used"), nil-prevote share.
fn metrics_line(report: &consensus_cluster::ClusterReport) -> String {
    let mut out = format!(
        "virtual_ms={} ticks={} best={} common={}",
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
            " | node{}(h={} r={} fh={} decide_len={} decide_head={:?} \
             end_round={} stale={:.3}({}/{}) wasted={:.3}({}/{}) nil={}/{} \
             grace={} jumps={} view_changes={})",
            n.index,
            n.height,
            n.round,
            n.finalized_height,
            n.decide_rounds.len(),
            n.decide_rounds.iter().take(8).collect::<Vec<_>>(),
            n.round,
            n.stale_share(),
            n.vote_arrivals_stale,
            n.vote_arrivals,
            n.wasted_share(),
            n.vote_wasted,
            n.vote_arrivals,
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
async fn proposer_stale_chase_control_stalls() {
    let mut c = build_control();
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_for(BUDGET_MS).await;

    println!("[sim][proposer-chase][control] seed=0x{:x} {}", SEED, metrics_line(&report));
    println!("{}", report.diagnostics());

    // LIVENESS (absent): the chase must burn the hour with ~no finals.
    // Bound, not exact-zero: the late-quorum path may occasionally complete
    // one height — the pin is "stall-rate", i.e. orders of magnitude below
    // the fix, while rounds spin by the thousand.
    assert!(
        report.common_height == 0 && report.best_height <= 1,
        "control must stall: unanimity + slow member + tight base = votes \
         land stale every round.\n{}",
        report.diagnostics()
    );
    // STALENESS: the fast pair's vote arrivals land one round late, every
    // time (the incident signature — votes absorbed into old buckets, never
    // counting). The slow member's own arrivals are never "stale" by this
    // definition — it is BEHIND, so everything it receives names a round
    // ahead of it; its chase signature is the jump count below.
    for n in report.nodes.iter().take(2) {
        assert!(
            n.vote_arrivals > 100,
            "control must exchange votes (a silent cluster proves nothing).\n{}",
            report.diagnostics()
        );
        assert!(
            n.stale_share() > 0.5,
            "node {}: control stale share {:.3} must exceed one half \
             (votes constantly one round stale).\n{}",
            n.index,
            n.stale_share(),
            report.diagnostics()
        );
    }
    // THE CHASE: the slow member burns its future-rule jump budget following
    // a network it never joins (thousands of `sync_round_to` jumps, zero
    // finals) — the "whoever is 1 round behind votes stale forever" half of
    // the incident.
    assert!(
        report.nodes[2].sync_jumps > 1_000,
        "slow member must chase via round jumps without converging.\n{}",
        report.diagnostics()
    );
    // WASTE: with zero finals, EVERY arrival sits in a bucket that never
    // decides — the stall, in one number.
    for n in &report.nodes {
        assert_eq!(
            n.wasted_share(),
            1.0,
            "node {}: control waste must be total (nothing ever decides).\n{}",
            n.index,
            report.diagnostics()
        );
    }
    // ROUNDS BURNED: voting without deciding — the fast pair spins thousands
    // of view changes in the window.
    let total_changes: u64 = report.nodes.iter().map(|n| n.view_changes).sum();
    assert!(
        total_changes > 10_000,
        "control must burn rounds (stall = voting without deciding).\n{}",
        report.diagnostics()
    );
    // SAFETY (vacuous but pinned): no fork, no double-votes.
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 1, "height {h} must have exactly one decided block");
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "slow-but-honest voters never double-vote.\n{}",
        report.diagnostics()
    );
}

#[tokio::test]
async fn proposer_straggler_grace_finalizes() {
    let mut c = build_fixed();
    assert_eq!(c.validators().quorum_power(), 3);
    assert_eq!(c.validators().total_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_for(BUDGET_MS).await;

    println!("[sim][proposer-chase][fixed] seed=0x{:x} {}", SEED, metrics_line(&report));
    println!("{}", report.diagnostics());

    // LIVENESS: the same window that stalls the control finalizes steadily.
    // One height costs ~one slow round trip (proposal out, votes back) plus
    // timeout slack — hundreds per twenty virtual minutes is the shape; the
    // pin is "same seed, orders of magnitude above control".
    assert!(
        report.common_height >= 100,
        "straggler grace must restore liveness under unanimity.\n{}",
        report.diagnostics()
    );
    // The slow member may trail the head by one height when the budget cuts
    // mid-round-trip; it must never fall further behind.
    assert!(
        report.best_height - report.common_height <= 1,
        "slow member trails by more than one height: it is not converging.\n{}",
        report.diagnostics()
    );
    // MECHANISM: the grace must have engaged (this is what the test pins,
    // not just the outcome — otherwise a lucky seed could pass).
    let total_grace: u64 = report.nodes.iter().map(|n| n.grace_extends).sum();
    assert!(
        total_grace > 0,
        "grace never engaged: the fix did not run.\n{}",
        report.diagnostics()
    );
    // WASTE COLLAPSE: arrivals now belong to buckets that decide — the late
    // arrivals the stale-share still reports are absorbed and counted by the
    // late-quorum path (decide deltas below prove it), instead of dying in
    // dead buckets. Control pins waste at exactly 1.0; the fix must leave it
    // an order of magnitude below.
    //
    // Residual (~6%, bar at 10%): the slow member's 500ms timeout still fires
    // mid-height (it cannot extend — it is the laggard, everyone else is with
    // or ahead of it), and its production-faithful view-change resend carries
    // its proposal stamped with the NEW round. When the slow member happens
    // to be scheduled for that round too, peers accept the re-sent proposal
    // and cast votes in a bucket that never reaches QC — while the round-0 QC
    // still decides first (deltas below). Harmless churn in a faithful
    // mechanism, not a second stall: finals flow at ~1 view change per height
    // (asserted below) instead of control's infinity.
    for n in &report.nodes {
        assert!(
            n.wasted_share() < 0.10,
            "node {}: wasted share {:.3} must collapse under the grace.\n{}",
            n.index,
            n.wasted_share(),
            report.diagnostics()
        );
    }
    // ROUND EFFICIENCY: post-transient heights decide in their FIRST round
    // (no stale-round QC ever carries a decision). Skip index 0 (the virtual
    // t=0 genesis transient: timestamp-0 proposals are refused until t>=1s).
    for n in &report.nodes {
        for (k, d) in n.decide_rounds.iter().enumerate().skip(1) {
            assert_eq!(
                *d, 0,
                "node {} decided height {} in round +{d}: a stale round \
                 carried the decision.\n{}",
                n.index,
                k + 1,
                report.diagnostics()
            );
        }
    }
    // ROUNDS USED: ~one view change per finalized height (the slow member's
    // mid-height timeout is the residual churn — it cannot extend, being the
    // laggard, so it still view-changes most heights; everyone still decides
    // in round 0 via the late path). Control burns tens of thousands of view
    // changes for zero finals.
    let total_changes: u64 = report.nodes.iter().map(|n| n.view_changes).sum();
    let finals = report.common_height.max(1);
    assert!(
        total_changes / finals <= 3,
        "too many view changes per final: {total_changes} changes for \
         {finals} finals.\n{}",
        report.diagnostics()
    );
    // SAFETY: no fork — exactly one decided block per height.
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 1, "height {h} must have exactly one decided block");
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "slow-but-honest voters never double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics()
    );
}
