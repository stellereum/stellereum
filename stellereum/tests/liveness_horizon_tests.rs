//! # Liveness horizon soak: 4 nodes, 1020 virtual seconds, fault script.
//!
//! Long-horizon liveness in virtual time only (no wall-clock asserts). One
//! deterministic fault script runs the whole horizon:
//!
//! * 4 equal-power validators (quorum = 3);
//! * node 2 is a SLOW member (`round_timeout_factor = 3`) for the whole run:
//!   timeout skew the quorum must absorb without stalling;
//! * node 3 is a NIL-flapper (`Byzantine::NilPrevote`: nil prevote every
//!   round — the live-shape vote a lock-stuck validator casts) for the whole
//!   run, so every live round mixes value and nil pressure while the honest
//!   3/4 keep carrying value quorums;
//! * three KILL+HEAL cycles on the pair {2, 3} (30 s virtual each): with two
//!   of four down the quorum is lost, so the chain STALLS instead of
//!   advancing — the returnees therefore resume at the SAME head they left
//!   (no height gap). This is the only kill shape whose heal converges
//!   in-sim: `adopt_committed` is exact-height, the tick harness drives no
//!   multi-height walk, and a returnee that misses finalized heights while
//!   down never closes the gap (reported gap, pinned by `chaos_n4_tests`:
//!   height catch-up lives in the production sync walk, not in-sim). Killing
//!   one node while the other three finalize would strand the returnee
//!   behind by construction and fake every convergence assertion downstream.
//!
//! The suite asserts, on virtual time only:
//!
//! 1. finals advance across EVERY 60 s virtual window (no silent stall; the
//!    worst window is recorded and printed). Outages (30 s) sit strictly
//!    inside a window, so every window still contains live chain time;
//! 2. resource bounds: peer-sighting tables bounded by the validator count,
//!    retained vote-set rounds bounded by `MAX_RETAINED_VOTE_ROUNDS` (and
//!    non-empty, so the check is not vacuous), every retained set bounded by
//!    the validator count, vote-waste a subset of arrivals with a capped
//!    share, arrivals linear in rounds used;
//! 3. breaker/hold metrics in bounds in BOTH regimes: at every window
//!    boundary and at the end (calm shape — nil streak below
//!    `NIL_CIRCUIT_BREAKER_K`, breaker not due, scan window at
//!    `ROUND_LOOKBACK`, no deadlock jump target on fresh progress, no local
//!    reset, sightings bounded) AND mid-outage (stall shape — the quorum-
//!    starved survivors reach K consecutive nil rounds and the breaker goes
//!    due within `K * 2 * BASE_MS` of stall onset, while still no deadlock
//!    jump: the outage is far below the 300 s no-progress timeout, so the
//!    heal — not a jump — restores progress). In-sim the breaker is
//!    observable as due-ness: the widening one-shot
//!    (`apply_nil_convergence`) runs in the production loop only and is
//!    unit-pinned by the breaker suite, so the sim asserts due, never fired.
//!    Zero straggler holds throughout (policy disabled), view changes and
//!    decide-rounds bounded;
//! 4. heal convergence each cycle: the returnees re-vote and all four nodes
//!    rejoin one common head within a bounded virtual latency after each
//!    heal (same-head resume, genuinely re-measured, not assumed);
//! 5. deterministic replay: the identical script run twice yields the same
//!    `ClusterReport::fingerprint`.
//!
//! Read-only consts under test: `NIL_CIRCUIT_BREAKER_K = 3`,
//! `ROUND_LOOKBACK = 8`, `REPHASE_SCAN_WINDOW = 4096`,
//! `MAX_RETAINED_VOTE_ROUNDS = 4096`, deadlock default timeout 300 s,
//! quorum 3-of-4. Any drift in those values fails this suite.
//!
//! ```text
//! cargo test --test liveness_horizon_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ConsensusCluster, NodeProfile};
use stellereum::consensus::{
    MAX_RETAINED_VOTE_ROUNDS, NIL_CIRCUIT_BREAKER_K, REPHASE_SCAN_WINDOW, ROUND_LOOKBACK,
};

/// Virtual tick quantum (harness default).
const TICK_MS: u64 = 100;
/// Base round timeout for the sim clusters (harness default).
const BASE_MS: u64 = 1_000;
/// Fixed cluster seed (both replay runs share it).
const SEED: u64 = 0x9071_2007u64;
/// No-progress timeout passed explicitly (== production default 300 s).
const TIMEOUT_SECS: u64 = 300;
/// Cluster size (quorum = 3).
const N_NODES: usize = 4;
/// Horizon: 1020 virtual seconds (> 1000 s required).
const HORIZON_MS: u64 = 1_020_000;
/// Liveness window: finals must advance in every one of these.
const WINDOW_MS: u64 = 60_000;
/// Kill-cycle outage length (virtual ms). Strictly inside one 60 s window so
/// every window keeps live chain time; long enough for the nil breaker to
/// engage (~6 s) and far below the 300 s deadlock timeout (heal restores).
const OUTAGE_MS: u64 = 30_000;
/// Kill schedule (virtual ms, strictly increasing, all inside the horizon).
/// Each entry sits strictly inside a 60 s window (never on a boundary), so
/// window-boundary calibration always samples the calm regime.
const KILL_AT: [u64; 3] = [190_000, 430_000, 670_000];
/// Killed pair: the slow member + the flapper. Survivors are the two clean
/// honest nodes — the stall is pure quorum loss, and the heal restores the
/// full fault mix (slow + flap) at the same head.
const KILL_PAIR: [usize; 2] = [2, 3];
/// Slow member timeout factor (node 2).
const SLOW_FACTOR: u64 = 3;
/// Mid-outage stall sample: this far past the kill (virtual ms). Late enough
/// for the breaker to have engaged, early enough to precede the heal.
const STALL_SAMPLE_MS: u64 = 20_000;
/// Heal convergence bound: all four nodes back on one common head within
/// this virtual latency after each heal.
const HEAL_BOUND_MS: u64 = 30_000;
/// Breaker engagement bound: nil-breaker due within this virtual latency
/// after stall onset (== the (a)-test unit bound `K * 2 * BASE_MS`; the
/// clock starts at the last observed progress, so an in-flight height
/// draining at kill time does not consume the budget). Due-ness is the
/// sim-observable engagement: the widening one-shot itself is
/// production-loop-only.
const FIRE_BOUND_MS: u64 = NIL_CIRCUIT_BREAKER_K as u64 * 2 * BASE_MS;
/// Floor on the horizon finalization rate (heights per virtual second). The
/// healthy sim pace is ~3/s; the floor is 12x below it so only a real stall
/// regime (not fault-script drag) can trip it.
const MIN_RATE_PER_SEC: f64 = 0.25;
/// Cap on the global vote-waste share (wasted / arrivals). The lone niler
/// wastes ~1 prevote arrival per round per node plus resends; the cap leaves
/// headroom over the calibrated value while catching a waste runaway.
const MAX_WASTE_SHARE: f64 = 0.60;
/// Cap on per-node arrivals per round used: the pump delivers, per round per
/// peer, at most 1 proposal + 1 prevote + 1 precommit + 1 commit + a
/// view-change resend of <= 3 messages, i.e. <= 6 from each of 3 peers = 18;
/// 24 leaves headroom for one-tick-latency overlap bursts.
const MAX_ARRIVALS_PER_ROUND: u64 = 24;
/// Cap on view changes per finalized height (cluster-wide mean). Healthy pace
/// is ~1; the cap tolerates sustained flapping drag but not a view-change
/// storm. Stall view changes (no heights) are accounted separately below.
const MAX_VIEW_CHANGES_PER_HEIGHT: f64 = 12.0;
/// Extra view-change budget per stall second (cluster-wide): a quorum-
/// starved pair turns rounds at ~1/s each, i.e. ~2/s cluster-wide; 8/s caps
/// a runaway while leaving headroom over the calibrated churn.
const MAX_STALL_VC_PER_SEC: f64 = 8.0;
/// Cap on the worst decide-round delta over the horizon (== the quorum scan
/// window: a decision must never cost more rounds than the scan can see).
const MAX_DECIDE_DELTA: u32 = ROUND_LOOKBACK;

/// One full horizon execution.
struct HorizonOutcome {
    report: consensus_cluster::ClusterReport,
    fingerprint: String,
    /// Finalized-height gain per 60 s virtual window, in order.
    window_gains: Vec<u64>,
    /// Index of the worst (smallest-gain) window.
    worst_window: usize,
    /// Virtual-ms latency from each heal to all-four-back-on-one-head.
    heal_latencies_ms: Vec<u64>,
    /// Virtual-ms latency from stall onset to breaker engagement, per cycle.
    fire_latencies_ms: Vec<u64>,
    /// Max retained vote-set rounds over the four nodes (end of run).
    max_retained_rounds: usize,
    /// Max retained vote-set size over the four nodes (end of run).
    max_retained_set_len: usize,
}

fn profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().with_round_timeout_factor(SLOW_FACTOR),
        NodeProfile::default().byzantine(Byzantine::NilPrevote),
    ]
}

/// Finalized head of one node, read directly (cheap per-tick probe).
fn finalized_of(cluster: &ConsensusCluster, index: usize) -> u64 {
    cluster.runtime(index).finalized.last().map(|(h, _)| *h).unwrap_or(0)
}

/// Retained vote-set rounds of one node, counted directly from the production
/// vote-set API (the bound is the production prune cap, not a harness
/// counter). Fresh maps per height make this the current height's rounds.
fn retained_vote_rounds(cluster: &ConsensusCluster, index: usize) -> usize {
    let hc = &cluster.runtime(index).hc;
    let mut count = 0usize;
    for r in 0..=hc.round {
        if hc.prevote_set(r).is_some() || hc.precommit_set(r).is_some() {
            count += 1;
        }
    }
    count
}

/// Largest retained vote set of one node (one vote per voter by construction).
fn max_retained_set_len(cluster: &ConsensusCluster, index: usize) -> usize {
    let hc = &cluster.runtime(index).hc;
    let mut max = 0usize;
    for r in 0..=hc.round {
        if let Some(set) = hc.prevote_set(r) {
            max = max.max(set.len());
        }
        if let Some(set) = hc.precommit_set(r) {
            max = max.max(set.len());
        }
    }
    max
}

/// Breaker/hold calibration in the CALM regime (window boundary or end):
/// nil streak below K, breaker not due, scan window at the normal lookback
/// (nothing in-sim widens it), no deadlock jump target on fresh progress, an
/// armed (full-timeout) jump target — if any transient alignment lag produces
/// one — still within one lookback (never a runaway), no local reset while
/// progress is fresh, sighting table bounded by the validator count.
///
/// NOTE on what is NOT asserted: `nil_breaker_fired_this_streak` is never
/// asserted because nothing in-sim can set it — the widening one-shot
/// (`apply_nil_convergence`) runs in the production loop (`main.rs`) only,
/// so in-sim the breaker is observable purely as due-ness and the action is
/// unit-pinned by `liveness_breaker_tests` (a). Asserting `!fired` here
/// would be vacuous (it cannot fail), so it is omitted, not faked.
fn assert_breaker_hold_calibrated(cluster: &ConsensusCluster, tag: &str) {
    for i in 0..N_NODES {
        let hc = &cluster.runtime(i).hc;
        assert!(
            hc.consecutive_nil_rounds < NIL_CIRCUIT_BREAKER_K,
            "[{tag}] node {i}: nil streak {} reached K={NIL_CIRCUIT_BREAKER_K}",
            hc.consecutive_nil_rounds,
        );
        assert!(
            !hc.nil_breaker_due(),
            "[{tag}] node {i}: nil breaker must never be due in the calm regime"
        );
        assert_eq!(
            hc.scan_lookback, ROUND_LOOKBACK,
            "[{tag}] node {i}: scan window must stay at ROUND_LOOKBACK (never widened)"
        );
        assert_eq!(
            hc.deadlock_breaker_target(0, TIMEOUT_SECS),
            None,
            "[{tag}] node {i}: jump breaker must have no target on fresh progress"
        );
        if let Some(target) = hc.deadlock_breaker_target(TIMEOUT_SECS, TIMEOUT_SECS) {
            assert!(
                target <= hc.round.saturating_add(ROUND_LOOKBACK),
                "[{tag}] node {i}: armed jump target {target} exceeds round {} + \
                 lookback {ROUND_LOOKBACK} (runaway)",
                hc.round,
            );
        }
        assert!(
            !hc.deadlock_local_reset_due(0, TIMEOUT_SECS),
            "[{tag}] node {i}: no local reset while progress is fresh"
        );
        assert!(
            hc.peer_rounds.len() <= N_NODES,
            "[{tag}] node {i}: sighting table holds {} peers (> {N_NODES} validators)",
            hc.peer_rounds.len(),
        );
    }
}

/// Breaker/hold calibration in the STALL regime (mid-outage sample): the two
/// quorum-starved survivors must show the engaged shape — streak at/above K
/// with the breaker due (due-ness is the sim-observable signal; the widening
/// one-shot is production-loop-only, so the scan stays at `ROUND_LOOKBACK`
/// in-sim) — while still no deadlock jump (the outage is far below the
/// no-progress timeout even granting the whole outage as idle) and the
/// killed pair frozen at their kill-time heads.
fn assert_breaker_hold_stalled(
    cluster: &ConsensusCluster,
    tag: &str,
    kill_heads: &[u64; N_NODES],
    outage_secs: u64,
) {
    for (i, &kill_head) in kill_heads.iter().enumerate() {
        let hc = &cluster.runtime(i).hc;
        if KILL_PAIR.contains(&i) {
            assert_eq!(
                finalized_of(cluster, i),
                kill_head,
                "[{tag}] node {i}: killed member's head must stay frozen while down"
            );
            continue;
        }
        assert!(
            hc.consecutive_nil_rounds >= NIL_CIRCUIT_BREAKER_K,
            "[{tag}] survivor {i}: quorum-starved streak {} never reached K={NIL_CIRCUIT_BREAKER_K} \
             (the stall must be real, not a slowdown)",
            hc.consecutive_nil_rounds,
        );
        assert!(
            hc.nil_breaker_due(),
            "[{tag}] survivor {i}: breaker must be due during a quorum-loss stall"
        );
        assert_eq!(
            hc.scan_lookback, ROUND_LOOKBACK,
            "[{tag}] survivor {i}: scan window untouched in-sim (the widening \
             one-shot is production-loop-only, unit-pinned)"
        );
        // Over-approximating no-progress by the whole outage makes this
        // None-assertion stronger: if no jump is due even then, the true
        // (smaller) idle time certainly admits none.
        assert_eq!(
            hc.deadlock_breaker_target(outage_secs, TIMEOUT_SECS),
            None,
            "[{tag}] survivor {i}: no deadlock jump on a sub-timeout stall (heal owns recovery)"
        );
        assert!(
            !hc.deadlock_local_reset_due(outage_secs, TIMEOUT_SECS),
            "[{tag}] survivor {i}: no local reset on a sub-timeout stall"
        );
    }
}

async fn run_horizon_once() -> HorizonOutcome {
    // --- Read-only calibration pins (const drift fails the suite). ---
    assert_eq!(NIL_CIRCUIT_BREAKER_K, 3, "breaker K pinned by code const");
    assert_eq!(ROUND_LOOKBACK, 8, "normal scan window pinned by code const");
    assert_eq!(
        REPHASE_SCAN_WINDOW, 4_096,
        "breaker-widened window pinned by code const"
    );
    assert_eq!(
        MAX_RETAINED_VOTE_ROUNDS, 4_096,
        "per-height retained-round cap pinned by code const"
    );
    // Outages sit strictly inside 60 s windows: no kill, sample, or heal may
    // touch a window boundary, so boundary calibration always sees calm.
    for (cycle, kill_at) in KILL_AT.iter().enumerate() {
        let window_start = kill_at / WINDOW_MS * WINDOW_MS;
        assert!(
            *kill_at > window_start && kill_at + OUTAGE_MS < window_start + WINDOW_MS,
            "cycle {cycle}: outage [{kill_at}, {}) must sit strictly inside one 60 s window",
            kill_at + OUTAGE_MS,
        );
        assert!(
            kill_at + STALL_SAMPLE_MS < kill_at + OUTAGE_MS,
            "cycle {cycle}: stall sample must precede the heal"
        );
    }

    let mut c = ConsensusCluster::build(N_NODES, profiles(), SEED, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3, "3-of-4 quorum arithmetic");
    c.seed_transactions(3).await;

    let mut window_gains = Vec::new();
    let mut prev_best = 0u64;
    let mut next_window = WINDOW_MS;
    let mut kills_pending = KILL_AT.to_vec();
    let mut heal_at: Option<u64> = None;
    let mut stall_sample_at: Option<u64> = None;
    let mut kill_heads: [u64; N_NODES] = [0; N_NODES];
    let mut stall_best_at_kill: u64 = 0;
    // Breaker-engagement watch (node 0: fast honest survivor).
    let mut last_progress_head: u64 = 0;
    let mut last_progress_tick: u64 = 0;
    let mut fire_tick: Option<u64> = None;
    let mut fire_latencies_ms = Vec::new();
    // Heal-convergence watch.
    let mut heal_tick: u64 = 0;
    let mut heal_votes_snapshot: [u64; N_NODES] = [0; N_NODES];
    let mut heal_latencies_ms = Vec::new();
    // Retained-table watch: the production vote-set tables are per-height
    // and reset on finalize, and the steady-state pipeline finalizes in
    // lock-step with the 60 s window grid — so a boundary snapshot always
    // catches a fresh height with empty tables. Track the maxima across
    // EVERY tick instead (phase-proof); the cap asserts run on the maxima
    // at the end, and non-emptiness on the maximum proves the scan observed
    // live tables.
    let mut peak_retained_rounds = 0usize;
    let mut peak_retained_set_len = 0usize;

    while c.now_ms() < HORIZON_MS {
        // Fault script: kill on schedule, sample the stall, heal after OUTAGE.
        if let Some(&kill_at) = kills_pending.first() {
            if c.now_ms() >= kill_at {
                for (i, head) in kill_heads.iter_mut().enumerate() {
                    *head = finalized_of(&c, i);
                }
                stall_best_at_kill = kill_heads.iter().copied().max().unwrap_or(0);
                for i in KILL_PAIR {
                    c.set_down(i, true);
                }
                stall_sample_at = Some(kill_at + STALL_SAMPLE_MS);
                heal_at = Some(kill_at + OUTAGE_MS);
                last_progress_head = kill_heads[0];
                last_progress_tick = kill_at;
                fire_tick = None;
                kills_pending.remove(0);
            }
        }
        if let Some(sample) = stall_sample_at {
            if c.now_ms() >= sample {
                stall_sample_at = None;
                // The stall must be (near-)total: with the quorum lost, at
                // most one in-flight height can still drain post-kill.
                let now_best = (0..N_NODES).map(|i| finalized_of(&c, i)).max().unwrap_or(0);
                assert!(
                    now_best <= stall_best_at_kill + 1,
                    "outage must stall finalization (best {stall_best_at_kill} -> {now_best}); \
                     the quorum is lost, so continued progress would mean the kill did not take"
                );
                assert_breaker_hold_stalled(
                    &c,
                    "stall",
                    &kill_heads,
                    OUTAGE_MS / 1000,
                );
            }
        }
        // Engagement watch: track the survivor's progress and first fire.
        if heal_at.is_some() {
            let head0 = finalized_of(&c, 0);
            if head0 > last_progress_head {
                last_progress_head = head0;
                last_progress_tick = c.now_ms();
            }
            let hc0 = &c.runtime(0).hc;
            if fire_tick.is_none() && hc0.nil_breaker_due() {
                fire_tick = Some(c.now_ms());
            }
        }
        if let Some(heal) = heal_at {
            if c.now_ms() >= heal {
                for i in KILL_PAIR {
                    c.set_down(i, false);
                }
                heal_at = None;
                if let Some(fired) = fire_tick {
                    fire_latencies_ms.push(fired.saturating_sub(last_progress_tick));
                }
                // Snapshot the returnees' vote counters; the poll below waits
                // for them to vote again AND for all four to share one head.
                let rep = c.report().await;
                for i in KILL_PAIR {
                    heal_votes_snapshot[i] = rep.nodes[i].prevotes_cast;
                }
                heal_tick = c.now_ms();
            }
        }
        c.tick().await;

        // Heal-convergence poll: all four UP on one common head with the
        // returnees voting again. Same-head resume makes this fast; the
        // bound below keeps it honest.
        if heal_tick > 0 {
            let h0 = finalized_of(&c, 0);
            let h1 = finalized_of(&c, 1);
            let h2 = finalized_of(&c, 2);
            let h3 = finalized_of(&c, 3);
            if h0 == h1 && h1 == h2 && h2 == h3 {
                let rep = c.report().await;
                if KILL_PAIR.iter().all(|i| rep.nodes[*i].prevotes_cast > heal_votes_snapshot[*i]) {
                    heal_latencies_ms.push(c.now_ms() - heal_tick);
                    heal_tick = 0;
                }
            }
        }

        // Window boundary: record progress + sample calm-regime calibration.
        if c.now_ms() >= next_window {
            let rep = c.report().await;
            window_gains.push(rep.best_height - prev_best);
            prev_best = rep.best_height;
            assert_breaker_hold_calibrated(&c, "window");
            next_window += WINDOW_MS;
        }

        // Retained-table watch: phase-proof peak tracking across every tick.
        for i in 0..N_NODES {
            peak_retained_rounds = peak_retained_rounds.max(retained_vote_rounds(&c, i));
            peak_retained_set_len = peak_retained_set_len.max(max_retained_set_len(&c, i));
        }
    }

    // Every outage must have engaged the breaker exactly once (no silent
    // stall without breaker action, no missing fire record).
    assert_eq!(
        fire_latencies_ms.len(),
        KILL_AT.len(),
        "one measured breaker engagement per kill cycle"
    );
    for (cycle, lat) in fire_latencies_ms.iter().enumerate() {
        assert!(
            *lat <= FIRE_BOUND_MS,
            "cycle {cycle}: breaker engaged {lat} ms after stall onset \
             (bound {FIRE_BOUND_MS} ms = K * 2 * BASE)"
        );
    }

    let mut max_set_len = peak_retained_set_len;
    let mut max_retained_rounds = peak_retained_rounds;
    for i in 0..N_NODES {
        max_retained_rounds = max_retained_rounds.max(retained_vote_rounds(&c, i));
        max_set_len = max_set_len.max(max_retained_set_len(&c, i));
    }
    assert_breaker_hold_calibrated(&c, "final");
    let report = c.report().await;
    let fingerprint = report.fingerprint();

    let worst_window = window_gains
        .iter()
        .enumerate()
        .min_by_key(|(_, &g)| g)
        .map(|(i, _)| i)
        .unwrap_or(0);

    HorizonOutcome {
        report,
        fingerprint,
        window_gains,
        worst_window,
        heal_latencies_ms,
        fire_latencies_ms,
        max_retained_rounds,
        max_retained_set_len: max_set_len,
    }
}

#[tokio::test]
async fn horizon_soak_advances_finals_bounds_resources_and_replays() {
    let first = run_horizon_once().await;
    let second = run_horizon_once().await;

    // --- (5) Deterministic replay: identical script, identical outcome. ---
    assert_eq!(
        first.fingerprint, second.fingerprint,
        "horizon script must replay bit-for-bit deterministically"
    );
    assert!(
        first.report.best_height > 0,
        "replay equality must be over a run that finalized something"
    );

    let report = &first.report;

    // --- (1) Finals advance across every 60 s virtual window. ---
    assert_eq!(
        first.window_gains.len(),
        (HORIZON_MS / WINDOW_MS) as usize,
        "one gain entry per 60 s window"
    );
    for (i, gain) in first.window_gains.iter().enumerate() {
        assert!(
            *gain > 0,
            "SILENT STALL: window {i} (virtual [{}, {}) s) finalized +{gain} heights.\n{}",
            (i as u64) * WINDOW_MS / 1000,
            ((i as u64) + 1) * WINDOW_MS / 1000,
            report.diagnostics(),
        );
    }
    let worst_gain = first.window_gains[first.worst_window];
    let rate = report.best_height as f64 / (report.virtual_ms as f64 / 1000.0);
    assert!(
        rate >= MIN_RATE_PER_SEC,
        "horizon rate {rate:.4}/s below floor {MIN_RATE_PER_SEC}/s.\n{}",
        report.diagnostics(),
    );
    println!(
        "[liveness-horizon] horizon={} s virtual best={} common={} rate={:.3}/s \
         windows={} worst_window={} (+{} heights)",
        report.virtual_ms / 1000,
        report.best_height,
        report.common_height,
        rate,
        first.window_gains.len(),
        first.worst_window,
        worst_gain,
    );
    println!("[liveness-horizon] window_gains={:?}", first.window_gains);

    // --- Safety shape (harness idiom): no fork, no honest double vote,
    //     finalizing nodes agree on state. ---
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "FORK at height {h}: nodes finalized different blocks"
        );
    }
    assert!(
        report.double_votes(&[3]).is_empty(),
        "honest voters never double-vote.\n{}",
        report.diagnostics(),
    );
    let live_roots: Vec<_> = report
        .nodes
        .iter()
        .filter(|n| n.finalized_height > 0)
        .map(|n| n.state_root)
        .collect();
    assert!(
        !live_roots.is_empty() && live_roots.windows(2).all(|w| w[0] == w[1]),
        "finalizing nodes must agree on state.\n{}",
        report.diagnostics(),
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every UP node reaches the head at the horizon end.\n{}",
        report.diagnostics(),
    );

    // --- (2) Resource bounds (harness counters + production vote-set API). ---
    let mut total_arrivals = 0u64;
    let mut total_wasted = 0u64;
    for n in &report.nodes {
        total_arrivals += n.vote_arrivals;
        total_wasted += n.vote_wasted;
        assert!(
            n.vote_wasted <= n.vote_arrivals,
            "node {}: waste ({}) is a subset of arrivals ({})",
            n.index,
            n.vote_wasted,
            n.vote_arrivals,
        );
        // Arrivals linear in rounds used (view changes + decided heights),
        // never in wall ticks: the pump delivers a bounded burst per round.
        let rounds_used = n.view_changes + n.decide_rounds.len() as u64 + 1;
        assert!(
            n.vote_arrivals <= MAX_ARRIVALS_PER_ROUND * rounds_used,
            "node {}: arrivals {} exceed {} x rounds_used {rounds_used} \
             (unbounded arrival map).\n{}",
            n.index,
            n.vote_arrivals,
            MAX_ARRIVALS_PER_ROUND,
            report.diagnostics(),
        );
        // No straggler holds on this script (policy disabled): the hold
        // metric must read exactly zero, not merely "small".
        assert_eq!(
            n.grace_extends, 0,
            "node {}: straggler hold engaged without the policy",
            n.index,
        );
    }
    let waste_share = total_wasted as f64 / total_arrivals.max(1) as f64;
    assert!(
        waste_share <= MAX_WASTE_SHARE,
        "waste share {waste_share:.3} exceeds cap {MAX_WASTE_SHARE} \
         (wasted={total_wasted} arrivals={total_arrivals}).\n{}",
        report.diagnostics(),
    );
    // Production vote-set tables: the peak over every tick of the run —
    // phase-proof (boundary snapshots always catch fresh heights in the
    // lock-step pipeline). Retained rounds capped per height, every
    // retained set capped by the validator count (one vote per voter). The
    // non-emptiness assert on the peak proves the scan observed live
    // tables (a boundary-only snapshot would read all zeros).
    assert!(
        first.max_retained_rounds >= 1,
        "retained-round scan must observe live vote tables"
    );
    assert!(
        first.max_retained_rounds <= MAX_RETAINED_VOTE_ROUNDS,
        "retained rounds {} exceed per-height cap {MAX_RETAINED_VOTE_ROUNDS}",
        first.max_retained_rounds,
    );
    assert!(
        first.max_retained_set_len <= N_NODES,
        "retained vote set holds {} votes (> {N_NODES} validators)",
        first.max_retained_set_len,
    );
    // View changes: live-height pace bounded per height, stall churn bounded
    // per stall second (quorum-starved rounds turn without deciding).
    let total_view_changes: u64 = report.nodes.iter().map(|n| n.view_changes).sum();
    let stall_secs = (OUTAGE_MS / 1000 * KILL_AT.len() as u64) as f64;
    let vc_budget =
        MAX_VIEW_CHANGES_PER_HEIGHT * report.best_height.max(1) as f64 + MAX_STALL_VC_PER_SEC * stall_secs;
    assert!(
        total_view_changes as f64 <= vc_budget,
        "view changes {} exceed budget {vc_budget:.0} \
         (live pace + stall churn).\n{}",
        total_view_changes,
        report.diagnostics(),
    );
    let worst_decide: u32 = report
        .nodes
        .iter()
        .flat_map(|n| n.decide_rounds.iter().copied())
        .max()
        .unwrap_or(0);
    assert!(
        worst_decide <= MAX_DECIDE_DELTA,
        "worst decide delta {worst_decide} exceeds scan window {MAX_DECIDE_DELTA}.\n{}",
        report.diagnostics(),
    );
    println!(
        "[liveness-horizon] bounds: arrivals={total_arrivals} wasted={total_wasted} \
         share={waste_share:.3} view_changes={total_view_changes} worst_decide={worst_decide} \
         retained_rounds={} max_set_len={}",
        first.max_retained_rounds, first.max_retained_set_len,
    );

    // --- (4) Heal convergence: every cycle's returnees re-vote and all four
    //     rejoin one common head within the bound. ---
    assert_eq!(
        first.heal_latencies_ms.len(),
        KILL_AT.len(),
        "one measured heal convergence per kill cycle"
    );
    for (cycle, lat) in first.heal_latencies_ms.iter().enumerate() {
        assert!(
            *lat <= HEAL_BOUND_MS,
            "cycle {cycle}: common head restored {lat} ms after heal \
             (bound {HEAL_BOUND_MS} ms)"
        );
    }
    println!(
        "[liveness-horizon] heal_latencies_ms={:?} (bound {HEAL_BOUND_MS})",
        first.heal_latencies_ms
    );
    println!(
        "[liveness-horizon] fire_latencies_ms={:?} (bound {FIRE_BOUND_MS})",
        first.fire_latencies_ms
    );
    println!(
        "[liveness-horizon] fingerprint={}",
        &first.fingerprint[..first.fingerprint.len().min(160)]
    );
}
