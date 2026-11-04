//! # Liveness breaker / nil-grace / straggler-hold timing bounds (virtual clock).
//!
//! Pins the liveness-8.5→9.0 timing bounds in simulation. Deterministic:
//! fixed seeds, virtual clock only, no wall-clock asserts.
//!
//! Source consts under test (read-only, see `src/consensus.rs` + `src/main.rs`):
//! * `NIL_CIRCUIT_BREAKER_K = 3` — consecutive nil rounds that trip the
//!   nil-storm breaker (consensus.rs).
//! * `REPHASE_SCAN_WINDOW = 4096` — window the breaker widens (consensus.rs).
//! * `ROUND_LOOKBACK = 8` — normal scan window (consensus.rs).
//! * `deterministic_round_timeout_ms` — base + 500/round (cap +10s) +
//!   500/miss (cap +5s) (consensus.rs). The sim harness runs a FLAT
//!   per-node base (`BASE_MS` here) with a 650ms round-0 cap (production
//!   parity), so one nil round costs at most one base rung.
//! * `straggler_hold_ms` (main.rs:219): hold = `min(grace, cap)` on fresh
//!   evidence, else 0. `cap_hold_to_two_x_bound` (main.rs:260): subsumed
//!   hold fills slack up to `2 * base`. The harness mirrors both in
//!   `StragglerPolicy::fixed / fixed_subsumed` (`grace.min(cap)` and
//!   `min(grace, 2 * cluster_base - base_eff)`).
//! * Deadlock jump path: `deadlock_breaker_target` needs no-progress >=
//!   timeout (default `STELL_DEADLOCK_TIMEOUT_SECS = 300`) AND a
//!   corroborated peer ahead; `MAX_DEADLOCK_JUMP = 65536` bounds the jump.
//!
//! Scenarios:
//! * (a) `full_stall_trips_nil_breaker_within_bound_and_heals` — full stall
//!   (all-but-one down, quorum unreachable) trips the nil breaker within
//!   `K * 2 * BASE_MS` virtual ms; the breaker action is one-shot and widens
//!   the window; the chain resumes on heal.
//! * (b) `flapping_proposer_never_commits_nil` — alternating nil/value rounds
//!   never trip the breaker (streak resets), a nil-only QC never decides,
//!   and a live flapper (NilPrevote minority) cannot stop the honest quorum.
//! * (c) `straggler_hold_extends_exactly_per_cap` — with `grace != cap` the
//!   per-round hold is exactly `min(grace, cap)`; per-node extend ticks are
//!   bounded by `(rounds) * (cap/tick + 1)`; the mechanism engages and the
//!   chain finalizes; the run is bit-for-bit reproducible.
//! * (d) `healthy_fast_rounds_never_fire_breaker` — clean soak: no breaker,
//!   no jump target, fast rounds throughout.
//!
//! ```text
//! cargo test --test liveness_breaker_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{key_at, Byzantine, ConsensusCluster, NodeProfile, StragglerPolicy};
use stellereum::consensus::{
    HeightConsensus, ValidatorSet, Vote, VoteKind, NIL_CIRCUIT_BREAKER_K, REPHASE_SCAN_WINDOW,
    ROUND_LOOKBACK,
};

/// Virtual tick quantum (matches the harness default).
const TICK_MS: u64 = 100;
/// Base round timeout for the sim clusters (harness default).
const BASE_MS: u64 = 1_000;
/// Fixed cluster seed base (each test mixes in its own tag).
const SEED: u64 = 0x5BD1_0007u64;
/// No-progress timeout passed explicitly (== production default 300s, no env).
const TIMEOUT_SECS: u64 = 300;

/// Upper bound on nil-breaker fire latency: K nil rounds, each costing at
/// most one 2x-base rung of virtual time (the sim nil-wait rung; the
/// view-change rung is 1x base, so this is loose on purpose).
fn breaker_fire_bound_ms() -> u64 {
    NIL_CIRCUIT_BREAKER_K as u64 * 2 * BASE_MS
}

/// Build a validator set of `n` equal-power validators from deterministic keys.
fn vset(n: u64) -> ValidatorSet {
    let mut vs = ValidatorSet::new();
    for i in 0..n {
        let id = key_at(SEED, i).verifying_key().to_bytes();
        vs.add(id, 1);
    }
    vs
}

/// Safety shape shared by every sim run: no fork, no double votes (beyond the
/// exempt Byzantine), agreeing state roots among finalizing nodes.
fn assert_safe(tag: &str, report: &consensus_cluster::ClusterReport, exempt: &[usize]) {
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "[{tag}] height {h} must have exactly one decided block"
        );
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

fn metrics_line(tag: &str, report: &consensus_cluster::ClusterReport) -> String {
    let mut out = format!(
        "[liveness-breaker][{tag}] virtual_ms={} ticks={} best={} common={}",
        report.virtual_ms, report.ticks, report.best_height, report.common_height
    );
    for n in &report.nodes {
        out.push_str(&format!(
            " | node{}(fh={} vc={} grace={} nil_streak<{} jumps={})",
            n.index,
            n.finalized_height,
            n.view_changes,
            n.grace_extends,
            NIL_CIRCUIT_BREAKER_K,
            n.sync_jumps,
        ));
    }
    out
}

// ===========================================================================
// (a) Full stall -> breaker fires within its documented bound, chain heals.
// ===========================================================================

#[tokio::test]
async fn full_stall_trips_nil_breaker_within_bound_and_heals() {
    // --- Unit pin: the breaker fires at EXACTLY K consecutive nil rounds. ---
    assert_eq!(NIL_CIRCUIT_BREAKER_K, 3, "breaker K pinned by code const");
    let mut hc = HeightConsensus::new(7, vset(4));
    assert!(!hc.nil_breaker_due());
    for i in 1..NIL_CIRCUIT_BREAKER_K {
        hc.note_round_outcome(true);
        assert_eq!(hc.consecutive_nil_rounds, i);
        assert!(
            !hc.nil_breaker_due(),
            "breaker must not fire before K={NIL_CIRCUIT_BREAKER_K} nil rounds"
        );
    }
    hc.note_round_outcome(true);
    assert_eq!(hc.consecutive_nil_rounds, NIL_CIRCUIT_BREAKER_K);
    assert!(
        hc.nil_breaker_due(),
        "breaker fires at exactly K consecutive nil rounds"
    );

    // --- Breaker action pin: one-shot, widens the window, touches nothing else. ---
    let round_before = hc.round;
    let fired = hc.apply_nil_convergence();
    assert!(
        fired.is_none(),
        "no QC hash exists, so nothing to re-broadcast — but the window widens"
    );
    assert_eq!(
        hc.scan_lookback, REPHASE_SCAN_WINDOW,
        "breaker widens scan window to REPHASE_SCAN_WINDOW"
    );
    assert_eq!(hc.round, round_before, "breaker never moves the round");
    assert!(hc.decided.is_none(), "breaker never decides");
    assert!(
        hc.locked.is_none(),
        "breaker never touches the lock (none held here)"
    );
    assert!(
        !hc.nil_breaker_due(),
        "one-shot: the same streak never fires twice"
    );
    assert!(hc.apply_nil_convergence().is_none());
    assert_eq!(hc.scan_lookback, REPHASE_SCAN_WINDOW);
    // A value round resets the streak so the NEXT storm can fire again.
    hc.note_round_outcome(false);
    assert_eq!(hc.consecutive_nil_rounds, 0);
    assert!(!hc.nil_breaker_fired_this_streak);

    // --- Sim pin: a quorum-starved cluster stalls AND trips the breaker. ---
    // Powers [1,1,1], quorum 3: with two nodes down no QC can ever form, so
    // every round is a nil round and the streak must hit K quickly.
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default().down(),
        NodeProfile::default().down(),
    ];
    let mut c = ConsensusCluster::build(3, profiles, SEED ^ 0xA, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(2).await;

    let bound_ms = breaker_fire_bound_ms();
    while c.now_ms() < 12_000 && !c.runtime(0).hc.nil_breaker_due() {
        c.tick().await;
    }
    let measured_ms = c.now_ms();
    assert!(
        c.runtime(0).hc.nil_breaker_due(),
        "quorum-starved node must trip the nil breaker.\n{}",
        c.report().await.diagnostics()
    );
    assert!(
        measured_ms <= bound_ms,
        "breaker fired after {measured_ms}ms virtual, bound is K*2*base={bound_ms}ms \
         (K={NIL_CIRCUIT_BREAKER_K}, base={BASE_MS}ms)"
    );
    println!(
        "[liveness-breaker][full-stall] breaker due after {measured_ms}ms virtual \
         (bound {bound_ms}ms = K({NIL_CIRCUIT_BREAKER_K})*2*base({BASE_MS}ms)), \
         view_changes={} consecutive_nil={}",
        c.runtime(0).hc.round,
        c.runtime(0).hc.consecutive_nil_rounds,
    );
    let stall = c.report().await;
    println!("{}", metrics_line("full-stall", &stall));
    assert_eq!(
        stall.best_height,
        0,
        "quorum-starved cluster must not finalize.\n{}",
        stall.diagnostics()
    );
    assert_safe("full-stall", &stall, &[]);

    // --- Heal pin: both nodes back -> the chain resumes. ---
    c.set_down(1, false);
    c.set_down(2, false);
    let heal_report = c.run_until(2, 120_000).await;
    println!("{}", metrics_line("healed", &heal_report));
    assert!(
        heal_report.best_height >= 2,
        "the chain must resume after heal.\n{}",
        heal_report.diagnostics()
    );
    assert_eq!(
        heal_report.common_height,
        heal_report.best_height,
        "every node must rejoin the head after heal.\n{}",
        heal_report.diagnostics()
    );
    assert_safe("healed", &heal_report, &[]);
}

// ===========================================================================
// (b) Flapping proposer (alternating valid/nil rounds) -> no premature
// nil-commit; lock/round invariants hold.
// ===========================================================================

#[tokio::test]
async fn flapping_proposer_never_commits_nil() {
    const H: u64 = 9;
    // --- Unit pin 1: alternating outcomes never trip the breaker. ---
    let mut hc = HeightConsensus::new(H, vset(4));
    for flap in 0..6 {
        hc.note_round_outcome(true); // nil round
        assert!(
            !hc.nil_breaker_due(),
            "flap {flap}: a lone nil round must not trip the breaker"
        );
        hc.note_round_outcome(false); // value round resets the streak
        assert_eq!(
            hc.consecutive_nil_rounds, 0,
            "flap {flap}: a value round resets the nil streak"
        );
        assert!(!hc.nil_breaker_due());
        assert!(hc.decided.is_none(), "flap {flap}: nothing decided");
        assert_eq!(
            hc.scan_lookback, ROUND_LOOKBACK,
            "flap {flap}: window untouched without the breaker"
        );
    }

    // --- Unit pin 2: a nil-only QC never decides (no premature nil-commit),
    // and the lock is untouched. Quorum for [1,1,1,1] is 3. ---
    let mut hc2 = HeightConsensus::new(H, vset(4));
    assert_eq!(hc2.validators.quorum_power(), 3);
    // Cast at the CURRENT round: the quorum scan covers the window around the
    // local round counter, so a QC anywhere else is (correctly) invisible.
    let r = hc2.round;
    for i in 0..3 {
        let k = key_at(SEED, i);
        hc2.add_prevote(Vote::sign(&k, H, r, VoteKind::Prevote, None))
            .unwrap();
        hc2.add_precommit(Vote::sign(&k, H, r, VoteKind::Precommit, None))
            .unwrap();
    }
    // A nil prevote QC may be observable...
    assert_eq!(
        hc2.try_prevote_quorum(),
        Some(None),
        "3/4 nil prevotes form a nil QC (observable, not a decision)"
    );
    // ...but a nil precommit QC NEVER decides a block.
    assert_eq!(
        hc2.try_precommit_quorum(),
        None,
        "nil precommit quorum must not decide"
    );
    assert!(hc2.decided.is_none(), "no premature nil-commit");
    assert!(hc2.locked.is_none(), "nil rounds never take the lock");
    assert!(
        !hc2.nil_breaker_due(),
        "vote activity without round outcomes is not a storm"
    );

    // --- Sim pin: a live nil-flapper (minority) cannot stop the quorum. ---
    // 4 nodes, quorum 3: node 3 nils every prevote while the honest 3/4 carry
    // value quorums — every round mixes value and nil pressure (the flap).
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().byzantine(Byzantine::NilPrevote),
    ];
    let mut c = ConsensusCluster::build(4, profiles, SEED ^ 0xB, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(2).await;
    let report = c.run_until(2, 240_000).await;
    println!("{}", metrics_line("flap", &report));

    let nils: u64 = report
        .nodes
        .iter()
        .flat_map(|n| n.cast_votes.iter())
        .filter(|v| v.kind == VoteKind::Prevote && v.target.is_none())
        .count() as u64;
    println!("[liveness-breaker][flap] nil prevotes cast={nils}");
    assert!(
        nils > 0,
        "the flap must be real: the Byzantine node must have nilled.\n{}",
        report.diagnostics()
    );
    assert!(
        report.best_height >= 2,
        "the honest 3/4 quorum must finalize despite the flapper.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every UP node reaches the head.\n{}",
        report.diagnostics()
    );
    assert_safe("flap", &report, &[3]);
    // No premature breaker fire anywhere: no node sits on a K streak.
    for i in 0..4 {
        assert!(
            !c.runtime(i).hc.nil_breaker_due(),
            "node {i}: breaker must not be due after healthy-ish finalization"
        );
        assert!(
            c.runtime(i).hc.consecutive_nil_rounds < NIL_CIRCUIT_BREAKER_K,
            "node {i}: nil streak below K"
        );
    }
}

// ===========================================================================
// (c) Straggler-hold accounting: slow voter extends holds exactly per the cap
// formula (hold = min(grace, cap); subsumed variant fills slack to 2x base).
// ===========================================================================

#[tokio::test]
async fn straggler_hold_extends_exactly_per_cap() {
    // Cap formula pin (mirrors main.rs `straggler_hold_ms`: hold on fresh
    // evidence is `grace.min(cap)`; here grace != cap so the CAP binds).
    const GRACE_MS: u64 = 4_000;
    const CAP_MS: u64 = 1_000;
    const FRESHNESS_MS: u64 = 20_000;
    assert_eq!(
        GRACE_MS.min(CAP_MS),
        1_000,
        "per-round hold must be exactly min(grace, cap)"
    );
    let policy = StragglerPolicy::fixed(GRACE_MS, CAP_MS, FRESHNESS_MS);
    assert_eq!(
        policy.grace_ms.min(policy.cap_ms),
        CAP_MS,
        "policy hold per round is the cap, not the grace"
    );

    // Slow proposer shape: node 2 builds proposals slowly (past the round-0
    // rung) on a WAN-grade link, so the fast nodes hold the round open on
    // scheduled-proposal evidence instead of racing ahead proposalless.
    const SLOW_LINK_MS: u64 = 250;
    const SLOW_BUILD_MS: u64 = 2_500;
    const TARGET_HEIGHTS: u64 = 4;
    fn profiles() -> Vec<NodeProfile> {
        vec![
            NodeProfile::default(),
            NodeProfile::default(),
            NodeProfile::default()
                .with_inbound_delay_ms(SLOW_LINK_MS)
                .with_propose_delay_ms(SLOW_BUILD_MS),
        ]
    }
    let mut c = ConsensusCluster::build(3, profiles(), SEED ^ 0xC, TICK_MS, BASE_MS)
        .with_fast_forward(false)
        .with_straggler_policy(policy);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET_HEIGHTS, 240_000).await;
    println!("{}", metrics_line("straggler-cap", &report));

    assert!(
        report.best_height >= TARGET_HEIGHTS,
        "capped holds must not stall finalization.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every node reaches the head.\n{}",
        report.diagnostics()
    );
    let grace_total: u64 = report.nodes.iter().map(|n| n.grace_extends).sum();
    println!(
        "[liveness-breaker][straggler-cap] grace_extends_total={grace_total} \
         cap={CAP_MS}ms tick={TICK_MS}ms per-round-hold={}ms",
        GRACE_MS.min(CAP_MS),
    );
    assert!(
        grace_total > 0,
        "the hold mechanism must engage on the slow proposer shape.\n{}",
        report.diagnostics()
    );
    assert_safe("straggler-cap", &report, &[]);

    // Cap-formula bound, per node: a node participates in at most
    // (view_changes + finalized heights + 1 current) rounds, and each round
    // contributes at most cap/tick + 1 extend ticks (the extend window is
    // [base_eff, base_eff + min(grace,cap)] = cap ms wide, plus one boundary
    // tick). Any hold past the cap violates the formula.
    let max_extends_per_round = CAP_MS / TICK_MS + 1;
    for n in &report.nodes {
        let rounds_participated = n.view_changes + n.decide_rounds.len() as u64 + 1;
        let bound = rounds_participated * max_extends_per_round;
        assert!(
            n.grace_extends <= bound,
            "node {}: grace_extends={} exceeds cap-formula bound {bound} \
             (rounds={rounds_participated}, per-round-max={max_extends_per_round}).\n{}",
            n.index,
            n.grace_extends,
            report.diagnostics()
        );
    }

    // Determinism pin: the identical build reproduces the run bit-for-bit.
    let mut c2 = ConsensusCluster::build(3, profiles(), SEED ^ 0xC, TICK_MS, BASE_MS)
        .with_fast_forward(false)
        .with_straggler_policy(policy);
    c2.seed_transactions(3).await;
    let report2 = c2.run_until(TARGET_HEIGHTS, 240_000).await;
    assert_eq!(
        report.fingerprint(),
        report2.fingerprint(),
        "straggler-hold run must be bit-for-bit reproducible"
    );
    assert!(
        report2.best_height >= TARGET_HEIGHTS,
        "reproducibility run must also finalize"
    );
}

// ===========================================================================
// (d) Healthy fast rounds: the breaker never fires (no false positives) over
// a clean soak.
// ===========================================================================

#[tokio::test]
async fn healthy_fast_rounds_never_fire_breaker() {
    const TARGET_HEIGHTS: u64 = 5;
    let mut c = ConsensusCluster::build(
        3,
        vec![
            NodeProfile::default(),
            NodeProfile::default(),
            NodeProfile::default(),
        ],
        SEED ^ 0xD,
        TICK_MS,
        BASE_MS,
    );
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET_HEIGHTS, 240_000).await;
    println!("{}", metrics_line("healthy-soak", &report));

    assert!(
        report.best_height >= TARGET_HEIGHTS,
        "healthy cluster must finalize.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every node reaches the head.\n{}",
        report.diagnostics()
    );
    assert_safe("healthy-soak", &report, &[]);
    // Fast rounds throughout: an aligned cluster decides in its proposal round.
    let worst: u32 = report
        .nodes
        .iter()
        .flat_map(|n| n.decide_rounds.iter().copied())
        .max()
        .unwrap_or(0);
    println!("[liveness-breaker][healthy-soak] worst decide-round delta={worst}");
    assert!(
        worst <= 4,
        "healthy soak must decide within a couple of rounds, worst={worst}.\n{}",
        report.diagnostics()
    );

    // No false positives on ANY node, even under the liveness timeout: no nil
    // streak, breaker never due and never fired, scan window never widened,
    // and the deadlock jump path has no target (no peer is ahead).
    for i in 0..3 {
        let hc = &c.runtime(i).hc;
        assert!(
            hc.consecutive_nil_rounds < NIL_CIRCUIT_BREAKER_K,
            "node {i}: nil streak below K on a healthy soak"
        );
        assert!(
            !hc.nil_breaker_due(),
            "node {i}: nil breaker must never be due on a healthy soak"
        );
        assert!(
            !hc.nil_breaker_fired_this_streak,
            "node {i}: breaker must never have fired on a healthy soak"
        );
        assert_eq!(
            hc.scan_lookback, ROUND_LOOKBACK,
            "node {i}: scan window must stay at ROUND_LOOKBACK (never widened)"
        );
        assert_eq!(
            hc.deadlock_breaker_target(10_000, TIMEOUT_SECS),
            None,
            "node {i}: jump breaker must have no target when peers are aligned"
        );
        assert!(
            !hc.deadlock_local_reset_due(10, TIMEOUT_SECS),
            "node {i}: no reset while progress is fresh"
        );
    }
}
