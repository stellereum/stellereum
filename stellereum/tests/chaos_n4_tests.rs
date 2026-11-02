//! # CHAOS-N4: 4-member sim cluster under WAN-ish skew.
//!
//! One member is DOWN (f=1) and one member is SLOW (5x round-timeout factor +
//! 250ms inbound / 250ms propose delay, the incident-scale WAN link), against
//! a generous 1000ms base: the degraded-but-live shape (quorum 3 of 4 still
//! reachable when the timeout covers the slow link).
//!
//! WHAT EACH TEST PROVES:
//! * `wan_skew_degraded_but_live_finals_keep_moving` — finals keep moving
//!   with f=1 down + 1 slow (degraded but live; the finals rate is recorded,
//!   rate > 0 rather than an exact count), the slow member votes inside the
//!   round, the down member finalizes nothing, no fork, no double-votes,
//!   live state roots agree. A deterministic replay pins the virtual-clock
//!   determinism (no `PhysicalInstant` exists anywhere in the harness or the
//!   consensus path — verified by grep: zero hits — so the virtual clock is
//!   the only clock and identical seeds must fingerprint identically).
//! * `slow_straggler_catches_up_via_phase_sync` — the slow member starts
//!   rounds-behind with a WAN-grade link (the straggler shape) and
//!   reconverges through the future-rule round-jump path (`sync_jumps > 0`),
//!   voting throughout, with finals flowing the whole time.
//! * `kill_heal_mid_run_liveness_holds_with_reported_height_gap` — the slow
//!   member is killed mid-run (the chain advances on the remaining 3/4, its
//!   head freezes, no fork), then healed: it re-participates and the live
//!   chain keeps moving. The multi-height height-convergence assertion is
//!   NOT expressible in-sim (exact-height adopt, no walk) and is reported as
//!   an explicit harness gap instead of faked.
//! * `down_member_marked_by_downtime_evidence` — the down member is marked at
//!   BOTH levels: consensus-level (zero votes cast while live precommit QCs
//!   form at power 3-of-4 without it) and ledger-level (a genuine 3-signer QC
//!   fed through `apply_downtime_slash_with_set` — the exact function
//!   `apply_block_transition` calls — records the down member's miss while
//!   signers stay clean).
//!
//! DETERMINISM: fixed seeds per test, virtual clock only, no OS randomness.
//! Every test runs on a bounded virtual budget (<= 120_000ms virtual, which
//! executes in seconds of wall time).
//!
//! ```text
//! cargo test --test chaos_n4_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile, key_at};
use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};

const TICK_MS: u64 = 100;
const BASE_MS: u64 = 1_000;
const SLOW_LINK_MS: u64 = 250;
const BUDGET_MS: u64 = 120_000;

/// Profiles for the degraded-but-live shape: two fast, one slow, one down.
fn wan_profiles() -> Vec<NodeProfile> {
    vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default()
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_LINK_MS),
        NodeProfile::default().down(),
    ]
}

/// Finals rate in heights per virtual second (pure function of the report).
fn finals_rate_per_virtual_s(best_height: u64, virtual_ms: u64) -> f64 {
    if virtual_ms == 0 {
        return 0.0;
    }
    best_height as f64 / (virtual_ms as f64 / 1_000.0)
}

#[tokio::test]
async fn wan_skew_degraded_but_live_finals_keep_moving() {
    const SEED: u64 = 0xC4A0_0001;
    const TARGET: u64 = 3;
    let mut c = ConsensusCluster::build(4, wan_profiles(), SEED, TICK_MS, BASE_MS);
    // Quorum for equal power 4 = 3: the two fast + the slow member are a
    // quorum without the down member.
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;

    let rate = finals_rate_per_virtual_s(report.best_height, report.virtual_ms);
    println!(
        "[chaos][wan-live] seed=0x{:x} virtual_ms={} ticks={} best={} common={} \
         finals_rate_per_virtual_s={:.3} decide_rounds={:?}",
        SEED,
        report.virtual_ms,
        report.ticks,
        report.best_height,
        report.common_height,
        rate,
        report
            .nodes
            .iter()
            .map(|n| n.decide_rounds.clone())
            .collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // LIVENESS (degraded but live): finals keep moving without the down member.
    assert!(
        report.best_height >= TARGET,
        "finals must keep moving with f=1 down + 1 slow.\n{}",
        report.diagnostics()
    );
    assert!(
        report.common_height >= TARGET,
        "every UP member must reach the target (common excludes the down node by construction).\n{}",
        report.diagnostics()
    );
    // The rate is recorded and strictly positive — a rate assertion, not an
    // exact count (timing stays generous-but-bounded by construction).
    assert!(
        rate > 0.0,
        "finals rate must be positive (best={} in {} virtual ms).\n{}",
        report.best_height,
        report.virtual_ms,
        report.diagnostics()
    );
    // The slow member participates (it votes inside the round when the base
    // covers its link); the down member finalizes nothing and casts nothing.
    assert!(
        report.nodes[2].prevotes_cast > 0,
        "the slow member must vote (its link is covered by the base timeout).\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.nodes[3].finalized_height, 0,
        "the down member must finalize nothing.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.nodes[3].prevotes_cast, 0,
        "the down member must cast no prevotes.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.nodes[3].precommits_cast, 0,
        "the down member must cast no precommits.\n{}",
        report.diagnostics()
    );
    // Live precommit QCs form at power 3-of-4 (the down power is absent).
    for i in 0..3 {
        assert!(
            report.nodes[i].precommit_qc_round.is_some(),
            "live node {i} must hold a precommit QC.\n{}",
            report.diagnostics()
        );
        assert_eq!(
            report.nodes[i].precommit_qc_power,
            Some(3),
            "live QCs must carry exactly the 3 live powers (down member absent).\n{}",
            report.diagnostics()
        );
    }
    // SAFETY among the live: no fork, no double-votes, state agrees.
    for (h, entries) in report.finalized_by_height() {
        let live: Vec<_> = entries
            .iter()
            .filter(|(i, _)| *i != 3)
            .map(|(_, x)| *x)
            .collect();
        let mut hashes = live.clone();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block among live nodes"
        );
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "slow-but-honest voters never double-vote.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = (0..3).map(|i| report.nodes[i].state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "live nodes must agree on state.\n{}",
        report.diagnostics()
    );

    // DETERMINISM: the identical scenario replays byte-identically (virtual
    // clock only — no PhysicalInstant exists in the harness or consensus path).
    let mut c2 = ConsensusCluster::build(4, wan_profiles(), SEED, TICK_MS, BASE_MS);
    c2.seed_transactions(3).await;
    let replay = c2.run_until(TARGET, BUDGET_MS).await;
    assert_eq!(
        report.fingerprint(),
        replay.fingerprint(),
        "identical seeds must fingerprint identically"
    );
    println!("[chaos][wan-live][replay] fingerprint stable");
}

/// The SLOW member catches up via PHASE SYNC: it starts rounds-behind with a
/// WAN-grade link (the straggler shape) and reconverges through the
/// future-rule round-jump path (`sync_jumps`), the same phase-alignment the
/// production drain performs on every peer vote.
#[tokio::test]
async fn slow_straggler_catches_up_via_phase_sync() {
    const SEED: u64 = 0xC4A0_0002;
    const TARGET: u64 = 3;
    const SLOW: usize = 2;
    const LATE_ROUNDS: u32 = 12;
    // Node 2 is the WAN straggler: slow clock, slow link, starts 12 rounds
    // behind. Node 3 is the f=1 floor (down from genesis).
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default()
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_LINK_MS)
            .late_by(LATE_ROUNDS),
        NodeProfile::default().down(),
    ];
    let mut c = ConsensusCluster::build(4, profiles, SEED, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    // The network starts at the highest offset; the straggler behind it.
    assert_eq!(c.base_round(), LATE_ROUNDS);
    assert_eq!(
        c.runtime(SLOW).hc.round,
        0,
        "the straggler must start at the bottom of the skew"
    );
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;

    println!(
        "[chaos][straggler-sync] seed=0x{:x} virtual_ms={} ticks={} best={} common={} \
         decide_rounds={:?} sync_jumps={:?}",
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
        report.nodes.iter().map(|n| n.sync_jumps).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());

    // CATCH-UP: the straggler reconverges — every UP node finalizes every
    // height (common excludes the genesis-down node by construction).
    assert!(
        report.best_height >= TARGET,
        "finals must keep moving with a straggler + a down member.\n{}",
        report.diagnostics()
    );
    assert!(
        report.common_height >= TARGET,
        "the straggler must catch up and finalize with the rest.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.nodes[SLOW].finalized_height, report.best_height,
        "the straggler must converge exactly onto the live head.\n{}",
        report.diagnostics()
    );
    // The sync mechanism REALLY ran: the straggler consumed the round-jump
    // path (peer votes pulling it into the network's round). Zero jumps with
    // a 12-round starting skew would mean the skew never separated the nodes
    // and the test proved nothing.
    assert!(
        report.nodes[SLOW].sync_jumps > 0,
        "the straggler must have used the phase-alignment path.\n{}",
        report.diagnostics()
    );
    // ...while still voting (a silent straggler that only follows is not the
    // WAN shape: its vote stays load-bearing with 3/4 quorum).
    assert!(
        report.nodes[SLOW].prevotes_cast > 0,
        "the straggler must vote, not just follow.\n{}",
        report.diagnostics()
    );
    // SAFETY: no fork among the up nodes, no double-votes, state agrees.
    for (h, entries) in report.finalized_by_height() {
        let live: Vec<_> = entries
            .iter()
            .filter(|(i, _)| *i != 3)
            .map(|(_, x)| *x)
            .collect();
        let mut hashes = live.clone();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block among up nodes"
        );
    }
    assert!(
        report.double_votes(&[]).is_empty(),
        "the straggler must not double-vote while reconverging.\n{}",
        report.diagnostics()
    );
    let roots: Vec<_> = (0..3).map(|i| report.nodes[i].state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "reconverged nodes must agree on state.\n{}",
        report.diagnostics()
    );
}

/// Mid-run kill of the slow member, then heal: the chain advances without it
/// (3/4 survivors are a quorum), its head freezes, and on heal it
/// re-participates at consensus level. What is NOT asserted is a multi-height
/// thereby — see the REPORTED GAP below.
#[tokio::test]
async fn kill_heal_mid_run_liveness_holds_with_reported_height_gap() {
    const SEED: u64 = 0xC4A0_0004;
    const PRE_KILL_HEIGHT: u64 = 2;
    const STALL_MS: u64 = 30_000;
    const SLOW: usize = 2;
    // All four start UP (node 2 slow); the f=1 outage is the mid-run kill.
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default()
            .with_round_timeout_factor(5)
            .with_inbound_delay_ms(SLOW_LINK_MS)
            .with_propose_delay_ms(SLOW_LINK_MS),
        NodeProfile::default(),
    ];
    let mut c = ConsensusCluster::build(4, profiles, SEED, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;

    // Phase 1: liveness with everyone up.
    let pre = c.run_until(PRE_KILL_HEIGHT, BUDGET_MS).await;
    assert!(
        pre.common_height >= PRE_KILL_HEIGHT,
        "liveness must be established before the kill.\n{}",
        pre.diagnostics()
    );

    // Phase 2: kill the slow member at time T; the chain advances without it.
    let kill_at = c.now_ms();
    c.set_down(SLOW, true);
    let mid = c.run_for(STALL_MS).await;
    let dead_head = mid.nodes[SLOW].finalized_height;
    println!(
        "[chaos][kill-heal][mid] seed=0x{:x} kill_at={} best={} common={} dead_head={}",
        SEED, kill_at, mid.best_height, mid.common_height, dead_head,
    );
    assert!(
        mid.best_height > dead_head,
        "the chain must advance without the killed member (3/4 survivors are a quorum).\n{}",
        mid.diagnostics()
    );
    assert_eq!(
        mid.nodes[SLOW].finalized_height, dead_head,
        "the killed member's head must stay frozen while down.\n{}",
        mid.diagnostics()
    );
    // No fork among the survivors while the member is out.
    for (h, entries) in mid.finalized_by_height() {
        let live: Vec<_> = entries
            .iter()
            .filter(|(i, _)| *i != SLOW)
            .map(|(_, x)| *x)
            .collect();
        let mut hashes = live.clone();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block among survivors"
        );
    }

    // Phase 3: heal. The returnee re-participates (its round timer restarts
    // and it votes at its height again) and the live chain keeps moving — the
    // returnee neither stalls the network nor forks it.
    let votes_before = mid.nodes[SLOW].prevotes_cast;
    c.set_down(SLOW, false);
    let report = c.run_for(STALL_MS).await;
    println!(
        "[chaos][kill-heal] seed=0x{:x} kill_at={} virtual_ms={} best={} common={} \
         returnee_head={} returnee_votes={} sync_jumps={:?}",
        SEED,
        kill_at,
        report.virtual_ms,
        report.best_height,
        report.common_height,
        report.nodes[SLOW].finalized_height,
        report.nodes[SLOW].prevotes_cast,
        report.nodes.iter().map(|n| n.sync_jumps).collect::<Vec<_>>(),
    );
    println!("{}", report.diagnostics());
    assert!(
        report.nodes[SLOW].prevotes_cast > votes_before,
        "the healed member must vote again after healing.\n{}",
        report.diagnostics()
    );
    assert!(
        report.best_height > mid.best_height,
        "the live chain must keep advancing after the heal (no stall induced).\n{}",
        report.diagnostics()
    );
    assert!(
        report.nodes[SLOW].finalized_height >= dead_head,
        "the returnee head must never regress.\n{}",
        report.diagnostics()
    );
    assert!(
        report.double_votes(&[]).is_empty(),
        "kill/heal must not produce double-votes.\n{}",
        report.diagnostics()
    );
    // REPORTED GAP (explicit, not a fake green): a returnee that fell several
    // heights behind does NOT converge back in-sim. `adopt_committed` is
    // exact-height (`height mismatch (ours .., peer ..)` otherwise) and the
    // tick harness drives no height walk, so a multi-height gap never closes
    // no matter how long the run. Production heals this via the sync walk
    // (`collect_missing_blocks` / `validate_sync_chain`, pinned at unit level
    // by `partition_heal_tests`); the tick harness has no primitive for it.
    // The height-convergence assertion is therefore unexpressible in-sim and
    // is reported here instead of faked.
    println!(
        "[chaos][REPORTED-GAP] multi-height returnee catch-up not expressible in-sim \
         (exact-height adopt, no walk): returnee_head={} vs best={}; \
         height convergence lives in the sync walk (partition_heal_tests).",
        report.nodes[SLOW].finalized_height,
        report.best_height,
    );
}

#[tokio::test]
async fn down_member_marked_by_downtime_evidence() {
    const SEED: u64 = 0xC4A0_0003;
    const TARGET: u64 = 2;
    const QC_HEIGHT: u64 = 7;
    let mut c = ConsensusCluster::build(4, wan_profiles(), SEED, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;
    assert!(
        report.common_height >= TARGET,
        "precondition: the live chain must move.\n{}",
        report.diagnostics()
    );

    // CONSENSUS-LEVEL EVIDENCE: the down member cast nothing while live
    // precommit QCs formed at power 3-of-4 without it.
    assert_eq!(report.nodes[3].prevotes_cast, 0);
    assert_eq!(report.nodes[3].precommits_cast, 0);
    for i in 0..3 {
        assert!(
            report.nodes[i].precommit_qc_round.is_some(),
            "live node {i} must hold a precommit QC.\n{}",
            report.diagnostics()
        );
        assert_eq!(
            report.nodes[i].precommit_qc_power,
            Some(3),
            "live QCs must exclude the down member's power.\n{}",
            report.diagnostics()
        );
    }

    // LEDGER-LEVEL EVIDENCE through the real path: bond the cluster's
    // validator ids, build a genuine 3-signer precommit QC with the live keys
    // (re-derived deterministically via key_at), and attribute it with
    // apply_downtime_slash_with_set — the exact function
    // apply_block_transition calls for the H-1 evidence.
    use stellereum::staking::{MIN_VALIDATOR_BOND, STAKING_POOL, STELL_MIN_BOND_BUFFER};
    use stellereum::state_engine::InMemoryStateEngine;

    let bond = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;
    let engine = InMemoryStateEngine::new();
    let live: Vec<usize> = vec![0, 1, 2];
    let down: usize = 3;
    let ids: Vec<[u8; 32]> = (0..4)
        .map(|i| key_at(SEED, i as u64).verifying_key().to_bytes())
        .collect();
    for id in &ids {
        engine
            .credit_native(id, bond * 4)
            .await
            .expect("fund member");
        engine
            .staking_write()
            .await
            .bond(*id, bond, 0)
            .expect("bond member");
    }
    engine
        .credit_native(&STAKING_POOL, bond * 10)
        .await
        .expect("fund pool");

    let evidence_hash = [0xAAu8; 32];
    let qc = QuorumCertificate {
        height: QC_HEIGHT,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(evidence_hash),
        signatures: live
            .iter()
            .map(|&i| {
                let v = Vote::sign(
                    &key_at(SEED, i as u64),
                    QC_HEIGHT,
                    0,
                    VoteKind::Precommit,
                    Some(evidence_hash),
                );
                (v.voter, v.signature)
            })
            .collect(),
    };
    let val_set = engine.staking_read().await.to_validator_set();
    assert_eq!(val_set.len(), 4, "precondition: 4 bonded members");
    assert!(
        qc.verify(&val_set),
        "precondition: the 3-signer QC must verify under the bonded set"
    );
    // Same function the real block path calls (one miss is below the
    // 10-miss slash threshold: evidence is marked, nothing burns yet).
    let burned = engine
        .apply_downtime_slash_with_set(QC_HEIGHT, Some(&qc), &val_set)
        .await;
    assert_eq!(burned, 0, "a single miss must mark, not slash");

    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.validators[&ids[down]].missed, 1,
        "the down member must be marked with a miss for the QC it skipped"
    );
    for &i in &live {
        assert_eq!(
            ledger.validators[&ids[i]].missed, 0,
            "signer {i} must accrue no miss"
        );
    }
    println!(
        "[chaos][downtime-evidence] seed=0x{:x} qc_height={} down_missed={} burned={}",
        SEED, QC_HEIGHT, ledger.validators[&ids[down]].missed, burned
    );
}
