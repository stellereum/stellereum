//! # SLASH-DRILL: equivocation + sustained-downtime slashing.
//!
//! WHAT EACH TEST PROVES:
//! * `double_vote_equivocation_recorded_and_slashed_via_wired_path` —
//!   (a) in-sim: a `Byzantine::DoublePrevote` member's conflicting pair is
//!   OBSERVED as equivocation evidence while the honest 3/4 keep finalizing
//!   (the vote set keeps the first vote — safety holds); (b) wired slash: the
//!   same offense class burns EXACTLY 5% through `try_finalize` →
//!   `apply_block_transition` → `apply_equivocation_slash` → ledger
//!   `slash_equivocation_verified` (the functions the real path calls), with
//!   the pool debited to the nano.
//! * `sustained_downtime_slash_ejects_below_min_with_power_change_at_h1` —
//!   a member parked one miss short of `DOWNTIME_MISS_THRESHOLD` at bare-MIN
//!   bond misses the next canonical QC: the 0.1% downtime slash fires through
//!   the real block path, the bond drops below MIN, the member is ejected
//!   from the derived set (jailed), and the power change is visible at H+1
//!   (set length 4 → 3, survivor-only QC still verifies, remainder quorate).
//! * `evidence_verification_unit_level_and_harness_gap` — fail-closed pins
//!   (a repeated single vote burns nothing and reverts the reporter tx; the
//!   gossip feed converts observations into canonical envelopes without
//!   touching stake) plus the explicit HARNESS GAP report (see below).
//!
//! HARNESS GAP (reported, not faked): the sim harness expresses a dignified
//! double-vote injection (`Byzantine::DoublePrevote` casts a genuine second
//! signed vote for a different target at the same height/round, and the
//! cluster records it in `ClusterReport.equivocations`) — but it has NO
//! primitive for packaging observed evidence into a block-carried
//! `SysCallReportEquivocation` envelope and finalizing it in-sim (there is no
//! block-producer feed hook in the harness tick). The end-to-end
//! sim→slash burn is therefore NOT expressible in-sim; the burn leg is pinned
//! at the evidence-verification unit level through `apply_block_transition`
//! (the same function the production finalize path runs), with byte-identical
//! envelopes to the ones `equivocation_feed_evidence` produces.
//!
//! DETERMINISM: fixed seeds everywhere (deterministic `det_key` bytes, seeded
//! harness builds, virtual clock only). No wall clock, no OS randomness.
//! Every sim leg runs on a bounded virtual budget (<= 120_000ms virtual).
//!
//! ```text
//! cargo test --test slash_drill_tests -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{Byzantine, ConsensusCluster, NodeProfile};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::{
    EquivocationEvidence, QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind,
};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{
    DOWNTIME_MISS_THRESHOLD, DOWNTIME_SLASH_BPS, EQUIVOCATION_SLASH_BPS, JAIL_RELEASE_DELAY_HEIGHTS,
    MIN_VALIDATOR_BOND, STAKING_POOL,
};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

const TICK_MS: u64 = 100;
const BASE_MS: u64 = 1_000;
const BUDGET_MS: u64 = 120_000;
/// Genesis funding per validator (far above the bonded stake, so fees never bind).
const BAL: u64 = 10_000 * 1_000_000_000;
const TS: u64 = 1_760_000_000;
const REPORT_GAS: u64 = 500_000;

/// Deterministic key `i` (no OS randomness; same shape as the live-stand rig).
fn det_key(i: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = i.wrapping_add(1);
    bytes[31] = 0x5A;
    SigningKey::from_bytes(&bytes)
}

fn id_of(k: &SigningKey) -> ValidatorId {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id_of(k), 1)).collect())
}

/// Genesis self-bond every validator carries (bare MIN via `fund_genesis`),
/// so the exact 5% burn is `MIN * 500 / 10_000` with no remainder.
fn expected_equivocation_burn() -> u64 {
    (MIN_VALIDATOR_BOND as u128 * EQUIVOCATION_SLASH_BPS as u128 / 10_000u128) as u64
}

/// Exact 0.1% downtime burn of a bare-MIN, delegation-free stake.
fn expected_downtime_burn() -> u64 {
    (MIN_VALIDATOR_BOND as u128 * DOWNTIME_SLASH_BPS as u128 / 10_000u128) as u64
}

/// A genuine conflicting vote pair by `offender` at consensus height 1.
fn double_sign(offender: &SigningKey) -> EquivocationEvidence {
    let a = Vote::sign(offender, 1, 0, VoteKind::Prevote, Some([0x11u8; 32]));
    let b = Vote::sign(offender, 1, 0, VoteKind::Prevote, Some([0x22u8; 32]));
    assert!(a.verify() && b.verify(), "precondition: both votes verify");
    EquivocationEvidence::new(id_of(offender), a, b)
}

fn report_tx(reporter: &SigningKey, nonce: u64, evidence: EquivocationEvidence) -> Transaction {
    Transaction::sign_with_payload(
        reporter,
        [0u8; 32],
        0,
        REPORT_GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallReportEquivocation {
            evidence: Box::new(evidence),
        }],
    )
}

fn mk_block(
    proposer: &SigningKey,
    height: u64,
    prev: [u8; 32],
    root: [u8; 32],
    txs: Vec<Transaction>,
) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut blk = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: root,
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: id_of(proposer),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    blk.sign_block(proposer);
    blk
}

fn scheduled_key<'a>(ks: &'a [SigningKey], vs: &ValidatorSet, h: u64, r: u32) -> &'a SigningKey {
    let want = vs.proposer_for(h, r).expect("non-empty set has a proposer");
    ks.iter()
        .find(|k| id_of(k) == want)
        .expect("schedule proposer is one of our keys")
}

/// Drive a FULL (4-of-4) precommit quorum for `bh` so the downtime leg burns
/// exactly 0 and any burn observed is the equivocation leg alone.
fn certify_full(
    rt: &mut ValidatorRuntime,
    ks: &[SigningKey],
    height: u64,
    bh: [u8; 32],
) -> QuorumCertificate {
    for k in ks.iter() {
        rt.on_prevote(Vote::sign(k, height, 0, VoteKind::Prevote, Some(bh)))
            .expect("prevote accepted");
        rt.on_precommit(Vote::sign(k, height, 0, VoteKind::Precommit, Some(bh)))
            .expect("precommit accepted");
    }
    assert_eq!(
        rt.hc.try_precommit_quorum(),
        Some(bh),
        "precondition: full quorum must form at height {height}"
    );
    rt.hc.precommit_qc.clone().expect("QC exists")
}

async fn pool_of(e: &Arc<InMemoryStateEngine>) -> u64 {
    e.get_account(&STAKING_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// One engine with four genesis validators bonded at bare MIN plus a funded
/// staking pool (the slash debit is real coins).
async fn bonded_engine(ks: &[SigningKey]) -> Arc<InMemoryStateEngine> {
    let vs = vset(ks);
    let e = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&e, &vs, BAL).await;
    e.credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
        .await
        .expect("pool credit");
    e
}

// ============================================================================
// 1. Double-vote recorded in-sim; the same offense class slashed via the wired
//    path (same functions the real path calls).
// ============================================================================

#[tokio::test]
async fn double_vote_equivocation_recorded_and_slashed_via_wired_path() {
    const SEED: u64 = 0x51A5_0001;
    const TARGET: u64 = 3;
    const EVIL: usize = 3;

    // ---- (a) in-sim: the double-vote is injected and OBSERVED ----
    let profiles = vec![
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default(),
        NodeProfile::default().byzantine(Byzantine::DoublePrevote),
    ];
    let mut c = ConsensusCluster::build(4, profiles, SEED, TICK_MS, BASE_MS);
    assert_eq!(c.validators().quorum_power(), 3);
    c.seed_transactions(3).await;
    let report = c.run_until(TARGET, BUDGET_MS).await;

    println!(
        "[slash][equiv-in-sim] seed=0x{:x} virtual_ms={} best={} common={} equivocations={}",
        SEED,
        report.virtual_ms,
        report.best_height,
        report.common_height,
        report.equivocations.len(),
    );
    println!("{}", report.diagnostics());

    // The injection ran: the cluster observed the conflicting pair...
    assert!(
        !report.equivocations.is_empty(),
        "the double-vote must be recorded as equivocation evidence.\n{}",
        report.diagnostics()
    );
    // ...cast by the designated Byzantine (and ONLY by it — honest nodes never
    // double-vote, so the exempt check is empty)...
    let all_dupes = report.double_votes(&[]);
    assert!(
        !all_dupes.is_empty(),
        "the evil member must have two different votes for one (height, round, kind).\n{}",
        report.diagnostics()
    );
    assert!(
        all_dupes.iter().all(|(i, _, _, _)| *i == EVIL),
        "only node {EVIL} may double-vote (got {all_dupes:?}).\n{}",
        report.diagnostics()
    );
    assert!(
        report.double_votes(&[EVIL]).is_empty(),
        "no HONEST node may double-vote.\n{}",
        report.diagnostics()
    );
    // ...while the honest 3/4 keep finalizing on the first-seen value.
    assert!(
        report.best_height >= TARGET,
        "the honest quorum must keep finalizing past the equivocation.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height, report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    for (h, entries) in report.finalized_by_height() {
        let mut hashes: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "height {h} must have exactly one decided block despite the double-vote"
        );
    }

    // ---- (b) wired slash: the same offense class burns exactly 5% ----
    // (Same functions the production finalize path calls:
    // try_finalize -> apply_block_transition (step 5b) ->
    // apply_equivocation_slash -> StakingLedger::slash_equivocation_verified.)
    let ks: Vec<SigningKey> = (0..4).map(det_key).collect();
    let vs = vset(&ks);
    let offender = id_of(&ks[3]);
    let engine = bonded_engine(&ks).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);

    let burn = expected_equivocation_burn();
    assert_eq!(burn, MIN_VALIDATOR_BOND / 20, "5% must be exact");
    assert_eq!(
        engine.staking_read().await.validators[&offender].self_bond,
        MIN_VALIDATOR_BOND,
        "precondition: offender bonded at bare MIN"
    );
    let pool_before = pool_of(&engine).await;
    let burned_before = engine.staking_read().await.total_burned;

    let evidence = double_sign(&ks[3]);
    let root = engine.get_state_root().await;
    let mut blk = mk_block(
        &ks[0],
        1,
        [0u8; 32],
        root,
        vec![report_tx(&ks[0], 0, evidence)],
    );
    let bh = blk.compute_hash();
    blk.precommit_qc = Some(certify_full(&mut rt, &ks, 1, bh));
    rt.blocks.insert(bh, blk.clone());
    assert_eq!(rt.try_finalize().await, Some(bh), "must finalize height 1");

    assert_eq!(rt.applied_statuses, vec![true], "valid report tx succeeds");
    let l = engine.staking_read().await;
    assert_eq!(
        l.validators[&offender].self_bond,
        MIN_VALIDATOR_BOND - burn,
        "bond must fall by exactly 5%"
    );
    assert_eq!(
        l.validators[&offender].total_slashed, burn,
        "offender counter must equal the burn"
    );
    assert_eq!(
        l.total_burned - burned_before,
        burn,
        "global burn delta must equal exactly one 5% slash (full QC: downtime leg burned 0)"
    );
    drop(l);
    assert_eq!(
        pool_before - pool_of(&engine).await,
        burn,
        "STAKING_POOL debit must equal the burn exactly"
    );
    println!("[slash][equiv-wired] offender burned={burn} (5% of MIN), pool debited nano-for-nano");
}

// ============================================================================
// 2. Sustained downtime: slash fires, below-MIN ejects, power change at H+1.
// ============================================================================

#[tokio::test]
async fn sustained_downtime_slash_ejects_below_min_with_power_change_at_h1() {
    let ks: Vec<SigningKey> = (0..4).map(det_key).collect();
    let vs = vset(&ks);
    let victim = id_of(&ks[3]);
    let engine = bonded_engine(&ks).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);

    // Victim sits exactly at MIN with a 9-miss streak: the next canonical miss
    // fires exactly one downtime slash.
    {
        let mut l = engine.staking_write().await;
        let rec = l.validators.get_mut(&victim).expect("victim bonded");
        rec.self_bond = MIN_VALIDATOR_BOND;
        rec.missed = DOWNTIME_MISS_THRESHOLD - 1;
        rec.last_downtime_penalty = 0;
    }
    let burn = expected_downtime_burn();
    assert_eq!(burn, MIN_VALIDATOR_BOND / 1000, "0.1% of MIN must be exact");
    let (len_before, q_before, total_before) = {
        let s = engine.staking_read().await.to_validator_set();
        (s.len(), s.quorum_power(), s.total_power())
    };
    assert_eq!(len_before, 4, "precondition: 4 elected");

    // Height 1 on 3 honest votes (victim silent). Genesis child: no canonical
    // evidence yet, so the streak is untouched.
    let pkey = scheduled_key(&ks, &vs, 1, 0).clone();
    let root = engine.get_state_root().await;
    let blk = mk_block(&pkey, 1, [0u8; 32], root, vec![]);
    let bh1 = blk.compute_hash();
    for &i in &[0usize, 1, 2] {
        rt.on_prevote(Vote::sign(&ks[i], 1, 0, VoteKind::Prevote, Some(bh1)))
            .unwrap();
        rt.on_precommit(Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh1)))
            .unwrap();
    }
    assert_eq!(rt.hc.try_precommit_quorum(), Some(bh1));
    let cert1 = rt.hc.precommit_qc.clone().expect("height-1 QC exists");
    assert!(cert1.verify(&vs), "precondition: QC must be genuine");
    rt.blocks.insert(bh1, blk);
    assert_eq!(rt.try_finalize().await, Some(bh1), "height 1 must finalize");
    assert_eq!(
        engine.staking_read().await.validators[&victim].missed,
        DOWNTIME_MISS_THRESHOLD - 1,
        "genesis child carries no evidence: streak untouched"
    );

    // Height 2 carries the height-1 QC as canonical evidence
    // (`decided_parent_qc`): the victim misses at the threshold, the 0.1%
    // slash fires through the real block path.
    let burned_before = engine.staking_read().await.total_burned;
    let pool_before = pool_of(&engine).await;
    let pkey2 = scheduled_key(&ks, &rt.validators, 2, 0).clone();
    let root2 = engine.get_state_root().await;
    let mut blk2 = mk_block(&pkey2, 2, bh1, root2, vec![]);
    blk2.last_qc = Some(cert1);
    blk2.validator_signatures.clear();
    blk2.sign_block(&pkey2);
    let bh2 = blk2.compute_hash();
    for &i in &[0usize, 1, 2] {
        rt.on_prevote(Vote::sign(&ks[i], 2, 0, VoteKind::Prevote, Some(bh2)))
            .unwrap();
        rt.on_precommit(Vote::sign(&ks[i], 2, 0, VoteKind::Precommit, Some(bh2)))
            .unwrap();
    }
    assert_eq!(rt.hc.try_precommit_quorum(), Some(bh2));
    rt.blocks.insert(bh2, blk2);
    assert_eq!(
        rt.try_finalize().await,
        Some(bh2),
        "height 2 must finalize on the 3 honest votes"
    );

    // THE SLASH: exactly 0.1% burned, pool-debited.
    let l = engine.staking_read().await;
    let bond_after = l.validators[&victim].self_bond;
    assert_eq!(
        bond_after,
        MIN_VALIDATOR_BOND - burn,
        "bare-MIN bond must fall by exactly the 0.1% slash"
    );
    assert!(
        bond_after < MIN_VALIDATOR_BOND,
        "0.1% on exactly-MIN must push the bond below the minimum"
    );
    assert_eq!(
        l.total_burned - burned_before,
        burn,
        "exactly one downtime slash must fire"
    );
    assert_eq!(
        l.validators[&victim].missed, 0,
        "the streak resets when the penalty fires"
    );
    // JAIL: the offender is excluded until evidence-height + delay.
    // (Transition attributes at evidence_height = block.height - 1 = 1.)
    let jail = l.jail.get(&victim).expect("downtime slash must jail");
    assert_eq!(jail.jailed_at_height, 1, "jailed at the evidence height");
    assert_eq!(
        jail.release_height,
        1 + JAIL_RELEASE_DELAY_HEIGHTS,
        "release is evidence height + delay"
    );
    drop(l);
    assert_eq!(
        pool_before - pool_of(&engine).await,
        burn,
        "STAKING_POOL debit must equal the burn exactly"
    );

    // EJECTED BELOW MIN + POWER CHANGE VISIBLE AT H+1: the derived set drops
    // the victim at the boundary the finalize installed.
    assert!(
        !rt.validators.contains(&victim),
        "validator below MIN must be dropped from the set at the boundary"
    );
    assert_eq!(rt.validators.len(), 3, "set must shrink 4 -> 3");
    let (q_after, total_after) = (rt.validators.quorum_power(), rt.validators.total_power());
    println!(
        "[slash][downtime] victim bond {bond_after} (< MIN), set 4 -> 3, \
         quorum {q_before} -> {q_after}, total {total_before} -> {total_after}, \
         jail release at {}",
        1 + JAIL_RELEASE_DELAY_HEIGHTS,
    );
    assert_ne!(q_after, q_before, "quorum_power must move with the new stake");
    assert_ne!(total_after, total_before, "total power must move with the new stake");
    assert!(
        total_after >= q_after,
        "remainder must still be quorate"
    );

    // The remainder can still certify: a survivor-only QC verifies against the
    // rotated H+1 set.
    let h_next = rt.height();
    let probe_hash = [0x77u8; 32];
    let qc = QuorumCertificate {
        height: h_next,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(probe_hash),
        signatures: [0usize, 1, 2]
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], h_next, 0, VoteKind::Precommit, Some(probe_hash));
                (v.voter, v.signature)
            })
            .collect(),
    };
    assert!(
        qc.verify(&rt.validators),
        "survivor-only QC must verify against the rotated set"
    );
}

// ============================================================================
// 3. Evidence-verification unit level (fail-closed + feed) and the harness gap.
// ============================================================================

#[tokio::test]
async fn evidence_verification_unit_level_and_harness_gap() {
    let ks: Vec<SigningKey> = (0..4).map(det_key).collect();
    let vs = vset(&ks);
    let offender = id_of(&ks[3]);

    // ---- (a) fail-closed: a single vote repeated is NOT equivocation ----
    // (Same ledger function the transition calls; nothing burns, and through
    // the block path the reporter's transaction reverts.)
    let engine = bonded_engine(&ks).await;
    {
        let mut l = engine.staking_write().await;
        let a = Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some([0x11u8; 32]));
        let non_pair = EquivocationEvidence::new(offender, a.clone(), a);
        assert_eq!(
            l.slash_equivocation_verified(&non_pair).unwrap(),
            0,
            "a repeated single vote must burn nothing"
        );
    }
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);
    let pool_before = pool_of(&engine).await;
    let root = engine.get_state_root().await;
    let repeated = {
        let a = Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some([0x11u8; 32]));
        EquivocationEvidence::new(offender, a.clone(), a)
    };
    let mut bad = mk_block(
        &ks[0],
        1,
        [0u8; 32],
        root,
        vec![report_tx(&ks[0], 0, repeated)],
    );
    let bad_hash = bad.compute_hash();
    bad.precommit_qc = Some(certify_full(&mut rt, &ks, 1, bad_hash));
    rt.blocks.insert(bad_hash, bad);
    assert_eq!(rt.try_finalize().await, Some(bad_hash));
    assert_eq!(
        rt.applied_statuses,
        vec![false],
        "invalid report tx must revert (reporter wastes gas)"
    );
    let l = engine.staking_read().await;
    assert_eq!(l.validators[&offender].self_bond, MIN_VALIDATOR_BOND);
    assert_eq!(l.validators[&offender].total_slashed, 0);
    assert_eq!(l.total_burned, 0, "nothing burns on invalid evidence");
    drop(l);
    assert_eq!(pool_of(&engine).await, pool_before, "pool untouched");

    // ---- (b) the feed turns gossip observations into canonical envelopes ----
    // without touching stake (the slash fires only when an envelope lands in a
    // decided block — the function block production calls).
    let engine2 = bonded_engine(&ks).await;
    let mut rt2 = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine2.clone(), 1);
    assert!(
        rt2.equivocation_feed_evidence().is_empty(),
        "no observations => empty feed"
    );
    let burned_before = engine2.staking_read().await.total_burned;
    rt2
        .on_prevote(Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some([0xABu8; 32])))
        .unwrap();
    rt2
        .on_prevote(Vote::sign(
            &ks[3],
            1,
            0,
            VoteKind::Prevote,
            Some([0xCDu8; 32]),
        ))
        .unwrap();
    assert_eq!(rt2.hc.equivocations().len(), 1, "evidence must be observed");
    let feed = rt2.equivocation_feed_evidence();
    assert_eq!(feed.len(), 1, "one offense => one envelope");
    assert_eq!(feed[0].voter, offender);
    assert_ne!(feed[0].vote_a.block_hash, feed[0].vote_b.block_hash);
    assert!(feed[0].vote_a.verify() && feed[0].vote_b.verify());
    let l2 = engine2.staking_read().await;
    assert_eq!(l2.total_burned, burned_before);
    assert_eq!(l2.validators[&offender].total_slashed, 0);
    drop(l2);
    // The feed envelope is slashable bytes: the same ledger verifier the
    // transition calls burns 5% on it (unit level, fresh ledger).
    let engine3 = bonded_engine(&ks).await;
    let burned = engine3
        .staking_write()
        .await
        .slash_equivocation_verified(&feed[0])
        .expect("feed envelope must verify");
    assert_eq!(
        burned,
        expected_equivocation_burn(),
        "the feed envelope must carry a slashable offense"
    );

    // ---- (c) REPORTED GAP (explicit, not a fake green) ----
    // The sim harness injects a double-vote dignifiedly at gossip level
    // (Byzantine::DoublePrevote: a genuine second signed vote, recorded in
    // ClusterReport.equivocations — see test 1a), but it has no primitive for
    // packaging observed evidence into a block-carried SysCallReportEquivocation
    // envelope and finalizing it in-sim. The burn leg is therefore pinned at
    // the evidence-verification unit level through apply_block_transition (the
    // same function production finalize runs), not in the sim run.
    println!(
        "[slash][REPORTED-GAP] sim harness cannot express block-carried \
         SysCallReportEquivocation injection in-sim (gossip-level DoublePrevote \
         only); slash burn pinned at unit level via apply_block_transition. \
         feed envelopes verified slashable above (burned={burned})."
    );
}
