//! WIRED PATH: equivocation (double-sign) slashing at 5%, from block-carried
//! evidence only.
//!
//! The carrier is the block BODY: `OpCode::SysCallReportEquivocation`
//! payloads in the decided block's own transactions, each envelope holding
//! BOTH conflicting votes fully, so every node re-verifies from the bytes
//! alone (no gossip input to any state transition). At apply
//! (`InMemoryStateEngine::apply_block_transition`, step 5b) each envelope is
//! re-verified fail-closed, canonicalized by offense key, burned at 5% of
//! total stake (self-bond first) via
//! `StakingLedger::slash_equivocation_verified`, pool-debited at the call
//! site, and deduped per offense (`offender ‖ height ‖ round ‖ kind ‖
//! conflicting hashes`) — the same offense slashes exactly once per chain.
//!
//! Fail-closed rule throughout: when in doubt the chain refuses to slash and
//! logs loudly (slash-wrongly is worse than slash-rarely).
//!
//! These tests pin the wired path (and nothing else):
//!  1. a double-sign burns EXACTLY 5% (bond, pool and counters to the nano);
//!  2. a repeated offense (in-block duplicate AND later-block re-inclusion)
//!     burns exactly once;
//!  3. a non-pair (single vote repeated) burns nothing and reverts the
//!     reporter's transaction;
//!  4. two engines applying the same block by different routes (finalize vs
//!     adopt) land on the same root with the same burn;
//!  5. the runtime feed converts local gossip observations into canonical
//!     envelopes without touching state.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::{
    EquivocationEvidence, QuorumCertificate, ValidatorId, ValidatorSet, VoteKind,
};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{EQUIVOCATION_SLASH_BPS, MIN_VALIDATOR_BOND, STAKING_POOL};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

/// Genesis balance per validator account (far above the bonded stake, so fees
/// never bind).
const BAL: u64 = 10_000 * 1_000_000_000;
/// Realistic block timestamp base - never 0.
const TS: u64 = 1_760_000_000;
/// Declared gas for a report transaction (far above the ~3k the envelope
/// costs; the declared-fee rule charges it to the reporter).
const REPORT_GAS: u64 = 500_000;

/// Genesis self-bond every validator carries (bare MIN via `bond_genesis`),
/// so the exact 5% burn is `MIN * 500 / 10_000` with no remainder.
fn expected_burn() -> u64 {
    (MIN_VALIDATOR_BOND as u128 * EQUIVOCATION_SLASH_BPS as u128 / 10_000u128) as u64
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn id_of(k: &SigningKey) -> ValidatorId {
    k.verifying_key().to_bytes()
}

/// A genuine conflicting pair by `offender` at consensus height 1.
fn double_sign(
    offender: &SigningKey,
    fk: &stellereum::post_quantum::FalconKeypair,
) -> EquivocationEvidence {
    let a = falcon_votes::fvote(offender, fk, 1, 0, VoteKind::Prevote, Some([0x11u8; 32]));
    let b = falcon_votes::fvote(offender, fk, 1, 0, VoteKind::Prevote, Some([0x22u8; 32]));
    assert!(a.verify() && b.verify(), "precondition: both votes verify");
    EquivocationEvidence::new(id_of(offender), a, b)
}

/// A non-pair: the SAME vote twice (a single vote repeated is not
/// equivocation and must burn nothing).
fn single_vote_repeated(
    offender: &SigningKey,
    fk: &stellereum::post_quantum::FalconKeypair,
) -> EquivocationEvidence {
    let a = falcon_votes::fvote(offender, fk, 1, 0, VoteKind::Prevote, Some([0x11u8; 32]));
    EquivocationEvidence::new(id_of(offender), a.clone(), a)
}

fn pq_id_of(fk: &stellereum::post_quantum::FalconKeypair) -> [u8; 32] {
    stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        &fk.public_key,
        &stellereum::post_quantum::DEFAULT_SALT,
    )
}

fn report_tx(
    reporter_fk: &stellereum::post_quantum::FalconKeypair,
    nonce: u64,
    evidence: EquivocationEvidence,
) -> Transaction {
    let payload = vec![OpCode::SysCallReportEquivocation {
        evidence: Box::new(evidence),
    }];
    let from = pq_id_of(reporter_fk);
    let probe = Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        reporter_fk.public_key.clone(),
        vec![0u8; stellereum::post_quantum::FALCON512_SIG_LEN],
        from,
        0,
        REPORT_GAS,
        nonce,
        1,
        1,
        payload.clone(),
        &stellereum::post_quantum::DEFAULT_SALT,
    );
    let sig = reporter_fk.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        reporter_fk.public_key.clone(),
        sig,
        from,
        0,
        REPORT_GAS,
        nonce,
        1,
        1,
        payload,
        &stellereum::post_quantum::DEFAULT_SALT,
    )
}

fn mk_block(
    proposer: &SigningKey,
    proposer_fk: &stellereum::post_quantum::FalconKeypair,
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
    blk.sign_block_with_falcon(proposer, proposer_fk);
    blk
}

/// Two engines with byte-identical pre-state: genesis validators plus an
/// identically funded staking pool (so the pool debit is exact and
/// comparable on both) and any extra PQ reporter accounts.
async fn mirrored_engines(
    vs: &ValidatorSet,
    extra_funded: &[[u8; 32]],
    n: usize,
) -> Vec<Arc<InMemoryStateEngine>> {
    let mut out = Vec::new();
    for _ in 0..n {
        let e = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&e, vs, BAL).await;
        e.credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("pool credit");
        for addr in extra_funded {
            e.credit_native(addr, BAL)
                .await
                .expect("extra account credit");
        }
        out.push(e);
    }
    let root0 = out[0].get_state_root().await;
    for (i, e) in out.iter().enumerate() {
        assert_eq!(
            e.get_state_root().await,
            root0,
            "precondition: engine {i} must start byte-identical to engine 0"
        );
    }
    out
}

/// Drive a FULL (4-of-4) precommit quorum for `bh` through the runtime, so the
/// downtime leg of the transition burns exactly 0 and any burn observed is
/// the equivocation leg alone. Returns the certificate the block must carry.
fn certify_full(
    rt: &mut ValidatorRuntime,
    ks: &[SigningKey],
    fks: &[stellereum::post_quantum::FalconKeypair],
    height: u64,
    bh: [u8; 32],
) -> QuorumCertificate {
    for (i, k) in ks.iter().enumerate() {
        rt.on_prevote(falcon_votes::fvote(
            k,
            &fks[i],
            height,
            0,
            VoteKind::Prevote,
            Some(bh),
        ))
        .expect("prevote accepted");
        rt.on_precommit(falcon_votes::fvote(
            k,
            &fks[i],
            height,
            0,
            VoteKind::Precommit,
            Some(bh),
        ))
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

// ===========================================================================
// 1. A double-sign burns EXACTLY 5%: bond, pool and counters to the nano
// ===========================================================================

#[tokio::test]
async fn double_sign_slashed_exactly_five_percent() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vs = vset(&ks);
    let offender = id_of(&ks[3]);
    let engines = mirrored_engines(&vs, &[pq_id_of(&fks[0])], 1).await;
    let engine = engines[0].clone();
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);

    // Genesis bond is bare MIN with no delegators, so 5% of total == 5% of
    // self-bond, computed with no remainder.
    let burn = expected_burn();
    assert_eq!(burn, MIN_VALIDATOR_BOND / 20, "5% must be exact");
    assert_eq!(
        engine.staking_read().await.validators[&offender].self_bond,
        MIN_VALIDATOR_BOND,
        "precondition: offender bonded at bare MIN"
    );
    let pool_before = pool_of(&engine).await;
    let burned_before = engine.staking_read().await.total_burned;

    let evidence = double_sign(&ks[3], &fks[3]);
    let root = engine.get_state_root().await;
    let mut blk = mk_block(
        &ks[0],
        &fks[0],
        1,
        [0u8; 32],
        root,
        vec![report_tx(&fks[0], 0, evidence)],
    );
    let bh = blk.compute_hash();
    blk.precommit_qc = Some(certify_full(&mut rt, &ks, &fks, 1, bh));
    rt.blocks.insert(bh, blk.clone());
    assert_eq!(rt.try_finalize().await, Some(bh), "must finalize height 1");

    // The report transaction itself succeeds (valid evidence is accepted).
    assert_eq!(rt.applied_statuses, vec![true], "valid report tx succeeds");
    // Exactly 5% left the bond...
    let l = engine.staking_read().await;
    assert_eq!(
        l.validators[&offender].self_bond,
        MIN_VALIDATOR_BOND - burn,
        "bond must fall by exactly 5%"
    );
    // ...was counted on the offender...
    assert_eq!(
        l.validators[&offender].total_slashed, burn,
        "offender counter must equal the burn"
    );
    // ...was counted globally (and ONLY this burn: the full QC means the
    // downtime leg burned 0)...
    assert_eq!(
        l.total_burned - burned_before,
        burn,
        "global burn delta must equal exactly one 5% slash"
    );
    drop(l);
    // ...and came out of the staking pool, nano for nano.
    assert_eq!(
        pool_before - pool_of(&engine).await,
        burn,
        "STAKING_POOL debit must equal the burn exactly"
    );
}

// ===========================================================================
// 2. A repeat offense slashes once: in-block duplicate AND later re-inclusion
// ===========================================================================

#[tokio::test]
async fn repeat_offense_slashed_once() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vs = vset(&ks);
    let offender = id_of(&ks[3]);
    let engines = mirrored_engines(&vs, &[pq_id_of(&fks[0])], 1).await;
    let engine = engines[0].clone();
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);
    let burn = expected_burn();

    // Block 1 carries the SAME offense twice (two reporter transactions).
    // Canonicalization drops the in-block duplicate: one 5% burn, not two.
    let evidence = double_sign(&ks[3], &fks[3]);
    let root = engine.get_state_root().await;
    let mut blk1 = mk_block(
        &ks[0],
        &fks[0],
        1,
        [0u8; 32],
        root,
        vec![
            report_tx(&fks[0], 0, evidence.clone()),
            report_tx(&fks[0], 1, evidence.clone()),
        ],
    );
    let bh1 = blk1.compute_hash();
    blk1.precommit_qc = Some(certify_full(&mut rt, &ks, &fks, 1, bh1));
    rt.blocks.insert(bh1, blk1.clone());
    assert_eq!(rt.try_finalize().await, Some(bh1), "must finalize height 1");
    // Both report transactions are valid evidence, so both succeed — but the
    // offense burns once.
    assert_eq!(rt.applied_statuses, vec![true, true]);
    let l = engine.staking_read().await;
    assert_eq!(l.validators[&offender].self_bond, MIN_VALIDATOR_BOND - burn);
    assert_eq!(
        l.total_burned, burn,
        "in-block duplicate must not double-burn"
    );
    assert_eq!(l.total_burned, burn);
    drop(l);
    let pool_after_1 = pool_of(&engine).await;

    // Block 2 re-includes the SAME offense. The ledger's per-offense dedup
    // (offender ‖ height ‖ round ‖ kind ‖ conflicting hashes) refuses it: the
    // transaction still succeeds (valid envelope), the burn is 0.
    //
    // Note: the block-1 slash pushed the offender below MIN, so it is out of
    // the derived consensus set now; the height-2 quorum is driven by the
    // three survivors only.
    let survivors = &ks[0..3];
    let root2 = engine.get_state_root().await;
    let mut blk2 = mk_block(
        &ks[0],
        &fks[0],
        2,
        bh1,
        root2,
        vec![report_tx(&fks[0], 2, evidence)],
    );
    let bh2 = blk2.compute_hash();
    for (i, k) in survivors.iter().enumerate() {
        rt.on_prevote(falcon_votes::fvote(
            k,
            &fks[i],
            2,
            0,
            VoteKind::Prevote,
            Some(bh2),
        ))
        .expect("prevote accepted");
        rt.on_precommit(falcon_votes::fvote(
            k,
            &fks[i],
            2,
            0,
            VoteKind::Precommit,
            Some(bh2),
        ))
        .expect("precommit accepted");
    }
    assert_eq!(
        rt.hc.try_precommit_quorum(),
        Some(bh2),
        "survivors must quorum"
    );
    blk2.precommit_qc = rt.hc.precommit_qc.clone();
    rt.blocks.insert(bh2, blk2.clone());
    assert_eq!(rt.try_finalize().await, Some(bh2), "must finalize height 2");

    assert_eq!(
        rt.applied_statuses,
        vec![true],
        "re-included report still executes"
    );
    let l = engine.staking_read().await;
    assert_eq!(
        l.validators[&offender].self_bond,
        MIN_VALIDATOR_BOND - burn,
        "re-inclusion must not burn again"
    );
    assert_eq!(
        l.total_burned, burn,
        "global burn must not move on re-inclusion"
    );
    drop(l);
    assert_eq!(
        pool_of(&engine).await,
        pool_after_1,
        "pool must not move on re-inclusion"
    );
}

// ===========================================================================
// 3. A single vote repeated is not equivocation: nothing burns, tx reverts
// ===========================================================================

#[tokio::test]
async fn single_vote_repeated_burns_nothing() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vs = vset(&ks);
    let offender = id_of(&ks[3]);
    let engines = mirrored_engines(&vs, &[pq_id_of(&fks[0])], 1).await;
    let engine = engines[0].clone();
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);

    let pool_before = pool_of(&engine).await;
    let root = engine.get_state_root().await;
    let mut blk = mk_block(
        &ks[0],
        &fks[0],
        1,
        [0u8; 32],
        root,
        vec![report_tx(&fks[0], 0, single_vote_repeated(&ks[3], &fks[3]))],
    );
    let bh = blk.compute_hash();
    blk.precommit_qc = Some(certify_full(&mut rt, &ks, &fks, 1, bh));
    rt.blocks.insert(bh, blk.clone());
    assert_eq!(rt.try_finalize().await, Some(bh), "must finalize height 1");

    // Fail-closed: the envelope does not verify, so the reporter's
    // transaction reverts (reporter wastes gas) and the scan skips it.
    assert_eq!(
        rt.applied_statuses,
        vec![false],
        "invalid report tx must revert"
    );
    let l = engine.staking_read().await;
    assert_eq!(
        l.validators[&offender].self_bond, MIN_VALIDATOR_BOND,
        "bond untouched"
    );
    assert_eq!(l.validators[&offender].total_slashed, 0);
    assert_eq!(l.total_burned, 0, "nothing burned");
    drop(l);
    assert_eq!(pool_of(&engine).await, pool_before, "pool untouched");
}

// ===========================================================================
// 4. Two engines, same block, different routes: same root, same burn
// ===========================================================================

#[tokio::test]
async fn two_engines_same_block_same_root() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vs = vset(&ks);
    let offender = id_of(&ks[3]);
    let engines = mirrored_engines(&vs, &[pq_id_of(&fks[0])], 2).await;
    let (engine_a, engine_b) = (engines[0].clone(), engines[1].clone());
    let mut a = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine_a.clone(), 1);
    let mut b = ValidatorRuntime::new(ks[1].clone(), vs.clone(), engine_b.clone(), 1);
    let burn = expected_burn();

    let evidence = double_sign(&ks[3], &fks[3]);
    // The adopt route checks the block proposer against the schedule
    // (`proposer_for`), so build the block under the scheduled key —
    // otherwise adoption fails closed on proposer mismatch while local
    // finalize (which imposes no schedule check) would still pass.
    let scheduled = vs.proposer_for(1, 0).expect("non-empty set has a proposer");
    let pi = ks
        .iter()
        .position(|k| id_of(k) == scheduled)
        .expect("scheduled proposer is one of ks");
    let root = engine_a.get_state_root().await;
    let mut blk = mk_block(
        &ks[pi],
        &fks[pi],
        1,
        [0u8; 32],
        root,
        vec![report_tx(&fks[0], 0, evidence)],
    );
    let bh = blk.compute_hash();
    let qc = certify_full(&mut a, &ks, &fks, 1, bh);
    blk.precommit_qc = Some(qc.clone());

    // Route A: local finalize (this node ALSO holds the gossip evidence, but
    // the transition must not read it).
    a.blocks.insert(bh, blk.clone());
    assert_eq!(a.try_finalize().await, Some(bh));
    // Route B: adopt the committed block + certificate from a peer.
    assert_eq!(b.adopt_committed(1, blk.clone(), qc).await, Ok(bh));

    let ra = a.state_root().await;
    let rb = b.state_root().await;
    assert_eq!(ra, rb, "same block => same root on every route");
    for (name, e) in [("finalize", &engine_a), ("adopt", &engine_b)] {
        let l = e.staking_read().await;
        assert_eq!(
            l.validators[&offender].self_bond,
            MIN_VALIDATOR_BOND - burn,
            "{name}: bond must fall by exactly 5%"
        );
        assert_eq!(l.total_burned, burn, "{name}: exactly one 5% burn");
        drop(l);
    }
    assert_eq!(
        pool_of(&engine_a).await,
        pool_of(&engine_b).await,
        "pool debits must agree across routes"
    );
}

// ===========================================================================
// 5. The feed turns local gossip observations into canonical envelopes
// ===========================================================================

#[tokio::test]
async fn feed_converts_local_observations_without_touching_state() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vs = vset(&ks);
    let engines = mirrored_engines(&vs, &[], 1).await;
    let engine = engines[0].clone();
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine.clone(), 1);

    assert!(
        rt.equivocation_feed_evidence().is_empty(),
        "no observations => empty feed"
    );
    let burned_before = engine.staking_read().await.total_burned;

    // Observe a double-vote over gossip (first vote counts for quorum, the
    // conflicting second is recorded as evidence).
    let bh = [0xABu8; 32];
    rt.on_prevote(falcon_votes::fvote(
        &ks[3],
        &fks[3],
        1,
        0,
        VoteKind::Prevote,
        Some(bh),
    ))
    .unwrap();
    rt.on_prevote(falcon_votes::fvote(
        &ks[3],
        &fks[3],
        1,
        0,
        VoteKind::Prevote,
        Some([0xCDu8; 32]),
    ))
    .unwrap();
    assert_eq!(rt.hc.equivocations().len(), 1, "evidence must be observed");

    let feed = rt.equivocation_feed_evidence();
    assert_eq!(feed.len(), 1, "one offense => one envelope");
    assert_eq!(feed[0].voter, id_of(&ks[3]));
    assert_ne!(feed[0].vote_a.block_hash, feed[0].vote_b.block_hash);
    assert!(feed[0].vote_a.verify() && feed[0].vote_b.verify());

    // The feed is read-only: observing votes and building envelopes moves no
    // stake (the slash fires only when an envelope lands in a decided block).
    let l = engine.staking_read().await;
    assert_eq!(l.total_burned, burned_before);
    assert_eq!(l.validators[&id_of(&ks[3])].total_slashed, 0);
}
