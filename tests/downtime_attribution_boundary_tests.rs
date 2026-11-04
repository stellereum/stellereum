//! # Downtime attribution at the activation boundary (W10.5).
//!
//! REVIEW DIMENSIONS 3 + 4 (enterprise-testnet consensus review):
//!
//! Every quorum reader must use the validator set IN FORCE AT THE
//! CERTIFICATE'S HEIGHT — never the live set. The proposal gate
//! (`ValidatorRuntime::check_last_qc_evidence`), the adopt path
//! (`adopt_committed`), the sync walk (`validate_sync_chain_with_sets`),
//! the light-client anchor (`verify_synced_blocks_against_anchor_with_sets`)
//! and the replay path (`replay_historical_block`) all do. The ONE reader
//! that did not was the downtime-slash attribution inside
//! `InMemoryStateEngine::apply_block_transition`: it verified the `last_qc`
//! evidence (height H-1) against the ledger-derived set read AFTER the
//! transition, i.e. after this block's own bond / unbond / slash
//! transactions, rewards and unbonding maturity had already mutated the
//! ledger.
//!
//! CONSEQUENCE (deterministic, consensus-safe, economically wrong): a bond
//! in block H raised the quorum out from under the genuine H-1 QC, so the
//! slash was SKIPPED on every node identically; an unbond in block H
//! removed a member from the eligible list, so the miss it earned was
//! forgiven on every node identically. No fork — every applier derived the
//! same wrong answer — but the wrong answer.
//!
//! FIX: the transition snapshots the staking-derived set BEFORE executing
//! anything and attributes through
//! [`InMemoryStateEngine::apply_downtime_slash_with_set`]. The snapshot is
//! a pure function of the engine pre-state, so local finalize, adopt, walk,
//! replay and reorg re-apply all derive the SAME set (unlike a
//! runtime-history oracle, which differs between nodes with different
//! history depths and would fork).
//!
//! The two tests below pin the boundary:
//!
//! * `bond_in_block_does_not_raise_the_quorum_under_parent_evidence` —
//!   transition level: a bond transaction inside block H rotates the set
//!   mid-transition, and the H-1 evidence must still be judged by the
//!   pre-transition (4-member) set. Fails on the old code (miss stays 0,
//!   slash skipped), passes on the new code (miss becomes 1).
//! * `explicit_set_oracle_differs_from_the_live_oracle_at_a_rotation` —
//!   direct oracle pin: the same genuine QC verifies under the pre-rotation
//!   set and fails under the post-rotation set, and each oracle attributes
//!   accordingly.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

const BOND: u64 = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;
const TS: u64 = 1_760_000_000;

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Four bonded validators with funded accounts, plus a funded staking pool
/// (the slash debit is real coins).
async fn four_member_engine(keys: &[SigningKey]) -> InMemoryStateEngine {
    assert_eq!(keys.len(), 4);
    let engine = InMemoryStateEngine::new();
    for k in keys {
        engine
            .credit_native(&id_of(k), BOND * 4)
            .await
            .expect("fund member");
        engine
            .staking_write()
            .await
            .bond(id_of(k), BOND, 0)
            .expect("bond member");
    }
    engine
        .credit_native(&stellereum::staking::STAKING_POOL, BOND * 10)
        .await
        .expect("fund pool");
    assert_eq!(engine.staking_read().await.to_validator_set().len(), 4);
    engine
}

/// A genuine precommit QC for `height` over `hash`, signed by `signers`.
fn genuine_qc(
    keys: &[SigningKey],
    signers: &[usize],
    height: u64,
    hash: [u8; 32],
) -> QuorumCertificate {
    let signatures = signers
        .iter()
        .map(|&i| {
            let v = Vote::sign(&keys[i], height, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures,
    }
}

fn block_h2_with_bond(
    proposer: [u8; 32],
    bond_tx: Transaction,
    last_qc: QuorumCertificate,
) -> Block {
    let txs = vec![bond_tx];
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 2,
        prev_hash: [0x11; 32],
        state_root: [0u8; 32],
        transactions: txs.clone(),
        cross_shard_out: vec![],
        timestamp: TS,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: Some(last_qc),
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&txs),
        epoch_key_commitment: [0u8; 32],
    }
}

/// Transition level: a bond inside block H must not move the quorum the H-1
/// evidence is judged by.
#[tokio::test]
async fn bond_in_block_does_not_raise_the_quorum_under_parent_evidence() {
    let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let engine = four_member_engine(&keys).await;
    let (a, b, c, d) = (
        id_of(&keys[0]),
        id_of(&keys[1]),
        id_of(&keys[2]),
        id_of(&keys[3]),
    );

    // The H-1 evidence: A, B, C signed; D missed. Genuine quorum of the
    // 4-member set (3 of 4 by headcount AND by power: 3*B >= floor(8*B/3)+1).
    let evidence_hash = [0xAA; 32];
    let qc = genuine_qc(&keys, &[0, 1, 2], 1, evidence_hash);
    assert!(
        qc.verify(&engine.staking_read().await.to_validator_set()),
        "precondition: the evidence must verify under the pre-transition set"
    );

    // A newcomer E bonds INSIDE block H=2. After the transition the set has
    // 5 members and the same 3 signatures are a sub-quorum — but the
    // evidence is for H-1, when the set still had 4.
    let newcomer = SigningKey::generate(&mut OsRng);
    let newcomer_id = id_of(&newcomer);
    engine
        .credit_native(&newcomer_id, BOND * 4)
        .await
        .expect("fund newcomer");
    let bond_tx = Transaction::sign_with_payload(
        &newcomer,
        newcomer_id,
        0,
        500_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallStake {
            validator: newcomer_id,
            amount: BOND,
        }],
    );

    let block = block_h2_with_bond(a, bond_tx, qc);
    engine.apply_block_transition(&block, 0).await;

    // The transition really did rotate the set mid-flight: without this the
    // test below is vacuous (no rotation, no boundary).
    let post = engine.staking_read().await.to_validator_set();
    assert_eq!(
        post.len(),
        5,
        "the bond transaction must have joined the set"
    );
    assert!(
        !genuine_qc(&keys, &[0, 1, 2], 1, evidence_hash).verify(&post),
        "precondition: the same signatures must be a sub-quorum of the post-transition set"
    );

    // …and yet D earned its miss: the evidence was judged by the
    // pre-transition set, under which the QC verifies and D is eligible.
    // (Old code: verify failed against the 5-set, attribution skipped,
    // D.missed stayed 0.)
    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.validators[&d].missed, 1,
        "D missed the H-1 QC and was a member at H-1: the miss must be recorded"
    );
    assert_eq!(
        ledger.validators[&a].missed, 0,
        "signers must not accrue misses"
    );
    assert_eq!(
        ledger.validators[&b].missed, 0,
        "signers must not accrue misses"
    );
    assert_eq!(
        ledger.validators[&c].missed, 0,
        "signers must not accrue misses"
    );
    assert_eq!(
        ledger.validators[&newcomer_id].missed, 0,
        "the newcomer was not a member at H-1 and must not accrue a miss for it"
    );
    let _ = (b, c);
}

/// Direct oracle pin: the explicit-set oracle and the live-set oracle give
/// different (each self-consistent) answers across a rotation, and the
/// explicit one is the boundary-correct one.
#[tokio::test]
async fn explicit_set_oracle_differs_from_the_live_oracle_at_a_rotation() {
    let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let (a, _b, _c, d) = (
        id_of(&keys[0]),
        id_of(&keys[1]),
        id_of(&keys[2]),
        id_of(&keys[3]),
    );
    let evidence_hash = [0xBB; 32];
    let qc = genuine_qc(&keys, &[0, 1, 2], 7, evidence_hash);

    // Half 1: the pre-rotation oracle attributes.
    let engine1 = four_member_engine(&keys).await;
    let pre_set = engine1.staking_read().await.to_validator_set();
    assert!(qc.verify(&pre_set));
    let burned = engine1
        .apply_downtime_slash_with_set(7, Some(&qc), &pre_set)
        .await;
    assert_eq!(burned, 0, "one miss is below the slash threshold");
    assert_eq!(
        engine1.staking_read().await.validators[&d].missed,
        1,
        "the pre-rotation oracle must record D's miss"
    );

    // Half 2: after a fifth member bonds, the LIVE oracle skips the very
    // same evidence (3 of 5 is a sub-quorum) — the old transition behavior.
    let engine2 = four_member_engine(&keys).await;
    let newcomer = SigningKey::generate(&mut OsRng);
    let newcomer_id = id_of(&newcomer);
    engine2
        .credit_native(&newcomer_id, BOND * 4)
        .await
        .expect("fund newcomer");
    engine2
        .staking_write()
        .await
        .bond(newcomer_id, BOND, 0)
        .expect("bond newcomer");
    let live5 = engine2.staking_read().await.to_validator_set();
    assert_eq!(live5.len(), 5);
    assert!(
        !qc.verify(&live5),
        "precondition: 3 signatures must not verify under the 5-set"
    );
    let burned = engine2.apply_downtime_slash(7, Some(&qc)).await;
    assert_eq!(burned, 0);
    assert_eq!(
        engine2.staking_read().await.validators[&d].missed,
        0,
        "the live oracle skips post-rotation evidence it cannot verify"
    );
    let _ = a;
}
