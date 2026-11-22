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
use stellereum::consensus::{QuorumCertificate, ValidatorSet, VoteKind, VoteSet};
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::pq_registry::{derive_validator_id, pq_voting_key_pop_preimage};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, RegisterValidatorPayload};
use stellereum::zkml::effective_chain_id;

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

const BOND: u64 = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;
const TS: u64 = 1_760_000_000;

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// FULL-PQ sender for the adversarial fixtures: implicit Falcon-512, key
/// registered globally (no activation surcharge). Returns the derived address.
fn pq_identity(seed: u8) -> ([u8; 32], FalconKeypair) {
    let fk = FalconKeypair::generate_from_seed(seed);
    let addr = derive_pq_address(PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(addr, PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (addr, fk)
}

/// FULL-PQ replacement for `Transaction::sign_with_payload` in fixtures,
/// registering a new validator under Ruleset v7 `SysCallRegisterValidator`.
fn pq_register_validator_tx(
    cold_fk: &FalconKeypair,
    cold_addr: [u8; 32],
    hot_fk: &FalconKeypair,
    amount: u64,
    gas_limit: u64,
) -> (Transaction, [u8; 32]) {
    let chain_id = effective_chain_id();
    let validator_id = derive_validator_id(chain_id, &cold_addr, hot_fk.public_key());
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &validator_id,
        &cold_addr,
        0,
        PqScheme::Falcon512,
        hot_fk.public_key(),
    );
    let voting_pop = hot_fk.sign(&pop_msg);
    let mut tx = Transaction {
        from: cold_addr,
        to: validator_id,
        amount: 0,
        gas_limit,
        nonce: 0,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: Vec::new(),
        payload: vec![OpCode::SysCallRegisterValidator(Box::new(
            RegisterValidatorPayload {
                amount,
                commission_bps: 0,
                withdrawal_address: cold_addr,
                voting_scheme: PqScheme::Falcon512.id(),
                voting_pubkey: hot_fk.public_key().to_vec(),
                voting_pop,
            },
        ))],
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = cold_fk.sign(&msg);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    (tx, validator_id)
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

/// A genuine precommit QC for `height` over `hash`, signed by `signers`,
/// compiled by the production committee path and bound to the block's real
/// parent (the adopt/attribution paths check the binding).
fn genuine_qc(
    keys: &[SigningKey],
    fks: &[stellereum::post_quantum::FalconKeypair],
    signers: &[usize],
    height: u64,
    hash: [u8; 32],
    parent: &[u8; 32],
) -> QuorumCertificate {
    let vs = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut set = VoteSet::new();
    for &i in signers {
        set.add(
            falcon_votes::fvote(
                &keys[i],
                &fks[i],
                height,
                0,
                VoteKind::Precommit,
                Some(hash),
            ),
            &vs,
            height,
            0,
            VoteKind::Precommit,
        )
        .expect("genuine vote admits");
    }
    set.certificate(Some(hash), &vs, parent)
        .expect("3-of-4 reaches quorum")
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
        cnvrf_v3: None,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&txs),
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }
}

/// Transition level: a bond inside block H must not move the quorum the H-1
/// evidence is judged by.
#[tokio::test]
async fn bond_in_block_does_not_raise_the_quorum_under_parent_evidence() {
    let (keys, fks) = falcon_votes::falcon_set(4);
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
    // Parent binds to the block that will carry this QC as `last_qc`.
    let qc = genuine_qc(&keys, &fks, &[0, 1, 2], 1, evidence_hash, &[0x11; 32]);
    assert!(
        qc.verify(&engine.staking_read().await.to_validator_set()),
        "precondition: the evidence must verify under the pre-transition set"
    );

    // A newcomer E bonds INSIDE block H=2. After the transition the set has
    // 5 members and the same 3 signatures are a sub-quorum — but the
    // evidence is for H-1, when the set still had 4.
    let (newcomer_cold_addr, newcomer_cold_fk) = pq_identity(0xE1);
    let (_, newcomer_hot_fk) = pq_identity(0xE3);
    engine
        .credit_native(&newcomer_cold_addr, BOND * 4)
        .await
        .expect("fund newcomer");
    let (bond_tx, newcomer_id) = pq_register_validator_tx(
        &newcomer_cold_fk,
        newcomer_cold_addr,
        &newcomer_hot_fk,
        BOND,
        500_000,
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
        !genuine_qc(&keys, &fks, &[0, 1, 2], 1, evidence_hash, &[0x11; 32]).verify(&post),
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
    let (keys, fks) = falcon_votes::falcon_set(4);
    let (a, _b, _c, d) = (
        id_of(&keys[0]),
        id_of(&keys[1]),
        id_of(&keys[2]),
        id_of(&keys[3]),
    );
    let evidence_hash = [0xBB; 32];
    // Fixture-only parent: this evidence is judged directly by the oracle,
    // never carried in a block, so no chain parent exists to bind.
    let qc = genuine_qc(&keys, &fks, &[0, 1, 2], 7, evidence_hash, &[0u8; 32]);

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
    let (newcomer_id, _newcomer_fk) = pq_identity(0xE2);
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
