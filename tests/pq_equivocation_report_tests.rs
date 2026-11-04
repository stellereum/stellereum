//! THE PQ EQUIVOCATION REPORT PATH: a post-quantum double-sign must be
//! PUNISHABLE on the live network.
//!
//! `StakingLedger::slash_pq_equivocation` has existed (and been tested) for a
//! long time, but nothing could reach it: there was no opcode to submit the
//! evidence, so a PQ double-sign was unpunishable on chain. The carrier is
//! now `OpCode::SysCallReportPqEquivocation`, whose evidence rides inside
//! the block body (the tx hash commits the payload, the block hash commits
//! the tx), so every node that applies the block reaches the SAME verdict
//! from the SAME bytes.
//!
//! What these tests pin:
//!  1. a VALID evidence slashes the accused validator by exactly 5% and the
//!     burned coins LEAVE the staking pool (the pool and the ledger must
//!     never drift apart by the burnt amount);
//!  2. an INVALID evidence (forged signature, same target, unknown voter) is
//!     refused fail-closed - the SLASH moves nothing: no coin is burned, the
//!     pool does not move and the accused validator keeps its bond. The
//!     reporter's own transaction is refused, and (SEC-07) that refusal is
//!     attributable, so the reporter pays the failure fee and burns its nonce
//!     - the STATE ROOT therefore moves by exactly that fee debit;
//!  3. the same offense burns exactly once per chain (the per-offense dedup
//!     key), even when the evidence is re-submitted in a later transaction;
//!  4. the state root moves (a slash is consensus state).

use ed25519_dalek::{Signer, SigningKey};
use stellereum::consensus::VoteKind;
use stellereum::sharding::Transaction;
use stellereum::staking::{CompactPqEquivocationEvidence, EQUIVOCATION_SLASH_BPS, STAKING_POOL};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

/// 1 STELL in nano.
const NANO: u64 = 1_000_000_000;
/// Block timestamp (never a wall clock).
const TS: u64 = 1_760_000_000;
/// Declared gas for the report transaction (far above the ~3k the envelope
/// costs).
const REPORT_GAS: u64 = 500_000;
/// The reporter's balance (it pays the gas).
const BAL: u64 = 10_000 * NANO;
/// The accused validator's self-bond. Above `MIN + buffer`, so `bond`
/// accepts it (the floor is 1100 STELL).
const BOND: u64 = 2_000 * NANO;

/// The exact 5% burn of `BOND` (self-bond only, no delegators).
fn expected_burn() -> u64 {
    (BOND as u128 * EQUIVOCATION_SLASH_BPS as u128 / 10_000u128) as u64
}

/// A genuine PQ double-sign: two conflicting votes at the same
/// (height, round, kind), both signed by the accused validator.
fn double_sign(offender: &SigningKey) -> CompactPqEquivocationEvidence {
    let height = 1u64;
    let round = 0u32;
    let kind = VoteKind::Prevote;
    let target_a = Some([0x11u8; 32]);
    let target_b = Some([0x22u8; 32]);
    let msg_a = stellereum::consensus::vote_sign_bytes(height, round, kind, &target_a);
    let msg_b = stellereum::consensus::vote_sign_bytes(height, round, kind, &target_b);
    CompactPqEquivocationEvidence {
        voter: offender.verifying_key().to_bytes(),
        height,
        round,
        kind,
        block_hash_a: target_a,
        signature_a: offender.sign(&msg_a).to_bytes().to_vec(),
        block_hash_b: target_b,
        signature_b: offender.sign(&msg_b).to_bytes().to_vec(),
    }
}

fn report_tx(
    reporter: &SigningKey,
    nonce: u64,
    evidence: CompactPqEquivocationEvidence,
) -> Transaction {
    Transaction::sign_with_payload(
        reporter,
        [0u8; 32],
        0,
        REPORT_GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallReportPqEquivocation {
            evidence: Box::new(evidence),
        }],
    )
}

/// An engine with one bonded validator, a funded reporter and a funded
/// staking pool (the pool holds the bonded principal).
async fn engine_with(victim: [u8; 32], reporter: [u8; 32]) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.credit_native(&reporter, BAL)
        .await
        .expect("reporter funded");
    e.credit_native(&STAKING_POOL, 10 * BOND)
        .await
        .expect("pool funded");
    e.staking_write().await.bond(victim, BOND, 0).unwrap();
    e
}

async fn pool_of(e: &InMemoryStateEngine) -> u64 {
    e.get_account(&STAKING_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

// ===========================================================================
// 1. A VALID evidence slashes the validator AND burns the pool
// ===========================================================================

#[tokio::test]
async fn valid_pq_evidence_slashes_the_validator_and_burns_the_staking_pool() {
    let offender = SigningKey::from_bytes(&[1u8; 32]);
    let reporter = SigningKey::from_bytes(&[2u8; 32]);
    let victim = offender.verifying_key().to_bytes();
    let reporter_pk = reporter.verifying_key().to_bytes();

    let e = engine_with(victim, reporter_pk).await;
    let pool_before = pool_of(&e).await;
    let root_before = e.get_state_root().await;

    let tx = report_tx(&reporter, 0, double_sign(&offender));
    e.apply_transaction(&tx, TS)
        .await
        .expect("a valid report must apply");

    let burn = expected_burn();
    let l = e.staking_read().await;
    assert_eq!(
        l.validators[&victim].self_bond,
        BOND - burn,
        "the accused validator must be slashed by exactly 5%"
    );
    assert_eq!(l.validators[&victim].total_slashed, burn);
    assert_eq!(l.total_burned, burn, "the burn must be counted globally");
    assert_eq!(
        l.pq_equivocation_dedup.len(),
        1,
        "the per-offense dedup key must be consumed"
    );
    assert_eq!(
        pool_of(&e).await,
        pool_before - burn,
        "the burnt coins must LEAVE the staking pool (no pool/ledger drift)"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before,
        "a slash is consensus state: the root must move"
    );
}

// ===========================================================================
// 2. An INVALID evidence is refused fail-closed: NOTHING moves
// ===========================================================================

#[tokio::test]
async fn invalid_pq_evidence_is_refused_fail_closed() {
    let offender = SigningKey::from_bytes(&[3u8; 32]);
    let stranger = SigningKey::from_bytes(&[4u8; 32]);
    let reporter = SigningKey::from_bytes(&[5u8; 32]);
    let victim = offender.verifying_key().to_bytes();
    let reporter_pk = reporter.verifying_key().to_bytes();

    let good = double_sign(&offender);

    // (a) A signature by somebody else.
    let mut forged = good.clone();
    let msg_b =
        stellereum::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &Some([0x22u8; 32]));
    forged.signature_b = stranger.sign(&msg_b).to_bytes().to_vec();

    // (b) The SAME target twice (not an equivocation at all).
    let mut same_target = good.clone();
    same_target.block_hash_b = same_target.block_hash_a;
    let msg_same =
        stellereum::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &Some([0x11u8; 32]));
    same_target.signature_b = offender.sign(&msg_same).to_bytes().to_vec();

    // (c) An unknown voter (never bonded).
    let mut unknown = good.clone();
    unknown.voter = stranger.verifying_key().to_bytes();

    for (label, ev) in [
        ("forged signature", forged),
        ("same target", same_target),
        ("unknown voter", unknown),
    ] {
        let e = engine_with(victim, reporter_pk).await;
        let pool_before = pool_of(&e).await;
        let root_before = e.get_state_root().await;

        let tx = report_tx(&reporter, 0, ev);
        // The fee the refusal charges, read BEFORE the transaction is applied
        // (the consensus floor carries the D2 penalty, which the block path
        // records at the END of the block).
        let fee = failure_fee(&e, &tx).await;
        let balance_before = e.get_account(&reporter_pk).await.unwrap().balance;
        assert!(
            e.apply_transaction(&tx, TS).await.is_err(),
            "{label}: an invalid report must be refused"
        );

        let l = e.staking_read().await;
        assert_eq!(
            l.validators[&victim].self_bond, BOND,
            "{label}: nothing may be slashed"
        );
        assert_eq!(l.total_burned, 0, "{label}: nothing may be burned");
        assert!(
            l.pq_equivocation_dedup.is_empty(),
            "{label}: the dedup key must not be consumed"
        );
        assert_eq!(
            pool_of(&e).await,
            pool_before,
            "{label}: the staking pool must not move"
        );
        drop(l);
        // PINNED POLICY (SEC-07 / F-01): the refusal is ATTRIBUTABLE (it got
        // past admission and failed during execution), so the reporter pays
        // the failure fee and consumes its nonce - and the state root moves
        // BY EXACTLY THAT FEE DEBIT. What must NOT move is the SLASH: no
        // burn, no pool debit, no dedup key.
        assert_refused_tx_paid_failure_fee(&e, &tx, fee, balance_before, 0).await;
        assert_ne!(
            e.get_state_root().await,
            root_before,
            "{label}: the paid refusal moves the root via the fee debit"
        );
    }
}

// ===========================================================================
// 3. The same offense burns exactly once per chain
// ===========================================================================

#[tokio::test]
async fn the_same_offense_burns_exactly_once() {
    let offender = SigningKey::from_bytes(&[6u8; 32]);
    let reporter = SigningKey::from_bytes(&[7u8; 32]);
    let victim = offender.verifying_key().to_bytes();
    let reporter_pk = reporter.verifying_key().to_bytes();

    let e = engine_with(victim, reporter_pk).await;
    let pool_before = pool_of(&e).await;
    let burn = expected_burn();

    let evidence = double_sign(&offender);
    e.apply_transaction(&report_tx(&reporter, 0, evidence.clone()), TS)
        .await
        .expect("the first report must apply");
    // The reporter pays a fee for the second one, but the SLASH must not
    // compound: the per-offense dedup key is already consumed.
    e.apply_transaction(&report_tx(&reporter, 1, evidence), TS)
        .await
        .expect("the duplicate report is accepted (and burns 0)");

    let l = e.staking_read().await;
    assert_eq!(
        l.validators[&victim].self_bond,
        BOND - burn,
        "the same offense must burn exactly once"
    );
    assert_eq!(l.total_burned, burn);
    assert_eq!(
        pool_of(&e).await,
        pool_before - burn,
        "the pool must be debited exactly once"
    );
}

// ===========================================================================
// 4. The BLOCK path burns the pool too (the block path settles the burn
//    through the same native commit, and a block-carried report must leave
//    the pool and the ledger in agreement)
// ===========================================================================

#[tokio::test]
async fn the_block_path_burns_the_staking_pool_too() {
    let offender = SigningKey::from_bytes(&[8u8; 32]);
    let reporter = SigningKey::from_bytes(&[9u8; 32]);
    let victim = offender.verifying_key().to_bytes();
    let reporter_pk = reporter.verifying_key().to_bytes();

    let e = engine_with(victim, reporter_pk).await;
    let pool_before = pool_of(&e).await;
    let burn = expected_burn();

    let tx = report_tx(&reporter, 0, double_sign(&offender));
    let (applied, failed, _, status, _) = e.apply_block_parallel_fees(&[tx], TS).await;
    assert_eq!((applied, failed), (1, 0), "the report must apply");
    assert_eq!(status, vec![true], "the report must succeed");

    let l = e.staking_read().await;
    assert_eq!(l.validators[&victim].self_bond, BOND - burn);
    assert_eq!(l.total_burned, burn);
    assert_eq!(
        pool_of(&e).await,
        pool_before - burn,
        "the block path must burn the pool exactly like the single-tx path"
    );
}
