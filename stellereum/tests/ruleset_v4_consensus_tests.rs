//! Ruleset v4: the SIGNED block round and the deterministic timestamp bound.
//!
//! These are the two consensus-correctness gaps the ruleset closes:
//!
//!  * the block identity had no signed round, so a proposer's honest
//!    cross-round re-proposal (A in round r, B in r+1, same height) was
//!    indistinguishable from a double-propose and proposal-equivocation
//!    slashing had to stay disabled;
//!  * the block timestamp had no deterministic parent-relative ceiling.
//!
//! Every assertion here is a pure function of the two headers (no wall clock),
//! except the honest-proposer test, which checks the proposer clamps INTO the
//! same deterministic window its peers enforce.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{
    proposal_equivocation_offense_rule, register_validator_pq_key,
    verify_proposal_equivocation_evidence, ProposalEquivocationEvidence, ValidatorId, ValidatorSet,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::protocol::{timestamp_within_bounds, MAX_BLOCK_TIMESTAMP_DRIFT_MS};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const BAL: u64 = 1_000_000_000_000_000;
const DRIFT_SECS: u64 = MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1_000;

fn id(k: &SigningKey) -> ValidatorId {
    k.verifying_key().to_bytes()
}

fn falcon_for(k: &SigningKey) -> FalconKeypair {
    FalconKeypair::generate_from_seed(k.to_bytes()[0])
}

/// A fully signed block at an explicit SIGNED round.
fn signed_block_at(
    k: &SigningKey,
    fk: &FalconKeypair,
    height: u64,
    round: u32,
    timestamp: u64,
) -> Block {
    let proposer = id(k);
    register_validator_pq_key(proposer, PqScheme::Falcon512, fk.public_key.clone());
    let mut b = Block::new_for_test(MASTERCHAIN_SHARD, height, [0u8; 32], [0u8; 32], vec![]);
    b.proposer = proposer;
    b.round = round;
    b.timestamp = timestamp;
    b.sign_block(k);
    let hash = b.compute_hash();
    b.validator_signatures
        .push((fk.validator_id(), fk.sign(&hash)));
    b
}

#[test]
fn compute_hash_changes_when_the_signed_round_changes() {
    let k = SigningKey::generate(&mut OsRng);
    let fk = falcon_for(&k);
    let r0 = signed_block_at(&k, &fk, 5, 0, 1_000);
    let mut r1 = r0.clone();
    r1.round = 1;
    assert_ne!(
        r0.compute_hash(),
        r1.compute_hash(),
        "the round must be part of the signed block identity"
    );
    // Round 0 is the zero-skipped legacy-compatible shape; non-zero rounds are
    // domain-separated and therefore a NEW identity.
    assert_ne!(r1.compute_hash(), {
        let mut r2 = r0.clone();
        r2.round = 2;
        r2.compute_hash()
    });
}

#[test]
fn honest_cross_round_pair_is_not_a_proposal_offense() {
    let k = SigningKey::generate(&mut OsRng);
    let fk = falcon_for(&k);
    let vs = ValidatorSet::from_list(vec![(id(&k), 1)]);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);

    // Same height, same proposer, DIFFERENT rounds: exactly what a view change
    // produces. The bodies differ, but the signed rounds do too.
    let a = signed_block_at(&k, &fk, 9, 7, 1_000);
    let b = signed_block_at(&k, &fk, 9, 8, 2_000);
    assert_ne!(a.compute_hash(), b.compute_hash());
    assert!(!proposal_equivocation_offense_rule(
        a.shard_id,
        b.shard_id,
        a.height,
        b.height,
        a.round,
        b.round,
        &a.compute_hash(),
        &b.compute_hash(),
    ));
    // Even an envelope that CLAIMS the lower round cannot turn the pair into
    // evidence: the claimed round must equal BOTH signed rounds.
    let ev = ProposalEquivocationEvidence::new_at_round(id(&k), a.round, a, b);
    assert!(
        !verify_proposal_equivocation_evidence(&ev, &member),
        "an honest cross-round re-proposal must never be slashable"
    );
}

#[test]
fn same_signed_round_with_different_hashes_is_a_proposal_offense() {
    let k = SigningKey::generate(&mut OsRng);
    let fk = falcon_for(&k);
    let vs = ValidatorSet::from_list(vec![(id(&k), 1)]);
    let member = |v: &ValidatorId| vs.validators.contains_key(v);

    let a = signed_block_at(&k, &fk, 9, 7, 1_000);
    let b = signed_block_at(&k, &fk, 9, 7, 2_000);
    assert_ne!(a.compute_hash(), b.compute_hash());
    assert!(proposal_equivocation_offense_rule(
        a.shard_id,
        b.shard_id,
        a.height,
        b.height,
        a.round,
        b.round,
        &a.compute_hash(),
        &b.compute_hash(),
    ));
    let ev = ProposalEquivocationEvidence::new(id(&k), a.clone(), b.clone());
    assert!(
        verify_proposal_equivocation_evidence(&ev, &member),
        "same SIGNED round + different signed bodies is a double-propose"
    );
    // A relabelled envelope (claimed round != signed rounds) is refused.
    let relabelled = ProposalEquivocationEvidence::new_at_round(id(&k), 8, a, b);
    assert!(
        !verify_proposal_equivocation_evidence(&relabelled, &member),
        "the claimed round is not trusted: it must match both signed rounds"
    );
}

async fn runtime_with_parent(parent_ts: u64) -> (ValidatorRuntime, [u8; 32], SigningKey) {
    let k = SigningKey::generate(&mut OsRng);
    let vs = ValidatorSet::from_list(vec![(id(&k), 1)]);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, BAL).await;
    let mut rt = ValidatorRuntime::new(k.clone(), vs, state, 1);

    let mut parent = Block::new_for_test(
        MASTERCHAIN_SHARD,
        1,
        [0u8; 32],
        rt.state.get_state_root().await,
        vec![],
    );
    parent.timestamp = parent_ts;
    parent.proposer = id(&k);
    let parent_hash = parent.compute_hash();
    rt.blocks.insert(parent_hash, parent.clone());
    rt.finalized = vec![(1, parent_hash)];
    rt.hc.height = 2;
    (rt, parent_hash, k)
}

async fn child(
    rt: &ValidatorRuntime,
    k: &SigningKey,
    parent_hash: [u8; 32],
    timestamp: u64,
) -> Block {
    let mut b = Block::new_for_test(
        MASTERCHAIN_SHARD,
        2,
        parent_hash,
        rt.state.get_state_root().await,
        vec![],
    );
    b.timestamp = timestamp;
    b.proposer = rt
        .validators
        .proposer_for(2, rt.hc.round)
        .expect("non-empty set has a proposer");
    b.round = rt.hc.round;
    register_validator_pq_key(b.proposer, PqScheme::Falcon512, falcon_for(k).public_key.clone());
    b.sign_block_with_falcon(k, &falcon_for(k));
    b
}

#[tokio::test]
async fn timestamp_before_parent_is_refused() {
    let (rt, parent_hash, k) = runtime_with_parent(1_000_000).await;
    let b = child(&rt, &k, parent_hash, 999_999).await;
    let err = rt
        .validate_proposal(&b, rt.state.get_state_root().await)
        .expect_err("a backwards timestamp must be refused");
    assert!(err.contains("timestamp moved backwards"), "{err}");
}

#[tokio::test]
async fn far_future_timestamp_is_refused_without_a_wall_clock() {
    let (rt, parent_hash, k) = runtime_with_parent(1_000_000).await;
    let b = child(&rt, &k, parent_hash, 1_000_000 + DRIFT_SECS + 1).await;
    let err = rt
        .validate_proposal(&b, rt.state.get_state_root().await)
        .expect_err("a far-future timestamp must be refused");
    assert!(err.contains("timestamp too far ahead of parent"), "{err}");

    // The bound is parent-relative, not "now"-relative: the same ABSOLUTE
    // timestamp is fine when the parent is close to it.
    let (rt2, parent_hash2, k2) = runtime_with_parent(1_000_000 + DRIFT_SECS).await;
    let ok = child(&rt2, &k2, parent_hash2, 1_000_000 + DRIFT_SECS).await;
    assert!(
        rt2.validate_proposal(&ok, rt2.state.get_state_root().await)
            .is_ok(),
        "the identical absolute value must be valid for its own parent"
    );
}

#[tokio::test]
async fn timestamp_rule_is_a_pure_function_of_parent_and_block() {
    // Two calls see the same inputs; no clock participates. The edge is
    // inclusive and one second past it is out.
    assert!(timestamp_within_bounds(1_000, 1_000));
    assert!(timestamp_within_bounds(1_000, 1_000 + DRIFT_SECS));
    assert!(!timestamp_within_bounds(1_000, 1_000 + DRIFT_SECS + 1));
    assert!(!timestamp_within_bounds(1_000, 999));
    assert_eq!(
        timestamp_within_bounds(7, 8),
        timestamp_within_bounds(7, 8),
        "the verdict must not depend on when it is evaluated"
    );
}

#[tokio::test]
async fn honest_proposer_clamps_into_the_validator_window() {
    let (mut rt, _parent_hash, k) = runtime_with_parent(1_000_000).await;
    // Our slot at this height/round (single-validator set).
    assert_eq!(rt.validators.proposer_for(rt.hc.height, rt.hc.round), Some(id(&k)));

    // A very fast local clock asks for far more than the protocol allows.
    let mut block = rt
        .propose(1_000_000 + DRIFT_SECS + 50_000)
        .await
        .expect("the scheduled proposer must build a block");
    assert_eq!(block.round, rt.hc.round, "proposer signs the current round");
    assert!(
        timestamp_within_bounds(1_000_000, block.timestamp),
        "the honest proposer must clamp into the deterministic window"
    );
    assert_eq!(
        block.timestamp,
        1_000_000 + DRIFT_SECS,
        "a fast clock clamps to the upper bound, never past it"
    );
    // The runtime has no Falcon signer in this fixture; add the PQ half the
    // validator gate requires (signatures are excluded from the hash).
    let fk = falcon_for(&k);
    register_validator_pq_key(id(&k), PqScheme::Falcon512, fk.public_key.clone());
    let hash = block.compute_hash();
    block
        .validator_signatures
        .push((fk.validator_id(), fk.sign(&hash)));
    // The gate accepts the body the proposer built.
    assert!(
        rt.validate_proposal(&block, rt.state.get_state_root().await)
            .is_ok(),
        "the honest proposer path must stay inside the validator bound"
    );
}

#[tokio::test]
async fn block_round_must_match_the_proposal_round() {
    let (mut rt, parent_hash, k) = runtime_with_parent(1_000_000).await;
    rt.hc.round = 5;
    let proposer = rt
        .validators
        .proposer_for(2, 5)
        .expect("non-empty set has a proposer");
    let fk = falcon_for(&k);
    register_validator_pq_key(proposer, PqScheme::Falcon512, fk.public_key.clone());
    let root = rt.state.get_state_root().await;

    let build = |round: u32| {
        let mut b = Block::new_for_test(
            MASTERCHAIN_SHARD,
            2,
            parent_hash,
            root,
            vec![],
        );
        b.timestamp = 1_000_000;
        b.proposer = proposer;
        b.round = round;
        b.sign_block_with_falcon(&k, &fk);
        b
    };

    let b = build(4); // the proposal is for round 5
    let err = rt
        .validate_proposal(&b, rt.state.get_state_root().await)
        .expect_err("a block whose signed round is not the proposal round must be refused");
    assert!(
        err.contains("block round 4 does not match proposal round 5"),
        "{err}"
    );

    let b = build(5);
    assert!(
        rt.validate_proposal(&b, rt.state.get_state_root().await)
            .is_ok(),
        "the matching signed round must be accepted"
    );
}
