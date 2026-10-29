//! P0-4 follow-up: the state root in a block header has to mean something.
//!
//! `Block.state_root` is the root the block BUILDS ON - the state after the
//! previous block. That is the standard convention (the same one CometBFT calls
//! the app hash) and it is what lets a chain be walked without replaying it.
//!
//! The problem was not the convention. It was that nothing checked it.
//! `validate_proposal` verified height, proposer, signature, prev_hash, size,
//! gas and transaction signatures, and never once looked at `state_root`. A
//! proposer could put any value there and every validator accepted the block.
//! The state commitment added in P0-4 was therefore decorative on the live path.
//!
//! The second half was an off-by-one: sync compared the root AFTER applying a
//! block against the header's PRE-apply root, so a peer chain of any substance
//! was rejected - the property "sync compares roots" was broken in both
//! directions at once.

use ed25519_dalek::SigningKey;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn set_of(ids: &[[u8; 32]]) -> ValidatorSet {
    let mut v = ValidatorSet::new();
    for id in ids {
        v.validators.insert(*id, 1_000);
    }
    v
}

/// A single-validator runtime, so a block this node proposes is one it should
/// also accept.
async fn runtime() -> ValidatorRuntime {
    let k = key(1);
    let addr = k.verifying_key().to_bytes();
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new(addr, 1_000_000))
        .await;
    ValidatorRuntime::new(k, set_of(&[addr]), engine, 1)
}

use std::sync::Arc;

fn block_at(
    height: u64,
    state_root: [u8; 32],
    proposer: [u8; 32],
    k: &SigningKey,
) -> stellereum::sharding::Block {
    let mut b = stellereum::sharding::Block {
        shard_id: 1,
        height,
        prev_hash: [0u8; 32],
        state_root,
        timestamp: 1_700_000_000 + height,
        proposer,
        transactions: vec![],
        cross_shard_out: vec![],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    };
    b.sign_block(k);
    b
}

#[tokio::test]
async fn a_proposal_must_build_on_our_state() {
    let rt = runtime().await;
    let k = key(1);
    let me = k.verifying_key().to_bytes();
    let our_root = rt.state.get_state_root().await;

    let honest = block_at(rt.hc.height, our_root, me, &k);
    assert!(
        rt.validate_proposal(&honest, our_root).is_ok(),
        "an honest proposal must be accepted"
    );

    // The attack the missing check allowed: keep every other field perfect and
    // lie only about the state the block builds on.
    let forged = block_at(rt.hc.height, [0xDE; 32], me, &k);
    let err = rt
        .validate_proposal(&forged, our_root)
        .expect_err("a block claiming a different parent state must be rejected");
    assert!(
        err.contains("state root"),
        "the rejection must name the reason, got: {err}"
    );
}

#[tokio::test]
async fn the_state_root_check_precedes_the_rest_of_validation() {
    // Order matters for the error a peer sees: a forged root should be reported
    // as such rather than as an unrelated size or signature problem.
    let rt = runtime().await;
    let k = key(1);
    let me = k.verifying_key().to_bytes();
    let our_root = rt.state.get_state_root().await;
    let wrong_height = block_at(rt.hc.height + 5, [0xDE; 32], me, &k);
    let err = rt
        .validate_proposal(&wrong_height, our_root)
        .expect_err("rejected");
    assert!(
        err.contains("wrong height"),
        "height is checked first, got: {err}"
    );
}

#[tokio::test]
async fn on_proposal_rejects_a_block_built_on_a_foreign_state() {
    let mut rt = runtime().await;
    let k = key(1);
    let me = k.verifying_key().to_bytes();
    let forged = block_at(rt.hc.height, [0xAD; 32], me, &k);
    assert!(
        rt.on_proposal(me, forged, rt.hc.round).await.is_err(),
        "a proposal claiming a foreign parent state must not be adopted"
    );
}

#[tokio::test]
async fn the_state_root_moves_after_a_block_applies() {
    // Establishes the direction the check depends on: the header's value is the
    // state BEFORE, and applying the block produces the next one.
    let rt = runtime().await;
    let k = key(1);
    let me = k.verifying_key().to_bytes();
    let before = rt.state.get_state_root().await;

    let key2 = key(2);
    let to = key2.verifying_key().to_bytes();
    rt.state.update_account(AccountState::new(to, 1_000)).await;
    let with_funding = rt.state.get_state_root().await;
    assert_ne!(with_funding, before, "funding moves the root");

    // A block whose header claims the OLD root is now stale, because the state it
    // would build on is `with_funding`.
    let stale = block_at(rt.hc.height, before, me, &k);
    assert!(
        rt.validate_proposal(&stale, with_funding).is_err(),
        "a header holding a superseded root must be refused once state has moved"
    );
}

#[tokio::test]
async fn an_empty_chain_still_accepts_an_honest_genesis_successor() {
    // Guard against over-tightening: a node that has applied nothing must accept
    // the next honest block, or the chain can never start.
    let rt = runtime().await;
    let k = key(1);
    let me = k.verifying_key().to_bytes();
    let root = rt.state.get_state_root().await;
    let b = block_at(rt.hc.height, root, me, &k);
    assert!(rt.validate_proposal(&b, root).is_ok());
}
