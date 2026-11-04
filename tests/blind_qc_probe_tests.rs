//! # Blind-QC-probe sync primitive: one-height walk with a height-bound QC.
//!
//! Live incident: a 1-height-behind node could never catch up because
//! `try_catch_up` only trusted the DHT shared head pointer (last-writer-wins:
//! a node reads back its OWN head = echo chamber) plus `peer_hint` (only set
//! from validated proposals, which a deaf node never gets). The production
//! fix (`src/main.rs::try_catch_up`) adds a blind-QC-probe fallback:
//! `fetch_block_qc(shard, our_tip+1)`; if a height-bound QC exists, walk it
//! with full verification.
//!
//! These tests pin the SYNC PRIMITIVE that fallback rests on — NOT
//! `try_catch_up` itself (needs the full runtime). A canned 1-block chain
//! (parent = our tip, height = tip+1) with a REAL `QuorumCertificate` (built
//! exactly like `src/sync.rs` tests build QCs: every validator signs
//! `Vote::sign(.., Precommit, Some(hash))` over the block hash) must pass
//! `collect_missing_blocks` + `walked_head_anchor` +
//! `validate_sync_chain_for_shard_with_sets`; the same chain with a FORGED QC
//! (wrong signers, no quorum power) must be refused at validation.

use rand::rngs::OsRng;
use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::sync::{
    collect_missing_blocks, validate_sync_chain_for_shard_with_sets, walked_head_anchor,
};

/// Build one finalized block at `height` on top of `prev_hash`, carrying a
/// REAL precommit QC from every key in `keys` (the `src/sync.rs`
/// `quorum_chain` pattern: proposer = schedule slot at round 0, block signed
/// by the proposer, QC = one Precommit vote per validator over the hash).
fn finalized_block(
    keys: &[SigningKey],
    validators: &ValidatorSet,
    height: u64,
    prev_hash: [u8; 32],
) -> Block {
    let proposer_id = validators
        .proposer_for(height, 0)
        .expect("non-empty set has a proposer");
    let proposer = keys
        .iter()
        .find(|k| k.verifying_key().to_bytes() == proposer_id)
        .expect("proposer is a member")
        .clone();
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root: [height as u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: height,
        proposer: proposer_id,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
    };
    b.sign_block(&proposer);
    let hash = b.compute_hash();
    let sigs = keys
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: sigs,
    });
    b
}

fn validator_set(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

/// The blind-QC-probe shape: our tip is height 0 (genesis sentinel), the QC
/// sidecar pins height 1, the body walk serves exactly that block.
#[tokio::test]
async fn blind_qc_probe_walk_accepts_genuine_qc() {
    let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let vs = validator_set(&keys);
    assert_eq!(vs.quorum_power(), 3);

    let our_tip = [0u8; 32];
    let block = finalized_block(&keys, &vs, 1, our_tip);
    let head_hash = block.compute_hash();

    // The QC sidecar is height-bound and genuine.
    let qc = block.precommit_qc.clone().expect("block carries a QC");
    assert_eq!(qc.height, 1);
    assert!(qc.verify(&vs), "canned QC must verify under the test set");

    let map: HashMap<[u8; 32], Block> =
        [(head_hash, block.clone())].into_iter().collect();
    let blocks = collect_missing_blocks(head_hash, our_tip, 256, |h| {
        let b = map.get(&h).cloned();
        async move { b }
    })
    .await
    .expect("one-height walk from our tip must collect");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 1);

    let next = walked_head_anchor(&blocks, head_hash, 1)
        .expect("walked head must anchor on the advertised tip+1");
    assert_eq!(next, 2);

    validate_sync_chain_for_shard_with_sets(&blocks, 1, our_tip, &|_| Some(vs.clone()), MASTERCHAIN_SHARD)
        .expect("genuine height-bound QC must validate");
}

/// NEGATIVE: the same walk shape but the QC is forged (signed by keys outside
/// the validator set): collection + anchoring still work (they only check
/// linkage), but full validation refuses the chain.
#[tokio::test]
async fn blind_qc_probe_refuses_forged_qc() {
    let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let vs = validator_set(&keys);

    let our_tip = [0u8; 32];
    let mut block = finalized_block(&keys, &vs, 1, our_tip);

    // Forge: replace the QC signers with keys the set never heard of.
    let forgers: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let hash = block.compute_hash();
    let forged_sigs = forgers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    block.precommit_qc = Some(QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: forged_sigs,
    });
    assert!(
        !block
            .precommit_qc
            .clone()
            .expect("QC present")
            .verify(&vs),
        "forged QC must NOT verify under the test set"
    );

    let head_hash = block.compute_hash();
    let map: HashMap<[u8; 32], Block> =
        [(head_hash, block.clone())].into_iter().collect();
    let blocks = collect_missing_blocks(head_hash, our_tip, 256, |h| {
        let b = map.get(&h).cloned();
        async move { b }
    })
    .await
    .expect("collection is linkage-only and still collects");
    assert_eq!(blocks.len(), 1);
    walked_head_anchor(&blocks, head_hash, 1).expect("anchor is linkage-only");

    let err = validate_sync_chain_for_shard_with_sets(
        &blocks,
        1,
        our_tip,
        &|_| Some(vs.clone()),
        MASTERCHAIN_SHARD,
    )
    .expect_err("forged QC must be refused");
    assert!(
        err.contains("quorum"),
        "refusal must name the quorum shortfall, got: {err}"
    );
}
