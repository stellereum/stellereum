//! Adopt-path parity with `try_precommit_quorum` (consensus.rs):
//! prevote-quorum consistency + lock-consistency inside `adopt_committed`.
//!
//! NOTE on scope: `adopt_committed(height, block, certificate)` takes only the
//! precommit QC, so a catching-up node with empty local prevote sets cannot
//! verify a prevote quorum it never saw. The check is therefore:
//!   * refuse when LOCAL prevotes show a quorum for a DIFFERENT target;
//!   * accept (transitive trust in the precommit QC) when local sets are empty.
//!     Full parity needs a wire change (ship a prevote QC alongside the commit);
//!     the first test pins that residual gap explicitly.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn vs_of(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

async fn runtime(ks: &[SigningKey], idx: usize) -> ValidatorRuntime {
    let vs = vs_of(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    ValidatorRuntime::new(ks[idx].clone(), vs, st, 1)
}

/// Block authored by the scheduled proposer for (1, 0) committing to our root.
async fn good_block(rt: &ValidatorRuntime, ks: &[SigningKey]) -> Block {
    let vs = rt.validators.clone();
    let proposer = vs.proposer_for(1, 0).unwrap();
    let pk = ks.iter().find(|k| id(k) == proposer).unwrap();
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pk);
    b
}

fn precommit_cert(ks: &[SigningKey], bh: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

/// Residual gap, pinned: a fresh node that observed NO prevotes accepts a valid
/// precommit QC. Without a wire change (prevote QC shipped alongside the commit)
/// it has no evidence to check -- refusing here would make catch-up impossible.
#[tokio::test]
async fn precommit_without_any_local_prevote_is_accepted_gap_pinned() {
    let ks = keys(4);
    let mut rt = runtime(&ks, 0).await;
    let blk = good_block(&rt, &ks).await;
    let bh = blk.compute_hash();
    let cert = precommit_cert(&ks, bh);
    assert!(cert.verify(&rt.validators));
    assert!(rt.hc.prevote_set(0).is_none(), "fresh node saw no prevotes");
    let r = rt.adopt_committed(1, blk, cert).await;
    assert_eq!(
        r,
        Ok(bh),
        "catch-up with empty prevote sets must still work; gap pinned, not closed"
    );
}

/// Matching prevote quorum + precommit QC is accepted.
#[tokio::test]
async fn matching_prevote_and_precommit_is_accepted() {
    let ks = keys(4);
    let mut rt = runtime(&ks, 0).await;
    let blk = good_block(&rt, &ks).await;
    let bh = blk.compute_hash();
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    let cert = precommit_cert(&ks, bh);
    let r = rt.adopt_committed(1, blk, cert).await;
    assert_eq!(r, Ok(bh));
}

/// Local prevote quorum for a DIFFERENT block refuses the adoption.
#[tokio::test]
async fn conflicting_local_prevote_quorum_refuses_adoption() {
    let ks = keys(4);
    let mut rt = runtime(&ks, 0).await;
    let blk = good_block(&rt, &ks).await;
    let bh = blk.compute_hash();
    let other = [0xEEu8; 32];
    assert_ne!(other, bh);
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(other)))
            .unwrap();
    }
    let cert = precommit_cert(&ks, bh);
    assert!(cert.verify(&rt.validators), "precommit QC itself is valid");
    let r = rt.adopt_committed(1, blk, cert).await;
    assert!(
        r.is_err(),
        "contradicting observed prevote quorum must refuse"
    );
    assert!(
        r.unwrap_err().contains("prevote quorum"),
        "refusal must name the prevote quorum"
    );
    assert!(rt.finalized.is_empty());
}

/// Adopting against our own lock is refused (mirror of try_precommit_quorum).
#[tokio::test]
async fn anti_lock_adoption_is_refused() {
    let ks = keys(4);
    let mut rt = runtime(&ks, 0).await;
    let blk = good_block(&rt, &ks).await;
    let bh = blk.compute_hash();
    rt.hc.locked = Some(([0xAAu8; 32], 0));
    let cert = precommit_cert(&ks, bh);
    let r = rt.adopt_committed(1, blk, cert).await;
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("lock"));
    assert!(rt.finalized.is_empty());
}

/// Adopting the block we are locked on succeeds.
#[tokio::test]
async fn adopting_the_locked_block_succeeds() {
    let ks = keys(4);
    let mut rt = runtime(&ks, 0).await;
    let blk = good_block(&rt, &ks).await;
    let bh = blk.compute_hash();
    rt.hc.locked = Some((bh, 0));
    let cert = precommit_cert(&ks, bh);
    let r = rt.adopt_committed(1, blk, cert).await;
    assert_eq!(r, Ok(bh));
}
