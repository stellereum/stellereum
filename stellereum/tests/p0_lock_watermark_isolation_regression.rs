//! Local safety invariants, not an end-to-end fork demonstration.
//! A restored checkpoint retains the lock, not the in-memory polka ledger.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{VoteWatermark, VoteWatermarkEntry};

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

const H: u64 = 71;

fn block_with(proposer: [u8; 32], round: u32, tag: u8) -> (stellereum::sharding::Block, [u8; 32]) {
    let blk = stellereum::sharding::Block {
        height: H,
        state_root: [tag; 32],
        timestamp: 71 + tag as u64,
        proposer,
        round,
        ..Default::default()
    };
    let h = blk.compute_hash();
    (blk, h)
}

fn runtime(ks: &[SigningKey], fk: &stellereum::post_quantum::FalconKeypair) -> ValidatorRuntime {
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    ValidatorRuntime::new(
        ks[0].clone(),
        vs,
        Arc::new(InMemoryStateEngine::new()),
        H,
    )
    .with_falcon_key(fk.clone())
}

fn polka(
    rt: &mut ValidatorRuntime,
    ks: &[SigningKey],
    fks: &[stellereum::post_quantum::FalconKeypair],
    round: u32,
    value: [u8; 32],
) {
    for i in 0..3 {
        let vote = falcon_votes::fvote(
            &ks[i],
            &fks[i],
            H,
            round,
            VoteKind::Prevote,
            Some(value),
        );
        assert!(vote.verify());
        rt.on_prevote(vote).unwrap();
    }
}

fn entry(vote: &Vote) -> VoteWatermarkEntry {
    VoteWatermarkEntry {
        height: vote.height,
        round: vote.round,
        kind: match vote.kind {
            VoteKind::Prevote => 0,
            VoteKind::Precommit => 1,
        },
        target: vote.block_hash,
        shard_id: vote.shard_id,
    }
}

// Construct the lock through actual verified votes and runtime signing. Restore
// just its checkpointed state in a fresh runtime, as the driver does; votes and
// the observed-polka ledger are intentionally not persisted by this fixture.
fn restored_lock(
    ks: &[SigningKey],
    fks: &[stellereum::post_quantum::FalconKeypair],
) -> (ValidatorRuntime, [u8; 32], stellereum::sharding::Block) {
    let mut original = runtime(ks, &fks[0]);
    let (blk_a, a) = block_with(ks[0].verifying_key().to_bytes(), 10, 0xa1);
    original.blocks.insert(a, blk_a.clone());
    original.hc.round = 10;
    polka(&mut original, ks, fks, 10, a);
    let signed = original.make_precommit().expect("round 10 polka");
    assert!(signed.verify());
    assert_eq!((signed.round, signed.block_hash), (10, Some(a)));
    let lock = original.hc.locked;
    assert_eq!(lock, Some((a, 10)));

    let mut restored = runtime(ks, &fks[0]);
    restored.hc.round = 11;
    restored.hc.locked = lock;
    (restored, a, blk_a)
}

#[test]
fn older_same_value_polka_never_regresses_restored_lock_round() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let (mut rt, a, blk_a) = restored_lock(&ks, &fks);
    rt.blocks.insert(a, blk_a);
    polka(&mut rt, &ks, &fks, 4, a);
    let _ = rt.make_precommit();
    assert_eq!(rt.hc.locked, Some((a, 10)), "lock round must not regress");
}

#[test]
fn older_conflicting_polka_cannot_release_restored_lock_after_same_value() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let (mut rt, a, blk_a) = restored_lock(&ks, &fks);
    let (blk_b, b) = block_with(ks[0].verifying_key().to_bytes(), 7, 0xb2);
    rt.blocks.insert(a, blk_a);
    rt.blocks.insert(b, blk_b);
    polka(&mut rt, &ks, &fks, 4, a);
    let _ = rt.make_precommit();
    polka(&mut rt, &ks, &fks, 7, b);
    let vote = rt.make_precommit();
    assert!(
        vote.as_ref().is_none_or(|v| v.block_hash != Some(b)),
        "a conflicting polka older than the original lock must not be signed"
    );
    assert_eq!(rt.hc.locked, Some((a, 10)));
}

#[test]
fn newer_same_value_polka_advances_restored_lock() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let (mut rt, a, blk_a) = restored_lock(&ks, &fks);
    rt.blocks.insert(a, blk_a);
    polka(&mut rt, &ks, &fks, 11, a);
    let vote = rt.make_precommit().expect("newer same-value polka");
    assert_eq!((vote.round, vote.block_hash), (11, Some(a)));
    assert_eq!(rt.hc.locked, Some((a, 11)));
}

#[test]
fn newer_conflicting_polka_replaces_restored_lock() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let (mut rt, _a, _blk_a) = restored_lock(&ks, &fks);
    let (blk_b, b) = block_with(ks[0].verifying_key().to_bytes(), 11, 0xb2);
    rt.blocks.insert(b, blk_b);
    polka(&mut rt, &ks, &fks, 11, b);
    let vote = rt.make_precommit().expect("newer conflicting polka");
    assert_eq!((vote.round, vote.block_hash), (11, Some(b)));
    assert_eq!(rt.hc.locked, Some((b, 11)));
}

#[test]
fn reset_without_locally_observed_qc_preserves_bodyless_lock() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let (mut rt, a, _blk_a) = restored_lock(&ks, &fks);
    assert!(!rt.blocks.contains_key(&a));
    assert!(!rt.hc.precommit_qc_observed());
    assert!(rt.hc.apply_deadlock_local_reset(false));
    assert_eq!(
        rt.hc.locked,
        Some((a, 10)),
        "absence of a local QC does not prove no other validator saw one"
    );
}

#[test]
fn later_real_prevote_then_older_polka_produces_signed_precommit() {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let mut rt = runtime(&ks, &fks[0]);
    let (blk_a, a) = block_with(ks[0].verifying_key().to_bytes(), 4, 0xa1);
    rt.blocks.insert(a, blk_a);
    rt.hc.round = 11;
    let prevote = rt.make_prevote().expect("nil prevote");
    assert!(prevote.verify());
    assert_eq!((prevote.round, prevote.block_hash), (11, None));
    rt.on_prevote(prevote.clone()).unwrap();

    let mut wm = VoteWatermark::default();
    wm.note(entry(&prevote));
    polka(&mut rt, &ks, &fks, 4, a);
    let precommit = rt.make_precommit().expect("late polka");
    assert!(precommit.verify());
    assert_eq!((precommit.round, precommit.block_hash), (4, Some(a)));
    assert_eq!(wm.floor_round(H), Some(11));
    assert_eq!(wm.precommit_at(H), None);
    wm.note(entry(&precommit));
    assert_eq!(wm.floor_round(H), Some(11));
    assert_eq!(wm.precommit_at(H).unwrap().round, 4);
    // The node driver uses the precommit-specific floor, not floor_round,
    // for precommit broadcast. Its private guard is not exercised here.
}
