//! Ruleset-v6 value identity (R-B): locks compare the ROUND-FREE value, not
//! the signed block hash.
//!
//! A block's signed `round` is part of [`Block::compute_hash`] (ruleset v4),
//! so a lock-rescue that re-serves the same body "verbatim" re-serves an old
//! round forever. Once the fsynced vote watermark is above that round (one
//! nil vote suffices), the value vote is refused and the height parks — the
//! live permanent stall. R-B fixes the mechanism, not the symptom:
//!
//! * the proposer re-stamps a rescued body at its CURRENT round and re-signs;
//! * the lock rules compare [`Block::value_id`] (the hash with `round := 0`),
//!   so the re-stamp is still the locked value;
//! * the signed hash remains the wire/vote/QC identity, and proposal
//!   equivocation still requires the SAME signed round with different hashes
//!   (a re-stamp is NOT evidence).
//!
//! These tests are deterministic: fixed keys, no wall clock, no network.

use ed25519_dalek::SigningKey;
use std::sync::Arc;

use stellereum::consensus::{
    verify_proposal_equivocation_evidence, HeightConsensus, ProposalEquivocationEvidence,
    ValidatorSet, VoteKind,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)] // GATE: shared fixture module keeps helpers this file does not use.
mod falcon_votes;

const HEIGHT: u64 = 1;

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// A minimally complete block body at `round`, signed by `key` (Ed + Falcon).
fn signed_body(key: &SigningKey, fk: &FalconKeypair, round: u32, state_root: [u8; 32]) -> Block {
    let mut b = Block {
        height: HEIGHT,
        timestamp: 1,
        state_root,
        proposer: id(key),
        round,
        ..Default::default()
    };
    b.sign_block_with_falcon(key, fk);
    b
}

// ===========================================================================
// 1. `value_id` is stable across rounds for the same value and differs
//    between different values.
// ===========================================================================
#[test]
fn value_id_is_round_free_and_value_sensitive() {
    let (ks, fks) = falcon_votes::falcon_set(1);
    let root = [0x11u8; 32];

    let r0 = signed_body(&ks[0], &fks[0], 0, root);
    let r1 = signed_body(&ks[0], &fks[0], 1, root);
    let r505 = signed_body(&ks[0], &fks[0], 505, root);

    assert_eq!(
        r0.value_id(),
        r1.value_id(),
        "the same value at another round must keep its identity"
    );
    assert_eq!(
        r1.value_id(),
        r505.value_id(),
        "identity must be stable across the whole round range"
    );
    assert_ne!(
        r0.compute_hash(),
        r1.compute_hash(),
        "the SIGNED hash must still commit the round"
    );
    assert_ne!(r0.compute_hash(), r505.compute_hash());

    // A different value (state root, timestamp or transaction body) is a
    // different identity even at the same round.
    let other_root = signed_body(&ks[0], &fks[0], 1, [0x22u8; 32]);
    assert_ne!(
        r1.value_id(),
        other_root.value_id(),
        "different values must not share a value id"
    );
    let mut other_ts = r1.clone();
    other_ts.timestamp = 2;
    assert_ne!(r1.value_id(), other_ts.value_id());
}

// ===========================================================================
// 2. The lock rule itself: a registered re-stamp is the locked value, an
//    unknown hash is never assumed equal, and a different value still nils.
// ===========================================================================
#[test]
fn lock_rule_accepts_a_registered_restamp_and_rejects_other_values() {
    let (ks, _fks) = falcon_votes::falcon_set(2);
    let vs = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());

    let old = [0x11u8; 32];
    let restamp = [0x22u8; 32];
    let other = [0x33u8; 32];
    let unknown = [0x44u8; 32];
    let value = [0xAAu8; 32];

    let mut hc = HeightConsensus::new(1, vs.clone());
    hc.round = 1;
    hc.locked = Some((old, 0));
    hc.note_value_id(old, value);
    hc.note_value_id(restamp, value);
    hc.note_value_id(other, [0xBBu8; 32]);

    assert!(
        hc.same_value(old, restamp),
        "registered re-stamp: same value"
    );
    assert!(
        !hc.same_value(old, unknown),
        "an unknown hash must never be assumed equal"
    );
    assert!(
        !hc.same_value(old, other),
        "different registered values must not compare equal"
    );

    // Locked on `old`, offered the re-stamped body at this round: vote it.
    let proposer = hc.proposer().expect("schedule must name a proposer");
    hc.receive_proposal(proposer, restamp)
        .expect("the re-stamped proposal is admissible");
    assert_eq!(
        hc.decide_prevote(),
        Some(restamp),
        "the lock is on the VALUE, so the re-stamp is voted"
    );

    // Locked on `old`, offered a genuinely different value: nil.
    let mut other_hc = HeightConsensus::new(1, vs);
    other_hc.round = 1;
    other_hc.locked = Some((old, 0));
    other_hc.note_value_id(old, value);
    other_hc.note_value_id(other, [0xBBu8; 32]);
    let proposer = other_hc.proposer().expect("schedule must name a proposer");
    other_hc
        .receive_proposal(proposer, other)
        .expect("proposal is still admissible");
    assert_eq!(
        other_hc.decide_prevote(),
        None,
        "a different value must still prevote nil against the lock"
    );
}

// ===========================================================================
// 3. A re-stamped body is accepted (and voted) by a peer that NEVER held the
//    old signed hash.
// ===========================================================================
#[tokio::test]
async fn restamped_body_is_accepted_by_a_peer_that_never_held_the_old_hash() {
    let (ks, fks) = falcon_votes::falcon_set(2);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let mut a = {
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1).with_falcon_key(fks[0].clone())
    };
    let mut b = {
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        ValidatorRuntime::new(ks[1].clone(), vset.clone(), state, 1).with_falcon_key(fks[1].clone())
    };

    // A authors the original body at a round it owns.
    while a.hc.proposer() != Some(id(&ks[0])) {
        a.hc.next_round();
    }
    let old = a.propose(1).await.expect("A must build the original body");
    let old_hash = old.compute_hash();
    assert_eq!(old.round, a.hc.round);

    // A locks it, view-changes to a LATER round it also owns, and rescues the
    // value there. The rescue must be re-stamped and re-signed.
    a.hc.locked = Some((old_hash, a.hc.round));
    while !(a.hc.round > old.round && a.hc.proposer() == Some(id(&ks[0]))) {
        a.hc.next_round();
    }
    let restamped = a.propose(1).await.expect("the locked body must be served");
    assert_eq!(restamped.round, a.hc.round);
    assert_eq!(restamped.value_id(), old.value_id());
    assert_ne!(restamped.compute_hash(), old_hash);
    let restamped_hash = restamped.compute_hash();

    // B never received `old`; it only sees the re-stamped body at A's round.
    assert!(
        !b.blocks.contains_key(&old_hash),
        "precondition: the peer must never have held the old signed hash"
    );
    b.hc.round = restamped.round;
    b.on_proposal(id(&ks[0]), restamped.clone(), restamped.round)
        .await
        .expect("a first-seen re-stamped body must be admissible");

    assert!(b.blocks.contains_key(&restamped_hash));
    assert!(!b.blocks.contains_key(&old_hash));
    let v = b
        .make_prevote()
        .expect("the peer must vote the body it accepted");
    assert_eq!(v.kind, VoteKind::Prevote);
    assert_eq!(v.round, restamped.round);
    assert_eq!(v.block_hash, Some(restamped_hash));
}

// ===========================================================================
// 4. Proposal-equivocation evidence still requires the SAME signed round: a
//    re-stamp of the same value is NOT evidence.
// ===========================================================================
#[test]
fn restamped_value_is_not_proposal_equivocation_evidence() {
    let (ks, fks) = falcon_votes::falcon_set(1);
    let proposer = id(&ks[0]);
    let is_validator = |v: &[u8; 32]| *v == proposer;

    let a = signed_body(&ks[0], &fks[0], 7, [0x11u8; 32]);
    let b = signed_body(&ks[0], &fks[0], 7, [0x22u8; 32]);
    let restamp = signed_body(&ks[0], &fks[0], 8, [0x11u8; 32]);

    // Sanity: `restamp` is the SAME value as `a`, at a later signed round.
    assert_eq!(a.value_id(), restamp.value_id());
    assert_ne!(a.compute_hash(), restamp.compute_hash());

    // Same signed round, different bodies: a genuine double-propose.
    let offense = ProposalEquivocationEvidence::new(proposer, a.clone(), b.clone());
    assert!(
        verify_proposal_equivocation_evidence(&offense, &is_validator),
        "a same-round pair of different bodies IS evidence"
    );

    // A re-stamped body has a DIFFERENT signed round, so it is not a
    // same-round pair — regardless of the envelope's claimed round.
    for claimed in [7u32, 8u32] {
        let ev = ProposalEquivocationEvidence::new_at_round(
            proposer,
            claimed,
            a.clone(),
            restamp.clone(),
        );
        assert!(
            !verify_proposal_equivocation_evidence(&ev, &is_validator),
            "claimed round {claimed}: a re-stamp must never be slashable"
        );
    }
    let ev = ProposalEquivocationEvidence::new(proposer, restamp, b);
    assert!(
        !verify_proposal_equivocation_evidence(&ev, &is_validator),
        "the `new` constructor cannot turn a cross-round re-stamp into evidence"
    );
}
