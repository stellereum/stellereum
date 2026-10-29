//! A-CONSENSUS PoC suite (adversarial, read-only + tests).
//! Each test asserts the SECURE behavior; a FAIL proves the bug on current code.

use stellereum::consensus::{
    HeightConsensus, ValidatorSet, Vote, VoteKind,
};
use stellereum::mempool::Mempool;

fn keys(n: usize) -> Vec<ed25519_dalek::SigningKey> {
    (0..n)
        .map(|_| ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng))
        .collect()
}

fn vset(ks: &[ed25519_dalek::SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

/// F1 (P1): second distinct proposal in the same round must NOT overwrite the first.
#[test]
fn poc_proposal_overwrite_same_round_is_rejected() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs);
    let prop = hc.proposer().expect("proposer");
    let h1 = [11u8; 32];
    let h2 = [22u8; 32];
    hc.receive_proposal(prop, h1).expect("first proposal accepted");
    let second = hc.receive_proposal(prop, h2);
    assert!(
        second.is_err(),
        "BUG: second distinct proposal same round overwrote first (proposal={:?})",
        hc.proposal
    );
    assert_eq!(hc.proposal, Some((prop, h1)), "first proposal must stick");
}

/// F2 (P1): epoch rotation must release sealed per-sender quota.
#[test]
fn poc_sealed_epoch_rotation_releases_sender_quota() {
    let mut pool = Mempool::new(100, 1);
    let sender = [7u8; 32];
    let eph =
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
    let mk = |tx_hash: [u8; 32], epoch: u64| stellereum::mev_epoch::SealedEnvelope {
        epoch,
        tx_hash,
        ephemeral_pk: eph,
        nonce: [0u8; 24],
        ciphertext: vec![1u8],
        meta: stellereum::mev_epoch::TransparentMeta {
            from: sender,
            nonce: 0,
            gas_limit: 0,
            priority_fee_per_gas: 0,
            source_shard: 0,
            target_shard: 0,
        },
    };
    let cur = pool.sealed_epoch();
    pool.add_sealed(mk([9u8; 32], cur)).expect("first sealed admitted");
    pool.set_sealed_epoch(cur + 1);
    // Fresh epoch: sender quota must be free again.
    let r = pool.add_sealed(mk([10u8; 32], cur + 1));
    assert!(
        r.is_ok(),
        "BUG: per-sender slot leaked across sealed epoch rotation: {r:?}"
    );
}

/// F3 (P2): a single verified far-future vote must not drag our round.
#[test]
fn poc_single_far_future_vote_does_not_drag_round() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs.clone());
    assert_eq!(hc.round, 0);
    let voter = ks[1].verifying_key().to_bytes();
    // Verified member round, far ahead of ours.
    let moved = hc.observe_peer_round(voter, 500);
    assert!(
        !moved && hc.round == 0,
        "BUG: one far-future vote dragged round 0 -> {} (no MAX_ROUND_AHEAD gate on sync path)",
        hc.round
    );
}

/// F4 (P2): quorum arithmetic must be saturating, never wrap/panic.
#[test]
fn poc_quorum_arithmetic_saturates_on_huge_power() {
    // Must not panic in debug nor wrap in release.
    let q = stellereum::consensus::consensus_quorum_min(u64::MAX);
    assert!(q > u64::MAX / 2, "quorum for MAX power must stay huge, got {q}");
}

/// F5 (SAFE, control): duplicate vote counts once + nil never unlocks.
#[test]
fn poc_control_dedup_and_nil_lock_safety() {
    let ks = keys(4);
    let vs = vset(&ks);
    // Dedup: same voter, two targets -> power counted once, equivocation recorded once.
    let mut hc = HeightConsensus::new(1, vs.clone());
    let v1 = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let v2 = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([2u8; 32]));
    hc.add_prevote(v1).unwrap();
    hc.add_prevote(v2).unwrap();
    let set = hc.prevote_set(0).unwrap();
    assert_eq!(set.power_for(Some([1u8; 32])), 1);
    assert_eq!(set.power_for(Some([2u8; 32])), 0);
    assert_eq!(set.equivocations().len(), 1);

    // Nil never unlocks: lock on A@0, nil quorum @1 -> lock stays.
    let mut hc2 = HeightConsensus::new(1, vs);
    hc2.locked = Some(([0xAAu8; 32], 0));
    for k in ks.iter().take(3) {
        hc2.add_prevote(Vote::sign(k, 1, 1, VoteKind::Prevote, None))
            .unwrap();
    }
    let _ = hc2.try_prevote_quorum_at();
    assert_eq!(
        hc2.locked,
        Some(([0xAAu8; 32], 0)),
        "nil quorum must never unlock a lock"
    );
}
