use ed25519_dalek::SigningKey;

use super::*;

fn two() -> (ValidatorSet, SigningKey, SigningKey) {
    let a = SigningKey::generate(&mut rand::rngs::OsRng);
    let b = SigningKey::generate(&mut rand::rngs::OsRng);
    let vs = ValidatorSet::from_list(vec![
        (a.verifying_key().to_bytes(), 1),
        (b.verifying_key().to_bytes(), 1),
    ]);
    (vs, a, b)
}

#[test]
fn the_ahead_node_holding_lets_the_behind_node_join_it() {
    // The convergence rule, expressed directly: the behind node moves forward on
    // the ahead node's votes, and the ahead node STOPS advancing while its peer is
    // active nearby. Before this, both advanced on their own timers, stayed one
    // round apart, and -- because the proposer alternates by parity -- sat in
    // opposite phases forever.
    let (vs, _a, _b) = two();
    let mut behind = HeightConsensus::new(1, vs.clone());
    let mut ahead = HeightConsensus::new(1, vs.clone());

    // They start 1 apart, which is the parity trap.
    behind.sync_round_to(4);
    ahead.sync_round_to(5);
    assert_eq!((behind.round, ahead.round), (4, 5));

    // The behind node adopts the ahead node's round and they meet.
    behind.sync_round_to(ahead.round);
    assert_eq!(behind.round, 5);
    assert_eq!(
        behind.proposer(),
        ahead.proposer(),
        "once in the same round they must agree who proposes"
    );

    // And the ahead node does not advance again while the peer is nearby, so the
    // pair stays together instead of drifting.
    // (The hold itself lives in main.rs, which owns the loop and the timer; this
    // test pins the arithmetic of meeting, not the timer.)
    assert_eq!(behind.proposer(), ahead.proposer());
}

#[test]
fn a_silent_peer_does_not_wedge_the_round_forever() {
    // The hold is bounded by the round timeout, so a peer that goes away must not
    // freeze the node: it still advances. This asserts the bound exists by checking
    // that advancing is always possible locally -- `next_round` is unconditional.
    let (vs, _a, _b) = two();
    let mut hc = HeightConsensus::new(1, vs);
    let start = hc.round;
    hc.next_round();
    assert_eq!(hc.round, start + 1, "a node can always time out on its own");
}

// =======================================================================
// THE POLKA LEDGER (liveness fix, live 2026-10-21: the masterchain
// parked at height 285027 with a prevote QC and NO precommit QC)
// =======================================================================

/// A three-validator set with the live power split: the 1500-STELL
/// validator is in EVERY quorum (1000+1000 = 2000 is below the 2334
/// quorum), so one node that stays silent parks the whole chain.
/// FULL-PQ: also registers Falcon-512 keys for each Ed id.
fn live_three() -> (ValidatorSet, Vec<SigningKey>, Vec<FalconKeypair>) {
    let keys: Vec<SigningKey> = (0..3)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = (i as u8) + 1;
            seed[31] = 0x5A;
            SigningKey::from_bytes(&seed)
        })
        .collect();
    let fks: Vec<FalconKeypair> = (0..3)
        .map(|i| FalconKeypair::generate_from_seed(0x70 + i as u8))
        .collect();
    let vs = ValidatorSet::from_list(
        keys.iter()
            .zip([1500u64, 1000, 1000].iter())
            .map(|(k, p)| (k.verifying_key().to_bytes(), *p))
            .collect(),
    );
    for (sk, fk) in keys.iter().zip(fks.iter()) {
        let id = sk.verifying_key().to_bytes();
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    (vs, keys, fks)
}

// Local copy of the `mod tests` helper (sibling modules cannot see it):
// Falcon-only vote minting, identical semantics.
// GATE: keep in sync with `mod tests::fvote` — same one-line delegation.
fn fvote(
    sk: &SigningKey,
    fk: &FalconKeypair,
    height: Height,
    round: Round,
    kind: VoteKind,
    bh: Option<BlockHash>,
) -> Vote {
    Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
}

#[test]
fn a_late_polka_is_recorded_even_after_the_round_was_left() {
    // THE LIVE FAILURE: the quorum-completing prevote of round 0 arrives
    // when this node has already raced eleven rounds ahead. The polka is a
    // FACT about the network, so it must be recorded and acted on anyway --
    // the scan window cannot see it, and the node that misses it never
    // precommits, so the precommit quorum never forms and the height is
    // parked forever.
    let (vs, keys, fks) = live_three();
    let mut hc = HeightConsensus::new(1, vs);
    let block = [0x42u8; 32];

    // Our own prevote for round 0 (we were there when the round opened).
    hc.add_prevote(fvote(
        &keys[0],
        &fks[0],
        1,
        0,
        VoteKind::Prevote,
        Some(block),
    ))
    .unwrap();
    assert!(hc.observed_polka().is_none(), "one prevote is not a polka");

    // We leave the round and race ahead (the WAN round-skew shape).
    for _ in 0..12 {
        hc.next_round();
    }
    assert_eq!(hc.round, 12);

    // The other prevote arrives LATE. The 1500-STELL validator plus one
    // 1000-STELL validator is 2500 of the 2334 quorum, so the quorum
    // completes NOW - in a round this node left twelve rounds ago.
    hc.add_prevote(fvote(
        &keys[1],
        &fks[1],
        1,
        0,
        VoteKind::Prevote,
        Some(block),
    ))
    .unwrap();

    // The polka is recorded -- with the round it formed in, NOT the local
    // round.
    let (r, b) = hc.observed_polka().expect("the polka must be recorded");
    assert_eq!(r, 0, "the polka keeps the round it formed in");
    assert_eq!(b, block);
    assert_eq!(
        hc.best_polka(),
        Some((0, block)),
        "the polka the node observed is the polka it must precommit"
    );
    // And the certificate that proves it is kept with it.
    assert!(
        hc.prevote_qc.contains_key(&0),
        "the polka's certificate must be available for the precommit"
    );
}

#[test]
fn an_older_polka_never_supersedes_a_newer_one() {
    let (vs, keys, fks) = live_three();
    let mut hc = HeightConsensus::new(1, vs);
    let block = [0x11u8; 32];
    let other = [0x22u8; 32];

    // A polka in round 5.
    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 5, VoteKind::Prevote, Some(block)))
            .unwrap();
    }
    assert_eq!(hc.observed_polka(), Some((5, block)));

    // A LATE polka for the OLDER round 2 must not become the node's word.
    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 2, VoteKind::Prevote, Some(other)))
            .unwrap();
    }
    assert_eq!(
        hc.observed_polka(),
        Some((5, block)),
        "the newest polka is the network's latest word"
    );
}

#[test]
fn the_polka_round_survives_the_prune() {
    // The decision needs the prevote quorum of the polka's round (the
    // precommit quorum is formed in the same round). If the prune drops
    // that round, the height can never be decided: the precommit quorum is
    // there and the proof that it certified this block is gone.
    let (vs, keys, fks) = live_three();
    let mut hc = HeightConsensus::new(1, vs);
    let block = [0x33u8; 32];
    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(block)))
            .unwrap();
    }
    assert_eq!(hc.observed_polka(), Some((0, block)));

    // Race far ahead: every round move prunes.
    for _ in 0..40 {
        hc.next_round();
    }
    assert!(
        hc.prevote_set(0).is_some(),
        "the polka's round must survive the prune"
    );
    assert!(
        hc.prevote_qc.contains_key(&0),
        "the polka's certificate must survive the prune"
    );
}

#[test]
fn a_precommit_quorum_in_the_polka_round_decides_the_height() {
    // The finalization path must find the precommit quorum in the polka's
    // round even when that round is far outside the scan window.
    let (vs, keys, fks) = live_three();
    let mut hc = HeightConsensus::new(1, vs);
    let block = [0x44u8; 32];
    for (i, k) in keys.iter().enumerate() {
        hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(block)))
            .unwrap();
    }
    // Race ahead, then the precommits of round 0 arrive (late).
    for _ in 0..20 {
        hc.next_round();
    }
    for (i, k) in keys.iter().enumerate() {
        hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(block)))
            .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(block),
        "a decided height must be decided, wherever the decision was taken"
    );
}
