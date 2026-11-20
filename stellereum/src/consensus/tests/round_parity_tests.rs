use ed25519_dalek::SigningKey;

use super::*;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n)
        .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
        .collect()
}

#[test]
fn with_an_even_set_there_is_no_parity_phase_to_deadlock_in() {
    // Hash-slot killed the linear parity this test used to pin: consecutive
    // rounds are independent draws, so two nodes at an odd offset can no
    // longer sit in opposite proposer phases forever (the old
    // `(height + round) % 2` alternation). What remains true and is pinned
    // here: determinism per (height, round), and statistical balance.
    let ks = keys(2);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );

    assert_eq!(
        vs.proposer_for(1, 5).unwrap(),
        vs.proposer_for(1, 5).unwrap(),
        "same slot, same proposer"
    );
    let seq: Vec<[u8; 32]> = (0..64u32).map(|r| vs.proposer_for(1, r).unwrap()).collect();
    let zeros = seq
        .iter()
        .filter(|p| *p == &ks[0].verifying_key().to_bytes())
        .count();
    assert!(
        (20..=44).contains(&zeros),
        "no parity structure, ~32/64 each, got {zeros}"
    );
}

#[test]
fn moving_to_the_peers_round_restores_a_shared_phase() {
    // Forward-only advance is what makes convergence safe: both nodes move to the
    // HIGHER round, so they meet rather than chase each other, and the parity they
    // end on is shared. This is what `main.rs` does on an ahead vote.
    let ks = keys(2);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut a = HeightConsensus::new(1, vs.clone());
    let mut b = HeightConsensus::new(1, vs.clone());

    // a is ahead at an odd offset. `advance_to_round` is deliberately capped at
    // +1 per call (round-DoS guard), so a single call cannot jump -- use the
    // explicit peer-sync entry point, which is what the consensus loop calls.
    for _ in 0..7 {
        a.advance_to_round(7);
    }
    assert_eq!(a.round, 7);
    b.sync_round_to(7);
    assert_eq!(b.round, 7, "b moved forward to a's round");
    assert_eq!(
        a.proposer(),
        b.proposer(),
        "same round, same expected proposer"
    );
}

#[test]
fn adopting_a_round_never_moves_a_node_backwards() {
    // A node must not be dragged back by a lagging peer, or it could re-vote a
    // round it already left.
    let ks = keys(2);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut hc = HeightConsensus::new(1, vs);
    // sync_round_to is itself capped at ROUND_LOOKBACK per call (audit F2).
    hc.sync_round_to(ROUND_LOOKBACK);
    assert_eq!(hc.round, ROUND_LOOKBACK);
    hc.sync_round_to(3); // a lagging peer
    assert_eq!(
        hc.round, ROUND_LOOKBACK,
        "the round only ever moves forward"
    );
}

// ============================================================================
// RESTART-LIVELOCK: the one-value-per-round rule is keyed on the proposal's
// SIGNED round, not on the local acceptance round.
// ============================================================================

#[test]
fn a_newer_signed_round_supersedes_a_stale_body_in_the_same_local_round() {
    let ks = keys(3);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut hc = HeightConsensus::new(1, vs);
    hc.round = 26;
    let proposer = hc.proposer().expect("the schedule names a proposer");
    let stale = [0xA1u8; 32]; // signed at round 25 by a pre-restart process
    let current = [0xB2u8; 32]; // the scheduled body for round 26 (re-stamped)

    // The delayed past-round body is still admissible as a VALUE (lock
    // rescue / one-round lag) ...
    hc.receive_proposal_for_at(proposer, stale, Some(proposer), 25)
        .expect("a delayed past-round body is admissible");
    assert_eq!(hc.proposal, Some((proposer, stale)));
    assert_eq!(hc.proposal_round, Some(26), "accepted in the local round");
    assert_eq!(hc.proposal_signed_round, Some(25), "signed identity kept");
    assert!(hc.has_live_proposal());

    // ... but it must not own round 26: the body the proposer signed FOR 26
    // supersedes it. This is the live failure ("proposal already recorded for
    // this round" followed by a nil/silent vote at the stale round).
    hc.receive_proposal_for_at(proposer, current, Some(proposer), 26)
        .expect("the current round's body must supersede the stale one");
    assert_eq!(hc.proposal, Some((proposer, current)));
    assert_eq!(hc.proposal_round, Some(26));
    assert_eq!(hc.proposal_signed_round, Some(26));

    // Equivocation is unchanged: a second DISTINCT body for the SAME signed
    // round is still refused, and the first seating survives.
    let equivocation = [0xC3u8; 32];
    let err = hc
        .receive_proposal_for_at(proposer, equivocation, Some(proposer), 26)
        .expect_err("same signed round + different hash is equivocation");
    assert!(err.contains("already recorded"), "got: {err}");
    assert_eq!(hc.proposal, Some((proposer, current)));

    // A stale signed round can never displace a newer one.
    assert!(hc
        .receive_proposal_for_at(proposer, stale, Some(proposer), 25)
        .is_err());
    assert_eq!(hc.proposal, Some((proposer, current)));

    // Re-receipt of the identical body stays idempotent-Ok.
    hc.receive_proposal_for_at(proposer, current, Some(proposer), 26)
        .expect("identical rebroadcast is idempotent");
}
