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
