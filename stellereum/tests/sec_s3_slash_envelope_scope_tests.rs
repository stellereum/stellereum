//! SEC-S3 regression: the slash primitives' per-offense dedup key commits the
//! EQUIVOCATION ENVELOPE's scope fields, so those fields must be validated
//! against the signed content before the key is consumed.
//!
//! * `EquivocationEvidence::offense_key` commits `envelope.shard_id`.
//! * `ProposalEquivocationEvidence::offense_key` commits `envelope.round`.
//!
//! The block-carried path canonicalizes through
//! `verify_equivocation_evidence` / `verify_proposal_equivocation_evidence`
//! (which enforce both), so the live path was safe. But the primitives
//! themselves accepted an envelope whose claimed scope did not match the
//! signed votes/blocks: re-labelling ONE genuine offense under a different
//! shard/round produced a different dedup key and burned another 5% of the
//! offender's stake per replay (and, for proposals, two honest cross-round
//! proposals were treated as a slashable offense at all). Fail closed: an
//! envelope naming another shard/round is not evidence for these bytes.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{
    register_validator_pq_key, verify_proposer_signature, EquivocationEvidence,
    ProposalEquivocationEvidence, Vote, VoteKind,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::{StakingLedger, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

fn bond_floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn bonded(validator: [u8; 32]) -> StakingLedger {
    let mut l = StakingLedger::new();
    l.bond(validator, bond_floor(), 0)
        .expect("fixture bond must succeed");
    l
}

#[test]
fn relabelled_vote_evidence_shard_cannot_burn_the_same_offense_twice() {
    let sk = SigningKey::generate(&mut OsRng);
    let voter = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(0x5A);
    register_validator_pq_key(voter, PqScheme::Falcon512, fk.public_key.clone());

    let a = Vote::sign_with_falcon(&sk, &fk, 10, 0, VoteKind::Prevote, Some([0x11u8; 32]));
    let b = Vote::sign_with_falcon(&sk, &fk, 10, 0, VoteKind::Prevote, Some([0x22u8; 32]));
    assert!(a.verify() && b.verify(), "fixture votes must verify");

    let ev = EquivocationEvidence::new(voter, a, b);
    assert_eq!(ev.shard_id, MASTERCHAIN_SHARD);

    let mut ledger = bonded(voter);
    let first = ledger
        .slash_equivocation_verified(&ev)
        .expect("genuine same-shard double-vote must slash");
    assert!(first > 0, "first processing must burn");

    // Same genuine votes, one envelope field re-labelled. The dedup key
    // commits the envelope shard, so BEFORE the fix this burned 5% AGAIN.
    let mut relabelled = ev.clone();
    relabelled.shard_id = ev.shard_id.wrapping_add(1);
    let bond_before = ledger.validators[&voter].self_bond;
    let burned = ledger
        .slash_equivocation_verified(&relabelled)
        .expect("a mismatched envelope is skipped, not an error");
    assert_eq!(
        burned, 0,
        "an envelope naming another shard is not evidence for these votes"
    );
    assert_eq!(
        ledger.validators[&voter].self_bond, bond_before,
        "the relabelled replay must not touch stake"
    );

    // The genuine envelope is still deduped by the offense key (one slash).
    assert_eq!(ledger.slash_equivocation_verified(&ev).unwrap(), 0);
}

#[test]
fn relabelled_proposal_evidence_round_cannot_burn_twice_and_cross_round_pair_is_not_an_offense() {
    let sk = SigningKey::generate(&mut OsRng);
    let proposer = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(0x5B);
    register_validator_pq_key(proposer, PqScheme::Falcon512, fk.public_key.clone());

    let mk = |ts: u64, round: u32| {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 7,
            round,
            proposer,
            timestamp: ts,
            ..Default::default()
        };
        b.sign_block(&sk);
        // `verify_proposer_signature` is Falcon-only; attach the Falcon half.
        let hash = b.compute_hash();
        b.validator_signatures
            .push((fk.validator_id(), fk.sign(&hash)));
        b
    };

    let a = mk(1_000, 3);
    let b = mk(2_000, 3);
    assert!(
        verify_proposer_signature(&a) && verify_proposer_signature(&b),
        "fixture blocks must verify"
    );

    // `new` takes block_a's SIGNED round, so the envelope is canonical.
    let ev = ProposalEquivocationEvidence::new(proposer, a.clone(), b.clone());
    assert_eq!(ev.round, 3);

    let mut ledger = bonded(proposer);
    let first = ledger
        .slash_proposal_equivocation_verified(&ev)
        .expect("genuine same-round double-propose must slash");
    assert!(first > 0, "first processing must burn");

    // Same genuine blocks, claimed round re-labelled. The dedup key commits
    // the claimed round, so BEFORE the fix this burned 5% AGAIN.
    let mut relabelled = ev.clone();
    relabelled.round = 4;
    let bond_before = ledger.validators[&proposer].self_bond;
    let burned = ledger
        .slash_proposal_equivocation_verified(&relabelled)
        .expect("a mismatched envelope is skipped, not an error");
    assert_eq!(
        burned, 0,
        "the claimed round must equal BOTH blocks' signed rounds"
    );
    assert_eq!(
        ledger.validators[&proposer].self_bond, bond_before,
        "the relabelled replay must not touch stake"
    );

    // An HONEST cross-round re-proposal at one height is not an offense at all
    // (A in round 3, B in round 4). `new` claims block_a's round (3), so the
    // B-side signed round (4) disagrees and the primitive must refuse.
    let honest_b = mk(3_000, 4);
    assert!(verify_proposer_signature(&honest_b));
    let cross_round = ProposalEquivocationEvidence::new(proposer, a, honest_b);
    assert_eq!(
        ledger
            .slash_proposal_equivocation_verified(&cross_round)
            .unwrap(),
        0,
        "cross-round proposals are not slashable (the verifier refuses them too)"
    );
}
