//! Validator-set ROTATION for the light client.
//!
//! The anchor is `(set, height)`: a header at `h + 1` verifies against the set
//! in force at `h + 1`, and the set in force changes only through
//! [`LightClient::rotate_validator_set`]. These tests pin the rotation rule:
//! a supermajority of the OLD set must sign the rotation point, and anything
//! else fails closed — including headers certified only by the superseded set
//! after the rotation.
//!
//! The theme, as everywhere in this module: nothing the client concludes may
//! rest on anything it did not verify. A rotation is a conclusion about who
//! speaks for the chain, so the bar is the same quorum bar as finality.

use ed25519_dalek::SigningKey;
use stellereum::consensus::{BlockHash, QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::light_client::{Checkpoint, LightClient, LightHeader, ValidatorSetRotation};

fn keys_from(seed_base: u8, n: usize) -> Vec<SigningKey> {
    (0..n)
        .map(|i| SigningKey::from_bytes(&[seed_base.wrapping_add(i as u8); 32]))
        .collect()
}

fn set_of(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn hash_of(n: u8) -> BlockHash {
    [n; 32]
}

/// A precommit certificate for `hash` at `height`, signed by `signers`.
fn cert(signers: &[SigningKey], height: u64, hash: BlockHash) -> QuorumCertificate {
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: signers
            .iter()
            .map(|k| {
                let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

fn header(
    height: u64,
    prev_hash: BlockHash,
    block_hash: BlockHash,
    signers: &[SigningKey],
) -> LightHeader {
    LightHeader {
        height,
        prev_hash,
        state_root: [0xA0u8; 32],
        block_hash,
        timestamp: 1_700_000_000 + height,
        proposer: signers[0].verifying_key().to_bytes(),
        cert: cert(signers, height, block_hash),
        signatures: Vec::new(),
    }
}

/// A client anchored at height 1 on `old_keys`' set, already advanced to a
/// height-2 tip — the position a rotation starts from.
fn client_at_tip2(old_keys: &[SigningKey]) -> (LightClient, BlockHash) {
    let validators = set_of(old_keys);
    let anchor_hash = hash_of(0x10);
    let anchor = Checkpoint::new(
        1,
        anchor_hash,
        [0u8; 32],
        [0xA0u8; 32],
        cert(&old_keys[..3], 1, anchor_hash),
    );
    let mut lc = LightClient::new(validators, anchor).expect("anchor verifies");
    assert_eq!(lc.validator_set_height(), 1);
    let tip_hash = hash_of(0x20);
    lc.apply_header(header(2, anchor_hash, tip_hash, &old_keys[..3]))
        .expect("same-set advance verifies");
    (lc, tip_hash)
}

#[test]
fn same_set_advance_verifies() {
    // A header at h+1 carrying an old-set quorum is accepted under the
    // anchored set, and the set marker does not move on a plain advance.
    let old_keys = keys_from(1, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys);
    assert_eq!(lc.tip_height(), 2);
    let next_hash = hash_of(0x21);
    lc.apply_header(header(3, tip_hash, next_hash, &old_keys[1..]))
        .expect("a quorum of the anchored set advances the chain");
    assert_eq!(lc.tip_height(), 3);
    assert_eq!(lc.tip_hash(), next_hash);
    assert_eq!(lc.validator_set_height(), 1);
}

#[test]
fn forged_header_is_refused() {
    // A header whose certificate is signed by outsiders — keys with no power
    // in the anchored set — carries no validator power and is refused.
    let old_keys = keys_from(1, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys);
    let outsiders = keys_from(0xF0, 4);
    let forged = header(3, tip_hash, hash_of(0xFF), &outsiders);
    assert!(
        lc.apply_header(forged).is_err(),
        "an outsider-certified header must never advance the client"
    );
    assert_eq!(lc.tip_height(), 2);
}

#[test]
fn rotation_with_old_quorum_is_accepted() {
    // The rotation point (height 3) is certified by a supermajority of the OLD
    // set; the client adopts the header AND the new set, effective at 3, and
    // the chain continues under the new set's authority.
    let old_keys = keys_from(1, 4);
    let new_keys = keys_from(0x41, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys);

    let rotation_hash = hash_of(0x30);
    let rotation = ValidatorSetRotation::new(
        header(3, tip_hash, rotation_hash, &old_keys[..3]),
        set_of(&new_keys),
    );
    assert_eq!(rotation.effective_height(), 3);
    lc.rotate_validator_set(rotation)
        .expect("an old-quorum rotation must be accepted");
    assert_eq!(lc.tip_height(), 3);
    assert_eq!(lc.tip_hash(), rotation_hash);
    assert_eq!(lc.validator_set_height(), 3);
    assert_eq!(lc.validators.validators, set_of(&new_keys).validators);

    // The chain continues: a header certified by the NEW set verifies.
    let next_hash = hash_of(0x31);
    lc.apply_header(header(4, rotation_hash, next_hash, &new_keys[..3]))
        .expect("post-rotation headers verify under the new set");
    assert_eq!(lc.tip_height(), 4);
}

#[test]
fn rotation_without_old_supermajority_is_refused() {
    // One old-set signature is not a quorum (4 at power 1 needs 3): the
    // rotation point is uncertified, so the set must not move — fail closed,
    // with the client exactly where it was.
    let old_keys = keys_from(1, 4);
    let new_keys = keys_from(0x41, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys);
    let before_set = lc.validators.clone();

    let rotation = ValidatorSetRotation::new(
        header(3, tip_hash, hash_of(0x30), &old_keys[..1]),
        set_of(&new_keys),
    );
    assert!(
        lc.rotate_validator_set(rotation).is_err(),
        "a rotation without an old-set supermajority must be refused"
    );
    assert_eq!(lc.validators.validators, before_set.validators);
    assert_eq!(lc.validator_set_height(), 1);
    assert_eq!(lc.tip_height(), 2);
}

#[test]
fn rotation_signed_by_the_new_set_for_itself_is_refused() {
    // Self-adoption: the NEW set certifies its own rotation point. The point
    // must be signed by the CURRENT (old) set, so a disjoint new set signing
    // for itself carries no old power and is refused.
    let old_keys = keys_from(1, 4);
    let new_keys = keys_from(0x41, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys);

    let rotation = ValidatorSetRotation::new(
        header(3, tip_hash, hash_of(0x30), &new_keys[..3]),
        set_of(&new_keys),
    );
    assert!(
        lc.rotate_validator_set(rotation).is_err(),
        "a set must never be able to adopt itself"
    );
    assert_eq!(lc.validator_set_height(), 1);
    assert_eq!(lc.tip_height(), 2);
}

#[test]
fn stale_set_header_is_refused_after_rotation() {
    // After rotating to a disjoint set, a header certified ONLY by the
    // superseded set is refused: it carries no power under the set in force.
    // (A replay of an already-taken height would additionally trip the shape
    // gate; this header is at a fresh height, so the refusal is purely the
    // set change doing its job.)
    let old_keys = keys_from(1, 4);
    let new_keys = keys_from(0x41, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys);

    let rotation_hash = hash_of(0x30);
    lc.rotate_validator_set(ValidatorSetRotation::new(
        header(3, tip_hash, rotation_hash, &old_keys[..3]),
        set_of(&new_keys),
    ))
    .expect("rotation must succeed first");

    let stale = header(4, rotation_hash, hash_of(0x99), &old_keys[..3]);
    assert!(
        lc.apply_header(stale).is_err(),
        "a header certified only by the superseded set must be refused after rotation"
    );
    assert_eq!(lc.tip_height(), 3);
    assert_eq!(lc.validators.validators, set_of(&new_keys).validators);
    assert_eq!(lc.validator_set_height(), 3);
}
