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
use stellereum::consensus::{BlockHash, QuorumCertificate, ValidatorSet, VoteKind};
use stellereum::light_client::{Checkpoint, LightClient, LightHeader, ValidatorSetRotation};

// This file uses `fvote` with file-local keys (`pq_for` below); `falcon_set`
// in the shared helper covers the fixed-seed case and is unused here.
#[allow(dead_code)]
#[path = "support/falcon_votes.rs"]
mod falcon_votes;

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

/// A precommit certificate for `hash` at `height`, compiled by the
/// production committee path against the FULL set `vs` and bound to `parent`.
/// Refusal fixtures fall through to the envelope-less shape: below quorum, or
/// with non-member signers, no PQ envelope can be compiled, and the
/// envelope-less shape is unconditionally invalid under FULL-PQ.
fn cert(
    signers: &[SigningKey],
    fks: &[stellereum::post_quantum::FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    hash: BlockHash,
    parent: &[u8; 32],
) -> QuorumCertificate {
    use stellereum::consensus::VoteSet;
    let mut set = VoteSet::new();
    let mut ed_sigs = Vec::new();
    for (k, fk) in signers.iter().zip(fks.iter()) {
        let v = falcon_votes::fvote(k, fk, height, 0, VoteKind::Precommit, Some(hash));
        if set
            .add(v.clone(), vs, height, 0, VoteKind::Precommit)
            .is_ok()
        {
            ed_sigs.push((v.voter, v.ed25519_signature().to_vec()));
        }
    }
    if let Some(qc) = set.certificate(Some(hash), vs, parent) {
        return qc;
    }
    QuorumCertificate {
        shard_id: 0,
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: ed_sigs,
    }
}

/// Falcon companions for file-local Ed keys, registered globally like
/// `falcon_set` does. `tag` separates Falcon-key domains so fixtures sharing
/// one test binary never collide.
fn pq_for(keys: &[SigningKey], tag: u8) -> Vec<stellereum::post_quantum::FalconKeypair> {
    use stellereum::consensus::register_validator_pq_key;
    use stellereum::post_quantum::{FalconKeypair, PqScheme};
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = FalconKeypair::generate_from_seed(tag.wrapping_add(i as u8));
            register_validator_pq_key(
                k.verifying_key().to_bytes(),
                PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect()
}

fn header(
    height: u64,
    prev_hash: BlockHash,
    body_tag: BlockHash,
    signers: &[SigningKey],
    fks: &[stellereum::post_quantum::FalconKeypair],
    vs: &ValidatorSet,
) -> LightHeader {
    let proposer = signers[0].verifying_key().to_bytes();
    let timestamp = 1_700_000_000 + height;
    let state_root = [0xA0u8; 32];
    let hdr = stellereum::sharding::BlockHeader {
        shard_id: 0,
        height,
        round: 0,
        prev_hash,
        state_root,
        body_commitment: body_tag,
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        timestamp,
        proposer,
    };
    let block_hash = hdr.compute_hash();
    LightHeader {
        height,
        prev_hash,
        state_root,
        block_hash,
        timestamp,
        proposer,
        cert: cert(signers, fks, vs, height, block_hash, &prev_hash),
        signatures: Vec::new(),
        shard_id: 0,
        round: 0,
        body_commitment: Some(body_tag),
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

/// A client anchored at height 1 on `old_keys`' set, already advanced to a
/// height-2 tip — the position a rotation starts from.
fn client_at_tip2(
    old_keys: &[SigningKey],
    old_fks: &[stellereum::post_quantum::FalconKeypair],
) -> (LightClient, BlockHash) {
    let validators = set_of(old_keys);
    let hdr1 = stellereum::sharding::BlockHeader {
        shard_id: 0,
        height: 1,
        round: 0,
        prev_hash: [0u8; 32],
        state_root: [0xA0u8; 32],
        body_commitment: hash_of(0x10),
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        timestamp: 0,
        proposer: [0u8; 32],
    };
    let anchor_hash = hdr1.compute_hash();
    let anchor = Checkpoint::from_block_header(
        hdr1,
        cert(
            &old_keys[..3],
            &old_fks[..3],
            &validators,
            1,
            anchor_hash,
            &[0u8; 32],
        ),
    );
    let mut lc = LightClient::new(validators.clone(), anchor).expect("anchor verifies");
    assert_eq!(lc.validator_set_height(), 1);
    let tip_hdr = header(
        2,
        anchor_hash,
        hash_of(0x20),
        &old_keys[..3],
        &old_fks[..3],
        &validators,
    );
    let tip_hash = tip_hdr.block_hash;
    lc.apply_header(tip_hdr).expect("same-set advance verifies");
    (lc, tip_hash)
}

#[test]
fn same_set_advance_verifies() {
    // A header at h+1 carrying an old-set quorum is accepted under the
    // anchored set, and the set marker does not move on a plain advance.
    let old_keys = keys_from(1, 4);
    let old_fks = pq_for(&old_keys, 0xA0);
    let old_vs = set_of(&old_keys);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys, &old_fks);
    assert_eq!(lc.tip_height(), 2);
    let next_hdr = header(
        3,
        tip_hash,
        hash_of(0x21),
        &old_keys[1..],
        &old_fks[1..],
        &old_vs,
    );
    let next_hash = next_hdr.block_hash;
    lc.apply_header(next_hdr)
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
    let old_fks = pq_for(&old_keys, 0xA0);
    let old_vs = set_of(&old_keys);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys, &old_fks);
    let outsiders = keys_from(0xF0, 4);
    let outsider_fks = pq_for(&outsiders, 0xA2);
    let forged = header(
        3,
        tip_hash,
        hash_of(0xFF),
        &outsiders,
        &outsider_fks,
        &old_vs,
    );
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
    let old_fks = pq_for(&old_keys, 0xA0);
    let old_vs = set_of(&old_keys);
    let new_keys = keys_from(0x41, 4);
    let new_fks = pq_for(&new_keys, 0xA1);
    let new_vs = set_of(&new_keys);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys, &old_fks);

    let rot_hdr = header(
        3,
        tip_hash,
        hash_of(0x30),
        &old_keys[..3],
        &old_fks[..3],
        &old_vs,
    );
    let rotation_hash = rot_hdr.block_hash;
    let rotation = ValidatorSetRotation::new(rot_hdr, new_vs.clone());
    assert_eq!(rotation.effective_height(), 3);
    lc.rotate_validator_set(rotation)
        .expect("an old-quorum rotation must be accepted");
    assert_eq!(lc.tip_height(), 3);
    assert_eq!(lc.tip_hash(), rotation_hash);
    assert_eq!(lc.validator_set_height(), 3);
    assert_eq!(lc.validators.validators, set_of(&new_keys).validators);

    // The chain continues: a header certified by the NEW set verifies.
    lc.apply_header(header(
        4,
        rotation_hash,
        hash_of(0x31),
        &new_keys[..3],
        &new_fks[..3],
        &new_vs,
    ))
    .expect("post-rotation headers verify under the new set");
    assert_eq!(lc.tip_height(), 4);
}

#[test]
fn rotation_without_old_supermajority_is_refused() {
    // One old-set signature is not a quorum (4 at power 1 needs 3): the
    // rotation point is uncertified, so the set must not move — fail closed,
    // with the client exactly where it was.
    let old_keys = keys_from(1, 4);
    let old_fks = pq_for(&old_keys, 0xA0);
    let old_vs = set_of(&old_keys);
    let new_keys = keys_from(0x41, 4);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys, &old_fks);
    let before_set = lc.validators.clone();

    let rotation = ValidatorSetRotation::new(
        header(
            3,
            tip_hash,
            hash_of(0x30),
            &old_keys[..1],
            &old_fks[..1],
            &old_vs,
        ),
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
    let old_fks = pq_for(&old_keys, 0xA0);
    let old_vs = set_of(&old_keys);
    let new_keys = keys_from(0x41, 4);
    let new_fks = pq_for(&new_keys, 0xA1);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys, &old_fks);

    let rotation = ValidatorSetRotation::new(
        header(
            3,
            tip_hash,
            hash_of(0x30),
            &new_keys[..3],
            &new_fks[..3],
            &old_vs,
        ),
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
    let old_fks = pq_for(&old_keys, 0xA0);
    let old_vs = set_of(&old_keys);
    let new_keys = keys_from(0x41, 4);
    let new_vs = set_of(&new_keys);
    let (mut lc, tip_hash) = client_at_tip2(&old_keys, &old_fks);

    let rot_hdr = header(
        3,
        tip_hash,
        hash_of(0x30),
        &old_keys[..3],
        &old_fks[..3],
        &old_vs,
    );
    let rotation_hash = rot_hdr.block_hash;
    lc.rotate_validator_set(ValidatorSetRotation::new(rot_hdr, new_vs.clone()))
        .expect("rotation must succeed first");

    let stale = header(
        4,
        rotation_hash,
        hash_of(0x99),
        &old_keys[..3],
        &old_fks[..3],
        &new_vs,
    );
    assert!(
        lc.apply_header(stale).is_err(),
        "a header certified only by the superseded set must be refused after rotation"
    );
    assert_eq!(lc.tip_height(), 3);
    assert_eq!(lc.validators.validators, set_of(&new_keys).validators);
    assert_eq!(lc.validator_set_height(), 3);
}
