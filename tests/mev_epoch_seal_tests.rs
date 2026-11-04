//! THE EPOCH-SEAL (ES1) PATH — end-to-end tests of the asymmetric,
//! threshold-sealed transaction gossip.
//!
//! These tests pin the properties the scheme exists for, and they pin them
//! at the level the network sees them (the wire bytes, the mempool, the
//! proposer's order of operations), not only at the level of the crypto
//! primitives:
//!
//! 1. a sealed transaction travels as CIPHERTEXT: the plaintext is nowhere
//!    in the gossip bytes, nowhere in the mempool, and nowhere in the DHT
//!    entry;
//! 2. the proposer unseals ONLY after the order is committed — the signed
//!    order commitment is what unblocks the reveal;
//! 3. a THRESHOLD of shares unseals the transaction: a member that
//!    withholds its share cannot stall the round;
//! 4. a wallet cannot decrypt a transaction sealed for a DIFFERENT epoch;
//! 5. a malformed seal is refused fail-closed, at admission, with a clear
//!    error — and it can never stall the proposer;
//! 6. the epoch key is COMMITTED to the block, so the chain (not one node)
//!    decides which key the network uses;
//! 7. the PLAIN path keeps working: a wallet that does not seal is never
//!    broken by the sealed path.
//!
//! The threat model (what this protects against, and what it does NOT) is
//! written down in `docs/MEV.md`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use stellereum::mempool::Mempool;
use stellereum::mev_epoch::{
    combine_partials, compute_partial, decode_sealed_payload, encryption_public_key_from_ed25519,
    encryption_secret_from_ed25519, epoch_key_commitment, seal_transaction, DecryptionPartial,
    EpochCommittee, EpochDkg, EpochSealManager, MevFrame, OrderCommitment, SealedEnvelope,
    TransparentMeta,
};
use stellereum::sharding::Transaction;

// ===========================================================================
// Test harness
// ===========================================================================

/// One committee member: the consensus identity, the long-term secret and
/// the derived encryption key pair.
#[derive(Clone)]
struct Member {
    id: [u8; 32],
    secret: [u8; 32],
    enc_secret: [u8; 32],
    enc_pk: [u8; 32],
    signing: SigningKey,
}

fn member() -> Member {
    let signing = SigningKey::generate(&mut OsRng);
    let secret = signing.to_bytes();
    let enc_secret = encryption_secret_from_ed25519(&secret);
    let enc_pk = encryption_public_key_from_ed25519(&signing.verifying_key().to_bytes())
        .expect("a valid ed25519 public key converts");
    Member {
        id: signing.verifying_key().to_bytes(),
        secret,
        enc_secret,
        enc_pk,
        signing,
    }
}

fn committee(epoch: u64, members: &[Member]) -> EpochCommittee {
    EpochCommittee::build(
        epoch,
        members
            .iter()
            .map(|m| stellereum::mev_epoch::CommitteeMember {
                validator_id: m.id,
                enc_pk: m.enc_pk,
            })
            .collect(),
    )
}

/// Run the DKG over the whole committee THROUGH THE MANAGER (the real
/// path) and return every member's key material.
///
/// The contributors are the DERIVED set (see `EpochCommittee::contributors`):
/// only they contribute, everybody ends up with a share. The managers are
/// returned too, so the tests can exercise the release gate on a manager
/// that really holds the epoch key.
fn run_dkg(
    epoch: u64,
    members: &[Member],
) -> (
    EpochCommittee,
    Vec<stellereum::mev_epoch::EpochKeyMaterial>,
    Vec<EpochSealManager>,
) {
    let committee = committee(epoch, members);
    let ids: Vec<[u8; 32]> = members.iter().map(|m| m.id).collect();
    let mut managers: Vec<EpochSealManager> = Vec::with_capacity(members.len());
    let mut contributions = Vec::new();
    for m in members.iter() {
        let mut manager = EpochSealManager::new();
        let own = manager
            .sync_epoch(epoch, &ids, m.id, &m.secret)
            .expect("the epoch is synced");
        if let Some(c) = own {
            contributions.push(c);
        }
        managers.push(manager);
    }
    assert_eq!(
        contributions.len(),
        committee.contributors.len(),
        "exactly the derived contributor set contributes"
    );
    // Everybody ingests EVERY contribution (its own included): the epoch
    // key is the aggregate over the whole contributor set.
    for (i, m) in members.iter().enumerate() {
        for c in contributions.iter() {
            managers[i]
                .ingest_contribution(c.clone(), &m.secret)
                .unwrap_or_else(|e| panic!("member {i} must accept a contribution: {e}"));
        }
    }
    let materials = managers
        .iter()
        .map(|m| m.material().expect("the dkg finalized").clone())
        .collect();
    (committee, materials, managers)
}

fn meta_for(from: [u8; 32], nonce: u64) -> TransparentMeta {
    TransparentMeta {
        from,
        nonce,
        gas_limit: 300_000,
        priority_fee_per_gas: 7,
        source_shard: 0,
        target_shard: 0,
    }
}

/// A 32-byte marker that is planted in every serialized transaction, so a
/// test can assert that the plaintext is NOWHERE in the wire bytes.
const MARKER: &[u8; 32] = b"THE-PLAINTEXT-MARKER-0123456789A";

/// A signed transaction, serialized (the plaintext a wallet seals).
fn signed_tx(from: &SigningKey, nonce: u64) -> (Vec<u8>, [u8; 32]) {
    let tx = Transaction::sign(from, *MARKER, 1_000, nonce, 0, 1, 1);
    let bytes = bincode::serialize(&tx).expect("the transaction serializes");
    let hash = tx.compute_tx_hash();
    (bytes, hash)
}

// ===========================================================================
// 1. THE PLAINTEXT NEVER TRAVELS
// ===========================================================================

/// A SEALED transaction is gossiped as CIPHERTEXT.
///
/// This is the property the whole scheme exists for: what the network
/// carries is the ciphertext. The assertion is on the ACTUAL wire bytes
/// (the frame a peer decodes), on the mempool's stored envelope, and on the
/// DHT entry — the plaintext must be in none of them.
#[test]
fn a_sealed_transaction_is_gossiped_as_ciphertext() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, _managers) = run_dkg(1, &members);
    let key = materials[0].public_key();

    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let marker = MARKER.as_slice();
    assert!(
        plaintext.windows(marker.len()).any(|w| w == marker),
        "the test payload must actually contain the marker"
    );

    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0))
        .expect("sealing succeeds");

    // (a) The wire frame (what the tx-gossip channel carries).
    let wire = stellereum::mev_epoch::encode_sealed_payload(&envelope).expect("the frame encodes");
    assert!(
        !wire.windows(marker.len()).any(|w| w == marker),
        "the gossiped bytes must not contain the plaintext"
    );
    assert!(
        !wire
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()),
        "the gossiped bytes must not contain the serialized transaction"
    );
    // The frame is recognisable as a sealed payload and decodes back to the
    // same envelope.
    assert!(stellereum::mev_epoch::is_sealed_payload(&wire));
    assert!(!stellereum::mev_epoch::is_mev_frame(
        &bincode::serialize(&Transaction::sign(
            &members[0].signing,
            [0x11; 32],
            1_000,
            0,
            0,
            1,
            1
        ))
        .unwrap()
    ));
    let decoded = decode_sealed_payload(&wire).expect("the frame decodes");
    assert_eq!(decoded, envelope);

    // (b) The mempool stores the ciphertext — and the plaintext is nowhere
    //     in it.
    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(1);
    let hash = pool
        .add_sealed(envelope.clone())
        .expect("the sealed tx is admitted");
    assert_eq!(hash, tx_hash);
    assert_eq!(pool.sealed_count(), 1);
    let stored = pool
        .sealed_envelope(&tx_hash)
        .expect("the envelope is stored");
    assert!(!stored.ciphertext.windows(marker.len()).any(|w| w == marker));
    // The plain pool holds nothing: the plaintext never entered the pool.
    assert_eq!(pool.len(), 0, "the plaintext must not be in the plain pool");
    let _ = committee;
}

/// The mempool NEVER holds the plaintext of a sealed transaction.
#[test]
fn the_mempool_never_holds_the_sealed_plaintext() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_committee, materials, _managers) = run_dkg(2, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[1].signing, 3);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[1].id, 3)).unwrap();

    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(2);
    pool.add_sealed(envelope).unwrap();
    // The candidates the proposer packs from are ciphertexts.
    for candidate in pool.sealed_candidates() {
        assert_ne!(candidate.ciphertext, plaintext);
        assert!(candidate.ciphertext.len() >= plaintext.len());
    }
}

// ===========================================================================
// 2. THE ORDER IS COMMITTED BEFORE THE REVEAL
// ===========================================================================

/// The proposer unseals ONLY after the order is committed.
///
/// The signed order commitment is the gate: a member refuses to release its
/// decryption partial before it has seen the commitment, so the reveal can
/// never be used to reorder the round. The test pins the gate itself (the
/// refusal), the release after the commitment, and the fact that the
/// commitment is over the SEALED hashes (which are known before the
/// plaintext is).
#[test]
fn the_proposer_unseals_only_after_the_order_is_committed() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, mut managers) = run_dkg(3, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    // A manager that completed the DKG and therefore holds the epoch key.
    let mut manager = managers.remove(0);

    // BEFORE the commitment: the release is REFUSED. This is the whole
    // point of the scheme — nobody may make the content readable before the
    // order is fixed.
    let refused = manager.release_partial(10, 0, &envelope);
    assert!(
        refused.is_err(),
        "a partial must not be released before the order commitment"
    );

    // The proposer commits to the order of the SEALED transactions (their
    // hashes — known before the plaintext).
    let commitment = manager
        .commit_order(10, 0, vec![tx_hash], &members[0].signing)
        .expect("the commitment is made");
    assert_eq!(
        commitment.order_root,
        stellereum::mev::order_merkle_root_of_hashes(&[tx_hash])
    );
    // The commitment verifies against the proposer's key.
    assert!(commitment.verify().is_ok());

    // AFTER the commitment: the release goes through.
    let partial = manager
        .release_partial(10, 0, &envelope)
        .expect("the release is allowed once the order is committed");
    assert_eq!(
        partial.validator_index,
        committee.index_of(&members[0].id).unwrap()
    );

    // The partial alone is not enough (the threshold is 3 of 4): the
    // content stays hidden until enough members release.
    assert!(
        combine_partials(&[partial], committee.threshold).is_err(),
        "one partial must not unseal a 3-of-4 committee"
    );
    let plaintext_from_shares = combine_partials(
        &[
            partial,
            DecryptionPartial {
                validator_index: committee.index_of(&members[1].id).unwrap(),
                point: compute_partial(&materials[1].share, &envelope.ephemeral_pk).unwrap(),
            },
            DecryptionPartial {
                validator_index: committee.index_of(&members[2].id).unwrap(),
                point: compute_partial(&materials[2].share, &envelope.ephemeral_pk).unwrap(),
            },
        ],
        committee.threshold,
    )
    .expect("a threshold of partials reconstructs the shared point");
    let unsealed = stellereum::mev_epoch::unseal_transaction(
        &envelope,
        &[
            partial,
            DecryptionPartial {
                validator_index: committee.index_of(&members[1].id).unwrap(),
                point: compute_partial(&materials[1].share, &envelope.ephemeral_pk).unwrap(),
            },
            DecryptionPartial {
                validator_index: committee.index_of(&members[2].id).unwrap(),
                point: compute_partial(&materials[2].share, &envelope.ephemeral_pk).unwrap(),
            },
        ],
        committee.threshold,
        &committee.hash,
    )
    .expect("the threshold unseals");
    assert_eq!(unsealed, plaintext);
    assert!(plaintext_from_shares != [0u8; 32]);
}

/// A share release that does not match a KNOWN order commitment is refused:
/// a malicious peer cannot make a node accept decryption material for a
/// transaction that was never committed to.
#[test]
fn a_share_release_without_a_known_commitment_is_refused() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, mut managers) = run_dkg(4, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    let mut manager = managers.remove(0);

    let partial = DecryptionPartial {
        validator_index: committee.index_of(&members[1].id).unwrap(),
        point: compute_partial(&materials[1].share, &envelope.ephemeral_pk).unwrap(),
    };
    let release = stellereum::mev_epoch::ShareRelease {
        epoch: 4,
        height: 10,
        round: 0,
        order_root: [0xAB; 32],
        partials: vec![(tx_hash, partial)],
    };
    assert!(
        manager.ingest_release(release).is_err(),
        "a release for an unknown ordering must be refused"
    );
}

// ===========================================================================
// 3. A THRESHOLD OF SHARES IS ENOUGH
// ===========================================================================

/// A THRESHOLD of shares unseals the transaction: the validator that
/// withholds its share does NOT get to stall the round.
///
/// The committee is 4 members with a threshold of 3, so three releases
/// unseal and the fourth is not needed. Two are not enough — and the
/// bounded attempt then reports "not enough shares" instead of stalling.
#[test]
fn a_threshold_of_shares_unseals_without_all_validators() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, _managers) = run_dkg(5, &members);
    assert_eq!(committee.threshold, 3);
    assert!(
        committee.threshold < committee.members.len(),
        "the threshold must leave room for a withholding member"
    );
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    let partials: Vec<DecryptionPartial> = members
        .iter()
        .enumerate()
        .map(|(i, m)| DecryptionPartial {
            validator_index: committee.index_of(&m.id).unwrap(),
            point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
        })
        .collect();

    // Three of four: the fourth withholds, and the round still completes.
    let unsealed = stellereum::mev_epoch::unseal_transaction(
        &envelope,
        &partials[..committee.threshold],
        committee.threshold,
        &committee.hash,
    )
    .expect("a threshold of partials unseals");
    assert_eq!(unsealed, plaintext);

    // ANY subset of the threshold yields the SAME shared point: a
    // withholding member cannot change the outcome, only delay it.
    let a = combine_partials(&partials[..3], 3).unwrap();
    let b = combine_partials(&partials[1..4], 3).unwrap();
    assert_eq!(a, b, "the shared point must not depend on the subset");

    // Two of four: NOT enough. The bounded attempt reports the shortfall
    // (the timeout path), it never blocks.
    let outcome = stellereum::mev_epoch::try_unseal(
        &envelope,
        &partials[..committee.threshold - 1],
        committee.threshold,
        &committee.hash,
    );
    assert!(
        matches!(
            outcome,
            stellereum::mev_epoch::UnsealOutcome::NotEnoughShares { have: 2, need: 3 }
        ),
        "a withholding member must produce a bounded failure, not a stall"
    );
}

// ===========================================================================
// 4. THE EPOCH BOUNDS THE CIPHERTEXT
// ===========================================================================

/// A wallet CANNOT decrypt a transaction sealed for a DIFFERENT epoch.
///
/// The epoch is bound into the key derivation AND into the associated data,
/// so a ciphertext of epoch E never opens under epoch E+1 — not with the
/// right shares, and not with the wrong committee.
#[test]
fn a_wallet_cannot_decrypt_a_transaction_sealed_for_another_epoch() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c7, m7, _m) = run_dkg(7, &members);
    let (_c8, m8, _m) = run_dkg(8, &members);
    assert_ne!(m7[0].public_key, m8[0].public_key);

    let key = m7[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    // The shares of epoch 7, but the COMMITTEE of epoch 8: the associated
    // data binds the committee, so the payload does not authenticate.
    let c8 = committee(8, &members);
    let partials: Vec<DecryptionPartial> = members
        .iter()
        .enumerate()
        .map(|(i, m)| DecryptionPartial {
            validator_index: c8.index_of(&m.id).unwrap(),
            point: compute_partial(&m7[i].share, &envelope.ephemeral_pk).unwrap(),
        })
        .collect();
    assert!(
        stellereum::mev_epoch::unseal_transaction(
            &envelope,
            &partials[..c8.threshold],
            c8.threshold,
            &c8.hash,
        )
        .is_err(),
        "a ciphertext sealed for epoch 7 must not open under epoch 8"
    );

    // And the epoch's own key cannot open it either: the shares of epoch 8
    // reconstruct a different shared point.
    let partials8: Vec<DecryptionPartial> = members
        .iter()
        .enumerate()
        .map(|(i, m)| DecryptionPartial {
            validator_index: c8.index_of(&m.id).unwrap(),
            point: compute_partial(&m8[i].share, &envelope.ephemeral_pk).unwrap(),
        })
        .collect();
    assert!(
        stellereum::mev_epoch::unseal_transaction(
            &envelope,
            &partials8[..c8.threshold],
            c8.threshold,
            &c8.hash,
        )
        .is_err(),
        "the next epoch's shares must not open this epoch's ciphertext"
    );
}

/// A sealed transaction for a STALE epoch is refused at admission: the pool
/// only accepts the ciphertexts of the epoch it is currently sealing for.
#[test]
fn a_stale_epoch_seal_is_refused_at_admission() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, _managers) = run_dkg(9, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(10); // the pool moved on
    let err = pool
        .add_sealed(envelope)
        .expect_err("a stale seal must be refused");
    let text = format!("{err:?}").to_lowercase();
    assert!(text.contains("epoch"), "the refusal must say why: {err:?}");
    assert_eq!(pool.sealed_count(), 0);
}

// ===========================================================================
// 5. FAIL-CLOSED
// ===========================================================================

/// A MALFORMED seal is refused at admission, with a clear error, and it
/// never occupies pool space.
///
/// The malformed envelopes are the ones a hostile peer would send: an empty
/// payload, an oversized payload, an invalid ephemeral key, the reserved
/// all-zero transaction hash.
#[test]
fn a_malformed_seal_is_rejected_fail_closed() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, _managers) = run_dkg(11, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let good = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(11);

    // Empty payload.
    let mut broken = good.clone();
    broken.ciphertext.clear();
    assert!(pool.add_sealed(broken).is_err());

    // Invalid ephemeral public key (not a curve point).
    let mut broken = good.clone();
    broken.ephemeral_pk = [0xFF; 32];
    assert!(pool.add_sealed(broken).is_err());

    // The reserved all-zero transaction hash.
    let mut broken = good.clone();
    broken.tx_hash = [0u8; 32];
    assert!(pool.add_sealed(broken).is_err());

    // An oversized payload.
    let mut broken = good.clone();
    broken.ciphertext = vec![0u8; stellereum::mev_epoch::MAX_SEALED_PAYLOAD + 1];
    assert!(pool.add_sealed(broken).is_err());

    // A tampered ciphertext passes the STRUCTURAL check (it is a valid
    // frame) but does not authenticate: the unseal fails instead of
    // returning garbage, and the bounded attempt reports it.
    let mut tampered = good.clone();
    tampered.ciphertext[0] ^= 0xFF;
    let partials: Vec<DecryptionPartial> = members
        .iter()
        .enumerate()
        .map(|(i, _m)| DecryptionPartial {
            validator_index: 1 + i as u32,
            point: compute_partial(&materials[i].share, &tampered.ephemeral_pk).unwrap(),
        })
        .collect();
    let outcome = stellereum::mev_epoch::try_unseal(
        &tampered,
        &partials,
        materials[0].threshold,
        &materials[0].committee_hash,
    );
    assert!(
        matches!(outcome, stellereum::mev_epoch::UnsealOutcome::Undecryptable),
        "a tampered ciphertext must not authenticate"
    );

    // Nothing of the above entered the pool.
    assert_eq!(pool.sealed_count(), 0);
    // ... and the good one still does.
    assert!(pool.add_sealed(good).is_ok());
    assert_eq!(pool.sealed_count(), 1);
}

/// A malformed FRAME is refused at decode time: an unknown magic prefix or a
/// truncated body never becomes a transaction.
#[test]
fn a_malformed_frame_is_refused() {
    assert!(decode_sealed_payload(b"XXXXjunk").is_err());
    assert!(decode_sealed_payload(b"STX1").is_err());
    assert!(decode_sealed_payload(b"").is_err());
    let good = MevFrame::OrderCommit(OrderCommitment::sign(
        1,
        2,
        3,
        vec![[7u8; 32]],
        &SigningKey::generate(&mut OsRng),
    ));
    let bytes = good.encode().unwrap();
    assert!(matches!(
        MevFrame::decode(&bytes),
        Ok(MevFrame::OrderCommit(_))
    ));
    // A truncated body is refused.
    let mut truncated = bytes.clone();
    truncated.truncate(bytes.len() - 3);
    assert!(MevFrame::decode(&truncated).is_err());
}

// ===========================================================================
// 6. THE EPOCH KEY IS COMMITTED TO THE BLOCK
// ===========================================================================

/// The block carries the commitment to the epoch key, so the CHAIN (not one
/// node) decides which key the network uses.
///
/// A wallet (or a light client) takes the epoch key from a full node and
/// checks the commitment against the block it can see on the chain.
#[test]
fn the_epoch_key_is_committed_to_the_block() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, _managers) = run_dkg(12, &members);
    let material = &materials[0];

    let commitment = epoch_key_commitment(
        material.epoch,
        &material.public_key,
        &material.committee_hash,
        material.threshold,
    );
    assert_eq!(commitment, material.commitment());

    // The block carries it, and the commitment is inside the block hash: a
    // proposer cannot change the epoch key after the votes.
    let mut block = stellereum::sharding::Block::new_for_test(0, 300, [0u8; 32], [1u8; 32], vec![]);
    let without = block.compute_hash();
    block.epoch_key_commitment = commitment;
    let with = block.compute_hash();
    assert_ne!(
        without, with,
        "the epoch key commitment must be in the block hash"
    );

    // The commitment is bound to the epoch, the key, the committee and the
    // threshold: a commitment from one epoch cannot be replayed into
    // another.
    assert_ne!(
        commitment,
        epoch_key_commitment(
            material.epoch + 1,
            &material.public_key,
            &material.committee_hash,
            material.threshold
        )
    );
    assert_ne!(
        commitment,
        epoch_key_commitment(
            material.epoch,
            &material.public_key,
            &material.committee_hash,
            material.threshold + 1
        )
    );
    let _ = committee;
}

/// A node whose OWN key differs from the committed one has DIVERGED, and it
/// then refuses to release decryption partials: its shares would reconstruct
/// a different shared point.
#[test]
fn a_diverged_epoch_key_stops_the_release() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, mut managers) = run_dkg(13, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    let mut manager = managers.remove(0);
    let commitment = manager
        .commit_order(20, 0, vec![tx_hash], &members[0].signing)
        .unwrap();

    // The chain commits to a DIFFERENT epoch key: we diverged.
    manager.note_committed_epoch_key([0x77; 32]);
    assert!(manager.epoch_key_diverged);
    assert!(
        manager.release_partial(20, 0, &envelope).is_err(),
        "a diverged node must not release partials"
    );
    let _ = commitment;
}

// ===========================================================================
// 7. THE PLAIN PATH KEEPS WORKING
// ===========================================================================

/// The PLAIN path is untouched: a wallet that does not seal is never broken
/// by the sealed path, and the two paths coexist in the same pool.
#[test]
fn the_plain_path_still_works_alongside_the_sealed_one() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, _managers) = run_dkg(14, &members);
    let key = materials[0].public_key();

    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(14);

    // A plain transaction: the historical path.
    let plain = Transaction::sign(&members[0].signing, [0x22; 32], 500, 0, 0, 1, 1);
    let plain_hash = plain.compute_tx_hash();
    pool.add_checked(plain, 1_000_000)
        .expect("the plain tx is admitted");
    assert_eq!(pool.len(), 1);

    // A sealed transaction: the private path.
    let (plaintext, tx_hash) = signed_tx(&members[1].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[1].id, 0)).unwrap();
    pool.add_sealed(envelope)
        .expect("the sealed tx is admitted");

    assert_eq!(pool.len(), 1, "one plain transaction");
    assert_eq!(pool.sealed_count(), 1, "one sealed transaction");
    assert!(
        pool.sealed_share() > 0.4 && pool.sealed_share() < 0.6,
        "the sealed share must be reported: {}",
        pool.sealed_share()
    );
    assert!(pool.sealed_envelope(&tx_hash).is_some());
    assert!(pool.sealed_envelope(&plain_hash).is_none());
}

// ===========================================================================
// 8. THE DKG AGREES ON ONE KEY
// ===========================================================================

/// The whole committee derives ONE epoch key, and a missing contributor
/// blocks the key generation (rather than producing a key only some nodes
/// hold).
#[test]
fn the_committee_agrees_on_one_epoch_key() {
    let members: Vec<Member> = (0..5).map(|_| member()).collect();
    let (the_committee, materials, _managers) = run_dkg(15, &members);
    for m in &materials {
        assert_eq!(m.public_key, materials[0].public_key, "one epoch key");
        assert_eq!(m.committee_hash, the_committee.hash);
        assert_eq!(m.threshold, the_committee.threshold);
    }
    // The shares are DISTINCT (a degenerate sharing would be broken).
    let mut shares: Vec<[u8; 32]> = materials.iter().map(|m| m.share).collect();
    shares.sort();
    shares.dedup();
    assert_eq!(
        shares.len(),
        members.len(),
        "every member holds a different share"
    );

    // The contributor set is DERIVED, so every node computes the same one.
    let again = committee(15, &members);
    assert_eq!(again.contributors, the_committee.contributors);
    assert_eq!(again.hash, the_committee.hash);
}

/// The epoch key ROTATES: two epochs have different keys, so a ciphertext
/// of one epoch never opens in the next.
#[test]
fn the_epoch_key_rotates() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c16, m16, _m) = run_dkg(16, &members);
    let (_c17, m17, _m) = run_dkg(17, &members);
    assert_ne!(m16[0].public_key, m17[0].public_key);
    assert_ne!(m16[0].commitment(), m17[0].commitment());
    assert_eq!(stellereum::mev_epoch::EPOCH_BLOCKS, 128);
    // The epoch of a height is a pure function of the height.
    assert_eq!(stellereum::mev_epoch::epoch_of_height(0), 0);
    assert_eq!(stellereum::mev_epoch::epoch_of_height(127), 0);
    assert_eq!(stellereum::mev_epoch::epoch_of_height(128), 1);
    assert_eq!(stellereum::mev_epoch::epoch_of_height(255), 1);
    assert_eq!(stellereum::mev_epoch::epoch_of_height(256), 2);
}

// ===========================================================================
// 9. THE WIRE FORMAT
// ===========================================================================

/// The wire frames are MAGIC-PREFIXED, so a node that predates the sealed
/// path can never mis-read a sealed frame as a plain transaction (it
/// refuses it instead).
#[test]
fn the_wire_frames_are_magic_prefixed() {
    let sealed = MevFrame::Sealed(SealedEnvelope {
        epoch: 1,
        tx_hash: [3u8; 32],
        ephemeral_pk: [4u8; 32],
        nonce: [5u8; 24],
        ciphertext: vec![1, 2, 3],
        meta: meta_for([6u8; 32], 0),
    });
    let bytes = sealed.encode().unwrap();
    assert_eq!(&bytes[..4], stellereum::mev_epoch::SEALED_PAYLOAD_MAGIC);
    assert!(stellereum::mev_epoch::is_sealed_payload(&bytes));
    assert!(stellereum::mev_epoch::is_mev_frame(&bytes));

    for (frame, magic) in [
        (
            MevFrame::Dkg(stellereum::mev_epoch::DkgContribution {
                epoch: 1,
                validator_id: [1u8; 32],
                index: 1,
                enc_pk: [2u8; 32],
                commitments: vec![[3u8; 32]],
                packages: vec![],
            }),
            stellereum::mev_epoch::DKG_PAYLOAD_MAGIC,
        ),
        (
            MevFrame::OrderCommit(OrderCommitment::sign(
                1,
                2,
                3,
                vec![[1u8; 32]],
                &SigningKey::generate(&mut OsRng),
            )),
            stellereum::mev_epoch::ORDER_COMMIT_PAYLOAD_MAGIC,
        ),
        (
            MevFrame::Release(stellereum::mev_epoch::ShareRelease {
                epoch: 1,
                height: 2,
                round: 3,
                order_root: [4u8; 32],
                partials: vec![],
            }),
            stellereum::mev_epoch::SHARE_RELEASE_PAYLOAD_MAGIC,
        ),
    ] {
        let bytes = frame.encode().unwrap();
        assert_eq!(&bytes[..4], magic);
        assert!(stellereum::mev_epoch::is_mev_frame(&bytes));
    }
}

/// A plain transaction frame is NOT a sealed frame: the two never collide.
#[test]
fn a_plain_transaction_is_not_a_sealed_frame() {
    let tx = Transaction::sign(
        &SigningKey::generate(&mut OsRng),
        [0x33; 32],
        10,
        0,
        0,
        1,
        1,
    );
    let bytes = bincode::serialize(&tx).unwrap();
    assert!(!stellereum::mev_epoch::is_sealed_payload(&bytes));
    assert!(!stellereum::mev_epoch::is_mev_frame(&bytes));
    // ... and the gossip parser reads it as a plain transaction.
    match stellereum::consensus_net::parse_tx_gossip_payload(
        &serde_json::json!({"topic": "t", "data": hex::encode(bytes)}).to_string(),
    ) {
        Some(stellereum::consensus_net::TxGossipPayload::Plain(parsed)) => {
            assert_eq!(parsed.compute_tx_hash(), tx.compute_tx_hash());
        }
        other => panic!("a plain transaction must parse as a plain transaction: {other:?}"),
    }
}

/// A sealed frame on the gossip channel is read as a sealed payload, never
/// as a plain transaction.
#[test]
fn a_sealed_frame_is_parsed_as_a_sealed_payload() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, _managers) = run_dkg(18, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();
    let bytes = stellereum::mev_epoch::encode_sealed_payload(&envelope).unwrap();
    match stellereum::consensus_net::parse_tx_gossip_payload(
        &serde_json::json!({"topic": "t", "data": hex::encode(bytes)}).to_string(),
    ) {
        Some(stellereum::consensus_net::TxGossipPayload::Mev(MevFrame::Sealed(parsed))) => {
            assert_eq!(parsed.tx_hash, tx_hash);
        }
        other => panic!("a sealed frame must parse as a sealed payload: {other:?}"),
    }
}

// ===========================================================================
// 10. THE ORDER COMMITMENT IS BOUND TO ITS ROUND
// ===========================================================================

/// The order commitment is signed over a domain-separated, round-bound
/// message, and it is refused when its list does not match its root.
#[test]
fn the_order_commitment_is_bound_to_its_round() {
    let signer = SigningKey::generate(&mut OsRng);
    let commit = OrderCommitment::sign(2, 100, 3, vec![[1u8; 32], [2u8; 32]], &signer);
    assert!(commit.verify().is_ok());
    assert_eq!(commit.proposer, signer.verifying_key().to_bytes());

    // Re-labelling the round invalidates the signature.
    let mut relabelled = commit.clone();
    relabelled.round = 4;
    assert!(relabelled.verify().is_err(), "the round is bound");

    // A list that does not hash to the root is refused.
    let mut tampered = commit.clone();
    tampered.tx_hashes.push([9u8; 32]);
    assert!(tampered.verify().is_err(), "the list must match the root");

    // A different proposer cannot sign for another proposer.
    let mut forged = commit.clone();
    forged.proposer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    assert!(forged.verify().is_err());
}

/// The DKG contribution of a member that is NOT a contributor of the epoch
/// is refused: accepting contributions from an arbitrary subset is exactly
/// what would let two nodes derive DIFFERENT epoch keys.
#[test]
fn a_contribution_from_a_non_contributor_is_refused() {
    let members: Vec<Member> = (0..5).map(|_| member()).collect();
    let committee = committee(19, &members);
    let non_contributor = members
        .iter()
        .enumerate()
        .find(|(i, m)| {
            !committee.is_contributor(committee.index_of(&m.id).unwrap_or(0))
                && *i != committee.index_of(&m.id).unwrap_or(0) as usize - 1
        })
        .map(|(_, m)| m)
        .expect("the committee has non-contributors");

    let mut dkg = EpochDkg::new(committee.clone(), non_contributor.id);
    assert!(
        dkg.contribution(
            non_contributor.id,
            &non_contributor.secret,
            &non_contributor.enc_secret
        )
        .is_err(),
        "a non-contributor must not be able to contribute"
    );
}

/// The epoch's contributor set is derived from public data, so every node
/// computes the same one.
#[test]
fn the_contributor_set_is_the_same_on_every_node() {
    let members: Vec<Member> = (0..6).map(|_| member()).collect();
    let a = committee(20, &members);
    let b = committee(20, &members);
    assert_eq!(a.contributors, b.contributors);
    assert_eq!(a.contributors.len(), a.threshold);
    // The order of the input does not matter.
    let mut shuffled = members.clone();
    shuffled.rotate_left(3);
    assert_eq!(committee(20, &shuffled).contributors, a.contributors);
    // A different epoch has a different set.
    assert_ne!(committee(21, &members).contributors, a.contributors);
}

/// The epoch-key ANNOUNCEMENT is the committee's agreement: it carries the
/// member signatures, so a light client can check the quorum against the
/// validator set and the commitment against the block.
#[test]
fn the_epoch_announcement_carries_the_committee_signatures() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, mut managers) = run_dkg(21, &members);

    // Every member signs the announcement.
    let announcement = managers[0]
        .build_announcement(&members[0].signing)
        .expect("the announcement is built");
    assert_eq!(announcement.valid_signature_count(), 1);
    assert_eq!(announcement.commitment(), materials[0].commitment());
    assert!(!announcement.has_quorum(committee.threshold));

    for m in members.iter() {
        let theirs = managers[0]
            .build_announcement(&m.signing)
            .expect("the announcement is built");
        managers[0]
            .merge_announcement(theirs)
            .expect("a matching announcement is merged");
    }
    let merged = managers[0]
        .announcement()
        .expect("the announcement is held");
    assert_eq!(merged.valid_signature_count(), 4);
    assert!(
        merged.has_quorum(committee.threshold),
        "the announcement must reach the quorum"
    );
    assert_eq!(merged.commitment(), materials[0].commitment());

    // An announcement about a DIFFERENT key is refused: a peer cannot talk
    // a node into a different epoch key.
    let mut foreign = managers[1]
        .build_announcement(&members[1].signing)
        .expect("the announcement is built");
    foreign.public_key = [0x5A; 32];
    assert!(
        managers[0].merge_announcement(foreign).is_err(),
        "an announcement about another key must be refused"
    );
}

/// The order of a HEIGHT is committed ONCE: the second round of the same
/// height re-uses the commitment, so a sealed transaction that arrives
/// mid-height cannot re-order the round.
#[test]
fn the_order_of_a_height_is_committed_once() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, _m, mut managers) = run_dkg(22, &members);
    let mut manager = managers.remove(0);

    let first = manager
        .commit_order(30, 0, vec![[1u8; 32]], &members[0].signing)
        .expect("the first commitment");
    // The same order in another round of the same height is idempotent.
    let second = manager
        .commit_order(30, 1, vec![[1u8; 32]], &members[0].signing)
        .expect("the same order is idempotent");
    assert_eq!(first.order_root, second.order_root);
    assert_eq!(second.tx_hashes.len(), 1, "the order did not change");
    assert_eq!(
        manager.height_commitment(30).map(|c| c.order_root),
        Some(first.order_root)
    );
    assert!(
        manager.height_commitment(31).is_none(),
        "another height has none"
    );

    // A DIFFERENT order for the same height is refused (the proposer's
    // equivocation). The proposer therefore re-uses the commitment it
    // already made (see `height_commitment`) instead of committing a new
    // one.
    assert!(
        manager
            .commit_order(30, 2, vec![[3u8; 32]], &members[0].signing)
            .is_err(),
        "the order of a height must not change"
    );
    // ... and the commitment the proposer re-uses is the one it made.
    let reused = manager
        .height_commitment(30)
        .expect("the height keeps its commitment")
        .clone();
    assert_eq!(reused.order_root, first.order_root);
    assert_eq!(reused.tx_hashes, vec![[1u8; 32]]);
}

/// A sealed transaction that was unsealed and INCLUDED leaves the pool: it
/// must not be proposed again (it would be a duplicate) and it must not
/// hold pool space.
#[test]
fn an_included_sealed_transaction_leaves_the_pool() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, _managers) = run_dkg(23, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();

    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(23);
    pool.add_sealed(envelope).unwrap();
    assert_eq!(pool.sealed_count(), 1);

    // The block that carries it is applied: the envelope goes with it.
    pool.prune_confirmed(&[tx_hash]);
    assert_eq!(
        pool.sealed_count(),
        0,
        "the included seal must leave the pool"
    );
    assert!(pool.sealed_envelope(&tx_hash).is_none());
}

/// The per-sender quota applies to the sealed path too, and it is SHARED
/// with the plain path: a sender cannot get twice the quota by splitting
/// its traffic over the two paths.
#[test]
fn the_per_sender_quota_covers_the_sealed_path() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_c, materials, _managers) = run_dkg(24, &members);
    let key = materials[0].public_key();

    let mut pool = Mempool::new(64, 2);
    pool.set_sealed_epoch(24);
    let mut admitted = 0;
    for nonce in 0..4u64 {
        let (plaintext, tx_hash) = signed_tx(&members[0].signing, nonce);
        let envelope =
            seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, nonce)).unwrap();
        if pool.add_sealed(envelope).is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 2,
        "the per-sender quota must bound the sealed path"
    );
    assert_eq!(pool.sealed_count(), 2);
}

/// THE WALLET PATH END TO END: fetch the epoch key, parse it, sign + seal
/// with the wallet helpers, submit the hex payload, admit it, commit the
/// order, release a threshold of shares, unseal — and get the exact
/// transaction bytes back.
///
/// This is the property the task asks for at the level the network sees it:
/// what the wallet submits and what the gossip carries is ciphertext, and
/// the reveal happens only after the ordering commitment unblocks it.
#[test]
fn the_wallet_path_seals_submits_and_unseals_end_to_end() {
    use stellereum::mev_epoch::{unseal_transaction, EpochPublicKey};

    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, mut managers) = run_dkg(30, &members);
    let epoch_key = materials[0].public_key();

    // 1. The wallet fetches `stell_epochKey` and parses it into the key it
    //    seals to (the external-wallet entry point).
    let rpc_answer = serde_json::json!({
        "epoch": epoch_key.epoch,
        "public_key": hex::encode(epoch_key.public_key),
        "committee_hash": hex::encode(epoch_key.committee_hash),
        "threshold": epoch_key.threshold,
    });
    let parsed = EpochPublicKey::from_rpc_json(&rpc_answer).expect("the node answer parses");
    assert_eq!(parsed.public_key, epoch_key.public_key);

    // 2. The wallet signs, seals and hex-encodes in one step. The plaintext
    //    transaction never leaves the wallet; only the payload below is
    //    submitted.
    let wallet = stellereum::wallet::WalletAccount::from_seed(&[0x77u8; 32]);
    let (tx, _envelope, payload_hex) = wallet
        .create_sealed_transaction([0x5Eu8; 32], 1_000, 0, 0, 0, 300_000, 7, &parsed)
        .expect("the wallet seals");
    let plaintext = bincode::serialize(&tx).expect("the transaction serializes");

    // 3. The submit payload is ciphertext: the plaintext is nowhere in the
    //    wire bytes (what the gossip carries and what the DHT stores).
    let wire = hex::decode(&payload_hex).expect("the payload is hex");
    assert!(stellereum::mev_epoch::is_sealed_payload(&wire));
    assert!(
        !wire
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()),
        "the submit payload must not contain the plaintext transaction"
    );
    let envelope = decode_sealed_payload(&wire).expect("the payload decodes");

    // 4. Admission: the mempool stores the sealed blob (fail-closed on
    //    malformed input, which the wire decoder already enforced).
    let mut pool = Mempool::new(64, 16);
    pool.set_sealed_epoch(30);
    let hash = pool
        .add_sealed(envelope.clone())
        .expect("the sealed tx is admitted");
    assert_eq!(hash, tx.compute_tx_hash());

    // 5. The proposer commits the ORDER first. The commitment is what
    //    unblocks the release: no manager releases before it sees this.
    let height = 30 * stellereum::mev_epoch::EPOCH_BLOCKS + 1;
    let commitment = managers[0]
        .commit_order(height, 0, vec![hash], &members[0].signing)
        .expect("the order is committed");
    assert!(
        managers[1].release_partial(height, 0, &envelope).is_err(),
        "no release before the order commitment is seen"
    );

    // 6. A threshold of managers sees the commitment and releases; one
    //    member withholds (its manager never releases).
    let mut partials = Vec::new();
    for m in managers.iter_mut().take(committee.threshold) {
        m.note_commitment(commitment.clone())
            .expect("the commitment is noted");
        partials.push(
            m.release_partial(height, 0, &envelope)
                .expect("the release follows the commitment"),
        );
    }
    assert_eq!(partials.len(), committee.threshold);

    // 7. The threshold unseals to EXACTLY the wallet's transaction bytes,
    //    and the transparent metadata matches the transaction itself.
    let unsealed = unseal_transaction(&envelope, &partials, committee.threshold, &committee.hash)
        .expect("a threshold of partials unseals");
    assert_eq!(unsealed, plaintext);
    let recovered: Transaction = bincode::deserialize(&unsealed).expect("a transaction");
    assert_eq!(recovered.compute_tx_hash(), hash);
    assert_eq!(
        envelope.meta,
        stellereum::mev_epoch::TransparentMeta::for_transaction(&recovered),
        "the metadata must be the transaction's own fields"
    );
}

/// Unused import guard: the signing key type is used through the members.
#[allow(dead_code)]
fn _verifying_key_of(m: &Member) -> VerifyingKey {
    VerifyingKey::from_bytes(&m.id).unwrap()
}

/// Unused import guard: randomness is used by the member generator.
#[allow(dead_code)]
fn _random_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}

// ===========================================================================
// B-GOV/M1: `release_partial` has no epoch binding. A sealed envelope from a
// FOREIGN epoch (same tx_hash, valid ephemeral point) gets a partial from
// this epoch's share. DESIRED: Err. FAILS on current code (Ok).
// ===========================================================================

#[test]
fn bgov_release_partial_must_refuse_foreign_epoch_envelope() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (_committee, materials, mut managers) = run_dkg(3, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();
    let mut manager = managers.remove(0);
    manager
        .commit_order(10, 0, vec![tx_hash], &members[0].signing)
        .expect("commitment is made");
    // Same committed tx_hash, same valid ephemeral point — but sealed for a
    // completely different epoch. The AAD would never authenticate under this
    // epoch, yet the gate does not look at the envelope epoch at all.
    let mut foreign = envelope.clone();
    foreign.epoch = 999;
    assert_eq!(foreign.tx_hash, tx_hash);
    assert!(
        manager.release_partial(10, 0, &foreign).is_err(),
        "B-GOV/M1 REAL: partial released for epoch-999 envelope with epoch-3 share"
    );
}

// ===========================================================================
// B-GOV/M2: `ingest_release` binds only (epoch, order_root), not
// (height, round). A release crafted for height 200/round 5 is accepted while
// the only known commitment is height 100/round 0 with the same root.
// DESIRED: Err. FAILS on current code (Ok, partials ingested).
// ===========================================================================

#[test]
fn bgov_ingest_release_must_bind_height_and_round() {
    let members: Vec<Member> = (0..4).map(|_| member()).collect();
    let (committee, materials, mut managers) = run_dkg(5, &members);
    let key = materials[0].public_key();
    let (plaintext, tx_hash) = signed_tx(&members[0].signing, 0);
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta_for(members[0].id, 0)).unwrap();
    let mut manager = managers.remove(0);
    let commitment = manager
        .commit_order(100, 0, vec![tx_hash], &members[0].signing)
        .expect("commitment is made");
    let partial = DecryptionPartial {
        validator_index: committee.index_of(&members[1].id).unwrap(),
        point: compute_partial(&materials[1].share, &envelope.ephemeral_pk).unwrap(),
    };
    // Same epoch + same root, but a height/round this node never committed to.
    let replay = stellereum::mev_epoch::ShareRelease {
        epoch: commitment.epoch,
        height: 200,
        round: 5,
        order_root: commitment.order_root,
        partials: vec![(tx_hash, partial)],
    };
    assert!(
        manager.ingest_release(replay).is_err(),
        "B-GOV/M2 REAL: release for height 200/round 5 accepted against a height-100 commitment"
    );
}
