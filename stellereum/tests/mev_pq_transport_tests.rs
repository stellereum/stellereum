//! MEV DKG PQ-TRANSPORT FALLBACK STEP — Falcon-authenticated framing around
//! the X25519 share-package leg.
//!
//! CONTEXT: the full RANK-1 swap (PQ-KEM encaps in place of the X25519 DH of
//! `encrypt/decrypt_share_package`) is BLOCKED — `ml-kem` is a direct
//! dependency of the sibling `infnode` crate only and is not addressable
//! from `stellereum` without a new dependency (forbidden). What these tests
//! pin is the fallback step: every `DkgContribution` travels in a
//! `PqTransportEnvelope` carrying the contributor's Falcon-512 signature
//! over the canonical bytes, and the authenticated ingest path refuses
//! anything that does not verify.
//!
//! What is pinned (extension only — no existing test is modified):
//! 1. seal/verify round-trip, with fixed vectors (seeded Falcon keypair
//!    public key, auth-message determinism and domain framing);
//! 2. tampering anywhere (signature, key, contribution bytes) is refused,
//!    at verify AND at ingest;
//! 3. the classical fallback is unchanged: with the default-off flag the
//!    swapped entry point finalizes byte-identical material (same epoch
//!    key, same transcript root, same shares);
//! 4. the threshold shape is intact end-to-end through the authenticated
//!    path: full DKG, same `P_e` as the classical run, seal, `t` partials
//!    unseal, `t - 1` do not.

use ed25519_dalek::SigningKey;
use stellereum::mev_epoch::{
    combine_partials, compute_partial, encryption_public_key_from_ed25519,
    encryption_secret_from_ed25519, pq_transport_auth_message, pq_transport_seal,
    pq_transport_verify, seal_transaction, unseal_transaction, CommitteeMember, DecryptionPartial,
    DkgContribution, EpochCommittee, EpochDkg, EpochKeyMaterial, PqTransportEnvelope,
    PQ_TRANSPORT_SIG_DOMAIN, PREFER_PQ_MEV_TRANSPORT,
};
use stellereum::post_quantum::FalconKeypair;

// ===========================================================================
// Harness (deterministic: fixed seeds, no randomness except the protocol's
// own ephemeral keys, which never affect the asserted values)
// ===========================================================================

struct Member {
    id: [u8; 32],
    secret: [u8; 32],
    enc_secret: [u8; 32],
    enc_pk: [u8; 32],
    falcon: FalconKeypair,
    falcon_pk: Vec<u8>,
}

fn member(ed_seed: [u8; 32], falcon_seed: [u8; 32]) -> Member {
    let signing = SigningKey::from_bytes(&ed_seed);
    let secret = signing.to_bytes();
    let enc_secret = encryption_secret_from_ed25519(&secret);
    let enc_pk = encryption_public_key_from_ed25519(&signing.verifying_key().to_bytes())
        .expect("a fixed ed25519 key converts");
    let falcon = FalconKeypair::generate_from_seed_bytes(&falcon_seed);
    let falcon_pk = falcon.public_key().to_vec();
    Member {
        id: signing.verifying_key().to_bytes(),
        secret,
        enc_secret,
        enc_pk,
        falcon,
        falcon_pk,
    }
}

fn four_members() -> Vec<Member> {
    (1u8..=4u8)
        .map(|i| member([i; 32], [0xA0 + i; 32]))
        .collect()
}

fn committee_of(epoch: u64, members: &[Member]) -> EpochCommittee {
    EpochCommittee::build(
        epoch,
        members
            .iter()
            .map(|m| CommitteeMember {
                validator_id: m.id,
                enc_pk: m.enc_pk,
            })
            .collect(),
    )
}

fn falcon_pk_of(members: &[Member], id: &[u8; 32]) -> Vec<u8> {
    members
        .iter()
        .find(|m| &m.id == id)
        .expect("contributor is a member")
        .falcon_pk
        .clone()
}

/// Build every contributor's contribution once (shared across runs so the
/// classical and swapped paths ingest byte-identical contributions).
fn build_contributions(
    committee: &EpochCommittee,
    members: &[Member],
) -> Vec<(DkgContribution, Vec<u8>)> {
    let mut dkgs: Vec<EpochDkg> = members
        .iter()
        .map(|m| EpochDkg::new(committee.clone(), m.id))
        .collect();
    let mut out = Vec::new();
    for (i, m) in members.iter().enumerate() {
        let index = committee.index_of(&m.id).expect("member has an index");
        if !committee.is_contributor(index) {
            continue;
        }
        let contribution = dkgs[i]
            .contribution(m.id, &m.secret, &m.enc_secret)
            .expect("a contributor builds its contribution");
        out.push((contribution, m.falcon_pk.clone()));
    }
    assert_eq!(
        out.len(),
        committee.contributors.len(),
        "exactly the derived contributor set contributes"
    );
    out
}

fn run_classical(
    committee: &EpochCommittee,
    members: &[Member],
    contributions: &[(DkgContribution, Vec<u8>)],
) -> Vec<EpochKeyMaterial> {
    let mut dkgs: Vec<EpochDkg> = members
        .iter()
        .map(|m| EpochDkg::new(committee.clone(), m.id))
        .collect();
    // Contributors must build (not publish) first so the own-contribution
    // ingest path has its evaluation.
    for (i, m) in members.iter().enumerate() {
        let index = committee.index_of(&m.id).expect("member has an index");
        if committee.is_contributor(index) {
            dkgs[i]
                .contribution(m.id, &m.secret, &m.enc_secret)
                .expect("a contributor builds its contribution");
        }
    }
    for (i, m) in members.iter().enumerate() {
        for (c, _) in contributions {
            dkgs[i]
                .ingest(c.clone(), &m.enc_secret)
                .unwrap_or_else(|e| panic!("member {i} must accept a contribution: {e}"));
        }
    }
    assert!(
        dkgs.iter().all(|d| d.can_finalize()),
        "every member finalizes"
    );
    dkgs
        .iter_mut()
        .map(|d| d.finalize().expect("finalize succeeds"))
        .collect()
}

fn run_swapped(
    committee: &EpochCommittee,
    members: &[Member],
    contributions: &[(DkgContribution, Vec<u8>)],
    authenticated: bool,
) -> Vec<EpochKeyMaterial> {
    let envelopes: Vec<PqTransportEnvelope> = contributions
        .iter()
        .map(|(c, _)| {
            let falcon = &members
                .iter()
                .find(|m| m.id == c.validator_id)
                .expect("contributor is a member")
                .falcon;
            pq_transport_seal(falcon, c.clone())
        })
        .collect();
    let mut dkgs: Vec<EpochDkg> = members
        .iter()
        .map(|m| EpochDkg::new(committee.clone(), m.id))
        .collect();
    for (i, m) in members.iter().enumerate() {
        let index = committee.index_of(&m.id).expect("member has an index");
        if committee.is_contributor(index) {
            dkgs[i]
                .contribution(m.id, &m.secret, &m.enc_secret)
                .expect("a contributor builds its contribution");
        }
    }
    for (i, m) in members.iter().enumerate() {
        for e in &envelopes {
            let expected = falcon_pk_of(members, &e.contribution.validator_id);
            let res = if authenticated {
                dkgs[i].ingest_authenticated(e, &m.enc_secret, &expected)
            } else {
                dkgs[i].ingest_pq_transport(e, &m.enc_secret, &expected)
            };
            res.unwrap_or_else(|e| panic!("member {i} must accept an envelope: {e}"));
        }
    }
    assert!(
        dkgs.iter().all(|d| d.can_finalize()),
        "every member finalizes through the swapped path"
    );
    dkgs
        .iter_mut()
        .map(|d| d.finalize().expect("finalize succeeds"))
        .collect()
}

/// Runtime view of the transport flag: pinned default-off here so a future
/// activation diff must update this suite deliberately (a bare `assert!` on
/// the const trips `clippy::assertions_on_constants`; the call keeps it a
/// runtime pin).
fn pq_transport_is_default_off() -> bool {
    !PREFER_PQ_MEV_TRANSPORT
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ===========================================================================
// 1. Seal/verify round-trip + fixed vectors
// ===========================================================================

/// Fixed vector: the Falcon-512 public key of seed `[0xA1; 32]`
/// (deterministic keygen; pinned so a keygen regression is caught here).
const FALCON_PK_SEED_A1_HEX: &str = "094638c07bef8a695031c5a243d2d23a16e12a9a88637a1678654692f228dc7434802e972854e212a16f184c5174e7b5da4932ad19e0f89635aa891f66b5ae8c65bda7491b9ad58c8045d613e7491cd16108795095a0be681b3441e0b114dbe1b8c7eb46c1a1c2b44a8a96f9296bd8c7ab52aa1081abeb892c88e21206d417bf8c3c76f26283a05170b61ca6ae5d06ef889b014b639a4609a3d5adbf8527e2762f2a8ed69611daa6e95fb015abafc8b9594979216751b888d4c8c5760064abc14ad3f8e2e95ed036e830574d830dc590170b0b74a5b2a45f156b9ec1170220ee1c9119ef2b36abe35dc07d9a164a958cf0ec30412e54068d95ebded4db69d199a861dd218d0eeaa0ece43082de9ac2dfc2e2718e10b565ce614b5499ea9b4f13347076c5590d1f3538a50bb7a80e2276dc00a1dcef8cf14d690482cf4fad7008db45224ca6c4cb3741cb100a83b3fae67d7a1a70351662485d7a21947287162004604a144a2ab1ed66808acad582a65143d74c64bba8f096066671ab28342ba38ef813460f52bf243b5b249cb5f3006966448d6bf41b9335a22e51f7dd1c2b297651d7e2905fe11c2b86e3b38f12b7f5a9e98b3ba586a2f687612db2888aa5e3d40ff42eb7fd06748444518827cc3b0b023b036657365d66199aa0a304645e7128d605a7468add77c8da2f22ca8d9bc1a52da6cae4a024e5cb6f297e95e2c4f5bb7e6a40960cafac2d9459e5030ab1c50f44d11ad42671aa86951d0580aa960a6598fa019a45c061cd311ae0abf529a27029698cb330211229b2abd67d1a8794918f8335a7ce179c0be7cd1a6daed2e8d8770e928f6ab7f0e5a5c5a0b6e16b3ea9f718618783a7464762e647aab90e5825ca0199d196f21fc99a67b7850dbcc9d653121b309be647a465d4aea2817c521ed2d48226e09440d4924b24c307929e7072b5d9c7aa13c32edeb228cda9bd797edbb40f590b6c9ebea55c43c3a7dd86d966142b31905b71ed20b8a88a4766e4ca6658d5b123a55b6aba41dab118c29ea6f6053280a66c293d55171716d5336eed0b5283f0a9718040b3591859053eb16c257b50109d8a53864575ba420625896f97fe7dd515d5d3a24de7d565e8fc371e5454ef86cf429806d89912a3802548b9a1519513e0a6254d5c197c322580e4684c02643724b60c50456d14f8d59a4762865677dda53361cd74ba3b2f58899c7f86725ff77908153b7a175437229ad9641d4e1cd52212d18e71a3000fcb0c271f";

#[test]
fn pq_transport_seal_verify_roundtrip_fixed_vectors() {
    let members = four_members();
    let committee = committee_of(5, &members);
    assert_eq!(committee.threshold, 3);
    let contributions = build_contributions(&committee, &members);
    let (contribution, _) = &contributions[0];

    // Fixed vector: seeded keypair determinism + pinned public key.
    let again = FalconKeypair::generate_from_seed_bytes(&[0xA1; 32]);
    assert_eq!(
        hex_of(again.public_key()),
        hex_of(&members[0].falcon_pk),
        "seeded Falcon keygen is deterministic"
    );
    assert_eq!(
        hex_of(&members[0].falcon_pk),
        FALCON_PK_SEED_A1_HEX,
        "pinned Falcon-512 public key vector"
    );
    assert_eq!(members[0].falcon_pk.len(), 897);
    assert_eq!(members[0].falcon_pk[0], 0x09, "FIPS 206 pk header");

    // Auth-message framing: deterministic, domain-prefixed, length-prefixed.
    let msg_a = pq_transport_auth_message(contribution);
    let msg_b = pq_transport_auth_message(contribution);
    assert_eq!(msg_a, msg_b, "the auth message is deterministic");
    assert!(
        msg_a.starts_with(PQ_TRANSPORT_SIG_DOMAIN),
        "the domain leads the preimage"
    );
    let len = u32::from_be_bytes(msg_a[PQ_TRANSPORT_SIG_DOMAIN.len()..][..4].try_into().unwrap());
    assert_eq!(
        len as usize,
        contribution.canonical_bytes().len(),
        "length-prefix framing"
    );

    // Round-trip: seal verifies against the contributor's expected key.
    let envelope = pq_transport_seal(&members[0].falcon, contribution.clone());
    assert_eq!(envelope.falcon_pk, members[0].falcon_pk);
    assert_eq!(envelope.falcon_sig.len(), 666);
    pq_transport_verify(&envelope, &members[0].falcon_pk)
        .expect("a fresh envelope verifies");

    // Falcon signing randomizes: a second seal verifies too (never assert
    // signature equality — FIPS 206 requires fresh randomness per signature).
    let envelope2 = pq_transport_seal(&members[0].falcon, contribution.clone());
    pq_transport_verify(&envelope2, &members[0].falcon_pk)
        .expect("a second seal verifies as well");
}

// ===========================================================================
// 2. Tampering is refused (verify and ingest)
// ===========================================================================

#[test]
fn pq_transport_tamper_is_refused() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let contributions = build_contributions(&committee, &members);
    let (contribution, _) = &contributions[0];
    let good = pq_transport_seal(&members[0].falcon, contribution.clone());
    let expected = &members[0].falcon_pk;

    // A bit flip in the signature is refused.
    let mut bad_sig = good.clone();
    bad_sig.falcon_sig[100] ^= 0x01;
    assert!(
        pq_transport_verify(&bad_sig, expected).is_err(),
        "flipped signature must be refused"
    );

    // A truncated signature is refused.
    let mut trunc = good.clone();
    trunc.falcon_sig.truncate(665);
    assert!(
        pq_transport_verify(&trunc, expected).is_err(),
        "truncated signature must be refused"
    );

    // An empty signature is refused.
    let mut empty = good.clone();
    empty.falcon_sig.clear();
    assert!(
        pq_transport_verify(&empty, expected).is_err(),
        "empty signature must be refused"
    );

    // The wrong expected key (another member's valid key) is refused.
    assert!(
        pq_transport_verify(&good, &members[1].falcon_pk).is_err(),
        "wrong expected key must be refused"
    );

    // A swapped self-carried key is refused even though it is well-formed.
    let mut swapped = good.clone();
    swapped.falcon_pk = members[1].falcon_pk.clone();
    assert!(
        pq_transport_verify(&swapped, expected).is_err(),
        "swapped envelope key must be refused"
    );

    // ANY mutation of the contribution invalidates the envelope: commitment.
    let mut bad_commit = good.clone();
    bad_commit.contribution.commitments[0][0] ^= 0x01;
    assert!(
        pq_transport_verify(&bad_commit, expected).is_err(),
        "mutated commitment must be refused"
    );

    // Package ciphertext.
    let mut bad_pkg = good.clone();
    bad_pkg.contribution.packages[0].ciphertext[0] ^= 0x01;
    assert!(
        pq_transport_verify(&bad_pkg, expected).is_err(),
        "mutated package must be refused"
    );

    // Epoch.
    let mut bad_epoch = good.clone();
    bad_epoch.contribution.epoch += 1;
    assert!(
        pq_transport_verify(&bad_epoch, expected).is_err(),
        "mutated epoch must be refused"
    );

    // Contributor index.
    let mut bad_index = good.clone();
    bad_index.contribution.index += 1;
    assert!(
        pq_transport_verify(&bad_index, expected).is_err(),
        "mutated index must be refused"
    );

    // The authenticated ingest path refuses a tampered envelope fail-closed
    // (it never reaches the VSS/package checks with forged bytes).
    let mut dkg = EpochDkg::new(committee, members[1].id);
    let err = dkg
        .ingest_authenticated(&bad_sig, &members[1].enc_secret, expected)
        .expect_err("tampered envelope must not ingest");
    assert!(
        err.contains("falcon"),
        "the refusal names the falcon leg: {err}"
    );
}

// ===========================================================================
// 3. The classical fallback is unchanged (default-off, byte-identical)
// ===========================================================================

#[test]
fn pq_transport_fallback_is_byte_identical() {
    assert!(
        pq_transport_is_default_off(),
        "the PQ transport leg is default-off"
    );
    let members = four_members();
    let committee = committee_of(5, &members);
    let contributions = build_contributions(&committee, &members);

    let classical = run_classical(&committee, &members, &contributions);
    // Default-off: the swapped entry point takes the classical branch and
    // must finalize the SAME material (same key, same transcript, same
    // shares) from the same contributions.
    let swapped = run_swapped(&committee, &members, &contributions, false);
    assert_eq!(classical.len(), swapped.len());
    for (i, (a, b)) in classical.iter().zip(swapped.iter()).enumerate() {
        assert_eq!(a.public_key, b.public_key, "member {i}: same epoch key");
        assert_eq!(
            a.transcript_root, b.transcript_root,
            "member {i}: same transcript root"
        );
        assert_eq!(a.share, b.share, "member {i}: same share");
        assert_eq!(a.committee_hash, b.committee_hash, "member {i}: same committee");
        assert_eq!(a.threshold, b.threshold, "member {i}: same threshold");
    }
}

// ===========================================================================
// 4. Threshold shape intact end-to-end through the authenticated path
// ===========================================================================

#[test]
fn pq_transport_threshold_shape_end_to_end() {
    let members = four_members();
    let committee = committee_of(5, &members);
    assert_eq!(committee.threshold, 3);
    let contributions = build_contributions(&committee, &members);

    // Full DKG with every contribution verified-then-ingested.
    let materials = run_swapped(&committee, &members, &contributions, true);
    // Same epoch key as the classical run over the same contributions.
    let classical = run_classical(&committee, &members, &contributions);
    for m in &materials {
        assert_eq!(
            m.public_key, classical[0].public_key,
            "the authenticated path derives the same P_e"
        );
    }
    assert_eq!(
        materials[0].transcript_root, classical[0].transcript_root,
        "the transcript binds the same contributions"
    );

    // Seal to P_e, unseal with a threshold of partials (one withholds).
    let key = materials[0].public_key();
    let plaintext = b"pq-transport threshold shape probe".to_vec();
    let tx_hash = [0x5Eu8; 32];
    let meta = stellereum::mev_epoch::TransparentMeta {
        from: members[0].id,
        nonce: 0,
        gas_limit: 21_000,
        priority_fee_per_gas: 1,
        source_shard: 0,
        target_shard: 0,
    };
    let envelope = seal_transaction(&key, &plaintext, tx_hash, meta).unwrap();
    let partials: Vec<DecryptionPartial> = members
        .iter()
        .enumerate()
        .map(|(i, m)| DecryptionPartial {
            validator_index: committee.index_of(&m.id).unwrap(),
            point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
        })
        .collect();

    // Any threshold subset reconstructs the same shared point.
    let a = combine_partials(&partials[..3], 3).unwrap();
    let b = combine_partials(&partials[1..4], 3).unwrap();
    assert_eq!(a, b, "the shared point must not depend on the subset");

    let unsealed = unseal_transaction(&envelope, &partials[..3], 3, &committee.hash)
        .expect("a threshold of partials unseals");
    assert_eq!(unsealed, plaintext);

    // Fewer than t partials never unseal.
    assert!(
        unseal_transaction(&envelope, &partials[..2], 3, &committee.hash).is_err(),
        "t - 1 partials must fail"
    );
}
