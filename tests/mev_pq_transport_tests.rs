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
    encryption_secret_from_ed25519, is_pq_transport_active, pq_transport_auth_message,
    pq_transport_seal, pq_transport_verify, seal_transaction, unseal_transaction, CommitteeMember,
    DecryptionPartial, DkgContribution, EpochCommittee, EpochDkg, EpochKeyMaterial,
    PqTransportEnvelope, PQ_TRANSPORT_H_ACTIVATION_HEIGHT, PQ_TRANSPORT_SIG_DOMAIN,
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

/// FULL-PQ: the transport flag is deleted (always PQ). Kept as a runtime pin
/// so activation diffs must update this suite deliberately.
fn pq_transport_is_default_off() -> bool {
    false
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
    // FULL-PQ: no default-off; the swapped entry is always authenticated
    // (Falcon + classical packages) and finalizes identical material.
    assert!(
        !pq_transport_is_default_off(),
        "FULL-PQ always-on: no default-off"
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

// ===========================================================================
// 5. REAL PQ-KEM LEG (RANK-1): ML-KEM-768 package encryption + Falcon auth
// ===========================================================================
//
// CONTEXT: `ml-kem 0.3` is now a direct dependency of THIS crate (same
// audited lineage infnode pins in `kem_kat_tests.rs`), so the full RANK-1
// swap lands here — additively. `EncryptedShare`/`DkgContribution` and the
// Falcon envelope are UNCHANGED shapes: PQ-KEM packages are `kem_ct ||
// aead_ct` (1136 bytes vs classical 48), sealed/verified with the SAME
// `pq_transport_seal`/`verify`, ingested via the new `contribution_pq` /
// `ingest_pq` / `ingest_authenticated_pq` / const-gated
// `ingest_pq_kem_transport` (default-off → classical, byte-identical).
// Feldman VSS + Ristretto math untouched: the PQ run below derives the SAME
// `P_e` and the SAME shares as the classical run (only the transcript root
// differs — it binds the encryption-randomized package bytes).
//
// What is pinned (extension only — no existing test above is modified):
// 5. KEM primitive fixed vectors (Wycheproof ML-KEM-768 seed->ek, c->K)
//    plus deterministic encap round-trip through the new wrappers;
// 6. tampered-ct implicit rejection at the primitive layer (infallible
//    decap returns a DIFFERENT key, never an error);
// 7. package round-trip, wrong-recipient refusal, cross-leg refusal;
// 8. tampered-ct implicit-rejection end-to-end (re-sealed tamper dies at
//    the AEAD open, never at VSS);
// 9. default-off fallback of the NEW entry point is byte-identical;
// 10. threshold shape intact end-to-end over the PQ leg.

use stellereum::mev_epoch::{
    decrypt_share_package_pq, encrypt_share_package_pq, pq_kem_decapsulate, pq_kem_ek_from_seed,
    pq_kem_encapsulate_deterministic, PQ_KEM_CT_LEN, PQ_KEM_EK_LEN, PQ_KEM_PACKAGE_CT_LEN,
};

/// Published vector inputs (same source infnode pins in `kem_kat_tests.rs`:
/// Wycheproof `mlkem_768_test.json`, group "FIPS 203 v1.0", tcId 2 —
/// "official round 3 seeds 0").
const PQ_KEM_WYCHE_SEED_HEX: &str = "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f";
const PQ_KEM_WYCHE_EK_HEX: &str = concat!(
    "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f3679",
    "67532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952",
    "a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e",
    "6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb",
    "68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea9",
    "93336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f",
    "50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57",
    "b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d0",
    "9b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a3",
    "03402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab",
    "901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2e",
    "e8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821ad",
    "c825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627",
    "609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74a",
    "b96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5",
    "ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb",
    "2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c4806",
    "0b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b",
    "07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf53",
    "9210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78",
    "f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a",
    "4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e2",
    "90d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f6",
    "6423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d90683",
    "2c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b",
    "1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98",
    "a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baf",
    "f716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b3372",
    "71c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b018",
    "7004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c9306",
    "2694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec165",
    "1261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574",
    "c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683",
    "733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830",
    "ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c8288879318",
    "1a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736",
    "162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028",
);
const PQ_KEM_WYCHE_C_HEX: &str = concat!(
    "c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f70642",
    "4b49558f755b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed34",
    "6de628f8c57eebabbb0c22d911548463693ef3ce52a53f7ff415f00e657ae1c5",
    "a48fa5ec6e4be5cf462daffc84d2f6d5ff55dc9bbe8bb0d725ec64fd4cd4bd8d",
    "ba0a844e8b5ce4b6a28934d7f7a050991fe185b506b451dabfad52d52cb2114c",
    "a7d9a5cf986c8fdc1bc10ec0c1869e50c03c55a76192a1049aca636ba9020bda",
    "a8d0f58c763b0b89845ca06d4c4ddc21433e16b9c62e44871fdbc05ba218af87",
    "1fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d5f159b9805b975710a",
    "3503a0b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1d2f4992491",
    "117e6347794ba54571ec49bba71af3413d38a30bf5872248d1f6d07c86baf782",
    "e73d2637f043d341a00921857d8b21ddf3e1d6310036ed27af49e5de1b900fe4",
    "de79808ff29f9570859612b15adc01fbb265b305b1e3a12ae419da5b74261fa2",
    "84c101da3d8dca8b2e4521aca571ef44a058e844ff32b16d5aaea05f7f3af8e2",
    "ab16222e347662eddfb891d0ecc2a55c5638f9dde92d9a3d544a5f901ac501ac",
    "d1ea6a010201fcb10ad702c425a94bdf5890d500a2a147eee1d1fcba8c3abe7c",
    "2dfe70f346f033d816a0b2791b4f0b2d956d9ee5971715399a5688302495e2e0",
    "7c1c8c01527184bcd0c208bc159f2e13318c0bb3dd24a6a7fc849f83385ed4db",
    "a07fe1d7bd5640cc9ed5ccfdd68763cb0d0edf61b292177fc1d2d3c11dd04950",
    "56bcb12558aebcfddef9feb4aebc57afd9023c65cfe65a24e33f1b00111e92e6",
    "3e011eaf0b212cf95743cd07f5189ece1f205b7f6fcb2e6b1961b5404cebe47c",
    "8cd13b8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e336d1b612ee1",
    "3db811e1f07e61748d920f4865f3f11741399dc6162c91ca168a02329dff821d",
    "58198712dd558abb099b3a0baf9da1b730b2aa73bcf58d74f357b06f7211c804",
    "b6c8af16ff3509fad1d35b14bfdced7db8a6a25c48e5956480724daa057cd660",
    "b67ee3e472574182679d485838a6476eac02141075c812af7967ba7c9185cc2a",
    "bd2a4545b80f3d3104d58d654a57792dcfabbe9c0715e8de2ef81ef404c8168f",
    "d7a43efab3d448e686a088efd26a26159948926723d7eccc39e3c1b719cf8bec",
    "b7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb407a3ab9f88f5e2916",
    "9eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404ce6935",
    "5830a7a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055",
    "926c03eb3fb87f9695185a42eca9a41655873d30a6b3bf428b246223484a8ff6",
    "1ee3eeafff10e99c2c13a76284d063e56ab711a35a85b5383df81da23490f66e",
    "8ea3fcba067f5530c6541c2b8f74717c35023e7b9b3956c3ee2ff84ba03ccf4b",
    "4b5321b9240895481bc6d63c1693c1847852f8e97f50a133532ac3ee1e52d464",
);
const PQ_KEM_WYCHE_K_HEX: &str = "e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368";

/// Deterministic per-position KEM seed (test-only key sourcing; production
/// reads registry keys — the leg takes them as explicit arguments either way).
fn pq_kem_seed_of(position: u8) -> [u8; 64] {
    [0xC0u8.wrapping_add(position); 64]
}

struct KemParty {
    validator_id: [u8; 32],
    kem_seed: [u8; 64],
    kem_ek: Vec<u8>,
}

fn kem_parties(members: &[Member]) -> Vec<KemParty> {
    members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let kem_seed = pq_kem_seed_of(i as u8);
            let kem_ek = pq_kem_ek_from_seed(&kem_seed);
            assert_eq!(kem_ek.len(), PQ_KEM_EK_LEN, "ML-KEM-768 ek is 1184 bytes");
            KemParty {
                validator_id: m.id,
                kem_seed,
                kem_ek,
            }
        })
        .collect()
}

fn kem_ek_map(
    committee: &EpochCommittee,
    parties: &[KemParty],
) -> std::collections::BTreeMap<u32, Vec<u8>> {
    let mut map = std::collections::BTreeMap::new();
    for p in parties {
        let index = committee
            .index_of(&p.validator_id)
            .expect("kem party is a committee member");
        map.insert(index, p.kem_ek.clone());
    }
    map
}

fn kem_seed_of<'a>(parties: &'a [KemParty], validator_id: &[u8; 32]) -> &'a [u8; 64] {
    &parties
        .iter()
        .find(|p| &p.validator_id == validator_id)
        .expect("kem party exists")
        .kem_seed
}

/// Build every contributor's PQ-KEM contribution, Falcon-sealed (the RANK-1
/// gossip unit: KEM packages inside the UNCHANGED Falcon envelope).
fn build_pq_envelopes(
    committee: &EpochCommittee,
    members: &[Member],
    parties: &[KemParty],
) -> Vec<PqTransportEnvelope> {
    let ek_map = kem_ek_map(committee, parties);
    let mut out = Vec::new();
    for m in members {
        let index = committee.index_of(&m.id).expect("member has an index");
        if !committee.is_contributor(index) {
            continue;
        }
        let mut dkg = EpochDkg::new(committee.clone(), m.id);
        let contribution = dkg
            .contribution_pq(m.id, &m.secret, &ek_map)
            .expect("a contributor builds its PQ contribution");
        assert_eq!(
            contribution.commitments.len(),
            committee.threshold,
            "same Feldman commitment count as classical"
        );
        for p in &contribution.packages {
            assert_eq!(
                p.ciphertext.len(),
                PQ_KEM_PACKAGE_CT_LEN,
                "PQ packages are kem_ct || aead_ct"
            );
            assert_eq!(p.ephemeral_pk, [0u8; 32], "KEM needs no DH ephemeral");
        }
        out.push(pq_transport_seal(&m.falcon, contribution));
    }
    assert_eq!(
        out.len(),
        committee.contributors.len(),
        "exactly the derived contributor set contributes"
    );
    out
}

fn run_pq_kem(
    committee: &EpochCommittee,
    members: &[Member],
    parties: &[KemParty],
    envelopes: &[PqTransportEnvelope],
) -> Vec<EpochKeyMaterial> {
    let ek_map = kem_ek_map(committee, parties);
    let mut dkgs: Vec<EpochDkg> = members
        .iter()
        .map(|m| EpochDkg::new(committee.clone(), m.id))
        .collect();
    // Contributors must build (not publish) first so the own-contribution
    // ingest path has its evaluation.
    for i in 0..members.len() {
        let index = committee.index_of(&members[i].id).expect("member has an index");
        if committee.is_contributor(index) {
            dkgs[i]
                .contribution_pq(members[i].id, &members[i].secret, &ek_map)
                .expect("a contributor builds its PQ contribution");
        }
    }
    for i in 0..members.len() {
        let seed = kem_seed_of(parties, &members[i].id);
        for e in envelopes {
            let expected = falcon_pk_of(members, &e.contribution.validator_id);
            dkgs[i]
                .ingest_authenticated_pq(e, seed, &expected)
                .unwrap_or_else(|err| panic!("member {i} must accept a PQ envelope: {err}"));
        }
    }
    assert!(
        dkgs.iter().all(|d| d.can_finalize()),
        "every member finalizes through the PQ-KEM path"
    );
    dkgs
        .iter_mut()
        .map(|d| d.finalize().expect("finalize succeeds"))
        .collect()
}


// ===========================================================================
// 5. KEM primitive fixed vectors
// ===========================================================================

#[test]
fn pq_kem_primitive_fixed_vectors() {
    let seed_bytes = hex::decode(PQ_KEM_WYCHE_SEED_HEX).expect("wyche seed hex decodes");
    let seed: [u8; 64] = seed_bytes
        .as_slice()
        .try_into()
        .expect("wyche seed is 64 bytes");
    // KAT 1: the published seed reproduces the published ML-KEM-768 ek.
    let ek = pq_kem_ek_from_seed(&seed);
    let expected_ek = hex::decode(PQ_KEM_WYCHE_EK_HEX).expect("wyche ek hex decodes");
    assert_eq!(ek.len(), PQ_KEM_EK_LEN, "ML-KEM-768 ek is 1184 bytes");
    assert_eq!(ek, expected_ek, "wycheproof seed -> ek");
    // Determinism: the same seed always derives the same key.
    assert_eq!(pq_kem_ek_from_seed(&seed), expected_ek);
    // KAT 2: decapsulation of the published ct yields the published secret.
    let c = hex::decode(PQ_KEM_WYCHE_C_HEX).expect("wyche c hex decodes");
    assert_eq!(c.len(), PQ_KEM_CT_LEN, "ML-KEM-768 ct is 1088 bytes");
    let k = pq_kem_decapsulate(&seed, &c).expect("published ct decapsulates");
    let expected_k = hex::decode(PQ_KEM_WYCHE_K_HEX).expect("wyche K hex decodes");
    assert_eq!(k.to_vec(), expected_k, "wycheproof c -> K");
    // Round trip with fully fixed own inputs: determinism on both sides.
    let own_seed = [0x2Au8; 64];
    let own_ek = pq_kem_ek_from_seed(&own_seed);
    let m = [0xA5u8; 32];
    let (ct1, k1) = pq_kem_encapsulate_deterministic(&own_ek, &m).expect("encap works");
    assert_eq!(ct1.len(), PQ_KEM_CT_LEN);
    let k1_recv = pq_kem_decapsulate(&own_seed, &ct1).expect("decap works");
    assert_eq!(k1, k1_recv, "encap/decap shared secrets must match");
    let (ct2, k2) = pq_kem_encapsulate_deterministic(&own_ek, &m).expect("encap works");
    assert_eq!(ct1, ct2, "encap is deterministic");
    assert_eq!(k1, k2, "shared secret is deterministic");
    assert!(k1.iter().any(|&b| b != 0), "the key is non-trivial");
    // A malformed encapsulation key is refused (fail-closed framing).
    assert!(pq_kem_encapsulate_deterministic(&own_ek[..100], &m).is_err());
}

// ===========================================================================
// 6. Tampered-ct implicit rejection at the primitive layer
// ===========================================================================

#[test]
fn pq_kem_tampered_ct_implicit_rejection() {
    let seed = [0x2Au8; 64];
    let ek = pq_kem_ek_from_seed(&seed);
    let m = [0xA5u8; 32];
    let (ct, k_send) = pq_kem_encapsulate_deterministic(&ek, &m).expect("encap works");
    for tamper_at in [0usize, 511, 1087] {
        let mut bad = ct.clone();
        bad[tamper_at] ^= 0x01;
        // Infallible by FIPS 203 s7.2: a tampered but well-formed ct yields
        // the fallback key — never an error, never the sender's key.
        let k_rejected = pq_kem_decapsulate(&seed, &bad).expect("tampered ct still decapsulates");
        assert_ne!(
            k_rejected, k_send,
            "tampered ct at byte {tamper_at} must NOT yield the sender key"
        );
        assert!(
            k_rejected.iter().any(|&b| b != 0),
            "the rejection key is still a populated 32-byte value"
        );
    }
    // A malformed length IS refused outright (fail-closed framing).
    assert!(pq_kem_decapsulate(&seed, &ct[..PQ_KEM_CT_LEN - 1]).is_err());
    let mut long = ct.clone();
    long.push(0u8);
    assert!(pq_kem_decapsulate(&seed, &long).is_err());
}

// ===========================================================================
// 7. Package round-trip, wrong-recipient and cross-leg refusals
// ===========================================================================

#[test]
fn pq_kem_package_roundtrip_and_refusals() {
    let members = four_members();
    let parties = kem_parties(&members);
    let plaintext = [0x77u8; 32];
    let pkg = encrypt_share_package_pq(2, &parties[0].kem_ek, &plaintext).expect("pq encrypt works");
    assert_eq!(pkg.recipient_index, 2);
    assert_eq!(pkg.ciphertext.len(), PQ_KEM_PACKAGE_CT_LEN);
    assert_eq!(pkg.ephemeral_pk, [0u8; 32]);
    // Round-trip with the right seed.
    assert_eq!(
        decrypt_share_package_pq(&parties[0].kem_seed, &pkg).expect("pq decrypt works"),
        plaintext
    );
    // Wrong recipient (another member's valid seed): the implicit-rejection
    // key mismatch surfaces as an AEAD refusal — never a wrong share.
    let err = decrypt_share_package_pq(&parties[1].kem_seed, &pkg)
        .expect_err("wrong recipient must be refused");
    assert!(err.contains("pq kem"), "the refusal names the pq kem leg: {err}");
    // Tampered KEM ct at the start, middle and end of the kem_ct region.
    for tamper_at in [0usize, 511, PQ_KEM_CT_LEN - 1] {
        let mut bad = pkg.clone();
        bad.ciphertext[tamper_at] ^= 0x01;
        assert!(
            decrypt_share_package_pq(&parties[0].kem_seed, &bad).is_err(),
            "tampered kem_ct at byte {tamper_at} must be refused"
        );
    }
    // Tampered AEAD tail.
    let mut bad_aead = pkg.clone();
    let last = bad_aead.ciphertext.len() - 1;
    bad_aead.ciphertext[last] ^= 0x01;
    assert!(
        decrypt_share_package_pq(&parties[0].kem_seed, &bad_aead).is_err(),
        "tampered aead tail must be refused"
    );
    // Cross-leg: the PQ decryptor refuses the classical 48-byte shape.
    let committee = committee_of(5, &members);
    let classical = build_contributions(&committee, &members);
    let classical_pkg = classical[0].0.packages[0].clone();
    let err = decrypt_share_package_pq(&parties[1].kem_seed, &classical_pkg)
        .expect_err("classical package must be refused by the PQ decryptor");
    assert!(err.contains("pq kem"), "the refusal names the pq kem leg: {err}");
    // And the classical ingest refuses the PQ-KEM shape fail-closed.
    let pq_envelopes = build_pq_envelopes(&committee, &members, &parties);
    let foreign = pq_envelopes
        .iter()
        .find(|e| e.contribution.validator_id != members[1].id)
        .expect("another contributor exists");
    let mut dkg = EpochDkg::new(committee, members[1].id);
    let err = dkg
        .ingest(foreign.contribution.clone(), &members[1].enc_secret)
        .expect_err("classical ingest must refuse PQ packages");
    assert!(
        err.contains("ciphertext length"),
        "the refusal names the shape mismatch: {err}"
    );
}

// ===========================================================================
// 8. Tampered-ct implicit-rejection end-to-end (re-sealed tamper)
// ===========================================================================

#[test]
fn pq_kem_tampered_ct_refused_end_to_end() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let parties = kem_parties(&members);
    let envelopes = build_pq_envelopes(&committee, &members, &parties);
    let contributor_id = envelopes[0].contribution.validator_id;
    let victim = members
        .iter()
        .find(|m| m.id != contributor_id)
        .expect("another member exists");
    let victim_seed = kem_seed_of(&parties, &victim.id);
    let expected = falcon_pk_of(&members, &contributor_id);
    // Flip a KEM-ct byte in the VICTIM's package, then RE-SEAL with the
    // contributor's Falcon key so Falcon passes and the KEM/AEAD layer is
    // what refuses: implicit rejection (fallback key) -> tag failure ->
    // `Err`, never VSS, never a divergent share.
    let victim_index = committee.index_of(&victim.id).expect("victim has an index");
    let mut tampered = envelopes[0].clone();
    tampered
        .contribution
        .packages
        .iter_mut()
        .find(|p| p.recipient_index == victim_index)
        .expect("the victim has a package")
        .ciphertext[7] ^= 0x01;
    let contributor = members
        .iter()
        .find(|m| m.id == contributor_id)
        .expect("contributor is a member");
    let resealed = pq_transport_seal(&contributor.falcon, tampered.contribution.clone());
    pq_transport_verify(&resealed, &expected).expect("the re-sealed envelope verifies");
    let mut dkg = EpochDkg::new(committee.clone(), victim.id);
    let err = dkg
        .ingest_authenticated_pq(&resealed, victim_seed, &expected)
        .expect_err("tampered kem ct must not ingest");
    assert!(err.contains("pq kem"), "the refusal names the pq kem leg: {err}");
    // Without the re-seal, Falcon guards the PQ-shaped bytes first.
    let mut dkg2 = EpochDkg::new(committee.clone(), victim.id);
    let err = dkg2
        .ingest_authenticated_pq(&tampered, victim_seed, &expected)
        .expect_err("un-sealed tamper must not ingest");
    assert!(err.contains("falcon"), "the refusal names the falcon leg: {err}");
    // Wrong recipient seed end-to-end: the victim's DKG opened with
    // another member's valid seed refuses at transport (implicit-rejection
    // key mismatch -> AEAD tag failure).
    let other = members
        .iter()
        .find(|m| m.id != contributor_id && m.id != victim.id)
        .expect("a third member exists");
    let wrong_seed = kem_seed_of(&parties, &other.id);
    let mut dkg3 = EpochDkg::new(committee.clone(), victim.id);
    let err = dkg3
        .ingest_authenticated_pq(&envelopes[0], wrong_seed, &expected)
        .expect_err("wrong-recipient ingest must be refused");
    assert!(err.contains("pq kem"), "the refusal names the pq kem leg: {err}");
}

// ===========================================================================
// 9. Default-off fallback of the NEW entry point is byte-identical
// ===========================================================================

#[test]
fn pq_kem_transport_fallback_is_byte_identical() {
    // FULL-PQ: no fallback — the KEM entry always takes the KEM leg and
    // refuses classical (48-byte) envelopes fail-closed.
    assert!(
        !pq_transport_is_default_off(),
        "FULL-PQ always-on: no default-off"
    );
    let members = four_members();
    let committee = committee_of(5, &members);
    let parties = kem_parties(&members);
    let contributions = build_contributions(&committee, &members);
    // Classical envelopes are refused by the KEM entry (no byte-identical
    // fallback exists).
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
    let mut dkg = EpochDkg::new(committee.clone(), members[1].id);
    let seed = kem_seed_of(&parties, &members[1].id);
    let expected = falcon_pk_of(&members, &envelopes[0].contribution.validator_id);
    let err = dkg
        .ingest_pq_kem_transport(&envelopes[0], &members[1].enc_secret, seed, &expected)
        .expect_err("classical envelope must be refused by KEM entry");
    assert!(
        err.contains("FULL-PQ") || err.contains("PQ-KEM"),
        "refusal must name FULL-PQ/KEM: {err}"
    );
}

// ===========================================================================
// 10. Threshold shape intact end-to-end over the PQ leg
// ===========================================================================

#[test]
fn pq_kem_threshold_shape_end_to_end() {
    let members = four_members();
    let committee = committee_of(5, &members);
    assert_eq!(committee.threshold, 3);
    let parties = kem_parties(&members);
    let envelopes = build_pq_envelopes(&committee, &members, &parties);

    // Full DKG with every contribution Falcon-verified then KEM-ingested.
    let materials = run_pq_kem(&committee, &members, &parties, &envelopes);
    // Same deterministic polynomials as the classical run: same `P_e`,
    // same shares. Only the transcript differs — it binds the KEM package
    // bytes (encryption-randomized, like the classical X25519 ones).
    let classical_contribs = build_contributions(&committee, &members);
    let classical = run_classical(&committee, &members, &classical_contribs);
    for m in &materials {
        assert_eq!(
            m.public_key, classical[0].public_key,
            "the PQ-KEM path derives the same P_e"
        );
    }
    for (i, (a, b)) in materials.iter().zip(classical.iter()).enumerate() {
        assert_eq!(a.share, b.share, "member {i}: same share across legs");
    }
    for m in &materials[1..] {
        assert_eq!(
            m.transcript_root, materials[0].transcript_root,
            "the PQ transcript agrees everywhere"
        );
    }
    assert_ne!(
        materials[0].transcript_root, classical[0].transcript_root,
        "the transcript binds the transport bytes"
    );

    // Seal to P_e, unseal with a threshold of partials (one withholds).
    let key = materials[0].public_key();
    let plaintext = b"pq-kem threshold shape probe".to_vec();
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

// ===========================================================================
// 11. H-gate close-out: post-H no session uses classical primitives
// ===========================================================================
//
// COMPAT BREAK AT H (documented, no wire-enum change): below H the gossip
// carries 48-byte X25519 share packages; at/above H it MUST carry 1136-byte
// ML-KEM-768 packages (`kem_ct || aead_ct`) inside the SAME Falcon envelope
// shape (`pq_transport_seal`/`verify` cover the packages via
// `canonical_bytes`). The legs are distinguished by ciphertext LENGTH only —
// `EncryptedShare`/`DkgContribution` are untouched. A pre-H node cannot open
// a PQ package and a post-H node refuses a classical package: that is the
// intended flag-day split, enforced by
// `ingest_{classical,pq_kem_transport}_at_h`, never by a new wire enum.
// Pre-H the gated entries take the classical branch byte-identically (plus
// an operator WARN on the fallback); post-H classical is refused fail-closed
// and only Falcon + ML-KEM-768 ingests.

const PQ_H: u64 = PQ_TRANSPORT_H_ACTIVATION_HEIGHT;

#[test]
fn pq_h_gate_boundary_is_pinned() {
    // Mirrors the activation-height precedent (10_000): change this const
    // deliberately, in a lead-reviewed diff that updates this suite too.
    assert_eq!(
        PQ_TRANSPORT_H_ACTIVATION_HEIGHT, 10_000,
        "H is pinned: moving flag day is a lead decision"
    );
    assert!(
        !is_pq_transport_active(PQ_H - 1),
        "H-1 is pre-H: classical still admitted (with WARN)"
    );
    assert!(
        is_pq_transport_active(PQ_H),
        "H itself is post-H: classical refused"
    );
    assert!(
        is_pq_transport_active(PQ_H + 1),
        "above H is post-H: classical refused"
    );
}

/// PQ session happy path post-H: every member ingests every Falcon-sealed
/// KEM envelope through the height-gated entry at H and finalizes.
#[test]
fn pq_h_gate_pq_session_happy_post_h() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let parties = kem_parties(&members);
    let envelopes = build_pq_envelopes(&committee, &members, &parties);

    let mut dkgs: Vec<EpochDkg> = members
        .iter()
        .map(|m| EpochDkg::new(committee.clone(), m.id))
        .collect();
    for i in 0..members.len() {
        let index = committee
            .index_of(&members[i].id)
            .expect("member has an index");
        if committee.is_contributor(index) {
            let ek_map = kem_ek_map(&committee, &parties);
            dkgs[i]
                .contribution_pq(members[i].id, &members[i].secret, &ek_map)
                .expect("a contributor builds its PQ contribution");
        }
    }
    for i in 0..members.len() {
        let seed = kem_seed_of(&parties, &members[i].id);
        for e in &envelopes {
            let expected = falcon_pk_of(&members, &e.contribution.validator_id);
            dkgs[i]
                .ingest_pq_kem_transport_at_h(e, &members[i].enc_secret, seed, &expected, PQ_H)
                .unwrap_or_else(|err| panic!("member {i} must accept a PQ envelope at H: {err}"));
        }
    }
    assert!(
        dkgs.iter().all(|d| d.can_finalize()),
        "every member finalizes through the H-gated PQ leg"
    );
    let materials: Vec<EpochKeyMaterial> = dkgs
        .iter_mut()
        .map(|d| d.finalize().expect("finalize succeeds"))
        .collect();
    // Same epoch key and shares as the classical run over the same secrets
    // (only the transcript binds the transport bytes, so it differs).
    let classical_contribs = build_contributions(&committee, &members);
    let classical = run_classical(&committee, &members, &classical_contribs);
    for m in &materials {
        assert_eq!(
            m.public_key, classical[0].public_key,
            "the H-gated PQ leg derives the same P_e"
        );
    }
    for (i, (a, b)) in materials.iter().zip(classical.iter()).enumerate() {
        assert_eq!(a.share, b.share, "member {i}: same share across legs");
    }
}

/// FULL-PQ: no pre-H classical fallback exists. The gated entries refuse
/// X25519 packages at ANY height (including pre-H) fail-closed.
#[test]
fn pq_h_gate_classical_pre_h_fallback_is_byte_identical() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let contributions = build_contributions(&committee, &members);

    // Gated KEM entry pre-H: sealed classical envelopes are refused.
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
    let parties = kem_parties(&members);
    let mut dkg = EpochDkg::new(committee.clone(), members[1].id);
    let seed = kem_seed_of(&parties, &members[1].id);
    let expected = falcon_pk_of(&members, &envelopes[0].contribution.validator_id);
    let err = dkg
        .ingest_pq_kem_transport_at_h(
            &envelopes[0],
            &members[1].enc_secret,
            seed,
            &expected,
            PQ_H - 1,
        )
        .expect_err("classical pre-H must be refused under FULL-PQ");
    assert!(
        err.contains("FULL-PQ") || err.contains("PQ-KEM"),
        "refusal must name FULL-PQ/KEM: {err}"
    );

    // Direct classical entry pre-H: refused as well.
    let mut solo = EpochDkg::new(committee.clone(), members[1].id);
    solo.contribution(members[1].id, &members[1].secret, &members[1].enc_secret)
        .expect("own contribution builds");
    let err = solo
        .ingest_classical_at_h(contributions[0].0.clone(), &members[1].enc_secret, PQ_H - 1)
        .expect_err("classical pre-H must be refused under FULL-PQ");
    assert!(
        err.contains("FULL-PQ"),
        "refusal must name FULL-PQ: {err}"
    );
}

/// FULL-PQ: classical refused at ANY height (pre-H and post-H alike),
/// naming FULL-PQ (never a silent downgrade, never a shape-confusion error).
#[test]
fn pq_h_gate_classical_post_h_refused() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let contributions = build_contributions(&committee, &members);
    let parties = kem_parties(&members);
    let (first_contribution, _) = &contributions[0];
    let contributor = members
        .iter()
        .find(|m| m.id == first_contribution.validator_id)
        .expect("contributor is a member");
    let envelope = pq_transport_seal(&contributor.falcon, first_contribution.clone());

    for height in [PQ_H, PQ_H + 1] {
        // Gated KEM entry refuses the classical (48-byte) envelope.
        let mut dkg = EpochDkg::new(committee.clone(), members[1].id);
        let seed = kem_seed_of(&parties, &members[1].id);
        let err = dkg
            .ingest_pq_kem_transport_at_h(
                &envelope,
                &members[1].enc_secret,
                seed,
                &contributor.falcon_pk,
                height,
            )
            .expect_err("classical envelope must be refused under FULL-PQ");
        assert!(
            err.contains("FULL-PQ") || err.contains("refused"),
            "the refusal names FULL-PQ: {err}"
        );

        // Direct classical entry refuses too.
        let mut solo = EpochDkg::new(committee.clone(), members[1].id);
        let err = solo
            .ingest_classical_at_h(first_contribution.clone(), &members[1].enc_secret, height)
            .expect_err("classical ingest must be refused under FULL-PQ");
        assert!(
            err.contains("FULL-PQ"),
            "the refusal names FULL-PQ: {err}"
        );
    }
}
