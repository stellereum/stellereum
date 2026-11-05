//! MEV committee KEM registry tests: registration, delayed rotation,
//! fail-closed refusals, registry-wired PQ contribution/ingest, classical
//! refusal end-to-end, threshold shape intact over the PQ leg.
//!
//! Deterministic: fixed seeds and explicit heights only — no wall-clock, no
//! env, no filesystem, no shared global state (safe under parallel test
//! execution). Threshold math, Feldman VSS and sealing are NEVER modified
//! here — the registry only decides WHICH bytes are keys.

use ed25519_dalek::SigningKey;
use stellereum::consensus::ValidatorId;
use stellereum::mev_epoch::{
    combine_partials, compute_partial, encryption_public_key_from_ed25519,
    encryption_secret_from_ed25519, pq_kem_ek_from_seed, pq_transport_seal, seal_transaction,
    unseal_transaction, CommitteeMember, DecryptionPartial, DkgContribution, EpochCommittee,
    EpochDkg, EpochKeyMaterial, PqTransportEnvelope, PQ_KEM_EK_LEN, PQ_KEM_PACKAGE_CT_LEN,
    PQ_TRANSPORT_H_ACTIVATION_HEIGHT,
};
use stellereum::mev_kem_registry::{
    MevKemRegistry, MevKemRegistryError, MEV_KEM_EK_LEN, MEV_KEM_HISTORY_LIMIT,
    MEV_KEM_ROTATION_DELAY_HEIGHTS,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::pq_registry::{PQ_KEY_HISTORY_LIMIT, PQ_ROTATION_DELAY_HEIGHTS};

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
    kem_seed: [u8; 64],
    kem_ek: Vec<u8>,
}

fn member(ed_seed: [u8; 32], falcon_seed: [u8; 32], kem_fill: u8) -> Member {
    let signing = SigningKey::from_bytes(&ed_seed);
    let secret = signing.to_bytes();
    let enc_secret = encryption_secret_from_ed25519(&secret);
    let enc_pk = encryption_public_key_from_ed25519(&signing.verifying_key().to_bytes())
        .expect("a fixed ed25519 key converts");
    let falcon = FalconKeypair::generate_from_seed_bytes(&falcon_seed);
    let falcon_pk = falcon.public_key().to_vec();
    let kem_seed = [kem_fill; 64];
    let kem_ek = pq_kem_ek_from_seed(&kem_seed);
    assert_eq!(kem_ek.len(), MEV_KEM_EK_LEN);
    Member {
        id: signing.verifying_key().to_bytes(),
        secret,
        enc_secret,
        enc_pk,
        falcon,
        falcon_pk,
        kem_seed,
        kem_ek,
    }
}

fn four_members() -> Vec<Member> {
    (1u8..=4u8)
        .map(|i| member([i; 32], [0xA0 + i; 32], 0xC0 + i))
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

fn kem_seed_of<'a>(members: &'a [Member], id: &[u8; 32]) -> &'a [u8; 64] {
    &members
        .iter()
        .find(|m| &m.id == id)
        .expect("member exists")
        .kem_seed
}

/// Register every member's KEM key at `at` (activation == now).
fn registered_registry(members: &[Member], at: u64) -> MevKemRegistry {
    let mut reg = MevKemRegistry::new();
    for m in members {
        reg.register(m.id, m.kem_ek.clone(), at, at, true)
            .expect("test registration must succeed");
    }
    reg
}

fn contributor_ids(committee: &EpochCommittee, members: &[Member]) -> Vec<[u8; 32]> {
    members
        .iter()
        .filter(|m| {
            committee.is_contributor(committee.index_of(&m.id).expect("member has an index"))
        })
        .map(|m| m.id)
        .collect()
}

fn seal_envelope(member: &Member, contribution: DkgContribution) -> PqTransportEnvelope {
    pq_transport_seal(&member.falcon, contribution)
}

fn member_by_id<'a>(members: &'a [Member], id: &[u8; 32]) -> &'a Member {
    members.iter().find(|m| &m.id == id).expect("member exists")
}

/// Full classical DKG (for the P_e / share-equality comparison only).
fn run_classical(committee: &EpochCommittee, members: &[Member]) -> Vec<EpochKeyMaterial> {
    let mut dkgs: Vec<EpochDkg> = members
        .iter()
        .map(|m| EpochDkg::new(committee.clone(), m.id))
        .collect();
    let mut contributions = Vec::new();
    for (i, m) in members.iter().enumerate() {
        if let Ok(c) = dkgs[i].contribution(m.id, &m.secret, &m.enc_secret) {
            dkgs[i].set_own(c.clone());
            contributions.push(c);
        }
    }
    assert_eq!(
        contributions.len(),
        committee.contributors.len(),
        "exactly the derived contributor set contributes"
    );
    for (i, m) in members.iter().enumerate() {
        for c in &contributions {
            dkgs[i]
                .ingest(c.clone(), &m.enc_secret)
                .unwrap_or_else(|e| panic!("member {i} must accept a contribution: {e}"));
        }
    }
    dkgs.into_iter()
        .map(|mut d| d.finalize().expect("finalize"))
        .collect()
}

// ===========================================================================
// 1. Const family: same delay philosophy as pq_registry, same KEM size as mev_epoch
// ===========================================================================

#[test]
fn kem_registry_consts_mirror_pq_registry_delay_philosophy() {
    // Same exit-window delay: rotation observable well before enforcement.
    assert_eq!(MEV_KEM_ROTATION_DELAY_HEIGHTS, 7_200);
    assert_eq!(
        MEV_KEM_ROTATION_DELAY_HEIGHTS, PQ_ROTATION_DELAY_HEIGHTS,
        "MEV KEM and PQ delays must move together (same rotation philosophy)"
    );
    assert_eq!(MEV_KEM_HISTORY_LIMIT, PQ_KEY_HISTORY_LIMIT);
    assert_eq!(MEV_KEM_HISTORY_LIMIT, 2);
    // The registry stores exactly ML-KEM-768 encapsulation keys.
    assert_eq!(MEV_KEM_EK_LEN, PQ_KEM_EK_LEN);
    assert_eq!(MEV_KEM_EK_LEN, 1184);
}

// ===========================================================================
// 2. Register/resolve happy path + fail-closed gates
// ===========================================================================

#[test]
fn kem_register_resolve_happy_path() {
    let members = four_members();
    let reg = registered_registry(&members, 10);
    assert_eq!(reg.len(), 4);
    assert!(!reg.is_empty());

    // Height-gated read serves the key inside its window.
    for m in &members {
        assert_eq!(reg.get_active_ek(&m.id, 10), Some(m.kem_ek.clone()));
        assert_eq!(reg.get_active_ek(&m.id, 999_999), Some(m.kem_ek.clone()));
        assert_eq!(reg.current_ek_of(&m.id), Some(m.kem_ek.clone()));
        assert!(reg.pending_of(&m.id).is_none());
        assert!(reg.history_of(&m.id).expect("history").is_empty());
    }
    // Before activation: fail-closed.
    assert_eq!(reg.get_active_ek(&members[0].id, 9), None);
    // Unknown validator: fail-closed, never a classical fallback.
    let unknown: ValidatorId = [0xFF; 32];
    assert_eq!(reg.get_active_ek(&unknown, 10), None);
    assert_eq!(reg.current_ek_of(&unknown), None);

    // Re-register refuses; wrong-size keys (incl. classical X25519) refuse.
    let mut reg = reg;
    assert_eq!(
        reg.register(members[0].id, members[0].kem_ek.clone(), 10, 10, true),
        Err(MevKemRegistryError::AlreadyRegistered)
    );
    assert_eq!(
        reg.register([0xEE; 32], vec![0u8; MEV_KEM_EK_LEN], 10, 10, false),
        Err(MevKemRegistryError::UnknownValidator)
    );
    assert_eq!(
        reg.register([0xEE; 32], vec![0u8; 32], 10, 10, true),
        Err(MevKemRegistryError::MalformedKey)
    );
    assert_eq!(
        reg.register([0xEE; 32], vec![0u8; MEV_KEM_EK_LEN], 9, 10, true),
        Err(MevKemRegistryError::ActivationInPast)
    );
    // announce/apply with no record refuse.
    assert_eq!(
        reg.announce_rotation(unknown, members[0].kem_ek.clone(), 10, true),
        Err(MevKemRegistryError::UnknownValidator)
    );
    assert_eq!(
        reg.apply_rotation(members[0].id, 10, true),
        Err(MevKemRegistryError::NoPendingRotation)
    );
}

// ===========================================================================
// 3. Unknown recipient refused (never classical fallback)
// ===========================================================================

#[test]
fn kem_contribution_unknown_recipient_refused() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let contributors = contributor_ids(&committee, &members);
    assert!(!contributors.is_empty());
    let contributor = member_by_id(&members, &contributors[0]);
    // Register everyone EXCEPT one member that is NOT the builder (so the
    // missing id is always a recipient the builder must encapsulate to).
    let left_out = members
        .iter()
        .find(|m| m.id != contributor.id)
        .expect("another member exists");
    let mut reg = MevKemRegistry::new();
    for m in &members {
        if m.id == left_out.id {
            continue;
        }
        reg.register(m.id, m.kem_ek.clone(), 0, 0, true)
            .expect("test registration must succeed");
    }
    let mut dkg = EpochDkg::new(committee, contributor.id);
    let err = dkg
        .contribution_pq_from_registry(contributor.id, &contributor.secret, &reg, 0)
        .expect_err("an unregistered recipient must be refused");
    assert!(
        err.contains("no active key") && err.contains("never classical fallback"),
        "refusal names the registry gap and the no-fallback rule: {err}"
    );
}

// ===========================================================================
// 4. Rotated key enforced post-delay
// ===========================================================================

#[test]
fn kem_rotated_key_enforced_post_delay() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let mut reg = registered_registry(&members, 0);

    // Rotate members[0]'s key at height 100 -> effective 7300.
    let rotated = &members[0];
    let new_seed = [0xD0u8; 64];
    let new_ek = pq_kem_ek_from_seed(&new_seed);
    assert_ne!(new_ek, rotated.kem_ek);
    reg.announce_rotation(rotated.id, new_ek.clone(), 100, true)
        .expect("announce must succeed");
    let pending = reg.pending_of(&rotated.id).expect("rotation pending");
    assert_eq!(pending.announced_height, 100);
    assert_eq!(
        pending.effective_height,
        100 + MEV_KEM_ROTATION_DELAY_HEIGHTS
    );
    // Second flight while one is pending refuses.
    assert_eq!(
        reg.announce_rotation(rotated.id, vec![0x11u8; MEV_KEM_EK_LEN], 101, true),
        Err(MevKemRegistryError::RotationAlreadyPending)
    );
    // Early apply refuses.
    assert_eq!(
        reg.apply_rotation(rotated.id, 101, true),
        Err(MevKemRegistryError::RotationNotDue)
    );
    // Pre-delay the OLD key is still authoritative (pending not yet effective).
    assert_eq!(
        reg.get_active_ek(&rotated.id, 100),
        Some(rotated.kem_ek.clone())
    );
    assert_eq!(
        reg.get_active_ek(&rotated.id, 100 + MEV_KEM_ROTATION_DELAY_HEIGHTS - 1),
        Some(rotated.kem_ek.clone())
    );
    // Post-delay the NEW key resolves even before apply runs.
    let effective = 100 + MEV_KEM_ROTATION_DELAY_HEIGHTS;
    assert_eq!(
        reg.get_active_ek(&rotated.id, effective),
        Some(new_ek.clone())
    );

    // A contribution built pre-delay encapsulates to the OLD key: the old
    // seed ingests fine through the registry path.
    let contributors = contributor_ids(&committee, &members);
    let builder_id = if contributors.contains(&rotated.id) && contributors.len() > 1 {
        *contributors.iter().find(|id| **id != rotated.id).unwrap()
    } else {
        contributors[0]
    };
    let builder = member_by_id(&members, &builder_id);
    let mut builder_dkg = EpochDkg::new(committee.clone(), builder.id);
    let pre = builder_dkg
        .contribution_pq_from_registry(builder.id, &builder.secret, &reg, 100)
        .expect("pre-delay contribution builds");
    let pre_env = seal_envelope(builder, pre);
    let mut victim = EpochDkg::new(committee.clone(), rotated.id);
    victim
        .ingest_authenticated_pq_from_registry(
            &pre_env,
            &rotated.kem_seed,
            &rotated.id,
            &falcon_pk_of(&members, &builder.id),
            &reg,
            100,
        )
        .expect("pre-delay ingest with the old seed must succeed");

    // Post-delay the registry demands the NEW key: old seed refused
    // (mismatch), new seed accepted.
    let mut builder_dkg2 = EpochDkg::new(committee.clone(), builder.id);
    let post = builder_dkg2
        .contribution_pq_from_registry(builder.id, &builder.secret, &reg, effective)
        .expect("post-delay contribution builds");
    assert!(
        post.packages
            .iter()
            .all(|p| p.ciphertext.len() == PQ_KEM_PACKAGE_CT_LEN),
        "registry-built packages are always KEM-shaped"
    );
    let post_env = seal_envelope(builder, post);
    let mut victim_old = EpochDkg::new(committee.clone(), rotated.id);
    let err = victim_old
        .ingest_authenticated_pq_from_registry(
            &post_env,
            &rotated.kem_seed,
            &rotated.id,
            &falcon_pk_of(&members, &builder.id),
            &reg,
            effective,
        )
        .expect_err("stale seed post-delay must be refused");
    assert!(
        err.contains("mismatch") && err.contains("post-delay"),
        "refusal names the rotation enforcement: {err}"
    );
    let mut victim_new = EpochDkg::new(committee.clone(), rotated.id);
    victim_new
        .ingest_authenticated_pq_from_registry(
            &post_env,
            &new_seed,
            &rotated.id,
            &falcon_pk_of(&members, &builder.id),
            &reg,
            effective,
        )
        .expect("post-delay ingest with the rotated seed must succeed");

    // Apply retires the old key into bounded history; due-sweep is exact.
    let applied = reg.apply_due_rotations(effective);
    assert_eq!(applied, vec![rotated.id]);
    assert_eq!(reg.current_ek_of(&rotated.id), Some(new_ek.clone()));
    assert!(reg.pending_of(&rotated.id).is_none());
    let history = reg.history_of(&rotated.id).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].ek, rotated.kem_ek);
    assert_eq!(history[0].activated_at, 0);
    assert_eq!(history[0].superseded_at, effective);

    // Cancel-by-reannounce: announce the CURRENT key clears a stale flight.
    reg.announce_rotation(
        rotated.id,
        vec![0x22u8; MEV_KEM_EK_LEN],
        effective + 1,
        true,
    )
    .expect("second rotation announces");
    assert!(reg.pending_of(&rotated.id).is_some());
    reg.announce_rotation(rotated.id, new_ek.clone(), effective + 1, true)
        .expect("re-announcing the current key cancels");
    assert!(reg.pending_of(&rotated.id).is_none());
    assert_eq!(reg.get_active_ek(&rotated.id, effective + 1), Some(new_ek));
}

// ===========================================================================
// 5. Classical contribution refused end-to-end (FULL-PQ, any height)
// ===========================================================================

#[test]
fn kem_classical_contribution_refused_end_to_end() {
    let members = four_members();
    let committee = committee_of(5, &members);
    let reg = registered_registry(&members, 0);

    // A classical contribution builds fine (shape check target) ...
    let mut classical_dkg = EpochDkg::new(committee.clone(), members[0].id);
    let classical = classical_dkg
        .contribution(members[0].id, &members[0].secret, &members[0].enc_secret)
        .expect("classical contribution builds");
    assert!(
        classical
            .packages
            .iter()
            .all(|p| p.ciphertext.len() != PQ_KEM_PACKAGE_CT_LEN),
        "classical packages are X25519-shaped, never KEM-shaped"
    );
    // ... but is refused at ANY height, naming FULL-PQ (never ingested).
    for height in [
        0u64,
        PQ_TRANSPORT_H_ACTIVATION_HEIGHT - 1,
        PQ_TRANSPORT_H_ACTIVATION_HEIGHT,
    ] {
        let mut dkg = EpochDkg::new(committee.clone(), members[1].id);
        let err = dkg
            .ingest_classical_at_h(classical.clone(), &members[1].enc_secret, height)
            .expect_err("classical ingest must be refused under FULL-PQ");
        assert!(
            err.contains("FULL-PQ"),
            "refusal names FULL-PQ at height {height}: {err}"
        );
    }

    // ... while the registry path NEVER emits classical bytes.
    let contributors = contributor_ids(&committee, &members);
    let contributor = member_by_id(&members, &contributors[0]);
    let mut dkg = EpochDkg::new(committee, contributor.id);
    let built = dkg
        .contribution_pq_from_registry(contributor.id, &contributor.secret, &reg, 0)
        .expect("registry contribution builds");
    assert!(
        built
            .packages
            .iter()
            .all(|p| p.ciphertext.len() == PQ_KEM_PACKAGE_CT_LEN),
        "registry-built packages are always KEM-shaped"
    );
}

// ===========================================================================
// 6. Threshold flow intact over the PQ leg via the registry
// ===========================================================================

#[test]
fn kem_threshold_flow_intact_over_pq_leg() {
    let members = four_members();
    let committee = committee_of(5, &members);
    assert_eq!(committee.threshold, 3);
    let reg = registered_registry(&members, 0);
    let contributors = contributor_ids(&committee, &members);

    // Full DKG: every contribution built from the registry and ingested
    // through the Falcon-authenticated registry path.
    let envelopes: Vec<PqTransportEnvelope> = contributors
        .iter()
        .map(|id| {
            let m = member_by_id(&members, id);
            let mut dkg = EpochDkg::new(committee.clone(), m.id);
            let contribution = dkg
                .contribution_pq_from_registry(m.id, &m.secret, &reg, 0)
                .expect("registry contribution builds");
            seal_envelope(m, contribution)
        })
        .collect();
    assert_eq!(envelopes.len(), committee.contributors.len());

    let mut materials = Vec::with_capacity(members.len());
    for m in &members {
        let mut dkg = EpochDkg::new(committee.clone(), m.id);
        // Contributors must build (not publish) first so the own-contribution
        // ingest path has its evaluation.
        if contributors.contains(&m.id) {
            dkg.contribution_pq_from_registry(m.id, &m.secret, &reg, 0)
                .expect("a contributor builds its PQ contribution");
        }
        let seed = kem_seed_of(&members, &m.id);
        for e in &envelopes {
            let expected = falcon_pk_of(&members, &e.contribution.validator_id);
            dkg.ingest_authenticated_pq_from_registry(e, seed, &m.id, &expected, &reg, 0)
                .unwrap_or_else(|err| panic!("member must accept a PQ envelope: {err}"));
        }
        assert!(dkg.can_finalize(), "every member finalizes");
        materials.push(dkg.finalize().expect("finalize succeeds"));
    }

    // Same epoch key and shares as the classical run over the same secrets
    // (only the transcript binds the transport bytes, so it differs).
    let classical = run_classical(&committee, &members);
    for m in &materials {
        assert_eq!(
            m.public_key, classical[0].public_key,
            "the registry PQ leg derives the same P_e"
        );
    }
    for (i, (a, b)) in materials.iter().zip(classical.iter()).enumerate() {
        assert_eq!(a.share, b.share, "member {i}: same share across legs");
    }

    // Seal to P_e, unseal with a threshold of partials (one withholds).
    let key = materials[0].public_key();
    let plaintext = b"kem-registry threshold shape probe".to_vec();
    let meta = stellereum::mev_epoch::TransparentMeta {
        from: members[0].id,
        nonce: 0,
        gas_limit: 21_000,
        priority_fee_per_gas: 1,
        source_shard: 0,
        target_shard: 0,
    };
    let envelope = seal_transaction(&key, &plaintext, [0x5Eu8; 32], meta).unwrap();
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
