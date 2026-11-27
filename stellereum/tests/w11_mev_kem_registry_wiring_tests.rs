//! WAVE 11 — MEV KEM registry wiring on `ValidatorRuntime`.
//!
//! Pins the two honest states of node-side epoch DKG:
//!
//! 1. NO wiring (no `MevKemRegistry`, no 64-byte ML-KEM seed): the runtime
//!    refuses node-side DKG and keeps `mempool.mev_seal.material() == None`,
//!    exactly the fail-closed state the earlier MEV PQ transport suite pins.
//! 2. Wiring installed (`with_mev_kem`): the SAME `PqDkg` / `PqRelease` frames
//!    are accepted, the epoch material finalizes, and it is byte-for-byte the
//!    material a directly-driven `EpochSealManager` derives from the same
//!    contribution set.
//!
//! It also pins seed hygiene: the seed never appears in the runtime's `Debug`
//! output and is held as `Zeroizing<[u8; 64]>`, not a plain array.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::mev_epoch::{
    pq_kem_ek_from_seed, pq_share_release_seal, pq_transport_seal, EpochDkg, EpochSealManager,
    MevFrame, ShareRelease,
};
use stellereum::mev_kem_registry::MevKemRegistry;
use stellereum::post_quantum::{set_pure_pq_override, FalconKeypair};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;

fn kem_seed(byte: u8) -> [u8; 64] {
    let mut seed = [0u8; 64];
    seed[0] = byte;
    seed[63] = byte ^ 0xA5;
    seed
}

fn registry_for(ids: &[[u8; 32]], seeds: &[[u8; 64]]) -> MevKemRegistry {
    let mut registry = MevKemRegistry::new();
    for (id, seed) in ids.iter().zip(seeds) {
        registry
            .register(*id, pq_kem_ek_from_seed(seed), 0, 0, true)
            .expect("test KEM key registers at genesis");
    }
    registry
}

fn register_peer_falcon(key: SigningKey, falcon: FalconKeypair) -> ValidatorRuntime {
    // Mirrors node startup: installing the Falcon keypair registers the
    // validator's PQ key in the consensus registry used to authenticate the
    // contributor's `PqDkg` envelope.
    let id = key.verifying_key().to_bytes();
    let set = ValidatorSet::from_list(vec![(id, 100)]);
    let state = Arc::new(InMemoryStateEngine::new());
    ValidatorRuntime::new(key, set, state, 1).with_falcon_key(falcon)
}

/// Build the peer's registry-wired contribution exactly as it travels on the
/// wire (Falcon-sealed `PqDkg`).
fn peer_envelope(
    epoch: u64,
    height: u64,
    ids: &[[u8; 32]],
    peer_id: [u8; 32],
    peer_secret: &[u8; 32],
    peer_falcon: &FalconKeypair,
    registry: &MevKemRegistry,
) -> stellereum::mev_epoch::PqTransportEnvelope {
    let committee =
        EpochSealManager::committee_from_registry(epoch, ids, registry, height).expect("committee");
    let mut dkg = EpochDkg::new(committee, peer_id);
    let contribution = dkg
        .contribution_pq_from_registry(peer_id, peer_secret, registry, height)
        .expect("peer contributes through the registry");
    pq_transport_seal(peer_falcon, contribution)
}

#[tokio::test]
async fn runtime_without_kem_wiring_refuses_node_side_dkg() {
    set_pure_pq_override(Some(true));

    let sk0 = SigningKey::from_bytes(&[0xD1; 32]);
    let sk1 = SigningKey::from_bytes(&[0xD2; 32]);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(id0, 100), (id1, 100)]);
    // The runtime builds the committee from the validator set's (BTreeMap)
    // order; every direct/peer construction must use the SAME order or the
    // committee hash differs.
    let ids: Vec<[u8; 32]> = validators.validators.keys().copied().collect();
    let fk0 = FalconKeypair::generate_from_seed_bytes(&[0xE1; 32]);
    let fk1 = FalconKeypair::generate_from_seed_bytes(&[0xE2; 32]);
    let kem0 = kem_seed(0x10);
    let kem1 = kem_seed(0x20);
    let registry = registry_for(&[id0, id1], &[kem0, kem1]);

    let state = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(sk0, validators, state, 1).with_falcon_key(fk0.clone());

    // Default posture: no registry, no seed.
    assert!(rt.mev_kem_registry.is_none());
    assert!(rt.mev_kem_seed.is_none());

    // Register contributor 1's Falcon key so the envelope is admissible by
    // the consensus PQ registry (as on a live node).
    let _peer = register_peer_falcon(sk1.clone(), fk1.clone());

    // DKG start must fail closed: no contribution is built or ingested.
    rt.sync_mev_epoch().await;
    assert!(
        rt.mempool.read().await.mev_seal.material().is_none(),
        "no KEM wiring => no epoch material"
    );
    assert!(
        rt.mempool
            .read()
            .await
            .mev_seal
            .own_contribution()
            .is_none(),
        "no KEM wiring => no node-side DKG contribution"
    );

    // Even a VALID, Falcon-sealed peer contribution must not manufacture
    // material without the registry + seed.
    let env = peer_envelope(0, 1, &ids, id1, &sk1.to_bytes(), &fk1, &registry);
    rt.on_mev_frame(MevFrame::PqDkg(env)).await;
    assert!(
        rt.mempool.read().await.mev_seal.material().is_none(),
        "FULL-PQ: runtime must refuse node-side DKG without the KEM wiring, never fall back"
    );
}

#[tokio::test]
async fn runtime_with_kem_wiring_matches_direct_manager_and_redacts_seed() {
    set_pure_pq_override(Some(true));

    let sk0 = SigningKey::from_bytes(&[0xD1; 32]);
    let sk1 = SigningKey::from_bytes(&[0xD2; 32]);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(id0, 100), (id1, 100)]);
    // Match the runtime's committee order exactly (BTreeMap by validator id).
    let ids: Vec<[u8; 32]> = validators.validators.keys().copied().collect();
    let fk0 = FalconKeypair::generate_from_seed_bytes(&[0xE1; 32]);
    let fk1 = FalconKeypair::generate_from_seed_bytes(&[0xE2; 32]);
    let kem0 = kem_seed(0x10);
    let kem1 = kem_seed(0x20);
    let registry = registry_for(&[id0, id1], &[kem0, kem1]);

    let state = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(sk0.clone(), validators, state, 1)
        .with_falcon_key(fk0.clone())
        .with_mev_kem(Arc::new(registry.clone()), kem0);

    let _peer = register_peer_falcon(sk1.clone(), fk1.clone());

    // Start the 2-of-2 DKG: our own contribution exists, but one contribution
    // cannot finalize a threshold-2 epoch.
    rt.sync_mev_epoch().await;
    assert!(
        rt.mempool.read().await.mev_seal.material().is_none(),
        "one contribution must not finalize a 2-of-2 DKG"
    );
    let own = rt
        .mempool
        .read()
        .await
        .mev_seal
        .own_contribution()
        .cloned()
        .expect("wired runtime publishes its own contribution");

    // Feed the peer's valid PqDkg frame: the epoch material finalizes.
    let peer_env = peer_envelope(0, 1, &ids, id1, &sk1.to_bytes(), &fk1, &registry);
    rt.on_mev_frame(MevFrame::PqDkg(peer_env.clone())).await;
    let runtime_material = rt
        .mempool
        .read()
        .await
        .mev_seal
        .material()
        .cloned()
        .expect("wired runtime finalizes the 2-of-2 epoch");

    // Direct control: same registry, same seeds, same exact contribution set.
    // The polynomial is deterministic in the long-term secret, so the direct
    // manager accepts the runtime's own (randomized-package) contribution.
    let mut direct = EpochSealManager::new();
    let _ = direct
        .sync_epoch_pq(0, &ids, id0, &sk0.to_bytes(), &kem0, &registry, 1)
        .expect("direct registry-wired sync");
    let own_env = pq_transport_seal(&fk0, own);
    direct
        .ingest_contribution_pq(&own_env, &kem0, &id0, fk0.public_key(), &registry, 1)
        .expect("direct manager accepts the same own contribution");
    direct
        .ingest_contribution_pq(&peer_env, &kem0, &id0, fk1.public_key(), &registry, 1)
        .expect("direct manager accepts the same peer contribution");
    let direct_material = direct.material().cloned().expect("direct material");

    assert_eq!(runtime_material.epoch, direct_material.epoch);
    assert_eq!(runtime_material.public_key, direct_material.public_key);
    assert_eq!(runtime_material.share, direct_material.share);
    assert_eq!(
        runtime_material.committee_hash,
        direct_material.committee_hash
    );
    assert_eq!(
        runtime_material.transcript_root,
        direct_material.transcript_root
    );
    assert_eq!(runtime_material.threshold, direct_material.threshold);
    assert_eq!(runtime_material.commitment(), direct_material.commitment());

    // The sibling Falcon-authenticated frame type is accepted on the same
    // wired runtime: install an empty order commitment, then feed the peer's
    // authenticated release against it. (Releases never consume KEM keys;
    // this pins that the wired DKG does not regress the release branch.)
    let order = {
        let mut pool = rt.mempool.write().await;
        pool.mev_seal
            .commit_order_pq(1, 0, Vec::new(), &sk0, &fk0)
            .expect("empty order commitment")
    };
    let release = ShareRelease {
        epoch: 0,
        height: 1,
        round: 0,
        order_root: order.order_root,
        partials: Vec::new(),
    };
    let release_env = pq_share_release_seal(&fk1, id1, release);
    rt.on_mev_frame(MevFrame::PqRelease(release_env)).await;
    assert!(
        rt.mempool.read().await.mev_seal.material().is_some(),
        "a valid PqRelease must not disturb the finalized epoch material"
    );

    // Seed hygiene: never in Debug, and held as `Zeroizing<[u8; 64]>`.
    let pool =
        stellereum::mempool::Mempool::default().with_mev_kem(Arc::new(registry.clone()), kem0);
    assert_eq!(*pool.mev_kem().expect("pool wiring").seed(), kem0);
    let pool_debug = format!("{pool:?}");
    assert!(
        !pool_debug.contains(&hex::encode(kem0)),
        "mempool Debug must never contain the MEV KEM seed"
    );

    let debug = format!("{rt:?}");
    assert!(
        !debug.contains(&hex::encode(kem0)),
        "runtime Debug must never contain the ML-KEM seed: {debug}"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "runtime Debug should name the seed as redacted: {debug}"
    );
    fn assert_zeroizing_seed(seed: &Option<zeroize::Zeroizing<[u8; 64]>>) {
        let seed = seed.as_ref().expect("wired runtime holds the seed");
        assert_eq!(seed.len(), 64, "FIPS-203 KEM seed is d || z (64 bytes)");
    }
    assert_zeroizing_seed(&rt.mev_kem_seed);
}

#[test]
fn kem_registry_upsert_and_merge_are_deterministic_idempotent_and_fail_closed() {
    use stellereum::mev_kem_registry::{MevKemRegistryError, MEV_KEM_EK_LEN};

    let id0 = SigningKey::from_bytes(&[0xA1; 32])
        .verifying_key()
        .to_bytes();
    let id1 = SigningKey::from_bytes(&[0xA2; 32])
        .verifying_key()
        .to_bytes();
    let id2 = SigningKey::from_bytes(&[0xA3; 32])
        .verifying_key()
        .to_bytes();
    let ek0 = pq_kem_ek_from_seed(&kem_seed(0x31));
    let ek1 = pq_kem_ek_from_seed(&kem_seed(0x32));
    let ek1_alt = pq_kem_ek_from_seed(&kem_seed(0x33));
    let ek2 = pq_kem_ek_from_seed(&kem_seed(0x34));

    let mut reg = MevKemRegistry::new();
    // Unknown validator refused.
    assert_eq!(
        reg.upsert_registered_ek(id0, ek0.clone(), 0, 0, false),
        Err(MevKemRegistryError::UnknownValidator)
    );
    // Malformed / wrong-length key refused.
    assert_eq!(
        reg.upsert_registered_ek(id0, vec![0x11; 32], 0, 0, true),
        Err(MevKemRegistryError::MalformedKey)
    );
    assert_eq!(
        reg.upsert_registered_ek(id0, vec![0xFF; MEV_KEM_EK_LEN], 0, 0, true),
        Err(MevKemRegistryError::MalformedKey)
    );
    // Future activation_height (> now_height) refused so peers cannot brick get_active_ek.
    assert_eq!(
        reg.upsert_registered_ek(id0, ek0.clone(), 10, 5, true),
        Err(MevKemRegistryError::ActivationInFuture)
    );
    assert!(reg.record_of(&id0).is_none());

    // First insert succeeds, identical re-announcement is idempotent (Ok(false)).
    assert_eq!(
        reg.upsert_registered_ek(id0, ek0.clone(), 0, 0, true),
        Ok(true)
    );
    assert_eq!(
        reg.upsert_registered_ek(id0, ek0.clone(), 0, 0, true),
        Ok(false)
    );

    // Conflicting key for already-registered validator is refused without rotation.
    assert_eq!(
        reg.upsert_registered_ek(id0, ek1.clone(), 0, 0, true),
        Err(MevKemRegistryError::AlreadyRegistered)
    );
    assert_eq!(reg.get_active_ek(&id0, 0), Some(ek0.clone()));

    // Deterministic merge_from: absorbs new entries, idempotent on matching ones.
    let mut other = MevKemRegistry::new();
    other.register(id0, ek0.clone(), 0, 0, true).unwrap();
    other.register(id1, ek1.clone(), 5, 0, true).unwrap();
    assert_eq!(reg.merge_from(&other), Ok(1));
    assert_eq!(reg.merge_from(&other), Ok(0));
    assert_eq!(reg.get_active_ek(&id1, 4), None);
    assert_eq!(reg.get_active_ek(&id1, 5), Some(ek1.clone()));

    // Atomic fail-closed merge_from: a single conflict aborts without inserting id2.
    let mut conflicting = MevKemRegistry::new();
    conflicting.register(id2, ek2.clone(), 0, 0, true).unwrap();
    conflicting.register(id1, ek1_alt, 0, 0, true).unwrap();
    assert_eq!(
        reg.merge_from(&conflicting),
        Err(MevKemRegistryError::AlreadyRegistered)
    );
    assert!(
        reg.record_of(&id2).is_none(),
        "failed merge_from must not partially mutate the registry"
    );

    // Resilient merge_non_conflicting skips only the conflicting validator (id1)
    // and still absorbs valid peer entries (id2).
    let merged = reg.merge_non_conflicting(&conflicting);
    assert_eq!(merged, 1);
    assert_eq!(reg.get_active_ek(&id1, 5), Some(ek1));
    assert_eq!(reg.get_active_ek(&id2, 0), Some(ek2));
}

#[test]
fn kem_key_announcement_seal_verify_and_wire_frame_roundtrip_and_reject_malformed() {
    use stellereum::mev_epoch::{
        is_mev_frame, kem_key_announcement_seal, kem_key_announcement_verify, KemKeyAnnouncement,
        KEM_KEY_ANNOUNCE_DOMAIN, KEM_KEY_PAYLOAD_MAGIC, MAX_MEV_FRAME_BYTES, PQ_KEM_EK_LEN,
    };

    assert_eq!(KEM_KEY_ANNOUNCE_DOMAIN, b"STELL_MEV_KEM_ANNOUNCE_V1");
    assert_eq!(KEM_KEY_PAYLOAD_MAGIC, b"MKM1");

    let sk = SigningKey::from_bytes(&[0xB0; 32]);
    let id = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed_bytes(&[0xB1; 32]);
    let other_fk = FalconKeypair::generate_from_seed_bytes(&[0xB2; 32]);
    let ek = pq_kem_ek_from_seed(&kem_seed(0x41));
    let chain_id = 777u64;

    // Malformed ek refused at seal time.
    assert!(kem_key_announcement_seal(&fk, chain_id, id, vec![0xAA; 32], 0).is_err());
    assert!(kem_key_announcement_seal(&fk, chain_id, id, vec![0xFF; PQ_KEM_EK_LEN], 0).is_err());

    let ann = kem_key_announcement_seal(&fk, chain_id, id, ek.clone(), 12)
        .expect("valid announcement seals");
    kem_key_announcement_verify(&ann, chain_id, fk.public_key())
        .expect("valid announcement verifies");

    // Cross-chain replay (wrong expected_chain_id or tampered chain_id) fails closed.
    assert!(kem_key_announcement_verify(&ann, chain_id + 1, fk.public_key()).is_err());
    let mut tampered_chain = ann.clone();
    tampered_chain.chain_id = chain_id + 1;
    assert!(
        kem_key_announcement_verify(&tampered_chain, chain_id + 1, fk.public_key()).is_err(),
        "mutated chain_id must fail Falcon signature verification"
    );

    // Wrong expected Falcon key, empty key/sig, tampered fields all fail closed.
    assert!(kem_key_announcement_verify(&ann, chain_id, other_fk.public_key()).is_err());
    assert!(kem_key_announcement_verify(&ann, chain_id, &[]).is_err());
    assert!(kem_key_announcement_verify(&ann, chain_id, &[0u8; 32]).is_err());

    let mut bad_sig = ann.clone();
    bad_sig.falcon_signature[10] ^= 0x01;
    assert!(kem_key_announcement_verify(&bad_sig, chain_id, fk.public_key()).is_err());

    let mut empty_sig = ann.clone();
    empty_sig.falcon_signature.clear();
    assert!(kem_key_announcement_verify(&empty_sig, chain_id, fk.public_key()).is_err());

    let mut bad_height = ann.clone();
    bad_height.activation_height += 1;
    assert!(kem_key_announcement_verify(&bad_height, chain_id, fk.public_key()).is_err());

    let mut bad_ek_len = ann.clone();
    bad_ek_len.ek.pop();
    assert!(kem_key_announcement_verify(&bad_ek_len, chain_id, fk.public_key()).is_err());

    let raw_forged = KemKeyAnnouncement {
        chain_id,
        validator_id: id,
        ek: vec![0xFF; PQ_KEM_EK_LEN],
        activation_height: 0,
        falcon_signature: ann.falcon_signature.clone(),
    };
    assert!(kem_key_announcement_verify(&raw_forged, chain_id, fk.public_key()).is_err());

    // Wire framing: MevFrame::KemKey roundtrips and rejects malformed/trailing/oversized bytes.
    let frame = MevFrame::KemKey(ann.clone());
    assert_eq!(frame.magic(), KEM_KEY_PAYLOAD_MAGIC);
    let wire = frame.encode().expect("kem key frame encodes");
    assert_eq!(&wire[..4], b"MKM1");
    assert!(is_mev_frame(&wire));
    assert!(!is_mev_frame(b"MKM1"));
    assert_eq!(
        MevFrame::decode(&wire).expect("kem key frame decodes"),
        frame
    );

    // Truncated body fails closed.
    assert!(MevFrame::decode(b"MKM1").is_err());
    let mut truncated = wire.clone();
    truncated.truncate(wire.len() - 4);
    assert!(MevFrame::decode(&truncated).is_err());

    // Trailing garbage fails closed.
    let mut trailing = wire.clone();
    trailing.push(0x99);
    assert!(MevFrame::decode(&trailing).is_err());

    // Pathological bincode length prefix fails closed without OOM.
    let mut evil = KEM_KEY_PAYLOAD_MAGIC.to_vec();
    evil.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(MevFrame::decode(&evil).is_err());

    // Oversized body (> MAX_MEV_FRAME_BYTES) fails closed.
    let mut oversized = Vec::with_capacity(4 + MAX_MEV_FRAME_BYTES as usize + 1);
    oversized.extend_from_slice(KEM_KEY_PAYLOAD_MAGIC);
    oversized.resize(4 + MAX_MEV_FRAME_BYTES as usize + 1, 0x22);
    assert!(is_mev_frame(&oversized));
    let err = MevFrame::decode(&oversized).expect_err("oversized MKM1 frame must fail closed");
    assert!(
        err.contains("exceeds max wire size"),
        "oversized refusal names wire limit: {err}"
    );
}

#[tokio::test]
async fn two_runtimes_exchange_kem_key_announcements_and_converge_to_same_epoch_material() {
    use stellereum::mev_epoch::{
        compute_partial, seal_transaction, unseal_transaction, DecryptionPartial, TransparentMeta,
    };

    set_pure_pq_override(Some(true));

    let sk0 = SigningKey::from_bytes(&[0xC1; 32]);
    let sk1 = SigningKey::from_bytes(&[0xC2; 32]);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(id0, 100), (id1, 100)]);
    let fk0 = FalconKeypair::generate_from_seed_bytes(&[0xF1; 32]);
    let fk1 = FalconKeypair::generate_from_seed_bytes(&[0xF2; 32]);
    let kem0 = kem_seed(0x51);
    let kem1 = kem_seed(0x52);

    // Mirror bootstrap.rs::mev_kem_registry_for_node: each node ONLY knows its OWN KEM key.
    let reg0 = registry_for(&[id0], &[kem0]);
    let reg1 = registry_for(&[id1], &[kem1]);

    // Test both wiring paths: rt0 via ValidatorRuntime::with_mev_kem, rt1 via Mempool::with_mev_kem.
    let mut rt0 = ValidatorRuntime::new(
        sk0.clone(),
        validators.clone(),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_falcon_key(fk0.clone())
    .with_mev_kem(Arc::new(reg0), kem0);

    let pool1 = Arc::new(tokio::sync::RwLock::new(
        stellereum::mempool::Mempool::default().with_mev_kem(Arc::new(reg1), kem1),
    ));
    let mut rt1 = ValidatorRuntime::new(
        sk1.clone(),
        validators,
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_falcon_key(fk1.clone())
    .with_mempool(pool1);

    // Tick 1: each node announces its own ML-KEM-768 key, but cannot start 2-of-2 DKG yet.
    rt0.sync_mev_epoch().await;
    rt1.sync_mev_epoch().await;
    assert!(rt0
        .mempool
        .read()
        .await
        .mev_seal
        .own_contribution()
        .is_none());
    assert!(rt1
        .mempool
        .read()
        .await
        .mev_seal
        .own_contribution()
        .is_none());

    let ann0 = rt0
        .mempool
        .read()
        .await
        .own_kem_announcement()
        .cloned()
        .expect("rt0 builds its KemKeyAnnouncement");
    let ann1 = rt1
        .mempool
        .read()
        .await
        .own_kem_announcement()
        .cloned()
        .expect("rt1 builds its KemKeyAnnouncement");

    // Exchange KemKey frames over wire encoding.
    let wire0 = MevFrame::KemKey(ann0).encode().expect("ann0 encodes");
    let wire1 = MevFrame::KemKey(ann1).encode().expect("ann1 encodes");
    let decoded0 = MevFrame::decode(&wire0).expect("ann0 decodes");
    let decoded1 = MevFrame::decode(&wire1).expect("ann1 decodes");

    rt0.on_mev_frame(decoded1.clone()).await;
    rt1.on_mev_frame(decoded0.clone()).await;

    // Idempotent re-delivery must succeed cleanly without disturbing state.
    rt0.on_mev_frame(decoded1).await;
    rt1.on_mev_frame(decoded0).await;

    // Tick 2: now both runtimes have the merged 2-validator registry and build DKG contributions.
    rt0.sync_mev_epoch().await;
    rt1.sync_mev_epoch().await;

    let contrib0 = rt0
        .mempool
        .read()
        .await
        .mev_seal
        .own_contribution()
        .cloned()
        .expect("rt0 publishes PqDkg contribution after learning peer KEM key");
    let contrib1 = rt1
        .mempool
        .read()
        .await
        .mev_seal
        .own_contribution()
        .cloned()
        .expect("rt1 publishes PqDkg contribution after learning peer KEM key");

    let env0 = pq_transport_seal(&fk0, contrib0);
    let env1 = pq_transport_seal(&fk1, contrib1);

    // Exchange PqDkg frames.
    rt0.on_mev_frame(MevFrame::PqDkg(env1)).await;
    rt1.on_mev_frame(MevFrame::PqDkg(env0)).await;

    let mat0 = rt0
        .mempool
        .read()
        .await
        .mev_seal
        .material()
        .cloned()
        .expect("rt0 finalizes 2-of-2 EpochKeyMaterial");
    let mat1 = rt1
        .mempool
        .read()
        .await
        .mev_seal
        .material()
        .cloned()
        .expect("rt1 finalizes 2-of-2 EpochKeyMaterial");

    assert_eq!(mat0.epoch, mat1.epoch);
    assert_eq!(mat0.public_key, mat1.public_key);
    assert_eq!(mat0.committee_hash, mat1.committee_hash);
    assert_eq!(mat0.transcript_root, mat1.transcript_root);
    assert_eq!(mat0.threshold, 2);
    assert_eq!(mat1.threshold, 2);
    assert_eq!(mat0.commitment(), mat1.commitment());

    // End-to-end check: a transaction sealed to the converged epoch key unseals with both shares.
    let committee0 = rt0
        .mempool
        .read()
        .await
        .mev_seal
        .committee()
        .cloned()
        .expect("committee present");
    let meta = TransparentMeta {
        from: [0x11; 32],
        nonce: 0,
        gas_limit: 21_000,
        priority_fee_per_gas: 1,
        source_shard: 1,
        target_shard: 1,
    };
    let sealed = seal_transaction(&mat0.public_key(), b"sealed-mev-tx", [0x22; 32], meta)
        .expect("wallet seals to converged epoch key");
    let p0 = DecryptionPartial {
        validator_index: committee0.index_of(&id0).unwrap(),
        point: compute_partial(&mat0.share, &sealed.ephemeral_pk).unwrap(),
    };
    let p1 = DecryptionPartial {
        validator_index: committee0.index_of(&id1).unwrap(),
        point: compute_partial(&mat1.share, &sealed.ephemeral_pk).unwrap(),
    };
    let plain = unseal_transaction(&sealed, &[p0, p1], 2, &mat0.committee_hash)
        .expect("converged shares unseal transaction");
    assert_eq!(plain, b"sealed-mev-tx");
}

#[tokio::test]
async fn forged_or_unwired_kem_key_announcements_are_refused_fail_closed() {
    use stellereum::mev_epoch::{kem_key_announcement_seal, KemKeyAnnouncement, PQ_KEM_EK_LEN};

    set_pure_pq_override(Some(true));

    let sk0 = SigningKey::from_bytes(&[0xB5; 32]);
    let sk1 = SigningKey::from_bytes(&[0xB6; 32]);
    let outsider_sk = SigningKey::from_bytes(&[0xB7; 32]);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let outsider_id = outsider_sk.verifying_key().to_bytes();

    let validators = ValidatorSet::from_list(vec![(id0, 100), (id1, 100)]);
    let fk0 = FalconKeypair::generate_from_seed_bytes(&[0xF5; 32]);
    let fk1 = FalconKeypair::generate_from_seed_bytes(&[0xF6; 32]);
    let attacker_fk = FalconKeypair::generate_from_seed_bytes(&[0xF7; 32]);
    let kem0 = kem_seed(0x61);
    let kem1 = kem_seed(0x62);
    let kem1_alt = kem_seed(0x63);

    // Register id1's and outsider's Falcon keys via helper runtimes (mirrors node startup).
    let _reg_peer = register_peer_falcon(sk1.clone(), fk1.clone());
    let _reg_outsider = register_peer_falcon(outsider_sk, attacker_fk.clone());

    let state = Arc::new(InMemoryStateEngine::new());
    let chain_id = state.chain_id;
    let reg0 = registry_for(&[id0], &[kem0]);
    let mut rt_wired = ValidatorRuntime::new(sk0.clone(), validators.clone(), state, 1)
        .with_falcon_key(fk0.clone())
        .with_mev_kem(Arc::new(reg0), kem0);

    // Unwired runtime must also refuse KemKey frames fail-closed.
    let mut rt_unwired =
        ValidatorRuntime::new(sk0, validators, Arc::new(InMemoryStateEngine::new()), 1)
            .with_falcon_key(fk0);

    let valid_ann1 = kem_key_announcement_seal(&fk1, chain_id, id1, pq_kem_ek_from_seed(&kem1), 0)
        .expect("valid ann1");
    rt_unwired
        .on_mev_frame(MevFrame::KemKey(valid_ann1.clone()))
        .await;
    assert!(
        rt_unwired.mempool.read().await.peer_kem_keys.is_empty(),
        "unwired runtime must refuse KemKey frames and never populate peer_kem_keys"
    );

    // 1. Bad Falcon signature (wrong key or flipped bit) is refused.
    let forged_sig =
        kem_key_announcement_seal(&attacker_fk, chain_id, id1, pq_kem_ek_from_seed(&kem1), 0)
            .expect("forged signature seals syntactically");
    rt_wired.on_mev_frame(MevFrame::KemKey(forged_sig)).await;
    assert!(rt_wired.mempool.read().await.peer_kem_keys.is_empty());

    let mut flipped_sig = valid_ann1.clone();
    flipped_sig.falcon_signature[0] ^= 0xFF;
    rt_wired.on_mev_frame(MevFrame::KemKey(flipped_sig)).await;
    assert!(rt_wired.mempool.read().await.peer_kem_keys.is_empty());

    // 2. Malformed ek length / non-canonical ML-KEM-768 ek is refused.
    let malformed_len = KemKeyAnnouncement {
        chain_id,
        validator_id: id1,
        ek: vec![0x42; 32],
        activation_height: 0,
        falcon_signature: valid_ann1.falcon_signature.clone(),
    };
    rt_wired.on_mev_frame(MevFrame::KemKey(malformed_len)).await;
    assert!(rt_wired.mempool.read().await.peer_kem_keys.is_empty());

    let malformed_canon = KemKeyAnnouncement {
        chain_id,
        validator_id: id1,
        ek: vec![0xFF; PQ_KEM_EK_LEN],
        activation_height: 0,
        falcon_signature: valid_ann1.falcon_signature.clone(),
    };
    rt_wired
        .on_mev_frame(MevFrame::KemKey(malformed_canon))
        .await;
    assert!(rt_wired.mempool.read().await.peer_kem_keys.is_empty());

    // 3. Non-validator id is refused even with a valid Falcon signature.
    let outsider_ann = kem_key_announcement_seal(
        &attacker_fk,
        chain_id,
        outsider_id,
        pq_kem_ek_from_seed(&kem1),
        0,
    )
    .expect("outsider ann seals");
    rt_wired.on_mev_frame(MevFrame::KemKey(outsider_ann)).await;
    assert!(rt_wired.mempool.read().await.peer_kem_keys.is_empty());

    // 3b. Cross-chain KemKeyAnnouncement (wrong chain_id) is refused fail-closed.
    let wrong_chain_ann =
        kem_key_announcement_seal(&fk1, chain_id + 1, id1, pq_kem_ek_from_seed(&kem1), 0)
            .expect("wrong chain ann seals");
    rt_wired
        .on_mev_frame(MevFrame::KemKey(wrong_chain_ann))
        .await;
    assert!(
        rt_wired.mempool.read().await.peer_kem_keys.is_empty(),
        "cross-chain KemKeyAnnouncement must be refused fail-closed"
    );

    // 3c. Future activation_height (> runtime height) is refused fail-closed.
    let future_ann = kem_key_announcement_seal(
        &fk1,
        chain_id,
        id1,
        pq_kem_ek_from_seed(&kem1),
        rt_wired.hc.height + 10,
    )
    .expect("future ann seals");
    rt_wired.on_mev_frame(MevFrame::KemKey(future_ann)).await;
    assert!(
        rt_wired.mempool.read().await.peer_kem_keys.is_empty(),
        "future-activation KemKeyAnnouncement must be refused fail-closed"
    );

    // 4. Valid announcement succeeds, and a subsequent conflicting key for id1 is refused.
    rt_wired.on_mev_frame(MevFrame::KemKey(valid_ann1)).await;
    assert_eq!(
        rt_wired
            .mempool
            .read()
            .await
            .peer_kem_keys
            .get_active_ek(&id1, 1),
        Some(pq_kem_ek_from_seed(&kem1))
    );

    let conflicting_ann1 =
        kem_key_announcement_seal(&fk1, chain_id, id1, pq_kem_ek_from_seed(&kem1_alt), 0)
            .expect("conflicting ann seals");
    rt_wired
        .on_mev_frame(MevFrame::KemKey(conflicting_ann1))
        .await;
    assert_eq!(
        rt_wired
            .mempool
            .read()
            .await
            .peer_kem_keys
            .get_active_ek(&id1, 1),
        Some(pq_kem_ek_from_seed(&kem1)),
        "conflicting KemKeyAnnouncement must never silently overwrite an existing key"
    );
}

#[tokio::test]
async fn single_peer_kem_conflict_does_not_drop_other_peers_keys() {
    set_pure_pq_override(Some(true));

    let sk0 = SigningKey::from_bytes(&[0x91; 32]);
    let sk1 = SigningKey::from_bytes(&[0x92; 32]);
    let sk2 = SigningKey::from_bytes(&[0x93; 32]);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let id2 = sk2.verifying_key().to_bytes();

    let fk0 = FalconKeypair::generate_from_seed_bytes(&[0x94; 32]);
    let kem0 = kem_seed(0x81);
    let kem1 = kem_seed(0x82);
    let kem1_conflict = kem_seed(0x83);
    let kem2 = kem_seed(0x84);

    // Base registry knows id0 and id1.
    let base_reg = registry_for(&[id0, id1], &[kem0, kem1]);

    // Check MevKemWiring::effective_registry directly: conflict on id1 in peer_overlay
    // must NOT drop id2's valid key.
    let pool =
        stellereum::mempool::Mempool::default().with_mev_kem(Arc::new(base_reg.clone()), kem0);
    let wiring = pool.mev_kem().expect("wiring present");
    assert_eq!(
        wiring.upsert_peer_ek(id2, pq_kem_ek_from_seed(&kem2), 0, 1, true),
        Ok(true)
    );
    let eff = wiring.effective_registry();
    assert_eq!(eff.get_active_ek(&id1, 1), Some(pq_kem_ek_from_seed(&kem1)));
    assert_eq!(eff.get_active_ek(&id2, 1), Some(pq_kem_ek_from_seed(&kem2)));

    // Now test ValidatorRuntime::mev_kem_material / sync_mev_epoch when peer_kem_keys
    // contains BOTH a conflicting key for id1 AND a valid key for id2.
    let validators = ValidatorSet::from_list(vec![(id0, 100), (id1, 100), (id2, 100)]);
    let mut rt = ValidatorRuntime::new(sk0, validators, Arc::new(InMemoryStateEngine::new()), 1)
        .with_falcon_key(fk0)
        .with_mev_kem(Arc::new(base_reg), kem0);

    {
        let mut mp = rt.mempool.write().await;
        mp.peer_kem_keys
            .upsert_registered_ek(id1, pq_kem_ek_from_seed(&kem1_conflict), 0, 1, true)
            .expect("insert conflicting id1 into peer_kem_keys");
        mp.peer_kem_keys
            .upsert_registered_ek(id2, pq_kem_ek_from_seed(&kem2), 0, 1, true)
            .expect("insert valid id2 into peer_kem_keys");
    }

    // Because id1's base key is preserved and id2 is merged (not dropped by the id1 conflict),
    // the 3-member committee DKG succeeds (`committee()` is built with all 3 keys).
    rt.sync_mev_epoch().await;
    let pool = rt.mempool.read().await;
    let committee = pool
        .mev_seal
        .committee()
        .expect("single-peer KEM conflict must not drop id2 and stall DKG");
    assert_eq!(committee.members.len(), 3);
    assert!(committee.index_of(&id2).is_some());
}

#[tokio::test]
async fn on_mev_frame_pq_release_rejects_missing_or_corrupted_dleq_proof() {
    use stellereum::mev_epoch::{
        compute_partial, pq_share_release_seal_with_dleq, prove_partial_dleq, seal_transaction,
        DecryptionPartial, TransparentMeta,
    };

    set_pure_pq_override(Some(true));

    let sk0 = SigningKey::from_bytes(&[0x71; 32]);
    let sk1 = SigningKey::from_bytes(&[0x72; 32]);
    let id0 = sk0.verifying_key().to_bytes();
    let id1 = sk1.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(id0, 100), (id1, 100)]);
    let ids: Vec<[u8; 32]> = validators.validators.keys().copied().collect();

    let fk0 = FalconKeypair::generate_from_seed_bytes(&[0x81; 32]);
    let fk1 = FalconKeypair::generate_from_seed_bytes(&[0x82; 32]);
    let kem0 = kem_seed(0x71);
    let kem1 = kem_seed(0x72);
    let registry = registry_for(&[id0, id1], &[kem0, kem1]);

    let _peer = register_peer_falcon(sk1.clone(), fk1.clone());

    let mut rt0 = ValidatorRuntime::new(
        sk0.clone(),
        validators,
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_falcon_key(fk0.clone())
    .with_mev_kem(Arc::new(registry.clone()), kem0);

    rt0.sync_mev_epoch().await;
    let own = rt0
        .mempool
        .read()
        .await
        .mev_seal
        .own_contribution()
        .cloned()
        .expect("own contribution");
    let own_env = pq_transport_seal(&fk0, own);
    let peer_env = peer_envelope(0, 1, &ids, id1, &sk1.to_bytes(), &fk1, &registry);
    rt0.on_mev_frame(MevFrame::PqDkg(peer_env.clone())).await;

    let mat0 = rt0
        .mempool
        .read()
        .await
        .mev_seal
        .material()
        .cloned()
        .expect("rt0 finalized material");

    // Derive peer's share via a direct EpochSealManager using the identical contributions.
    let mut mgr1 = EpochSealManager::new();
    let _ = mgr1
        .sync_epoch_pq(0, &ids, id1, &sk1.to_bytes(), &kem1, &registry, 1)
        .expect("mgr1 sync");
    mgr1.ingest_contribution_pq(&own_env, &kem1, &id1, fk0.public_key(), &registry, 1)
        .expect("mgr1 ingests own0");
    mgr1.ingest_contribution_pq(&peer_env, &kem1, &id1, fk1.public_key(), &registry, 1)
        .expect("mgr1 ingests peer1");
    let mat1 = mgr1.material().cloned().expect("mgr1 material");
    let peer_index = rt0
        .mempool
        .read()
        .await
        .mev_seal
        .committee()
        .expect("committee")
        .index_of(&id1)
        .expect("id1 index");

    let tx_hash = [0x44; 32];
    let meta = TransparentMeta {
        from: [0x33; 32],
        nonce: 0,
        gas_limit: 21_000,
        priority_fee_per_gas: 1,
        source_shard: 0,
        target_shard: 0,
    };
    let sealed =
        seal_transaction(&mat0.public_key(), b"dleq-payload", tx_hash, meta).expect("seal tx");

    let order = {
        let mut pool = rt0.mempool.write().await;
        pool.add_sealed(sealed.clone())
            .expect("mempool admits sealed envelope");
        pool.mev_seal
            .commit_order_pq(1, 0, vec![tx_hash], &sk0, &fk0)
            .expect("commit order")
    };

    let valid_point = compute_partial(&mat1.share, &sealed.ephemeral_pk).expect("valid partial");
    let valid_partial = DecryptionPartial {
        validator_index: peer_index,
        point: valid_point,
    };
    let valid_proof = prove_partial_dleq(
        &mat1.share,
        0,
        peer_index,
        &sealed.ephemeral_pk,
        &valid_point,
    )
    .expect("prove dleq");

    let release = ShareRelease {
        epoch: 0,
        height: 1,
        round: 0,
        order_root: order.order_root,
        partials: vec![(tx_hash, valid_partial)],
    };

    // 1. Falcon-signed release WITHOUT a DLEQ proof must be rejected when sealed envelope is in mempool.
    let missing_dleq_env = pq_share_release_seal(&fk1, id1, release.clone());
    rt0.on_mev_frame(MevFrame::PqRelease(missing_dleq_env))
        .await;
    assert_eq!(
        rt0.mempool.read().await.mev_seal.partial_count(&tx_hash),
        0,
        "PqRelease without DLEQ proof must be rejected"
    );

    // 2. Falcon-signed release with a corrupted DLEQ proof must be rejected.
    let mut bad_proof = valid_proof;
    bad_proof.challenge[0] ^= 0x01;
    let bad_dleq_env =
        pq_share_release_seal_with_dleq(&fk1, id1, release.clone(), vec![(tx_hash, bad_proof)]);
    rt0.on_mev_frame(MevFrame::PqRelease(bad_dleq_env)).await;
    assert_eq!(
        rt0.mempool.read().await.mev_seal.partial_count(&tx_hash),
        0,
        "PqRelease with corrupted DLEQ proof must be rejected"
    );

    // 3. Falcon-signed release with a mismatched partial (computed from wrong share) + valid proof must be rejected.
    let wrong_point = compute_partial(&mat0.share, &sealed.ephemeral_pk).expect("wrong partial");
    let mismatched_release = ShareRelease {
        epoch: 0,
        height: 1,
        round: 0,
        order_root: order.order_root,
        partials: vec![(
            tx_hash,
            DecryptionPartial {
                validator_index: peer_index,
                point: wrong_point,
            },
        )],
    };
    let mismatched_env = pq_share_release_seal_with_dleq(
        &fk1,
        id1,
        mismatched_release,
        vec![(tx_hash, valid_proof)],
    );
    rt0.on_mev_frame(MevFrame::PqRelease(mismatched_env)).await;
    assert_eq!(
        rt0.mempool.read().await.mev_seal.partial_count(&tx_hash),
        0,
        "PqRelease with mismatched partial must be rejected by DLEQ verification"
    );

    // 4. Positive control: valid Falcon signature + valid DLEQ proof is accepted.
    let valid_env =
        pq_share_release_seal_with_dleq(&fk1, id1, release, vec![(tx_hash, valid_proof)]);
    rt0.on_mev_frame(MevFrame::PqRelease(valid_env)).await;
    assert_eq!(
        rt0.mempool.read().await.mev_seal.partial_count(&tx_hash),
        1,
        "valid PqRelease with valid DLEQ proof must be accepted"
    );
}
