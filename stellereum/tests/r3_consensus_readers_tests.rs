//! Integration tests for R3-E (consensus readers, height-aware LightHeader quorum,
//! `sync_committed_pq_registry`, `pq_key_at_height_strict`, and `"pq_registry"` domain wiring).

use std::sync::Mutex;

use bincode::Options;
use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, clear_verified_vote_cache, get_validator_pq_key,
    pq_key_at_height, pq_key_at_height_strict, register_validator_pq_key,
    sync_committed_pq_registry, verified_vote_cache_len, QuorumCertificate, ValidatorSet, Vote,
    VoteKind,
};
use stellereum::light_client::LightHeader;
use stellereum::network::SNAPSHOT_PUBLISH_DOMAIN_KINDS;
use stellereum::post_quantum::{set_pure_pq_override, FalconKeypair, PqScheme};
use stellereum::pq_registry::{
    set_pq_lifecycle_activation_override, PqRegistry, PQ_ROTATION_DELAY_HEIGHTS,
};
use stellereum::storage::decode_pq_registry;
use stellereum::sync::SYNC_DOMAIN_KINDS;

/// Process-wide consensus PQ registries, verified-vote cache, and overrides are shared
/// across tests in this binary; serialize tests and restore clean state on exit.
static TEST_LOCK: Mutex<()> = Mutex::new(());

struct TestStateGuard;

impl TestStateGuard {
    fn new() -> Self {
        clear_validator_pq_keys_for_tests();
        sync_committed_pq_registry(&PqRegistry::new(), true);
        clear_verified_vote_cache();
        set_pure_pq_override(None);
        set_pq_lifecycle_activation_override(None);
        Self
    }
}

impl Drop for TestStateGuard {
    fn drop(&mut self) {
        set_pure_pq_override(None);
        set_pq_lifecycle_activation_override(None);
        clear_validator_pq_keys_for_tests();
        sync_committed_pq_registry(&PqRegistry::new(), true);
        clear_verified_vote_cache();
    }
}

fn light_header_at(
    height: u64,
    block_hash: [u8; 32],
    signatures: Vec<([u8; 32], Vec<u8>)>,
) -> LightHeader {
    LightHeader {
        height,
        prev_hash: [0x11u8; 32],
        state_root: [0x22u8; 32],
        block_hash,
        timestamp: height.saturating_mul(1_000),
        proposer: [0u8; 32],
        cert: QuorumCertificate {
            shard_id: 0,
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: Vec::new(),
        },
        signatures,
        shard_id: 0,
        round: 0,
        body_commitment: None,
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

#[test]
fn sync_committed_pq_registry_enforces_rotation_boundary_and_invalidates_vote_cache() {
    let _lock = TEST_LOCK.lock().unwrap();
    let _guard = TestStateGuard::new();

    let sk = SigningKey::from_bytes(&[0x31u8; 32]);
    let val_id = sk.verifying_key().to_bytes();
    let old_fk = FalconKeypair::generate_from_seed(0x41);
    let new_fk = FalconKeypair::generate_from_seed(0x42);
    let validators = ValidatorSet::from_list(vec![(val_id, 1)]);

    let mut reg_initial = PqRegistry::new();
    reg_initial
        .register(
            val_id,
            PqScheme::Falcon512,
            old_fk.public_key().to_vec(),
            0,
            0,
            true,
        )
        .expect("initial registration must succeed");
    sync_committed_pq_registry(&reg_initial, true);

    let announce_height = 5_000u64;
    let effective = announce_height + PQ_ROTATION_DELAY_HEIGHTS;
    let target = Some([0xABu8; 32]);

    // Pre-populate VERIFIED_VOTE_CACHE at height `E` before the rotation is synced:
    // under `reg_initial`, `old_fk` is still valid at height `E`, so the cache records `true`.
    let old_vote_at_e =
        Vote::sign_with_falcon(&sk, &old_fk, effective, 0, VoteKind::Precommit, target);
    assert!(
        old_vote_at_e.verify(),
        "pre-rotation registry must accept old key at E before announcement is committed"
    );
    let cache_len_before = verified_vote_cache_len();
    assert!(
        cache_len_before > 0,
        "vote verification must populate VERIFIED_VOTE_CACHE"
    );

    // Re-syncing the exact same registry with an already-empty legacy map must NOT clear cache.
    sync_committed_pq_registry(&reg_initial, true);
    assert_eq!(
        verified_vote_cache_len(),
        cache_len_before,
        "unchanged registry sync must not flush VERIFIED_VOTE_CACHE"
    );

    // Announce rotation effective at `E` and sync committed registry -> cache MUST be flushed.
    let mut reg_rotated = reg_initial.clone();
    reg_rotated
        .announce_rotation_seq(
            val_id,
            PqScheme::Falcon512,
            new_fk.public_key().to_vec(),
            announce_height,
            1,
            true,
        )
        .expect("rotation announcement must succeed");
    assert_eq!(
        reg_rotated.pending_of(&val_id).map(|p| p.effective_height),
        Some(effective)
    );
    sync_committed_pq_registry(&reg_rotated, true);
    assert_eq!(
        verified_vote_cache_len(),
        0,
        "changed committed registry must clear VERIFIED_VOTE_CACHE"
    );

    // Check both before `apply_due_rotations` (pending) and after `apply_due_rotations` (retired history).
    let mut reg_applied = reg_rotated.clone();
    assert_eq!(reg_applied.apply_due_rotations(effective), vec![val_id]);

    for (phase, reg) in [("pending", &reg_rotated), ("applied", &reg_applied)] {
        sync_committed_pq_registry(reg, true);

        // Key readers across `E - 1 / E / E + 1`:
        assert_eq!(
            pq_key_at_height(&val_id, effective - 1),
            Some((PqScheme::Falcon512, old_fk.public_key().to_vec())),
            "{phase}: E - 1 must resolve to old key"
        );
        assert_eq!(
            pq_key_at_height_strict(&val_id, effective - 1),
            Some((PqScheme::Falcon512, old_fk.public_key().to_vec())),
            "{phase}: strict reader at E - 1 must resolve to old key"
        );
        for h in [effective, effective + 1] {
            assert_eq!(
                pq_key_at_height(&val_id, h),
                Some((PqScheme::Falcon512, new_fk.public_key().to_vec())),
                "{phase}: height {h} must resolve to new key"
            );
            assert_eq!(
                pq_key_at_height_strict(&val_id, h),
                Some((PqScheme::Falcon512, new_fk.public_key().to_vec())),
                "{phase}: strict reader at height {h} must resolve to new key"
            );
        }

        // Vote verification across `E - 1 / E / E + 1` (including cache invalidation on `old_vote_at_e`):
        let old_vote_before =
            Vote::sign_with_falcon(&sk, &old_fk, effective - 1, 0, VoteKind::Precommit, target);
        let new_vote_before =
            Vote::sign_with_falcon(&sk, &new_fk, effective - 1, 0, VoteKind::Precommit, target);
        let new_vote_at_e =
            Vote::sign_with_falcon(&sk, &new_fk, effective, 0, VoteKind::Precommit, target);
        let old_vote_after =
            Vote::sign_with_falcon(&sk, &old_fk, effective + 1, 0, VoteKind::Precommit, target);
        let new_vote_after =
            Vote::sign_with_falcon(&sk, &new_fk, effective + 1, 0, VoteKind::Precommit, target);

        assert!(
            old_vote_before.verify(),
            "{phase}: old vote passes at E - 1"
        );
        assert!(
            !new_vote_before.verify(),
            "{phase}: new vote fails at E - 1"
        );
        assert!(
            !old_vote_at_e.verify(),
            "{phase}: old vote must fail at E after rotation sync"
        );
        assert!(new_vote_at_e.verify(), "{phase}: new vote passes at E");
        assert!(!old_vote_after.verify(), "{phase}: old vote fails at E + 1");
        assert!(new_vote_after.verify(), "{phase}: new vote passes at E + 1");

        // `LightHeader::verify_validator_quorum` across `E - 1 / E / E + 1` in both pure-PQ modes:
        for pure_pq in [false, true] {
            set_pure_pq_override(Some(pure_pq));

            let h_before_hash = [0x61u8; 32];
            let hdr_before_old = light_header_at(
                effective - 1,
                h_before_hash,
                vec![(val_id, old_fk.sign(&h_before_hash))],
            );
            let hdr_before_new = light_header_at(
                effective - 1,
                h_before_hash,
                vec![(val_id, new_fk.sign(&h_before_hash))],
            );
            assert!(
                hdr_before_old.verify_validator_quorum(&validators).is_ok(),
                "{phase} pure_pq={pure_pq}: LightHeader at E - 1 must accept old key"
            );
            assert!(
                hdr_before_new.verify_validator_quorum(&validators).is_err(),
                "{phase} pure_pq={pure_pq}: LightHeader at E - 1 must reject new key"
            );

            for h in [effective, effective + 1] {
                let bh = [0x70u8.wrapping_add((h - effective) as u8); 32];
                let hdr_old = light_header_at(h, bh, vec![(val_id, old_fk.sign(&bh))]);
                let hdr_new = light_header_at(h, bh, vec![(val_id, new_fk.sign(&bh))]);
                assert!(
                    hdr_old.verify_validator_quorum(&validators).is_err(),
                    "{phase} pure_pq={pure_pq}: LightHeader at {h} must reject old key"
                );
                assert!(
                    hdr_new.verify_validator_quorum(&validators).is_ok(),
                    "{phase} pure_pq={pure_pq}: LightHeader at {h} must accept new key"
                );
            }
        }
        set_pure_pq_override(None);
    }
}

#[test]
fn sync_committed_pq_registry_clear_legacy_map_prevents_process_local_leaks() {
    let _lock = TEST_LOCK.lock().unwrap();
    let _guard = TestStateGuard::new();

    let legacy_sk = SigningKey::from_bytes(&[0x51u8; 32]);
    let legacy_id = legacy_sk.verifying_key().to_bytes();
    let legacy_fk = FalconKeypair::generate_from_seed(0x52);

    let committed_sk = SigningKey::from_bytes(&[0x53u8; 32]);
    let committed_id = committed_sk.verifying_key().to_bytes();
    let committed_fk = FalconKeypair::generate_from_seed(0x54);

    // Populate process-local legacy map via `register_validator_pq_key`.
    register_validator_pq_key(
        legacy_id,
        PqScheme::Falcon512,
        legacy_fk.public_key().to_vec(),
    );
    assert_eq!(
        get_validator_pq_key(&legacy_id),
        Some((PqScheme::Falcon512, legacy_fk.public_key().to_vec()))
    );

    let mut reg = PqRegistry::new();
    reg.register(
        committed_id,
        PqScheme::Falcon512,
        committed_fk.public_key().to_vec(),
        0,
        0,
        true,
    )
    .expect("committed validator registration must succeed");

    // With `clear_legacy_map == false`, legacy map still holds `legacy_id`.
    sync_committed_pq_registry(&reg, false);
    assert_eq!(
        get_validator_pq_key(&legacy_id),
        Some((PqScheme::Falcon512, legacy_fk.public_key().to_vec()))
    );
    assert_eq!(
        pq_key_at_height(&legacy_id, 10),
        Some((PqScheme::Falcon512, legacy_fk.public_key().to_vec()))
    );
    assert_eq!(
        pq_key_at_height_strict(&legacy_id, 10),
        None,
        "strict reader must ignore legacy PQ_VALIDATOR_KEYS even before clear"
    );

    // Populate vote cache so we can prove clearing non-empty legacy map flushes it.
    let v = Vote::sign_with_falcon(
        &committed_sk,
        &committed_fk,
        10,
        0,
        VoteKind::Prevote,
        Some([0x99u8; 32]),
    );
    assert!(v.verify());
    assert!(verified_vote_cache_len() > 0);

    // With `clear_legacy_map == true`, legacy `PQ_VALIDATOR_KEYS` is emptied and cache is flushed.
    sync_committed_pq_registry(&reg, true);
    assert_eq!(
        verified_vote_cache_len(),
        0,
        "clearing non-empty PQ_VALIDATOR_KEYS must flush VERIFIED_VOTE_CACHE"
    );
    assert_eq!(
        get_validator_pq_key(&legacy_id),
        None,
        "legacy map must be empty after clear_legacy_map == true"
    );
    assert_eq!(
        get_validator_pq_key(&committed_id),
        None,
        "legacy map must stay empty for committed-only validators too"
    );
    assert_eq!(
        pq_key_at_height(&legacy_id, 10),
        None,
        "pq_key_at_height must not see cleared legacy-only validator"
    );
    assert_eq!(
        pq_key_at_height(&committed_id, 10),
        Some((PqScheme::Falcon512, committed_fk.public_key().to_vec())),
        "pq_key_at_height must still serve committed validator from PQ_COMMITTED_REGISTRY"
    );
    assert_eq!(
        pq_key_at_height_strict(&committed_id, 10),
        Some((PqScheme::Falcon512, committed_fk.public_key().to_vec()))
    );

    // Post-W3 gate: even if a process-local `register_validator_pq_key` occurs,
    // `pq_key_at_height` refuses legacy-only fallback once `pq_lifecycle_active_at(h)` is true.
    set_pq_lifecycle_activation_override(Some(100));
    sync_committed_pq_registry(&reg, true);
    assert_eq!(pq_key_at_height(&legacy_id, 100), None);
    assert_eq!(pq_key_at_height_strict(&legacy_id, 100), None);
}

#[test]
fn pq_registry_domain_registered_in_sync_and_snapshot_publish_and_decodes() {
    assert!(
        SYNC_DOMAIN_KINDS.contains(&"pq_registry"),
        "SYNC_DOMAIN_KINDS must include pq_registry"
    );
    assert!(
        SNAPSHOT_PUBLISH_DOMAIN_KINDS.contains(&"pq_registry"),
        "SNAPSHOT_PUBLISH_DOMAIN_KINDS must include pq_registry"
    );

    // Empty bytes decode to an empty registry; valid non-empty bytes roundtrip; corrupt bytes fail.
    assert!(decode_pq_registry(&[]).expect("empty bytes").is_empty());

    let mut reg = PqRegistry::new();
    let fk = FalconKeypair::generate_from_seed(0x61);
    let val_id = [0x77u8; 32];
    reg.register(
        val_id,
        PqScheme::Falcon512,
        fk.public_key().to_vec(),
        0,
        0,
        true,
    )
    .expect("register");
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&reg)
        .expect("encode pq_registry");
    let decoded = decode_pq_registry(&encoded).expect("decode pq_registry");
    assert_eq!(decoded.records(), reg.records());

    let mut trailing = encoded;
    trailing.push(0xAA);
    assert!(
        decode_pq_registry(&trailing).is_err(),
        "corrupt/trailing bytes must fail decode_pq_registry"
    );
}
