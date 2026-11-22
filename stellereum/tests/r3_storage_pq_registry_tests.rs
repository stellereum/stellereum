//! R3-C Storage & SnapV4 `PqRegistry` integration tests:
//! - Legacy `DomainSnapshotV8` / `DomainSnapshotV9` (`ValidatorStakeV1` 7-field)
//!   decode via `decode_domain_snapshot` with `withdrawal_address == None`, while
//!   `decode_domain_snapshot_strict` refuses `DomainSnapshotV9` / `V8`.
//! - Additive `"pq_registry"` sled tree roundtrip (`put_pq_registry`, `pq_registry_at`,
//!   `prune_pq_registry_below` respecting `aux_retained_heights`, and `AsyncPersistence`).
//! - `SnapV4` `DomainUnitId::PqRegistry == 272` (`N_DOMAIN_UNITS == 17`, `TOTAL_UNIT_TAGS == 273`)
//!   and `Base` / `Delta` roundtrip with non-empty `PqRegistry`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use stellereum::consensus::{consensus_chain_id, ValidatorId, ValidatorSet};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::pq_registry::PqRegistry;
use stellereum::snapshot_v4::{
    build_base_snapshot, build_delta_snapshot, verify_and_apply_base_with_key_resolver,
    verify_and_apply_delta_with_key_resolver, DomainUnitId, SnapStateV4, SnapV4Error,
    SnapshotBuildParams, TrustedSnapshotAnchor, UnitKind, N_ACCOUNT_BUCKETS, N_DOMAIN_UNITS,
    TOTAL_UNIT_TAGS, UNIT_ENC_FULL, UNIT_ENC_UNCHANGED,
};
use stellereum::staking::{required_bond_floor_nano, StakingLedger, ValidatorStake};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{
    decode_domain_snapshot, decode_domain_snapshot_strict, decode_pq_registry, AsyncPersistence,
    DomainSnapshot, DomainSnapshotV8, DomainSnapshotV9, StakingLedgerV5, StakingLedgerV6, Storage,
    ValidatorStakeV1,
};

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_store_dir(label: &str) -> std::path::PathBuf {
    let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("stell-r3c-{label}-{}-{seq}", std::process::id()))
}

fn kp_from_label(label: &[u8]) -> FalconKeypair {
    let seed = *blake3::hash(label).as_bytes();
    FalconKeypair::generate_from_seed_bytes(&seed)
}

fn make_validator_setup(label: &[u8]) -> (FalconKeypair, StakingLedger, ValidatorSet) {
    let kp = kp_from_label(label);
    let mut staking = StakingLedger::new();
    let min_bond = required_bond_floor_nano();
    staking
        .bond(kp.validator_id(), min_bond, 500)
        .expect("bond must succeed");
    let vset = staking.to_validator_set();
    assert!(!vset.validators.is_empty());
    (kp, staking, vset)
}

#[test]
fn domain_snapshot_v8_and_v9_upgrade_withdrawal_address_none_and_strict_refuses_legacy() {
    let val_id = [0x31u8; 32];
    let legacy_stake = ValidatorStakeV1 {
        self_bond: 1_100_000_000_000,
        delegated: 500_000_000_000,
        commission_bps: 750,
        pending_rewards: 42_000,
        total_slashed: 1_000,
        missed: 3,
        last_downtime_penalty: 99,
    };

    let mut v1_validators = HashMap::new();
    v1_validators.insert(val_id, legacy_stake.clone());

    // 1. DomainSnapshotV8 (StakingLedgerV5 with 7-field ValidatorStakeV1, no recent_full_exits).
    let v8 = DomainSnapshotV8 {
        staking: StakingLedgerV5 {
            validators: v1_validators.clone(),
            total_burned: 1_000,
            rewards_pool: 50_000,
            rewards_minted: 90_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let v8_bytes = bincode::serialize(&v8).expect("serialize V8");

    assert!(
        decode_domain_snapshot_strict(&v8_bytes).is_err(),
        "strict decoder must refuse legacy DomainSnapshotV8"
    );

    let upgraded_v8 = decode_domain_snapshot(&v8_bytes).expect("V8 decodes via fallback");
    let v8_rec = upgraded_v8
        .staking
        .validators
        .get(&val_id)
        .expect("validator survives V8 upgrade");
    assert_eq!(v8_rec.self_bond, legacy_stake.self_bond);
    assert_eq!(v8_rec.delegated, legacy_stake.delegated);
    assert_eq!(v8_rec.commission_bps, legacy_stake.commission_bps);
    assert_eq!(v8_rec.pending_rewards, legacy_stake.pending_rewards);
    assert_eq!(v8_rec.total_slashed, legacy_stake.total_slashed);
    assert_eq!(v8_rec.missed, legacy_stake.missed);
    assert_eq!(
        v8_rec.last_downtime_penalty,
        legacy_stake.last_downtime_penalty
    );
    assert_eq!(v8_rec.withdrawal_address, None);
    assert!(upgraded_v8.staking.recent_full_exits.is_empty());

    // 2. DomainSnapshotV9 (StakingLedgerV6 with 7-field ValidatorStakeV1 + recent_full_exits).
    let mut exits = HashMap::new();
    let exited_id = [0x77u8; 32];
    exits.insert(exited_id, (2_000_000_000, 12));
    let v9 = DomainSnapshotV9 {
        staking: StakingLedgerV6 {
            validators: v1_validators,
            recent_full_exits: exits.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    let v9_bytes = bincode::serialize(&v9).expect("serialize V9");

    assert!(
        decode_domain_snapshot_strict(&v9_bytes).is_err(),
        "strict decoder must refuse legacy DomainSnapshotV9"
    );

    let upgraded_v9 = decode_domain_snapshot(&v9_bytes).expect("V9 decodes via fallback");
    let v9_rec = upgraded_v9
        .staking
        .validators
        .get(&val_id)
        .expect("validator survives V9 upgrade");
    assert_eq!(v9_rec.withdrawal_address, None);
    assert_eq!(v9_rec.self_bond, legacy_stake.self_bond);
    assert_eq!(upgraded_v9.staking.recent_full_exits, exits);

    // 3. Current DomainSnapshot with withdrawal_address = Some(...) passes strict & lenient.
    let mut current_staking = StakingLedger::default();
    let withdrawal = [0xABu8; 32];
    current_staking.validators.insert(
        val_id,
        ValidatorStake {
            self_bond: legacy_stake.self_bond,
            delegated: legacy_stake.delegated,
            commission_bps: legacy_stake.commission_bps,
            pending_rewards: legacy_stake.pending_rewards,
            total_slashed: legacy_stake.total_slashed,
            missed: legacy_stake.missed,
            last_downtime_penalty: legacy_stake.last_downtime_penalty,
            withdrawal_address: Some(withdrawal),
        },
    );
    let current = DomainSnapshot {
        staking: current_staking,
        ..Default::default()
    };
    let current_bytes = bincode::serialize(&current).expect("serialize current DomainSnapshot");
    let strict = decode_domain_snapshot_strict(&current_bytes)
        .expect("strict decoder accepts current DomainSnapshot");
    assert_eq!(
        strict.staking.validators[&val_id].withdrawal_address,
        Some(withdrawal)
    );
    let lenient = decode_domain_snapshot(&current_bytes)
        .expect("lenient decoder accepts current DomainSnapshot");
    assert_eq!(
        lenient.staking.validators[&val_id].withdrawal_address,
        Some(withdrawal)
    );
}

#[tokio::test]
async fn storage_pq_registry_roundtrip_prune_and_async_persistence() {
    let dir = temp_store_dir("pq-registry");
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));

    let kp = kp_from_label(b"pq-reg-val-1");
    let mut reg = PqRegistry::new();
    reg.register(
        kp.validator_id(),
        PqScheme::Falcon512,
        kp.public_key().to_vec(),
        10,
        10,
        true,
    )
    .expect("register validator key");
    let reg_bytes = bincode::serialize(&reg).expect("serialize PqRegistry");

    // Empty and corrupt decoder boundary checks.
    assert!(
        decode_pq_registry(&[]).expect("empty bytes").is_empty(),
        "empty bytes must decode to empty PqRegistry"
    );
    assert!(
        decode_pq_registry(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err(),
        "corrupt bytes must fail closed"
    );
    let mut trailing = reg_bytes.clone();
    trailing.push(0x00);
    assert!(
        decode_pq_registry(&trailing).is_err(),
        "trailing bytes must fail closed"
    );

    // Direct put/get roundtrip.
    assert!(storage.pq_registry_at(10).expect("query").is_none());
    storage
        .put_pq_registry(10, &reg_bytes)
        .expect("put_pq_registry at 10");
    let fetched = storage
        .pq_registry_at(10)
        .expect("query")
        .expect("entry at 10 must exist");
    let decoded = decode_pq_registry(&fetched).expect("decode fetched");
    assert_eq!(decoded.records(), reg.records());

    // Pruning respects aux_retained_heights() via prune_domains_below().
    storage.put_state(20, b"state-20").expect("put state 20");
    storage
        .put_domains(20, b"domains-20")
        .expect("put domains 20");
    storage.put_state(50, b"state-50").expect("put state 50");
    storage
        .put_domains(50, b"domains-50")
        .expect("put domains 50");

    storage
        .put_pq_registry(20, &reg_bytes)
        .expect("put_pq_registry at 20");
    storage
        .put_pq_registry(30, &reg_bytes)
        .expect("put_pq_registry at 30");
    storage
        .put_pq_registry(50, &reg_bytes)
        .expect("put_pq_registry at 50");

    storage
        .prune_domains_below(40)
        .expect("prune_domains_below(40)");

    assert!(
        storage.pq_registry_at(10).expect("q10").is_none(),
        "unretained height 10 < 40 must be pruned"
    );
    assert!(
        storage.pq_registry_at(30).expect("q30").is_none(),
        "unretained height 30 < 40 must be pruned"
    );
    assert!(
        storage.pq_registry_at(20).expect("q20").is_some(),
        "snapshot height 20 must survive via aux_retained_heights()"
    );
    assert!(
        storage.pq_registry_at(50).expect("q50").is_some(),
        "height 50 >= 40 must survive"
    );

    // AsyncPersistence::enqueue_pq_registry writes to the tree.
    let ap = AsyncPersistence::start(storage.clone());
    ap.enqueue_pq_registry(60, reg_bytes.clone());
    ap.request_flush();
    for _ in 0..50 {
        if storage.pq_registry_at(60).expect("q60").is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let async_bytes = storage
        .pq_registry_at(60)
        .expect("q60")
        .expect("async enqueue must persist height 60");
    assert_eq!(
        decode_pq_registry(&async_bytes)
            .expect("decode async")
            .records(),
        reg.records()
    );

    drop(ap);
    drop(storage);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn snap_v4_pq_registry_unit_taxonomy_and_base_delta_roundtrip() {
    assert_eq!(N_DOMAIN_UNITS, 17);
    assert_eq!(TOTAL_UNIT_TAGS, N_ACCOUNT_BUCKETS + 17);
    assert_eq!(TOTAL_UNIT_TAGS, 273);
    assert_eq!(DomainUnitId::PqRegistry.tag(), 272);
    assert_eq!(DomainUnitId::from_tag(272), Some(DomainUnitId::PqRegistry));
    assert_eq!(
        UnitKind::from_tag(272),
        Some(UnitKind::Domain(DomainUnitId::PqRegistry))
    );
    assert_eq!(DomainUnitId::PqRegistry.name(), "PqRegistry");
    assert_eq!(DomainUnitId::from_tag(273), None);
    assert_eq!(UnitKind::from_tag(273), None);

    let chain_id = consensus_chain_id();
    let shard_id = 0u32;
    let (val_kp, staking, vset) = make_validator_setup(b"snapv4-pqreg-val");
    let val_id = val_kp.validator_id();
    let val_pk = val_kp.public_key().to_vec();

    let key_resolver = |id: &ValidatorId, _h: u64| -> Option<(PqScheme, Vec<u8>)> {
        if *id == val_id {
            Some((PqScheme::Falcon512, val_pk.clone()))
        } else {
            None
        }
    };

    // Build Base state at height 100 with non-empty PqRegistry.
    let engine = InMemoryStateEngine::new();
    let mut pq_reg_100 = PqRegistry::new();
    pq_reg_100
        .register(val_id, PqScheme::Falcon512, val_pk.clone(), 0, 0, true)
        .expect("register val key");

    let base_empty_pq = SnapStateV4::capture_from_engine(&engine, Some(&staking), None, None)
        .await
        .expect("capture empty pq_registry");
    assert!(base_empty_pq.pq_registry.is_empty());
    let root_empty_pq = base_empty_pq
        .compute_state_root()
        .await
        .expect("root empty pq");

    let base_100 = SnapStateV4::capture_from_engine_with_pq_registry(
        &engine,
        Some(&staking),
        None,
        None,
        Some(&pq_reg_100),
    )
    .await
    .expect("capture with pq_registry");
    assert_eq!(base_100.pq_registry.records(), pq_reg_100.records());

    let root_100 = base_100.compute_state_root().await.expect("root 100");
    assert_ne!(
        root_100, root_empty_pq,
        "non-empty PqRegistry must commit into SnapStateV4::compute_state_root()"
    );

    let boundary_100 = *blake3::hash(b"snapv4-boundary-100").as_bytes();
    let params_100 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 100,
        target_block_hash: boundary_100,
        target_state_root: root_100,
        validator_set: &vset,
    };
    let encoded_base =
        build_base_snapshot(&base_100, &params_100, &val_kp).expect("build base snapshot");
    let pq_desc_base = encoded_base
        .manifest
        .units
        .iter()
        .find(|u| u.unit_tag == DomainUnitId::PqRegistry.tag())
        .expect("Base manifest must include DomainUnitId::PqRegistry");
    assert_eq!(pq_desc_base.encoding, UNIT_ENC_FULL);

    let anchor_100 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 100,
        trusted_boundary_hash: boundary_100,
        trusted_state_root: root_100,
        validator_set: &vset,
    };
    let restored_base = verify_and_apply_base_with_key_resolver(
        &encoded_base.manifest,
        &encoded_base.chunks,
        &anchor_100,
        key_resolver,
    )
    .await
    .expect("verify_and_apply_base succeeds");
    assert_eq!(restored_base, base_100);
    assert_eq!(restored_base.pq_registry.records(), pq_reg_100.records());

    // Negative check: manifest claiming wrong root (empty PqRegistry root) fails closed.
    let bad_anchor = TrustedSnapshotAnchor {
        trusted_state_root: root_empty_pq,
        ..anchor_100
    };
    let mut bad_manifest = encoded_base.manifest.clone();
    bad_manifest.target_state_root = root_empty_pq;
    stellereum::snapshot_v4::sign_manifest(&mut bad_manifest, &val_kp).expect("resign");
    assert_eq!(
        verify_and_apply_base_with_key_resolver(
            &bad_manifest,
            &encoded_base.chunks,
            &bad_anchor,
            key_resolver,
        )
        .await,
        Err(SnapV4Error::StateRootMismatch)
    );

    // Delta 1 (100 -> 101): PqRegistry unchanged -> UNIT_ENC_UNCHANGED.
    let mut state_101 = base_100.clone();
    state_101.scalars.total_minted_nano = 1_000;
    let root_101 = state_101.compute_state_root().await.expect("root 101");
    let boundary_101 = *blake3::hash(b"snapv4-boundary-101").as_bytes();
    let params_101 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 101,
        target_block_hash: boundary_101,
        target_state_root: root_101,
        validator_set: &vset,
    };
    let delta_101 =
        build_delta_snapshot(&base_100, &state_101, 100, root_100, &params_101, &val_kp)
            .expect("build delta 101");
    let pq_desc_101 = delta_101
        .manifest
        .units
        .iter()
        .find(|u| u.unit_tag == DomainUnitId::PqRegistry.tag())
        .expect("Delta 101 must include DomainUnitId::PqRegistry");
    assert_eq!(pq_desc_101.encoding, UNIT_ENC_UNCHANGED);

    let anchor_101 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 101,
        trusted_boundary_hash: boundary_101,
        trusted_state_root: root_101,
        validator_set: &vset,
    };
    let restored_101 = verify_and_apply_delta_with_key_resolver(
        &restored_base,
        100,
        root_100,
        &delta_101.manifest,
        &delta_101.chunks,
        &anchor_101,
        key_resolver,
    )
    .await
    .expect("verify_and_apply_delta 101 succeeds");
    assert_eq!(restored_101, state_101);
    assert_eq!(restored_101.pq_registry.records(), pq_reg_100.records());

    // Delta 2 (101 -> 102): announce rotation in PqRegistry -> UNIT_ENC_FULL & roundtrips.
    let next_kp = kp_from_label(b"snapv4-pqreg-val-next");
    let mut state_102 = restored_101.clone();
    state_102
        .pq_registry
        .announce_rotation_seq(
            val_id,
            PqScheme::Falcon512,
            next_kp.public_key().to_vec(),
            102,
            1,
            true,
        )
        .expect("announce_rotation_seq");
    let root_102 = state_102.compute_state_root().await.expect("root 102");
    assert_ne!(root_102, root_101);
    let boundary_102 = *blake3::hash(b"snapv4-boundary-102").as_bytes();
    let params_102 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 102,
        target_block_hash: boundary_102,
        target_state_root: root_102,
        validator_set: &vset,
    };
    let delta_102 = build_delta_snapshot(
        &restored_101,
        &state_102,
        101,
        root_101,
        &params_102,
        &val_kp,
    )
    .expect("build delta 102");
    let pq_desc_102 = delta_102
        .manifest
        .units
        .iter()
        .find(|u| u.unit_tag == DomainUnitId::PqRegistry.tag())
        .expect("Delta 102 must include DomainUnitId::PqRegistry");
    assert_eq!(pq_desc_102.encoding, UNIT_ENC_FULL);

    let anchor_102 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 102,
        trusted_boundary_hash: boundary_102,
        trusted_state_root: root_102,
        validator_set: &vset,
    };
    let restored_102 = verify_and_apply_delta_with_key_resolver(
        &restored_101,
        101,
        root_101,
        &delta_102.manifest,
        &delta_102.chunks,
        &anchor_102,
        key_resolver,
    )
    .await
    .expect("verify_and_apply_delta 102 succeeds");
    assert_eq!(restored_102, state_102);
    assert_eq!(
        restored_102.pq_registry.records(),
        state_102.pq_registry.records()
    );
    assert!(restored_102.pq_registry.pending_of(&val_id).is_some());
}
