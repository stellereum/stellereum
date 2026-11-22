//! Comprehensive round-trip, anti-DoS, cryptographic binding, and safety-isolation
//! tests for `stellereum::snapshot_v4` (`SnapV4`).

use stellereum::snapshot_v4::{
    self, build_base_snapshot, build_delta_snapshot, canonical_manifest_body_bytes,
    canonical_vset_hash, compute_unit_hash, compute_units_merkle_root, decode_canonical_exact,
    decode_manifest_strict, empty_bucket_hash, encode_canonical, encode_manifest_strict,
    generate_unit_merkle_proof, manifest_signing_digest, sign_manifest,
    validate_manifest_pre_fetch, validate_manifest_pre_fetch_with_key_resolver,
    verify_and_apply_base, verify_and_apply_base_with_key_resolver, verify_and_apply_delta,
    verify_and_apply_delta_chain, verify_unit_chunk, verify_unit_merkle_proof, AccountBucketDelta,
    AccountBucketFull, CanonicalScalars, DomainUnitId, EncodedSnapshotV4, MapDiff, SnapStateV4,
    SnapV4Error, SnapshotBuildParams, SnapshotManifestV1, SnapshotUnitDesc,
    TrustedSnapshotAnchor, UnitKind, DELTA_FULL_THRESHOLD_DEN, DELTA_FULL_THRESHOLD_NUM,
    MAX_ACCOUNTS_PER_CHUNK, MAX_DELTA_CHAIN_LEN, MAX_MANIFEST_WIRE_BYTES,
    MAX_SNAPSHOT_DECODE_BYTES, MAX_SNAP_CHUNK_BYTES, MAX_SNAP_UNITS, MAX_SNAP_WIRE_BYTES,
    N_ACCOUNT_BUCKETS, N_DOMAIN_UNITS, SNAP_BUCKET_MULTI_DOMAIN, SNAP_DOMAIN_MULTI_DOMAIN,
    SNAP_EMPTY_BUCKET_DOMAIN, SNAP_MANIFEST_MAGIC, SNAP_MANIFEST_SIG_DOMAIN,
    SNAP_MANIFEST_VERSION, SNAP_MERKLE_EMPTY_DOMAIN, SNAP_MERKLE_LEAF_DOMAIN,
    SNAP_MERKLE_NODE_DOMAIN, SNAP_UNIT_HASH_DOMAIN, SNAP_VSET_HASH_DOMAIN, TOTAL_UNIT_TAGS,
    UNIT_ENC_DELTA, UNIT_ENC_FULL, UNIT_ENC_UNCHANGED,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use stellereum::consensus::{consensus_chain_id, register_validator_pq_key, ValidatorSet};
use stellereum::contract::Contract;
use stellereum::governance::GovAction;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::staking::{required_bond_floor_nano, StakingLedger};
use stellereum::state_engine::{AccountState, EscrowRecord, InMemoryStateEngine};
use stellereum::storage::{
    ConsensusCheckpoint, SafetyRecordIdentity, Storage, VoteWatermark, VoteWatermarkEntry,
};
use stellereum::token::TokenMetadata;
use stellereum::xshard2pc::XpcRecord;
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, SessionKeyRecord};

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_keypair(tag: &[u8]) -> FalconKeypair {
    let seed = *blake3::hash(tag).as_bytes();
    let kp = FalconKeypair::generate_from_seed_bytes(&seed);
    register_validator_pq_key(
        kp.validator_id(),
        PqScheme::Falcon512,
        kp.public_key().to_vec(),
    );
    kp
}

fn make_addr(bucket: u8, id: u8) -> [u8; 32] {
    let mut addr = [0u8; 32];
    addr[0] = bucket;
    addr[1] = id;
    addr[31] = id.wrapping_mul(17).wrapping_add(1);
    addr
}

fn make_hash(label: &[u8]) -> [u8; 32] {
    *blake3::hash(label).as_bytes()
}

fn make_validator_setup(tag: &[u8]) -> (FalconKeypair, StakingLedger, ValidatorSet) {
    let kp = unique_keypair(tag);
    let mut staking = StakingLedger::new();
    let min_bond =
        required_bond_floor_nano().max(stellereum::governance::PROPOSAL_MIN_STAKE_NANO);
    staking
        .bond(kp.validator_id(), min_bond, 500)
        .expect("bond must succeed");
    let vset = staking.to_validator_set();
    assert!(!vset.validators.is_empty());
    (kp, staking, vset)
}

fn resign_manifest(manifest: &mut SnapshotManifestV1, kp: &FalconKeypair) {
    manifest.units_merkle_root = compute_units_merkle_root(&manifest.units);
    sign_manifest(manifest, kp).expect("sign_manifest must succeed");
}

fn make_dummy_tx(nonce: u64) -> Transaction {
    Transaction {
        from: [0x11; 32],
        to: [0x22; 32],
        amount: 1000,
        gas_limit: 500_000,
        nonce,
        source_shard: 0,
        target_shard: 1,
        signature: vec![0xAA; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

#[test]
fn constants_and_unit_tag_taxonomy_are_exact() {
    assert_eq!(&SNAP_MANIFEST_MAGIC, b"STLSNPM1");
    assert_eq!(SNAP_MANIFEST_VERSION, 1);
    assert_eq!(N_ACCOUNT_BUCKETS, 256);
    assert_eq!(MAX_ACCOUNTS_PER_CHUNK, 16_384);
    assert_eq!(MAX_SNAP_UNITS, 4_096);
    assert_eq!(MAX_SNAP_CHUNK_BYTES, 1_048_576);
    assert_eq!(MAX_SNAP_WIRE_BYTES, 256 * 1024 * 1024);
    assert_eq!(MAX_SNAPSHOT_DECODE_BYTES, 512 * 1024 * 1024);
    assert_eq!(MAX_DELTA_CHAIN_LEN, 8);
    assert_eq!(DELTA_FULL_THRESHOLD_NUM, 70);
    assert_eq!(DELTA_FULL_THRESHOLD_DEN, 100);
    assert_eq!(N_DOMAIN_UNITS, 17);
    assert_eq!(TOTAL_UNIT_TAGS, 273);
    const _: () = assert!(MAX_MANIFEST_WIRE_BYTES >= 1024);
    assert!(!SNAP_MANIFEST_SIG_DOMAIN.is_empty());
    assert!(!SNAP_UNIT_HASH_DOMAIN.is_empty());
    assert!(!SNAP_EMPTY_BUCKET_DOMAIN.is_empty());
    assert!(!SNAP_BUCKET_MULTI_DOMAIN.is_empty());
    assert!(!SNAP_DOMAIN_MULTI_DOMAIN.is_empty());
    assert!(!SNAP_VSET_HASH_DOMAIN.is_empty());
    assert!(!SNAP_MERKLE_EMPTY_DOMAIN.is_empty());
    assert!(!SNAP_MERKLE_LEAF_DOMAIN.is_empty());
    assert!(!SNAP_MERKLE_NODE_DOMAIN.is_empty());

    for b in 0..N_ACCOUNT_BUCKETS {
        assert_eq!(
            UnitKind::from_tag(b as u16),
            Some(UnitKind::AccountBucket(b as u8))
        );
    }
    for (idx, &dom) in DomainUnitId::ALL.iter().enumerate() {
        assert_eq!(dom.tag(), (256 + idx) as u16);
        assert_eq!(DomainUnitId::from_tag(dom.tag()), Some(dom));
        assert_eq!(UnitKind::from_tag(dom.tag()), Some(UnitKind::Domain(dom)));
        assert!(!dom.name().is_empty());
    }
    assert_eq!(DomainUnitId::from_tag(271), Some(DomainUnitId::EvmBindings));
    assert_eq!(
        UnitKind::from_tag(271),
        Some(UnitKind::Domain(DomainUnitId::EvmBindings))
    );
    assert_eq!(DomainUnitId::from_tag(272), Some(DomainUnitId::PqRegistry));
    assert_eq!(
        UnitKind::from_tag(272),
        Some(UnitKind::Domain(DomainUnitId::PqRegistry))
    );
    assert_eq!(DomainUnitId::from_tag(273), None);
    assert_eq!(UnitKind::from_tag(273), None);
}

#[tokio::test]
async fn round_trip_base_and_delta_chain_matches_direct_full_snapshot() {
    let chain_id = consensus_chain_id();
    let shard_id = 0u32;
    let (val_kp, staking, vset) = make_validator_setup(b"round_trip_val_1");

    // 1. Build rich state at Base height = 100.
    let source = InMemoryStateEngine::new();
    let pq_user_kp = FalconKeypair::generate_from_seed_bytes(&make_hash(b"pq_user_1"));
    let pq_user_addr =
        derive_pq_address(PqScheme::Falcon512, pq_user_kp.public_key(), &DEFAULT_SALT);
    let bucket_a = pq_user_addr[0];
    let bucket_b = bucket_a.wrapping_add(1);
    let bucket_c = bucket_a.wrapping_add(2);

    let mut acc_a1 = AccountState::new(pq_user_addr, 5_000_000);
    acc_a1.nonce = 3;
    source.update_account(acc_a1).await;
    source
        .pin_pubkey(
            pq_user_addr,
            PqScheme::Falcon512,
            pq_user_kp.public_key(),
            &DEFAULT_SALT,
        )
        .await
        .expect("pin_pubkey");

    let addr_b1 = make_addr(bucket_b, 1);
    let addr_c1 = make_addr(bucket_c, 1);
    for id in 1..=6u8 {
        source
            .update_account(AccountState::new(
                make_addr(bucket_b, id),
                u64::from(id) * 1_000,
            ))
            .await;
    }
    source
        .update_account(AccountState::new(addr_c1, 3_000))
        .await;

    let token_id = {
        let mut tokens = source.tokens_write().await;
        tokens
            .create_token(
                addr_b1,
                TokenMetadata {
                    name: "TestUSD".to_string(),
                    symbol: "TUSD".to_string(),
                    decimals: 6,
                    total_supply: 0,
                    max_supply: Some(1_000_000_000),
                    minter: addr_b1,
                    paused: false,
                    description: "test token".to_string(),
                },
                500_000,
            )
            .expect("create_token")
    };
    let contract_addr = make_addr(0x55, 10);
    {
        let mut contracts = source.contracts_write().await;
        let mut storage_map = HashMap::new();
        storage_map.insert(1, 42);
        contracts.contracts.insert(
            contract_addr,
            Contract {
                address: contract_addr,
                creator: addr_b1,
                code_hash: make_hash(b"code1"),
                code: vec![0x00, 0x61, 0x73, 0x6D],
                storage: storage_map,
                created_at: 100,
                paused: false,
                balance: 777,
                abi: None,
                source_hash: None,
            },
        );
    }
    {
        let mut escrow = source.order_escrow_write().await;
        escrow.insert(
            (1, 10),
            EscrowRecord {
                trader: addr_b1,
                locked_base_stell: 1234,
                locked_quote_wusdt: 0,
                locked_quote_native: 0,
            },
        );
    }
    {
        let mut s = source.staking_write().await;
        *s = staking.clone();
    }
    {
        let mut oracle = source.oracle_write().await;
        oracle.publishers.insert(val_kp.validator_id());
    }
    {
        let mut sk = source.session_keys_write().await;
        sk.entries.insert(
            make_addr(0x70, 1),
            SessionKeyRecord {
                master: addr_b1,
                valid_until: 9999,
                max_gas_spend: 100_000,
                gas_spent: 500,
                scope: 1,
                max_value_per_tx: 50_000,
                revoked: false,
            },
        );
    }
    {
        let mut br = source.bridge_write().await;
        br.processed_source_txs.insert(make_hash(b"bridge_tx_1"));
    }
    {
        let mut zk = source.zkml_models_write().await;
        let layer = QuantizedLayer::new(2, 1, vec![1, 2], vec![3]);
        zk.register(
            make_hash(b"model_1"),
            QuantizedLinearModel::new(vec![layer]),
        )
        .expect("register model");
    }
    {
        let xpc_rec = XpcRecord::prepared(make_dummy_tx(1), 0, 1, 100);
        let replay = stellereum::sharding::CrossShardReplaySnapshot {
            engine_consumed: Vec::new(),
            runtime_consumed: Vec::new(),
            produced: vec![(xpc_rec.tx_hash, xpc_rec.tx.clone(), 100)],
            completed: Vec::new(),
            xpc: vec![xpc_rec],
        };
        source.restore_cross_shard_replay(&replay).await;
    }
    source.sync_aux_trie().await;
    let root_100 = source.get_state_root().await;
    let boundary_100 = make_hash(b"block_100");

    let base_state_100 = SnapStateV4::capture_from_engine(&source, None, None, None)
        .await
        .expect("capture base 100");
    let params_100 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 100,
        target_block_hash: boundary_100,
        target_state_root: root_100,
        validator_set: &vset,
    };
    let encoded_base = build_base_snapshot(&base_state_100, &params_100, &val_kp)
        .expect("build base snapshot 100");

    // Verify Base manifest wire round-trip and pre-fetch check.
    let manifest_bytes = encode_manifest_strict(&encoded_base.manifest).expect("encode manifest");
    let decoded_manifest = decode_manifest_strict(&manifest_bytes).expect("decode manifest");
    assert_eq!(decoded_manifest, encoded_base.manifest);
    let anchor_100 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 100,
        trusted_boundary_hash: boundary_100,
        trusted_state_root: root_100,
        validator_set: &vset,
    };
    validate_manifest_pre_fetch(&decoded_manifest, &anchor_100).expect("pre-fetch base valid");

    // Verify Merkle proof of a unit in Base manifest.
    let proof_0 = generate_unit_merkle_proof(&decoded_manifest.units, 0).expect("merkle proof");
    assert!(verify_unit_merkle_proof(
        &decoded_manifest.units_merkle_root,
        &decoded_manifest.units[0],
        &proof_0
    ));
    assert_eq!(
        base_state_100
            .unit_state_hash(DomainUnitId::Tokens.tag())
            .unwrap(),
        base_state_100
            .domain_state_hash(DomainUnitId::Tokens)
            .unwrap()
    );

    // Apply Base to a fresh engine.
    let verified_base = verify_and_apply_base(&decoded_manifest, &encoded_base.chunks, &anchor_100)
        .await
        .expect("verify_and_apply_base");
    assert_eq!(verified_base, base_state_100);
    let replica = InMemoryStateEngine::new();
    verified_base
        .apply_to_engine(&replica)
        .await
        .expect("apply base to replica");
    assert_eq!(replica.get_state_root().await, root_100);
    assert!(replica.get_pinned_pubkey_with_salt(&pq_user_addr).is_some());

    // 2. Delta 1 (height 100 -> 101): add in empty bucket_d, update bucket_b, delete sole account in bucket_c, update Tokens.
    let bucket_d = bucket_a.wrapping_add(3);
    let addr_d1 = make_addr(bucket_d, 1);
    let mut state_101 = base_state_100.clone();
    state_101.buckets[bucket_d as usize].push(AccountState::new(addr_d1, 9_999));
    state_101.buckets[bucket_b as usize][0].balance = 88_888;
    state_101.buckets[bucket_c as usize].clear(); // deleted sole account!
    state_101
        .tokens
        .tokens
        .get_mut(&token_id)
        .unwrap()
        .balances
        .insert(addr_d1, 250);
    state_101.scalars.total_minted_nano = 500;
    let root_101 = state_101.compute_state_root().await.expect("root 101");
    let boundary_101 = make_hash(b"block_101");
    let params_101 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 101,
        target_block_hash: boundary_101,
        target_state_root: root_101,
        validator_set: &vset,
    };
    let delta_1 = build_delta_snapshot(
        &base_state_100,
        &state_101,
        100,
        root_100,
        &params_101,
        &val_kp,
    )
    .expect("build delta 1");
    assert!(delta_1
        .manifest
        .units
        .iter()
        .any(|u| u.encoding == UNIT_ENC_UNCHANGED));
    assert!(delta_1
        .manifest
        .units
        .iter()
        .any(|u| u.encoding == UNIT_ENC_DELTA));

    // 3. Delta 2 (height 101 -> 102): update Contracts, OrderEscrow, delete escrow entry, update CrossShard & PqKeys.
    let mut state_102 = state_101.clone();
    state_102
        .contracts
        .contracts
        .get_mut(&contract_addr)
        .unwrap()
        .storage
        .insert(2, 99);
    state_102.order_escrow.escrow.remove(&(1, 10));
    state_102.order_escrow.escrow.insert(
        (2, 20),
        EscrowRecord {
            trader: addr_d1,
            locked_base_stell: 0,
            locked_quote_wusdt: 456,
            locked_quote_native: 0,
        },
    );
    let pq_user2_kp = FalconKeypair::generate_from_seed_bytes(&make_hash(b"pq_user_2"));
    let pq_user2_addr =
        derive_pq_address(PqScheme::Falcon512, pq_user2_kp.public_key(), &DEFAULT_SALT);
    let mut acc_u2 = AccountState::new(pq_user2_addr, 12_345);
    acc_u2.scheme = PqScheme::Falcon512;
    acc_u2.pubkey_hash = Some(*blake3::hash(pq_user2_kp.public_key()).as_bytes());
    let b_u2 = pq_user2_addr[0] as usize;
    state_102.buckets[b_u2].push(acc_u2);
    state_102.buckets[b_u2].sort_by_key(|a| a.address);
    let mut a_key = Vec::with_capacity(34);
    a_key.extend_from_slice(b"a:");
    a_key.extend_from_slice(&pq_user2_addr);
    let a_val = encode_canonical(&(
        PqScheme::Falcon512,
        pq_user2_kp.public_key().to_vec(),
        DEFAULT_SALT,
    ))
    .unwrap();
    state_102.pq_keys.entries.insert(a_key, a_val);

    let root_102 = state_102.compute_state_root().await.expect("root 102");
    let boundary_102 = make_hash(b"block_102");
    let params_102 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 102,
        target_block_hash: boundary_102,
        target_state_root: root_102,
        validator_set: &vset,
    };
    let delta_2 = build_delta_snapshot(&state_101, &state_102, 101, root_101, &params_102, &val_kp)
        .expect("build delta 2");

    // 4. Delta 3 (height 102 -> 103): rewrite >70% of bucket_b to trigger FullUnit fallback inside Delta,
    // plus update Governance, Bridge, CnVrfV3.
    let mut state_103 = state_102.clone();
    state_103.buckets[bucket_b as usize].clear();
    for i in 10..20u8 {
        state_103.buckets[bucket_b as usize]
            .push(AccountState::new(make_addr(bucket_b, i), i as u64 * 100));
    }
    state_103.buckets[bucket_b as usize].sort_by_key(|a| a.address);
    let mut gov = state_103.governance.to_governance();
    let mut led = state_103.staking.to_ledger();
    gov.propose(
        &mut led,
        val_kp.validator_id(),
        "test-prop".to_string(),
        GovAction::Signal("v4".to_string()),
        103,
    )
    .expect("gov propose");
    state_103.governance = snapshot_v4::CanonicalGovernance::from_governance(&gov);
    state_103.staking = snapshot_v4::CanonicalStakingLedger::from_ledger(&led);
    state_103
        .bridge
        .processed_source_txs
        .insert(make_hash(b"bridge_tx_2"));
    state_103.cnvrf_v3.v3_state.rolling_mix = [0x33; 48];
    state_103.cnvrf_v3.v3_state.rolling_mix_epoch = 2;

    let root_103 = state_103.compute_state_root().await.expect("root 103");
    let boundary_103 = make_hash(b"block_103");
    let params_103 = SnapshotBuildParams {
        chain_id,
        shard_id,
        target_height: 103,
        target_block_hash: boundary_103,
        target_state_root: root_103,
        validator_set: &vset,
    };
    let delta_3 = build_delta_snapshot(&state_102, &state_103, 102, root_102, &params_103, &val_kp)
        .expect("build delta 3");

    // Verify bucket_b switched to FullUnit because >70% changed!
    let bucket_b_desc = delta_3
        .manifest
        .units
        .iter()
        .find(|u| u.unit_tag == bucket_b as u16)
        .expect("bucket_b desc");
    assert_eq!(bucket_b_desc.encoding, UNIT_ENC_FULL);

    // Apply Base + Δ1 + Δ2 + Δ3 chain and compare with direct Base at height 103.
    let anchor_101 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 101,
        trusted_boundary_hash: boundary_101,
        trusted_state_root: root_101,
        validator_set: &vset,
    };
    let anchor_102 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 102,
        trusted_boundary_hash: boundary_102,
        trusted_state_root: root_102,
        validator_set: &vset,
    };
    let anchor_103 = TrustedSnapshotAnchor {
        chain_id,
        shard_id,
        target_height: 103,
        trusted_boundary_hash: boundary_103,
        trusted_state_root: root_103,
        validator_set: &vset,
    };

    let chained = verify_and_apply_delta_chain(
        &verified_base,
        100,
        root_100,
        &[
            (&delta_1, &anchor_101),
            (&delta_2, &anchor_102),
            (&delta_3, &anchor_103),
        ],
    )
    .await
    .expect("delta chain must verify and apply");

    // Build a direct Base snapshot from `state_103` and verify it separately.
    let direct_base_103 =
        build_base_snapshot(&state_103, &params_103, &val_kp).expect("direct base 103");
    let verified_direct_103 = verify_and_apply_base(
        &direct_base_103.manifest,
        &direct_base_103.chunks,
        &anchor_103,
    )
    .await
    .expect("verify direct base 103");

    assert_eq!(chained, verified_direct_103);
    assert_eq!(chained, state_103);

    let chain_engine = InMemoryStateEngine::new();
    chained
        .apply_to_engine(&chain_engine)
        .await
        .expect("apply chained to engine");
    let direct_engine = InMemoryStateEngine::new();
    verified_direct_103
        .apply_to_engine(&direct_engine)
        .await
        .expect("apply direct to engine");

    assert_eq!(
        chain_engine.get_state_root().await,
        direct_engine.get_state_root().await
    );
    assert_eq!(chain_engine.get_state_root().await, root_103);
    assert!(chain_engine
        .get_pinned_pubkey_with_salt(&pq_user2_addr)
        .is_some());
}

async fn make_minimal_base_fixture(
    tag: &[u8],
) -> (
    FalconKeypair,
    ValidatorSet,
    SnapStateV4,
    EncodedSnapshotV4,
    SnapshotBuildParams<'static>,
    [u8; 32],
) {
    let (kp, staking, vset) = make_validator_setup(tag);
    let vset_leaked: &'static ValidatorSet = Box::leak(Box::new(vset.clone()));
    let mut state = SnapStateV4 {
        staking: snapshot_v4::CanonicalStakingLedger::from_ledger(&staking),
        ..Default::default()
    };
    for id in 1..=6u8 {
        let addr = make_addr(0x07, id);
        state.buckets[0x07].push(AccountState::new(addr, 42_000 + u64::from(id)));
    }
    let root = state.compute_state_root().await.expect("compute root");
    let boundary = make_hash(tag);
    let params = SnapshotBuildParams {
        chain_id: consensus_chain_id(),
        shard_id: 0,
        target_height: 10,
        target_block_hash: boundary,
        target_state_root: root,
        validator_set: vset_leaked,
    };
    let encoded = build_base_snapshot(&state, &params, &kp).expect("build base");
    (kp, vset, state, encoded, params, root)
}

#[tokio::test]
async fn negative_manifest_state_root_and_boundary_hash_and_bindings_rejected() {
    let (kp, vset, _state, encoded, params, root) =
        make_minimal_base_fixture(b"neg_manifest_bindings").await;
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };

    // 1. Tampered state_root in manifest (even re-signed by valid validator) -> pre-fetch fail!
    let mut bad_root_m = encoded.manifest.clone();
    bad_root_m.target_state_root[0] ^= 0xFF;
    resign_manifest(&mut bad_root_m, &kp);
    assert_eq!(
        validate_manifest_pre_fetch(&bad_root_m, &anchor),
        Err(SnapV4Error::StateRootMismatch)
    );

    // 2. Tampered boundary_hash in manifest (re-signed) -> pre-fetch fail!
    let mut bad_boundary_m = encoded.manifest.clone();
    bad_boundary_m.target_block_hash[0] ^= 0xFF;
    resign_manifest(&mut bad_boundary_m, &kp);
    assert_eq!(
        validate_manifest_pre_fetch(&bad_boundary_m, &anchor),
        Err(SnapV4Error::BoundaryHashMismatch)
    );

    // 3. Tampered chain_id, shard_id, target_height, validator_set_hash, magic, version.
    let mut m = encoded.manifest.clone();
    m.chain_id += 1;
    resign_manifest(&mut m, &kp);
    assert!(matches!(
        validate_manifest_pre_fetch(&m, &anchor),
        Err(SnapV4Error::ChainIdMismatch { .. })
    ));

    let mut m = encoded.manifest.clone();
    m.shard_id += 1;
    resign_manifest(&mut m, &kp);
    assert!(matches!(
        validate_manifest_pre_fetch(&m, &anchor),
        Err(SnapV4Error::ShardIdMismatch { .. })
    ));

    let mut m = encoded.manifest.clone();
    m.target_height += 1;
    resign_manifest(&mut m, &kp);
    assert!(matches!(
        validate_manifest_pre_fetch(&m, &anchor),
        Err(SnapV4Error::HeightMismatch { .. })
    ));

    let mut m = encoded.manifest.clone();
    m.validator_set_hash[0] ^= 0x01;
    resign_manifest(&mut m, &kp);
    assert_eq!(
        validate_manifest_pre_fetch(&m, &anchor),
        Err(SnapV4Error::ValidatorSetHashMismatch)
    );

    let mut m = encoded.manifest.clone();
    m.magic = *b"BADMAGIC";
    assert_eq!(
        validate_manifest_pre_fetch(&m, &anchor),
        Err(SnapV4Error::InvalidMagic)
    );

    let mut m = encoded.manifest.clone();
    m.version = 99;
    assert_eq!(
        validate_manifest_pre_fetch(&m, &anchor),
        Err(SnapV4Error::UnsupportedVersion(99))
    );

    // 4. Validly signed manifest pointing to WRONG trusted_state_root vs actual state bytes ->
    // fails during throwaway verification with StateRootMismatch, never mutating live engine.
    let mut wrong_anchor = anchor;
    wrong_anchor.trusted_state_root = make_hash(b"wrong_trusted_root");
    let mut m_for_wrong_anchor = encoded.manifest.clone();
    m_for_wrong_anchor.target_state_root = wrong_anchor.trusted_state_root;
    resign_manifest(&mut m_for_wrong_anchor, &kp);
    let err = verify_and_apply_base(&m_for_wrong_anchor, &encoded.chunks, &wrong_anchor)
        .await
        .unwrap_err();
    assert_eq!(err, SnapV4Error::StateRootMismatch);
}

#[tokio::test]
async fn negative_manifest_signature_and_unauthorized_publisher_rejected() {
    let (_kp, vset, _state, encoded, params, root) =
        make_minimal_base_fixture(b"neg_manifest_sig").await;
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };

    // 1. Corrupt signature byte.
    let mut bad_sig = encoded.manifest.clone();
    bad_sig.publisher_sig[10] ^= 0x40;
    assert_eq!(
        validate_manifest_pre_fetch(&bad_sig, &anchor),
        Err(SnapV4Error::InvalidSignature)
    );

    // 2. Valid signature from non-validator keypair.
    let outsider_kp = unique_keypair(b"outsider_val_not_in_set");
    let mut outsider_m = encoded.manifest.clone();
    sign_manifest(&mut outsider_m, &outsider_kp).expect("sign");
    assert_eq!(
        validate_manifest_pre_fetch(&outsider_m, &anchor),
        Err(SnapV4Error::UnauthorizedPublisher)
    );

    // 3. Key resolver returns wrong scheme / missing key (also verified via verify_and_apply_base_with_key_resolver).
    assert_eq!(
        validate_manifest_pre_fetch_with_key_resolver(&encoded.manifest, &anchor, |_, _| None),
        Err(SnapV4Error::MissingPublisherKey)
    );
    assert_eq!(
        verify_and_apply_base_with_key_resolver(
            &encoded.manifest,
            &encoded.chunks,
            &anchor,
            |_, _| None
        )
        .await,
        Err(SnapV4Error::MissingPublisherKey)
    );
    assert_eq!(
        validate_manifest_pre_fetch_with_key_resolver(&encoded.manifest, &anchor, |_, _| {
            Some((PqScheme::MlDsa44, vec![0u8; 1312]))
        }),
        Err(SnapV4Error::InvalidSignature)
    );
}

#[tokio::test]
async fn negative_dos_limits_rejected_before_allocation() {
    let (kp, vset, state, encoded, params, root) =
        make_minimal_base_fixture(b"neg_dos_limits").await;
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };

    // 1. Wire-level crafted bincode manifest with gigantic `units` vec length (1_000_000_000)
    // and `4097` (MAX_SNAP_UNITS + 1): must fail in `decode_manifest_strict` BEFORE allocating!
    let mut crafted_wire = encode_manifest_strict(&encoded.manifest).expect("encode");
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.magic).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.version).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.chain_id).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.shard_id).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.kind).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.target_height).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.target_block_hash).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.target_state_root).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.validator_set_hash).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.total_wire_bytes).unwrap());
    prefix
        .extend_from_slice(&encode_canonical(&encoded.manifest.total_uncompressed_bytes).unwrap());
    prefix.extend_from_slice(&encode_canonical(&encoded.manifest.units_merkle_root).unwrap());
    let units_len_offset = prefix.len();

    // Overwrite `units` length prefix with 1_000_000_000 (u64 le) — would OOM if unchecked!
    crafted_wire[units_len_offset..units_len_offset + 8]
        .copy_from_slice(&1_000_000_000u64.to_le_bytes());
    assert!(matches!(
        decode_manifest_strict(&crafted_wire),
        Err(SnapV4Error::BincodeDecode(_))
    ));

    // Overwrite `units` length prefix with MAX_SNAP_UNITS + 1 = 4097.
    crafted_wire[units_len_offset..units_len_offset + 8]
        .copy_from_slice(&((MAX_SNAP_UNITS + 1) as u64).to_le_bytes());
    assert!(matches!(
        decode_manifest_strict(&crafted_wire),
        Err(SnapV4Error::BincodeDecode(_))
    ));

    // Oversized manifest wire buffer (> MAX_MANIFEST_WIRE_BYTES) rejected before decode.
    let oversized_buf = vec![0u8; MAX_MANIFEST_WIRE_BYTES + 1];
    assert!(matches!(
        decode_manifest_strict(&oversized_buf),
        Err(SnapV4Error::ManifestTooLarge { .. })
    ));

    // 2. Struct-level limits rejected in validate_manifest_pre_fetch before allocating chunk slots.
    let mut too_many_units = encoded.manifest.clone();
    while too_many_units.units.len() <= MAX_SNAP_UNITS {
        too_many_units.units.push(SnapshotUnitDesc {
            unit_tag: 0,
            sub_index: 99,
            encoding: UNIT_ENC_UNCHANGED,
            unit_hash: empty_bucket_hash(),
            chunk_hash: [0u8; 32],
            byte_len: 0,
        });
    }
    assert!(matches!(
        validate_manifest_pre_fetch(&too_many_units, &anchor),
        Err(SnapV4Error::TooManyUnits { .. })
    ));

    let mut too_many_wire = encoded.manifest.clone();
    too_many_wire.total_wire_bytes = MAX_SNAP_WIRE_BYTES + 1;
    assert!(matches!(
        validate_manifest_pre_fetch(&too_many_wire, &anchor),
        Err(SnapV4Error::WireBytesLimitExceeded { .. })
    ));

    let mut too_many_decode = encoded.manifest.clone();
    too_many_decode.total_uncompressed_bytes = MAX_SNAPSHOT_DECODE_BYTES + 1;
    assert!(matches!(
        validate_manifest_pre_fetch(&too_many_decode, &anchor),
        Err(SnapV4Error::DecodeBytesLimitExceeded { .. })
    ));

    let mut oversized_chunk = encoded.manifest.clone();
    let idx_full = oversized_chunk
        .units
        .iter()
        .position(|u| u.encoding == UNIT_ENC_FULL)
        .unwrap();
    oversized_chunk.units[idx_full].byte_len = (MAX_SNAP_CHUNK_BYTES as u32) + 1;
    oversized_chunk.total_wire_bytes +=
        (MAX_SNAP_CHUNK_BYTES as u64 + 1) - encoded.manifest.units[idx_full].byte_len as u64;
    oversized_chunk.total_uncompressed_bytes = oversized_chunk.total_wire_bytes;
    resign_manifest(&mut oversized_chunk, &kp);
    assert!(matches!(
        validate_manifest_pre_fetch(&oversized_chunk, &anchor),
        Err(SnapV4Error::ChunkTooLarge { .. })
    ));

    // 3. MAX_DELTA_CHAIN_LEN: 8 succeeds, 9 fails BEFORE processing any delta!
    let mut chain_states = vec![state.clone()];
    let mut chain_roots = vec![root];
    let mut chain_deltas = Vec::new();
    let mut chain_anchors = Vec::new();
    for step in 1..=(MAX_DELTA_CHAIN_LEN + 1) {
        let mut next = chain_states.last().unwrap().clone();
        next.buckets[0x07][0].balance += step as u64;
        let next_root = next.compute_state_root().await.unwrap();
        let next_h = 10 + step as u64;
        let boundary = make_hash(&[b'd', step as u8]);
        let p = SnapshotBuildParams {
            chain_id: params.chain_id,
            shard_id: params.shard_id,
            target_height: next_h,
            target_block_hash: boundary,
            target_state_root: next_root,
            validator_set: params.validator_set,
        };
        let d = build_delta_snapshot(
            chain_states.last().unwrap(),
            &next,
            10 + (step as u64 - 1),
            *chain_roots.last().unwrap(),
            &p,
            &kp,
        )
        .unwrap();
        chain_anchors.push(TrustedSnapshotAnchor {
            chain_id: params.chain_id,
            shard_id: params.shard_id,
            target_height: next_h,
            trusted_boundary_hash: boundary,
            trusted_state_root: next_root,
            validator_set: &vset,
        });
        chain_deltas.push(d);
        chain_states.push(next);
        chain_roots.push(next_root);
    }

    let ok_refs: Vec<(&EncodedSnapshotV4, &TrustedSnapshotAnchor<'_>)> = chain_deltas
        [..MAX_DELTA_CHAIN_LEN]
        .iter()
        .zip(chain_anchors[..MAX_DELTA_CHAIN_LEN].iter())
        .collect();
    let ok_res = verify_and_apply_delta_chain(&state, 10, root, &ok_refs).await;
    assert!(ok_res.is_ok(), "chain len == MAX_DELTA_CHAIN_LEN must pass");

    let bad_refs: Vec<(&EncodedSnapshotV4, &TrustedSnapshotAnchor<'_>)> =
        chain_deltas.iter().zip(chain_anchors.iter()).collect();
    let bad_res = verify_and_apply_delta_chain(&state, 10, root, &bad_refs).await;
    assert_eq!(
        bad_res.unwrap_err(),
        SnapV4Error::DeltaChainTooLong {
            len: MAX_DELTA_CHAIN_LEN + 1,
            max: MAX_DELTA_CHAIN_LEN,
        }
    );
}

#[tokio::test]
async fn negative_corrupted_chunk_and_merkle_proof_rejected() {
    let (kp, vset, _state, encoded, params, root) =
        make_minimal_base_fixture(b"neg_corrupt_chunk").await;
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };

    // 1. Corrupt 1 byte inside chunk (0x07, 0).
    let mut bad_chunks = encoded.chunks.clone();
    bad_chunks.get_mut(&(0x07, 0)).unwrap()[0] ^= 0xFF;
    assert_eq!(
        verify_and_apply_base(&encoded.manifest, &bad_chunks, &anchor).await,
        Err(SnapV4Error::ChunkHashMismatch {
            unit_tag: 0x07,
            sub_index: 0,
        })
    );

    // 2. Truncate chunk -> ChunkByteLenMismatch.
    let mut trunc_chunks = encoded.chunks.clone();
    trunc_chunks.get_mut(&(0x07, 0)).unwrap().pop();
    assert!(matches!(
        verify_and_apply_base(&encoded.manifest, &trunc_chunks, &anchor).await,
        Err(SnapV4Error::ChunkByteLenMismatch {
            unit_tag: 0x07,
            sub_index: 0,
            ..
        })
    ));

    // 3. Missing chunk -> MissingChunk; extra unexpected chunk -> UnexpectedChunk.
    let mut missing_chunks = encoded.chunks.clone();
    missing_chunks.remove(&(0x07, 0));
    assert_eq!(
        verify_and_apply_base(&encoded.manifest, &missing_chunks, &anchor).await,
        Err(SnapV4Error::MissingChunk {
            unit_tag: 0x07,
            sub_index: 0,
        })
    );
    let mut extra_chunks = encoded.chunks.clone();
    extra_chunks.insert((0x01, 0), vec![1, 2, 3]);
    assert_eq!(
        verify_and_apply_base(&encoded.manifest, &extra_chunks, &anchor).await,
        Err(SnapV4Error::UnexpectedChunk {
            unit_tag: 0x01,
            sub_index: 0,
        })
    );

    // 4. Tamper units_merkle_root (re-signed) -> UnitsMerkleRootMismatch pre-fetch.
    let mut bad_merkle_m = encoded.manifest.clone();
    bad_merkle_m.units_merkle_root[0] ^= 0xAA;
    sign_manifest(&mut bad_merkle_m, &kp).unwrap();
    assert_eq!(
        validate_manifest_pre_fetch(&bad_merkle_m, &anchor),
        Err(SnapV4Error::UnitsMerkleRootMismatch)
    );

    // 5. Tampered UnitMerkleProof -> verify_unit_merkle_proof returns false.
    let mut proof = generate_unit_merkle_proof(&encoded.manifest.units, 7).unwrap();
    assert!(verify_unit_merkle_proof(
        &encoded.manifest.units_merkle_root,
        &encoded.manifest.units[7],
        &proof
    ));
    proof.siblings[0][0] ^= 0x01;
    assert!(!verify_unit_merkle_proof(
        &encoded.manifest.units_merkle_root,
        &encoded.manifest.units[7],
        &proof
    ));
}

#[tokio::test]
async fn negative_delta_base_state_root_and_non_monotonic_chain_rejected() {
    let (kp, vset, state_10, _encoded_10, params_10, root_10) =
        make_minimal_base_fixture(b"neg_delta_base").await;

    let mut state_11 = state_10.clone();
    state_11.buckets[0x07][0].balance += 100;
    let root_11 = state_11.compute_state_root().await.unwrap();
    let boundary_11 = make_hash(b"b11");
    let params_11 = SnapshotBuildParams {
        chain_id: params_10.chain_id,
        shard_id: params_10.shard_id,
        target_height: 11,
        target_block_hash: boundary_11,
        target_state_root: root_11,
        validator_set: params_10.validator_set,
    };
    let delta_11 =
        build_delta_snapshot(&state_10, &state_11, 10, root_10, &params_11, &kp).unwrap();
    let anchor_11 = TrustedSnapshotAnchor {
        chain_id: params_10.chain_id,
        shard_id: params_10.shard_id,
        target_height: 11,
        trusted_boundary_hash: boundary_11,
        trusted_state_root: root_11,
        validator_set: &vset,
    };

    // 1. Local base has DIFFERENT state_root than delta.base_state_root -> DeltaBaseStateRootMismatch.
    let wrong_local_root = make_hash(b"forked_local_root");
    assert_eq!(
        verify_and_apply_delta(
            &state_10,
            10,
            wrong_local_root,
            &delta_11.manifest,
            &delta_11.chunks,
            &anchor_11,
        )
        .await,
        Err(SnapV4Error::DeltaBaseStateRootMismatch {
            expected: wrong_local_root,
            actual: root_10,
        })
    );

    // 2. Non-monotonic chain (anchor target_height <= base_height) -> NonMonotonicDeltaChain.
    let err = verify_and_apply_delta_chain(&state_10, 11, root_10, &[(&delta_11, &anchor_11)])
        .await
        .unwrap_err();
    assert_eq!(
        err,
        SnapV4Error::NonMonotonicDeltaChain {
            prev_height: 11,
            next_height: 11,
        }
    );

    // 3. Tampered expected_base_hash inside AccountBucketDelta chunk -> DeltaBaseUnitHashMismatch.
    let mut bad_base_delta = delta_11.clone();
    let mut parsed: AccountBucketDelta = decode_canonical_exact(
        &bad_base_delta.chunks[&(0x07, 0)],
        MAX_SNAP_CHUNK_BYTES as u64,
    )
    .unwrap();
    parsed.expected_base_hash[0] ^= 0x55;
    let new_bytes = encode_canonical(&parsed).unwrap();
    let desc_idx = bad_base_delta
        .manifest
        .units
        .iter()
        .position(|u| u.unit_tag == 0x07)
        .unwrap();
    let old_len = bad_base_delta.manifest.units[desc_idx].byte_len as u64;
    bad_base_delta.manifest.units[desc_idx].byte_len = new_bytes.len() as u32;
    bad_base_delta.manifest.units[desc_idx].chunk_hash = *blake3::hash(&new_bytes).as_bytes();
    bad_base_delta.manifest.total_wire_bytes =
        bad_base_delta.manifest.total_wire_bytes - old_len + new_bytes.len() as u64;
    bad_base_delta.manifest.total_uncompressed_bytes = bad_base_delta.manifest.total_wire_bytes;
    resign_manifest(&mut bad_base_delta.manifest, &kp);
    bad_base_delta.chunks.insert((0x07, 0), new_bytes);

    assert_eq!(
        verify_and_apply_delta(
            &state_10,
            10,
            root_10,
            &bad_base_delta.manifest,
            &bad_base_delta.chunks,
            &anchor_11,
        )
        .await,
        Err(SnapV4Error::DeltaBaseUnitHashMismatch { unit_tag: 0x07 })
    );
}

#[tokio::test]
async fn negative_duplicate_and_unsorted_buckets_and_keys_rejected() {
    let (kp, vset, state, encoded, params, root) =
        make_minimal_base_fixture(b"neg_dup_unsorted").await;
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };

    // 1. Duplicate unit descriptor in manifest.
    let mut dup_m = encoded.manifest.clone();
    dup_m.units.insert(0, dup_m.units[0]);
    resign_manifest(&mut dup_m, &kp);
    assert!(matches!(
        validate_manifest_pre_fetch(&dup_m, &anchor),
        Err(SnapV4Error::UnsortedOrDuplicateUnit { .. })
    ));

    // 2. Unsorted unit descriptors in manifest (swap bucket 1 and bucket 2).
    let mut unsorted_m = encoded.manifest.clone();
    unsorted_m.units.swap(1, 2);
    resign_manifest(&mut unsorted_m, &kp);
    assert!(matches!(
        validate_manifest_pre_fetch(&unsorted_m, &anchor),
        Err(SnapV4Error::UnsortedOrDuplicateUnit { .. })
    ));

    // 3. Missing unit descriptor in manifest (remove last domain).
    let mut missing_m = encoded.manifest.clone();
    let removed = missing_m.units.pop().unwrap();
    missing_m.total_wire_bytes -= removed.byte_len as u64;
    missing_m.total_uncompressed_bytes = missing_m.total_wire_bytes;
    resign_manifest(&mut missing_m, &kp);
    assert_eq!(
        validate_manifest_pre_fetch(&missing_m, &anchor),
        Err(SnapV4Error::MissingUnitDescriptor {
            unit_tag: removed.unit_tag
        })
    );

    // 4. Duplicate account inside AccountBucketFull chunk.
    let mut bad_bucket = encoded.clone();
    let mut bf: AccountBucketFull =
        decode_canonical_exact(&bad_bucket.chunks[&(0x07, 0)], MAX_SNAP_CHUNK_BYTES as u64)
            .unwrap();
    bf.accounts.push(bf.accounts[0].clone());
    let new_raw = encode_canonical(&bf).unwrap();
    let idx = bad_bucket
        .manifest
        .units
        .iter()
        .position(|u| u.unit_tag == 0x07)
        .unwrap();
    let old_len = bad_bucket.manifest.units[idx].byte_len as u64;
    bad_bucket.manifest.units[idx].byte_len = new_raw.len() as u32;
    bad_bucket.manifest.units[idx].chunk_hash = *blake3::hash(&new_raw).as_bytes();
    bad_bucket.manifest.units[idx].unit_hash = compute_unit_hash(0x07, 0, &new_raw);
    bad_bucket.manifest.total_wire_bytes =
        bad_bucket.manifest.total_wire_bytes - old_len + new_raw.len() as u64;
    bad_bucket.manifest.total_uncompressed_bytes = bad_bucket.manifest.total_wire_bytes;
    resign_manifest(&mut bad_bucket.manifest, &kp);
    bad_bucket.chunks.insert((0x07, 0), new_raw);

    assert_eq!(
        verify_and_apply_base(&bad_bucket.manifest, &bad_bucket.chunks, &anchor).await,
        Err(SnapV4Error::UnsortedOrDuplicateAccount { bucket: 0x07 })
    );

    // 5. Wrong bucket prefix address inside AccountBucketFull.
    let mut wrong_prefix = encoded.clone();
    let mut bf2: AccountBucketFull = decode_canonical_exact(
        &wrong_prefix.chunks[&(0x07, 0)],
        MAX_SNAP_CHUNK_BYTES as u64,
    )
    .unwrap();
    bf2.accounts[0].address = make_addr(0x08, 1);
    let new_raw2 = encode_canonical(&bf2).unwrap();
    let old_len2 = wrong_prefix.manifest.units[idx].byte_len as u64;
    wrong_prefix.manifest.units[idx].byte_len = new_raw2.len() as u32;
    wrong_prefix.manifest.units[idx].chunk_hash = *blake3::hash(&new_raw2).as_bytes();
    wrong_prefix.manifest.units[idx].unit_hash = compute_unit_hash(0x07, 0, &new_raw2);
    wrong_prefix.manifest.total_wire_bytes =
        wrong_prefix.manifest.total_wire_bytes - old_len2 + new_raw2.len() as u64;
    wrong_prefix.manifest.total_uncompressed_bytes = wrong_prefix.manifest.total_wire_bytes;
    resign_manifest(&mut wrong_prefix.manifest, &kp);
    wrong_prefix.chunks.insert((0x07, 0), new_raw2);

    assert_eq!(
        verify_and_apply_base(&wrong_prefix.manifest, &wrong_prefix.chunks, &anchor).await,
        Err(SnapV4Error::WrongBucketAddress {
            bucket: 0x07,
            addr_first_byte: 0x08,
        })
    );

    // 6. Unsorted / overlapping / missing-delete keys in AccountBucketDelta and MapDiff.
    let mut state_11 = state.clone();
    state_11.buckets[0x07][0].balance += 10;
    let root_11 = state_11.compute_state_root().await.unwrap();
    let b11 = make_hash(b"b11_dup");
    let p11 = SnapshotBuildParams {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: 11,
        target_block_hash: b11,
        target_state_root: root_11,
        validator_set: params.validator_set,
    };
    let delta_11 = build_delta_snapshot(&state, &state_11, 10, root, &p11, &kp).unwrap();
    let anchor_11 = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: 11,
        trusted_boundary_hash: b11,
        trusted_state_root: root_11,
        validator_set: &vset,
    };

    let mut overlap_delta = delta_11.clone();
    let mut abd: AccountBucketDelta = decode_canonical_exact(
        &overlap_delta.chunks[&(0x07, 0)],
        MAX_SNAP_CHUNK_BYTES as u64,
    )
    .unwrap();
    abd.deletes.push(abd.upserts[0].address);
    let d_raw = encode_canonical(&abd).unwrap();
    let d_idx = overlap_delta
        .manifest
        .units
        .iter()
        .position(|u| u.unit_tag == 0x07)
        .unwrap();
    let old_d_len = overlap_delta.manifest.units[d_idx].byte_len as u64;
    overlap_delta.manifest.units[d_idx].byte_len = d_raw.len() as u32;
    overlap_delta.manifest.units[d_idx].chunk_hash = *blake3::hash(&d_raw).as_bytes();
    overlap_delta.manifest.total_wire_bytes =
        overlap_delta.manifest.total_wire_bytes - old_d_len + d_raw.len() as u64;
    overlap_delta.manifest.total_uncompressed_bytes = overlap_delta.manifest.total_wire_bytes;
    resign_manifest(&mut overlap_delta.manifest, &kp);
    overlap_delta.chunks.insert((0x07, 0), d_raw);

    assert_eq!(
        verify_and_apply_delta(
            &state,
            10,
            root,
            &overlap_delta.manifest,
            &overlap_delta.chunks,
            &anchor_11,
        )
        .await,
        Err(SnapV4Error::UpsertDeleteOverlap {
            domain: "AccountBucketDelta"
        })
    );

    // Unsorted keys inside OrderEscrow MapDiff chunk rejected by verify_and_apply_delta.
    let mut base_escrow_state = state.clone();
    for oid in 1..=6u64 {
        base_escrow_state.order_escrow.escrow.insert(
            (1, oid),
            EscrowRecord {
                trader: make_addr(0x07, oid as u8),
                locked_base_stell: oid * 100,
                locked_quote_wusdt: 0,
                locked_quote_native: 0,
            },
        );
    }
    let esc_base_root = base_escrow_state.compute_state_root().await.unwrap();
    let mut target_escrow_state = base_escrow_state.clone();
    for oid in 10..=11u64 {
        target_escrow_state.order_escrow.escrow.insert(
            (2, oid),
            EscrowRecord {
                trader: make_addr(0x07, oid as u8),
                locked_base_stell: oid * 100,
                locked_quote_wusdt: 0,
                locked_quote_native: 0,
            },
        );
    }
    let esc_target_root = target_escrow_state.compute_state_root().await.unwrap();
    let esc_b = make_hash(b"esc_b11");
    let esc_p = SnapshotBuildParams {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: 11,
        target_block_hash: esc_b,
        target_state_root: esc_target_root,
        validator_set: params.validator_set,
    };
    let mut esc_delta = build_delta_snapshot(
        &base_escrow_state,
        &target_escrow_state,
        10,
        esc_base_root,
        &esc_p,
        &kp,
    )
    .unwrap();
    let esc_tag = DomainUnitId::OrderEscrow.tag();
    let esc_idx = esc_delta
        .manifest
        .units
        .iter()
        .position(|u| u.unit_tag == esc_tag)
        .unwrap();
    assert_eq!(esc_delta.manifest.units[esc_idx].encoding, UNIT_ENC_DELTA);
    let mut esc_diff: MapDiff<(u32, u64), EscrowRecord> = decode_canonical_exact(
        &esc_delta.chunks[&(esc_tag, 0)],
        MAX_SNAP_CHUNK_BYTES as u64,
    )
    .unwrap();
    esc_diff.upserts.swap(0, 1); // reverse sorted order!
    let esc_raw = encode_canonical(&esc_diff).unwrap();
    let old_esc_len = esc_delta.manifest.units[esc_idx].byte_len as u64;
    esc_delta.manifest.units[esc_idx].byte_len = esc_raw.len() as u32;
    esc_delta.manifest.units[esc_idx].chunk_hash = *blake3::hash(&esc_raw).as_bytes();
    esc_delta.manifest.total_wire_bytes =
        esc_delta.manifest.total_wire_bytes - old_esc_len + esc_raw.len() as u64;
    esc_delta.manifest.total_uncompressed_bytes = esc_delta.manifest.total_wire_bytes;
    resign_manifest(&mut esc_delta.manifest, &kp);
    esc_delta.chunks.insert((esc_tag, 0), esc_raw);
    let esc_anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: 11,
        trusted_boundary_hash: esc_b,
        trusted_state_root: esc_target_root,
        validator_set: &vset,
    };
    assert_eq!(
        verify_and_apply_delta(
            &base_escrow_state,
            10,
            esc_base_root,
            &esc_delta.manifest,
            &esc_delta.chunks,
            &esc_anchor,
        )
        .await,
        Err(SnapV4Error::UnsortedOrDuplicateKey {
            domain: "OrderEscrow"
        })
    );
}

#[tokio::test]
async fn negative_trailing_bytes_rejected() {
    let (kp, vset, _state, encoded, params, root) =
        make_minimal_base_fixture(b"neg_trailing_bytes").await;
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };

    // 1. Trailing byte on manifest wire bytes -> rejected by decode_manifest_strict.
    let mut m_bytes = encode_manifest_strict(&encoded.manifest).unwrap();
    m_bytes.push(0x00);
    assert!(matches!(
        decode_manifest_strict(&m_bytes),
        Err(SnapV4Error::BincodeDecode(_))
    ));

    // 2. Trailing byte on Scalars chunk (with updated chunk_hash/unit_hash/manifest sig so it
    // reaches decode_canonical_exact) -> rejected with BincodeDecode!
    let mut bad_trailing = encoded.clone();
    let tag = DomainUnitId::Scalars.tag();
    let mut raw = bad_trailing.chunks[&(tag, 0)].clone();
    raw.push(0x99);
    // Check verify_unit_chunk catches mismatched len first if manifest wasn't updated,
    // and strict decode catches trailing byte if manifest WAS updated.
    let idx = bad_trailing
        .manifest
        .units
        .iter()
        .position(|u| u.unit_tag == tag)
        .unwrap();
    assert!(matches!(
        verify_unit_chunk(&bad_trailing.manifest.units[idx], &raw),
        Err(SnapV4Error::ChunkByteLenMismatch { .. })
    ));

    let old_len = bad_trailing.manifest.units[idx].byte_len as u64;
    bad_trailing.manifest.units[idx].byte_len = raw.len() as u32;
    bad_trailing.manifest.units[idx].chunk_hash = *blake3::hash(&raw).as_bytes();
    bad_trailing.manifest.units[idx].unit_hash = compute_unit_hash(tag, 0, &raw);
    bad_trailing.manifest.total_wire_bytes =
        bad_trailing.manifest.total_wire_bytes - old_len + raw.len() as u64;
    bad_trailing.manifest.total_uncompressed_bytes = bad_trailing.manifest.total_wire_bytes;
    resign_manifest(&mut bad_trailing.manifest, &kp);
    bad_trailing.chunks.insert((tag, 0), raw);

    let err = verify_and_apply_base(&bad_trailing.manifest, &bad_trailing.chunks, &anchor)
        .await
        .unwrap_err();
    assert!(matches!(err, SnapV4Error::BincodeDecode(_)));
    let _: CanonicalScalars =
        decode_canonical_exact(&encoded.chunks[&(tag, 0)], MAX_SNAP_CHUNK_BYTES as u64).unwrap();
}

#[tokio::test]
async fn safety_isolation_invariant_no_safety_or_checkpoint_in_snap_v4() {
    let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_dir = std::env::temp_dir().join(format!(
        "stell_snap_v4_safety_{}_{}",
        std::process::id(),
        seq
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let (kp, vset, state, encoded, params, root) =
        make_minimal_base_fixture(b"safety_isolation").await;

    let store = Storage::open(&tmp_dir).expect("open temp Storage");
    let identity = SafetyRecordIdentity {
        validator: kp.validator_id(),
        chain: make_hash(b"test_chain_genesis"),
        shard: 0,
    };
    let safety_store = store
        .safety_record_store(identity)
        .expect("open safety_record_store");
    let sentinel_safety = b"SENTINEL_SAFETY_RECORD_V1_UNEXPORTABLE".to_vec();
    let rec = safety_store
        .persist(None, sentinel_safety.clone())
        .expect("persist safety record");
    assert_eq!(rec.generation, 1);

    let cp = ConsensusCheckpoint {
        height: 42,
        round: 3,
        locked_hash: Some(make_hash(b"locked_val_sentinel")),
        locked_round: 2,
        finalized_height: 41,
        finalized_hash: make_hash(b"finalized_sentinel"),
    };
    store.set_consensus(&cp).expect("set consensus checkpoint");

    let mut wm = VoteWatermark::default();
    wm.note(VoteWatermarkEntry {
        height: 42,
        round: 3,
        kind: 1,
        target: Some(make_hash(b"wm_target_sentinel")),
        shard_id: 0,
    });
    store.set_vote_watermark(&wm).expect("set vote watermark");

    // Verify neither manifest nor any chunk contains any safety/checkpoint/watermark sentinel bytes.
    let manifest_bytes = encode_manifest_strict(&encoded.manifest).unwrap();
    assert!(!manifest_bytes
        .windows(sentinel_safety.len())
        .any(|w| w == sentinel_safety.as_slice()));
    for chunk in encoded.chunks.values() {
        assert!(!chunk
            .windows(sentinel_safety.len())
            .any(|w| w == sentinel_safety.as_slice()));
    }

    // Run full SnapV4 verify + apply onto an engine while Storage holds safety/checkpoint/watermark.
    let anchor = TrustedSnapshotAnchor {
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        target_height: params.target_height,
        trusted_boundary_hash: params.target_block_hash,
        trusted_state_root: root,
        validator_set: &vset,
    };
    let restored = verify_and_apply_base(&encoded.manifest, &encoded.chunks, &anchor)
        .await
        .expect("verify_and_apply_base");
    let engine = InMemoryStateEngine::new();
    restored.apply_to_engine(&engine).await.expect("apply");
    assert_eq!(restored, state);
    assert_eq!(
        canonical_vset_hash(&vset),
        encoded.manifest.validator_set_hash
    );
    assert_eq!(
        manifest_signing_digest(&encoded.manifest),
        *blake3::Hasher::new()
            .update(SNAP_MANIFEST_SIG_DOMAIN)
            .update(&canonical_manifest_body_bytes(&encoded.manifest))
            .finalize()
            .as_bytes()
    );

    // Assert safety_record_v1, ConsensusCheckpoint, and VoteWatermark are completely untouched.
    let loaded_safety = safety_store.load().expect("load safety").expect("present");
    assert_eq!(loaded_safety.generation, 1);
    assert_eq!(loaded_safety.payload, sentinel_safety);
    let loaded_cp = store.consensus().expect("load cp").expect("present");
    assert_eq!(loaded_cp.height, cp.height);
    assert_eq!(loaded_cp.locked_hash, cp.locked_hash);
    assert_eq!(loaded_cp.finalized_hash, cp.finalized_hash);
    let loaded_wm = store.vote_watermark().expect("load wm").expect("present");
    assert_eq!(loaded_wm, wm);

    drop(safety_store);
    drop(store);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
