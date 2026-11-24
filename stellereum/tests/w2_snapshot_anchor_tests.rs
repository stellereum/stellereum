//! Regression tests for `P0-PEER-SNAPSHOT-ANCHOR`:
//!
//! 1. Retro-publish includes immutable headers/v2-headers/height-index (`_h_`,
//!    `_h2_`, `_hi_`) and QC sidecars (`_hq_`) without touching `shard_head`,
//!    and covers snapshot boundaries within the retention window so lagging
//!    nodes can verify snapshot anchors (while still failing closed when
//!    headers are absent or forged).
//! 2. Snapshot anchor verification (`use_tail_anchor == false` and `true`)
//!    threads per-height sets from `validator_set_history` across rotations
//!    (`4 -> 3 -> 4`), persists/restores `validator_set_history` via `Storage`,
//!    and fails closed (`None` from `validator_set_for_height_strict`) when a
//!    historical height is unknown or an anchor proposer was not in that
//!    height's set (no silent fallback to a neighboring or power-1 config set).

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    register_validator_pq_key, CommitteeSchedule, ValidatorSet, Vote, VoteKind, VoteSet,
};
use stellereum::network::{
    plan_block_header_writes, EpochTag, P2pNetworkAdapter, BUCKET_STELLEREUM_HEADERS,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::required_bond_floor_nano;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{AsyncPersistence, DomainSnapshot, Storage};
use stellereum::sync::{verify_snapshot_anchor_with_sets_and_schedule, HeaderLink};

#[path = "../src/node/policy.rs"]
#[allow(dead_code)]
pub(crate) mod node_policy;

#[allow(dead_code)]
mod node {
    pub(crate) use crate::node_policy as policy;
}

#[path = "../src/node/sync.rs"]
#[allow(dead_code)]
mod node_sync;

static DIR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "stell-w2-snap-anchor-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn bond_floor() -> u64 {
    required_bond_floor_nano()
}

fn fks_for(ks: &[SigningKey]) -> Vec<FalconKeypair> {
    ks.iter()
        .map(|k| FalconKeypair::generate_from_seed(k.to_bytes()[0]))
        .collect()
}

fn register_keys(ks: &[SigningKey], fks: &[FalconKeypair]) {
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
}

async fn seed_engine_bonded(
    engine: &InMemoryStateEngine,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    powers: &[u64],
) {
    register_keys(ks, fks);
    let mut ledger = engine.staking_write().await;
    let mut pq_reg = engine.pq_registry_write().await;
    for ((k, fk), &power) in ks.iter().zip(fks.iter()).zip(powers.iter()) {
        let id = k.verifying_key().to_bytes();
        ledger.bond(id, power, 0).expect("seed bond");
        ledger
            .validator_pq_keys
            .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
        let _ = pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
    }
    stellereum::consensus::sync_committed_pq_registry(&pq_reg, true);
}

fn attach_quorum(
    b: &mut Block,
    signers: &[&SigningKey],
    signer_fks: &[&FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    bh: [u8; 32],
    parent: [u8; 32],
) {
    let mut set = VoteSet::new();
    for (k, fk) in signers.iter().zip(signer_fks.iter()) {
        let v = Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(bh));
        set.add(v, vs, height, 0, VoteKind::Precommit)
            .expect("genuine precommit vote admits");
    }
    b.precommit_qc = set.certificate_with_parent(Some(bh), vs, Some(&parent));
}

fn make_signed_block(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    active_indices: &[usize],
) -> (Block, [u8; 32]) {
    let proposer_id = vs.proposer_for(height, 0).expect("non-empty set elects");
    let proposer_idx = ks
        .iter()
        .position(|k| k.verifying_key().to_bytes() == proposer_id)
        .expect("proposer must be in key list");
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: proposer_id,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        epoch_key_commitment: [0u8; 32],
        round: 0,
    };
    b.sign_block_with_falcon(&ks[proposer_idx], &fks[proposer_idx]);
    let bh = b.compute_hash();
    let signer_ks: Vec<&SigningKey> = active_indices.iter().map(|&i| &ks[i]).collect();
    let signer_fks: Vec<&FalconKeypair> = active_indices.iter().map(|&i| &fks[i]).collect();
    attach_quorum(&mut b, &signer_ks, &signer_fks, vs, height, bh, prev_hash);
    (b, bh)
}

async fn test_adapter(tag: &str) -> (Arc<P2pNetworkAdapter>, std::path::PathBuf) {
    let dir = temp_dir(tag);
    let cfg = infnode::config::NodeConfig {
        name: "w2-test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    };
    let node = infnode::node::Node::new(
        cfg,
        infnode::keyring::NodeKeys::generate(),
        infnode::keyring::PqKeys::generate(),
        dir.clone(),
        std::path::PathBuf::new(),
    )
    .await
    .expect("create test infnode");
    let adapter = Arc::new(P2pNetworkAdapter::new(node));
    adapter.set_epoch(EpochTag::from_genesis(&[0x55u8; 32]));
    (adapter, dir)
}

async fn publish_boundary_snapshot(
    adapter: &P2pNetworkAdapter,
    engine: &InMemoryStateEngine,
    boundary: u64,
) {
    let state_bytes = engine.create_snapshot().await;
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    let domains = DomainSnapshot::capture(engine, &staking, &gov).await;
    let domains_bytes = bincode::serialize(&domains).expect("serialize domains");
    let pq_reg_bytes = engine.pq_registry_snapshot().await;

    assert!(
        adapter
            .persist_domain_snapshot(MASTERCHAIN_SHARD, boundary, "domains", &domains_bytes)
            .await,
        "domains snapshot must publish"
    );
    if !pq_reg_bytes.is_empty() {
        assert!(
            adapter
                .persist_domain_snapshot(MASTERCHAIN_SHARD, boundary, "pq_registry", &pq_reg_bytes,)
                .await,
            "pq_registry snapshot must publish"
        );
    }
    assert!(
        adapter
            .persist_state_snapshot(MASTERCHAIN_SHARD, boundary, &state_bytes)
            .await,
        "state snapshot must publish"
    );
}

#[test]
fn retro_publish_header_plan_and_depth_cover_snapshot_boundaries() {
    let sk = SigningKey::from_bytes(&[0x31u8; 32]);
    let block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1000,
        prev_hash: [0x11u8; 32],
        state_root: [0x22u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_001_000,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    };
    let epoch = EpochTag::from_genesis(&[0xAAu8; 32]);
    let writes = plan_block_header_writes(&epoch, &block);
    assert_eq!(
        writes.len(),
        3,
        "header plan writes v1 header, v2 header, and height index"
    );
    for w in &writes {
        assert_eq!(w.bucket, BUCKET_STELLEREUM_HEADERS);
        assert!(w.kv.is_empty(), "retro header writes must never touch KV");
    }

    // Effective retro-publish depth covers snapshot intervals larger than 4096
    // when retention permits, and never shrinks below RETRO_PUBLISH_DEPTH.
    assert!(node_sync::effective_retro_publish_depth(1000, 8000) >= 4096);
    assert!(node_sync::effective_retro_publish_depth(5000, 20_000) >= 15_003);
    let anchors = node_sync::snapshot_boundary_anchor_heights(2500, 1000, 4096);
    assert_eq!(anchors, vec![999, 1000, 1001, 1999, 2000, 2001]);
}

/// Test 1: Snapshot at a boundary whose headers were previously unpublished
/// fails closed initially, succeeds once `retro_publish_pass` publishes the
/// immutable headers/index/QC (without touching `shard_head`), and still
/// refuses forged or missing headers fail-closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry serialized across node_sync and w2 tests.
async fn snapshot_boundary_succeeds_after_retro_publish_and_refuses_forged_headers() {
    let _lock = node_policy::test_support::global_lock();
    const BOUNDARY: u64 = 50;
    const TIP: u64 = 55;

    let ks: Vec<SigningKey> = (0..4)
        .map(|i| SigningKey::from_bytes(&[0x70 + i; 32]))
        .collect();
    let fks = fks_for(&ks);
    let bond = bond_floor();
    let powers = vec![bond; 4];
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), bond))
            .collect(),
    );

    let producer_engine = Arc::new(InMemoryStateEngine::new());
    seed_engine_bonded(&producer_engine, &ks, &fks, &powers).await;
    let mut producer_rt =
        ValidatorRuntime::new(ks[0].clone(), vs.clone(), producer_engine.clone(), 1);

    let (adapter, net_dir) = test_adapter("boundary-retro").await;
    let store_dir = temp_dir("boundary-retro-store");
    let storage = Arc::new(Storage::open(&store_dir).expect("open producer storage"));
    let persist = Arc::new(AsyncPersistence::start(storage.clone()));

    let mut blocks = Vec::with_capacity(TIP as usize);
    let mut prev = [0u8; 32];
    let mut boundary_root = [0u8; 32];
    let active_indices = [0usize, 1, 2, 3];
    for h in 1..=TIP {
        let root = producer_rt.state.get_state_root().await;
        let (b, bh) = make_signed_block(h, prev, root, &ks, &fks, &vs, &active_indices);
        producer_rt.apply_and_advance(bh, &b).await;
        storage.put_block(&b).expect("store block");
        if h == BOUNDARY {
            boundary_root = producer_rt.state.get_state_root().await;
            publish_boundary_snapshot(&adapter, &producer_rt.state, BOUNDARY).await;
        }
        prev = bh;
        blocks.push(b);
    }
    storage.flush().expect("flush blocks");

    // Precondition (fail-before): snapshot exists at BOUNDARY=50, but NO headers
    // are published on the DHT yet. `try_snapshot_sync` must refuse fail-closed.
    let lagging_engine = Arc::new(InMemoryStateEngine::new());
    let mut lagging_rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), lagging_engine, 1);
    let before =
        node_sync::try_snapshot_sync(&adapter, &mut lagging_rt, MASTERCHAIN_SHARD, TIP).await;
    assert_eq!(
        before, None,
        "snapshot must fail closed when boundary headers are unpublished"
    );
    assert!(lagging_rt.finalized.is_empty());

    // Run `retro_publish_pass` from `published_upto = 0`: immutable headers
    // (`_h_`, `_h2_`, `_hi_`, `_hq_`) and bodies are published, and `shard_head`
    // stays untouched.
    let mut published_upto = 0u64;
    node_sync::retro_publish_pass(
        adapter.clone(),
        &producer_rt,
        Some(&persist),
        &mut published_upto,
        None,
    )
    .await;
    assert_eq!(published_upto, TIP);
    assert!(
        adapter.fetch_head(MASTERCHAIN_SHARD).await.is_none(),
        "retro_publish_pass must never move or write shard_head"
    );
    for h in [BOUNDARY - 1, BOUNDARY, BOUNDARY + 1] {
        let expected_hash = blocks[(h - 1) as usize].compute_hash();
        assert_eq!(
            adapter.fetch_head_hash(MASTERCHAIN_SHARD, h).await,
            Some(expected_hash),
            "retro-published height index must resolve height {h}"
        );
        assert!(
            adapter
                .fetch_block_header(MASTERCHAIN_SHARD, h, expected_hash)
                .await
                .is_some(),
            "retro-published immutable header must exist at height {h}"
        );
    }

    // Now the lagging node catches up via snapshot sync at BOUNDARY=50.
    let synced =
        node_sync::try_snapshot_sync(&adapter, &mut lagging_rt, MASTERCHAIN_SHARD, TIP).await;
    assert_eq!(
        synced,
        Some(BOUNDARY),
        "snapshot sync must succeed once retro-publish publishes immutable boundary headers"
    );
    assert_eq!(
        lagging_rt.finalized.last().copied(),
        Some((BOUNDARY, blocks[(BOUNDARY - 1) as usize].compute_hash()))
    );
    assert_eq!(lagging_rt.state.get_state_root().await, boundary_root);

    // Forged-header fail-closed check: tamper with boundary-1 block header on a
    // fresh adapter where boundary-1 has a broken prev_hash link.
    let (forged_adapter, forged_dir) = test_adapter("forged-boundary").await;
    publish_boundary_snapshot(&forged_adapter, &producer_rt.state, BOUNDARY).await;
    let mut forged_prev = blocks[(BOUNDARY - 2) as usize].clone();
    forged_prev.prev_hash = [0xFFu8; 32];
    let bad_h = forged_prev.compute_hash();
    let forged_qc = blocks[(BOUNDARY - 2) as usize].precommit_qc.clone();
    forged_prev.precommit_qc = forged_qc;
    // Publish forged `boundary-1`, genuine `boundary`, genuine `boundary+1`.
    let _ = forged_adapter
        .retro_publish_blocks(
            [
                &forged_prev,
                &blocks[(BOUNDARY - 1) as usize],
                &blocks[BOUNDARY as usize],
            ],
            3,
        )
        .await;
    assert_ne!(bad_h, blocks[(BOUNDARY - 2) as usize].compute_hash());

    let forged_engine = Arc::new(InMemoryStateEngine::new());
    let mut forged_rt = ValidatorRuntime::new(ks[0].clone(), vs, forged_engine, 1);
    let refused =
        node_sync::try_snapshot_sync(&forged_adapter, &mut forged_rt, MASTERCHAIN_SHARD, TIP).await;
    assert_eq!(
        refused, None,
        "snapshot sync must fail closed when boundary-1 linkage/QC is forged"
    );
    assert!(forged_rt.finalized.is_empty());

    drop(persist);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = std::fs::remove_dir_all(&net_dir);
    let _ = std::fs::remove_dir_all(&forged_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Test 2: Chain-anchored snapshot sync (`use_tail_anchor == false`) across a
/// `4 -> 3 -> 4` validator-set rotation verifies each height against the exact
/// `validator_set_history` for that height, persists/restores history in
/// `Storage`, and refuses both unknown heights and forged anchor proposers
/// (never falling back silently to a neighbor or unit-power config set).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry serialized across node_sync and w2 tests.
async fn snapshot_anchor_across_4_3_4_rotation_uses_exact_history_and_fails_closed() {
    let _lock = node_policy::test_support::global_lock();
    const BOUNDARY: u64 = 15;
    const TIP: u64 = 18;

    let ks: Vec<SigningKey> = (0..4)
        .map(|i| SigningKey::from_bytes(&[0x90 + i; 32]))
        .collect();
    let fks = fks_for(&ks);
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let bond = bond_floor();

    let s4_a = ValidatorSet::from_list(ids.iter().map(|&id| (id, bond)).collect());
    let s3 = ValidatorSet::from_list(ids[..3].iter().map(|&id| (id, bond)).collect());
    let s4_b = ValidatorSet::from_list(vec![
        (ids[0], bond),
        (ids[1], bond),
        (ids[2], bond),
        (ids[3], bond * 2),
    ]);
    let config_power_1 = ValidatorSet::from_list(ids.iter().map(|&id| (id, 1)).collect());

    let producer_engine = Arc::new(InMemoryStateEngine::new());
    seed_engine_bonded(&producer_engine, &ks, &fks, &[bond; 4]).await;
    let mut builder =
        ValidatorRuntime::new(ks[0].clone(), s4_a.clone(), producer_engine.clone(), 1);

    let (adapter, net_dir) = test_adapter("rot-434").await;
    let mut blocks = Vec::with_capacity(TIP as usize);
    let mut prev = [0u8; 32];

    for h in 1..=TIP {
        let root = builder.state.get_state_root().await;
        let (active_vs, active_indices): (&ValidatorSet, Vec<usize>) = if h <= 6 {
            (&s4_a, vec![0, 1, 2, 3])
        } else if h <= 12 {
            (&s3, vec![0, 1, 2])
        } else {
            (&s4_b, vec![0, 1, 2, 3])
        };
        let (b, bh) = make_signed_block(h, prev, root, &ks, &fks, active_vs, &active_indices);
        builder.apply_and_advance(bh, &b).await;

        // Rotate 4 -> 3 after height 6 (in force at 7), and 3 -> 4 after height 12 (in force at 13).
        if h == 6 {
            builder
                .state
                .staking_write()
                .await
                .unbond(ids[3], bond, 6)
                .expect("unbond k3");
            assert!(
                builder
                    .refresh_validator_set_from_staking_checked(6, 6)
                    .await
            );
            assert_eq!(builder.validators.validators, s3.validators);
        } else if h == 12 {
            builder
                .state
                .credit_native(&ids[3], bond * 4)
                .await
                .expect("credit k3");
            builder
                .state
                .staking_write()
                .await
                .add_bond(ids[3], bond * 2)
                .expect("re-bond k3");
            assert!(
                builder
                    .refresh_validator_set_from_staking_checked(12, 12)
                    .await
            );
            assert_eq!(builder.validators.validators, s4_b.validators);
        }

        if h == BOUNDARY {
            publish_boundary_snapshot(&adapter, &builder.state, BOUNDARY).await;
        }
        prev = bh;
        blocks.push(b);
    }

    let report = adapter
        .retro_publish_blocks(blocks.iter(), blocks.len())
        .await;
    assert_eq!(report.failed, 0, "all chain blocks must retro-publish");

    // Persist `validator_set_history` in Storage across a simulated restart.
    let hist_dir = temp_dir("rot-434-storage");
    {
        let storage = Storage::open(&hist_dir).expect("open storage");
        storage
            .put_validator_set_history(&builder.export_validator_set_history())
            .expect("persist validator_set_history");
        storage.flush().expect("flush storage");
    }
    let loaded_history = Storage::open(&hist_dir)
        .expect("reopen storage")
        .load_validator_set_history()
        .expect("load validator_set_history")
        .expect("history must exist");

    // Lagging node at height 4 (`gap = 14 <= 50` => `use_tail_anchor == false`),
    // restored with the persisted `validator_set_history`.
    let lagging_engine = Arc::new(InMemoryStateEngine::new());
    seed_engine_bonded(&lagging_engine, &ks, &fks, &[bond; 4]).await;
    let mut lagging =
        ValidatorRuntime::new(ks[0].clone(), config_power_1.clone(), lagging_engine, 1);
    for b in blocks.iter().take(4) {
        let bh = b.compute_hash();
        lagging.apply_and_advance(bh, b).await;
    }
    lagging.restore_validator_set_history(loaded_history);

    // Every height resolves strictly to the exact historical set.
    assert_eq!(
        lagging
            .validator_set_for_height_strict(6)
            .map(|s| s.validators),
        Some(s4_a.validators.clone())
    );
    assert_eq!(
        lagging
            .validator_set_for_height_strict(9)
            .map(|s| s.validators),
        Some(s3.validators.clone())
    );
    assert_eq!(
        lagging
            .validator_set_for_height_strict(15)
            .map(|s| s.validators),
        Some(s4_b.validators.clone())
    );

    // Chain-anchored snapshot sync across `4 -> 3 -> 4` succeeds!
    let synced = node_sync::try_snapshot_sync(&adapter, &mut lagging, MASTERCHAIN_SHARD, TIP).await;
    assert_eq!(
        synced,
        Some(BOUNDARY),
        "chain-anchored snapshot sync must verify each height across 4 -> 3 -> 4 rotation"
    );
    assert_eq!(
        lagging.finalized.last().copied(),
        Some((BOUNDARY, blocks[(BOUNDARY - 1) as usize].compute_hash()))
    );

    // Fail-closed 1: unknown height below the earliest persisted entry returns `None`
    // (never falls back to neighboring set or power-1 config set).
    let partial_engine = Arc::new(InMemoryStateEngine::new());
    let mut partial = ValidatorRuntime::new(ks[0].clone(), config_power_1, partial_engine, 10);
    partial.restore_validator_set_history(vec![(7, s3.clone()), (13, s4_b.clone())]);
    assert!(
        partial.validator_set_for_height_strict(5).is_none(),
        "height predating earliest history must fail closed as None"
    );
    let err_missing_hist = verify_snapshot_anchor_with_sets_and_schedule(
        Some((4, blocks[3].compute_hash())),
        [0u8; 32],
        BOUNDARY + 1,
        |h| partial.validator_set_for_height_strict(h),
        |_| CommitteeSchedule::ParentHash,
        1_000_000,
        |h| {
            let b = blocks[(h - 1) as usize].clone();
            async move { HeaderLink::from_block(&b) }
        },
    )
    .await
    .expect_err("snapshot anchor must refuse height 5 when history starts at 7");
    assert!(
        err_missing_hist.contains("no validator set resolvable at height 5"),
        "unexpected refusal: {err_missing_hist}"
    );

    // Fail-closed 2: snapshot whose anchor height 8 carries a proposer (`k3`) who was
    // NOT in the historical set `s3` at height 8 (even though `k3` is in `s4_a` and
    // `s4_b`) must be refused and never fall back to neighboring `s4_b` / `s4_a`.
    let mut bad_proposer_block = blocks[7].clone(); // height 8
    bad_proposer_block.proposer = ids[3]; // k3 is NOT in s3
    bad_proposer_block.sign_block_with_falcon(&ks[3], &fks[3]);
    let bad_bh = bad_proposer_block.compute_hash();
    let bad_prev = bad_proposer_block.prev_hash;
    attach_quorum(
        &mut bad_proposer_block,
        &[&ks[0], &ks[1], &ks[2], &ks[3]],
        &[&fks[0], &fks[1], &fks[2], &fks[3]],
        &s4_b,
        8,
        bad_bh,
        bad_prev,
    );
    let err_proposer = verify_snapshot_anchor_with_sets_and_schedule(
        Some((4, blocks[3].compute_hash())),
        [0u8; 32],
        BOUNDARY + 1,
        |h| lagging.validator_set_for_height_strict(h),
        |_| CommitteeSchedule::ParentHash,
        1_000_000,
        |h| {
            let b = if h == 8 {
                bad_proposer_block.clone()
            } else {
                blocks[(h - 1) as usize].clone()
            };
            async move { HeaderLink::from_block(&b) }
        },
    )
    .await
    .expect_err("anchor proposer not in height-8 set s3 must be refused");
    assert!(
        err_proposer.contains("held no schedule slot"),
        "expected proposer schedule refusal at height 8, got: {err_proposer}"
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = std::fs::remove_dir_all(&net_dir);
    let _ = std::fs::remove_dir_all(&hist_dir);
}
