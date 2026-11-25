//! Wave 7 regression tests for Wave 6 Storage, State Engine, and Crash Recovery findings:
//!
//! 1. W6-A2-1: `STELL_EVM_SETTLED_V1` nullifier leaves survive snapshot/restore/reorg/archive.
//! 2. W6-A2-2: `SnapStateV4::apply_to_engine` restores `pq_registry` (matching `compute_state_root`).
//! 3. W6-A2-3: `try_snapshot_sync` persists boundary block, finalized tip, state & domains, and
//!    flushes BEFORE `advance_to_verified_snapshot` advances `safety_record_v1`.
//! 4. W6-A2-5: `prune_state_below` preserves the newest paired `(state ∩ domains)` height.
//! 5. W6-A2-6: `reserve_mint_nano` / `release_mint_nano` bump commitment generation when
//!    `total_minted_nano` changes (`mint_native` after `get_state_root()` moves `get_state_root()`).
//! 6. W6-A2-7: `prune_receipts_below` removes `receipts_by_height` and `receipt_meta_v2` before
//!    `receipts`, leaving zero orphan index rows and recovering cleanly from partial state.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{register_validator_pq_key, ValidatorSet, Vote, VoteKind, VoteSet};
use stellereum::evm_adapter::{self, LegacyTransaction};
use stellereum::network::{EpochTag, P2pNetworkAdapter};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::pq_registry::PqRegistry;
use stellereum::runtime::ValidatorRuntime;
use stellereum::safety::{SafetyAuthority, SafetyBootContext};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::snapshot_v4::SnapStateV4;
use stellereum::staking::required_bond_floor_nano;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    load_full_state_into, AsyncPersistence, DomainSnapshot, SafetyRecordIdentity, Storage,
};

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

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "stell-w7-recovery-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

const TS: u64 = 1_760_000_000;
const FUNDS: u64 = 10_000_000_000_000;
const GAS_LIMIT: u64 = 1_000_000;
const TRANSFER_WEI: u128 = 5_000 * 1_000_000_000;

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = 0xA5;
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn pq_of(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

fn secp(seed: u8) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("secp key")
}

fn low_s(s: &mut [u8; 32], rec: &mut u8) {
    if !evm_adapter::is_low_s(s) {
        let n = evm_adapter::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        *s = out;
        *rec ^= 1;
    }
}

fn evm_raw(
    key: &k256::ecdsa::SigningKey,
    chain: u64,
    nonce: u64,
    to: [u8; 20],
    value: u128,
) -> Vec<u8> {
    let mut tx = LegacyTransaction {
        nonce,
        gas_price: 1,
        gas_limit: 21_000,
        to: Some(to),
        value,
        data: vec![],
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain),
    };
    let (sig, recid) = key
        .sign_prehash_recoverable(&tx.signing_hash())
        .expect("sign evm intent");
    let raw = sig.to_bytes();
    tx.r.copy_from_slice(&raw[..32]);
    tx.s.copy_from_slice(&raw[32..64]);
    let mut rec = recid.to_byte();
    low_s(&mut tx.s, &mut rec);
    tx.v = chain * 2 + 35 + rec as u64;
    tx.encode()
}

fn carrier_tx(kp: &FalconKeypair, raw: &[u8], to_pq: [u8; 32], gas_limit: u64) -> Transaction {
    let pk = kp.public_key().to_vec();
    let intent_sig = kp.sign(&evm_adapter::evm_intent_digest(raw));
    let sign_this = evm_adapter::carrier_template_message(raw, &pk, &intent_sig, to_pq, gas_limit)
        .expect("carrier template");
    let tx_sig = kp.sign(&sign_this);
    evm_adapter::build_carrier_transaction(raw, &pk, &intent_sig, to_pq, gas_limit, &tx_sig)
        .expect("carrier transaction")
}

fn simple_block(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    txs: Vec<Transaction>,
) -> Block {
    let proposer = SigningKey::from_bytes(&[0x5Au8; 32]);
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: proposer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    };
    b.sign_block(&proposer);
    b
}

async fn flush_persist(ap: &AsyncPersistence) {
    ap.request_flush();
    for _ in 0..500 {
        if ap.pending() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    ap.storage().flush().expect("storage flush");
}

#[tokio::test]
async fn w6_a2_1_evm_settled_survives_persistence_restore_reorg_and_archive() {
    let dir = temp_dir("w6-a2-1");
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));
    let ap = AsyncPersistence::start(storage.clone());

    let chain = evm_adapter::effective_chain_id();
    let kp = falcon(0xD1);
    let sender = pq_of(&kp);
    let recipient = pq_of(&falcon(0xD2));
    let recipient2 = pq_of(&falcon(0xD3));

    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new(sender, FUNDS))
        .await;
    engine.update_account(AccountState::new(recipient, 0)).await;
    engine
        .update_account(AccountState::new(recipient2, 0))
        .await;

    let raw1 = evm_raw(&secp(0x6B), chain, 0, [0x22u8; 20], TRANSFER_WEI);
    let digest1 = evm_adapter::evm_intent_digest(&raw1);
    let tx1 = carrier_tx(&kp, &raw1, recipient, GAS_LIMIT);

    let height = 10u64;
    let b_h = simple_block(
        height,
        [0u8; 32],
        engine.get_state_root().await,
        vec![tx1.clone()],
    );
    let bh_h = b_h.compute_hash();
    let out = engine.apply_block_transition(&b_h, 0).await;
    assert_eq!(out.status, vec![true], "carrier tx must commit");
    assert!(
        engine.evm_intent_is_settled(&digest1).await,
        "committed carrier must mark evm_intent_is_settled"
    );

    let root_h10 = engine.get_state_root().await;

    // Persist block H, anchor block H+1 (commits to post-H root), and snapshot at H via AsyncPersistence.
    ap.enqueue_block(b_h);
    let anchor_blk = simple_block(height + 1, bh_h, root_h10, vec![]);
    let anchor_hash = anchor_blk.compute_hash();
    ap.enqueue_block(anchor_blk);
    ap.enqueue_finalized(height + 1, anchor_hash);
    ap.snapshot_state(&engine, height).await;
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    ap.snapshot_domains(&engine, &staking, &gov, height).await;
    flush_persist(&ap).await;

    // 1. Restart / load_full_state_into must verify root and preserve evm_intent_is_settled.
    let restored = InMemoryStateEngine::new();
    let (loaded_h, _, _) = load_full_state_into(&storage, &restored)
        .await
        .expect("load_full_state_into must verify root")
        .expect("paired snapshot present");
    assert_eq!(loaded_h, height);
    assert_eq!(restored.get_state_root().await, root_h10);
    assert!(
        restored.evm_intent_is_settled(&digest1).await,
        "evm_intent_is_settled must remain true after load_full_state_into"
    );
    let replay_out = restored
        .apply_block_transition(&simple_block(height + 1, bh_h, root_h10, vec![tx1]), 0)
        .await;
    assert_eq!(
        replay_out.status,
        vec![false],
        "replaying settled EVM intent after restore must be refused"
    );

    // 2. Archive rebuild_historical_trie at H=10 must restore evm_settled and pass root verification.
    let (_archive_trie, archive_root) = storage
        .rebuild_historical_trie(height, height + 1)
        .await
        .expect("rebuild_historical_trie must verify with evm_settled_state");
    assert_eq!(archive_root, root_h10);

    // 3. Reorg via restore_snapshot + restore_evm_settled must keep S's nullifiers and drop post-S ones.
    let snap_s = engine.create_snapshot().await;
    let settled_s = engine.evm_settled_snapshot().await;
    let evm_bindings_s = engine.evm_bindings_snapshot().await;

    let kp2 = falcon(0xD4);
    let sender2 = pq_of(&kp2);
    engine
        .update_account(AccountState::new(sender2, FUNDS))
        .await;
    let raw2 = evm_raw(&secp(0x6C), chain, 0, [0x33u8; 20], TRANSFER_WEI);
    let digest2 = evm_adapter::evm_intent_digest(&raw2);
    let tx2 = carrier_tx(&kp2, &raw2, recipient2, GAS_LIMIT);
    let out2 = engine
        .apply_block_transition(&simple_block(height + 1, bh_h, root_h10, vec![tx2]), 0)
        .await;
    assert_eq!(out2.status, vec![true]);
    assert!(engine.evm_intent_is_settled(&digest2).await);

    engine
        .restore_snapshot(&snap_s)
        .await
        .expect("reorg restore_snapshot");
    engine
        .restore_evm_bindings(&evm_bindings_s)
        .await
        .expect("reorg restore_evm_bindings");
    engine
        .restore_evm_settled(&settled_s)
        .await
        .expect("reorg restore_evm_settled");
    assert!(
        engine.evm_intent_is_settled(&digest1).await,
        "S's settled nullifier must survive reorg restore"
    );
    assert!(
        !engine.evm_intent_is_settled(&digest2).await,
        "post-S settled nullifier must be cleared on reorg restore"
    );
    assert_eq!(engine.get_state_root().await, root_h10);

    drop(ap);
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn w6_a2_2_snapv4_apply_to_engine_restores_pq_registry() {
    let src = InMemoryStateEngine::new();
    let kp = falcon(0x41);
    let val_id = [0x41u8; 32];
    let pk = kp.public_key().to_vec();

    let mut reg = PqRegistry::new();
    reg.register(val_id, PqScheme::Falcon512, pk.clone(), 0, 0, true)
        .expect("register validator key");
    src.restore_pq_registry_state(reg.clone()).await;

    let snap_v4 = SnapStateV4::capture_from_engine(&src, None, None, None)
        .await
        .expect("capture SnapStateV4");
    assert!(!snap_v4.pq_registry.is_empty());

    let expected_root = snap_v4.compute_state_root().await.expect("compute root");
    let target = InMemoryStateEngine::new();
    snap_v4
        .apply_to_engine(&target)
        .await
        .expect("apply_to_engine");

    assert_eq!(target.pq_registry_read().await.records(), reg.records());
    assert_eq!(
        target.get_state_root().await,
        expected_root,
        "target engine root after apply_to_engine must match SnapStateV4::compute_state_root"
    );

    // Applying an empty-pq_registry SnapStateV4 over a dirty engine clears pq_registry.
    let empty_v4 = SnapStateV4::default();
    empty_v4
        .apply_to_engine(&target)
        .await
        .expect("apply empty SnapStateV4");
    assert!(
        target.pq_registry_read().await.is_empty(),
        "apply_to_engine must clear stale pq_registry when snapshot pq_registry is empty"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry serialized across node_sync tests.
async fn w6_a2_3_try_snapshot_sync_persists_before_advancing_safety() {
    let _lock = node_policy::test_support::global_lock();
    const BOUNDARY: u64 = 50;
    const TIP: u64 = 55;

    let ks: Vec<SigningKey> = (0..4)
        .map(|i| SigningKey::from_bytes(&[0x70 + i; 32]))
        .collect();
    let fks: Vec<FalconKeypair> = ks
        .iter()
        .map(|k| FalconKeypair::generate_from_seed(k.to_bytes()[0]))
        .collect();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let bond = required_bond_floor_nano();
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), bond))
            .collect(),
    );

    let producer_engine = Arc::new(InMemoryStateEngine::new());
    {
        let mut ledger = producer_engine.staking_write().await;
        let mut pq_reg = producer_engine.pq_registry_write().await;
        for (k, fk) in ks.iter().zip(fks.iter()) {
            let id = k.verifying_key().to_bytes();
            ledger.bond(id, bond, 0).expect("bond");
            ledger
                .validator_pq_keys
                .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
            let _ =
                pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
        }
        stellereum::consensus::sync_committed_pq_registry(&pq_reg, true);
    }
    let mut producer_rt =
        ValidatorRuntime::new(ks[0].clone(), vs.clone(), producer_engine.clone(), 1);

    let net_dir = temp_dir("w6-a2-3-net");
    let cfg = infnode::config::NodeConfig {
        name: "w7-sync-test".to_string(),
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
        net_dir.clone(),
        std::path::PathBuf::new(),
    )
    .await
    .expect("create infnode");
    let adapter = Arc::new(P2pNetworkAdapter::new(node));
    adapter.set_epoch(EpochTag::from_genesis(&[0x55u8; 32]));

    let prod_store_dir = temp_dir("w6-a2-3-prod");
    let prod_storage = Arc::new(Storage::open(&prod_store_dir).expect("open producer store"));
    let prod_persist = Arc::new(AsyncPersistence::start(prod_storage.clone()));

    let mut prev = [0u8; 32];
    let mut boundary_root = [0u8; 32];
    let mut boundary_hash = [0u8; 32];
    for h in 1..=TIP {
        let root = producer_rt.state.get_state_root().await;
        let proposer_id = vs.proposer_for(h, 0).expect("proposer");
        let proposer_idx = ks
            .iter()
            .position(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer idx");
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
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
        let mut vset_votes = VoteSet::new();
        for (k, fk) in ks.iter().zip(fks.iter()) {
            let v = Vote::sign_with_falcon(k, fk, h, 0, VoteKind::Precommit, Some(bh));
            vset_votes
                .add(v, &vs, h, 0, VoteKind::Precommit)
                .expect("vote");
        }
        b.precommit_qc = vset_votes.certificate_with_parent(Some(bh), &vs, Some(&prev));
        producer_rt.apply_and_advance(bh, &b).await;
        prod_storage.put_block(&b).expect("put block");

        if h == BOUNDARY {
            boundary_hash = bh;
            boundary_root = producer_rt.state.get_state_root().await;
            let state_bytes = producer_rt.state.create_snapshot().await;
            let staking = producer_rt.state.staking_read().await.clone();
            let gov = producer_rt.state.governance_read().await.clone();
            let domains = DomainSnapshot::capture(&producer_rt.state, &staking, &gov).await;
            let domains_bytes = bincode::serialize(&domains).expect("serialize domains");
            let pq_reg_bytes = producer_rt.state.pq_registry_snapshot().await;
            assert!(
                adapter
                    .persist_domain_snapshot(MASTERCHAIN_SHARD, BOUNDARY, "domains", &domains_bytes)
                    .await
            );
            if !pq_reg_bytes.is_empty() {
                assert!(
                    adapter
                        .persist_domain_snapshot(
                            MASTERCHAIN_SHARD,
                            BOUNDARY,
                            "pq_registry",
                            &pq_reg_bytes
                        )
                        .await
                );
            }
            assert!(
                adapter
                    .persist_state_snapshot(MASTERCHAIN_SHARD, BOUNDARY, &state_bytes)
                    .await
            );
        }
        prev = bh;
    }
    prod_storage.flush().expect("flush prod");

    let mut published_upto = 0u64;
    node_sync::retro_publish_pass(
        adapter.clone(),
        &producer_rt,
        Some(&prod_persist),
        &mut published_upto,
        None,
    )
    .await;

    // Lagging validator with durable storage + durable SafetyAuthority.
    let lag_dir = temp_dir("w6-a2-3-lag");
    let lag_storage = Arc::new(Storage::open(&lag_dir).expect("open lagging storage"));
    let lag_persist = Arc::new(AsyncPersistence::start(lag_storage.clone()));
    let safety_id = SafetyRecordIdentity {
        validator: ks[0].verifying_key().to_bytes(),
        chain: [0x55u8; 32],
        shard: MASTERCHAIN_SHARD,
    };
    let safety = SafetyAuthority::open_from_storage(
        lag_storage.clone(),
        safety_id.clone(),
        SafetyBootContext {
            is_validator: true,
            is_observer_env: false,
            new_chain_explicit: true,
            restored_finalized: None,
            restored_state_height: None,
            restored_finalized_qc_verified: false,
            legacy_checkpoint: None,
            legacy_watermark: None,
        },
    );
    let lag_engine = Arc::new(InMemoryStateEngine::new());
    let mut lag_rt =
        ValidatorRuntime::new(ks[0].clone(), vs, lag_engine, 1).with_safety_authority(safety);

    let synced = node_sync::try_snapshot_sync_with_persistence(
        &adapter,
        &mut lag_rt,
        MASTERCHAIN_SHARD,
        TIP,
        Some(&lag_persist),
    )
    .await;
    assert_eq!(synced, Some(BOUNDARY));

    // Immediately verify durable disk state without any additional flush!
    assert_eq!(
        lag_storage.finalized().expect("finalized"),
        Some((BOUNDARY, boundary_hash)),
        "finalized pointer must be durable immediately upon try_snapshot_sync return"
    );
    assert!(
        lag_storage
            .get_block(&boundary_hash)
            .expect("get_block")
            .is_some(),
        "boundary block must be persisted"
    );
    assert!(
        lag_storage
            .get_state(BOUNDARY)
            .expect("get_state")
            .is_some(),
        "state snapshot must be persisted at boundary"
    );
    assert!(
        lag_storage
            .domain_at(BOUNDARY)
            .expect("domain_at")
            .is_some(),
        "domains snapshot must be persisted at boundary"
    );

    // Simulate crash & reboot into fresh engine/storage from `lag_dir`.
    drop(lag_rt);
    drop(lag_persist);
    drop(lag_storage);

    let mut reopened_opt = None;
    for _ in 0..40 {
        if let Ok(st) = Storage::open(&lag_dir) {
            reopened_opt = Some(st);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let reopened = reopened_opt.expect("reopen storage");
    let recovered_engine = InMemoryStateEngine::new();
    let (loaded_h, _, _) = load_full_state_into(&reopened, &recovered_engine)
        .await
        .expect("load_full_state_into after snapshot sync")
        .expect("paired snapshot exists on disk");
    assert_eq!(loaded_h, BOUNDARY);
    assert_eq!(recovered_engine.get_state_root().await, boundary_root);
    let rec = reopened
        .safety_record_store(safety_id)
        .expect("safety store")
        .load()
        .expect("load safety")
        .expect("safety record present");
    let safety_state = stellereum::safety::SafetyRecordPayload::decode_canonical(&rec.payload)
        .expect("decode safety payload");
    assert_eq!(safety_state.height, BOUNDARY + 1);
    assert_eq!(safety_state.finalized_height, BOUNDARY);

    drop(prod_persist);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = std::fs::remove_dir_all(&net_dir);
    let _ = std::fs::remove_dir_all(&prod_store_dir);
    let _ = std::fs::remove_dir_all(&lag_dir);
}

#[test]
fn w6_a2_5_prune_state_below_preserves_newest_paired_height() {
    let dir = temp_dir("w6-a2-5");
    let st = Storage::open(&dir).expect("open storage");

    // Paired snapshots at 100 and 200; unpaired state@300 (domains@300 has not landed yet).
    st.put_state(100, b"state-100").unwrap();
    st.put_domains(100, b"dom-100").unwrap();
    st.put_state(200, b"state-200").unwrap();
    st.put_domains(200, b"dom-200").unwrap();
    st.put_state(300, b"state-300").unwrap();

    // Prune below 250 (and even below 400): state@100 is pruned, state@200 (newest paired)
    // and state@300 (newest state) MUST both survive!
    let pruned = st.prune_state_below(250).unwrap();
    assert_eq!(pruned, 1, "only state@100 should be pruned");
    assert!(st.get_state(100).unwrap().is_none());
    assert!(
        st.get_state(200).unwrap().is_some(),
        "newest paired state@200 must survive while domains@300 has not landed"
    );
    assert!(st.get_state(300).unwrap().is_some());
    assert_eq!(
        st.latest_paired_snapshot().unwrap().map(|(h, _)| h),
        Some(200),
        "latest_paired_snapshot must remain available"
    );

    // Symmetric check: unpaired domains@400 while state@400 has not landed yet.
    st.put_domains(400, b"dom-400").unwrap();
    let pruned_dom = st.prune_domains_below(350).unwrap();
    assert_eq!(pruned_dom, 1, "only domains@100 should be pruned");
    assert!(st.domain_at(100).unwrap().is_none());
    assert!(
        st.domain_at(200).unwrap().is_some(),
        "newest paired domains@200 must survive while state@400 has not landed"
    );
    assert!(st.domain_at(400).unwrap().is_some());

    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn w6_a2_6_mint_native_after_get_state_root_moves_root() {
    let engine = InMemoryStateEngine::new();
    let addr = [0xAAu8; 32];
    engine.update_account(AccountState::new(addr, 0)).await;

    // Cache the commitment digest via get_state_root().
    let r0 = engine.get_state_root().await;

    // Mint native balance: reserve_mint_nano bumps commitment_generation.
    engine.mint_native(&addr, 1_000).await.expect("mint_native");
    let r1 = engine.get_state_root().await;
    assert_ne!(r1, r0, "mint_native must move get_state_root()");

    // Compare against an engine with identical account balance (1_000) but total_minted_nano == 0
    // (via update_account): roots MUST differ because total_minted_nano is folded into the digest!
    let unminted = InMemoryStateEngine::new();
    unminted
        .update_account(AccountState::new(addr, 1_000))
        .await;
    let r_unminted = unminted.get_state_root().await;
    assert_ne!(
        r1, r_unminted,
        "get_state_root() after mint_native must reflect updated total_minted_nano in commitment digest"
    );

    // And a second fresh engine that also calls mint_native produces the identical root.
    let engine2 = InMemoryStateEngine::new();
    engine2.update_account(AccountState::new(addr, 0)).await;
    let _ = engine2.get_state_root().await;
    engine2
        .mint_native(&addr, 1_000)
        .await
        .expect("mint_native 2");
    assert_eq!(engine2.get_state_root().await, r1);
}

#[test]
fn w6_a2_7_prune_receipts_below_deletes_indexes_before_bodies() {
    let dir = temp_dir("w6-a2-7");
    let st = Storage::open(&dir).expect("open storage");

    let kp = SigningKey::from_bytes(&[0x11u8; 32]);
    let from = kp.verifying_key().to_bytes();
    let mut tx_hashes = Vec::new();
    for h in 1..=20u64 {
        let tx = Transaction::sign(&kp, from, 10, 100, h, 0, 0);
        let bh = [h as u8; 32];
        tx_hashes.push((h, tx.compute_tx_hash()));
        st.put_receipts_for_block(h, &bh, &[tx], &[true], &[50])
            .expect("put_receipts_for_block");
    }

    let removed = st.prune_receipts_below(11).expect("prune_receipts_below");
    assert_eq!(removed, 10);
    assert_eq!(st.receipt_count().unwrap(), 10);
    assert_eq!(st.receipts_by_height_tree_for_test().len(), 10);

    for (h, tx_hash) in &tx_hashes {
        if *h < 11 {
            assert!(st.get_receipt(tx_hash).unwrap().is_none());
            assert!(
                st.receipt_meta(tx_hash).unwrap().is_none(),
                "receipt_meta_v2 row at height {h} must be pruned"
            );
        } else {
            assert!(st.get_receipt(tx_hash).unwrap().is_some());
            assert!(st.receipt_meta(tx_hash).unwrap().is_some());
        }
    }

    // Simulate mid-prune crash where index rows for h=11 were already deleted while body survived:
    // re-running prune_receipts_below(15) must cleanly remove h=11..=14 across all trees.
    let r11 = st.get_receipt(&tx_hashes[10].1).unwrap().unwrap();
    let mut idx11 = Vec::with_capacity(44);
    idx11.extend_from_slice(&r11.height.to_be_bytes());
    idx11.extend_from_slice(&r11.index.to_be_bytes());
    idx11.extend_from_slice(&r11.tx_hash);
    st.receipts_by_height_tree_for_test().remove(idx11).unwrap();

    let removed2 = st.prune_receipts_below(15).expect("idempotent re-prune");
    assert_eq!(removed2, 4);
    assert_eq!(st.receipt_count().unwrap(), 6);
    assert_eq!(st.receipts_by_height_tree_for_test().len(), 6);
    for (h, tx_hash) in &tx_hashes {
        if *h < 15 {
            assert!(st.receipt_meta(tx_hash).unwrap().is_none());
        } else {
            assert!(st.receipt_meta(tx_hash).unwrap().is_some());
        }
    }

    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}
