//! Integration tests for R2-D:
//! - `BlockHeaderRecordV2` + `HistoricalRoot` v4 boundary `H - 1 / H / H + 1` + `HeaderLink` forgery rejection
//! - `Storage` `"evm_bindings_state"` fail-closed restore + `"evm_bindings"` index surviving 50k+ prune
//! - `SNAP-MANIFEST-DOS` bounds (`MAX_BLOB_CHUNKS`, missing chunk `hash`, `> 512 MiB`) + `SNAP-DHT-NAME`
//! - `SNAP-PQKEYS` + `"evm_bindings"` in `SNAPSHOT_PUBLISH_DOMAIN_KINDS` / `SYNC_DOMAIN_KINDS` / `DomainUnitId`
//! - `SNAP-TIP-SKIP` via `finalized_post_root_at`
//! - `SnapV4` `safety_record_v1` / `ConsensusCheckpoint` / `VoteWatermark` isolation + `corrupted_delta_rejected`

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    consensus_chain_id, register_validator_pq_key, FalconKeypair, QuorumCertificate, ValidatorSet,
    Vote, VoteKind, VoteSet,
};
use stellereum::network::{
    parse_and_validate_snapshot_manifest, snapv4_manifest_name, EpochTag, BLOB_CHUNK_BYTES,
    MAX_BLOB_BYTES, MAX_BLOB_CHUNKS, SNAPSHOT_PUBLISH_DOMAIN_KINDS,
};
use stellereum::post_quantum::PqScheme;
use stellereum::sharding::{
    set_header_commit_activation_override, Block, Transaction, MASTERCHAIN_SHARD,
};
use stellereum::snapshot_v4::{
    build_base_snapshot, build_delta_snapshot, encode_canonical, sign_manifest, verify_unit_chunk,
    DomainUnitId, SnapStateV4, SnapshotBuildParams, TrustedSnapshotAnchor, N_DOMAIN_UNITS,
    TOTAL_UNIT_TAGS, UNIT_ENC_DELTA,
};
use stellereum::staking::required_bond_floor_nano;
use stellereum::state_engine::{
    set_evm_bindings_state_activation_override, AccountState, InMemoryStateEngine,
};
use stellereum::storage::{
    load_full_state_into, BlockHeaderRecordV2, ConsensusCheckpoint, DomainSnapshot,
    SafetyRecordIdentity, Storage, VoteWatermark, VoteWatermarkEntry,
};
use stellereum::sync::{
    fast_sync_snapv4_base, fast_sync_snapv4_incremental, fast_sync_state,
    fetch_verified_snapv4_chunks, verify_snapshot_anchor, verify_snapshot_anchor_tail, HeaderLink,
    SYNC_DOMAIN_KINDS,
};

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("stell-r2d-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct HeaderGateGuard;
impl HeaderGateGuard {
    fn set(h: u64) -> Self {
        set_header_commit_activation_override(Some(h));
        Self
    }
}
impl Drop for HeaderGateGuard {
    fn drop(&mut self) {
        set_header_commit_activation_override(None);
    }
}

struct EvmBindingsGateGuard;
impl EvmBindingsGateGuard {
    fn set(h: u64) -> Self {
        set_evm_bindings_state_activation_override(Some(h));
        Self
    }
}
impl Drop for EvmBindingsGateGuard {
    fn drop(&mut self) {
        set_evm_bindings_state_activation_override(None);
    }
}

fn make_validator() -> (SigningKey, FalconKeypair, ValidatorSet) {
    let seed = *blake3::hash(b"r2d_val_seed").as_bytes();
    let sk = SigningKey::from_bytes(&seed);
    let fk = FalconKeypair::generate_from_seed_bytes(&seed);
    let id = sk.verifying_key().to_bytes();
    register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key().to_vec());
    register_validator_pq_key(
        fk.validator_id(),
        PqScheme::Falcon512,
        fk.public_key().to_vec(),
    );
    let vs = ValidatorSet::from_list(vec![(id, 1)]);
    (sk, fk, vs)
}

fn sign_qc(
    height: u64,
    round: u32,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    sk: &SigningKey,
    fk: &FalconKeypair,
    vs: &ValidatorSet,
) -> QuorumCertificate {
    let mut set = VoteSet::new();
    let vote = Vote::sign_with_falcon(sk, fk, height, round, VoteKind::Precommit, Some(block_hash));
    set.add(vote, vs, height, round, VoteKind::Precommit)
        .expect("vote ingest");
    set.certificate_with_parent(Some(block_hash), vs, Some(&parent_hash))
        .expect("certificate")
}

fn make_block(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    sk: &SigningKey,
    fk: &FalconKeypair,
    vs: &ValidatorSet,
) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: Vec::new(),
        cross_shard_out: Vec::new(),
        timestamp: 1_700_000_000 + height,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: Vec::new(),
        shard_headers: Vec::new(),
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    };
    b.sign_block(sk);
    let bh = b.compute_hash();
    b.validator_signatures
        .push((fk.validator_id(), fk.sign(&bh)));
    b.precommit_qc = Some(sign_qc(height, 0, bh, prev_hash, sk, fk, vs));
    b
}

#[tokio::test]
async fn block_header_v2_and_historical_root_boundary_and_forged_link_rejected() {
    const H: u64 = 10;
    let _gate = HeaderGateGuard::set(H);
    let (sk, fk, vs) = make_validator();

    let dir = temp_dir("hdr_v2_boundary");
    let st = Storage::open(&dir).expect("open storage");

    let mut blocks = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..=12u64 {
        let root = [(h as u8).wrapping_add(0x10); 32];
        let b = make_block(h, prev, root, &sk, &fk, &vs);
        prev = b.compute_hash();
        st.put_block(&b).expect("put_block");
        blocks.push(b);
    }

    // H-1 (9), H (10), H+1 (11): BlockHeaderRecordV2 persisted & verified.
    for h in [H - 1, H, H + 1] {
        let v2 = st.header_v2_at(h).expect("header_v2_at").expect("present");
        assert_eq!(v2.header.height, h);
        assert_eq!(v2.block_hash, blocks[h as usize].compute_hash());
        if h >= H {
            assert_eq!(v2.header.compute_hash(), v2.block_hash);
        }
    }
    let latest = st.latest_header_v2().expect("latest").expect("present");
    assert_eq!(latest.header.height, 12);

    // HistoricalRoot at H-1 (anchored by H >= H): v4 fields populated and verified.
    let hr_pre = st.historical_root(H - 1, 12).expect("historical_root H-1");
    assert_eq!(hr_pre.anchor_height, H);
    assert!(hr_pre.anchor_body_commitment.is_some());
    assert_eq!(hr_pre.anchor_proposer, blocks[H as usize].proposer);

    // HistoricalRoot at H (anchored by H+1 >= H): v4 fields populated and verified.
    let hr_at = st.historical_root(H, 12).expect("historical_root H");
    assert_eq!(hr_at.anchor_height, H + 1);
    assert!(hr_at.anchor_body_commitment.is_some());

    // HistoricalRoot at H-2 (anchored by H-1 < H): legacy v3 anchor works with body_commitment = None.
    let hr_legacy = st.historical_root(H - 2, 12).expect("historical_root H-2");
    assert_eq!(hr_legacy.anchor_height, H - 1);
    assert_eq!(hr_legacy.anchor_body_commitment, None);

    // Genuine HeaderLink chain across H-1, H, H+1 passes anchor verification.
    let links: HashMap<u64, HeaderLink> = blocks
        .iter()
        .map(|b| (b.height, HeaderLink::from_block(b).expect("qc")))
        .collect();
    let genuine = verify_snapshot_anchor(
        Some((8, blocks[8].compute_hash())),
        [0u8; 32],
        11,
        &vs,
        100,
        |h| {
            let l = links.get(&h).cloned();
            async move { l }
        },
    )
    .await
    .expect("genuine chain across H-1/H/H+1 must verify");
    assert_eq!(genuine.state_root, blocks[11].state_root);

    // ATTACK 1: Forge `state_root` in HeaderLink at H (keeping valid QC over real block_hash).
    let mut forged_root_links = links.clone();
    let mut forged_at_h = forged_root_links.get(&H).cloned().unwrap();
    forged_at_h.state_root[0] ^= 0xFF;
    forged_root_links.insert(H, forged_at_h);
    let err_root = verify_snapshot_anchor(
        Some((8, blocks[8].compute_hash())),
        [0u8; 32],
        11,
        &vs,
        100,
        |h| {
            let l = forged_root_links.get(&h).cloned();
            async move { l }
        },
    )
    .await
    .expect_err("forged state_root with valid QC at >= H must be rejected");
    assert!(
        err_root.contains("compute_hash") || err_root.contains("mismatch"),
        "unexpected error: {err_root}"
    );

    // ATTACK 2: Forge `prev_hash` in HeaderLink at H+1 (keeping valid QC over real block_hash)
    // in tail-anchor mode at the oldest window height (where no parent exists to compare).
    let mut forged_prev_links = links.clone();
    let forged_at_9 = forged_prev_links.get(&9).cloned().unwrap();
    // Test at H (10) as oldest in tail window [10..=12]: forge prev_hash at 10 while keeping valid QC!
    let mut forged_at_10 = forged_prev_links.get(&10).cloned().unwrap();
    forged_at_10.prev_hash[0] ^= 0xAA;
    forged_prev_links.insert(10, forged_at_10);
    let err_prev = verify_snapshot_anchor_tail(12, &vs, |h| {
        let l = forged_prev_links.get(&h).cloned();
        async move { l }
    })
    .await
    .expect_err("forged prev_hash with valid QC at >= H must be rejected");
    assert!(
        err_prev.contains("compute_hash") || err_prev.contains("mismatch"),
        "unexpected error: {err_prev}"
    );
    let _ = forged_at_9;

    // ATTACK 3: Missing `body_commitment` at >= H rejected fail-closed.
    let mut missing_bc_links = links;
    let mut no_bc = missing_bc_links.get(&H).cloned().unwrap();
    no_bc.body_commitment = None;
    missing_bc_links.insert(H, no_bc);
    let err_bc = verify_snapshot_anchor(
        Some((8, blocks[8].compute_hash())),
        [0u8; 32],
        11,
        &vs,
        100,
        |h| {
            let l = missing_bc_links.get(&h).cloned();
            async move { l }
        },
    )
    .await
    .expect_err("missing body_commitment at >= H must fail closed");
    assert!(err_bc.contains("body_commitment"), "err={err_bc}");

    // Corrupt `headers_v2` at anchor height H+1 -> `header_v2_at` & `historical_root` fail closed.
    let mut bad_v2 = BlockHeaderRecordV2::of(&blocks[11]);
    bad_v2.header.state_root[0] ^= 0x55;
    st.put_header_v2(&bad_v2).expect("put tampered v2");
    assert!(
        st.header_v2_at(11).is_err(),
        "corrupted header_v2 must fail compute_hash check"
    );
    assert!(
        st.historical_root(10, 12).is_err(),
        "historical_root must fail closed when header_v2 fails compute_hash"
    );

    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn evm_bindings_state_fail_closed_and_index_survives_50k_prune() {
    let _gate = EvmBindingsGateGuard::set(1);
    let (sk, fk, vs) = make_validator();

    let dir = temp_dir("evm_bindings_storage");
    let st = Storage::open(&dir).expect("open");

    let source = InMemoryStateEngine::new();
    let pq_addr = [0x42u8; 32];
    let evm_addr = [0xE1u8; 20];
    source
        .update_account(AccountState::new(pq_addr, 1_000_000))
        .await;
    assert!(source
        .evm_bindings_write()
        .await
        .bind(evm_addr, pq_addr)
        .expect("bind"));
    source.sync_aux_trie().await;

    let snap_height = 10u64;
    let post_root = source.get_state_root().await;

    // Persist paired state + domains + evm_bindings_state at height 10,
    // and anchoring block at height 11.
    let state_bytes = source.create_snapshot().await;
    let staking = source.staking_read().await.clone();
    let gov = source.governance_read().await.clone();
    let dom = DomainSnapshot::capture(&source, &staking, &gov).await;
    let dom_bytes = bincode::serialize(&dom).expect("dom serialize");
    let evm_bytes = source.evm_bindings_snapshot().await;
    assert!(!evm_bytes.is_empty());

    st.put_state(snap_height, &state_bytes).unwrap();
    st.put_domains(snap_height, &dom_bytes).unwrap();
    st.put_evm_bindings_state(snap_height, &evm_bytes).unwrap();

    let anchor = make_block(11, [0x01; 32], post_root, &sk, &fk, &vs);
    st.put_block(&anchor).unwrap();
    st.set_finalized(11, &anchor.compute_hash()).unwrap();

    // Happy path: load_full_state_into restores EvmBindingsState and passes verify_restored_root.
    let restored = InMemoryStateEngine::new();
    let (loaded_h, _, _) = load_full_state_into(&st, &restored)
        .await
        .expect("load_full_state_into")
        .expect("some");
    assert_eq!(loaded_h, snap_height);
    assert_eq!(restored.get_state_root().await, post_root);
    assert_eq!(
        restored.evm_bindings_read().await.get_pq(&evm_addr),
        Some(pq_addr)
    );

    // Corruption path: bad bytes in evm_bindings_state -> fail closed!
    st.put_evm_bindings_state(snap_height, &[0xFF, 0x00, 0xAB])
        .unwrap();
    let victim = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&st, &victim).await.is_err(),
        "corrupted evm_bindings_state must fail closed"
    );

    // Missing path: empty evm_bindings_state when root commits to non-empty bindings -> root mismatch!
    st.put_evm_bindings_state(snap_height, &[]).unwrap();
    let victim2 = InMemoryStateEngine::new();
    let err = load_full_state_into(&st, &victim2)
        .await
        .expect_err("missing evm_bindings_state must fail verify_restored_root");
    assert!(
        err.to_string().contains("mismatch"),
        "expected root mismatch, got: {err}"
    );

    // Non-consensus crash-safe index "evm_bindings":
    // 1. Strict first-writer-wins (no overwrite on evm or pq conflict).
    assert!(st.put_evm_binding_if_absent(&evm_addr, &pq_addr).unwrap());
    assert!(
        !st.put_evm_binding_if_absent(&evm_addr, &pq_addr).unwrap(),
        "idempotent re-insert returns Ok(false)"
    );
    assert!(
        st.put_evm_binding_if_absent(&evm_addr, &[0x99u8; 32])
            .is_err(),
        "conflicting pq for same evm must be rejected"
    );
    assert!(
        st.put_evm_binding_if_absent(&[0x99u8; 20], &pq_addr)
            .is_err(),
        "conflicting evm for same pq must be rejected"
    );
    st.set_evm_bindings_cursor(1).unwrap();

    // 2. Insert blocks and receipts across 55_000+ height range and prune below 50_000:
    // "evm_bindings" must NEVER be pruned!
    let b1 = make_block(1, [0u8; 32], [0u8; 32], &sk, &fk, &vs);
    let h1 = st.put_block(&b1).unwrap();
    let tx1 = Transaction::sign(&sk, [0x22; 32], 100, 21_000, 0, 0, 0);
    st.put_receipts_for_block(1, &h1, &[tx1], &[true], &[21_000])
        .unwrap();

    let b_hi = make_block(55_000, [0x55; 32], [0u8; 32], &sk, &fk, &vs);
    let h_hi = st.put_block(&b_hi).unwrap();
    let tx_hi = Transaction::sign(&sk, [0x33; 32], 100, 21_000, 1, 0, 0);
    st.put_receipts_for_block(55_000, &h_hi, &[tx_hi], &[true], &[21_000])
        .unwrap();

    // Blocks at heights 11 (anchor above) and 1 are below 50_000 -> both pruned.
    assert_eq!(st.prune_blocks_below(50_000).unwrap(), 2);
    assert_eq!(st.prune_receipts_below(50_000).unwrap(), 1);

    // Binding from height 1 and cursor survive 50k+ block/receipt pruning!
    assert_eq!(st.evm_binding_by_evm(&evm_addr).unwrap(), Some(pq_addr));
    assert_eq!(st.evm_binding_by_pq(&pq_addr).unwrap(), Some(evm_addr));
    assert_eq!(st.evm_bindings_cursor().unwrap(), Some(1));
    assert_eq!(st.iter_evm_bindings().unwrap(), vec![(evm_addr, pq_addr)]);

    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn snap_manifest_dos_limits_and_content_addressed_dht_name() {
    let valid_hash = "ab".repeat(32);

    // 1. n_chunks > MAX_BLOB_CHUNKS (4096) rejected before allocating chunk slots.
    let too_many_chunks: Vec<serde_json::Value> = (0..=MAX_BLOB_CHUNKS)
        .map(|i| {
            serde_json::json!({
                "id": format!("c{i}"),
                "hash": valid_hash,
                "off": i * 1024,
                "len": 1024,
            })
        })
        .collect();
    let m_many = serde_json::json!({
        "size": (MAX_BLOB_CHUNKS + 1) * 1024,
        "nonce": "00112233445566778899aabb",
        "key": "11".repeat(32),
        "chunks": too_many_chunks,
    })
    .to_string();
    assert!(
        parse_and_validate_snapshot_manifest(&m_many).is_err(),
        "manifest with n_chunks > MAX_BLOB_CHUNKS must be rejected"
    );

    // 2. Missing chunk hash rejected (c["hash"] mandatory).
    let m_no_hash = serde_json::json!({
        "size": 1024,
        "nonce": "00112233445566778899aabb",
        "key": "11".repeat(32),
        "chunks": [
            { "id": "c0", "off": 0, "len": 1024 }
        ],
    })
    .to_string();
    let err_no_hash =
        parse_and_validate_snapshot_manifest(&m_no_hash).expect_err("missing chunk hash must fail");
    assert!(err_no_hash.contains("hash"), "err={err_no_hash}");

    // 3. Declared size > 512 MiB (MAX_BLOB_BYTES) rejected.
    let m_oversize = serde_json::json!({
        "size": (MAX_BLOB_BYTES as u64) + 1,
        "nonce": "00112233445566778899aabb",
        "key": "11".repeat(32),
        "chunks": [
            { "id": "c0", "hash": valid_hash, "off": 0, "len": BLOB_CHUNK_BYTES }
        ],
    })
    .to_string();
    let err_oversize =
        parse_and_validate_snapshot_manifest(&m_oversize).expect_err(">512 MiB must fail");
    assert!(
        err_oversize.contains("MAX_BLOB_BYTES"),
        "err={err_oversize}"
    );

    // 4. Valid manifest accepted.
    let m_ok = serde_json::json!({
        "size": 1024,
        "nonce": "00112233445566778899aabb",
        "key": "11".repeat(32),
        "chunks": [
            { "id": "c0", "hash": valid_hash, "off": 0, "len": 1024 }
        ],
    })
    .to_string();
    let (metas, _, _, sz) = parse_and_validate_snapshot_manifest(&m_ok).expect("valid manifest");
    assert_eq!(metas.len(), 1);
    assert_eq!(sz, 1024);

    // 5. SNAP-DHT-NAME: distinct state_roots at the same (epoch, shard, height) yield distinct DHT names.
    let epoch = EpochTag::from_genesis(&[0x55; 32]);
    let n1 = snapv4_manifest_name(&epoch, 0, 500, &[0xAA; 32]);
    let n2 = snapv4_manifest_name(&epoch, 0, 500, &[0xBB; 32]);
    assert_ne!(n1, n2);
    assert!(n1.contains("_snapm_0_500_"));
}

#[tokio::test]
async fn snapshot_publish_kinds_include_pq_keys_and_evm_bindings_and_fast_sync_restores() {
    assert!(SNAPSHOT_PUBLISH_DOMAIN_KINDS.contains(&"pq_keys"));
    assert!(SNAPSHOT_PUBLISH_DOMAIN_KINDS.contains(&"evm_bindings"));
    assert!(SYNC_DOMAIN_KINDS.contains(&"pq_keys"));
    assert!(SYNC_DOMAIN_KINDS.contains(&"evm_bindings"));
    assert_eq!(N_DOMAIN_UNITS, 16);
    assert_eq!(TOTAL_UNIT_TAGS, 272);
    assert_eq!(DomainUnitId::EvmBindings.tag(), 271);
    assert_eq!(DomainUnitId::from_tag(271), Some(DomainUnitId::EvmBindings));
    assert_eq!(DomainUnitId::EvmBindings.name(), "EvmBindings");

    let source = InMemoryStateEngine::new();
    let pq_addr = [0x71u8; 32];
    let evm_addr = [0xC3u8; 20];
    source
        .update_account(AccountState::new(pq_addr, 500_000))
        .await;
    assert!(source
        .evm_bindings_write()
        .await
        .bind(evm_addr, pq_addr)
        .unwrap());
    source.sync_aux_trie().await;
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;
    let staking = source.staking_read().await.clone();
    let gov = source.governance_read().await.clone();
    let dom = DomainSnapshot::capture(&source, &staking, &gov).await;
    let dom_bytes = bincode::serialize(&dom).unwrap();
    let evm_bytes = source.evm_bindings_snapshot().await;

    let target = InMemoryStateEngine::new();
    fast_sync_state(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind| {
            let d = dom_bytes.clone();
            let e = evm_bytes.clone();
            async move {
                match kind {
                    "domains" => Some(d),
                    "evm_bindings" => Some(e),
                    _ => None,
                }
            }
        },
    )
    .await
    .expect("fast_sync_state with evm_bindings must verify and restore");
    assert_eq!(target.get_state_root().await, root);
    assert_eq!(
        target.evm_bindings_read().await.get_pq(&evm_addr),
        Some(pq_addr)
    );

    // Without evm_bindings blob when domain is non-empty -> root mismatch fail-closed!
    let target_missing = InMemoryStateEngine::new();
    assert!(
        fast_sync_state(
            &target_missing,
            root,
            || async { Some(snap.clone()) },
            |kind| {
                let d = dom_bytes.clone();
                async move {
                    if kind == "domains" {
                        Some(d)
                    } else {
                        None
                    }
                }
            },
        )
        .await
        .is_err(),
        "missing non-empty evm_bindings must fail state_root check"
    );
}

#[tokio::test]
async fn snap_tip_skip_verifies_finalized_post_root_when_no_successor_exists() {
    let dir = temp_dir("tip_skip");
    let st = Storage::open(&dir).expect("open");

    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([0x22; 32], 123_456))
        .await;
    let tip_height = 50u64;
    let tip_root = engine.get_state_root().await;

    // Without finalized_post_root_v1 at tip (no height 51 block): legacy compat returns Ok(()).
    st.set_finalized(tip_height, &[0x11; 32]).unwrap();
    st.verify_restored_root(&engine, tip_height)
        .await
        .expect("legacy compat without finalized_post_root_v1");

    // With finalized_post_root_v1 recorded: genuine engine passes, tampered engine fails closed!
    st.put_finalized_post_root(tip_height, tip_root).unwrap();
    assert_eq!(
        st.finalized_post_root_at(tip_height).unwrap(),
        Some(tip_root)
    );
    st.verify_restored_root(&engine, tip_height)
        .await
        .expect("genuine tip state matches finalized_post_root_v1");

    let tampered = InMemoryStateEngine::new();
    tampered
        .update_account(AccountState::new([0x22; 32], 999_999))
        .await;
    let err = st
        .verify_restored_root(&tampered, tip_height)
        .await
        .expect_err(
            "SNAP-TIP-SKIP must reject tampered tip state when finalized_post_root_v1 is recorded",
        );
    assert!(
        err.to_string().contains("mismatch"),
        "expected mismatch error, got: {err}"
    );

    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn snapv4_preserves_safety_record_v1_and_rejects_corrupted_delta() {
    let seed = *blake3::hash(b"r2d_snapv4_val").as_bytes();
    let kp = FalconKeypair::generate_from_seed_bytes(&seed);
    register_validator_pq_key(
        kp.validator_id(),
        PqScheme::Falcon512,
        kp.public_key().to_vec(),
    );

    let source = InMemoryStateEngine::new();
    let addr = [0x15u8; 32];
    source.update_account(AccountState::new(addr, 10_000)).await;
    // Populate bucket 0x15 with enough unchanged accounts so a single-account
    // balance update stays well below the 70% full-unit fallback threshold and
    // encodes as `UNIT_ENC_DELTA`.
    for i in 1..=20u8 {
        let mut a = [0x15u8; 32];
        a[1] = i;
        source
            .update_account(AccountState::new(a, 5_000 + i as u64))
            .await;
    }
    let evm = [0xABu8; 20];
    assert!(source.evm_bindings_write().await.bind(evm, addr).unwrap());
    {
        let mut staking = source.staking_write().await;
        staking
            .bond(kp.validator_id(), required_bond_floor_nano(), 100)
            .expect("bond");
    }
    source.sync_aux_trie().await;
    let vset = source.staking_read().await.to_validator_set();
    let root_100 = source.get_state_root().await;
    let boundary_100 = *blake3::hash(b"b100").as_bytes();

    let state_100 = SnapStateV4::capture_from_engine(&source, None, None, None)
        .await
        .expect("capture 100");
    let params_100 = SnapshotBuildParams {
        chain_id: consensus_chain_id(),
        shard_id: MASTERCHAIN_SHARD,
        target_height: 100,
        target_block_hash: boundary_100,
        target_state_root: root_100,
        validator_set: &vset,
    };
    let enc_base = build_base_snapshot(&state_100, &params_100, &kp).expect("build base");
    let anchor_100 = TrustedSnapshotAnchor {
        chain_id: params_100.chain_id,
        shard_id: params_100.shard_id,
        target_height: 100,
        trusted_boundary_hash: boundary_100,
        trusted_state_root: root_100,
        validator_set: &vset,
    };

    // Build Delta at height 105 modifying balance and adding another EVM binding.
    let mut state_105 = state_100.clone();
    state_105.buckets[0x15][0].balance += 5_000;
    let addr2 = [0x16u8; 32];
    state_105.buckets[0x16].push(AccountState::new(addr2, 2_500));
    state_105.evm_bindings.by_evm.insert([0xCDu8; 20], addr2);
    let root_105 = state_105.compute_state_root().await.expect("root 105");
    let boundary_105 = *blake3::hash(b"b105").as_bytes();
    let params_105 = SnapshotBuildParams {
        chain_id: consensus_chain_id(),
        shard_id: MASTERCHAIN_SHARD,
        target_height: 105,
        target_block_hash: boundary_105,
        target_state_root: root_105,
        validator_set: &vset,
    };
    let enc_delta = build_delta_snapshot(&state_100, &state_105, 100, root_100, &params_105, &kp)
        .expect("build delta");
    let anchor_105 = TrustedSnapshotAnchor {
        chain_id: params_105.chain_id,
        shard_id: params_105.shard_id,
        target_height: 105,
        trusted_boundary_hash: boundary_105,
        trusted_state_root: root_105,
        validator_set: &vset,
    };

    // Initialize Storage with SafetyRecordStore + ConsensusCheckpoint + VoteWatermark.
    let dir = temp_dir("snapv4_safety");
    let st = Storage::open(&dir).expect("open");
    let identity = SafetyRecordIdentity {
        validator: kp.validator_id(),
        chain: [0x99; 32],
        shard: MASTERCHAIN_SHARD,
    };
    let safety = st.safety_record_store(identity.clone()).expect("safety");
    let mut rec = safety.persist(None, b"gen1".to_vec()).expect("gen1");
    for g in 2..=7u64 {
        rec = safety
            .persist(Some(g - 1), format!("gen{g}").into_bytes())
            .expect("advance gen");
    }
    assert_eq!(rec.generation, 7);

    let cp = ConsensusCheckpoint {
        height: 42,
        round: 3,
        locked_hash: Some([0x77; 32]),
        locked_round: 2,
        finalized_height: 41,
        finalized_hash: [0x66; 32],
    };
    st.set_consensus(&cp).unwrap();

    let mut wm = VoteWatermark::default();
    wm.note(VoteWatermarkEntry {
        height: 42,
        round: 3,
        kind: 1,
        target: Some([0x77; 32]),
        shard_id: MASTERCHAIN_SHARD,
    });
    st.set_vote_watermark(&wm).unwrap();

    // Sync Base into target_engine + storage.
    let target_engine = InMemoryStateEngine::new();
    let verified_chunks = fetch_verified_snapv4_chunks(&enc_base.manifest, |tag, sub, _| {
        let b = enc_base.chunks.get(&(tag, sub)).cloned();
        async move { b }
    })
    .await
    .expect("fetch verified base chunks");
    let (installed_100, _) = fast_sync_snapv4_base(
        &target_engine,
        &anchor_100,
        &enc_base.manifest,
        &verified_chunks,
        Some(&st),
    )
    .await
    .expect("fast_sync_snapv4_base");

    // Verify corrupted delta is REJECTED fail-closed before mutating target_engine!
    let mut bad_delta = enc_delta.clone();
    let delta_key = bad_delta
        .manifest
        .units
        .iter()
        .find(|d| d.encoding == UNIT_ENC_DELTA)
        .map(|d| (d.unit_tag, d.sub_index))
        .expect("at least one delta unit");
    if let Some(chunk) = bad_delta.chunks.get_mut(&delta_key) {
        chunk[0] ^= 0xFF;
    }
    let delta_desc = bad_delta
        .manifest
        .units
        .iter()
        .find(|d| (d.unit_tag, d.sub_index) == delta_key)
        .unwrap();
    assert!(
        verify_unit_chunk(delta_desc, bad_delta.chunks.get(&delta_key).unwrap()).is_err(),
        "corrupted delta chunk must fail verify_unit_chunk"
    );
    assert!(
        fast_sync_snapv4_incremental(
            &target_engine,
            &installed_100,
            100,
            root_100,
            &[(&bad_delta, &anchor_105)],
            Some(&st),
        )
        .await
        .is_err(),
        "corrupted_delta_rejected: incremental sync must fail closed"
    );
    // Target engine remains at state 100!
    assert_eq!(target_engine.get_state_root().await, root_100);
    assert!(st.snap_committed_at(105).unwrap().is_none());

    // Valid delta succeeds and persists to snap_committed[105].
    let (_, _) = fast_sync_snapv4_incremental(
        &target_engine,
        &installed_100,
        100,
        root_100,
        &[(&enc_delta, &anchor_105)],
        Some(&st),
    )
    .await
    .expect("valid incremental delta sync");
    assert_eq!(target_engine.get_state_root().await, root_105);
    assert_eq!(
        target_engine
            .evm_bindings_read()
            .await
            .get_pq(&[0xCDu8; 20]),
        Some(addr2)
    );

    // Reload from Storage SnapV4 trees via load_full_state_into!
    let reloaded_engine = InMemoryStateEngine::new();
    let (reloaded_h, _, _) = load_full_state_into(&st, &reloaded_engine)
        .await
        .expect("load_full_state_into from SnapV4")
        .expect("some");
    assert_eq!(reloaded_h, 105);
    assert_eq!(reloaded_engine.get_state_root().await, root_105);

    // Prune deltas below 105: retains 105 and its base 100 dependency!
    assert_eq!(st.prune_deltas_below(105).unwrap(), 0);
    assert!(st.snap_committed_at(100).unwrap().is_some());
    assert!(st.snap_committed_at(105).unwrap().is_some());

    // SAFETY BARRIER INVARIANT: safety_record_v1, ConsensusCheckpoint, and VoteWatermark UNTOUCHED!
    let safety_after = safety.load().unwrap().expect("safety record intact");
    assert_eq!(safety_after.generation, 7);
    assert_eq!(safety_after.payload, b"gen7");
    let cp_after = st
        .consensus()
        .unwrap()
        .expect("consensus checkpoint intact");
    assert_eq!(cp_after.height, 42);
    assert_eq!(cp_after.round, 3);
    assert_eq!(cp_after.locked_hash, Some([0x77; 32]));
    let wm_after = st.vote_watermark().unwrap().expect("vote watermark intact");
    assert_eq!(wm_after, wm);

    // Unused helper sanity check (encode_canonical / sign_manifest imported cleanly).
    let _ = encode_canonical(&0u64).unwrap();
    let mut m_dummy = enc_base.manifest.clone();
    sign_manifest(&mut m_dummy, &kp).unwrap();

    drop(safety);
    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}
