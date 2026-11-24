//! Regression tests for `P0-SAFETY-BOOT-ONE-BLOCK`:
//! proof-carrying boot reconciliation across a hard-`SIGKILL` 1-block gap
//! between durable `safety_record_v1` and `storage.finalized()` / state snapshot.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::safety::{
    derive_safety_chain_id, reconcile_boot_sigkill_gap, AuthorityMode, BootReconcileOutcome,
    SafetyAuthority, SafetyBootContext,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{
    load_full_state_into, wait_for_persist_drain, AsyncPersistence, SafetyRecordIdentity, Storage,
};

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)] // GATE: shared support helper module; this suite uses fvote_deterministic only.
mod falcon_votes;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "stell-w2-boot-rec-{tag}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            let _ = std::fs::remove_dir_all(&path);
        }
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.0.exists() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn identity_for(validator: [u8; 32], genesis_root: [u8; 32]) -> SafetyRecordIdentity {
    SafetyRecordIdentity {
        validator,
        chain: derive_safety_chain_id(stellereum::consensus::consensus_chain_id(), &genesis_root),
        shard: MASTERCHAIN_SHARD,
    }
}

fn clean_genesis_boot_ctx() -> SafetyBootContext {
    SafetyBootContext {
        is_validator: true,
        is_observer_env: false,
        new_chain_explicit: true,
        restored_finalized: None,
        restored_state_height: Some(0),
        restored_finalized_qc_verified: false,
        legacy_checkpoint: None,
        legacy_watermark: None,
    }
}

fn restart_boot_ctx(
    restored_finalized: Option<(u64, [u8; 32])>,
    restored_state_height: u64,
    restored_finalized_qc_verified: bool,
) -> SafetyBootContext {
    SafetyBootContext {
        is_validator: true,
        is_observer_env: false,
        new_chain_explicit: false,
        restored_finalized,
        restored_state_height: Some(restored_state_height),
        restored_finalized_qc_verified,
        legacy_checkpoint: None,
        legacy_watermark: None,
    }
}

/// Run one full consensus height across a 4-validator cluster and return the
/// finalized block (with attached `precommit_qc`) and its hash.
async fn finalize_one_height(
    nodes: &mut [ValidatorRuntime],
    ks: &[SigningKey],
    vset: &ValidatorSet,
    timestamp: u64,
) -> (Block, [u8; 32]) {
    let height = nodes[0].hc.height;
    let round = nodes[0].hc.round;
    let pid = vset
        .proposer_for(height, round)
        .expect("proposer for height/round");
    let pidx = ks
        .iter()
        .position(|k| k.verifying_key().to_bytes() == pid)
        .expect("proposer in ks");
    let block = nodes[pidx].propose(timestamp).await.expect("propose block");
    let bh = block.compute_hash();
    for (i, node) in nodes.iter_mut().enumerate() {
        if i != pidx {
            node.on_proposal(pid, block.clone(), round)
                .await
                .expect("peer accepts proposal");
        }
    }
    let prevotes: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.make_prevote().expect("prevote"))
        .collect();
    for pv in &prevotes {
        for node in nodes.iter_mut() {
            node.on_prevote(pv.clone()).expect("on_prevote");
        }
    }
    let precommits: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.make_precommit().expect("precommit"))
        .collect();
    for pc in &precommits {
        for node in nodes.iter_mut() {
            node.on_precommit(pc.clone()).expect("on_precommit");
        }
    }
    let mut finalized_block = None;
    for (i, node) in nodes.iter_mut().enumerate() {
        let got = node.try_finalize().await.expect("try_finalize");
        assert_eq!(got, bh);
        if i == 0 {
            finalized_block = node.blocks.get(&bh).cloned();
        }
    }
    let blk = finalized_block.expect("node 0 holds finalized block with QC");
    assert!(blk.precommit_qc.is_some());
    (blk, bh)
}

async fn make_cluster_with_durable_node0(
    dir: &TestDir,
) -> (
    Vec<SigningKey>,
    ValidatorSet,
    Arc<Storage>,
    SafetyRecordIdentity,
    [u8; 32],
    Vec<ValidatorRuntime>,
) {
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 10))
            .collect(),
    );
    let mut nodes = Vec::with_capacity(4);
    for i in 0..4 {
        let st = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&st, &vset, 1_000_000).await;
        let mut rt = ValidatorRuntime::new(ks[i].clone(), vset.clone(), st, 1)
            .with_falcon_key(fks[i].clone());
        rt.hc.set_parent_hash([0u8; 32]);
        nodes.push(rt);
    }
    let genesis_root = nodes[0].state.get_state_root().await;
    let storage = Arc::new(Storage::open(&dir.0).expect("open storage"));
    storage
        .set_meta("genesis_state_root", &genesis_root)
        .expect("set genesis_state_root");
    let id = identity_for(ks[0].verifying_key().to_bytes(), genesis_root);
    let auth =
        SafetyAuthority::open_from_storage(storage.clone(), id.clone(), clean_genesis_boot_ctx());
    assert_eq!(auth.mode(), AuthorityMode::Active);
    nodes[0] = std::mem::replace(
        &mut nodes[0],
        ValidatorRuntime::new(
            ks[0].clone(),
            vset.clone(),
            Arc::new(InMemoryStateEngine::new()),
            1,
        ),
    )
    .with_safety_authority(auth);
    (ks, vset, storage, id, genesis_root, nodes)
}

#[tokio::test]
async fn sigkill_gap_with_valid_block_in_store_reconciles_without_quarantine() {
    // Subcase A: H = 2 (storage.finalized() == 1, restored_state_height == 1,
    // safety_record_v1 at finalized_height = 2, height = 3, valid QC-carrying block 2 in store).
    {
        let dir = TestDir::new("reconcile-h2");
        let (ks, vset, storage, id, _genesis_root, mut nodes) =
            make_cluster_with_durable_node0(&dir).await;

        let (b1, h1) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_001).await;
        storage.put_block(&b1).expect("put b1");
        storage.set_finalized(1, &h1).expect("set_finalized 1");
        {
            let ap = AsyncPersistence::start(storage.clone());
            ap.snapshot_state(&nodes[0].state, 1).await;
            let ledger = nodes[0].staking_read().await.clone();
            let gov = nodes[0].state.governance_read().await.clone();
            ap.snapshot_domains(&nodes[0].state, &ledger, &gov, 1).await;
            ap.request_flush();
            let outcome = wait_for_persist_drain(|| ap.pending()).await;
            assert!(outcome.drained);
        }
        storage.flush().expect("flush height 1");

        // Height 2 finalizes: safety_record_v1 advances to finalized_height=2, height=3.
        // Persist block 2 body (with QC) in storage, but simulate SIGKILL before
        // `set_finalized(2, h2)` and state snapshot 2 land!
        let (b2, h2) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_002).await;
        storage.put_block(&b2).expect("put b2");
        storage.flush().expect("flush b2");
        let expected_post_h2_root = nodes[0].state.get_state_root().await;

        assert_eq!(storage.finalized().unwrap(), Some((1, h1)));
        let safety_before = nodes[0].safety.current_state().unwrap();
        let gen_before = nodes[0].safety.generation().unwrap();
        assert_eq!(
            (
                safety_before.height,
                safety_before.finalized_height,
                safety_before.finalized_hash
            ),
            (3, 2, h2)
        );

        drop(nodes);
        drop(storage);

        // Reboot: restore snapshot at height 1 and run proof-carrying boot reconciliation.
        let storage2 = Arc::new(Storage::open(&dir.0).expect("reopen storage"));
        assert_eq!(storage2.finalized().unwrap(), Some((1, h1)));

        let boot_state = Arc::new(InMemoryStateEngine::new());
        let (restored_h, ledger, gov) = load_full_state_into(&storage2, &boot_state)
            .await
            .expect("load_full_state_into")
            .expect("snapshot at height 1");
        assert_eq!(restored_h, 1);
        *boot_state.staking_write().await = ledger;
        *boot_state.governance_write().await = gov.clone();

        let mut rt_boot = ValidatorRuntime::new(ks[0].clone(), vset.clone(), boot_state, 2);
        rt_boot.governance = Some(gov);
        rt_boot.finalized.push((1, h1));
        rt_boot.hc.set_parent_hash(h1);

        let rec_outcome =
            reconcile_boot_sigkill_gap(&storage2, id.clone(), &mut rt_boot, restored_h)
                .await
                .expect("reconcile_boot_sigkill_gap must succeed");
        assert_eq!(
            rec_outcome,
            BootReconcileOutcome::Reconciled {
                from_height: 1,
                to_height: 2,
                finalized_hash: h2,
                replayed_to_height: 2,
            }
        );

        // Assert durable storage.finalized(), engine state, and runtime updated to H = 2.
        assert_eq!(storage2.finalized().unwrap(), Some((2, h2)));
        assert_eq!(rt_boot.state.get_state_root().await, expected_post_h2_root);
        assert_eq!(rt_boot.finalized.last().copied(), Some((2, h2)));
        assert_eq!(rt_boot.hc.height, 3);

        // Rebuild parent decision evidence and open SafetyAuthority -> Active (NOT quarantined!).
        rt_boot
            .restore_last_decision_from_finalized_block(&b2)
            .expect("restore last decision from b2");
        let auth2 = SafetyAuthority::open_from_storage(
            storage2.clone(),
            id.clone(),
            restart_boot_ctx(rt_boot.finalized.last().copied(), 2, true),
        );
        assert!(!auth2.is_quarantined());
        assert!(auth2.can_sign());
        assert_eq!(auth2.mode(), AuthorityMode::Active);
        assert_eq!(auth2.generation(), Some(gen_before));
        let safety_after = auth2.current_state().unwrap();
        assert_eq!(
            (
                safety_after.height,
                safety_after.finalized_height,
                safety_after.finalized_hash
            ),
            (3, 2, h2)
        );
    }

    // Subcase B: H = 1 boundary (`storage.finalized() == None`, `restored_state_height == 0`,
    // `safety_record_v1` at `finalized_height = 1, height = 2`, valid QC-carrying block 1 in store).
    {
        let dir = TestDir::new("reconcile-h1");
        let (ks, vset, storage, id, _genesis_root, mut nodes) =
            make_cluster_with_durable_node0(&dir).await;

        let (b1, h1) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_010).await;
        storage.put_block(&b1).expect("put b1");
        storage.flush().expect("flush b1");
        let expected_post_h1_root = nodes[0].state.get_state_root().await;
        assert_eq!(storage.finalized().unwrap(), None);

        drop(nodes);
        drop(storage);

        let storage2 = Arc::new(Storage::open(&dir.0).expect("reopen storage"));
        assert_eq!(storage2.finalized().unwrap(), None);

        let boot_state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&boot_state, &vset, 1_000_000).await;
        let mut rt_boot = ValidatorRuntime::new(ks[0].clone(), vset.clone(), boot_state, 1);
        rt_boot.hc.set_parent_hash([0u8; 32]);

        let rec_outcome = reconcile_boot_sigkill_gap(&storage2, id.clone(), &mut rt_boot, 0)
            .await
            .expect("reconcile height 1 from None finalized");
        assert_eq!(
            rec_outcome,
            BootReconcileOutcome::Reconciled {
                from_height: 0,
                to_height: 1,
                finalized_hash: h1,
                replayed_to_height: 1,
            }
        );
        assert_eq!(storage2.finalized().unwrap(), Some((1, h1)));
        assert_eq!(rt_boot.state.get_state_root().await, expected_post_h1_root);
        assert_eq!(rt_boot.finalized.last().copied(), Some((1, h1)));
        assert_eq!(rt_boot.hc.height, 2);

        rt_boot
            .restore_last_decision_from_finalized_block(&b1)
            .expect("restore last decision from b1");
        let auth2 = SafetyAuthority::open_from_storage(
            storage2,
            id,
            restart_boot_ctx(rt_boot.finalized.last().copied(), 1, true),
        );
        assert!(!auth2.is_quarantined());
        assert!(auth2.can_sign());
        assert_eq!(auth2.mode(), AuthorityMode::Active);
    }
}

#[tokio::test]
async fn sigkill_gap_missing_or_forged_block_still_quarantines() {
    // Prepare a baseline 1-block gap at H = 2 where storage.finalized() == (1, h1)
    // and safety_record_v1 == (finalized_height=2, finalized_hash=h2, height=3).
    enum TamperCase {
        MissingBlock,
        MissingQc,
        BadQcSignatures,
        WrongBlockHashOrPrevHash,
    }

    for case in [
        TamperCase::MissingBlock,
        TamperCase::MissingQc,
        TamperCase::BadQcSignatures,
        TamperCase::WrongBlockHashOrPrevHash,
    ] {
        let dir = TestDir::new("forged-quarantine");
        let (ks, vset, storage, id, _genesis_root, mut nodes) =
            make_cluster_with_durable_node0(&dir).await;

        let (b1, h1) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_001).await;
        storage.put_block(&b1).expect("put b1");
        storage.set_finalized(1, &h1).expect("set_finalized 1");
        {
            let ap = AsyncPersistence::start(storage.clone());
            ap.snapshot_state(&nodes[0].state, 1).await;
            let ledger = nodes[0].staking_read().await.clone();
            let gov = nodes[0].state.governance_read().await.clone();
            ap.snapshot_domains(&nodes[0].state, &ledger, &gov, 1).await;
            ap.request_flush();
            assert!(wait_for_persist_drain(|| ap.pending()).await.drained);
        }
        storage.flush().expect("flush height 1");

        let (b2, h2) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_002).await;

        match case {
            TamperCase::MissingBlock => {
                // Do not store b2 at all.
            }
            TamperCase::MissingQc => {
                let mut b2_no_qc = b2.clone();
                b2_no_qc.precommit_qc = None;
                storage.put_block(&b2_no_qc).expect("put b2_no_qc");
            }
            TamperCase::BadQcSignatures => {
                let mut b2_bad_qc = b2.clone();
                b2_bad_qc.precommit_qc = Some(QuorumCertificate {
                    height: 2,
                    round: 0,
                    kind: VoteKind::Precommit,
                    block_hash: Some(h2),
                    signatures: vec![],
                    shard_id: MASTERCHAIN_SHARD,
                });
                storage.put_block(&b2_bad_qc).expect("put b2_bad_qc");
            }
            TamperCase::WrongBlockHashOrPrevHash => {
                // Insert a tampered block with a different prev_hash under `h2` key in sled
                // so `compute_hash() != h2` (and `prev_hash != h1`).
                let mut b2_tampered = b2.clone();
                b2_tampered.prev_hash = [0x99; 32];
                let raw = bincode::serialize(&b2_tampered).expect("serialize tampered block");
                storage
                    .blocks_tree_for_test()
                    .insert(h2, raw)
                    .expect("inject tampered block bytes at h2");
            }
        }
        storage.flush().expect("flush tampered state");
        drop(nodes);
        drop(storage);

        let storage2 = Arc::new(Storage::open(&dir.0).expect("reopen storage"));
        let boot_state = Arc::new(InMemoryStateEngine::new());
        let (restored_h, ledger, gov) = load_full_state_into(&storage2, &boot_state)
            .await
            .expect("load_full_state_into")
            .expect("snapshot at height 1");
        *boot_state.staking_write().await = ledger;
        *boot_state.governance_write().await = gov.clone();

        let mut rt_boot = ValidatorRuntime::new(ks[0].clone(), vset.clone(), boot_state, 2);
        rt_boot.governance = Some(gov);
        rt_boot.finalized.push((1, h1));
        rt_boot.hc.set_parent_hash(h1);

        let rec_res =
            reconcile_boot_sigkill_gap(&storage2, id.clone(), &mut rt_boot, restored_h).await;
        assert!(
            rec_res.is_err(),
            "missing/forged block must refuse boot reconciliation"
        );
        // `storage.finalized()` MUST NOT advance when reconciliation fails!
        assert_eq!(storage2.finalized().unwrap(), Some((1, h1)));

        let auth2 = SafetyAuthority::open_from_storage(
            storage2,
            id,
            restart_boot_ctx(Some((1, h1)), restored_h, false),
        );
        assert!(
            auth2.is_quarantined(),
            "SafetyAuthority MUST quarantine fail-closed on unprovable SIGKILL gap"
        );
        assert!(!auth2.can_sign());
    }
}

#[tokio::test]
async fn existing_safety_authority_invariant_preserved_without_reconcile() {
    let dir = TestDir::new("direct-open-quarantine");
    let (ks, vset, storage, id, _genesis_root, mut nodes) =
        make_cluster_with_durable_node0(&dir).await;

    let (b1, h1) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_001).await;
    storage.put_block(&b1).expect("put b1");
    storage.set_finalized(1, &h1).expect("set_finalized 1");

    // Advance height 2 (safety_record_v1 at finalized_height=2, height=3), then cast a
    // prevote at height 3 round 4 so we also assert floors are never lowered.
    let (b2, h2) = finalize_one_height(&mut nodes, &ks, &vset, 1_700_000_002).await;
    storage.put_block(&b2).expect("put b2");
    storage.flush().expect("flush b2");

    while nodes[0].hc.round < 4 {
        nodes[0].next_round();
    }
    let pv3 = nodes[0].make_prevote().expect("prevote height 3 round 4");
    assert_eq!((pv3.height, pv3.round), (3, 4));
    let expected_safety = nodes[0].safety.current_state().unwrap();
    assert_eq!(expected_safety.finalized_height, 2);
    assert_eq!(expected_safety.height, 3);
    assert_eq!(expected_safety.highest_prevote_round, Some(4));

    drop(nodes);
    drop(storage);

    // Calling SafetyAuthority::open_from_storage DIRECTLY with restored_fh (1) <
    // payload.finalized_height (2) — WITHOUT running reconcile_boot_sigkill_gap —
    // MUST still quarantine fail-closed even though valid block 2 is in storage!
    let storage2 = Arc::new(Storage::open(&dir.0).expect("reopen storage"));
    let auth_direct = SafetyAuthority::open_from_storage(
        storage2.clone(),
        id.clone(),
        restart_boot_ctx(Some((1, h1)), 1, true),
    );
    assert!(
        auth_direct.is_quarantined(),
        "direct open_from_storage with payload.finalized_height > restored_fh MUST quarantine"
    );
    assert!(!auth_direct.can_sign());
    drop(auth_direct);

    // Verify safety_record_v1 on disk was NEVER lowered (floors & heights intact).
    let rec = storage2
        .safety_record_store(id)
        .unwrap()
        .load()
        .unwrap()
        .expect("safety record still present");
    let decoded = stellereum::safety::SafetyRecordPayload::decode_canonical(&rec.payload).unwrap();
    assert_eq!(decoded.finalized_height, 2);
    assert_eq!(decoded.finalized_hash, h2);
    assert_eq!(decoded.height, 3);
    assert_eq!(decoded.highest_prevote_round, Some(4));
}
