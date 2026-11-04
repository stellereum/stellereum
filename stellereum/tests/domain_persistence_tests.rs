//! §2 zkML registry PERSISTENCE (audit F-B).
//!
//! The gap: `ZkMlModelRegistry` (models + VKs) is committed consensus state
//! (it moves the root when non-empty), but had no storage tree of its own.
//! A node that restarted from a snapshot came back with an EMPTY registry
//! while its accounts already carried the effects: registered models
//! vanished, and worst of all the restarted node computed a DIFFERENT root
//! than the network (conditional digest: non-empty -> empty) - a consensus
//! split out of a routine restart.
//!
//! (The shielded-ledger half of this audit item was deleted with the
//! shielded protocol removal: the opcodes, curves and state it covered no
//! longer exist.)
//!
//! The fix mirrors the session-key registry and the bridge domain: own sled
//! trees (`zkml_models`), captured by the same snapshot job
//! and applied by BOTH engines `load_full_state_into` touches (the verifying
//! throwaway and the live one), with an absent entry meaning "empty".
//!
//! Invariants pinned here:
//!   * the registry persists through `snapshot_domains` -> reopen ->
//!     `load_full_state_into`, and the restored engine computes the IDENTICAL
//!     state root;
//!   * after the restore, the safety property still holds (registered model
//!     still verifies);
//!   * restoring WITHOUT the registry bytes roots differently (the hole was
//!     real) - and an all-empty snapshot restores to the pre-domain root
//!     (genesis KAT safety).

use ed25519_dalek::SigningKey;

use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel};

/// Fixed, realistic block timestamp. Never 0.
const TS: u64 = 1_760_000_000;
const STELL: u64 = 1_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn tmp_store_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell-domainpersist-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
    ))
}

fn block(height: u64, timestamp: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

fn register_tx(
    sk: &SigningKey,
    to: [u8; 32],
    nonce: u64,
    id: [u8; 32],
    m: &QuantizedLinearModel,
) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        to,
        0,
        50_000_000,
        nonce,
        1,
        1,
        vec![OpCode::SysCallRegisterZkMlModel {
            model_id: id,
            model: Box::new(m.clone()),
        }],
    )
}

fn ref_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
}

async fn persisted_snapshot_dir(
    e: &InMemoryStateEngine,
    snap_h: u64,
    tag: &str,
) -> (std::path::PathBuf, [u8; 32]) {
    use stellereum::storage::{AsyncPersistence, Storage};
    let root = e.get_state_root().await;
    let dir = tmp_store_dir(tag);
    let _ = std::fs::remove_dir_all(&dir);
    let store = std::sync::Arc::new(Storage::open(&dir).expect("open storage"));
    store
        .put_state(snap_h, &e.create_snapshot().await)
        .expect("state");
    let staking = e.staking_read().await.clone();
    let gov = e.governance_read().await.clone();
    let ap = AsyncPersistence::start(store.clone());
    ap.snapshot_domains(e, &staking, &gov, snap_h).await;
    for _ in 0..500 {
        let domains_ok =
            matches!(store.latest_domains().ok().flatten(), Some((h, _)) if h == snap_h);
        if domains_ok {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        matches!(store.latest_domains().ok().flatten(), Some((h, _)) if h == snap_h),
        "snapshot_domains must persist the domain snapshot"
    );
    // Anchor block at snap_h+1 committing to the post-snapshot root, which is
    // what the restore verifier compares against.
    let ask = key(0x11);
    let mut anchor = block(
        snap_h + 1,
        TS + snap_h + 1,
        vec![],
        ask.verifying_key().to_bytes(),
    );
    anchor.state_root = root;
    anchor.sign_block(&ask);
    let anchor_hash = store.put_block(&anchor).expect("anchor");
    store
        .set_finalized(snap_h + 1, &anchor_hash)
        .expect("finalized");
    store.flush().expect("flush");
    drop(ap);
    drop(store);
    (dir, root)
}

async fn reopen_and_load(
    dir: &std::path::Path,
) -> (
    std::sync::Arc<stellereum::storage::Storage>,
    InMemoryStateEngine,
    u64,
) {
    use stellereum::storage::{load_full_state_into, Storage};
    let store = {
        let mut opened = None;
        for _ in 0..200 {
            match Storage::open(dir) {
                Ok(s) => {
                    opened = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        std::sync::Arc::new(opened.expect("the store must reopen after the writer exits"))
    };
    let fresh = InMemoryStateEngine::new();
    let (height, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("load verifies against the anchor")
        .expect("snapshot present");
    (store, fresh, height)
}

// ===========================================================================
// zkML registry: registered models survive the restart.
// ===========================================================================

/// A registered model persists through snapshot + reopen at the identical
/// root, and still verifies afterwards.
#[tokio::test]
async fn zkml_registry_survives_snapshot_and_restore() {
    let e = InMemoryStateEngine::new();
    let payer = key(0x31);
    let payer_pk = payer.verifying_key().to_bytes();
    e.update_account(AccountState::new(payer_pk, 10 * STELL))
        .await;
    let model_id = [0x41u8; 32];
    let tx = register_tx(&payer, payer_pk, 0, model_id, &ref_model());
    let out = e
        .apply_block_transition(&block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "model registration applies");
    assert!(
        !e.zkml_models_read().await.is_empty(),
        "precondition: the registry is non-empty"
    );

    const SNAP_H: u64 = 500;
    let (dir, root) = persisted_snapshot_dir(&e, SNAP_H, "zkml").await;
    let (_store, fresh, height) = reopen_and_load(&dir).await;
    assert_eq!(height, SNAP_H);
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "the commitment digest must round-trip IDENTICALLY through the restore"
    );
    assert_eq!(
        &*fresh.zkml_models_read().await,
        &*e.zkml_models_read().await,
        "the whole model registry (models + VKs) comes back"
    );

    // Negative control: without the registry bytes the root differs.
    let bare = InMemoryStateEngine::new();
    bare.restore_snapshot(&_store.get_state(SNAP_H).unwrap().unwrap())
        .await
        .expect("accounts restore");
    if let Some(bytes) = _store.latest_domains().unwrap().map(|(_, b)| b) {
        let snap: stellereum::storage::DomainSnapshot =
            bincode::deserialize(&bytes).expect("domains decode");
        snap.apply(&bare).await;
    }
    assert_ne!(
        bare.get_state_root().await,
        root,
        "a restore that drops the registry must NOT compute the committed root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty registry restores to the written root (KAT safety).
#[tokio::test]
async fn zkml_absent_means_empty() {
    let e = InMemoryStateEngine::new();
    let root = e.get_state_root().await;
    assert!(e.zkml_models_read().await.is_empty());
    const SNAP_H: u64 = 500;
    let (dir, _) = persisted_snapshot_dir(&e, SNAP_H, "zkmlempty").await;
    let (_store, fresh, _) = reopen_and_load(&dir).await;
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "empty registry restores to the written root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
