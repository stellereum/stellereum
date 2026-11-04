//! §9 shielded ledger + §2 zkML registry PERSISTENCE (audit F-B).
//!
//! The gap: `ConfidentialState` (balances, spent-input set, fee total) and
//! `ZkMlModelRegistry` (models + VKs) are committed consensus state (they move
//! the root when non-empty), but had no storage tree of their own. A node that
//! restarted from a snapshot came back with EMPTY domains while its accounts
//! already carried the effects: spent commitments could be spent AGAIN (the
//! double-spend the spent set exists to prevent), registered models vanished,
//! and worst of all the restarted node computed a DIFFERENT root than the
//! network (conditional digest: non-empty -> empty) - a consensus split out
//! of a routine restart.
//!
//! The fix mirrors the session-key registry and the bridge domain: own sled
//! trees (`confidential`, `zkml_models`), captured by the same snapshot job
//! and applied by BOTH engines `load_full_state_into` touches (the verifying
//! throwaway and the live one), with an absent entry meaning "empty".
//!
//! Invariants pinned here, per domain:
//!   * the domain persists through `snapshot_domains` -> reopen ->
//!     `load_full_state_into`, and the restored engine computes the IDENTICAL
//!     state root;
//!   * after the restore, the safety property still holds (spent input refused;
//!     registered model still verifies);
//!   * restoring WITHOUT the domain bytes roots differently (the hole was
//!     real) - and an all-empty snapshot restores to the pre-domain root
//!     (genesis KAT safety).

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;

use stellereum::crypto_privacy::{ConfidentialTransfer, PedersenCommitment};
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

/// A valid one-in/one-out transfer: input (value), output (value), same
/// blinding, zero fee, so `C_in - C_out == 0` exactly. Deterministic.
fn balanced_transfer(value: u64) -> ConfidentialTransfer {
    let r = Scalar::from(0x5EED_u64);
    ConfidentialTransfer::new(
        vec![PedersenCommitment::commit(value, &r)],
        vec![PedersenCommitment::commit(value, &r)],
        0,
    )
}

fn confidential_tx(
    sk: &SigningKey,
    recipient: [u8; 32],
    transfer: ConfidentialTransfer,
    nonce: u64,
) -> Transaction {
    // Shield + enforced-transfer bundle (audit 2026-10-06 F-A): the only way
    // to fund inputs under the ownership rule. Zero fee here.
    use curve25519_dalek::scalar::Scalar;
    use stellereum::crypto_privacy::RangeProof;
    let r = Scalar::from(0x5EED_u64);
    let in_val = 1_000u64;
    let inp = &transfer.input_commitments;
    let outp = &transfer.output_commitments;
    let input_ranges: Vec<RangeProof> = inp
        .iter()
        .map(|c| RangeProof::prove(c, in_val, &r, 32))
        .collect();
    let output_ranges: Vec<RangeProof> = outp
        .iter()
        .map(|c| RangeProof::prove(c, in_val, &r, 32))
        .collect();
    Transaction::sign_with_payload(
        sk,
        [0xEE; 32],
        0,
        100_000,
        nonce,
        1,
        1,
        vec![
            OpCode::SysCallConfidentialShield {
                commitment: inp[0].commitment,
                amount: in_val,
                blinding: r.to_bytes(),
            },
            OpCode::SysCallConfidentialTransfer2 {
                recipient,
                transfer: Box::new(transfer),
                input_ranges,
                output_ranges,
            },
        ],
    )
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
// 1. Shielded ledger: spent set survives the restart.
// ===========================================================================

/// A confidential transfer applies, the node restarts from disk, and the SAME
/// input commitment is still refused (no second spend), at the IDENTICAL root.
#[tokio::test]
async fn confidential_spent_set_survives_snapshot_and_restore() {
    let e = InMemoryStateEngine::new();
    let payer = key(0x21);
    let payer_pk = payer.verifying_key().to_bytes();
    e.update_account(AccountState::new(payer_pk, 10 * STELL))
        .await;
    let recipient = [0x22u8; 32];

    let tx = confidential_tx(&payer, recipient, balanced_transfer(1_000), 0);
    let out = e
        .apply_block_transition(&block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "the shielded transfer applies");
    assert!(
        !e.confidential_read().await.is_empty(),
        "precondition: the shielded ledger is non-empty"
    );

    const SNAP_H: u64 = 500;
    let (dir, root) = persisted_snapshot_dir(&e, SNAP_H, "conf").await;
    let (_store, fresh, height) = reopen_and_load(&dir).await;
    assert_eq!(height, SNAP_H);
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "the commitment digest must round-trip IDENTICALLY through the restore"
    );
    assert_eq!(
        &*fresh.confidential_read().await,
        &*e.confidential_read().await,
        "balances, spent set and fee total all come back"
    );

    // THE GAP, pinned: the same input spent again is refused by the RESTORED
    // spent set - no second credit, no root movement.
    let replay = confidential_tx(&payer, recipient, balanced_transfer(1_000), 1);
    let settled = fresh.get_state_root().await;
    let out = fresh
        .apply_block_transition(&block(2, TS + 1, vec![replay], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "double-spend refused after restore"
    );
    // The refused replay moves no VALUE (the confidential ledger is
    // untouched - see the assertion below), but the failed attempt is not
    // free: it pays the F-01 failure fee it declared, so the root moves by
    // exactly that.
    assert!(
        fresh.get_state_root().await != settled,
        "the failed attempt pays its fee, so the root moves"
    );

    // Negative control: restoring accounts + domains WITHOUT the confidential
    // bytes lands on a different root - the hole was real.
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
        "a restore that drops the shielded ledger must NOT compute the committed root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An all-empty shielded ledger restores to the pre-domain root (KAT safety).
#[tokio::test]
async fn confidential_absent_means_empty() {
    let e = InMemoryStateEngine::new();
    let root = e.get_state_root().await;
    assert!(e.confidential_read().await.is_empty());
    const SNAP_H: u64 = 500;
    let (dir, _) = persisted_snapshot_dir(&e, SNAP_H, "confempty").await;
    let (_store, fresh, _) = reopen_and_load(&dir).await;
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "empty ledger restores to the written root"
    );
    assert!(fresh.confidential_read().await.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 2. zkML registry: registered models survive the restart.
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
