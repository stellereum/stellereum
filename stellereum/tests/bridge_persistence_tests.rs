//! §8 bridge domain PERSISTENCE: a restored node must still refuse a replayed
//! source transaction.
//!
//! The gap this file closes (documented when §8 policy landed in `1f973ff`):
//! the committed bridge domain - the source-tx replay set, the parked
//! withdrawal queue, the hourly rate window and the escrow mirror - had no
//! storage tree of its own. A node that restarted from a snapshot came back
//! with an EMPTY replay set while its accounts already carried the credit, so
//! the very same `source_tx_hash` could be claimed again: the double mint the
//! replay set exists to prevent, restored into existence by the restore path.
//!
//! The fix mirrors exactly how the session-key registry solved the same class
//! of problem (`session_registry_tests.rs`): its own sled tree, captured by the
//! same snapshot job and applied by BOTH engines `load_full_state_into`
//! touches (the verifying throwaway and the live one), with an absent entry
//! meaning "empty" - which is what the CONDITIONAL digest domain hashes as, so
//! a pre-bridge data directory still restores to the root it was written with
//! and `COMMITMENT_VERSION` stays 4.
//!
//! Invariants pinned here:
//!   * the domain persists through `snapshot_domains` -> `load_full_state_into`;
//!   * the restored engine computes the IDENTICAL state root (the commitment
//!     digest round-trips byte-for-byte);
//!   * after the restore, the SAME source tx is refused, credits nobody, and
//!     does not move the root;
//!   * restoring WITHOUT the bridge bytes roots differently - that is the hole,
//!     and it is why `verify_restored_root` would now reject such a restore.

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{
    BridgeIntent, SupportedChain, TeleportBridgeEngine, LARGE_WITHDRAWAL_THRESHOLD_NANO,
    WITHDRAWAL_TIME_LOCK_SECS,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, GAS_BRIDGE_INTENT};

/// Fixed, realistic block timestamp. Never 0.
const TS: u64 = 1_760_000_000;
/// Nano-STELL per STELL, for readable amounts.
const STELL: u64 = 1_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

/// Fund and bond `n` validators, so the committed relayer set the quorum
/// counts distinct signers from has `n` members (`(n*2+2)/3` needs 2 of 3).
async fn setup(n: usize) -> (InMemoryStateEngine, Vec<SigningKey>) {
    let e = InMemoryStateEngine::new();
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let k = key(0xA0 + i as u8);
        let pk = k.verifying_key().to_bytes();
        e.credit_native(&pk, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("fund the validator");
        e.staking_write()
            .await
            .bond(pk, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .expect("bond it into the committed ledger");
        keys.push(k);
    }
    (e, keys)
}

fn deposit(source_tx_hash: [u8; 32], recipient: [u8; 32], amount: u64) -> BridgeIntent {
    BridgeIntent::Deposit {
        chain: SupportedChain::Ton,
        source_tx_hash,
        recipient,
        amount,
    }
}

/// The `Attest` companion for `dep`: signatures over the canonical message
/// `TeleportBridgeEngine::deposit_signing_message` builds.
fn attest(dep: &BridgeIntent, signers: &[SigningKey]) -> BridgeIntent {
    let event = dep.deposit_event(Vec::new()).expect("deposit event");
    let msg = TeleportBridgeEngine::deposit_signing_message(&event);
    let signatures = signers
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let source_tx_hash = match dep {
        BridgeIntent::Deposit { source_tx_hash, .. } => *source_tx_hash,
        other => panic!("attest() only pairs with a Deposit: {other:?}"),
    };
    BridgeIntent::Attest {
        source_tx_hash,
        signatures,
    }
}

/// A wrapping transaction carrying the intents. `from == proposer`, so the
/// declared gas the block path charges is credited straight back to the payer
/// as the proposer fee: balance assertions see only the bridge's own movement.
fn bridge_tx(payer: &SigningKey, nonce: u64, ops: Vec<OpCode>) -> Transaction {
    let gas = GAS_BRIDGE_INTENT * ops.len() as u64 + 1_000;
    Transaction::sign_with_payload(
        payer,
        payer.verifying_key().to_bytes(),
        0,
        gas,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        ops,
    )
}

fn bridge_block(height: u64, timestamp: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
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

/// Wrap an attested deposit as one transaction's payload.
fn ops(att: BridgeIntent, intent: BridgeIntent) -> Vec<OpCode> {
    vec![
        OpCode::SysCallBridge(Box::new(att)),
        OpCode::SysCallBridge(Box::new(intent)),
    ]
}

fn tmp_store_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell-bridge-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ))
}

// ===========================================================================
// 1. Snapshot -> restore: the replay set survives, the digest round-trips,
//    and the SAME source tx is still refused.
// ===========================================================================

#[tokio::test]
async fn bridge_replay_set_survives_snapshot_and_restore() {
    use stellereum::storage::{load_full_state_into, AsyncPersistence, Storage};

    const SNAP_H: u64 = 500;
    const NEXT_H: u64 = SNAP_H + 1;

    let (e, vals) = setup(3).await;
    let payer = key(0x01);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xABu8; 32];
    let amount = 5_000 * STELL;

    // Apply a quorum-attested deposit through the live block path.
    let dep = deposit([0x71u8; 32], recipient, amount);
    let att = attest(&dep, &vals[..2]);
    let tx = bridge_tx(&payer, 0, ops(att.clone(), dep.clone()));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "the deposit applies");
    assert_eq!(balance(&e, &recipient).await, amount);
    assert!(
        e.bridge_read()
            .await
            .processed_source_txs
            .contains(&[0x71u8; 32]),
        "precondition: the replay set holds the credited source tx"
    );
    let root = e.get_state_root().await;

    // Persist through the REAL path: the account snapshot directly, the domain
    // + session-key + bridge snapshots through `AsyncPersistence::snapshot_domains`
    // (the same call `main.rs` makes each period).
    let dir = tmp_store_dir("restore");
    let _ = std::fs::remove_dir_all(&dir);
    let store = std::sync::Arc::new(Storage::open(&dir).expect("open storage"));
    store
        .put_state(SNAP_H, &e.create_snapshot().await)
        .expect("state");
    let staking = e.staking_read().await.clone();
    let gov = e.governance_read().await.clone();
    let ap = AsyncPersistence::start(store.clone());
    ap.snapshot_domains(&e, &staking, &gov, SNAP_H).await;

    let mut persisted = false;
    for _ in 0..500 {
        let domains_ok =
            matches!(store.latest_domains().ok().flatten(), Some((h, _)) if h == SNAP_H);
        let bridge_ok = store.bridge_at(SNAP_H).ok().flatten().is_some();
        if domains_ok && bridge_ok {
            persisted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        persisted,
        "snapshot_domains must persist BOTH the domain and the bridge snapshot"
    );

    // Anchor: the block at SNAP_H+1 commits to the post-SNAP_H root, which is
    // what the restore verifier compares against.
    let sk = key(0x11);
    let mut anchor = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: NEXT_H,
        prev_hash: [0u8; 32],
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: TS + NEXT_H,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    anchor.sign_block(&sk);
    let anchor_hash = store.put_block(&anchor).expect("anchor");
    store
        .set_finalized(NEXT_H, &anchor_hash)
        .expect("finalized");
    store.flush().expect("flush");
    drop(ap);
    drop(store);

    // ReOPEN the directory, the way a restarted node would.
    let store = {
        let mut opened = None;
        for _ in 0..200 {
            match Storage::open(&dir) {
                Ok(s) => {
                    opened = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        std::sync::Arc::new(opened.expect("the store must reopen after the writer exits"))
    };

    // Restart: a fresh engine must come back with the SAME root - a bridge
    // domain that restored empty would re-root the chain (it is committed
    // state) AND re-open the double mint.
    let fresh = InMemoryStateEngine::new();
    let (height, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("load verifies against the anchor")
        .expect("snapshot present");
    assert_eq!(height, SNAP_H);
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "the commitment digest must round-trip IDENTICALLY through the restore"
    );
    assert_eq!(
        &*fresh.bridge_read().await,
        &*e.bridge_read().await,
        "the whole bridge domain (replay set, queue, rate window, mirror) comes back"
    );
    assert_eq!(
        fresh.get_account(&recipient).await.map(|a| a.balance),
        Some(amount),
        "the credit itself is still there"
    );

    // THE GAP, pinned negatively: restoring accounts + domains WITHOUT the
    // bridge bytes lands on a different root - so the hole was real, and
    // `verify_restored_root` rejects it rather than resuming on it.
    let bare = InMemoryStateEngine::new();
    bare.restore_snapshot(&store.get_state(SNAP_H).unwrap().unwrap())
        .await
        .expect("accounts restore");
    if let Some(bytes) = store.latest_domains().unwrap().map(|(_, b)| b) {
        let snap: stellereum::storage::DomainSnapshot =
            bincode::deserialize(&bytes).expect("domains decode");
        snap.apply(&bare).await;
    }
    assert_ne!(
        bare.get_state_root().await,
        root,
        "a restore that drops the bridge domain must NOT compute the committed root"
    );

    // After the restore, the SAME claim is refused by the committed replay
    // set: no second credit, no root movement, nothing written.
    let settled = fresh.get_state_root().await;
    let replay = bridge_tx(&payer, 1, ops(att, dep));
    let out = fresh
        .apply_block_transition(&bridge_block(2, TS + 1, vec![replay], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "a restored node must still refuse a replayed source_tx_hash"
    );
    assert_eq!(
        balance(&fresh, &recipient).await,
        amount,
        "the replay must not mint a second credit"
    );
    // No second mint and no bridge-state change. (The root does move: the
    // refusal is an attributable failure, so it pays the D2 floor step and
    // consumes its nonce - the engine's fail-closed anti-DoS rule.)
    assert_ne!(
        fresh.get_state_root().await,
        settled,
        "the refusal itself is charged: nonce + D2 floor step"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 2. Bytes-level round trip: what the tree stores is exactly what the engine
//    reads back, and an ABSENT entry still means "empty" (pre-bridge dir).
// ===========================================================================

#[tokio::test]
async fn bridge_snapshot_bytes_round_trip_and_absent_means_empty() {
    let (e, vals) = setup(3).await;
    let payer = key(0x02);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xB0u8; 32];

    let dep = deposit([0x72u8; 32], recipient, 1_000 * STELL);
    let att = attest(&dep, &vals[..2]);
    let tx = bridge_tx(&payer, 0, ops(att, dep));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);

    let bytes = e.bridge_snapshot().await;
    assert!(!bytes.is_empty(), "a non-empty domain must serialize");

    let fresh = InMemoryStateEngine::new();
    assert!(
        fresh.bridge_read().await.processed_source_txs.is_empty(),
        "a brand-new engine starts with an empty replay set"
    );
    fresh
        .restore_bridge(&bytes)
        .await
        .expect("the stored bytes decode");
    assert_eq!(
        &*fresh.bridge_read().await,
        &*e.bridge_read().await,
        "bridge_snapshot -> restore_bridge is a faithful round trip"
    );

    // Garbage fails LOUD instead of installing a wiped replay set.
    let err = fresh.restore_bridge(b"not a bincode BridgeState").await;
    assert!(
        err.is_err(),
        "corrupt bridge bytes must be refused, not read as empty"
    );
    // ...and the refused install left the domain untouched.
    assert_eq!(
        &*fresh.bridge_read().await,
        &*e.bridge_read().await,
        "a refused restore must not clear the domain"
    );

    // Pre-bridge directory: NO entry at that height. `None` means "empty",
    // which is exactly what the conditional digest hashes - that is what keeps
    // the genesis known-answer (and COMMITMENT_VERSION = 4) in place.
    let dir = tmp_store_dir("absent");
    let _ = std::fs::remove_dir_all(&dir);
    let store = stellereum::storage::Storage::open(&dir).expect("open");
    assert!(store.bridge_at(7).unwrap().is_none());
    assert_eq!(
        stellereum::commitment::COMMITMENT_VERSION,
        5,
        "Genesis v5 version"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 3. The withdrawal queue rides along too (a parked request must not be
//    forgotten by a restore: the time-lock and the id counter are consensus).
// ===========================================================================

#[tokio::test]
async fn withdrawal_queue_and_rate_window_survive_the_restore() {
    let (e, _vals) = setup(3).await;
    let payer = key(0x03);
    let payer_pk = payer.verifying_key().to_bytes();
    let start = LARGE_WITHDRAWAL_THRESHOLD_NANO + 10 * STELL;
    e.credit_native(&payer_pk, start).await.expect("fund");

    let withdraw = BridgeIntent::Withdraw {
        chain: SupportedChain::Arbitrum,
        target_address: "0xdeadbeef".to_string(),
        amount: LARGE_WITHDRAWAL_THRESHOLD_NANO,
    };
    let tx = bridge_tx(&payer, 0, vec![OpCode::SysCallBridge(Box::new(withdraw))]);
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "the withdrawal parks");
    assert_eq!(
        e.bridge_read().await.pending_withdrawals.len(),
        1,
        "precondition: a request is queued"
    );

    // Snapshot -> restore (bytes path: the storage path is test 1's job).
    let fresh = InMemoryStateEngine::new();
    // Fund the payer so the ONLY thing that can refuse the release below is
    // the restored time-lock, not a missing balance.
    fresh
        .credit_native(&payer_pk, start)
        .await
        .expect("fund the restored payer");
    fresh
        .restore_bridge(&e.bridge_snapshot().await)
        .await
        .expect("restore");
    {
        let restored = fresh.bridge_read().await;
        assert_eq!(restored.pending_withdrawals.len(), 1, "the queue came back");
        assert_eq!(
            restored.next_withdrawal_id,
            e.bridge_read().await.next_withdrawal_id,
            "the id counter is carried, so ids stay stable across restarts"
        );
        assert_eq!(
            restored.hourly_withdrawn, LARGE_WITHDRAWAL_THRESHOLD_NANO,
            "the rate window came back"
        );
        assert_eq!(
            restored.last_rate_limit_reset, TS,
            "the window clock is the BLOCK timestamp that was committed"
        );
        assert_eq!(restored.escrow_balance, LARGE_WITHDRAWAL_THRESHOLD_NANO);
    }

    // The restored queue still enforces the time-lock: a release one minute
    // in is refused by the block, exactly as before the restart.
    // Fresh engine: the payer's account starts at nonce 0 here.
    let early = BridgeIntent::Release { req_id: 0 };
    let tx = bridge_tx(&payer, 0, vec![OpCode::SysCallBridge(Box::new(early))]);
    let out = fresh
        .apply_block_transition(&bridge_block(2, TS + 60, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "the restored time-lock still refuses an early release"
    );
    assert!(
        !fresh.bridge_read().await.pending_withdrawals[&0].executed,
        "the refused release changed nothing"
    );

    // ...and once the block clock matures it, the SAME restored queue admits
    // it. That also proves the refusal above was the time-lock itself rather
    // than a transaction that could never have applied (no balance, no queue).
    // The refused release above consumed its nonce (a refused transaction
    // still advances the nonce and pays the D2 floor step), so the payer is
    // at 1 now.
    let matured = BridgeIntent::Release { req_id: 0 };
    let tx = bridge_tx(&payer, 1, vec![OpCode::SysCallBridge(Box::new(matured))]);
    let out = fresh
        .apply_block_transition(
            &bridge_block(3, TS + WITHDRAWAL_TIME_LOCK_SECS, vec![tx], payer_pk),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "the restored time-lock matures on the block clock, not before"
    );
    assert!(
        fresh.bridge_read().await.pending_withdrawals[&0].executed,
        "the restored queue releases exactly once"
    );
}

// ===========================================================================
// 9. Pre-F-H snapshots still restore (migration, audit follow-up)
// ===========================================================================

/// Adding the mint-ceiling fields changed `BridgeState`'s bincode layout, and
/// bincode structs decode exact-size: a bare decode of pre-F-H bytes fails
/// with `UnexpectedEof` (observed live: nodes refused to start on old data
/// dirs). `restore_bridge` must upgrade V1 bytes instead of refusing.
#[tokio::test]
async fn pre_fh_bridge_snapshot_restores_via_upgrade() {
    use stellereum::bridge::BridgeStateV1;
    let mut v1 = BridgeStateV1::default();
    v1.processed_source_txs.insert([0xABu8; 32]);
    v1.next_withdrawal_id = 4;
    v1.hourly_withdrawn = 500;
    v1.escrow_balance = 600;
    let bytes = bincode::serialize(&v1).expect("V1 encodes");

    // The CURRENT decoder must reject these bytes (this pins why the fallback
    // exists - it is not dead code).
    assert!(
        bincode::deserialize::<stellereum::bridge::BridgeState>(&bytes).is_err(),
        "V1 bytes must not decode as the current struct"
    );

    let e = InMemoryStateEngine::new();
    e.restore_bridge(&bytes)
        .await
        .expect("V1 snapshot must restore via upgrade");
    let st = e.bridge_read().await;
    assert!(st.processed_source_txs.contains(&[0xABu8; 32]));
    assert_eq!(st.next_withdrawal_id, 4);
    assert_eq!(st.hourly_withdrawn, 500);
    assert_eq!(st.escrow_balance, 600);
    assert_eq!(st.hourly_deposited, 0);
    assert_eq!(st.total_minted, 0);
    drop(st);
    // ...and the upgraded domain still refuses replays.
    assert!(!e.bridge_read().await.is_empty());
}
