//! Local-restore root verification (`load_state_into` / `load_full_state_into`).
//!
//! A snapshot on disk plus the staking/governance domains used to be restored
//! with no comparison against anything: a truncated, corrupt, or wrong-height
//! snapshot loaded silently and the node ran on forged state. `sync::
//! fast_sync_state` already restores into a throwaway engine and requires an
//! exact root match; local restore now does the same, anchored on the
//! already-persisted finalized chain data.
//!
//! THE COMPARISON (H vs H+1): a block's `state_root` commits to the state
//! BEFORE the block applies -- the proposer reads the live root in `propose`
//! (`runtime.rs`), and `validate_proposal`, `adopt_committed`, and the sync
//! replay loop all check the header against the pre-apply root. A snapshot at
//! height S is written AFTER block S finalizes, so it holds the post-S state,
//! which is exactly the pre-state of block S+1. The expected root for snapshot
//! S is therefore the `state_root` of the header/block at S+1. Comparing
//! against S would reject every valid restore whose block changed any state.

use ed25519_dalek::SigningKey;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{load_full_state_into, load_state_into, DomainSnapshot, Storage};
use stellereum::token::TokenMetadata;

const SNAP_H: u64 = 100;
const NEXT_H: u64 = 101;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-restore-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11u8; 32])
}

fn mkblock(height: u64, prev: [u8; 32], state_root: [u8; 32], sk: &SigningKey) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(sk);
    b
}

fn token_meta(minter: [u8; 32]) -> TokenMetadata {
    TokenMetadata {
        name: "Wrapped".into(),
        symbol: "W".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter,
        paused: false,
        description: String::new(),
    }
}

/// Engine holding accounts + one token, as snapshotted right after block
/// SNAP_H finalized (post-S state).
async fn funded_engine() -> (InMemoryStateEngine, [u8; 32], [u8; 32], [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let user = [0xA1u8; 32];
    let minter = [0xB2u8; 32];
    engine.update_account(AccountState::new(user, 50_000)).await;
    engine
        .update_account(AccountState::new(minter, 5_000))
        .await;
    let tid = engine
        .create_token(minter, token_meta(minter), 1_000)
        .await
        .unwrap();
    (engine, user, minter, tid)
}

/// Persist a full valid chain: state+domains at SNAP_H, header/body at
/// SNAP_H+1 carrying the post-SNAP_H root, finalized at NEXT_H.
async fn persist_valid_chain(store: &Storage, engine: &InMemoryStateEngine) -> ([u8; 32], Vec<u8>) {
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let domains = DomainSnapshot::capture(
        engine,
        &stellereum::staking::StakingLedger::new(),
        &stellereum::governance::Governance::new(),
    )
    .await;
    let dbytes = bincode::serialize(&domains).unwrap();
    store.put_state(SNAP_H, &snap).unwrap();
    store.put_domains(SNAP_H, &dbytes).unwrap();
    let sk = test_key();
    let b0 = mkblock(SNAP_H, [0u8; 32], [0xEEu8; 32], &sk);
    let h0 = store.put_block(&b0).unwrap();
    let b1 = mkblock(NEXT_H, h0, root, &sk);
    let h1 = store.put_block(&b1).unwrap();
    store.set_finalized(NEXT_H, &h1).unwrap();
    store.flush().unwrap();
    (root, snap)
}

#[tokio::test]
async fn valid_snapshot_verifies_and_restores_everything() {
    let dir = tmpdir("valid");
    let store = Storage::open(&dir).unwrap();
    let (engine, user, minter, tid) = funded_engine().await;
    let (root, _) = persist_valid_chain(&store, &engine).await;
    drop(store);

    // Reopen: this is a restart reading the data directory back.
    let store = Storage::open(&dir).unwrap();
    let fresh = InMemoryStateEngine::new();
    let (h, _staking, _gov) = load_full_state_into(&store, &fresh)
        .await
        .expect("valid snapshot must verify")
        .expect("snapshot present");
    assert_eq!(h, SNAP_H);
    assert_eq!(fresh.get_account(&user).await.unwrap().balance, 50_000);
    assert_eq!(fresh.token_balance(&tid, &minter).await, 1_000);
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "restored root must equal the anchored root"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn valid_accounts_only_snapshot_verifies() {
    // No domains stored: `load_state_into` itself enforces the root check.
    let dir = tmpdir("acctonly");
    let store = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let user = [0xC3u8; 32];
    engine.update_account(AccountState::new(user, 7_777)).await;
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    store.put_state(SNAP_H, &snap).unwrap();
    let sk = test_key();
    let h0 = store
        .put_block(&mkblock(SNAP_H, [0u8; 32], [0xEEu8; 32], &sk))
        .unwrap();
    let h1 = store.put_block(&mkblock(NEXT_H, h0, root, &sk)).unwrap();
    store.set_finalized(NEXT_H, &h1).unwrap();

    let fresh = InMemoryStateEngine::new();
    let h = load_state_into(&store, &fresh)
        .await
        .expect("valid snapshot must verify");
    assert_eq!(h, Some(SNAP_H));
    assert_eq!(fresh.get_account(&user).await.unwrap().balance, 7_777);
    assert_eq!(fresh.get_state_root().await, root);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn mutated_account_snapshot_is_rejected_and_engine_untouched() {
    let dir = tmpdir("mutated");
    let store = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let user = [0xD4u8; 32];
    engine.update_account(AccountState::new(user, 1_000)).await;
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    store.put_state(SNAP_H, &snap).unwrap();
    let sk = test_key();
    let h0 = store
        .put_block(&mkblock(SNAP_H, [0u8; 32], [0xEEu8; 32], &sk))
        .unwrap();
    let h1 = store.put_block(&mkblock(NEXT_H, h0, root, &sk)).unwrap();
    store.set_finalized(NEXT_H, &h1).unwrap();

    // Attacker/griefed disk: same height, one balance inflated.
    let poison = InMemoryStateEngine::new();
    poison.restore_snapshot(&snap).await.unwrap();
    poison
        .update_account(AccountState::new(user, 999_999_999))
        .await;
    let bad = poison.create_snapshot().await;
    assert_ne!(bad, snap, "the mutation must actually change the bytes");
    store.put_state(SNAP_H, &bad).unwrap();

    let fresh = InMemoryStateEngine::new();
    let err = load_state_into(&store, &fresh)
        .await
        .expect_err("mutated snapshot must be rejected");
    let msg = format!("{err:?}");
    assert!(msg.contains("mismatch"), "loud mismatch error, got: {msg}");
    assert!(
        fresh.get_account(&user).await.is_none(),
        "the live engine must be untouched by a rejected snapshot"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn truncated_snapshot_is_rejected_and_engine_untouched() {
    let dir = tmpdir("trunc");
    let store = Storage::open(&dir).unwrap();
    let (engine, user, _minter, _tid) = funded_engine().await;
    let (_root, snap) = persist_valid_chain(&store, &engine).await;

    let cut = snap.len() / 2;
    assert!(cut > 0, "snapshot must be non-empty");
    store.put_state(SNAP_H, &snap[..cut]).unwrap();

    let fresh = InMemoryStateEngine::new();
    let err = load_full_state_into(&store, &fresh)
        .await
        .expect_err("truncated snapshot must be rejected");
    let msg = format!("{err:?}");
    assert!(msg.contains("restore"), "loud restore error, got: {msg}");
    assert!(
        fresh.get_account(&user).await.is_none(),
        "the live engine must be untouched by a rejected snapshot"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn wrong_height_snapshot_is_rejected() {
    // Snapshot bytes taken from a LATER state but stored under SNAP_H: the
    // root no longer matches the anchor at SNAP_H+1.
    let dir = tmpdir("wrongh");
    let store = Storage::open(&dir).unwrap();
    let (engine, user, _minter, _tid) = funded_engine().await;
    let (root_a, _) = persist_valid_chain(&store, &engine).await;

    engine
        .update_account(AccountState::new(user, 123_456))
        .await;
    let root_b = engine.get_state_root().await;
    assert_ne!(root_a, root_b, "the later state must hash differently");
    let snap_b = engine.create_snapshot().await;
    store.put_state(SNAP_H, &snap_b).unwrap();

    let fresh = InMemoryStateEngine::new();
    let err = load_full_state_into(&store, &fresh)
        .await
        .expect_err("wrong-height snapshot must be rejected");
    let msg = format!("{err:?}");
    assert!(msg.contains("mismatch"), "loud mismatch error, got: {msg}");
    assert!(
        fresh.get_account(&user).await.is_none(),
        "the live engine must be untouched by a rejected snapshot"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn tip_snapshot_without_successor_still_loads() {
    // A snapshot AT the finalized tip has no S+1 header yet, so there is no
    // independent anchor. Rejecting here would strand every node that
    // snapshotted at its tip and restarted; it loads (there is nothing to
    // contradict it).
    let dir = tmpdir("tip");
    let store = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let user = [0xE5u8; 32];
    engine
        .update_account(AccountState::new(user, 314_159))
        .await;
    let snap = engine.create_snapshot().await;
    const TIP: u64 = 77;
    store.put_state(TIP, &snap).unwrap();
    let sk = test_key();
    let hb = store
        .put_block(&mkblock(TIP, [0u8; 32], [0xEEu8; 32], &sk))
        .unwrap();
    store.set_finalized(TIP, &hb).unwrap();

    let fresh = InMemoryStateEngine::new();
    let h = load_state_into(&store, &fresh)
        .await
        .expect("tip snapshot must load");
    assert_eq!(h, Some(TIP));
    assert_eq!(fresh.get_account(&user).await.unwrap().balance, 314_159);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unpaired_snapshots_are_refused_not_frankensteined() {
    // State and domain snapshots are separate enqueued jobs, so a crash between them
    // leaves an unpaired tail. Loading state@H with domains@D!=H builds engine state
    // no anchor can validate -- the exact shape of the live f8f4 fork, where a node
    // resumed on mixed state while believing it had restored height 367. Only the
    // newest PAIRED height may load; anything else is an error, never a silent mix.
    let dir = tmpdir("unpaired");
    let store = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let user = [0xF1u8; 32];
    engine.update_account(AccountState::new(user, 777)).await;
    let snap = engine.create_snapshot().await;
    // State at 100, domains only at 90: no paired height at 100.
    store.put_state(100, &snap).unwrap();
    let sk = test_key();
    let hb = store
        .put_block(&mkblock(101, [0u8; 32], [0xEEu8; 32], &sk))
        .unwrap();
    store.set_finalized(101, &hb).unwrap();

    let fresh = InMemoryStateEngine::new();
    let res = load_full_state_into(&store, &fresh).await;
    assert!(
        res.is_err(),
        "unpaired snapshots must be refused, not mixed into a frankestate"
    );
    assert!(
        fresh.get_account(&user).await.is_none(),
        "the live engine must be untouched by a refused restore"
    );
    std::fs::remove_dir_all(&dir).ok();
}
