//! §7 Phase 1 "remove non-transport milliseconds": snapshot serialization left
//! the consensus tick (and the engine's read lock) and moved to the blocking
//! pool, so the bytes it produces are pinned here.
//!
//! The rule the change must not break: for the SAME engine state the off-tick
//! path must produce the SAME bytes the old inline path produced -- on disk and
//! on the wire. A snapshot whose bytes change is a state root that changes, and
//! `Storage::verify_restored_root` would then refuse every honest restore.
//!
//! The tick-side primitives themselves (fire-and-forget save, single-flight
//! prune, the ordered lanes) live in `src/main.rs` and are covered by
//! `mod tick_offload_tests` there -- integration tests cannot reach a binary
//! crate's items.

use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    clone_account_snapshot, serialize_off_tick, AsyncPersistence, DomainSnapshot, Storage,
};
use stellereum::token::TokenMetadata;
use std::path::PathBuf;
use std::sync::Arc;

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "stell_tick_offload_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ))
}

/// An engine with a non-trivial account set (64 funded accounts).
async fn engine_with_accounts() -> InMemoryStateEngine {
    let engine = InMemoryStateEngine::new();
    for i in 0..64u8 {
        engine
            .update_account(AccountState::new([i; 32], 1_000 + i as u64))
            .await;
    }
    engine
}

/// A registry entry so the DOMAIN snapshot is not an empty struct.
async fn tokenise(engine: &InMemoryStateEngine) {
    let who = [7u8; 32];
    let meta = TokenMetadata {
        name: "Wrapped".into(),
        symbol: "W".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: who,
        paused: false,
        description: String::new(),
    };
    engine.create_token(who, meta, 1_000).await.expect("token");
}

/// THE golden pin: `clone_account_snapshot` + `serialize_off_tick` (the off-tick
/// path the finalize loop now uses) must byte-for-byte equal
/// `InMemoryStateEngine::create_snapshot` (the inline path it replaced).
#[tokio::test]
async fn off_tick_snapshot_bytes_are_identical_to_create_snapshot() {
    let engine = engine_with_accounts().await;
    let root = engine.get_state_root().await;

    let before = engine.create_snapshot().await;
    let accounts = clone_account_snapshot(&engine).await;
    let after = serialize_off_tick(accounts)
        .await
        .expect("bincode of a Vec<AccountState> cannot fail");

    assert_eq!(
        before, after,
        "the off-tick encode must produce the exact bytes the inline encode produced"
    );
    assert!(!before.is_empty());

    // And those bytes still restore to the same state (and therefore root).
    let restored = InMemoryStateEngine::new();
    restored.restore_snapshot(&after).await.expect("restore");
    assert_eq!(restored.get_state_root().await, root);
    assert_eq!(
        restored.get_account(&[0u8; 32]).await.map(|a| a.balance),
        Some(1_000),
        "the bytes carry the accounts"
    );
}

/// The capture instant decides the bytes: cloning first and encoding later
/// must snapshot the state AT THE CLONE, not at the encode. This is what lets
/// the tick capture a snapshot and hand the (slow) encode to the blocking pool
/// without a later height's state leaking into a snapshot labeled `height`.
#[tokio::test]
async fn snapshot_bytes_are_frozen_at_the_capture_instant() {
    let engine = engine_with_accounts().await;

    let accounts = clone_account_snapshot(&engine).await;
    // State moves on AFTER the capture ...
    engine
        .update_account(AccountState::new([0xAA; 32], 999_999))
        .await;
    engine
        .update_account(AccountState::new([0u8; 32], 42))
        .await;

    let bytes = serialize_off_tick(accounts).await.expect("encode");
    let restored = InMemoryStateEngine::new();
    restored.restore_snapshot(&bytes).await.expect("restore");

    assert!(
        restored.get_account(&[0xAAu8; 32]).await.is_none(),
        "a post-capture account must not appear in the snapshot"
    );
    assert_eq!(
        restored.get_account(&[0u8; 32]).await.map(|a| a.balance),
        Some(1_000),
        "the snapshot is the state as it stood at capture time"
    );
}

/// What actually lands on disk through `AsyncPersistence::snapshot_state`
/// (the path the node's startup restore uses) must be the same bytes.
#[tokio::test]
async fn snapshot_state_written_to_disk_is_byte_identical() {
    let dir = tmp();
    let _ = std::fs::remove_dir_all(&dir);
    let store = Arc::new(Storage::open(&dir).expect("open storage"));
    let ap = AsyncPersistence::start(store.clone());

    let engine = engine_with_accounts().await;
    let expected = engine.create_snapshot().await;

    ap.snapshot_state(&engine, 7).await;
    ap.request_flush();

    // The background writer runs the enqueued job; poll like the persistence
    // tests do.
    let mut got: Option<Vec<u8>> = None;
    for _ in 0..500 {
        if let Ok(Some(bytes)) = store.get_state(7) {
            got = Some(bytes);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        got.expect("state snapshot must be written"),
        expected,
        "on-disk snapshot bytes must equal the inline `create_snapshot` bytes"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Same pin for the domain snapshot: `snapshot_domains` now serializes on the
/// blocking pool, and the bytes it enqueues must equal an inline
/// `bincode::serialize(&DomainSnapshot::capture(..))` of the same state.
#[tokio::test]
async fn snapshot_domains_bytes_written_to_disk_are_byte_identical() {
    let dir = tmp();
    let _ = std::fs::remove_dir_all(&dir);
    let store = Arc::new(Storage::open(&dir).expect("open storage"));
    let ap = AsyncPersistence::start(store.clone());

    let engine = engine_with_accounts().await;
    tokenise(&engine).await;
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();

    // The inline (old) encoding of exactly this state.
    let expected = bincode::serialize(&DomainSnapshot::capture(&engine, &staking, &gov).await)
        .expect("inline encode");

    ap.snapshot_domains(&engine, &staking, &gov, 7).await;
    ap.request_flush();

    let mut got: Option<Vec<u8>> = None;
    for _ in 0..500 {
        if let Ok(Some((h, bytes))) = store.latest_domains() {
            if h == 7 {
                got = Some(bytes);
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        got.expect("domain snapshot must be written"),
        expected,
        "on-disk domain bytes must equal the inline encode of the same capture"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
