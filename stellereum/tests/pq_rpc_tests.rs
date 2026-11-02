//! PQ registry RPC visibility: `stell_getPqKey` / `stell_getPqRegistryStatus`.
//! Read-only dispatch over the process-wide registry view + engine staking
//! ledger. Deterministic: fixed fills and explicit heights only.

use serde_json::json;
use std::sync::Arc;
use stellereum::consensus::ValidatorId;
use stellereum::governance::Governance;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{PqScheme, FALCON512_PUBKEY_LEN};
use stellereum::pq_registry::{PqRegistry, PQ_KEY_HISTORY_LIMIT, PQ_ROTATION_DELAY_HEIGHTS};
use stellereum::rpc::{pq_registry_handle, ReceiptIndex, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::staking::{StakingLedger, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

fn vid(n: u8) -> ValidatorId {
    [n; 32]
}

fn falcon_key(fill: u8) -> Vec<u8> {
    vec![fill; FALCON512_PUBKEY_LEN]
}

/// The registry view ([`pq_registry_handle`]) is process-wide: these tests
/// must not interleave reset/register/read sequences, so each holds this
/// file-local guard for its whole body (distinct validator ids alone would
/// not survive a concurrent reset wiping the map mid-read).
static TEST_SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn test_state_with_tip(tip: u64) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(stellereum::state_engine::InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(tip)),
        node_id: "pq-rpc:test".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(StakingLedger::new())),
        governance: Arc::new(tokio::sync::RwLock::new(Governance::new())),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn reset_registry() {
    *pq_registry_handle().write().await = PqRegistry::new();
}

async fn bond_and_register(st: &Arc<RpcState>, id: ValidatorId, key: &[u8], at: u64) {
    st.engine
        .staking_write()
        .await
        .bond(id, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .expect("bond must succeed");
    let mut ledger = st.engine.staking_write().await;
    let mut reg = pq_registry_handle().write().await;
    ledger
        .pq_register_key(&mut reg, id, PqScheme::Falcon512, key.to_vec(), at, at)
        .expect("register must succeed");
}

#[tokio::test]
async fn pq_rpc_happy_path_matches_direct_registry_reads() {
    let _serial = TEST_SERIAL.lock().await;
    reset_registry().await;
    let st = test_state_with_tip(50_000);
    let id = vid(0x41);
    let key = falcon_key(0xA5);
    bond_and_register(&st, id, &key, 10).await;

    let direct = {
        let reg = pq_registry_handle().read().await;
        reg.get_active_key(&id, 10).expect("direct read must hit")
    };
    let out = st
        .call("stell_getPqKey", json!({"validator": hex::encode(id)}))
        .await;
    assert_eq!(out["scheme"], json!(PqScheme::Falcon512.name()));
    assert_eq!(out["scheme_id"], json!(PqScheme::Falcon512.id()));
    assert_eq!(out["pubkey_hex"], json!(hex::encode(&direct.1)));
    assert_eq!(out["activated_at"], json!(10u64));

    // Explicit height read matches too.
    let out_h = st
        .call(
            "stell_getPqKey",
            json!({"validator": hex::encode(id), "height": 10u64}),
        )
        .await;
    assert_eq!(out_h["pubkey_hex"], json!(hex::encode(&key)));

    // Status constants are pinned.
    let status = st.call("stell_getPqRegistryStatus", json!({})).await;
    assert_eq!(status["delay_heights"], json!(PQ_ROTATION_DELAY_HEIGHTS));
    assert_eq!(status["delay_heights"], json!(7_200u64));
    assert_eq!(status["history_limit"], json!(PQ_KEY_HISTORY_LIMIT));
    assert!(status["count"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn pq_rpc_unknown_validator_errors_fail_closed() {
    let _serial = TEST_SERIAL.lock().await;
    reset_registry().await;
    let st = test_state_with_tip(50_000);
    let known = vid(0x42);
    bond_and_register(&st, known, &falcon_key(0xB0), 0).await;

    let unknown = vid(0x99);
    let out = st
        .call("stell_getPqKey", json!({"validator": hex::encode(unknown)}))
        .await;
    assert!(
        out.get("error").is_some(),
        "unknown validator must error, got {out}"
    );

    // Malformed validator param is a bad-request error, never a key.
    let bad = st.call("stell_getPqKey", json!({})).await;
    assert!(bad.get("error").is_some(), "missing validator must error");

    // Height above the tip refuses instead of fabricating.
    let above = st
        .call(
            "stell_getPqKey",
            json!({"validator": hex::encode(known), "height": 60_000u64}),
        )
        .await;
    assert!(above.get("error").is_some(), "above-tip height must error");
}

#[tokio::test]
async fn pq_rpc_height_indexed_reads_pre_post_effective() {
    let _serial = TEST_SERIAL.lock().await;
    reset_registry().await;
    let st = test_state_with_tip(50_000);
    let id = vid(0x43);
    let old = falcon_key(0xA5);
    let new = falcon_key(0x5A);
    bond_and_register(&st, id, &old, 10).await;
    {
        let mut ledger = st.engine.staking_write().await;
        let mut reg = pq_registry_handle().write().await;
        ledger
            .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, new.clone(), 100)
            .expect("announce must succeed");
    }
    let eff = 100 + PQ_ROTATION_DELAY_HEIGHTS;

    // Pre-effective: old key (matches direct read).
    let pre = st
        .call(
            "stell_getPqKey",
            json!({"validator": hex::encode(id), "height": eff - 1}),
        )
        .await;
    assert_eq!(pre["pubkey_hex"], json!(hex::encode(&old)));
    // At effective: new key even before apply runs.
    let post = st
        .call(
            "stell_getPqKey",
            json!({"validator": hex::encode(id), "height": eff}),
        )
        .await;
    assert_eq!(post["pubkey_hex"], json!(hex::encode(&new)));

    let direct_pre = {
        let reg = pq_registry_handle().read().await;
        reg.get_active_key(&id, eff - 1).expect("direct pre must hit")
    };
    let direct_post = {
        let reg = pq_registry_handle().read().await;
        reg.get_active_key(&id, eff).expect("direct post must hit")
    };
    assert_eq!(direct_pre.1, old);
    assert_eq!(direct_post.1, new);
}

#[tokio::test]
async fn pq_rpc_pending_rotation_visible_then_clears_on_apply() {
    let _serial = TEST_SERIAL.lock().await;
    reset_registry().await;
    let st = test_state_with_tip(50_000);
    let id = vid(0x44);
    let old = falcon_key(0xA5);
    let new = falcon_key(0x5A);
    bond_and_register(&st, id, &old, 0).await;
    {
        let mut ledger = st.engine.staking_write().await;
        let mut reg = pq_registry_handle().write().await;
        ledger
            .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, new.clone(), 0)
            .expect("announce must succeed");
    }
    let pending_out = st
        .call("stell_getPqKey", json!({"validator": hex::encode(id)}))
        .await;
    assert_eq!(pending_out["pending"]["pubkey_hex"], json!(hex::encode(&new)));
    assert_eq!(
        pending_out["pending"]["effective_height"],
        json!(PQ_ROTATION_DELAY_HEIGHTS)
    );
    assert_eq!(pending_out["pending"]["announced_height"], json!(0u64));

    {
        let mut ledger = st.engine.staking_write().await;
        let mut reg = pq_registry_handle().write().await;
        ledger
            .pq_apply_rotation(&mut reg, id, PQ_ROTATION_DELAY_HEIGHTS)
            .expect("apply must succeed");
    }
    let after = st
        .call(
            "stell_getPqKey",
            json!({"validator": hex::encode(id), "height": PQ_ROTATION_DELAY_HEIGHTS}),
        )
        .await;
    assert_eq!(after["pubkey_hex"], json!(hex::encode(&new)));
    assert!(
        after["pending"].is_null(),
        "pending must clear after apply, got {after}"
    );
}
