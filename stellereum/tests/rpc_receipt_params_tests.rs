//! Receipt/status parameter shapes (M6).
//!
//! Standard JSON-RPC clients send positional parameters (`[hash]`), while the
//! Stell wallet/explorer historically used `{"hash": h}` (and the CLI a bare
//! string). All three must resolve the same receipt; only a genuinely absent
//! hash is a parameter error.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;

use stellereum::mempool::Mempool;
use stellereum::rpc::{ReceiptIndex, RpcState, TxReceipt};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;

async fn state() -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "receipt-params-test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

#[tokio::test]
async fn receipt_and_status_accept_object_bare_and_array_hashes() {
    let st = state().await;
    let hash = [0xABu8; 32];
    let hash_hex = hex::encode(hash);
    st.receipts.write().await.insert(TxReceipt {
        tx_hash: hash,
        height: 41,
        block_hash: [0xCDu8; 32],
        index: 3,
        success: true,
        gas_limit: 300_000,
        fee_charged: 1_500,
        raw_tx: None,
        return_value: None,
        gas_used: Some(21_000),
        events: Vec::new(),
        contract_address: None,
    });

    let shapes: [(&str, Value); 3] = [
        ("object", json!({ "hash": hash_hex })),
        ("bare", json!(hash_hex)),
        ("array", json!([hash_hex])),
    ];
    for (name, params) in shapes {
        let r = st.call("stell_getTransactionReceipt", params.clone()).await;
        assert!(
            r.get("error").is_none(),
            "{name} shape must be accepted: {r}"
        );
        assert_eq!(r["tx_hash"], json!(hash_hex), "{name}: {r}");
        assert_eq!(r["height"], json!(41), "{name}: {r}");
        assert_eq!(r["status"], json!("success"), "{name}: {r}");

        let s = st.call("stell_getTransactionStatus", params).await;
        assert_eq!(s["status"], json!("success"), "{name}: {s}");
        assert_eq!(s["height"], json!(41), "{name}: {s}");
    }

    // A genuinely malformed positional shape is still a parameter error.
    let bad = st
        .call("stell_getTransactionReceipt", json!(["not-a-hash"]))
        .await;
    assert!(bad.get("error").is_some(), "malformed hash must be refused");
    let missing = st.call("stell_getTransactionReceipt", json!([])).await;
    assert!(missing.get("error").is_some());
}
