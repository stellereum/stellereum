//! RPC/API/SDK drift regression: pins request/response shapes for
//! live-but-previously-undocumented methods.
//!
//! Coverage:
//! * native manifest advertises exactly 35 methods including the 3 shielded
//!   arms (`src/native_api.rs` `METHODS`);
//! * `stell_shieldedTransfer` / `stell_shieldedBalance` / `stell_unshield`
//!   fail-closed shapes (`-32602` on missing params) and success envelopes;
//! * the same three are reachable over JSON-RPC (not `-32601`);
//! * the EVM / `net_*` / `web3_*` compatibility surface answers its
//!   documented shapes (`src/evm_adapter.rs`).

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;

use stellereum::evm_adapter::EvmAdapter;
use stellereum::mempool::Mempool;
use stellereum::native_api::{self, NATIVE_API_VERSION};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::state_engine::InMemoryStateEngine;

fn engine() -> InMemoryStateEngine {
    InMemoryStateEngine::new()
}

fn rpc_state() -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(engine()),
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "inf1:drift_regression".to_string(),
        chain_id: 5757,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

#[tokio::test]
async fn native_manifest_pins_35_methods_including_shielded() {
    let m = native_api::native_api_manifest();
    assert_eq!(m["version"], json!(NATIVE_API_VERSION));
    let methods = m["methods"].as_array().expect("methods array").clone();
    assert_eq!(methods.len(), 35, "native manifest method count drift");
    assert_eq!(m["method_count"], json!(35));
    for name in [
        "stell_shieldedTransfer",
        "stell_shieldedBalance",
        "stell_unshield",
    ] {
        assert!(
            methods.iter().any(|x| x["name"] == name),
            "manifest must advertise {name}"
        );
    }
    assert_eq!(native_api::METHODS.len(), 35);
    for name in [
        "stell_shieldedTransfer",
        "stell_shieldedBalance",
        "stell_unshield",
    ] {
        assert!(
            native_api::is_native_method(name),
            "{name} must route via native dispatch"
        );
    }
}

#[tokio::test]
async fn shielded_transfer_missing_params_is_invalid_params() {
    let e = engine();
    let err = native_api::dispatch(&e, "stell_shieldedTransfer", &json!({}))
        .await
        .expect_err("empty shielded transfer must refuse");
    assert_eq!(err.code(), -32602);
}

#[tokio::test]
async fn shielded_transfer_prepare_envelope_shape() {
    let e = engine();
    let to = hex::encode([0xabu8; 32]);
    let out = native_api::dispatch(
        &e,
        "stell_shieldedTransfer",
        &json!({"to": to, "amount": 1_000u64}),
    )
    .await
    .expect("plain-recipient shielded prepare must succeed");
    assert_eq!(out["action"], json!("shielded_transfer"));
    assert_eq!(out["submit_with"], json!("stell_sendRawTransaction"));
    assert!(out["gas_limit"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        out["transaction"]["op"],
        json!("SysCallConfidentialShield+SysCallConfidentialTransfer2")
    );
    assert_eq!(out["amount"], json!("1000"));
    assert_eq!(out["to"], json!(to));
    assert!(out["openings"].as_array().is_some());
    assert!(out["gas_breakdown"].is_object());
}

#[tokio::test]
async fn shielded_balance_shapes() {
    let e = engine();
    // Missing viewing key refuses fail-closed.
    let err = native_api::dispatch(&e, "stell_shieldedBalance", &json!({"payloads": []}))
        .await
        .expect_err("missing viewing_key must refuse");
    assert_eq!(err.code(), -32602);

    // Empty inventory scans to zero without echoing the secret.
    let vk = hex::encode([0x09u8; 32]);
    let out = native_api::dispatch(
        &e,
        "stell_shieldedBalance",
        &json!({"viewing_key": vk, "payloads": []}),
    )
    .await
    .expect("empty shielded scan must succeed");
    assert_eq!(out["spendable_sum"], json!("0"));
    assert_eq!(out["coin_count"], json!(0));
    assert_eq!(out["undecryptable"], json!(0));
    assert!(out["view_pub"].as_str().is_some());
    assert!(out.get("viewing_key").is_none(), "secret must not echo");
    assert!(out["chain"]["owned_outputs"].is_number());
}

#[tokio::test]
async fn unshield_missing_params_is_invalid_params() {
    let e = engine();
    let err = native_api::dispatch(&e, "stell_unshield", &json!({}))
        .await
        .expect_err("empty unshield must refuse");
    assert_eq!(err.code(), -32602);

    let to = hex::encode([0xccu8; 32]);
    let err2 = native_api::dispatch(&e, "stell_unshield", &json!({"to": to, "amount": 10u64}))
        .await
        .expect_err("unshield without inputs must refuse");
    assert_eq!(err2.code(), -32602);
}

#[tokio::test]
async fn rpc_router_routes_shielded_and_native_manifest() {
    let st = rpc_state();
    let app = stellereum::rpc::router(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    async fn post(addr: std::net::SocketAddr, method: &str, params: Value) -> Value {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        })
        .to_string();
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let (_, b) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
        serde_json::from_str(b).unwrap()
    }

    // Unknown params on a live method -> -32602 (reachable, not -32601).
    let r = post(addr, "stell_shieldedTransfer", json!({})).await;
    assert_eq!(r["error"]["code"], -32602);

    let r = post(addr, "stell_shieldedBalance", json!({})).await;
    assert_eq!(r["error"]["code"], -32602);

    // Manifest over HTTP pins the same count.
    let r = post(addr, "stell_nativeApi", json!({})).await;
    assert_eq!(r["result"]["method_count"], json!(35));
    let names: Vec<String> = r["result"]["methods"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["name"].as_str().map(str::to_string))
        .collect();
    for n in [
        "stell_shieldedTransfer",
        "stell_shieldedBalance",
        "stell_unshield",
    ] {
        assert!(names.contains(&n.to_string()), "manifest needs {n}");
    }
}

#[tokio::test]
async fn evm_compat_surface_shapes() {
    let a = EvmAdapter::new();
    assert_eq!(
        a.dispatch("eth_chainId", &json!(null)).unwrap(),
        json!("0x167d")
    );
    assert_eq!(
        a.dispatch("net_version", &json!(null)).unwrap(),
        json!("5757")
    );
    assert!(a
        .dispatch("web3_clientVersion", &json!(null))
        .unwrap()
        .is_string());
    assert!(a
        .dispatch("net_listening", &json!(null))
        .unwrap()
        .is_boolean());
    assert!(a
        .dispatch("net_peerCount", &json!(null))
        .unwrap()
        .is_string());
    assert!(a
        .dispatch("eth_syncing", &json!(null))
        .unwrap()
        .is_boolean());
    assert!(a
        .dispatch("eth_gasPrice", &json!(null))
        .unwrap()
        .is_string());
    assert!(a
        .dispatch("eth_maxPriorityFeePerGas", &json!(null))
        .unwrap()
        .is_string());
    // GATE: floor-aware estimate (evm_adapter.rs:16,130) — "0x445c0" = 280k
    // admission floor for transfers. Pure-EVM 0x5208 would under-quote and
    // get the tx refused at admission; the honest estimate covers the floor.
    assert_eq!(
        a.dispatch("eth_estimateGas", &json!([])).unwrap(),
        json!("0x445c0")
    );
    assert!(a
        .dispatch("eth_blockNumber", &json!(null))
        .unwrap()
        .is_string());
    // No uncles on this chain: known blocks report 0x0, unknown hashes are null.
    let zero_hash = format!("0x{}", "00".repeat(32));
    assert_eq!(
        a.dispatch("eth_getUncleCountByBlockHash", &json!([zero_hash]))
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        a.dispatch(
            "eth_getUncleByBlockHashAndIndex",
            &json!([zero_hash, "0x0"])
        )
        .unwrap(),
        Value::Null
    );
    // Filters: create -> bool uninstall round-trip.
    let id = a.dispatch("eth_newBlockFilter", &json!(null)).unwrap();
    assert!(id.as_str().is_some_and(|s| s.starts_with("0x")));
    let un = a.dispatch("eth_uninstallFilter", &json!([id])).unwrap();
    assert_eq!(un, json!(true));
    // Unknown ERC-20 selector echoes 0x.
    let call = a
        .dispatch(
            "eth_call",
            &json!([{"data": "0xdeadbeef00000000"}, "latest"]),
        )
        .unwrap();
    assert_eq!(call, json!("0x"));
}
