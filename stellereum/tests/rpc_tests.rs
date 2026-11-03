//! Targeted tests for RPC hardening, EVM adapter compatibility, and filter manager invariants.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use stellereum::evm_adapter::{
    self as evm, EvmLog, FilterCriteria, FilterManager, CHAIN_ID, CHAIN_ID_HEX, FILTER_TTL_SECS,
    MAX_ACTIVE_FILTERS, MAX_PENDING_PER_FILTER, NET_VERSION, STANDARD_TRANSFER_GAS,
    STANDARD_TRANSFER_GAS_HEX,
};
use stellereum::explorer::{self, GatewayState, ReadinessConfig};
use stellereum::mempool::Mempool;
use stellereum::rpc::{self, ReceiptIndex, RpcState};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::turnstile::CaptchaGate;

async fn http_post_with(
    addr: std::net::SocketAddr,
    path: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("\r\n{body}"));
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, String) {
    http_post_with(addr, path, body, &[]).await
}

async fn test_rpc_state(auth_token: Option<String>) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "inf1:test_node".to_string(),
        chain_id: CHAIN_ID,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

#[tokio::test]
async fn test_evm_chain_id_and_net_version() {
    // Invariant: chain ID is 5757 (0x167d), net_version is "5757"
    assert_eq!(CHAIN_ID, 5757);
    assert_eq!(CHAIN_ID_HEX, "0x167d");
    assert_eq!(NET_VERSION, "5757");

    assert_eq!(evm::eth_chain_id(), "0x167d");
    assert_eq!(evm::net_version(), "5757");

    let adapter = evm::EvmAdapter::new();
    let res_chain = adapter
        .dispatch("eth_chainId", &Value::Null)
        .expect("eth_chainId");
    assert_eq!(res_chain, json!("0x167d"));

    let res_net = adapter
        .dispatch("net_version", &Value::Null)
        .expect("net_version");
    assert_eq!(res_net, json!("5757"));
}

#[tokio::test]
async fn test_evm_block_number() {
    let st = test_rpc_state(None).await;
    let bnum = evm::eth_block_number_rpc(&st);
    assert_eq!(bnum, "0x64"); // 100 in hex

    st.height.store(5757, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(evm::eth_block_number_rpc(&st), "0x167d");
}

#[tokio::test]
async fn test_evm_get_balance() {
    let st = test_rpc_state(None).await;
    let user_bytes = [7u8; 32];
    // 5 STELL = 5_000_000_000 nanoSTELL = 5 * 10^18 Wei
    let nano_bal = 5_000_000_000u64;
    st.engine
        .update_account(AccountState::new(user_bytes, nano_bal))
        .await;

    let hex_addr = format!("0x{}", hex::encode(user_bytes));
    let params = json!([hex_addr, "latest"]);

    let bal_hex = evm::eth_get_balance_rpc(&st, &params)
        .await
        .expect("get balance");
    // 5 * 10^18 = 0x4563918244f40000
    assert_eq!(bal_hex, "0x4563918244f40000");

    // Zero balance for unknown account
    let empty_addr = format!("0x{}", hex::encode([9u8; 32]));
    let empty_bal = evm::eth_get_balance_rpc(&st, &json!([empty_addr, "latest"]))
        .await
        .expect("empty balance");
    assert_eq!(empty_bal, "0x0");
}

#[tokio::test]
async fn test_evm_call_erc20_stubs() {
    let adapter = evm::EvmAdapter::new();

    // 1. ERC-20 transfer (0xa9059cbb) -> abi encoded true
    let transfer_calldata = format!("0xa9059cbb{:0>64}{:0>64}", "11223344", "100");
    let res_transfer = adapter
        .dispatch(
            "eth_call",
            &json!([{ "data": transfer_calldata }, "latest"]),
        )
        .expect("transfer stub");
    assert_eq!(
        res_transfer,
        json!("0x0000000000000000000000000000000000000000000000000000000000000001")
    );

    // 2. ERC-20 approve (0x095ea7b3) -> abi encoded true
    let approve_calldata = format!("0x095ea7b3{:0>64}{:0>64}", "11223344", "ffff");
    let res_approve = adapter
        .dispatch("eth_call", &json!([{ "data": approve_calldata }, "latest"]))
        .expect("approve stub");
    assert_eq!(
        res_approve,
        json!("0x0000000000000000000000000000000000000000000000000000000000000001")
    );

    // 3. ERC-20 allowance (0xdd62ed3e) -> abi encoded u128::MAX
    let allowance_calldata = format!("0xdd62ed3e{:0>64}{:0>64}", "11223344", "55667788");
    let res_allowance = adapter
        .dispatch(
            "eth_call",
            &json!([{ "data": allowance_calldata }, "latest"]),
        )
        .expect("allowance stub");
    assert_eq!(
        res_allowance,
        json!("0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    );

    // 4. Unknown selector -> "0x"
    let unknown_calldata = "0xdeadbeef00000000";
    let res_unknown = adapter
        .dispatch("eth_call", &json!([{ "data": unknown_calldata }, "latest"]))
        .expect("unknown selector");
    assert_eq!(res_unknown, json!("0x"));
}

#[tokio::test]
async fn test_evm_estimate_gas_21k() {
    assert_eq!(STANDARD_TRANSFER_GAS, 21_000);
    assert_eq!(STANDARD_TRANSFER_GAS_HEX, "0x5208");

    let adapter = evm::EvmAdapter::new();

    // Standard transfer with empty params or simple object -> 21,000 ("0x5208")
    // F4 design (audit closure): the SERVED eth_estimateGas path applies the
    // 280k admission floor, so it returns 0x445c0, not pure 0x5208. The pure
    // amount lives in eth_estimate_gas_amount (pinned elsewhere).
    let est_empty = adapter
        .dispatch("eth_estimateGas", &json!([]))
        .expect("empty estimate");
    assert_eq!(est_empty, json!("0x445c0"));

    let est_tx = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "value": "0x1000"
            }]),
        )
        .expect("transfer estimate");
    assert_eq!(est_tx, json!("0x445c0"));

    // Calldata gas: pure would be 21,000 + 4 * 16 = 21,064 = 0x5248, but the
    // served path floors at 0x445c0 (F4) and pure < floor, so floor wins.
    let est_call = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0xdeadbeef"
            }]),
        )
        .expect("calldata estimate");
    assert_eq!(est_call, json!("0x445c0"));
}

#[tokio::test]
async fn test_filter_manager_security_invariants() {
    assert_eq!(FILTER_TTL_SECS, 300);
    assert_eq!(MAX_PENDING_PER_FILTER, 1_000);
    assert_eq!(MAX_ACTIVE_FILTERS, 10_000);

    let fm = FilterManager::new();

    // 1. Cryptographic 64-bit random filter IDs
    let id1 = fm.new_block_filter();
    let id2 = fm.new_pending_transaction_filter();
    let id3 = fm.new_filter(FilterCriteria::default());

    assert!(id1.starts_with("0x"));
    assert!(id2.starts_with("0x"));
    assert!(id3.starts_with("0x"));
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);

    // 2. Pending queue bounds (MAX_PENDING_PER_FILTER = 1,000)
    for i in 0..1200 {
        fm.notify_block_hash(format!("0x{:064x}", i));
    }
    let changes = fm.get_filter_changes(&id1).expect("changes");
    let arr = changes.as_array().expect("array");
    assert_eq!(arr.len(), 1_000, "pending blocks must be capped to 1000");

    // 3. Log filter pending queue bounds
    for i in 0..1100 {
        fm.notify_log(EvmLog {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            topics: vec![],
            data: format!("0x{:x}", i),
            block_number: Some("0x1".to_string()),
            transaction_hash: Some("0xabc".to_string()),
            transaction_index: Some("0x0".to_string()),
            block_hash: Some("0xdef".to_string()),
            log_index: Some(format!("0x{:x}", i)),
            removed: false,
        });
    }
    let log_changes = fm.get_filter_changes(&id3).expect("log changes");
    assert_eq!(
        log_changes.as_array().unwrap().len(),
        1_000,
        "pending logs capped to 1000"
    );

    // 4. Uninstall filter
    assert!(fm.uninstall_filter(&id1));
    assert!(
        fm.get_filter_changes(&id1).is_err(),
        "uninstalled filter must return error"
    );
}

#[tokio::test]
async fn test_rpc_hardening_body_limit_and_batches() {
    let st = test_rpc_state(None).await;
    let app = rpc::router(st);

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

    // 1. Normal request passes
    let valid_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": []
    });
    let (head, body) = http_post(addr, "/", &valid_req.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    let res: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(res["result"], "0x167d");

    // 2. Batch requests are SERVED per-item (JSON-RPC batch support with
    // caps: MAX_RPC_BATCH_ITEMS=64, bytes<=MAX_RPC_BODY). One-item batch of
    // a valid call returns an array with that call's result.
    let batch_req = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [] }
    ]);
    let (_, body_batch) = http_post(addr, "/", &batch_req.to_string()).await;
    let res_batch: Value = serde_json::from_str(&body_batch).unwrap();
    assert!(res_batch.is_array(), "batch must return an array");
    assert_eq!(res_batch[0]["result"], "0x167d");
    assert_eq!(res_batch[0]["id"], 1);

    // 3. Body exceeding 1 MiB is rejected
    // 1 MiB + 100 bytes payload
    let giant_str = "x".repeat(1024 * 1024 + 100);
    let giant_req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["{}"]}}"#,
        giant_str
    );
    let (head_giant, _) = http_post(addr, "/", &giant_req).await;
    // DefaultBodyLimit in Axum rejects oversized requests before buffering (413 Payload Too Large)
    assert!(
        head_giant.contains("413") || head_giant.contains("400"),
        "Oversized request must be rejected, got response headers:\n{head_giant}"
    );
}

#[tokio::test]
async fn test_fail_closed_mempool_dump() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 1. When auth_token is None -> FAIL-CLOSED
    let st_no_auth = test_rpc_state(None).await;
    let app_no_auth = rpc::router(st_no_auth);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app_no_auth.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "stell_mempoolDump",
        "params": {}
    });
    let (_, body) = http_post(addr, "/", &req.to_string()).await;
    let res: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(res["error"]["code"], -32001);
    assert!(
        res["error"]["message"]
            .as_str()
            .unwrap()
            .contains("disabled when auth_token is not configured"),
        "mempoolDump must fail closed without auth_token"
    );

    // 2. When auth_token is configured -> unauthorized with bad token
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let st_auth = test_rpc_state(Some("supersecret".to_string())).await;
    let app_auth = rpc::router(st_auth);
    tokio::spawn(async move {
        axum::serve(
            listener2,
            app_auth.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let req_bad = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "stell_mempoolDump",
        "params": { "token": "wrongtoken" }
    });
    let (_, body_bad) = http_post(addr2, "/", &req_bad.to_string()).await;
    let res_bad: Value = serde_json::from_str(&body_bad).unwrap();
    assert_eq!(res_bad["error"]["code"], -32001);
    assert!(res_bad["error"]["message"]
        .as_str()
        .unwrap()
        .contains("invalid API token"));

    // 3. Authorized request succeeds
    let req_good = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "stell_mempoolDump",
        "params": { "token": "supersecret" }
    });
    let (_, body_good) = http_post(addr2, "/", &req_good.to_string()).await;
    let res_good: Value = serde_json::from_str(&body_good).unwrap();
    assert!(res_good["result"].is_array());
}

#[tokio::test]
async fn test_rpc_cors_headers_on_gateway() {
    let st = test_rpc_state(None).await;
    let gw = Arc::new(GatewayState::with_captcha(
        st,
        1000,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::disabled()),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gw).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": []
    });

    let (head, _) = http_post_with(
        addr,
        "/rpc",
        &req.to_string(),
        &[("Origin", "http://localhost:3000")],
    )
    .await;

    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head
        .to_lowercase()
        .contains("access-control-allow-origin: *"));
    assert!(head
        .to_lowercase()
        .contains("access-control-allow-headers: content-type"));
}
