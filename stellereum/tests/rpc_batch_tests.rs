//! JSON-RPC batch support (rpc 9.5): HTTP-level coverage.
//!
//! The unit tests in `src/rpc.rs` cover `handle_rpc_batch_call` directly;
//! these tests pin the HTTP wire shapes: arrays in / array out, whole-batch
//! refusals as a single `-32600` object, notifications skipped, `204` for
//! all-notification batches, and single calls still answering with a bare
//! object.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use stellereum::mempool::Mempool;
use stellereum::rpc::{self, ReceiptIndex, RpcState};
use stellereum::state_engine::InMemoryStateEngine;

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

async fn test_rpc_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "inf1:test_node".to_string(),
        chain_id: 5757,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

async fn serve() -> std::net::SocketAddr {
    let st = test_rpc_state().await;
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
    addr
}

#[tokio::test]
async fn batch_happy_mixed_per_item_results() {
    let addr = serve().await;
    let batch = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 2, "method": "stell_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 3, "method": "stell_nopeNotReal", "params": []},
        {"jsonrpc": "2.0", "id": 4, "method": "stell_sendRawTransaction", "params": {}},
        {"jsonrpc": "2.0", "method": "eth_chainId", "params": []},
    ]);
    let (head, body) = http_post(addr, "/", &batch.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let res: Value = serde_json::from_str(&body).unwrap();
    // Array out, request order, notification skipped.
    assert!(res.is_array(), "{res}");
    assert_eq!(res.as_array().unwrap().len(), 4);
    assert_eq!(res[0]["id"], 1);
    assert_eq!(res[0]["result"], "0x167d");
    assert_eq!(res[1]["id"], 2);
    assert_eq!(res[1]["result"], 5757);
    assert_eq!(res[2]["id"], 3);
    assert_eq!(res[2]["error"]["code"], -32601);
    assert_eq!(res[3]["id"], 4);
    assert_eq!(res[3]["error"]["code"], -32602);
}

#[tokio::test]
async fn batch_ordering_follows_request_order() {
    let addr = serve().await;
    let batch = json!([
        {"jsonrpc": "2.0", "id": 30, "method": "stell_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 10, "method": "eth_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 20, "method": "stell_chainId", "params": []},
    ]);
    let (_, body) = http_post(addr, "/", &batch.to_string()).await;
    let res: Value = serde_json::from_str(&body).unwrap();
    let ids: Vec<i64> = res
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, vec![30, 10, 20]);
}

#[tokio::test]
async fn batch_empty_refused_whole() {
    let addr = serve().await;
    let (_, body) = http_post(addr, "/", "[]").await;
    let res: Value = serde_json::from_str(&body).unwrap();
    // Whole-batch refusal is a SINGLE error object, not an array.
    assert!(res.is_object(), "{res}");
    assert_eq!(res["error"]["code"], -32600);
}

#[tokio::test]
async fn batch_oversize_count_refused_whole() {
    let addr = serve().await;
    let items: Vec<Value> = (0..rpc::MAX_RPC_BATCH_ITEMS + 1)
        .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}))
        .collect();
    let (_, body) = http_post(addr, "/", &serde_json::to_string(&items).unwrap()).await;
    let res: Value = serde_json::from_str(&body).unwrap();
    assert!(res.is_object(), "{res}");
    assert_eq!(res["error"]["code"], -32600);
}

#[tokio::test]
async fn batch_all_notifications_yields_no_content() {
    let addr = serve().await;
    let batch = json!([
        {"jsonrpc": "2.0", "method": "eth_chainId", "params": []},
        {"jsonrpc": "2.0", "method": "stell_chainId", "params": []},
    ]);
    let (head, _) = http_post(addr, "/", &batch.to_string()).await;
    assert!(head.contains("204"), "{head}");
}

#[tokio::test]
async fn single_call_still_bare_object() {
    let addr = serve().await;
    let single = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []});
    let (head, body) = http_post(addr, "/", &single.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let res: Value = serde_json::from_str(&body).unwrap();
    assert!(res.is_object(), "{res}");
    assert_eq!(res["result"], "0x167d");
    assert_eq!(res["id"], 1);
}
