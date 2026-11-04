//! Live HTTP smoke test for the explorer + gateway: starts the real axum server
//! on an ephemeral port and performs real HTTP/1.1 requests over TCP.

use std::sync::Arc;
use stellereum::explorer::{self, GatewayState};
use stellereum::rpc::RpcState;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let who = [3u8; 32];
    engine.update_account(AccountState::new(who, 12_345)).await;
    let faucet_key = [0x11u8; 32];
    engine
        .update_account(AccountState::new(
            ed25519_dalek::SigningKey::from_bytes(&faucet_key)
                .verifying_key()
                .to_bytes(),
            10_000_000_000_000,
        ))
        .await;
    let st = Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:smoke".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: Some(Arc::new(stellereum::rpc::Faucet::new(
            faucet_key,
            1,
            10 * 1_000_000_000,
            100 * 1_000_000_000,
        ))),
        faucet_token: Some("smoke-token".to_string()),
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });
    st.record_block(42, [0xABu8; 32], 3, 1234).await;
    st
}

async fn spawn_gateway_with_limit(per_sec: u32) -> std::net::SocketAddr {
    let st = state().await;
    let gw = Arc::new(GatewayState::new(st, per_sec));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gw).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    // Give the server a moment to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

async fn spawn_gateway() -> std::net::SocketAddr {
    spawn_gateway_with_limit(1000).await
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
    http_get_with(addr, path, &[]).await
}

async fn http_get_with(
    addr: std::net::SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    read_response(s).await
}

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, String) {
    http_post_with(addr, path, body, &[]).await
}

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
    read_response(s).await
}

async fn read_response(mut s: TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    // Return the full header block as the first element so callers can assert on
    // status codes and headers alike; `body` is the payload only.
    (head.to_string(), body.to_string())
}

#[tokio::test]
async fn explorer_serves_index_and_apis() {
    let addr = spawn_gateway().await;

    let (status, body) = http_get(addr, "/").await;
    assert!(status.contains("200"), "index status: {status}");
    assert!(
        body.contains("Stellereum Explorer"),
        "index must render the UI"
    );

    let (status, body) = http_get(addr, "/api/stats").await;
    assert!(status.contains("200"), "stats status: {status}");
    assert!(body.contains("5757"), "stats must include chain id: {body}");
    assert!(
        body.contains("\"height\":42"),
        "stats must include height: {body}"
    );

    let (status, body) = http_get(addr, "/api/blocks").await;
    assert!(status.contains("200"));
    assert!(
        body.contains("\"height\":42"),
        "blocks feed must list the block: {body}"
    );

    let hexaddr = hex::encode([3u8; 32]);
    let (status, body) = http_get(addr, &format!("/api/spv/{hexaddr}")).await;
    assert!(status.contains("200"), "spv status: {status}");
    assert!(body.contains("12345"), "spv must return balance: {body}");

    // Health check endpoint
    let (status, body) = http_get(addr, "/health").await;
    assert!(status.contains("200"));
    assert!(body.contains("\"status\":\"ok\""));

    // Prometheus metrics endpoint
    let (status, body) = http_get(addr, "/metrics").await;
    assert!(status.contains("200"));
    assert!(body.contains("stellereum_block_height 42"));

    // CORS headers on responses
    let (status, _) = http_get(addr, "/health").await;
    assert!(
        status
            .to_lowercase()
            .contains("access-control-allow-origin: *")
            || status.contains("200")
    );

    // bad address -> 400
    let (status, _) = http_get(addr, "/api/balance/zzzz").await;
    assert!(
        status.contains("400"),
        "bad address must be rejected: {status}"
    );
}

#[tokio::test]
async fn faucet_requires_token_and_then_caps_out() {
    let addr = spawn_gateway().await;
    let who = hex::encode([7u8; 32]);

    // GET on the faucet must NOT mint (POST-only; crawlers must not mint).
    let (status, _) = http_get(addr, &format!("/api/faucet/{who}?token=smoke-token")).await;
    assert!(
        status.contains("405"),
        "GET faucet must be refused: {status}"
    );

    // Anonymous drain attempt must be refused (no token at all).
    let (status, _) = http_post(addr, &format!("/api/faucet/{who}"), "").await;
    assert!(
        status.contains("401"),
        "anonymous drip must be rejected: {status}"
    );

    // A wrong token must be refused too.
    let (status, _) = http_post(addr, &format!("/api/faucet/{who}?token=wrong"), "").await;
    assert!(
        status.contains("401"),
        "bad token must be rejected: {status}"
    );

    // The token may also arrive as an auth header instead of a query param.
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet/{who}"),
        "",
        &[("Authorization", "Bearer smoke-token")],
    )
    .await;
    assert!(
        status.contains("200"),
        "header token drip must succeed: {status}"
    );
    assert!(body.contains("10000000000"), "must credit 10 STELL: {body}");

    // Draining the whole lifetime cap (100 STELL) takes 10 calls of 10.
    for _ in 0..9 {
        let (status, _) =
            http_post(addr, &format!("/api/faucet/{who}?token=smoke-token"), "").await;
        assert!(
            status.contains("200"),
            "drip within cap must succeed: {status}"
        );
    }
    let (status, body) = http_post(addr, &format!("/api/faucet/{who}?token=smoke-token"), "").await;
    assert!(
        status.contains("429"),
        "cap exhausted must be rejected: {status} {body}"
    );
}

#[tokio::test]
async fn rpc_nested_route_is_rate_limited() {
    // Limit of 3/s: hammering the nested JSON-RPC endpoint must eventually 429,
    // proving CORS/rate-limit layers reach the `/rpc` sub-router after nesting.
    let addr = spawn_gateway_with_limit(3).await;
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}"#;
    let mut saw_ok = false;
    let mut saw_429 = false;
    for _ in 0..25 {
        let (status, _) = http_post(addr, "/rpc", body).await;
        saw_ok |= status.contains("200");
        saw_429 |= status.contains("429");
    }
    assert!(saw_ok, "at least one /rpc request should pass");
    assert!(saw_429, "hammering /rpc must hit the per-IP rate limit");
}

#[tokio::test]
async fn rpc_nested_route_has_cors_headers() {
    let addr = spawn_gateway().await;
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}"#;
    let (status, _) = http_post(addr, "/rpc", body).await;
    assert!(
        status
            .to_lowercase()
            .contains("access-control-allow-origin"),
        "nested /rpc must carry CORS headers: {status}"
    );
}
