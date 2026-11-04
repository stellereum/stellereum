//! End-to-end check of the streaming transports over a REAL socket.
//!
//! The unit tests in `src/rpc.rs` cover the subscription lifecycle and the
//! fan-out; this file checks the part only a real HTTP connection can show:
//! that `GET /events` really answers `text/event-stream` and that the frames
//! are framed as `data: {json}\n\n` on the wire (chunked transfer encoding
//! included).

use std::sync::Arc;
use std::time::Duration;

use stellereum::mempool::Mempool;
use stellereum::rpc::{self, ReceiptIndex, RpcState};
use stellereum::state_engine::InMemoryStateEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

fn test_state() -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        node_id: "test".to_string(),
        chain_id: 7,
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

/// Read the HTTP response until it carries an SSE frame (or the deadline).
async fn read_until_frame(sock: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut chunk = [0u8; 4096];
    while tokio::time::Instant::now() < deadline {
        let n = match tokio::time::timeout(Duration::from_secs(3), sock.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if String::from_utf8_lossy(&buf).contains("data: ") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn sse_endpoint_streams_event_stream_frames() {
    let st = test_state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = rpc::router(st.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    sock.write_all(
        b"GET /events?topics=newHeads HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n",
    )
    .await
    .expect("request");

    // A finalized head is pushed to the stream.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        rpc::publish_new_head(99, [0x5Au8; 32], 0, 1, 1_700_000_999);
    });

    let raw = read_until_frame(&mut sock).await;
    assert!(raw.contains("200 OK"), "status line, got: {raw}");
    assert!(
        raw.contains("text/event-stream"),
        "content type, got: {raw}"
    );
    assert!(raw.contains("data: {"), "SSE data frame, got: {raw}");
    assert!(raw.contains("\"height\":99"), "head payload, got: {raw}");
    assert!(
        raw.contains("\"finality\":\"finalized\""),
        "finality tag, got: {raw}"
    );
    assert!(raw.contains("\"shard_id\":0"), "shard id, got: {raw}");
}

#[tokio::test]
async fn sse_endpoint_reports_an_unknown_subscription() {
    let st = test_state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = rpc::router(st.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    sock.write_all(b"GET /events?sub_id=deadbeef HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk))
        .await
        .expect("timeout")
        .expect("read");
    buf.extend_from_slice(&chunk[..n]);
    let raw = String::from_utf8_lossy(&buf).to_string();
    assert!(
        raw.contains("404"),
        "unknown subscription must be a 404, got: {raw}"
    );
}
