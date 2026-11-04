//! WS residual close-out (rpc 8.5->9.0): subscriptions bounded per connection,
//! messages size-capped + rate-limited symmetric to HTTP, stale connections
//! reaped with a live-connection count proving no leak.
//!
//! All tests bind an ephemeral loopback listener only (no live nodes,
//! configs, or external network). Tests in this file share one process-wide
//! subscription hub and per-IP budgets, so they serialize on a mutex.

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use stellereum::mempool::Mempool;
use stellereum::rpc::{
    hub, set_ws_idle_timeout_for_tests, ws_live_connections, ReceiptIndex, RpcState,
    WS_MAX_MESSAGE_BYTES, WS_MAX_SUBS_PER_CONNECTION,
};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "ws:test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
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

async fn serve_ws(st: Arc<RpcState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let app = stellereum::rpc::router(st);
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (addr, server)
}

async fn connect(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
> {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("websocket handshake");
    ws
}

async fn recv_json<S>(ws: &mut S) -> Value
where
    S: StreamExt<
            Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("reply timeout")
        .expect("stream item")
        .expect("frame");
    serde_json::from_str(frame.to_text().expect("text")).expect("json")
}

fn ws_err_of(v: &Value) -> Option<String> {
    v.get("error")?
        .get("message")?
        .as_str()
        .map(|s| s.to_string())
}

/// Poll until `cond` holds (10 ms steps); panic with `what` on timeout.
async fn poll_until(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !cond() {
        if start.elapsed() > timeout {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn ws_subscriptions_capped_per_connection_fail_closed() {
    let _serial = SERIAL.lock().await;
    let st = test_state().await;
    let hub_before = hub().len();
    let (addr, server) = serve_ws(st).await;
    let mut ws = connect(addr).await;

    // Fill the connection: one subscribe per 300 ms stays under the 5/s
    // per-IP expensive-read budget (subscribe draws from it on WS), so every
    // refusal below is the per-CONNECTION cap, not the per-IP budget.
    let mut ids = Vec::new();
    for i in 0..WS_MAX_SUBS_PER_CONNECTION {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc": "2.0", "id": i, "method": "stell_subscribe", "params": ["newHeads"]})
                .to_string(),
        ))
        .await
        .expect("send subscribe");
        let reply = recv_json(&mut ws).await;
        let sid = reply["result"].as_str().unwrap_or_else(|| {
            panic!("subscribe {i} must succeed within the caps: {reply}")
        });
        assert_eq!(sid.len(), 32, "subscription id shape: {reply}");
        ids.push(sid.to_string());
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // The next subscribe on THIS connection is refused fail-closed.
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 1000, "method": "stell_subscribe", "params": ["newHeads"]})
            .to_string(),
    ))
    .await
    .expect("send over-cap subscribe");
    let reply = recv_json(&mut ws).await;
    let e = ws_err_of(&reply).unwrap_or_default();
    assert!(
        e.contains("per-connection"),
        "over-cap subscribe must name the per-connection limit: {reply}"
    );
    assert_eq!(reply["id"], json!(1000), "refusal echoes the id: {reply}");
    // A refused subscribe consumed no registry slot.
    assert_eq!(
        hub().len(),
        hub_before + WS_MAX_SUBS_PER_CONNECTION,
        "refused subs must not leak registry entries"
    );
    // The socket is still alive: a cheap read succeeds after the refusal.
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 1001, "method": "stell_chainId", "params": {}}).to_string(),
    ))
    .await
    .expect("send cheap read");
    let reply = recv_json(&mut ws).await;
    assert_eq!(reply["result"], json!(777), "socket survives refusal: {reply}");
    // Closing drops the connection's subscriptions: no leak.
    let _ = ws.close(None).await;
    poll_until(
        "owned subscriptions reaped on close",
        Duration::from_secs(10),
        || hub().len() == hub_before,
    )
    .await;
    server.abort();
}

#[tokio::test]
async fn ws_oversize_message_refused_socket_survives() {
    let _serial = SERIAL.lock().await;
    let st = test_state().await;
    let (addr, server) = serve_ws(st).await;
    let mut ws = connect(addr).await;

    // Just over the cap: refused, socket stays open.
    let big = "x".repeat(WS_MAX_MESSAGE_BYTES + 8);
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 1, "method": "stell_chainId", "params": {"pad": big}})
            .to_string(),
    ))
    .await
    .expect("send oversize");
    let reply = recv_json(&mut ws).await;
    let e = ws_err_of(&reply).unwrap_or_default();
    assert!(
        e.contains("too large"),
        "oversize frame must be refused as too large: {}",
        &reply.to_string()[..reply.to_string().len().min(200)]
    );
    // Socket alive afterwards: a normal read succeeds.
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 2, "method": "stell_chainId", "params": {}}).to_string(),
    ))
    .await
    .expect("send cheap read");
    let reply = recv_json(&mut ws).await;
    assert_eq!(reply["result"], json!(777), "socket survives refusal: {reply}");
    // Just under the cap parses (proves the bound, not a freeze): an unknown
    // method echoes "method not found" rather than "too large".
    let almost = "y".repeat(WS_MAX_MESSAGE_BYTES - 512);
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 3, "method": "stell_nopeMissing", "params": {"pad": almost}})
            .to_string(),
    ))
    .await
    .expect("send near-cap");
    let reply = recv_json(&mut ws).await;
    let e = ws_err_of(&reply).unwrap_or_default();
    assert!(
        e.contains("method not found"),
        "near-cap frame must parse (unknown method, not too large): {}",
        &reply.to_string()[..reply.to_string().len().min(200)]
    );
    let _ = ws.close(None).await;
    server.abort();
}

#[tokio::test]
async fn ws_idle_connections_reaped_counter_returns_to_baseline() {
    let _serial = SERIAL.lock().await;
    set_ws_idle_timeout_for_tests(1);
    let st = test_state().await;
    let (addr, server) = serve_ws(st).await;
    let baseline = ws_live_connections();

    let mut a = connect(addr).await;
    let mut b = connect(addr).await;
    poll_until(
        "both sessions counted live",
        Duration::from_secs(10),
        || ws_live_connections() == baseline + 2,
    )
    .await;
    // Neither session speaks nor is spoken to: the idle deadline must reap
    // both (server closes the socket) and the counter must return.
    for ws in [&mut a, &mut b] {
        let end = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match ws.next().await {
                    None => break,
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => break,
                    Some(_) => continue,
                }
            }
        })
        .await;
        assert!(end.is_ok(), "server must close the idle socket");
    }
    poll_until(
        "live count returns to baseline after reap",
        Duration::from_secs(10),
        || ws_live_connections() == baseline,
    )
    .await;
    set_ws_idle_timeout_for_tests(0);
    server.abort();
}

#[tokio::test]
async fn ws_active_connection_not_reaped_while_talking() {
    let _serial = SERIAL.lock().await;
    set_ws_idle_timeout_for_tests(1);
    let st = test_state().await;
    let (addr, server) = serve_ws(st).await;
    let baseline = ws_live_connections();

    // A client that keeps talking (a cheap read every 300 ms, well inside
    // the 1 s idle deadline) must NOT be reaped.
    let mut ws = connect(addr).await;
    poll_until(
        "session counted live",
        Duration::from_secs(10),
        || ws_live_connections() == baseline + 1,
    )
    .await;
    for i in 0..6 {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc": "2.0", "id": i, "method": "stell_chainId", "params": {}}).to_string(),
        ))
        .await
        .expect("send keepalive read");
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["result"], json!(777), "keepalive read: {reply}");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(
        ws_live_connections(),
        baseline + 1,
        "an active connection must not be reaped"
    );
    let _ = ws.close(None).await;
    poll_until(
        "live count returns to baseline after close",
        Duration::from_secs(10),
        || ws_live_connections() == baseline,
    )
    .await;
    set_ws_idle_timeout_for_tests(0);
    server.abort();
}
