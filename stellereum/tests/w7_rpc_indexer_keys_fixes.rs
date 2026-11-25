//! Wave 7 regression tests for Wave 6 RPC, SSE/WS, Bootstrap, and Key/Config fixes:
//! - W6-A5-1: SSE global, per-IP/bucket, and per-subscription attach RAII caps.
//! - W6-A5-2: Heavy RPC offloading (`stell_runGetMethod`, `stell_getProof`,
//!   `stell_getArchiveProof`, `stell_estimateFee`) + per-IP expensive-read
//!   token bucket & concurrency cap alongside `http_expensive_read_semaphore`.
//! - W6-A5-3/4: `STREAM_BROADCAST_CAPACITY == 8192`, `WS_MAX_CONNECTIONS_PER_IP == 32`
//!   RAII guard, and `WS_WRITE_TIMEOUT` closing slow consumers cleanly.
//! - W6-A6-4: `store bootstrap` refuses unexpected top-level dirs (e.g. `keys/`).
//! - W6-A6-6: `node_keys` malformed `enc2:` nonce returns `Err` (no panic) and refuses
//!   plaintext `validator.key` migration unless `STELL_KEY_PLAINTEXT=1`.
//! - W6-A8-15: `node_config::validate()` rejects non-loopback `http://`
//!   `remote_signer_url` when `remote_signer_token` is configured.

use axum::extract::Query;
use axum::http::StatusCode;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use stellereum::explorer::{self, GatewayState, ReadinessConfig};
use stellereum::mempool::Mempool;
use stellereum::node_config::NodeTomlConfig;
use stellereum::node_keys::{
    decrypt_bytes, load_node_keys, load_or_generate_consensus_key, write_private_file,
    ENV_PASSPHRASE, ENV_PASSPHRASE_ALT, ENV_PLAINTEXT, FALLBACK_ENV_PASSPHRASE,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::rpc::{
    hub, is_ws_expensive_method, publish_new_head, router as rpc_router,
    set_sse_max_connections_for_tests, set_sse_max_connections_per_client_for_tests,
    set_ws_max_connections_per_ip_for_tests, set_ws_write_timeout_ms_for_tests,
    sse_active_connections, sse_client_connections, sse_handler,
    try_acquire_http_expensive_read_with_ip, ws_active_connections, ws_ip_connections, Faucet,
    ReceiptIndex, RpcState, StreamQuery, SubscriptionTopic, HTTP_EXPENSIVE_READ_BURST_DEFAULT,
    HTTP_EXPENSIVE_READ_MAX_PER_IP, MAX_ATTACHED_PER_SUB, MAX_SUBSCRIPTIONS, SSE_MAX_CONNECTIONS,
    SSE_MAX_CONNECTIONS_PER_CLIENT, STREAM_BROADCAST_CAPACITY, WS_MAX_CONNECTIONS_PER_IP,
    WS_WRITE_TIMEOUT,
};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::Storage;
use stellereum::turnstile::CaptchaGate;

static ASYNC_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static ENV_SERIAL: Mutex<()> = Mutex::new(());
static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct SseOverrideReset;
impl Drop for SseOverrideReset {
    fn drop(&mut self) {
        set_sse_max_connections_for_tests(0);
        set_sse_max_connections_per_client_for_tests(0);
    }
}

struct WsOverrideReset;
impl Drop for WsOverrideReset {
    fn drop(&mut self) {
        set_ws_max_connections_per_ip_for_tests(0);
        set_ws_write_timeout_ms_for_tests(0);
    }
}

struct KeyEnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl KeyEnvGuard {
    fn new() -> Self {
        let vars = [
            ENV_PASSPHRASE,
            ENV_PASSPHRASE_ALT,
            FALLBACK_ENV_PASSPHRASE,
            ENV_PLAINTEXT,
        ];
        let saved = vars.iter().map(|&k| (k, std::env::var(k).ok())).collect();
        for &k in &vars {
            std::env::remove_var(k);
        }
        Self { saved }
    }
}

impl Drop for KeyEnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

struct TempDirCleanup(PathBuf);

impl TempDirCleanup {
    fn new(tag: &str) -> Self {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("stell-w7-{tag}-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn test_rpc_state(archive_store: Option<Arc<Storage>>) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    let faucet = Arc::new(Faucet::new([0x44u8; 32], 1, 10, 1_000_000_000));
    engine
        .update_account(AccountState::new(faucet.account(), 1_000_000_000_000_000))
        .await;
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(AtomicU64::new(1)),
        node_id: "w7-test-node".to_string(),
        chain_id: 5757,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: Some(faucet),
        faucet_token: Some("w7-faucet-tok".to_string()),
        msg_signing_seed: None,
        archive_store,
        shard_registry: ShardRegistry::single(),
    })
}

async fn serve_router(app: axum::Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    (addr, handle)
}

async fn poll_until(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !cond() {
        assert!(start.elapsed() < timeout, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn new_heads_query() -> Query<StreamQuery> {
    Query(StreamQuery {
        sub_id: None,
        topics: Some("newHeads".to_string()),
        contract: None,
        event_topics: None,
    })
}

// ===========================================================================
// W6-A5-1: SSE global, per-IP/bucket, and per-subscription RAII caps
// ===========================================================================

#[tokio::test]
async fn w6_a5_1_sse_enforces_global_per_client_and_per_sub_raii_caps() {
    let _serial = ASYNC_SERIAL.lock().await;
    let _reset = SseOverrideReset;

    assert_eq!(SSE_MAX_CONNECTIONS, 1024);
    assert_eq!(SSE_MAX_CONNECTIONS_PER_CLIENT, 64);
    assert_eq!(MAX_ATTACHED_PER_SUB, 8);

    // 1. Per-subscription attach cap (`MAX_ATTACHED_PER_SUB = 8`).
    let ip_v6_1: Ipv6Addr = "2001:db8:7777:1::1".parse().unwrap();
    let ip_v6_same_64: Ipv6Addr = "2001:db8:7777:1::99".parse().unwrap();
    let client_exact = IpAddr::V6(ip_v6_1).to_string();
    let sub_id = hub()
        .subscribe_for(SubscriptionTopic::NewHeads, Some(&client_exact))
        .expect("create sub");

    let mut attached_streams = Vec::new();
    for i in 0..MAX_ATTACHED_PER_SUB {
        let peer = SocketAddr::new(IpAddr::V6(ip_v6_1), 10_000 + i as u16);
        let resp = sse_handler(
            axum::http::HeaderMap::new(),
            Some(axum::extract::ConnectInfo(peer)),
            Query(StreamQuery {
                sub_id: Some(sub_id.clone()),
                topics: None,
                contract: None,
                event_topics: None,
            }),
        )
        .await
        .expect("within MAX_ATTACHED_PER_SUB");
        attached_streams.push(resp);
    }
    let over_sub = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V6(ip_v6_1),
            10_100,
        ))),
        Query(StreamQuery {
            sub_id: Some(sub_id.clone()),
            topics: None,
            contract: None,
            event_topics: None,
        }),
    )
    .await;
    assert_eq!(
        over_sub.err(),
        Some(StatusCode::TOO_MANY_REQUESTS),
        "9th attach to the same subscription must return 429"
    );
    assert_eq!(
        sse_client_connections(IpAddr::V6(ip_v6_1)),
        MAX_ATTACHED_PER_SUB
    );

    // Dropping one attached stream releases both the attach count and client/global slots.
    attached_streams.pop();
    assert_eq!(
        sse_client_connections(IpAddr::V6(ip_v6_1)),
        MAX_ATTACHED_PER_SUB - 1
    );
    let reattached = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V6(ip_v6_1),
            10_101,
        ))),
        Query(StreamQuery {
            sub_id: Some(sub_id.clone()),
            topics: None,
            contract: None,
            event_topics: None,
        }),
    )
    .await
    .expect("slot released on drop must allow re-attach");
    drop(reattached);
    drop(attached_streams);
    assert_eq!(sse_client_connections(IpAddr::V6(ip_v6_1)), 0);
    hub().unsubscribe(&sub_id);

    // 2. Per-IP /64 bucket SSE connection cap (`set_sse_max_connections_per_client_for_tests(2)`).
    set_sse_max_connections_per_client_for_tests(2);
    let s1 = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V6(ip_v6_1),
            11_000,
        ))),
        new_heads_query(),
    )
    .await
    .expect("1st SSE stream");
    let s2 = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V6(ip_v6_same_64),
            11_001,
        ))),
        new_heads_query(),
    )
    .await
    .expect("2nd SSE stream in /64");
    let s3 = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V6(ip_v6_same_64),
            11_002,
        ))),
        new_heads_query(),
    )
    .await;
    assert_eq!(
        s3.err(),
        Some(StatusCode::TOO_MANY_REQUESTS),
        "3rd SSE stream in same /64 bucket must be rejected with 429"
    );
    drop(s1);
    drop(s2);
    assert_eq!(sse_client_connections(IpAddr::V6(ip_v6_1)), 0);
    set_sse_max_connections_per_client_for_tests(0);

    // 3. Global SSE connection cap (`set_sse_max_connections_for_tests(2)`) via explorer `/events`.
    let base_active = sse_active_connections();
    set_sse_max_connections_for_tests(base_active + 2);
    let st = test_rpc_state(None).await;
    let gw = Arc::new(GatewayState::with_captcha(
        st,
        100,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::disabled()),
    ));
    let (addr, server) = serve_router(explorer::router(gw)).await;

    let mut c1 = TcpStream::connect(addr).await.unwrap();
    c1.write_all(b"GET /events?topics=newHeads HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf1 = [0u8; 512];
    let n1 = c1.read(&mut buf1).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf1[..n1]).starts_with("HTTP/1.1 200 OK"),
        "1st /events SSE must connect"
    );

    let mut c2 = TcpStream::connect(addr).await.unwrap();
    c2.write_all(b"GET /events?topics=newHeads HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf2 = [0u8; 512];
    let n2 = c2.read(&mut buf2).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf2[..n2]).starts_with("HTTP/1.1 200 OK"),
        "2nd /events SSE must connect"
    );

    let mut c3 = TcpStream::connect(addr).await.unwrap();
    c3.write_all(
        b"GET /events?topics=newHeads HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf3 = Vec::new();
    c3.read_to_end(&mut buf3).await.unwrap();
    let head3 = String::from_utf8_lossy(&buf3);
    assert!(
        head3.starts_with("HTTP/1.1 503"),
        "global SSE cap must refuse 3rd /events connection with 503, got: {head3}"
    );

    drop(c1);
    drop(c2);
    poll_until(
        "SSE active connections released on drop",
        Duration::from_secs(5),
        || sse_active_connections() == base_active,
    )
    .await;
    server.abort();
}

// ===========================================================================
// W6-A5-2: Heavy RPC offloading + per-IP expensive-read bucket/concurrency cap
// ===========================================================================

#[tokio::test]
async fn w6_a5_2_heavy_rpcs_offload_and_per_ip_bucket_prevents_starvation() {
    assert!(is_ws_expensive_method("stell_runGetMethod"));
    assert!(is_ws_expensive_method("stell_getArchiveProof"));
    assert!(is_ws_expensive_method("stell_getProof"));
    assert!(is_ws_expensive_method("stell_estimateFee"));

    // 1. Per-IP concurrency & token bucket prevents one IP from starving all 32 global permits.
    let attacker_ip: IpAddr = "198.51.100.10".parse().unwrap();
    let victim_ip: IpAddr = "203.0.113.20".parse().unwrap();

    let mut held_guards = Vec::new();
    for i in 0..HTTP_EXPENSIVE_READ_MAX_PER_IP {
        let g = try_acquire_http_expensive_read_with_ip("stell_getProof", attacker_ip)
            .unwrap_or_else(|e| panic!("permit {i} within per-IP cap must succeed: {e}"))
            .expect("expensive method returns Some(guard)");
        held_guards.push(g);
    }
    // 9th concurrent expensive read from same IP is rejected, even though 24/32 global permits remain free.
    let over_conc = try_acquire_http_expensive_read_with_ip("stell_runGetMethod", attacker_ip);
    assert!(
        over_conc.is_err(),
        "one IP must not hold more than {HTTP_EXPENSIVE_READ_MAX_PER_IP} global permits"
    );
    // Victim IP is unaffected and can acquire permits cleanly.
    let victim_guard = try_acquire_http_expensive_read_with_ip("stell_getArchiveProof", victim_ip)
        .expect("victim IP must not be starved by attacker IP")
        .expect("guard");
    drop(victim_guard);
    drop(held_guards);

    // Exhaust the per-IP token bucket on a fresh IP without holding concurrency permits.
    let flood_ip: IpAddr = "198.51.100.77".parse().unwrap();
    for i in 0..HTTP_EXPENSIVE_READ_BURST_DEFAULT {
        let g = try_acquire_http_expensive_read_with_ip("stell_estimateFee", flood_ip)
            .unwrap_or_else(|e| panic!("burst {i} should succeed: {e}"))
            .expect("guard");
        drop(g);
    }
    let over_bucket = try_acquire_http_expensive_read_with_ip("stell_getProof", flood_ip);
    assert!(
        over_bucket.is_err(),
        "exceeding per-IP expensive-read token bucket must fail closed"
    );

    // 2. Concurrent execution of `stell_runGetMethod`, `stell_getProof`,
    //    `stell_getArchiveProof`, and `stell_estimateFee` via spawn_blocking.
    let tmp = TempDirCleanup::new("archive-proof");
    let store = Arc::new(Storage::open(tmp.path()).expect("open storage"));
    let st = test_rpc_state(Some(store)).await;

    let creator = [0x11u8; 32];
    let wat_src = r#"(module (func (export "get_val") (param i64) (result i64) (i64.add (local.get 0) (i64.const 41))))"#;
    let wasm = wat::parse_str(wat_src).expect("wat");
    let contract_addr = st
        .engine
        .deploy_contract(creator, wasm, 1)
        .await
        .expect("deploy contract");
    st.engine
        .update_account(AccountState::new([0x22u8; 32], 500_000_000_000))
        .await;

    let (r_get, r_proof, r_arch, r_fee) = tokio::join!(
        st.call(
            "stell_runGetMethod",
            json!({
                "address": hex::encode(contract_addr),
                "method": "get_val",
                "args": [1]
            }),
        ),
        st.call(
            "stell_getProof",
            json!({ "address": hex::encode([0x22u8; 32]) }),
        ),
        st.call(
            "stell_getArchiveProof",
            json!({ "address": hex::encode([0x22u8; 32]), "height": 1 }),
        ),
        st.call(
            "stell_estimateFee",
            json!({
                "from": hex::encode([0x22u8; 32]),
                "to": hex::encode(contract_addr),
                "method": "get_val",
                "arg": 1,
            }),
        ),
    );
    assert_eq!(r_get["success"], json!(true), "runGetMethod: {r_get}");
    assert_eq!(r_get["return_value"], json!(42));
    assert!(
        r_proof.get("error").is_none() && r_proof["account_proof"].is_array(),
        "getProof: {r_proof}"
    );
    assert!(
        r_arch.get("error").is_some(),
        "getArchiveProof with no snapshot at height 1 fails closed cleanly: {r_arch}"
    );
    assert!(
        r_fee.get("error").is_none() && r_fee["estimated_fee"].as_u64().is_some(),
        "estimateFee: {r_fee}"
    );
}

// ===========================================================================
// W6-A5-3 & W6-A5-4: Broadcast capacity 8192, WS per-IP cap 32, WS write timeout
// ===========================================================================

#[tokio::test]
async fn w6_a5_3_4_ws_per_ip_cap_and_write_timeout_close_slow_consumer() {
    let _serial = ASYNC_SERIAL.lock().await;
    let _reset = WsOverrideReset;

    assert_eq!(STREAM_BROADCAST_CAPACITY, 8192);
    const _: () = assert!(STREAM_BROADCAST_CAPACITY > MAX_SUBSCRIPTIONS);
    assert_eq!(WS_MAX_CONNECTIONS_PER_IP, 32);
    assert_eq!(WS_WRITE_TIMEOUT, Duration::from_secs(10));

    let st = test_rpc_state(None).await;
    let (addr, server) = serve_router(rpc_router(st.clone())).await;

    // 1. Per-IP WS connection cap (`set_ws_max_connections_per_ip_for_tests(2)`).
    let base_active = ws_active_connections();
    set_ws_max_connections_per_ip_for_tests(2);
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();

    let (mut ws1, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("1st WS");
    let (mut ws2, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("2nd WS");
    poll_until("2 WS connections counted", Duration::from_secs(5), || {
        ws_ip_connections(loopback) == 2
    })
    .await;

    let ws3 = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await;
    assert!(
        ws3.is_err(),
        "3rd WS connection from same IP must be rejected pre-upgrade"
    );

    let _ = ws1.close(None).await;
    let _ = ws2.close(None).await;
    poll_until("WS per-IP count drops to 0", Duration::from_secs(5), || {
        ws_ip_connections(loopback) == 0 && ws_active_connections() == base_active
    })
    .await;
    set_ws_max_connections_per_ip_for_tests(0);

    // 2. Slow consumer write timeout closes stalled WS connection instead of pinning slot forever.
    set_ws_write_timeout_ms_for_tests(100);
    // Open a raw TCP WS upgrade with a tiny SO_RCVBUF so the kernel TCP send buffer fills
    // quickly once we stop reading, causing `socket.send` to stall and hit `WS_WRITE_TIMEOUT`.
    let sock = tokio::net::TcpSocket::new_v4().expect("v4 socket");
    sock.set_recv_buffer_size(4096).expect("small recv buf");
    let stream = sock.connect(addr).await.expect("raw connect");
    let (mut stalled_ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/ws"), stream)
        .await
        .expect("stalled WS connect");
    stalled_ws
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc": "2.0", "id": 1, "method": "stell_subscribe", "params": ["newHeads"]})
                .to_string(),
        ))
        .await
        .expect("subscribe");
    let reply = tokio::time::timeout(Duration::from_secs(5), stalled_ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let v: Value = serde_json::from_str(reply.to_text().unwrap()).unwrap();
    assert!(v["result"].is_string(), "subscribed: {v}");
    // Keep `stalled_ws` alive (never reading!) and flood enough notifications (>6 MB) so Linux
    // loopback TCP send buffers saturate and `socket.send` stalls until `WS_WRITE_TIMEOUT` (100 ms).
    for i in 0..40_000u64 {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&i.to_be_bytes());
        publish_new_head(1000 + i, h, 0, 1, 1_700_000_000 + i);
        if ws_ip_connections(loopback) == 0 {
            break;
        }
        if i % 200 == 0 {
            tokio::task::yield_now().await;
        }
    }
    poll_until(
        "slow stalled WS consumer closed by WS_WRITE_TIMEOUT",
        Duration::from_secs(10),
        || ws_ip_connections(loopback) == 0 && ws_active_connections() == base_active,
    )
    .await;
    drop(stalled_ws);
    server.abort();
}

// ===========================================================================
// W6-A6-4: store bootstrap refuses unexpected top-level dirs (e.g. keys/)
// ===========================================================================

#[test]
fn w6_a6_4_store_bootstrap_refuses_unexpected_top_level_dirs() {
    let tmp = TempDirCleanup::new("bootstrap-evil-dir");
    let src = tmp.path().join("src");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(src.join("store")).unwrap();
    std::fs::create_dir_all(src.join("keys")).unwrap();
    {
        let _storage = Storage::open(&src.join("store")).expect("open src store");
    }
    std::fs::write(src.join("keys").join("validator.key"), b"attacker-key").unwrap();

    std::fs::create_dir_all(data.join("keys")).unwrap();
    std::fs::write(data.join("keys").join("validator.key"), b"victim-key").unwrap();
    std::fs::create_dir_all(data.join("store")).unwrap();
    {
        let _old = Storage::open(&data.join("store")).expect("open old store");
    }

    let archive = tmp.path().join("evil.tar.zst");
    let tar_status = Command::new("tar")
        .args([
            "-I",
            "zstd",
            "-cf",
            archive.to_str().unwrap(),
            "-C",
            src.to_str().unwrap(),
            "store",
            "keys",
        ])
        .status()
        .expect("run tar");
    assert!(tar_status.success(), "tar -I zstd must create test archive");

    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--force",
            "--no-backup",
            "--observer",
        ])
        .output()
        .expect("run store bootstrap");
    assert!(
        !out.status.success(),
        "bootstrap must refuse archive containing keys/ dir"
    );
    assert_eq!(
        std::fs::read(data.join("keys").join("validator.key")).unwrap(),
        b"victim-key",
        "victim keys/ directory must never be deleted or overwritten"
    );
    assert!(
        data.join("store").exists(),
        "refused archive must leave existing store/ intact"
    );
}

// ===========================================================================
// W6-A6-6: node_keys malformed enc2 nonce + refuse plaintext validator.key migration
// ===========================================================================

#[test]
fn w6_a6_6_malformed_enc2_nonce_errors_and_plaintext_validator_migration_refused() {
    let _env_lock = ENV_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _env = KeyEnvGuard::new();

    // 1. Malformed enc2: nonce length != 24 must return Err, never panic.
    let bad_salt = hex::encode([0x11u8; 16]);
    let bad_nonce_short = hex::encode([0x22u8; 8]);
    let bad_nonce_long = hex::encode([0x22u8; 32]);
    let dummy_ct = hex::encode([0x33u8; 32]);

    for bad_nonce in [bad_nonce_short, bad_nonce_long] {
        let blob = format!("enc2:{bad_salt}:{bad_nonce}:{dummy_ct}");
        let res = decrypt_bytes(blob.as_bytes(), Some("passphrase"));
        assert!(res.is_err(), "malformed nonce must return Err");
        let msg = format!("{:#}", res.unwrap_err());
        assert!(
            msg.contains("nonce length"),
            "error must name invalid nonce length: {msg}"
        );
    }

    // 2. Plaintext validator.key migration from identity.key is refused unless STELL_KEY_PLAINTEXT=1.
    let tmp = TempDirCleanup::new("validator-migrate");
    let dir = tmp.path();
    let nk = infnode::keyring::NodeKeys::generate();
    write_private_file(&dir.join("e2e.key"), hex::encode(nk.kem_seed).as_bytes()).unwrap();
    let seed_bytes = [0x55u8; 32];
    write_private_file(
        &dir.join("identity.key"),
        hex::encode(seed_bytes).as_bytes(),
    )
    .unwrap();

    // Neither passphrase nor STELL_KEY_PLAINTEXT=1 -> refused!
    let err = load_node_keys(dir)
        .err()
        .expect("must refuse plaintext validator.key migration");
    assert!(
        format!("{err:#}").contains(ENV_PLAINTEXT),
        "refusal must mention {ENV_PLAINTEXT}: {err:#}"
    );
    assert!(!dir.join("validator.key").exists());
    assert!(dir.join("identity.key").exists());

    // With passphrase -> migrates and encrypts validator.key with enc2:.
    std::env::set_var(ENV_PASSPHRASE, "w7-key-passphrase");
    assert!(
        load_node_keys(dir).is_ok(),
        "migration with passphrase must succeed"
    );
    let raw_val = std::fs::read_to_string(dir.join("validator.key")).unwrap();
    assert!(
        raw_val.starts_with("enc2:"),
        "migrated validator.key must be enc2:-encrypted"
    );
    assert!(!dir.join("identity.key").exists());
    assert!(dir.join("identity.key.migrated").exists());

    let loaded_ck = load_or_generate_consensus_key(dir).expect("reload encrypted validator.key");
    assert_eq!(loaded_ck.to_bytes(), seed_bytes);

    // With STELL_KEY_PLAINTEXT=1 and no passphrase -> explicit opt-out permits plaintext migration.
    let tmp2 = TempDirCleanup::new("validator-migrate-plain");
    let dir2 = tmp2.path();
    std::env::remove_var(ENV_PASSPHRASE);
    std::env::set_var(ENV_PLAINTEXT, "1");
    write_private_file(
        &dir2.join("identity.key"),
        hex::encode(seed_bytes).as_bytes(),
    )
    .unwrap();
    let ck_plain = load_or_generate_consensus_key(dir2)
        .expect("explicit STELL_KEY_PLAINTEXT=1 allows migration");
    assert_eq!(ck_plain.to_bytes(), seed_bytes);
    let raw_plain = std::fs::read_to_string(dir2.join("validator.key")).unwrap();
    assert!(!raw_plain.starts_with("enc2:"));
}

// ===========================================================================
// W6-A8-15: node_config::validate() rejects non-loopback http:// remote_signer_url with token
// ===========================================================================

#[test]
fn w6_a8_15_node_config_rejects_non_loopback_http_remote_signer_with_token() {
    let bad_toml = r#"
[signer]
remote_signer_url = "http://10.0.0.42:9100/sign"
remote_signer_token = "super-secret-signer-token"
"#;
    let cfg = NodeTomlConfig::from_toml_str(bad_toml).expect("parse");
    let rep = cfg.validate_with_env(|_| None);
    assert!(
        !rep.is_ok(),
        "non-loopback http:// + token must fail validation"
    );
    assert!(
        rep.errors
            .iter()
            .any(|e| e.contains("remote_signer_url") && e.contains("non-loopback")),
        "unexpected errors: {:?}",
        rep.errors
    );

    // Userinfo bypass `http://127.0.0.1@evil.example:9100` must also be rejected.
    let spoofy_toml = r#"
[signer]
remote_signer_url = "http://127.0.0.1@evil.example:9100/sign"
remote_signer_token = "super-secret-signer-token"
"#;
    let spoofy = NodeTomlConfig::from_toml_str(spoofy_toml).expect("parse");
    assert!(!spoofy.validate_with_env(|_| None).is_ok());

    // Env token + TOML URL must also be caught.
    let url_only = NodeTomlConfig::from_toml_str(
        r#"
[signer]
remote_signer_url = "http://signer.internal:9100"
"#,
    )
    .expect("parse");
    let rep_env = url_only.validate_with_env(|k| {
        if k == "STELL_REMOTE_SIGNER_TOKEN" {
            Some("env-token".to_string())
        } else {
            None
        }
    });
    assert!(!rep_env.is_ok());

    // Loopback http:// and remote https:// with token are valid.
    for ok_url in [
        "http://127.0.0.1:9100/sign",
        "http://localhost:9100/sign",
        "http://[::1]:9100/sign",
        "https://signer.internal:9100/sign",
    ] {
        let toml =
            format!("[signer]\nremote_signer_url = \"{ok_url}\"\nremote_signer_token = \"tok\"\n");
        let c = NodeTomlConfig::from_toml_str(&toml).expect("parse");
        let r = c.validate_with_env(|_| None);
        assert!(
            r.is_ok(),
            "{ok_url} should be accepted, got errors: {:?}",
            r.errors
        );
    }

    // Keep unused import check satisfied if FalconKeypair isn't needed elsewhere.
    let _ = std::mem::size_of::<FalconKeypair>();
}
