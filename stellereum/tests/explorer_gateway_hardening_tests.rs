//! Hardening tests for the explorer gateway (`src/explorer.rs`):
//! 1. `/rpc` mounted inside the shared `TimeoutLayer(30s)` and
//!    `ConcurrencyLimitLayer(512)` without double rate-limiting;
//! 2. `GET /metrics` reusing the TTL-cached `health_data_dir_cache` path;
//! 3. `GET /api/contracts` deterministic sorting and optional `after` cursor
//!    while keeping the default response shape unchanged;
//! 4. `POST /api/faucet-public/:address` distinguishing `LifetimeCapExhausted`
//!    (`"faucet limit reached for this address"`) from `Cooldown` (`"cooling down"`),
//!    preserving per-IP budget on refusal, and rolling back via `rollback_grant`
//!    on mempool admission failure.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use stellereum::contract::Contract;
use stellereum::explorer::{self, GatewayState, HealthOptions, HealthThresholds, ReadinessConfig};
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::rpc::{Faucet, ReceiptIndex, RpcState, FAUCET_IP_MAX_PER_HOUR};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::turnstile::CaptchaGate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FAUCET_SEED: [u8; 32] = [0x6Bu8; 32];

fn faucet_addr_from_seed() -> [u8; 32] {
    let kp = FalconKeypair::generate_from_seed_bytes(&FAUCET_SEED);
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

async fn make_rpc_state(faucet: Option<Arc<Faucet>>, fund_faucet: bool) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    if fund_faucet {
        engine
            .update_account(AccountState::new(
                faucet_addr_from_seed(),
                100_000_000_000_000,
            ))
            .await;
    }
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(10)),
        node_id: "hardening:explorer".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet,
        faucet_token: Some("hardening-faucet-token".to_string()),
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: ShardRegistry::single(),
    })
}

fn make_gateway(
    rpc: Arc<RpcState>,
    per_sec: u32,
    health_options: HealthOptions,
) -> Arc<GatewayState> {
    Arc::new(
        GatewayState::with_captcha(
            rpc,
            per_sec,
            ReadinessConfig {
                max_stall_secs: 30,
                min_peers: 0,
            },
            Arc::new(CaptchaGate::disabled()),
        )
        .with_health_options(health_options),
    )
}

fn disabled_disk_health_opts() -> HealthOptions {
    HealthOptions {
        thresholds: HealthThresholds::default(),
        cache_ttl_ms: 1_000,
        data_dir: None,
    }
}

async fn spawn_gw(gw: Arc<GatewayState>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gw).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn http_get(addr: SocketAddr, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let all = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = all.split_once("\r\n\r\n").unwrap_or(("", &all));
    (head.to_string(), body.to_string())
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let all = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = all.split_once("\r\n\r\n").unwrap_or(("", &all));
    (head.to_string(), body.to_string())
}

fn status_code(head: &str) -> u16 {
    head.lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn rpc_post_request(body: Body, peer_port: u16) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/rpc")
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], peer_port))));
    req
}

fn stats_get_request(peer_port: u16) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/stats")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], peer_port))));
    req
}

fn dummy_contract(address: [u8; 32]) -> Contract {
    Contract {
        address,
        creator: [0x01u8; 32],
        code_hash: [0x02u8; 32],
        code: vec![0x00, 0x61, 0x73, 0x6d],
        storage: HashMap::new(),
        created_at: 1,
        paused: false,
        balance: 0,
        abi: None,
        source_hash: None,
    }
}

async fn call_router(
    svc: &mut axum::Router,
    req: Request<Body>,
) -> axum::response::Response {
    std::future::poll_fn(|cx| {
        <axum::Router as tower::Service<Request<Body>>>::poll_ready(svc, cx)
    })
    .await
    .unwrap();
    <axum::Router as tower::Service<Request<Body>>>::call(svc, req)
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn explorer_router_rpc_enforces_timeout_layer() {
    let rpc = make_rpc_state(None, false).await;
    let gw = make_gateway(rpc, 1_000, disabled_disk_health_opts());
    let mut svc = explorer::router(gw);

    // Hang inside `/rpc`'s body extractor forever (`futures::stream::pending`),
    // proving `TimeoutLayer(30s)` wraps the nested `/rpc` mount.
    let slow_body = Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>());
    let req = rpc_post_request(slow_body, 41001);

    let handle = tokio::spawn(async move { call_router(&mut svc, req).await });

    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        !handle.is_finished(),
        "/rpc slow request must still be pending before 30s timeout"
    );

    tokio::time::advance(Duration::from_secs(30) + Duration::from_millis(50)).await;
    let resp = handle.await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::REQUEST_TIMEOUT,
        "nested /rpc must hit TimeoutLayer(30s) and return 408"
    );
}

#[tokio::test]
async fn explorer_router_rpc_enforces_concurrency_limit_without_double_rate_limit() {
    // 1. Verify no double rate-limiting on `/rpc` and separate bucket from explorer routes.
    let rpc_rl = make_rpc_state(None, false).await;
    let gw_rl = make_gateway(rpc_rl, 3, disabled_disk_health_opts());
    let app_rl = explorer::router(gw_rl);
    let chain_id_payload = br#"{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}"#;

    for i in 0..3 {
        let mut svc = app_rl.clone();
        let req = rpc_post_request(Body::from(&chain_id_payload[..]), 42000 + i);
        let resp = call_router(&mut svc, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} within 3/s RPC budget must not be double-counted"
        );
    }
    {
        let mut svc = app_rl.clone();
        let req = rpc_post_request(Body::from(&chain_id_payload[..]), 42009);
        let resp = call_router(&mut svc, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "4th /rpc request in 1s must hit nested_rpc_rate_limit"
        );
    }
    {
        let mut svc = app_rl.clone();
        let req = stats_get_request(42010);
        let resp = call_router(&mut svc, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/api/stats must use its own bucket independent of /rpc"
        );
    }

    // 2. Verify `ConcurrencyLimitLayer(512)` wraps `/rpc`: hold 512 slow `/rpc`
    // requests in-flight, verify the 513th blocks, then release 1 and watch it pass.
    let rpc = make_rpc_state(None, false).await;
    let gw = make_gateway(rpc, 10_000, disabled_disk_health_opts());
    let app = explorer::router(gw);

    let entered = Arc::new(AtomicUsize::new(0));
    let mut txs = Vec::with_capacity(512);
    let mut handles = Vec::with_capacity(512);

    for i in 0..512u16 {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        txs.push(tx);
        let entered_c = Arc::clone(&entered);
        let body = Body::from_stream(futures::stream::once(async move {
            entered_c.fetch_add(1, Ordering::SeqCst);
            let _ = rx.await;
            Ok::<Bytes, std::io::Error>(Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}"#,
            ))
        }));
        let mut svc = app.clone();
        let req = rpc_post_request(body, 43000 + i);
        handles.push(tokio::spawn(async move { call_router(&mut svc, req).await }));
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        while entered.load(Ordering::SeqCst) < 512 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("all 512 /rpc requests should acquire concurrency permits");

    let mut svc513 = app.clone();
    let req513 = rpc_post_request(Body::from(&chain_id_payload[..]), 44000);
    let mut handle513 = tokio::spawn(async move { call_router(&mut svc513, req513).await });

    assert!(
        tokio::time::timeout(Duration::from_millis(120), &mut handle513)
            .await
            .is_err(),
        "513th /rpc request must block while all 512 ConcurrencyLimitLayer permits are held"
    );

    // Release 1 held permit: the 513th request must immediately complete with 200 OK.
    let _ = txs.pop().unwrap().send(());
    let resp513 = tokio::time::timeout(Duration::from_secs(2), handle513)
        .await
        .expect("513th /rpc request should finish once a permit is freed")
        .unwrap();
    assert_eq!(resp513.status(), StatusCode::OK);

    for tx in txs {
        let _ = tx.send(());
    }
    for h in handles {
        let _ = h.await;
    }
}

#[tokio::test]
async fn api_contracts_pagination_is_deterministic_and_supports_after_cursor() {
    let rpc_fwd = make_rpc_state(None, false).await;
    let rpc_rev = make_rpc_state(None, false).await;

    let mut addrs: Vec<[u8; 32]> = (0..25u8)
        .map(|i| {
            let mut a = [0u8; 32];
            a[0] = ((i as usize * 73 + 19) % 251) as u8;
            a[31] = i;
            a
        })
        .collect();

    {
        let mut reg = rpc_fwd.engine.contracts_write().await;
        for a in &addrs {
            reg.contracts.insert(*a, dummy_contract(*a));
        }
    }
    {
        let mut reg = rpc_rev.engine.contracts_write().await;
        for a in addrs.iter().rev() {
            reg.contracts.insert(*a, dummy_contract(*a));
        }
    }

    addrs.sort_unstable();
    let expected_hex: Vec<String> = addrs.iter().map(hex::encode).collect();

    let addr_fwd = spawn_gw(make_gateway(rpc_fwd, 1_000, disabled_disk_health_opts())).await;
    let addr_rev = spawn_gw(make_gateway(rpc_rev, 1_000, disabled_disk_health_opts())).await;

    // 1. Offset/limit pagination must be identical across insertion orders and keep default shape.
    let mut collected_fwd = Vec::new();
    let mut collected_rev = Vec::new();
    for offset in [0usize, 7, 14, 21] {
        let (head_f, body_f) =
            http_get(addr_fwd, &format!("/api/contracts?limit=7&offset={offset}")).await;
        let (head_r, body_r) =
            http_get(addr_rev, &format!("/api/contracts?limit=7&offset={offset}")).await;
        assert_eq!(status_code(&head_f), 200);
        assert_eq!(status_code(&head_r), 200);

        let vf: serde_json::Value = serde_json::from_str(&body_f).unwrap();
        let vr: serde_json::Value = serde_json::from_str(&body_r).unwrap();
        assert_eq!(
            vf, vr,
            "pages must match across independent insertion orders"
        );
        assert_eq!(vf["total"], 25);
        assert_eq!(vf["offset"], offset);
        assert!(
            vf.get("next_cursor").is_none(),
            "normal calls without `after` must preserve existing response shape: {body_f}"
        );

        let page: Vec<String> = vf["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        collected_fwd.extend(page.clone());
        collected_rev.extend(page);
    }
    assert_eq!(collected_fwd, expected_hex);
    assert_eq!(collected_rev, expected_hex);

    // 2. Cursor pagination via `after` traverses remaining items deterministically.
    let mut cursor_collected = Vec::new();
    let (_, first_body) = http_get(addr_fwd, "/api/contracts?limit=7&offset=0").await;
    let first_v: serde_json::Value = serde_json::from_str(&first_body).unwrap();
    let first_page: Vec<String> = first_v["contracts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let mut after = first_page.last().unwrap().clone();
    cursor_collected.extend(first_page);

    loop {
        let (head, body) =
            http_get(addr_fwd, &format!("/api/contracts?limit=7&after={after}")).await;
        assert_eq!(
            status_code(&head),
            200,
            "after={after} failed: {head} {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let page: Vec<String> = v["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        cursor_collected.extend(page);
        if v["has_more"] == false {
            assert!(v["next_cursor"].is_null());
            break;
        }
        after = v["next_cursor"].as_str().unwrap().to_string();
    }
    assert_eq!(cursor_collected, expected_hex);

    // 3. Malformed `after` cursor fails closed with 400.
    let (bad_head, _) = http_get(addr_fwd, "/api/contracts?after=not-a-hex-address").await;
    assert_eq!(status_code(&bad_head), 400);
}

#[tokio::test]
async fn api_faucet_public_distinguishes_lifetime_cap_from_cooldown_and_rolls_back() {
    // Part 1: exhausted lifetime cap returns "faucet limit reached", NEVER "cooling down" / "2700",
    // and does NOT consume the per-IP hourly budget.
    let faucet_cap = Arc::new(Faucet::new(FAUCET_SEED, 1, 5_000_000_000, 5_000_000_000));
    let capped_who = [0x41u8; 32];
    faucet_cap
        .build_transfer(capped_who, None, None)
        .await
        .expect("pre-exhaust recipient lifetime cap");
    let rpc_cap = make_rpc_state(Some(faucet_cap), true).await;
    let addr_cap = spawn_gw(make_gateway(rpc_cap, 1_000, disabled_disk_health_opts())).await;

    let (head, body) = http_post(
        addr_cap,
        &format!("/api/faucet-public/{}", hex::encode(capped_who)),
        "",
    )
    .await;
    assert_eq!(
        status_code(&head),
        429,
        "exhausted cap must be 429: {head} {body}"
    );
    assert!(
        body.contains("faucet limit reached"),
        "exhausted lifetime cap must report limit reached, got: {body}"
    );
    assert!(
        !body.contains("cooling down") && !body.contains("2700"),
        "exhausted lifetime cap must never masquerade as 2700s cooldown: {body}"
    );

    // Because `LifetimeCapExhausted` returned before charging `ip_buckets`,
    // all `FAUCET_IP_MAX_PER_HOUR` slots remain available for fresh addresses.
    for i in 0..FAUCET_IP_MAX_PER_HOUR {
        let fresh = [0x80u8 + (i as u8); 32];
        let (h, b) = http_post(
            addr_cap,
            &format!("/api/faucet-public/{}", hex::encode(fresh)),
            "",
        )
        .await;
        assert_eq!(
            status_code(&h),
            200,
            "fresh drip #{i} should succeed (budget preserved on cap refusal): {h} {b}"
        );
    }
    let (h_over, b_over) = http_post(
        addr_cap,
        &format!("/api/faucet-public/{}", hex::encode([0xEEu8; 32])),
        "",
    )
    .await;
    assert_eq!(status_code(&h_over), 429);
    assert!(
        b_over.contains("per-IP faucet budget exhausted"),
        "{b_over}"
    );

    // Part 2: active cooldown (when cap is NOT exhausted) still reports "cooling down".
    let faucet_cd = Arc::new(Faucet::new(FAUCET_SEED, 1, 5_000_000_000, 100_000_000_000));
    let rpc_cd = make_rpc_state(Some(faucet_cd), true).await;
    let addr_cd = spawn_gw(make_gateway(rpc_cd, 1_000, disabled_disk_health_opts())).await;
    let cd_who = hex::encode([0x42u8; 32]);
    let (h1, b1) = http_post(addr_cd, &format!("/api/faucet-public/{cd_who}"), "").await;
    assert_eq!(status_code(&h1), 200, "{h1} {b1}");
    let (h2, b2) = http_post(addr_cd, &format!("/api/faucet-public/{cd_who}"), "").await;
    assert_eq!(status_code(&h2), 429, "{h2} {b2}");
    assert!(
        b2.contains("cooling down"),
        "expected cooldown message: {b2}"
    );

    // Part 3: mempool admission failure rolls back both `dispensed` and `ip_buckets` via `rollback_grant`.
    let faucet_rb = Arc::new(Faucet::new(FAUCET_SEED, 1, 5_000_000_000, 100_000_000_000));
    // `fund_faucet = false` -> faucet balance is 0 -> mempool rejects with InsufficientBalance.
    let rpc_rb = make_rpc_state(Some(Arc::clone(&faucet_rb)), false).await;
    let addr_rb = spawn_gw(make_gateway(
        Arc::clone(&rpc_rb),
        1_000,
        disabled_disk_health_opts(),
    ))
    .await;
    let rb_who = [0x43u8; 32];
    let (h_fail, _) = http_post(
        addr_rb,
        &format!("/api/faucet-public/{}", hex::encode(rb_who)),
        "",
    )
    .await;
    assert_eq!(status_code(&h_fail), 503);
    assert_eq!(
        faucet_rb.dispensed_to(rb_who).await,
        0,
        "rollback_grant must restore dispensed total on mempool failure"
    );

    // Fund the faucet account and verify all `FAUCET_IP_MAX_PER_HOUR` slots are still intact.
    rpc_rb
        .engine
        .update_account(AccountState::new(
            faucet_addr_from_seed(),
            100_000_000_000_000,
        ))
        .await;
    for i in 0..FAUCET_IP_MAX_PER_HOUR {
        let fresh = [0xA0u8 + (i as u8); 32];
        let (h, b) = http_post(
            addr_rb,
            &format!("/api/faucet-public/{}", hex::encode(fresh)),
            "",
        )
        .await;
        assert_eq!(
            status_code(&h),
            200,
            "fresh drip #{i} should succeed after rollback_grant restored ip_buckets: {h} {b}"
        );
    }
}

#[tokio::test]
async fn prometheus_metrics_reuses_health_data_dir_cache() {
    let uniq = format!(
        "stellereum_metrics_cache_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let base = std::path::PathBuf::from("/tmp/opencode");
    let dir = if base.is_dir() {
        base.join(uniq)
    } else {
        std::env::temp_dir().join(uniq)
    };
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seed.bin"), vec![0xAAu8; 1234]).unwrap();

    let rpc = make_rpc_state(None, false).await;
    let gw = make_gateway(
        rpc,
        1_000,
        HealthOptions {
            thresholds: HealthThresholds::default(),
            cache_ttl_ms: 1_000,
            data_dir: Some(dir.clone()),
        },
    );
    let addr = spawn_gw(gw).await;

    let (head1, body1) = http_get(addr, "/metrics").await;
    assert_eq!(status_code(&head1), 200);
    assert!(
        body1.contains("stell_data_dir_bytes 1234\n"),
        "cold /metrics scrape must observe initial file size: {body1}"
    );

    // Mutate disk after initial scrape: within the 30s cache TTL, `/metrics`
    // must serve the cached size instead of re-walking the directory.
    std::fs::write(dir.join("snapshot-extra.bin"), vec![0xBBu8; 5000]).unwrap();
    let (head2, body2) = http_get(addr, "/metrics").await;
    assert_eq!(status_code(&head2), 200);
    assert!(
        body2.contains("stell_data_dir_bytes 1234\n"),
        "warm /metrics scrape must hit health_data_dir_cache within TTL: {body2}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
