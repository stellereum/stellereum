//! Wave 7 regression tests for `stellereum-indexer` Wave 6 hardening fixes:
//! - W6-A5-5: Concurrency limit (`503`), request timeout (`408`), per-IP rate
//!   limiting (`429`), and per-IP SSE stream cap (`MAX_INDEXER_SSE_PER_IP = 8`).
//! - W6-A5-6: Bounded `MAX_OFFSET` (`100_000`), dedicated `/program/:program/accounts`
//!   rate limit, and `spawn_blocking` DB offload.
//! - W6-A5-7: `constant_time_eq` (fixed-length SHA-256) + empty/whitespace
//!   `INDEXER_VERIFY_TOKEN` rejection + `"rpc_url"` stripped from all public
//!   JSON responses.
//! - W6-A5-8: Block height parameter `> i64::MAX` returns HTTP `400 Bad Request`
//!   instead of `500`.

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use stellereum_indexer::db::{BlockRecord, Database, VerifiedSource};
use stellereum_indexer::server::{
    create_router, create_router_with_limits, AppState, IndexerStreamHub, MAX_INDEXER_SSE_PER_IP,
};

async fn spawn_with_connect_info(
    app: Router,
) -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    (base, client, handle)
}

#[tokio::test]
async fn w6_a5_5_sse_per_ip_cap_rate_limit_concurrency_and_timeout() {
    assert_eq!(MAX_INDEXER_SSE_PER_IP, 8);

    // 1. Per-IP SSE cap (`MAX_INDEXER_SSE_PER_IP = 8`) + RAII cleanup.
    let db = Database::open(":memory:").expect("db");
    let hub = Arc::new(IndexerStreamHub::new());
    let state = AppState::new(db.clone()).with_stream_hub(Arc::clone(&hub));
    let (base, client, srv) = spawn_with_connect_info(create_router(state)).await;

    let mut open_streams = Vec::new();
    for _ in 0..MAX_INDEXER_SSE_PER_IP {
        let resp = client
            .get(format!("{base}/api/v2/stream?topics=newHeads"))
            .send()
            .await
            .expect("within per-IP SSE cap");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        open_streams.push(resp);
    }
    let over_cap = client
        .get(format!("{base}/api/v2/stream?topics=newHeads"))
        .send()
        .await
        .expect("9th SSE request");
    assert_eq!(
        over_cap.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "exceeding MAX_INDEXER_SSE_PER_IP must return 429"
    );

    // Dropping one stream frees the per-IP slot.
    open_streams.pop();
    let mut freed = false;
    for _ in 0..30 {
        if hub.active_clients_for_ip("127.0.0.1".parse().unwrap()) < MAX_INDEXER_SSE_PER_IP {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(freed, "dropping SSE stream must release per-IP slot");
    let reopened = client
        .get(format!("{base}/api/v2/stream?topics=newHeads"))
        .send()
        .await
        .expect("reopen");
    assert_eq!(reopened.status(), reqwest::StatusCode::OK);
    drop(reopened);
    drop(open_streams);
    srv.abort();

    // 2. Per-IP general rate limiter (`429`).
    let limited_app =
        create_router_with_limits(AppState::new(db.clone()), 64, Duration::from_secs(5), 3, 10);
    let (lim_base, lim_client, lim_srv) = spawn_with_connect_info(limited_app).await;
    let mut got_429 = false;
    for _ in 0..10 {
        let r = lim_client
            .get(format!("{lim_base}/api/v2/price"))
            .send()
            .await
            .unwrap();
        if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "per-IP rate limit must return 429");
    lim_srv.abort();

    // 3. Request timeout (`408`) + concurrency cap (`503`) on slow RPC proxy.
    let slow_rpc = Router::new().route(
        "/",
        axum::routing::post(|| async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            Json(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
        }),
    );
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_url = format!("http://{}", slow_listener.local_addr().unwrap());
    let slow_srv = tokio::spawn(async move {
        let _ = axum::serve(slow_listener, slow_rpc).await;
    });

    let timeout_app = create_router_with_limits(
        AppState::with_rpc(db.clone(), slow_url.clone()),
        1,
        Duration::from_millis(120),
        100,
        100,
    );
    let (to_base, to_client, to_srv) = spawn_with_connect_info(timeout_app).await;

    let c_a = to_client.clone();
    let b_a = to_base.clone();
    let h1 = tokio::spawn(async move { c_a.get(format!("{b_a}/api/v2/shards")).send().await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second = to_client
        .get(format!("{to_base}/api/v2/price"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "2nd concurrent request when max_concurrency=1 must return 503"
    );
    let first = h1.await.unwrap().unwrap();
    assert_eq!(
        first.status(),
        reqwest::StatusCode::REQUEST_TIMEOUT,
        "request exceeding timeout must return 408"
    );
    to_srv.abort();
    slow_srv.abort();
}

#[tokio::test]
async fn w6_a5_6_bounded_offset_and_program_accounts_rate_limit() {
    let db = Database::open(":memory:").expect("db");
    let app = create_router_with_limits(
        AppState::new(db),
        64,
        Duration::from_secs(5),
        100,
        2, // dedicated /program/:program/accounts limit = 2/s
    );
    let (base, client, srv) = spawn_with_connect_info(app).await;

    // Offset > 100_000 must fail closed with 400.
    for path in [
        "/api/v2/blocks?offset=100001",
        "/api/v2/contracts?offset=100001",
    ] {
        let r = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(
            r.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{path} must reject offset > 100_000 with 400"
        );
    }

    // Dedicated /program/:program/accounts rate limiter trips before general 100/s limit.
    let tok = "aa".repeat(32);
    let mut hit_prog_429 = false;
    for _ in 0..8 {
        let r = client
            .get(format!("{base}/api/v2/program/token/accounts?token={tok}"))
            .send()
            .await
            .unwrap();
        if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            hit_prog_429 = true;
            break;
        }
    }
    assert!(
        hit_prog_429,
        "/program/:program/accounts must enforce dedicated per-IP rate limit"
    );
    srv.abort();
}

#[tokio::test]
async fn w6_a5_7_empty_verify_token_rejected_and_rpc_url_stripped() {
    let db = Database::open(":memory:").expect("db");
    let addr = "aa".repeat(32);

    // 1. Whitespace-only or empty INDEXER_VERIFY_TOKEN must be rejected (401).
    for bad_tok in [Some("".to_string()), Some("   \t\n ".to_string()), None] {
        let mut st = AppState::with_rpc(db.clone(), "http://127.0.0.1:9".to_string());
        st.verify_token = bad_tok;
        let (base, client, srv) = spawn_with_connect_info(create_router(st)).await;
        let res = client
            .post(format!("{base}/api/v2/contract/{addr}/verify"))
            .header("X-Api-Key", "")
            .json(&json!({"source": "(module)"}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "empty/whitespace verify_token must refuse"
        );
        let res_ws = client
            .post(format!("{base}/api/v2/contract/{addr}/verify"))
            .header("X-Api-Key", "   ")
            .json(&json!({"source": "(module)"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res_ws.status(), reqwest::StatusCode::UNAUTHORIZED);
        srv.abort();
    }

    // 2. Public JSON responses must NEVER leak "rpc_url" (both 200 OK and 503 Unavailable).
    let mock_rpc = Router::new().route(
        "/",
        axum::routing::post(|| async {
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "shards": [{ "shard_id": 0, "tip_height": 1 }],
                    "total_shards": 1
                }
            }))
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_url = format!("http://{}", mock_listener.local_addr().unwrap());
    let mock_srv = tokio::spawn(async move {
        let _ = axum::serve(mock_listener, mock_rpc).await;
    });

    // Live /shards 200 OK must not contain "rpc_url".
    let st_live = AppState::with_rpc(db.clone(), mock_url.clone());
    let (live_base, client, live_srv) = spawn_with_connect_info(create_router(st_live)).await;
    let shards_ok: Value = client
        .get(format!("{live_base}/api/v2/shards"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        shards_ok.get("rpc_url").is_none() && !shards_ok.to_string().contains(&mock_url),
        "/shards 200 must strip rpc_url: {shards_ok}"
    );
    live_srv.abort();
    mock_srv.abort();

    // Dead RPC 503 responses must not contain "rpc_url".
    let dead_url = "http://127.0.0.1:19999";
    let mut st_dead = AppState::with_rpc(db, dead_url.to_string());
    st_dead.verify_token = Some("  valid-tok  ".to_string());
    let (dead_base, client, dead_srv) = spawn_with_connect_info(create_router(st_dead)).await;

    for path in [
        "/api/v2/shards",
        "/api/v2/validators",
        "/api/v2/staking",
        &format!("/api/v2/program/system/accounts?owner={addr}"),
    ] {
        let r = client
            .get(format!("{dead_base}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let body = r.text().await.unwrap();
        assert!(
            !body.contains("rpc_url") && !body.contains(dead_url),
            "{path} leaked rpc_url: {body}"
        );
    }

    let verify_503 = client
        .post(format!("{dead_base}/api/v2/contract/{addr}/verify"))
        .header("X-Api-Key", "valid-tok")
        .json(&json!({"source": "(module)"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        verify_503.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let vbody = verify_503.text().await.unwrap();
    assert!(
        !vbody.contains("rpc_url") && !vbody.contains(dead_url),
        "/verify leaked rpc_url: {vbody}"
    );
    dead_srv.abort();
    let _ = std::mem::size_of::<VerifiedSource>();
    let _: axum::routing::MethodRouter<()> = get(|| async {});
}

#[tokio::test]
async fn w6_a5_8_block_height_above_i64_max_returns_400_not_500() {
    let db = Database::open(":memory:").expect("db");
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 1,
        hash: "aa".repeat(32),
        timestamp: 1_792_000_000,
        tx_count: 0,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();

    let (base, client, srv) = spawn_with_connect_info(create_router(AppState::new(db))).await;

    let over_i64 = (i64::MAX as u64 + 1).to_string();
    let u64_max = u64::MAX.to_string();

    for param in [
        over_i64.as_str(),
        u64_max.as_str(),
        &format!("0:{over_i64}"),
        &format!("0:{u64_max}"),
    ] {
        let res = client
            .get(format!("{base}/api/v2/block/{param}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "/api/v2/block/{param} must return 400 instead of 500, got {}",
            res.status()
        );
    }
    srv.abort();
}
