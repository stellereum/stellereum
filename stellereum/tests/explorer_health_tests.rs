//! Operator health surface tests: `GET /health` + `GET /status`.
//!
//! The verdict is table-tested as a pure function; the HTTP surface is tested
//! against a fresh node (all optional subsystems empty) and against a node
//! whose last finalization is old enough to cross the documented threshold.
//! The TTL cache is tested in BOTH directions: a cached `critical` must not
//! survive past the TTL, and a cached `ok` must not hide a new `critical`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use stellereum::explorer::{
    self, evaluate_verdict, GatewayState, HealthFacts, HealthOptions, HealthStatus,
    HealthThresholds, ReadinessConfig,
};
use stellereum::mempool::Mempool;
use stellereum::rpc::{BlockSummary, ReceiptIndex, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn thresholds(min_peers: u64, max_lag: u64, critical_lag: u64) -> HealthThresholds {
    HealthThresholds {
        max_finalization_lag_secs: max_lag,
        critical_finalization_lag_secs: critical_lag,
        max_finalization_lag_blocks: 5,
        min_peers,
        max_mempool_oldest_age_secs: 300,
        max_persist_age_secs: 120,
        max_snapshot_age_secs: 3_600,
    }
}

fn healthy_facts() -> HealthFacts {
    HealthFacts {
        height: Some(100),
        finalization_lag_blocks: Some(0),
        finalization_lag_secs: Some(1),
        last_finalize_age_secs: Some(1),
        peer_count: Some(3),
        mempool_size: Some(2),
        mempool_oldest_age_secs: Some(1),
        last_persist_age_secs: Some(1),
        snapshot_age_secs: Some(10),
        consensus_round: Some(7),
        view_changes_last_5m: Some(0),
        rejected_proposals_total: Some(0),
        catch_up_mode: Some("at-tip".to_string()),
    }
}

#[test]
fn verdict_is_pure_and_table_tested() {
    let th = HealthThresholds::default();

    let ok = healthy_facts();
    let a = evaluate_verdict(&ok, &th);
    let b = evaluate_verdict(&ok, &th);
    assert_eq!(a, b, "verdict must be a pure function");
    assert_eq!(a.status, HealthStatus::Ok);
    assert!(a.reasons.is_empty(), "ok carries no reasons: {a:?}");

    // Degraded: finalization lag crosses the warning threshold but not the
    // critical one. The reason must name BOTH numbers.
    let mut lag = healthy_facts();
    lag.finalization_lag_secs = Some(14);
    lag.last_finalize_age_secs = Some(14);
    let v = evaluate_verdict(&lag, &th);
    assert_eq!(v.status, HealthStatus::Degraded, "{v:?}");
    assert!(
        v.reasons.iter().any(|r| r == "finalization lag 14 s > 5 s"),
        "exact lag reason: {:?}",
        v.reasons
    );

    // Critical: lag crosses the critical threshold.
    let mut stalled = healthy_facts();
    stalled.finalization_lag_secs = Some(61);
    stalled.last_finalize_age_secs = Some(61);
    let v = evaluate_verdict(&stalled, &th);
    assert_eq!(v.status, HealthStatus::Critical, "{v:?}");
    assert!(
        v.reasons
            .iter()
            .any(|r| r == "finalization lag 61 s > 60 s"),
        "exact critical reason: {:?}",
        v.reasons
    );

    // Degraded: network tip is too far ahead (block lag).
    let mut behind = healthy_facts();
    behind.finalization_lag_blocks = Some(6);
    let v = evaluate_verdict(&behind, &th);
    assert_eq!(v.status, HealthStatus::Degraded);
    assert!(
        v.reasons.iter().any(|r| r.contains("6 blocks > 5 blocks")),
        "{:?}",
        v.reasons
    );

    // Critical: zero peers with the default minimum.
    let mut peerless = healthy_facts();
    peerless.peer_count = Some(0);
    let v = evaluate_verdict(&peerless, &th);
    assert_eq!(v.status, HealthStatus::Critical);
    assert!(
        v.reasons.iter().any(|r| r.contains("0 peers observed")),
        "{:?}",
        v.reasons
    );

    // A solo/dev node opts out of the peer requirement.
    let solo = thresholds(0, 5, 60);
    let v = evaluate_verdict(&peerless, &solo);
    assert_eq!(v.status, HealthStatus::Ok, "{v:?}");

    // Degraded: old mempool head, slow persistence, stale snapshot.
    let mut aged = healthy_facts();
    aged.mempool_oldest_age_secs = Some(301);
    let v = evaluate_verdict(&aged, &th);
    assert_eq!(v.status, HealthStatus::Degraded);
    assert!(v.reasons.iter().any(|r| r.contains("oldest mempool tx")));

    let mut slow_disk = healthy_facts();
    slow_disk.last_persist_age_secs = Some(121);
    let v = evaluate_verdict(&slow_disk, &th);
    assert_eq!(v.status, HealthStatus::Degraded);
    assert!(v.reasons.iter().any(|r| r.contains("last persist age")));

    let mut stale_snap = healthy_facts();
    stale_snap.snapshot_age_secs = Some(3_601);
    let v = evaluate_verdict(&stale_snap, &th);
    assert_eq!(v.status, HealthStatus::Degraded);
    assert!(v.reasons.iter().any(|r| r.contains("snapshot age")));

    // Degraded: fresh node has nothing to prove yet.
    let mut fresh = healthy_facts();
    fresh.height = Some(0);
    fresh.finalization_lag_secs = None;
    fresh.last_finalize_age_secs = None;
    let v = evaluate_verdict(&fresh, &th);
    assert_eq!(v.status, HealthStatus::Degraded);
    assert!(v.reasons.iter().any(|r| r.contains("height 0")));
    assert!(
        v.reasons
            .iter()
            .any(|r| r.contains("no finalized block observed")),
        "{:?}",
        v.reasons
    );

    // Unavailable diagnostics are named, but do not fabricate a failure.
    let mut sparse = healthy_facts();
    sparse.finalization_lag_blocks = None;
    sparse.mempool_oldest_age_secs = None;
    sparse.consensus_round = None;
    let v = evaluate_verdict(&sparse, &th);
    assert_eq!(v.status, HealthStatus::Ok, "{v:?}");
    assert!(v
        .unknown
        .iter()
        .any(|u| u.contains("finalization block lag")));
    assert!(v.unknown.iter().any(|u| u.contains("consensus round")));
}

async fn state(height: u64, block_ts: Option<u64>) -> Arc<RpcState> {
    let st = Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(height)),
        node_id: "inf1:health-test".to_string(),
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
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: ShardRegistry::single(),
    });
    if let Some(ts) = block_ts {
        st.record_block(height, [0xABu8; 32], 1, ts).await;
    }
    st
}

fn gw(st: Arc<RpcState>, opts: HealthOptions) -> Arc<GatewayState> {
    Arc::new(
        GatewayState::with_captcha(
            st,
            10_000,
            ReadinessConfig {
                max_stall_secs: 30,
                min_peers: 0,
            },
            Arc::new(stellereum::turnstile::CaptchaGate::disabled()),
        )
        .with_health_options(opts),
    )
}

async fn spawn(gateway: Arc<GatewayState>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gateway).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

async fn http_get(addr: SocketAddr, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("health body must be JSON")
}

#[tokio::test]
async fn health_endpoint_is_shaped_and_safe_on_a_fresh_node() {
    let st = state(0, None).await;
    let addr = spawn(gw(
        st,
        HealthOptions {
            thresholds: thresholds(0, 5, 60),
            cache_ttl_ms: 20,
            data_dir: None,
        },
    ))
    .await;

    let (head, body) = http_get(addr, "/health").await;
    assert!(head.contains("200"), "fresh node health status: {head}");
    let v = json(&body);
    assert_eq!(v["schema"], "stellereum.health.v1");
    assert_eq!(v["identity"]["chain_id"], 5757);
    assert_eq!(v["identity"]["protocol_major"], 1);
    assert!(v["identity"]["fork_id"].is_number());
    assert_eq!(v["identity"]["node_id"], "inf1:health-test");
    assert_eq!(v["identity"]["shards"]["value"], serde_json::json!([0]));
    assert!(v["identity"]["software"]["string"]
        .as_str()
        .unwrap()
        .starts_with("stellereum/"));

    assert_eq!(v["chain"]["height"]["value"], 0);
    assert!(v["chain"]["finalized_height"]["value"].is_null());
    assert!(v["chain"]["finalized_height"]["reason"].is_string());
    assert!(v["chain"]["last_finalize_age"]["value"].is_null());
    assert!(v["chain"]["blocks_per_second"]["value"].is_null());
    assert!(v["chain"]["blocks_per_second"]["samples"].is_number());

    // Every consensus datum is present: measured or null + reason.
    assert!(v["consensus"]["round"].get("value").is_some());
    assert!(v["consensus"]["view_changes_last_5m"]["value"].is_null());
    assert!(v["consensus"]["view_changes_last_5m"]["reason"].is_string());
    assert!(v["consensus"]["rejected_proposals_total"]["value"].is_null());
    assert!(v["consensus"]["rejected_proposals_total"]["reason"].is_string());
    assert!(v["consensus"]["catch_up"]["mode"]["reason"].is_string());

    assert!(v["p2p"]["peer_count"]["value"].is_number());
    assert!(v["p2p"]["mesh"]["members"]["value"].is_null());
    assert!(v["p2p"]["mesh"]["members"]["reason"].is_string());
    // Phase 1 declares the byte counters but no production writer has run, so
    // they must be null + reason — never a fabricated zero.
    assert!(v["p2p"]["bytes"]["inbound_total"]["value"].is_null());
    assert!(v["p2p"]["bytes"]["inbound_total"]["reason"].is_string());
    assert!(v["p2p"]["bytes"]["outbound_total"]["value"].is_null());
    assert!(v["p2p"]["bytes"]["outbound_total"]["reason"].is_string());

    assert_eq!(v["mempool"]["size"]["value"], 0);
    // Empty pool: the accessor returns None (there is nothing to age), which
    // is reported as null + reason, not as age 0.
    assert!(v["mempool"]["oldest_pending_age"]["value"].is_null());
    assert_eq!(
        v["mempool"]["oldest_pending_age"]["reason"],
        "mempool is empty (no pending transaction to age)"
    );
    assert!(v["storage"]["data_dir_bytes"]["value"].is_null());
    assert!(v["storage"]["last_persist_age"]["value"].is_null());
    assert!(v["storage"]["last_persist_age"]["reason"].is_string());

    let status = v["verdict"]["status"].as_str().unwrap();
    assert!(matches!(status, "ok" | "degraded" | "critical"), "{status}");
    assert!(v["verdict"]["reasons"].is_array());
    assert!(
        !v["verdict"]["unknown"].as_array().unwrap().is_empty(),
        "missing producers must be named as unknown, not silently dropped"
    );

    let (head, html) = http_get(addr, "/status").await;
    assert!(head.contains("200"), "status page: {head}");
    assert!(html.contains("stellereum status"));
    assert!(html.contains(status));
}

#[tokio::test]
async fn health_reports_degraded_when_finalization_lag_exceeds_threshold() {
    let old = now_secs().saturating_sub(14);
    let st = state(9, Some(old)).await;
    let addr = spawn(gw(
        st,
        HealthOptions {
            thresholds: thresholds(0, 5, 60),
            cache_ttl_ms: 20,
            data_dir: None,
        },
    ))
    .await;

    let (head, body) = http_get(addr, "/health").await;
    assert!(head.contains("200"), "{head}");
    let v = json(&body);
    assert_eq!(v["chain"]["height"]["value"], 9);
    assert_eq!(v["chain"]["finalized_height"]["value"], 9);
    assert!(
        v["chain"]["last_finalize_age"]["value"].as_u64().unwrap() >= 14,
        "timestamp must be real: {body}"
    );
    assert_eq!(v["verdict"]["status"], "degraded", "{body}");
    let reasons = v["verdict"]["reasons"].as_array().unwrap();
    assert!(
        reasons
            .iter()
            .filter_map(|r| r.as_str())
            .any(|r| r.starts_with("finalization lag ") && r.contains("> 5 s")),
        "degraded reason must name the crossed threshold: {reasons:?}"
    );
}

async fn replace_recent(st: &RpcState, height: u64, ts: u64) {
    st.recent_blocks.write().await.clear();
    st.recent_blocks.write().await.push_front(BlockSummary {
        height,
        hash: hex::encode([0xABu8; 32]),
        tx_count: 1,
        timestamp: ts,
    });
}

#[tokio::test]
async fn health_cache_never_extends_a_stale_verdict_past_ttl() {
    // Critical lag threshold is 10 s in this test so the old sample is clearly
    // critical, and the fresh sample is clearly ok.
    let old = now_secs().saturating_sub(14);
    let st = state(5, Some(old)).await;
    let ttl_ms = 400;
    let addr = spawn(gw(
        st.clone(),
        HealthOptions {
            thresholds: thresholds(0, 5, 10),
            cache_ttl_ms: ttl_ms,
            data_dir: None,
        },
    ))
    .await;

    // Phase 1: a critical sample is cached as critical.
    let (_, body) = http_get(addr, "/health").await;
    let first = json(&body);
    assert_eq!(first["verdict"]["status"], "critical", "{body}");
    assert_eq!(first["cache"]["hit"], false);

    // Within the TTL the cached critical is served (and remains critical).
    let (_, body) = http_get(addr, "/health").await;
    let cached = json(&body);
    assert_eq!(cached["cache"]["hit"], true);
    assert_eq!(cached["verdict"]["status"], "critical");

    // The node recovers. A request INSIDE the TTL still sees the cached
    // critical; a request AFTER the TTL must recompute to ok.
    replace_recent(&st, 5, now_secs()).await;
    let (_, body) = http_get(addr, "/health").await;
    assert_eq!(
        json(&body)["verdict"]["status"],
        "critical",
        "within TTL the cache may serve the old sample"
    );
    tokio::time::sleep(std::time::Duration::from_millis(ttl_ms + 200)).await;
    let (_, body) = http_get(addr, "/health").await;
    let recovered = json(&body);
    assert_eq!(recovered["cache"]["hit"], false);
    assert_eq!(
        recovered["verdict"]["status"], "ok",
        "after TTL a stale critical must not be served: {body}"
    );

    // Phase 2 (the dangerous direction): a cached ok must not hide a new
    // critical beyond the TTL either.
    let (_, body) = http_get(addr, "/health").await;
    assert_eq!(json(&body)["verdict"]["status"], "ok");
    replace_recent(&st, 5, now_secs().saturating_sub(14)).await;
    let (_, body) = http_get(addr, "/health").await;
    assert_eq!(
        json(&body)["verdict"]["status"],
        "ok",
        "within TTL the cache may serve the old ok sample"
    );
    tokio::time::sleep(std::time::Duration::from_millis(ttl_ms + 200)).await;
    let (_, body) = http_get(addr, "/health").await;
    let degraded = json(&body);
    assert_eq!(degraded["cache"]["hit"], false);
    assert_eq!(
        degraded["verdict"]["status"], "critical",
        "after TTL a stale ok must not hide a new critical: {body}"
    );
}
