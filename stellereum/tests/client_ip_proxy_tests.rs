//! Proxy-aware IP tests: the gateway/explorer must key rate limits (and, via
//! the same `resolve_client_ip`, faucet budgets + Turnstile `remoteip`) on the
//! real client IP from `X-Forwarded-For` when the TCP peer is a trusted proxy
//! — not on the proxy's own address.
//!
//! The TCP peer in these tests is always 127.0.0.1, which is trusted by the
//! default `STELL_TRUSTED_PROXY_CIDRS` (loopback only), so `X-Forwarded-For`
//! must be honored without touching env vars (env is process-global; mutating
//! it here would race other tests in this binary).

use std::sync::Arc;
use stellereum::explorer::{self, GatewayState};
use stellereum::rpc::RpcState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn state() -> Arc<RpcState> {
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:proxy-ip".to_string(),
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
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

async fn spawn_gateway(per_sec: u32) -> std::net::SocketAddr {
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
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
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
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

fn unix_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The limiter must keep separate buckets per X-Forwarded-For identity even
/// though every TCP connection comes from the same proxy (127.0.0.1).
/// Before the fix all of these shared the 127.0.0.1 bucket: exhausting it
/// with identity A also throttled identity B.
#[tokio::test]
async fn limiter_distinguishes_ips_behind_trusted_proxy() {
    const PER_SEC: u32 = 3;
    // Fixed-window buckets reset on second boundaries; retry on a fresh
    // gateway if the wall clock rolls over mid-burst (otherwise a rollover
    // would reset the shared bucket and mask the bug).
    for _attempt in 0..5 {
        let addr = spawn_gateway(PER_SEC).await;
        let start = unix_sec();
        let a_headers = [("X-Forwarded-For", "1.2.3.4")];
        // Spend identity A's whole budget inside one second.
        let mut a_ok = 0;
        for _ in 0..PER_SEC {
            let (head, _) = http_get_with(addr, "/api/stats", &a_headers).await;
            if unix_sec() != start {
                break; // rolled over; retry
            }
            assert!(
                head.contains("200"),
                "identity A within budget must pass: {head}"
            );
            a_ok += 1;
        }
        if unix_sec() != start || a_ok != PER_SEC {
            continue; // second rolled over mid-burst; retry cleanly
        }
        // One more request as A must now be throttled.
        let (head_a, _) = http_get_with(addr, "/api/stats", &a_headers).await;
        if unix_sec() != start {
            continue;
        }
        assert!(
            head_a.contains("429"),
            "identity A over budget must be 429: {head_a}"
        );
        // A DIFFERENT client behind the same proxy must still have its own
        // full budget — this is exactly what failed when every client looked
        // like 127.0.0.1 (B got 429 from A's spending).
        let (head_b, _) =
            http_get_with(addr, "/api/stats", &[("X-Forwarded-For", "5.6.7.8")]).await;
        assert!(
            head_b.contains("200"),
            "identity B must have its own bucket (got: {head_b}); \
             limiter is still keyed on the proxy address"
        );
        return;
    }
    panic!("could not fit the burst into a single second after retries");
}

/// Without any forwarding headers the TCP peer is the identity (sanity: the
/// change must not break direct clients, and unknown/garbage XFF must fall
/// back to the peer rather than bypass the limiter).
#[tokio::test]
async fn limiter_falls_back_to_peer_on_garbage_headers() {
    const PER_SEC: u32 = 2;
    for _attempt in 0..5 {
        let addr = spawn_gateway(PER_SEC).await;
        let start = unix_sec();
        let garbage = [("X-Forwarded-For", "garbage;;;")];
        let mut ok = true;
        for _ in 0..PER_SEC {
            let (head, _) = http_get_with(addr, "/api/stats", &garbage).await;
            if unix_sec() != start {
                ok = false;
                break;
            }
            if !head.contains("200") {
                ok = false;
                break;
            }
        }
        if !ok || unix_sec() != start {
            continue;
        }
        let (head, _) = http_get_with(addr, "/api/stats", &garbage).await;
        if unix_sec() != start {
            continue;
        }
        assert!(
            head.contains("429"),
            "garbage XFF must fall back to the peer bucket and throttle: {head}"
        );
        return;
    }
    panic!("could not fit the burst into a single second after retries");
}
