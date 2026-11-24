//! Wave 4 pentest close-out — RPC / remote-signer hardening regressions.
//!
//! One test per finding, against the real code paths (no mocks):
//!
//! * S3-REMOTE-SIGNER-SAFETY-BYPASS:
//!   - `ConsensusSafetyState::check_and_advance` must not skip the lock check
//!     for a non-nil vote that carries no `value_id` while a lock exists;
//!   - a cross-kind equivocation (Prevote(r,A) then Precommit(r,B), B != A)
//!     must violate;
//!   - `LocalPqSigner` (the same `PqSigner` impl the runtime drives) must
//!     refuse the bypass once `set_consensus_lock` / `value_id` are threaded;
//!   - `serve_v2_http_connection*` bounds the request line, the header count
//!     and the body, and authenticates the bearer token in constant time.
//! * S3-SUBSCRIPTION-IPV6-AND-SSE-REFCOUNT:
//!   - the per-client subscription quota is keyed on the /64 bucket, not the
//!     exact address (rotating the interface id mints no fresh quota);
//!   - `attached` is a refcount, so dropping ONE of two streams keeps the
//!     subscription attached.
//! * S3-GATEWAY-BATCH-RATE-BYPASS: batch items on the gateway `/rpc` mount
//!   draw from the gateway's per-IP limiter (not the 300/s standalone one).
//! * S3-VERIFY-SOURCE-UNTHROTTLED: `stell_verifyContractSource` is classified
//!   expensive on WS and for the HTTP concurrency semaphore.
//! * S3-RATE-LIMITER-HARD-CAP: `RateLimiter` fails closed for new keys once a
//!   shard is at its entry cap, and recovers after the window ages out.
//!
//! Everything binds ephemeral loopback listeners only. Tests share the
//! process-wide subscription hub and WS-cap override, so the streaming ones
//! serialize on `SERIAL`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::RwLock;

use axum::extract::Query;
use stellereum::consensus::VoteKind;
use stellereum::explorer::{RateLimiter, RATE_LIMITER_MAX_ENTRIES_PER_SHARD};
use stellereum::mempool::Mempool;
use stellereum::post_quantum::FalconKeypair;
use stellereum::remote_signer::{
    serve_v2_http_connection_with_timeout, ConsensusSafetyState, ConsensusSignRequest,
    LocalPqSigner, PqSigner, PqSignerService, SignerError, FALCON_SIGNATURE_LEN,
};
use stellereum::rpc::{
    hub, is_ws_expensive_method, rpc_rate_buckets, ws_active_connections, ws_max_connections,
    ReceiptIndex, RpcState, StreamQuery, SubscriptionTopic, MAX_SUBSCRIPTIONS_PER_CLIENT,
    WS_MAX_CONNECTIONS,
};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn test_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "w4-rpc-signer-hardening".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn serve(app: axum::Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    (addr, server)
}

async fn poll_until<F: Fn() -> bool>(what: &str, limit: Duration, f: F) {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn vote(
    height: u64,
    round: u32,
    kind: VoteKind,
    block_hash: Option<[u8; 32]>,
) -> ConsensusSignRequest {
    ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height,
        round,
        kind,
        block_hash,
    }
}

// ---------------------------------------------------------------------------
// S3-REMOTE-SIGNER-SAFETY-BYPASS (a)/(b): guard rules
// ---------------------------------------------------------------------------

/// A non-nil vote with `value_id == None` MUST NOT slip past the lock check.
///
/// This is the exact bypass: the old code only compared when BOTH the locked
/// value id and the request value id were `Some`, so a request that simply
/// omitted `value_id` was signed against the lock.
#[test]
fn non_nil_vote_without_value_id_is_refused_under_lock() {
    let locked = [0xA1u8; 32];
    let state = ConsensusSafetyState {
        height: 5,
        locked_round: Some(2),
        locked_value_id: Some(locked),
        ..Default::default()
    };
    let target = [0x42u8; 32];

    for kind in [VoteKind::Prevote, VoteKind::Precommit] {
        let req = vote(5, 3, kind, Some(target));
        assert_eq!(
            state.check_and_advance(&req, None),
            Err(SignerError::SafetyViolation),
            "{kind:?} with no value_id must be refused while locked"
        );
        assert_eq!(
            state.check_and_advance(&req, Some([0xB2u8; 32])),
            Err(SignerError::SafetyViolation),
            "{kind:?} for a different value must be refused while locked"
        );
        assert!(
            state.check_and_advance(&req, Some(locked)).is_ok(),
            "{kind:?} for the locked value must be allowed"
        );
    }

    // A NIL vote endorses nothing and stays allowed under a lock.
    let nil = vote(5, 3, VoteKind::Prevote, None);
    assert!(state.check_and_advance(&nil, None).is_ok());
}

/// Prevote(r, A) followed by Precommit(r, B) with B != A is a cross-kind
/// equivocation and MUST violate; the same value at a later round is fine.
#[test]
fn cross_kind_equivocation_in_the_same_round_violates() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let base = ConsensusSafetyState {
        height: 9,
        ..Default::default()
    };

    let after_prevote = base
        .check_and_advance(&vote(9, 3, VoteKind::Prevote, Some(a)), Some(a))
        .expect("first prevote is safe");

    assert_eq!(
        after_prevote.check_and_advance(&vote(9, 3, VoteKind::Precommit, Some(b)), Some(b)),
        Err(SignerError::SafetyViolation),
        "precommit for a different value in the same round must be refused"
    );
    assert!(
        after_prevote
            .check_and_advance(&vote(9, 3, VoteKind::Precommit, Some(a)), Some(a))
            .is_ok(),
        "precommit for the prevoted value is the normal path"
    );
    assert!(
        after_prevote
            .check_and_advance(&vote(9, 4, VoteKind::Precommit, Some(b)), Some(b))
            .is_ok(),
        "a later round may endorse a different value (polka relock)"
    );

    // Symmetric direction: Precommit(r, A) then Prevote(r, B) must also fail.
    let after_precommit = base
        .check_and_advance(&vote(9, 3, VoteKind::Precommit, Some(a)), Some(a))
        .expect("first precommit is safe");
    assert_eq!(
        after_precommit.check_and_advance(&vote(9, 3, VoteKind::Prevote, Some(b)), Some(b)),
        Err(SignerError::SafetyViolation)
    );
}

/// The runtime threads the real `value_id` + lock state through `PqSigner`
/// (`RuntimeVoteSigner::sign_pq_with_safety` -> `set_consensus_lock` ->
/// `sign_consensus_checked_with_value_id`). Prove the same trait surface on
/// `LocalPqSigner` refuses the omission end-to-end.
#[test]
fn pq_signer_lock_is_enforced_through_value_id_threading() {
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x5Au8; 32]);
    let vid = kp.validator_id();
    let signer = LocalPqSigner::new(kp, vid).expect("local pq signer");

    let locked_value = [0x77u8; 32];
    signer
        .set_consensus_lock(12, 1, locked_value)
        .expect("lock is forward");

    let req = vote(12, 2, VoteKind::Prevote, Some([0x33u8; 32]));
    assert_eq!(
        signer.sign_consensus_with_value_id(&req, None),
        Err(SignerError::SafetyViolation),
        "omitting value_id must never bypass a live lock"
    );
    let sig = signer
        .sign_consensus_with_value_id(&req, Some(locked_value))
        .expect("vote for the locked value signs");
    assert_eq!(sig.len(), FALCON_SIGNATURE_LEN);

    // The anti-oracle checked wrapper enforces the same rule (fresh round so
    // the refusal is unambiguously the lock, not mere round monotonicity).
    let checked_req = vote(12, 3, VoteKind::Prevote, Some([0x33u8; 32]));
    let preimage = checked_req.canonical_signing_bytes();
    assert_eq!(
        signer.sign_consensus_checked_with_value_id(&checked_req, &preimage, None),
        Err(SignerError::SafetyViolation)
    );
}

// ---------------------------------------------------------------------------
// S3-REMOTE-SIGNER-SAFETY-BYPASS (d): v2 HTTP connection bounds
// ---------------------------------------------------------------------------

fn spawn_v2_signer(
    service: Arc<PqSignerService>,
    connections: usize,
    io_timeout: Duration,
) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(connections).flatten() {
            serve_v2_http_connection_with_timeout(&service, stream, io_timeout);
        }
    });
    (addr, handle)
}

fn raw_exchange(addr: SocketAddr, request: &[u8]) -> String {
    use std::io::{Read, Write};
    let mut sock = std::net::TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("client timeout");
    sock.write_all(request).expect("write");
    sock.flush().expect("flush");
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn v2_http_bounds_request_line_headers_and_authenticates() {
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x5Bu8; 32]);
    let vid = kp.validator_id();
    let service = Arc::new(
        PqSignerService::new(LocalPqSigner::new(kp, vid).expect("signer"))
            .with_bearer_token("w4-secret-token"),
    );
    let (addr, server) = spawn_v2_signer(Arc::clone(&service), 5, Duration::from_secs(5));

    // Correct token: 200.
    let ok = raw_exchange(
        addr,
        b"GET /v2/public_key HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer w4-secret-token\r\nConnection: close\r\n\r\n",
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "authorized: {ok}");

    // Same-length wrong token: 401 (constant-time compare, same shape).
    let wrong = raw_exchange(
        addr,
        b"GET /v2/public_key HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer w4-secret-tokeN\r\nConnection: close\r\n\r\n",
    );
    assert!(wrong.starts_with("HTTP/1.1 401"), "unauthorized: {wrong}");

    // Request line above the 8 KiB bound: 431, before any allocation.
    let long_line = format!(
        "GET /{} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer w4-secret-token\r\n\r\n",
        "a".repeat(9000)
    );
    let long = raw_exchange(addr, long_line.as_bytes());
    assert!(long.starts_with("HTTP/1.1 431"), "long line: {long}");

    // More than 64 header lines: 431.
    let mut many = String::from(
        "GET /v2/public_key HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer w4-secret-token\r\n",
    );
    for i in 0..65 {
        many.push_str(&format!("X-Bound-{i}: v\r\n"));
    }
    many.push_str("\r\n");
    let headers = raw_exchange(addr, many.as_bytes());
    assert!(headers.starts_with("HTTP/1.1 431"), "headers: {headers}");

    // Body above the 64 KiB bound: 413 before the body is read into memory.
    let oversized = raw_exchange(
        addr,
        b"POST /v2/sign HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer w4-secret-token\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n",
    );
    assert!(
        oversized.starts_with("HTTP/1.1 413"),
        "body bound: {oversized}"
    );

    server.join().expect("server thread");

    // A client that never sends a request line is cut off by the read timeout
    // with a 408 instead of pinning a worker forever.
    let (addr, server) = spawn_v2_signer(service, 1, Duration::from_millis(200));
    let timed_out = raw_exchange(addr, b"");
    assert!(
        timed_out.starts_with("HTTP/1.1 408"),
        "read timeout: {timed_out}"
    );
    server.join().expect("timeout server thread");
}

// ---------------------------------------------------------------------------
// S3-SUBSCRIPTION-IPV6-AND-SSE-REFCOUNT
// ---------------------------------------------------------------------------

/// Rotating the low 64 bits of an IPv6 address must not mint a fresh
/// per-client subscription quota: the budget key is the /64.
#[test]
fn subscription_quota_is_keyed_on_the_ipv6_slash_64() {
    let subnet_a_1: Ipv6Addr = "2001:db8:5153:1::1".parse().unwrap();
    let subnet_a_2: Ipv6Addr = "2001:db8:5153:1::dead:beef".parse().unwrap();
    let subnet_b: Ipv6Addr = "2001:db8:5153:2::1".parse().unwrap();

    let mut ids = Vec::new();
    let client_a = subnet_a_1.to_string();
    for _ in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
        let id = hub()
            .subscribe_for(SubscriptionTopic::NewHeads, Some(client_a.as_str()))
            .expect("quota slot");
        ids.push(id);
    }
    // Same /64, different interface identifier: the quota must be exhausted.
    let rotated_client = subnet_a_2.to_string();
    let rotated = hub().subscribe_for(SubscriptionTopic::NewHeads, Some(rotated_client.as_str()));
    assert!(
        rotated.is_err(),
        "rotating the IPv6 interface id must not mint a fresh quota"
    );
    // A different /64 is a different client bucket.
    let other_client = subnet_b.to_string();
    let other = hub()
        .subscribe_for(SubscriptionTopic::NewHeads, Some(other_client.as_str()))
        .expect("an independent /64 keeps its own quota");
    ids.push(other);

    for id in ids {
        hub().unsubscribe(&id);
    }
}

/// The SSE transport funnels through the same `subscribe_for`, so its
/// per-client quota must also be the `/64` bucket: 64 streams from one host,
/// then a rotated interface identifier in the same `/64` gets `429`, while a
/// different `/64` still opens a stream.
#[tokio::test]
async fn sse_quota_is_keyed_on_the_ipv6_slash_64() {
    let host_a_1: Ipv6Addr = "2001:db8:5153:7::1".parse().unwrap();
    let host_a_2: Ipv6Addr = "2001:db8:5153:7::2".parse().unwrap();
    let host_b: Ipv6Addr = "2001:db8:5153:8::1".parse().unwrap();
    let query = || {
        Query(StreamQuery {
            sub_id: None,
            topics: Some("newHeads".to_string()),
            contract: None,
            event_topics: None,
        })
    };

    let mut streams = Vec::new();
    for i in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
        let peer = SocketAddr::new(IpAddr::V6(host_a_1), 5000 + i as u16);
        let resp = stellereum::rpc::sse_handler(
            axum::http::HeaderMap::new(),
            Some(axum::extract::ConnectInfo(peer)),
            query(),
        )
        .await
        .expect("within the per-/64 SSE quota");
        streams.push(resp);
    }

    let rotated_peer = SocketAddr::new(IpAddr::V6(host_a_2), 6000);
    let refused = stellereum::rpc::sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(rotated_peer)),
        query(),
    )
    .await;
    assert_eq!(
        refused.err(),
        Some(axum::http::StatusCode::TOO_MANY_REQUESTS),
        "rotating the IPv6 interface id must not mint a fresh SSE quota"
    );

    let other_peer = SocketAddr::new(IpAddr::V6(host_b), 7000);
    let allowed = stellereum::rpc::sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(other_peer)),
        query(),
    )
    .await;
    assert!(
        allowed.is_ok(),
        "an independent /64 keeps its own SSE quota"
    );

    drop(streams);
}

/// `attached` is a live-transport refcount: dropping one of several SSE
/// streams must not mark the subscription detached (the TTL sweep would then
/// reap a subscription another stream still serves).
#[test]
fn attached_refcount_survives_one_of_two_detaches() {
    let client = "2001:db8:5153:9::1";
    let id = hub()
        .subscribe_for(SubscriptionTopic::NewHeads, Some(client))
        .expect("subscribe");

    hub().attach(&id); // SSE stream 1
    hub().attach(&id); // SSE stream 2
    let both = hub().get(&id).expect("subscription exists");
    assert_eq!(both.attached_count, 2);
    assert!(both.attached);

    hub().detach(&id); // stream 1 drops
    let one = hub().get(&id).expect("subscription exists");
    assert_eq!(one.attached_count, 1);
    assert!(
        one.attached,
        "one live stream must keep the subscription attached"
    );

    hub().detach(&id); // stream 2 drops
    let none = hub().get(&id).expect("subscription exists");
    assert_eq!(none.attached_count, 0);
    assert!(!none.attached);

    hub().unsubscribe(&id);
}

/// The global WS connection cap rejects the upgrade itself (HTTP 503) before
/// a session exists, and the RAII guard releases the slot when the session
/// ends.
#[tokio::test]
async fn ws_connection_cap_is_enforced_before_upgrade_and_released() {
    let _serial = SERIAL.lock().await;
    assert_eq!(ws_max_connections(), WS_MAX_CONNECTIONS);
    stellereum::rpc::set_ws_max_connections_for_tests(1);
    let st = test_state().await;
    let (addr, server) = serve(stellereum::rpc::router(st.clone())).await;

    let mut first = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("first WS fills the single slot");
    poll_until("first slot reserved", Duration::from_secs(5), || {
        ws_active_connections() == 1
    })
    .await;

    let second = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await;
    assert!(
        second.is_err(),
        "an over-cap upgrade must be refused, not accepted and dropped"
    );

    let _ = first.0.close(None).await;
    poll_until("slot released on close", Duration::from_secs(10), || {
        ws_active_connections() == 0
    })
    .await;
    let mut third = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("released slot is reusable");
    let _ = third.0.close(None).await;

    stellereum::rpc::set_ws_max_connections_for_tests(0);
    server.abort();
}

// ---------------------------------------------------------------------------
// S3-GATEWAY-BATCH-RATE-BYPASS
// ---------------------------------------------------------------------------

async fn post_json(addr: SocketAddr, path: &str, body: &Value) -> (u16, Value) {
    let body = body.to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let text = tokio::task::spawn_blocking(move || raw_exchange(addr, request.as_bytes()))
        .await
        .expect("blocking exchange");
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text}"));
    let payload = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_else(|| panic!("no HTTP body in response: {text}"));
    (
        status,
        serde_json::from_str(payload).expect("json response"),
    )
}

/// A batch on the gateway `/rpc` mount must draw per ITEM from the gateway's
/// configured per-IP limiter. With a 2/s gateway budget, a 20-item batch can
/// answer at most three items — one charge from the request middleware plus at
/// most two from one item window (the extra headroom tolerates a one-second
/// window rollover mid-batch) — and the rest must be refused with the
/// per-item `-32000` shape. Before the fix every item drew from the 300/s
/// standalone budget, so all twenty answered.
#[tokio::test]
async fn gateway_batch_items_draw_from_gateway_limiter() {
    let _serial = SERIAL.lock().await;
    let st = test_state().await;
    let gateway = Arc::new(stellereum::explorer::GatewayState::new(st, 2));
    let (addr, server) = serve(stellereum::explorer::router(gateway)).await;

    const ITEMS: usize = 20;
    let items: Vec<Value> = (0..ITEMS)
        .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "stell_blockNumber", "params": {}}))
        .collect();
    let (status, body) = post_json(addr, "/rpc", &Value::Array(items)).await;
    assert_eq!(status, 200, "the batch itself is admitted once: {body}");
    let arr = body.as_array().expect("batch response array");
    assert_eq!(arr.len(), ITEMS);

    let answered = arr.iter().filter(|v| v.get("result").is_some()).count();
    let limited = arr
        .iter()
        .filter(|v| v["error"]["code"] == json!(-32000))
        .count();
    assert_eq!(
        answered + limited,
        ITEMS,
        "every item is either answered or per-item rate limited: {arr:?}"
    );
    assert!(
        answered <= 3,
        "batch items must consume the gateway 2/s budget (max 3 in one window): {arr:?}"
    );
    assert!(answered >= 1, "the in-budget item answers: {arr:?}");
    assert!(
        limited >= ITEMS - 3,
        "the gateway budget, not the 300/s standalone one, must apply: {arr:?}"
    );

    server.abort();
}

// ---------------------------------------------------------------------------
// S3-VERIFY-SOURCE-UNTHROTTLED
// ---------------------------------------------------------------------------

/// `stell_verifyContractSource` runs a full `wat::parse_str` (offloaded to
/// `spawn_blocking`) and must therefore draw the expensive-read budget on WS
/// and the HTTP concurrency semaphore (`try_acquire_http_expensive_read`
/// gates on exactly `is_ws_expensive_method`).
#[test]
fn verify_contract_source_is_classified_expensive() {
    assert!(
        is_ws_expensive_method("stell_verifyContractSource"),
        "source verification must draw the per-IP expensive-read budget"
    );
    let buckets = rpc_rate_buckets("stell_verifyContractSource");
    assert!(buckets.contains(&"transport"));
    assert!(
        buckets.contains(&"expensive-ws"),
        "audit table must mirror the classifier: {buckets:?}"
    );
    assert!(!buckets.contains(&"expensive"), "it is not an estimate");
    // Cheap reads stay cheap.
    assert!(!is_ws_expensive_method("stell_blockNumber"));
    assert!(!is_ws_expensive_method("stell_getContractSource"));
}

// ---------------------------------------------------------------------------
// S3-RATE-LIMITER-HARD-CAP
// ---------------------------------------------------------------------------

/// At the per-shard entry cap a new key is refused (fail closed) instead of
/// growing the map without bound; once the fixed window ages out the same key
/// is admitted again.
#[test]
fn rate_limiter_hard_caps_entries_and_fails_closed() {
    let limiter = RateLimiter::new(10);
    let total_cap = RATE_LIMITER_MAX_ENTRIES_PER_SHARD * 16;
    let now = 1_000u64;

    // Fill every shard to its cap. Once a shard is full, candidates hashing to
    // it are refused, so the loop naturally converges on exactly `total_cap`.
    let mut i: u32 = 0;
    while limiter.total_tracked_entries() < total_cap && i < 1_000_000 {
        limiter.check_at(IpAddr::V4(Ipv4Addr::from(i)), now);
        i += 1;
    }
    assert_eq!(
        limiter.total_tracked_entries(),
        total_cap,
        "the limiter must never exceed {} tracked buckets",
        total_cap
    );

    // A brand-new key at the same instant is refused, not inserted.
    let fresh = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 250));
    assert!(
        !limiter.check_at(fresh, now),
        "a new key at the hard cap must fail closed"
    );
    assert_eq!(
        limiter.total_tracked_entries(),
        total_cap,
        "a refused key must not grow the map"
    );

    // Two seconds later the old windows are stale: the map shrinks and the
    // same key is serviceable again.
    assert!(limiter.check_at(fresh, now + 2));
    assert!(
        limiter.total_tracked_entries() <= total_cap,
        "stale windows are dropped instead of accumulating"
    );

    limiter.prune(now + 2);
    assert_eq!(limiter.total_tracked_entries(), 1);
}
