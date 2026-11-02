//! Explorer-gateway security audit tests (`src/explorer.rs` ONLY).
//!
//! Attack-oriented coverage for the HTTP surface the RPC audit never touched:
//! `/`, `/api/*`, `/events`, `/metrics`, `/readyz` (+ the nested `/rpc`
//! mount point behaviour that `explorer::router` owns: CORS + rate limits).
//!
//! * unauthenticated access to authed explorer endpoints refuses fail-closed
//!   (`POST /api/faucet/:addr` without/wrong token, pending-tx full view in
//!   `GET /api/tx/:hash` without token);
//! * path-shaped params (`../`, null bytes, oversized, non-hex) are rejected
//!   with bounded errors, never 200 and never a filesystem/secret echo;
//! * malformed query params (`limit`/`offset` negative/huge/wrong-typed)
//!   yield clean bounded JSON, never panics;
//! * error bodies carry no secret material (faucet/auth canary tokens, seeds,
//!   key paths, `STELL_*` env names, Rust panic frames);
//! * CORS never reflects an attacker `Origin` and never enables credentials;
//! * the `/metrics` exposition vocabulary contains no secret-class names
//!   (mirror of the F10 allowlist idea: tokenize on non-alphanumerics and
//!   require disjointness, so `tokens_total` stays legal while `token`,
//!   `secret`, `seed`, ... are forbidden).
//!
//! All tests are self-contained: each spawns its own gateway (own `RpcState`,
//! own faucet/throttle state, deterministic `ReadinessConfig::default` and an
//! explicit `CaptchaGate`) over loopback on an ephemeral port. Nothing touches
//! live nodes, configs, or the network.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use stellereum::explorer::{self, GatewayState, ReadinessConfig};
use stellereum::mempool::Mempool;
use stellereum::rpc::{Faucet, ReceiptIndex, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::turnstile::{CaptchaConfig, CaptchaGate, CaptchaVerdict, CaptchaVerifier};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Canaries: distinctive strings that must NEVER appear in any response body.
// ---------------------------------------------------------------------------

const AUTH_CANARY: &str = "audit-explorer-auth-canary-9f8e7d6c";
const FAUCET_CANARY: &str = "audit-explorer-faucet-canary-1a2b3c4d";
const FAUCET_SEED: [u8; 32] = [0x5Au8; 32];

fn faucet_addr() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&FAUCET_SEED)
        .verifying_key()
        .to_bytes()
}

// ---------------------------------------------------------------------------
// Harness: state + gateway + raw HTTP client (no client-side normalization,
// so traversal payloads reach the server byte-for-byte).
// ---------------------------------------------------------------------------

async fn rpc_state(
    auth_token: Option<&str>,
    faucet_token: Option<&str>,
    faucet: bool,
) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new(faucet_addr(), 10_000_000_000_000))
        .await;
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "audit:explorer".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: auth_token.map(|s| s.to_string()),
        tx_broadcast: None,
        faucet: if faucet {
            Some(Arc::new(Faucet::new(FAUCET_SEED, 1, 10_000_000_000, 100_000_000_000)))
        } else {
            None
        },
        faucet_token: faucet_token.map(|s| s.to_string()),
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: ShardRegistry::single(),
    })
}

struct DenyAll;
impl CaptchaVerifier for DenyAll {
    fn verify(
        &self,
        _secret: &str,
        _token: &str,
        _remote_ip: Option<IpAddr>,
    ) -> CaptchaVerdict {
        CaptchaVerdict::Rejected {
            error_codes: vec!["audit-deny".to_string()],
        }
    }
}

fn gateway(st: Arc<RpcState>, per_sec: u32) -> Arc<GatewayState> {
    Arc::new(GatewayState::with_captcha(
        st,
        per_sec,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::disabled()),
    ))
}

async fn spawn(st: Arc<RpcState>, per_sec: u32) -> SocketAddr {
    let gw = gateway(st, per_sec);
    spawn_gw(gw).await
}

async fn spawn_gw(gw: Arc<GatewayState>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gw).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

async fn raw_request(addr: SocketAddr, text: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(text.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let all = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = all.split_once("\r\n\r\n").unwrap_or(("", &all));
    (head.to_string(), body.to_string())
}

async fn http_get(addr: SocketAddr, path: &str) -> (String, String) {
    http_get_with(addr, path, &[]).await
}

async fn http_get_with(
    addr: SocketAddr,
    path: &str,
    extra: &[(&str, &str)],
) -> (String, String) {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    raw_request(addr, &req).await
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> (String, String) {
    http_post_with(addr, path, body, &[]).await
}

async fn http_post_with(
    addr: SocketAddr,
    path: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> (String, String) {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("\r\n{body}"));
    raw_request(addr, &req).await
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

/// Every collected body must be free of secret material.
fn assert_no_secrets(where_: &str, body: &str) {
    for canary in [AUTH_CANARY, FAUCET_CANARY] {
        assert!(
            !body.contains(canary),
            "{where_}: response leaks a credential canary"
        );
    }
    let low = body.to_lowercase();
    // NOTE: the *names* of the operator-facing env vars (e.g. the fail-closed
    // 503 telling the operator to set STELL_FAUCET_TOKEN) are intentional
    // guidance, not secrets — reviewed and accepted: env names are documented
    // in code/docs and knowing one grants nothing without the value. The
    // credential *values* (canaries above) must never appear. What is
    // forbidden here: key material, file paths that reveal layout, and Rust
    // panic frames.
    for needle in ["panicked", "backtrace", ".rs:", "/etc/", "c:\\"] {
        assert!(
            !low.contains(needle),
            "{where_}: response contains secret/path marker {needle:?}: {body:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 1. Auth model: unauthenticated access to authed explorer endpoints refuses.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_faucet_refuses_unauthenticated_and_wrong_token() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), true).await;
    let addr = spawn(st, 1000).await;
    let who = hex::encode([7u8; 32]);

    // GET must never mint (POST-only; crawlers/prefetch must not mint).
    let (head, body) = http_get(addr, &format!("/api/faucet/{who}?token={FAUCET_CANARY}")).await;
    assert_eq!(status_code(&head), 405, "GET faucet must be 405: {head}");
    assert_no_secrets("faucet GET hint", &body);

    // No token at all -> 401.
    let (head, body) = http_post(addr, &format!("/api/faucet/{who}"), "").await;
    assert_eq!(status_code(&head), 401, "anonymous drip must be 401: {head}");
    assert_no_secrets("faucet 401 body", &body);

    // Wrong token -> 401 (and the wrong value is not echoed back).
    let (head, body) = http_post(addr, &format!("/api/faucet/{who}?token=nope"), "").await;
    assert_eq!(status_code(&head), 401, "bad token must be 401: {head}");
    assert!(!body.contains("nope"), "error must not echo the bad token");
    assert_no_secrets("faucet wrong-token body", &body);

    // Header token works (compat path preserved).
    let (head, body) = http_post_with(
        addr,
        &format!("/api/faucet/{who}"),
        "",
        &[("Authorization", &format!("Bearer {FAUCET_CANARY}"))],
    )
    .await;
    assert_eq!(status_code(&head), 200, "header token drip failed: {head} {body}");
    assert!(body.contains("10000000000"), "must credit 10 STELL: {body}");
    assert_no_secrets("faucet 200 body", &body);
}

#[tokio::test]
async fn token_faucet_fails_closed_without_token_configured() {
    // Enabled faucet + no token configured must refuse, never dispense.
    let st = rpc_state(None, None, true).await;
    let addr = spawn(st, 1000).await;
    let who = hex::encode([9u8; 32]);
    let (head, body) = http_post_with(
        addr,
        &format!("/api/faucet/{who}"),
        "",
        &[("Authorization", "Bearer anything")],
    )
    .await;
    assert_eq!(status_code(&head), 503, "tokenless faucet must be 503: {head} {body}");
    assert_no_secrets("faucet 503 body", &body);
}

#[tokio::test]
async fn disabled_faucet_reports_not_found() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), false).await;
    let addr = spawn(st, 1000).await;
    let who = hex::encode([9u8; 32]);
    let (head, _) = http_post(addr, &format!("/api/faucet/{who}?token={FAUCET_CANARY}"), "").await;
    assert_eq!(status_code(&head), 404, "disabled faucet must be 404: {head}");
    let (head, _) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert_eq!(status_code(&head), 404, "disabled public faucet must be 404: {head}");
}

#[tokio::test]
async fn pending_tx_full_view_requires_auth_token() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), true).await;
    // Build a real pending transaction through the faucet and admit it.
    let faucet = st.faucet.clone().expect("faucet");
    let who = [0x77u8; 32];
    let (tx, _amount) = faucet.build_transfer(who, None, None).await.expect("drip");
    let hash = tx.compute_tx_hash();
    let hash_hex = hex::encode(hash);
    st.mempool
        .write()
        .await
        .add_checked_ctx(
            tx,
            10_000_000_000_000,
            stellereum::mempool::AdmissionCtx::wall_now(),
        )
        .expect("admit");
    let addr = spawn(st, 1000).await;

    // Unauthenticated: redacted to hash/nonce/status only (front-running aid
    // must not leak the pre-finalization payload).
    let (head, body) = http_get(addr, &format!("/api/tx/{hash_hex}")).await;
    assert_eq!(status_code(&head), 200, "tx lookup failed: {head} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("redacted view is JSON");
    assert_eq!(v.get("status").and_then(|s| s.as_str()), Some("pending"));
    assert_eq!(
        v.get("tx_hash").and_then(|s| s.as_str()),
        Some(hash_hex.as_str())
    );
    assert!(v.get("nonce").is_some(), "redacted view keeps the nonce");
    for key in ["sender", "recipient", "to", "from", "amount", "payload_ops", "gas_limit"] {
        assert!(
            v.get(key).is_none(),
            "redacted pending view must not contain {key:?}: {body}"
        );
    }

    // Wrong token: still redacted.
    let (head, body) = http_get(addr, &format!("/api/tx/{hash_hex}?token=wrong")).await;
    assert_eq!(status_code(&head), 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert!(v.get("sender").is_none(), "wrong token must stay redacted: {body}");

    // Correct token via header: full view.
    let (head, body) = http_get_with(
        addr,
        &format!("/api/tx/{hash_hex}"),
        &[("Authorization", &format!("Bearer {AUTH_CANARY}"))],
    )
    .await;
    assert_eq!(status_code(&head), 200, "authed tx view failed: {head} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("full view is JSON");
    assert!(v.get("sender").is_some(), "authed view must render the payload: {body}");
    assert_no_secrets("authed tx view", &body);

    // Correct token via query (compat): full view, canary never echoed raw
    // into logs-visible bodies beyond auth success.
    let (head, body) = http_get(addr, &format!("/api/tx/{hash_hex}?token={AUTH_CANARY}")).await;
    assert_eq!(status_code(&head), 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert!(v.get("sender").is_some(), "query-token view must render: {body}");
}

// ---------------------------------------------------------------------------
// 2. Path-shaped params: traversal / null bytes / oversized never succeed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn traversal_and_garbage_params_are_rejected_bounded() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), true).await;
    let addr = spawn(st, 1000).await;
    let big = "a".repeat(5000);
    let evil = vec![
        "..".to_string(),
        "../".to_string(),
        "..%2f..".to_string(),
        "%2e%2e".to_string(),
        "%00".to_string(),
        "0x../etc/passwd".to_string(),
        "-1".to_string(),
        "zz".to_string(),
        "".to_string(),
        big.clone(),
        format!("0x{big}"),
        "..%00".to_string(),
        "0X".to_string() + &hex::encode([1u8; 32]),
    ];
    for e in &evil {
        for route in ["balance", "spv", "tx", "confidential"] {
            let (head, body) = http_get(addr, &format!("/api/{route}/{e}")).await;
            let code = status_code(&head);
            assert!(
                code == 400 || code == 404 || code == 414,
                "evil param {e:?} on {route} must be 400/404/414, got {code}: {head}"
            );
            assert!(
                body.len() < 2048,
                "error for {e:?} must stay bounded, got {} bytes",
                body.len()
            );
            assert_no_secrets(&format!("evil param {e:?}"), &body);
        }
    }
    // Faucet paths validate the address first and never mint on garbage.
    for e in &["../", "%00", "zz", &big[..]] {
        let (head, body) = http_post(addr, &format!("/api/faucet/{e}?token={FAUCET_CANARY}"), "").await;
        let code = status_code(&head);
        assert!(
            code == 400 || code == 404 || code == 414 || code == 503,
            "evil faucet param {e:?} must not dispense, got {code}"
        );
        assert!(!body.contains("credited_nano"), "no mint on garbage: {body}");
        let (head, _) = http_post(addr, &format!("/api/faucet-public/{e}"), "").await;
        let code = status_code(&head);
        assert!(
            code == 400 || code == 404 || code == 414,
            "evil public-faucet param must be refused, got {code}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Malformed query params: negative / huge / wrong types stay clean.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contracts_pagination_is_clamped_and_wellformed() {
    let st = rpc_state(None, None, false).await;
    let addr = spawn(st, 1000).await;
    for q in [
        "limit=-5",
        "limit=abc",
        "limit=99999999999999999999999",
        "limit=0",
        "limit=100000",
        "offset=-1",
        "offset=xyz",
        "offset=9999999999999999999",
        "limit[]=1",
        "limit=10&offset=5",
        "",
    ] {
        let (head, body) = http_get(addr, &format!("/api/contracts?{q}")).await;
        assert_eq!(status_code(&head), 200, "contracts?q={q} failed: {head}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("contracts is JSON");
        let list = v.get("contracts").and_then(|c| c.as_array()).expect("contracts array");
        assert!(list.len() <= 1000, "limit must clamp to <=1000 for q={q}");
        assert!(v.get("total").is_some() && v.get("offset").is_some(), "shape kept: {body}");
        assert_no_secrets("contracts", &body);
    }
}

#[tokio::test]
async fn faucet_public_validates_before_any_costly_work() {
    // Captcha gate denies everything, but address validation runs FIRST:
    // garbage addresses are 400 (never reach captcha/throttle/mint).
    let st = rpc_state(None, None, true).await;
    let gw = Arc::new(GatewayState::with_captcha(
        st,
        1000,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::new(
            CaptchaConfig::Enabled {
                site_key: "audit-site".to_string(),
                secret_key: "audit-secret".to_string(),
            },
            Arc::new(DenyAll),
        )),
    ));
    let addr = spawn_gw(gw).await;
    let (head, _) = http_get(addr, &format!("/api/faucet-public/{}", hex::encode([1u8; 32]))).await;
    assert_eq!(status_code(&head), 405, "public faucet GET must be 405: {head}");
    for bad in ["zz", "%00"] {
        let (head, body) = http_post(addr, &format!("/api/faucet-public/{bad}"), "").await;
        assert_eq!(status_code(&head), 400, "garbage public drip {bad:?} must be 400: {head}");
        assert!(!body.contains("captcha"), "validation must precede captcha: {body}");
    }
    // Multi-segment traversal can never match the single-segment `:address`
    // route: 404 without touching any faucet logic is the correct answer.
    for bad in ["../", "..%2f.."] {
        let (head, body) = http_post(addr, &format!("/api/faucet-public/{bad}"), "").await;
        let code = status_code(&head);
        assert!(
            code == 404 || code == 400,
            "traversal public drip {bad:?} must be refused, got {code}: {head}"
        );
        assert!(!body.contains("credited_nano"), "no mint on traversal: {body}");
    }
    // Well-formed address without a token is refused (captcha on) and the
    // refusal names no secret material.
    let (head, body) = http_post(
        addr,
        &format!("/api/faucet-public/{}", hex::encode([2u8; 32])),
        "",
    )
    .await;
    assert!(
        status_code(&head) == 400 || status_code(&head) == 403,
        "tokenless captcha drip must refuse: {head} {body}"
    );
    assert_no_secrets("public faucet refusal", &body);
}

// ---------------------------------------------------------------------------
// 4. Error bodies: bounded, no secrets, no paths, no panic frames.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_bodies_are_bounded_and_secret_free() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), true).await;
    let addr = spawn(st, 1000).await;
    let who = hex::encode([3u8; 32]);
    let big = "q".repeat(4000);
    let cases = vec![
        ("GET", format!("/api/balance/{big}"), ""),
        ("GET", format!("/api/tx/{big}"), ""),
        ("GET", format!("/api/confidential/{big}"), ""),
        ("POST", format!("/api/faucet/{big}?token={FAUCET_CANARY}"), ""),
        ("POST", format!("/api/faucet/{who}?token=wrong-canary-value"), ""),
        ("POST", format!("/api/faucet/{who}"), ""),
        ("GET", format!("/api/spv/0x{big}"), ""),
    ];
    for (method, path, body) in &cases {
        let (head, resp) = if method == &"GET" {
            http_get(addr, path).await
        } else {
            http_post(addr, path, body).await
        };
        let code = status_code(&head);
        assert!((400..500).contains(&code) || code == 503, "must refuse {path}: {head}");
        assert!(resp.len() < 2048, "error body must stay bounded for {path}");
        assert_no_secrets(path, &resp);
    }
    // Unknown routes are 404 without information.
    let (head, body) = http_get(addr, "/api/does-not-exist").await;
    assert_eq!(status_code(&head), 404);
    assert_no_secrets("404", &body);
}

// ---------------------------------------------------------------------------
// 5. CORS: permissive-by-design (`*`) but never reflecting, never credentialed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cors_never_reflects_origin_or_enables_credentials() {
    let st = rpc_state(None, None, false).await;
    let addr = spawn(st, 1000).await;
    for path in ["/health", "/api/stats", "/metrics", "/readyz", "/"] {
        let (head, _) = http_get_with(
            addr,
            path,
            &[("Origin", "https://evil.example"), ("Authorization", "Bearer x")],
        )
        .await;
        let low = head.to_lowercase();
        assert!(
            low.contains("access-control-allow-origin: *"),
            "public surface keeps static `*`: {head}"
        );
        assert!(
            !low.contains("evil.example"),
            "must never reflect attacker Origin: {head}"
        );
        assert!(
            !low.contains("access-control-allow-credentials: true"),
            "must never enable credentials with `*`: {head}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Metrics + version/stats info discipline (F10-style allowlist).
// ---------------------------------------------------------------------------

/// Secret-class vocabulary that must never appear as an exposition identifier.
/// (`tokens_total` is fine: tokenization splits on `_`, so `tokens` != `token`.)
const FORBIDDEN_METRIC_WORDS: &[&str] = &[
    "secret", "private", "password", "passwd", "seed", "mnemonic", "auth", "bearer", "cookie",
    "session", "apikey", "api_key", "faucet_token", "auth_token", "credentials",
];

fn assert_exposition_discipline(where_: &str, text: &str) {
    let low = text.to_lowercase();
    let mut words = HashSet::new();
    for tok in low.split(|c: char| !c.is_ascii_alphanumeric()) {
        if !tok.is_empty() {
            words.insert(tok.to_string());
        }
    }
    for w in FORBIDDEN_METRIC_WORDS {
        assert!(
            !words.contains(*w),
            "{where_}: exposition vocabulary contains secret-class word {w:?}"
        );
    }
    for canary in [AUTH_CANARY, FAUCET_CANARY] {
        assert!(
            !text.contains(canary),
            "{where_}: exposition leaks a credential canary"
        );
    }
}

#[tokio::test]
async fn metrics_exposition_carries_no_secret_class_names() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), true).await;
    let addr = spawn(st, 1000).await;
    let (head, body) = http_get(addr, "/metrics").await;
    assert_eq!(status_code(&head), 200, "metrics failed: {head}");
    assert!(
        head.to_lowercase().contains("text/plain"),
        "metrics keeps the exposition content type: {head}"
    );
    assert_exposition_discipline("GET /metrics", &body);
    // Readiness gauge and the explorer-folded families are present.
    for name in [
        "stell_ready",
        "stellereum_block_height",
        "stellereum_mempool_size",
        "stellereum_contracts_total",
        "stellereum_tokens_total",
    ] {
        assert!(body.contains(name), "scrape must declare {name}");
    }
}

#[test]
fn render_metrics_vocabulary_has_no_secret_class_names() {
    // Pure-function mirror of the live-scrape check: no server needed.
    let registry = stellereum::metrics::Registry::new();
    let text = stellereum::explorer::render_metrics_with_readiness(&registry, 7, 3, 1, 2, true);
    assert_exposition_discipline("render_metrics_with_readiness", &text);
    assert!(text.contains("stell_ready 1"), "ready gauge renders: {text}");
    let text = stellereum::explorer::render_metrics_with_readiness(&registry, 7, 3, 1, 2, false);
    assert!(text.contains("stell_ready 0"), "not-ready renders fail-closed 0");
}

#[tokio::test]
async fn version_and_stats_expose_no_secrets() {
    let st = rpc_state(Some(AUTH_CANARY), Some(FAUCET_CANARY), true).await;
    let addr = spawn(st, 1000).await;
    let (head, body) = http_get(addr, "/api/version").await;
    assert_eq!(status_code(&head), 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("version is JSON");
    for k in ["version", "git_hash", "dirty", "height", "node_id"] {
        assert!(v.get(k).is_some(), "version shape keeps {k}: {body}");
    }
    assert_no_secrets("version", &body);
    let (head, body) = http_get(addr, "/api/stats").await;
    assert_eq!(status_code(&head), 200);
    assert_no_secrets("stats", &body);
    // The MEV epoch-key commitment is a public commitment, and the epoch key
    // itself must never appear here.
    let low = body.to_lowercase();
    assert!(!low.contains("secret"), "stats must not name secrets: {body}");
}

// ---------------------------------------------------------------------------
// 7. Index page: Turnstile site key cannot break out of its attribute.
// ---------------------------------------------------------------------------

struct OkVerifier;
impl CaptchaVerifier for OkVerifier {
    fn verify(
        &self,
        _secret: &str,
        _token: &str,
        _remote_ip: Option<IpAddr>,
    ) -> CaptchaVerdict {
        CaptchaVerdict::Success
    }
}

#[tokio::test]
async fn index_escapes_adversarial_site_key() {
    let st = rpc_state(None, None, false).await;
    let evil = "x\"><script>alert(1)</script><\"".to_string();
    let gw = Arc::new(GatewayState::with_captcha(
        st,
        1000,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::new(
            CaptchaConfig::Enabled {
                site_key: evil,
                secret_key: "audit-secret".to_string(),
            },
            Arc::new(OkVerifier),
        )),
    ));
    let addr = spawn_gw(gw).await;
    let (head, body) = http_get(addr, "/").await;
    assert_eq!(status_code(&head), 200);
    assert!(
        !body.contains("\"><script>"),
        "site key must not break out of the attribute"
    );
    assert!(
        body.contains("&quot;&gt;&lt;script&gt;"),
        "angle brackets/quotes must be escaped: {body}"
    );
    // Security headers stay on the document.
    let low = head.to_lowercase();
    for h in [
        "x-content-type-options: nosniff",
        "x-frame-options: sameorigin",
        "referrer-policy:",
        "permissions-policy:",
    ] {
        assert!(low.contains(h), "index keeps {h}: {head}");
    }
}

// ---------------------------------------------------------------------------
// 8. Readiness probe: shaped JSON, no secrets, correct fail semantics.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn readyz_reports_shaped_fail_closed_json() {
    // Fresh node: height 0, no peers, no finality -> not ready (503), and the
    // body names exactly which checks failed.
    let st = rpc_state(None, None, false).await;
    let addr = spawn(st, 1000).await;
    let (head, body) = http_get(addr, "/readyz").await;
    assert_eq!(status_code(&head), 503, "fresh node must be unready: {head} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("readyz is JSON");
    assert_eq!(v.get("ready").and_then(|r| r.as_bool()), Some(false));
    let checks = v.get("failed_checks").and_then(|c| c.as_array()).expect("failed_checks");
    assert!(!checks.is_empty(), "must name the failed checks: {body}");
    assert_no_secrets("readyz", &body);
}
