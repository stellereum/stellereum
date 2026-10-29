//! Public-faucet captcha tests (`POST /api/faucet-public/:address`).
//!
//! The Turnstile verifier is injected as a mock (see `CaptchaVerifier`), so
//! no test ever reaches Cloudflare. Env vars are NOT used to configure the
//! gate here — `GatewayState::with_captcha` injects it explicitly, keeping
//! the tests deterministic under parallel execution.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use stellereum::explorer::{self, GatewayState, ReadinessConfig};
use stellereum::rpc::RpcState;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::turnstile::{CaptchaConfig, CaptchaGate, CaptchaVerdict, CaptchaVerifier};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Canned verdict + call counter, so tests can assert both the HTTP outcome
/// AND whether siteverify was (not) reached.
struct MockVerifier {
    verdict: CaptchaVerdict,
    calls: AtomicUsize,
}

impl MockVerifier {
    fn new(verdict: CaptchaVerdict) -> Arc<Self> {
        Arc::new(Self { verdict, calls: AtomicUsize::new(0) })
    }
}

impl CaptchaVerifier for MockVerifier {
    fn verify(&self, _secret: &str, _token: &str, _remote_ip: Option<IpAddr>) -> CaptchaVerdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.verdict.clone()
    }
}

fn enabled_gate(verifier: Arc<MockVerifier>) -> Arc<CaptchaGate> {
    Arc::new(CaptchaGate::new(
        CaptchaConfig::Enabled {
            site_key: "test-site-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        },
        verifier,
    ))
}

async fn state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let who = [3u8; 32];
    engine.update_account(AccountState::new(who, 12_345)).await;
    let faucet_key = [0x11u8; 32];
    engine
        .update_account(AccountState::new(
            ed25519_dalek::SigningKey::from_bytes(&faucet_key).verifying_key().to_bytes(),
            10_000_000_000_000,
        ))
        .await;
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(stellereum::mempool::Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:turnstile".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(tokio::sync::RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(stellereum::rpc::ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: Some(Arc::new(stellereum::rpc::Faucet::new(
            faucet_key,
            1,
            10 * 1_000_000_000,
            100 * 1_000_000_000,
        ))),
        faucet_token: Some("smoke-token".to_string()),
    })
}

async fn spawn_gateway_with(captcha: Arc<CaptchaGate>) -> std::net::SocketAddr {
    let st = state().await;
    let gw = Arc::new(GatewayState::with_captcha(
        st,
        1000,
        ReadinessConfig::default(),
        captcha,
    ));
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

async fn spawn_gateway_no_captcha() -> std::net::SocketAddr {
    spawn_gateway_with(Arc::new(CaptchaGate::disabled())).await
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
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, String) {
    http_post_with(addr, path, body, &[]).await
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

fn ok_body(token: &str) -> String {
    format!(r#"{{"cf-turnstile-response":"{token}"}}"#)
}

// 1. No captcha configured → legacy behaviour: no token required, drip works,
//    and the per-IP throttle still bounds the faucet.
#[tokio::test]
async fn no_captcha_config_requires_no_token_and_keeps_throttle() {
    let addr = spawn_gateway_no_captcha().await;
    let who = hex::encode([7u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(status.contains("200"), "tokenless drip must work without captcha: {status} {body}");
    assert!(body.contains("pending"), "must mint: {body}");
    // Per-address cooldown: the very next request for the SAME address is 429.
    let (status, _) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(status.contains("429"), "cooldown must still apply: {status}");
}

// 2. Captcha configured, request without a token → 400 (siteverify not called).
#[tokio::test]
async fn captcha_enabled_missing_token_is_400() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([8u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(status.contains("400"), "missing token must be 400: {status} {body}");
    assert!(body.contains("captcha token required"), "body must explain: {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 0, "siteverify must not be called without a token");
}

// 3. Captcha configured, valid token (siteverify → {"success":true}) → 200 mint.
#[tokio::test]
async fn captcha_success_dispenses() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([9u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok-good")).await;
    assert!(status.contains("200"), "valid token must mint: {status} {body}");
    assert!(body.contains("\"status\":\"pending\""), "must mint: {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1, "siteverify must be called exactly once");
}

// 4. siteverify {"success":false,"error-codes":["invalid-input-response"]}
//    → 403 with the codes surfaced, no mint.
#[tokio::test]
async fn captcha_rejected_is_403_with_error_codes() {
    let mock = MockVerifier::new(CaptchaVerdict::Rejected {
        error_codes: vec!["invalid-input-response".to_string()],
    });
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([10u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok-bad")).await;
    assert!(status.contains("403"), "rejected token must be 403: {status} {body}");
    assert!(body.contains("invalid-input-response"), "error-codes must be surfaced: {body}");
    assert!(!body.contains("tok-bad"), "the token must never be echoed back: {body}");
}

// 5. siteverify unreachable/timeout → fail-closed 503, NO mint.
#[tokio::test]
async fn siteverify_unavailable_fails_closed() {
    let mock = MockVerifier::new(CaptchaVerdict::Unavailable {
        reason: "mock outage".to_string(),
    });
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([11u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok-x")).await;
    assert!(status.contains("503"), "outage must fail closed: {status} {body}");
    assert!(!body.contains("pending"), "must not mint on outage: {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    // The recipient got nothing: balance is still zero.
    let (_, bal) = http_get(addr, &format!("/api/balance/{who}")).await;
    assert!(bal.contains("\"balance\":\"0\""), "no mint on outage: {bal}");
}

// 6. Only the secret key set (misconfigured) → 503, fail-closed.
#[tokio::test]
async fn secret_only_config_is_503() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let gate = Arc::new(CaptchaGate::new(CaptchaConfig::Misconfigured, mock.clone()));
    let addr = spawn_gateway_with(gate).await;
    let who = hex::encode([12u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok-x")).await;
    assert!(status.contains("503"), "misconfigured gate must refuse: {status} {body}");
    assert!(body.contains("misconfigured"), "body must name the problem: {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 0, "verifier must not be consulted");
    // Even a tokenless request is refused with the same clarity.
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(status.contains("503"), "misconfigured gate must refuse everything: {status} {body}");
}

// 7. IP throttle fires BEFORE the captcha: once the per-IP budget is spent,
//    further requests are 429 even with a valid token — and a request without
//    any token is also 429 (not 400), proving the throttle check ran first.
#[tokio::test]
async fn ip_throttle_enforced_before_captcha() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    // Default budget is FAUCET_IP_MAX_PER_HOUR (20). Spend it with valid
    // tokens on distinct addresses (the per-address cooldown is separate).
    for i in 0..20u8 {
        let who = hex::encode([100u8.wrapping_add(i); 32]);
        let (status, body) =
            http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok")).await;
        assert!(status.contains("200"), "drip #{i} within budget must pass: {status} {body}");
    }
    let calls_after_budget = mock.calls.load(Ordering::SeqCst);
    // Over budget: a request WITHOUT a token gets 429, not 400 — the throttle
    // (which runs first) already rejected it, so the captcha was never asked.
    let who = hex::encode([200u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(status.contains("429"), "over-budget request must be 429: {status} {body}");
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        calls_after_budget,
        "siteverify must not be reached once the IP budget is spent"
    );
    // Over budget with a VALID token is also 429: the throttle gates the mint.
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok")).await;
    assert!(status.contains("429"), "over-budget request with token must be 429: {status} {body}");
}

// 8. Token via header (CF-Turnstile-Response) and via body both work.
#[tokio::test]
async fn token_accepted_from_header_and_body() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    // Body field.
    let who = hex::encode([13u8; 32]);
    let (status, body) =
        http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok-body")).await;
    assert!(status.contains("200"), "body token must work: {status} {body}");
    // Header.
    let who = hex::encode([14u8; 32]);
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet-public/{who}"),
        "",
        &[("CF-Turnstile-Response", "tok-header")],
    )
    .await;
    assert!(status.contains("200"), "header token must work: {status} {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    // Alias body field `turnstile_token` is accepted too.
    let who = hex::encode([15u8; 32]);
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        r#"{"turnstile_token":"tok-alias"}"#,
    )
    .await;
    assert!(status.contains("200"), "turnstile_token alias must work: {status} {body}");
}

// 9. Address validation runs BEFORE the captcha: a malformed address is
//    rejected with "bad address" and siteverify is never burned on it.
#[tokio::test]
async fn bad_address_rejected_before_siteverify() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let (status, body) = http_post(addr, "/api/faucet-public/zzzz", &ok_body("tok")).await;
    assert!(status.contains("400"), "bad address must be 400: {status} {body}");
    assert!(body.contains("bad address"), "must name the problem: {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 0, "siteverify must not be burned on garbage");
}

// 10. The index page embeds the Turnstile widget + script only when a site
//     key is configured; without it, no external script is referenced.
#[tokio::test]
async fn index_embeds_widget_only_when_configured() {
    // Captcha off.
    let addr = spawn_gateway_no_captcha().await;
    let (_, body) = http_get(addr, "/").await;
    assert!(body.contains("Public faucet"), "faucet form must be present: {}", &body[..body.len().min(200)]);
    assert!(
        !body.contains("challenges.cloudflare.com"),
        "no turnstile script when captcha is off"
    );
    assert!(!body.contains("data-sitekey"), "no widget when captcha is off");
    assert!(!body.contains("TS_REQUIRED=true"), "captcha must not be required when off");

    // Captcha on.
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock)).await;
    let (_, body) = http_get(addr, "/").await;
    assert!(body.contains("challenges.cloudflare.com/turnstile/v0/api.js"), "script must be embedded");
    assert!(body.contains("data-sitekey=\"test-site-key\""), "widget must carry the site key");
    assert!(body.contains("'cf-turnstile-response'"), "submit must send the token");
}
