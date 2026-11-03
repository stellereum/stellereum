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
        Arc::new(Self {
            verdict,
            calls: AtomicUsize::new(0),
        })
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
            ed25519_dalek::SigningKey::from_bytes(&faucet_key)
                .verifying_key()
                .to_bytes(),
            10_000_000_000_000,
        ))
        .await;
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:turnstile".to_string(),
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
        faucet: Some(Arc::new(stellereum::rpc::Faucet::new(
            faucet_key,
            1,
            10 * 1_000_000_000,
            100 * 1_000_000_000,
        ))),
        faucet_token: Some("smoke-token".to_string()),
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
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
    assert!(
        status.contains("200"),
        "tokenless drip must work without captcha: {status} {body}"
    );
    assert!(body.contains("pending"), "must mint: {body}");
    // Per-address cooldown: the very next request for the SAME address is 429.
    let (status, _) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(
        status.contains("429"),
        "cooldown must still apply: {status}"
    );
}

// 2. Captcha configured, request without a token → 400 (siteverify not called).
#[tokio::test]
async fn captcha_enabled_missing_token_is_400() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([8u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(
        status.contains("400"),
        "missing token must be 400: {status} {body}"
    );
    assert!(
        body.contains("captcha token required"),
        "body must explain: {body}"
    );
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        0,
        "siteverify must not be called without a token"
    );
}

// 3. Captcha configured, valid token (siteverify → {"success":true}) → 200 mint.
#[tokio::test]
async fn captcha_success_dispenses() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([9u8; 32]);
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        &ok_body("tok-good"),
    )
    .await;
    assert!(
        status.contains("200"),
        "valid token must mint: {status} {body}"
    );
    assert!(body.contains("\"status\":\"pending\""), "must mint: {body}");
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        1,
        "siteverify must be called exactly once"
    );
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
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        &ok_body("tok-bad"),
    )
    .await;
    assert!(
        status.contains("403"),
        "rejected token must be 403: {status} {body}"
    );
    assert!(
        body.contains("invalid-input-response"),
        "error-codes must be surfaced: {body}"
    );
    assert!(
        !body.contains("tok-bad"),
        "the token must never be echoed back: {body}"
    );
}

// 5. siteverify unreachable/timeout → fail-closed 503, NO mint.
#[tokio::test]
async fn siteverify_unavailable_fails_closed() {
    let mock = MockVerifier::new(CaptchaVerdict::Unavailable {
        reason: "mock outage".to_string(),
    });
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([11u8; 32]);
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        &ok_body("tok-x"),
    )
    .await;
    assert!(
        status.contains("503"),
        "outage must fail closed: {status} {body}"
    );
    assert!(!body.contains("pending"), "must not mint on outage: {body}");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    // The recipient got nothing: balance is still zero.
    let (_, bal) = http_get(addr, &format!("/api/balance/{who}")).await;
    assert!(
        bal.contains("\"balance\":\"0\""),
        "no mint on outage: {bal}"
    );
}

// 6. Only the secret key set (misconfigured) → 503, fail-closed.
#[tokio::test]
async fn secret_only_config_is_503() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let gate = Arc::new(CaptchaGate::new(CaptchaConfig::Misconfigured, mock.clone()));
    let addr = spawn_gateway_with(gate).await;
    let who = hex::encode([12u8; 32]);
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        &ok_body("tok-x"),
    )
    .await;
    assert!(
        status.contains("503"),
        "misconfigured gate must refuse: {status} {body}"
    );
    assert!(
        body.contains("misconfigured"),
        "body must name the problem: {body}"
    );
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        0,
        "verifier must not be consulted"
    );
    // Even a tokenless request is refused with the same clarity.
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(
        status.contains("503"),
        "misconfigured gate must refuse everything: {status} {body}"
    );
}

// 7. The per-IP throttle gates the MINT, and the captcha is verified FIRST.
//
//    CHECK ORDER (deliberate, `api_faucet_public`):
//    1. address validation (free) -> 2. captcha -> 3. per-IP throttle ->
//    4. mint.
//
//    The historical name of this test says "before captcha": that order was
//    FLIPPED on purpose. The captcha now runs FIRST so that a captcha-FAILING
//    request on a shared NAT IP cannot exhaust that IP's hourly budget and
//    lock out the honest users behind the same NAT - only a request that
//    passed the captcha may consume the budget.
//
//    What is still pinned here (and what the throttle is FOR): an over-budget
//    request NEVER reaches the mint, even with a valid captcha - it is 429.
//    And a tokenless request is refused by the captcha gate (400) before the
//    throttle is even consulted.
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
        assert!(
            status.contains("200"),
            "drip #{i} within budget must pass: {status} {body}"
        );
    }
    let calls_after_budget = mock.calls.load(Ordering::SeqCst);
    assert_eq!(
        calls_after_budget, 20,
        "every in-budget drip passed the captcha"
    );

    // Over budget WITH a valid token: the captcha is verified first (the
    // order is captcha -> throttle), and the THROTTLE then refuses the mint.
    let who = hex::encode([200u8; 32]);
    let (status, body) =
        http_post(addr, &format!("/api/faucet-public/{who}"), &ok_body("tok")).await;
    assert!(
        status.contains("429"),
        "over-budget request must be 429: {status} {body}"
    );
    assert!(
        mock.calls.load(Ordering::SeqCst) == calls_after_budget + 1,
        "the captcha is verified BEFORE the throttle (one more siteverify call)"
    );

    // A tokenless request is refused by the captcha gate (400) - the local
    // token-presence check runs before the throttle, so no siteverify call is
    // burned on it either.
    let calls_before_tokenless = mock.calls.load(Ordering::SeqCst);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(
        status.contains("400"),
        "tokenless request must be 400: {status} {body}"
    );
    assert!(
        mock.calls.load(Ordering::SeqCst) == calls_before_tokenless,
        "a request without a token must not reach siteverify"
    );

    // And the over-budget recipient still got NOTHING: the throttle gated
    // the mint even though the captcha passed.
    let (_, bal) = http_get(addr, &format!("/api/balance/{who}")).await;
    assert!(
        bal.contains("\"balance\":\"0\""),
        "no mint over budget: {bal}"
    );
}

// 8. Token via header (CF-Turnstile-Response) and via body both work.
#[tokio::test]
async fn token_accepted_from_header_and_body() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    // Body field.
    let who = hex::encode([13u8; 32]);
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        &ok_body("tok-body"),
    )
    .await;
    assert!(
        status.contains("200"),
        "body token must work: {status} {body}"
    );
    // Header.
    let who = hex::encode([14u8; 32]);
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet-public/{who}"),
        "",
        &[("CF-Turnstile-Response", "tok-header")],
    )
    .await;
    assert!(
        status.contains("200"),
        "header token must work: {status} {body}"
    );
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    // Alias body field `turnstile_token` is accepted too.
    let who = hex::encode([15u8; 32]);
    let (status, body) = http_post(
        addr,
        &format!("/api/faucet-public/{who}"),
        r#"{"turnstile_token":"tok-alias"}"#,
    )
    .await;
    assert!(
        status.contains("200"),
        "turnstile_token alias must work: {status} {body}"
    );
}

// 9. Address validation runs BEFORE the captcha: a malformed address is
//    rejected with 400 and siteverify is never burned on it.
//    POLICY (2026-10 address hardening): the gateway namespaces the failure as
//    "invalid address: ..." via `resolve_faucet_recipient` (was the bare
//    "bad address"); the pin is the 400 + zero-siteverify ordering, not the
//    exact prefix.
#[tokio::test]
async fn bad_address_rejected_before_siteverify() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let (status, body) = http_post(addr, "/api/faucet-public/zzzz", &ok_body("tok")).await;
    assert!(
        status.contains("400"),
        "bad address must be 400: {status} {body}"
    );
    assert!(
        body.to_lowercase().contains("address"),
        "must name the problem: {body}"
    );
    assert!(
        body.contains("invalid address"),
        "namespaced address error, got: {body}"
    );
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        0,
        "siteverify must not be burned on garbage"
    );
}

// 10. The index page embeds the Turnstile widget + script only when a site
//     key is configured; without it, no external script is referenced.
#[tokio::test]
async fn index_embeds_widget_only_when_configured() {
    // Captcha off.
    let addr = spawn_gateway_no_captcha().await;
    let (_, body) = http_get(addr, "/").await;
    assert!(
        body.contains("Public faucet"),
        "faucet form must be present: {}",
        &body[..body.len().min(200)]
    );
    assert!(
        !body.contains("challenges.cloudflare.com"),
        "no turnstile script when captcha is off"
    );
    assert!(
        !body.contains("data-sitekey"),
        "no widget when captcha is off"
    );
    assert!(
        !body.contains("TS_REQUIRED=true"),
        "captcha must not be required when off"
    );

    // Captcha on.
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock)).await;
    let (_, body) = http_get(addr, "/").await;
    assert!(
        body.contains("challenges.cloudflare.com/turnstile/v0/api.js"),
        "script must be embedded"
    );
    assert!(
        body.contains("data-sitekey=\"test-site-key\""),
        "widget must carry the site key"
    );
    assert!(
        body.contains("'cf-turnstile-response'"),
        "submit must send the token"
    );
}

// 11. Unconfigured captcha + NON-loopback claim → fail-closed 503 with a
//     clear message, no funds moved, siteverify never consulted. The
//     non-loopback client is simulated over the loopback test socket via
//     X-Forwarded-For (the loopback test peer is trusted by default, so the
//     resolved client IP is the forwarded public IP).
#[tokio::test]
async fn unconfigured_non_loopback_is_503_without_dispense() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let gate = Arc::new(CaptchaGate::new(CaptchaConfig::Disabled, mock.clone()));
    let addr = spawn_gateway_with(gate).await;
    let public_ip = "203.0.113.7";
    // Tokenless claim from the public internet.
    let who = hex::encode([21u8; 32]);
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet-public/{who}"),
        "",
        &[("X-Forwarded-For", public_ip)],
    )
    .await;
    assert!(
        status.contains("503"),
        "unconfigured captcha + public claim must be 503: {status} {body}"
    );
    assert!(
        body.contains("not configured"),
        "body must say captcha is not configured: {body}"
    );
    assert!(
        !body.contains("pending"),
        "must not mint on refusal: {body}"
    );
    // Even WITH a (bogus) token the unconfigured gate refuses before verify.
    let who2 = hex::encode([22u8; 32]);
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet-public/{who2}"),
        &ok_body("tok-any"),
        &[("X-Forwarded-For", public_ip)],
    )
    .await;
    assert!(
        status.contains("503"),
        "token does not bypass missing captcha config: {status} {body}"
    );
    assert!(
        body.contains("not configured"),
        "body must say captcha is not configured: {body}"
    );
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        0,
        "no verifier call when captcha is unconfigured"
    );
    // No funds moved: both refused recipients still hold exactly zero.
    for w in [who, who2] {
        let (_, bal) = http_get(addr, &format!("/api/balance/{w}")).await;
        assert!(
            bal.contains("\"balance\":\"0\""),
            "refused claim must dispense nothing, got: {bal}"
        );
    }
}

// 12. Unconfigured captcha + loopback claim → legacy local/dev path still
//     works (this is the allowed path the pre-existing test 1 exercises;
//     pinned here explicitly with an XFF loopback client too).
#[tokio::test]
async fn unconfigured_loopback_still_dispenses() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let gate = Arc::new(CaptchaGate::new(CaptchaConfig::Disabled, mock.clone()));
    let addr = spawn_gateway_with(gate).await;
    // Plain loopback (no forwarding headers).
    let who = hex::encode([23u8; 32]);
    let (status, body) = http_post(addr, &format!("/api/faucet-public/{who}"), "").await;
    assert!(
        status.contains("200"),
        "loopback claim without captcha must still work: {status} {body}"
    );
    assert!(body.contains("pending"), "must mint on loopback: {body}");
    // Explicit loopback via X-Forwarded-For from the trusted test peer.
    let who2 = hex::encode([24u8; 32]);
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet-public/{who2}"),
        "",
        &[("X-Forwarded-For", "127.0.0.1")],
    )
    .await;
    assert!(
        status.contains("200"),
        "XFF-loopback claim without captcha must still work: {status} {body}"
    );
    assert!(body.contains("pending"), "must mint on loopback: {body}");
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        0,
        "no verifier call on the unconfigured loopback path"
    );
}

// 13. Configured captcha + NON-loopback claim with a valid token → 200 mint
//     (the public operator path: captcha verified, then dispense).
#[tokio::test]
async fn configured_non_loopback_success_dispenses() {
    let mock = MockVerifier::new(CaptchaVerdict::Success);
    let addr = spawn_gateway_with(enabled_gate(mock.clone())).await;
    let who = hex::encode([25u8; 32]);
    let (status, body) = http_post_with(
        addr,
        &format!("/api/faucet-public/{who}"),
        &ok_body("tok-public"),
        &[("X-Forwarded-For", "198.51.100.9")],
    )
    .await;
    assert!(
        status.contains("200"),
        "valid public claim must mint: {status} {body}"
    );
    assert!(body.contains("\"status\":\"pending\""), "must mint: {body}");
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        1,
        "siteverify must be called exactly once for a public claim"
    );
}
