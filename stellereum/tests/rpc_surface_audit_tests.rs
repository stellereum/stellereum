//! RPC-surface security audit tests (`src/rpc.rs` + `src/explorer.rs` behavior).
//!
//! Attack-oriented coverage for the JSON-RPC surface (incl. `eth_*` compat),
//! the faucet (token + public paths) and the auth/token model:
//!
//! * unauthenticated admin-method calls are refused (fail-closed where the
//!   design says fail-closed);
//! * faucet lifetime caps hold over many claims, including a multi-address
//!   sybil rotation against one IP;
//! * malformed inputs (oversized / negative / garbage) yield clean bounded
//!   errors, never panics;
//! * error strings carry no secret material (tokens, seeds, key paths);
//! * the per-IP rate limiters isolate buckets per IP and reset per window.
//!
//! All tests are self-contained: each builds its own `RpcState` (hence its
//! own faucet/throttle state), so they are safe under parallel execution.
//! Nothing here touches live nodes, configs, or the network.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;

use stellereum::explorer::RateLimiter;
use stellereum::mempool::Mempool;
use stellereum::rpc::{faucet_ip_max_per_hour, hub, Faucet, ReceiptIndex, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const AUTH_TOKEN: &str = "audit-auth-token-xyz-123";
const FAUCET_TOKEN: &str = "audit-faucet-token-xyz-456";
const FAUCET_SEED: [u8; 32] = [0x33u8; 32];

fn faucet_addr() -> [u8; 32] {
    // FULL-PQ: the faucet account is the Falcon-512 address derived from the
    // seed (Faucet::account); fund that address, never a classical one.
    let pq_key =
        stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&FAUCET_SEED);
    stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        &pq_key.public_key,
        &stellereum::post_quantum::DEFAULT_SALT,
    )
}

/// Base state: no tokens, no faucet (local/dev shape).
async fn base_state(auth_token: Option<&str>, seed: Option<[u8; 32]>) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "audit:test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: auth_token.map(|s| s.to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: seed,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

/// State with an enabled, funded token faucet (`drip`/`cap` in nano-STELL).
async fn faucet_state(drip: u64, cap: u64, faucet_balance: u64) -> Arc<RpcState> {
    let base = base_state(None, None).await;
    base.engine
        .update_account(AccountState::new(faucet_addr(), faucet_balance))
        .await;
    Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: base.auth_token.clone(),
        tx_broadcast: base.tx_broadcast.clone(),
        faucet: Some(Arc::new(Faucet::new(FAUCET_SEED, 1, drip, cap))),
        faucet_token: Some(FAUCET_TOKEN.to_string()),
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

fn drip_req(address: &str) -> Value {
    json!({ "address": address, "token": FAUCET_TOKEN })
}

fn err_of(v: &Value) -> Option<String> {
    v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// 1. Auth model: unauthenticated admin-method calls must refuse.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_methods_refuse_unauthenticated_when_token_configured() {
    let st = base_state(Some(AUTH_TOKEN), Some([0x42u8; 32])).await;
    let addr_hex = hex::encode([0xABu8; 32]);
    // (method, params): every one of these mutates node state or signs with
    // the node key, so each must demand the token.
    let cases: Vec<(&str, Value)> = vec![
        ("stell_submitProposal", json!({"title": "t", "type": "signal"})),
        ("stell_vote", json!({"id": 0, "voter": addr_hex})),
        ("stell_executeProposal", json!({"id": 0})),
        ("stell_mempoolDump", json!({})),
        ("stell_signMessage", json!({"message": "hi"})),
        (
            "stell_signTypedData",
            json!({"contract": addr_hex, "method": "ping"}),
        ),
        ("stell_deployContract", json!({"code": "0x00"})),
        (
            "stell_callContract",
            json!({"contract": addr_hex, "method": "m"}),
        ),
        // The gate runs before any payload parsing: garbage params must
        // still report unauthorized, not a parse error.
        ("stell_submitPriceFeed", json!({"junk": 1})),
        ("stell_pmmBuy", json!({"junk": 1})),
        ("stell_pmmSell", json!({"junk": 1})),
    ];
    for (method, params) in &cases {
        let r = st.call(method, params.clone()).await;
        let e = err_of(&r).unwrap_or_default();
        assert!(
            e.contains("unauthorized"),
            "{method} must refuse an unauthenticated caller, got: {r}"
        );
    }
    // Wrong token is the same as no token.
    let r = st
        .call("stell_mempoolDump", json!({"token": "guess"}))
        .await;
    assert!(
        err_of(&r).unwrap_or_default().contains("unauthorized"),
        "a wrong token must be refused: {r}"
    );
    // None of the refusals may have mutated anything.
    assert_eq!(st.mempool.read().await.len(), 0);
}

#[tokio::test]
async fn admin_methods_accept_the_configured_token() {
    let st = base_state(Some(AUTH_TOKEN), Some([0x42u8; 32])).await;
    // mempoolDump with the token returns the (empty) pool listing.
    let r = st
        .call("stell_mempoolDump", json!({"token": AUTH_TOKEN}))
        .await;
    assert!(err_of(&r).is_none(), "tokened mempoolDump must work: {r}");
    assert_eq!(r, json!([]));
    // submitProposal with the token passes the gate and fails on params.
    let r = st
        .call("stell_submitProposal", json!({"token": AUTH_TOKEN}))
        .await;
    assert!(
        err_of(&r).unwrap_or_default().contains("missing proposal title"),
        "gate must pass with the token: {r}"
    );
    // signMessage with the token signs.
    let r = st
        .call(
            "stell_signMessage",
            json!({"message": "hi", "token": AUTH_TOKEN}),
        )
        .await;
    assert!(
        r.get("signature").and_then(|s| s.as_str()).is_some(),
        "tokened sign must succeed: {r}"
    );
}

#[tokio::test]
async fn mempool_dump_fails_closed_without_token() {
    let st = base_state(None, None).await;
    let r = st.call("stell_mempoolDump", json!({})).await;
    let e = err_of(&r).unwrap_or_default();
    assert!(
        e.contains("disabled when auth_token is not configured"),
        "mempoolDump must fail closed with no token configured: {r}"
    );
}

#[tokio::test]
async fn faucet_refuses_without_token_and_fails_closed_without_config() {
    let st = faucet_state(10, 25, 1_000_000).await;
    let who = hex::encode([0x42u8; 32]);
    // No token.
    let r = st.call("stell_faucet", json!({"address": who})).await;
    assert!(
        err_of(&r).unwrap_or_default().contains("faucet token"),
        "tokenless faucet request must be refused: {r}"
    );
    // Wrong token.
    let r = st
        .call(
            "stell_faucet",
            json!({"address": who, "token": "guess"}),
        )
        .await;
    assert!(
        err_of(&r).unwrap_or_default().contains("faucet token"),
        "wrong faucet token must be refused: {r}"
    );
    assert_eq!(st.mempool.read().await.len(), 0);
    // Enabled faucet with no token configured refuses to dispense at all.
    let base = base_state(None, None).await;
    base.engine
        .update_account(AccountState::new(faucet_addr(), 1_000_000))
        .await;
    let untokened = Arc::new(RpcState {
        faucet: Some(Arc::new(Faucet::new(FAUCET_SEED, 1, 10, 25))),
        faucet_token: None,
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: None,
        tx_broadcast: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    let r = untokened.call("stell_faucet", drip_req(&who)).await;
    assert!(
        err_of(&r).unwrap_or_default().contains("refusing to dispense"),
        "unconfigured faucet token must fail closed: {r}"
    );
    assert_eq!(untokened.mempool.read().await.len(), 0);
}

// ---------------------------------------------------------------------------
// 2. Faucet: lifetime caps over many claims + sybil + drain behavior.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn faucet_lifetime_caps_hold_over_many_claims() {
    // Drip 10, lifetime cap 25: 10 + 10 + 5, then exhausted.
    // FULL-PQ funding: each drip costs amount + GAS_BASIC_TRANSFER + the
    // PQ activation surcharge legs, so the treasury needs headroom.
    let st = faucet_state(10, 25, 10_000_000).await;
    let who = [0x42u8; 32];
    let who_hex = hex::encode(who);
    let r1 = st.call("stell_faucet", drip_req(&who_hex)).await;
    assert_eq!(r1["credited_nano"], json!("10"), "drip 1: {r1}");
    let r2 = st.call("stell_faucet", drip_req(&who_hex)).await;
    assert_eq!(r2["credited_nano"], json!("10"), "drip 2: {r2}");
    let r3 = st.call("stell_faucet", drip_req(&who_hex)).await;
    assert_eq!(
        r3["credited_nano"],
        json!("5"),
        "drip 3 is clamped to the remainder: {r3}"
    );
    let r4 = st.call("stell_faucet", drip_req(&who_hex)).await;
    assert!(
        err_of(&r4)
            .unwrap_or_default()
            .contains("faucet limit reached"),
        "drip 4 must hit the lifetime cap: {r4}"
    );
    let faucet = st.faucet.clone().expect("faucet enabled");
    assert_eq!(faucet.dispensed_to(who).await, 25);
    // Exactly three transfers queued with consecutive nonces.
    let pool = st.mempool.read().await;
    assert_eq!(pool.len(), 3);
    let mut nonces: Vec<u64> = pool.all().iter().map(|t| t.nonce).collect();
    nonces.sort_unstable();
    assert_eq!(nonces, vec![0, 1, 2]);
}

#[tokio::test]
async fn faucet_sybil_rotation_is_bounded_by_the_per_ip_throttle() {
    // One drip per address (drip == cap), so lifetime caps never bind: the
    // only thing stopping a 30-address rotation is the per-IP hourly budget.
    let st = faucet_state(10, 10, 1_000_000_000).await;
    let ip_max = faucet_ip_max_per_hour() as usize;
    let total = ip_max + 10;
    let mut granted = 0usize;
    for i in 0..total {
        let mut addr = [0u8; 32];
        addr[0] = (i / 256) as u8;
        addr[1] = (i % 256) as u8;
        addr[2] = 0x99;
        let r = st.call("stell_faucet", drip_req(&hex::encode(addr))).await;
        if err_of(&r).is_some() {
            let e = err_of(&r).unwrap_or_default();
            assert!(
                e.contains("per-IP faucet budget exhausted"),
                "sybil drip {i} must fail on the throttle, got: {r}"
            );
        } else {
            granted += 1;
        }
    }
    assert_eq!(
        granted, ip_max,
        "exactly one hourly budget may dispense, then the throttle bites"
    );
    assert_eq!(st.mempool.read().await.len(), granted);
}

#[tokio::test]
async fn faucet_drain_exhaustion_fails_cleanly_and_rolls_back() {
    // Treasury holds 5 nano; the drip is 10. Admission must fail and the
    // reservation (lifetime credit + nonce) must be rewound.
    let st = faucet_state(10, 1_000_000, 5).await;
    let who = [0x42u8; 32];
    let who_hex = hex::encode(who);
    let r = st.call("stell_faucet", drip_req(&who_hex)).await;
    let e = err_of(&r).unwrap_or_default();
    assert!(
        e.contains("rejected"),
        "an unfunded drip must be rejected cleanly: {r}"
    );
    assert_eq!(st.mempool.read().await.len(), 0);
    let faucet = st.faucet.clone().expect("faucet enabled");
    assert_eq!(
        faucet.dispensed_to(who).await,
        0,
        "failed drip must refund the lifetime credit"
    );
    // After funding, the next drip takes nonce 0: no gap was burned.
    st.engine
        .update_account(AccountState::new(faucet_addr(), 1_000_000))
        .await;
    let r = st.call("stell_faucet", drip_req(&who_hex)).await;
    assert_eq!(r["credited_nano"], json!("10"), "funded drip: {r}");
    let pool = st.mempool.read().await;
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.all()[0].nonce, 0, "rollback must rewind the nonce");
}

#[tokio::test]
async fn faucet_zero_amount_is_refused_without_state_touch() {
    let st = faucet_state(10, 1_000, 1_000_000).await;
    let who = hex::encode([0x42u8; 32]);
    let r = st
        .call(
            "stell_faucet",
            json!({"address": who, "token": FAUCET_TOKEN, "amount": 0}),
        )
        .await;
    assert!(
        err_of(&r).unwrap_or_default().contains("invalid amount"),
        "a zero drip must be refused: {r}"
    );
    assert_eq!(st.mempool.read().await.len(), 0);
    let faucet = st.faucet.clone().expect("faucet enabled");
    assert_eq!(faucet.dispensed_to([0x42u8; 32]).await, 0);
}

// ---------------------------------------------------------------------------
// 3. Malformed inputs: clean bounded errors, no panics.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_inputs_get_clean_errors() {
    let st = faucet_state(10, 1_000_000, 1_000_000).await;
    let big_hex = format!("0x{}", "ab".repeat(5_000));
    let cases: Vec<(&str, Value)> = vec![
        ("stell_getBalance", json!("zz")),
        ("stell_getBalance", json!({})),
        ("stell_getBalance", json!(big_hex.clone())),
        ("stell_getBalance", json!(12345)),
        ("stell_getProof", json!({"address": hex::encode([1u8; 32]), "storage_keys": vec!["x"; 33]})),
        (
            "stell_getProof",
            json!({"address": hex::encode([1u8; 32]), "storage_keys": [42]}),
        ),
        ("stell_sendRawTransaction", json!({"tx": "not-hex!!"})),
        ("stell_sendRawTransaction", json!({"tx": "0x00"})),
        ("stell_sendRawTransaction", json!({})),
        ("stell_estimateFee", json!({"max_gas": -1})),
        ("stell_estimateFee", json!({"max_gas": "garbage"})),
        ("stell_estimateFee", json!({})),
        ("stell_subscribe", json!(["notAThing"])),
        ("stell_subscribe", json!([])),
        ("stell_unsubscribe", json!([])),
        ("stell_getEvents", json!({})),
        ("stell_nopeNotReal", json!({})),
        (
            "stell_deployContract",
            json!({"code": "0xzz", "private_key": hex::encode([9u8; 32])}),
        ),
    ];
    for (method, params) in &cases {
        let r = st.call(method, params.clone()).await;
        assert!(
            err_of(&r).is_some(),
            "{method} must report a clean error, got: {r}"
        );
    }
    // Oversized raw tx: 600 KB of zeros decodes as hex but is over the body
    // cap, so it is refused as too large rather than deserialized.
    let huge = format!("0x{}", "00".repeat(600_000));
    let r = st.call("stell_sendRawTransaction", json!({"tx": huge})).await;
    assert!(
        err_of(&r).is_some(),
        "oversized tx must be refused, got result"
    );
    // runGetMethod reports param problems inside the result envelope.
    let r = st
        .call("stell_runGetMethod", json!({"address": "0x", "method": "m"}))
        .await;
    assert!(
        r.get("success") == Some(&json!(false)),
        "runGetMethod must fail soft, got: {r}"
    );
}

#[tokio::test]
async fn oversized_reflections_are_bounded() {
    let st = base_state(None, None).await;
    let huge = "x".repeat(5_000);
    // Unknown method echoes the name; a 5 KB name must not come back whole.
    let r = st.call(&format!("stell_{huge}"), json!({})).await;
    let e = err_of(&r).unwrap_or_default();
    assert!(e.contains("method not found"), "got: {e}");
    assert!(e.len() < 1_000, "method reflection must be bounded: {}", e.len());
    // Unknown subscription type, same rule.
    let r = st.call("stell_subscribe", json!([huge.clone()])).await;
    let e = err_of(&r).unwrap_or_default();
    assert!(e.contains("unknown subscription type"), "got: {e}");
    assert!(e.len() < 1_000, "subscribe reflection must be bounded: {}", e.len());
    // runGetMethod arg parsing echoes the offending string, truncated.
    let r = st
        .call(
            "stell_runGetMethod",
            json!({"address": hex::encode([5u8; 32]), "method": "m", "args": huge}),
        )
        .await;
    let body = r.to_string();
    assert!(
        body.len() < 2_000,
        "getter-arg reflection must be bounded: {}",
        body.len()
    );
    // Address parsing truncates the echo as well.
    let r = st
        .call(
            "stell_callContract",
            json!({"contract": huge, "method": "m"}),
        )
        .await;
    let e = err_of(&r).unwrap_or_default();
    assert!(e.contains("invalid contract address"), "got: {e}");
    assert!(e.len() < 1_000, "address reflection must be bounded: {}", e.len());
}

#[tokio::test]
async fn subscription_topics_are_capped() {
    let st = base_state(None, None).await;
    let contract = hex::encode([0x7Au8; 32]);
    // 33 topics (array form) is refused fail-closed.
    let many: Vec<Value> = (0..33).map(|i| json!(format!("t{i}"))).collect();
    let r = st
        .call(
            "stell_subscribe",
            json!(["events", {"contract": contract, "topics": many}]),
        )
        .await;
    assert!(
        err_of(&r).unwrap_or_default().contains("too many topics"),
        "over-cap topics must be refused: {r}"
    );
    // 33 topics (comma-string form) is refused too.
    let csv = (0..33).map(|i| format!("t{i}")).collect::<Vec<_>>().join(",");
    let r = st
        .call(
            "stell_subscribe",
            json!(["events", {"contract": contract, "topics": csv}]),
        )
        .await;
    assert!(
        err_of(&r).unwrap_or_default().contains("too many topics"),
        "over-cap csv topics must be refused: {r}"
    );
    // 32 topics still works, so the cap is a bound, not a freeze.
    let ok_many: Vec<Value> = (0..32).map(|i| json!(format!("t{i}"))).collect();
    let r = st
        .call(
            "stell_subscribe",
            json!(["events", {"contract": contract, "topics": ok_many}]),
        )
        .await;
    let sub_id = r.as_str().expect("32 topics must subscribe").to_string();
    assert_eq!(sub_id.len(), 32, "subscription id shape: {r}");
    assert!(hub().unsubscribe(&sub_id), "cleanup must remove the sub");
}

#[tokio::test]
async fn get_subscriptions_redacts_client_attribution() {
    use stellereum::rpc::SubscriptionTopic;
    // An attributed subscription (owned by 9.9.9.9 for the per-client
    // budget) must not leak its owner through the public listing — and the
    // bearer ids it lists must not carry attribution either.
    let id = hub()
        .subscribe_for(SubscriptionTopic::NewHeads, Some("9.9.9.9"))
        .expect("subscribe");
    let st = base_state(None, None).await;
    let r = st.call("stell_getSubscriptions", json!({})).await;
    let body = r.to_string();
    assert!(
        !body.contains("9.9.9.9"),
        "client IPs must not be enumerable: {body}"
    );
    assert!(
        !body.contains("\"client\""),
        "owner field must not be served: {body}"
    );
    let mine = r
        .as_array()
        .expect("listing is an array")
        .iter()
        .find(|e| e["id"] == json!(id))
        .expect("own subscription is listed");
    assert_eq!(mine["attached"], json!(false));
    assert!(hub().unsubscribe(&id), "cleanup must remove the sub");
}

// ---------------------------------------------------------------------------
// 4. Error-message secret scan.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_messages_carry_no_secret_material() {
    let st = faucet_state(10, 1_000, 1_000_000).await;
    let authed = base_state(Some(AUTH_TOKEN), Some([0x42u8; 32])).await;
    let seed_hex = hex::encode(FAUCET_SEED);
    let priv_hex = hex::encode([0x77u8; 32]);
    let probes: Vec<Value> = vec![
        st.call("stell_faucet", json!({"address": hex::encode([1u8; 32])})).await,
        st.call(
            "stell_faucet",
            json!({"address": hex::encode([1u8; 32]), "token": "wrong"}),
        )
        .await,
        st.call("stell_faucet", json!({"address": "zz", "token": FAUCET_TOKEN})).await,
        st.call(
            "stell_faucet",
            json!({"address": "0xzzzz", "token": FAUCET_TOKEN}),
        )
        .await,
        authed.call("stell_mempoolDump", json!({"token": "guess"})).await,
        authed.call("stell_deployContract", json!({"code": "0x00"})).await,
        authed
            .call(
                "stell_deployContract",
                json!({"code": "0x00", "private_key": priv_hex}),
            )
            .await,
        st.call("stell_getBalance", json!("0xab")).await,
        st.call("stell_sendRawTransaction", json!({"tx": "zz"})).await,
        st.call("stell_nopeMissing", json!({"token": AUTH_TOKEN})).await,
        st.call("stell_subscribe", json!(["bogus"])).await,
    ];
    let forbidden = [
        AUTH_TOKEN,
        FAUCET_TOKEN,
        seed_hex.as_str(),
        priv_hex.as_str(),
        "STELL_FAUCET_KEY",
        "STELL_RPC_AUTH_TOKEN",
        "BEGIN PRIVATE",
        ".pem",
        "/keys/",
    ];
    for v in &probes {
        let e = err_of(v).unwrap_or_default();
        assert!(!e.is_empty(), "probe must error, got: {v}");
        for secret in &forbidden {
            assert!(
                !e.contains(secret),
                "error leaks secret material {secret:?}: {e}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Rate-limit behavior.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gateway_rate_limiter_is_per_ip_and_windowed() {
    let rl = RateLimiter::new(2);
    let a: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let b: std::net::IpAddr = "5.6.7.8".parse().unwrap();
    let t = 1_700_000_000u64;
    assert!(rl.check_at(a, t));
    assert!(rl.check_at(a, t));
    assert!(!rl.check_at(a, t), "third hit in one window must refuse");
    // A different IP has its own bucket.
    assert!(rl.check_at(b, t));
    // The next window resets the budget.
    assert!(rl.check_at(a, t + 1));
}

#[tokio::test]
async fn faucet_ip_throttle_is_per_ip_and_hour_scoped() {
    let faucet = Faucet::new([0x55u8; 32], 0, 10, 1_000);
    let ip_max = faucet_ip_max_per_hour();
    let a: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let b: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let t = 1_700_000_000u64;
    for _ in 0..ip_max {
        assert!(faucet.check_ip_throttle(Some(a), t).await);
    }
    assert!(
        !faucet.check_ip_throttle(Some(a), t).await,
        "hourly budget must exhaust"
    );
    // Another IP is unaffected.
    assert!(faucet.check_ip_throttle(Some(b), t).await);
    // The next UTC hour resets the budget.
    assert!(faucet.check_ip_throttle(Some(a), t + 3_600).await);
    // Unattributed callers share one fallback bucket instead of bypassing.
    for _ in 0..ip_max {
        assert!(faucet.check_ip_throttle(None, t).await);
    }
    assert!(
        !faucet.check_ip_throttle(None, t).await,
        "fallback bucket must exhaust too"
    );
}

// ---------------------------------------------------------------------------
// 6. Micro-hardening: WS per-message expensive-read budget + `peer_ip=None`
//    attribution (RPC-surface audit residuals).
//
// (a) The HTTP upgrade passes the per-IP limiters ONCE; every WS frame after
// it must draw from a per-message expensive-read budget (heavy methods only;
// cheap methods flow freely; over budget is a clean error frame, never a
// socket drop).
// (b) `peer_ip=None` (in-process dispatch: `RpcState::call` /
// `handle_rpc_call`) used to SKIP the estimate-fee and per-client
// subscription caps; it now draws from the static "local" bucket with the
// SAME caps.
//
// The WS test binds an ephemeral loopback listener only (no live nodes,
// configs, or external network), mirroring the in-crate WS transport test.
// ---------------------------------------------------------------------------

/// Error message of a raw WS JSON-RPC reply envelope
/// (`{"result":..}` / `{"error":{"code":..,"message":..}}`), unlike
/// [`err_of`] which reads the flattened `RpcState::call` shape.
fn ws_err_of(v: &Value) -> Option<String> {
    v.get("error")?
        .get("message")?
        .as_str()
        .map(|s| s.to_string())
}

#[tokio::test]
async fn ws_expensive_reads_are_capped_per_message_without_dropping() {
    use futures::{SinkExt, StreamExt};

    let st = base_state(None, None).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let app = stellereum::rpc::router(st.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("websocket handshake");
    let who = hex::encode([0x11u8; 32]);
    let mut limited = 0usize;
    // 12 heavy frames back-to-back against a 5/s budget: no split across
    // wall-clock seconds can fit all 12, so at least one MUST be refused
    // with a clean error (never a drop — every frame gets a reply).
    for i in 0..12 {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "stell_getProof",
                "params": {"address": who},
            })
            .to_string(),
        ))
        .await
        .expect("send proof read");
        let reply = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("reply timeout")
            .expect("reply")
            .expect("frame");
        let reply: Value = serde_json::from_str(reply.to_text().expect("text")).expect("json");
        assert_eq!(reply["id"], json!(i), "replies stay in order: {reply}");
        if ws_err_of(&reply)
            .unwrap_or_default()
            .contains("expensive-read budget")
        {
            limited += 1;
        } else {
            assert!(
                ws_err_of(&reply).is_none(),
                "within budget a proof read must succeed: {reply}"
            );
        }
    }
    assert!(
        limited >= 1,
        "a 12-frame heavy burst must hit the per-message budget"
    );
    // Cheap reads draw nothing and the socket is still alive (clean errors,
    // never drops): 12 more cheap frames all succeed.
    for i in 0..12 {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc": "2.0", "id": 100 + i, "method": "stell_chainId", "params": {}})
                .to_string(),
        ))
        .await
        .expect("send cheap read");
        let reply = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("reply timeout")
            .expect("reply")
            .expect("frame");
        let reply: Value = serde_json::from_str(reply.to_text().expect("text")).expect("json");
        assert_eq!(reply["result"], json!(777), "cheap read must succeed: {reply}");
    }
    let _ = ws.close(None).await;
    server.abort();
}

#[tokio::test]
async fn in_process_estimate_fee_draws_from_the_local_bucket() {
    let st = base_state(None, None).await;
    // `RpcState::call` dispatches with `peer_ip=None`; the old code skipped
    // the estimate-fee budget for it. 15 rapid calls cannot fit in 5/s of
    // budget no matter how wall-clock seconds split them, so at least one
    // MUST be refused with the budget error (proving the cap applies).
    let mut limited = 0usize;
    for _ in 0..15 {
        let r = st.call("stell_estimateFee", json!({})).await;
        if err_of(&r)
            .unwrap_or_default()
            .contains("estimate-fee budget exhausted")
        {
            limited += 1;
        }
    }
    assert!(
        limited >= 1,
        "unattributed estimateFee calls must hit the local-bucket budget"
    );
}

#[tokio::test]
async fn in_process_subscribe_is_attributed_to_the_local_bucket() {
    use stellereum::rpc::SubscriptionTopic;
    // Attribution: an in-process subscribe lands in the static "local"
    // bucket instead of an unattributed (uncapped) entry.
    let st = base_state(None, None).await;
    let r = st.call("stell_subscribe", json!(["newHeads"])).await;
    let sub_id = r.as_str().expect("subscribe must succeed").to_string();
    let entry = hub().get(&sub_id).expect("registry entry");
    assert_eq!(
        entry.client.as_deref(),
        Some(stellereum::rpc::LOCAL_SUBSCRIBER_ID),
        "in-process subscribe must be attributed to the local bucket"
    );
    assert!(hub().unsubscribe(&sub_id), "cleanup must remove the sub");
    // Same caps: the "local" bucket gets exactly
    // MAX_SUBSCRIPTIONS_PER_CLIENT live entries. An ISOLATED hub takes the
    // fill — the process-wide hub is shared with every parallel test, so
    // filling it there would starve other tests' subscribes.
    let h = stellereum::rpc::SubscriptionHub::new();
    for _ in 0..stellereum::rpc::MAX_SUBSCRIPTIONS_PER_CLIENT {
        h.subscribe_for(SubscriptionTopic::NewHeads, Some(stellereum::rpc::LOCAL_SUBSCRIBER_ID))
            .expect("within the per-client cap");
    }
    let e = h
        .subscribe_for(SubscriptionTopic::NewHeads, Some(stellereum::rpc::LOCAL_SUBSCRIBER_ID))
        .expect_err("the 65th local subscription must be refused");
    assert!(
        e.contains("per-client"),
        "over-cap subscribe must name the per-client budget: {e}"
    );
}
