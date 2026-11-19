/// The token the test faucet expects; mirrors `STELL_FAUCET_TOKEN`.
const FAUCET_TOKEN: &str = "faucet-secret";
/// The token N-02/N-03 tests configure and present; mirrors
/// `STELL_RPC_AUTH_TOKEN`. Gov writes and contract previews require it
/// ALWAYS (no loopback escape), so happy-path tests use a state built by
/// `test_state_with_token` plus this token in params, while refusal tests
/// use plain `test_state()` (no token configured at all).
const TEST_TOKEN: &str = "test-token";

use super::*;
use crate::mempool::Mempool;
use crate::sharding::{ShardId, ShardRegistry};
use crate::state_engine::{AccountState, InMemoryStateEngine};
use axum::extract::Query;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;

async fn test_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "inf1:test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(crate::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(crate::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

/// Same as `test_state`, but with the testnet faucet enabled and its account
/// pre-funded, mirroring a real testnet genesis.
/// A `stell_faucet` request that presents the correct token.
fn drip_req(address: &str) -> serde_json::Value {
    json!({ "address": address, "token": FAUCET_TOKEN })
}

/// Same, but with the faucet left unconfigured: the operator forgot
/// `STELL_FAUCET_TOKEN`.
async fn test_state_with_untokened_faucet(drip: u64, cap: u64) -> Arc<RpcState> {
    let key_seed = [0x11u8; 32];
    // FULL-PQ: the faucet account is the Falcon-512 address derived from
    // the seed (Faucet::account); fund that address, never a classical one.
    // Funded for the PQ drip cost (amount + gas + activation surcharge,
    // reserved jointly per pooled tx) across a full lifetime-cap burst.
    let faucet_addr = {
        let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pq_key.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        )
    };
    let st = test_state().await;
    st.engine
        .update_account(AccountState::new(faucet_addr, 100_000_000))
        .await;
    Arc::new(RpcState {
        faucet: Some(Arc::new(Faucet::new(key_seed, 1, drip, cap))),
        faucet_token: None,
        msg_signing_seed: None,
        engine: st.engine.clone(),
        mempool: st.mempool.clone(),
        height: st.height.clone(),
        node_id: st.node_id.clone(),
        chain_id: st.chain_id,
        auth_token: st.auth_token.clone(),
        staking: st.staking.clone(),
        governance: st.governance.clone(),
        recent_blocks: st.recent_blocks.clone(),
        receipts: st.receipts.clone(),
        tx_broadcast: st.tx_broadcast.clone(),
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn test_state_with_faucet(drip: u64, cap: u64) -> Arc<RpcState> {
    let key_seed = [0x11u8; 32];
    // FULL-PQ: the faucet account is the Falcon-512 address derived from
    // the seed (Faucet::account); fund that address, never a classical one.
    // Funded for the PQ drip cost (amount + gas + activation surcharge,
    // reserved jointly per pooled tx) across a full lifetime-cap burst.
    let faucet_addr = {
        let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pq_key.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        )
    };
    let st = test_state().await;
    st.engine
        .update_account(AccountState::new(faucet_addr, 100_000_000))
        .await;
    Arc::new(RpcState {
        faucet: Some(Arc::new(Faucet::new(key_seed, 1, drip, cap))),
        faucet_token: Some(FAUCET_TOKEN.to_string()),
        msg_signing_seed: None,
        engine: st.engine.clone(),
        mempool: st.mempool.clone(),
        height: st.height.clone(),
        node_id: st.node_id.clone(),
        chain_id: st.chain_id,
        staking: st.staking.clone(),
        governance: st.governance.clone(),
        recent_blocks: st.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: st.auth_token.clone(),
        tx_broadcast: st.tx_broadcast.clone(),
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn call(st: &Arc<RpcState>, method: &str, params: Value) -> Value {
    let r = dispatch(st, Value::from(1), method, &params, None, None).await;
    r.0.error
        .map(|e| json!({"error": e.message}))
        .unwrap_or(r.0.result.unwrap_or(Value::Null))
}

/// Same empty node as `test_state`, but with an RPC auth token configured
/// (N-02/N-03 fixture): the only state on which gov writes and contract
/// previews are served. Present `TEST_TOKEN` in params (see
/// `call_with_token`); without it every such call is refused.
async fn test_state_with_token() -> Arc<RpcState> {
    let base = test_state().await;
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
        auth_token: Some(TEST_TOKEN.to_string()),
        tx_broadcast: base.tx_broadcast.clone(),
        faucet: base.faucet.clone(),
        faucet_token: base.faucet_token.clone(),
        msg_signing_seed: base.msg_signing_seed,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

/// `call` with the fixture token injected into object params (N-02/N-03
/// happy-path helper). Non-object params pass through untouched; refusal
/// tests keep using `call` directly (no token, or an explicitly wrong one).
async fn call_with_token(st: &Arc<RpcState>, method: &str, mut params: Value) -> Value {
    if let Value::Object(map) = &mut params {
        map.insert("token".to_string(), json!(TEST_TOKEN));
        // Fixture caller: since F3/F4 a direct-form `stell_callContract`
        // preview REQUIRES an explicit caller (the node never falls back to
        // the zero address). These tests are about call semantics, so they
        // supply a fixed non-privileged caller; `pentest_api_wave` pins the
        // refusal of a caller-less preview.
        if method == "stell_callContract" && !map.contains_key("caller") && !map.contains_key("tx")
        {
            map.insert("caller".to_string(), json!(hex::encode([0xF1u8; 32])));
        }
    }
    call(st, method, params).await
}

/// `call` with an explicit peer IP. Tests that hammer the per-IP
/// estimate-fee budget use DISTINCT loopback IPs so they don't share one
/// 5/s bucket and flake in parallel runs — same production path, same
/// caps, just attributed separately (mirrors distinct real clients).
async fn call_as(
    st: &Arc<RpcState>,
    peer_ip: std::net::IpAddr,
    method: &str,
    params: Value,
) -> Value {
    let r = dispatch(st, Value::from(1), method, &params, None, Some(peer_ip)).await;
    r.0.error
        .map(|e| json!({"error": e.message}))
        .unwrap_or(r.0.result.unwrap_or(Value::Null))
}

/// Mint a process-unique loopback IP for estimate-fee tests.
///
/// The estimate-fee budget is a process-global per-IP fixed-window (1s)
/// limiter, so two tests sharing one IP in the same second share one
/// bucket. Hand-picked constants (`.11`/`.12`/...) isolate by convention;
/// a minted IP isolates by construction: its bucket is empty no matter
/// what else runs in this process, in any order, on any thread. Tests
/// still go through [`call_as`] (same production path, same caps).
fn fresh_estimate_ip() -> std::net::IpAddr {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x010100);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        127,
        ((n >> 16) & 0xFF) as u8,
        ((n >> 8) & 0xFF) as u8,
        (n & 0xFF) as u8,
    ))
}

// GATE: operator-signed governance — deterministic test keys stand in
// for operator staking keys (never validator/consensus keys). The
// helpers sign EXACTLY what the production handlers verify.
use crate::wallet_signing::WalletSigningKey as TestGovKey;

/// Sign a gov proposal envelope for tests (chain-bound, minted by `key`
/// for `proposer` over the exact action the handler will apply).
fn sign_test_proposal(
    chain_id: u64,
    key: &TestGovKey,
    proposer: &[u8; 32],
    title: &str,
    action: &crate::governance::GovAction,
    nonce: u64,
) -> String {
    let msg = crate::governance::Governance::gov_propose_message(
        chain_id, proposer, title, action, nonce,
    );
    key.sign_message(chain_id, &msg).unwrap().to_hex()
}

/// Sign a gov vote envelope for tests.
fn sign_test_vote(
    chain_id: u64,
    key: &TestGovKey,
    voter: &[u8; 32],
    proposal_id: u64,
    choice: crate::governance::VoteChoice,
) -> String {
    let msg = crate::governance::Governance::gov_vote_message(chain_id, proposal_id, choice, voter);
    key.sign_message(chain_id, &msg).unwrap().to_hex()
}

/// PQ-sign an assembled block-carried gov template with the sender's own
/// key (the session/PQ signing path callers use): implicit Falcon-512
/// envelope over `signing_message`, key pre-registered globally via
/// `pq_pair` (the `pq_tx_payload` idiom — `seed` must be distinct per
/// sender within a test). The node never signs: this helper stands in
/// for the caller's wallet.
fn sign_gov_block_tx(
    seed: u8,
    pk: &[u8],
    mut tx: crate::sharding::Transaction,
) -> crate::sharding::Transaction {
    let msg = tx.signing_message();
    let sig = crate::sharding::Transaction::create_falcon512_test_signature(pk, &msg, seed);
    tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
        crate::post_quantum::PqScheme::Falcon512,
        sig,
    )
    .encode();
    tx
}

/// Hex of the bincode wire bytes of a signed tx (the `tx` param shape).
fn gov_tx_hex(tx: &crate::sharding::Transaction) -> String {
    hex::encode(bincode::serialize(tx).unwrap())
}

// GATE: H-02 — fixed test seed 0x42 stands in for the ephemeral dev-only
// key (`dev_msg_signing_seed_from_env`); it is NOT the validator key and
// no test may wire a validator/consensus key here. Justification: the
// address pin below needs a deterministic seed, while production mints a
// fresh random seed per boot.
async fn signing_state(token: Option<&str>) -> Arc<RpcState> {
    let base = test_state().await;
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
        auth_token: token.map(|t| t.to_string()),
        tx_broadcast: base.tx_broadcast.clone(),
        faucet: base.faucet.clone(),
        faucet_token: base.faucet_token.clone(),
        msg_signing_seed: Some([0x42u8; 32]),
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

#[tokio::test]
async fn sign_and_verify_message_round_trip() {
    // GATE: H-02 — dev-mode works only with a presented token (SIGN arms
    // are fail-closed without STELL_RPC_AUTH_TOKEN). Justification: this
    // test previously used an open tokenless node; updated to the gated
    // dev-mode path. The seed is the fixed test stand-in, not a
    // validator key.
    let st = signing_state(Some("secret")).await;
    let signed = call(
        &st,
        "stell_signMessage",
        json!({"message": "hello stellereum", "token": "secret"}),
    )
    .await;
    assert!(signed.get("error").is_none(), "sign must succeed: {signed}");
    // The node signs with its own key: seed 0x42, Falcon-512 only. The
    // address is the zero-salt PQ derivation, and the envelope is the
    // 1569-byte Falcon shape (no classical 102-byte Ed vector any more).
    let expected_addr =
        crate::wallet_signing::WalletSigningKey::falcon_from_seed(&[0x42u8; 32]).address();
    assert_eq!(signed["address"], json!(hex::encode(expected_addr)));
    assert_eq!(signed["scheme"], json!("Falcon-512"));
    assert_eq!(signed["scheme_id"], json!(2));
    assert_eq!(signed["chain_id"], json!(777));
    let sig = signed["signature"]
        .as_str()
        .expect("signature hex")
        .to_string();
    let verified = call(
        &st,
        "stell_verifyMessage",
        json!({
            "address": signed["address"],
            "message": "hello stellereum",
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(
        verified["valid"],
        json!(true),
        "round trip must verify: {verified}"
    );
    // Same bytes, hex form.
    let verified_hex = call(
        &st,
        "stell_verifyMessage",
        json!({
            "address": signed["address"],
            "message_hex": format!("0x{}", hex::encode("hello stellereum")),
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(verified_hex["valid"], json!(true));
}

#[tokio::test]
async fn sign_needs_token_but_verify_is_public() {
    let st = signing_state(Some("secret")).await;
    let denied = call(&st, "stell_signMessage", json!({"message": "hi"})).await;
    assert!(
        denied.get("error").is_some(),
        "sign without a token must be refused: {denied}"
    );
    let signed = call(
        &st,
        "stell_signMessage",
        json!({"message": "hi", "token": "secret"}),
    )
    .await;
    assert!(
        signed.get("error").is_none(),
        "sign with a token must succeed: {signed}"
    );
    // VERIFY stays public even on a token-gated node.
    let verified = call(
        &st,
        "stell_verifyMessage",
        json!({
            "address": signed["address"],
            "message": "hi",
            "signature": signed["signature"],
        }),
    )
    .await;
    assert_eq!(verified["valid"], json!(true));
    // Typed-data arms follow the same gate split.
    let typed_denied = call(
        &st,
        "stell_signTypedData",
        json!({"contract": hex::encode([0x01u8; 32]), "method": "ping"}),
    )
    .await;
    assert!(typed_denied.get("error").is_some());
    let typed = call(
        &st,
        "stell_signTypedData",
        json!({"contract": hex::encode([0x01u8; 32]), "method": "ping", "token": "secret"}),
    )
    .await;
    assert!(
        typed.get("error").is_none(),
        "typed sign with token: {typed}"
    );
    let tverified = call(
        &st,
        "stell_verifyTypedData",
        json!({
            "address": typed["address"],
            "contract": hex::encode([0x01u8; 32]),
            "method": "ping",
            "signature": typed["signature"],
        }),
    )
    .await;
    assert_eq!(tverified["valid"], json!(true));
}

#[tokio::test]
async fn sign_refuses_fail_closed_without_a_key() {
    // GATE: H-02 — prod-mode refused: token configured but no dev key
    // (production default) must refuse with "not configured", not sign.
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: Some("secret".to_string()),
        tx_broadcast: base.tx_broadcast.clone(),
        faucet: base.faucet.clone(),
        faucet_token: base.faucet_token.clone(),
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    let r = call(
        &st,
        "stell_signMessage",
        json!({"message": "hi", "token": "secret"}),
    )
    .await;
    assert!(r.get("error").is_some(), "keyless sign must fail: {r}");
    assert!(
        r["error"].as_str().unwrap().contains("not configured"),
        "{r}"
    );
    let t = call(
        &st,
        "stell_signTypedData",
        json!({"contract": hex::encode([0x01u8; 32]), "method": "ping", "token": "secret"}),
    )
    .await;
    assert!(t.get("error").is_some());
}

#[tokio::test]
async fn sign_refuses_without_token_even_with_key() {
    // GATE: H-02 — dev key present but no token configured/presented:
    // SIGN arms stay fail-closed (anonymous signing oracle refused).
    let st = signing_state(None).await;
    let r = call(&st, "stell_signMessage", json!({"message": "hi"})).await;
    assert!(r.get("error").is_some(), "tokenless sign must fail: {r}");
    assert!(
        r["error"]
            .as_str()
            .unwrap()
            .contains("STELL_RPC_AUTH_TOKEN"),
        "{r}"
    );
    let t = call(
        &st,
        "stell_signTypedData",
        json!({"contract": hex::encode([0x01u8; 32]), "method": "ping"}),
    )
    .await;
    assert!(t.get("error").is_some(), "{t}");
}

#[tokio::test]
async fn sign_refuses_non_loopback_peer() {
    // GATE: H-02 — loopback-only: a routable peer IP is refused even with
    // a valid token; loopback succeeds on the same state.
    let st = signing_state(Some("secret")).await;
    let params = json!({"message": "hi", "token": "secret"});
    let remote: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let denied = call_as(&st, remote, "stell_signMessage", params.clone()).await;
    assert!(
        denied.get("error").is_some(),
        "non-loopback sign must fail: {denied}"
    );
    assert!(
        denied["error"].as_str().unwrap().contains("loopback"),
        "{denied}"
    );
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let allowed = call_as(&st, loopback, "stell_signMessage", params).await;
    assert!(
        allowed.get("error").is_none(),
        "loopback sign must succeed: {allowed}"
    );
}

#[tokio::test]
async fn rpc_signature_does_not_verify_on_another_chain() {
    // GATE: H-02 — updated to the gated dev-mode path (token required);
    // domain assertions unchanged.
    let st = signing_state(Some("secret")).await;
    let signed = call(
        &st,
        "stell_signMessage",
        json!({"message": "move 1 STELL", "token": "secret"}),
    )
    .await;
    assert!(signed.get("error").is_none(), "sign must succeed: {signed}");
    let params = |chain: u64| {
        json!({
            "address": signed["address"],
            "message": "move 1 STELL",
            "signature": signed["signature"],
            "chain_id": chain,
        })
    };
    assert_eq!(
        call(&st, "stell_verifyMessage", params(777)).await["valid"],
        json!(true)
    );
    assert_eq!(
        call(&st, "stell_verifyMessage", params(778)).await["valid"],
        json!(false)
    );
}

#[tokio::test]
async fn rpc_tampered_message_and_bad_envelope_fail() {
    // GATE: H-02 — updated to the gated dev-mode path (token required);
    // tamper/envelope assertions unchanged.
    let st = signing_state(Some("secret")).await;
    let signed = call(
        &st,
        "stell_signMessage",
        json!({"message": "pay alice 1", "token": "secret"}),
    )
    .await;
    assert!(signed.get("error").is_none(), "sign must succeed: {signed}");
    let bad_msg = call(
        &st,
        "stell_verifyMessage",
        json!({
            "address": signed["address"],
            "message": "pay alice 2",
            "signature": signed["signature"],
        }),
    )
    .await;
    assert_eq!(bad_msg["valid"], json!(false), "{bad_msg}");
    // Malformed envelope is a params error, not "invalid".
    let bad_env = call(
        &st,
        "stell_verifyMessage",
        json!({
            "address": signed["address"],
            "message": "pay alice 1",
            "signature": "0x0102",
        }),
    )
    .await;
    assert!(bad_env.get("error").is_some(), "{bad_env}");
    // Both message forms at once is ambiguous.
    let both = call(
        &st,
        "stell_verifyMessage",
        json!({
            "address": signed["address"],
            "message": "pay alice 1",
            "message_hex": "0x01",
            "signature": signed["signature"],
        }),
    )
    .await;
    assert!(both.get("error").is_some(), "{both}");
}

#[tokio::test]
async fn typed_data_is_canonical_over_rpc() {
    // GATE: H-02 — updated to the gated dev-mode path (token required);
    // canonicalization assertions unchanged.
    let st = signing_state(Some("secret")).await;
    let contract = hex::encode([0xABu8; 32]);
    let args_a = json!({"to": "alice", "amount": 100});
    let args_b = json!({"amount": 100, "to": "alice"});
    let sign = |args: Value| {
        let st = st.clone();
        let contract = contract.clone();
        async move {
            call(
                &st,
                "stell_signTypedData",
                json!({
                    "contract": contract,
                    "method": "transfer",
                    "args": args,
                    "value": "1000",
                    "nonce": "7",
                    "token": "secret",
                }),
            )
            .await
        }
    };
    let a = sign(args_a).await;
    let b = sign(args_b).await;
    assert!(a.get("error").is_none(), "{a}");
    // Canonical content is deterministic; Falcon-512 signatures are
    // RANDOMIZED, so different key order still yields the SAME canonical
    // JSON (and both signatures verify it), but not the same signature bytes.
    assert_eq!(a["canonical"], b["canonical"]);
    assert_ne!(a["signature"], b["signature"]);
    assert_eq!(
        a["canonical"],
        json!(format!(
            "{{\"args\":{{\"amount\":100,\"to\":\"alice\"}},\"chain_id\":\"777\",\"contract\":\"0x{contract}\",\"method\":\"transfer\",\"nonce\":\"7\",\"value\":\"1000\"}}"
        ))
    );
    // And the canonical bytes verify.
    for s in [&a, &b] {
        let v = call(
            &st,
            "stell_verifyTypedData",
            json!({
                "address": s["address"],
                "contract": contract,
                "method": "transfer",
                "args": {"to": "alice", "amount": 100},
                "value": "1000",
                "nonce": "7",
                "signature": s["signature"],
            }),
        )
        .await;
        assert_eq!(v["valid"], json!(true), "{v}");
    }
    // Same fields on another chain do not verify.
    let other = call(
        &st,
        "stell_verifyTypedData",
        json!({
            "address": a["address"],
            "contract": contract,
            "method": "transfer",
            "args": {"to": "alice", "amount": 100},
            "value": "1000",
            "nonce": "7",
            "chain_id": 778,
            "signature": a["signature"],
        }),
    )
    .await;
    assert_eq!(other["valid"], json!(false));
}

/// A hub ISOLATED from every other test's traffic.
///
/// The subscription hub is one per process, so a test that asserts on
/// its contents (the invalidation window) would otherwise see whatever
/// the tests running next to it published. Installing a fresh hub for
/// this thread makes the assertion about the node's own history.
fn isolated_hub() -> &'static Arc<SubscriptionHub> {
    install_test_hub()
}

fn receipt_tx(seed: u8, nonce: u64) -> crate::sharding::Transaction {
    // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge),
    // shard 0 like the old fixture.
    pq_tx_shard(seed, [0xEE; 32], 10, 1, nonce, 0, 0)
}

/// Cached seeded Falcon-512 keypairs (256 slots by `seed: u8`), lazily
/// initialized once per seed and registered in `global_implicit_registry()`.
/// Avoids repeating 40,000 NTRU keygens in `receipt_batch_txs(20_000)`.
fn cached_pq_test_key(seed: u8) -> &'static ([u8; 32], crate::post_quantum::FalconKeypair) {
    type SeededPqEntry = ([u8; 32], crate::post_quantum::FalconKeypair);
    static CACHE: std::sync::OnceLock<Vec<std::sync::OnceLock<SeededPqEntry>>> =
        std::sync::OnceLock::new();
    let table = CACHE.get_or_init(|| (0..256).map(|_| std::sync::OnceLock::new()).collect());
    table[seed as usize].get_or_init(|| {
        let kp = crate::post_quantum::FalconKeypair::generate_from_seed(seed);
        let from = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &kp.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        );
        crate::sharding::Transaction::global_implicit_registry()
            .register(
                from,
                crate::post_quantum::PqScheme::Falcon512,
                &kp.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            )
            .expect("PQ test key must register");
        (from, kp)
    })
}

/// FULL-PQ test helper: implicit Falcon-512 tx (no activation surcharge,
/// so fee/balance assertions match the old classical fixtures exactly).
/// The key is pre-registered globally (idempotent) for intake/apply
/// verification. `seed` must be distinct per sender within a test.
fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
    let (from, kp) = cached_pq_test_key(seed);
    (*from, kp.public_key.clone())
}

fn pq_tx_payload(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    payload: Vec<crate::svm::OpCode>,
) -> crate::sharding::Transaction {
    let (from, kp) = cached_pq_test_key(seed);
    let mut tx = crate::sharding::Transaction {
        from: *from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
        crate::post_quantum::PqScheme::Falcon512,
        sig,
    )
    .encode();
    tx
}

fn pq_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
) -> crate::sharding::Transaction {
    pq_tx_chain(seed, to, amount, gas, nonce, None)
}

/// FULL-PQ replacement for `Transaction::sign_with_chain_id` in tests.
fn pq_tx_chain(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    chain: Option<u64>,
) -> crate::sharding::Transaction {
    pq_tx_shard_chain(seed, to, amount, gas, nonce, 1, 1, chain)
}

fn pq_tx_shard(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    s1: crate::sharding::ShardId,
    s2: crate::sharding::ShardId,
) -> crate::sharding::Transaction {
    pq_tx_shard_chain(seed, to, amount, gas, nonce, s1, s2, None)
}

// GATE: test-only PQ fixture helper with shard+chain params; splitting it
// would churn all callers for zero benefit.
#[allow(clippy::too_many_arguments)]
fn pq_tx_shard_chain(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    s1: crate::sharding::ShardId,
    s2: crate::sharding::ShardId,
    chain: Option<u64>,
) -> crate::sharding::Transaction {
    let (from, kp) = cached_pq_test_key(seed);
    let mut tx = crate::sharding::Transaction {
        from: *from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: s1,
        target_shard: s2,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    // Chain-bound envelopes commit the chain id in the signed message:
    // sign the probe message that already carries it (dummy sig of
    // pinned length — never decoded, only its chain field is read).
    if let Some(c) = chain {
        tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit_with_chain(
            crate::post_quantum::PqScheme::Falcon512,
            vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
            c,
        )
        .encode();
    }
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    let env = match chain {
        Some(c) => crate::sharding::PqSignatureEnvelope::new_implicit_with_chain(
            crate::post_quantum::PqScheme::Falcon512,
            sig,
            c,
        ),
        None => crate::sharding::PqSignatureEnvelope::new_implicit(
            crate::post_quantum::PqScheme::Falcon512,
            sig,
        ),
    };
    tx.signature = env.encode();
    tx
}

#[tokio::test]
async fn receipt_reports_height_block_index_and_status() {
    let st = test_state().await;
    let txs = vec![receipt_tx(0xA1, 0), receipt_tx(0xA2, 0)];
    st.record_receipts(77, [0xAB; 32], &txs, &[true, false], &[1, 0])
        .await;

    let ok_tx = call(
        &st,
        "stell_getTransactionReceipt",
        json!(hex::encode(txs[0].compute_tx_hash())),
    )
    .await;
    assert_eq!(ok_tx["height"], json!(77));
    assert_eq!(ok_tx["block_hash"], json!(hex::encode([0xABu8; 32])));
    assert_eq!(ok_tx["index"], json!(0));
    assert_eq!(ok_tx["status"], json!("success"));
    assert_eq!(
        ok_tx["fee_charged"],
        json!("1"),
        "receipt files the actual charge"
    );
    assert!(
        ok_tx["gas_limit"].as_str().is_some(),
        "limit is kept alongside"
    );

    let bad_tx = call(
        &st,
        "stell_getTransactionReceipt",
        json!(hex::encode(txs[1].compute_tx_hash())),
    )
    .await;
    assert_eq!(bad_tx["status"], json!("failed"));
    assert_eq!(bad_tx["index"], json!(1));
    assert_eq!(
        bad_tx["fee_charged"],
        json!("0"),
        "a failed tx paid nothing"
    );
}

#[tokio::test]
async fn receipt_distinguishes_pending_from_unknown() {
    let st = test_state().await;
    let tx = receipt_tx(0xA3, 0);
    let h = hex::encode(tx.compute_tx_hash());
    assert_eq!(
        call(&st, "stell_getTransactionStatus", json!(h)).await["status"],
        json!("unknown")
    );

    st.mempool.write().await.add(tx.clone()).unwrap();
    assert_eq!(
        call(&st, "stell_getTransactionStatus", json!(h)).await["status"],
        json!("pending")
    );

    st.record_receipts(5, [0x01; 32], std::slice::from_ref(&tx), &[true], &[1])
        .await;
    let done = call(&st, "stell_getTransactionStatus", json!(h)).await;
    assert_eq!(done["status"], json!("success"));
    assert_eq!(done["height"], json!(5));
}

#[tokio::test]
async fn receipt_status_and_block_are_consistent() {
    // Guards the invariant main.rs relies on: statuses are captured during
    // the single real application, never produced by re-applying the block
    // (which would execute every transfer a second time).
    // FULL-PQ: implicit Falcon-512 (no surcharge).
    let engine = Arc::new(InMemoryStateEngine::new());
    let tx = pq_tx_shard(0xA4, [0xEE; 32], 100, 1, 0, 0, 0);
    engine
        .update_account(AccountState::new(tx.from, 1_000))
        .await;
    let (applied, _failed, _fees, statuses, tx_fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 0)
        .await;

    assert_eq!(applied, 1);
    assert_eq!(
        statuses,
        vec![true],
        "one status per transaction, in block order"
    );
    assert_eq!(
        tx_fees,
        vec![1],
        "the receipt files what commit_native charged"
    );

    let balance_after = engine.get_account(&tx.from).await.unwrap().balance;
    assert_eq!(balance_after, 1_000 - 101, "value moved exactly once");

    // Statuses must describe the block, not a second execution: re-running
    // admission against post-state makes the spent nonce fail, so a naive
    // recompute would flip this successful tx to "failed".
    let (_a2, _f2, _fees2, again, again_fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 0)
        .await;
    assert_eq!(
        again,
        vec![false],
        "replay of a spent nonce is rejected, as it must be"
    );
    assert_eq!(
        again_fees,
        vec![0],
        "a refused transaction is charged nothing"
    );
}

#[tokio::test]
async fn receipt_index_is_bounded() {
    let mut idx = ReceiptIndex::default();
    for i in 0..(MAX_RECEIPTS + 10) {
        let h: [u8; 32] = blake3::hash(&(i as u64).to_be_bytes()).into();
        idx.insert(TxReceipt {
            tx_hash: h,
            height: i as u64,
            block_hash: [0u8; 32],
            index: 0,
            success: true,
            gas_limit: 0,
            fee_charged: 0,
            raw_tx: None,
            return_value: None,
            gas_used: None,
            events: Vec::new(),
            contract_address: None,
        });
    }
    assert_eq!(
        idx.len(),
        MAX_RECEIPTS,
        "a busy chain cannot exhaust memory"
    );
    let oldest: [u8; 32] = blake3::hash(&0u64.to_be_bytes()).into();
    assert!(idx.get(&oldest).is_none(), "oldest receipts are evicted");
    let newest: [u8; 32] = blake3::hash(&(MAX_RECEIPTS as u64 + 9).to_be_bytes()).into();
    assert!(idx.get(&newest).is_some(), "newest receipt is retained");
}

#[tokio::test]
async fn receipt_rejects_malformed_hash() {
    let st = test_state().await;
    let r = call(&st, "stell_getTransactionReceipt", json!("not-a-hash")).await;
    assert!(
        r.get("error").is_some(),
        "garbage hash is a client error, not a panic"
    );
}

#[tokio::test]
async fn evm_adapter_network_info_methods_through_rpc() {
    let st = test_state().await;
    assert_eq!(call(&st, "eth_chainId", json!([])).await, json!("0x167d"));
    assert_eq!(call(&st, "net_version", json!([])).await, json!("5757"));
    assert_eq!(
        call(&st, "web3_clientVersion", json!([])).await,
        json!("Stellereum/v5.0.0-evm-adapter")
    );
    assert_eq!(call(&st, "net_listening", json!([])).await, json!(true));
    // F8: the live observed count, never a fabricated constant.
    assert_eq!(
        call(&st, "net_peerCount", json!([])).await,
        json!(crate::evm_adapter::format_peer_count_hex(
            observed_peer_count()
        ))
    );
    // LIVE: same rule as `stell_syncing` — a recent verified peer height
    // above ours means syncing. `PEER_HEIGHT` is process-global and
    // monotonic, so the expectation is computed, not hardcoded.
    let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
    let expect_syncing = crate::evm_adapter::eth_syncing_for_heights(ours, fresh_peer_height());
    assert_eq!(
        call(&st, "eth_syncing", json!([])).await,
        json!(expect_syncing)
    );
    assert_eq!(
        call(&st, "stell_syncing", json!([])).await,
        json!(expect_syncing),
        "eth_syncing and stell_syncing must agree on the same heights"
    );
    assert_eq!(
        call(&st, "eth_gasPrice", json!([])).await,
        json!("0x3eb2788000")
    );
    assert_eq!(
        call(&st, "eth_maxPriorityFeePerGas", json!([])).await,
        json!("0x3b9aca00")
    );
    // F10: a sender-less estimate carries the worst-case D2 bond so it is
    // never below a real sender's admission floor.
    {
        let base = st.mempool.read().await.base_fee;
        let expected =
            21_000u64.max(base.saturating_add(crate::mempool::MAX_FAILED_SENDER_PENALTY));
        assert_eq!(
            call(&st, "eth_estimateGas", json!([])).await,
            json!(crate::evm_adapter::format_u64_hex(expected))
        );
    }
    // F9: no EVM fee market is committed, so the method refuses explicitly
    // instead of inventing a series.
    let fh = call(&st, "eth_feeHistory", json!([4, "latest", [25.0, 75.0]])).await;
    assert!(
        fh["error"].as_str().unwrap_or("").contains("not served"),
        "eth_feeHistory must refuse honestly: {fh}"
    );
}

#[tokio::test]
async fn bridge_dispute_reads_report_records_and_disputes() {
    use crate::bridge::{DepositRecord, Dispute, SupportedChain};
    let st = test_state().await;
    let hash = hex::encode([0x77u8; 32]);
    let r = call(
        &st,
        "stell_bridgeDeposit",
        json!({ "source_tx_hash": hash }),
    )
    .await;
    assert_eq!(r["found"], false, "no record on a fresh engine");
    let r = call(&st, "stell_bridgeDispute", json!({ "dispute_id": "0" })).await;
    assert_eq!(r["found"], false, "no dispute on a fresh engine");

    {
        let mut br = st.engine.bridge_write().await;
        br.deposit_records.insert(
            [0x77u8; 32],
            DepositRecord {
                recipient: [0x78u8; 32],
                amount: 100,
                chain: SupportedChain::Ton,
                via_quorum: true,
                deposited_at: 1000,
                disputed: true,
            },
        );
        br.disputes.insert(
            0,
            Dispute {
                source_tx_hash: [0x77u8; 32],
                challenger: [0x79u8; 32],
                recipient: [0x78u8; 32],
                amount: 100,
                bond: 200,
                deadline: 4600,
                resolved: false,
                confirmed: false,
            },
        );
    }
    let r = call(
        &st,
        "stell_bridgeDeposit",
        json!({ "source_tx_hash": hash }),
    )
    .await;
    assert_eq!(r["found"], true);
    assert_eq!(r["amount"], "100");
    assert_eq!(r["via_quorum"], true);
    assert_eq!(r["disputed"], true);
    let r = call(&st, "stell_bridgeDispute", json!({ "dispute_id": "0" })).await;
    assert_eq!(r["found"], true);
    assert_eq!(r["deadline"], 4600);
    assert_eq!(r["resolved"], false);
    let r = call(&st, "stell_bridgeDeposit", json!("not-a-hash")).await;
    assert!(r.get("error").is_some(), "garbage hash is a client error");
}

/// The bridge deposit's two halves must not shadow each other (audit W7.2).
///
/// `stell_bridgeDeposit` is the RECORD read; the native namespace's
/// PREPARE of the same deposit is `stell_bridgeDepositPrepare`. Before
/// the split, the read arm was matched FIRST, so the prepare was
/// unreachable over JSON-RPC.
#[tokio::test]
async fn bridge_deposit_read_and_prepare_have_distinct_names() {
    let st = test_state().await;

    // 1. The READ is still the read.
    let r = call(
        &st,
        "stell_bridgeDeposit",
        json!({ "source_tx_hash": hex::encode([0x77u8; 32]) }),
    )
    .await;
    assert_eq!(r["found"], false);

    // 2. A PREPARE-shaped call to the read is refused with a pointer to
    //    the prepare method — never a plausible-looking `found: false`.
    let r = call(
        &st,
        "stell_bridgeDeposit",
        json!({
            "chain": "ton",
            "source_tx_hash": hex::encode([0x77u8; 32]),
            "recipient": hex::encode([0x78u8; 32]),
            "amount": "10",
        }),
    )
    .await;
    let msg = r["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("stell_bridgeDepositPrepare"),
        "the refusal must name the prepare method, got: {msg}"
    );

    // 3. The PREPARE is reachable over JSON-RPC and answers with the
    //    transaction to sign.
    let r = call(
        &st,
        "stell_bridgeDepositPrepare",
        json!({
            "chain": "ton",
            "source_tx_hash": hex::encode([0x77u8; 32]),
            "recipient": hex::encode([0x78u8; 32]),
            "amount": "10",
        }),
    )
    .await;
    assert!(r.get("error").is_none(), "prepare must answer: {r}");
    assert_eq!(r["action"], "bridge_deposit");
    assert_eq!(r["transaction"]["op"], "SysCallBridge");
    assert_eq!(r["transaction"]["args"]["intent"], "Deposit");
    assert_eq!(r["submit_with"], "stell_sendRawTransaction");
}

/// The manifest must advertise BOTH halves under their own names, with
/// their own kinds (audit W7.2).
#[tokio::test]
async fn native_api_manifest_names_the_bridge_deposit_halves_unambiguously() {
    let st = test_state().await;
    let m = call(&st, "stell_nativeApi", json!({})).await;
    let methods = m["methods"].as_array().unwrap().clone();
    let find = |name: &str| {
        methods
            .iter()
            .find(|v| v["name"].as_str() == Some(name))
            .cloned()
    };
    let read = find("stell_bridgeDeposit");
    assert!(
        read.is_none(),
        "the record read is not part of the native namespace"
    );
    let prep = find("stell_bridgeDepositPrepare").expect("the prepare is advertised");
    assert_eq!(prep["kind"], "prepare");
    // No name in the namespace may be advertised twice.
    let mut names: Vec<&str> = methods
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "the manifest lists a method twice");
}

/// Every `GovAction` is reachable through `stell_submitProposal`, and an
/// UNKNOWN action string is refused (audit W7.2).
///
/// The dispatcher used to answer an unrecognised `type` with a `Signal`
/// action — a silent no-op that made a typo look like an accepted
/// proposal. It now fails closed.
///
/// GATE (operator-signed governance): every accepted proposal below is
/// submitted with a wallet signature over
/// (chain_id || proposer || title || action || nonce), bound to a staked
/// proposer key. Justification for touching this test: the handler now
/// refuses unsigned proposals fail-closed, so the reachability pins must
/// sign; the unknown-type and missing-param refusals still fire BEFORE
/// any signature check (unchanged fail-closed vocabulary gate).
#[tokio::test]
async fn submit_proposal_reaches_every_action_and_refuses_an_unknown_type() {
    // N-02: gov writes require a token on every bind, so this
    // reachability pin runs on the token fixture (refusal cases still pin
    // their own errors — the gate passes, then the vocabulary gate fires).
    let st = test_state_with_token().await;
    // The proposer is a real signing key: the handler binds the envelope
    // to the claimed staking address, so an arbitrary 0xA1 address can no
    // longer propose.
    let proposer_key = TestGovKey::falcon_from_seed(&[0xA1u8; 32]);
    let proposer_addr = proposer_key.address();
    let proposer = hex::encode(proposer_addr);

    // 1. An unknown action type is REFUSED, and nothing is recorded.
    let res = call_with_token(
        &st,
        "stell_submitProposal",
        json!({
            "title": "typo",
            "type": "set_min_validator_bondd",
            "value": 1,
            "proposer": proposer,
        }),
    )
    .await;
    let msg = res["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("unknown governance action type"),
        "unexpected error: {msg}"
    );
    assert!(
        st.governance.read().await.proposals.is_empty(),
        "a refused proposal must not be recorded"
    );

    // 2. A known type with a MISSING parameter is refused too (no
    //    defaults: a governance parameter is never silently invented).
    let res = call_with_token(
        &st,
        "stell_submitProposal",
        json!({ "title": "no value", "type": "set_min_gas_limit", "proposer": proposer }),
    )
    .await;
    let msg = res["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("missing parameter 'value'"),
        "unexpected error: {msg}"
    );

    // 3. Every canonical action type is accepted (the proposer is staked,
    //    otherwise the proposal is refused for the stake and not for the
    //    action). Each envelope carries a fresh nonce (replay protection).
    {
        let mut ledger = st.engine.staking_write().await;
        ledger
            .bond(proposer_addr, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
            .unwrap();
    }
    let cases: Vec<(&str, serde_json::Value)> = vec![
        (
            "set_min_validator_bond",
            json!({ "value": 20_000_000_000_000u64 }),
        ),
        ("set_equivocation_slash_bps", json!({ "value": 500 })),
        ("set_default_commission_bps", json!({ "value": 100 })),
        ("set_block_reward", json!({ "value": 1_000_000_000 })),
        ("set_pmm_redemption_buffer_bps", json!({ "value": 250 })),
        ("set_governance_quorum_bps", json!({ "value": 5_000 })),
        ("signal", json!({ "text": "hello governance" })),
        (
            "register_oracle_publisher",
            json!({ "publisher": hex::encode([0xB2u8; 32]) }),
        ),
        (
            "unregister_oracle_publisher",
            json!({ "publisher": hex::encode([0xB3u8; 32]) }),
        ),
        ("reset_oracle_breaker", json!({})),
        ("set_min_gas_limit", json!({ "value": 21_000 })),
        (
            "software_upgrade",
            json!({ "name": "v0.2.0", "height": 500, "sha256": hex::encode([0xC4u8; 32]) }),
        ),
        ("cancel_upgrade", json!({})),
    ];
    assert_eq!(
        cases.len(),
        crate::governance::GovAction::ACTION_TYPES.len(),
        "every documented action type must be covered by this test"
    );
    for (i, (action_type, extra)) in cases.iter().enumerate() {
        let title = format!("proposal {action_type}");
        let mut params =
            json!({ "title": title.clone(), "type": action_type, "proposer": proposer });
        if let serde_json::Value::Object(map) = extra {
            for (k, v) in map {
                params[k] = v.clone();
            }
        }
        // Sign EXACTLY what the handler will apply (same params shape).
        let action = crate::governance::gov_action_from_params(action_type, &params)
            .expect("test action must parse");
        let nonce = 1000u64 + i as u64;
        params["nonce"] = json!(nonce);
        params["signature"] = json!(sign_test_proposal(
            st.chain_id,
            &proposer_key,
            &proposer_addr,
            &title,
            &action,
            nonce
        ));
        let res = call_with_token(&st, "stell_submitProposal", params).await;
        assert!(
            res.get("error").is_none(),
            "action '{action_type}' must be reachable: {res}"
        );
        assert!(res["proposal_id"].is_u64(), "no proposal id: {res}");
    }

    // 4. The proposals carry the action types they were created with.
    let list = call(&st, "stell_listProposals", json!({})).await;
    let types: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["action_type"].as_str().unwrap_or_default().to_string())
        .collect();
    for (action_type, _) in &cases {
        assert!(
            types.contains(&action_type.to_string()),
            "the proposal for '{action_type}' is missing from {types:?}"
        );
    }
}

#[tokio::test]
async fn faucet_is_disabled_by_default() {
    let st = test_state().await;
    let r = call(
        &st,
        "stell_faucet",
        json!({ "address": hex::encode([0x42u8; 32]) }),
    )
    .await;
    assert!(
        r["error"].as_str().unwrap_or_default().contains("disabled"),
        "faucet must be off unless explicitly enabled: {r}"
    );
    assert!(
        st.engine.get_account(&[0x42u8; 32]).await.is_none(),
        "no account may be created"
    );
}

#[tokio::test]
async fn faucet_caps_survive_a_restart() {
    // The Wave-5 finding: lifetime caps lived in a bare in-process Mutex, so a
    // restart resurrected every capped address's full allowance (1000 STELL per
    // address per restart at production defaults, unbounded). Caps and the nonce
    // are now persisted on every mutation; a fresh Faucet over the saved bytes
    // must pick up exactly where the old one left off.
    use std::sync::{Arc, Mutex};
    let saved: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let saver = {
        let saved = Arc::clone(&saved);
        Arc::new(move |bytes: &[u8]| {
            *saved.lock().unwrap() = bytes.to_vec();
        }) as Arc<dyn Fn(&[u8]) + Send + Sync>
    };
    let key_seed = [0x11u8; 32];
    let old = Faucet::new(key_seed, 1, 10, 25).with_persist(saver);
    let who = [0x42u8; 32];

    // Exhaust the address: 10 + 10 + 5 == cap 25.
    assert!(old.build_transfer(who, None, None).await.is_some());
    assert!(old.build_transfer(who, None, None).await.is_some());
    assert!(old.build_transfer(who, None, None).await.is_some());
    assert_eq!(old.dispensed_to(who).await, 25);
    assert!(
        old.build_transfer(who, None, None).await.is_none(),
        "capped"
    );

    // "Restart": a fresh Faucet over the persisted bytes.
    let bytes = saved.lock().unwrap().clone();
    assert!(!bytes.is_empty(), "every drip must have persisted state");
    let new = Faucet::new(key_seed, 1, 10, 25);
    new.load_bytes(&bytes).await;
    assert_eq!(
        new.dispensed_to(who).await,
        25,
        "cap must survive the restart"
    );
    assert!(
        new.build_transfer(who, None, None).await.is_none(),
        "a capped address must stay capped after a restart"
    );

    // And a corrupt record fails closed to empty (under-serves, never over-mints).
    let broken = Faucet::new(key_seed, 1, 10, 25);
    broken.load_bytes(b"not-a-faucet-state").await;
    assert_eq!(broken.dispensed_to(who).await, 0);
}

#[tokio::test]
async fn faucet_caps_lifetime_credit_per_address() {
    // Small cap so the test can exhaust it: drips of 10, lifetime cap 25.
    let st = test_state_with_faucet(10, 25).await;
    let who = [0x42u8; 32];
    let hexa = hex::encode(who);

    // Requesting more than a drip can never exceed the drip amount.
    let r = call(
        &st,
        "stell_faucet",
        json!({ "address": hexa.clone(), "amount": u64::MAX, "token": FAUCET_TOKEN }),
    )
    .await;
    assert_eq!(r["credited_nano"], "10");
    assert_eq!(
        call(&st, "stell_faucet", drip_req(&hexa)).await["credited_nano"],
        "10"
    );
    // 3rd call is clamped by the lifetime cap to the remaining 5.
    let r3 = call(&st, "stell_faucet", drip_req(&hexa)).await;
    assert_eq!(r3["credited_nano"], "5");
    // 4th call: exhausted.
    let r4 = call(&st, "stell_faucet", drip_req(&hexa)).await;
    assert!(
        r4["error"].as_str().unwrap_or_default().contains("limit"),
        "{r4}"
    );

    // Every drip is a real, correctly signed transfer from the faucet account
    // sitting in the mempool — nothing was written straight into state.
    let pending = st.mempool.read().await.len();
    assert_eq!(pending, 3);
    for tx in st.mempool.read().await.all() {
        assert!(
            tx.verify_signature(),
            "faucet tx must carry a valid signature"
        );
        assert_eq!(tx.to, [0x42u8; 32]);
    }
}

#[tokio::test]
async fn public_drip_is_5_stell_per_45_minutes_per_address() {
    // TON-style public drip: fixed 5 STELL, one per address per 45 minutes.
    let faucet = Faucet::new([0x77u8; 32], 0, 10 * 1_000_000_000, 1_000_000_000_000);
    let who = [0x42u8; 32];
    let t0 = 1_700_000_000u64;

    // First drip succeeds with exactly 5 STELL.
    let (tx1, amount1) = faucet
        .build_public_transfer(who, t0, None)
        .await
        .expect("first public drip must succeed");
    assert_eq!(amount1, PUBLIC_DRIP_NANO);
    assert_eq!(amount1, 5 * 1_000_000_000);
    assert_eq!(tx1.to, who);
    assert!(
        tx1.verify_signature(),
        "public drip must carry a valid signature"
    );

    // Immediate retry is cooling down with seconds remaining.
    let err = faucet
        .build_public_transfer(who, t0 + 60, None)
        .await
        .expect_err("second drip within 45 minutes must cool down");
    assert_eq!(err, PUBLIC_DRIP_COOLDOWN_SECS - 60);

    // A different address is unaffected.
    let (tx2, amount2) = faucet
        .build_public_transfer([0x43u8; 32], t0 + 60, None)
        .await
        .expect("other address must not share cooldown");
    assert_eq!(amount2, PUBLIC_DRIP_NANO);
    assert_eq!(tx2.nonce, tx1.nonce + 1);

    // After exactly 45 minutes the same address may drip again.
    let (tx3, _) = faucet
        .build_public_transfer(who, t0 + PUBLIC_DRIP_COOLDOWN_SECS, None)
        .await
        .expect("drip after cooldown must succeed");
    assert_eq!(tx3.nonce, tx2.nonce + 1);

    // If rollback is called on a failed transaction, cooldown is cleared.
    faucet.rollback(&tx3, who, PUBLIC_DRIP_NANO).await;
    // Address can immediately request public drip again.
    let (tx4, _) = faucet
        .build_public_transfer(who, t0 + PUBLIC_DRIP_COOLDOWN_SECS + 5, None)
        .await
        .expect("drip after rollback must succeed immediately");
    assert_eq!(tx4.nonce, tx3.nonce);
}

#[tokio::test]
async fn faucet_uses_increasing_nonces() {
    let st = test_state_with_faucet(10, 100).await;
    call(&st, "stell_faucet", drip_req(&hex::encode([1u8; 32]))).await;
    call(&st, "stell_faucet", drip_req(&hex::encode([2u8; 32]))).await;
    let mut nonces: Vec<u64> = st
        .mempool
        .read()
        .await
        .all()
        .iter()
        .map(|t| t.nonce)
        .collect();
    nonces.sort_unstable();
    assert_eq!(nonces, vec![0, 1], "faucet txs must not reuse a nonce");
}

/// Fail-safe pure-PQ override: resets on drop so a panicking assertion
/// cannot leak enforcement into unrelated tests on this thread.
struct PurePqGuard;
impl PurePqGuard {
    fn enforce() -> Self {
        crate::post_quantum::set_pure_pq_override(Some(true));
        Self
    }
}
impl Drop for PurePqGuard {
    fn drop(&mut self) {
        crate::post_quantum::set_pure_pq_override(None);
    }
}

fn faucet_pq_keypair() -> crate::post_quantum::FalconKeypair {
    crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x11u8; 32])
}

#[test]
fn pq_explicit_transfer_verifies_under_pure_pq() {
    let _guard = PurePqGuard::enforce();
    let kp = faucet_pq_keypair();
    let to = [0xABu8; 32];
    let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    let tx = sign_pq_explicit_transfer(&kp, to, 1_000_000_000, gas, 0, 0, 0);
    // The sender is the faucet's own PQ account: this tx spends genesis
    // funds, which is exactly what `wallet send-pq --falcon-seed` relies on.
    let faucet = Faucet::new([0x11u8; 32], 0, 10, 25);
    assert_eq!(
        tx.from,
        faucet.account(),
        "helper sender must equal the pure-PQ faucet account"
    );
    assert_eq!(tx.to, to);
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.gas_limit, gas, "activation surcharge must ride the tx");
    assert!(
        tx.is_pq(),
        "the tx must carry a PQ1 envelope, never bare ed"
    );
    let env = tx.pq_envelope().expect("PQ envelope decodes");
    assert_eq!(env.scheme, crate::post_quantum::PqScheme::Falcon512);
    assert!(
        !env.is_implicit,
        "always explicit: first spend needs no registry"
    );
    assert!(
        env.pubkey.is_some(),
        "explicit carrier must embed the pubkey"
    );
    assert!(
        tx.verify_signature(),
        "faucet-shaped PQ tx must verify under PURE_PQ"
    );
}

#[tokio::test]
async fn pq_explicit_transfer_matches_faucet_drip_shape() {
    // The refactor pin: `Faucet::build_transfer` must build the same tx
    // SHAPE the shared helper builds (same fields, same envelope, both
    // verify). Signatures legitimately differ: Falcon signing is
    // randomized (`test_falcon_nonces_never_repeat`), so byte-equality of
    // the sig is the wrong assertion — structural identity is the pin.
    let _guard = PurePqGuard::enforce();
    let seed = [0x11u8; 32];
    let faucet = Faucet::new(seed, 0, 10_000_000_000, 1_000_000_000_000);
    let who = [0xCDu8; 32];
    let (drip_tx, amount) = faucet
        .build_transfer(who, Some(1_000_000_000), None)
        .await
        .expect("first drip fits the cap");
    let kp = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
    let helper_tx = sign_pq_explicit_transfer(
        &kp,
        who,
        amount,
        crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
        0,
        0,
        0,
    );
    for (field, a, b) in [
        ("from", drip_tx.from.to_vec(), helper_tx.from.to_vec()),
        ("to", drip_tx.to.to_vec(), helper_tx.to.to_vec()),
    ] {
        assert_eq!(a, b, "field {field} must match");
    }
    assert_eq!(drip_tx.amount, helper_tx.amount);
    assert_eq!(drip_tx.gas_limit, helper_tx.gas_limit);
    assert_eq!(drip_tx.nonce, helper_tx.nonce);
    assert_eq!(drip_tx.source_shard, helper_tx.source_shard);
    assert_eq!(drip_tx.target_shard, helper_tx.target_shard);
    assert_eq!(drip_tx.payload.len(), helper_tx.payload.len());
    let drip_env = drip_tx.pq_envelope().expect("drip envelope decodes");
    let helper_env = helper_tx.pq_envelope().expect("helper envelope decodes");
    assert_eq!(drip_env.scheme, helper_env.scheme);
    assert_eq!(drip_env.is_implicit, helper_env.is_implicit);
    assert_eq!(drip_env.pubkey, helper_env.pubkey);
    assert!(drip_tx.verify_signature());
    assert!(helper_tx.verify_signature());
}

#[test]
fn ed_signed_transfer_is_refused_under_pure_pq() {
    let _guard = PurePqGuard::enforce();
    let ed = SigningKey::from_bytes(&[0x22u8; 32]);
    let tx = crate::sharding::Transaction::sign(&ed, [0xABu8; 32], 1_000, 1000, 0, 0, 0);
    assert!(
        !tx.verify_signature(),
        "legacy ed25519 txs must be refused when PURE_PQ is enforced"
    );
}

#[test]
fn tampered_pq_transfer_is_refused() {
    let _guard = PurePqGuard::enforce();
    let kp = faucet_pq_keypair();
    let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    let tx = sign_pq_explicit_transfer(&kp, [0xABu8; 32], 1_000_000_000, gas, 0, 0, 0);
    assert!(tx.verify_signature(), "baseline must verify");

    let mut bad_sig = tx.clone();
    let last = bad_sig.signature.len() - 1;
    bad_sig.signature[last] ^= 0x01;
    assert!(
        !bad_sig.verify_signature(),
        "a tampered PQ signature must be refused"
    );

    let mut bad_amt = tx.clone();
    bad_amt.amount += 1;
    assert!(
        !bad_amt.verify_signature(),
        "a tampered amount must be refused"
    );

    let mut bad_to = tx.clone();
    bad_to.to[0] ^= 0xFF;
    assert!(
        !bad_to.verify_signature(),
        "a tampered recipient must be refused"
    );
}

#[test]
fn cross_shard_pq_shape_verifies_under_pure_pq() {
    // The 2PC demo's first leg: source = masterchain, target = workchain 1.
    let _guard = PurePqGuard::enforce();
    let kp = faucet_pq_keypair();
    let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    let tx = sign_pq_explicit_transfer(&kp, [0xABu8; 32], 1_000_000_000, gas, 0, 0, 1);
    assert_eq!(tx.source_shard, 0);
    assert_eq!(tx.target_shard, 1);
    assert!(
        tx.verify_signature(),
        "cross-shard PQ tx must verify under PURE_PQ"
    );
}

#[test]
fn pq_explicit_transfer_admits_under_pure_pq() {
    // The one mempool gate the in-process e2e cannot cover (it must run
    // with pure-PQ off so the harness's ed votes verify): under
    // enforcement the pool REQUIRES a PQ envelope with a post-quantum
    // scheme. The `send-pq` shape passes; a bare ed tx is refused.
    let _guard = PurePqGuard::enforce();
    let kp = faucet_pq_keypair();
    let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    let tx = sign_pq_explicit_transfer(&kp, [0xABu8; 32], 1_000_000_000, gas, 0, 0, 0);
    let mut pool = crate::mempool::Mempool::default();
    let ctx = crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(0);
    assert!(
        pool.add_checked_ctx(tx, 1_000_000_000_000_000u64, ctx)
            .is_ok(),
        "faucet-shaped PQ tx must admit under PURE_PQ"
    );

    let ed = SigningKey::from_bytes(&[0x22u8; 32]);
    let ed_tx = crate::sharding::Transaction::sign(&ed, [0xABu8; 32], 1_000, 1000, 0, 0, 0);
    let mut pool2 = crate::mempool::Mempool::default();
    let ctx2 = crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(0);
    assert!(
        pool2
            .add_checked_ctx(ed_tx, 1_000_000_000_000_000u64, ctx2)
            .is_err(),
        "bare ed tx must NOT admit under PURE_PQ"
    );
}

#[tokio::test]
async fn faucet_refuses_without_a_token() {
    // The regression that matters: an unauthenticated caller must not be
    // able to draw from the treasury, and a *misconfigured* node (faucet on,
    // token unset) must fail closed rather than mint for anyone.
    let st = test_state_with_faucet(10, 25).await;
    let who = hex::encode([0x42u8; 32]);

    // No token at all.
    let r = call(&st, "stell_faucet", json!({ "address": who.clone() })).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "a tokenless faucet request must be refused: {r}"
    );
    // Wrong token.
    let r2 = call(
        &st,
        "stell_faucet",
        json!({ "address": who.clone(), "token": "guess" }),
    )
    .await;
    assert!(
        r2["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "a wrong token must be refused: {r2}"
    );
    // Neither attempt may have touched the mempool or the recipient.
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "no unsigned tx may be queued"
    );
    assert!(st.engine.get_account(&[0x42u8; 32]).await.is_none());

    // And with the right token it works, so this is auth and not a freeze.
    let ok2 = call(&st, "stell_faucet", drip_req(&who)).await;
    assert_eq!(ok2["credited_nano"], "10");
}

#[tokio::test]
async fn enabled_faucet_without_a_configured_token_fails_closed() {
    // Same helper, but the operator forgot STELL_FAUCET_TOKEN. Dispensing
    // must be impossible, not silently open.
    let st = test_state_with_untokened_faucet(10, 25).await;
    let r = call(&st, "stell_faucet", drip_req(&hex::encode([0x42u8; 32]))).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("refusing to dispense"),
        "a faucet with no token must refuse even a well-formed request: {r}"
    );
    assert_eq!(st.mempool.read().await.len(), 0);
}

#[tokio::test]
async fn faucet_rejects_malformed_address() {
    let st = test_state_with_faucet(10, 25).await;
    let r = call(
        &st,
        "stell_faucet",
        json!({ "address": "zz", "token": FAUCET_TOKEN }),
    )
    .await;
    assert!(r["error"].is_string());
    let r2 = call(&st, "stell_faucet", json!({ "token": FAUCET_TOKEN })).await;
    assert!(r2["error"].is_string());
}

/// Sharded faucet harness: the faucet serves `shard`, the engine runs
/// that shard, the registry is `{0, 1}` (sharded), and the faucet account
/// is genesis-funded — mirroring a sharded testnet node.
async fn test_state_with_faucet_on_shard(drip: u64, cap: u64, shard: ShardId) -> Arc<RpcState> {
    let key_seed = [0x11u8; 32];
    // FULL-PQ: the faucet account is the Falcon-512 address derived from
    // the seed (Faucet::account); fund that address, never a classical one.
    // Funded for the PQ drip cost (amount + gas + activation surcharge,
    // reserved jointly per pooled tx) across a full lifetime-cap burst.
    let faucet_addr = {
        let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pq_key.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        )
    };
    let st = test_state().await;
    st.engine.set_shard_id(shard);
    st.engine
        .update_account(AccountState::new(faucet_addr, 100_000_000))
        .await;
    Arc::new(RpcState {
        faucet: Some(Arc::new(Faucet::new(key_seed, shard, drip, cap))),
        faucet_token: Some(FAUCET_TOKEN.to_string()),
        msg_signing_seed: None,
        engine: st.engine.clone(),
        mempool: st.mempool.clone(),
        height: st.height.clone(),
        node_id: st.node_id.clone(),
        chain_id: st.chain_id,
        staking: st.staking.clone(),
        governance: st.governance.clone(),
        recent_blocks: st.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: st.auth_token.clone(),
        tx_broadcast: st.tx_broadcast.clone(),
        archive_store: None,
        shard_registry: ShardRegistry::from_ids([0, 1]),
    })
}

/// A drip to a masterchain (`-1:`) account is a same-shard transfer on
/// shard 0 and finalizes there: the recipient is credited through the
/// shared `apply_block_transition` core (the live consensus path).
#[tokio::test]
async fn faucet_masterchain_drip_finalizes_on_shard_0() {
    let st = test_state_with_faucet_on_shard(10, 100, 0).await;
    let who = [0x42u8; 32];
    let r = call(
        &st,
        "stell_faucet",
        drip_req(&format!("-1:{}", hex::encode(who))),
    )
    .await;
    assert_eq!(
        r["credited_nano"], "10",
        "masterchain drip must be served: {r}"
    );
    assert_eq!(r["shard"], 0);
    {
        let pool = st.mempool.read().await;
        assert_eq!(pool.len(), 1);
        let tx = &pool.all()[0];
        assert_eq!(tx.to, who);
        assert_eq!(
            tx.source_shard, 0,
            "drip must execute where the recipient lives"
        );
        assert_eq!(tx.target_shard, 0);
        assert_eq!(tx.nonce, 0);
        assert!(tx.verify_signature(), "drip must carry a valid signature");
    }
    let block = crate::sharding::Block {
        shard_id: 0,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: st.mempool.read().await.all().to_vec(),
        cross_shard_out: vec![],
        timestamp: 1_700_000_000,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    let outcome = st.engine.apply_block_transition(&block, 0).await;
    assert_eq!(outcome.applied, 1, "the drip must apply on shard 0");
    assert_eq!(outcome.failed, 0);
    let acc = st
        .engine
        .get_account(&who)
        .await
        .expect("recipient must exist");
    assert_eq!(acc.balance, 10, "recipient must be credited the drip");
}

/// A drip to a workchain (bare) account is a same-shard transfer on the
/// shard the routing rule selects and finalizes there.
#[tokio::test]
async fn faucet_workchain_drip_finalizes_on_its_shard() {
    let st = test_state_with_faucet_on_shard(10, 100, 1).await;
    let who = [0x43u8; 32];
    let r = call(&st, "stell_faucet", drip_req(&hex::encode(who))).await;
    assert_eq!(
        r["credited_nano"], "10",
        "workchain drip must be served: {r}"
    );
    assert_eq!(
        r["shard"], 1,
        "bare address must route to the workchain shard: {r}"
    );
    {
        let pool = st.mempool.read().await;
        assert_eq!(pool.len(), 1);
        let tx = &pool.all()[0];
        assert_eq!(tx.to, who);
        assert_eq!(
            tx.source_shard, 1,
            "drip must execute where the recipient lives"
        );
        assert_eq!(tx.target_shard, 1);
    }
    let block = crate::sharding::Block {
        shard_id: 1,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: st.mempool.read().await.all().to_vec(),
        cross_shard_out: vec![],
        timestamp: 1_700_000_000,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    let outcome = st.engine.apply_block_transition(&block, 0).await;
    assert_eq!(outcome.applied, 1, "the drip must apply on shard 1");
    let acc = st
        .engine
        .get_account(&who)
        .await
        .expect("recipient must exist");
    assert_eq!(acc.balance, 10, "recipient must be credited the drip");
}

/// A drip that would be shard-filtered is refused AT ADMISSION with a
/// clear error — never queued — and the refusal burns no nonce: the next
/// servable drip keeps the exact nonce sequence as if the refusal never
/// happened (the live failure mode was stuck nonces 4,5,6 on source=1 for
/// masterchain recipients).
#[tokio::test]
async fn faucet_refuses_shard_mismatched_drip_without_burning_nonce() {
    // Faucet serves shard 0 (masterchain); the bare address routes to
    // shard 1 under the documented rule.
    let st = test_state_with_faucet_on_shard(10, 100, 0).await;
    let faucet = st.faucet.clone().expect("faucet enabled");
    let r = call(&st, "stell_faucet", drip_req(&hex::encode([0x42u8; 32]))).await;
    let err = r["error"]
        .as_str()
        .expect("shard-mismatched drip must be refused");
    assert!(
        err.contains("shard 1") && err.contains("shard 0"),
        "refusal must name both shards, not just fail: {err}"
    );
    // Nothing queued, nothing reserved, nonce untouched.
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "refused drip must not pend"
    );
    assert_eq!(faucet.dispensed_to([0x42u8; 32]).await, 0);
    // The next servable drips take nonces 0 and 1 — the refusal burned none.
    let ok = call(
        &st,
        "stell_faucet",
        drip_req(&format!("-1:{}", hex::encode([0x42u8; 32]))),
    )
    .await;
    assert_eq!(ok["credited_nano"], "10", "{ok}");
    let ok2 = call(
        &st,
        "stell_faucet",
        drip_req(&format!("-1:{}", hex::encode([0x44u8; 32]))),
    )
    .await;
    assert_eq!(ok2["credited_nano"], "10", "{ok2}");
    let mut nonces: Vec<u64> = st
        .mempool
        .read()
        .await
        .all()
        .iter()
        .map(|t| t.nonce)
        .collect();
    nonces.sort_unstable();
    assert_eq!(nonces, vec![0, 1], "refused drip must not burn a nonce");
}

/// VERIFICATION W10.2-hardening: the recipient-shard admission rule must
/// refuse a cross-shard drip BEFORE any nonce/cap reservation, and the
/// `-1:`/`0:` workchain prefixes must route exactly like the rule says.
///
/// Stronger than the existing refusal test: it pins the prefix matrix
/// directly against `resolve_faucet_recipient` —
/// * a `-1:`-prefixed address on a shard-0 faucet is ADMITTED (it IS the
///   masterchain form, not a bypass);
/// * a `0:`-prefixed address behaves identically (same shard, no alias);
/// * the SAME `-1:` address against a shard-1 faucet is REFUSED (the
///   prefix cannot smuggle a masterchain recipient onto a workchain
///   faucet, and vice versa);
/// * and the full RPC path still admits no mempool entry and burns no
///   nonce for the refused shape.
#[tokio::test]
async fn faucet_prefix_matrix_routes_before_nonce_reservation() {
    let st0 = test_state_with_faucet_on_shard(10, 100, 0).await;
    let faucet0 = st0.faucet.clone().expect("faucet enabled");
    let addr = hex::encode([0x42u8; 32]);
    // `-1:` names the masterchain: admitted on the shard-0 faucet.
    let (a, s) = resolve_faucet_recipient(&st0, &faucet0, &format!("-1:{addr}"))
        .await
        .expect("masterchain form must be servable by the shard-0 faucet");
    assert_eq!((a, s), ([0x42u8; 32], 0));
    // `0:` is the same shard, no alias, no bypass.
    let (a0, s0) = resolve_faucet_recipient(&st0, &faucet0, &format!("0:{addr}"))
        .await
        .expect("0: form must behave like -1:");
    assert_eq!((a0, s0), ([0x42u8; 32], 0));
    // Same `-1:` address against a shard-1 faucet: refused, not queued.
    let st1 = test_state_with_faucet_on_shard(10, 100, 1).await;
    let faucet1 = st1.faucet.clone().expect("faucet enabled");
    let err = resolve_faucet_recipient(&st1, &faucet1, &format!("-1:{addr}"))
        .await
        .expect_err("a masterchain recipient must be refused by the shard-1 faucet");
    assert!(err.contains("shard 1") && err.contains("shard 0"), "{err}");
    // Full RPC path: the refused shape reserves nothing.
    let r = call(&st1, "stell_faucet", drip_req(&format!("-1:{addr}"))).await;
    assert!(r["error"].is_string(), "refused drip must error: {r}");
    assert_eq!(
        st1.mempool.read().await.len(),
        0,
        "refused drip must not pend"
    );
    assert_eq!(faucet1.dispensed_to([0x42u8; 32]).await, 0);
    // ...while the servable shape on the matching faucet still works.
    let ok = call(&st0, "stell_faucet", drip_req(&format!("-1:{addr}"))).await;
    assert_eq!(ok["credited_nano"], "10", "{ok}");
    assert_eq!(ok["shard"], 0);
}

#[tokio::test]
async fn balance_query() {
    let st = test_state().await;
    let who = [3u8; 32];
    st.engine.update_account(AccountState::new(who, 5000)).await;
    let r = call(&st, "stell_getBalance", json!(hex::encode(who))).await;
    assert_eq!(r["balance"], "5000");
}

#[tokio::test]
async fn unknown_method_is_error() {
    let st = test_state().await;
    let r = call(&st, "does_not_exist", json!({})).await;
    assert!(r["error"].as_str().unwrap().contains("method not found"));
}

#[tokio::test]
async fn send_raw_transaction_valid_and_forged() {
    let st = test_state().await;
    // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
    let tx = pq_tx(0xB1, [1u8; 32], 10, 5, 0);
    // fund the sender so the balance check at admission passes
    st.engine
        .update_account(AccountState::new(tx.from, 1_000_000))
        .await;
    let raw = hex::encode(bincode::serialize(&tx).unwrap());
    let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
    assert!(r.as_str().is_some(), "valid tx must be accepted: {r}");
    assert_eq!(st.mempool.read().await.len(), 1);

    // forged signature must be rejected (tamper the trailing signature
    // bytes so the PQ envelope still parses and the verdict is the
    // signature failure, not a decode refusal).
    let mut bad = tx.clone();
    let last = bad.signature.len() - 1;
    bad.signature[last] ^= 0xFF;
    let raw_bad = hex::encode(bincode::serialize(&bad).unwrap());
    let r2 = call(&st, "stell_sendRawTransaction", json!({ "tx": raw_bad })).await;
    assert!(r2["error"].as_str().unwrap().contains("signature"));
    assert_eq!(
        st.mempool.read().await.len(),
        1,
        "forged tx must not enter mempool"
    );
}

/// A14 phase 1: an UNBOUND admission is still accepted, but it is
/// metered (`stell_unbound_tx_total` +1); a BOUND admission is silent
/// (meter untouched). The diff-based assertion is parallel-safe: the
/// global counter moves under every test admitting unbound txs, but
/// each test's own admissions add exactly their own count.
#[tokio::test]
async fn unbound_admission_is_metered_and_bound_is_silent() {
    let st = test_state().await;
    let local = crate::metrics::Registry::new();
    let meter = || crate::metrics::global().snapshot().unbound_tx as u64;

    // UNBOUND: admitted, metered. FULL-PQ: implicit Falcon-512, no chain.
    let tx = pq_tx(0xB2, [1u8; 32], 10, 100_000, 0);
    assert!(tx.chain_id().is_none(), "unbound PQ envelope has no chain");
    note_unbound_admission_into(&tx, &local);
    assert_eq!(
        local.snapshot().unbound_tx as u64,
        1,
        "one unbound admission meters exactly once"
    );
    st.engine
        .update_account(AccountState::new(tx.from, 10_000_000))
        .await;
    let before = meter();
    let raw = hex::encode(bincode::serialize(&tx).unwrap());
    let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
    assert!(r.as_str().is_some(), "phase 1 still admits unbound: {r}");
    assert!(
        meter() > before,
        "one unbound admission must increment global meter"
    );

    // BOUND (PQ chain envelope): admitted, meter silent.
    // FULL-PQ: implicit Falcon-512 bound to the consensus chain id.
    let bound = pq_tx_chain(0xB3, [1u8; 32], 10, 100_000, 0, Some(5757));
    assert_eq!(bound.chain_id(), Some(5757));
    note_unbound_admission_into(&bound, &local);
    assert_eq!(
        local.snapshot().unbound_tx as u64,
        1,
        "bound admission must not touch the meter"
    );
    st.engine
        .update_account(AccountState::new(bound.from, 10_000_000))
        .await;
    let raw2 = hex::encode(bincode::serialize(&bound).unwrap());
    let r2 = call(&st, "stell_sendRawTransaction", json!({ "tx": raw2 })).await;
    assert!(r2.as_str().is_some(), "bound txs admit cleanly: {r2}");
}

/// E1 confirmations rule: inclusion at height H under head N reports
/// N - H + 1 on both `stell_getTransactionStatus` and
/// `stell_getTransactionReceipt`; mempool-pending reports 0 on status;
/// unknown reports null.
#[tokio::test]
async fn status_and_receipt_report_confirmations() {
    let st = test_state().await;
    let tx = receipt_tx(0x09, 0);
    let h = hex::encode(tx.compute_tx_hash());

    // Unknown: null confirmations.
    let unknown = call(&st, "stell_getTransactionStatus", json!(h)).await;
    assert_eq!(unknown["status"], json!("unknown"));
    assert!(
        unknown["confirmations"].is_null(),
        "unknown has no depth: {unknown}"
    );

    // Pending: 0 confirmations.
    st.mempool.write().await.add(tx.clone()).unwrap();
    let pending = call(&st, "stell_getTransactionStatus", json!(h)).await;
    assert_eq!(pending["status"], json!("pending"));
    assert_eq!(pending["confirmations"], json!(0));

    // Included at 5, head at 7 -> 3 confirmations, on both methods.
    st.record_receipts(5, [0x01; 32], std::slice::from_ref(&tx), &[true], &[1])
        .await;
    st.height.store(7, std::sync::atomic::Ordering::Relaxed);
    let done = call(&st, "stell_getTransactionStatus", json!(h)).await;
    assert_eq!(done["status"], json!("success"));
    assert_eq!(done["height"], json!(5));
    assert_eq!(done["confirmations"], json!(3), "7 - 5 + 1");
    let receipt = call(&st, "stell_getTransactionReceipt", json!(h)).await;
    assert_eq!(receipt["status"], json!("success"));
    assert_eq!(receipt["confirmations"], json!(3), "7 - 5 + 1");

    // Head advances -> depth grows.
    st.height.store(10, std::sync::atomic::Ordering::Relaxed);
    let deeper = call(&st, "stell_getTransactionStatus", json!(h)).await;
    assert_eq!(deeper["confirmations"], json!(6), "10 - 5 + 1");
}

#[tokio::test]
async fn send_raw_transaction_forwards_to_gossip_channel() {
    let base = test_state().await;
    let (tx_out, mut tx_rx) = tokio::sync::mpsc::unbounded_channel();
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: Some(tx_out),
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
    let tx = pq_tx(0xB4, [1u8; 32], 10, 5, 0);
    st.engine
        .update_account(AccountState::new(tx.from, 1_000_000))
        .await;
    let raw = hex::encode(bincode::serialize(&tx).unwrap());

    let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
    assert!(r.as_str().is_some());

    // Must have been forwarded to the P2P gossip channel:
    let forwarded = tx_rx.try_recv().expect("must receive forwarded tx");
    assert_eq!(forwarded.amount, 10);
    // FULL-PQ sender: the PQ address derived from the test seed.
    let (want_from, _) = {
        let pk = crate::sharding::Transaction::sample_falcon512_pubkey(0xB4);
        (
            crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            ),
            pk,
        )
    };
    assert_eq!(forwarded.from, want_from);
}

/// Phase-2 EVM settlement: `eth_sendRawTransaction` admits the mapped
/// consensus transaction to the REAL mempool (not just the intent pool),
/// so the tx reaches block production. Strict chain_id/low-s/ecrecover
/// plus nonce/balance gating through the `evm_to_stell` mapping.
#[tokio::test]
async fn eth_send_raw_transaction_settles_into_mempool() {
    use crate::evm_adapter::{
        evm_to_stell_address, pubkey_to_address, wei_to_nano, LegacyTransaction, CHAIN_ID,
    };

    fn secp_key() -> k256::ecdsa::SigningKey {
        let bytes = hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
        k256::ecdsa::SigningKey::from_slice(&bytes).unwrap()
    }

    // Sign a legacy EIP-155 tx on chain 5757 (low-s normalized).
    fn sign_raw(nonce: u64, value_wei: u128) -> Vec<u8> {
        let key = secp_key();
        let unsigned = LegacyTransaction {
            nonce,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([0x35u8; 20]),
            value: value_wei,
            data: Vec::new(),
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
            chain_id: Some(CHAIN_ID),
        };
        let sighash = unsigned.signing_hash();
        let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.to_bytes()[0..32]);
        s.copy_from_slice(&sig.to_bytes()[32..64]);
        let (s, recid_b) = if crate::evm_adapter::is_low_s(&s) {
            (s, recid.to_byte())
        } else {
            // N - s, flip recovery bit (same normalization the
            // settlement builder applies).
            let n = crate::evm_adapter::SECP256K1_N;
            let mut out = [0u8; 32];
            let mut borrow: i32 = 0;
            for i in (0..32).rev() {
                let v = n[i] as i32 - s[i] as i32 - borrow;
                if v < 0 {
                    out[i] = (v + 256) as u8;
                    borrow = 1;
                } else {
                    out[i] = v as u8;
                    borrow = 0;
                }
            }
            (out, recid.to_byte() ^ 1)
        };
        LegacyTransaction {
            v: CHAIN_ID * 2 + 35 + recid_b as u64,
            r,
            s,
            ..unsigned
        }
        .encode()
    }

    let key = secp_key();
    let sender20 =
        pubkey_to_address(key.verifying_key().to_encoded_point(false).as_bytes()).unwrap();
    let sender32 = evm_to_stell_address(&sender20);
    let value_wei: u128 = 1_000_000_000_000_000_000;

    let st = test_state().await;
    st.engine
        .update_account(AccountState::new(
            sender32,
            wei_to_nano(value_wei) + 1_000_000,
        ))
        .await;

    // 1. FULL-PQ: the EVM settlement shape carries no PQ envelope, so
    // even a funded EVM tx is refused at admission (EVM settlement is
    // excised from the PQ-only intake path).
    let raw = hex::encode(sign_raw(0, value_wei));
    let r = call(&st, "eth_sendRawTransaction", json!([format!("0x{raw}")])).await;
    assert!(
        r.get("error").is_some(),
        "EVM tx must be refused in FULL-PQ mode: {r}"
    );
    assert_eq!(st.mempool.read().await.len(), 0);

    // 2. Wrong chain (chain-1 vector) is rejected, pool unchanged.
    let chain1 = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let r2 = call(
        &st,
        "eth_sendRawTransaction",
        json!([format!("0x{chain1}")]),
    )
    .await;
    assert!(
        r2.get("error").is_some(),
        "foreign chain must be rejected: {r2}"
    );
    assert_eq!(st.mempool.read().await.len(), 0);

    // 3. Unfunded sender is rejected by the balance gate, pool unchanged.
    let st_broke = test_state().await;
    let r3 = call(
        &st_broke,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(sign_raw(0, value_wei)))]),
    )
    .await;
    assert!(
        r3.get("error").is_some(),
        "unfunded EVM tx must be rejected: {r3}"
    );
    assert_eq!(st_broke.mempool.read().await.len(), 0);
}

#[tokio::test]
async fn write_methods_require_auth_token() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
    let tx = pq_tx(0xB5, [1u8; 32], 10, 5, 0);
    st.engine
        .update_account(AccountState::new(tx.from, 1_000_000))
        .await;
    let raw = hex::encode(bincode::serialize(&tx).unwrap());

    let r = call(
        &st,
        "stell_sendRawTransaction",
        json!({ "tx": raw.clone() }),
    )
    .await;
    assert!(
        r.as_str().is_some(),
        "public signed transaction must succeed without auth token"
    );

    // Admin methods like mempool dump still require the token
    let r_dump = call(&st, "stell_mempoolDump", json!({})).await;
    assert!(r_dump["error"].as_str().unwrap().contains("unauthorized"));
    let r_dump2 = call(&st, "stell_mempoolDump", json!({ "token": "secret" })).await;
    assert!(r_dump2.as_array().is_some(), "authorized dump must succeed");
}

/// P5 EXPLOIT (Critical, rpc.rs `stell_deployContract` /
/// `stell_callContract`): both arms wrote consensus state DIRECTLY over an
/// unauthenticated RPC — `deploy_contract_deterministic` minted a contract
/// into the engine, and `stell_callContract` ran `debit_native` /
/// `credit_native` + executed the call inline, bypassing mempool
/// admission, nonces and blocks entirely — with NO `auth_token` gate, while
/// every sibling write arm (`stell_submitProposal`, `stell_vote`,
/// `stell_submitPriceFeed`, `stell_pmmBuy/Sell`, `stell_signMessage`)
/// required one. An unauthenticated caller minted contracts and moved
/// native value whenever a token was configured. Fixed by gating both arms
/// with the same token check (fail-open when unconfigured, like the rest).
#[tokio::test]
async fn p5_contract_arms_require_auth_token_when_configured() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    // No token: must be refused as unauthorized (pre-fix: fell through to
    // "missing 'code' parameter" / "missing 'contract' parameter", i.e. no
    // gate at all).
    let r_deploy = call(&st, "stell_deployContract", json!({})).await;
    assert!(
        r_deploy["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "deploy without token must be refused: {r_deploy}"
    );
    let r_call = call(&st, "stell_callContract", json!({})).await;
    assert!(
        r_call["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "call without token must be refused: {r_call}"
    );
    // Wrong token: same refusal (constant-time comparison, no oracle).
    let r_bad = call(&st, "stell_deployContract", json!({ "token": "nope" })).await;
    assert!(
        r_bad["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "deploy with wrong token must be refused: {r_bad}"
    );
    // Correct token: passes the gate (fails later on params, not on auth).
    let r_ok = call(&st, "stell_deployContract", json!({ "token": "secret" })).await;
    assert!(
        !r_ok["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "deploy with correct token must pass the gate: {r_ok}"
    );
}

/// N-02/N-03: contract previews require a valid token ALWAYS (no token
/// configured at all is refused, on every bind), and a successful preview
/// NEVER enters the mempool — it executes on a state clone, returns the
/// result, and the tx is dropped. On-chain execution needs a separate
/// `stell_sendRawTransaction` submission of a locally-signed tx.
/// // GATE: N-02 token-always + N-03 preview mempool-DoS fix.
#[tokio::test]
async fn contract_previews_require_token_and_never_enter_mempool() {
    // 1. No token configured at all: both preview arms refuse (even the
    // keyless direct-params form), and nothing is pooled.
    let st = test_state().await;
    for (method, params) in [
        (
            "stell_deployContract",
            json!({ "code": hex::encode(sample_getter_wasm()) }),
        ),
        (
            "stell_callContract",
            json!({
                "contract": hex::encode([0x99u8; 32]),
                "method": "get",
                "value": 0u64,
            }),
        ),
    ] {
        let r = call(&st, method, params).await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "{method} with no token configured must be refused: {r}"
        );
    }
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "refused previews must not pool anything"
    );
    assert!(
        st.governance.read().await.proposals.is_empty(),
        "refused calls must not record anything"
    );

    // 2. Token configured + presented: previews succeed AND still pool
    // nothing. Fixture contract deployed engine-side (the way block
    // application materializes it).
    let st = test_state_with_token().await;
    let creator = [0xABu8; 32];
    let deployed = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();
    let root_before = st.engine.get_state_root().await;

    let deploy = call_with_token(
        &st,
        "stell_deployContract",
        json!({ "code": hex::encode(sample_getter_wasm()) }),
    )
    .await;
    // F6: the direct deploy form carries no signer, so it predicts NO address
    // (and no transaction hash) instead of a phantom from a random key.
    assert!(
        deploy["contract_address"].is_null(),
        "sender-less deploy preview must predict no address: {deploy}"
    );
    assert_eq!(
        deploy["deployed"],
        json!(false),
        "a deploy preview deploys nothing: {deploy}"
    );
    assert!(
        deploy["tx_hash"].is_null(),
        "no transaction is built (or hashed) for the direct form: {deploy}"
    );

    let previewed = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": hex::encode(deployed),
            "method": "double",
            "args": 21,
            // F3: a preview executes as an explicit caller, never as 0x00..
            "caller": format!("0x{}", hex::encode([0xABu8; 32])),
        }),
    )
    .await;
    assert_eq!(previewed["status"], json!("success"));
    assert_eq!(previewed["return_value"], json!(42));

    // The mempool is STILL empty (both previews dropped their txs) and
    // the state root is untouched (clone-only execution).
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "successful previews must never enter the mempool"
    );
    assert_eq!(
        st.engine.get_state_root().await,
        root_before,
        "previews must not move the state root"
    );

    // 3. Wrong token: same refusal, nothing pooled.
    let st2 = test_state_with_token().await;
    let r = call(
        &st2,
        "stell_callContract",
        json!({
            "contract": hex::encode(deployed),
            "method": "double",
            "args": 21,
            "token": "wrong",
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "wrong-token preview must be refused: {r}"
    );
    assert_eq!(st2.mempool.read().await.len(), 0);
}

/// H-03/H-04 (rpc.rs `stell_callContract` / `stell_deployContract`):
/// the old `from` + `private_key` pair let a caller debit ANY account
/// (`from=victim + private_key=attacker + value=N` drained the victim
/// straight into the contract, even when the call itself failed). The
/// whole key-accepting shape is gone: `private_key` is refused
/// fail-closed on both arms, `from` is refused too (without a key the
/// node cannot sign as the caller, so honoring it is impossible), and
/// the arms never debit — previews simulate `value` on a clone.
#[tokio::test]
async fn p5_call_contract_rejects_key_material_and_spoofed_sender() {
    // N-02: previews require a token on every bind, so the key-material
    // pins run on the token fixture (the gate passes, then the
    // no-key-material checks fire).
    let st = test_state_with_token().await;
    let victim = SigningKey::from_bytes(&[0x51u8; 32]);
    let victim_addr = victim.verifying_key().to_bytes();
    st.engine
        .update_account(AccountState::new(victim_addr, 1_000_000))
        .await;
    let attacker = SigningKey::from_bytes(&[0xA7u8; 32]);
    let contract = [0x99u8; 32];
    let before = st
        .engine
        .get_account(&victim_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(before, 1_000_000);
    // `private_key` is refused on the call arm (it used to select the
    // debit victim's fate via `from` + attacker key).
    let r = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": hex::encode(contract),
            "method": "get",
            "from": hex::encode(victim_addr),
            "private_key": hex::encode(attacker.to_bytes()),
            "value": 500u64,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no longer accepted"),
        "key material over RPC must be refused: {r}"
    );
    // `from` alone is refused too: without a key it cannot be honored.
    let r_from = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": hex::encode(contract),
            "method": "get",
            "from": hex::encode(victim_addr),
            "value": 500u64,
        }),
    )
    .await;
    assert!(
        r_from["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no longer accepted"),
        "spoofable sender must be refused: {r_from}"
    );
    // And on the deploy arm.
    let r_deploy = call_with_token(
        &st,
        "stell_deployContract",
        json!({
            "code": hex::encode(counter_getter_wasm()),
            "private_key": hex::encode(attacker.to_bytes()),
        }),
    )
    .await;
    assert!(
        r_deploy["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no longer accepted"),
        "deploy must refuse key material: {r_deploy}"
    );
    let after = st
        .engine
        .get_account(&victim_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(
        after, before,
        "victim balance must be untouched by the refused calls"
    );
    // Sanity: the keyless preview is still admitted past the key checks
    // (it fails later on the unknown contract — a clone-exec failure,
    // never a signer error — and files nothing that moves value).
    let r_self = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": hex::encode(contract),
            "method": "get",
            "value": 0u64,
            "caller": hex::encode(victim_addr),
        }),
    )
    .await;
    assert!(
        !r_self["error"].is_string(),
        "keyless preview must pass the key checks: {r_self}"
    );
    assert_eq!(r_self["status"], json!("failed"));
    assert!(
        r_self["outcome"]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not found"),
        "unknown contract must fail in preview: {r_self}"
    );
}

/// P5 EXPLOIT (Critical, rpc.rs `stell_deployContract` wrapped-tx path):
/// the `{tx}` branch decoded the tx, deployed it as `tx.from` and admitted
/// it to the mempool WITHOUT `verify_signature` — a forged `from` (bytes
/// flipped after signing) deployed a contract AS THE VICTIM. Fixed by
/// verifying the signature exactly like `stell_sendRawTransaction`.
#[tokio::test]
async fn p5_wrapped_deploy_rejects_forged_signature() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    let (victim_addr, _) = pq_pair(0xC1);
    st.engine
        .update_account(AccountState::new(victim_addr, 1_000_000))
        .await;
    let code = wat::parse_str(
        r#"(module (memory 1) (func (export "get") (param i64) (result i64) (local.get 0)))"#,
    )
    .expect("test wat compiles");
    // FULL-PQ: implicit Falcon-512 deploy vehicle.
    let mut forged = pq_tx_payload(
        0xC1,
        victim_addr,
        0,
        10_000,
        0,
        vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
    );
    // Flip the claimed sender AFTER signing: the bytes no longer match the
    // signature. Pre-fix this deployed as [0x52; 32] with no complaint.
    forged.from = [0x52u8; 32];
    let raw = hex::encode(bincode::serialize(&forged).unwrap());
    let r = call(
        &st,
        "stell_deployContract",
        json!({ "tx": raw, "token": "secret" }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("signature"),
        "forged wrapped deploy must fail signature verification: {r}"
    );
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "forged deploy must not land in the mempool"
    );
}

/// A feed submission is a WRITE-shaped method: same token gate as
/// `stell_sendRawTransaction`, and it is THIN - it admits the wrapping
/// transaction to the mempool and must not touch consensus state. The
/// price only exists once a block carries it.
/// FULL-PQ: classical ed25519 feed verification is REMOVED (no PQ feed
/// path exists in this zone; `PriceFeedUpdate::verify` is always false),
/// so even a well-formed classical feed is refused fail-closed. The
/// token gate still fires first, and the refusal still writes nothing.
#[tokio::test]
async fn submit_price_feed_admits_without_writing_state_and_requires_token() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    // FULL-PQ: the wrapping tx is implicit Falcon-512; the feed itself
    // stays publisher-signed (oracle path, outside tx admission).
    let (from, _) = pq_pair(0xC2);
    st.engine
        .update_account(AccountState::new(from, 1_000_000))
        .await;
    let publisher = SigningKey::from_bytes(&[0x42u8; 32]);
    let feed = crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
    let tx = pq_tx_payload(
        0xC2,
        from,
        0,
        10_000,
        0,
        vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
    );
    let raw = hex::encode(bincode::serialize(&tx).unwrap());

    // Gated by the SAME token as sendRawTransaction.
    let denied = call(&st, "stell_submitPriceFeed", json!({ "tx": raw.clone() })).await;
    assert!(denied["error"].as_str().unwrap().contains("unauthorized"));
    let denied2 = call(
        &st,
        "stell_submitPriceFeed",
        json!({ "tx": raw.clone(), "token": "nope" }),
    )
    .await;
    assert!(denied2["error"].as_str().unwrap().contains("unauthorized"));

    // Thin: admitted, gossiped, and NOT written into state.
    // FULL-PQ: the classical feed never verifies, so the authorized
    // submission is refused fail-closed (nothing admitted, nothing
    // written) — the THIN half of the property survives.
    let root_before = st.engine.get_state_root().await;
    let ok = call(
        &st,
        "stell_submitPriceFeed",
        json!({ "tx": raw.clone(), "token": "secret" }),
    )
    .await;
    assert!(
        ok["error"]
            .as_str()
            .unwrap_or_default()
            .contains("validly signed price feed"),
        "FULL-PQ: classical feed must be refused fail-closed: {ok}"
    );
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "refused feed must not enter the mempool"
    );
    assert_eq!(
        st.engine.get_state_root().await,
        root_before,
        "submitting a feed must NOT write consensus state"
    );
    assert!(
        st.engine.oracle_read().await.feeds.is_empty(),
        "no price may exist before a block carries the feed"
    );

    // Only a payload that actually carries a signed feed may use this method.
    let plain = pq_tx(0xC2, from, 1, 1_000, 1);
    let wrong = call(
        &st,
        "stell_submitPriceFeed",
        json!({ "tx": hex::encode(bincode::serialize(&plain).unwrap()), "token": "secret" }),
    )
    .await;
    assert!(
        wrong["error"].as_str().unwrap().contains("price feed"),
        "a non-feed transaction must not be admitted under this method: {wrong}"
    );

    // And a feed whose SIGNATURE does not check out is refused the same way.
    // FULL-PQ: swapping the payload after the wrapper was signed breaks
    // the WRAPPER signature, so the wrapper check fires first — still a
    // refusal with nothing pooled.
    let mut tampered = tx.clone();
    tampered.payload = vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(
        crate::oracle::PriceFeedUpdate::sign("STELL", 1, 1_700_000_000, &publisher),
    ))];
    let bad = call(
        &st,
        "stell_submitPriceFeed",
        json!({ "tx": hex::encode(bincode::serialize(&tampered).unwrap()), "token": "secret" }),
    )
    .await;
    assert!(
        bad["error"].as_str().unwrap().contains("signature"),
        "a payload swapped after signing must fail verification: {bad}"
    );
    assert_eq!(st.mempool.read().await.len(), 0, "nothing else got in");
}

/// Nonce-gap fail-fast must cover the shared `stell_submit*` admission
/// helper too (audit: blocks troubles): a far-future nonce via
/// `stell_submitPriceFeed` is refused exactly like via
/// `stell_sendRawTransaction`, instead of clogging the pool behind an
/// unreachable head.
/// FULL-PQ: no classical feed verifies (no PQ feed path in this zone),
/// so the signed-feed gate fires BEFORE the nonce-gap check — the gapped
/// wrapper is refused as an unsigned feed, still with nothing pooled.
/// Nonce-gap ordering itself stays pinned at the mempool choke point
/// (`nonce_gap_rejects_far_future_at_admission`).
#[tokio::test]
async fn submit_price_feed_rejects_far_future_nonce() {
    let st = test_state().await;
    // FULL-PQ: implicit Falcon-512 wrapper; feed stays publisher-signed.
    let (from, _) = pq_pair(0xC3);
    st.engine
        .update_account(AccountState::new(from, 1_000_000))
        .await;
    let publisher = SigningKey::from_bytes(&[0x42u8; 32]);
    let feed = crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
    let gapped = pq_tx_payload(
        0xC3,
        from,
        0,
        10_000,
        crate::mempool::Mempool::NONCE_FUTURE_WINDOW + 5,
        vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
    );
    let r = call(
        &st,
        "stell_submitPriceFeed",
        json!({ "tx": hex::encode(bincode::serialize(&gapped).unwrap()) }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("validly signed price feed"),
        "far-future-nonce payload tx must be refused: {r}"
    );
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "gapped tx must not enter mempool"
    );
}

#[tokio::test]
async fn mempool_dump_requires_auth_token() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    let r = call(&st, "stell_mempoolDump", json!({})).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "anonymous mempool dump must be refused: {r}"
    );
    let r2 = call(&st, "stell_mempoolDump", json!({ "token": "secret" })).await;
    assert!(r2.is_array(), "authorized dump must return the list: {r2}");

    // Fail-closed test: when auth_token is None, mempoolDump MUST refuse
    let st_no_token = test_state().await;
    let r_fail_closed = call(&st_no_token, "stell_mempoolDump", json!({})).await;
    assert!(
        r_fail_closed["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthorized"),
        "mempool dump must fail closed when auth_token is None: {r_fail_closed}"
    );
}

#[test]
fn constant_time_eq_behaves_like_equality() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(constant_time_eq("", ""));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "ab"));
    assert!(!constant_time_eq("ab", "abc"));
    assert!(!constant_time_eq("", "x"));
}

#[test]
fn parse_hash_and_addr_validate_length() {
    assert!(parse_hash("0x00").is_err());
    assert!(parse_hash("00").is_err());
    assert!(parse_addr("0x00").is_err());
    assert!(parse_addr("00").is_err());
    let good = hex::encode([7u8; 32]);
    assert_eq!(parse_hash(&good).unwrap(), [7u8; 32]);
    assert_eq!(parse_hash(&format!("0x{good}")).unwrap(), [7u8; 32]);
    assert_eq!(parse_addr(&good).unwrap(), [7u8; 32]);
    assert_eq!(parse_addr(&format!("0x{good}")).unwrap(), [7u8; 32]);
}

// ------------------------------------------------------------------
// `stell_getProof`
// ------------------------------------------------------------------

/// FULL-PQ anchoring QC for the light-client fixtures: a Falcon µQC
/// envelope (the green `qc_verification_*` idiom from the consensus
/// tests) plus the plain voter entry the light-client power pre-check
/// counts. The entry payload is inert metadata — the envelope is the
/// proof. Single-member set: the committee IS the validator.
fn pq_anchor_cert(
    val_id: [u8; 32],
    fk: &crate::post_quantum::FalconKeypair,
    validators: &crate::consensus::ValidatorSet,
    height: u64,
    block_hash: [u8; 32],
) -> crate::consensus::QuorumCertificate {
    use crate::consensus::{
        derive_sortition_committee, encode_pq_micro_envelope, micro_committee_size,
        vote_sign_bytes, PqMicroCertificate, QuorumCertificate, VoteKind, PQ_UQC_MARKER_ID,
    };
    let parent = [0u8; 32];
    let committee_size = micro_committee_size(validators.len());
    let committee = derive_sortition_committee(validators, height, 0, committee_size, &parent);
    let msg = vote_sign_bytes(height, 0, VoteKind::Precommit, &Some(block_hash));
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    let mut msigs = Vec::new();
    for (i, id) in committee.iter().enumerate() {
        assert_eq!(
            *id, val_id,
            "single-member fixture: the committee is the validator"
        );
        bitmask[i / 8] |= 1 << (i % 8);
        msigs.push(fk.sign(&msg));
    }
    let uqc = PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        height,
        0,
        committee_size,
        bitmask,
        msigs,
        parent,
    );
    QuorumCertificate {
        shard_id: 0,
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: vec![
            (val_id, fk.sign(&msg)),
            (PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc)),
        ],
    }
}

/// A light client that trusts `state_root` — the same root the node
/// serves — so the node's answer can be checked against a trusted header.
/// FULL-PQ: the anchor carries the Falcon µQC above (a classical
/// vote-list QC no longer verifies).
fn light_client_for(state_root: [u8; 32]) -> crate::light_client::LightClient {
    use crate::consensus::ValidatorSet;
    let fk = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
    let val_id = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &fk.public_key,
        &crate::post_quantum::DEFAULT_SALT,
    );
    crate::consensus::register_validator_pq_key(
        val_id,
        crate::post_quantum::PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    let validators = ValidatorSet::from_list(vec![(val_id, 1)]);
    let block_hash = [0x88u8; 32];
    let cert = pq_anchor_cert(val_id, &fk, &validators, 1, block_hash);
    let checkpoint =
        crate::light_client::Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
    crate::light_client::LightClient::new(validators, checkpoint).expect("light client")
}

#[tokio::test]
async fn get_proof_serves_an_account_proof_that_a_light_client_verifies() {
    let st = test_state().await;
    let who = [0x42u8; 32];
    st.engine
        .update_account(AccountState::new(who, 1_000_000_000_000))
        .await;

    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode(who) }),
    )
    .await;
    assert!(r.get("error").is_none(), "proof request must succeed: {r}");
    assert_eq!(r["address"], json!(hex::encode(who)));
    assert_eq!(r["balance"], json!(1_000_000_000_000u64));
    assert_eq!(r["nonce"], json!(0u64));
    let root_hex = r["state_root"].as_str().expect("state root");
    assert_eq!(root_hex.len(), 64, "state root is 32 bytes of hex");
    assert!(r["storage_proofs"].as_array().is_some());

    // The proof nodes are hex strings, and the leaf node carries the value
    // the proof commits to.
    let nodes: Vec<String> = r["account_proof"]
        .as_array()
        .expect("account proof array")
        .iter()
        .map(|n| n.as_str().expect("hex node").to_string())
        .collect();
    assert!(!nodes.is_empty(), "an account in the trie has a proof");
    let proof = crate::cpat2::MerkleProof::from_nodes(&nodes).expect("proof parses");
    assert_eq!(proof.kind, crate::cpat2::ProofKind::Inclusion);
    assert_eq!(proof.key, who);

    // It verifies against the root the node reported ...
    let root: [u8; 32] = hex::decode(root_hex).unwrap().try_into().unwrap();
    assert!(crate::cpat2::verify_proof(
        &root,
        &who,
        &proof.value,
        &proof
    ));

    // ... and a light client that trusts that root reaches the same
    // conclusion from the same answer.
    let lc = light_client_for(root);
    let answer = crate::light_client::ProofAnswer::from_json(&r).expect("answer parses");
    let proven = lc.verify_proof_answer(&answer).expect("answer must verify");
    assert_eq!(proven.balance, 1_000_000_000_000);
    assert_eq!(proven.nonce, 0);
    assert!(proven.exists);
    assert_eq!(proven.height, 1);
}

#[tokio::test]
async fn get_proof_proves_absence_for_an_unknown_account() {
    let st = test_state().await;
    let known = [0x42u8; 32];
    st.engine.update_account(AccountState::new(known, 7)).await;

    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode([0x99u8; 32]) }),
    )
    .await;
    assert!(r.get("error").is_none(), "proof request must succeed: {r}");
    assert_eq!(r["balance"], json!(0u64));
    assert_eq!(r["nonce"], json!(0u64));
    assert_eq!(r["exists"], json!(false));

    // The absence is PROVEN, not merely reported: the proof is an
    // exclusion proof and it verifies against the served root.
    let root: [u8; 32] = hex::decode(r["state_root"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nodes: Vec<String> = r["account_proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    assert!(
        !nodes.is_empty(),
        "an absent key still gets an exclusion proof"
    );
    let proof = crate::cpat2::MerkleProof::from_nodes(&nodes).expect("proof parses");
    assert_eq!(proof.kind, crate::cpat2::ProofKind::Exclusion);
    assert!(crate::cpat2::verify_exclusion_proof(
        &root,
        &[0x99u8; 32],
        &proof
    ));

    // And the light client agrees: the account is absent, with a proven
    // zero rather than a shrug.
    let lc = light_client_for(root);
    let answer = crate::light_client::ProofAnswer::from_json(&r).expect("answer parses");
    let proven = lc.verify_proof_answer(&answer).expect("answer must verify");
    assert!(!proven.exists);
    assert_eq!(proven.balance, 0);
}

#[tokio::test]
async fn get_proof_accepts_a_branded_address() {
    let st = test_state().await;
    let who = [0x42u8; 32];
    st.engine.update_account(AccountState::new(who, 5)).await;
    let branded = crate::address::encode_stl57_address(&who);

    let r = call(&st, "stell_getProof", json!({ "address": branded })).await;
    assert!(
        r.get("error").is_none(),
        "branded address must be accepted: {r}"
    );
    assert_eq!(r["address"], json!(hex::encode(who)));
    assert_eq!(r["balance"], json!(5u64));
}

#[tokio::test]
async fn get_proof_rejects_a_bad_address() {
    let st = test_state().await;
    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": "not-an-address" }),
    )
    .await;
    assert!(r["error"].as_str().unwrap().contains("bad address"));
    let r2 = call(&st, "stell_getProof", json!({})).await;
    assert!(r2["error"].as_str().unwrap().contains("missing address"));
}

#[tokio::test]
async fn get_proof_serves_storage_proofs() {
    let st = test_state().await;
    let who = [0x42u8; 32];
    st.engine.update_account(AccountState::new(who, 1)).await;
    // A raw state-trie key, the way a caller would name a storage slot.
    let slot = [0x5Au8; 32];
    st.engine
        .state_trie
        .write()
        .await
        .insert(&slot, b"slot-value");

    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode(who), "storage_keys": [hex::encode(slot)] }),
    )
    .await;
    assert!(r.get("error").is_none(), "proof request must succeed: {r}");
    let sp = &r["storage_proofs"][0];
    assert_eq!(sp["key"], json!(hex::encode(slot)));
    assert_eq!(sp["exists"], json!(true));
    assert_eq!(sp["value"], json!(hex::encode(b"slot-value")));

    let root: [u8; 32] = hex::decode(r["state_root"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let lc = light_client_for(root);
    let answer = crate::light_client::ProofAnswer::from_json(&r).expect("answer parses");
    let proven = lc.verify_proof_answer(&answer).expect("answer must verify");
    assert_eq!(proven.storage.len(), 1);
    assert!(proven.storage[0].exists);
    assert_eq!(proven.storage[0].value.as_deref(), Some(&b"slot-value"[..]));
}

#[tokio::test]
async fn get_proof_proves_an_absent_storage_key() {
    let st = test_state().await;
    let who = [0x42u8; 32];
    st.engine.update_account(AccountState::new(who, 1)).await;
    let missing = [0x6Bu8; 32];

    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode(who), "storage_keys": [hex::encode(missing)] }),
    )
    .await;
    let sp = &r["storage_proofs"][0];
    assert_eq!(sp["exists"], json!(false));
    assert!(sp["value"].is_null());
    assert!(
        !sp["proof"].as_array().unwrap().is_empty(),
        "absence is proven"
    );
}

#[tokio::test]
async fn get_proof_refuses_a_height_it_cannot_serve() {
    let st = test_state().await;
    // The node serves height 42 and keeps no historical state.
    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode([0x42u8; 32]), "block_height": 7 }),
    )
    .await;
    assert!(r["error"].as_str().unwrap().contains("historical state"));

    // The height it does serve is accepted.
    let ok_r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode([0x42u8; 32]), "block_height": 42 }),
    )
    .await;
    assert!(
        ok_r.get("error").is_none(),
        "current height must be served: {ok_r}"
    );
    assert_eq!(ok_r["height"], json!(42u64));
}

#[tokio::test]
async fn get_proof_caps_the_number_of_storage_keys() {
    let st = test_state().await;
    let keys: Vec<String> = (0..=MAX_PROOF_STORAGE_KEYS)
        .map(|i| hex::encode([i as u8; 32]))
        .collect();
    let r = call(
        &st,
        "stell_getProof",
        json!({ "address": hex::encode([0x42u8; 32]), "storage_keys": keys }),
    )
    .await;
    assert!(r["error"]
        .as_str()
        .unwrap()
        .contains("too many storage keys"));
}

#[tokio::test]
async fn malformed_request_rejected() {
    let st = test_state().await;
    // missing address
    let r = call(&st, "stell_getBalance", json!({})).await;
    assert!(r["error"].is_string());
    // bad hex address
    let r2 = call(&st, "stell_getBalance", json!("zzzz")).await;
    assert!(r2["error"].is_string());
}

#[tokio::test]
async fn token_methods() {
    let st = test_state().await;
    let who = [4u8; 32];
    let meta = crate::token::TokenMetadata {
        name: "Wrapped USDT".to_string(),
        symbol: "wUSDT".to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let id = st.engine.create_token(who, meta, 1000).await.unwrap();
    let r = call(
        &st,
        "stell_tokenSupply",
        json!({ "token": hex::encode(id) }),
    )
    .await;
    assert_eq!(r, "1000");
    let rb = call(
        &st,
        "stell_tokenBalance",
        json!({ "token": hex::encode(id), "account": hex::encode(who) }),
    )
    .await;
    assert_eq!(rb, "1000");
}

#[tokio::test]
async fn faucet_reconcile_fills_gaps_atomically() {
    // Reserved-but-never-executed nonces (wiped mempool) must not strand
    // later drips: reconcile takes mex(on-chain, pending).
    let f = Faucet::new([9u8; 32], 1, 10, 25);
    // Gap: on-chain 5, pending {7} (5,6 lost) -> must take 5, then 6.
    let (t1, _) = f
        .build_transfer([1u8; 32], None, Some((5, vec![7])))
        .await
        .unwrap();
    assert_eq!(t1.nonce, 5);
    // Pending {5} now (just built, pretend admitted): next is 6.
    let (t2, _) = f
        .build_transfer([2u8; 32], None, Some((5, vec![5, 7])))
        .await
        .unwrap();
    assert_eq!(t2.nonce, 6);
    // No reconcile info: pure increment (legacy behavior preserved).
    let (t3, _) = f.build_transfer([3u8; 32], None, None).await.unwrap();
    assert_eq!(t3.nonce, 7);
}

/// The PMM arms are WRITE-shaped: same token gate as
/// `stell_sendRawTransaction`, and THIN - they admit the wrapping
/// transaction to the mempool and must not touch consensus state. The curve
/// only moves when a block carries the syscall, so no node can mint STELL
/// or burn wUSDT by asking for it over RPC.
#[tokio::test]
async fn pmm_arms_admit_without_writing_state_and_require_token() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    // FULL-PQ: implicit Falcon-512 wrapper (registered globally).
    let (from, _) = pq_pair(0xC8);
    st.engine
        .update_account(AccountState::new(from, 1_000_000))
        .await;

    let buy = pq_tx_payload(
        0xC8,
        from,
        0,
        crate::svm::GAS_PMM_BUY,
        0,
        vec![crate::svm::OpCode::SysCallPmmBuy {
            usdt_micro: 250_000,
        }],
    );
    let buy_raw = hex::encode(bincode::serialize(&buy).unwrap());

    // Gated by the SAME token as sendRawTransaction.
    let denied = call(&st, "stell_pmmBuy", json!({ "tx": buy_raw.clone() })).await;
    assert!(denied["error"].as_str().unwrap().contains("unauthorized"));
    let denied2 = call(
        &st,
        "stell_pmmBuy",
        json!({ "tx": buy_raw.clone(), "token": "nope" }),
    )
    .await;
    assert!(denied2["error"].as_str().unwrap().contains("unauthorized"));

    // Thin: admitted and NOT written into state - the curve has not moved.
    let root_before = st.engine.get_state_root().await;
    let ok = call(
        &st,
        "stell_pmmBuy",
        json!({ "tx": buy_raw.clone(), "token": "secret" }),
    )
    .await;
    assert!(
        ok.as_str().is_some(),
        "authorized buy must be admitted: {ok}"
    );
    assert_eq!(
        st.mempool.read().await.len(),
        1,
        "it belongs in the mempool"
    );
    assert_eq!(
        st.engine.get_state_root().await,
        root_before,
        "submitting a PMM buy must NOT write consensus state"
    );
    assert_eq!(
        st.engine.pmm_read().await.minted_nano,
        0,
        "no curve movement may exist before a block carries the swap"
    );

    // A buy payload under the sell method is refused by its own predicate.
    let wrong = call(
        &st,
        "stell_pmmSell",
        json!({ "tx": buy_raw.clone(), "token": "secret" }),
    )
    .await;
    assert!(
        wrong["error"].as_str().unwrap().contains("SysCallPmmSell"),
        "a non-sell transaction must not be admitted under stell_pmmSell: {wrong}"
    );
    assert_eq!(
        st.mempool.read().await.len(),
        1,
        "the wrong arm admitted nothing"
    );

    // The matching sell payload is admitted the same thin way.
    let sell = pq_tx_payload(
        0xC8,
        from,
        0,
        crate::svm::GAS_PMM_SELL,
        1,
        vec![crate::svm::OpCode::SysCallPmmSell { stell_nano: 1_000 }],
    );
    let ok2 = call(
        &st,
        "stell_pmmSell",
        json!({ "tx": hex::encode(bincode::serialize(&sell).unwrap()), "token": "secret" }),
    )
    .await;
    assert!(
        ok2.as_str().is_some(),
        "authorized sell must be admitted: {ok2}"
    );
    assert_eq!(st.mempool.read().await.len(), 2);

    // `stell_pmmState` is a pure read: it reports the committed curve and
    // changes neither the root nor the mempool.
    let state = call(&st, "stell_pmmState", json!({})).await;
    assert!(state["price_micro_usd"].is_u64());
    assert_eq!(
        st.engine.get_state_root().await,
        root_before,
        "a state read must not move the root"
    );
    assert_eq!(st.mempool.read().await.len(), 2);
}

// ==================== Adopter replication: RPC serves adopted heights ===

#[tokio::test]
async fn adopter_records_serve_identical_receipts_and_no_txs_zero_view() {
    // The live bug: the proposer filed receipts + a real tx count while the
    // adopter filed nothing (txs=0, no receipts). `record_adopted_block` is
    // the adopt/walk hook; after it, receipt + block + block-txs reads must
    // match the proposer exactly.
    let proposer = test_state().await;
    let adopter = test_state().await;
    let txs = vec![receipt_tx(11, 0), receipt_tx(12, 1)];
    let bh = [0xBBu8; 32];
    proposer
        .record_receipts(77, bh, &txs, &[true, false], &[1, 0])
        .await;
    proposer.record_block(77, bh, txs.len(), 1_000).await;
    // Adopter path (verified body + single-apply statuses, behind finalization).
    adopter
        .record_adopted_block(77, bh, &txs, &[true, false], &[1, 0], 1_000)
        .await;

    for st in [&proposer, &adopter] {
        let blk = call(st, "stell_getBlock", json!({ "height": 77 })).await;
        assert_eq!(blk["txs"], json!(2), "no txs=0 view on either node");
        assert_eq!(blk["hash"], json!(hex::encode(bh)));
        let r0 = call(
            st,
            "stell_getTransactionReceipt",
            json!(hex::encode(txs[0].compute_tx_hash())),
        )
        .await;
        assert_eq!(
            (r0["height"].as_u64(), r0["status"].as_str()),
            (Some(77), Some("success"))
        );
        let txs_r = call(st, "stell_getBlockTransactions", json!({ "height": 77 })).await;
        assert_eq!(txs_r["txs"].as_array().map(|a| a.len()), Some(2));
    }
    // Byte-level receipt equality between the two nodes.
    let p = proposer
        .receipts
        .read()
        .await
        .get(&txs[1].compute_tx_hash())
        .unwrap()
        .clone();
    let a = adopter
        .receipts
        .read()
        .await
        .get(&txs[1].compute_tx_hash())
        .unwrap()
        .clone();
    assert_eq!(p.height, a.height);
    assert_eq!(p.block_hash, a.block_hash);
    assert_eq!((p.index, p.success), (a.index, a.success));
    assert_eq!(
        (p.fee_charged, a.fee_charged),
        (0, 0),
        "failed txs carry a zero charge on both"
    );
    assert_eq!(
        call(
            &proposer,
            "stell_getTransactionReceipt",
            json!(hex::encode(txs[0].compute_tx_hash()))
        )
        .await["fee_charged"],
        json!("1"),
        "block-txs and receipt views agree on the charge"
    );
}

#[tokio::test]
async fn base_fee_read_reports_the_live_admission_floor() {
    // Wallet pre-blast assertion: the read mirrors the mempool's floor.
    let st = test_state().await;
    let r = call(&st, "stell_baseFee", json!({})).await;
    assert_eq!(r["base_fee"], json!("0"), "library default floor is 0: {r}");
    st.mempool.write().await.base_fee = 560;
    let r = call(&st, "stell_baseFee", json!({})).await;
    assert_eq!(
        r["base_fee"],
        json!("560"),
        "floor tracks the live mempool: {r}"
    );
}

#[tokio::test]
async fn get_shards_serves_the_local_chain_topology() {
    // The wallet/indexer question the audit flagged: "which shards are
    // there, and where is each one?". On a single-chain node the answer is
    // the one shard this node runs, at this node's own head.
    let st = test_state().await;
    st.record_block(42, [0xAAu8; 32], 3, 1_000).await;

    let r = call(&st, "stell_getShards", json!({})).await;
    assert_eq!(r["total_shards"], json!(1), "one chain => one shard: {r}");
    assert_eq!(
        r["routing_prefix_bits"],
        json!(0),
        "a single shard needs no routing bit"
    );
    let shards = r["shards"].as_array().expect("shards array").clone();
    assert_eq!(shards.len(), 1);
    let s0 = &shards[0];
    assert_eq!(s0["shard_id"], json!(0));
    assert_eq!(s0["type"], json!("masterchain"));
    assert_eq!(
        s0["tip_height"],
        json!(42),
        "the tip height is the node's own height"
    );
    assert_eq!(
        s0["tip_hash"],
        json!(hex::encode([0xAAu8; 32])),
        "the tip hash is the committed head"
    );
    assert_eq!(
        s0["state_root"],
        json!(hex::encode(st.engine.get_state_root().await)),
        "the state root is the live trie root"
    );
    assert_eq!(
        s0["local"],
        json!(true),
        "the shard this node runs is marked local"
    );
}

#[tokio::test]
async fn get_shards_reports_every_committed_shard_head() {
    // Two shards committed by THIS process (the masterchain and a
    // workchain): both must be listed with their own committed head, and
    // the layout must report the routing width a client needs.
    let st = test_state().await;
    let reg = Arc::new(std::sync::RwLock::new(
        crate::sharding::FinalizedHeaderRegistry::default(),
    ));
    st.engine.with_finalized_headers(reg.clone());
    {
        let mut w = reg.write().unwrap();
        w.note_finalized_commitment(crate::sharding::ShardHeaderCommitment {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 285_028,
            block_hash: [0x11u8; 32],
            state_root: [0x22u8; 32],
            timestamp: 1_700_000_000,
        });
        w.note_finalized_commitment(crate::sharding::ShardHeaderCommitment {
            shard_id: crate::sharding::BASE_WORKCHAIN_SHARD_INITIAL,
            height: 63_400,
            block_hash: [0x33u8; 32],
            state_root: [0x44u8; 32],
            timestamp: 1_700_000_001,
        });
    }

    let r = call(&st, "stell_getShards", json!({})).await;
    assert_eq!(
        r["total_shards"],
        json!(2),
        "both committed shards are listed: {r}"
    );
    assert_eq!(
        r["routing_prefix_bits"],
        json!(1),
        "two shards need exactly one routing bit"
    );
    let shards = r["shards"].as_array().expect("shards array").clone();
    assert_eq!(shards.len(), 2);

    let mc = &shards[0];
    assert_eq!(mc["shard_id"], json!(0));
    assert_eq!(mc["type"], json!("masterchain"));
    assert_eq!(mc["tip_height"], json!(285_028));
    assert_eq!(mc["tip_hash"], json!(hex::encode([0x11u8; 32])));
    assert_eq!(mc["state_root"], json!(hex::encode([0x22u8; 32])));

    let wc = &shards[1];
    assert_eq!(wc["shard_id"], json!(1));
    assert_eq!(wc["type"], json!("workchain"));
    assert_eq!(wc["tip_height"], json!(63_400));
    assert_eq!(wc["tip_hash"], json!(hex::encode([0x33u8; 32])));
    assert_eq!(wc["state_root"], json!(hex::encode([0x44u8; 32])));
    assert_eq!(
        wc["local"],
        json!(false),
        "the sibling shard is not the local one"
    );
}

#[tokio::test]
async fn get_shards_refuses_a_height_above_the_tip() {
    // Never fabricate: a height this node has not reached is a miss, not
    // an answer with the current head pasted into it.
    let st = test_state().await;
    st.record_block(42, [0xAAu8; 32], 0, 1_000).await;

    let bad = call(&st, "stell_getShards", json!({ "height": 999_999 })).await;
    let msg = bad["error"]
        .as_str()
        .unwrap_or_else(|| panic!("expected an error, got {bad}"));
    assert!(
        msg.contains("above this node's tip"),
        "unexpected message: {msg}"
    );

    // A height at or below the tip is accepted and answered with the
    // current topology.
    let ok_r = call(&st, "stell_getShards", json!({ "height": 42 })).await;
    assert_eq!(
        ok_r["total_shards"],
        json!(1),
        "the topology is still served: {ok_r}"
    );
    assert!(
        ok_r.get("error").is_none(),
        "no error for a reachable height"
    );
}

/// A finalized two-height chain with a full snapshot at `H`: the state
/// this test's archive RPC arms prove history from.
struct ArchiveFixture {
    dir: std::path::PathBuf,
    store: Arc<crate::storage::Storage>,
    height: u64,
    tip: u64,
    root: [u8; 32],
    account: [u8; 32],
    signer: SigningKey,
}

async fn archive_fixture() -> (Arc<RpcState>, ArchiveFixture) {
    use crate::sharding::{Block, MASTERCHAIN_SHARD};
    use crate::state_engine::AccountState;

    let dir = std::env::temp_dir().join(format!(
        "stell_rpc_archive_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let store = Arc::new(crate::storage::Storage::open(&dir).unwrap());
    let signer = SigningKey::generate(&mut OsRng);
    // FULL-PQ: the proposer id's Falcon key is registered globally so
    // the anchoring µQC below verifies (the `qc_verification_*` idiom
    // from the consensus tests).
    let falcon = crate::post_quantum::FalconKeypair::generate();
    crate::consensus::register_validator_pq_key(
        signer.verifying_key().to_bytes(),
        crate::post_quantum::PqScheme::Falcon512,
        falcon.public_key.clone(),
    );

    let engine = Arc::new(InMemoryStateEngine::new());
    let account = [0xA1u8; 32];
    engine
        .update_account(AccountState::new(account, 1_000))
        .await;
    engine
        .update_account(AccountState::new([0xB2u8; 32], 7))
        .await;
    let root = engine.get_state_root().await;

    let height = 10u64;
    let tip = height + 1;
    store
        .put_state(height, &engine.create_snapshot().await)
        .unwrap();
    let domains = crate::storage::DomainSnapshot::capture(
        &engine,
        &crate::staking::StakingLedger::new(),
        &crate::governance::Governance::new(),
    )
    .await;
    store
        .put_domains(height, &bincode::serialize(&domains).unwrap())
        .unwrap();
    store
        .put_session_keys(height, &engine.session_keys_snapshot().await)
        .unwrap();
    store
        .put_bridge(height, &engine.bridge_snapshot().await)
        .unwrap();
    store
        .put_zkml_models(height, &engine.zkml_models_snapshot().await)
        .unwrap();

    let mk = |h: u64, prev: [u8; 32], state_root: [u8; 32]| {
        let order_root = crate::mev::compute_order_merkle_root(&[]);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: h,
            proposer: signer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: order_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
        };
        b.sign_block(&signer);
        b
    };
    let b_h = mk(height, [0u8; 32], [0xAAu8; 32]);
    let h_h = store.put_block(&b_h).unwrap();
    let mut b_next = mk(tip, h_h, root);
    let h_next = b_next.compute_hash();
    // FULL-PQ: the anchoring QC is the Falcon µQC (a classical
    // vote-list QC no longer verifies).
    let val_id = signer.verifying_key().to_bytes();
    let vset = crate::consensus::ValidatorSet::from_list(vec![(val_id, 1)]);
    let cert = pq_anchor_cert(val_id, &falcon, &vset, tip, h_next);
    b_next.precommit_qc = Some(cert);
    store.put_block(&b_next).unwrap();
    store.set_finalized(tip, &h_next).unwrap();

    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: Arc::new(std::sync::atomic::AtomicU64::new(tip)),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: base.auth_token.clone(),
        tx_broadcast: base.tx_broadcast.clone(),
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: Some(store.clone()),
        shard_registry: ShardRegistry::single(),
    });
    (
        st,
        ArchiveFixture {
            dir,
            store,
            height,
            tip,
            root,
            account,
            signer,
        },
    )
}

#[tokio::test]
async fn archive_proof_rpc_serves_history_and_root_authenticates_it() {
    use crate::consensus::ValidatorSet;
    use crate::light_client::{Checkpoint, LightClient};

    let (st, f) = archive_fixture().await;

    // Inclusion proof for the snapshotted account.
    let r = call(
        &st,
        "stell_getArchiveProof",
        json!({ "address": hex::encode(f.account), "height": f.height }),
    )
    .await;
    assert!(
        r.get("error").is_none(),
        "archive proof must be served: {r}"
    );
    assert_eq!(r["height"], json!(f.height));
    assert_eq!(r["state_root"], json!(hex::encode(f.root)));
    assert_eq!(r["proof_type"], json!("inclusion"));
    let proof = crate::cpat2::ArchiveProof::from_json(&r).expect("parse");
    assert!(
        proof.verify(),
        "served proof must verify against the historical root"
    );

    // Exclusion proof for an absent key, via the explicit `key` slot.
    let missing = [0xEEu8; 32];
    let r = call(
        &st,
        "stell_getArchiveProof",
        json!({
            "address": hex::encode(f.account),
            "key": hex::encode(missing),
            "height": f.height,
        }),
    )
    .await;
    assert_eq!(
        r["proof_type"],
        json!("exclusion"),
        "absent key proves absence: {r}"
    );
    let proof = crate::cpat2::ArchiveProof::from_json(&r).expect("parse");
    assert!(proof.verify());

    // The historical root, authenticated by the anchoring QC: parse into
    // a checkpoint, verify under OUR OWN validator set, adopt it, then
    // verify the archive proof against it — the full client path.
    let r = call(
        &st,
        "stell_getHistoricalRoot",
        json!({ "height": f.height }),
    )
    .await;
    assert!(
        r.get("error").is_none(),
        "historical root must be served: {r}"
    );
    assert_eq!(r["height"], json!(f.height));
    assert_eq!(r["state_root"], json!(hex::encode(f.root)));
    assert_eq!(r["finalized"], json!(true));
    let cp = Checkpoint::from_historical_root_json(&r).expect("parse checkpoint");
    let val_id = f.signer.verifying_key().to_bytes();
    let vset = ValidatorSet::from_list(vec![(val_id, 1)]);
    cp.verify(&vset)
        .expect("the QC must verify under our own set");
    let lc = LightClient::new(vset, cp).expect("anchor");
    let proven = lc
        .verify_archive_proof_json(
            &call(
                &st,
                "stell_getArchiveProof",
                json!({ "address": hex::encode(f.account), "height": f.height }),
            )
            .await,
        )
        .expect("archive proof must verify against the adopted historical root");
    assert!(proven.exists);
    assert_eq!(proven.archive_height, f.height);

    std::fs::remove_dir_all(&f.dir).ok();
}

#[tokio::test]
async fn archive_arms_fail_closed_without_a_store_and_above_the_tip() {
    let (st, f) = archive_fixture().await;

    // No store attached: honest refusal, not a memory proof relabeled.
    let bare = test_state().await;
    let r = call(
        &bare,
        "stell_getArchiveProof",
        json!({ "address": hex::encode(f.account), "height": f.height }),
    )
    .await;
    assert!(r["error"]
        .as_str()
        .unwrap_or_default()
        .contains("no durable store"));
    let r = call(
        &bare,
        "stell_getHistoricalRoot",
        json!({ "height": f.height }),
    )
    .await;
    assert!(r["error"]
        .as_str()
        .unwrap_or_default()
        .contains("no durable store"));

    // Above the tip: refused, never fabricated.
    let r = call(
        &st,
        "stell_getArchiveProof",
        json!({ "address": hex::encode(f.account), "height": f.tip + 100 }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("above the tip"),
        "{r}"
    );
    let r = call(
        &st,
        "stell_getHistoricalRoot",
        json!({ "height": f.tip + 100 }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("above the tip"),
        "{r}"
    );

    // Unknown height (never snapshotted, nothing retained): refused.
    let r = call(
        &st,
        "stell_getHistoricalRoot",
        json!({ "height": f.tip + 1 }),
    )
    .await;
    assert!(
        r["error"].is_string(),
        "an unanchored height must be an error: {r}"
    );

    std::fs::remove_dir_all(&f.dir).ok();
}

#[tokio::test]
async fn archive_proof_rpc_refuses_a_pruned_height() {
    use crate::state_engine::AccountState;

    let (st, f) = archive_fixture().await;
    // Age the chain past the fixture snapshot, then prune below the new
    // snapshot: the old height's data is gone for good.
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([0x77u8; 32], 5))
        .await;
    let later = f.height + 10;
    f.store
        .put_state(later, &engine.create_snapshot().await)
        .unwrap();
    let domains = crate::storage::DomainSnapshot::capture(
        &engine,
        &crate::staking::StakingLedger::new(),
        &crate::governance::Governance::new(),
    )
    .await;
    f.store
        .put_domains(later, &bincode::serialize(&domains).unwrap())
        .unwrap();
    f.store.prune_state_below(later).unwrap();
    f.store.prune_domains_below(later).unwrap();

    let r = call(
        &st,
        "stell_getArchiveProof",
        json!({ "address": hex::encode(f.account), "height": f.height }),
    )
    .await;
    let msg = r["error"]
        .as_str()
        .unwrap_or_else(|| panic!("a pruned height must be refused, got {r}"));
    assert!(
        msg.contains("pruned") || msg.contains("no state snapshot"),
        "refusal must say the height is pruned, got: {msg}"
    );
    std::fs::remove_dir_all(&f.dir).ok();
}

#[tokio::test]
async fn faucet_default_drip_is_10_stell_with_env_override() {
    // The compiled default funds 10 STELL per drip; operators override via
    // STELL_FAUCET_DRIP_STELL (whole STELL). Env is process-global, so this
    // test saves and restores it.
    let saved = std::env::var("STELL_FAUCET_DRIP_STELL").ok();
    std::env::remove_var("STELL_FAUCET_DRIP_STELL");
    assert_eq!(Faucet::default_drip_nano(), 10 * 1_000_000_000);
    std::env::set_var("STELL_FAUCET_DRIP_STELL", "25");
    assert_eq!(Faucet::default_drip_nano(), 25 * 1_000_000_000);
    match saved {
        Some(v) => std::env::set_var("STELL_FAUCET_DRIP_STELL", v),
        None => std::env::remove_var("STELL_FAUCET_DRIP_STELL"),
    }
}

#[tokio::test]
async fn unavailable_body_is_honest_unavailability_not_a_stall() {
    // Replication must NEVER block finalization and must never fabricate:
    // unknown heights/readers get an honest miss, and consensus state is
    // untouched by the read.
    let st = test_state().await;
    let h_before = st.height.load(std::sync::atomic::Ordering::Relaxed);
    let blk = call(&st, "stell_getBlock", json!({ "height": 999_999 })).await;
    assert!(
        blk["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not available yet"),
        "{blk}"
    );
    let txs = call(
        &st,
        "stell_getBlockTransactions",
        json!({ "height": 999_999 }),
    )
    .await;
    assert!(
        txs["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not available yet"),
        "{txs}"
    );
    let rcpt = call(
        &st,
        "stell_getTransactionReceipt",
        json!(hex::encode([0xDDu8; 32])),
    )
    .await;
    assert_eq!(
        rcpt["status"],
        json!("unknown"),
        "unknown tx is honestly unknown"
    );
    assert_eq!(
        st.height.load(std::sync::atomic::Ordering::Relaxed),
        h_before
    );
}

#[tokio::test]
async fn rpc_hydrates_from_the_durable_receipt_store() {
    // Restart path: the in-memory index is cold, the durable store holds the
    // adopter's filed receipts + header records; hydration restores serving.
    let dir = std::env::temp_dir().join(format!(
        "stell_rpc_hyd_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let store = crate::storage::Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    // FULL-PQ: receipt fixture is implicit Falcon-512; the block
    // proposer key stays classical (block path untouched).
    let tx = receipt_tx(0xC5, 0);
    let transactions = vec![tx.clone()];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut b = crate::sharding::Block {
        shard_id: crate::sharding::MASTERCHAIN_SHARD,
        height: 31,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 555,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    b.sign_block(&sk);
    let bh = b.compute_hash();
    store.put_block(&b).unwrap();
    store
        .put_receipts_for_block(31, &bh, &b.transactions, &[true], &[1])
        .unwrap();

    let st = test_state().await;
    hydrate_rpc_from_store(&st, &store).await;
    let r = call(
        &st,
        "stell_getTransactionReceipt",
        json!(hex::encode(tx.compute_tx_hash())),
    )
    .await;
    assert_eq!(
        (r["height"].as_u64(), r["status"].as_str()),
        (Some(31), Some("success"))
    );
    let blk = call(&st, "stell_getBlock", json!({ "height": 31 })).await;
    assert_eq!(
        blk["txs"],
        json!(1),
        "hydrated window serves the real tx count"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn rpc_accepts_stl57_address_and_archive_store_fallback() {
    let dir = std::env::temp_dir().join(format!(
        "stell_rpc_stl57_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let store = std::sync::Arc::new(crate::storage::Storage::open(&dir).unwrap());
    let sk = SigningKey::generate(&mut OsRng);
    let tx = receipt_tx(0xC6, 0);
    let transactions = vec![tx.clone()];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut b = crate::sharding::Block {
        shard_id: crate::sharding::MASTERCHAIN_SHARD,
        height: 77,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 999,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
    };
    b.sign_block(&sk);
    let bh = b.compute_hash();
    store.put_block(&b).unwrap();
    store
        .put_receipts_for_block(77, &bh, &b.transactions, &[true], &[1])
        .unwrap();

    let base = test_state().await;
    let st = Arc::new(RpcState {
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
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: Some(store.clone()),
        shard_registry: base.shard_registry.clone(),
    });

    // Branded Stl57... address works for stell_getBalance.
    let addr = [0x57u8; 32];
    st.engine
        .update_account(AccountState::new(addr, 42_000_000_000))
        .await;
    let stl57 = crate::address::encode_stl57_address(&addr);
    let bal_hex = call(&st, "stell_getBalance", json!(hex::encode(addr))).await;
    let bal_stl = call(&st, "stell_getBalance", json!({ "address": stl57 })).await;
    assert_eq!(bal_hex["balance"], json!("42000000000"));
    assert_eq!(bal_stl["balance"], json!("42000000000"));

    // Archive-store fallback when recent_blocks & receipts in memory are empty.
    let latest = call(&st, "stell_latestBlocks", json!({ "limit": 2 })).await;
    assert_eq!(latest.as_array().unwrap().len(), 1);
    assert_eq!(latest[0]["height"], json!(77));

    let blk = call(&st, "stell_getBlock", json!({ "height": 77 })).await;
    assert_eq!(blk["height"], json!(77));
    assert_eq!(blk["txs"], json!(1));

    let rcpt = call(
        &st,
        "stell_getTransactionReceipt",
        json!(hex::encode(tx.compute_tx_hash())),
    )
    .await;
    assert_eq!(rcpt["height"], json!(77));
    assert_eq!(rcpt["status"], json!("success"));

    std::fs::remove_dir_all(&dir).ok();
}

// ==================== stell_runGetMethod Tests ====================

fn sample_getter_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "double") (param $x i64) (result i64)
               (i64.mul (local.get $x) (i64.const 2)))
             (func (export "answer") (result i64)
               (i64.const 42))
             (func (export "add") (param $a i64) (param $b i64) (result i64)
               (i64.add (local.get $a) (local.get $b)))
             (func (export "trap") (param $x i64) (result i64)
               (unreachable)))"#,
    )
    .unwrap()
}

fn counter_getter_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (import "host" "sload" (func $sload (param i64) (result i64)))
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (func (export "inc") (param $key i64) (result i64)
               (call $sstore (local.get $key) (i64.add (call $sload (local.get $key)) (i64.const 1)))
               (call $sload (local.get $key)))
             (func (export "get") (param $key i64) (result i64)
               (call $sload (local.get $key))))"#,
    )
    .unwrap()
}

fn event_getter_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (import "host" "emit" (func $emit (param i64 i64)))
             (func (export "emit_test") (param $val i64) (result i64)
               (call $emit (i64.const 777) (local.get $val))
               (local.get $val)))"#,
    )
    .unwrap()
}

fn loop_getter_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "loop") (param $x i64) (result i64)
               (loop (br 0))
               (i64.const 0)))"#,
    )
    .unwrap()
}

/// A contract with a two- and a three-parameter method, deployed together
/// with a typed ABI manifest.
fn abi_contract_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (func (export "add") (param $a i64) (param $b i64) (result i64)
               (i64.add (local.get $a) (local.get $b)))
             (func (export "sum3") (param $a i64) (param $b i64) (param $c i64) (result i64)
               (i64.add (i64.add (local.get $a) (local.get $b)) (local.get $c))))"#,
    )
    .unwrap()
}

fn abi_contract_manifest() -> crate::contract_abi::ContractAbi {
    use crate::contract_abi::{AbiMethod, AbiParam, AbiType};
    crate::contract_abi::ContractAbi {
        methods: vec![
            AbiMethod::view(
                "add",
                vec![
                    AbiParam::new("a", AbiType::I64),
                    AbiParam::new("b", AbiType::I64),
                ],
                AbiType::I64,
            ),
            AbiMethod::view(
                "sum3",
                vec![
                    AbiParam::new("a", AbiType::I64),
                    AbiParam::new("b", AbiType::I64),
                    AbiParam::new("c", AbiType::I64),
                ],
                AbiType::I64,
            ),
        ],
        events: vec![],
    }
}

// ==================== stell_verifyContractSource Tests (P2-15) ====================

/// The canonical source form is `.wat` text; this one is also deployed
/// from `contracts/`-style text in the test below.
const VERIFY_WAT: &str = r#"(module
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))
  (func (export "get") (param i64) (result i64) (call $sload (local.get 0)))
  (func (export "set") (param i64) (result i64)
    (call $sstore (i64.const 0) (local.get 0))
    (call $emit (i64.const 1) (local.get 0))
    (local.get 0)))"#;

#[tokio::test]
async fn verify_contract_source_round_trip() {
    let st = test_state().await;
    // FULL-PQ: the creator is a Falcon-512 key and the registration envelope
    // is an explicit PQ1 envelope. The legacy 64-byte Ed25519 branch is gone
    // and its refusal is pinned by `contract_source`'s own unit test.
    let kp = crate::post_quantum::FalconKeypair::generate_from_seed(0xAB);
    let creator = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &kp.public_key,
        &crate::post_quantum::DEFAULT_SALT,
    );
    let wasm = wat::parse_str(VERIFY_WAT).unwrap();
    let addr = st.engine.deploy_contract(creator, wasm, 0).await.unwrap();
    let addr_hex = hex::encode(addr);

    // 1. The known `.wat` verifies (deployed bytes == rebuilt bytes).
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source": VERIFY_WAT, "compiler": "wat2wasm-1.0" }),
    )
    .await;
    assert_eq!(r["verified"], json!(true), "known source must verify: {r}");
    assert_eq!(r["reason"], json!("ok"));
    let source_hash = r["source_hash"].as_str().unwrap().to_string();
    assert_eq!(source_hash.len(), 64);

    // The `source_hex` spelling answers identically.
    let r_hex = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source_hex": hex::encode(VERIFY_WAT.as_bytes()), "compiler": "wat" }),
    )
    .await;
    assert_eq!(
        r_hex["verified"],
        json!(true),
        "hex form must verify: {r_hex}"
    );
    assert_eq!(r_hex["source_hash"], json!(source_hash));

    // 2. A tampered source is REFUSED (rebuilt hash mismatches).
    let tampered = VERIFY_WAT.replace("i64.const 1", "i64.const 2");
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source": tampered, "compiler": "wat2wasm-1.0" }),
    )
    .await;
    assert_eq!(
        r["verified"],
        json!(false),
        "tampered source must be refused: {r}"
    );

    // 3. A wrong-compiler claim is REFUSED (fail-closed, never guessed).
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source": VERIFY_WAT, "compiler": "solc-0.8.24" }),
    )
    .await;
    assert_eq!(
        r["verified"],
        json!(false),
        "foreign compiler must be refused: {r}"
    );

    // 4. Fresh contract: no source registered yet (absent = unverified).
    let r = call(
        &st,
        "stell_getContractSource",
        json!({ "contract": addr_hex }),
    )
    .await;
    assert_eq!(r["verified"], json!(false), "nothing registered yet: {r}");

    // 5. Registration without (or with a wrong) signature is refused.
    let r = call(
        &st,
        "stell_registerContractSource",
        json!({ "contract": addr_hex, "source_hash": source_hash }),
    )
    .await;
    assert!(
        r["error"].is_string(),
        "missing signature must be refused: {r}"
    );
    let bad_sig = hex::encode([0u8; crate::post_quantum::FALCON512_SIG_LEN]);
    let r = call(
        &st,
        "stell_registerContractSource",
        json!({ "contract": addr_hex, "source_hash": source_hash, "signature": bad_sig }),
    )
    .await;
    assert!(
        r["error"].is_string(),
        "forged signature must be refused: {r}"
    );

    // 6. The creator's signature registers the fingerprint — and, since F7,
    // ONLY together with the source text: registration re-runs the build.
    let shash_bytes = hex::decode(&source_hash).unwrap();
    let mut shash = [0u8; 32];
    shash.copy_from_slice(&shash_bytes);
    let msg = crate::contract_source::register_message(&addr, &shash);
    let sig = kp.sign(&msg);
    let envelope = crate::sharding::PqSignatureEnvelope::new_explicit(
        crate::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
    )
    .encode();
    // A hash-only claim is REFUSED: the node cannot rebuild it, so it cannot
    // attest it.
    let r = call(
        &st,
        "stell_registerContractSource",
        json!({ "contract": addr_hex, "source_hash": source_hash, "signature": hex::encode(&envelope) }),
    )
    .await;
    assert!(
        r["error"].as_str().unwrap_or_default().contains("source"),
        "hash-only registration must be refused: {r}"
    );
    let r = call(
        &st,
        "stell_registerContractSource",
        json!({
            "contract": addr_hex,
            "source_hash": source_hash,
            "source": VERIFY_WAT,
            "compiler": "wat2wasm-1.0",
            "signature": hex::encode(&envelope),
        }),
    )
    .await;
    assert_eq!(
        r["registered"],
        json!(true),
        "signed + rebuilt registration must land: {r}"
    );
    assert_eq!(r["rebuilt"], json!(true));

    // 7. The label is now readable; verification itself never set it
    // (it was `false` in step 4 before any registration).
    let r = call(
        &st,
        "stell_getContractSource",
        json!({ "contract": addr_hex }),
    )
    .await;
    assert_eq!(
        r["verified"],
        json!(true),
        "registered source reads back: {r}"
    );
    assert_eq!(r["source_hash"], json!(source_hash));

    // 8. Hash-only check against the registered fingerprint: it reports the
    // COMPARISON, never `verified` — no rebuild ran (F7).
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source_hash": source_hash }),
    )
    .await;
    assert_eq!(
        r["hash_matches_registered"],
        json!(true),
        "registered hash must match: {r}"
    );
    assert_eq!(
        r["verified"],
        json!(false),
        "a hash-only check is not verification: {r}"
    );
    assert!(r["rebuilt_code_hash"].is_null());
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source_hash": hex::encode([9u8; 32]) }),
    )
    .await;
    assert_eq!(
        r["verified"],
        json!(false),
        "foreign hash must not match: {r}"
    );
}

#[tokio::test]
async fn verify_contract_source_rejects_unknown_contract_and_flags() {
    let st = test_state().await;
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": hex::encode([9u8; 32]), "source": VERIFY_WAT }),
    )
    .await;
    assert_eq!(
        r["error"],
        json!("contract not found"),
        "unknown contract: {r}"
    );

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0xCDu8; 32]);
    let creator = sk.verifying_key().to_bytes();
    let wasm = wat::parse_str(VERIFY_WAT).unwrap();
    let addr = st.engine.deploy_contract(creator, wasm, 0).await.unwrap();
    let r = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": hex::encode(addr), "source": VERIFY_WAT, "compiler_flags": "--lto=fat" }),
    )
    .await;
    assert_eq!(
        r["verified"],
        json!(false),
        "unreproducible flags refused: {r}"
    );
}

#[tokio::test]
async fn run_get_method_with_abi_validates_and_types_the_call() {
    let st = test_state().await;
    let creator = [0x44u8; 32];
    let addr = st
        .engine
        .deploy_contract_with_abi(creator, abi_contract_wasm(), 0, abi_contract_manifest())
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);

    // The manifest is discoverable.
    let res = call(&st, "stell_getContractAbi", json!({ "contract": addr_hex })).await;
    assert_eq!(res["abi"]["methods"].as_array().unwrap().len(), 2);

    // A two-argument method is callable and the return value is typed.
    let res = call(
        &st,
        "stell_runGetMethod",
        json!({ "address": addr_hex, "method": "add", "args": [15, 27] }),
    )
    .await;
    assert_eq!(res["success"], json!(true));
    assert_eq!(res["return_value"], json!(42));
    assert_eq!(res["return_typed"], json!(42));

    // A three-argument method too.
    let res = call(
        &st,
        "stell_runGetMethod",
        json!({ "address": addr_hex, "method": "sum3", "args": [10, 20, 12] }),
    )
    .await;
    assert_eq!(res["success"], json!(true));
    assert_eq!(res["return_value"], json!(42));

    // The manifest is authoritative: a wrong argument count is refused.
    let res = call(
        &st,
        "stell_runGetMethod",
        json!({ "address": addr_hex, "method": "add", "args": [15] }),
    )
    .await;
    assert_eq!(res["success"], json!(false));
    assert!(res["error"]
        .as_str()
        .unwrap()
        .contains("expects 2 argument"));

    // So is an unknown method.
    let res = call(
        &st,
        "stell_runGetMethod",
        json!({ "address": addr_hex, "method": "nope", "args": [] }),
    )
    .await;
    assert_eq!(res["success"], json!(false));
}

#[tokio::test]
async fn call_contract_with_multi_argument_method() {
    // N-02: previews require a token on every bind.
    let st = test_state_with_token().await;
    let creator = [0x55u8; 32];
    let addr = st
        .engine
        .deploy_contract(creator, abi_contract_wasm(), 0)
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);

    // Three arguments reach a three-parameter method.
    let res = call_with_token(
        &st,
        "stell_callContract",
        json!({ "contract": addr_hex, "method": "sum3", "args": [10, 20, 12] }),
    )
    .await;
    assert_eq!(res["status"], json!("success"));
    assert_eq!(res["return_value"], json!(42));

    // A parameter is never dropped: the arity must match.
    let res = call_with_token(
        &st,
        "stell_callContract",
        json!({ "contract": addr_hex, "method": "sum3", "args": [10, 20] }),
    )
    .await;
    assert_eq!(res["status"], json!("failed"));
}

#[tokio::test]
async fn run_get_method_basic_execution_and_arg_formats() {
    let st = test_state().await;
    let creator = [0x11u8; 32];
    let addr = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);
    let addr_stl57 = crate::address::encode_stl57_address(&addr);

    // 1. Argument as integer number
    let res1 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": 21
        }),
    )
    .await;
    assert_eq!(res1["success"], json!(true));
    assert_eq!(res1["return_value"], json!(42));
    assert_eq!(res1["return_bytes"], json!("000000000000002a"));
    assert!(res1["fuel_used"].as_u64().unwrap() > 0);
    assert_eq!(res1["events"], json!([]));

    // 2. Argument as hex string with 0x prefix
    let res2 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": format!("0x{}", addr_hex),
            "method": "double",
            "args": "0x15"
        }),
    )
    .await;
    assert_eq!(res2["success"], json!(true));
    assert_eq!(res2["return_value"], json!(42));
    assert_eq!(res2["return_bytes"], json!("000000000000002a"));

    // 3. Argument as decimal string "21"
    let res3 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": "21"
        }),
    )
    .await;
    assert_eq!(res3["success"], json!(true));
    assert_eq!(res3["return_value"], json!(42));

    // 4. Argument as JSON array: [21]
    let res4 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": [21]
        }),
    )
    .await;
    assert_eq!(res4["success"], json!(true));
    assert_eq!(res4["return_value"], json!(42));

    // 5. Argument as JSON array of hex: ["0x15"]
    let res5 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": ["0x15"]
        }),
    )
    .await;
    assert_eq!(res5["success"], json!(true));
    assert_eq!(res5["return_value"], json!(42));

    // 6. Address in Stl57 format
    let res6 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_stl57,
            "method": "double",
            "args": 21
        }),
    )
    .await;
    assert_eq!(res6["success"], json!(true));
    assert_eq!(res6["return_value"], json!(42));

    // 7. 0-argument method "answer"
    let res7 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "answer",
            "args": []
        }),
    )
    .await;
    assert_eq!(res7["success"], json!(true));
    assert_eq!(res7["return_value"], json!(42));
    assert_eq!(res7["return_bytes"], json!("000000000000002a"));

    // 8. 2-argument method "add"
    let res8 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "add",
            "args": [15, 27]
        }),
    )
    .await;
    assert_eq!(res8["success"], json!(true));
    assert_eq!(res8["return_value"], json!(42));
}

#[tokio::test]
async fn run_get_method_zero_state_changes_and_zero_gas_fees() {
    let st = test_state().await;
    let creator = [0x22u8; 32];
    let addr = st
        .engine
        .deploy_contract(creator, counter_getter_wasm(), 0)
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);

    // Account balance setup to verify zero gas fees
    let caller_acc = [0x33u8; 32];
    let initial_balance = 5_000_000_000u64;
    st.engine
        .update_account(AccountState::new(caller_acc, initial_balance))
        .await;

    // 1. First getMethod call invokes inc(10)
    let r1 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "inc",
            "args": 10
        }),
    )
    .await;
    assert_eq!(r1["success"], json!(true));
    assert_eq!(r1["return_value"], json!(1));

    // Verify storage in state engine is COMPLETELY unmodified (zero state changes)
    let contract = st.engine.get_contract(&addr).await.unwrap();
    assert!(
        contract.storage.is_empty(),
        "contract storage must remain empty after getter invocation"
    );

    // Verify caller's account balance is completely untouched (zero gas fee charged)
    let acc_after = st.engine.get_account(&caller_acc).await.unwrap();
    assert_eq!(
        acc_after.balance, initial_balance,
        "no gas fees may be charged to any account for read-only getter"
    );

    // 2. Second getMethod call invokes inc(10) again: must return 1 again (not 2)
    let r2 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "inc",
            "args": 10
        }),
    )
    .await;
    assert_eq!(r2["success"], json!(true));
    assert_eq!(
        r2["return_value"],
        json!(1),
        "state must not have persisted from call 1"
    );

    // Verify storage in engine is still empty
    let contract2 = st.engine.get_contract(&addr).await.unwrap();
    assert!(contract2.storage.is_empty());

    // 3. Mutate consensus state deliberately via real call_contract
    st.engine
        .call_contract(&addr, "inc", 10, 50_000)
        .await
        .unwrap();
    let contract3 = st.engine.get_contract(&addr).await.unwrap();
    assert_eq!(contract3.storage.get(&10), Some(&1));

    // 4. Getter read "get" now sees the committed storage value 1
    let r_get = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "get",
            "args": 10
        }),
    )
    .await;
    assert_eq!(r_get["success"], json!(true));
    assert_eq!(r_get["return_value"], json!(1));

    // 5. Getter "inc" calculates 1 + 1 = 2 on the working copy
    let r3 = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "inc",
            "args": 10
        }),
    )
    .await;
    assert_eq!(r3["success"], json!(true));
    assert_eq!(r3["return_value"], json!(2));

    // But committed storage in engine is STILL 1 (the increment to 2 was discarded)
    let contract4 = st.engine.get_contract(&addr).await.unwrap();
    assert_eq!(contract4.storage.get(&10), Some(&1));
}

#[tokio::test]
async fn run_get_method_events_and_no_receipt_storage() {
    let st = test_state().await;
    let creator = [0x44u8; 32];
    let addr = st
        .engine
        .deploy_contract(creator, event_getter_wasm(), 0)
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);

    let res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "emit_test",
            "args": 999
        }),
    )
    .await;
    assert_eq!(res["success"], json!(true));
    assert_eq!(res["return_value"], json!(999));
    assert_eq!(res["return_bytes"], json!("00000000000003e7"));

    let events = res["events"].as_array().expect("events must be an array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["contract"], json!(addr_hex));
    assert_eq!(events[0]["topic"], json!(777));
    assert_eq!(events[0]["value"], json!(999));

    // Receipts index should NOT contain any new receipts
    assert_eq!(st.receipts.read().await.len(), 0);
}

#[tokio::test]
async fn run_get_method_safety_fuel_limit_and_error_handling() {
    let st = test_state().await;
    let creator = [0x55u8; 32];
    let sample_addr = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();
    let loop_addr = st
        .engine
        .deploy_contract(creator, loop_getter_wasm(), 0)
        .await
        .unwrap();

    // 1. Infinite loop is bounded by safety fuel limit (5,000,000)
    let loop_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": hex::encode(loop_addr),
            "method": "loop",
            "args": 0
        }),
    )
    .await;
    assert_eq!(loop_res["success"], json!(false));
    assert_eq!(loop_res["error"], json!("contract ran out of fuel"));
    assert!(loop_res["fuel_used"].as_u64().unwrap() >= 4_999_000);
    assert!(
        loop_res["fuel_used"].as_u64().unwrap() <= crate::contract::GET_METHOD_SAFETY_FUEL_LIMIT
    );

    // 2. Trapping contract (unreachable)
    let trap_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": hex::encode(sample_addr),
            "method": "trap",
            "args": 0
        }),
    )
    .await;
    assert_eq!(trap_res["success"], json!(false));
    assert_eq!(
        trap_res["error"],
        json!("contract trapped during execution")
    );
    assert!(trap_res["fuel_used"].as_u64().unwrap() > 0);

    // 3. Unknown contract
    let unknown_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": hex::encode([0xEEu8; 32]),
            "method": "double",
            "args": 10
        }),
    )
    .await;
    assert_eq!(unknown_res["success"], json!(false));
    assert_eq!(unknown_res["error"], json!("contract not found"));
    assert_eq!(unknown_res["fuel_used"], json!(0));

    // 4. Unknown method
    let no_method_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": hex::encode(sample_addr),
            "method": "non_existent_method",
            "args": 10
        }),
    )
    .await;
    assert_eq!(no_method_res["success"], json!(false));
    assert_eq!(
        no_method_res["error"],
        json!("contract does not export the requested method")
    );
    assert_eq!(no_method_res["fuel_used"], json!(0));

    // 5. Paused contract cannot be called
    st.engine
        .contracts_write()
        .await
        .pause(&sample_addr, creator)
        .unwrap();
    let paused_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": hex::encode(sample_addr),
            "method": "double",
            "args": 10
        }),
    )
    .await;
    assert_eq!(paused_res["success"], json!(false));
    assert_eq!(paused_res["error"], json!("contract is paused"));
    assert_eq!(paused_res["fuel_used"], json!(0));

    // 6. Invalid address format
    let invalid_addr_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": "not_an_address",
            "method": "double",
            "args": 10
        }),
    )
    .await;
    assert_eq!(invalid_addr_res["success"], json!(false));
    assert!(invalid_addr_res["error"]
        .as_str()
        .unwrap()
        .contains("invalid address"));
    assert_eq!(invalid_addr_res["fuel_used"], json!(0));

    // 7. Missing address
    let missing_addr_res = call(
        &st,
        "stell_runGetMethod",
        json!({
            "method": "double",
            "args": 10
        }),
    )
    .await;
    assert_eq!(missing_addr_res["success"], json!(false));
    assert!(missing_addr_res["error"]
        .as_str()
        .unwrap()
        .contains("missing"));
    assert_eq!(missing_addr_res["fuel_used"], json!(0));
}

#[tokio::test]
async fn run_get_method_block_height_pinning() {
    let st = test_state().await;
    let creator = [0x66u8; 32];
    let addr = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);

    // Height in test_state() is 42
    // 1. Height pin at current height (42) succeeds
    let res_curr = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": 21,
            "height": 42
        }),
    )
    .await;
    assert_eq!(res_curr["success"], json!(true));
    assert_eq!(res_curr["return_value"], json!(42));

    // 2. Height pin at past height (10) succeeds
    let res_past = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": 21,
            "height": 10
        }),
    )
    .await;
    assert_eq!(res_past["success"], json!(true));
    assert_eq!(res_past["return_value"], json!(42));

    // 3. Height pin in future (100 > 42) fails with descriptive error
    let res_future = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "double",
            "args": 21,
            "height": 100
        }),
    )
    .await;
    assert_eq!(res_future["success"], json!(false));
    assert!(
        res_future["error"]
            .as_str()
            .unwrap()
            .contains("pinned block height 100 exceeds current finalized height 42"),
        "future height pin must be rejected"
    );
    assert_eq!(res_future["fuel_used"], json!(0));
}

// ==================== stell_deployContract & stell_callContract Tests ====================

/// H-04/C-01 + N-03: the deploy arms validate + preview but never deploy
/// and never admit. The returned address is the SDK-canonical prediction
/// (`contract_address(tx.from, tx.nonce)` — exactly what block
/// application derives when this tx applies first for its sender), and
/// nothing is visible in state until a block carries the tx — which must
/// arrive via `stell_sendRawTransaction`, because the preview tx is
/// DROPPED (mempool stays empty).
/// (The old BLAKE3(code_hash || salt) address was a phantom the block
/// path never recreated — `init_data`/`salt` is retired: not part of the
/// replayable payload, so it cannot influence the chain.)
#[tokio::test]
async fn deploy_contract_predicts_address_and_admits_without_writing_state() {
    // N-02: previews require a token on every bind.
    let st = test_state_with_token().await;
    let code = sample_getter_wasm();
    let root_before = st.engine.get_state_root().await;

    // F6: the direct form carries no signer, so the address is predicted from
    // the `sender`(+`nonce`) the request NAMES — the same
    // `contract_address(tx.from, tx.nonce)` block application derives. No
    // random key, no receipt, no transaction.
    let (from, _kp) = pq_pair(0xC8);
    let expected_addr = crate::contract::contract_address(&from, 0);
    let res = call_with_token(
        &st,
        "stell_deployContract",
        json!({
            "code": hex::encode(&code),
            "sender": hex::encode(from),
            "nonce": 0,
            "init_data": hex::encode(vec![0x12, 0x34, 0x56, 0x78]),
        }),
    )
    .await;

    assert!(
        res["tx_hash"].is_null(),
        "the direct form builds no transaction, so it has no hash: {res}"
    );
    assert_eq!(res["deployed"], json!(false));
    assert_eq!(res["predicted"], json!(true));
    assert_eq!(
        res["contract_address"],
        json!(hex::encode(expected_addr)),
        "the prediction is contract_address(sender, nonce)"
    );
    assert_eq!(
        res["contract_address_stl57"],
        json!(crate::address::encode_stl57_address(&expected_addr))
    );
    assert_eq!(
        res["code_hash"],
        json!(hex::encode(
            <sha2::Sha256 as sha2::Digest>::digest(&code).as_slice()
        ))
    );
    // N-03/F5: nothing is pooled and NOTHING is receipted.
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "a deploy preview must never enter the mempool"
    );
    assert!(
        st.receipts.read().await.is_empty(),
        "a deploy preview must never file a receipt"
    );
    // Nothing is visible in consensus state before a block applies it.
    assert_eq!(
        st.engine.get_state_root().await,
        root_before,
        "a preview must not move the state root"
    );
    assert!(st.engine.get_contract(&expected_addr).await.is_none());
    assert!(st
        .engine
        .get_contract_code_hash(&expected_addr)
        .await
        .is_none());

    // The state change happens exactly once, at block application: fund the
    // sender, apply a REAL signed deploy at the predicted (sender, nonce), and
    // the predicted address materializes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    st.engine
        .update_account(AccountState::new(from, 1_000_000_000))
        .await;
    let vehicle = pq_tx_payload(
        0xC8,
        expected_addr,
        0,
        15_000_000,
        0,
        vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
    );
    st.engine.apply_transaction(&vehicle, now).await.unwrap();
    let stored = st
        .engine
        .get_contract(&expected_addr)
        .await
        .expect("applied deploy must materialize the contract");
    assert_eq!(stored.code, code);
    assert_eq!(
        st.engine.get_contract_code_hash(&expected_addr).await,
        Some(
            <sha2::Sha256 as sha2::Digest>::digest(&code)
                .as_slice()
                .try_into()
                .unwrap()
        )
    );
    // Re-applying the same tx is refused (nonce consumed): apply-once.
    let again = st.engine.apply_transaction(&vehicle, now).await;
    assert!(
        again.is_err(),
        "double application must be refused: {again:?}"
    );
    assert_eq!(
        st.engine.get_contract(&expected_addr).await.map(|c| c.code),
        Some(code),
        "the refused re-application must not disturb the deployed code"
    );
}

#[tokio::test]
async fn deploy_contract_with_signed_raw_tx_wrapper() {
    // N-02: previews require a token on every bind.
    let st = test_state_with_token().await;
    let code = counter_getter_wasm();

    // FULL-PQ: implicit Falcon-512 wrapper (registered globally).
    let (from, _) = pq_pair(0xC6);
    // Funded, so the admitted tx can actually apply at block time.
    st.engine
        .update_account(AccountState::new(from, 1_000_000_000))
        .await;
    let tx = pq_tx_payload(
        0xC6,
        [0u8; 32],
        0,
        15_000_000,
        0,
        vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
    );
    let tx_hash = tx.compute_tx_hash();
    let raw_hex = hex::encode(bincode::serialize(&tx).unwrap());
    // `init_data` is retired (not part of the payload): passing it must
    // not change the predicted address.
    let salt = vec![0xAB, 0xCD];

    let res = call_with_token(
        &st,
        "stell_deployContract",
        json!({
            "tx": raw_hex,
            "init_data": hex::encode(&salt),
        }),
    )
    .await;

    // SDK-canonical prediction: what block application derives.
    let expected_addr = crate::contract::contract_address(&from, 0);
    let root_after_funding = st.engine.get_state_root().await;
    assert_eq!(res["contract_address"], json!(hex::encode(expected_addr)));
    assert_eq!(res["tx_hash"], json!(hex::encode(tx_hash)));
    // N-03: the preview tx is dropped — the mempool stays EMPTY.
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "a deploy preview must never enter the mempool"
    );
    assert_eq!(
        st.engine.get_state_root().await,
        root_after_funding,
        "a preview must not move the state root"
    );
    assert!(st.engine.get_contract(&expected_addr).await.is_none());

    // Only block application materializes the contract — then the
    // contract is callable, exactly once.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    st.engine.apply_transaction(&tx, now).await.unwrap();
    let call_res = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": hex::encode(expected_addr),
            "method": "inc",
            "args": 10
        }),
    )
    .await;
    assert_eq!(call_res["status"], json!("success"));
    assert_eq!(call_res["return_value"], json!(1));
    let again = st.engine.apply_transaction(&tx, now).await;
    assert!(
        again.is_err(),
        "double application must be refused: {again:?}"
    );
}

#[tokio::test]
async fn deploy_contract_rejects_invalid_wasm() {
    // N-02: the token gate runs before validation, so the fixture token
    // is presented and the refusal below pins the wasm check (never auth).
    let st = test_state_with_token().await;
    let res = call_with_token(
        &st,
        "stell_deployContract",
        json!({
            "code": "deadbeef",
            "gas_limit": 5_000_000,
        }),
    )
    .await;
    assert!(res.get("error").is_some());
}

#[tokio::test]
async fn call_contract_execution_and_receipt_structured_outcomes() {
    // N-02: previews require a token on every bind.
    let st = test_state_with_token().await;
    // H-03 fixture setup deploys through the engine directly: the RPC
    // no longer deploys out-of-block, so tests materialize contracts the
    // way block application does.
    let creator = [0x11u8; 32];
    let deployed = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();

    let contract_addr_hex = hex::encode(deployed);
    let contract_addr = contract_addr_hex.as_str();
    let contract_stl57_hex = crate::address::encode_stl57_address(&deployed);
    let contract_stl57 = contract_stl57_hex.as_str();

    // 1. Call with integer argument
    let call1 = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_addr,
            "method": "double",
            "args": 21,
            "gas_limit": 1_000_000
        }),
    )
    .await;

    assert_eq!(call1["status"], json!("success"));
    assert_eq!(call1["return_value"], json!(42));
    assert!(call1["gas_used"].as_u64().unwrap() > 0);
    assert_eq!(call1["events"], json!([]));
    assert_eq!(call1["outcome"]["status"], json!("success"));
    assert_eq!(call1["outcome"]["return_value"], json!(42));

    // 2. F5: a preview is NOT an inclusion. The direct form has no
    // transaction at all, so there is no tx hash to look up and NO receipt may
    // be filed (the receipt ring serves mined transactions only).
    assert!(
        call1["tx_hash"].is_null(),
        "the direct form builds no transaction: {call1}"
    );
    assert_eq!(call1["preview_only"], json!(true));
    assert_eq!(call1["mined"], json!(false));
    assert!(
        st.receipts.read().await.is_empty(),
        "a preview must never file a receipt"
    );
    // 3. Unknown hashes stay unknown — nothing is fabricated.
    let c_receipt = call(
        &st,
        "stell_getContractReceipt",
        json!({ "hash": hex::encode([0u8; 32]) }),
    )
    .await;
    assert_eq!(c_receipt["status"], json!("unknown"));

    // 4. Call using branded Stl57 address format and hex args ("0x15")
    let call2 = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_stl57,
            "method": "double",
            "args": "0x15"
        }),
    )
    .await;
    assert_eq!(call2["status"], json!("success"));
    assert_eq!(call2["return_value"], json!(42));

    // 5. Call using decimal string ("15")
    let call3 = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_addr,
            "method": "double",
            "args": "15"
        }),
    )
    .await;
    assert_eq!(call3["status"], json!("success"));
    assert_eq!(call3["return_value"], json!(30));

    // 5b. Call using hex string ("0x10" = 16)
    let call3b = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_addr,
            "method": "double",
            "args": "0x10"
        }),
    )
    .await;
    assert_eq!(call3b["status"], json!("success"));
    assert_eq!(call3b["return_value"], json!(32));

    // 6. Call using array args: [21]
    let call4 = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_addr,
            "method": "double",
            "args": [21]
        }),
    )
    .await;
    assert_eq!(call4["status"], json!("success"));
    assert_eq!(call4["return_value"], json!(42));
}

/// H-03 + N-03: previews are result-identical but state-free, and the
/// previewed tx is dropped (never admitted). The counter contract is the
/// proof: two identical previews return the SAME value (the old suite
/// asserted 1-then-2, i.e. live mutation per call), storage stays empty
/// until a block applies the tx, and re-application is refused by the
/// nonce rule.
#[tokio::test]
async fn call_contract_state_mutations_and_events() {
    // N-02: previews require a token on every bind.
    let st = test_state_with_token().await;
    let creator = [0x33u8; 32];

    // 1. Counter contract (persistent storage), deployed engine-side.
    let counter = st
        .engine
        .deploy_contract(creator, counter_getter_wasm(), 0)
        .await
        .unwrap();
    let counter_hex = hex::encode(counter);
    let counter_addr = counter_hex.as_str();

    // Preview twice: same answer both times, nothing persisted, nothing
    // admitted (N-03: the mempool stays empty).
    for _ in 0..2 {
        let inc = call_with_token(
            &st,
            "stell_callContract",
            json!({ "contract": counter_addr, "method": "inc", "args": 7 }),
        )
        .await;
        assert_eq!(inc["status"], json!("success"));
        assert_eq!(inc["return_value"], json!(1));
    }
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "previews must never enter the mempool"
    );
    let get = call_with_token(
        &st,
        "stell_callContract",
        json!({ "contract": counter_addr, "method": "get", "args": 7 }),
    )
    .await;
    assert_eq!(get["status"], json!("success"));
    assert_eq!(
        get["return_value"],
        json!(0),
        "previews must not persist storage"
    );
    assert!(
        st.engine
            .get_contract(&counter)
            .await
            .map(|c| c.storage.is_empty())
            .unwrap_or(false),
        "registry storage must be untouched by previews"
    );

    // 2. The funded `tx` form previews the same answer, drops the tx,
    // and still changes nothing — until block application.
    // FULL-PQ: implicit Falcon-512 caller.
    let (caller_addr, _) = pq_pair(0xC7);
    st.engine
        .update_account(AccountState::new(caller_addr, 1_000_000_000))
        .await;
    let root_after_funding = st.engine.get_state_root().await;
    let call_tx = pq_tx_payload(
        0xC7,
        counter,
        0,
        1_000_000,
        0,
        vec![crate::svm::OpCode::SysCallCallContract {
            contract: counter,
            method: b"inc".to_vec(),
            arg: 7,
        }],
    );
    let preview = call_with_token(
        &st,
        "stell_callContract",
        json!({ "tx": hex::encode(bincode::serialize(&call_tx).unwrap()) }),
    )
    .await;
    assert_eq!(preview["status"], json!("success"));
    assert_eq!(preview["return_value"], json!(1));
    assert_eq!(
        st.mempool.read().await.len(),
        0,
        "a signed-tx preview must never enter the mempool"
    );
    assert_eq!(
        st.engine.get_state_root().await,
        root_after_funding,
        "a preview must not move the state root"
    );

    // 3. Apply-once: the first application persists exactly one
    // increment; the replay is refused and changes nothing.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    st.engine.apply_transaction(&call_tx, now).await.unwrap();
    let stored = st
        .engine
        .get_contract(&counter)
        .await
        .and_then(|c| c.storage.get(&7).copied());
    assert_eq!(stored, Some(1), "exactly one increment must apply");
    let replay = st.engine.apply_transaction(&call_tx, now).await;
    assert!(replay.is_err(), "double application must be refused");
    let stored_again = st
        .engine
        .get_contract(&counter)
        .await
        .and_then(|c| c.storage.get(&7).copied());
    assert_eq!(stored_again, Some(1), "the refused replay must not execute");
    // And the post-apply preview observes the applied state.
    let get_after = call_with_token(
        &st,
        "stell_callContract",
        json!({ "contract": counter_addr, "method": "get", "args": 7 }),
    )
    .await;
    assert_eq!(get_after["return_value"], json!(1));

    // 4. Event emission contract: the clone preview still reports events.
    let event_contract = st
        .engine
        .deploy_contract(creator, event_getter_wasm(), 0)
        .await
        .unwrap();
    let event_hex = hex::encode(event_contract);
    let event_addr = event_hex.as_str();

    let emit_call = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": event_addr,
            "method": "emit_test",
            "args": 888
        }),
    )
    .await;
    assert_eq!(emit_call["status"], json!("success"));
    assert_eq!(emit_call["return_value"], json!(888));
    let events = emit_call["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["contract"], json!(event_addr));
    assert_eq!(events[0]["topic"], json!(777));
    assert_eq!(events[0]["value"], json!(888));

    // F5: the preview's events live in the RESPONSE, never in a receipt (a
    // preview is not mined).
    assert!(
        emit_call["tx_hash"].is_null(),
        "the direct form builds no transaction: {emit_call}"
    );
    assert!(
        st.receipts.read().await.is_empty(),
        "a preview must never file a receipt, even when it emits events"
    );
}

/// H-03 result-equivalence: the clone preview reports byte-identical
/// failure shapes (trap, unknown method/contract, out-of-fuel) without
/// executing against live state. Fixtures deploy engine-side (the RPC no
/// longer deploys out-of-block).
#[tokio::test]
async fn call_contract_observable_failures() {
    // N-02: previews require a token on every bind.
    let st = test_state_with_token().await;
    let creator = [0x77u8; 32];
    let sample = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();
    let sample_hex = hex::encode(sample);
    let contract_addr = sample_hex.as_str();

    // 1. Trap failure
    let trap_res = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_addr,
            "method": "trap",
            "args": 0
        }),
    )
    .await;
    assert_eq!(trap_res["status"], json!("failed"));
    assert_eq!(trap_res["return_value"], Value::Null);
    // F5: a failed preview is not a failed MINED transaction — no receipt.
    assert!(trap_res["tx_hash"].is_null());
    assert!(
        st.receipts.read().await.is_empty(),
        "a preview must never file a receipt"
    );

    // 2. Unknown method failure
    let unknown_res = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": contract_addr,
            "method": "no_such_method",
            "args": 0
        }),
    )
    .await;
    assert_eq!(unknown_res["status"], json!("failed"));
    assert!(unknown_res["outcome"]["error"]
        .as_str()
        .unwrap()
        .contains("does not export"));

    // 3. Unknown contract address failure
    let unknown_c = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": hex::encode([0xEEu8; 32]),
            "method": "double",
            "args": 10
        }),
    )
    .await;
    assert_eq!(unknown_c["status"], json!("failed"));
    assert!(unknown_c["outcome"]["error"]
        .as_str()
        .unwrap()
        .contains("not found"));

    // 4. Out of fuel failure
    let loop_contract = st
        .engine
        .deploy_contract(creator, loop_getter_wasm(), 0)
        .await
        .unwrap();
    let loop_hex = hex::encode(loop_contract);
    let loop_addr = loop_hex.as_str();
    let oof_res = call_with_token(
        &st,
        "stell_callContract",
        json!({
            "contract": loop_addr,
            "method": "loop",
            "args": 0,
            "gas_limit": 500
        }),
    )
    .await;
    assert_eq!(oof_res["status"], json!("failed"));
    assert_eq!(oof_res["gas_used"], json!(500));
    assert!(oof_res["outcome"]["error"]
        .as_str()
        .unwrap()
        .contains("ran out of fuel"));
}

/// The estimate's gas ceiling is FIXED and the budget is HONEST (audit W7.2).
///
/// The old expression `gas_limit.max(10_000_000).min(5_000_000)` could
/// only ever evaluate to 5 000 000: the `.max()` was dead code that
/// pretended a caller could raise the ceiling. The semantics are now
/// explicit — the ceiling is a fixed maximum the caller may NOT raise, and
/// the caller MAY lower the budget with `max_gas`.
#[test]
fn estimate_fee_gas_budget_is_fixed_and_honoured_downwards() {
    // No request: the full (fixed) ceiling.
    assert_eq!(estimate_fee_gas_budget(None), Ok(ESTIMATE_FEE_GAS_CEILING));
    // A caller may lower it, and the request is HONOURED (not clamped up
    // to the ceiling).
    assert_eq!(
        estimate_fee_gas_budget(Some(ESTIMATE_FEE_MIN_GAS)),
        Ok(ESTIMATE_FEE_MIN_GAS)
    );
    assert_eq!(estimate_fee_gas_budget(Some(1_000_000)), Ok(1_000_000));
    // A caller may NEVER raise it: the refusal is explicit, and the
    // ceiling is never silently widened.
    let too_high = estimate_fee_gas_budget(Some(ESTIMATE_FEE_GAS_CEILING + 1)).unwrap_err();
    assert!(
        too_high.contains("exceeds the estimate gas ceiling"),
        "unexpected refusal: {too_high}"
    );
    assert_eq!(
        estimate_fee_gas_budget(Some(ESTIMATE_FEE_GAS_CEILING)),
        Ok(ESTIMATE_FEE_GAS_CEILING)
    );
    // A budget below one basic transfer cannot answer anything: refused,
    // not rounded up.
    let too_low = estimate_fee_gas_budget(Some(ESTIMATE_FEE_MIN_GAS - 1)).unwrap_err();
    assert!(
        too_low.contains("below the minimum estimate gas budget"),
        "unexpected refusal: {too_low}"
    );
}

#[tokio::test]
async fn estimate_fee_reports_its_budget_and_refuses_to_raise_the_ceiling() {
    let st = test_state().await;
    let from = hex::encode([1u8; 32]);
    let to = hex::encode([2u8; 32]);

    // 1. No `max_gas`: the budget IS the fixed ceiling, and the answer
    //    says so.
    let res = call(
        &st,
        "stell_estimateFee",
        json!({ "from": from, "to": to, "amount": 1000 }),
    )
    .await;
    assert_eq!(res["status"], json!("ok"));
    assert_eq!(res["gas_budget"], json!(ESTIMATE_FEE_GAS_CEILING));
    assert_eq!(res["gas_ceiling"], json!(ESTIMATE_FEE_GAS_CEILING));

    // 2. A LOWER `max_gas` is honoured.
    let res = call(
        &st,
        "stell_estimateFee",
        json!({ "from": from, "to": to, "amount": 1000, "max_gas": 1_000_000 }),
    )
    .await;
    assert_eq!(res["status"], json!("ok"));
    assert_eq!(res["gas_budget"], json!(1_000_000));

    // 3. A `max_gas` ABOVE the ceiling is refused — the caller cannot
    //    reopen the bounded cost of an unauthenticated read.
    let res = call(
        &st,
        "stell_estimateFee",
        json!({
            "from": from,
            "to": to,
            "amount": 1000,
            "max_gas": ESTIMATE_FEE_GAS_CEILING + 1,
        }),
    )
    .await;
    let msg = res["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("exceeds the estimate gas ceiling"),
        "unexpected error: {msg}"
    );

    // 4. A `max_gas` below the minimum is refused too.
    let res = call(
        &st,
        "stell_estimateFee",
        json!({
            "from": from,
            "to": to,
            "amount": 1000,
            "max_gas": ESTIMATE_FEE_MIN_GAS - 1,
        }),
    )
    .await;
    let msg = res["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("below the minimum estimate gas budget"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn test_estimate_fee_plain_transfer() {
    let st = test_state().await;
    let from = [1u8; 32];
    let to = [2u8; 32];
    // Own bucket (see `fresh_estimate_ip`): the 4 estimates below must
    // never share a 5/s window with another test, in any run order.
    let ip = fresh_estimate_ip();

    // 1. Plain transfer with explicit shards
    let res = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": hex::encode(from),
            "to": hex::encode(to),
            "amount": 1000,
            "source_shard": 0,
            "target_shard": 0
        }),
    )
    .await;

    assert_eq!(res["gas_limit"], json!(280000));
    assert_eq!(res["estimated_fee"], json!(280000));
    assert_eq!(res["base_fee"], json!(280000));
    assert_eq!(res["source_shard"], json!(0));
    assert_eq!(res["target_shard"], json!(0));
    assert_eq!(res["is_cross_shard"], json!(false));
    assert_eq!(res["status"], json!("ok"));

    // 2. TON workchain prefix rules: "-1:..." routes to masterchain (shard 0)
    let res_ton = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": format!("-1:{}", hex::encode(from)),
            "to": format!("-1:{}", hex::encode(to)),
            "amount": 500
        }),
    )
    .await;
    assert_eq!(res_ton["source_shard"], json!(0));
    assert_eq!(res_ton["target_shard"], json!(0));
    assert_eq!(res_ton["is_cross_shard"], json!(false));
    assert_eq!(res_ton["status"], json!("ok"));

    // 3. Cross-shard prefix: "1:..." routes to shard 1
    let res_cross = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": format!("-1:{}", hex::encode(from)),
            "to": format!("1:{}", hex::encode(to)),
            "amount": 500
        }),
    )
    .await;
    assert_eq!(res_cross["source_shard"], json!(0));
    assert_eq!(res_cross["target_shard"], json!(1));
    assert_eq!(res_cross["is_cross_shard"], json!(true));

    // 4. Raw transaction format: { "tx": <hex> }
    let key = ed25519_dalek::SigningKey::from_bytes(&from);
    let raw_tx = crate::sharding::Transaction::sign(&key, to, 1000, 280000, 0, 0, 0);
    let tx_hex = hex::encode(bincode::serialize(&raw_tx).unwrap());
    let res_raw = call_as(&st, ip, "stell_estimateFee", json!({ "tx": tx_hex })).await;
    assert_eq!(res_raw["gas_limit"], json!(280000));
    assert_eq!(res_raw["estimated_fee"], json!(280000));
    assert_eq!(res_raw["base_fee"], json!(280000));
    assert_eq!(res_raw["source_shard"], json!(0));
    assert_eq!(res_raw["target_shard"], json!(0));
    assert_eq!(res_raw["is_cross_shard"], json!(false));
    assert_eq!(res_raw["status"], json!("ok"));
}

#[tokio::test]
async fn test_estimate_fee_token_transfer() {
    let st = test_state().await;
    let who = [4u8; 32];
    let recipient = [5u8; 32];
    let meta = crate::token::TokenMetadata {
        name: "USD Tether".to_string(),
        symbol: "USDT".to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let token_id = st.engine.create_token(who, meta, 50_000).await.unwrap();
    // Own bucket (see `fresh_estimate_ip`).
    let ip = fresh_estimate_ip();

    // 1. Estimate fee with opcode array payload
    let res_op = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": hex::encode(who),
            "to": hex::encode(recipient),
            "source_shard": 0,
            "target_shard": 0,
            "payload": [
                {
                    "SysCallTokenTransfer": {
                        "token_id": token_id,
                        "to": recipient,
                        "amount": 250
                    }
                }
            ]
        }),
    )
    .await;

    assert_eq!(res_op["status"], json!("ok"));
    assert_eq!(res_op["gas_limit"], json!(280000));
    assert_eq!(res_op["estimated_fee"], json!(280000));
    assert_eq!(res_op["base_fee"], json!(280000));
    assert_eq!(res_op["source_shard"], json!(0));
    assert_eq!(res_op["target_shard"], json!(0));
    assert_eq!(res_op["is_cross_shard"], json!(false));

    // 2. Estimate fee with friendly token_id parameter
    let res_friendly = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": hex::encode(who),
            "to": hex::encode(recipient),
            "token_id": hex::encode(token_id),
            "amount": 500,
            "source_shard": 0,
            "target_shard": 0
        }),
    )
    .await;

    assert_eq!(res_friendly["status"], json!("ok"));
    assert_eq!(res_friendly["gas_limit"], json!(280000));
    assert_eq!(res_friendly["estimated_fee"], json!(280000));
    assert_eq!(res_friendly["base_fee"], json!(280000));
    assert_eq!(res_friendly["is_cross_shard"], json!(false));
}

#[tokio::test]
async fn test_estimate_fee_contract_call() {
    let st = test_state().await;
    let creator = [0x11u8; 32];
    let contract_addr = st
        .engine
        .deploy_contract(creator, sample_getter_wasm(), 0)
        .await
        .unwrap();
    let caller = [0x99u8; 32];
    // Own bucket (see `fresh_estimate_ip`).
    let ip = fresh_estimate_ip();

    // 1. Estimate fee with OpCode array
    let res = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": hex::encode(caller),
            "to": hex::encode(contract_addr),
            "source_shard": 0,
            "target_shard": 0,
            "payload": [
                {
                    "SysCallCallContract": {
                        "contract": contract_addr,
                        "method": "double",
                        "arg": 21
                    }
                }
            ]
        }),
    )
    .await;

    assert_eq!(res["status"], json!("ok"));
    assert_eq!(res["base_fee"], json!(280000));
    assert_eq!(res["source_shard"], json!(0));
    assert_eq!(res["target_shard"], json!(0));
    assert_eq!(res["is_cross_shard"], json!(false));
    // Gas limit and estimated fee must be at least the base fee floor (280k)
    assert!(res["gas_limit"].as_u64().unwrap() >= 280000);
    assert!(res["estimated_fee"].as_u64().unwrap() >= 280000);

    // 2. Estimate fee with friendly method parameter
    let res_friendly = call_as(
        &st,
        ip,
        "stell_estimateFee",
        json!({
            "from": hex::encode(caller),
            "to": hex::encode(contract_addr),
            "method": "double",
            "arg": 42,
            "source_shard": 0,
            "target_shard": 0
        }),
    )
    .await;

    assert_eq!(res_friendly["status"], json!("ok"));
    assert_eq!(res_friendly["base_fee"], json!(280000));
    assert_eq!(res_friendly["source_shard"], json!(0));
    assert_eq!(res_friendly["target_shard"], json!(0));
    assert_eq!(res_friendly["is_cross_shard"], json!(false));
    assert!(res_friendly["gas_limit"].as_u64().unwrap() >= 280000);
    assert!(res_friendly["estimated_fee"].as_u64().unwrap() >= 280000);
}

#[tokio::test]
async fn test_stell_get_events_endpoint_and_receipt_events() {
    let st = test_state().await;
    let contract_addr = [0x77u8; 32];
    let contract_hex = hex::encode(contract_addr);

    let tx = receipt_tx(0x33, 0);
    let tx_hash = tx.compute_tx_hash();
    let tx_hash_hex = hex::encode(tx_hash);

    let plain_tx = receipt_tx(0x44, 0);
    let plain_tx_hash = plain_tx.compute_tx_hash();
    let plain_tx_hex = hex::encode(plain_tx_hash);

    let txs = vec![tx.clone(), plain_tx.clone()];
    let events = vec![
        vec![
            crate::contract::ContractEvent {
                contract: contract_addr,
                topic: 1001,
                value: 2002,
            },
            crate::contract::ContractEvent {
                contract: contract_addr,
                topic: 1003,
                value: 2004,
            },
        ],
        vec![], // plain_tx has no events
    ];

    // Record receipts on block path (height 10)
    st.record_receipts_with_events(10, [0xAA; 32], &txs, &[true, true], &[1000, 500], &events)
        .await;

    // 1. stell_getTransactionReceipt includes events array
    let receipt = call(
        &st,
        "stell_getTransactionReceipt",
        json!({ "hash": tx_hash_hex }),
    )
    .await;
    assert_eq!(receipt["status"], json!("success"));
    let r_events = receipt["events"]
        .as_array()
        .expect("events must be an array");
    assert_eq!(r_events.len(), 2);
    assert_eq!(r_events[0]["contract"], json!(contract_hex));
    assert_eq!(r_events[0]["topic"], json!(1001));
    assert_eq!(r_events[0]["value"], json!(2002));
    assert_eq!(r_events[1]["contract"], json!(contract_hex));
    assert_eq!(r_events[1]["topic"], json!(1003));
    assert_eq!(r_events[1]["value"], json!(2004));

    // Plain tx receipt also has empty events array
    let plain_receipt = call(
        &st,
        "stell_getTransactionReceipt",
        json!({ "hash": plain_tx_hex }),
    )
    .await;
    assert_eq!(plain_receipt["events"], json!([]));

    // 2. stell_getEvents by tx_hash
    let evs_by_hash = call(&st, "stell_getEvents", json!({ "tx_hash": tx_hash_hex })).await;
    let arr = evs_by_hash.as_array().expect("must return event array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["topic"], json!(1001));
    assert_eq!(arr[0]["value"], json!(2002));
    assert_eq!(arr[1]["topic"], json!(1003));
    assert_eq!(arr[1]["value"], json!(2004));

    // Unknown tx_hash returns empty array
    let unknown = call(
        &st,
        "stell_getEvents",
        json!({ "tx_hash": hex::encode([0xFFu8; 32]) }),
    )
    .await;
    assert_eq!(unknown, json!([]));

    // 3. stell_getEvents by contract and block range
    let evs_by_contract = call(
        &st,
        "stell_getEvents",
        json!({
            "contract": contract_hex,
            "from_block": 5,
            "to_block": 15
        }),
    )
    .await;
    let arr_contract = evs_by_contract.as_array().expect("must return event array");
    assert_eq!(arr_contract.len(), 2);
    assert_eq!(arr_contract[0]["topic"], json!(1001));
    assert_eq!(arr_contract[0]["value"], json!(2002));

    // Outside block range (e.g. from 20 to 30) returns empty array
    let evs_out_of_range = call(
        &st,
        "stell_getEvents",
        json!({
            "contract": contract_hex,
            "from_block": 20,
            "to_block": 30
        }),
    )
    .await;
    assert_eq!(evs_out_of_range, json!([]));

    // Non-matching contract address returns empty array
    let evs_other_contract = call(
        &st,
        "stell_getEvents",
        json!({
            "contract": hex::encode([0x88u8; 32]),
            "from_block": 0,
            "to_block": 100
        }),
    )
    .await;
    assert_eq!(evs_other_contract, json!([]));

    // Missing parameters returns error
    let err_res = call(&st, "stell_getEvents", json!({})).await;
    assert!(err_res["error"].is_string());
}

// ===================================================================
// Streaming subscriptions (WebSocket + SSE)
// ===================================================================

/// A subscription id is 16 random bytes, hex-encoded.
fn assert_is_subscription_id(v: &Value) -> String {
    let s = v.as_str().expect("subscription id must be a string");
    assert_eq!(
        s.len(),
        SUBSCRIPTION_ID_BYTES * 2,
        "subscription id must be 16 bytes hex"
    );
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit()),
        "subscription id must be hex"
    );
    s.to_string()
}

#[tokio::test]
async fn subscribe_returns_a_hex_id_and_registers_it() {
    let st = test_state().await;
    let id = call(&st, "stell_subscribe", json!(["newHeads"])).await;
    let sub_id = assert_is_subscription_id(&id);
    assert!(
        hub().get(&sub_id).is_some(),
        "subscription must be in the registry"
    );
    let sub = hub().get(&sub_id).expect("subscription");
    assert_eq!(sub.topic, SubscriptionTopic::NewHeads);
    // Every subscribe returns a DISTINCT id.
    let other = call(&st, "stell_subscribe", json!(["newTxs"])).await;
    let other_id = assert_is_subscription_id(&other);
    assert_ne!(other_id, sub_id);
    hub().unsubscribe(&sub_id);
    hub().unsubscribe(&other_id);
}

#[tokio::test]
async fn unsubscribe_removes_the_subscription_and_is_idempotent() {
    let st = test_state().await;
    let sub_id =
        assert_is_subscription_id(&call(&st, "stell_subscribe", json!(["newHeads"])).await);
    assert_eq!(
        call(&st, "stell_unsubscribe", json!([sub_id])).await,
        json!(true)
    );
    assert!(hub().get(&sub_id).is_none(), "subscription must be gone");
    // Unsubscribing again is not an error, it just reports "not there".
    assert_eq!(
        call(&st, "stell_unsubscribe", json!([sub_id])).await,
        json!(false)
    );
    // A missing id is a parameter error.
    assert!(call(&st, "stell_unsubscribe", json!([])).await["error"].is_string());
}

#[tokio::test]
async fn subscribe_rejects_an_unknown_type() {
    let st = test_state().await;
    let r = call(&st, "stell_subscribe", json!(["notAThing"])).await;
    assert!(
        r["error"].is_string(),
        "unknown subscription type must be refused"
    );
    let r = call(&st, "stell_subscribe", json!([])).await;
    assert!(
        r["error"].is_string(),
        "missing subscription type must be refused"
    );
}

#[tokio::test]
async fn subscribe_events_normalizes_the_contract_and_topics() {
    let st = test_state().await;
    let id = call(
        &st,
        "stell_subscribe",
        json!(["events", { "contract": hex::encode([0x7Au8; 32]), "topics": ["1", "0x2"] }]),
    )
    .await;
    let sub_id = assert_is_subscription_id(&id);
    let sub = hub().get(&sub_id).expect("subscription");
    match sub.topic {
        SubscriptionTopic::Events { contract, topics } => {
            assert_eq!(contract, Some(hex::encode([0x7Au8; 32])));
            assert_eq!(topics, vec!["1".to_string(), "0x2".to_string()]);
        }
        other => panic!("expected an events subscription, got {other:?}"),
    }
    // A broken contract address is refused, not silently ignored.
    let bad = call(
        &st,
        "stell_subscribe",
        json!(["events", { "contract": "not-an-address" }]),
    )
    .await;
    assert!(bad["error"].is_string());
    hub().unsubscribe(&sub_id);
}

#[tokio::test]
async fn fanout_reaches_only_the_matching_subscriptions() {
    // An ISOLATED hub: the test's traffic cannot cross-talk with another
    // test's subscriptions on the process-wide hub.
    let h = SubscriptionHub::new();
    let heads = h.subscribe(SubscriptionTopic::NewHeads).expect("subscribe");
    let txs = h.subscribe(SubscriptionTopic::NewTxs).expect("subscribe");
    let evs = h
        .subscribe(SubscriptionTopic::Events {
            contract: Some(hex::encode([0x11u8; 32])),
            topics: vec!["7".to_string()],
        })
        .expect("subscribe");
    let other_evs = h
        .subscribe(SubscriptionTopic::Events {
            contract: Some(hex::encode([0x22u8; 32])),
            topics: vec![],
        })
        .expect("subscribe");

    // A new head addresses the `newHeads` subscriber only.
    let addressed = h.publish(
        &SubscriptionTopic::NewHeads,
        json!({ "height": 5, "hash": hex::encode([0x01u8; 32]) }),
    );
    assert_eq!(addressed, 1, "exactly one `newHeads` subscriber");

    // A contract event addresses the subscribers whose filter matches.
    let ev = crate::contract::ContractEvent {
        contract: [0x11u8; 32],
        topic: 7,
        value: 9,
    };
    let addressed = h.publish(
        &SubscriptionTopic::Events {
            contract: Some(hex::encode(ev.contract)),
            topics: vec![ev.topic.to_string()],
        },
        json!({ "contract": hex::encode(ev.contract) }),
    );
    assert_eq!(addressed, 1, "only the matching `events` subscriber");
    assert!(h.get(&evs).is_some());
    assert!(h.get(&other_evs).is_some());
    assert!(h.get(&heads).is_some());
    assert!(h.get(&txs).is_some());
}

#[tokio::test]
async fn fanout_notifications_carry_the_subscription_id_and_the_payload() {
    let h = SubscriptionHub::new();
    let sub_id = h.subscribe(SubscriptionTopic::NewHeads).expect("subscribe");
    let mut rx = h.notifications();
    let addressed = h.publish(
        &SubscriptionTopic::NewHeads,
        json!({ "height": 9, "hash": hex::encode([0x02u8; 32]), "finality": "finalized" }),
    );
    assert_eq!(addressed, 1);
    let note = rx.recv().await.expect("notification");
    assert_eq!(note.subscription, sub_id);
    assert_eq!(note.result["height"], json!(9));
    assert_eq!(note.result["finality"], json!("finalized"));
    // The wire shape is exactly {"subscription":..., "result":...}.
    let wire = serde_json::to_value(&note).expect("serialize");
    assert!(wire.get("subscription").is_some());
    assert!(wire.get("result").is_some());
    assert_eq!(wire.as_object().expect("object").len(), 2);
}

#[tokio::test]
async fn event_filter_matches_by_contract_and_topic() {
    let ev = SubscriptionTopic::Events {
        contract: Some(hex::encode([0x11u8; 32])),
        topics: vec!["7".to_string()],
    };
    // No filter: matches everything.
    assert!(topic_matches(
        &SubscriptionTopic::Events {
            contract: None,
            topics: vec![]
        },
        &ev
    ));
    // Same contract, same topic.
    assert!(topic_matches(
        &SubscriptionTopic::Events {
            contract: Some(hex::encode([0x11u8; 32])),
            topics: vec!["7".to_string()]
        },
        &ev
    ));
    // Same contract, topic given in hex.
    assert!(topic_matches(
        &SubscriptionTopic::Events {
            contract: Some(hex::encode([0x11u8; 32])),
            topics: vec!["0x7".to_string()]
        },
        &ev
    ));
    // Wildcard topic.
    assert!(topic_matches(
        &SubscriptionTopic::Events {
            contract: Some(hex::encode([0x11u8; 32])),
            topics: vec!["*".to_string()]
        },
        &ev
    ));
    // Other contract: no match.
    assert!(!topic_matches(
        &SubscriptionTopic::Events {
            contract: Some(hex::encode([0x22u8; 32])),
            topics: vec!["7".to_string()]
        },
        &ev
    ));
    // Other topic: no match.
    assert!(!topic_matches(
        &SubscriptionTopic::Events {
            contract: Some(hex::encode([0x11u8; 32])),
            topics: vec!["8".to_string()]
        },
        &ev
    ));
    // A `newHeads` filter never matches an event.
    assert!(!topic_matches(&SubscriptionTopic::NewHeads, &ev));
}

#[tokio::test]
async fn publish_hook_emits_the_documented_payload_shapes() {
    let h = SubscriptionHub::new();
    let heads = h.subscribe(SubscriptionTopic::NewHeads).expect("subscribe");
    let txs = h.subscribe(SubscriptionTopic::NewTxs).expect("subscribe");
    let evs = h
        .subscribe(SubscriptionTopic::Events {
            contract: None,
            topics: vec![],
        })
        .expect("subscribe");
    let mut rx = h.notifications();

    // newHeads
    let payload = json!({
        "height": 42u64,
        "hash": hex::encode([0x33u8; 32]),
        "shard_id": 0u32,
        "tx_count": 2usize,
        "timestamp": 1700000000u64,
        "finality": "finalized",
    });
    assert_eq!(h.publish(&SubscriptionTopic::NewHeads, payload.clone()), 1);
    let note = rx.recv().await.expect("head notification");
    assert_eq!(note.subscription, heads);
    assert_eq!(note.result, payload);

    // newTxs
    let payload = json!({
        "hash": hex::encode([0x44u8; 32]),
        "from": hex::encode([0x55u8; 32]),
        "to": hex::encode([0x66u8; 32]),
        "amount": 100u64,
        "status": "confirmed",
    });
    assert_eq!(h.publish(&SubscriptionTopic::NewTxs, payload.clone()), 1);
    let note = rx.recv().await.expect("tx notification");
    assert_eq!(note.subscription, txs);
    assert_eq!(note.result, payload);

    // events
    let ev = crate::contract::ContractEvent {
        contract: [0x77u8; 32],
        topic: 3,
        value: 4,
    };
    let payload = json!({
        "contract": hex::encode(ev.contract),
        "topics": vec!["3".to_string()],
        "data": hex::encode((ev.value as u64).to_be_bytes()),
        "block_height": 42u64,
        "tx_hash": hex::encode([0x88u8; 32]),
    });
    assert_eq!(
        h.publish(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode(ev.contract)),
                topics: vec!["3".to_string()]
            },
            payload.clone()
        ),
        1
    );
    let note = rx.recv().await.expect("event notification");
    assert_eq!(note.subscription, evs);
    assert_eq!(note.result, payload);
}

#[tokio::test]
async fn consensus_finalize_publishes_a_head_and_a_transaction() {
    // The consensus hook: `record_block` (finalize / adopt path) and
    // `record_receipts_with_events` are what the chain calls, so a
    // subscriber sees the finalized head and the included transaction.
    let st = test_state().await;
    let mut rx = hub().notifications();
    let head_sub = hub()
        .subscribe(SubscriptionTopic::NewHeads)
        .expect("subscribe");
    let tx_sub = hub()
        .subscribe(SubscriptionTopic::NewTxs)
        .expect("subscribe");
    let ev_sub = hub()
        .subscribe(SubscriptionTopic::Events {
            contract: None,
            topics: vec![],
        })
        .expect("subscribe");

    let tx = receipt_tx(7, 0);
    let tx_hash = tx.compute_tx_hash();
    st.record_receipts_with_events(
        77,
        [0xAB; 32],
        std::slice::from_ref(&tx),
        &[true],
        &[1],
        &[vec![crate::contract::ContractEvent {
            contract: [0x99u8; 32],
            topic: 1,
            value: 2,
        }]],
    )
    .await;
    st.record_block(77, [0xAB; 32], 1, 1_700_000_000).await;

    // Collect the notifications addressed to OUR subscriptions. The hub is
    // process-wide, so a concurrent test may publish other heads/txs on
    // it: pick the ones that carry OUR payload, never "the first one".
    let is_head =
        |r: &Value| r["height"] == json!(77) && r["hash"] == json!(hex::encode([0xAB; 32]));
    let is_tx = |r: &Value| r["hash"] == json!(hex::encode(tx_hash));
    let is_event = |r: &Value| r["contract"] == json!(hex::encode([0x99u8; 32]));
    let mut head: Option<Value> = None;
    let mut tx_notif: Option<Value> = None;
    let mut ev_notif: Option<Value> = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline
        && (head.is_none() || tx_notif.is_none() || ev_notif.is_none())
    {
        let note =
            match tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await {
                Ok(Ok(n)) => n,
                _ => continue,
            };
        if head.is_none() && is_head(&note.result) {
            head = Some(note.result.clone());
        }
        if tx_notif.is_none() && is_tx(&note.result) {
            tx_notif = Some(note.result.clone());
        }
        if ev_notif.is_none() && is_event(&note.result) {
            ev_notif = Some(note.result.clone());
        }
    }

    let head = head.as_ref().expect("head notification");
    assert_eq!(head["height"], json!(77));
    assert_eq!(head["hash"], hex::encode([0xAB; 32]));
    assert_eq!(head["shard_id"], json!(0));
    assert_eq!(head["tx_count"], json!(1));
    assert_eq!(head["timestamp"], json!(1_700_000_000u64));
    assert_eq!(head["finality"], json!("finalized"));

    let tx_notif = tx_notif.as_ref().expect("tx notification");
    assert_eq!(tx_notif["hash"], hex::encode(tx_hash));
    assert_eq!(tx_notif["from"], hex::encode(tx.from));
    assert_eq!(tx_notif["to"], hex::encode([0xEE; 32]));
    assert_eq!(tx_notif["amount"], json!(10u64));
    assert_eq!(tx_notif["status"], json!("confirmed"));

    let ev_notif = ev_notif.as_ref().expect("event notification");
    assert_eq!(ev_notif["contract"], hex::encode([0x99u8; 32]));
    assert_eq!(ev_notif["topics"], json!(["1"]));
    assert_eq!(ev_notif["block_height"], json!(77));
    assert_eq!(ev_notif["tx_hash"], hex::encode(tx_hash));

    hub().unsubscribe(&head_sub);
    hub().unsubscribe(&tx_sub);
    hub().unsubscribe(&ev_sub);
}

#[tokio::test]
async fn sse_stream_emits_data_frames() {
    use futures::StreamExt;
    let contract = hex::encode([0xEEu8; 32]);
    let resp = sse_handler(
        axum::http::HeaderMap::new(),
        None,
        Query(StreamQuery {
            sub_id: None,
            topics: Some("events".to_string()),
            contract: Some(contract.clone()),
            event_topics: None,
        }),
    )
    .await
    .expect("sse handler");
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let sub_id = resp
        .headers()
        .get("x-stell-subscription-id")
        .and_then(|v| v.to_str().ok())
        .expect("subscription id header")
        .to_string();
    let mut body = resp.into_body().into_data_stream();

    publish_contract_event(
        &crate::contract::ContractEvent {
            contract: [0xEEu8; 32],
            topic: 7,
            value: 42,
        },
        100,
        [0x11; 32],
    );

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let chunk = body.next().await.expect("sse stream ended");
            let text = String::from_utf8_lossy(&chunk.expect("chunk")).to_string();
            if let Some(pos) = text.find("data: ") {
                return text[pos + "data: ".len()..].trim().to_string();
            }
        }
    })
    .await
    .expect("sse frame timeout");

    let note: Value = serde_json::from_str(&frame).expect("json frame");
    assert_eq!(note["subscription"], json!(sub_id));
    assert_eq!(note["result"]["contract"], json!(contract));
    assert_eq!(note["result"]["topics"], json!(["7"]));
    assert_eq!(note["result"]["block_height"], json!(100));
    assert_eq!(note["result"]["tx_hash"], hex::encode([0x11u8; 32]));
}

#[tokio::test]
async fn websocket_transport_pushes_notifications() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let st = test_state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(st.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("websocket handshake");
    // Subscribe over the socket.
    ws.send(Message::Text(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "stell_subscribe",
            "params": ["newHeads"]
        })
        .to_string(),
    ))
    .await
    .expect("send subscribe");
    let reply = ws.next().await.expect("reply").expect("frame");
    let reply: Value = serde_json::from_str(reply.to_text().expect("text")).expect("json");
    assert_eq!(reply["id"], json!(1));
    let sub_id = assert_is_subscription_id(&reply["result"]);

    // A finalized head is pushed to the socket.
    publish_new_head(4242, [0x42u8; 32], 0, 3, 1_700_000_123);
    let pushed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let frame = ws.next().await.expect("frame").expect("msg");
            let text = frame.to_text().expect("text").to_string();
            let v: Value = serde_json::from_str(&text).expect("json");
            // The hub is process-wide: other heads may be pushed to the
            // same subscription, so pick the one we published.
            if v["subscription"] == json!(sub_id) && v["result"]["height"] == json!(4242) {
                return v;
            }
        }
    })
    .await
    .expect("push timeout");
    assert_eq!(pushed["subscription"], json!(sub_id));
    assert_eq!(pushed["result"]["height"], json!(4242));
    assert_eq!(pushed["result"]["hash"], hex::encode([0x42u8; 32]));
    assert_eq!(pushed["result"]["finality"], json!("finalized"));

    // Unsubscribing over the socket removes the subscription.
    ws.send(Message::Text(
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "stell_unsubscribe",
            "params": [sub_id]
        })
        .to_string(),
    ))
    .await
    .expect("send unsubscribe");
    let reply = ws.next().await.expect("reply").expect("frame");
    let reply: Value = serde_json::from_str(reply.to_text().expect("text")).expect("json");
    assert_eq!(reply["result"], json!(true));
    assert!(hub().get(&sub_id).is_none(), "subscription must be gone");

    let _ = ws.close(None).await;
    server.abort();
}

// ------------------------------------------------------------------
// Block invalidations: the read side (`stell_getInvalidations`) and
// the push side (the `invalidations` subscription topic).
// ------------------------------------------------------------------

/// The invalidation feed: what this node invalidated, and why.
#[tokio::test]
async fn get_invalidations_returns_the_published_signals() {
    let st = test_state().await;
    // An ISOLATED hub: the process-wide one carries the traffic of every
    // other test, so the window this test asserts on must be its own.
    let h = isolated_hub();
    let sig = crate::chain::InvalidationSignal {
        orphaned_blocks: vec![[0xA1u8; 32], [0xA2u8; 32]],
        reason: "candidate branch superseded at height 7".to_string(),
        height: 7,
    };
    publish_invalidation(&sig);

    let r = call(&st, "stell_getInvalidations", json!({})).await;
    let list = r["invalidations"].as_array().expect("array");
    assert_eq!(r["count"], json!(list.len()));
    assert_eq!(r["count"], json!(1), "only OUR signal is in the window");
    let found = list
        .iter()
        .find(|s| s["reason"] == json!("candidate branch superseded at height 7"))
        .expect("the published signal must be served");
    assert_eq!(found["height"], json!(7));
    assert_eq!(found["orphaned_count"], json!(2));
    assert_eq!(
        found["orphaned_blocks"][0],
        json!(hex::encode([0xA1u8; 32]))
    );
    assert_eq!(
        found["orphaned_blocks"][1],
        json!(hex::encode([0xA2u8; 32]))
    );
    // The window is the read side of the same promise the fan-out makes.
    assert_eq!(h.recent_invalidations(0).len(), 1);
}

/// The feed is EMPTY when nothing was invalidated: a node that never
/// forked has nothing to retract.
///
/// The hub is process-wide, so this test installs an ISOLATED one: the
/// assertion is then about the node's own history, not about the tests
/// running next to it.
#[tokio::test]
async fn get_invalidations_is_empty_when_nothing_was_invalidated() {
    let st = test_state().await;
    let h = isolated_hub();
    assert!(
        h.recent_invalidations(0).is_empty(),
        "a fresh hub knows no invalidation"
    );
    let r = call(&st, "stell_getInvalidations", json!({})).await;
    assert_eq!(r["count"], json!(0));
    assert_eq!(r["invalidations"], json!([]));
}

/// The feed's shape is stable: `count` always matches the list it
/// serves.
#[tokio::test]
async fn get_invalidations_answers_with_a_matching_count() {
    let st = test_state().await;
    isolated_hub();
    let r = call(&st, "stell_getInvalidations", json!({})).await;
    let n = r["invalidations"].as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(r["count"], json!(n));
    assert_eq!(r["count"], json!(0));
}

/// The feed is a RING BUFFER: the oldest signals are dropped and the
/// newest are served, and a limit returns the newest ones.
#[tokio::test]
async fn get_invalidations_serves_the_newest_signals_within_the_limit() {
    let st = test_state().await;
    let h = isolated_hub();
    for i in 0..(crate::chain::MAX_INVALIDATION_WINDOW + 5) {
        h.record_invalidation(crate::chain::InvalidationSignal {
            orphaned_blocks: vec![[i as u8; 32]],
            reason: format!("signal {i}"),
            height: i as u64,
        });
    }
    let r = call(&st, "stell_getInvalidations", json!({})).await;
    let list = r["invalidations"].as_array().expect("array");
    assert_eq!(list.len(), crate::chain::MAX_INVALIDATION_WINDOW);
    assert_eq!(
        list[0]["height"],
        json!(5u64),
        "the oldest signals are dropped"
    );
    assert_eq!(
        list[list.len() - 1]["height"],
        json!((crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64),
        "the newest signal is kept"
    );
    // A limit returns the newest signals only.
    let limited = call(&st, "stell_getInvalidations", json!({ "limit": 2 })).await;
    let limited = limited["invalidations"].as_array().expect("array");
    assert_eq!(limited.len(), 2);
    assert_eq!(
        limited[1]["height"],
        json!((crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64)
    );
}

/// The SSE transport knows the `invalidations` topic too: a browser
/// (which cannot speak WebSocket) follows the SAME signals a bot does.
#[tokio::test]
async fn the_sse_transport_streams_invalidations() {
    use futures::StreamExt;
    isolated_hub();
    let resp = sse_handler(
        axum::http::HeaderMap::new(),
        None,
        Query(StreamQuery {
            sub_id: None,
            topics: Some("invalidations".to_string()),
            contract: None,
            event_topics: None,
        }),
    )
    .await
    .expect("sse handler");
    let sub_id = resp
        .headers()
        .get("x-stell-subscription-id")
        .and_then(|v| v.to_str().ok())
        .expect("subscription id header")
        .to_string();
    let mut body = resp.into_body().into_data_stream();

    publish_invalidation(&crate::chain::InvalidationSignal {
        orphaned_blocks: vec![[0xC3u8; 32]],
        reason: "candidate branch superseded at height 5".to_string(),
        height: 5,
    });

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let chunk = body.next().await.expect("sse stream ended");
            let text = String::from_utf8_lossy(&chunk.expect("chunk")).to_string();
            if let Some(pos) = text.find("data: ") {
                return text[pos + "data: ".len()..].trim().to_string();
            }
        }
    })
    .await
    .expect("sse frame timeout");

    let note: Value = serde_json::from_str(&frame).expect("json frame");
    assert_eq!(note["subscription"], json!(sub_id));
    assert_eq!(note["result"]["height"], json!(5));
    assert_eq!(
        note["result"]["orphaned_blocks"][0],
        json!(hex::encode([0xC3u8; 32]))
    );
    assert_eq!(note["result"]["orphaned_count"], json!(1));
}

/// The EVENT HOOK: a streaming subscriber of the `invalidations` topic
/// receives the signal.
#[tokio::test]
async fn invalidation_subscribers_receive_the_signal() {
    let st = test_state().await;
    isolated_hub();
    let sub_id =
        assert_is_subscription_id(&call(&st, "stell_subscribe", json!(["invalidations"])).await);
    let mut rx = hub().notifications();
    let sig = crate::chain::InvalidationSignal {
        orphaned_blocks: vec![[0xB1u8; 32]],
        reason: "reorg: candidate branch superseded".to_string(),
        height: 3,
    };
    publish_invalidation(&sig);
    // The hub is process-wide: other notifications may arrive first, so
    // pick the one that belongs to OUR subscription.
    let note = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let n = rx.recv().await.expect("notification");
            if n.subscription == sub_id {
                break n;
            }
        }
    })
    .await
    .expect("push timeout");
    assert_eq!(note.result["height"], json!(3));
    assert_eq!(
        note.result["orphaned_blocks"][0],
        json!(hex::encode([0xB1u8; 32]))
    );
    assert_eq!(note.result["orphaned_count"], json!(1));
    hub().unsubscribe(&sub_id);
}

/// END TO END: the consensus runtime invalidates a losing branch, and
/// the signal reaches the RPC feed a client reads.
#[tokio::test]
async fn a_runtime_invalidation_reaches_the_rpc_feed() {
    use crate::consensus::ValidatorSet;
    use crate::runtime::ValidatorRuntime;
    use crate::sharding::{Block, MASTERCHAIN_SHARD};
    use crate::state_engine::InMemoryStateEngine;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let st = test_state().await;
    // An ISOLATED hub: the runtime publishes through the sink below, and
    // the window this test asserts on must hold nothing else.
    isolated_hub();

    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let mk = |height: u64, prev: [u8; 32], tag: u8| {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [tag; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: height,
            proposer: key.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
        };
        b.sign_block(&key);
        b
    };

    let mut rt = ValidatorRuntime::new(
        key.clone(),
        ValidatorSet::from_list(vec![(me, 1)]),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_invalidation_sink(Arc::new(|sig: crate::chain::InvalidationSignal| {
        publish_invalidation(&sig);
    }));

    // A finalized block anchors the fork-choice, then two candidates
    // compete at the next height, and a third block is finalized there:
    // the two candidates lose and are invalidated.
    let f1 = mk(1, [0u8; 32], 0xF1);
    let f1h = f1.compute_hash();
    rt.note_finalized_block(&f1);
    let c1 = mk(2, f1h, 0xC1);
    let c2 = mk(2, f1h, 0xC2);
    assert!(rt.record_candidate_block(&c1));
    assert!(rt.record_candidate_block(&c2));
    let w = mk(2, f1h, 0xA7);
    rt.note_finalized_block(&w);

    let r = call(&st, "stell_getInvalidations", json!({})).await;
    assert_eq!(r["count"], json!(2), "both losing candidates are reported");
    let mut hashes: Vec<String> = r["invalidations"]
        .as_array()
        .expect("array")
        .iter()
        .map(|s| {
            s["orphaned_blocks"][0]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    hashes.sort();
    let mut expected = vec![
        hex::encode(c1.compute_hash()),
        hex::encode(c2.compute_hash()),
    ];
    expected.sort();
    assert_eq!(hashes, expected);
    assert_eq!(r["invalidations"][0]["height"], json!(2));
}

/// The invalidation window is bounded and keeps the NEWEST signals.
#[tokio::test]
async fn the_invalidation_window_is_bounded_and_ordered() {
    let h = SubscriptionHub::new();
    for i in 0..(crate::chain::MAX_INVALIDATION_WINDOW + 5) {
        h.record_invalidation(crate::chain::InvalidationSignal {
            orphaned_blocks: vec![[i as u8; 32]],
            reason: format!("signal {i}"),
            height: i as u64,
        });
    }
    let win = h.recent_invalidations(0);
    assert_eq!(win.len(), crate::chain::MAX_INVALIDATION_WINDOW);
    assert_eq!(
        win.last().unwrap().height,
        (crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64
    );
    // A limit returns the NEWEST signals.
    let last_two = h.recent_invalidations(2);
    assert_eq!(last_two.len(), 2);
    assert_eq!(
        last_two[1].height,
        (crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64
    );
    // A signal without orphaned blocks carries no information: it is
    // never recorded.
    let before = h.recent_invalidations(0).len();
    h.record_invalidation(crate::chain::InvalidationSignal {
        orphaned_blocks: vec![],
        reason: "nothing".to_string(),
        height: 0,
    });
    assert_eq!(h.recent_invalidations(0).len(), before);
}

// ---- the native interface namespace (JSON-RPC level) ----

/// The native namespace is REACHABLE through the JSON-RPC dispatcher and
/// answers with its documented shape.
#[tokio::test]
async fn native_api_namespace_is_reachable_over_json_rpc() {
    let st = test_state().await;

    // The manifest: the whole interface in one call.
    let v = call(&st, "stell_nativeApi", json!({})).await;
    assert_eq!(v["version"], crate::native_api::NATIVE_API_VERSION);
    let methods = v["methods"].as_array().expect("methods array");
    assert!(methods.len() >= 21);
    assert!(methods.iter().any(|m| m["name"] == "stell_tokenTransfer"));
    assert!(methods.iter().any(|m| m["name"] == "stell_oracleFeeds"));

    // A read method answers with its documented shape.
    let v = call(
        &st,
        "stell_tokenBalanceOf",
        json!({ "token": hex::encode([9u8; 32]), "account": hex::encode([1u8; 32]) }),
    )
    .await;
    // The token does not exist: an error, never a zero balance.
    assert!(v["error"].is_string(), "unknown token must fail closed");

    // A missing parameter is an error too.
    let v = call(&st, "stell_tokenBalanceOf", json!({})).await;
    assert!(v["error"].is_string());

    // An unknown method is still "method not found".
    let v = call(&st, "stell_notARealMethod", json!({})).await;
    assert!(v["error"].is_string());
}

/// The native write methods produce a transaction to sign and never
/// mutate the state they read.
#[tokio::test]
async fn native_api_prepare_methods_do_not_mutate_state() {
    let st = test_state().await;
    let before = st.engine.get_state_root().await;

    let v = call(
        &st,
        "stell_orderBookPlace",
        json!({ "pair": 1, "side": "buy", "price": "250000", "amount": "10" }),
    )
    .await;
    assert_eq!(v["action"], "order_book_place");
    assert_eq!(v["transaction"]["op"], "SysCallPlaceOrder");
    assert_eq!(v["submit_with"], "stell_sendRawTransaction");

    let after = st.engine.get_state_root().await;
    assert_eq!(
        before, after,
        "a prepared transaction must not touch the state"
    );
}

/// `stell_runGetMethod` must be bounded in BOTH fuel and arity: the
/// getter's "legacy tolerance" fallback walks the whole argument list
/// looking for a matching export, so an unbounded argument array turns
/// one request into hundreds of thousands of export lookups.
#[tokio::test]
async fn run_get_method_refuses_an_unbounded_argument_list() {
    let st = test_state().await;
    let creator = [0x55u8; 32];
    let addr = st
        .engine
        .deploy_contract(creator, abi_contract_wasm(), 0)
        .await
        .unwrap();
    let addr_hex = hex::encode(addr);
    let many: Vec<i64> = (0..(crate::contract::MAX_CONTRACT_CALL_ARGS as i64 + 50)).collect();
    let r = call(
        &st,
        "stell_runGetMethod",
        json!({ "address": addr_hex, "method": "get", "args": many }),
    )
    .await;
    assert!(
        r["success"] == json!(false),
        "an oversized argument list must be refused: {r}"
    );
    let msg = r["error"].as_str().unwrap_or("");
    assert!(
        msg.contains("too many arguments") || msg.contains("argument"),
        "the refusal must name the argument problem: {msg}"
    );
}

// ===================================================================
// RPC SURFACE HARDENING (audit W6.7)
// ===================================================================

/// A call attributed to a client IP (the per-IP budgets need one).
async fn call_from(st: &Arc<RpcState>, method: &str, params: Value, ip: std::net::IpAddr) -> Value {
    let r = dispatch(st, Value::from(1), method, &params, None, Some(ip)).await;
    r.0.error
        .map(|e| json!({"error": e.message}))
        .unwrap_or(r.0.result.unwrap_or(Value::Null))
}

/// `stell_executeProposal` applies the action of a PASSED proposal — and
/// one of the actions is `SoftwareUpgrade`, the path that ends in an
/// `execve` of a new binary. It was the ONLY governance write arm with no
/// token gate, while `stell_submitProposal` and `stell_vote` were gated.
#[tokio::test]
async fn execute_proposal_requires_the_auth_token() {
    let base = test_state().await;
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });

    // A proposal that is already PASSED (the quorum is the ledger's job).
    {
        let mut g = st.governance.write().await;
        g.next_id = 7;
        g.proposals.insert(
            7,
            crate::governance::Proposal {
                id: 7,
                proposer: [0x01u8; 32],
                title: "t".into(),
                action: crate::governance::GovAction::Signal("hello".into()),
                created_at: 0,
                voting_end: 1,
                yes: 1,
                no: 0,
                abstain: 0,
                voters: Default::default(),
                status: crate::governance::ProposalStatus::Passed,
                electorate: 1,
                electorate_weights: None,
                proposer_lock: 0,
                weights: Default::default(),
            },
        );
    }

    // WITHOUT the token: refused.
    let r = call(&st, "stell_executeProposal", json!({ "id": 7 })).await;
    assert!(
        r["error"].as_str().unwrap_or("").contains("unauthorized"),
        "stell_executeProposal must require the auth token: {r}"
    );
    assert_eq!(
        st.governance.read().await.get(7).map(|p| p.status),
        Some(crate::governance::ProposalStatus::Passed),
        "a refused execution must not change the proposal"
    );

    // WITH the token: executed.
    let r = call(
        &st,
        "stell_executeProposal",
        json!({ "id": 7, "token": "secret" }),
    )
    .await;
    assert_eq!(
        r["executed"],
        json!(true),
        "an authorized execution must run: {r}"
    );
    assert_eq!(
        st.governance.read().await.get(7).map(|p| p.status),
        Some(crate::governance::ProposalStatus::Executed)
    );
}

/// The bind parser: only provably-loopback binds read as loopback, so the
/// gov-write gate fails closed on anything else.
/// // GATE: fail-closed direction of H-01 (unparseable → refused).
#[test]
fn bind_addr_loopback_parser_is_fail_closed() {
    for good in [
        "127.0.0.1:8545",
        "127.0.0.1",
        "127.2.3.4:1",
        "localhost:8545",
        "localhost",
        "[::1]:8545",
        "::1",
        "  127.0.0.1:8545  ",
    ] {
        assert!(bind_addr_is_loopback(good), "{good} must read as loopback");
    }
    for bad in [
        "0.0.0.0:8545",
        "0.0.0.0",
        "192.168.1.10:8545",
        "10.0.0.5:8545",
        "example.com:8545",
        "example.com",
        "",
        "garbage",
        ":8545",
        "[::1",
        "127.0.0.1:abc",
    ] {
        assert!(
            !bind_addr_is_loopback(bad),
            "{bad} must NOT read as loopback"
        );
    }
}

/// N-02: gov writes require a valid token ALWAYS, on EVERY bind — the
/// loopback escape is deleted. A missing/unconfigured token refuses on
/// both a loopback and a non-loopback bind (mock bind proves
/// bind-independence); a correct token serves on both binds.
/// // GATE: N-02 token-always; same refusal properties, never weakened.
#[tokio::test]
async fn gov_writes_require_token_on_every_bind() {
    // Panic-safe mock guard: the override is process-wide (a mutex, never
    // the env), so it must reset even when an assert below fails. The
    // mock now only steers the unsigned-dev-test escape — the token gate
    // ignores it, which is exactly what this test pins.
    struct BindGuard;
    impl Drop for BindGuard {
        fn drop(&mut self) {
            set_test_bind_loopback(None);
        }
    }
    let _guard = BindGuard;

    // 1. No token configured: all three gov writes refuse on a
    //    non-loopback bind AND on a loopback bind. The gate runs before
    //    payload parsing, so garbage params are still unauthorized
    //    (never a parse error).
    let st = test_state().await;
    for mock in [Some(false), Some(true)] {
        set_test_bind_loopback(mock);
        for (method, params) in [
            (
                "stell_submitProposal",
                json!({"title": "t", "type": "signal", "proposer": hex::encode([9u8; 32])}),
            ),
            (
                "stell_vote",
                json!({"id": 1, "voter": hex::encode([9u8; 32])}),
            ),
            ("stell_executeProposal", json!({"id": 1})),
        ] {
            let r = call(&st, method, params).await;
            assert!(
                r["error"].as_str().unwrap_or("").contains("unauthorized"),
                "{method} without a token (bind loopback={mock:?}) must refuse: {r}"
            );
        }
    }
    assert!(
        st.governance.read().await.proposals.is_empty(),
        "refused writes must not record anything"
    );

    // 2. Token configured but missing/wrong: still refused, on both binds.
    let st = test_state_with_token().await;
    for mock in [Some(false), Some(true)] {
        set_test_bind_loopback(mock);
        let r = call(&st, "stell_executeProposal", json!({ "id": 1 })).await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("unauthorized"),
            "missing token (bind loopback={mock:?}) must refuse: {r}"
        );
        let r = call(
            &st,
            "stell_executeProposal",
            json!({ "id": 1, "token": "wrong" }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("unauthorized"),
            "wrong token (bind loopback={mock:?}) must refuse: {r}"
        );
    }

    // 3. Correct token: signed flows work end to end on BOTH binds.
    // Block-carried update (HDAE-GOV): the DIRECT form mutates in this
    // process only, so it serves on SOLO sets (one bonded staker — the
    // single-node guard passes), pinned here with a self-vote; on a
    // TWO-staker set the same "correct token serves" property holds via
    // the BLOCK form (caller-signed tx into the mempool, nothing
    // recorded). Same property, per form, on both binds — never
    // weakened, only routed.
    for mock in [Some(false), Some(true)] {
        set_test_bind_loopback(mock);
        // 3a. Solo direct: propose + self-vote record end to end.
        let st = test_state_with_token().await;
        let proposer_key = TestGovKey::falcon_from_seed(&[0xA1u8; 32]);
        let proposer = proposer_key.address();
        {
            let mut ledger = st.engine.staking_write().await;
            ledger
                .bond(proposer, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                .unwrap();
        }
        let title = "dev".to_string();
        let action = crate::governance::GovAction::Signal("hi".to_string());
        let r = call_with_token(
            &st,
            "stell_submitProposal",
            json!({
                "title": title,
                "type": "signal",
                "text": "hi",
                "proposer": hex::encode(proposer),
                "nonce": 1u64,
                "signature": sign_test_proposal(st.chain_id, &proposer_key, &proposer, &title, &action, 1),
            }),
        )
        .await;
        let pid = r["proposal_id"].as_u64().unwrap_or_else(|| {
            panic!("token-authed submit (bind loopback={mock:?}) must work: {r}")
        });
        assert!(
            r.get("error").is_none(),
            "token-authed submit (bind loopback={mock:?}) must work: {r}"
        );
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(proposer),
                "choice": "yes",
                "signature": sign_test_vote(st.chain_id, &proposer_key, &proposer, pid, crate::governance::VoteChoice::Yes),
            }),
        )
        .await;
        assert_eq!(
            r["voted"],
            json!(true),
            "token-authed self-vote (bind loopback={mock:?}) must work: {r}"
        );
        // 3b. Multi-node block form: a caller-signed propose tx is
        // admitted on a two-staker set (direct would refuse there).
        let st2 = test_state_with_token().await;
        let (from, pk) = pq_pair(0xB1);
        {
            let mut ledger = st2.engine.staking_write().await;
            ledger
                .bond(from, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                .unwrap();
            ledger
                .bond([0xB2u8; 32], crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                .unwrap();
        }
        st2.engine
            .update_account(crate::state_engine::AccountState::new(
                from,
                1_000_000_000_000,
            ))
            .await;
        let height = st2.height.load(std::sync::atomic::Ordering::Relaxed) + 1;
        let ptx = crate::governance::Governance::gov_propose_tx(
            from,
            0,
            500_000,
            1,
            1,
            1,
            "dev".to_string(),
            action.clone(),
            height,
        )
        .expect("test propose template must build");
        let ptx = sign_gov_block_tx(0xB1, &pk, ptx);
        let r = call_with_token(
            &st2,
            "stell_submitProposal",
            json!({ "tx": gov_tx_hex(&ptx) }),
        )
        .await;
        assert!(
            r.as_str().is_some(),
            "token-authed block submit (bind loopback={mock:?}) must admit: {r}"
        );
        assert_eq!(
            st2.mempool.read().await.len(),
            1,
            "the tx must reach the mempool"
        );
        assert!(
            st2.governance.read().await.proposals.is_empty(),
            "admission must not record a proposal"
        );
    }
}

/// Operator-signed governance ingest: valid envelopes are accepted;
/// unsigned, wrong-key, tampered, cross-chain, and replayed envelopes
/// are refused fail-closed. Same-choice vote replay is idempotent;
/// different-choice replay is refused (first choice wins).
///
/// // GATE: new-path pins for operator-signed gov identity; extends, never weakens.
#[tokio::test]
async fn gov_writes_require_operator_signatures() {
    use crate::governance::{GovAction, VoteChoice};
    // N-02: the signature pins below run on the token fixture — the auth
    // gate passes, then the operator-signature checks fire.
    let st = test_state_with_token().await;
    let chain = st.chain_id;
    let proposer_key = TestGovKey::falcon_from_seed(&[0xA1u8; 32]);
    let proposer = proposer_key.address();
    let voter_key = TestGovKey::falcon_from_seed(&[0xB2u8; 32]);
    let voter = voter_key.address();
    let lone_key = TestGovKey::falcon_from_seed(&[0xC3u8; 32]);
    let lone = lone_key.address();
    // Block-carried update (HDAE-GOV): the direct form below mutates in
    // this process only, so this matrix runs on a SOLO set (the proposer
    // alone is bonded — the single-node guard passes). Lifecycle pins
    // use a SELF-vote (one vote per voter; the proposer's own stake
    // votes exactly like a second staker's would, and the refusal pins
    // fire before any stake check, so no property is weakened). The
    // block-form twins of these pins live in the block-form tests below
    // (admitted, never recorded).
    {
        let mut ledger = st.engine.staking_write().await;
        ledger
            .bond(proposer, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
            .unwrap();
    }
    let title = "sig test".to_string();
    let action = GovAction::Signal("hi".to_string());
    let submit = |title: &str, _action: &GovAction, nonce: u64, sig_hex: &str| {
        call_with_token(
            &st,
            "stell_submitProposal",
            json!({
                "title": title,
                "type": "signal",
                "text": "hi",
                "proposer": hex::encode(proposer),
                "nonce": nonce,
                "signature": sig_hex,
            }),
        )
    };

    // 1. Unsigned proposal: refused fail-closed (no new knob involved;
    //    this test process does not arm STELL_DEV_UNSAFE_TESTKEY).
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({
            "title": title,
            "type": "signal",
            "text": "hi",
            "proposer": hex::encode(proposer),
            "nonce": 1u64,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or("")
            .contains("missing gov signature"),
        "unsigned proposal must be refused: {r}"
    );

    // 2. Valid signed proposal: accepted.
    let sig = sign_test_proposal(chain, &proposer_key, &proposer, &title, &action, 1);
    let r = submit(&title, &action, 1, &sig).await;
    assert!(r.get("error").is_none(), "valid signed proposal: {r}");
    let pid = r["proposal_id"].as_u64().expect("proposal id");

    // 3. Exact replay of the envelope: refused (nonce consumed).
    let r = submit(&title, &action, 1, &sig).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or("")
            .contains("already consumed"),
        "replayed proposal nonce must be refused: {r}"
    );

    // 4. Wrong key: the voter's envelope presented as the proposer.
    let wrong_msg =
        crate::governance::Governance::gov_propose_message(chain, &proposer, &title, &action, 2);
    let wrong = voter_key.sign_message(chain, &wrong_msg).unwrap().to_hex();
    let r = submit(&title, &action, 2, &wrong).await;
    assert!(
        r["error"].as_str().unwrap_or("").contains("wrong key"),
        "wrong-key proposal must be refused: {r}"
    );

    // 5. Tampered title: signed "sig test", submitted as something else.
    let r = submit("tampered title", &action, 3, &sig).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("propose failed"),
        "tampered proposal must be refused: {r}"
    );

    // 6. Cross-chain envelope: minted for another chain.
    let cross_msg = crate::governance::Governance::gov_propose_message(
        chain + 1,
        &proposer,
        &title,
        &action,
        4,
    );
    let cross = proposer_key
        .sign_message(chain + 1, &cross_msg)
        .unwrap()
        .to_hex();
    let r = submit(&title, &action, 4, &cross).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("propose failed"),
        "cross-chain proposal must be refused: {r}"
    );

    // 7. Stakeless key, perfectly valid signature: refused (NotStaker).
    let lone_msg =
        crate::governance::Governance::gov_propose_message(chain, &lone, &title, &action, 5);
    let lone_sig = lone_key.sign_message(chain, &lone_msg).unwrap().to_hex();
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({
            "title": title,
            "type": "signal",
            "text": "hi",
            "proposer": hex::encode(lone),
            "nonce": 5u64,
            "signature": lone_sig,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no staked balance"),
        "stakeless proposer must be refused: {r}"
    );

    // 8. Unsigned vote: refused fail-closed.
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({"id": pid, "voter": hex::encode(voter), "choice": "yes"}),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or("")
            .contains("missing gov signature"),
        "unsigned vote must be refused: {r}"
    );

    // 9. Valid signed vote: accepted (self-vote on the solo set).
    let vsig = sign_test_vote(chain, &proposer_key, &proposer, pid, VoteChoice::Yes);
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": pid,
            "voter": hex::encode(proposer),
            "choice": "yes",
            "signature": vsig,
        }),
    )
    .await;
    assert_eq!(r["voted"], json!(true), "valid signed vote: {r}");
    let weight = r["weight"].as_str().unwrap_or("").to_string();

    // 10. Same-choice replay: idempotent, same weight.
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": pid,
            "voter": hex::encode(proposer),
            "choice": "yes",
            "signature": vsig,
        }),
    )
    .await;
    assert_eq!(r["voted"], json!(true), "same-choice replay: {r}");
    assert_eq!(r["weight"].as_str().unwrap_or(""), weight);

    // 11. Different choice with a fresh valid signature: refused.
    let flip = sign_test_vote(chain, &proposer_key, &proposer, pid, VoteChoice::No);
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": pid,
            "voter": hex::encode(proposer),
            "choice": "no",
            "signature": flip,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already voted"),
        "different-choice replay must be refused: {r}"
    );

    // 12. Tampered choice: Yes-envelope presented as No.
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": pid,
            "voter": hex::encode(proposer),
            "choice": "no",
            "signature": vsig,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("vote failed"),
        "tampered vote must be refused: {r}"
    );

    // 13. Cross-chain vote.
    let cross_vmsg =
        crate::governance::Governance::gov_vote_message(chain + 1, pid, VoteChoice::Yes, &proposer);
    let cross_vsig = proposer_key
        .sign_message(chain + 1, &cross_vmsg)
        .unwrap()
        .to_hex();
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": pid,
            "voter": hex::encode(proposer),
            "choice": "yes",
            "signature": cross_vsig,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("vote failed"),
        "cross-chain vote must be refused: {r}"
    );

    // 14. Stakeless key, valid vote signature: refused (NotStaker).
    let lone_vmsg =
        crate::governance::Governance::gov_vote_message(chain, pid, VoteChoice::Yes, &lone);
    let lone_vsig = lone_key.sign_message(chain, &lone_vmsg).unwrap().to_hex();
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": pid,
            "voter": hex::encode(lone),
            "choice": "yes",
            "signature": lone_vsig,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no staked balance"),
        "stakeless voter must be refused: {r}"
    );

    // 15-17. Block-form twins: caller-signed txs admit without recording.
    // The recorded proposal above (direct, solo) is the baseline: block
    // submissions must leave it exactly alone.
    let recorded = st.governance.read().await.proposals.len();
    let (bfrom, bpk) = pq_pair(0xD1);
    st.engine
        .update_account(crate::state_engine::AccountState::new(
            bfrom,
            1_000_000_000_000,
        ))
        .await;
    let bheight = st.height.load(std::sync::atomic::Ordering::Relaxed) + 1;
    // 15. Propose tx admitted, nothing recorded.
    let bptx = crate::governance::Governance::gov_propose_tx(
        bfrom,
        0,
        500_000,
        1,
        1,
        99,
        "block twin".to_string(),
        GovAction::Signal("hi".to_string()),
        bheight,
    )
    .expect("test propose template must build");
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({ "tx": gov_tx_hex(&sign_gov_block_tx(0xD1, &bpk, bptx)) }),
    )
    .await;
    assert!(r.as_str().is_some(), "block-form propose must admit: {r}");
    // 16. Vote tx admitted, tally unmoved.
    let tally_before = st.governance.read().await.get(pid).map(|p| p.yes);
    let bvtx = crate::governance::Governance::gov_vote_tx(
        bfrom,
        1,
        500_000,
        1,
        1,
        pid,
        VoteChoice::Yes,
        bheight,
    );
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({ "tx": gov_tx_hex(&sign_gov_block_tx(0xD1, &bpk, bvtx)) }),
    )
    .await;
    assert!(r.as_str().is_some(), "block-form vote must admit: {r}");
    assert_eq!(st.mempool.read().await.len(), 2);
    let g = st.governance.read().await;
    assert_eq!(
        g.proposals.len(),
        recorded,
        "block-form admissions must not record proposals"
    );
    assert_eq!(
        g.get(pid).map(|p| p.yes),
        tally_before,
        "block-form admissions must not move tallies"
    );
    drop(g);
    // 17. A non-gov tx under the gov method name is refused, admitted
    // nowhere (the payload predicate is the method's promise).
    let plain = pq_tx(0xD2, [0xEEu8; 32], 10, 100_000, 0);
    st.engine
        .update_account(crate::state_engine::AccountState::new(
            plain.from, 10_000_000,
        ))
        .await;
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({ "tx": gov_tx_hex(&plain) }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("SysCallGovPropose"),
        "non-gov payload must be refused: {r}"
    );
    assert_eq!(
        st.mempool.read().await.len(),
        2,
        "refused payload must not enter the mempool"
    );
}

/// Multi-node direct writes stay refused (HDAE-GOV): on a two-staker set
/// the DIRECT propose/vote/execute forms refuse with the documented
/// escape-env reason — the vote/execute refusals prove the guard runs
/// FIRST (unknown ids would otherwise fail as `UnknownProposal`), while
/// the BLOCK form on the SAME set admits (that is how multi-node
/// governance works now: admission mutates nothing).
///
/// The escape env is pinned to explicit OFF (`0`, no-restore: `0` reads
/// exactly like the default-off unset for every guard in the suite, so
/// residue is harmless; the only concurrent setter is the runtime escape
/// test's microsecond window).
#[tokio::test]
async fn gov_direct_writes_refuse_on_multi_node() {
    use crate::governance::{GovAction, VoteChoice, GOV_MULTINODE_WRITES_ENV};
    std::env::set_var(GOV_MULTINODE_WRITES_ENV, "0");
    let st = test_state_with_token().await;
    let proposer_key = TestGovKey::falcon_from_seed(&[0xA1u8; 32]);
    let proposer = proposer_key.address();
    {
        let mut ledger = st.engine.staking_write().await;
        ledger
            .bond(proposer, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
            .unwrap();
        ledger
            .bond([0xB2u8; 32], crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
            .unwrap();
    }
    // Direct propose (valid envelope: the ONLY refusal cause is the guard).
    let title = "multi".to_string();
    let action = GovAction::Signal("hi".to_string());
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({
            "title": title,
            "type": "signal",
            "text": "hi",
            "proposer": hex::encode(proposer),
            "nonce": 1u64,
            "signature": sign_test_proposal(st.chain_id, &proposer_key, &proposer, &title, &action, 1),
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains(GOV_MULTINODE_WRITES_ENV),
        "multi-node propose must name the escape env: {r}"
    );
    // Direct vote for an UNKNOWN id: still the guard, never the lookup.
    let vsig = sign_test_vote(
        st.chain_id,
        &proposer_key,
        &proposer,
        999_999,
        VoteChoice::Yes,
    );
    let r = call_with_token(
        &st,
        "stell_vote",
        json!({
            "id": 999_999u64,
            "voter": hex::encode(proposer),
            "choice": "yes",
            "signature": vsig,
        }),
    )
    .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains(GOV_MULTINODE_WRITES_ENV),
        "multi-node vote must refuse at the gate, not at lookup: {r}"
    );
    // Direct execute of an UNKNOWN id: still the guard.
    let r = call_with_token(&st, "stell_executeProposal", json!({ "id": 999_999u64 })).await;
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains(GOV_MULTINODE_WRITES_ENV),
        "multi-node execute must refuse at the gate: {r}"
    );
    assert!(
        st.governance.read().await.proposals.is_empty(),
        "refused writes must not record anything"
    );
    assert_eq!(st.mempool.read().await.len(), 0);
    // Block form on the SAME set: admitted, nothing recorded.
    let (from, pk) = pq_pair(0xC1);
    st.engine
        .update_account(crate::state_engine::AccountState::new(
            from,
            1_000_000_000_000,
        ))
        .await;
    let height = st.height.load(std::sync::atomic::Ordering::Relaxed) + 1;
    let ptx = crate::governance::Governance::gov_propose_tx(
        from,
        0,
        500_000,
        1,
        1,
        1,
        "multi".to_string(),
        GovAction::Signal("hi".to_string()),
        height,
    )
    .expect("test propose template must build");
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({ "tx": gov_tx_hex(&sign_gov_block_tx(0xC1, &pk, ptx)) }),
    )
    .await;
    assert!(
        r.as_str().is_some(),
        "block form must admit on multi-node: {r}"
    );
    assert_eq!(st.mempool.read().await.len(), 1);
    assert!(
        st.governance.read().await.proposals.is_empty(),
        "admission must not record a proposal"
    );
}

/// Minimal decided-block shell for gov apply tests (same literal shape
/// as the `apply_floor_tests` block builder; the apply path consumes
/// decided blocks and never checks block signatures).
fn gov_block(
    txs: Vec<crate::sharding::Transaction>,
    height: u64,
    timestamp: u64,
) -> crate::sharding::Block {
    crate::sharding::Block {
        shard_id: crate::sharding::MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs.clone(),
        cross_shard_out: vec![],
        timestamp,
        proposer: [0x99u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: crate::mev::compute_order_merkle_root(&txs),
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
    }
}

/// Same lifecycle properties as the direct path, via blocks (HDAE-GOV):
/// a builder-built, caller-signed propose tx admitted through RPC opens
/// the proposal when its block applies (id/title/action/electorate
/// identical to the direct path), and builder-built vote txs in the next
/// block record the snapshot-weighted tally. Nothing is recorded or
/// tallied before the blocks apply.
#[tokio::test]
async fn gov_propose_and_vote_apply_via_blocks() {
    use crate::governance::{GovAction, ProposalStatus, VoteChoice};
    let st = test_state_with_token().await;
    // Test-only activation: the live gate flips via the const, never
    // this flag (see `enable_gov_ops_for_tests`).
    st.engine.enable_gov_ops_for_tests();
    let (proposer, proposer_pk) = pq_pair(0xA1);
    let (voter, voter_pk) = pq_pair(0xB2);
    {
        let mut ledger = st.engine.staking_write().await;
        ledger
            .bond(proposer, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
            .unwrap();
        ledger
            .bond(voter, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
            .unwrap();
    }
    st.engine
        .update_account(crate::state_engine::AccountState::new(
            proposer,
            1_000_000_000_000,
        ))
        .await;
    st.engine
        .update_account(crate::state_engine::AccountState::new(
            voter,
            1_000_000_000_000,
        ))
        .await;
    // The RPC admits the propose tx without recording anything.
    let action = GovAction::Signal("via blocks".to_string());
    let ptx = crate::governance::Governance::gov_propose_tx(
        proposer,
        0,
        500_000,
        1,
        1,
        1,
        "blk".to_string(),
        action.clone(),
        43,
    )
    .expect("test propose template must build");
    let ptx = sign_gov_block_tx(0xA1, &proposer_pk, ptx);
    let r = call_with_token(
        &st,
        "stell_submitProposal",
        json!({ "tx": gov_tx_hex(&ptx) }),
    )
    .await;
    assert!(r.as_str().is_some(), "propose tx must admit: {r}");
    assert!(
        st.engine.governance_read().await.proposals.is_empty(),
        "admission must not open the proposal"
    );
    // Block 43 applies it: same record the direct path would write.
    let out = st
        .engine
        .apply_block_transition(&gov_block(vec![ptx], 43, 1_700_000_000), 0)
        .await;
    assert_eq!(out.status, vec![true], "carrier step must succeed");
    {
        let g = st.engine.governance_read().await;
        let p = g.get(1).expect("the block must open proposal 1");
        assert_eq!(p.title, "blk");
        assert_eq!(p.action, action);
        assert_eq!(p.status, ProposalStatus::Open);
        assert_eq!(p.yes, 0, "no tally before any vote block");
    }
    // Vote txs (both stakers) admit cleanly, then block 44 tallies.
    let vtx_p = crate::governance::Governance::gov_vote_tx(
        proposer,
        1,
        500_000,
        1,
        1,
        1,
        VoteChoice::Yes,
        44,
    );
    let vtx_p = sign_gov_block_tx(0xA1, &proposer_pk, vtx_p);
    let vtx_v =
        crate::governance::Governance::gov_vote_tx(voter, 0, 500_000, 1, 1, 1, VoteChoice::Yes, 44);
    let vtx_v = sign_gov_block_tx(0xB2, &voter_pk, vtx_v);
    for (method, tx) in [("stell_vote", &vtx_p), ("stell_vote", &vtx_v)] {
        let r = call_with_token(&st, method, json!({ "tx": gov_tx_hex(tx) })).await;
        assert!(r.as_str().is_some(), "vote tx must admit: {r}");
    }
    let out = st
        .engine
        .apply_block_transition(&gov_block(vec![vtx_p, vtx_v], 44, 1_700_000_012), 0)
        .await;
    assert_eq!(out.status, vec![true, true]);
    let g = st.engine.governance_read().await;
    let p = g.get(1).expect("proposal 1");
    let one = crate::governance::PROPOSAL_MIN_STAKE_NANO as u128;
    assert_eq!(p.yes, 2 * one, "both snapshot weights tally yes");
    assert_eq!(p.no, 0);
}

/// `stell_getEvents` must answer a BOUNDED list: the receipt index holds
/// up to 50 000 receipts and every receipt can carry up to 256 events, so
/// an unfiltered contract query could otherwise answer with millions of
/// events — an unbounded response body on an unauthenticated read.
#[tokio::test]
async fn get_events_answer_is_bounded() {
    let st = test_state().await;
    let contract = [0x77u8; 32];
    {
        let mut idx = st.receipts.write().await;
        // 200 receipts x 20 events = 4 000 events for ONE contract.
        for i in 0..200u64 {
            let events: Vec<crate::contract::ContractEvent> = (0..20)
                .map(|j| crate::contract::ContractEvent {
                    contract,
                    topic: j as i64,
                    value: i as i64,
                })
                .collect();
            idx.insert(TxReceipt {
                tx_hash: [i as u8; 32],
                height: 1 + i,
                block_hash: [0u8; 32],
                index: 0,
                success: true,
                gas_limit: 0,
                fee_charged: 0,
                raw_tx: None,
                return_value: None,
                gas_used: None,
                contract_address: None,
                events,
            });
        }
    }
    let r = call(
        &st,
        "stell_getEvents",
        json!({ "contract": hex::encode(contract), "from_block": 0, "to_block": 1000 }),
    )
    .await;
    let arr = r.as_array().expect("must return an event array");
    assert_eq!(
        arr.len(),
        MAX_EVENTS_RETURNED,
        "the answer must be capped at MAX_EVENTS_RETURNED"
    );
    assert!(
        arr.len() < 4_000,
        "the answer must be far smaller than the stored event count"
    );
}

/// The subscription registry is bounded GLOBALLY, but one client must not
/// be able to take the WHOLE registry and starve every other subscriber.
#[tokio::test]
async fn subscriptions_are_bounded_per_client() {
    let hub = isolated_hub();
    // The per-client cap.
    for _ in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
        hub.subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.1"))
            .expect("a client must be able to hold its own subscriptions");
    }
    let err = hub
        .subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.1"))
        .expect_err("the per-client cap must refuse the next one");
    assert!(
        err.contains("per-client"),
        "the error must name the cap: {err}"
    );
    // A DIFFERENT client is unaffected.
    hub.subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.2"))
        .expect("another client must not be starved by the first one");
    // An unattributed subscription is not charged to anybody.
    hub.subscribe(SubscriptionTopic::NewHeads)
        .expect("an unattributed subscription must work");
}

/// `stell_estimateFee` clones the WHOLE engine state and runs a full SVM
/// execution, so it gets its OWN (much smaller) per-IP budget instead of
/// the generic one.
#[tokio::test]
async fn estimate_fee_has_its_own_per_ip_budget() {
    let st = test_state().await;
    // Own bucket (see `fresh_estimate_ip`): the hammering must start from
    // an empty window no matter what else runs in this process.
    let ip = fresh_estimate_ip();
    // The budget is finite: after it is exhausted the call is refused.
    // The limiter is a per-second fixed window on wall-clock seconds, so
    // ONE hammer of budget+1 rapid calls can straddle a second boundary,
    // take a fresh window, and see no refusal. Rapid consecutive rounds
    // cannot ALL straddle (boundaries are 1s apart, a round is
    // milliseconds), so repeating the hammer on the SAME ip forces the
    // refusal without weakening the limit: every round still allows at
    // most ESTIMATE_FEE_RATE_LIMIT_DEFAULT per window. (The exact
    // in-window 5-ok/6th-refused threshold is pinned deterministically by
    // the `check_at` unit test; this test pins the production path.)
    let mut refused = false;
    for _ in 0..4 {
        for _ in 0..(ESTIMATE_FEE_RATE_LIMIT_DEFAULT as usize + 1) {
            let r = call_from(
                &st,
                "stell_estimateFee",
                json!({ "from": hex::encode([0x11u8; 32]), "to": hex::encode([0x22u8; 32]) }),
                ip,
            )
            .await;
            if r["error"]
                .as_str()
                .unwrap_or("")
                .contains("budget exhausted")
            {
                refused = true;
                break;
            }
        }
        if refused {
            break;
        }
    }
    assert!(
        refused,
        "the estimate-fee budget must be enforced per IP (it clones the whole state)"
    );
    // A DIFFERENT IP is unaffected by the first one's exhaustion.
    let other = fresh_estimate_ip();
    let r = call_from(
        &st,
        "stell_estimateFee",
        json!({ "from": hex::encode([0x11u8; 32]), "to": hex::encode([0x22u8; 32]) }),
        other,
    )
    .await;
    assert!(
        r["error"].as_str().unwrap_or("").is_empty(),
        "another IP must not be starved by the first one's budget: {r}"
    );
}

// -----------------------------------------------------------------------
// TAIL-1: batched receipt hashing.
//
// `record_receipts_with_events` hashes with one reused hasher and one
// reused scratch buffer (pre-sized output). The receipts it files must be
// byte-identical to the old per-transaction path: the test below pins the
// old logic as a reference implementation and compares every filed field,
// including the pre-existing-receipt merge branch. No wire-format,
// quorum or state-transition change: receipts are RPC views, and these
// tests prove the views are unchanged.
// -----------------------------------------------------------------------

/// The pre-batch receipt logic, frozen as the differential reference:
/// one hasher + one payload buffer per transaction, one bincode alloc per
/// receipt, and the same publish fan-out. Any divergence from
/// `record_receipts_with_events` fails.
async fn reference_record_receipts(
    st: &Arc<RpcState>,
    height: u64,
    block_hash: [u8; 32],
    txs: &[crate::sharding::Transaction],
    statuses: &[bool],
    fees: &[u64],
    events: &[Vec<crate::contract::ContractEvent>],
) {
    let mut idx = st.receipts.write().await;
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let success = statuses.get(i).copied().unwrap_or(false);
        let raw_tx = bincode::serialize(tx).ok().map(hex::encode);
        let h = tx.compute_tx_hash();
        hashes.push(h);
        let (rv, gu, ev, ca) = if let Some(existing) = idx.get(&h) {
            let evs = if !existing.events.is_empty() {
                existing.events.clone()
            } else {
                events.get(i).cloned().unwrap_or_default()
            };
            (
                existing.return_value,
                existing.gas_used,
                evs,
                existing.contract_address,
            )
        } else {
            (None, None, events.get(i).cloned().unwrap_or_default(), None)
        };
        idx.insert(TxReceipt {
            tx_hash: h,
            height,
            block_hash,
            index: i as u32,
            success,
            gas_limit: tx.gas_limit,
            fee_charged: fees
                .get(i)
                .copied()
                .unwrap_or(if success { tx.gas_limit } else { 0 }),
            raw_tx,
            return_value: rv,
            gas_used: gu,
            events: ev,
            contract_address: ca,
        });
    }
    drop(idx);
    for (i, tx) in txs.iter().enumerate() {
        let success = statuses.get(i).copied().unwrap_or(false);
        let hash = hashes[i];
        publish_new_tx(
            hash,
            tx.from,
            tx.to,
            tx.amount,
            if success { "confirmed" } else { "failed" },
        );
        if let Some(evs) = events.get(i) {
            for e in evs {
                publish_contract_event(e, height, hash);
            }
        }
    }
}

fn assert_receipts_equal(a: &TxReceipt, b: &TxReceipt, ctx: &str) {
    assert_eq!(a.tx_hash, b.tx_hash, "{ctx}: tx_hash");
    assert_eq!(a.height, b.height, "{ctx}: height");
    assert_eq!(a.block_hash, b.block_hash, "{ctx}: block_hash");
    assert_eq!(a.index, b.index, "{ctx}: index");
    assert_eq!(a.success, b.success, "{ctx}: success");
    assert_eq!(a.gas_limit, b.gas_limit, "{ctx}: gas_limit");
    assert_eq!(a.fee_charged, b.fee_charged, "{ctx}: fee_charged");
    assert_eq!(a.raw_tx, b.raw_tx, "{ctx}: raw_tx");
    assert_eq!(a.return_value, b.return_value, "{ctx}: return_value");
    assert_eq!(a.gas_used, b.gas_used, "{ctx}: gas_used");
    assert_eq!(a.events, b.events, "{ctx}: events");
    assert_eq!(
        a.contract_address, b.contract_address,
        "{ctx}: contract_address"
    );
}

fn receipt_batch_txs(n: usize) -> Vec<crate::sharding::Transaction> {
    (0..n)
        .map(|i| {
            let mut from = [0u8; 32];
            from[0..8]
                .copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
            receipt_tx(
                from[0].wrapping_add(from[7]).wrapping_add(i as u8),
                i as u64,
            )
        })
        .collect()
}

#[tokio::test]
async fn record_receipts_batched_is_byte_identical_to_reference() {
    let txs = receipt_batch_txs(256);
    let statuses: Vec<bool> = (0..txs.len()).map(|i| i % 3 != 0).collect();
    let fees: Vec<u64> = (0..txs.len()).map(|i| 1000 + i as u64).collect();
    let events: Vec<Vec<crate::contract::ContractEvent>> = (0..txs.len())
        .map(|i| {
            if i % 2 == 0 {
                vec![crate::contract::ContractEvent {
                    contract: [i as u8; 32],
                    topic: i as i64,
                    value: -(i as i64),
                }]
            } else {
                vec![]
            }
        })
        .collect();

    // Pre-existing receipts on BOTH states: exercises the merge branch
    // (kept return_value/gas_used/contract_address, kept non-empty events).
    for st in [test_state().await, test_state().await] {
        let _ = st;
    }
    let batched_st = test_state().await;
    let ref_st = test_state().await;
    for st in [&batched_st, &ref_st] {
        st.receipts.write().await.insert(TxReceipt {
            tx_hash: txs[0].compute_tx_hash(),
            height: 1,
            block_hash: [0xAA; 32],
            index: 0,
            success: true,
            gas_limit: txs[0].gas_limit,
            fee_charged: 7,
            raw_tx: None,
            return_value: Some(42),
            gas_used: Some(9000),
            events: vec![crate::contract::ContractEvent {
                contract: [0xE0; 32],
                topic: 1,
                value: 2,
            }],
            contract_address: Some([0xC0; 32]),
        });
    }

    batched_st
        .record_receipts_with_events(77, [0xAB; 32], &txs, &statuses, &fees, &events)
        .await;
    reference_record_receipts(&ref_st, 77, [0xAB; 32], &txs, &statuses, &fees, &events).await;

    let b = batched_st.receipts.read().await;
    let r = ref_st.receipts.read().await;
    assert_eq!(b.len(), r.len(), "same number of receipts filed");
    for tx in &txs {
        let h = tx.compute_tx_hash();
        let rb = b
            .get(&h)
            .unwrap_or_else(|| panic!("batched missing {}", hex::encode(h)));
        let rr = r
            .get(&h)
            .unwrap_or_else(|| panic!("reference missing {}", hex::encode(h)));
        assert_receipts_equal(rb, rr, &hex::encode(h));
    }
    // The pre-existing receipt's carried fields survive on both paths.
    let kept = b.get(&txs[0].compute_tx_hash()).unwrap();
    assert_eq!(kept.return_value, Some(42));
    assert_eq!(kept.gas_used, Some(9000));
    assert_eq!(kept.contract_address, Some([0xC0; 32]));
    assert_eq!(kept.events.len(), 1, "non-empty existing events are kept");
}

/// Perf: batched vs reference receipt recording over a block-sized batch.
/// Best-of-N per path (interleaved) to ride out allocator noise; prints
/// measured ms for the report. The hard assertion is byte equality.
#[tokio::test]
async fn perf_record_receipts_batched_vs_reference() {
    let txs = receipt_batch_txs(20_000);
    let statuses: Vec<bool> = (0..txs.len()).map(|i| i % 2 == 0).collect();
    let fees: Vec<u64> = (0..txs.len()).map(|i| 1000 + i as u64).collect();
    let events: Vec<Vec<crate::contract::ContractEvent>> = vec![vec![]; txs.len()];

    // Interleaved best-of-5: each iteration files into a FRESH state so
    // the receipt index starts empty every time.
    let mut best_reference = f64::INFINITY;
    let mut best_batched = f64::INFINITY;
    for _ in 0..5 {
        let ref_st = test_state().await;
        let t0 = std::time::Instant::now();
        reference_record_receipts(&ref_st, 77, [0xAB; 32], &txs, &statuses, &fees, &events).await;
        best_reference = best_reference.min(t0.elapsed().as_secs_f64() * 1000.0);

        let batched_st = test_state().await;
        let t0 = std::time::Instant::now();
        batched_st
            .record_receipts_with_events(77, [0xAB; 32], &txs, &statuses, &fees, &events)
            .await;
        best_batched = best_batched.min(t0.elapsed().as_secs_f64() * 1000.0);
    }

    let ref_st = test_state().await;
    reference_record_receipts(&ref_st, 77, [0xAB; 32], &txs, &statuses, &fees, &events).await;
    let batched_st = test_state().await;
    batched_st
        .record_receipts_with_events(77, [0xAB; 32], &txs, &statuses, &fees, &events)
        .await;
    let b = batched_st.receipts.read().await;
    let r = ref_st.receipts.read().await;
    assert_eq!(b.len(), r.len());
    for tx in &txs {
        let h = tx.compute_tx_hash();
        assert_receipts_equal(b.get(&h).unwrap(), r.get(&h).unwrap(), &hex::encode(h));
    }
    eprintln!(
        "[perf] record_receipts 20k txs (best of 5): reference={best_reference:.2}ms batched={best_batched:.2}ms speedup={:.2}x",
        if best_batched > 0.0 { best_reference / best_batched } else { f64::INFINITY },
    );
}

/// WS hardening consts stay consistent with the HTTP surface they mirror.
/// (The positivity/ordering shape is enforced at compile time next to
/// the consts; this test pins the cross-surface equalities.)
#[test]
fn ws_hardening_consts_are_sane() {
    // The WS frame cap mirrors the HTTP body cap: no transport smuggles
    // a bigger request than the other.
    assert_eq!(WS_MAX_MESSAGE_BYTES, MAX_RPC_BODY);
    // The per-message general budget mirrors the standalone transport
    // budget: same per-IP fixed-window shape, same ceiling.
    assert_eq!(
        WS_GENERAL_RATE_LIMIT_DEFAULT, STANDALONE_RATE_LIMIT_DEFAULT,
        "WS general budget must stay symmetric to the standalone HTTP budget"
    );
}

/// Batch caps stay consistent with the single-call bounds they mirror.
#[test]
fn rpc_batch_consts_are_sane() {
    // GATE: black_box defeats const-folding; pins must fail loudly if changed.
    assert!(std::hint::black_box(MAX_RPC_BATCH_ITEMS) > 0);
    // The total batch byte bound is a multiple of the single-call body
    // bound (currently 1x: a batch can never exceed a single call's
    // bound, so batches add no new DoS surface).
    assert_eq!(MAX_RPC_BATCH_BYTES, MAX_RPC_BODY);
    assert!(std::hint::black_box(MAX_RPC_BATCH_BYTES) <= MAX_RPC_BODY);
}

/// Same as `test_state`, but with an API token configured so the gated
/// arms can prove per-item auth inside a batch.
async fn test_state_authed() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "inf1:test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(crate::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(crate::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: Some("test-token".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

/// Happy batch: mixed methods (incl. 1 bad-params + 1 unknown + 1
/// malformed item + 1 notification) — every item answers independently,
/// one bad call never fails its siblings, order is preserved.
#[tokio::test]
async fn rpc_batch_happy_mixed_per_item_isolation() {
    let st = test_state().await;
    let items = vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "stell_chainId", "params": []}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "stell_nopeNotReal", "params": []}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "stell_sendRawTransaction", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 5}),
        json!({"jsonrpc": "2.0", "method": "eth_chainId", "params": []}),
    ];
    let raw = serde_json::to_string(&items).unwrap();
    let out = match handle_rpc_batch_call(&st, &items, raw.len(), None, None).await {
        Ok(v) => v,
        Err(_) => panic!("valid batch must dispatch"),
    };
    // 6 items minus 1 notification = 5 responses, in request order.
    assert_eq!(out.len(), 5);
    let body = serde_json::to_value(&out).unwrap();
    assert_eq!(body[0]["id"], 1);
    assert_eq!(body[0]["result"], "0x167d");
    assert_eq!(body[1]["id"], 2);
    assert_eq!(body[1]["result"], 777);
    assert_eq!(body[2]["id"], 3);
    assert_eq!(body[2]["error"]["code"], -32601);
    assert_eq!(body[3]["id"], 4);
    assert_eq!(body[3]["error"]["code"], -32602);
    // Malformed item: per-item `-32600` with a null id (spec: the id
    // could not be detected), siblings unaffected.
    assert_eq!(body[4]["id"], Value::Null);
    assert_eq!(body[4]["error"]["code"], -32600);
}

/// Batch ordering follows REQUEST order, not id order.
#[tokio::test]
async fn rpc_batch_preserves_request_order() {
    let st = test_state().await;
    let items = vec![
        json!({"jsonrpc": "2.0", "id": 30, "method": "stell_chainId", "params": []}),
        json!({"jsonrpc": "2.0", "id": 10, "method": "eth_chainId", "params": []}),
        json!({"jsonrpc": "2.0", "id": 20, "method": "stell_chainId", "params": []}),
    ];
    let raw = serde_json::to_string(&items).unwrap();
    let out = match handle_rpc_batch_call(&st, &items, raw.len(), None, None).await {
        Ok(v) => v,
        Err(_) => panic!("valid batch must dispatch"),
    };
    let ids: Vec<i64> = out
        .iter()
        .map(|r| serde_json::to_value(r).unwrap()["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, vec![30, 10, 20]);
}

/// Overall caps fail closed on the WHOLE batch (single `-32600` object,
/// no partial answers): empty, too many items, too many bytes.
#[tokio::test]
async fn rpc_batch_caps_refuse_whole_batch() {
    let st = test_state().await;
    // Empty batch.
    let empty: Vec<Value> = vec![];
    let refused = match handle_rpc_batch_call(&st, &empty, 2, None, None).await {
        Err(e) => e,
        Ok(_) => panic!("empty batch must be refused"),
    };
    assert_eq!(
        serde_json::to_value(&refused).unwrap()["error"]["code"],
        -32600
    );
    // One item over the item cap.
    let big: Vec<Value> = (0..MAX_RPC_BATCH_ITEMS + 1)
        .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}))
        .collect();
    let raw = serde_json::to_string(&big).unwrap();
    let refused = match handle_rpc_batch_call(&st, &big, raw.len(), None, None).await {
        Err(e) => e,
        Ok(_) => panic!("over-cap batch must be refused whole"),
    };
    assert_eq!(
        serde_json::to_value(&refused).unwrap()["error"]["code"],
        -32600
    );
    // At exactly the cap it dispatches (responses may be rate-shaped but
    // the batch itself is accepted).
    let at_cap: Vec<Value> = (0..MAX_RPC_BATCH_ITEMS)
        .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}))
        .collect();
    let raw = serde_json::to_string(&at_cap).unwrap();
    assert!(raw.len() <= MAX_RPC_BATCH_BYTES);
    let out = match handle_rpc_batch_call(&st, &at_cap, raw.len(), None, None).await {
        Ok(v) => v,
        Err(_) => panic!("at-cap batch must dispatch"),
    };
    assert_eq!(out.len(), MAX_RPC_BATCH_ITEMS);
    // Byte cap: same items, lied-about body length over the bound.
    let refused =
        match handle_rpc_batch_call(&st, &at_cap, MAX_RPC_BATCH_BYTES + 1, None, None).await {
            Err(e) => e,
            Ok(_) => panic!("over-bytes batch must be refused whole"),
        };
    assert_eq!(
        serde_json::to_value(&refused).unwrap()["error"]["code"],
        -32600
    );
}

/// Auth is per-item and mirrors the single-call shape exactly: a gated
/// arm without its token fails with `-32001` while its siblings succeed,
/// and a per-item params token opens just that item.
#[tokio::test]
async fn rpc_batch_auth_is_per_item() {
    let st = test_state_authed().await;
    let items = vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "stell_mempoolDump", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "stell_chainId", "params": []}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "stell_mempoolDump", "params": {"token": "test-token"}}),
    ];
    let raw = serde_json::to_string(&items).unwrap();
    let out = match handle_rpc_batch_call(&st, &items, raw.len(), None, None).await {
        Ok(v) => v,
        Err(_) => panic!("valid batch must dispatch"),
    };
    assert_eq!(out.len(), 3);
    let body = serde_json::to_value(&out).unwrap();
    // No token -> same `-32001` as the single call, sibling unaffected.
    assert_eq!(body[0]["error"]["code"], -32001);
    assert_eq!(body[1]["result"], 777);
    // Per-item params token opens just that item.
    assert!(body[2]["error"].is_null());
    assert!(body[2]["result"].is_array());
}

/// Rate-limit audit: EVERY public method maps to at least one bucket —
/// no unbucketed method. The list below is the full `dispatch` surface
/// (EVM + stell arms, both invalidation aliases) plus the whole native
/// namespace; if a method is added to `dispatch` without a bucket entry
/// here, extend BOTH the table and this list.
#[test]
fn rate_bucket_table_covers_every_public_method() {
    const TRANSPORT_ONLY: &[&str] = &[
        // EVM adapter surface (all sit under the transport limiter only).
        "eth_chainId",
        "net_version",
        "web3_clientVersion",
        "net_listening",
        "net_peerCount",
        "eth_syncing",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_estimateGas",
        "eth_feeHistory",
        "eth_getCode",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getTransactionReceipt",
        "eth_getTransactionByHash",
        "eth_getBlockTransactionCountByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getTransactionByBlockHashAndIndex",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getUncleCountByBlockHash",
        "eth_getUncleCountByBlockNumber",
        "eth_getUncleByBlockHashAndIndex",
        "eth_getUncleByBlockNumberAndIndex",
        "eth_call",
        "eth_newBlockFilter",
        "eth_newPendingTransactionFilter",
        "eth_newFilter",
        "eth_getFilterChanges",
        "eth_getFilterLogs",
        "eth_uninstallFilter",
        "eth_getLogs",
        "eth_getStorageAt",
        "eth_sendRawTransaction",
        // stell reads/writes under the transport limiter only.
        "stell_chainId",
        "stell_nodeId",
        "stell_blockNumber",
        "stell_syncing",
        "stell_getStateRoot",
        "stell_latestBlocks",
        "stell_getShards",
        "stell_getShardTopology",
        "stell_getBlock",
        "stell_getBlockTransactions",
        "stell_epochKey",
        "stell_sendSealedTransaction",
        "stell_mevStats",
        "stell_getBalance",
        "stell_getHistoricalRoot",
        "stell_getFinalizedHeader",
        "stell_getFinalizedCheckpoint",
        "stell_getEpochRoot",
        "stell_bridgeDeposit",
        "stell_bridgeDispute",
        "stell_tokenBalance",
        "stell_tokenSupply",
        "stell_tokenResolve",
        "stell_listTokens",
        "stell_getTransactionReceipt",
        "stell_getEvents",
        "stell_getTransactionStatus",
        "stell_stakeOf",
        "stell_getValidatorStatus",
        "stell_zkmlCapabilities",
        "stell_getValidators",
        "stell_getPqKey",
        "stell_getPqRegistryStatus",
        "stell_proposal",
        "stell_listProposals",
        "stell_governanceParams",
        "stell_mempoolSize",
        "stell_baseFee",
        "stell_verifyMessage",
        "stell_verifyTypedData",
        "stell_sendRawTransaction",
        "stell_pmmState",
        "stell_orderBook",
        "stell_sessionBudget",
        "stell_getContractAbi",
        "stell_verifyContractSource",
        "stell_getContractSource",
        "stell_registerContractSource",
        "stell_getContractReceipt",
        "stell_getInvalidations",
        "stell_invalidationFeed",
        "stell_unsubscribe",
        "stell_getSubscriptions",
    ];
    const EXPENSIVE_HTTP_AND_WS: &[&str] = &["stell_estimateFee"];
    const EXPENSIVE_WS_EXTRA: &[&str] = &[
        "stell_getProof",
        "stell_getArchiveProof",
        "stell_getBalanceSpv",
        "stell_tokenBalanceSpv",
        "stell_runGetMethod",
    ];
    const SUBSCRIPTION_CAPPED: &[&str] = &["stell_subscribe"];
    const FAUCET_CAPPED: &[&str] = &["stell_faucet"];
    const AUTH_GATED: &[&str] = &[
        "stell_mempoolDump",
        "stell_submitProposal",
        "stell_vote",
        "stell_executeProposal",
        "stell_signMessage",
        "stell_signTypedData",
        "stell_deployContract",
        "stell_callContract",
        "stell_submitPriceFeed",
        "stell_submitPqPriceFeed",
        "stell_pmmBuy",
        "stell_pmmSell",
    ];
    const NATIVE_NAMESPACE: &[&str] = &[
        "stell_tokenTransfer",
        "stell_tokenBalanceOf",
        "stell_tokenMetadata",
        "stell_tokenAllowance",
        "stell_tokenMint",
        "stell_tokenBurn",
        "stell_tokenApprove",
        "stell_tokenTransferFrom",
        "stell_tokenCreate",
        "stell_stakeBond",
        "stell_stakeUnbond",
        "stell_stakeWithdraw",
        "stell_delegate",
        "stell_undelegate",
        "stell_claimRewards",
        "stell_bridgeDepositPrepare",
        "stell_bridgeWithdraw",
        "stell_bridgeStatus",
        "stell_bridgeAttestStatus",
        "stell_bridgeReleaseEstimate",
        "stell_bridgeDeposits",
        "stell_orderBookPlace",
        "stell_orderBookCancel",
        "stell_orderBookSnapshot",
        "stell_placeOrder",
        "stell_cancelOrder",
        "stell_sessionKeyRegister",
        "stell_sessionKeyRevoke",
        "stell_sessionKeys",
        "stell_oraclePrice",
        "stell_oracleFeeds",
        "stell_nativeApi",
    ];
    // Every native method the dispatcher knows must be transport-bucketed.
    for m in crate::native_api::METHODS {
        assert!(
            NATIVE_NAMESPACE.contains(&m.name),
            "native method `{}` missing from the audit list",
            m.name
        );
        assert!(
            crate::native_api::is_native_method(m.name),
            "audit list entry `{}` is not a native method",
            m.name
        );
    }
    let mut all: Vec<&str> = Vec::new();
    all.extend_from_slice(TRANSPORT_ONLY);
    all.extend_from_slice(EXPENSIVE_HTTP_AND_WS);
    all.extend_from_slice(EXPENSIVE_WS_EXTRA);
    all.extend_from_slice(SUBSCRIPTION_CAPPED);
    all.extend_from_slice(FAUCET_CAPPED);
    all.extend_from_slice(AUTH_GATED);
    all.extend_from_slice(NATIVE_NAMESPACE);
    // No method listed twice under two categories (the bucket SETS may
    // overlap, but each method has exactly one audit row).
    let mut seen = std::collections::HashSet::new();
    for m in &all {
        assert!(seen.insert(*m), "method `{m}` listed in two audit rows");
    }
    // The table covers 141 public methods (143 minus the 3 removed
    // shielded methods, plus `stell_submitPqPriceFeed`); a dispatch arm
    // added without updating the table keeps this count stale on purpose
    // — bump it.
    // GATE (Ristretto excision): shieldedTransfer/shieldedBalance/unshield gone.
    assert_eq!(all.len(), 141, "audit list size drifted: recount dispatch");
    for m in &all {
        let buckets = rpc_rate_buckets(m);
        assert!(
            !buckets.is_empty(),
            "public method `{m}` has no rate-limit bucket"
        );
        assert!(
            buckets.contains(&"transport"),
            "public method `{m}` must sit under the transport limiter"
        );
        for b in buckets {
            assert!(
                [
                    "transport",
                    "expensive",
                    "expensive-ws",
                    "subscription",
                    "faucet",
                    "auth"
                ]
                .contains(b),
                "method `{m}` names an unknown bucket `{b}`"
            );
        }
    }
    // Spot-check the special rows (the table is not just "transport").
    assert!(rpc_rate_buckets("stell_estimateFee").contains(&"expensive"));
    assert!(rpc_rate_buckets("stell_getProof").contains(&"expensive-ws"));
    assert!(!rpc_rate_buckets("stell_getProof").contains(&"expensive"));
    assert!(rpc_rate_buckets("stell_subscribe").contains(&"subscription"));
    assert!(rpc_rate_buckets("stell_faucet").contains(&"faucet"));
    assert!(rpc_rate_buckets("stell_mempoolDump").contains(&"auth"));
    assert!(!rpc_rate_buckets("stell_getBalance").contains(&"auth"));
    // Unknown methods map to nothing (the `-32601` arm has no bucket).
    assert!(rpc_rate_buckets("stell_nopeNotReal").is_empty());
    assert!(rpc_rate_buckets("").is_empty());
}

#[tokio::test]
async fn submit_pq_price_feed_accepts_falcon512_and_alias() {
    let st = test_state_with_token().await;
    let (from, _) = pq_pair(0xD1);
    st.engine
        .update_account(AccountState::new(from, 1_000_000))
        .await;

    let publisher = crate::post_quantum::FalconKeypair::generate_from_seed(0x55);
    let feed = crate::oracle::PqPriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
    assert!(feed.verify(), "PQ feed fixture must verify");

    // 1. Accepted via `stell_submitPriceFeed` without writing oracle state.
    let tx1 = pq_tx_payload(
        0xD1,
        from,
        0,
        100_000,
        0,
        vec![crate::svm::OpCode::SysCallSubmitPqPriceFeed(Box::new(
            feed.clone(),
        ))],
    );
    let root_before = st.engine.get_state_root().await;
    let res1 = call_with_token(
        &st,
        "stell_submitPriceFeed",
        json!({ "tx": hex::encode(bincode::serialize(&tx1).unwrap()) }),
    )
    .await;
    assert!(
        res1.get("error").is_none(),
        "PQ feed must be admitted via stell_submitPriceFeed: {res1}"
    );
    assert_eq!(st.mempool.read().await.len(), 1);
    assert_eq!(st.engine.get_state_root().await, root_before);
    assert!(st.engine.oracle_read().await.feeds.is_empty());

    // 2. Accepted via alias `stell_submitPqPriceFeed`.
    let tx2 = pq_tx_payload(
        0xD1,
        from,
        0,
        100_000,
        1,
        vec![crate::svm::OpCode::SysCallSubmitPqPriceFeed(Box::new(
            feed.clone(),
        ))],
    );
    let res2 = call_with_token(
        &st,
        "stell_submitPqPriceFeed",
        json!({ "tx": hex::encode(bincode::serialize(&tx2).unwrap()) }),
    )
    .await;
    assert!(
        res2.get("error").is_none(),
        "PQ feed must be admitted via stell_submitPqPriceFeed: {res2}"
    );
    assert_eq!(st.mempool.read().await.len(), 2);

    // 3. Tampered PQ feed signature is refused on both methods.
    let mut bad_feed = feed;
    bad_feed.falcon_sig[0] ^= 0xFF;
    let bad_tx = pq_tx_payload(
        0xD1,
        from,
        0,
        100_000,
        2,
        vec![crate::svm::OpCode::SysCallSubmitPqPriceFeed(Box::new(
            bad_feed,
        ))],
    );
    let raw_bad = hex::encode(bincode::serialize(&bad_tx).unwrap());
    for method in ["stell_submitPriceFeed", "stell_submitPqPriceFeed"] {
        let rej = call_with_token(&st, method, json!({ "tx": raw_bad.clone() })).await;
        assert!(
            rej["error"]
                .as_str()
                .unwrap_or_default()
                .contains("validly signed price feed"),
            "tampered PQ feed must be refused on {method}: {rej}"
        );
    }
    assert_eq!(st.mempool.read().await.len(), 2);
}

#[tokio::test]
async fn register_contract_source_supports_pq_falcon512() {
    let st = test_state().await;
    let (creator, kp) = cached_pq_test_key(0xD2);
    let wasm = wat::parse_str(VERIFY_WAT).unwrap();
    let addr = st.engine.deploy_contract(*creator, wasm, 0).await.unwrap();
    let addr_hex = hex::encode(addr);

    let verify_res = call(
        &st,
        "stell_verifyContractSource",
        json!({ "contract": addr_hex, "source": VERIFY_WAT, "compiler": "wat2wasm-1.0" }),
    )
    .await;
    assert_eq!(verify_res["verified"], json!(true));
    let source_hash_hex = verify_res["source_hash"].as_str().unwrap().to_string();
    let shash: [u8; 32] = hex::decode(&source_hash_hex).unwrap().try_into().unwrap();

    let msg = crate::contract_source::register_message(&addr, &shash);
    let sig = kp.sign(&msg);
    let env = crate::sharding::PqSignatureEnvelope::new_explicit(
        crate::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
    )
    .encode();

    let reg_res = call(
        &st,
        "stell_registerContractSource",
        json!({
            "contract": addr_hex,
            "source_hash": source_hash_hex,
            // F7: registration re-runs the build; the source is mandatory.
            "source": VERIFY_WAT,
            "compiler": "wat2wasm-1.0",
            "signature": hex::encode(&env),
        }),
    )
    .await;
    assert_eq!(
        reg_res["registered"],
        json!(true),
        "PQ1 registration must succeed: {reg_res}"
    );

    let get_res = call(
        &st,
        "stell_getContractSource",
        json!({ "contract": addr_hex }),
    )
    .await;
    assert_eq!(get_res["verified"], json!(true));
    assert_eq!(get_res["source_hash"], json!(source_hash_hex));
}

#[tokio::test]
async fn sse_enforces_per_ip_subscription_cap() {
    isolated_hub();
    let ip1: std::net::SocketAddr = "10.20.30.40:5000".parse().unwrap();
    let ip2: std::net::SocketAddr = "10.20.30.41:5001".parse().unwrap();
    let mut active_streams = Vec::new();
    for _ in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
        let resp = sse_handler(
            axum::http::HeaderMap::new(),
            Some(axum::extract::ConnectInfo(ip1)),
            Query(StreamQuery {
                sub_id: None,
                topics: Some("newHeads".to_string()),
                contract: None,
                event_topics: None,
            }),
        )
        .await
        .expect("within per-IP SSE cap");
        active_streams.push(resp);
    }
    let rejected = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(ip1)),
        Query(StreamQuery {
            sub_id: None,
            topics: Some("newHeads".to_string()),
            contract: None,
            event_topics: None,
        }),
    )
    .await;
    assert_eq!(
        rejected.err(),
        Some(axum::http::StatusCode::TOO_MANY_REQUESTS),
        "exceeding per-IP SSE cap must return 429"
    );
    let other = sse_handler(
        axum::http::HeaderMap::new(),
        Some(axum::extract::ConnectInfo(ip2)),
        Query(StreamQuery {
            sub_id: None,
            topics: Some("newHeads".to_string()),
            contract: None,
            event_topics: None,
        }),
    )
    .await
    .expect("a different IP must remain unaffected");
    drop(other);
    drop(active_streams);
}

// ===========================================================================
// API-defect regressions (2026-11-19): block tag resolution, native
// transaction lookup, historical-state honesty, restart body reconstruction.
// ===========================================================================

#[tokio::test]
async fn stell_get_block_accepts_tags_positional_and_hex_selectors() {
    let st = test_state().await;
    st.record_block(41, [0x41; 32], 1, 1_700_000_041).await;
    st.record_block(42, [0x42; 32], 2, 1_700_000_042).await;

    // Every shape the eth adapter accepts must resolve the SAME committed
    // height. Before the fix only `{"height": <u64>}` worked; `"latest"` and
    // all positional/hex forms fell through to the "not available" error.
    for params in [
        json!({ "height": "latest" }),
        json!("latest"),
        json!(42),
        json!([42]),
        json!(["0x2a"]),
        json!({ "height": "0x2a" }),
        json!({ "height": 42 }),
    ] {
        let r = call(&st, "stell_getBlock", params.clone()).await;
        assert_eq!(
            r["height"],
            json!(42),
            "stell_getBlock {params} must resolve the head, got {r}"
        );
        assert_eq!(r["hash"], json!(hex::encode([0x42u8; 32])));
        // The sibling read must speak the same selector dialect.
        let txs = call(&st, "stell_getBlockTransactions", params).await;
        assert_eq!(
            txs["height"],
            json!(42),
            "stell_getBlockTransactions must resolve the same selector"
        );
    }

    // Above-tip tags/heights stay an honest not-available error, never a
    // fabricated block.
    for params in [json!({ "height": 43 }), json!("0x2b")] {
        let r = call(&st, "stell_getBlock", params).await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("above this node's tip"),
            "{r}"
        );
    }
    // Malformed selector is a params error.
    let bad = call(&st, "stell_getBlock", json!({ "height": "not-a-tag" })).await;
    assert!(bad["error"]
        .as_str()
        .unwrap_or_default()
        .contains("invalid"));
}

#[tokio::test]
async fn stell_get_transaction_by_hash_serves_finalized_and_pending_honestly() {
    let st = test_state().await;
    let block_hash = [0x5Au8; 32];
    let tx = receipt_tx(0xD7, 0);
    let tx_hash = tx.compute_tx_hash();
    st.record_block(30, block_hash, 1, 1_700_000_030).await;
    st.record_receipts(30, block_hash, std::slice::from_ref(&tx), &[true], &[7])
        .await;

    let r = call(
        &st,
        "stell_getTransactionByHash",
        json!([hex::encode(tx_hash)]),
    )
    .await;
    assert_eq!(r["tx_hash"], json!(hex::encode(tx_hash)));
    assert_eq!(r["status"], json!("success"));
    assert_eq!(r["height"], json!(30));
    assert_eq!(r["from"], json!(hex::encode(tx.from)));
    assert_eq!(r["to"], json!(hex::encode(tx.to)));
    assert_eq!(r["amount"], json!(tx.amount.to_string()));
    assert_eq!(r["body_available"], json!(true));

    // Pending pool body is served as pending, with no finalized height.
    let pending = receipt_tx(0xD8, 1);
    let pending_from = pending.from;
    let pending_hash = pending.compute_tx_hash();
    st.mempool
        .write()
        .await
        .add(pending)
        .expect("admit fixture");
    let p = call(
        &st,
        "stell_getTransactionByHash",
        json!({ "hash": hex::encode(pending_hash) }),
    )
    .await;
    assert_eq!(p["status"], json!("pending"));
    assert!(p["height"].is_null(), "{p}");
    assert_eq!(p["from"], json!(hex::encode(pending_from)));

    // Unknown hashes (object/bare/array shapes) are honestly unknown.
    for params in [
        json!({ "hash": hex::encode([0xEEu8; 32]) }),
        json!(hex::encode([0xEEu8; 32])),
        json!([hex::encode([0xEEu8; 32])]),
    ] {
        let u = call(&st, "stell_getTransactionByHash", params).await;
        assert_eq!(u["status"], json!("unknown"));
    }
    let missing = call(&st, "stell_getTransactionByHash", json!([])).await;
    assert!(missing["error"]
        .as_str()
        .unwrap_or_default()
        .contains("missing tx hash"));
}

#[tokio::test]
async fn historical_state_tags_are_refused_not_relabelled_as_current() {
    let st = test_state().await; // head = 42
    let addr = hex::encode([0x11u8; 32]);
    let cases: Vec<(&str, Value)> = vec![
        ("eth_getBalance", json!([addr.clone(), "0x1"])),
        ("eth_getTransactionCount", json!([addr.clone(), "0x1"])),
        ("eth_getCode", json!([addr.clone(), "0x1"])),
        ("eth_getStorageAt", json!([addr.clone(), "0x0", "0x1"])),
        ("eth_call", json!([{ "data": "0x" }, "0x1"])),
    ];
    for (method, params) in cases {
        let r = call(&st, method, params.clone()).await;
        let msg = r["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains("historical state") && msg.contains("not available"),
            "{method} {params} must refuse historical state, got {r}"
        );
    }
    // The same methods still answer for the current head.
    let bal = call(&st, "eth_getBalance", json!([addr, "latest"])).await;
    assert_eq!(bal, json!("0x0"));
    let code = call(&st, "eth_getCode", json!([addr, "latest"])).await;
    assert_eq!(code, json!("0x"));
}

#[tokio::test]
async fn restart_hydrated_tx_lookup_never_fabricates_a_zero_sender() {
    // Receipts restored from the durable store carry no raw transaction body.
    // The lookup must reconstruct it from the persisted block, and when that
    // body is not available it must answer `null`/`body_available: false` —
    // never a synthetic 0x000… sender with value 0 (audit F-11).
    let st = test_state().await;
    let tx_hash = [0xB7u8; 32];
    st.receipts.write().await.insert(TxReceipt {
        tx_hash,
        height: 9,
        block_hash: [0xC7u8; 32],
        index: 0,
        success: true,
        gas_limit: 21_000,
        fee_charged: 1,
        raw_tx: None,
        return_value: None,
        gas_used: None,
        events: Vec::new(),
        contract_address: None,
    });
    let evm = call(
        &st,
        "eth_getTransactionByHash",
        json!([hex::encode(tx_hash)]),
    )
    .await;
    assert!(
        evm.is_null(),
        "a body this node cannot reconstruct must not be synthesised: {evm}"
    );
    let native = call(
        &st,
        "stell_getTransactionByHash",
        json!([hex::encode(tx_hash)]),
    )
    .await;
    assert_eq!(native["status"], json!("success"));
    assert_eq!(native["body_available"], json!(false));
    assert!(native["from"].is_null(), "{native}");
    assert!(native["amount"].is_null(), "{native}");
    // The receipt itself still reports the committed status/height.
    let receipt = call(
        &st,
        "eth_getTransactionReceipt",
        json!([hex::encode(tx_hash)]),
    )
    .await;
    assert_eq!(receipt["status"], json!("0x1"));
    assert_eq!(receipt["blockNumber"], json!("0x9"));
}

#[tokio::test]
async fn eth_tx_lookup_rebuilds_restart_hydrated_body_from_archive_store() {
    let dir = std::env::temp_dir().join(format!(
        "stell_rpc_body_arch_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let store = std::sync::Arc::new(crate::storage::Storage::open(&dir).unwrap());
    let sk = SigningKey::generate(&mut OsRng);
    let tx = receipt_tx(0xCE, 0);
    let transactions = vec![tx.clone()];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut b = crate::sharding::Block {
        shard_id: crate::sharding::MASTERCHAIN_SHARD,
        height: 44,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 1_700_000_044,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
    };
    b.sign_block(&sk);
    let bh = b.compute_hash();
    store.put_block(&b).unwrap();
    store
        .put_receipts_for_block(44, &bh, &b.transactions, &[true], &[1])
        .unwrap();

    let base = test_state().await;
    let st = Arc::new(RpcState {
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
        faucet: base.faucet.clone(),
        faucet_token: base.faucet_token.clone(),
        msg_signing_seed: base.msg_signing_seed,
        archive_store: Some(store.clone()),
        shard_registry: ShardRegistry::single(),
    });
    hydrate_rpc_from_store(&st, store.as_ref()).await;

    let tx_hash = hex::encode(tx.compute_tx_hash());
    let view = call(&st, "eth_getTransactionByHash", json!([tx_hash])).await;
    assert_eq!(
        view["from"],
        json!(crate::evm_adapter::stell_address_to_evm(&tx.from)),
        "restart view must recover the real sender from the archive body: {view}"
    );
    assert_eq!(
        view["to"],
        json!(crate::evm_adapter::stell_address_to_evm(&tx.to))
    );
    assert_eq!(view["blockNumber"], json!("0x2c"));
    let receipt = call(
        &st,
        "eth_getTransactionReceipt",
        json!([hex::encode(tx.compute_tx_hash())]),
    )
    .await;
    assert_eq!(
        receipt["from"],
        json!(crate::evm_adapter::stell_address_to_evm(&tx.from)),
        "receipt must not fall back to the zero address when the body is archived: {receipt}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
