//! Bot/session-key visibility: `stell_sessionBudget` RPC + human-readable
//! confidential display (backend JSON the frontend consumes).
//!
//! Zones: RPC read path + explorer rendering only. No consensus change.

use std::sync::Arc;

use curve25519_dalek::Scalar;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::crypto_privacy::{ConfidentialState, ConfidentialTransfer, PedersenCommitment};
use stellereum::explorer::{self, GatewayState};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::zkml::{now_secs, SessionKeyAuthorization, SCOPE_TRANSFER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CHAIN_ID: u64 = 5757;

fn balanced_transfer(value: u64, fee: u64) -> ConfidentialTransfer {
    let r = Scalar::from(0x5EED_u64);
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    ConfidentialTransfer::new(vec![c_in], vec![c_out], fee)
}

async fn rpc_state() -> Arc<RpcState> {
    rpc_state_with_token(None).await
}

/// The same state, but with the gateway's API token configured (the
/// authenticated tier of the read endpoints).
async fn rpc_state_with_token(token: Option<&str>) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        node_id: "inf1:budget-test".to_string(),
        chain_id: CHAIN_ID,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: token.map(|t| t.to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

async fn spawn(st: Arc<RpcState>) -> std::net::SocketAddr {
    let gw = Arc::new(GatewayState::new(st, 1000));
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

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
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

fn rpc_body(method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string()
}

async fn budget_query(addr: std::net::SocketAddr, params: serde_json::Value) -> serde_json::Value {
    let (_, body) = http_post(addr, "/rpc", &rpc_body("stell_sessionBudget", params)).await;
    serde_json::from_str(&body).expect("rpc must return JSON")
}

/// Register one session key on-chain via a real session-signed transfer.
/// Returns (master, session, grant, gas_spent_by_first_tx).
async fn register_session(
    st: &Arc<RpcState>,
    max_gas_spend: u64,
    gas_limit: u64,
) -> (SigningKey, SigningKey, SessionKeyAuthorization) {
    let master = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng);
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    st.engine
        .update_account(AccountState::new(master_pub, 1_000_000_000_000))
        .await;
    let grant = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        now_secs() + 3600,
        max_gas_spend,
        SCOPE_TRANSFER,
        1_000_000,
        CHAIN_ID,
    );
    let tx = stellereum::sharding::Transaction::sign_with_session(
        &session,
        grant.clone(),
        [9u8; 32],
        10,
        gas_limit,
        0,
        1,
        1,
        vec![],
    );
    st.engine
        .apply_transaction(&tx, now_secs())
        .await
        .expect("first session tx must apply and register the key");
    (master, session, grant)
}

#[tokio::test]
async fn budget_registered_key_reports_remaining_math() {
    let st = rpc_state().await;
    let addr = spawn(st.clone()).await;
    let (_master, session, grant) = register_session(&st, 5_000, 100).await;
    let session_hex = hex::encode(session.verifying_key().to_bytes());

    // Object params.
    let resp = budget_query(addr, serde_json::json!({"session": session_hex})).await;
    let r = resp["result"].clone();
    assert_eq!(r["registered"], serde_json::json!(true), "{resp}");
    assert_eq!(r["revoked"], serde_json::json!(false), "{resp}");
    assert_eq!(
        r["valid_until"],
        serde_json::json!(grant.valid_until),
        "{resp}"
    );
    assert_eq!(r["scope"], serde_json::json!(grant.scope), "{resp}");
    assert_eq!(r["max_gas_spend"], serde_json::json!(5_000), "{resp}");
    // Empty-payload transfer charges the declared gas_limit.
    assert_eq!(r["spent"], serde_json::json!(100), "{resp}");
    assert_eq!(r["remaining_gas"], serde_json::json!(4_900), "{resp}");
    assert_eq!(
        r["master"],
        serde_json::json!(hex::encode(grant.master_address)),
        "{resp}"
    );
    // chain-id field present (node's chain id; registry record holds none).
    assert_eq!(r["chain_id"], serde_json::json!(CHAIN_ID), "{resp}");

    // Bare hex string params (also with 0x prefix).
    let resp2 = budget_query(addr, serde_json::json!(session_hex)).await;
    assert_eq!(
        resp2["result"]["remaining_gas"],
        serde_json::json!(4_900),
        "{resp2}"
    );
    let resp3 = budget_query(addr, serde_json::json!(format!("0x{session_hex}"))).await;
    assert_eq!(
        resp3["result"]["registered"],
        serde_json::json!(true),
        "{resp3}"
    );
}

#[tokio::test]
async fn budget_revoked_key_reports_revoked() {
    let st = rpc_state().await;
    let addr = spawn(st.clone()).await;
    let (master, session, _grant) = register_session(&st, 5_000, 100).await;
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();

    // Master revokes on chain (nonce 1: the session tx used nonce 0).
    let revoke = stellereum::sharding::Transaction::sign_with_payload(
        &master,
        master_pub,
        0,
        50_000,
        1,
        1,
        1,
        vec![stellereum::svm::OpCode::SysCallRevokeSession {
            session_pubkey: session_pub,
        }],
    );
    st.engine
        .apply_transaction(&revoke, now_secs())
        .await
        .expect("revoke must apply");

    let resp = budget_query(
        addr,
        serde_json::json!({"session": hex::encode(session_pub)}),
    )
    .await;
    let r = &resp["result"];
    assert_eq!(r["registered"], serde_json::json!(true), "{resp}");
    assert_eq!(r["revoked"], serde_json::json!(true), "{resp}");
    assert_eq!(r["chain_id"], serde_json::json!(CHAIN_ID), "{resp}");
    // Budget audit trail survives the key's death.
    assert_eq!(r["spent"], serde_json::json!(100), "{resp}");
    assert_eq!(r["remaining_gas"], serde_json::json!(4_900), "{resp}");
}

#[tokio::test]
async fn budget_unknown_key_returns_zeros_and_unregistered() {
    let st = rpc_state().await;
    let addr = spawn(st.clone()).await;
    let unknown = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
    let resp = budget_query(addr, serde_json::json!({"session": unknown})).await;
    let r = &resp["result"];
    assert_eq!(r["registered"], serde_json::json!(false), "{resp}");
    assert_eq!(r["revoked"], serde_json::json!(false), "{resp}");
    assert_eq!(r["valid_until"], serde_json::json!(0), "{resp}");
    assert_eq!(r["scope"], serde_json::json!(0), "{resp}");
    assert_eq!(r["max_gas_spend"], serde_json::json!(0), "{resp}");
    assert_eq!(r["spent"], serde_json::json!(0), "{resp}");
    assert_eq!(r["remaining_gas"], serde_json::json!(0), "{resp}");
    assert_eq!(r["master"], serde_json::json!("0".repeat(64)), "{resp}");
    assert_eq!(r["chain_id"], serde_json::json!(CHAIN_ID), "{resp}");
}

#[tokio::test]
async fn budget_rejects_missing_or_malformed_session() {
    let st = rpc_state().await;
    let addr = spawn(st.clone()).await;
    let resp = budget_query(addr, serde_json::json!({})).await;
    assert!(
        resp.get("error").is_some(),
        "missing session must error: {resp}"
    );
    let resp2 = budget_query(addr, serde_json::json!({"session": "zz"})).await;
    assert!(
        resp2.get("error").is_some(),
        "malformed hex must error: {resp2}"
    );
}

#[tokio::test]
async fn budget_read_needs_no_auth_token() {
    let st = rpc_state().await;
    let authed = Arc::new(RpcState {
        engine: st.engine.clone(),
        mempool: st.mempool.clone(),
        height: st.height.clone(),
        node_id: st.node_id.clone(),
        chain_id: st.chain_id,
        staking: st.staking.clone(),
        governance: st.governance.clone(),
        recent_blocks: st.recent_blocks.clone(),
        receipts: st.receipts.clone(),
        auth_token: Some("secret".to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });
    let addr = spawn(authed).await;
    let unknown = hex::encode([7u8; 32]);
    let resp = budget_query(addr, serde_json::json!({"session": unknown})).await;
    assert!(
        resp.get("result").is_some(),
        "reads must not require the write API token: {resp}"
    );
}

// ---- human-readable confidential display ----

#[test]
fn confidential_display_labels_shape_not_raw_hex() {
    let sender = [1u8; 32];
    let recipient = [2u8; 32];
    let transfer = balanced_transfer(1_000, 20);
    let state = ConfidentialState::new();
    let v = explorer::describe_confidential_transfer(&sender, &recipient, &transfer, &state);
    assert_eq!(v["kind"], serde_json::json!("confidential"));
    assert_eq!(v["sender"], serde_json::json!(hex::encode(sender)));
    assert_eq!(v["recipient"], serde_json::json!(hex::encode(recipient)));
    assert_eq!(v["fee"], serde_json::json!(20));
    assert_eq!(v["inputs"], serde_json::json!(1));
    assert_eq!(v["outputs"], serde_json::json!(1));
    assert_eq!(v["spent"], serde_json::json!([false]));
    assert_eq!(v["all_spent"], serde_json::json!(false));
    // Commitments are listed explicitly (labeled), not an opaque payload blob.
    assert_eq!(v["input_commitments"].as_array().unwrap().len(), 1);
    assert_eq!(v["output_commitments"].as_array().unwrap().len(), 1);
}

#[test]
fn confidential_display_marks_spent_inputs() {
    let sender = [1u8; 32];
    let recipient = [2u8; 32];
    let transfer = balanced_transfer(1_000, 20);
    let mut state = ConfidentialState::new();
    for c in &transfer.input_commitments {
        state.note_shielded_output(&sender, c.commitment);
    }
    state
        .apply_transfer(&sender, &recipient, &transfer)
        .expect("balanced transfer applies");
    let v = explorer::describe_confidential_transfer(&sender, &recipient, &transfer, &state);
    assert_eq!(v["spent"], serde_json::json!([true]));
    assert_eq!(v["all_spent"], serde_json::json!(true));
}

#[test]
fn transaction_display_routes_confidential_vs_transparent() {
    use stellereum::sharding::Transaction;
    let sk = SigningKey::generate(&mut OsRng);
    let state = ConfidentialState::new();
    // Confidential payload -> labeled shape.
    let ctx = Transaction::sign_with_payload(
        &sk,
        [2u8; 32],
        0,
        100_000,
        0,
        1,
        1,
        vec![stellereum::svm::OpCode::SysCallConfidentialTransfer {
            recipient: [2u8; 32],
            transfer: Box::new(balanced_transfer(500, 10)),
        }],
    );
    let v = explorer::describe_transaction(&ctx, &state);
    assert_eq!(v["kind"], serde_json::json!("confidential"));
    assert_eq!(v["fee"], serde_json::json!(10));
    assert_eq!(v["inputs"], serde_json::json!(1));
    // Plain transfer -> transparent summary, never "confidential".
    let plain = Transaction::sign(&sk, [3u8; 32], 5, 5, 1, 1, 1);
    let w = explorer::describe_transaction(&plain, &state);
    assert_eq!(w["kind"], serde_json::json!("transparent"));
    assert!(w.get("input_commitments").is_none());
}

#[tokio::test]
async fn gateway_tx_endpoint_renders_confidential_not_raw_hex() {
    let st = rpc_state().await;
    let addr = spawn(st.clone()).await;
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    st.engine
        .update_account(AccountState::new(from, 1_000_000_000_000))
        .await;
    let transfer = balanced_transfer(500, 10);
    let tx = stellereum::sharding::Transaction::sign_with_payload(
        &sk,
        from,
        0,
        100_000,
        0,
        1,
        1,
        vec![stellereum::svm::OpCode::SysCallConfidentialTransfer {
            recipient: [8u8; 32],
            transfer: Box::new(transfer.clone()),
        }],
    );
    let hash_hex = hex::encode(tx.compute_tx_hash());
    st.mempool.write().await.add(tx.clone()).unwrap();

    // (1) UNAUTHENTICATED: a PENDING body is REDACTED. Only the hash, the
    // nonce and the status are public - the pre-finalization payload is not
    // (front-running aid), so no confidential detail may leak here.
    let (status, body) = http_get(addr, &format!("/api/tx/{hash_hex}")).await;
    assert!(status.contains("200"), "{status} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["tx_hash"], serde_json::json!(hash_hex), "{v}");
    assert_eq!(v["nonce"], serde_json::json!(0));
    assert_eq!(v["status"], serde_json::json!("pending"));
    for leaked in ["kind", "sender", "recipient", "fee", "input_commitments"] {
        assert!(
            v.get(leaked).is_none(),
            "the pending body must not be rendered to an unauthenticated caller \
             (leaked {leaked}): {v}"
        );
    }

    // (2) AUTHENTICATED: the view renders the CONFIDENTIAL shape - labelled,
    // with the recipient and the inner fee - never a raw hex dump of the
    // payload.
    let token = "gateway-token";
    let st_auth = rpc_state_with_token(Some(token)).await;
    let addr_auth = spawn(st_auth.clone()).await;
    st_auth
        .engine
        .update_account(AccountState::new(from, 1_000_000_000_000))
        .await;
    st_auth.mempool.write().await.add(tx).unwrap();
    let (status, body) = http_get(addr_auth, &format!("/api/tx/{hash_hex}?token={token}")).await;
    assert!(status.contains("200"), "{status} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["kind"], serde_json::json!("confidential"), "{v}");
    assert_eq!(v["sender"], serde_json::json!(hex::encode(from)));
    assert_eq!(v["recipient"], serde_json::json!(hex::encode([8u8; 32])));
    assert_eq!(v["fee"], serde_json::json!(10));
    assert_eq!(v["inputs"], serde_json::json!(1));
    assert_eq!(v["outputs"], serde_json::json!(1));
    assert_eq!(v["status"], serde_json::json!("pending"));

    // A WRONG token is treated exactly like no token: the body stays redacted.
    let (status, body) = http_get(addr_auth, &format!("/api/tx/{hash_hex}?token=wrong")).await;
    assert!(status.contains("200"), "{status} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v.get("kind").is_none(),
        "a wrong token must not unlock the pending body: {v}"
    );

    // Spent-status endpoint: unspent before finalization.
    let commit_hex = hex::encode(transfer.input_commitments[0].commitment);
    let (status2, body2) = http_get(addr, &format!("/api/confidential/{commit_hex}")).await;
    assert!(status2.contains("200"), "{status2} {body2}");
    let s: serde_json::Value = serde_json::from_str(&body2).unwrap();
    assert_eq!(s["spent"], serde_json::json!(false), "{s}");

    // Unknown tx hash: honest unknown, never fabricated.
    let (status3, _) = http_get(addr, &format!("/api/tx/{}", hex::encode([9u8; 32]))).await;
    assert!(status3.contains("404"), "{status3}");
}
