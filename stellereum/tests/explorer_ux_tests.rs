//! Human-explorer read views: happy-path, cap enforcement, empty-store.
//!
//! Covers the three additive views in `stellereum::explorer`
//! (`/api/validator/:address`, `/api/finals`, `/api/account/:address`) over
//! real HTTP. Existing endpoints are untouched; one test asserts `/api/blocks`
//! still serves its exact shape alongside the new routes.

use std::sync::Arc;
use stellereum::explorer::{self, GatewayState};
use stellereum::rpc::{ReceiptIndex, RpcState, TxReceipt};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VALIDATOR: [u8; 32] = [0x21u8; 32];
const JAILED: [u8; 32] = [0x22u8; 32];
const SENDER: [u8; 32] = [0x33u8; 32];
const SENDER_KEY: [u8; 32] = [0x34u8; 32];
const OTHER: [u8; 32] = [0x35u8; 32];

async fn seeded_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new(SENDER, 9_000_000_000_000_000))
        .await;
    engine.update_account(AccountState::new(OTHER, 777)).await;

    let mut ledger = stellereum::staking::StakingLedger::new();
    ledger.bond(VALIDATOR, 5_000_000_000_000, 1000).unwrap();
    // Proof of correctness for delegation_count==1: the account view keys
    // delegations by exact delegator address (`*d == a` over
    // (validator, delegator) keys), and the happy-path test queries the
    // ed25519 pubkey derived from SENDER_KEY -- not the raw SENDER constant
    // ([0x33; 32]). Seeding the delegation from SENDER therefore correctly
    // yields 0 for the queried address; seed it from the derived pubkey so
    // the queried account is the delegator (validator totals unchanged).
    let sender_pub =
        ed25519_dalek::SigningKey::from_bytes(&SENDER_KEY).verifying_key().to_bytes();
    ledger
        .delegate(sender_pub, VALIDATOR, 100_000_000_000)
        .unwrap();
    ledger.bond(JAILED, 5_000_000_000_000, 500).unwrap();
    ledger.jail.insert(
        JAILED,
        stellereum::staking::JailRecord {
            jailed_at_height: 5,
            release_height: 50,
        },
    );

    let st = Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:ux".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(ledger)),
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
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });

    // Five finals, 10s apart; tx counts 1..=5.
    for (i, h) in (10u64..15).enumerate() {
        st.record_block(h, [0xABu8; 32], i + 1, 1000 + (i as u64) * 10)
            .await;
    }
    // One finalized receipt at height 13.
    st.receipts.write().await.insert(TxReceipt {
        tx_hash: [0xCCu8; 32],
        height: 13,
        block_hash: [0xABu8; 32],
        index: 0,
        success: true,
        gas_limit: 1000,
        fee_charged: 10,
        ..Default::default()
    });

    // One pending transfer SENDER -> OTHER (nonce 0).
    let key = ed25519_dalek::SigningKey::from_bytes(&SENDER_KEY);
    let sender = key.verifying_key().to_bytes();
    st.engine
        .update_account(AccountState::new(sender, 9_000_000_000_000_000))
        .await;
    let tx = stellereum::sharding::Transaction::sign(&key, OTHER, 42, 1000, 0, 0, 0);
    st.mempool.write().await.add(tx).unwrap();
    st
}

async fn empty_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:ux-empty".to_string(),
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

fn body_json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("response must be JSON")
}

#[tokio::test]
async fn validator_summary_happy_path() {
    let addr = spawn(seeded_state().await).await;
    let v = hex::encode(VALIDATOR);
    let (status, body) = http_get(addr, &format!("/api/validator/{v}")).await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    assert_eq!(j["known"], true);
    assert_eq!(j["validator"], v);
    assert_eq!(j["moniker"], format!("val-{}", &v[..8]));
    assert_eq!(j["in_set"], true);
    assert_eq!(j["power"], "5100000000000");
    assert_eq!(j["self_bond"], "5000000000000");
    assert_eq!(j["delegated"], "100000000000");
    assert_eq!(j["commission_bps"], 1000);
    assert_eq!(j["jailed"], false);
    assert!(j["pending_commission"].is_null(), "no announcement: {j}");
}

#[tokio::test]
async fn validator_summary_jailed() {
    let addr = spawn(seeded_state().await).await;
    let v = hex::encode(JAILED);
    let (status, body) = http_get(addr, &format!("/api/validator/{v}")).await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    assert_eq!(j["known"], true);
    assert_eq!(j["jailed"], true);
    assert_eq!(j["jailed_at_height"], 5);
    assert_eq!(j["release_height"], 50);
    assert_eq!(j["in_set"], false);
    assert_eq!(j["commission_bps"], 500);
}

#[tokio::test]
async fn validator_summary_unknown_and_bad() {
    let addr = spawn(seeded_state().await).await;
    let unknown = hex::encode([0x99u8; 32]);
    let (status, body) = http_get(addr, &format!("/api/validator/{unknown}")).await;
    assert!(status.contains("200"), "unknown is data, not error: {status}");
    let j = body_json(&body);
    assert_eq!(j["known"], false);
    assert_eq!(j["validator"], unknown);
    assert_eq!(j["power"], "0");
    assert_eq!(j["jailed"], false);
    assert!(j["self_bond"].is_null());

    let (status, _) = http_get(addr, "/api/validator/zzzz").await;
    assert!(status.contains("400"), "bad address must fail closed: {status}");
}

#[tokio::test]
async fn finals_feed_happy_path() {
    let addr = spawn(seeded_state().await).await;
    let (status, body) = http_get(addr, "/api/finals").await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    let rows = j.as_array().expect("feed must be an array");
    assert_eq!(rows.len(), 5, "store holds 5 finals: {j}");
    // Newest first.
    assert_eq!(rows[0]["height"], 14);
    assert_eq!(rows[4]["height"], 10);
    assert_eq!(rows[0]["txs"], 5);
    assert_eq!(rows[0]["interval_secs"], 10);
    assert_eq!(rows[1]["interval_secs"], 10);
    assert!(rows[4]["interval_secs"].is_null(), "oldest held row: {j}");
    // Receipt index joined per height.
    let h13 = rows.iter().find(|r| r["height"] == 13).unwrap();
    assert_eq!(h13["receipts"], 1);
    assert_eq!(rows[0]["receipts"], 0);
}

#[tokio::test]
async fn finals_feed_cap_enforced() {
    let addr = spawn(seeded_state().await).await;
    // Oversized N clamps to the hard cap (store holds 5, cap is 100).
    let (status, body) = http_get(addr, "/api/finals?limit=10000").await;
    assert!(status.contains("200"), "oversized clamps, not errors: {status}");
    let rows = body_json(&body).as_array().unwrap().len();
    assert_eq!(rows, 5);
    // Small N paginates newest-first.
    let (status, body) = http_get(addr, "/api/finals?limit=2").await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    assert_eq!(j.as_array().unwrap().len(), 2);
    assert_eq!(j[0]["height"], 14);
    assert_eq!(j[1]["height"], 13);
    // Abuse fails closed.
    let (status, _) = http_get(addr, "/api/finals?limit=0").await;
    assert!(status.contains("400"), "zero must be refused: {status}");
    let (status, _) = http_get(addr, "/api/finals?limit=abc").await;
    assert!(status.contains("400"), "non-numeric must be refused: {status}");
}

#[tokio::test]
async fn finals_feed_empty_store() {
    let addr = spawn(empty_state().await).await;
    let (status, body) = http_get(addr, "/api/finals").await;
    assert!(status.contains("200"), "status: {status}");
    assert_eq!(body_json(&body), serde_json::json!([]));
}

#[tokio::test]
async fn account_summary_happy_path() {
    let addr = spawn(seeded_state().await).await;
    let key = ed25519_dalek::SigningKey::from_bytes(&SENDER_KEY);
    let sender = hex::encode(key.verifying_key().to_bytes());
    let (status, body) = http_get(addr, &format!("/api/account/{sender}")).await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    assert_eq!(j["address"], sender);
    assert_eq!(j["balance"], "9000000000000000");
    assert_eq!(j["nonce"], 0);
    // Staking position as delegator.
    assert_eq!(j["delegation_count"], 1);
    assert_eq!(j["delegations"][0]["validator"], hex::encode(VALIDATOR));
    assert_eq!(j["delegations"][0]["amount"], "100000000000");
    assert_eq!(j["delegations_truncated"], false);
    assert!(j["as_validator"].is_null());
    // Pending tx ref out to OTHER.
    assert_eq!(j["recent_tx_count"], 1);
    assert_eq!(j["recent_txs"][0]["direction"], "out");
    assert_eq!(j["recent_txs"][0]["amount"], "42");
    assert_eq!(j["recent_txs"][0]["status"], "pending");
    assert_eq!(j["recent_txs_truncated"], false);
    // Existing endpoint untouched alongside the new ones.
    let (status, body) = http_get(addr, "/api/blocks").await;
    assert!(status.contains("200"));
    assert!(body.contains("\"height\":14"), "legacy feed intact: {body}");
}

#[tokio::test]
async fn account_summary_tx_cap_enforced() {
    let st = seeded_state().await;
    // 25 pending from the same sender (nonces 1..=25; nonce 0 already pooled).
    let key = ed25519_dalek::SigningKey::from_bytes(&SENDER_KEY);
    let sender = key.verifying_key().to_bytes();
    for n in 1u64..=25 {
        let tx = stellereum::sharding::Transaction::sign(&key, OTHER, n, 1000, n, 0, 0);
        st.mempool.write().await.add(tx).unwrap();
    }
    let addr = spawn(st).await;
    let (status, body) = http_get(addr, &format!("/api/account/{}", hex::encode(sender))).await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    assert_eq!(j["recent_tx_count"], 26);
    assert_eq!(j["recent_txs"].as_array().unwrap().len(), 20);
    assert_eq!(j["recent_txs_truncated"], true);
    // Newest nonce first.
    assert_eq!(j["recent_txs"][0]["nonce"], 25);
}

#[tokio::test]
async fn account_summary_empty_store() {
    let addr = spawn(empty_state().await).await;
    let unknown = hex::encode([0x77u8; 32]);
    let (status, body) = http_get(addr, &format!("/api/account/{unknown}")).await;
    assert!(status.contains("200"), "status: {status}");
    let j = body_json(&body);
    assert_eq!(j["address"], unknown);
    assert_eq!(j["balance"], "0");
    assert_eq!(j["nonce"], 0);
    assert!(j["as_validator"].is_null());
    assert_eq!(j["delegation_count"], 0);
    assert_eq!(j["recent_tx_count"], 0);
    assert_eq!(j["recent_txs"], serde_json::json!([]));
    assert_eq!(j["withdrawable"], "0");

    let (status, _) = http_get(addr, "/api/account/not-hex").await;
    assert!(status.contains("400"), "bad address must fail closed: {status}");
}
