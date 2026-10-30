//! B-IDX adversarial audit PoCs (read-only audit, tests-only scope).
//!
//! Each test asserts the SECURE behavior, so a failure on current code
//! demonstrates the finding. See RETURN summary for ranking.

use stellereum_indexer::db::{BlockRecord, Database, TxRecord};
use stellereum_indexer::server::{create_router, AppState};

fn seed_two_txs(db: &Database) {
    for (hash, from, to) in [
        ("0xaaaa", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ("0xbbbb", "0xcccccccccccccccccccccccccccccccccccccccc", "0xdddddddddddddddddddddddddddddddddddddddd"),
    ] {
        db.insert_transaction(&TxRecord {
            tx_hash: hash.to_string(),
            block_height: 1,
            tx_index: 0,
            from_addr: from.to_string(),
            to_addr: to.to_string(),
            from_stl57: None,
            to_stl57: None,
            amount: "1".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "1".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_000,
        })
        .unwrap();
    }
}

/// F1 (High): LIKE-wildcard injection in account lookup.
/// `resolve_address_variants("%")` builds LIKE pattern `%%%` with no
/// ESCAPE, so a one-character address filter matches the whole table.
#[test]
fn poc_f1_like_wildcard_matches_unrelated_rows() {
    let db = Database::open(":memory:").unwrap();
    seed_two_txs(&db);
    // A literal "%" is not an address and must match nothing.
    let rows = db.get_account_txs("%", 200, 0).unwrap();
    assert_eq!(
        rows.len(),
        0,
        "F1: address filter '%' must not match unrelated txs (got {})",
        rows.len()
    );
    let n = db.get_account_tx_count("%").unwrap();
    assert_eq!(n, 0, "F1: count('%') must be 0 (got {n})");
}

/// F2 (High): reorg / conflicting block at same (shard,height) is ignored.
/// `insert_block` uses INSERT OR IGNORE and the syncer skips a height it
/// already has, so a fork with a different hash never replaces the stale row.
#[test]
fn poc_f2_reorg_replaces_stale_block() {
    let db = Database::open(":memory:").unwrap();
    let mk = |hash: &str| BlockRecord {
        shard_id: 0,
        height: 10,
        hash: hash.to_string(),
        timestamp: 1_792_000_000,
        tx_count: 0,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    };
    db.insert_block(&mk("aaaa")).unwrap();
    // Reorg: same (shard,height), different canonical hash.
    db.insert_block(&mk("bbbb")).unwrap();
    let got = db.get_block_by_shard_and_height(0, 10).unwrap().unwrap();
    assert_eq!(
        got.hash, "bbbb",
        "F2: reorged height must serve the new hash (serves stale '{}')",
        got.hash
    );
}

/// F3 (Medium): unauthenticated expensive write.
/// POST /api/v2/contract/:address/verify forwards to the node and writes the
/// DB with no auth/rate-limit. Secure behavior: anonymous write is rejected.
#[tokio::test]
async fn poc_f3_verify_requires_auth() {
    // Mock node that confirms everything.
    let mock = axum::Router::new().route(
        "/",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "verified": true,
                    "compiler": "wat2wasm-1.0",
                    "compiler_flags": "",
                    "source_hash": "00",
                    "onchain_code_hash": "00",
                }
            }))
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_url = format!("http://{}", mock_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(mock_listener, mock).await.unwrap() });

    let db = Database::open(":memory:").unwrap();
    let mut app_state = AppState::with_rpc(db, mock_url);
    app_state.verify_token = Some("poc-token".to_string());
    let app = create_router(app_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = reqwest::Client::new();
    let addr = "aa".repeat(32);
    let res = client
        .post(format!("{base}/api/v2/contract/{addr}/verify"))
        .json(&serde_json::json!({"source": "(module)", "compiler": "wat2wasm-1.0"}))
        .send()
        .await
        .unwrap();
    assert!(
        res.status() == reqwest::StatusCode::UNAUTHORIZED
            || res.status() == reqwest::StatusCode::FORBIDDEN,
        "F3: anonymous verify must be rejected with 401/403 (got {})",
        res.status()
    );
    // Control: the operator token passes (mock node confirms everything).
    let res_ok = client
        .post(format!("{base}/api/v2/contract/{addr}/verify"))
        .header("X-Api-Key", "poc-token")
        .json(&serde_json::json!({"source": "(module)", "compiler": "wat2wasm-1.0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res_ok.status(),
        reqwest::StatusCode::OK,
        "authed verify must reach the node"
    );
}

/// F4 (Low): unbounded OFFSET accepted (CPU-scan DoS).
/// LIMIT is capped at 200 but OFFSET (u32) is unbounded.
#[tokio::test]
async fn poc_f4_huge_offset_rejected() {
    let db = Database::open(":memory:").unwrap();
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 1,
        hash: "h1".to_string(),
        timestamp: 1_792_000_000,
        tx_count: 0,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();
    let app = create_router(AppState::new(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/v2/blocks?limit=50&offset=4294967295"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "F4: u32::MAX offset must be rejected with 400 (got {})",
        res.status()
    );
}

/// F5 (Low): hash canonicalization split — exact-match lookup 404s on
/// case/`0X` variants the event endpoints handle case-insensitively.
#[tokio::test]
async fn poc_f5_tx_lookup_is_case_insensitive() {
    let db = Database::open(":memory:").unwrap();
    let hash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    db.insert_transaction(&TxRecord {
        tx_hash: hash.to_string(),
        block_height: 5,
        tx_index: 0,
        from_addr: "0xaa".to_string(),
        to_addr: "0xbb".to_string(),
        from_stl57: None,
        to_stl57: None,
        amount: "1".to_string(),
        fee_charged: "1".to_string(),
        gas_limit: "1".to_string(),
        status: "success".to_string(),
        timestamp: 1_792_000_000,
    })
    .unwrap();
    let app = create_router(AppState::new(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = reqwest::Client::new();
    let upper = format!("0x{}", hash.to_uppercase());
    let res = client.get(format!("{base}/api/v2/tx/{upper}")).send().await.unwrap();
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "F5: uppercase tx lookup must resolve (got {})",
        res.status()
    );
}
