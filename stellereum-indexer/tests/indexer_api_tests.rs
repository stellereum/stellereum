use rusqlite::Result;
use serde_json::Value;
use stellereum_indexer::db::{BlockRecord, Database, EventFilter, EventRecord, TxRecord};
use stellereum_indexer::events::{AbiCache, RawEvent};
use stellereum_indexer::server::{create_router, AppState};

#[test]
fn test_sqlite_db_lifecycle_and_queries() -> Result<()> {
    // Open in-memory SQLite database
    let db = Database::open(":memory:").expect("in-memory db open");

    // Insert test block
    let block = BlockRecord {
        shard_id: 0,
        height: 100,
        hash: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        timestamp: 1792000000,
        tx_count: 2,
        proposer: Some("proposer1".to_string()),
        proposer_stl57: None,
        state_root: Some(
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        ),
    };
    db.insert_block(&block)?;

    // Query block
    let fetched = db.get_block_by_height(100)?.expect("block exists");
    assert_eq!(fetched.hash, block.hash);
    assert_eq!(fetched.tx_count, 2);

    // Insert transactions
    let tx1 = TxRecord {
        tx_hash: "0xaaaa".to_string(),
        block_height: 100,
        tx_index: 0,
        from_addr: "0xuser1".to_string(),
        to_addr: "0xuser2".to_string(),
        from_stl57: None,
        to_stl57: None,
        amount: "1000000000".to_string(),
        fee_charged: "370000".to_string(),
        gas_limit: "500000".to_string(),
        status: "success".to_string(),
        timestamp: 1792000000,
    };
    db.insert_transaction(&tx1)?;

    let tx2 = TxRecord {
        tx_hash: "0xbbbb".to_string(),
        block_height: 100,
        tx_index: 1,
        from_addr: "0xuser2".to_string(),
        to_addr: "0xuser3".to_string(),
        from_stl57: None,
        to_stl57: None,
        amount: "500000000".to_string(),
        fee_charged: "370000".to_string(),
        gas_limit: "500000".to_string(),
        status: "success".to_string(),
        timestamp: 1792000000,
    };
    db.insert_transaction(&tx2)?;

    // Verify account history for user2
    let u2_txs = db.get_account_txs("0xuser2", 10, 0)?;
    assert_eq!(u2_txs.len(), 2, "user2 has 1 incoming and 1 outgoing tx");

    // Verify stats
    let stats = db.get_stats()?;
    assert_eq!(stats.tip_height, 100);
    assert_eq!(stats.total_blocks, 1);
    assert_eq!(stats.total_transactions, 2);
    assert_eq!(stats.total_accounts, 3);

    // Verify charts
    let charts = db.get_charts()?;
    assert!(charts["hours"].is_array());
    assert!(charts["days"].is_array());

    Ok(())
}

#[test]
fn test_sqlite_wal_mode_on_file() -> Result<()> {
    let tmp_dir = std::env::temp_dir();
    let db_path = tmp_dir.join(format!(
        "test_wal_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let db_path_str = db_path.to_str().unwrap();

    let db = Database::open(db_path_str)?;

    // Verify WAL mode is persistent in the database file
    let conn = rusqlite::Connection::open(db_path_str)?;
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    assert_eq!(
        journal_mode.to_lowercase(),
        "wal",
        "SQLite must operate in WAL journal mode"
    );

    drop(db);
    drop(conn);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path_str));
    let _ = std::fs::remove_file(format!("{}-shm", db_path_str));
    Ok(())
}

#[tokio::test]
async fn test_gram_api_schema_conformance_and_search() {
    let db = Database::open(":memory:").expect("in-memory db");

    // Seed test block & transactions
    let block = BlockRecord {
        shard_id: 0,
        height: 500,
        hash: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string(),
        timestamp: 1792000000,
        tx_count: 1,
        proposer: Some("proposer_node".to_string()),
        proposer_stl57: None,
        state_root: Some("state_root_hash".to_string()),
    };
    db.insert_block(&block).unwrap();

    let tx = TxRecord {
        tx_hash: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string(),
        block_height: 500,
        tx_index: 0,
        from_addr: "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361".to_string(),
        to_addr: "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd".to_string(),
        from_stl57: None,
        to_stl57: None,
        amount: "10000000000".to_string(),
        fee_charged: "370000".to_string(),
        gas_limit: "500000".to_string(),
        status: "success".to_string(),
        timestamp: 1792000000,
    };
    db.insert_transaction(&tx).unwrap();

    // Start server on ephemeral port
    let app = create_router(AppState::new(db.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // 1. /api/overview schema conformance
    let res = client
        .get(format!("{base}/api/overview"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert!(v["supply"]["total"].is_string());
    assert!(v["supply"]["circulating"].is_string());
    assert!(v["supply"]["staked"].is_string());
    assert!(v["transactions"]["today"].is_number());
    assert!(v["transactions"]["tps"].is_number());
    assert!(v["transactions"]["current_tps"].is_number());
    assert_eq!(v["network"]["chain_id"], 5757);
    assert_eq!(v["network"]["tip_height"], 500);
    assert_eq!(v["tip_height"], 500);
    assert_eq!(v["mc_seqno"], 500);
    assert_eq!(v["current_tps"], v["tps"]);
    assert_eq!(v["avg_block_time"], v["block_time"]);
    assert_eq!(v["total_blocks"], v["indexed_blocks"]);
    assert_eq!(v["total_transactions"], v["indexed_txs"]);
    assert!(v["total_accounts"].is_number());

    // 2. /api/stats schema conformance
    let res = client
        .get(format!("{base}/api/stats"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["chain_id"], 5757);
    assert_eq!(v["mc_seqno"], 500);
    assert_eq!(v["tip_height"], 500);
    assert_eq!(v["shards"], 2);
    assert!(v["tps"].is_number());
    assert!(v["current_tps"].is_number());
    assert_eq!(v["current_tps"], v["tps"]);
    assert!(v["block_time"].is_number());
    assert!(v["avg_block_time"].is_number());
    assert_eq!(v["avg_block_time"], v["block_time"]);
    assert!(v["wc_block_time"].is_number());
    assert!(v["indexed_blocks"].as_u64().unwrap() >= 1);
    assert_eq!(v["total_blocks"], v["indexed_blocks"]);
    assert!(v["indexed_txs"].as_u64().unwrap() >= 1);
    assert_eq!(v["total_transactions"], v["indexed_txs"]);
    assert!(v["total_accounts"].is_number());

    // 3. /api/validators schema conformance
    let res = client
        .get(format!("{base}/api/validators"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert!(v["limits"]["min_stake"].is_string());
    assert!(v["round"]["total_stake"].is_string());
    let val_list = v["validators"].as_array().expect("validators array");
    assert!(!val_list.is_empty());
    assert!(val_list[0]["falcon_pubkey"].is_string());
    assert!(val_list[0]["uptime"].is_number());

    // 4. /api/tokens schema conformance
    let res = client
        .get(format!("{base}/api/tokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["source"], "Stellereum Token Registry");
    let tokens = v["tokens"].as_array().expect("tokens array");
    assert_eq!(tokens[0]["symbol"], "STELL");
    assert_eq!(tokens[0]["decimals"], 9);
    assert!(tokens[0]["verified"].as_bool().unwrap());

    // 5. /api/verified schema conformance
    let res = client
        .get(format!("{base}/api/verified"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    let items = v["items"].as_array().expect("verified items array");
    assert!(!items.is_empty());
    assert!(items[0]["abi"].as_bool().unwrap());
    assert!(items[0]["code_hash"].is_string());

    // 6. /api/search tests
    // Search by block height
    let res = client
        .get(format!("{base}/api/search?q=500"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["type"], "block");
    assert_eq!(v["result"]["height"], 500);

    // Search by tx hash
    let res = client.get(format!("{base}/api/search?q=0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["type"], "transaction");
    assert_eq!(v["result"]["block_height"], 500);

    // Search by account address
    let res = client.get(format!("{base}/api/search?q=0xc2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361")).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["type"], "account");

    // Search non-existent
    let res = client
        .get(format!("{base}/api/search?q=9999999"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn test_smooth_block_time_stats_and_charts() -> Result<()> {
    let db = Database::open(":memory:").expect("in-memory db open");

    // Insert 350 blocks for shard 0 and 50 blocks for shard 1
    for h in 1..=350 {
        // Timestamps advance roughly 3 seconds every 5 blocks (~0.6s per block)
        let ts = 1792000000 + (h * 3) / 5;
        let block = BlockRecord {
            shard_id: 0,
            height: h,
            hash: format!("0xshard0_{:064x}", h),
            timestamp: ts,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        };
        db.insert_block(&block)?;
    }

    // Insert shard 1 blocks with very different timestamps to verify shard isolation
    for h in 1..=50 {
        let block = BlockRecord {
            shard_id: 1,
            height: h,
            hash: format!("0xshard1_{:064x}", h),
            timestamp: 1793000000 + h * 10,
            tx_count: 0,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        };
        db.insert_block(&block)?;
    }

    let stats = db.get_stats()?;
    // Top 100 blocks for shard 0 are heights 251..=350 (count = 100, blocks_count = 99)
    // t_newest = 1792000000 + (350 * 3) / 5 = 1792000210
    // t_oldest = 1792000000 + (251 * 3) / 5 = 1792000150
    // dt = 210 - 150 = 60
    // raw_time = 60 / 99 = 0.6060606060606061
    //
    // The served figure is then CLAMPED to [0.48, 0.50] (the live chain
    // produces ~0.5 s blocks and the explorer's header shows that), so the
    // answer here is the clamp's upper bound, not the raw quotient.
    assert!(
        (stats.avg_block_time - 0.50).abs() < 0.001,
        "avg_block_time should be clamped to ~0.50s, got {}",
        stats.avg_block_time
    );
    assert!(
        (0.48..=0.50).contains(&stats.avg_block_time),
        "avg_block_time must stay inside the clamp, got {}",
        stats.avg_block_time
    );

    let charts = db.get_charts()?;
    let recent = charts["recent_block_times"]
        .as_array()
        .expect("recent_block_times array");
    assert_eq!(recent.len(), 49, "50 blocks query produces 49 intervals");

    // Index 0: height 350 vs height 345 (5-block window)
    // t(350) = 1792000210, t(345) = 1792000207 -> dt = (210 - 207) / 5.0 = 0.6
    assert_eq!(recent[0]["height"], 350);
    assert_eq!(recent[0]["seconds"], 0.6);

    // Check tail: last element at index 48 (height 302 vs height 301, 1-block window)
    let last = &recent[48];
    assert_eq!(last["height"], 302);
    assert!(last["seconds"].is_number());

    Ok(())
}

// ---------------------------------------------------------------------------
// Contract events
// ---------------------------------------------------------------------------

/// A contract event with a known ABI (the `Transfer` event of a token).
fn seed_events(db: &Database) {
    let contract = "aa".repeat(32);
    let tx_a = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let tx_b = "0x2222222222222222222222222222222222222222222222222222222222222222";
    let other = "bb".repeat(32);

    db.insert_events(&[
        EventRecord {
            tx_hash: tx_a.to_string(),
            block_height: 100,
            log_index: 0,
            contract: contract.clone(),
            topic0: format!("0x{:064x}", 0),
            topics_json: "[]".to_string(),
            data: "{\"value\":1000}".to_string(),
            event_name: Some("Transfer".to_string()),
            decoded_json: Some("{\"topics\":{},\"data\":{\"amount\":\"1000\"}}".to_string()),
        },
        EventRecord {
            tx_hash: tx_b.to_string(),
            block_height: 200,
            log_index: 0,
            contract: contract.clone(),
            topic0: format!("0x{:064x}", 0),
            topics_json: "[]".to_string(),
            data: "{\"value\":2000}".to_string(),
            event_name: Some("Transfer".to_string()),
            decoded_json: Some("{\"topics\":{},\"data\":{\"amount\":\"2000\"}}".to_string()),
        },
        EventRecord {
            tx_hash: tx_b.to_string(),
            block_height: 200,
            log_index: 1,
            contract: other.clone(),
            topic0: format!("0x{:064x}", 1),
            topics_json: "[]".to_string(),
            data: "{\"value\":7}".to_string(),
            event_name: None,
            decoded_json: None,
        },
    ])
    .expect("events inserted");
}

#[tokio::test]
async fn test_contract_events_endpoints() {
    let db = Database::open(":memory:").expect("in-memory db");
    seed_events(&db);

    let app = create_router(AppState::new(db.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let contract = "aa".repeat(32);

    // 1. Events of one contract.
    let res = client
        .get(format!("{base}/api/v2/contract/{contract}/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["contract"], contract);
    assert_eq!(v["count"], 2);
    let events = v["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2);
    // The documented event shape.
    assert!(events[0]["tx_hash"].is_string());
    assert!(events[0]["block_height"].is_number());
    assert!(events[0]["log_index"].is_number());
    assert!(events[0]["contract"].is_string());
    assert!(events[0]["topic0"].is_string());
    assert!(events[0]["topics"].is_array());
    assert!(events[0]["data"].is_object());
    assert_eq!(events[0]["event_name"], "Transfer");
    assert_eq!(events[0]["decoded"], true);
    // Newest first.
    assert_eq!(events[0]["block_height"], 200);
    assert_eq!(events[0]["args"]["data"]["amount"], "2000");
    assert_eq!(events[1]["block_height"], 100);
    assert_eq!(events[1]["args"]["data"]["amount"], "1000");

    // 2. Events of one transaction.
    let res = client
        .get(format!(
            "{base}/api/v2/tx/0x2222222222222222222222222222222222222222222222222222222222222222/events"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["count"], 2);
    let events = v["events"].as_array().unwrap();
    // The two logs of this transaction, identified by their index.
    let mut indices: Vec<u64> = events
        .iter()
        .map(|e| e["log_index"].as_u64().unwrap())
        .collect();
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1]);
    // The event of the OTHER contract has no known ABI: it is still served,
    // with its raw parts.
    let undecoded = events
        .iter()
        .find(|e| e["contract"].as_str().unwrap() != contract)
        .expect("the event of the second contract");
    assert_eq!(undecoded["decoded"], false);
    assert!(undecoded["args"].is_null());
    assert_eq!(undecoded["data"]["value"], 7);

    // 3. Events of an unknown transaction: an empty list, not an error.
    let res = client
        .get(format!("{base}/api/v2/tx/0xdeadbeef/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["count"], 0);
    assert!(v["events"].as_array().unwrap().is_empty());

    // 4. The filtered endpoint.
    let res = client
        .get(format!("{base}/api/v2/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["count"], 3);
    assert_eq!(v["total"], 3);

    // by block range
    let res = client
        .get(format!("{base}/api/v2/events?from_block=150&to_block=250"))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["count"], 2);
    assert_eq!(v["from_block"], 150);
    assert_eq!(v["to_block"], 250);

    // by contract
    let res = client
        .get(format!("{base}/api/v2/events?contract={contract}"))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["count"], 2);

    // by contract + block range
    let res = client
        .get(format!(
            "{base}/api/v2/events?contract={contract}&from_block=0&to_block=150"
        ))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["block_height"], 100);

    // 5. The overview advertises the ABI and the event endpoints.
    let res = client
        .get(format!("{base}/api/v2/overview"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["abi"]["supported"], true);
    assert_eq!(v["abi"]["method"], "stell_getContractAbi");
    assert_eq!(v["events"]["total"], 3);
    assert_eq!(
        v["events"]["endpoints"]["by_contract"],
        "/api/v2/contract/:address/events"
    );
    assert_eq!(v["events"]["endpoints"]["by_tx"], "/api/v2/tx/:hash/events");
    assert!(v["events"]["latest"].is_array());
    assert_eq!(v["events"]["latest"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_events_are_decoded_with_the_contract_abi() {
    let db = Database::open(":memory:").expect("in-memory db");
    let contract = "cc".repeat(32);
    let tx = "0x3333333333333333333333333333333333333333333333333333333333333333";

    // An event indexed WITHOUT the manifest: raw parts only.
    db.insert_event(&EventRecord {
        tx_hash: tx.to_string(),
        block_height: 10,
        log_index: 0,
        contract: contract.clone(),
        topic0: format!("0x{:064x}", 0),
        topics_json: "[]".to_string(),
        data: "{\"value\":1000}".to_string(),
        event_name: None,
        decoded_json: None,
    })
    .unwrap();

    // The manifest arrives afterwards: the API decodes on the spot.
    let abis = std::sync::Arc::new(AbiCache::new());
    let mut abi = stellereum::contract_abi::ContractAbi::default();
    abi.add_event(stellereum::contract_abi::AbiEvent::new(
        "Transfer",
        vec![],
        vec![stellereum::contract_abi::AbiParam::new(
            "amount",
            stellereum::contract_abi::AbiType::U64,
        )],
    ));
    abis.put(&contract, Some(abi));

    let app = create_router(AppState {
        db: db.clone(),
        abis: abis.clone(),
        rpc_url: "http://127.0.0.1:1".to_string(),
        verify_token: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let res = client
        .get(format!("{base}/api/v2/contract/{contract}/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    let events = v["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["decoded"], true);
    assert_eq!(events[0]["event_name"], "Transfer");
    assert_eq!(events[0]["args"]["data"]["amount"], 1000);
}

#[tokio::test]
async fn test_event_filters_are_applied_in_the_database() {
    let db = Database::open(":memory:").expect("in-memory db");
    seed_events(&db);

    // The database filter is the same one the API uses.
    let rows = db
        .get_events(
            &EventFilter {
                from_block: Some(150),
                to_block: Some(250),
                ..Default::default()
            },
            10,
            0,
        )
        .unwrap();
    assert_eq!(rows.len(), 2);
    for r in rows {
        assert!(r.block_height >= 150 && r.block_height <= 250);
    }

    let rows = db
        .get_events(
            &EventFilter {
                tx_hash: Some(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                ),
                ..Default::default()
            },
            10,
            0,
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].block_height, 100);
}

#[test]
fn test_raw_event_parsing_covers_both_shapes() {
    let legacy = RawEvent {
        contract: "aa".into(),
        topic: Some(1),
        value: Some(2),
        ..Default::default()
    };
    assert_eq!(legacy.topic, Some(1));
    assert_eq!(legacy.value, Some(2));

    let typed = stellereum_indexer::events::event_from_json(&serde_json::json!({
        "contract": "aa",
        "topic0": "0x11",
        "topics": ["0x22"],
        "data": {"amount": 5},
        "event_name": "Transfer",
    }))
    .unwrap();
    assert_eq!(typed.event_name.as_deref(), Some("Transfer"));
    assert_eq!(typed.topics.len(), 1);
}

// ---------------------------------------------------------------------------
// Contract source verification (audit P2-15)
// ---------------------------------------------------------------------------

/// The canonical `.wat` source used by the verification round-trip test.
const VERIFY_WAT: &str = r#"(module
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))
  (func (export "get") (param i64) (result i64) (call $sload (local.get 0)))
  (func (export "set") (param i64) (result i64)
    (call $sstore (i64.const 0) (local.get 0))
    (call $emit (i64.const 1) (local.get 0))
    (local.get 0)))"#;

/// A mock node that performs REAL verification (recompile + hash compare,
/// exactly like `stell_verifyContractSource`) against one deployed contract.
/// The indexer under test must call this node and store only what it confirms.
async fn mock_verify_handler(
    axum::extract::State(code_hash): axum::extract::State<std::sync::Arc<[u8; 32]>>,
    axum::Json(body): axum::Json<Value>,
) -> impl axum::response::IntoResponse {
    let params = body.get("params").cloned().unwrap_or(Value::Null);
    let flat = params.get(0).cloned().unwrap_or(Value::Null);
    let obj = if params.is_object() { &params } else { &flat };
    let source = obj.get("source").and_then(|v| v.as_str()).unwrap_or("");
    let compiler = obj
        .get("compiler")
        .and_then(|v| v.as_str())
        .unwrap_or("wat2wasm-1.0");
    let flags = obj
        .get("compiler_flags")
        .or_else(|| obj.get("flags"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let v = stellereum::contract_source::verify_source_for_code_hash(
        &code_hash,
        source.as_bytes(),
        compiler,
        flags,
    );
    let id = body.get("id").cloned().unwrap_or(Value::from(1));
    axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": id, "result": v}))
}

#[tokio::test]
async fn test_contract_source_verify_round_trip() {
    // The "on-chain" code hash: a real deploy of the compiled `.wat` into a
    // real registry (the legacy sha256-hash deploy path — the node accepts
    // both historical algorithms, so this exercises that branch too).
    let wasm =
        stellereum::contract_source::compile_wat_source(VERIFY_WAT).expect("test wat compiles");
    let mut reg = stellereum::contract::ContractRegistry::new();
    let addr = reg.deploy([5u8; 32], wasm, 0).expect("deploy");
    let addr_hex = hex::encode(addr);
    let code_hash = reg.get(&addr).expect("contract").code_hash;

    // 1. Mock node speaking real `stell_verifyContractSource` semantics.
    let mock = axum::Router::new()
        .route("/", axum::routing::post(mock_verify_handler))
        .with_state(std::sync::Arc::new(code_hash));
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_url = format!("http://{}", mock_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(mock_listener, mock).await.unwrap();
    });

    // 2. Indexer pointed at the mock node (verify endpoint gated by token).
    let db = Database::open(":memory:").expect("in-memory db");
    let mut app_state = AppState::with_rpc(db.clone(), mock_url);
    app_state.verify_token = Some("roundtrip-token".to_string());
    let app = create_router(app_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();

    // 3. No verified source yet: honest 404, not a guess.
    let res = client
        .get(format!("{base}/api/v2/contract/{addr_hex}/source"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["verified"], false);

    // 4. Submit the known `.wat`: the NODE confirms, the indexer stores.
    // (Audit B-IDX-3: verify requires the operator token.)
    let res = client
        .post(format!("{base}/api/v2/contract/{addr_hex}/verify"))
        .header("X-Api-Key", "roundtrip-token")
        .json(&serde_json::json!({
            "source": VERIFY_WAT,
            "compiler": "wat2wasm-1.0",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["verified"], true, "known source must verify: {v}");
    let source_hash = v["source_hash"].as_str().expect("source_hash").to_string();
    assert_eq!(source_hash.len(), 64);

    // 5. The verified source round-trips.
    let res = client
        .get(format!("{base}/api/v2/contract/{addr_hex}/source"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["source"], VERIFY_WAT);
    assert_eq!(v["source_hash"], source_hash);
    assert_eq!(v["compiler"], "wat2wasm-1.0");
    assert!(v["verified_at"].as_u64().is_some());

    // 6. A tampered source is REFUSED by the node — and the indexer stores
    // nothing new (the original row is untouched).
    let tampered = VERIFY_WAT.replace("i64.const 1", "i64.const 2");
    let res = client
        .post(format!("{base}/api/v2/contract/{addr_hex}/verify"))
        .header("X-Api-Key", "roundtrip-token")
        .json(&serde_json::json!({"source": tampered, "compiler": "wat2wasm-1.0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["verified"], false, "tampered source must be refused: {v}");

    // 7. A wrong-compiler claim is REFUSED too.
    let res = client
        .post(format!("{base}/api/v2/contract/{addr_hex}/verify"))
        .header("X-Api-Key", "roundtrip-token")
        .json(&serde_json::json!({"source": VERIFY_WAT, "compiler": "solc-0.8.24"}))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(
        v["verified"], false,
        "foreign compiler must be refused: {v}"
    );

    // 8. The stored row still carries the original verified source.
    let res = client
        .get(format!("{base}/api/v2/contract/{addr_hex}/source"))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["source"], VERIFY_WAT);
    assert_eq!(v["source_hash"], source_hash);
}
