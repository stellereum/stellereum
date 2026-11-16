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

    // Start mock node RPC for live validator/staking endpoints
    let mock_rpc = axum::Router::new().route(
        "/",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "validators": [
                        { "validator": "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361", "power": "1000000000000" },
                        { "validator": "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd", "power": "1000000000000" },
                        { "validator": "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694", "power": "1000000000000" }
                    ],
                    "total_power": "3000000000000",
                    "quorum": "2000000000001",
                    "fragile": true,
                    "fragile_reason": "N=3 equal stake requires 3/3"
                }
            }))
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_url = format!("http://{}", mock_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(mock_listener, mock_rpc).await.unwrap();
    });

    // Start server on ephemeral port
    let app = create_router(AppState::with_rpc(db.clone(), mock_url));
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
    assert_eq!(v["shards"], 1);
    assert_eq!(v["validators_count"], 3);
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

    let mut state = AppState::with_rpc(db.clone(), "http://127.0.0.1:1".to_string());
    state.abis = abis.clone();
    let app = create_router(state);
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

#[tokio::test]
async fn test_tx_0x_prefix_sync_status_and_live_validators() {
    let db = Database::open(":memory:").expect("db");
    let tx_0x = "0x1bfac6710000000000000000000000000000000000000000000000000000a552";
    let tx_bare = "1bfac6710000000000000000000000000000000000000000000000000000a552";
    let blk_0x = "0xdeadbeef0000000000000000000000000000000000000000000000000000beef";
    let blk_bare = "deadbeef0000000000000000000000000000000000000000000000000000beef";

    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 42,
        hash: blk_0x.to_string(),
        timestamp: 1_794_000_000,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();
    db.insert_transaction(&TxRecord {
        tx_hash: tx_0x.to_string(),
        block_height: 42,
        tx_index: 0,
        from_addr: "aa".repeat(32),
        to_addr: "bb".repeat(32),
        from_stl57: None,
        to_stl57: None,
        amount: "100".to_string(),
        fee_charged: "1".to_string(),
        gas_limit: "10".to_string(),
        status: "success".to_string(),
        timestamp: 1_794_000_000,
    })
    .unwrap();

    // Unreachable RPC port -> honest 503 on validators and synced=false on status.
    let state = AppState::with_rpc(db.clone(), "http://127.0.0.1:1".to_string());
    let sync_status = state.sync_status.clone();
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    // Item 1: /api/v2/tx/:hash works BOTH with 0x and without 0x.
    for q in [tx_0x, tx_bare] {
        let r = client
            .get(format!("{base}/api/v2/tx/{q}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            reqwest::StatusCode::OK,
            "tx lookup failed for {q}"
        );
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["transaction"]["tx_hash"], tx_0x);
    }

    // Same for /api/v2/block/:hash with 0x and without 0x.
    for q in [blk_0x, blk_bare] {
        let r = client
            .get(format!("{base}/api/v2/block/{q}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            reqwest::StatusCode::OK,
            "block lookup failed for {q}"
        );
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["block"]["height"], 42);
    }

    // Item 3: /api/v2/status is NOT synced=true when lagging or disconnected.
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut s = sync_status.write().await;
        s.node_tip_height = Some(100);
        s.last_sync_at = Some(now);
    }
    let st_lag: Value = client
        .get(format!("{base}/api/v2/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st_lag["synced"], false);
    assert_eq!(st_lag["lag"], 58);

    // Caught up -> synced: true.
    {
        let mut s = sync_status.write().await;
        s.node_tip_height = Some(42);
    }
    let st_ok: Value = client
        .get(format!("{base}/api/v2/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st_ok["synced"], true);
    assert_eq!(st_ok["lag"], 0);

    // Item 5: unreachable node RPC -> 503 on /api/v2/validators (no fake hardcoded snapshot).
    let val_res = client
        .get(format!("{base}/api/v2/validators"))
        .send()
        .await
        .unwrap();
    assert_eq!(val_res.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_pq_32b_stl57_and_evm_20b_address_queries_across_endpoints() {
    let db = Database::open(":memory:").expect("db");

    // Full 32-byte PQ address (non-zero in first 12 bytes)
    let pq_bytes = [0xD4u8; 32];
    let pq_hex = hex::encode(pq_bytes);
    let pq_0x = format!("0x{pq_hex}");
    let pq_upper = format!("0X{}", pq_hex.to_uppercase());
    let pq_stl57 = stellereum::address::encode_stl57_address(&pq_bytes);

    // 32-byte zero-padded address & its 20-byte EVM equivalent
    let mut evm_padded_bytes = [0u8; 32];
    evm_padded_bytes[12..].copy_from_slice(&[0x55u8; 20]);
    let evm_padded_hex = hex::encode(evm_padded_bytes);
    let evm_padded_stl57 = stellereum::address::encode_stl57_address(&evm_padded_bytes);
    let evm20_hex = "55".repeat(20);
    let evm20_0x = format!("0x{evm20_hex}");

    // Seed two txs using mixed representations of the same PQ address (0x+64 and bare 64)
    db.insert_transaction(&TxRecord {
        tx_hash: "0xaa01".to_string(),
        block_height: 10,
        tx_index: 0,
        from_addr: pq_0x.clone(),
        to_addr: format!("0x{evm_padded_hex}"),
        from_stl57: Some(pq_stl57.clone()),
        to_stl57: Some(evm_padded_stl57.clone()),
        amount: "1000".to_string(),
        fee_charged: "10".to_string(),
        gas_limit: "100".to_string(),
        status: "success".to_string(),
        timestamp: 1_792_000_010,
    })
    .unwrap();
    db.insert_transaction(&TxRecord {
        tx_hash: "0xaa02".to_string(),
        block_height: 11,
        tx_index: 0,
        from_addr: pq_hex.clone(),
        to_addr: evm20_0x.clone(),
        from_stl57: Some(pq_stl57.clone()),
        to_stl57: Some(evm_padded_stl57.clone()),
        amount: "2000".to_string(),
        fee_charged: "10".to_string(),
        gas_limit: "100".to_string(),
        status: "success".to_string(),
        timestamp: 1_792_000_011,
    })
    .unwrap();

    // Seed a contract event & verified source using the 32-byte PQ address
    db.insert_event(&EventRecord {
        tx_hash: "0xaa01".to_string(),
        block_height: 10,
        log_index: 0,
        contract: pq_hex.clone(),
        topic0: format!("0x{:064x}", 0),
        topics_json: "[]".to_string(),
        data: "{\"value\":42}".to_string(),
        event_name: Some("Ping".to_string()),
        decoded_json: None,
    })
    .unwrap();
    db.upsert_verified_source(&stellereum_indexer::db::VerifiedSource {
        contract: pq_0x.clone(),
        source_text: "(module)".to_string(),
        compiler: "wat2wasm-1.0".to_string(),
        flags: String::new(),
        source_hash: "11".repeat(32),
        code_hash: "22".repeat(32),
        verified_at: 1_792_000_010,
    })
    .unwrap();

    let app = create_router(AppState::new(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    // 1. Account & tx queries with 0x+64 hex, 0X+64 hex, bare 64 hex, and Stl57...
    for form in [&pq_0x, &pq_upper, &pq_hex, &pq_stl57] {
        let acct: Value = client
            .get(format!("{base}/api/v2/account/{form}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(acct["address"], pq_hex);
        assert_eq!(acct["address_0x"], pq_0x);
        assert_eq!(acct["stl57"], pq_stl57);
        assert_eq!(acct["tx_count"], 2, "failed tx_count for {form}");

        let txs: Value = client
            .get(format!("{base}/api/v2/account/{form}/txs"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(txs["address"], pq_hex);
        assert_eq!(txs["stl57"], pq_stl57);
        assert_eq!(txs["transactions"].as_array().unwrap().len(), 2);

        let srch: Value = client
            .get(format!("{base}/api/v2/search?q={form}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(srch["type"], "account");
        assert_eq!(srch["address"], pq_hex);
        assert_eq!(srch["stl57"], pq_stl57);
        assert_eq!(srch["tx_count"], 2);
    }

    // 2. 20-byte EVM address & its 32-byte zero-padded Stl57 match both tx rows
    for evm_form in [&evm20_0x, &evm_padded_stl57] {
        let acct: Value = client
            .get(format!("{base}/api/v2/account/{evm_form}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(acct["stl57"], evm_padded_stl57);
        assert_eq!(acct["tx_count"], 2, "EVM/Stl57 alias failed for {evm_form}");
    }
    let evm_search: Value = client
        .get(format!(
            "{base}/api/v2/search?q=0X{}",
            evm20_hex.to_uppercase()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evm_search["type"], "account");
    assert_eq!(evm_search["address"], evm20_hex);
    assert_eq!(evm_search["stl57"], evm_padded_stl57);

    // 3. Whales coalesces 0x+64 and bare 64 into one 32-byte entry with tx_count=2
    let whales: Value = client
        .get(format!("{base}/api/v2/whales"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let whale_list = whales["whales"].as_array().unwrap();
    let pq_whale = whale_list
        .iter()
        .find(|w| w["address"] == pq_hex)
        .expect("full 32-byte PQ whale entry");
    assert_eq!(pq_whale["tx_count"], 2);
    assert_eq!(pq_whale["address_stl57"], pq_stl57);

    // 4. Contract events & verified source resolve by Stl57 as well as 0x+64 hex
    for form in [&pq_0x, &pq_stl57] {
        let ev: Value = client
            .get(format!("{base}/api/v2/contract/{form}/events"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(ev["contract"], pq_hex);
        assert_eq!(ev["contract_stl57"], pq_stl57);
        assert_eq!(ev["count"], 1);

        let src: Value = client
            .get(format!("{base}/api/v2/contract/{form}/source"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(src["verified"], true);
        assert_eq!(src["contract"], pq_hex);
        assert_eq!(src["contract_stl57"], pq_stl57);
    }
}

#[tokio::test]
async fn test_multi_shard_blocks_and_shards_endpoints() {
    let db = Database::open(":memory:").expect("db");

    // Seed blocks on shard 0 and shard 1 at overlapping height 10 + distinct heights
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 10,
        hash: "0xs0_block10".to_string(),
        timestamp: 1_792_000_010,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: Some("0xmc_root_10".to_string()),
    })
    .unwrap();
    db.insert_block(&BlockRecord {
        shard_id: 1,
        height: 10,
        hash: "0xs1_block10".to_string(),
        timestamp: 1_792_000_010,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: Some("0xwc_root_10".to_string()),
    })
    .unwrap();
    db.insert_block(&BlockRecord {
        shard_id: 1,
        height: 12,
        hash: "0xs1_block12".to_string(),
        timestamp: 1_792_000_012,
        tx_count: 0,
        proposer: None,
        proposer_stl57: None,
        state_root: Some("0xwc_root_12".to_string()),
    })
    .unwrap();

    db.insert_transaction_in_shard(
        0,
        &TxRecord {
            tx_hash: "0xtx_shard0".to_string(),
            block_height: 10,
            tx_index: 0,
            from_addr: format!("0x{}", "11".repeat(32)),
            to_addr: format!("0x{}", "22".repeat(32)),
            from_stl57: None,
            to_stl57: None,
            amount: "100".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_010,
        },
    )
    .unwrap();
    db.insert_transaction_in_shard(
        1,
        &TxRecord {
            tx_hash: "0xtx_shard1".to_string(),
            block_height: 10,
            tx_index: 0,
            from_addr: format!("0x{}", "33".repeat(32)),
            to_addr: format!("0x{}", "44".repeat(32)),
            from_stl57: None,
            to_stl57: None,
            amount: "200".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_010,
        },
    )
    .unwrap();

    // Mock node RPC serving STELL_SHARDS=0,1 topology
    let mock_rpc = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            let method = body["method"].as_str().unwrap_or("");
            let result = match method {
                "stell_getShards" => serde_json::json!({
                    "shards": [
                        {
                            "shard_id": 0,
                            "type": "masterchain",
                            "tip_height": 10,
                            "tip_hash": "0xs0_block10",
                            "state_root": "0xmc_root_10",
                            "local": true
                        },
                        {
                            "shard_id": 1,
                            "type": "workchain",
                            "tip_height": 12,
                            "tip_hash": "0xs1_block12",
                            "state_root": "0xwc_root_12",
                            "local": false
                        }
                    ],
                    "total_shards": 2,
                    "routing_prefix_bits": 1,
                    "sharding": { "min_shards": 2 }
                }),
                _ => Value::Null,
            };
            axum::Json(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_url = format!("http://{}", mock_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(mock_listener, mock_rpc).await.unwrap() });

    let app = create_router(AppState::with_rpc(db, mock_url));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    // 1. /api/v2/shards reports both shards + indexed stats + address lookup
    let addr32 = [0x77u8; 32];
    let stl57 = stellereum::address::encode_stl57_address(&addr32);
    let shards_res: Value = client
        .get(format!("{base}/api/v2/shards?address={stl57}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(shards_res["source"], "rpc");
    assert_eq!(shards_res["total_shards"], 2);
    assert_eq!(shards_res["routing_prefix_bits"], 1);
    let shards = shards_res["shards"].as_array().unwrap();
    assert_eq!(shards.len(), 2);
    assert_eq!(shards[0]["shard_id"], 0);
    assert_eq!(shards[0]["indexed_tip_height"], 10);
    assert_eq!(shards[0]["indexed_blocks"], 1);
    assert_eq!(shards[1]["shard_id"], 1);
    assert_eq!(shards[1]["indexed_tip_height"], 12);
    assert_eq!(shards[1]["indexed_blocks"], 2);
    assert_eq!(shards_res["address_lookup"]["address"], hex::encode(addr32));
    assert_eq!(shards_res["address_lookup"]["stl57"], stl57);
    assert_eq!(shards_res["address_lookup"]["routed_shard"], 1);

    // 2. /api/v2/stats reports shards=2
    let stats_res: Value = client
        .get(format!("{base}/api/v2/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats_res["shards"], 2);

    // 3. /api/v2/blocks supports unfiltered (all shards) and shard-filtered queries
    let all_blocks: Value = client
        .get(format!("{base}/api/v2/blocks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all_blocks["blocks"].as_array().unwrap().len(), 3);

    let s0_blocks: Value = client
        .get(format!("{base}/api/v2/blocks?shard_id=0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s0_blocks["shard_id"], 0);
    assert_eq!(s0_blocks["blocks"].as_array().unwrap().len(), 1);
    assert_eq!(s0_blocks["blocks"][0]["hash"], "0xs0_block10");

    let s1_blocks: Value = client
        .get(format!("{base}/api/v2/blocks?shard=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s1_blocks["shard_id"], 1);
    assert_eq!(s1_blocks["blocks"].as_array().unwrap().len(), 2);
    assert_eq!(s1_blocks["blocks"][0]["height"], 12);

    // 4. /api/v2/block/:param supports ?shard_id=1 and shard:height (1:10) with shard-scoped txs
    for path in ["/api/v2/block/10?shard_id=1", "/api/v2/block/1:10"] {
        let blk: Value = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(blk["block"]["shard_id"], 1);
        assert_eq!(blk["block"]["hash"], "0xs1_block10");
        let txs = blk["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["tx_hash"], "0xtx_shard1");
    }

    let blk0: Value = client
        .get(format!("{base}/api/v2/block/10?shard_id=0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blk0["block"]["shard_id"], 0);
    assert_eq!(blk0["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(blk0["transactions"][0]["tx_hash"], "0xtx_shard0");

    // 5. /api/v2/search?q=1:10 finds shard 1 block 10
    let srch: Value = client
        .get(format!("{base}/api/v2/search?q=1:10"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(srch["type"], "block");
    assert_eq!(srch["result"]["shard_id"], 1);
    assert_eq!(srch["result"]["hash"], "0xs1_block10");
}
