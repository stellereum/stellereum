use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use stellereum::contract_abi::{AbiEvent, AbiParam, AbiType, ContractAbi};
use stellereum_indexer::db::{
    BlockRecord, ContractRecord, Database, EventFilter, EventRecord, TokenBalanceRecord, TxRecord,
};
use stellereum_indexer::server::{create_router, AppState, IndexerStreamHub};
use stellereum_indexer::syncer::{parse_node_sse_frame, NodeSseEvent, SseFrame, Syncer};

async fn spawn_empty_rest() -> String {
    let mock_rest = Router::new().route("/api/blocks", get(|| async { Json(json!([])) }));
    let rest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest_url = format!("http://{}", rest_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rest_listener, mock_rest).await.unwrap() });
    rest_url
}

#[tokio::test]
async fn multishard_backfill_indexes_shard1_blocks_txs_balances_and_events() {
    let db = Database::open(":memory:").expect("db");
    let stream_hub = Arc::new(IndexerStreamHub::new());
    let rest_url = spawn_empty_rest().await;

    let kp = stellereum::post_quantum::FalconKeypair::generate();
    let token_id = [0x33u8; 32];
    let recipient = [0x44u8; 32];
    let recipient3 = [0x66u8; 32];
    let deployed_contract = [0x55u8; 32];
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    let tx1 = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0x11u8; 64],
        [0u8; 32],
        0,
        500_000,
        0,
        0,
        1,
        vec![
            stellereum::svm::OpCode::SysCallDeployContract { code: wasm },
            stellereum::svm::OpCode::SysCallTokenTransfer {
                token_id,
                to: recipient,
                amount: 750,
            },
        ],
        &[0u8; 16],
    );
    let tx1_hash_hex = hex::encode(tx1.compute_tx_hash());
    let raw_tx1_hex = hex::encode(bincode::serialize(&tx1).unwrap());

    let tx3 = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0x22u8; 64],
        recipient3,
        12_345,
        21_000,
        0,
        1,
        1,
        vec![],
        &[0u8; 16],
    );
    let tx3_hash_hex = hex::encode(tx3.compute_tx_hash());
    let raw_tx3_hex = hex::encode(bincode::serialize(&tx3).unwrap());

    let deployed_hex = hex::encode(deployed_contract);
    let token_hex = hex::encode(token_id);
    let recipient_hex = hex::encode(recipient);
    let sender_hex = hex::encode(tx1.from);

    let tx1_h_rpc = tx1_hash_hex.clone();
    let raw1_rpc = raw_tx1_hex.clone();
    let tx3_h_rpc = tx3_hash_hex.clone();
    let raw3_rpc = raw_tx3_hex.clone();
    let dep_rpc = deployed_hex.clone();
    let tok_rpc = token_hex.clone();
    let recp_rpc = recipient_hex.clone();
    let snd_rpc = sender_hex.clone();

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let tx1_h = tx1_h_rpc.clone();
            let raw1 = raw1_rpc.clone();
            let tx3_h = tx3_h_rpc.clone();
            let raw3 = raw3_rpc.clone();
            let dep_c = dep_rpc.clone();
            let tok = tok_rpc.clone();
            let recp = recp_rpc.clone();
            let snd = snd_rpc.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => json!("0x2"),
                    "stell_getShards" => json!({
                        "shards": [
                            {
                                "shard_id": 0,
                                "type": "masterchain",
                                "tip_height": 2,
                                "tip_hash": "0xs0_b2",
                                "state_root": "0xs0_root2",
                                "local": true
                            },
                            {
                                "shard_id": 1,
                                "type": "workchain",
                                "tip_height": 3,
                                "tip_hash": "0xs1_b3",
                                "state_root": "0xs1_root3",
                                "local": false
                            }
                        ],
                        "total_shards": 2,
                        "routing_prefix_bits": 1
                    }),
                    "stell_getBlock" => {
                        let shard_id = body["params"]["shard_id"].as_u64().unwrap_or(0);
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        match (shard_id, h) {
                            (0, 1..=2) => json!({
                                "shard_id": 0,
                                "height": h,
                                "hash": format!("0xs0_b{h}"),
                                "txs": 0,
                                "timestamp": 1_792_000_000 + h
                            }),
                            (1, 1) => json!({
                                "shard_id": 1,
                                "height": 1,
                                "hash": "0xs1_b1",
                                "txs": 1,
                                "timestamp": 1_792_001_001
                            }),
                            (1, 2) => json!({
                                "shard_id": 1,
                                "height": 2,
                                "hash": "0xs1_b2",
                                "txs": 0,
                                "timestamp": 1_792_001_002
                            }),
                            (1, 3) => json!({
                                "shard_id": 1,
                                "height": 3,
                                "hash": "0xs1_b3",
                                "txs": 1,
                                "timestamp": 1_792_001_003
                            }),
                            _ => Value::Null,
                        }
                    }
                    "stell_getBlockTransactions" => {
                        let shard_id = body["params"]["shard_id"].as_u64().unwrap_or(0);
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        match (shard_id, h) {
                            (1, 1) => json!({
                                "height": 1,
                                "txs": [{
                                    "tx_hash": tx1_h,
                                    "index": 0,
                                    "status": "success",
                                    "gas_limit": "500000",
                                    "fee_charged": "280000",
                                    "raw_tx": raw1,
                                }]
                            }),
                            (1, 3) => json!({
                                "height": 3,
                                "txs": [{
                                    "tx_hash": tx3_h,
                                    "index": 0,
                                    "status": "success",
                                    "gas_limit": "21000",
                                    "fee_charged": "21000",
                                    "raw_tx": raw3,
                                }]
                            }),
                            _ => json!({ "height": h, "txs": [] }),
                        }
                    }
                    "stell_getTransactionReceipt" => {
                        let h = body["params"]["hash"].as_str().unwrap_or("");
                        let h_clean = h.strip_prefix("0x").unwrap_or(h);
                        if h_clean.eq_ignore_ascii_case(&tx1_h) {
                            json!({
                                "tx_hash": tx1_h,
                                "height": 1,
                                "index": 0,
                                "status": "success",
                                "contract_address": dep_c,
                                "events": [{
                                    "contract": dep_c,
                                    "topic": 0,
                                    "value": 42
                                }]
                            })
                        } else if h_clean.eq_ignore_ascii_case(&tx3_h) {
                            json!({
                                "tx_hash": tx3_h,
                                "height": 3,
                                "index": 0,
                                "status": "success",
                                "events": []
                            })
                        } else {
                            Value::Null
                        }
                    }
                    "stell_getContractAbi" => json!({ "contract": dep_c, "abi": Value::Null }),
                    "stell_tokenBalance" => {
                        let req_tok = body["params"]["token"].as_str().unwrap_or("");
                        let req_acc = body["params"]["account"].as_str().unwrap_or("");
                        if req_tok == tok && req_acc == recp {
                            json!("750")
                        } else if req_tok == tok && req_acc == snd {
                            json!("250")
                        } else {
                            json!("0")
                        }
                    }
                    _ => Value::Null,
                };
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let syncer = Syncer::new(db.clone(), rest_url, rpc_url).with_stream_hub(stream_hub.clone());
    let caught_up = syncer.sync_step().await.expect("sync_step");
    assert!(caught_up);

    // Shard 0 local blocks 1..=2 indexed.
    assert_eq!(db.get_shard_tip_height(0).unwrap(), 2);
    assert!(db.get_block_by_shard_and_height(0, 1).unwrap().is_some());
    assert!(db.get_block_by_shard_and_height(0, 2).unwrap().is_some());

    // Shard 1 blocks 1..=3 ALL backfilled (not just a bare tx_count=0 tip stub at #3).
    assert_eq!(db.get_shard_tip_height(1).unwrap(), 3);
    let s1_b1 = db.get_block_by_shard_and_height(1, 1).unwrap().unwrap();
    assert_eq!(s1_b1.hash, "0xs1_b1");
    assert_eq!(s1_b1.tx_count, 1);

    let s1_b2 = db.get_block_by_shard_and_height(1, 2).unwrap().unwrap();
    assert_eq!(s1_b2.hash, "0xs1_b2");
    assert_eq!(s1_b2.tx_count, 0);

    let s1_b3 = db.get_block_by_shard_and_height(1, 3).unwrap().unwrap();
    assert_eq!(s1_b3.hash, "0xs1_b3");
    assert_eq!(s1_b3.tx_count, 1);
    assert_eq!(s1_b3.state_root.as_deref(), Some("0xs1_root3"));

    // Shard 1 transactions indexed.
    let s1_txs_b1 = db.get_block_txs_for_shard(1, 1).unwrap();
    assert_eq!(s1_txs_b1.len(), 1);
    assert_eq!(s1_txs_b1[0].tx_hash, format!("0x{tx1_hash_hex}"));
    assert_eq!(s1_txs_b1[0].from_addr, format!("0x{sender_hex}"));

    let s1_txs_b3 = db.get_block_txs_for_shard(1, 3).unwrap();
    assert_eq!(s1_txs_b3.len(), 1);
    assert_eq!(s1_txs_b3[0].tx_hash, format!("0x{tx3_hash_hex}"));
    assert_eq!(s1_txs_b3[0].amount, "12345");
    assert_eq!(
        s1_txs_b3[0].to_addr,
        format!("0x{}", hex::encode(recipient3))
    );

    // Shard 1 deployed contract, token balances, and contract events indexed.
    let contracts = db
        .get_contracts_by_filter_keyset(None, Some(&deployed_hex), Some(1), 10, None)
        .unwrap();
    assert_eq!(contracts.items.len(), 1);
    assert_eq!(contracts.items[0].shard_id, 1);
    assert_eq!(contracts.items[0].deploy_height, 1);

    let holders = db
        .get_token_holders_keyset(&token_hex, false, Some(1), 10, None)
        .unwrap();
    assert_eq!(holders.items.len(), 2);
    assert_eq!(holders.items[0].shard_id, 1);
    assert_eq!(holders.items[0].balance, "750");
    assert_eq!(holders.items[1].shard_id, 1);
    assert_eq!(holders.items[1].balance, "250");

    let event_filter = EventFilter {
        contract: Some(deployed_hex.clone()),
        ..Default::default()
    };
    assert_eq!(db.count_events(&event_filter).unwrap(), 1);
    let events = db.get_events(&event_filter, 10, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].block_height, 1);
    assert_eq!(events[0].tx_hash, format!("0x{tx1_hash_hex}"));

    assert!(stream_hub.latest_seq() >= 7);
}

#[tokio::test]
async fn single_shard_zero_preserves_zero_extra_rpc_calls() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    let block_calls = Arc::new(AtomicU64::new(0));
    let shards_calls = Arc::new(AtomicU64::new(0));
    let block_calls_rpc = Arc::clone(&block_calls);
    let shards_calls_rpc = Arc::clone(&shards_calls);

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let b_calls = Arc::clone(&block_calls_rpc);
            let s_calls = Arc::clone(&shards_calls_rpc);
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => json!("0x2"),
                    "stell_getShards" => {
                        s_calls.fetch_add(1, Ordering::AcqRel);
                        json!({
                            "shards": [{
                                "shard_id": 0,
                                "type": "masterchain",
                                "tip_height": 2,
                                "tip_hash": "0xs0_b2",
                                "local": true
                            }],
                            "total_shards": 1
                        })
                    }
                    "stell_getBlock" => {
                        b_calls.fetch_add(1, Ordering::AcqRel);
                        assert!(
                            body["params"].get("shard_id").is_none(),
                            "single-shard stell_getBlock params must remain unchanged"
                        );
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        json!({
                            "height": h,
                            "hash": format!("0xs0_b{h}"),
                            "txs": 0,
                            "timestamp": 1_792_000_000 + h
                        })
                    }
                    _ => Value::Null,
                };
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let syncer = Syncer::new(db.clone(), rest_url, rpc_url);
    assert!(syncer.sync_step().await.expect("sync_step 1"));
    assert_eq!(db.get_shard_tip_height(0).unwrap(), 2);
    assert_eq!(shards_calls.load(Ordering::Acquire), 1);
    assert_eq!(block_calls.load(Ordering::Acquire), 2);

    // Caught-up tick performs zero extra block fetches.
    assert!(syncer.sync_step().await.expect("sync_step 2"));
    assert_eq!(shards_calls.load(Ordering::Acquire), 2);
    assert_eq!(block_calls.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn multishard_backfill_paginates_across_ticks_and_falls_back_only_when_pruned() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    let kp = stellereum::post_quantum::FalconKeypair::generate();
    let tx70 = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0x33u8; 64],
        [0x88u8; 32],
        999,
        21_000,
        0,
        0,
        1,
        vec![],
        &[0u8; 16],
    );
    let tx70_hash = hex::encode(tx70.compute_tx_hash());
    let raw_tx70 = hex::encode(bincode::serialize(&tx70).unwrap());

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let tx_h = tx70_hash.clone();
            let raw_t = raw_tx70.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => json!("0x1"),
                    "stell_getShards" => json!({
                        "shards": [
                            {
                                "shard_id": 0,
                                "type": "masterchain",
                                "tip_height": 1,
                                "tip_hash": "0xs0_b1",
                                "local": true
                            },
                            {
                                "shard_id": 1,
                                "type": "workchain",
                                "tip_height": 70,
                                "tip_hash": "0xs1_b70",
                                "state_root": "0xs1_root70",
                                "local": false
                            },
                            {
                                "shard_id": 2,
                                "type": "workchain",
                                "tip_height": 5,
                                "tip_hash": "0xs2_b5",
                                "state_root": "0xs2_root5",
                                "local": false
                            }
                        ],
                        "total_shards": 3,
                        "routing_prefix_bits": 2
                    }),
                    "stell_getBlock" => {
                        let shard_id = body["params"]["shard_id"].as_u64().unwrap_or(0);
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        match (shard_id, h) {
                            (0, 1) => json!({
                                "shard_id": 0,
                                "height": 1,
                                "hash": "0xs0_b1",
                                "txs": 0,
                                "timestamp": 1_792_000_001
                            }),
                            (1, 1..=69) => json!({
                                "shard_id": 1,
                                "height": h,
                                "hash": format!("0xs1_b{h}"),
                                "txs": 0,
                                "timestamp": 1_792_001_000 + h
                            }),
                            (1, 70) => json!({
                                "shard_id": 1,
                                "height": 70,
                                "hash": "0xs1_b70",
                                "txs": 1,
                                "timestamp": 1_792_001_070
                            }),
                            // Shard 2 is pruned/summary-only: `stell_getBlock` returns null.
                            _ => Value::Null,
                        }
                    }
                    "stell_getBlockTransactions" => {
                        let shard_id = body["params"]["shard_id"].as_u64().unwrap_or(0);
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        if shard_id == 1 && h == 70 {
                            json!({
                                "height": 70,
                                "txs": [{
                                    "tx_hash": tx_h,
                                    "index": 0,
                                    "status": "success",
                                    "gas_limit": "21000",
                                    "fee_charged": "21000",
                                    "raw_tx": raw_t,
                                }]
                            })
                        } else {
                            json!({ "height": h, "txs": [] })
                        }
                    }
                    "stell_getTransactionReceipt" => json!({
                        "tx_hash": tx_h,
                        "height": 70,
                        "index": 0,
                        "status": "success",
                        "events": []
                    }),
                    _ => Value::Null,
                };
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let syncer = Syncer::new(db.clone(), rest_url, rpc_url);

    // Tick 1: shard 1 backfills 1..=64 (must NOT jump to a 70 stub), shard 2 falls back to head #5.
    let caught_up_1 = syncer.sync_step().await.expect("sync_step 1");
    assert!(!caught_up_1);
    assert_eq!(db.get_shard_tip_height(0).unwrap(), 1);
    assert_eq!(db.get_shard_tip_height(1).unwrap(), 64);
    assert!(db.get_block_by_shard_and_height(1, 70).unwrap().is_none());

    assert_eq!(db.get_shard_tip_height(2).unwrap(), 5);
    let s2_head = db.get_block_by_shard_and_height(2, 5).unwrap().unwrap();
    assert_eq!(s2_head.hash, "0xs2_b5");
    assert_eq!(s2_head.tx_count, 0);
    assert_eq!(s2_head.state_root.as_deref(), Some("0xs2_root5"));

    // Tick 2: shard 1 backfills remaining 65..=70 and indexes block 70's transaction.
    let caught_up_2 = syncer.sync_step().await.expect("sync_step 2");
    assert!(caught_up_2);
    assert_eq!(db.get_shard_tip_height(1).unwrap(), 70);
    let s1_70 = db.get_block_by_shard_and_height(1, 70).unwrap().unwrap();
    assert_eq!(s1_70.hash, "0xs1_b70");
    assert_eq!(s1_70.tx_count, 1);
    assert_eq!(s1_70.state_root.as_deref(), Some("0xs1_root70"));

    let txs_70 = db.get_block_txs_for_shard(1, 70).unwrap();
    assert_eq!(txs_70.len(), 1);
    assert_eq!(txs_70[0].amount, "999");
}

#[tokio::test]
async fn get_shards_longest_prefix_routing_with_two_plus_workchain_shards() {
    let db = Database::open(":memory:").expect("db");
    let mock_rpc = Router::new().route(
        "/",
        post(|| async {
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "shards": [
                        {
                            "shard_id": 0,
                            "type": "masterchain",
                            "tip_height": 10,
                            "prefix": 0u64,
                            "prefix_len": 0u8,
                            "local": true
                        },
                        {
                            "shard_id": 1,
                            "type": "workchain",
                            "tip_height": 10,
                            "prefix": 0u64,
                            "prefix_len": 1u8,
                            "local": false
                        },
                        {
                            "shard_id": 2,
                            "type": "workchain",
                            "tip_height": 10,
                            "prefix": (1u64 << 63),
                            "prefix_len": 1u8,
                            "local": false
                        },
                        {
                            "shard_id": 3,
                            "type": "workchain",
                            "tip_height": 10,
                            "prefix": ((1u64 << 63) | (1u64 << 62)),
                            "prefix_len": 2u8,
                            "local": false
                        }
                    ],
                    "total_shards": 4,
                    "routing_prefix_bits": 2
                }
            }))
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let app = create_router(AppState::with_rpc(db, rpc_url));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    // Leading bit 0 -> shard 1.
    let addr_bit0 = format!("0x00{}", "11".repeat(31));
    let r1: Value = client
        .get(format!("{base}/api/v2/shards?address={addr_bit0}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r1["address_lookup"]["routed_shard"].as_u64(), Some(1));

    // Leading bits 10... -> shard 2.
    let addr_bit10 = format!("0x80{}", "11".repeat(31));
    let r2: Value = client
        .get(format!("{base}/api/v2/shards?address={addr_bit10}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2["address_lookup"]["routed_shard"].as_u64(), Some(2));

    // Leading bits 11... -> shard 3 (longest prefix: len 2 beats len 1).
    let addr_bit11 = format!("0xc0{}", "11".repeat(31));
    let r3: Value = client
        .get(format!("{base}/api/v2/shards?address={addr_bit11}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r3["address_lookup"]["routed_shard"].as_u64(), Some(3));

    // Explicit -1: prefix still routes to masterchain shard 0.
    let r_mc: Value = client
        .get(format!("{base}/api/v2/shards?address=-1:{addr_bit11}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r_mc["address_lookup"]["routed_shard"].as_u64(), Some(0));
}

#[tokio::test]
async fn shard_aware_invalidation_and_query_filters_and_rpc_forwarding() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    // Seed blocks on both shard 0 and shard 1 at height 2.
    for sid in [0u32, 1u32] {
        db.insert_block(&BlockRecord {
            shard_id: sid,
            height: 1,
            hash: format!("0xs{sid}_b1"),
            timestamp: 1_792_000_001,
            tx_count: 0,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
        db.insert_block(&BlockRecord {
            shard_id: sid,
            height: 2,
            hash: format!("0xs{sid}_b2"),
            timestamp: 1_792_000_002,
            tx_count: 0,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
    }

    let mock_rpc = Router::new().route(
        "/",
        post(|Json(body): Json<Value>| async move {
            let method = body["method"].as_str().unwrap_or("");
            let result = match method {
                "stell_blockNumber" => json!("0x2"),
                "stell_getShards" => json!({
                    "shards": [
                        { "shard_id": 0, "type": "masterchain", "tip_height": 2, "tip_hash": "0xs0_b2", "local": true },
                        { "shard_id": 1, "type": "workchain", "tip_height": 1, "tip_hash": "0xs1_b1", "local": false }
                    ],
                    "total_shards": 2
                }),
                "stell_getProgramAccounts" => json!({
                    "program": body["params"]["program"],
                    "echo_shard_id": body["params"]["shard_id"],
                    "items": [],
                    "count": 0
                }),
                _ => Value::Null,
            };
            Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let syncer = Syncer::new(db.clone(), rest_url, rpc_url.clone());

    // 1. Invalidation with shard_id: None and empty orphaned_blocks must NOT wipe shard 0!
    let frame_no_shard = SseFrame {
        event: None,
        id: None,
        data: r#"{"height":2,"reason":"fork","orphaned_blocks":[]}"#.to_string(),
    };
    let ev_no_shard = parse_node_sse_frame(&frame_no_shard).expect("parse frame");
    assert!(matches!(
        ev_no_shard,
        NodeSseEvent::Invalidation { shard_id: None, .. }
    ));
    syncer
        .handle_node_sse_event(ev_no_shard, None)
        .await
        .expect("handle no-shard invalidation");
    assert!(
        db.get_block_by_shard_and_height(0, 2).unwrap().is_some(),
        "empty orphaned_blocks without shard_id must not wipe shard 0"
    );
    assert!(db.get_block_by_shard_and_height(1, 2).unwrap().is_some());

    // 2. Invalidation with shard_id: Some(1) and empty orphaned_blocks invalidates shard 1 only.
    let frame_s1 = SseFrame {
        event: None,
        id: None,
        data: r#"{"shard_id":1,"height":2,"reason":"fork","orphaned_blocks":[]}"#.to_string(),
    };
    let ev_s1 = parse_node_sse_frame(&frame_s1).expect("parse s1 frame");
    assert!(matches!(
        ev_s1,
        NodeSseEvent::Invalidation {
            shard_id: Some(1),
            height: Some(2),
            ..
        }
    ));
    syncer
        .handle_node_sse_event(ev_s1, None)
        .await
        .expect("handle s1 invalidation");
    assert!(
        db.get_block_by_shard_and_height(0, 2).unwrap().is_some(),
        "shard 1 invalidation must leave shard 0 height 2 intact"
    );
    assert!(
        db.get_block_by_shard_and_height(1, 2).unwrap().is_none(),
        "shard 1 height 2 must be invalidated"
    );

    // 3. Seed shard-specific txs, events, and contracts and verify HTTP ?shard_id= filters + RPC proxy forwarding.
    let addr0 = "aa".repeat(32);
    let addr1 = "bb".repeat(32);
    db.insert_transaction_in_shard(
        0,
        &TxRecord {
            tx_hash: "0xs0_t1".to_string(),
            block_height: 1,
            tx_index: 0,
            from_addr: format!("0x{addr0}"),
            to_addr: format!("0x{addr1}"),
            from_stl57: None,
            to_stl57: None,
            amount: "10".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_001,
        },
    )
    .unwrap();
    db.insert_transaction_in_shard(
        1,
        &TxRecord {
            tx_hash: "0xs1_t1".to_string(),
            block_height: 1,
            tx_index: 0,
            from_addr: format!("0x{addr1}"),
            to_addr: format!("0x{addr0}"),
            from_stl57: None,
            to_stl57: None,
            amount: "20".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_001,
        },
    )
    .unwrap();
    db.insert_event_in_shard(
        0,
        &EventRecord {
            tx_hash: "0xs0_t1".to_string(),
            block_height: 1,
            log_index: 0,
            contract: addr0.clone(),
            topic0: format!("0x{:064x}", 0),
            topics_json: "[]".to_string(),
            data: "{}".to_string(),
            event_name: None,
            decoded_json: None,
        },
    )
    .unwrap();
    db.insert_event_in_shard(
        1,
        &EventRecord {
            tx_hash: "0xs1_t1".to_string(),
            block_height: 1,
            log_index: 0,
            contract: addr1.clone(),
            topic0: format!("0x{:064x}", 0),
            topics_json: "[]".to_string(),
            data: "{}".to_string(),
            event_name: None,
            decoded_json: None,
        },
    )
    .unwrap();
    db.upsert_contract(&ContractRecord {
        shard_id: 0,
        address: addr0.clone(),
        address_stl57: None,
        creator: None,
        creator_stl57: None,
        code_hash: None,
        deploy_height: 1,
        has_abi: false,
    })
    .unwrap();
    db.upsert_contract(&ContractRecord {
        shard_id: 1,
        address: addr1.clone(),
        address_stl57: None,
        creator: None,
        creator_stl57: None,
        code_hash: None,
        deploy_height: 1,
        has_abi: false,
    })
    .unwrap();

    let app = create_router(AppState::with_rpc(db, rpc_url));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    let ev_s1: Value = client
        .get(format!("{base}/api/v2/events?shard_id=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ev_s1["count"].as_u64(), Some(1));
    assert_eq!(ev_s1["events"][0]["tx_hash"], "0xs1_t1");

    let tx_s1: Value = client
        .get(format!("{base}/api/v2/txs?shard_id=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let txs = tx_s1["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0]["tx_hash"], "0xs1_t1");

    let ct_s1: Value = client
        .get(format!("{base}/api/v2/contracts?shard_id=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let contracts = ct_s1["contracts"].as_array().unwrap();
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0]["contract"], addr1);

    let prog: Value = client
        .get(format!(
            "{base}/api/v2/program/system/accounts?owner={addr1}&shard_id=1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prog["echo_shard_id"].as_u64(), Some(1));
}

#[tokio::test]
async fn native_tx_decode_rejects_trailing_bytes() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    let kp = stellereum::post_quantum::FalconKeypair::generate();
    let tx = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0x11u8; 64],
        [0x77u8; 32],
        123,
        21_000,
        0,
        0,
        0,
        vec![],
        &[0u8; 16],
    );
    let tx_hash_hex = hex::encode(tx.compute_tx_hash());
    let mut raw_bytes = bincode::serialize(&tx).unwrap();
    raw_bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let trailing_hex = hex::encode(raw_bytes);

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let txh = tx_hash_hex.clone();
            let raw = trailing_hex.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => json!("0x1"),
                    "stell_getShards" => json!({
                        "shards": [{ "shard_id": 0, "type": "masterchain", "tip_height": 1, "tip_hash": "0xb1", "local": true }],
                        "total_shards": 1
                    }),
                    "stell_getBlock" => json!({
                        "height": 1,
                        "hash": "0xb1",
                        "txs": 1,
                        "timestamp": 1_792_000_001
                    }),
                    "stell_getBlockTransactions" => json!({
                        "height": 1,
                        "txs": [{
                            "tx_hash": txh,
                            "index": 0,
                            "status": "success",
                            "gas_limit": "21000",
                            "fee_charged": "21000",
                            "raw_tx": raw,
                        }]
                    }),
                    _ => Value::Null,
                };
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let syncer = Syncer::new(db.clone(), rest_url, rpc_url);
    syncer.sync_step().await.expect("sync_step");
    assert!(
        db.get_block_txs_for_shard(0, 1).unwrap().is_empty(),
        "raw_tx with trailing bytes must be rejected"
    );
}

#[tokio::test]
async fn get_validators_preserves_each_validators_own_falcon_pubkey_after_sort() {
    let db = Database::open(":memory:").expect("db");
    let addr_low = "11".repeat(32);
    let addr_high = "22".repeat(32);
    let addr_mid = "33".repeat(32);

    let a_low = addr_low.clone();
    let a_high = addr_high.clone();
    let a_mid = addr_mid.clone();
    let mock_rpc = Router::new().route(
        "/",
        post(move || {
            let v_low = a_low.clone();
            let v_high = a_high.clone();
            let v_mid = a_mid.clone();
            async move {
                // Intentionally unsorted (ascending / mixed power) so descending stake sort reorders items.
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "validators": [
                            { "validator": v_low, "power": "100", "falcon_pubkey": "falcon_pk_low_11" },
                            { "validator": v_high, "power": "300", "falcon_pubkey": "falcon_pk_high_22" },
                            { "validator": v_mid, "power": "200", "falcon_pubkey": "falcon_pk_mid_33" }
                        ],
                        "total_power": "600",
                        "quorum": "401",
                        "fragile": false,
                        "fragile_reason": Value::Null
                    }
                }))
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let app = create_router(AppState::with_rpc(db, rpc_url));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let resp = reqwest::Client::new()
        .get(format!("{base}/api/v2/validators"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let vals = body["validators"].as_array().expect("validators array");
    assert_eq!(vals.len(), 3);

    assert_eq!(vals[0]["rank"], 1);
    assert_eq!(vals[0]["address"], addr_high);
    assert_eq!(vals[0]["stake"], "300");
    assert_eq!(vals[0]["falcon_pubkey"], "falcon_pk_high_22");

    assert_eq!(vals[1]["rank"], 2);
    assert_eq!(vals[1]["address"], addr_mid);
    assert_eq!(vals[1]["stake"], "200");
    assert_eq!(vals[1]["falcon_pubkey"], "falcon_pk_mid_33");

    assert_eq!(vals[2]["rank"], 3);
    assert_eq!(vals[2]["address"], addr_low);
    assert_eq!(vals[2]["stake"], "100");
    assert_eq!(vals[2]["falcon_pubkey"], "falcon_pk_low_11");
}

#[tokio::test]
async fn transient_rpc_failure_during_fetch_abi_does_not_poison_abi_cache() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    let kp = stellereum::post_quantum::FalconKeypair::generate();
    let contract_hex = "cc".repeat(32);
    let sender_0x = format!("0x{}", "dd".repeat(32));

    let make_tx = |nonce: u64| {
        let tx = stellereum::sharding::Transaction::new_pq_explicit(
            stellereum::post_quantum::PqScheme::Falcon512,
            kp.public_key.clone(),
            vec![0x11u8; 64],
            [0xccu8; 32],
            0,
            200_000,
            nonce,
            0,
            0,
            vec![],
            &[0u8; 16],
        );
        let h = hex::encode(tx.compute_tx_hash());
        let raw = hex::encode(bincode::serialize(&tx).unwrap());
        (h, raw)
    };
    let (tx1_h, tx1_raw) = make_tx(0);
    let (tx2_h, tx2_raw) = make_tx(1);

    let mut abi = ContractAbi::default();
    abi.add_event(AbiEvent::new(
        "Deposited",
        vec![AbiParam::new("sender", AbiType::Address)],
        vec![AbiParam::new("amount", AbiType::U64)],
    ));
    let abi_json_val = abi.to_json_value();

    let tip_height = Arc::new(AtomicU64::new(1));
    let abi_rpc_healthy = Arc::new(AtomicBool::new(false));
    let abi_calls = Arc::new(AtomicU64::new(0));

    let tip_srv = Arc::clone(&tip_height);
    let healthy_srv = Arc::clone(&abi_rpc_healthy);
    let calls_srv = Arc::clone(&abi_calls);
    let c_srv = contract_hex.clone();
    let s_srv = sender_0x.clone();
    let t1_h = tx1_h.clone();
    let t1_r = tx1_raw.clone();
    let t2_h = tx2_h.clone();
    let t2_r = tx2_raw.clone();
    let abi_srv = abi_json_val.clone();

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let tip = Arc::clone(&tip_srv);
            let healthy = Arc::clone(&healthy_srv);
            let calls = Arc::clone(&calls_srv);
            let contract = c_srv.clone();
            let sender = s_srv.clone();
            let h1 = t1_h.clone();
            let r1 = t1_r.clone();
            let h2 = t2_h.clone();
            let r2 = t2_r.clone();
            let abi_val = abi_srv.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                if method == "stell_getContractAbi" {
                    calls.fetch_add(1, Ordering::AcqRel);
                    if !healthy.load(Ordering::Acquire) {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({ "error": "temporary rpc outage" })),
                        )
                            .into_response();
                    }
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "contract": contract,
                            "abi": abi_val
                        }
                    }))
                    .into_response();
                }

                let cur_tip = tip.load(Ordering::Acquire);
                let result = match method {
                    "stell_blockNumber" => json!(format!("0x{cur_tip:x}")),
                    "stell_getShards" => json!({
                        "shards": [{
                            "shard_id": 0,
                            "type": "masterchain",
                            "tip_height": cur_tip,
                            "tip_hash": format!("0xb{cur_tip}"),
                            "local": true
                        }],
                        "total_shards": 1
                    }),
                    "stell_getBlock" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        json!({
                            "shard_id": 0,
                            "height": h,
                            "hash": format!("0xb{h}"),
                            "txs": 1,
                            "timestamp": 1_792_000_000 + h
                        })
                    }
                    "stell_getBlockTransactions" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        let (tx_h, raw) = if h == 1 { (h1, r1) } else { (h2, r2) };
                        json!({
                            "height": h,
                            "txs": [{
                                "tx_hash": tx_h,
                                "index": 0,
                                "status": "success",
                                "gas_limit": "200000",
                                "fee_charged": "50000",
                                "raw_tx": raw
                            }]
                        })
                    }
                    "stell_getTransactionReceipt" => {
                        let req_h = body["params"]["hash"].as_str().unwrap_or("");
                        let clean = req_h.strip_prefix("0x").unwrap_or(req_h);
                        let (h, amount) = if clean.eq_ignore_ascii_case(&h1) {
                            (1u64, 111u64)
                        } else {
                            (2u64, 222u64)
                        };
                        json!({
                            "tx_hash": clean,
                            "height": h,
                            "index": 0,
                            "status": "success",
                            "events": [{
                                "contract": contract,
                                "topic": 0,
                                "topics": [sender],
                                "data": { "amount": amount }
                            }]
                        })
                    }
                    _ => Value::Null,
                };
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result })).into_response()
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

    let syncer = Syncer::new(db.clone(), rest_url, rpc_url);

    // Tick 1: ABI RPC returns HTTP 503. Event is stored raw, and AbiCache MUST NOT be poisoned with None.
    assert!(syncer.sync_step().await.expect("sync_step 1"));
    assert_eq!(abi_calls.load(Ordering::Acquire), 1);
    assert!(
        !syncer.abis().contains(&contract_hex),
        "transient ABI fetch failure must not poison AbiCache"
    );

    // Tick 2: ABI RPC recovers and block 2 emits another event from the same contract.
    abi_rpc_healthy.store(true, Ordering::Release);
    tip_height.store(2, Ordering::Release);
    assert!(syncer.sync_step().await.expect("sync_step 2"));
    assert_eq!(abi_calls.load(Ordering::Acquire), 2);
    assert!(syncer.abis().contains(&contract_hex));
    assert_eq!(syncer.abis().get(&contract_hex), Some(abi));

    let events = db
        .get_events(
            &EventFilter {
                contract: Some(contract_hex.clone()),
                ..Default::default()
            },
            10,
            0,
        )
        .unwrap();
    assert_eq!(events.len(), 2);
    // Block 2's event (newest first) was decoded at index time once ABI fetch succeeded.
    assert_eq!(events[0].block_height, 2);
    assert_eq!(events[0].event_name.as_deref(), Some("Deposited"));
    let decoded: Value = serde_json::from_str(events[0].decoded_json.as_deref().unwrap()).unwrap();
    assert_eq!(decoded["topics"]["sender"], sender_0x);
    assert_eq!(decoded["data"]["amount"], 222);
}

#[test]
fn identical_contract_address_across_shards_is_isolated_and_reorg_safe() {
    let db = Database::open(":memory:").expect("db");
    let shared_addr = "ab".repeat(32);
    let creator0 = "10".repeat(32);
    let creator1 = "20".repeat(32);
    let code_hash0 = "aa".repeat(32);
    let code_hash1 = "bb".repeat(32);

    for sid in [0u32, 1u32] {
        db.insert_block(&BlockRecord {
            shard_id: sid,
            height: 5,
            hash: format!("0xs{sid}_b5"),
            timestamp: 1_792_000_005,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
    }

    db.upsert_contract(&ContractRecord {
        shard_id: 0,
        address: shared_addr.clone(),
        address_stl57: None,
        creator: Some(creator0.clone()),
        creator_stl57: None,
        code_hash: Some(code_hash0.clone()),
        deploy_height: 5,
        has_abi: false,
    })
    .unwrap();

    db.upsert_contract(&ContractRecord {
        shard_id: 1,
        address: shared_addr.clone(),
        address_stl57: None,
        creator: Some(creator1.clone()),
        creator_stl57: None,
        code_hash: Some(code_hash1.clone()),
        deploy_height: 5,
        has_abi: false,
    })
    .unwrap();

    db.mark_contract_has_abi_in_shard(1, &shared_addr, true)
        .unwrap();

    let s0 = db
        .get_contracts_by_filter_keyset(None, Some(&shared_addr), Some(0), 10, None)
        .unwrap();
    assert_eq!(s0.items.len(), 1);
    assert_eq!(s0.items[0].shard_id, 0);
    assert_eq!(s0.items[0].creator.as_deref(), Some(creator0.as_str()));
    assert_eq!(s0.items[0].code_hash.as_deref(), Some(code_hash0.as_str()));
    assert!(!s0.items[0].has_abi);

    let s1 = db
        .get_contracts_by_filter_keyset(None, Some(&shared_addr), Some(1), 10, None)
        .unwrap();
    assert_eq!(s1.items.len(), 1);
    assert_eq!(s1.items[0].shard_id, 1);
    assert_eq!(s1.items[0].creator.as_deref(), Some(creator1.as_str()));
    assert_eq!(s1.items[0].code_hash.as_deref(), Some(code_hash1.as_str()));
    assert!(s1.items[0].has_abi);

    // Reorging shard 1 height 5 must remove shard 1's contract row while preserving shard 0's row.
    assert!(db.invalidate_shard_height(1, 5).unwrap());
    let s1_after = db
        .get_contracts_by_filter_keyset(None, Some(&shared_addr), Some(1), 10, None)
        .unwrap();
    assert!(s1_after.items.is_empty());

    let s0_after = db
        .get_contracts_by_filter_keyset(None, Some(&shared_addr), Some(0), 10, None)
        .unwrap();
    assert_eq!(s0_after.items.len(), 1);
    assert_eq!(
        s0_after.items[0].creator.as_deref(),
        Some(creator0.as_str())
    );
    assert_eq!(
        s0_after.items[0].code_hash.as_deref(),
        Some(code_hash0.as_str())
    );
}

#[test]
fn legacy_contracts_single_pk_migrates_idempotently_to_composite_pk() {
    let tmp_dir = std::env::temp_dir();
    let db_path = tmp_dir.join(format!(
        "test_contracts_v2_migration_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let db_path_str = db_path.to_str().unwrap();

    let shared_addr = "cd".repeat(32);
    let creator0 = "31".repeat(32);
    let creator1 = "32".repeat(32);

    {
        let conn = rusqlite::Connection::open(db_path_str).unwrap();
        conn.execute_batch(
            "CREATE TABLE contracts (
                 shard_id INTEGER NOT NULL DEFAULT 0,
                 address TEXT PRIMARY KEY,
                 creator TEXT,
                 code_hash TEXT,
                 deploy_height INTEGER NOT NULL,
                 has_abi INTEGER NOT NULL DEFAULT 0
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO contracts (shard_id, address, creator, code_hash, deploy_height, has_abi)
             VALUES (0, ?1, ?2, 'hash0', 3, 1)",
            rusqlite::params![shared_addr, creator0],
        )
        .unwrap();
    }

    // Opening twice verifies the migration is both effective and idempotent.
    let db1 = Database::open(db_path_str).unwrap();
    drop(db1);
    let db = Database::open(db_path_str).unwrap();

    db.upsert_contract(&ContractRecord {
        shard_id: 1,
        address: shared_addr.clone(),
        address_stl57: None,
        creator: Some(creator1.clone()),
        creator_stl57: None,
        code_hash: Some("hash1".to_string()),
        deploy_height: 7,
        has_abi: false,
    })
    .unwrap();

    let s0 = db
        .get_contracts_by_filter_keyset(None, Some(&shared_addr), Some(0), 10, None)
        .unwrap();
    assert_eq!(s0.items.len(), 1);
    assert_eq!(s0.items[0].creator.as_deref(), Some(creator0.as_str()));
    assert!(s0.items[0].has_abi);

    let s1 = db
        .get_contracts_by_filter_keyset(None, Some(&shared_addr), Some(1), 10, None)
        .unwrap();
    assert_eq!(s1.items.len(), 1);
    assert_eq!(s1.items[0].creator.as_deref(), Some(creator1.as_str()));

    drop(db);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{db_path_str}-wal"));
    let _ = std::fs::remove_file(format!("{db_path_str}-shm"));
}

#[test]
fn token_balance_reorg_restores_previous_balance_instead_of_wiping_holder() {
    let db = Database::open(":memory:").expect("db");
    let token_id = "55".repeat(32);
    let owner_a = "66".repeat(32);
    let owner_b = "77".repeat(32);

    for h in [5u64, 10u64] {
        db.insert_block(&BlockRecord {
            shard_id: 0,
            height: h,
            hash: format!("0xs0_b{h}"),
            timestamp: 1_792_000_000 + h,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
    }

    // Height 5: owner_a starts with 1000.
    db.upsert_token_balance(&TokenBalanceRecord {
        shard_id: 0,
        token_id: token_id.clone(),
        owner: owner_a.clone(),
        owner_stl57: None,
        balance: "1000".to_string(),
        updated_height: 5,
    })
    .unwrap();

    // Height 10: owner_a updates to 1500 (and again within height 10 to 1750);
    // owner_b is newly created at height 10 with 400.
    db.upsert_token_balance(&TokenBalanceRecord {
        shard_id: 0,
        token_id: token_id.clone(),
        owner: owner_a.clone(),
        owner_stl57: None,
        balance: "1500".to_string(),
        updated_height: 10,
    })
    .unwrap();
    db.upsert_token_balance(&TokenBalanceRecord {
        shard_id: 0,
        token_id: token_id.clone(),
        owner: owner_a.clone(),
        owner_stl57: None,
        balance: "1750".to_string(),
        updated_height: 10,
    })
    .unwrap();
    db.upsert_token_balance(&TokenBalanceRecord {
        shard_id: 0,
        token_id: token_id.clone(),
        owner: owner_b.clone(),
        owner_stl57: None,
        balance: "400".to_string(),
        updated_height: 10,
    })
    .unwrap();

    let before = db
        .get_token_holders_keyset(&token_id, false, Some(0), 10, None)
        .unwrap();
    assert_eq!(before.items.len(), 2);
    assert_eq!(before.items[0].owner, owner_a);
    assert_eq!(before.items[0].balance, "1750");
    assert_eq!(before.items[0].updated_height, 10);

    // Reorg at height 10 must restore owner_a to 1000 at height 5 and drop owner_b.
    assert!(db.invalidate_shard_height(0, 10).unwrap());

    let after = db
        .get_token_holders_keyset(&token_id, false, Some(0), 10, None)
        .unwrap();
    assert_eq!(after.items.len(), 1);
    assert_eq!(after.items[0].owner, owner_a);
    assert_eq!(after.items[0].balance, "1000");
    assert_eq!(after.items[0].updated_height, 5);

    // Invalidating height 5 then removes owner_a cleanly.
    assert!(db.invalidate_shard_height(0, 5).unwrap());
    let after_h5 = db
        .get_token_holders_keyset(&token_id, false, Some(0), 10, None)
        .unwrap();
    assert!(after_h5.items.is_empty());
}

#[tokio::test]
async fn get_block_defaults_to_shard0_without_interleaving_cross_shard_txs() {
    let db = Database::open(":memory:").expect("db");
    for sid in [0u32, 1u32] {
        db.insert_block(&BlockRecord {
            shard_id: sid,
            height: 10,
            hash: format!("0xs{sid}_h10"),
            timestamp: 1_792_000_010,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
        db.insert_transaction_in_shard(
            sid,
            &TxRecord {
                tx_hash: format!("0xs{sid}_tx0"),
                block_height: 10,
                tx_index: 0,
                from_addr: format!("0x{}", "11".repeat(32)),
                to_addr: format!("0x{}", "22".repeat(32)),
                from_stl57: None,
                to_stl57: None,
                amount: ((sid + 1) * 100).to_string(),
                fee_charged: "1".to_string(),
                gas_limit: "10".to_string(),
                status: "success".to_string(),
                timestamp: 1_792_000_010,
            },
        )
        .unwrap();
    }

    assert_eq!(db.get_block_txs(10).unwrap().len(), 1);
    assert_eq!(db.get_block_txs(10).unwrap()[0].tx_hash, "0xs0_tx0");

    let app = create_router(AppState::new(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    // Unqualified height defaults to shard 0 and only includes shard 0's tx.
    let b0: Value = client
        .get(format!("{base}/api/v2/block/10"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(b0["block"]["shard_id"], 0);
    assert_eq!(b0["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(b0["transactions"][0]["tx_hash"], "0xs0_tx0");

    // Explicit ?shard_id=1 returns shard 1 and only shard 1's tx.
    let b1: Value = client
        .get(format!("{base}/api/v2/block/10?shard_id=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(b1["block"]["shard_id"], 1);
    assert_eq!(b1["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(b1["transactions"][0]["tx_hash"], "0xs1_tx0");
}
