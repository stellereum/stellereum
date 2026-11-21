use axum::{
    body::Body,
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use stellereum_indexer::db::{
    BlockRecord, ContractRecord, Database, EventFilter, EventRecord, TokenBalanceRecord, TxRecord,
};
use stellereum_indexer::server::{
    create_router, AppState, IndexerStreamHub, StreamPublishInput, INDEXER_REPLAY_WINDOW,
    MAX_INDEXER_SSE_CLIENTS, MAX_PROGRAM_ACCOUNTS_LIMIT,
};
use stellereum_indexer::syncer::{
    parse_node_sse_frame, NodeSseEvent, SseDisconnectReason, SseFrameParser, Syncer,
};

async fn spawn_api(state: AppState) -> (String, reqwest::Client) {
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    (base, client)
}

#[tokio::test]
async fn indexer_keyset_cursor_stable_under_concurrent_inserts() {
    let db = Database::open(":memory:").expect("db");
    let addr_bytes = [0x42u8; 32];
    let addr_0x = format!("0x{}", hex::encode(addr_bytes));
    let other_0x = format!("0x{}", hex::encode([0x99u8; 32]));
    let contract_hex = "ab".repeat(32);

    // Seed 9 blocks (height 10 has BOTH shard 0 and shard 1 to verify composite block cursor),
    // 9 txs involving addr_0x, and 9 contract events.
    for h in 1u64..=8u64 {
        db.insert_block(&BlockRecord {
            shard_id: 0,
            height: h,
            hash: format!("0xblk_0_{h:064x}"),
            timestamp: 1_792_000_000 + h,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
    }
    for sid in [0u32, 1u32] {
        db.insert_block(&BlockRecord {
            shard_id: sid,
            height: 10,
            hash: format!("0xblk_{sid}_10"),
            timestamp: 1_792_000_010,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
    }

    for i in 0..9u32 {
        let h = 1 + (i as u64 / 2);
        let tx_idx = i % 2;
        db.insert_transaction(&TxRecord {
            tx_hash: format!("0xtx_{i:064x}"),
            block_height: h,
            tx_index: tx_idx,
            from_addr: addr_0x.clone(),
            to_addr: other_0x.clone(),
            from_stl57: None,
            to_stl57: None,
            amount: "100".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_000 + h,
        })
        .unwrap();

        db.insert_event(&EventRecord {
            tx_hash: format!("0xevtx_{i:064x}"),
            block_height: h,
            log_index: tx_idx,
            contract: contract_hex.clone(),
            topic0: format!("0x{:064x}", i),
            topics_json: "[]".to_string(),
            data: json!({"value": i}).to_string(),
            event_name: Some("Ping".to_string()),
            decoded_json: None,
        })
        .unwrap();
    }

    let (base, client) = spawn_api(AppState::new(db.clone())).await;

    // Page 1 (limit=3) for blocks, account txs, events.
    let b_p1: Value = client
        .get(format!("{base}/api/v2/blocks?limit=3"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(b_p1["has_more"], true);
    let b_cur1 = b_p1["next_cursor"].as_str().expect("block cursor 1");
    let mut seen_blocks: Vec<(u64, u32)> = b_p1["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["height"].as_u64().unwrap(),
                b["shard_id"].as_u64().unwrap() as u32,
            )
        })
        .collect();
    assert_eq!(seen_blocks, vec![(10, 0), (10, 1), (8, 0)]);

    let t_p1: Value = client
        .get(format!("{base}/api/v2/account/{addr_0x}/txs?limit=3"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(t_p1["has_more"], true);
    let t_cur1 = t_p1["next_cursor"].as_str().expect("tx cursor 1");
    let mut seen_txs: Vec<String> = t_p1["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tx_hash"].as_str().unwrap().to_string())
        .collect();

    let e_p1: Value = client
        .get(format!(
            "{base}/api/v2/events?contract={contract_hex}&limit=3"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(e_p1["has_more"], true);
    let e_cur1 = e_p1["next_cursor"].as_str().expect("event cursor 1");
    let mut seen_events: Vec<String> = e_p1["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["tx_hash"].as_str().unwrap().to_string())
        .collect();

    // CONCURRENT INSERTS at higher tip heights BETWEEN page 1 and page 2!
    for h in 200u64..=205u64 {
        db.insert_block(&BlockRecord {
            shard_id: 0,
            height: h,
            hash: format!("0xblk_new_{h:064x}"),
            timestamp: 1_792_000_500 + h,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
        db.insert_transaction(&TxRecord {
            tx_hash: format!("0xtx_new_{h:064x}"),
            block_height: h,
            tx_index: 0,
            from_addr: addr_0x.clone(),
            to_addr: other_0x.clone(),
            from_stl57: None,
            to_stl57: None,
            amount: "999".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_500 + h,
        })
        .unwrap();
        db.insert_event(&EventRecord {
            tx_hash: format!("0xevtx_new_{h:064x}"),
            block_height: h,
            log_index: 0,
            contract: contract_hex.clone(),
            topic0: format!("0x{:064x}", h),
            topics_json: "[]".to_string(),
            data: "{}".to_string(),
            event_name: Some("Ping".to_string()),
            decoded_json: None,
        })
        .unwrap();
    }

    // Drain remaining block pages using cursors; must NOT duplicate or skip anything <= 10.
    let mut next_b = Some(b_cur1.to_string());
    while let Some(cur) = next_b {
        let p: Value = client
            .get(format!("{base}/api/v2/blocks?limit=3&cursor={cur}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        for b in p["blocks"].as_array().unwrap() {
            seen_blocks.push((
                b["height"].as_u64().unwrap(),
                b["shard_id"].as_u64().unwrap() as u32,
            ));
        }
        next_b = p["next_cursor"].as_str().map(str::to_string);
        if !p["has_more"].as_bool().unwrap() {
            assert!(next_b.is_none());
            break;
        }
    }
    assert_eq!(
        seen_blocks,
        vec![
            (10, 0),
            (10, 1),
            (8, 0),
            (7, 0),
            (6, 0),
            (5, 0),
            (4, 0),
            (3, 0),
            (2, 0),
            (1, 0),
        ]
    );

    // Drain remaining tx pages; must match all 9 original txs with zero duplicates/skips.
    let mut next_t = Some(t_cur1.to_string());
    while let Some(cur) = next_t {
        let p: Value = client
            .get(format!(
                "{base}/api/v2/account/{addr_0x}/txs?limit=3&cursor={cur}"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        for t in p["transactions"].as_array().unwrap() {
            seen_txs.push(t["tx_hash"].as_str().unwrap().to_string());
        }
        next_t = p["next_cursor"].as_str().map(str::to_string);
        if !p["has_more"].as_bool().unwrap() {
            assert!(next_t.is_none());
            break;
        }
    }
    assert_eq!(seen_txs.len(), 9);
    let unique_txs: std::collections::HashSet<&String> = seen_txs.iter().collect();
    assert_eq!(unique_txs.len(), 9);
    assert!(seen_txs.iter().all(|h| !h.starts_with("0xtx_new_")));

    // Drain remaining event pages; must match all 9 original events with zero duplicates/skips.
    let mut next_e = Some(e_cur1.to_string());
    while let Some(cur) = next_e {
        let p: Value = client
            .get(format!(
                "{base}/api/v2/events?contract={contract_hex}&limit=3&cursor={cur}"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        for e in p["events"].as_array().unwrap() {
            seen_events.push(e["tx_hash"].as_str().unwrap().to_string());
        }
        next_e = p["next_cursor"].as_str().map(str::to_string);
        if !p["has_more"].as_bool().unwrap() {
            assert!(next_e.is_none());
            break;
        }
    }
    assert_eq!(seen_events.len(), 9);
    let unique_events: std::collections::HashSet<&String> = seen_events.iter().collect();
    assert_eq!(unique_events.len(), 9);
    assert!(seen_events.iter().all(|h| !h.starts_with("0xevtx_new_")));

    // Invalid cursors & conflicting cursor+offset fail closed with 400.
    let bad_cur = client
        .get(format!("{base}/api/v2/blocks?cursor=not_a_cursor"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_cur.status(), reqwest::StatusCode::BAD_REQUEST);

    let conflict = client
        .get(format!("{base}/api/v2/txs?cursor=10:0&offset=5"))
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn indexer_token_balances_and_contracts_tables_and_reorg_cleanup() {
    let db = Database::open(":memory:").expect("db");

    let tok_a = "10".repeat(32);
    let tok_b = "20".repeat(32);
    let tok_c = "30".repeat(32);
    let owner_1_bytes = [0xAAu8; 32];
    let owner_1 = hex::encode(owner_1_bytes);
    let owner_1_stl57 = stellereum::address::encode_stl57_address(&owner_1_bytes);
    let owner_2 = "bb".repeat(32);
    let owner_3 = "cc".repeat(32);

    // Seed token_balances (including large u64::MAX and zero balance).
    for (shard_id, token_id, owner, balance, updated_height) in [
        (0u32, tok_a.as_str(), owner_1.as_str(), "1000", 10u64),
        (0u32, tok_b.as_str(), owner_1.as_str(), "0", 11u64),
        (0u32, tok_c.as_str(), owner_1.as_str(), "500", 12u64),
        (
            0u32,
            tok_a.as_str(),
            owner_2.as_str(),
            "18446744073709551615",
            12u64,
        ),
        (0u32, tok_a.as_str(), owner_3.as_str(), "200", 13u64),
    ] {
        db.upsert_token_balance(&TokenBalanceRecord {
            shard_id,
            token_id: token_id.to_string(),
            owner: owner.to_string(),
            owner_stl57: None,
            balance: balance.to_string(),
            updated_height,
        })
        .unwrap();
    }

    // Seed contracts (including a contract with 0 events).
    let creator_a = "dd".repeat(32);
    let c_zero_ev = "ee".repeat(32);
    let c_with_ev = "ff".repeat(32);
    db.upsert_contract(&ContractRecord {
        shard_id: 0,
        address: c_zero_ev.clone(),
        address_stl57: None,
        creator: Some(creator_a.clone()),
        creator_stl57: None,
        code_hash: Some("12".repeat(32)),
        deploy_height: 20,
        has_abi: false,
    })
    .unwrap();
    db.upsert_contract(&ContractRecord {
        shard_id: 0,
        address: c_with_ev.clone(),
        address_stl57: None,
        creator: Some(creator_a.clone()),
        creator_stl57: None,
        code_hash: Some("34".repeat(32)),
        deploy_height: 25,
        has_abi: true,
    })
    .unwrap();
    db.insert_event(&EventRecord {
        tx_hash: "0xev_c".to_string(),
        block_height: 26,
        log_index: 0,
        contract: c_with_ev.clone(),
        topic0: format!("0x{:064x}", 0),
        topics_json: "[]".to_string(),
        data: "{}".to_string(),
        event_name: Some("Deployed".to_string()),
        decoded_json: None,
    })
    .unwrap();

    let (base, client) = spawn_api(AppState::new(db.clone())).await;

    // 1. /api/v2/account/:address/tokens (via Stl57 alias, excluding zero by default)
    let acct_toks: Value = client
        .get(format!(
            "{base}/api/v2/account/{owner_1_stl57}/tokens?limit=1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(acct_toks["address"], owner_1);
    assert_eq!(acct_toks["stl57"], owner_1_stl57);
    assert_eq!(acct_toks["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(acct_toks["tokens"][0]["token_id"], tok_a);
    assert_eq!(acct_toks["has_more"], true);
    let cur = acct_toks["next_cursor"].as_str().unwrap();

    let acct_toks_2: Value = client
        .get(format!(
            "{base}/api/v2/account/{owner_1}/tokens?limit=1&cursor={cur}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(acct_toks_2["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(acct_toks_2["tokens"][0]["token_id"], tok_c);
    assert_eq!(acct_toks_2["has_more"], false);

    // include_zero=true returns all 3
    let acct_toks_all: Value = client
        .get(format!(
            "{base}/api/v2/account/{owner_1}/tokens?include_zero=true"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(acct_toks_all["count"], 3);

    // 2. /api/v2/token/:token/holders: exact numeric descending order + keyset cursor
    let h_p1: Value = client
        .get(format!("{base}/api/v2/token/{tok_a}/holders?limit=2"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let holders_1 = h_p1["holders"].as_array().unwrap();
    assert_eq!(holders_1.len(), 2);
    assert_eq!(holders_1[0]["balance"], "18446744073709551615");
    assert_eq!(holders_1[1]["balance"], "1000");
    assert_eq!(h_p1["has_more"], true);
    let h_cur = h_p1["next_cursor"].as_str().unwrap();

    let h_p2: Value = client
        .get(format!(
            "{base}/api/v2/token/{tok_a}/holders?limit=2&cursor={h_cur}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let holders_2 = h_p2["holders"].as_array().unwrap();
    assert_eq!(holders_2.len(), 1);
    assert_eq!(holders_2[0]["balance"], "200");
    assert_eq!(h_p2["has_more"], false);

    // 3. /api/v2/program/:program/accounts bounds & filters
    let unfilt_token = client
        .get(format!("{base}/api/v2/program/token/accounts"))
        .send()
        .await
        .unwrap();
    assert_eq!(unfilt_token.status(), reqwest::StatusCode::BAD_REQUEST);

    let unfilt_sys = client
        .get(format!("{base}/api/v2/program/system/accounts"))
        .send()
        .await
        .unwrap();
    assert_eq!(unfilt_sys.status(), reqwest::StatusCode::BAD_REQUEST);

    let prog_tok: Value = client
        .get(format!(
            "{base}/api/v2/program/token/accounts?token={tok_a}&min_balance=500&limit=500"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prog_tok["limit"], MAX_PROGRAM_ACCOUNTS_LIMIT);
    assert_eq!(prog_tok["count"], 2); // 1000 and u64::MAX (>= 500)

    let prog_contract: Value = client
        .get(format!(
            "{base}/api/v2/program/contract/accounts?creator={creator_a}&limit=1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prog_contract["count"], 1);
    assert_eq!(prog_contract["items"][0]["address"], c_with_ev);
    let c_cur = prog_contract["next_cursor"].as_str().unwrap();

    let prog_contract_2: Value = client
        .get(format!(
            "{base}/api/v2/program/contract/accounts?creator={creator_a}&limit=1&cursor={c_cur}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prog_contract_2["items"][0]["address"], c_zero_ev);

    // 4. /api/v2/contracts includes contracts with 0 events as well as event emitters
    let all_contracts: Value = client
        .get(format!("{base}/api/v2/contracts?limit=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all_contracts["total"], 2);
    assert_eq!(all_contracts["contracts"][0]["contract"], c_with_ev);
    let ct_cur = all_contracts["next_cursor"].as_str().unwrap();
    let all_contracts_2: Value = client
        .get(format!("{base}/api/v2/contracts?limit=1&cursor={ct_cur}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all_contracts_2["contracts"][0]["contract"], c_zero_ev);

    // 5. Reorg cleanup: replacing (shard=0, height=50) removes its contract + token_balance
    //    while preserving (shard=1, height=50) and (shard=0, height=10).
    let reorg_contract = "55".repeat(32);
    let s1_contract = "66".repeat(32);
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 50,
        hash: "0xold_s0_50".to_string(),
        timestamp: 1_792_000_050,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();
    db.insert_block(&BlockRecord {
        shard_id: 1,
        height: 50,
        hash: "0xkeep_s1_50".to_string(),
        timestamp: 1_792_000_050,
        tx_count: 0,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();
    db.upsert_contract(&ContractRecord {
        shard_id: 0,
        address: reorg_contract.clone(),
        address_stl57: None,
        creator: Some(creator_a.clone()),
        creator_stl57: None,
        code_hash: None,
        deploy_height: 50,
        has_abi: false,
    })
    .unwrap();
    db.upsert_contract(&ContractRecord {
        shard_id: 1,
        address: s1_contract.clone(),
        address_stl57: None,
        creator: Some(creator_a.clone()),
        creator_stl57: None,
        code_hash: None,
        deploy_height: 50,
        has_abi: false,
    })
    .unwrap();
    let reorg_owner = "77".repeat(32);
    db.upsert_token_balance(&TokenBalanceRecord {
        shard_id: 0,
        token_id: tok_a.clone(),
        owner: reorg_owner.clone(),
        owner_stl57: None,
        balance: "999".to_string(),
        updated_height: 50,
    })
    .unwrap();

    // Canonical replacement at shard 0 height 50:
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 50,
        hash: "0xnew_s0_50".to_string(),
        timestamp: 1_792_000_051,
        tx_count: 0,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();

    let s0_c = db
        .get_contracts_by_filter_keyset(None, Some(&reorg_contract), None, 10, None)
        .unwrap();
    assert!(
        s0_c.items.is_empty(),
        "reorged shard 0 contract at height 50 must be removed"
    );
    let s1_c = db
        .get_contracts_by_filter_keyset(None, Some(&s1_contract), None, 10, None)
        .unwrap();
    assert_eq!(
        s1_c.items.len(),
        1,
        "shard 1 contract at height 50 must survive shard 0 reorg"
    );
    let reorg_tb = db
        .get_account_tokens_keyset(&reorg_owner, None, true, Some(0), 10, None)
        .unwrap();
    assert!(
        reorg_tb.items.is_empty(),
        "reorged token balance at (0, 50) must be removed"
    );

    // Direct invalidation by orphaned hash cleans up block + dependents.
    let inv = db
        .invalidate_block_hashes(&["0xKEEP_S1_50".to_string()])
        .unwrap();
    assert_eq!(inv, vec![(1, 50)]);
    assert!(db.get_block_by_shard_and_height(1, 50).unwrap().is_none());
    let s1_c_after = db
        .get_contracts_by_filter_keyset(None, Some(&s1_contract), None, 10, None)
        .unwrap();
    assert!(s1_c_after.items.is_empty());
}

#[tokio::test]
async fn indexer_sse_parser_and_push_sync_with_backfill_fallback() {
    // 1. Unit tests for SseFrameParser: chunk splits, CRLF, comments, multi-line data, OOM bound.
    let mut parser = SseFrameParser::new();
    let f1 = parser
        .feed(b": keep-alive\r\nevent: message\r\ndata: {\"a\":1,\r\n")
        .unwrap();
    assert!(f1.is_empty());
    let f2 = parser.feed(b"data: \"b\":2}\r\n\r\n").unwrap();
    assert_eq!(f2.len(), 1);
    assert_eq!(f2[0].event.as_deref(), Some("message"));
    assert_eq!(f2[0].data, "{\"a\":1,\n\"b\":2}");

    let lagged_frames = parser
        .feed(b"event: lagged\ndata: {\"lagged\":12,\"oldest_available_seq\":50}\n\n")
        .unwrap();
    assert_eq!(lagged_frames.len(), 1);
    assert_eq!(
        parse_node_sse_frame(&lagged_frames[0]),
        Some(NodeSseEvent::Lagged {
            skipped: 12,
            oldest_available_seq: Some(50),
        })
    );

    let mut bounded = SseFrameParser::with_max_bytes(64);
    assert!(bounded.feed(&[b'x'; 100]).is_err());

    // 2. Integration: Syncer SSE push -> contract & token_balances indexing -> invalidation -> lag backfill.
    let db = Database::open(":memory:").expect("db");
    let stream_hub = Arc::new(IndexerStreamHub::new());
    let phase = Arc::new(AtomicU64::new(1));

    let kp = stellereum::post_quantum::FalconKeypair::generate();
    let token_id = [0x33u8; 32];
    let recipient = [0x44u8; 32];
    let deployed_contract = [0x55u8; 32];
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let tx = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0x11u8; 64],
        [0u8; 32],
        0,
        500_000,
        0,
        0,
        0,
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
    let tx_hash_hex = hex::encode(tx.compute_tx_hash());
    let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap());
    let deployed_hex = hex::encode(deployed_contract);
    let token_hex = hex::encode(token_id);
    let recipient_hex = hex::encode(recipient);
    let sender_hex = hex::encode(tx.from);

    let phase_rpc = Arc::clone(&phase);
    let tx_hash_rpc = tx_hash_hex.clone();
    let raw_tx_rpc = raw_tx_hex.clone();
    let deployed_rpc = deployed_hex.clone();
    let token_rpc = token_hex.clone();
    let recipient_rpc = recipient_hex.clone();
    let sender_rpc = sender_hex.clone();

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let ph = phase_rpc.load(Ordering::Acquire);
            let tx_h = tx_hash_rpc.clone();
            let raw_t = raw_tx_rpc.clone();
            let dep_c = deployed_rpc.clone();
            let tok = token_rpc.clone();
            let recp = recipient_rpc.clone();
            let snd = sender_rpc.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => {
                        let tip = match ph {
                            1 => 1u64,
                            2 => 1u64,
                            _ => 3u64,
                        };
                        json!(format!("0x{tip:x}"))
                    }
                    "stell_getShards" => {
                        let tip = match ph {
                            1 | 2 => 1u64,
                            _ => 3u64,
                        };
                        json!({
                            "shards": [{
                                "shard_id": 0,
                                "type": "masterchain",
                                "tip_height": tip,
                                "tip_hash": if ph == 1 { "0xb1_old" } else { "0xb1_new" },
                                "local": true
                            }],
                            "total_shards": 1
                        })
                    }
                    "stell_getBlock" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        let hash = if h == 1 && ph == 1 {
                            "0xb1_old".to_string()
                        } else if h == 1 {
                            "0xb1_new".to_string()
                        } else {
                            format!("0xb{h}")
                        };
                        let txs = if h == 1 && ph == 1 { 1 } else { 0 };
                        json!({ "height": h, "hash": hash, "txs": txs, "timestamp": 1792000000 + h })
                    }
                    "stell_getBlockTransactions" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        if h == 1 && ph == 1 {
                            json!({
                                "height": 1,
                                "txs": [{
                                    "tx_hash": tx_h,
                                    "index": 0,
                                    "status": "success",
                                    "gas_limit": "500000",
                                    "fee_charged": "280000",
                                    "raw_tx": raw_t,
                                }]
                            })
                        } else {
                            json!({ "height": h, "txs": [] })
                        }
                    }
                    "stell_getTransactionReceipt" => {
                        json!({
                            "tx_hash": tx_h,
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

    // Mock SSE + REST node server
    let sse_phase = Arc::clone(&phase);
    let mock_node = Router::new()
        .route("/api/blocks", get(|| async { Json(json!([])) }))
        .route(
            "/events",
            get(move || {
                let ph = sse_phase.load(Ordering::Acquire);
                async move {
                    let body = match ph {
                        1 => "data: {\"subscription\":\"s1\",\"result\":{\"height\":1,\"hash\":\"0xb1_old\",\"shard_id\":0,\"tx_count\":1,\"timestamp\":1792000001,\"finality\":\"finalized\"}}\n\n".to_string(),
                        2 => "data: {\"subscription\":\"s2\",\"result\":{\"height\":1,\"reason\":\"fork\",\"orphaned_blocks\":[\"0xb1_old\"]}}\n\n".to_string(),
                        _ => "event: lagged\ndata: {\"subscription\":\"*\",\"lagged\":5,\"oldest_available_seq\":10,\"action\":\"backfill_required\"}\n\n".to_string(),
                    };
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
    let node_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_url = format!("http://{}", node_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(node_listener, mock_node).await.unwrap() });

    let syncer =
        Syncer::new(db.clone(), node_url.clone(), rpc_url).with_stream_hub(stream_hub.clone());
    let sse_url = format!("{node_url}/events?topics=newHeads,newTxs,events,invalidations");

    // Phase 1: SSE newHeads triggers sync_step -> indexes block 1, contract, token balances & events.
    let reason1 = syncer
        .consume_sse_once(&sse_url, Duration::from_secs(5), None)
        .await
        .expect("phase 1 sse");
    assert_eq!(reason1, SseDisconnectReason::Closed);
    assert_eq!(
        db.get_block_by_shard_and_height(0, 1)
            .unwrap()
            .unwrap()
            .hash,
        "0xb1_old"
    );
    let contracts = db
        .get_contracts_by_filter_keyset(None, Some(&deployed_hex), None, 10, None)
        .unwrap();
    assert_eq!(contracts.items.len(), 1);
    assert_eq!(contracts.items[0].deploy_height, 1);
    let holders = db
        .get_token_holders_keyset(&token_hex, false, None, 10, None)
        .unwrap();
    assert_eq!(holders.items.len(), 2);
    assert_eq!(holders.items[0].balance, "750");
    assert_eq!(holders.items[1].balance, "250");
    assert_eq!(
        db.count_events(&EventFilter::default()).unwrap(),
        1,
        "event must be indexed from receipt"
    );
    assert!(stream_hub.latest_seq() >= 3);

    // Phase 2: SSE invalidations rolls back 0xb1_old (and its contract/token balances) and re-indexes 0xb1_new.
    phase.store(2, Ordering::Release);
    let reason2 = syncer
        .consume_sse_once(&sse_url, Duration::from_secs(5), None)
        .await
        .expect("phase 2 sse");
    assert_eq!(reason2, SseDisconnectReason::Closed);
    assert_eq!(
        db.get_block_by_shard_and_height(0, 1)
            .unwrap()
            .unwrap()
            .hash,
        "0xb1_new"
    );
    assert!(
        db.get_contracts_by_filter_keyset(None, Some(&deployed_hex), None, 10, None)
            .unwrap()
            .items
            .is_empty(),
        "invalidated block's contract must be cleaned up"
    );
    assert!(
        db.get_token_holders_keyset(&token_hex, false, None, 10, None)
            .unwrap()
            .items
            .is_empty(),
        "invalidated block's token balances must be cleaned up"
    );

    // Phase 3: SSE lagged triggers backfill fallback up to height 3.
    phase.store(3, Ordering::Release);
    let reason3 = syncer
        .consume_sse_once(&sse_url, Duration::from_secs(5), None)
        .await
        .expect("phase 3 sse");
    assert_eq!(reason3, SseDisconnectReason::Lagged);
    assert_eq!(db.get_shard_tip_height(0).unwrap(), 3);
    assert!(db.get_block_by_shard_and_height(0, 2).unwrap().is_some());
    assert!(db.get_block_by_shard_and_height(0, 3).unwrap().is_some());
}

#[tokio::test]
async fn indexer_stream_endpoint_filtering_replay_and_limits() {
    assert_eq!(MAX_INDEXER_SSE_CLIENTS, 256);

    // 1. Test filtering, after_seq replay, and MAX_INDEXER_SSE_CLIENTS cap + RAII release.
    let db = Database::open(":memory:").expect("db");
    let hub = Arc::new(IndexerStreamHub::with_limits(2, Duration::from_secs(30)));
    let state = AppState::new(db.clone()).with_stream_hub(Arc::clone(&hub));
    let (base, client) = spawn_api(state).await;

    let contract_a = "aa".repeat(32);
    let contract_b = "bb".repeat(32);
    let seq1 = hub.publish(StreamPublishInput {
        topic: "newHeads",
        shard_id: 0,
        height: 1,
        contract: None,
        addresses: Vec::new(),
        payload: json!({ "height": 1 }),
    });
    let seq2 = hub.publish(StreamPublishInput {
        topic: "events",
        shard_id: 1,
        height: 2,
        contract: Some(contract_a.clone()),
        addresses: vec![contract_a.clone()],
        payload: json!({ "seq_tag": "match_a" }),
    });
    let _seq3 = hub.publish(StreamPublishInput {
        topic: "events",
        shard_id: 0,
        height: 3,
        contract: Some(contract_b.clone()),
        addresses: vec![contract_b.clone()],
        payload: json!({ "seq_tag": "wrong_shard_and_contract" }),
    });
    let seq4 = hub.publish(StreamPublishInput {
        topic: "events",
        shard_id: 1,
        height: 4,
        contract: Some(contract_a.clone()),
        addresses: vec![contract_a.clone()],
        payload: json!({ "seq_tag": "replay_a" }),
    });
    assert!(seq1 < seq2 && seq2 < seq4);

    // Invalid topic rejected with 400.
    let bad_topic = client
        .get(format!("{base}/api/v2/stream?topics=bogus"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_topic.status(), reqwest::StatusCode::BAD_REQUEST);

    // Connect client 1 with after_seq=seq1, filtering for shard_id=1 & contract_a.
    let mut resp1 = client
        .get(format!(
            "{base}/api/v2/stream?topics=events&shard_id=1&contract={contract_a}&after_seq={seq1}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), reqwest::StatusCode::OK);

    // Connect client 2 (reaches cap = 2).
    let resp2 = client
        .get(format!("{base}/api/v2/stream?topics=newHeads"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);

    // Client 3 MUST be refused fail-closed with 503 SERVICE_UNAVAILABLE.
    let resp3 = client
        .get(format!("{base}/api/v2/stream?topics=newHeads"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    // Publish live events: one non-matching (shard 0), one matching (shard 1, contract_a).
    hub.publish(StreamPublishInput {
        topic: "events",
        shard_id: 0,
        height: 5,
        contract: Some(contract_a.clone()),
        addresses: vec![contract_a.clone()],
        payload: json!({ "seq_tag": "drop_shard0" }),
    });
    let seq6 = hub.publish(StreamPublishInput {
        topic: "events",
        shard_id: 1,
        height: 6,
        contract: Some(contract_a.clone()),
        addresses: vec![contract_a.clone()],
        payload: json!({ "seq_tag": "live_a" }),
    });

    // Read 3 SSE frames from client 1: seq2 (replay), seq4 (replay), seq6 (live).
    let mut parser = SseFrameParser::new();
    let mut received = Vec::new();
    let read_res = tokio::time::timeout(Duration::from_secs(5), async {
        while received.len() < 3 {
            if let Some(chunk) = resp1.chunk().await.unwrap() {
                for frame in parser.feed(&chunk).unwrap() {
                    if !frame.data.trim().is_empty() {
                        let v: Value = serde_json::from_str(&frame.data).unwrap();
                        received.push(v);
                    }
                }
            }
        }
    })
    .await;
    assert!(read_res.is_ok(), "timed out reading filtered SSE frames");
    let seqs: Vec<u64> = received
        .iter()
        .map(|v| v["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![seq2, seq4, seq6]);

    // Drop client 2 -> active slot released -> new client succeeds!
    drop(resp2);
    let mut freed = false;
    for _ in 0..20 {
        if hub.active_clients() < 2 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(freed, "client drop must release stream slot");
    let resp_reopened = client
        .get(format!("{base}/api/v2/stream?topics=newHeads"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_reopened.status(), reqwest::StatusCode::OK);
    drop(resp1);
    drop(resp_reopened);

    // 2. Expired replay cursor returns 410 GONE.
    for i in 0..(INDEXER_REPLAY_WINDOW as u64 + 10) {
        hub.publish(StreamPublishInput {
            topic: "newHeads",
            shard_id: 0,
            height: 100 + i,
            contract: None,
            addresses: Vec::new(),
            payload: json!({ "height": 100 + i }),
        });
    }
    let expired = client
        .get(format!("{base}/api/v2/stream?topics=newHeads&after_seq=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), reqwest::StatusCode::GONE);

    // 3. Idle timeout reaps silent SSE stream and releases client slot.
    let idle_hub = Arc::new(IndexerStreamHub::with_limits(8, Duration::from_millis(120)));
    let idle_state = AppState::new(db).with_stream_hub(Arc::clone(&idle_hub));
    let (idle_base, idle_client) = spawn_api(idle_state).await;
    let mut idle_resp = idle_client
        .get(format!("{idle_base}/api/v2/stream?topics=newHeads"))
        .send()
        .await
        .unwrap();
    assert_eq!(idle_resp.status(), reqwest::StatusCode::OK);
    let eof = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match idle_resp.chunk().await.unwrap() {
                None => break,
                Some(_) => continue,
            }
        }
    })
    .await;
    assert!(eof.is_ok(), "idle SSE stream must terminate after timeout");
    for _ in 0..20 {
        if idle_hub.active_clients() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(idle_hub.active_clients(), 0);
}
