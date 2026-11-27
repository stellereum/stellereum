//! Wave 9 regression tests verifying `/api/v2/overview` reports honest metrics
//! on an empty or sparsely populated database without fabricated floors.

use serde_json::Value;
use stellereum_indexer::db::{BlockRecord, Database, TxRecord};
use stellereum_indexer::server::{create_router, AppState};

#[tokio::test]
async fn overview_reports_honest_zero_metrics_on_empty_db() {
    let db = Database::open(":memory:").expect("open in-memory db");
    let app = create_router(AppState::with_rpc(db, "http://127.0.0.1:1".to_string()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{addr}/api/v2/overview"))
        .send()
        .await
        .expect("request overview");
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let v: Value = res.json().await.expect("parse overview json");
    assert_eq!(v["tps"].as_f64(), Some(0.0));
    assert_eq!(v["current_tps"].as_f64(), Some(0.0));
    assert_eq!(v["transactions"]["tps"].as_f64(), Some(0.0));
    assert_eq!(v["transactions"]["current_tps"].as_f64(), Some(0.0));
    assert_eq!(v["network"]["tps"].as_f64(), Some(0.0));
    assert_eq!(v["network"]["current_tps"].as_f64(), Some(0.0));
    assert_eq!(v["transactions"]["daily_average"].as_u64(), Some(0));
    assert_eq!(v["transactions"]["today"].as_u64(), Some(0));
    assert_eq!(v["transactions"]["yesterday"].as_u64(), Some(0));
    assert!(
        v["price"].is_null(),
        "price must be null, got {}",
        v["price"]
    );
    assert_eq!(v["network"]["chain_id"].as_u64(), Some(5757));

    srv.abort();
}

#[tokio::test]
async fn overview_reports_actual_indexed_daily_counts_without_floors() {
    let db = Database::open(":memory:").expect("open in-memory db");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let today_start = (now / 86400) * 86400;
    let yesterday_ts = today_start.saturating_sub(3600);

    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 1,
        hash: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        timestamp: yesterday_ts,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .expect("insert block 1");

    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 2,
        hash: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        timestamp: today_start + 60,
        tx_count: 2,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .expect("insert block 2");

    let mk_tx = |hash: &str, height: u64, idx: u32, ts: u64| TxRecord {
        tx_hash: hash.to_string(),
        block_height: height,
        tx_index: idx,
        from_addr: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        to_addr: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        from_stl57: None,
        to_stl57: None,
        amount: "100".to_string(),
        fee_charged: "280000".to_string(),
        gas_limit: "325000".to_string(),
        status: "success".to_string(),
        timestamp: ts,
    };

    db.insert_transaction(&mk_tx("0x01", 1, 0, yesterday_ts))
        .expect("insert tx 1");
    db.insert_transaction(&mk_tx("0x02", 2, 0, today_start + 60))
        .expect("insert tx 2");
    db.insert_transaction(&mk_tx("0x03", 2, 1, today_start + 60))
        .expect("insert tx 3");

    let app = create_router(AppState::with_rpc(db, "http://127.0.0.1:1".to_string()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let res = reqwest::Client::new()
        .get(format!("http://{addr}/api/v2/overview"))
        .send()
        .await
        .expect("request overview");
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let v: Value = res.json().await.expect("parse overview json");
    assert_eq!(v["transactions"]["daily_average"].as_u64(), Some(3));
    assert_eq!(v["transactions"]["today"].as_u64(), Some(3));
    assert_eq!(v["transactions"]["yesterday"].as_u64(), Some(1));

    srv.abort();
}

#[tokio::test]
async fn stats_reports_real_unclamped_block_time_and_zero_or_fractional_tps() {
    let db = Database::open(":memory:").expect("open in-memory db");

    for h in 1u64..=4 {
        db.insert_block(&BlockRecord {
            shard_id: 0,
            height: h,
            hash: format!("0x{:064x}", h),
            timestamp: 1_792_000_000 + h * 3,
            tx_count: 0,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .expect("insert block");
    }

    let empty_tx_stats = db.get_stats().expect("get_stats");
    assert!(
        (empty_tx_stats.avg_block_time - 3.0).abs() < 1e-9,
        "avg_block_time must be real measured 3.0s without [0.48, 0.50] clamp, got {}",
        empty_tx_stats.avg_block_time
    );
    assert_eq!(
        empty_tx_stats.current_tps, 0.0,
        "current_tps must be 0.0 when no txs occurred, not floored to 1.0"
    );

    // Add 2 more blocks (total dt = 15s over 5 intervals -> 3.0s/block) with 3 txs total -> 0.2 TPS.
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 5,
        hash: format!("0x{:064x}", 5),
        timestamp: 1_792_000_015,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .expect("insert block 5");
    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 6,
        hash: format!("0x{:064x}", 6),
        timestamp: 1_792_000_018,
        tx_count: 2,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .expect("insert block 6");

    let frac_stats = db.get_stats().expect("get_stats");
    assert!((frac_stats.avg_block_time - 3.0).abs() < 1e-9);
    assert!(
        (frac_stats.current_tps - 0.2).abs() < 1e-9,
        "fractional TPS 0.2 must not be floored to 1.0, got {}",
        frac_stats.current_tps
    );

    let app = create_router(AppState::with_rpc(db, "http://127.0.0.1:1".to_string()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let v: Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v2/stats"))
        .send()
        .await
        .expect("request stats")
        .json()
        .await
        .expect("json");
    assert_eq!(v["mc_seqno"].as_u64(), Some(6));
    assert!((v["avg_block_time"].as_f64().unwrap() - 3.0).abs() < 1e-9);
    assert!((v["tps"].as_f64().unwrap() - 0.2).abs() < 1e-9);
    assert_eq!(v["wc_block_time"].as_f64(), Some(0.0));
    assert_eq!(v["wc_block_txs"].as_f64(), Some(0.0));

    srv.abort();
}

#[tokio::test]
async fn multishard_stats_and_status_use_shard0_and_per_shard_averages() {
    let db = Database::open(":memory:").expect("open in-memory db");

    // Shard 0: heights 1..=2, 4s apart -> avg_block_time = 4.0, 1 tx -> mc_block_txs = 0.5
    for h in 1u64..=2 {
        db.insert_block(&BlockRecord {
            shard_id: 0,
            height: h,
            hash: format!("0x10{:062x}", h),
            timestamp: 1_792_000_000 + (h - 1) * 4,
            tx_count: if h == 2 { 1 } else { 0 },
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .expect("insert s0 block");
    }
    db.insert_transaction_in_shard(
        0,
        &TxRecord {
            tx_hash: "0xs0_tx".to_string(),
            block_height: 2,
            tx_index: 0,
            from_addr: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            to_addr: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            from_stl57: None,
            to_stl57: None,
            amount: "10".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_004,
        },
    )
    .expect("insert s0 tx");

    // Shard 1: heights 1..=10 (higher than shard 0!), 2s apart -> wc_block_time = 2.0, 5 txs -> wc_block_txs = 0.5
    for h in 1u64..=10 {
        db.insert_block(&BlockRecord {
            shard_id: 1,
            height: h,
            hash: format!("0x20{:062x}", h),
            timestamp: 1_792_000_000 + (h - 1) * 2,
            tx_count: if h <= 5 { 1 } else { 0 },
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .expect("insert s1 block");
    }
    for h in 1u64..=5 {
        db.insert_transaction_in_shard(
            1,
            &TxRecord {
                tx_hash: format!("0xs1_tx_{h}"),
                block_height: h,
                tx_index: 0,
                from_addr: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
                to_addr: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_string(),
                from_stl57: None,
                to_stl57: None,
                amount: "10".to_string(),
                fee_charged: "1".to_string(),
                gas_limit: "10".to_string(),
                status: "success".to_string(),
                timestamp: 1_792_000_000 + (h - 1) * 2,
            },
        )
        .expect("insert s1 tx");
    }

    let state = AppState::with_rpc(db, "http://127.0.0.1:1".to_string());
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut s = state.sync_status.write().await;
        s.node_tip_height = Some(5);
        s.last_sync_at = Some(now);
    }

    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = reqwest::Client::new();
    let stats: Value = client
        .get(format!("http://{addr}/api/v2/stats"))
        .send()
        .await
        .expect("stats")
        .json()
        .await
        .expect("json");
    assert_eq!(stats["mc_seqno"].as_u64(), Some(2));
    assert!((stats["avg_block_time"].as_f64().unwrap() - 4.0).abs() < 1e-9);
    assert!((stats["wc_block_time"].as_f64().unwrap() - 2.0).abs() < 1e-9);
    assert!((stats["mc_block_txs"].as_f64().unwrap() - 0.5).abs() < 1e-9);
    assert!((stats["wc_block_txs"].as_f64().unwrap() - 0.5).abs() < 1e-9);

    let status: Value = client
        .get(format!("http://{addr}/api/v2/status"))
        .send()
        .await
        .expect("status")
        .json()
        .await
        .expect("json");
    assert_eq!(status["tip_height"].as_u64(), Some(2));
    assert_eq!(status["lag"].as_u64(), Some(3));
    assert_eq!(status["synced"].as_bool(), Some(false));

    srv.abort();
}

#[test]
fn invalidate_shard_height_recomputes_accounts_tx_count() {
    let db = Database::open(":memory:").expect("open in-memory db");
    let addr_a = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let addr_b = "0x2222222222222222222222222222222222222222222222222222222222222222";
    let addr_c = "0x3333333333333333333333333333333333333333333333333333333333333333";

    db.insert_block(&BlockRecord {
        shard_id: 0,
        height: 1,
        hash: "0xs0_b1".to_string(),
        timestamp: 1_792_000_001,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();
    db.insert_block(&BlockRecord {
        shard_id: 1,
        height: 1,
        hash: "0xs1_b1".to_string(),
        timestamp: 1_792_000_001,
        tx_count: 1,
        proposer: None,
        proposer_stl57: None,
        state_root: None,
    })
    .unwrap();

    db.insert_transaction_in_shard(
        0,
        &TxRecord {
            tx_hash: "0xtx0".to_string(),
            block_height: 1,
            tx_index: 0,
            from_addr: addr_a.to_string(),
            to_addr: addr_b.to_string(),
            from_stl57: None,
            to_stl57: None,
            amount: "1".to_string(),
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
            tx_hash: "0xtx1".to_string(),
            block_height: 1,
            tx_index: 0,
            from_addr: addr_a.to_string(),
            to_addr: addr_c.to_string(),
            from_stl57: None,
            to_stl57: None,
            amount: "1".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_001,
        },
    )
    .unwrap();

    assert_eq!(db.get_stats().unwrap().total_accounts, 3);
    assert!(db.invalidate_shard_height(1, 1).unwrap());
    let stats_after = db.get_stats().unwrap();
    assert_eq!(stats_after.total_transactions, 1);
    assert_eq!(
        stats_after.total_accounts, 2,
        "account C with 0 remaining txs must be removed"
    );
    assert_eq!(db.get_account_tx_count(addr_a).unwrap(), 1);
    assert_eq!(db.get_account_tx_count(addr_c).unwrap(), 0);
}
