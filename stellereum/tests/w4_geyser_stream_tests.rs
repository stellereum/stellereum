//! W4/E4 — Geyser-lite streaming contract (`docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §2.5).
//!
//! Proves, against the real RPC surface (router + SSE handler, no mocks):
//! * a workchain node reports ITS shard id in `newHeads` (never the
//!   masterchain constant) and the head carries `prev_hash`/`state_root`/
//!   `proposer` keys;
//! * `seq` is monotonic, `after_seq` replays from the bounded window, an
//!   out-of-window cursor is refused with `-32005`, and a lagging transport
//!   gets an explicit `lagged` frame over WS and SSE;
//! * `accountUpdates` / `tokenTransfers` filters are bounded and publish the
//!   real deltas of a finalized block, while a stalled client never delays
//!   `record_block`;
//! * the rate-bucket table covers the new E3 methods.

use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::RwLock;

use stellereum::mempool::Mempool;
use stellereum::rpc::{
    hub, publish_account_update, publish_block_deltas, router, rpc_rate_buckets, sse_handler,
    Notification, ReceiptIndex, RpcState, StreamQuery, SubscriptionTopic, GEYSER_REPLAY_WINDOW,
    MAX_REPLAY_BURST, MAX_SUBSCRIPTION_ACCOUNTS,
};
use stellereum::sharding::{ShardRegistry, Transaction};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

fn hex32(b: [u8; 32]) -> String {
    hex::encode(b)
}

/// Serializes the streaming tests: the subscription hub is ONE per process,
/// so the tests that assert on its `seq` window would otherwise see the
/// traffic of a sibling test (each test still uses unique accounts/ids).
fn hub_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// A node state with an engine pinned to `shard` (0 = masterchain, 1+ =
/// workchain).
fn node_state(shard: u32) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.set_shard_id(shard);
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(0)),
        node_id: "w4-geyser-tests".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn spawn_server(st: Arc<RpcState>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(st);
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    addr
}

/// One JSON-RPC call over real HTTP (so the wire error code is exercised, not
/// a flattened in-process result).
async fn http_json(addr: std::net::SocketAddr, body: Value) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    sock.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), sock.read_to_end(&mut buf))
        .await
        .expect("http read timeout")
        .expect("http read");
    let text = String::from_utf8_lossy(&buf);
    let payload = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_else(|| panic!("no HTTP body in response: {text}"));
    serde_json::from_str(payload).expect("json response")
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(addr: std::net::SocketAddr) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("ws handshake");
    ws
}

async fn ws_call(ws: &mut Ws, id: u64, method: &str, params: Value) -> Value {
    use tokio_tungstenite::tungstenite::Message;
    ws.send(Message::Text(
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
    ))
    .await
    .expect("ws send");
    // A transport-wide lag notice may interleave with the reply; it is not
    // the answer to this call.
    loop {
        let frame = ws_next_json(ws).await;
        if frame.get("lagged").is_some() {
            continue;
        }
        return frame;
    }
}

async fn ws_next_json(ws: &mut Ws) -> Value {
    let msg = tokio::time::timeout(Duration::from_secs(15), ws.next())
        .await
        .expect("ws frame timeout")
        .expect("ws closed")
        .expect("ws error");
    serde_json::from_str(msg.to_text().expect("text frame")).expect("json frame")
}

/// The next fan-out notification, tolerating a lagged receiver.
///
/// The hub is process-wide, so a test running next to this one can overflow
/// the channel; a `Lagged` error is not a failure of the assertion under test
/// (the transport-level lag notices are asserted over WS/SSE separately).
async fn next_note(rx: &mut tokio::sync::broadcast::Receiver<Notification>) -> Notification {
    loop {
        match rx.recv().await {
            Ok(note) => return note,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                panic!("subscription fan-out closed")
            }
        }
    }
}

/// `newHeads` must report the shard THIS node runs.
#[tokio::test]
async fn stream_new_heads_reports_real_workchain_shard_id() {
    let _serial = hub_test_lock().lock().await;
    let st = node_state(1);
    // Unique height/hash so concurrent tests cannot satisfy the assertion.
    let height = 9_400_001u64;
    let hash = [0xA1u8; 32];

    let sub = hub()
        .subscribe_for(SubscriptionTopic::NewHeads, Some("w4-heads-workchain"))
        .expect("subscribe newHeads");
    let mut rx = hub().notifications();
    st.record_block(height, hash, 0, 1_700_000_000).await;

    let note = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let note = next_note(&mut rx).await;
            if note.subscription == sub && note.result["hash"] == json!(hex32(hash)) {
                return note;
            }
        }
    })
    .await
    .expect("head notification");

    assert_eq!(
        note.result["shard_id"],
        json!(1),
        "a workchain node must not publish the masterchain constant: {}",
        note.result
    );
    assert_eq!(
        note.shard_id,
        Some(1),
        "the notification envelope must carry the shard id"
    );
    assert_eq!(note.height, Some(height));
    assert!(note.seq.is_some(), "every live push carries a seq");
    // The head always carries the certified-header keys (`null` when this
    // node has no recorded header for the height — never a made-up root).
    for key in ["prev_hash", "state_root", "proposer"] {
        assert!(
            note.result.get(key).is_some(),
            "newHeads payload must carry `{key}`: {}",
            note.result
        );
    }

    hub().unsubscribe(&sub);
}

/// `seq` monotonicity, in-window `after_seq` replay, out-of-window `-32005`,
/// and the explicit `lagged` frame on both transports.
#[tokio::test]
async fn stream_seq_replay_and_lagged_notice() {
    let _serial = hub_test_lock().lock().await;
    let st = node_state(0);
    let addr = spawn_server(st).await;

    let account = [0xB1u8; 32];
    let account_hex = hex32(account);
    let replay_sub = hub()
        .subscribe_for(
            SubscriptionTopic::AccountUpdates {
                accounts: vec![account_hex.clone()],
            },
            Some("w4-replay-window"),
        )
        .expect("subscribe accountUpdates");

    // Warm up the window so a cursor exists, then publish three events.
    publish_account_update(account, 8_000_000, [0x01u8; 32], 0);
    let cursor = hub().latest_seq().expect("a warm-up seq");
    for i in 0..3u64 {
        publish_account_update(account, 8_000_001 + i, [0x02u8; 32], 0);
    }
    let batch = hub()
        .replay_after(&replay_sub, cursor)
        .expect("in-window cursor");
    assert_eq!(
        batch.notifications.len(),
        3,
        "three events after the cursor"
    );
    assert_eq!(batch.remaining, 0);
    let seqs: Vec<u64> = batch
        .notifications
        .iter()
        .map(|n| n.seq.expect("replayed events carry a seq"))
        .collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "seq must be strictly monotonic: {seqs:?}"
    );
    assert!(seqs.iter().all(|s| *s > cursor));
    let replayed_seqs: Vec<u64> = batch.notifications.iter().map(|n| n.seq.unwrap()).collect();
    assert_eq!(seqs, replayed_seqs);

    // Push the cursor out of the bounded window: an explicit refusal.
    for i in 0..(GEYSER_REPLAY_WINDOW as u64 + 8) {
        publish_account_update(account, 8_100_000 + i, [0x03u8; 32], 0);
    }
    let expired = hub()
        .replay_after(&replay_sub, 0)
        .expect_err("cursor 0 must be out of the window");
    assert!(
        expired
            .to_string()
            .contains("replay cursor expired; backfill via RPC/indexer"),
        "explicit refusal text: {expired}"
    );
    assert!(hub().check_replay_cursor(0).is_err());

    // WS: in-window replay is delivered right after the subscribe reply.
    let other_account = [0xC1u8; 32];
    let other_hex = hex32(other_account);
    hub()
        .subscribe_for(
            SubscriptionTopic::AccountUpdates {
                accounts: vec![other_hex.clone()],
            },
            Some("w4-replay-ws-source"),
        )
        .expect("pre-create source subscription");
    let ws_cursor = hub().latest_seq().expect("latest seq");
    publish_account_update(other_account, 8_200_000, [0x04u8; 32], 0);
    publish_account_update(other_account, 8_200_001, [0x04u8; 32], 0);

    let mut ws = ws_connect(addr).await;
    let reply = ws_call(
        &mut ws,
        1,
        "stell_subscribe",
        json!([
            "accountUpdates",
            { "accounts": [other_hex.clone()], "after_seq": ws_cursor }
        ]),
    )
    .await;
    let ws_sub = reply
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("subscribe failed: {reply}"))
        .to_string();
    let mut replayed: Vec<Value> = Vec::new();
    while replayed.len() < 2 {
        let frame = ws_next_json(&mut ws).await;
        if frame.get("lagged").is_some() {
            continue;
        }
        assert_eq!(frame["subscription"], json!(ws_sub));
        replayed.push(frame);
    }
    for note in &replayed {
        assert_eq!(note["result"]["account"], json!(other_hex));
        assert!(
            note["seq"].as_u64().unwrap_or(0) > ws_cursor,
            "replayed seq must be after the cursor: {note}"
        );
    }
    assert!(replayed[0]["seq"].as_u64() < replayed[1]["seq"].as_u64());

    // WS: a stale cursor is the explicit JSON-RPC `-32005` (no subscription
    // is created, no silent hole).
    let stale = ws_call(
        &mut ws,
        2,
        "stell_subscribe",
        json!(["accountUpdates", { "accounts": [other_hex.clone()], "after_seq": 0 }]),
    )
    .await;
    assert_eq!(stale["error"]["code"], json!(-32005), "got {stale}");
    assert_eq!(
        stale["error"]["message"],
        json!("replay cursor expired; backfill via RPC/indexer")
    );

    // SSE: a receiver that is not drained overflows the broadcast and gets an
    // explicit `event: lagged` frame instead of a silent gap.
    let resp = sse_handler(
        axum::http::HeaderMap::new(),
        None,
        axum::extract::Query(StreamQuery {
            sub_id: None,
            topics: Some("newTxs".to_string()),
            contract: None,
            event_topics: None,
        }),
    )
    .await
    .expect("sse handler");
    let mut body = resp.into_body().into_data_stream();
    const SSES_OVERFLOW: usize = stellereum::rpc::STREAM_BROADCAST_CAPACITY + 1024;
    for i in 0..SSES_OVERFLOW {
        hub().publish(
            &SubscriptionTopic::NewTxs,
            json!({"hash": hex32([0xD1u8; 32]), "n": i}),
        );
    }
    let sse_lag = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let chunk = body.next().await?.ok()?;
            let text = String::from_utf8_lossy(&chunk).to_string();
            if text.contains("event: lagged") {
                return Some(text);
            }
        }
    })
    .await
    .expect("sse lag frame timeout")
    .expect("sse stream ended before a lag frame");
    assert!(
        sse_lag.contains("event: lagged\n"),
        "SSE lag frame must be an `event: lagged` frame: {sse_lag}"
    );
    let data = sse_lag
        .split("data: ")
        .nth(1)
        .expect("lagged data frame")
        .trim();
    let notice: Value = serde_json::from_str(data).expect("lagged json");
    assert_eq!(notice["subscription"], json!("*"));
    assert_eq!(notice["action"], json!("backfill_required"));
    assert!(notice["lagged"].as_u64().unwrap_or(0) > 0);
    assert!(notice.get("oldest_available_seq").is_some());

    // WS: the same overflow produces the structured lag notice over the socket.
    let _ = ws_call(&mut ws, 3, "stell_subscribe", json!(["newTxs"])).await;
    // No `.await` below: on the single-threaded test runtime the session task
    // cannot drain, so the broadcast queue overflows deterministically.
    for i in 0..(stellereum::rpc::STREAM_BROADCAST_CAPACITY as u64 + 1024) {
        hub().publish(
            &SubscriptionTopic::NewTxs,
            json!({"hash": hex32([0xD2u8; 32]), "n": i, "pad": "x".repeat(1024)}),
        );
    }
    let ws_lag = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let frame = ws_next_json(&mut ws).await;
            if frame.get("lagged").is_some() {
                return frame;
            }
        }
    })
    .await
    .expect("ws lag frame timeout");
    assert_eq!(ws_lag["subscription"], json!("*"));
    assert_eq!(ws_lag["action"], json!("backfill_required"));
    assert!(ws_lag["lagged"].as_u64().unwrap_or(0) > 0);
    assert!(ws_lag.get("oldest_available_seq").is_some());
}

fn token_transfer_tx(from: [u8; 32], to: [u8; 32], token_id: [u8; 32], amount: u64) -> Transaction {
    Transaction {
        from,
        to,
        amount: 0,
        gas_limit: 280_000,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: vec![],
        payload: vec![OpCode::SysCallTokenTransfer {
            token_id,
            to,
            amount,
        }],
        priority_fee_per_gas: 0,
    }
}

/// Account/token filters are bounded; deltas are published for a finalized
/// block; a stalled client never delays `record_block`.
#[tokio::test]
async fn stream_account_updates_and_token_transfers_caps_and_nonblocking() {
    let _serial = hub_test_lock().lock().await;
    let st = node_state(0);
    let addr = spawn_server(st.clone()).await;

    // ---- caps: 1..=MAX_SUBSCRIPTION_ACCOUNTS, else -32602 -----------------
    let too_many: Vec<String> = (0..(MAX_SUBSCRIPTION_ACCOUNTS + 1))
        .map(|i| hex32([0x40u8.wrapping_add(i as u8); 32]))
        .collect();
    let over = http_json(
        addr,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "stell_subscribe",
            "params": ["accountUpdates", { "accounts": too_many }]
        }),
    )
    .await;
    assert_eq!(over["error"]["code"], json!(-32602), "got {over}");
    assert!(
        over["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("at most 32"),
        "cap message: {over}"
    );

    let empty = http_json(
        addr,
        json!({
            "jsonrpc": "2.0", "id": 2, "method": "stell_subscribe",
            "params": ["accountUpdates", { "accounts": [] }]
        }),
    )
    .await;
    assert_eq!(empty["error"]["code"], json!(-32602), "got {empty}");

    let at_cap: Vec<String> = (0..MAX_SUBSCRIPTION_ACCOUNTS)
        .map(|i| hex32([0x60u8.wrapping_add(i as u8); 32]))
        .collect();
    let ok = http_json(
        addr,
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "stell_subscribe",
            "params": ["accountUpdates", { "accounts": at_cap }]
        }),
    )
    .await;
    assert!(
        ok.get("error").is_none(),
        "32 accounts must be accepted: {ok}"
    );

    let token_id = [0xE1u8; 32];
    let owner = [0xE2u8; 32];
    let tok = http_json(
        addr,
        json!({
            "jsonrpc": "2.0", "id": 4, "method": "stell_subscribe",
            "params": ["tokenTransfers", { "token": hex32(token_id), "owner": hex32(owner) }]
        }),
    )
    .await;
    assert!(tok.get("error").is_none(), "tokenTransfers accepted: {tok}");

    // ---- deltas of a finalized block -------------------------------------
    let from = [0xF1u8; 32];
    let to = [0xF2u8; 32];
    let account_sub = hub()
        .subscribe_for(
            SubscriptionTopic::AccountUpdates {
                accounts: vec![hex32(from)],
            },
            Some("w4-deltas-accounts"),
        )
        .expect("accountUpdates");
    let token_sub = hub()
        .subscribe_for(
            SubscriptionTopic::TokenTransfers {
                token: Some(hex32(token_id)),
                owner: Some(hex32(to)),
            },
            Some("w4-deltas-token"),
        )
        .expect("tokenTransfers");
    let mut rx = hub().notifications();

    let block_hash = [0xFAu8; 32];
    let tx = token_transfer_tx(from, to, token_id, 42);
    let changed = stellereum::rpc::block_account_deltas(std::slice::from_ref(&tx), &[true]);
    assert!(
        changed.contains(&from) && changed.contains(&to),
        "sender and recipient are the block's changed accounts: {changed:?}"
    );
    let (accounts, transfers) = publish_block_deltas(8_300_000, block_hash, 0, &[tx], &[true]);
    assert_eq!(accounts, 1, "one matching accountUpdates subscription");
    assert_eq!(transfers, 1, "one token transfer event");

    let mut saw_account = false;
    let mut saw_token = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !(saw_account && saw_token) {
            let note = next_note(&mut rx).await;
            if note.subscription == account_sub {
                assert_eq!(note.result["account"], json!(hex32(from)));
                assert_eq!(note.result["height"], json!(8_300_000));
                assert_eq!(note.shard_id, Some(0));
                saw_account = true;
            }
            if note.subscription == token_sub {
                assert_eq!(note.result["token"], json!(hex32(token_id)));
                assert_eq!(note.result["from"], json!(hex32(from)));
                assert_eq!(note.result["to"], json!(hex32(to)));
                assert_eq!(note.result["amount"], json!(42));
                saw_token = true;
            }
        }
    })
    .await
    .expect("delta notifications");

    // ---- a stalled consumer must not delay the record lane ---------------
    let stalled_account = [0xF3u8; 32];
    let stalled_sub = hub()
        .subscribe_for(
            SubscriptionTopic::AccountUpdates {
                accounts: vec![hex32(stalled_account)],
            },
            Some("w4-deltas-stalled"),
        )
        .expect("stalled subscription");
    let stalled_tx = token_transfer_tx(stalled_account, [0xF4u8; 32], token_id, 1);
    // This receiver is intentionally NEVER polled: it stands in for a dead /
    // hung SSE or WS client. The fan-out must stay non-blocking.
    let _stalled_rx = hub().notifications();

    let started = std::time::Instant::now();
    for i in 0..1_500u64 {
        publish_block_deltas(
            8_400_000 + i,
            block_hash,
            0,
            std::slice::from_ref(&stalled_tx),
            &[true],
        );
    }
    let publish_elapsed = started.elapsed();
    assert!(
        publish_elapsed < Duration::from_secs(5),
        "publishing to a stalled subscriber must not block ({publish_elapsed:?})"
    );

    let active_sub = hub()
        .subscribe_for(SubscriptionTopic::NewHeads, Some("w4-deltas-active"))
        .expect("active head subscription");
    let mut active_rx = hub().notifications();
    let started = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(5),
        st.record_block(8_500_001, [0xFBu8; 32], 0, 1_700_000_111),
    )
    .await
    .expect("record_block must not wait for a stalled subscriber");
    let record_elapsed = started.elapsed();
    assert!(
        record_elapsed < Duration::from_secs(5),
        "record_block delayed by a stalled subscriber ({record_elapsed:?})"
    );

    // The active consumer still got the head: the stall cost nobody else.
    let head = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let note = next_note(&mut active_rx).await;
            if note.subscription == active_sub && note.result["height"] == json!(8_500_001u64) {
                return note;
            }
        }
    })
    .await
    .expect("head reached the active subscriber");
    assert_eq!(head.result["shard_id"], json!(0));

    hub().unsubscribe(&stalled_sub);
    hub().unsubscribe(&account_sub);
    hub().unsubscribe(&token_sub);
    hub().unsubscribe(&active_sub);
}

/// Every public method has a rate-limit bucket; the E3 history/scan methods
/// are registered as expensive WS reads (E4 only registers them — E3 owns the
/// implementations).
#[tokio::test]
async fn rate_bucket_table_covers_every_public_method() {
    const KNOWN_BUCKETS: &[&str] = &[
        "transport",
        "expensive",
        "expensive-ws",
        "subscription",
        "faucet",
        "auth",
    ];

    for method in [
        "stell_getAddressHistory",
        "stell_getProgramAccounts",
        "stell_getTokenAccountsByOwner",
    ] {
        let buckets = rpc_rate_buckets(method);
        assert!(
            buckets.contains(&"transport"),
            "`{method}` must sit under the transport limiter, got {buckets:?}"
        );
        assert!(
            buckets.contains(&"expensive-ws"),
            "`{method}` must draw from the WS expensive budget, got {buckets:?}"
        );
        assert!(
            stellereum::rpc::is_ws_expensive_method(method),
            "`{method}` must be classified expensive on WS"
        );
        for b in buckets {
            assert!(
                KNOWN_BUCKETS.contains(b),
                "`{method}` names an unknown bucket `{b}`"
            );
        }
    }

    // The classifier and the table agree for every method either of them
    // knows: an expensive WS read always has the `expensive-ws` bucket.
    for method in [
        "stell_estimateFee",
        "stell_subscribe",
        "stell_getProof",
        "stell_getArchiveProof",
        "stell_getBalanceSpv",
        "stell_tokenBalanceSpv",
        "stell_runGetMethod",
        "stell_getAddressHistory",
        "stell_getProgramAccounts",
        "stell_getTokenAccountsByOwner",
    ] {
        assert!(stellereum::rpc::is_ws_expensive_method(method));
        assert!(rpc_rate_buckets(method).contains(&"expensive-ws"));
    }
    for method in ["stell_blockNumber", "stell_getBalance", "eth_chainId"] {
        assert!(!stellereum::rpc::is_ws_expensive_method(method));
        let buckets = rpc_rate_buckets(method);
        assert_eq!(
            buckets.len(),
            1,
            "`{method}` is transport-only: {buckets:?}"
        );
        assert!(buckets.contains(&"transport"));
    }
    assert!(rpc_rate_buckets("stell_nopeNotReal").is_empty());
    assert!(rpc_rate_buckets("").is_empty());

    // `MAX_REPLAY_BURST` is a real bound: one attach never drains more.
    assert_eq!(MAX_REPLAY_BURST, 256);
    assert_eq!(GEYSER_REPLAY_WINDOW, 512);
}
