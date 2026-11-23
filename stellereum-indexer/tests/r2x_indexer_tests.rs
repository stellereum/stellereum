//! R2-X regression tests for the indexer API:
//!
//! 1. `POST /api/v2/contract/:address/verify` must store exactly the source
//!    text the NODE verified. The node prefers `source_hex` when both forms
//!    are sent; a disagreeing pair is refused fail-closed.
//! 2. `GET /api/v2/stream?after_seq=` must not drop replay events silently
//!    past `MAX_REPLAY_BURST`: it emits a `lagged` / `backfill_required`
//!    notice (the same contract the node's own stream uses).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use stellereum_indexer::db::Database;
use stellereum_indexer::server::{
    create_router, AppState, IndexerStreamHub, StreamPublishInput, MAX_REPLAY_BURST,
};
use stellereum_indexer::syncer::SseFrameParser;

async fn spawn_api(state: AppState) -> (String, reqwest::Client) {
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (base, reqwest::Client::new())
}

/// A mock node that answers every verify submission with `verified: true`.
async fn spawn_confirming_node() -> String {
    let mock = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            let id = body.get("id").cloned().unwrap_or(Value::from(1));
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "verified": true,
                    "compiler": "wat2wasm-1.0",
                    "compiler_flags": "",
                    "source_hash": "11".repeat(32),
                    "onchain_code_hash": "22".repeat(32),
                }
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, mock).await.expect("serve");
    });
    url
}

#[tokio::test]
async fn r2x_verify_refuses_a_disagreeing_source_and_source_hex_pair() {
    let node_url = spawn_confirming_node().await;
    let db = Database::open(":memory:").expect("db");
    let mut state = AppState::with_rpc(db, node_url);
    state.verify_token = Some("r2x-token".to_string());
    let (base, client) = spawn_api(state).await;

    let addr = "aa".repeat(32);
    let res = client
        .post(format!("{base}/api/v2/contract/{addr}/verify"))
        .header("X-Api-Key", "r2x-token")
        .json(&json!({
            "source": "(module) ;; displayed source",
            "source_hex": hex::encode(b"(module) ;; verified source"),
            "compiler": "wat2wasm-1.0",
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a source/source_hex mismatch must be refused before the node is asked"
    );

    // Nothing may have been stored as a verified row.
    let res = client
        .get(format!("{base}/api/v2/contract/{addr}/source"))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn r2x_verify_stores_the_text_the_node_checked() {
    let node_url = spawn_confirming_node().await;
    let db = Database::open(":memory:").expect("db");
    let mut state = AppState::with_rpc(db, node_url);
    state.verify_token = Some("r2x-token".to_string());
    let (base, client) = spawn_api(state).await;

    let wat = "(module) ;; exact verified bytes";
    let addr = "bb".repeat(32);
    let res = client
        .post(format!("{base}/api/v2/contract/{addr}/verify"))
        .header("X-Api-Key", "r2x-token")
        .json(&json!({
            "source": wat,
            "source_hex": hex::encode(wat.as_bytes()),
            "compiler": "wat2wasm-1.0",
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let res = client
        .get(format!("{base}/api/v2/contract/{addr}/source"))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let v: Value = res.json().await.expect("json");
    assert_eq!(v["verified"], true);
    assert_eq!(v["source"], wat);
}

#[tokio::test]
async fn r2x_stream_signals_replay_overflow_instead_of_a_silent_gap() {
    let db = Database::open(":memory:").expect("db");
    let hub = Arc::new(IndexerStreamHub::with_limits(4, Duration::from_secs(10)));
    let state = AppState::new(db).with_stream_hub(Arc::clone(&hub));
    let (base, client) = spawn_api(state).await;

    let published = MAX_REPLAY_BURST + 7;
    for i in 0..published {
        hub.publish(StreamPublishInput {
            topic: "newHeads",
            shard_id: 0,
            height: i as u64,
            contract: None,
            addresses: Vec::new(),
            payload: json!({ "height": i }),
        });
    }

    let mut resp = client
        .get(format!("{base}/api/v2/stream?topics=newHeads&after_seq=0"))
        .send()
        .await
        .expect("connect");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let mut parser = SseFrameParser::new();
    let mut lagged: Option<Value> = None;
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        while lagged.is_none() {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    for frame in parser.feed(&chunk).expect("parse SSE") {
                        if frame.event.as_deref() == Some("lagged") {
                            lagged = Some(serde_json::from_str(&frame.data).expect("lagged json"));
                            break;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => panic!("stream read failed: {e}"),
            }
        }
    })
    .await;
    assert!(
        read.is_ok(),
        "timed out waiting for the replay-overflow notice"
    );

    let lag = lagged.expect("replay overflow must be announced, never silently dropped");
    assert_eq!(
        lag["lagged"].as_u64(),
        Some((published - MAX_REPLAY_BURST) as u64),
        "the notice must say how many matching events were not replayed: {lag}"
    );
    assert_eq!(lag["action"], "backfill_required");
    assert!(
        lag["oldest_available_seq"].as_u64().is_some(),
        "the notice must carry the oldest retained seq: {lag}"
    );
}
