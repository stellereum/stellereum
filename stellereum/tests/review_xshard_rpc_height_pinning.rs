//! REVIEW REGRESSION: `stell_runGetMethod` must never answer a PAST height
//! with CURRENT state.
//!
//! The RPC used to accept any `height <= tip` and then run the getter against
//! the live contract registry. A client asking for height H1 therefore got
//! the post-H2 value labelled as H1 — a false historical answer. This node
//! keeps no historical contract state, so the only honest answer for a past
//! pin is an explicit refusal (the same fail-closed rule `stell_getProof` and
//! the `eth_*` historical state tags already follow).
//!
//! Fail-before: with the old code the height-42 request returned 2 (the value
//! written at height 43), so the `assert_eq!(success, false)` below failed.

use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::RwLock;

use stellereum::mempool::Mempool;
use stellereum::rpc::{handle_rpc_call, ReceiptIndex, RpcRequest, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;

fn counter_contract() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (import "host" "sload" (func $sload (param i64) (result i64)))
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (func (export "inc") (param $key i64) (result i64)
               (call $sstore (local.get $key)
                             (i64.add (call $sload (local.get $key)) (i64.const 1)))
               (call $sload (local.get $key)))
             (func (export "get") (param $key i64) (result i64)
               (call $sload (local.get $key))))"#,
    )
    .expect("counter wat")
}

fn test_state(engine: Arc<InMemoryStateEngine>, height: u64) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(height)),
        node_id: "review:xshard-height".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn call(st: &RpcState, method: &str, params: Value) -> Value {
    let req = RpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: method.to_string(),
        params,
    };
    let res = handle_rpc_call(st, &req).await;
    if let Some(e) = res.error {
        json!({ "error": { "code": e.code, "message": e.message } })
    } else {
        res.result.unwrap_or(Value::Null)
    }
}

#[tokio::test]
async fn past_height_getter_is_refused_instead_of_relabelled_as_current() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let addr = engine
        .deploy_contract([0x66u8; 32], counter_contract(), 0)
        .await
        .expect("deploy counter");
    let addr_hex = hex::encode(addr);

    // H1 = 42: storage[0] becomes 1.
    let st = test_state(engine.clone(), 42);
    let (v1, _) = engine
        .call_contract(&addr, "inc", 0, 100_000)
        .await
        .expect("inc at H1");
    assert_eq!(v1, 1);

    // H2 = 43: storage[0] becomes 2.
    st.height.store(43, std::sync::atomic::Ordering::Relaxed);
    let (v2, _) = engine
        .call_contract(&addr, "inc", 0, 100_000)
        .await
        .expect("inc at H2");
    assert_eq!(v2, 2);

    // Asking for H1 now must NOT return the H2 value (2) under the H1 label.
    let past = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "get",
            "args": [0],
            "height": 42
        }),
    )
    .await;
    let past_success = past["success"].as_bool().unwrap_or(false);
    if past_success {
        // A real historical snapshot is also acceptable in principle — but
        // this node has none, so the ONLY acceptable successful answer would
        // be the H1 value. Returning H2 here is the bug this test pins.
        assert_eq!(
            past["return_value"],
            json!(1),
            "a past-height request must never observe the later value: {past}"
        );
    } else {
        assert!(
            past["error"]
                .as_str()
                .unwrap_or_default()
                .contains("historical state is not available"),
            "a past height must be refused as unsupported: {past}"
        );
    }

    // The CURRENT height still answers, with the current value.
    let current = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "get",
            "args": [0],
            "height": 43
        }),
    )
    .await;
    assert_eq!(current["success"], json!(true));
    assert_eq!(current["return_value"], json!(2));

    // A future height keeps its own, pre-existing refusal (unchanged).
    let future = call(
        &st,
        "stell_runGetMethod",
        json!({
            "address": addr_hex,
            "method": "get",
            "args": [0],
            "height": 44
        }),
    )
    .await;
    assert_eq!(future["success"], json!(false));
    assert!(future["error"]
        .as_str()
        .unwrap_or_default()
        .contains("exceeds current finalized height"));
}

/// The engine-level helper that the RPC naming implies ("with_height") must
/// follow the same rule: a past pin is unsupported, not a silent alias for
/// the current state.
#[tokio::test]
async fn engine_getter_with_height_refuses_a_past_pin() {
    let engine = InMemoryStateEngine::new();
    let addr = engine
        .deploy_contract([0x67u8; 32], counter_contract(), 0)
        .await
        .expect("deploy counter");
    engine
        .call_contract(&addr, "inc", 0, 100_000)
        .await
        .expect("inc");
    engine
        .call_contract(&addr, "inc", 0, 100_000)
        .await
        .expect("inc");

    let past = engine
        .run_get_method_with_height(&addr, "get", &[0], None, 43, Some(42))
        .await;
    assert!(!past.success);
    assert!(
        past.error
            .as_deref()
            .unwrap_or_default()
            .contains("historical state is not available"),
        "past pin must be refused: {past:?}"
    );

    let current = engine
        .run_get_method_with_height(&addr, "get", &[0], None, 43, Some(43))
        .await;
    assert!(current.success);
    assert_eq!(current.return_value, Some(2));
}
