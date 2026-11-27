use axum::{
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use stellereum::contract_abi::{AbiEvent, AbiMethod, AbiParam, AbiType, ContractAbi};
use stellereum::contract_source::code_hash_sha256;
use stellereum::post_quantum::{FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN};
use stellereum::sharding::Transaction;
use stellereum::svm::OpCode;
use stellereum_indexer::db::{Database, EventFilter};
use stellereum_indexer::syncer::Syncer;

async fn spawn_empty_rest() -> String {
    let mock_rest = Router::new().route("/api/blocks", get(|| async { Json(json!([])) }));
    let rest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest_url = format!("http://{}", rest_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(rest_listener, mock_rest).await.unwrap() });
    rest_url
}

fn build_signed_pq_tx(kp: &FalconKeypair, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        [0u8; 32],
        0,
        500_000,
        nonce,
        0,
        0,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    let tx = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        [0u8; 32],
        0,
        500_000,
        nonce,
        0,
        0,
        payload,
        &DEFAULT_SALT,
    );
    assert!(
        tx.verify_signature(),
        "signed SysCallDeployContractWithAbi transaction must have a valid PQ signature"
    );
    tx
}

#[tokio::test]
async fn deploy_with_abi_persists_abi_and_decodes_events_when_rpc_returns_null() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    let kp = FalconKeypair::generate();
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let expected_code_hash = hex::encode(code_hash_sha256(&wasm));

    let abi = ContractAbi {
        methods: vec![AbiMethod::mutating(
            "deposit",
            vec![AbiParam::new("amount", AbiType::U64)],
            AbiType::Bool,
        )],
        events: vec![AbiEvent::new(
            "Deposited",
            vec![AbiParam::new("sender", AbiType::Address)],
            vec![AbiParam::new("amount", AbiType::U64)],
        )],
    };
    let abi_json = abi.to_json().into_bytes();

    let deploy_tx = build_signed_pq_tx(
        &kp,
        0,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: wasm,
            abi_json,
        }],
    );
    let deploy_tx_hash = hex::encode(deploy_tx.compute_tx_hash());
    let deploy_raw_hex = hex::encode(bincode::serialize(&deploy_tx).expect("serialize deploy tx"));
    let creator_hex = hex::encode(deploy_tx.from);

    let contract_addr = [0x77u8; 32];
    let contract_hex = hex::encode(contract_addr);

    let call_tx = build_signed_pq_tx(
        &kp,
        1,
        vec![OpCode::SysCallCallContract {
            contract: contract_addr,
            method: b"deposit".to_vec(),
            arg: 12_345,
        }],
    );
    let call_tx_hash = hex::encode(call_tx.compute_tx_hash());
    let call_raw_hex = hex::encode(bincode::serialize(&call_tx).expect("serialize call tx"));

    let abi_rpc_calls = Arc::new(AtomicUsize::new(0));
    let abi_rpc_calls_srv = Arc::clone(&abi_rpc_calls);
    let d_hash = deploy_tx_hash.clone();
    let d_raw = deploy_raw_hex.clone();
    let c_hash = call_tx_hash.clone();
    let c_raw = call_raw_hex.clone();
    let dep_c = contract_hex.clone();
    let snd_0x = format!("0x{creator_hex}");

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let abi_calls = Arc::clone(&abi_rpc_calls_srv);
            let d_h = d_hash.clone();
            let d_r = d_raw.clone();
            let c_h = c_hash.clone();
            let c_r = c_raw.clone();
            let dep = dep_c.clone();
            let snd = snd_0x.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => json!("0x1"),
                    "stell_getShards" => json!({
                        "shards": [{
                            "shard_id": 0,
                            "type": "masterchain",
                            "tip_height": 1,
                            "tip_hash": "0xb1",
                            "local": true
                        }],
                        "total_shards": 1
                    }),
                    "stell_getBlock" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        if h == 1 {
                            json!({
                                "shard_id": 0,
                                "height": 1,
                                "hash": "0xb1",
                                "txs": 2,
                                "timestamp": 1_792_000_100
                            })
                        } else {
                            Value::Null
                        }
                    }
                    "stell_getBlockTransactions" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        if h == 1 {
                            json!({
                                "height": 1,
                                "txs": [
                                    {
                                        "tx_hash": d_h,
                                        "index": 0,
                                        "status": "success",
                                        "gas_limit": "500000",
                                        "fee_charged": "250000",
                                        "raw_tx": d_r,
                                    },
                                    {
                                        "tx_hash": c_h,
                                        "index": 1,
                                        "status": "success",
                                        "gas_limit": "500000",
                                        "fee_charged": "100000",
                                        "raw_tx": c_r,
                                    }
                                ]
                            })
                        } else {
                            json!({ "height": h, "txs": [] })
                        }
                    }
                    "stell_getTransactionReceipt" => {
                        let h = body["params"]["hash"].as_str().unwrap_or("");
                        let h_clean = h.strip_prefix("0x").unwrap_or(h);
                        if h_clean.eq_ignore_ascii_case(&d_h) {
                            json!({
                                "tx_hash": d_h,
                                "height": 1,
                                "index": 0,
                                "status": "success",
                                "contract_address": dep,
                                "events": [{
                                    "contract": dep,
                                    "topic": 0,
                                    "topics": [snd],
                                    "data": { "amount": 999 }
                                }]
                            })
                        } else if h_clean.eq_ignore_ascii_case(&c_h) {
                            json!({
                                "tx_hash": c_h,
                                "height": 1,
                                "index": 1,
                                "status": "success",
                                "events": [{
                                    "contract": dep,
                                    "topic": 0,
                                    "topics": [snd],
                                    "data": { "amount": 12_345 }
                                }]
                            })
                        } else {
                            Value::Null
                        }
                    }
                    "stell_getContractAbi" => {
                        abi_calls.fetch_add(1, Ordering::AcqRel);
                        json!({ "contract": dep, "abi": Value::Null })
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
    let caught_up = syncer.sync_step().await.expect("sync_step");
    assert!(caught_up);

    // 1. Even though `stell_getContractAbi` returns `null`, it did not even need
    //    to be polled because the inline ABI from `SysCallDeployContractWithAbi`
    //    was already cached during `apply_receipt_details`.
    assert_eq!(abi_rpc_calls.load(Ordering::Acquire), 0);

    // 2. `abis` cache immediately contains the deployed ContractAbi.
    let cached_abi = syncer
        .abis()
        .get(&contract_hex)
        .expect("ABI must be cached immediately from SysCallDeployContractWithAbi");
    assert_eq!(cached_abi, abi);

    // 3. `db` contracts table immediately records `has_abi = true`, `code_hash`, and `creator`.
    let contracts = db
        .get_contracts_by_filter_keyset(None, Some(&contract_hex), None, 10, None)
        .expect("query contracts");
    assert_eq!(contracts.items.len(), 1);
    let rec = &contracts.items[0];
    assert!(rec.has_abi, "contracts.has_abi must be true immediately");
    assert_eq!(rec.code_hash.as_deref(), Some(expected_code_hash.as_str()));
    assert_eq!(rec.creator.as_deref(), Some(creator_hex.as_str()));
    assert_eq!(rec.deploy_height, 1);

    // 4. Both emitted events (from the deploy tx and the follow-up call tx) are
    //    immediately decoded using the deployed ABI.
    let events = db
        .get_events(
            &EventFilter {
                contract: Some(contract_hex.clone()),
                ..Default::default()
            },
            10,
            0,
        )
        .expect("query events");
    assert_eq!(events.len(), 2);
    for ev in &events {
        assert_eq!(ev.event_name.as_deref(), Some("Deposited"));
        let decoded_str = ev
            .decoded_json
            .as_deref()
            .expect("decoded_json must be populated immediately");
        let decoded: Value = serde_json::from_str(decoded_str).expect("valid decoded_json");
        assert_eq!(decoded["topics"]["sender"], format!("0x{creator_hex}"));
    }
    let amounts: Vec<u64> = events
        .iter()
        .map(|ev| {
            let v: Value = serde_json::from_str(ev.decoded_json.as_deref().unwrap()).unwrap();
            v["data"]["amount"].as_u64().unwrap()
        })
        .collect();
    assert!(amounts.contains(&999));
    assert!(amounts.contains(&12_345));
}

#[tokio::test]
async fn reverted_deploy_with_abi_does_not_persist_abi_or_mark_has_abi() {
    let db = Database::open(":memory:").expect("db");
    let rest_url = spawn_empty_rest().await;

    let kp = FalconKeypair::generate();
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let abi = ContractAbi {
        methods: vec![],
        events: vec![AbiEvent::new(
            "Ping",
            vec![],
            vec![AbiParam::new("v", AbiType::U64)],
        )],
    };
    let deploy_tx = build_signed_pq_tx(
        &kp,
        0,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: wasm,
            abi_json: abi.to_json().into_bytes(),
        }],
    );
    let deploy_tx_hash = hex::encode(deploy_tx.compute_tx_hash());
    let deploy_raw_hex = hex::encode(bincode::serialize(&deploy_tx).expect("serialize deploy tx"));
    let contract_hex = hex::encode([0x88u8; 32]);

    let d_hash = deploy_tx_hash.clone();
    let d_raw = deploy_raw_hex.clone();
    let dep_c = contract_hex.clone();

    let mock_rpc = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let d_h = d_hash.clone();
            let d_r = d_raw.clone();
            let dep = dep_c.clone();
            async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => json!("0x1"),
                    "stell_getShards" => json!({
                        "shards": [{
                            "shard_id": 0,
                            "type": "masterchain",
                            "tip_height": 1,
                            "tip_hash": "0xb1",
                            "local": true
                        }],
                        "total_shards": 1
                    }),
                    "stell_getBlock" => json!({
                        "shard_id": 0,
                        "height": 1,
                        "hash": "0xb1",
                        "txs": 1,
                        "timestamp": 1_792_000_200
                    }),
                    "stell_getBlockTransactions" => json!({
                        "height": 1,
                        "txs": [{
                            "tx_hash": d_h,
                            "index": 0,
                            "status": "reverted",
                            "gas_limit": "500000",
                            "fee_charged": "250000",
                            "raw_tx": d_r,
                        }]
                    }),
                    "stell_getTransactionReceipt" => json!({
                        "tx_hash": d_h,
                        "height": 1,
                        "index": 0,
                        "status": "reverted",
                        "contract_address": dep,
                        "events": []
                    }),
                    "stell_getContractAbi" => json!({ "contract": dep, "abi": Value::Null }),
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
        syncer.abis().get(&contract_hex).is_none(),
        "reverted deploy must not persist ABI into cache"
    );
    let contracts = db
        .get_contracts_by_filter_keyset(None, Some(&contract_hex), None, 10, None)
        .expect("query contracts");
    assert_eq!(contracts.items.len(), 1);
    assert!(!contracts.items[0].has_abi);
    assert!(contracts.items[0].code_hash.is_none());
}
