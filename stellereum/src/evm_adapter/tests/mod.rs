use super::*;
use serde_json::{json, Value};

#[test]
fn test_network_info_constants() {
    assert_eq!(eth_chain_id(), "0x167d");
    assert_eq!(net_version(), "5757");
    assert_eq!(web3_client_version(), "Stellereum/v5.0.0-evm-adapter");
    assert!(net_listening());
    assert_eq!(net_peer_count(), "0x2");
    assert!(!eth_syncing());
}

#[test]
fn test_eth_syncing_for_heights_matches_stell_syncing_rule() {
    // Live rule shared with `stell_syncing`: a recent verified peer height
    // above ours means syncing; no sighting (or a peer at/below us) means
    // in sync.
    assert!(!eth_syncing_for_heights(42, None));
    assert!(!eth_syncing_for_heights(42, Some(42)));
    assert!(!eth_syncing_for_heights(42, Some(7)));
    assert!(eth_syncing_for_heights(42, Some(43)));
    // A faulty high vote still pins syncing while fresh — staleness is the
    // caller's job (it passes `None` past `PEER_HEIGHT_STALE_SECS`).
    assert!(eth_syncing_for_heights(0, Some(u64::MAX)));
}

#[test]
fn test_format_peer_count_hex_matches_adapter_view() {
    // The live formatter and the stateful adapter view agree; the
    // testnet-known default ("0x2") is just the formatter at 2.
    assert_eq!(format_peer_count_hex(0), "0x0");
    assert_eq!(format_peer_count_hex(2), NET_PEER_COUNT);
    assert_eq!(format_peer_count_hex(42), "0x2a");
    let custom = EvmAdapter::new().with_peer_count(42);
    assert_eq!(custom.net_peer_count(), format_peer_count_hex(42));
    // Static default stays honestly testnet-known.
    assert_eq!(net_peer_count(), "0x2");
    assert_eq!(EvmAdapter::new().net_peer_count(), "0x2");
}

#[test]
fn test_evm_adapter_dispatch_network_info() {
    let adapter = EvmAdapter::new();

    // 1. eth_chainId -> "0x167d"
    let chain_id_res = adapter
        .dispatch("eth_chainId", &Value::Null)
        .expect("eth_chainId");
    assert_eq!(chain_id_res, json!("0x167d"));

    // 2. net_version -> "5757"
    let net_version_res = adapter
        .dispatch("net_version", &Value::Null)
        .expect("net_version");
    assert_eq!(net_version_res, json!("5757"));

    // 3. web3_clientVersion -> "Stellereum/v5.0.0-evm-adapter"
    let client_ver_res = adapter
        .dispatch("web3_clientVersion", &Value::Null)
        .expect("web3_clientVersion");
    assert_eq!(client_ver_res, json!("Stellereum/v5.0.0-evm-adapter"));

    // 4. net_listening -> true
    let listening_res = adapter
        .dispatch("net_listening", &Value::Null)
        .expect("net_listening");
    assert_eq!(listening_res, json!(true));

    // 5. net_peerCount -> "0x2"
    let peer_count_res = adapter
        .dispatch("net_peerCount", &Value::Null)
        .expect("net_peerCount");
    assert_eq!(peer_count_res, json!("0x2"));

    // 6. eth_syncing -> false
    let syncing_res = adapter
        .dispatch("eth_syncing", &Value::Null)
        .expect("eth_syncing");
    assert_eq!(syncing_res, json!(false));

    // 7. Unknown method -> -32601 Method not found
    let err = adapter
        .dispatch("eth_unknownMethod", &Value::Null)
        .expect_err("unknown method must error");
    assert_eq!(err.code, METHOD_NOT_FOUND_CODE);
}

#[test]
fn test_jsonrpc_request_response_format() {
    let adapter = EvmAdapter::new();

    let req_json = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#;
    let resp_json = adapter.handle_raw_json(req_json);
    let resp: JsonRpcResponse<String> = serde_json::from_str(&resp_json).unwrap();
    assert_eq!(resp.jsonrpc, "2.0");
    assert_eq!(resp.id, json!(1));
    assert_eq!(resp.result, Some("0x167d".to_string()));
    assert!(resp.error.is_none());

    let req_json2 = r#"{"jsonrpc":"2.0","method":"net_version","params":[],"id":"req-alpha"}"#;
    let resp_json2 = adapter.handle_raw_json(req_json2);
    let resp2: JsonRpcResponse<String> = serde_json::from_str(&resp_json2).unwrap();
    assert_eq!(resp2.jsonrpc, "2.0");
    assert_eq!(resp2.id, json!("req-alpha"));
    assert_eq!(resp2.result, Some("5757".to_string()));

    let req_json3 = r#"{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":100}"#;
    let resp_json3 = adapter.handle_raw_json(req_json3);
    let resp3: JsonRpcResponse<String> = serde_json::from_str(&resp_json3).unwrap();
    assert_eq!(resp3.jsonrpc, "2.0");
    assert_eq!(resp3.id, json!(100));
    assert_eq!(
        resp3.result,
        Some("Stellereum/v5.0.0-evm-adapter".to_string())
    );

    let req_json4 = r#"{"jsonrpc":"2.0","method":"net_listening","params":[],"id":null}"#;
    let resp_json4 = adapter.handle_raw_json(req_json4);
    let resp4: JsonRpcResponse<bool> = serde_json::from_str(&resp_json4).unwrap();
    assert_eq!(resp4.jsonrpc, "2.0");
    assert_eq!(resp4.id, Value::Null);
    assert_eq!(resp4.result, Some(true));

    let req_json5 = r#"{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":55}"#;
    let resp_json5 = adapter.handle_raw_json(req_json5);
    let resp5: JsonRpcResponse<String> = serde_json::from_str(&resp_json5).unwrap();
    assert_eq!(resp5.jsonrpc, "2.0");
    assert_eq!(resp5.id, json!(55));
    assert_eq!(resp5.result, Some("0x2".to_string()));

    let req_json6 = r#"{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":77}"#;
    let resp_json6 = adapter.handle_raw_json(req_json6);
    let resp6: JsonRpcResponse<bool> = serde_json::from_str(&resp_json6).unwrap();
    assert_eq!(resp6.jsonrpc, "2.0");
    assert_eq!(resp6.id, json!(77));
    assert_eq!(resp6.result, Some(false));
}

#[test]
fn test_jsonrpc_batch_requests() {
    let adapter = EvmAdapter::new();
    let batch_req = r#"[
        {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
        {"jsonrpc":"2.0","method":"net_version","params":[],"id":2},
        {"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":3},
        {"jsonrpc":"2.0","method":"net_listening","params":[],"id":4},
        {"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":5},
        {"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":6}
    ]"#;

    let batch_resp_raw = adapter.handle_raw_json(batch_req);
    let batch_resp: Vec<JsonRpcResponse> = serde_json::from_str(&batch_resp_raw).unwrap();
    assert_eq!(batch_resp.len(), 6);

    assert_eq!(batch_resp[0].id, json!(1));
    assert_eq!(batch_resp[0].result, Some(json!("0x167d")));

    assert_eq!(batch_resp[1].id, json!(2));
    assert_eq!(batch_resp[1].result, Some(json!("5757")));

    assert_eq!(batch_resp[2].id, json!(3));
    assert_eq!(
        batch_resp[2].result,
        Some(json!("Stellereum/v5.0.0-evm-adapter"))
    );

    assert_eq!(batch_resp[3].id, json!(4));
    assert_eq!(batch_resp[3].result, Some(json!(true)));

    assert_eq!(batch_resp[4].id, json!(5));
    assert_eq!(batch_resp[4].result, Some(json!("0x2")));

    assert_eq!(batch_resp[5].id, json!(6));
    assert_eq!(batch_resp[5].result, Some(json!(false)));
}

#[test]
fn test_jsonrpc_error_handling() {
    let adapter = EvmAdapter::new();

    // 1. Parse error
    let bad_json = r#"{"jsonrpc":"2.0", method:"#;
    let resp_str = adapter.handle_raw_json(bad_json);
    let resp: JsonRpcResponse = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR_CODE);

    // 2. Method not found
    let bad_method = r#"{"jsonrpc":"2.0","method":"eth_unknown","params":[],"id":99}"#;
    let resp_str2 = adapter.handle_raw_json(bad_method);
    let resp2: JsonRpcResponse = serde_json::from_str(&resp_str2).unwrap();
    assert_eq!(resp2.id, json!(99));
    assert_eq!(resp2.error.as_ref().unwrap().code, METHOD_NOT_FOUND_CODE);
    assert!(resp2.result.is_none());

    // 3. Invalid request version
    let bad_ver = r#"{"jsonrpc":"1.0","method":"eth_chainId","params":[],"id":1}"#;
    let resp_str3 = adapter.handle_raw_json(bad_ver);
    let resp3: JsonRpcResponse = serde_json::from_str(&resp_str3).unwrap();
    assert_eq!(resp3.error.as_ref().unwrap().code, INVALID_REQUEST_CODE);
}

#[test]
fn test_evm_block_serde_exact() {
    let block = EvmBlock {
        number: Some("0x167d".to_string()),
        hash: Some(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        ),
        parent_hash: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            .to_string(),
        nonce: Some("0x0000000000000000".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: EMPTY_ROOT_HASH.to_string(),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: "0x0000000000000000000000000000000000000001".to_string(),
        difficulty: "0x0".to_string(),
        total_difficulty: Some("0x0".to_string()),
        extra_data: "0x".to_string(),
        size: "0x400".to_string(),
        gas_limit: "0x1c9c380".to_string(),
        gas_used: "0x5208".to_string(),
        timestamp: "0x651f0000".to_string(),
        transactions: BlockTransactions::Hashes(vec![
            "0xaaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999".to_string(),
        ]),
        uncles: Vec::new(),
        base_fee_per_gas: Some("0x7".to_string()),
        mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
        withdrawals: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    };

    let json_val = serde_json::to_value(&block).unwrap();
    let obj = json_val.as_object().unwrap();

    // Exact camelCase field name verifications
    assert!(obj.contains_key("number"));
    assert!(obj.contains_key("hash"));
    assert!(obj.contains_key("parentHash"));
    assert!(obj.contains_key("nonce"));
    assert!(obj.contains_key("sha3Uncles"));
    assert!(obj.contains_key("logsBloom"));
    assert!(obj.contains_key("transactionsRoot"));
    assert!(obj.contains_key("stateRoot"));
    assert!(obj.contains_key("receiptsRoot"));
    assert!(obj.contains_key("miner"));
    assert!(obj.contains_key("difficulty"));
    assert!(obj.contains_key("totalDifficulty"));
    assert!(obj.contains_key("extraData"));
    assert!(obj.contains_key("size"));
    assert!(obj.contains_key("gasLimit"));
    assert!(obj.contains_key("gasUsed"));
    assert!(obj.contains_key("timestamp"));
    assert!(obj.contains_key("transactions"));
    assert!(obj.contains_key("uncles"));
    assert!(obj.contains_key("baseFeePerGas"));
    assert!(obj.contains_key("mixHash"));

    // Ensure no snake_case leaks
    assert!(!obj.contains_key("parent_hash"));
    assert!(!obj.contains_key("gas_limit"));
    assert!(!obj.contains_key("gas_used"));
    assert!(!obj.contains_key("base_fee_per_gas"));

    // Round-trip verification
    let serialized = serde_json::to_string(&block).unwrap();
    let deserialized: EvmBlock = serde_json::from_str(&serialized).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn test_evm_transaction_serde_exact() {
    let tx = EvmTransaction {
        hash: "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000".to_string(),
        nonce: "0x1".to_string(),
        block_hash: Some(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        ),
        block_number: Some("0x167d".to_string()),
        transaction_index: Some("0x0".to_string()),
        from: "0x0000000000000000000000000000000000000001".to_string(),
        to: Some("0x0000000000000000000000000000000000000002".to_string()),
        value: "0xde0b6b3a7640000".to_string(),
        gas_price: Some("0x3b9aca00".to_string()),
        gas: "0x5208".to_string(),
        input: "0x".to_string(),
        v: "0x2b".to_string(),
        r: "0x1234".to_string(),
        s: "0x5678".to_string(),
        tx_type: Some("0x2".to_string()),
        chain_id: Some("0x167d".to_string()),
        max_fee_per_gas: Some("0x4a817c800".to_string()),
        max_priority_fee_per_gas: Some("0x3b9aca00".to_string()),
        access_list: Some(vec![EvmAccessListItem {
            address: "0x0000000000000000000000000000000000000003".to_string(),
            storage_keys: vec![
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ],
        }]),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let json_val = serde_json::to_value(&tx).unwrap();
    let obj = json_val.as_object().unwrap();

    assert!(obj.contains_key("hash"));
    assert!(obj.contains_key("nonce"));
    assert!(obj.contains_key("blockHash"));
    assert!(obj.contains_key("blockNumber"));
    assert!(obj.contains_key("transactionIndex"));
    assert!(obj.contains_key("from"));
    assert!(obj.contains_key("to"));
    assert!(obj.contains_key("value"));
    assert!(obj.contains_key("gasPrice"));
    assert!(obj.contains_key("gas"));
    assert!(obj.contains_key("input"));
    assert!(obj.contains_key("v"));
    assert!(obj.contains_key("r"));
    assert!(obj.contains_key("s"));
    assert!(obj.contains_key("type"));
    assert!(obj.contains_key("chainId"));
    assert!(obj.contains_key("maxFeePerGas"));
    assert!(obj.contains_key("maxPriorityFeePerGas"));
    assert!(obj.contains_key("accessList"));

    // Ensure no snake_case leaks
    assert!(!obj.contains_key("block_hash"));
    assert!(!obj.contains_key("gas_price"));
    assert!(!obj.contains_key("max_fee_per_gas"));

    // Round-trip verification
    let serialized = serde_json::to_string(&tx).unwrap();
    let deserialized: EvmTransaction = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tx, deserialized);

    // Test alias "data" for "input"
    let raw_with_data = r#"{
        "hash": "0x1111",
        "nonce": "0x1",
        "from": "0x0001",
        "value": "0x0",
        "gas": "0x5208",
        "data": "0xabcdef",
        "v": "0x1b",
        "r": "0x1",
        "s": "0x2"
    }"#;
    let parsed_tx: EvmTransaction = serde_json::from_str(raw_with_data).unwrap();
    assert_eq!(parsed_tx.input, "0xabcdef");
}

#[test]
fn test_evm_receipt_serde_exact() {
    let receipt = EvmReceipt {
        transaction_hash: "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
            .to_string(),
        transaction_index: "0x0".to_string(),
        block_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .to_string(),
        block_number: "0x167d".to_string(),
        from: "0x0000000000000000000000000000000000000001".to_string(),
        to: Some("0x0000000000000000000000000000000000000002".to_string()),
        cumulative_gas_used: "0x5208".to_string(),
        gas_used: "0x5208".to_string(),
        contract_address: None,
        logs: vec![EvmLog {
            address: "0x0000000000000000000000000000000000000002".to_string(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            block_number: Some("0x167d".to_string()),
            transaction_hash: Some(
                "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000".to_string(),
            ),
            transaction_index: Some("0x0".to_string()),
            block_hash: Some(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            ),
            log_index: Some("0x0".to_string()),
            removed: false,
        }],
        logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
        status: Some("0x1".to_string()),
        root: None,
        tx_type: Some("0x2".to_string()),
        effective_gas_price: Some("0x3b9aca00".to_string()),
        blob_gas_used: None,
        blob_gas_price: None,
    };

    let json_val = serde_json::to_value(&receipt).unwrap();
    let obj = json_val.as_object().unwrap();

    assert!(obj.contains_key("transactionHash"));
    assert!(obj.contains_key("transactionIndex"));
    assert!(obj.contains_key("blockHash"));
    assert!(obj.contains_key("blockNumber"));
    assert!(obj.contains_key("from"));
    assert!(obj.contains_key("to"));
    assert!(obj.contains_key("cumulativeGasUsed"));
    assert!(obj.contains_key("gasUsed"));
    assert!(obj.contains_key("contractAddress"));
    assert!(obj.contains_key("logs"));
    assert!(obj.contains_key("logsBloom"));
    assert!(obj.contains_key("status"));
    assert!(obj.contains_key("type"));
    assert!(obj.contains_key("effectiveGasPrice"));

    assert!(!obj.contains_key("transaction_hash"));
    assert!(!obj.contains_key("cumulative_gas_used"));

    // Round-trip verification
    let serialized = serde_json::to_string(&receipt).unwrap();
    let deserialized: EvmReceipt = serde_json::from_str(&serialized).unwrap();
    assert_eq!(receipt, deserialized);
}

#[test]
fn test_evm_fee_history_serde_exact() {
    let fee_history = EvmFeeHistory {
        oldest_block: "0x167d".to_string(),
        base_fee_per_gas: vec!["0x3b9aca00".to_string(), "0x342770c0".to_string()],
        gas_used_ratio: vec![0.5, 0.45],
        reward: Some(vec![
            vec!["0x1".to_string(), "0x2".to_string()],
            vec!["0x3".to_string(), "0x4".to_string()],
        ]),
    };

    let json_val = serde_json::to_value(&fee_history).unwrap();
    let obj = json_val.as_object().unwrap();

    assert!(obj.contains_key("oldestBlock"));
    assert!(obj.contains_key("baseFeePerGas"));
    assert!(obj.contains_key("gasUsedRatio"));
    assert!(obj.contains_key("reward"));

    assert!(!obj.contains_key("oldest_block"));
    assert!(!obj.contains_key("base_fee_per_gas"));
    assert!(!obj.contains_key("gas_used_ratio"));

    // Round-trip verification
    let serialized = serde_json::to_string(&fee_history).unwrap();
    let deserialized: EvmFeeHistory = serde_json::from_str(&serialized).unwrap();
    assert_eq!(fee_history, deserialized);
}

#[test]
fn test_custom_evm_adapter_configuration() {
    let custom = EvmAdapter::new()
        .with_chain_id(1337)
        .with_client_version("CustomClient/v1.0")
        .with_peer_count(42)
        .with_listening(false)
        .with_syncing(true)
        .with_gas_price(0x3eb2788000)
        .with_max_priority_fee_per_gas(0x0)
        .with_base_fee(0x3eb2788000)
        .with_head_block(100)
        .with_gas_used_ratio(0.25);

    assert_eq!(custom.eth_chain_id(), "0x539");
    assert_eq!(custom.net_version(), "1337");
    assert_eq!(custom.web3_client_version(), "CustomClient/v1.0");
    assert!(!custom.net_listening());
    assert_eq!(custom.net_peer_count(), "0x2a");
    assert!(custom.eth_syncing());
    assert_eq!(custom.eth_gas_price(), "0x3eb2788000");
    assert_eq!(custom.eth_max_priority_fee_per_gas(), "0x0");

    assert_eq!(
        custom.dispatch("eth_chainId", &Value::Null).unwrap(),
        json!("0x539")
    );
    assert_eq!(
        custom.dispatch("net_version", &Value::Null).unwrap(),
        json!("1337")
    );
    assert_eq!(
        custom.dispatch("web3_clientVersion", &Value::Null).unwrap(),
        json!("CustomClient/v1.0")
    );
    assert_eq!(
        custom.dispatch("net_listening", &Value::Null).unwrap(),
        json!(false)
    );
    assert_eq!(
        custom.dispatch("net_peerCount", &Value::Null).unwrap(),
        json!("0x2a")
    );
    assert_eq!(
        custom.dispatch("eth_syncing", &Value::Null).unwrap(),
        json!(true)
    );
    assert_eq!(
        custom.dispatch("eth_gasPrice", &Value::Null).unwrap(),
        json!("0x3eb2788000")
    );
    assert_eq!(
        custom
            .dispatch("eth_maxPriorityFeePerGas", &Value::Null)
            .unwrap(),
        json!("0x0")
    );
}

#[test]
fn test_gas_pricing_and_estimation_constants() {
    assert_eq!(eth_gas_price(), "0x3eb2788000");
    assert_eq!(eth_gas_price(), BASE_FEE_HEX);
    assert_eq!(eth_max_priority_fee_per_gas(), "0x3b9aca00");
    assert_eq!(eth_estimate_transfer_gas(), "0x5208");
    assert_eq!(STANDARD_TRANSFER_GAS, 21_000);
    assert_eq!(CONTRACT_CREATION_BASE_GAS, 53_000);

    let parsed_gas_price = parse_hex_u128(eth_gas_price()).expect("must parse u128 hex");
    assert_eq!(parsed_gas_price, 269_282_213_888);
    assert_eq!(parsed_gas_price, DEFAULT_BASE_FEE);

    let parsed_priority_fee =
        parse_hex_u128(eth_max_priority_fee_per_gas()).expect("must parse u128 hex");
    assert_eq!(parsed_priority_fee, 1_000_000_000);
}

#[test]
fn test_evm_adapter_dispatch_gas_and_estimation() {
    let adapter = EvmAdapter::new();

    // 1. eth_gasPrice -> "0x3eb2788000"
    let gas_price_res = adapter
        .dispatch("eth_gasPrice", &Value::Null)
        .expect("eth_gasPrice");
    assert_eq!(gas_price_res, json!("0x3eb2788000"));

    // 2. eth_maxPriorityFeePerGas -> "0x3b9aca00"
    let priority_res = adapter
        .dispatch("eth_maxPriorityFeePerGas", &Value::Null)
        .expect("eth_maxPriorityFeePerGas");
    assert_eq!(priority_res, json!("0x3b9aca00"));

    // 3. eth_estimateGas for transfer (empty params) -> "0x5208"
    let est_empty = adapter
        .dispatch("eth_estimateGas", &json!([]))
        .expect("estimate empty");
    assert_eq!(est_empty, json!("0x445c0"));

    // 4. eth_estimateGas for transfer (standard to/from/value call object) -> "0x5208"
    let est_tx = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "value": "0xde0b6b3a7640000"
            }]),
        )
        .expect("estimate transfer");
    assert_eq!(est_tx, json!("0x445c0"));

    // 5. eth_estimateGas with empty data "0x" -> "0x5208"
    let est_empty_data = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x"
            }]),
        )
        .expect("estimate empty data");
    assert_eq!(est_empty_data, json!("0x445c0"));

    // 6. eth_estimateGas with non-empty calldata (e.g. 4 bytes non-zero -> 21000 + 4*16 = 21064 = 0x5248)
    let est_call = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x12345678"
            }]),
        )
        .expect("estimate call data");
    assert_eq!(est_call, json!("0x445c0")); // floored (pure 0x5248 < 280k floor)

    // 7. eth_estimateGas contract creation (no to field, with bytecode: 53000 + calldata gas)
    // 2 non-zero bytes (0x60, 0x80) -> 53000 + 32 = 53032 = 0xcf28
    let est_create = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "data": "0x6080"
            }]),
        )
        .expect("estimate contract creation");
    assert_eq!(est_create, json!("0x445c0")); // floored (pure 0xcf28 < 280k floor)

    // 8. Invalid hex in data -> error
    let err = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0xinvalid"
            }]),
        )
        .expect_err("must error on invalid hex");
    assert_eq!(err.code, INVALID_PARAMS_CODE);
}

#[test]
fn test_evm_adapter_dispatch_fee_history() {
    let adapter = EvmAdapter::new();

    // 1. eth_feeHistory with array [4, "latest"]
    let fee_hist_val = adapter
        .dispatch("eth_feeHistory", &json!([4, "latest"]))
        .expect("fee history latest");
    let fh: EvmFeeHistory = serde_json::from_value(fee_hist_val).unwrap();

    // 5757 + 1 - 4 = 5754 = 0x167a
    assert_eq!(fh.oldest_block, "0x167a");
    // base_fee_per_gas includes next block (block_count + 1 = 5)
    assert_eq!(fh.base_fee_per_gas.len(), 5);
    for fee in &fh.base_fee_per_gas {
        assert_eq!(fee, "0x3eb2788000");
    }
    assert_eq!(fh.gas_used_ratio.len(), 4);
    assert!(fh.reward.is_none());

    // 2. eth_feeHistory with hex blockCount "0x4" and hex newestBlock "0x10" (16)
    // 16 + 1 - 4 = 13 = 0xd
    let fee_hist_val2 = adapter
        .dispatch("eth_feeHistory", &json!(["0x4", "0x10"]))
        .expect("fee history hex");
    let fh2: EvmFeeHistory = serde_json::from_value(fee_hist_val2).unwrap();
    assert_eq!(fh2.oldest_block, "0xd");
    assert_eq!(fh2.base_fee_per_gas.len(), 5);
    assert_eq!(fh2.gas_used_ratio.len(), 4);

    // 3. eth_feeHistory with rewardPercentiles [25.0, 75.0]
    let fee_hist_val3 = adapter
        .dispatch("eth_feeHistory", &json!([4, "0x10", [25.0, 75.0]]))
        .expect("fee history rewards");
    let fh3: EvmFeeHistory = serde_json::from_value(fee_hist_val3).unwrap();
    assert_eq!(fh3.oldest_block, "0xd");
    let rewards = fh3.reward.expect("must contain rewards");
    assert_eq!(rewards.len(), 4);
    for row in &rewards {
        assert_eq!(row.len(), 2);
        // 25% of 1_000_000_000 is 250_000_000 (0xee6b280)
        assert_eq!(row[0], "0xee6b280");
        // 75% of 1_000_000_000 is 750_000_000 (0x2cb41780)
        assert_eq!(row[1], "0x2cb41780");
    }

    // 4. eth_feeHistory when newestBlock < blockCount - 1 (e.g. blockCount = 10, newestBlock = 2)
    // actual_count = 3 (blocks 0, 1, 2)
    let fee_hist_val4 = adapter
        .dispatch("eth_feeHistory", &json!([10, 2]))
        .expect("fee history near genesis");
    let fh4: EvmFeeHistory = serde_json::from_value(fee_hist_val4).unwrap();
    assert_eq!(fh4.oldest_block, "0x0");
    assert_eq!(fh4.base_fee_per_gas.len(), 4);
    assert_eq!(fh4.gas_used_ratio.len(), 3);

    // 5. eth_feeHistory object parameters
    let fee_hist_val5 = adapter
        .dispatch(
            "eth_feeHistory",
            &json!({
                "blockCount": 2,
                "newestBlock": "0x5",
                "rewardPercentiles": [50.0]
            }),
        )
        .expect("fee history object params");
    let fh5: EvmFeeHistory = serde_json::from_value(fee_hist_val5).unwrap();
    // 5 + 1 - 2 = 4 = 0x4
    assert_eq!(fh5.oldest_block, "0x4");
    assert_eq!(fh5.base_fee_per_gas.len(), 3);
    assert_eq!(fh5.gas_used_ratio.len(), 2);
    let rewards5 = fh5.reward.expect("must have rewards");
    assert_eq!(rewards5.len(), 2);
    assert_eq!(rewards5[0].len(), 1);
    // 50% of 1_000_000_000 is 500_000_000 = 0x1dcd6500
    assert_eq!(rewards5[0][0], "0x1dcd6500");
}

#[test]
fn test_fee_history_parameter_validation() {
    let adapter = EvmAdapter::new();

    // 1. Missing params
    let err1 = adapter
        .dispatch("eth_feeHistory", &json!([]))
        .expect_err("empty params must fail");
    assert_eq!(err1.code, INVALID_PARAMS_CODE);

    // 2. Block count 0
    let err2 = adapter
        .dispatch("eth_feeHistory", &json!([0, "latest"]))
        .expect_err("zero count must fail");
    assert_eq!(err2.code, INVALID_PARAMS_CODE);

    // 3. Block count > 1024
    let err3 = adapter
        .dispatch("eth_feeHistory", &json!([1025, "latest"]))
        .expect_err(">1024 count must fail");
    assert_eq!(err3.code, INVALID_PARAMS_CODE);

    // 4. Reward percentile > 100
    let err4 = adapter
        .dispatch("eth_feeHistory", &json!([2, "latest", [105.0]]))
        .expect_err(">100 percentile must fail");
    assert_eq!(err4.code, INVALID_PARAMS_CODE);

    // 5. Reward percentiles descending
    let err5 = adapter
        .dispatch("eth_feeHistory", &json!([2, "latest", [80.0, 20.0]]))
        .expect_err("descending percentiles must fail");
    assert_eq!(err5.code, INVALID_PARAMS_CODE);
}

#[test]
fn test_keccak256_official_vectors() {
    // 1. Empty string: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let h_empty = keccak256(b"");
    assert_eq!(
        hex::encode(h_empty),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );

    // 2. "abc"
    let h_abc = keccak256(b"abc");
    assert_eq!(
        hex::encode(h_abc),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );

    // 3. "The quick brown fox jumps over the lazy dog"
    let h_fox = keccak256(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        hex::encode(h_fox),
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
    );

    // 4. "The quick brown fox jumps over the lazy dog."
    let h_fox_dot = keccak256(b"The quick brown fox jumps over the lazy dog.");
    assert_eq!(
        hex::encode(h_fox_dot),
        "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"
    );

    // 5. Single null byte [0x00]
    let h_null = keccak256(&[0x00]);
    assert_eq!(
        hex::encode(h_null),
        "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
    );

    // 6. Ethereum Empty Uncles Hash: keccak256(rlp([])) = keccak256([0xc0])
    let h_uncles = keccak256(&[0xc0]);
    assert_eq!(format!("0x{}", hex::encode(h_uncles)), EMPTY_UNCLES_HASH);

    // 7. Ethereum Empty Trie Root Hash: keccak256(rlp("")) = keccak256([0x80])
    let h_root = keccak256(&[0x80]);
    assert_eq!(format!("0x{}", hex::encode(h_root)), EMPTY_ROOT_HASH);

    // 8. ERC-20 method selectors
    let h_transfer = keccak256(b"transfer(address,uint256)");
    assert_eq!(&h_transfer[0..4], &[0xa9, 0x05, 0x9c, 0xbb]);

    let h_transfer_from = keccak256(b"transferFrom(address,address,uint256)");
    assert_eq!(&h_transfer_from[0..4], &[0x23, 0xb8, 0x72, 0xdd]);

    let h_balance_of = keccak256(b"balanceOf(address)");
    assert_eq!(&h_balance_of[0..4], &[0x70, 0xa0, 0x82, 0x31]);
}

#[test]
fn test_keccak256_streaming_and_boundaries() {
    // Test edge boundaries around RATE = 136 bytes:
    // 135 bytes (1 byte padding), 136 bytes (full block + full pad block), 137 bytes, 272 bytes (2 full blocks)
    for len in [0, 1, 135, 136, 137, 271, 272, 273, 500] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let oneshot = keccak256(&data);

        // Test streaming with varied chunk sizes
        for chunk_size in [1, 7, 33, 136, 200] {
            let mut hasher = Keccak256::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            let streamed = hasher.finalize();
            assert_eq!(
                oneshot, streamed,
                "mismatch at len {len} with chunk_size {chunk_size}"
            );
        }
    }
}

#[test]
fn test_rlp_standard_ethereum_vectors() {
    // 1. Empty string "" -> [0x80]
    assert_eq!(rlp_encode_bytes(b""), vec![0x80]);
    let decoded = RlpItem::decode(&[0x80]).unwrap();
    assert_eq!(decoded.as_bytes().unwrap(), b"");
    assert_eq!(decoded, RlpItem::Bytes(vec![]));
    assert_eq!(rlp_decode(&[0x80]).unwrap(), RlpItem::Bytes(vec![]));

    // 2. Single byte in [0x00, 0x7f]
    assert_eq!(rlp_encode_bytes(&[0x00]), vec![0x00]);
    assert_eq!(
        RlpItem::decode(&[0x00]).unwrap().as_bytes().unwrap(),
        &[0x00]
    );
    assert_eq!(RlpItem::decode(&[0x00]).unwrap(), RlpItem::Byte(0x00));
    assert_eq!(rlp_decode(&[0x00]).unwrap(), RlpItem::Byte(0x00));

    assert_eq!(rlp_encode_bytes(&[0x0f]), vec![0x0f]);
    assert_eq!(
        RlpItem::decode(&[0x0f]).unwrap().as_bytes().unwrap(),
        &[0x0f]
    );
    assert_eq!(RlpItem::decode(&[0x0f]).unwrap(), RlpItem::Byte(0x0f));

    assert_eq!(rlp_encode_bytes(&[0x7f]), vec![0x7f]);
    assert_eq!(
        RlpItem::decode(&[0x7f]).unwrap().as_bytes().unwrap(),
        &[0x7f]
    );
    assert_eq!(RlpItem::decode(&[0x7f]).unwrap(), RlpItem::Byte(0x7f));

    // 3. Single byte >= 0x80 -> encoded with 0x81 prefix
    assert_eq!(rlp_encode_bytes(&[0x80]), vec![0x81, 0x80]);
    assert_eq!(
        RlpItem::decode(&[0x81, 0x80]).unwrap().as_bytes().unwrap(),
        &[0x80]
    );
    assert_eq!(
        RlpItem::decode(&[0x81, 0x80]).unwrap(),
        RlpItem::Bytes(vec![0x80])
    );

    assert_eq!(rlp_encode_bytes(&[0xff]), vec![0x81, 0xff]);
    assert_eq!(
        RlpItem::decode(&[0x81, 0xff]).unwrap().as_bytes().unwrap(),
        &[0xff]
    );
    assert_eq!(
        RlpItem::decode(&[0x81, 0xff]).unwrap(),
        RlpItem::Bytes(vec![0xff])
    );

    // 4. Short strings "dog" and "cat"
    let enc_dog = rlp_encode_bytes(b"dog");
    assert_eq!(enc_dog, vec![0x83, b'd', b'o', b'g']);
    assert_eq!(
        RlpItem::decode(&enc_dog).unwrap().as_bytes().unwrap(),
        b"dog"
    );

    let enc_cat = rlp_encode_bytes(b"cat");
    assert_eq!(enc_cat, vec![0x83, b'c', b'a', b't']);
    assert_eq!(
        RlpItem::decode(&enc_cat).unwrap().as_bytes().unwrap(),
        b"cat"
    );

    // 5. 55-byte string (short string boundary)
    let s55 = vec![0x61u8; 55];
    let mut enc55 = vec![0xb7];
    enc55.extend_from_slice(&s55);
    assert_eq!(
        RlpItem::decode(&enc55).unwrap().as_bytes().unwrap(),
        s55.as_slice()
    );

    // 6. 56-byte string (long string boundary: 0xb8 + 1-byte length 0x38)
    let s56 = vec![0x62u8; 56];
    let mut enc56 = vec![0xb8, 0x38];
    enc56.extend_from_slice(&s56);
    assert_eq!(
        RlpItem::decode(&enc56).unwrap().as_bytes().unwrap(),
        s56.as_slice()
    );

    // 7. 1024-byte string (multi-byte length: 0xb9 0x04 0x00)
    let s1024 = vec![0xab; 1024];
    let enc1024 = rlp_encode_bytes(&s1024);
    assert_eq!(enc1024[0], 0xb9);
    assert_eq!(enc1024[1], 0x04);
    assert_eq!(enc1024[2], 0x00);
    assert_eq!(&enc1024[3..], s1024.as_slice());
    assert_eq!(
        RlpItem::decode(&enc1024).unwrap().as_bytes().unwrap(),
        s1024.as_slice()
    );

    // 8. Lists
    // Empty list [] -> [0xc0]
    assert_eq!(rlp_encode_list(&[]), vec![0xc0]);
    let dec_empty_list = RlpItem::decode(&[0xc0]).unwrap();
    assert_eq!(dec_empty_list.as_list().unwrap().len(), 0);

    // [[]] -> [0xc1, 0xc0]
    let enc_nested1 = rlp_encode_list(&[vec![0xc0]]);
    assert_eq!(enc_nested1, vec![0xc1, 0xc0]);
    let dec_nested1 = RlpItem::decode(&enc_nested1).unwrap();
    assert_eq!(dec_nested1.as_list().unwrap().len(), 1);
    assert_eq!(dec_nested1.at(0).unwrap().as_list().unwrap().len(), 0);

    // [[], []] -> [0xc2, 0xc0, 0xc0]
    let enc_nested2 = rlp_encode_list(&[vec![0xc0], vec![0xc0]]);
    assert_eq!(enc_nested2, vec![0xc2, 0xc0, 0xc0]);
    let dec_nested2 = RlpItem::decode(&enc_nested2).unwrap();
    assert_eq!(dec_nested2.as_list().unwrap().len(), 2);

    // ["cat", "dog"] -> [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
    let enc_cat_dog = rlp_encode_list(&[enc_cat.clone(), enc_dog.clone()]);
    assert_eq!(
        enc_cat_dog,
        vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
    );
    let dec_cat_dog = RlpItem::decode(&enc_cat_dog).unwrap();
    assert_eq!(dec_cat_dog.at(0).unwrap().as_bytes().unwrap(), b"cat");
    assert_eq!(dec_cat_dog.at(1).unwrap().as_bytes().unwrap(), b"dog");

    // [[], [[]], [[], [[]]]] -> [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
    let l_empty = vec![0xc0];
    let l_nested = vec![0xc1, 0xc0];
    let l_both = rlp_encode_list(&[l_empty.clone(), l_nested.clone()]);
    let deep = rlp_encode_list(&[l_empty, l_nested, l_both]);
    assert_eq!(deep, vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]);
    let dec_deep = RlpItem::decode(&deep).unwrap();
    assert_eq!(dec_deep.as_list().unwrap().len(), 3);

    // 9. Integers
    // 0 -> [0x80]
    assert_eq!(rlp_encode_u64(0), vec![0x80]);
    assert_eq!(RlpItem::decode(&[0x80]).unwrap().as_u64().unwrap(), 0);
    assert_eq!(RlpItem::decode(&[0x80]).unwrap().as_u128().unwrap(), 0);

    // 15 -> [0x0f]
    assert_eq!(rlp_encode_u64(15), vec![0x0f]);
    assert_eq!(RlpItem::decode(&[0x0f]).unwrap().as_u64().unwrap(), 15);

    // 1000 -> [0x82, 0x03, 0xe8]
    assert_eq!(rlp_encode_u64(1000), vec![0x82, 0x03, 0xe8]);
    assert_eq!(
        RlpItem::decode(&[0x82, 0x03, 0xe8])
            .unwrap()
            .as_u64()
            .unwrap(),
        1000
    );

    // 1024 -> [0x82, 0x04, 0x00]
    assert_eq!(rlp_encode_u64(1024), vec![0x82, 0x04, 0x00]);
    assert_eq!(
        RlpItem::decode(&[0x82, 0x04, 0x00])
            .unwrap()
            .as_u64()
            .unwrap(),
        1024
    );

    // Large u64
    let max_u64 = u64::MAX;
    let enc_max_u64 = rlp_encode_u64(max_u64);
    assert_eq!(
        RlpItem::decode(&enc_max_u64).unwrap().as_u64().unwrap(),
        max_u64
    );

    // Large u128
    let big_val = 1_000_000_000_000_000_000_000_000u128;
    let enc_big = rlp_encode_u128(big_val);
    assert_eq!(
        RlpItem::decode(&enc_big).unwrap().as_u128().unwrap(),
        big_val
    );
}

#[test]
fn test_rlp_non_canonical_and_malformed_rejections() {
    // 1. Single byte < 0x80 encoded as short string with 0x81 prefix -> NonCanonicalSingleByte
    assert_eq!(
        RlpItem::decode(&[0x81, 0x05]).unwrap_err(),
        RlpError::NonCanonicalSingleByte
    );

    // 2. Short payload encoded with long string prefix 0xb8 -> NonCanonicalLength
    assert_eq!(
        RlpItem::decode(&[0xb8, 0x04, 1, 2, 3, 4]).unwrap_err(),
        RlpError::NonCanonicalLength
    );

    // 3. Leading zero in string length field -> LeadingZeroInLength
    assert_eq!(
        RlpItem::decode(&[0xb8, 0x00, 0x38]).unwrap_err(),
        RlpError::LeadingZeroInLength
    );

    // 4. Short list encoded with long list prefix 0xf8 -> NonCanonicalLength
    assert_eq!(
        RlpItem::decode(&[0xf8, 0x02, 0xc0, 0xc0]).unwrap_err(),
        RlpError::NonCanonicalLength
    );

    // 5. Leading zero in list length field -> LeadingZeroInLength
    assert_eq!(
        RlpItem::decode(&[0xf8, 0x00, 0x38]).unwrap_err(),
        RlpError::LeadingZeroInLength
    );

    // 6. Integer with non-canonical leading zero -> LeadingZeroInInteger
    let dec_int_leading_zero = RlpItem::decode(&[0x82, 0x00, 0x2a]).unwrap();
    assert_eq!(
        dec_int_leading_zero.as_u64().unwrap_err(),
        RlpError::LeadingZeroInInteger
    );

    // 7. Trailing unparsed bytes -> TrailingBytes
    assert_eq!(
        RlpItem::decode(&[0x80, 0x00]).unwrap_err(),
        RlpError::TrailingBytes
    );

    // 8. Unexpected EOF / truncated payload
    assert_eq!(
        RlpItem::decode(&[0x85, 0x01, 0x02]).unwrap_err(),
        RlpError::UnexpectedEof
    );

    // 9. Empty buffer -> UnexpectedEof
    assert_eq!(RlpItem::decode(&[]).unwrap_err(), RlpError::UnexpectedEof);
}

#[test]
fn test_eip155_legacy_transaction_official_vector() {
    // Official Ethereum EIP-155 test vector
    let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw = hex::decode(hex_raw).expect("valid hex");

    // 1. Decode transaction
    let decoded = decode_raw_transaction(&raw).expect("valid legacy tx");
    let legacy = match decoded {
        DecodedTransaction::Legacy(tx) => tx,
        _ => panic!("expected legacy transaction"),
    };

    // 2. Validate decoded fields
    assert_eq!(legacy.nonce, 9);
    assert_eq!(legacy.gas_price, 20_000_000_000); // 20 Gwei
    assert_eq!(legacy.gas_limit, 21_000);
    let expected_to = hex::decode("3535353535353535353535353535353535353535").unwrap();
    assert_eq!(legacy.to.as_ref().unwrap(), expected_to.as_slice());
    assert_eq!(legacy.value, 1_000_000_000_000_000_000); // 1 ETH
    assert_eq!(legacy.data, Vec::<u8>::new());
    assert_eq!(legacy.v, 37); // chainId = 1, recovery_id = 0 (37 = 1 * 2 + 35)
    assert_eq!(legacy.chain_id, Some(1));
    assert_eq!(legacy.recovery_id(), 0);

    let expected_r =
        hex::decode("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276").unwrap();
    assert_eq!(legacy.r, expected_r.as_slice());

    let expected_s =
        hex::decode("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").unwrap();
    assert_eq!(legacy.s, expected_s.as_slice());

    // 3. Official EIP-155 signing hash
    let sighash = legacy.signing_hash();
    assert_eq!(
        hex::encode(sighash),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );

    // 4. Verify canonical RLP re-encoding matches raw bytes exactly
    let re_encoded = legacy.encode();
    assert_eq!(re_encoded, raw);

    // 5. Verify tx hash matches keccak256(raw)
    let tx_hash = legacy.compute_hash();
    assert_eq!(tx_hash, keccak256(&raw));

    // 6. Convert to EvmTransaction and verify fields
    let evm_tx = legacy.to_evm_transaction(None, None);
    assert_eq!(evm_tx.nonce, "0x9");
    assert_eq!(evm_tx.gas, "0x5208");
    assert_eq!(evm_tx.gas_price, Some("0x4a817c800".to_string()));
    assert_eq!(evm_tx.value, "0xde0b6b3a7640000");
    assert_eq!(evm_tx.v, "0x25");
    assert_eq!(evm_tx.chain_id, Some("0x1".to_string()));
    assert_eq!(evm_tx.tx_type, Some("0x0".to_string()));
}

#[test]
fn test_legacy_contract_creation_and_unprotected() {
    // Contract creation has to = None and init code in data
    let mut tx = LegacyTransaction {
        nonce: 0,
        gas_price: 1_000_000_000,
        gas_limit: 100_000,
        to: None,
        value: 0,
        data: vec![0x60, 0x80, 0x60, 0x40, 0x52], // sample init code
        v: 11549,                                 // Stellereum chain_id 5757: 5757 * 2 + 35 = 11549
        r: [0x01; 32],
        s: [0x02; 32],
        chain_id: Some(CHAIN_ID),
    };

    let encoded = tx.encode();
    let decoded = decode_legacy_transaction(&encoded).unwrap();
    assert_eq!(decoded.to, None);
    assert_eq!(decoded.chain_id, Some(5757));
    assert_eq!(decoded.recovery_id(), 0);
    assert_eq!(decoded.data, vec![0x60, 0x80, 0x60, 0x40, 0x52]);
    assert_eq!(decoded.encode(), encoded);

    // Pre-EIP-155 unprotected legacy transaction (v = 27)
    tx.v = 27;
    tx.chain_id = None;
    let encoded_unprotected = tx.encode();
    let decoded_unprotected = decode_legacy_transaction(&encoded_unprotected).unwrap();
    assert_eq!(decoded_unprotected.chain_id, None);
    assert_eq!(decoded_unprotected.recovery_id(), 0);
    // Unprotected signing data has 6 elements
    let sighash_data = decoded_unprotected.signing_data();
    let sighash_item = RlpItem::decode(&sighash_data).unwrap();
    assert_eq!(sighash_item.as_list().unwrap().len(), 6);
}

#[test]
fn test_eip1559_type2_envelope_empty_access_list() {
    let tx = Eip1559Transaction {
        chain_id: CHAIN_ID, // 5757
        nonce: 42,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 35_000_000_000,
        gas_limit: 45_000,
        to: Some([0x77; 20]),
        value: 500_000_000_000_000_000, // 0.5 ETH
        data: vec![0xde, 0xad, 0xbe, 0xef],
        access_list: Vec::new(),
        y_parity: 1,
        v: 1,
        r: [0x33; 32],
        s: [0x44; 32],
    };

    let envelope = tx.encode();
    assert_eq!(envelope[0], 0x02, "EIP-1559 envelope must start with 0x02");

    // Decode via top-level raw transaction decoder
    let decoded = decode_raw_transaction(&envelope).expect("decode valid EIP-1559 envelope");
    let decoded_1559 = match decoded {
        DecodedTransaction::Eip1559(t) => t,
        _ => panic!("expected EIP-1559"),
    };

    assert_eq!(decoded_1559.chain_id, 5757);
    assert_eq!(decoded_1559.nonce, 42);
    assert_eq!(decoded_1559.max_priority_fee_per_gas, 1_500_000_000);
    assert_eq!(decoded_1559.max_fee_per_gas, 35_000_000_000);
    assert_eq!(decoded_1559.gas_limit, 45_000);
    assert_eq!(decoded_1559.to, Some([0x77; 20]));
    assert_eq!(decoded_1559.value, 500_000_000_000_000_000);
    assert_eq!(decoded_1559.data, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded_1559.access_list.len(), 0);
    assert_eq!(decoded_1559.y_parity, 1);
    assert_eq!(decoded_1559.r, [0x33; 32]);
    assert_eq!(decoded_1559.s, [0x44; 32]);

    // Verify roundtrip
    assert_eq!(decoded_1559.encode(), envelope);

    // Verify hash is keccak256(0x02 || payload)
    let tx_hash = decoded_1559.compute_hash();
    assert_eq!(tx_hash, keccak256(&envelope));

    // Verify signing data starts with 0x02
    let sig_data = decoded_1559.signing_data();
    assert_eq!(sig_data[0], 0x02);
    let sig_payload = RlpItem::decode(&sig_data[1..]).unwrap();
    assert_eq!(sig_payload.as_list().unwrap().len(), 9);

    // Convert to EvmTransaction
    let evm_tx = decoded_1559.to_evm_transaction(None, None);
    assert_eq!(evm_tx.tx_type, Some("0x2".to_string()));
    assert_eq!(evm_tx.chain_id, Some("0x167d".to_string()));
    assert_eq!(evm_tx.max_fee_per_gas, Some("0x826299e00".to_string()));
    assert_eq!(
        evm_tx.max_priority_fee_per_gas,
        Some("0x59682f00".to_string())
    );
    assert_eq!(evm_tx.access_list, Some(vec![]));
}

#[test]
fn test_eip1559_type2_envelope_with_access_list() {
    let access_list = vec![
        AccessListItem {
            address: [0x11; 20],
            storage_keys: vec![[0xaa; 32], [0xbb; 32]],
        },
        AccessListItem {
            address: [0x22; 20],
            storage_keys: vec![],
        },
    ];

    let tx = Eip1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 80_000,
        to: None, // Contract creation
        value: 0,
        data: vec![0x60, 0x01, 0x60, 0x02, 0x01],
        access_list,
        y_parity: 0,
        v: 0,
        r: [0x55; 32],
        s: [0x66; 32],
    };

    let encoded = tx.encode();
    let decoded = decode_eip1559_transaction(&encoded).expect("decode with access list");

    assert_eq!(decoded.to, None);
    assert_eq!(decoded.access_list.len(), 2);
    assert_eq!(decoded.access_list[0].address, [0x11; 20]);
    assert_eq!(decoded.access_list[0].storage_keys.len(), 2);
    assert_eq!(decoded.access_list[0].storage_keys[0], [0xaa; 32]);
    assert_eq!(decoded.access_list[0].storage_keys[1], [0xbb; 32]);
    assert_eq!(decoded.access_list[1].address, [0x22; 20]);
    assert_eq!(decoded.access_list[1].storage_keys.len(), 0);

    // Roundtrip
    assert_eq!(decoded.encode(), encoded);

    // Convert to EvmTransaction
    let evm_tx = decoded.to_evm_transaction(None, None);
    assert_eq!(evm_tx.to, None);
    let al = evm_tx.access_list.unwrap();
    assert_eq!(al.len(), 2);
    assert_eq!(al[0].address, format!("0x{}", hex::encode([0x11; 20])));
    assert_eq!(al[0].storage_keys.len(), 2);
}

#[test]
fn test_ethereum_address_calculation_formula() {
    // Hardhat / Foundry Account #0:
    // Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    // Expected address: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
    let privkey_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let uncompressed = encoded_point.as_bytes(); // 65 bytes starting with 0x04

    assert_eq!(uncompressed.len(), 65);
    assert_eq!(uncompressed[0], 0x04);

    // Required formula: keccak256(pubkey_uncompressed[1..])[12..32]
    let derived_addr = pubkey_to_address(uncompressed).expect("valid uncompressed pubkey");
    let expected_addr = hex::decode("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
    assert_eq!(derived_addr.as_slice(), expected_addr.as_slice());

    // Also test with raw 64-byte coordinates (without 0x04 tag)
    let derived_from_coords = pubkey_to_address(&uncompressed[1..]).expect("valid 64-byte pubkey");
    assert_eq!(derived_from_coords.as_slice(), expected_addr.as_slice());

    // Also test with 33-byte compressed public key
    let compressed_point = verifying_key.to_encoded_point(true);
    let derived_from_compressed =
        pubkey_to_address(compressed_point.as_bytes()).expect("valid compressed pubkey");
    assert_eq!(derived_from_compressed.as_slice(), expected_addr.as_slice());
}

#[test]
fn test_ecrecover_known_hardhat_personal_sign_vector() {
    let privkey_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
    let expected_addr = pubkey_to_address(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();

    let msg_hash_bytes =
        hex::decode("eff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792").unwrap();
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&msg_hash_bytes);

    let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
    let v = 27u64 + recid.to_byte() as u64;
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[0..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);

    // 1. Core ecrecover
    let recovered = ecrecover(&msg_hash, v, &r, &s).expect("ecrecover should succeed");
    assert_eq!(recovered, expected_addr);

    // 2. verify_signature helper
    let is_valid =
        verify_signature(&expected_addr, &msg_hash, v, &r, &s).expect("verification succeeds");
    assert!(is_valid);

    // 3. Hex interface
    let recovered_hex = ecrecover_hex(
        "0xeff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792",
        &format!("0x{:x}", v),
        &format!("0x{}", hex::encode(r)),
        &format!("0x{}", hex::encode(s)),
    )
    .expect("hex ecrecover should succeed");
    assert_eq!(recovered_hex, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    // 4. Recover full 65-byte uncompressed public key
    let pubkey = ecrecover_pubkey(&msg_hash, v, &r, &s).expect("pubkey recovery succeeds");
    assert_eq!(pubkey[0], 0x04);
    let addr_from_pubkey = pubkey_to_address(&pubkey).unwrap();
    assert_eq!(addr_from_pubkey, expected_addr);
}

#[test]
fn test_ecrecover_eip155_canonical_vector_and_replay_protection() {
    // Official Ethereum EIP-155 test vector
    let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw = hex::decode(hex_raw).expect("valid hex");
    let decoded = decode_raw_transaction(&raw).expect("valid legacy tx");
    let legacy = match decoded {
        DecodedTransaction::Legacy(tx) => tx,
        _ => panic!("expected legacy tx"),
    };

    let sighash = legacy.signing_hash();
    assert_eq!(
        hex::encode(sighash),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );

    // Recover sender via LegacyTransaction method
    let recovered_sender = legacy
        .recover_sender()
        .expect("recover sender from EIP-155 tx");
    let checksummed = to_checksum_address(&recovered_sender);
    assert_eq!(checksummed.len(), 42);

    // Core ecrecover with explicit chain ID matching
    let rec_ok = ecrecover_with_chain_id(&sighash, legacy.v, &legacy.r, &legacy.s, Some(1))
        .expect("should match chain ID 1");
    assert_eq!(rec_ok, recovered_sender);

    // Replay protection: Expected chain ID 2 must FAIL with ChainIdMismatch
    let err_chain2 = ecrecover_with_chain_id(&sighash, legacy.v, &legacy.r, &legacy.s, Some(2))
        .expect_err("must reject replay attack on chain 2");
    assert_eq!(
        err_chain2,
        EvmError::ChainIdMismatch {
            expected: 2,
            got: 1
        }
    );

    // Replay protection: Stellereum chain ID 5757 must FAIL
    let err_stell =
        ecrecover_with_chain_id(&sighash, legacy.v, &legacy.r, &legacy.s, Some(CHAIN_ID))
            .expect_err("must reject replay attack on Stellereum (5757)");
    assert_eq!(
        err_stell,
        EvmError::ChainIdMismatch {
            expected: 5757,
            got: 1
        }
    );

    // Verify low-s compliance
    assert!(is_low_s(&legacy.s));
    // `recover_sender` stays chain-agnostic (validates v consistency only),
    // but `verify_signature` strictly requires Stellereum chain_id == 5757,
    // so the mainnet (chain_id == 1) vector must be rejected here.
    let err_verify = legacy
        .verify_signature()
        .expect_err("foreign chain_id must be rejected");
    assert_eq!(
        err_verify,
        EvmError::ChainIdMismatch {
            expected: CHAIN_ID,
            got: 1
        }
    );
}

#[test]
fn test_ecrecover_eip1559_transaction_roundtrip() {
    // Sign and verify an EIP-1559 transaction using Hardhat Account #0
    let privkey_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
    let expected_sender = pubkey_to_address(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();

    let chain_id = CHAIN_ID; // 5757
    let nonce = 15u64;
    let max_priority_fee = 2_000_000_000u128;
    let max_fee = 40_000_000_000u128;
    let gas_limit = 21_000u64;
    let to = Some([0x88; 20]);
    let value = 1_000_000_000_000_000_000u128;
    let data = vec![];

    let sighash = eip1559_tx_signing_hash(
        chain_id,
        nonce,
        max_priority_fee,
        max_fee,
        gas_limit,
        to.as_ref(),
        value,
        &data,
        &[],
    )
    .unwrap();

    // Sign with secp256k1 recoverable
    let (signature, recid) = signing_key.sign_prehash_recoverable(&sighash).unwrap();
    let y_parity = recid.to_byte();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature.to_bytes()[0..32]);
    s.copy_from_slice(&signature.to_bytes()[32..64]);

    // 1. Direct ecrecover with y_parity (0 or 1)
    let recovered = ecrecover(&sighash, y_parity as u64, &r, &s).expect("ecrecover eip1559");
    assert_eq!(recovered, expected_sender);

    // 2. Direct ecrecover with chain ID matching
    let rec_chain = ecrecover_with_chain_id(&sighash, y_parity as u64, &r, &s, Some(chain_id))
        .expect("ecrecover eip1559 with chain ID");
    assert_eq!(rec_chain, expected_sender);

    // 3. Construct Eip1559Transaction and verify
    let tx = Eip1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: max_priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit,
        to,
        value,
        data,
        access_list: vec![],
        y_parity,
        v: y_parity as u64,
        r,
        s,
    };

    assert_eq!(tx.signing_hash(), sighash);
    let tx_sender = tx.recover_sender().expect("tx recover_sender");
    assert_eq!(tx_sender, expected_sender);
    assert_eq!(tx.verify_signature().unwrap(), expected_sender);

    // 4. Encode to raw envelope, decode, and recover sender
    let raw_envelope = tx.encode();
    let decoded = decode_raw_transaction(&raw_envelope).expect("decode envelope");
    let decoded_sender = decoded.recover_sender().expect("decoded recover_sender");
    assert_eq!(decoded_sender, expected_sender);
}

#[test]
fn test_ecrecover_openzeppelin_vector() {
    let privkey_bytes =
        hex::decode("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
    let expected_addr = pubkey_to_address(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();

    let hash_bytes =
        hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    let (signature, recid) = signing_key.sign_prehash_recoverable(&hash).unwrap();
    let v = 27u64 + recid.to_byte() as u64;
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature.to_bytes()[0..32]);
    s.copy_from_slice(&signature.to_bytes()[32..64]);

    // Recovery succeeds and produces valid non-zero 20-byte address matching signer
    let recovered = ecrecover(&hash, v, &r, &s).expect("ecrecover succeeds");
    assert_eq!(recovered, expected_addr);
    assert!(is_low_s(&s));
}

#[test]
fn test_ecrecover_malleability_and_high_s_rejection() {
    let msg_hash = [0x55u8; 32];
    let v = 27u64;
    let r = [0x11u8; 32];

    // Construct s that is greater than SECP256K1_HALF_N
    let mut high_s = SECP256K1_HALF_N;
    high_s[31] = high_s[31].saturating_add(1);

    assert!(!is_low_s(&high_s));

    // ecrecover_tx must reject high s with InvalidSignatureS
    let err = ecrecover_tx(&msg_hash, v, &r, &high_s, None).expect_err("must reject high-s");
    assert_eq!(err, EvmError::InvalidSignatureS);
}

#[test]
fn test_ecrecover_error_conditions() {
    let hash = [0x42u8; 32];
    let r = [0x01u8; 32];
    let s = [0x02u8; 32];

    // 1. Invalid recovery id v = 2, 26, 34
    assert_eq!(
        ecrecover_with_chain_id(&hash, 2, &r, &s, None).unwrap_err(),
        EvmError::InvalidRecoveryId(2)
    );
    assert_eq!(
        ecrecover_with_chain_id(&hash, 26, &r, &s, None).unwrap_err(),
        EvmError::InvalidRecoveryId(26)
    );
    assert_eq!(
        ecrecover_with_chain_id(&hash, 34, &r, &s, None).unwrap_err(),
        EvmError::InvalidRecoveryId(34)
    );
    assert!(ecrecover(&hash, 2, &r, &s).is_err());
    assert!(ecrecover(&hash, 26, &r, &s).is_err());
    assert!(ecrecover(&hash, 34, &r, &s).is_err());

    // 2. r == 0
    let zero_r = [0u8; 32];
    assert_eq!(
        ecrecover_with_chain_id(&hash, 27, &zero_r, &s, None).unwrap_err(),
        EvmError::InvalidSignatureR
    );
    assert!(ecrecover(&hash, 27, &zero_r, &s).is_err());

    // 3. s == 0
    let zero_s = [0u8; 32];
    assert_eq!(
        ecrecover_with_chain_id(&hash, 27, &r, &zero_s, None).unwrap_err(),
        EvmError::InvalidSignatureS
    );
    assert!(ecrecover(&hash, 27, &r, &zero_s).is_err());

    // 4. Pre-EIP-155 legacy (v = 27) rejected when replay protection is strictly required
    let err_unprot = parse_v_with_chain_id(27, Some(1)).unwrap_err();
    assert_eq!(err_unprot, EvmError::ReplayProtectionRequired);

    // But allowed when allow_unprotected is true
    let (rec_id, chain_opt) = parse_v_with_chain_id_opts(27, Some(1), true).unwrap();
    assert_eq!(rec_id, 0);
    assert_eq!(chain_opt, None);
}

#[test]
fn test_to_checksum_address_official_eip55_vectors() {
    // Official EIP-55 test vectors
    let vectors = [
        (
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ),
        (
            "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        ),
        (
            "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        ),
        (
            "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ),
        (
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        ),
    ];

    for (input, expected) in vectors {
        let addr = parse_address(input).expect("valid address hex");
        let checksummed = to_checksum_address(&addr);
        assert_eq!(checksummed, expected, "failed for {input}");
    }
}

#[test]
fn test_evm_transaction_verify_sender() {
    let privkey_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
    let hash_bytes =
        hex::decode("eff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792").unwrap();
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&hash_bytes);
    let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
    let v = 27u64 + recid.to_byte() as u64;

    // Create an EvmTransaction with Account #0 signature
    let tx = EvmTransaction {
        hash: "0xeff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792".to_string(),
        nonce: "0x0".to_string(),
        block_hash: None,
        block_number: None,
        transaction_index: None,
        from: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
        to: Some("0x0000000000000000000000000000000000000001".to_string()),
        value: "0x0".to_string(),
        gas_price: Some("0x1".to_string()),
        gas: "0x5208".to_string(),
        input: "0x".to_string(),
        v: format!("0x{:x}", v),
        r: format!("0x{}", hex::encode(&sig.to_bytes()[0..32])),
        s: format!("0x{}", hex::encode(&sig.to_bytes()[32..64])),
        tx_type: Some("0x0".to_string()),
        chain_id: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    assert!(tx.verify_sender().unwrap(), "signature must match sender");

    // Tamper with from address
    let mut tampered = tx.clone();
    tampered.from = "0x0000000000000000000000000000000000000002".to_string();
    assert!(
        !tampered.verify_sender().unwrap(),
        "tampered sender must not match"
    );
}

// M-02: single chain-id source — verification follows effective_chain_id().
// These tests never touch the process environment (parallel-safe): they
// sign for `effective_chain_id()` itself, so they hold on any deployment
// (default 5757 live, custom elsewhere). Custom-id-vs-mismatch is covered
// both here (explicit-id paths) and in the integration file that serializes
// STELL_CHAIN_ID via EnvGuard.
fn m02_low_s_normalize(s: [u8; 32], recid_byte: u8) -> ([u8; 32], u8) {
    if is_low_s(&s) {
        return (s, recid_byte);
    }
    let mut out = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let v = SECP256K1_N[i] as i32 - s[i] as i32 - borrow;
        if v < 0 {
            out[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            out[i] = v as u8;
            borrow = 0;
        }
    }
    (out, recid_byte ^ 1)
}

fn m02_sign_legacy_for(chain_id: u64, nonce: u64) -> Vec<u8> {
    let key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let unsigned = LegacyTransaction {
        nonce,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some([0x35u8; 20]),
        value: 1_000,
        data: Vec::new(),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain_id),
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[0..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let (s, recid_b) = m02_low_s_normalize(s, recid.to_byte());
    LegacyTransaction {
        v: chain_id * 2 + 35 + recid_b as u64,
        r,
        s,
        ..unsigned
    }
    .encode()
}

fn m02_sign_eip1559_for(chain_id: u64, nonce: u64) -> Vec<u8> {
    let key = k256::ecdsa::SigningKey::from_slice(&[0x55u8; 32]).unwrap();
    let unsigned = Eip1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: Some([0x36u8; 20]),
        value: 2_000,
        data: Vec::new(),
        access_list: Vec::new(),
        y_parity: 0,
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[0..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let (s, y_parity) = m02_low_s_normalize(s, recid.to_byte());
    Eip1559Transaction {
        y_parity,
        v: y_parity as u64,
        r,
        s,
        ..unsigned
    }
    .encode()
}

#[test]
fn m02_legacy_verification_follows_effective_id() {
    let eff = effective_chain_id();
    assert!(eff > 0, "effective chain id must be non-zero");
    // Tx signed for the effective id verifies at every strict layer.
    let raw = m02_sign_legacy_for(eff, 810_001);
    let decoded = parse_legacy_transaction(&raw).expect("decodes");
    assert_eq!(decoded.chain_id, Some(eff));
    decoded.verify_signature().expect("effective id verifies");
    let sighash = decoded.signing_hash();
    validate_transaction_signature(&sighash, decoded.v, &decoded.r, &decoded.s)
        .expect("validate follows effective");
    eth_send_raw_transaction_bytes(&raw).expect("gate admits effective id");
    evm_raw_to_stell_transaction(&raw).expect("settlement maps effective id");
    // A foreign chain is refused at every strict layer.
    let other = if eff == 5757 { 1337 } else { 5757 };
    let raw_other = m02_sign_legacy_for(other, 810_002);
    let decoded_other = parse_legacy_transaction(&raw_other).expect("decodes");
    let err = decoded_other
        .verify_signature()
        .expect_err("foreign chain refused");
    assert_eq!(
        err,
        EvmError::ChainIdMismatch {
            expected: eff,
            got: other
        },
        "mismatch must name effective id"
    );
    let gate_err = eth_send_raw_transaction_bytes(&raw_other).expect_err("gate refuses foreign");
    assert!(
        gate_err.message.contains(&eff.to_string()),
        "gate must name effective chain, got: {}",
        gate_err.message
    );
}

#[test]
fn m02_eip1559_verification_follows_effective_id() {
    let eff = effective_chain_id();
    let raw = m02_sign_eip1559_for(eff, 820_001);
    let decoded = parse_eip1559_envelope(&raw).expect("decodes");
    assert_eq!(decoded.chain_id, eff);
    decoded.verify_signature().expect("effective id verifies");
    eth_send_raw_transaction_bytes(&raw).expect("gate admits effective id");
    evm_raw_to_stell_transaction(&raw).expect("settlement maps effective id");
    let other = if eff == 5757 { 1337 } else { 5757 };
    let raw_other = m02_sign_eip1559_for(other, 820_002);
    let decoded_other = parse_eip1559_envelope(&raw_other).expect("decodes");
    let err = decoded_other
        .verify_signature()
        .expect_err("foreign chain refused");
    assert_eq!(
        err,
        EvmError::ChainIdMismatch {
            expected: eff,
            got: other
        }
    );
    let gate_err = eth_send_raw_transaction_bytes(&raw_other).expect_err("gate refuses foreign");
    assert!(
        gate_err.message.contains(&eff.to_string()),
        "gate must name effective chain, got: {}",
        gate_err.message
    );
}

#[test]
fn m02_explicit_chain_paths_verify_custom_id() {
    // Explicit-id helpers (no env read) verify a custom chain under its own
    // id and refuse it under any other — the same rule effective paths apply.
    let custom: u64 = 9_999;
    let raw = m02_sign_legacy_for(custom, 830_001);
    let decoded = parse_legacy_transaction(&raw).expect("decodes");
    assert_eq!(decoded.chain_id, Some(custom));
    let sighash = decoded.signing_hash();
    validate_transaction_signature_with_chain_id(
        &sighash,
        decoded.v,
        &decoded.r,
        &decoded.s,
        Some(custom),
    )
    .expect("custom verifies under its own id");
    let err = validate_transaction_signature_with_chain_id(
        &sighash,
        decoded.v,
        &decoded.r,
        &decoded.s,
        Some(5757),
    )
    .expect_err("custom refused under 5757");
    assert!(
        err.contains("5757") && err.contains(&custom.to_string()),
        "unexpected: {err}"
    );
    let rec = ecrecover_with_chain_id(&sighash, decoded.v, &decoded.r, &decoded.s, Some(custom))
        .expect("ecrecover under custom");
    assert_eq!(
        rec,
        decoded.recover_sender().expect("recover under own chain")
    );
    // EIP-1559 envelope round-trips its own chain id into the view.
    let raw1559 = m02_sign_eip1559_for(custom, 830_002);
    let d1559 = parse_eip1559_envelope(&raw1559).expect("decodes");
    assert_eq!(d1559.chain_id, custom);
    let view = d1559.to_evm_transaction(None, None);
    assert_eq!(view.chain_id, Some(format!("0x{custom:x}")));
}

#[test]
fn m02_view_defaults_track_effective_id() {
    let eff = effective_chain_id();
    let tx = crate::sharding::Transaction {
        from: [0x11u8; 32],
        to: [0x22u8; 32],
        amount: 7,
        gas_limit: 21_000,
        nonce: 830_011,
        source_shard: 0,
        target_shard: 0,
        signature: vec![0u8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let view = stell_tx_to_evm(&tx, None, None, None);
    assert_eq!(view.chain_id, Some(eth_chain_id_for(eff)));
    let receipt = crate::rpc::TxReceipt {
        tx_hash: [0xabu8; 32],
        height: 5,
        block_hash: [0xcdu8; 32],
        index: 0,
        success: true,
        gas_limit: 21_000,
        fee_charged: 1_000,
        raw_tx: None,
        return_value: None,
        gas_used: None,
        events: Vec::new(),
        contract_address: None,
    };
    let rview = stell_receipt_to_evm_tx(&receipt).expect("receipt view");
    assert_eq!(rview.chain_id, Some(eth_chain_id_for(eff)));
}
