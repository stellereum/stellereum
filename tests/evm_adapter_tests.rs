use serde_json::{json, Value};
use std::sync::Arc;
use stellereum::evm_adapter::{
    abi_decode_string, abi_decode_u128, abi_decode_u256_be, abi_decode_u8, abi_encode_bool,
    abi_encode_string, abi_encode_u128, abi_encode_u256_be, abi_encode_u8, ecrecover,
    eth_blockNumber, eth_block_number, eth_call, eth_call_with_engine, eth_chain_id,
    eth_estimateGas, eth_estimate_gas, eth_estimate_transfer_gas, eth_feeHistory_direct,
    eth_fee_history, eth_fee_history_direct, eth_fee_history_with_head, eth_gasPrice,
    eth_gas_price, eth_getBalance, eth_getCode, eth_getTransactionCount, eth_get_balance,
    eth_get_code, eth_get_filter_changes, eth_get_filter_logs, eth_get_transaction_count,
    eth_maxPriorityFeePerGas, eth_max_priority_fee_per_gas, eth_max_priority_fee_per_gas_choice,
    eth_max_priority_fee_per_gas_zero, eth_new_block_filter, eth_new_filter,
    eth_new_pending_transaction_filter, eth_syncing, eth_uninstall_filter, evm_address_from_hex,
    evm_address_to_hex, evm_to_stell_address, evm_to_stell_address_from_hex,
    extract_address_from_calldata, extract_calldata, extract_filter_id, is_low_s, keccak256,
    keccak256_hex, nano_to_wei, nano_to_wei_hex, nano_to_wei_str, net_listening, net_peer_count,
    net_version, normalize_address, normalize_filter_id, notify_block, notify_log,
    notify_pending_tx, parse_eip1559_envelope, parse_eip1559_transaction, parse_evm_address,
    parse_evm_or_stell_address, parse_hex_u128, parse_hex_u64, parse_legacy_transaction,
    parse_raw_transaction, pubkey_to_address, rlp_decode, rlp_encode, stell_address_from_hex,
    stell_address_to_evm, stell_hash_to_evm, stell_to_evm_address, to_checksum_address,
    validate_transaction_signature, verify_transaction_signature, web3_client_version,
    wei_hex_to_nano, wei_str_to_nano, wei_to_nano, wei_to_nano_hex, wei_to_nano_str,
    AccessListItem, BlockTag, BlockTransactions, DecodedTransaction, Eip1559Transaction,
    EvmAccessListItem, EvmAdapter, EvmBlock, EvmError, EvmFeeHistory, EvmLog, EvmReceipt,
    EvmTransaction, FilterAddress, FilterCriteria, FilterManager, FilterTopic, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse, Keccak256, LegacyTransaction, RlpItem, BASE_FEE_HEX, CHAIN_ID,
    CHAIN_ID_HEX, CLIENT_VERSION, CONTRACT_CREATION_BASE_GAS, DEFAULT_BASE_FEE, DEFAULT_GAS_PRICE,
    DEFAULT_GAS_PRICE_HEX, DEFAULT_MAX_PRIORITY_FEE, DEFAULT_MAX_PRIORITY_FEE_HEX,
    DEFAULT_TOKEN_DECIMALS, DEFAULT_TOKEN_NAME, DEFAULT_TOKEN_SYMBOL, DEFAULT_TOTAL_SUPPLY,
    EMPTY_LOGS_BLOOM, EMPTY_ROOT_HASH, EMPTY_UNCLES_HASH, FILTER_TTL_SECS, INVALID_PARAMS_CODE,
    MAX_ACTIVE_FILTERS, MAX_PENDING_PER_FILTER, METHOD_NOT_FOUND_CODE, NANO_PER_STELL,
    NET_LISTENING, NET_PEER_COUNT, NET_VERSION, SECP256K1_HALF_N, SELECTOR_BALANCE_OF,
    SELECTOR_BALANCE_OF_HEX, SELECTOR_DECIMALS, SELECTOR_DECIMALS_HEX, SELECTOR_NAME,
    SELECTOR_NAME_HEX, SELECTOR_SYMBOL, SELECTOR_SYMBOL_HEX, SELECTOR_TOTAL_SUPPLY,
    SELECTOR_TOTAL_SUPPLY_HEX, STANDARD_TRANSFER_GAS, STANDARD_TRANSFER_GAS_HEX, WEI_PER_NANO,
    WEI_PER_STELL, ZERO_MAX_PRIORITY_FEE_HEX,
};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[test]
fn test_eth_chain_id_format() {
    let chain_id_str = eth_chain_id();
    assert_eq!(chain_id_str, "0x167d");
    assert_eq!(chain_id_str, CHAIN_ID_HEX);

    // Verify hex parses to decimal 5757
    let stripped = chain_id_str
        .strip_prefix("0x")
        .expect("must have 0x prefix");
    let val = u64::from_str_radix(stripped, 16).expect("must parse as hex u64");
    assert_eq!(val, 5757);
    assert_eq!(val, CHAIN_ID);
}

#[test]
fn test_net_version_format() {
    let version_str = net_version();
    assert_eq!(version_str, "5757");
    assert_eq!(version_str, NET_VERSION);

    // Verify decimal parses to 5757
    let val: u64 = version_str.parse().expect("must parse as decimal u64");
    assert_eq!(val, 5757);
}

#[test]
fn test_web3_client_version_format() {
    let client_version = web3_client_version();
    assert_eq!(client_version, "Stellereum/v5.0.0-evm-adapter");
    assert_eq!(client_version, CLIENT_VERSION);
}

#[test]
fn test_net_listening_format() {
    let listening = net_listening();
    assert!(listening);
    assert_eq!(listening, NET_LISTENING);
}

#[test]
fn test_net_peer_count_format() {
    let peer_count = net_peer_count();
    assert_eq!(peer_count, "0x2");
    assert_eq!(peer_count, NET_PEER_COUNT);

    let stripped = peer_count.strip_prefix("0x").expect("must have 0x prefix");
    let val = u64::from_str_radix(stripped, 16).expect("must parse as hex u64");
    assert_eq!(val, 2);
}

#[test]
fn test_eth_syncing_format() {
    let syncing = eth_syncing();
    assert!(!syncing);
}

#[test]
fn test_typed_jsonrpc_request_and_error() {
    let req = JsonRpcRequest::new(Some(json!(123)), "eth_chainId", json!([]));
    let adapter = EvmAdapter::new();
    let resp = adapter.handle_request(&req);
    assert_eq!(resp.id, json!(123));
    assert_eq!(resp.result, Some(json!("0x167d")));

    let err = JsonRpcError::method_not_found("eth_fake");
    assert_eq!(err.code, METHOD_NOT_FOUND_CODE);
}

#[test]
fn test_evm_adapter_direct_dispatch() {
    let adapter = EvmAdapter::new();

    // 1. eth_chainId -> "0x167d"
    let res = adapter.dispatch("eth_chainId", &Value::Null).unwrap();
    assert_eq!(res, json!("0x167d"));

    // 2. net_version -> "5757"
    let res = adapter.dispatch("net_version", &Value::Null).unwrap();
    assert_eq!(res, json!("5757"));

    // 3. web3_clientVersion -> "Stellereum/v5.0.0-evm-adapter"
    let res = adapter
        .dispatch("web3_clientVersion", &Value::Null)
        .unwrap();
    assert_eq!(res, json!("Stellereum/v5.0.0-evm-adapter"));

    // 4. net_listening -> true
    let res = adapter.dispatch("net_listening", &Value::Null).unwrap();
    assert_eq!(res, json!(true));

    // 5. net_peerCount -> "0x2"
    let res = adapter.dispatch("net_peerCount", &Value::Null).unwrap();
    assert_eq!(res, json!("0x2"));

    // 6. eth_syncing -> false
    let res = adapter.dispatch("eth_syncing", &Value::Null).unwrap();
    assert_eq!(res, json!(false));

    // 7. Unknown method -> Method not found
    let err = adapter.dispatch("eth_unknown", &Value::Null).unwrap_err();
    assert_eq!(err.code, METHOD_NOT_FOUND_CODE);
}

#[test]
fn test_jsonrpc_string_request_and_response() {
    let adapter = EvmAdapter::new();

    // Numeric ID
    let raw_req = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#;
    let raw_resp = adapter.handle_raw_json(raw_req);
    let resp: JsonRpcResponse<String> = serde_json::from_str(&raw_resp).unwrap();
    assert_eq!(resp.jsonrpc, "2.0");
    assert_eq!(resp.id, json!(1));
    assert_eq!(resp.result, Some("0x167d".to_string()));
    assert!(resp.error.is_none());

    // String ID
    let raw_req2 = r#"{"jsonrpc":"2.0","method":"net_version","params":[],"id":"tx-999"}"#;
    let raw_resp2 = adapter.handle_raw_json(raw_req2);
    let resp2: JsonRpcResponse<String> = serde_json::from_str(&raw_resp2).unwrap();
    assert_eq!(resp2.jsonrpc, "2.0");
    assert_eq!(resp2.id, json!("tx-999"));
    assert_eq!(resp2.result, Some("5757".to_string()));
    assert!(resp2.error.is_none());

    // Null ID
    let raw_req3 = r#"{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":null}"#;
    let raw_resp3 = adapter.handle_raw_json(raw_req3);
    let resp3: JsonRpcResponse<String> = serde_json::from_str(&raw_resp3).unwrap();
    assert_eq!(resp3.jsonrpc, "2.0");
    assert_eq!(resp3.id, Value::Null);
    assert_eq!(
        resp3.result,
        Some("Stellereum/v5.0.0-evm-adapter".to_string())
    );
    assert!(resp3.error.is_none());

    // Boolean result for net_listening
    let raw_req4 = r#"{"jsonrpc":"2.0","method":"net_listening","params":[],"id":42}"#;
    let raw_resp4 = adapter.handle_raw_json(raw_req4);
    let resp4: JsonRpcResponse<bool> = serde_json::from_str(&raw_resp4).unwrap();
    assert_eq!(resp4.jsonrpc, "2.0");
    assert_eq!(resp4.id, json!(42));
    assert_eq!(resp4.result, Some(true));
    assert!(resp4.error.is_none());

    // Hex result for net_peerCount
    let raw_req5 = r#"{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":43}"#;
    let raw_resp5 = adapter.handle_raw_json(raw_req5);
    let resp5: JsonRpcResponse<String> = serde_json::from_str(&raw_resp5).unwrap();
    assert_eq!(resp5.jsonrpc, "2.0");
    assert_eq!(resp5.id, json!(43));
    assert_eq!(resp5.result, Some("0x2".to_string()));
    assert!(resp5.error.is_none());

    // Boolean result for eth_syncing
    let raw_req6 = r#"{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":44}"#;
    let raw_resp6 = adapter.handle_raw_json(raw_req6);
    let resp6: JsonRpcResponse<bool> = serde_json::from_str(&raw_resp6).unwrap();
    assert_eq!(resp6.jsonrpc, "2.0");
    assert_eq!(resp6.id, json!(44));
    assert_eq!(resp6.result, Some(false));
    assert!(resp6.error.is_none());
}

#[test]
fn test_jsonrpc_batch_call() {
    let adapter = EvmAdapter::new();
    let batch = r#"[
        {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":10},
        {"jsonrpc":"2.0","method":"net_version","params":[],"id":20},
        {"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":30},
        {"jsonrpc":"2.0","method":"net_listening","params":[],"id":40},
        {"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":50},
        {"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":60}
    ]"#;

    let res_raw = adapter.handle_raw_json(batch);
    let res: Vec<JsonRpcResponse> = serde_json::from_str(&res_raw).unwrap();
    assert_eq!(res.len(), 6);

    assert_eq!(res[0].id, json!(10));
    assert_eq!(res[0].result, Some(json!("0x167d")));

    assert_eq!(res[1].id, json!(20));
    assert_eq!(res[1].result, Some(json!("5757")));

    assert_eq!(res[2].id, json!(30));
    assert_eq!(res[2].result, Some(json!("Stellereum/v5.0.0-evm-adapter")));

    assert_eq!(res[3].id, json!(40));
    assert_eq!(res[3].result, Some(json!(true)));

    assert_eq!(res[4].id, json!(50));
    assert_eq!(res[4].result, Some(json!("0x2")));

    assert_eq!(res[5].id, json!(60));
    assert_eq!(res[5].result, Some(json!(false)));
}

#[test]
fn test_evm_block_exact_serde_structure() {
    let block = EvmBlock {
        number: Some("0x1".to_string()),
        hash: Some(
            "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6".to_string(),
        ),
        parent_hash: "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            .to_string(),
        nonce: Some("0x0000000000000042".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: EMPTY_ROOT_HASH.to_string(),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: "0x1234567890123456789012345678901234567890".to_string(),
        difficulty: "0x20000".to_string(),
        total_difficulty: Some("0x20000".to_string()),
        extra_data: "0x".to_string(),
        size: "0x220".to_string(),
        gas_limit: "0x1c9c380".to_string(),
        gas_used: "0x5208".to_string(),
        timestamp: "0x60000000".to_string(),
        transactions: BlockTransactions::Hashes(vec![
            "0x5c504ed432cb51138b309dd5acb1fe5476a56b357beccfb27f4b9daebfc41250".to_string(),
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

    let serialized = serde_json::to_string_pretty(&block).unwrap();

    // Verify camelCase keys in JSON
    let val: Value = serde_json::from_str(&serialized).unwrap();
    let map = val.as_object().unwrap();

    let expected_keys = [
        "number",
        "hash",
        "parentHash",
        "nonce",
        "sha3Uncles",
        "logsBloom",
        "transactionsRoot",
        "stateRoot",
        "receiptsRoot",
        "miner",
        "difficulty",
        "totalDifficulty",
        "extraData",
        "size",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "transactions",
        "uncles",
        "baseFeePerGas",
        "mixHash",
    ];

    for key in expected_keys {
        assert!(
            map.contains_key(key),
            "Missing expected camelCase key: {key}"
        );
    }

    // Verify roundtrip
    let deserialized: EvmBlock = serde_json::from_str(&serialized).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn test_evm_transaction_exact_serde_structure() {
    let tx = EvmTransaction {
        hash: "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6".to_string(),
        nonce: "0x0".to_string(),
        block_hash: Some(
            "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3".to_string(),
        ),
        block_number: Some("0x1".to_string()),
        transaction_index: Some("0x0".to_string()),
        from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        to: Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        value: "0xde0b6b3a7640000".to_string(),
        gas_price: Some("0x4a817c800".to_string()),
        gas: "0x5208".to_string(),
        input: "0xa9059cbb".to_string(),
        v: "0x25".to_string(),
        r: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        s: "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
        tx_type: Some("0x2".to_string()),
        chain_id: Some("0x167d".to_string()),
        max_fee_per_gas: Some("0x59682f000".to_string()),
        max_priority_fee_per_gas: Some("0x3b9aca00".to_string()),
        access_list: Some(vec![EvmAccessListItem {
            address: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
            storage_keys: vec![
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ],
        }]),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let serialized = serde_json::to_string_pretty(&tx).unwrap();
    let val: Value = serde_json::from_str(&serialized).unwrap();
    let map = val.as_object().unwrap();

    let expected_keys = [
        "hash",
        "nonce",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "from",
        "to",
        "value",
        "gasPrice",
        "gas",
        "input",
        "v",
        "r",
        "s",
        "type",
        "chainId",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "accessList",
    ];

    for key in expected_keys {
        assert!(
            map.contains_key(key),
            "Missing expected camelCase key: {key}"
        );
    }

    // Verify roundtrip
    let deserialized: EvmTransaction = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tx, deserialized);
}

#[test]
fn test_evm_receipt_exact_serde_structure() {
    let receipt = EvmReceipt {
        transaction_hash: "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6"
            .to_string(),
        transaction_index: "0x0".to_string(),
        block_hash: "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            .to_string(),
        block_number: "0x1".to_string(),
        from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        to: Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        cumulative_gas_used: "0x5208".to_string(),
        gas_used: "0x5208".to_string(),
        contract_address: None,
        logs: vec![EvmLog {
            address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000".to_string(),
            block_number: Some("0x1".to_string()),
            transaction_hash: Some(
                "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6".to_string(),
            ),
            transaction_index: Some("0x0".to_string()),
            block_hash: Some(
                "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3".to_string(),
            ),
            log_index: Some("0x0".to_string()),
            removed: false,
        }],
        logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
        status: Some("0x1".to_string()),
        root: None,
        tx_type: Some("0x2".to_string()),
        effective_gas_price: Some("0x4a817c800".to_string()),
        blob_gas_used: None,
        blob_gas_price: None,
    };

    let serialized = serde_json::to_string_pretty(&receipt).unwrap();
    let val: Value = serde_json::from_str(&serialized).unwrap();
    let map = val.as_object().unwrap();

    let expected_keys = [
        "transactionHash",
        "transactionIndex",
        "blockHash",
        "blockNumber",
        "from",
        "to",
        "cumulativeGasUsed",
        "gasUsed",
        "contractAddress",
        "logs",
        "logsBloom",
        "status",
        "type",
        "effectiveGasPrice",
    ];

    for key in expected_keys {
        assert!(
            map.contains_key(key),
            "Missing expected camelCase key: {key}"
        );
    }

    // Verify roundtrip
    let deserialized: EvmReceipt = serde_json::from_str(&serialized).unwrap();
    assert_eq!(receipt, deserialized);
}

#[test]
fn test_evm_fee_history_exact_serde_structure() {
    let fee_history = EvmFeeHistory {
        oldest_block: "0x167d".to_string(),
        base_fee_per_gas: vec![
            "0x3b9aca00".to_string(),
            "0x342770c0".to_string(),
            "0x2df9b7a8".to_string(),
        ],
        gas_used_ratio: vec![0.5, 0.42, 0.38],
        reward: Some(vec![
            vec!["0x1".to_string(), "0x2".to_string()],
            vec!["0x3".to_string(), "0x4".to_string()],
            vec!["0x5".to_string(), "0x6".to_string()],
        ]),
    };

    let serialized = serde_json::to_string_pretty(&fee_history).unwrap();
    let val: Value = serde_json::from_str(&serialized).unwrap();
    let map = val.as_object().unwrap();

    assert!(map.contains_key("oldestBlock"));
    assert!(map.contains_key("baseFeePerGas"));
    assert!(map.contains_key("gasUsedRatio"));
    assert!(map.contains_key("reward"));

    // Check types inside fee history
    assert!(map["oldestBlock"].is_string());
    assert!(map["baseFeePerGas"].is_array());
    assert!(map["gasUsedRatio"].is_array());
    assert!(map["reward"].is_array());

    // Verify roundtrip
    let deserialized: EvmFeeHistory = serde_json::from_str(&serialized).unwrap();
    assert_eq!(fee_history, deserialized);
}

// ============================================================================
// Gas Parameters, Gas Estimation & EIP-1559 Fee History Tests (MetaMask)
// ============================================================================

#[test]
fn test_eth_gas_price_wei_hex_format() {
    // 1. eth_gasPrice returns base fee in Wei formatted as hex quantity ("0x3eb2788000")
    let gas_price_hex = eth_gas_price();
    assert_eq!(gas_price_hex, "0x3eb2788000");
    assert_eq!(gas_price_hex, BASE_FEE_HEX);
    assert_eq!(gas_price_hex, DEFAULT_GAS_PRICE_HEX);
    assert_eq!(eth_gasPrice(), "0x3eb2788000");

    // 2. Verify numerical value: 0x3eb2788000 = 269_282_213_888 Wei
    let parsed_wei = parse_hex_u128(gas_price_hex).expect("must parse hex u128");
    assert_eq!(parsed_wei, 269_282_213_888);
    assert_eq!(parsed_wei, DEFAULT_BASE_FEE);
    assert_eq!(parsed_wei, DEFAULT_GAS_PRICE);

    // 3. Verify dispatch via EvmAdapter
    let adapter = EvmAdapter::new();
    let res = adapter
        .dispatch("eth_gasPrice", &Value::Null)
        .expect("dispatch eth_gasPrice");
    assert_eq!(res, json!("0x3eb2788000"));
    assert_eq!(adapter.eth_gas_price(), "0x3eb2788000");
    assert_eq!(adapter.eth_gasPrice(), "0x3eb2788000");

    // 4. Custom gas price adapter configuration
    let custom = EvmAdapter::new().with_gas_price(1_000_000_000);
    assert_eq!(custom.eth_gas_price(), "0x3b9aca00");
    assert_eq!(
        custom.dispatch("eth_gasPrice", &Value::Null).unwrap(),
        json!("0x3b9aca00")
    );
}

#[test]
fn test_eth_max_priority_fee_per_gas_format() {
    // 1. Default max priority fee: "0x3b9aca00" (1 Gwei = 1_000_000_000 Wei)
    let priority_fee_hex = eth_max_priority_fee_per_gas();
    assert_eq!(priority_fee_hex, "0x3b9aca00");
    assert_eq!(priority_fee_hex, DEFAULT_MAX_PRIORITY_FEE_HEX);
    assert_eq!(eth_maxPriorityFeePerGas(), "0x3b9aca00");

    let parsed_tip = parse_hex_u128(priority_fee_hex).expect("must parse tip hex");
    assert_eq!(parsed_tip, 1_000_000_000);
    assert_eq!(parsed_tip, DEFAULT_MAX_PRIORITY_FEE);

    // 2. Zero max priority fee: "0x0"
    let zero_fee_hex = eth_max_priority_fee_per_gas_zero();
    assert_eq!(zero_fee_hex, "0x0");
    assert_eq!(zero_fee_hex, ZERO_MAX_PRIORITY_FEE_HEX);

    // Choice helper
    assert_eq!(eth_max_priority_fee_per_gas_choice(true), "0x0");
    assert_eq!(eth_max_priority_fee_per_gas_choice(false), "0x3b9aca00");

    // 3. EvmAdapter default and zero dispatch
    let adapter = EvmAdapter::new();
    let res = adapter
        .dispatch("eth_maxPriorityFeePerGas", &Value::Null)
        .expect("dispatch default");
    assert_eq!(res, json!("0x3b9aca00"));
    assert_eq!(adapter.eth_max_priority_fee_per_gas(), "0x3b9aca00");
    assert_eq!(adapter.eth_maxPriorityFeePerGas(), "0x3b9aca00");

    let zero_adapter = EvmAdapter::new().with_max_priority_fee_per_gas(0);
    let zero_res = zero_adapter
        .dispatch("eth_maxPriorityFeePerGas", &Value::Null)
        .expect("dispatch zero");
    assert_eq!(zero_res, json!("0x0"));
    assert_eq!(zero_adapter.eth_max_priority_fee_per_gas(), "0x0");
}

#[test]
fn test_eth_estimate_gas_transfers_and_calls() {
    let adapter = EvmAdapter::new();

    // 1. Standard transfer gas constant
    assert_eq!(STANDARD_TRANSFER_GAS, 21_000);
    assert_eq!(STANDARD_TRANSFER_GAS_HEX, "0x5208");
    assert_eq!(eth_estimate_transfer_gas(), "0x5208");

    // 2. Empty / null parameters return the floored estimate ("0x445c0" = 280000;
    // audit B-VM: max(pure EVM figure, admission floor))
    assert_eq!(eth_estimate_gas(&Value::Null).unwrap(), "0x445c0");
    assert_eq!(eth_estimate_gas(&json!([])).unwrap(), "0x445c0");
    assert_eq!(eth_estimateGas(&json!([])).unwrap(), "0x445c0");
    assert_eq!(adapter.eth_estimate_gas(&json!([])).unwrap(), "0x445c0");
    assert_eq!(adapter.eth_estimateGas(&json!([])).unwrap(), "0x445c0");
    assert_eq!(
        adapter.dispatch("eth_estimateGas", &json!([])).unwrap(),
        json!("0x445c0")
    );

    // 3. Standard native transfer call object: floored to "0x445c0"
    let tx_obj = json!([{
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0xde0b6b3a7640000"
    }]);
    let est = adapter.dispatch("eth_estimateGas", &tx_obj).unwrap();
    assert_eq!(est, json!("0x445c0"));

    // 4. Object without array wrapper
    let direct_obj = json!({
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0x1"
    });
    assert_eq!(eth_estimate_gas(&direct_obj).unwrap(), "0x445c0");

    // 5. Empty data "0x" or ""
    let empty_data = json!([{
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x"
    }]);
    assert_eq!(
        adapter.dispatch("eth_estimateGas", &empty_data).unwrap(),
        json!("0x445c0")
    );

    // 6. With block tag in params: [{"to": "..."}, "latest"]
    let with_tag = json!([{
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0x1"
    }, "latest"]);
    assert_eq!(eth_estimate_gas(&with_tag).unwrap(), "0x445c0");

    // 7. Non-empty calldata: floored to 0x44080 (pure figure 21064 would be rejectable)
    let call_data = json!([{
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x12345678"
    }]);
    assert_eq!(
        adapter.dispatch("eth_estimateGas", &call_data).unwrap(),
        json!("0x445c0")
    );

    // 8. Calldata with zero bytes (4 gas per zero, 16 per non-zero): 0x00010200 -> 21000 + 2*4 + 2*16 = 21040 = 0x5230
    let mixed_data = json!([{
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x00010200"
    }]);
    assert_eq!(
        adapter.dispatch("eth_estimateGas", &mixed_data).unwrap(),
        json!("0x445c0")
    );

    // 9. Input field alias for data
    let input_field = json!([{
        "to": "0x2222222222222222222222222222222222222222",
        "input": "0x12345678"
    }]);
    assert_eq!(
        adapter.dispatch("eth_estimateGas", &input_field).unwrap(),
        json!("0x445c0")
    );

    // 10. Contract creation: no "to" field + bytecode in data -> 53000 + calldata gas
    // "0x6080" has 2 non-zero bytes: pure figure 53032 floored to 0x44080
    assert_eq!(CONTRACT_CREATION_BASE_GAS, 53_000);
    let create_call = json!([{ "data": "0x6080" }]);
    assert_eq!(
        adapter.dispatch("eth_estimateGas", &create_call).unwrap(),
        json!("0x445c0")
    );

    // Contract creation with explicit empty "to": "0x"
    let create_empty_to = json!([{ "to": "0x", "data": "0x6080" }]);
    assert_eq!(
        adapter
            .dispatch("eth_estimateGas", &create_empty_to)
            .unwrap(),
        json!("0x445c0")
    );

    // 11. Error handling: invalid hex in data
    let err_hex = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0xnothex"
            }]),
        )
        .unwrap_err();
    assert_eq!(err_hex.code, INVALID_PARAMS_CODE);

    // Invalid params type (e.g. string)
    let err_type = adapter
        .dispatch("eth_estimateGas", &json!("invalid"))
        .unwrap_err();
    assert_eq!(err_type.code, INVALID_PARAMS_CODE);
}

#[test]
fn test_eth_fee_history_eip1559_metamask_compliance() {
    let adapter = EvmAdapter::new();

    // MetaMask standard fee history query:
    // eth_feeHistory(block_count: 4, newest_block: "latest", reward_percentiles: [10.0, 50.0, 90.0])
    let params = json!([4, "latest", [10.0, 50.0, 90.0]]);
    let res = adapter
        .dispatch("eth_feeHistory", &params)
        .expect("eth_feeHistory latest");

    // 1. Structure verification: camelCase keys expected by MetaMask
    let obj = res.as_object().expect("fee history must be an object");
    assert!(obj.contains_key("oldestBlock"));
    assert!(obj.contains_key("baseFeePerGas"));
    assert!(obj.contains_key("gasUsedRatio"));
    assert!(obj.contains_key("reward"));

    // 2. oldestBlock: hex quantity starting with 0x
    let oldest_block_str = obj["oldestBlock"].as_str().expect("oldestBlock is string");
    assert!(oldest_block_str.starts_with("0x"));
    let oldest_block_num = parse_hex_u64(oldest_block_str).expect("oldestBlock parses as hex u64");
    // head = 5757, count = 4: 5757 + 1 - 4 = 5754 = 0x167a
    assert_eq!(oldest_block_num, 5754);
    assert_eq!(oldest_block_str, "0x167a");

    // 3. baseFeePerGas: MUST have length block_count + 1 (5 items) for MetaMask pending fee calculation
    let base_fees = obj["baseFeePerGas"]
        .as_array()
        .expect("baseFeePerGas is array");
    assert_eq!(
        base_fees.len(),
        5,
        "baseFeePerGas length must be block_count + 1"
    );
    for fee in base_fees {
        let s = fee.as_str().expect("base fee item is hex string");
        assert!(s.starts_with("0x"));
        let val = parse_hex_u128(s).expect("base fee item parses as u128");
        assert_eq!(val, DEFAULT_BASE_FEE);
        assert_eq!(s, "0x3eb2788000");
    }

    // 4. gasUsedRatio: MUST have length block_count (4 items) with floats in [0.0, 1.0]
    let ratios = obj["gasUsedRatio"]
        .as_array()
        .expect("gasUsedRatio is array");
    assert_eq!(
        ratios.len(),
        4,
        "gasUsedRatio length must equal block_count"
    );
    for ratio in ratios {
        let r = ratio.as_f64().expect("ratio is float");
        assert!((0.0..=1.0).contains(&r), "ratio {r} must be in [0.0, 1.0]");
    }

    // 5. reward: MUST have length block_count (4 rows), each with reward_percentiles.len() (3 columns)
    let rewards = obj["reward"].as_array().expect("reward is array");
    assert_eq!(rewards.len(), 4, "reward length must equal block_count");
    for row in rewards {
        let row_arr = row.as_array().expect("reward row is array");
        assert_eq!(
            row_arr.len(),
            3,
            "reward row length must equal percentiles count"
        );

        let p10 = parse_hex_u128(row_arr[0].as_str().unwrap()).unwrap();
        let p50 = parse_hex_u128(row_arr[1].as_str().unwrap()).unwrap();
        let p90 = parse_hex_u128(row_arr[2].as_str().unwrap()).unwrap();

        // 10% of 1_000_000_000 = 100_000_000 = 0x5f5e100
        assert_eq!(row_arr[0].as_str().unwrap(), "0x5f5e100");
        // 50% of 1_000_000_000 = 500_000_000 = 0x1dcd6500
        assert_eq!(row_arr[1].as_str().unwrap(), "0x1dcd6500");
        // 90% of 1_000_000_000 = 900_000_000 = 0x35a4e900
        assert_eq!(row_arr[2].as_str().unwrap(), "0x35a4e900");

        // Monotonically non-decreasing tips
        assert!(p10 <= p50);
        assert!(p50 <= p90);
    }

    // 6. Direct serde roundtrip
    let fh: EvmFeeHistory = serde_json::from_value(res).unwrap();
    assert_eq!(fh.oldest_block, "0x167a");
    assert_eq!(fh.base_fee_per_gas.len(), 5);
    assert_eq!(fh.gas_used_ratio.len(), 4);
    assert!(fh.reward.is_some());
    assert_eq!(fh.reward.as_ref().unwrap().len(), 4);
}

#[test]
fn test_eth_fee_history_without_rewards() {
    let adapter = EvmAdapter::new();

    // Query fee history without 3rd parameter (rewardPercentiles)
    let res = adapter
        .dispatch("eth_feeHistory", &json!([5, "latest"]))
        .expect("fee history no rewards");
    let obj = res.as_object().unwrap();

    // reward field must be absent when not requested
    assert!(!obj.contains_key("reward") || obj["reward"].is_null());

    let base_fees = obj["baseFeePerGas"].as_array().unwrap();
    assert_eq!(base_fees.len(), 6); // 5 + 1

    let ratios = obj["gasUsedRatio"].as_array().unwrap();
    assert_eq!(ratios.len(), 5);

    let fh: EvmFeeHistory = serde_json::from_value(res).unwrap();
    assert!(fh.reward.is_none());
}

#[test]
fn test_eth_fee_history_block_tags_and_ranges() {
    let adapter = EvmAdapter::new();

    // 1. Hex block count and hex newestBlock: 4 blocks ending at block 16 (0x10)
    // 16 + 1 - 4 = 13 = 0xd
    let res_hex = adapter
        .dispatch("eth_feeHistory", &json!(["0x4", "0x10"]))
        .unwrap();
    let fh_hex: EvmFeeHistory = serde_json::from_value(res_hex).unwrap();
    assert_eq!(fh_hex.oldest_block, "0xd");
    assert_eq!(fh_hex.base_fee_per_gas.len(), 5);
    assert_eq!(fh_hex.gas_used_ratio.len(), 4);

    // 2. Near genesis: requesting 10 blocks when newestBlock is 2
    // actual_count = min(10, 2 + 1) = 3 (blocks 0, 1, 2)
    // oldest_block = 2 + 1 - 3 = 0 = "0x0"
    let res_genesis = adapter
        .dispatch("eth_feeHistory", &json!([10, 2, [50.0]]))
        .unwrap();
    let fh_genesis: EvmFeeHistory = serde_json::from_value(res_genesis).unwrap();
    assert_eq!(fh_genesis.oldest_block, "0x0");
    assert_eq!(fh_genesis.base_fee_per_gas.len(), 4); // 3 + 1
    assert_eq!(fh_genesis.gas_used_ratio.len(), 3);
    assert_eq!(fh_genesis.reward.unwrap().len(), 3);

    // 3. Object parameters format
    let res_obj = adapter
        .dispatch(
            "eth_feeHistory",
            &json!({
                "blockCount": 2,
                "newestBlock": "0x8",
                "rewardPercentiles": [25.0, 75.0]
            }),
        )
        .unwrap();
    let fh_obj: EvmFeeHistory = serde_json::from_value(res_obj).unwrap();
    // 8 + 1 - 2 = 7 = 0x7
    assert_eq!(fh_obj.oldest_block, "0x7");
    assert_eq!(fh_obj.base_fee_per_gas.len(), 3);
    assert_eq!(fh_obj.gas_used_ratio.len(), 2);
    assert_eq!(fh_obj.reward.unwrap().len(), 2);

    // 4. Direct typed helper: eth_fee_history_direct / eth_feeHistory_direct
    let fh_direct = eth_fee_history_direct(4, 5757, Some(vec![25.0, 75.0])).unwrap();
    assert_eq!(fh_direct.oldest_block, "0x167a");
    assert_eq!(fh_direct.base_fee_per_gas.len(), 5);
    assert_eq!(fh_direct.reward.unwrap().len(), 4);

    let fh_direct_alias = eth_feeHistory_direct(4, 5757, None).unwrap();
    assert_eq!(fh_direct_alias.oldest_block, "0x167a");
    assert_eq!(fh_direct_alias.base_fee_per_gas.len(), 5);
    assert!(fh_direct_alias.reward.is_none());

    // 5. Adapter method eth_fee_history_direct
    let fh_adapter_direct = adapter.eth_fee_history_direct(3, 100, None).unwrap();
    // 100 + 1 - 3 = 98 = 0x62
    assert_eq!(fh_adapter_direct.oldest_block, "0x62");
    assert_eq!(fh_adapter_direct.base_fee_per_gas.len(), 4);

    // 6. With custom head via eth_fee_history_with_head
    let fh_head = eth_fee_history_with_head(&json!([4, "latest"]), 50).unwrap();
    // 50 + 1 - 4 = 47 = 0x2f
    assert_eq!(fh_head.oldest_block, "0x2f");
    assert_eq!(fh_head.base_fee_per_gas.len(), 5);
}

#[test]
fn test_eth_fee_history_parameter_validation_errors() {
    let adapter = EvmAdapter::new();

    // 1. Missing params
    let err_empty = adapter.dispatch("eth_feeHistory", &json!([])).unwrap_err();
    assert_eq!(err_empty.code, INVALID_PARAMS_CODE);

    // 2. Block count 0
    let err_zero = adapter
        .dispatch("eth_feeHistory", &json!([0, "latest"]))
        .unwrap_err();
    assert_eq!(err_zero.code, INVALID_PARAMS_CODE);

    // 3. Block count > 1024
    let err_overflow = adapter
        .dispatch("eth_feeHistory", &json!([1025, "latest"]))
        .unwrap_err();
    assert_eq!(err_overflow.code, INVALID_PARAMS_CODE);

    // 4. Percentile > 100
    let err_pct = adapter
        .dispatch("eth_feeHistory", &json!([2, "latest", [105.0]]))
        .unwrap_err();
    assert_eq!(err_pct.code, INVALID_PARAMS_CODE);

    // 5. Percentile < 0
    let err_neg = adapter
        .dispatch("eth_feeHistory", &json!([2, "latest", [-5.0]]))
        .unwrap_err();
    assert_eq!(err_neg.code, INVALID_PARAMS_CODE);

    // 6. Descending percentiles
    let err_desc = adapter
        .dispatch("eth_feeHistory", &json!([2, "latest", [80.0, 20.0]]))
        .unwrap_err();
    assert_eq!(err_desc.code, INVALID_PARAMS_CODE);
}

#[test]
fn test_metamask_gas_jsonrpc_string_dispatch_end_to_end() {
    let adapter = EvmAdapter::new();

    // 1. eth_gasPrice
    let req1 = r#"{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":1}"#;
    let resp1_raw = adapter.handle_raw_json(req1);
    let resp1: JsonRpcResponse<String> = serde_json::from_str(&resp1_raw).unwrap();
    assert_eq!(resp1.id, json!(1));
    assert_eq!(resp1.result.unwrap(), "0x3eb2788000");

    // 2. eth_maxPriorityFeePerGas
    let req2 = r#"{"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":2}"#;
    let resp2_raw = adapter.handle_raw_json(req2);
    let resp2: JsonRpcResponse<String> = serde_json::from_str(&resp2_raw).unwrap();
    assert_eq!(resp2.id, json!(2));
    assert_eq!(resp2.result.unwrap(), "0x3b9aca00");

    // 3. eth_estimateGas for transfer
    let req3 = r#"{"jsonrpc":"2.0","method":"eth_estimateGas","params":[{"to":"0x2222222222222222222222222222222222222222"}],"id":3}"#;
    let resp3_raw = adapter.handle_raw_json(req3);
    let resp3: JsonRpcResponse<String> = serde_json::from_str(&resp3_raw).unwrap();
    assert_eq!(resp3.id, json!(3));
    assert_eq!(resp3.result.unwrap(), "0x445c0");

    // 4. eth_feeHistory
    let req4 =
        r#"{"jsonrpc":"2.0","method":"eth_feeHistory","params":[4,"latest",[25.0,75.0]],"id":4}"#;
    let resp4_raw = adapter.handle_raw_json(req4);
    let resp4: JsonRpcResponse<EvmFeeHistory> = serde_json::from_str(&resp4_raw).unwrap();
    assert_eq!(resp4.id, json!(4));
    let fh = resp4.result.unwrap();
    assert_eq!(fh.oldest_block, "0x167a");
    assert_eq!(fh.base_fee_per_gas.len(), 5);
    assert_eq!(fh.gas_used_ratio.len(), 4);
    assert_eq!(fh.reward.unwrap().len(), 4);

    // 5. Batch request combining all MetaMask gas initialization calls
    let batch = r#"[
        {"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":10},
        {"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":20},
        {"jsonrpc":"2.0","method":"eth_feeHistory","params":[4,"latest",[50.0]],"id":30},
        {"jsonrpc":"2.0","method":"eth_estimateGas","params":[],"id":40}
    ]"#;
    let batch_resp_raw = adapter.handle_raw_json(batch);
    let batch_resp: Vec<JsonRpcResponse> = serde_json::from_str(&batch_resp_raw).unwrap();
    assert_eq!(batch_resp.len(), 4);
    assert_eq!(batch_resp[0].result, Some(json!("0x3eb2788000")));
    assert_eq!(batch_resp[1].result, Some(json!("0x3b9aca00")));
    assert!(batch_resp[2]
        .result
        .as_ref()
        .unwrap()
        .get("oldestBlock")
        .is_some());
    assert_eq!(batch_resp[3].result, Some(json!("0x445c0")));
}

#[test]
fn test_metamask_gas_indicator_calculation_simulation() {
    let adapter = EvmAdapter::new();

    // Simulate MetaMask gas fee controller flow:
    // Step 1: Fetch EIP-1559 fee history with percentiles [10.0, 50.0, 90.0]
    let fh_val = adapter
        .dispatch("eth_feeHistory", &json!([5, "latest", [10.0, 50.0, 90.0]]))
        .unwrap();
    let fh: EvmFeeHistory = serde_json::from_value(fh_val).unwrap();

    // Step 2: Next block base fee is the last element of base_fee_per_gas
    assert_eq!(fh.base_fee_per_gas.len(), 6);
    let next_base_fee_hex = fh.base_fee_per_gas.last().unwrap();
    let next_base_fee = parse_hex_u128(next_base_fee_hex).expect("parse base fee");
    assert_eq!(next_base_fee, DEFAULT_BASE_FEE);

    // Step 3: Priority fee suggestions from the newest block rewards
    let rewards = fh.reward.as_ref().unwrap();
    let newest_rewards = rewards.last().unwrap();
    let low_tip = parse_hex_u128(&newest_rewards[0]).unwrap();
    let medium_tip = parse_hex_u128(&newest_rewards[1]).unwrap();
    let high_tip = parse_hex_u128(&newest_rewards[2]).unwrap();

    assert!(low_tip < medium_tip);
    assert!(medium_tip < high_tip);

    // Step 4: Max fee per gas calculation (EIP-1559 buffer: 2 * base_fee + tip)
    let max_fee_medium = 2 * next_base_fee + medium_tip;

    // Step 5: Gas limit estimation via eth_estimateGas
    let est_gas_hex = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "value": "0xde0b6b3a7640000"
            }]),
        )
        .unwrap();
    let gas_limit = parse_hex_u64(est_gas_hex.as_str().unwrap()).unwrap();
    // Audit B-VM: floored to the admission floor (280000), not raw 21k.
    assert_eq!(gas_limit, 280_000);

    // Step 6: Estimated transaction max fee in Wei
    let max_cost_wei = (gas_limit as u128) * max_fee_medium;
    assert!(max_cost_wei > 0);

    // Step 7: Fallback sanity checks: eth_gasPrice and eth_maxPriorityFeePerGas match
    let gas_price = parse_hex_u128(adapter.eth_gas_price().as_str()).unwrap();
    assert_eq!(gas_price, next_base_fee);

    let priority_fee = parse_hex_u128(adapter.eth_max_priority_fee_per_gas().as_str()).unwrap();
    assert_eq!(priority_fee, DEFAULT_MAX_PRIORITY_FEE);
}

// ============================================================================
// Ethereum Keccak-256 Tests
// ============================================================================

#[test]
fn test_keccak256_official_ethereum_vectors() {
    // 1. Empty string: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let empty_hash = keccak256(b"");
    assert_eq!(
        hex::encode(empty_hash),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(
        keccak256_hex(b""),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );

    // 2. Short string "abc"
    let abc_hash = keccak256(b"abc");
    assert_eq!(
        hex::encode(abc_hash),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );

    // 3. Pangram
    let fox_hash = keccak256(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        hex::encode(fox_hash),
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
    );

    // 4. Single null byte
    let null_hash = keccak256(&[0x00]);
    assert_eq!(
        hex::encode(null_hash),
        "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
    );

    // 6. Ethereum Empty Uncles Hash: keccak256(rlp([])) = keccak256([0xc0])
    let uncles_hash = keccak256(&[0xc0]);
    assert_eq!(format!("0x{}", hex::encode(uncles_hash)), EMPTY_UNCLES_HASH);

    // 7. Ethereum Empty Trie Root Hash: keccak256(rlp("")) = keccak256([0x80])
    let root_hash = keccak256(&[0x80]);
    assert_eq!(format!("0x{}", hex::encode(root_hash)), EMPTY_ROOT_HASH);

    // 8. Standard ERC-20 method selectors (first 4 bytes of Keccak-256)
    let transfer_hash = keccak256(b"transfer(address,uint256)");
    assert_eq!(&transfer_hash[0..4], &[0xa9, 0x05, 0x9c, 0xbb]);

    let transfer_from_hash = keccak256(b"transferFrom(address,address,uint256)");
    assert_eq!(&transfer_from_hash[0..4], &[0x23, 0xb8, 0x72, 0xdd]);

    let balance_of_hash = keccak256(b"balanceOf(address)");
    assert_eq!(&balance_of_hash[0..4], &[0x70, 0xa0, 0x82, 0x31]);

    let approve_hash = keccak256(b"approve(address,uint256)");
    assert_eq!(&approve_hash[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);

    let total_supply_hash = keccak256(b"totalSupply()");
    assert_eq!(&total_supply_hash[0..4], &[0x18, 0x16, 0x0d, 0xdd]);

    let name_hash = keccak256(b"name()");
    assert_eq!(&name_hash[0..4], &[0x06, 0xfd, 0xde, 0x03]);

    let symbol_hash = keccak256(b"symbol()");
    assert_eq!(&symbol_hash[0..4], &[0x95, 0xd8, 0x9b, 0x41]);

    let decimals_hash = keccak256(b"decimals()");
    assert_eq!(&decimals_hash[0..4], &[0x31, 0x3c, 0xe5, 0x67]);
}

#[test]
fn test_keccak256_streaming_and_rate_boundaries() {
    // Keccak-256 rate is 136 bytes. Verify boundary conditions:
    // 0, 1, 135 (rate - 1), 136 (exact rate), 137 (rate + 1), 271, 272 (2 * rate), 273, 500
    for len in [0, 1, 135, 136, 137, 271, 272, 273, 500] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let expected = keccak256(&data);

        // Verify streaming Keccak256 with chunks of various sizes
        for chunk_size in [1, 7, 33, 136, 200] {
            let mut hasher = Keccak256::new();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            let actual = hasher.finalize();
            assert_eq!(
                expected, actual,
                "streaming mismatch for length {len} with chunk size {chunk_size}"
            );
        }
    }
}

// ============================================================================
// Clean RLP Decoder Tests (RlpItem: Byte, Bytes, List)
// ============================================================================

#[test]
fn test_rlp_decode_byte_variant() {
    // Single bytes in [0x00, 0x7f] are decoded into RlpItem::Byte
    for b in [0x00, 0x01, 0x0f, 0x42, 0x7f] {
        let item = rlp_decode(&[b]).expect("valid single byte");
        assert_eq!(item, RlpItem::Byte(b));
        assert_eq!(item.as_bytes().unwrap(), &[b]);
        assert_eq!(item.as_u64().unwrap(), b as u64);
        assert_eq!(item.len(), 1);
        assert!(!item.is_empty());
    }
}

#[test]
fn test_rlp_decode_bytes_variant() {
    // 1. Empty string "" -> 0x80
    let empty_item = rlp_decode(&[0x80]).expect("valid empty string");
    assert_eq!(empty_item, RlpItem::Bytes(vec![]));
    assert_eq!(empty_item.as_bytes().unwrap(), b"");
    assert_eq!(empty_item.as_u64().unwrap(), 0);
    assert_eq!(empty_item.len(), 0);
    assert!(empty_item.is_empty());

    // 2. Single byte >= 0x80 encoded with 0x81 prefix
    let b80 = rlp_decode(&[0x81, 0x80]).expect("valid 0x80 byte");
    assert_eq!(b80, RlpItem::Bytes(vec![0x80]));
    assert_eq!(b80.as_bytes().unwrap(), &[0x80]);

    let bff = rlp_decode(&[0x81, 0xff]).expect("valid 0xff byte");
    assert_eq!(bff, RlpItem::Bytes(vec![0xff]));
    assert_eq!(bff.as_bytes().unwrap(), &[0xff]);

    // 3. Short strings "dog" and "cat"
    let dog_encoded = vec![0x83, b'd', b'o', b'g'];
    let dog = rlp_decode(&dog_encoded).expect("valid 'dog'");
    assert_eq!(dog, RlpItem::Bytes(b"dog".to_vec()));
    assert_eq!(dog.as_bytes().unwrap(), b"dog");

    let cat_encoded = vec![0x83, b'c', b'a', b't'];
    let cat = rlp_decode(&cat_encoded).expect("valid 'cat'");
    assert_eq!(cat, RlpItem::Bytes(b"cat".to_vec()));
    assert_eq!(cat.as_bytes().unwrap(), b"cat");

    // 4. Boundary 55-byte string (short string limit: 0x80 + 55 = 0xb7)
    let s55 = vec![0x61u8; 55];
    let mut enc55 = vec![0xb7];
    enc55.extend_from_slice(&s55);
    let item55 = rlp_decode(&enc55).expect("valid 55-byte string");
    assert_eq!(item55, RlpItem::Bytes(s55));

    // 5. Boundary 56-byte string (long string: 0xb8, length 0x38 = 56)
    let s56 = vec![0x62u8; 56];
    let mut enc56 = vec![0xb8, 0x38];
    enc56.extend_from_slice(&s56);
    let item56 = rlp_decode(&enc56).expect("valid 56-byte long string");
    assert_eq!(item56, RlpItem::Bytes(s56));

    // 6. 1024-byte multi-byte length string (0xb9, 0x04, 0x00)
    let s1024 = vec![0xee; 1024];
    let mut enc1024 = vec![0xb9, 0x04, 0x00];
    enc1024.extend_from_slice(&s1024);
    let item1024 = rlp_decode(&enc1024).expect("valid 1024-byte string");
    assert_eq!(item1024, RlpItem::Bytes(s1024));

    // 7. Integers encoded in RLP
    // 15 -> [0x0f] (Byte)
    assert_eq!(rlp_decode(&[0x0f]).unwrap().as_u64().unwrap(), 15);
    // 1000 -> [0x82, 0x03, 0xe8] (Bytes)
    assert_eq!(
        rlp_decode(&[0x82, 0x03, 0xe8]).unwrap().as_u64().unwrap(),
        1000
    );
    // 1024 -> [0x82, 0x04, 0x00]
    assert_eq!(
        rlp_decode(&[0x82, 0x04, 0x00]).unwrap().as_u64().unwrap(),
        1024
    );
}

#[test]
fn test_rlp_decode_list_variant() {
    // 1. Empty list [] -> 0xc0
    let empty_list = rlp_decode(&[0xc0]).expect("valid empty list");
    assert_eq!(empty_list, RlpItem::List(vec![]));
    assert_eq!(empty_list.as_list().unwrap().len(), 0);
    assert!(empty_list.is_empty());

    // 2. Nested list [[]] -> [0xc1, 0xc0]
    let nested = rlp_decode(&[0xc1, 0xc0]).expect("valid nested list");
    assert_eq!(nested, RlpItem::List(vec![RlpItem::List(vec![])]));
    assert_eq!(nested.as_list().unwrap().len(), 1);
    assert_eq!(nested.at(0).unwrap().as_list().unwrap().len(), 0);

    // 3. List of strings: ["cat", "dog"] -> [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
    let cat_dog_raw = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
    let cat_dog = rlp_decode(&cat_dog_raw).expect("valid ['cat', 'dog']");
    assert_eq!(
        cat_dog,
        RlpItem::List(vec![
            RlpItem::Bytes(b"cat".to_vec()),
            RlpItem::Bytes(b"dog".to_vec()),
        ])
    );
    assert_eq!(cat_dog.at(0).unwrap().as_bytes().unwrap(), b"cat");
    assert_eq!(cat_dog.at(1).unwrap().as_bytes().unwrap(), b"dog");

    // 4. Complex nested list: [[], [[]], [[], [[]]]]
    // yellow paper: [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
    let complex_raw = vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0];
    let complex = rlp_decode(&complex_raw).expect("valid complex nested list");
    assert_eq!(complex.as_list().unwrap().len(), 3);
    assert_eq!(complex.at(0).unwrap(), &RlpItem::List(vec![]));
    assert_eq!(
        complex.at(1).unwrap(),
        &RlpItem::List(vec![RlpItem::List(vec![])])
    );

    // 5. rlp_encode roundtrip
    assert_eq!(rlp_encode(&complex), complex_raw);
}

#[test]
fn test_rlp_decode_non_canonical_and_error_rejections() {
    // 1. Single byte < 0x80 encoded with 0x81 prefix is non-canonical
    assert!(rlp_decode(&[0x81, 0x05]).is_err());
    assert!(rlp_decode(&[0x81, 0x7f]).is_err());

    // 2. Short string (< 56 bytes) encoded with long header 0xb8 is non-canonical
    assert!(rlp_decode(&[0xb8, 0x04, 1, 2, 3, 4]).is_err());

    // 3. Leading zero in string length field is non-canonical
    assert!(rlp_decode(&[0xb8, 0x00, 0x38]).is_err());

    // 4. Short list encoded with long list header 0xf8 is non-canonical
    assert!(rlp_decode(&[0xf8, 0x02, 0xc0, 0xc0]).is_err());

    // 5. Leading zero in list length field is non-canonical
    assert!(rlp_decode(&[0xf8, 0x00, 0x38]).is_err());

    // 6. Integer with non-canonical leading zero
    let item_leading_zero = rlp_decode(&[0x82, 0x00, 0x2a]).unwrap();
    assert!(item_leading_zero.as_u64().is_err());

    // 7. Trailing unparsed bytes after valid item
    assert!(rlp_decode(&[0x80, 0x00]).is_err());
    assert!(rlp_decode(&[0x05, 0x06]).is_err());

    // 8. Unexpected EOF / truncated payload
    assert!(rlp_decode(&[]).is_err());
    assert!(rlp_decode(&[0x85, 0x01, 0x02]).is_err());
    assert!(rlp_decode(&[0xc5, 0x01, 0x02]).is_err());
}

// ============================================================================
// EIP-155 Legacy Transaction Parser Tests
// ============================================================================

#[test]
fn test_eip155_legacy_transaction_official_vector() {
    // Official Ethereum EIP-155 test vector:
    // [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw = hex::decode(hex_raw).expect("valid hex");

    // 1. Parse using parse_legacy_transaction
    let tx = parse_legacy_transaction(&raw).expect("must parse legacy transaction");

    // 2. Verify all decoded fields: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.gas_price, 20_000_000_000); // 20 Gwei = 0x04a817c800
    assert_eq!(tx.gas_limit, 21_000); // 0x5208
    let expected_to = hex::decode("3535353535353535353535353535353535353535").unwrap();
    assert_eq!(tx.to, Some(expected_to.as_slice().try_into().unwrap()));
    assert_eq!(tx.value, 1_000_000_000_000_000_000); // 1 ETH = 0x0de0b6b3a7640000
    assert_eq!(tx.data, Vec::<u8>::new()); // 0x80 -> empty bytes
    assert_eq!(tx.v, 37); // chainId = 1, recoveryId = 0 (37 = 1 * 2 + 35)
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.recovery_id(), 0);

    let expected_r =
        hex::decode("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276").unwrap();
    assert_eq!(tx.r.as_slice(), expected_r.as_slice());

    let expected_s =
        hex::decode("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").unwrap();
    assert_eq!(tx.s.as_slice(), expected_s.as_slice());

    // 3. Verify official EIP-155 signing hash
    let sighash = tx.signing_hash();
    assert_eq!(
        hex::encode(sighash),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );

    // 4. Verify tx hash matches keccak256(raw)
    let tx_hash = tx.compute_hash();
    assert_eq!(tx_hash, keccak256(&raw));

    // 5. Re-encoding matches original wire bytes exactly
    assert_eq!(tx.encode(), raw);

    // 6. Parse via top-level parse_raw_transaction
    let decoded_generic = parse_raw_transaction(&raw).expect("must parse raw tx");
    match decoded_generic {
        DecodedTransaction::Legacy(t) => assert_eq!(t, tx),
        _ => panic!("expected legacy transaction"),
    }
}

#[test]
fn test_legacy_contract_creation_and_unprotected() {
    // Contract creation legacy transaction (to: None, data: init bytecode)
    let init_code = vec![0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15];
    let tx = LegacyTransaction {
        nonce: 0,
        gas_price: 2_500_000_000,
        gas_limit: 150_000,
        to: None,
        value: 0,
        data: init_code.clone(),
        v: 11549, // Stellereum chain_id 5757: 5757 * 2 + 35 = 11549
        r: [0xaa; 32],
        s: [0xbb; 32],
        chain_id: Some(CHAIN_ID),
    };

    let encoded = tx.encode();
    let parsed = parse_legacy_transaction(&encoded).expect("parse contract creation legacy tx");
    assert_eq!(parsed.nonce, 0);
    assert_eq!(parsed.gas_price, 2_500_000_000);
    assert_eq!(parsed.gas_limit, 150_000);
    assert_eq!(parsed.to, None);
    assert_eq!(parsed.value, 0);
    assert_eq!(parsed.data, init_code);
    assert_eq!(parsed.v, 11549);
    assert_eq!(parsed.chain_id, Some(5757));
    assert_eq!(parsed.recovery_id(), 0);
    assert_eq!(parsed.r, [0xaa; 32]);
    assert_eq!(parsed.s, [0xbb; 32]);
    assert_eq!(parsed.encode(), encoded);

    // Pre-EIP-155 legacy transaction (v = 27, chain_id = None)
    let mut unprotected_tx = tx;
    unprotected_tx.v = 27;
    unprotected_tx.chain_id = None;
    let enc_unprotected = unprotected_tx.encode();
    let parsed_unprotected =
        parse_legacy_transaction(&enc_unprotected).expect("parse unprotected legacy tx");
    assert_eq!(parsed_unprotected.v, 27);
    assert_eq!(parsed_unprotected.chain_id, None);
    assert_eq!(parsed_unprotected.recovery_id(), 0);
}

// ============================================================================
// EIP-1559 Type 2 Envelope Transaction Parser Tests
// ============================================================================

#[test]
fn test_eip1559_type2_envelope_parsing_empty_access_list() {
    // EIP-1559 envelope: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])
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

    let raw_envelope = tx.encode();
    assert_eq!(
        raw_envelope[0], 0x02,
        "EIP-1559 envelope must start with 0x02 type byte"
    );

    // 1. Parse via parse_eip1559_envelope
    let parsed = parse_eip1559_envelope(&raw_envelope).expect("must parse EIP-1559 envelope");

    // 2. Verify all decoded fields
    assert_eq!(parsed.chain_id, 5757);
    assert_eq!(parsed.nonce, 42);
    assert_eq!(parsed.max_priority_fee_per_gas, 1_500_000_000);
    assert_eq!(parsed.max_fee_per_gas, 35_000_000_000);
    assert_eq!(parsed.gas_limit, 45_000);
    assert_eq!(parsed.to, Some([0x77; 20]));
    assert_eq!(parsed.value, 500_000_000_000_000_000);
    assert_eq!(parsed.data, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(parsed.access_list.len(), 0);
    assert_eq!(parsed.v, 1);
    assert_eq!(parsed.y_parity, 1);
    assert_eq!(parsed.r, [0x33; 32]);
    assert_eq!(parsed.s, [0x44; 32]);

    // 3. Re-encode matches original envelope bytes
    assert_eq!(parsed.encode(), raw_envelope);

    // 4. Compute hash is keccak256(0x02 || rlp_payload)
    assert_eq!(parsed.compute_hash(), keccak256(&raw_envelope));

    // 5. Signing data starts with 0x02 and has 9 elements (no v, r, s)
    let sig_data = parsed.signing_data();
    assert_eq!(sig_data[0], 0x02);
    let sig_item = rlp_decode(&sig_data[1..]).expect("valid signing rlp");
    assert_eq!(sig_item.as_list().unwrap().len(), 9);

    // 6. Parse via top-level parse_raw_transaction
    let generic = parse_raw_transaction(&raw_envelope).expect("parse raw tx generic");
    match generic {
        DecodedTransaction::Eip1559(t) => assert_eq!(t, tx),
        _ => panic!("expected EIP-1559 envelope"),
    }
}

#[test]
fn test_eip1559_type2_envelope_parsing_with_access_list() {
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
        nonce: 10,
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

    let raw = tx.encode();
    let parsed = parse_eip1559_transaction(&raw).expect("parse EIP-1559 with access list");

    assert_eq!(parsed.to, None);
    assert_eq!(parsed.access_list.len(), 2);
    assert_eq!(parsed.access_list[0].address, [0x11; 20]);
    assert_eq!(parsed.access_list[0].storage_keys.len(), 2);
    assert_eq!(parsed.access_list[0].storage_keys[0], [0xaa; 32]);
    assert_eq!(parsed.access_list[0].storage_keys[1], [0xbb; 32]);
    assert_eq!(parsed.access_list[1].address, [0x22; 20]);
    assert_eq!(parsed.access_list[1].storage_keys.len(), 0);
    assert_eq!(parsed.v, 0);
    assert_eq!(parsed.y_parity, 0);
    assert_eq!(parsed.r, [0x55; 32]);
    assert_eq!(parsed.s, [0x66; 32]);

    assert_eq!(parsed.encode(), raw);
}

#[test]
fn test_eip1559_envelope_error_rejections() {
    // 1. Invalid transaction type prefix (0x01 instead of 0x02)
    assert!(parse_eip1559_envelope(&[0x01, 0xc0]).is_err());

    // 2. Legacy prefix (0xc0) passed to EIP-1559 parser
    assert!(parse_eip1559_envelope(&[0xc0]).is_err());

    // 3. Empty buffer
    assert!(parse_eip1559_envelope(&[]).is_err());

    // 4. Truncated envelope (only 0x02 byte with no payload)
    assert!(parse_eip1559_envelope(&[0x02]).is_err());

    // 5. Envelope with invalid / truncated RLP payload
    assert!(parse_eip1559_envelope(&[0x02, 0xf8, 0x10, 0x01]).is_err());
}

// ============================================================================
// ERC-20 Calldata Emulation & ABI Encoding / Decoding Tests
// ============================================================================

#[test]
fn test_erc20_abi_string_encoding_and_decoding() {
    // 1. "Stellereum"
    let enc_name = abi_encode_string("Stellereum");
    assert!(enc_name.starts_with("0x"));
    let dec_name = abi_decode_string(&enc_name).expect("decode 'Stellereum'");
    assert_eq!(dec_name, "Stellereum");

    // 2. "STELL"
    let enc_symbol = abi_encode_string("STELL");
    assert!(enc_symbol.starts_with("0x"));
    let dec_symbol = abi_decode_string(&enc_symbol).expect("decode 'STELL'");
    assert_eq!(dec_symbol, "STELL");

    // 3. Empty string
    let enc_empty = abi_encode_string("");
    let dec_empty = abi_decode_string(&enc_empty).expect("decode empty string");
    assert_eq!(dec_empty, "");

    // 4. Long string spanning multiple 32-byte chunks
    let long_str = "Stellereum Native Token on L1 Sub-Second Quantum Finality Chain";
    let enc_long = abi_encode_string(long_str);
    let dec_long = abi_decode_string(&enc_long).expect("decode long string");
    assert_eq!(dec_long, long_str);

    // 5. Bytes32 fallback decoding (e.g. legacy tokens returning bytes32 symbol)
    let mut b32 = [0u8; 32];
    b32[0..5].copy_from_slice(b"STELL");
    let b32_hex = format!("0x{}", hex::encode(b32));
    assert_eq!(abi_decode_string(&b32_hex).unwrap(), "STELL");
}

#[test]
fn test_erc20_abi_uint_encoding_and_decoding() {
    // 1. uint8 decimals (18)
    let enc_dec = abi_encode_u8(18);
    assert_eq!(
        enc_dec,
        "0x0000000000000000000000000000000000000000000000000000000000000012"
    );
    let dec_dec = abi_decode_u8(&enc_dec).expect("decode decimals 18");
    assert_eq!(dec_dec, 18);

    // 2. uint8 boundary values
    assert_eq!(abi_decode_u8(&abi_encode_u8(0)).unwrap(), 0);
    assert_eq!(abi_decode_u8(&abi_encode_u8(255)).unwrap(), 255);

    // 3. uint128 total supply (1_000_000_000_000_000_000_000_000_000)
    let total_supply = DEFAULT_TOTAL_SUPPLY;
    let enc_supply = abi_encode_u128(total_supply);
    assert!(enc_supply.starts_with("0x"));
    let dec_supply = abi_decode_u128(&enc_supply).expect("decode total supply");
    assert_eq!(dec_supply, total_supply);

    // 4. uint128 balance zero
    assert_eq!(abi_decode_u128(&abi_encode_u128(0)).unwrap(), 0);

    // 5. uint256 big-endian helper
    let u256_val = [0x55u8; 32];
    let enc_256 = abi_encode_u256_be(&u256_val);
    assert_eq!(abi_decode_u256_be(&enc_256).unwrap(), u256_val);
}

#[test]
fn test_erc20_name_call() {
    let adapter = EvmAdapter::new();

    // 1. Exact selector 0x06fdde03 via emulate_erc20_call
    let res = adapter.emulate_erc20_call("0x06fdde03");
    let name = abi_decode_string(&res).expect("name string");
    assert_eq!(name, "Stellereum");
    assert_eq!(name, DEFAULT_TOKEN_NAME);

    // 2. Uppercase hex 0x06FDDE03
    let res_upper = adapter.emulate_erc20_call("0x06FDDE03");
    assert_eq!(abi_decode_string(&res_upper).unwrap(), "Stellereum");

    // 3. Bare hex without 0x prefix
    let res_bare = adapter.emulate_erc20_call(SELECTOR_NAME);
    assert_eq!(abi_decode_string(&res_bare).unwrap(), "Stellereum");

    // 4. Through eth_call with standard call object [{ to: ..., data: "0x06fdde03" }, "latest"]
    let call_obj = json!([{
        "to": "0x1111111111111111111111111111111111111111",
        "data": SELECTOR_NAME_HEX
    }, "latest"]);
    let eth_call_res = adapter.handle_eth_call(&call_obj).expect("eth_call name");
    let val_str = eth_call_res.as_str().expect("must be string");
    assert_eq!(abi_decode_string(val_str).unwrap(), "Stellereum");

    // 5. Through eth_call with "input" alias
    let call_input = json!([{
        "to": "0x1111111111111111111111111111111111111111",
        "input": SELECTOR_NAME_HEX
    }]);
    let eth_call_input = adapter
        .handle_eth_call(&call_input)
        .expect("eth_call input name");
    assert_eq!(
        abi_decode_string(eth_call_input.as_str().unwrap()).unwrap(),
        "Stellereum"
    );

    // 6. Direct module-level function eth_call
    let global_res = eth_call(&json!([{ "data": SELECTOR_NAME_HEX }])).expect("global eth_call");
    assert_eq!(
        abi_decode_string(global_res.as_str().unwrap()).unwrap(),
        "Stellereum"
    );

    // 7. Custom token name configured on adapter
    let custom_adapter = EvmAdapter::new().with_token_name("CustomStell");
    let custom_res = custom_adapter.emulate_erc20_call(SELECTOR_NAME_HEX);
    assert_eq!(abi_decode_string(&custom_res).unwrap(), "CustomStell");
}

#[test]
fn test_erc20_symbol_call() {
    let adapter = EvmAdapter::new();

    // 1. Selector 0x95d89b41
    let res = adapter.emulate_erc20_call("0x95d89b41");
    let symbol = abi_decode_string(&res).expect("symbol string");
    assert_eq!(symbol, "STELL");
    assert_eq!(symbol, DEFAULT_TOKEN_SYMBOL);

    // 2. Uppercase selector
    let res_upper = adapter.emulate_erc20_call("0x95D89B41");
    assert_eq!(abi_decode_string(&res_upper).unwrap(), "STELL");

    // 3. Bare selector
    let res_bare = adapter.emulate_erc20_call(SELECTOR_SYMBOL);
    assert_eq!(abi_decode_string(&res_bare).unwrap(), "STELL");

    // 4. Via dispatch("eth_call", ...)
    let dispatch_res = adapter
        .dispatch("eth_call", &json!([{ "data": SELECTOR_SYMBOL_HEX }]))
        .expect("dispatch eth_call symbol");
    assert_eq!(
        abi_decode_string(dispatch_res.as_str().unwrap()).unwrap(),
        "STELL"
    );

    // 5. Custom symbol
    let custom_adapter = EvmAdapter::new().with_token_symbol("XSTELL");
    let custom_res = custom_adapter.emulate_erc20_call(SELECTOR_SYMBOL_HEX);
    assert_eq!(abi_decode_string(&custom_res).unwrap(), "XSTELL");
}

#[test]
fn test_erc20_decimals_call() {
    let adapter = EvmAdapter::new();

    // 1. Selector 0x313ce567
    let res = adapter.emulate_erc20_call("0x313ce567");
    // Verify 32-byte left-padded hex quantity
    assert_eq!(
        res,
        "0x0000000000000000000000000000000000000000000000000000000000000012"
    );
    let decimals = abi_decode_u8(&res).expect("decimals u8");
    assert_eq!(decimals, 18);
    assert_eq!(decimals, DEFAULT_TOKEN_DECIMALS);

    // 2. Uppercase and bare selector
    let res_upper = adapter.emulate_erc20_call("0x313CE567");
    assert_eq!(abi_decode_u8(&res_upper).unwrap(), 18);
    let res_bare = adapter.emulate_erc20_call(SELECTOR_DECIMALS);
    assert_eq!(abi_decode_u8(&res_bare).unwrap(), 18);

    // 3. Via dispatch("eth_call", ...)
    let dispatch_res = adapter
        .dispatch("eth_call", &json!([{ "data": SELECTOR_DECIMALS_HEX }]))
        .expect("dispatch decimals");
    assert_eq!(abi_decode_u8(dispatch_res.as_str().unwrap()).unwrap(), 18);

    // 4. Custom decimals
    let custom_adapter = EvmAdapter::new().with_token_decimals(9);
    let custom_res = custom_adapter.emulate_erc20_call(SELECTOR_DECIMALS_HEX);
    assert_eq!(abi_decode_u8(&custom_res).unwrap(), 9);
}

#[test]
fn test_erc20_total_supply_call() {
    let adapter = EvmAdapter::new();

    // 1. Selector 0x18160ddd
    let res = adapter.emulate_erc20_call("0x18160ddd");
    let supply = abi_decode_u128(&res).expect("total supply u128");
    assert_eq!(supply, DEFAULT_TOTAL_SUPPLY);
    assert_eq!(supply, 1_000_000_000_000_000_000_000_000_000);

    // 2. Uppercase and bare selector
    let res_upper = adapter.emulate_erc20_call("0x18160DDD");
    assert_eq!(abi_decode_u128(&res_upper).unwrap(), DEFAULT_TOTAL_SUPPLY);
    let res_bare = adapter.emulate_erc20_call(SELECTOR_TOTAL_SUPPLY);
    assert_eq!(abi_decode_u128(&res_bare).unwrap(), DEFAULT_TOTAL_SUPPLY);

    // 3. Via dispatch("eth_call", ...)
    let dispatch_res = adapter
        .dispatch("eth_call", &json!([{ "data": SELECTOR_TOTAL_SUPPLY_HEX }]))
        .expect("dispatch total supply");
    assert_eq!(
        abi_decode_u128(dispatch_res.as_str().unwrap()).unwrap(),
        DEFAULT_TOTAL_SUPPLY
    );

    // 4. Custom total supply
    let custom_supply = 21_000_000_000_000_000_000_000_000u128;
    let custom_adapter = EvmAdapter::new().with_total_supply(custom_supply);
    let custom_res = custom_adapter.emulate_erc20_call(SELECTOR_TOTAL_SUPPLY_HEX);
    assert_eq!(abi_decode_u128(&custom_res).unwrap(), custom_supply);
}

#[test]
fn test_erc20_balance_of_call() {
    let adapter = EvmAdapter::new();

    // 1. Unset address returns default 0
    let calldata_alice =
        "0x70a082310000000000000000000000001111111111111111111111111111111111111111";
    let res_zero = adapter.emulate_erc20_call(calldata_alice);
    let bal_zero = abi_decode_u128(&res_zero).expect("balance u128");
    assert_eq!(bal_zero, 0);

    // 2. Set balance in Wei on adapter (e.g. 500 STELL in Wei = 500 * 10^18)
    let balance_wei = 500_000_000_000_000_000_000u128;
    adapter.set_balance("0x1111111111111111111111111111111111111111", balance_wei);

    let res_alice = adapter.emulate_erc20_call(calldata_alice);
    let bal_alice = abi_decode_u128(&res_alice).expect("balance alice");
    assert_eq!(bal_alice, balance_wei);

    // 3. Call via eth_call object parameter
    let call_obj = json!([{
        "to": "0x9999999999999999999999999999999999999999",
        "data": calldata_alice
    }]);
    let eth_call_res = adapter
        .handle_eth_call(&call_obj)
        .expect("eth_call balanceOf");
    assert_eq!(
        abi_decode_u128(eth_call_res.as_str().unwrap()).unwrap(),
        balance_wei
    );

    // 4. Bob with 32-byte Stellereum address format
    let bob_evm = "0x2222222222222222222222222222222222222222";
    let bob_stell = "0x0000000000000000000000002222222222222222222222222222222222222222";
    let bob_balance = 1_250_000_000_000_000_000_000u128; // 1250 STELL
    adapter.set_balance(bob_stell, bob_balance);

    // Query with standard 20-byte calldata
    let calldata_bob = format!("0x70a08231000000000000000000000000{}", &bob_evm[2..]);
    let res_bob = adapter.emulate_erc20_call(&calldata_bob);
    assert_eq!(abi_decode_u128(&res_bob).unwrap(), bob_balance);

    // Query with 32-byte calldata
    let calldata_bob_32 = format!("0x70a08231{}", &bob_stell[2..]);
    let res_bob_32 = adapter.emulate_erc20_call(&calldata_bob_32);
    assert_eq!(abi_decode_u128(&res_bob_32).unwrap(), bob_balance);

    // 5. Custom default balance
    let custom_adapter = EvmAdapter::new().with_default_balance(42);
    let res_default = custom_adapter.emulate_erc20_call(
        "0x70a082310000000000000000000000003333333333333333333333333333333333333333",
    );
    assert_eq!(abi_decode_u128(&res_default).unwrap(), 42);
}

#[tokio::test]
async fn test_erc20_balance_of_with_state_engine() {
    let engine = Arc::new(InMemoryStateEngine::new());

    // Create an account with balance = 7_000_000_000 nano-STELL (7 STELL)
    let evm_addr_bytes = [0x55u8; 20];
    let mut stell_addr_bytes = [0u8; 32];
    stell_addr_bytes[12..32].copy_from_slice(&evm_addr_bytes);

    let initial_nano = 7_000_000_000u64; // 7 STELL
    engine
        .update_account(AccountState::new(stell_addr_bytes, initial_nano))
        .await;

    // Verify account exists in engine
    let acct = engine
        .get_account(&stell_addr_bytes)
        .await
        .expect("account exists");
    assert_eq!(acct.balance, initial_nano);

    // Construct balanceOf calldata for this account
    let calldata = format!(
        "0x70a08231000000000000000000000000{}",
        hex::encode(evm_addr_bytes)
    );

    // 1. Direct handle_eth_call_with_engine
    let adapter = EvmAdapter::new();
    let res = adapter
        .handle_eth_call_with_engine(&engine, &json!([{ "data": calldata }]))
        .await
        .expect("eth_call with engine");

    let wei_result = abi_decode_u128(res.as_str().unwrap()).expect("decode wei");
    // 7 nano-STELL * 10^9 = 7 * 10^18 Wei
    let expected_wei = 7_000_000_000_000_000_000u128;
    assert_eq!(wei_result, expected_wei);

    // 2. Adapter configured with_engine
    let engine_adapter = EvmAdapter::new().with_engine(engine.clone());
    let res_eng = engine_adapter.emulate_erc20_call(&calldata);
    assert_eq!(abi_decode_u128(&res_eng).unwrap(), expected_wei);

    // 3. Dispatch through dispatch_with_engine
    let disp_res = engine_adapter
        .dispatch_with_engine(&engine, "eth_call", &json!([{ "data": calldata }]))
        .await
        .expect("dispatch_with_engine eth_call");
    assert_eq!(
        abi_decode_u128(disp_res.as_str().unwrap()).unwrap(),
        expected_wei
    );
}

#[test]
fn test_erc20_unrecognized_selectors_and_edge_cases() {
    let adapter = EvmAdapter::new();

    // 1. ERC-20 mutation simulations (transfer, approve) return true (F-03 fix)
    let transfer_data = "0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001";
    assert_eq!(
        adapter.emulate_erc20_call(transfer_data),
        abi_encode_bool(true)
    );

    let approve_data = "0x095ea7b300000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001";
    assert_eq!(
        adapter.emulate_erc20_call(approve_data),
        abi_encode_bool(true)
    );

    // 2. Random unknown selector 0xdeadbeef
    assert_eq!(adapter.emulate_erc20_call("0xdeadbeef"), "0x");

    // 3. Calldata shorter than 4 bytes (8 hex characters) returns "0x"
    assert_eq!(adapter.emulate_erc20_call("0x"), "0x");
    assert_eq!(adapter.emulate_erc20_call(""), "0x");
    assert_eq!(adapter.emulate_erc20_call("0x12"), "0x");
    assert_eq!(adapter.emulate_erc20_call("0x123456"), "0x");

    // 4. Missing / null / empty parameters in handle_eth_call
    assert_eq!(adapter.handle_eth_call(&Value::Null).unwrap(), json!("0x"));
    assert_eq!(adapter.handle_eth_call(&json!([])).unwrap(), json!("0x"));
    assert_eq!(adapter.handle_eth_call(&json!([{}])).unwrap(), json!("0x"));
    assert_eq!(
        adapter.handle_eth_call(&json!([{ "data": "0x" }])).unwrap(),
        json!("0x")
    );
    assert_eq!(
        adapter.handle_eth_call(&json!([{ "data": "" }])).unwrap(),
        json!("0x")
    );
}

#[test]
fn test_erc20_calls_through_jsonrpc_string_and_batch() {
    let adapter = EvmAdapter::new();
    adapter.set_balance(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        999_000_000_000_000_000_000,
    );

    // 1. Single raw JSON string request
    let raw_req = r#"{
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": "0x0000000000000000000000000000000000000001", "data": "0x06fdde03"}],
        "id": 100
    }"#;
    let raw_resp = adapter.handle_raw_json(raw_req);
    let resp: JsonRpcResponse<String> = serde_json::from_str(&raw_resp).unwrap();
    assert_eq!(resp.id, json!(100));
    let name_str = resp.result.unwrap();
    assert_eq!(abi_decode_string(&name_str).unwrap(), "Stellereum");

    // 2. Batch request containing all 5 ERC-20 methods and an unknown selector
    let batch_req = r#"[
        {"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x06fdde03"}],"id":1},
        {"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x95d89b41"}],"id":2},
        {"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x313ce567"}],"id":3},
        {"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x18160ddd"}],"id":4},
        {"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x70a08231000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"id":5},
        {"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0xdeadbeef"}],"id":6}
    ]"#;

    let batch_resp_raw = adapter.handle_raw_json(batch_req);
    let responses: Vec<JsonRpcResponse<String>> = serde_json::from_str(&batch_resp_raw).unwrap();
    assert_eq!(responses.len(), 6);

    // id 1: name -> "Stellereum"
    assert_eq!(
        abi_decode_string(&responses[0].result.clone().unwrap()).unwrap(),
        "Stellereum"
    );
    // id 2: symbol -> "STELL"
    assert_eq!(
        abi_decode_string(&responses[1].result.clone().unwrap()).unwrap(),
        "STELL"
    );
    // id 3: decimals -> 18
    assert_eq!(
        abi_decode_u8(&responses[2].result.clone().unwrap()).unwrap(),
        18
    );
    // id 4: totalSupply -> 10^27
    assert_eq!(
        abi_decode_u128(&responses[3].result.clone().unwrap()).unwrap(),
        DEFAULT_TOTAL_SUPPLY
    );
    // id 5: balanceOf -> 999 * 10^18
    assert_eq!(
        abi_decode_u128(&responses[4].result.clone().unwrap()).unwrap(),
        999_000_000_000_000_000_000
    );
    // id 6: unknown -> "0x"
    assert_eq!(responses[5].result.clone().unwrap(), "0x");
}

// ============================================================================
// MetaMask Filter Polling Tests (eth_new*Filter, eth_getFilter*, eth_uninstallFilter)
// ============================================================================

#[test]
fn test_eth_new_block_filter_lifecycle() {
    let adapter = EvmAdapter::new();

    // 1. eth_newBlockFilter returns a valid hex filter ID
    let filter_id = adapter.eth_new_block_filter();
    assert!(filter_id.starts_with("0x"));

    // 2. eth_getFilterChanges initially returns empty array []
    let init_changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("initial changes");
    assert_eq!(init_changes, json!([]));

    // 3. Notify two new block hashes
    let block1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let block2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    adapter.notify_block(block1);
    adapter.notify_block(block2);

    // 4. eth_getFilterChanges returns the new block hashes
    let changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("polled block changes");
    assert_eq!(changes, json!([block1, block2]));

    // 5. Subsequent poll immediately returns empty array [] (changes consumed)
    let empty_changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("subsequent empty changes");
    assert_eq!(empty_changes, json!([]));

    // 6. Notify a third block -> next poll returns only the new one
    let block3 = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    adapter.notify_block(block3);
    let third_changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("third change");
    assert_eq!(third_changes, json!([block3]));

    // 7. eth_getFilterLogs on block filter returns empty array []
    let logs = adapter
        .eth_get_filter_logs(&json!([filter_id.clone()]))
        .expect("block filter logs");
    assert_eq!(logs, json!([]));

    // 8. eth_uninstallFilter returns true
    let uninstalled = adapter
        .eth_uninstall_filter(&json!([filter_id.clone()]))
        .expect("uninstall filter");
    assert!(uninstalled);

    // 9. Subsequent eth_getFilterChanges on uninstalled filter returns error
    let err = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect_err("must error on uninstalled filter");
    assert_eq!(err.message, "filter not found");

    // 10. Subsequent eth_getFilterLogs on uninstalled filter returns error
    let err_logs = adapter
        .eth_get_filter_logs(&json!([filter_id.clone()]))
        .expect_err("must error on uninstalled filter");
    assert_eq!(err_logs.message, "filter not found");
}

#[test]
fn test_eth_new_pending_tx_filter_lifecycle() {
    let adapter = EvmAdapter::new();

    // 1. eth_newPendingTransactionFilter returns a filter ID
    let filter_id = adapter.eth_new_pending_transaction_filter();
    assert!(filter_id.starts_with("0x"));

    // 2. Initial poll returns []
    let init_changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("initial pending changes");
    assert_eq!(init_changes, json!([]));

    // 3. Notify pending transactions
    let tx1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let tx2 = "0x2222222222222222222222222222222222222222222222222222222222222222";
    adapter.notify_pending_tx(tx1);
    adapter.notify_pending_tx(tx2);

    // 4. Poll returns pending tx hashes
    let changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("polled tx changes");
    assert_eq!(changes, json!([tx1, tx2]));

    // 5. Subsequent poll returns []
    assert_eq!(
        adapter
            .eth_get_filter_changes(&json!([filter_id.clone()]))
            .unwrap(),
        json!([])
    );

    // 6. eth_getFilterLogs on pending tx filter returns []
    assert_eq!(
        adapter
            .eth_get_filter_logs(&json!([filter_id.clone()]))
            .unwrap(),
        json!([])
    );

    // 7. eth_uninstallFilter returns true
    assert!(adapter
        .eth_uninstall_filter(&json!([filter_id.clone()]))
        .unwrap());

    // 8. Polling uninstalled filter fails
    assert!(adapter.eth_get_filter_changes(&json!([filter_id])).is_err());
}

#[test]
fn test_eth_new_filter_logs_lifecycle() {
    let adapter = EvmAdapter::new();

    // 1. Register filter with address criteria
    let contract_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let filter_criteria = json!({
        "address": contract_addr,
        "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
    });

    let filter_id = adapter
        .eth_new_filter(&json!([filter_criteria]))
        .expect("create log filter");
    assert!(filter_id.starts_with("0x"));

    // 2. Initial poll returns []
    let init_changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("initial log changes");
    assert_eq!(init_changes, json!([]));

    // 3. Construct matching log
    let matching_log = EvmLog {
        address: contract_addr.to_string(),
        topics: vec![
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
        ],
        data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000".to_string(),
        block_number: Some("0x10".to_string()),
        transaction_hash: Some(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        ),
        transaction_index: Some("0x0".to_string()),
        block_hash: Some(
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        ),
        log_index: Some("0x0".to_string()),
        removed: false,
    };

    // 4. Construct non-matching log (different address)
    let non_matching_log = EvmLog {
        address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        topics: vec![
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
        ],
        data: "0x0".to_string(),
        block_number: Some("0x10".to_string()),
        transaction_hash: Some("0x9999".to_string()),
        transaction_index: Some("0x1".to_string()),
        block_hash: Some("0xabcdef".to_string()),
        log_index: Some("0x1".to_string()),
        removed: false,
    };

    // 5. Notify both logs
    adapter.notify_log(non_matching_log);
    adapter.notify_log(matching_log.clone());

    // 6. eth_getFilterChanges returns only the matching log
    let changes = adapter
        .eth_get_filter_changes(&json!([filter_id.clone()]))
        .expect("log changes");
    let changes_arr = changes.as_array().expect("array of logs");
    assert_eq!(changes_arr.len(), 1);
    assert_eq!(changes_arr[0]["address"], contract_addr);

    // 7. Subsequent poll returns []
    assert_eq!(
        adapter
            .eth_get_filter_changes(&json!([filter_id.clone()]))
            .unwrap(),
        json!([])
    );

    // 8. eth_getFilterLogs returns all accumulated matching logs
    let all_logs = adapter
        .eth_get_filter_logs(&json!([filter_id.clone()]))
        .expect("get_filter_logs");
    let all_arr = all_logs.as_array().expect("all logs array");
    assert_eq!(all_arr.len(), 1);
    assert_eq!(all_arr[0]["address"], contract_addr);

    // 9. Uninstall filter returns true
    assert!(adapter
        .eth_uninstall_filter(&json!([filter_id.clone()]))
        .unwrap());

    // 10. Polling uninstalled filter fails
    assert!(adapter.eth_get_filter_logs(&json!([filter_id])).is_err());
}

#[test]
fn test_filter_criteria_advanced_matching() {
    // 1. Multiple addresses filter
    let criteria_addrs = FilterCriteria {
        address: Some(FilterAddress::Multiple(vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ])),
        ..Default::default()
    };

    let log_addr1 = EvmLog {
        address: "0x1111111111111111111111111111111111111111".to_string(),
        topics: vec![],
        data: "0x".to_string(),
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        block_hash: None,
        log_index: None,
        removed: false,
    };
    let log_addr3 = EvmLog {
        address: "0x3333333333333333333333333333333333333333".to_string(),
        topics: vec![],
        data: "0x".to_string(),
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        block_hash: None,
        log_index: None,
        removed: false,
    };

    assert!(criteria_addrs.matches(&log_addr1));
    assert!(!criteria_addrs.matches(&log_addr3));

    // 2. Wildcard topic filter: [Some(transfer), None, Some(to_address)]
    let transfer_sig = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let recipient_topic = "0x0000000000000000000000009999999999999999999999999999999999999999";
    let criteria_wildcard = FilterCriteria {
        topics: Some(vec![
            Some(FilterTopic::Single(transfer_sig.to_string())),
            None, // Wildcard: matches any sender
            Some(FilterTopic::Single(recipient_topic.to_string())),
        ]),
        ..Default::default()
    };

    let log_transfer = EvmLog {
        address: "0xaaaa".to_string(),
        topics: vec![
            transfer_sig.to_string(),
            "0x0000000000000000000000001234567890123456789012345678901234567890".to_string(), // Any sender
            recipient_topic.to_string(),
        ],
        data: "0x".to_string(),
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        block_hash: None,
        log_index: None,
        removed: false,
    };

    let log_wrong_recipient = EvmLog {
        address: "0xaaaa".to_string(),
        topics: vec![
            transfer_sig.to_string(),
            "0x0000000000000000000000001234567890123456789012345678901234567890".to_string(),
            "0x0000000000000000000000008888888888888888888888888888888888888888".to_string(), // Wrong recipient
        ],
        data: "0x".to_string(),
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        block_hash: None,
        log_index: None,
        removed: false,
    };

    assert!(criteria_wildcard.matches(&log_transfer));
    assert!(!criteria_wildcard.matches(&log_wrong_recipient));

    // 3. Block range filtering (fromBlock = 10, toBlock = 20)
    let criteria_blocks = FilterCriteria {
        from_block: Some("0xa".to_string()), // 10
        to_block: Some("0x14".to_string()),  // 20
        ..Default::default()
    };

    let mut log_block = log_transfer.clone();
    log_block.block_number = Some("0xf".to_string()); // 15
    assert!(criteria_blocks.matches(&log_block));

    log_block.block_number = Some("0x5".to_string()); // 5 (< 10)
    assert!(!criteria_blocks.matches(&log_block));

    log_block.block_number = Some("0x19".to_string()); // 25 (> 20)
    assert!(!criteria_blocks.matches(&log_block));
}

#[test]
fn test_eth_uninstall_filter_behavior() {
    let adapter = EvmAdapter::new();

    // 1. Install multiple filters
    let id1 = adapter.eth_new_block_filter();
    let id2 = adapter.eth_new_pending_transaction_filter();
    let id3 = adapter.eth_new_filter(&json!([])).unwrap();

    // 2. Uninstall with array param ["0x..."]
    assert!(adapter.eth_uninstall_filter(&json!([id1.clone()])).unwrap());

    // 3. Uninstall with string param "0x..."
    assert!(adapter.eth_uninstall_filter(&json!(id2.clone())).unwrap());

    // 4. Uninstall with numeric param
    let num_id = parse_hex_u64(&id3).unwrap();
    assert!(adapter.eth_uninstall_filter(&json!([num_id])).unwrap());

    // 5. Calling uninstall on already uninstalled or non-existent ID returns true
    assert!(adapter.eth_uninstall_filter(&json!(["0x9999"])).unwrap());
    assert!(adapter.eth_uninstall_filter(&json!([9999])).unwrap());

    // 6. Direct module-level function eth_uninstall_filter
    let id_global = eth_new_block_filter();
    assert!(eth_uninstall_filter(&json!([id_global])).unwrap());
}

#[test]
fn test_filter_polling_through_jsonrpc_string_and_batch() {
    let adapter = EvmAdapter::new();

    // 1. Create block filter via handle_raw_json
    let req_create = r#"{"jsonrpc":"2.0","method":"eth_newBlockFilter","params":[],"id":1}"#;
    let resp_create_raw = adapter.handle_raw_json(req_create);
    let resp_create: JsonRpcResponse<String> = serde_json::from_str(&resp_create_raw).unwrap();
    assert_eq!(resp_create.id, json!(1));
    let filter_id = resp_create.result.unwrap();

    // 2. Notify block
    let block_hash = "0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef";
    adapter.notify_block(block_hash);

    // 3. Poll filter changes via handle_raw_json
    let req_poll = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_getFilterChanges","params":["{}"],"id":2}}"#,
        filter_id
    );
    let resp_poll_raw = adapter.handle_raw_json(&req_poll);
    let resp_poll: JsonRpcResponse<Vec<String>> = serde_json::from_str(&resp_poll_raw).unwrap();
    assert_eq!(resp_poll.id, json!(2));
    assert_eq!(resp_poll.result.unwrap(), vec![block_hash]);

    // 4. Uninstall filter via handle_raw_json
    let req_uninstall = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_uninstallFilter","params":["{}"],"id":3}}"#,
        filter_id
    );
    let resp_uninstall_raw = adapter.handle_raw_json(&req_uninstall);
    let resp_uninstall: JsonRpcResponse<bool> = serde_json::from_str(&resp_uninstall_raw).unwrap();
    assert_eq!(resp_uninstall.id, json!(3));
    assert!(resp_uninstall.result.unwrap());

    // 5. Subsequent poll fails with error code -32000
    let resp_poll_after = adapter.handle_raw_json(&req_poll);
    let resp_err: JsonRpcResponse<Value> = serde_json::from_str(&resp_poll_after).unwrap();
    assert!(resp_err.error.is_some());
    assert_eq!(resp_err.error.unwrap().message, "filter not found");
}

#[tokio::test]
async fn test_erc20_and_filters_through_rpc_layer() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(tokio::sync::RwLock::new(
        stellereum::mempool::Mempool::default(),
    ));

    // Fund test account on engine
    let user_evm = [0x77u8; 20];
    let mut user_stell = [0u8; 32];
    user_stell[12..32].copy_from_slice(&user_evm);
    engine
        .update_account(AccountState::new(user_stell, 12_000_000_000))
        .await; // 12 STELL

    let rpc_state = Arc::new(stellereum::rpc::RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "node1:test".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });

    // 1. eth_call name() through RPC
    let resp_name = rpc_state
        .call("eth_call", json!([{ "data": "0x06fdde03" }]))
        .await;
    let name_str = resp_name.as_str().unwrap().to_string();
    assert_eq!(abi_decode_string(&name_str).unwrap(), "Stellereum");

    // 2. eth_call symbol() through RPC
    let resp_symbol = rpc_state
        .call("eth_call", json!([{ "data": "0x95d89b41" }]))
        .await;
    let symbol_str = resp_symbol.as_str().unwrap().to_string();
    assert_eq!(abi_decode_string(&symbol_str).unwrap(), "STELL");

    // 3. eth_call decimals() through RPC
    let resp_dec = rpc_state
        .call("eth_call", json!([{ "data": "0x313ce567" }]))
        .await;
    let dec_str = resp_dec.as_str().unwrap().to_string();
    assert_eq!(abi_decode_u8(&dec_str).unwrap(), 18);

    // 4. eth_call totalSupply() through RPC
    let resp_supply = rpc_state
        .call("eth_call", json!([{ "data": "0x18160ddd" }]))
        .await;
    let supply_str = resp_supply.as_str().unwrap().to_string();
    assert_eq!(abi_decode_u128(&supply_str).unwrap(), DEFAULT_TOTAL_SUPPLY);

    // 5. eth_call balanceOf() through RPC querying engine balance
    let calldata_bal = format!(
        "0x70a08231000000000000000000000000{}",
        hex::encode(user_evm)
    );
    let resp_bal = rpc_state
        .call("eth_call", json!([{ "data": calldata_bal }]))
        .await;
    let bal_str = resp_bal.as_str().unwrap().to_string();
    // 12 nano-STELL = 12 * 10^18 Wei
    assert_eq!(
        abi_decode_u128(&bal_str).unwrap(),
        12_000_000_000_000_000_000
    );

    // 6. eth_call with unknown selector through RPC returns "0x"
    let resp_unknown = rpc_state
        .call("eth_call", json!([{ "data": "0xdeadbeef" }]))
        .await;
    assert_eq!(resp_unknown, json!("0x"));

    // 7. Filter polling through RPC
    let resp_bf = rpc_state.call("eth_newBlockFilter", json!([])).await;
    let filter_id = resp_bf.as_str().unwrap().to_string();

    let resp_un = rpc_state
        .call("eth_uninstallFilter", json!([filter_id]))
        .await;
    assert_eq!(resp_un, json!(true));
}

#[tokio::test]
async fn test_evm_adapter_module_level_helpers() {
    // 1. extract_calldata
    let call_val = json!([{ "data": "0x06fdde03" }]);
    let calldata = extract_calldata(&call_val);
    assert_eq!(calldata, Some("0x06fdde03"));

    // 2. extract_address_from_calldata & normalize_address
    let addr = extract_address_from_calldata(
        "0000000000000000000000001111111111111111111111111111111111111111",
    )
    .unwrap();
    assert_eq!(addr, "0x1111111111111111111111111111111111111111");
    assert_eq!(
        normalize_address("1111111111111111111111111111111111111111"),
        "0x1111111111111111111111111111111111111111"
    );

    // 3. extract_filter_id & normalize_filter_id
    let id_extracted = extract_filter_id(&json!(["0x0a"])).unwrap();
    assert_eq!(id_extracted, "0xa");
    assert_eq!(normalize_filter_id("0x00a"), "0xa");

    // 4. Gas & fee helpers
    assert_eq!(eth_gas_price(), "0x3eb2788000");
    assert_eq!(eth_max_priority_fee_per_gas(), "0x3b9aca00");
    assert_eq!(eth_estimate_gas(&json!([])).unwrap(), "0x445c0");
    assert!(eth_fee_history(&json!([1, "latest"])).is_ok());

    // 5. Module-level filter functions
    let bf_id = eth_new_block_filter();
    assert!(bf_id.starts_with("0x"));
    notify_block("0xaaaa");
    let changes = eth_get_filter_changes(&json!([bf_id.clone()])).unwrap();
    assert!(changes.as_array().unwrap().contains(&json!("0xaaaa")));

    let ptx_id = eth_new_pending_transaction_filter();
    notify_pending_tx("0xbbbb");
    let tx_changes = eth_get_filter_changes(&json!([ptx_id.clone()])).unwrap();
    assert!(tx_changes.as_array().unwrap().contains(&json!("0xbbbb")));

    let log_id = eth_new_filter(&json!([])).unwrap();
    notify_log(EvmLog {
        address: "0xcccc".to_string(),
        topics: vec![],
        data: "0x".to_string(),
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        block_hash: None,
        log_index: None,
        removed: false,
    });
    let log_changes = eth_get_filter_changes(&json!([log_id.clone()])).unwrap();
    assert_eq!(log_changes.as_array().unwrap().len(), 1);
    let all_logs = eth_get_filter_logs(&json!([log_id.clone()])).unwrap();
    assert_eq!(all_logs.as_array().unwrap().len(), 1);

    assert!(eth_uninstall_filter(&json!([bf_id])).unwrap());
    assert!(eth_uninstall_filter(&json!([ptx_id])).unwrap());
    assert!(eth_uninstall_filter(&json!([log_id])).unwrap());

    // 6. eth_call_with_engine
    let eng = InMemoryStateEngine::new();
    let eng_res = eth_call_with_engine(&eng, &json!([{ "data": "0x06fdde03" }]))
        .await
        .unwrap();
    assert_eq!(
        abi_decode_string(eng_res.as_str().unwrap()).unwrap(),
        "Stellereum"
    );

    // 7. Constants verification
    assert_eq!(DEFAULT_BASE_FEE, 0x3eb2788000);
    assert_eq!(SELECTOR_BALANCE_OF, "70a08231");
    assert_eq!(SELECTOR_BALANCE_OF_HEX, "0x70a08231");
}

// ============================================================================
// Block, Transaction, and Receipt EVM Translation & MetaMask Compatibility Tests
// ============================================================================

fn test_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn test_signed_tx(
    from_key: &ed25519_dalek::SigningKey,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
) -> Transaction {
    Transaction::sign(from_key, to, amount, gas_limit, nonce, 0, 0)
}

async fn test_rpc_state_with_height(height: u64) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(tokio::sync::RwLock::new(
        stellereum::mempool::Mempool::default(),
    ));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(height)),
        node_id: "test-node:01".to_string(),
        chain_id: CHAIN_ID,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

#[tokio::test]
async fn test_eth_block_number_hex_quantity_format() {
    // 1. Direct function eth_block_number and alias eth_blockNumber
    assert_eq!(eth_block_number(0), "0x0");
    assert_eq!(eth_blockNumber(0), "0x0");
    assert_eq!(eth_block_number(1), "0x1");
    assert_eq!(eth_blockNumber(1), "0x1");
    assert_eq!(eth_block_number(42), "0x2a");
    assert_eq!(eth_blockNumber(42), "0x2a");
    assert_eq!(eth_block_number(5757), "0x167d");
    assert_eq!(eth_blockNumber(5757), "0x167d");
    assert_eq!(eth_block_number(1_000_000), "0xf4240");

    // 2. Through EvmAdapter instance
    let adapter = EvmAdapter::new().with_height(255);
    assert_eq!(adapter.eth_block_number(), "0xff");
    assert_eq!(adapter.eth_blockNumber(), "0xff");

    // 3. Through RpcState
    let st = test_rpc_state_with_height(77).await;
    assert_eq!(st.eth_block_number(), "0x4d");
    assert_eq!(st.eth_blockNumber(), "0x4d");

    // 4. Through JSON-RPC call
    let resp = st.call("eth_blockNumber", json!([])).await;
    assert_eq!(resp, json!("0x4d"));

    // Advance height and verify update
    st.height.store(100, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(st.eth_block_number(), "0x64");
    assert_eq!(st.call("eth_blockNumber", json!([])).await, json!("0x64"));
}

#[tokio::test]
async fn test_eth_get_block_by_number_metamask_compatibility() {
    // 1. Tag parsing verification
    assert_eq!(BlockTag::parse_str("latest").unwrap(), BlockTag::Latest);
    assert_eq!(BlockTag::parse_str("LATEST").unwrap(), BlockTag::Latest);
    assert_eq!(BlockTag::parse_str("earliest").unwrap(), BlockTag::Earliest);
    assert_eq!(BlockTag::parse_str("EARLIEST").unwrap(), BlockTag::Earliest);
    assert_eq!(BlockTag::parse_str("pending").unwrap(), BlockTag::Pending);
    assert_eq!(
        BlockTag::parse_str("finalized").unwrap(),
        BlockTag::Finalized
    );
    assert_eq!(BlockTag::parse_str("safe").unwrap(), BlockTag::Safe);
    assert_eq!(BlockTag::parse_str("0x0").unwrap(), BlockTag::Number(0));
    assert_eq!(BlockTag::parse_str("0x1").unwrap(), BlockTag::Number(1));
    assert_eq!(BlockTag::parse_str("0x2a").unwrap(), BlockTag::Number(42));
    assert_eq!(BlockTag::parse_str("42").unwrap(), BlockTag::Number(42));
    assert!(BlockTag::parse_str("invalid_tag").is_err());

    // 2. Setup RpcState with blocks and receipts
    let st = test_rpc_state_with_height(1).await;
    let genesis_hash = [0x11u8; 32];
    let block1_hash = [0x22u8; 32];
    st.record_block(0, genesis_hash, 0, 1_700_000_000).await;
    st.record_block(1, block1_hash, 2, 1_700_000_002).await;

    let key0 = test_signing_key(1);
    let key1 = test_signing_key(2);
    let recipient0 = [0x44u8; 32];
    let recipient1 = [0x66u8; 32];

    let tx0 = test_signed_tx(&key0, recipient0, 1_000_000_000, 21_000, 0); // 1 STELL
    let tx1 = test_signed_tx(&key1, recipient1, 2_000_000_000, 30_000, 1); // 2 STELL
    let txs = vec![tx0.clone(), tx1.clone()];
    let statuses = vec![true, true];
    let fees = vec![21_000, 25_000]; // total gas used: 46_000 = 0xb3b0

    st.record_receipts(1, block1_hash, &txs, &statuses, &fees)
        .await;

    // 3. Test eth_getBlockByNumber("latest", false) -> array of tx hashes
    let block_hashes = st
        .eth_get_block_by_number("latest", false)
        .await
        .unwrap()
        .expect("block 1 must exist");

    assert_eq!(block_hashes.number, Some("0x1".to_string()));
    assert_eq!(block_hashes.hash, Some(stell_hash_to_evm(&block1_hash)));
    assert_eq!(block_hashes.parent_hash, stell_hash_to_evm(&genesis_hash));
    assert_eq!(block_hashes.gas_used, "0xb3b0"); // 46_000
    assert_eq!(block_hashes.gas_limit, "0x1c9c380"); // 30,000,000

    match &block_hashes.transactions {
        BlockTransactions::Hashes(hashes) => {
            assert_eq!(hashes.len(), 2);
            assert_eq!(hashes[0], stell_hash_to_evm(&tx0.compute_tx_hash()));
            assert_eq!(hashes[1], stell_hash_to_evm(&tx1.compute_tx_hash()));
        }
        _ => panic!("expected BlockTransactions::Hashes when full_tx is false"),
    }

    // 4. Validate exact JSON schema for MetaMask
    let json_val = serde_json::to_value(&block_hashes).unwrap();
    let map = json_val.as_object().unwrap();

    let expected_metamask_keys = [
        "number",
        "hash",
        "parentHash",
        "nonce",
        "sha3Uncles",
        "logsBloom",
        "transactionsRoot",
        "stateRoot",
        "receiptsRoot",
        "miner",
        "difficulty",
        "totalDifficulty",
        "extraData",
        "size",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "transactions",
        "uncles",
        "baseFeePerGas",
        "mixHash",
    ];

    for key in expected_metamask_keys {
        assert!(map.contains_key(key), "MetaMask expects field: {key}");
    }

    // Detailed field assertions
    assert_eq!(map["number"].as_str().unwrap(), "0x1");
    assert_eq!(map["hash"].as_str().unwrap().len(), 66); // 32 bytes hex with 0x
    assert_eq!(map["parentHash"].as_str().unwrap().len(), 66);
    assert_eq!(map["nonce"].as_str().unwrap().len(), 18); // 8 bytes hex with 0x
    assert_eq!(map["sha3Uncles"].as_str().unwrap().len(), 66);
    assert_eq!(map["logsBloom"].as_str().unwrap().len(), 514); // 256 bytes hex with 0x
    assert_eq!(map["miner"].as_str().unwrap().len(), 42); // 20 bytes hex with 0x
    assert_eq!(map["difficulty"].as_str().unwrap(), "0x0");
    assert_eq!(map["totalDifficulty"].as_str().unwrap(), "0x0");
    assert_eq!(map["extraData"].as_str().unwrap(), "0x");
    assert_eq!(map["size"].as_str().unwrap(), "0x400"); // 1024 bytes
    assert_eq!(map["gasLimit"].as_str().unwrap(), "0x1c9c380");
    assert_eq!(map["gasUsed"].as_str().unwrap(), "0xb3b0");
    assert_eq!(map["timestamp"].as_str().unwrap(), "0x6553f102");
    assert!(map["transactions"].is_array());
    assert_eq!(map["transactions"].as_array().unwrap().len(), 2);
    assert!(map["uncles"].is_array());
    assert!(map["uncles"].as_array().unwrap().is_empty());
    assert_eq!(map["baseFeePerGas"].as_str().unwrap(), "0x7");
    assert_eq!(map["mixHash"].as_str().unwrap().len(), 66);

    // 5. Test eth_getBlockByNumber("latest", true) -> full hydrated tx objects
    let block_full = st
        .eth_get_block_by_number("latest", true)
        .await
        .unwrap()
        .expect("block 1 must exist");

    match &block_full.transactions {
        BlockTransactions::Full(txs_list) => {
            assert_eq!(txs_list.len(), 2);
            assert_eq!(txs_list[0].hash, stell_hash_to_evm(&tx0.compute_tx_hash()));
            assert_eq!(txs_list[0].block_number, Some("0x1".to_string()));
            assert_eq!(txs_list[0].transaction_index, Some("0x0".to_string()));
            assert_eq!(txs_list[0].from, stell_address_to_evm(&tx0.from));
            assert_eq!(txs_list[0].to, Some(stell_address_to_evm(&tx0.to)));
            assert_eq!(txs_list[0].value, "0xde0b6b3a7640000"); // 10^18 Wei
            assert_eq!(txs_list[0].gas, "0x5208"); // 21_000

            assert_eq!(txs_list[1].hash, stell_hash_to_evm(&tx1.compute_tx_hash()));
            assert_eq!(txs_list[1].block_number, Some("0x1".to_string()));
            assert_eq!(txs_list[1].transaction_index, Some("0x1".to_string()));
            assert_eq!(txs_list[1].from, stell_address_to_evm(&tx1.from));
            assert_eq!(txs_list[1].to, Some(stell_address_to_evm(&tx1.to)));
            assert_eq!(txs_list[1].value, "0x1bc16d674ec80000"); // 2 * 10^18 Wei
            assert_eq!(txs_list[1].gas, "0x7530"); // 30_000
        }
        _ => panic!("expected BlockTransactions::Full when full_tx is true"),
    }

    // 6. Test tags: "earliest" (resolves to height 0)
    let genesis_block = st
        .eth_get_block_by_number("earliest", false)
        .await
        .unwrap()
        .expect("genesis block must exist");
    assert_eq!(genesis_block.number, Some("0x0".to_string()));
    assert_eq!(genesis_block.hash, Some(stell_hash_to_evm(&genesis_hash)));
    assert_eq!(
        genesis_block.parent_hash,
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(genesis_block.gas_used, "0x0");

    // 7. Test tags: "pending" (resolves to head height 1)
    let pending_block = st
        .eth_get_block_by_number("pending", false)
        .await
        .unwrap()
        .expect("pending block resolves to latest");
    assert_eq!(pending_block.number, Some("0x1".to_string()));

    // 8. Test hex height: "0x1"
    let hex_block = st
        .eth_get_block_by_number("0x1", false)
        .await
        .unwrap()
        .expect("hex height 0x1 must exist");
    assert_eq!(hex_block.number, Some("0x1".to_string()));

    // 9. Non-existent block returns None (result: null in JSON-RPC)
    let missing_block = st.eth_get_block_by_number("0x9999", false).await.unwrap();
    assert!(missing_block.is_none());

    // 10. Invalid block tag returns JsonRpcError::invalid_params
    let err_tag = st
        .eth_get_block_by_number("invalid_tag", false)
        .await
        .unwrap_err();
    assert_eq!(err_tag.code, -32602);
}

#[tokio::test]
async fn test_eth_get_block_by_hash_metamask_compatibility() {
    let st = test_rpc_state_with_height(1).await;
    let genesis_hash = [0x33u8; 32];
    let block1_hash = [0x44u8; 32];
    st.record_block(0, genesis_hash, 0, 1_700_000_000).await;
    st.record_block(1, block1_hash, 1, 1_700_000_005).await;

    let key = test_signing_key(5);
    let tx = test_signed_tx(&key, [0x88u8; 32], 500_000_000, 21_000, 0);
    st.record_receipts(
        1,
        block1_hash,
        std::slice::from_ref(&tx),
        &[true],
        &[21_000],
    )
    .await;

    let hash_hex_lower = stell_hash_to_evm(&block1_hash);
    let hash_hex_upper = format!("0X{}", hex::encode(block1_hash).to_uppercase());
    let hash_bare = hex::encode(block1_hash);

    // 1. Lowercase 0x-prefixed hash
    let b1 = st
        .eth_get_block_by_hash(&hash_hex_lower, false)
        .await
        .unwrap()
        .expect("block 1 by lower hash");
    assert_eq!(b1.number, Some("0x1".to_string()));
    assert_eq!(b1.hash, Some(hash_hex_lower.clone()));
    assert_eq!(b1.parent_hash, stell_hash_to_evm(&genesis_hash));
    assert_eq!(b1.gas_used, "0x5208");

    // 2. Uppercase 0X-prefixed hash
    let b2 = st
        .eth_get_block_by_hash(&hash_hex_upper, false)
        .await
        .unwrap()
        .expect("block 1 by upper hash");
    assert_eq!(b2.hash, Some(hash_hex_lower.clone()));

    // 3. Bare 64 hex character string without 0x
    let b3 = st
        .eth_get_block_by_hash(&hash_bare, false)
        .await
        .unwrap()
        .expect("block 1 by bare hash");
    assert_eq!(b3.hash, Some(hash_hex_lower.clone()));

    // 4. Query with full_tx = true
    let b_full = st
        .eth_get_block_by_hash(&hash_hex_lower, true)
        .await
        .unwrap()
        .expect("block 1 full");
    match b_full.transactions {
        BlockTransactions::Full(txs) => {
            assert_eq!(txs.len(), 1);
            assert_eq!(txs[0].hash, stell_hash_to_evm(&tx.compute_tx_hash()));
            assert_eq!(txs[0].from, stell_address_to_evm(&tx.from));
        }
        _ => panic!("expected full transactions"),
    }

    // 5. Non-existent hash returns None
    let missing_hash = format!("0x{}", hex::encode([0x99u8; 32]));
    let missing = st
        .eth_get_block_by_hash(&missing_hash, false)
        .await
        .unwrap();
    assert!(missing.is_none());

    // 6. Invalid hash returns error code -32602
    assert!(st.eth_get_block_by_hash("0x123", false).await.is_err());
    assert!(st.eth_get_block_by_hash("not-a-hash", false).await.is_err());
}

#[tokio::test]
async fn test_eth_get_transaction_receipt_metamask_compatibility() {
    let st = test_rpc_state_with_height(1).await;
    let block_hash = [0x55u8; 32];
    st.record_block(1, block_hash, 2, 1_700_000_010).await;

    let key0 = test_signing_key(10);
    let key1 = test_signing_key(11);
    let to0 = [0xaau8; 32];
    let to1 = [0xbbu8; 32];

    let tx0 = test_signed_tx(&key0, to0, 1_000_000_000, 21_000, 0); // success
    let tx1 = test_signed_tx(&key1, to1, 2_000_000_000, 50_000, 1); // failure
    let tx0_hash = tx0.compute_tx_hash();
    let tx1_hash = tx1.compute_tx_hash();

    let txs = vec![tx0.clone(), tx1.clone()];
    let statuses = vec![true, false]; // tx0: success, tx1: failure
    let fees = vec![21_000, 15_000]; // tx0 fee: 21_000, tx1 fee: 15_000

    st.record_receipts(1, block_hash, &txs, &statuses, &fees)
        .await;

    // 1. Check successful transaction receipt (tx0)
    let r0 = st
        .eth_get_transaction_receipt(&stell_hash_to_evm(&tx0_hash))
        .await
        .unwrap()
        .expect("receipt tx0");

    assert_eq!(r0.transaction_hash, stell_hash_to_evm(&tx0_hash));
    assert_eq!(r0.transaction_index, "0x0");
    assert_eq!(r0.block_hash, stell_hash_to_evm(&block_hash));
    assert_eq!(r0.block_number, "0x1");
    assert_eq!(r0.from, stell_address_to_evm(&tx0.from));
    assert_eq!(r0.to, Some(stell_address_to_evm(&tx0.to)));
    assert_eq!(r0.cumulative_gas_used, "0x5208"); // 21_000
    assert_eq!(r0.gas_used, "0x5208"); // 21_000
    assert_eq!(r0.contract_address, None);
    assert_eq!(r0.logs, Vec::<EvmLog>::new());
    assert_eq!(r0.logs_bloom, EMPTY_LOGS_BLOOM);
    assert_eq!(r0.status, Some("0x1".to_string())); // EIP-658 success
    assert_eq!(r0.tx_type, Some("0x0".to_string()));
    assert_eq!(r0.effective_gas_price, Some("0x1".to_string()));

    // 2. Validate exact JSON schema for MetaMask
    let r0_json = serde_json::to_value(&r0).unwrap();
    let r0_map = r0_json.as_object().unwrap();

    let expected_receipt_keys = [
        "transactionHash",
        "transactionIndex",
        "blockHash",
        "blockNumber",
        "from",
        "to",
        "cumulativeGasUsed",
        "gasUsed",
        "contractAddress",
        "logs",
        "logsBloom",
        "status",
        "type",
        "effectiveGasPrice",
    ];

    for key in expected_receipt_keys {
        assert!(
            r0_map.contains_key(key),
            "MetaMask expects receipt key: {key}"
        );
    }

    assert_eq!(r0_map["status"].as_str().unwrap(), "0x1");
    assert!(r0_map["contractAddress"].is_null());
    assert!(r0_map["logs"].is_array());
    assert!(r0_map["logs"].as_array().unwrap().is_empty());
    assert_eq!(r0_map["logsBloom"].as_str().unwrap().len(), 514);
    assert_eq!(r0_map["from"].as_str().unwrap().len(), 42);
    assert_eq!(r0_map["to"].as_str().unwrap().len(), 42);

    // 3. Check failed transaction receipt (tx1)
    let r1 = st
        .eth_get_transaction_receipt(&stell_hash_to_evm(&tx1_hash))
        .await
        .unwrap()
        .expect("receipt tx1");

    assert_eq!(r1.transaction_hash, stell_hash_to_evm(&tx1_hash));
    assert_eq!(r1.transaction_index, "0x1");
    assert_eq!(r1.status, Some("0x0".to_string())); // EIP-658 failure
    assert_eq!(r1.gas_used, "0x3a98"); // 15_000
    assert_eq!(r1.cumulative_gas_used, "0x8ca0"); // 21_000 + 15_000 = 36_000 = 0x8ca0

    let r1_json = serde_json::to_value(&r1).unwrap();
    assert_eq!(r1_json["status"].as_str().unwrap(), "0x0");
    assert_eq!(r1_json["cumulativeGasUsed"].as_str().unwrap(), "0x8ca0");
    assert_eq!(r1_json["gasUsed"].as_str().unwrap(), "0x3a98");

    // 4. Non-existent receipt returns None
    let missing_hash = format!("0x{}", hex::encode([0xfeu8; 32]));
    assert!(st
        .eth_get_transaction_receipt(&missing_hash)
        .await
        .unwrap()
        .is_none());

    // 5. Invalid hash format returns error
    assert!(st.eth_get_transaction_receipt("0xbad").await.is_err());
}

#[tokio::test]
async fn test_eth_get_transaction_by_hash_metamask_compatibility() {
    let st = test_rpc_state_with_height(1).await;
    let block_hash = [0x66u8; 32];
    st.record_block(1, block_hash, 1, 1_700_000_020).await;

    let key0 = test_signing_key(20);
    let to0 = [0xccu8; 32];
    let tx0 = test_signed_tx(&key0, to0, 1_500_000_000, 21_000, 0); // 1.5 STELL
    let tx0_hash = tx0.compute_tx_hash();

    // Record finalized transaction receipt
    st.record_receipts(
        1,
        block_hash,
        std::slice::from_ref(&tx0),
        &[true],
        &[21_000],
    )
    .await;

    // 1. Lookup finalized transaction from receipts
    let evm_tx0 = st
        .eth_get_transaction_by_hash(&stell_hash_to_evm(&tx0_hash))
        .await
        .unwrap()
        .expect("tx0 must be found");

    assert_eq!(evm_tx0.hash, stell_hash_to_evm(&tx0_hash));
    assert_eq!(evm_tx0.block_hash, Some(stell_hash_to_evm(&block_hash)));
    assert_eq!(evm_tx0.block_number, Some("0x1".to_string()));
    assert_eq!(evm_tx0.transaction_index, Some("0x0".to_string()));
    assert_eq!(evm_tx0.from, stell_address_to_evm(&tx0.from));
    assert_eq!(evm_tx0.to, Some(stell_address_to_evm(&tx0.to)));
    assert_eq!(evm_tx0.value, "0x14d1120d7b160000"); // 1.5 * 10^18 Wei
    assert_eq!(evm_tx0.gas, "0x5208");
    assert_eq!(evm_tx0.gas_price, Some("0x1".to_string()));
    assert_eq!(evm_tx0.nonce, "0x0");
    assert_eq!(evm_tx0.chain_id, Some(format!("0x{:x}", CHAIN_ID)));
    assert_eq!(evm_tx0.tx_type, Some("0x0".to_string()));

    // Validate JSON structure for MetaMask
    let tx_json = serde_json::to_value(&evm_tx0).unwrap();
    let tx_map = tx_json.as_object().unwrap();
    let expected_tx_keys = [
        "hash",
        "nonce",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "from",
        "to",
        "value",
        "gasPrice",
        "gas",
        "input",
        "v",
        "r",
        "s",
        "type",
        "chainId",
    ];
    for key in expected_tx_keys {
        assert!(tx_map.contains_key(key), "MetaMask expects tx key: {key}");
    }
    assert_eq!(tx_map["from"].as_str().unwrap().len(), 42);
    assert_eq!(tx_map["to"].as_str().unwrap().len(), 42);

    // 2. Lookup pending transaction from mempool
    let key1 = test_signing_key(21);
    let to1 = [0xddu8; 32];
    let tx1 = test_signed_tx(&key1, to1, 500_000_000, 21_000, 0);
    let tx1_hash = tx1.compute_tx_hash();
    st.mempool.write().await.add(tx1.clone()).unwrap();

    let evm_pending = st
        .eth_get_transaction_by_hash(&stell_hash_to_evm(&tx1_hash))
        .await
        .unwrap()
        .expect("pending tx must be found in mempool");

    assert_eq!(evm_pending.hash, stell_hash_to_evm(&tx1_hash));
    assert_eq!(evm_pending.block_hash, None); // null when pending in EVM
    assert_eq!(evm_pending.block_number, None); // null when pending
    assert_eq!(evm_pending.transaction_index, None); // null when pending
    assert_eq!(evm_pending.from, stell_address_to_evm(&tx1.from));
    assert_eq!(evm_pending.to, Some(stell_address_to_evm(&tx1.to)));

    let pending_json = serde_json::to_value(&evm_pending).unwrap();
    assert!(pending_json["blockHash"].is_null());
    assert!(pending_json["blockNumber"].is_null());
    assert!(pending_json["transactionIndex"].is_null());

    // 3. Non-existent transaction returns None
    let missing_hash = format!("0x{}", hex::encode([0xeeu8; 32]));
    assert!(st
        .eth_get_transaction_by_hash(&missing_hash)
        .await
        .unwrap()
        .is_none());

    // 4. Invalid hash format returns error
    assert!(st.eth_get_transaction_by_hash("0xdead").await.is_err());
}

#[tokio::test]
async fn test_rpc_dispatch_metamask_jsonrpc_protocol_flow() {
    let st = test_rpc_state_with_height(10).await;
    let genesis_hash = [0x71u8; 32];
    let head_hash = [0x72u8; 32];
    st.record_block(0, genesis_hash, 0, 1_700_000_000).await;
    st.record_block(10, head_hash, 1, 1_700_000_050).await;

    let key = test_signing_key(30);
    let to = [0xeeu8; 32];
    let tx = test_signed_tx(&key, to, 1_000_000_000, 21_000, 0);
    let tx_hash_hex = stell_hash_to_evm(&tx.compute_tx_hash());
    let head_hash_hex = stell_hash_to_evm(&head_hash);

    st.record_receipts(10, head_hash, std::slice::from_ref(&tx), &[true], &[21_000])
        .await;

    // 1. eth_blockNumber -> "0xa" (10)
    let resp_bn = st.call("eth_blockNumber", json!([])).await;
    assert_eq!(resp_bn, json!("0xa"));

    // 2. eth_getBlockByNumber("latest", false)
    let resp_block_hashes = st
        .call("eth_getBlockByNumber", json!(["latest", false]))
        .await;
    assert_eq!(resp_block_hashes["number"], json!("0xa"));
    assert_eq!(resp_block_hashes["hash"], json!(head_hash_hex));
    assert_eq!(resp_block_hashes["gasUsed"], json!("0x5208"));
    assert_eq!(
        resp_block_hashes["transactions"],
        json!([tx_hash_hex.clone()])
    );

    // 3. eth_getBlockByNumber("latest", true)
    let resp_block_full = st
        .call("eth_getBlockByNumber", json!(["latest", true]))
        .await;
    assert_eq!(resp_block_full["number"], json!("0xa"));
    let full_tx_arr = resp_block_full["transactions"].as_array().unwrap();
    assert_eq!(full_tx_arr.len(), 1);
    assert_eq!(full_tx_arr[0]["hash"], json!(tx_hash_hex.clone()));
    assert_eq!(full_tx_arr[0]["blockNumber"], json!("0xa"));

    // 4. eth_getBlockByHash
    let resp_block_by_hash = st
        .call("eth_getBlockByHash", json!([head_hash_hex.clone(), false]))
        .await;
    assert_eq!(resp_block_by_hash["number"], json!("0xa"));
    assert_eq!(resp_block_by_hash["hash"], json!(head_hash_hex.clone()));

    // 5. eth_getTransactionReceipt
    let resp_receipt = st
        .call("eth_getTransactionReceipt", json!([tx_hash_hex.clone()]))
        .await;
    assert_eq!(resp_receipt["transactionHash"], json!(tx_hash_hex.clone()));
    assert_eq!(resp_receipt["status"], json!("0x1"));
    assert_eq!(resp_receipt["gasUsed"], json!("0x5208"));
    assert_eq!(resp_receipt["cumulativeGasUsed"], json!("0x5208"));
    assert_eq!(resp_receipt["logs"], json!([]));
    assert!(resp_receipt["contractAddress"].is_null());

    // 6. eth_getTransactionByHash
    let resp_tx = st
        .call("eth_getTransactionByHash", json!([tx_hash_hex.clone()]))
        .await;
    assert_eq!(resp_tx["hash"], json!(tx_hash_hex.clone()));
    assert_eq!(resp_tx["blockNumber"], json!("0xa"));
    assert_eq!(resp_tx["from"], json!(stell_address_to_evm(&tx.from)));
    assert_eq!(resp_tx["to"], json!(stell_address_to_evm(&tx.to)));
    assert_eq!(resp_tx["value"], json!("0xde0b6b3a7640000"));

    // 7. Non-existent block and transaction return null
    let fake_hash = format!("0x{}", hex::encode([0x99u8; 32]));
    let resp_fake_block = st
        .call("eth_getBlockByHash", json!([fake_hash.clone(), false]))
        .await;
    assert_eq!(resp_fake_block, Value::Null);

    let resp_fake_receipt = st
        .call("eth_getTransactionReceipt", json!([fake_hash.clone()]))
        .await;
    assert_eq!(resp_fake_receipt, Value::Null);

    let resp_fake_tx = st
        .call("eth_getTransactionByHash", json!([fake_hash]))
        .await;
    assert_eq!(resp_fake_tx, Value::Null);
}

// ============================================================================
// secp256k1 ECDSA & ecrecover Transaction Signature Verification Tests
// ============================================================================

#[test]
fn test_ecrecover_known_ethereum_transaction_vector() {
    // Canonical Ethereum EIP-155 official test vector:
    // Signed transaction RLP:
    // [nonce=9, gasPrice=20 Gwei, gasLimit=21000, to=0x35..., value=1 ETH, data='', v=37, r, s]
    let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw = hex::decode(hex_raw).expect("valid hex");

    let tx = parse_legacy_transaction(&raw).expect("must parse legacy transaction");
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.gas_price, 20_000_000_000);
    assert_eq!(tx.gas_limit, 21_000);
    assert_eq!(tx.value, 1_000_000_000_000_000_000);
    assert_eq!(tx.v, 37);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.recovery_id(), 0);

    // Official EIP-155 signing hash:
    // keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0]))
    let sighash = tx.signing_hash();
    assert_eq!(
        hex::encode(sighash),
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    );

    // 1. Recover sender address using ecrecover
    let recovered_addr = ecrecover(&sighash, tx.v, &tx.r, &tx.s)
        .expect("ecrecover must succeed for canonical EIP-155 vector");
    assert_ne!(recovered_addr, [0u8; 20]);

    // 2. Independently derive expected address from private key 0x4646...46
    let privkey_bytes = [0x46u8; 32];
    let signing_key =
        k256::ecdsa::SigningKey::from_slice(&privkey_bytes).expect("valid secp256k1 private key");
    let verifying_key = signing_key.verifying_key();
    let uncompressed_pt = verifying_key.to_encoded_point(false);
    let expected_addr =
        pubkey_to_address(uncompressed_pt.as_bytes()).expect("derive address from pubkey");

    // 3. Verify recovered address matches expected address exactly
    assert_eq!(recovered_addr, expected_addr);

    // 4. Verify address calculation formula: keccak256(&uncompressed[1..])[12..32]
    let manual_hash = keccak256(&uncompressed_pt.as_bytes()[1..65]);
    assert_eq!(&manual_hash[12..32], recovered_addr.as_slice());

    // 5. Verify EIP-55 checksum formatting of recovered address
    let checksum_addr = to_checksum_address(&recovered_addr);
    assert_eq!(checksum_addr.len(), 42);
    assert!(checksum_addr.starts_with("0x"));

    // 6. Verify canonical low-s under EIP-2
    assert!(is_low_s(&tx.s));
}

#[test]
fn test_transaction_signature_validation_replay_protection_and_low_s() {
    // Generate valid signature using Hardhat Account #0
    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let expected_addr = pubkey_to_address(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(expected_addr),
        "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );

    let test_tx_hash = keccak256(b"Stellereum L1 test transaction payload");

    // Sign hash using secp256k1 RFC 6979 deterministic ECDSA
    let (sig, recid) = signing_key.sign_prehash_recoverable(&test_tx_hash).unwrap();
    let rec_id = recid.to_byte();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);

    // 1. Stellereum EIP-155 v parameter: v = 2 * 5757 + 35 + rec_id = 11549 + rec_id
    let stell_v = 2 * CHAIN_ID + 35 + rec_id as u64;
    assert!(stell_v == 11549 || stell_v == 11550);

    // Validation specifically targeting Stellereum (chain_id == 5757) must succeed
    let validated_sender = validate_transaction_signature(&test_tx_hash, stell_v, &r, &s)
        .expect("validation for chain_id 5757 must succeed");
    assert_eq!(validated_sender, expected_addr);

    // Also via verify_transaction_signature alias
    let verified_sender = verify_transaction_signature(&test_tx_hash, stell_v, &r, &s)
        .expect("verify_transaction_signature alias must succeed");
    assert_eq!(verified_sender, expected_addr);

    // 2. Replay protection: Replay of an Ethereum Mainnet (chain_id = 1) tx on Stellereum must FAIL
    let eth_mainnet_v = 2 + 35 + rec_id as u64; // v = 37 or 38
    let err_replay = validate_transaction_signature(&test_tx_hash, eth_mainnet_v, &r, &s)
        .expect_err("replay attack from chain 1 must be rejected on Stellereum");
    assert!(
        err_replay.contains("replay protection") || err_replay.contains("mismatch"),
        "error message should indicate replay protection mismatch: {err_replay}"
    );

    // 3. Replay protection: Pre-EIP-155 unprotected legacy transaction (v = 27 or 28) must FAIL
    let legacy_v = 27u64 + rec_id as u64;
    let err_unprot = validate_transaction_signature(&test_tx_hash, legacy_v, &r, &s).expect_err(
        "unprotected legacy transaction must be rejected when replay protection is enforced",
    );
    assert!(
        err_unprot.contains("replay protection required") || err_unprot.contains("unprotected"),
        "error message should indicate replay protection required: {err_unprot}"
    );

    // 4. EIP-2 low-s canonicality check:
    // Construct malleable high-s value greater than SECP256K1_HALF_N
    let mut high_s = SECP256K1_HALF_N;
    high_s[31] = high_s[31].saturating_add(1);

    // high_s must NOT be low-s
    assert!(!is_low_s(&high_s));
    assert!(is_low_s(&s));

    // Validating with high_s must be rejected under EIP-2
    let err_high_s = validate_transaction_signature(&test_tx_hash, stell_v, &r, &high_s)
        .expect_err("high-s signature must be rejected under EIP-2");
    assert!(
        err_high_s.contains("canonical") || err_high_s.contains("EIP-2"),
        "error message should cite EIP-2 non-canonical s: {err_high_s}"
    );
}

#[test]
fn test_ecrecover_eip1559_and_eip155_recovery_formulas() {
    let privkey =
        hex::decode("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let expected_addr = pubkey_to_address(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();

    let tx_hash = keccak256(b"EIP-1559 typed transaction payload");
    let (sig, recid) = signing_key.sign_prehash_recoverable(&tx_hash).unwrap();
    let rec_id = recid.to_byte();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);

    // 1. EIP-1559: v = 0 or v = 1 (y_parity)
    let y_parity = rec_id as u64;
    assert!(y_parity == 0 || y_parity == 1);
    let recovered_1559 = ecrecover(&tx_hash, y_parity, &r, &s)
        .expect("ecrecover with EIP-1559 y_parity must succeed");
    assert_eq!(recovered_1559, expected_addr);

    // 2. EIP-155: v = 2 * chain_id + 35 + rec_id
    // Formula check: rec_id = (v - 35 - 2 * chain_id) % 2
    let chain_id = CHAIN_ID; // 5757
    let v_eip155 = 2 * chain_id + 35 + rec_id as u64;
    let extracted_rec_id = ((v_eip155 - 35 - 2 * chain_id) % 2) as u8;
    assert_eq!(extracted_rec_id, rec_id);

    let recovered_155 =
        ecrecover(&tx_hash, v_eip155, &r, &s).expect("ecrecover with EIP-155 v must succeed");
    assert_eq!(recovered_155, expected_addr);

    // 3. Pre-EIP-155 legacy: v = 27 + rec_id
    let v_legacy = 27u64 + rec_id as u64;
    let recovered_legacy =
        ecrecover(&tx_hash, v_legacy, &r, &s).expect("ecrecover with legacy v must succeed");
    assert_eq!(recovered_legacy, expected_addr);
}

// ============================================================================
// Address Mapping & Balance Scaling Tests (Zones of Responsibility)
// ============================================================================

#[test]
fn test_evm_to_stell_address_padding() {
    let evm_addr: [u8; 20] = [
        0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94, 0x35,
        0xe7, 0xef, 0x1b, 0xea, 0xed,
    ];

    let stell_addr = evm_to_stell_address(&evm_addr);

    // 1. Verify exact 12 zero bytes on the left
    assert_eq!(
        &stell_addr[0..12],
        &[0u8; 12],
        "left 12 bytes must be exactly 0"
    );

    // 2. Verify remaining 20 bytes match the EVM address
    assert_eq!(
        &stell_addr[12..32],
        &evm_addr,
        "bytes 12..32 must match EVM address"
    );

    // 3. Roundtrip back to EVM address
    let extracted = stell_to_evm_address(&stell_addr);
    assert_eq!(
        extracted, evm_addr,
        "stell_to_evm_address must recover exact EVM address"
    );
}

#[test]
fn test_stell_to_evm_address_extraction() {
    // Arbitrary 32-byte address with arbitrary prefix
    let mut stell_addr = [0xffu8; 32];
    stell_addr[0..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    let evm_part: [u8; 20] = [0x42; 20];
    stell_addr[12..32].copy_from_slice(&evm_part);

    let extracted = stell_to_evm_address(&stell_addr);
    assert_eq!(
        extracted, evm_part,
        "must extract bytes 12..32 regardless of prefix"
    );
}

#[test]
fn test_evm_address_from_hex_and_to_hex() {
    let evm_raw: [u8; 20] = [
        0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94, 0x35,
        0xe7, 0xef, 0x1b, 0xea, 0xed,
    ];

    // 1. Parse 20-byte address with "0x" prefix
    let parsed1 = evm_address_from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
    assert_eq!(parsed1, evm_raw);

    // 2. Parse 20-byte address without "0x" prefix
    let parsed2 = evm_address_from_hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
    assert_eq!(parsed2, evm_raw);

    // 3. Parse 20-byte mixed-case checksummed address
    let parsed3 = evm_address_from_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
    assert_eq!(parsed3, evm_raw);

    // 4. Parse 32-byte Stellereum address (64 hex characters) with 0x prefix
    let parsed4 =
        evm_address_from_hex("0x0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .unwrap();
    assert_eq!(parsed4, evm_raw);

    // 5. Parse 32-byte Stellereum address without 0x prefix
    let parsed5 =
        evm_address_from_hex("0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .unwrap();
    assert_eq!(parsed5, evm_raw);

    // 6. evm_address_to_hex formats with 0x prefix and lowercase
    let hex_str = evm_address_to_hex(&evm_raw);
    assert_eq!(hex_str, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");

    // 7. parse_evm_address alias
    let parsed_alias = parse_evm_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
    assert_eq!(parsed_alias, evm_raw);

    // 8. Error on invalid lengths
    assert!(evm_address_from_hex("0x1234").is_err(), "too short");
    assert!(
        evm_address_from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae").is_err(),
        "39 hex chars"
    );
    assert!(
        evm_address_from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed00").is_err(),
        "42 hex chars"
    );
    assert!(
        evm_address_from_hex(
            "0x0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed00"
        )
        .is_err(),
        "66 hex chars"
    );

    // 9. Error on invalid characters
    assert!(evm_address_from_hex("0xzzzzb6053f3e94c9b9a09f33669435e7ef1beaed").is_err());
}

#[test]
fn test_parse_evm_or_stell_address_both_formats() {
    let evm_hex = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    let stell_hex = "0x0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed";

    // 20-byte input pads to 32 bytes
    let from_20 = parse_evm_or_stell_address(evm_hex).expect("parse 20-byte hex");
    assert_eq!(&from_20[0..12], &[0u8; 12]);

    // 32-byte input yields identical 32-byte array
    let from_32 = parse_evm_or_stell_address(stell_hex).expect("parse 32-byte hex");
    assert_eq!(from_20, from_32);

    // Alias checks
    assert_eq!(stell_address_from_hex(evm_hex).unwrap(), from_20);
    assert_eq!(evm_to_stell_address_from_hex(evm_hex).unwrap(), from_20);
}

#[test]
fn test_nano_to_wei_and_wei_to_nano_scaling() {
    // 1 STELL = 10^9 nano-STELL = 10^18 Wei
    // 1 nano-STELL = 10^9 Wei
    assert_eq!(NANO_PER_STELL, 1_000_000_000);
    assert_eq!(WEI_PER_STELL, 1_000_000_000_000_000_000);
    assert_eq!(WEI_PER_NANO, 1_000_000_000);

    // 1. Zero scaling
    assert_eq!(nano_to_wei(0), 0);
    assert_eq!(wei_to_nano(0), 0);

    // 2. 1 nano-STELL -> 10^9 Wei
    assert_eq!(nano_to_wei(1), 1_000_000_000);
    assert_eq!(wei_to_nano(1_000_000_000), 1);

    // 3. 1 STELL = 10^9 nano-STELL -> 10^18 Wei
    assert_eq!(nano_to_wei(1_000_000_000), 1_000_000_000_000_000_000);
    assert_eq!(wei_to_nano(1_000_000_000_000_000_000), 1_000_000_000);

    // 4. Fractional STELL: 0.5 STELL = 500_000_000 nano -> 500_000_000_000_000_000 Wei
    assert_eq!(nano_to_wei(500_000_000), 500_000_000_000_000_000);
    assert_eq!(wei_to_nano(500_000_000_000_000_000), 500_000_000);

    // 5. Large value: 21,000,000 STELL
    let large_nano: u64 = 21_000_000 * 1_000_000_000;
    let expected_wei: u128 = 21_000_000 * 1_000_000_000_000_000_000;
    assert_eq!(nano_to_wei(large_nano), expected_wei);
    assert_eq!(wei_to_nano(expected_wei), large_nano);

    // 6. Max nano (u64::MAX) converts without overflow
    let max_wei = nano_to_wei(u64::MAX);
    assert_eq!(max_wei, (u64::MAX as u128) * 1_000_000_000);
    assert_eq!(wei_to_nano(max_wei), u64::MAX);

    // 7. Sub-nano truncation
    assert_eq!(
        wei_to_nano(999_999_999),
        0,
        "sub-nano wei must truncate to 0"
    );
    assert_eq!(
        wei_to_nano(1_000_000_001),
        1,
        "remainder truncates to 1 nano"
    );

    // 8. Reversibility check
    for test_nano in [0, 1, 42, 1000, 1_000_000_000, 50_000_000_000] {
        assert_eq!(wei_to_nano(nano_to_wei(test_nano)), test_nano);
    }

    // 9. Saturation on extreme u128
    assert_eq!(wei_to_nano(u128::MAX), u64::MAX);
}

#[test]
fn test_nano_wei_hex_and_string_helpers() {
    // 1 STELL = 10^9 nano -> 10^18 Wei = 0xde0b6b3a7640000
    assert_eq!(nano_to_wei_hex(1_000_000_000), "0xde0b6b3a7640000");
    assert_eq!(nano_to_wei_hex(0), "0x0");
    assert_eq!(nano_to_wei_hex(1), "0x3b9aca00"); // 10^9 = 0x3b9aca00

    assert_eq!(nano_to_wei_str(1_000_000_000), "1000000000000000000");
    assert_eq!(wei_to_nano_str(1_000_000_000_000_000_000), "1000000000");

    assert_eq!(wei_to_nano_hex(1_000_000_000_000_000_000), "0x3b9aca00");

    assert_eq!(wei_hex_to_nano("0xde0b6b3a7640000").unwrap(), 1_000_000_000);
    assert_eq!(
        wei_str_to_nano("1000000000000000000").unwrap(),
        1_000_000_000
    );
}

#[tokio::test]
async fn test_eth_get_balance_scaling_and_hex() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let evm_addr_hex = "0x407d73d8a49eeb85d32cf465507dd71d507100c1";
    let stell_addr = parse_evm_or_stell_address(evm_addr_hex).unwrap();

    // 1. Non-existent account returns "0x0"
    let bal_empty = eth_get_balance(&engine, &json!([evm_addr_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(bal_empty, "0x0");

    // 2. Fund account with 5 STELL = 5_000_000_000 nano-STELL
    // Expected Wei: 5 * 10^18 = 5_000_000_000_000_000_000 = 0x4563918244f40000
    engine
        .update_account(AccountState::new(stell_addr, 5_000_000_000))
        .await;

    // Query with 20-byte EVM address
    let bal_hex = eth_get_balance(&engine, &json!([evm_addr_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(bal_hex, "0x4563918244f40000");

    // Query with 32-byte Stellereum address
    let stell_hex = format!("0x{}", hex::encode(stell_addr));
    let bal_hex_32 = eth_get_balance(&engine, &json!([stell_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(bal_hex_32, "0x4563918244f40000");

    // Query with block tags: earliest, pending, finalized, safe, hex number
    for tag in ["earliest", "pending", "finalized", "safe", "0x1"] {
        let b = eth_get_balance(&engine, &json!([evm_addr_hex, tag]))
            .await
            .unwrap();
        assert_eq!(b, "0x4563918244f40000");
    }

    // Object parameter format
    let bal_obj = eth_get_balance(
        &engine,
        &json!({ "address": evm_addr_hex, "blockTag": "latest" }),
    )
    .await
    .unwrap();
    assert_eq!(bal_obj, "0x4563918244f40000");

    // Error on invalid address
    assert!(eth_get_balance(&engine, &json!(["0xinvalid", "latest"]))
        .await
        .is_err());

    // Error on invalid block tag
    assert!(
        eth_get_balance(&engine, &json!([evm_addr_hex, "invalid_tag"]))
            .await
            .is_err()
    );

    // 3. Test through EvmAdapter with engine
    let adapter = EvmAdapter::new().with_engine(engine.clone());
    let res = adapter
        .dispatch("eth_getBalance", &json!([evm_addr_hex, "latest"]))
        .unwrap();
    assert_eq!(res, json!("0x4563918244f40000"));

    let res_async = adapter
        .dispatch_async("eth_getBalance", &json!([evm_addr_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(res_async, json!("0x4563918244f40000"));

    let method_res = adapter.eth_getBalance(evm_addr_hex, "latest").unwrap();
    assert_eq!(method_res, "0x4563918244f40000");

    // 4. Test EvmAdapter with standalone in-memory balance in Wei
    let standalone_adapter =
        EvmAdapter::new().with_balance(evm_addr_hex, 1_000_000_000_000_000_000);
    assert_eq!(
        standalone_adapter
            .eth_getBalance(evm_addr_hex, "latest")
            .unwrap(),
        "0xde0b6b3a7640000"
    );
    assert_eq!(
        standalone_adapter
            .dispatch("eth_getBalance", &json!([evm_addr_hex, "latest"]))
            .unwrap(),
        json!("0xde0b6b3a7640000")
    );

    // 5. Standalone eth_getBalance function
    assert_eq!(eth_getBalance(evm_addr_hex, "latest").unwrap(), "0x0");
}

#[tokio::test]
async fn test_eth_get_transaction_count_nonce_hex() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let evm_addr_hex = "0x407d73d8a49eeb85d32cf465507dd71d507100c1";
    let stell_addr = parse_evm_or_stell_address(evm_addr_hex).unwrap();

    // 1. Non-existent account returns "0x0"
    let nonce_empty = eth_get_transaction_count(&engine, &json!([evm_addr_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(nonce_empty, "0x0");

    // 2. Account with nonce 42 (0x2a)
    let mut acc = AccountState::new(stell_addr, 1000);
    acc.nonce = 42;
    engine.update_account(acc).await;

    let nonce_hex = eth_get_transaction_count(&engine, &json!([evm_addr_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(nonce_hex, "0x2a");

    // 32-byte address query
    let stell_hex = format!("0x{}", hex::encode(stell_addr));
    let nonce_32 = eth_get_transaction_count(&engine, &json!([stell_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(nonce_32, "0x2a");

    // Error on invalid address
    assert!(
        eth_get_transaction_count(&engine, &json!(["0xbad", "latest"]))
            .await
            .is_err()
    );

    // Error on invalid block tag
    assert!(
        eth_get_transaction_count(&engine, &json!([evm_addr_hex, "bogus"]))
            .await
            .is_err()
    );

    // 3. Test through EvmAdapter with engine
    let adapter = EvmAdapter::new().with_engine(engine);
    let res = adapter
        .dispatch("eth_getTransactionCount", &json!([evm_addr_hex, "latest"]))
        .unwrap();
    assert_eq!(res, json!("0x2a"));

    let res_async = adapter
        .dispatch_async("eth_getTransactionCount", &json!([evm_addr_hex, "latest"]))
        .await
        .unwrap();
    assert_eq!(res_async, json!("0x2a"));

    let method_res = adapter
        .eth_getTransactionCount(evm_addr_hex, "latest")
        .unwrap();
    assert_eq!(method_res, "0x2a");

    // Standalone function
    let standalone_nonce = eth_getTransactionCount(evm_addr_hex, "latest").unwrap();
    assert_eq!(standalone_nonce, "0x0");
}

#[test]
fn test_eth_get_code_always_returns_0x() {
    let evm_addr_hex = "0x407d73d8a49eeb85d32cf465507dd71d507100c1";

    // 1. Direct standalone function
    assert_eq!(eth_getCode(evm_addr_hex, "latest").unwrap(), "0x");
    assert_eq!(eth_get_code(), "0x");

    // 2. EvmAdapter method
    let adapter = EvmAdapter::new();
    assert_eq!(adapter.eth_getCode(evm_addr_hex, "latest").unwrap(), "0x");
    assert_eq!(adapter.eth_get_code(), "0x");

    // 3. JSON-RPC dispatch (both 20-byte and 32-byte addresses)
    let res = adapter
        .dispatch("eth_getCode", &json!([evm_addr_hex, "latest"]))
        .unwrap();
    assert_eq!(res, json!("0x"));

    let stell_hex = "0x000000000000000000000000407d73d8a49eeb85d32cf465507dd71d507100c1";
    let res_32 = adapter
        .dispatch("eth_getCode", &json!([stell_hex, "latest"]))
        .unwrap();
    assert_eq!(res_32, json!("0x"));

    // Empty params returns "0x"
    assert_eq!(
        adapter.dispatch("eth_getCode", &Value::Null).unwrap(),
        json!("0x")
    );

    // Invalid address produces error
    assert!(adapter.dispatch("eth_getCode", &json!(["0xbad"])).is_err());

    // Invalid block tag produces error
    assert!(adapter
        .dispatch("eth_getCode", &json!([evm_addr_hex, "invalid_tag"]))
        .is_err());
}

#[tokio::test]
async fn test_eth_state_methods_via_rpc_layer() {
    let st = test_rpc_state_with_height(10).await;
    let evm_addr_hex = "0x407d73d8a49eeb85d32cf465507dd71d507100c1";
    let stell_addr = parse_evm_or_stell_address(evm_addr_hex).unwrap();

    // 1. Initially balance = 0, nonce = 0, code = "0x"
    let res_bal = st
        .call("eth_getBalance", json!([evm_addr_hex, "latest"]))
        .await;
    assert_eq!(res_bal, json!("0x0"));

    let res_nonce = st
        .call("eth_getTransactionCount", json!([evm_addr_hex, "latest"]))
        .await;
    assert_eq!(res_nonce, json!("0x0"));

    let res_code = st
        .call("eth_getCode", json!([evm_addr_hex, "latest"]))
        .await;
    assert_eq!(res_code, json!("0x"));

    // 2. Fund account with 2.5 STELL = 2_500_000_000 nano-STELL, nonce = 10 (0xa)
    // 2.5 STELL = 2_500_000_000_000_000_000 Wei = 0x22b1c8c1227a0000
    let mut acc = AccountState::new(stell_addr, 2_500_000_000);
    acc.nonce = 10;
    st.engine.update_account(acc).await;

    // eth_getBalance via RPC
    let res_bal_funded = st
        .call("eth_getBalance", json!([evm_addr_hex, "latest"]))
        .await;
    assert_eq!(res_bal_funded, json!("0x22b1c8c1227a0000"));

    // eth_getTransactionCount via RPC
    let res_nonce_funded = st
        .call("eth_getTransactionCount", json!([evm_addr_hex, "latest"]))
        .await;
    assert_eq!(res_nonce_funded, json!("0xa"));

    // Also test 32-byte address format via RPC
    let stell_hex = format!("0x{}", hex::encode(stell_addr));
    let res_bal_32 = st
        .call("eth_getBalance", json!([stell_hex, "latest"]))
        .await;
    assert_eq!(res_bal_32, json!("0x22b1c8c1227a0000"));
}

// ============================================================================
// RLP DoS guards: recursion depth + checked arithmetic (no panic / overflow)
// ============================================================================

#[test]
fn test_rlp_deep_nesting_over_64_returns_error_without_panic() {
    use stellereum::evm_adapter::MAX_RLP_DEPTH;
    assert_eq!(MAX_RLP_DEPTH, 64);

    // Boundary: exactly MAX depth must still decode.
    let mut ok_item = RlpItem::Byte(0x01);
    for _ in 0..MAX_RLP_DEPTH {
        ok_item = RlpItem::List(vec![ok_item]);
    }
    let ok_enc = rlp_encode(&ok_item);
    let ok_res = rlp_decode(&ok_enc);
    assert!(ok_res.is_ok(), "depth == MAX_RLP_DEPTH must decode");

    // Over the limit: MAX + 1 nesting must return Err, not panic / stack-overflow.
    let mut deep_item = RlpItem::Byte(0x01);
    for _ in 0..(MAX_RLP_DEPTH + 1) {
        deep_item = RlpItem::List(vec![deep_item]);
    }
    let deep_enc = rlp_encode(&deep_item);
    let deep_res = rlp_decode(&deep_enc);
    assert!(deep_res.is_err(), "depth > MAX_RLP_DEPTH must be rejected");

    // Far over the limit (e.g. 128) likewise returns Err without panicking.
    let mut bomb = RlpItem::Byte(0x01);
    for _ in 0..128 {
        bomb = RlpItem::List(vec![bomb]);
    }
    let bomb_enc = rlp_encode(&bomb);
    let bomb_res = rlp_decode(&bomb_enc);
    assert!(bomb_res.is_err(), "deep nesting bomb must be rejected");
}

#[test]
fn test_rlp_len_usize_max_returns_error_without_overflow() {
    // Long-string header claiming len == usize::MAX: 0xbf + 8 x 0xff on 64-bit.
    // `total_header + len` would wrap in unchecked arithmetic; decoder must use
    // checked_add and return Err (UnexpectedEof), never panic.
    let len_bytes = vec![0xffu8; 8];
    let usize_max = usize::MAX;
    // Sanity: this header really encodes usize::MAX on this platform.
    let mut check: usize = 0;
    for &b in &len_bytes {
        check = check
            .checked_shl(8)
            .and_then(|v| v.checked_add(b as usize))
            .unwrap();
    }
    assert_eq!(check, usize_max);

    let mut hostile_str = vec![0xbf];
    hostile_str.extend_from_slice(&len_bytes);
    let res_str = rlp_decode(&hostile_str);
    assert!(
        res_str.is_err(),
        "len == usize::MAX string must be rejected, not overflow"
    );

    // Same for a long list: 0xff + 8 x 0xff.
    let mut hostile_list = vec![0xff];
    hostile_list.extend_from_slice(&len_bytes);
    let res_list = rlp_decode(&hostile_list);
    assert!(
        res_list.is_err(),
        "len == usize::MAX list must be rejected, not overflow"
    );
}

#[test]
fn test_abi_decode_string_hostile_offset_len_returns_error_without_panic() {
    // offset = 0x8000... (usize::MAX/2 + 1): `offset * 2` overflows -> Err, no panic.
    let huge_offset_hex = format!("0x{:0>64x}", (usize::MAX / 2) + 1);
    let body = format!("{huge_offset_hex}{}", "00".repeat(64));
    let res = abi_decode_string(&body);
    assert!(
        res.is_err(),
        "overflowing offset must be rejected, not panic"
    );

    // Declared string len == usize::MAX: `len * 2` overflows -> Err, no panic.
    let normal_offset = format!("{:0>64x}", 32);
    let max_len = format!("{:0>64x}", usize::MAX);
    let payload = format!("0x{normal_offset}{max_len}");
    let res2 = abi_decode_string(&payload);
    assert!(
        res2.is_err(),
        "len == usize::MAX must be rejected, not overflow"
    );
}

// ============================================================================
// FilterManager GC (TTL 300s, caps) & replay protection (chain_id == 5757)
// ============================================================================

#[test]
fn test_filter_gc_constants() {
    assert_eq!(FILTER_TTL_SECS, 300, "filter TTL must be 300s");
    assert_eq!(
        MAX_ACTIVE_FILTERS, 10_000,
        "max active filters must be 10000"
    );
    assert_eq!(
        MAX_PENDING_PER_FILTER, 1_000,
        "max pending per filter must be 1000"
    );
    assert_eq!(CHAIN_ID, 5757);
}

#[test]
fn test_filter_expiration_by_timeout_lazy_gc() {
    let manager = FilterManager::new();

    // 1. Fresh filters are usable.
    let block_id = manager.new_block_filter();
    let log_id = manager.new_filter(FilterCriteria::default());
    assert_eq!(manager.get_filter_changes(&block_id).unwrap(), json!([]));
    assert_eq!(manager.get_filter_changes(&log_id).unwrap(), json!([]));
    assert_eq!(
        manager.sweep_expired(),
        0,
        "fresh filters must not be swept"
    );

    // 2. Age the block filter beyond TTL -> lazy expiration on next poll.
    assert!(manager.expire_filter_for_test(&block_id));
    let err_changes = manager
        .get_filter_changes(&block_id)
        .expect_err("expired filter must report not found");
    assert_eq!(err_changes.message, "filter not found");
    // Second access still reports not found (entry was dropped, incl. buffers).
    let err_again = manager
        .get_filter_changes(&block_id)
        .expect_err("expired entry must stay gone");
    assert_eq!(err_again.message, "filter not found");

    // 3. Same for get_filter_logs on a log filter (all_logs must be freed).
    manager.notify_log(EvmLog {
        address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        topics: vec![],
        data: "0x".to_string(),
        block_number: None,
        transaction_hash: None,
        transaction_index: None,
        block_hash: None,
        log_index: None,
        removed: false,
    });
    // Log filter was polled above so last_poll is fresh; all_logs has 1 entry.
    assert_eq!(
        manager
            .get_filter_logs(&log_id)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(manager.expire_filter_for_test(&log_id));
    let err_logs = manager
        .get_filter_logs(&log_id)
        .expect_err("expired log filter must report not found on get_filter_logs");
    assert_eq!(err_logs.message, "filter not found");
    let err_changes2 = manager
        .get_filter_changes(&log_id)
        .expect_err("expired log filter must report not found on get_filter_changes");
    assert_eq!(err_changes2.message, "filter not found");

    // 4. sweep_expired collects idle filters without any poll.
    let stale_id = manager.new_block_filter();
    assert!(manager.expire_filter_for_test(&stale_id));
    assert_eq!(manager.sweep_expired(), 1, "one stale filter must be swept");
    assert_eq!(
        manager
            .get_filter_changes(&stale_id)
            .expect_err("swept filter is gone")
            .message,
        "filter not found"
    );

    // 5. Active polling keeps a filter alive (no false expiry).
    let live_id = manager.new_block_filter();
    manager.notify_block_hash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    let changes = manager.get_filter_changes(&live_id).unwrap();
    assert_eq!(changes.as_array().unwrap().len(), 1);
    assert_eq!(manager.sweep_expired(), 0);
}

#[test]
fn test_filter_pending_cap_1000() {
    let manager = FilterManager::new();

    // Block hashes are capped at MAX_PENDING_PER_FILTER (oldest evicted).
    let block_id = manager.new_block_filter();
    for i in 0..(MAX_PENDING_PER_FILTER + 5) {
        manager.notify_block_hash(format!("0x{:064x}", i + 1));
    }
    let changes = manager.get_filter_changes(&block_id).unwrap();
    let arr = changes.as_array().unwrap();
    assert_eq!(
        arr.len(),
        MAX_PENDING_PER_FILTER,
        "pending block hashes must be capped at 1000"
    );
    // First 5 evicted, latest 1000 kept.
    assert_eq!(arr[0], json!(format!("0x{:064x}", 6)));
    assert_eq!(
        arr[MAX_PENDING_PER_FILTER - 1],
        json!(format!("0x{:064x}", MAX_PENDING_PER_FILTER + 5))
    );

    // Log buffers (pending_logs AND all_logs) are capped as well.
    let log_id = manager.new_filter(FilterCriteria::default());
    for _ in 0..(MAX_PENDING_PER_FILTER + 5) {
        manager.notify_log(EvmLog {
            address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            topics: vec![],
            data: "0x".to_string(),
            block_number: None,
            transaction_hash: None,
            transaction_index: None,
            block_hash: None,
            log_index: None,
            removed: false,
        });
    }
    let pending = manager.get_filter_changes(&log_id).unwrap();
    assert_eq!(
        pending.as_array().unwrap().len(),
        MAX_PENDING_PER_FILTER,
        "pending_logs must be capped at 1000"
    );
    let all = manager.get_filter_logs(&log_id).unwrap();
    assert_eq!(
        all.as_array().unwrap().len(),
        MAX_PENDING_PER_FILTER,
        "all_logs must be capped at 1000 (no unbounded growth)"
    );
}

#[test]
fn test_verify_signature_rejects_foreign_chain_id() {
    // --- Legacy: official Ethereum mainnet vector (chain_id == 1) ---
    let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw = hex::decode(hex_raw).unwrap();
    let foreign_legacy = parse_legacy_transaction(&raw).unwrap();
    assert_eq!(foreign_legacy.chain_id, Some(1));
    // Recovery itself is chain-agnostic and succeeds...
    assert!(foreign_legacy.recover_sender().is_ok());
    // ...but strict verification must cut off чужой chain_id.
    let err = foreign_legacy
        .verify_signature()
        .expect_err("chain_id 1 must be rejected on Stellereum");
    assert_eq!(
        err,
        EvmError::ChainIdMismatch {
            expected: 5757,
            got: 1
        }
    );

    // --- Legacy: unprotected pre-EIP-155 (v = 27, chain_id = None) ---
    let mut unprotected = foreign_legacy.clone();
    unprotected.v = 27;
    unprotected.chain_id = None;
    let err_unprot = unprotected
        .verify_signature()
        .expect_err("unprotected legacy must be rejected");
    assert_eq!(err_unprot, EvmError::ReplayProtectionRequired);

    // --- Legacy: valid Stellereum signature (chain_id == 5757) must verify ---
    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let expected_addr = pubkey_to_address(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();
    let mut stell_legacy = LegacyTransaction {
        nonce: 7,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some([0x35; 20]),
        value: 1_000_000_000_000_000_000,
        data: vec![],
        v: 0, // filled after signing
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(CHAIN_ID),
    };
    let sighash = stell_legacy.signing_hash();
    let (sig, recid) = signing_key.sign_prehash_recoverable(&sighash).unwrap();
    let rec_id = recid.to_byte();
    stell_legacy.r.copy_from_slice(&sig.to_bytes()[..32]);
    stell_legacy.s.copy_from_slice(&sig.to_bytes()[32..64]);
    stell_legacy.v = 2 * CHAIN_ID + 35 + rec_id as u64;
    assert_eq!(stell_legacy.verify_signature().unwrap(), expected_addr);
    // And via the unified enum.
    assert_eq!(
        DecodedTransaction::Legacy(stell_legacy.clone())
            .verify_signature()
            .unwrap(),
        expected_addr
    );
    assert_eq!(
        DecodedTransaction::Legacy(foreign_legacy.clone())
            .verify_signature()
            .unwrap_err(),
        EvmError::ChainIdMismatch {
            expected: 5757,
            got: 1
        }
    );

    // --- EIP-1559: foreign chain_id == 1 must be cut off ---
    let foreign_1559 = Eip1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 21_000,
        to: Some([0x11; 20]),
        value: 0,
        data: vec![],
        access_list: vec![],
        y_parity: 0,
        v: 0,
        r: [0x33; 32],
        s: [0x44; 32],
    };
    let err_1559 = foreign_1559
        .verify_signature()
        .expect_err("EIP-1559 chain_id 1 must be rejected");
    assert_eq!(
        err_1559,
        EvmError::ChainIdMismatch {
            expected: 5757,
            got: 1
        }
    );

    // --- EIP-1559: valid Stellereum signature must verify ---
    let mut stell_1559 = Eip1559Transaction {
        chain_id: CHAIN_ID,
        nonce: 9,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: Some([0x22; 20]),
        value: 0,
        data: vec![],
        access_list: vec![],
        y_parity: 0,
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };
    let sighash_1559 = stell_1559.signing_hash();
    let (sig2, recid2) = signing_key.sign_prehash_recoverable(&sighash_1559).unwrap();
    stell_1559.r.copy_from_slice(&sig2.to_bytes()[..32]);
    stell_1559.s.copy_from_slice(&sig2.to_bytes()[32..64]);
    stell_1559.y_parity = recid2.to_byte();
    stell_1559.v = stell_1559.y_parity as u64;
    assert_eq!(stell_1559.verify_signature().unwrap(), expected_addr);
    assert_eq!(
        DecodedTransaction::Eip1559(stell_1559.clone())
            .verify_signature()
            .unwrap(),
        expected_addr
    );
    assert_eq!(
        DecodedTransaction::Eip1559(foreign_1559.clone())
            .verify_signature()
            .unwrap_err(),
        EvmError::ChainIdMismatch {
            expected: 5757,
            got: 1
        }
    );
}

// ============================================================================
// Missing EVM getters: block tx counts, tx-by-block-index, uncles (MetaMask)
// ============================================================================

fn test_evm_tx_fixture(hash_byte: u8) -> EvmTransaction {
    let hash = format!("0x{}", hex::encode([hash_byte; 32]));
    EvmTransaction {
        hash,
        nonce: "0x0".to_string(),
        block_hash: Some(format!("0x{}", hex::encode([0xabu8; 32]))),
        block_number: Some("0x5".to_string()),
        transaction_index: Some("0x0".to_string()),
        from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        to: Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        value: "0x0".to_string(),
        gas_price: Some("0x1".to_string()),
        gas: "0x5208".to_string(),
        input: "0x".to_string(),
        v: "0x2d09".to_string(),
        r: "0x0".to_string(),
        s: "0x0".to_string(),
        tx_type: Some("0x0".to_string()),
        chain_id: Some(CHAIN_ID_HEX.to_string()),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

fn test_evm_block_fixture(number_hex: &str, hash: &str, txs: BlockTransactions) -> EvmBlock {
    EvmBlock {
        number: Some(number_hex.to_string()),
        hash: Some(hash.to_string()),
        parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        nonce: Some("0x0000000000000000".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: EMPTY_ROOT_HASH.to_string(),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: "0x0000000000000000000000000000000000000000".to_string(),
        difficulty: "0x0".to_string(),
        total_difficulty: Some("0x0".to_string()),
        extra_data: "0x".to_string(),
        size: "0x400".to_string(),
        gas_limit: "0x1c9c380".to_string(),
        gas_used: "0x0".to_string(),
        timestamp: "0x6553f102".to_string(),
        transactions: txs,
        uncles: Vec::new(),
        base_fee_per_gas: Some("0x7".to_string()),
        mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
        withdrawals: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    }
}

#[test]
fn test_eth_get_block_transaction_count_metamask_format() {
    let mut adapter = EvmAdapter::new().with_head_block(5);
    let tx0 = test_evm_tx_fixture(0x11);
    let tx1 = test_evm_tx_fixture(0x22);
    adapter.insert_transaction(tx0.clone());
    adapter.insert_transaction(tx1.clone());
    let block_hash = format!("0x{}", hex::encode([0xabu8; 32]));
    let block = test_evm_block_fixture(
        "0x5",
        &block_hash,
        BlockTransactions::Hashes(vec![tx0.hash.clone(), tx1.hash.clone()]),
    );
    adapter.insert_block(block);

    // MetaMask: eth_getBlockTransactionCountByHash -> QUANTITY hex
    let res_hash = adapter
        .dispatch(
            "eth_getBlockTransactionCountByHash",
            &json!([block_hash.clone()]),
        )
        .unwrap();
    assert_eq!(res_hash, json!("0x2"));

    // MetaMask: eth_getBlockTransactionCountByNumber with tag and hex number
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByNumber", &json!(["latest"]))
            .unwrap(),
        json!("0x2")
    );
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByNumber", &json!(["0x5"]))
            .unwrap(),
        json!("0x2")
    );
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByNumber", &json!([5]))
            .unwrap(),
        json!("0x2")
    );

    // Unknown block -> null
    let fake = format!("0x{}", hex::encode([0x99u8; 32]));
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByHash", &json!([fake.clone()]))
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByNumber", &json!(["0x9999"]))
            .unwrap(),
        Value::Null
    );

    // Invalid params -> -32602
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByHash", &json!(["0x123"]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByNumber", &json!(["bogus"]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch("eth_getBlockTransactionCountByHash", &json!([]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );

    // Raw JSON-RPC MetaMask format (id preserved, result is QUANTITY string)
    let raw = r#"{"jsonrpc":"2.0","method":"eth_getBlockTransactionCountByNumber","params":["0x5"],"id":7}"#.to_string();
    let resp_raw = adapter.handle_raw_json(&raw);
    let resp: JsonRpcResponse<String> = serde_json::from_str(&resp_raw).unwrap();
    assert_eq!(resp.id, json!(7));
    assert_eq!(resp.result.unwrap(), "0x2");
}

#[test]
fn test_eth_get_transaction_by_block_and_index_metamask_format() {
    let mut adapter = EvmAdapter::new().with_head_block(9);
    let mut tx0 = test_evm_tx_fixture(0x31);
    tx0.transaction_index = Some("0x0".to_string());
    let mut tx1 = test_evm_tx_fixture(0x32);
    tx1.transaction_index = Some("0x1".to_string());
    let block_hash = format!("0x{}", hex::encode([0xcdu8; 32]));
    let block = test_evm_block_fixture(
        "0x9",
        &block_hash,
        BlockTransactions::Full(vec![tx0.clone(), tx1.clone()]),
    );
    adapter.insert_block(block);

    // By hash + index
    let got0 = adapter
        .dispatch(
            "eth_getTransactionByBlockHashAndIndex",
            &json!([block_hash.clone(), "0x0"]),
        )
        .unwrap();
    assert_eq!(got0["hash"], json!(tx0.hash));
    assert_eq!(got0["transactionIndex"], json!("0x0"));

    let got1 = adapter
        .dispatch(
            "eth_getTransactionByBlockHashAndIndex",
            &json!([block_hash.clone(), "0x1"]),
        )
        .unwrap();
    assert_eq!(got1["hash"], json!(tx1.hash));

    // By number + index (hex tag, decimal number index)
    let got_num = adapter
        .dispatch(
            "eth_getTransactionByBlockNumberAndIndex",
            &json!(["0x9", "0x1"]),
        )
        .unwrap();
    assert_eq!(got_num["hash"], json!(tx1.hash));
    let got_num_dec = adapter
        .dispatch(
            "eth_getTransactionByBlockNumberAndIndex",
            &json!(["latest", 0]),
        )
        .unwrap();
    assert_eq!(got_num_dec["hash"], json!(tx0.hash));

    // Out of range -> null
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockHashAndIndex",
                &json!([block_hash.clone(), "0x2"])
            )
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockNumberAndIndex",
                &json!(["0x9", "0x2"])
            )
            .unwrap(),
        Value::Null
    );

    // Unknown block -> null
    let fake = format!("0x{}", hex::encode([0xfeu8; 32]));
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockHashAndIndex",
                &json!([fake.clone(), "0x0"])
            )
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockNumberAndIndex",
                &json!(["0x9999", "0x0"])
            )
            .unwrap(),
        Value::Null
    );

    // Invalid params -> -32602
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockHashAndIndex",
                &json!([block_hash.clone(), "0xzz"])
            )
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockHashAndIndex",
                &json!(["0x123", "0x0"])
            )
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getTransactionByBlockNumberAndIndex",
                &json!(["bogus", "0x0"])
            )
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );

    // Raw JSON-RPC MetaMask format with full tx object
    let raw = r#"{"jsonrpc":"2.0","method":"eth_getTransactionByBlockNumberAndIndex","params":["0x9","0x0"],"id":"mm-1"}"#.to_string();
    let resp_raw = adapter.handle_raw_json(&raw);
    let resp: JsonRpcResponse<EvmTransaction> = serde_json::from_str(&resp_raw).unwrap();
    assert_eq!(resp.id, json!("mm-1"));
    assert_eq!(resp.result.unwrap().hash, tx0.hash);
}

#[test]
fn test_eth_get_uncle_metamask_format() {
    let mut adapter = EvmAdapter::new().with_head_block(3);
    let block_hash = format!("0x{}", hex::encode([0xefu8; 32]));
    let block = test_evm_block_fixture("0x3", &block_hash, BlockTransactions::Hashes(vec![]));
    adapter.insert_block(block);

    // Uncle count is always 0x0 for a known block
    assert_eq!(
        adapter
            .dispatch("eth_getUncleCountByBlockHash", &json!([block_hash.clone()]))
            .unwrap(),
        json!("0x0")
    );
    assert_eq!(
        adapter
            .dispatch("eth_getUncleCountByBlockNumber", &json!(["0x3"]))
            .unwrap(),
        json!("0x0")
    );
    assert_eq!(
        adapter
            .dispatch("eth_getUncleCountByBlockNumber", &json!(["latest"]))
            .unwrap(),
        json!("0x0")
    );

    // Uncle by index is always null
    assert_eq!(
        adapter
            .dispatch(
                "eth_getUncleByBlockHashAndIndex",
                &json!([block_hash.clone(), "0x0"])
            )
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        adapter
            .dispatch("eth_getUncleByBlockNumberAndIndex", &json!(["0x3", "0x0"]))
            .unwrap(),
        Value::Null
    );

    // Unknown block -> null (count and uncle)
    let fake = format!("0x{}", hex::encode([0xfdu8; 32]));
    assert_eq!(
        adapter
            .dispatch("eth_getUncleCountByBlockHash", &json!([fake.clone()]))
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        adapter
            .dispatch("eth_getUncleCountByBlockNumber", &json!(["0x9999"]))
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getUncleByBlockHashAndIndex",
                &json!([fake.clone(), "0x0"])
            )
            .unwrap(),
        Value::Null
    );

    // Invalid params -> -32602
    assert_eq!(
        adapter
            .dispatch("eth_getUncleCountByBlockHash", &json!(["0x123"]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getUncleByBlockHashAndIndex",
                &json!([block_hash.clone(), "nope"])
            )
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );

    // Raw JSON-RPC MetaMask format
    let raw_count =
        r#"{"jsonrpc":"2.0","method":"eth_getUncleCountByBlockNumber","params":["0x3"],"id":11}"#
            .to_string();
    let resp_raw = adapter.handle_raw_json(&raw_count);
    let resp: JsonRpcResponse<String> = serde_json::from_str(&resp_raw).unwrap();
    assert_eq!(resp.id, json!(11));
    assert_eq!(resp.result.unwrap(), "0x0");

    let raw_uncle = r#"{"jsonrpc":"2.0","method":"eth_getUncleByBlockNumberAndIndex","params":["0x3","0x0"],"id":12}"#.to_string();
    let resp_raw2 = adapter.handle_raw_json(&raw_uncle);
    let resp2: JsonRpcResponse<Value> = serde_json::from_str(&resp_raw2).unwrap();
    assert_eq!(resp2.id, json!(12));
    assert!(resp2.result.is_none() || resp2.result == Some(Value::Null));
    assert!(resp2.error.is_none());
}

#[tokio::test]
async fn test_rpc_dispatch_block_tx_uncle_metamask_flow() {
    let st = test_rpc_state_with_height(10).await;
    let genesis_hash = [0x71u8; 32];
    let head_hash = [0x72u8; 32];
    st.record_block(0, genesis_hash, 0, 1_700_000_000).await;
    st.record_block(10, head_hash, 1, 1_700_000_050).await;

    let key = test_signing_key(30);
    let to = [0xeeu8; 32];
    let tx = test_signed_tx(&key, to, 1_000_000_000, 21_000, 0);
    let tx_hash_hex = stell_hash_to_evm(&tx.compute_tx_hash());
    let head_hash_hex = stell_hash_to_evm(&head_hash);
    st.record_receipts(10, head_hash, std::slice::from_ref(&tx), &[true], &[21_000])
        .await;

    // Block tx counts via rpc.rs dispatch
    assert_eq!(
        st.call("eth_getBlockTransactionCountByNumber", json!(["latest"]))
            .await,
        json!("0x1")
    );
    assert_eq!(
        st.call("eth_getBlockTransactionCountByNumber", json!(["0xa"]))
            .await,
        json!("0x1")
    );
    assert_eq!(
        st.call(
            "eth_getBlockTransactionCountByHash",
            json!([head_hash_hex.clone()])
        )
        .await,
        json!("0x1")
    );
    assert_eq!(
        st.call("eth_getBlockTransactionCountByNumber", json!(["0x0"]))
            .await,
        json!("0x0")
    );

    // Tx by block+index via rpc.rs dispatch
    let by_num = st
        .call(
            "eth_getTransactionByBlockNumberAndIndex",
            json!(["latest", "0x0"]),
        )
        .await;
    assert_eq!(by_num["hash"], json!(tx_hash_hex.clone()));
    assert_eq!(by_num["blockNumber"], json!("0xa"));
    assert_eq!(by_num["transactionIndex"], json!("0x0"));
    let by_hash = st
        .call(
            "eth_getTransactionByBlockHashAndIndex",
            json!([head_hash_hex.clone(), "0x0"]),
        )
        .await;
    assert_eq!(by_hash["hash"], json!(tx_hash_hex.clone()));

    // Out of range / missing -> null
    assert_eq!(
        st.call(
            "eth_getTransactionByBlockNumberAndIndex",
            json!(["latest", "0x1"])
        )
        .await,
        Value::Null
    );
    let fake = format!("0x{}", hex::encode([0x99u8; 32]));
    assert_eq!(
        st.call("eth_getBlockTransactionCountByHash", json!([fake.clone()]))
            .await,
        Value::Null
    );
    assert_eq!(
        st.call(
            "eth_getTransactionByBlockHashAndIndex",
            json!([fake.clone(), "0x0"])
        )
        .await,
        Value::Null
    );

    // Uncles via rpc.rs dispatch: counts 0x0, bodies null
    assert_eq!(
        st.call("eth_getUncleCountByBlockNumber", json!(["latest"]))
            .await,
        json!("0x0")
    );
    assert_eq!(
        st.call(
            "eth_getUncleCountByBlockHash",
            json!([head_hash_hex.clone()])
        )
        .await,
        json!("0x0")
    );
    assert_eq!(
        st.call(
            "eth_getUncleByBlockNumberAndIndex",
            json!(["latest", "0x0"])
        )
        .await,
        Value::Null
    );
    assert_eq!(
        st.call(
            "eth_getUncleByBlockHashAndIndex",
            json!([head_hash_hex.clone(), "0x0"])
        )
        .await,
        Value::Null
    );

    // Errors surface as {"error": ...} through RpcState::call helper
    let bad = st
        .call("eth_getBlockTransactionCountByHash", json!(["0x123"]))
        .await;
    assert!(bad.get("error").is_some());
}

// ============================================================================
// EVM intent-pool -> L1 settlement bridge (pending -> mined via secp envelope)
// ============================================================================

/// Sign an EIP-1559 intent for CHAIN_ID with low-s normalization (EIP-2).
fn sign_eip1559_intent_low_s(
    tx: &mut stellereum::evm_adapter::Eip1559Transaction,
    key: &k256::ecdsa::SigningKey,
) {
    let sighash = tx.signing_hash();
    let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
    let raw = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);
    let mut parity = recid.to_byte();
    if !stellereum::evm_adapter::is_low_s(&s) {
        // N - s, flip parity (same rule as build_secp_settlement_tx).
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = N[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        s = out;
        parity ^= 1;
    }
    tx.r = r;
    tx.s = s;
    tx.y_parity = parity;
    tx.v = parity as u64;
}

/// Build a valid signed EIP-1559 raw for CHAIN_ID 5757 with a unique nonce.
fn build_signed_eip1559_raw(nonce: u64, to20: [u8; 20]) -> (String, String) {
    use stellereum::evm_adapter::Eip1559Transaction;
    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let mut tx = Eip1559Transaction {
        chain_id: CHAIN_ID,
        nonce,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: Some(to20),
        value: 0,
        data: vec![],
        access_list: vec![],
        y_parity: 0,
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };
    sign_eip1559_intent_low_s(&mut tx, &key);
    let raw = tx.encode();
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let hash_hex = format!(
        "0x{}",
        hex::encode(stellereum::evm_adapter::keccak256(&raw))
    );
    (raw_hex, hash_hex)
}

#[tokio::test]
async fn test_evm_pending_to_mined_receipt_via_secp() {
    use stellereum::evm_adapter as evm;
    // Unique intent so parallel tests never share map keys.
    let (raw_hex, evm_hash) = build_signed_eip1559_raw(9001, [0x77; 20]);

    // 1. Submit intent -> pending pool, receipt is null (honest pending).
    let submitted = evm::eth_send_raw_transaction(&json!([raw_hex.clone()])).unwrap();
    assert_eq!(submitted.to_lowercase(), evm_hash.to_lowercase());
    assert!(evm::eth_pending_tx(&evm_hash).is_some());
    let pending = evm::eth_pending_tx(&evm_hash).unwrap();
    assert_eq!(pending.block_number, None);
    assert_eq!(pending.block_hash, None);

    let st = test_rpc_state_with_height(41).await;
    assert!(st
        .eth_get_transaction_receipt(&evm_hash)
        .await
        .unwrap()
        .is_none());
    // Pending view via RpcState has no block binding yet.
    let pending_view = st
        .eth_get_transaction_by_hash(&evm_hash)
        .await
        .unwrap()
        .expect("pending intent");
    assert_eq!(pending_view.block_number, None);

    // 2. Finalize the SAME EVM hash via a secp envelope (same secp key).
    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let secp_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let stell_tx =
        evm::build_secp_settlement_tx(&secp_key, &evm_hash, [0xAA; 32], 0, 21_000, 0).unwrap();
    assert!(evm::is_secp_settlement_tx(&stell_tx));
    assert!(evm::verify_secp_settlement(&stell_tx).is_ok());
    let stell_hash = stell_tx.compute_tx_hash();

    let block_hash = [0x5Eu8; 32];
    st.record_block(42, block_hash, 1, 1_700_000_100).await;
    st.record_receipts(
        42,
        block_hash,
        std::slice::from_ref(&stell_tx),
        &[true],
        &[21_000],
    )
    .await;

    // 3. Bidirectional mapping works.
    assert_eq!(evm::evm_to_stell_hash(&evm_hash).unwrap(), stell_hash);
    assert_eq!(
        evm::stell_to_evm_hash(&stell_hash).unwrap().to_lowercase(),
        evm_hash.to_lowercase()
    );

    // 4. eth_getTransactionReceipt by EVM hash: full receipt, not null.
    let receipt = st
        .eth_get_transaction_receipt(&evm_hash)
        .await
        .unwrap()
        .expect("settled receipt");
    assert_eq!(
        receipt.transaction_hash.to_lowercase(),
        evm_hash.to_lowercase()
    );
    assert_eq!(receipt.status, Some("0x1".to_string()));
    assert_eq!(receipt.block_number, "0x2a"); // 42
    assert_eq!(receipt.block_hash, evm::stell_hash_to_evm(&block_hash));
    assert_eq!(receipt.gas_used, "0x5208"); // 21_000
    assert!(!receipt.cumulative_gas_used.is_empty());

    // 5. eth_getTransactionByHash by EVM hash: mined view wins over pending.
    let mined = st
        .eth_get_transaction_by_hash(&evm_hash)
        .await
        .unwrap()
        .expect("mined tx");
    assert_eq!(mined.hash.to_lowercase(), evm_hash.to_lowercase());
    assert_eq!(mined.block_number, Some("0x2a".to_string()));
    assert!(mined.block_hash.is_some());

    // 6. Direct stell-hash lookup still works (both directions).
    let by_stell = st
        .eth_get_transaction_receipt(&evm::stell_hash_to_evm(&stell_hash))
        .await
        .unwrap()
        .expect("receipt by stell hash");
    assert_eq!(by_stell.block_number, "0x2a");
    assert_eq!(by_stell.status, Some("0x1".to_string()));
}

#[tokio::test]
async fn test_evm_settlement_mapping_both_directions_and_rejects_bad_envelope() {
    use stellereum::evm_adapter as evm;
    let (raw_hex, evm_hash) = build_signed_eip1559_raw(9002, [0x78; 20]);
    let submitted = evm::eth_send_raw_transaction(&json!([raw_hex])).unwrap();
    assert_eq!(submitted.to_lowercase(), evm_hash.to_lowercase());

    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let secp_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    // Unique stell nonce per test -> unique stell hash.
    let stell_tx =
        evm::build_secp_settlement_tx(&secp_key, &evm_hash, [0xBB; 32], 0, 21_000, 77).unwrap();
    let stell_hash = stell_tx.compute_tx_hash();

    // Tampered envelope must NOT link (fail-closed).
    let mut bad = stell_tx.clone();
    bad.signature[50] ^= 0xff;
    assert!(evm::verify_secp_settlement(&bad).is_err());
    assert!(evm::link_secp_settlement(&bad).is_none());

    // Wrong-sender envelope must NOT verify: flip tx.from but keep signature.
    let mut wrong_from = stell_tx.clone();
    wrong_from.from = [0x11; 32];
    assert!(evm::verify_secp_settlement(&wrong_from).is_err());

    // Valid link registers both directions.
    let (linked_evm, linked_stell) = evm::link_secp_settlement(&stell_tx).unwrap();
    assert_eq!(linked_evm.to_lowercase(), evm_hash.to_lowercase());
    assert_eq!(linked_stell, stell_hash);
    assert_eq!(evm::evm_to_stell_hash(&evm_hash).unwrap(), stell_hash);
    assert_eq!(
        evm::stell_to_evm_hash(&stell_hash).unwrap().to_lowercase(),
        evm_hash.to_lowercase()
    );

    // Unknown hashes resolve to None in both directions.
    let unknown = format!("0x{}", hex::encode([0xF0u8; 32]));
    assert!(evm::evm_to_stell_hash(&unknown).is_none());
    assert!(evm::stell_to_evm_hash(&[0xF1u8; 32]).is_none());

    // Settled receipt/tx builders report the EVM hash, not the stell hash.
    let st = test_rpc_state_with_height(43).await;
    let block_hash = [0x6Au8; 32];
    st.record_block(43, block_hash, 1, 1_700_000_200).await;
    st.record_receipts(
        43,
        block_hash,
        std::slice::from_ref(&stell_tx),
        &[true],
        &[21_000],
    )
    .await;
    let r = st
        .eth_get_transaction_receipt(&evm_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.transaction_hash.to_lowercase(), evm_hash.to_lowercase());
    assert_eq!(r.status, Some("0x1".to_string()));
    let t = st
        .eth_get_transaction_by_hash(&evm_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.hash.to_lowercase(), evm_hash.to_lowercase());
    assert!(t.block_number.is_some());
}

#[test]
fn test_evm_adapter_global_settled_lookup() {
    use stellereum::evm_adapter as evm;
    let (raw_hex, evm_hash) = build_signed_eip1559_raw(9003, [0x79; 20]);
    let _ = evm::eth_send_raw_transaction(&json!([raw_hex])).unwrap();
    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let secp_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let stell_tx =
        evm::build_secp_settlement_tx(&secp_key, &evm_hash, [0xCC; 32], 0, 21_000, 78).unwrap();
    let stell_hash = stell_tx.compute_tx_hash();
    evm::link_secp_settlement(&stell_tx);

    // EvmAdapter-level settled views (global map, no RpcState needed).
    let mut adapter = EvmAdapter::new();
    let fake_block = [0x7Bu8; 32];
    let stell_receipt = stellereum::rpc::TxReceipt {
        tx_hash: stell_hash,
        height: 7,
        block_hash: fake_block,
        index: 0,
        success: true,
        gas_limit: 21_000,
        fee_charged: 21_000,
        raw_tx: bincode::serialize(&stell_tx).ok().map(hex::encode),
        return_value: None,
        gas_used: None,
        events: Vec::new(),
        contract_address: None,
    };
    adapter.insert_stell_receipt(&stell_receipt);
    let got = adapter
        .eth_get_transaction_receipt(&evm_hash)
        .unwrap()
        .expect("global settled receipt");
    assert_eq!(got.transaction_hash.to_lowercase(), evm_hash.to_lowercase());
    assert_eq!(got.status, Some("0x1".to_string()));
    assert_eq!(got.block_number, "0x7");
    assert_eq!(got.gas_used, "0x5208");
    let got_tx = adapter
        .eth_get_transaction_by_hash(&evm_hash)
        .unwrap()
        .expect("global settled tx");
    assert_eq!(got_tx.hash.to_lowercase(), evm_hash.to_lowercase());
}

// ============================================================================
// eth_getLogs (global + adapter + RPC) & eth_getStorageAt (empty storage)
// ============================================================================

fn test_log_fixture(
    addr: &str,
    topics: Vec<String>,
    block: &str,
    tx: &str,
    log_idx: &str,
) -> EvmLog {
    EvmLog {
        address: addr.to_string(),
        topics,
        data: "0x".to_string(),
        block_number: Some(block.to_string()),
        transaction_hash: Some(tx.to_string()),
        transaction_index: Some("0x0".to_string()),
        block_hash: Some(format!("0x{}", hex::encode([0xabu8; 32]))),
        log_index: Some(log_idx.to_string()),
        removed: false,
    }
}

fn test_receipt_fixture(tx_byte: u8, logs: Vec<EvmLog>) -> EvmReceipt {
    EvmReceipt {
        transaction_hash: format!("0x{}", hex::encode([tx_byte; 32])),
        transaction_index: "0x0".to_string(),
        block_hash: format!("0x{}", hex::encode([0xabu8; 32])),
        block_number: logs
            .first()
            .and_then(|l| l.block_number.clone())
            .unwrap_or_else(|| "0x1".to_string()),
        from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        to: Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        cumulative_gas_used: "0x5208".to_string(),
        gas_used: "0x5208".to_string(),
        contract_address: None,
        logs,
        logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
        status: Some("0x1".to_string()),
        root: None,
        tx_type: Some("0x0".to_string()),
        effective_gas_price: Some("0x1".to_string()),
        blob_gas_used: None,
        blob_gas_price: None,
    }
}

#[test]
fn test_eth_get_logs_filtering_address_topics_blocks_and_limit() {
    use stellereum::evm_adapter as evm;
    assert_eq!(evm::MAX_GET_LOGS_RESULTS, 1000);

    let addr_a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let addr_b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let topic_t0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let topic_t1 = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let tx0 = format!("0x{}", hex::encode([0x10u8; 32]));
    let tx1 = format!("0x{}", hex::encode([0x11u8; 32]));

    let mut adapter = EvmAdapter::new();
    adapter.insert_receipt(test_receipt_fixture(
        0x10,
        vec![
            test_log_fixture(addr_a, vec![topic_t0.to_string()], "0x5", &tx0, "0x0"),
            test_log_fixture(addr_a, vec![topic_t1.to_string()], "0x6", &tx0, "0x1"),
        ],
    ));
    adapter.insert_receipt(test_receipt_fixture(
        0x11,
        vec![test_log_fixture(
            addr_b,
            vec![topic_t0.to_string()],
            "0x7",
            &tx1,
            "0x0",
        )],
    ));

    // 1. Empty filter returns all 3 logs, deterministically ordered by block.
    let all = adapter.eth_get_logs(&json!([{}])).unwrap();
    let arr = all.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["blockNumber"], json!("0x5"));
    assert_eq!(arr[1]["blockNumber"], json!("0x6"));
    assert_eq!(arr[2]["blockNumber"], json!("0x7"));

    // 2. Address filter (single + multi).
    let by_a = adapter
        .eth_get_logs(&json!([{ "address": addr_a }]))
        .unwrap();
    assert_eq!(by_a.as_array().unwrap().len(), 2);
    let by_multi = adapter
        .eth_get_logs(&json!([{ "address": [addr_a, addr_b] }]))
        .unwrap();
    assert_eq!(by_multi.as_array().unwrap().len(), 3);
    let by_b = adapter
        .eth_get_logs(&json!([{ "address": addr_b }]))
        .unwrap();
    assert_eq!(by_b.as_array().unwrap().len(), 1);

    // 3. Topics filter.
    let by_t0 = adapter
        .eth_get_logs(&json!([{ "topics": [topic_t0] }]))
        .unwrap();
    assert_eq!(by_t0.as_array().unwrap().len(), 2);
    let by_t1 = adapter
        .eth_get_logs(&json!([{ "topics": [topic_t1] }]))
        .unwrap();
    assert_eq!(by_t1.as_array().unwrap().len(), 1);

    // 4. Block range filter.
    let ranged = adapter
        .eth_get_logs(&json!([{ "fromBlock": "0x6", "toBlock": "0x7" }]))
        .unwrap();
    assert_eq!(ranged.as_array().unwrap().len(), 2);
    let from_only = adapter
        .eth_get_logs(&json!([{ "fromBlock": "0x7" }]))
        .unwrap();
    assert_eq!(from_only.as_array().unwrap().len(), 1);
    let to_only = adapter
        .eth_get_logs(&json!([{ "toBlock": "0x5" }]))
        .unwrap();
    assert_eq!(to_only.as_array().unwrap().len(), 1);

    // 5. Combined filter + dispatch wiring (both method spellings hit the same handler).
    let combo = adapter
        .dispatch(
            "eth_getLogs",
            &json!([{ "address": addr_a, "topics": [topic_t0] }]),
        )
        .unwrap();
    assert_eq!(combo.as_array().unwrap().len(), 1);
    assert_eq!(
        adapter
            .eth_getLogs(&json!([{ "address": addr_a }]))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Global free-function aliases resolve (empty global may or may not contain our instance logs;
    // here we only assert the call shape is an array, instance-level asserts above pin the logic).
    assert!(evm::eth_get_logs(&json!([{}])).unwrap().is_array());
    assert!(evm::eth_getLogs(&json!([{}])).unwrap().is_array());

    // 6. Limit: 1005 matching logs truncate to 1000.
    let mut big = EvmAdapter::new();
    let mut logs = Vec::new();
    for i in 0..1005u64 {
        logs.push(test_log_fixture(
            addr_a,
            vec![topic_t0.to_string()],
            "0x1",
            &format!("0x{:064x}", i + 1),
            &format!("0x{:x}", i),
        ));
    }
    big.insert_receipt(test_receipt_fixture(0x20, logs));
    let capped = big.eth_get_logs(&json!([{}])).unwrap();
    assert_eq!(capped.as_array().unwrap().len(), 1000);
    let capped_dispatch = big.dispatch("eth_getLogs", &json!([{}])).unwrap();
    assert_eq!(capped_dispatch.as_array().unwrap().len(), 1000);
}

#[test]
fn test_eth_get_storage_at_always_empty_but_validated() {
    use stellereum::evm_adapter as evm;
    let empty = "0x0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(evm::EMPTY_STORAGE_VALUE_HEX, empty);

    let addr = "0x407d73d8a49eeb85d32cf465507dd71d507100c1";
    let adapter = EvmAdapter::new();

    // 1. Valid positional params return empty slot (all tags accepted, tag is validated only).
    for tag in ["latest", "earliest", "pending", "finalized", "safe", "0x1"] {
        let got = adapter
            .eth_get_storage_at(&json!([addr, "0x0", tag]))
            .unwrap();
        assert_eq!(got, empty);
    }
    // Without tag defaults to latest.
    assert_eq!(
        adapter.eth_get_storage_at(&json!([addr, "0x01"])).unwrap(),
        empty
    );
    // Object form.
    assert_eq!(
        adapter
            .eth_get_storage_at(
                &json!({ "address": addr, "position": "0x00", "blockTag": "latest" })
            )
            .unwrap(),
        empty
    );
    // Typed direct helper + camelCase aliases.
    assert_eq!(
        adapter
            .eth_get_storage_at_direct(addr, "0x0", "latest")
            .unwrap(),
        empty
    );
    assert_eq!(
        adapter
            .eth_getStorageAt(&json!([addr, "0x0", "latest"]))
            .unwrap(),
        empty
    );
    assert_eq!(
        evm::eth_get_storage_at(&json!([addr, "0x0", "latest"])).unwrap(),
        empty
    );
    assert_eq!(
        evm::eth_getStorageAt(&json!([addr, "0x0", "latest"])).unwrap(),
        empty
    );

    // 2. Dispatch wiring.
    assert_eq!(
        adapter
            .dispatch("eth_getStorageAt", &json!([addr, "0x0", "latest"]))
            .unwrap(),
        json!(empty)
    );

    // 3. Raw JSON-RPC shape.
    let raw = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_getStorageAt","params":["{addr}","0x0","latest"],"id":9}}"#
    );
    let resp_raw = adapter.handle_raw_json(&raw);
    let resp: JsonRpcResponse<String> = serde_json::from_str(&resp_raw).unwrap();
    assert_eq!(resp.id, json!(9));
    assert_eq!(resp.result.unwrap(), empty);

    // 4. Validation: bad address / position / tag -> -32602, never a fabricated value.
    assert_eq!(
        adapter
            .dispatch("eth_getStorageAt", &json!(["0xbad", "0x0", "latest"]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch(
                "eth_getStorageAt",
                &json!([
                    addr,
                    "0x123456789012345678901234567890123456789012345678901234567890123456789",
                    "latest"
                ])
            )
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch("eth_getStorageAt", &json!([addr, "nothex", "latest"]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch("eth_getStorageAt", &json!([addr, "0x0", "bogus"]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
    assert_eq!(
        adapter
            .dispatch("eth_getStorageAt", &json!([]))
            .unwrap_err()
            .code,
        INVALID_PARAMS_CODE
    );
}

#[tokio::test]
async fn test_eth_get_logs_and_storage_via_rpc_layer() {
    use stellereum::evm_adapter as evm;
    let st = test_rpc_state_with_height(10).await;

    // Honest emptiness on a fresh node: isolated address filter matches nothing
    // (Stell receipts carry no logs; global logs from other tests use other addresses).
    let isolated = "0xcccccccccccccccccccccccccccccccccccccccc";
    let empty_logs = st
        .call("eth_getLogs", json!([{ "address": isolated }]))
        .await;
    assert_eq!(empty_logs, json!([]));

    // Storage via RPC dispatch returns the empty slot.
    let addr = "0x407d73d8a49eeb85d32cf465507dd71d507100c1";
    let stored = st
        .call("eth_getStorageAt", json!([addr, "0x0", "latest"]))
        .await;
    assert_eq!(stored, json!(evm::EMPTY_STORAGE_VALUE_HEX));

    // Direct RpcState methods (both casings) agree.
    assert_eq!(
        st.eth_get_logs(&json!([{ "address": isolated }]))
            .await
            .unwrap(),
        json!([])
    );
    assert_eq!(
        st.eth_getLogs(&json!([{ "address": isolated }]))
            .await
            .unwrap(),
        json!([])
    );
    assert_eq!(
        st.eth_get_storage_at(&json!([addr, "0x0", "latest"]))
            .await
            .unwrap(),
        evm::EMPTY_STORAGE_VALUE_HEX
    );
    assert_eq!(
        st.eth_getStorageAt(&json!([addr, "0x0", "latest"]))
            .await
            .unwrap(),
        evm::EMPTY_STORAGE_VALUE_HEX
    );

    // dispatch_with_state merges the same way (isolated filter -> []).
    let adapter = EvmAdapter::new();
    let via_state = adapter
        .dispatch_with_state(&st, "eth_getLogs", &json!([{ "address": isolated }]))
        .await
        .unwrap();
    assert_eq!(via_state, json!([]));
    let stored_state = adapter
        .dispatch_with_state(&st, "eth_getStorageAt", &json!([addr, "0x0", "latest"]))
        .await
        .unwrap();
    assert_eq!(stored_state, json!(evm::EMPTY_STORAGE_VALUE_HEX));

    // RPC-level errors surface as {"error": ...} through the call helper.
    let bad = st
        .call("eth_getStorageAt", json!(["0xbad", "0x0", "latest"]))
        .await;
    assert!(bad.get("error").is_some());
}

// ============================================================================
// B-VM audit PoCs (read-only, no behavior change). Each test PASSES on the
// current code by demonstrating the flaw; the secure behavior would REJECT.
// ============================================================================

#[test]
fn bvm_poc_estimate_gas_unbounded_calldata_is_accepted() {
    use stellereum::evm_adapter as evm;
    // 100k zero bytes of calldata: no length cap in eth_estimate_gas_amount
    // (src/evm_adapter.rs:4388-4405); the node hex-decodes + sums it all.
    let big = format!("0x{}", "00".repeat(100_000));
    let params = json!([{ "to": "0x0000000000000000000000000000000000000001", "data": big }]);
    let res = evm::eth_estimate_gas_amount(&params).unwrap();
    assert!(
        res > 400_000,
        "unbounded calldata priced without cap: {res}"
    );
}

#[test]
fn bvm_poc_short_calldata_word_is_zero_padded_not_rejected() {
    use stellereum::evm_adapter as evm;
    // FIXED (audit B-VM): short words refuse (EVM requires 32-byte words).
    let got = evm::extract_address_from_calldata("1234");
    assert_eq!(got, None);
    // ... so balanceOf on a short word reverts (empty) instead of answering.
    let out = evm::EvmAdapter::new().emulate_erc20_call("0x70a082311234");
    assert_eq!(out, "0x", "short balanceOf word must revert, not answer");
}

#[test]
fn bvm_poc_secp_prefix_aliasing_accepts_nonzero_prefix() {
    use stellereum::evm_adapter as evm;
    let privkey =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
    let secp_key = k256::ecdsa::SigningKey::from_slice(&privkey).unwrap();
    let sender20 =
        evm::pubkey_to_address(secp_key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    // Honest zero-prefixed sender; the signature is made OVER these bytes.
    let mut from_zero = [0u8; 32];
    from_zero[12..32].copy_from_slice(&sender20);
    let evm_hash = format!("0x{}", hex::encode([0xABu8; 32]));
    let evm_bytes = evm::parse_hash_bytes(&evm_hash).unwrap();
    let unsigned = stellereum::sharding::Transaction {
        from: from_zero,
        to: [0xAA; 32],
        amount: 0,
        gas_limit: 21_000,
        nonce: 4242,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let sighash = evm::keccak256(&unsigned.signing_message());
    let (sig, recid) = secp_key.sign_prehash_recoverable(&sighash).unwrap();
    let raw = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);
    let mut recid_byte = recid.to_byte();
    if !evm::is_low_s(&s) {
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = evm::SECP256K1_N[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        s = out;
        recid_byte ^= 1;
    }
    let mut envelope = Vec::with_capacity(evm::SECP_ENVELOPE_LEN);
    envelope.extend_from_slice(evm::SECP_ENVELOPE_MAGIC);
    envelope.extend_from_slice(&evm_bytes);
    envelope.extend_from_slice(&r);
    envelope.extend_from_slice(&s);
    envelope.push(recid_byte);
    let tx_alias = stellereum::sharding::Transaction {
        from: from_zero,
        to: [0xAA; 32],
        amount: 0,
        gas_limit: 21_000,
        nonce: 4242,
        source_shard: 0,
        target_shard: 0,
        signature: envelope,
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    // Control: honest zero-prefixed sender verifies.
    assert!(
        evm::verify_secp_settlement(&tx_alias).is_ok(),
        "zero-prefixed same key must verify"
    );
    // Attack: same low-20 bytes, hostile 12-byte prefix over the SIGNED bytes.
    let mut from_alias = [0xFFu8; 32];
    from_alias[12..32].copy_from_slice(&sender20);
    let tx_spoofed = stellereum::sharding::Transaction {
        from: from_alias,
        ..tx_alias.clone()
    };
    assert!(
        evm::verify_secp_settlement(&tx_spoofed).is_err(),
        "FIXED (audit B-VM): non-zero Stell prefix must refuse (aliasing closed)"
    );
}

#[test]
fn bvm_poc_wei_truncation_and_verbatim_gas_below_floor() {
    use stellereum::evm_adapter as evm;
    // wei_to_nano truncates sub-nano to ZERO — documented, the only safe
    // direction (rounding up would CREATE value). Pinned, not changed.
    assert_eq!(evm::wei_to_nano(1), 0);
    assert_eq!(evm::wei_to_nano(999_999_999), 0);
    // FIXED (audit B-VM): served estimates honor the RPC.md contract
    // (max(pure EVM figure, admission floor)) so forwarded figures are
    // never rejected for under-declared gas. Pure helpers stay pure
    // (pinned by closeout); the floor lives in the served path.
    let params = json!([{ "to": "0x0000000000000000000000000000000000000001" }]);
    let est = evm::eth_estimate_gas(&params).unwrap();
    assert_eq!(est, "0x445c0");
    assert!(
        evm::eth_estimate_gas_amount(&params).unwrap() < stellereum::svm::GAS_BASIC_TRANSFER,
        "pure figure stays unfloored underneath"
    );
}
