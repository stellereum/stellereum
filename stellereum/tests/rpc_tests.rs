//! Targeted tests for RPC hardening, EVM adapter compatibility, and filter manager invariants.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use stellereum::evm_adapter::{
    self as evm, EvmLog, FilterCriteria, FilterManager, CHAIN_ID, CHAIN_ID_HEX, FILTER_TTL_SECS,
    MAX_ACTIVE_FILTERS, MAX_PENDING_PER_FILTER, NET_VERSION, STANDARD_TRANSFER_GAS,
    STANDARD_TRANSFER_GAS_HEX,
};
use stellereum::explorer::{self, GatewayState, ReadinessConfig};
use stellereum::mempool::Mempool;
use stellereum::rpc::{self, ReceiptIndex, RpcState};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::turnstile::CaptchaGate;

async fn http_post_with(
    addr: std::net::SocketAddr,
    path: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("\r\n{body}"));
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (String, String) {
    http_post_with(addr, path, body, &[]).await
}

async fn test_rpc_state(auth_token: Option<String>) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "inf1:test_node".to_string(),
        chain_id: CHAIN_ID,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

#[tokio::test]
async fn test_evm_chain_id_and_net_version() {
    // Invariant: chain ID is 5757 (0x167d), net_version is "5757"
    assert_eq!(CHAIN_ID, 5757);
    assert_eq!(CHAIN_ID_HEX, "0x167d");
    assert_eq!(NET_VERSION, "5757");

    assert_eq!(evm::eth_chain_id(), "0x167d");
    assert_eq!(evm::net_version(), "5757");

    let adapter = evm::EvmAdapter::new();
    let res_chain = adapter
        .dispatch("eth_chainId", &Value::Null)
        .expect("eth_chainId");
    assert_eq!(res_chain, json!("0x167d"));

    let res_net = adapter
        .dispatch("net_version", &Value::Null)
        .expect("net_version");
    assert_eq!(res_net, json!("5757"));
}

#[tokio::test]
async fn test_evm_block_number() {
    let st = test_rpc_state(None).await;
    let bnum = evm::eth_block_number_rpc(&st);
    assert_eq!(bnum, "0x64"); // 100 in hex

    st.height.store(5757, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(evm::eth_block_number_rpc(&st), "0x167d");
}

#[tokio::test]
async fn test_evm_get_balance() {
    let st = test_rpc_state(None).await;
    let user_bytes = [7u8; 32];
    // 5 STELL = 5_000_000_000 nanoSTELL = 5 * 10^18 Wei
    let nano_bal = 5_000_000_000u64;
    st.engine
        .update_account(AccountState::new(user_bytes, nano_bal))
        .await;

    let hex_addr = format!("0x{}", hex::encode(user_bytes));
    let params = json!([hex_addr, "latest"]);

    let bal_hex = evm::eth_get_balance_rpc(&st, &params)
        .await
        .expect("get balance");
    // 5 * 10^18 = 0x4563918244f40000
    assert_eq!(bal_hex, "0x4563918244f40000");

    // Zero balance for unknown account
    let empty_addr = format!("0x{}", hex::encode([9u8; 32]));
    let empty_bal = evm::eth_get_balance_rpc(&st, &json!([empty_addr, "latest"]))
        .await
        .expect("empty balance");
    assert_eq!(empty_bal, "0x0");
}

#[tokio::test]
async fn test_evm_call_erc20_stubs() {
    let adapter = evm::EvmAdapter::new();

    // 1. ERC-20 transfer (0xa9059cbb) -> EMPTY: no EVM interpreter exists,
    // so a state-changing call is never reported as successful (F2).
    let transfer_calldata = format!("0xa9059cbb{:0>64}{:0>64}", "11223344", "100");
    let res_transfer = adapter
        .dispatch(
            "eth_call",
            &json!([{ "data": transfer_calldata }, "latest"]),
        )
        .expect("transfer stub");
    assert_eq!(res_transfer, json!("0x"));

    // 2. ERC-20 approve (0x095ea7b3) -> EMPTY, never `true` (F2)
    let approve_calldata = format!("0x095ea7b3{:0>64}{:0>64}", "11223344", "ffff");
    let res_approve = adapter
        .dispatch("eth_call", &json!([{ "data": approve_calldata }, "latest"]))
        .expect("approve stub");
    assert_eq!(res_approve, json!("0x"));

    // 3. ERC-20 allowance (0xdd62ed3e) -> EMPTY: no approvals are stored, so
    // an infinite approval is never invented (F2)
    let allowance_calldata = format!("0xdd62ed3e{:0>64}{:0>64}", "11223344", "55667788");
    let res_allowance = adapter
        .dispatch(
            "eth_call",
            &json!([{ "data": allowance_calldata }, "latest"]),
        )
        .expect("allowance stub");
    assert_eq!(res_allowance, json!("0x"));
    assert_ne!(
        res_allowance,
        json!("0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    );

    // 4. Unknown selector -> "0x"
    let unknown_calldata = "0xdeadbeef00000000";
    let res_unknown = adapter
        .dispatch("eth_call", &json!([{ "data": unknown_calldata }, "latest"]))
        .expect("unknown selector");
    assert_eq!(res_unknown, json!("0x"));
}

#[tokio::test]
async fn test_evm_estimate_gas_21k() {
    assert_eq!(STANDARD_TRANSFER_GAS, 21_000);
    assert_eq!(STANDARD_TRANSFER_GAS_HEX, "0x5208");

    let adapter = evm::EvmAdapter::new();

    // Standard transfer with empty params or simple object -> 21,000 ("0x5208")
    // F4 design (audit closure): the SERVED eth_estimateGas path applies the
    // 280k admission floor, so it returns 0x445c0, not pure 0x5208. The pure
    // amount lives in eth_estimate_gas_amount (pinned elsewhere).
    let est_empty = adapter
        .dispatch("eth_estimateGas", &json!([]))
        .expect("empty estimate");
    assert_eq!(est_empty, json!("0x445c0"));

    let est_tx = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "value": "0x1000"
            }]),
        )
        .expect("transfer estimate");
    assert_eq!(est_tx, json!("0x445c0"));

    // Calldata gas: pure would be 21,000 + 4 * 16 = 21,064 = 0x5248, but the
    // served path floors at 0x445c0 (F4) and pure < floor, so floor wins.
    let est_call = adapter
        .dispatch(
            "eth_estimateGas",
            &json!([{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0xdeadbeef"
            }]),
        )
        .expect("calldata estimate");
    assert_eq!(est_call, json!("0x445c0"));
}

#[tokio::test]
async fn test_filter_manager_security_invariants() {
    assert_eq!(FILTER_TTL_SECS, 300);
    assert_eq!(MAX_PENDING_PER_FILTER, 1_000);
    assert_eq!(MAX_ACTIVE_FILTERS, 10_000);

    let fm = FilterManager::new();

    // 1. Cryptographic 64-bit random filter IDs
    let id1 = fm.new_block_filter();
    let id2 = fm.new_pending_transaction_filter();
    let id3 = fm.new_filter(FilterCriteria::default());

    assert!(id1.starts_with("0x"));
    assert!(id2.starts_with("0x"));
    assert!(id3.starts_with("0x"));
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);

    // 2. Pending queue bounds (MAX_PENDING_PER_FILTER = 1,000)
    for i in 0..1200 {
        fm.notify_block_hash(format!("0x{:064x}", i));
    }
    let changes = fm.get_filter_changes(&id1).expect("changes");
    let arr = changes.as_array().expect("array");
    assert_eq!(arr.len(), 1_000, "pending blocks must be capped to 1000");

    // 3. Log filter pending queue bounds
    for i in 0..1100 {
        fm.notify_log(EvmLog {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            topics: vec![],
            data: format!("0x{:x}", i),
            block_number: Some("0x1".to_string()),
            transaction_hash: Some("0xabc".to_string()),
            transaction_index: Some("0x0".to_string()),
            block_hash: Some("0xdef".to_string()),
            log_index: Some(format!("0x{:x}", i)),
            removed: false,
        });
    }
    let log_changes = fm.get_filter_changes(&id3).expect("log changes");
    assert_eq!(
        log_changes.as_array().unwrap().len(),
        1_000,
        "pending logs capped to 1000"
    );

    // 4. Uninstall filter
    assert!(fm.uninstall_filter(&id1));
    assert!(
        fm.get_filter_changes(&id1).is_err(),
        "uninstalled filter must return error"
    );
}

#[tokio::test]
async fn test_rpc_hardening_body_limit_and_batches() {
    let st = test_rpc_state(None).await;
    let app = rpc::router(st);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // 1. Normal request passes
    let valid_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": []
    });
    let (head, body) = http_post(addr, "/", &valid_req.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    let res: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(res["result"], "0x167d");

    // 2. Batch requests are SERVED per-item (JSON-RPC batch support with
    // caps: MAX_RPC_BATCH_ITEMS=64, bytes<=MAX_RPC_BODY). One-item batch of
    // a valid call returns an array with that call's result.
    let batch_req = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [] }
    ]);
    let (_, body_batch) = http_post(addr, "/", &batch_req.to_string()).await;
    let res_batch: Value = serde_json::from_str(&body_batch).unwrap();
    assert!(res_batch.is_array(), "batch must return an array");
    assert_eq!(res_batch[0]["result"], "0x167d");
    assert_eq!(res_batch[0]["id"], 1);

    // 3. Body exceeding 1 MiB is rejected
    // 1 MiB + 100 bytes payload
    let giant_str = "x".repeat(1024 * 1024 + 100);
    let giant_req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["{}"]}}"#,
        giant_str
    );
    let (head_giant, _) = http_post(addr, "/", &giant_req).await;
    // DefaultBodyLimit in Axum rejects oversized requests before buffering (413 Payload Too Large)
    assert!(
        head_giant.contains("413") || head_giant.contains("400"),
        "Oversized request must be rejected, got response headers:\n{head_giant}"
    );
}

#[tokio::test]
async fn test_fail_closed_mempool_dump() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 1. When auth_token is None -> FAIL-CLOSED
    let st_no_auth = test_rpc_state(None).await;
    let app_no_auth = rpc::router(st_no_auth);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app_no_auth.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "stell_mempoolDump",
        "params": {}
    });
    let (_, body) = http_post(addr, "/", &req.to_string()).await;
    let res: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(res["error"]["code"], -32001);
    assert!(
        res["error"]["message"]
            .as_str()
            .unwrap()
            .contains("disabled when auth_token is not configured"),
        "mempoolDump must fail closed without auth_token"
    );

    // 2. When auth_token is configured -> unauthorized with bad token
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let st_auth = test_rpc_state(Some("supersecret".to_string())).await;
    let app_auth = rpc::router(st_auth);
    tokio::spawn(async move {
        axum::serve(
            listener2,
            app_auth.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let req_bad = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "stell_mempoolDump",
        "params": { "token": "wrongtoken" }
    });
    let (_, body_bad) = http_post(addr2, "/", &req_bad.to_string()).await;
    let res_bad: Value = serde_json::from_str(&body_bad).unwrap();
    assert_eq!(res_bad["error"]["code"], -32001);
    assert!(res_bad["error"]["message"]
        .as_str()
        .unwrap()
        .contains("invalid API token"));

    // 3. Authorized request succeeds
    let req_good = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "stell_mempoolDump",
        "params": { "token": "supersecret" }
    });
    let (_, body_good) = http_post(addr2, "/", &req_good.to_string()).await;
    let res_good: Value = serde_json::from_str(&body_good).unwrap();
    assert!(res_good["result"].is_array());
}

#[tokio::test]
async fn test_rpc_cors_headers_on_gateway() {
    let st = test_rpc_state(None).await;
    let gw = Arc::new(GatewayState::with_captcha(
        st,
        1000,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::disabled()),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gw).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": []
    });

    let (head, _) = http_post_with(
        addr,
        "/rpc",
        &req.to_string(),
        &[("Origin", "http://localhost:3000")],
    )
    .await;

    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head
        .to_lowercase()
        .contains("access-control-allow-origin: *"));
    assert!(head
        .to_lowercase()
        .contains("access-control-allow-headers: content-type"));
}

/// FULL-PQ EVM surface: `eth_getCode` reads committed bytecode, `eth_getProof`
/// serves the state trie, and `eth_subscribe` refuses with the missing
/// transport named (never a dead subscription id).
#[tokio::test]
async fn test_evm_read_views_are_state_backed_and_subscribe_refuses() {
    let st = test_rpc_state(None).await;
    let evm20 = [0x4Du8; 20];
    let evm_hex = format!("0x{}", hex::encode(evm20));
    let stell = evm::parse_evm_or_stell_address(&evm_hex).expect("address");

    let mut acc = AccountState::new(stell, 1_000_000_000);
    acc.code = vec![0x60u8, 0x2a, 0x60, 0x00, 0x52];
    st.engine.update_account(acc).await;

    let code = st.call("eth_getCode", json!([evm_hex, "latest"])).await;
    assert_eq!(code, json!("0x602a600052"));

    let proof = st
        .call(
            "eth_getProof",
            json!([format!("0x{}", hex::encode(evm20)), [], "latest"]),
        )
        .await;
    assert!(proof.get("error").is_none(), "proof must serve: {proof}");
    assert!(proof["accountProof"].as_array().is_some());
    assert_eq!(proof["exists"], json!(true));

    let sub = st.call("eth_subscribe", json!(["newHeads"])).await;
    let msg = sub["error"].as_str().unwrap_or("");
    assert!(
        msg.contains("eth_subscription") && msg.contains("stell_subscribe"),
        "subscribe refusal names the gap, got {sub}"
    );
}

#[tokio::test]
async fn test_get_program_accounts_with_proof_no_deadlock_and_exact_proofs() {
    use stellereum::token::{TokenMetadata, TokenOp};

    let st = test_rpc_state(None).await;
    let creator = [0x11u8; 32];
    let holder2 = [0x22u8; 32];

    let metadata = TokenMetadata {
        name: "ProofToken".to_string(),
        symbol: "PRF".to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: Some(1_000_000),
        minter: creator,
        paused: false,
        description: String::new(),
    };
    let token_id = st
        .engine
        .create_token(creator, metadata, 1_000_000)
        .await
        .expect("create token");
    st.engine
        .token_execute(
            &token_id,
            creator,
            TokenOp::Transfer {
                to: holder2,
                amount: 250_000,
            },
        )
        .await
        .expect("transfer token");

    let token_res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        st.call(
            "stell_getProgramAccounts",
            json!({
                "program": "token",
                "token": hex::encode(token_id),
                "with_proof": true,
            }),
        ),
    )
    .await
    .expect("token getProgramAccounts must not deadlock");
    assert!(
        token_res.get("error").is_none(),
        "unexpected token error: {token_res}"
    );
    let token_items = token_res["items"].as_array().expect("token items");
    assert_eq!(token_items.len(), 2);
    for item in token_items {
        let owner_hex = item["owner"].as_str().expect("owner hex");
        let owner_bytes: [u8; 32] = hex::decode(owner_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let expected_proof = serde_json::to_value(
            st.engine
                .get_token_balance_proof(&token_id, &owner_bytes)
                .await,
        )
        .expect("serialize proof");
        assert!(!expected_proof.is_null(), "token balance proof must exist");
        assert_eq!(item["proof"], expected_proof);
    }

    let owner_res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        st.call(
            "stell_getProgramAccounts",
            json!({
                "program": "token",
                "owner": hex::encode(holder2),
                "with_proof": true,
            }),
        ),
    )
    .await
    .expect("owner getProgramAccounts must not deadlock");
    let owner_items = owner_res["items"].as_array().expect("owner items");
    assert_eq!(owner_items.len(), 1);
    let expected_owner_proof =
        serde_json::to_value(st.engine.get_token_balance_proof(&token_id, &holder2).await)
            .expect("serialize proof");
    assert_eq!(owner_items[0]["proof"], expected_owner_proof);

    let wasm = wat::parse_str(
        r#"(module
             (func (export "answer") (result i64)
               (i64.const 42)))"#,
    )
    .expect("compile wat");
    let contract_addr = st
        .engine
        .deploy_contract(creator, wasm.clone(), 1_000)
        .await
        .expect("deploy contract");
    st.engine
        .update_account(AccountState::new(contract_addr, 50_000))
        .await;

    let contract_res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        st.call(
            "stell_getProgramAccounts",
            json!({
                "program": "contract",
                "creator": hex::encode(creator),
                "with_proof": true,
                "include_code": true,
            }),
        ),
    )
    .await
    .expect("contract getProgramAccounts must not deadlock");
    assert!(
        contract_res.get("error").is_none(),
        "unexpected contract error: {contract_res}"
    );
    let contract_items = contract_res["items"].as_array().expect("contract items");
    assert_eq!(contract_items.len(), 1);
    assert_eq!(contract_items[0]["code"], json!(hex::encode(&wasm)));
    let expected_acct_proof =
        serde_json::to_value(st.engine.get_account_proof(&contract_addr).await)
            .expect("serialize account proof");
    assert!(!expected_acct_proof.is_null(), "account proof must exist");
    assert_eq!(contract_items[0]["proof"], expected_acct_proof);
}

#[tokio::test]
async fn test_preview_contract_call_parity_with_heavy_unrelated_contracts() {
    use stellereum::contract::Contract;
    use stellereum::rpc::BlockSummary;

    let wasm = wat::parse_str(
        r#"(module
             (import "host" "sload" (func $sload (param i64) (result i64)))
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (import "host" "emit" (func $emit (param i64 i64)))
             (import "host" "block_time" (func $block_time (result i64)))
             (func (export "inc") (param $key i64) (result i64)
               (local $next i64)
               (local.set $next (i64.add (call $sload (local.get $key)) (i64.const 1)))
               (call $sstore (local.get $key) (local.get $next))
               (call $emit (local.get $key) (local.get $next))
               (i64.add (local.get $next) (call $block_time))))"#,
    )
    .expect("compile wat");

    let creator = [0x33u8; 32];
    let caller = [0x44u8; 32];
    let st_clean = test_rpc_state(Some("test-token".to_string())).await;
    let st_heavy = test_rpc_state(Some("test-token".to_string())).await;

    let summary = BlockSummary {
        height: 100,
        hash: hex::encode([0xAAu8; 32]),
        tx_count: 1,
        timestamp: 1_700_000_123,
    };
    st_clean
        .recent_blocks
        .write()
        .await
        .push_front(summary.clone());
    st_heavy.recent_blocks.write().await.push_front(summary);

    let target_clean = st_clean
        .engine
        .deploy_contract(creator, wasm.clone(), 1_700_000_000)
        .await
        .expect("deploy clean");
    let target_heavy = st_heavy
        .engine
        .deploy_contract(creator, wasm, 1_700_000_000)
        .await
        .expect("deploy heavy");
    assert_eq!(target_clean, target_heavy);

    {
        let mut reg = st_heavy.engine.contracts_write().await;
        for i in 0u8..16 {
            let mut addr = [0x80u8; 32];
            addr[31] = i;
            let mut storage = std::collections::HashMap::new();
            for slot in 0i64..100 {
                storage.insert(slot, slot * 7);
            }
            reg.contracts.insert(
                addr,
                Contract {
                    address: addr,
                    creator: [0x99u8; 32],
                    code_hash: [i; 32],
                    code: vec![0xAAu8; 64 * 1024],
                    storage,
                    created_at: 1_600_000_000,
                    paused: false,
                    balance: 1_000_000,
                    abi: None,
                    source_hash: None,
                },
            );
            reg.next_nonce = reg.next_nonce.saturating_add(1);
        }
    }

    let req = json!({
        "token": "test-token",
        "contract": hex::encode(target_clean),
        "method": "inc",
        "args": [7],
        "caller": hex::encode(caller),
    });
    let res_clean = st_clean.call("stell_callContract", req.clone()).await;
    let res_heavy = st_heavy.call("stell_callContract", req).await;

    assert_eq!(res_clean, res_heavy);
    assert_eq!(res_heavy["status"], json!("success"));
    assert_eq!(res_heavy["return_value"], json!(1_700_000_124i64));
    assert_eq!(res_heavy["preview_only"], json!(true));
    assert_eq!(res_heavy["mined"], json!(false));
    assert_eq!(res_heavy["events"].as_array().expect("events").len(), 1);
    assert!(
        st_heavy
            .engine
            .get_contract(&target_heavy)
            .await
            .expect("target exists")
            .storage
            .is_empty(),
        "preview must not mutate live contract storage"
    );
}

#[tokio::test]
async fn test_eth_get_logs_height_range_filtering_accuracy() {
    use stellereum::evm_adapter::{EvmAdapter, EvmReceipt, EMPTY_LOGS_BLOOM};
    use stellereum::rpc::TxReceipt;

    let st = test_rpc_state(None).await;
    {
        let mut idx = st.receipts.write().await;
        for (i, h) in [1u64, 2, 3, 3, 4, 5, 6].into_iter().enumerate() {
            let mut tx_hash = [0u8; 32];
            tx_hash[0] = (i + 1) as u8;
            let mut block_hash = [0u8; 32];
            block_hash[0] = h as u8;
            if i == 3 {
                block_hash[1] = 0xEE;
            }
            idx.insert(TxReceipt {
                tx_hash,
                height: h,
                block_hash,
                index: i as u32,
                success: true,
                gas_limit: 21_000,
                fee_charged: 21_000,
                raw_tx: None,
                return_value: None,
                gas_used: Some(21_000),
                events: Vec::new(),
                contract_address: None,
            });
        }
        let range_heights: Vec<u64> = idx.by_height.range(2..=4).map(|(h, _)| *h).collect();
        assert_eq!(range_heights, vec![2, 3, 4]);
        assert_eq!(idx.by_height.get(&3).map(Vec::len), Some(2));
    }

    let isolated = "0xde17a710a710a710a710a710a710a710a710a717";
    for query in [
        json!([{ "address": isolated, "fromBlock": "0x2", "toBlock": "0x4" }]),
        json!([{ "address": isolated, "fromBlock": "earliest", "toBlock": "0x3" }]),
        json!([{ "address": isolated, "fromBlock": "0x4", "toBlock": "latest" }]),
        json!([{ "address": isolated, "fromBlock": "0x5", "toBlock": "0x2" }]),
        json!([{
            "address": isolated,
            "blockHash": format!("0x{:02x}{}", 3u8, "00".repeat(31))
        }]),
    ] {
        let res = st
            .eth_get_logs(&query)
            .await
            .expect("eth_get_logs succeeds");
        assert_eq!(res, json!([]));
    }

    let mut adapter = EvmAdapter::new();
    for b in 1u64..=5 {
        let tx_hash = format!("0x{:064x}", b);
        let block_hash = format!("0x{:064x}", b + 0x100);
        let block_hex = format!("0x{:x}", b);
        adapter.insert_receipt(EvmReceipt {
            transaction_hash: tx_hash.clone(),
            transaction_index: "0x0".to_string(),
            block_hash: block_hash.clone(),
            block_number: block_hex.clone(),
            from: "0x1111111111111111111111111111111111111111".to_string(),
            to: Some(isolated.to_string()),
            cumulative_gas_used: "0x5208".to_string(),
            gas_used: "0x5208".to_string(),
            contract_address: None,
            logs: vec![EvmLog {
                address: isolated.to_string(),
                topics: vec![format!("0x{:064x}", b)],
                data: "0x".to_string(),
                block_number: Some(block_hex),
                transaction_hash: Some(tx_hash),
                transaction_index: Some("0x0".to_string()),
                block_hash: Some(block_hash),
                log_index: Some("0x0".to_string()),
                removed: false,
            }],
            logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
            status: Some("0x1".to_string()),
            root: None,
            tx_type: Some("0x0".to_string()),
            effective_gas_price: Some("0x1".to_string()),
            blob_gas_used: None,
            blob_gas_price: None,
        });
    }

    let mid = adapter
        .eth_get_logs(&json!([{ "address": isolated, "fromBlock": "0x2", "toBlock": "0x4" }]))
        .expect("bounded range");
    let mid_blocks: Vec<&str> = mid
        .as_array()
        .expect("array")
        .iter()
        .map(|l| l["blockNumber"].as_str().expect("blockNumber"))
        .collect();
    assert_eq!(mid_blocks, vec!["0x2", "0x3", "0x4"]);

    let early = adapter
        .eth_get_logs(&json!([{ "address": isolated, "fromBlock": "earliest", "toBlock": "0x2" }]))
        .expect("earliest to 0x2");
    let early_blocks: Vec<&str> = early
        .as_array()
        .expect("array")
        .iter()
        .map(|l| l["blockNumber"].as_str().expect("blockNumber"))
        .collect();
    assert_eq!(early_blocks, vec!["0x1", "0x2"]);

    let tail = adapter
        .eth_get_logs(&json!([{ "address": isolated, "fromBlock": "0x4", "toBlock": "latest" }]))
        .expect("0x4 to latest");
    let tail_blocks: Vec<&str> = tail
        .as_array()
        .expect("array")
        .iter()
        .map(|l| l["blockNumber"].as_str().expect("blockNumber"))
        .collect();
    assert_eq!(tail_blocks, vec!["0x4", "0x5"]);

    let inverted = adapter
        .eth_get_logs(&json!([{ "address": isolated, "fromBlock": "0x5", "toBlock": "0x2" }]))
        .expect("inverted range");
    assert_eq!(inverted, json!([]));
}
