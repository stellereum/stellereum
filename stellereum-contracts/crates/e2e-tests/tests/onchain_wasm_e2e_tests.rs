//! End-to-End Onchain Integration Tests for Rust-Compiled WASM Contracts in Stellereum VM

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

async fn funded_engine() -> (InMemoryStateEngine, SigningKey, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let sk = SigningKey::generate(&mut OsRng);
    let addr = sk.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(addr, 10_000_000_000_000))
        .await;
    (engine, sk, addr)
}

fn deploy_tx(sk: &SigningKey, nonce: u64, code: Vec<u8>) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        [0u8; 32],
        0,
        10_000_000,
        nonce,
        1,
        1,
        vec![OpCode::SysCallDeployContract { code }],
    )
}

fn call_tx(sk: &SigningKey, nonce: u64, contract: [u8; 32], method: &str, arg: i64) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        [0u8; 32],
        0,
        10_000_000,
        nonce,
        1,
        1,
        vec![OpCode::SysCallCallContract {
            contract,
            method: method.as_bytes().to_vec(),
            arg,
        }],
    )
}

fn load_wasm(name: &str) -> Vec<u8> {
    let p1 = format!("target/wasm32-unknown-unknown/release/{name}.wasm");
    let p2 = format!("../../target/wasm32-unknown-unknown/release/{name}.wasm");
    if let Ok(bytes) = fs::read(&p1) {
        bytes
    } else {
        fs::read(&p2).unwrap_or_else(|_| panic!("Failed to find {name}.wasm at {p1} or {p2}"))
    }
}

#[tokio::test]
#[allow(clippy::identity_op)] // GATE: `id * BASE + ...` names the packed leading field; `1 *` is intentional.
                              // (pre-existing idiom across these pins)
async fn test_rust_wasm_stl_dns_onchain() {
    let (engine, sk, _) = funded_engine().await;

    // Load Rust-compiled WASM binary
    let wasm_code = load_wasm("stl_dns");

    // Deploy contract
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "Deployment must succeed");
    let contract_addr = engine.all_contract_addresses().await[0];

    // Initialize with Treasury Account 99
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, contract_addr, "init", 99)], 0)
        .await;
    assert_eq!(applied, 1);

    // TON Auction Grid: check get_min_bid(4) -> 200, get_min_bid(3) -> -1
    let (bid4, _) = engine
        .call_contract(&contract_addr, "get_min_bid", 4, 100_000)
        .await
        .unwrap();
    assert_eq!(bid4, 200);

    let (bid3, _) = engine
        .call_contract(&contract_addr, "get_min_bid", 3, 100_000)
        .await
        .unwrap();
    assert_eq!(bid3, -1);

    // Start auction for domain_id 1 (4-letter domain 'star.stl', bidder 10)
    let start_arg = 1 * 10_000_000_000 + 10 * 100_000 + 4;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(&sk, 2, contract_addr, "start_auction", start_arg)],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Check hue: (1 * 137) % 360 = 137
    let (hue, _) = engine
        .call_contract(&contract_addr, "get_hue", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(hue, 137);

    // Place counter-bid: bidder 20 outbids with +10% -> 220
    let bid_arg = 1 * 10_000_000_000 + 20 * 10_000 + 1;
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 3, contract_addr, "place_bid", bid_arg)], 0)
        .await;
    assert_eq!(applied, 1);

    // Finalize auction
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 4, contract_addr, "finalize_auction", 1)], 0)
        .await;
    assert_eq!(applied, 1);

    // Verify resolve -> User 20
    let (winner, _) = engine
        .call_contract(&contract_addr, "resolve", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(winner, 20);

    // Test canonical reserved burn domain (burn.stl) and vault.stl
    let burn_id = stellereum_contract_sdk::address::DOMAIN_BURN;
    let (burn_target, _) = engine
        .call_contract(&contract_addr, "resolve", burn_id, 100_000)
        .await
        .unwrap();
    assert_eq!(
        burn_target, 0,
        "System burn domain must resolve to Black Hole 0"
    );

    let vault_id = stellereum_contract_sdk::address::DOMAIN_VAULT;
    let (vault_target, _) = engine
        .call_contract(&contract_addr, "resolve", vault_id, 100_000)
        .await
        .unwrap();
    assert_eq!(
        vault_target, 99,
        "Protocol vault must resolve to Treasury 99"
    );
}

#[tokio::test]
#[allow(clippy::identity_op)] // GATE: `id * BASE + ...` names the packed leading field; `1 *` is intentional.
                              // (pre-existing idiom across these pins)
async fn test_rust_wasm_sts20_token_onchain() {
    let (engine, sk, _) = funded_engine().await;

    let wasm_code = load_wasm("sts20_token");

    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0));
    let contract_addr = engine.all_contract_addresses().await[0];

    // Init 1,000,000 tokens
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, contract_addr, "init", 1_000_000)], 0)
        .await;
    assert_eq!(applied, 1);

    let (supply, _) = engine
        .call_contract(&contract_addr, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(supply, 1_000_000);

    // CT-P0: transfer binds from_id to the authenticated host.caller; a plain
    // tx signer is never the canonical id address, so the move is refused
    // (ERR_UNAUTHORIZED return — the tx applies but nothing moves). Exact fee
    // math is pinned natively (token lifecycle with mock caller).
    let transfer_arg = 1 * 100_000_000 + 2 * 100_000 + 10_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(&sk, 2, contract_addr, "transfer", transfer_arg)],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    let (bal2, _) = engine
        .call_contract(&contract_addr, "balance_of", 2, 100_000)
        .await
        .unwrap();
    assert_eq!(bal2, 0, "CT-P0: refused transfer credits nothing");

    let (bal_treasury, _) = engine
        .call_contract(&contract_addr, "balance_of", 99, 100_000)
        .await
        .unwrap();
    assert_eq!(bal_treasury, 0, "CT-P0: refused transfer accrues no fee");

    let (bal1, _) = engine
        .call_contract(&contract_addr, "balance_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(bal1, 1_000_000, "CT-P0: refused transfer debits nothing");
}

#[tokio::test]
#[allow(clippy::identity_op)] // GATE: `id * BASE + ...` names the packed leading field; `1 *` is intentional.
                              // (pre-existing idiom across these pins)
async fn test_rust_wasm_liquidity_pool_onchain() {
    let (engine, sk, _) = funded_engine().await;

    let wasm_code = load_wasm("liquidity_pool");
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0));
    let pool = engine.all_contract_addresses().await[0];

    // Init with 30 BPS (0.3%) fee
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, pool, "init", 30)], 0)
        .await;
    assert_eq!(applied, 1);

    // CT-P0: deposit binds user_id to the authenticated host.caller; a plain
    // tx signer is never the canonical id address, so funding is refused
    // (ERR_UNAUTHORIZED return — the tx applies but nothing moves). Exact
    // share math is pinned natively (pool lifecycle with mock caller).
    let dep_arg = 1 * 10_000_000_000 + 10_000 * 100_000 + 40_000;
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 2, pool, "deposit", dep_arg)], 0)
        .await;
    assert_eq!(applied, 1);

    let (res_a, _) = engine
        .call_contract(&pool, "get_reserve_a", 0, 100_000)
        .await
        .unwrap();
    let (res_b, _) = engine
        .call_contract(&pool, "get_reserve_b", 0, 100_000)
        .await
        .unwrap();
    let (shares, _) = engine
        .call_contract(&pool, "shares_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(res_a, 0, "CT-P0: refused deposit funds nothing");
    assert_eq!(res_b, 0, "CT-P0: refused deposit funds nothing");
    assert_eq!(shares, 0, "CT-P0: refused deposit mints no shares");

    // Swap quote for 1,000 Token A on the empty pool: exact zero.
    let (quote, _) = engine
        .call_contract(&pool, "swap_quote", 1_000, 100_000)
        .await
        .unwrap();
    assert_eq!(quote, 0);

    // Execute swap: refused on the empty pool, reserves untouched.
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 3, pool, "swap_a_for_b", 1_000)], 0)
        .await;
    assert_eq!(applied, 1);

    let (res_a_after, _) = engine
        .call_contract(&pool, "get_reserve_a", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(res_a_after, 0);
}

#[tokio::test]
#[allow(clippy::identity_op)] // GATE: `id * BASE + ...` names the packed leading field; `1 *` is intentional.
                              // (pre-existing idiom across these pins)
async fn test_rust_wasm_account_object_onchain() {
    let (engine, sk, _) = funded_engine().await;

    let wasm_code = load_wasm("account_object");
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0));
    let aa = engine.all_contract_addresses().await[0];

    // Init for Owner 42
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, aa, "init", 42)], 0)
        .await;
    assert_eq!(applied, 1);

    let (owner, _) = engine
        .call_contract(&aa, "get_owner", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(owner, 42);

    // Create session 1 with 50,000 budget
    let s_arg = 1 * 10_000_000_000 + 10 * 100_000 + 50_000;
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 2, aa, "create_session", s_arg)], 0)
        .await;
    assert_eq!(applied, 1);

    // Spend 12,000 -> 38,000 left
    let spend_arg = 1 * 1_000_000 + 12_000;
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 3, aa, "spend_with_session", spend_arg)], 0)
        .await;
    assert_eq!(applied, 1);

    let (budget_left, _) = engine
        .call_contract(&aa, "get_session_budget", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(budget_left, 38_000);
}
