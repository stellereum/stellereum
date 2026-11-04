//! Comprehensive Integration Tests for Ecosystem Smart Contracts:
//! 1. STS-20 Custom Fungible Token Contract (`sts20_token.wat`)
//! 2. Automated Market Maker Liquidity Pool Contract (`liquidity_pool.wat`)

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use stellereum::cell::PatriciaTrie;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{contract_key, AccountState, InMemoryStateEngine};
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

#[tokio::test]
async fn test_sts20_token_contract_lifecycle() {
    let (engine, sk, _) = funded_engine().await;

    // 1. Read and compile sts20_token.wat
    let wat_src = fs::read_to_string("contracts/sts20_token.wat").expect("sts20_token.wat exists");
    let wasm_code = wat::parse_str(&wat_src).expect("compile sts20_token.wat to wasm");

    // 2. Deploy contract on-chain
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "Contract deployment must succeed"
    );
    assert_eq!(engine.contract_count().await, 1);
    let token_contract = engine.all_contract_addresses().await[0];

    // Verify code hash in state trie
    let root = engine.get_state_root().await;
    let key = contract_key(&token_contract);
    let proof = engine
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&key)
        .expect("merkle proof exists");
    let code_hash = engine
        .get_contract(&token_contract)
        .await
        .unwrap()
        .code_hash;
    assert!(PatriciaTrie::verify_merkle_proof(
        &root, &key, &code_hash, &proof
    ));

    // 3. Initialize Token with 1,000,000 units
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, token_contract, "init", 1_000_000)], 0)
        .await;
    assert_eq!(applied, 1);

    // Verify Total Supply = 1,000,000
    let (total_supply, _) = engine
        .call_contract(&token_contract, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(total_supply, 1_000_000);

    // Verify Admin (Account 1) Balance = 1,000,000
    let (admin_bal, _) = engine
        .call_contract(&token_contract, "balance_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(admin_bal, 1_000_000);

    // 4. Transfer 10,000 tokens from Account 1 to Account 2
    // Packed arg: from_id (1) * 100,000,000 + to_id (2) * 100,000 + amount (10,000) = 100_210_000
    let transfer_arg = 100_000_000 + 2 * 100_000 + 10_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(&sk, 2, token_contract, "transfer", transfer_arg)],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Tax is 50 bps (0.5%): tax on 10,000 = 50 tokens
    // Net transfer to Account 2 = 9,950 tokens
    // Treasury (Account 99) = 50 tokens
    // Admin (Account 1) = 1,000,000 - 10,000 = 990,000 tokens
    let (bal2, _) = engine
        .call_contract(&token_contract, "balance_of", 2, 100_000)
        .await
        .unwrap();
    assert_eq!(
        bal2, 9_950,
        "Recipient must receive 9,950 tokens after 0.5% tax"
    );

    let (treasury_bal, _) = engine
        .call_contract(&token_contract, "balance_of", 99, 100_000)
        .await
        .unwrap();
    assert_eq!(treasury_bal, 50, "Treasury must receive 50 tokens tax");

    let (bal1, _) = engine
        .call_contract(&token_contract, "balance_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(bal1, 990_000, "Sender must have 990,000 tokens remaining");

    // 5. Burn 40,000 tokens from Admin
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 3, token_contract, "burn", 40_000)], 0)
        .await;
    assert_eq!(applied, 1);

    let (new_supply, _) = engine
        .call_contract(&token_contract, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(new_supply, 960_000, "Total supply must decrease to 960,000");

    let (bal1_after_burn, _) = engine
        .call_contract(&token_contract, "balance_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(
        bal1_after_burn, 950_000,
        "Admin balance must decrease by burned amount"
    );

    // 6. Mint 50,000 new tokens to Admin
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 4, token_contract, "mint", 50_000)], 0)
        .await;
    assert_eq!(applied, 1);

    let (supply_after_mint, _) = engine
        .call_contract(&token_contract, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(
        supply_after_mint, 1_010_000,
        "Total supply must increase to 1,010,000"
    );

    let (bal1_after_mint, _) = engine
        .call_contract(&token_contract, "balance_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(
        bal1_after_mint, 1_000_000,
        "Admin balance must increase by minted amount"
    );
}

#[tokio::test]
async fn test_liquidity_pool_amm_contract_lifecycle() {
    let (engine, sk, _) = funded_engine().await;

    // 1. Read and compile liquidity_pool.wat
    let wat_src =
        fs::read_to_string("contracts/liquidity_pool.wat").expect("liquidity_pool.wat exists");
    let wasm_code = wat::parse_str(&wat_src).expect("compile liquidity_pool.wat to wasm");

    // 2. Deploy AMM pool contract
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "AMM deployment must succeed");
    let pool_contract = engine.all_contract_addresses().await[0];

    // 3. Initialize AMM pool with 30 BPS fee (0.3%)
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, pool_contract, "init", 30)], 0)
        .await;
    assert_eq!(applied, 1);

    // 4. Initial Liquidity Deposit from User 1: 10,000 Token A and 40,000 Token B
    // packed encoding: user_id (1) * 10,000,000,000 + amount_a (10,000) * 100,000 + amount_b (40,000)
    let deposit_arg1 = 10_000_000_000 + 10_000 * 100_000 + 40_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(&sk, 2, pool_contract, "deposit", deposit_arg1)],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Initial shares = (10,000 + 40,000) / 2 = 25,000
    let (res_a, _) = engine
        .call_contract(&pool_contract, "get_reserve_a", 0, 100_000)
        .await
        .unwrap();
    let (res_b, _) = engine
        .call_contract(&pool_contract, "get_reserve_b", 0, 100_000)
        .await
        .unwrap();
    let (total_shares, _) = engine
        .call_contract(&pool_contract, "get_total_shares", 0, 100_000)
        .await
        .unwrap();
    let (user1_shares, _) = engine
        .call_contract(&pool_contract, "shares_of", 1, 100_000)
        .await
        .unwrap();

    assert_eq!(res_a, 10_000);
    assert_eq!(res_b, 40_000);
    assert_eq!(total_shares, 25_000);
    assert_eq!(user1_shares, 25_000);

    // 5. Test Constant-Product Swap Quote: swap 1,000 Token A -> Token B
    // x = 10,000, y = 40,000, dx = 1,000, fee = 30 bps (0.3%)
    // dx_net = 1,000 * 9970 / 10000 = 997
    // dy = (40,000 * 997) / (10,000 + 997) = 39,880,000 / 10,997 ≈ 3,626
    let (quote_dy, _) = engine
        .call_contract(&pool_contract, "swap_quote", 1_000, 100_000)
        .await
        .unwrap();
    assert_eq!(
        quote_dy, 3_626,
        "Swap quote must compute constant product output"
    );

    // 6. Execute Swap A -> B with 1,000 Token A
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 3, pool_contract, "swap_a_for_b", 1_000)], 0)
        .await;
    assert_eq!(applied, 1);

    // Verify updated reserves after swap
    let (res_a_post_swap, _) = engine
        .call_contract(&pool_contract, "get_reserve_a", 0, 100_000)
        .await
        .unwrap();
    let (res_b_post_swap, _) = engine
        .call_contract(&pool_contract, "get_reserve_b", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(
        res_a_post_swap, 11_000,
        "Reserve A must increase by 1,000 input tokens"
    );
    assert_eq!(
        res_b_post_swap,
        40_000 - 3_626,
        "Reserve B must decrease by output tokens"
    );

    // 7. Withdraw partial liquidity: User 1 withdraws 5,000 shares (20% of pool)
    // packed: user_id (1) * 1,000,000 + shares (5,000) = 1_005_000
    let withdraw_arg = 1_000_000 + 5_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(&sk, 4, pool_contract, "withdraw", withdraw_arg)],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    let (user1_shares_after, _) = engine
        .call_contract(&pool_contract, "shares_of", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(
        user1_shares_after, 20_000,
        "User must have 20,000 shares remaining"
    );

    let (total_shares_after, _) = engine
        .call_contract(&pool_contract, "get_total_shares", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(
        total_shares_after, 20_000,
        "Total pool shares must decrease by 5,000"
    );
}

#[tokio::test]
async fn test_account_object_smart_account_lifecycle() {
    let (engine, sk, _) = funded_engine().await;

    // 1. Read and compile account_object.wat
    let wat_src =
        fs::read_to_string("contracts/account_object.wat").expect("account_object.wat exists");
    let wasm_code = wat::parse_str(&wat_src).expect("compile account_object.wat to wasm");

    // 2. Deploy Account Object contract
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "Account Object deployment must succeed"
    );
    let aa_contract = engine.all_contract_addresses().await[0];

    // 3. Initialize Account Object for Owner 42
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, aa_contract, "init", 42)], 0)
        .await;
    assert_eq!(applied, 1);

    let (owner, _) = engine
        .call_contract(&aa_contract, "get_owner", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(owner, 42, "Owner must be 42");

    // 4. Guardian setup: initially 0, rotate to Guardian 777
    let (initial_guardian, _) = engine
        .call_contract(&aa_contract, "get_guardian", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(initial_guardian, 0);

    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 2, aa_contract, "rotate_guardian", 777)], 0)
        .await;
    assert_eq!(applied, 1);
    let (new_guardian, _) = engine
        .call_contract(&aa_contract, "get_guardian", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(new_guardian, 777, "Guardian must be rotated to 777");

    // 5. Create Session 1: service 10, budget 50,000 nano-STELL
    // packed: session_id (1) * 10,000,000,000 + service_id (10) * 100,000 + budget (50,000)
    let session1_arg = 10_000_000_000 + 10 * 100_000 + 50_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(&sk, 3, aa_contract, "create_session", session1_arg)],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Verify session 1 is active and has full budget
    let (is_active, _) = engine
        .call_contract(&aa_contract, "is_session_active", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(is_active, 1, "Session 1 must be active");

    let (budget, _) = engine
        .call_contract(&aa_contract, "get_session_budget", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(budget, 50_000, "Initial session budget must be 50,000");

    // 6. Spend 12,000 using Session 1
    // packed: session_id (1) * 1,000,000 + amount (12,000) = 1_012_000
    let spend1_arg = 1_000_000 + 12_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                4,
                aa_contract,
                "spend_with_session",
                spend1_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    let (remaining1, _) = engine
        .call_contract(&aa_contract, "get_session_budget", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(remaining1, 38_000, "Remaining budget must be 38,000");

    // 7. Spend 20,000 using Session 1
    let spend2_arg = 1_000_000 + 20_000;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                5,
                aa_contract,
                "spend_with_session",
                spend2_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    let (remaining2, _) = engine
        .call_contract(&aa_contract, "get_session_budget", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(remaining2, 18_000, "Remaining budget must be 18,000");

    // 8. Attempt to spend 25,000 (exceeds remaining budget 18,000) -> MUST FAIL / REVERT
    let spend_over_arg = 1_000_000 + 25_000;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                6,
                aa_contract,
                "spend_with_session",
                spend_over_arg,
            )],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "Over-budget spend must fail closed"
    );

    let current_nonce = engine
        .get_account(&sk.verifying_key().to_bytes())
        .await
        .unwrap()
        .nonce;
    eprintln!("Current onchain nonce after failed call: {}", current_nonce);

    // 9. Revoke Session 1
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                current_nonce,
                aa_contract,
                "revoke_session",
                1,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Verify session is now inactive
    let (is_active_revoked, _) = engine
        .call_contract(&aa_contract, "is_session_active", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(is_active_revoked, 0, "Revoked session must be inactive");

    // 10. Attempt to spend using revoked session -> MUST FAIL / REVERT
    let spend_revoked_arg = 1_000_000 + 1_000;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                current_nonce + 1,
                aa_contract,
                "spend_with_session",
                spend_revoked_arg,
            )],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "Spend on revoked session must fail closed"
    );
}

#[tokio::test]
async fn test_stl_domain_registry_auction_and_dns_lifecycle() {
    let (engine, sk, _) = funded_engine().await;

    // 1. Read and compile stl_domain_registry.wat
    let wat_src = fs::read_to_string("contracts/stl_domain_registry.wat")
        .expect("stl_domain_registry.wat exists");
    let wasm_code = wat::parse_str(&wat_src).expect("compile stl_domain_registry.wat to wasm");

    // 2. Deploy STL Domain Registry contract
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, wasm_code)], 0)
        .await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "STL Registry deployment must succeed"
    );
    let registry_contract = engine.all_contract_addresses().await[0];

    // 3. Initialize Registry with Treasury Account 99
    let (applied, _) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, registry_contract, "init", 99)], 0)
        .await;
    assert_eq!(applied, 1);

    // 4a. Attempt to register 3-letter domain 'ceo.stl' (length = 3 < 4) -> MUST REVERT
    let bad_start_arg = 10_000_000_000 + 10 * 100_000 + 3;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                2,
                registry_contract,
                "start_auction",
                bad_start_arg,
            )],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "Names shorter than 4 characters must fail closed"
    );

    // 4b. Start Auction for 4-letter premium domain 'star.stl' (domain_id = 1, bidder = 10, length = 4, min bid 200 STELL)
    // packed: domain_id (1) * 10,000,000,000 + bidder_id (10) * 100,000 + length (4)
    let cur_nonce = engine
        .get_account(&sk.verifying_key().to_bytes())
        .await
        .unwrap()
        .nonce;
    let start_arg = 10_000_000_000 + 10 * 100_000 + 4;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce,
                registry_contract,
                "start_auction",
                start_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Check card hue: (1 * 137) % 360 = 137 degrees
    let (hue, _) = engine
        .call_contract(&registry_contract, "get_hue", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(hue, 137, "Deterministic card hue must be 137");

    // Unfinalized domain must NOT resolve
    let (res_initial, _) = engine
        .call_contract(&registry_contract, "resolve", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(res_initial, 0, "Domain in auction must not resolve");

    // 5. Counter-bid from User 20: outbids User 10 with +10%
    // packed: domain_id (1) * 10,000,000,000 + bidder_id (20) * 10,000 + step (1)
    let bid_arg = 10_000_000_000 + 20 * 10_000 + 1;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce + 1,
                registry_contract,
                "place_bid",
                bid_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // 6. Finalize auction after deadline passes
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce + 2,
                registry_contract,
                "finalize_auction",
                1,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // 7. Verify domain resolution: resolve('ceo.stl' / id 1) must resolve to User 20 (the winner)!
    let (target, _) = engine
        .call_contract(&registry_contract, "resolve", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(target, 20, "Domain must resolve to auction winner User 20");

    // Verify 1 year expiry
    let (expiry, _) = engine
        .call_contract(&registry_contract, "get_expiry", 1, 100_000)
        .await
        .unwrap();
    assert!(
        expiry >= 1750010000 + 31536000,
        "Domain must be registered for 1 year"
    );

    // 8. DNS Re-pointing: User 20 points domain to target address 777
    // packed: domain_id (1) * 10,000,000,000 + caller_id (20) * 100,000 + new_target (777)
    let set_target_arg = 10_000_000_000 + 20 * 100_000 + 777;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce + 3,
                registry_contract,
                "set_target",
                set_target_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    let (new_target, _) = engine
        .call_contract(&registry_contract, "resolve", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(new_target, 777, "Domain must now resolve to 777");

    // Unauthorized re-pointing attempt from non-owner (e.g. caller 999) -> REVERTS
    let bad_set_arg = 10_000_000_000 + 999 * 100_000 + 888;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce + 4,
                registry_contract,
                "set_target",
                bad_set_arg,
            )],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "Unauthorized re-pointing must fail closed"
    );

    // 9. Transfer domain (NFT Sale / Transfer): User 20 transfers domain to User 30
    // packed: domain_id (1) * 10,000,000,000 + caller_id (20) * 100,000 + new_owner (30)
    let cur_nonce = engine
        .get_account(&sk.verifying_key().to_bytes())
        .await
        .unwrap()
        .nonce;
    let transfer_arg = 10_000_000_000 + 20 * 100_000 + 30;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce,
                registry_contract,
                "transfer",
                transfer_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    // Old owner User 20 can no longer change target -> REVERTS
    let old_owner_arg = 10_000_000_000 + 20 * 100_000 + 111;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce + 1,
                registry_contract,
                "set_target",
                old_owner_arg,
            )],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "Former owner cannot modify target"
    );

    // New owner User 30 sets target to 999 -> SUCCEEDS
    let cur_nonce2 = engine
        .get_account(&sk.verifying_key().to_bytes())
        .await
        .unwrap()
        .nonce;
    let new_owner_set_arg = 10_000_000_000 + 30 * 100_000 + 999;
    let (applied, _) = engine
        .apply_block_parallel(
            &[call_tx(
                &sk,
                cur_nonce2,
                registry_contract,
                "set_target",
                new_owner_set_arg,
            )],
            0,
        )
        .await;
    assert_eq!(applied, 1);

    let (final_target, _) = engine
        .call_contract(&registry_contract, "resolve", 1, 100_000)
        .await
        .unwrap();
    assert_eq!(
        final_target, 999,
        "Domain now resolves to 999 set by new owner"
    );
}

// B-VM audit PoC (read-only, no behavior change). PASSES by demonstrating the
// flaw; the secure decoder would REJECT trailing bytes.
#[test]
fn bvm_poc_abi_decode_return_ignores_trailing_bytes() {
    use stellereum::contract_abi::{AbiMethod, AbiType, AbiValue, ContractAbi};
    let mut abi = ContractAbi::new();
    abi.add_method(AbiMethod::view("get", vec![], AbiType::I64));
    // Canonical bare I64 payload is 8 bytes; append 1 trailing byte.
    // src/contract_abi.rs:1111-1116 decodes without an is_empty() check.
    let mut bytes = 7i64.to_be_bytes().to_vec();
    bytes.push(0xFF);
    // FIXED (audit B-VM): trailing bytes after a bare scalar refuse.
    let err = abi.decode_return("get", &bytes).unwrap_err();
    assert!(
        matches!(err, stellereum::contract_abi::AbiError::TrailingBytes { got: 1 }),
        "expected TrailingBytes(1), got {err:?}"
    );
    // Control: exact bytes still decode.
    let v = abi.decode_return("get", &7i64.to_be_bytes()).unwrap();
    assert_eq!(v, AbiValue::I64(7));
}
