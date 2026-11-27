//! Wave 9C E2E Tests: 32-Byte Post-Quantum (Falcon-512) Wallet Authentication
//! via `host.caller()` + `host.calldata()` across the 4 reference contracts.

use std::fs;
use stellereum::chain_spec::set_contract_abi_onchain_activation_override;
use stellereum::contract::{contract_address, ContractCallContext, ContractRegistry};
use stellereum::contract_abi::ContractAbi;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme};
use stellereum::sharding::{PqSignatureEnvelope, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum_contract_sdk::address::DOMAIN_VAULT;
use stellereum_contract_sdk::{
    ERR_ALREADY_EXISTS, ERR_INSUFFICIENT_BALANCE, ERR_INVALID_ARGUMENT, ERR_UNAUTHORIZED, SUCCESS,
};

async fn funded_engine_with_users(
    count: usize,
) -> (InMemoryStateEngine, Vec<(FalconKeypair, [u8; 32])>) {
    let engine = InMemoryStateEngine::new();
    let mut users = Vec::with_capacity(count);
    for _ in 0..count {
        let kp = FalconKeypair::generate();
        let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &[0u8; 16]);
        engine
            .update_account(AccountState::new(addr, 10_000_000_000_000))
            .await;
        users.push((kp, addr));
    }
    (engine, users)
}

fn sign_pq_tx(kp: &FalconKeypair, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &[0u8; 16]);
    let mut tx = Transaction {
        from,
        to: [0u8; 32],
        amount: 0,
        gas_limit: 20_000_000,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    tx.signature =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, kp.public_key.clone(), sig).encode();
    tx
}

fn deploy_tx(kp: &FalconKeypair, nonce: u64, code: Vec<u8>) -> Transaction {
    sign_pq_tx(kp, nonce, vec![OpCode::SysCallDeployContract { code }])
}

fn call_args_tx(
    kp: &FalconKeypair,
    nonce: u64,
    contract: [u8; 32],
    method: &str,
    args: Vec<i64>,
    calldata: Vec<u8>,
) -> Transaction {
    sign_pq_tx(
        kp,
        nonce,
        vec![OpCode::SysCallCallContractArgs {
            contract,
            method: method.as_bytes().to_vec(),
            args,
            calldata,
        }],
    )
}

fn call_tx(
    kp: &FalconKeypair,
    nonce: u64,
    contract: [u8; 32],
    method: &str,
    arg: i64,
) -> Transaction {
    sign_pq_tx(
        kp,
        nonce,
        vec![OpCode::SysCallCallContract {
            contract,
            method: method.as_bytes().to_vec(),
            arg,
        }],
    )
}

async fn query_pq_at(
    engine: &InMemoryStateEngine,
    contract: &[u8; 32],
    method: &str,
    calldata: &[u8],
    block_time: u64,
) -> (i64, Vec<u8>) {
    let mut snapshot: ContractRegistry = engine.contracts_read().await.clone();
    let ctx = ContractCallContext {
        block_time,
        ..Default::default()
    };
    let outcome = snapshot
        .call_with_context_args_calldata_hardened_at(
            contract,
            method,
            &[0],
            calldata,
            1_000_000,
            &ctx,
            [0u8; 32],
            [0u8; 32],
            true,
            0,
        )
        .expect("query_pq_at call failed");
    (outcome.result, outcome.return_data)
}

struct AbiGateResetGuard;

impl Drop for AbiGateResetGuard {
    fn drop(&mut self) {
        set_contract_abi_onchain_activation_override(None);
    }
}

async fn get_nonce(engine: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    engine.get_account(addr).await.map(|a| a.nonce).unwrap_or(0)
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

async fn query_pq(
    engine: &InMemoryStateEngine,
    contract: &[u8; 32],
    method: &str,
    calldata: &[u8],
) -> (i64, Vec<u8>) {
    let mut snapshot: ContractRegistry = engine.contracts_read().await.clone();
    let ctx = ContractCallContext::default();
    let outcome = snapshot
        .call_with_context_args_calldata_hardened_at(
            contract,
            method,
            &[0],
            calldata,
            1_000_000,
            &ctx,
            [0u8; 32],
            [0u8; 32],
            true,
            0,
        )
        .expect("query_pq call failed");
    (outcome.result, outcome.return_data)
}

#[tokio::test]
async fn test_w9_sts20_token_pq_auth_onchain_and_registry() {
    let (engine, users) = funded_engine_with_users(3).await;
    let (alice_kp, alice) = (&users[0].0, users[0].1);
    let (_bob_kp, bob) = (&users[1].0, users[1].1);
    let (stranger_kp, stranger) = (&users[2].0, users[2].1);

    let wasm_code = load_wasm("sts20_token");
    let (applied, failed) = engine
        .apply_block_parallel(
            &[deploy_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                wasm_code.clone(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0), "deployment must succeed");
    let token = engine.all_contract_addresses().await[0];

    // Alice initializes with 1_000_000 tokens via init_pq(calldata: 1_000_000 LE)
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "init_pq",
                vec![0],
                1_000_000u64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    let (supply, _) = engine
        .call_contract(&token, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(supply, 1_000_000);
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &alice).await.0,
        1_000_000
    );

    // Alice transfers 10_000 to Bob (50 bps fee = 50 goes to PQ treasury = Alice)
    let mut tf_cd = Vec::with_capacity(40);
    tf_cd.extend_from_slice(&bob);
    tf_cd.extend_from_slice(&10_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "transfer_pq",
                vec![0],
                tf_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &bob).await.0,
        9_950
    );
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &alice).await.0,
        990_050
    );

    // Forged/stranger PQ caller cannot re-init, mint, or transfer Alice's tokens
    let mut steal_cd = Vec::with_capacity(40);
    steal_cd.extend_from_slice(&stranger);
    steal_cd.extend_from_slice(&5_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[
                call_args_tx(
                    stranger_kp,
                    get_nonce(&engine, &stranger).await,
                    token,
                    "init_pq",
                    vec![0],
                    500u64.to_le_bytes().to_vec(),
                ),
                call_args_tx(
                    stranger_kp,
                    get_nonce(&engine, &stranger).await + 1,
                    token,
                    "mint_pq",
                    vec![0],
                    50_000u64.to_le_bytes().to_vec(),
                ),
                call_args_tx(
                    stranger_kp,
                    get_nonce(&engine, &stranger).await + 2,
                    token,
                    "transfer_pq",
                    vec![0],
                    steal_cd.clone(),
                ),
            ],
            0,
        )
        .await;
    assert_eq!((applied, failed), (3, 0));
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &stranger)
            .await
            .0,
        0
    );
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &bob).await.0,
        9_950
    );
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &alice).await.0,
        990_050
    );

    // Direct ContractRegistry verification of exact PQ error codes + approve_pq/transfer_from_pq
    let mut reg = ContractRegistry::new();
    let reg_token = reg.deploy(alice, wasm_code, 0).unwrap();
    let alice_ctx = ContractCallContext {
        caller: alice,
        ..Default::default()
    };
    let stranger_ctx = ContractCallContext {
        caller: stranger,
        ..Default::default()
    };
    let bob_ctx = ContractCallContext {
        caller: bob,
        ..Default::default()
    };

    let res = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "init_pq",
            &[0],
            &1_000_000u64.to_le_bytes(),
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap();
    assert_eq!(res.result, SUCCESS);

    let reinit = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "init_pq",
            &[0],
            &500u64.to_le_bytes(),
            1_000_000,
            &stranger_ctx,
            stranger,
            stranger,
            true,
            0,
        )
        .unwrap();
    assert_eq!(reinit.result, ERR_ALREADY_EXISTS);

    let mint_forged = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "mint_pq",
            &[0],
            &5_000u64.to_le_bytes(),
            1_000_000,
            &stranger_ctx,
            stranger,
            stranger,
            true,
            0,
        )
        .unwrap();
    assert_eq!(mint_forged.result, ERR_UNAUTHORIZED);

    let tf_forged = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "transfer_pq",
            &[0],
            &steal_cd,
            1_000_000,
            &stranger_ctx,
            stranger,
            stranger,
            true,
            0,
        )
        .unwrap();
    assert_eq!(tf_forged.result, ERR_INSUFFICIENT_BALANCE);

    // Alice approves Bob for 2_000; Stranger cannot spend it; Bob spends 1_000 to Stranger
    let mut approve_cd = Vec::with_capacity(40);
    approve_cd.extend_from_slice(&bob);
    approve_cd.extend_from_slice(&2_000u64.to_le_bytes());
    let ap_res = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "approve_pq",
            &[0],
            &approve_cd,
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap();
    assert_eq!(ap_res.result, SUCCESS);

    let mut tf_from_cd = Vec::with_capacity(72);
    tf_from_cd.extend_from_slice(&alice);
    tf_from_cd.extend_from_slice(&stranger);
    tf_from_cd.extend_from_slice(&1_000u64.to_le_bytes());

    let tf_from_forged = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "transfer_from_pq",
            &[0],
            &tf_from_cd,
            1_000_000,
            &stranger_ctx,
            stranger,
            stranger,
            true,
            0,
        )
        .unwrap();
    assert_eq!(tf_from_forged.result, ERR_UNAUTHORIZED);

    let tf_from_ok = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "transfer_from_pq",
            &[0],
            &tf_from_cd,
            1_000_000,
            &bob_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap();
    assert_eq!(tf_from_ok.result, SUCCESS);

    let stranger_bal = reg
        .call_with_context_args_calldata_hardened_at(
            &reg_token,
            "balance_of_pq",
            &[0],
            &stranger,
            1_000_000,
            &stranger_ctx,
            stranger,
            stranger,
            true,
            0,
        )
        .unwrap();
    assert_eq!(stranger_bal.result, 995);
}

#[tokio::test]
async fn test_w9_account_object_pq_session_auth_onchain() {
    let (engine, users) = funded_engine_with_users(3).await;
    let (owner_kp, owner) = (&users[0].0, users[0].1);
    let (delegate_kp, delegate) = (&users[1].0, users[1].1);
    let (stranger_kp, stranger) = (&users[2].0, users[2].1);

    let wasm_code = load_wasm("account_object");
    let (applied, failed) = engine
        .apply_block_parallel(
            &[deploy_tx(
                owner_kp,
                get_nonce(&engine, &owner).await,
                wasm_code,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    let aa = engine.all_contract_addresses().await[0];

    // Owner initializes PQ account
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner_kp,
                get_nonce(&engine, &owner).await,
                aa,
                "init_pq",
                vec![0],
                Vec::new(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    let (has_owner, owner_ret) = query_pq(&engine, &aa, "get_owner_pq", &[]).await;
    assert_eq!(has_owner, 1);
    assert_eq!(owner_ret, owner);

    // Stranger cannot create a session
    let mut rogue_create = Vec::with_capacity(48);
    rogue_create.extend_from_slice(&1u64.to_le_bytes());
    rogue_create.extend_from_slice(&stranger);
    rogue_create.extend_from_slice(&50_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                stranger_kp,
                get_nonce(&engine, &stranger).await,
                aa,
                "create_session_pq",
                vec![0],
                rogue_create,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "is_session_active_pq", &1u64.to_le_bytes())
            .await
            .0,
        0
    );

    // Owner creates session 1 for delegate with 50_000 budget
    let mut create_cd = Vec::with_capacity(48);
    create_cd.extend_from_slice(&1u64.to_le_bytes());
    create_cd.extend_from_slice(&delegate);
    create_cd.extend_from_slice(&50_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner_kp,
                get_nonce(&engine, &owner).await,
                aa,
                "create_session_pq",
                vec![0],
                create_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_session_budget_pq", &1u64.to_le_bytes())
            .await
            .0,
        50_000
    );

    // Stranger cannot spend from session 1 (bearer-token gap closed)
    let mut spend_cd = Vec::with_capacity(16);
    spend_cd.extend_from_slice(&1u64.to_le_bytes());
    spend_cd.extend_from_slice(&12_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                stranger_kp,
                get_nonce(&engine, &stranger).await,
                aa,
                "spend_with_session_pq",
                vec![0],
                spend_cd.clone(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_session_budget_pq", &1u64.to_le_bytes())
            .await
            .0,
        50_000
    );

    // Designated delegate spends 12_000 -> 38_000 remaining
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                delegate_kp,
                get_nonce(&engine, &delegate).await,
                aa,
                "spend_with_session_pq",
                vec![0],
                spend_cd.clone(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_session_budget_pq", &1u64.to_le_bytes())
            .await
            .0,
        38_000
    );

    // Stranger cannot revoke; owner revokes; delegate can no longer spend
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                stranger_kp,
                get_nonce(&engine, &stranger).await,
                aa,
                "revoke_session_pq",
                vec![0],
                1u64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "is_session_active_pq", &1u64.to_le_bytes())
            .await
            .0,
        1
    );

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner_kp,
                get_nonce(&engine, &owner).await,
                aa,
                "revoke_session_pq",
                vec![0],
                1u64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "is_session_active_pq", &1u64.to_le_bytes())
            .await
            .0,
        0
    );

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                delegate_kp,
                get_nonce(&engine, &delegate).await,
                aa,
                "spend_with_session_pq",
                vec![0],
                spend_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_session_budget_pq", &1u64.to_le_bytes()).await,
        (0, 0i64.to_le_bytes().to_vec())
    );
}

#[tokio::test]
async fn test_w9_liquidity_pool_and_stl_dns_pq_onchain() {
    // 1. Liquidity Pool PQ auth
    let (engine, users) = funded_engine_with_users(3).await;
    let (lp_kp, lp) = (&users[0].0, users[0].1);
    let (bob_kp, bob) = (&users[1].0, users[1].1);
    let (stranger_kp, stranger) = (&users[2].0, users[2].1);

    let pool_wasm = load_wasm("liquidity_pool");
    let (applied, failed) = engine
        .apply_block_parallel(
            &[deploy_tx(lp_kp, get_nonce(&engine, &lp).await, pool_wasm)],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    let pool = engine.all_contract_addresses().await[0];

    let (applied, failed) = engine
        .apply_block_parallel(
            &[sign_pq_tx(
                lp_kp,
                get_nonce(&engine, &lp).await,
                vec![OpCode::SysCallCallContract {
                    contract: pool,
                    method: b"init".to_vec(),
                    arg: 30,
                }],
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    let mut dep_cd = Vec::with_capacity(16);
    dep_cd.extend_from_slice(&100_000u64.to_le_bytes());
    dep_cd.extend_from_slice(&400_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                lp_kp,
                get_nonce(&engine, &lp).await,
                pool,
                "deposit_pq",
                vec![0],
                dep_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &pool, "shares_of_pq", &lp).await.0,
        200_000
    );

    // Stranger cannot withdraw LP's shares
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                stranger_kp,
                get_nonce(&engine, &stranger).await,
                pool,
                "withdraw_pq",
                vec![0],
                50_000u64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &pool, "shares_of_pq", &lp).await.0,
        200_000
    );

    // LP withdraws 50_000 shares
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                lp_kp,
                get_nonce(&engine, &lp).await,
                pool,
                "withdraw_pq",
                vec![0],
                50_000u64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &pool, "shares_of_pq", &lp).await.0,
        150_000
    );

    // 2. STL-DNS PQ auction + block_time() duration enforcement
    let dns_wasm = load_wasm("stl_dns");
    let mut reg = ContractRegistry::new();
    let dns = reg.deploy(lp, dns_wasm, 0).unwrap();

    let t0 = 1_750_000_000u64;
    let alice_ctx = ContractCallContext {
        caller: lp,
        block_time: t0,
        ..Default::default()
    };
    let bob_ctx = ContractCallContext {
        caller: bob,
        block_time: t0 + 100,
        ..Default::default()
    };
    let stranger_ctx = ContractCallContext {
        caller: stranger,
        block_time: t0 + 3600,
        ..Default::default()
    };

    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "init_pq",
            &[0],
            &[],
            1_000_000,
            &alice_ctx,
            lp,
            lp,
            true,
            0,
        )
        .unwrap()
        .result,
        SUCCESS
    );

    let mut start_cd = Vec::with_capacity(16);
    start_cd.extend_from_slice(&42u64.to_le_bytes());
    start_cd.extend_from_slice(&4u64.to_le_bytes());
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "start_auction_pq",
            &[0],
            &start_cd,
            1_000_000,
            &alice_ctx,
            lp,
            lp,
            true,
            0,
        )
        .unwrap()
        .result,
        42
    );

    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "place_bid_pq",
            &[0],
            &42u64.to_le_bytes(),
            1_000_000,
            &bob_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        220
    );

    // Premature finalization at t0 + 1800 (< 3600s) MUST fail
    let early_ctx = ContractCallContext {
        caller: bob,
        block_time: t0 + 1800,
        ..Default::default()
    };
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "finalize_auction_pq",
            &[0],
            &42u64.to_le_bytes(),
            1_000_000,
            &early_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        ERR_INVALID_ARGUMENT
    );

    // After 3600s, finalization succeeds and resolves to Bob
    let late_ctx = ContractCallContext {
        caller: bob,
        block_time: t0 + 3600,
        ..Default::default()
    };
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "finalize_auction_pq",
            &[0],
            &42u64.to_le_bytes(),
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        SUCCESS
    );

    let resolved = reg
        .call_with_context_args_calldata_hardened_at(
            &dns,
            "resolve_pq",
            &[0],
            &42u64.to_le_bytes(),
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap();
    assert_eq!(resolved.result, 1);
    assert_eq!(resolved.return_data, bob);

    // Stranger cannot transfer Bob's domain
    let mut xfer_cd = Vec::with_capacity(40);
    xfer_cd.extend_from_slice(&42u64.to_le_bytes());
    xfer_cd.extend_from_slice(&stranger);
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "transfer_pq",
            &[0],
            &xfer_cd,
            1_000_000,
            &stranger_ctx,
            stranger,
            stranger,
            true,
            0,
        )
        .unwrap()
        .result,
        ERR_UNAUTHORIZED
    );

    // Bob transfers domain 42 to lp
    let mut xfer_ok = Vec::with_capacity(40);
    xfer_ok.extend_from_slice(&42u64.to_le_bytes());
    xfer_ok.extend_from_slice(&lp);
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "transfer_pq",
            &[0],
            &xfer_ok,
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        SUCCESS
    );

    let resolved_after = reg
        .call_with_context_args_calldata_hardened_at(
            &dns,
            "resolve_pq",
            &[0],
            &42u64.to_le_bytes(),
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap();
    assert_eq!(resolved_after.result, 1);
    assert_eq!(resolved_after.return_data, lp);

    // SLOT_PQ_MODE legacy lockout on stl-dns (including resolve).
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "resolve",
            &[42],
            &[],
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "resolve",
            &[DOMAIN_VAULT],
            &[],
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &dns,
            "start_auction",
            &[55 * 10_000_000_000 + 2 * 100_000 + 5],
            &[],
            1_000_000,
            &late_ctx,
            bob,
            bob,
            true,
            0,
        )
        .unwrap()
        .result,
        ERR_UNAUTHORIZED
    );
}

#[tokio::test]
async fn test_w19_sts20_burn_pq_allowance_pq_and_lockout_onchain() {
    let (engine, users) = funded_engine_with_users(3).await;
    let (alice_kp, alice) = (&users[0].0, users[0].1);
    let (bob_kp, bob) = (&users[1].0, users[1].1);
    let (stranger_kp, stranger) = (&users[2].0, users[2].1);

    let wasm_code = load_wasm("sts20_token");
    let (applied, failed) = engine
        .apply_block_parallel(
            &[deploy_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                wasm_code.clone(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    let token = engine.all_contract_addresses().await[0];

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "init_pq",
                vec![0],
                1_000_000u64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    // Approve Bob for 5_000 and verify allowance_pq on-chain.
    let mut ap_cd = Vec::with_capacity(40);
    ap_cd.extend_from_slice(&bob);
    ap_cd.extend_from_slice(&5_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "approve_pq",
                vec![0],
                ap_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    let mut alw_cd = Vec::with_capacity(64);
    alw_cd.extend_from_slice(&alice);
    alw_cd.extend_from_slice(&bob);
    let (alw_val, alw_ret) = query_pq(&engine, &token, "allowance_pq", &alw_cd).await;
    assert_eq!(alw_val, 5_000);
    assert_eq!(alw_ret, 5_000i64.to_le_bytes());

    // Bob transfers 1_000 from Alice to Stranger; allowance_pq drops to 4_000.
    let mut tf_from_cd = Vec::with_capacity(72);
    tf_from_cd.extend_from_slice(&alice);
    tf_from_cd.extend_from_slice(&stranger);
    tf_from_cd.extend_from_slice(&1_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                bob_kp,
                get_nonce(&engine, &bob).await,
                token,
                "transfer_from_pq",
                vec![0],
                tf_from_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &token, "allowance_pq", &alw_cd).await.0,
        4_000
    );

    // Alice burns 100_000 via burn_pq; Stranger (balance 995) fails to burn 5_000.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[
                call_args_tx(
                    alice_kp,
                    get_nonce(&engine, &alice).await,
                    token,
                    "burn_pq",
                    vec![0],
                    100_000u64.to_le_bytes().to_vec(),
                ),
                call_args_tx(
                    stranger_kp,
                    get_nonce(&engine, &stranger).await,
                    token,
                    "burn_pq",
                    vec![0],
                    5_000u64.to_le_bytes().to_vec(),
                ),
            ],
            0,
        )
        .await;
    assert_eq!((applied, failed), (2, 0));

    let (supply, _) = engine
        .call_contract(&token, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(supply, 900_000);
    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &stranger)
            .await
            .0,
        995
    );

    // SLOT_PQ_MODE legacy lockout on-chain: getters & mutators refuse with ERR_UNAUTHORIZED.
    assert_eq!(
        engine
            .call_contract(&token, "balance_of", 1, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        engine
            .call_contract(&token, "allowance", 1_000_000 + 2, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );
    let (applied, failed) = engine
        .apply_block_parallel(
            &[
                call_tx(alice_kp, get_nonce(&engine, &alice).await, token, "mint", 50_000),
                call_tx(
                    alice_kp,
                    get_nonce(&engine, &alice).await + 1,
                    token,
                    "burn",
                    50_000,
                ),
                call_tx(
                    alice_kp,
                    get_nonce(&engine, &alice).await + 2,
                    token,
                    "transfer",
                    100_000_000 + 2 * 100_000 + 100,
                ),
            ],
            0,
        )
        .await;
    assert_eq!((applied, failed), (3, 0));
    let (supply_after, _) = engine
        .call_contract(&token, "total_supply", 0, 100_000)
        .await
        .unwrap();
    assert_eq!(supply_after, 900_000);
}

#[tokio::test]
async fn test_w19_liquidity_pool_init_pq_swaps_and_lockout_onchain() {
    let (engine, users) = funded_engine_with_users(2).await;
    let (lp_kp, lp) = (&users[0].0, users[0].1);
    let (trader_kp, trader) = (&users[1].0, users[1].1);

    let pool_wasm = load_wasm("liquidity_pool");
    let (applied, failed) = engine
        .apply_block_parallel(
            &[deploy_tx(lp_kp, get_nonce(&engine, &lp).await, pool_wasm)],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    let pool = engine.all_contract_addresses().await[0];

    // Initialize in PQ mode with 30 bps fee.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                lp_kp,
                get_nonce(&engine, &lp).await,
                pool,
                "init_pq",
                vec![0],
                30i64.to_le_bytes().to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    // Legacy shares_of / deposit / withdraw / swaps locked out under SLOT_PQ_MODE.
    assert_eq!(
        engine
            .call_contract(&pool, "shares_of", 1, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        engine
            .call_contract(&pool, "swap_a_for_b", 1_000, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        engine
            .call_contract(&pool, "swap_b_for_a", 1_000, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(
                lp_kp,
                get_nonce(&engine, &lp).await,
                pool,
                "deposit",
                10_000_000_000 + 10_000 * 100_000 + 40_000,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        engine
            .call_contract(&pool, "get_total_shares", 0, 100_000)
            .await
            .unwrap()
            .0,
        0
    );

    // PQ deposit 10_000 A and 40_000 B -> isqrt(10_000 * 40_000) = 20_000 shares.
    let mut dep_cd = Vec::with_capacity(16);
    dep_cd.extend_from_slice(&10_000u64.to_le_bytes());
    dep_cd.extend_from_slice(&40_000u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                lp_kp,
                get_nonce(&engine, &lp).await,
                pool,
                "deposit_pq",
                vec![0],
                dep_cd,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &pool, "shares_of_pq", &lp).await.0,
        20_000
    );
    assert_eq!(
        engine
            .call_contract(&pool, "swap_a_for_b", 1_000, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );
    assert_eq!(
        engine
            .call_contract(&pool, "swap_b_for_a", 1_000, 100_000)
            .await
            .unwrap()
            .0,
        ERR_UNAUTHORIZED
    );

    // Slippage check: (1_000, 3_627) rejected, reserves untouched; (1_000, 3_626) succeeds.
    let mut bad_swap = Vec::with_capacity(16);
    bad_swap.extend_from_slice(&1_000u64.to_le_bytes());
    bad_swap.extend_from_slice(&3_627u64.to_le_bytes());
    let mut good_swap = Vec::with_capacity(16);
    good_swap.extend_from_slice(&1_000u64.to_le_bytes());
    good_swap.extend_from_slice(&3_626u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                trader_kp,
                get_nonce(&engine, &trader).await,
                pool,
                "swap_a_for_b_pq",
                vec![0],
                bad_swap,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        engine
            .call_contract(&pool, "get_reserve_a", 0, 100_000)
            .await
            .unwrap()
            .0,
        10_000
    );

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                trader_kp,
                get_nonce(&engine, &trader).await,
                pool,
                "swap_a_for_b_pq",
                vec![0],
                good_swap,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        engine
            .call_contract(&pool, "get_reserve_a", 0, 100_000)
            .await
            .unwrap()
            .0,
        11_000
    );
    assert_eq!(
        engine
            .call_contract(&pool, "get_reserve_b", 0, 100_000)
            .await
            .unwrap()
            .0,
        36_374
    );

    // Reverse swap B -> A: (3_000, 836) rejected; (3_000, 835) succeeds.
    let mut bad_rev = Vec::with_capacity(16);
    bad_rev.extend_from_slice(&3_000u64.to_le_bytes());
    bad_rev.extend_from_slice(&836u64.to_le_bytes());
    let mut good_rev = Vec::with_capacity(16);
    good_rev.extend_from_slice(&3_000u64.to_le_bytes());
    good_rev.extend_from_slice(&835u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[
                call_args_tx(
                    trader_kp,
                    get_nonce(&engine, &trader).await,
                    pool,
                    "swap_b_for_a_pq",
                    vec![0],
                    bad_rev,
                ),
                call_args_tx(
                    trader_kp,
                    get_nonce(&engine, &trader).await + 1,
                    pool,
                    "swap_b_for_a_pq",
                    vec![0],
                    good_rev,
                ),
            ],
            0,
        )
        .await;
    assert_eq!((applied, failed), (2, 0));
    assert_eq!(
        engine
            .call_contract(&pool, "get_reserve_a", 0, 100_000)
            .await
            .unwrap()
            .0,
        10_165
    );
    assert_eq!(
        engine
            .call_contract(&pool, "get_reserve_b", 0, 100_000)
            .await
            .unwrap()
            .0,
        39_374
    );
}

#[tokio::test]
async fn test_w19_account_object_pq_lifecycle_and_lockout_onchain() {
    let (engine, users) = funded_engine_with_users(5).await;
    let (owner1_kp, owner1) = (&users[0].0, users[0].1);
    let (owner2_kp, owner2) = (&users[1].0, users[1].1);
    let (guardian_kp, guardian) = (&users[2].0, users[2].1);
    let (_tenant_kp, tenant) = (&users[3].0, users[3].1);
    let (delegate_kp, delegate) = (&users[4].0, users[4].1);

    let wasm_code = load_wasm("account_object");
    let (applied, failed) = engine
        .apply_block_parallel(
            &[deploy_tx(
                owner1_kp,
                get_nonce(&engine, &owner1).await,
                wasm_code,
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    let aa = engine.all_contract_addresses().await[0];

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner1_kp,
                get_nonce(&engine, &owner1).await,
                aa,
                "init_pq",
                vec![0],
                Vec::new(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    // Legacy getters return ERR_UNAUTHORIZED and legacy mutators trap/revert on-chain.
    for getter in [
        "get_owner",
        "get_guardian",
        "get_pending_owner",
        "get_active_tenant",
        "is_rental_active",
        "is_session_active",
        "get_session_budget",
    ] {
        assert_eq!(
            engine.call_contract(&aa, getter, 1, 100_000).await.unwrap().0,
            ERR_UNAUTHORIZED,
            "legacy getter {getter} must fail closed under PQ mode"
        );
    }
    let (applied, failed) = engine
        .apply_block_parallel(
            &[
                call_tx(
                    owner1_kp,
                    get_nonce(&engine, &owner1).await,
                    aa,
                    "transfer_ownership",
                    10_000_000_000 + 2,
                ),
                call_tx(
                    owner1_kp,
                    get_nonce(&engine, &owner1).await + 1,
                    aa,
                    "rotate_guardian",
                    10_000_000_000 + 3,
                ),
            ],
            0,
        )
        .await;
    assert_eq!((applied, failed), (0, 2));

    // Rotate guardian -> guardian initiates recovery -> owner1 cancels -> guardian re-initiates -> finalize after 72h.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner1_kp,
                get_nonce(&engine, &owner1).await,
                aa,
                "rotate_guardian_pq",
                vec![0],
                guardian.to_vec(),
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_guardian_pq", &[]).await,
        (1, guardian.to_vec())
    );

    let t0 = 1_750_000_000u64;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                guardian_kp,
                get_nonce(&engine, &guardian).await,
                aa,
                "initiate_recovery_pq",
                vec![0],
                owner2.to_vec(),
            )],
            t0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_pending_owner_pq", &[]).await,
        (1, owner2.to_vec())
    );

    // Owner1 vetoes recovery.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner1_kp,
                get_nonce(&engine, &owner1).await,
                aa,
                "cancel_recovery_pq",
                vec![0],
                Vec::new(),
            )],
            t0 + 10,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_pending_owner_pq", &[]).await.0,
        0
    );

    // Guardian re-initiates recovery; premature finalize at t0 + 1000 leaves owner1; finalize at t0 + 259_200 transfers to owner2.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                guardian_kp,
                get_nonce(&engine, &guardian).await,
                aa,
                "initiate_recovery_pq",
                vec![0],
                owner2.to_vec(),
            )],
            t0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                guardian_kp,
                get_nonce(&engine, &guardian).await,
                aa,
                "finalize_recovery_pq",
                vec![0],
                Vec::new(),
            )],
            t0 + 1000,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_owner_pq", &[]).await,
        (1, owner1.to_vec())
    );

    let t_unlock = t0 + 259_200;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                guardian_kp,
                get_nonce(&engine, &guardian).await,
                aa,
                "finalize_recovery_pq",
                vec![0],
                Vec::new(),
            )],
            t_unlock,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_owner_pq", &[]).await,
        (1, owner2.to_vec())
    );

    // Owner2 sets tenant for 2 hours, checks active & expiry & revoke.
    let mut rent_cd = Vec::with_capacity(40);
    rent_cd.extend_from_slice(&tenant);
    rent_cd.extend_from_slice(&2u64.to_le_bytes());
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner2_kp,
                get_nonce(&engine, &owner2).await,
                aa,
                "set_tenant_pq",
                vec![0],
                rent_cd,
            )],
            t_unlock,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq_at(&engine, &aa, "is_rental_active_pq", &[], t_unlock + 100)
            .await
            .0,
        1
    );
    assert_eq!(
        query_pq_at(&engine, &aa, "get_active_tenant_pq", &[], t_unlock + 100).await,
        (1, tenant.to_vec())
    );
    assert_eq!(
        query_pq_at(&engine, &aa, "is_rental_active_pq", &[], t_unlock + 7200)
            .await
            .0,
        0
    );

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner2_kp,
                get_nonce(&engine, &owner2).await,
                aa,
                "revoke_rental_pq",
                vec![0],
                Vec::new(),
            )],
            t_unlock + 10,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq_at(&engine, &aa, "is_rental_active_pq", &[], t_unlock + 20)
            .await
            .0,
        0
    );

    // Session budget update: create session 1 (50_000), spend 10_000, reduce to 25_000 -> 15_000 left.
    let mut sess_cd = Vec::with_capacity(48);
    sess_cd.extend_from_slice(&1u64.to_le_bytes());
    sess_cd.extend_from_slice(&delegate);
    sess_cd.extend_from_slice(&50_000u64.to_le_bytes());
    let mut spend_cd = Vec::with_capacity(16);
    spend_cd.extend_from_slice(&1u64.to_le_bytes());
    spend_cd.extend_from_slice(&10_000u64.to_le_bytes());
    let mut upd_cd = Vec::with_capacity(16);
    upd_cd.extend_from_slice(&1u64.to_le_bytes());
    upd_cd.extend_from_slice(&25_000u64.to_le_bytes());

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner2_kp,
                get_nonce(&engine, &owner2).await,
                aa,
                "create_session_pq",
                vec![0],
                sess_cd,
            )],
            t_unlock + 20,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));

    let (applied, failed) = engine
        .apply_block_parallel(
            &[
                call_args_tx(
                    delegate_kp,
                    get_nonce(&engine, &delegate).await,
                    aa,
                    "spend_with_session_pq",
                    vec![0],
                    spend_cd,
                ),
                call_args_tx(
                    delegate_kp,
                    get_nonce(&engine, &delegate).await + 1,
                    aa,
                    "update_session_budget_pq",
                    vec![0],
                    upd_cd,
                ),
            ],
            t_unlock + 21,
        )
        .await;
    assert_eq!((applied, failed), (2, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_session_budget_pq", &1u64.to_le_bytes())
            .await
            .0,
        15_000
    );

    // Direct PQ ownership transfer back to owner1.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_args_tx(
                owner2_kp,
                get_nonce(&engine, &owner2).await,
                aa,
                "transfer_ownership_pq",
                vec![0],
                owner1.to_vec(),
            )],
            t_unlock + 22,
        )
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(
        query_pq(&engine, &aa, "get_owner_pq", &[]).await,
        (1, owner1.to_vec())
    );
}

#[tokio::test]
async fn test_w19_deploy_contract_with_abi_and_pq_calls() {
    const ABI_HEIGHT: u64 = 500;
    let _reset = AbiGateResetGuard;
    set_contract_abi_onchain_activation_override(Some(ABI_HEIGHT));

    let (engine, users) = funded_engine_with_users(2).await;
    let (alice_kp, alice) = (&users[0].0, users[0].1);
    let (_bob_kp, bob) = (&users[1].0, users[1].1);

    let wasm_code = load_wasm("sts20_token");
    let abi_json = br#"{"methods":[{"name":"init_pq","params":[{"name":"_arg","type":"i64"}],"returns":"i64","mutates_state":true},{"name":"balance_of_pq","params":[{"name":"_arg","type":"i64"}],"returns":"i64","mutates_state":false},{"name":"burn_pq","params":[{"name":"_arg","type":"i64"}],"returns":"i64","mutates_state":true},{"name":"approve_pq","params":[{"name":"_arg","type":"i64"}],"returns":"i64","mutates_state":true},{"name":"allowance_pq","params":[{"name":"_arg","type":"i64"}],"returns":"i64","mutates_state":false}],"events":[]}"#.to_vec();
    let expected_abi = ContractAbi::from_json(std::str::from_utf8(&abi_json).unwrap()).unwrap();

    // Below gate (H - 1): SysCallDeployContractWithAbi reverts fail-closed.
    let pre_tx = sign_pq_tx(
        alice_kp,
        get_nonce(&engine, &alice).await,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: wasm_code.clone(),
            abi_json: abi_json.clone(),
        }],
    );
    let err = engine
        .apply_transaction_at_height(&pre_tx, 1_750_000_000, ABI_HEIGHT - 1)
        .await
        .expect_err("SysCallDeployContractWithAbi must fail below gate");
    assert!(err.contains("inactive at height"));

    // At gate (H): deploy with inline ABI commits contract + ContractAbi on-chain.
    let deploy_nonce = get_nonce(&engine, &alice).await;
    let token = contract_address(&alice, deploy_nonce);
    let deploy_with_abi_tx = sign_pq_tx(
        alice_kp,
        deploy_nonce,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: wasm_code,
            abi_json,
        }],
    );
    engine
        .apply_transaction_at_height(&deploy_with_abi_tx, 1_750_000_001, ABI_HEIGHT)
        .await
        .expect("SysCallDeployContractWithAbi must succeed at gate");

    assert_eq!(engine.get_contract_abi(&token).await, Some(expected_abi.clone()));
    assert_eq!(
        engine.get_contract_abi_json(&token).await,
        Some(expected_abi.to_json())
    );

    // Call PQ entrypoints on the ABI-deployed contract.
    engine
        .apply_transaction_at_height(
            &call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "init_pq",
                vec![0],
                500_000u64.to_le_bytes().to_vec(),
            ),
            1_750_000_002,
            ABI_HEIGHT,
        )
        .await
        .unwrap();
    engine
        .apply_transaction_at_height(
            &call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "burn_pq",
                vec![0],
                125_000u64.to_le_bytes().to_vec(),
            ),
            1_750_000_003,
            ABI_HEIGHT,
        )
        .await
        .unwrap();

    let mut ap_cd = Vec::with_capacity(40);
    ap_cd.extend_from_slice(&bob);
    ap_cd.extend_from_slice(&10_000u64.to_le_bytes());
    engine
        .apply_transaction_at_height(
            &call_args_tx(
                alice_kp,
                get_nonce(&engine, &alice).await,
                token,
                "approve_pq",
                vec![0],
                ap_cd,
            ),
            1_750_000_004,
            ABI_HEIGHT,
        )
        .await
        .unwrap();

    assert_eq!(
        query_pq(&engine, &token, "balance_of_pq", &alice).await.0,
        375_000
    );
    let mut alw_cd = Vec::with_capacity(64);
    alw_cd.extend_from_slice(&alice);
    alw_cd.extend_from_slice(&bob);
    assert_eq!(
        query_pq(&engine, &token, "allowance_pq", &alw_cd).await.0,
        10_000
    );
}

#[tokio::test]
async fn test_w22b_legacy_init_blocks_pq_and_high_reserve_pool_wasm() {
    let (_engine, users) = funded_engine_with_users(2).await;
    let alice = users[0].1;
    let bob = users[1].1;
    let alice_ctx = ContractCallContext {
        caller: alice,
        ..Default::default()
    };

    // 1. sts20-token initialized via legacy init() blocks all *_pq entrypoints.
    let mut reg = ContractRegistry::new();
    let token_wasm = load_wasm("sts20_token");
    let token = reg.deploy(alice, token_wasm, 0).unwrap();
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &token,
            "init",
            &[1_000_000],
            &[],
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap()
        .result,
        SUCCESS
    );

    let mut alw_cd = Vec::with_capacity(64);
    alw_cd.extend_from_slice(&alice);
    alw_cd.extend_from_slice(&bob);
    let mut ap_cd = Vec::with_capacity(40);
    ap_cd.extend_from_slice(&bob);
    ap_cd.extend_from_slice(&1_000u64.to_le_bytes());
    let mut tf_from_cd = Vec::with_capacity(72);
    tf_from_cd.extend_from_slice(&alice);
    tf_from_cd.extend_from_slice(&bob);
    tf_from_cd.extend_from_slice(&1_000u64.to_le_bytes());

    let amount_cd = 1_000u64.to_le_bytes();

    for (method, cd) in [
        ("balance_of_pq", alice.as_slice()),
        ("allowance_pq", alw_cd.as_slice()),
        ("approve_pq", ap_cd.as_slice()),
        ("transfer_pq", ap_cd.as_slice()),
        ("transfer_from_pq", tf_from_cd.as_slice()),
        ("mint_pq", amount_cd.as_slice()),
        ("burn_pq", amount_cd.as_slice()),
    ] {
        assert_eq!(
            reg.call_with_context_args_calldata_hardened_at(
                &token,
                method,
                &[0],
                cd,
                1_000_000,
                &alice_ctx,
                alice,
                alice,
                true,
                0,
            )
            .unwrap()
            .result,
            ERR_UNAUTHORIZED,
            "sts20-token {method} must reject legacy-initialized contract"
        );
    }

    // 2. account-object initialized via legacy init() blocks *_pq mutators.
    let aa_wasm = load_wasm("account_object");
    let aa = reg.deploy(alice, aa_wasm, 0).unwrap();
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &aa,
            "init",
            &[42],
            &[],
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap()
        .result,
        42
    );

    let mut create_cd = Vec::with_capacity(48);
    create_cd.extend_from_slice(&1u64.to_le_bytes());
    create_cd.extend_from_slice(&bob);
    create_cd.extend_from_slice(&1_000u64.to_le_bytes());
    let mut spend_cd = Vec::with_capacity(16);
    spend_cd.extend_from_slice(&1u64.to_le_bytes());
    spend_cd.extend_from_slice(&100u64.to_le_bytes());

    let sess_id_cd = 1u64.to_le_bytes();

    for (method, cd) in [
        ("create_session_pq", create_cd.as_slice()),
        ("spend_with_session_pq", spend_cd.as_slice()),
        ("revoke_session_pq", sess_id_cd.as_slice()),
        ("update_session_budget_pq", spend_cd.as_slice()),
        ("transfer_ownership_pq", bob.as_slice()),
    ] {
        assert_eq!(
            reg.call_with_context_args_calldata_hardened_at(
                &aa,
                method,
                &[0],
                cd,
                1_000_000,
                &alice_ctx,
                alice,
                alice,
                true,
                0,
            )
            .unwrap()
            .result,
            ERR_UNAUTHORIZED,
            "account-object {method} must reject legacy-initialized contract"
        );
    }

    // 3. liquidity-pool high-reserve (500M STELL) quote & PQ swap succeeds without ERR_OVERFLOW.
    let pool_wasm = load_wasm("liquidity_pool");
    let pool = reg.deploy(alice, pool_wasm, 0).unwrap();
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &pool,
            "init_pq",
            &[0],
            &30i64.to_le_bytes(),
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap()
        .result,
        SUCCESS
    );

    let res_500m: u64 = 500_000_000 * 1_000_000_000;
    let dx_100m: u64 = 100_000_000 * 1_000_000_000;
    let expected_out: i64 = 83_124_895_781_223_945;

    let mut dep_cd = Vec::with_capacity(16);
    dep_cd.extend_from_slice(&res_500m.to_le_bytes());
    dep_cd.extend_from_slice(&res_500m.to_le_bytes());
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &pool,
            "deposit_pq",
            &[0],
            &dep_cd,
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap()
        .result,
        res_500m as i64
    );

    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &pool,
            "swap_quote",
            &[dx_100m as i64],
            &[],
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap()
        .result,
        expected_out
    );

    let mut swap_cd = Vec::with_capacity(16);
    swap_cd.extend_from_slice(&dx_100m.to_le_bytes());
    swap_cd.extend_from_slice(&(expected_out as u64).to_le_bytes());
    assert_eq!(
        reg.call_with_context_args_calldata_hardened_at(
            &pool,
            "swap_a_for_b_pq",
            &[0],
            &swap_cd,
            1_000_000,
            &alice_ctx,
            alice,
            alice,
            true,
            0,
        )
        .unwrap()
        .result,
        expected_out
    );
}
