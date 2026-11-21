//! R1-A WASM hardening tests (`contract.rs`, `rpc/contracts.rs`, `state_engine/contracts.rs`).
//!
//! Verifies both:
//! 1. 100% legacy equivalence when `hardened == false` (`< H`):
//!    - `deploy` uses global `ContractRegistry::next_nonce`;
//!    - `validate_code` does not pass `validate_fuel`;
//!    - `host.send_message` charges flat `FUEL_SEND_MESSAGE = 100`;
//!    - `host.origin` returns `caller`;
//!    - `run_contract_hardened(..., false)` matches legacy `call_with_context`;
//!    - `call_contract_structured_with_value_hardened(..., false)` preserves pre-gate value behaviour.
//! 2. Hardened behaviour when `hardened == true` (`>= H`):
//!    - `SubCallSnapshot` rolls back child `storage`, `balance`, `events`,
//!      `outbound_messages`, and `last_return_data` on child trap/`OutOfFuel`/depth overflow
//!      while preserving parent mutations committed before the sub-call;
//!    - `host.caller()` returns immediate `calling_contract` and `host.origin()` returns `tx.from`;
//!    - `validate_code_hardened` accepts finite `(start ...)` within fuel and rejects
//!      infinite-loop `(start ...)` with `OutOfFuel`;
//!    - `host.send_message` with 64 KiB payload under small fuel fails with `OutOfFuel`;
//!    - `deploy_with_nonce(creator, code, tx.nonce, now)` matches hardened address prediction
//!      and rejects duplicate deploys on the same address, while pre-gate RPC `stell_deployContract`
//!      reads `contracts.next_nonce` matching `ContractRegistry::deploy_inner`;
//!    - `call_contract_structured_with_value_hardened(..., true)` rolls back `value` from both
//!      `Contract.balance` and `accounts[contract]` back to `accounts[caller]` on failure/OOF.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::RwLock;

use stellereum::contract::{
    contract_address, predicted_deploy_address, predicted_deploy_nonce, run_contract_hardened,
    ContractCallContext, ContractCallOptions, ContractError, ContractEvent, ContractMessage,
    ContractRegistry, SubCallSnapshot, FUEL_SEND_MESSAGE, FUEL_SEND_MESSAGE_PER_BYTE,
    MAX_CALL_DEPTH, MAX_CONTRACT_FUEL,
};
use stellereum::evm_adapter;
use stellereum::governance::Governance;
use stellereum::mempool::Mempool;
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::sharding::ShardRegistry;
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const RPC_AUTH_TOKEN: &str = "r1-wasm-hardening-test-token";

fn stateful_subcall_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "sstore" (func $sstore (param i64 i64)))
          (import "host" "emit" (func $emit (param i64 i64)))
          (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
          (import "host" "return_data" (func $return_data (param i32 i32)))
          (memory (export "memory") 1)
          (func $write_msg_buf
            (i64.store (i32.const 0) (i64.const 0x1111111111111111))
            (i64.store (i32.const 8) (i64.const 0x2222222222222222))
            (i64.store (i32.const 16) (i64.const 0x3333333333333333))
            (i64.store (i32.const 24) (i64.const 0x4444444444444444))
            (i32.store (i32.const 32) (i32.const 0x59414b4f)))
          (func (export "mutate_ok") (param $k i64) (param $v i64) (result i64)
            (call $write_msg_buf)
            (call $sstore (local.get $k) (local.get $v))
            (call $emit (local.get $k) (local.get $v))
            (drop (call $send_message (i64.const 0) (i64.const 32) (i64.const 100) (i64.const 32) (i64.const 4) (i64.const 1)))
            (call $return_data (i32.const 32) (i32.const 4))
            (local.get $v))
          (func (export "mutate_then_trap") (param $k i64) (param $v i64) (result i64)
            (call $write_msg_buf)
            (call $sstore (local.get $k) (local.get $v))
            (call $emit (local.get $k) (local.get $v))
            (drop (call $send_message (i64.const 0) (i64.const 32) (i64.const 100) (i64.const 32) (i64.const 4) (i64.const 1)))
            (unreachable))
          (func (export "mutate_then_oof") (param $k i64) (param $v i64) (result i64)
            (call $write_msg_buf)
            (call $sstore (local.get $k) (local.get $v))
            (call $emit (local.get $k) (local.get $v))
            (drop (call $send_message (i64.const 0) (i64.const 32) (i64.const 100) (i64.const 32) (i64.const 4) (i64.const 1)))
            (loop $l
              (br $l))
            (i64.const 0)))"#,
    )
    .expect("stateful_subcall_wasm compiles")
}

fn caller_origin_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "caller" (func $caller (param i32)))
          (import "host" "origin" (func $origin (param i32)))
          (import "host" "return_data" (func $return_data (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "who") (param i64) (result i64)
            (call $caller (i32.const 0))
            (call $origin (i32.const 32))
            (call $return_data (i32.const 0) (i32.const 64))
            (i64.const 1)))"#,
    )
    .expect("caller_origin_wasm compiles")
}

fn finite_start_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (global $init_done (mut i64) (i64.const 0))
          (func $init
            (global.set $init_done (i64.const 42)))
          (start $init)
          (func (export "get") (param i64) (result i64)
            (global.get $init_done)))"#,
    )
    .expect("finite_start_wasm compiles")
}

fn infinite_start_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (func $spin
            (loop $l
              (br $l)))
          (start $spin)
          (func (export "ping") (param i64) (result i64)
            (i64.const 1)))"#,
    )
    .expect("infinite_start_wasm compiles")
}

fn send_message_64k_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
          (memory (export "memory") 2)
          (func (export "send_64k") (param i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0x0102030405060708))
            (i64.store (i32.const 8) (i64.const 0x090a0b0c0d0e0f10))
            (i64.store (i32.const 16) (i64.const 0x1112131415161718))
            (i64.store (i32.const 24) (i64.const 0x191a1b1c1d1e1f20))
            (call $send_message
              (i64.const 0)
              (i64.const 32)
              (i64.const 0)
              (i64.const 64)
              (i64.const 65536)
              (i64.const 1))))"#,
    )
    .expect("send_message_64k_wasm compiles")
}

fn value_target_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "value" (func $value (result i64)))
          (func (export "ok") (param i64) (result i64)
            (call $value))
          (func (export "trap") (param i64) (result i64)
            (unreachable))
          (func (export "spin") (param i64) (result i64)
            (loop $l
              (br $l))
            (i64.const 0)))"#,
    )
    .expect("value_target_wasm compiles")
}

#[test]
fn legacy_pre_gate_behavior_is_preserved() {
    let mut reg = ContractRegistry::new();
    let creator_a = [0x11u8; 32];
    let creator_b = [0x22u8; 32];

    // 1. Legacy deploy uses global next_nonce.
    let code_msg = send_message_64k_wasm();
    let addr_a = reg.deploy(creator_a, code_msg.clone(), 0).unwrap();
    let addr_b = reg.deploy(creator_b, caller_origin_wasm(), 0).unwrap();
    assert_eq!(addr_a, contract_address(&creator_a, 0));
    assert_eq!(addr_b, contract_address(&creator_b, 1));
    assert_eq!(reg.next_nonce, 2);

    // 2. Legacy validate_code without start fuel limit rejects bad code as before
    //    and preserves pre-gate behaviour on empty/invalid wasm.
    assert_eq!(
        ContractRegistry::validate_code(&[]),
        Err(ContractError::EmptyCode)
    );
    assert_eq!(
        ContractRegistry::validate_code(&[1, 2, 3]),
        Err(ContractError::InvalidWasm)
    );

    // 3. Legacy send_message charges flat FUEL_SEND_MESSAGE = 100 even for 64 KiB payload.
    assert_eq!(FUEL_SEND_MESSAGE, 100);
    let legacy_ctx = ContractCallContext {
        caller: creator_a,
        value: 0,
        block_time: 10,
        block_hash: [0u8; 32],
    };
    let legacy_out = reg
        .call_with_context_hardened(
            &addr_a,
            "send_64k",
            0,
            5_000,
            &legacy_ctx,
            creator_b,
            creator_a,
            false,
        )
        .expect("legacy 64 KiB send_message must succeed with 5_000 fuel (flat 100 cost)");
    assert_eq!(legacy_out.result, 1);
    assert_eq!(legacy_out.outbound_messages.len(), 1);
    assert_eq!(legacy_out.outbound_messages[0].payload.len(), 65_536);

    // 4. Legacy host.origin returns caller when hardened == false.
    let legacy_who = reg
        .call_with_context_hardened(
            &addr_b,
            "who",
            0,
            50_000,
            &legacy_ctx,
            creator_b,
            creator_a,
            false,
        )
        .expect("legacy who succeeds");
    assert_eq!(&legacy_who.return_data[0..32], &creator_a);
    assert_eq!(&legacy_who.return_data[32..64], &creator_a);

    // 5. run_contract_hardened(..., false) matches legacy call_with_context fuel & output.
    let c_b = reg.get(&addr_b).unwrap().clone();
    let (res, used, ..) = run_contract_hardened(
        addr_b,
        &c_b.code,
        &c_b.storage,
        c_b.balance,
        "who",
        &[0],
        &[],
        50_000,
        &legacy_ctx,
        creator_b,
        false,
    )
    .expect("run_contract_hardened(false) succeeds");
    assert_eq!(res, legacy_who.result);
    assert_eq!(used, legacy_who.fuel_used);
}

#[test]
fn hardened_subcall_snapshot_rolls_back_child_failures_and_preserves_parent() {
    let mut reg = ContractRegistry::new();
    let creator = [0x33u8; 32];
    let code = stateful_subcall_wasm();

    let parent_addr = reg
        .deploy_with_nonce_and_balance(creator, code.clone(), 0, 1, 1_000)
        .unwrap();
    let child_addr = reg
        .deploy_with_nonce_and_balance(creator, code, 1, 1, 500)
        .unwrap();

    let mut events: Vec<ContractEvent> = Vec::new();
    let mut outbound: Vec<ContractMessage> = Vec::new();

    // Step 1: Parent A mutates storage, balance, events, outbound, and last_return_data.
    let parent_opts = ContractCallOptions {
        caller: creator,
        origin: creator,
        value: 0,
        block_time: 100,
        block_hash: [0u8; 32],
        hardened: true,
    };
    let parent_out = reg
        .execute_subcall_hardened(
            &parent_addr,
            "mutate_ok",
            &[10, 777],
            &[],
            100_000,
            &parent_opts,
            0,
            &mut events,
            &mut outbound,
        )
        .expect("parent call must succeed");
    assert_eq!(parent_out.result, 777);
    assert_eq!(reg.get(&parent_addr).unwrap().storage.get(&10), Some(&777));
    assert_eq!(reg.get_balance(&parent_addr), 900);
    assert_eq!(events.len(), 1);
    assert_eq!(outbound.len(), 1);
    assert_eq!(reg.last_return_data, b"OKAY");

    // Step 2: Nested sub-call to Child B traps after writing storage, balance, event, outbound.
    let child_opts = ContractCallOptions {
        caller: parent_addr,
        origin: creator,
        value: 0,
        block_time: 100,
        block_hash: [0u8; 32],
        hardened: true,
    };
    let err_trap = reg
        .execute_subcall_hardened(
            &child_addr,
            "mutate_then_trap",
            &[20, 888],
            &[],
            100_000,
            &child_opts,
            1,
            &mut events,
            &mut outbound,
        )
        .unwrap_err();
    assert_eq!(err_trap, ContractError::Trapped);

    // Child state is completely rolled back; parent mutations remain intact.
    assert!(reg.get(&child_addr).unwrap().storage.is_empty());
    assert_eq!(reg.get_balance(&child_addr), 500);
    assert_eq!(reg.get(&parent_addr).unwrap().storage.get(&10), Some(&777));
    assert_eq!(reg.get_balance(&parent_addr), 900);
    assert_eq!(events.len(), 1);
    assert_eq!(outbound.len(), 1);
    assert_eq!(reg.last_return_data, b"OKAY");

    // Step 3: Nested sub-call to Child B hits OutOfFuel after mutating host state.
    let err_oof = reg
        .execute_subcall_hardened(
            &child_addr,
            "mutate_then_oof",
            &[30, 999],
            &[],
            5_000,
            &child_opts,
            1,
            &mut events,
            &mut outbound,
        )
        .unwrap_err();
    assert_eq!(err_oof, ContractError::OutOfFuel);
    assert!(reg.get(&child_addr).unwrap().storage.is_empty());
    assert_eq!(reg.get_balance(&child_addr), 500);
    assert_eq!(events.len(), 1);
    assert_eq!(outbound.len(), 1);
    assert_eq!(reg.last_return_data, b"OKAY");

    // Step 4: Exceeding MAX_CALL_DEPTH fails and preserves parent mutations.
    let err_depth = reg
        .execute_subcall_hardened(
            &child_addr,
            "mutate_ok",
            &[40, 123],
            &[],
            100_000,
            &child_opts,
            MAX_CALL_DEPTH + 1,
            &mut events,
            &mut outbound,
        )
        .unwrap_err();
    assert_eq!(err_depth, ContractError::Trapped);
    assert!(reg.get(&child_addr).unwrap().storage.is_empty());
    assert_eq!(events.len(), 1);
    assert_eq!(outbound.len(), 1);

    // Step 5: Direct SubCallSnapshot capture + rollback after a successful child sub-call.
    let snap = SubCallSnapshot::capture(
        &reg,
        &[parent_addr, child_addr],
        events.len(),
        outbound.len(),
    );
    reg.execute_subcall_hardened(
        &child_addr,
        "mutate_ok",
        &[50, 555],
        &[],
        100_000,
        &child_opts,
        1,
        &mut events,
        &mut outbound,
    )
    .expect("child call succeeds before outer revert");
    assert_eq!(reg.get(&child_addr).unwrap().storage.get(&50), Some(&555));
    assert_eq!(reg.get_balance(&child_addr), 400);
    assert_eq!(events.len(), 2);
    assert_eq!(outbound.len(), 2);

    snap.rollback(&mut reg, &mut events, &mut outbound);
    assert!(reg.get(&child_addr).unwrap().storage.is_empty());
    assert_eq!(reg.get_balance(&child_addr), 500);
    assert_eq!(reg.get(&parent_addr).unwrap().storage.get(&10), Some(&777));
    assert_eq!(reg.get_balance(&parent_addr), 900);
    assert_eq!(events.len(), 1);
    assert_eq!(outbound.len(), 1);
    assert_eq!(reg.last_return_data, b"OKAY");
}

#[test]
fn hardened_caller_vs_origin_distinction() {
    let mut reg = ContractRegistry::new();
    let tx_from = [0xA1u8; 32];
    let contract_a = [0xB2u8; 32];
    let contract_b = reg
        .deploy_with_nonce(tx_from, caller_origin_wasm(), 0, 1)
        .unwrap();

    let ctx = ContractCallContext {
        caller: contract_a,
        value: 0,
        block_time: 123,
        block_hash: [0u8; 32],
    };

    // Nested A -> B: host.caller() == A, host.origin() == tx.from.
    let out = reg
        .call_with_context_hardened(
            &contract_b,
            "who",
            0,
            50_000,
            &ctx,
            tx_from,
            contract_a,
            true,
        )
        .expect("hardened who succeeds");
    assert_eq!(out.return_data.len(), 64);
    assert_eq!(
        &out.return_data[0..32],
        &contract_a,
        "host.caller() must be the immediate calling contract"
    );
    assert_eq!(
        &out.return_data[32..64],
        &tx_from,
        "host.origin() must be immutable tx.from"
    );
}

#[test]
fn validate_code_hardened_bounds_start_section_by_fuel() {
    let finite = finite_start_wasm();
    assert_eq!(
        ContractRegistry::validate_code_hardened(&finite, 10_000),
        Ok(()),
        "legal module with finite (start) within fuel budget must pass"
    );

    let infinite = infinite_start_wasm();
    assert_eq!(
        ContractRegistry::validate_code_hardened(&infinite, 10_000),
        Err(ContractError::OutOfFuel),
        "infinite loop in (start) must be rejected with OutOfFuel in bounded time"
    );
}

#[test]
fn hardened_send_message_charges_per_byte_fuel() {
    let mut reg = ContractRegistry::new();
    let creator = [0x55u8; 32];
    let addr = reg
        .deploy_with_nonce(creator, send_message_64k_wasm(), 0, 1)
        .unwrap();

    let ctx = ContractCallContext {
        caller: creator,
        value: 0,
        block_time: 1,
        block_hash: [0u8; 32],
    };

    // 5_000 fuel is enough for flat 100 + wasm instructions, but NOT for 65_536 bytes.
    let err = reg
        .call_with_context_hardened(&addr, "send_64k", 0, 5_000, &ctx, creator, creator, true)
        .unwrap_err();
    assert_eq!(err, ContractError::OutOfFuel);

    // With sufficient fuel it succeeds and consumes >= FUEL_SEND_MESSAGE + 65_536 * PER_BYTE.
    let out = reg
        .call_with_context_hardened(&addr, "send_64k", 0, 200_000, &ctx, creator, creator, true)
        .expect("64 KiB send_message succeeds when fuel covers per-byte cost");
    assert_eq!(out.result, 1);
    assert!(
        out.fuel_used >= FUEL_SEND_MESSAGE + 65_536 * FUEL_SEND_MESSAGE_PER_BYTE,
        "expected per-byte fuel >= {}, got {}",
        FUEL_SEND_MESSAGE + 65_536 * FUEL_SEND_MESSAGE_PER_BYTE,
        out.fuel_used
    );
}

#[tokio::test]
async fn deploy_with_nonce_and_rpc_prediction_parity() {
    let mut reg = ContractRegistry::new();
    let creator_1 = [0x10u8; 32];
    let creator_2 = [0x20u8; 32];
    let code = finite_start_wasm();

    let addr_1 = reg
        .deploy_with_nonce(creator_1, code.clone(), 7, 10)
        .expect("creator_1 deploy at nonce 7 succeeds");
    assert_eq!(addr_1, contract_address(&creator_1, 7));
    assert_eq!(
        addr_1,
        predicted_deploy_address(&creator_1, reg.next_nonce, 7, true)
    );

    let addr_2 = reg
        .deploy_with_nonce(creator_2, code.clone(), 0, 11)
        .expect("creator_2 deploy at nonce 0 succeeds");
    assert_eq!(addr_2, contract_address(&creator_2, 0));
    assert_eq!(
        addr_2,
        predicted_deploy_address(&creator_2, reg.next_nonce, 0, true)
    );

    // Duplicate deploy on same (creator, tx_nonce) must fail with AlreadyExists.
    assert_eq!(
        reg.deploy_with_nonce(creator_1, code.clone(), 7, 12),
        Err(ContractError::AlreadyExists)
    );

    // Pre-gate (`hardened == false`) prediction uses contracts.next_nonce, matching deploy_inner.
    assert_eq!(predicted_deploy_nonce(42, 7, false), 42);
    assert_eq!(predicted_deploy_nonce(42, 7, true), 7);
    assert_eq!(
        predicted_deploy_address(&creator_1, 42, 7, false),
        contract_address(&creator_1, 42)
    );

    // End-to-end RPC `stell_deployContract` pre-gate check against InMemoryStateEngine:
    // advance contracts.next_nonce to 1 by deploying once, then verify RPC predicts
    // SDK-canonical address under `"contract_address"` while exposing `"legacy_contract_address"`
    // from contracts.next_nonce=1 pre-gate, and 1:1 parity on-chain post-gate.
    let rpc_code = value_target_wasm();
    let engine = Arc::new(InMemoryStateEngine::new());
    let first_deployed = engine
        .deploy_contract(creator_1, rpc_code.clone(), 1)
        .await
        .expect("initial legacy deploy succeeds");
    assert_eq!(first_deployed, contract_address(&creator_1, 0));
    assert_eq!(engine.contracts_read().await.next_nonce, 1);

    let st = Arc::new(RpcState {
        engine: engine.clone(),
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(0)),
        node_id: "r1-test".to_string(),
        chain_id: evm_adapter::effective_chain_id(),
        staking: Arc::new(RwLock::new(StakingLedger::new())),
        governance: Arc::new(RwLock::new(Governance::new())),
        recent_blocks: Arc::new(RwLock::new(VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: Some(RPC_AUTH_TOKEN.to_string()),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });

    let res: Value = st
        .call(
            "stell_deployContract",
            json!({
                "code": format!("0x{}", hex::encode(&rpc_code)),
                "sender": format!("0x{}", hex::encode(creator_2)),
                "nonce": 9,
                "token": RPC_AUTH_TOKEN,
            }),
        )
        .await;
    let expected_sdk = hex::encode(contract_address(&creator_2, 9));
    let expected_legacy = hex::encode(contract_address(&creator_2, 1));
    assert_eq!(
        res.get("contract_address").and_then(|v| v.as_str()),
        Some(expected_sdk.as_str()),
        "SDK-canonical contract_address must use tx.nonce (9), got {res}"
    );
    assert_eq!(res.get("nonce").and_then(|v| v.as_u64()), Some(9));
    assert_eq!(
        res.get("legacy_contract_address").and_then(|v| v.as_str()),
        Some(expected_legacy.as_str()),
        "pre-gate RPC prediction must expose legacy_contract_address from contracts.next_nonce (1), got {res}"
    );
    assert_eq!(
        res.get("legacy_next_nonce").and_then(|v| v.as_u64()),
        Some(1)
    );

    // Post-gate (>= H): enable WASM_XSHARD_PMM_HARDENING at height 0 (with RAII reset)
    // and verify 1:1 parity between RPC `"contract_address"` and real on-chain block apply.
    struct ResetWasmGate;
    impl Drop for ResetWasmGate {
        fn drop(&mut self) {
            stellereum::chain_spec::set_wasm_xshard_pmm_hardening_activation_override(None);
        }
    }
    let _reset_gate = ResetWasmGate;
    stellereum::chain_spec::set_wasm_xshard_pmm_hardening_activation_override(Some(0));

    let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x7A);
    let salt = [0x31u8; 16];
    let signer_addr = stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        &kp.public_key,
        &salt,
    );
    engine
        .update_account(AccountState::new(signer_addr, 50_000_000))
        .await;

    let payload = vec![stellereum::svm::OpCode::SysCallDeployContract { code: rpc_code }];
    let dummy_sig = vec![0u8; stellereum::post_quantum::FALCON512_SIG_LEN];
    let probe_tx = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        dummy_sig,
        [0u8; 32],
        0,
        5_000_000,
        0,
        1,
        1,
        payload.clone(),
        &salt,
    );
    let real_sig = kp.sign(&probe_tx.signing_message());
    let deploy_tx = stellereum::sharding::Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        kp.public_key.clone(),
        real_sig,
        [0u8; 32],
        0,
        5_000_000,
        0,
        1,
        1,
        payload,
        &salt,
    );
    let raw_tx_hex = hex::encode(bincode::serialize(&deploy_tx).unwrap());

    let res_hardened: Value = st
        .call(
            "stell_deployContract",
            json!({
                "tx": raw_tx_hex,
                "token": RPC_AUTH_TOKEN,
            }),
        )
        .await;
    let expected_onchain_addr = contract_address(&signer_addr, deploy_tx.nonce);
    let expected_onchain_hex = hex::encode(expected_onchain_addr);
    assert_eq!(
        res_hardened
            .get("contract_address")
            .and_then(|v| v.as_str()),
        Some(expected_onchain_hex.as_str()),
        "hardened RPC must predict contract_address(tx.from, tx.nonce), got {res_hardened}"
    );
    assert!(
        res_hardened.get("legacy_contract_address").is_none(),
        "hardened RPC must omit legacy_contract_address, got {res_hardened}"
    );

    let (applied, failed, _fees, status, _tx_fees, _events) = engine
        .apply_block_parallel_fees_with_events_at_height(&[deploy_tx], 100, 1)
        .await;
    assert_eq!(applied, 1);
    assert_eq!(failed, 0);
    assert_eq!(status, vec![true]);
    assert!(
        engine.get_contract(&expected_onchain_addr).await.is_some(),
        "on-chain contract must exist at exact RPC-predicted contract_address(tx.from, tx.nonce)"
    );
}

#[tokio::test]
async fn hardened_call_contract_structured_with_value_rolls_back_on_error_and_oof() {
    let engine = InMemoryStateEngine::new();
    let creator = [0x41u8; 32];
    let caller = [0x42u8; 32];
    engine
        .update_account(AccountState::new(caller, 10_000))
        .await;

    let contract_addr = engine
        .deploy_contract(creator, value_target_wasm(), 0)
        .await
        .expect("deploy value target");
    engine
        .update_account(AccountState::new(contract_addr, 250))
        .await;

    // 1. Trapping call: value=500 must be rolled back from both Contract.balance and accounts.
    let trap_out = engine
        .call_contract_structured_with_value_hardened(
            Some(caller),
            &contract_addr,
            "trap",
            0,
            MAX_CONTRACT_FUEL,
            500,
            true,
        )
        .await;
    assert_eq!(trap_out.status, "failed");
    assert_eq!(
        engine.get_account(&caller).await.map(|a| a.balance),
        Some(10_000),
        "caller balance must be fully refunded on trap"
    );
    assert_eq!(
        engine.get_account(&contract_addr).await.map(|a| a.balance),
        Some(250),
        "contract account balance must not retain transferred value on trap"
    );
    assert_eq!(
        engine
            .contracts_read()
            .await
            .get(&contract_addr)
            .unwrap()
            .balance,
        0,
        "Contract.balance must be rolled back on trap"
    );

    // 2. OutOfFuel call: value=700 must be rolled back completely.
    let oof_out = engine
        .call_contract_structured_with_value_hardened(
            Some(caller),
            &contract_addr,
            "spin",
            0,
            1_000,
            700,
            true,
        )
        .await;
    assert_eq!(oof_out.status, "failed");
    assert_eq!(oof_out.gas_used, 1_000);
    assert_eq!(
        engine.get_account(&caller).await.map(|a| a.balance),
        Some(10_000)
    );
    assert_eq!(
        engine.get_account(&contract_addr).await.map(|a| a.balance),
        Some(250)
    );
    assert_eq!(
        engine
            .contracts_read()
            .await
            .get(&contract_addr)
            .unwrap()
            .balance,
        0
    );

    // 3. Missing contract: value=300 must be rolled back completely.
    let missing_addr = [0x99u8; 32];
    let missing_out = engine
        .call_contract_structured_with_value_hardened(
            Some(caller),
            &missing_addr,
            "ok",
            0,
            10_000,
            300,
            true,
        )
        .await;
    assert_eq!(missing_out.status, "failed");
    assert_eq!(
        engine.get_account(&caller).await.map(|a| a.balance),
        Some(10_000)
    );
    assert_eq!(
        engine.get_account(&missing_addr).await.map(|a| a.balance),
        Some(0)
    );

    // 4. Successful call: value=500 is transferred and kept.
    let ok_out = engine
        .call_contract_structured_with_value_hardened(
            Some(caller),
            &contract_addr,
            "ok",
            0,
            50_000,
            500,
            true,
        )
        .await;
    assert_eq!(ok_out.status, "success");
    assert_eq!(ok_out.return_value, Some(500));
    assert_eq!(
        engine.get_account(&caller).await.map(|a| a.balance),
        Some(9_500)
    );
    assert_eq!(
        engine.get_account(&contract_addr).await.map(|a| a.balance),
        Some(750)
    );
    assert_eq!(
        engine
            .contracts_read()
            .await
            .get(&contract_addr)
            .unwrap()
            .balance,
        750
    );
}
