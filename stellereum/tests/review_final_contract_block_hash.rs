//! FINAL REVIEW FIX (`host.block_hash` must be deterministic, not zero).
//!
//! The VM used to hardcode `ContractCallContext.block_hash = [0u8; 32]`, so a
//! contract could not observe any block identifier. This test drives a real
//! `SysCallCallContract` (and `SysCallCallContractArgs`) through
//! `execute_payload_with_preverify_at_height_and_parent` and pins:
//!   * the compiled default `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT = u64::MAX`
//!     (disabled): contracts keep seeing 32 zero bytes;
//!   * with the gate active: contracts see the exact PARENT hash passed in,
//!     byte-identical across two independent executions of the same block;
//!   * that value differs from the CURRENT block hash (which commits execution
//!     output via `body_commitment` and therefore cannot be pre-known).

use stellereum::chain_spec::{
    contract_block_hash_active_at, set_contract_block_hash_activation_override,
    CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT,
};
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, VmExecutionResult};

const CALLER: [u8; 32] = [0x33u8; 32];
const PARENT: [u8; 32] = [0x7au8; 32];

/// Clears the thread-local activation override on drop, so one test cannot
/// leak its gate into the next test on the same worker thread.
struct GateReset;
impl Drop for GateReset {
    fn drop(&mut self) {
        set_contract_block_hash_activation_override(None);
    }
}

fn block_hash_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (import "host" "block_hash" (func $block_hash (param i32)))
             (memory (export "memory") 1)
             (func (export "read") (param $ignored i64) (result i64)
               (call $block_hash (i32.const 0))
               (i64.load (i32.const 0))))"#,
    )
    .expect("block_hash contract compiles")
}

fn unsigned_call(contract: [u8; 32], method: &str, nonce: u64) -> Transaction {
    Transaction {
        from: CALLER,
        to: [0u8; 32],
        amount: 0,
        gas_limit: 5_000_000,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: vec![OpCode::SysCallCallContract {
            contract,
            method: method.as_bytes().to_vec(),
            arg: 0,
        }],
        priority_fee_per_gas: 0,
    }
}

async fn deploy(engine: &InMemoryStateEngine) -> [u8; 32] {
    engine
        .deploy_contract(CALLER, block_hash_wasm(), 0)
        .await
        .expect("contract deploy must succeed")
}

async fn read_block_hash(
    engine: &InMemoryStateEngine,
    contract: [u8; 32],
    height: u64,
    parent: [u8; 32],
    nonce: u64,
) -> u64 {
    let tx = unsigned_call(contract, "read", nonce);
    let (res, _) = engine
        .execute_payload_with_preverify_at_height_and_parent(&tx, 0, height, parent)
        .await
        .expect("contract call payload must execute");
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            return_value.expect("the getter returns a value")
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn contract_block_hash_is_zero_while_the_gate_is_disabled() {
    let _reset = GateReset;
    // The compiled default needs an explicit governance decision.
    assert_eq!(CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT, u64::MAX);
    set_contract_block_hash_activation_override(Some(u64::MAX));
    assert!(!contract_block_hash_active_at(0));
    assert!(!contract_block_hash_active_at(u64::MAX));

    let engine = InMemoryStateEngine::new();
    let contract = deploy(&engine).await;
    let seen = read_block_hash(&engine, contract, 5, PARENT, 0).await;
    assert_eq!(
        seen, 0,
        "disabled gate must preserve the historical zero for compatibility"
    );
}

#[tokio::test]
async fn contract_block_hash_is_the_parent_and_byte_identical_across_runs() {
    let _reset = GateReset;
    set_contract_block_hash_activation_override(Some(0));
    assert!(contract_block_hash_active_at(0));
    assert!(contract_block_hash_active_at(5));

    let engine = InMemoryStateEngine::new();
    let contract = deploy(&engine).await;

    // Two INDEPENDENT executions of the same logical block (same height and
    // same parent) must observe the exact same bytes.
    let first = read_block_hash(&engine, contract, 5, PARENT, 0).await;
    let second = read_block_hash(&engine, contract, 5, PARENT, 0).await;
    assert_eq!(first, second, "host.block_hash must be deterministic");

    // The getter does `i64.load`, i.e. little-endian bytes 0..8 of the parent.
    let expected = u64::from_le_bytes(PARENT[0..8].try_into().unwrap());
    assert_eq!(
        first, expected,
        "contracts must see the exact parent hash passed in"
    );

    // The CURRENT block hash commits execution output (body_commitment folds
    // in `cross_shard_out`), so it differs from the parent and could not have
    // been known before execution.
    let current = Block::new_for_test(1, 6, PARENT, [0x11u8; 32], Vec::new()).compute_hash();
    assert_ne!(current, PARENT, "a block hash cannot equal its parent");
    assert_ne!(
        first,
        u64::from_le_bytes(current[0..8].try_into().unwrap()),
        "the contract must NOT observe the not-yet-known current block hash"
    );
}

#[tokio::test]
async fn call_contract_args_also_sees_the_parent_hash() {
    let _reset = GateReset;
    set_contract_block_hash_activation_override(Some(0));

    let engine = InMemoryStateEngine::new();
    let contract = deploy(&engine).await;

    // SysCallCallContractArgs is the second contract entry point; it shares
    // the same `ContractCallContext` wiring and must expose the same value.
    let tx = Transaction {
        from: CALLER,
        to: [0u8; 32],
        amount: 0,
        gas_limit: 5_000_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: vec![OpCode::SysCallCallContractArgs {
            contract,
            method: b"read".to_vec(),
            args: vec![0],
            calldata: Vec::new(),
        }],
        priority_fee_per_gas: 0,
    };
    let (res, _) = engine
        .execute_payload_with_preverify_at_height_and_parent(&tx, 0, 5, PARENT)
        .await
        .expect("contract args payload must execute");
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(
                return_value.expect("getter returns a value"),
                u64::from_le_bytes(PARENT[0..8].try_into().unwrap())
            );
        }
        other => panic!("expected success, got {other:?}"),
    }
}
