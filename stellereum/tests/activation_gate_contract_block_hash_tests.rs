//! PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test
//! deliberately.
//!
//! `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` is compiled `u64::MAX` (INERT).
//! Today `host.block_hash` is PRESENT and succeeds, but `svm` substitutes
//! `[0u8; 32]` for the parent hash the block path supplied. These tests drive
//! the same public payload entry point the live block path uses and prove that
//! pre-activation value is exactly 32 zero bytes for both contract entry points.
//!
//! If the constant is lowered, `assert_inert_contract_block_hash` fails in
//! every test in this file, so arming the gate cannot silently keep these
//! assertions. The post-activation e2e (block apply on two engines, reorg and
//! replay) is still missing; see `docs/ACTIVATION_GATES.md`.

use stellereum::chain_spec::{
    contract_block_hash_activation_height, contract_block_hash_active_at,
    set_contract_block_hash_activation_override, CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, VmExecutionResult};

const CALLER: [u8; 32] = [0x33u8; 32];

/// Clears the thread-local override on drop so a panicking assertion cannot
/// leak a test activation into another test on the same worker thread.
struct GateReset;

impl Drop for GateReset {
    fn drop(&mut self) {
        set_contract_block_hash_activation_override(None);
    }
}

fn assert_inert_contract_block_hash() {
    assert_eq!(
        CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT,
        u64::MAX,
        "host.block_hash was armed; this file pins the pre-activation zero and \
         must be updated together with a post-activation e2e"
    );
    assert_eq!(contract_block_hash_activation_height(), u64::MAX);
    for height in [0u64, 1, 1_000, 253_000, 10_000_000, u64::MAX - 1, u64::MAX] {
        assert!(
            !contract_block_hash_active_at(height),
            "the compiled gate must be inactive at every height, including {height}"
        );
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

fn unsigned_call(payload: Vec<OpCode>) -> Transaction {
    Transaction {
        from: CALLER,
        to: [0u8; 32],
        amount: 0,
        gas_limit: 5_000_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    }
}

async fn deploy(engine: &InMemoryStateEngine) -> [u8; 32] {
    engine
        .deploy_contract(CALLER, block_hash_wasm(), 0)
        .await
        .expect("contract deploy must succeed")
}

async fn execute_and_read(
    engine: &InMemoryStateEngine,
    tx: &Transaction,
    height: u64,
    parent: [u8; 32],
) -> u64 {
    let (res, _) = engine
        .execute_payload_with_preverify_at_height_and_parent(tx, 0, height, parent)
        .await
        .expect("contract call payload must execute");
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            return_value.expect("the block_hash getter returns a value")
        }
        other => panic!("expected a successful contract call, got {other:?}"),
    }
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[tokio::test]
async fn pins_pre_activation_block_hash_is_zero_at_every_reachable_height() {
    let _reset = GateReset;
    set_contract_block_hash_activation_override(None);
    assert_inert_contract_block_hash();

    let engine = InMemoryStateEngine::new();
    let contract = deploy(&engine).await;

    // The payload entry point receives a real parent hash; pre-activation the
    // gate must discard it and hand the contract zero.
    for (height, parent) in [
        (0u64, [0u8; 32]),
        (1, [0x11u8; 32]),
        (5, [0x7au8; 32]),
        (253_000, [0xffu8; 32]),
    ] {
        let tx = unsigned_call(vec![OpCode::SysCallCallContract {
            contract,
            method: b"read".to_vec(),
            arg: 0,
        }]);
        let seen = execute_and_read(&engine, &tx, height, parent).await;
        assert_eq!(
            seen, 0,
            "pre-activation host.block_hash must stay 32 zero bytes at height {height}"
        );
    }
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[tokio::test]
async fn pins_pre_activation_zero_for_both_contract_entry_points() {
    let _reset = GateReset;
    set_contract_block_hash_activation_override(None);
    assert_inert_contract_block_hash();

    let engine = InMemoryStateEngine::new();
    let contract = deploy(&engine).await;
    let parent = [0x5au8; 32];

    // `SysCallCallContract` (arg form).
    let direct = unsigned_call(vec![OpCode::SysCallCallContract {
        contract,
        method: b"read".to_vec(),
        arg: 0,
    }]);
    assert_eq!(
        execute_and_read(&engine, &direct, 5, parent).await,
        0,
        "SysCallCallContract must not observe the parent hash while the gate is inert"
    );

    // `SysCallCallContractArgs` (args + calldata form) shares the same
    // `ContractCallContext`; it must expose the same pre-activation zero.
    let with_args = unsigned_call(vec![OpCode::SysCallCallContractArgs {
        contract,
        method: b"read".to_vec(),
        args: vec![0],
        calldata: Vec::new(),
    }]);
    assert_eq!(
        execute_and_read(&engine, &with_args, 5, parent).await,
        0,
        "SysCallCallContractArgs must not observe the parent hash while the gate is inert"
    );
}
