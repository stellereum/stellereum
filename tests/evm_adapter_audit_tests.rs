//! EVM-adapter + SVM audit tests (gas, precompiles, isolation, F4 estimate split).
//!
//! Scope: `evm_adapter.rs` / `svm.rs` only. Each test proves one audit claim:
//! out-of-gas reverts atomically, malformed precompile input fails clean,
//! contract storage is namespaced, there is no synchronous reentrancy import,
//! and the F4 pure-vs-floored estimate split stays coherent.

use serde_json::json;
use stellereum::contract::ContractRegistry;
use stellereum::evm_adapter::{
    self, eth_estimate_gas, eth_estimate_gas_amount, eth_estimate_gas_with_floor, EvmAdapter,
    CONTRACT_CREATION_BASE_GAS, STANDARD_TRANSFER_GAS,
};
use stellereum::svm::{
    contract_call_gas, opcode_gas, OpCode, Svm, VmContext, VmExecutionResult, GAS_BASIC_TRANSFER,
    GAS_CONTRACT_CALL, GAS_CONTRACT_CALL_PER_ARG, GAS_CONTRACT_CALL_PER_BYTE,
    MAX_CONTRACT_CALLDATA_BYTES, MAX_CONTRACT_METHOD_LEN,
};

const COUNTER_WAT: &str = r#"(module
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (func (export "inc") (param $k i64) (result i64)
    (call $sstore (local.get $k) (i64.add (call $sload (local.get $k)) (i64.const 1)))
    (call $sload (local.get $k))))"#;

fn test_ctx<'a>(
    sender: [u8; 32],
    balance: u64,
    contracts: Option<&'a mut ContractRegistry>,
) -> VmContext<'a> {
    VmContext {
        sender,
        balance,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: 1_729_000_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts,
        staking: None,
        pmm: None,
        min_validator_bond: 1_000,
        default_commission_bps: 100,
        payouts: Vec::new(),
        oracle: None,
    }
}

fn deploy_counter(creator: [u8; 32]) -> (ContractRegistry, [u8; 32]) {
    let code = wat::parse_str(COUNTER_WAT).expect("counter wat compiles");
    let mut reg = ContractRegistry::new();
    let addr = reg.deploy(creator, code, 0).expect("counter deploys");
    (reg, addr)
}

fn inc_call(addr: [u8; 32], key: i64) -> Vec<OpCode> {
    vec![OpCode::SysCallCallContract {
        contract: addr,
        method: b"inc".to_vec(),
        arg: key,
    }]
}

// ---------------------------------------------------------------------------
// F4: pure-vs-floored estimate split
// ---------------------------------------------------------------------------

#[test]
fn f4_pure_vs_served_split_is_coherent_and_pinned() {
    // Pins: pure transfer figure and admission floor.
    assert_eq!(STANDARD_TRANSFER_GAS, 21_000);
    assert_eq!(GAS_BASIC_TRANSFER, 280_000);

    // Empty params: pure is the EVM figure, served honors the floor.
    let empty = json!([]);
    assert_eq!(eth_estimate_gas_amount(&empty).unwrap(), 21_000);
    assert_eq!(
        eth_estimate_gas(&empty).unwrap(),
        "0x445c0",
        "served empty estimate must be the 280k floor"
    );
    assert_eq!(
        eth_estimate_gas_with_floor(&empty, GAS_BASIC_TRANSFER).unwrap(),
        "0x445c0"
    );
    // Zero floor passes the pure figure through unchanged.
    assert_eq!(
        eth_estimate_gas_with_floor(&empty, 0).unwrap(),
        "0x5208"
    );

    // served == max(pure, floor) for a range of floors: pure never exceeds served.
    for floor in [0u64, 1, 21_000, 100_000, 280_000, 1_000_000] {
        let pure = eth_estimate_gas_amount(&empty).unwrap();
        let served_hex = eth_estimate_gas_with_floor(&empty, floor).unwrap();
        let served =
            u64::from_str_radix(served_hex.trim_start_matches("0x"), 16).expect("hex served");
        assert_eq!(served, pure.max(floor), "served must be max(pure, floor)");
        assert!(pure <= served, "pure must never exceed served");
    }
}

#[test]
fn f4_calldata_pricing_and_contract_creation_pinned() {
    // One zero byte costs 4, one nonzero byte costs 16 (yellow-paper calldata pricing).
    let zero = json!([{ "to": "0x1111111111111111111111111111111111111111", "data": "0x00" }]);
    let nonzero = json!([{ "to": "0x1111111111111111111111111111111111111111", "data": "0xff" }]);
    assert_eq!(eth_estimate_gas_amount(&zero).unwrap(), 21_000 + 4);
    assert_eq!(eth_estimate_gas_amount(&nonzero).unwrap(), 21_000 + 16);

    // Contract creation (no `to` + calldata) uses the creation base.
    // "0x6001" is two nonzero bytes: 2 * 16.
    let create = json!([{ "data": "0x6001" }]);
    assert_eq!(
        eth_estimate_gas_amount(&create).unwrap(),
        CONTRACT_CREATION_BASE_GAS + 16 + 16,
        "creation base (53k) + per-byte calldata"
    );
    assert_eq!(CONTRACT_CREATION_BASE_GAS, 53_000);

    // Malformed / oversized calldata fails closed, never prices attacker bytes.
    let bad_hex = json!([{ "to": "0x1111111111111111111111111111111111111111", "data": "0xzz" }]);
    assert!(eth_estimate_gas_amount(&bad_hex).is_err());
    let huge = format!("0x{}", "ff".repeat(evm_adapter::MAX_EVM_RAW_TX_BYTES + 1));
    let oversized = json!([{ "to": "0x1111111111111111111111111111111111111111", "data": huge }]);
    assert!(eth_estimate_gas_amount(&oversized).is_err());
    assert!(eth_estimate_gas(&oversized).is_err());
}

// ---------------------------------------------------------------------------
// Gas exhaustion: halts cleanly, state rolled back
// ---------------------------------------------------------------------------

#[test]
fn gas_exhaustion_halts_cleanly_and_rolls_back() {
    let sender = [0x99u8; 32];
    let (mut reg, addr) = deploy_counter([0x11u8; 32]);

    // Baseline: a funded call persists storage key 42 == 1.
    let gas = contract_call_gas(3, 1, 0) + 100_000;
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    match Svm::execute(&inc_call(addr, 42), gas, &mut ctx) {
        VmExecutionResult::Success { .. } => {}
        other => panic!("funded call must succeed, got {other:?}"),
    }
    assert_eq!(ctx.contracts.as_ref().unwrap().get(&addr).unwrap().storage.get(&42), Some(&1));

    // Starve the call of wasmi fuel (covers the table charge, not the body):
    // must report OutOfGas and leave storage at 1 (no partial increment).
    let starved = contract_call_gas(3, 1, 0) + 10;
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    match Svm::execute(&inc_call(addr, 42), starved, &mut ctx) {
        VmExecutionResult::OutOfGas => {}
        other => panic!("starved call must be OutOfGas, got {other:?}"),
    }
    assert_eq!(
        ctx.contracts.as_ref().unwrap().get(&addr).unwrap().storage.get(&42),
        Some(&1),
        "out-of-gas must not persist a partial write"
    );

    // Zero gas: the table charge itself cannot be paid.
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    match Svm::execute(&inc_call(addr, 42), 0, &mut ctx) {
        VmExecutionResult::OutOfGas => {}
        other => panic!("zero-gas call must be OutOfGas, got {other:?}"),
    }
}

#[test]
fn contract_call_wire_caps_fail_closed() {
    let sender = [0x99u8; 32];
    let (mut reg, addr) = deploy_counter([0x11u8; 32]);

    // Oversized method name reverts (never reaches UTF-8/export lookup).
    let big_method = vec![OpCode::SysCallCallContract {
        contract: addr,
        method: vec![b'a'; MAX_CONTRACT_METHOD_LEN + 1],
        arg: 0,
    }];
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    assert!(
        matches!(Svm::execute(&big_method, 10_000_000, &mut ctx), VmExecutionResult::Reverted(_)),
        "oversized method must revert"
    );

    // Oversized calldata reverts.
    let big_data = vec![OpCode::SysCallCallContractArgs {
        contract: addr,
        method: b"inc".to_vec(),
        args: vec![42],
        calldata: vec![0u8; MAX_CONTRACT_CALLDATA_BYTES + 1],
    }];
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    assert!(
        matches!(Svm::execute(&big_data, 10_000_000, &mut ctx), VmExecutionResult::Reverted(_)),
        "oversized calldata must revert"
    );

    // Too many args reverts before the registry clone.
    let many_args = vec![OpCode::SysCallCallContractArgs {
        contract: addr,
        method: b"inc".to_vec(),
        args: vec![0i64; 9],
        calldata: Vec::new(),
    }];
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    assert!(
        matches!(Svm::execute(&many_args, 10_000_000, &mut ctx), VmExecutionResult::Reverted(_)),
        "9-arg call must revert (max 8)"
    );

    // Gas table prices the wire: base + per-arg + per method/calldata byte.
    assert_eq!(
        contract_call_gas(3, 1, 0),
        GAS_CONTRACT_CALL + GAS_CONTRACT_CALL_PER_ARG + 3 * GAS_CONTRACT_CALL_PER_BYTE
    );
    assert_eq!(
        opcode_gas(&OpCode::SysCallCallContract {
            contract: addr,
            method: b"inc".to_vec(),
            arg: 0,
        }),
        contract_call_gas(3, 1, 0),
        "table and dispatch helper must agree"
    );
    assert_eq!(
        opcode_gas(&OpCode::SysCallCallContractArgs {
            contract: addr,
            method: b"inc".to_vec(),
            args: vec![1, 2],
            calldata: vec![0u8; 100],
        }),
        contract_call_gas(3, 2, 100),
        "calldata bytes must be priced"
    );
}

// ---------------------------------------------------------------------------
// Precompile (ERC-20 emulation) abuse: malformed inputs fail clean
// ---------------------------------------------------------------------------

#[test]
fn precompile_malformed_inputs_fail_clean() {
    let adapter = EvmAdapter::new();

    // Unknown selector and empty input: honest empty, no panic.
    assert_eq!(adapter.emulate_erc20_call("0xdeadbeef"), "0x");
    assert_eq!(adapter.emulate_erc20_call("0x"), "0x");
    assert_eq!(adapter.emulate_erc20_call("not hex at all!!"), "0x");

    // Short word: strict 32-byte words only.
    assert_eq!(adapter.emulate_erc20_call("0x70a082311234"), "0x");
    assert_eq!(evm_adapter::extract_address_from_calldata("1234"), None);

    // Non-hex word: clean None.
    assert_eq!(
        evm_adapter::extract_address_from_calldata(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ),
        None
    );

    // Nonzero-padded word: NOT an address (malformed ABI) — must be empty,
    // never aliased to the embedded low 20 bytes.
    let padded = "0x70a08231ffffffffffffffffffffffff1111111111111111111111111111111111111111".to_string();
    assert_eq!(adapter.emulate_erc20_call(&padded), "0x");
    assert_eq!(
        evm_adapter::extract_address_from_calldata(
            "ffffffffffffffffffffffff1111111111111111111111111111111111111111"
        ),
        None
    );

    // Well-formed zero-padded word still resolves.
    assert_eq!(
        evm_adapter::extract_address_from_calldata(
            "0000000000000000000000001111111111111111111111111111111111111111"
        )
        .unwrap(),
        "0x1111111111111111111111111111111111111111"
    );

    // State-changing selectors are read-only emulation: pinned true, never error.
    for sel in ["a9059cbb", "095ea7b3", "23b87266"] {
        let out = adapter.emulate_erc20_call(&format!("0x{sel}"));
        assert_eq!(out, format!("0x{:0>64}", "1"), "selector {sel} must emulate true");
    }
    // Allowance emulation pins u128::MAX.
    let out = adapter.emulate_erc20_call("0xdd62ed3e");
    assert_eq!(out, format!("0x{:0>64x}", u128::MAX));
}

// ---------------------------------------------------------------------------
// State isolation: storage namespaced per contract
// ---------------------------------------------------------------------------

#[test]
fn storage_isolation_contract_cannot_touch_other_state() {
    let sender = [0x99u8; 32];
    let code_a = wat::parse_str(COUNTER_WAT).expect("wat");
    let code_b = wat::parse_str(COUNTER_WAT).expect("wat");
    let mut reg = ContractRegistry::new();
    let addr_a = reg.deploy([0x11u8; 32], code_a, 0).expect("deploy A");
    let addr_b = reg.deploy([0x22u8; 32], code_b, 0).expect("deploy B");
    assert_ne!(addr_a, addr_b);

    // Two increments on A, same key.
    for _ in 0..2 {
        let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
        let gas = contract_call_gas(3, 1, 0) + 100_000;
        match Svm::execute(&inc_call(addr_a, 7), gas, &mut ctx) {
            VmExecutionResult::Success { .. } => {}
            other => panic!("call A must succeed, got {other:?}"),
        }
    }
    // B untouched by A's writes despite sharing key and code.
    assert_eq!(reg.get(&addr_a).unwrap().storage.get(&7), Some(&2));
    assert_eq!(reg.get(&addr_b).unwrap().storage.get(&7), None);

    // One increment on B: A unchanged.
    let mut ctx = test_ctx(sender, 1_000_000, Some(&mut reg));
    let gas = contract_call_gas(3, 1, 0) + 100_000;
    match Svm::execute(&inc_call(addr_b, 7), gas, &mut ctx) {
        VmExecutionResult::Success { .. } => {}
        other => panic!("call B must succeed, got {other:?}"),
    }
    assert_eq!(reg.get(&addr_b).unwrap().storage.get(&7), Some(&1));
    assert_eq!(
        reg.get(&addr_a).unwrap().storage.get(&7),
        Some(&2),
        "B's write must not leak into A"
    );
}

// ---------------------------------------------------------------------------
// Reentrancy: no synchronous cross-contract call surface
// ---------------------------------------------------------------------------

#[test]
fn no_synchronous_cross_contract_call_surface() {
    // A contract importing a synchronous call host function cannot deploy:
    // the deploy-time dry-run instantiation rejects unresolvable imports.
    let reentrant = wat::parse_str(
        r#"(module
          (import "host" "call_contract" (func $call_contract (param i64) (result i64)))
          (func (export "evil") (param i64) (result i64)
            (call $call_contract (local.get 0))))"#,
    )
    .expect("wat parses");
    let mut reg = ContractRegistry::new();
    assert!(
        reg.deploy([0x33u8; 32], reentrant, 0).is_err(),
        "unresolvable host import must fail deploy"
    );

    // Paused contracts refuse calls fail-closed (no state change via reentry).
    let (mut reg, addr) = deploy_counter([0x44u8; 32]);
    reg.pause(&addr, [0x44u8; 32]).expect("creator pauses");
    let mut ctx = test_ctx([0x99u8; 32], 1_000_000, Some(&mut reg));
    let gas = contract_call_gas(3, 1, 0) + 100_000;
    match Svm::execute(&inc_call(addr, 1), gas, &mut ctx) {
        VmExecutionResult::Reverted(_) => {}
        other => panic!("paused call must revert, got {other:?}"),
    }
}
