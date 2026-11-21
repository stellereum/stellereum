//! Equivalence, isolation, eviction, concurrency, fuel, and snapshot tests for:
//! 1. Shared `wasmi::Engine` + bounded FIFO `wasmi::Module` cache keyed by `blake3(code)`
//!    (isolated `Store`, `Linker`, and `Instance` per invocation).
//! 2. `host.calldata` charging fuel before cloning `calldata` (`OutOfFuel` parity).
//! 3. `ContractRegistry::contracts` deterministic `BTreeMap` ordering and bincode
//!    round-trip compatibility with legacy `HashMap`-serialized snapshots.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use stellereum::commitment::contracts_preimage;
use stellereum::contract::{
    Contract, ContractCallContext, ContractError, ContractOutcome, ContractRegistry,
    CONTRACT_MODULE_CACHE_CAP, FUEL_CALLDATA, FUEL_CALLDATA_PER_BYTE, MAX_CONTRACT_CODE_SIZE,
};
use stellereum::contract_abi::{AbiMethod, AbiParam, AbiType, ContractAbi};
use stellereum::storage::DomainSnapshot;

fn rich_isolation_wasm(salt: u32) -> Vec<u8> {
    let wat_src = format!(
        r#"(module
          (import "host" "sload" (func $sload (param i64) (result i64)))
          (import "host" "sstore" (func $sstore (param i64 i64)))
          (import "host" "emit" (func $emit (param i64 i64)))
          (import "host" "caller" (func $caller (param i32)))
          (import "host" "value" (func $value (result i64)))
          (import "host" "calldata" (func $calldata (param i32) (result i64)))
          (import "host" "return_data" (func $return_data (param i32 i32)))
          (memory (export "memory") 2)
          (global $g (mut i64) (i64.const 10))
          (func (export "exec") (param $k i64) (param $delta i64) (result i64)
            (local $prev i64)
            (local $cd_len i64)
            (global.set $g (i64.add (global.get $g) (local.get $delta)))
            (local.set $prev (call $sload (local.get $k)))
            (call $sstore (local.get $k) (i64.add (local.get $prev) (global.get $g)))
            (call $emit (local.get $k) (global.get $g))
            (call $caller (i32.const 0))
            (local.set $cd_len (call $calldata (i32.const 32)))
            (call $return_data (i32.const 0) (i32.add (i32.const 32) (i32.wrap_i64 (local.get $cd_len))))
            (i64.add (i64.add (local.get $prev) (global.get $g)) (i64.add (call $value) (i64.const {salt}))))
          (func (export "get_sum") (param $k i64) (result i64)
            (global.set $g (i64.add (global.get $g) (i64.const 5)))
            (call $emit (i64.const 99) (global.get $g))
            (i64.add (i64.add (call $sload (local.get $k)) (global.get $g)) (i64.const {salt}))))"#
    );
    wat::parse_str(&wat_src).expect("rich isolation wat compiles")
}

fn counter_offset_wasm(offset: i64) -> Vec<u8> {
    let wat_src = format!(
        r#"(module
          (global $g (mut i64) (i64.const 3))
          (func (export "calc") (param $x i64) (result i64)
            (global.set $g (i64.add (global.get $g) (local.get $x)))
            (i64.add (global.get $g) (i64.const {offset}))))"#
    );
    wat::parse_str(&wat_src).expect("counter offset wat compiles")
}

fn calldata_reader_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "calldata" (func $calldata (param i32) (result i64)))
          (memory (export "memory") 2)
          (func (export "read_cd") (param $dummy i64) (result i64)
            (call $calldata (i32.const 0))))"#,
    )
    .expect("calldata reader wat compiles")
}

fn insert_raw_contract(reg: &mut ContractRegistry, addr: [u8; 32], code: Vec<u8>) {
    let code_hash: [u8; 32] = Sha256::digest(&code).into();
    reg.contracts.insert(
        addr,
        Contract {
            address: addr,
            creator: [0x11; 32],
            code_hash,
            code,
            storage: HashMap::new(),
            created_at: 1,
            paused: false,
            balance: 0,
            abi: None,
            source_hash: None,
        },
    );
}

#[test]
fn cold_and_hot_cache_run_contract_and_get_method_are_identical_and_isolated() {
    let code = rich_isolation_wasm(123);
    let addr = [0xA1; 32];

    let mut reg_cold = ContractRegistry::new();
    insert_raw_contract(&mut reg_cold, addr, code.clone());

    let mut reg_hot = ContractRegistry::new();
    insert_raw_contract(&mut reg_hot, addr, code.clone());

    let ctx = ContractCallContext {
        caller: [0x42; 32],
        value: 500,
        block_time: 1_700_000_000,
        block_hash: [0x77; 32],
    };
    let cd = b"stellereum-cache-calldata";

    // Cold read-only get_method before any validate_code/deploy on this bytecode.
    let get_cold = reg_cold.run_get_method(&addr, "get_sum", &[1], None);
    assert!(get_cold.success);
    assert_eq!(get_cold.return_value, Some(5 + 10 + 123));

    // Hot read-only get_method on an independent registry.
    let get_hot = reg_hot.run_get_method(&addr, "get_sum", &[1], None);
    assert_eq!(get_hot, get_cold);

    // Cold vs hot state-changing execution on two fresh registries with identical initial state.
    let out_cold: ContractOutcome = reg_cold
        .call_with_context_args_calldata(&addr, "exec", &[1, 7], cd, 200_000, &ctx)
        .expect("cold exec succeeds");
    let out_hot: ContractOutcome = reg_hot
        .call_with_context_args_calldata(&addr, "exec", &[1, 7], cd, 200_000, &ctx)
        .expect("hot exec succeeds");

    assert_eq!(out_cold, out_hot);
    assert_eq!(out_cold.result, 17 + 500 + 123);
    assert_eq!(out_cold.return_data.len(), 32 + cd.len());
    assert_eq!(&out_cold.return_data[..32], &ctx.caller);
    assert_eq!(&out_cold.return_data[32..], cd);
    assert_eq!(
        reg_cold.get(&addr).unwrap().storage,
        reg_hot.get(&addr).unwrap().storage
    );
    assert_eq!(reg_cold.get(&addr).unwrap().storage.get(&1), Some(&17));

    // Repeated call on the SAME registry still starts with a fresh Instance ($g = 10),
    // proving global/memory state never leaks across cached Module executions.
    let out_second = reg_hot
        .call_with_context_args_calldata(&addr, "exec", &[1, 7], cd, 200_000, &ctx)
        .expect("second exec succeeds");
    assert_eq!(out_second.result, 17 + 17 + 500 + 123);
    assert_eq!(out_second.fuel_used, out_cold.fuel_used);
    assert_eq!(reg_hot.get(&addr).unwrap().storage.get(&1), Some(&34));

    // Read-only getter observes the updated storage without mutating it.
    let get_after = reg_hot.run_get_method(&addr, "get_sum", &[1], None);
    assert!(get_after.success);
    assert_eq!(get_after.return_value, Some(34 + 15 + 123));
    let get_after_repeat = reg_hot.run_get_method(&addr, "get_sum", &[1], None);
    assert_eq!(get_after_repeat, get_after);
    assert_eq!(reg_hot.get(&addr).unwrap().storage.get(&1), Some(&34));
}

#[test]
fn module_cache_eviction_beyond_capacity_preserves_exact_equivalence() {
    let mut reg = ContractRegistry::new();
    let total = CONTRACT_MODULE_CACHE_CAP + 32;
    let mut entries = Vec::with_capacity(total);

    for i in 0..total {
        // Offset by 1_000_000 so bytecodes do not collide with other tests.
        let offset = 1_000_000 + i as i64;
        let code = counter_offset_wasm(offset);
        assert!(ContractRegistry::validate_code(&code).is_ok());
        let addr = reg
            .deploy([0x22; 32], code, i as u64)
            .expect("deploy succeeds");
        entries.push((addr, offset));
    }

    // Record baseline outcomes for the earliest (now evicted) and latest (hot) contracts.
    let (first_addr, first_offset) = entries[0];
    let (mid_addr, mid_offset) = entries[16];
    let (last_addr, last_offset) = entries[total - 1];

    let first_before = reg.call(&first_addr, "calc", 10, 50_000).unwrap();
    let first_get_before = reg.run_get_method(&first_addr, "calc", &[10], None);

    // Re-fill the entire cache capacity with newer modules so `first_addr` is guaranteed evicted.
    for i in total..(total + CONTRACT_MODULE_CACHE_CAP + 8) {
        let code = counter_offset_wasm(1_000_000 + i as i64);
        assert!(ContractRegistry::validate_code(&code).is_ok());
    }

    // Re-validate and re-execute the evicted module: behavior & fuel must be identical.
    assert!(ContractRegistry::validate_code(&reg.get(&first_addr).unwrap().code).is_ok());
    let first_after = reg.call(&first_addr, "calc", 10, 50_000).unwrap();
    let first_get_after = reg.run_get_method(&first_addr, "calc", &[10], None);
    assert_eq!(first_after, first_before);
    assert_eq!(first_after.0, 13 + first_offset);
    assert_eq!(first_get_after, first_get_before);

    // Mid and last contracts also remain exact.
    let mid_res = reg.call(&mid_addr, "calc", 10, 50_000).unwrap();
    assert_eq!(mid_res.0, 13 + mid_offset);
    let last_res = reg.call(&last_addr, "calc", 10, 50_000).unwrap();
    assert_eq!(last_res.0, 13 + last_offset);
}

#[test]
fn concurrent_validation_call_and_get_method_are_deterministic_and_isolated() {
    let shared_code = Arc::new(rich_isolation_wasm(777));
    let mut base_reg = ContractRegistry::new();
    let addr = base_reg
        .deploy([0x33; 32], (*shared_code).clone(), 0)
        .expect("deploy succeeds");

    let ctx = ContractCallContext {
        caller: [0x55; 32],
        value: 25,
        block_time: 42,
        block_hash: [0x88; 32],
    };
    let cd = b"parallel-wasm-check";
    let expected_outcome = base_reg
        .clone()
        .call_with_context_args_calldata(&addr, "exec", &[5, 9], cd, 200_000, &ctx)
        .expect("baseline exec succeeds");
    let expected_get = base_reg.run_get_method(&addr, "get_sum", &[5], None);

    std::thread::scope(|s| {
        for tid in 0..8u64 {
            let base = &base_reg;
            let code_ref = Arc::clone(&shared_code);
            let expected_out = &expected_outcome;
            let expected_getter = &expected_get;
            let ctx_ref = &ctx;

            s.spawn(move || {
                for iter in 0..16u64 {
                    assert!(ContractRegistry::validate_code(&code_ref).is_ok());

                    // Unique per-thread/iteration module to interleave cache misses & evictions.
                    let unique_code = counter_offset_wasm(2_000_000 + ((tid * 100 + iter) as i64));
                    assert!(ContractRegistry::validate_code(&unique_code).is_ok());

                    let mut local_reg = base.clone();
                    let out = local_reg
                        .call_with_context_args_calldata(
                            &addr,
                            "exec",
                            &[5, 9],
                            cd,
                            200_000,
                            ctx_ref,
                        )
                        .expect("concurrent exec succeeds");
                    assert_eq!(&out, expected_out);
                    assert_eq!(local_reg.get(&addr).unwrap().storage.get(&5), Some(&19));

                    let getter = base.run_get_method(&addr, "get_sum", &[5], None);
                    assert_eq!(&getter, expected_getter);
                }
            });
        }
    });
}

#[test]
fn invalid_wasm_errors_match_on_cache_miss_and_cache_hit() {
    assert_eq!(
        ContractRegistry::validate_code(&[]),
        Err(ContractError::EmptyCode)
    );
    assert_eq!(
        ContractRegistry::validate_code(&vec![0u8; MAX_CONTRACT_CODE_SIZE + 1]),
        Err(ContractError::CodeTooLarge)
    );

    // 1. Syntactically invalid WASM (never cached, always InvalidWasm).
    let garbage = b"not-valid-wasm-bytecode-01".to_vec();
    for _ in 0..4 {
        assert_eq!(
            ContractRegistry::validate_code(&garbage),
            Err(ContractError::InvalidWasm)
        );
    }

    let truncated = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0xff];
    let mut bad_reg = ContractRegistry::new();
    let bad_addr = [0xB1; 32];
    insert_raw_contract(&mut bad_reg, bad_addr, truncated.clone());
    for _ in 0..4 {
        assert_eq!(
            ContractRegistry::validate_code(&truncated),
            Err(ContractError::InvalidWasm)
        );
        assert_eq!(
            bad_reg.call(&bad_addr, "f", 0, 10_000),
            Err(ContractError::InvalidWasm)
        );
        let resp = bad_reg.run_get_method(&bad_addr, "f", &[0], None);
        assert!(!resp.success);
        assert_eq!(resp.fuel_used, 0);
        assert_eq!(
            resp.error.as_deref(),
            Some("contract code is not a valid wasm module")
        );
    }

    // 2. Excess memory pages (129 > MAX_CONTRACT_PAGES = 128).
    let over_mem = wat::parse_str(
        r#"(module (memory 129) (func (export "f") (param i64) (result i64) local.get 0))"#,
    )
    .unwrap();
    for _ in 0..4 {
        assert_eq!(
            ContractRegistry::validate_code(&over_mem),
            Err(ContractError::InvalidWasm)
        );
    }

    // 3. Valid WASM module with unresolvable host import (Module::new succeeds,
    //    instantiation fails identically on miss and hit).
    let bad_import = wat::parse_str(
        r#"(module
          (import "host" "nonexistent_fn" (func $missing (param i64) (result i64)))
          (func (export "f") (param i64) (result i64)
            (call $missing (local.get 0))))"#,
    )
    .unwrap();
    for _ in 0..4 {
        assert_eq!(
            ContractRegistry::validate_code(&bad_import),
            Err(ContractError::UnresolvableImports)
        );
    }

    // 4. Valid WASM module whose `start` function traps (Module::new succeeds,
    //    instantiate_and_start fails identically on miss and hit).
    let trapping_start = wat::parse_str(
        r#"(module
          (func $init (unreachable))
          (start $init)
          (func (export "f") (param i64) (result i64)
            (local.get 0)))"#,
    )
    .unwrap();
    let trap_addr = [0xB2; 32];
    insert_raw_contract(&mut bad_reg, trap_addr, trapping_start.clone());
    for _ in 0..4 {
        assert_eq!(
            ContractRegistry::validate_code(&trapping_start),
            Err(ContractError::InvalidWasm)
        );
        assert_eq!(
            bad_reg.call(&trap_addr, "f", 0, 10_000),
            Err(ContractError::InvalidWasm)
        );
        let resp = bad_reg.run_get_method(&trap_addr, "f", &[0], None);
        assert!(!resp.success);
        assert_eq!(resp.error.as_deref(), Some("contract instantiation failed"));
    }
}

#[test]
fn host_calldata_charges_fuel_before_clone_and_preserves_out_of_fuel() {
    let code = calldata_reader_wasm();
    let mut reg = ContractRegistry::new();
    let addr = reg.deploy([0x44; 32], code, 0).expect("deploy succeeds");
    let ctx = ContractCallContext::default();

    let big_calldata = vec![0xABu8; 64 * 1024];
    let expected_host_fuel = FUEL_CALLDATA + (big_calldata.len() as u64) * FUEL_CALLDATA_PER_BYTE;

    // Various insufficient fuel budgets must all return OutOfFuel deterministically.
    for budget in [1u64, 100, expected_host_fuel - 1, expected_host_fuel] {
        let err = reg
            .call_with_context_args_calldata(&addr, "read_cd", &[0], &big_calldata, budget, &ctx)
            .unwrap_err();
        assert_eq!(err, ContractError::OutOfFuel, "budget={budget}");
    }

    // Sufficient fuel succeeds and returns the exact calldata byte length.
    let outcome = reg
        .call_with_context_args_calldata(
            &addr,
            "read_cd",
            &[0],
            &big_calldata,
            expected_host_fuel + 10_000,
            &ctx,
        )
        .expect("sufficient fuel succeeds");
    assert_eq!(outcome.result, big_calldata.len() as i64);
    assert!(outcome.fuel_used > expected_host_fuel);

    // Empty calldata works with minimal fuel and still charges FUEL_CALLDATA on OOF.
    let empty_err = reg
        .call_with_context_args_calldata(&addr, "read_cd", &[0], &[], 1, &ctx)
        .unwrap_err();
    assert_eq!(empty_err, ContractError::OutOfFuel);

    let empty_ok = reg
        .call_with_context_args_calldata(&addr, "read_cd", &[0], &[], 1_000, &ctx)
        .expect("empty calldata succeeds");
    assert_eq!(empty_ok.result, 0);
    assert!(empty_ok.fuel_used >= FUEL_CALLDATA);
}

#[test]
fn contract_registry_btreemap_order_and_bincode_roundtrip_legacy_compat() {
    #[derive(Serialize)]
    struct LegacyContractRegistry {
        contracts: HashMap<[u8; 32], Contract>,
        next_nonce: u64,
        last_return_data: Vec<u8>,
    }

    let order_a: [u8; 6] = [0x50, 0x10, 0x90, 0x30, 0x70, 0x20];
    let order_b: [u8; 6] = [0x20, 0x90, 0x10, 0x70, 0x30, 0x50];

    let mut reg_a = ContractRegistry::new();
    let mut reg_b = ContractRegistry::new();

    let abi = ContractAbi {
        methods: vec![AbiMethod::view(
            "calc",
            vec![AbiParam::new("x", AbiType::I64)],
            AbiType::I64,
        )],
        events: vec![],
    };

    for (idx, b) in order_a.iter().enumerate() {
        let addr = [*b; 32];
        let code = counter_offset_wasm(3_000_000 + *b as i64);
        let code_hash: [u8; 32] = Sha256::digest(&code).into();
        let mut storage = HashMap::new();
        storage.insert(1, *b as i64);
        reg_a.contracts.insert(
            addr,
            Contract {
                address: addr,
                creator: [0x01; 32],
                code_hash,
                code,
                storage,
                created_at: idx as u64 + 10,
                paused: idx % 2 == 1,
                balance: (*b as u64) * 1_000,
                abi: if idx % 2 == 0 {
                    Some(abi.clone())
                } else {
                    None
                },
                source_hash: if idx % 3 == 0 {
                    Some([*b ^ 0xFF; 32])
                } else {
                    None
                },
            },
        );
    }
    reg_a.next_nonce = 42;
    reg_a.last_return_data = b"ret-bytes".to_vec();

    for b in order_b.iter() {
        let addr = [*b; 32];
        reg_b
            .contracts
            .insert(addr, reg_a.contracts.get(&addr).unwrap().clone());
    }
    reg_b.next_nonce = 42;
    reg_b.last_return_data = b"ret-bytes".to_vec();

    // 1. Key order is strictly sorted and independent of insertion order.
    let keys_a: Vec<[u8; 32]> = reg_a.contracts.keys().copied().collect();
    let keys_b: Vec<[u8; 32]> = reg_b.contracts.keys().copied().collect();
    assert_eq!(keys_a, keys_b);
    assert!(keys_a.windows(2).all(|w| w[0] < w[1]));

    // 2. Bincode round-trip of ContractRegistry and DomainSnapshot.
    let encoded = bincode::serialize(&reg_a).expect("serialize ContractRegistry");
    let decoded: ContractRegistry =
        bincode::deserialize(&encoded).expect("deserialize ContractRegistry");
    assert_eq!(decoded.next_nonce, reg_a.next_nonce);
    assert_eq!(decoded.last_return_data, reg_a.last_return_data);
    assert_eq!(
        decoded.contracts.keys().copied().collect::<Vec<_>>(),
        keys_a
    );
    for (k, orig) in &reg_a.contracts {
        let got = decoded.contracts.get(k).expect("contract present");
        assert_eq!(got.address, orig.address);
        assert_eq!(got.creator, orig.creator);
        assert_eq!(got.code_hash, orig.code_hash);
        assert_eq!(got.code, orig.code);
        assert_eq!(got.storage, orig.storage);
        assert_eq!(got.created_at, orig.created_at);
        assert_eq!(got.paused, orig.paused);
        assert_eq!(got.balance, orig.balance);
        assert_eq!(got.abi, orig.abi);
        assert_eq!(got.source_hash, orig.source_hash);
    }
    assert_eq!(contracts_preimage(&decoded), contracts_preimage(&reg_a));

    let snap = DomainSnapshot {
        contracts: reg_a.clone(),
        ..Default::default()
    };
    let snap_bytes = bincode::serialize(&snap).expect("serialize DomainSnapshot");
    let snap_decoded: DomainSnapshot =
        bincode::deserialize(&snap_bytes).expect("deserialize DomainSnapshot");
    assert_eq!(
        contracts_preimage(&snap_decoded.contracts),
        contracts_preimage(&reg_a)
    );

    // 3. Legacy HashMap-serialized bytes decode cleanly into the BTreeMap-backed
    //    ContractRegistry with identical byte length and commitment preimage.
    let mut legacy_map = HashMap::new();
    for (k, v) in &reg_a.contracts {
        legacy_map.insert(*k, v.clone());
    }
    let legacy = LegacyContractRegistry {
        contracts: legacy_map,
        next_nonce: reg_a.next_nonce,
        last_return_data: reg_a.last_return_data.clone(),
    };
    let legacy_bytes = bincode::serialize(&legacy).expect("serialize LegacyContractRegistry");
    assert_eq!(legacy_bytes.len(), encoded.len());

    let upgraded: ContractRegistry =
        bincode::deserialize(&legacy_bytes).expect("decode legacy HashMap bytes into BTreeMap");
    assert_eq!(upgraded.next_nonce, reg_a.next_nonce);
    assert_eq!(upgraded.last_return_data, reg_a.last_return_data);
    assert_eq!(
        upgraded.contracts.keys().copied().collect::<Vec<_>>(),
        keys_a
    );
    assert_eq!(contracts_preimage(&upgraded), contracts_preimage(&reg_a));
}
