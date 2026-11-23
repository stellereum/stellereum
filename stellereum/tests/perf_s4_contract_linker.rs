//! S4 (perf) regression: the host `Linker` for the process-wide wasmi engine is
//! built ONCE, not per contract invocation.
//!
//! `validate_code`, `validate_code_hardened`, `run_get_method` and the
//! hardened (>= H) consensus contract call all run on the shared
//! `contract_engine()`. Building the host linker registers 14 host functions
//! (string interning, a fresh trampoline `Arc` and a `BTreeMap` insert each)
//! for a definition table that never changes, so it is cached now.
//!
//! The cache is ONLY valid for the shared engine: the pre-R1 path builds a
//! per-call `consensus_contract_engine()` and must keep building its own
//! linker over it (`Linker::instantiate_and_start` asserts the engine
//! identity). This test pins both directions and that the cached linker
//! executes byte-identically to a freshly built one.

use std::collections::HashMap;

use stellereum::contract::{
    run_contract_hardened, Contract, ContractCallContext, ContractRegistry,
};

const ADDR: [u8; 32] = [0xA1; 32];

/// A self-contained module (no imports, no memory) with one getter. The
/// mutable global starts fresh on every instantiation, so repeated calls are
/// directly comparable.
fn tiny_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (global $g (mut i64) (i64.const 3))
          (func (export "calc") (param $x i64) (result i64)
            (global.set $g (i64.add (global.get $g) (local.get $x)))
            (i64.add (global.get $g) (i64.const 7))))"#,
    )
    .expect("tiny contract compiles")
}

fn insert_raw_contract(reg: &mut ContractRegistry, addr: [u8; 32], code: Vec<u8>) {
    let code_hash: [u8; 32] = *blake3::hash(&code).as_bytes();
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
fn shared_engine_host_linker_is_built_once_and_executes_identically() {
    let code = tiny_wasm();
    let ctx = ContractCallContext {
        caller: [0x42; 32],
        value: 0,
        block_time: 1_700_000_000,
        block_hash: [0x77; 32],
    };

    // Warm the process-wide engine + linker, so the baseline is the steady
    // state (`CONTRACT_LINKER` is a `OnceLock`).
    ContractRegistry::validate_code(&code).expect("valid wasm");
    let baseline = ContractRegistry::perf_s4_host_linker_builds();

    // Every repeated use of the shared engine must reuse it.
    ContractRegistry::validate_code(&code).expect("valid wasm");
    ContractRegistry::validate_code_hardened(&code, 1_000_000).expect("valid wasm");

    let mut reg = ContractRegistry::new();
    insert_raw_contract(&mut reg, ADDR, code.clone());

    let get1 = reg.run_get_method(&ADDR, "calc", &[7], Some(100_000));
    let get2 = reg.run_get_method(&ADDR, "calc", &[7], Some(100_000));
    assert!(get1.success, "getter must succeed: {get1:?}");
    assert_eq!(get1.return_value, Some(17), "3 + 7 + 7");
    assert_eq!(
        get1, get2,
        "the cached linker executes identically on repeated calls"
    );

    let out1 = reg
        .call_with_context_hardened(
            &ADDR, "calc", 7, 100_000, &ctx, ctx.caller, ctx.caller, true,
        )
        .expect("hardened call runs on the shared engine");
    let out2 = reg
        .call_with_context_hardened(
            &ADDR, "calc", 7, 100_000, &ctx, ctx.caller, ctx.caller, true,
        )
        .expect("hardened call runs on the shared engine");
    assert_eq!(out1.result, 17);
    assert_eq!(
        (out1.result, out1.fuel_used),
        (out2.result, out2.fuel_used),
        "the cached linker burns identical fuel and returns identical values"
    );

    assert_eq!(
        ContractRegistry::perf_s4_host_linker_builds(),
        baseline,
        "S4: validation, read-only getters and hardened consensus calls must NOT rebuild the \
         host linker for the shared engine"
    );

    // Counter liveness + cache scope: the pre-R1 path owns a PER-CALL engine,
    // so it must build its own linker over it.
    let before_legacy = ContractRegistry::perf_s4_host_linker_builds();
    let legacy = run_contract_hardened(
        ADDR,
        &code,
        &HashMap::new(),
        0,
        "calc",
        &[7],
        &[],
        100_000,
        &ctx,
        ctx.caller,
        false,
    )
    .expect("the pre-R1 execution path still works");
    assert_eq!(legacy.0, 17, "same contract, same result");
    assert_eq!(
        ContractRegistry::perf_s4_host_linker_builds(),
        before_legacy + 1,
        "S4: a per-call engine must still build its own linker (the cache is scoped to the \
         shared engine, where reuse is sound)"
    );
}
