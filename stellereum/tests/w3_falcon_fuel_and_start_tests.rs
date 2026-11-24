//! Wave 3 Activation Batch 1 regressions:
//! - `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT` (`u64::MAX`, INERT):
//!   * Pre-activation (`< H` / default `u64::MAX`): `host.falcon512_verify`
//!     charges `FUEL_FALCON512_VERIFY` (`2_000` + byte lengths) and
//!     `SysCallDeployContract` preserves legacy `(start)` gas accounting.
//!   * Post-activation (`>= H`): `host.falcon512_verify` charges
//!     `FUEL_FALCON512_VERIFY_V2` (`150_000` + byte lengths, trapping with
//!     `OutOfFuel` / `OutOfGas` under `20_000` fuel), and
//!     `SysCallDeployContract` validates and runs `(start)` **once** while
//!     deducting actual `(start)` fuel from `state.gas_remaining` (capped at
//!     `min(VALIDATE_CODE_START_FUEL_LIMIT, state.gas_remaining)`).
//! - `WASM_TABLE_ELEMENTS_CAP_HEIGHT` (`u64::MAX`, INERT):
//!   * Wired into `svm.rs` (`SysCallDeployContract`, `SysCallCallContract`,
//!     `SysCallCallContractArgs`) and `state_engine/contracts.rs`
//!     (`deploy_contract_deterministic_at`): uncapped below `H`, enforced at `H`.

use std::collections::HashMap;
use std::fmt::Write as _;

use stellereum::chain_spec::{
    current_activation_schedule, falcon_host_fuel_v2_active_at,
    set_falcon_host_fuel_v2_activation_override, set_wasm_table_elements_cap_override,
    wasm_table_elements_cap_active_at, ActivationStatus, FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT,
};
use stellereum::contract::{
    contract_address, contract_deploy_gas, run_contract_hardened_at, ContractCallContext,
    ContractError, ContractRegistry, FUEL_FALCON512_VERIFY, FUEL_FALCON512_VERIFY_V2,
    MAX_CONTRACT_TABLE_ELEMENTS, VALIDATE_CODE_START_FUEL_LIMIT,
};
use stellereum::feature_gates;
use stellereum::post_quantum::{FalconKeypair, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{
    contract_call_gas, ActorSendRequest, OpCode, Svm, VmContext, VmExecOptions, VmExecutionResult,
};

struct GateResetGuard;

impl Drop for GateResetGuard {
    fn drop(&mut self) {
        set_falcon_host_fuel_v2_activation_override(None);
        set_wasm_table_elements_cap_override(None);
    }
}

fn escape_wat_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        let _ = write!(&mut out, "\\{b:02x}");
    }
    out
}

fn falcon_verify_wasm() -> Vec<u8> {
    let kp = FalconKeypair::generate_from_seed(0x5A);
    let msg = b"w3 falcon fuel v2 verification msg";
    let sig = kp.sign(msg);
    assert_eq!(kp.public_key.len(), FALCON512_PUBKEY_LEN);
    assert_eq!(sig.len(), FALCON512_SIG_LEN);

    let wat_src = format!(
        r#"(module
             (import "host" "falcon512_verify" (func $falcon512_verify (param i32 i32 i32 i32 i32 i32) (result i32)))
             (memory (export "memory") 1)
             (data (i32.const 0) "{msg_esc}")
             (data (i32.const 64) "{pk_esc}")
             (data (i32.const 1024) "{sig_esc}")
             (func (export "verify_sig") (param $dummy i64) (result i64)
               (i64.extend_i32_u
                 (call $falcon512_verify
                   (i32.const 0) (i32.const {msg_len})
                   (i32.const 64) (i32.const {pk_len})
                   (i32.const 1024) (i32.const {sig_len})))))"#,
        msg_esc = escape_wat_bytes(msg),
        pk_esc = escape_wat_bytes(&kp.public_key),
        sig_esc = escape_wat_bytes(&sig),
        msg_len = msg.len(),
        pk_len = kp.public_key.len(),
        sig_len = sig.len(),
    );
    wat::parse_str(&wat_src).expect("falcon_verify_wasm compiles")
}

fn start_loop_wasm(iters: u64) -> Vec<u8> {
    let wat_src = format!(
        r#"(module
             (func $init
               (local $i i64)
               (local.set $i (i64.const 0))
               (loop $l
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))
                 (br_if $l (i64.lt_u (local.get $i) (i64.const {iters})))))
             (start $init)
             (func (export "ping") (param i64) (result i64)
               (i64.const 7)))"#
    );
    wat::parse_str(&wat_src).expect("start_loop_wasm compiles")
}

fn start_falcon_verify_wasm() -> Vec<u8> {
    let kp = FalconKeypair::generate_from_seed(0x6B);
    let msg = b"w3 start falcon verify";
    let sig = kp.sign(msg);
    let wat_src = format!(
        r#"(module
             (import "host" "falcon512_verify" (func $falcon512_verify (param i32 i32 i32 i32 i32 i32) (result i32)))
             (memory (export "memory") 1)
             (data (i32.const 0) "{msg_esc}")
             (data (i32.const 64) "{pk_esc}")
             (data (i32.const 1024) "{sig_esc}")
             (func $init
               (drop
                 (call $falcon512_verify
                   (i32.const 0) (i32.const {msg_len})
                   (i32.const 64) (i32.const {pk_len})
                   (i32.const 1024) (i32.const {sig_len}))))
             (start $init)
             (func (export "ping") (param i64) (result i64)
               (i64.const 9)))"#,
        msg_esc = escape_wat_bytes(msg),
        pk_esc = escape_wat_bytes(&kp.public_key),
        sig_esc = escape_wat_bytes(&sig),
        msg_len = msg.len(),
        pk_len = kp.public_key.len(),
        sig_len = sig.len(),
    );
    wat::parse_str(&wat_src).expect("start_falcon_verify_wasm compiles")
}

fn oversized_table_with_ping_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (table 100000 funcref)
             (func (export "ping") (param $x i64) (result i64)
               (i64.add (local.get $x) (i64.const 1))))"#,
    )
    .expect("oversized_table_with_ping_wasm compiles")
}

fn make_vm_ctx(sender: [u8; 32], contracts: &mut ContractRegistry) -> VmContext<'_> {
    VmContext {
        sender,
        balance: 100_000_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: 1_700_000_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts: Some(contracts),
        staking: None,
        pmm: None,
        min_validator_bond: 1_000,
        default_commission_bps: 100,
        payouts: Vec::new(),
        oracle: None,
    }
}

#[test]
fn falcon_host_fuel_v2_gate_is_inert_by_default() {
    let _reset = GateResetGuard;
    assert_eq!(FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT, u64::MAX);
    assert_eq!(FUEL_FALCON512_VERIFY, 2_000);
    assert_eq!(FUEL_FALCON512_VERIFY_V2, 150_000);

    for height in [0u64, 1, 1_000, 10_000_000, u64::MAX - 1, u64::MAX] {
        assert!(!falcon_host_fuel_v2_active_at(height));
        assert!(!wasm_table_elements_cap_active_at(height));
    }

    let schedule = current_activation_schedule();
    for name in [
        "WASM_TABLE_ELEMENTS_CAP_HEIGHT",
        "FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT",
    ] {
        let gate = schedule
            .gates
            .iter()
            .find(|g| g.name == name)
            .unwrap_or_else(|| panic!("{name} must be in current_activation_schedule()"));
        assert_eq!(gate.activation_height, u64::MAX);
        assert_eq!(gate.status, ActivationStatus::GatedOff);
    }

    let table = feature_gates::table();
    let row = table
        .iter()
        .find(|g| g.id == "falcon-host-fuel-v2")
        .expect("falcon-host-fuel-v2 must be in feature_gates::table()");
    assert_eq!(row.symbol, "FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT");
    assert_eq!(row.value, u64::MAX);
    assert_eq!(row.status(), "INERT");
    assert_eq!(row.test, Some("tests/w3_falcon_fuel_and_start_tests.rs"));
}

#[test]
fn falcon512_verify_fuel_is_byte_identical_below_gate_and_v2_at_or_above_gate() {
    let _reset = GateResetGuard;
    const H: u64 = 500;
    set_falcon_host_fuel_v2_activation_override(Some(H));

    let code = falcon_verify_wasm();
    let creator = [0x11u8; 32];
    let ctx = ContractCallContext {
        caller: creator,
        value: 0,
        block_time: 1_700_000_000,
        block_hash: [0u8; 32],
    };

    // Direct run_contract_hardened_at check:
    // Below H (H - 1): 20_000 fuel succeeds and burns ~2_000 + lengths (< 20_000).
    let (res_pre, fuel_pre, ..) = run_contract_hardened_at(
        [0x22u8; 32],
        &code,
        &HashMap::new(),
        0,
        "verify_sig",
        &[0],
        &[],
        20_000,
        &ctx,
        creator,
        true,
        H - 1,
    )
    .expect("pre-activation falcon512_verify must succeed under 20_000 fuel");
    assert_eq!(res_pre, 1);
    assert!(fuel_pre >= FUEL_FALCON512_VERIFY);
    assert!(fuel_pre < 20_000);

    // At H: 20_000 fuel MUST trap with OutOfFuel.
    let err_at_h = run_contract_hardened_at(
        [0x22u8; 32],
        &code,
        &HashMap::new(),
        0,
        "verify_sig",
        &[0],
        &[],
        20_000,
        &ctx,
        creator,
        true,
        H,
    )
    .unwrap_err();
    assert_eq!(err_at_h, ContractError::OutOfFuel);

    // At H with 250_000 fuel: succeeds and burns exact delta (150_000 - 2_000 = 148_000) more.
    let (res_post, fuel_post, ..) = run_contract_hardened_at(
        [0x22u8; 32],
        &code,
        &HashMap::new(),
        0,
        "verify_sig",
        &[0],
        &[],
        250_000,
        &ctx,
        creator,
        true,
        H,
    )
    .expect("post-activation falcon512_verify must succeed with 250_000 fuel");
    assert_eq!(res_post, 1);
    assert_eq!(
        fuel_post - fuel_pre,
        FUEL_FALCON512_VERIFY_V2 - FUEL_FALCON512_VERIFY
    );

    // End-to-end SVM check (`SysCallCallContract` and `SysCallCallContractArgs`).
    let mut reg = ContractRegistry::new();
    let addr = reg.deploy_with_nonce(creator, code, 0, 1).unwrap();
    let call_base = contract_call_gas(b"verify_sig".len(), 1, 0);

    // Below H: succeeds with call_base + 20_000 gas.
    let mut sends = Vec::<ActorSendRequest>::new();
    let opts_pre = VmExecOptions {
        wasm_pmm_hardening: true,
        chain_height: H - 1,
        ..Default::default()
    };
    let mut vm_ctx_pre = make_vm_ctx(creator, &mut reg);
    let svm_pre = Svm::execute_with_confidential_and_sends_at(
        &[OpCode::SysCallCallContract {
            contract: addr,
            method: b"verify_sig".to_vec(),
            arg: 0,
        }],
        call_base + 20_000,
        &mut vm_ctx_pre,
        &mut sends,
        None,
        &opts_pre,
    );
    match svm_pre {
        VmExecutionResult::Success {
            gas_used,
            return_value,
            ..
        } => {
            assert_eq!(return_value, Some(1));
            assert_eq!(gas_used, call_base + fuel_pre);
        }
        other => panic!("expected Success below H, got {other:?}"),
    }

    // At H: 20_000 contract fuel fails with OutOfGas.
    let opts_post = VmExecOptions {
        wasm_pmm_hardening: true,
        chain_height: H,
        ..Default::default()
    };
    let mut vm_ctx_oof = make_vm_ctx(creator, &mut reg);
    let svm_oof = Svm::execute_with_confidential_and_sends_at(
        &[OpCode::SysCallCallContract {
            contract: addr,
            method: b"verify_sig".to_vec(),
            arg: 0,
        }],
        call_base + 20_000,
        &mut vm_ctx_oof,
        &mut sends,
        None,
        &opts_post,
    );
    assert!(
        matches!(svm_oof, VmExecutionResult::OutOfGas),
        "expected OutOfGas at H under 20_000 fuel, got {svm_oof:?}"
    );

    // At H via SysCallCallContractArgs with sufficient gas: charges v2 fuel.
    let args_base = contract_call_gas(b"verify_sig".len(), 1, 0);
    let mut vm_ctx_post = make_vm_ctx(creator, &mut reg);
    let svm_post = Svm::execute_with_confidential_and_sends_at(
        &[OpCode::SysCallCallContractArgs {
            contract: addr,
            method: b"verify_sig".to_vec(),
            args: vec![0],
            calldata: Vec::new(),
        }],
        args_base + 250_000,
        &mut vm_ctx_post,
        &mut sends,
        None,
        &opts_post,
    );
    match svm_post {
        VmExecutionResult::Success {
            gas_used,
            return_value,
            ..
        } => {
            assert_eq!(return_value, Some(1));
            assert_eq!(gas_used, args_base + fuel_post);
        }
        other => panic!("expected Success at H with 250_000 fuel, got {other:?}"),
    }
}

#[test]
fn deploy_runs_start_once_and_charges_start_fuel_at_or_above_gate() {
    let _reset = GateResetGuard;
    const H: u64 = 1_000;
    set_falcon_host_fuel_v2_activation_override(Some(H));

    let code = start_loop_wasm(5_000);
    let deploy_base = contract_deploy_gas(code.len());
    let single_start_fuel = ContractRegistry::validate_code_hardened_and_measure_at(
        &code,
        VALIDATE_CODE_START_FUEL_LIMIT,
        H,
    )
    .expect("single start measurement must succeed");
    assert!(
        single_start_fuel > 10_000,
        "5_000-iter (start) loop should burn substantial fuel, got {single_start_fuel}"
    );

    let sender = [0x33u8; 32];
    let mut sends = Vec::<ActorSendRequest>::new();

    // 1. Pre-activation (H - 1): preserves legacy deploy gas accounting
    //    (0 start fuel charged to caller, succeeds even with only deploy_base gas).
    {
        let mut reg = ContractRegistry::new();
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 7,
            chain_height: H - 1,
            ..Default::default()
        };
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract { code: code.clone() }],
            deploy_base,
            &mut ctx,
            &mut sends,
            None,
            &opts,
        );
        match res {
            VmExecutionResult::Success { gas_used, .. } => {
                assert_eq!(
                    gas_used, deploy_base,
                    "below gate, SysCallDeployContract must preserve legacy gas accounting"
                );
            }
            other => panic!("expected Success below gate, got {other:?}"),
        }
        assert!(reg.exists(&contract_address(&sender, 7)));
    }

    // 2. Post-activation (H): insufficient gas for (start) fails with OutOfGas.
    {
        let mut reg = ContractRegistry::new();
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 8,
            chain_height: H,
            ..Default::default()
        };
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract { code: code.clone() }],
            deploy_base + single_start_fuel - 1,
            &mut ctx,
            &mut sends,
            None,
            &opts,
        );
        assert!(
            matches!(res, VmExecutionResult::OutOfGas),
            "expected OutOfGas when gas_remaining < start fuel, got {res:?}"
        );
        assert!(!reg.exists(&contract_address(&sender, 8)));
    }

    // 3. Post-activation (H): exact deploy_base + single_start_fuel succeeds and
    //    charges (start) ONCE (exact equality proves neither 0x nor 2x execution).
    {
        let mut reg = ContractRegistry::new();
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 9,
            chain_height: H,
            ..Default::default()
        };
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract { code: code.clone() }],
            deploy_base + single_start_fuel + 50_000,
            &mut ctx,
            &mut sends,
            None,
            &opts,
        );
        match res {
            VmExecutionResult::Success { gas_used, .. } => {
                assert_eq!(
                    gas_used,
                    deploy_base + single_start_fuel,
                    "(start) must run and charge caller gas exactly ONCE"
                );
            }
            other => panic!("expected Success at H, got {other:?}"),
        }
        assert!(reg.exists(&contract_address(&sender, 9)));
    }

    // 4. (start) calling host.falcon512_verify is also governed by v2 fuel at H:
    //    succeeds with deploy_base + 20_000 below H, hits OutOfGas at H, and
    //    succeeds at H when given deploy_base + start_falcon_fuel (>= 150_000).
    {
        let start_pq_code = start_falcon_verify_wasm();
        let pq_deploy_base = contract_deploy_gas(start_pq_code.len());
        let pq_start_fuel = ContractRegistry::validate_code_hardened_and_measure_at(
            &start_pq_code,
            VALIDATE_CODE_START_FUEL_LIMIT,
            H,
        )
        .expect("start falcon verify measurement at H must succeed");
        assert!(pq_start_fuel >= FUEL_FALCON512_VERIFY_V2);

        let mut reg = ContractRegistry::new();
        let mut ctx_oof = make_vm_ctx(sender, &mut reg);
        let opts_h = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 10,
            chain_height: H,
            ..Default::default()
        };
        let res_oof = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract {
                code: start_pq_code.clone(),
            }],
            pq_deploy_base + 20_000,
            &mut ctx_oof,
            &mut sends,
            None,
            &opts_h,
        );
        assert!(
            matches!(res_oof, VmExecutionResult::OutOfGas),
            "expected OutOfGas for (start) calling falcon512_verify under 20_000 gas at H, got {res_oof:?}"
        );

        let mut ctx_ok = make_vm_ctx(sender, &mut reg);
        let res_ok = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract {
                code: start_pq_code,
            }],
            pq_deploy_base + pq_start_fuel,
            &mut ctx_ok,
            &mut sends,
            None,
            &opts_h,
        );
        match res_ok {
            VmExecutionResult::Success { gas_used, .. } => {
                assert_eq!(gas_used, pq_deploy_base + pq_start_fuel);
            }
            other => panic!("expected Success with full pq_start_fuel, got {other:?}"),
        }
        assert!(reg.exists(&contract_address(&sender, 10)));
    }
}

#[tokio::test]
async fn wasm_table_cap_is_wired_in_svm_and_state_engine_below_vs_at_gate() {
    let _reset = GateResetGuard;
    const H: u64 = 250;
    set_wasm_table_elements_cap_override(Some(H));
    const _: () = assert!(MAX_CONTRACT_TABLE_ELEMENTS < 100_000);

    let code = oversized_table_with_ping_wasm();
    let sender = [0x44u8; 32];
    let deploy_gas = contract_deploy_gas(code.len()) + 50_000;
    let mut sends = Vec::<ActorSendRequest>::new();

    // 1. SVM SysCallDeployContract at H - 1 succeeds; at H fails with InvalidWasm.
    let mut reg = ContractRegistry::new();
    {
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts_pre = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 1,
            chain_height: H - 1,
            ..Default::default()
        };
        let res_pre = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract { code: code.clone() }],
            deploy_gas,
            &mut ctx,
            &mut sends,
            None,
            &opts_pre,
        );
        assert!(
            matches!(res_pre, VmExecutionResult::Success { .. }),
            "oversized table must still deploy below H, got {res_pre:?}"
        );
    }

    let legacy_addr = contract_address(&sender, 1);
    assert!(reg.exists(&legacy_addr));

    // Execution of that pre-gate contract: succeeds at H - 1, fails at H.
    let call_gas = contract_call_gas(b"ping".len(), 1, 0) + 50_000;
    {
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts_pre = VmExecOptions {
            wasm_pmm_hardening: true,
            chain_height: H - 1,
            ..Default::default()
        };
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContract {
                contract: legacy_addr,
                method: b"ping".to_vec(),
                arg: 41,
            }],
            call_gas,
            &mut ctx,
            &mut sends,
            None,
            &opts_pre,
        );
        assert!(
            matches!(
                res,
                VmExecutionResult::Success {
                    return_value: Some(42),
                    ..
                }
            ),
            "pre-gate contract call must succeed below H, got {res:?}"
        );
    }
    {
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts_at = VmExecOptions {
            wasm_pmm_hardening: true,
            chain_height: H,
            ..Default::default()
        };
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContract {
                contract: legacy_addr,
                method: b"ping".to_vec(),
                arg: 41,
            }],
            call_gas,
            &mut ctx,
            &mut sends,
            None,
            &opts_at,
        );
        assert!(
            matches!(res, VmExecutionResult::Reverted(_)),
            "oversized table execution must fail at H, got {res:?}"
        );
    }

    // Deploy at H must revert (InvalidWasm).
    {
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let opts_at = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 2,
            chain_height: H,
            ..Default::default()
        };
        let res_at = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContract { code: code.clone() }],
            deploy_gas,
            &mut ctx,
            &mut sends,
            None,
            &opts_at,
        );
        assert!(
            matches!(res_at, VmExecutionResult::Reverted(ref m) if m.contains("not a valid wasm module") || m.contains("invalid wasm") || m.contains("InvalidWasm")),
            "oversized table deploy at H must revert with InvalidWasm, got {res_at:?}"
        );
        assert!(!reg.exists(&contract_address(&sender, 2)));
    }

    // 2. State engine deterministic deploy at H - 1 vs H.
    let engine = InMemoryStateEngine::new();
    let ok_outcome = engine
        .deploy_contract_deterministic_at(sender, code.clone(), b"salt-pre", 1, H - 1)
        .await;
    assert!(
        ok_outcome.is_ok(),
        "deploy_contract_deterministic_at below H must succeed, got {ok_outcome:?}"
    );
    let err_outcome = engine
        .deploy_contract_deterministic_at(sender, code, b"salt-at", 2, H)
        .await;
    assert_eq!(err_outcome, Err(ContractError::InvalidWasm));
}
