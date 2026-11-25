//! Wave 7 regressions for Wave 6 SVM, RPC getter, and Actor Mailbox findings:
//! - W6-A4-1: `ACTOR_MAILBOX_HARDENING_HEIGHT` (`u64::MAX`, INERT):
//!   * Below `H` (`H - 1` / default `u64::MAX`): legacy `try_deliver` behavior unchanged.
//!   * At `H`: attacker cannot drain `victim`'s balance via `SysCallActorSend` or
//!     `host.send_message` with `ActorSendBody { Transfer / SysCallActorSend / ... }`;
//!     self-sends and pure/read-only non-self deliveries still work.
//! - W6-A4-2: `route_contract_messages_hardened` + `SysCallCallContract*`:
//!   * Below `H` (`H - 1`): legacy unbounded routing unchanged.
//!   * At `H`: `body.gas_budget` is bounded at `MAX_CONTRACT_ACTOR_GAS_BUDGET` (`1_000_000`)
//!     and `GAS_ACTOR_DELIVER + body.gas_budget` is billed against `state.gas_remaining`.
//! - W6-A4-3 & W6-A4-4: Immediate non-consensus RPC getter hardening & table `min` check:
//!   * `run_get_method` immediately enforces `store_limits_with_table_cap(true)` (rejects
//!     `(table 100000 funcref)` with no max) and `FUEL_FALCON512_VERIFY_V2` (`150_000`).
//!   * `validate_code_with_table_cap` / `validate_code_hardened_with_table_cap` reject
//!     `(table 100000 funcref)` even without a maximum (`flags & 1 == 0`).
//!   * `execute_subcall_hardened_at` threads height-gate flags cleanly.

use std::collections::HashMap;
use std::fmt::Write as _;

use stellereum::chain_spec::{
    actor_mailbox_hardening_active_at, current_activation_schedule,
    set_actor_mailbox_hardening_override, set_falcon_host_fuel_v2_activation_override,
    set_wasm_table_elements_cap_override, ActivationStatus, ACTOR_MAILBOX_HARDENING_HEIGHT,
};
use stellereum::contract::{
    ContractCallOptions, ContractError, ContractMessage, ContractRegistry,
    FUEL_FALCON512_VERIFY_V2, MAX_CONTRACT_TABLE_ELEMENTS,
};
use stellereum::feature_gates;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::{Block, ShardTopology, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, ActorSendBody, InMemoryStateEngine};
use stellereum::svm::{
    contract_call_gas, ActorSendRequest, OpCode, Svm, VmContext, VmExecOptions, VmExecutionResult,
    GAS_ACTOR_DELIVER, GAS_ACTOR_SEND, MAX_CONTRACT_ACTOR_GAS_BUDGET,
};

const H: u64 = 500;

struct GateResetGuard;

impl Drop for GateResetGuard {
    fn drop(&mut self) {
        set_actor_mailbox_hardening_override(None);
        set_wasm_table_elements_cap_override(None);
        set_falcon_host_fuel_v2_activation_override(None);
    }
}

fn escape_wat_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        let _ = write!(&mut out, "\\{b:02x}");
    }
    out
}

fn sign_pq_tx(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let dummy = vec![0u8; FALCON512_SIG_LEN];
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        dummy,
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
        &DEFAULT_SALT,
    )
}

fn send_message_wasm(recipient: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let wat_src = format!(
        r#"(module
             (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
             (memory (export "memory") 1)
             (data (i32.const 0) "{recip_esc}")
             (data (i32.const 64) "{payload_esc}")
             (func (export "send") (param $val i64) (result i64)
               (call $send_message
                 (i64.const 0) (i64.const 32)
                 (local.get $val)
                 (i64.const 64) (i64.const {payload_len})
                 (i64.const 1))))"#,
        recip_esc = escape_wat_bytes(recipient),
        payload_esc = escape_wat_bytes(payload),
        payload_len = payload.len(),
    );
    wat::parse_str(&wat_src).expect("send_message_wasm compiles")
}

fn falcon_verify_wasm() -> Vec<u8> {
    let kp = FalconKeypair::generate_from_seed(0x7A);
    let msg = b"w7 rpc getter falcon fuel v2 check";
    let sig = kp.sign(msg);
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

fn oversized_table_no_max_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (table 100000 funcref)
             (func (export "ping") (param $x i64) (result i64)
               (i64.add (local.get $x) (i64.const 1))))"#,
    )
    .expect("oversized_table_no_max_wasm compiles")
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
        timestamp: 1_760_000_000,
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
fn actor_mailbox_hardening_gate_is_inert_by_default() {
    let _reset = GateResetGuard;
    assert_eq!(ACTOR_MAILBOX_HARDENING_HEIGHT, u64::MAX);
    assert_eq!(MAX_CONTRACT_ACTOR_GAS_BUDGET, 1_000_000);

    for height in [0u64, 1, 1_000, 10_000_000, u64::MAX - 1, u64::MAX] {
        assert!(!actor_mailbox_hardening_active_at(height));
    }

    let schedule = current_activation_schedule();
    let gate = schedule
        .gates
        .iter()
        .find(|g| g.name == "ACTOR_MAILBOX_HARDENING_HEIGHT")
        .expect("ACTOR_MAILBOX_HARDENING_HEIGHT must be in current_activation_schedule()");
    assert_eq!(gate.activation_height, u64::MAX);
    assert_eq!(gate.status, ActivationStatus::GatedOff);

    let table = feature_gates::table();
    let row = table
        .iter()
        .find(|g| g.id == "actor-mailbox-hardening")
        .expect("actor-mailbox-hardening must be in feature_gates::table()");
    assert_eq!(row.symbol, "ACTOR_MAILBOX_HARDENING_HEIGHT");
    assert_eq!(row.value, u64::MAX);
    assert_eq!(row.status(), "INERT");
    assert_eq!(row.test, Some("tests/w7_svm_and_contracts_fixes.rs"));
}

#[tokio::test]
async fn w6_a4_1_actor_send_cannot_drain_victim_at_h_while_h_minus_1_is_legacy() {
    let _reset = GateResetGuard;
    set_actor_mailbox_hardening_override(Some(H));

    let attacker_kp = FalconKeypair::generate_from_seed(0xA1);
    let attacker = derive_pq_address(PqScheme::Falcon512, &attacker_kp.public_key, &DEFAULT_SALT);
    let victim = [0xBBu8; 32];
    let proposer = [0xCCu8; 32];

    let body_program = vec![OpCode::Transfer {
        recipient: attacker,
        amount: 500_000,
    }];
    let send_op = OpCode::SysCallActorSend {
        recipient: victim,
        value: 500,
        body: body_program.clone(),
        bounce: true,
        gas_budget: 350_000,
    };
    let gas_limit = GAS_ACTOR_SEND + GAS_ACTOR_DELIVER + 350_000 + 5_000;

    // 1. Pre-activation (H - 1): legacy behavior unchanged (body runs against victim).
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(attacker, 1_000_000))
            .await;
        engine
            .update_account(AccountState::new(victim, 500_000))
            .await;
        engine.update_account(AccountState::new(proposer, 0)).await;

        let tx = sign_pq_tx(
            &attacker_kp,
            attacker,
            0,
            gas_limit,
            0,
            vec![send_op.clone()],
        );
        let blk = Block {
            height: H - 1,
            timestamp: 1_760_000_000,
            proposer,
            transactions: vec![tx],
            ..Default::default()
        };
        let out = engine.apply_block_transition(&blk, 0).await;
        assert_eq!(out.status, vec![true]);
        // Below H, legacy behavior executed the transfer from victim's account.
        assert_eq!(engine.get_account(&victim).await.unwrap().balance, 500);
    }

    // 2. Post-activation (H): attacker cannot drain victim via SysCallActorSend.
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(attacker, 1_000_000))
            .await;
        engine
            .update_account(AccountState::new(victim, 500_000))
            .await;
        engine.update_account(AccountState::new(proposer, 0)).await;

        let tx = sign_pq_tx(&attacker_kp, attacker, 0, gas_limit, 0, vec![send_op]);
        let blk = Block {
            height: H,
            timestamp: 1_760_000_000,
            proposer,
            transactions: vec![tx],
            ..Default::default()
        };
        let out = engine.apply_block_transition(&blk, 0).await;
        assert_eq!(out.status, vec![true]);
        assert_eq!(
            engine.get_account(&victim).await.unwrap().balance,
            500_000,
            "victim balance must be untouched when non-self ActorSendBody attempts Transfer at H"
        );
        let fee = out.tx_fees[0];
        // Attacker got the 500 bounce back, so attacker lost only the fee.
        assert_eq!(
            engine.get_account(&attacker).await.unwrap().balance,
            1_000_000 - fee
        );
    }

    // 3. Post-activation (H): attacker cannot drain victim via contract host.send_message
    //    carrying ActorSendBody { Transfer } or { SysCallActorSend }.
    for malicious_program in [
        vec![OpCode::Transfer {
            recipient: attacker,
            amount: 500_000,
        }],
        vec![OpCode::SysCallActorSend {
            recipient: attacker,
            value: 500_000,
            body: Vec::new(),
            bounce: true,
            gas_budget: 0,
        }],
    ] {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(attacker, 5_000_000))
            .await;
        engine
            .update_account(AccountState::new(victim, 500_000))
            .await;
        engine.update_account(AccountState::new(proposer, 0)).await;

        let payload = bincode::serialize(&ActorSendBody {
            program: malicious_program,
            gas_budget: 10_000,
        })
        .unwrap();
        let wasm = send_message_wasm(&victim, &payload);
        let contract_addr = engine.deploy_contract(attacker, wasm, 1).await.unwrap();
        engine
            .update_account(AccountState::new(contract_addr, 1_000))
            .await;

        let tx = sign_pq_tx(
            &attacker_kp,
            attacker,
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_addr,
                method: b"send".to_vec(),
                arg: 500,
            }],
        );
        let blk = Block {
            height: H,
            timestamp: 1_760_000_000,
            proposer,
            transactions: vec![tx],
            ..Default::default()
        };
        let out = engine.apply_block_transition(&blk, 0).await;
        assert_eq!(out.status, vec![true]);
        assert_eq!(
            engine.get_account(&victim).await.unwrap().balance,
            500_000,
            "victim balance must be untouched by malicious contract outbound ActorSendBody at H"
        );
        assert_eq!(
            engine.get_account(&contract_addr).await.unwrap().balance,
            1_000,
            "contract value must bounce back to contract once on delivery refusal"
        );
    }

    // 4. At H: legitimate non-self pure / empty ActorSendBody still delivers value,
    //    and legitimate self-send (sender == recipient) may execute Transfer.
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(attacker, 5_000_000))
            .await;
        engine.update_account(AccountState::new(victim, 0)).await;
        engine.update_account(AccountState::new(proposer, 0)).await;

        let tx_pure = sign_pq_tx(
            &attacker_kp,
            attacker,
            0,
            gas_limit,
            0,
            vec![OpCode::SysCallActorSend {
                recipient: victim,
                value: 300,
                body: vec![OpCode::Push(2), OpCode::Push(3), OpCode::Add],
                bounce: true,
                gas_budget: 1_000,
            }],
        );
        let tx_self = sign_pq_tx(
            &attacker_kp,
            attacker,
            0,
            GAS_ACTOR_SEND + GAS_ACTOR_DELIVER + 350_000 + 5_000,
            1,
            vec![OpCode::SysCallActorSend {
                recipient: attacker,
                value: 100,
                body: vec![OpCode::Transfer {
                    recipient: victim,
                    amount: 200,
                }],
                bounce: true,
                gas_budget: 350_000,
            }],
        );
        let blk = Block {
            height: H,
            timestamp: 1_760_000_000,
            proposer,
            transactions: vec![tx_pure, tx_self],
            ..Default::default()
        };
        let out = engine.apply_block_transition(&blk, 0).await;
        assert_eq!(out.status, vec![true, true]);
        assert_eq!(engine.get_account(&victim).await.unwrap().balance, 500);
    }
}

#[test]
fn w6_a4_2_host_send_message_gas_budget_bounded_and_billed_at_h() {
    let _reset = GateResetGuard;
    set_actor_mailbox_hardening_override(Some(H));

    let sender = [0x11u8; 32];
    let recipient = [0x22u8; 32];

    let unbounded_payload = bincode::serialize(&ActorSendBody {
        program: vec![OpCode::Nop],
        gas_budget: u64::MAX,
    })
    .unwrap();
    let bounded_payload = bincode::serialize(&ActorSendBody {
        program: vec![OpCode::Nop],
        gas_budget: 50_000,
    })
    .unwrap();

    let unbounded_wasm = send_message_wasm(&recipient, &unbounded_payload);
    let bounded_wasm = send_message_wasm(&recipient, &bounded_payload);

    let mut reg = ContractRegistry::new();
    let addr_unbounded = reg
        .deploy_with_nonce_and_balance(sender, unbounded_wasm, 0, 1, 10_000)
        .unwrap();
    let addr_bounded = reg
        .deploy_with_nonce_and_balance(sender, bounded_wasm, 1, 1, 10_000)
        .unwrap();

    let call_base = contract_call_gas(b"send".len(), 1, 0);
    let mut sends = Vec::<ActorSendRequest>::new();

    // 1. Below H (H - 1): legacy behavior accepts u64::MAX gas_budget without billing it.
    {
        let opts_pre = VmExecOptions {
            wasm_pmm_hardening: true,
            chain_height: H - 1,
            ..Default::default()
        };
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContract {
                contract: addr_unbounded,
                method: b"send".to_vec(),
                arg: 100,
            }],
            call_base + 50_000,
            &mut ctx,
            &mut sends,
            None,
            &opts_pre,
        );
        assert!(
            matches!(res, VmExecutionResult::Success { .. }),
            "below H, legacy send_message with unbounded gas_budget must remain unchanged, got {res:?}"
        );

        let mut accounts = HashMap::from([
            (addr_unbounded, AccountState::new(addr_unbounded, 1_000)),
            (recipient, AccountState::new(recipient, 0)),
        ]);
        let mut xout = Vec::new();
        let debited = Svm::route_contract_messages_hardened(
            &[ContractMessage {
                msg_id: [1u8; 32],
                sender: addr_unbounded,
                recipient,
                value: 100,
                payload: unbounded_payload.clone(),
                bounce: true,
            }],
            &mut accounts,
            &mut xout,
            MASTERCHAIN_SHARD,
            false,
            &ShardTopology::new(),
            H - 1,
        );
        assert_eq!(debited.len(), 1);
        assert_eq!(accounts[&recipient].inbox.len(), 1);
    }

    // 2. At H: gas_budget = u64::MAX is refused in both SysCallCallContract* and router.
    {
        let opts_post = VmExecOptions {
            wasm_pmm_hardening: true,
            chain_height: H,
            ..Default::default()
        };
        let mut ctx = make_vm_ctx(sender, &mut reg);
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContract {
                contract: addr_unbounded,
                method: b"send".to_vec(),
                arg: 100,
            }],
            5_000_000,
            &mut ctx,
            &mut sends,
            None,
            &opts_post,
        );
        assert!(
            matches!(res, VmExecutionResult::Reverted(_)),
            "at H, gas_budget = u64::MAX must revert, got {res:?}"
        );

        // Also refused via SysCallCallContractArgs.
        let args_base = contract_call_gas(b"send".len(), 1, 0);
        let mut ctx_args = make_vm_ctx(sender, &mut reg);
        let res_args = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContractArgs {
                contract: addr_unbounded,
                method: b"send".to_vec(),
                args: vec![100],
                calldata: Vec::new(),
            }],
            args_base + 5_000_000,
            &mut ctx_args,
            &mut sends,
            None,
            &opts_post,
        );
        assert!(
            matches!(res_args, VmExecutionResult::Reverted(_)),
            "at H, SysCallCallContractArgs with gas_budget = u64::MAX must revert, got {res_args:?}"
        );

        // Direct route_contract_messages_hardened at H also refuses > MAX_CONTRACT_ACTOR_GAS_BUDGET.
        let mut accounts =
            HashMap::from([(addr_unbounded, AccountState::new(addr_unbounded, 1_000))]);
        let mut xout = Vec::new();
        let debited = Svm::route_contract_messages_hardened(
            &[ContractMessage {
                msg_id: [2u8; 32],
                sender: addr_unbounded,
                recipient,
                value: 100,
                payload: unbounded_payload,
                bounce: true,
            }],
            &mut accounts,
            &mut xout,
            MASTERCHAIN_SHARD,
            false,
            &ShardTopology::new(),
            H,
        );
        assert!(debited.is_empty());
        assert_eq!(accounts[&addr_unbounded].balance, 1_000);
        assert!(!accounts.contains_key(&recipient));
    }

    // 3. At H: bounded gas_budget (50_000) bills GAS_ACTOR_DELIVER + 50_000 against caller gas.
    {
        let opts_post = VmExecOptions {
            wasm_pmm_hardening: true,
            chain_height: H,
            ..Default::default()
        };
        let mut ctx_oof = make_vm_ctx(sender, &mut reg);
        let res_oof = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContract {
                contract: addr_bounded,
                method: b"send".to_vec(),
                arg: 100,
            }],
            call_base + 20_000,
            &mut ctx_oof,
            &mut sends,
            None,
            &opts_post,
        );
        assert!(
            matches!(res_oof, VmExecutionResult::OutOfGas),
            "at H, caller without GAS_ACTOR_DELIVER + 50_000 gas must fail with OutOfGas, got {res_oof:?}"
        );

        let mut ctx_ok = make_vm_ctx(sender, &mut reg);
        let res_ok = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCallContract {
                contract: addr_bounded,
                method: b"send".to_vec(),
                arg: 100,
            }],
            call_base + 200_000,
            &mut ctx_ok,
            &mut sends,
            None,
            &opts_post,
        );
        match res_ok {
            VmExecutionResult::Success { gas_used, .. } => {
                assert!(
                    gas_used >= call_base + GAS_ACTOR_DELIVER + 50_000,
                    "gas_used ({gas_used}) must include GAS_ACTOR_DELIVER + 50_000"
                );
            }
            other => panic!("expected Success with sufficient gas at H, got {other:?}"),
        }
    }
}

#[test]
fn w6_a4_3_and_4_rpc_getter_enforces_table_cap_and_falcon_fuel_v2_immediately() {
    let _reset = GateResetGuard;

    // 1. No-max oversized table `(table 100000 funcref)` is rejected by validation
    //    when enforce_table_cap = true, and by run_get_method immediately (even at default u64::MAX).
    let table_code = oversized_table_no_max_wasm();
    assert_eq!(
        ContractRegistry::validate_code_with_table_cap(&table_code, true),
        Err(ContractError::InvalidWasm)
    );
    assert_eq!(
        ContractRegistry::validate_code_hardened_with_table_cap(&table_code, 1_000_000, true),
        Err(ContractError::InvalidWasm)
    );

    let mut reg = ContractRegistry::new();
    // Legacy deploy (pre-table-cap activation) allowed the module on chain.
    let table_addr = reg.deploy([0x44u8; 32], table_code, 1).unwrap();
    let table_resp = reg.run_get_method(&table_addr, "ping", &[41], None);
    assert!(
        !table_resp.success,
        "run_get_method must refuse oversized (table 100000 funcref) immediately without gate override"
    );

    // Within cap (<= MAX_CONTRACT_TABLE_ELEMENTS) still works.
    let ok_table_code = wat::parse_str(format!(
        r#"(module
             (table {MAX_CONTRACT_TABLE_ELEMENTS} funcref)
             (func (export "ping") (param $x i64) (result i64)
               (i64.add (local.get $x) (i64.const 1))))"#
    ))
    .unwrap();
    let ok_addr = reg.deploy([0x44u8; 32], ok_table_code, 2).unwrap();
    let ok_resp = reg.run_get_method(&ok_addr, "ping", &[41], None);
    assert!(ok_resp.success);
    assert_eq!(ok_resp.return_value, Some(42));

    // 2. run_get_method immediately enforces FUEL_FALCON512_VERIFY_V2 (150_000).
    let falcon_code = falcon_verify_wasm();
    let falcon_addr = reg.deploy([0x55u8; 32], falcon_code, 3).unwrap();
    let low_fuel_resp = reg.run_get_method(&falcon_addr, "verify_sig", &[0], Some(20_000));
    assert!(
        !low_fuel_resp.success,
        "run_get_method must enforce FUEL_FALCON512_VERIFY_V2 immediately and reject 20_000 fuel"
    );
    let high_fuel_resp = reg.run_get_method(&falcon_addr, "verify_sig", &[0], Some(250_000));
    assert!(
        high_fuel_resp.success,
        "run_get_method with 250_000 fuel must succeed: {:?}",
        high_fuel_resp.error
    );
    assert_eq!(high_fuel_resp.return_value, Some(1));
    assert!(high_fuel_resp.fuel_used >= FUEL_FALCON512_VERIFY_V2);

    // 3. execute_subcall_hardened_at threads height-gate flags cleanly.
    set_wasm_table_elements_cap_override(Some(H));
    set_falcon_host_fuel_v2_activation_override(Some(H));
    let opts = ContractCallOptions {
        caller: [0x55u8; 32],
        origin: [0x55u8; 32],
        value: 0,
        block_time: 100,
        block_hash: [0u8; 32],
        hardened: true,
    };
    let mut events = Vec::new();
    let mut outbound = Vec::new();
    let sub_pre = reg
        .execute_subcall_hardened_at(
            &falcon_addr,
            "verify_sig",
            &[0],
            &[],
            20_000,
            &opts,
            1,
            &mut events,
            &mut outbound,
            H - 1,
        )
        .expect("below H, subcall with 20_000 fuel succeeds");
    assert_eq!(sub_pre.result, 1);

    let sub_post_err = reg
        .execute_subcall_hardened_at(
            &falcon_addr,
            "verify_sig",
            &[0],
            &[],
            20_000,
            &opts,
            1,
            &mut events,
            &mut outbound,
            H,
        )
        .unwrap_err();
    assert_eq!(sub_post_err, ContractError::OutOfFuel);

    let sub_table_err = reg
        .execute_subcall_hardened_at(
            &table_addr,
            "ping",
            &[41],
            &[],
            100_000,
            &opts,
            1,
            &mut events,
            &mut outbound,
            H,
        )
        .unwrap_err();
    assert_eq!(sub_table_err, ContractError::InvalidWasm);
}
