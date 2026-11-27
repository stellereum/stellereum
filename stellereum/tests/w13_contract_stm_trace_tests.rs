//! Wave 13B Block-STM multi-version contract trace & overlay tests.
//!
//! Verifies:
//! 1. Disjoint-key concurrent execution on the same contract (`key=1` vs `key=2`):
//!    `validate_reads` passes and `commit_into_registry` matches sequential execution identically.
//! 2. Read-after-write conflict detection & re-execution:
//!    `tx 1` speculatively reads `Base` for `key=1` while `tx 0` writes `key=1`,
//!    `validate_reads(1, ..)` returns `false`, re-execution with `incarnation=1`
//!    reads `ReadVersion::Tx(0, 0)`, validates `true`, and commits byte-identically
//!    to sequential execution.
//! 3. `MAX_CONTRACT_STORAGE_KEYS` (`4_096`) boundary detection when two concurrent
//!    transactions each add 1 new slot key starting from `len = 4_095`.
//! 4. `host.send_message` balance read-after-write conflict & `balance_delta_spent`
//!    tracking matching sequential execution.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use stellereum::contract::{
    Contract, ContractCallOptions, ContractError, ContractLoc, ContractMvMemory, ContractOutcome,
    ContractRegistry, ReadVersion, MAX_CONTRACT_STORAGE_KEYS,
};

fn stm_test_contract_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "sload" (func $sload (param i64) (result i64)))
          (import "host" "sstore" (func $sstore (param i64 i64)))
          (import "host" "emit" (func $emit (param i64 i64)))
          (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
          (import "host" "return_data" (func $return_data (param i32 i32)))
          (memory (export "memory") 1)
          ;; Read slot `key`, add `delta`, store back to `key`, emit event, and return new value.
          (func (export "add_slot") (param $key i64) (param $delta i64) (result i64)
            (local $next i64)
            (local.set $next (i64.add (call $sload (local.get $key)) (local.get $delta)))
            (call $sstore (local.get $key) (local.get $next))
            (call $emit (local.get $key) (local.get $next))
            (i64.store (i32.const 0) (local.get $next))
            (call $return_data (i32.const 0) (i32.const 8))
            (local.get $next))
          ;; Read `read_key`, add `delta`, store into `write_key`, return written value.
          (func (export "copy_add") (param $read_key i64) (param $write_key i64) (param $delta i64) (result i64)
            (local $val i64)
            (local.set $val (i64.add (call $sload (local.get $read_key)) (local.get $delta)))
            (call $sstore (local.get $write_key) (local.get $val))
            (call $emit (local.get $write_key) (local.get $val))
            (local.get $val))
          ;; Blindly write `key` = `val` and return `val`.
          (func (export "write_slot") (param $key i64) (param $val i64) (result i64)
            (call $sstore (local.get $key) (local.get $val))
            (local.get $val))
          ;; Send an outbound message transferring `amount` nano-STELL and return msg_num.
          (func (export "send_value") (param $amount i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0x1111111111111111))
            (i64.store (i32.const 8) (i64.const 0x2222222222222222))
            (i64.store (i32.const 16) (i64.const 0x3333333333333333))
            (i64.store (i32.const 24) (i64.const 0x4444444444444444))
            (i32.store (i32.const 32) (i32.const 0x41424344))
            (call $send_message
              (i64.const 0)
              (i64.const 32)
              (local.get $amount)
              (i64.const 32)
              (i64.const 4)
              (i64.const 1))))"#,
    )
    .expect("stm_test_contract_wasm compiles")
}

fn setup_contract(
    initial_storage: HashMap<i64, i64>,
    balance: u64,
) -> (ContractRegistry, [u8; 32]) {
    let code = stm_test_contract_wasm();
    let code_hash: [u8; 32] = Sha256::digest(&code).into();
    let addr = [0xC1; 32];
    let mut reg = ContractRegistry::new();
    reg.contracts.insert(
        addr,
        Contract {
            address: addr,
            creator: [0x01; 32],
            code_hash,
            code,
            storage: initial_storage,
            created_at: 1,
            paused: false,
            balance,
            abi: None,
            source_hash: None,
        },
    );
    (reg, addr)
}

fn default_hardened_opts() -> ContractCallOptions {
    ContractCallOptions {
        caller: [0x22; 32],
        origin: [0x33; 32],
        value: 0,
        block_time: 1_700_000_000,
        block_hash: [0x44; 32],
        hardened: true,
    }
}

#[test]
fn stm_disjoint_keys_concurrent_matches_sequential() {
    let mut initial = HashMap::new();
    initial.insert(1, 100);
    initial.insert(2, 200);
    let (mut reg_stm, addr) = setup_contract(initial, 0);
    let mut reg_seq = reg_stm.clone();
    let opts = default_hardened_opts();

    // Sequential reference execution.
    let seq_0: ContractOutcome = reg_seq
        .call_with_options(&addr, "add_slot", &[1, 15], &[], 200_000, &opts)
        .expect("seq tx 0 succeeds");
    let seq_1: ContractOutcome = reg_seq
        .call_with_options(&addr, "add_slot", &[2, 25], &[], 200_000, &opts)
        .expect("seq tx 1 succeeds");

    // Concurrent STM execution against shared `&ContractRegistry`.
    let mv = Arc::new(ContractMvMemory::new(&reg_stm));
    let barrier = Barrier::new(2);
    let (res_0, res_1) = std::thread::scope(|s| {
        let h0 = s.spawn(|| {
            barrier.wait();
            reg_stm.call_with_stm_trace(
                &addr,
                "add_slot",
                &[1, 15],
                &[],
                200_000,
                &opts,
                0,
                mv.clone(),
            )
        });
        let h1 = s.spawn(|| {
            barrier.wait();
            reg_stm.call_with_stm_trace(
                &addr,
                "add_slot",
                &[2, 25],
                &[],
                200_000,
                &opts,
                1,
                mv.clone(),
            )
        });
        (h0.join().expect("thread 0"), h1.join().expect("thread 1"))
    });

    let (stm_0, trace_0) = res_0.expect("stm tx 0 succeeds");
    let (stm_1, trace_1) = res_1.expect("stm tx 1 succeeds");

    mv.record_incarnation(0, 0, addr, &trace_0);
    mv.record_incarnation(1, 0, addr, &trace_1);

    assert!(mv.validate_reads(0, &trace_0));
    assert!(mv.validate_reads(1, &trace_1));

    mv.commit_into_registry(&mut reg_stm);

    assert_eq!(stm_0, seq_0);
    assert_eq!(stm_1, seq_1);
    assert_eq!(
        reg_stm.get(&addr).unwrap().storage,
        reg_seq.get(&addr).unwrap().storage
    );
    assert_eq!(reg_stm.get(&addr).unwrap().storage.get(&1), Some(&115));
    assert_eq!(reg_stm.get(&addr).unwrap().storage.get(&2), Some(&225));
}

#[test]
fn stm_read_after_write_conflict_detects_and_reexecutes_identically() {
    let mut initial = HashMap::new();
    initial.insert(1, 10);
    let (mut reg_stm, addr) = setup_contract(initial, 0);
    let mut reg_seq = reg_stm.clone();
    let opts = default_hardened_opts();

    // Sequential reference: tx 0 writes key=1 -> 42; tx 1 reads key=1 (42), writes key=2 -> 47.
    let seq_0 = reg_seq
        .call_with_options(&addr, "write_slot", &[1, 42], &[], 200_000, &opts)
        .expect("seq tx 0 succeeds");
    let seq_1 = reg_seq
        .call_with_options(&addr, "copy_add", &[1, 2, 5], &[], 200_000, &opts)
        .expect("seq tx 1 succeeds");

    let mv = Arc::new(ContractMvMemory::new(&reg_stm));

    // Speculatively run tx 1 BEFORE tx 0 has recorded its write to key=1.
    let (stm_1_inc0, trace_1_inc0) = reg_stm
        .call_with_stm_trace(
            &addr,
            "copy_add",
            &[1, 2, 5],
            &[],
            200_000,
            &opts,
            1,
            mv.clone(),
        )
        .expect("speculative tx 1 succeeds");
    assert_eq!(stm_1_inc0.result, 15);
    assert!(trace_1_inc0
        .reads
        .contains(&(ContractLoc::Slot(addr, 1), ReadVersion::Base)));
    mv.record_incarnation(1, 0, addr, &trace_1_inc0);

    // Now tx 0 executes and records incarnation 0 writing key=1 -> 42.
    let (stm_0, trace_0) = reg_stm
        .call_with_stm_trace(
            &addr,
            "write_slot",
            &[1, 42],
            &[],
            200_000,
            &opts,
            0,
            mv.clone(),
        )
        .expect("stm tx 0 succeeds");
    mv.record_incarnation(0, 0, addr, &trace_0);

    assert!(mv.validate_reads(0, &trace_0));
    // tx 1 read Base for key=1, but latest_version_below is now Tx(0, 0) -> conflict!
    assert_eq!(
        mv.latest_version_below(ContractLoc::Slot(addr, 1), 1),
        ReadVersion::Tx(0, 0)
    );
    assert!(!mv.validate_reads(1, &trace_1_inc0));

    // Invalidate and re-execute tx 1 (incarnation = 1).
    mv.invalidate_tx(1);
    let (stm_1_inc1, trace_1_inc1) = reg_stm
        .call_with_stm_trace(
            &addr,
            "copy_add",
            &[1, 2, 5],
            &[],
            200_000,
            &opts,
            1,
            mv.clone(),
        )
        .expect("re-executed tx 1 succeeds");
    assert_eq!(stm_1_inc1.result, 47);
    assert!(trace_1_inc1
        .reads
        .contains(&(ContractLoc::Slot(addr, 1), ReadVersion::Tx(0, 0))));
    mv.record_incarnation(1, 1, addr, &trace_1_inc1);
    assert!(mv.validate_reads(1, &trace_1_inc1));

    mv.commit_into_registry(&mut reg_stm);

    assert_eq!(stm_0, seq_0);
    assert_eq!(stm_1_inc1, seq_1);
    assert_eq!(
        reg_stm.get(&addr).unwrap().storage,
        reg_seq.get(&addr).unwrap().storage
    );
    assert_eq!(reg_stm.get(&addr).unwrap().storage.get(&1), Some(&42));
    assert_eq!(reg_stm.get(&addr).unwrap().storage.get(&2), Some(&47));
}

#[test]
fn stm_storage_key_limit_boundary_detects_concurrent_overflow() {
    let mut initial = HashMap::with_capacity(MAX_CONTRACT_STORAGE_KEYS - 1);
    for k in 0..(MAX_CONTRACT_STORAGE_KEYS as i64 - 1) {
        initial.insert(k, 1);
    }
    assert_eq!(initial.len(), 4_095);

    let (mut reg_stm, addr) = setup_contract(initial, 0);
    let mut reg_seq = reg_stm.clone();
    let opts = default_hardened_opts();

    // Sequential reference: tx 0 adds key 10_000 (len -> 4_096), tx 1 traps on key 10_001.
    let seq_0 = reg_seq
        .call_with_options(&addr, "write_slot", &[10_000, 111], &[], 200_000, &opts)
        .expect("seq tx 0 fits within 4_096 cap");
    assert_eq!(seq_0.result, 111);
    let seq_1_err = reg_seq
        .call_with_options(&addr, "write_slot", &[10_001, 222], &[], 200_000, &opts)
        .expect_err("seq tx 1 exceeds MAX_CONTRACT_STORAGE_KEYS");
    assert_eq!(seq_1_err, ContractError::Trapped);

    // Concurrent STM: both tx 0 and tx 1 execute before either records, both observing len = 4_095.
    let mv = Arc::new(ContractMvMemory::new(&reg_stm));
    let barrier = Barrier::new(2);
    let (res_0, res_1) = std::thread::scope(|s| {
        let h0 = s.spawn(|| {
            barrier.wait();
            reg_stm.call_with_stm_trace(
                &addr,
                "write_slot",
                &[10_000, 111],
                &[],
                200_000,
                &opts,
                0,
                mv.clone(),
            )
        });
        let h1 = s.spawn(|| {
            barrier.wait();
            reg_stm.call_with_stm_trace(
                &addr,
                "write_slot",
                &[10_001, 222],
                &[],
                200_000,
                &opts,
                1,
                mv.clone(),
            )
        });
        (h0.join().expect("thread 0"), h1.join().expect("thread 1"))
    });

    let (stm_0, trace_0) = res_0.expect("speculative tx 0 succeeds at 4_095");
    let (_stm_1_spec, trace_1_spec) = res_1.expect("speculative tx 1 succeeds at 4_095");
    assert_eq!(trace_0.new_slot_keys, 1);
    assert_eq!(trace_1_spec.new_slot_keys, 1);
    assert!(trace_1_spec
        .reads
        .contains(&(ContractLoc::StorageLen(addr), ReadVersion::Base)));

    mv.record_incarnation(0, 0, addr, &trace_0);
    mv.record_incarnation(1, 0, addr, &trace_1_spec);

    // tx 0 remains valid, while tx 1's StorageLen read version is invalidated by Tx(0, 0).
    assert!(mv.validate_reads(0, &trace_0));
    assert_eq!(
        mv.latest_version_below(ContractLoc::StorageLen(addr), 1),
        ReadVersion::Tx(0, 0)
    );
    assert!(!mv.validate_reads(1, &trace_1_spec));

    // Invalidate and re-execute tx 1 against len = 4_096 -> traps cleanly.
    mv.invalidate_tx(1);
    let stm_1_err = reg_stm
        .call_with_stm_trace(
            &addr,
            "write_slot",
            &[10_001, 222],
            &[],
            200_000,
            &opts,
            1,
            mv.clone(),
        )
        .expect_err("re-executed tx 1 hits MAX_CONTRACT_STORAGE_KEYS");
    assert_eq!(stm_1_err, ContractError::Trapped);

    mv.commit_into_registry(&mut reg_stm);

    assert_eq!(stm_0, seq_0);
    assert_eq!(
        reg_stm.get(&addr).unwrap().storage.len(),
        MAX_CONTRACT_STORAGE_KEYS
    );
    assert_eq!(
        reg_stm.get(&addr).unwrap().storage,
        reg_seq.get(&addr).unwrap().storage
    );
}

#[test]
fn stm_send_message_balance_conflict_and_delta_matches_sequential() {
    let (mut reg_stm, addr) = setup_contract(HashMap::new(), 500);
    let mut reg_seq = reg_stm.clone();
    let opts = default_hardened_opts();

    // Sequential: tx 0 spends 350 (bal -> 150, ok msg #1); tx 1 tries 300 (insufficient -> -2).
    let seq_0 = reg_seq
        .call_with_options(&addr, "send_value", &[350], &[], 200_000, &opts)
        .expect("seq tx 0 succeeds");
    let seq_1 = reg_seq
        .call_with_options(&addr, "send_value", &[300], &[], 200_000, &opts)
        .expect("seq tx 1 returns -2");
    assert_eq!(seq_0.result, 1);
    assert_eq!(seq_1.result, -2);

    let mv = Arc::new(ContractMvMemory::new(&reg_stm));

    // Speculatively run tx 1 first against Base balance 500 -> sees enough balance (returns 1).
    let (stm_1_inc0, trace_1_inc0) = reg_stm
        .call_with_stm_trace(
            &addr,
            "send_value",
            &[300],
            &[],
            200_000,
            &opts,
            1,
            mv.clone(),
        )
        .expect("speculative tx 1 succeeds");
    assert_eq!(stm_1_inc0.result, 1);
    assert_eq!(trace_1_inc0.balance_delta_spent, 300);
    assert!(trace_1_inc0
        .reads
        .contains(&(ContractLoc::Balance(addr), ReadVersion::Base)));
    mv.record_incarnation(1, 0, addr, &trace_1_inc0);

    // Run tx 0 against Base balance 500 -> spends 350.
    let (stm_0, trace_0) = reg_stm
        .call_with_stm_trace(
            &addr,
            "send_value",
            &[350],
            &[],
            200_000,
            &opts,
            0,
            mv.clone(),
        )
        .expect("stm tx 0 succeeds");
    assert_eq!(trace_0.balance_delta_spent, 350);
    mv.record_incarnation(0, 0, addr, &trace_0);

    // tx 1 fails Balance validation and re-executes against 150 -> returns -2, spent = 0.
    assert!(!mv.validate_reads(1, &trace_1_inc0));
    mv.invalidate_tx(1);
    let (stm_1_inc1, trace_1_inc1) = reg_stm
        .call_with_stm_trace(
            &addr,
            "send_value",
            &[300],
            &[],
            200_000,
            &opts,
            1,
            mv.clone(),
        )
        .expect("re-executed tx 1 returns -2");
    assert_eq!(stm_1_inc1.result, -2);
    assert_eq!(trace_1_inc1.balance_delta_spent, 0);
    assert!(trace_1_inc1
        .reads
        .contains(&(ContractLoc::Balance(addr), ReadVersion::Tx(0, 0))));
    mv.record_incarnation(1, 1, addr, &trace_1_inc1);
    assert!(mv.validate_reads(1, &trace_1_inc1));

    mv.commit_into_registry(&mut reg_stm);

    assert_eq!(stm_0, seq_0);
    assert_eq!(stm_1_inc1, seq_1);
    assert_eq!(
        reg_stm.get(&addr).unwrap().balance,
        reg_seq.get(&addr).unwrap().balance
    );
    assert_eq!(reg_stm.get(&addr).unwrap().balance, 150);
}
