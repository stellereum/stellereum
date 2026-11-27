//! Wave 10 regressions for consensus-committed ABI persistence at deploy time:
//! - `CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` (`u64::MAX`, INERT by default):
//!   * `current_activation_schedule()` and `feature_gates::table()` expose it as `INERT`.
//!   * Below `H` (`H - 1` / default `u64::MAX`): `OpCode::SysCallDeployContractWithAbi`
//!     reverts fail-closed with `"SysCallDeployContractWithAbi inactive at height ..."` and
//!     deploys nothing.
//!   * At `H`: validates `abi_json.len() <= MAX_CONTRACT_ABI_BYTES`, valid UTF-8, and
//!     `ContractAbi::from_json` + `validate()`, deploys the WASM contract identically to
//!     `SysCallDeployContract`, commits `Contract.abi` into `ContractRegistry` and `state_root`
//!     deterministically across independent engines, and makes `get_contract_abi_json` return
//!     the committed ABI.
//!   * Bincode discriminant of `OpCode::SysCallDeployContractWithAbi` is `65` (preserving
//!     `0..=64` identically and matching `stellereum-sdk` and `sdk-js`).

use stellereum::chain_spec::{
    contract_abi_onchain_activation_height, contract_abi_onchain_active_at,
    current_activation_schedule, set_contract_abi_onchain_activation_override, ActivationStatus,
    CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT,
};
use stellereum::contract::{contract_address, contract_deploy_gas, ContractRegistry};
use stellereum::contract_abi::ContractAbi;
use stellereum::feature_gates;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::{Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    contract_deploy_with_abi_gas, opcode_gas, ActorSendRequest, OpCode, Svm, VmContext,
    VmExecOptions, VmExecutionResult, GAS_PER_BYTE, MAX_CONTRACT_ABI_BYTES,
};

const H: u64 = 500;

struct GateResetGuard;

impl Drop for GateResetGuard {
    fn drop(&mut self) {
        set_contract_abi_onchain_activation_override(None);
    }
}

fn minimal_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (memory (export "memory") 1)
             (func (export "ping") (param i64) (result i64)
               (i64.add (local.get 0) (i64.const 1))))"#,
    )
    .expect("minimal_wasm compiles")
}

fn sample_abi_json() -> Vec<u8> {
    br#"{"methods":[{"name":"ping","params":[{"name":"x","type":"i64"}],"returns":"i64","mutates_state":false}],"events":[]}"#.to_vec()
}

/// Canonical Falcon-512 PQ address of `kp` (the chain never stores an
/// `address` field on the keypair; the address is always derived).
fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

fn sign_pq_tx(
    kp: &FalconKeypair,
    chain_id: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let dummy = vec![0u8; FALCON512_SIG_LEN];
    let probe = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        dummy,
        pq_addr(kp),
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload.clone(),
        &DEFAULT_SALT,
        chain_id,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        pq_addr(kp),
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
        &DEFAULT_SALT,
        chain_id,
    )
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
fn contract_abi_onchain_gate_is_inert_by_default_and_registered() {
    let _reset = GateResetGuard;
    assert_eq!(CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT, u64::MAX);
    assert_eq!(contract_abi_onchain_activation_height(), u64::MAX);

    for height in [0u64, 1, 500, 1_000_000, u64::MAX - 1, u64::MAX] {
        assert!(!contract_abi_onchain_active_at(height));
    }

    let schedule = current_activation_schedule();
    let gate = schedule
        .gates
        .iter()
        .find(|g| g.name == "CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT")
        .expect("CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT must be in current_activation_schedule()");
    assert_eq!(gate.activation_height, u64::MAX);
    assert_eq!(gate.status, ActivationStatus::GatedOff);

    let table = feature_gates::table();
    let row = table
        .iter()
        .find(|g| g.id == "contract-abi-onchain")
        .expect("contract-abi-onchain must be in feature_gates::table()");
    assert_eq!(row.symbol, "CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT");
    assert_eq!(row.value, u64::MAX);
    assert_eq!(row.status(), "INERT");
    assert_eq!(row.test, Some("tests/w10_deploy_contract_abi_tests.rs"));
}

#[test]
fn opcode_discriminant_is_65_and_wire_and_gas_match_sdk_layout() {
    let code = minimal_wasm();
    let abi_json = sample_abi_json();
    let op = OpCode::SysCallDeployContractWithAbi {
        code: code.clone(),
        abi_json: abi_json.clone(),
    };

    let bytes = bincode::serialize(&op).expect("serialize SysCallDeployContractWithAbi");
    let mut expected = Vec::new();
    expected.extend_from_slice(&65u32.to_le_bytes());
    expected.extend_from_slice(&(code.len() as u64).to_le_bytes());
    expected.extend_from_slice(&code);
    expected.extend_from_slice(&(abi_json.len() as u64).to_le_bytes());
    expected.extend_from_slice(&abi_json);
    assert_eq!(
        bytes, expected,
        "bincode layout must match stellereum-sdk / sdk-js discriminant 65"
    );

    // Existing discriminants 0..=64 remain untouched.
    let deploy_bytes = bincode::serialize(&OpCode::SysCallDeployContract { code: code.clone() })
        .expect("serialize SysCallDeployContract");
    assert_eq!(&deploy_bytes[..4], &19u32.to_le_bytes());

    let apply_comm_bytes = bincode::serialize(&OpCode::SysCallApplyCommission {
        validator: [0x42u8; 32],
    })
    .expect("serialize SysCallApplyCommission");
    assert_eq!(&apply_comm_bytes[..4], &64u32.to_le_bytes());

    // Gas pricing mirrors SysCallDeployContract + abi_json.len().min(MAX_CONTRACT_ABI_BYTES) * GAS_PER_BYTE.
    let expected_gas = contract_deploy_gas(code.len()) + (abi_json.len() as u64) * GAS_PER_BYTE;
    assert_eq!(opcode_gas(&op), expected_gas);
    assert_eq!(
        contract_deploy_with_abi_gas(code.len(), abi_json.len()),
        expected_gas
    );

    let oversized = OpCode::SysCallDeployContractWithAbi {
        code: code.clone(),
        abi_json: vec![b' '; MAX_CONTRACT_ABI_BYTES + 123],
    };
    assert_eq!(
        opcode_gas(&oversized),
        contract_deploy_gas(code.len()) + (MAX_CONTRACT_ABI_BYTES as u64) * GAS_PER_BYTE
    );

    let kp = FalconKeypair::generate_from_seed(0xA1);
    let tx = sign_pq_tx(&kp, 5757, 1_000_000, 0, vec![op]);
    let wire_est = Mempool::estimate_tx_wire_bytes(&tx);
    assert!(
        wire_est >= 256 + 128 + code.len() + abi_json.len(),
        "estimate_tx_wire_bytes must account for code + abi_json, got {wire_est}"
    );
}

#[tokio::test]
async fn deploy_with_abi_refused_below_h_and_committed_deterministically_at_h() {
    let _reset = GateResetGuard;
    set_contract_abi_onchain_activation_override(Some(H));

    let code = minimal_wasm();
    let abi_json = sample_abi_json();
    let expected_abi = ContractAbi::from_json(std::str::from_utf8(&abi_json).unwrap()).unwrap();

    // 1. VM-level check at H - 1: reverts fail-closed before deploying.
    {
        let mut reg = ContractRegistry::new();
        let mut ctx = make_vm_ctx([0x11u8; 32], &mut reg);
        let mut sends = Vec::<ActorSendRequest>::new();
        let opts = VmExecOptions {
            wasm_pmm_hardening: true,
            tx_nonce: 0,
            chain_height: H - 1,
            ..Default::default()
        };
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallDeployContractWithAbi {
                code: code.clone(),
                abi_json: abi_json.clone(),
            }],
            1_000_000,
            &mut ctx,
            &mut sends,
            None,
            &opts,
        );
        match res {
            VmExecutionResult::Reverted(msg) => {
                assert!(
                    msg.contains("inactive at height"),
                    "unexpected revert message at H - 1: {msg}"
                );
            }
            other => panic!("expected Reverted at H - 1, got {other:?}"),
        }
        assert!(reg.contracts.is_empty());
    }

    // 2. Engine-level H - 1 vs H across two independent engines + a control engine without ABI.
    let engine_a = InMemoryStateEngine::new();
    let engine_b = InMemoryStateEngine::new();
    let engine_no_abi = InMemoryStateEngine::new();

    let kp = FalconKeypair::generate_from_seed(0xB2);
    let addr = contract_address(&pq_addr(&kp), 0);

    for engine in [&engine_a, &engine_b, &engine_no_abi] {
        engine
            .update_account(AccountState::new(pq_addr(&kp), 100_000_000_000))
            .await;
    }

    // At H - 1: transaction fails fail-closed, contract does not exist, ABI is None.
    let tx_pre = sign_pq_tx(
        &kp,
        engine_a.chain_id,
        1_000_000,
        0,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: code.clone(),
            abi_json: abi_json.clone(),
        }],
    );
    let err_pre = engine_a
        .apply_transaction_at_height(&tx_pre, 1_700_000_000, H - 1)
        .await
        .expect_err("SysCallDeployContractWithAbi must fail at H - 1");
    assert!(
        err_pre.contains("inactive at height"),
        "expected inactive revert at H - 1, got: {err_pre}"
    );
    assert!(engine_a.get_contract(&addr).await.is_none());
    assert_eq!(engine_a.get_contract_abi_json(&addr).await, None);

    // Nonce was consumed by the failed tx at H - 1 on engine_a; apply the same failed tx on engine_b
    // so both engines remain at identical state & nonce=1 before testing H.
    let err_pre_b = engine_b
        .apply_transaction_at_height(&tx_pre, 1_700_000_000, H - 1)
        .await
        .expect_err("engine_b must also fail at H - 1");
    assert!(err_pre_b.contains("inactive at height"));
    assert_eq!(
        engine_a.get_state_root().await,
        engine_b.get_state_root().await
    );

    // At H: deploy with ABI on engine_a and engine_b (nonce 1), and without ABI on engine_no_abi (nonce 0).
    let deployed_addr = contract_address(&pq_addr(&kp), 1);
    let tx_h = sign_pq_tx(
        &kp,
        engine_a.chain_id,
        1_000_000,
        1,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: code.clone(),
            abi_json: abi_json.clone(),
        }],
    );
    engine_a
        .apply_transaction_at_height(&tx_h, 1_700_000_001, H)
        .await
        .expect("SysCallDeployContractWithAbi must succeed at H on engine_a");
    engine_b
        .apply_transaction_at_height(&tx_h, 1_700_000_001, H)
        .await
        .expect("SysCallDeployContractWithAbi must succeed at H on engine_b");

    let contract_a = engine_a
        .get_contract(&deployed_addr)
        .await
        .expect("contract must exist on engine_a");
    assert_eq!(contract_a.code, code);
    assert_eq!(contract_a.abi.as_ref(), Some(&expected_abi));
    assert_eq!(
        engine_a.get_contract_abi(&deployed_addr).await,
        Some(expected_abi.clone())
    );

    let abi_json_returned = engine_a
        .get_contract_abi_json(&deployed_addr)
        .await
        .expect("get_contract_abi_json must return committed ABI");
    assert_eq!(abi_json_returned, expected_abi.to_json());
    assert_eq!(
        ContractAbi::from_json(&abi_json_returned).unwrap(),
        expected_abi
    );

    let root_a = engine_a.get_state_root().await;
    let root_b = engine_b.get_state_root().await;
    assert_eq!(
        root_a, root_b,
        "state_root must match deterministically across two engines"
    );

    // Control: deploying without ABI at identical nonce=1 produces a DIFFERENT state_root.
    let fail_ctrl = sign_pq_tx(
        &kp,
        engine_no_abi.chain_id,
        1_000_000,
        0,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: code.clone(),
            abi_json: abi_json.clone(),
        }],
    );
    let _ = engine_no_abi
        .apply_transaction_at_height(&fail_ctrl, 1_700_000_000, H - 1)
        .await;
    let tx_plain = sign_pq_tx(
        &kp,
        engine_no_abi.chain_id,
        1_000_000,
        1,
        vec![OpCode::SysCallDeployContract { code }],
    );
    engine_no_abi
        .apply_transaction_at_height(&tx_plain, 1_700_000_001, H)
        .await
        .expect("plain deploy at nonce 1 succeeds");
    assert_ne!(
        root_a,
        engine_no_abi.get_state_root().await,
        "persisting ContractAbi must move state_root compared to deploying without ABI"
    );
}

#[tokio::test]
async fn deploy_with_abi_rejects_malformed_and_oversized_abi_fail_closed() {
    let _reset = GateResetGuard;
    set_contract_abi_onchain_activation_override(Some(H));

    let code = minimal_wasm();
    let kp = FalconKeypair::generate_from_seed(0xC3);
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new(pq_addr(&kp), 100_000_000_000))
        .await;

    let bad_cases: [(&str, Vec<u8>); 4] = [
        ("malformed JSON", b"{not valid json".to_vec()),
        ("non-UTF8 bytes", vec![0xff, 0xfe, 0xfd]),
        (
            "duplicate method validation failure",
            br#"{"methods":[{"name":"dup","params":[]},{"name":"dup","params":[]}]}"#.to_vec(),
        ),
        (
            "oversized ABI (> 64 KiB)",
            vec![b' '; MAX_CONTRACT_ABI_BYTES + 1],
        ),
    ];

    for (nonce, (label, bad_abi)) in bad_cases.into_iter().enumerate() {
        let nonce = nonce as u64;
        let predicted = contract_address(&pq_addr(&kp), nonce);
        let tx = sign_pq_tx(
            &kp,
            engine.chain_id,
            2_000_000,
            nonce,
            vec![OpCode::SysCallDeployContractWithAbi {
                code: code.clone(),
                abi_json: bad_abi,
            }],
        );
        let err = engine
            .apply_transaction_at_height(&tx, 1_700_000_000 + nonce, H)
            .await
            .expect_err(&format!("{label}: expected failure"));
        assert!(
            err.contains("ABI") || err.contains("SVM reverted"),
            "{label}: unexpected error: {err}"
        );
        assert!(
            engine.get_contract(&predicted).await.is_none(),
            "{label}: failed ABI deploy must not materialize contract"
        );
        assert_eq!(
            engine.get_contract_abi_json(&predicted).await,
            None,
            "{label}: failed ABI deploy must not store ABI"
        );
    }
}
