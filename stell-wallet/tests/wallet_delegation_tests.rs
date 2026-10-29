//! Comprehensive Delegation Lifecycle & SPV Wallet Test Suite
//!
//! Verifies:
//! 1. CLI argument parsing for `delegate`, `begin-unbond`, `withdraw-unbond`, `claim-rewards`.
//! 2. Transaction construction and parameter validation across all delegation operations.
//! 3. Opcode payload structures and bincode serialization discriminants matching
//!    `stellereum::svm::OpCode` (SysCallDelegate: 23 [svm.rs:375], SysCallBeginUndelegate: 44,
//!    SysCallUndelegate: 24 [svm.rs:377], SysCallClaimRewards: 25 [svm.rs:379],
//!    SysCallClaimDelegatorRewards: 45).
//! 4. Mempool admission, receipt polling, and fail-closed error handling against
//!    a real in-process `stellereum` RPC node stack.

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

use client::LightClient;
use rpc::{RpcConfig, TxFinality};
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stellereum::svm::{
    OpCode, GAS_BASIC_TRANSFER, GAS_STAKE_BOND, GAS_STAKE_CLAIM, GAS_STAKE_UNBOND,
};
use stellereum::wallet::WalletAccount;

static NEXT_PORT: AtomicU16 = AtomicU16::new(19800);

// -----------------------------------------------------------------------------
// Test harness: real in-process RPC node running axum + real SVM state engine
// -----------------------------------------------------------------------------

struct LiveNode {
    url: String,
    state: Arc<stellereum::rpc::RpcState>,
    engine: Arc<stellereum::state_engine::InMemoryStateEngine>,
}

async fn spawn_node(auth_token: Option<String>) -> LiveNode {
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    let mempool = Arc::new(tokio::sync::RwLock::new(
        stellereum::mempool::Mempool::default()
            .with_base_fee(GAS_BASIC_TRANSFER)
            .with_session_registry(engine.session_keys_handle()),
    ));
    let state = Arc::new(stellereum::rpc::RpcState {
        engine: engine.clone(),
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "wallet-delegation-test-node".to_string(),
        chain_id: 5757,
        staking: engine.staking_handle(),
        governance: engine.governance_handle(),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let url = format!("http://127.0.0.1:{port}/");
    let svc = state.clone();
    let bind = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = stellereum::rpc::serve(&bind, svc).await;
    });
    let probe = RpcConfig {
        url: url.clone(),
        auth_token: None,
        faucet_token: None,
    };
    for _ in 0..100 {
        if rpc::chain_id(&probe).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    LiveNode { url, state, engine }
}

async fn rpc_client(node: &LiveNode) -> LightClient {
    LightClient::connect_rpc(&node.url, None, None, 4, 1)
        .await
        .expect("connect_rpc")
}

fn test_account(seed_byte: u8) -> WalletAccount {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[1] = 0xBD;
    seed[2] = 0x99;
    WalletAccount::from_seed(&seed)
}

async fn fund_account(node: &LiveNode, addr: [u8; 32], balance: u64) {
    node.engine
        .update_account(stellereum::state_engine::AccountState::new(addr, balance))
        .await;
}

fn get_opcode_discriminant(op: &OpCode) -> u32 {
    let bytes = bincode::serialize(op).expect("serialize opcode");
    assert!(
        bytes.len() >= 4,
        "bincode encodes discriminant in first 4 bytes"
    );
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

// -----------------------------------------------------------------------------
// 1. CLI Argument Parsing Tests (against `stell` compiled binary)
// -----------------------------------------------------------------------------

#[test]
fn test_cli_parsing_delegate_command() {
    let bin = env!("CARGO_BIN_EXE_stell");

    // Help displays usage and expected arguments
    let out = Command::new(bin)
        .args(["delegate", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("delegate [OPTIONS] <AMOUNT>"));
    assert!(stdout.contains("--validator <VALIDATOR>"));

    // Missing amount fails with clap error code 2
    let out_err = Command::new(bin).args(["delegate"]).output().expect("exec");
    assert_eq!(out_err.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out_err.stderr);
    assert!(stderr.contains("required arguments were not provided") || stderr.contains("<AMOUNT>"));

    // Passing an invalid hex validator triggers validator hex validation
    let out_bad_hex = Command::new(bin)
        .args(["delegate", "100", "--validator", "not-hex-at-all"])
        .output()
        .expect("exec");
    assert!(!out_bad_hex.status.success());
    let err_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out_bad_hex.stdout),
        String::from_utf8_lossy(&out_bad_hex.stderr)
    );
    assert!(
        err_msg.contains("validator key") || err_msg.contains("hex") || err_msg.contains("Invalid")
    );

    // Passing invalid amount (negative or 0) triggers amount parser error
    let out_zero = Command::new(bin)
        .args(["delegate", "0"])
        .output()
        .expect("exec");
    assert!(!out_zero.status.success());
    let err_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out_zero.stdout),
        String::from_utf8_lossy(&out_zero.stderr)
    );
    assert!(err_msg.contains("greater than zero") || err_msg.contains("Wallet not found"));
}

#[test]
fn test_cli_parsing_begin_unbond_command() {
    let bin = env!("CARGO_BIN_EXE_stell");

    // Help displays usage
    let out = Command::new(bin)
        .args(["begin-unbond", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("begin-unbond [OPTIONS] <AMOUNT>"));
    assert!(stdout.contains("--validator <VALIDATOR>"));

    // Missing amount fails with code 2
    let out_err = Command::new(bin)
        .args(["begin-unbond"])
        .output()
        .expect("exec");
    assert_eq!(out_err.status.code(), Some(2));

    // Invalid validator key length rejected
    let out_short_hex = Command::new(bin)
        .args(["begin-unbond", "50", "--validator", "deadbeef"])
        .output()
        .expect("exec");
    assert!(!out_short_hex.status.success());
    let err_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out_short_hex.stdout),
        String::from_utf8_lossy(&out_short_hex.stderr)
    );
    assert!(err_msg.contains("32 bytes") || err_msg.contains("64 hex"));
}

#[test]
fn test_cli_parsing_withdraw_unbond_command() {
    let bin = env!("CARGO_BIN_EXE_stell");

    // Help displays usage
    let out = Command::new(bin)
        .args(["withdraw-unbond", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("withdraw-unbond [OPTIONS]"));
    assert!(stdout.contains("--validator <VALIDATOR>"));

    // Bad hex validator rejected
    let out_bad_hex = Command::new(bin)
        .args(["withdraw-unbond", "--validator", "zzzz1234"])
        .output()
        .expect("exec");
    assert!(!out_bad_hex.status.success());
}

#[test]
fn test_cli_parsing_claim_rewards_command() {
    let bin = env!("CARGO_BIN_EXE_stell");

    // Help displays usage
    let out = Command::new(bin)
        .args(["claim-rewards", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("claim-rewards [OPTIONS]"));
    assert!(stdout.contains("--validator <VALIDATOR>"));
    assert!(stdout.contains("--delegator"));

    // Bad hex validator rejected
    let out_bad = Command::new(bin)
        .args(["claim-rewards", "--validator", "1234"])
        .output()
        .expect("exec");
    assert!(!out_bad.status.success());
}

// -----------------------------------------------------------------------------
// 2. Transaction Construction & Gas Limits Tests
// -----------------------------------------------------------------------------

#[test]
fn test_tx_construction_delegate() {
    let delegator = test_account(0x10);
    let validator = [0xAAu8; 32];
    let amount_nano = 250_000_000_000u64; // 250 STELL
    let nonce = 5;

    // Direct construction via helper
    let tx1 = LightClient::build_delegate_tx(&delegator, validator, amount_nano, nonce);

    // Direct construction via WalletAccount::create_payload_transaction
    let tx2 = delegator.create_payload_transaction(
        vec![OpCode::SysCallDelegate {
            validator,
            amount: amount_nano,
        }],
        GAS_STAKE_BOND + GAS_BASIC_TRANSFER,
        nonce,
    );

    assert_eq!(tx1.compute_tx_hash(), tx2.compute_tx_hash());
    assert_eq!(tx1.from, delegator.address);
    assert_eq!(tx1.to, delegator.address);
    assert_eq!(tx1.amount, 0); // Native transfer amount is 0; delegated amount is in payload
    assert_eq!(tx1.gas_limit, GAS_STAKE_BOND + GAS_BASIC_TRANSFER);
    assert_eq!(tx1.gas_limit, 2_000 + 280_000);
    assert_eq!(tx1.nonce, nonce);
    assert!(tx1.verify_signature(), "signature must verify locally");

    // Check payload
    assert_eq!(tx1.payload.len(), 1);
    match &tx1.payload[0] {
        OpCode::SysCallDelegate {
            validator: v,
            amount: a,
        } => {
            assert_eq!(*v, validator);
            assert_eq!(*a, amount_nano);
        }
        other => panic!("expected SysCallDelegate, got {other:?}"),
    }
}

#[test]
fn test_tx_construction_begin_unbond() {
    let delegator = test_account(0x20);
    let validator = [0xBBu8; 32];
    let amount_nano = 100_000_000_000u64; // 100 STELL
    let nonce = 12;

    let tx = LightClient::build_begin_unbond_tx(&delegator, validator, amount_nano, nonce);

    assert_eq!(tx.from, delegator.address);
    assert_eq!(tx.gas_limit, GAS_STAKE_UNBOND + GAS_BASIC_TRANSFER);
    assert_eq!(tx.gas_limit, 800 + 280_000);
    assert_eq!(tx.nonce, nonce);
    assert!(tx.verify_signature());

    assert_eq!(tx.payload.len(), 1);
    match &tx.payload[0] {
        OpCode::SysCallBeginUndelegate {
            validator: v,
            amount: a,
        } => {
            assert_eq!(*v, validator);
            assert_eq!(*a, amount_nano);
        }
        other => panic!("expected SysCallBeginUndelegate, got {other:?}"),
    }
}

#[test]
fn test_tx_construction_withdraw_unbond() {
    let delegator = test_account(0x30);
    let validator = [0xCCu8; 32];
    let nonce = 15;

    let tx = LightClient::build_withdraw_unbond_tx(&delegator, validator, nonce);

    assert_eq!(tx.from, delegator.address);
    assert_eq!(tx.gas_limit, GAS_STAKE_UNBOND + GAS_BASIC_TRANSFER);
    assert_eq!(tx.gas_limit, 800 + 280_000);
    assert_eq!(tx.nonce, nonce);
    assert!(tx.verify_signature());

    assert_eq!(tx.payload.len(), 1);
    match &tx.payload[0] {
        OpCode::SysCallUndelegate { validator: v } => {
            assert_eq!(*v, validator);
        }
        other => panic!("expected SysCallUndelegate, got {other:?}"),
    }
}

#[test]
fn test_tx_construction_claim_rewards_validator_and_delegator() {
    let account = test_account(0x40);
    let other_validator = [0xDDu8; 32];
    let nonce = 22;

    // Case 1: Validator claiming its own validator rewards (SysCallClaimRewards)
    let tx_val = LightClient::build_claim_rewards_tx(&account, account.address, false, nonce);
    assert_eq!(tx_val.from, account.address);
    assert_eq!(tx_val.gas_limit, GAS_STAKE_CLAIM + GAS_BASIC_TRANSFER);
    assert_eq!(tx_val.gas_limit, 600 + 280_000);
    assert!(tx_val.verify_signature());
    assert_eq!(tx_val.payload.len(), 1);
    match &tx_val.payload[0] {
        OpCode::SysCallClaimRewards { validator: v } => {
            assert_eq!(*v, account.address);
        }
        other => panic!("expected SysCallClaimRewards, got {other:?}"),
    }

    // Case 2: Delegator claiming accrued rewards from a third-party validator (SysCallClaimDelegatorRewards)
    let tx_del = LightClient::build_claim_rewards_tx(&account, other_validator, true, nonce + 1);
    assert_eq!(tx_del.from, account.address);
    assert_eq!(tx_del.gas_limit, GAS_STAKE_CLAIM + GAS_BASIC_TRANSFER);
    assert_eq!(tx_del.gas_limit, 600 + 280_000);
    assert!(tx_del.verify_signature());
    assert_eq!(tx_del.payload.len(), 1);
    match &tx_del.payload[0] {
        OpCode::SysCallClaimDelegatorRewards { validator: v } => {
            assert_eq!(*v, other_validator);
        }
        other => panic!("expected SysCallClaimDelegatorRewards, got {other:?}"),
    }

    // Case 3: Explicit build_claim_delegator_rewards_tx helper
    let tx_del_explicit =
        LightClient::build_claim_delegator_rewards_tx(&account, other_validator, nonce + 1);
    assert_eq!(tx_del.compute_tx_hash(), tx_del_explicit.compute_tx_hash());

    // Case 4: Explicit build_claim_validator_rewards_tx helper
    let tx_val_explicit =
        LightClient::build_claim_validator_rewards_tx(&account, account.address, nonce);
    assert_eq!(tx_val.compute_tx_hash(), tx_val_explicit.compute_tx_hash());
}

// -----------------------------------------------------------------------------
// 3. Opcode Discriminant Verification matching stellereum::svm::OpCode
// -----------------------------------------------------------------------------

#[test]
fn test_verify_opcode_discriminants_exhaustive() {
    let dummy_val = [0x55u8; 32];

    // 1. SysCallDelegate (defined at svm.rs line 375, bincode discriminant 23)
    let op_delegate = OpCode::SysCallDelegate {
        validator: dummy_val,
        amount: 100,
    };
    let disc_delegate = get_opcode_discriminant(&op_delegate);
    assert_eq!(
        disc_delegate, 23,
        "SysCallDelegate must have bincode discriminant 23 (svm.rs:375)"
    );

    // 2. SysCallBeginUndelegate (discriminant 44)
    let op_begin_unbond = OpCode::SysCallBeginUndelegate {
        validator: dummy_val,
        amount: 100,
    };
    let disc_begin_unbond = get_opcode_discriminant(&op_begin_unbond);
    assert_eq!(
        disc_begin_unbond, 44,
        "SysCallBeginUndelegate must have bincode discriminant 44"
    );

    // 3. SysCallUndelegate (defined at svm.rs line 377, bincode discriminant 24)
    let op_withdraw_unbond = OpCode::SysCallUndelegate {
        validator: dummy_val,
    };
    let disc_withdraw = get_opcode_discriminant(&op_withdraw_unbond);
    assert_eq!(
        disc_withdraw, 24,
        "SysCallUndelegate must have bincode discriminant 24 (svm.rs:377)"
    );

    // 4. SysCallClaimRewards (defined at svm.rs line 379, bincode discriminant 25)
    let op_claim_val = OpCode::SysCallClaimRewards {
        validator: dummy_val,
    };
    let disc_claim_val = get_opcode_discriminant(&op_claim_val);
    assert_eq!(
        disc_claim_val, 25,
        "SysCallClaimRewards must have bincode discriminant 25 (svm.rs:379)"
    );

    // 5. SysCallClaimDelegatorRewards (discriminant 45)
    let op_claim_del = OpCode::SysCallClaimDelegatorRewards {
        validator: dummy_val,
    };
    let disc_claim_del = get_opcode_discriminant(&op_claim_del);
    assert_eq!(
        disc_claim_del, 45,
        "SysCallClaimDelegatorRewards must have bincode discriminant 45"
    );

    // Verify round-trip deserialization preserves opcodes
    let raw_del = bincode::serialize(&op_delegate).unwrap();
    let de_del: OpCode = bincode::deserialize(&raw_del).unwrap();
    assert!(matches!(de_del, OpCode::SysCallDelegate { .. }));

    let raw_bu = bincode::serialize(&op_begin_unbond).unwrap();
    let de_bu: OpCode = bincode::deserialize(&raw_bu).unwrap();
    assert!(matches!(de_bu, OpCode::SysCallBeginUndelegate { .. }));

    let raw_wu = bincode::serialize(&op_withdraw_unbond).unwrap();
    let de_wu: OpCode = bincode::deserialize(&raw_wu).unwrap();
    assert!(matches!(de_wu, OpCode::SysCallUndelegate { .. }));

    let raw_cr = bincode::serialize(&op_claim_val).unwrap();
    let de_cr: OpCode = bincode::deserialize(&raw_cr).unwrap();
    assert!(matches!(de_cr, OpCode::SysCallClaimRewards { .. }));

    let raw_cdr = bincode::serialize(&op_claim_del).unwrap();
    let de_cdr: OpCode = bincode::deserialize(&raw_cdr).unwrap();
    assert!(matches!(
        de_cdr,
        OpCode::SysCallClaimDelegatorRewards { .. }
    ));
}

// -----------------------------------------------------------------------------
// 4. Receipt Polling and Node Interaction Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_delegate_tx_admission_and_receipt_confirmation() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x51);
    let validator = [0x11u8; 32];
    fund_account(&node, delegator.address, 100_000_000_000).await;

    let client = rpc_client(&node).await;
    let tx = LightClient::build_delegate_tx(&delegator, validator, 10_000_000_000, 0);

    // Broadcast: admitted to mempool, reports Pending before block finalization
    let (tx_hash, finality) = client.broadcast_tx(&tx).await.expect("broadcast delegate");
    assert_eq!(tx_hash, tx.compute_tx_hash());
    assert_eq!(finality, TxFinality::Pending);
    assert!(node.state.mempool.read().await.contains(&tx_hash));

    // Consensus finalize hook records successful receipt at height 1
    node.state
        .record_receipts(
            1,
            [0x01u8; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[282_000],
        )
        .await;

    let cfg = client.rpc.clone().unwrap();
    let final_status = rpc::poll_receipt(&cfg, &hex::encode(tx_hash), 5, 1);
    assert!(
        matches!(final_status, TxFinality::Confirmed { height: 1, .. }),
        "expected Confirmed@1, got {final_status:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_begin_unbond_admission_and_receipt_confirmation() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x52);
    let validator = [0x22u8; 32];
    fund_account(&node, delegator.address, 100_000_000_000).await;

    let client = rpc_client(&node).await;
    let tx = LightClient::build_begin_unbond_tx(&delegator, validator, 5_000_000_000, 0);

    let (tx_hash, finality) = client
        .broadcast_tx(&tx)
        .await
        .expect("broadcast begin unbond");
    assert_eq!(finality, TxFinality::Pending);
    assert!(node.state.mempool.read().await.contains(&tx_hash));

    // Finalize at height 2
    node.state
        .record_receipts(
            2,
            [0x02u8; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[280_800],
        )
        .await;

    let cfg = client.rpc.clone().unwrap();
    let final_status = rpc::poll_receipt(&cfg, &hex::encode(tx_hash), 5, 1);
    assert!(matches!(
        final_status,
        TxFinality::Confirmed { height: 2, .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_withdraw_unbond_admission_and_receipt_confirmation() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x53);
    let validator = [0x33u8; 32];
    fund_account(&node, delegator.address, 50_000_000_000).await;

    let client = rpc_client(&node).await;
    let tx = LightClient::build_withdraw_unbond_tx(&delegator, validator, 0);

    let (tx_hash, finality) = client
        .broadcast_tx(&tx)
        .await
        .expect("broadcast withdraw unbond");
    assert_eq!(finality, TxFinality::Pending);

    // Finalize at height 3
    node.state
        .record_receipts(
            3,
            [0x03u8; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[280_800],
        )
        .await;

    let cfg = client.rpc.clone().unwrap();
    let final_status = rpc::poll_receipt(&cfg, &hex::encode(tx_hash), 5, 1);
    assert!(matches!(
        final_status,
        TxFinality::Confirmed { height: 3, .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_claim_rewards_admission_and_receipt_confirmation() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x54);
    let validator = [0x44u8; 32];
    fund_account(&node, delegator.address, 50_000_000_000).await;

    let client = rpc_client(&node).await;
    let tx = LightClient::build_claim_delegator_rewards_tx(&delegator, validator, 0);

    let (tx_hash, finality) = client
        .broadcast_tx(&tx)
        .await
        .expect("broadcast claim delegator rewards");
    assert_eq!(finality, TxFinality::Pending);

    // Finalize at height 4
    node.state
        .record_receipts(
            4,
            [0x04u8; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[280_600],
        )
        .await;

    let cfg = client.rpc.clone().unwrap();
    let final_status = rpc::poll_receipt(&cfg, &hex::encode(tx_hash), 5, 1);
    assert!(matches!(
        final_status,
        TxFinality::Confirmed { height: 4, .. }
    ));
}

// -----------------------------------------------------------------------------
// 5. Error Handling & Node Rejection Tests
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_receipt_polling_rejection_marks_failed_not_confirmed() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x61);
    let validator = [0x66u8; 32];
    fund_account(&node, delegator.address, 50_000_000_000).await;

    let client = rpc_client(&node).await;
    let tx = LightClient::build_delegate_tx(&delegator, validator, 5_000_000_000, 0);
    let (tx_hash, _) = client.broadcast_tx(&tx).await.unwrap();

    // Node reports receipt with success=false (SVM execution reverted)
    node.state
        .record_receipts(
            5,
            [0x05u8; 32],
            std::slice::from_ref(&tx),
            &[false],
            &[282_000],
        )
        .await;

    let cfg = client.rpc.clone().unwrap();
    let status = rpc::poll_receipt(&cfg, &hex::encode(tx_hash), 5, 1);
    assert!(
        matches!(
            status,
            TxFinality::Failed {
                height: Some(5),
                ..
            }
        ),
        "failed receipt must never report confirmed: got {status:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_node_rejection_mempool_insufficient_funds() {
    let node = spawn_node(None).await;
    let broke_delegator = test_account(0x62); // 0 balance
    let validator = [0x77u8; 32];

    let client = rpc_client(&node).await;
    let tx = LightClient::build_delegate_tx(&broke_delegator, validator, 1_000_000_000, 0);

    // Node mempool admission rejects transactions with balance < gas_limit
    let res = client.broadcast_tx(&tx).await;
    assert!(
        res.is_err(),
        "node must reject admission for account with zero balance"
    );
    let err_text = res.err().unwrap();
    assert!(err_text.contains("rejected") && err_text.contains("cannot pay"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_node_rejection_corrupted_signature() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x63);
    let validator = [0x88u8; 32];
    fund_account(&node, delegator.address, 50_000_000_000).await;

    let client = rpc_client(&node).await;
    let mut tx = LightClient::build_delegate_tx(&delegator, validator, 1_000_000_000, 0);

    // Tamper with signature
    tx.signature[0] ^= 0xFF;

    let res = client.broadcast_tx(&tx).await;
    assert!(
        res.is_err(),
        "tampered signature must be rejected immediately"
    );
    assert!(res.err().unwrap().contains("signature"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_receipt_polling_timeout_honestly_returns_pending() {
    let node = spawn_node(None).await;
    let delegator = test_account(0x64);
    let validator = [0x99u8; 32];
    fund_account(&node, delegator.address, 50_000_000_000).await;

    let client = rpc_client(&node).await;
    let tx = LightClient::build_delegate_tx(&delegator, validator, 1_000_000_000, 0);
    let (tx_hash, _) = client.broadcast_tx(&tx).await.unwrap();

    let cfg = client.rpc.clone().unwrap();
    // Poll with 1 second timeout when no block is minted
    let polled = rpc::poll_receipt(&cfg, &hex::encode(tx_hash), 1, 1);
    assert_eq!(
        polled,
        TxFinality::Pending,
        "polling timeout must honestly return Pending, never fabricate Confirmed"
    );
}
