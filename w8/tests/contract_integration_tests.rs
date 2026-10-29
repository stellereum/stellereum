//! On-chain WASM contract lifecycle through the real transaction/block path.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::cell::PatriciaTrie;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{contract_key, AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

/// `(func (export "double") (param i64) (result i64) local.get 0; i64.const 2; i64.mul)`
const DOUBLE_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, //
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7e, //
    0x03, 0x02, 0x01, 0x00, //
    0x07, 0x0a, 0x01, 0x06, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x00, 0x00, //
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x42, 0x02, 0x7e, 0x0b, //
];

async fn funded() -> (InMemoryStateEngine, SigningKey, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let sk = SigningKey::generate(&mut OsRng);
    let addr = sk.verifying_key().to_bytes();
    engine.update_account(AccountState::new(addr, 1_000_000_000_000)).await;
    (engine, sk, addr)
}

fn deploy_tx(sk: &SigningKey, nonce: u64, code: Vec<u8>) -> Transaction {
    Transaction::sign_with_payload(
        sk, [0u8; 32], 0, 5_000_000, nonce, 1, 1,
        vec![OpCode::SysCallDeployContract { code }],
    )
}

fn call_tx(sk: &SigningKey, nonce: u64, contract: [u8; 32], method: &str, arg: i64) -> Transaction {
    Transaction::sign_with_payload(
        sk, [0u8; 32], 0, 5_000_000, nonce, 1, 1,
        vec![OpCode::SysCallCallContract { contract, method: method.as_bytes().to_vec(), arg }],
    )
}

#[tokio::test]
async fn deploy_then_call_onchain() {
    let (engine, sk, _) = funded().await;

    let (applied, failed) = engine.apply_block_parallel(&[deploy_tx(&sk, 0, DOUBLE_WASM.to_vec())], 0).await;
    assert_eq!((applied, failed), (1, 0), "deploy must be applied");
    assert_eq!(engine.contract_count().await, 1);
    let addr = engine.all_contract_addresses().await[0];

    // The deployed code hash is committed into the state root (SPV-provable).
    let root = engine.get_state_root().await;
    let key = contract_key(&addr);
    let proof = engine
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&key)
        .expect("contract proof must exist");
    let code_hash = engine.get_contract(&addr).await.unwrap().code_hash;
    assert!(
        PatriciaTrie::verify_merkle_proof(&root, &key, &code_hash, &proof),
        "contract code hash must verify against the state root"
    );

    // Execute it via a real transaction.
    let (applied, failed) = engine
        .apply_block_parallel(&[call_tx(&sk, 1, addr, "double", 21)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "call must be applied");
    assert_eq!(engine.call_contract(&addr, "double", 100, 10_000).await.unwrap().0, 200);
}

#[tokio::test]
async fn reverting_payload_discards_the_deploy() {
    // Deploy a valid contract and then hit a failing token syscall in the SAME
    // payload: the whole execution (including the deploy) must be discarded.
    let (engine, sk, _) = funded().await;
    let missing_token = [0xABu8; 32];
    let payload = vec![
        OpCode::SysCallDeployContract { code: DOUBLE_WASM.to_vec() },
        OpCode::SysCallTokenTransfer { token_id: missing_token, to: [1u8; 32], amount: 1 },
    ];
    let tx = Transaction::sign_with_payload(&sk, [0u8; 32], 0, 5_000_000, 0, 1, 1, payload);
    let (applied, failed) = engine.apply_block_parallel(&[tx], 0).await;
    assert_eq!(applied, 0, "reverting payload must not be applied");
    assert_eq!(failed, 1);
    assert_eq!(engine.contract_count().await, 0, "deploy must be rolled back (atomicity)");
}

#[tokio::test]
async fn invalid_wasm_is_rejected_onchain() {
    let (engine, sk, _) = funded().await;
    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(&sk, 0, vec![0xDE, 0xAD, 0xBE, 0xEF])], 0)
        .await;
    assert_eq!(applied, 0, "invalid wasm deploy must fail");
    assert_eq!(failed, 1);
    assert_eq!(engine.contract_count().await, 0);
}

#[tokio::test]
async fn out_of_fuel_call_reverts() {
    let (engine, sk, _) = funded().await;
    engine.apply_block_parallel(&[deploy_tx(&sk, 0, DOUBLE_WASM.to_vec())], 0).await;
    let addr = engine.all_contract_addresses().await[0];

    // gas_limit barely covers the base call cost -> almost no wasmi fuel left.
    let tx = Transaction::sign_with_payload(
        &sk, [0u8; 32], 0, 1_050, 1, 1, 1,
        vec![OpCode::SysCallCallContract { contract: addr, method: b"double".to_vec(), arg: 1 }],
    );
    let (applied, failed) = engine.apply_block_parallel(&[tx], 0).await;
    assert_eq!(applied, 0, "out-of-fuel call must not be applied");
    assert_eq!(failed, 1);
}
