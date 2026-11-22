//! FINAL REVIEW FIX (cross-shard contract sends burn value).
//!
//! A contract that calls `host.send_message` for a recipient on a NON-LOCAL
//! shard had no authenticated delivery path: the router built an unsigned,
//! unproven record, overwrote the canonical `msg_id`, wrote no escrow leaf, and
//! the hardened router debited `accounts[msg.sender]` before enqueuing it. No
//! inbound gate can accept such a record, so the value was DESTROYED — with no
//! delivery and no bounce.
//!
//! `WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT = 0` makes the source REFUSE the
//! whole payload before any mutation/debit. These tests pin the producer-side
//! behaviour through the REAL block path:
//!   * a value-bearing cross-shard send reverts the transaction, leaves the
//!     contract balance unchanged and `cross_shard_out` empty;
//!   * a ZERO-value cross-shard message is refused the same way;
//!   * a SAME-shard contract message still delivers to the recipient inbox.

use stellereum::chain_spec::{
    wasm_xshard_contract_send_refusal_active_at, WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT,
};
use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::sharding::{Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, ActorMessage, InMemoryStateEngine};
use stellereum::svm::OpCode;

const USER_SEED: u8 = 0x43;
const CONTRACT_FUNDS: u64 = 1_000_000;
const SEND_VALUE: i64 = 350_000;

/// Recipient whose leading bytes route to workchain shard 1 under the default
/// topology (`ShardTopology::new()`); the contract runs on shard 0.
const CROSS_SHARD_RECIPIENT: [u8; 32] = [0x77u8; 32];

fn send_contract_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (import "host" "send_message"
               (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
             (memory (export "memory") 1)
             (func $store_recipient
               (i64.store (i32.const 0) (i64.const 0x7777777777777777))
               (i64.store (i32.const 8) (i64.const 0x7777777777777777))
               (i64.store (i32.const 16) (i64.const 0x7777777777777777))
               (i64.store (i32.const 24) (i64.const 0x7777777777777777)))
             (func (export "send_value") (param $val i64) (result i64)
               (call $store_recipient)
               ;; recipient ptr/len, value, empty payload, bounce = 1
               (call $send_message
                 (i64.const 0) (i64.const 32) (local.get $val)
                 (i64.const 32) (i64.const 0) (i64.const 1)))
             (func (export "send_zero") (param $val i64) (result i64)
               (call $store_recipient)
               ;; value = 0, empty payload, bounce = 1
               (call $send_message
                 (i64.const 0) (i64.const 32) (i64.const 0)
                 (i64.const 32) (i64.const 0) (i64.const 1))))"#,
    )
    .expect("send_message contract compiles")
}

fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ fixture registration must succeed");
    (from, pk)
}

fn pq_sign_with_payload(seed: u8, nonce: u64, gas: u64, payload: Vec<OpCode>) -> Transaction {
    let (from, pk) = pq_pair(seed);
    let mut tx = Transaction {
        from,
        to: [0u8; 32],
        amount: 0,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    assert!(tx.is_pq(), "PQ fixture must build the PQ envelope");
    assert!(tx.verify_signature(), "PQ fixture signature must verify");
    tx
}

fn deploy_tx(seed: u8, nonce: u64, code: Vec<u8>) -> Transaction {
    pq_sign_with_payload(
        seed,
        nonce,
        5_000_000,
        vec![OpCode::SysCallDeployContract { code }],
    )
}

fn call_tx(seed: u8, nonce: u64, contract: [u8; 32], method: &str, arg: i64) -> Transaction {
    pq_sign_with_payload(
        seed,
        nonce,
        5_000_000,
        vec![OpCode::SysCallCallContract {
            contract,
            method: method.as_bytes().to_vec(),
            arg,
        }],
    )
}

/// Deploy the sender contract, fund it, and return `(engine, sender, contract)`.
async fn deployed(local_shard: u32) -> (InMemoryStateEngine, [u8; 32], [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    engine.enable_cross_shard();
    engine.set_shard_id(local_shard);
    let (sender, _) = pq_pair(USER_SEED);
    engine
        .update_account(AccountState::new(sender, 1_000_000_000_000))
        .await;

    let (applied, failed) = engine
        .apply_block_parallel(&[deploy_tx(USER_SEED, 0, send_contract_wasm())], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "contract deploy must apply");
    let contract = engine.all_contract_addresses().await[0];
    engine
        .update_account(AccountState::new(contract, CONTRACT_FUNDS))
        .await;
    (engine, sender, contract)
}

async fn contract_balance(engine: &InMemoryStateEngine, contract: &[u8; 32]) -> u64 {
    engine
        .get_account(contract)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

#[test]
fn refusal_gate_is_active_from_genesis() {
    assert_eq!(WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT, 0);
    assert!(wasm_xshard_contract_send_refusal_active_at(0));
    assert!(wasm_xshard_contract_send_refusal_active_at(u64::MAX));
}

#[tokio::test]
async fn value_bearing_cross_shard_contract_send_reverts_without_debit_or_record() {
    let (engine, _sender, contract) = deployed(MASTERCHAIN_SHARD).await;
    // The registry mirror is populated from the account balance per call, so
    // its pre-call value is what a full rollback must restore.
    let registry_balance_before = engine
        .get_contract(&contract)
        .await
        .expect("contract registry entry")
        .balance;

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(USER_SEED, 1, contract, "send_value", SEND_VALUE)],
            0,
        )
        .await;

    // Fail-before: on the old code this call applied and the contract was
    // debited by SEND_VALUE while an undeliverable record sat in
    // `cross_shard_out`. After the refusal the whole payload reverts.
    assert_eq!(
        (applied, failed),
        (0, 1),
        "a cross-shard contract send must revert"
    );
    assert_eq!(
        contract_balance(&engine, &contract).await,
        CONTRACT_FUNDS,
        "the source contract keeps the value: no burn"
    );
    assert_eq!(
        engine
            .get_contract(&contract)
            .await
            .expect("contract registry entry")
            .balance,
        registry_balance_before,
        "the registry balance is rolled back too (host.send_message had debited it in memory)"
    );
    assert!(
        engine.get_cross_shard_out().await.is_empty(),
        "no undeliverable cross-shard record may be enqueued"
    );

    // Zero-value messages are refused too: the record itself is invalid, not
    // just the value movement.
    let (applied, failed) = engine
        .apply_block_parallel(&[call_tx(USER_SEED, 2, contract, "send_zero", 0)], 0)
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "a zero-value cross-shard message must revert as well"
    );
    assert_eq!(
        contract_balance(&engine, &contract).await,
        CONTRACT_FUNDS,
        "a zero-value refusal leaves the balance untouched"
    );
    assert!(
        engine.get_cross_shard_out().await.is_empty(),
        "no zero-value cross-shard record may be enqueued"
    );
}

#[tokio::test]
async fn same_shard_contract_send_still_delivers_to_inbox() {
    // Local shard 1: the recipient resolves to shard 1 under the default
    // topology, so this is a SAME-shard message and must keep working exactly
    // as before (actor inbox, not `cross_shard_out`).
    let (engine, _sender, contract) = deployed(1).await;
    // A same-shard message is delivered into the recipient's INBOX only when
    // the account exists; with `bounce = 1` and no account the correct
    // semantics are a bounce back to the sender (covered by the actor path,
    // not by `cross_shard_out`). Create the account so this test pins the
    // delivery branch.
    engine
        .update_account(AccountState::new(CROSS_SHARD_RECIPIENT, 0))
        .await;

    let (applied, failed) = engine
        .apply_block_parallel(
            &[call_tx(USER_SEED, 1, contract, "send_value", SEND_VALUE)],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0), "same-shard send must apply");
    assert_eq!(
        contract_balance(&engine, &contract).await,
        CONTRACT_FUNDS - SEND_VALUE as u64,
        "the sender is debited exactly once for a delivered same-shard message"
    );
    assert!(
        engine.get_cross_shard_out().await.is_empty(),
        "a same-shard message never enters cross_shard_out"
    );

    let recipient = engine
        .get_account(&CROSS_SHARD_RECIPIENT)
        .await
        .expect("same-shard recipient inbox must exist");
    assert_eq!(recipient.inbox.len(), 1, "recipient inbox gets the message");
    let msg: &ActorMessage = &recipient.inbox[0];
    assert_eq!(msg.sender, contract);
    assert_eq!(msg.recipient, CROSS_SHARD_RECIPIENT);
    assert_eq!(msg.value, SEND_VALUE as u64);
    assert!(!msg.bounced);
}
