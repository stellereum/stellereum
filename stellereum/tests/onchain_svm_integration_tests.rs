//! End-to-end tests proving the SVM / token / orderbook are actually executed
//! as part of block application (on-chain), not just as a standalone library.

use stellereum::orderbook::PAIR_STELL_USDT;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

async fn funded_engine(owner: [u8; 32], balance: u64) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.update_account(AccountState::new(owner, balance)).await;
    e
}

/// FULL-PQ sender fixture: an implicit Falcon-512 identity, registered
/// globally so the tx pays no activation surcharge.
fn pq_owner(seed: u8) -> ([u8; 32], FalconKeypair) {
    let fk = FalconKeypair::generate_from_seed(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (from, fk)
}

/// FULL-PQ replacement for `Transaction::sign_with_payload` in fixtures.
fn pq_tx(
    fk: &FalconKeypair,
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, fk.sign(&msg)).encode();
    tx
}

#[tokio::test]
async fn token_syscall_in_payload_is_applied_on_chain() {
    let (from, fk) = pq_owner(0x61);
    let engine = funded_engine(from, 1_000_000).await;

    let meta = stellereum::token::TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let token_id = engine.create_token(from, meta, 1_000).await.unwrap();

    let to = [7u8; 32];
    let payload = vec![OpCode::SysCallTokenTransfer {
        token_id,
        to,
        amount: 400,
    }];
    // The token table is priced at the native floor, so the declared gas must
    // cover it.
    let tx = pq_tx(&fk, from, [0u8; 32], 0, 300_000, 0, payload);

    engine
        .apply_transaction(&tx, 0)
        .await
        .expect("payload must execute");

    assert_eq!(engine.token_balance(&token_id, &from).await, 600);
    assert_eq!(engine.token_balance(&token_id, &to).await, 400);
}

#[tokio::test]
async fn reverting_payload_does_not_move_native_balance() {
    let (from, fk) = pq_owner(0x62);
    let engine = funded_engine(from, 1_000_000).await;

    let missing = [0xAB; 32];
    let payload = vec![OpCode::SysCallTokenTransfer {
        token_id: missing,
        to: [7u8; 32],
        amount: 1,
    }];
    let tx = pq_tx(&fk, from, [9u8; 32], 5_000, 100_000, 0, payload);

    let res = engine.apply_transaction(&tx, 0).await;
    assert!(res.is_err(), "reverting payload must fail the tx");

    let acc = engine.get_account(&from).await.unwrap();
    // No VALUE moved (the recipient is not credited, the token supply is
    // untouched) - but the failed attempt is not free: it pays the F-01
    // failure fee it declared and consumes the nonce, exactly like the block
    // path (so the two paths agree on the state root).
    assert_eq!(
        acc.balance, 900_000,
        "only the failure fee is charged on revert"
    );
    assert_eq!(acc.nonce, 1, "a failed attempt consumes the nonce");
    assert!(
        engine.get_account(&[9u8; 32]).await.is_none(),
        "recipient must not be credited"
    );
}

#[tokio::test]
async fn orderbook_order_in_payload_is_recorded_in_consensus_state() {
    let (from, fk) = pq_owner(0x63);
    let engine = funded_engine(from, 10_000_000_000).await;

    let payload = vec![OpCode::SysCallPlaceOrder {
        pair_id: PAIR_STELL_USDT,
        is_buy: false,
        price: 250_000,
        amount: 1_000,
    }];
    let tx = pq_tx(&fk, from, [0u8; 32], 0, 10_000_000, 0, payload);
    engine
        .apply_transaction(&tx, 0)
        .await
        .expect("order placement must work");

    let books = engine.orderbooks_read().await;
    let book = books.get_book(PAIR_STELL_USDT).expect("book exists");
    let (_, ask) = book.get_best_bid_ask();
    assert_eq!(ask, Some(250_000), "resting ask must be in consensus state");
}

#[test]
fn payload_is_bound_into_the_signature() {
    let (from, fk) = pq_owner(0x64);
    let mut tx = pq_tx(
        &fk,
        from,
        [1u8; 32],
        0,
        100_000,
        0,
        vec![OpCode::Push(1), OpCode::Halt],
    );
    assert!(tx.verify_signature());
    tx.payload = vec![OpCode::Push(2), OpCode::Halt];
    assert!(
        !tx.verify_signature(),
        "tampered payload must fail verification"
    );
}

#[tokio::test]
async fn block_execution_runs_payloads_and_conserves_native_value() {
    let (from, fk) = pq_owner(0x65);
    let to = [5u8; 32];
    let engine = funded_engine(from, 1_000_000).await;

    let payload = vec![OpCode::Push(42), OpCode::Halt];
    let tx = pq_tx(&fk, from, to, 1_000, 560, 0, payload);
    let (applied, failed) = engine.apply_block_parallel(&[tx], 0).await;
    assert_eq!((applied, failed), (1, 0));

    let sender = engine.get_account(&from).await.unwrap();
    let recipient = engine.get_account(&to).await.unwrap();
    assert_eq!(sender.balance, 1_000_000 - 1_000 - 560);
    assert_eq!(recipient.balance, 1_000);
}
