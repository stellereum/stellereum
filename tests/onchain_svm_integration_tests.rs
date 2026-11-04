//! End-to-end tests proving the SVM / token / orderbook are actually executed
//! as part of block application (on-chain), not just as a standalone library.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::orderbook::PAIR_STELL_USDT;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

async fn funded_engine(owner: [u8; 32], balance: u64) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.update_account(AccountState::new(owner, balance)).await;
    e
}

#[tokio::test]
async fn token_syscall_in_payload_is_applied_on_chain() {
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
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
    let tx = Transaction::sign_with_payload(&sk, [0u8; 32], 0, 300_000, 0, 1, 1, payload);

    engine
        .apply_transaction(&tx, 0)
        .await
        .expect("payload must execute");

    assert_eq!(engine.token_balance(&token_id, &from).await, 600);
    assert_eq!(engine.token_balance(&token_id, &to).await, 400);
}

#[tokio::test]
async fn reverting_payload_does_not_move_native_balance() {
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let engine = funded_engine(from, 1_000_000).await;

    let missing = [0xAB; 32];
    let payload = vec![OpCode::SysCallTokenTransfer {
        token_id: missing,
        to: [7u8; 32],
        amount: 1,
    }];
    let tx = Transaction::sign_with_payload(&sk, [9u8; 32], 5_000, 100_000, 0, 1, 1, payload);

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
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let engine = funded_engine(from, 10_000_000_000).await;

    let payload = vec![OpCode::SysCallPlaceOrder {
        pair_id: PAIR_STELL_USDT,
        is_buy: false,
        price: 250_000,
        amount: 1_000,
    }];
    let tx = Transaction::sign_with_payload(&sk, [0u8; 32], 0, 10_000_000, 0, 1, 1, payload);
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
    let sk = SigningKey::generate(&mut OsRng);
    let mut tx = Transaction::sign_with_payload(
        &sk,
        [1u8; 32],
        0,
        100_000,
        0,
        1,
        1,
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
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let to = [5u8; 32];
    let engine = funded_engine(from, 1_000_000).await;

    let payload = vec![OpCode::Push(42), OpCode::Halt];
    let tx = Transaction::sign_with_payload(&sk, to, 1_000, 560, 0, 1, 1, payload);
    let (applied, failed) = engine.apply_block_parallel(&[tx], 0).await;
    assert_eq!((applied, failed), (1, 0));

    let sender = engine.get_account(&from).await.unwrap();
    let recipient = engine.get_account(&to).await.unwrap();
    assert_eq!(sender.balance, 1_000_000 - 1_000 - 560);
    assert_eq!(recipient.balance, 1_000);
}
