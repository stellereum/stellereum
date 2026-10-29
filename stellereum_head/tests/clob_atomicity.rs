//! CLOB atomicity follow-ups (review of the B1 fix).
//!
//! HOLES. `execute_payload` settles the CLOB value side live
//! (`settle_clob_effects`: native moves on the accounts map + trie, wUSDT
//! Transfer/Mint/Burn on the token registry, escrow + book commits) and the
//! caller (`apply_transaction` / `apply_block_parallel_fees`) can still refuse
//! the transaction AFTER that — here via a `commit_native` recipient overflow
//! the settlement never checks. Before the follow-up fixes that left:
//!
//!  1. token effects behind: `snapshot_payload_domains` did not snapshot the
//!     token registry for `SysCallPlaceOrder | SysCallCancelOrder`, so
//!     `rollback_payload` restored nothing token-side (a wUSDT mint survived);
//!  2. native effects behind: Phase 2 `apply_native_moves` wrote the accounts
//!     map + trie with no undo record, so a later refusal kept the moved coins.
//!
//! FIX: the opcode gate snapshots tokens for order syscalls, and the CLOB leg
//! returns a pre-move snapshot (`None` = account did not exist, mirroring
//! `commit_native`) threaded through `ExecPostActions` into `rollback_payload`
//! on the commit-failure path of BOTH callers.
//!
//! These tests pin the FIXED behavior: a taker SELL that fills against a
//! wUSDT-escrowed maker BUY mints wUSDT and moves base, then the enclosing
//! transaction is refused by `commit_native` (recipient overflow). Nothing
//! survives: no mint, no moved coins, no escrow/book change.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

const STELL: u64 = 1_000_000_000;
const PRICE: u64 = 250_000; // $0.25
const PAIR: u32 = 1;

/// wUSDT quote value of `base_nano` nano-STELL at `price_micro` (the
/// `place_order_settled` convention the maker leg locks under).
fn quote_wusdt(price: u64, base_nano: u64) -> u64 {
    ((price as u128) * (base_nano as u128) / 1_000_000_000u128) as u64
}

async fn setup() -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let minter = [0x11u8; 32];
    let meta = TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter,
        paused: false,
        description: String::new(),
    };
    let usdt = engine.create_token(minter, meta, 0).await.unwrap();
    *engine.pmm_usdt_token_write().await = Some(usdt);
    (engine, usdt)
}

/// Maker rests a BUY escrowed in wUSDT; returns (maker key, order id,
/// locked quote, maker native before, maker wusdt before).
async fn rest_maker_buy(
    engine: &InMemoryStateEngine,
    usdt: &[u8; 32],
    amount: u64,
) -> (SigningKey, u64) {
    let maker = SigningKey::generate(&mut OsRng);
    let maker_addr = maker.verifying_key().to_bytes();
    let q = quote_wusdt(PRICE, amount);
    engine
        .update_account(AccountState::new(maker_addr, 5 * STELL))
        .await;
    engine
        .token_execute(
            usdt,
            [0x11u8; 32],
            stellereum::token::TokenOp::Mint { to: maker_addr, amount: 10_000_000 },
        )
        .await
        .unwrap();
    let (order_id, fills) = engine
        .place_order_settled(PAIR, maker_addr, OrderSide::Buy, OrderType::Limit, PRICE, amount, 100)
        .await
        .unwrap();
    assert_eq!(fills, 0);
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR, order_id))
            .map(|r| r.locked_quote_wusdt),
        Some(q),
        "the maker buy locks its quote in wUSDT"
    );
    (maker, order_id)
}

/// A taker SELL that fills the maker's buy, wrapped so `commit_native`
/// overflows crediting `overflow_to` and refuses the whole transaction.
fn doomed_taker_sell(
    taker: &SigningKey,
    overflow_to: [u8; 32],
    amount: u64,
) -> stellereum::sharding::Transaction {
    stellereum::sharding::Transaction::sign_with_payload(
        taker,
        overflow_to,
        1_000, // tiny transfer that overflows the recipient
        100_000,
        0,
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR,
            is_buy: false,
            price: PRICE,
            amount,
        }],
    )
}

#[tokio::test]
async fn clob_fill_rolls_back_when_the_native_commit_fails() {
    let (engine, usdt) = setup().await;
    let amount = 2 * STELL;
    let q = quote_wusdt(PRICE, amount);
    let (maker, order_id) = rest_maker_buy(&engine, &usdt, amount).await;
    let maker_addr = maker.verifying_key().to_bytes();

    let taker = SigningKey::generate(&mut OsRng);
    let taker_addr = taker.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(taker_addr, 10 * STELL))
        .await;

    // A recipient so full the 1,000-nano transfer cannot land.
    let overflow_to = [0xFFu8; 32];
    engine
        .update_account(AccountState::new(overflow_to, u64::MAX - 50))
        .await;

    let taker_native0 = engine.get_account(&taker_addr).await.unwrap().balance;
    let maker_native0 = engine.get_account(&maker_addr).await.unwrap().balance;
    let taker_wusdt0 = engine.token_balance(&usdt, &taker_addr).await;
    let maker_wusdt0 = engine.token_balance(&usdt, &maker_addr).await;
    let supply0 = engine.token_total_supply(&usdt).await;
    let escrow0 = engine.order_escrow_read().await.clone();
    let books0 = {
        let snap = engine.commitment_snapshot().await;
        let mut v: Vec<(u32, Vec<u8>)> = snap
            .orderbooks
            .books
            .iter()
            .map(|(pair, book)| (*pair, bincode::serialize(book).unwrap()))
            .collect();
        v.sort();
        v
    };
    let overflow0 = engine.get_account(&overflow_to).await.unwrap().balance;

    let tx = doomed_taker_sell(&taker, overflow_to, amount);
    let res = engine.apply_transaction(&tx, 200).await;
    assert!(res.is_err(), "commit_native must refuse the overflow: {res:?}");

    // Native: nobody paid, nobody was paid.
    assert_eq!(
        engine.get_account(&taker_addr).await.unwrap().balance,
        taker_native0,
        "FIXED(2): the taker's base debit did not survive the refusal"
    );
    assert_eq!(
        engine.get_account(&maker_addr).await.unwrap().balance,
        maker_native0,
        "FIXED(2): the maker's base credit did not survive the refusal"
    );
    assert_eq!(
        engine.get_account(&overflow_to).await.unwrap().balance,
        overflow0,
        "the overflowed credit landed nowhere"
    );
    // Tokens: the fill's wUSDT mint is gone (needs the order-syscall token
    // snapshot) and the supply is back.
    assert_eq!(
        engine.token_balance(&usdt, &taker_addr).await,
        taker_wusdt0,
        "FIXED(1): no wUSDT mint from a refused transaction"
    );
    assert_eq!(
        engine.token_balance(&usdt, &maker_addr).await,
        maker_wusdt0,
        "the maker's escrowed quote is untouched"
    );
    assert_eq!(
        engine.token_total_supply(&usdt).await,
        supply0,
        "supply unchanged (mint rolled back, burn never re-applied)"
    );
    // Escrow + book: the maker's order still rests, fully collateralised.
    assert_eq!(
        *engine.order_escrow_read().await,
        escrow0,
        "the escrow record survived with its lock intact"
    );
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR, order_id))
            .map(|r| r.locked_quote_wusdt),
        Some(q),
        "the maker's wUSDT lock is whole"
    );
    assert_eq!(
        {
            let snap = engine.commitment_snapshot().await;
            let mut v: Vec<(u32, Vec<u8>)> = snap
                .orderbooks
                .books
                .iter()
                .map(|(pair, book)| (*pair, bincode::serialize(book).unwrap()))
                .collect();
            v.sort();
            v
        },
        books0,
        "the book is byte-identical: the fill never happened"
    );
    assert_eq!(
        engine.get_account(&taker_addr).await.unwrap().nonce, 0,
        "a refused transaction consumes no nonce"
    );
}

#[tokio::test]
async fn clob_fill_rolls_back_on_the_block_path_when_the_native_commit_fails() {
    let (engine, usdt) = setup().await;
    let amount = 2 * STELL;
    let (maker, _) = rest_maker_buy(&engine, &usdt, amount).await;
    let maker_addr = maker.verifying_key().to_bytes();

    let taker = SigningKey::generate(&mut OsRng);
    let taker_addr = taker.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(taker_addr, 10 * STELL))
        .await;
    let overflow_to = [0xFEu8; 32];
    engine
        .update_account(AccountState::new(overflow_to, u64::MAX - 50))
        .await;

    let taker_native0 = engine.get_account(&taker_addr).await.unwrap().balance;
    let supply0 = engine.token_total_supply(&usdt).await;
    let escrow0 = engine.order_escrow_read().await.clone();

    let tx = doomed_taker_sell(&taker, overflow_to, amount);
    let (applied, failed, _fees, status, fees) =
        engine.apply_block_parallel_fees(std::slice::from_ref(&tx), 200).await;
    assert_eq!((applied, failed), (0, 1), "the block path refuses the tx");
    assert_eq!(status, vec![false]);
    assert_eq!(fees, vec![0], "a refused transaction is charged no fee");

    assert_eq!(
        engine.get_account(&taker_addr).await.unwrap().balance,
        taker_native0,
        "FIXED(2): block path keeps no CLOB coins either"
    );
    assert_eq!(
        engine.token_balance(&usdt, &taker_addr).await,
        0,
        "FIXED(1): block path keeps no CLOB mint either"
    );
    assert_eq!(engine.token_total_supply(&usdt).await, supply0);
    assert_eq!(*engine.order_escrow_read().await, escrow0);
    assert_eq!(
        engine.get_account(&maker_addr).await.unwrap().nonce, 0,
        "the maker never moved"
    );
}
