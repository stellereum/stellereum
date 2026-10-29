//! On-chain CLOB settlement on the LIVE path:
//!
//!  * `apply_transaction` (the single-transaction API) and
//!    `apply_block_parallel_fees` (what the consensus loop calls) must reach
//!    the SAME settlement - same book, same escrow, same balances, same state
//!    root - because both go through `execute_payload` -> `settle_clob_effects`
//!    -> `commit_native`;
//!  * `ctx.timestamp`, plumbed from `block.timestamp`, must stamp the order and
//!    decide TIME priority in a price level (it used to be a dead 0, so two
//!    orders at the same price matched in bare insertion order).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::commitment::commitment_digest;
use stellereum::orderbook::{OrderSide, OrderType, PAIR_STELL_USDT};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

const STELL: u64 = 1_000_000_000;
const PRICE: u64 = 250_000; // $0.25

fn native_quote(price: u64, amount: u64) -> u64 {
    price.saturating_mul(amount) / 1_000_000
}

fn buy_tx(key: &SigningKey, nonce: u64, gas_limit: u64, amount: u64) -> Transaction {
    let from = key.verifying_key().to_bytes();
    Transaction::sign_with_payload(
        key,
        from,
        0,
        gas_limit,
        nonce,
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_USDT,
            is_buy: true,
            price: PRICE,
            amount,
        }],
    )
}

/// Build the SAME starting state twice: a maker with 100 STELL resting a
/// 10 STELL sell, a taker with 10 STELL, one wUSDT token. Deterministic, so
/// two engines can be compared byte for byte.
async fn base_engine(seller: &SigningKey, taker: &SigningKey) -> InMemoryStateEngine {
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

    let s = seller.verifying_key().to_bytes();
    let t = taker.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(s, 100 * STELL))
        .await;
    engine
        .update_account(AccountState::new(t, 10 * STELL))
        .await;
    engine
}

/// The shared start, plus the maker's 10 STELL resting sell.
async fn build(seller: &SigningKey, taker: &SigningKey) -> InMemoryStateEngine {
    let engine = base_engine(seller, taker).await;
    let s = seller.verifying_key().to_bytes();
    engine
        .place_order_settled(
            PAIR_STELL_USDT,
            s,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            10 * STELL,
            1,
        )
        .await
        .unwrap();
    engine
}

/// Deterministic dump of the book: sorted by pair, each actor serialized (its
/// bids/asks are `BTreeMap`s, so the bytes are a function of the content only).
async fn books_bytes(e: &InMemoryStateEngine) -> Vec<(u32, Vec<u8>)> {
    let snap = e.commitment_snapshot().await;
    let mut v: Vec<(u32, Vec<u8>)> = snap
        .orderbooks
        .books
        .iter()
        .map(|(pair, book)| (*pair, bincode::serialize(book).unwrap()))
        .collect();
    v.sort();
    v
}

/// Deterministic dump of the escrow map, sorted by (pair, order id).
async fn escrow_bytes(e: &InMemoryStateEngine) -> Vec<((u32, u64), Vec<u8>)> {
    let snap = e.commitment_snapshot().await;
    let mut v: Vec<((u32, u64), Vec<u8>)> = snap
        .order_escrow
        .iter()
        .map(|(key, rec)| (*key, bincode::serialize(rec).unwrap()))
        .collect();
    v.sort();
    v
}

/// The whole point of sharing `execute_payload` + `commit_native`: with the
/// declared gas limit equal to what the payload consumes (the only documented
/// divergence between the two callers), the two paths produce the SAME state
/// root, not merely "equivalent" state.
#[tokio::test]
async fn both_apply_paths_reach_the_identical_state_root() {
    let seller = SigningKey::generate(&mut OsRng);
    let taker = SigningKey::generate(&mut OsRng);
    let a = build(&seller, &taker).await;
    let b = build(&seller, &taker).await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "the two engines start identical"
    );

    // GAS_ORDER_PLACE + one crossed level: exactly what this payload consumes,
    // so the single-tx path (charges what was used) and the block path (charges
    // the declared limit) charge the same fee.
    let gas = stellereum::svm::GAS_ORDER_PLACE + stellereum::svm::GAS_PER_MATCH_LEVEL;
    let tx = buy_tx(&taker, 0, gas, 4 * STELL);

    a.apply_transaction(&tx, 42)
        .await
        .expect("single-tx path applies");
    let (applied, failed, fees, status, _) = b
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 42)
        .await;
    assert_eq!((applied, failed), (1, 0), "the block path applies it too");
    assert_eq!(fees, gas, "the block path collects the declared limit");
    assert_eq!(status, vec![true]);

    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "IDENTICAL STATE ROOT: same book, same escrow, same balances, same fees"
    );

    assert_eq!(
        commitment_digest(&a.commitment_snapshot().await),
        commitment_digest(&b.commitment_snapshot().await),
        "same commitment digest (books, escrow, tokens, staking, PMM, contracts)"
    );
    assert_eq!(
        books_bytes(&a).await,
        books_bytes(&b).await,
        "same book bytes"
    );
    assert_eq!(
        escrow_bytes(&a).await,
        escrow_bytes(&b).await,
        "same escrow bytes"
    );

    let s = seller.verifying_key().to_bytes();
    let t = taker.verifying_key().to_bytes();
    for e in [&a, &b] {
        // The maker was paid 1 STELL of quote for 4 STELL sold.
        assert_eq!(
            e.get_account(&s).await.unwrap().balance,
            90 * STELL + native_quote(PRICE, 4 * STELL)
        );
        // The taker paid the quote and received the collateral.
        assert_eq!(
            e.get_account(&t).await.unwrap().balance,
            10 * STELL - native_quote(PRICE, 4 * STELL) + 4 * STELL - gas
        );
        // The 6 STELL that never traded are still locked.
        assert_eq!(
            e.order_escrow_read()
                .await
                .get(&(PAIR_STELL_USDT, 1))
                .unwrap()
                .locked_base_stell,
            6 * STELL
        );
    }
}

/// The documented fee divergence (single-tx charges what was consumed, blocks
/// charge the declared limit) must be the ONLY thing that differs. The
/// settlement itself - book, escrow, tokens, the maker's balance, the whole
/// commitment digest - is identical, and the taker differs by exactly the fee
/// delta.
#[tokio::test]
async fn settlement_is_identical_even_when_the_fee_number_differs() {
    let seller = SigningKey::generate(&mut OsRng);
    let taker = SigningKey::generate(&mut OsRng);
    let a = build(&seller, &taker).await;
    let b = build(&seller, &taker).await;

    let gas_used = stellereum::svm::GAS_ORDER_PLACE + stellereum::svm::GAS_PER_MATCH_LEVEL;
    let declared = 50_000u64; // declared >> consumed
    assert!(declared > gas_used);
    let tx = buy_tx(&taker, 0, declared, 4 * STELL);

    a.apply_transaction(&tx, 7).await.expect("single-tx path");
    let (applied, failed, fees, _, _) = b.apply_block_parallel_fees(&[tx], 7).await;
    assert_eq!((applied, failed, fees), (1, 0, declared));

    // Everything except the fee is the same.
    assert_eq!(
        books_bytes(&a).await,
        books_bytes(&b).await,
        "the fill landed in the same book"
    );
    assert_eq!(
        escrow_bytes(&a).await,
        escrow_bytes(&b).await,
        "the same escrow was released"
    );
    let da = commitment_digest(&a.commitment_snapshot().await);
    let db = commitment_digest(&b.commitment_snapshot().await);
    assert_eq!(da, db, "THE SETTLEMENT OUTCOME IS IDENTICAL");

    let s = seller.verifying_key().to_bytes();
    let t = taker.verifying_key().to_bytes();
    let bal_a = a.get_account(&s).await.unwrap().balance;
    let bal_b = b.get_account(&s).await.unwrap().balance;
    assert_eq!(bal_a, bal_b, "the maker does not care which path settled");

    let taker_a = a.get_account(&t).await.unwrap().balance;
    let taker_b = b.get_account(&t).await.unwrap().balance;
    assert_eq!(
        taker_a - taker_b,
        declared - gas_used,
        "the taker differs by EXACTLY the fee divergence, nothing else"
    );
}

/// `ctx.timestamp` comes from `block.timestamp` and stamps the order, and a
/// price level is ordered by TIME, not by raw insertion order: an order stamped
/// earlier is filled first even when it was inserted later.
#[tokio::test]
async fn block_timestamp_stamps_orders_and_decides_time_priority() {
    let seller = SigningKey::generate(&mut OsRng);
    let taker = SigningKey::generate(&mut OsRng);
    // No maker order from `build` here: this test owns the whole PRICE level.
    let engine = base_engine(&seller, &taker).await;
    let s = seller.verifying_key().to_bytes();

    // 1) The stamp on a resting order placed through the CLOB API is `now`.
    let oid_500 = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            s,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            2 * STELL,
            500,
        )
        .await
        .unwrap()
        .0;
    // 2) ...and one placed through the VM is the BLOCK timestamp, not 0.
    let bot = SigningKey::generate(&mut OsRng);
    let bot_addr = bot.verifying_key().to_bytes();
    let gas = stellereum::svm::GAS_ORDER_PLACE;
    // A SELL locks its `amount` (base), not the quote: fund the base + the fee.
    engine
        .update_account(AccountState::new(bot_addr, 2 * STELL + gas))
        .await;
    engine
        .apply_transaction(
            &Transaction::sign_with_payload(
                &bot,
                bot_addr,
                0,
                gas,
                0,
                1,
                1,
                vec![OpCode::SysCallPlaceOrder {
                    pair_id: PAIR_STELL_USDT,
                    is_buy: false,
                    price: PRICE + 1_000,
                    amount: 2 * STELL,
                }],
            ),
            4_242,
        )
        .await
        .expect("resting ask");
    let stamped = engine
        .orderbooks_read()
        .await
        .books
        .get(&PAIR_STELL_USDT)
        .unwrap()
        .asks
        .values()
        .flatten()
        .find(|o| o.trader == bot_addr)
        .map(|o| o.timestamp)
        .expect("the bot's ask rests");
    assert_eq!(
        stamped, 4_242,
        "ctx.timestamp is the block timestamp, not a dead 0"
    );

    // 3) TIME PRIORITY. The FIRST order inserted into the level is stamped 500;
    //    the second one, inserted afterwards, is stamped 400 - earlier, so it
    //    has priority. A cross must therefore fill the stamp-400 order first.
    let oid_400 = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            s,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            2 * STELL,
            400,
        )
        .await
        .unwrap()
        .0;
    assert_ne!(oid_400, oid_500);
    let level = engine
        .orderbooks_read()
        .await
        .books
        .get(&PAIR_STELL_USDT)
        .unwrap()
        .asks
        .get(&PRICE)
        .cloned()
        .expect("one price level");
    let stamps: Vec<u64> = level.iter().map(|o| o.timestamp).collect();
    assert_eq!(stamps, vec![400, 500], "time priority, not insertion order");

    // The taker takes the whole level: 2 STELL from the stamp-400 order.
    let fill_gas = stellereum::svm::GAS_ORDER_PLACE + stellereum::svm::GAS_PER_MATCH_LEVEL;
    engine
        .update_account(AccountState::new(
            taker.verifying_key().to_bytes(),
            10 * STELL,
        ))
        .await;
    let taker_addr = taker.verifying_key().to_bytes();
    engine
        .apply_transaction(
            &Transaction::sign_with_payload(
                &taker,
                taker_addr,
                0,
                fill_gas,
                0,
                1,
                1,
                vec![OpCode::SysCallPlaceOrder {
                    pair_id: PAIR_STELL_USDT,
                    is_buy: true,
                    price: PRICE,
                    amount: 2 * STELL,
                }],
            ),
            4_243,
        )
        .await
        .expect("cross");

    let level = engine
        .orderbooks_read()
        .await
        .books
        .get(&PAIR_STELL_USDT)
        .unwrap()
        .asks
        .get(&PRICE)
        .cloned()
        .expect("the later-stamped order must survive");
    assert_eq!(
        level.iter().map(|o| o.timestamp).collect::<Vec<_>>(),
        vec![500],
        "the stamp-400 order was filled first and is gone"
    );
    assert_eq!(
        level[0].filled, 0,
        "the stamp-500 order was not touched at all"
    );

    // ...and its escrow was released while the survivor's (and the untouched
    // far-side ask) are still intact.
    let escrow = engine.order_escrow_read().await.clone();
    assert!(
        !escrow.contains_key(&(PAIR_STELL_USDT, oid_400)),
        "the filled order's escrow was released with it"
    );
    let survivor = escrow
        .get(&(PAIR_STELL_USDT, oid_500))
        .expect("the survivor still locked");
    assert_eq!(survivor.locked_base_stell, 2 * STELL);
    assert_eq!(
        survivor.locked_quote_wusdt + survivor.locked_quote_native,
        0
    );
    assert_eq!(
        escrow
            .values()
            .filter(|r| r.locked_base_stell == 2 * STELL)
            .count(),
        2,
        "the survivor plus the bot's untouched ask"
    );
}
