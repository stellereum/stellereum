//! F2 one-call order placement: `stell_placeOrder` / `stell_cancelOrder`.
//!
//! The prepare surface validates against committed state (pair exists,
//! price/amount sane, escrow lock fundable, cancel ownership) and answers
//! with the signable transaction WITHOUT mutating anything; the settled path
//! (`place_order_settled` / `cancel_order_settled`, i.e. what the block does
//! with the signed transaction) locks and releases the escrow. These tests
//! pin both halves:
//!
//! * place -> the order rests in the book with its escrow locked;
//! * cancel -> the escrow is released and the order is gone;
//! * cancel by a non-owner is refused (settled AND prepare);
//! * a placement the trader cannot fund is refused (settled AND prepare);
//! * an unknown pair is refused at prepare time (`-32004`);
//! * the prepares mutate nothing (same rule as the native-API namespace).

use serde_json::json;
use stellereum::native_api::dispatch;
use stellereum::orderbook::{OrderSide, OrderType, PAIR_STELL_USDT};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const STELL: u64 = 1_000_000_000;
const PRICE: u64 = 250_000; // $0.25 in micro-USD

fn trader(n: u8) -> [u8; 32] {
    [n; 32]
}

async fn engine_with_seller() -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let seller = trader(0xA1);
    engine
        .update_account(AccountState::new(seller, 100 * STELL))
        .await;
    // `place_order_settled` resolves the quote token up front (even for a
    // pure native sell), so the test engine wires a wUSDT token the same way
    // the settlement tests do.
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
    let usdt = engine.create_token(trader(0x11), meta, 0).await.unwrap();
    *engine.pmm_usdt_token_write().await = Some(usdt);
    (engine, seller)
}

async fn snapshot_version(engine: &InMemoryStateEngine) -> u64 {
    dispatch(engine, "stell_orderBookSnapshot", &json!({ "pair": 1 }))
        .await
        .unwrap()["version"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn place_rests_in_book_with_escrow_locked() {
    let (engine, seller) = engine_with_seller().await;

    let (order_id, trades) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            4 * STELL,
            1,
        )
        .await
        .unwrap();
    assert_eq!(order_id, 1);
    assert_eq!(trades, 0, "no counterparty yet -> rests");

    // The order is visible in the committed book ...
    let books = engine.orderbooks_read().await;
    let resting = books
        .get_book(PAIR_STELL_USDT)
        .unwrap()
        .find_order(order_id)
        .cloned();
    drop(books);
    let resting = resting.expect("the placed order must rest in the book");
    assert_eq!(resting.trader, seller);
    assert_eq!(resting.amount, 4 * STELL);

    // ... with its base escrow locked (96 live, 4 locked) ...
    let locked = engine
        .order_escrow_read()
        .await
        .get(&(PAIR_STELL_USDT, order_id))
        .unwrap()
        .locked_base_stell;
    assert_eq!(locked, 4 * STELL, "a resting sell locks its base STELL");
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        96 * STELL
    );

    // ... and the snapshot sequence moved exactly once.
    assert_eq!(snapshot_version(&engine).await, 1);
}

#[tokio::test]
async fn cancel_releases_escrow_and_removes_the_order() {
    let (engine, seller) = engine_with_seller().await;
    let (order_id, _) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            4 * STELL,
            1,
        )
        .await
        .unwrap();

    let cancelled = engine
        .cancel_order_settled(PAIR_STELL_USDT, order_id, seller)
        .await
        .unwrap();
    assert!(cancelled.is_some(), "owner cancel removes the order");

    // Gone from the book, escrow released, funds back.
    let books = engine.orderbooks_read().await;
    assert!(books
        .get_book(PAIR_STELL_USDT)
        .unwrap()
        .find_order(order_id)
        .is_none());
    drop(books);
    assert!(engine
        .order_escrow_read()
        .await
        .get(&(PAIR_STELL_USDT, order_id))
        .is_none());
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        100 * STELL,
        "cancel refunds the locked base"
    );

    // Placement + cancellation = two book mutations.
    assert_eq!(snapshot_version(&engine).await, 2);
}

#[tokio::test]
async fn cancel_by_a_non_owner_is_refused_and_keeps_escrow() {
    let (engine, seller) = engine_with_seller().await;
    let (order_id, _) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            4 * STELL,
            1,
        )
        .await
        .unwrap();

    // Settled path: anyone but the owner is refused ...
    let stranger = trader(0xE0);
    let res = engine
        .cancel_order_settled(PAIR_STELL_USDT, order_id, stranger)
        .await;
    assert!(res.is_err(), "a non-owner cancel must be refused");

    // ... and the prepare is refused with `-32003` before anything is signed.
    let err = dispatch(
        &engine,
        "stell_cancelOrder",
        &json!({ "order_id": order_id, "trader": hex::encode(stranger) }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), -32003);

    // The victim's order and escrow are untouched.
    let books = engine.orderbooks_read().await;
    assert!(books
        .get_book(PAIR_STELL_USDT)
        .unwrap()
        .find_order(order_id)
        .is_some());
    drop(books);
    assert!(engine
        .order_escrow_read()
        .await
        .get(&(PAIR_STELL_USDT, order_id))
        .is_some());
}

#[tokio::test]
async fn place_without_balance_is_refused() {
    // The wired engine (quote token configured) isolates the failure to the
    // funding check rather than the token wiring.
    let (engine, _) = engine_with_seller().await;
    let poor = trader(0xB0);

    // Settled path cannot fund the base lock ...
    let res = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            poor,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            4 * STELL,
            1,
        )
        .await;
    assert!(res.is_err(), "an unfunded seller must be refused");

    // ... and the one-call prepare refuses with `-32003` before signing.
    let err = dispatch(
        &engine,
        "stell_placeOrder",
        &json!({
            "pair": PAIR_STELL_USDT,
            "side": "sell",
            "price": PRICE.to_string(),
            "amount": (4 * STELL).to_string(),
            "trader": hex::encode(poor),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), -32003);
}

#[tokio::test]
async fn place_with_a_bad_pair_is_refused() {
    let (engine, seller) = engine_with_seller().await;
    for method in ["stell_placeOrder", "stell_orderBookPlace"] {
        let err = dispatch(
            &engine,
            method,
            &json!({
                "pair": 4242,
                "side": "buy",
                "price": "250000",
                "amount": "10",
                "trader": hex::encode(seller),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004, "{method} must refuse a bad pair");
    }
}

#[tokio::test]
async fn market_order_type_is_refused_not_silently_downgraded() {
    let (engine, seller) = engine_with_seller().await;
    let err = dispatch(
        &engine,
        "stell_placeOrder",
        &json!({
            "pair": PAIR_STELL_USDT,
            "side": "buy",
            "price": "250000",
            "amount": "10",
            "order_type": "market",
            "trader": hex::encode(seller),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), -32003);
}

#[tokio::test]
async fn prepares_mutate_nothing() {
    let (engine, seller) = engine_with_seller().await;

    // A prepare for a funded trader succeeds ...
    let v = dispatch(
        &engine,
        "stell_placeOrder",
        &json!({
            "pair": PAIR_STELL_USDT,
            "side": "sell",
            "price": PRICE.to_string(),
            "amount": (4 * STELL).to_string(),
            "trader": hex::encode(seller),
        }),
    )
    .await
    .unwrap();
    assert_eq!(v["action"], "place_order");
    assert_eq!(v["transaction"]["op"], "SysCallPlaceOrder");
    assert_eq!(v["submit_with"], "stell_sendRawTransaction");

    // ... but the book, the escrow and the snapshot sequence are untouched:
    // the state moves only when the SIGNED transaction lands in a block.
    let books = engine.orderbooks_read().await;
    assert!(books
        .get_book(PAIR_STELL_USDT)
        .unwrap()
        .find_order(1)
        .is_none());
    assert_eq!(books.get_book(PAIR_STELL_USDT).unwrap().version, 0);
    drop(books);
    assert!(engine.order_escrow_read().await.is_empty());
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        100 * STELL
    );
}
