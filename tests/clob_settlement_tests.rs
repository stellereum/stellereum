//! A7: the native CLOB actually settles matched trades against real balances
//! (native STELL base, wUSDT quote), all-or-nothing.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::orderbook::{OrderSide, OrderType, PAIR_STELL_USDT};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::token::{TokenMetadata, TokenOp};

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

const STELL: u64 = 1_000_000_000;

/// The committed-domain digest the trie holds: it folds tokens, orderbooks,
/// the escrow, the oracle and every other committed subsystem, so it is the
/// one value that says "nothing but the accounts changed".
async fn committed_digest(engine: &InMemoryStateEngine) -> Vec<u8> {
    engine
        .state_trie
        .read()
        .await
        .get(&stellereum::commitment::commitment_key())
        .expect("the commitment digest must be written into the trie")
        .to_vec()
}

async fn setup() -> (InMemoryStateEngine, [u8; 32], [u8; 32], [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let minter = [0x11u8; 32];
    let seller = [0xA1u8; 32];
    let buyer = [0xB2u8; 32];

    // wUSDT token + PMM quote wiring.
    let meta = TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let usdt = engine.create_token(minter, meta, 0).await.unwrap();
    engine
        .token_execute(
            &usdt,
            minter,
            TokenOp::Mint {
                to: buyer,
                amount: 10_000_000,
            },
        )
        .await
        .unwrap();
    *engine.pmm_usdt_token_write().await = Some(usdt);

    // Seller holds native STELL.
    engine
        .update_account(AccountState::new(seller, 100 * STELL))
        .await;
    engine.update_account(AccountState::new(buyer, 0)).await;
    (engine, seller, buyer, usdt)
}

#[tokio::test]
async fn matched_trade_moves_stell_and_wusdt_between_parties() {
    let (engine, seller, buyer, usdt) = setup().await;

    // Seller rests a sell: 4 STELL @ $0.25.
    let (_, trades) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            250_000,
            4 * STELL,
            1,
        )
        .await
        .unwrap();
    assert_eq!(trades, 0, "no counterparty yet -> rests");

    // Buyer crosses: 4 STELL @ $0.25 => pays 1.00 wUSDT.
    let (_, trades) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            buyer,
            OrderSide::Buy,
            OrderType::Limit,
            250_000,
            4 * STELL,
            2,
        )
        .await
        .unwrap();
    assert_eq!(trades, 1, "one match must settle");

    let seller_native = engine.get_account(&seller).await.unwrap().balance;
    let buyer_native = engine.get_account(&buyer).await.unwrap().balance;
    assert_eq!(seller_native, 96 * STELL, "seller paid 4 STELL");
    assert_eq!(buyer_native, 4 * STELL, "buyer received 4 STELL");

    assert_eq!(
        engine.token_balance(&usdt, &seller).await,
        1_000_000,
        "seller received 1.00 wUSDT"
    );
    assert_eq!(
        engine.token_balance(&usdt, &buyer).await,
        9_000_000,
        "buyer paid 1.00 wUSDT"
    );
}

#[tokio::test]
async fn unfunded_counterparty_aborts_settlement_without_state_change() {
    let (engine, seller, buyer, usdt) = setup().await;
    // Drain the buyer's wUSDT so it cannot pay.
    let bal = engine.token_balance(&usdt, &buyer).await;
    engine
        .token_execute(
            &usdt,
            buyer,
            TokenOp::Burn {
                from: buyer,
                amount: bal,
            },
        )
        .await
        .unwrap();

    engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            250_000,
            4 * STELL,
            1,
        )
        .await
        .unwrap();

    let res = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            buyer,
            OrderSide::Buy,
            OrderType::Limit,
            250_000,
            4 * STELL,
            2,
        )
        .await;
    assert!(res.is_err(), "buyer without wUSDT must not settle");

    // Seller's order is still resting in escrow (4 STELL locked, 96 live):
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        96 * STELL
    );
    assert_eq!(engine.get_account(&buyer).await.unwrap().balance, 0);
    assert_eq!(engine.token_balance(&usdt, &buyer).await, 0);

    // Canceling refunds the 4 STELL back to 100 STELL:
    engine
        .cancel_order_settled(PAIR_STELL_USDT, 1, seller)
        .await
        .unwrap();
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        100 * STELL
    );
}

#[tokio::test]
async fn self_trade_is_skipped_and_never_partially_settles() {
    let (engine, who, _, usdt) = setup().await;
    engine
        .update_account(AccountState::new(who, 100 * STELL))
        .await;

    // Same address rests a sell and then buys it: a self-trade nets to zero and
    // must not move any funds or error mid-settlement.
    engine
        .place_order_settled(
            PAIR_STELL_USDT,
            who,
            OrderSide::Sell,
            OrderType::Limit,
            250_000,
            4 * STELL,
            1,
        )
        .await
        .unwrap();
    let (_, trades) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            who,
            OrderSide::Buy,
            OrderType::Limit,
            250_000,
            4 * STELL,
            2,
        )
        .await
        .unwrap();
    assert_eq!(trades, 1, "sides crossed");
    assert_eq!(
        engine.get_account(&who).await.unwrap().balance,
        100 * STELL,
        "self-trade nets to zero"
    );
    assert_eq!(
        engine.token_balance(&usdt, &who).await,
        0,
        "wUSDT unchanged"
    );
}

#[tokio::test]
async fn dust_quote_rejected_before_any_settlement() {
    let (engine, seller, buyer, _) = setup().await;
    // Tiny price*amount -> quote value rounds to zero.
    engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            1,
            1,
            1,
        )
        .await
        .unwrap();
    let res = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            buyer,
            OrderSide::Buy,
            OrderType::Limit,
            1,
            1,
            2,
        )
        .await;
    assert!(res.is_err(), "zero-value quote must be rejected");
    // Seller has 1 nano in escrow, cancel restores exact 100 STELL:
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        100 * STELL - 1
    );
    engine
        .cancel_order_settled(PAIR_STELL_USDT, 1, seller)
        .await
        .unwrap();
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        100 * STELL
    );
    assert_eq!(engine.get_account(&buyer).await.unwrap().balance, 0);
}

#[tokio::test]
async fn clob_requires_a_configured_quote_token() {
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([1u8; 32], 10 * STELL))
        .await;
    let res = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            [1u8; 32],
            OrderSide::Sell,
            OrderType::Limit,
            250_000,
            STELL,
            0,
        )
        .await;
    assert!(res.is_err(), "no quote token configured -> reject");
}

#[tokio::test]
async fn resting_order_locks_escrow_and_cancel_refunds_fully() {
    let (engine, seller, buyer, usdt) = setup().await;

    // 1) Resting SELL locks native STELL into escrow:
    let (order_id, _) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            250_000,
            10 * STELL,
            1,
        )
        .await
        .unwrap();
    // 100 STELL - 10 STELL locked = 90 STELL:
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        90 * STELL
    );
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR_STELL_USDT, order_id))
            .unwrap()
            .locked_base_stell,
        10 * STELL
    );

    // Cancel and verify full refund:
    let cancelled = engine
        .cancel_order_settled(PAIR_STELL_USDT, order_id, seller)
        .await
        .unwrap();
    assert!(cancelled.is_some());
    assert_eq!(
        engine.get_account(&seller).await.unwrap().balance,
        100 * STELL,
        "fully refunded"
    );
    assert!(engine
        .order_escrow_read()
        .await
        .get(&(PAIR_STELL_USDT, order_id))
        .is_none());

    // 2) Resting BUY locks wUSDT into escrow:
    let (buy_id, _) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            buyer,
            OrderSide::Buy,
            OrderType::Limit,
            250_000,
            8 * STELL,
            2,
        )
        .await
        .unwrap();
    // 8 STELL @ $0.25 = 2.00 wUSDT locked (2_000_000 units):
    assert_eq!(engine.token_balance(&usdt, &buyer).await, 8_000_000);
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR_STELL_USDT, buy_id))
            .unwrap()
            .locked_quote_wusdt,
        2_000_000
    );

    // Cancel and verify full refund of wUSDT:
    let cancelled_buy = engine
        .cancel_order_settled(PAIR_STELL_USDT, buy_id, buyer)
        .await
        .unwrap();
    assert!(cancelled_buy.is_some());
    assert_eq!(
        engine.token_balance(&usdt, &buyer).await,
        10_000_000,
        "wUSDT fully refunded"
    );
    assert!(engine
        .order_escrow_read()
        .await
        .get(&(PAIR_STELL_USDT, buy_id))
        .is_none());
}

// ==================== SVM path: the live escrow lifecycle ====================
//
// `place_order_settled` settles under the wUSDT quote convention;
// `OpCode::SysCallPlaceOrder` settles under the native one (`order_cost` =
// price * amount / 1e6, debited from the sender's balance). Both go through
// the same engine settlement and both must move real value.

/// The VM's native quote - the same arithmetic as `order_cost`, so a test can
/// predict the taker's payment to the nano.
fn native_quote(price: u64, amount: u64) -> u64 {
    price.saturating_mul(amount) / 1_000_000
}

/// wUSDT quote, the `place_order_settled` convention.
fn wusdt_quote(price: u64, amount: u64) -> u64 {
    ((price as u128) * (amount as u128) / 1_000_000_000u128) as u64
}

fn order_tx(
    key: &ed25519_dalek::SigningKey,
    nonce: u64,
    gas_limit: u64,
    payload: Vec<stellereum::svm::OpCode>,
) -> stellereum::sharding::Transaction {
    let from = key.verifying_key().to_bytes();
    stellereum::sharding::Transaction::sign_with_payload(
        key, from, 0, gas_limit, nonce, 1, 1, payload,
    )
}

async fn native_of(engine: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    engine.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

/// The escrow/order lockstep invariant: a record exists exactly when the order
/// it secures is resting, it belongs to that order's trader, and what it holds
/// is exactly the unfilled remainder (in the asset that side locks).
async fn assert_escrow_invariants(engine: &InMemoryStateEngine, pair: u32) {
    let escrow = engine.order_escrow_read().await.clone();
    let books = engine.orderbooks_read().await.clone();
    let book = books.books.get(&pair).expect("book exists");

    for (key, rec) in escrow.iter() {
        assert_eq!(key.0, pair, "this test only watches one pair");
        let order = book.find_order(key.1).unwrap_or_else(|| {
            panic!(
                "ORPHAN: escrow (base {}, wUSDT {}, native {}) for order {} which is not in the book",
                rec.locked_base_stell, rec.locked_quote_wusdt, rec.locked_quote_native, key.1
            )
        });
        assert_eq!(
            order.trader, rec.trader,
            "escrow belongs to the order's trader"
        );
        assert!(
            rec.locked_base_stell + rec.locked_quote_wusdt + rec.locked_quote_native > 0,
            "every escrow record must lock something for order {}",
            key.1
        );
        let remaining = order.amount - order.filled;
        assert!(remaining > 0, "a fully filled order must not keep a record");
        if matches!(order.side, OrderSide::Sell) {
            assert_eq!(
                rec.locked_base_stell, remaining,
                "a sell locks its unfilled base"
            );
            assert_eq!(
                rec.locked_quote_wusdt + rec.locked_quote_native,
                0,
                "and no quote"
            );
        } else {
            assert_eq!(rec.locked_base_stell, 0, "a buy locks no base");
            assert!(
                rec.locked_quote_wusdt > 0 || rec.locked_quote_native > 0,
                "a buy locks quote"
            );
            let native = native_quote(order.price, remaining);
            let wusdt = wusdt_quote(order.price, remaining);
            assert!(
                rec.locked_quote_native == native || rec.locked_quote_wusdt == wusdt,
                "the lock tracks the unfilled remainder (got native {} want {native}, wUSDT {} want {wusdt})",
                rec.locked_quote_native,
                rec.locked_quote_wusdt
            );
        }
    }

    // The other direction: nothing rests unlocked. A resting sell always has a
    // non-zero base lock; a resting buy has a record unless its quote rounds to
    // zero (a dust bid, which locks nothing by definition).
    for order in book.bids.values().chain(book.asks.values()).flatten() {
        let remaining = order.amount - order.filled;
        if remaining == 0 {
            continue;
        }
        let rec = escrow.get(&(pair, order.order_id));
        if matches!(order.side, OrderSide::Sell) {
            assert!(
                rec.is_some(),
                "RESTING SELL {} is not escrowed",
                order.order_id
            );
        } else {
            let needs_lock =
                native_quote(order.price, remaining) > 0 || wusdt_quote(order.price, remaining) > 0;
            if needs_lock {
                assert!(
                    rec.is_some(),
                    "RESTING BUY {} (quote {} / {}) is not escrowed",
                    order.order_id,
                    native_quote(order.price, remaining),
                    wusdt_quote(order.price, remaining)
                );
            }
        }
    }
}

/// PLACE -> partial fill through the SVM -> CANCEL, all in real funds: the
/// maker is paid for what traded, keeps the lock on what did not, and the
/// cancel hands back exactly the remainder.
#[tokio::test]
async fn svm_place_partial_fill_and_cancel_move_value_end_to_end() {
    let (engine, seller, _buyer, _usdt) = setup().await;
    let price = 250_000u64;

    // 1) PLACE: 10 STELL of collateral goes into escrow.
    let (order_id, fills) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            price,
            10 * STELL,
            1,
        )
        .await
        .unwrap();
    assert_eq!(fills, 0);
    assert_eq!(
        native_of(&engine, &seller).await,
        90 * STELL,
        "place locks 10 STELL"
    );
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR_STELL_USDT, order_id))
            .unwrap()
            .locked_base_stell,
        10 * STELL
    );
    assert_escrow_invariants(&engine, PAIR_STELL_USDT).await;

    // 2) FILL 4 of the 10 through the SVM: the taker pays
    //    native_quote = 250_000 * 4e9 / 1e6 = 1 STELL of quote.
    let taker = SigningKey::generate(&mut OsRng);
    let taker_addr = taker.verifying_key().to_bytes();
    let cost = native_quote(price, 4 * STELL);
    assert_eq!(cost, STELL, "4 STELL at $0.25 is 1.00 of quote");
    engine
        .update_account(AccountState::new(taker_addr, 10 * STELL))
        .await;

    let gas = stellereum::svm::GAS_ORDER_PLACE + stellereum::svm::GAS_PER_MATCH_LEVEL;
    let t = order_tx(
        &taker,
        0,
        gas,
        vec![stellereum::svm::OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_USDT,
            is_buy: true,
            price,
            amount: 4 * STELL,
        }],
    );
    engine
        .apply_transaction(&t, 1)
        .await
        .expect("the fill must settle");

    assert_eq!(
        native_of(&engine, &seller).await,
        91 * STELL,
        "the maker was paid 1 STELL of quote for 4 STELL of collateral"
    );
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR_STELL_USDT, order_id))
            .unwrap()
            .locked_base_stell,
        6 * STELL,
        "only the unfilled 6 STELL stay locked"
    );
    assert_eq!(
        native_of(&engine, &taker_addr).await,
        10 * STELL - cost + 4 * STELL - gas,
        "the taker paid the quote, received the collateral and paid the fee"
    );
    assert_escrow_invariants(&engine, PAIR_STELL_USDT).await;

    // 3) CANCEL the remainder: the last 6 STELL come back, nothing more.
    let cancelled = engine
        .cancel_order_settled(PAIR_STELL_USDT, order_id, seller)
        .await
        .unwrap();
    assert!(cancelled.is_some());
    assert_eq!(
        native_of(&engine, &seller).await,
        97 * STELL,
        "90 live + 1 paid + 6 refunded"
    );
    assert!(engine
        .order_escrow_read()
        .await
        .get(&(PAIR_STELL_USDT, order_id))
        .is_none());
    assert_eq!(
        engine.orderbooks_read().await.books[&PAIR_STELL_USDT].depth(),
        (0, 0)
    );

    // Native value is conserved up to the burned fee.
    let total = native_of(&engine, &seller).await + native_of(&engine, &taker_addr).await;
    assert_eq!(total, 110 * STELL - gas, "exactly the fee left the system");
}

/// GRIEFING: an account that can afford the quote but not the fee/amount
/// reservation must not be able to place an order at all. The VM's own
/// affordability check passes (it only sees the balance), admission passes
/// (the balance is above the declared limit), and the settlement is what
/// refuses - before anything moves - because the lock would eat the fee
/// reserve. The VM's book commit is rolled back with it, so the maker's order
/// and both escrows are byte-for-byte what they were.
///
/// F-01 / SEC-07: the refusal is attributable, so the taker pays the failure
/// fee and its nonce is consumed. The escrow lock did NOT happen (the
/// settlement refused before it), so the taker lost exactly the fee - the
/// order cost never left its balance. That fee debit IS a state change, so
/// the state root moves; the pin is that NOTHING ELSE moved (the committed
/// domain digest - tokens, orderbooks, escrow, oracle, ... - is byte-identical
/// and the maker's account is untouched).
#[tokio::test]
async fn under_reserved_svm_taker_cannot_touch_the_book_or_the_escrow() {
    let (engine, seller, _buyer, _usdt) = setup().await;
    let price = 250_000u64;
    let (order_id, _) = engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            price,
            10 * STELL,
            1,
        )
        .await
        .unwrap();

    let gas = stellereum::svm::GAS_ORDER_PLACE;
    let cost = native_quote(price - 1, 4 * STELL);

    // A bid one tick below the ask: it will REST, so its whole order_cost is
    // locked. Fund it with exactly the cost + 500: admission still passes
    // (the balance is far above the declared limit) but after the lock only
    // 500 remain, which cannot pay the fee - the settlement must refuse.
    let taker = SigningKey::generate(&mut OsRng);
    let taker_addr = taker.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(taker_addr, cost + 500))
        .await;

    let maker_before = native_of(&engine, &seller).await;
    let book_before = engine
        .orderbooks_read()
        .await
        .books
        .get(&PAIR_STELL_USDT)
        .cloned();
    let escrow_before = engine.order_escrow_read().await.clone();
    let root_before = engine.get_state_root().await;
    let digest_before = committed_digest(&engine).await;

    let t = order_tx(
        &taker,
        0,
        gas,
        vec![stellereum::svm::OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_USDT,
            is_buy: true,
            price: price - 1,
            amount: 4 * STELL,
        }],
    );
    let fee = failure_fee(&engine, &t).await;
    let res = engine.apply_transaction(&t, 1).await;
    println!("under-reserved taker: {res:?}");
    assert!(
        res.is_err(),
        "a lock that would eat the fee reserve must be refused before it happens"
    );

    let book_after = engine
        .orderbooks_read()
        .await
        .books
        .get(&PAIR_STELL_USDT)
        .cloned();
    assert_eq!(
        bincode::serialize(&book_after).unwrap(),
        bincode::serialize(&book_before).unwrap(),
        "the VM's book commit was rolled back with the failed settlement"
    );
    assert_eq!(
        engine.order_escrow_read().await.clone(),
        escrow_before,
        "neither escrow changed"
    );
    assert_eq!(
        native_of(&engine, &seller).await,
        maker_before,
        "the maker was not paid"
    );
    // F-01: the taker pays the failure fee (its declared limit) and its
    // nonce is consumed - but the ORDER COST did not move: the escrow lock
    // was refused before it happened.
    assert_refused_tx_paid_failure_fee(&engine, &t, fee, cost + 500, 0).await;
    assert_eq!(
        native_of(&engine, &taker_addr).await + fee,
        cost + 500,
        "the taker lost exactly the failure fee: the order cost never left its balance"
    );
    assert_ne!(
        engine.get_state_root().await,
        root_before,
        "F-01: the failure fee is a state change, so the root moves"
    );
    assert_eq!(
        committed_digest(&engine).await,
        digest_before,
        "and NOTHING ELSE moved: every committed domain (tokens, orderbooks, escrow, oracle) \
         is byte-identical"
    );
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR_STELL_USDT, order_id))
            .unwrap()
            .locked_base_stell,
        10 * STELL
    );
}

/// INVARIANT: after a pile of placements through both entry points, fills and
/// cancels, every escrow record is backed by a resting order (and vice versa).
/// An orphan is exactly a record with no order, or an order with no record -
/// and both would make "cancel refunds" and "fill releases" unreachable.
#[tokio::test]
async fn escrow_records_and_resting_orders_stay_in_lockstep() {
    let (engine, seller, buyer, usdt) = setup().await;
    let price = 250_000u64;

    engine
        .place_order_settled(
            PAIR_STELL_USDT,
            seller,
            OrderSide::Sell,
            OrderType::Limit,
            price,
            5 * STELL,
            1,
        )
        .await
        .unwrap();
    engine
        .place_order_settled(
            PAIR_STELL_USDT,
            buyer,
            OrderSide::Buy,
            OrderType::Limit,
            price,
            3 * STELL,
            2,
        )
        .await
        .unwrap();

    // An SVM bid that rests: its whole order_cost is locked in native.
    let bot = SigningKey::generate(&mut OsRng);
    let bot_addr = bot.verifying_key().to_bytes();
    let gas = stellereum::svm::GAS_ORDER_PLACE;
    engine
        .update_account(AccountState::new(bot_addr, 4 * STELL + gas))
        .await;
    let cost = native_quote(price - 1, 4 * STELL);
    engine
        .apply_transaction(
            &order_tx(
                &bot,
                0,
                gas,
                vec![stellereum::svm::OpCode::SysCallPlaceOrder {
                    pair_id: PAIR_STELL_USDT,
                    is_buy: true,
                    price: price - 1,
                    amount: 4 * STELL,
                }],
            ),
            3,
        )
        .await
        .expect("resting bid");
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .values()
            .find(|r| r.trader == bot_addr)
            .unwrap()
            .locked_quote_native,
        cost,
        "the SVM bid locked its native order_cost"
    );

    // An SVM sell that rests: base lock.
    let bot2 = SigningKey::generate(&mut OsRng);
    let bot2_addr = bot2.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(bot2_addr, 6 * STELL + gas))
        .await;
    engine
        .apply_transaction(
            &order_tx(
                &bot2,
                0,
                gas,
                vec![stellereum::svm::OpCode::SysCallPlaceOrder {
                    pair_id: PAIR_STELL_USDT,
                    is_buy: false,
                    price: price + 1_000,
                    amount: 6 * STELL,
                }],
            ),
            4,
        )
        .await
        .expect("resting ask");
    assert_escrow_invariants(&engine, PAIR_STELL_USDT).await;

    // A crossing fill drains one record completely and leaves another intact.
    let crosser = SigningKey::generate(&mut OsRng);
    let crosser_addr = crosser.verifying_key().to_bytes();
    let fill_gas = stellereum::svm::GAS_ORDER_PLACE + stellereum::svm::GAS_PER_MATCH_LEVEL;
    engine
        .update_account(AccountState::new(crosser_addr, 10 * STELL))
        .await;
    engine
        .apply_transaction(
            &order_tx(
                &crosser,
                0,
                fill_gas,
                vec![stellereum::svm::OpCode::SysCallPlaceOrder {
                    pair_id: PAIR_STELL_USDT,
                    is_buy: true,
                    price,
                    amount: 5 * STELL,
                }],
            ),
            5,
        )
        .await
        .expect("crossing fill");
    assert_escrow_invariants(&engine, PAIR_STELL_USDT).await;
    // The 5 STELL sell is gone (fully filled) and its record with it.
    assert!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR_STELL_USDT, 1))
            .is_none(),
        "a drained record is removed with its order"
    );

    // Cancel one resting order so a record disappears by refund, not by fill.
    let bot_oid = engine
        .orderbooks_read()
        .await
        .books
        .get(&PAIR_STELL_USDT)
        .unwrap()
        .bids
        .values()
        .flatten()
        .find(|o| o.trader == bot_addr)
        .map(|o| o.order_id)
        .expect("the bot's bid is resting");
    let bot_before = native_of(&engine, &bot_addr).await;
    engine
        .cancel_order_settled(PAIR_STELL_USDT, bot_oid, bot_addr)
        .await
        .expect("owner cancel")
        .expect("order exists");
    assert_eq!(
        native_of(&engine, &bot_addr).await,
        bot_before + cost,
        "the native lock came back"
    );
    assert_escrow_invariants(&engine, PAIR_STELL_USDT).await;

    // wUSDT only ever shrank (locks burned) and never grew.
    assert!(engine.token_total_supply(&usdt).await.unwrap() <= 10_000_000);
}
