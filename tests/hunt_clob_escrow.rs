//! CLOB escrow on the SVM place-order path - the fix for the original hunt.
//!
//! HISTORY. `OpCode::SysCallPlaceOrder` used to match orders directly on the
//! LIVE orderbook, charge the taker a purely internal `order_cost`
//! (decrementing `current_balance` but pushing NOTHING into `ctx.transfers`),
//! and return the trades. `apply_transaction` read only
//! `gas_used, transfers, payouts` from the result and THREW THE TRADES AWAY,
//! while the mutated book was committed by the SVM's clone-commit. So: real
//! orders got marked `filled` and deleted from the book, the maker's escrow
//! record was never touched, and the taker paid nothing but gas. The maker
//! could no longer cancel (the order was gone) so its escrowed funds were
//! unreachable forever.
//!
//! These tests used to PIN that broken behaviour (they asserted the zero cost,
//! the stranded escrow, the unreachable cancel). They now pin the opposite:
//!
//!  * the taker's `order_cost` is really debited and really ends up in
//!    `order_escrow` for the resting part and with the counterparty for the
//!    filled part (`ClobEvent::Place` -> `settle_clob_effects`);
//!  * crossing a maker releases the maker's escrow to the taker instead of
//!    stranding it;
//!  * nothing is left in `order_escrow` that is not a resting order.
//!
//! EXPLICIT TEST UPDATES (this is the "if a test pins the broken behaviour"
//! list): `svm_crossing_orphans_a_makers_escrow` ->
//! `svm_crossing_settles_a_makers_escrow`, `one_tx_orphans_many_maker_escrows`
//! -> `one_tx_settles_many_maker_escrows`, `svm_place_order_cost_is_never_actually_debited`
//! -> `svm_place_order_cost_is_locked_into_escrow`. The negative control
//! (`control_clob_self_trade_nets_to_zero`) is unchanged.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::{TokenMetadata, TokenOp};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn tx_of(key: &SigningKey, nonce: u64, payload: Vec<OpCode>) -> stellereum::sharding::Transaction {
    let from = key.verifying_key().to_bytes();
    stellereum::sharding::Transaction::sign_with_payload(
        key, from, 0, 100_000, nonce, 1, 1, payload,
    )
}

/// The exact `order_cost` the VM computes for a buy (`src/svm.rs`), so a test
/// can predict the escrow lock to the nano.
///
/// THE SAME u128 MATH THE VM USES: the product is formed in u128 and only
/// then divided (and clamped to u64::MAX). A u64 `saturating_mul` would
/// SILENTLY UNDER-PRICE every order whose notional overflows u64 - and the
/// engine's own escrow lock (`ClobQuoteMode::NativeSvm::quote`) prices in
/// u128, so a saturating helper would disagree with the settlement it is
/// supposed to predict.
fn order_cost(price: u64, amount: u64) -> u64 {
    let prod = (price as u128) * (amount as u128);
    (prod / 1_000_000u128).min(u64::MAX as u128) as u64
}

async fn setup() -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let usdt_minter = [0x11u8; 32];
    let meta = TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: usdt_minter,
        paused: false,
        description: String::new(),
    };
    let usdt_id = engine.create_token(usdt_minter, meta, 0).await.unwrap();
    engine.pmm_init_usdt(usdt_id, 1_000_000_000_000).await;
    (engine, usdt_id)
}

/// The victim escrows 1,000 STELL behind a resting sell order. An attacker
/// crosses it through the SVM.
///
/// FIXED: the crossing MOVES VALUE. The taker pays the quote for the fill, the
/// victim's escrow is released into the taker's hands, and the escrow record
/// disappears with the order. Before the fix the taker paid only gas and the
/// 1,000 STELL were stranded forever.
#[tokio::test]
async fn svm_crossing_settles_a_makers_escrow() {
    let (engine, _usdt) = setup().await;
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();

    let price = 250_000u64; // $0.25
    let amount = stell(1_000);
    let cost = order_cost(price, amount); // 250 STELL of native quote

    engine
        .update_account(AccountState::new(victim_addr, amount + 100_000))
        .await;
    let victim_before = engine.get_account(&victim_addr).await.unwrap().balance;

    // 1. Victim posts a resting sell: 1,000 STELL are debited into escrow.
    let (order_id, fills) = engine
        .place_order_settled(
            1,
            victim_addr,
            OrderSide::Sell,
            OrderType::Limit,
            price,
            amount,
            100,
        )
        .await
        .unwrap();
    let escrowed = engine
        .order_escrow_read()
        .await
        .get(&(1, order_id))
        .cloned();
    println!("victim placed order {order_id}, fills={fills}, escrow={escrowed:?}");
    let after_lock = engine.get_account(&victim_addr).await.unwrap().balance;
    assert_eq!(
        after_lock,
        victim_before - amount,
        "STELL moved into escrow"
    );
    assert_eq!(escrowed.as_ref().unwrap().locked_base_stell, amount);

    // 2. Attacker crosses it through the SVM.
    engine
        .update_account(AccountState::new(attacker_addr, cost + 100_000))
        .await;
    let attacker_before = engine.get_account(&attacker_addr).await.unwrap().balance;
    let t = tx_of(
        &attacker,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price,
            amount,
        }],
    );
    engine
        .apply_transaction(&t, 0)
        .await
        .expect("cross must succeed");
    let attacker_after = engine.get_account(&attacker_addr).await.unwrap().balance;

    // The taker paid the quote and received the 1,000 STELL collateral.
    assert_eq!(
        attacker_after,
        attacker_before - cost + amount - 1_240,
        "the taker pays order_cost (1 match level = 1_240 gas) and receives the base"
    );
    println!(
        "attacker: {attacker_before} -> {attacker_after} (cost {cost}, got {amount} back, 1240 gas)"
    );

    // 3. The victim was PAID the quote and no longer has anything locked.
    let victim_after = engine.get_account(&victim_addr).await.unwrap().balance;
    assert_eq!(
        victim_after,
        after_lock + cost,
        "the maker's collateral converted into the quote it was sold for"
    );
    assert!(
        engine
            .order_escrow_read()
            .await
            .get(&(1, order_id))
            .is_none(),
        "the escrow record died with the order it secured"
    );

    // 4. The order is consumed, so the victim can no longer cancel it - which
    //    is correct now: there is nothing left to refund.
    let book_empty = engine
        .orderbooks_read()
        .await
        .books
        .get(&1)
        .map(|b| b.depth())
        .unwrap_or((0, 0));
    assert_eq!(
        book_empty,
        (0, 0),
        "the victim's order was consumed and deleted"
    );
    let cancel = engine.cancel_order_settled(1, order_id, victim_addr).await;
    assert!(
        cancel.unwrap().is_none(),
        "the order can no longer be found"
    );
    assert!(
        engine.order_escrow_read().await.is_empty(),
        "no escrow survives the fill"
    );
}

/// Loop it: N resting orders, ONE attacker transaction that crosses all of
/// them. Every victim must be paid and every escrow released in that single tx.
#[tokio::test]
async fn one_tx_settles_many_maker_escrows() {
    let (engine, _usdt) = setup().await;
    let price = 250_000u64;
    let per_order = stell(100);
    let per_cost = order_cost(price, per_order);
    let n = 8u64;

    let mut victims = Vec::new();
    for _ in 0..n {
        let k = SigningKey::generate(&mut OsRng);
        let a = k.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(a, per_order + 100_000))
            .await;
        let (oid, _) = engine
            .place_order_settled(
                1,
                a,
                OrderSide::Sell,
                OrderType::Limit,
                price,
                per_order,
                100,
            )
            .await
            .unwrap();
        victims.push((a, oid));
    }
    let escrowed_before: u64 = engine
        .order_escrow_read()
        .await
        .values()
        .map(|e| e.locked_base_stell)
        .sum();
    assert_eq!(escrowed_before, n * per_order);

    // One transaction, N crossings: N * (GAS_ORDER_PLACE + one match level).
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(attacker_addr, n * per_cost + 100_000))
        .await;
    let before = engine.get_account(&attacker_addr).await.unwrap().balance;
    let payload: Vec<OpCode> = (0..n)
        .map(|_| OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price,
            amount: per_order,
        })
        .collect();
    let t = tx_of(&attacker, 0, payload);
    engine.apply_transaction(&t, 0).await.unwrap();
    let after = engine.get_account(&attacker_addr).await.unwrap().balance;
    let gas = n * (stellereum::svm::GAS_ORDER_PLACE + stellereum::svm::GAS_PER_MATCH_LEVEL);
    println!("attacker spent {gas} gas to consume {n} resting orders");
    assert_eq!(
        after,
        before - n * per_cost + n * per_order - gas,
        "the taker paid every maker and collected every collateral"
    );

    // Nothing is stranded: every escrow released with its order.
    let stranded: u64 = engine
        .order_escrow_read()
        .await
        .values()
        .map(|e| e.locked_base_stell)
        .sum();
    assert_eq!(stranded, 0, "all {n} escrows were released to their buyers");
    assert!(engine.order_escrow_read().await.is_empty());
    assert_eq!(engine.orderbooks_read().await.books[&1].depth(), (0, 0));

    // Every victim got paid its quote exactly once.
    for (a, oid) in &victims {
        let bal = engine.get_account(a).await.unwrap().balance;
        assert_eq!(
            bal,
            100_000 + per_cost,
            "victim {} received exactly the quote for its fill",
            hex::encode(&a[..3])
        );
        assert!(engine
            .cancel_order_settled(1, *oid, *a)
            .await
            .unwrap()
            .is_none());
    }
}

/// The taker's `order_cost` used to be charged against a *virtual* balance the
/// state engine never saw, so an account could place orders it could never
/// afford. FIXED: the cost is really debited and really locked in escrow for
/// the resting part of the order.
#[tokio::test]
async fn svm_place_order_cost_is_locked_into_escrow() {
    let (engine, _usdt) = setup().await;
    let price = 1_000_000u64; // $1.00
    let amount = stell(1_000_000); // 1,000,000 STELL notional
    let cost = order_cost(price, amount);

    let trader = SigningKey::generate(&mut OsRng);
    let trader_addr = trader.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(trader_addr, cost + 1_000_000))
        .await;
    let before = engine.get_account(&trader_addr).await.unwrap().balance;
    println!("trader real balance {before}, order cost {cost}");

    let t = tx_of(
        &trader,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price,
            amount,
        }],
    );
    engine
        .apply_transaction(&t, 0)
        .await
        .expect("order must be accepted");
    let after = engine.get_account(&trader_addr).await.unwrap().balance;
    assert_eq!(
        after,
        before - cost - stellereum::svm::GAS_ORDER_PLACE,
        "the whole order cost is debited from the real balance, plus gas"
    );

    // ...and it is sitting in escrow, backing the resting bid.
    let escrow = engine.order_escrow_read().await.clone();
    assert_eq!(escrow.len(), 1, "a resting order must carry escrow");
    let (&key, rec) = escrow.iter().next().unwrap();
    assert_eq!(rec.trader, trader_addr);
    assert_eq!(rec.locked_quote_native, cost, "the lock IS the order cost");
    assert_eq!(rec.locked_base_stell, 0);
    assert_eq!(rec.locked_quote_wusdt, 0);

    let book = engine
        .orderbooks_read()
        .await
        .books
        .get(&1)
        .cloned()
        .unwrap();
    assert_eq!(book.depth().0, 1, "the bid is live in consensus state");
    assert_eq!(book.get_best_bid_ask().0, Some(price));
    let resting = book.find_order(key.1).expect("the order is in the book");
    assert_eq!(resting.amount, amount);

    // Cancelling gives the money back - the escrow lifecycle is closed.
    engine
        .cancel_order_settled(1, key.1, trader_addr)
        .await
        .expect("cancel")
        .expect("order exists");
    assert_eq!(
        engine.get_account(&trader_addr).await.unwrap().balance,
        before - stellereum::svm::GAS_ORDER_PLACE,
        "the lock came back in full; only gas was spent"
    );
    assert!(engine.order_escrow_read().await.is_empty());
    assert_eq!(engine.orderbooks_read().await.books[&1].depth(), (0, 0));
}

/// NEGATIVE RESULT: the CLOB self-trade branch refunds the maker out of the
/// escrow with an unconditional mint, but the escrow is always exactly the
/// order size, so it nets to zero - I could not turn it into a mint here.
#[tokio::test]
async fn control_clob_self_trade_nets_to_zero() {
    let (engine, usdt) = setup().await;
    let taker = SigningKey::generate(&mut OsRng);
    let a = taker.verifying_key().to_bytes();
    let price = 250_000u64;
    let amount = stell(1_000);
    engine
        .update_account(AccountState::new(a, amount * 2 + 1_000_000))
        .await;
    // Give the account wUSDT so the escrow can be locked.
    let minter = [0x11u8; 32];
    engine
        .token_execute(
            &usdt,
            minter,
            TokenOp::Mint {
                to: a,
                amount: 1_000_000_000,
            },
        )
        .await
        .unwrap();
    let before = engine.get_account(&a).await.unwrap().balance;
    let supply_before = engine.token_total_supply(&usdt).await;

    // Post a buy, then cross it with our own sell -> self trade.
    engine
        .place_order_settled(1, a, OrderSide::Buy, OrderType::Limit, price, amount, 100)
        .await
        .unwrap();
    let locked = engine
        .order_escrow_read()
        .await
        .values()
        .map(|e| e.locked_quote_wusdt)
        .sum::<u64>();
    let r = engine
        .place_order_settled(1, a, OrderSide::Sell, OrderType::Limit, price, amount, 200)
        .await;
    println!("self-cross result: {r:?}; wUSDT escrowed was {locked}");
    let after = engine.get_account(&a).await.unwrap().balance;
    let supply_after = engine.token_total_supply(&usdt).await;
    println!("native {before} -> {after}; wUSDT supply {supply_before:?} -> {supply_after:?}");
    assert!(
        supply_after.unwrap_or(0) <= supply_before.unwrap_or(0),
        "the self-trade refund is backed by the burned escrow, not printed"
    );
}
