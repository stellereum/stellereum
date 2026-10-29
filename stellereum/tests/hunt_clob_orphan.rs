//! ADVERSARIAL HUNT: the SVM order syscalls and CLOB escrow custody.
//!
//! Three hypotheses, all about the same class of error -- a value movement that
//! one layer of the stack believes it performed but the layer that actually
//! commits balances never performs, and an escrow whose lifecycle is not tied to
//! the order it is supposed to secure:
//!
//!  1. `OpCode::SysCallPlaceOrder` charges `order_cost` against the VM's
//!     *phantom* `current_balance` only. It never emits a `transfer`, and
//!     `apply_transaction` only ever debits `tx.amount + fee + sum(transfers)`.
//!     => the order is free.
//!  2. `OpCode::SysCallCancelOrder` cancels ANY order by id, with no check that
//!     `ctx.sender` owns it, and it never touches `order_escrow`.
//!     => a stranger can remove a funded order and orphan its escrow forever.
//!  3. `OrderbookActor::submit_order_bounded` silently evicts the worst price
//!     level when `max_depth` is exceeded, again orphaning the escrow.
//!
//! STATUS: all three are fixed and this file now pins the FIXES. Hypothesis 1
//! is settled by `ClobEvent::Place` -> `settle_clob_effects` (order cost really
//! debited, really locked), 2 by the ownership check in the syscall, and 3 by
//! refusing the newcomer's rest instead of evicting a funded order.
//!
//! EXPLICIT TEST UPDATES (tests that used to pin the broken behaviour):
//! `svm_place_order_never_debits_the_order_cost` ->
//! `svm_place_order_escrows_the_order_cost`, and
//! `depth_eviction_orphans_escrow` -> `depth_saturation_never_orphans_escrow`.
//! `anyone_can_cancel_a_foreign_order_and_orphan_its_escrow` already asserted
//! the fixed behaviour of hypothesis 2 and is unchanged.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_ORDER_PLACE};
use stellereum::token::TokenMetadata;

const NANO: u64 = 1_000_000_000;
const GAS: u64 = 1_000_000;

fn tx(key: &SigningKey, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    Transaction::sign_with_payload(key, [0xEE; 32], 0, GAS, nonce, 0, 1, payload)
}

async fn bal(e: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    e.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

fn meta(minter: [u8; 32]) -> TokenMetadata {
    TokenMetadata {
        name: "wUSDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: Some(u64::MAX),
        minter,
        paused: false,
        description: String::new(),
    }
}

/// Set up a state engine with a configured wUSDT quote token.
async fn clob_engine() -> (InMemoryStateEngine, [u8; 32]) {
    let e = InMemoryStateEngine::new();
    let minter = [0xF0; 32];
    let usdt = e
        .create_token(minter, meta(minter), 0)
        .await
        .expect("create wUSDT");
    e.pmm_init_usdt(usdt, 1_000_000_000_000).await;
    (e, usdt)
}

// ---------------------------------------------------------------------------
// 1. Orders placed through the SVM cost nothing.
//
// HUNT-FIXED: `SysCallPlaceOrder` now hands a `ClobEvent::Place` to the
// engine, which debits `order_cost` and locks it in `order_escrow` for the
// resting part (this test's order rests in full, so the whole cost is locked).
// The old assertions pinned the broken behaviour - only gas charged, an empty
// escrow, "consensus state written for free" - and are inverted here.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn svm_place_order_escrows_the_order_cost() {
    let e = InMemoryStateEngine::new();
    let alice = SigningKey::generate(&mut OsRng);
    let alice_addr = alice.verifying_key().to_bytes();
    let start = 1_000 * NANO;
    e.update_account(AccountState::new(alice_addr, start)).await;

    // A limit BUY for 1,000 STELL at $0.25 => 250 STELL of quote, against a
    // 1,000 STELL account. The VM's own guard passes; the chain must charge
    // and escrow the 250 STELL.
    let price_micro = 250_000u64;
    let amount = 1_000 * NANO;
    let cost = price_micro.saturating_mul(amount) / 1_000_000; // same as svm.rs

    e.apply_transaction(
        &tx(
            &alice,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: price_micro,
                amount,
            }],
        ),
        0,
    )
    .await
    .expect("order must be accepted");

    let after = bal(&e, &alice_addr).await;
    let gas = GAS_ORDER_PLACE as i128;
    println!("start        = {start}");
    println!("order_cost   = {cost} (escrowed)");
    println!("after        = {after}");
    println!("actual debit = {}", start - after);
    println!("gas          = {gas}");

    assert_eq!(
        after,
        start - cost - GAS_ORDER_PLACE,
        "the {} nano order cost is really debited, plus gas",
        cost
    );
    assert_eq!(
        (start - after) as i128,
        cost as i128 + gas,
        "cost + gas, nothing else"
    );

    // The position IS secured: one escrow record for exactly that cost.
    let escrow = e.order_escrow_read().await.clone();
    assert_eq!(escrow.len(), 1, "a funded-looking order must carry escrow");
    let (&key, rec) = escrow.iter().next().unwrap();
    assert_eq!(rec.trader, alice_addr);
    assert_eq!(rec.locked_quote_native, cost, "the lock is the order cost");
    assert_eq!(rec.locked_base_stell, 0);
    assert_eq!(rec.locked_quote_wusdt, 0);

    let book_orders: usize = e
        .orderbooks_read()
        .await
        .books
        .get(&1)
        .map(|b| b.bids.values().map(|v| v.len()).sum::<usize>())
        .unwrap_or(0);
    assert_eq!(book_orders, 1, "the order really is resting in the book");
    assert!(
        e.orderbooks_read().await.books[&1]
            .find_order(key.1)
            .is_some(),
        "the escrowed order is reachable in the book"
    );
    println!("resting orders with escrow: {book_orders}");

    // And it is all gettable back: cancel refunds the lock.
    e.cancel_order_settled(1, key.1, alice_addr)
        .await
        .expect("cancel")
        .expect("order exists");
    assert_eq!(bal(&e, &alice_addr).await, start - GAS_ORDER_PLACE);
    assert!(e.order_escrow_read().await.is_empty(), "escrow released");
}

// ---------------------------------------------------------------------------
// 2. A stranger can cancel a funded order, and its escrow is orphaned forever.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn anyone_can_cancel_a_foreign_order_and_orphan_its_escrow() {
    let (e, usdt) = clob_engine().await;
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();
    let pair = 1u32;
    let price = 250_000u64;

    e.update_account(AccountState::new(victim_addr, 1_000 * NANO))
        .await;
    e.update_account(AccountState::new(attacker_addr, 10 * NANO))
        .await;
    e.token_execute(
        &usdt,
        [0xF0; 32],
        stellereum::token::TokenOp::Mint {
            to: victim_addr,
            amount: 1_000_000_000,
        },
    )
    .await
    .unwrap();

    // The victim posts a real, fully-escrowed resting bid through the CLOB path.
    let amount = 500 * NANO;
    let (order_id, fills) = e
        .place_order_settled(
            pair,
            victim_addr,
            OrderSide::Buy,
            OrderType::Limit,
            price,
            amount,
            0,
        )
        .await
        .expect("victim order");
    assert_eq!(fills, 0);
    let esc = e.order_escrow_read().await.get(&(pair, order_id)).cloned();
    println!("victim order {order_id} escrow = {esc:?}");
    let locked = esc.expect("escrow must exist").locked_quote_wusdt;
    assert!(locked > 0, "the victim's wUSDT really is locked");
    let victim_after_lock = bal(&e, &victim_addr).await;

    // THE ATTACK - now a regression test.
    //
    // There was no `order.trader == ctx.sender` check, so a stranger could cancel
    // any resting order for a trivial gas cost. The escrow record stayed in place
    // while the order it secured disappeared, and the only release path looks the
    // order up in the book - so the funds were stranded permanently. That is
    // censorship plus theft of the escrowed balance, using one transaction.
    let res = e
        .apply_transaction(
            &tx(&attacker, 0, vec![OpCode::SysCallCancelOrder { order_id }]),
            0,
        )
        .await;
    assert!(
        res.is_err(),
        "a stranger must not be able to cancel someone else's order: {res:?}"
    );

    // Nothing was touched: the order is still resting and the escrow still
    // matches it, so the owner can still act on it.
    let still_in_book = e
        .orderbooks_read()
        .await
        .books
        .get(&pair)
        .map(|b| {
            b.bids
                .values()
                .flat_map(|v| v.iter())
                .any(|o| o.order_id == order_id)
        })
        .unwrap_or(false);
    assert!(
        still_in_book,
        "the victim's order must survive a stranger's cancel attempt"
    );
    assert!(
        e.order_escrow_read().await.get(&(pair, order_id)).is_some(),
        "the escrow is untouched, so it is still releasable by its owner"
    );
    assert_eq!(
        bal(&e, &victim_addr).await,
        victim_after_lock,
        "a refused cancel moved no coins"
    );
    println!("HUNT-FIXED: foreign cancel refused, order and escrow both intact");

    // And the owner can still cancel their own order, refunding the escrow.
    let owner = e
        .cancel_order_settled(pair, order_id, victim_addr)
        .await
        .expect("owner cancel succeeds");
    assert!(
        owner.is_some(),
        "the owner must still be able to cancel and reclaim"
    );
}

// ---------------------------------------------------------------------------
// 3. Depth eviction used to orphan escrow the same way, with no attacker at all.
//    HUNT-FIXED: a full book now refuses the newcomer instead of evicting a
//    funded resting order.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn depth_saturation_never_orphans_escrow() {
    let (e, usdt) = clob_engine().await;
    let trader = [0xA5; 32];
    let pair = 1u32;
    let minter = [0xF0; 32];
    e.update_account(AccountState::new(trader, 1_000_000 * NANO))
        .await;
    e.token_execute(
        &usdt,
        minter,
        stellereum::token::TokenOp::Mint {
            to: trader,
            amount: 1_000_000_000_000,
        },
    )
    .await
    .unwrap();

    // max_depth is 1000, so push 1001 distinct price levels.
    let mut ids = Vec::new();
    for i in 0..1001u64 {
        let (id, _) = e
            .place_order_settled(
                pair,
                trader,
                OrderSide::Buy,
                OrderType::Limit,
                200_000 + i,
                10 * NANO,
                0,
            )
            .await
            .expect("order");
        ids.push(id);
    }
    let escrow_count = e.order_escrow_read().await.len();
    let levels = e
        .orderbooks_read()
        .await
        .books
        .get(&pair)
        .map(|b| b.bids.len())
        .unwrap_or(0);
    println!("levels in book = {levels}, escrows = {escrow_count}");
    // HUNT-FIXED: the book refuses the NEWCOMER instead of evicting the worst
    // funded level, so the depth bound still holds and no escrow is stranded.
    assert_eq!(levels, 1000, "the depth bound still holds");
    assert_eq!(
        escrow_count, 1000,
        "only resting orders carry escrow - the refused one locked nothing"
    );

    let resting: Vec<u64> = e
        .orderbooks_read()
        .await
        .books
        .get(&pair)
        .map(|b| {
            b.bids
                .iter()
                .flat_map(|(_, v)| v.iter())
                .map(|o| o.order_id)
                .collect::<Vec<_>>()
        })
        .unwrap();
    assert_eq!(
        resting.len(),
        1000,
        "every funded order is still in the book"
    );

    // The invariant the whole escrow design rests on: a record exists if and
    // only if the order it secures is resting.
    let escrow_snapshot = e.order_escrow_read().await.clone();
    for (key, rec) in escrow_snapshot.iter() {
        let in_book = e
            .orderbooks_read()
            .await
            .books
            .get(&key.0)
            .map(|b| b.find_order(key.1).is_some())
            .unwrap_or(false);
        assert!(
            in_book,
            "escrow for order {} is held by a book that does not contain it",
            key.1
        );
        assert!(rec.locked_quote_wusdt > 0, "and it is actually funded");
    }

    // The refused order never locked anything, so there is nothing to strand:
    // it is simply not in the book and not in escrow.
    let refused = ids[1000];
    println!("refused order id = {refused}");
    assert!(
        !resting.contains(&refused),
        "the newcomer did not get a resting slot"
    );
    assert!(
        !e.order_escrow_read().await.contains_key(&(pair, refused)),
        "and locked nothing on the way in"
    );
    assert!(
        e.cancel_order_settled(pair, refused, trader)
            .await
            .unwrap()
            .is_none(),
        "cancelling an order that never rested is a no-op, not a refund of nothing"
    );
    assert_eq!(
        e.order_escrow_read().await.len(),
        1000,
        "no escrow record appeared out of the refusal"
    );

    // And every order that DID rest can still be cancelled and refunded.
    for id in ids.iter().take(1000) {
        assert!(e
            .cancel_order_settled(pair, *id, trader)
            .await
            .unwrap()
            .is_some());
    }
    assert!(
        e.order_escrow_read().await.is_empty(),
        "every lock released"
    );
    assert_eq!(e.orderbooks_read().await.books[&pair].depth(), (0, 0));
}
