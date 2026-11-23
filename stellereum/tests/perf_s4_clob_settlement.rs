//! S4 (perf) regression: CLOB settlement no longer clones the WHOLE token
//! registry on the consensus apply paths, and a REFUSED settlement plan still
//! leaves no trace.
//!
//! `settle_clob_effects` used to plan every order against a private copy of
//! the complete `TokenRegistry` (every token, every balance) - per order
//! transaction - and then overwrite the live registry with it. The consensus
//! apply paths already hold a pre-payload domain snapshot
//! (`snapshot_payload_domains_at`) and restore it through `rollback_payload`
//! on any `Err`, so they now let the plan run against the live registry
//! (`stage_tokens == false`) and rely on that restore: the same committed end
//! state, without the clone.
//!
//! This file pins BOTH halves of that claim:
//!
//!  1. COUNTING (`perf_s4_token_stage_clones`): the single-transaction
//!     consensus path takes ZERO whole-registry clones; a standalone
//!     `execute_payload` caller (which owns no domain snapshot) still takes
//!     exactly one - the fallback is intact, not silently dropped.
//!  2. ATOMICITY: a taker SELL whose fill mints wUSDT and whose plan is then
//!     REFUSED by the settlement reserve check (the tx value exceeds what the
//!     sender may keep) must leave the token supply, both parties' wUSDT
//!     balances, the escrow map, the order book and the maker's native
//!     balance exactly as they were. The sender loses only the F-01 failure
//!     fee and consumes its nonce.
//!
//! Why the reserve check: it runs AFTER the whole fill plan (including the
//! wUSDT mint to the seller) has been applied to the planning registry, so it
//! is precisely the "plan wrote tokens, then refused" path the in-place mode
//! must roll back.

use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

const STELL: u64 = 1_000_000_000;
/// Nano-STELL the maker parks in the engine (enough for the escrow legs).
const MAKER_BAL: u64 = 5 * STELL;
/// Nano-STELL the taker starts with.
const TAKER_BAL: u64 = 10 * STELL;
const PRICE: u64 = 250_000; // $0.25
const PAIR: u32 = 1;
/// Declared gas of the taker transaction (also its reservation).
const GAS: u64 = 100_000;
const NOW: u64 = 200;

/// wUSDT quote value of `base_nano` nano-STELL at `price_micro` - the
/// `place_order_settled` (wUSDT) convention the maker leg locks under.
fn quote_wusdt(price: u64, base_nano: u64) -> u64 {
    ((price as u128) * (base_nano as u128) / 1_000_000_000u128) as u64
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
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

/// Maker rests a BUY for `amount` base, escrowed in wUSDT.
async fn rest_maker_buy(
    engine: &InMemoryStateEngine,
    usdt: &[u8; 32],
    amount: u64,
) -> (FalconKeypair, u64) {
    let maker = FalconKeypair::generate();
    let maker_addr = pq_addr(&maker);
    engine
        .update_account(AccountState::new(maker_addr, MAKER_BAL))
        .await;
    engine
        .token_execute(
            usdt,
            [0x11u8; 32],
            stellereum::token::TokenOp::Mint {
                to: maker_addr,
                amount: 10_000_000,
            },
        )
        .await
        .unwrap();
    let (order_id, fills) = engine
        .place_order_settled(
            PAIR,
            maker_addr,
            OrderSide::Buy,
            OrderType::Limit,
            PRICE,
            amount,
            100,
        )
        .await
        .unwrap();
    assert_eq!(fills, 0, "the book starts empty: nothing fills");
    (maker, order_id)
}

/// A taker SELL for `order_amount` base at `PRICE` that FULLY fills the
/// maker's resting buy, carrying a `value` (the transaction's own `amount`)
/// large enough that the settlement's "keep the reservation" check refuses the
/// whole plan AFTER the fill's wUSDT mint was planned.
fn reserve_refused_taker_sell(
    taker: &FalconKeypair,
    to: [u8; 32],
    order_amount: u64,
    value: u64,
) -> Transaction {
    let pk = taker.public_key().to_vec();
    let payload = vec![OpCode::SysCallPlaceOrder {
        pair_id: PAIR,
        is_buy: false,
        price: PRICE,
        amount: order_amount,
    }];
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        value,
        GAS,
        0,
        1,
        1,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = taker.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        to,
        value,
        GAS,
        0,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

/// Serialized books, sorted by pair id, so equality is a byte comparison.
async fn books_bytes(engine: &InMemoryStateEngine) -> Vec<(u32, Vec<u8>)> {
    let snap = engine.commitment_snapshot().await;
    let mut v: Vec<(u32, Vec<u8>)> = snap
        .orderbooks
        .books
        .iter()
        .map(|(pair, book)| (*pair, bincode::serialize(book).unwrap()))
        .collect();
    v.sort();
    v
}

/// Everything the REFUSED plan must not have touched, snapshotted before it
/// runs.
struct Pre {
    maker_native: u64,
    taker_native: u64,
    maker_wusdt: u64,
    taker_wusdt: u64,
    supply: Option<u64>,
    escrow: std::collections::HashMap<(u32, u64), stellereum::state_engine::EscrowRecord>,
    books: Vec<(u32, Vec<u8>)>,
}

async fn snapshot(
    engine: &InMemoryStateEngine,
    usdt: &[u8; 32],
    maker: &[u8; 32],
    taker: &[u8; 32],
) -> Pre {
    Pre {
        maker_native: engine.get_account(maker).await.unwrap().balance,
        taker_native: engine.get_account(taker).await.unwrap().balance,
        maker_wusdt: engine.token_balance(usdt, maker).await,
        taker_wusdt: engine.token_balance(usdt, taker).await,
        supply: engine.token_total_supply(usdt).await,
        escrow: engine.order_escrow_read().await.clone(),
        books: books_bytes(engine).await,
    }
}

#[tokio::test]
async fn consensus_clob_settlement_takes_no_token_clone_and_a_refused_plan_leaves_no_trace() {
    let order_amount = 2 * STELL;
    // Leave native headroom for the admission fee: a taker sized to the exact
    // balance is rejected at admission ("insufficient balance") and would
    // never reach the CLOB reserve check this test exists to exercise.
    let value = TAKER_BAL - GAS - 1_000_000;

    // ---- (1) Consensus path: apply_transaction ------------------------------
    let (engine, usdt) = setup().await;
    let (maker, order_id) = rest_maker_buy(&engine, &usdt, order_amount).await;
    let maker_addr = pq_addr(&maker);
    let taker = FalconKeypair::generate();
    let taker_addr = pq_addr(&taker);
    engine
        .update_account(AccountState::new(taker_addr, TAKER_BAL))
        .await;

    let tx = reserve_refused_taker_sell(&taker, [0xD1; 32], order_amount, value);
    // Snapshotted BEFORE the transaction: the failure fee is a function of the
    // consensus floor, which the apply path folds at the end.
    let fee = failure_fee(&engine, &tx).await;
    assert!(fee > 0, "a refused transaction is never free");
    let pre = snapshot(&engine, &usdt, &maker_addr, &taker_addr).await;
    let locked0 = engine
        .order_escrow_read()
        .await
        .get(&(PAIR, order_id))
        .map(|r| r.locked_quote_wusdt);
    assert_eq!(
        locked0,
        Some(quote_wusdt(PRICE, order_amount)),
        "the maker's buy is fully collateralised before the taker arrives"
    );

    let clones_before = InMemoryStateEngine::perf_s4_token_stage_clones();
    let res = engine.apply_transaction(&tx, NOW).await;
    let err = res.expect_err("the settlement reserve check must refuse the plan");
    assert!(
        err.starts_with("CLOB settlement failed:"),
        "same error shape as before: {err}"
    );
    assert_eq!(
        InMemoryStateEngine::perf_s4_token_stage_clones() - clones_before,
        0,
        "S4: the consensus apply path must NOT clone the whole token registry \
         (it owns a payload-domain snapshot instead)"
    );

    // F-01: attributable refusal - the taker pays the fee and consumes the
    // nonce, nothing else moves.
    assert_refused_tx_paid_failure_fee(&engine, &tx, fee, pre.taker_native, 0).await;
    assert_eq!(
        engine.get_account(&taker_addr).await.unwrap().balance,
        pre.taker_native.saturating_sub(fee),
        "the taker lost exactly the failure fee"
    );
    assert_eq!(
        engine.token_total_supply(&usdt).await,
        pre.supply,
        "the fill's wUSDT mint must not survive a refused settlement plan"
    );
    assert_eq!(
        engine.token_balance(&usdt, &taker_addr).await,
        pre.taker_wusdt,
        "the taker received no quote for a fill that never settled"
    );
    assert_eq!(
        engine.token_balance(&usdt, &maker_addr).await,
        pre.maker_wusdt,
        "the maker's escrowed quote is untouched"
    );
    assert_eq!(
        *engine.order_escrow_read().await,
        pre.escrow,
        "no escrow record was created, drained or rewritten"
    );
    assert_eq!(
        books_bytes(&engine).await,
        pre.books,
        "the book is byte-identical: the failed fill never happened"
    );
    assert_eq!(
        engine.get_account(&maker_addr).await.unwrap().balance,
        pre.maker_native,
        "no native leg of the fill moved"
    );
    assert_eq!(
        engine
            .order_escrow_read()
            .await
            .get(&(PAIR, order_id))
            .map(|r| r.locked_quote_wusdt),
        locked0,
        "the maker's resting order is still fully collateralised"
    );

    // ---- (2) Standalone path: execute_payload (no domain snapshot) ----------
    //
    // This caller keeps the private staging copy, so it still pays exactly one
    // whole-registry clone - the fallback the consensus path no longer uses.
    let (engine2, usdt2) = setup().await;
    let (maker2, _) = rest_maker_buy(&engine2, &usdt2, order_amount).await;
    let maker_addr2 = pq_addr(&maker2);
    let taker2 = FalconKeypair::generate();
    let taker_addr2 = pq_addr(&taker2);
    engine2
        .update_account(AccountState::new(taker_addr2, TAKER_BAL))
        .await;
    let tx2 = reserve_refused_taker_sell(&taker2, [0xD2; 32], order_amount, value);
    let pre2 = snapshot(&engine2, &usdt2, &maker_addr2, &taker_addr2).await;

    let clones_before = InMemoryStateEngine::perf_s4_token_stage_clones();
    let res2 = engine2.execute_payload(&tx2, NOW).await;
    assert!(
        res2.is_err(),
        "the same reservation refusal applies to the standalone entry point"
    );
    assert_eq!(
        InMemoryStateEngine::perf_s4_token_stage_clones() - clones_before,
        1,
        "S4: a caller WITHOUT a domain snapshot must still stage a private copy"
    );
    // ... and that copy is exactly what keeps the refused plan invisible even
    // though this caller does not roll anything back.
    assert_eq!(
        engine2.token_total_supply(&usdt2).await,
        pre2.supply,
        "staging: a refused plan leaves the live token registry untouched"
    );
    assert_eq!(
        engine2.token_balance(&usdt2, &taker_addr2).await,
        pre2.taker_wusdt,
        "staging: no quote mint reached the taker"
    );
    assert_eq!(
        engine2.get_account(&taker_addr2).await.unwrap().balance,
        pre2.taker_native,
        "the standalone entry point settles no native leg and charges no fee"
    );
}
