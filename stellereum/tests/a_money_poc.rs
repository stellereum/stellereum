//! A-MONEY adversarial PoCs: money-conservation invariants that MUST hold.
//!
//! Each test asserts the CORRECT (money-safe) behavior. A FAILURE on current
//! code proves a real money bug. Scope: TESTS ONLY, no src edits.

use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::token::{TokenMetadata, TokenOp};

const STELL: u64 = 1_000_000_000;
const PRICE: u64 = 250_000; // $0.25
const PAIR: u32 = 1;

/// wUSDT quote (micro) for `base_nano` at `price_micro` under the
/// `place_order_settled` convention.
fn quote_wusdt(price: u64, base_nano: u64) -> u64 {
    ((price as u128) * (base_nano as u128) / 1_000_000_000u128) as u64
}

fn wusdt_meta_capped(minter: [u8; 32], cap: u64) -> TokenMetadata {
    TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: Some(cap),
        minter,
        paused: false,
        description: String::new(),
    }
}

/// P0: `place_order_settled` must be ALL-OR-NOTHING. It validates affordability
/// up front but then settles trades in a loop against LIVE state (native
/// debits/credits, token Mint via minter authority, live escrow map) with `?`
/// returns. A mid-loop mint refusal (here: supply-cap on the SECOND of two
/// maker-quote releases) must roll back the first trade. Current code commits
/// the book only at the end (clone dropped on Err) while keeping trade 1's
/// funds moved: partial settlement + book/escrow desync (re-matchable).
#[tokio::test]
async fn a_money_p0_place_order_settled_is_atomic_over_capped_quote_mint() {
    let engine = InMemoryStateEngine::new();
    let minter = [0x11u8; 32];
    // Cap 3000 micro. Funding 1000+1000, locks burn 200+200 (->1600),
    // filler mint 1200 (->2800). Trade1 mint 200 (->3000, fits),
    // trade2 mint 200 (->3200 > cap, refused).
    let usdt = engine
        .create_token(minter, wusdt_meta_capped(minter, 3_000), 0)
        .await
        .unwrap();
    *engine.pmm_usdt_token_write().await = Some(usdt);

    let maker1 = [0xA1u8; 32];
    let maker2 = [0xA2u8; 32];
    let taker = [0xB0u8; 32];
    let filler = [0xF0u8; 32];
    let each: u64 = 800_000; // nano-STELL; q = 200 micro each at PRICE
    assert_eq!(quote_wusdt(PRICE, each), 200);

    for (m, fund) in [(maker1, 1_000u64), (maker2, 1_000u64)] {
        engine.update_account(AccountState::new(m, 5 * STELL)).await;
        engine
            .token_execute(&usdt, minter, TokenOp::Mint { to: m, amount: fund })
            .await
            .unwrap();
        let (oid, fills) = engine
            .place_order_settled(PAIR, m, OrderSide::Buy, OrderType::Limit, PRICE, each, 100)
            .await
            .unwrap();
        assert_eq!(fills, 0);
        let _ = oid;
    }
    // Filler mint consumes the headroom so only the FIRST release fits.
    engine
        .token_execute(
            &usdt,
            minter,
            TokenOp::Mint {
                to: filler,
                amount: 1_200,
            },
        )
        .await
        .unwrap();
    assert_eq!(engine.token_total_supply(&usdt).await, Some(2_800));

    engine
        .update_account(AccountState::new(taker, 10 * STELL))
        .await;
    let escrow_before = engine.order_escrow_read().await.clone();

    let res = engine
        .place_order_settled(
            PAIR,
            taker,
            OrderSide::Sell,
            OrderType::Limit,
            PRICE,
            each * 2,
            200,
        )
        .await;
    assert!(res.is_err(), "second quote release must exceed the cap: {res:?}");

    // ATOMICITY: a refused settlement moves nothing anywhere. Collect every
    // symptom before failing so one run documents the full desync.
    let taker_wusdt = engine.token_balance(&usdt, &taker).await;
    let supply = engine.token_total_supply(&usdt).await;
    let escrow_now = engine.order_escrow_read().await.clone();
    assert!(
        taker_wusdt == 0 && supply == Some(2_800) && escrow_now == escrow_before,
        "P0 partial settlement: taker wUSDT={taker_wusdt} (want 0), supply={supply:?} (want Some(2800)), escrow_changed={} (trade-1 mint/escrow-drain survived a refused settlement; book clone was dropped so the book still shows unfilled makers)",
        escrow_now != escrow_before,
    );
}

// DROPPED lead (documented, not a finding): PMM `as u64` receipt casts
// (`stell_minted`, `supply_after`, `usdt_paid`) were reviewed for the same
// truncation class. Verdict: unreachable — `d = sqrt(a^2+X)-a` with a>0 is
// always `< 2^64` before the u128 domain overflows, and cumulative
// reserve/supply would need ~$18T throughput. No PoC possible; not reported.
/// P1: slash must cover stake that is in the unbonding pipeline. `slash`
/// totals self-bond + active delegated + SELF unbonding only; a delegator's
/// in-flight `unbonding` entry (owner = Some) and matured `withdrawable` are
/// never touched, so `undelegate` (or maturing + not yet withdrawing) before a
/// slash escapes the burn deterministically.
#[test]
fn a_money_p1_slash_covers_delegator_unbonding_pipeline() {
    let mut l = StakingLedger::new();
    let v = [0x01u8; 32];
    let d = [0xD1u8; 32];
    let floor = stellereum::staking::required_bond_floor_nano();
    l.bond(v, floor, stellereum::staking::DEFAULT_COMMISSION_BPS)
        .unwrap();
    let delegated = 500 * STELL;
    l.delegate(d, v, delegated).unwrap();
    let exiting = 200 * STELL;
    l.undelegate(d, v, exiting, 1_000).unwrap();

    let full_total: u64 = floor + delegated; // nothing left the system
    let expected_burn = ((full_total as u128) * 500u128 / 10_000u128) as u64; // 5%
    let burned = l.slash(v, stellereum::staking::EQUIVOCATION_SLASH_BPS).unwrap();

    assert_eq!(
        burned, expected_burn,
        "P1: slash burned {burned} but 5% of the full slashable total ({full_total}) is {expected_burn} — in-flight delegator stake escaped"
    );
    let pipe: u64 = l.unbonding.iter().map(|e| e.amount).sum();
    assert_eq!(
        pipe,
        exiting - ((exiting as u128) * 500u128 / 10_000u128) as u64,
        "P1: delegator unbonding entry was not slashed pro-rata"
    );
}

/// P2: `process_unbonding` aggregates with `saturating_add` into
/// `withdrawable`: on overflow the excess is silently destroyed (fail-open cap
/// instead of fail-closed refusal, unlike the L3-checked `add_bond` /
/// `delegate` paths). Unreachable at live supplies (u64::MAX nano ~= 18B
/// STELL) but wrong by policy: stake accounting must refuse rather than cap.
#[test]
fn a_money_p2_unbonding_maturation_never_saturates() {
    let mut l = StakingLedger::new();
    let v = [0x02u8; 32];
    l.withdrawable.insert((v, [0u8; 32]), u64::MAX - 5);
    l.unbonding.push(stellereum::staking::UnbondingEntry {
        validator: v,
        owner: None,
        amount: 100,
        release_at: 0,
    });
    l.process_unbonding(1).expect_err(
        "P2: maturation exceeding u64::MAX must refuse (ArithmeticOverflow), never saturate",
    );
    let got = l.withdrawable.get(&(v, [0u8; 32])).copied().unwrap_or(0);
    // Untouched by the refused maturation (still the pre-existing balance).
    assert_eq!(got, u64::MAX - 5, "refused maturation must move nothing");
    // And the entry stays pending for a future (possible) maturation.
    assert_eq!(l.unbonding.len(), 1, "refused entry stays pending");
}
