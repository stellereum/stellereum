//! PMM security tests: the primary market maker must be arbitrage-proof and
//! must never let the USDT reserve be drained below its ring-fenced buffer.

use stellereum::pmm::{PmmError, PrimaryMarketMaker, PMM_REDEMPTION_BUFFER_BPS};

fn usdt(n: u64) -> u64 {
    n * 1_000_000
}
fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// No sequence of buys ever lets a full redemption exceed the usable reserve.
#[test]
fn reserve_can_never_be_fully_drained() {
    let mut pmm = PrimaryMarketMaker::new();
    pmm.buy_with_usdt(usdt(50_000)).unwrap();
    let usable = pmm.usable_reserve_micro();
    let max = pmm.max_redeemable_stell();
    let payout = {
        // pay out max by actually selling it, then confirm what remains >= buffer
        let r = pmm.sell_stell(max).unwrap();
        r.usdt_paid
    };
    assert!(payout as u128 <= usable);
    assert!(
        pmm.reserve_micro >= pmm.redemption_buffer_micro,
        "reserve must never fall below the ring-fenced buffer"
    );
}

/// A buy followed by selling everything allowed cannot profit (no free lunch).
#[test]
fn no_roundtrip_profit() {
    for amount in [100u64, 1_000, 10_000, 100_000, 1_000_000] {
        let mut pmm = PrimaryMarketMaker::new();
        let bought = pmm.buy_with_usdt(usdt(amount)).unwrap();
        let max = pmm.max_redeemable_stell();
        let paid = pmm.sell_stell(max).unwrap().usdt_paid;
        assert!(
            paid <= bought.usdt_paid,
            "round-trip must not profit (buy={}, redeem={})",
            bought.usdt_paid,
            paid
        );
    }
}

/// Selling more than the minted supply is always rejected.
#[test]
fn cannot_redeem_unminted_supply() {
    let mut pmm = PrimaryMarketMaker::new();
    pmm.buy_with_usdt(usdt(100)).unwrap();
    assert_eq!(
        pmm.sell_stell(stell(1_000_000_000)),
        Err(PmmError::InsufficientReserve)
    );
}

/// The price is monotonically increasing with supply: buying pushes it up,
/// selling pulls it down.
#[test]
fn price_monotonic_along_curve() {
    let mut pmm = PrimaryMarketMaker::new();
    let p0 = pmm.price_micro_usd();
    pmm.buy_with_usdt(usdt(1_000_000)).unwrap();
    let p1 = pmm.price_micro_usd();
    assert!(p1 > p0, "buying raises price");
    let max = pmm.max_redeemable_stell();
    pmm.sell_stell(max).unwrap();
    let p2 = pmm.price_micro_usd();
    assert!(p2 < p1, "selling lowers price");
}

/// Concurrency-equivalent determinism: two PMMs fed the same trades agree exactly.
#[test]
fn identical_trades_yield_identical_state() {
    let mut a = PrimaryMarketMaker::new();
    let mut b = PrimaryMarketMaker::new();
    for amt in [500u64, 3_000, 12_345, 999] {
        a.buy_with_usdt(usdt(amt)).unwrap();
        b.buy_with_usdt(usdt(amt)).unwrap();
    }
    let da = a.max_redeemable_stell();
    let db = b.max_redeemable_stell();
    assert_eq!(a, b);
    assert_eq!(da, db);
    assert_eq!(a.price_micro_usd(), b.price_micro_usd());
}

/// The ring-fenced buffer equals the configured ratio of buy proceeds.
#[test]
fn buffer_matches_ratio() {
    let mut pmm = PrimaryMarketMaker::new();
    pmm.buy_with_usdt(usdt(100_000)).unwrap();
    let expected = usdt(100_000) as u128 * PMM_REDEMPTION_BUFFER_BPS as u128 / 10_000;
    assert_eq!(pmm.redemption_buffer_micro, expected);
}
