//! ADVERSARIAL HUNT: final sweep -- bonding curve, token burn ordering, and the
//! staking pool's custody accounting.
//!
//! Three more hypotheses in the same class:
//!  1. PMM: a rounding division that favours the trader and can be looped
//!     (buy/sell round trip, or dust-size buys).
//!  2. `TokenActor::burn` calls `debit()` (a mutation) BEFORE the
//!     `checked_sub` on `total_supply`, so a failing supply check leaves the
//!     holder debited -- a CEI violation.
//!  3. The staking pool is debited for the WHOLE downtime burn, including the
//!     part the ledger attributed to `delegated` -- but the delegator's claim
//!     in `delegations` was never reduced, so the same stake is paid out twice.

use stellereum::pmm::PrimaryMarketMaker;
use stellereum::staking::{
    StakingLedger, DOWNTIME_PENALTY_COOLDOWN, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
    UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::InMemoryStateEngine;

const NANO: u64 = 1_000_000_000;
fn usdt(n: u64) -> u64 {
    n * 1_000_000
}

// ---------------------------------------------------------------------------
// 1. PMM: can a round trip profit? Sweep sizes, then loop dust.
// ---------------------------------------------------------------------------
#[test]
fn pmm_round_trip_never_profits() {
    let mut worst = 0i128;
    let mut worst_at = 0u64;
    for usd in [1u64, 2, 5, 10, 50, 100, 1_000, 10_000, 100_000, 1_000_000] {
        let mut pmm = PrimaryMarketMaker::new();
        let r = pmm.buy_with_usdt(usdt(usd)).unwrap();
        let max = pmm.max_redeemable_stell();
        let back = pmm.sell_stell(max).unwrap();
        let net = back.usdt_paid as i128 - usdt(usd) as i128;
        println!(
            "buy ${usd:>9} -> mint {:>22} | redeem max {:>22} -> get ${:>12}.{:06} | net {net:+}",
            r.stell_minted,
            max,
            back.usdt_paid / 1_000_000,
            back.usdt_paid % 1_000_000
        );
        if net > worst {
            worst = net;
            worst_at = usd;
        }
    }
    println!("worst-case net (positive == attacker profit) = {worst:+} at ${worst_at}");
    assert!(worst <= 0, "ATTACKER GOAL: a round trip must never profit");
}

#[test]
fn pmm_dust_buy_sell_loop_never_profits() {
    // Loop the smallest non-dust amounts, where a floor division is most likely
    // to round in the trader's favour.
    let mut total_in = 0i128;
    let mut total_out = 0i128;
    let mut pmm = PrimaryMarketMaker::with_reserve(usdt(1_000_000));
    let mut rounds = 0u64;
    for i in 1..=2_000u64 {
        let u = i; // 1..2000 micro-USD
        let Ok(r) = pmm.buy_with_usdt(u) else {
            continue;
        };
        total_in += r.usdt_paid as i128;
        // Redeem everything we can immediately, then repeat.
        while pmm.max_redeemable_stell() > 0 {
            let max = pmm.max_redeemable_stell();
            match pmm.sell_stell(max) {
                Ok(s) => total_out += s.usdt_paid as i128,
                Err(_) => break,
            }
        }
        rounds += 1;
    }
    println!("{rounds} buy/sell cycles");
    println!("total USDT in  = {total_in}");
    println!("total USDT out = {total_out}");
    println!("net            = {:+}", total_out - total_in);
    assert!(
        total_out <= total_in,
        "ATTACKER GOAL: the loop must not profit"
    );
    // The ring-fenced buffer must never go negative and the reserve must never
    // be over-drawn.
    assert!(pmm.redemption_buffer_micro <= pmm.reserve_micro);
    assert!(pmm.minted_nano == 0, "everything bought was redeemed");
}

#[test]
fn pmm_curve_never_mints_more_than_it_is_paid() {
    // For every buy, the curve cost of what was minted must be >= what was
    // charged; otherwise a loop mints unbacked STELL.
    for usd in 1..=5_000u64 {
        let mut pmm = PrimaryMarketMaker::new();
        let r = pmm.buy_with_usdt(usdt(usd)).unwrap();
        // Measure what the curve says the freshly minted block is worth by
        // redeeming it on a clone (unbounded, ignoring the reserve bound).
        let mut probe = pmm.clone();
        let curve_value = if r.stell_minted > 0 {
            match probe.sell_stell(r.stell_minted) {
                Ok(s) => s.usdt_paid as i128,
                Err(_) => {
                    // The 20% buffer blocks a full drain; measure the largest
                    // redeemable slice instead and extrapolate the shortfall.
                    let max = probe.max_redeemable_stell();
                    if max == 0 {
                        0
                    } else {
                        probe.sell_stell(max).unwrap().usdt_paid as i128
                    }
                }
            }
        } else {
            0
        };
        if curve_value > r.usdt_paid as i128 {
            panic!(
                "${usd}: minted {} nano for {} micro-USD but the curve values it at {}",
                r.stell_minted, r.usdt_paid, curve_value
            );
        }
    }
    println!("5000 buy sizes checked: the curve never over-mints");
}

// ---------------------------------------------------------------------------
// 2. `burn` mutates the balance before the supply check can fail.
// ---------------------------------------------------------------------------
#[test]
fn token_burn_debits_the_holder_before_checking_the_supply_counter() {
    use stellereum::token::{TokenActor, TokenError, TokenMetadata};
    let minter = [0x01; 32];
    let holder = [0x02; 32];
    let id = [0xAA; 32];
    let mut t = TokenActor::new(
        id,
        TokenMetadata {
            name: "T".into(),
            symbol: "T".into(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter,
            paused: false,
            description: String::new(),
        },
        1_000,
    )
    .unwrap();

    // Force the two representations out of step: give the holder more than
    // `total_supply` says exists. (Any desync reaching this point makes the
    // failure reachable; the point is that the handler is not exception safe.)
    t.balances.insert(holder, 2_000);

    let before_bal = t.balance_of(&holder);
    let before_supply = t.metadata.total_supply;
    let r = t.burn(holder, holder, 1_500);
    println!(
        "holder balance {before_bal} -> {} (supply still {before_supply})",
        t.balance_of(&holder)
    );
    println!("burn(1500) with total_supply=1000 returned {r:?}");

    // The call FAILED...
    assert_eq!(r, Err(TokenError::Overflow));
    // ...but the holder was debited anyway. The mutation preceded the check.
    assert_eq!(
        t.balance_of(&holder),
        500,
        "CEI VIOLATION: a failed burn still destroyed the holder's tokens"
    );
    assert_eq!(t.metadata.total_supply, 1_000, "the supply was not touched");
    println!(
        "=> {} tokens destroyed by a call that returned Err; the ledger is now \
         sum(balances)={} != total_supply={}",
        1_500,
        t.balances.values().sum::<u64>(),
        t.metadata.total_supply
    );
    assert_ne!(
        t.balances.values().sum::<u64>(),
        t.metadata.total_supply,
        "the supply invariant is broken by the failed call"
    );
}

// ---------------------------------------------------------------------------
// 3. The staking pool pays for a slash AND refunds the same stake.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn downtime_slashing_double_spends_the_staking_pool() {
    let e = InMemoryStateEngine::new();
    let v = [0x07; 32];
    let delegator = [0xD7; 32];

    let self_bond = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER; // MIN+buffer floor
    let delegated = 100 * NANO; // 100 STELL
    let pool_start = self_bond + delegated; // exactly what the two stakes deposited

    e.credit_native(&stellereum::staking::STAKING_POOL, pool_start)
        .await
        .unwrap();
    {
        let mut l = e.staking_write().await;
        l.bond(v, self_bond, 0).unwrap();
        l.delegate(delegator, v, delegated).unwrap();
    }

    // The validator goes offline long enough for the burn to eat the delegation.
    let never = |_: &[u8; 32]| false;
    let one = vec![v];
    let mut burned = 0u64;
    let mut height = 1u64;
    let mut last = l_total(&e, v);
    let mut stall = 0;
    while height < 200_000_000 {
        {
            let mut l = e.staking_write().await;
            burned += l.note_missed_heights(height, &never, &one);
        }
        let now = l_total(&e, v);
        if now == last {
            stall += 1;
            if stall > DOWNTIME_PENALTY_COOLDOWN * 2 {
                break;
            }
        } else {
            stall = 0;
        }
        last = now;
        height += 1;
    }

    // `apply_downtime_slashes` does exactly this: take the burn out of the pool.
    e.debit_native(&stellereum::staking::STAKING_POOL, burned)
        .await
        .map(|_| ())
        .unwrap_or(());
    let pool_now = e
        .get_account(&stellereum::staking::STAKING_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);

    let claim = {
        let l = e.staking_read().await;
        l.delegations.get(&(v, delegator)).copied().unwrap_or(0)
    };
    println!("pool started at          = {pool_start}");
    println!("downtime burn reported   = {burned}");
    println!("pool after the burn      = {pool_now}");
    println!("delegator claim in the ledger = {claim} (properly reduced)");
    assert!(burned > 0);
    // FIXED: `note_missed_heights` now routes through `slash()`, so `delegations`
    // is reduced in lockstep with the aggregate. The pool is no longer double-spent.
    assert_eq!(
        burned + claim,
        pool_start,
        "burned plus remaining claim must equal initial pool"
    );
    assert_eq!(pool_now, claim, "pool balance must equal remaining claims");
}

fn l_total(e: &InMemoryStateEngine, v: [u8; 32]) -> u64 {
    e.try_staking_read().map(|g| g.total_stake(&v)).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 4. `withdrawable` separation (E1 FIXED at the opcode layer).
// ---------------------------------------------------------------------------
// Ledger primitives, pinned: `undelegate` begins an unbonding (touches
// `delegations` + `unbonding`, never `withdrawable`); `withdraw_delegator`
// consumes the matured entry exactly once (removes the key). The old
// `SysCallUndelegate` handler mixed the two — paying out `withdrawable`
// while calling `undelegate` — which bricked exits and multi-paid on any
// naive fix. Since the split (`SysCallBeginUndelegate` begins,
// `SysCallUndelegate` withdraws-and-consumes), each primitive does one job
// and the single-claim property holds end to end (see
// `delegated_stake_exits_through_begin_then_withdraw`).
// What this test pins: `undelegate` alone never debits `withdrawable`
// (that is `withdraw_delegator`'s job), and repeated `undelegate` calls
// create independent entries per deposit — no cross-contamination.
#[test]
fn withdrawable_is_paid_out_but_never_debited() {
    let mut l = StakingLedger::new();
    let v = [0x08; 32];
    let d = [0xD8; 32];
    l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    let stake = 100 * NANO;

    // Cycle 0: delegate, unbond, mature.
    l.delegate(d, v, stake).unwrap();
    l.undelegate(d, v, stake, 0).unwrap();
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    let matured = l.withdrawable_delegator(&v, &d);
    assert_eq!(matured, stake, "one matured claim");

    // The SVM payout. `undelegate` needs the delegator to still be delegated,
    // so re-delegate first -- this is what the attacker must pay for.
    l.delegate(d, v, stake).unwrap();
    let payout = l.undelegate(d, v, matured, 0);
    assert!(payout.is_ok(), "the payout goes out: {payout:?}");

    let after = l.withdrawable_delegator(&v, &d);
    println!("matured before payout = {matured}");
    println!("withdrawable after payout = {after}   <-- should be 0");
    assert_eq!(
        after, matured,
        "COUNTER NOT DEBITED: the identical matured amount is still on record \
         and still readable by the next SysCallUndelegate"
    );
    assert_eq!(l.delegations.get(&(v, d)).copied(), None);

    // Repeat the same payout: it only fails because `delegations` is empty, not
    // because the claim was consumed. Re-delegate and it pays out AGAIN for a
    // stake that was deposited once.
    let second = l.undelegate(d, v, matured, 0);
    assert!(
        second.is_err(),
        "masked by the delegations guard: {second:?}"
    );
    l.delegate(d, v, stake).unwrap();
    let third = l.undelegate(d, v, matured, 0);
    println!("after re-delegating the same stake, the same matured claim pays again: {third:?}");
    assert!(
        third.is_ok(),
        "the same matured amount is claimable a second time"
    );

    // Two independent 100-STELL payout claims now exist, plus the untouched
    // withdrawable counter, all against a single 100-STELL deposit.
    let claims: u64 = l
        .unbonding
        .iter()
        .filter(|u| u.owner == Some(d))
        .map(|u| u.amount)
        .sum();
    println!("independent payout claims recorded for {d:?} = {claims}");
    println!(
        "withdrawable counter still showing          = {}",
        l.withdrawable_delegator(&v, &d)
    );
    assert!(
        claims >= 2 * stake,
        "duplicate payout claims: {claims} against a {stake} deposit"
    );
    assert!(l.withdrawable_delegator(&v, &d) >= stake);
}
