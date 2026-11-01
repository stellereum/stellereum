//! Economic audit of the staking ledger (2026-11-01).
//!
//! Scope: `src/staking.rs` (+ `src/tokenomics.rs` for the genesis vault)
//! behavior only. These tests pin the MONEY invariants:
//!
//!  * CONSERVATION: stake is never created or destroyed except through the
//!    priced gates — bond/delegate (inflow), withdraw (outflow), slash
//!    (stake → `total_burned`, 1:1). Rewards are minted once (`rewards_minted`,
//!    capped) and every claim drains the backing pool 1:1.
//!  * ROUNDING: slash floors (favors the offender, never the protocol);
//!    delegator cuts floor (dust stays staked, never swept); lazy rewards
//!    truncate the rate (dust stays locked in the pool, never swept).
//!  * NO PANICS: adversarial `u64::MAX`/zero/dust values fail closed with
//!    `Err`, never with an arithmetic panic, on any reachable ledger state.
//!
//! The centerpiece is a deterministic operation fuzzer (fixed seed, no
//! `rand`, no clock): N random ops over M accounts asserting the supply
//! invariant after EVERY step.

use stellereum::staking::{
    StakingError, StakingLedger, BPS_DENOMINATOR, DEFAULT_COMMISSION_BPS, DOWNTIME_SLASH_BPS,
    EQUIVOCATION_SLASH_BPS, MAX_ACTIVE_VALIDATORS, MICRO_COMMITTEE_SLASH_BPS, MIN_DELEGATION,
    MIN_VALIDATOR_BOND, REWARDS_EMISSION_CAP, UNBONDING_PERIOD_SECS,
};
use stellereum::tokenomics::{GenesisVault, GENESIS_VAULT_CAP};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}
fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}
fn del(n: u8) -> [u8; 32] {
    [0xD0u8.wrapping_add(n); 32]
}
fn floor_nano() -> u64 {
    stellereum::staking::required_bond_floor_nano()
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64): reproducible on every machine.
// ---------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next() % n
    }
}

// ---------------------------------------------------------------------------
// Ledger census helpers: every nano accounted for, in u128 (exact).
// ---------------------------------------------------------------------------

/// Active stake buckets: self-bond aggregates + delegated aggregates.
fn active_stake(l: &StakingLedger) -> u128 {
    l.validators
        .values()
        .map(|v| v.self_bond as u128 + v.delegated as u128)
        .sum()
}
fn unbonding_sum(l: &StakingLedger) -> u128 {
    l.unbonding.iter().map(|e| e.amount as u128).sum()
}
fn withdrawable_sum(l: &StakingLedger) -> u128 {
    l.withdrawable.values().map(|a| *a as u128).sum()
}
/// Map/aggregate consistency: the per-delegator map must equal the aggregate.
fn delegations_map_sum(l: &StakingLedger) -> u128 {
    l.delegations.values().map(|a| *a as u128).sum()
}
fn delegated_aggregate_sum(l: &StakingLedger) -> u128 {
    l.validators.values().map(|v| v.delegated as u128).sum()
}
/// Every delegator entitlement: settled map + lazy unsettled, over the union
/// of live positions and leftover settled rows.
fn total_delegator_entitlement(l: &StakingLedger) -> u128 {
    use std::collections::HashSet;
    let mut keys: HashSet<([u8; 32], [u8; 32])> = HashSet::new();
    for k in l.delegations.keys() {
        keys.insert(*k);
    }
    for k in l.delegator_rewards.keys() {
        keys.insert(*k);
    }
    keys.iter()
        .map(|(v, d)| l.delegator_rewards_of(*d, *v) as u128)
        .sum()
}
fn validator_pending_sum(l: &StakingLedger) -> u128 {
    l.validators
        .values()
        .map(|v| v.pending_rewards as u128)
        .sum()
}

// ---------------------------------------------------------------------------
// 1. THE CONSERVATION FUZZER.
// ---------------------------------------------------------------------------

/// Property test: 3000 randomized ledger ops over 5 validators / 8
/// delegators with boundary-biased amounts. After EVERY op:
///
///  A. active + unbonding + withdrawable + burned == bonded_in − withdrawn
///  B. rewards_pool + claimed == rewards_minted (and minted ≤ cap)
///  C. outstanding entitlements (validator pending + delegator total) ≤ pool
///  D. delegations map == delegated aggregates (no drift)
///  E. no op ever panics (boundary values fail closed with Err)
#[test]
fn conservation_holds_over_randomized_bond_slash_reward_unbond_sequences() {
    const OPS: usize = 3000;
    const N_VAL: u8 = 5;
    const N_DEL: u8 = 8;

    // Boundary-biased amount pool: zero, dust, minimums ± 1, floor ± 1,
    // realistic sizes, and u64::MAX-scale adversarials.
    let edge: Vec<u64> = vec![
        0,
        1,
        2,
        7,
        MIN_DELEGATION - 1,
        MIN_DELEGATION,
        MIN_DELEGATION + 1,
        MIN_VALIDATOR_BOND - 1,
        MIN_VALIDATOR_BOND,
        MIN_VALIDATOR_BOND + 1,
        floor_nano() - 1,
        floor_nano(),
        floor_nano() + 1,
        stell(1),
        stell(999),
        stell(1100),
        stell(50_000),
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
        u64::MAX / 2 + 1,
    ];

    let mut rng = Lcg(0xEC0A_0FE1_CAFE_0007);
    let mut l = StakingLedger::new();
    let mut bonded_in: u128 = 0;
    let mut withdrawn_out: u128 = 0;
    let mut claimed_out: u128 = 0;
    // u128-exact burn ledger: the on-ledger `total_burned` counter is u64 and
    // saturates at u64::MAX (transparency only — stake buckets stay exact),
    // so the harness tracks the true cumulative burn separately and pins the
    // counter as `min(expected, MAX)`.
    let mut burned_expected: u128 = 0;
    let mut now: u64 = 1_000_000;
    let mut saw_bond = false;
    let mut saw_slash = false;
    let mut saw_reward = false;
    let mut saw_claim = false;
    let mut saw_withdraw = false;
    let mut saw_fail_closed = false;

    for step in 0..OPS {
        // Monotone chain clock (block timestamps never go backwards).
        now = now.saturating_add(rng.below(100_000));
        let v = vid(1 + (rng.below(N_VAL as u64) as u8));
        let d = del(rng.below(N_DEL as u64) as u8);
        let amount = edge[(rng.below(edge.len() as u64)) as usize];
        let bounced = rng.below(7) == 0; // sometimes-absurd bps/commission
        match rng.below(100) {
            0..=9 => {
                // BOND a fresh validator (or fail closed).
                let commission = if bounced {
                    10_001 + rng.below(1000)
                } else {
                    rng.below(BPS_DENOMINATOR + 1)
                };
                match l.bond(v, amount, commission) {
                    Ok(()) => {
                        bonded_in += amount as u128;
                        saw_bond = true;
                    }
                    Err(_) => saw_fail_closed = true,
                }
            }
            10..=17 => {
                // ADD_BOND top-up (or fail closed on overflow/unknown).
                match l.add_bond(v, amount) {
                    Ok(()) => bonded_in += amount as u128,
                    Err(_) => saw_fail_closed = true,
                }
            }
            18..=32 => {
                // DELEGATE (or fail closed).
                match l.delegate(d, v, amount) {
                    Ok(()) => bonded_in += amount as u128,
                    Err(_) => saw_fail_closed = true,
                }
            }
            33..=43 => {
                // UNBOND self-bond (or fail closed).
                if l.unbond(v, amount, now).is_err() {
                    saw_fail_closed = true;
                }
            }
            44..=54 => {
                // UNDELEGATE (or fail closed).
                if l.undelegate(d, v, amount, now).is_err() {
                    saw_fail_closed = true;
                }
            }
            55..=60 => {
                // MATURE unbondings.
                if l.process_unbonding(now).is_err() {
                    // Fail-closed overflow refusal: entries stay pending.
                    saw_fail_closed = true;
                }
            }
            61..=66 => {
                // WITHDRAW self-bond (or fail closed).
                match l.withdraw(v) {
                    Ok(a) => {
                        withdrawn_out += a as u128;
                        saw_withdraw = true;
                    }
                    Err(_) => saw_fail_closed = true,
                }
            }
            67..=72 => {
                // WITHDRAW delegator (or fail closed).
                match l.withdraw_delegator(d, v) {
                    Ok(a) => {
                        withdrawn_out += a as u128;
                        saw_withdraw = true;
                    }
                    Err(_) => saw_fail_closed = true,
                }
            }
            73..=82 => {
                // SLASH with a protocol-realistic bps (or fail closed).
                let bps = [
                    0,
                    1,
                    10,
                    DOWNTIME_SLASH_BPS,
                    100,
                    EQUIVOCATION_SLASH_BPS,
                    1000,
                    5000,
                    10_000,
                ][(rng.below(9)) as usize];
                match l.slash(v, bps) {
                    Ok(b) => {
                        burned_expected += b as u128;
                        if b > 0 {
                            saw_slash = true;
                        }
                    }
                    Err(_) => saw_fail_closed = true,
                }
            }
            83..=91 => {
                // DISTRIBUTE reward (or fail closed over cap/unknown).
                match l.distribute_reward(v, amount) {
                    Ok(()) => saw_reward = true,
                    Err(_) => saw_fail_closed = true,
                }
            }
            92..=95 => {
                // CLAIM validator rewards (or fail closed on shortfall).
                match l.claim_validator_rewards(v) {
                    Ok(a) => {
                        claimed_out += a as u128;
                        if a > 0 {
                            saw_claim = true;
                        }
                    }
                    Err(_) => saw_fail_closed = true,
                }
            }
            _ => {
                // CLAIM delegator rewards (0 = nothing claimable, intact).
                let a = l.claim_delegator_rewards(d, v);
                claimed_out += a as u128;
                if a > 0 {
                    saw_claim = true;
                }
            }
        }

        // ---- INVARIANT A: stake conservation (u128-exact). ----
        let active = active_stake(&l);
        let unbond = unbonding_sum(&l);
        let wd = withdrawable_sum(&l);
        assert_eq!(
            active + unbond + wd + burned_expected,
            bonded_in - withdrawn_out,
            "step {step}: STAKE CONSERVATION BROKEN (active {active} + unbond {unbond} + wd {wd} + burned {burned_expected} != in {bonded_in} − out {withdrawn_out})"
        );
        // ---- INVARIANT A2: the transparency counter tracks the burn exactly
        // until u64::MAX, then saturates (live supplies never reach it).
        assert_eq!(
            l.total_burned as u128,
            burned_expected.min(u64::MAX as u128),
            "step {step}: total_burned counter diverged"
        );
        // ---- INVARIANT B: rewards conservation + cap. ----
        assert_eq!(
            l.rewards_pool as u128 + claimed_out,
            l.rewards_minted as u128,
            "step {step}: REWARDS CONSERVATION BROKEN"
        );
        assert!(
            (l.rewards_minted as u128) <= REWARDS_EMISSION_CAP as u128,
            "step {step}: emission cap exceeded"
        );
        // ---- INVARIANT C: the pool covers every outstanding entitlement. ----
        let outstanding = validator_pending_sum(&l) + total_delegator_entitlement(&l);
        assert!(
            outstanding <= l.rewards_pool as u128,
            "step {step}: outstanding {outstanding} exceeds pool {} (mint-from-nothing)",
            l.rewards_pool
        );
        // ---- INVARIANT D: map/aggregate consistency (the old drift class). ----
        assert_eq!(
            delegations_map_sum(&l),
            delegated_aggregate_sum(&l),
            "step {step}: delegation map drifted from aggregate"
        );
    }

    // The run must have exercised every money path, including failures.
    assert!(saw_bond, "fuzz must include bonds");
    assert!(saw_slash, "fuzz must include slashes");
    assert!(saw_reward, "fuzz must include rewards");
    assert!(saw_claim, "fuzz must include claims");
    assert!(saw_withdraw, "fuzz must include withdrawals");
    assert!(saw_fail_closed, "fuzz must include fail-closed refusals");

    // Conservation verdict, stated as numbers.
    assert_eq!(
        active_stake(&l) + unbonding_sum(&l) + withdrawable_sum(&l) + burned_expected,
        bonded_in - withdrawn_out,
        "FINAL stake conservation"
    );
    assert_eq!(
        l.total_burned as u128,
        burned_expected.min(u64::MAX as u128),
        "FINAL burn counter"
    );
    assert_eq!(
        l.rewards_pool as u128 + claimed_out,
        l.rewards_minted as u128,
        "FINAL rewards conservation"
    );
}

// ---------------------------------------------------------------------------
// 2. ROUNDING PINS.
// ---------------------------------------------------------------------------

/// Slash math floors: the burn is `floor(total * bps / 10_000)` — the dust
/// favors the offender, never the protocol. Pin the direction AND the
/// conservation (stake decrease == burned == total_burned delta).
#[test]
fn slash_rounds_against_the_protocol_not_the_validator() {
    let mut l = StakingLedger::new();
    // floor (1100 STELL) + 1 nano: 5% = 55000000000.05 → floors to .00.
    let bond = floor_nano() + 1;
    l.bond(vid(1), bond, DEFAULT_COMMISSION_BPS).unwrap();
    let before = l.total_stake(&vid(1));
    let burned = l.slash(vid(1), EQUIVOCATION_SLASH_BPS).unwrap();
    let exact_floor = (bond as u128 * EQUIVOCATION_SLASH_BPS as u128 / 10_000u128) as u64;
    assert_eq!(burned, 55_000_000_000, "floor(1100000000001 * 5%)");
    assert_eq!(burned, exact_floor);
    assert_eq!(
        l.total_stake(&vid(1)),
        before - burned,
        "stake − burned, exactly"
    );
    assert_eq!(l.total_burned, burned, "burned is tracked 1:1");
    // Micro-committee arm is EXACT at 100%: burned == total, nothing left.
    let mut m = StakingLedger::new();
    m.bond(vid(2), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    m.delegate(del(1), vid(2), stell(1000)).unwrap();
    let total = m.total_stake(&vid(2));
    assert_eq!(total, stell(3000));
    let burned100 = m.slash(vid(2), MICRO_COMMITTEE_SLASH_BPS).unwrap();
    assert_eq!(
        burned100, total,
        "100% slash burns the whole stake, exactly"
    );
    assert_eq!(m.total_stake(&vid(2)), 0);
    assert_eq!(m.total_burned, total);
}

/// Delegated-leg slash dust stays STAKED (favors the slashed delegators, is
/// never swept to the protocol): per-delegator cuts floor, the remainder is
/// simply not burned, and the books stay exact.
#[test]
fn delegator_slash_dust_stays_staked_never_swept() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    // Three odd stakes so the proportional cuts truncate.
    l.delegate(del(1), vid(1), stell(1000) + 1).unwrap();
    l.delegate(del(2), vid(1), stell(1000) + 2).unwrap();
    l.delegate(del(3), vid(1), stell(1000) + 3).unwrap();
    let stake_before = l.total_stake(&vid(1));
    // Burn everything of self first, then spill into delegations: slash 50%.
    let burned = l.slash(vid(1), 5_000).unwrap();
    let stake_after = l.total_stake(&vid(1));
    assert_eq!(
        stake_before - stake_after,
        burned,
        "every burned nano left a stake bucket"
    );
    assert_eq!(l.total_burned, burned);
    // The burn cannot exceed the exact 50% (floors only reduce it).
    let exact_half = (stake_before as u128 * 5000 / 10_000) as u64;
    assert!(burned <= exact_half, "floors never burn MORE than exact");
    assert!(
        exact_half - burned < 3,
        "dust is bounded by the delegator count, got {}",
        exact_half - burned
    );
    // Map and aggregate agree to the nano.
    assert_eq!(delegations_map_sum(&l), delegated_aggregate_sum(&l));
}

/// Lazy rewards truncate fairly: no delegator is ever OVER-paid versus the
/// exact pro-rata share, the validator leg is exact, and the dust stays
/// locked in the pool (protocol-favoring, unexploitable).
#[test]
fn rewards_truncate_fairly_and_dust_stays_in_the_pool() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(1100), 1_000).unwrap();
    l.delegate(del(1), vid(1), stell(1000) + 1).unwrap();
    l.delegate(del(2), vid(1), stell(1000) + 2).unwrap();
    let delegated = l.validators[&vid(1)].delegated;
    let reward = stell(200);
    l.distribute_reward(vid(1), reward).unwrap();

    // Exact pro-rata reference (validator leg identical by construction).
    let total = stell(1100) + delegated;
    let delegated_share = (reward as u128 * delegated as u128 / total as u128) as u64;
    let commission = (delegated_share as u128 * 1000 / 10_000) as u64;
    let validator_leg = reward - delegated_share + commission;
    let pool = delegated_share - commission;
    assert_eq!(l.claim_validator_rewards(vid(1)).unwrap(), validator_leg);

    let mut paid = 0u64;
    for (i, extra) in [1u64, 2].iter().enumerate() {
        let d = del((i + 1) as u8);
        let stake = stell(1000) + extra;
        let exact = (pool as u128 * stake as u128 / delegated as u128) as u64;
        let got = l.claim_delegator_rewards(d, vid(1));
        assert!(
            got <= exact,
            "delegator {i}: never over-paid ({got} > {exact})"
        );
        assert!(exact - got <= 1, "delegator {i}: off by more than a nano");
        paid += got;
    }
    // Conservation: minted == validator leg + delegator payouts + pool dust.
    assert_eq!(l.rewards_minted, reward);
    assert_eq!(l.rewards_pool, reward - validator_leg - paid);
    // Second claims pay nothing (no double-claim).
    assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), 0);
}

// ---------------------------------------------------------------------------
// 3. MICRO-COMMITTEE 100% BURN ACCOUNTING.
// ---------------------------------------------------------------------------

/// 100% slash burns the ENTIRE slashable base (self + active delegated +
/// in-flight unbonding), tracks it 1:1 in `total_burned`, and clears the
/// delegator map exactly (no orphaned positions in the exact case).
#[test]
fn micro_committee_100_percent_burn_is_exact_and_conserving() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();
    l.delegate(del(2), vid(1), stell(500)).unwrap();
    l.undelegate(del(2), vid(1), stell(200), 0).unwrap(); // in-flight stake
    let slashable_before = active_stake(&l) + unbonding_sum(&l) + withdrawable_sum(&l);
    let burned = l.slash(vid(1), MICRO_COMMITTEE_SLASH_BPS).unwrap();
    assert_eq!(burned as u128, slashable_before, "100% burns the whole base");
    assert_eq!(active_stake(&l), 0);
    assert_eq!(unbonding_sum(&l), 0);
    assert_eq!(l.total_burned, burned);
    assert!(
        l.delegations.is_empty(),
        "exact 100% cut leaves no orphaned delegation rows"
    );
}

// ---------------------------------------------------------------------------
// 4. OVERFLOW ADVERSARIALS (u64::MAX / zero / dust): fail closed, no panic.
// ---------------------------------------------------------------------------

/// Adversarial unbonding stack (2× u64::MAX pending across entries): the old
/// `Iterator::sum` panicked here in debug (wrapped in release, understating
/// the slashable base). The saturating sums refuse to panic; the haircut cap
/// keeps consumption within `burn` so conservation holds to the nano.
/// The u64 `total_burned` transparency counter saturates at u64::MAX while
/// the stake buckets stay exact (unreachable at live supplies).
#[test]
fn adversarial_unbonding_stack_never_panics_and_conserves() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), u64::MAX, 0).unwrap();
    l.unbond(vid(1), u64::MAX, 0).unwrap(); // entry #1: MAX, self → 0
    l.add_bond(vid(1), u64::MAX).unwrap(); // self → MAX again
    l.unbond(vid(1), u64::MAX, 0).unwrap(); // entry #2: MAX, self → 0
    assert_eq!(unbonding_sum(&l), 2 * u64::MAX as u128);

    // Full 100% slash over the saturated base: no panic, exact books.
    // burn = MAX (saturated base); entry #1 is consumed in full, entry #2
    // is untouched — consumption never exceeds burn, conservation exact.
    let bonded_in = 2 * u64::MAX as u128;
    let burned = l.slash(vid(1), 10_000).unwrap();
    assert_eq!(burned, u64::MAX, "saturated base MAX → burn MAX");
    assert_eq!(l.unbonding.len(), 1, "only burn-covered entries are consumed");
    assert_eq!(
        active_stake(&l) + unbonding_sum(&l) + withdrawable_sum(&l) + burned as u128,
        bonded_in,
        "conservation holds over adversarial state"
    );
    // The remainder is still slashable: second burn consumes entry #2.
    let burned2 = l.slash(vid(1), 10_000).unwrap();
    assert_eq!(burned2, u64::MAX);
    assert_eq!(active_stake(&l) + unbonding_sum(&l), 0);
    // The transparency counter saturates at u64::MAX (2×MAX burned, MAX
    // counted) while the money path — the returned `burned` amounts the
    // caller debits from the pool — stayed exact both times.
    assert_eq!(l.total_burned, u64::MAX);
}

/// Maturing an overflow-scale queue fails closed (entries stay pending,
/// retried next block) instead of panicking or destroying dust.
#[test]
fn overflow_scale_maturation_fails_closed_not_panics() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), u64::MAX, 0).unwrap();
    l.unbond(vid(1), u64::MAX, 0).unwrap();
    l.add_bond(vid(1), u64::MAX).unwrap();
    l.unbond(vid(1), u64::MAX, 0).unwrap();
    // Both entries mature, but their sum (2×MAX) cannot fit one withdrawable
    // key: the maturation refuses and BOTH entries stay pending.
    let res = l.process_unbonding(UNBONDING_PERIOD_SECS + 1);
    assert_eq!(res, Err(StakingError::ArithmeticOverflow));
    assert_eq!(l.unbonding.len(), 2, "refused maturation destroys nothing");
    assert_eq!(l.withdrawable_of(&vid(1)), 0);
}

/// Zero and dust amounts: bond/delegate minimums refuse, zero unbond/claim
/// paths are no-ops that move nothing and panic nowhere.
#[test]
fn zero_and_dust_amounts_move_nothing_and_panic_nowhere() {
    let mut l = StakingLedger::new();
    assert_eq!(l.bond(vid(1), 0, 0), Err(StakingError::BondBelowMinimum));
    assert_eq!(l.bond(vid(1), 1, 0), Err(StakingError::BondBelowMinimum));
    l.bond(vid(1), floor_nano(), 0).unwrap();
    assert_eq!(
        l.delegate(del(1), vid(1), 0),
        Err(StakingError::DelegationBelowMinimum)
    );
    assert_eq!(
        l.delegate([0u8; 32], vid(1), stell(5)),
        Err(StakingError::ZeroAddress)
    );
    // Zero unbond is accepted but creates a zero entry that matures to zero.
    l.unbond(vid(1), 0, 0).unwrap();
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    assert_eq!(l.withdrawable_of(&vid(1)), 0);
    assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
    // Zero reward is a no-op; unknown/zero-stake validators refuse (no mint).
    assert!(l.distribute_reward(vid(1), 0).is_ok());
    assert_eq!(l.rewards_minted, 0);
    l.unbond(vid(1), floor_nano(), 0).unwrap(); // full exit, self → 0
    assert_eq!(
        l.distribute_reward(vid(1), stell(1)),
        Err(StakingError::NotValidator),
        "zero-stake validator must not mint"
    );
    assert_eq!(l.rewards_minted, 0, "refused distribution mints nothing");
    assert_eq!(
        l.distribute_reward(vid(9), stell(1)),
        Err(StakingError::NotValidator)
    );
}

/// `u64::MAX` reward / top-up attempts fail closed without panic and without
/// minting or crediting anything.
#[test]
fn max_value_reward_and_topup_fail_closed() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), floor_nano(), 0).unwrap();
    assert_eq!(
        l.distribute_reward(vid(1), u64::MAX),
        Err(StakingError::RewardsCapExceeded)
    );
    assert_eq!(l.rewards_minted, 0);
    assert_eq!(l.rewards_pool, 0);
    assert_eq!(l.validators[&vid(1)].pending_rewards, 0);
    // add_bond that would overflow refuses instead of saturating at MAX.
    l.add_bond(vid(1), u64::MAX - floor_nano()).unwrap(); // self → MAX
    assert_eq!(l.validators[&vid(1)].self_bond, u64::MAX);
    assert_eq!(l.add_bond(vid(1), 1), Err(StakingError::ArithmeticOverflow));
    assert_eq!(
        l.validators[&vid(1)].self_bond,
        u64::MAX,
        "refused top-up moves nothing"
    );
}

// ---------------------------------------------------------------------------
// 5. VALIDATOR-SET DERIVATION UNDER ADVERSARIAL POWER.
// ---------------------------------------------------------------------------

/// Power table with adversarial values: saturating stake, deterministic
/// order (highest first, id tiebreak), hard cap at 250 — and no panic.
#[test]
fn validator_set_derivation_is_exact_under_adversarial_power() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), u64::MAX, 0).unwrap();
    l.bond(vid(2), u64::MAX - 1, 0).unwrap();
    l.bond(vid(3), floor_nano(), 0).unwrap();
    // Saturating total: MAX self + MAX delegated would wrap a naive add.
    l.delegate(del(1), vid(3), u64::MAX).unwrap();
    assert_eq!(
        l.total_stake(&vid(3)),
        u64::MAX,
        "total saturates, never wraps"
    );
    let vs = l.to_validator_set();
    let powers: Vec<u64> = vs.validators.values().copied().collect();
    assert!(powers.contains(&u64::MAX));
    // Deterministic ranking: MAX powers first.
    let ranked = {
        let mut v: Vec<([u8; 32], u64)> = vs.validators.iter().map(|(id, p)| (*id, *p)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    };
    assert_eq!(ranked[0].1, u64::MAX);
    // Cap: 260 bonded validators elect exactly 250.
    let mut big = StakingLedger::new();
    for i in 0..260u32 {
        let mut id = [0xBBu8; 32];
        id[0] = (i & 0xff) as u8;
        id[1] = ((i >> 8) & 0xff) as u8;
        big.bond(id, floor_nano() + (i as u64), 0).unwrap();
    }
    assert_eq!(
        big.to_validator_set().validators.len(),
        MAX_ACTIVE_VALIDATORS
    );
    assert_eq!(big.elected_count(), MAX_ACTIVE_VALIDATORS);
}

// ---------------------------------------------------------------------------
// 6. UNBONDING PERIOD: no instant exit, no bypass.
// ---------------------------------------------------------------------------

/// Every exit waits out the full cooldown: early withdraw fails, maturity is
/// exact at `release_at`, each batch pays exactly once, and a far-future
/// clock saturates (fail-closed lock, never an early release).
#[test]
fn unbonding_cooldown_has_no_instant_exit_or_bypass() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(5000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();
    l.unbond(vid(1), stell(1000), 1_000).unwrap();
    l.undelegate(del(1), vid(1), stell(400), 1_000).unwrap();

    // Before maturity: nothing withdrawable, both withdraws fail.
    l.process_unbonding(1_000).unwrap();
    assert_eq!(l.withdrawable_of(&vid(1)), 0);
    assert_eq!(l.withdrawable_delegator(&vid(1), &del(1)), 0);
    assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
    assert_eq!(
        l.withdraw_delegator(del(1), vid(1)),
        Err(StakingError::NothingToWithdraw)
    );
    // One second before release: still nothing.
    l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS - 1)
        .unwrap();
    assert_eq!(l.withdrawable_of(&vid(1)), 0);
    // Exactly at release: both batches mature, each pays exactly once.
    l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS).unwrap();
    assert_eq!(l.withdrawable_of(&vid(1)), stell(1000));
    assert_eq!(l.withdrawable_delegator(&vid(1), &del(1)), stell(400));
    assert_eq!(l.withdraw(vid(1)).unwrap(), stell(1000));
    assert_eq!(l.withdraw_delegator(del(1), vid(1)).unwrap(), stell(400));
    assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
    // Double-unbond batches are independent (no single-batch lock).
    l.unbond(vid(1), stell(1000), 2_000).unwrap();
    l.unbond(vid(1), stell(1000), 3_000).unwrap();
    l.process_unbonding(3_000 + UNBONDING_PERIOD_SECS).unwrap();
    assert_eq!(l.withdrawable_of(&vid(1)), stell(2000));
}

/// Far-future unbond saturates `release_at` (fail-closed): the funds stay
/// locked until the chain clock actually reaches u64::MAX — never released
/// early by a wrapped timestamp.
#[test]
fn far_future_unbond_saturates_fail_closed() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(5000), DEFAULT_COMMISSION_BPS).unwrap();
    l.unbond(vid(1), stell(1000), u64::MAX).unwrap();
    assert_eq!(l.unbonding[0].release_at, u64::MAX);
    l.process_unbonding(u64::MAX - 1).unwrap();
    assert_eq!(
        l.withdrawable_of(&vid(1)),
        0,
        "saturated lock releases nothing early"
    );
    assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
}

// ---------------------------------------------------------------------------
// 7. GENESIS ALLOCATIONS (tokenomics): cap is exact, absurd mints saturate.
// ---------------------------------------------------------------------------

/// The 250M STELL genesis vault cap is exact: minting exactly to the cap
/// succeeds, one nano more fails closed — and an absurd mint saturates to
/// `u64::MAX` (refused over-cap) instead of wrapping to dust and sneaking
/// under the cap.
#[test]
fn genesis_vault_cap_is_exact_and_absurd_mints_saturate() {
    // calculate_mint is exact on the reference values.
    // 1 USDT ($1) at $1 → 1/0.25 = 4 STELL.
    assert_eq!(
        GenesisVault::calculate_mint(1_000_000, 6, 1_000_000),
        stell(4)
    );
    // Absurd inputs saturate instead of wrapping to a small number.
    assert_eq!(
        GenesisVault::calculate_mint(u64::MAX, 6, u64::MAX),
        u64::MAX
    );
    assert_eq!(
        GenesisVault::calculate_mint(u64::MAX, 9, u64::MAX),
        u64::MAX
    );

    let mut vault = GenesisVault::new();
    // Fill exactly to the cap with repeated mints.
    vault.total_minted_nano = GENESIS_VAULT_CAP - stell(4);
    vault
        .deposit_and_mint("USDT", 1_000_000, 1_000_000)
        .unwrap();
    assert_eq!(vault.total_minted_nano, GENESIS_VAULT_CAP);
    // One nano over the cap fails closed and moves nothing.
    let before = vault.clone();
    assert!(vault
        .deposit_and_mint("USDT", 1_000_000, 1_000_000)
        .is_err());
    assert_eq!(vault.total_minted_nano, before.total_minted_nano);
    assert_eq!(vault.usdt_deposited_micro, before.usdt_deposited_micro);
    // A saturating (absurd) mint is refused over-cap, never wrapped-accepted.
    let mut v2 = GenesisVault::new();
    assert!(v2.deposit_and_mint("USDT", u64::MAX, u64::MAX).is_err());
    assert_eq!(v2.total_minted_nano, 0);
    assert_eq!(v2.usdt_deposited_micro, 0);
    // Unknown asset fails closed.
    assert!(v2.deposit_and_mint("DOGE", 100, 100).is_err());
}

/// Genesis bonds bypass the MIN+buffer floor (grandfathered) but the
/// validator-set filter still applies: below-MIN genesis stake is tracked
/// yet unelected — pinned so a floor change can never silently elect it.
#[test]
fn genesis_floor_bypass_is_tracked_but_unelected_below_min() {
    let mut l = StakingLedger::new();
    l.bond_genesis(vid(1), MIN_VALIDATOR_BOND - 1, 0).unwrap();
    assert_eq!(l.total_stake(&vid(1)), MIN_VALIDATOR_BOND - 1);
    assert!(
        !l.to_validator_set().validators.contains_key(&vid(1)),
        "below-MIN genesis stake must not be elected"
    );
    l.bond_genesis(vid(2), MIN_VALIDATOR_BOND, 0).unwrap();
    assert!(l.to_validator_set().validators.contains_key(&vid(2)));
}

// ---------------------------------------------------------------------------
// 8. DEFENSIVE MICRO-FIXES (staking-economics audit 2026-11-01, lows).
// ---------------------------------------------------------------------------

// Low (b), behavior-preservation at COMPILE time: every live slash constant
// is in range, so the new `BadSlashBps` gate is a no-op on all reachable
// paths (`slash` wrappers pass only these constants). A future constant
// bump past 10_000 fails the build here, not a slash at runtime.
const _: () = assert!(DOWNTIME_SLASH_BPS <= BPS_DENOMINATOR);
const _: () = assert!(EQUIVOCATION_SLASH_BPS <= BPS_DENOMINATOR);
const _: () = assert!(MICRO_COMMITTEE_SLASH_BPS <= BPS_DENOMINATOR);

/// Low (b): `slash` with `bps > 10_000` is refused fail-closed with
/// `BadSlashBps` and moves NOTHING (no stake change, no `total_burned`
/// change, no map/aggregate drift). Without the gate a `bps > 10_000` would
/// compute `burn > total` while every consumption below is clamped by real
/// stake, so the excess would silently vanish into `remaining` — destroyed
/// value that neither stays staked nor reaches `total_burned`.
#[test]
fn slash_bps_over_10000_is_refused_fail_closed() {
    use stellereum::staking::BPS_DENOMINATOR;
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(5000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();
    let stake_before = l.total_stake(&vid(1));
    let burned_before = l.total_burned;
    for bps in [BPS_DENOMINATOR + 1, 10_001, 15_000, 20_000, u64::MAX] {
        assert_eq!(
            l.slash(vid(1), bps),
            Err(StakingError::BadSlashBps),
            "bps {bps} must be refused"
        );
    }
    // The gate fires before the membership lookup: unknown validators get
    // the bps error, not NotValidator — input validation is order-stable.
    assert_eq!(
        l.slash(vid(9), BPS_DENOMINATOR + 1),
        Err(StakingError::BadSlashBps)
    );
    assert_eq!(l.slash(vid(9), 500), Err(StakingError::NotValidator));
    // Refused slashes move nothing.
    assert_eq!(l.total_stake(&vid(1)), stake_before);
    assert_eq!(l.total_burned, burned_before);
    assert_eq!(delegations_map_sum(&l), delegated_aggregate_sum(&l));
    assert!(!format!("{}", StakingError::BadSlashBps).is_empty());
}

/// Low (b), behavior-preservation: every valid `bps` (0..=10_000) behaves
/// EXACTLY as before the gate — `floor(total * bps / 10_000)` burned 1:1
/// into `total_burned` — and every live slash constant is in range, so no
/// reachable path can hit the new refusal.
#[test]
fn slash_bps_boundaries_pass_identical() {
    use stellereum::staking::BPS_DENOMINATOR;
    // The live slash constants are pinned in range by the compile-time
    // asserts above; the 100% arm is exactly the denominator.
    assert_eq!(MICRO_COMMITTEE_SLASH_BPS, BPS_DENOMINATOR);
    // Boundary sweep on fresh ledgers: exact floor, 1:1 burn tracking.
    for bps in [0u64, 1, 10, DOWNTIME_SLASH_BPS, 100, EQUIVOCATION_SLASH_BPS, 1000, 5000, 9999, 10_000] {
        let mut l = StakingLedger::new();
        let bond = stell(2000) + 7; // +7 dust so floors are load-bearing
        l.bond(vid(1), bond, DEFAULT_COMMISSION_BPS).unwrap();
        let expected = (bond as u128 * bps as u128 / BPS_DENOMINATOR as u128) as u64;
        let burned = l.slash(vid(1), bps).unwrap();
        assert_eq!(burned, expected, "bps {bps}: burn must equal the exact floor");
        assert_eq!(l.total_stake(&vid(1)), bond - burned);
        assert_eq!(l.total_burned, burned);
    }
    // The downtime wrapper path is unchanged (0.1% of total, self-first).
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
    let expected = (stell(1100) as u128 * DOWNTIME_SLASH_BPS as u128 / 10_000u128) as u64;
    let burned = l.slash_downtime(vid(1)).unwrap();
    assert_eq!(burned, expected);
    assert_eq!(l.total_burned, burned);
}

/// Low (a), caller-side hardening: `bond` accepts any `u64` amount, so the
/// staking layer CAN feed `ValidatorSet` powers whose naive sum overflows —
/// 2+ validators at `u64::MAX` already wrap a plain `Iterator::sum` (which
/// is what the frozen `ValidatorSet::total_power` in `consensus.rs` does:
/// panic in debug, wrap in release). No production staking code calls that
/// sum (`quorum_fragility` already folds with `saturating_add`), and the new
/// `elected_total_power_saturating` gives staking-layer consumers the safe
/// fold over the exact same elected set: it saturates at `u64::MAX` and
/// never panics, while small sets stay exact.
#[test]
fn elected_total_power_saturates_without_panic_under_adversarial_bonds() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), u64::MAX, 0).unwrap();
    l.bond(vid(2), u64::MAX, 0).unwrap();
    l.bond(vid(3), u64::MAX - 1, 0).unwrap();
    // Set construction itself never sums, so it cannot panic.
    let vs = l.to_validator_set();
    assert_eq!(vs.validators.len(), 3);
    // The hardened staking-layer fold saturates instead of panicking.
    assert_eq!(l.elected_total_power_saturating(), u64::MAX);
    // Fragility reporting (the other staking-layer power fold) is panic-free.
    let _ = l.quorum_fragility();
    // Small sets stay exact: saturating fold == plain sum in range.
    let mut s = StakingLedger::new();
    s.bond(vid(1), stell(2000), 0).unwrap();
    s.bond(vid(2), stell(3000), 0).unwrap();
    assert_eq!(s.elected_total_power_saturating(), stell(5000));
}
