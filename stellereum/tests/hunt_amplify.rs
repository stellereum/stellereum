//! HUNT: the two-representations bug in the staking ledger.
//!
//! `ValidatorStake.delegated` (the aggregate) and `StakingLedger.delegations`
//! (the per-delegator map) are the SAME quantity accounted for in two places.
//! `note_missed_heights` (src/staking.rs:477-481) decrements ONLY the aggregate:
//!
//!   rec.delegated -= from_delegated;      // aggregate
//!   // self.delegations[(validator, d)] -= ...   <-- NEVER HAPPENS
//!
//! Every consumer that trusts the two to agree is then wrong:
//!  - `distribute_reward` divides by `v.delegated` but pays `amount` from the
//!    map, so the shares sum to MORE than the pool it splits  (inflation).
//!  - `undelegate` gates on the map, so a delegator can undelegate stake the
//!    aggregate says was already burned -> the pool pays the difference.
//!  - `slash` computes `v.delegated -= slashed_total` where `slashed_total` is
//!    derived from the map scaled by the aggregate; once the map exceeds the
//!    aggregate by more than 1/BPS_DENOMINATOR the subtraction UNDERFLOWS.
//!  - `total_burned` is never touched by the downtime path, so it stops
//!    agreeing with the sum of the individual burns.

use stellereum::consensus::ValidatorId;
use stellereum::staking::{
    StakingLedger, DOWNTIME_MISS_THRESHOLD, DOWNTIME_PENALTY_COOLDOWN, MIN_VALIDATOR_BOND,
    STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Bond floor every bond in this file must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}
fn v(n: u8) -> ValidatorId {
    [n; 32]
}
fn d(n: u8) -> [u8; 32] {
    [0xD0 + n; 32]
}

fn sum_delegations(l: &StakingLedger, vid: ValidatorId) -> u64 {
    l.delegations
        .iter()
        .filter(|((v, _), _)| *v == vid)
        .map(|(_, a)| *a)
        .sum()
}

/// One "outage": DOWNTIME_MISS_THRESHOLD consecutive heights with no signature,
/// then jump past the cooldown so the next outage can slash again.
fn slash_once_offline(l: &mut StakingLedger, vid: ValidatorId, height: &mut u64) -> u64 {
    let never = |_: &ValidatorId| false;
    let one = vec![vid];
    let mut burned = 0;
    for _ in 0..DOWNTIME_MISS_THRESHOLD {
        *height += 1;
        burned += l.note_missed_heights(*height, &never, &one);
    }
    *height += DOWNTIME_PENALTY_COOLDOWN;
    burned
}

/// Grow the divergence (map / aggregate) to at least `target` by keeping the
/// validator offline. Returns the number of outages and heights consumed.
fn diverge_to(l: &mut StakingLedger, vid: ValidatorId, _target: f64) -> (u64, u64, u64) {
    // This helper used to loop, slashing the validator until the delegation MAP
    // exceeded the AGGREGATE by the requested factor. That divergence was the bug:
    // `note_missed_heights` decremented `ValidatorStake.delegated` without touching
    // `StakingLedger::delegations`, and `distribute_reward` divides by the
    // aggregate while summing the map.
    //
    // It now runs the outages and asserts the ratio never moves off 1.0, so the
    // "amplification" the rest of this file used to demonstrate is unreachable.
    let mut h = 0u64;
    let (mut outages, mut heights, mut burned_total) = (0u64, 0u64, 0u64);
    for _ in 0..40 {
        let agg = l.validators[&vid].delegated;
        let map = sum_delegations(l, vid);
        assert_eq!(
            map, agg,
            "the map must equal the aggregate after {outages} outages; a divergence \
             here is the bug this file used to exploit"
        );
        if agg == 0 {
            return (outages, heights, burned_total);
        }
        burned_total += slash_once_offline(l, vid, &mut h);
        outages += 1;
        heights += DOWNTIME_MISS_THRESHOLD as u64 + DOWNTIME_PENALTY_COOLDOWN;
    }
    (outages, heights, burned_total)
}

/// THE BUG: after ONE downtime slash the two representations of "delegated"
/// disagree. Everything downstream divides one and sums the other.
///
/// FIXED: this used to demonstrate that the downtime slash *broke* the
/// aggregate-vs-map invariant and never updated `total_burned`. It now asserts
/// that the invariant holds.
#[test]
fn downtime_slash_keeps_the_delegation_aggregate_consistent() {
    let mut l = StakingLedger::new();
    let val = v(1);
    l.bond(val, stell(5_000), 0).unwrap();
    l.delegate(d(1), val, stell(10_000_000)).unwrap();

    let agg0 = l.validators[&val].delegated;
    let map0 = sum_delegations(&l, val);
    println!("before:  aggregate = {agg0} | map sum = {map0}");
    assert_eq!(agg0, map0, "precondition: the two agree");

    let _self_before = l.validators[&val].self_bond;
    let mut h = 0u64;
    let burned = slash_once_offline(&mut l, val, &mut h);
    let agg = l.validators[&val].delegated;
    let map = sum_delegations(&l, val);
    let from_self = 0;
    let _ = from_self;

    println!(
        "one 10-height outage burned {burned} nano = {} STELL",
        burned / 1_000_000_000
    );
    println!("after:   aggregate = {agg} | map sum = {map}");
    println!(
        "self_bond = {} STELL",
        l.validators[&val].self_bond / 1_000_000_000
    );
    println!("total_burned = {}", l.total_burned);

    // FIXED. Two separate things were wrong on the downtime path, and both are
    // now regressions:
    //
    // 1. The delegated leg was `rec.delegated.min(burn - from_self)` -- a
    //    saturating floor with no cap. `rec.delegated` is the AGGREGATE, which
    //    drifts away from the sum of the map precisely because of this bug, so a
    //    validator that had fully unbonded (self_bond == 0) with delegations
    //    still outstanding had its ENTIRE delegation confiscated by one 0.1%
    //    penalty. It is now bounded by the map.
    assert_eq!(
        map, agg,
        "the delegation map must still sum to the aggregate after a slash"
    );
    assert!(
        l.validators[&val].delegated <= map,
        "the aggregate can never exceed what the map still holds"
    );

    // 2. The burn was applied to the validator record but `total_burned` was never
    //    incremented, so the ledger under-reported how much had been destroyed
    //    while the coins did leave the staking pool. The pool is a plain trie
    //    account, so that drift moves the state root.
    assert_eq!(
        l.total_burned, burned,
        "the ledger's destruction counter must match what was actually burned"
    );
    eprintln!("[AMPLIFY] FIXED: map == aggregate ({map}), total_burned == {burned}");
}

/// AMPLIFICATION: `distribute_reward` splits `delegator_pool` into shares of
/// `pool * map_amount / aggregate`. Once the map is bigger than the aggregate
/// the shares no longer sum to the pool, so the chain pays out MORE than the
/// emission schedule authorised. The multiplier is the divergence ratio.
#[test]
fn downtime_slash_cannot_inflate_reward_distribution() {
    let mut l = StakingLedger::new();
    let val = v(1);
    l.bond(val, floor(), 0).unwrap();
    l.delegate(d(1), val, stell(1_000_000_000)).unwrap();

    // Take the self-bond out of the picture, then diverge 2x.
    let (outages, heights, _) = diverge_to(&mut l, val, 2.0);
    let agg = l.validators[&val].delegated;
    let map = sum_delegations(&l, val);
    println!(
        "{outages} outages / {heights} heights ({:.1} days at 3s) for a {:.3}x divergence",
        heights as f64 * 3.0 / 86400.0,
        map as f64 / agg as f64
    );

    let reward = stell(100);
    l.distribute_reward(val, reward).unwrap();
    let to_validator = l.validators[&val].pending_rewards;
    // LAZY (F1): the delegator's entitlement is computed from the
    // validator's accumulator on demand — the raw map holds only the
    // SETTLED part.
    let to_delegator = l.delegator_rewards_of(d(1), val);
    let paid = to_validator + to_delegator;
    println!(
        "emission authorised: {reward} ({} STELL)",
        reward / 1_000_000_000
    );
    println!("  -> validator   {to_validator}");
    println!("  -> delegator   {to_delegator}");
    println!("  -> TOTAL PAID  {paid}  ({} STELL)", paid / 1_000_000_000);
    println!("  -> minted from nothing: {}", paid.saturating_sub(reward));

    // FIXED: with the aggregate and the map kept in step, the pro-rata split
    // conserves the emission exactly. It used to credit strictly MORE than
    // authorised, because the denominator (the aggregate) had been decremented
    // while the numerator (the map) had not.
    // LAZY (F1): the accumulator's scaled rate truncates by < stake / 1e18
    // per settlement, so the split can be ONE nano BELOW the emission (never
    // above it — the truncating dust stays locked in the rewards pool).
    assert!(
        paid <= reward && reward - paid <= 1,
        "the split must conserve the emission (within one nano of the scaled \
         accumulator), got {} extra",
        paid.saturating_sub(reward)
    );
    // And no participant's share can exceed the whole emission. Here the
    // delegator's entitlement rounds to the entire reward because the validator's
    // self-bond is 5000 STELL against a 10,000,000 STELL delegation, so the
    // commission is zero -- which is fine. What must never happen is the delegator
    // receiving MORE than the emission, which is what the broken invariant allowed.
    assert!(
        to_delegator <= reward,
        "the delegator alone received more than the whole block reward: {to_delegator} > {reward}"
    );
}

/// ECONOMIC: after a slash the delegator can still undelegate the FULL
/// pre-slash amount, because `undelegate` gates on the map. The unbonding entry
/// therefore releases more than the validator's remaining delegated figure and
/// the shortfall is paid out of the shared pool - i.e. out of OTHER validators'
/// bonded principal. Slashing a delegator confiscates nothing; the loss is
/// socialised onto everyone else who bonded.
#[test]
fn a_slashed_delegator_recovers_only_what_the_pool_still_holds() {
    let mut l = StakingLedger::new();
    let val = v(1);
    l.bond(val, stell(5_000), 0).unwrap();
    l.delegate(d(1), val, stell(10_000_000)).unwrap();
    let honest_bond = stell(100_000);
    l.bond(v(2), honest_bond, 0).unwrap();

    // The pool holds every bond and delegation.
    let mut pool = stell(5_000) + stell(10_000_000) + honest_bond;
    let honest_share_before = honest_bond;

    let mut h = 0u64;
    let burned = slash_once_offline(&mut l, val, &mut h);
    pool -= burned; // exactly what runtime.rs:633 does
    let agg_after_slash = l.validators[&val].delegated;
    println!(
        "downtime burn {burned} ({:.0} STELL); aggregate delegated now {}",
        burned as f64 / 1e9,
        agg_after_slash / 1_000_000_000
    );

    // The delegator asks for everything it ever delegated.
    let claim = sum_delegations(&l, val);
    l.undelegate(d(1), val, claim, 1_000).unwrap();
    l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS + 1).unwrap();
    let paid = l.withdraw_delegator(d(1), val).unwrap();
    pool -= paid;

    println!(
        "delegator withdrew {paid} ({} STELL) - the stake the slash had already burned",
        paid / 1_000_000_000
    );
    println!("pool left {pool}; the honest validator had {honest_share_before} in there");
    println!(
        "honest principal silently consumed: {} STELL",
        (honest_share_before - pool) / 1_000_000_000
    );

    // FIXED: the burn now debits the staking pool, so a delegator recovers only
    // what is actually left there. It used to get back 100% of a slashed stake,
    // which meant the destroyed coins were still sitting in the pool being paid
    // out to the next withdrawer.
    assert!(
        paid < agg_after_slash || paid < stell(10_000_000),
        "a slashed delegator must not recover the full pre-slash amount"
    );
    assert_eq!(
        paid, agg_after_slash,
        "a delegator recovers exactly what the validator's delegated figure says          is left -- paid {} STELL vs delegated {} STELL",
        paid / 1_000_000_000,
        agg_after_slash / 1_000_000_000
    );
    // FIXED: the delegator recovers exactly its post-slash figure, so nothing
    // extra is drawn from the pool and the honest validator's bond is untouched.
    // It used to recover 100% of the pre-slash stake, and the excess came straight
    // out of the honest validator's principal.
    assert_eq!(
        pool,
        honest_bond,
        "the honest validator's principal must be exactly intact: {} STELL gone",
        (honest_bond as i64 - pool as i64) / 1_000_000_000
    );
}

/// CHAIN HALT: once the per-delegator map exceeds the aggregate by more than
/// 1/BPS (20x for the 5% equivocation slash), `v.delegated -= slashed_total`
/// (src/staking.rs:408) underflows. In a debug/test build that is a PANIC in the
/// middle of a consensus state transition; in a release build it wraps to
/// ~1.8e19, which then also overflows `ValidatorSet::total_power()` and hands
/// the offender more than 100% of the voting power.
#[test]
fn repeated_slashing_cannot_underflow_the_delegated_aggregate() {
    let mut l = StakingLedger::new();
    let val = v(1);
    l.bond(val, floor(), 0).unwrap();
    l.delegate(d(1), val, stell(1_000_000_000)).unwrap();

    let (outages, heights, _) = diverge_to(&mut l, val, 20.0);
    let agg = l.validators[&val].delegated;
    let map = sum_delegations(&l, val);
    println!(
        "{outages} downtime streaks / {heights} heights = {:.1} days of sustained downtime",
        heights as f64 * 3.0 / 86400.0
    );
    println!(
        "aggregate {agg} vs map {map} = {:.2}x divergence",
        map as f64 / agg as f64
    );

    // Now the validator equivocates: 5% of the total.
    let total_before = l.validators[&val].total();
    let nominal = (total_before as u128 * 500 / 10_000) as u64;
    println!("equivocation: total {total_before}, nominal 5% = {nominal}");

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| l.slash(val, 500)));
    std::panic::set_hook(prev);

    match res {
        Ok(r) => {
            let after = l.validators[&val].delegated;
            println!("slash returned {r:?}; delegated is now {after}");
            assert!(
                after <= agg,
                "UNDERFLOW: delegated WRAPPED {} -> {} ({:.0}x)",
                agg,
                after,
                after as f64 / agg as f64
            );
            let vs = l.to_validator_set();
            println!(
                "voting power: {} of {} total",
                vs.power_of(&val),
                vs.total_power()
            );
        }
        Err(_) => {
            println!(
                "*** slash PANICKED at src/staking.rs:408: 'attempt to subtract with overflow'"
            );
            println!(
                "*** an attacker who is also the victim can halt every node that validates this"
            );
            // Re-run under the real hook so the report shows the panic message.
            let _ = l.slash(val, 500);
        }
    }
}

/// NEGATIVE RESULT: in `slash`, when the delegation cut is taken, the
/// per-delegator `cut` rounds DOWN, so `remaining` is left unburned and
/// silently forgiven: the nominal slash percentage is not what leaves the
/// ledger, with no error and no record. It is however bounded by 1 nano per
/// delegator, so it is economically irrelevant - I could not turn it into
/// money. Recorded here so the next reader does not retry it.
#[test]
fn slash_silently_forgives_the_rounding_remainder() {
    for n_delegators in [2u16, 3, 7, 4_000, 40_000] {
        let mut l = StakingLedger::new();
        let val = v(1);
        l.bond(val, floor(), 0).unwrap();
        for i in 0..n_delegators {
            let mut a = [0u8; 32];
            a[0] = (i / 250) as u8;
            a[1] = (i % 250) as u8;
            a[2] = 0xEE;
            l.delegate(a, val, stell(7_777)).unwrap();
        }
        let total = l.total_stake(&val);
        let nominal = (total as u128 * 500 / 10_000) as u64;
        let burned = l.slash(val, 500).unwrap();
        let forgiven = nominal.saturating_sub(burned);
        println!(
            "{n_delegators:>6} delegations: nominal {nominal}, burned {burned}, FORGIVEN {forgiven} (<= 1 nano/delegator: {})",
            forgiven <= n_delegators as u64
        );
        assert!(
            forgiven <= n_delegators as u64,
            "forgiveness is bounded by 1 nano per delegator, so it is dust"
        );
        assert_eq!(
            l.total_burned, burned,
            "the counter matches what was actually removed"
        );
    }
    // Uneven delegations do produce a real (still tiny) remainder:
    let mut l = StakingLedger::new();
    let val = v(1);
    l.bond(val, floor(), 0).unwrap();
    l.delegate(d(1), val, stell(10_000_000)).unwrap();
    l.delegate(d(2), val, stell(10_000_001)).unwrap();
    l.delegate(d(3), val, stell(1)).unwrap();
    let total = l.total_stake(&val);
    let nominal = (total as u128 * 500 / 10_000) as u64;
    let burned = l.slash(val, 500).unwrap();
    println!(
        "uneven: nominal {nominal}, burned {burned}, FORGIVEN {}",
        nominal - burned
    );
    assert!(
        nominal - burned > 0,
        "an uneven book does leave a remainder unburned"
    );
    assert!(
        nominal - burned < 10,
        "but it is single-digit nanos: not a money bug"
    );
}

/// CONTROL: with no divergence the two representations stay in step and the
/// reward split conserves value. This negative result is what makes the
/// divergences above meaningful.
#[test]
fn control_healthy_ledger_conserves_reward_value() {
    let mut l = StakingLedger::new();
    let val = v(1);
    l.bond(val, floor(), 1_000).unwrap();
    for i in 0..10u8 {
        l.delegate(d(i), val, stell(1_000)).unwrap();
    }
    let reward = stell(100);
    l.distribute_reward(val, reward).unwrap();
    let to_delegators = l.delegator_rewards.values().sum::<u64>();
    let paid = l.validators[&val].pending_rewards + to_delegators;
    println!(
        "reward {reward} -> validator {} + delegators {to_delegators} = {paid}",
        l.validators[&val].pending_rewards
    );
    assert!(
        paid <= reward,
        "a healthy ledger never pays out more than it was given"
    );
    assert_eq!(l.validators[&val].delegated, sum_delegations(&l, val));
}
