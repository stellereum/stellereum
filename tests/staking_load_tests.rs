//! Staking load tests: MANY delegators (50 across 3 validators).
//!
//! The delegation map vs aggregate invariant (`delegated == sum(map)` per
//! validator) broke before; it must hold under stress. Pure, in-process,
//! deterministic `StakingLedger` tests: no sleeps, no `#[ignore]`.
//!
//! A `pool` variable shadows the on-chain STAKING_POOL account semantics:
//!   * credit on bond / delegate (funds enter the pool),
//!   * debit on slash burn (coins destroyed) and on withdraw (funds leave),
//!   * unbond/undelegate + process move funds between bonded/unbonding/
//!     withdrawable buckets WITHOUT leaving the pool.

use std::collections::HashMap;
use stellereum::staking::{StakingLedger, DOWNTIME_SLASH_BPS, UNBONDING_PERIOD_SECS};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn vid(i: u8) -> [u8; 32] {
    [0xA0 + i; 32]
}

/// Unique delegator address for index j (j < 64). Avoids [0u8; 32], which is
/// the self-bond withdrawable owner key.
fn del_addr(j: u8) -> [u8; 32] {
    let mut a = [0xCB; 32];
    a[0] = j;
    a[1] = 0xD1;
    a
}

fn validators() -> Vec<[u8; 32]> {
    vec![vid(0), vid(1), vid(2)]
}

/// Varied but deterministic delegation sizes (all >= MIN_DELEGATION).
fn del_amount(j: u8) -> u64 {
    stell(100 * ((j % 5) as u64 + 1)) // 100..500 STELL
}

fn validator_of(j: u8) -> [u8; 32] {
    vid(j % 3)
}

/// Sum of the delegation map for one validator.
fn map_sum(l: &StakingLedger, v: &[u8; 32]) -> u64 {
    l.delegations
        .iter()
        .filter(|((vid, _), _)| vid == v)
        .map(|(_, a)| *a)
        .sum()
}

/// Assert `delegated == sum(map)` for every validator.
fn assert_map_aggregate_in_step(l: &StakingLedger, vs: &[[u8; 32]], ctx: &str) {
    for v in vs {
        let agg = l.validators.get(v).map(|r| r.delegated).unwrap_or(0);
        let sum = map_sum(l, v);
        assert_eq!(
            agg,
            sum,
            "map/aggregate divergence {ctx}: validator {:02x?} aggregate={agg} map_sum={sum}",
            &v[..2],
        );
    }
}

/// Build the standard load fixture: 3 validators bonded, 50 delegators spread
/// round-robin. Returns (ledger, shadow_pool).
fn build_loaded_ledger() -> (StakingLedger, u64) {
    let mut l = StakingLedger::new();
    let mut pool: u64 = 0;
    for v in validators() {
        l.bond(v, stell(5_000), 0).unwrap();
        pool += stell(5_000);
    }
    for j in 0..50u8 {
        let amt = del_amount(j);
        l.delegate(del_addr(j), validator_of(j), amt).unwrap();
        pool += amt;
    }
    (l, pool)
}

/// Test 1: after 50 delegations across 3 validators, `delegated == sum(map)`
/// per validator and the pool covers all bonded stake.
#[test]
fn load_50_delegators_map_aggregate_and_pool_solvency() {
    let (l, pool) = build_loaded_ledger();
    let vs = validators();

    assert_map_aggregate_in_step(&l, &vs, "post-delegation");

    // 50 distinct map entries, correctly partitioned.
    assert_eq!(
        l.delegations.len(),
        50,
        "all 50 delegations must be tracked"
    );
    assert_eq!(
        l.delegations.keys().filter(|(v, _)| *v == vid(0)).count(),
        17
    );
    assert_eq!(
        l.delegations.keys().filter(|(v, _)| *v == vid(1)).count(),
        17
    );
    assert_eq!(
        l.delegations.keys().filter(|(v, _)| *v == vid(2)).count(),
        16
    );

    // Pool solvency: every bonded nano sits in the pool; nothing burned yet.
    let bonded_total: u64 = vs.iter().map(|v| l.total_stake(v)).sum();
    assert_eq!(l.total_burned, 0, "no burns yet");
    assert_eq!(
        pool, bonded_total,
        "pool must exactly cover bonded stake: pool={pool} bonded={bonded_total}"
    );

    // Consensus power follows the same totals.
    let vset = l.to_validator_set();
    for v in &vs {
        assert_eq!(vset.power_of(v), l.total_stake(v));
    }
}

/// Test 2: rewards over several heights are exactly pro-rata and the total
/// distributed equals the emission.
///
/// Trick for exactness: with commission 0 and `reward == total_stake`, the
/// delegated share equals `delegated` exactly and each delegator's cut equals
/// their own stake exactly -- no flooring dust anywhere.
#[test]
fn load_rewards_exactly_pro_rata_over_heights() {
    let (mut l, pool_before) = build_loaded_ledger();
    let vs = validators();
    const HEIGHTS: u64 = 5;

    // Snapshot stakes (rewards accrue to pending/rewards maps, not to stake).
    let mut totals: HashMap<[u8; 32], u64> = HashMap::new();
    let mut self_bonds: HashMap<[u8; 32], u64> = HashMap::new();
    let mut emission: u64 = 0;
    for v in &vs {
        let t = l.total_stake(v);
        totals.insert(*v, t);
        self_bonds.insert(*v, l.validators[v].self_bond);
        emission += t * HEIGHTS;
    }

    for _ in 0..HEIGHTS {
        for v in &vs {
            let reward = totals[v]; // == current total; stake never changes here
            l.distribute_reward(*v, reward).unwrap();
        }
        assert_map_aggregate_in_step(&l, &vs, "after reward height");
    }

    // Claim everything and check exact pro-rata figures.
    let mut distributed: u64 = 0;
    for v in &vs {
        let vpay = l.claim_validator_rewards(*v).unwrap();
        assert_eq!(
            vpay,
            self_bonds[v] * HEIGHTS,
            "validator must earn exactly its self-share each height"
        );
        distributed += vpay;
        for j in 0..50u8 {
            if validator_of(j) != *v {
                continue;
            }
            let got = l.claim_delegator_rewards(del_addr(j), *v);
            assert_eq!(
                got,
                del_amount(j) * HEIGHTS,
                "delegator {j} must earn exactly its pro-rata share"
            );
            distributed += got;
        }
    }
    assert_eq!(
        distributed, emission,
        "total distributed {distributed} must equal emission {emission}"
    );

    // Proportionality spot-check: a 400-STELL delegator earns exactly 4x a
    // 100-STELL delegator on the same validator. (Re-run one height fresh.)
    let (mut l2, _) = build_loaded_ledger();
    let v = validator_of(0); // del 0 -> 100 STELL; del 3 -> 400 STELL (same validator: 0%3==0, 3%3==0)
    assert_eq!(validator_of(3), v);
    l2.distribute_reward(v, l2.total_stake(&v)).unwrap();
    let r_small = l2
        .delegator_rewards
        .get(&(v, del_addr(0)))
        .copied()
        .unwrap_or(0);
    let r_big = l2
        .delegator_rewards
        .get(&(v, del_addr(3)))
        .copied()
        .unwrap_or(0);
    assert_eq!(r_big, 4 * r_small, "rewards must scale exactly with stake");

    // Rewards are minted accounting: the staking pool is untouched.
    let bonded_total: u64 = vs.iter().map(|v| l.total_stake(v)).sum();
    assert_eq!(
        pool_before, bonded_total,
        "rewards must not move pool funds"
    );
}

/// Test 3: unbond half the delegators (25) at staggered heights, process,
/// withdraw. Each recovers exactly its post-slash figure; map/aggregate stay
/// in step throughout.
///
/// Setup includes a 60% slash on V0 so the "post-slash figure" is non-trivial
/// (self-bond exhausted, delegators haircut); other validators are unslashed.
#[test]
fn load_staggered_unbond_withdraw_recovers_post_slash_exactly() {
    let (mut l, mut pool) = build_loaded_ledger();
    let vs = validators();

    // Heavy slash on V0: burn = 60% of total > self-bond, so the delegated leg
    // is cut proportionally (floor dust possible; we read post-slash truth).
    let v0 = vid(0);
    let burn0 = l.slash(v0, 6_000).unwrap();
    assert!(burn0 > 0, "slash must burn something");
    pool -= burn0;
    assert_map_aggregate_in_step(&l, &vs, "post-slash");

    // Record post-slash per-delegator truth.
    let mut post_slash: HashMap<u8, u64> = HashMap::new();
    for j in 0..50u8 {
        post_slash.insert(
            j,
            l.delegations
                .get(&(validator_of(j), del_addr(j)))
                .copied()
                .unwrap_or(0),
        );
    }
    // V0 delegators were actually haircut; others untouched.
    assert!(
        (0..50u8)
            .filter(|j| j % 3 == 0)
            .all(|j| post_slash[&j] < del_amount(j)),
        "V0 delegators must show the post-slash haircut"
    );
    assert!(
        (0..50u8)
            .filter(|j| j % 3 != 0)
            .all(|j| post_slash[&j] == del_amount(j)),
        "other validators' delegators must be untouched"
    );

    // Unbond half: every even-indexed delegator (25), full post-slash amount,
    // at staggered `now` timestamps.
    const BASE: u64 = 1_000_000;
    const STEP: u64 = 7;
    let exiting: Vec<u8> = (0..50u8).filter(|j| j % 2 == 0).collect();
    assert_eq!(exiting.len(), 25);
    for (k, j) in exiting.iter().enumerate() {
        let now = BASE + (k as u64) * STEP;
        l.undelegate(del_addr(*j), validator_of(*j), post_slash[j], now)
            .unwrap();
        assert_map_aggregate_in_step(&l, &vs, "during staggered undelegate");
    }
    // Unbonding moves nothing out of the pool.
    let bonded: u64 = vs.iter().map(|v| l.total_stake(v)).sum();
    let in_flight: u64 = l.unbonding.iter().map(|e| e.amount).sum();
    let ready: u64 = l.withdrawable.values().sum();
    assert_eq!(
        pool,
        bonded + in_flight + ready,
        "pool still holds unbonding funds"
    );

    // Staggered maturation: at BASE + PERIOD only the first (k=0) entry is due.
    l.process_unbonding(BASE + UNBONDING_PERIOD_SECS).unwrap();
    let j0 = exiting[0];
    assert_eq!(
        l.withdrawable_delegator(&validator_of(j0), &del_addr(j0)),
        post_slash[&j0],
        "only the earliest staggered entry matures first"
    );
    assert_eq!(
        l.withdrawable.len(),
        1,
        "exactly one staggered entry may mature at the earliest deadline"
    );
    // A later entry is not yet mature.
    let jlast = exiting[24];
    assert_eq!(
        l.withdrawable_delegator(&validator_of(jlast), &del_addr(jlast)),
        0,
        "the latest staggered entry must still be locked"
    );

    // Full maturation then per-delegator withdraw of exact post-slash figures.
    l.process_unbonding(BASE + 24 * STEP + UNBONDING_PERIOD_SECS).unwrap();
    assert!(l.unbonding.is_empty(), "all staggered entries must mature");
    for j in &exiting {
        let got = l
            .withdraw_delegator(del_addr(*j), validator_of(*j))
            .unwrap();
        pool -= got;
        assert_eq!(
            got, post_slash[j],
            "delegator {j} must recover exactly its post-slash figure"
        );
        assert_map_aggregate_in_step(&l, &vs, "during withdrawals");
    }
    // Exited map entries are gone; stayers are intact.
    for j in &exiting {
        assert!(
            !l.delegations
                .contains_key(&(validator_of(*j), del_addr(*j))),
            "exited delegator {j} must leave no map residue"
        );
    }
    for j in (0..50u8).filter(|j| j % 2 == 1) {
        assert_eq!(
            l.delegations.get(&(validator_of(j), del_addr(j))).copied(),
            Some(post_slash[&j]),
            "staying delegator {j} must be untouched"
        );
    }
    assert_map_aggregate_in_step(&l, &vs, "final");
    // Pool still solvent over what remains + nothing pending.
    let bonded_end: u64 = vs.iter().map(|v| l.total_stake(v)).sum();
    let ready_end: u64 = l.withdrawable.values().sum();
    assert_eq!(ready_end, 0, "all matured funds were withdrawn");
    assert_eq!(
        pool, bonded_end,
        "pool must exactly cover remaining bonded stake"
    );
}

/// Test 4: a downtime slash debits the delegation map AND the aggregate AND
/// the pool consistently.
///
/// PINNED POLICY (the slash base): a downtime slash burns `bps` of the
/// validator's WHOLE remaining stake - the bonded self-bond, the stake still
/// LOCKED in the unbonding queue, and the delegations - and it consumes it in
/// THAT ORDER: the validator's own money first (so a validator cannot unbond
/// and then go offline to dodge the penalty), the delegators' money last.
/// A MATURED unbond is withdrawable and no longer slashable.
///
/// The target's self-bond is fully unbonded first (legal full exit). The
/// unbonding entry is still LOCKED, so phase 1's burn comes out of it and the
/// delegation map must NOT move. Phase 2 matures that entry and the NEXT
/// downtime streak then lands on the delegators, where the map must move.
#[test]
fn load_downtime_slash_debits_map_aggregate_and_pool() {
    let (mut l, mut pool) = build_loaded_ledger();
    let vs = validators();
    let target = vid(1);

    // Full self-bond exit: legal (remaining == 0), delegations stay. The
    // unbonding entry is LOCKED until it matures.
    let self_bond = l.validators[&target].self_bond;
    l.unbond(target, self_bond, 0).unwrap();
    assert_eq!(l.validators[&target].self_bond, 0);
    assert_map_aggregate_in_step(&l, &vs, "after self exit");

    let agg_before = l.validators[&target].delegated;
    let map_before = map_sum(&l, &target);
    assert_eq!(agg_before, map_before);
    let burned_before = l.total_burned;
    let per_del_before: HashMap<[u8; 32], u64> = l
        .delegations
        .iter()
        .filter(|((v, _), _)| *v == target)
        .map(|((_, d), a)| (*d, *a))
        .collect();
    assert_eq!(per_del_before.len(), 17);
    let in_flight_before: u64 = l
        .unbonding
        .iter()
        .filter(|e| e.validator == target && e.owner.is_none())
        .map(|e| e.amount)
        .sum();
    assert_eq!(
        in_flight_before, self_bond,
        "the self-bond is in the unbonding queue"
    );

    // Drive 10 missed heights (threshold) with everyone else signing.
    let eligible = vs.clone();
    let signer = |v: &[u8; 32]| *v != target;
    let mut burned_total: u64 = 0;
    for h in 1..=stellereum::staking::DOWNTIME_MISS_THRESHOLD as u64 {
        burned_total += l.note_missed_heights(h, &signer, &eligible);
    }
    assert!(
        burned_total > 0,
        "downtime slash must fire at the threshold"
    );
    pool -= burned_total;

    // Nominal 0.1% burn over the WHOLE remaining stake (self 0 + delegated +
    // the locked unbonding principal). This burn is taken from the
    // validator's OWN locked principal, so it is exact (no per-delegator
    // floor dust: no delegator is touched).
    let nominal = (agg_before + in_flight_before) * DOWNTIME_SLASH_BPS / 10_000;
    assert!(nominal > 0, "fixture must be large enough to burn");
    assert_eq!(
        burned_total, nominal,
        "the burn is the nominal share of the validator's whole remaining stake"
    );

    // The VALIDATOR paid: its locked unbonding principal is debited, and the
    // delegations are untouched (the delegators' money is the LAST resort).
    let in_flight_after: u64 = l
        .unbonding
        .iter()
        .filter(|e| e.validator == target && e.owner.is_none())
        .map(|e| e.amount)
        .sum();
    assert_eq!(
        in_flight_before - in_flight_after,
        burned_total,
        "the locked unbonding principal paid the burn"
    );
    assert_eq!(
        l.validators[&target].delegated, agg_before,
        "the delegators did not pay this burn"
    );
    assert_eq!(
        map_sum(&l, &target),
        agg_before,
        "the delegation map did not move (the validator's own money paid)"
    );
    assert_eq!(
        l.total_burned,
        burned_before + burned_total,
        "total_burned must track the burn"
    );
    assert_eq!(
        l.total_stake(&target),
        agg_before,
        "the bonded stake is unchanged (the burn came from the unbonding queue)"
    );
    assert_map_aggregate_in_step(&l, &vs, "after phase 1");

    // Phase 2: the unbonding MATURES. A matured unbond is withdrawable, not
    // slashable, so the NEXT downtime streak lands on the delegators - and
    // the map MUST move with it.
    l.process_unbonding(UNBONDING_PERIOD_SECS).unwrap();
    let matured: u64 = l.withdrawable.values().sum();
    assert_eq!(
        matured, in_flight_after,
        "the matured unbond is withdrawable"
    );
    assert_eq!(
        l.unbonding.iter().filter(|e| e.validator == target).count(),
        0,
        "nothing is left in the unbonding queue"
    );

    let mut burned_total2: u64 = 0;
    // The cooldown (DOWNTIME_PENALTY_COOLDOWN) must have elapsed since the
    // first penalty (height 10), and the streak must reach the threshold
    // again.
    for h in 11..=(10 + stellereum::staking::DOWNTIME_PENALTY_COOLDOWN) {
        burned_total2 += l.note_missed_heights(h, &signer, &eligible);
    }
    assert!(
        burned_total2 > 0,
        "the second downtime streak must slash too"
    );
    pool -= burned_total2;

    // Nominal 0.1% burn of the delegations, modulo per-delegator floor dust
    // (< #delegators nanos).
    let nominal2 = agg_before * DOWNTIME_SLASH_BPS / 10_000;
    assert!(
        burned_total2 <= nominal2 && nominal2 - burned_total2 < 17,
        "burned {burned_total2} must equal nominal {nominal2} modulo floor dust"
    );

    // Aggregate, map, burn ledger, and pool all agree on the same figure.
    let agg_after = l.validators[&target].delegated;
    assert_eq!(
        agg_before - agg_after,
        burned_total2,
        "aggregate debit must equal the burn"
    );
    let map_after = map_sum(&l, &target);
    assert_eq!(
        map_after, agg_after,
        "map sum {map_after} must equal aggregate {agg_after} after slash"
    );
    let cut_sum: u64 = per_del_before
        .iter()
        .map(|(d, b)| b - l.delegations.get(&(target, *d)).copied().unwrap_or(0))
        .sum();
    assert_eq!(
        cut_sum, burned_total2,
        "sum of per-delegator map cuts {cut_sum} must equal the burn {burned_total2}"
    );
    assert_eq!(
        l.total_burned,
        burned_before + burned_total + burned_total2,
        "total_burned must track both burns"
    );
    assert_eq!(
        l.total_stake(&target),
        agg_after,
        "total stake drops by exactly the burn (self was 0)"
    );
    let bonded: u64 = vs.iter().map(|v| l.total_stake(v)).sum();
    let in_flight: u64 = l.unbonding.iter().map(|e| e.amount).sum();
    let withdrawable: u64 = l.withdrawable.values().sum();
    assert_eq!(
        pool,
        bonded + in_flight + withdrawable,
        "pool {pool} must equal bonded {bonded} + in-flight unbonding {in_flight} \
         + matured (withdrawable) {withdrawable}"
    );

    // Bystanders untouched: other validators' aggregates and maps identical.
    for v in vs.iter().filter(|v| **v != target) {
        assert_map_aggregate_in_step(&l, std::slice::from_ref(v), "bystander");
    }
    // No double-slash on replay of the same evidence height.
    let replay = l.note_missed_heights(
        stellereum::staking::DOWNTIME_MISS_THRESHOLD as u64,
        &signer,
        &eligible,
    );
    assert_eq!(replay, 0, "replaying the same height must not slash again");
    assert_map_aggregate_in_step(&l, &vs, "post-replay");
}
