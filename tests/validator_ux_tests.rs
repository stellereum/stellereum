//! Validator-UX gap coverage: unjail flow, redelegate fast path, mutable
//! commission with delegator-exit window, bare-MIN ejection-edge refusal,
//! and the conservation invariant across all of them.
//!
//! Design rules under test (all consts in `stellereum::staking`, no env):
//!  - jail is automatic on a downtime slash (`note_missed_heights`); release
//!    is `jailed_at + JAIL_RELEASE_DELAY_HEIGHTS` (1,000 heights);
//!  - `unjail` needs release reached AND self-bond back at MIN+buffer
//!    (`required_bond_floor_nano`, 1,100 STELL) — fail-closed otherwise;
//!  - `redelegate` moves voting power immediately but arms a
//!    `UNBONDING_PERIOD_SECS` anti-long-range lock against chaining the fast
//!    path (`undelegate` stays available — it is the slow path);
//!  - commission moves at most `COMMISSION_MAX_DELTA_BPS` (500 = 5pp) per
//!    announced step, takes effect `COMMISSION_EFFECT_DELAY_HEIGHTS`
//!    (7,200) heights after announcement, at most one effective change per
//!    `COMMISSION_CHANGE_COOLDOWN_HEIGHTS` (7,200);
//!  - conservation: every non-mint/non-burn transition leaves
//!    `ledger_stake_supply` exactly unchanged; `slash` lowers it by exactly
//!    the burned amount while `total_burned` rises by the same.

use stellereum::staking::{
    StakingError, StakingLedger, BPS_DENOMINATOR, COMMISSION_CHANGE_COOLDOWN_HEIGHTS,
    COMMISSION_EFFECT_DELAY_HEIGHTS, COMMISSION_MAX_DELTA_BPS, DEFAULT_COMMISSION_BPS,
    DOWNTIME_MISS_THRESHOLD, JAIL_RELEASE_DELAY_HEIGHTS, MIN_VALIDATOR_BOND, UNBONDING_PERIOD_SECS,
};

fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}

fn del(n: u8) -> [u8; 32] {
    [0xD0 + n; 32]
}

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Drive `v` into a downtime slash (and therefore jail) by keeping it
/// offline for a full miss streak ending at `last_height`. Returns burned.
fn jail_by_downtime(l: &mut StakingLedger, v: [u8; 32], last_height: u64) -> u64 {
    let never = |_: &[u8; 32]| false;
    let one = vec![v];
    let mut burned = 0u64;
    let start = last_height.saturating_sub(DOWNTIME_MISS_THRESHOLD as u64 - 1);
    for h in start..=last_height {
        burned += l.note_missed_heights(h, &never, &one);
    }
    burned
}

#[test]
fn unjail_happy_path_after_window_with_buffer_intact() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(1200), DEFAULT_COMMISSION_BPS).unwrap();
    l.bond(vid(2), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    assert_eq!(l.elected_count(), 2);

    // Offline for a full streak ending at height 10: slashed AND jailed.
    let burned = jail_by_downtime(&mut l, vid(1), 10);
    assert!(burned > 0, "the streak must cost something");
    assert!(l.is_jailed(&vid(1)), "downtime slash must jail");
    let rec = l.jail_record(&vid(1)).expect("jail record");
    assert_eq!(rec.jailed_at_height, 10);
    assert_eq!(rec.release_height, 10 + JAIL_RELEASE_DELAY_HEIGHTS);

    // Out of the set while jailed (power intact, votes gone).
    assert!(!l.to_validator_set().validators.contains_key(&vid(1)));
    assert_eq!(l.elected_count(), 1);

    // Too early: refused, ledger untouched.
    assert_eq!(
        l.unjail(vid(1), rec.release_height - 1),
        Err(StakingError::CooldownNotElapsed)
    );
    assert!(l.is_jailed(&vid(1)));

    // At release with the buffer intact (1200 − 1.2 STELL still ≥ 1100):
    // re-admitted, history preserved.
    let slashed_total = l.validators[&vid(1)].total_slashed;
    assert!(slashed_total > 0);
    l.unjail(vid(1), rec.release_height).unwrap();
    assert!(!l.is_jailed(&vid(1)));
    assert!(l.to_validator_set().validators.contains_key(&vid(1)));
    assert_eq!(l.elected_count(), 2);
    assert_eq!(
        l.validators[&vid(1)].total_slashed,
        slashed_total,
        "unjail must never launder slash history"
    );
}

#[test]
fn unjail_refusals_unknown_bare_min_then_topup() {
    let mut l = StakingLedger::new();
    // Unknown validator: not jailed.
    assert_eq!(l.unjail(vid(9), 1_000_000), Err(StakingError::NotJailed));

    // Bond exactly at the floor: one downtime slash pushes self-bond under
    // MIN+buffer and jails.
    l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
    let burned = jail_by_downtime(&mut l, vid(1), 10);
    assert!(burned > 0);
    assert!(l.is_jailed(&vid(1)));
    let left = l.validators[&vid(1)].self_bond;
    assert!(left < stell(1100), "slash must eat into the buffer: {left}");
    assert!(left >= MIN_VALIDATOR_BOND, "one 0.1% slash must not eject");

    // At release but bare: refused (ejection edge — one more slash ejects).
    let release = l.jail_record(&vid(1)).unwrap().release_height;
    assert_eq!(
        l.unjail(vid(1), release),
        Err(StakingError::BondBelowMinimum)
    );
    assert!(l.is_jailed(&vid(1)));
    assert!(!l.to_validator_set().validators.contains_key(&vid(1)));

    // Top up past the buffer (fail-open top-up WARNs, still accepted), then
    // unjail succeeds.
    l.add_bond(vid(1), stell(10)).unwrap();
    assert!(l.validators[&vid(1)].self_bond >= stell(1100));
    l.unjail(vid(1), release).unwrap();
    assert!(l.to_validator_set().validators.contains_key(&vid(1)));
}

#[test]
fn jail_blocks_entry_but_never_holds_funds_hostage() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();
    jail_by_downtime(&mut l, vid(1), 10);
    assert!(l.is_jailed(&vid(1)));

    // Entry refused: new delegations and rewards cannot park on a jailed key.
    assert_eq!(
        l.delegate(del(2), vid(1), stell(1000)),
        Err(StakingError::Jailed)
    );
    assert_eq!(
        l.distribute_reward(vid(1), stell(10)),
        Err(StakingError::Jailed)
    );
    // Redelegate TO a jailed validator refused; redelegate AWAY (flee)
    // allowed. Jail vid(2) as well so the TO-jailed case is covered.
    l.bond(vid(2), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    jail_by_downtime(&mut l, vid(2), 10);
    assert_eq!(
        l.redelegate(del(1), vid(1), vid(2), stell(100), 0),
        Err(StakingError::Jailed)
    );

    // Exits stay available: undelegate and top-up work while jailed.
    l.undelegate(del(1), vid(1), stell(1000), 0).unwrap();
    l.add_bond(vid(1), stell(100)).unwrap();
    // Partial unbond is still floor-gated while jailed (no thin remainder):
    // self-bond is ~1998 STELL, leaving ~998 is refused.
    assert_eq!(
        l.unbond(vid(1), stell(1000), 0),
        Err(StakingError::BondBelowMinimum)
    );
    // Full exit works (remaining 0).
    let sb = l.validators[&vid(1)].self_bond;
    l.unbond(vid(1), sb, 0).unwrap();
    assert_eq!(l.validators[&vid(1)].self_bond, 0);
}

#[test]
fn redelegate_happy_path_moves_power_and_settles_both_sides() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), 0).unwrap();
    l.bond(vid(2), stell(2000), 0).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();

    // One emission at A: D earns exactly 100 STELL (0% commission).
    l.distribute_reward(vid(1), stell(300)).unwrap();
    let owed_at_a = l.delegator_rewards_of(del(1), vid(1));
    assert_eq!(owed_at_a, stell(100));

    let supply_before = l.ledger_stake_supply();
    l.redelegate(del(1), vid(1), vid(2), stell(1000), 0)
        .unwrap();
    assert_eq!(
        l.ledger_stake_supply(),
        supply_before,
        "redelegate must conserve stake exactly"
    );

    // Power moved immediately.
    assert_eq!(l.validators[&vid(1)].delegated, 0);
    assert_eq!(l.validators[&vid(2)].delegated, stell(1000));
    assert_eq!(
        l.delegations.get(&(vid(2), del(1))).copied(),
        Some(stell(1000))
    );
    // From-side accrual survived the move verbatim, keyed at A.
    assert_eq!(l.delegator_rewards_of(del(1), vid(1)), owed_at_a);
    // Arrival does not back-earn: D has nothing at B yet.
    assert_eq!(l.delegator_rewards_of(del(1), vid(2)), 0);
    // Anti-long-range lock armed on the arrival position.
    assert_eq!(
        l.redelegation_locked_until(&vid(2), &del(1)),
        UNBONDING_PERIOD_SECS
    );

    // Next emission at B pays D exactly the new 100 STELL; the A accrual is
    // claimable separately and exactly once.
    l.distribute_reward(vid(2), stell(300)).unwrap();
    assert_eq!(l.delegator_rewards_of(del(1), vid(2)), stell(100));
    assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), owed_at_a);
    assert_eq!(l.claim_delegator_rewards(del(1), vid(2)), stell(100));
}

#[test]
fn redelegate_abuse_is_refused_fail_closed() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    l.bond(vid(2), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    l.bond(vid(3), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();
    let supply = l.ledger_stake_supply();

    // Shape violations.
    assert_eq!(
        l.redelegate(del(1), vid(1), vid(1), stell(100), 0),
        Err(StakingError::InvalidRedelegation)
    );
    assert_eq!(
        l.redelegate(del(1), vid(1), vid(2), 0, 0),
        Err(StakingError::InsufficientDelegation)
    );
    assert_eq!(
        l.redelegate(del(1), vid(1), vid(2), stell(1001), 0),
        Err(StakingError::InsufficientDelegation)
    );
    assert_eq!(
        l.redelegate([0u8; 32], vid(1), vid(2), stell(1), 0),
        Err(StakingError::ZeroAddress)
    );
    // Unknown source with no position reads as insufficient (same precedence
    // as `undelegate`: the position check fires before the membership check).
    assert_eq!(
        l.redelegate(del(1), vid(9), vid(2), stell(1), 0),
        Err(StakingError::InsufficientDelegation)
    );
    assert_eq!(
        l.redelegate(del(1), vid(1), vid(9), stell(1), 0),
        Err(StakingError::NotValidator)
    );
    assert_eq!(l.ledger_stake_supply(), supply, "refusals move nothing");

    // Fast-path chaining blocked inside the unbonding window.
    l.redelegate(del(1), vid(1), vid(2), stell(400), 0).unwrap();
    assert_eq!(
        l.redelegate(del(1), vid(2), vid(3), stell(100), 1),
        Err(StakingError::CooldownNotElapsed)
    );
    // The slow path stays open on a locked position.
    l.undelegate(del(1), vid(2), stell(400), 1).unwrap();
    // After the window the fast path works again.
    l.delegate(del(1), vid(2), stell(400)).unwrap();
    l.redelegate(del(1), vid(2), vid(3), stell(100), UNBONDING_PERIOD_SECS)
        .unwrap();
    assert_eq!(
        l.delegations.get(&(vid(3), del(1))).copied(),
        Some(stell(100))
    );

    // Governance-locked stake cannot take the fast path either.
    l.delegate(del(2), vid(1), stell(500)).unwrap();
    l.lock_governance(del(2), stell(500));
    assert_eq!(
        l.redelegate(del(2), vid(1), vid(2), stell(1), UNBONDING_PERIOD_SECS + 1),
        Err(StakingError::LockedInGovernanceVote)
    );
    l.unlock_governance(del(2), stell(500));
}

#[test]
fn commission_bounded_change_with_exit_window() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), 1_000).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();

    // Announce +600pp-beyond-bound in one step: refused.
    assert_eq!(
        l.announce_commission(vid(1), 1_000 + COMMISSION_MAX_DELTA_BPS + 1, 100),
        Err(StakingError::CommissionDeltaExceeded)
    );
    // Over 100%: refused as bad commission.
    assert_eq!(
        l.announce_commission(vid(1), BPS_DENOMINATOR + 1, 100),
        Err(StakingError::BadCommission)
    );
    // Unknown validator.
    assert_eq!(
        l.announce_commission(vid(9), 1_200, 100),
        Err(StakingError::NotValidator)
    );

    // Legal announce: 10% -> 15% (delta exactly the bound).
    l.announce_commission(vid(1), 1_500, 100).unwrap();
    let sched = l.commission_schedule_of(&vid(1)).expect("schedule");
    let pending = sched.pending.expect("pending change");
    assert_eq!(pending.new_bps, 1_500);
    assert_eq!(pending.announced_height, 100);
    assert_eq!(
        pending.effective_height,
        100 + COMMISSION_EFFECT_DELAY_HEIGHTS
    );
    // Rate has NOT moved yet.
    assert_eq!(l.validators[&vid(1)].commission_bps, 1_000);

    // Early apply: refused. Nothing pending for others: refused.
    assert_eq!(
        l.apply_commission(vid(1), 100 + COMMISSION_EFFECT_DELAY_HEIGHTS - 1),
        Err(StakingError::CommissionNotDue)
    );
    assert_eq!(
        l.apply_commission(vid(2), 1_000_000),
        Err(StakingError::NotValidator)
    );

    // Emission inside the window still uses the OLD rate (10% of the 100
    // STELL delegated share = 10): the raise cannot clip in-flight rewards.
    l.distribute_reward(vid(1), stell(300)).unwrap();
    assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), stell(90));
    // And delegators can still exit mid-window.
    l.undelegate(del(1), vid(1), stell(1000), 101).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();

    // At the effective height the change installs; new emission uses it.
    l.apply_commission(vid(1), 100 + COMMISSION_EFFECT_DELAY_HEIGHTS)
        .unwrap();
    assert_eq!(l.validators[&vid(1)].commission_bps, 1_500);
    l.distribute_reward(vid(1), stell(300)).unwrap();
    // 15% of the 100 STELL delegated share = 15 to validator, 85 to D.
    assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), stell(85));

    // Cooldown: another announce too soon is refused.
    assert_eq!(
        l.announce_commission(vid(1), 2_000, 100 + COMMISSION_EFFECT_DELAY_HEIGHTS),
        Err(StakingError::CommissionNotDue)
    );
    // After the cooldown window a further bounded step works.
    let later = 100 + COMMISSION_EFFECT_DELAY_HEIGHTS + COMMISSION_CHANGE_COOLDOWN_HEIGHTS;
    l.announce_commission(vid(1), 2_000, later).unwrap();
    // Announcing the CURRENT rate cancels the pending change.
    l.announce_commission(vid(1), 1_500, later).unwrap();
    assert!(
        l.commission_schedule_of(&vid(1))
            .and_then(|s| s.pending)
            .is_none(),
        "re-announcing the current rate must cancel the pending change"
    );
    assert_eq!(
        l.apply_commission(vid(1), later + COMMISSION_EFFECT_DELAY_HEIGHTS),
        Err(StakingError::CommissionNotDue)
    );
    assert_eq!(l.validators[&vid(1)].commission_bps, 1_500);
}

#[test]
fn min_edge_refusals_and_rotate_carries_jail() {
    let mut l = StakingLedger::new();
    // Bare MIN and just-under-floor bonds are refused (fail-closed).
    assert_eq!(
        l.bond(vid(1), MIN_VALIDATOR_BOND, DEFAULT_COMMISSION_BPS),
        Err(StakingError::BondBelowMinimum)
    );
    assert_eq!(
        l.bond(
            vid(1),
            MIN_VALIDATOR_BOND + 100 * 1_000_000_000 - 1,
            DEFAULT_COMMISSION_BPS
        ),
        Err(StakingError::BondBelowMinimum)
    );
    l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();

    // Partial unbond that would leave a bare edge is refused; full exit OK.
    assert_eq!(
        l.unbond(vid(1), stell(1), 0),
        Err(StakingError::BondBelowMinimum)
    );
    l.unbond(vid(1), stell(1100), 0).unwrap();
    assert_eq!(l.validators[&vid(1)].self_bond, 0);
    l.add_bond(vid(1), stell(2000)).unwrap();

    // Jail + rotate: the standing (jail record, schedule, locks) travels.
    // Arm a redelegation lock INTO vid(1) first (redelegate into a jailed
    // key is refused, so this must happen before the jailing below).
    l.bond(vid(3), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(del(9), vid(3), stell(500)).unwrap();
    l.redelegate(del(9), vid(3), vid(1), stell(500), 0).unwrap();
    let lock_before = l.redelegation_locked_until(&vid(1), &del(9));
    assert!(lock_before > 0);
    jail_by_downtime(&mut l, vid(1), 10);
    assert!(l.is_jailed(&vid(1)));
    l.announce_commission(vid(1), 1_200, 50).unwrap();
    l.rotate_key(vid(1), vid(2)).unwrap();
    assert!(!l.is_jailed(&vid(1)));
    assert!(l.is_jailed(&vid(2)), "jail must travel with the record");
    assert!(
        l.commission_schedule_of(&vid(2))
            .and_then(|s| s.pending)
            .is_some(),
        "pending commission must travel with the record"
    );
    assert!(
        l.redelegation_locked_until(&vid(1), &del(9)) == 0,
        "old key must carry no lock after rotation"
    );
    assert_eq!(
        l.redelegation_locked_until(&vid(2), &del(9)),
        lock_before,
        "redelegation lock must travel with the record"
    );
    // Unjail works under the new key once conditions hold.
    let release = l.jail_record(&vid(2)).unwrap().release_height;
    l.add_bond(vid(2), stell(10)).unwrap();
    // self-bond is 2000-ish minus the 0.1% slash: above the floor already.
    l.unjail(vid(2), release).unwrap();
    assert!(!l.is_jailed(&vid(2)));
}

#[test]
fn conservation_holds_across_every_transition() {
    let mut l = StakingLedger::new();
    l.bond(vid(1), stell(2000), 1_000).unwrap();
    l.bond(vid(2), stell(2000), 1_000).unwrap();
    l.delegate(del(1), vid(1), stell(1000)).unwrap();
    l.delegate(del(2), vid(2), stell(500)).unwrap();
    let funded = l.ledger_stake_supply();
    assert_eq!(funded, stell(2000 + 2000 + 1000 + 500));
    assert_eq!(l.total_burned, 0);

    // Non-burn transitions preserve the supply exactly.
    l.redelegate(del(1), vid(1), vid(2), stell(300), 0).unwrap();
    assert_eq!(l.ledger_stake_supply(), funded);
    l.undelegate(del(2), vid(2), stell(500), 0).unwrap();
    assert_eq!(l.ledger_stake_supply(), funded);
    l.unbond(vid(1), stell(500), 0).unwrap();
    assert_eq!(l.ledger_stake_supply(), funded);
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    assert_eq!(l.ledger_stake_supply(), funded);
    assert_eq!(l.withdraw_delegator(del(2), vid(2)).unwrap(), stell(500));
    assert_eq!(l.ledger_stake_supply(), funded - stell(500));
    // Withdrawal pays OUT (external leg): supply falls by exactly the paid
    // amount — value left the ledger, it was not destroyed inside it.

    // Slash destroys exactly the burned amount, booked in total_burned.
    let before = l.ledger_stake_supply();
    let burned_before = l.total_burned;
    let burned = l.slash(vid(2), 1_000).unwrap(); // 10%
    assert!(burned > 0);
    assert_eq!(l.total_burned, burned_before + burned);
    assert_eq!(l.ledger_stake_supply(), before - burned);

    // Rewards MINT backing (supply untouched — new value, pool-backed).
    let supply = l.ledger_stake_supply();
    l.distribute_reward(vid(1), stell(100)).unwrap();
    assert_eq!(l.ledger_stake_supply(), supply);
    let v_amt = l.claim_validator_rewards(vid(1)).unwrap();
    assert!(v_amt > 0);
    assert_eq!(l.ledger_stake_supply(), supply);

    // Unjail + commission paths move no stake.
    jail_by_downtime(&mut l, vid(1), 50);
    let supply = l.ledger_stake_supply();
    let release = l.jail_record(&vid(1)).unwrap().release_height;
    l.unjail(vid(1), release).unwrap();
    assert_eq!(l.ledger_stake_supply(), supply);
    l.announce_commission(vid(1), 1_200, release).unwrap();
    l.apply_commission(vid(1), release + COMMISSION_EFFECT_DELAY_HEIGHTS)
        .unwrap();
    assert_eq!(l.ledger_stake_supply(), supply);
}
