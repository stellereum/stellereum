//! ADVERSARIAL HUNT: the staking ledger keeps the SAME quantity in two places.
//!
//! `ValidatorStake.delegated` (a single aggregate) and
//! `StakingLedger.delegations[(validator, delegator)]` (per-delegator) are two
//! representations of one number. Every code path is supposed to move both at
//! once. `StakingLedger::slash` does. `StakingLedger::note_missed_heights`
//! does NOT -- it decrements `rec.delegated` and never touches `delegations`.
//!
//! That divergence is then consumed by two unchecked divisions:
//!   - `distribute_reward`:  share = delegator_pool * amount / v.delegated
//!   - `undelegate`:         the `amount > current` guard reads `delegations`
//!
//! So once `v.delegated` has been ground down by downtime slashes while
//! `delegations` still holds the original figure, the pro-rata reward split
//! OVERPAYS by the ratio between the two, and the claimed rewards are credited
//! to a real native balance with no corresponding debit anywhere.
//!
//! This is the "two balance representations reconciled with a bad write-back"
//! shape of the August 2026 Cosmos EVM account/balance incident.

use stellereum::staking::{
    StakingLedger, DOWNTIME_MISS_THRESHOLD, DOWNTIME_PENALTY_COOLDOWN, MIN_VALIDATOR_BOND,
    STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::InMemoryStateEngine;

const NANO: u64 = 1_000_000_000;

/// Emulate the chain's real downtime-slash cadence: `apply_downtime_slashes`
/// runs `note_missed_heights` on EVERY finalised height with the validator
/// offline. Returns the total `burned` the ledger reported.
fn grind_delegated_to_zero(l: &mut StakingLedger, v: [u8; 32], max_height: u64) -> u64 {
    let never = |_: &[u8; 32]| false;
    let one = vec![v];
    let mut burned_total = 0u64;
    let mut last = l.total_stake(&v);
    let mut stall = 0u64;
    for height in 1..=max_height {
        burned_total += l.note_missed_heights(height, &never, &one);
        let now = l.total_stake(&v);
        if now == last {
            // burn has floored to zero: nothing more will ever move
            stall += 1;
            if stall > DOWNTIME_PENALTY_COOLDOWN * 2 {
                break;
            }
        } else {
            stall = 0;
        }
        last = now;
    }
    burned_total
}

/// Restore the bond floor and clear the downtime jail installed by the grind,
/// so the reward-split assertions run on a validator that may be paid.
fn unjail_after_downtime(l: &mut StakingLedger, v: [u8; 32]) {
    let target = stellereum::staking::required_bond_floor_nano();
    let current = l.validators[&v].self_bond;
    if current < target {
        l.add_bond(v, target - current)
            .expect("top up the bond to the floor");
    }
    l.unjail(v, u64::MAX)
        .expect("cooldown elapsed; bond at floor");
}

fn sum_delegations(l: &StakingLedger, v: [u8; 32]) -> u64 {
    l.delegations
        .iter()
        .filter(|((vid, _), _)| *vid == v)
        .map(|(_, a)| *a)
        .sum()
}

// ---------------------------------------------------------------------------
// The desync itself.
// ---------------------------------------------------------------------------
#[test]
fn downtime_slash_decrements_the_aggregate_but_not_the_per_delegator_map() {
    let mut l = StakingLedger::new();
    let v = [0x01; 32];
    let d = [0xD1; 32];

    l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    let delegated = 100 * NANO; // 100 STELL delegated
    l.delegate(d, v, delegated).unwrap();

    assert_eq!(l.validators[&v].delegated, delegated);
    assert_eq!(sum_delegations(&l, v), delegated);

    let burned = grind_delegated_to_zero(&mut l, v, 200_000_000);

    let agg = l.validators[&v].delegated;
    let per = sum_delegations(&l, v);
    println!("after downtime slashes:");
    println!("  burned (returned)      = {burned}");
    println!("  validators[.delegated] = {agg}");
    println!("  sum(delegations)       = {per}");
    println!("  self_bond              = {}", l.validators[&v].self_bond);
    println!("  total_burned (global)  = {}", l.total_burned);
    println!(
        "  validators[.total_slashed] = {}",
        l.validators[&v].total_slashed
    );

    // FIXED: this used to assert the two representations DISAGREE. The downtime
    // slash decremented `ValidatorStake.delegated` without touching
    // `StakingLedger::delegations`, so the aggregate and the per-delegator map
    // drifted apart by exactly the burned amount -- and `distribute_reward` divides
    // by one while summing the other. `note_missed_heights` now routes through
    // `slash`, which moves both.
    assert_eq!(
        agg, per,
        "the two representations of the delegated total must agree"
    );
    assert!(
        per >= agg,
        "the per-delegator map still claims more than the validator holds"
    );
}

// ---------------------------------------------------------------------------
// `total_burned` never sees a downtime burn.
// ---------------------------------------------------------------------------
#[test]
fn total_burned_ignores_every_downtime_slash() {
    let mut l = StakingLedger::new();
    let v = [0x02; 32];
    l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();

    let never = |_: &[u8; 32]| false;
    let one = vec![v];
    let mut returned = 0u64;
    for height in 1..=(DOWNTIME_MISS_THRESHOLD as u64) {
        returned += l.note_missed_heights(height, &never, &one);
    }
    println!("downtime slash burned    = {returned}");
    println!(
        "validators[.total_slashed] = {}",
        l.validators[&v].total_slashed
    );
    println!("ledger.total_burned      = {}", l.total_burned);
    assert!(returned > 0, "the slash did burn something");
    assert_eq!(
        l.validators[&v].total_slashed, returned,
        "the per-validator counter saw it"
    );
    // FIXED: `note_missed_heights` used to decrement the validator's bond without
    // incrementing the global counter, and without touching the delegation map or
    // the staking pool. The pool is a plain trie account, so that drift moved the
    // state root. It now routes through `slash`, which keeps every field in step.
    assert_eq!(
        l.total_burned, returned,
        "the global counter must see the downtime burn too"
    );
}

// ---------------------------------------------------------------------------
// The desync is monetised: pro-rata rewards are overpaid, and the overpayment
// is credited to a real native balance with no debit anywhere.
// ---------------------------------------------------------------------------
#[test]
fn desync_inflates_delegator_rewards() {
    let mut l = StakingLedger::new();
    let v = [0x03; 32];
    let d = [0xD3; 32];

    l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    let delegated = 100 * NANO; // 100 STELL
    l.delegate(d, v, delegated).unwrap();

    let burned = grind_delegated_to_zero(&mut l, v, 200_000_000);
    // The downtime slashes also jail the validator. Rewards are refused for a
    // jailed validator (a separate, correct gate), so re-admit it here to keep
    // this test on its own property: the pro-rata split after the delegation
    // aggregate has been ground down.
    unjail_after_downtime(&mut l, v);
    let agg = l.validators[&v].delegated;
    let per = sum_delegations(&l, v);
    println!("ground state: burned={burned} delegated_agg={agg} delegations_map={per}");
    println!("desync ratio = {}x", per as f64 / agg.max(1) as f64);

    // One block's reward, as `apply_block_fees_rewards` distributes it.
    let reward = 1_000_000_000u64; // 1 STELL
    let before = l.claim_delegator_rewards(d, v);
    assert_eq!(before, 0);
    l.distribute_reward(v, reward).unwrap();
    let payout = l.claim_delegator_rewards(d, v);
    let validator_part = l.claim_validator_rewards(v).unwrap();

    println!("reward distributed       = {reward}");
    println!("credited to the DELEGATOR= {payout}");
    println!("credited to the VALIDATOR = {validator_part}");
    println!("total credited            = {}", payout + validator_part);

    // FIXED: the split is now exactly pro-rata. It used to hand the delegator more
    // than the entire emission, because the denominator had been decremented while
    // the numerator had not.
    assert!(
        payout <= reward,
        "a delegator must not receive more than the whole block reward: {payout}"
    );
    assert!(
        payout + validator_part <= reward + validator_part,
        "the ledger minted more reward than existed (inflation)"
    );
}

// ---------------------------------------------------------------------------
// End to end through the real state engine: the inflated reward becomes a real,
// spendable native STELL balance that was never debited from anyone.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn inflated_rewards_become_spendable_native_stell() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellereum::consensus::ValidatorSet;
    use stellereum::post_quantum::{
        derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
    };
    use stellereum::runtime::ValidatorRuntime;
    use stellereum::sharding::Transaction;

    let engine = std::sync::Arc::new(InMemoryStateEngine::new());
    let v = [0x04; 32];
    // FULL-PQ: the spender is a Falcon-512 key; its account is the derived
    // PQ address the reward is delegated under.
    let delegator = FalconKeypair::generate_from_seed(0xD4);
    let delegator_addr =
        derive_pq_address(PqScheme::Falcon512, &delegator.public_key, &DEFAULT_SALT);

    // Fund the staking pool so the setup is realistic.
    engine
        .credit_native(&stellereum::staking::STAKING_POOL, 10_000_000 * NANO)
        .await
        .unwrap();

    {
        let mut l = engine.staking_write().await;
        l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .unwrap();
        let delegated = 100 * NANO;
        l.delegate(delegator_addr, v, delegated).unwrap();
        let burned = grind_delegated_to_zero(&mut l, v, 200_000_000);
        unjail_after_downtime(&mut l, v);
        println!("downtime burned from the pool = {burned}");
        println!(
            "delegated_agg = {}, delegations_map = {}",
            l.validators[&v].delegated,
            sum_delegations(&l, v)
        );
    }

    // One block's reward. Large enough that the (post-fix) pro-rata share of
    // the remaining 999-nano delegation is still a non-zero payout, so the
    // spendable-native leg is actually exercised.
    let reward = 1_000_000_000_000_000u64;
    let key = SigningKey::generate(&mut OsRng);
    let mut rt = ValidatorRuntime::new(key, ValidatorSet::new(), engine.clone(), 1);
    rt = rt.with_block_reward(reward);

    // The delegator starts with NOTHING.
    let start_bal = engine
        .get_account(&delegator_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(start_bal, 0, "the delegator starts empty");

    // A block is finalised and the proposer (validator `v`) earns a reward.
    rt.staking_write()
        .await
        .distribute_reward(v, reward)
        .unwrap();
    engine
        .credit_native(&stellereum::staking::REWARDS_POOL, reward)
        .await
        .expect("back the accrual");

    // The delegator claims. `stake_claim_delegator_rewards` calls
    // `credit_native` -- there is no debit of any pool anywhere on this path.
    let claimed = rt.stake_claim_delegator_rewards(delegator_addr, v).await;
    let end_bal = engine
        .get_account(&delegator_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);

    println!("block reward      = {reward}");
    println!("claimed           = {claimed}");
    println!("delegator balance = {start_bal} -> {end_bal}");

    // FIXED: a delegator could claim strictly more than the whole block reward,
    // because the reward split divided by the validator's `delegated` aggregate
    // while summing the delegation map, and the downtime slash had decremented
    // only the aggregate. With both moved together the split is exactly
    // pro-rata and cannot exceed the emission.
    assert!(
        claimed <= reward,
        "a delegator must not claim more than the whole reward: {claimed}"
    );
    assert!(end_bal > start_bal, "the delegator ends up with real STELL");
    // And the STELL is spendable: it can be moved by an ordinary Falcon-512
    // PQ transaction (the claimed balance must also cover the consensus fee
    // floor, so move half of it).
    let spend = end_bal / 2;
    let pk = delegator.public_key.clone();
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        [0xAB; 32],
        spend,
        100_000,
        0,
        0,
        1,
        Vec::new(),
        &DEFAULT_SALT,
    );
    let sig = delegator.sign(&probe.signing_message());
    let spend_tx = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        [0xAB; 32],
        spend,
        100_000,
        0,
        0,
        1,
        Vec::new(),
        &DEFAULT_SALT,
    );
    engine
        .apply_transaction(&spend_tx, 0)
        .await
        .expect("the inflated balance must be spendable");
    println!("ATTACKER GOAL MET: {end_bal} nano-STELL of unbacked value is spendable");
}
