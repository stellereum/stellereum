//! ADVERSARIAL HUNT: the SVM staking syscalls.
//!
//! Hypothesis: the staking syscalls reachable from a *transaction payload*
//! (`OpCode::SysCallClaimRewards`, `OpCode::SysCallUnbond`) name a validator but
//! never check that the transaction SENDER is that validator. The payout
//! beneficiary is `ctx.sender`, so a third party can sweep a validator's
//! accrued rewards, and can force a validator out of the validator set.
//!
//! This is the "the same quantity is accounted for in two places" pattern: the
//! ledger knows the owner of `pending_rewards` / `self_bond`, and the VM's
//! payout path acts on a caller-supplied `validator` without consulting the
//! ledger's owner field.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::sharding::Transaction;
use stellereum::staking::{self, StakingLedger};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

const NANO: u64 = 1_000_000_000;
/// A generous gas limit; only the *consumed* gas is charged.
const GAS: u64 = 100_000;

fn tx(key: &SigningKey, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    Transaction::sign_with_payload(
        key, [0xEE; 32], // `to` is irrelevant for a payload-only tx
        0, GAS, nonce, 0, 1, payload,
    )
}

/// The total native STELL in existence, as tracked by the account map.
/// This is the invariant an inflation bug breaks.
async fn total_supply(e: &InMemoryStateEngine) -> u64 {
    let map = e.accounts.read().await;
    map.values().map(|a| a.balance).sum()
}

async fn bal(e: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    e.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ATTACK 1: steal a validator's accrued staking rewards.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_stranger_cannot_steal_validator_rewards_via_claim_rewards() {
    let e = InMemoryStateEngine::new();

    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();

    let validator = [0x77; 32];
    let start = 100_000 * NANO;
    let attacker_start = 1_000 * NANO;
    e.update_account(AccountState::new(victim_addr, start))
        .await;
    e.update_account(AccountState::new(attacker_addr, attacker_start))
        .await;

    // 1. The victim bonds, so the staking pool is funded with real value.
    let bond = 10_000 * NANO;
    e.apply_transaction(
        &tx(
            &victim,
            0,
            vec![OpCode::SysCallStake {
                validator,
                amount: bond,
            }],
        ),
        0,
    )
    .await
    .expect("victim bond");
    let pool = bal(&e, &staking::STAKING_POOL).await;
    assert_eq!(pool, bond, "victim's bond is parked in the pool");

    // 2. Blocks are finalised and the victim accrues rewards. This is the normal
    //    path: `Runtime` calls `distribute_reward(block.proposer, block_reward)`
    //    on every finalised block, and the reward is attributed to the
    //    *validator* (the proposer), not to any delegator.
    let block_reward = 500 * NANO;
    let mut accrued = 0u64;
    for _ in 0..10 {
        e.staking_write()
            .await
            .distribute_reward(validator, block_reward)
            .unwrap();
        accrued += block_reward;
    }
    let victim_rewards = e.staking_read().await.validators[&validator].pending_rewards;
    assert_eq!(
        victim_rewards, accrued,
        "victim owns these rewards in the ledger"
    );
    println!("victim accrued rewards      = {victim_rewards}");

    let supply_before = total_supply(&e).await;
    let attacker_before = bal(&e, &attacker_addr).await;

    // 3. THE ATTACK. The attacker is not the validator, is not bonded to it, and
    //    has no relationship to it whatsoever. It just names the victim.
    let err = e
        .apply_transaction(
            &tx(
                &attacker,
                0,
                vec![OpCode::SysCallClaimRewards { validator }],
            ),
            0,
        )
        .await
        .expect_err("a stranger must not be able to claim another validator's rewards");
    println!("claim by a stranger rejected: {err}");

    let attacker_after = bal(&e, &attacker_addr).await;
    let pool_after = bal(&e, &staking::STAKING_POOL).await;
    let leftover = e.staking_read().await.validators[&validator].pending_rewards;

    let profit = attacker_after as i128 - attacker_before as i128;
    println!("attacker  {attacker_before} -> {attacker_after}  (profit {profit})");
    println!("pool      {pool} -> {pool_after} (untouched)");
    println!("victim pending_rewards left = {leftover} (fully intact)");

    // FIXED: the theft is rejected and NOTHING is credited - the victim keeps
    // every pending reward and the pool is never debited. The attacker's own
    // failed attempt costs them the F-01 failure fee (the declared gas
    // limit), which is the price of the block space their attempt consumed -
    // never a coin of the victim's rewards.
    assert_eq!(
        profit,
        -(100_000i128),
        "the theft is rejected: only the failure fee is paid"
    );
    assert_eq!(
        leftover, accrued,
        "the victim's reward balance is untouched by the failed claim"
    );
    assert_eq!(
        pool, pool_after,
        "the pool was never debited, so the victim's bond stays solvent"
    );
    assert_eq!(
        total_supply(&e).await,
        // The direct-apply path has no proposer to credit the F-01 failure fee
        // to, so on THAT path the fee leaves the native supply. What matters
        // here is that NOTHING of the victim's rewards moved: no theft, no
        // inflation.
        supply_before - 100_000,
        "no reward moved: the theft is rejected (only the failure fee left)"
    );

    // (The "owner may still claim" positive case is covered in
    // tests/hunt_staking_theft.rs; here the validator ID is a synthetic
    // [0x77; 32] that is nobody's pubkey, so no owner exists to call it.)
}

// ---------------------------------------------------------------------------
// ATTACK 1b: the sweep is repeatable -- the attacker skims every block's reward.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn reward_theft_is_not_loopable() {
    let e = InMemoryStateEngine::new();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();
    let validator = [0x11; 32];

    // Fund the pool directly so the thief does not even have to bond first.
    e.update_account(AccountState::new(attacker_addr, 1_000 * NANO))
        .await;
    e.credit_native(&staking::STAKING_POOL, 1_000_000 * NANO)
        .await
        .unwrap();
    // The validator exists (bonded at genesis); it has accrued nothing yet.
    e.staking_write()
        .await
        .bond(
            validator,
            staking::MIN_VALIDATOR_BOND + staking::STELL_MIN_BOND_BUFFER,
            0,
        )
        .unwrap();

    let reward = 10 * NANO;
    let mut nonce = 0u64;
    let stolen = 0u64;
    let start = bal(&e, &attacker_addr).await;

    // Every block the proposer earns a reward; the thief tries to skim each one.
    for round in 0..25u64 {
        e.staking_write()
            .await
            .distribute_reward(validator, reward)
            .unwrap();
        e.apply_transaction(
            &tx(
                &attacker,
                nonce,
                vec![OpCode::SysCallClaimRewards { validator }],
            ),
            0,
        )
        .await
        .expect_err(&format!(
            "round {round}: a stranger must not be able to claim"
        ));
        nonce += 1;
    }
    let end = bal(&e, &attacker_addr).await;
    println!("attacker {start} -> {end}; skimmed {stolen}; all {nonce} claims rejected");
    assert_eq!(
        end,
        start - 25 * 100_000,
        "FIXED: 25 rejected claims stole nothing - only the failure fees"
    );
    assert_eq!(
        e.staking_read().await.validators[&validator].pending_rewards,
        25 * reward,
        "every reward the victim earned is still owed to the victim"
    );
    assert_eq!(
        bal(&e, &staking::STAKING_POOL).await,
        1_000_000 * NANO,
        "the pool is untouched by the failed sweep"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 2: force-unbond somebody else's validator -> remove it from the set.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn a_stranger_cannot_force_unbond_a_validator_and_eject_it_from_the_set() {
    let e = InMemoryStateEngine::new();
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);

    let validator = [0x55; 32];
    e.update_account(AccountState::new(victim_addr, 100_000 * NANO))
        .await;
    e.update_account(AccountState::new(attacker.verifying_key().to_bytes(), NANO))
        .await;

    let bond = 50_000 * NANO;
    e.apply_transaction(
        &tx(
            &victim,
            0,
            vec![OpCode::SysCallStake {
                validator,
                amount: bond,
            }],
        ),
        0,
    )
    .await
    .unwrap();

    let vs = e.staking_read().await.to_validator_set();
    println!(
        "validator set BEFORE attack: {:?}",
        vs.validators.keys().collect::<Vec<_>>()
    );
    println!("victim power = {}", vs.power_of(&validator));
    assert!(
        vs.validators.contains_key(&validator),
        "victim is a validator"
    );
    assert_eq!(vs.power_of(&validator), bond);

    // THE ATTACK: the attacker submits `SysCallUnbond` naming the victim.
    // FIXED: the handler checks `ctx.sender == validator`, so this is refused.
    let self_bond = e.staking_read().await.validators[&validator].self_bond;
    let amount = if self_bond >= staking::MIN_VALIDATOR_BOND {
        staking::MIN_VALIDATOR_BOND
    } else {
        self_bond
    };
    let err = e
        .apply_transaction(
            &tx(
                &attacker,
                0,
                vec![OpCode::SysCallUnbond { validator, amount }],
            ),
            0,
        )
        .await
        .expect_err("a stranger must not be able to force-unbond a validator");
    println!("force-unbond rejected: {err}");
    let _txs = 1u64;

    let vs = e.staking_read().await.to_validator_set();
    println!(
        "validator set AFTER  attack: {:?}",
        vs.validators.keys().collect::<Vec<_>>()
    );
    println!("total power = {} (still {bond})", vs.total_power());

    assert!(
        vs.validators.contains_key(&validator),
        "FIXED: the victim is still in the validator set"
    );
    assert_eq!(
        vs.total_power(),
        bond,
        "the network keeps its full voting power; nobody was ejected"
    );
    assert_eq!(
        bal(&e, &staking::STAKING_POOL).await,
        bond,
        "the victim's stake is still fully bonded in the pool"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 2b: pure ledger view -- the handler has no notion of the owner at all.
// ---------------------------------------------------------------------------
#[test]
fn unbond_and_claim_have_no_owner_check_in_the_ledger() {
    // `claim_validator_rewards(validator)` returns the balance for whoever asks.
    // The type system gives us no way to even express "the owner".
    let mut l = StakingLedger::new();
    let owner = [0x01; 32];
    l.bond(owner, 10_000 * NANO, 0).unwrap();
    l.distribute_reward(owner, 7 * NANO).unwrap();
    assert_eq!(l.validators[&owner].pending_rewards, 7 * NANO);
    // There is no `claim_rewards_for(signer, validator)` anywhere: the only
    // signature takes the validator id alone.
    let stolen = l.claim_validator_rewards(owner).unwrap();
    assert_eq!(stolen, 7 * NANO);
    assert_eq!(l.validators[&owner].pending_rewards, 0);
}
