//! HUNT: unauthenticated theft of staking rewards from the shared STAKING_POOL.
//!
//! Hypothesis (src/svm.rs:523-540): `OpCode::SysCallClaimRewards { validator }`
//! calls `StakingLedger::claim_validator_rewards(validator)`, which is keyed by
//! the VALIDATOR id, not by `ctx.sender`, and then queues the payout as
//! `(STAKING_POOL, ctx.sender, amount)`. Nothing checks that the sender is the
//! validator that earned the reward. STAKING_POOL is a single shared account
//! holding EVERY validator's bonded principal, so the payout is paid out of
//! other validators' bonded stake.
//!
//! Attacker goal: sender balance strictly greater than before, paid for with a
//! few hundred nano-STELL of gas.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::staking::{MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Bond floor every bond in this file must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn tx_of(key: &SigningKey, nonce: u64, payload: Vec<OpCode>) -> stellereum::sharding::Transaction {
    tx_of_gas(key, nonce, 10_000, payload)
}

fn tx_of_gas(
    key: &SigningKey,
    nonce: u64,
    gas: u64,
    payload: Vec<OpCode>,
) -> stellereum::sharding::Transaction {
    let from = key.verifying_key().to_bytes();
    stellereum::sharding::Transaction::sign_with_payload(key, from, 0, gas, nonce, 1, 1, payload)
}

async fn bal(engine: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    engine.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

/// Anyone with dust can drain any validator's accrued rewards out of the shared
/// staking pool. The victim's `pending_rewards` is zeroed, so the honest
/// validator never even sees the loss coming.
#[tokio::test]
async fn stranger_cannot_steal_validator_rewards_from_pool() {
    let engine = InMemoryStateEngine::new();

    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();

    // Victim bonds 10,000 STELL -> the coins land in the shared STAKING_POOL.
    engine
        .update_account(AccountState::new(victim_addr, stell(10_000) + 10_000))
        .await;
    let bond = tx_of(
        &victim,
        0,
        vec![OpCode::SysCallStake {
            validator: victim_addr,
            amount: stell(10_000),
        }],
    );
    engine
        .apply_transaction(&bond, 0)
        .await
        .expect("bond must succeed");

    let pool_after_bond = bal(&engine, &STAKING_POOL).await;
    assert_eq!(pool_after_bond, stell(10_000), "bond must sit in the pool");

    // Blocks accrue a reward to the victim (this is what the runtime does at
    // every height: `distribute_reward(block.proposer, block_reward)` PLUS
    // the matching native mint into REWARDS_POOL — E2: a bare ledger accrual
    // with no backing must not pay).
    {
        let mut l = engine.staking_write().await;
        l.distribute_reward(victim_addr, stell(500)).unwrap();
        assert_eq!(l.validators[&victim_addr].pending_rewards, stell(500));
    }
    engine
        .credit_native(&REWARDS_POOL, stell(500))
        .await
        .expect("back the accrual");

    // The attacker holds NOTHING but gas, and is not the validator, not a
    // delegator, has no bond, no signature over the victim's key. One syscall.
    engine
        .update_account(AccountState::new(attacker_addr, 10_000))
        .await;
    let before = bal(&engine, &attacker_addr).await;
    assert_eq!(before, 10_000);

    let steal = tx_of(
        &attacker,
        0,
        vec![OpCode::SysCallClaimRewards {
            validator: victim_addr,
        }],
    );
    // FIXED: ClaimRewards is owner-only, so the theft is refused outright.
    let fee = failure_fee(&engine, &steal).await;
    let err = engine
        .apply_transaction(&steal, 0)
        .await
        .expect_err("a stranger must not be able to claim someone else's rewards");
    println!("reward theft rejected: {err}");

    let after = bal(&engine, &attacker_addr).await;
    let pool_after = bal(&engine, &STAKING_POOL).await;

    println!("attacker balance: {before} -> {after}  (gas charged, nothing gained)");
    println!("staking pool:     {pool_after_bond} -> {pool_after} (untouched)");
    println!(
        "victim pending:   {} (still owed in full)",
        engine.staking_read().await.validators[&victim_addr].pending_rewards
    );

    // F-01 / SEC-07: the refusal is ATTRIBUTABLE (the syscall ran and said
    // no), so the attacker pays the failure fee and its nonce is consumed.
    // A failure that cost nothing would be a free DoS - and a spammer could
    // push "claim someone else's rewards" at the chain for nothing. What the
    // attacker must NOT get is the reward: the pool is untouched and the
    // victim's pending rewards are intact.
    assert_refused_tx_paid_failure_fee(&engine, &steal, fee, before, 0).await;
    assert!(
        after < before,
        "the refused theft cost the attacker its fee and gained it nothing"
    );
    assert_eq!(
        pool_after, pool_after_bond,
        "the pool still fully backs every bonded obligation"
    );
    assert_eq!(
        engine.staking_read().await.validators[&victim_addr].pending_rewards,
        stell(500),
        "the victim's reward is intact and still claimable by the victim"
    );
    assert_eq!(
        engine.staking_read().await.total_stake(&victim_addr),
        stell(10_000),
        "ledger still records the full bond"
    );
    // Solvency invariant restored.
    assert!(
        pool_after >= engine.staking_read().await.total_stake(&victim_addr),
        "POOL IS SOLVENT: the coins still cover the bonded obligation"
    );

    // The owner can still claim, so this is an auth check and not a freeze.
    let owner = tx_of_gas(
        &victim,
        1,
        2_000,
        vec![OpCode::SysCallClaimRewards {
            validator: victim_addr,
        }],
    );
    engine
        .apply_transaction(&owner, 0)
        .await
        .expect("the validator may still claim its own rewards");
    assert_eq!(
        engine.staking_read().await.validators[&victim_addr].pending_rewards,
        0
    );
}

/// The same one-line syscall, looped over every validator in the ledger, drains
/// the entire bonded principal of the network into the attacker's account.
#[tokio::test]
async fn stranger_cannot_drain_the_pool_by_looping_over_validators() {
    let engine = InMemoryStateEngine::new();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(attacker_addr, 10_000_000))
        .await;

    // 20 honest validators, each bonding the MIN+buffer floor.
    let mut validators = Vec::new();
    for _i in 0..20u8 {
        let k = SigningKey::generate(&mut OsRng);
        let a = k.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(a, floor() + 10_000))
            .await;
        let t = tx_of(
            &k,
            0,
            vec![OpCode::SysCallStake {
                validator: a,
                amount: floor(),
            }],
        );
        engine.apply_transaction(&t, 0).await.unwrap();
        {
            let mut l = engine.staking_write().await;
            l.distribute_reward(a, stell(900)).unwrap();
        }
        validators.push(a);
    }

    let pool_before = bal(&engine, &STAKING_POOL).await;
    let attacker_before = bal(&engine, &attacker_addr).await;

    // 20 transactions, one per validator -- every single one must bounce.
    for (i, v) in validators.iter().enumerate() {
        let t = tx_of(
            &attacker,
            i as u64,
            vec![OpCode::SysCallClaimRewards { validator: *v }],
        );
        // F-01 / SEC-07: every refused attempt is attributable and costs the
        // attacker its declared limit, and burns its nonce - so the loop
        // cannot be free, and cannot be replayed with the same nonce.
        let fee = failure_fee(&engine, &t).await;
        let before_attempt = bal(&engine, &attacker_addr).await;
        engine
            .apply_transaction(&t, 0)
            .await
            .expect_err("a stranger must not be able to claim a validator's rewards");
        assert_refused_tx_paid_failure_fee(&engine, &t, fee, before_attempt, i as u64).await;
    }

    let pool_after = bal(&engine, &STAKING_POOL).await;
    let attacker_after = bal(&engine, &attacker_addr).await;
    println!("honest bonds in pool: {pool_before}");
    println!("pool after 20 attempts: {pool_after}");
    println!(
        "attacker: {attacker_before} -> {attacker_after} (loss {} STELL in gas)",
        (attacker_before - attacker_after) / 1_000_000_000
    );

    assert_eq!(
        pool_after, pool_before,
        "20 rejected claims move not a single coin out of the pool"
    );
    // F-01: the loop is NOT free - 20 refusals x the declared limit. This is
    // the anti-DoS half of the contract: the theft fails AND it costs the
    // attacker. (The value half: the pool never moved - asserted above.)
    assert_eq!(
        attacker_after,
        attacker_before - 20 * 10_000,
        "all 20 claims rolled back atomically: only the failure fee was charged"
    );
    assert_eq!(
        engine.get_account(&attacker_addr).await.unwrap().nonce,
        20,
        "every refusal consumed its nonce"
    );
    for v in &validators {
        assert_eq!(
            engine.staking_read().await.validators[v].pending_rewards,
            stell(900),
            "every honest validator keeps its pending reward"
        );
    }
    let l = engine.staking_read().await;
    let still_owed: u64 = l.validators.values().map(|v| v.total()).sum();
    assert_eq!(still_owed, 20 * floor(), "20 validators x floor bonded");
    assert!(
        pool_after >= still_owed,
        "SOLVENT: the ledger claims {still_owed} nano bonded and {pool_after} nano of coins exist"
    );
}

/// A third party can also destroy (not just steal) a validator's rewards: when
/// the pool cannot cover the payout the transaction errors, but the ledger
/// mutation from the SVM's clone-commit was ALREADY written to consensus state,
/// so `pending_rewards` is silently zeroed and the reward is burned.
#[tokio::test]
async fn failed_claim_does_not_burn_validator_rewards() {
    let engine = InMemoryStateEngine::new();
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();

    engine
        .update_account(AccountState::new(victim_addr, floor() + 10_000))
        .await;
    let bond = tx_of(
        &victim,
        0,
        vec![OpCode::SysCallStake {
            validator: victim_addr,
            amount: floor(),
        }],
    );
    engine.apply_transaction(&bond, 0).await.unwrap();
    {
        let mut l = engine.staking_write().await;
        // Reward far larger than the pool: 5,000 STELL earned on a floor bond.
        l.distribute_reward(victim_addr, stell(5_000)).unwrap();
    }
    engine
        .update_account(AccountState::new(attacker_addr, 10_000))
        .await;

    let t = tx_of(
        &attacker,
        0,
        vec![OpCode::SysCallClaimRewards {
            validator: victim_addr,
        }],
    );
    let res = engine.apply_transaction(&t, 0).await;
    println!("apply_transaction result: {res:?}");
    let pending = engine.staking_read().await.validators[&victim_addr].pending_rewards;
    println!("victim pending_rewards after the FAILED tx: {pending}");
    println!("pool: {}", bal(&engine, &STAKING_POOL).await);
    assert!(
        res.is_err(),
        "a stranger's claim is refused: only the validator may claim"
    );
    assert_eq!(
        pending,
        stell(5_000),
        "FIXED: a failed claim must NOT destroy the validator's pending rewards"
    );
    // And the pool was never debited by the refused payout.
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        floor(),
        "the refused payout debited nothing from the pool"
    );
}
