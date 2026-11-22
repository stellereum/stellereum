//! P1 follow-up: the chain must not run without validators.
//!
//! Found on a live two-node run after the state-root fix. Both nodes reported
//! identical heights and identical state roots, which looked perfectly healthy,
//! while `stell_getValidators` returned an empty set, `total_power` was "0" and
//! `quorum` was "1".
//!
//! Two separate defects, and both are covered here:
//!
//! 1. `quorum_power()` computed `(0 * 2) / 3 + 1 == 1`, so a set with no power
//!    needed a single vote to reach quorum. One node could finalise every block
//!    alone. Two nodes would then produce byte-identical empty blocks and agree
//!    on every root, so the agreement was an artefact of both being empty, not
//!    evidence of consensus.
//! 2. `fund_genesis` credited validator accounts but never bonded them. Since
//!    the validator set is derived from the staking ledger, a fresh chain came
//!    up with an empty set and fell straight into (1).

use ed25519_dalek::SigningKey;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::fund_genesis;
use stellereum::state_engine::InMemoryStateEngine;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn set_of(ids: &[[u8; 32]]) -> ValidatorSet {
    let mut v = ValidatorSet::new();
    for id in ids {
        v.validators.insert(*id, 1_000);
    }
    v
}

#[test]
fn empty_validator_set_can_never_reach_quorum() {
    let empty = ValidatorSet::new();
    assert_eq!(empty.total_power(), 0);
    assert_eq!(
        empty.quorum_power(),
        u64::MAX,
        "zero power must not yield a quorum of 1, or a single vote finalises"
    );
}

#[test]
fn zero_power_validators_cannot_reach_quorum() {
    // Distinct from empty: the set is populated, but every entry carries no
    // power (a validator that bonded nothing). This must fail closed too.
    let mut v = ValidatorSet::new();
    v.validators.insert([1u8; 32], 0);
    v.validators.insert([2u8; 32], 0);
    assert_eq!(v.total_power(), 0);
    assert_eq!(v.quorum_power(), u64::MAX);
}

#[test]
fn real_validator_set_has_a_reachable_quorum() {
    // The guard must not brick a healthy chain.
    let v = set_of(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
    let q = v.quorum_power();
    assert_eq!(v.total_power(), 3_000);
    assert_eq!(q, (3_000 * 2) / 3 + 1);
    assert!(
        q > 0 && q <= v.total_power(),
        "a real set must be able to finalise"
    );
}

#[test]
fn quorum_is_by_power_so_small_sets_need_unanimity() {
    // Quorum is a fraction of total power, not a head count. With three
    // equal-power validators, two of them hold exactly 2/3 while quorum is
    // strictly more than 2/3, so all three are required.
    //
    // This is the standard BFT trade-off rather than a defect, but it is worth
    // stating plainly: a 3-validator chain tolerates zero faults, and the
    // 2-validator testnet is in the same position. One silent validator halts
    // it. Four validators is the first size that tolerates one fault, since
    // 3 of 4 meets the 2/3+1 threshold.
    let three = set_of(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
    assert_eq!(three.total_power(), 3_000);
    assert_eq!(three.quorum_power(), 2_001);
    assert!(1_000 < three.quorum_power(), "one of three is never enough");
    assert!(
        2_000 < three.quorum_power(),
        "two of three equal-power validators are still short of 2/3+1"
    );
    assert!(3_000 >= three.quorum_power(), "all three must agree");

    let four = set_of(&[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
    assert_eq!(four.quorum_power(), 2_667);
    assert!(
        3_000 >= four.quorum_power(),
        "three of four must be enough, so one faulty validator is survivable"
    );
}

#[tokio::test]
async fn genesis_bonds_its_validators() {
    let engine = InMemoryStateEngine::new();
    let a = key(1).verifying_key().to_bytes();
    let b = key(2).verifying_key().to_bytes();
    let vset = set_of(&[a, b]);

    fund_genesis(&engine, &vset, 100_000_000_000_000_000).await;

    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.validators.len(),
        2,
        "funded-but-unbonded validators leave the set empty, and an empty set \
         finalises alone"
    );
    assert!(ledger.validators.contains_key(&a));
    assert!(ledger.validators.contains_key(&b));
    for (id, stake) in &ledger.validators {
        assert!(
            stake.self_bond >= stellereum::staking::MIN_VALIDATOR_BOND,
            "validator {id:?} bonded below the minimum, so it would not count"
        );
    }
}

#[tokio::test]
async fn genesis_bond_is_identical_on_every_node() {
    // Two nodes must compute the same ledger, or their genesis state roots
    // diverge and the chain splits at height zero.
    let a = key(1).verifying_key().to_bytes();
    let b = key(2).verifying_key().to_bytes();
    let vset = set_of(&[a, b]);

    let left = InMemoryStateEngine::new();
    fund_genesis(&left, &vset, 100_000_000_000_000_000).await;
    let right = InMemoryStateEngine::new();
    fund_genesis(&right, &vset, 100_000_000_000_000_000).await;

    assert_eq!(
        left.get_state_root().await,
        right.get_state_root().await,
        "genesis must be deterministic across nodes"
    );
}

#[tokio::test]
async fn genesis_does_not_double_bond_a_repeated_validator() {
    let engine = InMemoryStateEngine::new();
    let a = key(1).verifying_key().to_bytes();
    let vset = set_of(&[a]);

    fund_genesis(&engine, &vset, 100_000_000_000_000_000).await;
    let first = engine.staking_read().await.validators[&a].self_bond;
    fund_genesis(&engine, &vset, 100_000_000_000_000_000).await;
    let second = engine.staking_read().await.validators[&a].self_bond;

    assert_eq!(first, second, "funding twice must not inflate the bond");
}

#[tokio::test]
async fn a_fresh_chain_has_a_non_empty_validator_set() {
    // End-to-end shape of the live bug: a freshly funded chain must not report
    // zero power and a quorum of one.
    let engine = InMemoryStateEngine::new();
    let a = key(1).verifying_key().to_bytes();
    let b = key(2).verifying_key().to_bytes();
    fund_genesis(&engine, &set_of(&[a, b]), 100_000_000_000_000_000).await;

    let derived: ValidatorSet = engine.staking_read().await.to_validator_set();
    assert_eq!(derived.validators.len(), 2);
    assert!(derived.total_power() > 0);
    assert!(
        derived.quorum_power() < u64::MAX,
        "a live chain must be able to reach quorum"
    );
}
