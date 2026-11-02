//! Staking-ledger V2 migration: bytes persisted before the coordinated upgrade
//! that appended `equivocation_dedup` + `vesting_schedules` must decode via
//! `DomainSnapshotV2` with both new sets empty (exact — neither registry
//! existed when written). Regression pin for the live-boot refusal
//! ("restore domains: io error") that bricked both validators on upgrade.
use stellereum::staking::{StakingLedger, StakingLedgerV2, MIN_VALIDATOR_BOND};
use stellereum::storage::{decode_domain_snapshot, DomainSnapshotV2};

#[test]
fn v2_ledger_bytes_decode_with_empty_new_sets() {
    // Bond on the CURRENT ledger (V2 has no methods by design), then move the
    // E2-era fields into a V2 shape — exactly the bytes the live network
    // persisted before the upgrade appended the two trailing fields.
    let mut live = StakingLedger::default();
    let v = [0x42u8; 32];
    // Bond via the floor-exempt genesis path (production bytes were
    // genesis-bonded at bare MIN before the floor existed).
    live.bond_genesis(v, MIN_VALIDATOR_BOND, 0)
        .expect("genesis-style bond at bare MIN must succeed");
    assert!(live.to_validator_set().contains(&v));
    let StakingLedger {
        validators,
        delegations,
        delegator_rewards,
        unbonding,
        withdrawable,
        total_burned,
        rewards_pool,
        rewards_minted,
        locked_governance,
        pq_equivocation_dedup,
        validator_pq_keys,
        ..
    } = live;

    let snap = DomainSnapshotV2 {
        staking: StakingLedgerV2 {
            validators,
            delegations,
            delegator_rewards,
            unbonding,
            withdrawable,
            total_burned,
            rewards_pool,
            rewards_minted,
            locked_governance,
            pq_equivocation_dedup,
            validator_pq_keys,
        },
        ..Default::default()
    };
    let bytes = bincode::serialize(&snap).expect("V2 snapshot serializes");
    // Current-struct decode must FAIL on V2 bytes (this is the boot refusal).
    assert!(
        bincode::deserialize::<stellereum::storage::DomainSnapshot>(&bytes).is_err(),
        "documents why the migration exists"
    );
    // The migration path accepts them.
    let back = decode_domain_snapshot(&bytes).expect("V2 migration must succeed");
    assert!(
        back.staking.to_validator_set().contains(&v),
        "bond survives"
    );
    assert_eq!(
        back.staking.validators[&v].self_bond, MIN_VALIDATOR_BOND,
        "power byte-identical"
    );
    assert!(
        back.staking.equivocation_dedup.is_empty(),
        "dedup starts empty"
    );
    assert!(
        back.staking.vesting_schedules.is_empty(),
        "vesting starts empty"
    );
}

#[test]
fn current_shape_still_decodes_directly() {
    let snap = stellereum::storage::DomainSnapshot::default();
    let bytes = bincode::serialize(&snap).expect("current serializes");
    let back = decode_domain_snapshot(&bytes).expect("current decodes directly");
    assert!(back.staking.validators.is_empty());
}

/// Staking-ledger V7 migration: bytes persisted after the F1 lazy accumulator
/// but before the downtime-jail/commission/lock maps (the CURRENT shape minus
/// those three trailing maps) must decode via `DomainSnapshotV7` with the
/// three new maps empty (exact — none of the paths that create them existed
/// when written) while the accumulator state survives byte-identical.
/// Truly corrupt bytes are still refused fail-closed.
#[test]
fn v7_pre_jail_trio_bytes_decode_with_empty_new_maps() {
    use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER, StakingLedger};
    use stellereum::storage::{DomainSnapshotV7, StakingLedgerV4};

    // A live ledger in the V7-era shape: bonded, delegated, and carrying
    // LAZY accumulator state (the whole point of V7 over V3 is that the
    // accumulator maps are present and must survive).
    let mut live = StakingLedger::new();
    let v = [0x42u8; 32];
    let delegator = [0x43u8; 32];
    live.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .expect("bond above the floor must succeed");
    live.delegate(delegator, v, 2_000_000_000).unwrap();
    live.distribute_reward(v, 1_000_000_000).unwrap();
    assert!(
        !live.reward_accumulators.is_empty(),
        "the V7-era ledger must carry accumulator state, or this test proves nothing"
    );

    // The OLD bytes: the ledger WITHOUT the three jail-trio maps —
    // byte-identical to what a pre-upgrade node wrote.
    let old = DomainSnapshotV7 {
        staking: StakingLedgerV4 {
            validators: live.validators.clone(),
            delegations: live.delegations.clone(),
            delegator_rewards: live.delegator_rewards.clone(),
            unbonding: live.unbonding.clone(),
            withdrawable: live.withdrawable.clone(),
            total_burned: live.total_burned,
            rewards_pool: live.rewards_pool,
            rewards_minted: live.rewards_minted,
            locked_governance: live.locked_governance.clone(),
            pq_equivocation_dedup: live.pq_equivocation_dedup.clone(),
            equivocation_dedup: live.equivocation_dedup.clone(),
            validator_pq_keys: live.validator_pq_keys.clone(),
            min_validator_bond: live.min_validator_bond,
            vesting_schedules: live.vesting_schedules.clone(),
            reward_accumulators: live.reward_accumulators.clone(),
            delegator_reward_checkpoints: live.delegator_reward_checkpoints.clone(),
        },
        ..Default::default()
    };
    let old_bytes = bincode::serialize(&old).expect("V7 snapshot serializes");
    // Current-struct decode must FAIL on V7 bytes (this is the boot refusal
    // the fallback exists for).
    assert!(
        bincode::deserialize::<stellereum::storage::DomainSnapshot>(&old_bytes).is_err(),
        "documents why the V7 fallback exists"
    );
    // The migration path accepts them.
    let back = decode_domain_snapshot(&old_bytes).expect("V7 migration must succeed");
    assert!(
        back.staking.to_validator_set().contains(&v),
        "bond survives"
    );
    assert_eq!(
        back.staking.validators[&v].self_bond,
        MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
        "power byte-identical"
    );
    assert_eq!(
        back.staking.reward_accumulators, live.reward_accumulators,
        "the V7-era accumulator survives (this is what V3 would have dropped)"
    );
    assert_eq!(
        back.staking.delegator_reward_checkpoints, live.delegator_reward_checkpoints,
        "checkpoints survive"
    );
    assert!(
        back.staking.jail.is_empty(),
        "no phantom jail: the jailing path did not exist when written"
    );
    assert!(
        back.staking.commission_schedule.is_empty(),
        "no phantom commission schedule"
    );
    assert!(
        back.staking.redelegation_lock.is_empty(),
        "no phantom redelegation locks"
    );
    // Fail-closed: truncated bytes are refused, never partially upgraded.
    let cut = old_bytes.len() / 2;
    assert!(
        decode_domain_snapshot(&old_bytes[..cut]).is_err(),
        "truncated V7 bytes must be refused"
    );
    assert!(
        decode_domain_snapshot(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err(),
        "garbage bytes must be refused"
    );
}
