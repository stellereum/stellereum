//! Integration tests: staking powers consensus and equivocation slashing.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::staking::{StakingLedger, DEFAULT_COMMISSION_BPS, EQUIVOCATION_SLASH_BPS};
use stellereum::state_engine::InMemoryStateEngine;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

/// Validator voting power mirrors bonded stake (self + delegated).
#[test]
fn consensus_power_follows_stake() {
    let ks = keys(3);
    let mut ledger = StakingLedger::new();
    for (i, k) in ks.iter().enumerate() {
        let amount = stell(1_100 * (i as u64 + 1));
        ledger
            .bond(k.verifying_key().to_bytes(), amount, DEFAULT_COMMISSION_BPS)
            .unwrap();
    }
    let vs = ledger.to_validator_set();
    assert_eq!(vs.total_power(), stell(6_600));
    assert_eq!(vs.power_of(&ks[2].verifying_key().to_bytes()), stell(3_300));
}

/// The runtime slashes a validator that equivocates, reducing its stake and
/// injecting the equivocation evidence into the ledger.
#[tokio::test]
async fn runtime_slashes_equivocation() {
    let ks = keys(4);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );

    let mut ledger = StakingLedger::new();
    for k in &ks {
        ledger
            .bond(
                k.verifying_key().to_bytes(),
                stell(1_100),
                DEFAULT_COMMISSION_BPS,
            )
            .unwrap();
    }
    let offender = ks[0].verifying_key().to_bytes();

    let state = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1).with_staking(ledger);

    // The offender double-votes at height 1 round 0: two conflicting prevotes.
    let a = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let b = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([2u8; 32]));
    rt.hc.add_prevote(a).unwrap();
    rt.hc
        .add_precommit(Vote::sign(
            &ks[1],
            1,
            0,
            VoteKind::Precommit,
            Some([1u8; 32]),
        ))
        .unwrap();
    rt.hc.add_prevote(b).unwrap();
    assert_eq!(rt.hc.equivocations().len(), 1, "evidence must be recorded");

    let burned = rt.apply_equivocation_slashes().await;
    let expected = stell(1_100) * EQUIVOCATION_SLASH_BPS / 10_000;
    assert_eq!(burned, expected, "5% of 1100 STELL must be burned");

    let ledger = rt.staking_read().await.clone();
    assert_eq!(ledger.total_stake(&offender), stell(1_100) - expected);
    assert_eq!(ledger.total_burned, expected);
}

/// Slashing is a no-op when no staking ledger is attached (backward compatible).
#[tokio::test]
async fn no_ledger_no_slash() {
    let ks = keys(4);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let state = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
    let a = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let b = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([2u8; 32]));
    rt.hc.add_prevote(a).unwrap();
    rt.hc.add_prevote(b).unwrap();
    assert_eq!(rt.apply_equivocation_slashes().await, 0);
}

/// A slashed validator's total stake never underflows and burn is bounded.
#[test]
fn slash_never_over_burns() {
    let sk = SigningKey::generate(&mut OsRng);
    let mut ledger = StakingLedger::new();
    ledger
        .bond(
            sk.verifying_key().to_bytes(),
            stell(1_100),
            DEFAULT_COMMISSION_BPS,
        )
        .unwrap();
    // 200% slash would be nonsense; cap at the whole stake via repeated 100% slashes.
    let id = sk.verifying_key().to_bytes();
    let first = ledger.slash(id, 10_000).unwrap();
    assert_eq!(first, stell(1_100));
    assert_eq!(ledger.total_stake(&id), 0);
    // slashing an empty validator yields zero, not an error/underflow
    assert_eq!(ledger.slash(id, 10_000).unwrap(), 0);
}

/// The block proposer accrues the block reward on finalization. Each node keeps
/// its own local ledger, so we assert on the proposer's ledger (which holds the
/// proposer's own stake). In a real deployment the ledger is consensus state.
#[tokio::test]
async fn proposer_receives_block_reward_on_finalize() {
    use stellereum::runtime::Cluster;

    let ks = keys(4);
    let mut nodes = Vec::new();
    for k in &ks {
        // Every node must start from the SAME ledger. The staking ledger is part
        // of the state root, so a node seeded with only its own bond computes a
        // different root from its peers, and a proposal built on one is correctly
        // refused by the others. This was invisible while staking was outside the
        // commitment; the per-node ledgers here were a real inconsistency.
        let mut ledger = StakingLedger::new();
        for v in &ks {
            ledger
                .bond(
                    v.verifying_key().to_bytes(),
                    stell(1_100),
                    DEFAULT_COMMISSION_BPS,
                )
                .unwrap();
        }
        let rt = ValidatorRuntime::new(
            k.clone(),
            ValidatorSet::from_list(
                ks.iter()
                    .map(|x| (x.verifying_key().to_bytes(), 1))
                    .collect(),
            ),
            Arc::new(InMemoryStateEngine::new()),
            1,
        )
        .with_staking(ledger)
        .with_block_reward(stell(7));
        nodes.push(rt);
    }
    let mut cluster = Cluster { nodes };

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let proposer_id = cluster.nodes[proposer_idx].id;

    let bh = cluster.run_height(1_000).await;
    assert_ne!(bh, [0u8; 32]);

    // The proposer finalized height 1 and credited itself 7 STELL.
    let p = &cluster.nodes[proposer_idx];
    assert_eq!(p.finalized.last().unwrap().0, 1);
    let pending = p
        .staking_read()
        .await
        .validators
        .get(&proposer_id)
        .unwrap()
        .pending_rewards;
    assert_eq!(pending, stell(7), "proposer must accrue the block reward");
}

/// The full staking lifecycle is reachable through the runtime (on-chain):
/// bond -> delegate -> undelegate -> cooldown -> withdraw, with attribution.
#[tokio::test]
async fn runtime_staking_lifecycle_is_on_chain() {
    use stellereum::state_engine::AccountState;

    let k = SigningKey::generate(&mut OsRng);
    let val = k.verifying_key().to_bytes();
    let delegator = [0xDD; 32];

    let state = Arc::new(InMemoryStateEngine::new());
    state
        .update_account(AccountState::new(val, stell(10_000)))
        .await;
    state
        .update_account(AccountState::new(delegator, stell(10_000)))
        .await;

    let mut rt =
        ValidatorRuntime::new(k, ValidatorSet::from_list(vec![(val, 1)]), state.clone(), 1)
            .with_staking(StakingLedger::new());

    rt.stake_bond(val, stell(2_000), DEFAULT_COMMISSION_BPS)
        .await
        .unwrap();
    rt.stake_delegate(delegator, val, stell(1_000))
        .await
        .unwrap();
    assert_eq!(state.staking_read().await.total_stake(&val), stell(3_000));
    // A8: the funds actually moved OUT of the accounts.
    assert_eq!(state.get_account(&val).await.unwrap().balance, stell(8_000));
    assert_eq!(
        state.get_account(&delegator).await.unwrap().balance,
        stell(9_000)
    );

    rt.stake_undelegate(delegator, val, stell(1_000), 0)
        .await
        .unwrap();
    // Before cooldown: nothing withdrawable; delegator must not be able to
    // withdraw and the validator must not be able to steal it.
    rt.process_unbonding(1).await;
    assert!(rt.stake_withdraw_delegator(delegator, val).await.is_err());
    assert!(rt.stake_withdraw(val).await.is_err());

    // After cooldown the delegator (only) can withdraw the funds.
    rt.process_unbonding(stellereum::staking::UNBONDING_PERIOD_SECS + 1)
        .await;
    assert_eq!(
        rt.stake_withdraw_delegator(delegator, val).await.unwrap(),
        stell(1_000)
    );
    assert!(
        rt.stake_withdraw(val).await.is_err(),
        "validator must not get delegator funds"
    );
    // Delegator's balance is whole again.
    assert_eq!(
        state.get_account(&delegator).await.unwrap().balance,
        stell(10_000)
    );
}

#[tokio::test]
async fn stake_without_funds_is_rejected_and_moves_nothing() {
    use stellereum::state_engine::AccountState;

    let k = SigningKey::generate(&mut OsRng);
    let val = k.verifying_key().to_bytes();

    let state = Arc::new(InMemoryStateEngine::new());
    state
        .update_account(AccountState::new(val, stell(100)))
        .await; // far below min bond

    let mut rt =
        ValidatorRuntime::new(k, ValidatorSet::from_list(vec![(val, 1)]), state.clone(), 1)
            .with_staking(StakingLedger::new());

    // Cannot bond 1100 STELL with only 100 STELL.
    assert!(rt
        .stake_bond(val, stell(1_100), DEFAULT_COMMISSION_BPS)
        .await
        .is_err());
    assert_eq!(
        state.get_account(&val).await.unwrap().balance,
        stell(100),
        "no funds moved"
    );
    assert_eq!(state.staking_read().await.total_stake(&val), 0);
}

/// P1: at a height boundary the runtime rotates the consensus validator set to
/// reflect bonded stake (weighted power), deterministically from the ledger.
#[tokio::test]
async fn validator_set_rotates_from_stake() {
    use stellereum::state_engine::AccountState;

    let ks = keys(2);
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|i| (*i, 1)).collect());

    let state = Arc::new(InMemoryStateEngine::new());
    for id in &ids {
        state
            .update_account(AccountState::new(*id, stell(20_000)))
            .await;
    }

    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state.clone(), 1)
        .with_staking(StakingLedger::new());
    rt.stake_bond(ids[0], stell(1_100), DEFAULT_COMMISSION_BPS)
        .await
        .unwrap();
    rt.stake_bond(ids[1], stell(3_000), DEFAULT_COMMISSION_BPS)
        .await
        .unwrap();

    // W10.5 ACTIVATION BOUNDARY: the refresh STAGES the rotation for height
    // L+1 (here: derived at height 1, in force from height 2) instead of
    // moving the live quorum mid-flight. The staged set must already carry
    // the bonded powers; the in-force set must still be the old one.
    assert!(
        rt.refresh_validator_set_from_staking().await,
        "set must change"
    );
    let (activation, staged) = rt
        .pending_validators
        .clone()
        .expect("the rotation must be staged, not installed");
    assert_eq!(
        activation, 2,
        "a change derived at height 1 takes effect at height 2"
    );
    assert_eq!(staged.power_of(&ids[1]), stell(3_000));
    assert_eq!(staged.power_of(&ids[0]), stell(1_100));
    assert_eq!(
        rt.validators.power_of(&ids[1]),
        1,
        "in-force set must not move mid-flight"
    );

    // Advance across the boundary with a real height-1 finalize (both old
    // members vote under the still-in-force old set), and the staged set
    // activates exactly on arrival.
    let proposer_id = rt
        .validators
        .proposer_for(1, 0)
        .expect("schedule must name a proposer");
    let pkey = ks
        .iter()
        .find(|k| k.verifying_key().to_bytes() == proposer_id)
        .unwrap();
    let mut blk = stellereum::sharding::Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_001,
        proposer: proposer_id,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    };
    blk.sign_block(pkey);
    let bh = blk.compute_hash();
    for k in ks.iter() {
        rt.on_prevote(stellereum::consensus::Vote::sign(
            k,
            1,
            0,
            stellereum::consensus::VoteKind::Prevote,
            Some(bh),
        ))
        .unwrap();
        rt.on_precommit(stellereum::consensus::Vote::sign(
            k,
            1,
            0,
            stellereum::consensus::VoteKind::Precommit,
            Some(bh),
        ))
        .unwrap();
    }
    assert_eq!(rt.hc.try_precommit_quorum(), Some(bh));
    rt.blocks.insert(bh, blk);
    assert_eq!(rt.try_finalize().await, Some(bh));
    assert_eq!(rt.height(), 2);

    assert_eq!(rt.validators.power_of(&ids[1]), stell(3_000));
    assert_eq!(rt.validators.power_of(&ids[0]), stell(1_100));
    assert_eq!(
        rt.hc.validators.power_of(&ids[1]),
        stell(3_000),
        "consensus set updated too"
    );
}

/// Governance is driven through the runtime against the staking ledger.
#[tokio::test]
async fn runtime_governance_flow_is_on_chain() {
    use stellereum::governance::{
        GovAction, Governance, ProposalStatus, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS,
    };

    let ks = keys(3);
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let mut ledger = StakingLedger::new();
    for id in &ids {
        ledger
            .bond(*id, stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
    }

    let mut rt = ValidatorRuntime::new(
        ks[0].clone(),
        ValidatorSet::from_list(ids.iter().map(|i| (*i, 1)).collect()),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_staking(ledger)
    .with_governance(Governance::new());

    let id = rt
        .gov_propose(
            ids[0],
            "raise reward".into(),
            GovAction::SetBlockReward(stell(9)),
            0,
        )
        .unwrap();
    rt.gov_vote(ids[0], id, VoteChoice::Yes, 1).unwrap();
    rt.gov_vote(ids[1], id, VoteChoice::Yes, 1).unwrap();
    rt.gov_vote(ids[2], id, VoteChoice::No, 1).unwrap();
    let status = rt
        .gov_finalize(id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
        .unwrap();
    assert_eq!(status, ProposalStatus::Passed);
    let applied = rt.gov_execute(ids[0], id).unwrap();
    assert_eq!(applied.block_reward, Some(stell(9)));
}
