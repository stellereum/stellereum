//! E2 (staking economics): rewards are minted into an explicit, capped pool.
//!
//! Previously `distribute_reward` credited ledger counters with no backing and
//! both claim opcodes paid out of `STAKING_POOL` — i.e. out of bonded
//! principal — with no cap anywhere on the path. These tests pin the fix:
//!   1. a block reward mints 1:1 into `REWARDS_POOL` (ledger + native coins),
//!      leaves `STAKING_POOL` (principal) byte-identical, and claims drain
//!      the rewards pool;
//!   2. minting past `REWARDS_EMISSION_CAP` is refused fail-closed: no ledger
//!      credit, no native mint, no phantom pending rewards.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{
    MIN_VALIDATOR_BOND, REWARDS_EMISSION_CAP, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// New-bond floor since the re-entry fix: bare-MIN bonds are refused, so every
/// SysCallStake below bonds exactly MIN+buffer.
fn bond_amount() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}
use stellereum::svm::{OpCode, GAS_STAKE_CLAIM};

const STELL: u64 = 1_000_000_000;
const TS: u64 = 1_760_000_000;

fn tx_of(key: &SigningKey, nonce: u64, gas_limit: u64, payload: Vec<OpCode>) -> Transaction {
    let from = key.verifying_key().to_bytes();
    Transaction::sign_with_payload(
        key,
        from,
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
    )
}

fn block_of(height: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

async fn bal(engine: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    engine.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

/// (1) Rewards come from the pool, not principal: the block mint credits
/// `REWARDS_POOL` 1:1 (ledger accounting AND native coins), `STAKING_POOL`
/// stays exactly the bonded amount, and the later claim drains the rewards
/// pool while principal never moves.
#[tokio::test]
async fn block_reward_mints_into_pool_and_claim_leaves_principal_untouched() {
    let engine = InMemoryStateEngine::new();
    let val = SigningKey::generate(&mut OsRng);
    let val_addr = val.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(val_addr, bond_amount() + 5_000_000))
        .await;

    engine
        .apply_transaction(
            &tx_of(
                &val,
                0,
                20_000,
                vec![OpCode::SysCallStake {
                    validator: val_addr,
                    amount: bond_amount(),
                }],
            ),
            0,
        )
        .await
        .unwrap();
    assert_eq!(bal(&engine, &STAKING_POOL).await, bond_amount());

    // The block mint: reward R to the proposer.
    let r = 5 * STELL;
    engine
        .apply_block_transition(&block_of(1, vec![], val_addr), r)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(
            l.rewards_minted, r,
            "cumulative mint tracks the block reward"
        );
        assert_eq!(l.rewards_pool, r, "mint funds the ledger pool 1:1");
        assert_eq!(
            l.validators[&val_addr].pending_rewards, r,
            "proposer accrues the full reward (no delegators)"
        );
    }
    assert_eq!(
        bal(&engine, &REWARDS_POOL).await,
        r,
        "native mint lands in REWARDS_POOL"
    );
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        bond_amount(),
        "principal is untouched by the mint"
    );

    // Claim: exact payout minus claim gas, drained from the rewards pool.
    let before = bal(&engine, &val_addr).await;
    engine
        .apply_transaction(
            &tx_of(
                &val,
                1,
                100_000,
                vec![OpCode::SysCallClaimRewards {
                    validator: val_addr,
                }],
            ),
            0,
        )
        .await
        .expect("claim works");
    assert_eq!(
        bal(&engine, &val_addr).await,
        before + r - GAS_STAKE_CLAIM,
        "exact claim payout minus claim gas"
    );
    assert_eq!(
        bal(&engine, &REWARDS_POOL).await,
        0,
        "claim drains the rewards pool"
    );
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        bond_amount(),
        "principal is untouched by the claim"
    );
    assert_eq!(engine.staking_read().await.rewards_pool, 0);
}

/// (1b) Same funding discipline for the delegator leg: delegation principal
/// stays parked while rewards arrive from, and leave, the rewards pool.
#[tokio::test]
async fn delegator_rewards_come_from_pool_not_principal() {
    let engine = InMemoryStateEngine::new();
    let validator = [0xCCu8; 32];
    let funder = SigningKey::generate(&mut OsRng);
    let funder_addr = funder.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(funder_addr, bond_amount() + 20_000))
        .await;
    engine
        .apply_transaction(
            &tx_of(
                &funder,
                0,
                20_000,
                vec![OpCode::SysCallStake {
                    validator,
                    amount: bond_amount(),
                }],
            ),
            0,
        )
        .await
        .unwrap();

    let delegator = SigningKey::generate(&mut OsRng);
    let delegator_addr = delegator.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(delegator_addr, 1_000 * STELL + 5_000_000))
        .await;
    engine
        .apply_transaction(
            &tx_of(
                &delegator,
                0,
                100_000,
                vec![OpCode::SysCallDelegate {
                    validator,
                    amount: 1_000 * STELL,
                }],
            ),
            0,
        )
        .await
        .unwrap();
    // Principal parked: bond + delegation, nothing else.
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        bond_amount() + 1_000 * STELL
    );
    assert_eq!(bal(&engine, &REWARDS_POOL).await, 0);

    let r = 100 * STELL;
    engine
        .apply_block_transition(&block_of(1, vec![], validator), r)
        .await;
    assert_eq!(bal(&engine, &REWARDS_POOL).await, r);
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        bond_amount() + 1_000 * STELL,
        "delegation principal untouched by the mint"
    );
    // LAZY (F1): the accrued reward is computed from the validator's
    // accumulator on demand — the raw map holds only the SETTLED part.
    let owed: u64 = engine
        .staking_read()
        .await
        .delegator_rewards_of(delegator_addr, validator);
    assert!(owed > 0, "delegation accrued rewards");

    let before = bal(&engine, &delegator_addr).await;
    engine
        .apply_transaction(
            &tx_of(
                &delegator,
                1,
                100_000,
                vec![OpCode::SysCallClaimDelegatorRewards { validator }],
            ),
            0,
        )
        .await
        .expect("delegator claim works");
    assert_eq!(
        bal(&engine, &delegator_addr).await,
        before + owed - GAS_STAKE_CLAIM
    );
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        bond_amount() + 1_000 * STELL,
        "delegation principal untouched by the claim"
    );
}

/// (2) Cap enforced fail-closed: minting past the cap refuses with no ledger
/// credit and no native mint; minting exactly to the cap still works.
#[tokio::test]
async fn rewards_cap_is_fail_closed_over_cap() {
    let engine = InMemoryStateEngine::new();
    let val = SigningKey::generate(&mut OsRng);
    let val_addr = val.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(val_addr, bond_amount() + 5_000_000))
        .await;
    engine
        .apply_transaction(
            &tx_of(
                &val,
                0,
                20_000,
                vec![OpCode::SysCallStake {
                    validator: val_addr,
                    amount: bond_amount(),
                }],
            ),
            0,
        )
        .await
        .unwrap();

    // White-box pre-fill to just under the cap.
    {
        let mut l = engine.staking_write().await;
        l.rewards_minted = REWARDS_EMISSION_CAP - 100;
        l.rewards_pool = 50;
    }

    // 101 over the remaining 100: refused end-to-end (no mint, no credit).
    engine
        .apply_block_transition(&block_of(1, vec![], val_addr), 101)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(
            l.rewards_minted,
            REWARDS_EMISSION_CAP - 100,
            "no partial mint"
        );
        assert_eq!(l.rewards_pool, 50, "pool untouched by refused mint");
        assert_eq!(
            l.validators[&val_addr].pending_rewards, 0,
            "refused mint credits no phantom rewards"
        );
    }
    assert_eq!(
        bal(&engine, &REWARDS_POOL).await,
        0,
        "no native mint on refusal"
    );

    // Exactly to the cap: allowed.
    engine
        .apply_block_transition(&block_of(2, vec![], val_addr), 100)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(l.rewards_minted, REWARDS_EMISSION_CAP);
        assert_eq!(l.rewards_pool, 150);
        assert_eq!(l.validators[&val_addr].pending_rewards, 100);
    }
    assert_eq!(bal(&engine, &REWARDS_POOL).await, 100);

    // At the cap: even 1 nano refuses.
    engine
        .apply_block_transition(&block_of(3, vec![], val_addr), 1)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(l.rewards_minted, REWARDS_EMISSION_CAP);
        assert_eq!(
            l.validators[&val_addr].pending_rewards, 100,
            "still no phantom credit"
        );
    }
    assert_eq!(
        bal(&engine, &REWARDS_POOL).await,
        100,
        "still no native mint"
    );
}
