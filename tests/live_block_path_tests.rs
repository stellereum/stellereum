//! P0 regression: the LIVE consensus path moved no native funds.
//!
//! `ValidatorRuntime::try_finalize` / `apply_and_advance` /
//! `replay_historical_block` all reach the state engine through
//! `apply_block_fees_rewards` -> `InMemoryStateEngine::apply_block_parallel_fees`.
//! That path ran the SVM payload and then threw the result's `transfers` and
//! `payouts` away (it only checked `execute_payload(..).is_ok()`), while
//! `apply_transaction` applied them. On a real block, therefore:
//!
//!   * `OpCode::Transfer` credited nobody,
//!   * `SysCallStake` recorded a bond but never moved the bond into the
//!     staking pool (free consensus power),
//!   * `SysCallClaimRewards` zeroed `pending_rewards` but paid nothing.
//!
//! Every pre-existing test for those used `apply_transaction`, so nothing
//! caught it. These tests drive the SAME payloads through the block path.
//!
//! They also pin the second half of the hole: `execute_payload` hardcoded
//! `timestamp: 0`, so the VM's "now" was epoch 0 even though the block carried
//! a real timestamp - `SysCallUnbond` matured at
//! `UNBONDING_PERIOD_SECS` instead of `block.timestamp + UNBONDING_PERIOD_SECS`
//! and contracts were created at time 0.

use ed25519_dalek::SigningKey;
use stellereum::sharding::Transaction;
use stellereum::staking::{
    MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    OpCode, GAS_BASIC_TRANSFER, GAS_STAKE_BOND, GAS_STAKE_CLAIM, GAS_STAKE_UNBOND,
};

/// A fixed, realistic block timestamp. Never 0: 0 is exactly the bug.
const BLOCK_TS: u64 = 1_760_000_000;

/// Bond floor every bond in this file must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

async fn pool(e: &InMemoryStateEngine) -> u64 {
    balance(e, &STAKING_POOL).await
}

// ---------------------------------------------------------------------------
// 1. OpCode::Transfer through the live path
// ---------------------------------------------------------------------------

/// The recipient of a payload `Transfer` must actually receive the coins when
/// the transaction is applied as part of a block.
#[tokio::test]
async fn payload_transfer_moves_native_funds_on_the_live_block_path() {
    let engine = InMemoryStateEngine::new();
    let sk = key(0x11);
    let sender = sk.verifying_key().to_bytes();
    let plain_to = [0xAAu8; 32];
    let payload_to = [0xBBu8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;

    // gas_limit == the opcode's own cost, so the assertion below is about the
    // value movement and not about which fee rule a path charges.
    let tx = Transaction::sign_with_payload(
        &sk,
        plain_to,
        1_000,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        vec![OpCode::Transfer {
            recipient: payload_to,
            amount: 5_000,
        }],
    );

    let (applied, failed, fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TS)
        .await;

    assert_eq!((applied, failed), (1, 0), "the payload transaction applies");
    assert_eq!(status, vec![true]);
    assert_eq!(fees, GAS_BASIC_TRANSFER, "the declared gas is collected");

    // THE regression: before the fix the payload's transfers were discarded, so
    // `payload_to` stayed at 0 while the transaction reported success.
    assert_eq!(
        balance(&engine, &payload_to).await,
        5_000,
        "the payload Transfer must credit its recipient"
    );
    assert_eq!(
        balance(&engine, &plain_to).await,
        1_000,
        "the plain amount still moves"
    );
    assert_eq!(
        balance(&engine, &sender).await,
        start - 1_000 - GAS_BASIC_TRANSFER - 5_000,
        "the sender pays the amount, the fee AND what the payload moved"
    );
    assert_eq!(engine.get_account(&sender).await.unwrap().nonce, 1);
}

// ---------------------------------------------------------------------------
// 2. SysCallStake through the live path: the bond must reach the pool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sys_call_stake_funds_the_staking_pool_on_the_live_block_path() {
    let engine = InMemoryStateEngine::new();
    let sk = key(0x22);
    let validator = sk.verifying_key().to_bytes();
    let start = floor() + GAS_STAKE_BOND + 4_242;
    engine
        .update_account(AccountState::new(validator, start))
        .await;
    assert_eq!(pool(&engine).await, 0, "the pool starts empty");

    let tx = Transaction::sign_with_payload(
        &sk,
        validator,
        0,
        GAS_STAKE_BOND,
        0,
        1,
        1,
        vec![OpCode::SysCallStake {
            validator,
            amount: floor(),
        }],
    );

    let (applied, failed, _fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0), "the bond transaction applies");
    assert_eq!(status, vec![true]);

    // THE regression: the ledger recorded the bond but the transfer that parks
    // the coins in the pool was discarded - consensus power bought for free.
    assert_eq!(
        pool(&engine).await,
        floor(),
        "the bond must be paid into the staking pool"
    );
    assert_eq!(
        balance(&engine, &validator).await,
        start - floor() - GAS_STAKE_BOND,
        "the bond and the gas leave the sender"
    );
    let vs = engine.staking_read().await.to_validator_set();
    assert_eq!(
        vs.power_of(&validator),
        floor(),
        "the bond still buys voting power - now backed by real coins"
    );
}

// ---------------------------------------------------------------------------
// 3. SysCallClaimRewards through the live path: the payout comes from the
//    rewards pool, never from bonded principal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_rewards_payout_comes_from_the_rewards_pool_on_the_live_block_path() {
    let engine = InMemoryStateEngine::new();
    let sk = key(0x33);
    let validator = sk.verifying_key().to_bytes();
    let start = floor() + GAS_STAKE_BOND + GAS_STAKE_CLAIM;
    engine
        .update_account(AccountState::new(validator, start))
        .await;

    // Block 1: bond through the live path, so the pool really holds the coins.
    let bond_tx = Transaction::sign_with_payload(
        &sk,
        validator,
        0,
        GAS_STAKE_BOND,
        0,
        1,
        1,
        vec![OpCode::SysCallStake {
            validator,
            amount: floor(),
        }],
    );
    let (applied, failed, _, _, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&bond_tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0));
    let after_bond = balance(&engine, &validator).await;
    assert_eq!(pool(&engine).await, floor());

    // Accrue rewards, the way `apply_block_transition` does for a proposer:
    // the ledger entry AND the backing coins in REWARDS_POOL (a bare ledger
    // accrual with no backing must not pay, by design — E2).
    let reward = 500_000_000_000u64; // 500 STELL
    engine
        .staking_write()
        .await
        .distribute_reward(validator, reward)
        .unwrap();
    engine
        .credit_native(&REWARDS_POOL, reward)
        .await
        .expect("back the accrual");
    assert_eq!(
        engine.staking_read().await.validators[&validator].pending_rewards,
        reward
    );

    // Block 2: claim through the live path.
    let claim_tx = Transaction::sign_with_payload(
        &sk,
        [0u8; 32],
        0,
        GAS_STAKE_CLAIM,
        1,
        1,
        1,
        vec![OpCode::SysCallClaimRewards { validator }],
    );
    let (applied, failed, _fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&claim_tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0), "the claim applies");
    assert_eq!(status, vec![true]);

    // THE regression: `pending_rewards` was zeroed while the payout itself was
    // discarded - the reward simply vanished. E2: the payout must drain the
    // rewards pool while bonded principal stays untouched.
    assert_eq!(
        engine.staking_read().await.validators[&validator].pending_rewards,
        0,
        "the claim consumes the accrued reward"
    );
    assert_eq!(
        pool(&engine).await,
        floor(),
        "the claim must not touch bonded principal"
    );
    assert_eq!(
        balance(&engine, &REWARDS_POOL).await,
        0,
        "the payout drains the rewards pool"
    );
    assert_eq!(
        balance(&engine, &validator).await,
        after_bond + reward - GAS_STAKE_CLAIM,
        "the payout reaches the claimant"
    );
}

// ---------------------------------------------------------------------------
// 4. block.timestamp reaches the VM (SysCallUnbond maturity)
// ---------------------------------------------------------------------------

/// `SysCallUnbond` stamps `release_at = now + UNBONDING_PERIOD_SECS`, where
/// `now` comes from `VmContext.timestamp`. It used to be hardcoded 0, so an
/// unbond matured at `UNBONDING_PERIOD_SECS` after the epoch instead of
/// `block.timestamp + UNBONDING_PERIOD_SECS` - and matured immediately on any
/// chain whose blocks are older than the cooldown.
#[tokio::test]
async fn block_timestamp_reaches_the_vm_unbonding_maturity() {
    let engine = InMemoryStateEngine::new();
    let sk = key(0x44);
    let validator = sk.verifying_key().to_bytes();
    let start = floor() + GAS_STAKE_BOND + GAS_STAKE_UNBOND;
    engine
        .update_account(AccountState::new(validator, start))
        .await;

    // Block 1: bond so there is something to unbond.
    let bond_tx = Transaction::sign_with_payload(
        &sk,
        validator,
        0,
        GAS_STAKE_BOND,
        0,
        1,
        1,
        vec![OpCode::SysCallStake {
            validator,
            amount: floor(),
        }],
    );
    let (applied, failed, _, _, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&bond_tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0));

    // Block 2: full exit, applied at BLOCK_TS.
    let unbond_tx = Transaction::sign_with_payload(
        &sk,
        [0u8; 32],
        0,
        GAS_STAKE_UNBOND,
        1,
        1,
        1,
        vec![OpCode::SysCallUnbond {
            validator,
            amount: floor(),
        }],
    );
    let (applied, failed, _fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&unbond_tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0), "the unbond applies");
    assert_eq!(status, vec![true]);

    let ledger = engine.staking_read().await;
    assert_eq!(ledger.unbonding.len(), 1, "one unbonding entry");
    assert_eq!(
        ledger.unbonding[0].release_at,
        BLOCK_TS + UNBONDING_PERIOD_SECS,
        "maturity is measured from the BLOCK timestamp, not from epoch 0"
    );
    assert_ne!(
        ledger.unbonding[0].release_at, UNBONDING_PERIOD_SECS,
        "0 + UNBONDING_PERIOD_SECS is exactly the hardcoded-timestamp bug"
    );
    drop(ledger);

    // The maturity clock is real: the entry must NOT be withdrawable yet, and
    // must be once the block timestamp has advanced past the release time.
    engine
        .staking_write()
        .await
        .process_unbonding(BLOCK_TS + UNBONDING_PERIOD_SECS - 1)
        .unwrap();
    assert_eq!(
        engine.staking_read().await.withdrawable_of(&validator),
        0,
        "not mature one second early"
    );
    engine
        .staking_write()
        .await
        .process_unbonding(BLOCK_TS + UNBONDING_PERIOD_SECS)
        .unwrap();
    assert_eq!(
        engine.staking_read().await.withdrawable_of(&validator),
        floor(),
        "mature exactly at release_at"
    );
}

// ---------------------------------------------------------------------------
// 5. block.timestamp reaches the VM (contract creation time)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_timestamp_reaches_the_vm_contract_creation_time() {
    let engine = InMemoryStateEngine::new();
    let sk = key(0x55);
    let creator = sk.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(creator, 10_000_000))
        .await;

    let code = wat::parse_str("(module)").expect("wat compiles");
    let tx = Transaction::sign_with_payload(
        &sk,
        [0u8; 32],
        0,
        200_000,
        0,
        1,
        1,
        vec![OpCode::SysCallDeployContract { code }],
    );
    let (applied, failed, _fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0), "the deploy applies");
    assert_eq!(status, vec![true]);

    let addresses = engine.all_contract_addresses().await;
    assert_eq!(addresses.len(), 1, "one contract deployed");
    let contract = engine
        .get_contract(&addresses[0])
        .await
        .expect("contract exists");
    assert_eq!(
        contract.created_at, BLOCK_TS,
        "a contract is created when the block that deployed it says it is"
    );
    assert_ne!(contract.created_at, 0, "0 is the hardcoded-timestamp bug");
}

// ---------------------------------------------------------------------------
// 6/7. The live path and the single-tx path cannot disagree
// ---------------------------------------------------------------------------

async fn run_on_both_paths(
    tx: &Transaction,
    funding: u64,
) -> (InMemoryStateEngine, InMemoryStateEngine, usize, usize) {
    let single = InMemoryStateEngine::new();
    let block = InMemoryStateEngine::new();
    for e in [&single, &block] {
        e.update_account(AccountState::new(tx.from, funding)).await;
    }

    let res = single.apply_transaction(tx, BLOCK_TS).await;
    let single_err = res.is_err();
    let (applied, failed, _fees, _status, _) = block
        .apply_block_parallel_fees(std::slice::from_ref(tx), BLOCK_TS)
        .await;

    assert_eq!(
        single_err,
        failed == 1,
        "the two paths must reach the same verdict (single-tx err={single_err}, block applied={applied} failed={failed})"
    );
    (single, block, applied, failed)
}

/// The same transaction, applied through the two live entry points, must move
/// the same value and produce the same state root. `gas_limit` is set to the
/// gas the payload actually consumes, so the (documented) difference in which
/// fee number each path charges cannot mask a value-movement difference.
#[tokio::test]
async fn live_block_path_and_single_tx_path_agree_on_a_payload_transfer() {
    let sk = key(0x66);
    let sender = sk.verifying_key().to_bytes();
    let plain_to = [0xCCu8; 32];
    let payload_to = [0xDDu8; 32];

    let tx = Transaction::sign_with_payload(
        &sk,
        plain_to,
        2_000,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        vec![OpCode::Transfer {
            recipient: payload_to,
            amount: 7_000,
        }],
    );

    let (single, block, applied, failed) = run_on_both_paths(&tx, 1_000_000).await;
    assert_eq!((applied, failed), (1, 0));

    for e in [&single, &block] {
        assert_eq!(
            balance(e, &payload_to).await,
            7_000,
            "payload transfer credited"
        );
        assert_eq!(balance(e, &plain_to).await, 2_000, "plain amount credited");
        assert_eq!(
            balance(e, &sender).await,
            1_000_000 - 2_000 - GAS_BASIC_TRANSFER - 7_000
        );
        assert_eq!(e.get_account(&sender).await.unwrap().nonce, 1);
    }
    assert_eq!(
        single.get_state_root().await,
        block.get_state_root().await,
        "both paths must commit identical state"
    );
}

/// A payload that moves more than the sender can afford is refused on BOTH
/// paths, and refuses atomically: no coins move, no nonce is burned, same root.
/// This is the "a failed transfer inside a block behaves like the single-tx
/// path" property.
#[tokio::test]
async fn unaffordable_payload_transfer_fails_identically_on_both_paths() {
    let sk = key(0x77);
    let sender = sk.verifying_key().to_bytes();
    let plain_to = [0xEEu8; 32];
    let payload_to = [0xEFu8; 32];

    // Exactly enough for `amount + gas_limit` (so admission accepts it), and
    // the payload then tries to move all of it on top - the combined debit is
    // unaffordable.
    let funding = 1_000 + GAS_BASIC_TRANSFER;
    let tx = Transaction::sign_with_payload(
        &sk,
        plain_to,
        1_000,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        vec![OpCode::Transfer {
            recipient: payload_to,
            amount: 1_000 + GAS_BASIC_TRANSFER,
        }],
    );

    let (single, block, applied, failed) = run_on_both_paths(&tx, funding).await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "both paths refuse the transaction"
    );

    for e in [&single, &block] {
        // No VALUE moves (the atomicity property) - but the failed attempt is
        // not free: it pays the fee it declared and its nonce is consumed,
        // the SAME on both paths.
        assert_eq!(
            balance(e, &sender).await,
            funding - GAS_BASIC_TRANSFER,
            "a refused transfer moves no value; only the failure fee is charged"
        );
        assert_eq!(
            e.get_account(&sender).await.unwrap().nonce,
            1,
            "the failure consumes the nonce"
        );
        assert_eq!(balance(e, &plain_to).await, 0, "no plain amount credited");
        assert_eq!(
            balance(e, &payload_to).await,
            0,
            "no payload amount credited"
        );
    }
    assert_eq!(
        single.get_state_root().await,
        block.get_state_root().await,
        "a refused transaction must leave identical state on both paths"
    );
}
