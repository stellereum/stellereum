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

use stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::pq_registry::{derive_validator_id, pq_voting_key_pop_preimage};
use stellereum::sharding::Transaction;
use stellereum::staking::{
    MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    OpCode, RegisterValidatorPayload, GAS_BASIC_TRANSFER, GAS_STAKE_CLAIM, GAS_STAKE_UNBOND,
};
use stellereum::zkml::effective_chain_id;

/// A fixed, realistic block timestamp. Never 0: 0 is exactly the bug.
const BLOCK_TS: u64 = 1_760_000_000;

/// Bond floor every bond in this file must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

/// FULL-PQ fixture key. The node refuses bare Ed25519 transaction envelopes,
/// so every sender is a Falcon keypair signing a PQ envelope.
fn key(seed: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed(seed)
}

fn addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

/// The PQ mirror of `Transaction::sign_with_payload`.
#[allow(clippy::too_many_arguments)]
// GATE: mirrors the production constructor's full tx context.
fn pq_tx(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<OpCode>,
) -> Transaction {
    let pk = kp.public_key().to_vec();
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        payload,
        &DEFAULT_SALT,
    )
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

async fn pool(e: &InMemoryStateEngine) -> u64 {
    balance(e, &STAKING_POOL).await
}

fn register_op(cold_addr: [u8; 32], hot_kp: &FalconKeypair, amount: u64) -> (OpCode, [u8; 32]) {
    let chain_id = effective_chain_id();
    let vid = derive_validator_id(chain_id, &cold_addr, hot_kp.public_key());
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &vid,
        &cold_addr,
        0,
        PqScheme::Falcon512,
        hot_kp.public_key(),
    );
    let op = OpCode::SysCallRegisterValidator(Box::new(RegisterValidatorPayload {
        amount,
        commission_bps: 0,
        withdrawal_address: cold_addr,
        voting_scheme: PqScheme::Falcon512.id(),
        voting_pubkey: hot_kp.public_key().to_vec(),
        voting_pop: hot_kp.sign(&pop_msg),
    }));
    (op, vid)
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
    let sender = addr(&sk);
    let plain_to = [0xAAu8; 32];
    let payload_to = [0xBBu8; 32];
    let start = 1_000_000u64;
    engine
        .update_account(AccountState::new(sender, start))
        .await;

    // gas_limit == the opcode's own cost, so the assertion below is about the
    // value movement and not about which fee rule a path charges.
    let tx = pq_tx(
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
    assert_eq!(
        fees,
        GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS,
        "the declared gas plus the PQ activation surcharge is collected"
    );

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
        start - 1_000 - fees - 5_000,
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
    let validator = addr(&sk);
    let hot = key(0x23);
    let (reg_op, vid) = register_op(validator, &hot, floor());
    let start = floor() + GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS + 4_242;
    engine
        .update_account(AccountState::new(validator, start))
        .await;
    assert_eq!(pool(&engine).await, 0, "the pool starts empty");

    let tx = pq_tx(&sk, validator, 0, GAS_BASIC_TRANSFER, 0, 1, 1, vec![reg_op]);

    let (applied, failed, fees, status, _) = engine
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
        start - floor() - fees,
        "the bond and the fee leave the sender"
    );
    let vs = engine.staking_read().await.to_validator_set();
    assert_eq!(
        vs.power_of(&vid),
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
    let validator = addr(&sk);
    let hot = key(0x34);
    let (reg_op, vid) = register_op(validator, &hot, floor());
    let start = floor() + GAS_BASIC_TRANSFER + GAS_STAKE_CLAIM + 2 * PQ_ACTIVATION_SURCHARGE_GAS;
    engine
        .update_account(AccountState::new(validator, start))
        .await;

    // Block 1: register & bond through the live path, so the pool really holds the coins.
    let bond_tx = pq_tx(&sk, validator, 0, GAS_BASIC_TRANSFER, 0, 1, 1, vec![reg_op]);
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
        .distribute_reward(vid, reward)
        .unwrap();
    engine
        .credit_native(&REWARDS_POOL, reward)
        .await
        .expect("back the accrual");
    assert_eq!(
        engine.staking_read().await.validators[&vid].pending_rewards,
        reward
    );

    // Block 2: claim through the live path (signed by cold withdrawal_address).
    let claim_tx = pq_tx(
        &sk,
        [0u8; 32],
        0,
        GAS_STAKE_CLAIM,
        1,
        1,
        1,
        vec![OpCode::SysCallClaimRewards { validator: vid }],
    );
    let (applied, failed, claim_fees, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&claim_tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0), "the claim applies");
    assert_eq!(status, vec![true]);

    // THE regression: `pending_rewards` was zeroed while the payout itself was
    // discarded - the reward simply vanished. E2: the payout must drain the
    // rewards pool while bonded principal stays untouched.
    assert_eq!(
        engine.staking_read().await.validators[&vid].pending_rewards,
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
        after_bond + reward - claim_fees,
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
    let validator = addr(&sk);
    let hot = key(0x45);
    let (reg_op, vid) = register_op(validator, &hot, floor());
    let start = floor() + GAS_BASIC_TRANSFER + GAS_STAKE_UNBOND + 2 * PQ_ACTIVATION_SURCHARGE_GAS;
    engine
        .update_account(AccountState::new(validator, start))
        .await;

    // Block 1: register & bond so there is something to unbond.
    let bond_tx = pq_tx(&sk, validator, 0, GAS_BASIC_TRANSFER, 0, 1, 1, vec![reg_op]);
    let (applied, failed, _, _, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&bond_tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0));

    // Block 2: full exit, applied at BLOCK_TS.
    let unbond_tx = pq_tx(
        &sk,
        [0u8; 32],
        0,
        GAS_STAKE_UNBOND,
        1,
        1,
        1,
        vec![OpCode::SysCallUnbond {
            validator: vid,
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
        engine.staking_read().await.withdrawable_of(&vid),
        0,
        "not mature one second early"
    );
    engine
        .staking_write()
        .await
        .process_unbonding(BLOCK_TS + UNBONDING_PERIOD_SECS)
        .unwrap();
    assert_eq!(
        engine.staking_read().await.withdrawable_of(&vid),
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
    let creator = addr(&sk);
    engine
        .update_account(AccountState::new(creator, 10_000_000))
        .await;

    let code = wat::parse_str("(module)").expect("wat compiles");
    let tx = pq_tx(
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
    let sender = addr(&sk);
    let plain_to = [0xCCu8; 32];
    let payload_to = [0xDDu8; 32];

    let tx = pq_tx(
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
            1_000_000 - 2_000 - (GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS) - 7_000
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
    let sender = addr(&sk);
    let plain_to = [0xEEu8; 32];
    let payload_to = [0xEFu8; 32];

    // Exactly enough for `amount + gas_limit` (so admission accepts it), and
    // the payload then tries to move all of it on top - the combined debit is
    // unaffordable.
    let fee = GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS;
    let funding = 1_000 + fee;
    let tx = pq_tx(
        &sk,
        plain_to,
        1_000,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        vec![OpCode::Transfer {
            recipient: payload_to,
            amount: 1_000 + fee,
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
            funding - fee,
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
