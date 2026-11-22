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

use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::pq_registry::{derive_validator_id, pq_voting_key_pop_preimage};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{
    MIN_VALIDATOR_BOND, REWARDS_EMISSION_CAP, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// New-bond floor since the re-entry fix: bare-MIN bonds are refused, so every
/// SysCallRegisterValidator below bonds exactly MIN+buffer.
fn bond_amount() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}
use stellereum::svm::{OpCode, RegisterValidatorPayload, GAS_BASIC_TRANSFER};
use stellereum::zkml::effective_chain_id;

const STELL: u64 = 1_000_000_000;
const TS: u64 = 1_760_000_000;

/// FULL-PQ sender identity: implicit Falcon-512, registered globally.
fn pq_key(seed: u8) -> (FalconKeypair, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed(seed);
    let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(addr, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (kp, addr)
}

/// FULL-PQ replacement for `Transaction::sign_with_payload`.
fn tx_of(kp: &FalconKeypair, nonce: u64, gas_limit: u64, payload: Vec<OpCode>) -> Transaction {
    let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    let mut t = Transaction {
        from,
        to: from,
        amount: 0,
        gas_limit,
        nonce,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = kp.sign(&msg);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
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
        cnvrf_v3: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }
}

async fn bal(engine: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    engine.get_account(a).await.map(|x| x.balance).unwrap_or(0)
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

/// (1) Rewards come from the pool, not principal: the block mint credits
/// `REWARDS_POOL` 1:1 (ledger accounting AND native coins), `STAKING_POOL`
/// stays exactly the bonded amount, and the later claim drains the rewards
/// pool while principal never moves.
#[tokio::test]
async fn block_reward_mints_into_pool_and_claim_leaves_principal_untouched() {
    let engine = InMemoryStateEngine::new();
    let (val, val_addr) = pq_key(0x91);
    let (val_hot, _) = pq_key(0xA1);
    let (reg_op, val_vid) = register_op(val_addr, &val_hot, bond_amount());
    engine
        .update_account(AccountState::new(val_addr, bond_amount() + 5_000_000))
        .await;

    engine
        .apply_transaction(&tx_of(&val, 0, 20_000, vec![reg_op]), 0)
        .await
        .unwrap();
    assert_eq!(bal(&engine, &STAKING_POOL).await, bond_amount());

    // The block mint: reward R to the proposer.
    let r = 5 * STELL;
    engine
        .apply_block_transition(&block_of(1, vec![], val_vid), r)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(
            l.rewards_minted, r,
            "cumulative mint tracks the block reward"
        );
        assert_eq!(l.rewards_pool, r, "mint funds the ledger pool 1:1");
        assert_eq!(
            l.validators[&val_vid].pending_rewards, r,
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

    // Claim: exact payout minus intrinsic claim gas, drained from the rewards pool.
    let before = bal(&engine, &val_addr).await;
    engine
        .apply_transaction(
            &tx_of(
                &val,
                1,
                500_000,
                vec![OpCode::SysCallClaimRewards { validator: val_vid }],
            ),
            0,
        )
        .await
        .expect("claim works");
    assert_eq!(
        bal(&engine, &val_addr).await,
        before + r - GAS_BASIC_TRANSFER,
        "exact claim payout minus intrinsic claim gas"
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
    let (funder, funder_addr) = pq_key(0x92);
    let (val_hot, _) = pq_key(0xA2);
    let (reg_op, validator) = register_op(funder_addr, &val_hot, bond_amount());
    engine
        .update_account(AccountState::new(funder_addr, bond_amount() + 20_000))
        .await;
    engine
        .apply_transaction(&tx_of(&funder, 0, 20_000, vec![reg_op]), 0)
        .await
        .unwrap();

    let (delegator, delegator_addr) = pq_key(0x93);
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
                500_000,
                vec![OpCode::SysCallClaimDelegatorRewards { validator }],
            ),
            0,
        )
        .await
        .expect("delegator claim works");
    assert_eq!(
        bal(&engine, &delegator_addr).await,
        before + owed - GAS_BASIC_TRANSFER
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
    let (val, val_addr) = pq_key(0x94);
    let (val_hot, _) = pq_key(0xA4);
    let (reg_op, val_vid) = register_op(val_addr, &val_hot, bond_amount());
    engine
        .update_account(AccountState::new(val_addr, bond_amount() + 5_000_000))
        .await;
    engine
        .apply_transaction(&tx_of(&val, 0, 20_000, vec![reg_op]), 0)
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
        .apply_block_transition(&block_of(1, vec![], val_vid), 101)
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
            l.validators[&val_vid].pending_rewards, 0,
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
        .apply_block_transition(&block_of(2, vec![], val_vid), 100)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(l.rewards_minted, REWARDS_EMISSION_CAP);
        assert_eq!(l.rewards_pool, 150);
        assert_eq!(l.validators[&val_vid].pending_rewards, 100);
    }
    assert_eq!(bal(&engine, &REWARDS_POOL).await, 100);

    // At the cap: even 1 nano refuses.
    engine
        .apply_block_transition(&block_of(3, vec![], val_vid), 1)
        .await;
    {
        let l = engine.staking_read().await;
        assert_eq!(l.rewards_minted, REWARDS_EMISSION_CAP);
        assert_eq!(
            l.validators[&val_vid].pending_rewards, 100,
            "still no phantom credit"
        );
    }
    assert_eq!(
        bal(&engine, &REWARDS_POOL).await,
        100,
        "still no native mint"
    );
}
