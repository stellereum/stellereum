//! HUNT: unauthenticated forced unbonding -> validator-set capture + 2-day
//! lock-up of honest validators' bonded principal.
//!
//! Hypothesis (src/svm.rs:481-489): `OpCode::SysCallUnbond { validator, amount }`
//! calls `StakingLedger::unbond(validator, amount, ts)`, which is keyed by the
//! VALIDATOR id. The sender is never compared to the validator, so *anyone* can
//! unbond *anyone's* self-bond. `to_validator_set()` (src/staking.rs:354) only
//! admits `self_bond >= MIN_VALIDATOR_BOND`, and `ValidatorRuntime::
//! refresh_validator_set_from_staking` (src/runtime.rs:710) rebuilds the
//! consensus set from exactly that function at every height boundary. So one
//! transaction signed by a dust key can delete every honest validator from the
//! consensus set.

// FULL-PQ: fixture transactions are Falcon-512 PQ1 envelopes; the node
// refuses classical Ed25519 envelopes at apply admission.
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::pq_registry::{derive_validator_id, pq_voting_key_pop_preimage};
use stellereum::staking::{
    MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    OpCode, RegisterValidatorPayload, GAS_BASIC_TRANSFER, GAS_STAKE_CLAIM, GAS_STAKE_UNBOND,
};
use stellereum::zkml::effective_chain_id;

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Bond floor every bond in this file must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn pq_key(seed: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed(seed)
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

fn tx_of(
    key: &FalconKeypair,
    nonce: u64,
    gas_limit: u64,
    payload: Vec<OpCode>,
) -> stellereum::sharding::Transaction {
    let from = pq_addr(key);
    let pk = key.public_key.clone();
    let probe = stellereum::sharding::Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        from,
        0,
        gas_limit,
        nonce,
        1,
        1,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = key.sign(&probe.signing_message());
    stellereum::sharding::Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        from,
        0,
        gas_limit,
        nonce,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

async fn bal(engine: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    engine.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

/// The engine's SUCCESS fee for a syscall that consumes `gas_used`:
/// `max(max(gas_used, TX_INTRINSIC_GAS).min(gas_limit), consensus floor) + surcharge`
/// (same rule as `commit_native` under `EXEC_HARDENING_V1`).
async fn success_fee(
    engine: &InMemoryStateEngine,
    tx: &stellereum::sharding::Transaction,
    gas_used: u64,
) -> u64 {
    let (floor_base, surcharge) = engine.consensus_floor_parts(tx).await;
    let billed = gas_used.max(GAS_BASIC_TRANSFER).min(tx.gas_limit);
    billed.max(floor_base).saturating_add(surcharge)
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

/// One dust-funded transaction from a stranger empties an honest validator's
/// self-bond, silently removing it from the consensus validator set.
#[tokio::test]
async fn stranger_cannot_force_unbond_an_honest_validator() {
    let engine = InMemoryStateEngine::new();
    let honest = pq_key(0x31);
    let honest_addr = pq_addr(&honest);
    let honest_hot = pq_key(0x33);
    let attacker = pq_key(0x32);
    let attacker_addr = pq_addr(&attacker);

    let honest_start = floor() + 200_000;
    engine
        .update_account(AccountState::new(honest_addr, honest_start))
        .await;
    let (reg_op, honest_vid) = register_op(honest_addr, &honest_hot, floor());
    let bond = tx_of(&honest, 0, 20_000, vec![reg_op]);
    engine.apply_transaction(&bond, 0).await.unwrap();
    // Snapshot AFTER the successful bond: the grief below must not move a
    // single nano of the honest validator's remaining balance.
    let honest_after_bond = bal(&engine, &honest_addr).await;
    assert!(
        engine
            .staking_read()
            .await
            .to_validator_set()
            .validators
            .contains_key(&honest_vid),
        "precondition: honest validator is in the set"
    );

    // The attacker holds only dust: enough to clear admission (the
    // consensus floor), nowhere near the honest validator's bond.
    engine
        .update_account(AccountState::new(attacker_addr, 100_000))
        .await;
    let t = tx_of(
        &attacker,
        0,
        20_000,
        vec![OpCode::SysCallUnbond {
            validator: honest_vid,
            amount: floor(),
        }],
    );
    // FIXED: SysCallUnbond is owner-only, so the grief is refused.
    let err = engine
        .apply_transaction(&t, 0)
        .await
        .expect_err("a stranger must not be able to force-unbond someone else");
    println!("attacker force-unbond rejected: {err}");

    let l = engine.staking_read().await;
    assert_eq!(
        l.validators[&honest_vid].self_bond,
        floor(),
        "the honest validator keeps its whole bond"
    );
    assert!(
        l.to_validator_set().validators.contains_key(&honest_vid),
        "the honest validator is still in the consensus set"
    );
    assert!(l.unbonding.is_empty(), "no unbonding entry was created");
    drop(l);
    // The honest validator's STELL is untouched in every respect.
    assert_eq!(
        bal(&engine, &honest_addr).await,
        honest_after_bond,
        "the refused force-unbond moved no honest STELL"
    );
    assert_eq!(bal(&engine, &STAKING_POOL).await, floor());

    // And the owner (cold withdrawal_address) may still unbond, so the check is an auth check, not a ban.
    let owner_tx = tx_of(
        &honest,
        1,
        2_000,
        vec![OpCode::SysCallUnbond {
            validator: honest_vid,
            amount: floor(),
        }],
    );
    engine
        .apply_transaction(&owner_tx, 0)
        .await
        .expect("the validator may still unbond its own stake");
    assert_eq!(
        engine.staking_read().await.validators[&honest_vid].self_bond,
        0
    );
}

/// CHAIN: attacker bonds first, then in ONE transaction unbonds every honest
/// validator. The next height the consensus validator set is the attacker alone.
#[tokio::test]
async fn one_tx_cannot_capture_the_validator_set() {
    let engine = InMemoryStateEngine::new();
    let attacker = pq_key(0x41);
    let attacker_addr = pq_addr(&attacker);
    let attacker_hot = pq_key(0x42);

    // 10 honest validators.
    let mut honest = Vec::new();
    for i in 0..10u8 {
        let k = pq_key(0x50 + i);
        let a = pq_addr(&k);
        let k_hot = pq_key(0xA0 + i);
        engine
            .update_account(AccountState::new(a, floor() + 200_000))
            .await;
        let (reg_op, vid) = register_op(a, &k_hot, floor());
        let t = tx_of(&k, 0, 20_000, vec![reg_op]);
        engine.apply_transaction(&t, 0).await.unwrap();
        honest.push(vid);
    }
    // Attacker buys in with the bare minimum.
    engine
        .update_account(AccountState::new(attacker_addr, floor() + 4_000_000))
        .await;
    let (atk_reg_op, attacker_vid) = register_op(attacker_addr, &attacker_hot, floor());
    let t = tx_of(&attacker, 0, 4_000_000, vec![atk_reg_op]);
    engine.apply_transaction(&t, 0).await.unwrap();

    let vs = engine.staking_read().await.to_validator_set();
    println!(
        "validator set before the attack: {} members",
        vs.validators.len()
    );
    assert_eq!(vs.validators.len(), 11);

    // ONE transaction, 10 syscalls, 800 gas each. The attacker unbonds all 10
    // honest validators. No signature of theirs is needed, no stake of theirs.
    let payload: Vec<OpCode> = honest
        .iter()
        .map(|v| OpCode::SysCallUnbond {
            validator: *v,
            amount: floor(),
        })
        .collect();
    let gas = 10 * 800 + 10_000;
    let t = tx_of(&attacker, 1, gas, payload);
    // FIXED: every one of the 10 syscalls is owner-checked, so the whole
    // payload is refused atomically -- the batch buys the attacker nothing.
    let err = engine
        .apply_transaction(&t, 0)
        .await
        .expect_err("one stranger must not be able to unbond the honest set");
    println!("batch force-unbond of 10 validators rejected: {err}");

    let vs = engine.staking_read().await.to_validator_set();
    println!(
        "validator set after the attempt: {} members",
        vs.validators.len()
    );
    assert_eq!(vs.validators.len(), 11, "the honest set is intact");
    assert!(
        !vs.validators.contains_key(&attacker_vid) || vs.validators.len() == 11,
        "the attacker captured nothing"
    );
    assert_eq!(
        vs.total_power(),
        11 * floor(),
        "no single tx can collapse consensus power to the attacker"
    );
    for v in &honest {
        assert!(
            vs.validators.contains_key(v),
            "honest validator {} still holds its bond",
            hex::encode(&v[..4])
        );
    }
    // The pool still holds every honest validator's real money; the attacker
    // never touched a coin of theirs.
    println!(
        "pool still holds: {} STELL of honest principal",
        bal(&engine, &STAKING_POOL).await / 1_000_000_000
    );
    assert_eq!(bal(&engine, &STAKING_POOL).await, 11 * floor());
}

/// Delegated stake exits through the transaction path (E1 FIXED): begin
/// with `SysCallBeginUndelegate` (starts the unbonding), mature past the
/// cooldown, release with `SysCallUndelegate` (consumes the matured entry,
/// pays exactly once). Previously the begin step did not exist on-chain and
/// `SysCallUndelegate` could neither start nor finish an exit.
#[tokio::test]
async fn delegated_stake_exits_through_begin_then_withdraw() {
    let engine = InMemoryStateEngine::new();
    let delegator = pq_key(0x61);
    let delegator_addr = pq_addr(&delegator);

    // A validator registered and bonded by a cold withdrawal address.
    let funder = pq_key(0x62);
    let funder_addr = pq_addr(&funder);
    let val_hot = pq_key(0x63);
    let (reg_op, validator) = register_op(funder_addr, &val_hot, floor());
    engine
        .update_account(AccountState::new(funder_addr, floor() + 200_000))
        .await;
    engine
        .apply_transaction(&tx_of(&funder, 0, 20_000, vec![reg_op]), 0)
        .await
        .unwrap();

    // The delegator delegates 5,000 STELL.
    engine
        .update_account(AccountState::new(delegator_addr, stell(5_000) + 5_000_000))
        .await;
    let d = tx_of(
        &delegator,
        0,
        100_000,
        vec![OpCode::SysCallDelegate {
            validator,
            amount: stell(5_000),
        }],
    );
    engine.apply_transaction(&d, 0).await.unwrap();
    let after_delegate = bal(&engine, &delegator_addr).await;
    println!("delegator after delegating 5,000 STELL: {after_delegate} nano");

    // Begin unbonding the full position, mature it, then withdraw.
    // process_unbonding is what the runtime runs at every height boundary.
    let mut nonce = 1u64;
    let t = tx_of(
        &delegator,
        nonce,
        100_000,
        vec![OpCode::SysCallBeginUndelegate {
            validator,
            amount: stell(5_000),
        }],
    );
    let begin_fee = success_fee(&engine, &t, GAS_STAKE_UNBOND).await;
    engine
        .apply_transaction(&t, 0)
        .await
        .expect("begin unbonding works");
    nonce += 1;
    // Withdrawing BEFORE maturity must refuse (nothing matured yet).
    //
    // F-01 / SEC-07: the refusal is attributable, so it costs the declared
    // limit and CONSUMES THE NONCE - so the real withdraw below must be
    // signed with the next nonce (reusing the old one would fail admission).
    let early = tx_of(
        &delegator,
        nonce,
        100_000,
        vec![OpCode::SysCallUndelegate { validator }],
    );
    let early_fee = failure_fee(&engine, &early).await;
    let before_early = bal(&engine, &delegator_addr).await;
    assert!(
        engine.apply_transaction(&early, 0).await.is_err(),
        "no matured funds yet: must refuse, not pay zero"
    );
    assert_refused_tx_paid_failure_fee(&engine, &early, early_fee, before_early, nonce).await;
    nonce += 1;
    engine
        .staking_write()
        .await
        .process_unbonding(UNBONDING_PERIOD_SECS + 1)
        .unwrap();
    assert_eq!(
        engine
            .staking_read()
            .await
            .withdrawable_delegator(&validator, &delegator_addr),
        stell(5_000),
        "cooldown matured the full position"
    );
    // Withdraw: consumes the entry, pays exactly once.
    let t = tx_of(
        &delegator,
        nonce,
        100_000,
        vec![OpCode::SysCallUndelegate { validator }],
    );
    let withdraw_fee = success_fee(&engine, &t, GAS_STAKE_UNBOND).await;
    engine
        .apply_transaction(&t, 0)
        .await
        .expect("withdraw works");
    nonce += 1;
    // Second withdraw: entry consumed, must refuse (single-claim). It is a
    // refusal like any other, so it costs the failure fee too.
    let again = tx_of(
        &delegator,
        nonce,
        100_000,
        vec![OpCode::SysCallUndelegate { validator }],
    );
    let again_fee = failure_fee(&engine, &again).await;
    let before_again = bal(&engine, &delegator_addr).await;
    assert!(
        engine.apply_transaction(&again, 0).await.is_err(),
        "consumed entry cannot pay twice"
    );
    assert_refused_tx_paid_failure_fee(&engine, &again, again_fee, before_again, nonce).await;

    let l = engine.staking_read().await;
    assert_eq!(
        l.delegations
            .get(&(validator, delegator_addr))
            .copied()
            .unwrap_or(0),
        0,
        "position fully exited"
    );
    assert_eq!(
        l.withdrawable_delegator(&validator, &delegator_addr),
        0,
        "entry consumed by the payout"
    );
    assert!(l.unbonding.is_empty(), "no dangling entries");
    let final_bal = bal(&engine, &delegator_addr).await;
    // EXACT conservation: the 5,000 STELL came back, minus exactly the gas
    // consumed on this (single-transaction) path. `apply_transaction` charges
    // the gas actually used on a SUCCESS (`GAS_STAKE_UNBOND` for begin and
    // for withdraw), while the two REFUSED withdraws (early + replay) cost the
    // FAILURE FEE - the declared limit - because a refusal is attributable
    // and must not be free (SEC-07). A failure that cost nothing would be a
    // free DoS and a free replay.
    println!("delegator ended with {final_bal} nano (position 5,000 STELL exited)");
    assert_eq!(
        final_bal,
        after_delegate + stell(5_000) - begin_fee - early_fee - withdraw_fee - again_fee,
        "exact conservation: 5,000 STELL back minus the two success fees and the two failure fees"
    );
}

/// F2 (HIGH): a SNARK VK carrying a test-only deterministic-setup attestation
/// is REJECTED on chain — a deterministic revert on the attestation bytes —
/// never just warned about. Test setups are waste-derivable by construction,
/// so a registered one would let whoever knows the seed forge proofs against
/// whatever model it anchors.
#[tokio::test]
async fn test_only_snark_vk_registration_reverts() {
    let engine = InMemoryStateEngine::new();
    let key = pq_key(0x71);
    let addr = pq_addr(&key);
    engine
        .update_account(AccountState::new(addr, stell(10) + 5_000_000))
        .await;
    let model_id = [0x51u8; 32];
    let mk_vk = |attestation: Vec<u8>| {
        Box::new(stellereum::zkml_attestation::ModelSpec {
            spec_hash: [0x77; 32],
            spec_bytes: vec![9u8; 64],
            setup_attestation: attestation,
            n_public_inputs: 0,
            in_dim: 0,
            out_dim: 0,
        })
    };
    // The test-setup prefix reverts, naming the reason.
    let t = tx_of(
        &key,
        0,
        100_000,
        vec![OpCode::SysCallRegisterZkMlSpec {
            model_id,
            spec: mk_vk(b"TEST-ONLY-DETERMINISTIC-SETUP:v1:test".to_vec()),
        }],
    );
    let err = engine
        .apply_transaction(&t, 0)
        .await
        .expect_err("a test-only VK must be rejected, not warned about");
    assert!(
        err.contains("test-only"),
        "the rejection must name the reason, got: {err}"
    );
    // The gate is exactly the prefix: a production-marked attestation passes
    // it (this one then fails later at the registry — unknown model — which
    // proves the refusal above came from the attestation check, not a blanket
    // ban on the opcode).
    let t = tx_of(
        &key,
        0,
        100_000,
        vec![OpCode::SysCallRegisterZkMlSpec {
            model_id,
            spec: mk_vk(b"ceremony:powers-of-tau/test".to_vec()),
        }],
    );
    let err = engine
        .apply_transaction(&t, 0)
        .await
        .expect_err("unknown model must still fail at the registry");
    assert!(
        !err.contains("test-only"),
        "a production attestation must clear the prefix gate, got: {err}"
    );
}

/// E8: delegator rewards are claimable on chain via
/// `SysCallClaimDelegatorRewards`. The ledger's `claim_delegator_rewards` had
/// no opcode reaching it, so delegator rewards accrued but could never be
/// paid out; the claim consumes the entry (single-claim) and pays from the
/// staking pool, mirroring the undelegate-withdraw arm.
#[tokio::test]
async fn delegator_rewards_claim_through_opcode() {
    let engine = InMemoryStateEngine::new();
    let funder = pq_key(0x81);
    let funder_addr = pq_addr(&funder);
    let val_hot = pq_key(0x84);
    let (reg_op, validator) = register_op(funder_addr, &val_hot, floor());
    engine
        .update_account(AccountState::new(funder_addr, floor() + 200_000))
        .await;
    engine
        .apply_transaction(&tx_of(&funder, 0, 20_000, vec![reg_op]), 0)
        .await
        .unwrap();

    let delegator = pq_key(0x82);
    let delegator_addr = pq_addr(&delegator);
    engine
        .update_account(AccountState::new(delegator_addr, stell(1_000) + 5_000_000))
        .await;
    engine
        .apply_transaction(
            &tx_of(
                &delegator,
                0,
                100_000,
                vec![OpCode::SysCallDelegate {
                    validator,
                    amount: stell(1_000),
                }],
            ),
            0,
        )
        .await
        .unwrap();

    // Accrue rewards (block rewards credit this; here the test drives it).
    // E2: the ledger accrual is only half of a mint — the block path also
    // mints the SAME coins into REWARDS_POOL, so back the entry the same way
    // here (a bare accrual with no backing must not pay, by design).
    engine
        .staking_write()
        .await
        .distribute_reward(validator, stell(100))
        .unwrap();
    engine
        .credit_native(&REWARDS_POOL, stell(100))
        .await
        .expect("back the accrual with pool coins");
    // LAZY (F1): the accrued reward is computed from the validator's
    // accumulator on demand — the raw map holds only the SETTLED part.
    let expect = engine
        .staking_read()
        .await
        .delegator_rewards_of(delegator_addr, validator);
    assert!(expect > 0, "the delegation must have accrued rewards");

    // Claim: exact payout minus exactly the claim gas.
    let before = bal(&engine, &delegator_addr).await;
    let claim_tx = tx_of(
        &delegator,
        1,
        100_000,
        vec![OpCode::SysCallClaimDelegatorRewards { validator }],
    );
    let claim_fee = success_fee(&engine, &claim_tx, GAS_STAKE_CLAIM).await;
    engine
        .apply_transaction(&claim_tx, 0)
        .await
        .expect("delegator claim works");
    assert_eq!(
        bal(&engine, &delegator_addr).await,
        before + expect - claim_fee,
        "exact claim payout minus the claim fee"
    );
    // Consumed: a second claim reverts (single-claim, no double-pay).
    let again = tx_of(
        &delegator,
        2,
        100_000,
        vec![OpCode::SysCallClaimDelegatorRewards { validator }],
    );
    assert!(
        engine.apply_transaction(&again, 0).await.is_err(),
        "a consumed reward entry cannot pay twice"
    );
    // And a stranger with no rewards gets a clear refusal, not coins.
    let stranger = pq_key(0x83);
    let stranger_addr = pq_addr(&stranger);
    engine
        .update_account(AccountState::new(stranger_addr, 5_000_000))
        .await;
    let err = engine
        .apply_transaction(
            &tx_of(
                &stranger,
                0,
                100_000,
                vec![OpCode::SysCallClaimDelegatorRewards { validator }],
            ),
            0,
        )
        .await
        .expect_err("no rewards must refuse");
    assert!(
        err.contains("no delegator rewards"),
        "the refusal must name the reason, got: {err}"
    );
}

/// NEGATIVE RESULT on the replay/double-spend class: the unbond ->
/// cooldown -> withdrawable -> withdraw path is single-use. `process_unbonding`
/// drains matured entries out of the pending list, and both `withdraw` and
/// `withdraw_delegator` `remove()` the key before returning, so the same entry
/// cannot be matured or paid twice. I could not break it.
#[test]
fn withdrawal_cannot_be_replayed_or_double_matured() {
    use stellereum::staking::{StakingError, UNBONDING_PERIOD_SECS};
    let mut l = stellereum::staking::StakingLedger::new();
    let val = [0x91u8; 32];
    let del = [0x92u8; 32];
    l.bond(val, MIN_VALIDATOR_BOND * 2 + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    l.delegate(del, val, stell(1_000)).unwrap();

    // Self-bond unbond + delegator undelegation, matured in the same instant.
    l.unbond(val, MIN_VALIDATOR_BOND, 0).unwrap();
    l.undelegate(del, val, stell(1_000), 0).unwrap();
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    let pending_after_first = l.unbonding.len();
    // Maturing AGAIN at a later time must not re-credit anything.
    l.process_unbonding(UNBONDING_PERIOD_SECS * 2 + 5).unwrap();
    l.process_unbonding(u64::MAX / 2).unwrap();
    println!(
        "unbonding entries after the first maturity: {pending_after_first}, later: {}",
        l.unbonding.len()
    );
    assert_eq!(
        l.withdrawable_of(&val),
        MIN_VALIDATOR_BOND,
        "credited exactly once"
    );
    assert_eq!(
        l.withdrawable_delegator(&val, &del),
        stell(1_000),
        "credited exactly once"
    );

    // Withdraw repeatedly.
    let first = l.withdraw(val).unwrap();
    assert_eq!(first, MIN_VALIDATOR_BOND);
    for i in 0..5 {
        assert_eq!(
            l.withdraw(val),
            Err(StakingError::NothingToWithdraw),
            "replay {i} must fail"
        );
    }
    let dfirst = l.withdraw_delegator(del, val).unwrap();
    assert_eq!(dfirst, stell(1_000));
    for i in 0..5 {
        assert_eq!(
            l.withdraw_delegator(del, val),
            Err(StakingError::NothingToWithdraw),
            "delegator replay {i} must fail"
        );
    }
    // Cross-owner withdrawal is refused: the delegator's entry is not the
    // validator's and vice versa.
    l.process_unbonding(u64::MAX / 2).unwrap();
    println!("NEGATIVE RESULT: unbond/withdraw is single-use and owner-scoped");
    assert_eq!(l.withdrawable_of(&val), 0);
    assert_eq!(l.withdrawable_delegator(&val, &del), 0);
}
