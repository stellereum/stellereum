//! HUNT (CLOSED as B1): `apply_transaction` used to commit the SVM's state
//! BEFORE the balance it was about to require existed, and returned an error
//! WITHOUT rolling anything back.
//!
//! Order of operations in src/state_engine.rs::apply_transaction (pre-fix):
//!   1. verify signature, nonce, `balance >= tx.amount + tx.gas_limit`
//!   2. `execute_payload(tx)` -> SVM::execute -> the clone-commit wrote the
//!      token registry, the orderbooks, the contracts AND THE STAKING LEDGER
//!      into the live engine
//!   3. NOW re-derive the real debit: `required = tx.amount + fee + vm_out`
//!      and bail out if `balance < required`
//!
//! The VM was given the sender's FULL balance and never told that `tx.amount`
//! had already been committed to the recipient, so a payload could legitimately
//! move the whole balance inside the VM; step 3 then rejected the transaction
//! *after* step 2 had already written consensus state. The sender was not
//! charged, the coins never moved, and the ledger kept the mutation: free
//! consensus power, free mints, replayable (nonce unmoved).
//!
//! FIX: the caller snapshots every payload-mutable domain before execution
//! (`snapshot_payload_domains`) and rolls everything back on ANY post-VM
//! failure (`rollback_payload` + settlement undo records) — a rejected
//! transaction now leaves literally nothing behind. Tests 1-2 below pin the
//! FIXED behavior (they asserted the exploit before the fix).

// FULL-PQ: fixture transactions are Falcon-512 PQ1 envelopes; the node
// refuses classical Ed25519 envelopes at apply admission.
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::pq_registry::{derive_validator_id, pq_voting_key_pop_preimage};
use stellereum::staking::{MIN_VALIDATOR_BOND, STAKING_POOL, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, RegisterValidatorPayload};
use stellereum::token::TokenMetadata;
use stellereum::zkml::effective_chain_id;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// The bond floor every stake must clear (bare MIN is refused).
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

mod support;
use support::failure_fee;

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

fn pq_key(seed: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed(seed)
}

fn tx_of(
    key: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    payload: Vec<OpCode>,
) -> stellereum::sharding::Transaction {
    let pk = key.public_key.clone();
    let probe = stellereum::sharding::Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        0,
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
        to,
        amount,
        gas_limit,
        0,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

/// FIXED (was CRITICAL): a transaction that the engine REJECTS leaves no
/// validator bond behind. The bond attempt is rolled back with everything
/// else; consensus power cannot be conjured from an unaffordable tx.
#[tokio::test]
async fn free_validator_bond_from_a_rejected_transaction() {
    let engine = InMemoryStateEngine::new();
    let attacker = pq_key(0xA1);
    let attacker_addr = pq_addr(&attacker);
    let attacker_hot = pq_key(0xA2);
    let chain_id = effective_chain_id();
    let validator = derive_validator_id(chain_id, &attacker_addr, attacker_hot.public_key());
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &validator,
        &attacker_addr,
        0,
        PqScheme::Falcon512,
        attacker_hot.public_key(),
    );

    // Enough to pass admission and the bond floor inside the VM, but not
    // enough to ALSO pay the carried amount plus the failure fee: the VM
    // spends the bond first, then the real debit is discovered short.
    let balance = floor() + 55_000;
    engine
        .update_account(AccountState::new(attacker_addr, balance))
        .await;

    // `tx.amount = 100` is what tips step 3 over the edge: the VM is handed
    // the whole balance, spends all of it on the bond, and the state engine
    // then discovers it must also pay the 100 to the recipient.
    let t = tx_of(
        &attacker,
        [0x99u8; 32],
        100,
        10_000,
        vec![OpCode::SysCallRegisterValidator(Box::new(
            RegisterValidatorPayload {
                amount: floor(),
                commission_bps: 0,
                withdrawal_address: attacker_addr,
                voting_scheme: PqScheme::Falcon512.id(),
                voting_pubkey: attacker_hot.public_key().to_vec(),
                voting_pop: attacker_hot.sign(&pop_msg),
            },
        ))],
    );
    let fee = failure_fee(&engine, &t).await;
    let res = engine.apply_transaction(&t, 0).await;
    println!("apply_transaction -> {res:?}");

    let l = engine.staking_read().await;
    let bonded = l
        .validators
        .get(&validator)
        .map(|v| v.self_bond)
        .unwrap_or(0);
    let in_set = l.to_validator_set().validators.contains_key(&validator);
    let power = l.to_validator_set().power_of(&validator);
    drop(l);
    let attacker_bal = engine.get_account(&attacker_addr).await.unwrap().balance;
    let pool = engine
        .get_account(&STAKING_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    let recipient = engine
        .get_account(&[0x99u8; 32])
        .await
        .map(|a| a.balance)
        .unwrap_or(0);

    println!(
        "rejected tx, yet: bonded = {bonded} ({} STELL)",
        bonded / 1_000_000_000
    );
    println!("in validator set = {in_set}, voting power = {power}");
    println!("attacker balance {balance} -> {attacker_bal} (unchanged: it cost nothing)");
    println!("staking pool balance = {pool}");
    println!("recipient balance = {recipient}");

    assert!(res.is_err(), "the engine rejects the transaction");
    assert_eq!(
        bonded, 0,
        "FIXED: the rolled-back bond leaves no record in the ledger"
    );
    assert!(!in_set, "no consensus power without funded bond");
    assert_eq!(power, 0);
    // F-01: a rejected transaction is not free - it pays the failure fee
    // (the declared gas limit) and consumes the nonce, exactly like the
    // block path. What it must NOT do is move the bond, the pool or the
    // recipient's money.
    assert_eq!(
        attacker_bal,
        balance - fee,
        "it cost the attacker the failure fee - and nothing else"
    );
    assert_eq!(pool, 0, "not one coin of the bond is in the staking pool");
    assert_eq!(recipient, 0, "the transfer did not happen either");
}

/// The same hole minted tokens: a minter's token mint survived in consensus
/// state even though the enclosing transaction was rejected as unaffordable.
/// FIXED: the mint is rolled back with everything else.
#[tokio::test]
async fn rejected_transaction_still_commits_a_token_mint() {
    let engine = InMemoryStateEngine::new();
    let minter = pq_key(0xB1);
    let minter_addr = pq_addr(&minter);
    let victim = pq_key(0xB2);
    let victim_addr = pq_addr(&victim);

    let meta = TokenMetadata {
        name: "Test".into(),
        symbol: "TST".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: minter_addr,
        paused: false,
        description: String::new(),
    };
    let token = engine.create_token(minter_addr, meta, 0).await.unwrap();
    let supply0 = engine.token_total_supply(&token).await;

    // The mint costs nothing; the trailing `Transfer` of the whole balance is
    // what makes the real debit exceed what the account has once `tx.amount`
    // is added - AFTER the mint was committed. The starting balance clears
    // admission (amount + gas_limit + the consensus floor).
    let start = 360_000u64;
    engine
        .update_account(AccountState::new(minter_addr, start))
        .await;
    let t = tx_of(
        &minter,
        [0x77u8; 32],
        9_000,
        300_000,
        vec![
            OpCode::SysCallTokenMint {
                token_id: token,
                to: victim_addr,
                amount: 1_000_000_000,
            },
            OpCode::Transfer {
                recipient: [0x55u8; 32],
                amount: start,
            },
        ],
    );
    let fee = failure_fee(&engine, &t).await;
    let res = engine.apply_transaction(&t, 0).await;
    println!("apply_transaction -> {res:?}");
    let supply1 = engine.token_total_supply(&token).await;
    let victim_tok = engine.token_balance(&token, &victim_addr).await;
    let minter_bal = engine.get_account(&minter_addr).await.unwrap().balance;
    println!(
        "supply {supply0:?} -> {supply1:?}; victim got {victim_tok}; minter balance {minter_bal}"
    );

    assert!(res.is_err(), "the transaction is rejected");
    assert_eq!(
        victim_tok, 0,
        "FIXED: no tokens minted by a rejected transaction"
    );
    assert_eq!(supply1, supply0, "supply unchanged");
    // The failure fee is charged: the MINT itself moved nothing.
    assert_eq!(
        minter_bal,
        start - fee,
        "the minter paid the failure fee - and nothing else"
    );
}

/// A payout failure (state_engine.rs:528) is raised AFTER the sender has been
/// debited and its nonce consumed at :492-493, so a "failed" transaction still
/// costs the sender money and burns a nonce.
#[tokio::test]
async fn rejected_payout_still_debits_the_sender_and_burns_the_nonce() {
    let engine = InMemoryStateEngine::new();
    let validator = pq_key(0xC1);
    let validator_addr = pq_addr(&validator);
    let validator_hot = pq_key(0xC3);
    let chain_id = effective_chain_id();
    let vid = derive_validator_id(chain_id, &validator_addr, validator_hot.public_key());
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &vid,
        &validator_addr,
        0,
        PqScheme::Falcon512,
        validator_hot.public_key(),
    );
    let attacker = pq_key(0xC2);
    let attacker_addr = pq_addr(&attacker);

    // A validator bond small enough that the pool cannot cover the reward.
    engine
        .update_account(AccountState::new(validator_addr, floor() + 100_000))
        .await;
    let b = tx_of(
        &validator,
        validator_addr,
        0,
        20_000,
        vec![OpCode::SysCallRegisterValidator(Box::new(
            RegisterValidatorPayload {
                amount: floor(),
                commission_bps: 0,
                withdrawal_address: validator_addr,
                voting_scheme: PqScheme::Falcon512.id(),
                voting_pubkey: validator_hot.public_key().to_vec(),
                voting_pop: validator_hot.sign(&pop_msg),
            },
        ))],
    );
    engine.apply_transaction(&b, 0).await.unwrap();
    {
        let mut l = engine.staking_write().await;
        l.distribute_reward(vid, stell(5_000)).unwrap();
    }

    let start = 100_000u64;
    engine
        .update_account(AccountState::new(attacker_addr, start))
        .await;
    let t = tx_of(
        &attacker,
        [0x01u8; 32],
        0,
        20_000,
        // The attacker claims for ITSELF, which passes the ownership check, so
        // this reaches the payout stage the atomicity property is about. Using
        // someone else's id no longer gets that far: the opcode rejects it
        // outright, which is the reward-theft fix.
        vec![OpCode::SysCallClaimRewards {
            validator: attacker_addr,
        }],
    );
    let fee = failure_fee(&engine, &t).await;
    let res = engine.apply_transaction(&t, 0).await;
    let acc = engine.get_account(&attacker_addr).await.unwrap();
    println!("apply_transaction -> {res:?}");
    println!(
        "attacker: balance {} -> {}, nonce {}",
        start, acc.balance, acc.nonce
    );
    println!(
        "validator pending_rewards now {} (was 5000000000000)",
        engine.staking_read().await.validators[&vid].pending_rewards
    );

    assert!(res.is_err(), "the claim is refused");
    // F-01: a failed attempt is not free. The rejection happens INSIDE the
    // payload (the caller is not a bonded validator, and the ownership check
    // refuses a claim for anyone else), so the transaction RAN and failed -
    // and a failure the sender can pay for costs the fee they declared and
    // consumes their nonce. The same rule the block path applies, so the two
    // paths cannot disagree about the state root.
    //
    // What must NOT happen is the VALUE moving: no reward is credited, no
    // reward counter is destroyed, no bond is recorded.
    assert_eq!(acc.nonce, 1, "a failed attempt consumes the nonce");
    assert_eq!(
        acc.balance,
        start - fee,
        "a failed attempt pays the failure fee - and moves no other value"
    );
    // The victim's accrued rewards are untouched: a failed claim must not zero
    // the counter. (Before the ownership fix this transaction reached the payout
    // stage as a THIRD PARTY and zeroed it while crediting the wrong account.)
    assert_eq!(
        engine.staking_read().await.validators[&vid].pending_rewards,
        5_000_000_000_000u64,
        "a failed claim must not destroy the validator's accrued rewards"
    );
}
