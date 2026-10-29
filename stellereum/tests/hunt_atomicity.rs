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

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::staking::{MIN_VALIDATOR_BOND, STAKING_POOL, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn tx_of(
    key: &SigningKey,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    payload: Vec<OpCode>,
) -> stellereum::sharding::Transaction {
    let _from = key.verifying_key().to_bytes();
    stellereum::sharding::Transaction::sign_with_payload(
        key, to, amount, gas_limit, 0, 1, 1, payload,
    )
}

/// FIXED (was CRITICAL): a transaction that the engine REJECTS leaves no
/// validator bond behind. The bond attempt is rolled back with everything
/// else; consensus power cannot be conjured from an unaffordable tx.
#[tokio::test]
async fn free_validator_bond_from_a_rejected_transaction() {
    let engine = InMemoryStateEngine::new();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();
    let validator = [0x42u8; 32];

    // Enough to pass the *first* check (`amount + gas_limit`), and exactly
    // enough to bond the 1,000 STELL minimum inside the VM.
    let balance = MIN_VALIDATOR_BOND + 2_000;
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
        2_000,
        vec![OpCode::SysCallStake {
            validator,
            amount: MIN_VALIDATOR_BOND,
        }],
    );
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
        balance - 2_000,
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
    let minter = SigningKey::generate(&mut OsRng);
    let minter_addr = minter.verifying_key().to_bytes();
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();

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

    // The minter holds 20,000 STELL. The mint costs it nothing; the trailing
    // `Transfer` of the whole balance is what makes the real debit exceed what
    // the account has once `tx.amount` is added - AFTER the mint was committed.
    engine
        .update_account(AccountState::new(minter_addr, 309_500))
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
                amount: 20_000,
            },
        ],
    );
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
    // The failure fee is charged (the declared gas limit, 300k): the MINT
    // itself moved nothing.
    assert_eq!(minter_bal, 9_500, "the minter paid the failure fee");
}

/// A payout failure (state_engine.rs:528) is raised AFTER the sender has been
/// debited and its nonce consumed at :492-493, so a "failed" transaction still
/// costs the sender money and burns a nonce.
#[tokio::test]
async fn rejected_payout_still_debits_the_sender_and_burns_the_nonce() {
    let engine = InMemoryStateEngine::new();
    let validator = SigningKey::generate(&mut OsRng);
    let validator_addr = validator.verifying_key().to_bytes();
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = attacker.verifying_key().to_bytes();

    // A validator bond small enough that the pool cannot cover the reward.
    engine
        .update_account(AccountState::new(
            validator_addr,
            MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER + 20_000,
        ))
        .await;
    let b = tx_of(
        &validator,
        validator_addr,
        0,
        20_000,
        vec![OpCode::SysCallStake {
            validator: validator_addr,
            amount: MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
        }],
    );
    engine.apply_transaction(&b, 0).await.unwrap();
    {
        let mut l = engine.staking_write().await;
        l.distribute_reward(validator_addr, stell(5_000)).unwrap();
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
    let res = engine.apply_transaction(&t, 0).await;
    let acc = engine.get_account(&attacker_addr).await.unwrap();
    println!("apply_transaction -> {res:?}");
    println!(
        "attacker: balance {} -> {}, nonce {}",
        start, acc.balance, acc.nonce
    );
    println!(
        "validator pending_rewards now {} (was 5000000000000)",
        engine.staking_read().await.validators[&validator_addr].pending_rewards
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
        start - 20_000,
        "a failed attempt pays the fee it declared - and moves no other value"
    );
    // The victim's accrued rewards are untouched: a failed claim must not zero
    // the counter. (Before the ownership fix this transaction reached the payout
    // stage as a THIRD PARTY and zeroed it while crediting the wrong account.)
    assert_eq!(
        engine.staking_read().await.validators[&validator_addr].pending_rewards,
        5_000_000_000_000u64,
        "a failed claim must not destroy the validator's accrued rewards"
    );
}
