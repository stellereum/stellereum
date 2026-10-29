//! HUNT: token supply invariants (mostly negative results), and the staking
//! withdrawal path, which credits the withdrawer with a MINT instead of moving
//! the coins out of the STAKING_POOL.
//!
//! `ValidatorRuntime::stake_withdraw` (src/runtime.rs:272) does
//!   `let amount = ledger.withdraw(v)?;  self.state.credit_native(&v, amount)`
//! `credit_native` (src/state_engine.rs:1424) is a pure mint: it adds to the
//! account balance with no matching debit anywhere. The staking pool - the one
//! account that is supposed to hold the bonded principal - is never debited on
//! the withdrawal leg, so every unbond/withdraw cycle inflates the native
//! supply and leaves the pool over-collateralised with the same coins.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::consensus::ValidatorSet;
use stellereum::runtime::ValidatorRuntime;
use stellereum::staking::{
    StakingLedger, MIN_VALIDATOR_BOND, STAKING_POOL, STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::{TokenError, TokenMetadata};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

#[test]
fn token_supply_cap_cannot_be_exceeded() {
    let minter = [1u8; 32];
    let meta = TokenMetadata {
        name: "Capped".into(),
        symbol: "CAP".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: Some(1_000_000),
        minter,
        paused: false,
        description: String::new(),
    };
    let mut t = stellereum::token::TokenActor::new([9u8; 32], meta, 0).unwrap();
    t.mint(minter, [2u8; 32], 1_000_000).unwrap();
    assert_eq!(t.metadata.total_supply, 1_000_000);
    assert_eq!(
        t.mint(minter, [2u8; 32], 1),
        Err(TokenError::SupplyCapExceeded),
        "NEGATIVE RESULT: the cap holds"
    );
    // And after a burn the cap is re-usable, exactly once.
    t.burn(minter, [2u8; 32], 1).unwrap();
    assert!(t.mint(minter, [2u8; 32], 1).is_ok());
    assert_eq!(
        t.mint(minter, [2u8; 32], 1),
        Err(TokenError::SupplyCapExceeded)
    );
}

#[test]
fn token_burn_cannot_drive_the_supply_below_zero() {
    let minter = [1u8; 32];
    let meta = TokenMetadata {
        name: "X".into(),
        symbol: "X".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter,
        paused: false,
        description: String::new(),
    };
    let mut t = stellereum::token::TokenActor::new([9u8; 32], meta, 500).unwrap();
    assert_eq!(
        t.burn(minter, [1u8; 32], 501),
        Err(TokenError::InsufficientBalance)
    );
    assert_eq!(
        t.metadata.total_supply, 500,
        "NEGATIVE RESULT: a failed burn changes nothing"
    );
    // A non-minter cannot burn someone else's tokens.
    assert_eq!(t.burn([7u8; 32], [2u8; 32], 1), Err(TokenError::NotMinter));
    // Burning the whole supply lands exactly on zero, never below.
    t.burn(minter, [1u8; 32], 500).unwrap();
    assert_eq!(t.metadata.total_supply, 0);
    assert_eq!(t.balance_of(&minter), 0);
}

#[test]
fn allowances_cannot_be_overdrawn_or_replayed_after_revoke() {
    let owner = [1u8; 32];
    let spender = [2u8; 32];
    let meta = TokenMetadata {
        name: "X".into(),
        symbol: "X".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        // the owner is the minter, so the initial supply lands with it
        minter: owner,
        paused: false,
        description: String::new(),
    };
    let mut t = stellereum::token::TokenActor::new([9u8; 32], meta, 1_000).unwrap();
    t.approve(owner, spender, 100).unwrap();
    t.transfer_from(spender, owner, [3u8; 32], 101).unwrap_err();
    t.transfer_from(spender, owner, [3u8; 32], 100).unwrap();
    assert_eq!(t.allowance(&owner, &spender), 0);
    assert_eq!(
        t.transfer_from(spender, owner, [3u8; 32], 1),
        Err(TokenError::InsufficientAllowance),
        "NEGATIVE RESULT: the spent allowance is gone"
    );
    // Re-approve, then revoke with approve(0), then try to spend.
    t.approve(owner, spender, 50).unwrap();
    t.approve(owner, spender, 0).unwrap();
    assert_eq!(
        t.transfer_from(spender, owner, [3u8; 32], 1),
        Err(TokenError::InsufficientAllowance),
        "NEGATIVE RESULT: a revoked allowance cannot be spent"
    );
    // A spender cannot move more than the owner's live balance either.
    t.approve(owner, spender, u64::MAX).unwrap();
    assert_eq!(
        t.transfer_from(spender, owner, [3u8; 32], 901),
        Err(TokenError::InsufficientBalance)
    );
    assert_eq!(
        t.balance_of(&owner),
        900,
        "a failed transfer_from moved nothing"
    );
}

/// FIXED (M2): every unbond -> cooldown -> withdraw cycle now debits the pool
/// symmetrically, so no STELL is created: the same coins move from pool to
/// validator exactly once, and the pool can never cover withdrawals it no
/// longer owns. This is the regression pin for the fix.
#[tokio::test]
async fn staking_withdrawal_moves_coins_from_the_pool() {
    let state = Arc::new(InMemoryStateEngine::new());
    let ks: Vec<SigningKey> = (0..1).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let v = ks[0].verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(v, 1)]);
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state.clone(), 1)
        .with_staking(StakingLedger::new());

    let bond = stell(10_000);
    state
        .update_account(AccountState::new(v, 6 * bond + 100_000))
        .await;
    rt.stake_bond(v, bond, 0).await.unwrap();
    let pool_after_bond = state.get_account(&STAKING_POOL).await.unwrap().balance;
    println!(
        "after bonding {bond}: pool holds {pool_after_bond}, validator holds {}",
        state.get_account(&v).await.unwrap().balance
    );
    assert_eq!(pool_after_bond, bond);

    let supply_before = {
        let m = state.accounts.read().await;
        m.values().map(|a| a.balance).sum::<u64>()
    };
    let mut now = 1_000u64;
    let mut total_minted = 0u64;
    for cycle in 0..5u64 {
        now += 1;
        // Full exit, then wait out the cooldown and withdraw.
        rt.staking_write()
            .await
            .unbond(v, stell(10_000), now)
            .unwrap();
        now += UNBONDING_PERIOD_SECS + 1;
        rt.process_unbonding(now).await;
        let pool_before = state.get_account(&STAKING_POOL).await.unwrap().balance;
        let got = rt.stake_withdraw(v).await.unwrap();
        total_minted += got;
        let pool = state.get_account(&STAKING_POOL).await.unwrap().balance;
        println!(
            "cycle {cycle}: withdrew {got}, validator balance now {}, pool {pool} (debited {got})",
            state.get_account(&v).await.unwrap().balance
        );
        assert_eq!(
            pool,
            pool_before - got,
            "the withdrawal must move coins out of the pool"
        );
        // Re-bond so the next cycle can run. `bond()` refuses a re-registration,
        // so this is `add_bond` + a pool credit - exactly what
        // `OpCode::SysCallStake` does on an existing validator.
        {
            let mut l = rt.staking_write().await;
            l.add_bond(v, bond).unwrap();
        }
        state.debit_native(&v, bond).await.unwrap();
        state.credit_native(&STAKING_POOL, bond).await.unwrap();
    }

    let pool = state.get_account(&STAKING_POOL).await.unwrap().balance;
    let validator = state.get_account(&v).await.unwrap().balance;
    let supply_after = {
        let m = state.accounts.read().await;
        m.values().map(|a| a.balance).sum::<u64>()
    };
    println!(
        "after 5 cycles: validator holds {validator}, pool holds {pool}, moved {total_minted}"
    );
    println!("native supply: {supply_before} -> {supply_after} (must be conserved)");
    assert_eq!(
        total_minted,
        5 * bond,
        "five full exits return 10,000 STELL each"
    );
    assert_eq!(
        supply_after, supply_before,
        "FIXED: withdrawing must conserve the native money supply"
    );
    assert_eq!(
        pool, bond,
        "the pool holds exactly the one live escrow after re-bonding each cycle"
    );
}

/// `add_bond` (src/staking.rs:195) — the branch `OpCode::SysCallStake` takes
/// for an existing validator — has no ownership check at all: the bond is taken
/// from whoever signs the transaction and the voting power goes to the validator
/// named in the payload. Anyone can therefore buy someone else's consensus
/// weight (or, more interestingly, hand a colluding validator 51% of the set).
#[tokio::test]
async fn third_party_can_buy_any_validators_voting_power() {
    let engine = InMemoryStateEngine::new();
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = victim.verifying_key().to_bytes();
    let funder = SigningKey::generate(&mut OsRng);
    let funder_addr = funder.verifying_key().to_bytes();

    engine
        .update_account(AccountState::new(
            victim_addr,
            MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER + 20_000,
        ))
        .await;
    let b = stellereum::sharding::Transaction::sign_with_payload(
        &victim,
        victim_addr,
        0,
        20_000,
        0,
        1,
        1,
        vec![OpCode::SysCallStake {
            validator: victim_addr,
            amount: MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
        }],
    );
    engine.apply_transaction(&b, 0).await.unwrap();
    let before = engine
        .staking_read()
        .await
        .to_validator_set()
        .power_of(&victim_addr);
    println!("victim validator power before: {before}");

    // The funder signs a transaction that names the VICTIM's validator id.
    engine
        .update_account(AccountState::new(funder_addr, stell(1_000_000) + 100_000))
        .await;
    let t = stellereum::sharding::Transaction::sign_with_payload(
        &funder,
        funder_addr,
        0,
        100_000,
        0,
        1,
        1,
        vec![OpCode::SysCallStake {
            validator: victim_addr,
            amount: stell(1_000_000),
        }],
    );
    engine.apply_transaction(&t, 0).await.unwrap();
    let power = engine
        .staking_read()
        .await
        .to_validator_set()
        .power_of(&victim_addr);
    println!(
        "the funder paid {} STELL and bought a stranger {} STELL of voting power",
        stell(1_000_000) / 1_000_000_000,
        (power - before) / 1_000_000_000
    );
    assert_eq!(power, before + stell(1_000_000));
    assert_eq!(
        engine.get_account(&funder_addr).await.unwrap().balance,
        98_000,
        "the funder's coins left their account (only the 2,000 gas stayed)"
    );
    assert_eq!(
        engine.get_account(&victim_addr).await.unwrap().balance,
        18_000,
        "the validator was never debited: the coins went to the pool"
    );
    assert_eq!(
        engine.get_account(&STAKING_POOL).await.unwrap().balance,
        MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER + stell(1_000_000),
        "and the pool now holds 1,101,000 STELL of backing for a validator that owns none of it"
    );
}
