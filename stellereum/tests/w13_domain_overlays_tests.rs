//! Wave 13A domain overlay differential tests:
//! - `TokenRegistry::plan_*` + `apply_tx_delta` vs sequential `TokenRegistry::execute`
//! - `OrderbookManager::clone_pair` + `apply_pair_book` vs sequential `get_book_mut`
//! - `StakingLedger::plan_*` / `plan_tx_slice` + `apply_tx_delta` vs sequential `StakingLedger`

use stellereum::commitment::{books_preimage, staking_preimage, tokens_preimage};
use stellereum::orderbook::{
    Order, OrderSide, OrderType, OrderbookActor, OrderbookManager, PAIR_STELL_TON, PAIR_STELL_USDT,
};
use stellereum::staking::{
    required_bond_floor_nano, JailRecord, StakingError, StakingLedger, StakingTxSliceOp,
    DEFAULT_COMMISSION_BPS, MIN_DELEGATION, UNBONDING_PERIOD_SECS,
};
use stellereum::token::{
    TokenError, TokenMetadata, TokenOp, TokenRegistry, TokenTxDelta, ZERO_ADDRESS,
};

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn meta(name: &str, symbol: &str, max_supply: Option<u64>) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

fn assert_tokens_equal(seq: &TokenRegistry, ovl: &TokenRegistry) {
    assert_eq!(seq.next_nonce, ovl.next_nonce);
    assert_eq!(seq.tokens.len(), ovl.tokens.len());
    for (id, a_seq) in &seq.tokens {
        let a_ovl = ovl
            .tokens
            .get(id)
            .expect("token present in overlay registry");
        assert_eq!(a_seq.id, a_ovl.id);
        assert_eq!(a_seq.metadata, a_ovl.metadata);
        assert_eq!(a_seq.balances, a_ovl.balances);
        assert_eq!(a_seq.allowances, a_ovl.allowances);
    }
    assert_eq!(tokens_preimage(seq), tokens_preimage(ovl));
}

fn assert_staking_equal(seq: &StakingLedger, ovl: &StakingLedger) {
    assert_eq!(seq.validators, ovl.validators);
    assert_eq!(seq.delegations, ovl.delegations);
    assert_eq!(seq.delegator_rewards, ovl.delegator_rewards);
    assert_eq!(seq.unbonding, ovl.unbonding);
    assert_eq!(seq.withdrawable, ovl.withdrawable);
    assert_eq!(seq.total_burned, ovl.total_burned);
    assert_eq!(seq.rewards_pool, ovl.rewards_pool);
    assert_eq!(seq.rewards_minted, ovl.rewards_minted);
    assert_eq!(seq.reward_accumulators, ovl.reward_accumulators);
    assert_eq!(
        seq.delegator_reward_checkpoints,
        ovl.delegator_reward_checkpoints
    );
    assert_eq!(staking_preimage(seq), staking_preimage(ovl));
}

fn assert_order_eq(a: &Order, b: &Order) {
    assert_eq!(a.order_id, b.order_id);
    assert_eq!(a.trader, b.trader);
    assert_eq!(a.side, b.side);
    assert_eq!(a.order_type, b.order_type);
    assert_eq!(a.price, b.price);
    assert_eq!(a.amount, b.amount);
    assert_eq!(a.filled, b.filled);
    assert_eq!(a.timestamp, b.timestamp);
}

#[test]
fn token_plan_and_apply_matches_sequential_across_all_ops_and_zero_drains() {
    let minter = addr(1);
    let alice = addr(2);
    let bob = addr(3);
    let spender = addr(4);

    let mut seq = TokenRegistry::new();
    let tok_a = seq
        .create_token(minter, meta("Alpha", "ALP", Some(10_000)), 1_000)
        .unwrap();
    let tok_b = seq
        .create_token(minter, meta("Beta", "BET", None), 500)
        .unwrap();
    let mut ovl = seq.clone();

    // 1. Mint on tok_a
    let ev_seq = seq
        .execute(
            &tok_a,
            minter,
            TokenOp::Mint {
                to: alice,
                amount: 400,
            },
        )
        .unwrap();
    let delta = ovl.plan_mint(&tok_a, minter, alice, 400).unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert_tokens_equal(&seq, &ovl);

    // 2. Partial transfer alice -> bob, then full drain of bob -> minter (must remove bob!)
    let ev_seq = seq
        .execute(
            &tok_a,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 150,
            },
        )
        .unwrap();
    let delta = ovl.plan_transfer(&tok_a, alice, bob, 150).unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert_tokens_equal(&seq, &ovl);

    let ev_seq = seq
        .execute(
            &tok_a,
            bob,
            TokenOp::Transfer {
                to: minter,
                amount: 150,
            },
        )
        .unwrap();
    let delta = ovl.plan_transfer(&tok_a, bob, minter, 150).unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert!(
        !ovl.get(&tok_a).unwrap().balances.contains_key(&bob),
        "0-drained balance must be removed from actor.balances"
    );
    assert_tokens_equal(&seq, &ovl);

    // 3. Approve non-zero, partial transfer_from, then full transfer_from draining BOTH allowance & balance
    let ev_seq = seq
        .execute(
            &tok_a,
            alice,
            TokenOp::Approve {
                spender,
                amount: 250,
            },
        )
        .unwrap();
    let delta = ovl.plan_approve(&tok_a, alice, spender, 250).unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert_tokens_equal(&seq, &ovl);

    let ev_seq = seq
        .execute(
            &tok_a,
            spender,
            TokenOp::TransferFrom {
                from: alice,
                to: bob,
                amount: 100,
            },
        )
        .unwrap();
    let delta = ovl
        .plan_transfer_from(&tok_a, spender, alice, bob, 100)
        .unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert_tokens_equal(&seq, &ovl);

    let ev_seq = seq
        .execute(
            &tok_a,
            spender,
            TokenOp::TransferFrom {
                from: alice,
                to: bob,
                amount: 150,
            },
        )
        .unwrap();
    let delta = ovl
        .plan_transfer_from(&tok_a, spender, alice, bob, 150)
        .unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert!(
        !ovl.get(&tok_a).unwrap().balances.contains_key(&alice),
        "0-drained balance from transfer_from must be removed"
    );
    assert!(
        !ovl.get(&tok_a)
            .unwrap()
            .allowances
            .contains_key(&(alice, spender)),
        "0-drained allowance from transfer_from must be removed"
    );
    assert_tokens_equal(&seq, &ovl);

    // 4. Approve then approve(0) removes allowance entry
    seq.execute(
        &tok_b,
        minter,
        TokenOp::Approve {
            spender,
            amount: 300,
        },
    )
    .unwrap();
    let delta = ovl.plan_approve(&tok_b, minter, spender, 300).unwrap();
    ovl.apply_tx_delta(delta);
    assert_tokens_equal(&seq, &ovl);

    seq.execute(&tok_b, minter, TokenOp::Approve { spender, amount: 0 })
        .unwrap();
    let delta = ovl.plan_approve(&tok_b, minter, spender, 0).unwrap();
    ovl.apply_tx_delta(delta);
    assert!(
        !ovl.get(&tok_b)
            .unwrap()
            .allowances
            .contains_key(&(minter, spender)),
        "approve(0) must remove allowance entry"
    );
    assert_tokens_equal(&seq, &ovl);

    // 5. Burn partial and full drain (by holder and by minter)
    let ev_seq = seq
        .execute(
            &tok_a,
            bob,
            TokenOp::Burn {
                from: bob,
                amount: 100,
            },
        )
        .unwrap();
    let delta = ovl.plan_burn(&tok_a, bob, bob, 100).unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert_tokens_equal(&seq, &ovl);

    let ev_seq = seq
        .execute(
            &tok_a,
            minter,
            TokenOp::Burn {
                from: bob,
                amount: 150,
            },
        )
        .unwrap();
    let delta = ovl.plan_burn(&tok_a, minter, bob, 150).unwrap();
    assert_eq!(delta.events, vec![ev_seq]);
    ovl.apply_tx_delta(delta);
    assert!(
        !ovl.get(&tok_a).unwrap().balances.contains_key(&bob),
        "0-drained balance from burn must be removed"
    );
    assert_tokens_equal(&seq, &ovl);
}

#[test]
fn token_plan_error_parity_and_multi_op_overlay() {
    let minter = addr(10);
    let alice = addr(11);
    let bob = addr(12);
    let missing = addr(99);

    let mut reg = TokenRegistry::new();
    let tok = reg
        .create_token(minter, meta("Capped", "CAP", Some(1_000)), 800)
        .unwrap();

    // Error parity against immutable base
    assert_eq!(
        reg.plan_transfer(&missing, minter, alice, 10),
        Err(TokenError::TokenNotFound)
    );
    assert_eq!(
        reg.plan_transfer(&tok, minter, alice, 0),
        Err(TokenError::ZeroAmount)
    );
    assert_eq!(
        reg.plan_transfer(&tok, minter, ZERO_ADDRESS, 10),
        Err(TokenError::ZeroAddress)
    );
    assert_eq!(
        reg.plan_transfer(&tok, minter, minter, 10),
        Err(TokenError::SelfTransfer)
    );
    assert_eq!(
        reg.plan_transfer(&tok, minter, alice, 801),
        Err(TokenError::InsufficientBalance)
    );
    assert_eq!(
        reg.plan_transfer_from(&tok, alice, minter, bob, 1),
        Err(TokenError::InsufficientAllowance)
    );
    assert_eq!(
        reg.plan_mint(&tok, alice, alice, 1),
        Err(TokenError::NotMinter)
    );
    assert_eq!(
        reg.plan_mint(&tok, minter, alice, 201),
        Err(TokenError::SupplyCapExceeded)
    );
    assert_eq!(
        reg.plan_burn(&tok, alice, minter, 1),
        Err(TokenError::NotMinter)
    );

    // Multi-op chaining into one TokenTxDelta on &TokenRegistry
    let mut seq = reg.clone();
    seq.execute(
        &tok,
        minter,
        TokenOp::Mint {
            to: alice,
            amount: 200,
        },
    )
    .unwrap();
    seq.execute(
        &tok,
        alice,
        TokenOp::Approve {
            spender: bob,
            amount: 150,
        },
    )
    .unwrap();
    seq.execute(
        &tok,
        bob,
        TokenOp::TransferFrom {
            from: alice,
            to: bob,
            amount: 150,
        },
    )
    .unwrap();
    seq.execute(
        &tok,
        bob,
        TokenOp::Burn {
            from: bob,
            amount: 150,
        },
    )
    .unwrap();

    let mut delta = TokenTxDelta::default();
    reg.plan_mint_into(&mut delta, &tok, minter, alice, 200)
        .unwrap();
    reg.plan_approve_into(&mut delta, &tok, alice, bob, 150)
        .unwrap();
    reg.plan_transfer_from_into(&mut delta, &tok, bob, alice, bob, 150)
        .unwrap();
    reg.plan_burn_into(&mut delta, &tok, bob, bob, 150).unwrap();
    reg.apply_tx_delta(delta);

    assert_tokens_equal(&seq, &reg);

    // Paused & renounced checks
    seq.execute(&tok, minter, TokenOp::Pause).unwrap();
    assert_eq!(
        seq.plan_transfer(&tok, minter, alice, 1),
        Err(TokenError::Paused)
    );
    assert_eq!(
        seq.plan_mint(&tok, minter, alice, 1),
        Err(TokenError::Paused)
    );
    assert_eq!(
        seq.plan_burn(&tok, minter, minter, 1),
        Err(TokenError::Paused)
    );
    // Approvals remain allowed while paused
    assert!(seq.plan_approve(&tok, minter, alice, 5).is_ok());

    seq.execute(&tok, minter, TokenOp::Unpause).unwrap();
    seq.execute(&tok, minter, TokenOp::RenounceMinter).unwrap();
    assert_eq!(
        seq.plan_mint(&tok, minter, alice, 1),
        Err(TokenError::MinterRenounced)
    );
}

#[test]
fn orderbook_clone_pair_and_apply_pair_book_matches_sequential_bounded() {
    let alice = addr(1);
    let bob = addr(2);
    let carol = addr(3);

    let mut seq = OrderbookManager::new();
    let mut ovl = OrderbookManager::new();

    // Resting asks on PAIR_STELL_USDT
    {
        let (o_seq, t_seq) = seq.get_book_mut(PAIR_STELL_USDT).submit_order_bounded(
            alice,
            OrderSide::Sell,
            OrderType::Limit,
            100,
            50,
            10,
            64,
        );
        let mut book = ovl.clone_pair(PAIR_STELL_USDT).unwrap();
        let (o_ovl, t_ovl) =
            book.submit_order_bounded(alice, OrderSide::Sell, OrderType::Limit, 100, 50, 10, 64);
        ovl.apply_pair_book(PAIR_STELL_USDT, book);
        assert_order_eq(&o_seq, &o_ovl);
        assert_eq!(t_seq, t_ovl);
    }

    {
        let (o_seq, t_seq) = seq
            .get_book_mut(PAIR_STELL_USDT)
            .submit_order_bounded_with_fills(
                carol,
                OrderSide::Sell,
                OrderType::Limit,
                105,
                40,
                11,
                64,
                256,
            );
        let mut book = ovl.clone_pair(PAIR_STELL_USDT).unwrap();
        let (o_ovl, t_ovl) = book.submit_order_bounded_with_fills(
            carol,
            OrderSide::Sell,
            OrderType::Limit,
            105,
            40,
            11,
            64,
            256,
        );
        ovl.apply_pair_book(PAIR_STELL_USDT, book);
        assert_order_eq(&o_seq, &o_ovl);
        assert_eq!(t_seq, t_ovl);
    }

    // Crossing limit buy on PAIR_STELL_USDT with max_levels = 1 (bounded)
    {
        let (o_seq, t_seq) = seq
            .get_book_mut(PAIR_STELL_USDT)
            .submit_order_bounded_with_fills(
                bob,
                OrderSide::Buy,
                OrderType::Limit,
                110,
                75,
                12,
                1,
                256,
            );
        let mut book = ovl.clone_pair(PAIR_STELL_USDT).unwrap();
        let (o_ovl, t_ovl) = book.submit_order_bounded_with_fills(
            bob,
            OrderSide::Buy,
            OrderType::Limit,
            110,
            75,
            12,
            1,
            256,
        );
        ovl.apply_pair_book(PAIR_STELL_USDT, book);
        assert_order_eq(&o_seq, &o_ovl);
        assert_eq!(t_seq, t_ovl);
        assert_eq!(t_ovl.len(), 1);
    }

    // Separate pair PAIR_STELL_TON remains isolated and also matches
    {
        let (o_seq, t_seq) = seq
            .get_book_mut(PAIR_STELL_TON)
            .submit_order_bounded_with_fills(
                alice,
                OrderSide::Buy,
                OrderType::Limit,
                200,
                30,
                15,
                64,
                256,
            );
        let mut book = ovl.clone_pair(PAIR_STELL_TON).unwrap();
        let (o_ovl, t_ovl) = book.submit_order_bounded_with_fills(
            alice,
            OrderSide::Buy,
            OrderType::Limit,
            200,
            30,
            15,
            64,
            256,
        );
        ovl.apply_pair_book(PAIR_STELL_TON, book);
        assert_order_eq(&o_seq, &o_ovl);
        assert_eq!(t_seq, t_ovl);
    }

    // Unregistered pair id (99): clone_pair returns None, apply_pair_book registers it
    let custom_pair = 99u32;
    assert!(ovl.clone_pair(custom_pair).is_none());
    {
        let (o_seq, t_seq) = seq.get_book_mut(custom_pair).submit_order_bounded(
            carol,
            OrderSide::Sell,
            OrderType::Limit,
            50,
            10,
            20,
            64,
        );
        let mut book = ovl
            .clone_pair(custom_pair)
            .unwrap_or_else(|| OrderbookActor::new(custom_pair, 1000));
        let (o_ovl, t_ovl) =
            book.submit_order_bounded(carol, OrderSide::Sell, OrderType::Limit, 50, 10, 20, 64);
        ovl.apply_pair_book(custom_pair, book);
        assert_order_eq(&o_seq, &o_ovl);
        assert_eq!(t_seq, t_ovl);
    }

    assert_eq!(books_preimage(&seq), books_preimage(&ovl));
    for pair in [PAIR_STELL_USDT, PAIR_STELL_TON, custom_pair] {
        let b_seq = seq.get_book(pair).unwrap();
        let b_ovl = ovl.get_book(pair).unwrap();
        assert_eq!(b_seq.version, b_ovl.version);
        assert_eq!(b_seq.next_order_id, b_ovl.next_order_id);
        assert_eq!(b_seq.depth(), b_ovl.depth());
    }
}

#[test]
fn staking_plan_and_apply_matches_sequential_including_zero_removals_and_unbonding_order() {
    let v1 = addr(1);
    let v2 = addr(2);
    let d1 = addr(11);
    let d2 = addr(12);

    let mut seq = StakingLedger::new();
    seq.bond(
        v1,
        required_bond_floor_nano() + stell(1_000),
        DEFAULT_COMMISSION_BPS,
    )
    .unwrap();
    seq.bond(v2, required_bond_floor_nano() + stell(2_000), 2_000)
        .unwrap();
    let mut ovl = seq.clone();

    // 1. Delegate to v1 and v2 (via plan_delegate and plan_tx_slice)
    seq.delegate(d1, v1, stell(500)).unwrap();
    seq.delegate(d2, v2, stell(800)).unwrap();

    let delta1 = ovl.plan_delegate(d1, v1, stell(500)).unwrap();
    assert_eq!(delta1.staking_pool_delta, stell(500) as i128);
    let delta2 = ovl
        .plan_tx_slice(StakingTxSliceOp::Delegate {
            delegator: d2,
            validator: v2,
            amount: stell(800),
        })
        .unwrap();
    ovl.apply_tx_delta(delta1).unwrap();
    ovl.apply_tx_delta(delta2).unwrap();
    assert_staking_equal(&seq, &ovl);

    // 2. Distribute rewards on both validators
    seq.distribute_reward(v1, stell(100)).unwrap();
    seq.distribute_reward(v2, stell(200)).unwrap();
    ovl.distribute_reward(v1, stell(100)).unwrap();
    ovl.distribute_reward(v2, stell(200)).unwrap();
    assert_staking_equal(&seq, &ovl);

    // 3. Partial begin_undelegate on v1, unbond on v2, full begin_undelegate on v2 (verifies Vec order & 0-removal)
    seq.undelegate(d1, v1, stell(200), 100).unwrap();
    seq.unbond(v2, stell(500), 101).unwrap();
    seq.undelegate(d2, v2, stell(800), 102).unwrap();

    // INVARIANT (see `StakingLedger::apply_tx_delta` docs): a delta carries a
    // full `ValidatorStake` snapshot, so two deltas touching the SAME validator
    // must not be planned against the same base — the later snapshot would
    // revert the earlier one. The parallel executor guarantees this by keying
    // every staking op on `ResourceKeyV2::Validator(id)` (Write), which forces
    // same-validator ops into different waves. Mirror that here: apply each
    // same-validator delta before planning the next.
    let u1 = ovl.plan_begin_undelegate(d1, v1, stell(200), 100).unwrap();
    ovl.apply_tx_delta(u1).unwrap();
    let u2 = ovl.plan_unbond(v2, stell(500), 101).unwrap();
    ovl.apply_tx_delta(u2).unwrap();
    let u3 = ovl
        .plan_tx_slice(StakingTxSliceOp::BeginUndelegate {
            delegator: d2,
            validator: v2,
            amount: stell(800),
            now: 102,
        })
        .unwrap();
    ovl.apply_tx_delta(u3).unwrap();
    assert!(
        !ovl.delegations.contains_key(&(v2, d2)),
        "full undelegate must remove 0 delegation entry"
    );
    assert_staking_equal(&seq, &ovl);

    // 4. More rewards, then claim validator & delegator rewards
    seq.distribute_reward(v1, stell(50)).unwrap();
    ovl.distribute_reward(v1, stell(50)).unwrap();

    let v1_rew_seq = seq.claim_validator_rewards(v1).unwrap();
    let v1_rew_delta = ovl.plan_claim_rewards(v1).unwrap();
    assert_eq!(v1_rew_delta.claimed_rewards(), v1_rew_seq);
    ovl.apply_tx_delta(v1_rew_delta).unwrap();
    assert_staking_equal(&seq, &ovl);

    let d1_rew_seq = seq.claim_delegator_rewards(d1, v1);
    assert!(d1_rew_seq > 0);
    let d1_rew_delta = ovl.plan_claim_delegator_rewards(d1, v1).unwrap();
    assert_eq!(d1_rew_delta.claimed_rewards(), d1_rew_seq);
    ovl.apply_tx_delta(d1_rew_delta).unwrap();
    assert!(!ovl.delegator_rewards.contains_key(&(v1, d1)));
    assert_staking_equal(&seq, &ovl);

    let d2_rew_seq = seq.claim_delegator_rewards(d2, v2);
    assert!(d2_rew_seq > 0);
    let d2_rew_delta = ovl
        .plan_tx_slice(StakingTxSliceOp::ClaimDelegatorRewards {
            delegator: d2,
            validator: v2,
        })
        .unwrap();
    assert_eq!(d2_rew_delta.claimed_rewards(), d2_rew_seq);
    ovl.apply_tx_delta(d2_rew_delta).unwrap();
    assert_staking_equal(&seq, &ovl);

    // 5. Mature unbonding entries and test plan_undelegate (withdraw_delegator) & plan_withdraw_self_bond
    let mature_at = 102 + UNBONDING_PERIOD_SECS;
    seq.process_unbonding(mature_at).unwrap();
    ovl.process_unbonding(mature_at).unwrap();
    assert_staking_equal(&seq, &ovl);

    let wd_seq = seq.withdraw_delegator(d1, v1).unwrap();
    let wd_delta = ovl.plan_undelegate(d1, v1).unwrap();
    assert_eq!(wd_delta.withdrawn_amount(), wd_seq);
    ovl.apply_tx_delta(wd_delta).unwrap();
    assert!(!ovl.withdrawable.contains_key(&(v1, d1)));
    assert_staking_equal(&seq, &ovl);

    let ws_seq = seq.withdraw(v2).unwrap();
    let ws_delta = ovl.plan_withdraw_self_bond(v2).unwrap();
    assert_eq!(ws_delta.withdrawn_amount(), ws_seq);
    ovl.apply_tx_delta(ws_delta).unwrap();
    assert!(!ovl.withdrawable.contains_key(&(v2, [0u8; 32])));
    assert_staking_equal(&seq, &ovl);
}

#[test]
fn staking_plan_and_apply_enforces_rewards_pool_exhaustion_and_error_parity() {
    let v1 = addr(1);
    let v2 = addr(2);
    let v_missing = addr(99);
    let d1 = addr(11);
    let d2 = addr(12);

    let mut ledger = StakingLedger::new();
    ledger
        .bond(
            v1,
            required_bond_floor_nano() + stell(1_000),
            DEFAULT_COMMISSION_BPS,
        )
        .unwrap();
    ledger
        .bond(
            v2,
            required_bond_floor_nano() + stell(1_000),
            DEFAULT_COMMISSION_BPS,
        )
        .unwrap();
    ledger.delegate(d1, v1, stell(500)).unwrap();
    ledger.delegate(d2, v2, stell(500)).unwrap();
    ledger.distribute_reward(v1, stell(100)).unwrap();
    ledger.distribute_reward(v2, stell(100)).unwrap();

    // Error parity on plan_*
    assert_eq!(
        ledger.plan_delegate(ZERO_ADDRESS, v1, stell(10)),
        Err(StakingError::ZeroAddress)
    );
    assert_eq!(
        ledger.plan_delegate(d1, v1, MIN_DELEGATION - 1),
        Err(StakingError::DelegationBelowMinimum)
    );
    assert_eq!(
        ledger.plan_delegate(d1, v_missing, MIN_DELEGATION),
        Err(StakingError::NotValidator)
    );
    assert_eq!(
        ledger.plan_unbond(v1, stell(5_000), 0),
        Err(StakingError::InsufficientBond)
    );
    assert_eq!(
        ledger.plan_unbond(v1, stell(1_500), 0),
        Err(StakingError::BondBelowMinimum)
    );
    assert_eq!(
        ledger.plan_begin_undelegate(d1, v1, stell(501), 0),
        Err(StakingError::InsufficientDelegation)
    );
    assert_eq!(
        ledger.plan_undelegate(d1, v1),
        Err(StakingError::NothingToWithdraw)
    );
    assert_eq!(
        ledger.plan_withdraw_self_bond(v1),
        Err(StakingError::NothingToWithdraw)
    );
    assert_eq!(
        ledger.plan_claim_rewards(v_missing),
        Err(StakingError::NotValidator)
    );

    // Governance lock & jail error parity
    let mut locked_ledger = ledger.clone();
    locked_ledger.lock_governance(d1, stell(400));
    assert_eq!(
        locked_ledger.plan_begin_undelegate(d1, v1, stell(200), 0),
        Err(StakingError::LockedInGovernanceVote)
    );
    locked_ledger.jail.insert(
        v1,
        JailRecord {
            jailed_at_height: 1,
            release_height: 4_001,
        },
    );
    assert_eq!(
        locked_ledger.plan_delegate(d1, v1, stell(10)),
        Err(StakingError::Jailed)
    );

    // Direct plan-time rewards_pool shortfall on claim_validator_rewards
    let mut short_ledger = ledger.clone();
    short_ledger.rewards_pool = 1;
    assert_eq!(
        short_ledger.claim_validator_rewards(v1),
        Err(StakingError::RewardsPoolShortfall)
    );
    assert_eq!(
        short_ledger.plan_claim_rewards(v1),
        Err(StakingError::RewardsPoolShortfall)
    );

    // Commit-time rewards_pool exhaustion across two parallel plans on disjoint validators:
    // Both plan against the same read-only snapshot (`rewards_pool` reduced so one fits, two exceed).
    let v1_pending = ledger.validators.get(&v1).unwrap().pending_rewards;
    let v2_pending = ledger.validators.get(&v2).unwrap().pending_rewards;
    assert!(v1_pending > 0 && v2_pending > 0);
    ledger.rewards_pool = v1_pending + v2_pending - 1;

    let d_v1 = ledger.plan_claim_rewards(v1).unwrap();
    let d_v2 = ledger.plan_claim_rewards(v2).unwrap();

    let pre_v2 = ledger.validators.get(&v2).unwrap().clone();
    ledger.apply_tx_delta(d_v1).unwrap();
    assert_eq!(ledger.rewards_pool, v2_pending - 1);
    assert_eq!(ledger.validators.get(&v1).unwrap().pending_rewards, 0);

    let err = ledger.apply_tx_delta(d_v2).unwrap_err();
    assert_eq!(err, StakingError::RewardsPoolShortfall);
    assert_eq!(ledger.rewards_pool, v2_pending - 1);
    assert_eq!(ledger.validators.get(&v2).unwrap(), &pre_v2);

    // Also verify commit-time rewards_pool exhaustion on delegator reward deltas
    let d1_owed = ledger.delegator_rewards_of(d1, v1);
    let d2_owed = ledger.delegator_rewards_of(d2, v2);
    assert!(d1_owed > 0 && d2_owed > 0);
    ledger.rewards_pool = d1_owed + d2_owed - 1;

    let del_delta_1 = ledger.plan_claim_delegator_rewards(d1, v1).unwrap();
    let del_delta_2 = ledger.plan_claim_delegator_rewards(d2, v2).unwrap();
    ledger.apply_tx_delta(del_delta_1).unwrap();
    assert_eq!(ledger.rewards_pool, d2_owed - 1);

    let pre_acc_v2 = ledger.reward_accumulators.get(&v2).cloned();
    let err2 = ledger.apply_tx_delta(del_delta_2).unwrap_err();
    assert_eq!(err2, StakingError::RewardsPoolShortfall);
    assert_eq!(ledger.rewards_pool, d2_owed - 1);
    assert_eq!(ledger.reward_accumulators.get(&v2), pre_acc_v2.as_ref());
    assert_eq!(ledger.delegator_rewards_of(d2, v2), d2_owed);
}
