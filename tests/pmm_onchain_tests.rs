//! Proves the PMM operates on real on-chain balances: buying mints native
//! STELL and burns wUSDT; selling burns native STELL and mints wUSDT; the
//! system conserves value and the ring-fenced reserve cannot be drained.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_PMM_BUY, GAS_PMM_SELL};
use stellereum::token::{TokenMetadata, TokenOp};

async fn setup() -> (InMemoryStateEngine, [u8; 32], [u8; 32], [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let sk = SigningKey::generate(&mut OsRng);
    let buyer = sk.verifying_key().to_bytes();
    let usdt_minter = [0x11u8; 32];
    engine.update_account(AccountState::new(buyer, 0)).await;

    // Create the bridged-USDT token (wUSDT) with a minter-controlled supply.
    let meta = TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let usdt_id = engine.create_token(usdt_minter, meta, 0).await.unwrap();
    // Mint 1,000,000 wUSDT to the buyer (6 decimals -> $1,000,000).
    engine
        .token_execute(
            &usdt_id,
            usdt_minter,
            TokenOp::Mint {
                to: buyer,
                amount: 1_000_000_000_000,
            },
        )
        .await
        .unwrap();
    // Seed the PMM with $1,000,000 USDT reserve.
    engine.pmm_init_usdt(usdt_id, 1_000_000_000_000).await;
    (engine, buyer, usdt_id, usdt_minter)
}

#[tokio::test]
async fn pmm_buy_mints_native_stell_and_burns_wusdt() {
    let (engine, buyer, usdt_id, _) = setup().await;

    let before_usdt = engine.token_balance(&usdt_id, &buyer).await;
    let receipt = engine.pmm_buy(buyer, 250_000).await.unwrap(); // $0.25

    assert!(receipt.stell_minted > 0, "buy must mint STELL");
    let after_usdt = engine.token_balance(&usdt_id, &buyer).await;
    assert_eq!(
        after_usdt,
        before_usdt - 250_000,
        "wUSDT must be debited exactly"
    );

    let native = engine.get_account(&buyer).await.unwrap().balance;
    assert_eq!(
        native, receipt.stell_minted,
        "native STELL credited on-chain"
    );
}

#[tokio::test]
async fn pmm_roundtrip_does_not_make_free_money() {
    let (engine, buyer, usdt_id, _) = setup().await;

    let usdt_before = engine.token_balance(&usdt_id, &buyer).await;
    let buy = engine.pmm_buy(buyer, 1_000_000).await.unwrap(); // $1.00
    let sell = engine.pmm_sell(buyer, buy.stell_minted).await.unwrap();

    // Selling everything back must not yield more USDT than was put in.
    assert!(
        sell.usdt_paid <= 1_000_000,
        "round-trip must not create value (paid {} > spent 1000000)",
        sell.usdt_paid
    );
    let usdt_after = engine.token_balance(&usdt_id, &buyer).await;
    assert!(usdt_after <= usdt_before, "no free USDT via round-trip");
}

#[tokio::test]
async fn pmm_sell_cannot_drain_the_ring_fenced_reserve() {
    let (engine, buyer, _, _) = setup().await;
    // Give the buyer a huge native STELL balance to attempt a full drain.
    let buyer2 = buyer;
    {
        let mut map = engine.accounts.write().await;
        map.get_mut(&buyer2).unwrap().balance = u64::MAX / 2;
    }

    // The PMM only minted its own supply via buys; selling more than was ever
    // minted must be rejected outright.
    let res = engine.pmm_sell(buyer2, 10_000_000_000_000_000).await;
    assert!(res.is_err(), "cannot redeem more STELL than the PMM minted");
}

#[tokio::test]
async fn pmm_sell_without_native_balance_is_rejected_atomically() {
    let (engine, buyer, usdt_id, _) = setup().await;
    // Buy a little, then try to sell more than the buyer holds.
    let buy = engine.pmm_buy(buyer, 100_000).await.unwrap();
    let res = engine.pmm_sell(buyer, buy.stell_minted + 1_000_000).await;
    assert!(res.is_err(), "must reject selling more STELL than held");

    // Atomicity: buyer's native balance unchanged, wUSDT curve untouched.
    let native = engine.get_account(&buyer).await.unwrap().balance;
    assert_eq!(
        native, buy.stell_minted,
        "failed sell must not change balances"
    );
    let usdt = engine.token_balance(&usdt_id, &buyer).await;
    assert_eq!(
        usdt,
        1_000_000_000_000 - 100_000,
        "wUSDT unchanged by failed sell"
    );
}

#[tokio::test]
async fn pmm_buy_without_usdt_is_rejected() {
    let (engine, buyer, _, _) = setup().await;
    // Drain the buyer's wUSDT first.
    let usdt_id = engine.pmm_usdt_token_read().await.unwrap();
    let bal = engine.token_balance(&usdt_id, &buyer).await;
    engine
        .token_execute(
            &usdt_id,
            buyer,
            TokenOp::Burn {
                from: buyer,
                amount: bal,
            },
        )
        .await
        .unwrap();
    let res = engine.pmm_buy(buyer, 1_000).await;
    assert!(res.is_err(), "cannot buy with zero wUSDT");
}

/// A fixed, realistic block timestamp: 0 is exactly the epoch-0 bug the live
/// path used to have.
const BLOCK_TS: u64 = 1_760_000_000;

/// The PMM syscalls must move REAL native STELL on the LIVE consensus path,
/// not only through the direct `pmm_buy`/`pmm_sell` engine methods. A block
/// carrying `SysCallPmmBuy` mints STELL and burns wUSDT; the mirror
/// `SysCallPmmSell` burns STELL and mints the wUSDT payout; and the round trip
/// cannot create value. This drives both through `apply_block_parallel_fees`,
/// the same core the validator runtime uses to apply a finalized block.
#[tokio::test]
async fn pmm_buy_sell_roundtrip_on_the_live_block_path() {
    let engine = InMemoryStateEngine::new();
    let treasury_key = SigningKey::from_bytes(&[0x11u8; 32]);
    let treasury = treasury_key.verifying_key().to_bytes();
    let buyer_key = SigningKey::from_bytes(&[0x22u8; 32]);
    let buyer = buyer_key.verifying_key().to_bytes();
    let start = 1_000_000u64;
    engine.update_account(AccountState::new(buyer, start)).await;

    let meta = TokenMetadata {
        name: "Wrapped USDT".into(),
        symbol: "wUSDT".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let usdt_id = engine.create_token(treasury, meta, 0).await.unwrap();
    engine
        .token_execute(
            &usdt_id,
            treasury,
            TokenOp::Mint {
                to: buyer,
                amount: 1_000_000_000,
            },
        )
        .await
        .unwrap();
    engine.pmm_init_usdt(usdt_id, 1_000_000_000).await;

    // The wiring the syscalls read: the quote token and the mint authority.
    let (pmm0, quote, minter) = engine.pmm_state().await;
    assert_eq!(quote, Some(usdt_id));
    assert_eq!(minter, treasury, "the treasury is the wUSDT minter");

    // Expected curve result, computed off the committed pre-block state.
    let usdt_micro = 1_000_000u64;
    let mut trial = pmm0.clone();
    let expected_buy = trial
        .buy_with_buffer(usdt_micro, stellereum::pmm::PMM_REDEMPTION_BUFFER_BPS)
        .unwrap();

    let buy_tx = Transaction::sign_with_payload(
        &buyer_key,
        buyer,
        0,
        GAS_PMM_BUY,
        0,
        1,
        1,
        vec![OpCode::SysCallPmmBuy { usdt_micro }],
    );
    let (applied, failed, fees, status, _) =
        engine.apply_block_parallel_fees(&[buy_tx], BLOCK_TS).await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "the PMM buy must apply as part of a block"
    );
    assert_eq!(status, vec![true]);
    assert_eq!(
        fees, GAS_PMM_BUY,
        "the block path charges the declared gas limit"
    );

    let native_after_buy = engine.get_account(&buyer).await.unwrap().balance;
    assert_eq!(
        native_after_buy,
        start - GAS_PMM_BUY + expected_buy.stell_minted,
        "the buy's native STELL mint must be committed by the engine"
    );
    assert_eq!(
        engine.token_balance(&usdt_id, &buyer).await,
        1_000_000_000 - usdt_micro,
        "the buyer's wUSDT must be burned exactly"
    );
    {
        // Scoped so the read guard is released before the next block apply,
        // which takes the PMM write lock inside `execute_payload`.
        let committed = engine.pmm_read().await;
        assert_eq!(
            committed.minted_nano, expected_buy.stell_minted as u128,
            "the committed curve must have advanced"
        );
        assert_eq!(
            committed.reserve_micro,
            1_000_000_000u128 + usdt_micro as u128,
            "the full wUSDT payment must be in the reserve"
        );
    }
    assert_eq!(engine.get_account(&buyer).await.unwrap().nonce, 1);

    // Sell the maximum redeemable amount back through the same block path. The
    // expected receipt is computed off a clone of the committed curve, which
    // must be dropped before the apply below.
    let (sell_amount, expected_sell) = {
        let committed = engine.pmm_read().await;
        let sell_amount = committed.max_redeemable_stell();
        assert!(sell_amount > 0, "some redemption must be possible");
        let mut trial2 = committed.clone();
        (sell_amount, trial2.sell_stell(sell_amount).unwrap())
    };

    let sell_tx = Transaction::sign_with_payload(
        &buyer_key,
        buyer,
        0,
        GAS_PMM_SELL,
        1,
        1,
        1,
        vec![OpCode::SysCallPmmSell {
            stell_nano: sell_amount,
        }],
    );
    let (applied, failed, fees, status, _) = engine
        .apply_block_parallel_fees(&[sell_tx], BLOCK_TS + 1)
        .await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "the PMM sell must apply as part of a block"
    );
    assert_eq!(status, vec![true]);
    assert_eq!(fees, GAS_PMM_SELL);

    let native_final = engine.get_account(&buyer).await.unwrap().balance;
    assert_eq!(
        native_final,
        native_after_buy - GAS_PMM_SELL - sell_amount,
        "the sell's native STELL burn must be committed by the engine"
    );
    assert_eq!(
        engine.token_balance(&usdt_id, &buyer).await,
        1_000_000_000 - usdt_micro + expected_sell.usdt_paid,
        "the wUSDT payout must be minted exactly"
    );
    let after = engine.pmm_read().await;
    assert_eq!(
        after.minted_nano,
        expected_buy.stell_minted as u128 - sell_amount as u128,
        "the committed curve must have wound back"
    );

    // Value conservation: the redemption can never return more wUSDT than was
    // paid in, so a full live-path round trip cannot mint free money.
    assert!(
        expected_sell.usdt_paid <= usdt_micro,
        "round trip must not profit: {} paid back for {} spent",
        expected_sell.usdt_paid,
        usdt_micro
    );
}
