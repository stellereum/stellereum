//! REGRESSION (review execution/atomicity, claim 1): a PMM native swap settled
//! BEFORE a later refusal must be undone with it.
//!
//! Order inside `execute_payload_with_preverify_at_height`:
//!   1. the VM runs and clone-commits the wUSDT/curve halves;
//!   2. `settle_pmm_native` writes the native STELL leg into the ACCOUNTS map
//!      and reserves the buy's gross issuance against `total_minted_nano`;
//!   3. the bridge shard gate ("bridge intents settle on the masterchain
//!      only") can still return `Err`.
//!
//! The caller rolls a refused payload back with an EMPTY `ExecPostActions`
//! (it never received one), so `rollback_payload` restores the pmm/token
//! domain snapshots but CANNOT restore the native account leg or the supply
//! reservation. Before the fix that gate returned without the
//! `release_mint_nano` / `restore_pmm_native` pair that every other
//! post-PMM refusal arm performs, so a rejected transaction:
//!   * kept the minted STELL credited to the buyer (free money), and
//!   * permanently consumed supply headroom (the gross counter never went
//!     back down),
//!
//! while the PMM curve and token registry DID roll back — a half-applied
//! swap.
//!
//! The tests assert the whole rejected transaction is invisible except for
//! the F-01 attributable failure fee, which is charged by the caller after
//! the rollback.

use stellereum::bridge::{BridgeIntent, SupportedChain};
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BRIDGE_INTENT, GAS_PMM_BUY, GAS_PMM_SELL};
use stellereum::token::{TokenMetadata, TokenOp};

mod support;
use support::failure_fee;

const BLOCK_TS: u64 = 1_760_000_000;

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

/// A signed PQ transaction tagged with a NON-masterchain source shard, which
/// is exactly what makes the bridge shard gate refuse it on a sharded engine.
fn shard1_tx(
    key: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let pk = key.public_key.clone();
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        1,
        1,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = key.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

/// wUSDT + PMM wiring shared by both tests. Returns the quote token id.
async fn setup_pmm(engine: &InMemoryStateEngine, buyer: [u8; 32], treasury: [u8; 32]) -> [u8; 32] {
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
                amount: 100_000_000,
            },
        )
        .await
        .unwrap();
    engine.pmm_init_usdt(usdt_id, 1_000_000_000).await;
    usdt_id
}

fn withdraw() -> BridgeIntent {
    BridgeIntent::Withdraw {
        chain: SupportedChain::Ethereum,
        target_address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        amount: 1_000,
    }
}

/// FAIL-BEFORE: on the unfixed code the buyer keeps the minted STELL and the
/// global supply counter stays advanced even though the transaction was
/// rejected at the bridge shard gate.
#[tokio::test]
async fn pmm_buy_rolled_back_when_bridge_shard_gate_refuses() {
    let engine = InMemoryStateEngine::new();
    // Multi-shard mode: the C7 bridge gate is armed, so a non-masterchain
    // source is refused AFTER the PMM leg settled.
    engine.enable_cross_shard();

    let treasury = [0x11u8; 32];
    let kp = FalconKeypair::generate_from_seed(0xE1);
    let buyer = pq_addr(&kp);
    let start_native = 1_000_000u64;
    engine
        .update_account(AccountState::new(buyer, start_native))
        .await;
    let usdt_id = setup_pmm(&engine, buyer, treasury).await;

    // Pre-state of every domain the payload could touch.
    let (pmm_minted_before, pmm_reserve_before) = {
        let p = engine.pmm_read().await;
        (p.minted_nano, p.reserve_micro)
    };
    let token_supply_before = engine
        .tokens_read()
        .await
        .get(&usdt_id)
        .map(|t| t.metadata.total_supply)
        .unwrap();
    let buyer_usdt_before = engine.token_balance(&usdt_id, &buyer).await;
    // Pin the counter ABOVE zero first: when it is zero the engine folds the
    // genesis allocation into the very first reservation and a rollback
    // releases only the mint (the genesis baseline is permanent — a
    // pre-existing counter rule), which would make "unchanged" ambiguous.
    // With the counter already non-zero, the buy's reservation is the only
    // delta and a leak shows up exactly.
    engine.mint_native(&[0x5Au8; 32], 1).await.unwrap();
    let total_minted_before = engine.total_minted_nano();
    assert!(total_minted_before > 0, "counter pinned above zero");

    let tx = shard1_tx(
        &kp,
        buyer,
        0,
        GAS_PMM_BUY + GAS_BRIDGE_INTENT,
        0,
        vec![
            OpCode::SysCallPmmBuy {
                usdt_micro: 1_000_000,
            },
            OpCode::SysCallBridge(Box::new(withdraw())),
        ],
    );
    // Call BEFORE the apply: the refusal itself raises the D2 penalty.
    let fee = failure_fee(&engine, &tx).await;

    let res = engine.apply_transaction(&tx, BLOCK_TS).await;
    assert!(res.is_err(), "the bridge shard gate must refuse this tx");
    assert!(
        res.as_ref().unwrap_err().contains("masterchain only"),
        "expected the C7 shard-gate refusal, got {:?}",
        res
    );

    // The only movement a refused transaction may make: the failure fee.
    let buyer_native_after = engine.get_account(&buyer).await.unwrap().balance;
    assert_eq!(
        buyer_native_after,
        start_native.saturating_sub(fee),
        "the PMM buy's native STELL mint must NOT survive the refusal"
    );
    assert_eq!(
        engine.total_minted_nano(),
        total_minted_before,
        "the buy's supply reservation must be released with the swap"
    );
    let (pmm_minted_after, pmm_reserve_after) = {
        let p = engine.pmm_read().await;
        (p.minted_nano, p.reserve_micro)
    };
    assert_eq!(
        (pmm_minted_after, pmm_reserve_after),
        (pmm_minted_before, pmm_reserve_before),
        "the committed PMM curve must be unchanged"
    );
    assert_eq!(
        engine.token_balance(&usdt_id, &buyer).await,
        buyer_usdt_before,
        "the buyer's wUSDT must be unchanged"
    );
    assert_eq!(
        engine
            .tokens_read()
            .await
            .get(&usdt_id)
            .map(|t| t.metadata.total_supply),
        Some(token_supply_before),
        "the wUSDT supply must be unchanged"
    );
    assert_eq!(
        engine
            .get_account(&stellereum::bridge::BRIDGE_ESCROW)
            .await
            .map(|a| a.balance)
            .unwrap_or(0),
        0,
        "the refused withdrawal must not be escrowed"
    );
}

/// The mirror (sell) leg: the native STELL DEBIT must be restored even though
/// no supply reservation is involved. Same gate, same order.
#[tokio::test]
async fn pmm_sell_rolled_back_when_bridge_shard_gate_refuses() {
    let engine = InMemoryStateEngine::new();
    engine.enable_cross_shard();

    let treasury = [0x12u8; 32];
    let kp = FalconKeypair::generate_from_seed(0xE2);
    let buyer = pq_addr(&kp);
    let start_native = 1_000_000u64;
    engine
        .update_account(AccountState::new(buyer, start_native))
        .await;
    let usdt_id = setup_pmm(&engine, buyer, treasury).await;
    // Create redeemable STELL through the direct PMM entry point (committed
    // state before this test's transaction).
    engine.pmm_buy(buyer, 1_000_000).await.unwrap();

    let (sell_amount, pmm_minted_before, pmm_reserve_before) = {
        let p = engine.pmm_read().await;
        let max = p.max_redeemable_stell();
        assert!(max > 1, "the buy must leave something redeemable");
        ((max / 2).max(1), p.minted_nano, p.reserve_micro)
    };
    let buyer_native_before = engine.get_account(&buyer).await.unwrap().balance;
    let buyer_usdt_before = engine.token_balance(&usdt_id, &buyer).await;

    let tx = shard1_tx(
        &kp,
        buyer,
        0,
        GAS_PMM_SELL + GAS_BRIDGE_INTENT,
        0,
        vec![
            OpCode::SysCallPmmSell {
                stell_nano: sell_amount,
            },
            OpCode::SysCallBridge(Box::new(withdraw())),
        ],
    );
    let fee = failure_fee(&engine, &tx).await;

    let res = engine.apply_transaction(&tx, BLOCK_TS).await;
    assert!(res.is_err(), "the bridge shard gate must refuse this tx");
    assert!(
        res.as_ref().unwrap_err().contains("masterchain only"),
        "expected the C7 shard-gate refusal, got {:?}",
        res
    );

    assert_eq!(
        engine.get_account(&buyer).await.unwrap().balance,
        buyer_native_before.saturating_sub(fee),
        "the PMM sell's native STELL debit must NOT survive the refusal"
    );
    let (pmm_minted_after, pmm_reserve_after) = {
        let p = engine.pmm_read().await;
        (p.minted_nano, p.reserve_micro)
    };
    assert_eq!(
        (pmm_minted_after, pmm_reserve_after),
        (pmm_minted_before, pmm_reserve_before),
        "the committed PMM curve must be unchanged"
    );
    assert_eq!(
        engine.token_balance(&usdt_id, &buyer).await,
        buyer_usdt_before,
        "the wUSDT payout must not survive the refusal"
    );
    assert_eq!(
        engine
            .get_account(&stellereum::bridge::BRIDGE_ESCROW)
            .await
            .map(|a| a.balance)
            .unwrap_or(0),
        0,
        "the refused withdrawal must not be escrowed"
    );
}
