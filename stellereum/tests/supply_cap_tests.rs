//! GLOBAL supply cap, enforced in the state engine itself.
//!
//! `TOTAL_SUPPLY_CAP` (1B STELL) used to be a per-subsystem notion only:
//! `GENESIS_VAULT_CAP` (250M), `REWARDS_EMISSION_CAP` (350M) and
//! `BRIDGE_MINT_CAP_NANO` (100M) each bounded their OWN pool, so N pools could
//! each respect their local cap while their SUM blew past 1B. These tests pin
//! the engine-level invariant that closes that hole:
//!
//! * a mint ([`InMemoryStateEngine::mint_native`], which
//!   [`InMemoryStateEngine::credit_native`] delegates to) atomically reserves
//!   against one monotone counter and fails closed one nano past the cap;
//! * a TRANSFER is never capped — moving existing value near (and at) the cap
//!   still works, through [`InMemoryStateEngine::transfer_native`] and the
//!   fee/refund credit [`InMemoryStateEngine::credit_native_transfer`];
//! * the block-reward mint stops exactly at the cap and reserves global
//!   headroom BEFORE it mutates the staking ledger (no unbacked reward
//!   accounting);
//! * the counter is monotone: burns do not restore headroom and a refused mint
//!   does not consume any;
//! * a snapshot restore rebases the counter to the restored supply, so a
//!   restarted node cannot mint a second full cap from zero.
//!
//! SCOPE NOTE: the counter is folded into the consensus state root
//! (`commitment::assemble_cached_digest_with_cnvrf_and_minted`), so a node
//! that lost or reset it can no longer hide behind an identical root. It is
//! still PER-ENGINE: see `per_engine_cap_is_not_a_chain_wide_cap_known_gap`
//! for the workchain gap (a chain-wide cap needs a cross-shard registry).

use ed25519_dalek::SigningKey;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::{required_bond_floor_nano, REWARDS_EMISSION_CAP, REWARDS_POOL};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::tokenomics::TOTAL_SUPPLY_CAP;

const STELL: u64 = 1_000_000_000;
const TS: u64 = 1_760_000_000;

fn addr(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Minimal decided block at `height` with no transactions. Block-signature
/// verification is outside `apply_block_transition` (same shape as the
/// existing block-path tests), so any deterministic key works.
fn empty_block(proposer_key: &SigningKey, height: u64) -> Block {
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: TS,
        proposer: proposer_key.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
    };
    block.sign_block(proposer_key);
    block
}

#[tokio::test]
async fn mint_to_the_cap_succeeds_one_nano_past_fails_closed() {
    let engine = InMemoryStateEngine::new();
    let holder = addr(0x11);

    assert_eq!(engine.total_minted_nano(), 0, "fresh engine mints nothing");
    assert_eq!(
        engine.remaining_mint_headroom_nano(),
        TOTAL_SUPPLY_CAP,
        "all of the supply cap is headroom on a fresh engine"
    );

    // Mint the ENTIRE cap in one shot: allowed, and it lands in the account.
    engine
        .mint_native(&holder, TOTAL_SUPPLY_CAP)
        .await
        .expect("minting exactly up to the cap must succeed");
    assert_eq!(engine.total_minted_nano(), TOTAL_SUPPLY_CAP);
    assert_eq!(engine.remaining_mint_headroom_nano(), 0);
    assert_eq!(
        engine
            .get_account(&holder)
            .await
            .expect("holder exists")
            .balance,
        TOTAL_SUPPLY_CAP
    );

    // One nano past the cap: refused, and the refusal moves NOTHING.
    let newcomer = addr(0x12);
    let err = engine
        .mint_native(&newcomer, 1)
        .await
        .expect_err("one nano past the cap must fail closed");
    assert!(err.contains("global supply cap"), "unexpected error: {err}");
    assert_eq!(
        engine.total_minted_nano(),
        TOTAL_SUPPLY_CAP,
        "a refused mint must not consume headroom"
    );
    assert!(
        engine.get_account(&newcomer).await.is_none(),
        "a refused mint must not create the account"
    );

    // `credit_native` (the faucet / genesis / PMM mint entry point) is the
    // SAME capped primitive — no side door around the global counter.
    let err = engine
        .credit_native(&newcomer, 1)
        .await
        .expect_err("credit_native must also fail closed at the cap");
    assert!(err.contains("global supply cap"), "unexpected error: {err}");
    assert_eq!(engine.total_minted_nano(), TOTAL_SUPPLY_CAP);
}

#[tokio::test]
async fn transfer_near_the_cap_is_never_capped() {
    let engine = InMemoryStateEngine::new();
    let sender = addr(0x21);
    let recipient = addr(0x22);

    // Leave exactly 1 STELL of mint headroom.
    let minted = TOTAL_SUPPLY_CAP - STELL;
    engine.mint_native(&sender, minted).await.unwrap();
    assert_eq!(engine.remaining_mint_headroom_nano(), STELL);

    // A transfer near the cap moves value and does NOT touch the counter.
    engine
        .transfer_native(&sender, &recipient, STELL)
        .await
        .expect("a transfer near the cap must never be capped");
    assert_eq!(engine.total_minted_nano(), minted);
    assert_eq!(
        engine.get_account(&sender).await.unwrap().balance,
        TOTAL_SUPPLY_CAP - 2 * STELL
    );
    assert_eq!(engine.get_account(&recipient).await.unwrap().balance, STELL);

    // The credit half of a fee/refund (value already collected from a debit)
    // is uncapped too, even with ZERO headroom left.
    engine
        .credit_native_transfer(&recipient, STELL)
        .await
        .expect("crediting existing value must never be capped");
    assert_eq!(
        engine.get_account(&recipient).await.unwrap().balance,
        2 * STELL
    );
    assert_eq!(engine.total_minted_nano(), minted);

    // Fill the cap, then transfer again: still allowed.
    engine.mint_native(&sender, STELL).await.unwrap();
    assert_eq!(engine.remaining_mint_headroom_nano(), 0);
    engine
        .transfer_native(&sender, &recipient, STELL)
        .await
        .expect("a transfer at the exact cap must still work");
    assert_eq!(engine.total_minted_nano(), TOTAL_SUPPLY_CAP);

    // An unaffordable transfer is refused BEFORE either balance moves.
    let sender_before = engine.get_account(&sender).await.unwrap().balance;
    let recipient_before = engine.get_account(&recipient).await.unwrap().balance;
    let err = engine
        .transfer_native(&recipient, &sender, TOTAL_SUPPLY_CAP)
        .await
        .expect_err("over-balance transfer must fail closed");
    assert!(err.contains("Insufficient"), "unexpected error: {err}");
    assert_eq!(
        engine.get_account(&sender).await.unwrap().balance,
        sender_before,
        "a refused transfer must not debit"
    );
    assert_eq!(
        engine.get_account(&recipient).await.unwrap().balance,
        recipient_before,
        "a refused transfer must not credit"
    );
    assert_eq!(engine.total_minted_nano(), TOTAL_SUPPLY_CAP);
}

#[tokio::test]
async fn reward_minting_stops_exactly_at_the_cap() {
    let reward: u64 = STELL;
    // Prove the binding constraint is the GLOBAL cap, not the rewards pool
    // (350M) or the genesis vault (250M).
    assert!(reward < REWARDS_EMISSION_CAP);

    let engine = InMemoryStateEngine::new();
    let proposer_key = SigningKey::from_bytes(&[0x5A; 32]);
    let proposer = proposer_key.verifying_key().to_bytes();
    // Bonded proposer: `distribute_reward` refuses unknown/zero-stake ids, so
    // without this the transition would stop on the LEDGER leg and the test
    // would not exercise the native mint at all.
    engine
        .staking_write()
        .await
        .bond(proposer, required_bond_floor_nano(), 0)
        .expect("proposer must bond");

    // Pre-fill the mint counter so EXACTLY one block reward of headroom
    // remains. Every engine mint (rewards, faucet/`credit_native`, PMM buys)
    // shares this one counter — that is the whole point: local caps can be
    // respected per pool, this one bounds their sum.
    let filler = addr(0x31);
    engine
        .mint_native(&filler, TOTAL_SUPPLY_CAP - reward)
        .await
        .unwrap();
    assert_eq!(engine.remaining_mint_headroom_nano(), reward);

    // Block 1: the reward mint consumes the LAST of the headroom.
    engine
        .apply_block_transition(&empty_block(&proposer_key, 1), reward)
        .await;
    assert_eq!(
        engine.total_minted_nano(),
        TOTAL_SUPPLY_CAP,
        "the reward mint must land exactly on the cap"
    );
    {
        let ledger = engine.staking_read().await;
        assert_eq!(ledger.rewards_minted, reward);
        assert_eq!(ledger.rewards_pool, reward);
        assert_eq!(
            ledger.validators.get(&proposer).unwrap().pending_rewards,
            reward
        );
    }
    let pool_balance_at_cap = engine
        .get_account(&REWARDS_POOL)
        .await
        .expect("rewards pool backing account exists")
        .balance;
    assert_eq!(pool_balance_at_cap, reward);

    // Block 2: the ledger leg would accept (350M pool, only 1 STELL minted),
    // but the engine reserves global headroom BEFORE distributing, so the
    // transition stops without touching the ledger at all: no reward
    // accounting exists without 1:1 native backing.
    engine
        .apply_block_transition(&empty_block(&proposer_key, 2), reward)
        .await;
    assert_eq!(
        engine.total_minted_nano(),
        TOTAL_SUPPLY_CAP,
        "no mint may pass the cap"
    );
    {
        let ledger = engine.staking_read().await;
        assert_eq!(ledger.rewards_minted, reward, "rewards counter unchanged");
        assert_eq!(ledger.rewards_pool, reward, "rewards pool unchanged");
        assert_eq!(
            ledger.validators.get(&proposer).unwrap().pending_rewards,
            reward,
            "no second pending reward was split"
        );
    }
    assert_eq!(
        engine.get_account(&REWARDS_POOL).await.unwrap().balance,
        reward,
        "rewards backing account balances the ledger exactly"
    );
}

#[tokio::test]
async fn counter_is_monotone_across_mints_burns_and_refusals() {
    let engine = InMemoryStateEngine::new();
    let holder = addr(0x41);

    assert_eq!(engine.total_minted_nano(), 0);
    engine.mint_native(&holder, 10).await.unwrap();
    assert_eq!(engine.total_minted_nano(), 10);
    engine.mint_native(&holder, 20).await.unwrap();
    assert_eq!(engine.total_minted_nano(), 30);

    // A burn is NOT a headroom refund: gross lifetime minting stays monotone.
    engine.debit_native(&holder, 25).await.unwrap();
    assert_eq!(
        engine.total_minted_nano(),
        30,
        "burning must not restore mint headroom"
    );
    assert_eq!(engine.get_account(&holder).await.unwrap().balance, 5);
    assert_eq!(
        engine.remaining_mint_headroom_nano(),
        TOTAL_SUPPLY_CAP - 30,
        "headroom is cap - gross minted, never cap - current balance"
    );

    // A refused mint leaves the counter exactly where it was.
    assert!(engine.mint_native(&holder, TOTAL_SUPPLY_CAP).await.is_err());
    assert_eq!(engine.total_minted_nano(), 30);

    // A zero mint is a no-op (no account, no counter movement).
    engine.mint_native(&addr(0x42), 0).await.unwrap();
    assert_eq!(engine.total_minted_nano(), 30);
    assert!(engine.get_account(&addr(0x42)).await.is_none());
}

#[tokio::test]
async fn failed_balance_credit_releases_the_reservation() {
    let engine = InMemoryStateEngine::new();
    // Take the genesis-baseline fold FIRST (it happens only on the `0 -> x`
    // counter transition, and it sums the current balances). This test is
    // about the reservation/credit split, so start from a clean non-zero
    // counter and a saturated account that is NOT pre-minted supply.
    engine.mint_native(&addr(0x60), 1).await.unwrap();
    assert_eq!(engine.total_minted_nano(), 1);
    // A balance one nano below u64::MAX: the account credit overflows, but
    // only AFTER the global reservation succeeded. The reservation must be
    // released, or a failed mint would permanently burn headroom.
    let saturated = addr(0x61);
    engine
        .update_account(AccountState::new(saturated, u64::MAX))
        .await;
    let err = engine
        .mint_native(&saturated, 1)
        .await
        .expect_err("balance overflow must fail closed");
    assert!(err.contains("native overflow"), "unexpected error: {err}");
    assert_eq!(
        engine.total_minted_nano(),
        1,
        "a failed credit must release the reservation"
    );
    assert_eq!(engine.remaining_mint_headroom_nano(), TOTAL_SUPPLY_CAP - 1);

    // The remaining cap stays mintable: nothing was leaked.
    engine
        .mint_native(&addr(0x62), TOTAL_SUPPLY_CAP - 1)
        .await
        .expect("no headroom may be lost to a failed credit");
    assert_eq!(engine.total_minted_nano(), TOTAL_SUPPLY_CAP);
}

#[tokio::test]
async fn snapshot_restore_rebases_counter_to_restored_supply() {
    let source = InMemoryStateEngine::new();
    let holder = addr(0x51);
    source.mint_native(&holder, 5 * STELL).await.unwrap();
    assert_eq!(source.total_minted_nano(), 5 * STELL);
    let snapshot = source.create_snapshot().await;

    let restored = InMemoryStateEngine::new();
    assert_eq!(restored.total_minted_nano(), 0);
    restored.restore_snapshot(&snapshot).await.expect("restore");
    assert_eq!(
        restored.total_minted_nano(),
        5 * STELL,
        "a restored node's counter is the restored supply, not zero"
    );
    assert_eq!(
        restored.remaining_mint_headroom_nano(),
        TOTAL_SUPPLY_CAP - 5 * STELL
    );

    // The whole point: a restarted node cannot mint a SECOND full cap on top
    // of the state it just loaded.
    let newcomer = addr(0x52);
    assert!(restored
        .mint_native(&newcomer, TOTAL_SUPPLY_CAP)
        .await
        .is_err());
    restored
        .mint_native(&newcomer, TOTAL_SUPPLY_CAP - 5 * STELL)
        .await
        .expect("exactly the remaining headroom still mints");
    assert_eq!(restored.total_minted_nano(), TOTAL_SUPPLY_CAP);
}

/// The minted-supply scalar is COMMITTED: two engines that differ only in how
/// much they minted must NOT report the same state root, and a chain that has
/// minted nothing keeps the pinned genesis root.
#[tokio::test]
async fn minted_supply_moves_the_state_root() {
    use stellereum::state_engine::InMemoryStateEngine;

    let a = InMemoryStateEngine::new();
    let b = InMemoryStateEngine::new();
    assert_eq!(a.get_state_root().await, b.get_state_root().await);

    let who = [0x5Au8; 32];
    a.credit_native(&who, 1_000).await.expect("mint under cap");
    let ra = a.get_state_root().await;
    let rb = b.get_state_root().await;
    assert_ne!(
        ra, rb,
        "a minted balance and an empty engine must not share a root"
    );

    // A pure transfer does not change minted supply, so the counter term is
    // identical: the roots differ only because of the balance move below.
    let other = [0x5Bu8; 32];
    a.transfer_native(&who, &other, 400)
        .await
        .expect("transfer");
    assert!(
        a.get_state_root().await != ra,
        "balances still move the root"
    );
}

/// WORKCHAIN BYPASS — PROOF OF THE KNOWN PER-ENGINE GAP (not a fix).
///
/// `total_minted_nano` is a field of ONE `InMemoryStateEngine`. A sharded node
/// runs one engine per shard/workchain, each with its own counter, so N shards
/// can each mint a full `TOTAL_SUPPLY_CAP`: the enforced ceiling is
/// `N * cap + N * pre-mined genesis`, not the chain-wide `cap`. This test
/// characterises the gap so it cannot regress silently into a claim that the
/// hard cap is global. Fixing it requires a CHAIN-WIDE supply registry (a
/// masterchain-owned counter every shard reserves against, i.e. cross-shard
/// protocol work), not another per-engine check; `node/` wiring is outside
/// this wave's scope.
#[tokio::test]
async fn per_engine_cap_is_not_a_chain_wide_cap_known_gap() {
    let shard_a = InMemoryStateEngine::new();
    let shard_b = InMemoryStateEngine::new();
    shard_a.enable_cross_shard();
    shard_b.enable_cross_shard();

    // Each engine accepts a FULL cap independently.
    shard_a
        .mint_native(&addr(0xA1), TOTAL_SUPPLY_CAP)
        .await
        .expect("shard A may mint to its own cap");
    shard_b
        .mint_native(&addr(0xB2), TOTAL_SUPPLY_CAP)
        .await
        .expect("shard B may mint to its own cap");

    assert_eq!(shard_a.total_minted_nano(), TOTAL_SUPPLY_CAP);
    assert_eq!(shard_b.total_minted_nano(), TOTAL_SUPPLY_CAP);
    let chain_total = shard_a.total_minted_nano() as u128 + shard_b.total_minted_nano() as u128;
    assert_eq!(
        chain_total,
        2 * TOTAL_SUPPLY_CAP as u128,
        "the two engines' minted supplies add up to TWICE the advertised cap: \
         TOTAL_SUPPLY_CAP currently bounds one engine, not the chain"
    );

    // Each engine still fails closed one nano past its OWN counter.
    assert!(shard_a.mint_native(&addr(0xA3), 1).await.is_err());
    assert!(shard_b.mint_native(&addr(0xB3), 1).await.is_err());
}
