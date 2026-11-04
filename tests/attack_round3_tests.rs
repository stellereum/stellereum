//! Round 3: remaining historical attack classes and suspicious code paths.
//! Covers: zero-quorum footgun, routing to inactive shards, bridge cumulative
//! rate-limit, orderbook FIFO/conservation, MEV cross-round shares, trie
//! non-inclusion, session-key cross-master replay, deserialization length bombs,
//! state-root consistency after many ops, and genesis vault edge cases.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::bridge::{SupportedChain, TeleportBridgeEngine};
use stellereum::cell::PatriciaTrie;
use stellereum::mev::MevPreemptionEngine;
use stellereum::orderbook::{OrderSide, OrderbookActor};
use stellereum::sharding::{
    Block, CrossShardMessage, SharedLiquidityHub, Transaction, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{token_balance_key, InMemoryStateEngine};
use stellereum::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};
use stellereum::tokenomics::GenesisVault;
use stellereum::zkml::SessionKeyAuthorization;

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

fn meta(name: &str, symbol: &str) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

// ============================================================================
// CONSENSUS FOOTGUN: a zero required-quorum must never accept an unsigned block.
// ============================================================================
#[test]
fn consensus_zero_quorum_must_not_accept_unsigned_block() {
    let block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 0,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    assert!(
        !block.verify_signatures(0),
        "an unsigned block must NEVER pass a zero quorum (footgun)"
    );
}

// ============================================================================
// ROUTING: a cross-shard message to an inactive/unknown shard must not be queued.
// ============================================================================
#[test]
fn cross_shard_to_inactive_shard_not_queued() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 999);
    let msg = CrossShardMessage::new_trusted(1, 999, tx, [0u8; 32], [0u8; 32]);

    let mut hub = SharedLiquidityHub::new(vec![1, 2]); // shard 999 does not exist
    let _seq = hub.route_cross_shard_message(msg);
    assert!(
        hub.take_inbound_messages(999).is_empty(),
        "must not be queued to a phantom shard"
    );
}

// ============================================================================
// BRIDGE: the hourly rate limit is cumulative across many requests.
// ============================================================================
#[test]
fn bridge_cumulative_rate_limit() {
    let v = SigningKey::generate(&mut OsRng);
    let mut bridge = TeleportBridgeEngine::new(vec![v.verifying_key().to_bytes()]);
    let now = 10_000u64;
    let each = 100_000u64 * 1_000_000_000; // 100k STELL each

    // 5 x 100k = 500k == hourly limit
    for _ in 0..5 {
        bridge
            .request_withdrawal(
                addr(1),
                SupportedChain::Arbitrum,
                "0xabc".to_string(),
                each,
                now,
            )
            .unwrap();
    }
    // The 6th exceeds the hourly cap
    assert!(
        bridge
            .request_withdrawal(
                addr(1),
                SupportedChain::Arbitrum,
                "0xabc".to_string(),
                each,
                now
            )
            .is_err(),
        "cumulative hourly rate limit must be enforced"
    );
}

// ============================================================================
// ORDERBOOK: price-time priority (FIFO within a price level)
// ============================================================================
#[test]
fn orderbook_fifo_price_time_priority() {
    let mut book = OrderbookActor::new(1, 100);
    let (s1, _) = book.submit_order(addr(1), OrderSide::Sell, 100, 5, 1);
    let (_s2, _) = book.submit_order(addr(2), OrderSide::Sell, 100, 5, 2);
    let (_buy, trades) = book.submit_order(addr(3), OrderSide::Buy, 100, 5, 3);
    assert_eq!(trades.len(), 1);
    assert_eq!(
        trades[0].maker_order_id, s1.order_id,
        "earlier order must fill first (FIFO)"
    );
}

// ============================================================================
// ORDERBOOK: trade amounts conserve (maker fill == taker fill == trade amount)
// ============================================================================
#[test]
fn orderbook_trade_amount_conservation() {
    let mut book = OrderbookActor::new(1, 100);
    let (sell, _) = book.submit_order(addr(1), OrderSide::Sell, 100, 10, 1);
    let (buy, trades) = book.submit_order(addr(2), OrderSide::Buy, 100, 4, 2);

    let total: u64 = trades.iter().map(|t| t.amount).sum();
    assert_eq!(total, 4);
    assert_eq!(sell.filled, 0, "the returned order snapshot is pre-fill");
    assert_eq!(buy.filled, 4);
    // Conservation: sum of maker fills == sum of taker fills
    let maker_fills: u64 = trades.iter().map(|t| t.amount).sum();
    assert_eq!(maker_fills, buy.filled);
}

// ============================================================================
// MEV: threshold shares from a different round must not decrypt this round
// ============================================================================
#[test]
fn mev_cross_round_shares_rejected() {
    let mut mev = MevPreemptionEngine::new();
    let (key1, _shares1) = mev.prepare_threshold_round(1, 3, 5);
    let (_key2, shares2) = mev.prepare_threshold_round(2, 3, 5);

    let data = b"round1_secret";
    let env = MevPreemptionEngine::seal_transaction(1, &key1, data).unwrap();

    let mixed = vec![shares2[0].clone(), shares2[1].clone(), shares2[2].clone()];
    assert!(
        mev.unseal_with_shares(&env, &mixed).is_err(),
        "shares from another round must not decrypt"
    );
}

// ============================================================================
// TRIE: non-inclusion returns None (no proof for a missing key)
// ============================================================================
#[test]
fn trie_non_inclusion_returns_none() {
    let mut trie = PatriciaTrie::new();
    assert!(
        trie.generate_merkle_proof(&addr(1)).is_none(),
        "empty trie has no proofs"
    );

    trie.insert(&addr(1), b"v1");
    assert!(trie.generate_merkle_proof(&addr(1)).is_some());
    assert!(
        trie.generate_merkle_proof(&addr(2)).is_none(),
        "missing key must yield no proof"
    );
}

// ============================================================================
// SESSION KEY: a delegation is bound to its master; cannot be replayed for another
// ============================================================================
#[test]
fn session_key_cross_master_replay_rejected() {
    let master = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng);
    let session_pub = session.verifying_key().to_bytes();
    let mut auth = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        4_000_000_000,
        1_000,
        stellereum::zkml::SCOPE_ALL,
        u64::MAX,
        0,
    );
    assert!(auth.verify());

    // Tamper the master address -> signature no longer matches
    auth.master_address = addr(0xAB);
    assert!(
        !auth.verify(),
        "delegation must be bound to the master address"
    );
}

// ============================================================================
// DESERIALIZATION: a crafted huge length prefix must not OOM/panic
// ============================================================================
#[test]
fn deserialization_length_bomb_safe() {
    // Transaction layout: from(32) to(32) amount(8) gas(8) nonce(8) src(4) dst(4)
    // then signature Vec length (u64 LE) followed by (missing) data.
    let mut bytes = vec![0u8; 32 + 32 + 8 + 8 + 8 + 4 + 4];
    bytes.extend_from_slice(&u64::MAX.to_le_bytes()); // signature length = huge
    let res = bincode::deserialize::<Transaction>(&bytes);
    assert!(
        res.is_err(),
        "length bomb must fail gracefully, not allocate/OOM"
    );
}

// ============================================================================
// STATE ROOT: after many token ops, SPV proofs for a holder still verify
// ============================================================================
#[tokio::test]
async fn token_state_root_consistent_after_many_ops() {
    let engine = InMemoryStateEngine::new();
    let a = addr(1);
    let b = addr(2);
    let id = engine
        .create_token(a, meta("T", "T"), 1_000_000)
        .await
        .unwrap();

    for i in 0..51u64 {
        if i % 2 == 0 {
            engine
                .token_execute(
                    &id,
                    a,
                    TokenOp::Transfer {
                        to: b,
                        amount: 1_000,
                    },
                )
                .await
                .unwrap();
        } else {
            engine
                .token_execute(
                    &id,
                    b,
                    TokenOp::Transfer {
                        to: a,
                        amount: 1_000,
                    },
                )
                .await
                .unwrap();
        }
    }
    let root = engine.get_state_root().await;
    let bal = engine.token_balance(&id, &b).await;
    let key = token_balance_key(&id, &b);
    let proof = engine.get_token_balance_proof(&id, &b).await.unwrap();
    assert!(
        PatriciaTrie::verify_merkle_proof(&root, &key, &bal.to_be_bytes(), &proof),
        "SPV proof must hold after many operations"
    );
    assert_eq!(
        engine.token_total_supply(&id).await,
        Some(1_000_000),
        "supply conserved"
    );
}

// ============================================================================
// GENESIS VAULT: zero deposit mints nothing (no free money)
// ============================================================================
#[test]
fn genesis_vault_zero_deposit_mints_nothing() {
    let mut vault = GenesisVault::new();
    let minted = vault.deposit_and_mint("USDT", 0, 1_000_000).unwrap();
    assert_eq!(minted, 0, "zero deposit must mint zero");
    assert_eq!(vault.total_minted_nano, 0);
}

// ============================================================================
// STATE: duplicate application of the same signed tx is rejected (nonce)
// ============================================================================
#[tokio::test]
async fn duplicate_signed_tx_rejected() {
    let engine = InMemoryStateEngine::new();
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let to = addr(2);
    engine
        .update_account(stellereum::state_engine::AccountState::new(from, 10_000))
        .await;

    let tx = Transaction::sign(&sk, to, 1_000, 0, 0, 1, 1);
    assert!(engine.apply_transaction(&tx, 0).await.is_ok());
    // Same tx again -> nonce already advanced
    assert!(
        engine.apply_transaction(&tx, 0).await.is_err(),
        "duplicate tx must be rejected"
    );
}
