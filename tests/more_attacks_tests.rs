//! Second wave of adversarial tests: consensus, orderbook, actor model,
//! privacy primitives, MEV threshold shares, tokenomics and sharding.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::crypto_privacy::{PedersenCommitment, StealthAddress, ViewingKey};
use stellereum::mev::MevPreemptionEngine;
use stellereum::orderbook::{OrderSide, OrderbookActor};
use stellereum::sharding::{Block, DynamicShardManager, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, ActorMessage, InMemoryStateEngine};
use stellereum::tokenomics::GenesisVault;
use stellereum::zkml::SessionKeyAuthorization;

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

// ============================================================================
// CONSENSUS: duplicate signatures must NOT fake a quorum.
// An attacker holding ONE validator key must not be able to produce quorum 3
// by signing the same block three times.
// ============================================================================
#[test]
fn consensus_duplicate_signatures_do_not_fake_quorum() {
    let attacker = SigningKey::generate(&mut OsRng);

    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0xAA; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1000,
        proposer: attacker.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };

    // Sign the SAME block three times with the SAME key
    block.sign_block(&attacker);
    block.sign_block(&attacker);
    block.sign_block(&attacker);
    assert_eq!(block.validator_signatures.len(), 3);

    // Quorum of 3 must NOT be satisfied by one distinct validator
    assert!(
        !block.verify_signatures(3),
        "one validator signing 3 times must NOT satisfy quorum 3 (fake quorum!)"
    );
    // Quorum of 1 is legitimately satisfied by that one validator
    assert!(block.verify_signatures(1));
}

// ============================================================================
// CONSENSUS: a block signature must not be replayable at another height
// ============================================================================
#[test]
fn consensus_block_signature_not_replayable_across_height() {
    let val = SigningKey::generate(&mut OsRng);
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 10,
        prev_hash: [0u8; 32],
        state_root: [1u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1000,
        proposer: val.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    block.sign_block(&val);
    assert!(block.verify_signatures(1));

    // Replay the same signatures onto a different height
    let mut replayed = block.clone();
    replayed.height = 11;
    assert!(
        !replayed.verify_signatures(1),
        "signature must be bound to block height"
    );
}

// ============================================================================
// ORDERBOOK: cancellation refunds exactly the unfilled amount, never the filled part
// ============================================================================
#[test]
fn orderbook_cancel_refunds_only_unfilled() {
    let mut book = OrderbookActor::new(1, 100);
    let maker = addr(1);
    let taker = addr(2);

    let (sell, _) = book.submit_order(maker, OrderSide::Sell, 100, 10, 0);
    let (_buy, trades) = book.submit_order(taker, OrderSide::Buy, 100, 4, 0);
    assert_eq!(trades.len(), 1);
    assert_eq!(trades[0].amount, 4);

    let cancelled = book.cancel_order(sell.order_id).unwrap();
    assert_eq!(cancelled.filled, 4);
    assert_eq!(
        cancelled.amount - cancelled.filled,
        6,
        "only 6 unfilled must be refunded"
    );
}

// ============================================================================
// ORDERBOOK: depth cap prevents unbounded order spam
// ============================================================================
#[test]
fn orderbook_depth_cap_enforced() {
    let mut book = OrderbookActor::new(1, 3); // max 3 price levels
    let trader = addr(1);
    for i in 0..20u64 {
        book.submit_order(trader, OrderSide::Buy, 100 + i, 10, 0);
    }
    let (bids, asks) = book.depth();
    assert!(bids <= 3, "bid depth must be capped at 3, got {bids}");
    assert!(asks <= 3);
}

// ============================================================================
// ORDERBOOK: zero-amount order is a harmless no-op (no state corruption)
// ============================================================================
#[test]
fn orderbook_zero_amount_noop() {
    let mut book = OrderbookActor::new(1, 100);
    let (_order, trades) = book.submit_order(addr(1), OrderSide::Buy, 100, 0, 0);
    assert!(trades.is_empty());
    assert_eq!(
        book.depth(),
        (0, 0),
        "zero-amount order must not enter the book"
    );
}

// ============================================================================
// GENESIS VAULT: cumulative cap cannot be exceeded by repeated deposits
// ============================================================================
#[test]
fn genesis_vault_cumulative_cap_enforced() {
    let mut vault = GenesisVault::new();
    // 62,500,000 USDT at $1.00 == exactly 250,000,000 STELL (the cap)
    let amount_micro = 62_500_000u64 * 1_000_000;
    let minted = vault
        .deposit_and_mint("USDT", amount_micro, 1_000_000)
        .unwrap();
    assert_eq!(minted, 250_000_000u64 * 1_000_000_000);

    // Any further deposit must be rejected
    assert!(
        vault
            .deposit_and_mint("USDT", 1_000_000, 1_000_000)
            .is_err(),
        "cap must not be exceeded"
    );
}

// ============================================================================
// GENESIS VAULT: unsupported assets rejected
// ============================================================================
#[test]
fn genesis_vault_unsupported_asset_rejected() {
    let mut vault = GenesisVault::new();
    assert!(vault
        .deposit_and_mint("BTC", 1_000_000, 60_000_000_000)
        .is_err());
    assert!(vault.deposit_and_mint("DOGE", 1_000_000, 100_000).is_err());
}

// ============================================================================
// SESSION KEYS: budget and expiry boundaries are exact
// ============================================================================
#[test]
fn session_key_budget_and_expiry_boundaries() {
    let master = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng);
    let session_pub = session.verifying_key().to_bytes();
    let valid_until = 4_000_000_000u64; // far future (still > now_secs)
    let mut auth = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        valid_until,
        1_000,
        stellereum::zkml::SCOPE_ALL,
        u64::MAX,
        0,
    );

    // Spend exactly the budget
    assert!(auth.verify_and_spend_gas(1_000, 1_000).is_ok());
    // Any further spend exceeds the budget
    assert!(
        auth.verify_and_spend_gas(1, 1_000).is_err(),
        "budget must not be exceeded"
    );

    // Fresh key: expired exactly one second after valid_until
    let mut auth2 = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        valid_until,
        1_000,
        stellereum::zkml::SCOPE_ALL,
        u64::MAX,
        0,
    );
    assert!(
        auth2.verify_and_spend_gas(10, valid_until).is_ok(),
        "valid at the boundary"
    );
    assert!(
        auth2.verify_and_spend_gas(10, valid_until + 1).is_err(),
        "expired one second later"
    );
}

// ============================================================================
// ACTOR MODEL: bounce storm terminates and conserves total value
// ============================================================================
#[tokio::test]
async fn actor_bounce_storm_terminates_and_conserves() {
    let engine = InMemoryStateEngine::new();
    let a = addr(1);
    let b = addr(2);
    engine.update_account(AccountState::new(a, 100_000)).await;
    engine.update_account(AccountState::new(b, 100_000)).await;

    // Fire many messages at a non-existent recipient with bounce enabled
    for _ in 0..500 {
        let msg = ActorMessage::new(a, addr(250), 100, b"x".to_vec(), true);
        engine.send_message(msg).await.unwrap();
    }

    // Drain inboxes a bounded number of steps
    for _ in 0..10 {
        let _ = engine.step_actor_execution().await.unwrap();
    }

    let total = engine.get_account(&a).await.unwrap().balance
        + engine.get_account(&b).await.unwrap().balance;
    assert_eq!(
        total, 200_000,
        "bounced funds must be conserved (no inflation/loss)"
    );
}

// ============================================================================
// ACTOR MODEL: message to a non-existent actor without bounce is dropped safely
// ============================================================================
#[tokio::test]
async fn actor_message_no_bounce_drops_safely() {
    let engine = InMemoryStateEngine::new();
    let a = addr(1);
    engine.update_account(AccountState::new(a, 1_000)).await;

    let msg = ActorMessage::new(a, addr(250), 500, b"x".to_vec(), false);
    engine.send_message(msg).await.unwrap();
    // Sender balance is debited; funds are not stuck in a phantom inbox
    let acc = engine.get_account(&a).await.unwrap();
    assert_eq!(acc.balance, 500);
}

// ============================================================================
// ACTOR MODEL: message from a NON-EXISTENT sender must be rejected (free-mint fix)
// ============================================================================
#[tokio::test]
async fn actor_message_from_ghost_sender_rejected() {
    let engine = InMemoryStateEngine::new();
    let victim = addr(2);
    engine.update_account(AccountState::new(victim, 0)).await;

    // ghost sender is not in the state; sending value from it must fail
    let ghost = addr(200);
    let msg = ActorMessage::new(ghost, victim, 1_000_000, b"".to_vec(), false);
    assert!(
        engine.send_message(msg).await.is_err(),
        "message from non-existent sender must be rejected"
    );

    // even after an execution step the victim must NOT be credited
    let _ = engine.step_actor_execution().await;
    assert_eq!(
        engine.get_account(&victim).await.unwrap().balance,
        0,
        "ghost sender must not mint value for the recipient"
    );
}

// ============================================================================
// PRIVACY: Pedersen commitment rejects wrong value / wrong blinding
// ============================================================================
#[test]
fn pedersen_wrong_value_or_blinding_rejected() {
    let r1 = PedersenCommitment::random_blinding();
    let r2 = PedersenCommitment::random_blinding();
    let c = PedersenCommitment::commit(500, &r1);

    assert!(c.verify(500, &r1));
    assert!(!c.verify(501, &r1), "wrong value must fail");
    assert!(!c.verify(500, &r2), "wrong blinding must fail");
}

// ============================================================================
// PRIVACY: stealth address is only recognized by the true recipient
// ============================================================================
#[test]
fn stealth_address_wrong_recipient_rejected() {
    let view_priv = Scalar::random(&mut OsRng);
    let view_pub = (RISTRETTO_BASEPOINT_POINT * view_priv)
        .compress()
        .to_bytes();
    let spend_priv = Scalar::random(&mut OsRng);
    let spend_pub = (RISTRETTO_BASEPOINT_POINT * spend_priv)
        .compress()
        .to_bytes();

    let stealth = StealthAddress::generate(&view_pub, &spend_pub).unwrap();
    assert!(stealth.is_for_recipient(&view_priv, &spend_pub).unwrap());

    // A different viewer must not recognize it
    let other_view = Scalar::random(&mut OsRng);
    assert!(
        !stealth.is_for_recipient(&other_view, &spend_pub).unwrap(),
        "wrong viewer must not match"
    );
}

// ============================================================================
// PRIVACY: only the intended auditor can decrypt a viewing payload
// ============================================================================
#[test]
fn viewing_key_unauthorized_decrypt_rejected() {
    let auditor = ViewingKey::generate();
    let other = ViewingKey::generate();
    let blinding = PedersenCommitment::random_blinding();

    let payload =
        ViewingKey::encrypt_amount_for_auditor(&auditor.view_pub, 12_345, &blinding).unwrap();
    assert_eq!(auditor.decrypt_amount(&payload).unwrap().0, 12_345);

    // A different viewing key cannot decrypt
    assert!(
        other.decrypt_amount(&payload).is_err(),
        "unauthorized viewing key must fail"
    );
}

// ============================================================================
// MEV: a tampered threshold share prevents decryption (integrity of shares)
// ============================================================================
#[test]
fn mev_tampered_share_prevents_decryption() {
    let mut mev = MevPreemptionEngine::new();
    let (key, shares) = mev.prepare_threshold_round(1, 3, 5);
    let data = b"secret_hft_order";
    let env = MevPreemptionEngine::seal_transaction(1, &key, data).unwrap();

    let mut tampered = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
    tampered[0].share_lo[0] ^= 0xFF;

    assert!(
        mev.unseal_with_shares(&env, &tampered).is_err(),
        "a tampered share must not reconstruct a valid key"
    );

    // Genuine shares work
    let honest = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
    assert_eq!(mev.unseal_with_shares(&env, &honest).unwrap(), data);
}

// ============================================================================
// SHARDING: address routing after a split lands in a valid child shard
// ============================================================================
#[test]
fn sharding_routing_after_split() {
    let mut mgr = DynamicShardManager::new();
    mgr.record_tx_load(1, 600);
    let (c0, c1) = mgr.check_and_split(1).unwrap();
    assert_eq!(c0.prefix_len, 1);
    assert_eq!(c1.prefix_len, 1);

    // Route a bunch of addresses; each must map to a known shard
    for i in 0..50u8 {
        let mut a = [0u8; 32];
        a[0] = i;
        let sid = mgr.route_address(&a);
        assert!(
            mgr.shards.contains_key(&sid),
            "routed to unknown shard {sid}"
        );
    }
}

// ============================================================================
// STATE: a transfer creates the recipient account and conserves total balance
// ============================================================================
#[tokio::test]
async fn state_transfer_conserves_total_and_creates_account() {
    let engine = InMemoryStateEngine::new();
    let a = addr(1);
    let newbie = addr(200);
    engine.update_account(AccountState::new(a, 10_000)).await;

    let tx = Transaction {
        from: a,
        to: newbie,
        amount: 2_000,
        gas_limit: 0,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: vec![],
        payload: vec![],
        priority_fee_per_gas: 0,
    };
    // apply_transaction requires a valid signature; use a real signer instead
    let sk = SigningKey::generate(&mut OsRng);
    let a2 = sk.verifying_key().to_bytes();
    engine.update_account(AccountState::new(a2, 10_000)).await;
    let signed = Transaction::sign(&sk, newbie, 2_000, 0, 0, 1, 1);
    let _ = tx; // discard unsigned example

    engine.apply_transaction(&signed, 0).await.unwrap();
    let a_bal = engine.get_account(&a2).await.unwrap().balance;
    let n_bal = engine.get_account(&newbie).await.unwrap().balance;
    assert_eq!(a_bal, 8_000);
    assert_eq!(n_bal, 2_000);
    assert_eq!(a_bal + n_bal, 10_000, "native value must be conserved");
}
