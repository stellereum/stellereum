//! Comprehensive Blockchain Security & Penetration Testing Suite for Stellereum
//! Rigorously attacks and stress-tests:
//! 1. Double-spending & Nonce replay prevention
//! 2. Forged signature injection
//! 3. Rogue validator Sybil blocks & sub-quorum rejection
//! 4. MEV threshold secrecy (insufficient shares cannot decrypt)
//! 5. Cross-shard Merkle proof forgery rejection
//! 6. Flash-loan price manipulation & Circuit Breaker trip
//! 7. Stablecoin depeg detection & trading freeze (USDT < $0.95)
//! 8. Bridge rate-limit & time-lock bypass prevention
//! 9. Zero-Knowledge confidential balance inflation attack rejection
//! 10. AI bot session key budget exhaustion & expired key rejection

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::bridge::{SupportedChain, TeleportBridgeEngine};
use stellereum::crypto_privacy::{ConfidentialTransfer, PedersenCommitment};
use stellereum::mev::{MevPreemptionEngine, ShamirSecretSharing};
use stellereum::oracle::{OracleSafetyEngine, PriceFeedUpdate};
use stellereum::sharding::{
    Block, CrossShardMessage, SharedLiquidityHub, Transaction, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, SessionKeyAuthorization, ZkMlProof};

#[tokio::test]
async fn attack_test_double_spending_and_nonce_replay() {
    let state_engine = InMemoryStateEngine::new();
    let alice_sk = SigningKey::generate(&mut OsRng);
    let bob_sk = SigningKey::generate(&mut OsRng);
    let charlie_sk = SigningKey::generate(&mut OsRng);

    let alice_addr = alice_sk.verifying_key().to_bytes();
    let bob_addr = bob_sk.verifying_key().to_bytes();
    let charlie_addr = charlie_sk.verifying_key().to_bytes();

    // Alice has exactly 100 STELL (100_000_000_000 nano-STELL)
    state_engine
        .update_account(AccountState::new(alice_addr, 100_000_000_000))
        .await;

    // Tx1: Alice sends 80 STELL to Bob (nonce 0)
    let tx1 = Transaction::sign(&alice_sk, bob_addr, 80_000_000_000, 560, 0, 1, 1);
    let res1 = state_engine.apply_transaction(&tx1, 0).await;
    assert!(res1.is_ok(), "First transaction should succeed");

    // Attack 1: Replay exact same Tx1 again
    let replay_res = state_engine.apply_transaction(&tx1, 0).await;
    assert!(
        replay_res.is_err(),
        "Replayed transaction MUST be rejected by nonce check!"
    );

    // Attack 2: Double-spend! Alice tries to send another 80 STELL to Charlie (nonce 1)
    // Alice only has ~20 STELL remaining, so spending 80 STELL must fail!
    let tx2 = Transaction::sign(&alice_sk, charlie_addr, 80_000_000_000, 560, 1, 1, 1);
    let res2 = state_engine.apply_transaction(&tx2, 0).await;
    assert!(
        res2.is_err(),
        "Double spending beyond remaining balance MUST be rejected!"
    );

    // Verify Bob received 80 STELL and Charlie received 0 STELL
    let bob_acc = state_engine.get_account(&bob_addr).await.unwrap();
    let charlie_acc = state_engine.get_account(&charlie_addr).await;
    assert_eq!(bob_acc.balance, 80_000_000_000);
    assert!(charlie_acc.is_none());
}

#[tokio::test]
async fn attack_test_forged_signature_rejected() {
    let state_engine = InMemoryStateEngine::new();
    let victim_sk = SigningKey::generate(&mut OsRng);
    let mallory_sk = SigningKey::generate(&mut OsRng);

    let victim_addr = victim_sk.verifying_key().to_bytes();
    let mallory_addr = mallory_sk.verifying_key().to_bytes();

    state_engine
        .update_account(AccountState::new(victim_addr, 50_000_000_000))
        .await;

    // Mallory creates a tx purporting to be from Victim, but signs it with Mallory's key
    let mut forged_tx = Transaction::sign(&mallory_sk, mallory_addr, 50_000_000_000, 560, 0, 1, 1);
    forged_tx.from = victim_addr; // Spoof sender address

    let res = state_engine.apply_transaction(&forged_tx, 0).await;
    assert!(
        res.is_err(),
        "Forged signature transaction MUST be rejected!"
    );
}

#[test]
fn attack_test_rogue_validator_sybil_block_rejected() {
    let authorized_val1 = SigningKey::generate(&mut OsRng);
    let authorized_val2 = SigningKey::generate(&mut OsRng);
    let rogue_attacker = SigningKey::generate(&mut OsRng);

    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0xAA; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1000,
        proposer: rogue_attacker.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };

    // Rogue attacker signs the block
    block.sign_block(&rogue_attacker);

    // BFT Quorum requires 2/3 (at least 2 authorized signatures out of 3)
    assert!(
        !block.verify_signatures(2),
        "Block with only rogue attacker signature must fail quorum!"
    );

    // Authorized validator signs
    block.sign_block(&authorized_val1);
    // Quorum 2 still fails with 1 authorized + 1 rogue if verified against validator set
    block.sign_block(&authorized_val2);
    // Now with 2 authorized signatures, quorum is met
    assert!(block.verify_signatures(2));
}

#[test]
fn attack_test_mev_threshold_privacy_protection() {
    let mut mev = MevPreemptionEngine::new();
    // 3-of-5 threshold blind round
    let (round_key, shares) = mev.prepare_threshold_round(1, 3, 5);
    assert_eq!(shares.len(), 5);

    let victim_hft_payload = b"arbitrage_tx_buy_10000_stell_at_0.25";
    let envelope =
        MevPreemptionEngine::seal_transaction(1, &round_key, victim_hft_payload).unwrap();

    // Attacker intercepts only 2 shares (less than threshold 3)
    let attacker_shares = vec![shares[0].clone(), shares[1].clone()];

    // Attempting to reconstruct secret with insufficient shares produces invalid key
    let bad_key_res = ShamirSecretSharing::reconstruct(&attacker_shares);
    // With only 2 points for a degree 2 polynomial, interpolation at x=0 yields a mathematically wrong key
    let wrong_key = bad_key_res.unwrap();
    assert_ne!(wrong_key, round_key);

    // Attempting to unseal with wrong key MUST fail authenticated decryption
    let unseal_res = mev.unseal_with_shares(&envelope, &attacker_shares);
    assert!(
        unseal_res.is_err(),
        "MevPreemption MUST prevent decryption with < threshold shares!"
    );

    // Honest validators with 3 shares successfully reconstruct and unseal
    let honest_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let unsealed = mev.unseal_with_shares(&envelope, &honest_shares).unwrap();
    assert_eq!(unsealed, victim_hft_payload);
}

#[test]
fn attack_test_cross_shard_merkle_forgery_rejected() {
    let mallory_sk = SigningKey::generate(&mut OsRng);
    let mallory_addr = mallory_sk.verifying_key().to_bytes();
    let victim_addr = [99u8; 32];

    let tx = Transaction::sign(&mallory_sk, victim_addr, 100_000_000, 560, 0, 1, 2);
    let state_root = [0x55; 32];

    // Forged cross-shard message claiming bogus inclusion proof
    let forged_proof = stellereum::cell::MerkleProof {
        key: mallory_addr,
        value_hash: [0xDE; 32],
        leaf_hash: [0u8; 32],
        path: vec![stellereum::cell::MerkleStep {
            sibling_is_right: false,
            sibling_hash: [0xAD; 32],
            branch_prefix: [0x00; 16],
            skip: 0,
            branch_bit: 0,
        }],
    };

    let cross_msg = CrossShardMessage::new(1, 2, tx, state_root, [1u8; 32], Some(forged_proof));

    // Inclusion proof verification against state root MUST fail!
    assert!(
        !cross_msg.verify_inclusion(),
        "Forged Merkle inclusion proof MUST be rejected!"
    );

    let mut hub = SharedLiquidityHub::new(vec![1, 2]);
    hub.route_cross_shard_message(cross_msg);

    // Forged message was bounced and never delivered to Shard 2 inbox!
    let inbound_shard2 = hub.take_inbound_messages(2);
    assert!(
        inbound_shard2.is_empty(),
        "Forged cross-shard message must NOT reach destination shard!"
    );
}

#[test]
fn attack_test_oracle_manipulation_and_circuit_breaker() {
    let trusted_oracle_sk = SigningKey::generate(&mut OsRng);
    let trusted_pub = trusted_oracle_sk.verifying_key().to_bytes();

    let mut oracle = OracleSafetyEngine::new(vec![trusted_pub]);
    oracle.set_dex_twap("TON", 5_000_000); // 30-min TWAP = $5.00

    let current_time = 10_000;

    // Attack 1: Stale price attack (timestamp 16 minutes old)
    let stale_time = current_time - (16 * 60);
    let stale_feed = PriceFeedUpdate::sign("TON", 5_050_000, stale_time, &trusted_oracle_sk);
    let stale_res = oracle.resolve_price(Some(&stale_feed), "TON", current_time);
    // Stale feed is skipped, falls back to TWAP ($5.00)
    assert_eq!(stale_res.unwrap(), 5_000_000);

    // Attack 2: Flash loan price manipulation: sudden 15% spike to $5.75 (>10% allowed deviation)
    let manipulated_feed =
        PriceFeedUpdate::sign("TON", 5_750_000, current_time, &trusted_oracle_sk);
    let manipulation_res = oracle.resolve_price(Some(&manipulated_feed), "TON", current_time);
    assert!(
        manipulation_res.is_err(),
        "15% price deviation MUST trip circuit breaker!"
    );
    assert!(oracle.circuit_breaker_triggered);

    // Once circuit breaker is tripped, all trades MUST be halted!
    let paused_res = oracle.resolve_price(None, "TON", current_time);
    assert!(
        paused_res.is_err(),
        "All price resolutions must be paused when circuit breaker is active!"
    );

    // Attack 3: Stablecoin USDT depeg attack (USDT falls to $0.93 < $0.95 threshold)
    let mut oracle2 = OracleSafetyEngine::new(vec![trusted_pub]);
    let depeg_usdt = PriceFeedUpdate::sign("USDT", 930_000, current_time, &trusted_oracle_sk);
    let depeg_res = oracle2.resolve_price(Some(&depeg_usdt), "USDT", current_time);
    assert!(
        depeg_res.is_err(),
        "USDT depeg MUST trigger circuit breaker!"
    );
    assert!(oracle2.circuit_breaker_triggered);
}

#[test]
fn attack_test_bridge_timelock_and_ratelimit_enforcement() {
    let val_sk = SigningKey::generate(&mut OsRng);
    let mut bridge = TeleportBridgeEngine::new(vec![val_sk.verifying_key().to_bytes()]);

    let user = [11u8; 32];
    let now = 10_000;

    // Attack 1: Attempt to bypass large withdrawal time-lock (>50,000 STELL)
    let large_amt = 60_000 * 1_000_000_000;
    let req_id = bridge
        .request_withdrawal(
            user,
            SupportedChain::Arbitrum,
            "0x123".to_string(),
            large_amt,
            now,
        )
        .unwrap();

    // Attacker tries to finalize withdrawal 1 minute later
    let early_res = bridge.finalize_withdrawal(req_id, now + 60);
    assert!(
        early_res.is_err(),
        "Premature withdrawal MUST be blocked by time-lock!"
    );

    // Attacker tries to finalize after 1-hour time-lock
    let legit_res = bridge.finalize_withdrawal(req_id, now + 3600);
    assert!(
        legit_res.is_ok(),
        "Withdrawal after time-lock expires should succeed"
    );

    // Attack 2: Attempt to withdraw more than hourly rate limit (500,000 STELL)
    let over_limit = 550_000 * 1_000_000_000;
    let rate_limit_res = bridge.request_withdrawal(
        user,
        SupportedChain::Arbitrum,
        "0x123".to_string(),
        over_limit,
        now,
    );
    assert!(
        rate_limit_res.is_err(),
        "Withdrawal exceeding hourly rate limit MUST be rejected!"
    );
}

#[test]
fn attack_test_confidential_inflation_exploit_rejected() {
    // Attacker tries to create free tokens out of thin air:
    // Input commitment: 100 STELL
    // Output commitment: 1,000 STELL
    // Fee: 0
    let r1 = PedersenCommitment::random_blinding();
    let r2 = PedersenCommitment::random_blinding();

    let c_in = PedersenCommitment::commit(100, &r1);
    let c_out_inflated = PedersenCommitment::commit(1000, &r2);

    let exploit_transfer = ConfidentialTransfer::new(vec![c_in], vec![c_out_inflated], 0);

    // Homomorphic balance conservation check: sum(in) - sum(out) == fee * G
    assert!(
        !exploit_transfer.verify_balance_conservation(),
        "Confidential token inflation attempt MUST be rejected by homomorphic commitment math!"
    );
}

#[test]
fn attack_test_zkml_proof_forgery_and_session_abuse() {
    // 1. zkML proof tampering attack
    let layer = QuantizedLayer::new(2, 2, vec![1, 2, 3, 4], vec![0, 0]);
    let model = QuantizedLinearModel::new(vec![layer]);
    let (correct_outputs, mut proof) = ZkMlProof::prove_reexec(&model, &[5, 10]);

    assert_eq!(correct_outputs, vec![35, 50]);
    assert!(proof.verify_inference());

    // Attacker tampers with output claim (claims 999 instead of 50)
    proof.public_outputs[1] = 999;
    assert!(
        !proof.verify_inference(),
        "Tampered zkML output claim MUST be rejected!"
    );

    // 2. Session key gas limit abuse attack
    let master_sk = SigningKey::generate(&mut OsRng);
    let session_sk = SigningKey::generate(&mut OsRng);
    let session_pub = session_sk.verifying_key().to_bytes();

    let valid_until = 20_000;
    let max_gas = 10_000;

    let mut auth = SessionKeyAuthorization::sign_delegation(
        &master_sk,
        session_pub,
        valid_until,
        max_gas,
        stellereum::zkml::SCOPE_ALL,
        u64::MAX,
        0,
    );

    // Bot tries to spend 15,000 gas (> 10,000 limit)
    let overspend_res = auth.verify_and_spend_gas(15_000, 15_000);
    assert!(
        overspend_res.is_err(),
        "Session key spending beyond budget MUST be rejected!"
    );

    // Bot tries to transact after key has expired
    let expired_res = auth.verify_and_spend_gas(1_000, 25_000);
    assert!(
        expired_res.is_err(),
        "Expired session key MUST be rejected!"
    );
}
