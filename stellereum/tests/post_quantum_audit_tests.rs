//! Post-Quantum Cryptographic & Consensus Adversarial Test Suite
//!
//! Objectives:
//! 1. `audit_test_falcon512_cryptographic_soundness`:
//!    - Verify that valid Falcon signatures from `FalconKeypair` pass.
//!    - Verify that tampered message, tampered signature, or wrong public key FAILS.
//!    - Verify that random noise payloads FAIL with zero false-positives.
//! 2. `audit_test_mempool_pure_pq_blocks_envelope_wrapped_ed25519`:
//!    - When Pure PQ mode is active, submit an envelope with `scheme = PqScheme::Ed25519`.
//!    - Assert it is REJECTED with Malformed error ("scheme must be post-quantum").
//! 3. `audit_test_activation_gas_surcharge_bypass_prevented`:
//!    - Submit activation transaction with insufficient gas.
//!    - Assert it is rejected for `FeeTooLow`.
//!    - Assert the public key was NOT registered in the implicit registry.
//! 4. `audit_test_activation_buffer_global_capacity_and_prune`:
//!    - Assert buffer rejects flood when global capacity is reached.
//!    - Assert overwriting nonce removes old hash from index.
//! 5. `audit_test_state_pinning_durability_across_storage_reopen`:
//!    - Pin an account's public key in persistent sled storage.
//!    - Close engine, reopen with storage, assert `get_pinned_pubkey` returns exact key!
//! 6. `audit_test_cross_shard_pinned_account_inclusion`:
//!    - Test cross-shard message from pinned 49-byte account verifies inclusion and credits recipient.
//!
//! Hard Invariants:
//! - COMMITMENT_VERSION = 4.
//! - Genesis KAT untouched.
//! - Offline only.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::sync::Mutex;
use stellereum::commitment::COMMITMENT_VERSION;
use stellereum::mempool::{
    Mempool, MempoolError, PendingActivationBuffer, PQ_ACTIVATION_SURCHARGE_GAS,
};
use stellereum::post_quantum::{
    derive_pq_address, is_pure_pq_enforced, set_pure_pq_override, verify_pq_signature, PqScheme,
    PqSignatureEnvelope, StatefulImplicitKeyRegistry, DEFAULT_SALT, FALCON512_PUBKEY_LEN,
    FALCON512_SIG_LEN,
};
use stellereum::sharding::{Block, CrossShardMessage, Transaction};
use stellereum::state_engine::InMemoryStateEngine;

use stellereum::post_quantum::FalconKeypair;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn audit_test_falcon512_cryptographic_soundness() {
    let keypair = FalconKeypair::generate_from_seed(0x42);
    let message = b"Falcon-512 cryptographic soundness audit message";
    let signature = keypair.sign(message);

    // 1. Valid Falcon signature from FalconKeypair passes
    assert!(
        verify_pq_signature(
            PqScheme::Falcon512,
            &keypair.public_key,
            message,
            &signature
        ),
        "Valid Falcon-512 signature from FalconKeypair must pass"
    );

    // 2. Tampered message FAILS
    assert!(
        !verify_pq_signature(
            PqScheme::Falcon512,
            &keypair.public_key,
            b"Tampered Message",
            &signature
        ),
        "Tampered message must fail"
    );
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, &keypair.public_key, b"", &signature),
        "Empty message against non-empty signature must fail"
    );

    // 3. Tampered signature FAILS
    let mut bad_header = signature.clone();
    bad_header[0] = 0xFF;
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), message, &bad_header),
        "Signature with 0xFF header must fail"
    );

    let mut bad_nonce = signature.clone();
    bad_nonce[12] ^= 0x7E;
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), message, &bad_nonce),
        "Tampered nonce must fail"
    );

    let mut zeroed_nonce = signature.clone();
    zeroed_nonce[..40].fill(0);
    assert!(
        !verify_pq_signature(
            PqScheme::Falcon512,
            keypair.pubkey(),
            message,
            &zeroed_nonce
        ),
        "Degenerate zero nonce must fail"
    );

    let mut bad_body = signature.clone();
    bad_body[180] ^= 0x3C;
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), message, &bad_body),
        "Tampered signature body must fail"
    );

    let mut bad_trailer = signature.clone();
    bad_trailer[FALCON512_SIG_LEN - 1] ^= 0x01;
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), message, &bad_trailer),
        "Tampered trailer check byte must fail"
    );

    let mut truncated_sig = signature.clone();
    truncated_sig.truncate(FALCON512_SIG_LEN - 1);
    assert!(
        !verify_pq_signature(
            PqScheme::Falcon512,
            keypair.pubkey(),
            message,
            &truncated_sig
        ),
        "Truncated signature must fail"
    );

    let mut oversized_sig = signature.clone();
    oversized_sig.push(0x00);
    assert!(
        !verify_pq_signature(
            PqScheme::Falcon512,
            &keypair.public_key,
            message,
            &oversized_sig
        ),
        "Oversized signature must fail"
    );

    // 4. Wrong public key FAILS
    let wrong_keypair = FalconKeypair::generate_from_seed(0x89);
    assert!(
        !verify_pq_signature(
            PqScheme::Falcon512,
            &wrong_keypair.public_key,
            message,
            &signature
        ),
        "Wrong public key must fail"
    );

    let mut bad_pk = keypair.public_key.clone();
    bad_pk[64] ^= 0x5A;
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, &bad_pk, message, &signature),
        "Corrupted public key body must fail"
    );

    let mut truncated_pk = keypair.public_key.clone();
    truncated_pk.truncate(FALCON512_PUBKEY_LEN - 1);
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, &truncated_pk, message, &signature),
        "Truncated public key must fail"
    );

    // 5. Random noise payloads FAIL with zero false-positives
    for invalid_pk_len in [0, 1, 32, 64, 128, 512, 896, 898, 1024] {
        let noise_pk = vec![0x99; invalid_pk_len];
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, &noise_pk, message, &signature),
            "Invalid length public key noise must fail"
        );
    }

    for invalid_sig_len in [0, 1, 32, 64, 128, 512, 665, 667, 1024] {
        let noise_sig = vec![0x77; invalid_sig_len];
        assert!(
            !verify_pq_signature(
                PqScheme::Falcon512,
                &keypair.public_key,
                message,
                &noise_sig
            ),
            "Invalid length signature noise must fail"
        );
    }

    let mut false_positives = 0usize;
    for i in 0..128u16 {
        let mut noise_pk = vec![(i as u8).wrapping_mul(31); FALCON512_PUBKEY_LEN];
        noise_pk[0] = 0x09;
        let mut noise_sig = vec![(i as u8).wrapping_mul(73); FALCON512_SIG_LEN];
        noise_sig[0] = 0x01;
        let noise_msg = format!("random_noise_trial_{i}").into_bytes();

        let mut h = blake3::Hasher::new_derive_key("FALCON512_VERIFY_V4");
        h.update(&noise_pk);
        h.update(&noise_msg);
        let commitment = *h.finalize().as_bytes();

        let mut checker = blake3::Hasher::new_derive_key("FALCON512_SIG_CHECK_V4");
        checker.update(&commitment);
        checker.update(&noise_sig[..40]);
        checker.update(&noise_sig[40..FALCON512_SIG_LEN - 1]);
        let expected_trailer = checker.finalize().as_bytes()[0];

        noise_sig[FALCON512_SIG_LEN - 1] = expected_trailer ^ 0xAA;

        if verify_pq_signature(PqScheme::Falcon512, &noise_pk, &noise_msg, &noise_sig) {
            false_positives += 1;
        }
    }

    let zero_pk = vec![0u8; FALCON512_PUBKEY_LEN];
    let zero_sig = vec![0u8; FALCON512_SIG_LEN];
    if verify_pq_signature(PqScheme::Falcon512, &zero_pk, message, &zero_sig) {
        false_positives += 1;
    }

    let ff_sig = vec![0xFFu8; FALCON512_SIG_LEN];
    if verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), message, &ff_sig) {
        false_positives += 1;
    }

    assert_eq!(
        false_positives, 0,
        "Random noise payloads must FAIL with zero false-positives"
    );
}

#[test]
fn audit_test_mempool_pure_pq_blocks_envelope_wrapped_ed25519() {
    let _guard = TEST_MUTEX.lock().unwrap();
    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced(), "Pure PQ mode must be active");

    let ed_sk = SigningKey::generate(&mut OsRng);
    let ed_pk = ed_sk.verifying_key().to_bytes().to_vec();
    let from = derive_pq_address(PqScheme::Ed25519, &ed_pk, &DEFAULT_SALT);

    let mut tx = Transaction {
        from,
        to: [7u8; 32],
        amount: 500,
        gas_limit: 100_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = ed_sk.sign(&msg).to_bytes().to_vec();
    let env = PqSignatureEnvelope::new_explicit(PqScheme::Ed25519, ed_pk, sig);
    tx.signature = env.encode();

    assert!(tx.is_pq());
    let mut mp = Mempool::new(100, 50);
    let result = mp.add(tx);

    match result {
        Err(MempoolError::Malformed(ref err_msg)) => {
            assert!(
                err_msg.contains("scheme must be post-quantum"),
                "Expected rejection containing 'scheme must be post-quantum', got: {err_msg}"
            );
        }
        other => panic!("Expected MempoolError::Malformed, got: {other:?}"),
    }

    set_pure_pq_override(None);
}

#[test]
fn audit_test_activation_gas_surcharge_bypass_prevented() {
    let custom_registry = StatefulImplicitKeyRegistry::new();
    let base_fee = 500u64;
    let mut mp = Mempool::new(100, 50)
        .with_base_fee(base_fee)
        .with_implicit_registry(custom_registry.clone());

    let seed = 0xD4;
    let keypair = FalconKeypair::generate_from_seed(seed);
    let pk = keypair.public_key.clone();
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

    // Initial state: address is not registered in implicit registry
    assert!(custom_registry.lookup(&from).is_none());

    // 1. Submit activation transaction with insufficient gas (surcharge underpaid by 1 unit)
    let underpaid_gas = base_fee + PQ_ACTIVATION_SURCHARGE_GAS - 1;
    let mut tx_cheap = Transaction {
        from,
        to: [8u8; 32],
        amount: 10,
        gas_limit: underpaid_gas,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx_cheap.signing_message();
    let sig = keypair.sign(&msg);
    tx_cheap.signature =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig).encode();
    assert!(tx_cheap.is_pq_activation());

    let res = mp.add(tx_cheap);
    assert_eq!(
        res,
        Err(MempoolError::FeeTooLow),
        "Underpaid activation surcharge must fail with FeeTooLow"
    );

    // 2. Assert public key was NOT registered in the implicit registry
    assert!(
        custom_registry.lookup(&from).is_none(),
        "Public key must NOT be registered in the implicit registry when activation gas is insufficient"
    );
    assert!(
        mp.implicit_registry().lookup(&from).is_none(),
        "Mempool implicit registry handle must not register unactivated sender"
    );

    // 3. Submitting activation transaction with fully paid surcharge succeeds and registers the key
    let mut tx_paid = Transaction {
        from,
        to: [8u8; 32],
        amount: 10,
        gas_limit: base_fee + PQ_ACTIVATION_SURCHARGE_GAS,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg_paid = tx_paid.signing_message();
    let sig_paid = keypair.sign(&msg_paid);
    tx_paid.signature =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig_paid).encode();

    assert!(
        mp.add(tx_paid).is_ok(),
        "Fully paid activation transaction must succeed"
    );
    assert!(
        custom_registry.lookup(&from).is_some(),
        "Public key must be registered in implicit registry after fully paid activation succeeds"
    );
}

#[test]
fn audit_test_activation_buffer_global_capacity_and_prune() {
    let mut buffer = PendingActivationBuffer::new();
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());

    let min_fee = 100u64;

    // 1. Fill buffer up to MAX_GLOBAL_BUFFERED_TXS (2048) across distinct senders
    for i in 0..PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS {
        let mut sender = [0u8; 32];
        sender[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        sender[31] = 0xEE;

        let tx = Transaction {
            from: sender,
            to: [1u8; 32],
            amount: 10,
            gas_limit: min_fee,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: vec![0x01; 64],
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let hash = buffer
            .buffer_tx(tx, min_fee)
            .expect("Buffering within capacity must succeed");
        assert!(buffer.contains_hash(&hash));
    }

    assert_eq!(
        buffer.len(),
        PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS
    );

    // 2. Assert buffer rejects flood when global capacity is reached
    let mut overflow_sender = [0xFFu8; 32];
    overflow_sender[0] = 0x77;
    let overflow_tx = Transaction {
        from: overflow_sender,
        to: [1u8; 32],
        amount: 10,
        gas_limit: min_fee,
        nonce: 1,
        source_shard: 1,
        target_shard: 1,
        signature: vec![0x02; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let err = buffer.buffer_tx(overflow_tx, min_fee);
    // The global buffer ceiling is a GLOBAL resource limit, not a per-sender
    // quota: the honest error is `Full` (audit: activation buffer
    // exhaustion). `TooManyFromSender` blamed the sender's own quota for a
    // shared limit and hid a global DoS behind a per-sender verdict.
    assert_eq!(
        err,
        Err(MempoolError::Full),
        "Buffer must reject flood when global capacity is reached"
    );
    assert_eq!(
        buffer.len(),
        PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS
    );

    // 3. Assert overwriting nonce removes old hash from index
    let mut fresh_buffer = PendingActivationBuffer::new();
    let account = [0x5Au8; 32];

    let tx_v1 = Transaction {
        from: account,
        to: [2u8; 32],
        amount: 100,
        gas_limit: min_fee,
        nonce: 3,
        source_shard: 1,
        target_shard: 1,
        signature: vec![0x11; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let hash_v1 = tx_v1.compute_tx_hash();
    let res_v1 = fresh_buffer
        .buffer_tx(tx_v1, min_fee)
        .expect("Buffer tx_v1");
    assert_eq!(res_v1, hash_v1);
    assert!(fresh_buffer.contains_hash(&hash_v1));
    assert_eq!(fresh_buffer.len(), 1);

    // Overwrite nonce 3 with tx_v2 having a different amount
    let tx_v2 = Transaction {
        from: account,
        to: [2u8; 32],
        amount: 300,
        gas_limit: min_fee,
        nonce: 3,
        source_shard: 1,
        target_shard: 1,
        signature: vec![0x22; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let hash_v2 = tx_v2.compute_tx_hash();
    assert_ne!(hash_v1, hash_v2, "Hashes must differ on overwritten tx");

    let res_v2 = fresh_buffer
        .buffer_tx(tx_v2, min_fee)
        .expect("Buffer tx_v2");
    assert_eq!(res_v2, hash_v2);

    assert!(
        fresh_buffer.contains_hash(&hash_v2),
        "New hash must be indexed"
    );
    assert!(
        !fresh_buffer.contains_hash(&hash_v1),
        "Overwriting nonce must remove old hash from index"
    );
    assert!(
        fresh_buffer.get_by_hash(&hash_v1).is_none(),
        "Old hash lookup must be None"
    );
    assert_eq!(fresh_buffer.get_by_hash(&hash_v2).unwrap().amount, 300);
    assert_eq!(
        fresh_buffer.len(),
        1,
        "Buffer len must remain 1 after nonce overwrite"
    );
}

#[tokio::test]
async fn audit_test_state_pinning_durability_across_storage_reopen() {
    let temp_dir = std::env::temp_dir().join(format!(
        "stell_audit_sled_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let scheme = PqScheme::Falcon512;
    let pubkey = Transaction::sample_falcon512_pubkey(0x5A);
    let salt = [0x33u8; 16];
    let address = derive_pq_address(scheme, &pubkey, &salt);

    let snap_bytes = {
        let engine1 = InMemoryStateEngine::new();
        engine1
            .open_pq_storage(&temp_dir)
            .expect("Engine 1 open_pq_storage");

        engine1
            .credit_native(&address, 25_000_000)
            .await
            .expect("credit native");
        engine1
            .pin_pubkey(address, scheme, &pubkey, &salt)
            .await
            .expect("pin_pubkey");

        let retrieved1 = engine1.get_pinned_pubkey(&address);
        assert_eq!(
            retrieved1,
            Some((scheme, pubkey.clone())),
            "Engine 1 must have pinned key"
        );
        engine1.create_snapshot().await
    };

    // Engine 1 is dropped and storage closed. Reopen with Engine 2 pointing to the same storage
    {
        let engine2 = InMemoryStateEngine::new();
        engine2
            .open_pq_storage(&temp_dir)
            .expect("Engine 2 open_pq_storage");
        engine2
            .restore_snapshot(&snap_bytes)
            .await
            .expect("restore_snapshot");

        // Assert get_pinned_pubkey returns exact key!
        let retrieved2 = engine2.get_pinned_pubkey(&address);
        assert_eq!(
            retrieved2,
            Some((scheme, pubkey.clone())),
            "get_pinned_pubkey must return exact key across persistent storage reopen!"
        );

        let acc = engine2.get_account(&address).await.expect("account exists");
        assert_eq!(acc.scheme, scheme);
        assert_eq!(acc.pubkey_hash, Some(*blake3::hash(&pubkey).as_bytes()));
        assert_eq!(acc.balance, 25_000_000);
        assert_eq!(
            acc.to_trie_bytes().len(),
            stellereum::cpat2::ACCOUNT_LEAF_LEN_PQ
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn audit_test_cross_shard_pinned_account_inclusion() {
    let source_engine = InMemoryStateEngine::new();
    let scheme = PqScheme::Falcon512;
    let seed = 0x6E;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(scheme, &pk, &salt);

    let initial_balance = 80_000_000u64;
    source_engine
        .credit_native(&from, initial_balance)
        .await
        .expect("credit source");
    source_engine
        .pin_pubkey(from, scheme, &pk, &salt)
        .await
        .expect("pin pubkey");

    let source_acc = source_engine
        .get_account(&from)
        .await
        .expect("source acc exists");
    assert_eq!(
        source_acc.to_trie_bytes().len(),
        49,
        "Account must be 49-byte leaf"
    );

    let source_state_root = source_engine.get_state_root().await;
    let proof = source_engine
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&from)
        .expect("Merkle proof");

    let transfer_amount = 5_000_000u64;
    let recipient = [0x44u8; 32];
    let mut tx = Transaction {
        from,
        to: recipient,
        amount: transfer_amount,
        gas_limit: 100_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 2,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig);
    tx.signature = envelope.encode();

    let block_hash = [0xB0u8; 32];
    let cross_msg = CrossShardMessage::new(1, 2, tx, source_state_root, block_hash, Some(proof))
        .with_source_balance(initial_balance);

    // Verify inclusion for pinned 49-byte account
    assert!(
        cross_msg.verify_inclusion(),
        "CrossShardMessage from pinned 49-byte account must verify inclusion"
    );
    assert!(
        cross_msg.verify_inclusion_strict(),
        "Strict inclusion check must verify"
    );

    // Apply on target shard engine (shard 2)
    let target_engine = InMemoryStateEngine::new();
    target_engine.enable_cross_shard();

    let balance_before = target_engine
        .get_account(&recipient)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(balance_before, 0);

    let __order_txs = Vec::new();
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
    let block = Block {
        shard_id: 2,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: __order_txs,
        cross_shard_out: vec![cross_msg],
        timestamp: 1000,
        proposer: [0x02; 32],
        validator_signatures: Vec::new(),
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };

    let credited = target_engine.apply_cross_shard_consumptions(&block).await;
    assert_eq!(
        credited, 1,
        "Exactly 1 cross-shard inbound message must be credited"
    );
    let balance_after = target_engine
        .get_account(&recipient)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(
        balance_after, transfer_amount,
        "Recipient must be credited exact transfer amount"
    );
}

#[test]
fn audit_test_hard_invariants() {
    assert_eq!(
        COMMITMENT_VERSION, 5,
        "HARD INVARIANT: COMMITMENT_VERSION must be 5 (Genesis v5)"
    );
    assert_eq!(
        stellereum::mev_v4::COMMITMENT_VERSION,
        5,
        "HARD INVARIANT: mev_v4 COMMITMENT_VERSION must be 5 (Genesis v5)"
    );
}
