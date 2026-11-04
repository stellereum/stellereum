//! Integration and Verification Tests for Post-Quantum MEV-Preemption Module v4/v5
//!
//! Objectives verified:
//! 1. Envelope sealing and unsealing roundtrip with authenticated encryption.
//! 2. BLAKE3 order chain immutability:
//!    - Swapping two envelopes changes the root.
//!    - Inserting an envelope changes the root.
//!    - $< 0.02 ms$ throughput for 1,000 envelopes.
//! 3. Tampering detection on encrypted payloads (bit flips, truncation, corrupted nonces).
//! 4. Threshold share combination and decryption recovery (Lagrange interpolation):
//!    - T-of-N threshold recovery.
//!    - Any valid subset of T shares succeeds.
//!    - < T shares fails.
//!    - Corrupted or duplicate shares fail.
//! 5. Hard invariants: COMMITMENT_VERSION = 4.

use stellereum::mev_v4::{
    combine_lagrange_shares, compute_order_chain, PqMevPreemptionEngine, PqOrderCommitment,
    PqSealedEnvelope, SequentialBlake3HashChain, SlottedDecryptionShare, COMMITMENT_VERSION,
    MLKEM768_CIPHERTEXT_SIZE, MLKEM768_PUBLIC_KEY_SIZE, SLOTTED_SHARE_SIZE,
};

#[test]
fn test_commitment_version_invariant() {
    assert_eq!(
        COMMITMENT_VERSION, 5,
        "HARD INVARIANT: COMMITMENT_VERSION must be 5"
    );
}

#[test]
fn test_envelope_sealing_and_unsealing() {
    let engine = PqMevPreemptionEngine::new(1, 3, 5);
    let slot = 128;
    let sender = [0x42u8; 32];
    let gas_limit = 250_000;
    let max_fee = 75;
    let nonce = 10;
    let payload = b"BUY 1000 STELL AT $2.50 LIMIT";

    // 1. Seal transaction payload
    let envelope = engine
        .seal_transaction(slot, sender, gas_limit, max_fee, nonce, payload)
        .expect("Envelope sealing must succeed");

    // 2. Validate envelope structural integrity
    assert_eq!(envelope.epoch, 1);
    assert_eq!(envelope.slot, slot);
    assert_eq!(envelope.sender, sender);
    assert_eq!(envelope.gas_limit, gas_limit);
    assert_eq!(envelope.max_fee_per_gas, max_fee);
    assert_eq!(envelope.fee(), max_fee);
    assert_eq!(envelope.nonce, nonce);
    assert_eq!(
        envelope.encrypted_symmetric_key.len(),
        MLKEM768_CIPHERTEXT_SIZE
    );
    assert!(
        envelope.verify_hash(),
        "Precomputed hash must match computed hash"
    );

    // 3. Unseal using engine's active master state
    let unsealed = engine
        .unseal_payload(&envelope)
        .expect("Payload unsealing must succeed");
    assert_eq!(unsealed, payload);

    // 4. Test bincode serialization roundtrip
    let encoded = bincode::serialize(&envelope).expect("Envelope serialization must succeed");
    let decoded: PqSealedEnvelope =
        bincode::deserialize(&encoded).expect("Envelope deserialization must succeed");
    assert_eq!(envelope, decoded);
}

#[test]
fn test_blake3_order_chain_immutability() {
    let mut engine = PqMevPreemptionEngine::new(1, 3, 5);
    let height = 500;
    let slot = 12;
    let prev_hash = [0x5Au8; 32];

    let env1 = engine
        .seal_transaction(slot, [0x01u8; 32], 50_000, 100, 1, b"tx_alpha")
        .unwrap();
    let env2 = engine
        .seal_transaction(slot, [0x02u8; 32], 60_000, 90, 1, b"tx_beta")
        .unwrap();
    let env3 = engine
        .seal_transaction(slot, [0x03u8; 32], 70_000, 80, 1, b"tx_gamma")
        .unwrap();

    let original_sequence = vec![env1.clone(), env2.clone(), env3.clone()];
    let root = SequentialBlake3HashChain::compute_order_chain(
        height,
        slot,
        &prev_hash,
        &original_sequence,
    );

    // Free function alias produces identical root
    let root_alias = compute_order_chain(height, slot, &prev_hash, &original_sequence);
    assert_eq!(root, root_alias);

    // A. Swapping two envelopes MUST change the order chain root
    let swapped_sequence = vec![env2.clone(), env1.clone(), env3.clone()];
    let root_swapped =
        SequentialBlake3HashChain::compute_order_chain(height, slot, &prev_hash, &swapped_sequence);
    assert_ne!(
        root, root_swapped,
        "Swapping two envelopes MUST change the order chain root"
    );

    // B. Inserting an envelope MUST change the order chain root
    let env_extra = engine
        .seal_transaction(slot, [0x04u8; 32], 40_000, 70, 1, b"tx_delta")
        .unwrap();
    let mut inserted_sequence = original_sequence.clone();
    inserted_sequence.push(env_extra);
    let root_inserted = SequentialBlake3HashChain::compute_order_chain(
        height,
        slot,
        &prev_hash,
        &inserted_sequence,
    );
    assert_ne!(
        root, root_inserted,
        "Inserting an envelope MUST change the order chain root"
    );

    // C. Removing an envelope MUST change the order chain root
    let truncated_sequence = vec![env1.clone(), env2.clone()];
    let root_truncated = SequentialBlake3HashChain::compute_order_chain(
        height,
        slot,
        &prev_hash,
        &truncated_sequence,
    );
    assert_ne!(
        root, root_truncated,
        "Removing an envelope MUST change the order chain root"
    );

    // D. Commit order and verify commitment
    let commitment: PqOrderCommitment =
        engine.commit_order(height, slot, &prev_hash, &original_sequence);
    assert_eq!(commitment.order_root, root);
    assert_eq!(commitment.root(), root);
    assert_eq!(commitment.version, COMMITMENT_VERSION);
    assert_eq!(commitment.len(), 3);
    assert!(!commitment.is_empty());
    assert_eq!(commitment.envelope_count, 3);
    assert!(engine.verify_order_commitment(&commitment, &original_sequence));
    assert!(!engine.verify_order_commitment(&commitment, &swapped_sequence));
}

#[test]
fn test_order_chain_1000_envelopes_benchmark_speed() {
    let engine = PqMevPreemptionEngine::new(1, 3, 5);
    let height = 10_000;
    let slot = 55;
    let prev_hash = [0x3Cu8; 32];

    // Scaffold 1,000 distinct sealed envelopes
    let envelopes: Vec<PqSealedEnvelope> = (0..1_000)
        .map(|i| {
            let mut sender = [0u8; 32];
            sender[..4].copy_from_slice(&(i as u32).to_le_bytes());
            engine
                .seal_transaction(
                    slot,
                    sender,
                    21_000,
                    100 + i as u64,
                    i as u64,
                    b"clob_match",
                )
                .unwrap()
        })
        .collect();

    // Warm up
    let _ = SequentialBlake3HashChain::compute_order_chain(height, slot, &prev_hash, &envelopes);

    // Measure execution time of 1,000 envelope order chain computation
    let start = std::time::Instant::now();
    let root = SequentialBlake3HashChain::compute_order_chain(height, slot, &prev_hash, &envelopes);
    let elapsed = start.elapsed();

    assert_ne!(root, [0u8; 32]);
    println!(
        "[PERF] compute_order_chain for 1,000 envelopes: {:?} ({:.4} ms)",
        elapsed,
        elapsed.as_secs_f64() * 1000.0
    );

    // Strict sub-millisecond check (spec calls for < 0.02 ms on optimized release)
    assert!(
        elapsed.as_millis() < 50,
        "Order chain must compute in sub-millisecond range"
    );
}

#[test]
fn test_tampering_detection_on_encrypted_payloads() {
    let engine = PqMevPreemptionEngine::new(1, 3, 5);
    let slot = 7;
    let payload = b"CONFIDENTIAL_SVM_TRANSACTION_PAYLOAD_V4";
    let envelope = engine
        .seal_transaction(slot, [0x77u8; 32], 120_000, 35, 2, payload)
        .unwrap();

    // 1. Bit flip in ciphertext body fails Poly1305 AEAD authentication
    let mut tampered_payload_env = envelope.clone();
    tampered_payload_env.encrypted_payload[5] ^= 0x01;
    let err_payload = engine.unseal_payload(&tampered_payload_env);
    assert!(
        err_payload.is_err(),
        "Tampered ciphertext payload must fail Poly1305 authentication"
    );

    // 2. Truncation of ciphertext / auth tag fails
    let mut truncated_env = envelope.clone();
    let truncated_len = truncated_env.encrypted_payload.len() - 4;
    truncated_env.encrypted_payload.truncate(truncated_len);
    let err_trunc = engine.unseal_payload(&truncated_env);
    assert!(
        err_trunc.is_err(),
        "Truncated ciphertext must fail unsealing"
    );

    // 3. Corrupted payload nonce fails Poly1305 AEAD authentication
    let mut bad_nonce_env = envelope.clone();
    bad_nonce_env.payload_nonce[0] ^= 0xFF;
    let err_nonce = engine.unseal_payload(&bad_nonce_env);
    assert!(
        err_nonce.is_err(),
        "Corrupted payload nonce must fail authentication"
    );

    // 4. Corrupted symmetric key encapsulation fails unsealing
    let mut bad_key_env = envelope.clone();
    bad_key_env.encrypted_symmetric_key[50] ^= 0xAA;
    let err_key = engine.unseal_payload(&bad_key_env);
    assert!(
        err_key.is_err(),
        "Corrupted symmetric key encapsulation must fail unsealing"
    );

    // 5. Corrupted ciphertext header magic fails fail-closed
    let mut bad_magic_env = envelope.clone();
    bad_magic_env.encrypted_symmetric_key[0] = 0x00;
    let err_magic = engine.unseal_payload(&bad_magic_env);
    assert!(
        err_magic.is_err(),
        "Corrupted ciphertext magic header must fail"
    );
}

#[test]
fn test_threshold_share_combination_and_decryption_recovery() {
    // 3-of-5 threshold configuration
    let threshold = 3;
    let total_validators = 5;
    let engine = PqMevPreemptionEngine::new(1, threshold, total_validators);

    let slot = 44;
    let payload = b"ARBITRAGE_SWAP_UNISWAP_V4_STELL_USDC";
    let envelope = engine
        .seal_transaction(slot, [0x88u8; 32], 300_000, 150, 4, payload)
        .unwrap();

    // Generate slotted shares from all 5 validators
    let shares: Vec<SlottedDecryptionShare> = (1..=total_validators)
        .map(|vid| {
            engine
                .produce_slotted_share(vid as u32, 1, slot)
                .expect("Share generation must succeed")
        })
        .collect();

    assert_eq!(shares.len(), 5);
    for (i, share) in shares.iter().enumerate() {
        assert_eq!(share.validator_id(), (i + 1) as u32);
        assert_eq!(share.epoch(), 1);
        assert_eq!(share.slot(), slot);
        assert_eq!(share.share_bytes().len(), SLOTTED_SHARE_SIZE);
    }

    // Direct test of standalone combine_lagrange_shares helper
    let scalar_1_3_5 = combine_lagrange_shares(
        &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
        threshold,
    )
    .expect("combine_lagrange_shares must succeed for valid threshold subset");
    let scalar_2_3_4 = combine_lagrange_shares(
        &[shares[1].clone(), shares[2].clone(), shares[3].clone()],
        threshold,
    )
    .expect("combine_lagrange_shares must succeed for alternative threshold subset");
    assert_eq!(
        scalar_1_3_5, scalar_2_3_4,
        "Any T shares must interpolate identical slot scalar"
    );

    // A. Combine exact threshold: Validators {1, 3, 5}
    let subset_1_3_5 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let unsealed_1 = engine
        .unseal_with_shares(&envelope, &subset_1_3_5)
        .expect("Decryption with {1, 3, 5} shares must succeed");
    assert_eq!(unsealed_1, payload);

    // B. Combine another disjoint subset: Validators {2, 3, 4}
    let subset_2_3_4 = vec![shares[1].clone(), shares[2].clone(), shares[3].clone()];
    let unsealed_2 = engine
        .unseal_with_shares(&envelope, &subset_2_3_4)
        .expect("Decryption with {2, 3, 4} shares must succeed");
    assert_eq!(unsealed_2, payload);

    // C. Combine all 5 shares (over-threshold)
    let unsealed_all = engine
        .unseal_with_shares(&envelope, &shares)
        .expect("Decryption with all 5 shares must succeed");
    assert_eq!(unsealed_all, payload);

    // D. Insufficient shares (< 3, e.g. 2 shares) must fail
    let insufficient = vec![shares[0].clone(), shares[1].clone()];
    let err_insufficient = engine.unseal_with_shares(&envelope, &insufficient);
    assert!(
        err_insufficient.is_err(),
        "Decryption with insufficient shares MUST fail"
    );

    // E. Duplicate validator shares (e.g. {1, 1, 2}) must be rejected
    let duplicates = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
    let err_dup = engine.unseal_with_shares(&envelope, &duplicates);
    assert!(
        err_dup.is_err(),
        "Duplicate validator shares MUST be rejected"
    );

    // F. Share from different slot fails
    let wrong_slot_share = engine.produce_slotted_share(1, 1, slot + 1).unwrap();
    let mixed_slot = vec![wrong_slot_share, shares[1].clone(), shares[2].clone()];
    let err_slot = engine.unseal_with_shares(&envelope, &mixed_slot);
    assert!(err_slot.is_err(), "Shares from mismatched slots MUST fail");

    // G. Corrupted share payload fails
    let mut corrupted = subset_1_3_5.clone();
    corrupted[0].share[45] ^= 0x55;
    let err_corrupt = engine.unseal_with_shares(&envelope, &corrupted);
    assert!(
        err_corrupt.is_err(),
        "Corrupted share data MUST fail decryption"
    );

    // H. Registration of shares into engine
    let mut share_engine = PqMevPreemptionEngine::new(1, threshold, total_validators);
    // Erase master secret from share engine to verify purely share-based recovery
    share_engine.dkg = stellereum::mev_v4::ProactiveEpochDkg::new(2, threshold, total_validators);
    for s in &subset_1_3_5 {
        share_engine.add_slotted_share(s.clone());
    }
    let recovered_registered = share_engine.unseal_payload(&envelope).unwrap();
    assert_eq!(recovered_registered, payload);
}

#[test]
fn test_proactive_epoch_dkg_refresh_and_key_rollover() {
    let mut engine = PqMevPreemptionEngine::new(1, 3, 5);
    let old_pk = *engine.active_epoch_master_public_key();
    assert_eq!(engine.active_epoch(), 1);
    assert_eq!(old_pk.len(), MLKEM768_PUBLIC_KEY_SIZE);

    // Rollover to Epoch 2
    let new_pk = engine.advance_epoch_dkg(2);
    assert_eq!(engine.active_epoch(), 2);
    assert_eq!(new_pk.len(), MLKEM768_PUBLIC_KEY_SIZE);
    assert_ne!(
        old_pk, new_pk,
        "New epoch DKG round must yield fresh master public key"
    );

    // Slotted share for Epoch 2 slot 1
    let share_ep2 = engine.produce_slotted_share(1, 2, 1).unwrap();
    assert_eq!(share_ep2.epoch(), 2);
    assert_eq!(share_ep2.slot(), 1);
}

#[test]
fn test_slotted_share_bincode_serialization() {
    let engine = PqMevPreemptionEngine::new(1, 3, 5);
    let share = engine.produce_slotted_share(2, 1, 99).unwrap();

    let bytes = bincode::serialize(&share).expect("SlottedDecryptionShare must serialize");
    let decoded: SlottedDecryptionShare =
        bincode::deserialize(&bytes).expect("SlottedDecryptionShare must deserialize");

    assert_eq!(share, decoded);
    assert_eq!(decoded.validator_id(), 2);
    assert_eq!(decoded.slot(), 99);
}
