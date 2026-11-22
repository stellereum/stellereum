use super::*;
use crate::post_quantum::{derive_pq_address, PqScheme};
use crate::sharding::{PqSignatureEnvelope, Transaction};

#[tokio::test]
async fn test_dormant_account_activation_and_spend_pinned_pubkey() {
    let engine = InMemoryStateEngine::new();
    let scheme = PqScheme::Falcon512;
    let pubkey = vec![0x42u8; scheme.pubkey_size()];
    let salt = [0x01u8; 16];
    let address = derive_pq_address(scheme, &pubkey, &salt);

    // Phase 1: Dormant account receives funds
    engine.credit_native(&address, 10_000_000).await.unwrap();

    let acc_dormant = engine.get_account(&address).await.unwrap();
    assert_eq!(acc_dormant.balance, 10_000_000);
    assert_eq!(acc_dormant.nonce, 0);
    assert_eq!(acc_dormant.pubkey_hash, None);
    assert_eq!(
        acc_dormant.to_trie_bytes().len(),
        crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY
    );
    assert_eq!(engine.get_pinned_pubkey(&address), None);

    // Phase 2: First spend pins public key
    engine
        .pin_pubkey(address, scheme, &pubkey, &salt)
        .await
        .unwrap();

    let acc_pinned = engine.get_account(&address).await.unwrap();
    assert_eq!(acc_pinned.balance, 10_000_000);
    assert_eq!(acc_pinned.scheme, scheme);
    let expected_hash = *blake3::hash(&pubkey).as_bytes();
    assert_eq!(acc_pinned.pubkey_hash, Some(expected_hash));
    assert_eq!(
        acc_pinned.to_trie_bytes().len(),
        crate::cpat2::ACCOUNT_LEAF_LEN_PQ
    );

    // Phase 3: Second spend retrieves pinned public key
    let retrieved = engine.get_pinned_pubkey(&address);
    assert!(retrieved.is_some());
    let (ret_scheme, ret_pk) = retrieved.unwrap();
    assert_eq!(ret_scheme, scheme);
    assert_eq!(ret_pk, pubkey);
}

#[tokio::test]
async fn test_address_preimage_mismatch_rejection() {
    let engine = InMemoryStateEngine::new();
    let scheme = PqScheme::Falcon512;
    let pubkey = vec![0x33u8; scheme.pubkey_size()];
    let salt = [0x55u8; 16];
    let correct_address = derive_pq_address(scheme, &pubkey, &salt);

    // Tampered address
    let mut tampered_address = correct_address;
    tampered_address[0] ^= 0xff;
    let res_tampered_addr = engine
        .pin_pubkey(tampered_address, scheme, &pubkey, &salt)
        .await;
    assert!(res_tampered_addr.is_err());
    assert!(res_tampered_addr.unwrap_err().contains("Address mismatch"));

    // Tampered salt
    let tampered_salt = [0xaa; 16];
    let res_tampered_salt = engine
        .pin_pubkey(correct_address, scheme, &pubkey, &tampered_salt)
        .await;
    assert!(res_tampered_salt.is_err());
    assert!(res_tampered_salt.unwrap_err().contains("Address mismatch"));

    // Invalid pubkey length
    let bad_pk = vec![0x11u8; 64];
    let res_bad_len = engine
        .pin_pubkey(correct_address, scheme, &bad_pk, &salt)
        .await;
    assert!(res_bad_len.is_err());
    assert!(res_bad_len
        .unwrap_err()
        .contains("Invalid public key length"));
}

#[tokio::test]
async fn test_persistence_across_simulated_reopen() {
    let dir = std::env::temp_dir().join(format!(
        "stell_pq_sim_reopen_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let scheme = PqScheme::Falcon512;
    let pubkey = vec![0x77u8; scheme.pubkey_size()];
    let salt = [0x88u8; 16];
    let address = derive_pq_address(scheme, &pubkey, &salt);

    let snap_bytes = {
        let engine1 = InMemoryStateEngine::new();
        engine1.open_pq_storage(&dir).unwrap();

        engine1.credit_native(&address, 50_000_000).await.unwrap();
        engine1
            .pin_pubkey(address, scheme, &pubkey, &salt)
            .await
            .unwrap();

        assert_eq!(
            engine1.get_pinned_pubkey(&address),
            Some((scheme, pubkey.clone()))
        );
        engine1.create_snapshot().await
    };

    // Engine 1 is dropped; simulate re-open with Engine 2 pointing to the same storage
    {
        let engine2 = InMemoryStateEngine::new();
        engine2.open_pq_storage(&dir).unwrap();
        engine2.restore_snapshot(&snap_bytes).await.unwrap();

        let retrieved = engine2.get_pinned_pubkey(&address);
        assert_eq!(retrieved, Some((scheme, pubkey.clone())));

        let acc = engine2.get_account(&address).await.unwrap();
        assert_eq!(acc.scheme, scheme);
        assert_eq!(acc.pubkey_hash, Some(*blake3::hash(&pubkey).as_bytes()));
        assert_eq!(acc.balance, 50_000_000);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn m03_restore_pq_keys_refuses_invalid_entries_fail_closed() {
    // One valid address record plus two corrupt ones (wrong-address pin,
    // hash-mismatched key): the corrupt entries are skipped (counted +
    // logged) and the restore still installs the valid entry.
    let scheme = PqScheme::Falcon512;
    let seed = 0xE7;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = [0x3Au8; 16];
    let addr = derive_pq_address(scheme, &pk, &salt);
    let engine = InMemoryStateEngine::new();
    engine.credit_native(&addr, 10_000_000).await.unwrap();
    engine.pin_pubkey(addr, scheme, &pk, &salt).await.unwrap();

    let mut akey = Vec::with_capacity(34);
    akey.extend_from_slice(b"a:");
    akey.extend_from_slice(&addr);
    let aval = bincode::serialize(&(scheme, pk.clone(), salt)).unwrap();
    // Corrupt 1: the right key filed under the wrong address
    // (derive(scheme,pk,salt) != address, and no leaf there either).
    let wrong_addr = [0xBBu8; 32];
    let mut bad_key = Vec::with_capacity(34);
    bad_key.extend_from_slice(b"a:");
    bad_key.extend_from_slice(&wrong_addr);
    let bad_key_val = bincode::serialize(&(scheme, pk.clone(), salt)).unwrap();
    // Corrupt 2: the right address bound to a different key
    // (blake3(pk) != leaf pubkey_hash).
    let other_pk = Transaction::sample_falcon512_pubkey(0xE8);
    let bad_pk_val = bincode::serialize(&(scheme, other_pk, salt)).unwrap();
    let blob = bincode::serialize(&vec![
        (akey.clone(), aval),
        (bad_key, bad_key_val),
        (akey, bad_pk_val),
    ])
    .unwrap();
    engine
        .restore_pq_keys(&blob)
        .await
        .expect("invalid entries must not abort the restore");
    assert_eq!(
        engine.get_pinned_pubkey(&addr),
        Some((scheme, pk)),
        "valid entry installs"
    );
    assert_eq!(
        engine.get_pinned_pubkey(&wrong_addr),
        None,
        "wrong-address entry refused"
    );
}

#[tokio::test]
async fn test_ml_dsa_44_refused_and_falcon_pinning_succeeds() {
    let engine = InMemoryStateEngine::new();

    // ML-DSA-44 DISABLED (no verifier): pinning refuses fail-closed.
    let scheme_mldsa = PqScheme::MlDsa44;
    let pk_mldsa = vec![0xa1u8; scheme_mldsa.pubkey_size()];
    let salt_mldsa = [0x12u8; 16];
    let addr_mldsa = derive_pq_address(scheme_mldsa, &pk_mldsa, &salt_mldsa);
    engine.credit_native(&addr_mldsa, 1_000).await.unwrap();
    assert!(engine
        .pin_pubkey(addr_mldsa, scheme_mldsa, &pk_mldsa, &salt_mldsa)
        .await
        .is_err());
    assert_eq!(engine.get_pinned_pubkey(&addr_mldsa), None);

    // FULL-PQ: the removed classical schemes (0x01 Ed25519, 0x04 Hybrid) are
    // not enum values any more, so they are refused at parse time. The old
    // "Hybrid pins" / "Ed25519 pins" assertions are inverted to refusals.
    assert!(PqScheme::from_id(1).is_err(), "Ed25519 id must be refused");
    assert!(PqScheme::from_id(4).is_err(), "Hybrid id must be refused");

    // Positive control: a second Falcon-512 key (different salt) still pins.
    let scheme_falcon = PqScheme::Falcon512;
    let pk_falcon = vec![0xb2u8; scheme_falcon.pubkey_size()];
    let salt_falcon = [0x34u8; 16];
    let addr_falcon = derive_pq_address(scheme_falcon, &pk_falcon, &salt_falcon);
    engine.credit_native(&addr_falcon, 2_000).await.unwrap();
    engine
        .pin_pubkey(addr_falcon, scheme_falcon, &pk_falcon, &salt_falcon)
        .await
        .unwrap();
    assert_eq!(
        engine.get_pinned_pubkey(&addr_falcon),
        Some((scheme_falcon, pk_falcon))
    );
}

#[tokio::test]
async fn test_idempotent_pinning_and_conflicting_rejection() {
    let engine = InMemoryStateEngine::new();
    let scheme = PqScheme::Falcon512;
    let pubkey = vec![0x10u8; scheme.pubkey_size()];
    let salt = [0x20u8; 16];
    let address = derive_pq_address(scheme, &pubkey, &salt);

    engine.credit_native(&address, 10_000).await.unwrap();
    engine
        .pin_pubkey(address, scheme, &pubkey, &salt)
        .await
        .unwrap();

    // Re-pinning identical key is idempotent and succeeds
    assert!(engine
        .pin_pubkey(address, scheme, &pubkey, &salt)
        .await
        .is_ok());

    // Conflicting registration (different key matching same address would fail address derivation,
    // but if someone bypassed derivation or tried different scheme):
    let mut map = engine.accounts.write().await;
    let acc = map.get_mut(&address).unwrap();
    acc.pubkey_hash = Some([0x99; 32]);
    drop(map);

    let err = engine.pin_pubkey(address, scheme, &pubkey, &salt).await;
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("Conflicting public key"));
}

#[tokio::test]
async fn test_pinned_pubkey_persists_across_stop_and_restart() {
    let dir = std::env::temp_dir().join(format!(
        "stell_pq_persist_restart_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let scheme = PqScheme::Falcon512;
    let pubkey = vec![0x4au8; scheme.pubkey_size()];
    let salt = [0x9bu8; 16];
    let address = derive_pq_address(scheme, &pubkey, &salt);

    // Initial session: open storage, attach tree, pin key, verify, and stop engine
    {
        let storage = crate::storage::Storage::open(&dir).unwrap();
        let engine = InMemoryStateEngine::new();
        engine.attach_pq_tree(storage.pq_keys.clone());

        engine.credit_native(&address, 100_000).await.unwrap();
        engine
            .pin_pubkey(address, scheme, &pubkey, &salt)
            .await
            .unwrap();

        assert_eq!(
            engine.get_pinned_pubkey(&address),
            Some((scheme, pubkey.clone()))
        );
        storage.flush().unwrap();
        // engine and storage dropped here ("engine stop")
    }

    // Restart session: fresh engine, re-opened storage, re-attached tree
    {
        let storage_restarted = crate::storage::Storage::open(&dir).unwrap();
        let engine_restarted = InMemoryStateEngine::new();
        engine_restarted.attach_pq_tree(storage_restarted.pq_keys.clone());

        // Pinned public key persists across engine stop and restart
        let retrieved = engine_restarted.get_pinned_pubkey(&address);
        assert_eq!(
            retrieved,
            Some((scheme, pubkey.clone())),
            "pinned public key must persist across engine stop and restart"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_get_pinned_pubkey_returns_exact_registered_key_after_reattaching_storage() {
    let dir = std::env::temp_dir().join(format!(
        "stell_pq_exact_key_reattach_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let storage = crate::storage::Storage::open(&dir).unwrap();

    let scheme_falcon = PqScheme::Falcon512;
    let pk_falcon = vec![0x1au8; scheme_falcon.pubkey_size()];
    let salt_falcon = [0x2bu8; 16];
    let addr_falcon = derive_pq_address(scheme_falcon, &pk_falcon, &salt_falcon);

    let scheme_mldsa = PqScheme::MlDsa44;
    let pk_mldsa = vec![0x3cu8; scheme_mldsa.pubkey_size()];
    let salt_mldsa = [0x4du8; 16];
    let addr_mldsa = derive_pq_address(scheme_mldsa, &pk_mldsa, &salt_mldsa);

    // FULL-PQ: Ed25519 is removed; the second persistent key is another
    // Falcon-512 key (different salt) so the multi-key persistence check
    // still covers two distinct entries.
    let scheme_ed = PqScheme::Falcon512;
    let pk_ed = vec![0x5eu8; scheme_ed.pubkey_size()];
    let salt_ed = [0x6fu8; 16];
    let addr_ed = derive_pq_address(scheme_ed, &pk_ed, &salt_ed);

    // Register keys via first engine
    {
        let engine = InMemoryStateEngine::new();
        engine.attach_pq_tree(storage.pq_keys.clone());

        engine
            .pin_pubkey(addr_falcon, scheme_falcon, &pk_falcon, &salt_falcon)
            .await
            .unwrap();
        // ML-DSA-44 DISABLED: pinning refuses; the key is never stored.
        assert!(engine
            .pin_pubkey(addr_mldsa, scheme_mldsa, &pk_mldsa, &salt_mldsa)
            .await
            .is_err());
        engine
            .pin_pubkey(addr_ed, scheme_ed, &pk_ed, &salt_ed)
            .await
            .unwrap();
        storage.flush().unwrap();
    }

    // Re-attach storage to a brand new engine
    let fresh_engine = InMemoryStateEngine::new();
    // Before re-attaching, unpinned/unattached keys return None
    assert_eq!(fresh_engine.get_pinned_pubkey(&addr_falcon), None);
    assert_eq!(fresh_engine.get_pinned_pubkey(&addr_mldsa), None);
    assert_eq!(fresh_engine.get_pinned_pubkey(&addr_ed), None);

    // Re-attach persistent storage tree
    fresh_engine.attach_pq_tree(storage.pq_keys.clone());

    // Verify get_pinned_pubkey returns the exact registered keys
    let got_falcon = fresh_engine
        .get_pinned_pubkey(&addr_falcon)
        .expect("falcon key must be retrieved");
    assert_eq!(got_falcon, (scheme_falcon, pk_falcon));

    let got_mldsa = fresh_engine.get_pinned_pubkey(&addr_mldsa);
    assert_eq!(got_mldsa, None, "disabled ML-DSA-44 keys are never stored");

    let got_ed = fresh_engine
        .get_pinned_pubkey(&addr_ed)
        .expect("second Falcon key must be retrieved");
    assert_eq!(got_ed, (scheme_ed, pk_ed));

    // Unregistered address returns None
    let unpinned_addr = [0xffu8; 32];
    assert_eq!(fresh_engine.get_pinned_pubkey(&unpinned_addr), None);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_block_execution_pq_activation_pinning_and_disk_persistence() {
    let dir = std::env::temp_dir().join(format!(
        "stell_block_exec_pq_pin_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let engine = InMemoryStateEngine::new();
    engine.open_pq_storage(&dir).unwrap();

    let scheme = PqScheme::Falcon512;
    let seed = 0x5D;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = crate::post_quantum::DEFAULT_SALT;
    let from = derive_pq_address(scheme, &pk, &salt);
    let recipient = [0x77u8; 32];

    let initial_balance = 50_000_000u64;
    engine.credit_native(&from, initial_balance).await.unwrap();

    // Verify account is legacy / unpinned before execution
    let acc_before = engine.get_account(&from).await.unwrap();
    assert_eq!(acc_before.pubkey_hash, None);
    assert_eq!(
        acc_before.to_trie_bytes().len(),
        crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY
    );
    let leaf_before = engine.state_trie.read().await.get(&from).unwrap().to_vec();
    assert_eq!(leaf_before.len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
    assert_eq!(engine.get_pinned_pubkey(&from), None);

    // Build PQ activation transaction
    let amount = 50_000u64;
    let gas_limit = 500_000u64;
    let mut tx = Transaction {
        from,
        to: recipient,
        amount,
        gas_limit,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig);
    tx.signature = envelope.encode();

    assert!(tx.is_pq_activation());

    // Execute block with the PQ activation transaction
    let (applied, failed, _fees, status, _tx_fees) =
        engine.apply_block_parallel_fees(&[tx], 1000).await;
    assert_eq!(applied, 1);
    assert_eq!(failed, 0);
    assert!(status[0]);

    // 1. Verify AccountState.pubkey_hash is set to Some
    let acc_after = engine.get_account(&from).await.unwrap();
    let expected_hash = *blake3::hash(&pk).as_bytes();
    assert_eq!(acc_after.pubkey_hash, Some(expected_hash));
    assert_eq!(acc_after.scheme, scheme);
    assert_eq!(acc_after.nonce, 1);

    // Verify activation surcharge gas fee deducted from sender's balance in commit_native
    // Under Ruleset v7 (`EXEC_HARDENING_V1_ACTIVATION_HEIGHT = 0`), intrinsic floor is `TX_INTRINSIC_GAS`.
    let billed = InMemoryStateEngine::TX_INTRINSIC_GAS;
    let expected_balance = initial_balance - amount - billed - PQ_ACTIVATION_SURCHARGE_GAS;
    assert_eq!(acc_after.balance, expected_balance);

    // 2. Verify account leaf becomes 49 bytes (ACCOUNT_LEAF_LEN_PQ)
    assert_eq!(
        acc_after.to_trie_bytes().len(),
        crate::cpat2::ACCOUNT_LEAF_LEN_PQ
    );
    assert_eq!(acc_after.to_trie_bytes().len(), 49);
    let leaf_after = engine.state_trie.read().await.get(&from).unwrap().to_vec();
    assert_eq!(leaf_after.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
    assert_eq!(leaf_after.len(), 49);

    // 3. Verify public key is persisted to disk
    let in_engine_pk = engine.get_pinned_pubkey(&from);
    assert_eq!(in_engine_pk, Some((scheme, pk.clone())));

    // Drop engine so sled releases the lock on the directory
    drop(engine);

    let fresh_engine = InMemoryStateEngine::new();
    fresh_engine.open_pq_storage(&dir).unwrap();
    let persisted_pk = fresh_engine.get_pinned_pubkey(&from);
    assert_eq!(
        persisted_pk,
        Some((scheme, pk)),
        "Public key must be persisted to disk and retrieved by fresh engine"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_steady_state_implicit_transactions_follow_activation_and_lookup_pinned_key() {
    let dir = std::env::temp_dir().join(format!(
        "stell_steady_state_implicit_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let engine = InMemoryStateEngine::new();
    engine.open_pq_storage(&dir).unwrap();

    let scheme = PqScheme::Falcon512;
    let seed = 0x82;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = crate::post_quantum::DEFAULT_SALT;
    let from = derive_pq_address(scheme, &pk, &salt);
    let recipient = [0x99u8; 32];

    engine.credit_native(&from, 20_000_000).await.unwrap();

    // 1. Block 1: Apply PQ activation transaction (nonce 0, explicit pubkey)
    let mut tx_act = Transaction {
        from,
        to: recipient,
        amount: 10_000,
        gas_limit: 500_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg_act = tx_act.signing_message();
    let sig_act = Transaction::create_falcon512_test_signature(&pk, &msg_act, seed);
    tx_act.signature = PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig_act).encode();
    assert!(tx_act.is_pq_activation());

    let (applied1, failed1, _, _, _) = engine.apply_block_parallel_fees(&[tx_act], 1000).await;
    assert_eq!(applied1, 1);
    assert_eq!(failed1, 0);

    // Verify pinned key exists
    let (pinned_scheme, pinned_pk) = engine
        .get_pinned_pubkey(&from)
        .expect("Pinned key must exist after activation");
    assert_eq!(pinned_scheme, scheme);
    assert_eq!(pinned_pk, pk);

    // 2. Block 2: Steady-state implicit transaction (nonce 1, 0-byte pubkey on wire)
    let mut tx_imp = Transaction {
        from,
        to: recipient,
        amount: 20_000,
        gas_limit: 500_000,
        nonce: 1,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg_imp = tx_imp.signing_message();
    let sig_imp = Transaction::create_falcon512_test_signature(&pk, &msg_imp, seed);
    tx_imp.signature = PqSignatureEnvelope::new_implicit(scheme, sig_imp).encode();

    assert!(!tx_imp.is_pq_activation());
    assert!(tx_imp.is_pq_implicit());

    let (applied2, failed2, _, status2, _) =
        engine.apply_block_parallel_fees(&[tx_imp], 1001).await;
    assert_eq!(
        applied2, 1,
        "Steady-state implicit transaction must succeed"
    );
    assert_eq!(failed2, 0);
    assert!(status2[0]);

    // Verify account state and trie leaf format
    let acc_after2 = engine.get_account(&from).await.unwrap();
    assert_eq!(acc_after2.nonce, 2);
    assert_eq!(acc_after2.pubkey_hash, Some(*blake3::hash(&pk).as_bytes()));
    assert_eq!(
        acc_after2.to_trie_bytes().len(),
        crate::cpat2::ACCOUNT_LEAF_LEN_PQ
    );
    assert_eq!(engine.state_trie.read().await.get(&from).unwrap().len(), 49);

    // 3. Steady-state across engine restart: fresh engine with attached storage
    drop(engine);
    let storage = crate::storage::Storage::open(&dir).unwrap();
    let restarted_engine = InMemoryStateEngine::new();
    restarted_engine.attach_pq_tree(storage.pq_keys.clone());
    restarted_engine.update_account(acc_after2).await;

    // Verify restarted engine looks up the pinned key
    let looked_up = restarted_engine.get_pinned_pubkey(&from);
    assert_eq!(looked_up, Some((scheme, pk.clone())));

    // Next implicit transaction on restarted engine
    let mut tx_imp2 = Transaction {
        from,
        to: recipient,
        amount: 5_000,
        gas_limit: 500_000,
        nonce: 2,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg_imp2 = tx_imp2.signing_message();
    let sig_imp2 = Transaction::create_falcon512_test_signature(&pk, &msg_imp2, seed);
    tx_imp2.signature = PqSignatureEnvelope::new_implicit(scheme, sig_imp2).encode();

    let (applied3, failed3, _, _, _) = restarted_engine
        .apply_block_parallel_fees(&[tx_imp2], 1002)
        .await;
    assert_eq!(
        applied3, 1,
        "Steady-state implicit transaction on restarted engine must succeed"
    );
    assert_eq!(failed3, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn m03_custom_salt_restart_heal_implicit_verifies() {
    // M-03 liveness regression: a non-default-salt account must recover
    // across a restart. Origin pins with a custom salt; the restart
    // heals from the accounts snapshot + the pq_keys blob, and the
    // healed implicit registry (pinned salt, NOT DEFAULT_SALT) verifies
    // an implicit-PQ transaction. Diskless (fallback) path throughout,
    // so the salt survives only via the pinned record.
    use crate::post_quantum::DEFAULT_SALT;
    let scheme = PqScheme::Falcon512;
    let seed = 0xE3;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = [0x9Cu8; 16];
    assert_ne!(salt, DEFAULT_SALT, "test needs a non-default salt");
    let from = derive_pq_address(scheme, &pk, &salt);

    let engine1 = InMemoryStateEngine::new();
    engine1.credit_native(&from, 50_000_000).await.unwrap();
    engine1.pin_pubkey(from, scheme, &pk, &salt).await.unwrap();
    assert_eq!(
        engine1.get_pinned_pubkey_with_salt(&from),
        Some((scheme, pk.clone(), salt)),
        "fallback must persist the pinned salt"
    );
    let snap = engine1.create_snapshot().await;
    let mut akey = Vec::with_capacity(34);
    akey.extend_from_slice(b"a:");
    akey.extend_from_slice(&from);
    let aval = bincode::serialize(&(scheme, pk.clone(), salt)).unwrap();
    let mut hkey = Vec::with_capacity(34);
    hkey.extend_from_slice(b"h:");
    hkey.extend_from_slice(blake3::hash(&pk).as_bytes());
    let blob = bincode::serialize(&vec![(akey, aval), (hkey, pk.clone())]).unwrap();
    drop(engine1);

    // Restart: fresh diskless engine installs the snapshot + the blob.
    let engine2 = InMemoryStateEngine::new();
    engine2.restore_snapshot(&snap).await.unwrap();
    engine2.restore_pq_keys(&blob).await.unwrap();
    assert_eq!(
        engine2.get_pinned_pubkey_with_salt(&from),
        Some((scheme, pk.clone(), salt)),
        "healing must recover the PINNED salt, not DEFAULT_SALT"
    );

    // An implicit-PQ transaction verifies against the healed state: the
    // block path heals the global implicit registry from the pinned salt
    // before verifying, so a custom-salt account stays live.
    let mut tx = Transaction {
        from,
        to: [0x77u8; 32],
        amount: 1_000,
        gas_limit: 50_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(scheme, sig).encode();
    assert!(tx.is_pq_implicit());
    let (applied, failed, _, _, _) = engine2.apply_block_parallel_fees(&[tx], 1000).await;
    assert_eq!(
        applied, 1,
        "implicit-PQ tx on the healed custom-salt account must apply"
    );
    assert_eq!(failed, 0);
}
