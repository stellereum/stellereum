use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::{
    Block, CrossShardMessage, FinalizedHeaderRegistry, Transaction, CHAIN_ID_COMMITMENT_TAG,
    EVM_CHAIN_ID, PRIORITY_FEE_COMMITMENT_TAG, SPONSOR_COMMITMENT_TAG, SPONSOR_SIG_TAG,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::xshard2pc::{
    is_retired, source_action, SourceAction, XpcPhase, XpcRecord, XPC_ABORT_REQUEST, XPC_COMMIT,
    XPC_PREPARE, XPC_PREPARE_ACK, XPC_TERMINAL_RETENTION_HEIGHTS,
};
use stellereum::zkml::{SessionKeyAuthorization, SCOPE_ALL};

fn carrier(shard_id: u32, height: u64, msgs: Vec<CrossShardMessage>) -> Block {
    Block {
        shard_id,
        height,
        timestamp: 1_770_000_000 + height,
        proposer: [0x11; 32],
        cross_shard_out: msgs,
        ..Default::default()
    }
}

fn signed_pq_explicit_tx(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        280_000,
        nonce,
        source_shard,
        target_shard,
        vec![],
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        to,
        amount,
        280_000,
        nonce,
        source_shard,
        target_shard,
        vec![],
        &DEFAULT_SALT,
    )
}

#[tokio::test]
async fn pruned_committed_xpc_cannot_be_reopened_by_prepare_or_abort_request() {
    let kp = FalconKeypair::generate_from_seed(71);
    let sender_addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    let recipient = [0x88u8; 32];
    let amount = 1_000_000u64;
    let initial_bal = 5_000_000_000u64;

    let tx = signed_pq_explicit_tx(&kp, recipient, amount, 0, 0, 1);
    let tx_hash = tx.compute_tx_hash();

    let source = InMemoryStateEngine::new();
    source.enable_cross_shard();
    source
        .update_account(AccountState::new(sender_addr, initial_bal))
        .await;
    source
        .pin_pubkey(
            sender_addr,
            PqScheme::Falcon512,
            &kp.public_key,
            &DEFAULT_SALT,
        )
        .await
        .expect("pin pq key");

    let source_account_root = source.get_state_root().await;
    let account_proof = source.get_account_proof(&sender_addr).await;
    let pk_hash = source
        .get_account(&sender_addr)
        .await
        .and_then(|a| a.pubkey_hash)
        .expect("pinned pq pubkey hash");
    let anchor_prepare = [0xA1u8; 32];

    source
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), 0, 1, 1)])
        .await;
    let source_prepared_root = source.get_state_root().await;
    let xpc_proof = source
        .get_xpc_proof(&tx_hash)
        .await
        .expect("source PREPARED leaf proof");
    let anchor_commit = [0xA2u8; 32];

    // Height-0 anchors remain valid past the 2PC terminal retention window,
    // isolating the post-prune replay guard from anchor expiry.
    let reg = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    {
        let mut guard = reg.write().unwrap();
        guard.note_finalized(0, anchor_prepare, source_account_root);
        guard.note_finalized(0, anchor_commit, source_prepared_root);
    }

    let target = InMemoryStateEngine::new();
    target.enable_cross_shard();
    target.with_finalized_headers(reg);

    // 1. Target prepares at height 1.
    let prepare_msg = CrossShardMessage::new_xpc(
        XPC_PREPARE,
        0,
        1,
        tx.clone(),
        source_account_root,
        anchor_prepare,
        account_proof,
    )
    .with_source_balance(initial_bal)
    .with_sender_pubkey_hash(PqScheme::Falcon512.id(), pk_hash);
    assert!(
        prepare_msg.verify_inclusion_strict(),
        "precondition: prepare inclusion proof is valid"
    );
    target
        .apply_cross_shard_consumptions(&carrier(1, 1, vec![prepare_msg.clone()]))
        .await;
    assert_eq!(
        target.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Prepared)
    );

    // 2. Target commits at height 2 and credits recipient once.
    let commit_msg = CrossShardMessage::new_xpc(
        XPC_COMMIT,
        0,
        1,
        tx.clone(),
        source_prepared_root,
        anchor_commit,
        Some(xpc_proof.clone()),
    );
    let credited = target
        .apply_cross_shard_consumptions(&carrier(1, 2, vec![commit_msg.clone()]))
        .await;
    assert_eq!(credited, 1);
    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount)
    );
    assert_eq!(
        target.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Committed)
    );
    assert!(target.is_cross_shard_completed(&tx_hash).await);

    // 3. Prune terminal XPC record after retention window elapses.
    let prune_height = 2 + XPC_TERMINAL_RETENTION_HEIGHTS;
    assert_eq!(target.prune_terminal_xpc_records(prune_height).await, 1);
    assert!(target.xpc_record(&tx_hash).await.is_none());
    assert_eq!(target.xpc_len().await, 0);
    assert!(target.is_cross_shard_completed(&tx_hash).await);

    let root_after_prune = target.get_state_root().await;

    // 4. Re-submitting Prepare with a live anchor must be rejected without
    // recreating a zombie Prepared record in cross_shard_xpc.
    let reprepare_credited = target
        .apply_cross_shard_consumptions(&carrier(1, prune_height + 1, vec![prepare_msg]))
        .await;
    assert_eq!(reprepare_credited, 0);
    assert!(
        target.xpc_record(&tx_hash).await.is_none(),
        "pruned completed transfer must never reopen as zombie Prepared"
    );
    assert_eq!(target.xpc_len().await, 0);
    assert_eq!(target.get_state_root().await, root_after_prune);
    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount)
    );

    // 5. Submitting AbortRequest with a live anchor must also be rejected
    // without writing Aborted over an already-committed transfer.
    let abort_req = CrossShardMessage::new_xpc(
        XPC_ABORT_REQUEST,
        0,
        1,
        tx,
        source_prepared_root,
        anchor_commit,
        Some(xpc_proof),
    );
    let abort_credited = target
        .apply_cross_shard_consumptions(&carrier(1, prune_height + 2, vec![abort_req]))
        .await;
    assert_eq!(abort_credited, 0);
    assert!(
        target.xpc_record(&tx_hash).await.is_none(),
        "pruned completed transfer must never record Aborted"
    );
    assert_eq!(target.xpc_len().await, 0);
    assert_eq!(target.get_state_root().await, root_after_prune);
    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount)
    );

    // 6. Duplicate Commit after prune is also rejected and never double-credits.
    let replay_commit = target
        .apply_cross_shard_consumptions(&carrier(1, prune_height + 3, vec![commit_msg]))
        .await;
    assert_eq!(replay_commit, 0);
    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount)
    );
}

#[tokio::test]
async fn xpc_prepare_ack_refresh_updates_decided_height_and_state_root() {
    let kp = FalconKeypair::generate_from_seed(72);
    let recipient = [0x89u8; 32];
    let tx = signed_pq_explicit_tx(&kp, recipient, 1_000_000, 0, 0, 1);
    let tx_hash = tx.compute_tx_hash();
    let anchor_target = [0xB1u8; 32];

    let target = InMemoryStateEngine::new();
    target.enable_cross_shard();
    target
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), 0, 1, 5)])
        .await;
    let target_root = target.get_state_root().await;
    let target_proof = target
        .get_xpc_proof(&tx_hash)
        .await
        .expect("target PREPARED leaf proof");

    let reg = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    reg.write()
        .unwrap()
        .note_finalized(1, anchor_target, target_root);

    let source = InMemoryStateEngine::new();
    source.enable_cross_shard();
    source.with_finalized_headers(reg);
    source
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), 0, 1, 5)])
        .await;

    let ack = CrossShardMessage::new_xpc(
        XPC_PREPARE_ACK,
        1,
        0,
        tx,
        target_root,
        anchor_target,
        Some(target_proof),
    );

    // Initial PrepareAck commits the source at height 10.
    let credited_initial = source
        .apply_cross_shard_consumptions(&carrier(0, 10, vec![ack.clone()]))
        .await;
    assert_eq!(credited_initial, 0);
    let rec_10 = source
        .xpc_record(&tx_hash)
        .await
        .expect("committed source record");
    assert_eq!(rec_10.phase, XpcPhase::Committed);
    assert_eq!(rec_10.decided_height, 10);
    assert!(source.is_cross_shard_completed(&tx_hash).await);
    let root_10 = source.get_state_root().await;

    // Same-height PrepareAck is a no-op.
    let credited_same = source
        .apply_cross_shard_consumptions(&carrier(0, 10, vec![ack.clone()]))
        .await;
    assert_eq!(credited_same, 0);
    assert_eq!(source.get_state_root().await, root_10);

    // Later PrepareAck at height 50 refreshes decided_height and advances committed state root.
    let credited_refresh = source
        .apply_cross_shard_consumptions(&carrier(0, 50, vec![ack]))
        .await;
    assert_eq!(credited_refresh, 0);
    let rec_50 = source
        .xpc_record(&tx_hash)
        .await
        .expect("refreshed source record");
    assert_eq!(rec_50.phase, XpcPhase::Committed);
    assert_eq!(rec_50.decided_height, 50);
    assert_ne!(
        source.get_state_root().await,
        root_10,
        "refreshing decided_height must move committed state_root"
    );
    assert_eq!(source_action(&rec_50, 51), SourceAction::Commit);
    assert!(!is_retired(&rec_50, 50));
}

fn reference_compute_tx_hash(tx: &Transaction) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(tx.from);
    hasher.update(tx.to);
    hasher.update(tx.amount.to_be_bytes());
    hasher.update(tx.gas_limit.to_be_bytes());
    hasher.update(tx.nonce.to_be_bytes());
    hasher.update(tx.source_shard.to_be_bytes());
    hasher.update(tx.target_shard.to_be_bytes());
    hasher.update(b"PAYLOAD");
    match bincode::serialize(&tx.payload) {
        Ok(bytes) => {
            hasher.update((bytes.len() as u32).to_be_bytes());
            hasher.update(&bytes);
        }
        Err(_) => hasher.update(u32::MAX.to_be_bytes()),
    }
    if tx.priority_fee_per_gas != 0 {
        hasher.update(PRIORITY_FEE_COMMITMENT_TAG);
        hasher.update(tx.priority_fee_per_gas.to_be_bytes());
    }
    if let Some(d) = tx.delegation() {
        let mut out = Vec::new();
        out.extend_from_slice(b"SESSION");
        match bincode::serialize(&d) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        hasher.update(out);
    }
    if tx.is_chain_id_bound() {
        hasher.update(CHAIN_ID_COMMITMENT_TAG);
        if let Some(cid) = tx.chain_id_from_envelope() {
            hasher.update(cid.to_be_bytes());
        }
    }
    if let Some(auth) = tx.sponsor_auth() {
        let mut out = Vec::new();
        out.extend_from_slice(SPONSOR_COMMITMENT_TAG);
        match bincode::serialize(&auth) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        hasher.update(out);
    }
    if tx.is_evm() {
        hasher.update(b"EVM_TX");
        hasher.update(&tx.signature);
    }
    if tx.is_pq() {
        hasher.update(b"PQ_ENV");
        hasher.update(&tx.signature);
    }
    hasher.finalize().into()
}

fn reference_chain_id(tx: &Transaction) -> Option<u64> {
    if let Some(auth) = tx.sponsor_auth() {
        return Some(auth.chain_id);
    }
    if let Some(d) = tx.delegation() {
        Some(d.chain_id)
    } else if let Some(cid) = tx.chain_id_from_envelope() {
        Some(cid)
    } else if let Some(env) = tx.pq_envelope() {
        env.chain_id
    } else if tx.is_evm() {
        Some(EVM_CHAIN_ID)
    } else {
        None
    }
}

#[test]
fn compute_tx_hash_and_metadata_match_reference_across_all_tx_variants() {
    let ed_user = SigningKey::from_bytes(&[11u8; 32]);
    let ed_sponsor = SigningKey::from_bytes(&[12u8; 32]);
    let ed_session = SigningKey::from_bytes(&[13u8; 32]);

    let fk_master = FalconKeypair::generate_from_seed(21);
    let fk_session = FalconKeypair::generate_from_seed(22);
    let fk_sponsor = FalconKeypair::generate_from_seed(23);

    let to = [0x44u8; 32];
    let payload = vec![OpCode::Push(7), OpCode::Nop];

    // 1. Plain legacy & priority & chain-bound Ed transactions.
    let plain = Transaction::sign(&ed_user, to, 100, 280_000, 1, 0, 1);
    let plain_priority = Transaction::sign_with_payload_and_priority(
        &ed_user,
        to,
        200,
        300_000,
        2,
        0,
        0,
        payload.clone(),
        55,
    );
    let plain_chain = Transaction::sign_with_payload_and_chain_id(
        &ed_user,
        to,
        300,
        300_000,
        3,
        0,
        1,
        payload.clone(),
        5757,
    );

    // 2. Delegated (SF1 Falcon-512 session + SK1 legacy framing).
    let grant_pq = SessionKeyAuthorization::sign_delegation_falcon512(
        &fk_master,
        PqScheme::Falcon512,
        fk_session.public_key(),
        1_900_000_000,
        10_000_000,
        SCOPE_ALL,
        1_000_000,
        5757,
    );
    let delegated_pq = Transaction::sign_with_session_falcon512(
        &fk_session,
        grant_pq.clone(),
        to,
        400,
        280_000,
        4,
        0,
        1,
        payload.clone(),
    );
    let mut delegated_pq_prio = delegated_pq.clone();
    delegated_pq_prio.priority_fee_per_gas = 99;

    let mut grant_ed = grant_pq;
    grant_ed.master_address = ed_user.verifying_key().to_bytes();
    grant_ed.session_pubkey = ed_session.verifying_key().to_bytes();
    let delegated_ed =
        Transaction::sign_with_session(&ed_session, grant_ed, to, 450, 280_000, 5, 0, 0, vec![]);

    // 3. Sponsored (PQ Falcon-512 SP1 + Ed SP1 + self-sponsored + malformed SP1).
    let sponsored_pq = Transaction::sign_with_sponsor_falcon512(
        &fk_master,
        &fk_sponsor,
        to,
        500,
        280_000,
        6,
        0,
        1,
        payload.clone(),
        10,
        500_000,
        1_900_000_000,
        vec![to],
        5757,
    );
    let self_sponsored_pq = Transaction::sign_with_sponsor_falcon512(
        &fk_master,
        &fk_master,
        to,
        525,
        280_000,
        7,
        0,
        0,
        vec![],
        0,
        500_000,
        1_900_000_000,
        vec![],
        5757,
    );
    let sponsored_ed = Transaction::sign_with_sponsor(
        &ed_user,
        &ed_sponsor,
        to,
        550,
        280_000,
        8,
        0,
        1,
        vec![],
        5,
        500_000,
        1_900_000_000,
        vec![],
        5757,
    );
    let mut malformed_sponsored = plain.clone();
    malformed_sponsored.signature.extend_from_slice(&[0u8; 8]);
    malformed_sponsored
        .signature
        .extend_from_slice(&999u32.to_be_bytes());
    malformed_sponsored
        .signature
        .extend_from_slice(SPONSOR_SIG_TAG);
    assert!(malformed_sponsored.sponsor_malformed());

    // 4. PQ explicit & implicit (with and without chain_id).
    let pq_explicit = signed_pq_explicit_tx(&fk_master, to, 600, 9, 0, 1);
    let pq_explicit_chain_probe = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        fk_master.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        650,
        280_000,
        10,
        0,
        1,
        payload.clone(),
        &DEFAULT_SALT,
        5757,
    );
    let pq_explicit_chain = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        fk_master.public_key.clone(),
        fk_master.sign(&pq_explicit_chain_probe.signing_message()),
        to,
        650,
        280_000,
        10,
        0,
        1,
        payload.clone(),
        &DEFAULT_SALT,
        5757,
    );

    let pq_from = derive_pq_address(PqScheme::Falcon512, fk_master.public_key(), &DEFAULT_SALT);
    let pq_implicit_probe = Transaction::new_pq_implicit(
        pq_from,
        PqScheme::Falcon512,
        vec![0u8; FALCON512_SIG_LEN],
        to,
        700,
        280_000,
        11,
        0,
        1,
        vec![],
    );
    let pq_implicit = Transaction::new_pq_implicit(
        pq_from,
        PqScheme::Falcon512,
        fk_master.sign(&pq_implicit_probe.signing_message()),
        to,
        700,
        280_000,
        11,
        0,
        1,
        vec![],
    );
    let pq_implicit_chain_probe = Transaction::new_pq_implicit_with_chain(
        pq_from,
        PqScheme::Falcon512,
        vec![0u8; FALCON512_SIG_LEN],
        to,
        750,
        280_000,
        12,
        0,
        1,
        payload,
        5757,
    );
    let pq_implicit_chain = Transaction::new_pq_implicit_with_chain(
        pq_from,
        PqScheme::Falcon512,
        fk_master.sign(&pq_implicit_chain_probe.signing_message()),
        to,
        750,
        280_000,
        12,
        0,
        1,
        vec![OpCode::Push(7), OpCode::Nop],
        5757,
    );

    // 5. EVM envelope.
    let evm = Transaction::new_evm(
        [0x15u8; 32],
        to,
        800,
        21_000,
        13,
        0,
        0,
        vec![0xf8, 0x42, 0x01, 0x80],
    );
    assert!(evm.is_evm());

    // Extra sanity: a valid sponsored tx with an authentic SponsorAuthorization round-trip.
    assert!(sponsored_pq.is_sponsored());
    assert_eq!(sponsored_pq.sponsor_auth().unwrap().chain_id, 5757);

    let variants = vec![
        plain,
        plain_priority,
        plain_chain,
        delegated_pq,
        delegated_pq_prio,
        delegated_ed,
        sponsored_pq,
        self_sponsored_pq,
        sponsored_ed,
        malformed_sponsored,
        pq_explicit,
        pq_explicit_chain,
        pq_implicit,
        pq_implicit_chain,
        evm,
    ];

    let batched = Transaction::compute_tx_hashes_batched(&variants);
    assert_eq!(batched.len(), variants.len());

    for (idx, tx) in variants.iter().enumerate() {
        let expected_hash = reference_compute_tx_hash(tx);
        assert_eq!(
            tx.compute_tx_hash(),
            expected_hash,
            "compute_tx_hash mismatch at variant index {idx}"
        );
        assert_eq!(
            batched[idx], expected_hash,
            "compute_tx_hashes_batched mismatch at variant index {idx}"
        );
        assert_eq!(
            tx.chain_id(),
            reference_chain_id(tx),
            "chain_id mismatch at variant index {idx}"
        );
        // Also verify signing_message() determinism across repeated calls.
        assert_eq!(tx.signing_message(), tx.signing_message());
    }
}

#[tokio::test]
async fn record_legacy_escrow_and_xpc_source_prepares_preserve_first_match_and_order() {
    let kp = FalconKeypair::generate_from_seed(81);
    let to_s1 = [0x31u8; 32];
    let to_s2 = [0x32u8; 32];

    let tx_ok_dup_first = signed_pq_explicit_tx(&kp, to_s1, 100, 0, 0, 1);
    let tx_same_shard = signed_pq_explicit_tx(&kp, to_s1, 200, 1, 0, 0);
    let tx_failed = signed_pq_explicit_tx(&kp, to_s1, 300, 2, 0, 1);
    let tx_ok_second = signed_pq_explicit_tx(&kp, to_s2, 400, 3, 0, 2);
    let tx_fail_dup_first = signed_pq_explicit_tx(&kp, to_s1, 500, 4, 0, 1);
    let tx_legacy_mixed = signed_pq_explicit_tx(&kp, to_s1, 600, 5, 0, 1);
    let tx_not_in_block = signed_pq_explicit_tx(&kp, to_s1, 700, 6, 0, 1);
    let tx_inbound = signed_pq_explicit_tx(&kp, to_s1, 800, 7, 1, 0);

    // Block transactions contain duplicates with differing status flags:
    // - tx_ok_dup_first: index 0 -> true, index 3 -> false (first match MUST win => true)
    // - tx_fail_dup_first: index 5 -> false, index 6 -> true (first match MUST win => false)
    let transactions = vec![
        tx_ok_dup_first.clone(),
        tx_same_shard,
        tx_failed.clone(),
        tx_ok_dup_first.clone(),
        tx_ok_second.clone(),
        tx_fail_dup_first.clone(),
        tx_fail_dup_first.clone(),
        tx_legacy_mixed.clone(),
    ];
    let status = vec![true, true, false, false, true, false, true, true];

    // 1. Legacy escrow receipt path with duplicates and mixed valid/invalid messages.
    let legacy_msgs = vec![
        CrossShardMessage::new(1, 0, tx_inbound.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new(0, 1, tx_not_in_block.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new(0, 1, tx_failed.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new(0, 1, tx_fail_dup_first.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new(0, 1, tx_ok_dup_first.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new(0, 2, tx_ok_second.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new(0, 1, tx_ok_dup_first.clone(), [0u8; 32], [0u8; 32], None),
    ];
    let legacy_block = Block {
        shard_id: 0,
        height: 10,
        transactions: transactions.clone(),
        cross_shard_out: legacy_msgs,
        ..Default::default()
    };

    let legacy_engine = InMemoryStateEngine::new();
    legacy_engine.enable_cross_shard();
    let escrow_count = legacy_engine
        .record_legacy_escrow_receipts(&legacy_block, &status)
        .await;
    assert_eq!(escrow_count, 3);
    assert!(legacy_engine
        .get_legacy_escrow_proof(&tx_ok_dup_first.compute_tx_hash())
        .await
        .is_some());
    assert!(legacy_engine
        .get_legacy_escrow_proof(&tx_ok_second.compute_tx_hash())
        .await
        .is_some());
    assert!(legacy_engine
        .get_legacy_escrow_proof(&tx_failed.compute_tx_hash())
        .await
        .is_none());
    assert!(legacy_engine
        .get_legacy_escrow_proof(&tx_fail_dup_first.compute_tx_hash())
        .await
        .is_none());
    assert!(legacy_engine
        .get_legacy_escrow_proof(&tx_not_in_block.compute_tx_hash())
        .await
        .is_none());

    // Compare against canonical deduplicated baseline.
    let canonical_legacy_block = Block {
        shard_id: 0,
        height: 10,
        transactions: vec![tx_ok_dup_first.clone(), tx_ok_second.clone()],
        cross_shard_out: vec![
            CrossShardMessage::new(0, 1, tx_ok_dup_first.clone(), [0u8; 32], [0u8; 32], None),
            CrossShardMessage::new(0, 2, tx_ok_second.clone(), [0u8; 32], [0u8; 32], None),
        ],
        ..Default::default()
    };
    let legacy_baseline = InMemoryStateEngine::new();
    legacy_baseline.enable_cross_shard();
    assert_eq!(
        legacy_baseline
            .record_legacy_escrow_receipts(&canonical_legacy_block, &[true, true])
            .await,
        2
    );
    assert_eq!(
        legacy_engine.get_state_root().await,
        legacy_baseline.get_state_root().await
    );

    // 2. XPC source prepare path mixed with legacy escrow + duplicates.
    let xpc_msgs = vec![
        CrossShardMessage::new_xpc(XPC_PREPARE, 1, 0, tx_inbound, [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            1,
            tx_not_in_block,
            [0u8; 32],
            [0u8; 32],
            None,
        ),
        CrossShardMessage::new_xpc(XPC_PREPARE, 0, 1, tx_failed, [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            1,
            tx_fail_dup_first.clone(),
            [0u8; 32],
            [0u8; 32],
            None,
        ),
        CrossShardMessage::new(0, 1, tx_legacy_mixed.clone(), [0u8; 32], [0u8; 32], None),
        CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            1,
            tx_ok_dup_first.clone(),
            [0u8; 32],
            [0u8; 32],
            None,
        ),
        CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            2,
            tx_ok_second.clone(),
            [0u8; 32],
            [0u8; 32],
            None,
        ),
        // Duplicate PREPARE for tx_ok_dup_first must be a no-op.
        CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            1,
            tx_ok_dup_first.clone(),
            [0u8; 32],
            [0u8; 32],
            None,
        ),
    ];
    let xpc_block = Block {
        shard_id: 0,
        height: 10,
        transactions,
        cross_shard_out: xpc_msgs,
        ..Default::default()
    };

    let xpc_engine = InMemoryStateEngine::new();
    xpc_engine.enable_cross_shard();
    let created = xpc_engine
        .apply_xpc_source_prepares(&xpc_block, &status)
        .await;
    assert_eq!(created, 2);
    assert!(xpc_engine
        .get_legacy_escrow_proof(&tx_legacy_mixed.compute_tx_hash())
        .await
        .is_some());
    assert!(xpc_engine
        .xpc_record(&tx_fail_dup_first.compute_tx_hash())
        .await
        .is_none());

    let canonical_xpc_block = Block {
        shard_id: 0,
        height: 10,
        transactions: vec![
            tx_legacy_mixed.clone(),
            tx_ok_dup_first.clone(),
            tx_ok_second.clone(),
        ],
        cross_shard_out: vec![
            CrossShardMessage::new(0, 1, tx_legacy_mixed, [0u8; 32], [0u8; 32], None),
            CrossShardMessage::new_xpc(
                XPC_PREPARE,
                0,
                1,
                tx_ok_dup_first,
                [0u8; 32],
                [0u8; 32],
                None,
            ),
            CrossShardMessage::new_xpc(XPC_PREPARE, 0, 2, tx_ok_second, [0u8; 32], [0u8; 32], None),
        ],
        ..Default::default()
    };
    let xpc_baseline = InMemoryStateEngine::new();
    xpc_baseline.enable_cross_shard();
    assert_eq!(
        xpc_baseline
            .apply_xpc_source_prepares(&canonical_xpc_block, &[true, true, true])
            .await,
        2
    );

    assert_eq!(
        xpc_engine.get_state_root().await,
        xpc_baseline.get_state_root().await
    );
    let snap_actual: Vec<_> = xpc_engine
        .xpc_snapshot()
        .await
        .into_iter()
        .map(|r| (r.tx_hash, r.phase, r.prepared_height, r.decided_height))
        .collect();
    let snap_expected: Vec<_> = xpc_baseline
        .xpc_snapshot()
        .await
        .into_iter()
        .map(|r| (r.tx_hash, r.phase, r.prepared_height, r.decided_height))
        .collect();
    assert_eq!(snap_actual, snap_expected);
}
