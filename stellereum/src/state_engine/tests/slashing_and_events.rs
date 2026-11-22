use super::*;

#[tokio::test]
async fn test_sec03_downtime_slash_with_falcon_uqc() {
    use crate::consensus::{QuorumCertificate, VoteKind};
    use crate::staking::{DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // Four bonded validators: genuine quorum certificates need three of
    // four, so the offline member's absence is QUORUM-PROVEN by a QC that
    // still verifies (V-P34 R2: the old test fed garbage-marker QCs that
    // `verify` rejects — exactly the forgiveness hole — and asserted the
    // decode-only attribution. Genuine QCs only now).
    let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let (honest_id, offline_id) = (ids[0], ids[1]);
    let bond_amount = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;

    let engine = InMemoryStateEngine::new();
    for id in &ids {
        engine.credit_native(id, bond_amount * 2).await.unwrap();
        engine
            .staking_write()
            .await
            .bond(*id, bond_amount, 0)
            .unwrap();
    }
    engine
        .credit_native(&crate::staking::STAKING_POOL, bond_amount * 10)
        .await
        .unwrap();

    let vs = engine.staking_read().await.to_validator_set();
    assert_eq!(vs.len(), 4);

    // Genuine Falcon QC: honest + members 2,3 sign; offline misses.
    // FULL-PQ (mirrors `sync::tests::pq_cert_for`): a classical
    // `Vote::sign` QC no longer verifies, so the quorum is compiled from
    // genuine Falcon votes into a µQC (Ed list for power + Falcon
    // envelope for crypto) — the only form `QuorumCertificate::verify`
    // accepts. The parent is the zero hash (no chain parent in this unit
    // shape); the offline member (ids[1]) never signs, exactly as before.
    let fks: Vec<crate::post_quantum::FalconKeypair> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0xA0 + i as u8);
            crate::consensus::register_validator_pq_key(
                k.verifying_key().to_bytes(),
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect();
    let qc_without_offline = || {
        let mut set = crate::consensus::VoteSet::new();
        for &i in &[0usize, 2, 3] {
            let v = crate::consensus::Vote::sign_with_falcon(
                &keys[i],
                &fks[i],
                1,
                0,
                VoteKind::Precommit,
                Some([0xAA; 32]),
            );
            set.add(v, &vs, 1, 0, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some([0xAA; 32]), &vs, Some(&[0u8; 32]))
            .expect("quorum must compile a Falcon µQC")
    };
    assert!(
        qc_without_offline().verify(&vs),
        "3-of-4 genuine QC must verify and drive the slash path"
    );

    // Apply downtime slash for heights 1..=threshold - 1
    for h in 1..DOWNTIME_MISS_THRESHOLD as u64 {
        let burned = engine
            .apply_downtime_slash(h, Some(&qc_without_offline()))
            .await;
        assert_eq!(burned, 0);
        let ledger = engine.staking_read().await;
        assert_eq!(
            ledger.validators[&honest_id].missed, 0,
            "honest signer must NOT accumulate missed blocks"
        );
        assert_eq!(
            ledger.validators[&offline_id].missed, h as u32,
            "offline non-signer MUST accumulate missed blocks"
        );
    }

    // At threshold, offline validator gets slashed
    let burned = engine
        .apply_downtime_slash(DOWNTIME_MISS_THRESHOLD as u64, Some(&qc_without_offline()))
        .await;
    assert!(burned > 0, "offline validator must be slashed at threshold");
    {
        let ledger = engine.staking_read().await;
        assert_eq!(ledger.validators[&honest_id].missed, 0);
        assert_eq!(
            ledger.validators[&honest_id].total_slashed, 0,
            "honest validator must NEVER be slashed"
        );
        assert!(
            ledger.validators[&offline_id].total_slashed > 0,
            "offline validator must be slashed"
        );
    }

    // 2. Offline member comes back online and signs a genuine QC: the
    // streak is forgiven (missed resets to 0). Same FULL-PQ µQC shape,
    // now WITH the returning member (ids[1]) signing.
    let qc_with_offline = {
        let mut set = crate::consensus::VoteSet::new();
        for &i in &[1usize, 2, 3] {
            let v = crate::consensus::Vote::sign_with_falcon(
                &keys[i],
                &fks[i],
                20,
                0,
                VoteKind::Precommit,
                Some([0xBB; 32]),
            );
            set.add(v, &vs, 20, 0, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some([0xBB; 32]), &vs, Some(&[0u8; 32]))
            .expect("quorum must compile a Falcon µQC")
    };
    assert!(
        qc_with_offline.verify(&vs),
        "returning-member QC must verify"
    );
    engine
        .apply_downtime_slash(20, Some(&qc_with_offline))
        .await;
    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.validators[&offline_id].missed, 0,
        "signing a genuine QC forgives the missed streak"
    );

    // 3. Fail-closed: a REJECTED QC (garbage markers, no verifiable
    // quorum) moves NOBODY — neither forgiving the offline member nor
    // accusing the honest one. This is the V-P34 R2 hole pinned shut:
    // the old decode-only attribution forgave on this exact shape.
    let garbage_qc = QuorumCertificate {
        shard_id: 0,
        height: 21,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some([0xCC; 32]),
        signatures: vec![
            (
                crate::consensus::PQ_UQC_MARKER_ID,
                b"garbage-not-an-envelope".to_vec(),
            ),
            (honest_id, vec![0x77u8; 64]),
        ],
    };
    assert!(
        !garbage_qc.verify(&vs),
        "garbage-marker QC must be rejected"
    );
    assert!(garbage_qc.signers_set(&vs).is_empty());
    let missed_before: u32 = engine.staking_read().await.validators[&offline_id].missed;
    let honest_before: u32 = engine.staking_read().await.validators[&honest_id].missed;
    let burned = engine.apply_downtime_slash(21, Some(&garbage_qc)).await;
    assert_eq!(burned, 0, "rejected QC must burn nothing");
    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.validators[&offline_id].missed, missed_before,
        "rejected QC must accrue no misses"
    );
    assert_eq!(
        ledger.validators[&honest_id].missed, honest_before,
        "rejected QC must accuse nobody"
    );
}

#[tokio::test]
async fn test_sec07_free_failure_dos_charges_fee_and_increments_nonce() {
    use crate::sharding::{Block, MASTERCHAIN_SHARD};
    use crate::svm::OpCode;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let engine = InMemoryStateEngine::new();
    // FULL-PQ: transaction signers are Falcon-512 (implicit,
    // pre-registered, no surcharge). The block proposer key stays
    // classical: block-signature verification is outside tx admission.
    let (alice_addr, _alice_pk) = pq_pair(0xA1);
    let recipient = [0x55u8; 32];
    let proposer = SigningKey::generate(&mut OsRng);
    let proposer_addr = proposer.verifying_key().to_bytes();

    let initial_balance = 1_000_000u64;
    engine
        .credit_native(&alice_addr, initial_balance)
        .await
        .unwrap();

    // 1. Transaction that fails execution (e.g. out of gas)
    // Admitted because sender covers amount (0) + gas_limit (50_000).
    // Fails at execution because 100 gas cannot run a 280k basic transfer opcode.
    let gas_limit = 50_000u64;
    let (fail_tx, _, _) = pq_tx_payload(
        0xA1,
        recipient,
        0,
        gas_limit,
        0,
        vec![OpCode::Transfer {
            recipient: [0xCC; 32],
            amount: 1,
        }],
    );

    let transactions = vec![fail_tx.clone()];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 1000,
        proposer: proposer_addr,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
        round: 0,
    };
    block.sign_block(&proposer);

    let outcome = engine.apply_block_transition(&block, 0).await;

    // Verify:
    // 1. Status is "failed" (outcome.status[0] == false)
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert_eq!(outcome.status, vec![false], "receipt records status failed");
    // 2. fee_charged equals the fee (gas_limit)
    assert_eq!(
        outcome.tx_fees,
        vec![gas_limit],
        "receipt records actual fee_charged"
    );
    assert_eq!(outcome.fees_collected, gas_limit);

    // 3. Sender balance debited and nonce incremented
    let sender = engine.get_account(&alice_addr).await.unwrap();
    assert_eq!(
        sender.balance,
        initial_balance - gas_limit,
        "fee debited from sender"
    );
    assert_eq!(sender.nonce, 1, "sender nonce incremented");

    // 4. Conservation of value: under Ruleset v7 (`FEE_MARKET_V2 = 0`),
    // 50% of `gas_limit` is burned and the remainder goes to the proposer
    // (proposer is not an active validator so the 20% staking leg falls back to proposer).
    let burn1 = ((gas_limit as u128) * (crate::tokenomics::DEFAULT_FEE_BURN_BPS as u128)
        / (crate::staking::BPS_DENOMINATOR as u128)) as u64;
    let proposer_fee1 = gas_limit - burn1;
    let proposer_acc = engine.get_account(&proposer_addr).await.unwrap();
    assert_eq!(
        proposer_acc.balance, proposer_fee1,
        "proposer credited with post-burn share of failure fee"
    );
    assert_eq!(
        sender.balance + proposer_acc.balance + burn1,
        initial_balance,
        "funds conserved across sender, proposer, and burn"
    );

    // 5. Test sender whose balance drops below fee during execution:
    // Tx1 spends balance, Tx2 was admitted but now cannot cover the full fee.
    // Balance saturates to 0, nonce increments, and actual fee_charged equals debited amount.
    let alice_drain_seed = 0xA2u8;
    let (alice_drain_addr, _alice_drain_pk) = pq_pair(alice_drain_seed);
    let bob_addr = [0xB0; 32];
    // Under Ruleset v7 (`EXEC_HARDENING_V1 = 0`), Tx1 bills `TX_INTRINSIC_GAS` (280_000).
    // 1_000_000 - 600_000 - 280_000 = 120_000 left, below Tx2's 200_000 failure fee.
    engine
        .credit_native(&alice_drain_addr, 1_000_000)
        .await
        .unwrap();

    let (tx_drain, _, _) = pq_tx_payload(
        alice_drain_seed,
        recipient,
        0,
        500_000,
        0,
        vec![OpCode::Transfer {
            recipient: bob_addr,
            amount: 600_000,
        }],
    );
    // Tx2 is admitted against simulated remainder (1M - 500k = 500k >= 200k),
    // but at execution time Tx1 left only 120k balance.
    let (tx_broke, _, _) = pq_tx_payload(
        alice_drain_seed,
        recipient,
        0,
        200_000,
        1,
        vec![OpCode::Transfer {
            recipient: [0xCC; 32],
            amount: 1,
        }],
    );

    let transactions = vec![tx_drain, tx_broke];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut block2 = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 2,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 1001,
        proposer: proposer_addr,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
        round: 0,
    };
    block2.sign_block(&proposer);

    let outcome2 = engine.apply_block_transition(&block2, 0).await;
    assert_eq!(outcome2.applied, 1);
    assert_eq!(outcome2.failed, 1);
    assert_eq!(outcome2.status, vec![true, false]);
    let tx1_fee = InMemoryStateEngine::TX_INTRINSIC_GAS;
    assert_eq!(
        outcome2.tx_fees,
        vec![tx1_fee, 0],
        "an uncoverable failure fee moves nothing"
    );
    assert_eq!(outcome2.fees_collected, tx1_fee);

    let sender_drain = engine.get_account(&alice_drain_addr).await.unwrap();
    assert_eq!(
        sender_drain.balance,
        1_000_000 - 600_000 - tx1_fee,
        "the dust is not drained by an uncoverable failure"
    );
    assert_eq!(sender_drain.nonce, 1, "no pay, no advance: nonce untouched");

    let bob = engine.get_account(&bob_addr).await.unwrap();
    assert_eq!(bob.balance, 600_000);

    let burn2 = ((tx1_fee as u128) * (crate::tokenomics::DEFAULT_FEE_BURN_BPS as u128)
        / (crate::staking::BPS_DENOMINATOR as u128)) as u64;
    let proposer_fee2 = tx1_fee - burn2;
    let proposer_acc2 = engine.get_account(&proposer_addr).await.unwrap();
    assert_eq!(proposer_acc2.balance, proposer_fee1 + proposer_fee2);

    // Value conservation: the drain sender's 1M is the sender's remainder +
    // bob's 600k + proposer's fee share + burn for THIS block.
    assert_eq!(
        sender_drain.balance + bob.balance + proposer_fee2 + burn2,
        1_000_000,
        "funds conserved: every debit arrived somewhere"
    );
}

#[tokio::test]
async fn test_block_execution_collects_contract_events() {
    let engine = InMemoryStateEngine::new();
    let sk_seed = 0xA3u8;
    let (from, _pk) = pq_pair(sk_seed);
    engine
        .update_account(AccountState::new(from, 10_000_000))
        .await;

    let code = wat::parse_str(
        r#"(module
             (import "host" "emit" (func $emit (param i64 i64)))
             (func (export "emit_val") (param $val i64) (result i64)
               (call $emit (i64.const 999) (local.get $val))
               (local.get $val)))"#,
    )
    .unwrap();

    let contract_addr = engine.deploy_contract(from, code, 100).await.unwrap();

    let (tx, _, _) = pq_tx_payload(
        sk_seed,
        contract_addr,
        0,
        500_000,
        0,
        vec![crate::svm::OpCode::SysCallCallContract {
            contract: contract_addr,
            method: b"emit_val".to_vec(),
            arg: 12345,
        }],
    );

    let proposer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let transactions = vec![tx];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut block = crate::sharding::Block {
        shard_id: crate::sharding::MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 1000,
        proposer: proposer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
        round: 0,
    };
    block.sign_block(&proposer);

    let outcome = engine.apply_block_transition(&block, 0).await;
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.status, vec![true]);
    assert_eq!(outcome.events.len(), 1);
    assert_eq!(outcome.events[0].len(), 1);
    assert_eq!(outcome.events[0][0].contract, contract_addr);
    assert_eq!(outcome.events[0][0].topic, 999);
    assert_eq!(outcome.events[0][0].value, 12345);
}

/// SLASH-02: the engine-side slash debit is fail-CLOSED and LOUD, never a
/// dropped `let _ =`.
///
/// The scenario is the one the finding describes: the ledger removes the
/// stake (and counts it in `total_burned`), but the backing pool cannot fund
/// the debit (here: it was already drained, i.e. the state was drifted before
/// the slash). The contract under test:
///
///  * the caller is told what ACTUALLY left the pool, not what the ledger
///    claimed;
///  * the pool is never over-drawn (it ends at exactly 0);
///  * `total_burned` is repaired down by the unbacked shortfall, so the
///    committed supply counter never claims coins that did not move.
#[tokio::test]
async fn slash_pool_shortfall_is_capped_reported_and_never_silent() {
    use crate::consensus::{QuorumCertificate, VoteKind};
    use crate::staking::{DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND, STAKING_POOL};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let offline_id = ids[1];
    let bond_amount = MIN_VALIDATOR_BOND + crate::staking::STELL_MIN_BOND_BUFFER;

    let engine = InMemoryStateEngine::new();
    for id in &ids {
        engine.credit_native(id, bond_amount * 2).await.unwrap();
        engine
            .staking_write()
            .await
            .bond(*id, bond_amount, 0)
            .unwrap();
    }
    // Fund the pool with the real bonds (the ledger is ledger-only; these
    // tests move the native side by hand).
    engine
        .credit_native(&STAKING_POOL, 4 * bond_amount)
        .await
        .unwrap();

    let vs = engine.staking_read().await.to_validator_set();
    let fks: Vec<crate::post_quantum::FalconKeypair> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0x30 + i as u8);
            crate::consensus::register_validator_pq_key(
                k.verifying_key().to_bytes(),
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect();
    let qc_without_offline = || -> QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for &i in &[0usize, 2, 3] {
            let v = crate::consensus::Vote::sign_with_falcon(
                &keys[i],
                &fks[i],
                1,
                0,
                VoteKind::Precommit,
                Some([0xAA; 32]),
            );
            set.add(v, &vs, 1, 0, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some([0xAA; 32]), &vs, Some(&[0u8; 32]))
            .expect("quorum must compile a Falcon µQC")
    };

    for h in 1..DOWNTIME_MISS_THRESHOLD as u64 {
        assert_eq!(
            engine
                .apply_downtime_slash(h, Some(&qc_without_offline()))
                .await,
            0
        );
    }

    // DRIFT: the pool is drained to 1 nano — far below the ~10^9-nano burn
    // the ledger is about to claim.
    let pool_balance = engine.get_account(&STAKING_POOL).await.unwrap().balance;
    engine
        .debit_native(&STAKING_POOL, pool_balance - 1)
        .await
        .expect("drain the pool to one nano");

    let burned = engine
        .apply_downtime_slash(DOWNTIME_MISS_THRESHOLD as u64, Some(&qc_without_offline()))
        .await;

    // What the ledger CLAIMED (its own counter) is far larger than what the
    // pool could fund.
    let ledger = engine.staking_read().await;
    let claimed = ledger.validators[&offline_id].total_slashed;
    assert!(
        claimed > 1,
        "precondition: the ledger claims a slash larger than the pool holds"
    );
    assert_eq!(
        burned, 1,
        "SLASH-02: the caller is told what actually left the pool"
    );
    assert_eq!(
        ledger.total_burned, 1,
        "SLASH-02: the committed burn counter is repaired by the unbacked shortfall"
    );
    drop(ledger);
    assert_eq!(
        engine.get_account(&STAKING_POOL).await.unwrap().balance,
        0,
        "the pool is taken to exactly zero, never over-drawn"
    );
}
