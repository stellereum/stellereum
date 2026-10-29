//! Integration tests covering all Stellereum core modules:
//! - Cell / Bag of Cells / Patricia Trie
//! - SVM & Micro-Gas Model
//! - CLOB Orderbook Actor
//! - zkML Proofs & Session Keys
//! - Selective Confidentiality (Pedersen Commitments & Stealth Addresses)
//! - 3-Tier Price Safety Network & Oracle
//! - Genesis Vault & Tokenomics
//! - MEV Preemption (Blind Rounds)
//! - Teleport Bridges (Locks & Quorum)
//! - Sharding & Cross-Shard Atomic Messages

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use stellereum::bridge::{SupportedChain, TeleportBridgeEngine, TeleportDepositEvent};
    use stellereum::cell::{BagOfCells, Cell, PatriciaTrie};
    use stellereum::crypto_privacy::{
        ConfidentialTransfer, PedersenCommitment, StealthAddress, ViewingKey,
    };
    use stellereum::mev::MevPreemptionEngine;
    use stellereum::oracle::{OracleSafetyEngine, PriceFeedUpdate};
    use stellereum::orderbook::{OrderSide, OrderbookActor};
    use stellereum::sharding::{
        Block, CrossShardMessage, DynamicShardManager, SharedLiquidityHub, Transaction,
        MASTERCHAIN_SHARD,
    };
    use stellereum::state_engine::{AccountState, InMemoryStateEngine};
    use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult, GAS_BASIC_TRANSFER};
    use stellereum::tokenomics::{GenesisVault, TeamVestingSchedule, GENESIS_VAULT_CAP};
    use stellereum::zkml::{
        QuantizedLayer, QuantizedLinearModel, SessionKeyAuthorization, ZkMlProof,
    };

    #[test]
    fn test_cells_and_patricia_trie() {
        let mut trie = PatriciaTrie::new();
        let key1 = [1u8; 32];
        let val1 = b"value_cell_one";
        let key2 = [2u8; 32];
        let val2 = b"value_cell_two";

        trie.insert(&key1, val1);
        let root1 = trie.root_hash();
        assert_ne!(root1, [0u8; 32]);

        trie.insert(&key2, val2);
        let root2 = trie.root_hash();
        assert_ne!(root1, root2);

        // Test Cryptographic Merkle Inclusion Proof
        let proof1 = trie
            .generate_merkle_proof(&key1)
            .expect("Failed to generate Merkle proof");
        assert!(PatriciaTrie::verify_merkle_proof(
            &root2, &key1, val1, &proof1
        ));

        // Test tamper detection in Merkle proof
        assert!(!PatriciaTrie::verify_merkle_proof(
            &root2,
            &key1,
            b"tampered_value",
            &proof1
        ));

        // Test Canonical BoC DAG chunking & binary serialization
        let large_payload = vec![42u8; 350]; // Spans across multiple 128-byte cells
        let (boc, root_cell) = Cell::from_bytes(&large_payload);
        assert!(boc.cells.len() >= 3);

        let reconstructed = boc
            .read_bytes(&root_cell)
            .expect("Failed to read cell chain");
        assert_eq!(reconstructed, large_payload);

        let boc_bytes = boc.to_boc_bytes();
        let deserialized_boc =
            BagOfCells::from_boc_bytes(&boc_bytes).expect("Failed to deserialize BoC bytes");
        let roundtrip = deserialized_boc
            .read_bytes(&root_cell)
            .expect("Failed to read deserialized BoC");
        assert_eq!(roundtrip, large_payload);
    }

    #[tokio::test]
    async fn test_actor_model_and_bounce_semantics() {
        let state_engine = InMemoryStateEngine::new();
        let alice = [101u8; 32];
        let bob = [102u8; 32];
        let non_existent = [255u8; 32];

        state_engine
            .update_account(AccountState::new(alice, 10_000))
            .await;
        state_engine.update_account(AccountState::new(bob, 0)).await;

        // 1. Send message from Alice to Bob
        let msg = stellereum::state_engine::ActorMessage::new(
            alice,
            bob,
            2_500,
            b"internal_call".to_vec(),
            true,
        );
        state_engine.send_message(msg).await.unwrap();

        // Alice's balance deducted immediately
        let alice_acc = state_engine.get_account(&alice).await.unwrap();
        assert_eq!(alice_acc.balance, 7_500);

        // Bob has 1 pending message in inbox
        let bob_acc = state_engine.get_account(&bob).await.unwrap();
        assert_eq!(bob_acc.inbox.len(), 1);

        // Step execution processes inboxes
        let processed = state_engine.step_actor_execution().await.unwrap();
        assert_eq!(processed, 1);
        let bob_after = state_engine.get_account(&bob).await.unwrap();
        assert_eq!(bob_after.balance, 2_500);

        // 2. Test TON-style bounce semantics: send to non-existent actor with bounce=true
        let bounce_target_msg = stellereum::state_engine::ActorMessage::new(
            alice,
            non_existent,
            3_000,
            b"will_bounce".to_vec(),
            true,
        );
        state_engine.send_message(bounce_target_msg).await.unwrap();

        // After send: value is in-flight inside the bounce message (not yet credited)
        let alice_mid = state_engine.get_account(&alice).await.unwrap();
        assert_eq!(
            alice_mid.balance, 4_500,
            "value is in-flight until the bounce is processed"
        );
        assert_eq!(alice_mid.inbox.len(), 1);
        assert!(alice_mid.inbox[0].bounced);

        // Processing the bounce credits the value back exactly once
        state_engine.step_actor_execution().await.unwrap();
        let alice_after_bounce = state_engine.get_account(&alice).await.unwrap();
        assert_eq!(
            alice_after_bounce.balance, 7_500,
            "bounce returns funds exactly once"
        );
    }

    #[test]
    fn test_block_quorum_and_consensus_signatures() {
        let val1 = SigningKey::generate(&mut OsRng);
        let val2 = SigningKey::generate(&mut OsRng);
        let val3 = SigningKey::generate(&mut OsRng);

        let mut block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 42,
            prev_hash: [1u8; 32],
            state_root: [2u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1234567,
            proposer: val1.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };

        // Sign with 2 validators out of 3
        block.sign_block(&val1);
        block.sign_block(&val2);

        // Quorum 2 succeeds
        assert!(block.verify_signatures(2));
        // Quorum 3 fails
        assert!(!block.verify_signatures(3));

        // Sign with 3rd validator
        block.sign_block(&val3);
        assert!(block.verify_signatures(3));
    }

    #[test]
    fn test_svm_micro_gas_and_transfers() {
        let sender = [5u8; 32];
        let recipient = [6u8; 32];
        let mut orderbooks = std::collections::HashMap::new();
        orderbooks.insert(1, OrderbookActor::new(1, 100));

        let mut ctx = VmContext {
            sender,
            balance: 10_000,
            orderbooks: Some(&mut orderbooks),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            pmm: None,
            zkml_proof: None,
            timestamp: 1000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
            default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
            payouts: Vec::new(),
            oracle: None,
        };

        let ops = vec![
            OpCode::LoadBalance,
            OpCode::Push(100),
            OpCode::Add,
            OpCode::Transfer {
                recipient,
                amount: 500,
            },
            OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: 1_000_000, // 1 USD
                amount: 200,
            },
        ];

        let res = Svm::execute(&ops, 500_000, &mut ctx);
        match res {
            VmExecutionResult::Success {
                gas_used,
                return_value,
                new_balance,
                transfers,
                ..
            } => {
                assert!(gas_used >= GAS_BASIC_TRANSFER);
                assert_eq!(return_value, Some(1)); // Order ID 1
                assert_eq!(new_balance, 10_000 - 500 - 200);
                assert_eq!(transfers.len(), 1);
                assert_eq!(transfers[0].1, 500);
            }
            other => panic!("Execution failed: {:?}", other),
        }
    }

    #[test]
    fn test_clob_orderbook_matching() {
        let mut book = OrderbookActor::new(1, 100);
        let trader_a = [10u8; 32];
        let trader_b = [11u8; 32];

        // Trader A places limit sell: 10 units @ price 100
        let (sell_order, trades) = book.submit_order(trader_a, OrderSide::Sell, 100, 10, 1000);
        assert_eq!(trades.len(), 0);
        assert_eq!(sell_order.filled, 0);

        // Trader B places buy order: 6 units @ price 100
        let (buy_order, trades) = book.submit_order(trader_b, OrderSide::Buy, 100, 6, 1005);
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].amount, 6);
        assert_eq!(trades[0].price, 100);
        assert_eq!(buy_order.filled, 6);

        // Cancel remaining 4 units of Trader A's order
        let cancelled = book.cancel_order(sell_order.order_id);
        assert!(cancelled.is_some());
        assert_eq!(cancelled.unwrap().filled, 6);
    }

    #[test]
    fn test_zkml_and_session_keys() {
        let master_key = SigningKey::generate(&mut OsRng);
        let session_key = SigningKey::generate(&mut OsRng);
        let session_pub = session_key.verifying_key().to_bytes();
        let valid_until = 4_000_000_000;
        let max_gas = 100_000;

        let mut auth = SessionKeyAuthorization::sign_delegation(
            &master_key,
            session_pub,
            valid_until,
            max_gas,
            stellereum::zkml::SCOPE_ALL,
            u64::MAX,
            0,
        );
        assert!(auth.verify());

        // Test gas budgeting
        assert!(auth.verify_and_spend_gas(5_000, 1_000).is_ok());
        assert_eq!(auth.gas_spent, 5_000);

        // Test session key transaction signature verification
        let sample_tx = b"bot_arbitrage_trade_payload";
        let sig = session_key.sign(sample_tx);
        assert!(auth.verify_session_signature(sample_tx, sig.to_bytes().as_ref()));

        // Real zkML Verifiable Proof test: 2-input -> 2-output Linear + ReLU layer
        let weights = vec![2, -1, 1, 3]; // [ [2, -1], [1, 3] ]
        let biases = vec![1, -2];
        let layer = QuantizedLayer::new(2, 2, weights, biases);
        let model = QuantizedLinearModel::new(vec![layer]);

        let inputs = vec![3i64, 4i64];
        // z[0] = 3*2 + 4*1 + 1 = 11; a[0] = max(0, 11) = 11
        // z[1] = 3*(-1) + 4*3 - 2 = 7; a[1] = max(0, 7) = 7
        let (outputs, proof) = ZkMlProof::prove_reexec(&model, &inputs);
        assert_eq!(outputs, vec![11, 7]);
        assert!(proof.verify_inference());
    }

    #[test]
    fn test_pedersen_commitments_and_stealth_addresses() {
        let r1 = PedersenCommitment::random_blinding();
        let r2 = PedersenCommitment::random_blinding();

        let c1 = PedersenCommitment::commit(500, &r1);
        let c2 = PedersenCommitment::commit(300, &r2);
        assert!(c1.verify(500, &r1));

        let c_sum = c1.add(&c2).expect("Homomorphic addition failed");
        let r_sum = r1 + r2;
        assert!(c_sum.verify(800, &r_sum));

        // Confidential Transfer balance conservation test:
        // Input: 500 + 300 = 800.
        // Output: 750 with blinding r_out. Fee: 50.
        // Blinding conservation: r_out = r1 + r2.
        let r_out = r1 + r2;
        let c_out = PedersenCommitment::commit(750, &r_out);
        let transfer = ConfidentialTransfer::new(vec![c1, c2], vec![c_out], 50);
        assert!(transfer.verify_balance_conservation());

        // Stealth Address
        let view_priv = Scalar::random(&mut OsRng);
        let view_pub = (curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * view_priv)
            .compress()
            .to_bytes();

        let spend_priv = Scalar::random(&mut OsRng);
        let spend_pub = (curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * spend_priv)
            .compress()
            .to_bytes();

        let stealth = StealthAddress::generate(&view_pub, &spend_pub).unwrap();
        let is_mine = stealth.is_for_recipient(&view_priv, &spend_pub).unwrap();
        assert!(is_mine);

        // Viewing Key Audit test
        let auditor_vk = ViewingKey::generate();
        let blind_audit = PedersenCommitment::random_blinding();
        let enc_payload =
            ViewingKey::encrypt_amount_for_auditor(&auditor_vk.view_pub, 12_500, &blind_audit)
                .unwrap();
        let (dec_val, dec_blind) = auditor_vk.decrypt_amount(&enc_payload).unwrap();
        assert_eq!(dec_val, 12_500);
        assert_eq!(dec_blind, blind_audit);
    }

    #[test]
    fn test_oracle_3_tier_safety_network() {
        let oracle_key = SigningKey::generate(&mut OsRng);
        let oracle_pub = oracle_key.verifying_key().to_bytes();

        let mut engine = OracleSafetyEngine::new(vec![oracle_pub]);
        engine.set_dex_twap("TON", 5_000_000); // $5.00

        let now = 10_000;
        let update = PriceFeedUpdate::sign("TON", 5_100_000, now, &oracle_key);

        // Tier 1 resolution
        let resolved = engine.resolve_price(Some(&update), "TON", now).unwrap();
        assert_eq!(resolved, 5_100_000);

        // Circuit breaker on depeg USDT
        let bad_usdt = PriceFeedUpdate::sign("USDT", 920_000, now, &oracle_key); // $0.92
        let depeg_res = engine.resolve_price(Some(&bad_usdt), "USDT", now);
        assert!(depeg_res.is_err());
        assert!(engine.circuit_breaker_triggered);
    }

    #[test]
    fn test_genesis_vault_minting() {
        let mut vault = GenesisVault::new();

        // 100 USDT ($100 USD) -> 400 STELL ($100 / $0.25)
        let minted = vault
            .deposit_and_mint("USDT", 100_000_000, 1_000_000)
            .unwrap();
        assert_eq!(minted, 400 * 1_000_000_000);
        assert!(vault.total_minted_nano <= GENESIS_VAULT_CAP);

        // Team Vesting test: 12m cliff, 24m linear
        let vesting = TeamVestingSchedule::new(1000);
        assert_eq!(vesting.unlocked_amount(1000 + 100), 0); // Before cliff
                                                            // 12 months after cliff + half of 24m vesting = 50% unlocked
        let half_vesting_time =
            1000 + vesting.cliff_duration_secs + vesting.vesting_duration_secs / 2;
        let unlocked = vesting.unlocked_amount(half_vesting_time);
        assert_eq!(unlocked, vesting.total_allocation / 2);
    }

    #[test]
    fn test_teleport_bridge_gateway() {
        let val1 = SigningKey::generate(&mut OsRng);
        let val2 = SigningKey::generate(&mut OsRng);
        let val3 = SigningKey::generate(&mut OsRng);

        let v1_pub = val1.verifying_key().to_bytes();
        let v2_pub = val2.verifying_key().to_bytes();
        let v3_pub = val3.verifying_key().to_bytes();

        let mut bridge = TeleportBridgeEngine::new(vec![v1_pub, v2_pub, v3_pub]);

        // Create deposit event from TON
        let source_tx = [77u8; 32];
        let recipient = [88u8; 32];
        let asset = "USDT".to_string();
        let amount: u64 = 10_000 * 1_000_000_000; // 10,000 STELL

        // Sign via the canonical message (includes the chain tag since C8).
        let proto = TeleportDepositEvent {
            source_chain: SupportedChain::Ton,
            source_tx_hash: source_tx,
            recipient,
            asset: asset.clone(),
            amount,
            validator_signatures: vec![],
            zk_proof: None,
        };
        let msg = TeleportBridgeEngine::deposit_signing_message(&proto);

        let sig1 = val1.sign(&msg);
        let sig2 = val2.sign(&msg);

        let deposit_event = TeleportDepositEvent {
            source_chain: SupportedChain::Ton,
            source_tx_hash: source_tx,
            recipient,
            asset,
            amount,
            validator_signatures: vec![(v1_pub, sig1.to_vec()), (v2_pub, sig2.to_vec())],
            zk_proof: None,
        };

        // Quorum 2/3 succeeds
        let processed = bridge.process_deposit(&deposit_event);
        assert!(processed.is_ok());

        // Test large withdrawal time-lock (>50k STELL locked for 3600s)
        let large_amount = 60_000 * 1_000_000_000;
        let req_id = bridge
            .request_withdrawal(
                recipient,
                SupportedChain::Arbitrum,
                "0x1234567890abcdef".to_string(),
                large_amount,
                10_000,
            )
            .unwrap();

        // Attempting to finalize immediately fails due to time-lock
        assert!(bridge.finalize_withdrawal(req_id, 10_100).is_err());
        // Attempting to finalize after 3600s time-lock succeeds
        assert!(bridge.finalize_withdrawal(req_id, 10_000 + 3600).is_ok());
    }

    #[test]
    fn test_mev_threshold_blind_rounds() {
        let mut mev = MevPreemptionEngine::new();
        let val1 = SigningKey::generate(&mut OsRng);
        let val2 = SigningKey::generate(&mut OsRng);
        let val3 = SigningKey::generate(&mut OsRng);

        // Prepare 2-of-3 threshold blind round
        let (round_key, shares) = mev.prepare_threshold_round(1, 2, 3);
        assert_eq!(shares.len(), 3);

        let tx_data = b"raw_high_frequency_arb_tx";
        let envelope = MevPreemptionEngine::seal_transaction(1, &round_key, tx_data).unwrap();

        let commit =
            mev.commit_blind_round(1, std::slice::from_ref(&envelope), &[val1, val2, val3]);
        assert!(MevPreemptionEngine::verify_round_commitment(&commit, 2));

        // Reconstruct key with only 2 shares (shares[0] and shares[2])
        let partial_shares = vec![shares[0].clone(), shares[2].clone()];
        let decrypted_with_shares = mev.unseal_with_shares(&envelope, &partial_shares).unwrap();
        assert_eq!(decrypted_with_shares, tx_data);
    }

    #[tokio::test]
    async fn test_in_memory_state_and_sharding() {
        let state_engine = InMemoryStateEngine::new();
        let user = [99u8; 32];
        let mut acc_init = AccountState::new(user, 50_000_000);
        acc_init.nonce = 1;
        state_engine.update_account(acc_init).await;

        let acc = state_engine.get_account(&user).await.unwrap();
        assert_eq!(acc.balance, 50_000_000);

        let root = state_engine.get_state_root().await;
        assert_ne!(root, [0u8; 32]);

        // Dynamic Sharding split and merge test
        let mut shard_mgr = DynamicShardManager::new();
        // Record high load to trigger auto-split on shard 1
        shard_mgr.record_tx_load(1, 600);
        let split_res = shard_mgr.check_and_split(1);
        assert!(split_res.is_some());
        let (child0, child1) = split_res.unwrap();
        assert_eq!(child0.prefix_len, 1);
        assert_eq!(child1.prefix_len, 1);

        // Record low load and test merge
        let merged = shard_mgr.check_and_merge(child0.shard_id, child1.shard_id);
        assert!(merged.is_some());
        assert_eq!(merged.unwrap().prefix_len, 0);

        // Cross-shard message routing with Shared Sequencer
        let mut hub = SharedLiquidityHub::new(vec![0, 1]);
        let tx = Transaction {
            from: user,
            to: [77u8; 32],
            amount: 1_000,
            gas_limit: 1000,
            nonce: 1,
            source_shard: 0,
            target_shard: 1,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };

        let cross_msg = CrossShardMessage::new_trusted(0, 1, tx, root, [2u8; 32]);

        let seq = hub.route_cross_shard_message(cross_msg);
        assert_eq!(seq, 1);
        let inbound = hub.take_inbound_messages(1);
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].target_shard, 1);
    }
}
