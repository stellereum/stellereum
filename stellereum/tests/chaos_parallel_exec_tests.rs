//! Chaos, Adversarial, and Differential Tests for Parallel Execution Engine.
//!
//! Verifies strict equivalence between sequential execution (`engine.set_parallel_exec(false)`)
//! and parallel execution (`engine.set_parallel_exec(true)`), including:
//! - 50 randomized chaos blocks with varying sizes, duplicate nonces, balance exhaustion, self-transfers
//! - Multi-wave sender conflict ordering and nonce sequence preservation without races
//! - Clean balance depletion across waves with atomic rollback and status match
//! - Mixed STS token and CLOB limit/cancel orders with resource isolation and deterministic barrier handling
//! - Cyclic transaction chains (A->B->C->A) across waves with deadlock-freedom and determinism

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

use stellereum::parallel_exec::DisjointScheduler;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};

const STELL: u64 = 1_000_000_000;

fn token_meta(name: &str, symbol: &str) -> TokenMetadata {
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

fn new_engine(parallel: bool) -> InMemoryStateEngine {
    let engine = InMemoryStateEngine::new();
    engine.set_parallel_exec(parallel);
    engine
}

async fn fund_engine(engine: &InMemoryStateEngine, keys: &[SigningKey], initial_bal: u64) {
    for sk in keys {
        let addr = sk.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(addr, initial_bal))
            .await;
    }
}

// ---------------------------------------------------------------------------
// TEST 1: fuzz_random_blocks_bit_identical_roots
// ---------------------------------------------------------------------------
#[tokio::test]
async fn fuzz_random_blocks_bit_identical_roots() {
    let mut rng = StdRng::seed_from_u64(0x42_1337_CAFE_BABE);

    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    // Pool of 30 senders with heterogeneous balances
    let num_senders = 30;
    let senders: Vec<SigningKey> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();

    // 10 external recipient addresses (not senders)
    let external_recipients: Vec<[u8; 32]> = (0..10)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    let shared_recipient = external_recipients[0];

    // Seed balances in both engines identically
    for (i, sk) in senders.iter().enumerate() {
        let addr = sk.verifying_key().to_bytes();
        let bal = if i < 15 {
            50_000_000u64 // Wealthy
        } else if i < 23 {
            500_000u64 // Moderate
        } else if i < 27 {
            5_000u64 // Low / tight
        } else {
            0u64 // Zero balance
        };
        engine_seq
            .update_account(AccountState::new(addr, bal))
            .await;
        engine_par
            .update_account(AccountState::new(addr, bal))
            .await;
    }

    let mut total_self_transfers = 0usize;
    let mut total_balance_exhausting = 0usize;
    let mut total_duplicate_nonces = 0usize;
    let mut total_shared_recipients = 0usize;
    let mut total_gapped_nonces = 0usize;
    let mut total_txs_executed = 0usize;

    // Generate and execute 50 randomized blocks
    let num_blocks = 50;
    for block_idx in 0..num_blocks {
        // Varying block sizes across 10..200
        let block_size: usize = match block_idx % 5 {
            0 => rng.gen_range(10..=30),
            1 => rng.gen_range(30..=80),
            2 => rng.gen_range(80..=130),
            3 => rng.gen_range(130..=200),
            _ => rng.gen_range(15..=150),
        };

        // Query starting nonces and balances for this block
        let mut sim_nonce: HashMap<[u8; 32], u64> = HashMap::new();
        let mut sim_bal: HashMap<[u8; 32], u64> = HashMap::new();
        for sk in &senders {
            let addr = sk.verifying_key().to_bytes();
            let acc = engine_seq
                .get_account(&addr)
                .await
                .unwrap_or_else(|| AccountState::new(addr, 0));
            sim_nonce.insert(addr, acc.nonce);
            sim_bal.insert(addr, acc.balance);
        }

        let mut txs = Vec::with_capacity(block_size);

        for _ in 0..block_size {
            let archetype = rng.gen_range(0..100);

            if archetype < 35 {
                // 1. Plain valid transfer
                let s_idx = rng.gen_range(0..senders.len());
                let sk = &senders[s_idx];
                let from = sk.verifying_key().to_bytes();
                let nonce = *sim_nonce.get(&from).unwrap_or(&0);

                let to = if rng.gen_bool(0.5) {
                    let r_idx = rng.gen_range(0..senders.len());
                    senders[r_idx].verifying_key().to_bytes()
                } else {
                    let e_idx = rng.gen_range(0..external_recipients.len());
                    external_recipients[e_idx]
                };

                let amount = rng.gen_range(1..=100);
                let gas_limit = rng.gen_range(0..=15);
                txs.push(Transaction::sign(sk, to, amount, gas_limit, nonce, 1, 1));

                sim_nonce.insert(from, nonce + 1);
                let cur = *sim_bal.get(&from).unwrap_or(&0);
                sim_bal.insert(from, cur.saturating_sub(amount + gas_limit));
            } else if archetype < 50 {
                // 2. Self-transfer A -> A
                let s_idx = rng.gen_range(0..senders.len());
                let sk = &senders[s_idx];
                let from = sk.verifying_key().to_bytes();
                let nonce = *sim_nonce.get(&from).unwrap_or(&0);

                let amount = rng.gen_range(1..=50);
                let gas_limit = rng.gen_range(0..=10);
                txs.push(Transaction::sign(sk, from, amount, gas_limit, nonce, 1, 1));

                total_self_transfers += 1;
                sim_nonce.insert(from, nonce + 1);
                let cur = *sim_bal.get(&from).unwrap_or(&0);
                sim_bal.insert(from, cur.saturating_sub(gas_limit));
            } else if archetype < 65 {
                // 3. Shared recipient transfer
                let s_idx = rng.gen_range(0..senders.len());
                let sk = &senders[s_idx];
                let from = sk.verifying_key().to_bytes();
                let nonce = *sim_nonce.get(&from).unwrap_or(&0);

                let amount = rng.gen_range(1..=50);
                let gas_limit = rng.gen_range(0..=10);
                txs.push(Transaction::sign(
                    sk,
                    shared_recipient,
                    amount,
                    gas_limit,
                    nonce,
                    1,
                    1,
                ));

                total_shared_recipients += 1;
                sim_nonce.insert(from, nonce + 1);
                let cur = *sim_bal.get(&from).unwrap_or(&0);
                sim_bal.insert(from, cur.saturating_sub(amount + gas_limit));
            } else if archetype < 78 {
                // 4. Balance-exhausting transaction
                let s_idx = rng.gen_range(0..senders.len());
                let sk = &senders[s_idx];
                let from = sk.verifying_key().to_bytes();
                let nonce = *sim_nonce.get(&from).unwrap_or(&0);
                let cur_bal = *sim_bal.get(&from).unwrap_or(&0);

                let to = external_recipients[rng.gen_range(0..external_recipients.len())];
                let amount = cur_bal.saturating_add(rng.gen_range(1..=50_000));
                let gas_limit = 10;
                txs.push(Transaction::sign(sk, to, amount, gas_limit, nonce, 1, 1));

                total_balance_exhausting += 1;
                // Don't advance sim_nonce or balance since it will fail
            } else if archetype < 88 {
                // 5. Duplicate nonce (reuse current nonce without advancing)
                let s_idx = rng.gen_range(0..senders.len());
                let sk = &senders[s_idx];
                let from = sk.verifying_key().to_bytes();
                let nonce = *sim_nonce.get(&from).unwrap_or(&0);

                let to = external_recipients[rng.gen_range(0..external_recipients.len())];
                let amount = rng.gen_range(1..=20);
                let gas_limit = 5;
                txs.push(Transaction::sign(sk, to, amount, gas_limit, nonce, 1, 1));

                total_duplicate_nonces += 1;
            } else if archetype < 95 {
                // 6. Gapped nonce
                let s_idx = rng.gen_range(0..senders.len());
                let sk = &senders[s_idx];
                let from = sk.verifying_key().to_bytes();
                let nonce = *sim_nonce.get(&from).unwrap_or(&0);

                let to = external_recipients[rng.gen_range(0..external_recipients.len())];
                let amount = rng.gen_range(1..=20);
                let gas_limit = 5;
                txs.push(Transaction::sign(
                    sk,
                    to,
                    amount,
                    gas_limit,
                    nonce + rng.gen_range(5..=50),
                    1,
                    1,
                ));

                total_gapped_nonces += 1;
            } else {
                // 7. Unfunded sender
                let fresh_key = SigningKey::generate(&mut rng);
                let to = external_recipients[0];
                txs.push(Transaction::sign(&fresh_key, to, 10, 10, 0, 1, 1));
            }
        }

        total_txs_executed += txs.len();

        let timestamp = 1_700_000_000 + (block_idx as u64) * 100;
        let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
        let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

        // Differential assertions:
        assert_eq!(
            res_seq.0, res_par.0,
            "Block {block_idx}: applied count mismatch (seq: {}, par: {})",
            res_seq.0, res_par.0
        );
        assert_eq!(
            res_seq.1, res_par.1,
            "Block {block_idx}: failed count mismatch (seq: {}, par: {})",
            res_seq.1, res_par.1
        );
        assert_eq!(
            res_seq.2, res_par.2,
            "Block {block_idx}: fees_collected mismatch (seq: {}, par: {})",
            res_seq.2, res_par.2
        );
        assert_eq!(
            res_seq.3, res_par.3,
            "Block {block_idx}: status array mismatch"
        );
        assert_eq!(
            res_seq.4, res_par.4,
            "Block {block_idx}: fees array mismatch"
        );

        // State roots must be bit-identical!
        let root_seq = engine_seq.get_state_root().await;
        let root_par = engine_par.get_state_root().await;
        assert_eq!(
            root_seq, root_par,
            "Block {block_idx}: state root mismatch between seq and par"
        );

        // Cross-verify all sender accounts
        for sk in &senders {
            let addr = sk.verifying_key().to_bytes();
            let a_seq = engine_seq.get_account(&addr).await;
            let a_par = engine_par.get_account(&addr).await;
            assert_eq!(
                a_seq.as_ref().map(|a| (a.balance, a.nonce)),
                a_par.as_ref().map(|a| (a.balance, a.nonce)),
                "Block {block_idx}: sender account mismatch for {:?}",
                hex::encode(&addr[..4]),
            );
        }
    }

    // Verify chaos diversity coverage
    assert!(
        total_self_transfers > 0,
        "chaos must include self transfers"
    );
    assert!(
        total_balance_exhausting > 0,
        "chaos must include balance exhausting txs"
    );
    assert!(
        total_duplicate_nonces > 0,
        "chaos must include duplicate nonces"
    );
    assert!(
        total_shared_recipients > 0,
        "chaos must include shared recipients"
    );
    assert!(total_gapped_nonces > 0, "chaos must include gapped nonces");
    assert!(
        total_txs_executed >= 2500,
        "executed adequate chaos transactions"
    );
}

// ---------------------------------------------------------------------------
// TEST 2: parallel_exec_sender_conflict_exact_ordering
// ---------------------------------------------------------------------------
#[tokio::test]
async fn parallel_exec_sender_conflict_exact_ordering() {
    let mut rng = StdRng::seed_from_u64(0x1122_3344_5566_7788);

    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    let alice = SigningKey::generate(&mut rng);
    let bob = SigningKey::generate(&mut rng);
    let charlie = SigningKey::generate(&mut rng);
    let dave = SigningKey::generate(&mut rng);

    let alice_addr = alice.verifying_key().to_bytes();
    let bob_addr = bob.verifying_key().to_bytes();
    let charlie_addr = charlie.verifying_key().to_bytes();
    let dave_addr = dave.verifying_key().to_bytes();

    let r1 = SigningKey::generate(&mut rng).verifying_key().to_bytes();
    let r2 = SigningKey::generate(&mut rng).verifying_key().to_bytes();
    let r3 = SigningKey::generate(&mut rng).verifying_key().to_bytes();
    let r4 = SigningKey::generate(&mut rng).verifying_key().to_bytes();

    let initial_bal = 10_000_000u64;
    fund_engine(
        &engine_seq,
        &[alice.clone(), bob.clone(), charlie.clone(), dave.clone()],
        initial_bal,
    )
    .await;
    fund_engine(
        &engine_par,
        &[alice.clone(), bob.clone(), charlie.clone(), dave.clone()],
        initial_bal,
    )
    .await;

    // Block with multiple transactions from same sender (Alice: nonce 0, 1, 2)
    // mixed with disjoint senders (Bob: 0, 1, 2; Charlie: 0, 1; Dave: 0)
    let txs = vec![
        // Wave 0 candidates (disjoint senders, each nonce 0)
        Transaction::sign(&alice, r1, 100, 10, 0, 1, 1), // 0: Alice nonce 0
        Transaction::sign(&bob, r2, 200, 10, 0, 1, 1),   // 1: Bob nonce 0
        Transaction::sign(&charlie, r3, 300, 10, 0, 1, 1), // 2: Charlie nonce 0
        Transaction::sign(&dave, r4, 400, 10, 0, 1, 1),  // 3: Dave nonce 0
        // Wave 1 candidates (sender conflicts with Wave 0, nonce 1)
        Transaction::sign(&alice, r2, 110, 10, 1, 1, 1), // 4: Alice nonce 1
        Transaction::sign(&bob, r3, 210, 10, 1, 1, 1),   // 5: Bob nonce 1
        Transaction::sign(&charlie, r4, 310, 10, 1, 1, 1), // 6: Charlie nonce 1
        // Wave 2 candidates (sender conflicts with Wave 1, nonce 2)
        Transaction::sign(&alice, r3, 120, 10, 2, 1, 1), // 7: Alice nonce 2
        Transaction::sign(&bob, r4, 220, 10, 2, 1, 1),   // 8: Bob nonce 2
    ];

    // Verify wave scheduling structure: exactly 3 waves
    let waves = DisjointScheduler::schedule(&txs);
    assert_eq!(waves.len(), 3, "must schedule into exactly 3 waves");
    assert_eq!(waves[0], vec![0, 1, 2, 3], "Wave 0: initial disjoint set");
    assert_eq!(waves[1], vec![4, 5, 6], "Wave 1: second nonce batch");
    assert_eq!(waves[2], vec![7, 8], "Wave 2: third nonce batch");

    let timestamp = 1_700_000_100;
    let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
    let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

    // Strict equivalence
    assert_eq!(res_seq.0, 9, "all 9 transactions must apply sequentially");
    assert_eq!(res_par.0, 9, "all 9 transactions must apply in parallel");
    assert_eq!(res_seq.1, 0);
    assert_eq!(res_par.1, 0);
    assert_eq!(res_seq.3, vec![true; 9]);
    assert_eq!(res_par.3, vec![true; 9]);
    assert_eq!(res_seq.4, vec![10; 9]);
    assert_eq!(res_par.4, vec![10; 9]);

    let root_seq = engine_seq.get_state_root().await;
    let root_par = engine_par.get_state_root().await;
    assert_eq!(root_seq, root_par, "state roots must match bit-identically");

    // Verify Alice was executed in exact sequential order without race:
    // Nonce must be 3, balance must be initial - (100+10) - (110+10) - (120+10) = initial - 360
    let a_seq = engine_seq.get_account(&alice_addr).await.unwrap();
    let a_par = engine_par.get_account(&alice_addr).await.unwrap();
    assert_eq!(a_par.nonce, 3, "Alice nonce must advance exactly to 3");
    assert_eq!(
        a_par.balance,
        initial_bal - 360,
        "Alice balance debited correctly"
    );
    assert_eq!(a_seq.nonce, a_par.nonce);
    assert_eq!(a_seq.balance, a_par.balance);

    // Verify Bob: nonce 3, initial - (200+10) - (210+10) - (220+10) = initial - 660
    let b_par = engine_par.get_account(&bob_addr).await.unwrap();
    assert_eq!(b_par.nonce, 3);
    assert_eq!(b_par.balance, initial_bal - 660);

    let c_par = engine_par.get_account(&charlie_addr).await.unwrap();
    assert_eq!(c_par.nonce, 2);
    assert_eq!(c_par.balance, initial_bal - 630);

    let d_par = engine_par.get_account(&dave_addr).await.unwrap();
    assert_eq!(d_par.nonce, 1);
    assert_eq!(d_par.balance, initial_bal - 410);

    // Adversarial sub-case: Out-of-order nonces mixed across waves
    // Alice sends nonce 3 (gap, expected 3, succeeds), then nonce 5 (gap), then nonce 4
    let adv_txs = vec![
        Transaction::sign(&alice, r1, 10, 5, 3, 1, 1), // valid next nonce (3)
        Transaction::sign(&bob, r1, 10, 5, 3, 1, 1),   // valid next nonce (3)
        Transaction::sign(&alice, r2, 10, 5, 5, 1, 1), // BAD nonce (5, expected 4) -> fails
        Transaction::sign(&bob, r2, 10, 5, 4, 1, 1),   // valid next nonce (4)
        Transaction::sign(&alice, r3, 10, 5, 4, 1, 1), // valid next nonce (4, since 5 failed) -> succeeds!
    ];

    let adv_res_seq = engine_seq
        .apply_block_parallel_fees(&adv_txs, timestamp + 1)
        .await;
    let adv_res_par = engine_par
        .apply_block_parallel_fees(&adv_txs, timestamp + 1)
        .await;

    assert_eq!(adv_res_seq.0, adv_res_par.0);
    assert_eq!(adv_res_seq.1, adv_res_par.1);
    assert_eq!(adv_res_seq.3, adv_res_par.3);
    assert_eq!(adv_res_seq.3, vec![true, true, false, true, true]);
    assert_eq!(adv_res_seq.4, adv_res_par.4);

    let adv_root_seq = engine_seq.get_state_root().await;
    let adv_root_par = engine_par.get_state_root().await;
    assert_eq!(
        adv_root_seq, adv_root_par,
        "adversarial state roots must match bit-identically"
    );
}

// ---------------------------------------------------------------------------
// TEST 3: parallel_exec_balance_depletion_in_later_wave
// ---------------------------------------------------------------------------
#[tokio::test]
async fn parallel_exec_balance_depletion_in_later_wave() {
    // Exact requirement:
    // Sender has 100 STELL; sends 60 to B (wave 0) and 60 to C (wave 1).
    // Wave 0 succeeds, Wave 1 fails cleanly (insufficient balance), undo and status arrays match sequential.

    let mut rng = StdRng::seed_from_u64(0x9988_7766_5544_3322);

    let sender = SigningKey::generate(&mut rng);
    let sender_addr = sender.verifying_key().to_bytes();
    let b_addr = SigningKey::generate(&mut rng).verifying_key().to_bytes();
    let c_addr = SigningKey::generate(&mut rng).verifying_key().to_bytes();

    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    let initial_balance = 100 * STELL;
    engine_seq
        .update_account(AccountState::new(sender_addr, initial_balance))
        .await;
    engine_par
        .update_account(AccountState::new(sender_addr, initial_balance))
        .await;

    // Tx0: Sender -> B (60 STELL, wave 0)
    let tx0 = Transaction::sign(&sender, b_addr, 60 * STELL, 0, 0, 1, 1);
    // Tx1: Sender -> C (60 STELL, wave 1 due to sender conflict)
    let tx1 = Transaction::sign(&sender, c_addr, 60 * STELL, 0, 1, 1, 1);

    let txs = vec![tx0, tx1];

    let waves = DisjointScheduler::schedule(&txs);
    assert_eq!(waves.len(), 2, "must be partitioned into wave 0 and wave 1");
    assert_eq!(waves[0], vec![0]);
    assert_eq!(waves[1], vec![1]);

    let timestamp = 1_700_000_200;
    let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
    let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

    // Assert: wave 0 applied (1), wave 1 failed (1)
    assert_eq!(res_seq.0, 1, "sequential: 1 applied");
    assert_eq!(res_seq.1, 1, "sequential: 1 failed");
    assert_eq!(res_par.0, 1, "parallel: 1 applied");
    assert_eq!(res_par.1, 1, "parallel: 1 failed");

    // Status array: [true, false]
    assert_eq!(res_seq.3, vec![true, false], "sequential status array");
    assert_eq!(res_par.3, vec![true, false], "parallel status array");
    assert_eq!(res_seq.4, res_par.4, "fees array must match");

    // Balances after execution:
    // Sender: 100 STELL - 60 STELL = 40 STELL, nonce = 1
    // B: 60 STELL
    // C: 0 (clean failure, no credit)
    let s_acc_par = engine_par.get_account(&sender_addr).await.unwrap();
    assert_eq!(s_acc_par.balance, 40 * STELL);
    assert_eq!(s_acc_par.nonce, 1);

    let b_acc_par = engine_par.get_account(&b_addr).await.unwrap();
    assert_eq!(b_acc_par.balance, 60 * STELL);

    let c_acc_par = engine_par.get_account(&c_addr).await;
    assert!(c_acc_par.is_none() || c_acc_par.unwrap().balance == 0);

    let root_seq = engine_seq.get_state_root().await;
    let root_par = engine_par.get_state_root().await;
    assert_eq!(root_seq, root_par, "state roots must match bit-identically");

    // Sub-case 2: Payload-driven depletion and atomic rollback
    // Sender has 100 STELL.
    // Tx0 has declared amount 0, gas 10, but payload transfers 60 STELL to B.
    // Tx1 has declared amount 50 STELL, gas 10.
    // Both pass admission! Wave 0 runs and debits 60 STELL + 10 fee = leaves 30 STELL.
    // Wave 1 attempts to debit 50 + 10 = 60 STELL, fails at execution commit, triggering rollback!
    {
        let engine_s = new_engine(false);
        let engine_p = new_engine(true);

        let s2 = SigningKey::generate(&mut rng);
        let s2_addr = s2.verifying_key().to_bytes();
        let b2_addr = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let c2_addr = SigningKey::generate(&mut rng).verifying_key().to_bytes();

        engine_s
            .update_account(AccountState::new(s2_addr, 100 * STELL))
            .await;
        engine_p
            .update_account(AccountState::new(s2_addr, 100 * STELL))
            .await;

        let payload_transfer = vec![OpCode::Transfer {
            recipient: b2_addr,
            amount: 60 * STELL,
        }];
        let p_tx0 =
            Transaction::sign_with_payload(&s2, b2_addr, 0, 300_000, 0, 1, 1, payload_transfer);
        let p_tx1 = Transaction::sign(&s2, c2_addr, 50 * STELL, 300_000, 1, 1, 1);

        let p_txs = vec![p_tx0, p_tx1];
        let res_s = engine_s
            .apply_block_parallel_fees(&p_txs, timestamp + 1)
            .await;
        let res_p = engine_p
            .apply_block_parallel_fees(&p_txs, timestamp + 1)
            .await;

        assert_eq!(res_s.0, 1);
        assert_eq!(res_s.1, 1);
        assert_eq!(res_p.0, 1);
        assert_eq!(res_p.1, 1);
        assert_eq!(res_s.3, vec![true, false]);
        assert_eq!(res_p.3, vec![true, false]);
        // The second transaction cannot cover 50 STELL + its fee, so it
        // FAILS - and a failed attempt is not free: the sender pays the fee
        // it declared (the block space it consumed) and its nonce is
        // consumed. (A failure whose FEE the sender cannot cover moves
        // nothing at all - see `broke_sender_failure_changes_nothing`.)
        assert_eq!(res_s.4, vec![300_000, 300_000]);
        assert_eq!(res_p.4, vec![300_000, 300_000]);

        let s2_acc = engine_p.get_account(&s2_addr).await.unwrap();
        assert_eq!(
            s2_acc.balance,
            100 * STELL - 60 * STELL - 300_000 - 300_000,
            "the failed attempt pays its fee"
        );
        assert_eq!(s2_acc.nonce, 2, "the failure consumes the nonce");

        let root_s = engine_s.get_state_root().await;
        let root_p = engine_p.get_state_root().await;
        assert_eq!(
            root_s, root_p,
            "payload rollback state roots must match bit-identically"
        );
    }
}

// ---------------------------------------------------------------------------
// TEST 4: parallel_exec_mixed_token_and_clob_payloads
// ---------------------------------------------------------------------------
#[tokio::test]
async fn parallel_exec_mixed_token_and_clob_payloads() {
    let mut rng = StdRng::seed_from_u64(0x3344_5566_7788_9900);

    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    let minter = SigningKey::generate(&mut rng);
    let minter_addr = minter.verifying_key().to_bytes();

    let user_a = SigningKey::generate(&mut rng);
    let user_a_addr = user_a.verifying_key().to_bytes();

    let user_b = SigningKey::generate(&mut rng);
    let user_b_addr = user_b.verifying_key().to_bytes();

    let trader_1 = SigningKey::generate(&mut rng);
    let trader_1_addr = trader_1.verifying_key().to_bytes();

    let trader_2 = SigningKey::generate(&mut rng);
    let trader_2_addr = trader_2.verifying_key().to_bytes();

    let trader_3 = SigningKey::generate(&mut rng);
    let trader_3_addr = trader_3.verifying_key().to_bytes();

    let recipient_a = SigningKey::generate(&mut rng).verifying_key().to_bytes();
    let recipient_b = SigningKey::generate(&mut rng).verifying_key().to_bytes();
    let plain_dest = SigningKey::generate(&mut rng).verifying_key().to_bytes();

    // Fund all participants with native STELL for fees and orders
    let initial_stell = 50_000_000u64;
    for &addr in &[
        user_a_addr,
        user_b_addr,
        trader_1_addr,
        trader_2_addr,
        trader_3_addr,
        minter_addr,
    ] {
        engine_seq
            .update_account(AccountState::new(addr, initial_stell))
            .await;
        engine_par
            .update_account(AccountState::new(addr, initial_stell))
            .await;
    }

    // Create two distinct STS fungible tokens on both engines
    let token_1 = engine_seq
        .create_token(minter_addr, token_meta("Token Alpha", "ALPHA"), 1_000_000)
        .await
        .unwrap();
    let _ = engine_par
        .create_token(minter_addr, token_meta("Token Alpha", "ALPHA"), 1_000_000)
        .await
        .unwrap();

    let token_2 = engine_seq
        .create_token(minter_addr, token_meta("Token Beta", "BETA"), 1_000_000)
        .await
        .unwrap();
    let _ = engine_par
        .create_token(minter_addr, token_meta("Token Beta", "BETA"), 1_000_000)
        .await
        .unwrap();

    // Distribute token balances: User A has Token 1, User B has Token 2
    for engine in &[&engine_seq, &engine_par] {
        engine
            .token_execute(
                &token_1,
                minter_addr,
                TokenOp::Transfer {
                    to: user_a_addr,
                    amount: 20_000,
                },
            )
            .await
            .unwrap();
        engine
            .token_execute(
                &token_2,
                minter_addr,
                TokenOp::Transfer {
                    to: user_b_addr,
                    amount: 30_000,
                },
            )
            .await
            .unwrap();
    }

    let mut txs = Vec::new();

    // WAVE 0: Mutually disjoint across Token 1, Token 2, CLOB Pair 1, CLOB Pair 2, Plain Transfer
    // Tx 0: Token 1 transfer (User A -> Recipient A)
    txs.push(Transaction::sign_with_payload(
        &user_a,
        recipient_a,
        0,
        300_000,
        0,
        1,
        1,
        vec![OpCode::SysCallTokenTransfer {
            token_id: token_1,
            to: recipient_a,
            amount: 5_000,
        }],
    ));

    // Tx 1: Token 2 transfer (User B -> Recipient B)
    txs.push(Transaction::sign_with_payload(
        &user_b,
        recipient_b,
        0,
        300_000,
        0,
        1,
        1,
        vec![OpCode::SysCallTokenTransfer {
            token_id: token_2,
            to: recipient_b,
            amount: 4_000,
        }],
    ));

    // Tx 2: CLOB Limit Buy on Pair 1 (Trader 1)
    let dest_t1 = [0x11u8; 32];
    txs.push(Transaction::sign_with_payload(
        &trader_1,
        dest_t1,
        0,
        2_000,
        0,
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 100_000,
            amount: 10,
        }],
    ));

    // Tx 3: CLOB Limit Buy on Pair 2 (Trader 2)
    let dest_t2 = [0x22u8; 32];
    txs.push(Transaction::sign_with_payload(
        &trader_2,
        dest_t2,
        0,
        2_000,
        0,
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 2,
            is_buy: true,
            price: 200_000,
            amount: 20,
        }],
    ));

    // Tx 4: Plain STELL Transfer (Trader 3 -> plain_dest)
    txs.push(Transaction::sign(&trader_3, plain_dest, 1_000, 10, 0, 1, 1));

    // WAVE 1: Conflicts pushing each subsystem to the next wave
    // Tx 5: User A sends more Token 1 (conflicts on Token 1 and user_a)
    txs.push(Transaction::sign_with_payload(
        &user_a,
        recipient_a,
        0,
        300_000,
        1,
        1,
        1,
        vec![OpCode::SysCallTokenTransfer {
            token_id: token_1,
            to: recipient_a,
            amount: 2_000,
        }],
    ));

    // Tx 6: User B sends more Token 2 (conflicts on Token 2 and user_b)
    txs.push(Transaction::sign_with_payload(
        &user_b,
        recipient_b,
        0,
        300_000,
        1,
        1,
        1,
        vec![OpCode::SysCallTokenTransfer {
            token_id: token_2,
            to: recipient_b,
            amount: 3_000,
        }],
    ));

    // Tx 7: Trader 1 places another order on Pair 1 (conflicts on Orderbook 1)
    txs.push(Transaction::sign_with_payload(
        &trader_1,
        dest_t1,
        0,
        2_000,
        1,
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 105_000,
            amount: 5,
        }],
    ));

    // WAVE 2: Global barrier (Cancel order on Pair 1 by Trader 1)
    // Order 2 was placed in Tx 7 by Trader 1 on Pair 1 (order_id 2 only exists on Pair 1)
    txs.push(Transaction::sign_with_payload(
        &trader_1,
        dest_t1,
        0,
        1_000,
        2,
        1,
        1,
        vec![OpCode::SysCallCancelOrder { order_id: 2 }],
    ));

    // WAVE 3: Post-barrier transactions
    txs.push(Transaction::sign_with_payload(
        &user_a,
        recipient_a,
        0,
        300_000,
        2,
        1,
        1,
        vec![OpCode::SysCallTokenTransfer {
            token_id: token_1,
            to: recipient_a,
            amount: 1_000,
        }],
    ));

    let waves = DisjointScheduler::schedule(&txs);
    assert!(
        waves.len() >= 4,
        "must schedule into at least 4 waves due to conflicts and global cancel barrier"
    );
    assert_eq!(
        waves[0],
        vec![0, 1, 2, 3, 4],
        "Wave 0 contains all 5 disjoint parallel tasks"
    );

    let timestamp = 1_700_000_300;
    let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
    let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

    // Equivalence assertions
    assert_eq!(res_seq.0, txs.len(), "all txs apply sequentially");
    assert_eq!(res_par.0, txs.len(), "all txs apply in parallel");
    assert_eq!(res_seq.1, 0);
    assert_eq!(res_par.1, 0);
    assert_eq!(res_seq.3, res_par.3, "status vector must match");
    assert_eq!(res_seq.4, res_par.4, "fees vector must match");

    let root_seq = engine_seq.get_state_root().await;
    let root_par = engine_par.get_state_root().await;
    assert_eq!(
        root_seq, root_par,
        "state roots must match bit-identically across mixed token & clob waves"
    );

    // Verify token resource isolation and exact balance updates:
    // User A: 20_000 - 5_000 - 2_000 - 1_000 = 12_000
    // Recipient A: 5_000 + 2_000 + 1_000 = 8_000
    assert_eq!(
        engine_seq.token_balance(&token_1, &user_a_addr).await,
        12_000
    );
    assert_eq!(
        engine_par.token_balance(&token_1, &user_a_addr).await,
        12_000
    );
    assert_eq!(
        engine_seq.token_balance(&token_1, &recipient_a).await,
        8_000
    );
    assert_eq!(
        engine_par.token_balance(&token_1, &recipient_a).await,
        8_000
    );

    // User B: 30_000 - 4_000 - 3_000 = 23_000
    // Recipient B: 4_000 + 3_000 = 7_000
    assert_eq!(
        engine_seq.token_balance(&token_2, &user_b_addr).await,
        23_000
    );
    assert_eq!(
        engine_par.token_balance(&token_2, &user_b_addr).await,
        23_000
    );
    assert_eq!(
        engine_seq.token_balance(&token_2, &recipient_b).await,
        7_000
    );
    assert_eq!(
        engine_par.token_balance(&token_2, &recipient_b).await,
        7_000
    );
}

// ---------------------------------------------------------------------------
// TEST 5: parallel_exec_cyclic_chains
// ---------------------------------------------------------------------------
#[tokio::test]
async fn parallel_exec_cyclic_chains() {
    let mut rng = StdRng::seed_from_u64(0x5566_7788_99AA_BBCC);

    // Sub-case 1: Basic 3-cycle (A -> B, B -> C, C -> A)
    {
        let engine_seq = new_engine(false);
        let engine_par = new_engine(true);

        let a = SigningKey::generate(&mut rng);
        let b = SigningKey::generate(&mut rng);
        let c = SigningKey::generate(&mut rng);

        let a_addr = a.verifying_key().to_bytes();
        let b_addr = b.verifying_key().to_bytes();
        let c_addr = c.verifying_key().to_bytes();

        let initial_bal = 100_000u64;
        fund_engine(&engine_seq, &[a.clone(), b.clone(), c.clone()], initial_bal).await;
        fund_engine(&engine_par, &[a.clone(), b.clone(), c.clone()], initial_bal).await;

        let tx0 = Transaction::sign(&a, b_addr, 500, 10, 0, 1, 1); // A -> B
        let tx1 = Transaction::sign(&b, c_addr, 500, 10, 0, 1, 1); // B -> C
        let tx2 = Transaction::sign(&c, a_addr, 500, 10, 0, 1, 1); // C -> A

        let txs = vec![tx0, tx1, tx2];

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 3, "cyclic dependencies must produce 3 waves");
        assert_eq!(waves[0], vec![0], "Wave 0: A -> B");
        assert_eq!(waves[1], vec![1], "Wave 1: B -> C");
        assert_eq!(waves[2], vec![2], "Wave 2: C -> A");

        let timestamp = 1_700_000_400;
        let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
        let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

        assert_eq!(res_seq.0, 3);
        assert_eq!(res_par.0, 3);
        assert_eq!(res_seq.1, 0);
        assert_eq!(res_par.1, 0);
        assert_eq!(res_seq.3, vec![true; 3]);
        assert_eq!(res_par.3, vec![true; 3]);

        let root_seq = engine_seq.get_state_root().await;
        let root_par = engine_par.get_state_root().await;
        assert_eq!(
            root_seq, root_par,
            "basic 3-cycle roots must be bit-identical"
        );

        // Net balance unchanged minus 10 gas fee: initial_bal - 10
        for addr in &[a_addr, b_addr, c_addr] {
            let acc = engine_par.get_account(addr).await.unwrap();
            assert_eq!(acc.balance, initial_bal - 10);
            assert_eq!(acc.nonce, 1);
        }
    }

    // Sub-case 2: Multiple concurrent independent cycles (A->B->C->A, D->E->F->D, G->H->I->G)
    // Scheduled across 3 parallel waves (4 cycles in parallel = 4 txs per wave)
    {
        let engine_seq = new_engine(false);
        let engine_par = new_engine(true);

        let num_cycles = 4;
        let mut all_keys = Vec::new();
        let mut cycle_keys = Vec::new();

        for _ in 0..num_cycles {
            let k1 = SigningKey::generate(&mut rng);
            let k2 = SigningKey::generate(&mut rng);
            let k3 = SigningKey::generate(&mut rng);
            all_keys.push(k1.clone());
            all_keys.push(k2.clone());
            all_keys.push(k3.clone());
            cycle_keys.push((k1, k2, k3));
        }

        let initial_bal = 100_000u64;
        fund_engine(&engine_seq, &all_keys, initial_bal).await;
        fund_engine(&engine_par, &all_keys, initial_bal).await;

        let mut txs = Vec::new();
        // Hop 0 for all cycles
        for (k1, k2, _) in &cycle_keys {
            txs.push(Transaction::sign(
                k1,
                k2.verifying_key().to_bytes(),
                100,
                10,
                0,
                1,
                1,
            ));
        }
        // Hop 1 for all cycles
        for (_, k2, k3) in &cycle_keys {
            txs.push(Transaction::sign(
                k2,
                k3.verifying_key().to_bytes(),
                100,
                10,
                0,
                1,
                1,
            ));
        }
        // Hop 2 for all cycles
        for (k1, _, k3) in &cycle_keys {
            txs.push(Transaction::sign(
                k3,
                k1.verifying_key().to_bytes(),
                100,
                10,
                0,
                1,
                1,
            ));
        }

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 3, "must schedule into exactly 3 waves");
        assert_eq!(
            waves[0].len(),
            num_cycles,
            "Wave 0: all cycle hop 0s run concurrently"
        );
        assert_eq!(
            waves[1].len(),
            num_cycles,
            "Wave 1: all cycle hop 1s run concurrently"
        );
        assert_eq!(
            waves[2].len(),
            num_cycles,
            "Wave 2: all cycle hop 2s run concurrently"
        );

        let timestamp = 1_700_000_410;
        let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
        let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

        assert_eq!(res_seq.0, num_cycles * 3);
        assert_eq!(res_par.0, num_cycles * 3);
        assert_eq!(res_seq.1, 0);
        assert_eq!(res_par.1, 0);
        assert_eq!(res_seq.3, res_par.3);
        assert_eq!(res_seq.4, res_par.4);

        let root_seq = engine_seq.get_state_root().await;
        let root_par = engine_par.get_state_root().await;
        assert_eq!(
            root_seq, root_par,
            "concurrent cycles roots must be bit-identical"
        );
    }

    // Sub-case 3: Long 12-node cycle ring
    {
        let engine_seq = new_engine(false);
        let engine_par = new_engine(true);

        let ring_size = 12;
        let ring: Vec<SigningKey> = (0..ring_size)
            .map(|_| SigningKey::generate(&mut rng))
            .collect();

        fund_engine(&engine_seq, &ring, 100_000).await;
        fund_engine(&engine_par, &ring, 100_000).await;

        let mut txs = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            let next = (i + 1) % ring_size;
            let to = ring[next].verifying_key().to_bytes();
            txs.push(Transaction::sign(&ring[i], to, 50, 10, 0, 1, 1));
        }

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), ring_size, "12-node cycle requires 12 waves");

        let timestamp = 1_700_000_420;
        let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
        let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

        assert_eq!(res_seq.0, ring_size);
        assert_eq!(res_par.0, ring_size);
        assert_eq!(res_seq.3, res_par.3);

        let root_seq = engine_seq.get_state_root().await;
        let root_par = engine_par.get_state_root().await;
        assert_eq!(root_seq, root_par, "ring cycle roots must be bit-identical");
    }

    // Sub-case 4: Adversarial broken cycle (A -> B succeeds, B -> C fails, C -> A succeeds)
    {
        let engine_seq = new_engine(false);
        let engine_par = new_engine(true);

        let a = SigningKey::generate(&mut rng);
        let b = SigningKey::generate(&mut rng);
        let c = SigningKey::generate(&mut rng);

        let a_addr = a.verifying_key().to_bytes();
        let b_addr = b.verifying_key().to_bytes();
        let c_addr = c.verifying_key().to_bytes();

        fund_engine(&engine_seq, &[a.clone(), b.clone(), c.clone()], 100_000).await;
        fund_engine(&engine_par, &[a.clone(), b.clone(), c.clone()], 100_000).await;

        let tx0 = Transaction::sign(&a, b_addr, 100, 10, 0, 1, 1); // Valid (nonce 0)
        let tx1 = Transaction::sign(&b, c_addr, 100, 10, 999, 1, 1); // Invalid (bad nonce 999)
        let tx2 = Transaction::sign(&c, a_addr, 100, 10, 0, 1, 1); // Valid (nonce 0)

        let txs = vec![tx0, tx1, tx2];

        let timestamp = 1_700_000_430;
        let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
        let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

        assert_eq!(res_seq.0, 2);
        assert_eq!(res_par.0, 2);
        assert_eq!(res_seq.1, 1);
        assert_eq!(res_par.1, 1);
        assert_eq!(res_seq.3, vec![true, false, true]);
        assert_eq!(res_par.3, vec![true, false, true]);
        assert_eq!(res_seq.4, res_par.4);

        let root_seq = engine_seq.get_state_root().await;
        let root_par = engine_par.get_state_root().await;
        assert_eq!(
            root_seq, root_par,
            "broken cycle roots must be bit-identical"
        );
    }
}
