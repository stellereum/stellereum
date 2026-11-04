//! Integration and equivalence tests for Disjoint Wave Parallel Execution (Track #1).
//! Verifies that parallel execution produces exact bit-identical state roots,
//! statuses, and fee accounting as sequential execution, across various workloads.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

fn token_meta(name: &str, symbol: &str) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
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

#[tokio::test]
async fn test_equivalence_100_tx_block() {
    let mut rng = OsRng;
    let senders: Vec<SigningKey> = (0..10).map(|_| SigningKey::generate(&mut rng)).collect();
    let recipients: Vec<[u8; 32]> = (0..10)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    let initial_balance = 10_000_000u64;
    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    fund_engine(&engine_seq, &senders, initial_balance).await;
    fund_engine(&engine_par, &senders, initial_balance).await;

    // 10 senders, 10 txs each = 100 txs.
    let mut txs = Vec::with_capacity(100);
    for nonce in 0..10u64 {
        for (i, sender) in senders.iter().enumerate() {
            let to = recipients[i];
            let tx = Transaction::sign(sender, to, 100, 10, nonce, 1, 1);
            txs.push(tx);
        }
    }

    let timestamp = 1_700_000_000;
    let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
    let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

    // (applied, failed, fees_collected, status, fees)
    assert_eq!(res_seq.0, res_par.0, "applied count must match");
    assert_eq!(res_seq.1, res_par.1, "failed count must match");
    assert_eq!(res_seq.2, res_par.2, "fees_collected must match");
    assert_eq!(res_seq.3, res_par.3, "status array must match");
    assert_eq!(res_seq.4, res_par.4, "fees array must match");
    assert_eq!(res_seq.0, 100, "all 100 transactions should apply");
    assert_eq!(res_seq.1, 0, "0 transactions should fail");

    let root_seq = engine_seq.get_state_root().await;
    let root_par = engine_par.get_state_root().await;
    assert_eq!(root_seq, root_par, "state roots must be bit-identical");

    // Verify account balances match byte-for-byte
    for sk in &senders {
        let addr = sk.verifying_key().to_bytes();
        let a_seq = engine_seq.get_account(&addr).await.unwrap();
        let a_par = engine_par.get_account(&addr).await.unwrap();
        assert_eq!(a_seq.balance, a_par.balance);
        assert_eq!(a_seq.nonce, a_par.nonce);
    }
}

#[tokio::test]
async fn test_equivalence_400_tx_block() {
    let mut rng = OsRng;
    let senders: Vec<SigningKey> = (0..20).map(|_| SigningKey::generate(&mut rng)).collect();
    let recipients: Vec<[u8; 32]> = (0..20)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    let initial_balance = 50_000_000u64;
    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    fund_engine(&engine_seq, &senders, initial_balance).await;
    fund_engine(&engine_par, &senders, initial_balance).await;

    // 20 senders, 20 txs each = 400 txs.
    let mut txs = Vec::with_capacity(400);
    for nonce in 0..20u64 {
        for (i, sender) in senders.iter().enumerate() {
            let to = recipients[i];
            let tx = Transaction::sign(sender, to, 50, 10, nonce, 1, 1);
            txs.push(tx);
        }
    }

    let timestamp = 1_700_000_100;
    let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
    let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

    assert_eq!(res_seq.0, res_par.0, "applied count must match");
    assert_eq!(res_seq.1, res_par.1, "failed count must match");
    assert_eq!(res_seq.2, res_par.2, "fees_collected must match");
    assert_eq!(res_seq.3, res_par.3, "status array must match");
    assert_eq!(res_seq.4, res_par.4, "fees array must match");
    assert_eq!(res_seq.0, 400, "all 400 transactions should apply");

    let root_seq = engine_seq.get_state_root().await;
    let root_par = engine_par.get_state_root().await;
    assert_eq!(
        root_seq, root_par,
        "state roots must be bit-identical for 400-tx block"
    );
}

#[tokio::test]
async fn test_mixed_workload_concurrency() {
    let mut rng = OsRng;
    let keys: Vec<SigningKey> = (0..10).map(|_| SigningKey::generate(&mut rng)).collect();
    let unfunded = SigningKey::generate(&mut rng);
    let zero_bal = SigningKey::generate(&mut rng);

    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    fund_engine(&engine_seq, &keys, 10_000_000).await;
    fund_engine(&engine_par, &keys, 10_000_000).await;

    // Fund zero-bal account with 0 balance
    let zero_addr = zero_bal.verifying_key().to_bytes();
    engine_seq
        .update_account(AccountState::new(zero_addr, 0))
        .await;
    engine_par
        .update_account(AccountState::new(zero_addr, 0))
        .await;

    // Create a fungible token on both engines
    let token_creator = keys[0].verifying_key().to_bytes();
    let meta = token_meta("GOLD", "GLD");
    let token_id = engine_seq
        .create_token(token_creator, meta.clone(), 100_000)
        .await
        .unwrap();
    let _ = engine_par
        .create_token(token_creator, meta, 100_000)
        .await
        .unwrap();

    let mut txs = Vec::new();
    let mut nonce_tracker = vec![0u64; keys.len()];

    // 1. Plain transfers (some independent, some conflicting, some chained)
    let recipient_a = keys[1].verifying_key().to_bytes();
    let recipient_b = keys[2].verifying_key().to_bytes();

    // Alice -> Bob
    txs.push(Transaction::sign(
        &keys[0],
        recipient_a,
        1000,
        10,
        nonce_tracker[0],
        1,
        1,
    ));
    nonce_tracker[0] += 1;

    // Bob -> Charlie (chain)
    txs.push(Transaction::sign(
        &keys[1],
        recipient_b,
        500,
        10,
        nonce_tracker[1],
        1,
        1,
    ));
    nonce_tracker[1] += 1;

    // Alice -> Bob again (sender conflict)
    txs.push(Transaction::sign(
        &keys[0],
        recipient_a,
        200,
        10,
        nonce_tracker[0],
        1,
        1,
    ));
    nonce_tracker[0] += 1;

    // Dave -> Bob (recipient conflict)
    txs.push(Transaction::sign(
        &keys[3],
        recipient_a,
        300,
        10,
        nonce_tracker[3],
        1,
        1,
    ));
    nonce_tracker[3] += 1;

    // 2. Token transfers
    let token_to = keys[4].verifying_key().to_bytes();
    let token_tx = Transaction::sign_with_payload(
        &keys[0],
        recipient_a,
        0,
        1000,
        nonce_tracker[0],
        1,
        1,
        vec![OpCode::SysCallTokenTransfer {
            token_id,
            to: token_to,
            amount: 1000,
        }],
    );
    txs.push(token_tx);
    nonce_tracker[0] += 1;

    // 3. Orderbook limit orders
    let ob_tx1 = Transaction::sign_with_payload(
        &keys[4],
        [0u8; 32],
        0,
        1000,
        nonce_tracker[4],
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 100,
            amount: 10,
        }],
    );
    txs.push(ob_tx1);
    nonce_tracker[4] += 1;

    let ob_tx2 = Transaction::sign_with_payload(
        &keys[5],
        [0u8; 32],
        0,
        1000,
        nonce_tracker[5],
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: false,
            price: 105,
            amount: 5,
        }],
    );
    txs.push(ob_tx2);
    nonce_tracker[5] += 1;

    // 4. Zero-balance failure: zero balance account attempts transfer
    let zero_tx = Transaction::sign(&zero_bal, recipient_a, 100, 10, 0, 1, 1);
    txs.push(zero_tx);

    // 5. Unfunded account attempts transfer
    let unfunded_tx = Transaction::sign(&unfunded, recipient_a, 100, 10, 0, 1, 1);
    txs.push(unfunded_tx);

    // 6. Bad nonce failure: Alice sends with future nonce gap
    let bad_nonce_tx = Transaction::sign(&keys[0], recipient_a, 100, 10, 999, 1, 1);
    txs.push(bad_nonce_tx);

    // More independent transfers
    for i in 6..10 {
        let to = keys[(i + 1) % keys.len()].verifying_key().to_bytes();
        txs.push(Transaction::sign(
            &keys[i],
            to,
            50,
            10,
            nonce_tracker[i],
            1,
            1,
        ));
        nonce_tracker[i] += 1;
    }

    let timestamp = 1_700_000_200;
    let res_seq = engine_seq.apply_block_parallel_fees(&txs, timestamp).await;
    let res_par = engine_par.apply_block_parallel_fees(&txs, timestamp).await;

    assert_eq!(
        res_seq.0, res_par.0,
        "applied count must match in mixed workload"
    );
    assert_eq!(
        res_seq.1, res_par.1,
        "failed count must match in mixed workload"
    );
    assert_eq!(
        res_seq.2, res_par.2,
        "fees_collected must match in mixed workload"
    );
    assert_eq!(res_seq.3, res_par.3, "status must match in mixed workload");
    assert_eq!(res_seq.4, res_par.4, "fees must match in mixed workload");

    let root_seq = engine_seq.get_state_root().await;
    let root_par = engine_par.get_state_root().await;
    assert_eq!(
        root_seq, root_par,
        "state roots must match in mixed workload"
    );
}

#[tokio::test]
async fn test_micro_benchmark_throughput_gain() {
    let mut rng = OsRng;
    let num_senders = 20;
    let txs_per_sender = 20;
    let total_txs = num_senders * txs_per_sender;

    let senders: Vec<SigningKey> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();
    let recipients: Vec<[u8; 32]> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    let initial_balance = 100_000_000u64;

    // Warm-up run to initialize rayon / thread pools
    {
        let warmup_engine = new_engine(true);
        fund_engine(&warmup_engine, &senders[..2], initial_balance).await;
        let warmup_txs = vec![
            Transaction::sign(&senders[0], recipients[0], 10, 10, 0, 1, 1),
            Transaction::sign(&senders[1], recipients[1], 10, 10, 0, 1, 1),
        ];
        let _ = warmup_engine
            .apply_block_parallel_fees(&warmup_txs, 1000)
            .await;
    }

    let mut txs = Vec::with_capacity(total_txs);
    for nonce in 0..txs_per_sender as u64 {
        for (i, sender) in senders.iter().enumerate() {
            let to = recipients[i];
            txs.push(Transaction::sign(sender, to, 25, 10, nonce, 1, 1));
        }
    }

    let timestamp = 1_700_000_300;

    let mut best_seq = std::time::Duration::MAX;
    let mut best_par = std::time::Duration::MAX;

    for iter in 0..3 {
        let engine_s = new_engine(false);
        let engine_p = new_engine(true);
        fund_engine(&engine_s, &senders, initial_balance).await;
        fund_engine(&engine_p, &senders, initial_balance).await;

        let start_seq = Instant::now();
        let res_seq = engine_s
            .apply_block_parallel_fees(&txs, timestamp + iter)
            .await;
        let dur_seq = start_seq.elapsed();
        if dur_seq < best_seq {
            best_seq = dur_seq;
        }

        let start_par = Instant::now();
        let res_par = engine_p
            .apply_block_parallel_fees(&txs, timestamp + iter)
            .await;
        let dur_par = start_par.elapsed();
        if dur_par < best_par {
            best_par = dur_par;
        }

        assert_eq!(res_seq.0, res_par.0);
        assert_eq!(res_seq.0, total_txs);
        let root_seq = engine_s.get_state_root().await;
        let root_par = engine_p.get_state_root().await;
        assert_eq!(root_seq, root_par);
    }

    let speedup = best_seq.as_secs_f64() / best_par.as_secs_f64().max(0.000001);
    println!(
        "\n[BENCH] {} tx block: Sequential: {:?} ({:.0} tx/s) | Parallel: {:?} ({:.0} tx/s) | Speedup: {:.2}x",
        total_txs,
        best_seq,
        total_txs as f64 / best_seq.as_secs_f64(),
        best_par,
        total_txs as f64 / best_par.as_secs_f64(),
        speedup
    );

    // Assert parallel execution achieves throughput gain
    assert!(
        speedup >= 1.0,
        "Parallel execution must achieve speedup over sequential (got {:.2}x)",
        speedup
    );
}
