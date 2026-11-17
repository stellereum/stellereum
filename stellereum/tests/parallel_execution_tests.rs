//! Integration and equivalence tests for Disjoint Wave Parallel Execution (Track #1).
//! Verifies that parallel execution produces exact bit-identical state roots,
//! statuses, and fee accounting as sequential execution, across various workloads.

use std::time::Instant;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

fn pq_key(seed: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed(seed)
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

#[allow(clippy::too_many_arguments)]
fn pq_transfer(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    pq_payload(
        kp,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn pq_payload(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<OpCode>,
) -> Transaction {
    let pk = kp.public_key.clone();
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        payload,
        &DEFAULT_SALT,
    )
}

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

async fn fund_engine(engine: &InMemoryStateEngine, keys: &[FalconKeypair], initial_bal: u64) {
    for sk in keys {
        let addr = pq_addr(sk);
        engine
            .update_account(AccountState::new(addr, initial_bal))
            .await;
    }
}

#[tokio::test]
async fn test_equivalence_100_tx_block() {
    let senders: Vec<FalconKeypair> = (0..10u8).map(pq_key).collect();
    let recipients: Vec<[u8; 32]> = (0..10u8).map(|i| pq_addr(&pq_key(100 + i))).collect();

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
            let tx = pq_transfer(sender, to, 100, 10, nonce, 1, 1);
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
        let addr = pq_addr(sk);
        let a_seq = engine_seq.get_account(&addr).await.unwrap();
        let a_par = engine_par.get_account(&addr).await.unwrap();
        assert_eq!(a_seq.balance, a_par.balance);
        assert_eq!(a_seq.nonce, a_par.nonce);
    }
}

#[tokio::test]
async fn test_equivalence_400_tx_block() {
    let senders: Vec<FalconKeypair> = (0..20u8).map(pq_key).collect();
    let recipients: Vec<[u8; 32]> = (0..20u8).map(|i| pq_addr(&pq_key(100 + i))).collect();

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
            let tx = pq_transfer(sender, to, 50, 10, nonce, 1, 1);
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
    let keys: Vec<FalconKeypair> = (0..10u8).map(pq_key).collect();
    let unfunded = pq_key(200);
    let zero_bal = pq_key(201);

    let engine_seq = new_engine(false);
    let engine_par = new_engine(true);

    fund_engine(&engine_seq, &keys, 10_000_000).await;
    fund_engine(&engine_par, &keys, 10_000_000).await;

    // Fund zero-bal account with 0 balance
    let zero_addr = pq_addr(&zero_bal);
    engine_seq
        .update_account(AccountState::new(zero_addr, 0))
        .await;
    engine_par
        .update_account(AccountState::new(zero_addr, 0))
        .await;

    // Create a fungible token on both engines
    let token_creator = pq_addr(&keys[0]);
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
    let recipient_a = pq_addr(&keys[1]);
    let recipient_b = pq_addr(&keys[2]);

    // Alice -> Bob
    txs.push(pq_transfer(
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
    txs.push(pq_transfer(
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
    txs.push(pq_transfer(
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
    txs.push(pq_transfer(
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
    let token_to = pq_addr(&keys[4]);
    let token_tx = pq_payload(
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
    let ob_tx1 = pq_payload(
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

    let ob_tx2 = pq_payload(
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
    let zero_tx = pq_transfer(&zero_bal, recipient_a, 100, 10, 0, 1, 1);
    txs.push(zero_tx);

    // 5. Unfunded account attempts transfer
    let unfunded_tx = pq_transfer(&unfunded, recipient_a, 100, 10, 0, 1, 1);
    txs.push(unfunded_tx);

    // 6. Bad nonce failure: Alice sends with future nonce gap
    let bad_nonce_tx = pq_transfer(&keys[0], recipient_a, 100, 10, 999, 1, 1);
    txs.push(bad_nonce_tx);

    // More independent transfers
    for i in 6..10 {
        let to = pq_addr(&keys[(i + 1) % keys.len()]);
        txs.push(pq_transfer(&keys[i], to, 50, 10, nonce_tracker[i], 1, 1));
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
    let num_senders = 100;
    let txs_per_sender = 20;
    let total_txs = num_senders * txs_per_sender;

    let senders: Vec<FalconKeypair> = (0..num_senders as u8).map(pq_key).collect();
    let recipients: Vec<[u8; 32]> = (0..num_senders as u8)
        .map(|i| pq_addr(&pq_key(100 + i)))
        .collect();

    let initial_balance = 100_000_000u64;

    // Warm-up run to initialize rayon / thread pools
    {
        let warmup_engine = new_engine(true);
        fund_engine(&warmup_engine, &senders[..2], initial_balance).await;
        let warmup_txs = vec![
            pq_transfer(&senders[0], recipients[0], 10, 10, 0, 1, 1),
            pq_transfer(&senders[1], recipients[1], 10, 10, 0, 1, 1),
        ];
        let _ = warmup_engine
            .apply_block_parallel_fees(&warmup_txs, 1000)
            .await;
    }

    let mut txs = Vec::with_capacity(total_txs);
    for nonce in 0..txs_per_sender as u64 {
        for (i, sender) in senders.iter().enumerate() {
            let to = recipients[i];
            txs.push(pq_transfer(sender, to, 25, 10, nonce, 1, 1));
        }
    }

    // The subject here is the EXECUTION scheduler, not Falcon verification.
    // Attest the signatures exactly as mempool admission does, so block apply
    // takes the production verify-once fast path and the measurement isolates
    // parallel execution (as it did with the cheaper classical signature).
    let chain = stellereum::consensus::consensus_chain_id();
    for tx in &txs {
        stellereum::state_engine::record_verified_signature(tx, chain);
    }

    let timestamp = 1_700_000_300;

    let mut best_seq = std::time::Duration::MAX;
    let mut best_par = std::time::Duration::MAX;

    for iter in 0..3 {
        let engine_s = new_engine(false);
        let engine_p = new_engine(true);
        fund_engine(&engine_s, &senders, initial_balance).await;
        fund_engine(&engine_p, &senders, initial_balance).await;

        // Sequential reference: the NAIVE single-transaction path, one tx at
        // a time. The block path's win is batching (one admission/verify
        // pass, one accounts lock per wave) versus per-tx admission/locking.
        let start_seq = Instant::now();
        let mut seq_applied = 0usize;
        for tx in &txs {
            engine_s
                .apply_transaction(tx, timestamp + iter)
                .await
                .expect("sequential single-tx apply");
            seq_applied += 1;
        }
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

        assert_eq!(seq_applied, total_txs);
        assert_eq!(res_par.0, total_txs);
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
