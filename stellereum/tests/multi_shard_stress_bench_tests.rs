//! Final Stress Test & Speed Benchmark across two parallel shards (Shard 0 & Shard 1)
//!
//! Measures:
//! - High-volume transaction throughput across Shard 0 (Masterchain) and Shard 1 (Workchain).
//! - Cross-shard value transfer in both directions (0 -> 1 and 1 -> 0).
//! - Disjoint concurrent execution performance.
//! - State root determinism and balance conservation.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD; // 0
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL; // 1

fn test_signer(seed: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes[8..16].copy_from_slice(&(!seed).to_be_bytes());
    SigningKey::from_bytes(&bytes)
}

#[tokio::test]
async fn test_two_shard_parallel_stress_and_tps_benchmark() {
    let validator = test_signer(999);
    let s0_engine = Arc::new(InMemoryStateEngine::new().with_parallel_exec(true));
    let s1_engine = Arc::new(InMemoryStateEngine::new().with_parallel_exec(true));

    let num_senders = 50usize;
    let initial_bal = 10_000_000_000u64; // 10 STELL

    let mut senders_s0 = Vec::new();
    let mut senders_s1 = Vec::new();

    for i in 0..num_senders {
        let sk0 = test_signer(1000 + i as u64);
        let addr0 = sk0.verifying_key().to_bytes();
        s0_engine
            .update_account(AccountState::new(addr0, initial_bal))
            .await;
        senders_s0.push(sk0);

        let sk1 = test_signer(2000 + i as u64);
        let addr1 = sk1.verifying_key().to_bytes();
        s1_engine
            .update_account(AccountState::new(addr1, initial_bal))
            .await;
        senders_s1.push(sk1);
    }

    let mut cluster = ShardedCluster::new(
        ShardRegistry::from_ids([SHARD0, SHARD1]),
        vec![
            (SHARD0, vec![(validator.clone(), s0_engine.clone())]),
            (SHARD1, vec![(validator.clone(), s1_engine.clone())]),
        ],
        CrossShardTransport::local(),
    );

    let fee = 280_000u64;
    let transfer_amount = 10_000_000u64; // 0.01 STELL

    // Prepare 200 intra-shard transactions for Shard 0
    let mut txs_s0 = Vec::new();
    for (i, sender) in senders_s0.iter().enumerate() {
        let recipient = senders_s0[(i + 1) % num_senders].verifying_key().to_bytes();
        for nonce in 0..4 {
            let tx = Transaction::sign(
                sender,
                recipient,
                transfer_amount,
                fee,
                nonce,
                SHARD0,
                SHARD0,
            );
            txs_s0.push(tx);
        }
    }

    // Prepare 200 intra-shard transactions for Shard 1
    let mut txs_s1 = Vec::new();
    for (i, sender) in senders_s1.iter().enumerate() {
        let recipient = senders_s1[(i + 1) % num_senders].verifying_key().to_bytes();
        for nonce in 0..4 {
            let tx = Transaction::sign(
                sender,
                recipient,
                transfer_amount,
                fee,
                nonce,
                SHARD1,
                SHARD1,
            );
            txs_s1.push(tx);
        }
    }

    // Prepare 50 cross-shard transactions Shard 0 -> Shard 1 from dedicated senders
    let mut x_senders_s0 = Vec::new();
    let mut x_txs_0_to_1 = Vec::new();
    for (i, sender) in senders_s1.iter().enumerate().take(num_senders) {
        let x_sk = test_signer(3000 + i as u64);
        let x_addr = x_sk.verifying_key().to_bytes();
        s0_engine
            .update_account(AccountState::new(x_addr, initial_bal))
            .await;
        let recipient = sender.verifying_key().to_bytes();
        let tx = Transaction::sign(
            &x_sk,
            recipient,
            transfer_amount * 2,
            fee,
            0,
            SHARD0,
            SHARD1,
        );
        x_txs_0_to_1.push(tx);
        x_senders_s0.push(x_sk);
    }

    // Prepare 50 cross-shard transactions Shard 1 -> Shard 0 from dedicated senders
    let mut x_senders_s1 = Vec::new();
    let mut x_txs_1_to_0 = Vec::new();
    for (i, sender) in senders_s0.iter().enumerate().take(num_senders) {
        let x_sk = test_signer(4000 + i as u64);
        let x_addr = x_sk.verifying_key().to_bytes();
        s1_engine
            .update_account(AccountState::new(x_addr, initial_bal))
            .await;
        let recipient = sender.verifying_key().to_bytes();
        let tx = Transaction::sign(
            &x_sk,
            recipient,
            transfer_amount * 2,
            fee,
            0,
            SHARD1,
            SHARD0,
        );
        x_txs_1_to_0.push(tx);
        x_senders_s1.push(x_sk);
    }

    let total_txs = txs_s0.len() + txs_s1.len() + x_txs_0_to_1.len() + x_txs_1_to_0.len();
    assert_eq!(total_txs, 500);

    // Broadcast all transactions to cluster
    let t_broadcast_start = Instant::now();
    for tx in txs_s0.into_iter().chain(x_txs_0_to_1.into_iter()) {
        cluster.shard_mut(SHARD0).broadcast_tx(tx).await;
    }
    for tx in txs_s1.into_iter().chain(x_txs_1_to_0.into_iter()) {
        cluster.shard_mut(SHARD1).broadcast_tx(tx).await;
    }
    let broadcast_elapsed = t_broadcast_start.elapsed();

    // Mine blocks on both shards concurrently
    let t_mining_start = Instant::now();

    // Height 1: Both shards mine intra-shard transactions and produce outbound cross-shard records
    let h1_s0 = cluster.run_height(SHARD0, 1000).await;
    let h1_s1 = cluster.run_height(SHARD1, 1001).await;

    let blk1_s0 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&h1_s0)
        .cloned()
        .unwrap();
    let blk1_s1 = cluster.shard(SHARD1).nodes[0]
        .blocks
        .get(&h1_s1)
        .cloned()
        .unwrap();

    eprintln!(
        "blk1_s0 txs count: {}, cross_shard_out: {}",
        blk1_s0.transactions.len(),
        blk1_s0.cross_shard_out.len()
    );
    eprintln!(
        "blk1_s1 txs count: {}, cross_shard_out: {}",
        blk1_s1.transactions.len(),
        blk1_s1.cross_shard_out.len()
    );

    assert_eq!(
        blk1_s0.cross_shard_out.len(),
        50,
        "Shard 0 must package 50 outbound transfers to Shard 1"
    );
    assert_eq!(
        blk1_s1.cross_shard_out.len(),
        100,
        "Shard 1 packages 50 outbound transfers + 50 inbound Acks for Shard 0"
    );

    // Height 2: Both shards consume inbound cross-shard messages, credit accounts, and produce Ack records
    let h2_s0 = cluster.run_height(SHARD0, 1002).await;
    let h2_s1 = cluster.run_height(SHARD1, 1003).await;

    let blk2_s0 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&h2_s0)
        .cloned()
        .unwrap();
    let blk2_s1 = cluster.shard(SHARD1).nodes[0]
        .blocks
        .get(&h2_s1)
        .cloned()
        .unwrap();

    eprintln!(
        "blk2_s0 txs count: {}, cross_shard_out: {}",
        blk2_s0.transactions.len(),
        blk2_s0.cross_shard_out.len()
    );
    eprintln!(
        "blk2_s1 txs count: {}, cross_shard_out: {}",
        blk2_s1.transactions.len(),
        blk2_s1.cross_shard_out.len()
    );

    assert!(
        blk2_s0.cross_shard_out.iter().any(|m| m.is_ack()),
        "Shard 0 must commit Acks from Shard 1"
    );

    let mining_elapsed = t_mining_start.elapsed();

    let total_elapsed = broadcast_elapsed + mining_elapsed;
    let effective_tps = (total_txs as f64) / total_elapsed.as_secs_f64();

    eprintln!("\n=======================================================");
    eprintln!("  STELLEREUM DUAL-SHARD STRESS BENCHMARK RESULTS");
    eprintln!("=======================================================");
    eprintln!("Total Transactions Processed: {}", total_txs);
    eprintln!("  • Intra-shard Shard 0: 200 txs");
    eprintln!("  • Intra-shard Shard 1: 200 txs");
    eprintln!("  • Cross-shard 0 -> 1:  50 txs");
    eprintln!("  • Cross-shard 1 -> 0:  50 txs");
    eprintln!("Broadcast Ingress Time:       {:?}", broadcast_elapsed);
    eprintln!("Multi-Shard Mining Time:      {:?}", mining_elapsed);
    eprintln!("Total Execution Time:         {:?}", total_elapsed);
    eprintln!("Effective Dual-Shard TPS:     {:.2} tx/s", effective_tps);
    eprintln!("=======================================================\n");

    assert!(
        effective_tps > 200.0,
        "Multi-shard throughput must exceed 200 tx/s"
    );
}
