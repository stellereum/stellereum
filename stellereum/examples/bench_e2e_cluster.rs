//! Real End-to-End BFT Consensus Benchmark
//! Runs a real multi-validator cluster through full BFT rounds:
//! Mempool injection -> Propose -> OnProposal -> Prevotes -> Precommits -> TryFinalize -> ApplyLane
//! Compares sequential execution vs parallel execution on the identical workload!

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Instant;
use stellereum::runtime::{Cluster, ValidatorRuntime};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[tokio::main]
async fn main() {
    println!(
        "╔══════════════════════════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║       STELLEREUM REAL END-TO-END BFT CONSENSUS BENCHMARK                         ║"
    );
    println!(
        "║       Full Pipeline: Mempool -> Propose -> Prevote -> Precommit -> Finalize      ║"
    );
    println!(
        "║       Hardware: AMD Ryzen 5 3600 (6 Cores / 12 Threads)                          ║"
    );
    println!(
        "╚══════════════════════════════════════════════════════════════════════════════════╝\n"
    );

    // Test both 1,000 txs and 4,000 txs
    for total_txs in [1_000usize, 4_000usize] {
        println!(
            "================================================================================"
        );
        println!(
            "REAL E2E LOAD TEST: {} Transactions across BFT Cluster",
            total_txs
        );
        println!(
            "================================================================================"
        );

        // Run Sequential Baseline first
        let seq_tps = run_cluster_benchmark(total_txs, false).await;

        // Run Parallel Engine
        let par_tps = run_cluster_benchmark(total_txs, true).await;

        let speedup = par_tps / seq_tps;
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("RESULT FOR {} TXS:", total_txs);
        println!("  Sequential E2E Consensus: {:>8.1} real e2e TPS", seq_tps);
        println!("  Parallel E2E Consensus:   {:>8.1} real e2e TPS", par_tps);
        println!("  Actual E2E Speedup:       {:>8.2}x", speedup);
        println!(
            "================================================================================\n"
        );
    }
}

async fn run_cluster_benchmark(total_txs: usize, parallel: bool) -> f64 {
    // 2-node BFT cluster (matching the live stand topology)
    let val_keys: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let val_set = stellereum::consensus::ValidatorSet::from_list(
        val_keys
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );

    let engine_a = Arc::new(InMemoryStateEngine::new());
    let engine_b = Arc::new(InMemoryStateEngine::new());

    engine_a.set_parallel_exec(parallel);
    engine_b.set_parallel_exec(parallel);

    let rt_a = ValidatorRuntime::new(val_keys[0].clone(), val_set.clone(), engine_a.clone(), 0)
        .with_parallel_exec(parallel);
    let rt_b = ValidatorRuntime::new(val_keys[1].clone(), val_set.clone(), engine_b.clone(), 0)
        .with_parallel_exec(parallel);

    let mut cluster = Cluster::new(vec![
        (val_keys[0].clone(), engine_a.clone()),
        (val_keys[1].clone(), engine_b.clone()),
    ]);

    // Replace the internal runtimes with our properly configured ones
    cluster.nodes[0] = rt_a;
    cluster.nodes[1] = rt_b;

    // Generate funded senders
    // For 1,000 txs: 50 senders x 20 txs
    // For 4,000 txs: 200 senders x 20 txs
    let senders_count = (total_txs / 20).max(1);
    let sender_keys: Vec<SigningKey> = (0..senders_count)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect();
    let recipient = [0xEEu8; 32];

    for sk in &sender_keys {
        let addr = sk.verifying_key().to_bytes();
        let init_bal = 1_000_000_000_000u64; // plenty of STELL
        engine_a
            .update_account(AccountState::new(addr, init_bal))
            .await;
        engine_b
            .update_account(AccountState::new(addr, init_bal))
            .await;
    }
    engine_a
        .update_account(AccountState::new(recipient, 0))
        .await;
    engine_b
        .update_account(AccountState::new(recipient, 0))
        .await;

    // Build contiguous nonce transactions
    let mut all_txs = Vec::with_capacity(total_txs);
    for sk in &sender_keys {
        for nonce in 0..20u64 {
            if all_txs.len() >= total_txs {
                break;
            }
            let tx = Transaction::sign(sk, recipient, 1_000, 280_000, nonce, 0, 0);
            all_txs.push(tx);
        }
    }

    // Ingest all transactions into mempools of both nodes
    for tx in &all_txs {
        cluster.broadcast_tx(tx.clone()).await;
    }

    let mode_str = if parallel { "PARALLEL" } else { "SEQUENTIAL" };
    print!("  Running {} BFT cluster across heights... ", mode_str);

    let start_wall = Instant::now();
    let mut total_applied = 0usize;
    let mut height = 1u64;

    // MAX_BLOCK_GAS = 500M -> ~1785 transfers per block
    // 1,000 txs will take ~1 block; 4,000 txs will take ~3 blocks
    while total_applied < total_txs {
        let ts = 1_700_000_000 + height;
        let bh = cluster.run_height(ts).await;

        // Count how many applied so far
        let block_tx_count = cluster.nodes[0]
            .blocks
            .get(&bh)
            .map(|b| b.transactions.len())
            .unwrap_or(0);
        total_applied += block_tx_count;

        if block_tx_count == 0 && total_applied < total_txs {
            // Mempool drained or blocked
            break;
        }
        height += 1;
    }

    let elapsed = start_wall.elapsed();
    let elapsed_sec = elapsed.as_secs_f64();
    let real_e2e_tps = total_applied as f64 / elapsed_sec;

    println!(
        "Done in {:.3}s! ({} blocks, {}/{} txs finalized)",
        elapsed_sec,
        height - 1,
        total_applied,
        total_txs
    );
    real_e2e_tps
}
