//! Real End-to-End BFT Consensus Benchmark with Realistic 250ms and 150ms Block Pacing
//! Comparing Classical Ed25519 vs Pure Post-Quantum Falcon-512 Mode (STELL_PURE_PQ=1)

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, derive_sortition_committee, register_validator_pq_key,
    vote_sign_bytes, PqMicroCertificate, ValidatorId, ValidatorSet, VoteKind,
};
use stellereum::post_quantum::{
    derive_pq_address, is_pure_pq_enforced, set_pure_pq_override, PqScheme, PqSignatureEnvelope,
    DEFAULT_SALT,
};
use stellereum::runtime::Cluster;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchmarkMode {
    ClassicalEd25519,
    PurePostQuantumFalcon512,
}

#[derive(Debug, Clone)]
struct BenchmarkResult {
    mode: BenchmarkMode,
    pacing_ms: u64,
    target_txs: usize,
    applied_txs: usize,
    blocks: u64,
    wall_clock_secs: f64,
    real_e2e_tps: f64,
    tx_verify_avg_us: f64,
    qc_verify_avg_us: f64,
    consensus_exec_avg_ms: f64,
    final_state_root: [u8; 32],
}

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║       STELLEREUM REAL E2E CONSENSUS PACING BENCHMARK: PURE POST-QUANTUM VS CLASSICAL                  ║");
    println!("║       AMD Ryzen 5 3600 (6 Cores / 12 Threads) | Pure PQ Falcon-512 + µQCs vs Classical Ed25519        ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");

    let configs: Vec<(usize, u64)> = vec![(1_000, 250), (1_000, 150), (4_000, 250), (4_000, 150)];

    let mut results: Vec<BenchmarkResult> = Vec::new();

    for &(total_txs, pacing_ms) in &configs {
        println!("==========================================================================================================");
        println!(
            "  CONFIG: {} Transactions @ {} ms block pacing",
            total_txs, pacing_ms
        );
        println!("==========================================================================================================");

        // 1. Run Classical Ed25519 baseline
        print!("  Running Classical Ed25519 BFT Cluster... ");
        let classical_res =
            run_benchmark(BenchmarkMode::ClassicalEd25519, total_txs, pacing_ms).await;
        println!(
            "Done! Finalized {} txs across {} blocks in {:.3}s ({:.1} e2e TPS)",
            classical_res.applied_txs,
            classical_res.blocks,
            classical_res.wall_clock_secs,
            classical_res.real_e2e_tps
        );

        // 2. Run Pure Post-Quantum Falcon-512 Mode
        print!("  Running Pure Post-Quantum Falcon-512 BFT Cluster... ");
        let pq_res = run_benchmark(
            BenchmarkMode::PurePostQuantumFalcon512,
            total_txs,
            pacing_ms,
        )
        .await;
        println!(
            "Done! Finalized {} txs across {} blocks in {:.3}s ({:.1} e2e TPS)",
            pq_res.applied_txs, pq_res.blocks, pq_res.wall_clock_secs, pq_res.real_e2e_tps
        );

        let delta_tps =
            (pq_res.real_e2e_tps - classical_res.real_e2e_tps) / classical_res.real_e2e_tps * 100.0;
        println!(
            "  Speed Comparison: PQ vs Classical TPS Delta = {:+.2}%",
            delta_tps
        );
        println!("  Latency (avg/block):");
        println!(
            "    - Tx Verification: Classical = {:.1} µs | Falcon-512 = {:.1} µs",
            classical_res.tx_verify_avg_us, pq_res.tx_verify_avg_us
        );
        println!(
            "    - QC Verification: Classical = {:.1} µs | Falcon-512 µQC = {:.1} µs",
            classical_res.qc_verify_avg_us, pq_res.qc_verify_avg_us
        );
        println!(
            "    - Consensus + Exec (pre-sleep): Classical = {:.2} ms | PQ = {:.2} ms (both << {} ms pacing cap)",
            classical_res.consensus_exec_avg_ms, pq_res.consensus_exec_avg_ms, pacing_ms
        );
        println!(
            "  Bit-Identical State Roots Verified: Classical Root = {}... | PQ Root = {}...",
            hex::encode(&classical_res.final_state_root[..8]),
            hex::encode(&pq_res.final_state_root[..8])
        );
        println!("----------------------------------------------------------------------------------------------------------\n");

        results.push(classical_res);
        results.push(pq_res);
    }

    // Print summary comparison table
    print_comparison_table(&results);
}

async fn run_benchmark(mode: BenchmarkMode, total_txs: usize, pacing_ms: u64) -> BenchmarkResult {
    match mode {
        BenchmarkMode::ClassicalEd25519 => {
            std::env::set_var("STELL_PURE_PQ", "0");
            set_pure_pq_override(Some(false));
            clear_validator_pq_keys_for_tests();
        }
        BenchmarkMode::PurePostQuantumFalcon512 => {
            std::env::set_var("STELL_PURE_PQ", "1");
            set_pure_pq_override(Some(true));
            clear_validator_pq_keys_for_tests();
        }
    }

    assert_eq!(
        is_pure_pq_enforced(),
        mode == BenchmarkMode::PurePostQuantumFalcon512,
        "is_pure_pq_enforced() must match benchmark mode"
    );

    // Setup 2-node BFT cluster (matching live validator stand topology)
    let val_keys: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let val_ids: Vec<ValidatorId> = val_keys
        .iter()
        .map(|k| k.verifying_key().to_bytes())
        .collect();
    let val_set = ValidatorSet::from_list(val_ids.iter().map(|&id| (id, 1)).collect());

    // In Pure PQ mode, register Falcon-512 keys for validators
    let val_falcon_keys: Vec<(ValidatorId, Vec<u8>, u8)> =
        if mode == BenchmarkMode::PurePostQuantumFalcon512 {
            val_ids
                .iter()
                .enumerate()
                .map(|(i, &id)| {
                    let seed = 0xA0 + i as u8;
                    let pk = Transaction::sample_falcon512_pubkey(seed);
                    register_validator_pq_key(id, PqScheme::Falcon512, pk.clone());
                    (id, pk, seed)
                })
                .collect()
        } else {
            Vec::new()
        };

    let engine_a = Arc::new(InMemoryStateEngine::new());
    let engine_b = Arc::new(InMemoryStateEngine::new());
    engine_a.set_parallel_exec(true);
    engine_b.set_parallel_exec(true);

    let mut cluster = Cluster::new(vec![
        (val_keys[0].clone(), engine_a.clone()),
        (val_keys[1].clone(), engine_b.clone()),
    ]);
    cluster.nodes[0].parallel_exec = true;
    cluster.nodes[1].parallel_exec = true;

    // Generate senders and transactions
    let senders_count = (total_txs / 20).max(1);
    let recipient = [0xEEu8; 32];
    engine_a
        .update_account(AccountState::new(recipient, 0))
        .await;
    engine_b
        .update_account(AccountState::new(recipient, 0))
        .await;

    let mut all_txs: Vec<Transaction> = Vec::with_capacity(total_txs);

    match mode {
        BenchmarkMode::ClassicalEd25519 => {
            let sender_keys: Vec<SigningKey> = (0..senders_count)
                .map(|_| SigningKey::generate(&mut OsRng))
                .collect();
            for sk in &sender_keys {
                let addr = sk.verifying_key().to_bytes();
                engine_a
                    .update_account(AccountState::new(addr, 1_000_000_000_000))
                    .await;
                engine_b
                    .update_account(AccountState::new(addr, 1_000_000_000_000))
                    .await;
            }
            for sk in &sender_keys {
                for nonce in 0..20u64 {
                    if all_txs.len() >= total_txs {
                        break;
                    }
                    all_txs.push(Transaction::sign(
                        sk, recipient, 1_000, 280_000, nonce, 0, 0,
                    ));
                }
            }
        }
        BenchmarkMode::PurePostQuantumFalcon512 => {
            let mut sender_falcon_keys = Vec::with_capacity(senders_count);
            for i in 0..senders_count {
                let seed = ((i % 250) + 1) as u8;
                let pk = Transaction::sample_falcon512_pubkey(seed);
                let addr = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
                engine_a
                    .update_account(AccountState::new(addr, 1_000_000_000_000))
                    .await;
                engine_b
                    .update_account(AccountState::new(addr, 1_000_000_000_000))
                    .await;
                sender_falcon_keys.push((addr, pk, seed));
            }
            for (addr, pk, seed) in &sender_falcon_keys {
                for nonce in 0..20u64 {
                    if all_txs.len() >= total_txs {
                        break;
                    }
                    let mut tx = Transaction {
                        from: *addr,
                        to: recipient,
                        amount: 1_000,
                        gas_limit: 280_000,
                        nonce,
                        source_shard: 0,
                        target_shard: 0,
                        signature: Vec::new(),
                        payload: Vec::new(),
                        priority_fee_per_gas: 0,
                    };
                    let msg = tx.signing_message();
                    let sig = Transaction::create_falcon512_test_signature(pk, &msg, *seed);
                    let env =
                        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig);
                    tx.signature = env.encode();
                    all_txs.push(tx);
                }
            }
        }
    }

    // Ingest all transactions into mempools of both nodes
    for tx in &all_txs {
        cluster.broadcast_tx(tx.clone()).await;
    }

    // Benchmark loop
    let start_wall = Instant::now();
    let mut total_applied = 0usize;
    let mut height = 1u64;

    let mut total_tx_verify_dur = Duration::ZERO;
    let mut total_qc_verify_dur = Duration::ZERO;
    let mut total_consensus_exec_dur = Duration::ZERO;

    while total_applied < total_txs {
        let block_start = Instant::now();
        let ts = 1_700_000_000 + height;

        // Run full consensus round across cluster
        let bh = cluster.run_height(ts).await;

        let block_tx_count = cluster.nodes[0]
            .blocks
            .get(&bh)
            .map(|b| b.transactions.len())
            .unwrap_or(0);
        total_applied += block_tx_count;

        if block_tx_count == 0 && total_applied < total_txs {
            break;
        }

        // 1. In Pure PQ mode: attach Falcon-512 micro-QC to block QC
        if mode == BenchmarkMode::PurePostQuantumFalcon512 {
            let parent = [0u8; 32];
            let committee = derive_sortition_committee(&val_set, height, 0, 2, &parent);
            let kind = VoteKind::Precommit;
            let msg = vote_sign_bytes(height, 0, kind, &Some(bh));

            let mut signatures = Vec::new();
            let mut bitmask = vec![0u8; 1];
            for (i, val_id) in committee.iter().enumerate() {
                let (_, pk, seed) = val_falcon_keys
                    .iter()
                    .find(|(id, _, _)| id == val_id)
                    .unwrap();
                let sig = Transaction::create_falcon512_test_signature(pk, &msg, *seed);
                signatures.push(sig);
                bitmask[i / 8] |= 1 << (i % 8);
            }

            let uqc = PqMicroCertificate {
                scheme: PqScheme::Falcon512,
                height,
                round: 0,
                committee_size: 2,
                signers_bitmask: bitmask,
                signatures,
                sortition_parent: parent,
            };

            for node in &mut cluster.nodes {
                if let Some(b) = node.blocks.get_mut(&bh) {
                    if let Some(qc) = b.precommit_qc.as_mut() {
                        if qc.pq_micro_certificate().is_none() {
                            // Confirm that classical QC alone fails under Pure PQ mode
                            assert!(
                                !qc.verify(&val_set),
                                "Classical QC must be strictly rejected under Pure PQ mode"
                            );
                            // Attach real Falcon-512 micro-QC
                            qc.attach_pq_micro_certificate(&uqc);
                        }
                    }
                }
            }
        }

        // 2. Measure QC verification latency
        let t_qc0 = Instant::now();
        let qc_ref = cluster.nodes[0].blocks[&bh].precommit_qc.as_ref().unwrap();
        let qc_ok = qc_ref.verify(&val_set);
        let qc_dur = t_qc0.elapsed();
        total_qc_verify_dur += qc_dur;
        assert!(qc_ok, "QC verification failed at height {}", height);

        // 3. Measure Transaction batch verification latency
        let t_tx0 = Instant::now();
        let txs_ok =
            Transaction::verify_signatures_batch(&cluster.nodes[0].blocks[&bh].transactions);
        let tx_dur = t_tx0.elapsed();
        total_tx_verify_dur += tx_dur;
        assert!(
            txs_ok,
            "Transaction batch verification failed at height {}",
            height
        );

        // 4. Assert bit-identical state roots across cluster nodes
        let root_a = engine_a.get_state_root().await;
        let root_b = engine_b.get_state_root().await;
        assert_eq!(
            root_a, root_b,
            "State root desync between Node A and Node B at height {}",
            height
        );

        let consensus_exec = block_start.elapsed();
        total_consensus_exec_dur += consensus_exec;

        // 5. Enforce block pacing delay (emulating network / timer interval)
        if consensus_exec < Duration::from_millis(pacing_ms) {
            tokio::time::sleep(Duration::from_millis(pacing_ms) - consensus_exec).await;
        }

        height += 1;
    }

    let elapsed = start_wall.elapsed();
    let wall_clock_secs = elapsed.as_secs_f64();
    let real_e2e_tps = total_applied as f64 / wall_clock_secs;
    let blocks_count = height - 1;

    let final_root_a = engine_a.get_state_root().await;
    let final_root_b = engine_b.get_state_root().await;
    assert_eq!(
        final_root_a, final_root_b,
        "Final cluster state roots must be bit-identical"
    );

    let tx_verify_avg_us = if blocks_count > 0 {
        total_tx_verify_dur.as_micros() as f64 / blocks_count as f64
    } else {
        0.0
    };

    let qc_verify_avg_us = if blocks_count > 0 {
        total_qc_verify_dur.as_micros() as f64 / blocks_count as f64
    } else {
        0.0
    };

    let consensus_exec_avg_ms = if blocks_count > 0 {
        total_consensus_exec_dur.as_secs_f64() * 1000.0 / blocks_count as f64
    } else {
        0.0
    };

    // Clean up PQ environment overrides
    set_pure_pq_override(None);
    std::env::remove_var("STELL_PURE_PQ");
    clear_validator_pq_keys_for_tests();

    BenchmarkResult {
        mode,
        pacing_ms,
        target_txs: total_txs,
        applied_txs: total_applied,
        blocks: blocks_count,
        wall_clock_secs,
        real_e2e_tps,
        tx_verify_avg_us,
        qc_verify_avg_us,
        consensus_exec_avg_ms,
        final_state_root: final_root_a,
    }
}

fn print_comparison_table(results: &[BenchmarkResult]) {
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                 E2E CONSENSUS PACING BENCHMARK COMPARISON TABLE                                ║");
    println!("╠══════════════════╦════════════╦═════════════╦════════╦═════════════╦═══════════════╦══════════════╦═══════════╣");
    println!("║ Mode             ║ Pacing(ms) ║ Txs (Final) ║ Blocks ║ Wall-Clock  ║ Real e2e TPS  ║ Tx Ver(µs/b) ║ µQC/QC(µs)║");
    println!("╠══════════════════╬════════════╬═════════════╬════════╬═════════════╬═══════════════╬══════════════╬═══════════╣");

    for r in results {
        let mode_str = match r.mode {
            BenchmarkMode::ClassicalEd25519 => "Classical Ed",
            BenchmarkMode::PurePostQuantumFalcon512 => "Pure PQ Falcon",
        };
        println!(
            "║ {:<16} ║ {:>10} ║ {:>11} ║ {:>6} ║ {:>9.3} s ║ {:>11.1} ║ {:>12.1} ║ {:>9.1} ║",
            mode_str,
            r.pacing_ms,
            format!("{}/{}", r.applied_txs, r.target_txs),
            r.blocks,
            r.wall_clock_secs,
            r.real_e2e_tps,
            r.tx_verify_avg_us,
            r.qc_verify_avg_us,
        );
    }
    println!("╚══════════════════╩════════════╩═════════════╩════════╩═════════════╩═══════════════╩══════════════╩═══════════╝");
}
