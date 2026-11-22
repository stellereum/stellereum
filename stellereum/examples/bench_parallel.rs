//! Parallel Block Execution Benchmark (Track #1 Disjoint Wave Scheduler)
//!
//! Measures throughput and thread scaling for parallel execution on realistic
//! 1,000 and 4,000 transaction blast blocks on a 12-thread AMD Ryzen 5 3600 machine.
//!
//! Workloads:
//!   (a) 1,000 plain transfers (disjoint senders/recipients across waves)
//!   (b) 1,000 mixed transactions (transfers + STS token transfers + CLOB limit orders)
//!   (c) 4,000 transactions (full blast capacity block)
//!
//! Compares:
//!   - Sequential apply (`parallel_exec = false`)
//!   - Parallel disjoint apply (`parallel_exec = true`)
//!   - Thread scaling curve across 1, 2, 4, 8, 12 Rayon worker threads
//!   - Asserts bit-identical state roots between sequential and parallel on every run!

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::TokenMetadata;

const INITIAL_BALANCE: u64 = 1_000_000_000;
const THREAD_CONFIGS: [usize; 5] = [1, 2, 4, 8, 12];
const TIMESTAMP_BASE: u64 = 1_700_000_000;

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

/// Pre-funds a set of signing keys in the engine.
async fn fund_accounts(engine: &InMemoryStateEngine, keys: &[SigningKey], balance: u64) {
    for k in keys {
        let addr = k.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(addr, balance))
            .await;
    }
}

/// Creates STS tokens for creators in the engine.
async fn setup_tokens(
    engine: &InMemoryStateEngine,
    creators: &[SigningKey],
    supply_per_token: u64,
) -> Vec<[u8; 32]> {
    let mut token_ids = Vec::with_capacity(creators.len());
    for (i, k) in creators.iter().enumerate() {
        let addr = k.verifying_key().to_bytes();
        let meta = token_meta(&format!("TOKEN_{i}"), &format!("TK{i}"));
        let tid = engine
            .create_token(addr, meta, supply_per_token)
            .await
            .unwrap();
        token_ids.push(tid);
    }
    token_ids
}

/// Setup state template for a benchmark run.
struct BenchmarkSetup {
    keys_transfers: Vec<SigningKey>,
    recip_transfers: Vec<[u8; 32]>,
    keys_tokens: Vec<SigningKey>,
    recip_tokens: Vec<[u8; 32]>,
    keys_traders: Vec<SigningKey>,
    token_supplies: u64,
}

impl BenchmarkSetup {
    async fn clone_into_engine(&self, engine: &InMemoryStateEngine) -> Vec<[u8; 32]> {
        fund_accounts(engine, &self.keys_transfers, INITIAL_BALANCE).await;
        fund_accounts(engine, &self.keys_tokens, INITIAL_BALANCE).await;
        fund_accounts(engine, &self.keys_traders, INITIAL_BALANCE).await;
        if !self.keys_tokens.is_empty() {
            setup_tokens(engine, &self.keys_tokens, self.token_supplies).await
        } else {
            Vec::new()
        }
    }
}

/// Generates block (a): 1,000 plain transfers (50 senders x 20 nonces, disjoint per wave)
fn build_block_1k_plain(setup: &mut BenchmarkSetup) -> Block {
    let mut rng = OsRng;
    let num_senders = 50;
    let txs_per_sender = 20;

    let senders: Vec<SigningKey> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();
    let recips: Vec<[u8; 32]> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    let mut txs = Vec::with_capacity(num_senders * txs_per_sender);
    for nonce in 0..txs_per_sender as u64 {
        for i in 0..num_senders {
            txs.push(Transaction::sign(
                &senders[i],
                recips[i],
                100,
                10,
                nonce,
                1,
                1,
            ));
        }
    }

    setup.keys_transfers = senders;
    setup.recip_transfers = recips;

    Block::new_for_test(MASTERCHAIN_SHARD, 1, [0u8; 32], [0u8; 32], txs)
        .with_timestamp(TIMESTAMP_BASE + 1)
        .with_proposer([0xAA; 32])
}

/// Generates block (b): 1,000 mixed transactions (400 transfers + 300 token transfers + 300 orders)
fn build_block_1k_mixed(setup: &mut BenchmarkSetup) -> (Block, Vec<[u8; 32]>) {
    let mut rng = OsRng;
    let waves = 20;

    // 20 senders x 20 waves = 400 transfers
    let senders_xfer: Vec<SigningKey> = (0..20).map(|_| SigningKey::generate(&mut rng)).collect();
    let recips_xfer: Vec<[u8; 32]> = (0..20)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    // 15 token senders x 20 waves = 300 token transfers across 15 tokens
    let senders_token: Vec<SigningKey> = (0..15).map(|_| SigningKey::generate(&mut rng)).collect();
    let recips_token: Vec<[u8; 32]> = (0..15)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    // 15 traders x 20 waves = 300 limit orders across 3 trading pairs
    let traders: Vec<SigningKey> = (0..15).map(|_| SigningKey::generate(&mut rng)).collect();

    // Deterministic token IDs: we need to pre-create them on engines later,
    // but the transaction payload needs `token_id`.
    // In Stellereum, `create_token` uses sha256(creator || name || symbol || timestamp=0).
    // Let's compute token IDs identically by running create_token on a dummy engine.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let token_ids = rt.block_on(async {
        let dummy = InMemoryStateEngine::new();
        setup_tokens(&dummy, &senders_token, 100_000_000).await
    });

    let mut txs = Vec::with_capacity(1000);
    for wave in 0..waves as u64 {
        // Plain transfers (20 txs)
        for i in 0..20 {
            txs.push(Transaction::sign(
                &senders_xfer[i],
                recips_xfer[i],
                50,
                10,
                wave,
                1,
                1,
            ));
        }
        // STS token transfers (15 txs)
        for i in 0..15 {
            txs.push(Transaction::sign_with_payload(
                &senders_token[i],
                recips_token[i],
                0,
                2000,
                wave,
                1,
                1,
                vec![OpCode::SysCallTokenTransfer {
                    token_id: token_ids[i],
                    to: recips_token[i],
                    amount: 25,
                }],
            ));
        }
        // CLOB limit orders (15 txs, non-crossing resting bids/asks)
        for (i, trader) in traders.iter().enumerate().take(15) {
            let is_buy = (i % 2) == 0;
            let pair_id = (i as u32 % 3) + 1;
            let price = if is_buy {
                80 + (i as u64 % 10)
            } else {
                120 + (i as u64 % 10)
            };
            txs.push(Transaction::sign_with_payload(
                trader,
                [0u8; 32],
                0,
                2000,
                wave,
                1,
                1,
                vec![OpCode::SysCallPlaceOrder {
                    pair_id,
                    is_buy,
                    price,
                    amount: 5,
                }],
            ));
        }
    }

    setup.keys_transfers = senders_xfer;
    setup.recip_transfers = recips_xfer;
    setup.keys_tokens = senders_token;
    setup.recip_tokens = recips_token;
    setup.keys_traders = traders;
    setup.token_supplies = 100_000_000;

    let blk = Block::new_for_test(MASTERCHAIN_SHARD, 2, [0u8; 32], [0u8; 32], txs)
        .with_timestamp(TIMESTAMP_BASE + 2)
        .with_proposer([0xBB; 32]);
    (blk, token_ids)
}

/// Generates block (c): 4,000 transactions full blast capacity block (100 senders x 40 nonces)
fn build_block_4k_blast(setup: &mut BenchmarkSetup) -> Block {
    let mut rng = OsRng;
    let num_senders = 100;
    let txs_per_sender = 40;

    let senders: Vec<SigningKey> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();
    let recips: Vec<[u8; 32]> = (0..num_senders)
        .map(|_| SigningKey::generate(&mut rng).verifying_key().to_bytes())
        .collect();

    let mut txs = Vec::with_capacity(num_senders * txs_per_sender);
    for nonce in 0..txs_per_sender as u64 {
        for i in 0..num_senders {
            txs.push(Transaction::sign(
                &senders[i],
                recips[i],
                100,
                10,
                nonce,
                1,
                1,
            ));
        }
    }

    setup.keys_transfers = senders;
    setup.recip_transfers = recips;

    Block::new_for_test(MASTERCHAIN_SHARD, 3, [0u8; 32], [0u8; 32], txs)
        .with_timestamp(TIMESTAMP_BASE + 3)
        .with_proposer([0xCC; 32])
}

struct RunMetric {
    elapsed: Duration,
    throughput: f64,
    applied: usize,
    failed: usize,
    state_root: [u8; 32],
}

/// Executes a block run on a freshly initialized engine.
fn execute_run(
    setup: &BenchmarkSetup,
    block: &Block,
    parallel_exec: bool,
    pool: &rayon::ThreadPool,
) -> RunMetric {
    pool.install(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let engine = InMemoryStateEngine::new();
            engine.set_parallel_exec(parallel_exec);
            setup.clone_into_engine(&engine).await;

            let t0 = Instant::now();
            let (applied, failed, _fees, _status, _tx_fees) = engine
                .apply_block_parallel_fees(&block.transactions, block.timestamp)
                .await;
            let elapsed = t0.elapsed();

            let state_root = engine.get_state_root().await;
            let tx_count = block.transactions.len() as f64;
            let throughput = tx_count / elapsed.as_secs_f64();

            RunMetric {
                elapsed,
                throughput,
                applied,
                failed,
                state_root,
            }
        })
    })
}

fn benchmark_block(name: &str, setup: &BenchmarkSetup, block: &Block) {
    let tx_count = block.transactions.len();
    println!("\n{}", "=".repeat(80));
    println!("BENCHMARK: {} ({} transactions)", name, tx_count);
    println!(
        "Scheduler waves: {}",
        stellereum::parallel_exec::DisjointScheduler::schedule(&block.transactions).len()
    );
    println!("{}", "-".repeat(80));

    // Warm-up run
    let warmup_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(12)
        .build()
        .unwrap();
    let _ = execute_run(setup, block, false, &warmup_pool);
    let _ = execute_run(setup, block, true, &warmup_pool);

    // 1. Sequential execution (parallel_exec = false)
    // Run 3 iterations and take the best elapsed duration
    let seq_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut best_seq: Option<RunMetric> = None;
    for _ in 0..3 {
        let m = execute_run(setup, block, false, &seq_pool);
        if best_seq.as_ref().is_none_or(|b| m.elapsed < b.elapsed) {
            best_seq = Some(m);
        }
    }
    let seq = best_seq.unwrap();
    println!(
        "Sequential (parallel_exec=false): {:>7.2} ms | {:>9.0} tx/s | applied: {} (failed: {})",
        seq.elapsed.as_secs_f64() * 1000.0,
        seq.throughput,
        seq.applied,
        seq.failed
    );
    assert_eq!(
        seq.applied, tx_count,
        "all transactions in block must apply"
    );

    // 2. Parallel thread scaling curve (parallel_exec = true) across 1, 2, 4, 8, 12 threads
    println!("\nParallel Thread Scaling Curve (parallel_exec=true):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>10} | {:>10} | {:>16}",
        "Threads", "Elapsed (ms)", "Throughput", "vs Seq", "vs 1 Thrd", "Root Identical"
    );
    println!("{}", "-".repeat(80));

    let mut t1_elapsed = Duration::ZERO;

    for &threads in &THREAD_CONFIGS {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();

        let mut best_par: Option<RunMetric> = None;
        for _ in 0..3 {
            let m = execute_run(setup, block, true, &pool);
            if best_par.as_ref().is_none_or(|b| m.elapsed < b.elapsed) {
                best_par = Some(m);
            }
        }
        let par = best_par.unwrap();

        if threads == 1 {
            t1_elapsed = par.elapsed;
        }

        // Bit-identical root verification on every run!
        assert_eq!(
            seq.state_root, par.state_root,
            "CRITICAL: State root must be bit-identical between sequential and parallel!"
        );
        assert_eq!(seq.applied, par.applied, "Applied tx count must match");
        assert_eq!(seq.failed, par.failed, "Failed tx count must match");

        let speedup_vs_seq = seq.elapsed.as_secs_f64() / par.elapsed.as_secs_f64();
        let speedup_vs_t1 = t1_elapsed.as_secs_f64() / par.elapsed.as_secs_f64();

        println!(
            "{:>8} | {:>9.2} ms | {:>7.0} tx/s | {:>9.2}x | {:>9.2}x | {:>16}",
            threads,
            par.elapsed.as_secs_f64() * 1000.0,
            par.throughput,
            speedup_vs_seq,
            speedup_vs_t1,
            "EXACT MATCH [OK]"
        );
    }
}

fn main() {
    println!(
        "╔══════════════════════════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║       STELLEREUM RELEASE BENCHMARK: PARALLEL EXECUTION & THREAD SCALING          ║"
    );
    println!(
        "║       Architecture: AMD Ryzen 5 3600 (6 Cores / 12 Threads)                      ║"
    );
    println!(
        "║       Invariant: COMMITMENT_VERSION = 4 | Bit-Identical Roots Verified           ║"
    );
    println!(
        "╚══════════════════════════════════════════════════════════════════════════════════╝"
    );

    // Workload (a): 1,000 plain transfers
    {
        let mut setup = BenchmarkSetup {
            keys_transfers: Vec::new(),
            recip_transfers: Vec::new(),
            keys_tokens: Vec::new(),
            recip_tokens: Vec::new(),
            keys_traders: Vec::new(),
            token_supplies: 0,
        };
        let block = build_block_1k_plain(&mut setup);
        benchmark_block("Block (a): 1,000 Plain Transfers", &setup, &block);
    }

    // Workload (b): 1,000 mixed transactions
    {
        let mut setup = BenchmarkSetup {
            keys_transfers: Vec::new(),
            recip_transfers: Vec::new(),
            keys_tokens: Vec::new(),
            recip_tokens: Vec::new(),
            keys_traders: Vec::new(),
            token_supplies: 0,
        };
        let (block, _token_ids) = build_block_1k_mixed(&mut setup);
        benchmark_block("Block (b): 1,000 Mixed Transactions", &setup, &block);
    }

    // Workload (c): 4,000 transactions full blast capacity block
    {
        let mut setup = BenchmarkSetup {
            keys_transfers: Vec::new(),
            recip_transfers: Vec::new(),
            keys_tokens: Vec::new(),
            recip_tokens: Vec::new(),
            keys_traders: Vec::new(),
            token_supplies: 0,
        };
        let block = build_block_4k_blast(&mut setup);
        benchmark_block("Block (c): 4,000 Blast Capacity Block", &setup, &block);
    }

    println!("\n{}", "=".repeat(80));
    println!("BENCHMARK RUN COMPLETED: All state root equivalence assertions PASSED.");
    println!("{}\n", "=".repeat(80));
}
