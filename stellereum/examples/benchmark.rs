//! Performance benchmark: TPS, latency and protocol throughput.
//! Run in RELEASE for realistic numbers:
//!     cargo run --release --example benchmark
//!
//! Measures:
//!   - Native transfer TPS (state engine)
//!   - Token transfer TPS (STS standard + trie sync)
//!   - SVM execution throughput (opcodes/sec)
//!   - Orderbook matching (orders/sec)
//!   - Patricia trie: insert / proof-gen / proof-verify (ops/sec)
//!   - Consensus vote ingestion (votes/sec)
//!   - Block hashing + signing (blocks/sec)
//!   - Wire protocol: frame sign/verify + encode/decode (frames/sec)

use ed25519_dalek::{Signer, SigningKey};
use infnode::proto::Frame;
use rand::rngs::OsRng;
use std::time::Instant;
use stellereum::cell::PatriciaTrie;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind, VoteSet};
use stellereum::orderbook::{OrderSide, OrderbookActor};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};
use stellereum::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};

fn rate(iters: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs <= 0.0 {
        return 0.0;
    }
    iters as f64 / elapsed_secs
}

fn fmt(n: f64) -> String {
    if n >= 1_000_000.0 {
        format!("{:.2}M", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{:.2}K", n / 1_000.0)
    } else {
        format!("{:.1}", n)
    }
}

fn meta() -> TokenMetadata {
    TokenMetadata {
        name: "Bench".to_string(),
        symbol: "BNC".to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

#[tokio::main]
async fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║         STELLEREUM PERFORMANCE BENCHMARK (TPS / LATENCY)             ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!(
        "  profile: {}   (run with --release for real numbers)",
        if cfg!(debug_assertions) {
            "DEBUG (slow)"
        } else {
            "RELEASE"
        }
    );
    println!();

    // ---- 1. Native transfer TPS -------------------------------------------
    {
        let engine = InMemoryStateEngine::new();
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        let to = [2u8; 32];
        engine
            .update_account(AccountState::new(from, u64::MAX / 2))
            .await;

        let n = 5_000u64;
        let txs: Vec<Transaction> = (0..n)
            .map(|i| Transaction::sign(&sk, to, 1, 0, i, 1, 1))
            .collect();

        let t = Instant::now();
        for tx in &txs {
            engine.apply_transaction(tx, 0).await.unwrap();
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Execution] Native transfer TPS ............ {:>10} tx/s  ({:.2?} total)",
            fmt(rate(n, secs)),
            t.elapsed()
        );
    }

    // ---- 2. Token transfer TPS --------------------------------------------
    {
        let engine = InMemoryStateEngine::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let id = engine
            .create_token(a, meta(), 1_000_000_000_000)
            .await
            .unwrap();

        let n = 2_000u64;
        let t = Instant::now();
        for i in 0..n {
            if i % 2 == 0 {
                engine
                    .token_execute(&id, a, TokenOp::Transfer { to: b, amount: 1 })
                    .await
                    .unwrap();
            } else {
                engine
                    .token_execute(&id, b, TokenOp::Transfer { to: a, amount: 1 })
                    .await
                    .unwrap();
            }
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Execution] Token transfer TPS ............ {:>10} tx/s  ({:.2?} total)",
            fmt(rate(n, secs)),
            t.elapsed()
        );
    }

    // ---- 3. SVM opcode throughput -----------------------------------------
    {
        let ops: Vec<OpCode> = std::iter::repeat_n(OpCode::Nop, 1_000).collect();
        let n = 5_000u64;
        let mut total_ops = 0u64;
        let t = Instant::now();
        for _ in 0..n {
            let mut ctx = VmContext {
                sender: [1u8; 32],
                balance: 1,
                orderbooks: None,
                patricia_trie: None,
                session_auth: None,
                session_keys: None,
                pmm: None,
                zkml_proof: None,
                timestamp: 1,
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
            if let VmExecutionResult::Success { .. } = Svm::execute(&ops, 1_000_000, &mut ctx) {
                total_ops += ops.len() as u64
            }
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Execution] SVM opcode throughput ......... {:>10} ops/s ({:.2?} total)",
            fmt(rate(total_ops, secs)),
            t.elapsed()
        );
    }

    // ---- 3b. SVM mixed realistic payload (measurement only) ----------------
    // Same harness shape as section 3: a stack-neutral arithmetic + transfer
    // mix, run once as a single 1M-op execute (streaming) and as 1,000-op x
    // 1,000 fresh-context executes (many-small-payloads).
    {
        let window = [
            OpCode::Push(3),
            OpCode::Push(4),
            OpCode::Add,
            OpCode::Push(2),
            OpCode::Mul,
            OpCode::LoadBalance,
            OpCode::Pop,
            OpCode::Push(14),
            OpCode::Sub,
            OpCode::Pop,
        ];
        let mk_mixed = |len: usize| {
            let mut v = Vec::with_capacity(len + len / 200 + 1);
            for i in 0..len {
                v.push(window[i % window.len()].clone());
                if i % 200 == 199 {
                    v.push(OpCode::Transfer {
                        recipient: [9u8; 32],
                        amount: 1,
                    });
                }
            }
            v
        };
        let mk_mixed_ctx = || VmContext {
            sender: [1u8; 32],
            balance: 1_000_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            pmm: None,
            zkml_proof: None,
            timestamp: 1,
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
        let ops = mk_mixed(1_000_000);
        let mut total_ops = 0u64;
        let t = Instant::now();
        for _ in 0..3 {
            let mut ctx = mk_mixed_ctx();
            if let VmExecutionResult::Success { .. } = Svm::execute(&ops, u64::MAX / 2, &mut ctx) {
                total_ops += ops.len() as u64
            }
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Execution] SVM mixed single-call ......... {:>10} ops/s ({:.2?} total)",
            fmt(rate(total_ops, secs)),
            t.elapsed()
        );

        let chunk = mk_mixed(1_000);
        let mut total_ops = 0u64;
        let t = Instant::now();
        for _ in 0..1_000 {
            let mut ctx = mk_mixed_ctx();
            if let VmExecutionResult::Success { .. } = Svm::execute(&chunk, 1_000_000, &mut ctx) {
                total_ops += chunk.len() as u64
            }
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Execution] SVM mixed chunked ............. {:>10} ops/s ({:.2?} total)",
            fmt(rate(total_ops, secs)),
            t.elapsed()
        );
    }

    // ---- 4. Orderbook matching --------------------------------------------
    {
        let mut book = OrderbookActor::new(1, 100_000);
        let n = 5_000u64;
        let mut matched = 0u64;
        let t = Instant::now();
        for i in 0..n {
            let trader = [(i % 250) as u8; 32];
            if i % 2 == 0 {
                book.submit_order(trader, OrderSide::Sell, 100, 10, i);
            } else {
                let (_o, trades) = book.submit_order(trader, OrderSide::Buy, 100, 10, i);
                matched += trades.len() as u64;
            }
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Execution] Orderbook orders .............. {:>10} ord/s ({:.2?} total, {} fills)",
            fmt(rate(n, secs)),
            t.elapsed(),
            matched
        );
    }

    // ---- 5. Patricia trie --------------------------------------------------
    {
        let n = 10_000u64;
        let mut trie = PatriciaTrie::new();
        let t = Instant::now();
        for i in 0..n {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_be_bytes());
            trie.insert(&k, &i.to_be_bytes());
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [State]     Trie inserts ................. {:>10} ins/s ({:.2?} total)",
            fmt(rate(n, secs)),
            t.elapsed()
        );

        let keys: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..8].copy_from_slice(&i.to_be_bytes());
                k
            })
            .collect();
        let root = trie.root_hash();

        let pn = 2_000u64;
        let t2 = Instant::now();
        let proofs: Vec<_> = keys
            .iter()
            .take(pn as usize)
            .map(|k| trie.generate_merkle_proof(k).unwrap())
            .collect();
        let secs2 = t2.elapsed().as_secs_f64();
        println!(
            "  [State]     Merkle proof generation ...... {:>10} prf/s ({:.2?} total)",
            fmt(rate(pn, secs2)),
            t2.elapsed()
        );

        let t3 = Instant::now();
        for (k, p) in keys.iter().take(pn as usize).zip(proofs.iter()) {
            let v = trie.get(k).unwrap();
            assert!(PatriciaTrie::verify_merkle_proof(&root, k, v, p));
        }
        let secs3 = t3.elapsed().as_secs_f64();
        println!(
            "  [State]     Merkle proof verification .... {:>10} vrf/s ({:.2?} total)",
            fmt(rate(pn, secs3)),
            t3.elapsed()
        );
    }

    // ---- 6. Consensus vote ingestion --------------------------------------
    {
        let n = 2_000usize;
        let keys: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let vs = ValidatorSet::from_list(
            keys.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let votes: Vec<Vote> = keys
            .iter()
            .map(|k| Vote::sign(k, 1, 0, VoteKind::Prevote, Some([7u8; 32])))
            .collect();

        let mut set = VoteSet::new();
        let t = Instant::now();
        for v in votes {
            let _ = set.add(v, &vs, 1, 0, VoteKind::Prevote);
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Consensus] Vote verify+ingest ........... {:>10} vote/s ({:.2?} total)",
            fmt(rate(n as u64, secs)),
            t.elapsed()
        );
    }

    // ---- 7. Block hashing + signing ---------------------------------------
    {
        let sk = SigningKey::generate(&mut OsRng);
        let n = 20_000u64;
        let t = Instant::now();
        for i in 0..n {
            let mut b = Block::new_for_test(MASTERCHAIN_SHARD, i, [0u8; 32], [0u8; 32], vec![])
                .with_timestamp(i)
                .with_proposer(sk.verifying_key().to_bytes());
            b.sign_block(&sk);
            let _ = b.compute_hash();
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  [Consensus] Block hash+sign .............. {:>10} blk/s ({:.2?} total)",
            fmt(rate(n, secs)),
            t.elapsed()
        );
    }

    // ---- 8. Wire protocol (frame sign/verify/encode/decode) ---------------
    {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let n = 20_000u64;
        let payload = vec![0u8; 1024];
        let t = Instant::now();
        for i in 0..n {
            let mut f = Frame {
                kind: 4,
                seq: i as u32,
                ts: i as i64,
                src: [1u8; 20],
                dst: [2u8; 20],
                svc: 0,
                payload: payload.clone(),
                nonce: vec![],
                sig: [0u8; 64],
            };
            let d = blake3::hash(&f.sign_data());
            f.sig = sk.sign(d.as_bytes()).to_bytes();
            let bytes = f.encode();
            let dec = Frame::decode(&bytes).unwrap();
            assert!(dec.verify(&vk));
        }
        let secs = t.elapsed().as_secs_f64();
        let mbps = (n as f64 * 1024.0) / secs / 1_000_000.0;
        println!("  [Wire]      Frame sign+verify+enc+dec .... {:>10} frm/s ({:.2?} total, ~{:.0} MB/s @1KiB)", fmt(rate(n, secs)), t.elapsed(), mbps);
    }

    println!("\n╚══════════════════════════════════════════════════════════════════════╝\n");
}
