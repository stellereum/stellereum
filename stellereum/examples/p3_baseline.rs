//! P3 baseline: timing harness for the three hot paths under optimization.
//!
//! Run with: `cargo run --release --example p3_baseline`
//!
//! Measures, before and after each P3 change:
//!   1. `get_state_root` latency vs state size (H1: incremental commitment).
//!   2. `QuorumCertificate::verify` latency vs signer count (H2: batch verify).
//!   3. Block-apply latency with N transactions (H3: already parallel).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Instant;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn ms(nanos: u128, iters: u64) -> f64 {
    nanos as f64 / 1_000_000.0 / iters as f64
}

#[tokio::main]
async fn main() {
    println!(
        "profile: {}",
        if cfg!(debug_assertions) {
            "DEBUG (slow)"
        } else {
            "RELEASE"
        }
    );
    println!();

    // ---- 1. get_state_root vs state size ----
    for accounts in [100u64, 1_000, 10_000] {
        let engine = Arc::new(InMemoryStateEngine::new());
        for i in 0..accounts {
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&i.to_le_bytes());
            engine
                .update_account(AccountState::new(addr, 1_000_000))
                .await;
        }
        // Warm up (first read commits the digest).
        let _ = engine.get_state_root().await;
        let t = Instant::now();
        let iters = 20u64;
        for _ in 0..iters {
            let _ = engine.get_state_root().await;
        }
        println!(
            "  get_state_root: {:>6} accounts -> {:>8.3} ms/read",
            accounts,
            ms(t.elapsed().as_nanos(), iters)
        );
    }
    println!();

    // ---- 1b. get_state_root with heavy non-trie domains ----
    {
        let engine = Arc::new(InMemoryStateEngine::new());
        // 200 validators x 50 delegators + orderbook + contracts pressure.
        for v in 0..200u64 {
            let mut val = [0u8; 32];
            val[..8].copy_from_slice(&v.to_le_bytes());
            engine
                .update_account(AccountState::new(val, 10_000_000_000_000))
                .await;
            engine
                .staking_write()
                .await
                .bond(val, 1_000_000_000_000, 0)
                .unwrap();
            for d in 0..50u64 {
                let mut dep = [0u8; 32];
                dep[..8].copy_from_slice(&d.to_le_bytes());
                dep[8..16].copy_from_slice(&v.to_le_bytes());
                engine
                    .update_account(AccountState::new(dep, 10_000_000))
                    .await;
                engine
                    .staking_write()
                    .await
                    .delegate(dep, val, 2_000_000_000)
                    .unwrap();
            }
        }
        let _ = engine.get_state_root().await;
        let t = Instant::now();
        let iters = 20u64;
        for _ in 0..iters {
            let _ = engine.get_state_root().await;
        }
        println!(
            "  get_state_root heavy cached: 200 val + 10k deleg -> {:>8.3} ms/read",
            ms(t.elapsed().as_nanos(), iters)
        );
        // Forced recompute: mutate between reads (a transfer touches accounts).
        let t = Instant::now();
        let mut acc = [7u8; 32];
        for i in 0..iters {
            acc[0] = i as u8;
            engine.update_account(AccountState::new(acc, i)).await;
            let _ = engine.get_state_root().await;
        }
        println!(
            "  get_state_root heavy dirty: 200 val + 10k deleg -> {:>8.3} ms/read",
            ms(t.elapsed().as_nanos(), iters)
        );
    }
    println!();

    // ---- 2. QC verify vs signer count ----
    for n in [2usize, 4, 10, 25, 50, 100] {
        let ks: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let bh = [0x42u8; 32];
        let sigs: Vec<([u8; 32], Vec<u8>)> = ks
            .iter()
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        let qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs,
        };
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        assert!(qc.verify(&vs));
        let t = Instant::now();
        let iters = 20u64;
        for _ in 0..iters {
            assert!(qc.verify(&vs));
        }
        println!(
            "  QC verify: {:>3} signers -> {:>8.3} ms/verify",
            n,
            ms(t.elapsed().as_nanos(), iters)
        );
    }
    println!();

    // ---- 2b. Tx signature verify: scalar loop vs batch (BEFORE vs AFTER) ----
    // BEFORE: every hot path verified one tx at a time (`verify_signature` in
    // a loop: mempool insert, gossip ingest, RPC submit, propose filter).
    // AFTER: `Transaction::verify_signatures_batch[_parallel]` /
    // `verify_signatures_partitioned` (same `verify_batch` pattern as the QC
    // precedent, commit 687ec90). All-valid sets: batch must win; the numbers
    // below are the delta.
    for n in [10usize, 100, 1_000] {
        let sk = SigningKey::generate(&mut OsRng);
        let to = [9u8; 32];
        let txs: Vec<Transaction> = (0..n as u64)
            .map(|i| Transaction::sign(&sk, to, 1, 0, i, 1, 1))
            .collect();
        assert!(Transaction::verify_signatures_batch(&txs));
        // BEFORE (scalar loop).
        let t = Instant::now();
        let iters = 10u64;
        for _ in 0..iters {
            assert!(txs.iter().all(|tx| tx.verify_signature()));
        }
        let scalar_ms = ms(t.elapsed().as_nanos(), iters);
        // AFTER (batch).
        let t = Instant::now();
        for _ in 0..iters {
            assert!(Transaction::verify_signatures_batch(&txs));
        }
        let batch_ms = ms(t.elapsed().as_nanos(), iters);
        // AFTER with offender identification (partitioned; all-valid fast path).
        let t = Instant::now();
        for _ in 0..iters {
            let flags = Transaction::verify_signatures_partitioned(&txs);
            assert!(flags.iter().all(|b| *b));
        }
        let part_ms = ms(t.elapsed().as_nanos(), iters);
        println!(
            "  tx verify: {:>5} txs scalar {:>8.3} ms ({:>7.1} ver/s) | batch {:>8.3} ms ({:.2}x) | partitioned {:>8.3} ms ({:.2}x)",
            n,
            scalar_ms,
            n as f64 / (scalar_ms / 1000.0),
            batch_ms,
            scalar_ms / batch_ms.max(1e-9),
            part_ms,
            scalar_ms / part_ms.max(1e-9),
        );
    }
    println!();

    // ---- 2c. Vote verify: scalar loop vs batch (BEFORE vs AFTER) ----
    // BEFORE: `VoteSet::add` verified each vote with scalar `Vote::verify`
    // (prevote/precommit ingestion, 23.13K vote/s stand ceiling).
    // AFTER: `Vote::verify_batch` / `Vote::partition_valid` /
    // `VoteSet::add_batch` (quorum-like set: one height/round/kind/target, so
    // one shared message — the same shape as the QC fast path).
    for n in [10usize, 50, 100] {
        let ks: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let bh = [0x42u8; 32];
        let votes: Vec<Vote> = ks
            .iter()
            .map(|k| Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .collect();
        assert!(Vote::verify_batch(&votes));
        let t = Instant::now();
        let iters = 20u64;
        for _ in 0..iters {
            assert!(votes.iter().all(|v| v.verify()));
        }
        let scalar_ms = ms(t.elapsed().as_nanos(), iters);
        let t = Instant::now();
        for _ in 0..iters {
            assert!(Vote::verify_batch(&votes));
        }
        let batch_ms = ms(t.elapsed().as_nanos(), iters);
        let t = Instant::now();
        for _ in 0..iters {
            assert!(Vote::partition_valid(&votes).iter().all(|b| *b));
        }
        let part_ms = ms(t.elapsed().as_nanos(), iters);
        println!(
            "  vote verify: {:>3} votes scalar {:>8.3} ms ({:>7.1} ver/s) | batch {:>8.3} ms ({:.2}x) | partitioned {:>8.3} ms ({:.2}x)",
            n,
            scalar_ms,
            n as f64 / (scalar_ms / 1000.0),
            batch_ms,
            scalar_ms / batch_ms.max(1e-9),
            part_ms,
            scalar_ms / part_ms.max(1e-9),
        );
    }
    println!();

    // ---- 3. Block apply vs tx count ----
    for n in [10usize, 100, 1_000] {
        let engine = Arc::new(InMemoryStateEngine::new());
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(from, u64::MAX / 2))
            .await;
        let to = [9u8; 32];
        engine.update_account(AccountState::new(to, 0)).await;
        let txs: Vec<Transaction> = (0..n as u64)
            .map(|i| Transaction::sign(&sk, to, 1, 0, i, 1, 1))
            .collect();
        let t = Instant::now();
        let (applied, _, _, _, _) = engine.apply_block_parallel_fees(&txs, 0).await;
        assert_eq!(applied, n);
        println!(
            "  apply block: {:>5} txs -> {:>8.3} ms total ({:>8.1} tx/s)",
            n,
            t.elapsed().as_secs_f64() * 1000.0,
            n as f64 / t.elapsed().as_secs_f64()
        );
    }
}
