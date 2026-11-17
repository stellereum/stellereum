//! Performance smoke tests (part of `cargo test`).
//! For REAL numbers run the full benchmark in release:
//!     cargo run --release --example benchmark
//!
//! These assertions are deliberately loose so they pass in debug too; their job
//! is to catch catastrophic regressions, not to be precise micro-benchmarks.

use std::time::Instant;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};

fn tps(iters: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        iters as f64 / secs
    }
}

#[tokio::test]
async fn perf_native_transfer_tps() {
    let engine = InMemoryStateEngine::new();
    // FULL-PQ: native transfers are signed Falcon-512 PQ1 envelopes.
    let sk = FalconKeypair::generate_from_seed(0x11);
    let from = derive_pq_address(PqScheme::Falcon512, &sk.public_key, &DEFAULT_SALT);
    let to = [2u8; 32];
    engine
        .update_account(AccountState::new(from, u64::MAX / 2))
        .await;

    let n = 500u64;
    let pk = sk.public_key.clone();
    let txs: Vec<Transaction> = (0..n)
        .map(|i| {
            let probe = Transaction::new_pq_explicit(
                PqScheme::Falcon512,
                pk.clone(),
                vec![0u8; FALCON512_SIG_LEN],
                to,
                1,
                0,
                i,
                1,
                1,
                Vec::new(),
                &DEFAULT_SALT,
            );
            let sig = sk.sign(&probe.signing_message());
            Transaction::new_pq_explicit(
                PqScheme::Falcon512,
                pk.clone(),
                sig,
                to,
                1,
                0,
                i,
                1,
                1,
                Vec::new(),
                &DEFAULT_SALT,
            )
        })
        .collect();

    let t = Instant::now();
    for tx in &txs {
        engine.apply_transaction(tx, 0).await.unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    let rate = tps(n, secs);
    println!("[perf] native transfer TPS = {:.0} tx/s", rate);
    // Loose bound: passes in debug (where Falcon verify is slower than release).
    assert!(rate > 10.0, "native TPS collapsed: {rate}");
}

#[test]
fn perf_svm_opcode_throughput() {
    let ops: Vec<OpCode> = std::iter::repeat_n(OpCode::Nop, 1_000).collect();
    let n = 200u64;
    let t = Instant::now();
    let mut total = 0u64;
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
            total += ops.len() as u64;
        }
    }
    let secs = t.elapsed().as_secs_f64();
    let rate = tps(total, secs);
    println!("[perf] SVM opcode throughput = {:.0} ops/s", rate);
    assert!(rate > 100_000.0, "SVM throughput collapsed: {rate}");
}

/// Guards against the known O(n^2) trie rebuild regression: inserting must not
/// blow up catastrophically for a modest key count.
#[test]
fn perf_trie_insert_smoke() {
    use stellereum::cell::PatriciaTrie;
    let mut trie = PatriciaTrie::new();
    let n = 200u64;
    let t = Instant::now();
    for i in 0..n {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&i.to_be_bytes());
        trie.insert(&k, &i.to_be_bytes());
    }
    let secs = t.elapsed().as_secs_f64();
    let rate = tps(n, secs);
    println!(
        "[perf] trie insert = {:.0} ins/s  (NOTE: O(n) rebuild, target of Stage 4)",
        rate
    );
    // Very loose: just ensure it completes and is not absurdly slow.
    assert!(
        rate > 5.0,
        "trie insert path is pathologically slow: {rate}"
    );
}
