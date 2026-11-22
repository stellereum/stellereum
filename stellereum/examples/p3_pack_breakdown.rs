//! Packing breakdown: selection / propose stages / apply / thread scaling.
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::consensus::ValidatorSet;
use stellereum::mempool::Mempool;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}
fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn fee(i: u64) -> u64 {
    (i.wrapping_mul(7919) % 1000) + 1
}
fn legacy_tx(sk: &SigningKey, to: [u8; 32], nonce: u64, seq: u64) -> Transaction {
    Transaction::sign(sk, to, 1, fee(seq), nonce, 1, 1)
}

#[tokio::main]
async fn main() {
    const RECIP: [u8; 32] = [9u8; 32];
    let keys: Vec<SigningKey> = (0..100u64).map(det_key).collect();
    let build_pool = || {
        let mut p = Mempool::new(20_000, 10_000);
        let mut seq = 0u64;
        for sk in &keys {
            for nonce in 0..100u64 {
                p.add_checked(legacy_tx(sk, RECIP, nonce, seq), BAL)
                    .unwrap();
                seq += 1;
            }
        }
        p
    };

    // ---- selection: trivial vs nonce-filter ----
    let pool = build_pool();
    for _ in 0..2 {
        let _ = pool.select_for_block_multi(10_000, 30_000_000, |_| true);
    }
    let t = Instant::now();
    for _ in 0..5 {
        let out = pool.select_for_block_multi(10_000, 30_000_000, |_| true);
        assert_eq!(out.len(), 10_000);
    }
    println!(
        "select trivial 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 5.0
    );

    let mut expected: std::collections::HashMap<[u8; 32], (u64, u64)> =
        std::collections::HashMap::new();
    for k in &keys {
        expected.insert(id_of(k), (0, BAL));
    }
    let t = Instant::now();
    for _ in 0..5 {
        let next = std::cell::RefCell::new(expected.clone());
        let out = pool.select_for_block_multi(10_000, 30_000_000, |tx| {
            if let Some((exp, bal)) = next.borrow_mut().get_mut(&tx.from) {
                if tx.nonce != *exp {
                    return false;
                }
                let cost = tx.amount + tx.gas_limit;
                if *bal < cost {
                    return false;
                }
                *exp += 1;
                *bal -= cost;
                true
            } else {
                false
            }
        });
        assert_eq!(out.len(), 10_000);
    }
    println!(
        "select nonce-filter 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 5.0
    );

    // ---- senders() vs all() derivation ----
    let t = Instant::now();
    for _ in 0..20 {
        let _ = pool.senders();
    }
    println!(
        "senders() 10k: {:.3} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 20.0
    );
    let t = Instant::now();
    for _ in 0..20 {
        let v = pool.all();
        let _: std::collections::BTreeSet<[u8; 32]> = v.iter().map(|tx| tx.from).collect();
    }
    println!(
        "all()+derive 10k: {:.3} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 20.0
    );

    // ---- full propose (pool prebuilt, engine pre-funded; time propose only) ----
    let funding: Vec<([u8; 32], u64)> = keys.iter().map(|k| (id_of(k), BAL)).collect();
    // warm
    {
        let pool2 = Arc::new(tokio::sync::RwLock::new(build_pool()));
        let val_sk = det_key(42_000_000);
        let val = id_of(&val_sk);
        let engine = Arc::new(InMemoryStateEngine::new());
        engine.update_account(AccountState::new(val, BAL)).await;
        for (a, b) in &funding {
            engine.update_account(AccountState::new(*a, *b)).await;
        }
        let vs = ValidatorSet::from_list(vec![(val, 1)]);
        let mut rt = ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool2);
        let _ = rt.propose(TS).await.unwrap();
    }
    let t = Instant::now();
    let mut block = None;
    for _ in 0..5 {
        let pool2 = Arc::new(tokio::sync::RwLock::new(build_pool()));
        let val_sk = det_key(42_000_000);
        let val = id_of(&val_sk);
        let engine = Arc::new(InMemoryStateEngine::new());
        engine.update_account(AccountState::new(val, BAL)).await;
        for (a, b) in &funding {
            engine.update_account(AccountState::new(*a, *b)).await;
        }
        let vs = ValidatorSet::from_list(vec![(val, 1)]);
        let mut rt = ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool2);
        let t1 = Instant::now();
        let b = rt.propose(TS).await.unwrap();
        let _ = t1;
        block = Some(b);
    }
    // NOTE: pool rebuild (signing 10k) is inside the loop above; isolate below.
    println!(
        "propose+poolbuild 10k x5 avg: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 5.0
    );
    let block = block.unwrap();

    // propose-only, pool+engine prebuilt once, fresh runtime per propose is
    // impossible (propose consumes mempool state? no — propose only reads).
    // Reuse one runtime 5x to time propose itself.
    {
        let pool2 = Arc::new(tokio::sync::RwLock::new(build_pool()));
        let val_sk = det_key(42_000_000);
        let val = id_of(&val_sk);
        let engine = Arc::new(InMemoryStateEngine::new());
        engine.update_account(AccountState::new(val, BAL)).await;
        for (a, b) in &funding {
            engine.update_account(AccountState::new(*a, *b)).await;
        }
        let vs = ValidatorSet::from_list(vec![(val, 1)]);
        let mut rt = ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool2);
        let t = Instant::now();
        for _ in 0..5 {
            let b = rt.propose(TS).await.unwrap();
            assert_eq!(b.transactions.len(), 10_000);
        }
        println!(
            "propose-only 10k (same pool): {:.2} ms",
            t.elapsed().as_secs_f64() * 1000.0 / 5.0
        );
    }

    // ---- assembly pieces ----
    let t = Instant::now();
    let mut enc_len = 0;
    for _ in 0..5 {
        let bytes = bincode::serialize(&block).unwrap();
        enc_len = bytes.len();
    }
    println!(
        "block encode 10k ({} bytes): {:.2} ms",
        enc_len,
        t.elapsed().as_secs_f64() * 1000.0 / 5.0
    );
    let t = Instant::now();
    for _ in 0..5 {
        let _ = block.compute_hash();
    }
    println!(
        "block compute_hash 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 5.0
    );
    let t = Instant::now();
    for _ in 0..5 {
        let mut acc = 0u64;
        for tx in &block.transactions {
            acc ^= tx.compute_tx_hash()[0] as u64;
        }
        std::hint::black_box(acc);
    }
    println!(
        "compute_tx_hash x10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 5.0
    );

    // unseal gate sequential vs parallel (plain txs: hash+lookup)
    {
        let pool_r = build_pool();
        let txs = pool_r.select_for_block_multi(10_000, 30_000_000, |_| true);
        let t = Instant::now();
        for _ in 0..5 {
            let mut kept = 0;
            for tx in &txs {
                if matches!(
                    pool_r.mev.verify_pool_tx(tx),
                    stellereum::mev::SealVerdict::Match | stellereum::mev::SealVerdict::NotSealed
                ) {
                    kept += 1;
                }
            }
            assert_eq!(kept, 10_000);
        }
        println!(
            "unseal sequential 10k: {:.2} ms",
            t.elapsed().as_secs_f64() * 1000.0 / 5.0
        );
        use rayon::prelude::*;
        let t = Instant::now();
        for _ in 0..5 {
            let checked: Vec<bool> = txs
                .par_iter()
                .map(|tx| {
                    matches!(
                        pool_r.mev.verify_pool_tx(tx),
                        stellereum::mev::SealVerdict::Match
                            | stellereum::mev::SealVerdict::NotSealed
                    )
                })
                .collect();
            assert_eq!(checked.len(), 10_000);
        }
        println!(
            "unseal parallel 10k: {:.2} ms",
            t.elapsed().as_secs_f64() * 1000.0 / 5.0
        );
    }

    // ---- sig verify ----
    let t = Instant::now();
    for _ in 0..3 {
        assert!(Transaction::verify_signatures_batch_parallel(
            &block.transactions
        ));
    }
    println!(
        "batch-parallel sig verify 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 3.0
    );
    let t = Instant::now();
    for _ in 0..3 {
        assert!(Transaction::verify_signatures_batch(&block.transactions));
    }
    println!(
        "sequential batch sig verify 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / 3.0
    );

    // ---- apply vs N ----
    for n in [1_000usize, 5_000, 10_000] {
        let e = Arc::new(InMemoryStateEngine::new());
        let txs: Vec<Transaction> = block.transactions[..n].to_vec();
        for k in &keys {
            e.update_account(AccountState::new(id_of(k), BAL)).await;
        }
        e.update_account(AccountState::new(RECIP, 0)).await;
        let t = Instant::now();
        let (applied, failed, _, _, _) = e.apply_block_parallel_fees(&txs, TS).await;
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(applied, n);
        assert_eq!(failed, 0);
        println!(
            "apply {n}: {ms:.2} ms ({:.0} tx/s)",
            n as f64 / (ms / 1000.0)
        );
    }

    // ---- apply split: sig verify vs commit (commit measured by pre-verified path is same fn; report verify share) ----
    {
        let e = Arc::new(InMemoryStateEngine::new());
        for k in &keys {
            e.update_account(AccountState::new(id_of(k), BAL)).await;
        }
        e.update_account(AccountState::new(RECIP, 0)).await;
        let txs = &block.transactions;
        let t = Instant::now();
        for _ in 0..3 {
            assert!(Transaction::verify_signatures_batch_parallel(txs));
        }
        let vms = t.elapsed().as_secs_f64() * 1000.0 / 3.0;
        let t = Instant::now();
        let (a, _, _, _, _) = e.apply_block_parallel_fees(txs, TS).await;
        let ams = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(a, 10_000);
        println!(
            "apply split 10k: verify {vms:.2} ms of {ams:.2} ms total ({:.0}% verify)",
            vms / ams * 100.0
        );
    }

    // ---- thread scaling curve 1/2/4/8 (isolated pools, same 10k workload) ----
    // The two rayon kernels on the packing path — the proposer unseal gate and
    // the batched ed25519 verify (commit 850cfff, reused here) — measured inside
    // `ThreadPoolBuilder` pools so ONE run prints the whole curve. `par_iter` /
    // `par_chunks` inside `install` run on that pool, so each line is the kernel
    // at exactly that thread count. Full propose/apply scaling still needs
    // external runs (they use the global pool): RAYON_NUM_THREADS=1/2/4/8 gave
    // propose-only 926/511/311/215 ms and apply-10k 242/147/94/71 ms.
    {
        let pool_r = build_pool();
        let txs = pool_r.select_for_block_multi(10_000, 30_000_000, |_| true);
        assert_eq!(txs.len(), 10_000);
        for threads in [1usize, 2, 4, 8] {
            let tp = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let t = Instant::now();
            for _ in 0..3 {
                tp.install(|| {
                    assert!(Transaction::verify_signatures_batch_parallel(&txs));
                });
            }
            let vms = t.elapsed().as_secs_f64() * 1000.0 / 3.0;
            let t = Instant::now();
            for _ in 0..3 {
                tp.install(|| {
                    use rayon::prelude::*;
                    let checked: Vec<bool> = txs
                        .par_iter()
                        .map(|tx| {
                            matches!(
                                pool_r.mev.verify_pool_tx(tx),
                                stellereum::mev::SealVerdict::Match
                                    | stellereum::mev::SealVerdict::NotSealed
                            )
                        })
                        .collect();
                    assert_eq!(checked.len(), 10_000);
                });
            }
            let ums = t.elapsed().as_secs_f64() * 1000.0 / 3.0;
            println!("threads {threads}: verify {vms:.2} ms, unseal {ums:.2} ms");
        }
    }

    // ---- thread scaling: RAYON_NUM_THREADS must be set externally; report current ----
    println!("rayon threads: {}", rayon::current_num_threads());
}
