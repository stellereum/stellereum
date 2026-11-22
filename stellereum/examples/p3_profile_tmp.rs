//! Temp profiling harness for block packing (NOT committed).
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
    let threads = rayon::current_num_threads();
    println!("rayon threads: {threads}");
    const RECIP: [u8; 32] = [9u8; 32];

    // Build 10k pool: 100 senders x 100 nonces.
    let keys: Vec<SigningKey> = (0..100u64).map(det_key).collect();
    let mut pool = Mempool::new(20_000, 10_000);
    let mut seq = 0u64;
    for sk in &keys {
        for nonce in 0..100u64 {
            pool.add_checked(legacy_tx(sk, RECIP, nonce, seq), BAL)
                .unwrap();
            seq += 1;
        }
    }
    assert_eq!(pool.len(), 10_000);

    // ---- 1. selection time: trivial accept ----
    for _ in 0..3 {
        let _ = pool.select_for_block_multi(10_000, 30_000_000, |_| true);
    }
    let t = Instant::now();
    let iters = 5;
    for _ in 0..iters {
        let out = pool.select_for_block_multi(10_000, 30_000_000, |_| true);
        assert_eq!(out.len(), 10_000);
    }
    println!(
        "select trivial-accept 10k pool: {:.2} ms/pass-set",
        t.elapsed().as_secs_f64() * 1000.0 / iters as f64
    );

    // ---- 2. selection with stateful nonce filter (realistic propose-like) ----
    // snapshot balances like propose does
    let mut expected: std::collections::HashMap<[u8; 32], (u64, u64)> =
        std::collections::HashMap::new();
    for k in &keys {
        expected.insert(id_of(k), (0, BAL));
    }
    let t = Instant::now();
    for _ in 0..iters {
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
        "select nonce-filter 10k pool: {:.2} ms/pass-set",
        t.elapsed().as_secs_f64() * 1000.0 / iters as f64
    );

    // ---- 3. full propose ----
    let funding: Vec<([u8; 32], u64)> = keys.iter().map(|k| (id_of(k), BAL)).collect();
    let mk_rt = || {
        let pool2 = {
            let mut p = Mempool::new(20_000, 10_000);
            let mut s = 0u64;
            for sk in &keys {
                for nonce in 0..100u64 {
                    p.add_checked(legacy_tx(sk, RECIP, nonce, s), BAL).unwrap();
                    s += 1;
                }
            }
            Arc::new(tokio::sync::RwLock::new(p))
        };
        let val_sk = det_key(42_000_000);
        let val = id_of(&val_sk);
        let engine = Arc::new(InMemoryStateEngine::new());
        (val_sk, val, engine, pool2, funding.clone())
    };
    // warm
    {
        let (val_sk, val, engine, pool2, funding) = mk_rt();
        engine.update_account(AccountState::new(val, BAL)).await;
        for (a, b) in &funding {
            engine.update_account(AccountState::new(*a, *b)).await;
        }
        let vs = ValidatorSet::from_list(vec![(val, 1)]);
        let mut rt = ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool2);
        let _ = rt.propose(TS).await.unwrap();
    }
    let t = Instant::now();
    let piters = 3;
    let mut last_block = None;
    for _ in 0..piters {
        let (val_sk, val, engine, pool2, funding) = mk_rt();
        engine.update_account(AccountState::new(val, BAL)).await;
        for (a, b) in &funding {
            engine.update_account(AccountState::new(*a, *b)).await;
        }
        let vs = ValidatorSet::from_list(vec![(val, 1)]);
        let mut rt = ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool2);
        let b = rt.propose(TS).await.unwrap();
        last_block = Some(b);
    }
    println!(
        "full propose 10k: {:.2} ms/propose",
        t.elapsed().as_secs_f64() * 1000.0 / piters as f64
    );
    let block = last_block.unwrap();

    // ---- 4. propose assembly pieces: encode / hash / sign ----
    let t = Instant::now();
    let eiters = 5;
    let mut enc_len = 0;
    for _ in 0..eiters {
        let bytes = bincode::serialize(&block).unwrap();
        enc_len = bytes.len();
    }
    println!(
        "block bincode encode 10k ({} bytes): {:.2} ms",
        enc_len,
        t.elapsed().as_secs_f64() * 1000.0 / eiters as f64
    );

    let t = Instant::now();
    for _ in 0..eiters {
        let _ = block.compute_hash();
    }
    println!(
        "block compute_hash 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / eiters as f64
    );

    // compute_tx_hash share: hash all txs
    let t = Instant::now();
    for _ in 0..eiters {
        let mut acc = 0u64;
        for tx in &block.transactions {
            let h = tx.compute_tx_hash();
            acc ^= h[0] as u64;
        }
        std::hint::black_box(acc);
    }
    println!(
        "compute_tx_hash x10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / eiters as f64
    );

    // batch sig verify share
    let t = Instant::now();
    let viters = 3;
    for _ in 0..viters {
        assert!(Transaction::verify_signatures_batch_parallel(
            &block.transactions
        ));
    }
    println!(
        "batch sig verify 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / viters as f64
    );
    let t = Instant::now();
    for _ in 0..viters {
        let flags = Transaction::verify_signatures_partitioned(&block.transactions);
        assert!(flags.iter().all(|b| *b));
    }
    println!(
        "partitioned sig verify 10k: {:.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / viters as f64
    );

    // ---- 5. apply vs tx count ----
    for n in [1_000usize, 5_000, 10_000] {
        let e = Arc::new(InMemoryStateEngine::new());
        let txs: Vec<Transaction> = block.transactions[..n].to_vec();
        // fund senders involved: fund all (cheap, one-time)
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

    // ---- 6. e2e: propose + apply + root ----
    {
        let (val_sk, val, engine, pool2, funding) = mk_rt();
        engine.update_account(AccountState::new(val, BAL)).await;
        for (a, b) in &funding {
            engine.update_account(AccountState::new(*a, *b)).await;
        }
        let vs = ValidatorSet::from_list(vec![(val, 1)]);
        let mut rt = ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool2);
        let t = Instant::now();
        let b = rt.propose(TS).await.unwrap();
        let t_propose = t.elapsed();
        let t2 = Instant::now();
        let (a, f, _, _, _) = rt
            .state
            .apply_block_parallel_fees(&b.transactions, TS)
            .await;
        let t_apply = t2.elapsed();
        let root = rt.state.get_state_root().await;
        println!(
            "e2e propose {:.2} ms + apply {:.2} ms = {:.2} ms; applied={a} failed={f} root={}",
            t_propose.as_secs_f64() * 1000.0,
            t_apply.as_secs_f64() * 1000.0,
            (t_propose + t_apply).as_secs_f64() * 1000.0,
            hex::encode(&root[..8])
        );
    }
}
