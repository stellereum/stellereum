use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // 500 distinct funded senders, 20 tx each = 10k txs
        let keys: Vec<SigningKey> = (0..500).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let engine = InMemoryStateEngine::new();
        for sk in &keys {
            engine
                .update_account(AccountState::new(sk.verifying_key().to_bytes(), 10_000_000))
                .await;
        }
        let mut txs = Vec::new();
        let n_each = 20u64;
        for (i, sk) in keys.iter().enumerate() {
            let to = keys[(i + 1) % keys.len()].verifying_key().to_bytes();
            for nonce in 0..n_each {
                txs.push(Transaction::sign(sk, to, 10, 0, nonce, 1, 1));
            }
        }
        let n = txs.len() as u64;

        // sequential apply_transaction
        let e1 = InMemoryStateEngine::new();
        for sk in &keys {
            e1.update_account(AccountState::new(sk.verifying_key().to_bytes(), 10_000_000))
                .await;
        }
        let t0 = Instant::now();
        for tx in &txs {
            let _ = e1.apply_transaction(tx, 0).await;
        }
        let seq = n as f64 / t0.elapsed().as_secs_f64();

        // batched+grouped block apply
        let e2 = InMemoryStateEngine::new();
        for sk in &keys {
            e2.update_account(AccountState::new(sk.verifying_key().to_bytes(), 10_000_000))
                .await;
        }
        let t1 = Instant::now();
        let (applied, _f) = e2.apply_block_parallel(&txs, 0).await;
        let par = n as f64 / t1.elapsed().as_secs_f64();

        println!("txs={n} applied={applied}");
        println!("sequential apply_transaction: {seq:.0} tx/s");
        println!("block apply (batched+grouped): {par:.0} tx/s");
        println!("speedup: {:.2}x", par / seq);
        // state roots equal?
        println!(
            "roots equal: {}",
            e1.get_state_root().await == e2.get_state_root().await
        );
    });
}
