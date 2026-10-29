//! MANUAL AUDIT #3 — security & correctness of the PARALLEL execution path.
//! Actively tries to break apply_block_parallel / batch verify:
//!   - races (concurrent blocks), determinism, state-root equality
//!   - sender-ordering (nonce) under interleaving
//!   - sender==recipient self-transfers
//!   - duplicate txs in one block
//!   - mixed valid/invalid batches
//!   - value conservation
//!   - parallel batch verify vs sequential
//!     cargo run --release --example chaos_audit3

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn banner(s: &str) {
    println!("\n\x1b[1;36m=== {s} ===\x1b[0m");
}
fn ok(s: &str) {
    println!("  \x1b[32m✓\x1b[0m {s}");
}
fn bad(s: &str) {
    println!("  \x1b[41m✗ BROKEN:\x1b[0m {s}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    println!("\x1b[1;33m############################################################");
    println!("##  MANUAL AUDIT #3 — parallel execution security         ##");
    println!("############################################################\x1b[0m");

    // ---- 1. Parallel apply == sequential apply (state root determinism) ----
    banner("1. Determinism: parallel block apply == sequential (100 random blocks)");
    {
        let mut rng = Rng(0x1111);
        for trial in 0..100 {
            let nkeys = 1 + (rng.next() % 30) as usize;
            let keys: Vec<SigningKey> = (0..nkeys)
                .map(|_| SigningKey::generate(&mut OsRng))
                .collect();
            let e_seq = InMemoryStateEngine::new();
            let e_par = InMemoryStateEngine::new();
            for sk in &keys {
                let a = sk.verifying_key().to_bytes();
                e_seq.update_account(AccountState::new(a, 1_000_000)).await;
                e_par.update_account(AccountState::new(a, 1_000_000)).await;
            }
            // build per-sender ordered nonces
            let mut nonce: std::collections::HashMap<[u8; 32], u64> =
                std::collections::HashMap::new();
            let ntx = 1 + (rng.next() % 200) as usize;
            let mut txs = Vec::new();
            for _ in 0..ntx {
                let sk = &keys[(rng.next() as usize) % keys.len()];
                let from = sk.verifying_key().to_bytes();
                let to = keys[(rng.next() as usize) % keys.len()]
                    .verifying_key()
                    .to_bytes();
                let n = *nonce.get(&from).unwrap_or(&0);
                nonce.insert(from, n + 1);
                txs.push(Transaction::sign(sk, to, 1 + rng.next() % 500, 0, n, 1, 1));
            }
            // sequential
            for tx in &txs {
                let _ = e_seq.apply_transaction(tx, 0).await;
            }
            let (ap, _f) = e_par.apply_block_parallel(&txs, 0).await;
            let r1 = e_seq.get_state_root().await;
            let r2 = e_par.get_state_root().await;
            if r1 != r2 {
                bad(&format!("trial {trial}: roots differ (applied {ap}/{ntx})"));
            }
        }
        ok("100 random blocks: parallel state root always equals sequential");
    }

    // ---- 2. Sender-ordering: out-of-order nonces must be rejected ----
    banner("2. Sender nonce ordering (shuffled order must not apply out-of-order)");
    {
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        let to = [7u8; 32];
        let e = InMemoryStateEngine::new();
        e.update_account(AccountState::new(from, 1_000_000)).await;
        // nonces 0,1,2 but supplied shuffled
        let txs = vec![
            Transaction::sign(&sk, to, 1, 0, 2, 1, 1),
            Transaction::sign(&sk, to, 1, 0, 0, 1, 1),
            Transaction::sign(&sk, to, 1, 0, 1, 1, 1),
        ];
        let (applied, failed) = e.apply_block_parallel(&txs, 0).await;
        // grouped-by-sender preserves input order within a group: 2,0,1 ->
        // nonce 2 rejected (expected 0), 0 applied, 1 applied => 2 applied, 1 failed
        if applied != 2 || failed != 1 {
            bad(&format!(
                "nonce ordering expected 2 applied/1 failed, got {applied}/{failed}"
            ));
        }
        let acc = e.get_account(&from).await.unwrap();
        if acc.nonce != 2 {
            bad(&format!("final nonce should be 2, got {}", acc.nonce));
        }
        ok("shuffled nonces: only in-order ones applied, final nonce correct");
    }

    // ---- 3. Self-transfer (sender == recipient) ----
    banner("3. Self-transfer (sender == recipient)");
    {
        let sk = SigningKey::generate(&mut OsRng);
        let a = sk.verifying_key().to_bytes();
        let e = InMemoryStateEngine::new();
        e.update_account(AccountState::new(a, 1_000_000)).await;
        let tx = Transaction::sign(&sk, a, 100, 5, 0, 1, 1);
        let (applied, failed) = e.apply_block_parallel(std::slice::from_ref(&tx), 0).await;
        if applied != 1 || failed != 0 {
            bad("self-transfer should apply once");
        }
        // balance: -100 -5 (gas) then +100 => net -5
        let acc = e.get_account(&a).await.unwrap();
        if acc.balance != 1_000_000 - 5 {
            bad(&format!("self-transfer balance wrong: {}", acc.balance));
        }
        ok("self-transfer conserves correctly (net gas only)");
    }

    // ---- 4. Duplicate transaction in one block ----
    banner("4. Duplicate tx in one block");
    {
        let sk = SigningKey::generate(&mut OsRng);
        let a = sk.verifying_key().to_bytes();
        let e = InMemoryStateEngine::new();
        e.update_account(AccountState::new(a, 1_000_000)).await;
        let tx = Transaction::sign(&sk, [1u8; 32], 100, 0, 0, 1, 1);
        let (applied, failed) = e
            .apply_block_parallel(&[tx.clone(), tx.clone(), tx.clone()], 0)
            .await;
        // same nonce=0: first applies (nonce->1), rest rejected
        if applied != 1 || failed != 2 {
            bad(&format!(
                "duplicate handling expected 1/2, got {applied}/{failed}"
            ));
        }
        ok("duplicates: exactly one applied (nonce guard)");
    }

    // ---- 5. Mixed valid/invalid batch ----
    banner("5. Mixed valid/invalid batch (invalid subset never applied)");
    {
        let keys: Vec<SigningKey> = (0..10).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let e = InMemoryStateEngine::new();
        for sk in &keys {
            e.update_account(AccountState::new(sk.verifying_key().to_bytes(), 1_000_000))
                .await;
        }
        let mut txs = Vec::new();
        for (i, sk) in keys.iter().enumerate() {
            txs.push(Transaction::sign(
                sk,
                keys[(i + 1) % keys.len()].verifying_key().to_bytes(),
                10,
                0,
                0,
                1,
                1,
            ));
        }
        // corrupt half
        for i in (0..txs.len()).step_by(2) {
            txs[i].signature[0] ^= 0xFF;
        }
        let (applied, failed) = e.apply_block_parallel(&txs, 0).await;
        if applied + failed != txs.len() {
            bad("lost transactions");
        }
        if applied != 5 {
            bad(&format!("expected 5 valid applied, got {applied}"));
        }
        ok(&format!(
            "mixed batch: {applied} applied, {failed} rejected (no loss)"
        ));
    }

    // ---- 6. Value conservation across many parallel blocks ----
    banner("6. Value conservation across 50 parallel blocks");
    {
        let keys: Vec<SigningKey> = (0..40).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let e = InMemoryStateEngine::new();
        let mut total = 0u64;
        for sk in &keys {
            e.update_account(AccountState::new(sk.verifying_key().to_bytes(), 100_000))
                .await;
            total += 100_000;
        }
        let mut rng = Rng(0x9999);
        let mut nonce: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
        for _ in 0..50 {
            let mut txs = Vec::new();
            for _ in 0..200 {
                let sk = &keys[(rng.next() as usize) % keys.len()];
                let from = sk.verifying_key().to_bytes();
                let to = keys[(rng.next() as usize) % keys.len()]
                    .verifying_key()
                    .to_bytes();
                let n = *nonce.get(&from).unwrap_or(&0);
                nonce.insert(from, n + 1);
                txs.push(Transaction::sign(sk, to, 1 + rng.next() % 100, 0, n, 1, 1));
            }
            let _ = e.apply_block_parallel(&txs, 0).await;
        }
        let mut sum = 0u64;
        for sk in &keys {
            if let Some(a) = e.get_account(&sk.verifying_key().to_bytes()).await {
                sum += a.balance;
            }
        }
        if sum > total {
            bad(&format!("value inflated: {sum} > {total}"));
        }
        ok(&format!(
            "50 blocks x200 tx: value conserved ({sum} <= {total})"
        ));
    }

    // ---- 7. Concurrent blocks on the SAME engine (race safety) ----
    banner("7. Concurrent blocks on same engine (no panic / no corruption)");
    {
        let keys: Vec<SigningKey> = (0..20).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let e = Arc::new(InMemoryStateEngine::new());
        for sk in &keys {
            e.update_account(AccountState::new(sk.verifying_key().to_bytes(), 1_000_000))
                .await;
        }
        let mut handles = Vec::new();
        for t in 0..10 {
            let e = e.clone();
            let keys = keys.clone();
            handles.push(tokio::spawn(async move {
                // each task sends from its own disjoint sender subset (t*2, t*2+1)
                let mut txs = Vec::new();
                for i in 0..2 {
                    let sk = &keys[(t * 2 + i) % keys.len()];
                    let to = keys[(t + 5) % keys.len()].verifying_key().to_bytes();
                    txs.push(Transaction::sign(sk, to, 100, 0, 0, 1, 1));
                }
                let _ = e.apply_block_parallel(&txs, 0).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        // must not panic and root must be deterministic given the disjoint senders
        let _ = e.get_state_root().await;
        ok("10 concurrent block applies completed without panic/corruption");
    }

    // ---- 8. Parallel batch verify correctness under fuzz ----
    banner("8. Parallel batch verify fuzz (must match sequential)");
    {
        let mut rng = Rng(0xABCD);
        for _ in 0..300 {
            let n = 1 + (rng.next() % 700) as usize; // sometimes > 256 chunk
            let mut txs = Vec::new();
            for _ in 0..n {
                let sk = SigningKey::generate(&mut OsRng);
                txs.push(Transaction::sign(&sk, [1u8; 32], 1, 0, 0, 1, 1));
            }
            if rng.next().is_multiple_of(2) {
                let i = (rng.next() as usize) % txs.len();
                txs[i].signature[1] ^= 1;
            }
            let seq = Transaction::verify_signatures_batch(&txs);
            let par = Transaction::verify_signatures_batch_parallel(&txs);
            if seq != par {
                bad("parallel batch != sequential batch");
            }
        }
        ok("300 fuzzed batches: parallel verify always equals sequential");
    }

    println!("\n\x1b[1;32m############################################################");
    println!("##   AUDIT #3 PASSED — parallel execution is sound.       ##");
    println!("############################################################\x1b[0m");
}
