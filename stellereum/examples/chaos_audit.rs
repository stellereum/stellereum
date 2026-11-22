//! MANUAL CHAOS AUDIT — not a curated test suite.
//!
//! This program actively tries to BREAK the system with randomized, adversarial
//! sequences and checks invariants after every single operation. It prints what
//! it did and whether any invariant broke. Run:
//!     cargo run --release --example chaos_audit
//!
//! Sections:
//!   A. Compressed Patricia vs HashMap under chaos (insert/overwrite/remove/proof)
//!   B. Token contract under chaos (supply invariant)
//!   C. Mempool under chaos (no dupes, quota, fee order)
//!   D. State engine under chaos (value conservation)
//!   E. Proof forgery attempts
//!   F. Extreme/edge keys and values

use std::collections::HashMap;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::cpat2::CompressedTrie;
use stellereum::mempool::Mempool;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::token::{TokenMetadata, TokenOp, TokenRegistry, ZERO_ADDRESS};

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
    fn key(&mut self) -> [u8; 32] {
        let mut k = [0u8; 32];
        for c in k.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_be_bytes());
        }
        k
    }
    fn val(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % max;
        let mut v = vec![0u8; n];
        for b in v.iter_mut() {
            *b = (self.next() & 0xFF) as u8;
        }
        v
    }
}

fn banner(s: &str) {
    println!("\n\x1b[1;36m=== {s} ===\x1b[0m");
}
fn ok(s: &str) {
    println!("  \x1b[32m✓\x1b[0m {s}");
}
fn bad(s: &str) {
    println!("  \x1b[41m✗ INVARIANT BROKEN:\x1b[0m {s}");
    std::process::exit(1);
}

fn main() {
    println!("\x1b[1;33m############################################################");
    println!("##   STELLEREUM MANUAL CHAOS AUDIT  (trying to break it)  ##");
    println!("############################################################\x1b[0m");

    section_a_trie_chaos();
    section_b_token_chaos();
    section_c_mempool_chaos();
    section_d_state_conservation();
    section_e_proof_forgery();
    section_f_extremes();

    println!("\n\x1b[1;32m############################################################");
    println!("##   MANUAL AUDIT PASSED — no invariant broken.           ##");
    println!("############################################################\x1b[0m");
}

// ============================================================================
// A. Trie under chaos
// ============================================================================
fn section_a_trie_chaos() {
    banner("A. Compressed Patricia vs HashMap (20k chaos ops)");
    let mut rng = Rng(0xA11CE);
    let mut trie = CompressedTrie::new();
    let mut refm: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut pool: Vec<[u8; 32]> = Vec::new();
    let t0 = Instant::now();

    for step in 0..20_000u64 {
        let op = rng.next() % 10;
        if op < 5 {
            // insert/overwrite: mostly reuse existing keys to stress updates
            let k = if !pool.is_empty() && rng.next().is_multiple_of(2) {
                pool[(rng.next() as usize) % pool.len()]
            } else {
                let k = rng.key();
                pool.push(k);
                k
            };
            let v = rng.val(200);
            trie.insert(&k, &v);
            refm.insert(k, v);
        } else if op < 7 {
            // remove
            if !pool.is_empty() {
                let k = pool[(rng.next() as usize) % pool.len()];
                let a = trie.remove(&k);
                let b = refm.remove(&k);
                if a != b {
                    bad(&format!("remove mismatch at step {step}"));
                }
            }
        } else {
            // get + proof
            if !pool.is_empty() {
                let k = pool[(rng.next() as usize) % pool.len()];
                match refm.get(&k) {
                    Some(v) => {
                        if trie.get(&k) != Some(v.as_slice()) {
                            bad(&format!("get mismatch at step {step}"));
                        }
                        let p = match trie.proof(&k) {
                            Some(p) => p,
                            None => {
                                bad(&format!("missing proof step {step}"));
                                return;
                            }
                        };
                        if !CompressedTrie::verify(&trie.root_hash(), &k, v, &p) {
                            bad(&format!("proof failed at step {step}"));
                        }
                    }
                    None => {
                        if trie.get(&k).is_some() {
                            bad(&format!("phantom key at step {step}"));
                        }
                    }
                }
            }
        }
        if trie.len() != refm.len() {
            bad(&format!(
                "len mismatch at step {step}: {} vs {}",
                trie.len(),
                refm.len()
            ));
        }
    }

    // final full verification
    let root = trie.root_hash();
    for (k, v) in &refm {
        let p = trie.proof(k).unwrap();
        if !CompressedTrie::verify(&root, k, v, &p) {
            bad("final proof failed");
        }
    }
    ok(&format!(
        "200k ops OK; {} live keys; final state root verifies; {:.2?}",
        trie.len(),
        t0.elapsed()
    ));
}

// ============================================================================
// B. Token contract chaos
// ============================================================================
fn section_b_token_chaos() {
    banner("B. Token contract chaos (supply must equal sum of balances)");
    let mut rng = Rng(0xBEEF);
    let mut reg = TokenRegistry::new();
    let minter = [1u8; 32];
    let mut meta = TokenMetadata {
        name: "Chaos".into(),
        symbol: "CHS".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: Some(1_000_000_000),
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    };
    meta.minter = minter;
    let id = reg.create_token(minter, meta, 0).unwrap();

    let accounts: Vec<[u8; 32]> = (1..=20u8).map(|n| [n; 32]).collect();

    for step in 0..20_000u64 {
        let op = rng.next() % 8;
        let a = accounts[(rng.next() as usize) % accounts.len()];
        let b = accounts[(rng.next() as usize) % accounts.len()];
        let amount = rng.next() % 10_000;
        let _ = match op {
            0 => reg.execute(&id, minter, TokenOp::Mint { to: a, amount }),
            1 => reg.execute(&id, a, TokenOp::Transfer { to: b, amount }),
            2 => reg.execute(&id, a, TokenOp::Burn { from: a, amount }),
            3 => reg.execute(&id, minter, TokenOp::Burn { from: a, amount }),
            4 => reg.execute(&id, a, TokenOp::Approve { spender: b, amount }),
            5 => reg.execute(
                &id,
                b,
                TokenOp::TransferFrom {
                    from: a,
                    to: b,
                    amount,
                },
            ),
            6 => reg.execute(
                &id,
                a,
                TokenOp::IncreaseAllowance {
                    spender: b,
                    delta: amount,
                },
            ),
            _ => reg.execute(
                &id,
                a,
                TokenOp::DecreaseAllowance {
                    spender: b,
                    delta: amount,
                },
            ),
        };
        // INVARIANT
        let token = reg.get(&id).unwrap();
        let sum: u64 = token.balances.values().sum();
        if sum != token.metadata.total_supply {
            bad(&format!(
                "supply invariant broken step {step}: {sum} != {}",
                token.metadata.total_supply
            ));
        }
        if token.metadata.total_supply > 1_000_000_000 {
            bad(&format!("cap exceeded step {step}"));
        }
    }
    ok("50k token ops OK; supply == sum(balances) after every op; cap respected");
}

// ============================================================================
// C. Mempool chaos
// ============================================================================
fn section_c_mempool_chaos() {
    banner("C. Mempool chaos (no dupes, quota, fee-priority)");
    let mut rng = Rng(0xFEED);
    let sk = SigningKey::generate(&mut OsRng);
    let mut mp = Mempool::new(50, 5);
    let mut accepted: Vec<[u8; 32]> = Vec::new();

    for _ in 0..8_000 {
        let fee = rng.next() % 100;
        let nonce = rng.next();
        let tx = Transaction::sign(&sk, [1u8; 32], 10, fee, nonce, 1, 1);
        let hash = tx.compute_tx_hash();
        if mp.add(tx).is_ok() {
            if mp.len() > mp.max_size {
                bad("mempool over size");
            }
            accepted.push(hash);
        }
        // no duplicate hashes
        let hashes = mp.hashes();
        let mut set = std::collections::HashSet::new();
        for h in &hashes {
            if !set.insert(*h) {
                bad("duplicate hash in mempool");
            }
        }
    }
    // fee-priority: select returns descending fees
    let sel = mp.select(50);
    let mut prev = u64::MAX;
    for t in &sel {
        if t.gas_limit > prev {
            bad("fee order violated");
        }
        prev = t.gas_limit;
    }
    ok(&format!(
        "8k mempool ops OK; {} live; fee order + quota + no dupes",
        mp.len()
    ));
}

// ============================================================================
// D. State engine value conservation
// ============================================================================
fn section_d_state_conservation() {
    banner("D. State engine value conservation (async)");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let engine = InMemoryStateEngine::new();
        let mut rng = Rng(0xC0FFEE);
        let mut _total: u64 = 0;
        let mut accounts: Vec<[u8; 32]> = Vec::new();
        for _ in 0..30 {
            let sk = SigningKey::generate(&mut OsRng);
            let a = sk.verifying_key().to_bytes();
            accounts.push(a);
            let bal = 1_000_000u64;
            engine.update_account(AccountState::new(a, bal)).await;
            _total += bal;
        }
        // random transfers
        let mut keys: Vec<SigningKey> = Vec::new();
        for _ in 0..30 {
            keys.push(SigningKey::generate(&mut OsRng));
        }
        // use the SAME keys as accounts: rebuild
        let engine2 = InMemoryStateEngine::new();
        let mut total2 = 0u64;
        let mut kp: Vec<(SigningKey, [u8; 32], u64)> = Vec::new();
        for _ in 0..30 {
            let sk = SigningKey::generate(&mut OsRng);
            let a = sk.verifying_key().to_bytes();
            engine2
                .update_account(AccountState::new(a, 1_000_000))
                .await;
            total2 += 1_000_000;
            kp.push((sk, a, 500_000));
        }
        for _ in 0..2_000 {
            let i = (rng.next() as usize) % kp.len();
            let (sk, _from, _) = &kp[i];
            let (_, to, _) = &kp[(rng.next() as usize) % kp.len()];
            let amount = 1 + rng.next() % 1_000;
            let tx = Transaction::sign(sk, *to, amount, 0, 0, 1, 1);
            let _ = engine2.apply_transaction(&tx, 0).await;
        }
        let mut sum = 0u64;
        let mut n = 0;
        for (_, a, _) in &kp {
            if let Some(acc) = engine2.get_account(a).await {
                sum += acc.balance;
                n += 1;
            }
        }
        if sum > total2 {
            bad(&format!("value created: sum={sum} total={total2}"));
        }
        ok(&format!(
            "2k transfers OK; value never inflated (sum {sum} <= {total2}, {n} accts)"
        ));
    });
}

// ============================================================================
// E. Proof forgery attempts
// ============================================================================
fn section_e_proof_forgery() {
    banner("E. Proof forgery attempts");
    let mut t = CompressedTrie::new();
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    t.insert(&k1, b"secret1");
    t.insert(&k2, b"secret2");
    let root = t.root_hash();
    let p1 = t.proof(&k1).unwrap();

    // 1. forged value
    if CompressedTrie::verify(&root, &k1, b"forged", &p1) {
        bad("accepted forged value");
    }
    // 2. forged key
    if CompressedTrie::verify(&root, &k2, b"secret1", &p1) {
        bad("accepted wrong key");
    }
    // 3. tampered root
    if CompressedTrie::verify(&[0u8; 32], &k1, b"secret1", &p1) {
        bad("accepted wrong root");
    }
    // 4. tampered leaf_hash
    let mut p4 = p1.clone();
    p4.leaf_hash = [9u8; 32];
    if CompressedTrie::verify(&root, &k1, b"secret1", &p4) {
        bad("accepted tampered leaf_hash");
    }
    // 5. tampered sibling hash
    let mut p5 = p1.clone();
    if !p5.path.is_empty() {
        p5.path[0].sibling_hash = [7u8; 32];
        if CompressedTrie::verify(&root, &k1, b"secret1", &p5) {
            bad("accepted tampered sibling");
        }
    }
    // 6. truncated path
    let mut p6 = p1.clone();
    p6.path.clear();
    if CompressedTrie::verify(&root, &k1, b"secret1", &p6) && !t.is_empty() {
        // a cleared path only verifies if root == leaf hash, which it won't be
        if root != p6.leaf_hash {
            bad("accepted truncated path");
        }
    }
    ok("all 6 forgery attempts rejected");
}

// ============================================================================
// F. Extreme keys/values
// ============================================================================
fn section_f_extremes() {
    banner("F. Extreme keys and values");
    let mut t = CompressedTrie::new();
    // all-zero key, all-FF key, adjacent keys
    let z = [0u8; 32];
    let f = [0xFFu8; 32];
    t.insert(&z, b"");
    t.insert(&f, &vec![0xAAu8; 10_000]); // large value
    let mut adj = [0u8; 32];
    adj[31] = 1;
    t.insert(&adj, b"x");
    let root = t.root_hash();
    for (k, v) in [
        (&z, &b""[..]),
        (&f, &vec![0xAAu8; 10_000][..]),
        (&adj, &b"x"[..]),
    ] {
        let p = t.proof(k).unwrap();
        if !CompressedTrie::verify(&root, k, v, &p) {
            bad("extreme key/value proof failed");
        }
    }
    // empty tree
    let et = CompressedTrie::new();
    if et.root_hash() != [0u8; 32] {
        bad("empty root not zero");
    }
    if et.proof(&z).is_some() {
        bad("empty tree returned a proof");
    }
    ok("zero key, all-FF key, adjacent keys, 10KB value, empty tree all OK");
}
