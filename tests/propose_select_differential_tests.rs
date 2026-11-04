//! Differential: optimized `select_for_block_multi` == original, tx-for-tx.
//!
//! The optimization hoists the per-transaction packing costs (gas, wire
//! estimate, proof units — pure functions of the transaction) out of the
//! multi-pass fee-ordered walk. The visit order, the stateful accept
//! predicate call sequence, and the cap comparisons are untouched, so the
//! selection must be IDENTICAL. This file proves it against a naive
//! reference that reimplements the ORIGINAL logic (BTreeMap fee-order walk
//! per pass, costs recomputed inline per element per pass, hash-keyed taken
//! set) using only the public API.
//!
//! Randomized mempools, FIXED seeds: a deterministic xorshift64 generates
//! senders, nonce runs (with gaps, forcing multi-pass revisits), priority
//! bids, gas, amounts and payloads. Every (seed, cap-combo) pair must agree
//! tx-for-tx. Plus a propose-level pin: two fresh runtimes over the SAME
//! mempool state must propose byte-identical bodies.
//!
//! Reports only, no timing asserts: every test here is a correctness gate.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::mempool::Mempool;
use stellereum::runtime::{ValidatorRuntime, MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};
use stellereum::zkml_attestation::AttestationProof;

use ed25519_dalek::SigningKey;

type TxHash = [u8; 32];
const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

/// Deterministic xorshift64: fixed seeds, no wall clock, no OsRng.
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
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// ORIGINAL selection logic (pre-optimization): fee-order walk per pass over
/// a BTreeMap, costs recomputed inline per element per pass. The optimized
/// `select_multi` must agree with this tx-for-tx on every input.
fn reference_select<F>(
    txs: &[Transaction],
    max_txs: usize,
    max_gas: u64,
    passes: usize,
    mut accept: F,
) -> Vec<TxHash>
where
    F: FnMut(&Transaction) -> bool,
{
    // The pool refuses duplicate hashes; the reference dedups the same way
    // (first occurrence wins — duplicates are byte-identical anyway).
    let mut seen: HashSet<TxHash> = HashSet::new();
    let mut by_hash: HashMap<TxHash, &Transaction> = HashMap::new();
    let mut order: BTreeMap<(u64, u64, TxHash), TxHash> = BTreeMap::new();
    for t in txs {
        let h = t.compute_tx_hash();
        if seen.insert(h) {
            by_hash.insert(h, t);
            order.insert((t.priority_fee_per_gas, Mempool::effective_fee(t), h), h);
        }
    }
    let mut out: Vec<TxHash> = Vec::new();
    let mut taken: HashSet<TxHash> = HashSet::new();
    let mut gas = 0u64;
    let mut wire = 0usize;
    let mut proofs = 0usize;
    for _ in 0..passes.max(1) {
        let before = out.len();
        for ((_, _, h), _) in order.iter().rev() {
            if out.len() >= max_txs {
                break;
            }
            if taken.contains(h) {
                continue;
            }
            let tx = by_hash[h];
            if !accept(tx) {
                continue;
            }            let g = tx.gas_limit;
            if gas.saturating_add(g) > max_gas {
                continue;
            }
            let w = Mempool::estimate_tx_wire_bytes(tx);
            if wire.saturating_add(w) > Mempool::MAX_BLOCK_WIRE_BYTES {
                continue;
            }
            let p = Mempool::count_tx_proof_units(tx);
            if proofs.saturating_add(p) > Mempool::MAX_BLOCK_PROOF_UNITS {
                continue;
            }
            gas = gas.saturating_add(g);
            wire = wire.saturating_add(w);
            proofs = proofs.saturating_add(p);
            taken.insert(*h);
            out.push(*h);
        }
        if out.len() == before {
            break;
        }
    }
    out
}

/// Nonce-contiguity filter (the shape that forces multi-pass revisits):
/// accept exactly the next expected nonce per sender. Interior mutability
/// so it fits the `Fn` predicate bound of the pool selection API.
struct NonceFilter {
    expected: std::cell::RefCell<HashMap<[u8; 32], u64>>,
}
impl NonceFilter {
    fn new() -> Self {
        Self {
            expected: std::cell::RefCell::new(HashMap::new()),
        }
    }
    fn accept(&self, t: &Transaction) -> bool {
        let mut map = self.expected.borrow_mut();
        let e = map.entry(t.from).or_insert(0);
        if t.nonce == *e {
            *e += 1;
            true
        } else {
            false
        }
    }
}

/// Randomized pool with a fixed seed: nonce runs with gaps (multi-pass),
/// scattered priority bids (fee order far from pool order), scattered gas,
/// mixed payloads (empty + Transfer ops), plus one wire-cap-busting tx and
/// one proof-cap-busting tx. Returns the pool AND the inserted tx vec (the
/// reference selects from the vec; the pool is the optimized input).
fn randomized_pool(seed: u64) -> (Mempool, Vec<Transaction>) {
    let mut rng = Rng(0x9E3779B97F4A7C15u64.wrapping_add(seed.wrapping_mul(0xBF58476D1CE4E5B9)));
    let mut pool = Mempool::new(20_000, 5_000);
    let mut all: Vec<Transaction> = Vec::new();
    let n_senders = 30 + rng.below(21); // 30..=50
    for s in 0..n_senders {
        let sk = det_key(900_000 + seed * 1_000 + s);
        let depth = 1 + rng.below(6); // 1..=6 deep chains
        let mut nonce = rng.below(2); // some senders start ahead (gap at 0)
        for _ in 0..depth {
            if rng.below(100) < 15 {
                nonce += 1; // nonce gap: successors wait for a later pass
            }
            let bid = rng.below(2000);
            let gas = GAS_BASIC_TRANSFER + rng.below(5000);
            let amount = 1 + rng.below(100);
            let payload = if rng.below(100) < 70 {
                Vec::new()
            } else {
                let n_ops = 1 + rng.below(3) as usize;
                (0..n_ops)
                    .map(|k| OpCode::Transfer {
                        recipient: [(k as u8).wrapping_add(s as u8); 32],
                        amount: 1,
                    })
                    .collect()
            };
            let tx = Transaction::sign_with_payload_and_priority(
                &sk,
                [7u8; 32],
                amount,
                gas,
                nonce,
                1,
                1,
                payload,
                bid,
            );
            nonce += 1;
            pool.add_checked(tx.clone(), BAL).expect("funded admission");
            all.push(tx);
        }
    }
    // Duplicate insert attempts must not change the pool (admission refuses
    // them); the reference dedups identically. Re-push one known tx.
    if let Some(dup) = all.first().cloned() {
        assert!(pool.add_checked(dup, BAL).is_err(), "duplicate must be refused");
    }
    // Wire pressure: 20 fat txs (~1MB estimated wire each) with HIGH bids so
    // they select first and fill ~20MB of the 24MB wire budget. Later fat
    // txs must skip on wire while small ones still fit — both sides must
    // agree exactly which. (Single oversize txs never reach selection:
    // admission refuses them, so the wire cap only binds cumulatively.)
    for i in 0..20u64 {
        let sk = det_key(777_000 + seed * 100 + i);
        let fat_ops: Vec<OpCode> = (0..5_000)
            .map(|k| OpCode::Transfer {
                recipient: [(k % 251) as u8; 32],
                amount: 1,
            })
            .collect();
        let bid = 50_000 + i;
        let fat = Transaction::sign_with_payload_and_priority(
            &sk,
            [8u8; 32],
            1,
            GAS_BASIC_TRANSFER + bid + 1_000,
            0,
            1,
            1,
            fat_ops,
            bid,
        );
        pool.add_checked(fat.clone(), BAL).expect("fat admits");
        all.push(fat);
    }
    // Proof pressure: 40 txs carrying one attestation op each (64 units) =
    // 2560 cumulative units > 2048 cap, so the tail must skip on proofs.
    // Bids sit below the fat txs but above the small fry.
    for i in 0..40u64 {
        let sk = det_key(778_000 + seed * 100 + i);
        let bid = 30_000 + i;
        let ops = vec![OpCode::SysCallVerifyZkMlAttestation {
            model_id: [3u8; 32],
            proof: Box::new(AttestationProof {
                model_hash: [0u8; 32],
                spec_hash: [0u8; 32],
                public_inputs: Vec::new(),
                public_outputs: Vec::new(),
                proof_bytes: Vec::new(),
            }),
        }];
        let heavy = Transaction::sign_with_payload_and_priority(
            &sk,
            [8u8; 32],
            1,
            GAS_BASIC_TRANSFER + bid + 1_000,
            0,
            1,
            1,
            ops,
            bid,
        );
        assert_eq!(Mempool::count_tx_proof_units(&heavy), 64);
        pool.add_checked(heavy.clone(), BAL).expect("heavy admits");
        all.push(heavy);
    }
    (pool, all)
}

fn check_seed(seed: u64) {
    let (pool, all) = randomized_pool(seed);
    // (max_txs, max_gas, passes): full, count-capped, gas-capped, 1-pass.
    let combos: [(usize, u64, usize); 4] = [
        (MAX_BLOCK_TXS, MAX_BLOCK_GAS, 64),
        (50, u64::MAX, 64),
        (10_000, 2_000_000, 64),
        (10_000, u64::MAX, 1),
    ];
    for (max_txs, max_gas, passes) in combos {
        let f_opt = NonceFilter::new();
        let got: Vec<TxHash> = if passes == 1 {
            pool.select_for_block(max_txs, max_gas, |t| f_opt.accept(t))
                .iter()
                .map(|t| t.compute_tx_hash())
                .collect()
        } else {
            pool.select_for_block_multi(max_txs, max_gas, |t| f_opt.accept(t))
                .iter()
                .map(|t| t.compute_tx_hash())
                .collect()
        };
        let f_ref = NonceFilter::new();
        let want = reference_select(&all, max_txs, max_gas, passes, |t| f_ref.accept(t));
        assert_eq!(
            got, want,
            "seed={seed} caps=({max_txs},{max_gas}) passes={passes}: optimized must match original tx-for-tx (got {} txs, want {} txs)",
            got.len(),
            want.len(),
        );
    }
}

#[test]
fn differential_fixed_seeds_1_to_4() {
    for seed in 1..=4u64 {
        check_seed(seed);
    }
}

#[test]
fn differential_fixed_seeds_5_to_8() {
    for seed in 5..=8u64 {
        check_seed(seed);
    }
}

/// Same mempool state through two fresh runtimes: byte-identical bodies
/// (same tx order, same hash). The select optimization must not move a
/// single transaction.
#[tokio::test]
async fn propose_same_state_byte_identical_bodies() {
    let (pool, all) = randomized_pool(42);
    // Fund every sender on a shared engine.
    let engine = Arc::new(InMemoryStateEngine::new());
    let mut senders: HashSet<[u8; 32]> = HashSet::new();
    for t in &all {
        senders.insert(t.from);
    }
    for s in &senders {
        engine.update_account(AccountState::new(*s, BAL)).await;
    }
    let val_sk = det_key(42_000_001);
    let val_id = val_sk.verifying_key().to_bytes();
    engine.update_account(AccountState::new(val_id, BAL)).await;
    let pool = Arc::new(tokio::sync::RwLock::new(pool));
    let mut bodies = Vec::new();
    for _ in 0..2 {
        let vs = ValidatorSet::from_list(vec![(val_id, 1)]);
        let mut rt = ValidatorRuntime::new(
            SigningKey::from_bytes(&val_sk.to_bytes()),
            vs,
            engine.clone(),
            1,
        )
        .with_mempool(pool.clone());
        let b = rt.propose(TS).await.expect("propose must succeed");
        bodies.push(b.transactions.iter().map(|t| t.compute_tx_hash()).collect::<Vec<_>>());
    }
    assert!(!bodies[0].is_empty());
    assert_eq!(bodies[0], bodies[1], "same state must propose identical bodies");
}
