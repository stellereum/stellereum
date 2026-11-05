//! Differential parity: parallel apply == serial apply, byte-exact.
//!
//! The parallel block path (`apply_block_parallel_fees` with
//! `set_parallel_exec(true)`) must leave bit-identical end-state to the
//! sequential path over the SAME block: applied/failed counters,
//! `fees_collected`, per-transaction status and fee vectors, every touched
//! account's `(balance, nonce)`, and the state root.
//!
//! Fixtures are randomized with FIXED seeds (SplitMix64 below, no wall clock,
//! no OS RNG), so failures are reproducible: re-running with the same seed
//! rebuilds the same block. The mix covers plain transfers (disjoint,
//! conflicting, chained, self), payload transfers, sponsored (paymaster)
//! transfers, and every failure leg (bad nonce, replay, unfunded sender,
//! uncoverable fee, expired sponsor grant, out-of-gas payload). EXTENDS the
//! apply surface - no existing test is touched or weakened.

use std::collections::{HashMap, HashSet};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{PqSignatureEnvelope, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

const BAL: u64 = 10_000_000_000;
const TS: u64 = 1_700_001_000;
const CHAIN_ID: u64 = 5757;
const SENDERS: usize = 64;

/// SplitMix64: deterministic PRNG with a fixed seed. No OS entropy, so the
/// fixtures below are identical on every run, every box.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.next() % n
    }
}

fn det_seed(id: u64) -> [u8; 32] {
    let mut seed = [0x51u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..16].copy_from_slice(&0x9E37_79B9_7F4A_7C15u64.to_le_bytes());
    seed
}

/// FULL-PQ sender identity: Falcon-512 keypair derived deterministically
/// from the numeric id (same domain separation as the old ed25519 fixture),
/// registered globally for implicit-envelope verification.
fn det_addrs(id: u64) -> ([u8; 32], Vec<u8>) {
    let kp = FalconKeypair::generate_from_seed_bytes(&det_seed(id));
    let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (from, kp.public_key.clone())
}

fn addr_of(id: u64) -> [u8; 32] {
    det_addrs(id).0
}

/// Classical ed25519 fixture key, kept ONLY for the paymaster-v1 sponsored
/// mix: that composition is classical-only by design (plain legacy inner),
/// so sponsored fixtures stay classical and both paths refuse them
/// identically (parity by identical refusal). No PQ sponsor composition exists.
fn det_ed_key(i: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&det_seed(i))
}

/// FULL-PQ replacement for `Transaction::sign{,_with_payload}` in fixtures:
/// implicit Falcon-512 (registered globally; no surcharge), so fee/balance
/// assertions match the old classical fixtures exactly.
fn pq_tx(id: u64, to: [u8; 32], amount: u64, gas: u64, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    let (from, pk) = det_addrs(id);
    let kp = FalconKeypair::generate_from_seed_bytes(&det_seed(id));
    debug_assert_eq!(kp.public_key, pk);
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = kp.sign(&msg);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

fn new_engine(parallel: bool) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.set_parallel_exec(parallel);
    e
}

async fn fund(
    e: &InMemoryStateEngine,
    winners: &[(u64, u64)],
    sponsor: Option<(u64, u64)>,
) {
    for &(id, bal) in winners {
        e.update_account(AccountState::new(addr_of(id), bal)).await;
    }
    if let Some((id, bal)) = sponsor {
        e.update_account(AccountState::new(addr_of(id), bal)).await;
    }
}

/// Compare two engines after applying the same block: counters, fees,
/// per-tx vectors, every touched account's balance+nonce, and the root.
/// Byte-exact means ALL of these, not just the counters.
async fn assert_parity(
    seq: &InMemoryStateEngine,
    par: &InMemoryStateEngine,
    txs: &[Transaction],
    addrs: &HashSet<[u8; 32]>,
    case: &str,
) {
    let ts = TS;
    let r_seq = seq.apply_block_parallel_fees(txs, ts).await;
    let r_par = par.apply_block_parallel_fees(txs, ts).await;
    assert_eq!(r_seq.0, r_par.0, "{case}: applied must match");
    assert_eq!(r_seq.1, r_par.1, "{case}: failed must match");
    assert_eq!(r_seq.2, r_par.2, "{case}: fees_collected must match");
    assert_eq!(r_seq.3, r_par.3, "{case}: status must match");
    assert_eq!(r_seq.4, r_par.4, "{case}: tx fees must match");
    for a in addrs {
        let s = seq.get_account(a).await;
        let p = par.get_account(a).await;
        match (s, p) {
            (Some(s), Some(p)) => {
                assert_eq!(s.balance, p.balance, "{case}: balance of {}", hex_of(a));
                assert_eq!(s.nonce, p.nonce, "{case}: nonce of {}", hex_of(a));
            }
            (None, None) => {}
            _ => panic!("{case}: account existence diverged for {}", hex_of(a)),
        }
    }
    assert_eq!(
        seq.get_state_root().await,
        par.get_state_root().await,
        "{case}: state roots must be bit-identical"
    );
}

fn hex_of(a: &[u8; 32]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in a {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Randomized plain mix: disjoint, conflicting, chained and self transfers
/// plus bad-nonce / replay / unfunded / uncoverable-fee failures.
fn plain_mixed_txs(seed: u64, n: usize) -> (Vec<Transaction>, HashSet<[u8; 32]>) {
    let mut rng = SplitMix64(seed);
    let mut txs = Vec::with_capacity(n);
    let mut addrs = HashSet::new();
    let mut nonces = vec![0u64; SENDERS];
    for _ in 0..n {
        let s = rng.below(SENDERS as u64);
        let kind = rng.below(100);
        let to = if kind < 60 {
            let r = addr_of(1_000_000 + rng.below(1_000_000));
            addrs.insert(r);
            r
        } else if kind < 80 {
            let r = addr_of(rng.below(SENDERS as u64));
            addrs.insert(r);
            r
        } else {
            let r = addr_of(s);
            addrs.insert(r);
            r
        };
        addrs.insert(addr_of(s));
        let amount = 1 + rng.below(5_000);
        let fail = rng.below(100);
        let nonce = if fail < 6 {
            // nonce gap: skips ahead, must fail without moving state.
            nonces[s as usize] + 1 + rng.below(3)
        } else if fail < 10 && nonces[s as usize] > 0 {
            // replay: reuses an old nonce.
            nonces[s as usize] - 1
        } else {
            let n = nonces[s as usize];
            nonces[s as usize] += 1;
            n
        };
        let gas = if (10..13).contains(&fail) {
            // uncoverable fee: sender cannot cover amount + fee.
            BAL + 1_000_000
        } else {
            GAS_BASIC_TRANSFER
        };
        let from_id = if (13..16).contains(&fail) {
            // unfunded sender: never admitted, moves nothing.
            let id = 5_000_000 + rng.below(1_000_000);
            addrs.insert(addr_of(id));
            id
        } else {
            s
        };
        txs.push(pq_tx(from_id, to, amount, gas, nonce, Vec::new()));
    }
    (txs, addrs)
}

/// Payload mix: `Transfer`-syscall payloads (declared limit above consumed),
/// plain transfers, and out-of-gas payload failures.
fn payload_mixed_txs(seed: u64, n: usize) -> (Vec<Transaction>, HashSet<[u8; 32]>) {
    let mut rng = SplitMix64(seed);
    let mut txs = Vec::with_capacity(n);
    let mut addrs = HashSet::new();
    let mut nonces = vec![0u64; SENDERS];
    for _ in 0..n {
        let s = rng.below(SENDERS as u64);
        let to = addr_of(2_000_000 + rng.below(1_000_000));
        addrs.insert(addr_of(s));
        addrs.insert(to);
        let inner = addr_of(3_000_000 + rng.below(1_000_000));
        addrs.insert(inner);
        let nonce = nonces[s as usize];
        nonces[s as usize] += 1;
        let kind = rng.below(100);
        if kind < 50 {
            txs.push(pq_tx(
                s,
                to,
                1 + rng.below(1_000),
                500_000,
                nonce,
                vec![OpCode::Transfer {
                    recipient: inner,
                    amount: 1 + rng.below(500),
                }],
            ));
        } else if kind < 60 {
            // out-of-gas payload: admitted shape, fails at execution, pays
            // the floor via the failure-fee path on both engines.
            txs.push(pq_tx(
                s,
                to,
                1,
                100,
                nonce,
                vec![OpCode::Transfer {
                    recipient: inner,
                    amount: 1,
                }],
            ));
        } else {
            txs.push(pq_tx(
                s,
                to,
                1 + rng.below(1_000),
                GAS_BASIC_TRANSFER,
                nonce,
                Vec::new(),
            ));
        }
    }
    (txs, addrs)
}

/// Sponsored (paymaster) mix: user pays value, sponsor pays the fee; plus
/// expired-grant and under-capped-grant failures. The sponsor account is the
/// shared mutable leg the wave snapshot must cover on both paths.
fn sponsored_mixed_txs(
    seed: u64,
    n: usize,
    sponsor_id: u64,
) -> (Vec<Transaction>, HashSet<[u8; 32]>) {
    let mut rng = SplitMix64(seed);
    let mut txs = Vec::with_capacity(n);
    let mut addrs = HashSet::from([addr_of(sponsor_id)]);
    let mut nonces = vec![0u64; SENDERS];
    let sponsor_key = det_ed_key(sponsor_id);
    for _ in 0..n {
        let s = rng.below(SENDERS as u64);
        let to = addr_of(4_000_000 + rng.below(1_000_000));
        addrs.insert(addr_of(s));
        addrs.insert(to);
        let nonce = nonces[s as usize];
        nonces[s as usize] += 1;
        let kind = rng.below(100);
        let (max_fee, valid_until) = if kind < 10 {
            // expired grant: refused, moves nothing on either path.
            (10 * GAS_BASIC_TRANSFER, TS - 1)
        } else if kind < 15 {
            // under-capped grant: cannot cover the fee, refused.
            (1, TS + 1_000_000)
        } else {
            (10 * GAS_BASIC_TRANSFER, TS + 1_000_000)
        };
        txs.push(Transaction::sign_with_sponsor(
            &det_ed_key(s),
            &sponsor_key,
            to,
            1 + rng.below(1_000),
            GAS_BASIC_TRANSFER,
            nonce,
            1,
            1,
            Vec::new(),
            0,
            max_fee,
            valid_until,
            vec![to],
            CHAIN_ID,
        ));
    }
    (txs, addrs)
}

#[tokio::test]
async fn parallel_plain_mixed_parity_fixed_seed() {
    let (txs, addrs) = plain_mixed_txs(0xC0F_FEEu64, 256);
    let funded: Vec<(u64, u64)> = (0..SENDERS as u64).map(|i| (i, BAL)).collect();
    let seq = new_engine(false);
    let par = new_engine(true);
    fund(&seq, &funded, None).await;
    fund(&par, &funded, None).await;
    assert_parity(&seq, &par, &txs, &addrs, "plain_mixed").await;
}

#[tokio::test]
async fn parallel_payload_mixed_parity_fixed_seed() {
    let (txs, addrs) = payload_mixed_txs(0xBEEFu64, 128);
    let funded: Vec<(u64, u64)> = (0..SENDERS as u64).map(|i| (i, BAL)).collect();
    let seq = new_engine(false);
    let par = new_engine(true);
    fund(&seq, &funded, None).await;
    fund(&par, &funded, None).await;
    assert_parity(&seq, &par, &txs, &addrs, "payload_mixed").await;
}

#[tokio::test]
async fn parallel_sponsored_mixed_parity_fixed_seed() {
    let sponsor_id = 777_000u64;
    let (txs, addrs) = sponsored_mixed_txs(0x5EEDu64, 64, sponsor_id);
    let funded: Vec<(u64, u64)> = (0..SENDERS as u64).map(|i| (i, BAL)).collect();
    let seq = new_engine(false);
    let par = new_engine(true);
    fund(&seq, &funded, Some((sponsor_id, BAL))).await;
    fund(&par, &funded, Some((sponsor_id, BAL))).await;
    assert_parity(&seq, &par, &txs, &addrs, "sponsored_mixed").await;
}

#[tokio::test]
async fn parallel_large_disjoint_parity_fixed_seed() {
    // 1000 mutually-disjoint senders: one wave of 1000, the full concurrent
    // path (snapshot -> chunked rayon plan -> CAS merge) on the widest shape.
    let n = 1000usize;
    let base = 9_000_000u64;
    let mut rng = SplitMix64(0xD15_EEDu64);
    let mut txs = Vec::with_capacity(n);
    let mut addrs = HashSet::new();
    for i in 0..n as u64 {
        let to = addr_of(base + n as u64 + i);
        addrs.insert(addr_of(base + i));
        addrs.insert(to);
        txs.push(pq_tx(
            base + i,
            to,
            1 + rng.below(1_000),
            GAS_BASIC_TRANSFER,
            0,
            Vec::new(),
        ));
    }
    let funded: Vec<(u64, u64)> = (0..n as u64).map(|i| (base + i, BAL)).collect();
    let seq = new_engine(false);
    let par = new_engine(true);
    fund(&seq, &funded, None).await;
    fund(&par, &funded, None).await;
    assert_parity(&seq, &par, &txs, &addrs, "large_disjoint").await;
}

#[tokio::test]
async fn parallel_plan_chunk_sizes_agree_fixed_seed() {
    // The plan-chunk knob is perf-only: every chunk size must produce the
    // same end-state as serial over a randomized block. Sweeps the same
    // values the bench measures, in-process, without touching the global env
    // outside this test's own serial section.
    let (txs, addrs) = plain_mixed_txs(0xC4A11u64, 256);
    let funded: Vec<(u64, u64)> = (0..SENDERS as u64).map(|i| (i, BAL)).collect();
    let seq = new_engine(false);
    fund(&seq, &funded, None).await;
    let r_seq = seq.apply_block_parallel_fees(&txs, TS).await;
    let root_seq = seq.get_state_root().await;
    let mut bals = HashMap::new();
    for a in &addrs {
        bals.insert(*a, seq.get_account(a).await.map(|x| (x.balance, x.nonce)));
    }
    for &c in &[1usize, 8, 32, 128, 512, 2048] {
        std::env::set_var("STELL_PARALLEL_PLAN_CHUNK", c.to_string());
        let par = new_engine(true);
        fund(&par, &funded, None).await;
        let r_par = par.apply_block_parallel_fees(&txs, TS).await;
        assert_eq!((r_seq.0, r_seq.1, r_seq.2), (r_par.0, r_par.1, r_par.2));
        assert_eq!(r_seq.3, r_par.3);
        assert_eq!(r_seq.4, r_par.4);
        assert_eq!(root_seq, par.get_state_root().await, "chunk {c}");
        for a in &addrs {
            assert_eq!(
                bals[a],
                par.get_account(a).await.map(|x| (x.balance, x.nonce)),
                "chunk {c}"
            );
        }
    }
    std::env::remove_var("STELL_PARALLEL_PLAN_CHUNK");
}
