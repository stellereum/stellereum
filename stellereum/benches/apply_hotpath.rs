//! BLOCK-APPLY hot-path attribution bench (std-only; no criterion).
//!
//! Run in RELEASE:
//!     cargo test --release --bench apply_hotpath -- --nocapture --test-threads=1
//!
//! WHY IT EXISTS: `packing::apply_mixed_*` reports ONE number for the whole
//! live apply path. Before changing anything in that path, this bench
//! decomposes it into the phases the loop actually runs, so an optimisation
//! has a before/after number for the phase it targets:
//!
//! * `apply_phase` — the real `apply_block_parallel_fees` over N=1000 txs in
//!   three shapes: mixed (the packing fixture: 3/4 plain + 1/4 single
//!   `Transfer` payload), all-plain, all-payload. The difference between the
//!   shapes is the per-payload-transaction tax (VM run + domain guards).
//! * `sched_phase` — `DisjointScheduler::schedule` alone on the same block
//!   (one access-key `Vec` per transaction + the wave map).
//! * `verifyonce_phase` — `verified_signature_covers` over the same attested
//!   block (the per-tx sha256 + cache lock the apply path pays even when the
//!   signature itself is NOT re-verified).
//! * `trie_phase` — the same number of leaf inserts the apply path performs
//!   (one per touched account) directly on `CompressedTrie`.
//! * `root_phase` — `get_state_root()` twice on a populated engine: the
//!   stale (recompute + fold) read and the steady (no-op) read.
//!
//! REPORTS, not gates: no timing asserts, only correctness asserts — a slow
//! machine must still be green.
//!
//! MEASURED ATTRIBUTION (n = 1_000 mixed txs, release, median of 3-5, empty
//! chain, attested signatures — the `packing::apply_mixed_1000` shape):
//!
//! | phase                                   | before  | after   | delta |
//! |-----------------------------------------|---------|---------|-------|
//! | `apply_block_parallel_fees`, mixed       | 5.71 ms | 3.18 ms | −44%  |
//! |  … of which account-leaf trie inserts    | 2.31 ms | 0.23 ms | −90%  |
//! |  … of which verify-once cover checks     | 1.51 ms | 1.10 ms | −27%  |
//! |  … of which `DisjointScheduler::schedule`| 0.18 ms |    —    | not re-measured |
//! |  … of which the per-tx engine loop       | 1.71 ms |    —    | not re-measured |
//!
//! "before" for the two changed rows was taken on THIS machine with this
//! bench before the edits (`[hotpath][trie] changed_value` 2_372.7 ns and
//! `[hotpath][verifyonce]` 1_509.8 ns); "after" is the same rows afterwards
//! (233.8 ns and 1_097.0 ns). The `apply` row's "before" is the previously
//! documented 5.71 ms (other wave, other load) and is indicative only — the
//! load-proof comparison for it is the sum of the two rows above plus the
//! in-process A/Bs below.
//! The two biggest numbers lived OUTSIDE `state_engine/apply.rs`,
//! `state_engine/accounts.rs`, `parallel_exec.rs` and `commitment.rs`
//! (`cpat2.rs` trie path re-hashing and `verify_once.rs`'s two sha256 per
//! transaction), and both were changed (2026-11-18):
//!
//! * `cpat2.rs`: inserts mark the branches on the key's path dirty and the
//!   first root/proof read flushes them bottom-up, so a block of K inserts
//!   hashes each touched branch ONCE instead of once per key on its path;
//!   the descent mutates in place (no re-boxing per level) and each branch
//!   caches its leftmost key so the skipped-prefix compare is a field read.
//!   Row `hotpath_trie_1000` `changed_value`: 2_372.7 → 233.8 ns/insert; with
//!   the block's root read included, 381.3 ns/insert.
//! * `verify_once.rs`: the signature is no longer sha256'd twice (for PQ/EVM
//!   transactions `tx_hash` already commits those exact bytes), the tx hash
//!   reuses a per-thread hasher/scratch, and the signing-preimage hash runs
//!   OUTSIDE the cache lock. Row `hotpath_verifyonce_1000`: 1_509.8 → 1_097.0
//!   ns/tx.
//!
//! Both comparisons are re-derived in-process by `hotpath_trie_ab` /
//! `hotpath_verifyonce_ab`, which keep the pre-change implementation as a
//! reference, time the two alternately, and assert the observable is
//! unchanged (identical trie root after every block; identical accept/refuse
//! verdict per transaction). That is the only comparison this machine allows:
//! it runs other builds, so absolute numbers from two different processes are
//! not comparable (single-shot runs of the same binary vary by ~60%).
//!
//! Scheduler before/after lives in `hotpath_schedule_ab`: it keeps the
//! pre-change per-transaction-allocation implementation as an in-process
//! reference (asserting the wave partitions are IDENTICAL) and times both
//! alternately, so the comparison is not contaminated by other load on the
//! machine. Same-binary A/B runs: 318.8 → 230.0 µs (−27.9%) and 222.0 →
//! 150.7 µs (−32.1%). Nothing in `apply.rs` / `accounts.rs` /
//! `commitment.rs` was changed: every candidate there measured either below
//! this bench's noise floor or below 1% of the block (see the rows
//! `domain_fold`, `guard_tax`, `fold_parts`, `pq_envelope`).

use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;
use stellereum::parallel_exec::{extract_access_keys, DisjointScheduler, ResourceKey};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{verified_signature_covers, AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

const BAL: u64 = 1_000_000_000_000;
const TS: u64 = 9_000_000_007;
const RECIPIENT: [u8; 32] = [9u8; 32];
/// Distinct senders the fixture can draw on (max row size + slack).
const SENDERS: usize = 2_048;

fn pq_seed(i: u64) -> [u8; 32] {
    let mut seed = [0x71u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed
}

struct PqSender {
    kp: FalconKeypair,
    from: [u8; 32],
}

/// One deterministic Falcon-512 sender per index, registered in the
/// process-global implicit registry once (keygen is the expensive part).
fn senders() -> &'static [PqSender] {
    static SENDERS_ONCE: OnceLock<Vec<PqSender>> = OnceLock::new();
    SENDERS_ONCE.get_or_init(|| {
        (0..SENDERS as u64)
            .into_par_iter()
            .map(|i| {
                let kp = FalconKeypair::generate_from_seed_bytes(&pq_seed(i));
                let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
                let _ = Transaction::global_implicit_registry().register(
                    from,
                    PqScheme::Falcon512,
                    &kp.public_key,
                    &DEFAULT_SALT,
                );
                PqSender { kp, from }
            })
            .collect()
    })
}

/// Falcon-signed implicit-envelope transfer for sender `idx`, nonce 0, with an
/// optional syscall payload.
fn pq_tx(idx: usize, payload: Vec<OpCode>) -> Transaction {
    let s = &senders()[idx];
    let skeleton = Transaction {
        from: s.from,
        to: RECIPIENT,
        amount: 1,
        gas_limit: GAS_BASIC_TRANSFER,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: payload.clone(),
        priority_fee_per_gas: 0,
    };
    let msg = skeleton.signing_message();
    let sig = s.kp.sign_with_seed(&msg, &pq_seed(9_000_000 + idx as u64));
    Transaction::new_pq_implicit(
        s.from,
        PqScheme::Falcon512,
        sig,
        RECIPIENT,
        1,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        payload,
    )
}

fn medal_us(nanos: f64, ops: usize) -> String {
    let us = nanos / 1000.0;
    format!("{us:>9.1} us total ({:>7.1} ns/op)", nanos / ops as f64)
}

fn median_ns(repeats: usize, warmup: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..warmup {
        f();
    }
    let mut v = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        v.push(t.elapsed().as_nanos() as f64);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn rt_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds")
        .block_on(f)
}

fn block(n: usize) -> Vec<Transaction> {
    (0..n)
        .into_par_iter()
        .map(|i| pq_tx(i, Vec::new()))
        .collect()
}

fn mixed_block(n: usize) -> Vec<Transaction> {
    (0..n)
        .into_par_iter()
        .map(|i| {
            let payload = if i % 4 == 3 {
                vec![OpCode::Transfer {
                    recipient: RECIPIENT,
                    amount: 1,
                }]
            } else {
                Vec::new()
            };
            pq_tx(i, payload)
        })
        .collect()
}

fn payload_block(n: usize) -> Vec<Transaction> {
    (0..n)
        .into_par_iter()
        .map(|i| {
            pq_tx(
                i,
                vec![OpCode::Transfer {
                    recipient: RECIPIENT,
                    amount: 1,
                }],
            )
        })
        .collect()
}

fn fresh_engine(n: usize) -> InMemoryStateEngine {
    rt_block_on(async {
        let e = InMemoryStateEngine::new();
        for s in &senders()[..n] {
            e.update_account(AccountState::new(s.from, BAL)).await;
        }
        e.update_account(AccountState::new(RECIPIENT, 0)).await;
        e
    })
}

/// Applies one block to a FRESH funded engine (built outside the timer) and
/// returns the apply wall time in ns. The first call on fresh state also
/// attests every signature in the verify-once cache, so the timed runs see
/// the steady-state (attested) apply path, exactly like `packing`.
fn apply_once(txs: &[Transaction], n: usize) -> f64 {
    let e = fresh_engine(n);
    let t = Instant::now();
    let (applied, failed, _, _, _) = rt_block_on(e.apply_block_parallel_fees(txs, TS));
    let ns = t.elapsed().as_nanos() as f64;
    assert_eq!((applied, failed), (n, 0), "every tx must apply");
    ns
}

fn bench_apply_shape(label: &str, n: usize, txs: Vec<Transaction>) {
    // Correctness + attestation warmup first.
    let _ = apply_once(&txs, n);
    let mut v = Vec::new();
    for _ in 0..3 {
        v.push(apply_once(&txs, n));
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let ns = v[v.len() / 2];
    println!(
        "[hotpath][apply][{label}] n={n} wall={:.3} ms ({:.0} tx/s) per_tx={:.0} ns",
        ns / 1e6,
        n as f64 / (ns / 1e9).max(1e-9),
        ns / n as f64,
    );
}

#[test]
fn hotpath_apply_shapes_1000() {
    bench_apply_shape("mixed", 1_000, mixed_block(1_000));
    bench_apply_shape("plain", 1_000, block(1_000));
    bench_apply_shape("payload", 1_000, payload_block(1_000));
}

#[test]
fn hotpath_schedule_1000() {
    let plain = block(1_000);
    let mut waves = 0usize;
    let ns = median_ns(20, 2, || {
        waves = DisjointScheduler::schedule(&plain).len();
    });
    println!(
        "[hotpath][schedule] n=1000 waves={waves} time={}",
        medal_us(ns, plain.len())
    );
    assert!(waves > 0);
}

/// PRE-CHANGE scheduler, kept ONLY here as the A/B reference: it allocates a
/// fresh access-key `Vec` per transaction (the shape `DisjointScheduler::
/// schedule` had before the buffer-reuse change) and is otherwise the same
/// greedy wave assignment. The parity assert below pins that the reused
/// buffer returns the identical partition for every fixture shape.
fn schedule_with_per_tx_alloc(txs: &[Transaction]) -> Vec<Vec<usize>> {
    if txs.is_empty() {
        return Vec::new();
    }
    let mut waves: Vec<Vec<usize>> = Vec::new();
    let mut last_wave_for_key: HashMap<ResourceKey, usize> = HashMap::new();
    let mut last_global_wave: Option<usize> = None;
    let mut current_max_wave: usize = 0;
    for (i, tx) in txs.iter().enumerate() {
        let keys = extract_access_keys(tx);
        let has_global = keys.contains(&ResourceKey::Global);
        let target_wave = if has_global {
            if i == 0 {
                0
            } else {
                current_max_wave + 1
            }
        } else {
            let mut wave_idx = last_global_wave.map(|w| w + 1).unwrap_or(0);
            for key in &keys {
                if let Some(&w) = last_wave_for_key.get(key) {
                    wave_idx = wave_idx.max(w + 1);
                }
            }
            wave_idx
        };
        if has_global {
            last_global_wave = Some(target_wave);
        }
        for key in &keys {
            last_wave_for_key.insert(*key, target_wave);
        }
        current_max_wave = current_max_wave.max(target_wave);
        while waves.len() <= target_wave {
            waves.push(Vec::new());
        }
        waves[target_wave].push(i);
    }
    waves
}

#[test]
fn hotpath_schedule_ab() {
    // Three shapes: all-plain (the live block), mixed payloads, and a block
    // carrying a GLOBAL barrier op (contract deploy) in the middle.
    let plain = block(1_000);
    let mixed = mixed_block(1_000);
    let mut globals = block(1_000);
    globals[500] = pq_tx(
        500,
        vec![OpCode::SysCallDeployContract {
            code: vec![0x00, 0x61, 0x73, 0x6D],
        }],
    );
    for (label, txs) in [("plain", &plain), ("mixed", &mixed), ("global", &globals)] {
        let new = DisjointScheduler::schedule(txs);
        let old = schedule_with_per_tx_alloc(txs);
        assert_eq!(new, old, "{label}: partitioned waves must be identical");
    }
    let mut old_ns = Vec::new();
    let mut new_ns = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let a = schedule_with_per_tx_alloc(&plain);
        old_ns.push(t.elapsed().as_nanos() as f64);
        let t = Instant::now();
        let b = DisjointScheduler::schedule(&plain);
        new_ns.push(t.elapsed().as_nanos() as f64);
        assert_eq!(a, b);
    }
    old_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    new_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let old = old_ns[old_ns.len() / 2];
    let new = new_ns[new_ns.len() / 2];
    println!(
        "[hotpath][schedule_ab] n=1000 per_tx_alloc={} reused_buffer={} delta={:+.1}%",
        medal_us(old, plain.len()),
        medal_us(new, plain.len()),
        (new - old) / old * 100.0
    );
}

#[test]
fn hotpath_verifyonce_1000() {
    let txs = mixed_block(1_000);
    // Attest them the way a first apply does.
    let e = fresh_engine(1_000);
    let _ = rt_block_on(e.apply_block_parallel_fees(&txs, TS));
    let chain = stellereum::zkml::effective_chain_id();
    assert!(
        verified_signature_covers(&txs[0], chain),
        "fixture must be attested after one apply"
    );
    let mut hits = 0usize;
    let ns = median_ns(10, 2, || {
        hits = txs
            .iter()
            .filter(|tx| verified_signature_covers(tx, chain))
            .count();
    });
    println!(
        "[hotpath][verifyonce] n=1000 hits={hits} time={}",
        medal_us(ns, txs.len())
    );
    assert_eq!(hits, txs.len());
}

#[test]
fn hotpath_trie_1000() {
    let keys: Vec<[u8; 32]> = senders()[..1_000].iter().map(|s| s.from).collect();
    let leaf = {
        let a = AccountState::new([0u8; 32], BAL);
        a.to_trie_bytes()
    };
    // Cold trie: what a first block pays (insert into an empty trie).
    let ns_cold = median_ns(10, 2, || {
        let mut t = stellereum::cpat2::CompressedTrie::new();
        for k in &keys {
            t.insert(k, &leaf);
        }
        assert_eq!(t.len(), keys.len());
    });
    // Warm trie: the SHAPE the apply path actually has (the engine's
    // `update_account` already inserted every leaf, so a block re-inserts the
    // same keys and only the changed values move).
    let mut t = stellereum::cpat2::CompressedTrie::new();
    for k in &keys {
        t.insert(k, &leaf);
    }
    let ns_warm = median_ns(10, 2, || {
        for k in &keys {
            t.insert(k, &leaf);
        }
        assert_eq!(t.len(), keys.len());
    });
    // Changed value: every touched account's leaf bytes differ, so the insert
    // cannot short-circuit on an unchanged value. NOTE this row does NOT read
    // the root, so with deferred branch hashing it prices only the inserts;
    // the block cost is the `changed_value+root` row below.
    let mut changed = leaf.clone();
    changed[7] ^= 0x01;
    let ns_changed = median_ns(10, 2, || {
        for k in &keys {
            t.insert(k, &changed);
        }
        for k in &keys {
            t.insert(k, &leaf);
        }
        assert_eq!(t.len(), keys.len());
    });
    // The honest BLOCK shape: every touched leaf changes AND the block ends by
    // reading the state root. A trie that defers ancestor hashing to the root
    // read must be priced with that read included, not only for the inserts.
    let ns_block = median_ns(10, 2, || {
        for k in &keys {
            t.insert(k, &changed);
        }
        std::hint::black_box(t.root_hash());
        for k in &keys {
            t.insert(k, &leaf);
        }
        std::hint::black_box(t.root_hash());
        assert_eq!(t.len(), keys.len());
    });
    println!(
        "[hotpath][trie] inserts={} cold={} warm_reinsert={} changed_value={} changed_value+root={}",
        keys.len(),
        medal_us(ns_cold, keys.len()),
        medal_us(ns_warm, keys.len()),
        medal_us(ns_changed / 2.0, keys.len()),
        medal_us(ns_block / 2.0, keys.len())
    );
}

/// The payload tax in isolation: `execute_payload` (VM run + the domain
/// guards it takes) for the same fixture, with and without a `Transfer`
/// syscall payload. No commit, no trie — this is exactly the code
/// `apply_block_parallel_fees` runs before `commit_native` for a payload tx.
#[test]
fn hotpath_exec_payload_1000() {
    let payloads = payload_block(1_000);
    let plain = block(1_000);
    let e = fresh_engine(1_000);
    let mut ok = 0usize;
    let ns_payload = median_ns(5, 1, || {
        ok = 0;
        rt_block_on(async {
            for tx in &payloads {
                if e.execute_payload(tx, TS).await.is_ok() {
                    ok += 1;
                }
            }
        });
    });
    println!(
        "[hotpath][exec_payload] n=1000 payload time={}",
        medal_us(ns_payload, payloads.len())
    );
    let ns_plain = median_ns(5, 1, || {
        rt_block_on(async {
            for tx in &plain {
                let _ = e.execute_payload(tx, TS).await;
            }
        });
    });
    println!(
        "[hotpath][exec_payload] n=1000 empty  time={}",
        medal_us(ns_plain, plain.len())
    );
    assert_eq!(ok, payloads.len(), "every Transfer payload must execute");
}

#[test]
fn hotpath_root_read() {
    let txs = payload_block(256);
    let e = fresh_engine(256);
    let (applied, failed, _, _, _) = rt_block_on(e.apply_block_parallel_fees(&txs, TS));
    assert_eq!((applied, failed), (256, 0));
    let cold = median_ns(50, 5, || {
        // Every iteration bumps one domain, forcing the stale fold again.
        rt_block_on(async { e.bump_domain_generation(stellereum::commitment::Domain::Tokens) });
        let _ = rt_block_on(e.get_state_root());
    });
    let warm = median_ns(50, 5, || {
        let _ = rt_block_on(e.get_state_root());
    });
    println!(
        "[hotpath][root] stale_fold={} steady_read={} (each includes one tokio runtime build)",
        medal_us(cold, 1),
        medal_us(warm, 1)
    );
}

// ---- populated-domain fixtures (the tempo_probe shape) --------------------

fn make_tokens(n_tokens: usize, bals: usize) -> stellereum::token::TokenRegistry {
    let mut reg = stellereum::token::TokenRegistry::new();
    for i in 0..n_tokens {
        let mut id = [0x70u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let md = stellereum::token::TokenMetadata {
            name: format!("tok{i}"),
            symbol: format!("T{i}"),
            decimals: 8,
            total_supply: 1_000_000 + i as u64,
            max_supply: None,
            minter: [i as u8; 32],
            paused: false,
            description: String::new(),
        };
        let mut actor =
            stellereum::token::TokenActor::new(id, md, 1_000_000).expect("valid metadata");
        for j in 0..bals {
            let mut acct = [0xA1u8; 32];
            acct[..8].copy_from_slice(&(j as u64).to_be_bytes());
            actor.balances.insert(acct, (i as u64) * 1000 + j as u64);
        }
        reg.tokens.insert(id, actor);
    }
    reg.next_nonce = n_tokens as u64;
    reg
}

fn make_contracts(n: usize) -> stellereum::contract::ContractRegistry {
    let mut reg = stellereum::contract::ContractRegistry::new();
    for i in 0..n {
        let mut addr = [0xC0u8; 32];
        addr[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let mut storage = std::collections::HashMap::new();
        for k in 0..16i64 {
            storage.insert(k, (i as i64) * 1000 + k);
        }
        reg.contracts.insert(
            addr,
            stellereum::contract::Contract {
                address: addr,
                creator: [i as u8; 32],
                code_hash: [0xCC; 32],
                code: vec![0x00, 0x61, 0x73, 0x6D],
                storage,
                created_at: i as u64,
                paused: i % 2 == 0,
                balance: 0,
                abi: None,
                source_hash: None,
            },
        );
    }
    reg.next_nonce = n as u64;
    reg
}

fn make_staking(n: usize) -> stellereum::staking::StakingLedger {
    let mut l = stellereum::staking::StakingLedger::new();
    for i in 0..n {
        let mut id = [0x5Au8; 32];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        l.validators.insert(
            id,
            stellereum::staking::ValidatorStake {
                self_bond: 10_000_000 + i as u64,
                delegated: i as u64 * 7,
                commission_bps: 100,
                pending_rewards: i as u64,
                total_slashed: 0,
                missed: 0,
                last_downtime_penalty: 0,
                withdrawal_address: None,
            },
        );
    }
    l
}

/// Where the per-domain fold cost goes for a rebuilt domain: the clone of the
/// live registry, the preimage build, and the clone the cache stores. The
/// fold (`commit_consensus_domains_cached`) pays ALL THREE for every domain
/// whose generation moved.
#[test]
fn hotpath_fold_parts() {
    let e = InMemoryStateEngine::new();
    rt_block_on(async {
        *e.tokens_write().await = make_tokens(200, 8);
    });
    let clone_state = median_ns(20, 2, || {
        rt_block_on(async {
            let s = e.tokens_read().await.clone();
            std::hint::black_box(&s);
        })
    });
    let snapshot = rt_block_on(async { e.tokens_read().await.clone() });
    let preimage = stellereum::commitment::tokens_preimage(&snapshot);
    let build = median_ns(20, 2, || {
        let b = stellereum::commitment::tokens_preimage(&snapshot);
        std::hint::black_box(&b);
    });
    let clone_bytes = median_ns(20, 2, || {
        let b = preimage.clone();
        std::hint::black_box(&b);
    });
    println!(
        "[hotpath][fold_parts] tokens(200x8) clone_state={} build_preimage={} clone_preimage={} bytes={}",
        medal_us(clone_state, 1),
        medal_us(build, 1),
        medal_us(clone_bytes, 1),
        preimage.len()
    );
}

/// What ONE `is_pq_activation()` / `pq_envelope()` costs: both fully DECODE
/// the PQ1 envelope (allocating a copy of the Falcon signature bytes).
/// Measured here so the per-transaction envelope work in the block path is a
/// number, not a guess. NOTE the shape it also documents: `is_pq_activation()`
/// is `pq_envelope().map(!is_implicit && pubkey.is_some()).unwrap_or(false)`,
/// so for an ordinary IMPLICIT transaction it already does exactly ONE decode
/// and the guarded body that calls `pq_envelope()` again never runs — a
/// "collapse the duplicate decode" refactor therefore changes nothing on the
/// implicit path (confirmed by an alternating A/B of two bench binaries:
/// before min 5.213 ms vs after min 5.291 ms, i.e. inside noise) and was not
/// kept.
#[test]
fn hotpath_pq_envelope_decode_1000() {
    let txs = block(1_000);
    let mut decoded = 0usize;
    let ns_decode = median_ns(20, 2, || {
        decoded = txs.iter().filter(|tx| tx.pq_envelope().is_some()).count();
    });
    let mut activations = 0usize;
    let ns_pred = median_ns(20, 2, || {
        activations = txs.iter().filter(|tx| tx.is_pq_activation()).count();
    });
    println!(
        "[hotpath][pq_envelope] n=1000 decode={} is_pq_activation={} decoded={decoded} activations={activations}",
        medal_us(ns_decode, txs.len()),
        medal_us(ns_pred, txs.len())
    );
    assert_eq!(
        decoded,
        txs.len(),
        "every fixture tx carries a PQ1 envelope"
    );
    assert_eq!(activations, 0, "implicit envelopes are not activations");
}

/// The guard tax a payload transaction pays before its VM ever runs: the
/// tokens/books/contracts/staking/PMM/oracle WRITE guards (each of which also
/// bumps that domain's commitment generation) plus the governance / PMM-quote
/// reads `execute_payload_with_preverify` takes per transaction.
#[test]
fn hotpath_payload_guard_tax() {
    const N: usize = 1_000;
    let e = fresh_engine(1);
    let ns = median_ns(20, 2, || {
        rt_block_on(async {
            for _ in 0..N {
                let tokens = e.tokens_write().await;
                let books = e.orderbooks_write().await;
                let contracts = e.contracts_write().await;
                let staking = e.staking_write().await;
                let pmm = e.pmm_write().await;
                let gov1 = e.governance_read().await;
                let gov2 = e.governance_read().await;
                let gov3 = e.governance_read().await;
                let usdt = e.pmm_usdt_token_read().await;
                let treasury = e.pmm_treasury_read().await;
                let oracle = e.oracle_write().await;
                drop((
                    tokens, books, contracts, staking, pmm, gov1, gov2, gov3, usdt, treasury,
                    oracle,
                ));
            }
        })
    });
    println!(
        "[hotpath][guard_tax] per_payload_guard_set={}",
        medal_us(ns, N)
    );
}

/// How much domain re-work a payload-bearing block CAUSES: every payload
/// transaction takes the tokens/books/contracts/staking/PMM/oracle write
/// guards, and each guard acquisition bumps that domain's content generation,
/// so the block's end-of-apply commitment fold rebuilds all six even when the
/// payload (a plain `Transfer`) touched none of them. This row prices exactly
/// that waste against the same engine with ONE domain stale.
#[test]
fn hotpath_domain_fold_waste() {
    let e = InMemoryStateEngine::new();
    let tx = &payload_block(1)[0];
    let rt = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    };
    let runtime = rt();
    runtime.block_on(async {
        for s in &senders()[..1] {
            e.update_account(AccountState::new(s.from, BAL)).await;
        }
        e.update_account(AccountState::new(tx.to, 0)).await;
        *e.tokens_write().await = make_tokens(200, 8);
        *e.contracts_write().await = make_contracts(50);
        *e.staking_write().await = make_staking(50);
    });
    // One payload tx: the six guards bump six generations.
    runtime.block_on(async {
        e.execute_payload(tx, TS)
            .await
            .expect("transfer payload runs");
    });
    let timed = |runtime: &tokio::runtime::Runtime, e: &InMemoryStateEngine| {
        let t = Instant::now();
        let root = runtime.block_on(async { e.get_state_root().await });
        (t.elapsed().as_nanos() as f64, root)
    };
    let fold_six = timed(&runtime, &e).0;
    // Steady: nothing stale.
    let fold_steady = timed(&runtime, &e).0;
    // One domain stale (the minimum a block that really touched tokens pays).
    runtime.block_on(async { e.bump_domain_generation(stellereum::commitment::Domain::Tokens) });
    let fold_one = timed(&runtime, &e).0;
    println!(
        "[hotpath][domain_fold] fold_steady={} fold_one_domain={} fold_after_payload(6)={} waste={}",
        medal_us(fold_steady, 1),
        medal_us(fold_one, 1),
        medal_us(fold_six, 1),
        medal_us(fold_six - fold_one, 1)
    );
    assert!(fold_six > 0.0);
}

// ============================================================================
// In-binary A/B references (load-proof old-vs-new, same process)
// ============================================================================
//
// The machine this repo is benchmarked on runs other builds, so a single
// "before" number taken from an older binary is not comparable to an "after"
// number taken later. Following `hotpath_schedule_ab`, the pre-change
// implementation is kept here as an in-process REFERENCE, the two are timed
// alternately, and the reference is asserted to agree with the live code on
// the observable that matters (trie root / verify-once verdict).

/// The PRE-CHANGE `cpat2` insert path, verbatim: owned `Option<Node>`
/// recursion that re-boxes every node on the key's path, and the deep
/// leftmost-leaf descent to recover a branch's skipped prefix.
mod legacy_trie {
    use stellereum::cpat2::{branch_hash, leaf_hash, Key, H};

    pub enum Node {
        Leaf(Key, H),
        Branch {
            skip: u16,
            bit: u8,
            left: Box<Node>,
            right: Box<Node>,
            hash: H,
        },
    }

    fn bit(k: &Key, d: usize) -> u8 {
        if d >= 256 {
            return 0;
        }
        (k[d / 8] >> (7 - (d % 8))) & 1
    }

    fn common(a: &Key, b: &Key, from: usize) -> usize {
        let mut d = from;
        while d < 256 && bit(a, d) == bit(b, d) {
            d += 1;
        }
        d
    }

    fn node_hash(node: &Node) -> H {
        match node {
            Node::Leaf(_, h) | Node::Branch { hash: h, .. } => *h,
        }
    }

    fn mk_branch(skip: u16, bit: u8, left: Node, right: Node) -> Node {
        let l = node_hash(&left);
        let r = node_hash(&right);
        let h = branch_hash(skip, bit, &l, &r);
        Node::Branch {
            skip,
            bit,
            left: Box::new(left),
            right: Box::new(right),
            hash: h,
        }
    }

    fn insert(node: Option<Node>, key: Key, lh: H, depth: usize) -> Node {
        match node {
            None => Node::Leaf(key, lh),
            Some(Node::Leaf(ek, eh)) => {
                if ek == key {
                    return Node::Leaf(key, lh);
                }
                let cp = common(&ek, &key, depth);
                let skip = (cp - depth) as u16;
                let bit0 = bit(&ek, cp);
                let (left, right) = if bit0 == 0 {
                    (Node::Leaf(ek, eh), Node::Leaf(key, lh))
                } else {
                    (Node::Leaf(key, lh), Node::Leaf(ek, eh))
                };
                mk_branch(skip, 0, left, right)
            }
            Some(Node::Branch {
                skip,
                bit: bbit,
                left,
                right,
                hash,
            }) => {
                let bp = depth + skip as usize;
                if bp >= 256 {
                    return Node::Branch {
                        skip,
                        bit: bbit,
                        left,
                        right,
                        hash,
                    };
                }
                let cp_skip =
                    common_prefix_len(&key, left.as_ref(), right.as_ref(), depth, skip as usize);
                if cp_skip < skip as usize {
                    let new_skip = cp_skip as u16;
                    let diverge_at = depth + cp_skip;
                    let new_bit = bit(&key, diverge_at);
                    let existing_skip = (skip as usize - cp_skip - 1) as u16;
                    let existing = mk_branch(existing_skip, bbit, *left, *right);
                    let incoming = Node::Leaf(key, lh);
                    let (l, r) = if new_bit == 0 {
                        (incoming, existing)
                    } else {
                        (existing, incoming)
                    };
                    return mk_branch(new_skip, 0, l, r);
                }
                if bit(&key, bp) == 0 {
                    let nl = insert(Some(*left), key, lh, bp + 1);
                    mk_branch(skip, bbit, nl, *right)
                } else {
                    let nr = insert(Some(*right), key, lh, bp + 1);
                    mk_branch(skip, bbit, *left, nr)
                }
            }
        }
    }

    fn common_prefix_len(key: &Key, left: &Node, right: &Node, depth: usize, skip: usize) -> usize {
        let rep = representative_key(left).or_else(|| representative_key(right));
        match rep {
            Some(rk) => {
                let mut d = 0;
                while d < skip && bit(key, depth + d) == bit(rk, depth + d) {
                    d += 1;
                }
                d
            }
            None => skip,
        }
    }

    fn representative_key(n: &Node) -> Option<&Key> {
        match n {
            Node::Leaf(k, _) => Some(k),
            Node::Branch { left, .. } => representative_key(left),
        }
    }

    /// Mirrors the pre-change `CompressedTrie` field-for-field, INCLUDING the
    /// `entries` map bookkeeping, so the A/B compares the whole insert path.
    pub struct LegacyTrie {
        root: Option<Node>,
        pub entries: std::collections::HashMap<Key, Vec<u8>>,
    }

    impl LegacyTrie {
        pub fn new() -> Self {
            Self {
                root: None,
                entries: std::collections::HashMap::new(),
            }
        }
        pub fn insert(&mut self, key: &Key, value: &[u8]) {
            if let Some(existing) = self.entries.get_mut(key) {
                if existing.as_slice() == value && self.root.is_some() {
                    return;
                }
                existing.clear();
                existing.extend_from_slice(value);
            } else {
                self.entries.insert(*key, value.to_vec());
            }
            let lh = leaf_hash(key, value);
            let r = self.root.take();
            self.root = Some(insert(r, *key, lh, 0));
        }
        pub fn root_hash(&self) -> H {
            match &self.root {
                None => [0u8; 32],
                Some(n) => node_hash(n),
            }
        }
    }
}

/// TRIE A/B: identical root, alternating timings.
///
/// Corpus = the apply shape: 1000 distinct keys, every leaf's value differs
/// from the previous block's (so the insert cannot short-circuit), plus a
/// fresh-build row. Roots are asserted equal after EVERY phase — the pinned
/// consensus root in `src/cpat2.rs` pins it against the pre-change
/// implementation independently.
#[test]
fn hotpath_trie_ab() {
    let keys: Vec<[u8; 32]> = senders()[..1_000].iter().map(|s| s.from).collect();
    let base = AccountState::new([0u8; 32], BAL).to_trie_bytes();
    let changed = {
        let mut c = base.clone();
        c[7] ^= 0x01;
        c
    };

    let new_cold = {
        let mut t = stellereum::cpat2::CompressedTrie::new();
        for k in &keys {
            t.insert(k, &base);
        }
        t.root_hash()
    };
    let old_cold = {
        let mut t = legacy_trie::LegacyTrie::new();
        for k in &keys {
            t.insert(k, &base);
        }
        t.root_hash()
    };
    assert_eq!(new_cold, old_cold, "cold-build root must be identical");

    // Changed-value update on a populated trie: the honest per-block shape.
    let mut fresh = stellereum::cpat2::CompressedTrie::new();
    let mut legacy = legacy_trie::LegacyTrie::new();
    for k in &keys {
        fresh.insert(k, &base);
        legacy.insert(k, &base);
    }
    for k in &keys {
        fresh.insert(k, &changed);
        legacy.insert(k, &changed);
    }
    assert_eq!(
        fresh.root_hash(),
        legacy.root_hash(),
        "changed-value root must be identical"
    );

    // One measured unit = ONE block: all 1000 touched leaves change, then the
    // block's state root is read. Values alternate so every insert really
    // changes a leaf (the `warm_reinsert` no-op path is measured separately).
    let mut new_ns = Vec::new();
    let mut old_ns = Vec::new();
    for i in 0..18 {
        let value = if i % 2 == 0 { &changed } else { &base };
        let t = Instant::now();
        for k in &keys {
            fresh.insert(k, value);
        }
        let fresh_root = fresh.root_hash();
        new_ns.push(t.elapsed().as_nanos() as f64);
        let t = Instant::now();
        for k in &keys {
            legacy.insert(k, value);
        }
        let legacy_root = legacy.root_hash();
        old_ns.push(t.elapsed().as_nanos() as f64);
        assert_eq!(fresh_root, legacy_root, "block root must be identical");
    }
    new_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    old_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let new = new_ns[new_ns.len() / 2];
    let old = old_ns[old_ns.len() / 2];
    println!(
        "[hotpath][trie_ab] per_block=1000_inserts+root old={} new={} delta={:+.1}%",
        medal_us(old, 1_000),
        medal_us(new, 1_000),
        (new - old) / old * 100.0
    );
}

/// The PRE-CHANGE verify-once cover check, verbatim: `compute_tx_hash` (fresh
/// payload scratch per call), a standalone sha256 over the FULL signature,
/// the signing preimage hashed while holding the cache lock, and
/// `chain_id()` evaluated inside the comparison.
///
/// Its own map is keyed exactly like the live one and fed from the same
/// attestation records, so the A/B asserts the verdict for every transaction
/// is unchanged, not just that it is faster.
mod legacy_verify_once {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use stellereum::sharding::Transaction;

    #[derive(Clone)]
    pub struct Rec {
        pub from: [u8; 32],
        pub tx_hash: [u8; 32],
        pub sig_len: usize,
        pub msg_hash: [u8; 32],
        pub bound_chain: Option<u64>,
        pub verified_for_chain: u64,
        pub pure_pq_enforced: bool,
    }

    fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
        let mut h: Sha256 = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// (tx hash, signature sha256, attesting chain) -> attestation.
    pub type Key = ([u8; 32], [u8; 32], u64);

    pub struct Cache {
        map: Mutex<HashMap<Key, Rec>>,
    }

    impl Cache {
        pub fn new() -> Self {
            Self {
                map: Mutex::new(HashMap::new()),
            }
        }

        pub fn record(&self, tx: &Transaction, verified_for_chain: u64) {
            let rec = Rec {
                from: tx.from,
                tx_hash: tx.compute_tx_hash(),
                sig_len: tx.signature.len(),
                msg_hash: sha256_bytes(&tx.signing_message()),
                bound_chain: tx.chain_id(),
                verified_for_chain,
                pure_pq_enforced: stellereum::post_quantum::is_pure_pq_enforced(),
            };
            self.map.lock().unwrap().insert(
                (rec.tx_hash, sha256_bytes(&tx.signature), verified_for_chain),
                rec,
            );
        }

        pub fn covers(&self, tx: &Transaction, expected_chain: u64) -> bool {
            // Same PQ-implicit registry guard the live path takes first.
            if tx.is_pq_implicit()
                && Transaction::global_implicit_registry()
                    .lookup(&tx.from)
                    .is_none()
            {
                return false;
            }
            let tx_hash = tx.compute_tx_hash();
            let sig_hash = sha256_bytes(&tx.signature);
            let guard = self.map.lock().unwrap();
            let Some(rec) = guard.get(&(tx_hash, sig_hash, expected_chain)) else {
                return false;
            };
            rec.from == tx.from
                && rec.tx_hash == tx_hash
                && rec.sig_len == tx.signature.len()
                && rec.msg_hash == sha256_bytes(&tx.signing_message())
                && rec.bound_chain == tx.chain_id()
                && rec.verified_for_chain == expected_chain
                && rec.pure_pq_enforced == stellereum::post_quantum::is_pure_pq_enforced()
        }
    }
}

/// VERIFY-ONCE A/B: same accept/refuse verdict per transaction, alternating
/// timings. The reference cache is populated from the LIVE attestations
/// (after one real apply), so both sides answer over the same records.
#[test]
fn hotpath_verifyonce_ab() {
    let txs = mixed_block(1_000);
    let e = fresh_engine(1_000);
    let _ = rt_block_on(e.apply_block_parallel_fees(&txs, TS));
    let chain = stellereum::zkml::effective_chain_id();

    let reference = legacy_verify_once::Cache::new();
    for tx in &txs {
        reference.record(tx, chain);
    }
    // Verdict parity on this block...
    for tx in &txs {
        assert_eq!(
            verified_signature_covers(tx, chain),
            reference.covers(tx, chain),
            "cover verdict must be unchanged"
        );
    }
    // ...and on a chain the attestation does NOT cover (both must refuse).
    let foreign = chain.wrapping_add(1);
    for tx in txs.iter().take(64) {
        assert!(!verified_signature_covers(tx, foreign));
        assert!(!reference.covers(tx, foreign));
    }

    let mut new_ns = Vec::new();
    let mut old_ns = Vec::new();
    for _ in 0..9 {
        let t = Instant::now();
        let live = txs
            .iter()
            .filter(|tx| verified_signature_covers(tx, chain))
            .count();
        new_ns.push(t.elapsed().as_nanos() as f64);
        let t = Instant::now();
        let old = txs.iter().filter(|tx| reference.covers(tx, chain)).count();
        old_ns.push(t.elapsed().as_nanos() as f64);
        assert_eq!(live, old);
    }
    new_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    old_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let new = new_ns[new_ns.len() / 2];
    let old = old_ns[old_ns.len() / 2];
    println!(
        "[hotpath][verifyonce_ab] n=1000 old={} new={} delta={:+.1}%",
        medal_us(old, txs.len()),
        medal_us(new, txs.len()),
        (new - old) / old * 100.0
    );
}

/// Where the verify-once cover check's time goes, so a change can be
/// attributed: the transaction hash, the signature sha256, the signing
/// preimage sha256, and the chain-domain resolution (`chain_id()` decodes the
/// PQ envelope).
#[test]
fn hotpath_verifyonce_parts() {
    let txs = mixed_block(1_000);
    let hashes = median_ns(10, 2, || {
        let mut n = 0usize;
        for tx in &txs {
            n += tx.compute_tx_hash()[0] as usize;
        }
        assert!(n > 0);
    });
    // Same hash, reusing one hasher + payload scratch instead of allocating a
    // fresh payload `Vec` per transaction (what `verify_once` does now).
    let mut batch = Transaction::batch_hasher();
    let mut batched = Vec::new();
    for _ in 0..12 {
        let t = Instant::now();
        let mut n = 0usize;
        for tx in &txs {
            n += batch.hash_one(tx)[0] as usize;
        }
        batched.push(t.elapsed().as_nanos() as f64);
        assert!(n > 0);
    }
    batched.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let batched_ns = batched[batched.len() / 2];
    let sigs = median_ns(10, 2, || {
        use sha2::Digest;
        let mut n = 0usize;
        for tx in &txs {
            let d = sha2::Sha256::digest(&tx.signature);
            n += d[0] as usize;
        }
        assert!(n > 0);
    });
    let msgs = median_ns(10, 2, || {
        use sha2::Digest;
        let mut n = 0usize;
        for tx in &txs {
            let d = sha2::Sha256::digest(tx.signing_message());
            n += d[0] as usize;
        }
        assert!(n > 0);
    });
    let chains = median_ns(10, 2, || {
        let mut n = 0usize;
        for tx in &txs {
            n += tx.chain_id().is_some() as usize + tx.is_pq_implicit() as usize;
        }
        assert!(n > 0);
    });
    println!(
        "[hotpath][verifyonce_parts] n=1000 tx_hash={} tx_hash_batched={} sig_sha256={} msg_sha256={} chain_id={}",
        medal_us(hashes, txs.len()),
        medal_us(batched_ns, txs.len()),
        medal_us(sigs, txs.len()),
        medal_us(msgs, txs.len()),
        medal_us(chains, txs.len())
    );
}

/// Hashing floor for one leaf insert: the leaf hash plus the ~10 branch
/// hashes a 1000-leaf Patricia path needs (measured separately, so the
/// attribution is a number rather than a guess).
#[test]
fn hotpath_trie_parts() {
    let keys: Vec<[u8; 32]> = senders()[..1_000].iter().map(|s| s.from).collect();
    let leaf = AccountState::new([0u8; 32], BAL).to_trie_bytes();
    let mut t = stellereum::cpat2::CompressedTrie::new();
    for k in &keys {
        t.insert(k, &leaf);
    }
    let depth: usize = keys
        .iter()
        .map(|k| t.proof(k).map(|p| p.path.len()).unwrap_or(0))
        .sum::<usize>()
        / keys.len();
    let leaf_ns = median_ns(10, 2, || {
        let mut n = 0usize;
        for k in &keys {
            n += stellereum::cpat2::leaf_hash(k, &leaf)[0] as usize;
        }
        assert!(n > 0);
    });
    let mut h = [7u8; 32];
    let branch_ns = median_ns(10, 2, || {
        for i in 0..10_000usize {
            h = stellereum::cpat2::branch_hash((i % 256) as u16, (i & 1) as u8, &h, &h);
        }
        assert_ne!(h, [0u8; 32]);
    });
    println!(
        "[hotpath][trie_parts] depth={depth} leaf_hash_1000={} branch_hash_10000={} per_insert_hash_floor={:.0} ns",
        medal_us(leaf_ns, keys.len()),
        medal_us(branch_ns, 10_000),
        (leaf_ns + branch_ns * depth as f64 / 10_000.0) / keys.len() as f64
    );
}
