//! TEMPO probe: rank the costs inside TEMPO scope (`commitment.rs`, `cpat2.rs`).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench tempo_probe -- --nocapture
//! REPORTS, not gates: no timing asserts, only correctness asserts
//! (cached assembly == streaming digest; trie root stable; batch verify ok).
//! A slow machine must still be green.
//!
//! What is measured (all host wall ms via `Instant`, median-of-repeats):
//! * `tokens_domain` — `tokens_preimage` over 200 tokens x 8 balances.
//! * `contracts_domain_cold_vs_warm` — reference vs ABI-cached preimage over
//!   50 contracts (2 methods + 1 event + 16 storage slots each); prints
//!   cold ms, warm ms, byte length, ABI hits/misses.
//! * `staking_domain` — `staking_preimage` over 50 validators.
//! * `assemble_hot_vs_streaming` — full `commitment_digest` streaming vs
//!   all-hit cached assembly on the same snapshot (the per-block steady
//!   state cost); prints both ms, byte total, speedup, hit counters.
//! * `trie_insert_and_root` — `CompressedTrie` insert of 5k keys (total ms,
//!   per-op ns) plus isolated `root_hash()` ms (expected ~us: cached root).
//! * `batch_verify_20tx` — live-path `verify_signatures_batch` for a 20-tx
//!   block (the validation-tax probe, same as the harness `[vel][cpu]` row).

use std::collections::HashMap;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use stellereum::commitment::{
    AbiJsonCache, Domain, DomainCache, assemble_cached_digest, assemble_from_cache,
    contracts_preimage, contracts_preimage_cached, staking_preimage, tokens_preimage,
    CommitmentSnapshot,
};
use stellereum::contract::ContractRegistry;
use stellereum::contract_abi::{AbiEvent, AbiMethod, AbiParam, AbiType, ContractAbi};
use stellereum::cpat2::CompressedTrie;
use stellereum::sharding::Transaction;

fn medal_ms(ms: f64) -> String {
    format!("{ms:.3} ms")
}

/// Median of `repeats` runs of `f` (after `warmup` warmups), in ms.
fn median_ms(repeats: usize, warmup: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..warmup {
        f();
    }
    let mut v = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        v.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn det_key(seed: u8, i: u64) -> [u8; 32] {
    let mut k = [seed; 32];
    k[0..8].copy_from_slice(&i.to_be_bytes());
    k
}

fn make_tokens(n_tokens: usize, bals_per_token: usize) -> stellereum::token::TokenRegistry {
    let mut reg = stellereum::token::TokenRegistry::new();
    for i in 0..n_tokens {
        let id = det_key(0x70, i as u64);
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
            stellereum::token::TokenActor::new(id, md, 1_000_000).expect("valid test metadata");
        for j in 0..bals_per_token {
            actor.balances.insert(det_key(0xA1, j as u64), (i as u64) * 1000 + j as u64);
        }
        reg.tokens.insert(id, actor);
    }
    reg.next_nonce = n_tokens as u64;
    reg
}

fn make_abi(i: usize) -> ContractAbi {
    ContractAbi {
        methods: vec![
            AbiMethod::new(
                format!("method{i}"),
                vec![
                    AbiParam::new("x", AbiType::I64),
                    AbiParam::new("owner", AbiType::Address),
                ],
                AbiType::I64,
                true,
            ),
            AbiMethod::new(
                "view",
                vec![AbiParam::new("note", AbiType::String)],
                AbiType::U64,
                false,
            ),
        ],
        events: vec![AbiEvent::new(
            format!("ev{i}"),
            vec![AbiParam::new("t", AbiType::I64)],
            vec![AbiParam::new("blob", AbiType::Bytes)],
        )],
    }
}

fn make_contracts(n: usize) -> ContractRegistry {
    let mut reg = ContractRegistry::new();
    for i in 0..n {
        let addr = det_key(0xC0, i as u64);
        let mut storage = HashMap::new();
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
                abi: Some(make_abi(i)),
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
        l.validators.insert(
            det_key(0x5A, i as u64),
            stellereum::staking::ValidatorStake {
                self_bond: 10_000_000 + i as u64,
                delegated: i as u64 * 7,
                commission_bps: 100,
                pending_rewards: i as u64,
                total_slashed: 0,
                missed: 0,
                last_downtime_penalty: 0,
            },
        );
    }
    l
}

fn empty_snapshot_with(
    tokens: stellereum::token::TokenRegistry,
    contracts: ContractRegistry,
    staking: stellereum::staking::StakingLedger,
) -> CommitmentSnapshot {
    CommitmentSnapshot {
        tokens,
        staking,
        orderbooks: stellereum::orderbook::OrderbookManager::new(),
        order_escrow: HashMap::new(),
        pmm: stellereum::pmm::PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts,
        governance: stellereum::governance::Governance::new(),
        oracle: stellereum::oracle::OracleState::default(),
        session_keys: stellereum::zkml::SessionKeyRegistry::default(),
        bridge: stellereum::bridge::BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    }
}

#[test]
fn tempo_tokens_domain() {
    let reg = make_tokens(200, 8);
    let mut len = 0usize;
    let ms = median_ms(10, 2, || {
        let b = tokens_preimage(&reg);
        len = b.len();
    });
    println!("[tempo][tokens] 200tok/8bal preimage={len} bytes time={} (median-of-10)", medal_ms(ms));
    assert!(len > 0);
}

#[test]
fn tempo_contracts_domain_cold_vs_warm() {
    let reg = make_contracts(50);
    let reference = contracts_preimage(&reg);
    let mut cache = AbiJsonCache::default();
    let cold = contracts_preimage_cached(&reg, &mut cache);
    assert_eq!(cold, reference, "cold cache must equal reference");
    let cold_misses = cache.misses;
    let ms_cold = median_ms(5, 1, || {
        let mut c = AbiJsonCache::default();
        let _ = contracts_preimage_cached(&reg, &mut c);
    });
    cache.hits = 0;
    cache.misses = 0;
    let mut len = 0usize;
    let ms_warm = median_ms(10, 2, || {
        let b = contracts_preimage_cached(&reg, &mut cache);
        len = b.len();
    });
    println!(
        "[tempo][contracts] 50 contracts preimage={len} bytes cold={} (misses={cold_misses}) warm={} abi_hits={} abi_misses={}",
        medal_ms(ms_cold),
        medal_ms(ms_warm),
        cache.hits,
        cache.misses,
    );
    assert_eq!(len, reference.len());
}

#[test]
fn tempo_staking_domain() {
    let l = make_staking(50);
    let mut len = 0usize;
    let ms = median_ms(10, 2, || {
        let b = staking_preimage(&l);
        len = b.len();
    });
    println!("[tempo][staking] 50 vals preimage={len} bytes time={} (median-of-10)", medal_ms(ms));
    assert!(len > 0);
}

#[test]
fn tempo_assemble_hot_vs_streaming() {
    let s = empty_snapshot_with(make_tokens(200, 8), make_contracts(50), make_staking(50));
    let zkml = stellereum::zkml::ZkMlModelRegistry::default();
    let reference = stellereum::commitment::commitment_digest_with_zkml(&s, &zkml);
    let ms_stream = median_ms(10, 2, || {
        let _ = stellereum::commitment::commitment_digest_with_zkml(&s, &zkml);
    });
    // Fill every slot once (cold), then time the all-hit steady state.
    let mut cache = DomainCache::default();
    let gens = [7u64; 13];
    macro_rules! fill {
        ($domain:expr, $build:expr) => {{
            let b: Vec<u8> = $build;
            cache.put($domain, gens[$domain.index()], b.clone());
            b
        }};
    }
    let domains = [
        fill!(Domain::Tokens, tokens_preimage(&s.tokens)),
        fill!(Domain::Staking, staking_preimage(&s.staking)),
        fill!(
            Domain::Pmm,
            stellereum::commitment::pmm_preimage(&s.pmm, &s.pmm_usdt_token, &s.pmm_treasury)
        ),
        fill!(
            Domain::Contracts,
            contracts_preimage_cached(&s.contracts, &mut cache.abi)
        ),
        fill!(
            Domain::Escrow,
            stellereum::commitment::escrow_preimage(&s.order_escrow)
        ),
        fill!(
            Domain::Governance,
            stellereum::commitment::governance_preimage(&s.governance)
        ),
        fill!(
            Domain::Oracle,
            stellereum::commitment::oracle_preimage(&s.oracle)
        ),
        fill!(
            Domain::SessionKeys,
            stellereum::commitment::session_keys_preimage(&s.session_keys)
        ),
        fill!(
            Domain::Books,
            stellereum::commitment::books_preimage(&s.orderbooks)
        ),
        fill!(
            Domain::Bridge,
            stellereum::commitment::bridge_preimage(&s.bridge)
        ),
        fill!(
            Domain::CrossShard,
            stellereum::commitment::cross_shard_preimage(
                &s.cross_shard_consumed,
                &s.cross_shard_produced,
                &s.cross_shard_completed
            )
        ),
        fill!(
            Domain::Xpc,
            stellereum::commitment::xpc_preimage(&s.cross_shard_xpc)
        ),
        fill!(
            Domain::Zkml,
            stellereum::commitment::zkml_preimage(&zkml)
        ),
    ];
    let total: usize = domains.iter().map(|b| b.len()).sum();
    let refs: [&[u8]; 13] = [
        &domains[0],
        &domains[1],
        &domains[2],
        &domains[3],
        &domains[4],
        &domains[5],
        &domains[6],
        &domains[7],
        &domains[8],
        &domains[9],
        &domains[10],
        &domains[11],
        &domains[12],
    ];
    assert_eq!(assemble_cached_digest(refs), reference, "cached == streaming");
    cache.reset_counters();
    let ms_hot = median_ms(10, 2, || {
        let mut parts: [Vec<u8>; 13] = std::array::from_fn(|_| Vec::new());
        for d in Domain::ALL {
            parts[d.index()] = cache.get(d, gens[d.index()]).expect("all-hit");
        }
        let r: [&[u8]; 13] = [
            &parts[0], &parts[1], &parts[2], &parts[3], &parts[4], &parts[5],
            &parts[6], &parts[7], &parts[8], &parts[9], &parts[10], &parts[11],
            &parts[12],
        ];
        let _ = assemble_cached_digest(r);
    });
    println!(
        "[tempo][assemble] preimage_total={total} bytes streaming={} hot(all-hit,13 clones)={} speedup={:.2}x hits={} misses={}",
        medal_ms(ms_stream),
        medal_ms(ms_hot),
        if ms_hot > 0.0 { ms_stream / ms_hot } else { f64::INFINITY },
        cache.hits,
        cache.misses,
    );
    assert_eq!(cache.hits, 13 * 12, "12 timed runs x 13 domains all-hit");
    assert_eq!(cache.misses, 0);
}

#[test]
fn tempo_trie_insert_and_root() {
    let keys: Vec<[u8; 32]> = (0..5000u64).map(|i| det_key(0xBE, i)).collect();
    let ms_insert = median_ms(3, 1, || {
        let mut t = CompressedTrie::new();
        for k in &keys {
            t.insert(k, b"value-16-bytes!!");
        }
        assert_eq!(t.len(), 5000);
    });
    let mut t = CompressedTrie::new();
    for k in &keys {
        t.insert(k, b"value-16-bytes!!");
    }
    let mut root = [0u8; 32];
    let ms_root = median_ms(100, 10, || {
        root = t.root_hash();
    });
    println!(
        "[tempo][trie] 5k inserts total={} ({:.1} us/op) root_hash alone={} root={}",
        medal_ms(ms_insert),
        ms_insert * 1000.0 / 5000.0,
        medal_ms(ms_root),
        hex::encode(&root[..4]),
    );
    assert_ne!(root, [0u8; 32]);
}

#[test]
fn tempo_batch_verify_20tx() {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let to = [0x11u8; 32];
    let txs: Vec<Transaction> = (0..20u64)
        .map(|n| Transaction::sign(&sk, to, 1_000, 21_000, n, 0, 0))
        .collect();
    let mut ok = false;
    let ms = median_ms(20, 2, || {
        ok = Transaction::verify_signatures_batch(&txs);
    });
    println!("[tempo][validate] batch_verify_20tx={} ok={ok} ({:.3} ms/tx)", medal_ms(ms), ms / 20.0);
    assert!(ok);
}

/// Block-scale intake-verify probe (PERF_PROFILE §6.2): the proposal-intake
/// path batch-verifies every foreign block's signatures. Fixed fixtures of
/// N plain transfers from N DISTINCT senders (the live block shape, not the
/// single-sender 20tx probe above); reports SERIAL
/// (`verify_signatures_batch`, the intake path before the §6.2 change) vs
/// PARALLEL (`verify_signatures_batch_parallel`, the §6.2 live path) wall ms
/// and ns/op side by side. REPORTS, not gates: correctness asserts only
/// (both verdicts true) — a slow machine must still be green.
fn intake_verify_fixture(n: usize, key_base: u64) -> Vec<Transaction> {
    let to = [0x11u8; 32];
    (0..n as u64)
        .map(|i| {
            let mut seed = [0xA5u8; 32];
            seed[..8].copy_from_slice(&(key_base + i).to_le_bytes());
            let sk = SigningKey::from_bytes(&seed);
            Transaction::sign(&sk, to, 1_000, 21_000, 0, 0, 0)
        })
        .collect()
}

fn intake_verify_serial_vs_parallel_row(n: usize, key_base: u64) {
    let txs = intake_verify_fixture(n, key_base);
    assert!(Transaction::verify_signatures_batch(&txs));
    assert!(Transaction::verify_signatures_batch_parallel(&txs));
    let repeats = if n >= 1000 { 5 } else { 10 };
    let serial_ms = median_ms(repeats, 2, || {
        assert!(Transaction::verify_signatures_batch(&txs));
    });
    let parallel_ms = median_ms(repeats, 2, || {
        assert!(Transaction::verify_signatures_batch_parallel(&txs));
    });
    let serial_ns_per_op = serial_ms * 1e6 / n as f64;
    let parallel_ns_per_op = parallel_ms * 1e6 / n as f64;
    println!(
        "[tempo][validate][intake_verify] n={n} serial={} ({serial_ns_per_op:.0} ns/op) parallel={} ({parallel_ns_per_op:.0} ns/op) speedup={:.2}x",
        medal_ms(serial_ms),
        medal_ms(parallel_ms),
        serial_ms / parallel_ms.max(1e-9),
    );
}

#[test]
fn tempo_batch_verify_blockscale_428() {
    intake_verify_serial_vs_parallel_row(428, 500_000);
}

#[test]
fn tempo_batch_verify_blockscale_1000() {
    intake_verify_serial_vs_parallel_row(1_000, 600_000);
}

/// Zero-copy steady-state assembly vs the cloning hot path (fixed fixture).
///
/// Same snapshot as `tempo_assemble_hot_vs_streaming` (200 tokens x 8
/// balances, 50 contracts, 50 validators): reports streaming ms (full
/// re-walk/re-sort/re-hash), hot-clone ms (13 `Vec` clones + one hash — the
/// pre-change steady-state cost) and zero-copy ms (`assemble_from_cache`:
/// the same slot bytes hashed in place, no clones). REPORTS, not gates:
/// correctness asserts only (all three digests equal, all-hit counters) — a
/// slow machine must still be green. The never-slower gate is the manual
/// before/after comparison in the task report.
#[test]
fn tempo_assemble_zero_copy_vs_hot() {
    let s = empty_snapshot_with(make_tokens(200, 8), make_contracts(50), make_staking(50));
    let zkml = stellereum::zkml::ZkMlModelRegistry::default();
    let reference = stellereum::commitment::commitment_digest_with_zkml(&s, &zkml);
    let ms_stream = median_ms(10, 2, || {
        let _ = stellereum::commitment::commitment_digest_with_zkml(&s, &zkml);
    });
    // Fill every slot once (cold), then time the all-hit steady state.
    let mut cache = DomainCache::default();
    let gens = [7u64; 13];
    macro_rules! fill {
        ($domain:expr, $build:expr) => {{
            let b: Vec<u8> = $build;
            cache.put($domain, gens[$domain.index()], b.clone());
            b
        }};
    }
    let domains = [
        fill!(Domain::Tokens, tokens_preimage(&s.tokens)),
        fill!(Domain::Staking, staking_preimage(&s.staking)),
        fill!(
            Domain::Pmm,
            stellereum::commitment::pmm_preimage(&s.pmm, &s.pmm_usdt_token, &s.pmm_treasury)
        ),
        fill!(
            Domain::Contracts,
            contracts_preimage_cached(&s.contracts, &mut cache.abi)
        ),
        fill!(
            Domain::Escrow,
            stellereum::commitment::escrow_preimage(&s.order_escrow)
        ),
        fill!(
            Domain::Governance,
            stellereum::commitment::governance_preimage(&s.governance)
        ),
        fill!(
            Domain::Oracle,
            stellereum::commitment::oracle_preimage(&s.oracle)
        ),
        fill!(
            Domain::SessionKeys,
            stellereum::commitment::session_keys_preimage(&s.session_keys)
        ),
        fill!(
            Domain::Books,
            stellereum::commitment::books_preimage(&s.orderbooks)
        ),
        fill!(
            Domain::Bridge,
            stellereum::commitment::bridge_preimage(&s.bridge)
        ),
        fill!(
            Domain::CrossShard,
            stellereum::commitment::cross_shard_preimage(
                &s.cross_shard_consumed,
                &s.cross_shard_produced,
                &s.cross_shard_completed
            )
        ),
        fill!(
            Domain::Xpc,
            stellereum::commitment::xpc_preimage(&s.cross_shard_xpc)
        ),
        fill!(
            Domain::Zkml,
            stellereum::commitment::zkml_preimage(&zkml)
        ),
    ];
    let total: usize = domains.iter().map(|b| b.len()).sum();
    let refs: [&[u8]; 13] = [
        &domains[0],
        &domains[1],
        &domains[2],
        &domains[3],
        &domains[4],
        &domains[5],
        &domains[6],
        &domains[7],
        &domains[8],
        &domains[9],
        &domains[10],
        &domains[11],
        &domains[12],
    ];
    assert_eq!(assemble_cached_digest(refs), reference, "cached == streaming");
    assert_eq!(
        assemble_from_cache(&mut cache, &gens).expect("all-hit"),
        reference,
        "zero-copy == streaming"
    );
    cache.reset_counters();
    let ms_hot_clone = median_ms(10, 2, || {
        let mut parts: [Vec<u8>; 13] = std::array::from_fn(|_| Vec::new());
        for d in Domain::ALL {
            parts[d.index()] = cache.get(d, gens[d.index()]).expect("all-hit");
        }
        let r: [&[u8]; 13] = [
            &parts[0], &parts[1], &parts[2], &parts[3], &parts[4], &parts[5],
            &parts[6], &parts[7], &parts[8], &parts[9], &parts[10], &parts[11],
            &parts[12],
        ];
        let _ = assemble_cached_digest(r);
    });
    cache.reset_counters();
    let ms_zero_copy = median_ms(10, 2, || {
        let _ = assemble_from_cache(&mut cache, &gens).expect("all-hit");
    });
    println!(
        "[tempo][assemble][zero_copy] preimage_total={total} bytes streaming={} hot_clone={} zero_copy={} clone_speedup={:.2}x zero_copy_speedup={:.2}x hits={} misses={}",
        medal_ms(ms_stream),
        medal_ms(ms_hot_clone),
        medal_ms(ms_zero_copy),
        if ms_hot_clone > 0.0 { ms_stream / ms_hot_clone } else { f64::INFINITY },
        if ms_zero_copy > 0.0 { ms_stream / ms_zero_copy } else { f64::INFINITY },
        cache.hits,
        cache.misses,
    );
    assert_eq!(cache.misses, 0, "steady-state recommit must not miss");
}
