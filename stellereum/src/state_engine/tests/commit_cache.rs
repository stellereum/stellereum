use super::*;

// -----------------------------------------------------------------------
// TAIL-1: per-domain commitment caching + engine wiring.
//
// The cached commit path must produce byte-identical roots to the
// reference streaming digest on every mutation sequence (no wire-format,
// quorum or state-transition change); a single-domain mutation must
// invalidate exactly one cache slot; and a deep copy (fork) must start
// with an empty cache so one fork's bytes can never be served to the
// other. The perf test prints measured ms for the report.
// -----------------------------------------------------------------------

/// The reference streaming digest of an engine's current state (the
/// pre-TAIL-1 code path, kept as the differential oracle).
async fn reference_digest(engine: &InMemoryStateEngine) -> [u8; 32] {
    let snap = engine.commitment_snapshot().await;
    let zkml = engine.zkml_models.read().await.clone();
    crate::commitment::commitment_digest_with_zkml(&snap, &zkml)
}

/// The digest the engine actually folded into the trie (the live path).
async fn committed_trie_digest(engine: &InMemoryStateEngine) -> [u8; 32] {
    engine.get_state_root().await;
    let trie = engine.state_trie.read().await;
    let raw = trie
        .get(&crate::commitment::commitment_key())
        .expect("commitment digest key present after root read");
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn cache_stats(engine: &InMemoryStateEngine) -> (u64, u64) {
    let c = engine.domain_cache.lock().unwrap();
    (c.hits, c.misses)
}

fn reset_cache_stats(engine: &InMemoryStateEngine) {
    engine.domain_cache.lock().unwrap().reset_counters();
}

/// Seed a populated state through the write accessors (so every domain
/// generation moves exactly as on the live path).
async fn seed_populated_engine(
    engine: &InMemoryStateEngine,
    n_tokens: usize,
    bals_per_token: usize,
    n_contracts: usize,
    n_validators: usize,
) {
    use crate::contract_abi::{AbiEvent, AbiMethod, AbiParam, AbiType, ContractAbi};
    {
        let mut reg = engine.tokens_write().await;
        for i in 0..n_tokens {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            id[8] = 0x70;
            let md = crate::token::TokenMetadata {
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
                crate::token::TokenActor::new(id, md, 1_000_000).expect("valid test metadata");
            for j in 0..bals_per_token {
                let mut acct = [0u8; 32];
                acct[0..8].copy_from_slice(&(j as u64).to_be_bytes());
                acct[8] = 0xA1;
                acct[9] = i as u8;
                actor.balances.insert(acct, (i as u64) * 1000 + j as u64);
            }
            reg.tokens.insert(id, actor);
        }
        reg.next_nonce = n_tokens as u64;
    }
    {
        let mut ledger = engine.staking_write().await;
        for i in 0..n_validators {
            let mut v = [0u8; 32];
            v[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            v[8] = 0x5A;
            ledger.validators.insert(
                v,
                crate::staking::ValidatorStake {
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
    }
    {
        let mut reg = engine.contracts_write().await;
        for i in 0..n_contracts {
            let mut addr = [0u8; 32];
            addr[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            addr[8] = 0xC0;
            let abi = ContractAbi {
                methods: vec![AbiMethod::new(
                    format!("method{i}"),
                    vec![
                        AbiParam::new("x", AbiType::I64),
                        AbiParam::new("owner", AbiType::Address),
                    ],
                    AbiType::I64,
                    true,
                )],
                events: vec![AbiEvent::new(
                    format!("ev{i}"),
                    vec![AbiParam::new("t", AbiType::I64)],
                    vec![],
                )],
            };
            let mut storage = std::collections::HashMap::new();
            for k in 0..16i64 {
                storage.insert(k, (i as i64) * 1000 + k);
            }
            reg.contracts.insert(
                addr,
                crate::contract::Contract {
                    address: addr,
                    creator: [i as u8; 32],
                    code_hash: [0xCC; 32],
                    code: vec![0x00, 0x61, 0x73, 0x6D],
                    storage,
                    created_at: i as u64,
                    paused: false,
                    balance: 0,
                    abi: Some(abi),
                    source_hash: None,
                },
            );
        }
        reg.next_nonce = n_contracts as u64;
    }
    engine.oracle_write().await.publishers.insert([0x0Au8; 32]);
    engine.oracle_write().await.feeds.insert(
        "STELL/USD".to_string(),
        crate::oracle::CommittedFeed {
            price_micro_usd: 250_000,
            timestamp: 1,
            publisher: [0x0Au8; 32],
        },
    );
    engine.session_keys_write().await.entries.insert(
        [0x5Eu8; 32],
        crate::zkml::SessionKeyRecord {
            master: [0x6Eu8; 32],
            valid_until: 9999,
            max_gas_spend: 1_000_000,
            gas_spent: 3,
            scope: 1,
            max_value_per_tx: 500,
            revoked: false,
        },
    );
    engine
        .bridge_write()
        .await
        .processed_source_txs
        .insert([0xB1u8; 32]);
    {
        let mut mgr = engine.orderbooks_write().await;
        let mut book = crate::orderbook::OrderbookActor::new(7, 64);
        book.next_order_id = 2;
        book.asks.insert(
            100,
            vec![crate::orderbook::Order {
                order_id: 1,
                trader: [0x07u8; 32],
                side: crate::orderbook::OrderSide::Sell,
                order_type: crate::orderbook::OrderType::Limit,
                price: 100,
                amount: 5,
                filled: 0,
                timestamp: 1,
            }],
        );
        mgr.books.insert(7, book);
    }
    engine.order_escrow_write().await.insert(
        (7, 1),
        EscrowRecord {
            trader: [0x07u8; 32],
            locked_base_stell: 5,
            locked_quote_wusdt: 0,
            locked_quote_native: 0,
        },
    );
}

/// The live cached commit equals the reference streaming digest, after
/// every single-domain mutation in sequence.
#[tokio::test]
async fn engine_cached_commit_matches_streaming_reference() {
    let engine = InMemoryStateEngine::new();
    seed_populated_engine(&engine, 64, 4, 32, 16).await;
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await,
        "cold commit must equal the streaming reference"
    );
    // One mutation per domain; the root must track the reference exactly.
    engine.staking_write().await.total_burned += 1;
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.tokens_write().await.next_nonce += 1;
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine
        .contracts_write()
        .await
        .contracts
        .values_mut()
        .next()
        .unwrap()
        .storage
        .insert(12345, 1);
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.governance_write().await.next_id += 100;
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.oracle_write().await.breaker_tripped = true;
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.session_keys_write().await.entries.clear();
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.orderbooks_write().await.books.remove(&7);
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.order_escrow_write().await.clear();
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.bridge_write().await.escrow_balance = 7;
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    // Cross-shard + xpc + zkml touch.
    engine
        .cross_shard_completed
        .write()
        .await
        .insert([0xC5u8; 32]);
    engine.bump_domain_generation(crate::commitment::Domain::CrossShard);
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.zkml_models_write().await.models.insert(
        [0x2Au8; 32],
        crate::zkml::ZkMlModelRecord {
            model_hash: [0x2Bu8; 32],
            model: crate::zkml::QuantizedLinearModel::new(vec![]),
            spec: None,
        },
    );
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await
    );
    engine.bump_domain_generation(crate::commitment::Domain::Pmm);
    assert_eq!(
        committed_trie_digest(&engine).await,
        reference_digest(&engine).await,
        "a bare domain bump with no content change must not move the root"
    );
}

/// A single-domain mutation invalidates exactly one cache slot; a
/// no-change root read is served by the global skip without touching the
/// cache at all.
#[tokio::test]
async fn engine_cache_invalidates_only_the_mutated_domain() {
    let engine = InMemoryStateEngine::new();
    seed_populated_engine(&engine, 32, 2, 16, 8).await;
    let _ = committed_trie_digest(&engine).await;
    reset_cache_stats(&engine);
    engine.staking_write().await.total_burned += 1;
    let _ = committed_trie_digest(&engine).await;
    let (hits, misses) = cache_stats(&engine);
    assert_eq!(
        misses, 1,
        "exactly the staking domain rebuilds, got {misses}"
    );
    assert_eq!(hits, 12, "every other domain must be a hit, got {hits}");
    // Steady state: the global generation skip serves the read; the
    // per-domain cache is not even consulted.
    reset_cache_stats(&engine);
    let r1 = engine.get_state_root().await;
    let r2 = engine.get_state_root().await;
    assert_eq!(r1, r2);
    assert_eq!(
        cache_stats(&engine),
        (0, 0),
        "no-change reads must not consult the domain cache"
    );
}

/// Deep copies start with an empty cache and diverge safely: the fork's
/// post-mutation root equals ITS OWN streaming reference (it never serves
/// the parent's bytes), and the parent's root is untouched.
#[tokio::test]
async fn engine_fork_clone_starts_empty_and_diverges_safely() {
    let parent = InMemoryStateEngine::new();
    seed_populated_engine(&parent, 32, 2, 16, 8).await;
    let parent_root = committed_trie_digest(&parent).await;
    assert_eq!(parent_root, reference_digest(&parent).await);
    assert!(
        parent.domain_cache.lock().unwrap().slots_filled() > 0,
        "parent commit must populate its cache"
    );

    let fork = parent.clone_for_simulation().await;
    assert_eq!(
        fork.domain_cache.lock().unwrap().slots_filled(),
        0,
        "a deep copy must start with an EMPTY preimage cache"
    );
    assert_eq!(
        cache_stats(&fork),
        (0, 0),
        "no process-wide cache may leak hits into the fork"
    );
    // The fork agrees with the parent before diverging.
    assert_eq!(
        committed_trie_digest(&fork).await,
        parent_root,
        "identical state must commit identically"
    );
    // Diverge the fork: its root must equal ITS OWN reference, and the
    // parent must be unaffected.
    fork.staking_write().await.total_burned += 999;
    let fork_root = committed_trie_digest(&fork).await;
    assert_eq!(
        fork_root,
        reference_digest(&fork).await,
        "fork root must equal the fork's own streaming reference"
    );
    assert_ne!(fork_root, parent_root, "the fork must actually diverge");
    assert_eq!(
        committed_trie_digest(&parent).await,
        parent_root,
        "fork mutations must not leak into the parent"
    );
    assert_eq!(
        reference_digest(&parent).await,
        parent_root,
        "parent reference unchanged"
    );
}

/// Perf: cold commit vs single-domain-touch commit vs no-change read on a
/// populated engine. Prints measured ms for the report; the hard
/// assertion is root equality with the streaming reference.
#[tokio::test]
async fn perf_engine_commit_cold_vs_single_domain_touch() {
    let engine = InMemoryStateEngine::new();
    seed_populated_engine(&engine, 1500, 8, 300, 200).await;

    let t0 = std::time::Instant::now();
    let cold = committed_trie_digest(&engine).await;
    let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(cold, reference_digest(&engine).await);

    engine.staking_write().await.total_burned += 1;
    let t0 = std::time::Instant::now();
    let touched = committed_trie_digest(&engine).await;
    let touched_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(touched, reference_digest(&engine).await);

    let t0 = std::time::Instant::now();
    let _ = engine.get_state_root().await;
    let noop_ms = t0.elapsed().as_secs_f64() * 1000.0;

    eprintln!(
        "[perf] engine commit populated (1500 tokens/300 contracts/200 vals): cold={cold_ms:.2}ms single-domain-touch={touched_ms:.2}ms no-change={noop_ms:.3}ms speedup={:.1}x",
        if touched_ms > 0.0 { cold_ms / touched_ms } else { f64::INFINITY },
    );
}
