//! Differential: zero-copy batch assembly equals the streaming digest.
//!
//! REPORTS, not gates: correctness asserts only (cached == streaming over
//! randomized mutation sequences at fixed seeds; stale generation misses
//! instead of mis-digesting). A slow machine must still be green.
//!
//! This mirrors the `commitment.rs` unit differential through the PUBLIC API
//! so it runs even when unrelated `#[cfg(test)]` modules elsewhere in the
//! crate do not compile: integration targets link the non-test lib only.

use std::collections::HashMap;

use stellereum::commitment::{
    Domain, DomainCache, assemble_cached_digest, assemble_from_cache, books_preimage,
    bridge_preimage, contracts_preimage_cached, cross_shard_preimage, escrow_preimage,
    governance_preimage, oracle_preimage, pmm_preimage, session_keys_preimage, staking_preimage,
    tokens_preimage, xpc_preimage, zkml_preimage, CommitmentSnapshot,
};

fn populated_snapshot(
    n_tokens: usize,
    bals_per_token: usize,
    n_contracts: usize,
    n_validators: usize,
) -> CommitmentSnapshot {
    use stellereum::contract_abi::{AbiEvent, AbiMethod, AbiParam, AbiType, ContractAbi};
    let mut s = CommitmentSnapshot {
        tokens: stellereum::token::TokenRegistry::new(),
        staking: stellereum::staking::StakingLedger::new(),
        orderbooks: stellereum::orderbook::OrderbookManager::new(),
        order_escrow: HashMap::new(),
        pmm: stellereum::pmm::PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: stellereum::contract::ContractRegistry::new(),
        governance: stellereum::governance::Governance::new(),
        oracle: stellereum::oracle::OracleState::default(),
        session_keys: stellereum::zkml::SessionKeyRegistry::default(),
        bridge: stellereum::bridge::BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    };
    for i in 0..n_tokens {
        let mut id = [0u8; 32];
        id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        id[8] = 0x70;
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
            let mut acct = [0u8; 32];
            acct[0..8].copy_from_slice(&(j as u64).to_be_bytes());
            acct[8] = 0xA1;
            acct[9] = i as u8;
            actor.balances.insert(acct, (i as u64) * 1000 + j as u64);
        }
        s.tokens.tokens.insert(id, actor);
    }
    s.tokens.next_nonce = n_tokens as u64;
    for i in 0..n_validators {
        let mut v = [0u8; 32];
        v[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        v[8] = 0x5A;
        let bond = if i == 0 {
            20_000u64 * 1_000_000_000
        } else {
            10_000_000 + i as u64
        };
        s.staking.validators.insert(
            v,
            stellereum::staking::ValidatorStake {
                self_bond: bond,
                delegated: i as u64 * 7,
                commission_bps: 100,
                pending_rewards: i as u64,
                total_slashed: 0,
                missed: 0,
                last_downtime_penalty: 0,
            },
        );
    }
    for i in 0..n_contracts {
        let mut addr = [0u8; 32];
        addr[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        addr[8] = 0xC0;
        let abi = ContractAbi {
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
        };
        let mut storage = HashMap::new();
        for k in 0..16i64 {
            storage.insert(k, (i as i64) * 1000 + k);
        }
        s.contracts.contracts.insert(
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
                abi: Some(abi),
                source_hash: None,
            },
        );
    }
    s.contracts.next_nonce = n_contracts as u64;
    let mut gov_ledger = s.staking.clone();
    let mut proposer = [0u8; 32];
    proposer[8] = 0x5A;
    s.governance
        .propose(
            &mut gov_ledger,
            proposer,
            "raise-the-roof".to_string(),
            stellereum::governance::GovAction::Signal("test".to_string()),
            1,
        )
        .expect("test proposal proposes");
    s.oracle.publishers.insert([0x0Au8; 32]);
    s.oracle.feeds.insert(
        "STELL/USD".to_string(),
        stellereum::oracle::CommittedFeed {
            price_micro_usd: 250_000,
            timestamp: 1,
            publisher: [0x0Au8; 32],
        },
    );
    s.session_keys.entries.insert(
        [0x5Eu8; 32],
        stellereum::zkml::SessionKeyRecord {
            master: [0x6Eu8; 32],
            valid_until: 9999,
            max_gas_spend: 1_000_000,
            gas_spent: 3,
            scope: 1,
            max_value_per_tx: 500,
            revoked: false,
        },
    );
    s.bridge.processed_source_txs.insert([0xB1u8; 32]);
    s.bridge.escrow_balance = 42;
    let mut book = stellereum::orderbook::OrderbookActor::new(7, 64);
    book.next_order_id = 2;
    book.asks.insert(
        100,
        vec![stellereum::orderbook::Order {
            order_id: 1,
            trader: [0x07u8; 32],
            side: stellereum::orderbook::OrderSide::Sell,
            order_type: stellereum::orderbook::OrderType::Limit,
            price: 100,
            amount: 5,
            filled: 0,
            timestamp: 1,
        }],
    );
    s.orderbooks.books.insert(7, book);
    s.order_escrow.insert(
        (7, 1),
        stellereum::state_engine::EscrowRecord {
            trader: [0x07u8; 32],
            locked_base_stell: 5,
            locked_quote_wusdt: 0,
            locked_quote_native: 0,
        },
    );
    s.cross_shard_consumed.push(stellereum::sharding::CrossShardKey {
        source_shard: 1,
        finalized_in_block: [0x11u8; 32],
        msg_id: [0x22u8; 32],
    });
    let xpc_tx = stellereum::sharding::Transaction::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]),
        [0x43u8; 32],
        1,
        1,
        0,
        0,
        0,
    );
    s.cross_shard_xpc
        .push(stellereum::xshard2pc::XpcRecord::prepared(xpc_tx, 0, 1, 3));
    s
}

fn streaming_of(s: &CommitmentSnapshot, zkml: &stellereum::zkml::ZkMlModelRegistry) -> [u8; 32] {
    stellereum::commitment::commitment_digest_with_zkml(s, zkml)
}

/// Clone-path assembly (test mirror of the engine's cached commit path).
fn assemble_clone(
    s: &CommitmentSnapshot,
    zkml: &stellereum::zkml::ZkMlModelRegistry,
    gens: &[u64; 13],
    cache: &mut DomainCache,
) -> [u8; 32] {
    macro_rules! fill {
        ($domain:expr, $build:expr) => {{
            let gen = gens[$domain.index()];
            match cache.get($domain, gen) {
                Some(b) => b,
                None => {
                    let b: Vec<u8> = $build;
                    cache.put($domain, gen, b.clone());
                    b
                }
            }
        }};
    }
    let domains = [
        fill!(Domain::Tokens, tokens_preimage(&s.tokens)),
        fill!(Domain::Staking, staking_preimage(&s.staking)),
        fill!(
            Domain::Pmm,
            pmm_preimage(&s.pmm, &s.pmm_usdt_token, &s.pmm_treasury)
        ),
        fill!(
            Domain::Contracts,
            contracts_preimage_cached(&s.contracts, &mut cache.abi)
        ),
        fill!(Domain::Escrow, escrow_preimage(&s.order_escrow)),
        fill!(Domain::Governance, governance_preimage(&s.governance)),
        fill!(Domain::Oracle, oracle_preimage(&s.oracle)),
        fill!(
            Domain::SessionKeys,
            session_keys_preimage(&s.session_keys)
        ),
        fill!(Domain::Books, books_preimage(&s.orderbooks)),
        fill!(Domain::Bridge, bridge_preimage(&s.bridge)),
        fill!(
            Domain::CrossShard,
            cross_shard_preimage(
                &s.cross_shard_consumed,
                &s.cross_shard_produced,
                &s.cross_shard_completed
            )
        ),
        fill!(Domain::Xpc, xpc_preimage(&s.cross_shard_xpc)),
        fill!(Domain::Zkml, zkml_preimage(zkml)),
    ];
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
    assemble_cached_digest(refs)
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) ^ self.0
    }
}

#[test]
fn zero_copy_and_clone_paths_match_streaming_over_randomized_sequences() {
    for seed in [0x1234_5678_9ABC_DEF1u64, 0x9E37_79B9_7F4A_7C15u64] {
        let mut s = populated_snapshot(32, 4, 16, 8);
        let val0 = *s.staking.validators.keys().next().unwrap();
        for i in 0..6u8 {
            let a = [i.wrapping_add(0x10); 32];
            let b = [i.wrapping_add(0x20); 32];
            s.staking.delegations.insert((val0, a), i as u64);
            s.staking.delegator_rewards.insert((val0, a), i as u64);
            s.staking.withdrawable.insert((val0, a), i as u64);
            s.staking.locked_governance.insert(a, i as u64);
            s.staking.equivocation_dedup.insert(a);
            s.staking.pq_equivocation_dedup.insert(b);
            s.staking.validator_pq_keys.insert(
                a,
                (
                    stellereum::post_quantum::PqScheme::Falcon512,
                    vec![i; 32],
                ),
            );
            s.staking.vesting_schedules.insert(
                b,
                stellereum::tokenomics::TeamVestingSchedule::new(i as u64),
            );
            s.staking.reward_accumulators.insert(
                a,
                stellereum::staking::ValidatorRewardState {
                    reward_per_token: i as u128,
                    ..Default::default()
                },
            );
            s.staking
                .delegator_reward_checkpoints
                .insert((val0, a), i as u128);
            s.staking.jail.insert(
                a,
                stellereum::staking::JailRecord {
                    jailed_at_height: i as u64,
                    release_height: i as u64 + 100,
                },
            );
            s.staking.commission_schedule.insert(
                a,
                stellereum::staking::CommissionSchedule {
                    last_effective_height: Some(i as u64),
                    pending: None,
                },
            );
            s.staking.redelegation_lock.insert((val0, a), i as u64);
            let tok = *s.tokens.tokens.keys().next().unwrap();
            if let Some(actor) = s.tokens.tokens.get_mut(&tok) {
                actor.allowances.insert((a, b), i as u64);
            }
        }
        let zkml = stellereum::zkml::ZkMlModelRegistry::default();
        let mut cache = DomainCache::default();
        let mut gens = [3u64; 13];
        let reference = streaming_of(&s, &zkml);
        let cloned = assemble_clone(&s, &zkml, &gens, &mut cache);
        assert_eq!(cloned, reference, "seed {seed:#x}: cold clone-path diverged");
        let zero = assemble_from_cache(&mut cache, &gens)
            .expect("seed: all-hit zero-copy assembly must succeed");
        assert_eq!(zero, reference, "seed {seed:#x}: zero-copy diverged");
        let mut stale = gens;
        stale[Domain::Tokens.index()] += 1;
        assert_eq!(
            assemble_from_cache(&mut cache, &stale),
            None,
            "seed {seed:#x}: stale generation must miss, not mis-digest"
        );
        let mut rng = Lcg(seed);
        for step in 0..200u64 {
            match rng.next() % 10 {
                0 => {
                    let id = *s.tokens.tokens.keys().next().unwrap();
                    let actor = s.tokens.tokens.get_mut(&id).unwrap();
                    let acct = [(step as u8).wrapping_add(1); 32];
                    *actor.balances.entry(acct).or_insert(0) += 1;
                    gens[Domain::Tokens.index()] += 1;
                }
                1 => {
                    s.staking.total_burned += 1;
                    gens[Domain::Staking.index()] += 1;
                }
                2 => {
                    let a = [(step as u8).wrapping_add(0x40); 32];
                    s.staking.delegations.insert((val0, a), step);
                    s.staking.delegator_rewards.insert((val0, a), step);
                    s.staking.withdrawable.insert((val0, a), step);
                    gens[Domain::Staking.index()] += 1;
                }
                3 => {
                    let a = [(step as u8).wrapping_add(0x50); 32];
                    s.staking.locked_governance.insert(a, step);
                    s.staking.equivocation_dedup.insert(a);
                    s.staking.jail.insert(
                        a,
                        stellereum::staking::JailRecord {
                            jailed_at_height: step,
                            release_height: step + 100,
                        },
                    );
                    s.staking.redelegation_lock.insert((val0, a), step);
                    gens[Domain::Staking.index()] += 1;
                }
                4 => {
                    let a = [(step as u8).wrapping_add(0x60); 32];
                    s.staking.reward_accumulators.insert(
                        a,
                        stellereum::staking::ValidatorRewardState {
                            reward_per_token: step as u128,
                            ..Default::default()
                        },
                    );
                    s.staking
                        .delegator_reward_checkpoints
                        .insert((val0, a), step as u128);
                    gens[Domain::Staking.index()] += 1;
                }
                5 => {
                    let addr = *s.contracts.contracts.keys().next().unwrap();
                    let c = s.contracts.contracts.get_mut(&addr).unwrap();
                    *c.storage.entry(step as i64).or_insert(0) += 1;
                    gens[Domain::Contracts.index()] += 1;
                }
                6 => {
                    let mut ledger = s.staking.clone();
                    let voter = [(step as u8).wrapping_add(0xF0); 32];
                    let val = s.staking.validators.keys().next().copied().unwrap();
                    ledger
                        .delegations
                        .insert((val, voter), 20_000u64 * 1_000_000_000);
                    let _ = s.governance.vote(
                        &mut ledger,
                        voter,
                        0,
                        stellereum::governance::VoteChoice::Yes,
                        step + 2,
                    );
                    gens[Domain::Governance.index()] += 1;
                }
                7 => {
                    s.oracle.breaker_tripped = step % 2 == 0;
                    gens[Domain::Oracle.index()] += 1;
                }
                8 => {
                    s.order_escrow.insert(
                        (7, step),
                        stellereum::state_engine::EscrowRecord {
                            trader: [step as u8; 32],
                            locked_base_stell: step,
                            locked_quote_wusdt: 0,
                            locked_quote_native: 0,
                        },
                    );
                    gens[Domain::Escrow.index()] += 1;
                }
                _ => {
                    if let Some(book) = s.orderbooks.books.get_mut(&7) {
                        book.next_order_id += 1;
                    }
                    gens[Domain::Books.index()] += 1;
                }
            }
            let cloned = assemble_clone(&s, &zkml, &gens, &mut cache);
            let reference = streaming_of(&s, &zkml);
            assert_eq!(
                cloned, reference,
                "seed {seed:#x} step {step}: clone-path diverged from streaming"
            );
            let zero = assemble_from_cache(&mut cache, &gens).expect(
                "seed: cache was just filled by the clone path, zero-copy must hit",
            );
            assert_eq!(
                zero, reference,
                "seed {seed:#x} step {step}: zero-copy diverged from streaming"
            );
        }
    }
}
