//! Wave 14b: Dynamic shard split/merge live state migration tests on `InMemoryStateEngine`.

use std::collections::{BTreeSet, HashMap};

use stellereum::cell::PatriciaTrie;
use stellereum::contract_abi::{AbiMethod, AbiParam, AbiType, ContractAbi};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{
    address_prefix_bit, MergeRefusal, MigrationDirection, SplitRefusal,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD, MIN_ACCOUNTS_PER_SHARD,
    SHARD_MERGE_LOAD_THRESHOLD, SHARD_SPLIT_LOAD_THRESHOLD,
};
use stellereum::state_engine::{
    contract_abi_key, contract_key, token_balance_key, token_supply_key, AccountState,
    InMemoryStateEngine, ShardMigrationError,
};
use stellereum::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};
use stellereum::tokenomics::TOTAL_SUPPLY_CAP;

const TEST_CHAIN_ID: u64 = 4242;

const STATEFUL_WAT: &str = r#"(module
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))
  (func (export "get") (param i64) (result i64) (call $sload (local.get 0)))
  (func (export "set") (param i64) (result i64)
    (call $sstore (i64.const 0) (local.get 0))
    (call $emit (i64.const 1) (local.get 0))
    (local.get 0)))"#;

fn stateful_abi() -> ContractAbi {
    ContractAbi {
        methods: vec![
            AbiMethod::view(
                "get",
                vec![AbiParam::new("key", AbiType::I64)],
                AbiType::I64,
            ),
            AbiMethod::mutating(
                "set",
                vec![AbiParam::new("val", AbiType::I64)],
                AbiType::I64,
            ),
        ],
        events: vec![],
    }
}

fn synthetic_address(i: u64) -> [u8; 32] {
    let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&z.to_be_bytes());
    a[8..16].copy_from_slice(&z.rotate_left(17).to_be_bytes());
    a
}

fn synthetic_balance(i: u64) -> u64 {
    10_000 + (i % 977) * 17
}

fn token_meta(name: &str, symbol: &str) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: "Wave 14b test token".to_string(),
    }
}

async fn seed_accounts(engine: &InMemoryStateEngine, count: u64) -> Vec<[u8; 32]> {
    let mut addrs = Vec::with_capacity(count as usize);
    for i in 0..count {
        let addr = synthetic_address(i);
        let mut acc = AccountState::new(addr, synthetic_balance(i));
        acc.nonce = i % 7;
        engine.update_account(acc).await;
        addrs.push(addr);
    }
    addrs
}

#[tokio::test]
async fn split_refuses_masterchain_and_low_load_and_low_accounts() {
    // 1. Masterchain refuses to split.
    let mc = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    mc.set_shard_id(MASTERCHAIN_SHARD);
    seed_accounts(&mc, MIN_ACCOUNTS_PER_SHARD).await;
    mc.sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 500)
        .await;
    let err = mc.execute_shard_split(MASTERCHAIN_SHARD).await.unwrap_err();
    assert_eq!(err, ShardMigrationError::MasterchainForbidden);

    // 2. Shard id mismatch refuses fail-closed.
    let wc = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    wc.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);
    let mismatch_err = wc
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL + 1)
        .await
        .unwrap_err();
    assert_eq!(
        mismatch_err,
        ShardMigrationError::ShardMismatch {
            expected: BASE_WORKCHAIN_SHARD_INITIAL + 1,
            actual: BASE_WORKCHAIN_SHARD_INITIAL,
        }
    );

    // 3. Too few accounts refuses without mutating topology.
    seed_accounts(&wc, MIN_ACCOUNTS_PER_SHARD - 1).await;
    wc.sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD)
        .await;
    let few_err = wc
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .unwrap_err();
    assert_eq!(
        few_err,
        ShardMigrationError::SplitRefused(SplitRefusal::TooFewAccounts {
            accounts: MIN_ACCOUNTS_PER_SHARD - 1,
            minimum: MIN_ACCOUNTS_PER_SHARD,
        })
    );
    {
        let topo = wc.shard_topology().await;
        assert_eq!(topo.shard_count(), 2);
        assert_eq!(topo.transitions, 0);
    }

    // 4. Load below threshold refuses without mutating topology.
    let extra = synthetic_address(MIN_ACCOUNTS_PER_SHARD - 1);
    wc.update_account(AccountState::new(extra, 50_000)).await;
    wc.sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD - 1)
        .await;
    let low_load_err = wc
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .unwrap_err();
    assert_eq!(
        low_load_err,
        ShardMigrationError::SplitRefused(SplitRefusal::LoadTooLow {
            load: SHARD_SPLIT_LOAD_THRESHOLD - 1,
            threshold: SHARD_SPLIT_LOAD_THRESHOLD,
        })
    );
    {
        let topo = wc.shard_topology().await;
        assert_eq!(topo.shard_count(), 2);
        assert_eq!(topo.transitions, 0);
    }
}

#[tokio::test]
async fn split_partitions_accounts_contracts_tokens_and_preserves_spv_and_totals() {
    let engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    engine.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);

    let count = MIN_ACCOUNTS_PER_SHARD + 20;
    let addrs = seed_accounts(&engine, count).await;

    let bit0_addrs: Vec<[u8; 32]> = addrs
        .iter()
        .copied()
        .filter(|a| address_prefix_bit(a, 0) == 0)
        .collect();
    let bit1_addrs: Vec<[u8; 32]> = addrs
        .iter()
        .copied()
        .filter(|a| address_prefix_bit(a, 0) == 1)
        .collect();
    assert!(bit0_addrs.len() >= 2, "expected multiple bit-0 addresses");
    assert!(!bit1_addrs.is_empty(), "expected bit-1 addresses");

    let creator0 = bit0_addrs[0];
    let holder0 = bit0_addrs[1];
    let holder1 = bit1_addrs[0];

    // Deploy contract with ABI and mutate persistent storage slot 0.
    let wasm = wat::parse_str(STATEFUL_WAT).expect("valid WAT");
    let contract_addr = engine
        .deploy_contract_with_abi(creator0, wasm, 100, stateful_abi())
        .await
        .expect("contract deploy");
    let call_out = engine
        .call_contract_structured(&contract_addr, "set", 1337, 100_000)
        .await;
    assert_eq!(call_out.status, "success");

    // Create STS token and split holdings across bit-0 and bit-1 shards.
    let token_id = engine
        .create_token(creator0, token_meta("Wave14Token", "W14"), 1_000_000)
        .await
        .expect("token create");
    engine
        .token_execute(
            &token_id,
            creator0,
            TokenOp::Transfer {
                to: holder1,
                amount: 350_000,
            },
        )
        .await
        .expect("transfer to bit-1 holder");
    engine
        .token_execute(
            &token_id,
            creator0,
            TokenOp::Transfer {
                to: holder0,
                amount: 150_000,
            },
        )
        .await
        .expect("transfer to bit-0 holder");

    let parent_balance_sum: u128 = engine
        .accounts
        .read()
        .await
        .values()
        .map(|a| a.balance as u128)
        .sum();

    engine
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 100)
        .await;

    let split = engine
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .expect("shard split must succeed");

    assert_eq!(split.transition.plan.direction, MigrationDirection::Split);
    let split_bit = split.transition.plan.split_bit;
    assert_eq!(split_bit, 0);

    let c0 = &split.child0;
    let c1 = &split.child1;
    assert_eq!(c0.shard_id(), split.transition.children[0].shard_id);
    assert_eq!(c1.shard_id(), split.transition.children[1].shard_id);
    assert_eq!(c0.chain_id, TEST_CHAIN_ID);
    assert_eq!(c1.chain_id, TEST_CHAIN_ID);

    // 1. Disjoint, complete, prefix-routed account partitioning + exact native sum.
    let c0_accounts = c0.accounts.read().await;
    let c1_accounts = c1.accounts.read().await;
    assert_eq!(c0_accounts.len() + c1_accounts.len(), count as usize);

    let mut seen = BTreeSet::new();
    let mut sum0: u128 = 0;
    let mut sum1: u128 = 0;
    for (addr, acc) in c0_accounts.iter() {
        assert_eq!(address_prefix_bit(addr, split_bit), 0);
        assert!(seen.insert(*addr));
        sum0 += acc.balance as u128;
    }
    for (addr, acc) in c1_accounts.iter() {
        assert_eq!(address_prefix_bit(addr, split_bit), 1);
        assert!(seen.insert(*addr));
        sum1 += acc.balance as u128;
    }
    assert_eq!(seen.len(), count as usize);
    assert_eq!(sum0 + sum1, parent_balance_sum);
    drop(c0_accounts);
    drop(c1_accounts);

    // 2. Contract partitioned by its contract_address bit with ABI and storage intact.
    if address_prefix_bit(&contract_addr, split_bit) == 0 {
        let c = c0
            .get_contract(&contract_addr)
            .await
            .expect("contract in c0");
        assert!(c.abi.is_some());
        assert_eq!(c.storage.get(&0), Some(&1337));
        assert!(c1.get_contract(&contract_addr).await.is_none());
    } else {
        let c = c1
            .get_contract(&contract_addr)
            .await
            .expect("contract in c1");
        assert!(c.abi.is_some());
        assert_eq!(c.storage.get(&0), Some(&1337));
        assert!(c0.get_contract(&contract_addr).await.is_none());
    }

    // 3. Token balances + supply conservation across children, plus SPV verification.
    assert_eq!(c0.token_balance(&token_id, &creator0).await, 500_000);
    assert_eq!(c0.token_balance(&token_id, &holder0).await, 150_000);
    assert_eq!(c0.token_balance(&token_id, &holder1).await, 0);
    assert_eq!(c1.token_balance(&token_id, &holder1).await, 350_000);
    assert_eq!(c1.token_balance(&token_id, &creator0).await, 0);

    let s0 = c0
        .token_total_supply(&token_id)
        .await
        .expect("c0 holds token metadata");
    let s1 = c1
        .token_total_supply(&token_id)
        .await
        .expect("c1 holds token metadata");
    assert_eq!(s0, 1_000_000, "c0 preserves token total_supply");
    assert_eq!(s1, 1_000_000, "c1 preserves token total_supply");
    assert!(
        c1.state_trie
            .read()
            .await
            .get(&token_supply_key(&token_id))
            .is_none(),
        "only minter shard owns token_supply_key in state_trie"
    );

    let root0 = c0.get_state_root().await;
    let root1 = c1.get_state_root().await;

    let supply_proof = c0
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&token_supply_key(&token_id))
        .expect("supply proof on minter child");
    assert!(PatriciaTrie::verify_merkle_proof(
        &root0,
        &token_supply_key(&token_id),
        &1_000_000u64.to_be_bytes(),
        &supply_proof,
    ));

    let holder1_proof = c1
        .get_token_balance_proof(&token_id, &holder1)
        .await
        .expect("token balance proof on c1");
    assert!(PatriciaTrie::verify_merkle_proof(
        &root1,
        &token_balance_key(&token_id, &holder1),
        &350_000u64.to_be_bytes(),
        &holder1_proof,
    ));

    // 4. Every account SPV proof verifies against its child's state root.
    for addr in &addrs {
        if address_prefix_bit(addr, split_bit) == 0 {
            let acc = c0.get_account(addr).await.unwrap();
            let proof = c0.get_account_proof(addr).await.unwrap();
            assert!(PatriciaTrie::verify_merkle_proof(
                &root0,
                addr,
                &acc.to_trie_bytes(),
                &proof
            ));
        } else {
            let acc = c1.get_account(addr).await.unwrap();
            let proof = c1.get_account_proof(addr).await.unwrap();
            assert!(PatriciaTrie::verify_merkle_proof(
                &root1,
                addr,
                &acc.to_trie_bytes(),
                &proof
            ));
        }
    }

    c0.shard_topology()
        .await
        .verify_invariants()
        .expect("c0 invariants");
    c1.shard_topology()
        .await
        .verify_invariants()
        .expect("c1 invariants");
}

#[tokio::test]
async fn split_then_merge_roundtrip_restores_exact_state() {
    let parent = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    parent.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);

    let count = MIN_ACCOUNTS_PER_SHARD + 24;
    let addrs = seed_accounts(&parent, count).await;
    let creator0 = addrs
        .iter()
        .copied()
        .find(|a| address_prefix_bit(a, 0) == 0)
        .expect("bit-0 addr");
    let holder1 = addrs
        .iter()
        .copied()
        .find(|a| address_prefix_bit(a, 0) == 1)
        .expect("bit-1 addr");

    let wasm = wat::parse_str(STATEFUL_WAT).expect("valid WAT");
    let contract_addr = parent
        .deploy_contract_with_abi(creator0, wasm, 77, stateful_abi())
        .await
        .expect("deploy");
    assert_eq!(
        parent
            .call_contract_structured(&contract_addr, "set", 9001, 100_000)
            .await
            .status,
        "success"
    );

    let token_id = parent
        .create_token(creator0, token_meta("Roundtrip", "RND"), 2_000_000)
        .await
        .expect("create token");
    parent
        .token_execute(
            &token_id,
            creator0,
            TokenOp::Transfer {
                to: holder1,
                amount: 750_000,
            },
        )
        .await
        .expect("transfer token");

    let root_before = parent.get_state_root().await;

    parent
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 50)
        .await;
    let split = parent
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .expect("split succeeds");
    let id0 = split.child0.shard_id();
    let id1 = split.child1.shard_id();

    // Anti-oscillation: freshly split shards cannot immediately merge while load is high.
    let high_load_merge = parent
        .execute_shard_merge(&split.child0, id0, &split.child1, id1)
        .await
        .unwrap_err();
    assert!(matches!(
        high_load_merge,
        ShardMigrationError::MergeRefused(MergeRefusal::LoadTooHigh { .. })
    ));

    // Quiet window drains load below SHARD_MERGE_LOAD_THRESHOLD.
    split.child0.sync_topology_from_accounts(10).await;
    split.child1.sync_topology_from_accounts(10).await;

    let merge = parent
        .execute_shard_merge(&split.child0, id0, &split.child1, id1)
        .await
        .expect("merge succeeds after quiet window");

    assert_eq!(merge.transition.plan.direction, MigrationDirection::Merge);
    assert_eq!(merge.merged.shard_id(), merge.transition.parent.shard_id);
    assert_ne!(merge.merged.shard_id(), id0);
    assert_ne!(merge.merged.shard_id(), id1);
    assert_ne!(merge.merged.shard_id(), BASE_WORKCHAIN_SHARD_INITIAL);

    // Exact accounts, contracts, token balances, and state root restored.
    assert_eq!(merge.merged.accounts.read().await.len(), count as usize);
    for (i, addr) in addrs.iter().enumerate() {
        let acc = merge
            .merged
            .get_account(addr)
            .await
            .expect("account restored");
        assert_eq!(acc.balance, synthetic_balance(i as u64));
        assert_eq!(acc.nonce, (i as u64) % 7);
    }

    let restored_contract = merge
        .merged
        .get_contract(&contract_addr)
        .await
        .expect("contract restored");
    assert!(restored_contract.abi.is_some());
    assert_eq!(restored_contract.storage.get(&0), Some(&9001));

    assert_eq!(
        merge.merged.token_balance(&token_id, &creator0).await,
        1_250_000
    );
    assert_eq!(
        merge.merged.token_balance(&token_id, &holder1).await,
        750_000
    );
    assert_eq!(
        merge.merged.token_total_supply(&token_id).await,
        Some(2_000_000)
    );

    merge
        .merged
        .shard_topology()
        .await
        .verify_invariants()
        .expect("merged topology invariants");

    let root_after = merge.merged.get_state_root().await;
    assert_eq!(
        root_after, root_before,
        "split -> merge roundtrip must restore bit-identical state root"
    );
}

#[tokio::test]
async fn split_fails_closed_on_unclassified_trie_key() {
    let engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    engine.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);
    seed_accounts(&engine, MIN_ACCOUNTS_PER_SHARD + 10).await;
    engine
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 25)
        .await;

    let stray_key = [0xEEu8; 32];
    engine
        .state_trie
        .write()
        .await
        .insert(&stray_key, b"stray-unclassified-state");

    let err = engine
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .unwrap_err();
    assert_eq!(err, ShardMigrationError::UnclassifiedKey(stray_key));

    // Topology must remain unmutated on failure.
    let topo = engine.shard_topology().await;
    assert_eq!(topo.shard_count(), 2);
    assert_eq!(topo.transitions, 0);
}

#[tokio::test]
async fn split_refuses_non_empty_staking_or_bridge_domains() {
    // 1. Non-empty staking domain refuses fail-closed.
    let staking_engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    staking_engine.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);
    seed_accounts(&staking_engine, MIN_ACCOUNTS_PER_SHARD + 8).await;
    staking_engine
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 50)
        .await;
    staking_engine.staking_write().await.rewards_pool = 10_000;

    let err = staking_engine
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        ShardMigrationError::UnsupportedNonEmptyDomain("staking")
    );
    assert_eq!(staking_engine.shard_topology().await.transitions, 0);

    // 2. Non-empty bridge domain refuses fail-closed.
    let bridge_engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    bridge_engine.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);
    seed_accounts(&bridge_engine, MIN_ACCOUNTS_PER_SHARD + 8).await;
    bridge_engine
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 50)
        .await;
    bridge_engine
        .bridge_write()
        .await
        .processed_source_txs
        .insert([0x42u8; 32]);

    let err = bridge_engine
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        ShardMigrationError::UnsupportedNonEmptyDomain("bridge")
    );
    assert_eq!(bridge_engine.shard_topology().await.transitions, 0);
}

#[tokio::test]
async fn split_partitions_chain_mint_limit_and_pq_keys_and_penalties() {
    let engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    engine.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);

    let addrs = seed_accounts(&engine, MIN_ACCOUNTS_PER_SHARD + 12).await;

    // Find one bit-0 and one bit-1 Falcon-512 PQ address for pq_keys_fallback + pq_registry.
    let mut bit0_pq: Option<(FalconKeypair, [u8; 32])> = None;
    let mut bit1_pq: Option<(FalconKeypair, [u8; 32])> = None;
    for seed_byte in 1u8..=255u8 {
        let kp = FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32]);
        let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        if address_prefix_bit(&addr, 0) == 0 && bit0_pq.is_none() {
            bit0_pq = Some((kp, addr));
        } else if address_prefix_bit(&addr, 0) == 1 && bit1_pq.is_none() {
            bit1_pq = Some((kp, addr));
        }
        if bit0_pq.is_some() && bit1_pq.is_some() {
            break;
        }
    }
    let (kp0, pq_addr0) = bit0_pq.expect("bit-0 pq key");
    let (kp1, pq_addr1) = bit1_pq.expect("bit-1 pq key");

    engine
        .update_account(AccountState::new(pq_addr0, 50_000))
        .await;
    engine
        .update_account(AccountState::new(pq_addr1, 60_000))
        .await;
    engine
        .pin_pubkey(
            pq_addr0,
            PqScheme::Falcon512,
            &kp0.public_key,
            &DEFAULT_SALT,
        )
        .await
        .expect("pin bit-0 pq key");
    engine
        .pin_pubkey(
            pq_addr1,
            PqScheme::Falcon512,
            &kp1.public_key,
            &DEFAULT_SALT,
        )
        .await
        .expect("pin bit-1 pq key");

    // Register PQ registry records on bit-0 and bit-1 validator IDs.
    let val0 = addrs
        .iter()
        .copied()
        .find(|a| address_prefix_bit(a, 0) == 0)
        .expect("bit-0 validator id");
    let val1 = addrs
        .iter()
        .copied()
        .find(|a| address_prefix_bit(a, 0) == 1)
        .expect("bit-1 validator id");
    {
        let mut reg = engine.pq_registry_write().await;
        reg.register(
            val0,
            PqScheme::Falcon512,
            kp0.public_key.clone(),
            0,
            0,
            true,
        )
        .expect("register val0");
        reg.register(
            val1,
            PqScheme::Falcon512,
            kp1.public_key.clone(),
            0,
            0,
            true,
        )
        .expect("register val1");
    }

    // Install D2 consensus penalties on bit-0 and bit-1 addresses AND set total_minted_nano = 1
    // via StateSnapshotV2 restore to verify the parent_minted == 1 non-double-count fix.
    let mut snap = engine.capture_state_snapshot().await;
    let mut penalty_map = HashMap::new();
    penalty_map.insert(val0, 280_000);
    penalty_map.insert(val1, 560_000);
    snap.penalty = penalty_map;
    snap.total_minted_nano = 1;
    let snap_bytes = bincode::serialize(&snap).expect("serialize snapshot");
    engine
        .restore_snapshot(&snap_bytes)
        .await
        .expect("restore snapshot");
    // Re-populate pq_registry and pq_keys_fallback after restore_snapshot cleared pq_registry.
    {
        let mut reg = engine.pq_registry_write().await;
        reg.register(
            val0,
            PqScheme::Falcon512,
            kp0.public_key.clone(),
            0,
            0,
            true,
        )
        .expect("re-register val0");
        reg.register(
            val1,
            PqScheme::Falcon512,
            kp1.public_key.clone(),
            0,
            0,
            true,
        )
        .expect("re-register val1");
    }
    engine
        .pin_pubkey(
            pq_addr0,
            PqScheme::Falcon512,
            &kp0.public_key,
            &DEFAULT_SALT,
        )
        .await
        .expect("re-pin bit-0 pq key");
    engine
        .pin_pubkey(
            pq_addr1,
            PqScheme::Falcon512,
            &kp1.public_key,
            &DEFAULT_SALT,
        )
        .await
        .expect("re-pin bit-1 pq key");

    let parent_root_before = engine.get_state_root().await;

    engine
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 10)
        .await;
    let split = engine
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .expect("split succeeds");

    let c0 = &split.child0;
    let c1 = &split.child1;

    // 1. chain_mint_limit_nano is partitioned without exceeding TOTAL_SUPPLY_CAP.
    assert_eq!(c0.chain_mint_limit_nano(), TOTAL_SUPPLY_CAP / 2);
    assert_eq!(
        c1.chain_mint_limit_nano(),
        TOTAL_SUPPLY_CAP - TOTAL_SUPPLY_CAP / 2
    );
    assert_eq!(
        c0.chain_mint_limit_nano() + c1.chain_mint_limit_nano(),
        TOTAL_SUPPLY_CAP
    );

    // 2. total_minted_nano == 1 stays non-zero on child0 (which holds balances),
    //    preventing genesis_allocation_nano() double-counting on subsequent mint.
    assert_eq!(c0.total_minted_nano() + c1.total_minted_nano(), 1);
    assert_eq!(c0.total_minted_nano(), 1);
    let sim0 = c0.clone_for_simulation().await;
    sim0.mint_native(&pq_addr0, 100)
        .await
        .expect("mint on sim0");
    assert_eq!(
        sim0.total_minted_nano(),
        101,
        "child0 must not re-fold genesis balances on first post-split mint"
    );

    // 3. pq_keys_fallback partitioned by address split bit.
    assert!(c0.get_pinned_pubkey_with_salt(&pq_addr0).is_some());
    assert!(c0.get_pinned_pubkey_with_salt(&pq_addr1).is_none());
    assert!(c1.get_pinned_pubkey_with_salt(&pq_addr1).is_some());
    assert!(c1.get_pinned_pubkey_with_salt(&pq_addr0).is_none());

    // 4. pq_registry partitioned by validator_id split bit.
    assert!(c0.pq_registry_read().await.record_of(&val0).is_some());
    assert!(c0.pq_registry_read().await.record_of(&val1).is_none());
    assert!(c1.pq_registry_read().await.record_of(&val1).is_some());
    assert!(c1.pq_registry_read().await.record_of(&val0).is_none());

    // 5. consensus_penalty partitioned by address split bit.
    let p0 = c0.consensus_penalty_try_read().expect("c0 penalty");
    let p1 = c1.consensus_penalty_try_read().expect("c1 penalty");
    assert_eq!(p0.get(&val0).copied(), Some(280_000));
    assert_eq!(p0.get(&val1), None);
    assert_eq!(p1.get(&val1).copied(), Some(560_000));
    assert_eq!(p1.get(&val0), None);

    // 6. Merge roundtrip restores chain_mint_limit_nano, pq_registry, pq_keys_fallback, penalties, and root.
    c0.sync_topology_from_accounts(10).await;
    c1.sync_topology_from_accounts(10).await;
    let merge = engine
        .execute_shard_merge(c0, c0.shard_id(), c1, c1.shard_id())
        .await
        .expect("merge succeeds");
    assert_eq!(merge.merged.chain_mint_limit_nano(), TOTAL_SUPPLY_CAP);
    assert_eq!(merge.merged.total_minted_nano(), 1);
    assert!(merge
        .merged
        .get_pinned_pubkey_with_salt(&pq_addr0)
        .is_some());
    assert!(merge
        .merged
        .get_pinned_pubkey_with_salt(&pq_addr1)
        .is_some());
    assert!(merge
        .merged
        .pq_registry_read()
        .await
        .record_of(&val0)
        .is_some());
    assert!(merge
        .merged
        .pq_registry_read()
        .await
        .record_of(&val1)
        .is_some());
    let mp = merge
        .merged
        .consensus_penalty_try_read()
        .expect("merged penalty");
    assert_eq!(mp.get(&val0).copied(), Some(280_000));
    assert_eq!(mp.get(&val1).copied(), Some(560_000));
    assert_eq!(merge.merged.get_state_root().await, parent_root_before);
}

#[tokio::test]
async fn merge_refuses_when_child_tx_load_exceeds_threshold() {
    let parent = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    parent.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);
    seed_accounts(&parent, MIN_ACCOUNTS_PER_SHARD + 12).await;
    parent
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 100)
        .await;

    let split = parent
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .expect("split succeeds");
    let id0 = split.child0.shard_id();
    let id1 = split.child1.shard_id();

    // Even if the parent's cached topology decayed loads to 0, child0's live load
    // above SHARD_MERGE_LOAD_THRESHOLD MUST unconditionally block the merge.
    parent.shard_topology_mut().await.decay_load(u64::MAX);
    split
        .child0
        .sync_topology_from_accounts(SHARD_MERGE_LOAD_THRESHOLD + 1)
        .await;
    split.child1.sync_topology_from_accounts(0).await;

    let err = parent
        .execute_shard_merge(&split.child0, id0, &split.child1, id1)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ShardMigrationError::MergeRefused(MergeRefusal::LoadTooHigh { .. })
    ));
}

#[tokio::test]
async fn split_and_merge_conserve_allowances_and_contract_spv_proofs() {
    let parent = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    parent.set_shard_id(BASE_WORKCHAIN_SHARD_INITIAL);

    let addrs = seed_accounts(&parent, MIN_ACCOUNTS_PER_SHARD + 16).await;
    let owner0 = addrs
        .iter()
        .copied()
        .find(|a| address_prefix_bit(a, 0) == 0)
        .expect("bit-0 owner");
    let owner1 = addrs
        .iter()
        .copied()
        .find(|a| address_prefix_bit(a, 0) == 1)
        .expect("bit-1 owner");

    // Deploy both a regular ABI contract and a deterministic contract (raw `&code` leaf, no AccountState).
    let wasm = wat::parse_str(STATEFUL_WAT).expect("valid WAT");
    let abi_contract = parent
        .deploy_contract_with_abi(owner0, wasm.clone(), 100, stateful_abi())
        .await
        .expect("deploy abi contract");
    let det_outcome = parent
        .deploy_contract_deterministic(owner0, wasm, b"det-salt-w14", 101)
        .await
        .expect("deploy deterministic contract");
    let det_contract = det_outcome.contract_address;
    assert!(
        parent.get_account(&det_contract).await.is_none(),
        "deterministic contract has raw code leaf without AccountState"
    );

    // Create token, transfer to bit-1 holder, and approve allowances on both shards.
    let token_id = parent
        .create_token(owner0, token_meta("AllowanceToken", "ALW"), 1_000_000)
        .await
        .expect("create token");
    parent
        .token_execute(
            &token_id,
            owner0,
            TokenOp::Transfer {
                to: owner1,
                amount: 400_000,
            },
        )
        .await
        .expect("transfer to owner1");
    parent
        .token_execute(
            &token_id,
            owner0,
            TokenOp::Approve {
                spender: owner1,
                amount: 125_000,
            },
        )
        .await
        .expect("owner0 approve");
    parent
        .token_execute(
            &token_id,
            owner1,
            TokenOp::Approve {
                spender: owner0,
                amount: 75_000,
            },
        )
        .await
        .expect("owner1 approve");

    let root_before = parent.get_state_root().await;

    parent
        .sync_topology_from_accounts(SHARD_SPLIT_LOAD_THRESHOLD + 10)
        .await;
    let split = parent
        .execute_shard_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .await
        .expect("split succeeds");
    let c0 = &split.child0;
    let c1 = &split.child1;

    // Allowances partitioned by owner's split bit.
    assert_eq!(
        c0.tokens_read()
            .await
            .get(&token_id)
            .expect("c0 token")
            .allowance(&owner0, &owner1),
        125_000
    );
    assert_eq!(
        c1.tokens_read()
            .await
            .get(&token_id)
            .expect("c1 token")
            .allowance(&owner1, &owner0),
        75_000
    );

    // Burn on non-minter shard (c1) works because total_supply is preserved.
    let c1_burn_sim = c1.clone_for_simulation().await;
    c1_burn_sim
        .token_execute(
            &token_id,
            owner1,
            TokenOp::Burn {
                from: owner1,
                amount: 10_000,
            },
        )
        .await
        .expect("burn on non-minter shard must succeed");
    assert_eq!(
        c1_burn_sim.token_total_supply(&token_id).await,
        Some(990_000)
    );

    // Contract SPV proofs (code_hash, abi, and raw deterministic code leaf) verify on owning child.
    let (abi_child, abi_root) = if address_prefix_bit(&abi_contract, 0) == 0 {
        (c0, c0.get_state_root().await)
    } else {
        (c1, c1.get_state_root().await)
    };
    let abi_c = abi_child
        .get_contract(&abi_contract)
        .await
        .expect("abi contract");
    let c_proof = abi_child
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&contract_key(&abi_contract))
        .expect("contract_key proof");
    assert!(PatriciaTrie::verify_merkle_proof(
        &abi_root,
        &contract_key(&abi_contract),
        &abi_c.code_hash,
        &c_proof
    ));
    let a_proof = abi_child
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&contract_abi_key(&abi_contract))
        .expect("contract_abi_key proof");
    assert!(PatriciaTrie::verify_merkle_proof(
        &abi_root,
        &contract_abi_key(&abi_contract),
        abi_c.abi.as_ref().unwrap().to_json().as_bytes(),
        &a_proof
    ));

    let (det_child, det_root) = if address_prefix_bit(&det_contract, 0) == 0 {
        (c0, c0.get_state_root().await)
    } else {
        (c1, c1.get_state_root().await)
    };
    let raw_code = det_child
        .get_contract_code_from_trie(&det_contract)
        .await
        .expect("raw deterministic code leaf");
    let raw_proof = det_child
        .state_trie
        .read()
        .await
        .generate_merkle_proof(&det_contract)
        .expect("raw deterministic code proof");
    assert!(PatriciaTrie::verify_merkle_proof(
        &det_root,
        &det_contract,
        &raw_code,
        &raw_proof
    ));

    // Merge back and verify allowances, contract SPV proofs, and exact root roundtrip.
    c0.sync_topology_from_accounts(5).await;
    c1.sync_topology_from_accounts(5).await;
    let merge = parent
        .execute_shard_merge(c0, c0.shard_id(), c1, c1.shard_id())
        .await
        .expect("merge succeeds");
    let merged = &merge.merged;
    let m_tok = merged
        .tokens_read()
        .await
        .get(&token_id)
        .expect("merged token")
        .clone();
    assert_eq!(m_tok.allowance(&owner0, &owner1), 125_000);
    assert_eq!(m_tok.allowance(&owner1, &owner0), 75_000);
    assert_eq!(m_tok.metadata.total_supply, 1_000_000);
    assert!(merged
        .get_contract_code_from_trie(&det_contract)
        .await
        .is_some());
    assert_eq!(merged.get_state_root().await, root_before);
}
