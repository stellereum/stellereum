//! Reproducible load test of the DYNAMIC SHARDING path: a split and a merge
//! over a synthetic account set, with a REAL trie.
//!
//! What this test DEMONSTRATES (and what it does NOT):
//!
//! * DEMONSTRATED: the split re-assigns accounts by the documented prefix
//!   rule, the trie migration moves every account leaf into exactly one
//!   child trie, the merge is the inverse, the total balance is conserved,
//!   every account stays reachable, the routing rule keeps resolving, and
//!   the topology CONVERGES (a split shard is not merge-eligible, so the
//!   cycle cannot oscillate).
//! * NOT DEMONSTRATED: a LIVE-NETWORK split. No split has been performed on
//!   the testnet or on mainnet; this test drives the state machine over a
//!   synthetic account set in-process.
//!
//! Run with: `cargo test --test sharding_topology_tests`

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::RwLock;

use stellereum::cell::PatriciaTrie;
use stellereum::mempool::Mempool;
use stellereum::rpc::RpcState;
use stellereum::sharding::{
    address_prefix_bit, route_shard, MigrationDirection, MigrationManifest, ShardAddress,
    ShardTopology, TrieMigration, MASTERCHAIN_SHARD, MAX_SHARDS, MIN_ACCOUNTS_PER_SHARD,
    SHARD_SPLIT_LOAD_THRESHOLD,
};
use stellereum::state_engine::InMemoryStateEngine;

/// The number of synthetic accounts in the load test.
const N_ACCOUNTS: u64 = 2_000;

/// A deterministic synthetic account address (splitmix64 of the index), so
/// the test is reproducible byte-for-byte on every run.
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

/// The balance of a synthetic account.
fn synthetic_balance(i: u64) -> u64 {
    1_000 + (i % 977) * 13
}

/// A topology holding the synthetic account set, plus the matching trie and
/// the migration manifest that describes it.
struct Fixture {
    topology: ShardTopology,
    trie: PatriciaTrie,
    manifest: MigrationManifest,
}

fn fixture(n: u64) -> Fixture {
    let mut topology = ShardTopology::new();
    let mut trie = PatriciaTrie::new();
    let mut manifest = MigrationManifest::new();
    for i in 0..n {
        let addr = synthetic_address(i);
        let balance = synthetic_balance(i);
        topology.register_account(addr, balance);
        // The account leaf the engine would store: balance || nonce.
        let mut leaf = Vec::with_capacity(16);
        leaf.extend_from_slice(&balance.to_be_bytes());
        leaf.extend_from_slice(&0u64.to_be_bytes());
        trie.insert(&addr, &leaf);
        manifest.own(addr, addr);
    }
    Fixture {
        topology,
        trie,
        manifest,
    }
}

/// Every account leaf that lives in the given tries, keyed by address.
fn leaves(tries: &[&PatriciaTrie]) -> std::collections::BTreeMap<[u8; 32], Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    for t in tries {
        for (k, v) in t.compressed().entries.iter() {
            assert!(
                out.insert(*k, v.clone()).is_none(),
                "an account must not live in two tries"
            );
        }
    }
    out
}

#[test]
fn split_and_merge_preserve_balances_ownership_and_converge() {
    let mut f = fixture(N_ACCOUNTS);
    let total_before = f.topology.total_balance();
    let accounts_before: BTreeSet<[u8; 32]> = f
        .topology
        .all_accounts()
        .iter()
        .map(|a| a.address)
        .collect();
    assert_eq!(accounts_before.len() as u64, N_ACCOUNTS);

    // ---- SPLIT ---------------------------------------------------------
    f.topology
        .record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD + 100);
    let split = f
        .topology
        .check_and_split(1)
        .expect("the split trigger fires: enough accounts and enough load");
    assert_eq!(split.plan.direction, MigrationDirection::Split);
    assert_eq!(split.plan.account_count, N_ACCOUNTS as usize);
    assert!(
        split.plan.balances_conserve(),
        "a split must conserve the total balance"
    );
    assert_eq!(split.plan.source_balance, total_before);

    // 1. The total balance is preserved by the account-level re-assignment.
    assert_eq!(f.topology.total_balance(), total_before);

    // 2. Every account is still owned by exactly one shard, and the OWNER is
    //    the shard the routing rule selects.
    let [c0, c1] = split.children;
    f.topology
        .verify_invariants()
        .expect("invariants after the split");
    for acct in f.topology.all_accounts() {
        let owner = f.topology.owner_of(&acct.address).expect("still owned");
        let routed = route_shard(&f.topology, &ShardAddress::Workchain(acct.address));
        assert_eq!(owner, routed, "the rule and the ownership must agree");
        // The prefix bit at the split depth decides the child.
        let expected = if address_prefix_bit(&acct.address, split.plan.split_bit) == 0 {
            c0.shard_id
        } else {
            c1.shard_id
        };
        assert_eq!(owner, expected, "the prefix bit must decide the child");
    }

    // 3. The TRIE migration moves every account leaf into exactly one child.
    let migration = TrieMigration::new(split.plan.clone(), f.manifest.clone());
    let (child0, child1) = migration
        .execute_split(&f.trie)
        .expect("the trie migration runs");
    migration
        .verify_split(&f.trie, &child0, &child1)
        .expect("the trie migration verifies");

    // Every account is still REACHABLE: exactly one child holds its leaf,
    // with the same bytes.
    let moved = leaves(&[&child0, &child1]);
    assert_eq!(moved.len() as u64, N_ACCOUNTS);
    for i in 0..N_ACCOUNTS {
        let addr = synthetic_address(i);
        let leaf = moved.get(&addr).expect("the account is still reachable");
        let mut expected = Vec::new();
        expected.extend_from_slice(&synthetic_balance(i).to_be_bytes());
        expected.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(leaf, &expected, "the leaf must be byte-identical");
    }

    // 4. The topology CONVERGES: a shard that has just split is not
    //    merge-eligible, so the cycle cannot oscillate.
    assert!(
        f.topology
            .check_and_merge(c0.shard_id, c1.shard_id)
            .is_none(),
        "a freshly split shard must not be merge-eligible"
    );
    let shard_count = f.topology.shard_count();
    for _ in 0..8 {
        for id in f.topology.shards().map(|(id, _)| *id).collect::<Vec<_>>() {
            assert!(f.topology.check_and_split(id).is_none());
        }
        assert_eq!(f.topology.shard_count(), shard_count, "no oscillation");
    }

    // ---- MERGE ---------------------------------------------------------
    // The load window rolls: the shard drains (to zero) and becomes
    // merge-eligible. The split preserved the parent's load in SUM, so the
    // children together still carry it until the window rolls over.
    f.topology.decay_load(SHARD_SPLIT_LOAD_THRESHOLD + 100);
    let merge = f
        .topology
        .check_and_merge(c0.shard_id, c1.shard_id)
        .expect("the merge trigger fires once the load decayed");
    assert_eq!(merge.plan.direction, MigrationDirection::Merge);
    assert!(merge.plan.balances_conserve());

    // 5. The total balance is preserved by the merge.
    assert_eq!(f.topology.total_balance(), total_before);

    // 6. Every account is back on one shard, with its balance.
    f.topology
        .verify_invariants()
        .expect("invariants after the merge");
    let accounts_after: BTreeSet<[u8; 32]> = f
        .topology
        .all_accounts()
        .iter()
        .map(|a| a.address)
        .collect();
    assert_eq!(accounts_after, accounts_before, "no account was lost");
    let expected_balances: std::collections::BTreeMap<[u8; 32], u64> = (0..N_ACCOUNTS)
        .map(|i| (synthetic_address(i), synthetic_balance(i)))
        .collect();
    for acct in f.topology.all_accounts() {
        assert_eq!(
            acct.balance, expected_balances[&acct.address],
            "the balance must be preserved"
        );
    }

    // 7. The trie merge is the INVERSE of the trie split.
    let merge_migration = TrieMigration::new(merge.plan.clone(), f.manifest.clone());
    let parent = merge_migration
        .execute_merge(&child0, &child1)
        .expect("the trie merge runs");
    merge_migration
        .verify_merge(&parent, &child0, &child1)
        .expect("the trie merge verifies");
    let merged = leaves(&[&parent]);
    assert_eq!(merged.len() as u64, N_ACCOUNTS, "no account was lost");

    // 8. The topology is a FIXED POINT now: no further transition fires
    //    without new load.
    assert!(f.topology.check_and_split(merge.parent.shard_id).is_none());
    assert!(f
        .topology
        .check_and_merge(merge.parent.shard_id, c0.shard_id)
        .is_none());
}

#[test]
fn the_split_respects_the_published_cap_and_thresholds() {
    let mut f = fixture(N_ACCOUNTS);
    f.topology.record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD);

    // Split repeatedly until the cap stops it.
    let mut guard = 0;
    loop {
        let candidates: Vec<u32> = f
            .topology
            .shards()
            .map(|(id, _)| *id)
            .filter(|id| *id != MASTERCHAIN_SHARD)
            .collect();
        let mut progressed = false;
        for id in candidates {
            f.topology.record_tx_load(id, SHARD_SPLIT_LOAD_THRESHOLD);
            if f.topology.check_and_split(id).is_some() {
                progressed = true;
                break;
            }
        }
        if !progressed {
            break;
        }
        guard += 1;
        assert!(guard < 64, "the split loop must terminate");
        assert!(
            f.topology.shard_count() <= MAX_SHARDS,
            "the published shard cap must hold"
        );
    }
    assert_eq!(f.topology.shard_count(), MAX_SHARDS);

    // The account minimum is published and enforced.
    assert_eq!(MIN_ACCOUNTS_PER_SHARD, 100);
    let mut tiny = ShardTopology::new();
    tiny.register_account(synthetic_address(0), 1);
    tiny.record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD);
    assert!(
        tiny.check_and_split(1).is_none(),
        "a shard below the account minimum must not split"
    );
}

#[test]
fn an_unclassified_trie_key_aborts_the_migration() {
    // Fail closed: a trie key the manifest does not classify must abort the
    // migration rather than silently drop state.
    let stray = [0xAAu8; 32];
    let mut big = fixture(200);
    big.trie.insert(&stray, &[1, 2, 3]);
    big.topology.record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD);
    let split = big.topology.check_and_split(1).expect("split");
    let migration = TrieMigration::new(split.plan.clone(), big.manifest.clone());
    let err = migration
        .execute_split(&big.trie)
        .expect_err("the migration must abort on an unclassified key");
    assert!(
        matches!(
            err,
            stellereum::sharding::MigrationError::UnclassifiedKey(_)
        ),
        "unexpected error: {err:?}"
    );
}

async fn test_rpc_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "inf1:test_node".to_string(),
        chain_id: 5757,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

#[tokio::test]
async fn the_rpc_publishes_the_topology_and_the_thresholds() {
    let st = test_rpc_state().await;

    // `stell_getShards` carries the `sharding` section: the rule, the
    // thresholds and the rule parameters.
    let r = st.call("stell_getShards", json!({})).await;
    let sharding = r
        .get("sharding")
        .expect("the sharding section must be present");
    assert_eq!(sharding["rule_id"], json!("workchain-prefix-v1"));
    assert_eq!(sharding["min_accounts_per_shard"], json!(100));
    assert_eq!(sharding["max_shards"], json!(16));
    assert_eq!(sharding["split_load_threshold"], json!(500));
    assert_eq!(sharding["merge_load_threshold"], json!(50));
    assert_eq!(sharding["max_prefix_bits"], json!(60));
    assert_eq!(
        sharding["max_workchain_shard_space"],
        json!(1_152_921_504_606_846_976u64)
    );
    assert_eq!(sharding["masterchain_shard"], json!(0));
    assert_eq!(sharding["base_workchain_shard"], json!(1));
    assert_eq!(sharding["masterchain_address_form"], json!("-1:<addr>"));

    // `stell_getShardTopology` reports the live topology.
    let t = st.call("stell_getShardTopology", json!({})).await;
    assert_eq!(t["parameters"]["max_shards"], json!(16));
    let shards = t["shards"].as_array().expect("shards");
    assert_eq!(shards.len(), 2);
    assert_eq!(shards[0]["shard_id"], json!(0));
    assert_eq!(shards[0]["shard_type"], json!("masterchain"));
    assert_eq!(shards[1]["shard_id"], json!(1));
    assert_eq!(shards[1]["shard_type"], json!("workchain"));
    assert_eq!(shards[1]["prefix_len"], json!(0));
}

#[tokio::test]
async fn run_get_method_reports_the_shard_the_same_rule_resolves() {
    let st = test_rpc_state().await;

    // Split the node's topology so the rule has something to say.
    {
        let mut topology = st.engine.shard_topology_mut().await;
        for i in 0..1_000u64 {
            topology.register_account(synthetic_address(i), synthetic_balance(i));
        }
        topology.record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD + 1);
        topology.check_and_split(1).expect("split");
    }

    let expected: Vec<(String, u32)> = {
        let topology = st.engine.shard_topology().await;
        (0..50u64)
            .map(|i| {
                let addr = synthetic_address(i);
                (
                    hex::encode(addr),
                    route_shard(&topology, &ShardAddress::Workchain(addr)),
                )
            })
            .collect()
    };
    for (addr_hex, expected_shard) in expected {
        let r = st
            .call(
                "stell_runGetMethod",
                json!({"address": addr_hex, "method": "get"}),
            )
            .await;
        assert_eq!(
            r["shard"].as_u64().expect("the shard must be reported") as u32,
            expected_shard,
            "runGetMethod must report the shard the rule resolves"
        );
        assert!(r["shard_is_local"].is_boolean());
    }

    // The masterchain form names the masterchain explicitly.
    let r = st
        .call(
            "stell_runGetMethod",
            json!({"address": format!("-1:{}", hex::encode(synthetic_address(0))), "method": "get"}),
        )
        .await;
    assert_eq!(
        r["shard"].as_u64(),
        Some(0),
        "the -1: form is the masterchain"
    );
}

#[tokio::test]
async fn the_rpc_routing_rule_is_the_one_the_topology_uses() {
    let st = test_rpc_state().await;

    // Split the node's topology so the routing rule has something to say.
    {
        let mut topology = st.engine.shard_topology_mut().await;
        for i in 0..1_000u64 {
            topology.register_account(synthetic_address(i), synthetic_balance(i));
        }
        topology.record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD + 1);
        let split = topology.check_and_split(1).expect("split");
        assert_eq!(split.children.len(), 2);
    }

    // The rule the RPC applies must agree with the rule the topology
    // applies — one source of truth.
    let topology = st.engine.shard_topology().await;
    let mut expected = std::collections::HashMap::new();
    for i in 0..1_000u64 {
        let addr = synthetic_address(i);
        expected.insert(addr, route_shard(&topology, &ShardAddress::Workchain(addr)));
    }
    drop(topology);

    // PROOF (audit-repro root cause, not a routing change): the routing rule
    // itself is unchanged — `resolve_shard_for_address` (rpc.rs:2623) still
    // calls `route_shard` (sharding.rs:2318), the single source of truth.
    // What changed is intentional DoS hardening in f0b641d (rpc.rs:5727-5737
    // + rpc.rs:1150-1167): in-process `RpcState::call` (`peer_ip=None`) no
    // longer bypasses the `stell_estimateFee` 5/s per-IP budget
    // (`ESTIMATE_FEE_RATE_LIMIT_DEFAULT`, rpc.rs:1133) and instead draws from
    // the shared `LOCAL_BUCKET_IP` bucket — the old `if let Some(ip)` skip
    // was an audit-residual bypass (cloning whole state per estimate). So 200
    // rapid in-process estimates now correctly hit "budget exhausted". Sample
    // 5 (== budget) RPC calls; the full 1000-address rule agreement is still
    // computed above, and 0..5 covers both split children.
    for i in 0..5u64 {
        let addr = synthetic_address(i);
        let r = st
            .call(
                "stell_estimateFee",
                json!({
                    "from": hex::encode(synthetic_address(9_999)),
                    "to": hex::encode(addr),
                    "amount": 1,
                }),
            )
            .await;
        assert!(r.get("error").is_none(), "estimate failed: {r}");
        // The fee response names the target shard it simulated for.
        let shard = r["target_shard"].as_u64().expect("target_shard");
        assert_eq!(shard as u32, expected[&addr], "the rule must agree");
    }
}
