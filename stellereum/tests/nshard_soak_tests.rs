//! N-shard enablement soak: 3 shards finalize + interoperate, 4 shards boot,
//! invalid configs refused (NEW FILE ONLY — no existing file modified).
//!
//! Proves the config-driven N-shard path end to end in-process, using only the
//! existing harness (`Cluster::new_sharded` helpers, `ShardedCluster`,
//! `CrossShardTransport::local`, M2 transfer idiom):
//!  1. `ShardRegistry::parse_list` accepts N shards from `STELL_SHARDS`
//!     (unique/sorted, master 0 present, cap N<=16, fail-closed errors).
//!  2. The boot guard allows the CONFIGURED set behind the hatch (not just
//!     any set: invalid registries are refused even with the hatch), while
//!     the default `{0}` still boots unchanged.
//!  3. N=3: all three shards finalize; transfers across directed pairs
//!     (0->1, 1->2, 0->2) debit/credit exactly with supply conserved.
//!  4. N=4: all four shards boot, finalize, and publish workchain heads.
//!
//! Deterministic: fixed keys, fixed heights, fixed amounts. Single validator
//! per shard (quorum dynamics of N=3+ per shard are covered by
//! `shard2_n3_soak_tests`, not repeated here).

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::{Cluster, ShardedCluster};
use stellereum::sharding::{
    check_workchain_boot_guard_with_hatch, ShardRegistry, Transaction, MASTERCHAIN_SHARD,
    MAX_SHARDS, WORKCHAIN_FREEZE_DOC,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = 1;
const SHARD2: u32 = 2;
const SHARD3: u32 = 3;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// N single-validator shards sharing one node-local cross-shard transport
/// (the M2 idiom). Funding is per shard: `funding[i]` funds shard `i`.
async fn sharded_n(
    validator: &SigningKey,
    shards: &[u32],
    funding: &[Vec<([u8; 32], u64)>],
) -> ShardedCluster {
    assert_eq!(
        shards.len(),
        funding.len(),
        "one funding list per configured shard"
    );
    let registry = ShardRegistry::from_ids(shards.iter().copied());
    assert_eq!(
        registry.len(),
        shards.len(),
        "configured shards must be unique"
    );
    let mut entries = Vec::new();
    for (shard, fund) in shards.iter().zip(funding.iter()) {
        let engine = Arc::new(InMemoryStateEngine::new());
        for (addr, bal) in fund {
            engine.update_account(AccountState::new(*addr, *bal)).await;
        }
        entries.push((*shard, vec![(validator.clone(), engine)]));
    }
    ShardedCluster::new(registry, entries, CrossShardTransport::local())
}

async fn balance_at(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    sc.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

fn finalized_len(c: &Cluster) -> usize {
    c.nodes[0].finalized.len()
}

// ---------------------------------------------------------------------------
// (1) Config validation: parse_list accepts N, refuses the invalid.
// ---------------------------------------------------------------------------

#[test]
fn nshard_parse_accepts_n_shards_sorted_unique() {
    let r = ShardRegistry::parse_list("0,1,2").expect("valid N=3 list must parse");
    assert!(r.is_sharded());
    assert_eq!(r.ids().collect::<Vec<_>>(), vec![0, 1, 2]);
    // Whitespace tolerated, order normalized ascending.
    let r = ShardRegistry::parse_list(" 2, 0,1 ").expect("valid list must parse");
    assert_eq!(r.ids().collect::<Vec<_>>(), vec![0, 1, 2]);
    // Full cap parses.
    let full = (0..MAX_SHARDS as u32)
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let r = ShardRegistry::parse_list(&full).expect("cap-sized list must parse");
    assert_eq!(r.len(), MAX_SHARDS);
    // Single canonical still parses.
    assert_eq!(
        ShardRegistry::parse_list("0").expect("single must parse"),
        ShardRegistry::single()
    );
}

#[test]
fn nshard_parse_refuses_invalid_fail_closed() {
    // Duplicate id.
    let e = ShardRegistry::parse_list("0,1,1").expect_err("dup id must be refused");
    assert!(e.contains("twice"), "dup error must name the cause: {e}");
    // Multi-shard without the masterchain.
    let e = ShardRegistry::parse_list("1,2").expect_err("missing master must be refused");
    assert!(
        e.contains(&MASTERCHAIN_SHARD.to_string()),
        "missing-master error must name shard 0: {e}"
    );
    // Over the cap.
    let over = (0..=MAX_SHARDS as u32)
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let e = ShardRegistry::parse_list(&over).expect_err("N>cap must be refused");
    assert!(e.contains(&MAX_SHARDS.to_string()), "cap error must name it: {e}");
    // Unparsable entry.
    let e = ShardRegistry::parse_list("0,abc").expect_err("bad id must be refused");
    assert!(e.contains("abc"), "bad-id error must name the entry: {e}");
    // Empty entry.
    assert!(ShardRegistry::parse_list("0,,1").is_err());
    assert!(ShardRegistry::parse_list("").is_err());
    assert!(ShardRegistry::parse_list("   ").is_err());
}

#[test]
fn nshard_guard_hatch_allows_configured_set_only() {
    let valid3 = ShardRegistry::parse_list("0,1,2").expect("valid");
    // Valid configured set: refused without hatch, allowed with it.
    let e = check_workchain_boot_guard_with_hatch(&valid3, false)
        .expect_err("multishard without hatch must refuse");
    assert!(e.contains(WORKCHAIN_FREEZE_DOC), "must name freeze doc: {e}");
    assert!(check_workchain_boot_guard_with_hatch(&valid3, true).is_ok());
    // INVALID set (multi-shard, no masterchain): refused EVEN with the hatch.
    let invalid = ShardRegistry::from_ids([1, 2]);
    assert!(invalid.is_sharded());
    assert!(check_workchain_boot_guard_with_hatch(&invalid, true).is_err());
    assert!(check_workchain_boot_guard_with_hatch(&invalid, false).is_err());
    // INVALID set (over the cap): refused EVEN with the hatch.
    let over = ShardRegistry::from_ids(0..=MAX_SHARDS as u32);
    assert!(check_workchain_boot_guard_with_hatch(&over, true).is_err());
    // Default {0} still boots unchanged either way.
    assert!(check_workchain_boot_guard_with_hatch(&ShardRegistry::single(), false).is_ok());
    assert!(check_workchain_boot_guard_with_hatch(&ShardRegistry::single(), true).is_ok());
}

// ---------------------------------------------------------------------------
// (3) N=3 soak: all finalize + transfers across pairs + conservation.
// ---------------------------------------------------------------------------

/// N=3: all three shards finalize every driven height; three transfers across
/// three directed pairs (0->1, 1->2, 0->2) each debit/credit exactly, and the
/// three-shard supply is conserved end to end.
#[tokio::test]
async fn nshard_3_all_finalize_and_xfer_across_pairs() {
    let validator = key(41);
    let sender0 = key(42);
    let sender1 = key(43);
    let recipient1 = key(44);
    let recipient2 = key(45);
    let validator_addr = id_of(&validator);
    let s0 = id_of(&sender0);
    let s1 = id_of(&sender1);
    let r1 = id_of(&recipient1);
    let r2 = id_of(&recipient2);

    let mut sc = sharded_n(
        &validator,
        &[SHARD0, SHARD1, SHARD2],
        &[vec![(s0, 1_000_000)], vec![(s1, 500_000)], vec![]],
    )
    .await;

    let mut ts = 100u64;
    // Warmup: every shard alive before any value moves.
    for _ in 0..3 {
        for shard in [SHARD0, SHARD1, SHARD2] {
            ts += 1;
            sc.run_height(shard, ts).await;
        }
    }
    // Gas is credited to the block proposer (the validator), so the
    // conservation view must include the validator on every shard.
    let supply_before = balance_at(&sc, SHARD0, &s0).await
        + balance_at(&sc, SHARD0, &validator_addr).await
        + balance_at(&sc, SHARD1, &s1).await
        + balance_at(&sc, SHARD1, &validator_addr).await
        + balance_at(&sc, SHARD2, &validator_addr).await;

    // Pair 1: 0 -> 1.
    let tx_a = Transaction::sign(&sender0, r1, 10_000, 50, 0, SHARD0, SHARD1);
    sc.broadcast_tx(tx_a.clone()).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    assert!(
        sc.shard(SHARD0).nodes[0]
            .blocks
            .values()
            .flat_map(|b| b.cross_shard_out.iter())
            .any(|m| m.target_shard == SHARD1),
        "source shard0 must emit the 0->1 outbound message"
    );
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    assert_eq!(balance_at(&sc, SHARD1, &r1).await, 10_000);

    // Pair 2: 1 -> 2.
    let tx_b = Transaction::sign(&sender1, r2, 4_000, 20, 0, SHARD1, SHARD2);
    sc.broadcast_tx(tx_b.clone()).await;
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    assert!(
        sc.shard(SHARD1).nodes[0]
            .blocks
            .values()
            .flat_map(|b| b.cross_shard_out.iter())
            .any(|m| m.target_shard == SHARD2),
        "source shard1 must emit the 1->2 outbound message"
    );
    ts += 1;
    sc.run_height(SHARD2, ts).await;
    assert_eq!(balance_at(&sc, SHARD2, &r2).await, 4_000);

    // Pair 3: 0 -> 2 (second nonce on sender0).
    let tx_c = Transaction::sign(&sender0, r2, 5_000, 25, 1, SHARD0, SHARD2);
    sc.broadcast_tx(tx_c.clone()).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    assert!(
        sc.shard(SHARD0).nodes[0]
            .blocks
            .values()
            .flat_map(|b| b.cross_shard_out.iter())
            .any(|m| m.target_shard == SHARD2),
        "source shard0 must emit the 0->2 outbound message"
    );
    ts += 1;
    sc.run_height(SHARD2, ts).await;
    assert_eq!(balance_at(&sc, SHARD2, &r2).await, 9_000);

    // Post-transfer soak: all three shards keep finalizing.
    for _ in 0..3 {
        for shard in [SHARD0, SHARD1, SHARD2] {
            ts += 1;
            sc.run_height(shard, ts).await;
        }
    }

    let f0 = finalized_len(sc.shard(SHARD0));
    let f1 = finalized_len(sc.shard(SHARD1));
    let f2 = finalized_len(sc.shard(SHARD2));
    assert!(f0 >= 8 && f1 >= 8 && f2 >= 8, "every shard finalizes throughout");
    assert_eq!(sc.shard(SHARD0).height(), sc.shard(SHARD1).height());
    assert_eq!(sc.shard(SHARD1).height(), sc.shard(SHARD2).height());

    assert_eq!(
        balance_at(&sc, SHARD0, &s0).await,
        1_000_000 - (10_000 + 50) - (5_000 + 25),
        "sender0 debited both amounts + gas exactly"
    );
    assert_eq!(
        balance_at(&sc, SHARD1, &s1).await,
        500_000 - (4_000 + 20),
        "sender1 debited amount + gas exactly"
    );
    assert_eq!(balance_at(&sc, SHARD1, &r1).await, 10_000);
    assert_eq!(balance_at(&sc, SHARD2, &r2).await, 9_000);
    let supply_after = balance_at(&sc, SHARD0, &s0).await
        + balance_at(&sc, SHARD0, &validator_addr).await
        + balance_at(&sc, SHARD1, &s1).await
        + balance_at(&sc, SHARD1, &validator_addr).await
        + balance_at(&sc, SHARD1, &r1).await
        + balance_at(&sc, SHARD2, &r2).await
        + balance_at(&sc, SHARD2, &validator_addr).await;
    assert_eq!(
        supply_after, supply_before,
        "N=3 cross-pair transfers must conserve supply"
    );
    eprintln!(
        "N3 soak: finals0={f0} finals1={f1} finals2={f2} \
         supply_before={supply_before} supply_after={supply_after}"
    );
}

// ---------------------------------------------------------------------------
// (4) N=4 boot + heads.
// ---------------------------------------------------------------------------

/// N=4: every configured shard boots and finalizes, and the shared finalized
/// header registry publishes a head for every workchain (1, 2, 3) — the set
/// the masterchain commits via `collect_shard_header_commitments`.
#[tokio::test]
async fn nshard_4_boot_and_heads() {
    let validator = key(51);
    let mut sc = sharded_n(
        &validator,
        &[SHARD0, SHARD1, SHARD2, SHARD3],
        &[vec![], vec![], vec![], vec![]],
    )
    .await;

    let mut ts = 500u64;
    for _ in 0..4 {
        for shard in [SHARD0, SHARD1, SHARD2, SHARD3] {
            ts += 1;
            sc.run_height(shard, ts).await;
        }
    }
    for shard in [SHARD0, SHARD1, SHARD2, SHARD3] {
        assert_eq!(
            finalized_len(sc.shard(shard)),
            4,
            "shard{shard} must finalize every boot height"
        );
    }

    let reg = sc.shard(SHARD0).nodes[0]
        .finalized_headers
        .as_ref()
        .expect("sharded cluster wires the shared header registry");
    let heads = reg.read().expect("registry readable").workchain_headers();
    let mut head_shards: Vec<u32> = heads.iter().map(|h| h.shard_id).collect();
    head_shards.sort_unstable();
    head_shards.dedup();
    assert_eq!(
        head_shards,
        vec![SHARD1, SHARD2, SHARD3],
        "registry must publish a head for every configured workchain"
    );
    eprintln!(
        "N4 boot: finals0={} finals1={} finals2={} finals3={} heads={head_shards:?}",
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
        finalized_len(sc.shard(SHARD2)),
        finalized_len(sc.shard(SHARD3)),
    );
}
