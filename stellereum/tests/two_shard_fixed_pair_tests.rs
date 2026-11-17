//! The FIXED public two-shard configuration (`{0,1}`), end to end.
//!
//! `PUBLIC_SHARD_PAIR` names the one MULTI-shard registry the public protocol
//! supports today: the masterchain (shard 0) plus the base workchain (shard 1).
//! It boots WITHOUT `STELL_EXPERIMENTAL_SHARDS`; every other set still needs
//! the hatch (pinned in `tests/workchain_guard_tests.rs` and in the
//! `boot_guard_tests` module of `src/sharding/topology.rs`).
//!
//! This file pins the two-shard pair as a SUPPORTED configuration, not an
//! experiment:
//!  1. the pair is accepted by the boot guard without the hatch, in any input
//!     order, while `{1}`, `{2}`, `{0,1,2}` and over-cap sets still refuse;
//!  2. both shards finalize blocks and the masterchain publishes/commits their
//!     shard heads (TON `shard_hashes`), binding them into its own block hash;
//!  3. one native cross-shard transfer debits the source and credits the target
//!     EXACTLY once, a replayed message cannot credit twice, and the source
//!     block's registry anchor resolves so the inbound message verifies;
//!  4. a restart-style re-application of the same finalized blocks reproduces
//!     byte-identical state roots on BOTH shards.
//!
//! Deterministic: fixed keys, fixed timestamps, fixed amounts, no sleeps.
//! Honest limit: this is the in-process harness (`ShardedCluster`), not a live
//! multi-process network; cross-shard transport is node-local.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
use stellereum::network::CrossShardTransport;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::rpc::sign_pq_explicit_transfer;
use stellereum::runtime::{ChainState, Cluster, ShardedCluster};
use stellereum::sharding::{
    check_workchain_boot_guard_with_hatch, is_public_shard_pair, Block, ShardRegistry,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD, MAX_SHARDS, PUBLIC_SHARD_PAIR,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const VALIDATORS_PER_SHARD: u8 = 2;
/// Declared gas for an explicit PQ transfer (the soak/faucet fixture value).
const GAS_LIMIT: u64 = 50 + PQ_ACTIVATION_SURCHARGE_GAS;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn pq_sender(seed: u8) -> (FalconKeypair, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed(seed);
    let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    (kp, addr)
}

/// The registry under test: the fixed public pair, built from the constant.
fn fixed_pair_registry() -> ShardRegistry {
    ShardRegistry::from_ids(PUBLIC_SHARD_PAIR.iter().copied())
}

async fn funded_engine(funding: &[([u8; 32], u64)]) -> Arc<InMemoryStateEngine> {
    let engine = Arc::new(InMemoryStateEngine::new());
    for (addr, balance) in funding {
        engine
            .update_account(AccountState::new(*addr, *balance))
            .await;
    }
    engine
}

/// Build a two-shard cluster under the FIXED pair registry. Every node gets
/// its OWN state engine; every member of a shard starts from the same funding
/// (identical genesis), exactly like `tests/shard2_n3_soak_tests.rs`.
async fn two_shard_cluster(
    validators: &[SigningKey],
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let mut shard0_nodes = Vec::new();
    for v in validators {
        shard0_nodes.push((v.clone(), funded_engine(shard0_funding).await));
    }
    let mut shard1_nodes = Vec::new();
    for v in validators {
        shard1_nodes.push((v.clone(), funded_engine(shard1_funding).await));
    }
    ShardedCluster::new(
        fixed_pair_registry(),
        vec![(SHARD0, shard0_nodes), (SHARD1, shard1_nodes)],
        CrossShardTransport::local(),
    )
}

fn validator_keys() -> Vec<SigningKey> {
    (0..VALIDATORS_PER_SHARD).map(|i| key(0x40 + i)).collect()
}

fn finalized_blocks(c: &Cluster) -> Vec<Block> {
    let node = &c.nodes[0];
    node.finalized
        .iter()
        .map(|(_, hash)| {
            node.blocks
                .get(hash)
                .expect("finalized block body retained")
                .clone()
        })
        .collect()
}

async fn balance_at(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    sc.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// Every member of the shard must hold the same root (same blocks applied).
async fn assert_shard_roots_agree(sc: &ShardedCluster, shard: u32) {
    let root = sc.shard(shard).nodes[0].state_root().await;
    for (i, node) in sc.shard(shard).nodes.iter().enumerate() {
        assert_eq!(
            node.state_root().await,
            root,
            "shard{shard} node{i} diverged from node0"
        );
    }
}

/// Total native balance across the accounts we watch on both shards.
async fn watched_supply(
    sc: &ShardedCluster,
    shard0_addrs: &[[u8; 32]],
    shard1_addrs: &[[u8; 32]],
) -> u64 {
    let mut total = 0u64;
    for a in shard0_addrs {
        total += balance_at(sc, SHARD0, a).await;
    }
    for a in shard1_addrs {
        total += balance_at(sc, SHARD1, a).await;
    }
    total
}

/// (1) The fixed pair is the ONLY hatch-free multi-shard registry, in any
/// order, and everything else keeps refusing.
#[test]
fn fixed_pair_is_the_only_hatch_free_boot_configuration() {
    // Order-independent: the BTreeSet backing canonicalises `1,0` to `0,1`.
    let ascending = fixed_pair_registry();
    let reversed = ShardRegistry::from_ids([SHARD1, SHARD0]);
    assert_eq!(ascending, reversed);
    assert_eq!(ascending.ids().collect::<Vec<_>>(), vec![SHARD0, SHARD1]);
    assert!(is_public_shard_pair(&ascending));
    assert!(is_public_shard_pair(&reversed));

    // The pair boots WITHOUT the hatch; the hatch does not change that.
    check_workchain_boot_guard_with_hatch(&ascending, false)
        .expect("the fixed public pair must boot without STELL_EXPERIMENTAL_SHARDS");
    check_workchain_boot_guard_with_hatch(&ascending, true).expect("pair boots with hatch too");

    // Everything else still needs the hatch; the message names the pair.
    let refused: &[&[u32]] = &[
        &[SHARD1],            // {1}
        &[2],                 // {2}
        &[SHARD0, 2],         // {0,2}
        &[SHARD0, SHARD1, 2], // {0,1,2}
    ];
    for ids in refused {
        let registry = ShardRegistry::from_ids(ids.iter().copied());
        assert!(
            !is_public_shard_pair(&registry),
            "{ids:?} must not match the fixed pair"
        );
        let err = check_workchain_boot_guard_with_hatch(&registry, false)
            .expect_err("only {0} and the fixed pair are hatch-free");
        assert!(err.contains("0,1"), "refusal must name the pair: {err}");
    }
    // A MALFORMED set is refused by `validate` before the freeze text (and is
    // refused even WITH the hatch): the masterchain rule is what it names.
    let no_masterchain = ShardRegistry::from_ids([SHARD1, 2]);
    let err = check_workchain_boot_guard_with_hatch(&no_masterchain, false)
        .expect_err("{1,2} has no masterchain");
    assert!(
        err.contains("without the masterchain") || err.contains("must include"),
        "malformed set must name the masterchain rule: {err}"
    );
    assert!(check_workchain_boot_guard_with_hatch(&no_masterchain, true).is_err());
    // Over the shard cap: refused even WITH the hatch, and never the pair.
    let over_cap = ShardRegistry::from_ids(0..=MAX_SHARDS as u32);
    assert!(check_workchain_boot_guard_with_hatch(&over_cap, false).is_err());
    assert!(check_workchain_boot_guard_with_hatch(&over_cap, true).is_err());
    assert!(!is_public_shard_pair(&over_cap));
}

/// (2) Both shards finalize blocks, and the masterchain's own block publishes
/// their heads and cryptographically commits to them.
#[tokio::test]
async fn both_shards_finalize_and_masterchain_commits_their_heads() {
    let validators = validator_keys();
    let mut sc = two_shard_cluster(&validators, &[], &[]).await;
    assert_eq!(sc.registry, fixed_pair_registry());

    // Shard 1 first, then the masterchain: the masterchain block at height H
    // commits to the workchain head finalized at height H.
    let mut ts = 7_000_000u64;
    for _ in 0..3 {
        ts += 1;
        sc.run_height(SHARD1, ts).await;
        ts += 1;
        sc.run_height(SHARD0, ts).await;
    }

    for shard in [SHARD0, SHARD1] {
        let finalized = &sc.shard(shard).nodes[0].finalized;
        assert_eq!(
            finalized.len(),
            3,
            "shard{shard} must finalize every driven height"
        );
        assert_eq!(
            finalized.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "shard{shard} heights must be contiguous"
        );
        assert_shard_roots_agree(&sc, shard).await;
    }

    let workchain = finalized_blocks(sc.shard(SHARD1))
        .pop()
        .expect("shard1 finalized blocks");
    let master = finalized_blocks(sc.shard(SHARD0))
        .pop()
        .expect("masterchain finalized blocks");

    assert_eq!(master.shard_id, SHARD0);
    assert!(
        master.shard_headers_canonical(),
        "the published shard-head set must be canonical"
    );
    let head = master
        .shard_head(SHARD1)
        .expect("the masterchain must publish the workchain shard head");
    assert_eq!(head.shard_id, SHARD1);
    assert_eq!(head.height, workchain.height);
    assert_eq!(
        head.block_hash,
        workchain.compute_hash(),
        "the committed shard head must name the finalized workchain block"
    );
    assert_eq!(
        head.state_root, workchain.state_root,
        "the committed shard head must carry the workchain root"
    );

    // The commitment is inside the block hash: dropping or tampering with the
    // head changes what the quorum signed.
    let mut without = master.clone();
    without.shard_headers.clear();
    assert_ne!(
        master.compute_hash(),
        without.compute_hash(),
        "the shard-head commitment must be bound into the masterchain block hash"
    );

    // A workchain block never publishes shard heads (it commits to its own
    // body only).
    assert!(
        workchain.shard_headers.is_empty(),
        "a workchain block must not publish shard heads"
    );
}

/// (3) One native cross-shard transfer: exact debit, exactly-once credit, a
/// replay that cannot credit twice, and a resolvable source anchor.
#[tokio::test]
async fn native_transfer_credits_once_and_source_anchor_verifies() {
    let validators = validator_keys();
    let (sender, sender_addr) = pq_sender(0x51);
    let recipient_addr = id_of(&key(0x52));
    let initial = 1_000_000u64;
    let amount = 10_000u64;

    let mut sc = two_shard_cluster(&validators, &[(sender_addr, initial)], &[]).await;
    let mut ts = 8_000_000u64;
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    assert_eq!(balance_at(&sc, SHARD0, &sender_addr).await, initial);
    assert_eq!(balance_at(&sc, SHARD1, &recipient_addr).await, 0);

    // Produce the transfer on the source shard.
    let tx = sign_pq_explicit_transfer(
        &sender,
        recipient_addr,
        amount,
        GAS_LIMIT,
        0,
        SHARD0,
        SHARD1,
    );
    let tx_hash = tx.compute_tx_hash();
    sc.broadcast_tx(tx.clone()).await;
    ts += 1;
    let source_hash = sc.run_height(SHARD0, ts).await;
    let source_block = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&source_hash)
        .expect("source block retained")
        .clone();
    assert_eq!(
        source_block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_outbound_for(SHARD0))
            .count(),
        1,
        "the source must emit exactly one outbound message"
    );
    assert_eq!(
        balance_at(&sc, SHARD0, &sender_addr).await,
        initial - amount - GAS_LIMIT - PQ_ACTIVATION_SURCHARGE_GAS,
        "the source must be debited exactly once"
    );

    // Consume it on the target shard.
    ts += 1;
    let target_hash = sc.run_height(SHARD1, ts).await;
    let target_block = sc.shard(SHARD1).nodes[0]
        .blocks
        .get(&target_hash)
        .expect("target block retained")
        .clone();
    let inbound = target_block
        .cross_shard_out
        .iter()
        .find(|m| m.is_inbound_for(SHARD1))
        .expect("the target block must commit the consumption record")
        .clone();
    assert_eq!(inbound.tx.compute_tx_hash(), tx_hash);
    assert_eq!(balance_at(&sc, SHARD1, &recipient_addr).await, amount);

    // The registry anchor for the source block (the block the message names)
    // must resolve to the very root the message carries, so an inbound message
    // verifies strictly.
    let registry_handle = sc.shard(SHARD1).nodes[0]
        .finalized_headers
        .as_ref()
        .expect("the fixture wires the finalized-header registry")
        .clone();
    let anchor = {
        let reg = registry_handle.read().expect("registry lock");
        reg.lookup(SHARD0, &inbound.finalized_in_block)
    };
    assert_eq!(
        anchor,
        Some(inbound.source_state_root),
        "the source block's registry anchor must resolve to the message root"
    );
    assert_eq!(
        inbound.finalized_in_block, source_block.prev_hash,
        "the message names its source block (the parent of the producing block)"
    );
    assert!(
        sc.shard(SHARD1).nodes[0].verify_cross_shard_anchored(&inbound),
        "an anchored inbound message must verify against the finalized source header"
    );

    let watched0 = [sender_addr];
    let watched1 = [recipient_addr];
    let supply_before = watched_supply(&sc, &watched0, &watched1).await;

    // Replay attack: re-seed the same transaction on the source and re-publish
    // the consumed message on the target, twice each.
    sc.broadcast_tx(tx.clone()).await;
    sc.broadcast_tx(tx.clone()).await;
    for _ in 0..2 {
        sc.transport
            .broadcast_cross_shard(&inbound)
            .await
            .expect("node-local re-broadcast must succeed");
    }
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }

    // Exactly-once: no second debit, no second credit, supply conserved.
    assert_eq!(
        balance_at(&sc, SHARD0, &sender_addr).await,
        initial - amount - GAS_LIMIT - PQ_ACTIVATION_SURCHARGE_GAS,
        "a replayed message must not debit the source twice"
    );
    assert_eq!(
        balance_at(&sc, SHARD1, &recipient_addr).await,
        amount,
        "a replayed message must not credit the target twice"
    );
    assert_eq!(
        watched_supply(&sc, &watched0, &watched1).await,
        supply_before,
        "replay must not mint or burn value"
    );

    // Exactly one committed consumption record for this transaction across the
    // whole finalized target chain.
    let committed = finalized_blocks(sc.shard(SHARD1))
        .iter()
        .flat_map(|b| b.cross_shard_out.iter())
        .filter(|m| m.is_inbound_for(SHARD1) && m.tx.compute_tx_hash() == tx_hash)
        .count();
    assert_eq!(committed, 1, "exactly one consumption record must commit");

    for shard in [SHARD0, SHARD1] {
        assert_shard_roots_agree(&sc, shard).await;
    }
}

/// (4) Restart-style re-application: replaying the SAME finalized blocks into a
/// fresh engine, block by block, reproduces byte-identical state roots on both
/// shards.
#[tokio::test]
async fn restart_replay_reproduces_identical_roots_on_both_shards() {
    let validators = validator_keys();
    let (sender, sender_addr) = pq_sender(0x61);
    let recipient_addr = id_of(&key(0x62));
    let initial = 750_000u64;
    let amount = 12_345u64;

    let mut sc = two_shard_cluster(&validators, &[(sender_addr, initial)], &[]).await;
    let mut ts = 9_000_000u64;
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }

    let tx = sign_pq_explicit_transfer(
        &sender,
        recipient_addr,
        amount,
        GAS_LIMIT,
        0,
        SHARD0,
        SHARD1,
    );
    sc.broadcast_tx(tx).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    ts += 1;
    sc.run_height(SHARD1, ts).await;

    // Soak a few more heights so the replay covers state after the credit too.
    for _ in 0..3 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }

    // Live roots to reproduce.
    let live0 = sc.shard(SHARD0).nodes[0].state_root().await;
    let live1 = sc.shard(SHARD1).nodes[0].state_root().await;

    // Replay shard 0 into a fresh engine funded with the same genesis. The
    // engine must run the same SHARDED configuration: cross-shard execution on
    // (so an outbound transfer is a debit, not a local credit) and the C1
    // anchor registry hydrated from the live node's finalized headers (what a
    // real restart restores from its store before it applies anything).
    let replay0 = Arc::new(InMemoryStateEngine::new());
    replay0.enable_cross_shard();
    replay0
        .update_account(AccountState::new(sender_addr, initial))
        .await;
    let anchors = sc.shard(SHARD1).nodes[0]
        .finalized_headers
        .clone()
        .expect("the fixture wires the finalized-header registry");
    let mut chain0 = ChainState::new(replay0.clone());
    for block in finalized_blocks(sc.shard(SHARD0)) {
        chain0.apply_block(&block).await;
    }
    assert_eq!(
        replay0.get_state_root().await,
        live0,
        "shard0 restart replay must reproduce the live state root"
    );

    // Replay shard 1 into a fresh engine funded with the same (empty) genesis,
    // with the same sharded configuration and hydrated anchors so the inbound
    // credit is re-derived exactly as the live node derived it.
    let replay1 = Arc::new(InMemoryStateEngine::new());
    replay1.enable_cross_shard();
    replay1.with_finalized_headers(anchors);
    let mut chain1 = ChainState::new(replay1.clone());
    for block in finalized_blocks(sc.shard(SHARD1)) {
        chain1.apply_block(&block).await;
    }
    assert_eq!(
        replay1.get_state_root().await,
        live1,
        "shard1 restart replay must reproduce the live state root"
    );

    // The replay also reproduces the balances (not just the root).
    let sender_replayed = replay0
        .get_account(&sender_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(
        sender_replayed,
        balance_at(&sc, SHARD0, &sender_addr).await,
        "replay must reproduce the source balance"
    );
    let recipient_replayed = replay1
        .get_account(&recipient_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(
        recipient_replayed, amount,
        "replay must reproduce the credited target balance"
    );

    // Both shards' members already agree; the replay agrees with all of them.
    for shard in [SHARD0, SHARD1] {
        assert_shard_roots_agree(&sc, shard).await;
    }
}
