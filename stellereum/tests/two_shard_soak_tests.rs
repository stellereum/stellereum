//! Bounded two-shard soak for the FIXED public pair (`{0,1}`).
//!
//! Runs a fixed number of heights (`SOAK_HEIGHTS = 40`) on BOTH shards of the
//! supported public configuration, in TWO independently built clusters, and
//! asserts:
//!   * the two clusters reach byte-identical state roots on shard 0 and shard 1
//!     at every checkpoint and at the end (determinism);
//!   * both shards finalize every driven height (no stalled chain);
//!   * each cross-shard transfer is produced once and consumed once on the
//!     other shard — zero cross-shard divergence;
//!   * native supply is conserved end to end.
//!
//! Bounded runtime: no live network, no sleeps, no timers; the test asserts its
//! own wall-clock stays under 60 s. Honest limit: in-process `ShardedCluster`
//! harness, not a multi-process live soak.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
use stellereum::network::CrossShardTransport;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::rpc::sign_pq_explicit_transfer;
use stellereum::runtime::{Cluster, ShardedCluster};
use stellereum::sharding::{
    Block, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
    PUBLIC_SHARD_PAIR,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

/// Bounded soak length: 40 heights on EACH shard (80 consensus rounds).
const SOAK_HEIGHTS: u64 = 40;
/// Root checkpoints (heights divisible by this also cross-check the pair).
const CHECKPOINT_EVERY: u64 = 10;
/// Declared gas for an explicit PQ transfer (the fixed-pair test fixture value).
const GAS_LIMIT: u64 = 50 + PQ_ACTIVATION_SURCHARGE_GAS;
const INITIAL_BALANCE: u64 = 5_000_000;

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

fn fixed_pair_registry() -> ShardRegistry {
    ShardRegistry::from_ids(PUBLIC_SHARD_PAIR.iter().copied())
}

/// One validator per shard: the soak measures cross-shard determinism over many
/// heights, not quorum breadth (covered by `shard2_n3_soak_tests`).
async fn two_shard_cluster(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    async fn funded_engine(funding: &[([u8; 32], u64)]) -> Arc<InMemoryStateEngine> {
        let engine = Arc::new(InMemoryStateEngine::new());
        for (addr, balance) in funding {
            engine
                .update_account(AccountState::new(*addr, *balance))
                .await;
        }
        engine
    }
    // Every shard runs a full validator set regardless of how many accounts it
    // is funded with; each node gets its OWN engine from that shard's genesis.
    let nodes0 = vec![(validator.clone(), funded_engine(shard0_funding).await)];
    let nodes1 = vec![(validator.clone(), funded_engine(shard1_funding).await)];
    ShardedCluster::new(
        fixed_pair_registry(),
        vec![(SHARD0, nodes0), (SHARD1, nodes1)],
        CrossShardTransport::local(),
    )
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

/// `(height, shard0 root, shard1 root)` checkpoints taken while driving.
type Trace = Vec<(u64, [u8; 32], [u8; 32])>;

/// Clear the previous height's decision QC before the next proposal.
///
/// `last_qc` (canonical downtime evidence) is OPTIONAL: the runtime accepts
/// `None`, which is exactly the shape a genesis child or a freshly restored
/// node proposes. It is dropped here because a QC carries Falcon-512 vote
/// signatures, and Falcon signing is randomized (FIPS 206): two
/// independently built clusters would embed different signature BYTES in
/// their block hashes even for identical state, and the cross-shard replay
/// keys name block hashes. Dropping the optional QC makes block identity a
/// pure function of state, which is what the cross-cluster determinism
/// assertion measures.
fn drop_parent_qc(sc: &mut ShardedCluster) {
    for cluster in sc.shards.values_mut() {
        for node in &mut cluster.nodes {
            node.last_decision = None;
        }
    }
}

/// Drive both shards from height 1 to `SOAK_HEIGHTS`, seeding the scheduled
/// transfers at their fixed heights. Returns the root checkpoints.
async fn drive_soak(sc: &mut ShardedCluster, transfers: &[(u64, Transaction)]) -> Trace {
    let mut trace = Vec::new();
    let mut ts = 11_000_000u64;
    for height in 1..=SOAK_HEIGHTS {
        for (at, tx) in transfers {
            if *at == height {
                sc.broadcast_tx(tx.clone()).await;
            }
        }
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        drop_parent_qc(sc);
        ts += 1;
        sc.run_height(SHARD1, ts).await;
        drop_parent_qc(sc);
        if height % CHECKPOINT_EVERY == 0 {
            trace.push((
                height,
                sc.shard(SHARD0).nodes[0].state_root().await,
                sc.shard(SHARD1).nodes[0].state_root().await,
            ));
        }
    }
    trace
}

fn produced_outbound(c: &Cluster, tx_hash: &[u8; 32]) -> usize {
    finalized_blocks(c)
        .iter()
        .flat_map(|b| b.cross_shard_out.iter())
        .filter(|m| m.is_outbound_for(SHARD0) && m.tx.compute_tx_hash() == *tx_hash)
        .count()
}

fn consumed_inbound(c: &Cluster, tx_hash: &[u8; 32]) -> usize {
    finalized_blocks(c)
        .iter()
        .flat_map(|b| b.cross_shard_out.iter())
        .filter(|m| m.is_inbound_for(SHARD1) && m.tx.compute_tx_hash() == *tx_hash)
        .count()
}

#[tokio::test]
async fn fixed_pair_soak_is_deterministic_and_never_diverges() {
    let started = Instant::now();
    let validator = key(0x71);

    // Two independent senders (each's first transfer is a PQ activation, so the
    // fee is the documented `GAS_LIMIT + SURCHARGE`) and one recipient.
    let (sender_a, addr_a) = pq_sender(0x72);
    let (sender_b, addr_b) = pq_sender(0x73);
    let recipient = id_of(&key(0x74));
    let amounts = [1_000u64, 2_500u64];

    // Mint each transaction ONCE and clone it into both clusters: Falcon-512
    // signing is randomized, so independently minted transactions would differ
    // in signature bytes (hence tx hash) and the two runs would not be the same
    // inputs.
    let transfer_a = sign_pq_explicit_transfer(
        &sender_a, recipient, amounts[0], GAS_LIMIT, 0, SHARD0, SHARD1,
    );
    let transfer_b = sign_pq_explicit_transfer(
        &sender_b, recipient, amounts[1], GAS_LIMIT, 0, SHARD0, SHARD1,
    );
    let transfers = [(5u64, transfer_a.clone()), (25u64, transfer_b.clone())];

    let funding = [(addr_a, INITIAL_BALANCE), (addr_b, INITIAL_BALANCE)];

    // Cluster A, then an INDEPENDENTLY built cluster B with the same genesis.
    let mut cluster_a = two_shard_cluster(&validator, &funding, &[]).await;
    let mut cluster_b = two_shard_cluster(&validator, &funding, &[]).await;
    assert_eq!(cluster_a.registry, fixed_pair_registry());
    assert_eq!(cluster_b.registry, fixed_pair_registry());

    let supply_before = balance_at(&cluster_a, SHARD0, &addr_a).await
        + balance_at(&cluster_a, SHARD0, &addr_b).await
        + balance_at(&cluster_a, SHARD1, &recipient).await;

    let trace_a = drive_soak(&mut cluster_a, &transfers).await;
    let trace_b = drive_soak(&mut cluster_b, &transfers).await;

    // Determinism: every checkpoint root matches between independent clusters.
    assert_eq!(
        trace_a.len(),
        (SOAK_HEIGHTS / CHECKPOINT_EVERY) as usize,
        "every checkpoint must be recorded"
    );
    for (ca, cb) in trace_a.iter().zip(trace_b.iter()) {
        assert_eq!(ca.0, cb.0, "checkpoint heights must line up");
        assert_eq!(
            ca.1, cb.1,
            "shard0 root diverged between independent clusters at height {}",
            ca.0
        );
        assert_eq!(
            ca.2, cb.2,
            "shard1 root diverged between independent clusters at height {}",
            ca.0
        );
    }
    let (head_a, head_b) = (
        (
            trace_a.last().expect("trace").1,
            trace_a.last().expect("trace").2,
        ),
        (
            trace_b.last().expect("trace").1,
            trace_b.last().expect("trace").2,
        ),
    );
    assert_eq!(head_a, head_b, "final roots must be byte-identical");

    // Both shards finalized every driven height in both clusters.
    for cluster in [&cluster_a, &cluster_b] {
        for shard in [SHARD0, SHARD1] {
            assert_eq!(
                cluster.shard(shard).nodes[0].finalized.len(),
                SOAK_HEIGHTS as usize,
                "shard{shard} must finalize every soaked height"
            );
            assert_eq!(
                cluster.shard(shard).height(),
                SOAK_HEIGHTS + 1,
                "shard{shard} consensus height must advance by exactly {SOAK_HEIGHTS}"
            );
        }
    }

    // Zero cross-shard divergence: each transfer produced once, consumed once,
    // in BOTH clusters.
    for tx in [&transfer_a, &transfer_b] {
        let tx_hash = tx.compute_tx_hash();
        for cluster in [&cluster_a, &cluster_b] {
            assert_eq!(
                produced_outbound(cluster.shard(SHARD0), &tx_hash),
                1,
                "the source must emit the transfer exactly once"
            );
            assert_eq!(
                consumed_inbound(cluster.shard(SHARD1), &tx_hash),
                1,
                "the target must consume the transfer exactly once"
            );
        }
    }

    // Value: every credit landed exactly once and nothing was minted or burned.
    let credited = amounts.iter().sum::<u64>();
    for cluster in [&cluster_a, &cluster_b] {
        assert_eq!(
            balance_at(cluster, SHARD1, &recipient).await,
            credited,
            "the recipient must be credited exactly the transferred amounts"
        );
        for (addr, amount) in [(&addr_a, amounts[0]), (&addr_b, amounts[1])] {
            assert_eq!(
                balance_at(cluster, SHARD0, addr).await,
                INITIAL_BALANCE - amount - GAS_LIMIT - PQ_ACTIVATION_SURCHARGE_GAS,
                "the source must be debited exactly once (amount + fee)"
            );
        }
    }
    let supply_after = balance_at(&cluster_a, SHARD0, &addr_a).await
        + balance_at(&cluster_a, SHARD0, &addr_b).await
        + balance_at(&cluster_a, SHARD1, &recipient).await;
    // Fees are the only thing that leaves the watched balances: the transferred
    // AMOUNTS are conserved across the shard boundary, and the burn is exactly
    // the deterministic per-transfer fee on both clusters.
    let burned_fees = 2 * (GAS_LIMIT + PQ_ACTIVATION_SURCHARGE_GAS);
    assert_eq!(
        supply_before - supply_after,
        burned_fees,
        "the transferred value must be conserved (only the deterministic fees burn)"
    );

    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "bounded soak must finish in < 60 s, took {elapsed:?}"
    );
    eprintln!(
        "fixed-pair soak: {SOAK_HEIGHTS} heights/shard, 2 independent clusters, \
         final roots shard0={} shard1={}, recipient={credited}, elapsed={:.2}s",
        hex::encode(&head_a.0[..8]),
        hex::encode(&head_a.1[..8]),
        elapsed.as_secs_f64(),
    );
}
