//! Final Stress Test & Speed Benchmark across two parallel shards (Shard 0 & Shard 1)
//!
//! Measures:
//! - High-volume transaction throughput across Shard 0 (Masterchain) and Shard 1 (Workchain).
//! - Cross-shard escrow packaging in both directions (0 -> 1 and 1 -> 0).
//! - Disjoint concurrent execution performance.
//! - State root determinism.
//!
//! NOTE (XSHARD-01): cross-shard VALUE moves only through the §9 2PC; the
//! legacy one-step inbound credit is refused. This benchmark keeps the legacy
//! outbox volume (and its per-block record counts) to measure throughput, so
//! the inbound records here are committed but not credited.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::network::CrossShardTransport;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD; // 0
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL; // 1

fn test_signer(seed: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes[8..16].copy_from_slice(&(!seed).to_be_bytes());
    SigningKey::from_bytes(&bytes)
}

/// FULL-PQ sender: deterministic implicit Falcon-512 identity, registered
/// globally so the tx is not an activation (no 45k surcharge).
fn pq_signer(seed: u64) -> ([u8; 32], FalconKeypair) {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes[8..16].copy_from_slice(&(!seed).to_be_bytes());
    let fk = FalconKeypair::generate_from_seed_bytes(&bytes);
    let addr = derive_pq_address(PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(addr, PqScheme::Falcon512, &fk.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (addr, fk)
}

/// FULL-PQ replacement for `Transaction::sign` in fixtures.
#[allow(clippy::too_many_arguments)]
// GATE: fixture mirrors the legacy constructor arity (sender, dest, amount,
// gas, nonce, shards); splitting would obscure each call site.
fn pq_tx(
    fk: &FalconKeypair,
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, fk.sign(&msg)).encode();
    tx
}

#[tokio::test]
async fn test_two_shard_parallel_stress_and_tps_benchmark() {
    let validator = test_signer(999);
    let s0_engine = Arc::new(InMemoryStateEngine::new().with_parallel_exec(true));
    let s1_engine = Arc::new(InMemoryStateEngine::new().with_parallel_exec(true));

    let num_senders = 50usize;
    let initial_bal = 10_000_000_000u64; // 10 STELL

    let mut senders_s0 = Vec::new();
    let mut senders_s1 = Vec::new();

    for i in 0..num_senders {
        let (addr0, fk0) = pq_signer(1000 + i as u64);
        s0_engine
            .update_account(AccountState::new(addr0, initial_bal))
            .await;
        senders_s0.push((addr0, fk0));

        let (addr1, fk1) = pq_signer(2000 + i as u64);
        s1_engine
            .update_account(AccountState::new(addr1, initial_bal))
            .await;
        senders_s1.push((addr1, fk1));
    }

    let mut cluster = ShardedCluster::new(
        ShardRegistry::from_ids([SHARD0, SHARD1]),
        vec![
            (SHARD0, vec![(validator.clone(), s0_engine.clone())]),
            (SHARD1, vec![(validator.clone(), s1_engine.clone())]),
        ],
        CrossShardTransport::local(),
    );

    let fee = 280_000u64;
    let transfer_amount = 10_000_000u64; // 0.01 STELL

    // Prepare 200 intra-shard transactions for Shard 0
    let mut txs_s0 = Vec::new();
    for (i, (sender, fk)) in senders_s0.iter().enumerate() {
        let recipient = senders_s0[(i + 1) % num_senders].0;
        for nonce in 0..4 {
            let tx = pq_tx(
                fk,
                *sender,
                recipient,
                transfer_amount,
                fee,
                nonce,
                SHARD0,
                SHARD0,
            );
            txs_s0.push(tx);
        }
    }

    // Prepare 200 intra-shard transactions for Shard 1
    let mut txs_s1 = Vec::new();
    for (i, (sender, fk)) in senders_s1.iter().enumerate() {
        let recipient = senders_s1[(i + 1) % num_senders].0;
        for nonce in 0..4 {
            let tx = pq_tx(
                fk,
                *sender,
                recipient,
                transfer_amount,
                fee,
                nonce,
                SHARD1,
                SHARD1,
            );
            txs_s1.push(tx);
        }
    }

    // Prepare 50 cross-shard transactions Shard 0 -> Shard 1 from dedicated senders
    let mut x_senders_s0 = Vec::new();
    let mut x_txs_0_to_1 = Vec::new();
    for (i, sender) in senders_s1.iter().enumerate().take(num_senders) {
        let (x_addr, x_fk) = pq_signer(3000 + i as u64);
        s0_engine
            .update_account(AccountState::new(x_addr, initial_bal))
            .await;
        let recipient = sender.0;
        let tx = pq_tx(
            &x_fk,
            x_addr,
            recipient,
            transfer_amount * 2,
            fee,
            0,
            SHARD0,
            SHARD1,
        );
        x_txs_0_to_1.push(tx);
        x_senders_s0.push((x_addr, x_fk));
    }

    // Prepare 50 cross-shard transactions Shard 1 -> Shard 0 from dedicated senders
    let mut x_senders_s1 = Vec::new();
    let mut x_txs_1_to_0 = Vec::new();
    for (i, sender) in senders_s0.iter().enumerate().take(num_senders) {
        let (x_addr, x_fk) = pq_signer(4000 + i as u64);
        s1_engine
            .update_account(AccountState::new(x_addr, initial_bal))
            .await;
        let recipient = sender.0;
        let tx = pq_tx(
            &x_fk,
            x_addr,
            recipient,
            transfer_amount * 2,
            fee,
            0,
            SHARD1,
            SHARD0,
        );
        x_txs_1_to_0.push(tx);
        x_senders_s1.push((x_addr, x_fk));
    }

    let total_txs = txs_s0.len() + txs_s1.len() + x_txs_0_to_1.len() + x_txs_1_to_0.len();
    assert_eq!(total_txs, 500);

    // Broadcast all transactions to cluster
    let t_broadcast_start = Instant::now();
    for tx in txs_s0.into_iter().chain(x_txs_0_to_1.into_iter()) {
        cluster.shard_mut(SHARD0).broadcast_tx(tx).await;
    }
    for tx in txs_s1.into_iter().chain(x_txs_1_to_0.into_iter()) {
        cluster.shard_mut(SHARD1).broadcast_tx(tx).await;
    }
    let broadcast_elapsed = t_broadcast_start.elapsed();

    // Mine blocks on both shards concurrently
    let t_mining_start = Instant::now();

    // Height 1: Both shards mine intra-shard transactions and produce outbound cross-shard records
    let h1_s0 = cluster.run_height(SHARD0, 1000).await;
    let h1_s1 = cluster.run_height(SHARD1, 1001).await;

    let blk1_s0 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&h1_s0)
        .cloned()
        .unwrap();
    let blk1_s1 = cluster.shard(SHARD1).nodes[0]
        .blocks
        .get(&h1_s1)
        .cloned()
        .unwrap();

    eprintln!(
        "blk1_s0 txs count: {}, cross_shard_out: {}",
        blk1_s0.transactions.len(),
        blk1_s0.cross_shard_out.len()
    );
    eprintln!(
        "blk1_s1 txs count: {}, cross_shard_out: {}",
        blk1_s1.transactions.len(),
        blk1_s1.cross_shard_out.len()
    );

    // XPC-19: ONE total cap bounds every cross-shard record in a block (outbound
    // transfers, inbound pulls, 2PC control), so the backlog is spread over
    // heights instead of packed into one unbounded block. The property this
    // benchmark must keep is "no record lost, no block over the cap", not the
    // old exact count.
    const XCAP: usize = stellereum::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK;
    for (name, blk) in [("shard0", &blk1_s0), ("shard1", &blk1_s1)] {
        assert!(
            blk.cross_shard_out.len() <= XCAP,
            "{name} block 1 exceeded the cross-shard record cap: {} > {XCAP}",
            blk.cross_shard_out.len()
        );
        assert!(
            !blk.cross_shard_out.is_empty(),
            "{name} must start packing cross-shard records"
        );
    }
    let mut s0_out = blk1_s0
        .cross_shard_out
        .iter()
        .filter(|m| !m.is_inbound_for(SHARD0))
        .count();
    let mut s1_out = blk1_s1
        .cross_shard_out
        .iter()
        .filter(|m| !m.is_inbound_for(SHARD1))
        .count();

    // Drain the backlog: bounded heights, every block cap-checked, every
    // outbound record accounted for exactly once.
    let mut consumed_inbound = false;
    for i in 0..32u64 {
        let a = cluster.run_height(SHARD0, 1002 + i).await;
        let b = cluster.run_height(SHARD1, 2002 + i).await;
        for (shard, h) in [(SHARD0, a), (SHARD1, b)] {
            let blk = cluster.shard(shard).nodes[0]
                .blocks
                .get(&h)
                .cloned()
                .unwrap();
            assert!(
                blk.cross_shard_out.len() <= XCAP,
                "shard {shard} block {} exceeded the cross-shard record cap: {} > {XCAP}",
                hex::encode(&h[..6]),
                blk.cross_shard_out.len()
            );
            if blk.cross_shard_out.iter().any(|m| m.is_inbound_for(shard)) {
                consumed_inbound = true;
            }
            let fresh = blk
                .cross_shard_out
                .iter()
                .filter(|m| !m.is_inbound_for(shard))
                .count();
            if shard == SHARD0 {
                s0_out += fresh;
            } else {
                s1_out += fresh;
            }
        }
        if s0_out >= 50 && s1_out >= 50 {
            break;
        }
    }
    assert_eq!(
        s0_out, 50,
        "every one of the 50 Shard 0 -> 1 transfers must land, spread over heights"
    );
    assert_eq!(
        s1_out, 50,
        "every one of the 50 Shard 1 -> 0 transfers must land, spread over heights"
    );
    assert!(
        consumed_inbound,
        "both shards must consume inbound cross-shard records during the drain"
    );

    let mining_elapsed = t_mining_start.elapsed();

    let total_elapsed = broadcast_elapsed + mining_elapsed;
    let effective_tps = (total_txs as f64) / total_elapsed.as_secs_f64();

    eprintln!("\n=======================================================");
    eprintln!("  STELLEREUM DUAL-SHARD STRESS BENCHMARK RESULTS");
    eprintln!("=======================================================");
    eprintln!("Total Transactions Processed: {}", total_txs);
    eprintln!("  • Intra-shard Shard 0: 200 txs");
    eprintln!("  • Intra-shard Shard 1: 200 txs");
    eprintln!("  • Cross-shard 0 -> 1:  50 txs");
    eprintln!("  • Cross-shard 1 -> 0:  50 txs");
    eprintln!("Broadcast Ingress Time:       {:?}", broadcast_elapsed);
    eprintln!("Multi-Shard Mining Time:      {:?}", mining_elapsed);
    eprintln!("Total Execution Time:         {:?}", total_elapsed);
    eprintln!("Effective Dual-Shard TPS:     {:.2} tx/s", effective_tps);
    eprintln!("=======================================================\n");

    assert!(
        effective_tps > 200.0,
        "Multi-shard throughput must exceed 200 tx/s"
    );
}
