//! Shard-2 soak: two shards finalize + interoperate in-process (UNPARK §4 proof).
//!
//! Workchain 6.0 -> 8.0 WITHOUT live touch: local/sim proof of the UNPARK
//! plan (`docs/WORKCHAIN_DECISION.md` §4) using only the existing
//! in-process harness (`Cluster::new_sharded` helpers, `ShardedCluster`).
//!
//! What this file proves, end to end inside a running 2-shard cluster:
//!  1. Both shards finalize N heights (per-shard finals recorded).
//!  2. A cross-shard transfer debit/credits with supply conserved through a
//!     longer soak (not just the M2 unit step — warmup heights, transfer,
//!     post heights, then the accounting).
//!  3. A masterchain rotation propagates to the workchain set through the
//!     periodic repair path (`refresh_workchain_set_from_master`, the call
//!     `main.rs` runs on a timer).
//!  4. Freezing one shard mid-soak does not deadlock the other; the frozen
//!     shard heals and interoperates afterwards.
//!
//! Deterministic: fixed keys, fixed heights, fixed amounts. Single validator
//! per shard (quorum dynamics of N=3+ are NOT covered here — see GAPS).

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::{Cluster, ShardedCluster};
use stellereum::sharding::{
    ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const SOAK_HEIGHTS: u64 = 10;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

/// Two single-validator shards sharing one node-local cross-shard transport
/// (the M2 idiom). Engines are pre-funded; everything else is empty.
async fn sharded_pair(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard1_funding {
        s1.update_account(AccountState::new(*addr, *bal)).await;
    }
    ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    )
}

async fn balance(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
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

/// (a) Both shards finalize N heights in-process; per-shard finals recorded.
#[tokio::test]
async fn shard2_soak_both_shards_finalize() {
    let validator = key(1);
    let mut sc = sharded_pair(&validator, &[], &[]).await;
    let t0 = Instant::now();
    for h in 1..=SOAK_HEIGHTS {
        let bh0 = sc.run_height(SHARD0, h * 2 - 1).await;
        let bh1 = sc.run_height(SHARD1, h * 2).await;
        assert_eq!(sc.shard(SHARD0).nodes[0].blocks.get(&bh0).unwrap().shard_id, SHARD0);
        assert_eq!(sc.shard(SHARD1).nodes[0].blocks.get(&bh1).unwrap().shard_id, SHARD1);
    }
    let dt = t0.elapsed();
    let f0 = finalized_len(sc.shard(SHARD0));
    let f1 = finalized_len(sc.shard(SHARD1));
    eprintln!(
        "SOAK finals: shard0={f0} shard1={f1} heights={SOAK_HEIGHTS} elapsed_ms={} rate_hz={:.1}",
        dt.as_millis(),
        (2 * SOAK_HEIGHTS) as f64 / dt.as_secs_f64().max(1e-9),
    );
    assert_eq!(f0 as u64, SOAK_HEIGHTS, "shard0 must finalize every height");
    assert_eq!(f1 as u64, SOAK_HEIGHTS, "shard1 must finalize every height");
    assert_eq!(sc.shard(SHARD0).height(), SOAK_HEIGHTS + 1);
    assert_eq!(sc.shard(SHARD1).height(), SOAK_HEIGHTS + 1);
}

/// (b) Cross-shard transfer conserves supply end to end through the soak:
/// warmup heights, transfer, post heights, then the accounting.
#[tokio::test]
async fn shard2_soak_cross_shard_transfer_conserves_supply() {
    let validator = key(11);
    let sender = key(12);
    let recipient = key(13);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();
    let validator_addr = validator.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    // Warmup: both shards alive before any value moves.
    for h in 1..=3 {
        sc.run_height(SHARD0, h).await;
        sc.run_height(SHARD1, h).await;
    }
    let supply_before = balance(&sc, SHARD0, &sender_addr).await
        + balance(&sc, SHARD0, &validator_addr).await
        + balance(&sc, SHARD1, &recipient_addr).await;

    let amount = 10_000u64;
    let gas = 50u64;
    let tx = Transaction::sign(&sender, recipient_addr, amount, gas, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx).await;
    let src_bh = sc.run_height(SHARD0, 4).await;
    assert_eq!(
        sc.shard(SHARD0).nodes[0].blocks.get(&src_bh).unwrap().cross_shard_out.len(),
        1,
        "source must emit exactly one outbound message"
    );
    let tgt_bh = sc.run_height(SHARD1, 4).await;
    assert!(
        sc.shard(SHARD1).nodes[0]
            .blocks
            .get(&tgt_bh)
            .unwrap()
            .cross_shard_out
            .iter()
            .any(|m| m.is_inbound_for(SHARD1)),
        "target must commit the consumption record"
    );
    // Post-transfer soak: both shards keep finalizing after value moved.
    for h in 5..=7 {
        sc.run_height(SHARD0, h).await;
        sc.run_height(SHARD1, h).await;
    }
    let supply_after = balance(&sc, SHARD0, &sender_addr).await
        + balance(&sc, SHARD0, &validator_addr).await
        + balance(&sc, SHARD1, &recipient_addr).await;
    eprintln!(
        "SOAK xfer: amount={amount} gas={gas} sender_after={} recipient_after={} \
         supply_before={supply_before} supply_after={supply_after} \
         finals0={} finals1={}",
        balance(&sc, SHARD0, &sender_addr).await,
        balance(&sc, SHARD1, &recipient_addr).await,
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
    );
    assert_eq!(
        balance(&sc, SHARD1, &recipient_addr).await,
        amount,
        "recipient credited exactly once"
    );
    assert_eq!(
        balance(&sc, SHARD0, &sender_addr).await,
        1_000_000 - amount - gas,
        "sender debited amount + gas exactly"
    );
    assert_eq!(
        supply_after, supply_before,
        "cross-shard transfer must conserve supply end to end through the soak"
    );
}

/// (c) Masterchain rotation propagates to the workchain set via the periodic
/// repair path (`refresh_workchain_set_from_master`) inside the running
/// 2-shard cluster.
#[tokio::test]
async fn shard2_soak_rotation_propagates_to_workchain() {
    let validator = key(21);
    let validator_addr = validator.verifying_key().to_bytes();
    let mut sc = sharded_pair(&validator, &[], &[]).await;
    // Wire the workchain runtimes to the LIVE masterchain ledger handle
    // (what `main.rs` does process-wide via `master_staking`); reads are
    // atomic, writes go through the master engine.
    let master_handle = sc.shard(SHARD0).nodes[0].state.staking_handle();
    for n in &mut sc.shard_mut(SHARD1).nodes {
        n.master_staking = Some(master_handle.clone());
    }
    for h in 1..=2 {
        sc.run_height(SHARD0, h).await;
        sc.run_height(SHARD1, h).await;
    }
    // Rotation on the masterchain: bond the validator's own key (the set
    // keeps its single member so the 1-node shards keep finalizing; the
    // power change is the observable rotation).
    let floor = stellereum::staking::required_bond_floor_nano();
    sc.shard(SHARD0).nodes[0]
        .state
        .staking_write()
        .await
        .bond(validator_addr, floor, 0)
        .expect("masterchain bond must be accepted");

    // The masterchain itself is a silent no-op for the workchain repair.
    assert!(
        !sc.shard_mut(SHARD0).nodes[0].refresh_workchain_set_from_master().await,
        "masterchain must ignore the workchain repair"
    );
    // The workchain picks the rotation up with no finalize in between.
    let staged = sc.shard_mut(SHARD1).nodes[0].refresh_workchain_set_from_master().await;
    let w = &sc.shard(SHARD1).nodes[0];
    let (activation, pending) = w
        .pending_validators
        .clone()
        .expect("rotation must stage a pending set");
    eprintln!(
        "SOAK rotation: staged={staged} activation={activation} \
         pending_power={:?} inforce_power={:?}",
        pending.validators.get(&validator_addr),
        w.validators.validators.get(&validator_addr),
    );
    assert!(staged, "workchain must stage the masterchain rotation");
    assert_eq!(activation, w.hc.height + 1);
    assert_eq!(pending.validators.get(&validator_addr), Some(&floor));
    // The next boundary installs it — drive it with a real finalized height.
    sc.run_height(SHARD1, 3).await;
    let w = &sc.shard(SHARD1).nodes[0];
    assert_eq!(
        w.validators.validators.get(&validator_addr),
        Some(&floor),
        "workchain sees the rotated set after the boundary"
    );
    eprintln!(
        "SOAK rotation installed: finals1={} height1={}",
        finalized_len(sc.shard(SHARD1)),
        sc.shard(SHARD1).height(),
    );
}

/// (d) Freeze shard1 mid-soak: shard0 keeps finalizing (no cross-shard
/// deadlock); heal shard1 and it catches up and interoperates.
#[tokio::test]
async fn shard2_soak_freeze_and_heal() {
    let validator = key(31);
    let sender = key(32);
    let recipient = key(33);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 500_000)], &[]).await;
    for h in 1..=3 {
        sc.run_height(SHARD0, h).await;
        sc.run_height(SHARD1, h).await;
    }
    let f0_pre = finalized_len(sc.shard(SHARD0));
    let f1_pre = finalized_len(sc.shard(SHARD1));
    // FREEZE shard1: drive 4 more heights on shard0 only.
    for h in 4..=7 {
        sc.run_height(SHARD0, h).await;
    }
    let f0_frozen = finalized_len(sc.shard(SHARD0));
    let f1_frozen = finalized_len(sc.shard(SHARD1));
    eprintln!(
        "SOAK freeze: finals0 {f0_pre}->{f0_frozen} finals1 {f1_pre}->{f1_frozen} (shard1 frozen)"
    );
    assert_eq!(f0_frozen, f0_pre + 4, "shard0 keeps finalizing while shard1 is frozen");
    assert_eq!(f1_frozen, f1_pre, "frozen shard finalizes nothing");
    // HEAL: shard1 resumes finalizing from where it stopped.
    for h in 4..=7 {
        sc.run_height(SHARD1, h).await;
    }
    let f1_healed = finalized_len(sc.shard(SHARD1));
    eprintln!("SOAK heal: finals1 {f1_frozen}->{f1_healed}");
    assert_eq!(f1_healed, f1_pre + 4, "healed shard catches up");
    // Interop still works after the heal.
    let tx = Transaction::sign(&sender, recipient_addr, 5_000, 25, 0, SHARD0, SHARD1);
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx).await;
    sc.run_height(SHARD0, 8).await;
    sc.run_height(SHARD1, 8).await;
    assert_eq!(
        balance(&sc, SHARD1, &recipient_addr).await,
        5_000,
        "post-heal cross-shard transfer must credit"
    );
    eprintln!(
        "SOAK post-heal xfer ok: finals0={} finals1={}",
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
    );
}
