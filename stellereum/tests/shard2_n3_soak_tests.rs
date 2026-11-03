//! Shard-2 N=3 soak: three validators per shard (workchain 7.5 -> 8.5 proof, no live touch).
//!
//! Closes the "1 validator/shard" gap of `shard2_soak_tests.rs` using only the
//! existing in-process harness (`Cluster::new_sharded` helpers, `ShardedCluster`,
//! `CrossShardTransport::local`, `refresh_workchain_set_from_master`).
//! NEW FILE ONLY — no existing file modified. Deterministic: fixed keys, fixed
//! heights, fixed amounts, no sleeps, no randomness.
//!
//! QUORUM MATH (frozen core, `consensus.rs:766`): quorum is `floor(2T/3)+1`
//! over voting POWER `T`, so:
//! * N=3 equal power (T=3): quorum = 3 — UNANIMOUS. Losing any 1 stalls the
//!   shard (proven in `shard2_n3_equal_power_loss_stalls_then_heals`).
//! * N=3 weighted 2:1:1 (T=4F): quorum = `floor(8F/3)+1`; losing a 1F node
//!   leaves 3F which still meets quorum (proven in
//!   `shard2_n3_weighted_quorum_survives_single_loss`), while losing the 2F
//!   node stalls — the power quorum is exact in both directions.
//!
//! What this file proves, end to end with 3 validators per shard (6 nodes):
//!  1. (a) Both shards finalize under a weighted 2:1:1 set; killing 1 small
//!     node per shard mid-soak keeps both shards finalizing on 2/3 NODES
//!     (power quorum still met); rates recorded.
//!  2. (a') Equal-power N=3 refuses weak finalization: killing 1 per shard
//!     pins both shards (0 heights/s, height pinned), and heal (reinsert +
//!     view-change to a fresh round) resumes finalization. This is the safety
//!     direction of per-shard quorum — NOT a liveness failure.
//!  3. (b) Cross-shard transfer through a degraded soak: value emitted at full
//!     quorum, shards degraded (no partial credit while degraded), healed,
//!     consumption completes exactly once, supply conserved end to end.
//!  4. (c) A masterchain rotation propagates to BOTH shards' sets: master set
//!     converges at its finalize boundary, workchain sets stage via
//!     `refresh_workchain_set_from_master` and install at the next boundary,
//!     on all 3 nodes of each shard.
//!  5. (d) Full shard-1 freeze (all 3 validators down = no heights driven):
//!     shard-0 keeps finalizing (no cross-shard deadlock); heal drives the
//!     missed heights, all 3 shard-1 nodes converge to one root, interop works.
//!  6. (e) Double-spend across shards: the same receipt replayed on both
//!     shards twice each credits exactly once; forged replay proposals are
//!     refused on every target node; supply conserved.
//!
//! GAPS (honest, harness-expressible limits):
//! * No real P2P/network/timers in-process; freeze is cooperative (heights not
//!   driven), not a crashed live process.
//! * Heal after DIVERGENCE (a node missing finalized heights rejoining) is not
//!   proven: `Cluster::run_height` has no walk/rejoin path in-harness. Tests
//!   heal only un-diverged stalls (nothing finalized while degraded) or resume
//!   frozen shards whose nodes never diverged. The live walk path
//!   (`try_catch_up`/`walk_chain`/`adopt_committed`) is out of harness scope.
//! * Rotation asserted via the direct repair call (the same function `main.rs`
//!   runs on a timer), not via the timed loop itself.
//! * Legacy outbox flow only — the XPC 2PC activation path is covered by
//!   `xshard_2pc_tests`, not soaked here.
//! * No wall-clock latency/tempo claims — in-process rounds have no network.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Instant;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::{Cluster, ShardedCluster, ValidatorRuntime};
use stellereum::sharding::{
    Block, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

/// N validators per shard; every node gets its OWN state engine (nodes never
/// share mutable state). Funding is applied to EVERY engine of that shard so
/// all members start from identical genesis.
async fn sharded_n(
    validators: &[SigningKey],
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let mut s0nodes = Vec::new();
    for v in validators {
        let e = Arc::new(InMemoryStateEngine::new());
        for (addr, bal) in shard0_funding {
            e.update_account(AccountState::new(*addr, *bal)).await;
        }
        s0nodes.push((v.clone(), e));
    }
    let mut s1nodes = Vec::new();
    for v in validators {
        let e = Arc::new(InMemoryStateEngine::new());
        for (addr, bal) in shard1_funding {
            e.update_account(AccountState::new(*addr, *bal)).await;
        }
        s1nodes.push((v.clone(), e));
    }
    ShardedCluster::new(
        sharded(),
        vec![(SHARD0, s0nodes), (SHARD1, s1nodes)],
        CrossShardTransport::local(),
    )
}

fn finalized_len(c: &Cluster) -> usize {
    c.nodes[0].finalized.len()
}

async fn balance_at(sc: &ShardedCluster, shard: u32, idx: usize, addr: &[u8; 32]) -> u64 {
    sc.shard(shard).nodes[idx]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// Every member of the shard must hold the same balance (same blocks applied).
async fn assert_balances_agree(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) {
    let first = balance_at(sc, shard, 0, addr).await;
    for (i, n) in sc.shard(shard).nodes.iter().enumerate() {
        let b = n.state.get_account(addr).await.map(|a| a.balance).unwrap_or(0);
        assert_eq!(b, first, "shard{shard} node{i} balance diverged");
    }
}

/// Every member of the shard must hold the same state root (convergence).
async fn assert_roots_agree(sc: &ShardedCluster, shard: u32) {
    let r0 = sc.shard(shard).nodes[0].state_root().await;
    for (i, n) in sc.shard(shard).nodes.iter().enumerate() {
        assert_eq!(n.state_root().await, r0, "shard{shard} node{i} root diverged");
    }
}

async fn supply_view(sc: &ShardedCluster, s0_addrs: &[[u8; 32]], s1_addrs: &[[u8; 32]]) -> u64 {
    let mut total = 0u64;
    for a in s0_addrs {
        total += balance_at(sc, SHARD0, 0, a).await;
    }
    for a in s1_addrs {
        total += balance_at(sc, SHARD1, 0, a).await;
    }
    total
}

/// Remove one NON-proposer node (a crashed validator). The caller must only
/// drive heights whose scheduled proposer is still live (see
/// `ValidatorSet::proposer_for` lookahead), or the harness panics with
/// `no proposer for this height`.
fn kill_non_proposer(c: &mut Cluster) -> ValidatorRuntime {
    let idx = c
        .nodes
        .iter()
        .position(|n| !n.is_proposer())
        .expect("n>1 always has a non-proposer");
    c.nodes.remove(idx)
}

/// Reinsert a stashed node and view-change every node to a fresh round: a
/// stalled `run_height` leaves steps past `Propose` on the survivors, and
/// `propose` only builds from `Step::Propose`.
fn heal(c: &mut Cluster, n: ValidatorRuntime) {
    c.nodes.push(n);
    for n in &mut c.nodes {
        n.next_round();
    }
}

/// (a) Both shards finalize with per-shard quorum under a weighted 2:1:1 set;
/// killing 1 SMALL node per shard mid-soak keeps both shards finalizing on
/// 2/3 nodes (power quorum still met). Rates recorded for full and degraded.
#[tokio::test]
async fn shard2_n3_weighted_quorum_survives_single_loss() {
    let va = key(101);
    let vb = key(102);
    let vc = key(103);
    let vks = vec![va.clone(), vb.clone(), vc.clone()];
    let (ida, idb, idc) = (id_of(&va), id_of(&vb), id_of(&vc));

    let mut sc = sharded_n(&vks, &[], &[]).await;
    // Wire the workchain runtimes to the LIVE masterchain ledger handle (what
    // `main.rs` does process-wide via `master_staking`).
    let master_handle = sc.shard(SHARD0).nodes[0].state.staking_handle();
    for n in &mut sc.shard_mut(SHARD1).nodes {
        n.master_staking = Some(master_handle.clone());
    }

    let mut ts = 1_000_000u64;
    // Full-quorum soak on the genesis equal-power set.
    let t0 = Instant::now();
    for _ in 0..4 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    let full_rate = 8.0 / t0.elapsed().as_secs_f64().max(1e-9);
    assert_eq!(finalized_len(sc.shard(SHARD0)), 4);
    assert_eq!(finalized_len(sc.shard(SHARD1)), 4);
    assert_roots_agree(&sc, SHARD0).await;
    assert_roots_agree(&sc, SHARD1).await;

    // Weight the power 2:1:1 (F = bond floor) on EVERY master engine — each
    // master node derives its set from its own ledger, so all three must see
    // the same bonds or the sets diverge.
    let f = stellereum::staking::required_bond_floor_nano();
    for n in &sc.shard(SHARD0).nodes {
        let mut st = n.state.staking_write().await;
        st.bond(ida, 2 * f, 0).expect("bond A must be accepted");
        st.bond(idb, f, 0).expect("bond B must be accepted");
        st.bond(idc, f, 0).expect("bond C must be accepted");
    }
    // Masterchain repair is a silent no-op on the masterchain itself.
    for i in 0..3 {
        assert!(
            !sc.shard_mut(SHARD0).nodes[i].refresh_workchain_set_from_master().await,
            "masterchain must ignore the workchain repair"
        );
    }
    // The workchain stages the rotation on every node.
    for i in 0..3 {
        assert!(
            sc.shard_mut(SHARD1).nodes[i].refresh_workchain_set_from_master().await,
            "workchain node{i} must stage the rotation"
        );
    }
    let h1 = sc.shard(SHARD1).height();
    for (i, n) in sc.shard(SHARD1).nodes.iter().enumerate() {
        let (activation, pending) = n.pending_validators.clone().expect("rotation staged");
        assert_eq!(activation, h1 + 1, "node{i}: activation is the next boundary");
        assert_eq!(pending.validators.get(&ida), Some(&(2 * f)), "node{i}: A=2F");
        assert_eq!(pending.validators.get(&idb), Some(&f), "node{i}: B=F");
        assert_eq!(pending.validators.get(&idc), Some(&f), "node{i}: C=F");
    }
    // Install at the boundary with real finalized heights on BOTH shards.
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    for shard in [SHARD0, SHARD1] {
        for (i, n) in sc.shard(shard).nodes.iter().enumerate() {
            assert_eq!(n.validators.validators.get(&ida), Some(&(2 * f)), "shard{shard} node{i}");
            assert_eq!(n.validators.validators.get(&idb), Some(&f), "shard{shard} node{i}");
            assert_eq!(n.validators.validators.get(&idc), Some(&f), "shard{shard} node{i}");
        }
    }
    // Power quorum is exact in both directions: T=4F, losing 1F keeps quorum,
    // losing 2F (validator A) must stall.
    let total = sc.shard(SHARD0).nodes[0].validators.total_power();
    let q = sc.shard(SHARD0).nodes[0].validators.quorum_power();
    assert_eq!(total, 4 * f);
    assert!(total - f >= q, "losing a 1F node must keep quorum (3F vs {q})");
    assert!(total - 2 * f < q, "losing the 2F node must stall (power quorum exact)");
    eprintln!("N3 weighted set: total={total} quorum={q} floor={f}");

    // Full-quorum soak on the weighted set (proves the rotated set finalizes).
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    assert_eq!(finalized_len(sc.shard(SHARD0)), 7);
    assert_eq!(finalized_len(sc.shard(SHARD1)), 7);

    // Victim: a SMALL node unscheduled for the next 2 heights on both shards
    // (identical sets => identical schedules; lookahead is inherent and
    // deterministic via `proposer_for`).
    let h = sc.shard(SHARD0).height();
    assert_eq!(h, sc.shard(SHARD1).height());
    assert_eq!(
        sc.shard(SHARD0).nodes[0].validators.validators,
        sc.shard(SHARD1).nodes[0].validators.validators,
        "both shards must run the identical weighted set"
    );
    let set = sc.shard(SHARD0).nodes[0].validators.clone();
    let victim = [idb, idc]
        .into_iter()
        .find(|id| (0..2u64).all(|k| set.proposer_for(h + k, 0) != Some(*id)))
        .expect("one small node must be free of the next-2 schedule");
    for shard in [SHARD0, SHARD1] {
        let vidx = vks.iter().position(|k| id_of(k) == victim).expect("member key");
        let stashed = sc.shard_mut(shard).nodes.remove(vidx);
        assert_eq!(stashed.id, victim, "must kill exactly the selected victim");
        assert_eq!(sc.shard(shard).nodes.len(), 2);
    }
    eprintln!("N3 kill: victim={} (1F), 2/3 nodes remain per shard", hex::encode(victim));

    // DEGRADED soak: 2 heights per shard on 2/3 nodes — must keep finalizing.
    let t1 = Instant::now();
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    let degraded_rate = 4.0 / t1.elapsed().as_secs_f64().max(1e-9);
    assert_eq!(finalized_len(sc.shard(SHARD0)), 9, "shard0 finalizes degraded 2/3");
    assert_eq!(finalized_len(sc.shard(SHARD1)), 9, "shard1 finalizes degraded 2/3");
    assert_eq!(sc.shard(SHARD0).height(), h + 2);
    assert_eq!(sc.shard(SHARD1).height(), h + 2);
    assert_roots_agree(&sc, SHARD0).await;
    assert_roots_agree(&sc, SHARD1).await;
    eprintln!(
        "N3 rates: full_quorum={full_rate:.1} heights/s degraded_2of3={degraded_rate:.1} heights/s \
         finals0=9 finals1=9 victim_power=1F quorum={q}"
    );
}

/// (a') Equal-power N=3 (quorum 3/3, unanimous) refuses weak finalization:
/// killing 1 per shard pins both shards (0 new finals, height pinned); heal
/// via reinsert + fresh-round view-change resumes finalization.
#[tokio::test]
async fn shard2_n3_equal_power_loss_stalls_then_heals() {
    let vks = vec![key(111), key(112), key(113)];
    let mut sc = sharded_n(&vks, &[], &[]).await;
    for shard in [SHARD0, SHARD1] {
        let vs = &sc.shard(shard).nodes[0].validators;
        assert_eq!(vs.total_power(), 3);
        assert_eq!(vs.quorum_power(), 3, "equal-power N=3 needs unanimity");
    }

    let mut ts = 2_000_000u64;
    let t0 = Instant::now();
    for _ in 0..4 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    let full_rate = 8.0 / t0.elapsed().as_secs_f64().max(1e-9);
    assert_eq!(finalized_len(sc.shard(SHARD0)), 4);
    assert_eq!(finalized_len(sc.shard(SHARD1)), 4);

    // Kill 1 per shard mid-soak.
    let s0 = kill_non_proposer(sc.shard_mut(SHARD0));
    let s1 = kill_non_proposer(sc.shard_mut(SHARD1));
    assert_eq!(sc.shard(SHARD0).nodes.len(), 2);
    assert_eq!(sc.shard(SHARD1).nodes.len(), 2);
    // Remaining power 2 < quorum 3: the shards MUST stall (weak-QC refusal).
    let t1 = Instant::now();
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    let stall_dt = t1.elapsed();
    assert_eq!(finalized_len(sc.shard(SHARD0)), 4, "2/3 power must not finalize");
    assert_eq!(finalized_len(sc.shard(SHARD1)), 4, "2/3 power must not finalize");
    assert_eq!(sc.shard(SHARD0).height(), 5, "stalled height must not advance");
    assert_eq!(sc.shard(SHARD1).height(), 5, "stalled height must not advance");
    eprintln!(
        "N3 unanimous stall: 0 new finals in {}ms (2 remaining power < quorum 3)",
        stall_dt.as_millis()
    );

    // Heal: reinsert + fresh round, then both shards resume on 3/3.
    heal(sc.shard_mut(SHARD0), s0);
    heal(sc.shard_mut(SHARD1), s1);
    assert_eq!(sc.shard(SHARD0).nodes.len(), 3);
    assert_eq!(sc.shard(SHARD1).nodes.len(), 3);
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    assert_eq!(finalized_len(sc.shard(SHARD0)), 6);
    assert_eq!(finalized_len(sc.shard(SHARD1)), 6);
    assert_roots_agree(&sc, SHARD0).await;
    assert_roots_agree(&sc, SHARD1).await;
    eprintln!("N3 heal: resumed 3/3, finals0=6 finals1=6 full_rate={full_rate:.1} heights/s");
}

/// (b) Cross-shard transfer through a degraded soak: emitted at full quorum,
/// shards degraded (no partial credit while degraded), healed, consumption
/// completes exactly once, supply conserved end to end.
#[tokio::test]
async fn shard2_n3_cross_shard_transfer_through_degraded_soak() {
    let vks = vec![key(121), key(122), key(123)];
    let vaddrs: Vec<[u8; 32]> = vks.iter().map(id_of).collect();
    let sender = key(124);
    let recipient = key(125);
    let sender_addr = id_of(&sender);
    let recipient_addr = id_of(&recipient);

    let mut sc = sharded_n(&vks, &[(sender_addr, 1_000_000)], &[]).await;
    let mut ts = 3_000_000u64;
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    let mut s0_view = vaddrs.clone();
    s0_view.push(sender_addr);
    let supply_before = supply_view(&sc, &s0_view, &[recipient_addr]).await;

    // Emit at full quorum.
    let amount = 10_000u64;
    let gas = 50u64;
    let tx = Transaction::sign(&sender, recipient_addr, amount, gas, 0, SHARD0, SHARD1);
    sc.broadcast_tx(tx.clone()).await;
    ts += 1;
    let src_bh = sc.run_height(SHARD0, ts).await;
    assert_eq!(
        sc.shard(SHARD0).nodes[0].blocks.get(&src_bh).unwrap().cross_shard_out.len(),
        1,
        "source must emit exactly one outbound message"
    );
    assert_balances_agree(&sc, SHARD0, &sender_addr).await;

    // Degrade both shards mid-soak: neither may finalize (unanimous N=3).
    let d0 = kill_non_proposer(sc.shard_mut(SHARD0));
    let d1 = kill_non_proposer(sc.shard_mut(SHARD1));
    let f0 = finalized_len(sc.shard(SHARD0));
    let f1 = finalized_len(sc.shard(SHARD1));
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    assert_eq!(finalized_len(sc.shard(SHARD0)), f0, "degraded source must stall");
    assert_eq!(finalized_len(sc.shard(SHARD1)), f1, "degraded target must stall");
    // No partial credit while degraded: recipient unfunded on every live node.
    for (i, n) in sc.shard(SHARD1).nodes.iter().enumerate() {
        assert_eq!(
            n.state.get_account(&recipient_addr).await.map(|a| a.balance).unwrap_or(0),
            0,
            "target node{i} must not credit while degraded"
        );
    }
    eprintln!("N3 degraded transfer: 0 finals, 0 credits while 2/3 (f0={f0} f1={f1})");

    // Heal both shards, then the in-flight value completes exactly once.
    heal(sc.shard_mut(SHARD0), d0);
    heal(sc.shard_mut(SHARD1), d1);
    ts += 1;
    let tgt_bh = sc.run_height(SHARD1, ts).await;
    assert!(
        sc.shard(SHARD1).nodes[0]
            .blocks
            .get(&tgt_bh)
            .unwrap()
            .cross_shard_out
            .iter()
            .any(|m| m.is_inbound_for(SHARD1)),
        "target must commit the consumption record after heal"
    );
    // Post-transfer soak at full quorum.
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    assert_balances_agree(&sc, SHARD0, &sender_addr).await;
    assert_balances_agree(&sc, SHARD1, &recipient_addr).await;
    assert_roots_agree(&sc, SHARD0).await;
    assert_roots_agree(&sc, SHARD1).await;
    assert_eq!(balance_at(&sc, SHARD1, 0, &recipient_addr).await, amount);
    assert_eq!(balance_at(&sc, SHARD0, 0, &sender_addr).await, 1_000_000 - amount - gas);
    let supply_after = supply_view(&sc, &s0_view, &[recipient_addr]).await;
    assert_eq!(supply_after, supply_before, "supply must be conserved through the degraded soak");
    eprintln!(
        "N3 degraded xfer ok: amount={amount} gas={gas} supply={supply_before}->{supply_after} \
         finals0={} finals1={}",
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
    );
}

/// (c) Masterchain rotation propagates to BOTH shards' sets: the master set
/// converges at its own finalize boundary while every workchain node stages
/// via `refresh_workchain_set_from_master` and installs at the next boundary.
#[tokio::test]
async fn shard2_n3_rotation_propagates_to_both_shards() {
    let vks = vec![key(131), key(132), key(133)];
    let vaddrs: Vec<[u8; 32]> = vks.iter().map(id_of).collect();
    let mut sc = sharded_n(&vks, &[], &[]).await;
    let master_handle = sc.shard(SHARD0).nodes[0].state.staking_handle();
    for n in &mut sc.shard_mut(SHARD1).nodes {
        n.master_staking = Some(master_handle.clone());
    }

    let mut ts = 4_000_000u64;
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    // Rotation on the masterchain: bond every validator at the floor on every
    // master engine (each master node reads its own ledger).
    let floor = stellereum::staking::required_bond_floor_nano();
    for n in &sc.shard(SHARD0).nodes {
        let mut st = n.state.staking_write().await;
        for a in &vaddrs {
            st.bond(*a, floor, 0).expect("masterchain bond must be accepted");
        }
    }
    // Masterchain repair is a no-op on all 3 master nodes.
    for i in 0..3 {
        assert!(
            !sc.shard_mut(SHARD0).nodes[i].refresh_workchain_set_from_master().await,
            "master node{i} must ignore the workchain repair"
        );
    }
    // Every workchain node stages the rotation with no finalize in between.
    for i in 0..3 {
        assert!(
            sc.shard_mut(SHARD1).nodes[i].refresh_workchain_set_from_master().await,
            "workchain node{i} must stage the rotation"
        );
    }
    let h1 = sc.shard(SHARD1).height();
    for (i, n) in sc.shard(SHARD1).nodes.iter().enumerate() {
        let (activation, pending) = n.pending_validators.clone().expect("rotation staged");
        assert_eq!(activation, h1 + 1, "node{i}: activation at next boundary");
        for a in &vaddrs {
            assert_eq!(pending.validators.get(a), Some(&floor), "node{i}: power=floor");
        }
    }
    eprintln!("N3 rotation staged on 3/3 workchain nodes at activation={}", h1 + 1);
    // Both boundaries install it with real finalized heights.
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    for shard in [SHARD0, SHARD1] {
        for (i, n) in sc.shard(shard).nodes.iter().enumerate() {
            for a in &vaddrs {
                assert_eq!(
                    n.validators.validators.get(a),
                    Some(&floor),
                    "shard{shard} node{i}: rotated power installed"
                );
            }
        }
    }
    assert_roots_agree(&sc, SHARD0).await;
    assert_roots_agree(&sc, SHARD1).await;
    eprintln!(
        "N3 rotation installed both shards: finals0={} finals1={} height0={} height1={}",
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
        sc.shard(SHARD0).height(),
        sc.shard(SHARD1).height(),
    );
}

/// (d) Full shard-1 freeze (all 3 validators down = no heights driven):
/// shard-0 keeps finalizing (no cross-shard deadlock); heal drives the missed
/// heights, all 3 shard-1 nodes converge, interop works afterwards.
#[tokio::test]
async fn shard2_n3_freeze_shard1_heal_catch_up() {
    let vks = vec![key(141), key(142), key(143)];
    let sender = key(144);
    let recipient = key(145);
    let sender_addr = id_of(&sender);
    let recipient_addr = id_of(&recipient);

    let mut sc = sharded_n(&vks, &[(sender_addr, 500_000)], &[]).await;
    let mut ts = 5_000_000u64;
    for _ in 0..3 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    let f0_pre = finalized_len(sc.shard(SHARD0));
    let f1_pre = finalized_len(sc.shard(SHARD1));
    // FREEZE shard1: 4 more heights on shard0 only (all 3 shard-1 down).
    for _ in 0..4 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
    }
    let f0_frozen = finalized_len(sc.shard(SHARD0));
    let f1_frozen = finalized_len(sc.shard(SHARD1));
    assert_eq!(f0_frozen, f0_pre + 4, "shard0 keeps finalizing while shard1 frozen");
    assert_eq!(f1_frozen, f1_pre, "frozen shard finalizes nothing");
    eprintln!("N3 freeze: finals0 {f0_pre}->{f0_frozen} finals1 {f1_pre}->{f1_frozen}");

    // HEAL: shard1 resumes from where it stopped and catches up height-for-height.
    for _ in 0..4 {
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    let f1_healed = finalized_len(sc.shard(SHARD1));
    assert_eq!(f1_healed, f1_pre + 4, "healed shard catches up");
    assert_eq!(sc.shard(SHARD1).height(), sc.shard(SHARD0).height());
    assert_roots_agree(&sc, SHARD1).await;
    eprintln!("N3 heal: finals1 {f1_frozen}->{f1_healed}, roots agree on 3/3 nodes");

    // Interop still works after the heal.
    let tx = Transaction::sign(&sender, recipient_addr, 5_000, 25, 0, SHARD0, SHARD1);
    sc.broadcast_tx(tx).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    ts += 1;
    sc.run_height(SHARD1, ts).await;
    assert_balances_agree(&sc, SHARD1, &recipient_addr).await;
    assert_eq!(balance_at(&sc, SHARD1, 0, &recipient_addr).await, 5_000);
    eprintln!(
        "N3 post-heal xfer ok: finals0={} finals1={}",
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
    );
}

/// (e) Double-spend across shards: the same receipt replayed on both shards
/// twice each credits exactly once; forged replay proposals are refused on
/// every target node; supply conserved.
#[tokio::test]
async fn shard2_n3_double_spend_refused_everywhere() {
    let vks = vec![key(151), key(152), key(153)];
    let vaddrs: Vec<[u8; 32]> = vks.iter().map(id_of).collect();
    let sender = key(154);
    let recipient = key(155);
    let sender_addr = id_of(&sender);
    let recipient_addr = id_of(&recipient);

    let mut sc = sharded_n(&vks, &[(sender_addr, 1_000_000)], &[]).await;
    let mut ts = 6_000_000u64;
    let amount = 20_000u64;
    let gas = 50u64;
    let tx = Transaction::sign(&sender, recipient_addr, amount, gas, 0, SHARD0, SHARD1);
    sc.broadcast_tx(tx.clone()).await;
    ts += 1;
    sc.run_height(SHARD0, ts).await;
    ts += 1;
    let tgt_bh = sc.run_height(SHARD1, ts).await;
    let consumed_msg = sc.shard(SHARD1).nodes[0]
        .blocks
        .get(&tgt_bh)
        .cloned()
        .expect("target block retained")
        .cross_shard_out
        .into_iter()
        .find(|m| m.is_inbound_for(SHARD1))
        .expect("consumption record committed");
    assert_eq!(balance_at(&sc, SHARD1, 0, &recipient_addr).await, amount);

    let mut s0_view = vaddrs.clone();
    s0_view.push(sender_addr);
    let supply_before = supply_view(&sc, &s0_view, &[recipient_addr]).await;

    // Attack: same receipt on both shards, twice each — same tx re-seeded
    // twice per shard plus the consumed message rebroadcast twice.
    sc.broadcast_tx(tx.clone()).await;
    sc.broadcast_tx(tx.clone()).await;
    sc.transport.broadcast_cross_shard(&consumed_msg).await.unwrap();
    sc.transport.broadcast_cross_shard(&consumed_msg).await.unwrap();
    for _ in 0..2 {
        ts += 1;
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
    }
    // Exactly-once everywhere: no second credit, no second debit.
    assert_balances_agree(&sc, SHARD0, &sender_addr).await;
    assert_balances_agree(&sc, SHARD1, &recipient_addr).await;
    assert_eq!(balance_at(&sc, SHARD1, 0, &recipient_addr).await, amount, "no double mint");
    assert_eq!(
        balance_at(&sc, SHARD0, 0, &sender_addr).await,
        1_000_000 - amount - gas,
        "no second debit"
    );
    let supply_after = supply_view(&sc, &s0_view, &[recipient_addr]).await;
    assert_eq!(supply_after, supply_before, "replay must conserve supply");
    assert_roots_agree(&sc, SHARD0).await;
    assert_roots_agree(&sc, SHARD1).await;

    // A forged proposal re-including the consumed message is refused on EVERY
    // target node — even with the scheduled proposer signing it, so the
    // refusal names the replay, not the schedule.
    ts += 1;
    for (i, node) in sc.shard(SHARD1).nodes.iter().enumerate() {
        let height = node.height();
        let prev = node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        let root = node.state_root().await;
        let sched = node.validators.proposer_for(height, node.hc.round).expect("non-empty set");
        let skey: SigningKey =
            vks.iter().find(|k| id_of(k) == sched).expect("member key").clone();
        let mut forged = Block {
            shard_id: SHARD1,
            height,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![consumed_msg.clone()],
            timestamp: ts,
            proposer: sched,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        forged.sign_block(&skey);
        let err = node
            .validate_proposal(&forged, root)
            .expect_err("replayed consumption must be refused");
        assert!(err.contains("replayed"), "target node{i}: {err}");
    }
    eprintln!(
        "N3 double-spend refused: recipient={amount} supply={supply_before}->{supply_after} \
         forged_replay_refused_on=3/3 finals0={} finals1={}",
        finalized_len(sc.shard(SHARD0)),
        finalized_len(sc.shard(SHARD1)),
    );
}
