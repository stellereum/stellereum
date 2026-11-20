//! Restart / height-sync liveness (the last live HEIGHT split).
//!
//! THE FAILURE THIS EXISTS FOR (live 2026-11-20, ruleset 6): after a restart a
//! node came back at its persisted height while the rest of the network had
//! already decided several heights without it. The round chase (`f+1`, F5) was
//! fine, but the node never adopted the heights it missed:
//!
//!   * `adopt_committed` refused a VERIFIED precommit quorum for the node's
//!     exact next height whenever the certificate's round was ABOVE the
//!     node's restored round ("certificate is for round N not 0"). A
//!     restarted node comes back at round 0 (or its watermark floor) while
//!     the peers decided that height several rounds in; and because every
//!     peer has moved to a HIGHER height there are no votes at OUR height for
//!     the f+1 chase to follow. Refusal was permanent: the only remaining
//!     path was a DHT body walk, which strands when a body is missing.
//!   * A restart whose engine state was AHEAD of the stored finalize pointer
//!     seeded `hc.height = S + 1` with `finalized` still at `F < S`, so it
//!     proposed above its own finalized parent and its catch-up walk anchored
//!     at F while the engine was already past F.
//!
//! WHAT IS PINNED HERE:
//!   1. a verified commit for our exact next height is adoptable regardless
//!      of the certificate round (forward-round catch-up); the safety gates
//!      (parent link, quorum, lock/value, watermark) are unchanged;
//!   2. a 3-validator cluster whose 1-power node restarts from a persisted
//!      tip 2-5 heights behind adopts the retained commits and resumes
//!      finality, with one block per height and no double vote;
//!   3. the same after TWO nodes restart;
//!   4. the restore reconciliation never lets the node propose above its own
//!      finalized parent.
//!
//! Determinism: virtual-time cluster, seeded keys, seeded message order.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::{ValidatorSet, VoteKind, VoteSet};
use stellereum::post_quantum::FalconKeypair;
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::ConsensusCluster;

/// Generous virtual budget: a few round timeouts per height is enough, and a
/// stall is reported instead of hanging.
const BUDGET_MS: u64 = 240_000;

/// Heights the peers advance while the restarted node is out (2-5).
const CATCH_UP_HEIGHTS: u64 = 3;

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn vs_of(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

async fn runtime(ks: &[SigningKey], idx: usize) -> ValidatorRuntime {
    let vs = vs_of(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    ValidatorRuntime::new(ks[idx].clone(), vs, st, 1)
}

async fn block_at_round(
    rt: &ValidatorRuntime,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    height: u64,
    round: u32,
    prev: [u8; 32],
) -> Block {
    let vs = rt.validators.clone();
    let proposer = vs.proposer_for(height, round).unwrap();
    let idx = ks.iter().position(|k| id(k) == proposer).unwrap();
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round,
    };
    b.sign_block_with_falcon(&ks[idx], &fks[idx]);
    b
}

fn precommit_cert(
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    height: u64,
    round: u32,
    bh: [u8; 32],
    parent: [u8; 32],
) -> stellereum::consensus::QuorumCertificate {
    let vs = vs_of(ks);
    let mut set = VoteSet::new();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        set.add(
            falcon_votes::fvote(k, fk, height, round, VoteKind::Precommit, Some(bh)),
            &vs,
            height,
            round,
            VoteKind::Precommit,
        )
        .expect("genuine vote admits");
    }
    set.certificate_with_parent(Some(bh), &vs, Some(&parent))
        .expect("unanimous precommits reach quorum")
}

// ===========================================================================
// 1. The adopt path: a decision is adopted by round, not gated on it.
// ===========================================================================

#[tokio::test]
async fn a_restarted_node_adopts_a_forward_round_commit() {
    let (ks, fks) = falcon_votes::falcon_set(3);
    let mut rt = runtime(&ks, 0).await;
    // Restart shape: consensus at height 1, round 0 (no checkpoint/watermark).
    assert_eq!((rt.hc.height, rt.hc.round), (1, 0));
    // The network decided height 1 in round 3 (round churn while we were out).
    let blk = block_at_round(&rt, &ks, &fks, 1, 3, [0u8; 32]).await;
    let bh = blk.compute_hash();
    let cert = precommit_cert(&ks, &fks, 1, 3, bh, [0u8; 32]);
    assert!(cert.verify(&rt.validators));
    let got = rt.adopt_committed(1, blk, cert).await;
    assert_eq!(
        got,
        Ok(bh),
        "a verified commit at a certificate round above our restored round must be \
         adoptable: it is a decision for our exact next height, and no peer votes at \
         this height anymore for the round chase to follow"
    );
    assert_eq!(rt.finalized.last().map(|(h, _)| *h), Some(1));
    assert_eq!(rt.hc.height, 2);
}

#[tokio::test]
async fn forward_round_adoption_still_refuses_a_conflicting_lock() {
    let (ks, fks) = falcon_votes::falcon_set(3);
    let mut rt = runtime(&ks, 0).await;
    let locked = [0xAAu8; 32];
    rt.hc.locked = Some((locked, 5));
    let blk = block_at_round(&rt, &ks, &fks, 1, 3, [0u8; 32]).await;
    let bh = blk.compute_hash();
    assert_ne!(bh, locked);
    let cert = precommit_cert(&ks, &fks, 1, 3, bh, [0u8; 32]);
    let got = rt.adopt_committed(1, blk, cert).await;
    assert!(
        got.is_err(),
        "a commit for a DIFFERENT value at or below our lock round must still be refused"
    );
    assert_eq!(
        rt.hc.height, 1,
        "a refused commit must not advance the height"
    );
}

// ===========================================================================
// 2. The cluster: restart one node behind a live quorum.
// ===========================================================================

/// A 3-validator cluster with powers 2/1/1 (quorum 3): the 2-power node plus
/// either 1-power node can finalize, so a single 1-power node can go down and
/// the other two keep producing. X is the last index; its persisted tip is
/// `base` while the network advances `CATCH_UP_HEIGHTS` without it.
async fn single_restart_cluster() -> (ConsensusCluster, u64) {
    let mut c = ConsensusCluster::with_powers(&[2, 1, 1]);
    c.retain_commits();
    c.seed_transactions(64).await;
    let x_id = c.runtime(2).id;
    // Choose a base whose next few heights NEED X for round 0, so the peers
    // decide them in round >= 1 while X is out. That is the live shape: the
    // returning node's next height was decided at a round it never saw.
    let mut base = 3u64;
    while !(base + 1..=base + CATCH_UP_HEIGHTS)
        .any(|h| c.validators().proposer_for(h, 0) == Some(x_id))
    {
        base += 1;
        assert!(
            base < 40,
            "deterministic schedule must offer a window quickly"
        );
    }
    c.run_until(base, BUDGET_MS).await;
    (c, base)
}

/// Assert the shared post-restart invariants: every up node finalized the same
/// contiguous heights with ONE block per height, and nobody double-voted.
fn assert_common_finality(c: &consensus_cluster::ClusterReport, target: u64) {
    for n in &c.nodes {
        assert!(
            n.finalized_height >= target,
            "node {} stalled at {} (target {target}): {}",
            n.index,
            n.finalized_height,
            c.diagnostics()
        );
        for (i, (h, _)) in n.finalized.iter().enumerate() {
            assert_eq!(
                *h,
                (i as u64) + 1,
                "node {} finalized a non-contiguous height sequence",
                n.index
            );
        }
    }
    // One block per height across all nodes (no fork).
    for (height, entries) in c.finalized_by_height() {
        let mut hashes: Vec<[u8; 32]> = entries.iter().map(|(_, h)| *h).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            1,
            "FORK at height {height}: nodes finalized different blocks"
        );
    }
    let dbl = c.double_votes(&[]);
    assert!(
        dbl.is_empty(),
        "EQUIVOCATION after restart: {dbl:?}\n{}",
        c.diagnostics()
    );
}

#[tokio::test]
async fn one_restarted_node_adopts_forward_round_commits_and_finality_resumes() {
    let (mut c, base) = single_restart_cluster().await;
    let x = 2usize;
    c.set_down(x, true);
    let target = base + CATCH_UP_HEIGHTS;
    let report = c.run_until(target, BUDGET_MS).await;
    assert!(
        report.nodes[0].finalized_height >= target && report.nodes[1].finalized_height >= target,
        "the 2+1 quorum must keep producing while X is out: {}",
        report.diagnostics()
    );
    assert!(
        c.retained_commits()
            .iter()
            .any(|(h, _, cert)| *h > base && cert.round > 0),
        "the down window must decide at least one height in a round above X's restored \
         round 0 (otherwise this scenario does not exercise forward-round catch-up)"
    );

    // Restart X from its PERSISTED tip `base` (the heights above it are cleared
    // from memory) and push the retained commits, exactly like a peer's
    // `Committed` rebroadcast.
    c.restart_member(x, Some(base)).await;
    c.set_down(x, false);
    c.deliver_committed_above(x, base);

    let report = c.run_until(target + 2, BUDGET_MS).await;
    assert_common_finality(&report, target + 2);
}

// ===========================================================================
// 3. Two nodes restart at once (one behind, one at the tip).
// ===========================================================================

#[tokio::test]
async fn two_restarted_nodes_reconverge_and_finality_resumes() {
    let (mut c, base) = single_restart_cluster().await;
    let x = 2usize;
    let y = 1usize;
    c.set_down(x, true);
    let target = base + CATCH_UP_HEIGHTS;
    let report = c.run_until(target, BUDGET_MS).await;
    assert!(
        report.nodes[0].finalized_height >= target && report.nodes[1].finalized_height >= target,
        "the 2+1 quorum must keep producing while X is out: {}",
        report.diagnostics()
    );
    assert!(
        c.retained_commits()
            .iter()
            .any(|(h, _, cert)| *h > base && cert.round > 0),
        "the down window must decide at least one height in a round above X's restored round 0"
    );

    // BOTH nodes restart at the same instant: X from its stale persisted tip,
    // Y from the live tip. The cluster then has to re-anchor on them again.
    c.restart_member(x, Some(base)).await;
    c.restart_member(y, None).await;
    c.set_down(x, false);
    c.deliver_committed_above(x, base);

    let report = c.run_until(target + 2, BUDGET_MS).await;
    assert_common_finality(&report, target + 2);
}

// ===========================================================================
// 4. Runtime backstop: no proposal above our own finalized parent.
// ===========================================================================

#[tokio::test]
async fn a_runtime_above_its_finalized_parent_builds_no_proposal() {
    let (ks, fks) = falcon_votes::falcon_set(1);
    assert_eq!(fks.len(), 1);
    let vs = vs_of(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, st, 1);
    assert!(rt.is_proposer(), "solo validator owns every slot");
    // Positive control: the one legal relationship builds a block.
    rt.finalized.push((2, [0x22u8; 32]));
    rt.hc = stellereum::consensus::HeightConsensus::new(3, rt.validators.clone());
    rt.hc.set_parent_hash([0x22u8; 32]);
    assert!(
        rt.propose(1).await.is_some(),
        "a proposal at finalized_tip + 1 is legal"
    );

    // Restart shape: engine/consensus at 6 while the finalized pointer is 2.
    // Building here would skip heights 3..5 and use block 2 as the parent.
    rt.hc = stellereum::consensus::HeightConsensus::new(6, rt.validators.clone());
    rt.hc.set_parent_hash([0x22u8; 32]);
    assert!(
        rt.propose(2).await.is_none(),
        "a runtime above its own finalized parent must never propose"
    );
}
