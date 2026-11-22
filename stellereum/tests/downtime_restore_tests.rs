//! DOWNTIME-RESTORE: rebuild the parent-decision evidence across a restart.
//!
//! THE LIVE DEFECT (testnet, node A restarted at its tip): every peer rejected
//! its proposal with
//!
//! ```text
//! [consensus] rejected proposal ...: proposal: block at height 13219 omits
//! the downtime evidence for decided height 13218
//! ```
//!
//! `ValidatorRuntime::last_decision` (the stash `propose()` reads to embed the
//! canonical downtime QC for the parent height) was IN-MEMORY ONLY. A plain
//! restart at the tip has no adopt and no catch-up, so the stash stayed `None`
//! and the restarted proposer emitted `last_qc: None`. Peers that DID decide
//! the parent reject an omission outright (the evidence exists), so the height
//! could not finalize while that node held the slot.
//!
//! These tests drive a real 3-validator cluster, rebuild one member's runtime
//! from a `Storage` written with its finalized chain (in-memory
//! `last_decision` is not carried over - exactly a process restart), and pin:
//!
//! 1. the restarted proposer reconstructs the evidence from the PERSISTED
//!    finalized block + its embedded precommit QC, its proposal names the
//!    parent height/hash and carries a real precommit quorum, the other two
//!    accept it, and the cluster finalizes `tip + 1`;
//! 2. a persisted tip WITHOUT an embedded QC fails CLOSED: the node emits no
//!    proposal at all, then after it adopts a valid peer decision (which
//!    restores the evidence) it proposes correctly again.
//!
//! Determinism: virtual-clock cluster, seeded keys/messages, one temp store per
//! test.

use std::path::PathBuf;

use stellereum::consensus::{BlockHash, ValidatorId, VoteKind};
use stellereum::sharding::Block;
use stellereum::storage::Storage;

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::ConsensusCluster;

/// A few round timeouts are enough for every height here; a stall is reported.
const BUDGET_MS: u64 = 240_000;

fn temp_store(tag: &str) -> (PathBuf, Storage) {
    let dir = std::env::temp_dir().join(format!(
        "stell-downtime-restore-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = Storage::open(&dir).expect("open temp store");
    (dir, store)
}

/// Write a member's finalized chain (bodies + tip pointer) exactly as the
/// production finalize path persists it: the stored tip body carries the
/// precommit QC attached at finalization.
fn persist_finalized_chain(
    cluster: &ConsensusCluster,
    index: usize,
    store: &Storage,
) -> (u64, BlockHash) {
    let rt = cluster.runtime(index);
    let (tip, tip_hash) = *rt
        .finalized
        .last()
        .expect("member has a finalized tip before the restart");
    for (height, hash) in rt.finalized.iter() {
        let block = rt
            .blocks
            .get(hash)
            .unwrap_or_else(|| panic!("no retained body for finalized height {height}"));
        store.put_block(block).expect("persist finalized body");
    }
    store
        .set_finalized(tip, &tip_hash)
        .expect("persist finalized pointer");
    (tip, tip_hash)
}

fn proposer_index(cluster: &ConsensusCluster, height: u64, round: u32) -> usize {
    let proposer: ValidatorId = cluster
        .validators()
        .proposer_for(height, round)
        .expect("non-empty set has a proposer");
    (0..cluster.len())
        .find(|&i| cluster.runtime(i).id == proposer)
        .expect("every proposer is a cluster member")
}

fn finalized_block(cluster: &ConsensusCluster, index: usize, height: u64) -> Block {
    let rt = cluster.runtime(index);
    let hash = rt
        .finalized
        .iter()
        .find(|(h, _)| *h == height)
        .map(|(_, h)| *h)
        .unwrap_or_else(|| panic!("member {index} has not finalized height {height}"));
    rt.blocks
        .get(&hash)
        .cloned()
        .unwrap_or_else(|| panic!("no retained body for finalized height {height}"))
}

fn assert_evidence(block: &Block, expected_parent: (u64, BlockHash)) {
    let qc = block
        .last_qc
        .as_ref()
        .expect("proposal must carry the canonical downtime evidence");
    assert_eq!(
        (qc.height, qc.block_hash),
        (expected_parent.0, Some(expected_parent.1)),
        "downtime evidence must name the parent height and hash"
    );
    assert_eq!(
        qc.kind,
        VoteKind::Precommit,
        "downtime evidence must be a precommit quorum, not prevotes"
    );
    assert_eq!(
        qc.shard_id, block.shard_id,
        "downtime evidence must belong to the block's shard"
    );
}

// ===========================================================================
// 1. The live defect: restart at the tip, become the proposer, carry the
//    evidence, and let the other two accept.
// ===========================================================================

#[tokio::test]
async fn restarted_proposer_reconstructs_downtime_evidence_from_persisted_tip() {
    let mut cluster = ConsensusCluster::new(3, &[1, 1, 1]);
    cluster.seed_transactions(16).await;
    let report = cluster.run_until(5, BUDGET_MS).await;
    assert!(
        report.common_height >= 5,
        "precondition: cluster must produce: {}",
        report.diagnostics()
    );
    // Warm-up refusals (the harness starts proposals before the first timestamp
    // is established) are baseline noise; only NEW refusals of the restarted
    // proposer matter below.
    let refusals_before: Vec<u64> = report.nodes.iter().map(|n| n.proposals_refused).collect();

    let tip = cluster.runtime(0).finalized.last().unwrap().0;
    let index = proposer_index(&cluster, tip + 1, 0);

    let (dir, store) = temp_store("positive");
    let (persisted_tip, tip_hash) = persist_finalized_chain(&cluster, index, &store);
    assert_eq!(persisted_tip, tip);

    // PROCESS RESTART: the runtime is rebuilt from the store only. Nothing
    // in memory (including `last_decision`) survives.
    cluster
        .restart_member_from_store(index, &store)
        .await
        .expect("restart from persisted store");
    let restarted = cluster.runtime(index);
    assert!(
        !restarted.parent_evidence_missing,
        "the persisted tip body carries its precommit QC: the decision evidence must be \
         reconstructible"
    );
    assert_eq!(
        restarted.last_decision.as_ref().map(|(h, _, _)| *h),
        Some(tip),
        "boot must rebuild `last_decision` for the PERSISTED finalized tip"
    );
    let restarted_id = restarted.id;

    // Node `index` owns the next slot: its proposal must carry the evidence,
    // and the two peers that know the parent decision must accept it.
    let report = cluster.run_until(tip + 1, BUDGET_MS).await;
    assert!(
        report.nodes.iter().all(|n| n.finalized_height > tip),
        "the cluster must finalize tip + 1 with the restarted proposer: {}",
        report.diagnostics()
    );
    for n in report.nodes.iter().filter(|n| n.index != index) {
        assert_eq!(
            n.proposals_refused,
            refusals_before[n.index],
            "peer {} refused the restarted proposer's block: {}",
            n.index,
            report.diagnostics()
        );
    }

    let block = finalized_block(&cluster, index, tip + 1);
    assert_eq!(
        block.proposer,
        restarted_id,
        "the restarted node must have authored height {} (it owned the round-0 slot)",
        tip + 1
    );
    assert_evidence(&block, (tip, tip_hash));

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 2. Fail closed when the persisted tip cannot prove the parent decision.
// ===========================================================================

#[tokio::test]
async fn missing_tip_qc_refuses_to_propose_then_adoption_restores_evidence() {
    let mut cluster = ConsensusCluster::new(3, &[1, 1, 1]);
    cluster.seed_transactions(16).await;
    let report = cluster.run_until(5, BUDGET_MS).await;
    assert!(
        report.common_height >= 5,
        "precondition: cluster must produce: {}",
        report.diagnostics()
    );

    let tip = cluster.runtime(0).finalized.last().unwrap().0;
    let index = proposer_index(&cluster, tip + 1, 0);
    let (dir, store) = temp_store("negative");
    let (persisted_tip, tip_hash) = persist_finalized_chain(&cluster, index, &store);
    assert_eq!(persisted_tip, tip);

    // Simulate an OLD stored body that predates embedded decision proofs. The
    // QC is excluded from `compute_hash`, so this is the SAME finalized block.
    let mut stripped = store
        .get_block(&tip_hash)
        .expect("read persisted tip")
        .expect("tip body present");
    stripped.precommit_qc = None;
    assert_eq!(
        stripped.compute_hash(),
        tip_hash,
        "removing the attached QC must not change the block identity"
    );
    store.put_block(&stripped).expect("persist stripped tip");

    cluster
        .restart_member_from_store(index, &store)
        .await
        .expect("restart from persisted store");
    let restarted = cluster.runtime(index);
    assert!(
        restarted.last_decision.is_none(),
        "without an embedded QC there is no locally verifiable parent decision"
    );
    assert!(
        restarted.parent_evidence_missing,
        "boot must arm the fail-closed proposal gate"
    );
    assert!(
        cluster.propose_once(index).await.is_none(),
        "a node that cannot prove the parent decision must NOT emit a block omitting \
         required downtime evidence"
    );

    // The other two decide tip + 1. The restarted node adopts their valid
    // decision; that restores the evidence from verified peer data.
    let report = cluster.run_until(tip + 1, BUDGET_MS).await;
    assert!(
        report.nodes.iter().all(|n| n.finalized_height > tip),
        "the two healthy peers must still finalize tip + 1: {}",
        report.diagnostics()
    );
    let after_adopt = cluster.runtime(index);
    assert_eq!(
        after_adopt.last_decision.as_ref().map(|(h, _, _)| *h),
        Some(tip + 1),
        "adopting a verified block restores the parent-decision stash"
    );
    assert!(
        !after_adopt.parent_evidence_missing,
        "the fail-closed gate must clear once a verified decision is recorded"
    );
    let recovered_id = after_adopt.id;

    // Find the restarted node's next round-0 slot and prove it proposes a
    // valid, evidence-carrying block again (no permanent liveness loss).
    let mut next_slot = tip + 2;
    while proposer_index(&cluster, next_slot, 0) != index {
        next_slot += 1;
        assert!(
            next_slot < tip + 20,
            "deterministic schedule must offer the restarted node a slot quickly"
        );
    }
    let report = cluster.run_until(next_slot, BUDGET_MS).await;
    assert!(
        report.nodes.iter().all(|n| n.finalized_height >= next_slot),
        "cluster must finalize the restarted node's next slot: {}",
        report.diagnostics()
    );
    let block = finalized_block(&cluster, index, next_slot);
    assert_eq!(
        block.proposer, recovered_id,
        "the recovered node must author its own slot again"
    );
    let parent_hash = cluster
        .runtime(index)
        .finalized
        .iter()
        .find(|(h, _)| *h == next_slot - 1)
        .map(|(_, h)| *h)
        .expect("parent of the recovered proposal is finalized");
    assert_evidence(&block, (next_slot - 1, parent_hash));

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
