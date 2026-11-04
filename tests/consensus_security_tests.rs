//! Consensus security tests: BFT safety & liveness under Byzantine faults.
//!
//! Safety  — no two conflicting blocks can ever both reach a quorum.
//! Liveness — the network keeps finalizing despite up to < 1/3 Byzantine power.
//! Plus: view-change recovery, equivocation evidence, lock enforcement, QC checks.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{HeightConsensus, QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{Cluster, ValidatorRuntime};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}

// ============================================================================
// Quorum math: strictly more than 2/3, for a range of validator counts.
// ============================================================================
#[test]
fn quorum_threshold_is_two_thirds_plus_one() {
    for (n, expected) in [
        (1usize, 1u64),
        (2, 2),
        (3, 3),
        (4, 3),
        (5, 4),
        (6, 5),
        (7, 5),
        (10, 7),
    ] {
        let ks = keys(n);
        assert_eq!(vset(&ks).quorum_power(), expected, "n={n}");
    }
}

// ============================================================================
// SAFETY: with 4 validators (quorum 3) and 1 Byzantine, two conflicting blocks
// can never BOTH reach a quorum — the honest majority prevents a fork.
// ============================================================================
#[test]
fn safety_no_conflicting_quorum_with_one_byzantine() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs.clone());

    let a = bh(1);
    let b = bh(2);

    // 3 validators prevote A (2 honest + 1 that will equivocate)
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    assert_eq!(
        hc.try_prevote_quorum(),
        Some(Some(a)),
        "A must reach quorum"
    );

    // Now the same 3 validators (equivocators) + the 4th try to build quorum on B
    for k in &ks {
        let _ = hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(b)));
    }

    let set = hc.prevote_set(0).unwrap();
    assert!(set.quorum_reached(Some(a), &vs), "A keeps its quorum");
    assert!(
        !set.quorum_reached(Some(b), &vs),
        "B must NOT reach quorum (safety)"
    );
    // The conflicting votes are recorded as equivocation evidence
    assert!(
        !hc.equivocations().is_empty(),
        "equivocation must be recorded"
    );
}

// ============================================================================
// SAFETY: a locked validator never prevotes a conflicting value in a later round.
// ============================================================================
#[test]
fn safety_lock_prevents_conflicting_prevote() {
    let ks = keys(4);
    let mut hc = HeightConsensus::new(1, vset(&ks));
    hc.locked = Some((bh(1), 0)); // locked on A
    hc.round = 1;
    hc.proposal = Some((hc.proposer().unwrap(), bh(2))); // proposer offers B
    assert_eq!(
        hc.decide_prevote(),
        None,
        "locked validator must prevote nil for a conflicting value"
    );
    hc.proposal = Some((hc.proposer().unwrap(), bh(1)));
    assert_eq!(
        hc.decide_prevote(),
        Some(bh(1)),
        "may prevote the locked value"
    );
}

// ============================================================================
// LIVENESS: 4 validators, 1 silent -> the remaining 3 (a quorum) still finalize.
// ============================================================================
#[tokio::test]
async fn liveness_with_one_silent_validator() {
    let ks = keys(4);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();

    let mut nodes = Vec::new();
    for k in &ks {
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(from, 1_000_000)).await;
        nodes.push((k.clone(), st));
    }
    let mut cluster = Cluster::new(nodes);
    cluster
        .broadcast_tx(Transaction::sign(&user, [9u8; 32], 10, 0, 0, 1, 1))
        .await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    let target = block.compute_hash();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let er = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), er).await.unwrap();
        }
    }
    // only the first 3 vote (quorum = 3); the 4th stays silent
    let prevotes: Vec<Vote> = cluster
        .nodes
        .iter()
        .take(3)
        .filter_map(|n| n.make_prevote())
        .collect();
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<Vote> = cluster
        .nodes
        .iter_mut()
        .take(3)
        .filter_map(|n| n.make_precommit())
        .collect();
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }
    let mut finalized = 0;
    for n in cluster.nodes.iter_mut().take(3) {
        if n.try_finalize().await == Some(target) {
            finalized += 1;
        }
    }
    assert_eq!(finalized, 3, "quorum must finalize with 1/4 silent");
}

// ============================================================================
// LIVENESS: 7 validators (quorum 5), 2 silent -> the remaining 5 still finalize.
// ============================================================================
#[tokio::test]
async fn liveness_with_two_silent_of_seven() {
    let ks = keys(7);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let mut nodes = Vec::new();
    for k in &ks {
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(from, 1_000_000)).await;
        nodes.push((k.clone(), st));
    }
    let mut cluster = Cluster::new(nodes);
    cluster
        .broadcast_tx(Transaction::sign(&user, [9u8; 32], 10, 0, 0, 1, 1))
        .await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    let target = block.compute_hash();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let er = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), er).await.unwrap();
        }
    }
    // 5 of 7 vote (quorum 5); 2 silent
    let prevotes: Vec<Vote> = cluster
        .nodes
        .iter()
        .take(5)
        .filter_map(|n| n.make_prevote())
        .collect();
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<Vote> = cluster
        .nodes
        .iter_mut()
        .take(5)
        .filter_map(|n| n.make_precommit())
        .collect();
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }
    let mut finalized = 0;
    for n in cluster.nodes.iter_mut().take(5) {
        if n.try_finalize().await == Some(target) {
            finalized += 1;
        }
    }
    assert_eq!(finalized, 5, "5/7 must finalize with 2 silent");
}

// ============================================================================
// LIVENESS: view change recovers after a round with no quorum.
// ============================================================================
#[test]
fn view_change_recovers_liveness() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs.clone());
    let a = bh(1);

    // Round 0: only 2 prevote (below quorum 3) -> no quorum
    for k in ks.iter().take(2) {
        hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    assert_eq!(hc.try_prevote_quorum(), None, "no quorum in round 0");

    // View change to round 1
    hc.next_round();
    assert_eq!(hc.round, 1);
    assert!(hc.proposal.is_none());

    // Round 1: 3 prevote -> quorum
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, 1, 1, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    assert_eq!(
        hc.try_prevote_quorum(),
        Some(Some(a)),
        "quorum in round 1 after view change"
    );
}

// ============================================================================
// Equivocation: a double-vote is recorded as slashing evidence.
// ============================================================================
#[test]
fn equivocation_evidence_collected() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs);
    let _ = hc.add_prevote(Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(1))));
    let _ = hc.add_prevote(Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(2))));
    let ev = hc.equivocations();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, ks[0].verifying_key().to_bytes());
}

// ============================================================================
// A QC with duplicate signers must not fake a quorum.
// ============================================================================
#[test]
fn qc_rejects_duplicate_signers() {
    let ks = keys(4);
    let vs = vset(&ks);
    let a = bh(9);
    let v = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(a));
    let sigs = vec![
        (v.voter, v.signature.clone()),
        (v.voter, v.signature.clone()),
        (v.voter, v.signature.clone()),
    ];
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(a),
        signatures: sigs,
    };
    assert!(!qc.verify(&vs), "duplicate signers must not fake a quorum");
}

// ============================================================================
// A QC with a tampered block hash must fail (signatures are bound to content).
// ============================================================================
#[test]
fn qc_rejects_tampered_block_hash() {
    let ks = keys(4);
    let vs = vset(&ks);
    let a = bh(9);
    let sigs: Vec<([u8; 32], Vec<u8>)> = ks
        .iter()
        .take(3)
        .map(|k| {
            let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(a));
            (v.voter, v.signature)
        })
        .collect();
    let mut qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(a),
        signatures: sigs,
    };
    assert!(qc.verify(&vs));
    qc.block_hash = Some(bh(8)); // tamper
    assert!(!qc.verify(&vs), "tampered QC must fail");
}

// ============================================================================
// A validator runtime never finalizes without a quorum.
// ============================================================================
#[tokio::test]
async fn no_finality_without_quorum() {
    let ks = keys(4);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let mut nodes = Vec::new();
    for k in &ks {
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(from, 1_000_000)).await;
        nodes.push((k.clone(), st));
    }
    let mut cluster = Cluster::new(nodes);
    cluster
        .broadcast_tx(Transaction::sign(&user, [9u8; 32], 1, 0, 0, 1, 1))
        .await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let er = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), er).await.unwrap();
        }
    }
    // only 2 of 4 vote -> below quorum
    let prevotes: Vec<Vote> = cluster
        .nodes
        .iter()
        .take(2)
        .filter_map(|n| n.make_prevote())
        .collect();
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<Vote> = cluster
        .nodes
        .iter_mut()
        .take(2)
        .filter_map(|n| n.make_precommit())
        .collect();
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }
    for n in cluster.nodes.iter_mut() {
        assert_eq!(
            n.try_finalize().await,
            None,
            "must not finalize below quorum"
        );
    }
}

// ============================================================================
// A proposal is bound to its proposer: a non-proposer's block is rejected.
// ============================================================================
#[tokio::test]
async fn proposal_from_wrong_proposer_rejected() {
    let ks = keys(4);
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(
        ks[0].verifying_key().to_bytes(),
        1_000_000,
    ))
    .await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset(&ks), st, 1);

    // The real proposer for (1,0) is deterministic; make a block signed by someone else.
    let real_proposer = rt.hc.proposer().unwrap();
    let impostor = ks
        .iter()
        .find(|k| k.verifying_key().to_bytes() != real_proposer)
        .unwrap();
    let mut bad = stellereum::sharding::Block {
        shard_id: 0,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: impostor.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    bad.sign_block(impostor);
    assert!(
        rt.on_proposal(impostor.verifying_key().to_bytes(), bad, rt.hc.round)
            .await
            .is_err(),
        "impostor proposal must be rejected"
    );
}
