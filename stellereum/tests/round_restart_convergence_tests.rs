//! Round convergence after a single-node restart / freeze (audit F3).
//!
//! The live ruleset-6 shape: one node restored a watermark round far above its
//! peers (~130 vs ~5), proposals in the 128-135 band were refused as
//! `stale round`, and the rounds climbed forever while height 3396 stayed
//! parked. The cause was the corroboration constant `2`: at N=3 with exactly
//! one node ahead, `supporting_peers_count(target) >= 2` was unsatisfiable —
//! reaching two requires the convergence it is supposed to cause. The BFT
//! bound is `f + 1` (N=3 -> 1).
//!
//! These tests pin the four properties the fix must hold:
//!   1. a node held at round 0 chases a single verified peer at round 40 and
//!      finalises with the cluster;
//!   2. a node restored at round 130 while its peers are at round 5 does not
//!      strand the cluster — the peers chase it and every height finalises;
//!   3. one Byzantine validator alone still cannot ratchet an honest node
//!      past the per-round / per-height jump budgets;
//!   4. a node holding a live (unlocked) proposal still chases; the
//!      accept-wipe livelock is not reintroduced (after the chase it accepts
//!      and votes the new round's proposal).

use std::sync::Arc;

use stellereum::consensus::{
    Round, ValidatorId, ValidatorSet, Vote, VoteKind, MAX_PEER_ROUND_ADVANCE_PER_HEIGHT,
    MAX_SYNC_JUMPS_PER_ROUND, ROUND_LOOKBACK,
};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::state_engine::InMemoryStateEngine;

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

struct Node {
    rt: ValidatorRuntime,
    id: ValidatorId,
}

async fn three_nodes() -> Vec<Node> {
    let (ks, fks) = falcon_votes::falcon_set(3);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1u64))
            .collect(),
    );
    assert_eq!(vset.quorum_power(), 3, "N=3 needs unanimity");
    let mut nodes = Vec::with_capacity(3);
    for i in 0..3 {
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        let rt = ValidatorRuntime::new(ks[i].clone(), vset.clone(), state, 1)
            .with_falcon_key(fks[i].clone())
            .with_deterministic_sim_signing();
        nodes.push(Node {
            rt,
            id: ks[i].verifying_key().to_bytes(),
        });
    }
    nodes
}

fn proposer_index(nodes: &[Node], round: Round) -> usize {
    let p = nodes[0]
        .rt
        .validators
        .proposer_for(nodes[0].rt.hc.height, round)
        .expect("a proposer exists for every round");
    nodes
        .iter()
        .position(|n| n.id == p)
        .expect("the proposer is a member")
}

fn advance_to(nodes: &mut [Node], indices: &[usize], target: Round) {
    for &i in indices {
        while nodes[i].rt.hc.round < target {
            nodes[i].rt.hc.next_round();
        }
        assert_eq!(nodes[i].rt.hc.round, target);
    }
}

#[test]
fn corroboration_threshold_is_f_plus_one() {
    use stellereum::consensus::round_corroboration_threshold;

    // N=3 accepts one verified peer (the live fix); N=4..6 needs two;
    // N=7..9 needs three. The floor is always at least one.
    assert_eq!(round_corroboration_threshold(0), 1);
    assert_eq!(round_corroboration_threshold(1), 1);
    assert_eq!(round_corroboration_threshold(2), 1);
    assert_eq!(round_corroboration_threshold(3), 1);
    assert_eq!(round_corroboration_threshold(4), 2);
    assert_eq!(round_corroboration_threshold(5), 2);
    assert_eq!(round_corroboration_threshold(6), 2);
    assert_eq!(round_corroboration_threshold(7), 3);
    assert_eq!(round_corroboration_threshold(9), 3);
    assert_eq!(round_corroboration_threshold(10), 4);
}

// ===========================================================================
// 1. One node at round 0, the peers at ~40: one verified vote is enough.
// ===========================================================================

#[tokio::test]
async fn held_node_chases_one_verified_round_40_and_finalises() {
    let mut nodes = three_nodes().await;

    // Pick a target in the live ~40 band whose proposer is NOT the held node,
    // so the held node has to chase before it can accept the proposal.
    let mut target = 40u32;
    while proposer_index(&nodes, target) == 0 {
        target += 1;
    }
    assert!(target <= 48, "target must stay in the ~40 band");
    assert!(
        target - nodes[0].rt.hc.round <= MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK,
        "the chase must fit the documented per-round budget"
    );

    // The two peers (the network) advance to the target, using the real
    // view-change path.
    advance_to(&mut nodes, &[1, 2], target);

    let leader = proposer_index(&nodes, target);
    assert_ne!(leader, 0, "the proposer is one of the advancing peers");
    let other = if leader == 1 { 2 } else { 1 };
    let leader_id = nodes[leader].id;

    let block = nodes[leader]
        .rt
        .propose(1)
        .await
        .expect("the scheduled peer proposes at the target round");
    let bh = block.compute_hash();
    nodes[other]
        .rt
        .on_proposal(leader_id, block.clone(), target)
        .await
        .expect("the other peer accepts the proposal");

    // The held node hears ONE verified value vote at the target, before it
    // has the body. On HEAD (constant two) this bought +8 and then the replay
    // dedup stuck it; with f+1=1 it reaches the target inside the budget.
    let leader_vote = nodes[leader]
        .rt
        .make_prevote()
        .expect("the proposer prevotes its body");
    assert_eq!(leader_vote.round, target);
    nodes[0]
        .rt
        .on_prevote(leader_vote.clone())
        .expect("the verified vote is admissible");
    assert_eq!(
        nodes[0].rt.hc.round, target,
        "one verified reporter at N=3 (f+1=1) must pull the held node to the target"
    );

    nodes[leader].rt.on_prevote(leader_vote.clone()).unwrap();
    nodes[other].rt.on_prevote(leader_vote.clone()).unwrap();

    let other_vote = nodes[other]
        .rt
        .make_prevote()
        .expect("the other peer prevotes the same body");
    assert_eq!(other_vote.round, target);
    for n in nodes.iter_mut() {
        n.rt.on_prevote(other_vote.clone()).unwrap();
    }

    nodes[0]
        .rt
        .on_proposal(leader_id, block.clone(), target)
        .await
        .expect("the caught-up node accepts the proposal at its new round");
    let held_vote = nodes[0]
        .rt
        .make_prevote()
        .expect("the caught-up node prevotes the body");
    assert_eq!(held_vote.round, target);
    for n in nodes.iter_mut() {
        n.rt.on_prevote(held_vote.clone()).unwrap();
    }

    let precommits: Vec<Vote> = nodes
        .iter_mut()
        .map(|n| {
            n.rt.make_precommit()
                .expect("the polka is precommitted at its own round")
        })
        .collect();
    assert!(
        precommits.iter().all(|p| p.round == target),
        "precommits follow the polka round"
    );
    for v in &precommits {
        for n in nodes.iter_mut() {
            n.rt.on_precommit(v.clone()).unwrap();
        }
    }
    for (i, n) in nodes.iter_mut().enumerate() {
        assert_eq!(
            n.rt.try_finalize().await,
            Some(bh),
            "node {i} must finalise the body the cluster prevoted"
        );
    }
}

// ===========================================================================
// 2. The exact live shape: one restored node at round ~130, peers at round 5.
// ===========================================================================

#[tokio::test]
async fn restored_round_130_does_not_strand_peers_at_round_5() {
    let mut nodes = three_nodes().await;

    // The restored node comes back at its persisted watermark round. Choose a
    // round in the live band where the RESTORED node owns the proposal slot,
    // so its first post-restart message can carry the value the peers need.
    let mut restored_round = 130u32;
    while proposer_index(&nodes, restored_round) != 0 {
        restored_round += 1;
    }
    assert!(
        restored_round <= 140,
        "the restored round must stay in the live ~130 band"
    );
    // The other two nodes are in the network's early rounds.
    advance_to(&mut nodes, &[1, 2], 5);
    nodes[0].rt.hc.round = restored_round;
    assert_eq!(nodes[0].rt.hc.round, restored_round);
    assert_eq!(nodes[1].rt.hc.round, 5);
    assert_eq!(nodes[2].rt.hc.round, 5);

    let block = nodes[0]
        .rt
        .propose(1)
        .await
        .expect("the restored proposer serves its round");
    let bh = block.compute_hash();
    let restored_id = nodes[0].id;
    let restored_vote = nodes[0]
        .rt
        .make_prevote()
        .expect("the restored proposer prevotes its body");
    assert_eq!(restored_vote.round, restored_round);
    nodes[0].rt.on_prevote(restored_vote.clone()).unwrap();

    // The single verified post-restart vote is the only round evidence the
    // peers get. The per-round jump budget carries each peer +64 (5 -> 69);
    // after its own view change refills the budget, the retransmitted vote
    // carries it the rest of the way (~130). On HEAD each stopped at +8
    // (5 -> 13), and the replay dedup then froze it there forever.
    let per_round = MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK;
    assert!(
        restored_round - 5 <= MAX_PEER_ROUND_ADVANCE_PER_HEIGHT,
        "the whole catch-up must fit the per-height budget"
    );
    for i in [1usize, 2] {
        nodes[i]
            .rt
            .on_prevote(restored_vote.clone())
            .expect("the restored node's vote is admissible");
        assert_eq!(
            nodes[i].rt.hc.round,
            5 + per_round,
            "peer {i} must consume the full per-round budget toward the restored round"
        );
        nodes[i].rt.hc.next_round();
        nodes[i]
            .rt
            .on_prevote(restored_vote.clone())
            .expect("the retransmitted vote is admissible");
        assert_eq!(
            nodes[i].rt.hc.round, restored_round,
            "peer {i} must chase the restored node's verified round"
        );
        nodes[i]
            .rt
            .on_proposal(restored_id, block.clone(), restored_round)
            .await
            .expect("the caught-up peer accepts the restored proposal");
    }

    let peer_votes: Vec<(usize, Vote)> = [1usize, 2]
        .into_iter()
        .map(|i| {
            let v = nodes[i]
                .rt
                .make_prevote()
                .expect("the caught-up peer prevotes the proposal");
            assert_eq!(v.round, restored_round);
            (i, v)
        })
        .collect();
    for (_, v) in &peer_votes {
        for n in nodes.iter_mut() {
            n.rt.on_prevote(v.clone()).unwrap();
        }
    }

    let precommits: Vec<Vote> = nodes
        .iter_mut()
        .map(|n| {
            n.rt.make_precommit()
                .expect("the polka is precommitted at its own round")
        })
        .collect();
    assert!(
        precommits.iter().all(|p| p.round == restored_round),
        "precommits follow the polka round"
    );
    for v in &precommits {
        for n in nodes.iter_mut() {
            n.rt.on_precommit(v.clone()).unwrap();
        }
    }
    for (i, n) in nodes.iter_mut().enumerate() {
        assert_eq!(
            n.rt.try_finalize().await,
            Some(bh),
            "node {i} must finalise after the restart convergence"
        );
    }
}

// ===========================================================================
// 3. Negative: one Byzantine validator alone is still bounded by the budgets.
// ===========================================================================

#[tokio::test]
async fn single_byzantine_cannot_ratchet_past_the_budgets() {
    let (mut nodes, ks, fks) = {
        let nodes = three_nodes().await;
        let (ks, fks) = falcon_votes::falcon_set(3);
        (nodes, ks, fks)
    };
    let start = nodes[0].rt.hc.round;
    let height = nodes[0].rt.hc.height;

    // 80 rounds of view changes, each followed by a burst of fresh, verified,
    // far-ahead votes from the SAME Byzantine validator.
    let rounds = 80u32;
    for k in 0..rounds {
        for j in 0..10u32 {
            let target = start + 500 + k * 1_000 + j;
            let v = falcon_votes::fvote(
                &ks[1],
                &fks[1],
                height,
                target,
                VoteKind::Prevote,
                None,
            );
            let _ = nodes[0].rt.on_prevote(v);
        }
        nodes[0].rt.hc.next_round();
    }

    // Own view changes are not peer-driven: the cluster's own timeouts may
    // advance one round each, but the liar's influence stops at the lifetime
    // budget.
    let ceiling = start + MAX_PEER_ROUND_ADVANCE_PER_HEIGHT + rounds;
    assert!(
        nodes[0].rt.hc.round <= ceiling,
        "one liar ratcheted to {} (ceiling {ceiling}): the per-height budget must bound it",
        nodes[0].rt.hc.round
    );
    // The budget is spent: one more fresh far vote moves nothing.
    let before = nodes[0].rt.hc.round;
    let extra = falcon_votes::fvote(
        &ks[1],
        &fks[1],
        height,
        start + 1_000_000,
        VoteKind::Prevote,
        None,
    );
    let _ = nodes[0].rt.on_prevote(extra);
    assert_eq!(
        nodes[0].rt.hc.round, before,
        "past the per-height budget a lone liar buys nothing"
    );
}

// ===========================================================================
// 4. A live proposal does not block the chase (accept-wipe livelock guard).
// ===========================================================================

#[tokio::test]
async fn live_proposal_still_chases_and_votes_the_new_round() {
    let mut nodes = three_nodes().await;

    // Give the held node a real live proposal for its current round.
    let r0 = nodes[0].rt.hc.round;
    let p0 = proposer_index(&nodes, r0);
    let p0_id = nodes[p0].id;
    let first = nodes[p0]
        .rt
        .propose(1)
        .await
        .expect("the round's proposer builds a body");
    if p0 != 0 {
        nodes[0]
            .rt
            .on_proposal(p0_id, first.clone(), r0)
            .await
            .expect("the held node accepts the live proposal");
    }
    assert!(
        nodes[0].rt.hc.has_live_proposal(),
        "test setup: the held node must hold a live proposal"
    );
    assert!(nodes[0].rt.hc.locked.is_none(), "the proposal is unlocked");

    // The network moves ~40 rounds ahead. A verified peer vote names a
    // DIFFERENT value (nil), so the old unlocked proposal is dead: the chase
    // must still run (and wipe it), not sit on the stale proposal.
    let mut target = r0 + 40;
    while proposer_index(&nodes, target) == 0 {
        target += 1;
    }
    advance_to(&mut nodes, &[1, 2], target);
    let ahead = nodes[1]
        .rt
        .make_prevote()
        .expect("the ahead peer has a nil prevote");
    assert_eq!(ahead.round, target);
    nodes[0]
        .rt
        .on_prevote(ahead)
        .expect("the verified vote is admissible");

    assert_eq!(
        nodes[0].rt.hc.round, target,
        "a live proposal must not block the chase when the proposal is not our lock"
    );
    assert!(
        !nodes[0].rt.hc.has_live_proposal(),
        "the dead unlocked proposal is wiped (accept-wipe livelock protection)"
    );

    // Convergence continues: the target round's proposer proposes and the
    // caught-up node arms and votes it instead of sitting proposalless.
    let leader = proposer_index(&nodes, target);
    let leader_id = nodes[leader].id;
    let block = nodes[leader]
        .rt
        .propose(1)
        .await
        .expect("the target round's proposer builds a body");
    nodes[0]
        .rt
        .on_proposal(leader_id, block, target)
        .await
        .expect("the caught-up node accepts the new round's proposal");
    let v = nodes[0]
        .rt
        .make_prevote()
        .expect("the caught-up node votes the new round");
    assert_eq!(v.round, target);
}
