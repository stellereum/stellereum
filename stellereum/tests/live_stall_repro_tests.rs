//! Deterministic reproduction of the LIVE ruleset-v5 consensus stall.
//!
//! # The live symptom
//!
//! Three validators ACCEPTED the SAME block (same hash, signed at round `r`)
//! and prevoted it, but each prevote named a DIFFERENT round (505 / 507 /
//! 515). No round ever collected a quorum, so `make_precommit` never ran, no
//! precommit QC formed, and the height never finalised. Rounds advanced
//! independently and the gap grew; the proposer re-served the same locked
//! body (same hash, older signed round) every round.
//!
//! # What this file pins
//!
//! The scenario is driven ONLY through the public runtime API
//! (`propose`, `on_proposal`, `make_prevote`, `on_prevote`,
//! `make_precommit`, `on_precommit`, `next_round`, `try_finalize`). It does
//! not model a timer, a network pump, or any private state, so it stays valid
//! whichever rule the F1 liveness fix changes.
//!
//! The triggering sequence is built from the ONE asymmetry that matters: a
//! body certified at round `r` is re-served while the validators have already
//! timeout-stepped to `r+3`, `r+1` and `r+2`. Every receiver accepts the body
//! (it is genuine, for this height, by the scheduled proposer, and they
//! already hold it) and stamps its prevote with its OWN local round. Three
//! prevotes for the same hash in three different buckets = no quorum.
//!
//! The base round `r` is chosen so the SAME proposer owns `r, r+1, r+2, r+3`
//! (4 consecutive hash-slot draws for one validator). That removes the
//! near-future `on_proposal` phase alignment from the scenario, leaving the
//! round-stamp divergence as the single cause — exactly the live shape where
//! one validator kept the proposer slot while the peers drifted.
//!
//! * [`same_body_is_prevoted_in_the_signed_round`] pins the fix:
//!   three local round counters, but all prevotes carry the body's SIGNED
//!   round, so the quorum forms and the height finalises.
//! * [`same_body_converges_to_one_round_and_finalises`] asserts the same
//!   property end to end through the precommit quorum.
//!
//! No wall-clock sleeps and no random draws drive the protocol: keys and
//! Falcon signing are deterministic, and every step below is an explicit
//! call.

use ed25519_dalek::SigningKey;
use std::sync::Arc;

use stellereum::consensus::{BlockHash, Round, ValidatorId, ValidatorSet, Vote};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)] // GATE: shared fixture module keeps helpers this file does not use.
mod falcon_votes;

/// The height under test. Height 1 roots at the zero parent, so no parent
/// hash negotiation is needed.
const HEIGHT: u64 = 1;

/// Three validators, one vote each. `quorum_power()` is 3, i.e. ALL THREE
/// must prevote the same hash in the SAME round — the live "no round reaches
/// 3 votes" condition.
const N: usize = 3;

/// One runtime per validator, all with the SAME genesis state and validator
/// set (the production precondition for accepting each other's blocks).
struct Node {
    rt: ValidatorRuntime,
    id: ValidatorId,
}

/// Build the three runtimes. Deterministic keys and Falcon signing; each node
/// has its own `InMemoryStateEngine`, funded identically.
async fn three_nodes() -> (Vec<Node>, ValidatorSet) {
    let (ks, fks) = falcon_votes::falcon_set(N);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1u64))
            .collect(),
    );
    assert_eq!(
        vset.quorum_power(),
        N as u64,
        "the reproduction needs unanimity: no round may form a quorum with fewer than 3 votes"
    );

    let mut nodes = Vec::with_capacity(N);
    for (i, k) in ks.iter().enumerate() {
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        let rt = ValidatorRuntime::new(k.clone(), vset.clone(), state, 1)
            .with_falcon_key(fks[i].clone())
            .with_deterministic_sim_signing();
        nodes.push(Node {
            rt,
            id: signer_id(k),
        });
    }
    (nodes, vset)
}

fn signer_id(k: &SigningKey) -> ValidatorId {
    k.verifying_key().to_bytes()
}

/// Find a base round `r` whose proposer also owns `r+1`, `r+2` and `r+3`.
///
/// This is a real consecutive-run of a single validator's hash slots
/// (`ValidatorSet::proposer_for`), probability 1/27 per round. It is what
/// makes the scenario free of `on_proposal` phase alignment: every receiver
/// already expects the re-serving proposer at its own current round, so the
/// only thing that differs between the three prevotes is the round they are
/// stamped with. The search is deterministic and bounded.
fn consecutive_proposer_round(vset: &ValidatorSet) -> (Round, ValidatorId) {
    for r in 0u32..4096 {
        let Some(p) = vset.proposer_for(HEIGHT, r) else {
            continue;
        };
        if (1..=3).all(|d| vset.proposer_for(HEIGHT, r + d) == Some(p)) {
            return (r, p);
        }
    }
    panic!("no 4-round single-proposer window in the first 4096 rounds");
}

/// The scenario up to (and including) the three prevotes.
///
/// Steps, all explicit:
/// 1. all three start at base round `r`;
/// 2. the scheduled proposer signs the body at `r`;
/// 3. the other two ACCEPT that body at `r` (they now hold the hash);
/// 4. timeout steps move the proposer to `r+3`, B to `r+1`, C to `r+2`;
/// 5. the SAME body is re-served (signed round stays `r`, the envelope names
///    the proposer's live round `r+3`);
/// 6. all three accept it and cast a prevote for the SAME hash — each stamped
///    with its own local round.
async fn three_prevotes_for_re_served_body() -> Scenario {
    let (mut nodes, vset) = three_nodes().await;
    let (r, proposer) = consecutive_proposer_round(&vset);

    let proposer_idx = nodes
        .iter()
        .position(|n| n.id == proposer)
        .expect("the schedule must name a member");
    let mut others: Vec<usize> = (0..N).filter(|i| *i != proposer_idx).collect();
    others.sort_unstable();
    let b_idx = others[0];
    let c_idx = others[1];

    // 1. Base round for every validator.
    for n in nodes.iter_mut() {
        n.rt.hc.round = r;
    }

    // 2. The scheduled proposer builds and signs the body at round `r`.
    let block = nodes[proposer_idx]
        .rt
        .propose(1)
        .await
        .expect("the scheduled proposer must build a block in the propose step");
    assert_eq!(block.height, HEIGHT);
    assert_eq!(block.proposer, proposer);
    assert_eq!(block.round, r, "the body is signed at the base round");
    let bh = block.compute_hash();

    // 3. The two followers accept it at `r`. (The proposer already recorded
    // its own proposal inside `propose`.)
    for i in [b_idx, c_idx] {
        nodes[i]
            .rt
            .on_proposal(proposer, block.clone(), r)
            .await
            .expect("the genuine body must be accepted at its signed round");
        assert!(
            nodes[i].rt.blocks.contains_key(&bh),
            "the follower must hold the body before it is re-served (the HEAD \
             `accepts_block_round` exception is 'a body we already hold')"
        );
    }

    // 4. Timeout steps. `next_round` is the public view-change primitive the
    // node loop calls when its round timer expires: the proposer is now 3
    // rounds ahead, B one, C two.
    for _ in 0..3 {
        nodes[proposer_idx].rt.next_round();
    }
    nodes[b_idx].rt.next_round();
    nodes[c_idx].rt.next_round();
    nodes[c_idx].rt.next_round();

    assert_eq!(nodes[proposer_idx].rt.hc.round, r + 3);
    assert_eq!(nodes[b_idx].rt.hc.round, r + 1);
    assert_eq!(nodes[c_idx].rt.hc.round, r + 2);

    // 5. The proposer re-serves the LOCKED body: same bytes, same hash, still
    // signed at `r`. The (unsigned) envelope names the proposer's live round
    // `r+3`, so no receiver refuses it as a stale envelope.
    let envelope_round = r + 3;
    for (i, n) in nodes.iter_mut().enumerate() {
        n.rt.on_proposal(proposer, block.clone(), envelope_round)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "node {i} at round {} refused the re-served body signed at {r}: {e}",
                    n.rt.hc.round
                )
            });
    }

    // 6. Each node prevotes the body it holds, stamped with its LOCAL round.
    let mut votes = Vec::with_capacity(N);
    for (i, n) in nodes.iter().enumerate() {
        let vote = n.rt.make_prevote().unwrap_or_else(|| {
            panic!(
                "node {i} at round {} holds a live proposal but produced no prevote",
                n.rt.hc.round
            )
        });
        assert_eq!(
            vote.round, block.round,
            "the prevote names the BODY's signed round (coherent on every holder), \
             not the local round {}",
            n.rt.hc.round
        );
        assert_eq!(
            vote.block_hash,
            Some(bh),
            "node {i} prevoted a different value (or nil) instead of the re-served body"
        );
        votes.push(vote);
    }

    Scenario {
        nodes,
        vset,
        base_round: r,
        block,
        block_hash: bh,
        prevotes: votes,
    }
}

/// Everything the assertions need, plus the delivery helper.
struct Scenario {
    nodes: Vec<Node>,
    vset: ValidatorSet,
    base_round: Round,
    block: Block,
    block_hash: BlockHash,
    prevotes: Vec<Vote>,
}

impl Scenario {
    /// Deliver every prevote to every node (full broadcast, one round trip).
    /// `on_prevote` also applies the production future-round rule, so this is
    /// how a lagging node learns the network's newest round.
    fn broadcast_prevotes(&mut self) {
        let votes = self.prevotes.clone();
        for n in self.nodes.iter_mut() {
            for v in &votes {
                n.rt.on_prevote(v.clone())
                    .unwrap_or_else(|e| panic!("prevote rejected at h={}: {e}", v.height));
            }
        }
    }

    fn cast_precommits(&mut self) -> Vec<Option<Vote>> {
        self.nodes
            .iter_mut()
            .map(|n| n.rt.make_precommit())
            .collect()
    }

    fn broadcast_precommits(&mut self, precommits: &[Vote]) {
        for n in self.nodes.iter_mut() {
            for v in precommits {
                n.rt.on_precommit(v.clone())
                    .unwrap_or_else(|e| panic!("precommit rejected at h={}: {e}", v.height));
            }
        }
    }

    /// Does this node hold a prevote quorum (a polka) in round `q`?
    fn has_polka_at(&self, i: usize, q: Round) -> bool {
        self.nodes[i]
            .rt
            .hc
            .prevote_set(q)
            .and_then(|s| s.quorum_target(&self.vset))
            .is_some()
    }
}

// ===========================================================================
// 1. THE REPRODUCTION (runs today; pins the buggy behaviour).
// ===========================================================================

/// Reproduce the live stall: the SAME signed body reaches all three
/// validators, all three prevote it, and the votes land in three different
/// rounds, so no prevote quorum ever forms and the height never finalises.
///
/// The test asserts the divergence EXPLICITLY (it does not merely "fail to
/// finalise"), so the exact live signature is visible in the assertion text:
/// `same hash, rounds [r+3, r+1, r+2], quorum is 3`.
#[tokio::test]
async fn same_body_is_prevoted_in_the_signed_round() {
    let mut sc = three_prevotes_for_re_served_body().await;
    let r = sc.base_round;

    // THE FIX: one body, three local rounds, but ALL prevotes land in the
    // body's SIGNED round. The signed round is identical on every holder, so
    // the votes share a bucket even though the validators' local counters do
    // not.
    let rounds: Vec<Round> = sc.prevotes.iter().map(|v| v.round).collect();
    assert_eq!(
        rounds,
        vec![r; N],
        "every prevote for the re-served body must carry its SIGNED round {r}"
    );
    let hashes: Vec<Option<BlockHash>> = sc.prevotes.iter().map(|v| v.block_hash).collect();
    assert!(
        hashes.iter().all(|h| *h == Some(sc.block_hash)),
        "all three prevotes must name the SAME block hash: {hashes:?} vs {}",
        hex::encode(sc.block_hash)
    );
    assert_eq!(
        sc.block.round, r,
        "the re-served body keeps its ORIGINAL signed round (the hash is the locked value)"
    );

    // Deliver the votes. The future-round rule still follows the newest vote
    // (r+3), but the prevote QUORUM is in r — the shared signed round.
    sc.broadcast_prevotes();
    for i in 0..N {
        assert!(
            sc.has_polka_at(i, r),
            "node {i} must hold the prevote quorum at the body's signed round {r}"
        );
    }

    // Polka => precommit at the polka round => precommit QC => finality.
    let precommits: Vec<Vote> = sc
        .cast_precommits()
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.unwrap_or_else(|| {
                panic!("node {i} must precommit the certified body at round {r}")
            })
        })
        .collect();
    assert!(precommits.iter().all(|p| p.round == r));
    sc.broadcast_precommits(&precommits);
    for i in 0..N {
        assert_eq!(
            sc.nodes[i].rt.try_finalize().await,
            Some(sc.block_hash),
            "node {i} must finalise the body all three prevoted"
        );
    }
}

// ===========================================================================
// 2. THE DESIRED PROPERTY (after the F1 liveness fix).
// ===========================================================================

/// The companion liveness property: after the F1 fix, the SAME re-served
/// body must be prevoted by all three validators in ONE round (whichever
/// round the fix picks — the block's signed round or the newest live round),
/// the polka must become a precommit quorum, and the height must finalise.
///
/// This is the end-to-end property; the vote round is the body's SIGNED
/// round, so it is identical on every holder regardless of local drift.
#[tokio::test]
async fn same_body_converges_to_one_round_and_finalises() {
    let mut sc = three_prevotes_for_re_served_body().await;

    // DESIRED: one prevote round for the same body.
    let mut rounds: Vec<Round> = sc.prevotes.iter().map(|v| v.round).collect();
    rounds.sort_unstable();
    rounds.dedup();
    assert_eq!(
        rounds.len(),
        1,
        "after the fix all three prevotes must land in ONE round, got {:?} \
         for the same body {}",
        sc.prevotes.iter().map(|v| v.round).collect::<Vec<_>>(),
        hex::encode(sc.block_hash)
    );
    let q = rounds[0];
    assert!(
        sc.prevotes.iter().all(|v| v.block_hash == Some(sc.block_hash)),
        "all three prevotes must still name the re-served body"
    );
    assert_eq!(
        sc.block.round, sc.base_round,
        "the fix must not change the body's signed round: the hash is the value peers are locked on"
    );

    // Full round trip: prevotes -> polka -> precommits -> precommit QC.
    sc.broadcast_prevotes();
    for i in 0..N {
        assert!(
            sc.has_polka_at(i, q),
            "node {i} must hold the prevote quorum at the common round {q}"
        );
    }
    let precommits: Vec<Vote> = sc
        .cast_precommits()
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.unwrap_or_else(|| {
                panic!("node {i} must precommit the certified body at the polka round {q}")
            })
        })
        .collect();
    assert!(
        precommits.iter().all(|p| p.round == q),
        "precommits must follow the polka's own round {q}"
    );
    sc.broadcast_precommits(&precommits);

    // The height must finalise, with the SAME hash on every node.
    for i in 0..N {
        let fin = sc.nodes[i].rt.try_finalize().await;
        assert_eq!(
            fin,
            Some(sc.block_hash),
            "node {i} must finalise the body the cluster prevoted"
        );
    }
}
