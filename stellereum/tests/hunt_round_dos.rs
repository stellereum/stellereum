//! HUNT: unauthenticated round-counter advance -> permanent consensus liveness kill.
//!
//! Target: src/main.rs:417 and src/main.rs:442
//!
//!     ConsensusMsg::Proposal { round: r, block, .. } => {
//!         rt.hc.advance_to_round(r);            // <-- BEFORE validate_proposal
//!         ...
//!     ConsensusMsg::Vote { vote: v, .. } => {
//!         rt.hc.advance_to_round(v.round);       // <-- BEFORE vote.verify()
//!
//! `advance_to_round` (src/consensus.rs:490) caps the *per-message* step at
//! MAX_ROUND_AHEAD = 1000. It does NOT cap the node's absolute round. The caller
//! invokes it once per inbound datagram inside `while let Ok(raw) = rx.try_recv()`,
//! so N datagrams move the node N*1000 rounds. The `round` field of both messages
//! is entirely unauthenticated and is never cross-checked against the block, the
//! vote's round, or the sender's identity.
//!
//! This is the CometBFT class: auxiliary data (a round number) taken from a peer
//! and consumed by an index-like counter with no cryptographic binding, and no
//! error raised.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{
    HeightConsensus, ValidatorId, ValidatorSet, Vote, VoteKind, MAX_ROUND_AHEAD, ROUND_LOOKBACK,
};
use stellereum::consensus_net::{parse_incoming, ConsensusMsg};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn ids(ks: &[SigningKey]) -> Vec<ValidatorId> {
    ks.iter().map(|k| k.verifying_key().to_bytes()).collect()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ids(ks).into_iter().map(|i| (i, 1)).collect())
}
fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Replay of the exact dispatch performed by src/main.rs:406-468. Kept verbatim in
/// structure so the PoC exercises the real production control flow.
struct VictimLoop {
    pub hc: HeightConsensus,
}

impl VictimLoop {
    /// `msg` is what came off the wire. Mirrors main.rs's `while let Ok(raw) = rx.try_recv()`.
    fn on_wire(&mut self, msg: &ConsensusMsg) {
        match msg {
            ConsensusMsg::Proposal {
                round: r, block, ..
            } => {
                // main.rs:417 -- happens unconditionally, before any validation
                self.hc.advance_to_round(*r);
                // main.rs:421 -- validation happens only AFTER the round moved
                let _ = self
                    .hc
                    .receive_proposal(block.proposer, block.compute_hash());
            }
            ConsensusMsg::Vote { vote: v, .. } => {
                // main.rs:442 -- happens unconditionally, before v.verify()
                self.hc.advance_to_round(v.round);
                match v.kind {
                    VoteKind::Prevote => {
                        let _ = self.hc.add_prevote(v.clone());
                    }
                    VoteKind::Precommit => {
                        let _ = self.hc.add_precommit(v.clone());
                    }
                }
            }
            ConsensusMsg::Committed { .. } => {}
            // P3-H4: the production drain flattens a Batch to its inners in
            // sender order; the PoC mirrors that so batched inners exercise
            // the same per-message control flow.
            ConsensusMsg::Batch(items) => {
                for m in items {
                    self.on_wire(m);
                }
            }
        }
    }
}

fn garbage_block(h: u64) -> Block {
    // A completely unsigned, meaningless block. It never needs to pass
    // validate_proposal: advance_to_round has already run by then.
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: [0xEE; 32],
        state_root: [0xDD; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 0,
        proposer: [0xAB; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

// ===========================================================================
// 1. The core primitive: N datagrams => N * MAX_ROUND_AHEAD rounds
// ===========================================================================

// ===========================================================================
// 1. FIXED. A peer message may advance the round counter by at most ONE round.
// The attacker is not even a validator; it never held a key.
// ===========================================================================

#[test]
fn hunt_finding_1_unauthenticated_datagrams_cannot_buy_rounds() {
    let ks = keys(4);
    let mut v = VictimLoop {
        hc: HeightConsensus::new(1, vset(&ks)),
    };
    assert_eq!(v.hc.round, 0);

    let datagrams = 500usize;
    for i in 0..datagrams {
        let msg = ConsensusMsg::Proposal {
            height: 1,
            round: (i as u32) * MAX_ROUND_AHEAD + 1_000,
            block: garbage_block(1),
        };
        // It must survive the real wire path (hex + JSON + bincode).
        let raw = serde_json::json!({
            "topic": "stellereum/consensus/v1",
            "data": hex::encode(msg.encode().unwrap()),
        })
        .to_string();
        let parsed = parse_incoming(&raw).expect("attacker datagram decodes");
        v.on_wire(&parsed);
    }

    println!(
        "[FINDING 1] after {datagrams} unauthenticated datagrams: round = {}",
        v.hc.round
    );
    assert_eq!(
        v.hc.round as usize, datagrams,
        "one round per datagram, never 1000 per datagram"
    );
    assert!(
        (v.hc.round as u64) < 100_000,
        "the attacker no longer pushes the node past 100k rounds"
    );
}

// ===========================================================================
// 2. Consequence: the honest network's proposals are now permanently rejected
// ===========================================================================

// ===========================================================================
// 2. FIXED. Consequence of the old bug: honest proposals were permanently
// rejected. With a one-round advance the victim stays in step with the network.
// ===========================================================================

#[test]
fn hunt_finding_1b_honest_proposers_are_still_accepted() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut v = VictimLoop {
        hc: HeightConsensus::new(1, vs.clone()),
    };

    // 20 forged datagrams, as in the original attack.
    for i in 0..20u32 {
        v.on_wire(&ConsensusMsg::Proposal {
            height: 1,
            round: 10_000 + i,
            block: garbage_block(1),
        });
    }
    let victim_round = v.hc.round;
    println!("[FINDING 1b] victim round = {victim_round} (was 0)");

    // The damage is bounded: rounds are bought one at a time, so 20 datagrams
    // cannot shove the node 20,000 rounds ahead.
    assert!(
        victim_round <= 100,
        "20 datagrams must not move the victim more than ~20 rounds, got {victim_round}"
    );

    // Rounds never go down, so the network converges by advancing to meet the
    // victim. What must remain true is that at the round the victim is actually
    // in, the honest proposer for THAT round is accepted.
    let honest_proposer = vs.proposer_for(1, victim_round).unwrap();
    v.hc.receive_proposal(honest_proposer, bh(victim_round as u8))
        .expect("FIXED: the honest proposer for the victim's own round is accepted");
    println!("[FINDING 1b] FIXED: the victim still follows the network at round {victim_round}");
}

// ===========================================================================
// 3. Consequence: the victim collects real quorum votes and still NEVER finalizes
// ===========================================================================

// ===========================================================================
// 3. FIXED. Consequence: the victim used to collect a real quorum at the honest
// round and still be unable to finalise, because the quorum was only ever
// inspected for the victim's own (attacker-chosen) round.
// ===========================================================================

#[test]
fn hunt_finding_1c_quorum_at_the_victims_round_now_finalises() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut v = VictimLoop {
        hc: HeightConsensus::new(1, vs.clone()),
    };

    for i in 0..20u32 {
        v.on_wire(&ConsensusMsg::Proposal {
            height: 1,
            round: 10_000 + i,
            block: garbage_block(1),
        });
    }
    let r = v.hc.round;
    let proposer = vs.proposer_for(1, r).unwrap();
    v.hc.receive_proposal(proposer, bh(r as u8))
        .expect("honest proposal for the victim's own round is accepted");

    for k in ks.iter() {
        v.hc.add_prevote(Vote::sign(k, 1, r, VoteKind::Prevote, Some(bh(r as u8))))
            .unwrap();
    }
    assert!(
        v.hc.try_prevote_quorum().is_some(),
        "a real 4/4 prevote quorum is visible at the round the node is in"
    );
    for k in ks.iter() {
        v.hc.add_precommit(Vote::sign(k, 1, r, VoteKind::Precommit, Some(bh(r as u8))))
            .unwrap();
    }
    let qc =
        v.hc.try_precommit_quorum()
            .expect("FIXED: the chain finalises again");
    assert_eq!(qc, bh(r as u8), "the QC commits to the agreed block");
    println!(
        "[FINDING 1c] FIXED: recovery is operational at round {r}, QC = {}",
        hex::encode(&qc[..4])
    );
}

// ===========================================================================
// 5. FIXED. `next_round` used to be `self.round += 1` -> panic in debug /
//    wrap to 0 in release at u32::MAX. It now saturates.
// ===========================================================================

#[test]
fn hunt_finding_1e_next_round_saturates_at_u32_max() {
    let ks = keys(4);
    let mut hc = HeightConsensus::new(1, vset(&ks));

    // Fast check: boundary saturation without 4.29 billion single-step iterations.
    hc.round = u32::MAX - 1;
    hc.advance_to_round(u32::MAX);
    assert_eq!(hc.round, u32::MAX, "advance_to_round must reach u32::MAX");
    hc.advance_to_round(u32::MAX);
    assert_eq!(
        hc.round,
        u32::MAX,
        "advance_to_round must saturate at u32::MAX"
    );
    println!("[FINDING 1e] reached u32::MAX; round = {}", hc.round);

    // src/consensus.rs used to do `self.round += 1`, which panicked in debug and
    // wrapped to 0 in release. It is now saturating_add.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hc.next_round()));
    assert!(r.is_ok(), "next_round must not panic at u32::MAX");
    assert_eq!(
        hc.round,
        u32::MAX,
        "next_round must saturate, not wrap to 0"
    );
    println!("[FINDING 1e] FIXED: next_round saturated at {}", hc.round);
}

// ===========================================================================
// 4. FIXED. The cap used to be per-datagram (1000 rounds each), so 100 datagrams
// bought 100,000 rounds in about a second of attacker traffic. One peer message
// now advances at most ONE round.
// ===========================================================================

#[test]
fn hunt_finding_1d_one_datagram_buys_at_most_one_round() {
    let ks = keys(4);
    let mut hc = HeightConsensus::new(1, vset(&ks));

    hc.advance_to_round(u32::MAX);
    assert_eq!(hc.round, 1, "one datagram buys at most one round");
    println!("[FINDING 1d] after 1 datagram: round = {}", hc.round);

    for _ in 0..99 {
        hc.advance_to_round(u32::MAX);
    }
    println!("[FINDING 1d] after 100 datagrams: round = {}", hc.round);
    assert_eq!(hc.round, 100, "100 datagrams buy 100 rounds, not 100,000");
    assert!(
        hc.round < MAX_ROUND_AHEAD,
        "a second of attacker traffic no longer buys a thousandfold"
    );
}

// ===========================================================================
// 6. Audit F2. The vote drain arm (src/main.rs) used to call
//    `note_peer_vote_round` (and `note_lock_hint`) BEFORE `on_prevote` /
//    `on_precommit`, and therefore before `Vote::verify`. A Batch of 32 junk
//    votes thus advanced the round by up to 32 * MAX_SYNC_JUMP(64) = 2048 with
//    no signatures at all. The fixed arm authenticates first and only syncs a
//    vote that verified, is a member, and is in scope; `drain_vote` below
//    mirrors that fixed arm exactly.
// ===========================================================================

async fn two_validator_rt() -> (ValidatorRuntime, Vec<SigningKey>) {
    let ks = keys(2);
    let vs = vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, 1_000_000_000_000_000).await;
    let rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
    (rt, ks)
}

/// Mirrors the FIXED vote-drain arm in src/main.rs: run the kind handler
/// (which performs `Vote::verify` + membership/scope checks) FIRST, and only
/// then record the lock hint and sync the round. Returns whether it verified.
fn drain_vote(rt: &mut ValidatorRuntime, v: Vote, locked: Option<[u8; 32]>) -> bool {
    let (vh, vk, vr, vbh) = (v.height, v.kind, v.round, v.block_hash);
    let accepted = match vk {
        VoteKind::Prevote => rt.on_prevote(v).is_ok(),
        VoteKind::Precommit => rt.on_precommit(v).is_ok(),
    };
    if accepted {
        rt.note_lock_hint(vh, vk, vbh, locked);
        rt.note_peer_vote_round(vh, vr);
    }
    accepted
}

#[tokio::test]
async fn hunt_finding_f2_junk_votes_never_move_the_round() {
    let (mut rt, ks) = two_validator_rt().await;
    let h = rt.hc.height;
    let r = rt.hc.round;
    let member = ks[1].verifying_key().to_bytes();
    let outsider = SigningKey::generate(&mut OsRng);
    let outsider_id = outsider.verifying_key().to_bytes();
    assert_ne!(outsider_id, member, "outsider is not a validator");

    // 64 votes at round+64..+: half carry a REAL member id with a forged
    // signature (Vote::verify fails), half are correctly signed by a
    // non-member (power_of == 0). Neither is attributable, so neither may move
    // the round.
    for i in 0..64u32 {
        let target_round = r + 64 + i;
        let v = if i % 2 == 0 {
            Vote::signed_with(
                member,
                h,
                target_round,
                VoteKind::Prevote,
                None,
                vec![0u8; 64],
            )
        } else {
            Vote::sign(&outsider, h, target_round, VoteKind::Prevote, None)
        };
        assert!(!drain_vote(&mut rt, v, None), "junk vote must not verify");
        assert_eq!(
            rt.hc.round, r,
            "junk vote at r{target_round} must not move us (round stays {r})"
        );
    }
    println!(
        "[FINDING F2] FIXED: 64 junk votes at r+64..r+127 left round = {}",
        rt.hc.round
    );
}

#[tokio::test]
async fn hunt_finding_f2_verified_far_vote_still_syncs_bounded() {
    let (mut rt, ks) = two_validator_rt().await;
    let h = rt.hc.height;
    let r = rt.hc.round;

    // A genuinely signed far vote from a real member, within MAX_ROUND_AHEAD.
    // It converges us toward the peer's round, bounded by the per-round jump
    // budget (MAX_SYNC_JUMPS_PER_ROUND capped jumps of ROUND_LOOKBACK each):
    // the Tendermint future-round rule, with the round-DoS bound intact.
    let v = Vote::sign(&ks[1], h, r + 100, VoteKind::Prevote, None);
    assert!(
        drain_vote(&mut rt, v, None),
        "verified far vote must be accepted"
    );
    assert_eq!(
        rt.hc.round,
        r + stellereum::consensus::MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK,
        "verified far vote must still sync, bounded by the per-round jump budget"
    );
    println!(
        "[FINDING F2] verified far vote moved r{r} -> r{} (budget cap {})",
        rt.hc.round,
        stellereum::consensus::MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK
    );
}

#[tokio::test]
async fn hunt_finding_f2_batch_of_32_junk_votes_does_not_inflate() {
    let (mut rt, _ks) = two_validator_rt().await;
    let h = rt.hc.height;
    let r = rt.hc.round;
    let outsider = SigningKey::generate(&mut OsRng);

    // A Batch of 32 junk votes. Under the old ordering this bought
    // 32 * MAX_SYNC_JUMP(64) = 2048 rounds; now it must buy zero.
    let batch = ConsensusMsg::Batch(
        (0..32u32)
            .map(|i| ConsensusMsg::Vote {
                vote: Vote::sign(&outsider, h, r + 64 + i, VoteKind::Prevote, None),
                locked: None,
            })
            .collect(),
    );

    // The production drain flattens a Batch into its inners in sender order.
    if let ConsensusMsg::Batch(inner) = batch {
        for msg in inner {
            if let ConsensusMsg::Vote { vote, locked } = msg {
                assert!(
                    !drain_vote(&mut rt, vote, locked),
                    "junk inner must not verify"
                );
            }
        }
    }

    assert_eq!(
        rt.hc.round, r,
        "a batch of 32 junk votes must not inflate the round counter"
    );
    println!(
        "[FINDING F2] FIXED: batch of 32 junk votes left round = {}",
        rt.hc.round
    );
}
