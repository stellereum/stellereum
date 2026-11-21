//! Signed-round liveness regressions (ruleset v4/v5).
//!
//! A block's identity now commits the BFT `round`. Lock rescue deliberately
//! re-serves the SAME locked body, so that body keeps the round it was
//! ORIGINALLY signed under while the network moves on. The liveness trap is
//! not acceptance (that is allowed for a known body) — it is what happens
//! NEXT: a node that follows a peer into a later round used to have its
//! accepted proposal wiped, so it arrived in the peer's round unarmed and
//! could not prevote the body the rest of the network was prevoting. Live
//! evidence: all three validators accepted and prevoted block #1 at r505,
//! r507 and r515 respectively; no round ever collected three votes.
//!
//! These tests drive real [`ValidatorRuntime`]s (real signatures, real vote
//! sets, real certificates) over a deterministic virtual-clock wire, with a
//! forced locked body and the live start stagger. They fail on the pre-fix
//! code (the laggards reach the head round with no live proposal, or stop
//! one ROUND_LOOKBACK short of it, and the height never decides within the
//! bounded window).

use ed25519_dalek::SigningKey;
use std::collections::VecDeque;
use std::sync::Arc;

use stellereum::consensus::{register_validator_pq_key, Vote, VoteKind, ValidatorSet};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

const TICK_MS: u64 = 100;
const DELAY_MS: u64 = 150;
/// Retransmit cadence while a round is live (production mirrors this).
const REXMIT_MS: u64 = 400;

#[derive(Clone)]
enum Msg {
    Proposal { from: usize, block: Box<Block>, round: u32 },
    Vote(Vote),
}

struct Pending {
    at: u64,
    to: usize,
    msg: Msg,
}

struct Node {
    rt: ValidatorRuntime,
    start_ms: u64,
    round_started_ms: u64,
    last_prevoted: Option<(u64, u32)>,
    last_precommitted: Option<(u64, u32)>,
    last_vote: Option<Vote>,
    last_rexmit_ms: u64,
    vote_rounds: Vec<(u64, u32, Option<[u8; 32]>)>,
}

struct Rig {
    nodes: Vec<Node>,
    wire: VecDeque<Pending>,
    now_ms: u64,
    /// Round timeout used by the rig (large while the forced lock is under
    /// test, so only the round-SYNC path can decide the height).
    timeout_ms: u64,
    dev_key: SigningKey,
    nonce: u64,
}

fn node_keys(seed: u64) -> Vec<SigningKey> {
    (0..3)
        .map(|i| {
            let mut raw = [0u8; 32];
            raw[0] = (i as u8).wrapping_add(1);
            raw[31] = 0xA5;
            raw[1] = seed as u8;
            SigningKey::from_bytes(&raw)
        })
        .collect()
}

impl Rig {
    /// Build three nodes whose validator set has the LIVE power split
    /// (1500/1000/1000: the 1500 node is in every quorum), then force every
    /// node onto the SAME locked body signed at an older round and stagger
    /// their local rounds/starts.
    async fn locked_body(
        starts_ms: &[u64],
        round_offsets: &[u32],
    ) -> (Rig, [u8; 32], u32) {
        let ks = node_keys(0x51);
        let powers = [1000u64, 1000, 1500];
        let vs = ValidatorSet::from_list(
            ks.iter()
                .zip(powers)
                .map(|(k, p)| (k.verifying_key().to_bytes(), p))
                .collect(),
        );
        let mut nodes = Vec::new();
        for (i, k) in ks.iter().enumerate() {
            let fk = FalconKeypair::generate_from_seed(0x20 + i as u8);
            register_validator_pq_key(
                k.verifying_key().to_bytes(),
                PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            let state = Arc::new(InMemoryStateEngine::new());
            fund_genesis(&state, &vs, 1_000_000_000_000_000).await;
            let rt = ValidatorRuntime::new(k.clone(), vs.clone(), state, 1)
                .with_falcon_key(fk)
                .with_deterministic_sim_signing();
            nodes.push(Node {
                rt,
                start_ms: starts_ms[i],
                round_started_ms: starts_ms[i],
                last_prevoted: None,
                last_precommitted: None,
                last_vote: None,
                last_rexmit_ms: 0,
                vote_rounds: Vec::new(),
            });
        }

        // A funded dev account whose tx makes the follow-on heights real.
        let dev_key = {
            let mut raw = [0x77u8; 32];
            raw[31] = 0x33;
            SigningKey::from_bytes(&raw)
        };
        let dev_addr = dev_key.verifying_key().to_bytes();
        for n in nodes.iter_mut() {
            n.rt
                .state
                .update_account(AccountState::new(dev_addr, 1_000_000_000_000_000_000))
                .await;
        }

        // Node 0 (the 1500-power validator) authors the locked body at a
        // round it owns. All other nodes are then placed on their staggered
        // rounds and hold the SAME body/lock (the live rescue shape).
        while nodes[0].rt.hc.proposer().unwrap() != ks[0].verifying_key().to_bytes() {
            for n in nodes.iter_mut() {
                n.rt.hc.next_round();
            }
        }
        let base_round = nodes[0].rt.hc.round;
        let body = nodes[0]
            .rt
            .propose(1)
            .await
            .expect("node 0 must author the locked body");
        let bh = body.compute_hash();

        for (i, n) in nodes.iter_mut().enumerate() {
            for _ in 0..round_offsets[i] {
                n.rt.hc.next_round();
            }
            n.rt.blocks.insert(bh, body.clone());
            n.rt.hc.locked = Some((bh, base_round));
            // The body was accepted; re-proposals of it are live proposals at
            // whatever round the node is in (that is what the rescue does).
            n.rt.hc.proposal = Some((body.proposer, bh));
            n.rt.hc.proposal_round = Some(n.rt.hc.round);
            n.round_started_ms = n.start_ms;
        }

        (
            Rig {
                nodes,
                wire: VecDeque::new(),
                now_ms: 0,
                timeout_ms: 60_000,
                dev_key,
                nonce: 0,
            },
            bh,
            base_round,
        )
    }

    fn active(&self, i: usize) -> bool {
        self.now_ms >= self.nodes[i].start_ms
    }

    async fn seed_tx(&mut self) {
        self.nonce += 1;
        let tx = Transaction::sign(
            &self.dev_key,
            [0x11u8; 32],
            1,
            21_000,
            self.nonce,
            MASTERCHAIN_SHARD,
            MASTERCHAIN_SHARD,
        );
        for n in self.nodes.iter_mut() {
            n.rt.add_tx(tx.clone()).await;
        }
    }

    fn send(&mut self, to: usize, msg: Msg) {
        if !self.active(to) {
            return; // a node that has not started yet never receives
        }
        self.wire.push_back(Pending {
            at: self.now_ms + DELAY_MS,
            to,
            msg,
        });
    }

    fn broadcast(&mut self, from: usize, msg: Msg) {
        for to in 0..self.nodes.len() {
            if to != from {
                self.send(to, msg.clone());
            }
        }
    }

    /// Run one virtual tick of the production phase order.
    async fn tick(&mut self) {
        self.now_ms += TICK_MS;

        // 1. propose
        for i in 0..self.nodes.len() {
            if !self.active(i) {
                continue;
            }
            let (h, r) = (self.nodes[i].rt.hc.height, self.nodes[i].rt.hc.round);
            if self.nodes[i].rt.is_proposer()
                && self.nodes[i].rt.hc.step == stellereum::consensus::Step::Propose
                && !self.nodes[i].rt.hc.has_live_proposal()
            {
                let ts = self.now_ms / 1000 + h;
                if let Some(block) = self.nodes[i].rt.propose(ts).await {
                    let proposer = self.nodes[i].rt.id;
                    let msg = Msg::Proposal {
                        from: i,
                        block: Box::new(block),
                        round: r,
                    };
                    let _ = proposer;
                    self.broadcast(i, msg);
                }
            }
        }

        // 2. prevote (value vote when armed; nil only after 2x timeout, which
        //    the bounded windows below never reach)
        for i in 0..self.nodes.len() {
            if !self.active(i) {
                continue;
            }
            let h = self.nodes[i].rt.hc.height;
            let waited = self.now_ms.saturating_sub(self.nodes[i].round_started_ms);
            let armed = self.nodes[i].rt.hc.has_live_proposal();
            let vote_round = self.nodes[i].rt.prevote_round();
            if self.nodes[i].last_prevoted != Some((h, vote_round))
                && (armed || waited >= 2 * self.timeout_ms)
            {
                if let Some(v) = self.nodes[i].rt.make_prevote() {
                    self.nodes[i].last_prevoted = Some((h, v.round));
                    self.nodes[i].last_vote = Some(v.clone());
                    self.nodes[i].vote_rounds.push((h, v.round, v.block_hash));
                    let _ = self.nodes[i].rt.on_prevote(v.clone());
                    self.broadcast(i, Msg::Vote(v));
                }
            }
        }

        // 3. drain
        let mut due = Vec::new();
        while let Some(front) = self.wire.front() {
            if front.at > self.now_ms {
                break;
            }
            due.push(self.wire.pop_front().expect("front exists"));
        }
        for p in due {
            let before = self.nodes[p.to].rt.hc.round;
            match p.msg {
                Msg::Proposal { from, block, round } => {
                    let proposer = self.nodes[from].rt.id;
                    let _ = self
                        .nodes[p.to]
                        .rt
                        .on_proposal(proposer, *block, round)
                        .await;
                }
                Msg::Vote(v) => match v.kind {
                    VoteKind::Prevote => {
                        let _ = self.nodes[p.to].rt.on_prevote(v);
                    }
                    VoteKind::Precommit => {
                        let _ = self.nodes[p.to].rt.on_precommit(v);
                    }
                },
            }
            if self.nodes[p.to].rt.hc.round != before {
                self.nodes[p.to].round_started_ms = self.now_ms;
            }
        }

        // 4. precommit
        for i in 0..self.nodes.len() {
            if !self.active(i) {
                continue;
            }
            if let Some(v) = self.nodes[i].rt.make_precommit() {
                if self.nodes[i].last_precommitted != Some((v.height, v.round)) {
                    self.nodes[i].last_precommitted = Some((v.height, v.round));
                    self.nodes[i].last_vote = Some(v.clone());
                    let _ = self.nodes[i].rt.on_precommit(v.clone());
                    self.broadcast(i, Msg::Vote(v));
                }
            }
        }

        // 5. finalize
        for i in 0..self.nodes.len() {
            if !self.active(i) {
                continue;
            }
            let before = self.nodes[i].rt.hc.height;
            let _ = self.nodes[i].rt.try_finalize().await;
            if self.nodes[i].rt.hc.height != before {
                self.nodes[i].last_prevoted = None;
                self.nodes[i].last_precommitted = None;
                self.nodes[i].last_vote = None;
                self.nodes[i].round_started_ms = self.now_ms;
                self.seed_tx().await;
            }
        }

        // 6. retransmit the last vote while still in the same round (the
        //    production periodic re-send: a late starter must still hear the
        //    head's vote).
        for i in 0..self.nodes.len() {
            if !self.active(i) {
                continue;
            }
            if self.now_ms.saturating_sub(self.nodes[i].last_rexmit_ms) >= REXMIT_MS {
                if let Some(v) = self.nodes[i].last_vote.clone() {
                    if v.height == self.nodes[i].rt.hc.height
                        && self.nodes[i].last_prevoted == Some((v.height, v.round))
                    {
                        self.nodes[i].last_rexmit_ms = self.now_ms;
                        self.broadcast(i, Msg::Vote(v));
                    }
                }
            }
        }

        // 7. view change
        for i in 0..self.nodes.len() {
            if self.active(i) && self.now_ms.saturating_sub(self.nodes[i].round_started_ms) >= self.timeout_ms
            {
                self.nodes[i].rt.hc.next_round();
                self.nodes[i].round_started_ms = self.now_ms;
                self.nodes[i].last_prevoted = None;
                self.nodes[i].last_precommitted = None;
                self.nodes[i].last_vote = None;
            }
        }
    }

    async fn run_until_height(&mut self, target: u64, max_ms: u64) {
        while self.now_ms < max_ms
            && self
                .nodes
                .iter()
                .any(|n| n.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0) < target)
        {
            self.tick().await;
        }
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .map(|n| n.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0))
            .collect()
    }

    fn rounds(&self) -> Vec<u32> {
        self.nodes.iter().map(|n| n.rt.hc.round).collect()
    }
}

/// Test 1: staggered start (2 s / 4 s) with a deliberate one-round offset on
/// the locked body's height. The LAN exchange must decide the height WITHOUT
/// waiting out a single 60 s round timer: every acceptor has to prevote the
/// re-served body in the SAME round.
#[tokio::test]
async fn staggered_start_one_round_offset_finalises_without_a_view_change() {
    let (mut rig, bh, base) = Rig::locked_body(&[0, 2_000, 4_000], &[0, 1, 2]).await;
    assert_eq!(rig.nodes[2].rt.hc.round, base + 2, "1500 node is the head");
    rig.run_until_height(2, 10_000).await;

    let heights = rig.heights();
    assert!(
        heights.iter().all(|h| *h >= 2),
        "staggered cluster must finalise the locked height before any view \
         change (timeout is 60 s); heights={heights:?} rounds={:?} body={}",
        rig.rounds(),
        hex::encode(&bh[..6])
    );
    // Every deciding prevote named the locked body in its SIGNED round, so
    // all three landed in the SAME bucket regardless of local round drift.
    for (i, n) in rig.nodes.iter().enumerate() {
        assert!(
            n.vote_rounds
                .iter()
                .any(|(_, r, target)| *r == base && *target == Some(bh)),
            "node {i} must prevote the locked body in its signed round {base}; \
             casts={:?}",
            n.vote_rounds
        );
    }

    // ...and the chain KEEPS finalising after the rescue height.
    rig.run_until_height(4, 60_000).await;
    let heights = rig.heights();
    assert!(
        heights.iter().all(|h| *h >= 4),
        "the cluster must keep finalising after the rescue; heights={heights:?}"
    );
}

/// Test 2: force a locked-body re-proposal across a round gap WIDER than
/// ROUND_LOOKBACK (the live r505 -> r515 shape). Every node holds and is
/// locked on the same older-signed body; only the round-sync path can make
/// the votes coincide.
#[tokio::test]
async fn locked_body_reproposed_across_rounds_still_finalises() {
    let (mut rig, bh, base) = Rig::locked_body(&[0, 0, 0], &[0, 2, 10]).await;
    assert_eq!(rig.nodes[2].rt.hc.round, base + 10);
    rig.run_until_height(2, 10_000).await;

    let heights = rig.heights();
    assert!(
        heights.iter().all(|h| *h >= 2),
        "a locked body re-proposed across rounds must still finalise; \
         heights={heights:?} rounds={:?} body={}",
        rig.rounds(),
        hex::encode(&bh[..6])
    );
    // The laggard at +0 cannot have stopped one lookback short or stamped a
    // different round: it must have prevoted the locked body in its SIGNED
    // round, the same bucket as the head.
    assert!(
        rig.nodes[0]
            .vote_rounds
            .iter()
            .any(|(_, r, target)| *r == base && *target == Some(bh)),
        "the laggard must prevote the locked body in its signed round {base}; casts={:?}",
        rig.nodes[0].vote_rounds
    );
}

// ============================================================================
// Direct state-machine pins for the two rules the cluster tests exercise.
// ============================================================================

#[tokio::test]
async fn same_value_vote_keeps_the_proposal_live_in_the_peer_round() {
    let (ks, fks) = falcon_votes::falcon_set(3);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .zip([1500u64, 1000, 1000])
            .map(|(k, p)| (k.verifying_key().to_bytes(), p))
            .collect(),
    );
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1)
        .with_falcon_key(fks[0].clone());

    // A live proposal accepted in the current round.
    let body = Block {
        height: rt.hc.height,
        state_root: rt.state.get_state_root().await,
        timestamp: 1,
        proposer: rt.hc.proposer().unwrap(),
        round: rt.hc.round,
        ..Default::default()
    };
    let bh = body.compute_hash();
    rt.hc.proposal = Some((body.proposer, bh));
    rt.hc.proposal_round = Some(rt.hc.round);
    rt.hc.locked = Some((bh, rt.hc.round));
    rt.blocks.insert(bh, body);

    let r = rt.hc.round;
    // A verified peer votes the SAME body ten rounds ahead. With the fix we
    // converge all the way and remain armed; without it we stop at +8 (one
    // ROUND_LOOKBACK) with the proposal wiped.
    assert!(rt.note_peer_vote_round_for(rt.hc.height, r + 10, Some(bh)));
    assert_eq!(rt.hc.round, r + 10, "same-value vote must reach its round");
    assert!(rt.hc.has_live_proposal(), "locked proposal must survive the sync");
    assert_eq!(rt.hc.decide_prevote(), Some(bh));
    assert_eq!(rt.prevote_round(), r);

    // A DIFFERENT-target vote keeps the conservative one-step bound: the
    // same-value rule must not become a round-DoS.
    let other = [0xABu8; 32];
    assert!(rt.note_peer_vote_round_for(rt.hc.height, r + 100, Some(other)));
    assert_eq!(
        rt.hc.round,
        r + 10 + stellereum::consensus::ROUND_LOOKBACK,
        "different value: exactly one lookback step"
    );
    // The proposal is LOCKED, so the Tendermint locked-value rule keeps it
    // live (we would still prevote our lock); only the jump DISTANCE stays
    // conservative for a value the network is not voting.
    assert!(rt.hc.has_live_proposal());
    let v = rt.make_prevote().expect("locked node still votes its lock");
    assert_eq!(v.block_hash, Some(bh));
    assert_eq!(v.round, r, "still the body's signed round");
    assert!(
        rt.make_prevote().is_none(),
        "SafetyAuthority refuses re-signing the same prevote round"
    );
}

#[tokio::test]
async fn two_near_head_peers_corroborate_the_full_chase() {
    let (ks, fks) = falcon_votes::falcon_set(3);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1u64))
            .collect(),
    );
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1)
        .with_falcon_key(fks[0].clone());
    let r = rt.hc.round;
    // Two distinct peers in the head's neighbourhood (r+2 and r+10) let the
    // r->r+10 jump finish in one call; a lone reporter would stop at +8.
    let p1 = falcon_votes::fvote(
        &ks[1],
        &fks[1],
        rt.hc.height,
        r + 2,
        VoteKind::Prevote,
        None,
    );
    let p2 = falcon_votes::fvote(
        &ks[2],
        &fks[2],
        rt.hc.height,
        r + 10,
        VoteKind::Prevote,
        None,
    );
    rt.on_prevote(p1).unwrap();
    rt.on_prevote(p2).unwrap();
    assert_eq!(rt.hc.round, r + 10);
}
