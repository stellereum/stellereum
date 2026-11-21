//! RESTART-LIVELOCK (P0): a stale proposal from a PREVIOUS process must never
//! own the current round's slot.
//!
//! # The live failure (saved evidence, `/tmp/opencode/livelock/`)
//!
//! After the validators were restarted the chain LIVELOCKED at #17396: all
//! three nodes had finalized #17395 with the same state root, the round
//! climbed 4 -> 26+ with no precommit quorum, and every round ended in a view
//! change. After the final simultaneous restart the proposer schedules agreed
//! (r24/r25/r26 -> the same validator) and that validator DID propose every
//! round, yet the others never voted the proposal:
//!
//! ```text
//! RX proposal from 5762c3311356 #17396 r26
//! rejected proposal from 5762c3311356 at #17396 r26:
//!     proposal already recorded for this round
//! RX Prevote from 5762c3311356 #17396 r26 target 425ac266
//! RX Prevote from df3d10f3549f #17396 r26 target nil
//! ```
//!
//! # Root cause
//!
//! `HeightConsensus::receive_proposal_for` keyed the one-value-per-round rule
//! on the LOCAL acceptance round (`proposal_round == hc.round`) plus the exact
//! hash. `on_proposal` legitimately admits a body whose SIGNED round is older
//! than the local round (lock rescue / one-round lag), so a delayed
//! pre-restart frame signed at `k < r` recorded itself as "the proposal for
//! round r". The scheduled proposer's genuine body for round r — under
//! ruleset v6 a RE-STAMP at `block.round == r` — then hit
//! `"proposal already recorded for this round"` and was refused. The node
//! held only the older signed body, so its value prevote was stamped at `k`
//! (`k <=` its fsynced watermark after the restart) and was suppressed: it
//! stayed silent or nil-voted, never voted the hash the proposer was voting,
//! and no round could reach the 3-of-3 quorum.
//!
//! The fix keys the rule on the BODY's signed round: a strictly newer signed
//! round SUPERSEDES the held body (different signed rounds are different
//! proposals by construction — the round is inside the signed block identity),
//! while the SAME signed round with a different hash is still equivocation and
//! a stale signed round can never displace a newer one.
//!
//! These tests drive real [`ValidatorRuntime`]s (real Falcon votes, real vote
//! sets, real certificates) on a deterministic virtual clock. The restart is
//! simulated exactly like the boot path: a fresh `HeightConsensus` for the
//! persisted height, the persisted round/watermark restored, the in-memory
//! proposal cache cleared, and the parent-decision evidence rebuilt from the
//! persisted finalized block (DOWNTIME-RESTORE).

use std::collections::VecDeque;
use std::sync::Arc;

use stellereum::consensus::{BlockHash, HeightConsensus, Round, ValidatorId, ValidatorSet, Vote};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)] // GATE: shared fixture module keeps helpers this file does not use.
mod falcon_votes;

const TICK_MS: u64 = 50;
/// One-way wire delay (a WAN: proposals routinely cross a round boundary).
const DELAY_MS: u64 = 250;
/// View-change timeout of the virtual cluster.
const ROUND_TIMEOUT_MS: u64 = 3_000;
/// Production proposal/vote retransmit cadence.
const REXMIT_MS: u64 = 400;
/// The height the restart happens at: ~20 heights are finalized first, so the
/// state roots, validator set and parent chain are non-trivial.
const RESTART_HEIGHT: u64 = 21;

#[derive(Clone)]
enum Msg {
    Proposal { round: Round, block: Box<Block> },
    Vote(Vote),
}

struct Pending {
    at: u64,
    to: usize,
    msg: Msg,
}

struct Node {
    rt: ValidatorRuntime,
    id: ValidatorId,
    /// Highest round signed as a prevote at the current height (the fsynced
    /// write-ahead watermark restored on boot).
    prevote_floor: Option<(u64, Round)>,
    /// Highest round signed as a precommit at the current height.
    precommit_floor: Option<(u64, Round)>,
    /// Restored `last_prevoted` (the exact round of the last prevote).
    last_prevoted: Option<(u64, Round)>,
    last_precommitted: Option<(u64, Round)>,
    round_started_ms: u64,
    cast_prevote: Option<Vote>,
    cast_precommit: Option<Vote>,
    last_rexmit_ms: u64,
    /// (height, round, at_ms) of the last verified peer vote seen here.
    peer_seen: Option<(u64, Round, u64)>,
    /// The round at which the node finalized RESTART_HEIGHT (for the bound).
    restart_finalized_at: Option<Round>,
}

impl Node {
    fn at_or_below_prevote_floor(&self, height: u64, round: Round) -> bool {
        crate::at_or_below(self.prevote_floor, height, round)
    }

    fn at_or_below_precommit_floor(&self, height: u64, round: Round) -> bool {
        crate::at_or_below(self.precommit_floor, height, round)
    }
}

fn at_or_below(floor: Option<(u64, Round)>, height: u64, round: Round) -> bool {
    matches!(floor, Some((h, r)) if h == height && round <= r)
}

fn advance_floor(floor: &mut Option<(u64, Round)>, height: u64, round: Round) {
    match floor {
        Some((h, r)) if *h == height => {
            if round > *r {
                *r = round;
            }
        }
        _ => *floor = Some((height, round)),
    }
}

struct Cluster {
    nodes: Vec<Node>,
    wire: VecDeque<Pending>,
    now_ms: u64,
}

impl Cluster {
    async fn new() -> Cluster {
        let (ks, fks) = falcon_votes::falcon_set(3);
        let vset = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1u64))
                .collect(),
        );
        assert_eq!(
            vset.quorum_power(),
            3,
            "N=3 needs unanimity: the live shape had no round with a partial quorum"
        );
        let mut nodes = Vec::with_capacity(3);
        for (i, k) in ks.iter().enumerate() {
            let state = Arc::new(InMemoryStateEngine::new());
            fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
            let rt = ValidatorRuntime::new(k.clone(), vset.clone(), state, 1)
                .with_falcon_key(fks[i].clone())
                .with_deterministic_sim_signing();
            nodes.push(Node {
                rt,
                id: k.verifying_key().to_bytes(),
                prevote_floor: None,
                precommit_floor: None,
                last_prevoted: None,
                last_precommitted: None,
                round_started_ms: 0,
                cast_prevote: None,
                cast_precommit: None,
                last_rexmit_ms: 0,
                peer_seen: None,
                restart_finalized_at: None,
            });
        }
        Cluster {
            nodes,
            wire: VecDeque::new(),
            now_ms: 0,
        }
    }

    fn proposer(&self, height: u64, round: Round) -> Option<ValidatorId> {
        self.nodes[0].rt.validators.proposer_for(height, round)
    }

    fn index_of(&self, proposer: ValidatorId) -> usize {
        self.nodes
            .iter()
            .position(|n| n.id == proposer)
            .expect("the schedule names a member of the set")
    }

    fn broadcast(&mut self, from: usize, msg: Msg) {
        for to in 0..self.nodes.len() {
            if to == from {
                continue;
            }
            self.wire.push_back(Pending {
                at: self.now_ms + DELAY_MS,
                to,
                msg: msg.clone(),
            });
        }
    }

    fn send_to(&mut self, to: usize, msg: Msg) {
        self.wire.push_back(Pending {
            at: self.now_ms + DELAY_MS,
            to,
            msg,
        });
    }

    fn timestamp(height: u64, round: Round) -> u64 {
        height * 1_000 + round as u64
    }

    /// Ticks the production phase order: propose/prevote, drain, precommit,
    /// finalize, view change, retransmit. Every gate the driver applies to a
    /// vote (the write-ahead watermark floor and the once-per-round dedup) is
    /// applied here too, so a vote a live node would refuse is never counted.
    async fn tick(&mut self) {
        let now = self.now_ms;
        for i in 0..self.nodes.len() {
            let height = self.nodes[i].rt.hc.height;
            let round = self.nodes[i].rt.hc.round;
            let ts = Self::timestamp(height, round);

            // ---- propose --------------------------------------------------
            if self.nodes[i].rt.is_proposer()
                && !self.nodes[i].rt.hc.has_live_proposal()
                && !self.nodes[i].rt.has_pending_apply()
            {
                if let Some(block) = self.nodes[i].rt.propose(ts).await {
                    let round = self.nodes[i].rt.hc.round;
                    self.broadcast(i, Msg::Proposal { round, block: Box::new(block) });
                }
            }

            // ---- prevote (value, then nil) --------------------------------
            let has_live = self.nodes[i].rt.hc.has_live_proposal();
            let prevote_round = self.nodes[i].rt.prevote_round();
            if has_live
                && self.nodes[i].last_prevoted != Some((height, prevote_round))
                && !self.nodes[i].at_or_below_prevote_floor(height, prevote_round)
            {
                if let Some(v) = self.nodes[i].rt.make_prevote() {
                    debug_assert_eq!(
                        v.block_hash,
                        self.nodes[i].rt.hc.proposal.map(|(_, h)| h),
                        "a value prevote must name the held proposal"
                    );
                    self.cast_prevote(i, v);
                }
            } else if !has_live {
                let elapsed = now.saturating_sub(self.nodes[i].round_started_ms);
                let peer_alive = matches!(
                    self.nodes[i].peer_seen,
                    Some((ph, pr, at))
                        if ph == height
                            && pr + 1 >= round
                            && now.saturating_sub(at) < ROUND_TIMEOUT_MS
                );
                if elapsed >= 2 * ROUND_TIMEOUT_MS
                    && !peer_alive
                    && self.nodes[i].last_prevoted != Some((height, round))
                    && !self.nodes[i].at_or_below_prevote_floor(height, round)
                {
                    if let Some(v) = self.nodes[i].rt.make_prevote() {
                        debug_assert!(
                            v.block_hash.is_none(),
                            "no live proposal must prevote nil"
                        );
                        self.cast_prevote(i, v);
                    }
                }
            }
        }

        // ---- drain --------------------------------------------------------
        let due: Vec<Pending> = {
            let mut due = Vec::new();
            while let Some(front) = self.wire.front() {
                if front.at > now {
                    break;
                }
                due.push(self.wire.pop_front().expect("front exists"));
            }
            due
        };
        for p in due {
            let height = self.nodes[p.to].rt.hc.height;
            match p.msg {
                Msg::Proposal { round, block } => {
                    let proposer = block.proposer;
                    let _ = self.nodes[p.to]
                        .rt
                        .on_proposal(proposer, *block, round)
                        .await;
                }
                Msg::Vote(v) => {
                    if v.height != height {
                        continue;
                    }
                    match v.kind {
                        stellereum::consensus::VoteKind::Prevote => {
                            let _ = self.nodes[p.to].rt.on_prevote(v.clone());
                        }
                        stellereum::consensus::VoteKind::Precommit => {
                            let _ = self.nodes[p.to].rt.on_precommit(v.clone());
                        }
                    }
                    self.nodes[p.to].peer_seen = Some((v.height, v.round, now));
                }
            }
        }

        // ---- precommit ----------------------------------------------------
        for i in 0..self.nodes.len() {
            let height = self.nodes[i].rt.hc.height;
            if let Some(v) = self.nodes[i].rt.make_precommit() {
                if self.nodes[i].last_precommitted != Some((height, v.round))
                    && !self.nodes[i].at_or_below_precommit_floor(height, v.round)
                {
                    self.nodes[i].last_precommitted = Some((height, v.round));
                    advance_floor(&mut self.nodes[i].precommit_floor, height, v.round);
                    let _ = self.nodes[i].rt.on_precommit(v.clone());
                    self.nodes[i].cast_precommit = Some(v.clone());
                    self.broadcast(i, Msg::Vote(v));
                }
            }
        }

        // ---- finalize -----------------------------------------------------
        for i in 0..self.nodes.len() {
            let before = self.nodes[i].rt.hc.height;
            let round = self.nodes[i].rt.hc.round;
            if self.nodes[i].rt.try_finalize().await.is_some() {
                if before == RESTART_HEIGHT && self.nodes[i].restart_finalized_at.is_none() {
                    self.nodes[i].restart_finalized_at = Some(round);
                }
                self.nodes[i].last_prevoted = None;
                self.nodes[i].last_precommitted = None;
                self.nodes[i].cast_prevote = None;
                self.nodes[i].cast_precommit = None;
                self.nodes[i].round_started_ms = now;
                self.nodes[i].peer_seen = None;
            }
        }

        // ---- view change --------------------------------------------------
        for i in 0..self.nodes.len() {
            let elapsed = now.saturating_sub(self.nodes[i].round_started_ms);
            if elapsed < ROUND_TIMEOUT_MS {
                continue;
            }
            // Production re-sends the round's votes and OUR live proposal
            // before leaving it (a lost frame must not cost the round).
            for v in [
                self.nodes[i].cast_prevote.clone(),
                self.nodes[i].cast_precommit.clone(),
            ]
            .into_iter()
            .flatten()
            {
                self.broadcast(i, Msg::Vote(v));
            }
            if let Some((_, ph)) = self.nodes[i].rt.hc.proposal {
                if let Some(b) = self.nodes[i].rt.blocks.get(&ph).cloned() {
                    self.broadcast(
                        i,
                        Msg::Proposal {
                            round: self.nodes[i].rt.hc.round,
                            block: Box::new(b),
                        },
                    );
                }
            }
            self.nodes[i].rt.next_round();
            self.nodes[i].last_prevoted = None;
            self.nodes[i].last_precommitted = None;
            self.nodes[i].cast_prevote = None;
            self.nodes[i].cast_precommit = None;
            self.nodes[i].round_started_ms = now;
        }

        // ---- periodic retransmit -----------------------------------------
        for i in 0..self.nodes.len() {
            if now.saturating_sub(self.nodes[i].last_rexmit_ms) < REXMIT_MS {
                continue;
            }
            self.nodes[i].last_rexmit_ms = now;
            for v in [
                self.nodes[i].cast_prevote.clone(),
                self.nodes[i].cast_precommit.clone(),
            ]
            .into_iter()
            .flatten()
            {
                self.broadcast(i, Msg::Vote(v));
            }
            if let Some((_, ph)) = self.nodes[i].rt.hc.proposal {
                if let Some(b) = self.nodes[i].rt.blocks.get(&ph).cloned() {
                    // Production envelope: the round we are in, even when the
                    // body itself was signed at an older round.
                    self.broadcast(
                        i,
                        Msg::Proposal {
                            round: self.nodes[i].rt.hc.round,
                            block: Box::new(b),
                        },
                    );
                }
            }
        }
    }

    fn cast_prevote(&mut self, i: usize, v: Vote) {
        let height = v.height;
        self.nodes[i].last_prevoted = Some((height, v.round));
        advance_floor(&mut self.nodes[i].prevote_floor, height, v.round);
        let _ = self.nodes[i].rt.on_prevote(v.clone());
        self.nodes[i].cast_prevote = Some(v.clone());
        self.broadcast(i, Msg::Vote(v));
    }

    /// Run virtual time until `done` or `max_ms` elapses. Returns the virtual
    /// milliseconds consumed.
    async fn run_until(&mut self, max_ms: u64, done: impl Fn(&Cluster) -> bool) -> u64 {
        let start = self.now_ms;
        while self.now_ms - start < max_ms {
            if done(self) {
                return self.now_ms - start;
            }
            self.tick().await;
            tokio::task::yield_now().await;
            self.now_ms += TICK_MS;
        }
        self.now_ms - start
    }

    fn all_at_least(&self, height: u64) -> bool {
        self.nodes.iter().all(|n| n.rt.hc.height >= height)
    }

    /// Restart the selected nodes from PERSISTED state only:
    ///
    /// * the finalized tip and the state stay (that is what the store holds);
    /// * `hc` is rebuilt for the persisted height, with the persisted round,
    ///   the lock, and the parent hash re-anchored from the finalized tip;
    /// * the vote watermark floors and the restored `last_prevoted` stay;
    /// * the in-memory proposal cache (the `HeightConsensus` itself) is gone;
    /// * the parent-decision evidence is rebuilt from the persisted finalized
    ///   block, exactly like the boot path (DOWNTIME-RESTORE), so a valid
    ///   proposal can still be built at the next height.
    fn restart(&mut self, indices: &[usize], restored_round: Round) {
        for &i in indices {
            let height = self.nodes[i].rt.hc.height;
            let mut hc = HeightConsensus::new(height, self.nodes[i].rt.validators.clone());
            if let Some((fh, fhash)) = self.nodes[i].rt.finalized.last().copied() {
                hc.set_parent_hash(fhash);
                if let Some(block) = self.nodes[i].rt.blocks.get(&fhash).cloned() {
                    self.nodes[i]
                        .rt
                        .restore_last_decision_from_finalized_block(&block)
                        .expect("DOWNTIME-RESTORE: the persisted tip must rebuild its parent QC");
                }
                assert!(fh + 1 == height, "test setup: tip must be height - 1");
            }
            // A restart NEVER rewinds below the signed vote watermark.
            let floor = [self.nodes[i].prevote_floor, self.nodes[i].precommit_floor]
                .into_iter()
                .flatten()
                .filter(|(h, _)| *h == height)
                .map(|(_, r)| r)
                .max();
            hc.round = floor.map_or(restored_round, |f| restored_round.max(f));
            self.nodes[i].rt.hc = hc;
            self.nodes[i].rt.install_committee_schedule();
            // In-memory-only driver state is gone too.
            self.nodes[i].cast_prevote = None;
            self.nodes[i].cast_precommit = None;
            self.nodes[i].peer_seen = None;
            self.nodes[i].last_rexmit_ms = 0;
            self.nodes[i].round_started_ms = self.now_ms;
            self.nodes[i].last_prevoted =
                self.nodes[i].prevote_floor.filter(|(h, _)| *h == height);
        }
    }

    /// The driver's value-prevote gate: a live proposal, not already voted in
    /// that round, and strictly above the fsynced watermark floor.
    fn value_prevote(&self, i: usize) -> Option<Vote> {
        let h = self.nodes[i].rt.hc.height;
        if !self.nodes[i].rt.hc.has_live_proposal() {
            return None;
        }
        let r = self.nodes[i].rt.prevote_round();
        if self.nodes[i].last_prevoted == Some((h, r))
            || self.nodes[i].at_or_below_prevote_floor(h, r)
        {
            return None;
        }
        self.nodes[i].rt.make_prevote()
    }

    fn polka_at(&self, i: usize, round: Round) -> Option<Option<BlockHash>> {
        self.nodes[i]
            .rt
            .hc
            .prevote_set(round)
            .and_then(|s| s.quorum_target(&self.nodes[i].rt.validators))
    }

    /// Assert the first post-restart round is coherent: every node prevotes
    /// the SAME hash in the SAME round, and after exchanging those votes every
    /// node holds the prevote quorum (a polka) — i.e. the round can actually
    /// decide instead of ending in a view change.
    fn confirm_first_round_quorum(&mut self, round: Round, expected: BlockHash) {
        let height = self.nodes[0].rt.hc.height;
        let mut votes = Vec::with_capacity(self.nodes.len());
        for i in 0..self.nodes.len() {
            let v = self.value_prevote(i).unwrap_or_else(|| {
                panic!(
                    "node {i} at round {} produced no value prevote after the restart: the                      pre-restart body still owns the current round's slot",
                    self.nodes[i].rt.hc.round
                )
            });
            assert_eq!(v.round, round, "node {i}: the vote must name the current round");
            assert_eq!(
                v.block_hash,
                Some(expected),
                "node {i}: all nodes must prevote the SAME post-restart proposal"
            );
            // Mark the vote as cast so the tick loop does not cast it twice.
            self.nodes[i].last_prevoted = Some((height, v.round));
            advance_floor(&mut self.nodes[i].prevote_floor, height, v.round);
            votes.push(v);
        }
        // Exchange them (full mesh): the polka must exist on every node.
        for i in 0..self.nodes.len() {
            for v in &votes {
                self.nodes[i]
                    .rt
                    .on_prevote(v.clone())
                    .expect("the post-restart value prevote is admissible");
            }
        }
        for i in 0..self.nodes.len() {
            assert_eq!(
                self.polka_at(i, round),
                Some(Some(expected)),
                "node {i} must hold the prevote quorum for the post-restart body at round {round}"
            );
        }
    }
}

/// Drive the healthy chain to `RESTART_HEIGHT` (20 finalized heights) under
/// the production phase order, then stop.
async fn cluster_at_restart_height() -> Cluster {
    let mut c = Cluster::new().await;
    let budget = 900_000;
    c.run_until(budget, |c| c.all_at_least(RESTART_HEIGHT))
        .await;
    assert!(
        c.all_at_least(RESTART_HEIGHT),
        "precondition: the healthy cluster must finalize ~20 heights before the restart; \
         heights={:?} rounds={:?} now={}",
        c.nodes.iter().map(|n| n.rt.hc.height).collect::<Vec<_>>(),
        c.nodes.iter().map(|n| n.rt.hc.round).collect::<Vec<_>>(),
        c.now_ms
    );
    assert!(
        c.nodes.iter().all(|n| n.rt.hc.height == RESTART_HEIGHT),
        "precondition: every node is on the restart height"
    );
    // Anything still queued belongs to the pre-crash rounds; each scenario
    // below re-injects exactly the frame it needs.
    c.wire.clear();
    for node in c.nodes.iter_mut() {
        node.peer_seen = None;
        node.cast_prevote = None;
        node.cast_precommit = None;
        node.round_started_ms = c.now_ms;
    }
    c
}

/// Find a round `k` at `height` where one validator owns BOTH `k` and `k + 1`
/// (so a pre-restart body signed at `k` is still by the scheduled proposer
/// when the restarted nodes are at `k + 1`), while `k + 2` belongs to
/// somebody else (a single stale body costs exactly the poisoned round).
fn stale_body_window(c: &Cluster, height: u64) -> (Round, ValidatorId) {
    for k in 0u32..100_000 {
        let Some(p) = c.proposer(height, k) else {
            continue;
        };
        if c.proposer(height, k + 1) == Some(p) && c.proposer(height, k + 2) != Some(p) {
            return (k, p);
        }
    }
    panic!("no two-round proposer window at height {height}");
}

/// Find `(k, r, p)` with `r >= k + 2` where the SAME validator `p` owns both
/// rounds. A body signed at `k` and re-advertised at `r` is then genuinely
/// stale (beyond the one-round lag) while still passing the proposer-slot
/// check at `r` -- exactly the retransmit shape that poisoned a restarted
/// follower.
fn stale_body_gap_window(c: &Cluster, height: u64) -> (Round, Round, ValidatorId) {
    for k in 0u32..100_000 {
        let Some(p) = c.proposer(height, k) else {
            continue;
        };
        for gap in 2u32..8 {
            if c.proposer(height, k + gap) == Some(p) {
                return (k, k + gap, p);
            }
        }
    }
    panic!("no stale-body gap window at height {height}");
}

// ===========================================================================
// 1. NEGATIVE: a stale proposal for a past round must never block the
//    current round, and must never make the node vote the past round.
// ===========================================================================

#[tokio::test]
async fn stale_proposal_does_not_block_the_current_round() {
    let mut c = cluster_at_restart_height().await;
    let height = RESTART_HEIGHT;
    let (k, p) = stale_body_window(&c, height);
    let pi = c.index_of(p);

    // Everyone is at the pre-restart round k.
    for node in c.nodes.iter_mut() {
        node.rt.hc.round = k;
        node.round_started_ms = c.now_ms;
    }

    // The scheduled proposer signs a real body for k. This is the frame that
    // is still in flight when the process dies.
    let stale = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k))
        .await
        .expect("the scheduled proposer must build a body at k");
    assert_eq!(stale.round, k);
    let stale_hash = stale.compute_hash();

    // The round moves on: the network (and this node, after its restart)
    // reaches k + 1 while the frame is still in flight.
    let mut restarted = Vec::new();
    for i in 0..c.nodes.len() {
        if i != pi {
            // Both followers voted nil at k before the crash (the live shape:
            // no quorum formed at the pre-restart round), then moved on.
            let nil = c.nodes[i]
                .rt
                .make_prevote()
                .expect("an unarmed node must nil-vote");
            assert_eq!(nil.round, k);
            assert_eq!(nil.block_hash, None);
            c.nodes[i].prevote_floor = Some((height, k));
            c.nodes[i].last_prevoted = Some((height, k));
            c.nodes[i].rt.next_round();
            restarted.push(i);
        }
    }
    c.nodes[pi].rt.next_round();
    assert_eq!(c.nodes[pi].rt.hc.round, k + 1);

    // Restart the two followers from persisted state, clearing the in-memory
    // proposal cache. They come back at k + 1 (the persisted round).
    c.restart(&restarted, k + 1);
    for &i in &restarted {
        assert_eq!(c.nodes[i].rt.hc.round, k + 1);
        assert!(!c.nodes[i].rt.hc.has_live_proposal());
    }

    // The pre-restart frame lands now, addressed to the CURRENT round. It is
    // genuine and correctly authored, so it is admitted as a value (no
    // regression of the lock-rescue path) — but it is signed at k and must
    // NOT own the current round's slot.
    for &i in &restarted {
        c.send_to(
            i,
            Msg::Proposal {
                round: k,
                block: Box::new(stale.clone()),
            },
        );
    }
    // Deliver immediately (deterministic).
    let due: Vec<Pending> = c.wire.drain(..).collect();
    for p in due {
        let proposer = stale.proposer;
        c.nodes[p.to]
            .rt
            .on_proposal(proposer, stale.clone(), k)
            .await
            .expect("a genuine past-round body is still admissible as a value");
    }

    // The scheduled proposer re-stamps for the CURRENT round (ruleset v6).
    let current = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k + 1))
        .await
        .expect("the scheduled proposer must propose at k + 1");
    assert_eq!(current.round, k + 1);
    assert_ne!(current.compute_hash(), stale_hash);
    let current_hash = current.compute_hash();

    for &i in &restarted {
        c.nodes[i]
            .rt
            .on_proposal(p, current.clone(), k + 1)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "the current round's proposal was refused after a stale past-round body \
                     was admitted: {e} (this is the RESTART-LIVELOCK admission defect)"
                )
            });
        let v = c.value_prevote(i).unwrap_or_else(|| {
            panic!(
                "node {i} holds the current round's proposal but produced no value prevote \
                 (stale body still owns the slot)"
            )
        });
        assert_eq!(v.round, k + 1, "the vote must name the current round");
        assert_eq!(
            v.block_hash,
            Some(current_hash),
            "the vote must name the proposal the scheduled proposer signed for THIS round"
        );
    }
}

// ===========================================================================
// 2. ONE node restarts from persisted state with an in-flight pre-restart
//    proposal. The cluster must finalize the next height in the FIRST
//    post-restart round, with all three prevoting the same hash.
// ===========================================================================

#[tokio::test]
async fn one_restart_with_inflight_stale_proposal_finalises_in_the_first_round() {
    let mut c = cluster_at_restart_height().await;
    let height = RESTART_HEIGHT;
    let (k, p) = stale_body_window(&c, height);
    let pi = c.index_of(p);
    // The restarted node is a follower of the window's proposer.
    let victim = (0..c.nodes.len()).find(|i| *i != pi).unwrap();

    for node in c.nodes.iter_mut() {
        node.rt.hc.round = k;
        node.round_started_ms = c.now_ms;
    }
    let stale = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k))
        .await
        .expect("the scheduled proposer builds a body at k");
    assert_eq!(stale.round, k);

    // Pre-restart: nobody reaches quorum at k; the victim nil-votes at k (its
    // fsynced watermark), then the process dies while the proposal frame is
    // still in flight.
    for i in 0..c.nodes.len() {
        if i == pi {
            continue;
        }
        let nil = c.nodes[i].rt.make_prevote().expect("unarmed nil at k");
        assert_eq!(nil.round, k);
        assert_eq!(nil.block_hash, None);
        c.nodes[i].prevote_floor = Some((height, k));
        c.nodes[i].last_prevoted = Some((height, k));
        c.nodes[i].rt.next_round();
    }
    c.nodes[pi].rt.next_round();
    assert_eq!(c.nodes[victim].rt.hc.round, k + 1);

    // Restart ONLY the victim, at the persisted round k + 1.
    c.restart(&[victim], k + 1);
    assert_eq!(c.nodes[victim].rt.hc.round, k + 1);
    assert_eq!(
        c.nodes[victim].last_prevoted,
        Some((height, k)),
        "the write-ahead watermark is restored"
    );

    // The pre-restart frame reaches the restarted node now (envelope k: the
    // original frame), while its local round is k + 1.
    c.nodes[victim]
        .rt
        .on_proposal(p, stale.clone(), k)
        .await
        .expect("the in-flight past-round body is admissible as a value");

    // The proposer re-stamps for k + 1 and broadcasts. On HEAD the victim
    // rejects it here with "proposal already recorded for this round".
    let current = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k + 1))
        .await
        .expect("the scheduled proposer proposes at k + 1");
    assert_eq!(current.round, k + 1);
    let current_hash = current.compute_hash();
    // The proposer holds its own body; deliver it to the two followers (the
    // restarted node is one of them). On HEAD the victim refuses it here with
    // "proposal already recorded for this round".
    for i in 0..c.nodes.len() {
        if i == pi {
            continue;
        }
        c.nodes[i]
            .rt
            .on_proposal(p, current.clone(), k + 1)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "node {i} refused the current round's proposal after a stale past-round \
                     body was admitted: {e} (this is the RESTART-LIVELOCK admission defect)"
                )
            });
    }

    // Every live node must prevote the SAME hash in the SAME round, and the
    // exchanged votes must form the quorum in that first post-restart round.
    c.confirm_first_round_quorum(k + 1, current_hash);

    let consumed = c
        .run_until(60_000, |c| {
            c.nodes.iter().all(|n| n.rt.hc.height > height)
        })
        .await;
    assert!(
        c.nodes.iter().all(|n| n.rt.hc.height > height),
        "one restarted validator must not strand the cluster: height {height} never \
         finalized in {consumed} ms (rounds {:?})",
        c.nodes.iter().map(|n| n.rt.hc.round).collect::<Vec<_>>()
    );

    // The deciding round must be the first post-restart round (no lost round).
    for i in 0..c.nodes.len() {
        assert_eq!(
            c.nodes[i].restart_finalized_at,
            Some(k + 1),
            "node {i}: the restart must cost ZERO rounds"
        );
    }
}

// ===========================================================================
// 3. ALL THREE restart from persisted state with an in-flight pre-restart
//    proposal (the shape that hung live for 26+ rounds). The cluster must
//    finalize the next height in the first post-restart round, with every
//    node accepting the scheduled proposal and prevoting the same hash.
// ===========================================================================

#[tokio::test]
async fn all_three_restart_with_inflight_stale_proposal_finalises_in_the_first_round() {
    let mut c = cluster_at_restart_height().await;
    let height = RESTART_HEIGHT;
    let (k, p) = stale_body_window(&c, height);
    let pi = c.index_of(p);

    for node in c.nodes.iter_mut() {
        node.rt.hc.round = k;
        node.round_started_ms = c.now_ms;
    }
    let stale = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k))
        .await
        .expect("the scheduled proposer builds a body at k");
    assert_eq!(stale.round, k);

    // Pre-restart: the followers nil-vote at k; no quorum forms; the process
    // dies with the proposal frame still in flight.
    for i in 0..c.nodes.len() {
        if i == pi {
            continue;
        }
        let nil = c.nodes[i].rt.make_prevote().expect("unarmed nil at k");
        assert_eq!(nil.round, k);
        assert_eq!(nil.block_hash, None);
        c.nodes[i].prevote_floor = Some((height, k));
        c.nodes[i].last_prevoted = Some((height, k));
    }

    // Simultaneous restart of ALL THREE from persisted state: same finalized
    // tip, same state root, same validator set, in-memory consensus cleared.
    let all: Vec<usize> = (0..c.nodes.len()).collect();
    c.restart(&all, k + 1);
    for &i in &all {
        assert_eq!(c.nodes[i].rt.hc.round, k + 1);
        assert!(
            !c.nodes[i].rt.hc.has_live_proposal(),
            "node {i}: the in-memory proposal cache is cleared by the restart"
        );
    }

    // The pre-restart frames still in the network reach the followers at
    // their new round (the proposer never receives its own proposal).
    for &i in &all {
        if i != pi {
            c.nodes[i]
                .rt
                .on_proposal(p, stale.clone(), k)
                .await
                .expect("the in-flight past-round body is admissible as a value");
        }
    }

    // The proposer re-stamps for k + 1. On HEAD every follower refuses it as
    // "already recorded for this round" and falls silent: only the proposer
    // votes, no quorum forms, and the height hangs.
    let current = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k + 1))
        .await
        .expect("the scheduled proposer proposes at k + 1");
    assert_eq!(current.round, k + 1);
    let current_hash = current.compute_hash();
    // Deliver the current-round body to the two followers synchronously (the
    // proposer holds its own). On HEAD every follower refuses it here as
    // "already recorded for this round" and falls silent: only the proposer
    // votes, no quorum forms, and the height hangs.
    for i in 0..c.nodes.len() {
        if i == pi {
            continue;
        }
        c.nodes[i]
            .rt
            .on_proposal(p, current.clone(), k + 1)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "node {i} refused the current round's proposal after the restart: {e}                      (this is the RESTART-LIVELOCK admission defect)"
                )
            });
    }

    // LIVE ASSERTION: in the first post-restart round every node accepts the
    // scheduled proposer's body, prevotes that exact hash, and the exchanged
    // votes form the quorum (a precommit quorum can therefore follow).
    c.confirm_first_round_quorum(k + 1, current_hash);

    let consumed = c
        .run_until(60_000, |c| {
            c.nodes.iter().all(|n| n.rt.hc.height > height)
        })
        .await;
    assert!(
        c.nodes.iter().all(|n| n.rt.hc.height > height),
        "the simultaneous restart must not livelock: height {height} never finalized in \
         {consumed} ms (rounds {:?})",
        c.nodes.iter().map(|n| n.rt.hc.round).collect::<Vec<_>>()
    );
    for i in 0..c.nodes.len() {
        assert_eq!(
            c.nodes[i].restart_finalized_at,
            Some(k + 1),
            "node {i} must decide in the FIRST post-restart round"
        );
    }
}

/// Restart selected nodes from persisted state while KEEPING the lock(s) and
/// the round-free value identity of each locked body. The production boot path
/// does the same: a lock names a signed hash, the body is durable state, and
/// `value_id` is how a re-stamped rescue body is recognised as the same value.
fn restart_with_persisted_locks(c: &mut Cluster, indices: &[usize], restored_round: Round) {
    let locks: Vec<_> = indices
        .iter()
        .map(|&i| c.nodes[i].rt.hc.locked)
        .collect();
    c.restart(indices, restored_round);
    for (slot, &i) in indices.iter().enumerate() {
        if let Some((h, lock_round)) = locks[slot] {
            c.nodes[i].rt.hc.locked = Some((h, lock_round));
            if let Some(body) = c.nodes[i].rt.blocks.get(&h).cloned() {
                let vid = body.value_id();
                c.nodes[i].rt.hc.note_value_id(h, vid);
            }
        }
    }
}

// ===========================================================================
// 4. RESTART-SPLIT: all three restart with a RESTORED LOCK and an empty
//    proposal cache, while a stale body (signed at k) is still circulating
//    under the CURRENT round (k + 1) envelope. The stale frame must NOT arm
//    the scheduled proposer's slot, or it can never re-stamp the locked
//    value; every node must prevote the SAME current-round body and the
//    height must decide in the first post-restart round.
// ===========================================================================

#[tokio::test]
async fn all_three_restart_with_restored_lock_and_stale_rebroadcast_decide_first_round() {
    let mut c = cluster_at_restart_height().await;
    let height = RESTART_HEIGHT;
    let (k, r, p) = stale_body_gap_window(&c, height);
    let pi = c.index_of(p);

    for node in c.nodes.iter_mut() {
        node.rt.hc.round = k;
        node.round_started_ms = c.now_ms;
    }

    // Pre-restart: the scheduled proposer signs body X at k; every node
    // prevotes it and locks it (a full prevote QC exists, only the precommit
    // quorum is still missing when the process dies).
    let stale = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k))
        .await
        .expect("the scheduled proposer builds X at k");
    assert_eq!(stale.round, k);
    let stale_hash = stale.compute_hash();
    for i in 0..c.nodes.len() {
        if i != pi {
            c.nodes[i]
                .rt
                .on_proposal(p, stale.clone(), k)
                .await
                .expect("followers accept X at k");
        }
    }
    let mut votes = Vec::with_capacity(c.nodes.len());
    for i in 0..c.nodes.len() {
        let v = c.nodes[i]
            .rt
            .make_prevote()
            .expect("every node prevotes X at k");
        assert_eq!(v.round, k);
        assert_eq!(v.block_hash, Some(stale_hash));
        c.nodes[i].last_prevoted = Some((height, k));
        advance_floor(&mut c.nodes[i].prevote_floor, height, k);
        c.nodes[i].cast_prevote = Some(v.clone());
        votes.push(v);
    }
    for i in 0..c.nodes.len() {
        for v in &votes {
            c.nodes[i]
                .rt
                .on_prevote(v.clone())
                .expect("the prevote quorum is admissible");
        }
        assert_eq!(
            c.nodes[i].rt.hc.try_prevote_quorum(),
            Some(Some(stale_hash)),
            "precondition: every node observed the polka for X"
        );
        assert!(c.nodes[i]
            .rt
            .make_precommit()
            .is_some_and(|pc| pc.round == k));
        assert_eq!(
            c.nodes[i].rt.hc.locked.map(|(h, _)| h),
            Some(stale_hash),
            "precondition: every node locked X at k"
        );
    }

    // Coordinated restart into round r (the fsynced watermark), with the
    // locks and their value identities restored and the proposal cache empty.
    let all: Vec<usize> = (0..c.nodes.len()).collect();
    restart_with_persisted_locks(&mut c, &all, r);
    for &i in &all {
        assert_eq!(c.nodes[i].rt.hc.round, r);
        assert!(!c.nodes[i].rt.hc.has_live_proposal());
        assert_eq!(
            c.nodes[i].rt.hc.locked.map(|(h, _)| h),
            Some(stale_hash),
            "node {i}: the lock must survive the restart"
        );
    }

    // The stale frame is re-advertised under the CURRENT envelope (this is
    // what the old retransmit path did). It is still a valid body for its own
    // signed round, but it must not become the proposal for k + 1.
    for &i in &all {
        c.nodes[i]
            .rt
            .on_proposal(p, stale.clone(), r)
            .await
            .expect("a genuine stale body is still admissible as a candidate");
        assert!(
            !c.nodes[i].rt.hc.has_live_proposal(),
            "node {i}: a body signed at k must not own round r's proposal slot"
        );
    }

    // The proposer at r is the author of X (by construction), so it CAN
    // and MUST re-stamp the locked value at the current round.
    let current = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, r))
        .await
        .expect("the stale frame must not block the locked value's re-stamp");
    assert_eq!(current.round, r);
    assert_ne!(current.compute_hash(), stale_hash);
    let current_hash = current.compute_hash();
    for i in 0..c.nodes.len() {
        if i != pi {
            c.nodes[i]
                .rt
                .on_proposal(p, current.clone(), r)
                .await
                .expect("the current-round re-stamp of the locked value is accepted");
        }
    }

    // LIVE ASSERTION: same hash, same round, real quorum on every node.
    c.confirm_first_round_quorum(r, current_hash);

    let consumed = c
        .run_until(60_000, |c| {
            c.nodes.iter().all(|n| n.rt.hc.height > height)
        })
        .await;
    assert!(
        c.nodes.iter().all(|n| n.rt.hc.height > height),
        "the restored-lock restart must not livelock: height {height} never finalized in \
         {consumed} ms (rounds {:?})",
        c.nodes.iter().map(|n| n.rt.hc.round).collect::<Vec<_>>()
    );
    for i in 0..c.nodes.len() {
        assert_eq!(
            c.nodes[i].restart_finalized_at,
            Some(r),
            "node {i}: the height must decide in the first post-restart round"
        );
    }
}

// ===========================================================================
// 5. NEGATIVE (admission): a stale body re-broadcast at the CURRENT round
//    must never be the value a fresh (unlocked, empty-cache) node prevotes
//    when the genuine current-round body exists.
// ===========================================================================

#[tokio::test]
async fn stale_rebroadcast_never_arms_a_fresh_node_when_current_body_exists() {
    let mut c = cluster_at_restart_height().await;
    let height = RESTART_HEIGHT;
    let (k, r, p) = stale_body_gap_window(&c, height);
    let pi = c.index_of(p);
    let fresh = (0..c.nodes.len()).find(|i| *i != pi).unwrap();

    // The stale body is signed at k by the proposer that also owns k + 1.
    c.nodes[pi].rt.hc.round = k;
    c.nodes[pi].round_started_ms = c.now_ms;
    let stale = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, k))
        .await
        .expect("the scheduled proposer builds the stale body at k");
    let stale_hash = stale.compute_hash();

    // The fresh node restarts into r: no lock, no proposal cache, no
    // watermark. This is the node the old retransmit poisoned.
    c.restart(&[fresh], r);
    assert_eq!(c.nodes[fresh].rt.hc.round, r);
    assert!(c.nodes[fresh].rt.hc.locked.is_none());

    c.nodes[fresh]
        .rt
        .on_proposal(p, stale.clone(), r)
        .await
        .expect("the stale body is still admissible as a candidate body");
    assert!(
        !c.nodes[fresh].rt.hc.has_live_proposal(),
        "a stale body re-broadcast at r must not own the current round's slot"
    );
    assert!(
        c.value_prevote(fresh).is_none(),
        "a fresh node must not prevote a stale body that was merely re-enveloped"
    );

    // The genuine current-round body arrives: it must be accepted and voted.
    c.nodes[pi].rt.hc.round = r;
    let current = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, r))
        .await
        .expect("the scheduled proposer builds the genuine current body");
    assert_eq!(current.round, r);
    assert_ne!(current.compute_hash(), stale_hash);

    c.nodes[fresh]
        .rt
        .on_proposal(p, current.clone(), r)
        .await
        .expect("the current-round body must still be accepted");
    let v = c.value_prevote(fresh).expect("the fresh node votes the genuine body");
    assert_eq!(v.round, r);
    assert_eq!(
        v.block_hash,
        Some(current.compute_hash()),
        "the only value a fresh node may prevote here is the current-round body"
    );
}

// ===========================================================================
// 6. NEGATIVE (lock-rescue regression): a genuinely late but CURRENT-round
//    (re-stamped) body is still accepted and voted. That is the rescue path
//    the stale-body guard must not touch.
// ===========================================================================

#[tokio::test]
async fn late_current_round_body_is_still_accepted_and_voted() {
    let mut c = cluster_at_restart_height().await;
    let height = RESTART_HEIGHT;
    let (_k, r, p) = stale_body_gap_window(&c, height);
    let pi = c.index_of(p);
    let fresh = (0..c.nodes.len()).find(|i| *i != pi).unwrap();

    // Build the CURRENT-round body directly.
    c.nodes[pi].rt.hc.round = r;
    c.nodes[pi].round_started_ms = c.now_ms;
    let current = c.nodes[pi]
        .rt
        .propose(Cluster::timestamp(height, r))
        .await
        .expect("the scheduled proposer builds at r");
    assert_eq!(current.round, r);
    let current_hash = current.compute_hash();

    // The receiver restarts at r with an empty cache; the frame arrives
    // late, but its signed round is CURRENT, so it is the real proposal.
    c.restart(&[fresh], r);
    c.nodes[fresh]
        .rt
        .on_proposal(p, current.clone(), r)
        .await
        .expect("a late current-round body is a normal proposal, not a stale one");
    let v = c
        .value_prevote(fresh)
        .expect("the current-round body must be voted");
    assert_eq!(v.round, r);
    assert_eq!(v.block_hash, Some(current_hash));
}
