//! A deterministic, in-process MULTI-NODE CONSENSUS LIVENESS harness.
//!
//! # WHAT THIS IS FOR
//!
//! The live 4-node WAN stand was parked at height 285027 from 2026-10-19: the
//! nodes formed a 3.5-STELL **prevote** quorum but never a **precommit**
//! quorum, so nothing ever finalized. Nothing in the suite exercised several
//! nodes with SKEWED round clocks and asserted that the chain finalizes, so
//! that whole class of failure could come back silently.
//!
//! This module is that missing test rig. It runs N real
//! [`ValidatorRuntime`]s against each other, driven by a **virtual clock** and
//! a **deterministic message pump** (no wall clock in the protocol path, no
//! OS randomness), and it drives the REAL consensus code paths:
//! [`ValidatorRuntime::propose`], [`ValidatorRuntime::on_proposal`],
//! [`ValidatorRuntime::make_prevote`] / [`ValidatorRuntime::on_prevote`],
//! [`ValidatorRuntime::make_precommit`] / [`ValidatorRuntime::on_precommit`],
//! [`ValidatorRuntime::try_finalize`] and [`ValidatorRuntime::adopt_committed`].
//! Nothing here is a mock: the quorum accounting, the certificates, the vote
//! sets and the state transitions are the production ones.
//!
//! # DETERMINISM CONTRACT
//!
//! * **Keys** are derived from a seed (`SigningKey::from_bytes`), never from
//!   the OS RNG.
//! * **The clock** is virtual: the harness advances `now_ms` by a fixed tick
//!   and never reads the wall clock to decide anything.
//! * **Message loss / delay** is drawn from a seeded xorshift64* PRNG, in a
//!   fixed broadcast order.
//! * **The node tick** mirrors the production main loop
//!   (`propose -> prevote -> drain -> precommit -> finalize -> view change`).
//!
//! # WHY THERE IS NO WALL CLOCK ANYWHERE IN HERE
//!
//! The consensus state machine is CLOCK-FREE: `src/consensus.rs` contains no
//! `Instant::now`, no `SystemTime::now` and no `elapsed()`. The peer-driven
//! round-jump budget (`HeightConsensus::sync_round_to`) is per ROUND
//! (`MAX_SYNC_JUMPS_PER_ROUND`), refilled on every view change, so a node
//! that fell behind can always follow the network without a timer expiring.
//!
//! That is what makes this harness both fast and reproducible: it runs the
//! whole cluster as fast as the CPU allows and still gets the same answer
//! every time. (The only wall clock in the runtime is the deadlock breaker's
//! `last_progress_at`, and the harness never calls that path.)
//!
//! # WHAT IS MODELLED, AND WHAT IS DELIBERATELY NOT
//!
//! MODELLED (the production rules, one for one):
//!
//! * the tick order `propose -> prevote -> drain -> precommit -> finalize ->
//!   view change` (`src/main.rs`'s consensus loop);
//! * "prevote a value only with a live proposal" and "prevote NIL after
//!   twice the round timeout without one" (production 2 / 2b);
//! * "precommit at the POLKA's round, deduped on `(height, vote.round)`"
//!   (production 4) — the rule that the live #285027 stall was about;
//! * the re-send of this round's votes AND of our own proposal on a view
//!   change (production's retransmit);
//! * the commit broadcast, so a peer that missed the deciding vote adopts
//!   the committed block (`adopt_committed`);
//! * one tick of network latency on every message, plus the optional
//!   per-node delay / loss profile.
//!
//! SIMPLIFIED ON PURPOSE:
//!
//! * the round timeout is FLAT per node (scaled by the node's skew
//!   factor) instead of the production's backoff ladder
//!   (`effective_round_timeout_ms` grows the timeout with the number of
//!   view changes at the height) and its view-change HOLD. A flat timeout
//!   makes a stuck height spin FASTER, so a scenario reaches its verdict
//!   sooner; it cannot make a healthy cluster look unhealthy.
//! * the message pump has no reordering beyond the delay profile and no
//!   partition, so a scenario that needs a partition models it with the
//!   `down` flag.
//!
//!
//! # REUSE
//!
//! ```ignore
//! mod support;
//! use support::consensus_cluster::ConsensusCluster;
//! ```

#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use stellereum::consensus::{
    BlockHash, Height, HeightConsensus, QuorumCertificate, Round, ValidatorId, ValidatorSet, Vote,
    VoteKind,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

// ===========================================================================
// Deterministic PRNG (xorshift64*) - no OS randomness anywhere in the harness.
// ===========================================================================

/// A tiny seeded PRNG. Deterministic across runs and platforms: the same seed
/// yields the same sequence, which is what makes the drop/delay draws
/// reproducible.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Build a PRNG from a seed. The state is forced non-zero (xorshift64*
    /// degenerates at zero).
    pub fn new(seed: u64) -> Self {
        Rng { state: seed | 1 }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `[0, n)` (0 when `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    /// True with probability `permille / 1000`.
    pub fn chance(&mut self, permille: u32) -> bool {
        permille > 0 && self.below(1000) < permille as u64
    }
}

// ===========================================================================
// Configuration
// ===========================================================================

/// SIM-ONLY straggler-aware round extension (proposer-rework experiment).
///
/// This policy is HARNESS-ONLY test code: it is never consulted by any
/// production path (`src/` is untouched). It models the recommended design —
/// slow the round rate while a straggler is detected via observed peer rounds
/// instead of racing a fixed backoff — so a scenario can compare stall vs.
/// fix on the same seed with everything else identical.
///
/// Two evidence-gated clauses, both bounded by `cap_ms` and both requiring
/// FRESH evidence (a silent peer stops stretching rounds once its last
/// observed vote ages past `freshness_ms`, so a dead peer cannot park the
/// chain — only a live-but-slow one buys extra time):
///
/// * (1) BEHIND-VOTE: some other validator was recently observed voting at an
///   older (height, round) than ours — its vote for our round may still be in
///   flight, so grant it `grace_ms` before view-changing.
/// * (2) SCHEDULED-PROPOSAL: we hold no live proposal and the scheduled
///   proposer of our (height, round) is not demonstrably ahead of us (never
///   heard, or last seen at-or-behind our round, recently) — its proposal may
///   still be in flight, so wait for the scheduled value instead of racing to
///   the next round proposalless.
///
/// Disabled by default: every pre-existing scenario runs with `enabled: false`
/// and is bit-identical to before (no RNG, wire, or timing change on that
/// path — only passive counters are recorded).
#[derive(Clone, Copy, Debug)]
pub struct StragglerPolicy {
    /// Master switch. `false` = control behaviour, exactly the old harness.
    pub enabled: bool,
    /// Extra round time granted per engagement, in virtual ms.
    pub grace_ms: u64,
    /// Hard cap on the extra time (single clause; the two clauses do not
    /// stack — one grace per round at most).
    pub cap_ms: u64,
    /// How recent (virtual ms) a peer sighting must be to count as evidence.
    pub freshness_ms: u64,
    /// SIM-ONLY round-timer accounting fix (TEMPO §5.3): subsume the grace
    /// into the pre-existing 2× peer-active hold bound instead of adding it
    /// past the deterministic deadline. `false` = production-today stacking
    /// (`deadline = base + grace`); `true` = fixed
    /// (`deadline = base + min(grace, max(0, 2 * cluster_base - base))`).
    /// Default `false`, so every pre-existing scenario is unaffected; the
    /// accounting scenario opts in explicitly. (The production hold itself —
    /// `hold_bounded` — needs no harness model here: the scenario operates in
    /// the saturated regime `grace >= slack`, where the hold is masked in
    /// both compositions and the deadlines above match production exactly.)
    pub subsume_grace: bool,
}

impl Default for StragglerPolicy {
    fn default() -> Self {
        StragglerPolicy {
            enabled: false,
            grace_ms: 0,
            cap_ms: 0,
            freshness_ms: 20_000,
            subsume_grace: false,
        }
    }
}

impl StragglerPolicy {
    /// A bounded grace: `grace_ms` extra round time on fresh straggler
    /// evidence, capped at `cap_ms`, evidence fresher than `freshness_ms`.
    pub fn fixed(grace_ms: u64, cap_ms: u64, freshness_ms: u64) -> Self {
        StragglerPolicy {
            enabled: true,
            grace_ms,
            cap_ms,
            freshness_ms,
            subsume_grace: false,
        }
    }

    /// Same bounded grace, but subsumed into the 2× hold bound (the
    /// round-timer accounting fix): the deadline can fill the slack up to
    /// `2 * cluster_base`, never stack past it.
    pub fn fixed_subsumed(grace_ms: u64, cap_ms: u64, freshness_ms: u64) -> Self {
        StragglerPolicy {
            enabled: true,
            grace_ms,
            cap_ms,
            freshness_ms,
            subsume_grace: true,
        }
    }
}

/// What a Byzantine validator does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Byzantine {
    /// Behave honestly.
    None,
    /// Cast a SECOND prevote for a DIFFERENT block at the same
    /// (height, round). The vote set keeps the FIRST vote, so the honest
    /// quorum still forms, and the conflicting pair is recorded as
    /// equivocation evidence.
    DoublePrevote,
    /// Broadcast a SECOND, CONFLICTING proposal for the SAME (height, round)
    /// whenever this member is the proposer: the honest block is cloned, its
    /// timestamp bumped by one second and the copy re-signed with the same
    /// key, so the second body is genuine (passes authentication and
    /// validation) but names a DIFFERENT hash, and it is put on the wire
    /// AFTER the honest one.
    ///
    /// The production proposal path keeps the FIRST value
    /// (`HeightConsensus::receive_proposal` refuses "proposal already
    /// recorded for this round"), so every honest node votes the first body
    /// and refuses the second: no fork, liveness preserved. The refused
    /// second proposal is the proof the attack ran (`proposals_refused`).
    DoubleProposal,
    /// Cast a NIL prevote at every (height, round), immediately, instead of
    /// the production prevote (value with a live proposal, nil after twice
    /// the round timeout without one).
    ///
    /// THE LIVE SHAPE (stalled chain, largest-power validator voting nil at
    /// a high round): a validator locked on a value the network no longer
    /// proposes — or holding no live proposal at all — prevotes nil every
    /// round (`HeightConsensus::decide_prevote`). When its power alone
    /// exceeds `total - quorum` (any holder of more than a third on a
    /// skewed set), no value can ever reach a prevote quorum again: the
    /// polka that would unlock it never forms, so it nils forever and the
    /// height never finalizes. The harness models the VOTE (nil every
    /// round), not the lock that caused it: the quorum arithmetic is what
    /// is under test.
    ///
    /// Precommits are untouched (the node still follows the polka, if one
    /// ever forms), so this is not an equivocation: one vote per
    /// (height, round, kind), always nil.
    NilPrevote,
}

/// The per-node profile of a cluster member.
#[derive(Clone, Debug)]
pub struct NodeProfile {
    /// Voting power in the validator set.
    pub power: u64,
    /// This node's round timeout MULTIPLIER (1 = the cluster base, 5 = five
    /// times slower).
    pub round_timeout_factor: u64,
    /// The node starts this many rounds BEHIND the rest of the cluster (the
    /// "N rounds late" scenario). The offset is applied to the cluster's
    /// starting round, so the scenario does not have to burn N rounds of
    /// virtual time to create the skew.
    pub late_rounds: u32,
    /// The node is DOWN: it never proposes, never votes, and nothing is
    /// delivered to it.
    pub down: bool,
    /// Permille of the VOTES addressed to this node that are dropped.
    pub vote_loss_permille: u32,
    /// Permille of the PRECOMMITS addressed to this node that are dropped.
    ///
    /// Separate from `vote_loss_permille` because "the prevote quorum forms
    /// but the precommit quorum never does" is THE live failure shape, and
    /// it needs a fault that spares the prevotes.
    pub precommit_loss_permille: u32,
    /// Byzantine behaviour.
    pub byzantine: Byzantine,
    /// Extra delivery delay applied to the messages addressed to this node.
    pub inbound_delay_ms: u64,
    /// SPD attribution knob (harness-only, temporary): extra virtual ms added to
    /// PROPOSAL delivery from this node, modeling a slow 1-vCPU proposer whose
    /// block build + pubsub schedule takes seconds. 0 = fast (default, all
    /// pre-existing tests). Set only by the SPD attribution harness.
    pub propose_delay_ms: u64,
}

impl Default for NodeProfile {
    fn default() -> Self {
        NodeProfile {
            power: 1,
            round_timeout_factor: 1,
            late_rounds: 0,
            down: false,
            vote_loss_permille: 0,
            precommit_loss_permille: 0,
            byzantine: Byzantine::None,
            inbound_delay_ms: 0,
            propose_delay_ms: 0,
        }
    }
}

impl NodeProfile {
    /// A profile with the given voting power.
    pub fn with_power(mut self, power: u64) -> Self {
        self.power = power;
        self
    }

    /// A profile whose round timeout is `factor` times the cluster base.
    pub fn with_round_timeout_factor(mut self, factor: u64) -> Self {
        self.round_timeout_factor = factor.max(1);
        self
    }

    /// A profile that starts `rounds` rounds behind the cluster.
    pub fn late_by(mut self, rounds: u32) -> Self {
        self.late_rounds = rounds;
        self
    }

    /// A profile for a DOWN node.
    pub fn down(mut self) -> Self {
        self.down = true;
        self
    }

    /// A profile that drops `permille` of the votes addressed to it.
    pub fn losing_votes(mut self, permille: u32) -> Self {
        self.vote_loss_permille = permille;
        self
    }

    /// A profile that drops `permille` of the PRECOMMITS addressed to it.
    pub fn losing_precommits(mut self, permille: u32) -> Self {
        self.precommit_loss_permille = permille;
        self
    }

    /// A profile with the given Byzantine behaviour.
    pub fn byzantine(mut self, mode: Byzantine) -> Self {
        self.byzantine = mode;
        self
    }

    /// A profile with an extra inbound delivery delay.
    pub fn with_inbound_delay_ms(mut self, ms: u64) -> Self {
        self.inbound_delay_ms = ms;
        self
    }

    /// SPD attribution knob: slow-proposer build delay (harness-only).
    pub fn with_propose_delay_ms(mut self, ms: u64) -> Self {
        self.propose_delay_ms = ms;
        self
    }
}

// ===========================================================================
// Reporting
// ===========================================================================

/// One vote a node CAST, recorded by the harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CastVote {
    pub height: Height,
    pub round: Round,
    pub kind: VoteKind,
    pub target: Option<BlockHash>,
}

/// The per-node view a scenario asserts on.
#[derive(Clone, Debug, Default)]
pub struct NodeReport {
    /// The node's index in the cluster.
    pub index: usize,
    /// Short id of the node (first 4 bytes of the validator id, hex).
    pub id: String,
    /// The height the node's consensus is currently at.
    pub height: Height,
    /// The round the node's consensus is currently at.
    pub round: Round,
    /// The highest height the node finalized.
    pub finalized_height: Height,
    /// Every height/hash the node finalized, in order.
    pub finalized: Vec<(Height, BlockHash)>,
    /// The round each finalized height was DECIDED in (the precommit
    /// quorum's round). The liveness metric: how many rounds a height cost.
    pub decide_rounds: Vec<Round>,
    /// The round the node's CURRENT height started in. The decide rounds are
    /// measured as a DELTA against it, so a cluster that starts at round 30
    /// does not look like it burned 30 rounds on its first height.
    pub height_start_round: Round,
    /// How many prevotes the node CAST.
    pub prevotes_cast: u64,
    /// How many precommits the node CAST.
    pub precommits_cast: u64,
    /// How many prevotes the node RECEIVED (and accepted).
    pub prevotes_received: u64,
    /// How many precommits the node RECEIVED (and accepted).
    pub precommits_received: u64,
    /// SIM-ONLY: vote arrivals observed in the drain, accepted or not.
    /// The denominator of the stale-arrival share.
    pub vote_arrivals: u64,
    /// SIM-ONLY: arrivals whose vote named our height but an OLDER round than
    /// the one we were in when they landed — "one round stale", the incident
    /// signature (votes absorbed into old buckets, never counting).
    pub vote_arrivals_stale: u64,
    /// SIM-ONLY: ticks on which the straggler grace kept this node's round
    /// open past its base timeout (the "mechanism really ran" pin).
    pub grace_extends: u64,
    /// SIM-ONLY: view changes taken (round timeouts that fired). The "rounds
    /// used" half of the liveness metric: voting without deciding shows up
    /// as thousands of view changes per finalized height.
    pub view_changes: u64,
    /// SIM-ONLY: arrivals in (height, round) buckets that never decided
    /// anything on this node. Arrival LATENESS (landing after the local round
    /// moved on) is what the incident reported; WASTE is the load-bearing
    /// half — the late-quorum path can still absorb and count a late arrival,
    /// but a wasted one never belonged to any quorum.
    pub vote_wasted: u64,
    /// How many proposals the node received.
    pub proposals_received: u64,
    /// How many proposals the node REFUSED.
    pub proposals_refused: u64,
    /// The round in which the node's PREVOTE quorum certificate formed.
    pub prevote_qc_round: Option<Round>,
    /// The VOTING POWER behind the prevote quorum target.
    ///
    /// The live failure was "3.5 STELL prevoted but no precommit quorum
    /// formed". This number is how a report says it out loud: the power is
    /// what the quorum is measured in, and `quorum_power` is what it needed.
    pub prevote_qc_power: Option<u64>,
    /// The VOTING POWER behind the precommit quorum target.
    pub precommit_qc_power: Option<u64>,
    /// The voting power the validator set demands for a quorum.
    pub quorum_power: u64,
    /// The round in which a PRECOMMIT was EXPECTED: the round of the prevote
    /// quorum the node holds (Tendermint casts the precommit at the polka's
    /// own round). `Some` with no matching `precommit_qc_round` is exactly
    /// the live failure shape: a prevote QC that never turned into a
    /// precommit QC.
    pub precommit_expected_round: Option<Round>,
    /// The round in which the node cast its precommit (the polka's round).
    pub precommit_round: Option<Round>,
    /// The round of the node's precommit quorum certificate (the decision).
    pub precommit_qc_round: Option<Round>,
    /// The block hash the node locked on (if any).
    pub locked: Option<BlockHash>,
    /// The consensus-side explanation of why the node is not finalizing
    /// (`HeightConsensus::finalize_blockers`).
    pub blockers: Option<String>,
    /// The node's current state root.
    pub state_root: BlockHash,
    /// How many round jumps the node consumed (the phase-alignment path).
    pub sync_jumps: u32,
    /// Every vote the node CAST (the double-vote invariant reads this).
    pub cast_votes: Vec<CastVote>,
}

impl NodeReport {
    /// A one-line human summary, used in the failure diagnostics.
    ///
    /// It names EVERYTHING a liveness failure needs: the node's height and
    /// round, how many prevotes and precommits it cast and received, the
    /// round in which the prevote QC formed, the round in which the precommit
    /// was EXPECTED, the round in which the precommit QC formed (if it ever
    /// did), and the voting power behind each of the two quorums against the
    /// power the set demands. "prevote QC at round 30 (3.5/4.0 power,
    /// quorum 2.67), precommit expected at round 30, precommit QC: none" IS
    /// the live #285027 failure, in one line.
    pub fn summary(&self) -> String {
        format!(
            "node {} ({}): h={} r={} finalized_h={} decide_rounds={:?} \
             prevotes(cast/recv)={}/{} \
             precommits(cast/recv)={}/{} proposals(recv/refused)={}/{} \
             prevote_qc(round/power)={:?}/{:?} precommit_expected_round={:?} \
             precommit_round={:?} precommit_qc(round/power)={:?}/{:?} \
             quorum_power={} locked={:?} sync_jumps={} blockers={:?} \
             arrivals(stale/total)={}/{} grace_extends={} view_changes={} wasted={}",
            self.index,
            self.id,
            self.height,
            self.round,
            self.finalized_height,
            self.decide_rounds,
            self.prevotes_cast,
            self.prevotes_received,
            self.precommits_cast,
            self.precommits_received,
            self.proposals_received,
            self.proposals_refused,
            self.prevote_qc_round,
            self.prevote_qc_power,
            self.precommit_expected_round,
            self.precommit_round,
            self.precommit_qc_round,
            self.precommit_qc_power,
            self.quorum_power,
            self.locked.map(|h| hex::encode(&h[..4])),
            self.sync_jumps,
            self.blockers,
            self.vote_arrivals_stale,
            self.vote_arrivals,
            self.grace_extends,
            self.view_changes,
            self.vote_wasted,
        )
    }

    /// SIM-ONLY: share of vote arrivals that landed stale (older round than
    /// the one we were in at receipt). 1.0 = every vote arrived a round late.
    pub fn stale_share(&self) -> f64 {
        if self.vote_arrivals == 0 {
            0.0
        } else {
            self.vote_arrivals_stale as f64 / self.vote_arrivals as f64
        }
    }

    /// SIM-ONLY: share of vote arrivals that never belonged to any decision
    /// (their bucket formed no quorum on this node). 1.0 = every vote was
    /// absorbed into a dead bucket — the stall, in one number.
    pub fn wasted_share(&self) -> f64 {
        if self.vote_arrivals == 0 {
            0.0
        } else {
            self.vote_wasted as f64 / self.vote_arrivals as f64
        }
    }
}

/// The result of a cluster run.
#[derive(Clone, Debug, Default)]
pub struct ClusterReport {
    /// Virtual milliseconds the cluster ran for.
    pub virtual_ms: u64,
    /// How many ticks the cluster executed.
    pub ticks: u64,
    /// The per-node views.
    pub nodes: Vec<NodeReport>,
    /// Every equivocation pair the cluster OBSERVED (voter, vote, vote).
    pub equivocations: Vec<(ValidatorId, Vote, Vote)>,
    /// The highest height any node finalized.
    pub best_height: Height,
    /// The height EVERY up node finalized (the chain's common head).
    pub common_height: Height,
}

impl ClusterReport {
    /// The per-node views rendered as one diagnostic block.
    pub fn diagnostics(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "cluster ran {} ticks / {} ms of virtual time; best height {}; common height {}\n",
            self.ticks, self.virtual_ms, self.best_height, self.common_height
        ));
        for n in &self.nodes {
            out.push_str("  ");
            out.push_str(&n.summary());
            out.push('\n');
        }
        if !self.equivocations.is_empty() {
            out.push_str(&format!(
                "  equivocations observed: {}\n",
                self.equivocations.len()
            ));
        }
        out
    }

    /// A deterministic fingerprint of the WHOLE run outcome.
    ///
    /// Two runs of the same scenario must produce the SAME fingerprint: the
    /// same finalized blocks (height AND hash), the same rounds, the same
    /// vote counts and the same sequence of cast votes. It is the machine
    /// check for "the harness is deterministic" — a fingerprint that differs
    /// between two identical runs means something in the harness reads a
    /// clock, an RNG or an unordered map.
    pub fn fingerprint(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "run(virtual_ms={},ticks={},best={},common={})",
            self.virtual_ms, self.ticks, self.best_height, self.common_height
        ));
        for n in &self.nodes {
            out.push_str(&format!(
                "|n{}(h={},r={},fh={},pc={},pp={},cc={},cp={},pr={},pf={},pvqc={:?},pcqc={:?},sr={},sj={})",
                n.index,
                n.height,
                n.round,
                n.finalized_height,
                n.prevotes_cast,
                n.prevotes_received,
                n.precommits_cast,
                n.precommits_received,
                n.proposals_received,
                n.proposals_refused,
                n.prevote_qc_round,
                n.precommit_qc_round,
                hex::encode(&n.state_root[..8]),
                n.sync_jumps,
            ));
            // The finalized chain itself, in order.
            for (h, hash) in &n.finalized {
                out.push_str(&format!("#{}:{} ", h, hex::encode(hash)));
            }
            // Every vote the node cast, in order.
            for v in &n.cast_votes {
                let kind = match v.kind {
                    VoteKind::Prevote => "p",
                    VoteKind::Precommit => "c",
                };
                let target = v.target.map(|t| hex::encode(&t[..4])).unwrap_or_default();
                out.push_str(&format!("v{}/{}/{}:{} ", v.height, v.round, kind, target));
            }
        }
        out
    }

    /// The double-vote invariant: no node may cast two DIFFERENT votes for
    /// the same (height, round, kind).
    ///
    /// Returns the offending `(node, height, round, kind)` tuples. A node
    /// listed in `exempt` (the designated Byzantine) is not checked.
    pub fn double_votes(&self, exempt: &[usize]) -> Vec<(usize, Height, Round, VoteKind)> {
        let mut out = Vec::new();
        for node in &self.nodes {
            if exempt.contains(&node.index) {
                continue;
            }
            // `VoteKind` is not `Hash`, so the kind is tagged by hand.
            let mut seen: HashMap<(Height, Round, u8), Option<BlockHash>> = HashMap::new();
            for v in &node.cast_votes {
                let tag = match v.kind {
                    VoteKind::Prevote => 0u8,
                    VoteKind::Precommit => 1u8,
                };
                match seen.get(&(v.height, v.round, tag)) {
                    Some(first) if *first != v.target => {
                        out.push((node.index, v.height, v.round, v.kind));
                    }
                    Some(_) => {}
                    None => {
                        seen.insert((v.height, v.round, tag), v.target);
                    }
                }
            }
        }
        out
    }

    /// The heights finalized by EVERY up node, with the hash each node
    /// finalized there. A fork shows up as two different hashes at one
    /// height.
    pub fn finalized_by_height(&self) -> HashMap<Height, Vec<(usize, BlockHash)>> {
        let mut out: HashMap<Height, Vec<(usize, BlockHash)>> = HashMap::new();
        for node in &self.nodes {
            for (h, hash) in &node.finalized {
                out.entry(*h).or_default().push((node.index, *hash));
            }
        }
        out
    }
}

// ===========================================================================
// The wire
// ===========================================================================

/// One message in flight.
#[derive(Clone, Debug)]
enum Wire {
    Proposal {
        proposer: ValidatorId,
        block: Block,
        round: Round,
    },
    Vote {
        vote: Vote,
        locked: Option<BlockHash>,
    },
    Committed {
        height: Height,
        block: Block,
        certificate: QuorumCertificate,
    },
}

/// A message queued for delivery.
#[derive(Clone, Debug)]
struct Pending {
    deliver_at: u64,
    seq: u64,
    to: usize,
    wire: Wire,
}

// ===========================================================================
// The cluster
// ===========================================================================

/// One validator inside the cluster.
struct Member {
    index: usize,
    id: ValidatorId,
    key: SigningKey,
    rt: ValidatorRuntime,
    profile: NodeProfile,
    /// Virtual ms at which this node joined the network.
    active_from_ms: u64,
    /// Virtual ms at which the current round started (the round timer).
    round_started_ms: u64,
    /// The (height, round) this node last cast a prevote in.
    last_prevoted: Option<(Height, Round)>,
    /// The (height, round) this node last cast a precommit in.
    last_precommitted: Option<(Height, Round)>,
    /// The (height, round) this node already proposed in.
    proposed: Option<(Height, Round)>,
    /// The last prevote / precommit cast in the current round (re-broadcast
    /// on a view change, exactly like the production loop).
    last_prevote: Option<Vote>,
    last_precommit: Option<Vote>,
    /// The equivocation the Byzantine node injected (height, round).
    byzantine_round: Option<(Height, Round)>,
    /// The round each finalized height was decided in.
    decide_rounds: Vec<Round>,
    /// The round the node's CURRENT height started in (the offset the
    /// decide rounds are measured against).
    height_start_round: Round,
    /// SIM-ONLY straggler bookkeeping: the newest (height, round, virtual ms)
    /// at which each peer was observed voting. Updated for every vote on the
    /// wire (accepted or not — like production `observe_peer_vote`, the round
    /// counter is true information even when the vote itself is not votable).
    /// Read ONLY by the SIM-ONLY straggler grace; production code never sees
    /// it. Recording is passive (no RNG, no wire change), so control runs
    /// with the policy disabled behave exactly as before.
    sim_sightings: HashMap<ValidatorId, (Height, Round, u64)>,
    /// SIM-ONLY: per-(height, round) vote arrival counts, accepted or not.
    /// Passive (no RNG, no wire change). Lets the report separate arrival
    /// LATENESS (a vote landing after its round moved on — which the
    /// late-quorum path can still absorb and count) from true WASTE (votes in
    /// buckets that never decide anything).
    arrivals_by_bucket: HashMap<(Height, Round), u64>,
    /// SIM-ONLY: the ABSOLUTE (height, cert round) of every height this node
    /// decided itself. (The public `decide_rounds` are deltas against the
    /// height's start round; waste accounting needs the absolute bucket.)
    decide_abs: Vec<(Height, Round)>,
    stats: MemberStats,
}

/// Per-node counters.
#[derive(Clone, Debug, Default)]
struct MemberStats {
    prevotes_cast: u64,
    precommits_cast: u64,
    prevotes_received: u64,
    precommits_received: u64,
    proposals_received: u64,
    proposals_refused: u64,
    proposals_sent: u64,
    sync_jumps: u32,
    /// The newest round in which this node held a PREVOTE quorum, and the
    /// voting power behind it (persisted across the height reset, so the
    /// diagnostic survives a finalize).
    ///
    /// The round and the power are kept TOGETHER so a report can never show
    /// the round of one observation next to the power of another.
    last_prevote_qc: Option<(Round, u64)>,
    /// The newest round in which this node held a PRECOMMIT quorum, and the
    /// voting power behind it.
    last_precommit_qc: Option<(Round, u64)>,
    /// The round in which this node last CAST a precommit (the polka's
    /// round). Persisted, because the live `last_precommitted` marker is
    /// cleared on every view change and a report taken between two rounds
    /// would otherwise show nothing.
    last_precommit_cast: Option<Round>,
    /// SIM-ONLY: vote arrivals observed in the drain (accepted or not).
    vote_arrivals: u64,
    /// SIM-ONLY: arrivals naming our height but an older round (stale).
    vote_arrivals_stale: u64,
    /// SIM-ONLY: ticks the straggler grace held the round open past base.
    grace_extends: u64,
    /// SIM-ONLY: view changes taken (round timeouts fired). The "rounds
    /// used" half of the liveness metric.
    view_changes: u64,
}

/// A deterministic multi-node consensus cluster.
pub struct ConsensusCluster {
    members: Vec<Member>,
    validators: ValidatorSet,
    wire: Vec<Pending>,
    now_ms: u64,
    tick_ms: u64,
    round_timeout_ms: u64,
    rng: Rng,
    seq: u64,
    /// The cluster's shared starting round (every node that is NOT late
    /// starts here).
    base_round: Round,
    /// Every vote every node CAST, for the double-vote invariant.
    cast_votes: Vec<Vec<CastVote>>,
    /// The equivocation pairs the cluster observed.
    equivocations: Vec<(ValidatorId, Vote, Vote)>,
    /// The transaction template the cluster seeds every mempool with.
    dev_key: SigningKey,
    dev_address: [u8; 32],
    recipient: [u8; 32],
    genesis_balance: u64,
    /// VEL-1 model switch: proposal-fast-forward (prebuild hit) hides the
    /// proposer's build delay on same-tick post-finalize broadcasts.
    /// Default true (AFTER); set false for the production-faithful BEFORE
    /// (empty-only production path), where every broadcast pays full delay.
    /// `SPD_FAST_FORWARD=0` in the environment also disables it.
    fast_forward: bool,
    /// VEL-2 vote-fan-in pipeline: vote in the same tick that accepts the
    /// proposal instead of waiting for the next tick's prevote step.
    /// Default true (AFTER); set false for the BEFORE comparison.
    vote_pipeline: bool,
    /// SIM-ONLY straggler-aware round extension (default: disabled = exact
    /// old harness behaviour). Scenarios opt in via
    /// [`Self::with_straggler_policy`].
    straggler: StragglerPolicy,
}

impl ConsensusCluster {
    /// Build a cluster of `n_validators` validators with EQUAL power.
    ///
    /// `skew` is the per-node round-timeout MULTIPLIER: `skew[i] == 1` is the
    /// base round timeout, `skew[i] == 5` is five times slower. A shorter
    /// `skew` slice means "the remaining nodes have no skew".
    ///
    /// For UNEQUAL voting power (e.g. `1500/1000/1000`) use
    /// [`Self::with_powers`] or [`Self::with_profiles`].
    pub fn new(n_validators: usize, skew: &[u64]) -> Self {
        let profiles = (0..n_validators)
            .map(|i| NodeProfile {
                round_timeout_factor: skew.get(i).copied().unwrap_or(1).max(1),
                ..Default::default()
            })
            .collect();
        Self::with_profiles(n_validators, profiles)
    }

    /// Build a cluster from explicit per-node profiles.
    pub fn with_profiles(n_validators: usize, profiles: Vec<NodeProfile>) -> Self {
        let seed = 0x5741_5220_4C49_5645u64; // "WART_LIVE"
        Self::build(n_validators, profiles, seed, 100, 1000)
    }

    /// Build a cluster whose validators hold UNEQUAL voting power.
    ///
    /// `powers[i]` is the voting power of node `i` (e.g. `[1500, 1000,
    /// 1000]`). The quorum the cluster then demands is the set's own
    /// two-thirds rule (`ValidatorSet::quorum_power`), so a scenario can say
    /// "the down node holds 40% of the power, so the chain cannot finalize"
    /// and have the arithmetic be the REAL one.
    pub fn with_powers(powers: &[u64]) -> Self {
        let profiles = powers
            .iter()
            .map(|p| NodeProfile::default().with_power(*p))
            .collect();
        Self::with_profiles(powers.len(), profiles)
    }

    /// The full constructor: everything is explicit.
    pub fn build(
        n_validators: usize,
        profiles: Vec<NodeProfile>,
        seed: u64,
        tick_ms: u64,
        round_timeout_ms: u64,
    ) -> Self {
        assert!(n_validators > 0, "a cluster needs at least one validator");
        assert_eq!(
            n_validators,
            profiles.len(),
            "one profile per validator is required"
        );
        let mut members: Vec<Member> = Vec::with_capacity(n_validators);

        // The cluster's shared starting round: every node that is NOT late
        // starts here. A late node starts `late_rounds` behind it.
        let base_round = profiles.iter().map(|p| p.late_rounds).max().unwrap_or(0);

        // The FULL validator set FIRST: every node must see the SAME set (a
        // node whose set held only itself would reach quorum alone and
        // finalize the chain unilaterally).
        let mut validators = ValidatorSet::new();
        for (i, profile) in profiles.iter().enumerate() {
            let id = key_at(seed, i as u64).verifying_key().to_bytes();
            validators.add(id, profile.power.max(1));
        }

        // Deterministic keys: seed || index. No OS randomness.
        for (i, profile) in profiles.iter().enumerate() {
            let key = key_at(seed, i as u64);
            let id = key.verifying_key().to_bytes();
            let profile = profile.clone();

            // Every node gets its OWN state engine (nodes do not share
            // mutable state in reality).
            let state = Arc::new(InMemoryStateEngine::new());
            let mut rt = ValidatorRuntime::new(key.clone(), validators.clone(), state, 1);
            // The base round of the cluster. A late node starts behind it.
            let mut hc = HeightConsensus::new(1, validators.clone());
            hc.round = base_round.saturating_sub(profile.late_rounds);
            rt.hc = hc;
            members.push(Member {
                index: i,
                id,
                key,
                rt,
                profile,
                active_from_ms: 0,
                round_started_ms: 0,
                last_prevoted: None,
                last_precommitted: None,
                proposed: None,
                last_prevote: None,
                last_precommit: None,
                byzantine_round: None,
                decide_rounds: Vec::new(),
                height_start_round: base_round,
                sim_sightings: HashMap::new(),
                arrivals_by_bucket: HashMap::new(),
                decide_abs: Vec::new(),
                stats: MemberStats::default(),
            });
        }

        // The dev account that funds the chain and pays the fees.
        let dev_key = key_at(seed, 0xDEAD_BEEF);
        let dev_address = dev_key.verifying_key().to_bytes();
        let recipient = [0x11u8; 32];
        let genesis_balance = 1_000_000_000_000_000_000u64;

        ConsensusCluster {
            members,
            validators,
            wire: Vec::new(),
            now_ms: 0,
            tick_ms,
            round_timeout_ms,
            rng: Rng::new(seed),
            seq: 0,
            base_round,
            cast_votes: (0..n_validators).map(|_| Vec::new()).collect(),
            equivocations: Vec::new(),
            dev_key,
            dev_address,
            recipient,
            genesis_balance,
            fast_forward: true,
            vote_pipeline: true,
            straggler: StragglerPolicy::default(),
        }
    }

    /// VEL-1 model switch (see field docs). Builder-style; default true.
    pub fn with_fast_forward(mut self, on: bool) -> Self {
        self.fast_forward = on;
        self
    }

    /// VEL-2 vote-fan-in pipeline switch (see field docs). Default true.
    pub fn with_vote_pipeline(mut self, on: bool) -> Self {
        self.vote_pipeline = on;
        self
    }

    /// SIM-ONLY straggler-aware round extension (see [`StragglerPolicy`]).
    /// Default is disabled (exact old harness behaviour).
    pub fn with_straggler_policy(mut self, policy: StragglerPolicy) -> Self {
        self.straggler = policy;
        self
    }

    /// SIM-ONLY: extra round time for node `i` this tick under the straggler
    /// policy (0 when disabled or when no fresh straggler evidence exists).
    /// At most one grace per round (the clauses do not stack); always bounded
    /// by the policy cap.
    fn straggler_grace_ms(&self, i: usize) -> u64 {
        let p = self.straggler;
        if !p.enabled || p.grace_ms == 0 {
            return 0;
        }
        let me = &self.members[i];
        let (my_h, my_r) = (me.rt.hc.height, me.rt.hc.round);
        let now = self.now_ms;
        let fresh = |seen_ms: u64| now.saturating_sub(seen_ms) <= p.freshness_ms;
        // Clause (1) BEHIND-VOTE: a live peer's newest observed vote names an
        // older (height, round) than ours — its vote for our round may still
        // be in flight.
        let behind = me
            .sim_sightings
            .iter()
            .any(|(id, (h, r, t))| *id != me.id && (*h, *r) < (my_h, my_r) && fresh(*t));
        if behind {
            return p.grace_ms.min(p.cap_ms);
        }
        // Clause (2) SCHEDULED-PROPOSAL: we hold no live proposal and the
        // scheduled proposer of our (height, round) is not demonstrably ahead
        // of us — its proposal may still be in flight, so wait for the
        // scheduled value instead of racing to the next round proposalless.
        // (A proposer that is ahead of us means WE are the straggler; the
        // future-round rule, not waiting, is our way back.)
        if !me.rt.hc.has_live_proposal() {
            if let Some(proposer) = self.validators.proposer_for(my_h, my_r) {
                if proposer != me.id {
                    let waiting = match me.sim_sightings.get(&proposer) {
                        // Never heard from the proposer: optimistic wait
                        // (bounded by the cap; startup only in practice).
                        None => true,
                        Some((h, r, t)) => (*h, *r) <= (my_h, my_r) && fresh(*t),
                    };
                    if waiting {
                        return p.grace_ms.min(p.cap_ms);
                    }
                }
            }
        }
        0
    }

    /// Whether the SPD fast-forward applies this tick: the field AND the
    /// legacy `SPD_FAST_FORWARD` environment override (0 disables).
    fn fast_forward_on(&self) -> bool {
        self.fast_forward && std::env::var("SPD_FAST_FORWARD").as_deref() != Ok("0")
    }

    /// The cluster's validator set.
    pub fn validators(&self) -> &ValidatorSet {
        &self.validators
    }

    /// The number of validators.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// True when the cluster has no validators.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The virtual clock, in milliseconds.
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Access a member's runtime (read-only).
    pub fn runtime(&self, index: usize) -> &ValidatorRuntime {
        &self.members[index].rt
    }

    /// The cluster's base (non-late) starting round.
    pub fn base_round(&self) -> Round {
        self.base_round
    }

    /// Take a member DOWN (or bring it back) MID-SCENARIO.
    ///
    /// The `down` profile flag is static (dead from genesis); this flips it
    /// while the virtual clock runs, modelling a kill at time T: the node
    /// stops proposing and voting, and no NEW messages are addressed to it.
    /// A re-activated node restarts its round timer from now, so it does not
    /// spend a stale timeout the instant it returns. Restart past the flag
    /// flip is best-effort (the scenario suite only pins the kill path).
    pub fn set_down(&mut self, index: usize, down: bool) {
        self.members[index].profile.down = down;
        if !down {
            self.members[index].round_started_ms = self.now_ms;
        }
    }

    /// Seed every node's mempool with the same transaction, so the blocks
    /// carry real content and the state root EVOLVES height by height (a
    /// state-root comparison over an always-empty state proves nothing).
    pub async fn seed_transactions(&mut self, count: u64) {
        for m in self.members.iter_mut() {
            // The dev account is funded identically on every node, so every
            // node starts from the same state root.
            m.rt.state
                .update_account(AccountState::new(self.dev_address, self.genesis_balance))
                .await;
            m.rt.state
                .update_account(AccountState::new(self.recipient, self.genesis_balance))
                .await;
            for nonce in 0..count {
                let tx = Transaction::sign(
                    &self.dev_key,
                    self.recipient,
                    1_000,
                    21_000,
                    nonce,
                    MASTERCHAIN_SHARD,
                    MASTERCHAIN_SHARD,
                );
                m.rt.add_tx(tx).await;
            }
        }
    }

    /// Seed every node's mempool with `txs_per_sender` transactions from EACH
    /// of `n_senders` distinct funded senders (R-tempo block-tempo proof).
    ///
    /// One sender's nonces are contiguous from 0, so every height packs about
    /// one transaction per sender until a sender's queue drains: `n_senders`
    /// txs/height of real content, and the state root evolves every height.
    /// Deterministic: sender keys derive from the cluster seed, funding is
    /// identical on every node.
    pub async fn seed_transactions_multi(&mut self, n_senders: u64, txs_per_sender: u64) {
        for m in self.members.iter_mut() {
            m.rt.state
                .update_account(AccountState::new(self.recipient, self.genesis_balance))
                .await;
            for s in 0..n_senders {
                let sk = key_at(0xBEEF_0000, s);
                let from = sk.verifying_key().to_bytes();
                m.rt.state
                    .update_account(AccountState::new(from, self.genesis_balance))
                    .await;
                for nonce in 0..txs_per_sender {
                    let tx = Transaction::sign(
                        &sk,
                        self.recipient,
                        1_000,
                        21_000,
                        nonce,
                        MASTERCHAIN_SHARD,
                        MASTERCHAIN_SHARD,
                    );
                    m.rt.add_tx(tx).await;
                }
            }
        }
    }

    /// Give ONE node a state the others do not have.
    ///
    /// This exists so a scenario can prove the state-root check is NOT
    /// vacuous: a harness that compared the roots of a cluster whose roots
    /// could never differ would pass forever and mean nothing. Perturbing
    /// one node's state makes the roots differ, and the check must notice.
    pub async fn perturb_state_of(&self, index: usize) {
        let state = self.members[index].rt.state.clone();
        // A junk account no other node has.
        let junk = [0xA5u8; 32];
        state
            .update_account(AccountState::new(junk, 7_919_191_919_191))
            .await;
    }

    /// Run the cluster until `target_height` has been finalized by EVERY up
    /// member, or until the virtual budget runs out.
    ///
    /// Returns the report; the caller asserts on it.
    pub async fn run_until(&mut self, target_height: Height, max_virtual_ms: u64) -> ClusterReport {
        while self.now_ms < max_virtual_ms {
            if self
                .members
                .iter()
                .filter(|m| !m.profile.down)
                .all(|m| m.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0) >= target_height)
            {
                break;
            }
            self.tick().await;
        }
        self.report().await
    }

    /// Run the cluster for a fixed amount of VIRTUAL time.
    pub async fn run_for(&mut self, virtual_ms: u64) -> ClusterReport {
        let target = self.now_ms + virtual_ms;
        while self.now_ms < target {
            self.tick().await;
        }
        self.report().await
    }

    /// One cluster tick: every member runs the production node loop, in
    /// index order.
    pub async fn tick(&mut self) {
        self.now_ms += self.tick_ms;
        let stamp = self.now_ms;

        for i in 0..self.members.len() {
            // 1. PROPOSE (normal path: full propose_delay build cost)
            self.step_propose(i, stamp).await;
            // 2. PREVOTE
            self.step_prevote(i, stamp).await;
            // 3. DRAIN the inbox
            self.step_drain(i).await;
            // The diagnostic: remember the newest round in which this node
            // held a prevote / precommit quorum. This runs BEFORE the
            // finalize, because the finalize RESETS the height consensus -
            // reading it afterwards would lose exactly the fact the
            // diagnostic exists to report ("the QC formed at round R, the
            // precommit was expected at round R").
            let (pv, pc) = qc_rounds(&self.members[i].rt);
            if let Some(seen) = pv {
                let slot = self.members[i].stats.last_prevote_qc.get_or_insert(seen);
                if seen.0 > slot.0 {
                    *slot = seen;
                }
            }
            if let Some(seen) = pc {
                let slot = self.members[i].stats.last_precommit_qc.get_or_insert(seen);
                if seen.0 > slot.0 {
                    *slot = seen;
                }
            }
            // 4. PRECOMMIT
            self.step_precommit(i).await;
            // 5. FINALIZE
            // SPD proposal-fast-forward (harness mirror of the production fix):
            // if this finalize advanced the height, propose for the new height
            // IN THE SAME TICK instead of waiting for the next tick's propose
            // gate. Saves one tick (tick_ms virtual ms) per height. SAFE: same
            // propose gate (is_proposer, Propose step, propose-delay model),
            // same parent (finalized head), same wire bytes, idempotent via
            // `proposed` (once per (height, round)). Prevote stays next-tick
            // (proposal needs a tick + delay to arrive), so no nil-vote burn.
            let h_before = self.members[i].rt.hc.height;
            self.step_finalize(i).await;
            if self.members[i].rt.hc.height != h_before && self.fast_forward_on() {
                // SPD proposal-fast-forward: the next proposer pre-built its
                // block while the previous height was voting (proposer
                // lookahead is inherent), so the build cost is hidden and the
                // proposal broadcasts immediately. Model by zeroing the
                // propose_delay for this one broadcast (same-tick + prebuilt).
                let saved = self.members[i].profile.propose_delay_ms;
                self.members[i].profile.propose_delay_ms = 0;
                self.step_propose(i, stamp).await;
                self.members[i].profile.propose_delay_ms = saved;
            }
            // 6. VIEW CHANGE
            self.step_round_timeout(i, stamp);
        }
    }

    /// Is this member participating at all?
    fn is_active(&self, i: usize) -> bool {
        let m = &self.members[i];
        !m.profile.down && self.now_ms >= m.active_from_ms
    }

    /// The member's effective round timeout, in virtual ms.
    fn timeout_of(&self, i: usize) -> u64 {
        let factor = self.members[i].profile.round_timeout_factor.max(1);
        self.round_timeout_ms.saturating_mul(factor)
    }

    /// The timestamp a block built at this instant carries (virtual seconds).
    fn timestamp(&self) -> u64 {
        self.now_ms / 1000
    }

    // ------------------------------------------------------------------
    // Step 1: propose
    // ------------------------------------------------------------------

    async fn step_propose(&mut self, i: usize, stamp: u64) {
        if !self.is_active(i) {
            return;
        }
        let (h, r) = {
            let m = &self.members[i];
            (m.rt.hc.height, m.rt.hc.round)
        };
        if self.members[i].proposed == Some((h, r)) {
            return;
        }
        let ts = self.timestamp();
        let block = self.members[i].rt.propose(ts).await;
        let Some(block) = block else { return };
        let proposer = self.members[i].id;
        let round = self.members[i].rt.hc.round;
        self.members[i].proposed = Some((h, round));
        self.members[i].stats.proposals_sent += 1;
        // An equivocating proposer signs a SECOND body for the same slot
        // (timestamp +1s, re-signed: genuine, but a different hash). It is
        // built BEFORE the honest broadcast but put on the wire AFTER it, so
        // every honest node accepts the first body and refuses the second —
        // the production one-value rule, exercised end to end. (This point is
        // only reachable when THIS call proposed: the `proposed` guard above
        // returns early on the same-tick fast-forward re-entry, so there is
        // exactly one equivocation per (height, round).)
        let equivocation = if self.members[i].profile.byzantine == Byzantine::DoubleProposal {
            let mut evil = block.clone();
            evil.timestamp = evil.timestamp.saturating_add(1);
            evil.validator_signatures.clear();
            evil.sign_block(&self.members[i].key);
            Some(evil)
        } else {
            None
        };
        self.broadcast(
            i,
            Wire::Proposal {
                proposer,
                block,
                round,
            },
            stamp,
        );
        if let Some(evil) = equivocation {
            self.members[i].stats.proposals_sent += 1;
            self.broadcast(
                i,
                Wire::Proposal {
                    proposer,
                    block: evil,
                    round,
                },
                stamp,
            );
        }
    }

    // ------------------------------------------------------------------
    // Step 2: prevote
    // ------------------------------------------------------------------

    async fn step_prevote(&mut self, i: usize, stamp: u64) {
        if !self.is_active(i) {
            return;
        }
        let (h, r) = {
            let m = &self.members[i];
            (m.rt.hc.height, m.rt.hc.round)
        };
        if self.members[i].last_prevoted == Some((h, r)) {
            return;
        }
        // THE LIVE NIL SHAPE (see `Byzantine::NilPrevote`): this member
        // prevotes nil at every round, immediately — the vote a validator
        // locked on a value nobody proposes casts via the production path
        // (2) the moment it holds no live proposal for its lock. One vote
        // per (height, round): never an equivocation, always nil.
        if self.members[i].profile.byzantine == Byzantine::NilPrevote {
            let vote = Vote::sign(&self.members[i].key, h, r, VoteKind::Prevote, None);
            let locked = lock_hint(&self.members[i].rt, &vote);
            let _ = self.members[i].rt.on_prevote(vote.clone());
            self.members[i].stats.prevotes_cast += 1;
            self.members[i].last_prevoted = Some((h, r));
            self.members[i].last_prevote = Some(vote.clone());
            self.record_cast(i, &vote);
            self.broadcast(i, Wire::Vote { vote, locked }, stamp);
            return;
        }
        // The production loop votes once per round: a value vote when a live
        // proposal is held, and a NIL vote after twice the round timeout when
        // no proposal ever arrived (the nil vote is what keeps a behind node
        // visible to its peers).
        let live = self.members[i].rt.hc.has_live_proposal();
        if !live {
            let waited = self.now_ms.saturating_sub(self.members[i].round_started_ms);
            // SIM-ONLY: under the straggler policy the nil wait stretches with
            // the same grace as the view change (don't nil a round whose
            // scheduled value may still be in flight — the vote equivalent of
            // the scheduled-proposal clause). Value votes are unaffected (they
            // fire immediately on a live proposal).
            let mut nil_wait = self.timeout_of(i).saturating_mul(2);
            if self.straggler.enabled {
                nil_wait = nil_wait.saturating_add(self.straggler_grace_ms(i));
            }
            if waited < nil_wait {
                return;
            }
        }
        let Some(vote) = self.members[i].rt.make_prevote() else {
            return;
        };
        let locked = lock_hint(&self.members[i].rt, &vote);
        let _ = self.members[i].rt.on_prevote(vote.clone());
        self.members[i].stats.prevotes_cast += 1;
        self.members[i].last_prevoted = Some((h, r));
        self.members[i].last_prevote = Some(vote.clone());
        self.record_cast(i, &vote);

        // The honest vote goes out FIRST: the vote set keeps the FIRST vote
        // it sees, so a conflicting vote that arrives afterwards is recorded
        // as the equivocation and never displaces the honest value.
        self.broadcast(
            i,
            Wire::Vote {
                vote: vote.clone(),
                locked,
            },
            stamp,
        );

        // A Byzantine member double-votes: the SAME (height, round, kind)
        // with a DIFFERENT target. The vote set keeps the first vote, so the
        // honest quorum still forms, and the pair is recorded as evidence.
        if self.members[i].profile.byzantine == Byzantine::DoublePrevote
            && self.members[i].byzantine_round.is_none()
        {
            let fake = fake_target(h, r, &vote);
            let evil = Vote::sign(&self.members[i].key, h, r, VoteKind::Prevote, Some(fake));
            self.members[i].byzantine_round = Some((h, r));
            self.record_cast(i, &evil);
            self.broadcast(
                i,
                Wire::Vote {
                    vote: evil,
                    locked: None,
                },
                stamp,
            );
        }
    }

    // ------------------------------------------------------------------
    // Step 3: drain
    // ------------------------------------------------------------------

    async fn step_drain(&mut self, i: usize) {
        // Take the messages addressed to this node that are due.
        let now = self.now_ms;
        let height_before = self.members[i].rt.hc.height;
        let mut due: Vec<Pending> = Vec::new();
        let mut keep: Vec<Pending> = Vec::new();
        for p in self.wire.drain(..) {
            if p.to == i && p.deliver_at <= now {
                due.push(p);
            } else {
                keep.push(p);
            }
        }
        self.wire = keep;
        // Deterministic delivery order.
        due.sort_by_key(|p| (p.deliver_at, p.seq));

        for p in due {
            match p.wire {
                Wire::Proposal {
                    proposer,
                    block,
                    round,
                } => {
                    self.members[i].stats.proposals_received += 1;
                    let before = self.members[i].rt.hc.round;
                    let res = self.members[i].rt.on_proposal(proposer, block, round).await;
                    if let Err(e) = &res {
                        self.members[i].stats.proposals_refused += 1;
                        if std::env::var("CLUSTER_DEBUG").as_deref() == Ok("1") {
                            eprintln!(
                                "[dbg] node{i} refused proposal h={} r={round}: {e}",
                                self.members[i].rt.hc.height
                            );
                        }
                    }
                    // The proposal path can phase-align the node (a bounded
                    // round jump). The production loop restarts the round
                    // timer when the round moves under it.
                    if self.members[i].rt.hc.round != before {
                        self.members[i].stats.sync_jumps += 1;
                        self.members[i].round_started_ms = self.now_ms;
                    }
                    // VEL-2 vote-fan-in pipeline: vote in the SAME tick that
                    // accepted the proposal instead of waiting for the next
                    // tick's prevote step. Timing-only: the vote content is
                    // identical to what the next-tick step would cast (same
                    // round — no timeout fires mid-tick — same live proposal,
                    // same lock, same `make_prevote`), the dedup key is the
                    // same `(height, round)`, and QCs stay strictly
                    // per-round, so quorum intersection is untouched: earlier
                    // arrival can only form the same QC sooner, never a
                    // different one. Refused proposals never reach here.
                    if self.vote_pipeline && res.is_ok() {
                        let (h2, r2) = {
                            let m = &self.members[i];
                            (m.rt.hc.height, m.rt.hc.round)
                        };
                        if self.is_active(i)
                            && self.members[i].profile.byzantine != Byzantine::NilPrevote
                            && self.members[i].last_prevoted != Some((h2, r2))
                            && self.members[i].rt.hc.has_live_proposal()
                        {
                            if let Some(vote) = self.members[i].rt.make_prevote() {
                                let locked = lock_hint(&self.members[i].rt, &vote);
                                let _ = self.members[i].rt.on_prevote(vote.clone());
                                self.members[i].stats.prevotes_cast += 1;
                                self.members[i].last_prevoted = Some((h2, r2));
                                self.members[i].last_prevote = Some(vote.clone());
                                self.record_cast(i, &vote);
                                let stamp = self.now_ms;
                                self.broadcast(i, Wire::Vote { vote, locked }, stamp);
                            }
                        }
                    }
                }
                Wire::Vote { vote, locked } => {
                    let kind = vote.kind;
                    let height = vote.height;
                    let round_before = self.members[i].rt.hc.round;
                    let accepted = {
                        let rt = &mut self.members[i].rt;
                        rt.note_lock_hint(height, kind, vote.block_hash, locked);
                        match kind {
                            VoteKind::Prevote => {
                                let ok = rt.on_prevote(vote.clone()).is_ok();
                                if ok {
                                    self.members[i].stats.prevotes_received += 1;
                                }
                                ok
                            }
                            VoteKind::Precommit => {
                                let ok = rt.on_precommit(vote.clone()).is_ok();
                                if ok {
                                    self.members[i].stats.precommits_received += 1;
                                }
                                ok
                            }
                        }
                    };
                    // Phase alignment, exactly like the production drain: a
                    // verified peer vote pulls us into its round. The production
                    // path does this INSIDE `on_prevote`/`on_precommit`
                    // (`note_peer_vote_round`), so the harness observes the
                    // round move instead of driving it a second time - driving
                    // it twice would spend the consensus code's per-round jump
                    // budget twice for one vote.
                    if accepted
                        && height == self.members[i].rt.hc.height
                        && self.members[i].rt.hc.round != round_before
                    {
                        self.members[i].stats.sync_jumps += 1;
                        // The production loop restarts the round timer when
                        // the round moves under it.
                        self.members[i].round_started_ms = self.now_ms;
                    }
                    // SIM-ONLY straggler bookkeeping + stale-arrival counters.
                    // Passive: no RNG, no wire change, so control runs are
                    // unaffected. Staleness is judged at ARRIVAL time against
                    // the round we were in before this vote moved us.
                    {
                        let m = &mut self.members[i];
                        m.stats.vote_arrivals += 1;
                        *m.arrivals_by_bucket
                            .entry((height, vote.round))
                            .or_insert(0) += 1;
                        if height == m.rt.hc.height && vote.round < round_before {
                            m.stats.vote_arrivals_stale += 1;
                        }
                        // Newest sighting per peer (monotonic per voter — a
                        // delayed old vote never rewinds it, mirroring
                        // production `note_peer_round`).
                        let entry = m.sim_sightings.entry(vote.voter).or_insert((
                            height,
                            vote.round,
                            self.now_ms,
                        ));
                        if (height, vote.round) > (entry.0, entry.1) {
                            *entry = (height, vote.round, self.now_ms);
                        } else if (height, vote.round) == (entry.0, entry.1) {
                            entry.2 = self.now_ms;
                        }
                    }
                }
                Wire::Committed {
                    height,
                    block,
                    certificate,
                } => {
                    // A peer already committed this height: adopt it (the
                    // certificate is verified against OUR validator set).
                    let rt = &mut self.members[i].rt;
                    let _ = rt.adopt_committed(height, block, certificate).await;
                }
            }
        }
        // An adopt in the drain above can advance the height without a view
        // change: restart the round timer exactly like the production loop
        // does ("New height, new round timer"), or the stale timer fires a
        // view change within milliseconds and drops the next votes.
        if self.members[i].rt.hc.height != height_before {
            self.members[i].round_started_ms = self.now_ms;
        }

        // Collect the equivocation evidence the node observed. The consensus
        // layer keeps it per height; it is read BEFORE the height is reset by
        // a finalize.
        let seen = self.members[i].rt.hc.equivocations();
        for ev in seen {
            let known = self.equivocations.iter().any(|(v, a, b)| {
                *v == ev.0 && a.block_hash == ev.1.block_hash && b.block_hash == ev.2.block_hash
            });
            if !known {
                self.equivocations.push(ev);
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 4: precommit
    // ------------------------------------------------------------------

    async fn step_precommit(&mut self, i: usize) {
        if !self.is_active(i) {
            return;
        }
        let h = self.members[i].rt.hc.height;
        let Some(vote) = self.members[i].rt.make_precommit() else {
            return;
        };
        // The precommit is stamped with the POLKA's round, which may differ
        // from the node's local round. The dedup key is (height, vote.round).
        if self.members[i].last_precommitted == Some((h, vote.round)) {
            return;
        }
        let _ = self.members[i].rt.on_precommit(vote.clone());
        self.members[i].stats.precommits_cast += 1;
        self.members[i].last_precommitted = Some((h, vote.round));
        self.members[i].last_precommit = Some(vote.clone());
        // The persisted copy: the live marker is cleared on the next view
        // change, so a report taken between rounds would lose it.
        self.members[i].stats.last_precommit_cast = Some(vote.round);
        self.record_cast(i, &vote);
        let stamp = self.now_ms;
        self.broadcast(i, Wire::Vote { vote, locked: None }, stamp);
    }

    // ------------------------------------------------------------------
    // Step 5: finalize
    // ------------------------------------------------------------------

    async fn step_finalize(&mut self, i: usize) {
        if !self.is_active(i) {
            return;
        }
        let height = self.members[i].rt.hc.height;
        let Some(finalized_hash) = self.members[i].rt.try_finalize().await else {
            return;
        };
        // `try_finalize` RESETS the height consensus, so the decision proof
        // has already been stashed in `last_decision` (that is exactly what
        // the production commit broadcast reads).
        let Some((h, block, cert)) = self.members[i].rt.last_decision.clone() else {
            return;
        };
        debug_assert_eq!(h, height);
        // The hash the runtime finalized and the hash of the block the
        // decision proof carries must be the SAME block. If they ever were
        // not, the commit broadcast would carry a different block than the
        // one the node finalized - a fork the node cannot see.
        assert_eq!(
            finalized_hash,
            block.compute_hash(),
            "node {} finalized a hash that does not match the decided block \
             at height {}",
            i,
            h
        );
        // The round the decision was taken in (the precommit quorum's round):
        // the liveness metric of "how many rounds did this height cost".
        // Measured as a DELTA from the round the height started in, so a
        // cluster that starts at round 30 does not look like it burned 30
        // rounds on its first height.
        let start = self.members[i].height_start_round;
        self.members[i]
            .decide_rounds
            .push(cert.round.saturating_sub(start));
        // SIM-ONLY: the absolute deciding bucket, for waste accounting
        // (which arrival buckets ever belonged to a decision).
        self.members[i].decide_abs.push((h, cert.round));
        // The commit broadcast: a peer that missed the deciding vote learns
        // the outcome and adopts the block (this is the catch-up path the
        // production loop uses).
        let stamp = self.now_ms;
        self.broadcast(
            i,
            Wire::Committed {
                height: h,
                block,
                certificate: cert,
            },
            stamp,
        );
        // The next height starts at round 0.
        self.members[i].height_start_round = 0;
        // New height, new round timer (mirrors the production loop: "New
        // height, new round timer" — a stale timer inherited from the previous
        // height would fire a view change within milliseconds of the advance
        // and drop the next height's first votes; measured live as a view
        // change 269ms after an adopt, and in this harness as a spurious
        // round every timeout/height_ms heights on fast profiles).
        self.members[i].round_started_ms = stamp;
    }

    // ------------------------------------------------------------------
    // Step 6: view change
    // ------------------------------------------------------------------

    fn step_round_timeout(&mut self, i: usize, stamp: u64) {
        if !self.is_active(i) {
            return;
        }
        // SPD production-parity: round-0 proposal wait is capped (production
        // STELL_ROUND_ZERO_TIMEOUT_MS default 650ms). Without this the harness
        // is optimistic (3500ms flat) and never shows the live r0-timeout waste.
        // Effective timeout = min(base*factor, 650) while r0 holds no live proposal.
        let mut eff = self.timeout_of(i);
        {
            let hc = &self.members[i].rt.hc;
            if hc.round == 0 && !hc.has_live_proposal() {
                eff = eff.min(650);
            }
        }
        // SIM-ONLY straggler grace (no-op unless the scenario opted in):
        // hold the round open while fresh evidence says a straggler's vote
        // or the scheduled proposal may still be in flight. Counted only
        // when the grace actually saves the round (the base timeout had
        // already expired), so `grace_extends` pins "the mechanism engaged",
        // not "the condition was true".
        let base_eff = eff;
        let grace = self.straggler_grace_ms(i);
        if grace > 0 {
            // SIM-ONLY accounting fix (`subsume_grace`): fill the slack up
            // to the pre-existing 2× bound instead of stacking past the
            // deadline — mirrors production `cap_hold_to_two_x_bound`
            // (slack = 2 * cluster base − deterministic deadline here;
            // `eff` already holds the base/factor/round-0-cap composition).
            // Default-off: `false` keeps the production-today stacking.
            let grace = if self.straggler.subsume_grace {
                grace.min((self.round_timeout_ms.saturating_mul(2)).saturating_sub(base_eff))
            } else {
                grace
            };
            eff = eff.saturating_add(grace);
            if stamp.saturating_sub(self.members[i].round_started_ms) >= base_eff {
                self.members[i].stats.grace_extends += 1;
            }
        }
        if stamp.saturating_sub(self.members[i].round_started_ms) < eff {
            return;
        }
        // Re-broadcast this round's votes before leaving it (the production
        // loop does exactly this: a single lost datagram must not cost a peer
        // its quorum for the whole round).
        let resend: Vec<Vote> = [
            self.members[i].last_prevote.clone(),
            self.members[i].last_precommit.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();
        for v in resend {
            let locked = lock_hint(&self.members[i].rt, &v);
            self.broadcast(i, Wire::Vote { vote: v, locked }, stamp);
        }
        // Re-send OUR proposal for this round too (the production loop does
        // the same): a peer that was one round behind misses the first copy
        // and would otherwise never vote this round.
        let own_proposal = {
            let m = &self.members[i];
            match m.rt.hc.proposal {
                Some((p, hash)) if p == m.id => m.rt.blocks.get(&hash).cloned(),
                _ => None,
            }
        };
        if let Some(block) = own_proposal {
            let proposer = self.members[i].id;
            let round = self.members[i].rt.hc.round;
            self.broadcast(
                i,
                Wire::Proposal {
                    proposer,
                    block,
                    round,
                },
                stamp,
            );
        }
        self.members[i].rt.next_round();
        self.members[i].round_started_ms = stamp;
        self.members[i].stats.view_changes += 1;
        self.members[i].last_prevoted = None;
        self.members[i].last_precommitted = None;
        self.members[i].last_prevote = None;
        self.members[i].last_precommit = None;
        self.members[i].proposed = None;
    }

    // ------------------------------------------------------------------
    // The message pump
    // ------------------------------------------------------------------

    /// Send a message from `from` to every OTHER member, honouring the
    /// per-node drop rate and delivery delay.
    fn broadcast(&mut self, from: usize, wire: Wire, stamp: u64) {
        let targets: Vec<usize> = (0..self.members.len())
            .filter(|i| *i != from && !self.members[*i].profile.down)
            .collect();
        for to in targets {
            // The drop decision is drawn ONCE, at broadcast time, in a fixed
            // order - so the whole run is reproducible.
            let drop = match &wire {
                Wire::Vote { vote, .. } => {
                    let permille = self.members[to].profile.vote_loss_permille;
                    let mut dropped = permille > 0 && self.rng.chance(permille);
                    if !dropped && vote.kind == VoteKind::Precommit {
                        let pm = self.members[to].profile.precommit_loss_permille;
                        dropped = pm > 0 && self.rng.chance(pm);
                    }
                    dropped
                }
                _ => false,
            };
            if drop {
                continue;
            }
            let mut delay = self.members[to].profile.inbound_delay_ms;
            // SPD slow-proposer model: the PROPOSER's build/schedule delay
            // postpones its proposals (votes unaffected). Harness-only.
            if matches!(&wire, Wire::Proposal { .. }) {
                delay = delay.saturating_add(self.members[from].profile.propose_delay_ms);
            }
            self.seq += 1;
            self.wire.push(Pending {
                // A message is never delivered in the tick it was sent: the
                // network has at least one tick of latency.
                deliver_at: stamp + self.tick_ms + delay,
                seq: self.seq,
                to,
                wire: wire.clone(),
            });
        }
    }

    /// Record a cast vote for the double-vote invariant.
    fn record_cast(&mut self, i: usize, vote: &Vote) {
        self.cast_votes[i].push(CastVote {
            height: vote.height,
            round: vote.round,
            kind: vote.kind,
            target: vote.block_hash,
        });
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------

    /// Snapshot the cluster's state.
    pub async fn report(&self) -> ClusterReport {
        let mut nodes = Vec::with_capacity(self.members.len());
        let mut best_height = 0u64;
        let mut common_height = u64::MAX;
        for m in &self.members {
            let finalized_height = m.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
            best_height = best_height.max(finalized_height);
            if !m.profile.down {
                common_height = common_height.min(finalized_height);
            }
            let hc = &m.rt.hc;
            // The live QC rounds (the newest round in the lookback window
            // that holds a quorum), falling back to the persisted value so
            // the fact survives the height reset a finalize performs. The
            // round AND the power always come from the SAME observation.
            let (live_pv, live_pc) = qc_rounds(&m.rt);
            let (prevote_qc_round, prevote_qc_power) = match live_pv {
                Some((r, p)) => (Some(r), Some(p)),
                None => match m.stats.last_prevote_qc {
                    Some((r, p)) => (Some(r), Some(p)),
                    None => (None, None),
                },
            };
            let (precommit_qc_round, precommit_qc_power) = match live_pc {
                Some((r, p)) => (Some(r), Some(p)),
                None => match m.stats.last_precommit_qc {
                    Some((r, p)) => (Some(r), Some(p)),
                    None => (None, None),
                },
            };
            // A precommit is EXPECTED at the polka's round: the round in
            // which the prevote quorum formed.
            let precommit_expected_round = prevote_qc_round;
            // SIM-ONLY waste accounting: an arrival bucket (h, r) is USEFUL
            // iff h finalized on this node AND (r is the cert round of h, or
            // h was adopted rather than decided here — catch-up arrivals for
            // an adopted height did their job by definition). Everything else
            // never belonged to any quorum: the stall, counted vote by vote.
            let deciding: HashMap<Height, Round> = m.decide_abs.iter().copied().collect();
            let finalized_h: HashSet<Height> = m.rt.finalized.iter().map(|(h, _)| *h).collect();
            let mut vote_wasted = 0u64;
            for ((h, r), c) in &m.arrivals_by_bucket {
                let useful = finalized_h.contains(h) && deciding.get(h).is_none_or(|cr| cr == r);
                if !useful {
                    vote_wasted += c;
                }
            }
            nodes.push(NodeReport {
                index: m.index,
                id: hex::encode(&m.id[..4]),
                height: hc.height,
                round: hc.round,
                finalized_height,
                finalized: m.rt.finalized.clone(),
                decide_rounds: m.decide_rounds.clone(),
                height_start_round: m.height_start_round,
                prevotes_cast: m.stats.prevotes_cast,
                precommits_cast: m.stats.precommits_cast,
                prevotes_received: m.stats.prevotes_received,
                precommits_received: m.stats.precommits_received,
                proposals_received: m.stats.proposals_received,
                proposals_refused: m.stats.proposals_refused,
                prevote_qc_round,
                prevote_qc_power,
                precommit_qc_power,
                quorum_power: self.validators.quorum_power(),
                precommit_expected_round,
                precommit_round: m
                    .last_precommitted
                    .map(|(_, r)| r)
                    .or(m.stats.last_precommit_cast),
                precommit_qc_round,
                locked: hc.locked.map(|(b, _)| b),
                blockers: hc.finalize_blockers(),
                state_root: m.rt.state.get_state_root().await,
                sync_jumps: m.stats.sync_jumps,
                cast_votes: self.cast_votes[m.index].clone(),
                vote_arrivals: m.stats.vote_arrivals,
                vote_arrivals_stale: m.stats.vote_arrivals_stale,
                grace_extends: m.stats.grace_extends,
                view_changes: m.stats.view_changes,
                vote_wasted,
            });
        }
        if common_height == u64::MAX {
            common_height = 0;
        }
        ClusterReport {
            virtual_ms: self.now_ms,
            ticks: self.now_ms / self.tick_ms.max(1),
            nodes,
            equivocations: self.equivocations.clone(),
            best_height,
            common_height,
        }
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// The deterministic key for `(seed, index)`.
pub fn key_at(seed: u64, index: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&index.to_le_bytes());
    bytes[16..24].copy_from_slice(&0x5354_454c_4c45_5245u64.to_le_bytes());
    SigningKey::from_bytes(&bytes)
}

/// The lock hint attached to an outgoing vote (nil prevotes only).
fn lock_hint(rt: &ValidatorRuntime, v: &Vote) -> Option<BlockHash> {
    if v.kind == VoteKind::Prevote && v.block_hash.is_none() {
        rt.hc.locked.map(|(b, _)| b)
    } else {
        None
    }
}

/// The newest round in the node's lookback window that holds a PREVOTE
/// quorum, and the newest that holds a PRECOMMIT quorum.
///
/// Each is returned with the VOTING POWER behind the quorum target, so a
/// report can literally say "3.5 of 4 STELL prevoted, quorum is 2.67 STELL,
/// and no precommit arrived" - the live failure shape, in numbers.
///
/// This is the harness's version of the consensus code's own quorum scan
/// (`HeightConsensus::rounds_to_inspect`), and it is what turns "the chain
/// is not finalizing" into "the prevote QC formed at round R, the precommit
/// was expected at round R and never arrived".
#[allow(clippy::type_complexity)]
// GATE: test helper returns optional (round, power) pairs for prevote/precommit; tuple shape keeps assertions direct.
fn qc_rounds(rt: &ValidatorRuntime) -> (Option<(Round, u64)>, Option<(Round, u64)>) {
    let hc = &rt.hc;
    let mut prevote = None;
    let mut precommit = None;
    let low = hc
        .round
        .saturating_sub(stellereum::consensus::ROUND_LOOKBACK);
    for r in (low..=hc.round).rev() {
        if prevote.is_none() {
            if let Some(set) = hc.prevote_set(r) {
                if let Some(target) = set.quorum_target(&hc.validators) {
                    prevote = Some((r, set.power_for(target)));
                }
            }
        }
        if precommit.is_none() {
            if let Some(found) = hc.precommit_set(r).and_then(|set| {
                set.quorum_target(&hc.validators)
                    .flatten()
                    .map(|hash| (r, set.power_for(Some(hash))))
            }) {
                precommit = Some(found);
            }
        }
    }
    (prevote, precommit)
}

/// A deterministic "other block" a Byzantine validator double-votes for.
fn fake_target(height: Height, round: Round, vote: &Vote) -> BlockHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"STELLEREUM_BYZANTINE_EQUIVOCATION_V1");
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(&vote.voter);
    hasher.update(&vote.block_hash.unwrap_or([0u8; 32]));
    *hasher.finalize().as_bytes()
}
