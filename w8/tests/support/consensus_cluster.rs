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
//! The ONE wall-clock dependency is inside the consensus code itself:
//! `HeightConsensus::sync_round_to` allows at most
//! `MAX_SYNC_JUMPS_PER_SEC` (4) round jumps per **wall** second. A node whose
//! round clock is skewed needs one such jump per network round to stay in the
//! network's round, so the harness paces the cluster against the wall clock
//! (see [`ConsensusCluster::pace`]) whenever a scenario contains a skewed
//! node. Without that pacing a skewed scenario would be a coin flip on the
//! machine's speed - and a skipped jump is exactly the "no precommit QC"
//! stall this harness exists to catch.
//!
//! # REUSE
//!
//! ```ignore
//! mod support;
//! use support::consensus_cluster::ConsensusCluster;
//! ```

#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    /// Byzantine behaviour.
    pub byzantine: Byzantine,
    /// Extra delivery delay applied to the messages addressed to this node.
    pub inbound_delay_ms: u64,
}

impl Default for NodeProfile {
    fn default() -> Self {
        NodeProfile {
            power: 1,
            round_timeout_factor: 1,
            late_rounds: 0,
            down: false,
            vote_loss_permille: 0,
            byzantine: Byzantine::None,
            inbound_delay_ms: 0,
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
    /// How many prevotes the node CAST.
    pub prevotes_cast: u64,
    /// How many precommits the node CAST.
    pub precommits_cast: u64,
    /// How many prevotes the node RECEIVED (and accepted).
    pub prevotes_received: u64,
    /// How many precommits the node RECEIVED (and accepted).
    pub precommits_received: u64,
    /// How many proposals the node received.
    pub proposals_received: u64,
    /// How many proposals the node REFUSED.
    pub proposals_refused: u64,
    /// The round in which the node's PREVOTE quorum certificate formed.
    pub prevote_qc_round: Option<Round>,
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
    pub fn summary(&self) -> String {
        format!(
            "node {} ({}): h={} r={} finalized_h={} prevotes(cast/recv)={}/{} \
             precommits(cast/recv)={}/{} qc_round={:?} precommit_round={:?} \
             precommit_qc_round={:?} locked={:?} sync_jumps={} blockers={:?}",
            self.index,
            self.id,
            self.height,
            self.round,
            self.finalized_height,
            self.prevotes_cast,
            self.prevotes_received,
            self.precommits_cast,
            self.precommits_received,
            self.prevote_qc_round,
            self.precommit_round,
            self.precommit_qc_round,
            self.locked.map(|h| hex::encode(&h[..4])),
            self.sync_jumps,
            self.blockers,
        )
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
            let mut seen: HashMap<(Height, Round, VoteKind), Option<BlockHash>> = HashMap::new();
            for v in &node.cast_votes {
                match seen.get(&(v.height, v.round, v.kind)) {
                    Some(first) if *first != v.target => {
                        out.push((node.index, v.height, v.round, v.kind));
                    }
                    Some(_) => {}
                    None => {
                        seen.insert((v.height, v.round, v.kind), v.target);
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
    /// Wall-clock pacing state.
    pace_start_wall: Instant,
    pace_start_ms: u64,
    /// How many network rounds the cluster may advance per wall second.
    /// `None` disables the pacing (only safe when no node can fall behind).
    pace_rounds_per_wall_second: Option<u64>,
    /// How many round jumps the harness spends per wall second (the
    /// consensus code allows `MAX_SYNC_JUMPS_PER_SEC` = 4).
    jump_budget_per_wall_second: u32,
    jump_window_start: Instant,
    jump_budget_used: u32,
}

/// The default number of network rounds the harness lets the cluster advance
/// per wall second while a node is catching up.
///
/// The consensus code allows `MAX_SYNC_JUMPS_PER_SEC` (4) round jumps per wall
/// second, and a node whose round clock is skewed needs ONE jump per network
/// round to stay in the network's round. Capping the cluster at 3 rounds per
/// wall second keeps the jump demand (3) below the consensus budget (4).
pub const DEFAULT_PACE_ROUNDS_PER_WALL_SEC: u64 = 3;

/// The default number of round jumps the harness spends per wall second.
const DEFAULT_JUMPS_PER_WALL_SEC: u32 = 3;

/// Extra slack (ms) added to the harness's own jump window so it always
/// resets no later than the consensus code's window (whose start is the
/// node's construction time).
const JUMP_WINDOW_SLACK_MS: u64 = 50;

impl ConsensusCluster {
    /// Build a cluster of `n_validators` validators with EQUAL power.
    ///
    /// `skew` is the per-node round-timeout MULTIPLIER: `skew[i] == 1` is the
    /// base round timeout, `skew[i] == 5` is five times slower. A shorter
    /// `skew` slice means "the remaining nodes have no skew".
    pub fn new(n_validators: usize, skew: &[u64]) -> Self {
        let profiles = (0..n_validators)
            .map(|i| {
                let mut p = NodeProfile::default();
                p.round_timeout_factor = skew.get(i).copied().unwrap_or(1).max(1);
                p
            })
            .collect();
        Self::with_profiles(n_validators, profiles)
    }

    /// Build a cluster from explicit per-node profiles.
    pub fn with_profiles(n_validators: usize, profiles: Vec<NodeProfile>) -> Self {
        let seed = 0x5741_5220_4C49_5645u64; // "WART_LIVE"
        Self::build(n_validators, profiles, seed, 100, 1000)
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
        let build_start = Instant::now();
        let mut members: Vec<Member> = Vec::with_capacity(n_validators);
        let mut validators = ValidatorSet::new();

        // The cluster's shared starting round: every node that is NOT late
        // starts here. A late node starts `late_rounds` behind it.
        let base_round = profiles.iter().map(|p| p.late_rounds).max().unwrap_or(0);

        // Deterministic keys: seed || index. No OS randomness.
        for i in 0..n_validators {
            let key = key_at(seed, i as u64);
            let id = key.verifying_key().to_bytes();
            let profile = profiles[i].clone();
            validators.add(id, profile.power.max(1));

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
            pace_start_wall: build_start,
            pace_start_ms: 0,
            pace_rounds_per_wall_second: None,
            jump_budget_per_wall_second: DEFAULT_JUMPS_PER_WALL_SEC,
            // The window starts BEFORE the nodes were built, so the harness's
            // budget window always ends no later than the consensus code's.
            jump_window_start: build_start,
            jump_budget_used: 0,
        }
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

    /// Enable the wall-clock pacing of the cluster.
    ///
    /// REQUIRED for any scenario in which a node's round clock is skewed: the
    /// consensus code allows a bounded number of round jumps per WALL second,
    /// and a skewed node needs one per network round to stay in the network's
    /// round. Without the pacing the outcome depends on the machine's speed.
    pub fn with_pacing(mut self, rounds_per_wall_second: u64) -> Self {
        self.pace_rounds_per_wall_second = Some(rounds_per_wall_second.max(1));
        self
    }

    /// Seed every node's mempool with the same transaction, so the blocks
    /// carry real content and the state root EVOLVES height by height (a
    /// state-root comparison over an always-empty state proves nothing).
    pub async fn seed_transactions(&mut self, count: u64) {
        for m in self.members.iter_mut() {
            // The dev account is funded identically on every node, so every
            // node starts from the same state root.
            m.rt
                .state
                .update_account(AccountState::new(self.dev_address, self.genesis_balance))
                .await;
            m.rt
                .state
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
        self.pace();
        let stamp = self.now_ms;

        for i in 0..self.members.len() {
            // 1. PROPOSE
            self.step_propose(i, stamp).await;
            // 2. PREVOTE
            self.step_prevote(i, stamp).await;
            // 3. DRAIN the inbox
            self.step_drain(i).await;
            // 4. PRECOMMIT
            self.step_precommit(i).await;
            // 5. FINALIZE
            self.step_finalize(i).await;
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
        // The production loop votes once per round: a value vote when a live
        // proposal is held, and a NIL vote after twice the round timeout when
        // no proposal ever arrived (the nil vote is what keeps a behind node
        // visible to its peers).
        let live = self.members[i].rt.hc.has_live_proposal();
        if !live {
            let waited = self.now_ms.saturating_sub(self.members[i].round_started_ms);
            if waited < self.timeout_of(i).saturating_mul(2) {
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
                vote,
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
            let evil = Vote::sign(
                &self.members[i].key,
                h,
                r,
                VoteKind::Prevote,
                Some(fake),
            );
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
                    if res.is_err() {
                        self.members[i].stats.proposals_refused += 1;
                    }
                    // The proposal path can phase-align the node (a bounded
                    // round jump), which spends the consensus code's
                    // wall-clock jump budget. Account for it.
                    if self.members[i].rt.hc.round != before {
                        self.members[i].stats.sync_jumps += 1;
                        self.account_jump();
                        self.members[i].round_started_ms = self.now_ms;
                    }
                }
                Wire::Vote { vote, locked } => {
                    let kind = vote.kind;
                    let height = vote.height;
                    let round = vote.round;
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
                    if accepted && height == self.members[i].rt.hc.height {
                        // Phase alignment, exactly like the production drain:
                        // a verified peer vote pulls us into its round.
                        let moved = self
                            .members[i]
                            .rt
                            .note_peer_vote_round(height, round);
                        if moved {
                            self.members[i].stats.sync_jumps += 1;
                            self.account_jump();
                            // The production loop restarts the round timer
                            // when the round moves under it.
                            self.members[i].round_started_ms = self.now_ms;
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

        // Collect the equivocation evidence the node observed. The consensus
        // layer keeps it per height; it is read BEFORE the height is reset by
        // a finalize.
        let seen = self.members[i].rt.hc.equivocations();
        for ev in seen {
            let known = self
                .equivocations
                .iter()
                .any(|(v, a, b)| {
                    *v == ev.0
                        && a.block_hash == ev.1.block_hash
                        && b.block_hash == ev.2.block_hash
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
        self.record_cast(i, &vote);
        let stamp = self.now_ms;
        self.broadcast(
            i,
            Wire::Vote {
                vote,
                locked: None,
            },
            stamp,
        );
    }

    // ------------------------------------------------------------------
    // Step 5: finalize
    // ------------------------------------------------------------------

    async fn step_finalize(&mut self, i: usize) {
        if !self.is_active(i) {
            return;
        }
        let height = self.members[i].rt.hc.height;
        let Some(bh) = self.members[i].rt.try_finalize().await else {
            return;
        };
        // `try_finalize` RESETS the height consensus, so the decision proof
        // has already been stashed in `last_decision` (that is exactly what
        // the production commit broadcast reads).
        let Some((h, block, cert)) = self.members[i].rt.last_decision.clone() else {
            return;
        };
        debug_assert_eq!(h, height);
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
    }

    // ------------------------------------------------------------------
    // Step 6: view change
    // ------------------------------------------------------------------

    fn step_round_timeout(&mut self, i: usize, stamp: u64) {
        if !self.is_active(i) {
            return;
        }
        if stamp.saturating_sub(self.members[i].round_started_ms) < self.timeout_of(i) {
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
            self.broadcast(
                i,
                Wire::Vote {
                    vote: v,
                    locked,
                },
                stamp,
            );
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
                Wire::Vote { .. } => {
                    let permille = self.members[to].profile.vote_loss_permille;
                    permille > 0 && self.rng.chance(permille)
                }
                _ => false,
            };
            if drop {
                continue;
            }
            let delay = self.members[to].profile.inbound_delay_ms;
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

    /// Keep the consensus code's wall-clock sync-jump limiter happy.
    ///
    /// `HeightConsensus::sync_round_to` allows at most
    /// `MAX_SYNC_JUMPS_PER_SEC` (4) round jumps per WALL second. The
    /// harness spends at most `jump_budget_per_wall_second` per wall second
    /// and sleeps for the remainder of the window when the budget is spent,
    /// so the consensus limiter never refuses a jump the scenario needs.
    /// This is the ONLY place the harness touches the wall clock, and it
    /// never influences a consensus verdict - only the pacing.
    fn account_jump(&mut self) {
        let window = Duration::from_millis(1000);
        if self.jump_window_start.elapsed() >= window {
            self.jump_window_start = Instant::now();
            self.jump_budget_used = 0;
        }
        if self.jump_budget_used >= self.jump_budget_per_wall_second {
            let spent = self.jump_window_start.elapsed();
            let wait = window
                .saturating_sub(spent)
                .saturating_add(Duration::from_millis(JUMP_WINDOW_SLACK_MS));
            std::thread::sleep(wait);
            self.jump_window_start = Instant::now();
            self.jump_budget_used = 0;
        }
        self.jump_budget_used += 1;
    }

    /// Pace the virtual clock against the wall clock.
    ///
    /// A node whose round clock is skewed needs one round jump per network
    /// round to stay in the network's round, and the consensus code allows a
    /// bounded number of jumps per WALL second. Capping the cluster's round
    /// rate keeps the jump demand below the consensus budget, so a skewed
    /// scenario converges the same way on every machine.
    fn pace(&mut self) {
        let Some(rounds_per_s) = self.pace_rounds_per_wall_second else {
            return;
        };
        let virtual_since = self.now_ms.saturating_sub(self.pace_start_ms);
        let wall_ms = self.pace_start_wall.elapsed().as_millis() as u64;
        // Virtual ms allowed at the configured round rate.
        let allowed = wall_ms
            .saturating_mul(rounds_per_s)
            .saturating_mul(self.round_timeout_ms)
            / 1000;
        if virtual_since > allowed {
            let excess = virtual_since - allowed;
            // How many wall ms the excess is worth at this rate.
            let rate = (rounds_per_s * self.round_timeout_ms / 1000).max(1);
            let wait_ms = excess / rate;
            if wait_ms > 0 {
                std::thread::sleep(Duration::from_millis(wait_ms));
            }
        }
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
            // The prevote QC round: the newest round the node holds a
            // prevote certificate for.
            let prevote_qc_round = hc.prevote_qc.keys().copied().max();
            nodes.push(NodeReport {
                index: m.index,
                id: hex::encode(&m.id[..4]),
                height: hc.height,
                round: hc.round,
                finalized_height,
                finalized: m.rt.finalized.clone(),
                prevotes_cast: m.stats.prevotes_cast,
                precommits_cast: m.stats.precommits_cast,
                prevotes_received: m.stats.prevotes_received,
                precommits_received: m.stats.precommits_received,
                proposals_received: m.stats.proposals_received,
                proposals_refused: m.stats.proposals_refused,
                prevote_qc_round,
                precommit_round: m.last_precommitted.map(|(_, r)| r),
                precommit_qc_round: hc.precommit_qc.as_ref().map(|qc| qc.round),
                locked: hc.locked.map(|(b, _)| b),
                blockers: hc.finalize_blockers(),
                state_root: m.rt.state.get_state_root().await,
                sync_jumps: m.stats.sync_jumps,
                cast_votes: self.cast_votes[m.index].clone(),
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

/// A deterministic "other block" a Byzantine validator double-votes for.
fn fake_target(height: Height, round: Round, vote: &Vote) -> BlockHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"STELLEREUM_BYZANTINE_EQUIVOCATION_V1");
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(vote.voter);
    hasher.update(vote.block_hash.unwrap_or([0u8; 32]));
    *hasher.finalize().as_bytes()
}
