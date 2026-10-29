//! A deterministic, in-process MULTI-NODE rig that models the production
//! consensus loop of `src/main.rs` EXACTLY, on a virtual clock.
//!
//! # WHY THIS EXISTS
//!
//! The live 4-node WAN stand parked at height 285027 with a prevote quorum
//! and no precommit quorum. Nothing in the suite drove SEVERAL nodes with
//! skewed round clocks and asserted that the chain finalizes, so that whole
//! class of failure could come back silently.
//!
//! # WHAT IS REAL HERE
//!
//! Real [`ValidatorRuntime`]s: real Ed25519/Falcon signatures, real vote
//! sets, real quorum accounting, real quorum certificates, real state
//! transitions. Nothing in the consensus path is mocked — only the CLOCK and
//! the TRANSPORT are simulated.
//!
//! # WHAT IS SIMULATED
//!
//! * the clock (a virtual `now_ms` the harness advances by one tick), so a
//!   ten-minute WAN scenario runs in milliseconds and is bit-for-bit
//!   reproducible;
//! * the transport (a deterministic message pump with a per-link delivery
//!   delay).
//!
//! # THE PRODUCTION PHASE ORDER (this is the part that matters)
//!
//! `src/main.rs` runs, per 100 ms tick:
//!
//! 1. propose (if we are the scheduled proposer),
//! 2. prevote (value prevote when we hold a live proposal, nil prevote after
//!    2x the round timeout),
//! 3. drain the inbound queue (proposals, votes, committed blocks),
//! 4. precommit (when a prevote quorum exists),
//! 5. finalize (on a precommit quorum),
//! 6. view change (on the round timeout, with the production HOLD rules and
//!    the production vote re-send).
//!
//! The order matters and is reproduced here: a proposal accepted in the drain
//! is prevoted in the NEXT tick's prevote phase, and the view change comes
//! last so a round that just received votes is never abandoned in the same
//! tick.

#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use std::collections::VecDeque;
use std::sync::Arc;

use stellereum::consensus::{
    BlockHash, HeightConsensus, QuorumCertificate, ValidatorSet, Vote, VoteKind,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::InMemoryStateEngine;

// ===========================================================================
// Production constants (mirrored from src/main.rs)
// ===========================================================================

/// The production consensus tick (`STELL_TICK_MS`).
pub const TICK_MS: u64 = 100;
/// The live cluster's round timeout (`STELL_ROUND_TIMEOUT_MS`).
pub const LIVE_ROUND_TIMEOUT_MS: u64 = 3_500;
/// Per-round view-change backoff (`main.rs`).
pub const BACKOFF_PER_ROUND_MS: u64 = 500;
pub const BACKOFF_CAP_MS: u64 = 10_000;
/// `STELL_ROUND_ZERO_TIMEOUT_MS` default.
pub const ROUND_ZERO_TIMEOUT_MS: u64 = 650;
/// `STELL_MIN_BLOCK_MS` default.
pub const MIN_BLOCK_MS: u64 = 400;

/// `main.rs::effective_round_timeout_ms` — the backoff counts the view
/// changes THIS HEIGHT has failed (`hc.timeouts`), NOT the absolute round
/// number.
pub fn effective_round_timeout_ms(base_ms: u64, timeouts: u32) -> u64 {
    base_ms
        .saturating_add((timeouts as u64).saturating_mul(BACKOFF_PER_ROUND_MS))
        .min(base_ms.saturating_add(BACKOFF_CAP_MS))
}

// ===========================================================================
// The wire
// ===========================================================================

#[derive(Clone, Debug)]
enum Msg {
    Proposal {
        round: u32,
        block: Block,
    },
    Vote(Vote),
    Committed {
        height: u64,
        block: Block,
        certificate: QuorumCertificate,
    },
}

struct Envelope {
    deliver_at_ms: u64,
    to: usize,
    msg: Msg,
}

#[derive(Default)]
struct Wire {
    queue: VecDeque<Envelope>,
}

impl Wire {
    /// Queue a message for delivery at `deliver_at_ms`.
    ///
    /// The queue is kept in DELIVERY-TIME ORDER: a FIFO would let one
    /// long-delayed message (a stalled vote) block every message queued
    /// behind it, which is a transport bug the real network does not have
    /// (messages are delivered independently of each other).
    fn send(&mut self, to: usize, msg: Msg, deliver_at_ms: u64) {
        let envelope = Envelope {
            deliver_at_ms,
            to,
            msg,
        };
        let at = self.queue.len();
        for (i, e) in self.queue.iter().enumerate() {
            if e.deliver_at_ms > deliver_at_ms {
                self.queue.insert(i, envelope);
                return;
            }
        }
        self.queue.insert(at, envelope);
    }

    fn take_due(&mut self, now_ms: u64) -> Vec<(usize, Msg)> {
        let mut out = Vec::new();
        while let Some(e) = self.queue.front() {
            if e.deliver_at_ms > now_ms {
                break;
            }
            let e = self.queue.pop_front().expect("front exists");
            out.push((e.to, e.msg));
        }
        out
    }
}

// ===========================================================================
// A node
// ===========================================================================

pub struct Node {
    pub rt: ValidatorRuntime,
    pub idx: usize,
    /// This node votes (validator) or only follows (observer).
    pub voting: bool,
    /// This node's own round timeout.
    pub base_timeout_ms: u64,
    /// When the node joined the network (virtual ms) — the start skew.
    pub start_ms: u64,
    /// When the node's current round started.
    round_started_ms: u64,
    /// When the node produced its last block (`STELL_MIN_BLOCK_MS` gate).
    last_block_at_ms: u64,
    last_prevoted: Option<(u64, u32)>,
    last_precommitted: Option<(u64, u32)>,
    cast_prevote: Option<Vote>,
    cast_precommit: Option<Vote>,
    /// (height, round, at_ms) of the last peer vote seen at our height.
    peer_round_seen: Option<(u64, u32, u64)>,
    /// Every prevote this node cast, for the diagnosis.
    pub prevotes_cast: Vec<(u32, Option<BlockHash>)>,
    /// Every precommit this node cast, for the diagnosis.
    pub precommits_cast: Vec<(u32, Option<BlockHash>)>,
    /// The height this node is currently consensusing.
    tracked_height: u64,
}

impl Node {
    /// The effective round timeout of this node right now (production
    /// ladder: base + per-view-change backoff, capped).
    pub fn effective_timeout_ms(&self) -> u64 {
        effective_round_timeout_ms(self.base_timeout_ms, self.rt.hc.timeouts)
    }
}

// ===========================================================================
// The cluster
// ===========================================================================

/// Per-node profile.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Voting power (0 = observer: it follows but never votes).
    pub power: u64,
    /// This node's own round timeout.
    pub round_timeout_ms: u64,
    /// When the node joins the network.
    pub start_ms: u64,
    /// How many rounds this node starts BEHIND the others.
    pub late_rounds: u32,
    /// One-way message delay TO this node.
    pub delay_ms: u64,
    /// Permille of inbound messages DROPPED (the WAN is lossy).
    pub loss_permille: u32,
    /// EXTRA delay applied to the VOTES this node receives (a slow /
    /// asymmetric link: the vote arrives long after it was cast).
    pub vote_delay_ms: u64,
}

impl Profile {
    pub fn validator(power: u64) -> Self {
        Profile {
            power,
            round_timeout_ms: LIVE_ROUND_TIMEOUT_MS,
            start_ms: 0,
            late_rounds: 0,
            delay_ms: 400,
            loss_permille: 0,
            vote_delay_ms: 0,
        }
    }
    pub fn observer() -> Self {
        Profile {
            power: 0,
            round_timeout_ms: LIVE_ROUND_TIMEOUT_MS,
            start_ms: 0,
            late_rounds: 0,
            delay_ms: 400,
            loss_permille: 0,
            vote_delay_ms: 0,
        }
    }
    pub fn vote_delay(mut self, ms: u64) -> Self {
        self.vote_delay_ms = ms;
        self
    }
    pub fn start(mut self, ms: u64) -> Self {
        self.start_ms = ms;
        self
    }
    pub fn timeout(mut self, ms: u64) -> Self {
        self.round_timeout_ms = ms;
        self
    }
    pub fn late(mut self, rounds: u32) -> Self {
        self.late_rounds = rounds;
        self
    }
    pub fn delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }
    pub fn loss(mut self, permille: u32) -> Self {
        self.loss_permille = permille;
        self
    }
}

/// A tiny seeded PRNG (xorshift64*) — no OS randomness in the harness.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng { state: seed | 1 }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// The report of a finished scenario.
#[derive(Debug)]
pub struct Report {
    /// The height each node is currently consensusing.
    pub heights: Vec<u64>,
    /// The round each node is in.
    pub rounds: Vec<u32>,
    /// The prevotes each node cast, per height.
    pub prevotes_cast: Vec<Vec<(u32, Option<BlockHash>)>>,
    /// The precommits each node cast, per height.
    pub precommits_cast: Vec<Vec<(u32, Option<BlockHash>)>>,
    /// The finalized chain of each node.
    pub finalized: Vec<Vec<(u64, BlockHash)>>,
    /// Virtual milliseconds elapsed.
    pub virtual_ms: u64,
}

impl Report {
    /// The lowest finalized height across the nodes.
    pub fn common_finalized(&self) -> u64 {
        self.finalized
            .iter()
            .filter_map(|f| f.last().map(|(h, _)| *h))
            .min()
            .unwrap_or(0)
    }
}

pub struct Cluster {
    nodes: Vec<Node>,
    wire: Wire,
    delays: Vec<u64>,
    vote_delays: Vec<u64>,
    losses: Vec<u32>,
    now_ms: u64,
    tx_key: SigningKey,
    tx_nonce: u64,
    /// Print the "precommit quorum but no decision" diagnosis every tick.
    pub diagnose_finalize: bool,
    /// The message-loss PRNG (seeded: the run is reproducible).
    rng: Rng,
    /// Every block hash that was ever proposed (for the diagnosis).
    pub proposed: std::collections::HashSet<BlockHash>,
}

impl Cluster {
    pub async fn new(profiles: &[Profile]) -> Cluster {
        let n = profiles.len();
        let keys: Vec<SigningKey> = (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i as u8).wrapping_add(1);
                seed[31] = 0x5A;
                SigningKey::from_bytes(&seed)
            })
            .collect();
        let vset = ValidatorSet::from_list(
            keys.iter()
                .zip(profiles.iter())
                .filter(|(_, p)| p.power > 0)
                .map(|(k, p)| (k.verifying_key().to_bytes(), p.power))
                .collect(),
        );
        let mut nodes = Vec::new();
        for i in 0..n {
            let state = Arc::new(InMemoryStateEngine::new());
            // The GENESIS bond is PROPORTIONAL to the profile power, so the
            // validator-set ROTATION at the height boundary (the ledger is
            // re-read and the powers become the bonded stakes) keeps the live
            // power split (1500/1000/1000) instead of flattening it to equal
            // stakes. The live cluster's quorum was 2334 of 3500 — i.e. the
            // 1500-STELL validator was in EVERY quorum — and that shape is
            // the one under test.
            {
                let mut ledger = state.staking_write().await;
                for (k, p) in keys.iter().zip(profiles.iter()) {
                    if p.power == 0 {
                        continue;
                    }
                    let id = k.verifying_key().to_bytes();
                    state
                        .update_account(stellereum::state_engine::AccountState::new(
                            id,
                            1_000_000_000_000_000_000,
                        ))
                        .await;
                    let _ = ledger.bond_genesis(id, p.power, 0);
                }
            }
            let rt = ValidatorRuntime::new(keys[i].clone(), vset.clone(), state, 1);
            let mut node = Node {
                rt,
                idx: i,
                voting: profiles[i].power > 0,
                base_timeout_ms: profiles[i].round_timeout_ms,
                start_ms: profiles[i].start_ms,
                round_started_ms: profiles[i].start_ms,
                last_block_at_ms: 0,
                last_prevoted: None,
                last_precommitted: None,
                cast_prevote: None,
                cast_precommit: None,
                peer_round_seen: None,
                prevotes_cast: Vec::new(),
                precommits_cast: Vec::new(),
                tracked_height: 1,
            };
            // A node that joins late is BEHIND the network: the round counter
            // is where the network is.
            node.rt.hc.round = profiles[i].late_rounds;
            nodes.push(node);
        }
        // A funded account whose transactions make every proposal DIFFERENT
        // (an empty mempool makes every proposal byte-identical, which hides
        // the lock / re-propose pathology).
        let mut seed = [0u8; 32];
        seed[0] = 0x77;
        seed[31] = 0xA5;
        let tx_key = SigningKey::from_bytes(&seed);
        let tx_addr = tx_key.verifying_key().to_bytes();
        for node in &nodes {
            node.rt
                .state
                .update_account(stellereum::state_engine::AccountState::new(
                    tx_addr,
                    1_000_000_000_000_000_000,
                ))
                .await;
        }
        Cluster {
            nodes,
            wire: Wire::default(),
            delays: profiles.iter().map(|p| p.delay_ms).collect(),
            vote_delays: profiles.iter().map(|p| p.vote_delay_ms).collect(),
            losses: profiles.iter().map(|p| p.loss_permille).collect(),
            now_ms: 0,
            tx_key,
            tx_nonce: 0,
            diagnose_finalize: false,
            rng: Rng::new(0x5EED_1234_ABCD_0001),
            proposed: std::collections::HashSet::new(),
        }
    }

    async fn seed_tx(&mut self) {
        self.tx_nonce += 1;
        let tx = Transaction::sign(&self.tx_key, [7u8; 32], 1, 1_000, self.tx_nonce, 0, 0);
        for node in self.nodes.iter_mut() {
            node.rt.add_tx(tx.clone()).await;
        }
    }

    /// Broadcast to every other node, each with ITS OWN delivery delay and
    /// loss rate. The loss draw happens ONCE, at broadcast time, in a fixed
    /// order, so the whole run is reproducible.
    fn broadcast(&mut self, from: usize, msg: Msg) {
        let now = self.now_ms;
        for i in 0..self.nodes.len() {
            if i == from {
                continue;
            }
            let permille = self.losses[i];
            if permille > 0 && self.rng.below(1000) < permille as u64 {
                continue; // dropped in transit
            }
            let mut delay = self.delays[i];
            if matches!(msg, Msg::Vote(_)) {
                delay += self.vote_delays[i];
            }
            self.wire.send(i, msg.clone(), now + delay);
        }
    }

    /// Run the scenario for `duration_ms` of virtual time.
    pub async fn run(&mut self, duration_ms: u64) -> Report {
        let end = self.now_ms + duration_ms;
        while self.now_ms < end {
            let now = self.now_ms;
            self.tick(now).await;
            // The apply worker is a separate task: yield so it can run (the
            // test runtime is single-threaded, so a tight loop would starve
            // it and the height would never advance).
            tokio::task::yield_now().await;
            self.now_ms += TICK_MS;
        }
        self.report()
    }

    async fn tick(&mut self, now: u64) {
        let n = self.nodes.len();

        // ---- height bookkeeping --------------------------------------
        let mut advanced = false;
        for i in 0..n {
            let h = self.nodes[i].rt.hc.height;
            if h != self.nodes[i].tracked_height {
                self.nodes[i].tracked_height = h;
                self.nodes[i].last_prevoted = None;
                self.nodes[i].last_precommitted = None;
                self.nodes[i].cast_prevote = None;
                self.nodes[i].cast_precommit = None;
                self.nodes[i].round_started_ms = now;
                self.nodes[i].prevotes_cast.clear();
                self.nodes[i].precommits_cast.clear();
                advanced = true;
            }
        }
        if advanced {
            self.seed_tx().await;
        }

        // ---- phase 1 + 2: propose, prevote ----------------------------
        for i in 0..n {
            if now < self.nodes[i].start_ms {
                continue;
            }
            let height = self.nodes[i].rt.hc.height;
            let round = self.nodes[i].rt.hc.round;

            // propose
            if self.nodes[i].voting
                && self.nodes[i].rt.is_proposer()
                && !self.nodes[i].rt.hc.has_live_proposal()
                && now.saturating_sub(self.nodes[i].last_block_at_ms) >= MIN_BLOCK_MS
            {
                let ts = height * 1_000 + round as u64;
                let proposed = self.nodes[i].rt.propose(ts).await;
                if self.diagnose_finalize && height == 2 {
                    eprintln!(
                        "[diag] node {i} h={height} r{round} PROPOSE -> {}: \
                         is_proposer={} step={:?} pending_apply={} live={}",
                        if proposed.is_some() { "OK" } else { "None" },
                        self.nodes[i].rt.is_proposer(),
                        self.nodes[i].rt.hc.step,
                        self.nodes[i].rt.has_pending_apply(),
                        self.nodes[i].rt.hc.has_live_proposal()
                    );
                }
                if let Some(block) = proposed {
                    self.nodes[i].last_block_at_ms = now;
                    let r = self.nodes[i].rt.hc.round;
                    self.proposed.insert(block.compute_hash());
                    self.broadcast(i, Msg::Proposal { round: r, block });
                }
            }

            // prevote (value), or nil after 2x the round timeout — but only
            // when no peer is alive in this round (the production "wait for a
            // peer" rule: a nil prevote spends this node's one vote for the
            // round, and a round with a nil vote can never carry the polka
            // the rest of the network is voting for).
            let has_live = self.nodes[i].rt.hc.has_live_proposal();
            let elapsed = now.saturating_sub(self.nodes[i].round_started_ms);
            let peer_alive_in_round = matches!(
                self.nodes[i].peer_round_seen,
                Some((ph, pr, at))
                    if ph == height
                        && pr + 1 >= round
                        && now.saturating_sub(at) < self.nodes[i].base_timeout_ms
            );
            let want_nil =
                !has_live && elapsed >= 2 * self.nodes[i].base_timeout_ms && !peer_alive_in_round;
            if self.nodes[i].voting
                && self.nodes[i].last_prevoted != Some((height, round))
                && (has_live || want_nil)
            {
                if let Some(v) = self.nodes[i].rt.make_prevote() {
                    if self.diagnose_finalize && height == 2 {
                        eprintln!(
                            "[diag] node {i} h={height} r{round} prevote target={:?} live={has_live} \
                             locked={:?} proposal={:?} proposal_round={:?} step={:?}",
                            v.block_hash.map(|b| hex::encode(&b[..3])),
                            self.nodes[i].rt.hc.locked.map(|(b, r)| (hex::encode(&b[..3]), r)),
                            self.nodes[i].rt.hc.proposal.map(|(_, b)| hex::encode(&b[..3])),
                            self.nodes[i].rt.hc.proposal_round,
                            self.nodes[i].rt.hc.step
                        );
                    }
                    self.nodes[i].last_prevoted = Some((height, round));
                    self.nodes[i].prevotes_cast.push((v.round, v.block_hash));
                    let _ = self.nodes[i].rt.on_prevote(v.clone());
                    self.broadcast(i, Msg::Vote(v.clone()));
                    self.nodes[i].cast_prevote = Some(v);
                }
            }
        }

        // ---- phase 3: drain -------------------------------------------
        let due = self.wire.take_due(now);
        for (to, msg) in due {
            let height = self.nodes[to].rt.hc.height;
            match msg {
                Msg::Proposal { round, block } => {
                    let proposer = block.proposer;
                    let bh = block.height;
                    if let Err(e) = self.nodes[to].rt.on_proposal(proposer, block, round).await {
                        if self.diagnose_finalize {
                            eprintln!(
                                "[diag] node {to} refused proposal h={bh} r{round} from {:?}: {e}",
                                hex::encode(&proposer[..4])
                            );
                        }
                    }
                }
                Msg::Vote(v) => {
                    if v.height != height {
                        continue;
                    }
                    let before = self.nodes[to].rt.hc.round;
                    match v.kind {
                        VoteKind::Prevote => {
                            let _ = self.nodes[to].rt.on_prevote(v.clone());
                        }
                        VoteKind::Precommit => {
                            let _ = self.nodes[to].rt.on_precommit(v.clone());
                        }
                    }
                    self.nodes[to].peer_round_seen = Some((v.height, v.round, now));
                    if self.nodes[to].rt.hc.round != before {
                        self.nodes[to].round_started_ms = now;
                    }
                }
                Msg::Committed {
                    height: ch,
                    block,
                    certificate,
                } => {
                    if self.diagnose_finalize {
                        eprintln!(
                            "[diag] node {to} got Committed h={ch} (our height {height}) round={}",
                            certificate.round
                        );
                    }
                    if ch != height {
                        continue;
                    }
                    if let Err(e) = self.nodes[to]
                        .rt
                        .adopt_committed(ch, block, certificate)
                        .await
                    {
                        if self.diagnose_finalize {
                            eprintln!("[diag] node {to} refused to adopt committed h={ch}: {e}");
                        }
                    }
                }
            }
        }

        if self.diagnose_finalize {
            for i in 0..n {
                if self.nodes[i].rt.hc.height == 2 {
                    eprintln!(
                        "[diag] after drain: node {i} h=2 r{} live={} proposal={:?} proposal_round={:?} step={:?}",
                        self.nodes[i].rt.hc.round,
                        self.nodes[i].rt.hc.has_live_proposal(),
                        self.nodes[i].rt.hc.proposal.map(|(_, b)| hex::encode(&b[..3])),
                        self.nodes[i].rt.hc.proposal_round,
                        self.nodes[i].rt.hc.step
                    );
                }
            }
        }
        // ---- phase 4: precommit ---------------------------------------
        for i in 0..n {
            if !self.nodes[i].voting {
                continue;
            }
            let height = self.nodes[i].rt.hc.height;
            if let Some(v) = self.nodes[i].rt.make_precommit() {
                if self.nodes[i].last_precommitted != Some((height, v.round)) {
                    self.nodes[i].last_precommitted = Some((height, v.round));
                    self.nodes[i].precommits_cast.push((v.round, v.block_hash));
                    let _ = self.nodes[i].rt.on_precommit(v.clone());
                    self.broadcast(i, Msg::Vote(v.clone()));
                    self.nodes[i].cast_precommit = Some(v);
                }
            }
        }

        // ---- phase 5: finalize ----------------------------------------
        for i in 0..n {
            // DIAGNOSIS: a precommit quorum that does not become a decision
            // is the live failure (the height stays parked). Report it.
            if self.diagnose_finalize {
                let hc = &self.nodes[i].rt.hc;
                let mut qc_round: Option<u32> = None;
                for r in 0..=hc.round.min(4096) {
                    if let Some(set) = hc.precommit_set(r) {
                        if set.quorum_target(&hc.validators).flatten().is_some() {
                            qc_round = Some(r);
                            break;
                        }
                    }
                }
                if let Some(r) = qc_round {
                    let decided = hc.decided;
                    let body = decided.and_then(|d| self.nodes[i].rt.blocks.get(&d).cloned());
                    let body_info = match (&decided, &body) {
                        (Some(d), Some(b)) => format!(
                            "body present: hash_ok={} order_root_ok={}",
                            b.compute_hash() == *d,
                            b.order_merkle_root
                                == stellereum::mev::compute_order_merkle_root(&b.transactions)
                        ),
                        (Some(_), None) => "body MISSING".to_string(),
                        _ => "no decision".to_string(),
                    };
                    eprintln!(
                        "[diag] node {i} h={} has a PRECOMMIT QUORUM at r{r} but has not decided \
                         (blockers: {:?}) decided={:?} step={:?} {}",
                        hc.height,
                        hc.finalize_blockers(),
                        decided.map(|d| hex::encode(&d[..4])),
                        hc.step,
                        body_info
                    );
                }
            }
            // The DECISION is what is under test, so the harness uses the
            // await-inline finalize path: the production path queues the
            // execution on the apply worker and the height advances when the
            // worker reports back, which a virtual clock cannot wait for
            // deterministically (the worker would be starved by the tight
            // tick loop). `prepare_decided_block` - the quorum, body, order
            // and cap gates - is shared by both paths, so the decision
            // semantics are identical.
            let height_before = self.nodes[i].rt.hc.height;
            let decided = self.nodes[i].rt.try_finalize().await;
            if let Some(bh) = decided {
                if let Some(block) = self.nodes[i].rt.blocks.get(&bh).cloned() {
                    if let Some(cert) = block.precommit_qc.clone() {
                        self.broadcast(
                            i,
                            Msg::Committed {
                                height: height_before,
                                block,
                                certificate: cert,
                            },
                        );
                    }
                }
                self.nodes[i].last_prevoted = None;
                self.nodes[i].last_precommitted = None;
                self.nodes[i].cast_prevote = None;
                self.nodes[i].cast_precommit = None;
                self.nodes[i].round_started_ms = now;
            }
        }

        // ---- phase 6: view change -------------------------------------
        for i in 0..n {
            if !self.nodes[i].voting {
                continue;
            }
            if now < self.nodes[i].start_ms {
                continue;
            }
            let height = self.nodes[i].rt.hc.height;
            let round = self.nodes[i].rt.hc.round;
            let timeout = self.nodes[i].effective_timeout_ms();
            let elapsed = now.saturating_sub(self.nodes[i].round_started_ms);

            // The production HOLD rules: a live peer nearby (or a peer heard
            // from inside this round's timeout window) keeps us in the round
            // for at most 2x the timeout.
            let peer_is_active_nearby = matches!(
                self.nodes[i].peer_round_seen,
                Some((ph, pr, at))
                    if ph == height
                        && now.saturating_sub(at) < 2 * timeout
                        && pr <= round
                        && pr + 1 >= round
            );
            let peer_alive_recently = matches!(
                self.nodes[i].peer_round_seen,
                Some((ph, _, at)) if ph == height && now.saturating_sub(at) < timeout
            );
            let hold_bounded =
                (peer_is_active_nearby || peer_alive_recently) && elapsed < 2 * timeout;

            if elapsed > timeout && !hold_bounded {
                // Re-send this round's votes before leaving it (production
                // does exactly this: a single lost datagram must not cost a
                // peer its quorum for the whole round).
                for v in [
                    self.nodes[i].cast_prevote.clone(),
                    self.nodes[i].cast_precommit.clone(),
                ]
                .into_iter()
                .flatten()
                {
                    self.broadcast(i, Msg::Vote(v));
                }
                self.nodes[i].rt.next_round();
                self.nodes[i].last_prevoted = None;
                self.nodes[i].last_precommitted = None;
                self.nodes[i].cast_prevote = None;
                self.nodes[i].cast_precommit = None;
                self.nodes[i].round_started_ms = now;
            }
        }
    }

    pub fn report(&self) -> Report {
        Report {
            heights: self.nodes.iter().map(|n| n.rt.hc.height).collect(),
            rounds: self.nodes.iter().map(|n| n.rt.hc.round).collect(),
            prevotes_cast: self.nodes.iter().map(|n| n.prevotes_cast.clone()).collect(),
            precommits_cast: self
                .nodes
                .iter()
                .map(|n| n.precommits_cast.clone())
                .collect(),
            finalized: self.nodes.iter().map(|n| n.rt.finalized.clone()).collect(),
            virtual_ms: self.now_ms,
        }
    }

    /// The nodes' consensus state (for the diagnosis).
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// A deep per-node diagnosis of why a height is not finalizing.
    pub fn diagnose(&self) -> String {
        let mut s = String::new();
        for n in &self.nodes {
            let hc = &n.rt.hc;
            s.push_str(&format!(
                "\n== node {} (validator={}) height={} round={} step={:?} locked={:?} timeouts={} \
                 scan_lookback={} max_peer_round={:?} observed_polka={:?} peers={:?}\n",
                n.idx,
                n.voting,
                hc.height,
                hc.round,
                hc.step,
                hc.locked,
                hc.timeouts,
                hc.scan_lookback,
                hc.max_peer_round(),
                hc.observed_polka().map(|(r, b)| (r, hex::encode(&b[..4]))),
                hc.peer_rounds
            ));
            s.push_str(&format!(
                "   finalize_blockers: {:?}\n",
                hc.finalize_blockers()
            ));
            let mut rounds: Vec<u32> = Vec::new();
            for r in 0..=hc.round.min(4096) {
                if hc.prevote_set(r).is_some() || hc.precommit_set(r).is_some() {
                    rounds.push(r);
                }
            }
            for r in rounds {
                let pv = hc.prevote_set(r);
                let pc = hc.precommit_set(r);
                s.push_str(&format!(
                    "   r{r}: prevotes n={} quorum={:?} | precommits n={} quorum={:?}\n",
                    pv.map(|s| s.len()).unwrap_or(0),
                    pv.and_then(|s| s.quorum_target(&hc.validators)),
                    pc.map(|s| s.len()).unwrap_or(0),
                    pc.and_then(|s| s.quorum_target(&hc.validators)),
                ));
                // The power distribution: which target got how much.
                if let Some(pv) = pv {
                    let nil = pv.power_for(None);
                    let mut vals: Vec<(u64, u32)> = Vec::new();
                    for h in &self.proposed {
                        let p = pv.power_for(Some(*h));
                        if p > 0 {
                            vals.push((p, u32::from_be_bytes(h[0..4].try_into().unwrap())));
                        }
                    }
                    vals.sort_by(|a, b| b.0.cmp(&a.0));
                    vals.truncate(4);
                    s.push_str(&format!(
                        "        power: nil={nil} values={:?} (quorum needs {})\n",
                        vals,
                        hc.validators.quorum_power()
                    ));
                }
            }
        }
        s
    }
}

// ===========================================================================
// Diagnosis helpers
// ===========================================================================

/// How many DISTINCT precommits (non-nil) the given casts contain in `round`.
pub fn precommits_in_round(casts: &[(u32, Option<BlockHash>)], round: u32) -> usize {
    casts
        .iter()
        .filter(|(r, t)| *r == round && t.is_some())
        .count()
}

/// How many DISTINCT prevotes (non-nil) the given casts contain in `round`.
pub fn prevotes_in_round(casts: &[(u32, Option<BlockHash>)], round: u32) -> usize {
    casts
        .iter()
        .filter(|(r, t)| *r == round && t.is_some())
        .count()
}

/// The round in which the given casts have the most non-nil votes.
pub fn busiest_round(casts: &[(u32, Option<BlockHash>)]) -> Option<u32> {
    let mut best: Option<(u32, usize)> = None;
    for (r, t) in casts {
        if t.is_none() {
            continue;
        }
        match best {
            Some((br, n)) if *r == br => best = Some((br, n + 1)),
            Some((br, _n)) if *r > br => best = Some((*r, 1)),
            Some(_) => {}
            None => best = Some((*r, 1)),
        }
    }
    best.map(|(r, _)| r)
}

/// A one-line-per-node summary of a report (the diagnosis dump).
pub fn dump(report: &Report) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "heights={:?} rounds={:?} virtual_ms={}\n",
        report.heights, report.rounds, report.virtual_ms
    ));
    for (i, node) in report.prevotes_cast.iter().enumerate() {
        s.push_str(&format!(
            "  node {i}: prevotes={:?} precommits={:?}\n",
            node,
            report.precommits_cast.get(i).unwrap_or(&vec![])
        ));
    }
    s
}

/// The height consensus of a node (test-only accessor).
pub fn hc_of(node: &Node) -> &HeightConsensus {
    &node.rt.hc
}
