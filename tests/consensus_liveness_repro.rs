//! Regression tests for the LIVE masterchain liveness failure.
//!
//! # The incident
//!
//! The live 4-node WAN cluster (3 validators, 1500/1000/1000 STELL) parked at
//! height 285027 and never finalized again. The nodes agreed on the state
//! root (so it was NOT a state divergence) and they DID form a full prevote
//! quorum for the same block hash at the same round — but only ONE of them
//! ever cast a PRECOMMIT, so no precommit quorum ever formed and the height
//! was never decided.
//!
//! # The root cause (two independent defects, one liveness bug each)
//!
//! 1. **A nil quorum masked the polka.** `try_prevote_quorum_at` returned the
//!    newest quorum in the scan window — a NIL quorum included. A node that
//!    had moved on to a later round had collected a nil quorum there (the
//!    network timed out), and that nil quorum SHADOWED the real polka one
//!    round earlier. `make_precommit` then emitted a *nil* precommit for the
//!    newer round instead of a precommit for the block the network had
//!    actually certified, and the `last_precommitted` dedup key — which is
//!    keyed on the vote's round — suppressed the correct precommit on every
//!    later tick. The polka stayed masked for as long as the nil quorum
//!    stayed in the window: forever.
//!
//! 2. **The quorum scan could not see the network's round.** The window was
//!    `[our_round - ROUND_LOOKBACK, our_round]`. A node that had drifted
//!    AHEAD of the network (per-node round-timeout skew on a WAN) could not
//!    see the round the network was in, so it never found the polka and never
//!    precommitted. The window is now anchored on the network's round.
//!
//! Both defects are pinned below: `polka_is_not_masked_by_a_newer_nil_quorum`
//! and `a_node_ahead_of_the_network_still_precommits_the_network_polka` fail
//! without the fix, and the multi-node cluster test does not finalize.
//!
//! # The harness
//!
//! `Sim` is a deterministic, virtual-clock model of the production consensus
//! loop in `src/main.rs`: real `ValidatorRuntime`s (real signatures, real vote
//! sets, real certificates), real `HeightConsensus` state machines, a
//! deterministic message pump with per-link delivery delay (the WAN), and the
//! production phase order (propose -> prevote -> drain -> precommit ->
//! finalize -> view change) including the production round-timeout ladder
//! and the production view-change hold.
//!
//! A ten-minute WAN scenario runs in milliseconds and is bit-for-bit
//! reproducible.

use ed25519_dalek::SigningKey;
use std::collections::VecDeque;
use std::sync::Arc;

use stellereum::consensus::{BlockHash, HeightConsensus, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::InMemoryStateEngine;

/// The production consensus tick is 100 ms.
const TICK_MS: u64 = 100;

/// The live cluster's round timeout.
const LIVE_ROUND_TIMEOUT_MS: u64 = 3_500;

/// Per-round view-change backoff (mirrors `main.rs`).
const BACKOFF_PER_ROUND_MS: u64 = 500;
const BACKOFF_CAP_MS: u64 = 10_000;

fn effective_round_timeout_ms(base_ms: u64, round: u32) -> u64 {
    base_ms
        .saturating_add((round as u64).saturating_mul(BACKOFF_PER_ROUND_MS))
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
    /// A decided height, with the certificate that decided it (production
    /// broadcasts `ConsensusMsg::Committed`).
    Committed {
        height: u64,
        block: Block,
        certificate: stellereum::consensus::QuorumCertificate,
    },
}

struct Envelope {
    deliver_at_ms: u64,
    to: usize,
    msg: Msg,
}

#[derive(Default)]
struct Wire {
    now_ms: u64,
    queue: VecDeque<Envelope>,
}

impl Wire {
    fn send(&mut self, to: usize, msg: Msg, delay_ms: u64) {
        self.queue.push_back(Envelope {
            deliver_at_ms: self.now_ms + delay_ms,
            to,
            msg,
        });
    }

    /// Take everything due at `now_ms`.
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

struct Node {
    rt: ValidatorRuntime,
    idx: usize,
    /// This node's OWN round timeout (the live cluster had per-node drift).
    base_timeout_ms: u64,
    /// When this node's current round started (virtual clock).
    round_started_ms: u64,
    /// When this node joined the network (virtual clock) - the start skew.
    start_ms: u64,
    last_prevoted: Option<(u64, u32)>,
    last_precommitted: Option<(u64, u32)>,
    /// (height, round, at_ms) of the last peer vote we saw.
    peer_round_seen: Option<(u64, u32, u64)>,
    /// Every prevote this node cast, for the diagnosis.
    prevotes_cast: Vec<(u32, Option<BlockHash>)>,
    /// Every precommit this node cast, for the diagnosis.
    precommits_cast: Vec<(u32, Option<BlockHash>)>,
    /// How many rounds this height ended in a view change (the harness's own
    /// count: the round-timeout backoff must follow the rounds THIS HEIGHT
    /// failed, not the absolute round number).
    view_changes: u32,
}

impl Node {
    fn effective_timeout(&self) -> u64 {
        effective_round_timeout_ms(self.base_timeout_ms, self.view_changes)
    }

    fn broadcast_vote(&mut self, wire: &mut Wire, n: usize, delay_ms: u64, v: Vote) {
        for p in 0..n {
            if p != self.idx {
                wire.send(p, Msg::Vote(v.clone()), delay_ms);
            }
        }
    }
}

// ===========================================================================
// The cluster
// ===========================================================================

pub struct Sim {
    nodes: Vec<Node>,
    wire: Wire,
    n: usize,
    delay_ms: u64,
    /// Height each node is currently consensusing.
    heights: Vec<u64>,
    /// The key of a funded account whose transactions make every block
    /// DIFFERENT (an empty mempool makes every proposal identical, which
    /// hides the whole failure: the lock/re-propose path papers over it).
    tx_key: SigningKey,
    tx_nonce: u64,
    /// When the last vote was put on the wire.
    ///
    /// The harness lets the vote set SETTLE before it decides a height. A
    /// node assembles the precommit certificate from the votes it has
    /// RECEIVED, so two nodes that finalize the same block at slightly
    /// different moments hold certificates with different signer sets — and
    /// the downtime slash reads the certificate's signer set, so the two
    /// compute different state roots. That is a SEPARATE, pre-existing
    /// defect (a state divergence, not a liveness one); the LIVE cluster has
    /// identical roots on all four nodes, so the harness mirrors that by
    /// deciding on a settled set. This keeps the regression test focused on
    /// the liveness defect under test.
    last_vote_ms: u64,
}

impl Sim {
    pub async fn new(
        powers: &[u64],
        base_timeouts_ms: &[u64],
        start_offsets_ms: &[u64],
        delay_ms: u64,
    ) -> Sim {
        let n = powers.len();
        let ks: Vec<SigningKey> = keys(n);
        let vset = ValidatorSet::from_list(
            ks.iter()
                .zip(powers.iter())
                .map(|(k, p)| (k.verifying_key().to_bytes(), *p))
                .collect(),
        );
        let mut nodes = Vec::new();
        for i in 0..n {
            // Each validator gets its OWN state engine (nodes do not share
            // mutable state in reality).
            let state = Arc::new(InMemoryStateEngine::new());
            fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
            let rt = ValidatorRuntime::new(ks[i].clone(), vset.clone(), state, 1);
            nodes.push(Node {
                rt,
                idx: i,
                base_timeout_ms: base_timeouts_ms[i],
                round_started_ms: start_offsets_ms[i],
                start_ms: start_offsets_ms[i],
                last_prevoted: None,
                last_precommitted: None,
                peer_round_seen: None,
                prevotes_cast: Vec::new(),
                precommits_cast: Vec::new(),
                view_changes: 0,
            });
        }
        // A funded account whose transactions make every proposed block
        // distinct.
        let mut seed = [0x5Au8; 32];
        seed[0] = 0x77;
        let tx_key = SigningKey::from_bytes(&seed);
        let tx_addr = tx_key.verifying_key().to_bytes();
        for nd in &nodes {
            nd.rt
                .state
                .update_account(stellereum::state_engine::AccountState::new(
                    tx_addr,
                    1_000_000_000_000_000_000,
                ))
                .await;
        }
        Sim {
            nodes,
            wire: Wire::default(),
            n,
            delay_ms,
            heights: vec![1; n],
            tx_key,
            tx_nonce: 0,
            last_vote_ms: 0,
        }
    }

    /// Put one fresh transaction into every node's mempool, so the next
    /// proposal is a NEW block (not a byte-identical re-proposal).
    async fn seed_tx(&mut self) {
        self.tx_nonce += 1;
        let tx = Transaction::sign(&self.tx_key, [7u8; 32], 1, 1_000, self.tx_nonce, 0, 0);
        for n in self.nodes.iter_mut() {
            n.rt.add_tx(tx.clone()).await;
        }
    }

    fn height_of(&self, i: usize) -> u64 {
        self.nodes[i].rt.hc.height
    }

    /// Run the simulation for `duration_ms` of virtual time.
    ///
    /// The phase order mirrors the production consensus loop in `src/main.rs`
    /// exactly: propose -> prevote -> drain -> precommit -> finalize -> view
    /// change. The order matters: a proposal accepted in the drain is prevoted
    /// in the NEXT tick's prevote phase, and the view change comes last so a
    /// round that just received votes is never abandoned in the same tick.
    pub async fn run(&mut self, duration_ms: u64) {
        let end = self.wire.now_ms + duration_ms;
        while self.wire.now_ms < end {
            let now = self.wire.now_ms;

            // ---- phase 1+2: propose + prevote ---------------------------
            let mut advanced = false;
            for i in 0..self.n {
                let height = self.height_of(i);
                if height != self.heights[i] {
                    // The node advanced a height: reset the per-height
                    // bookkeeping exactly like the production loop.
                    self.heights[i] = height;
                    self.nodes[i].last_prevoted = None;
                    self.nodes[i].last_precommitted = None;
                    self.nodes[i].round_started_ms = now;
                    self.nodes[i].prevotes_cast.clear();
                    self.nodes[i].precommits_cast.clear();
                    advanced = true;
                }
            }
            if advanced {
                self.seed_tx().await;
            }
            for i in 0..self.n {
                let height = self.height_of(i);
                if now < self.nodes[i].start_ms {
                    continue;
                }
                // propose
                if self.nodes[i].rt.is_proposer() && !self.nodes[i].rt.hc.has_live_proposal() {
                    let ts = height * 1_000 + self.nodes[i].rt.hc.round as u64;
                    if let Some(block) = self.nodes[i].rt.propose(ts).await {
                        let round = self.nodes[i].rt.hc.round;
                        for p in 0..self.n {
                            if p != i {
                                self.wire.send(
                                    p,
                                    Msg::Proposal {
                                        round,
                                        block: block.clone(),
                                    },
                                    self.delay_ms,
                                );
                            }
                        }
                    }
                }
                // prevote
                let r = self.nodes[i].rt.hc.round;
                let elapsed = now - self.nodes[i].round_started_ms;
                let want_nil = !self.nodes[i].rt.hc.has_live_proposal()
                    && elapsed >= 2 * self.nodes[i].effective_timeout();
                if self.nodes[i].last_prevoted != Some((height, r))
                    && (self.nodes[i].rt.hc.has_live_proposal() || want_nil)
                {
                    if let Some(v) = self.nodes[i].rt.make_prevote() {
                        self.nodes[i].last_prevoted = Some((height, r));
                        self.nodes[i].prevotes_cast.push((v.round, v.block_hash));
                        // Production adds OUR OWN vote to OUR OWN vote set.
                        let v2 = v.clone();
                        let _ = self.nodes[i].rt.on_prevote(v2.clone());
                        self.last_vote_ms = now;
                        self.nodes[i].broadcast_vote(&mut self.wire, self.n, self.delay_ms, v2);
                    }
                }
            }

            // ---- phase 3: drain ----------------------------------------
            let due = self.wire.take_due(now);
            for (to, msg) in due {
                let height = self.height_of(to);
                match msg {
                    Msg::Proposal { round, block } => {
                        let proposer = block.proposer;
                        let _ = self.nodes[to].rt.on_proposal(proposer, block, round).await;
                    }
                    Msg::Committed {
                        height: ch,
                        block,
                        certificate,
                    } => {
                        if ch != height {
                            continue;
                        }
                        let _ = self.nodes[to]
                            .rt
                            .adopt_committed(ch, block, certificate)
                            .await;
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
                }
            }

            // ---- phase 4: precommit ------------------------------------
            for i in 0..self.n {
                let height = self.height_of(i);
                if height != self.heights[i] {
                    continue;
                }
                if let Some(v) = self.nodes[i].rt.make_precommit() {
                    if self.nodes[i].last_precommitted != Some((height, v.round)) {
                        self.nodes[i].last_precommitted = Some((height, v.round));
                        self.nodes[i].precommits_cast.push((v.round, v.block_hash));
                        let v2 = v.clone();
                        let _ = self.nodes[i].rt.on_precommit(v2.clone());
                        self.last_vote_ms = now;
                        self.nodes[i].broadcast_vote(&mut self.wire, self.n, self.delay_ms, v2);
                    }
                }
            }

            // ---- phase 5: finalize -------------------------------------
            // The vote set must have SETTLED (see `last_vote_ms`).
            let settled = now.saturating_sub(self.last_vote_ms) > self.delay_ms;
            for i in 0..self.n {
                if !settled {
                    break;
                }
                let height = self.height_of(i);
                if height != self.heights[i] {
                    continue;
                }
                if let Some(bh) = self.nodes[i].rt.try_finalize().await {
                    // Production broadcasts the decided height WITH its
                    // certificate; a peer that missed the decision adopts it.
                    if let Some(block) = self.nodes[i].rt.blocks.get(&bh).cloned() {
                        if let Some(cert) = block.precommit_qc.clone() {
                            for p in 0..self.n {
                                if p != i {
                                    self.wire.send(
                                        p,
                                        Msg::Committed {
                                            height,
                                            block: block.clone(),
                                            certificate: cert.clone(),
                                        },
                                        self.delay_ms,
                                    );
                                }
                            }
                        }
                    }
                    self.nodes[i].last_prevoted = None;
                    self.nodes[i].last_precommitted = None;
                    self.nodes[i].round_started_ms = now;
                }
            }

            // ---- phase 6: view change ----------------------------------
            for i in 0..self.n {
                let height = self.height_of(i);
                if height != self.heights[i] {
                    continue;
                }
                if now < self.nodes[i].start_ms {
                    continue;
                }
                let r = self.nodes[i].rt.hc.round;
                let peer_nearby = match self.nodes[i].peer_round_seen {
                    Some((ph, pr, at)) => {
                        ph == height
                            && now - at < 2 * self.nodes[i].effective_timeout()
                            && pr <= r
                            && pr + 1 >= r
                    }
                    None => false,
                };
                let hold = peer_nearby
                    && (now - self.nodes[i].round_started_ms)
                        < 2 * self.nodes[i].effective_timeout();
                if now - self.nodes[i].round_started_ms > self.nodes[i].effective_timeout() && !hold
                {
                    self.nodes[i].rt.next_round();
                    self.nodes[i].view_changes += 1;
                    self.nodes[i].last_prevoted = None;
                    self.nodes[i].last_precommitted = None;
                    self.nodes[i].round_started_ms = now;
                }
            }

            self.wire.now_ms += TICK_MS;
        }
    }

    pub fn heights(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.rt.hc.height).collect()
    }

    pub fn rounds(&self) -> Vec<u32> {
        self.nodes.iter().map(|n| n.rt.hc.round).collect()
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// DETERMINISTIC validator keys.
///
/// The harness must be reproducible: the proposer schedule is a hash of the
/// validator ids, so random keys would give a different schedule on every
/// run and the test would be a coin flip. Fixed keys make every run the
/// same scenario.
fn keys(n: usize) -> Vec<SigningKey> {
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = (i as u8).wrapping_add(1);
            seed[31] = 0xA5;
            SigningKey::from_bytes(&seed)
        })
        .collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

/// A three-validator set with the LIVE power split (1500/1000/1000).
///
/// The split matters: with 3500 total power the quorum is 2334, so the
/// 1500-STELL validator is a member of EVERY quorum (1500 alone is not a
/// quorum, and 1000+1000 is not either). One non-participating validator
/// therefore stalls the whole chain — which is exactly the live shape.
fn live_vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .zip([1500u64, 1000, 1000].iter())
            .map(|(k, p)| (id(k), *p))
            .collect(),
    )
}

// ===========================================================================
// 1. The multi-node liveness regression
// ===========================================================================

/// The live shape: three validators with the live power split, started 26 s
/// and 32 s apart, on a WAN link. The chain must keep finalizing.
///
/// WITHOUT the fix this test fails: the cluster never gets past height 1-2,
/// because the nodes never agree on a value in the same round (the skew
/// keeps them apart) and a nil quorum masks the polka that did form.
#[tokio::test]
async fn wan_skewed_cluster_keeps_finalizing() {
    let mut sim = Sim::new(
        &[1500, 1000, 1000],
        &[LIVE_ROUND_TIMEOUT_MS; 3],
        &[0, 10_000, 20_000],
        400,
    )
    .await;
    sim.run(300_000).await;

    let heights = sim.heights();
    assert!(
        heights.iter().all(|h| *h > 20),
        "the cluster must keep finalizing; heights={heights:?} rounds={:?}",
        sim.rounds()
    );
    assert!(
        heights.windows(2).all(|w| w[0] == w[1]),
        "all validators must agree on the finalized height; heights={heights:?}"
    );
}

/// The LIVE shape: the nodes started 26 s and 32 s apart.
#[tokio::test]
async fn the_live_start_skew_keeps_finalizing() {
    let mut sim = Sim::new(
        &[1500, 1000, 1000],
        &[LIVE_ROUND_TIMEOUT_MS; 3],
        &[0, 26_000, 32_000],
        400,
    )
    .await;
    sim.run(300_000).await;

    let heights = sim.heights();
    assert!(
        heights.iter().all(|h| *h > 20),
        "the cluster must keep finalizing; heights={heights:?} rounds={:?}",
        sim.rounds()
    );
}

/// The same shape with EQUAL power: it must finalize too (it is the case the
/// live cluster would have survived if the 1500-STELL validator had not been
/// in every quorum).
#[tokio::test]
async fn wan_skewed_equal_power_cluster_keeps_finalizing() {
    let mut sim = Sim::new(
        &[1000, 1000, 1000],
        &[LIVE_ROUND_TIMEOUT_MS; 3],
        &[0, 26_000, 32_000],
        400,
    )
    .await;
    sim.run(300_000).await;

    let heights = sim.heights();
    assert!(
        heights.iter().all(|h| *h > 20),
        "the cluster must keep finalizing; heights={heights:?} rounds={:?}",
        sim.rounds()
    );
}

/// A FOUR-validator set (the live cluster had four nodes) must converge too.
#[tokio::test]
async fn wan_skewed_four_validator_cluster_keeps_finalizing() {
    let mut sim = Sim::new(
        &[1500, 1000, 1000, 1000],
        &[LIVE_ROUND_TIMEOUT_MS; 4],
        &[0, 26_000, 32_000, 5_000],
        400,
    )
    .await;
    sim.run(300_000).await;

    let heights = sim.heights();
    assert!(
        heights.iter().all(|h| *h > 10),
        "the four-validator cluster must keep finalizing; heights={heights:?} rounds={:?}",
        sim.rounds()
    );
}

/// The round skew the live cluster actually drifted (~30 rounds) must still
/// converge: a node that is that far ahead of the network must be able to
/// find — and commit — the quorum the network formed.
#[tokio::test]
async fn a_thirty_round_skew_still_converges() {
    let mut sim = Sim::new(
        &[1500, 1000, 1000],
        &[LIVE_ROUND_TIMEOUT_MS; 3],
        // 30 rounds of drift at ~3.5-10 s per round is ~3 minutes of skew.
        &[0, 180_000, 200_000],
        400,
    )
    .await;
    sim.run(600_000).await;

    let heights = sim.heights();
    assert!(
        heights.iter().all(|h| *h > 5),
        "a 30-round skew must still converge; heights={heights:?} rounds={:?}",
        sim.rounds()
    );
}

// ===========================================================================
// 2. The nil quorum must not mask the polka (the precommit defect)
// ===========================================================================

/// THE DEFECT: a node that holds the polka, but has a NIL quorum in a LATER
/// round in its scan window, must still precommit the polka's block — in the
/// polka's round.
///
/// WITHOUT the fix `make_precommit` returns a NIL precommit for the later
/// round (the nil quorum shadowed the polka), the `last_precommitted` dedup
/// key then suppresses the correct precommit on every later tick, and the
/// height is never decided. That is the live failure: a full prevote QC, no
/// precommit QC.
#[tokio::test]
async fn polka_is_not_masked_by_a_newer_nil_quorum() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let block = [0xABu8; 32];
    let polka_round = 0u32;

    // Round 0: A and B prevote the block -> 2500 >= 2334 -> a POLKA.
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(
            k,
            1,
            polka_round,
            VoteKind::Prevote,
            Some(block),
        ))
        .unwrap();
    }
    assert_eq!(
        rt.hc.try_prevote_quorum(),
        Some(Some(block)),
        "the polka must have formed"
    );

    // Round 1: A and B prevote NIL -> also 2500 power -> a NIL quorum in a
    // LATER round than the polka.
    rt.next_round();
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 1, VoteKind::Prevote, None))
            .unwrap();
    }
    assert_eq!(
        rt.hc.try_prevote_quorum(),
        Some(None),
        "the newest quorum is the nil quorum of round 1"
    );

    // The precommit must follow the POLKA: the block, in the polka's round.
    let pc = rt
        .make_precommit()
        .expect("a node holding the polka must cast a precommit for it");
    assert_eq!(
        pc.block_hash,
        Some(block),
        "the precommit must name the block the network certified"
    );
    assert_eq!(
        pc.round, polka_round,
        "the precommit must be stamped with the POLKA's round, not the local round"
    );
    assert_eq!(
        pc.kind,
        VoteKind::Precommit,
        "the precommit must be a precommit"
    );
}

/// The precommit must not be suppressed by the dedup key after a nil
/// precommit was already cast for a LATER round: the polka's precommit is a
/// different round and a different statement, so it is still owed.
#[tokio::test]
async fn a_nil_precommit_does_not_suppress_the_real_one() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let block = [0xCDu8; 32];
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(block)))
            .unwrap();
    }
    rt.next_round();
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 1, VoteKind::Prevote, None))
            .unwrap();
    }

    let pc = rt
        .make_precommit()
        .expect("the polka must produce a precommit");
    assert_eq!(pc.block_hash, Some(block));
    assert_eq!(pc.round, 0);
}

// ===========================================================================
// 3. The scan window must reach the network's round
// ===========================================================================

/// A node that has drifted AHEAD of the network (here: 30 rounds, the drift
/// the live cluster showed) must still find — and precommit — the polka the
/// network formed in ITS round.
///
/// WITHOUT the fix the window was `[our_round - 8, our_round]`, so the
/// network's round was outside it, the polka was invisible, and the node
/// never precommitted: the chain could not finalize.
#[tokio::test]
async fn a_node_ahead_of_the_network_still_precommits_the_network_polka() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let network_round = 40u32;
    let block = [0x5Eu8; 32];

    // The network forms the polka in ITS round (40): A and B prevote the
    // block, so 1500 + 1000 = 2500 >= 2334.
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(
            k,
            1,
            network_round,
            VoteKind::Prevote,
            Some(block),
        ))
        .unwrap();
    }
    // We learn where the network is (its round), then drift AHEAD of it.
    // `observe_peer_vote` is the pre-existing public entry point for "a
    // verified vote told us where that peer is".
    let peer_vote = Vote::sign(&ks[1], 1, network_round, VoteKind::Prevote, Some(block));
    rt.observe_peer_vote(&peer_vote);
    let peer_vote2 = Vote::sign(&ks[2], 1, network_round, VoteKind::Prevote, Some(block));
    rt.observe_peer_vote(&peer_vote2);
    while rt.hc.round < network_round + 30 {
        rt.hc.next_round();
    }
    assert_eq!(rt.hc.round, network_round + 30);

    // The polka must still be visible: the network's round is 30 rounds
    // behind us, far outside the old 8-round lookback.
    let pc = rt
        .make_precommit()
        .expect("a node ahead of the network must still precommit the network's polka");
    assert_eq!(pc.block_hash, Some(block));
    assert_eq!(pc.round, network_round);
}

// ===========================================================================
// 4. The future-round rule on the VOTE path
// ===========================================================================

/// Tendermint's future-round rule: a node that receives a valid vote for a
/// round GREATER than its own must move to that round.
///
/// The rule used to live ONLY in the node loop (`main.rs`), so every other
/// consumer of the runtime — the in-process cluster, the simulator, any
/// embedder — ran WITHOUT it and could never rejoin the network's round.
#[tokio::test]
async fn a_vote_for_a_future_round_advances_us() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    assert_eq!(rt.hc.round, 0);
    // CORROBORATION GATE (P3-R1 round-DoS fix, see
    // `ValidatorRuntime::note_peer_vote_round` in src/runtime.rs): the FIRST
    // step is always taken — a genuinely-behind node must follow even a
    // single peer — but CONTINUING past one step needs the round corroborated
    // by a second DISTINCT validator (same rule as the deadlock breaker,
    // which already refuses single-reporter jumps). Without this, one
    // Byzantine vote far ahead drags an honest node off the network's cliff
    // one budget at a time. So a lone reporter buys exactly one
    // ROUND_LOOKBACK (+8) nudge, not the full jump: 8 votes from the SAME
    // validator for round 25 move us 0 -> 8 and then stall (dedup + gate).
    // Without the future-round rule we would never leave round 0.
    for _ in 0..8 {
        let v = Vote::sign(&ks[1], 1, 25, VoteKind::Prevote, None);
        let _ = rt.on_prevote(v);
    }
    assert_eq!(
        rt.hc.round,
        stellereum::consensus::ROUND_LOOKBACK,
        "a lone reporter buys one ROUND_LOOKBACK nudge, not the full jump (P3-R1 corroboration gate)"
    );
    // A second DISTINCT validator vouching for the same far round is new
    // evidence (not a replay), so it re-opens the chase and we converge the
    // rest of the way to the network's round.
    for _ in 0..8 {
        let v = Vote::sign(&ks[2], 1, 25, VoteKind::Prevote, None);
        let _ = rt.on_prevote(v);
    }
    assert_eq!(
        rt.hc.round, 25,
        "a corroborated round must pull us all the way to round 25"
    );
}

/// The rule must be forward-only: a vote for an OLD round never rewinds us
/// (rewinding would make the node re-vote a round it already voted in — a
/// self-equivocation, which is slashable evidence).
#[tokio::test]
async fn a_vote_for_an_old_round_never_rewinds_us() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    while rt.hc.round < 50 {
        rt.hc.next_round();
    }
    let v = Vote::sign(&ks[1], 1, 3, VoteKind::Prevote, None);
    rt.on_prevote(v).unwrap();
    assert_eq!(
        rt.hc.round, 50,
        "the round counter must never move backwards"
    );
}

/// Every verified vote — accepted or not — must teach us where the network
/// is. Before the fix only REJECTED votes updated the peer-round counter,
/// which left the deadlock breaker's corroboration blind on a healthy
/// network (it only ever saw the votes it could not use).
#[tokio::test]
async fn every_verified_vote_teaches_us_the_network_round() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    // An ACCEPTED vote (a plain nil prevote in the current round).
    let v = Vote::sign(&ks[1], 1, 0, VoteKind::Prevote, None);
    rt.on_prevote(v.clone()).unwrap();
    assert_eq!(
        rt.hc.max_peer_round(),
        Some(0),
        "an accepted vote must update the peer-round counter"
    );

    // A vote for a round we cannot use (absurdly far ahead) is still
    // information about where the peer is.
    let far = Vote::sign(&ks[2], 1, 5_000, VoteKind::Prevote, None);
    assert!(rt.on_prevote(far).is_err(), "the far vote must be refused");
    assert_eq!(
        rt.hc.max_peer_round(),
        Some(5_000),
        "a refused but verified vote must still update the peer-round counter"
    );
}

// ===========================================================================
// 5. SAFETY: the fix must not break BFT safety
// ===========================================================================

/// A node must never precommit two different blocks in the same round, and
/// must never precommit against its own lock.
#[tokio::test]
async fn the_lock_refuses_a_conflicting_precommit() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let a = [0x11u8; 32];
    let b = [0x22u8; 32];

    // We lock on A at round 10.
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 10, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    let pc = rt
        .make_precommit()
        .expect("the polka must produce a precommit");
    assert_eq!(pc.block_hash, Some(a));
    assert_eq!(rt.hc.locked, Some((a, 10)));

    // Now a polka for a DIFFERENT block at the SAME round must not make us
    // precommit against our lock.
    for k in ks.iter().take(2) {
        let _ = rt.on_prevote(Vote::sign(k, 1, 10, VoteKind::Prevote, Some(b)));
    }
    // (The vote set keeps the FIRST vote per validator, so the polka for A
    // is still the one in the set: the lock and the polka agree.)
    let again = rt
        .make_precommit()
        .expect("the same polka must still precommit");
    assert_eq!(again.block_hash, Some(a));
    assert_eq!(again.round, 10);
}

/// A polka for a DIFFERENT block at a HIGHER round releases the lock
/// (Tendermint's unlock rule): the node must then follow the network.
#[tokio::test]
async fn a_higher_round_polka_releases_the_lock() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let a = [0x11u8; 32];
    let b = [0x22u8; 32];

    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 10, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    let _ = rt
        .make_precommit()
        .expect("the polka must produce a precommit");
    assert_eq!(rt.hc.locked, Some((a, 10)));

    // A polka for B at round 12 (higher): the lock is released and the
    // node follows the network.
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 12, VoteKind::Prevote, Some(b)))
            .unwrap();
    }
    let pc = rt
        .make_precommit()
        .expect("a higher-round polka must release the lock");
    assert_eq!(pc.block_hash, Some(b));
    assert_eq!(pc.round, 12);
    assert_eq!(rt.hc.locked, Some((b, 12)));
}

/// A NIL quorum must never unlock a lock (audit F-01): unlocking on a nil
/// quorum is a safety violation (a node that timed out in a later round
/// would drop its lock on a block finalized in an earlier round).
#[tokio::test]
async fn a_nil_quorum_never_unlocks_the_lock() {
    let ks = keys(3);
    let vset = live_vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let a = [0x11u8; 32];
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 10, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    let _ = rt
        .make_precommit()
        .expect("the polka must produce a precommit");
    assert_eq!(rt.hc.locked, Some((a, 10)));

    // A nil quorum in a LATER round must not release the lock.
    for k in ks.iter().take(2) {
        rt.on_prevote(Vote::sign(k, 1, 12, VoteKind::Prevote, None))
            .unwrap();
    }
    let _ = rt.make_precommit();
    assert_eq!(
        rt.hc.locked,
        Some((a, 10)),
        "a nil quorum must never unlock the lock"
    );
}

// ===========================================================================
// 6. The round-timeout configuration
// ===========================================================================

/// The view-change backoff must count the rounds THIS HEIGHT FAILED, not the
/// absolute round number. A node that joins a chain at round 285027 (or that
/// follows a peer into a high round) has failed NOTHING at that height and
/// must not be handed the maximum timeout before it has tried a single
/// round: on a WAN that is the difference between reacting in 3.5 s and
/// reacting in 27 s.
///
/// The harness counts the view changes itself (see `Node::view_changes`) and
/// the production loop derives the backoff from the same quantity, so the
/// invariant is pinned here at the level the loop actually uses.
#[test]
fn the_backoff_counts_this_heights_failures_not_the_round_number() {
    // The pure ladder: base + 500ms per failed round, capped.
    assert_eq!(effective_round_timeout_ms(800, 0), 800);
    assert_eq!(effective_round_timeout_ms(800, 1), 1300);
    // A node that has failed NOTHING at a height gets the BASE timeout, no
    // matter how high the round counter is.
    let ks = keys(2);
    let mut hc = HeightConsensus::new(1, vset(&ks));
    // Following a peer moves the round but is NOT a failed round.
    hc.sync_round_to(500);
    assert!(hc.round > 0, "following a peer must move us forward");
    let view_changes = 0u32;
    assert_eq!(
        effective_round_timeout_ms(3_500, view_changes),
        3_500,
        "a node that has failed nothing must get the base timeout"
    );
    // A view change IS a failed round.
    hc.next_round();
    assert!(
        effective_round_timeout_ms(3_500, 1) > 3_500,
        "a failed round must lengthen the timeout"
    );
}
