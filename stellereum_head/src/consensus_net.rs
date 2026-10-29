//! Consensus P2P transport: carries proposals and votes between validators over
//! the infnode pubsub layer — WITHOUT modifying infnode.
//!
//! Design (per the "blockchain stays outside infnode" rule):
//!  - infnode is used only through its public API:
//!      * `register_app_sub(topic)` to receive app-level messages
//!      * `request_to(peer, "pubsub.publish", {topic,data})` to broadcast
//!  - Messages are an enum serialized with bincode and hex-encoded into `data`.
//!
//! Security: every inbound message is size-checked and bincode-decoded; malformed
//! or oversized payloads are rejected. Vote signatures are verified downstream by
//! the consensus engine, so a forged vote is dropped there.

use crate::consensus::{QuorumCertificate, Vote, VoteKind};
use crate::network::P2pNetworkAdapter;
use crate::sharding::{Block, ShardRegistry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Base name for the pubsub topic carrying consensus traffic.
///
/// The live topic appends the chain epoch, because pubsub is NOT isolated by the
/// blob epoch: a topic is a name peers subscribe to, and messages published under it
/// are relayed across the overlay. Observed live: after wiping both data directories
/// and starting a NEW genesis, nodes were still receiving `#1 r10071` proposals and
/// old state roots from the previous chain, because the previous run's votes and
/// proposals were still being relayed under the fixed topic name. A node then rejects
/// them ("wrong height", "state root ... does not match") forever, which looks exactly
/// like a consensus bug and is really a namespace leak.
///
/// Scoping the topic to the epoch means a node only ever hears its own chain's
/// consensus traffic.
pub const CONSENSUS_TOPIC_BASE: &str = "stellereum/consensus/v1";

/// Pubsub topic carrying transaction gossip. Also epoch-scoped; see
/// [`CONSENSUS_TOPIC_BASE`].
pub const TX_TOPIC_BASE: &str = "stellereum/tx/v1";

/// The consensus topic for a chain epoch.
pub fn consensus_topic(epoch: &str) -> String {
    format!("{CONSENSUS_TOPIC_BASE}/{epoch}")
}

/// The consensus topic for one shard of a multi-shard process.
///
/// Two shards can share one infnode node and one chain epoch (the epoch is
/// derived from the shard-0 genesis so both instances agree on the P2P
/// namespace), so the topic MUST carry the shard id as well or the two
/// consensus instances would hear each other's proposals and votes. Kept
/// additive: the single-shard topic above is byte-for-byte unchanged.
pub fn consensus_topic_for_shard(epoch: &str, shard_id: u32) -> String {
    format!("{CONSENSUS_TOPIC_BASE}/{epoch}/shard/{shard_id}")
}

/// The transaction-gossip topic for a chain epoch.
pub fn tx_topic(epoch: &str) -> String {
    format!("{TX_TOPIC_BASE}/{epoch}")
}

/// Max accepted consensus message size (matches infnode's frame cap of 32 MiB).
pub const MAX_CONSENSUS_MSG: usize = 32 * 1024 * 1024;

/// Max accepted transaction gossip message size (a single tx is small).
pub const MAX_TX_MSG: usize = 1024 * 1024;

/// Max consensus messages carried in one batch (P3-H4 gossip batching).
pub const MAX_BATCH_ITEMS: usize = 32;

/// Max encoded bytes of a single batch (P3-H4 gossip batching).
pub const MAX_BATCH_BYTES: usize = 512 * 1024;

/// A broadcast sub-stage slower than this is logged at WARN (rate-limited);
/// anything faster is logged at DEBUG. The point is to name the slow stage
/// (encode vs `request_to`) instead of only the aggregate broadcast time.
pub const SUBTIMING_WARN_MS: u128 = 200;

/// Minimum gap between two WARN lines from the same sub-timing call site, so a
/// persistently slow transport cannot flood the log.
pub const SUBTIMING_WARN_MIN_GAP_MS: u64 = 1000;

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pure rate-limit decision, split out so it is testable with a synthetic clock.
/// Successful (allowed) calls stamp `gate` with `now_ms`.
fn warn_allowed(gate: &AtomicU64, now_ms: u64) -> bool {
    let last = gate.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= SUBTIMING_WARN_MIN_GAP_MS {
        gate.store(now_ms, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Log one broadcast sub-stage. WARN above [`SUBTIMING_WARN_MS`] (at most once
/// per [`SUBTIMING_WARN_MIN_GAP_MS`] per `gate`), DEBUG otherwise. `gate` is a
/// per-call-site last-WARN epoch-ms (a `static AtomicU64`).
pub fn log_stage(gate: &AtomicU64, site: &str, detail: &str, took: std::time::Duration) {
    if took.as_millis() >= SUBTIMING_WARN_MS {
        if warn_allowed(gate, epoch_ms()) {
            tracing::warn!(
                "[consensus][subtiming] {site} {detail} took {took:?} (>{SUBTIMING_WARN_MS}ms)"
            );
        }
    } else {
        tracing::debug!("[consensus][subtiming] {site} {detail} took {took:?}");
    }
}

/// Maximum number of drained chunks that may wait in the background broadcast
/// sender before the flush stops draining and applies backpressure (the rest
/// stay in the consensus outbox and are retried/still deduplicated next tick).
/// Bounds memory if the transport is wedged without ever dropping a message.
pub const MAX_PENDING_CHUNKS: usize = 256;

/// Coalescing window for duplicate vote sends (tail-killer, send side).
///
/// The loop re-enqueues the same vote from three paths (periodic retransmit,
/// view-change re-send, timer flush) within ~100-400ms of each other. The
/// outbox dedups only while items are still queued; once a chunk is handed to
/// the background sender a re-enqueue becomes a second wire copy, which is the
/// 3-4x duplicate RX seen live. Suppressing an identical vote re-send inside
/// this window coalesces those copies. It is deliberately SHORTER than the
/// retransmit cadence (`max(150ms, timeout/2)` = 400ms at the live 800ms
/// timeout): a vote lost in transit is still retried on schedule, only the
/// same-tick duplicates collapse.
pub const VOTE_SEND_DEDUP_TTL_MS: u64 = 200;

/// A vote is superseded once we are two rounds past it: a prevote/precommit
/// for round r at height h can never contribute to a quorum once the node is
/// at (h, r+2), because quorums form per (height, round) and the network has
/// moved on. Dropping such votes under pressure is safe; proposals, commits
/// and finalized artifacts are NEVER droppable (a commit is the only proof a
/// lagging peer learns the outcome from).
pub const SUPERSEDED_ROUND_LAG: u32 = 2;

/// Wire identity of one cast vote: (height, round, kind, voter).
pub type VoteWireKey = (u64, u32, u8, [u8; 32]);

fn vote_kind_tag(kind: VoteKind) -> u8 {
    match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    }
}

/// The wire key of a vote message, or `None` for proposals/commits/batches
/// (never deduped, never dropped).
pub fn vote_wire_key(msg: &ConsensusMsg) -> Option<VoteWireKey> {
    match msg {
        ConsensusMsg::Vote { vote, .. } => Some((
            vote.height,
            vote.round,
            vote_kind_tag(vote.kind),
            vote.voter,
        )),
        _ => None,
    }
}

/// True when `msg` is a vote that is superseded at `(height, round)`: same
/// height, and its round is at least [`SUPERSEDED_ROUND_LAG`] behind. Never
/// true for proposals, commits, or batches.
pub fn is_superseded_vote(msg: &ConsensusMsg, height: u64, round: u32) -> bool {
    match msg {
        ConsensusMsg::Vote { vote, .. } => {
            vote.height == height
                && vote.round.saturating_add(SUPERSEDED_ROUND_LAG) <= round
        }
        _ => false,
    }
}

/// Coalesce one send batch: drop superseded votes for `(height, round)` and
/// collapse duplicate votes to their first occurrence, preserving order.
/// Proposals, commits and batches pass through untouched (order included).
pub fn coalesce_for_send(
    msgs: Vec<ConsensusMsg>,
    height: u64,
    round: u32,
) -> Vec<ConsensusMsg> {
    let mut seen: std::collections::HashSet<VoteWireKey> =
        std::collections::HashSet::new();
    msgs.into_iter()
        .filter(|m| {
            if is_superseded_vote(m, height, round) {
                return false;
            }
            match vote_wire_key(m) {
                Some(k) => seen.insert(k),
                None => true,
            }
        })
        .collect()
}

/// Retransmit interval for the current round: `max(150ms, timeout/2)`,
/// doubling for every full round-timeout elapsed, capped at `2 * timeout`.
///
/// The old fixed cadence re-sent at full rate no matter how long a round had
/// been stuck, so a wedged round amplified into a retry storm on top of the
/// 2s TIMEOUTs. Backing off while stuck keeps loss recovery (the first
/// retries still fire at the fast cadence) without the thunder.
pub fn retransmit_interval_ms(round_timeout_ms: u64, elapsed_ms: u64) -> u64 {
    let base = (round_timeout_ms / 2).max(150);
    let cap = round_timeout_ms.saturating_mul(2).max(base);
    let doublings = elapsed_ms / round_timeout_ms.max(1);
    let shifted = base.saturating_mul(1u64 << doublings.min(2));
    shifted.min(cap)
}

/// Send-time dedup of identical votes across flushes (the outbox dedup only
/// covers still-queued items). Non-votes always pass. Pure + time-injected so
/// the window is testable without a clock.
pub struct VoteSendFilter {
    ttl: Duration,
    sent: HashMap<VoteWireKey, Instant>,
}

impl VoteSendFilter {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, sent: HashMap::new() }
    }

    /// True when `msg` may go on the wire now. Records the send; an identical
    /// vote sent within `ttl` is suppressed (coalesced).
    pub fn should_send(&mut self, msg: &ConsensusMsg, now: Instant) -> bool {
        let Some(key) = vote_wire_key(msg) else {
            return true;
        };
        // Opportunistic expiry: the map holds at most a few keys (one per
        // vote we cast per round), so a linear sweep on insert is trivial.
        self.sent.retain(|_, at| now.duration_since(*at) < self.ttl);
        if self.sent.contains_key(&key) {
            return false;
        }
        self.sent.insert(key, now);
        true
    }
}

/// Rate-limit state for the encode sub-stage (one per batch).
static ENCODE_STAGE_GATE: AtomicU64 = AtomicU64::new(0);
/// Rate-limit state for the per-peer `request_to` sub-stage.
static REQUEST_STAGE_GATE: AtomicU64 = AtomicU64::new(0);
/// Rate-limit state for the whole background flush (one per chunk).
static FLUSH_STAGE_GATE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    /// A proposer's block proposal for (height, round).
    Proposal { height: u64, round: u32, block: Block },
    /// A prevote or precommit. `locked` carries the sender's locked block hash,
    /// and is Some ONLY on nil prevotes cast because of a lock (validRound-lite):
    /// it tells the block's author "I am stuck on YOUR body, re-propose it at
    /// your slot and we converge". Never set on block votes or precommits, so
    /// persisted quorum certificates stay hintless and byte-compatible.
    /// Wire-only (gossip, never persisted): both sides upgrade together.
    Vote { vote: Vote, locked: Option<[u8; 32]> },
    /// A block this node has committed (precommit quorum reached), together with
    /// the certificate that proves it.
    ///
    /// Without this a peer that missed the last vote of a round never learns the
    /// outcome: it sits in a different round, keeps proposing blocks the rest of
    /// the network rejects as "wrong height", and the chain is stuck there. The
    /// commit broadcast is what lets a lagging node catch up in place instead of
    /// only at restart.
    Committed {
        height: u64,
        block: Block,
        certificate: QuorumCertificate,
    },
    /// A batch of consensus messages gossiped together (P3-H4).
    ///
    /// Batching amortizes one `request_to` per peer over up to
    /// [`MAX_BATCH_ITEMS`] messages / [`MAX_BATCH_BYTES`] bytes. Batches
    /// never nest: an inner `Batch` is rejected on decode.
    Batch(Vec<ConsensusMsg>),
}

/// True when a single message is large enough to flush the gossip outbox
/// immediately instead of waiting for the batch timer (P3-H4).
pub fn is_large(msg: &ConsensusMsg) -> bool {
    msg.is_large()
}

/// True when a consensus message must bypass the peer failure-cooldown skip.
///
/// Only [`ConsensusMsg::Committed`] qualifies: it is the cheap live path a
/// lagging node catches up through (full block + QC, no DHT work), so it must
/// not starve for the 60s [`PEER_SKIP_COOLDOWN`]. Votes and proposals stay
/// skippable — retrying them at a dead peer only pays the 2s join tax again.
pub fn committed_bypasses_skip(msg: &ConsensusMsg) -> bool {
    matches!(msg, ConsensusMsg::Committed { .. })
}

/// True when a batch carries the live catch-up path (any member bypasses).
fn batch_bypasses_skip(msgs: &[ConsensusMsg]) -> bool {
    msgs.iter().any(committed_bypasses_skip)
}

 /// Encode `items` as one [`ConsensusMsg::Batch`] (P3-H4).
pub fn batch_encode(items: &[ConsensusMsg]) -> Result<Vec<u8>, String> {
    ConsensusMsg::batch_encode(items)
}

impl ConsensusMsg {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("consensus msg encode: {e}"))
    }

    /// Validate a decoded batch: non-empty, bounded count/size, never nested.
    fn check_batch(items: &[ConsensusMsg], outer_len: usize) -> Result<(), String> {
        if items.is_empty() {
            return Err("empty consensus batch".to_string());
        }
        if items.len() > MAX_BATCH_ITEMS {
            return Err(format!("consensus batch too many items: {}", items.len()));
        }
        if outer_len > MAX_BATCH_BYTES {
            return Err(format!("consensus batch too large: {outer_len} bytes"));
        }
        if items.iter().any(|m| matches!(m, ConsensusMsg::Batch(_))) {
            return Err("nested consensus batch".to_string());
        }
        Ok(())
    }

    /// True when this message should flush the gossip outbox immediately.
    /// Proposals and commits carry full block bodies, so they always flush;
    /// anything else flushes only when its encoding is big (>= 64 KiB).
    pub fn is_large(&self) -> bool {
        match self {
            ConsensusMsg::Proposal { .. } | ConsensusMsg::Committed { .. } => true,
            ConsensusMsg::Batch(..) => true,
            ConsensusMsg::Vote { .. } => self
                .encode()
                .map(|b| b.len() >= 64 * 1024)
                .unwrap_or(false),
        }
    }

    /// Encode `items` as one [`ConsensusMsg::Batch`].
    pub fn batch_encode(items: &[ConsensusMsg]) -> Result<Vec<u8>, String> {
        if items.is_empty() {
            return Err("empty consensus batch".to_string());
        }
        if items.len() > MAX_BATCH_ITEMS {
            return Err(format!("consensus batch too many items: {}", items.len()));
        }
        if items.iter().any(|m| matches!(m, ConsensusMsg::Batch(_))) {
            return Err("nested consensus batch".to_string());
        }
        let batch = ConsensusMsg::Batch(items.to_vec());
        let bytes =
            bincode::serialize(&batch).map_err(|e| format!("consensus batch encode: {e}"))?;
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(format!("consensus batch too large: {} bytes", bytes.len()));
        }
        if bytes.len() > MAX_CONSENSUS_MSG {
            return Err("consensus message too large".to_string());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty consensus message".to_string());
        }
        if bytes.len() > MAX_CONSENSUS_MSG {
            return Err("consensus message too large".to_string());
        }
        let msg: Self =
            bincode::deserialize(bytes).map_err(|e| format!("consensus msg decode: {e}"))?;
        if let Self::Batch(items) = &msg {
            Self::check_batch(items, bytes.len())?;
        }
        Ok(msg)
    }
}

/// Transport handle for consensus messages over infnode.
pub struct ConsensusNetwork {
    pub adapter: Arc<P2pNetworkAdapter>,
    pub topic: String,
    /// Recently-sent votes for send-time coalescing (see
    /// [`VOTE_SEND_DEDUP_TTL_MS`]). Short critical section, never held across
    /// an await. Proposals/commits bypass it (always sent).
    sent_votes: Mutex<VoteSendFilter>,
    /// Per-peer liveness: consecutive send/probe failures. A peer that fails
    /// [`PEER_SKIP_THRESHOLD`] times in a row is SKIPPED for
    /// [`PEER_SKIP_COOLDOWN`] (no dial, no 2s join tax), then retried: one
    /// dead peer entry used to add 2s to EVERY broadcast join, which stretched
    /// ticks past the round timeouts and stalled finality chain-wide
    /// (observed live: a single dead peer halted a healthy 2-node stand).
    /// Mutex-only, never held across await (snapshot-then-update).
    /// Shared (`Arc`) so DETACHED per-peer sends (see `send_payload_with_skip`)
    /// keep recording outcomes after the flush moved on: detaching a task never
    /// drops the ledger, so no outcome is lost.
    peer_health: Arc<Mutex<HashMap<[u8; 20], PeerHealth>>>,
    /// Consecutive probe-TIMEOUT streak per peer for the N-timeout eviction
    /// rule (see [`probe_evict_after`]): incremented on probe timeout, cleared
    /// on any answering probe (ok or fast error). Mutex-only, never held
    /// across await (snapshot-then-update).
    probe_timeouts: Mutex<HashMap<[u8; 20], u32>>,
    /// Per-peer last broadcast schedule (epoch-ms) for the send-pacing floor
    /// (see [`CONS_BCAST_MIN_INTERVAL_MS_DEFAULT`]). Mutex-only, never held
    /// across await.
    bcast_last_ms: Mutex<HashMap<[u8; 20], u64>>,
    /// Per-peer last probe time (epoch-ms) for the probe-pacing floor
    /// (see [`CONS_PROBE_MIN_INTERVAL_MS_DEFAULT`]). Mutex-only, never held
    /// across await.
    probe_last_ms: Mutex<HashMap<[u8; 20], u64>>,
    /// Inbound bulk-replication budget per peer (see [`InboundBulkLimiter`]).
    /// Votes/proposals/commits bypass it; only bulk gossip is deferred.
    /// Mutex-only, never held across await.
    inbound_bulk: Mutex<InboundBulkLimiter>,
}

/// Consecutive-failure counter for one peer (see `peer_health`).
#[derive(Clone, Copy, Default)]
struct PeerHealth {
    /// Consecutive failures (transport error or timeout). Reset on success.
    fails: u32,
    /// When the last failure happened (cooldown measured from here).
    last_fail: Option<std::time::Instant>,
}

/// Skip a peer after this many consecutive failures.
const PEER_SKIP_THRESHOLD: u32 = 3;
/// ...and retry it after this long.
const PEER_SKIP_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Per-request send/probe budget. Default 2000ms (LAN-speed stands); WAN
/// validators raise it via `STELL_SEND_TIMEOUT_MS` — with an 11s peer, a 2s
/// cap turns every send into a certain timeout and the node can never vote
/// (observed live: a WAN newcomer's votes never landed). Single choke point
/// for all consensus-net request caps; the unit-test deadline below keeps
/// its own literal 2s.
fn send_timeout() -> std::time::Duration {
    std::env::var("STELL_SEND_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 500)
        .map(std::time::Duration::from_millis)
        .unwrap_or(std::time::Duration::from_secs(2))
}

/// Pure cooldown decision (unit-tested): skip once the failure count reaches
/// the threshold and the last failure is still inside the cooldown window.
/// An old failure means "retry now" (returns false); a zero count never
/// skips, even with a stale timestamp.
fn peer_in_cooldown(fails: u32, last_fail: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    fails >= PEER_SKIP_THRESHOLD
        && last_fail.is_some_and(|t| now.saturating_duration_since(t) < PEER_SKIP_COOLDOWN)
}

/// Bound on the per-peer JOIN phase of ONE flush in ms (default 500,
/// `STELL_BROADCAST_JOIN_MS`): the flush returns after this even if some peers
/// have not answered. Unanswered tasks are DETACHED, never aborted — they
/// still send and still record their outcome (see `send_one_peer`), so no
/// message is dropped and no outcome is lost; only the sender queue moves on.
/// 500ms keeps a healthy flush (LAN-speed stands answer in ms) fully joined
/// while a dead peer's ~1.5s "no session key" stall can never hold the queue.
pub const BROADCAST_JOIN_TIMEOUT_MS_DEFAULT: u64 = 500;

/// Parse helper for [`broadcast_join_timeout_ms`]: garbage/zero disables
/// nothing, it falls back to the default (same clamp-instead-of-disable shape
/// as the replication pacing parsers). Time-injected so tests need no env.
pub fn parse_broadcast_join_timeout_ms(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(BROADCAST_JOIN_TIMEOUT_MS_DEFAULT)
}

/// Effective flush join budget (`STELL_BROADCAST_JOIN_MS`, default 500). Read
/// per flush (cheap, no I/O) so the budget is live-tunable without restart.
pub fn broadcast_join_timeout_ms() -> u64 {
    parse_broadcast_join_timeout_ms(std::env::var("STELL_BROADCAST_JOIN_MS").ok())
}

/// Consecutive probe timeouts before the shared connection is evicted
/// (default 3, `STELL_PROBE_EVICT_AFTER`). A single timeout only records and
/// moves on; eviction needs a streak, so one slow probe cannot cascade into
/// conn-close storms.
pub const PROBE_EVICT_AFTER_DEFAULT: u32 = 3;

/// Parse helper for [`probe_evict_after`]: garbage/zero falls back to the
/// default (clamped, never disabled). Time-injected so tests need no env.
pub fn parse_probe_evict_after(raw: Option<String>) -> u32 {
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(PROBE_EVICT_AFTER_DEFAULT)
}

/// Effective probe-eviction streak (`STELL_PROBE_EVICT_AFTER`, default 3).
pub fn probe_evict_after() -> u32 {
    parse_probe_evict_after(std::env::var("STELL_PROBE_EVICT_AFTER").ok())
}

/// Pure eviction decision: evict only once the consecutive-timeout streak
/// reaches the threshold. The threshold is clamped to >= 1 so a zero config
/// still means "evict on first timeout", never "never evict".
pub fn probe_timeout_should_evict(consecutive_timeouts: u32, evict_after: u32) -> bool {
    consecutive_timeouts >= evict_after.max(1)
}

/// Pure join-backoff decision (audit-network handshake-storm fix): a peer in
/// failure cooldown gets no join dial on this pass; every other peer does.
/// Time-injected (takes the already-computed cooldown bit) so tests pin it
/// without a node.
pub fn join_should_dial(in_cooldown: bool) -> bool {
    !in_cooldown
}

/// Height carried by a [`ConsensusMsg::Committed`], or `None` for every other
/// variant. Outbox/drain policy uses it to dedup and prioritize the live
/// catch-up path without touching consensus validation.
pub fn committed_height_of(msg: &ConsensusMsg) -> Option<u64> {
    match msg {
        ConsensusMsg::Committed { height, .. } => Some(*height),
        _ => None,
    }
}

/// Reorder one tick's flattened inbound messages so live catch-up survives a
/// flood (audit-network F2): [`ConsensusMsg::Committed`] first (stable,
/// sender order preserved within each class), everything else after. Pure so
/// the drain policy is test-pinned without a node; the drain calls this on
/// each flattened envelope before the verification-budget check, so a
/// `Committed` riding with 32 junk votes is verified first instead of being
/// dropped as flood tail.
pub fn prioritize_inbound_for_verify(mut msgs: Vec<ConsensusMsg>) -> Vec<ConsensusMsg> {
    msgs.sort_by_key(|m| committed_height_of(m).is_none());
    msgs
}

/// Where one peer's send belongs on this flush (see [`plan_peer_send`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPlan {
    /// Send concurrently and bound the flush on this peer's answer.
    Joined,
    /// Send concurrently but NEVER block the flush on this peer: detached from
    /// the start, outcome still recorded on completion.
    Detached,
    /// Do not attempt this peer on this flush.
    Skipped,
}

/// Pure send-set decision, split out so it is unit-testable:
///
/// * a live peer is always [`SendPlan::Joined`];
/// * a cooldown peer on a normal payload is [`SendPlan::Skipped`] (no dial, no
///   join tax);
/// * a cooldown peer on an EXEMPT payload (Committed catch-up, see
///   [`committed_bypasses_skip`]) is [`SendPlan::Detached`]: still attempted
///   so a returning node catches up, but never in the joined set, so a dead
///   peer's stall cannot inherit into every vote batch.
pub fn plan_peer_send(in_cooldown: bool, exempt_skip: bool) -> SendPlan {
    if in_cooldown {
        if exempt_skip {
            SendPlan::Detached
        } else {
            SendPlan::Skipped
        }
    } else {
        SendPlan::Joined
    }
}

/// Await `handles`, bounded by `budget`. Returns `(completed, detached)`.
///
/// The flush-latency bound, shared by the broadcast path and its tests:
/// whatever has not finished when `budget` elapses is DETACHED via
/// `JoinSet::detach_all` — tasks keep running to completion in the
/// background (their sends and their outcome recording are inside the task),
/// only the waiter moves on. Nothing is aborted, nothing is dropped: a slow
/// peer delays neither the fast peers' observation nor the sender queue.
pub async fn join_with_timeout<T: Send + 'static>(
    handles: Vec<tokio::task::JoinHandle<T>>,
    budget: Duration,
) -> (Vec<T>, usize) {
    if handles.is_empty() {
        return (Vec::new(), 0);
    }
    let mut set = tokio::task::JoinSet::new();
    for h in handles {
        set.spawn(async move { h.await.ok() });
    }
    let mut done = Vec::new();
    let mut drained = false;
    let mut budget_sleep = Box::pin(tokio::time::sleep(budget));
    loop {
        if set.is_empty() {
            drained = true;
            break;
        }
        tokio::select! {
            // `biased`: drain every already-ready completion before noticing
            // the expired budget, so fast peers join even in a slow flush.
            biased;
            r = set.join_next() => {
                match r {
                    Some(Ok(Some(v))) => done.push(v),
                    // Inner task panicked/cancelled, or the wrapper failed:
                    // nothing to collect, keep draining the rest.
                    Some(Ok(None)) | Some(Err(_)) => {}
                    None => {
                        drained = true;
                        break;
                    }
                }
            }
            _ = &mut budget_sleep => break,
        }
    }
    if drained {
        (done, 0)
    } else {
        let pending = set.len();
        set.detach_all();
        (done, pending)
    }
}

impl ConsensusNetwork {
    pub fn new(adapter: Arc<P2pNetworkAdapter>) -> Self {
        // Epoch-scoped: the adapter knows the chain it belongs to, so the topic is
        // derived from it rather than being a fixed name shared by every chain.
        let topic = consensus_topic(adapter.epoch().as_str());
        Self {
            adapter,
            topic,
            sent_votes: Mutex::new(VoteSendFilter::new(Duration::from_millis(
                VOTE_SEND_DEDUP_TTL_MS,
            ))),
            peer_health: Arc::new(Mutex::new(HashMap::new())),
            probe_timeouts: Mutex::new(HashMap::new()),
            bcast_last_ms: Mutex::new(HashMap::new()),
            probe_last_ms: Mutex::new(HashMap::new()),
            inbound_bulk: Mutex::new(InboundBulkLimiter::with_defaults()),
        }
    }

    /// Construct a shard-scoped consensus network. In a single-shard process
    /// (`registry.is_sharded() == false`) this is identical to [`Self::new`], so
    /// default deployments keep the historical topic; a multi-shard process
    /// appends the shard id so instances cannot cross-talk.
    pub fn new_for_shard(
        adapter: Arc<P2pNetworkAdapter>,
        shard_id: u32,
        registry: &ShardRegistry,
    ) -> Self {
        let topic = if registry.is_sharded() {
            consensus_topic_for_shard(adapter.epoch().as_str(), shard_id)
        } else {
            consensus_topic(adapter.epoch().as_str())
        };
        Self {
            adapter,
            topic,
            sent_votes: Mutex::new(VoteSendFilter::new(Duration::from_millis(
                VOTE_SEND_DEDUP_TTL_MS,
            ))),
            peer_health: Arc::new(Mutex::new(HashMap::new())),
            probe_timeouts: Mutex::new(HashMap::new()),
            bcast_last_ms: Mutex::new(HashMap::new()),
            probe_last_ms: Mutex::new(HashMap::new()),
            inbound_bulk: Mutex::new(InboundBulkLimiter::with_defaults()),
        }
    }

    /// Subscribe to inbound consensus messages. Returns a raw string receiver
    /// (JSON with a `data` field). Use `parse_incoming` to decode.
    pub async fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        tracing::info!("[consensus] subscribing to topic {}", self.topic);
        self.adapter.node.register_app_sub(&self.topic).await
    }

    /// True when this peer is in failure cooldown (skip it: no dial, no join
    /// tax). Snapshot read, never held across await.
    fn peer_skipped(&self, pid: &[u8; 20]) -> bool {
        let now = std::time::Instant::now();
        match self.peer_health.lock() {
            Ok(h) => match h.get(pid) {
                Some(ph) => peer_in_cooldown(ph.fails, ph.last_fail, now),
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// Record one send/probe outcome for the backoff ledger.
    fn peer_record(&self, pid: [u8; 20], ok: bool) {
        Self::record_health(&self.peer_health, pid, ok);
    }

    /// Ledger update shared by the inline paths ([`Self::peer_record`]) and
    /// the DETACHED per-peer tasks ([`Self::send_one_peer`]), which only hold
    /// an `Arc` to the ledger — never `&self`, because they may outlive the
    /// flush that spawned them.
    fn record_health(health: &Mutex<HashMap<[u8; 20], PeerHealth>>, pid: [u8; 20], ok: bool) {
        let now = std::time::Instant::now();
        if let Ok(mut h) = health.lock() {
            if ok {
                h.remove(&pid);
            } else {
                let e = h.entry(pid).or_default();
                e.fails = e.fails.saturating_add(1);
                e.last_fail = Some(now);
                if e.fails == PEER_SKIP_THRESHOLD {
                    tracing::warn!(
                        "[net] peer {} failing {}x in a row: skipping sends/probes for {:?}",
                        hex::encode(pid),
                        e.fails,
                        PEER_SKIP_COOLDOWN,
                    );
                }
            }
        }
    }

    /// True when this node has at least one peer worth sending to: any known
    /// peer NOT in failure cooldown. Fail-open (`true`) when the peer table is
    /// empty — single-node/dev stands have no peers and must never read that
    /// as "no healthy route".
    pub fn has_nonskipped_peers(&self) -> bool {
        let peers = self.peer_ids();
        if peers.is_empty() {
            return true;
        }
        peers.iter().any(|pid| !self.peer_skipped(pid))
    }

    /// One more consecutive probe TIMEOUT for `pid`; returns the new streak.
    fn probe_timeout_hit(&self, pid: [u8; 20]) -> u32 {
        match self.probe_timeouts.lock() {
            Ok(mut m) => {
                let e = m.entry(pid).or_insert(0);
                *e = e.saturating_add(1);
                *e
            }
            Err(_) => 1,
        }
    }

    /// Clear `pid`'s probe-timeout streak: any answering probe (ok or fast
    /// error) proves the connection is alive and breaks the streak.
    fn probe_timeout_clear(&self, pid: &[u8; 20]) {
        if let Ok(mut m) = self.probe_timeouts.lock() {
            m.remove(pid);
        }
    }

    /// Resolve every configured peer to a node id.
    ///
    /// The peer's `node-id` is preferred over its name: name resolution depends
    /// on a name registry that fills in asymmetrically (a node can know the name
    /// of a peer that does not yet know its own), and a failed lookup used to
    /// make `broadcast` silently send nothing — stalling consensus with no error
    /// anywhere. A node id is always resolvable.
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        let mut out = Vec::new();
        for p in &self.adapter.node.cfg.peers {
            let pid = p.node_id_raw().or_else(|_| self.adapter.node.resolve(&p.name));
            match pid {
                Ok(pid) => out.push(pid),
                Err(e) => tracing::warn!("[consensus] cannot resolve peer {}: {e}", p.name),
            }
        }
        out
    }

    /// Register as a NETWORK subscriber to the consensus topic on every peer, so
    /// that peer-published messages are relayed to our local app subscription.
    /// Idempotent — safe to call repeatedly until peers connect.
    ///
    /// Join backoff (audit-network handshake-storm fix): peers in failure
    /// cooldown ([`SendPlan::Skipped`]) get NO join dial here. A join is a full
    /// `request_to` round trip (up to [`send_timeout`]) per peer; dialing a
    /// dead validator endpoint on every reconnect tick re-creates the
    /// handshake-timeout storm the cooldown exists to suppress. The peer is
    /// re-dialed once its cooldown expires (next `join` then attempts it).
    pub async fn join(&self) {
        let payload = serde_json::json!({ "topic": self.topic })
            .to_string()
            .into_bytes();
        // Concurrent with a bounded join budget (same shape as the broadcast
        // flush): the old serial loop paid one dead peer's full 2s timeout on
        // EVERY 60s window (~1.7s measured live), stretching the tick past
        // round timeouts for no reason. Slow peers detach and still record
        // their outcome; skipped peers cost nothing.
        let mut handles = Vec::new();
        for pid in self.peer_ids() {
            if self.peer_skipped(&pid) {
                tracing::debug!(
                    "[net] join {} skipped (failure cooldown, no dial)",
                    hex::encode(pid)
                );
                continue;
            }
            let node = Arc::clone(&self.adapter.node);
            let health = Arc::clone(&self.peer_health);
            let payload = payload.clone();
            handles.push(tokio::spawn(async move {
                let r = tokio::time::timeout(
                    send_timeout(),
                    node.request_to(pid, "pubsub.subscribe", payload),
                )
                .await;
                Self::record_health(&health, pid, matches!(r, Ok(Ok(_))));
            }));
        }
        let budget = std::time::Duration::from_millis(broadcast_join_timeout_ms());
        let (_done, _detached) = join_with_timeout(handles, budget).await;
    }

    /// Liveness probe: `core.ping` every peer with a visible outcome. Silent
    /// one-directional blackouts (requests return ok but nothing arrives, or
    /// hang until timeout) are indistinguishable from health without this:
    /// a failing probe names the dead direction in one line.
    pub async fn probe_peers(&self) {
        for pid in self.peer_ids() {
            if self.peer_skipped(&pid) {
                tracing::debug!("[net] probe {} skipped (failure cooldown)", hex::encode(pid));
                continue;
            }
            // Probe pacing (backpressure 2026-10-14): a probe is a full
            // `request_to` round trip per peer; without a floor, overlapping
            // probe ticks (timer + reconnect + manual) re-hammer a peer that is
            // already timing out — the same retry-feeds-timeout shape as the
            // `dht.store` storm, one layer up. Over-frequent probes defer here
            // with a debug line, never with a warn (pacing is normal, not failure).
            if !self.probe_due_and_stamp(&pid) {
                tracing::debug!(
                    "[net] probe {} skipped (probe pacing floor {}ms)",
                    hex::encode(pid),
                    cons_probe_min_interval_ms()
                );
                continue;
            }
            let t = std::time::Instant::now();
            let r = tokio::time::timeout(
                send_timeout(),
                self.adapter.node.request_to(pid, "core.ping", b"{}".to_vec()),
            )
            .await;
            match r {
                Ok(Ok(_)) => {
                    self.peer_record(pid, true);
                    self.probe_timeout_clear(&pid);
                    tracing::info!(
                        "[net] probe {} ok in {:?}",
                        hex::encode(pid),
                        t.elapsed()
                    );
                }
                Ok(Err(e)) => {
                    self.peer_record(pid, false);
                    // A fast error still proves the connection answers, so it
                    // breaks the TIMEOUT streak: eviction is for consecutive
                    // timeouts, not for any failure.
                    self.probe_timeout_clear(&pid);
                    tracing::warn!(
                        "[net] probe {} err in {:?}: {e}",
                        hex::encode(pid),
                        t.elapsed()
                    );
                }
                Err(_) => {
                    self.peer_record(pid, false);
                    let streak = self.probe_timeout_hit(pid);
                    let after = probe_evict_after();
                    if probe_timeout_should_evict(streak, after) {
                        tracing::warn!(
                            "[net] probe {} TIMEOUT after {:?}; evicting conn ({streak} consecutive timeouts >= {after})",
                            hex::encode(pid),
                            t.elapsed(),
                        );
                        self.adapter.node.invalidate_peer_conn(pid).await;
                    } else {
                        // Single (or sub-threshold) timeout: record + move on.
                        // The connection stays; a transient stall must not
                        // cascade into a conn-close/redial storm.
                        tracing::warn!(
                            "[net] probe {} TIMEOUT after {:?}; keeping conn ({streak}/{after} consecutive timeouts)",
                            hex::encode(pid),
                            t.elapsed(),
                        );
                    }
                }
            }
        }
    }

    /// Broadcast a consensus message to all configured peers (best-effort).
    /// We send `pubsub.msg` (the terminal delivery op) directly to each peer, so
    /// the message lands in the peer's local app subscription. `pubsub.publish`
    /// would only fan out to that peer's own subscribers, not to its app_subs.
    ///
    /// Outcomes are LOGGED, never swallowed: a one-directional delivery
    /// blackout once stalled the stand for 10 minutes with every consensus
    /// check green, because `let _ =` hid whether the peer denied, errored,
    /// or timed out. TIMEOUT@~2000ms with no receiver-side `req` lines means
    /// a dead cached connection (nothing ever evicts it); a fast `ok:false`
    /// denial plus receiver `req_denied` lines means an ACL/config problem.
    ///
    /// 1-item wrapper over [`Self::broadcast_batch`] (P3-H4).
    pub async fn broadcast(&self, msg: &ConsensusMsg) {
        self.broadcast_batch(std::slice::from_ref(msg)).await;
    }

    /// Broadcast several consensus messages as ONE encoded batch with ONE
    /// `request_to` per peer (P3-H4 gossip batching). A single item is sent
    /// with the legacy single encoding; several items go as one `Batch`.
    pub async fn broadcast_batch(&self, msgs: &[ConsensusMsg]) {
        if msgs.is_empty() {
            return;
        }
        // Send-time coalescing (tail-killer): an identical vote that already
        // went on the wire within VOTE_SEND_DEDUP_TTL_MS is suppressed here,
        // at the single choke point every path (timer flush, retransmit,
        // view-change re-send) funnels through. The first send of a round's
        // votes always passes; only same-tick duplicates collapse, so loss
        // recovery on the retransmit cadence is unaffected. Proposals and
        // commits always pass.
        let live: Vec<ConsensusMsg> = {
            let now = Instant::now();
            match self.sent_votes.lock() {
                Ok(mut filter) => msgs
                    .iter()
                    .filter(|m| filter.should_send(m, now))
                    .cloned()
                    .collect(),
                Err(_) => msgs.to_vec(),
            }
        };
        if live.is_empty() {
            return;
        }
        let msgs = &live;
        // Stage (a): bincode encode + hex + JSON framing. Timed separately so a
        // live measurement can tell a CPU-bound encode from a slow transport.
        let t_encode = std::time::Instant::now();
        let bytes = if msgs.len() == 1 {
            match msgs[0].encode() {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!("[consensus] broadcast: encode failed, sending nothing");
                    return;
                }
            }
        } else {
            match ConsensusMsg::batch_encode(msgs) {
                Ok(b) => b,
                Err(e) => {
                    // Size-aware fallback (audit: blocks troubles): a fat
                    // proposal batched with votes failed the 512KB batch cap
                    // and the WHOLE chunk — proposal included — was silently
                    // dropped. Fall back to single-encode per message (each
                    // still capped at MAX_CONSENSUS_MSG): votes may still drop
                    // oversize, but a proposal always goes out alone.
                    tracing::warn!(
                        "[consensus] broadcast_batch: {e}, falling back to single sends"
                    );
                    return self.broadcast_singles(msgs).await;
                }
            }
        };
        let nbytes = bytes.len();
        let data = hex::encode(bytes);
        let payload = serde_json::json!({ "topic": self.topic, "data": data })
            .to_string()
            .into_bytes();
        log_stage(
            &ENCODE_STAGE_GATE,
            "encode",
            &format!("items={} bytes={nbytes}", msgs.len()),
            t_encode.elapsed(),
        );
        let exempt = batch_bypasses_skip(msgs);
        self.send_payload_with_skip(payload, exempt).await;
    }

    /// Single-encode fallback for a chunk that failed batch encoding (see
    /// `broadcast_batch`): each message goes out alone, so one oversize
    /// member cannot sink its batch-mates. Proposals (which forced the
    /// fallback by their size) travel singleton; small votes regroup in later
    /// flushes. Each singleton is still capped at MAX_CONSENSUS_MSG.
    async fn broadcast_singles(&self, msgs: &[ConsensusMsg]) {
        for m in msgs {
            let exempt = committed_bypasses_skip(m);
            match m.encode() {
                Ok(b) => {
                    if b.len() > MAX_CONSENSUS_MSG {
                        tracing::warn!(
                            "[consensus] singleton message too large ({} bytes), dropping",
                            b.len()
                        );
                        continue;
                    }
                    let payload = serde_json::json!({ "topic": self.topic, "data": hex::encode(b) })
                        .to_string()
                        .into_bytes();
                    self.send_payload_with_skip(payload, exempt).await;
                }
                Err(e) => {
                    tracing::warn!("[consensus] singleton encode failed: {e}");
                }
            }
        }
    }

    /// Shared per-peer delivery with connection eviction (used by both
    /// [`Self::broadcast`] and [`Self::broadcast_batch`]).
    ///
    /// Per-peer sends run CONCURRENTLY (one task per peer), not serially. The
    /// old serial loop made one slow peer's `request_to` (up to the 2s cap
    /// each) head-of-line-block every peer behind it, so a single unscheduled
    /// handler stretched the whole flush to 2-4s and every height paid it
    /// several times. Concurrency bounds one flush by the SLOWEST peer instead
    /// of the SUM, the join budget ([`BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`])
    /// bounds it further by detaching stragglers, and a timing-out peer no
    /// longer delays the rest.
    ///
    /// `exempt_skip` bypasses the failure-cooldown skip (see
    /// [`committed_bypasses_skip`]): exempt payloads still attempt every
    /// resolvable peer and still record outcomes, so the health ledger keeps
    /// learning — but cooldown peers are attempted DETACHED, never joined, so
    /// a dead peer's stall cannot ride along on a catch-up send. Only the skip
    /// is lifted, not the timeout or the recording.
    async fn send_payload(&self, payload: Vec<u8>) {
        self.send_payload_with_skip(payload, false).await;
    }

    /// One peer's send, self-contained for DETACH: it carries everything it
    /// needs (`Arc`s + owned payload) and records + logs its own outcome, so
    /// a task detached by the join budget still sends and still lands in the
    /// health ledger when it finishes. No message dropped, no outcome lost.
    async fn send_one_peer(
        adapter: Arc<P2pNetworkAdapter>,
        health: Arc<Mutex<HashMap<[u8; 20], PeerHealth>>>,
        pid: [u8; 20],
        payload: Vec<u8>,
        wait_ms: u64,
    ) {
        if wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
        let t = std::time::Instant::now();
        let r = tokio::time::timeout(
            send_timeout(),
            adapter.node.request_to(pid, "pubsub.msg", payload),
        )
        .await;
        let elapsed = t.elapsed();
        // Stage (b): the whole `request_to` for this peer. infnode does not
        // expose its internal dial-vs-response split, so (b1)/(b2) are not
        // reachable from here (see the infnode instrumentation note in the
        // report); this names the transport stage vs stage (a).
        log_stage(
            &REQUEST_STAGE_GATE,
            "request_to",
            &format!("peer={} total", hex::encode(pid)),
            elapsed,
        );
        let hexid = hex::encode(pid);
        match r {
            Ok(Ok(resp)) if resp.starts_with(b"{\"ok\":false") => {
                Self::record_health(&health, pid, false);
                tracing::warn!(
                    "[consensus] broadcast to {} denied/fast-fail in {:?}: {}",
                    hexid,
                    elapsed,
                    String::from_utf8_lossy(&resp),
                );
            }
            Ok(Ok(_)) => {
                Self::record_health(&health, pid, true);
                let took = elapsed;
                // Slow-but-successful is exactly what hid the tick stall:
                // the consensus loop AWAITS every broadcast, so a peer
                // that answers in 1-2s (under the 2s cap, therefore never
                // logged) stretches a tick to seconds with no warning.
                if took >= std::time::Duration::from_millis(300) {
                    tracing::warn!(
                        "[consensus] broadcast to {} slow: {:?} (still under the cap)",
                        hexid,
                        took
                    );
                } else {
                    tracing::debug!("[consensus] broadcast to {} ok in {:?}", hexid, took);
                }
            }
            // Transport error or timeout: the cached connection is suspect
            // (a dead conn is reused forever because our 2s budget preempts
            // the inner 120s self-heal). Evict it so the next broadcast
            // redials fresh instead of hanging on the same dead conn.
            Ok(Err(e)) => {
                Self::record_health(&health, pid, false);
                tracing::warn!(
                    "[consensus] broadcast to {} transport-err in {:?}: {e}",
                    hexid, elapsed,
                );
                // NO eviction here. Eviction closes the shared connection,
                // which kills the peer's frame_loop for it too; one slow
                // response then cascaded into ~2300 conn_closed events per
                // node and every redial cost ~1s. `request_to` already
                // drops a genuinely dead connection on its inner retry,
                // and the periodic probe (which does evict) is the
                // liveness check -- a single slow message must not decide.
            }
            Err(_) => {
                Self::record_health(&health, pid, false);
                tracing::warn!(
                    "[consensus] broadcast to {} TIMEOUT after {:?}",
                    hexid, elapsed,
                );
                // See above: time out, log, move on -- do not evict.
            }
        }
    }

    async fn send_payload_with_skip(&self, payload: Vec<u8>, exempt_skip: bool) {
        let peers = self.peer_ids();
        if peers.is_empty() {
            tracing::warn!("[consensus] no resolvable peers to broadcast to");
            return;
        }
        // Joined set = live peers only. Cooldown peers on an EXEMPT payload
        // are still attempted (catch-up must reach a returning node) but as
        // DETACHED sends from the start — never in the joined set — so a dead
        // peer's stall cannot inherit into a vote batch via a retro-Commit.
        let mut joined = Vec::with_capacity(peers.len());
        let mut skipped = 0u32;
        let mut detached = 0u32;
        for pid in peers {
            // Failure cooldown (see `peer_health`): a dead peer costs nothing
            // here instead of its 2s join tax every broadcast. Exempt
            // payloads (Committed catch-up) still attempt it, detached.
            match plan_peer_send(self.peer_skipped(&pid), exempt_skip) {
                SendPlan::Skipped => {
                    skipped += 1;
                    continue;
                }
                SendPlan::Detached => {
                    detached += 1;
                    // Send pacing (backpressure 2026-10-14): minimum gap between two
                    // sends to the SAME peer (`CONS_BCAST_MIN_INTERVAL_MS_DEFAULT`,
                    // default 25ms — far below consensus timescales, far above hammer
                    // rates). The wait is bounded by the floor itself and rides inside
                    // the peer's task, so peers still send concurrently and no vote is
                    // ever dropped or starved — only same-peer bursts are spaced.
                    let wait_ms = self.bcast_wait_and_stamp(&pid);
                    // Detached from the start: the handle is dropped at once.
                    // The task keeps running (send + record on completion),
                    // only the flush refuses to wait for it.
                    tokio::spawn(Self::send_one_peer(
                        Arc::clone(&self.adapter),
                        Arc::clone(&self.peer_health),
                        pid,
                        payload.clone(),
                        wait_ms,
                    ));
                    continue;
                }
                SendPlan::Joined => {}
            }
            // Send pacing (backpressure 2026-10-14): minimum gap between two
            // sends to the SAME peer (`CONS_BCAST_MIN_INTERVAL_MS_DEFAULT`,
            // default 25ms — far below consensus timescales, far above hammer
            // rates). The wait is bounded by the floor itself and rides inside
            // the peer's task, so peers still send concurrently and no vote is
            // ever dropped or starved — only same-peer bursts are spaced.
            let wait_ms = self.bcast_wait_and_stamp(&pid);
            joined.push(tokio::spawn(Self::send_one_peer(
                Arc::clone(&self.adapter),
                Arc::clone(&self.peer_health),
                pid,
                payload.clone(),
                wait_ms,
            )));
        }
        // Never join slow peers past the budget (see
        // [`BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`]): one dead peer's 1.5s "no
        // session key" join used to stall the whole flush. On expiry the rest
        // detach — they still send and still record, just off the queue.
        let (joined_n, detached_late) =
            join_with_timeout(joined, Duration::from_millis(broadcast_join_timeout_ms())).await;
        if detached_late > 0 {
            tracing::warn!(
                "[consensus] broadcast join budget ({}ms) exceeded: joined {} peer(s), detached {} slow peer(s) (still recording on completion)",
                broadcast_join_timeout_ms(),
                joined_n.len(),
                detached_late,
            );
        }
        if skipped > 0 {
            tracing::debug!(
                "[consensus] broadcast skipped {skipped} peer(s) in failure cooldown"
            );
        }
        if detached > 0 {
            tracing::debug!(
                "[consensus] broadcast detached {detached} exempt peer(s) in failure cooldown (attempted, not joined)"
            );
        }
    }

    /// Start the dedicated, ordered broadcast sender for this network and
    /// return the handle the consensus loop enqueues into (P4 transport-loop
    /// decoupling).
    ///
    /// The consensus loop must never await the `request_to` round trip: on a
    /// 1-vCPU host the peer's pubsub handler can take 0.4-2.0s to be
    /// scheduled, and a height needs several flushes, so awaiting each one
    /// stretched a tick by seconds. This task performs the sends strictly in
    /// FIFO order, so message ORDER and the receiver's dedup-by-key semantics
    /// are unchanged; only the waiting moves off the tick.
    ///
    /// RECOMMENDATION (not implemented here, deliberately): the round trip
    /// itself is still the delivery floor, because `pubsub.msg` is a REQUEST
    /// whose response is produced by the receiver's handler after it is
    /// scheduled. A direct consensus transport -- a unidirectional QUIC
    /// stream / datagram that does not wait for a handler-produced response,
    /// or a write-only `request_to`-style `send` op -- would remove the floor
    /// rather than merely overlap it. That is a separate, larger change (new
    /// infnode op + framing) and must not be smuggled in here.
    pub fn start_sender(self: &Arc<Self>) -> ConsensusSender {
        let net = Arc::clone(self);
        spawn_ordered_sender(move |chunk: BroadcastChunk| {
            let net = Arc::clone(&net);
            async move { net.broadcast_batch(&chunk).await }
        })
    }
}

/// One drained gossip chunk (up to [`MAX_BATCH_ITEMS`] consensus messages)
/// handed to the background sender.
pub type BroadcastChunk = Vec<ConsensusMsg>;

/// Handle to the dedicated ordered broadcast sender. Cheap to clone; all clones
/// feed the same FIFO queue and therefore the same wire order.
#[derive(Clone)]
pub struct ConsensusSender {
    tx: mpsc::UnboundedSender<BroadcastChunk>,
    /// Chunks handed to the queue but not yet sent (channel depth). Kept here
    /// because tokio's `UnboundedSender` exposes no `len()`; used for the
    /// backpressure cap and the flush sub-timing line.
    pending: Arc<AtomicUsize>,
}

impl ConsensusSender {
    /// Enqueue one drained chunk. Non-blocking. Returns `false` when the queue
    /// is at [`MAX_PENDING_CHUNKS`] (or the sender task is gone), in which case
    /// the caller keeps the chunk in its outbox for a later flush. A chunk is
    /// never dropped or duplicated by this path: the outbox moved it out
    /// exactly once, and dedup lives at enqueue time.
    pub fn enqueue(&self, chunk: BroadcastChunk) -> bool {
        if self.pending.load(Ordering::Relaxed) >= MAX_PENDING_CHUNKS {
            return false;
        }
        if self.tx.send(chunk).is_ok() {
            self.pending.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Chunks waiting behind the transport (for the flush sub-timing line).
    pub fn queued(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }
}

/// Spawn a single long-lived task that drains `send` jobs strictly in FIFO
/// order. Split out from [`ConsensusNetwork::start_sender`] so the ordering /
/// backpressure invariant is testable without a live infnode transport.
pub fn spawn_ordered_sender<F, Fut>(mut send: F) -> ConsensusSender
where
    F: FnMut(BroadcastChunk) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<BroadcastChunk>();
    let pending = Arc::new(AtomicUsize::new(0));
    let task_pending = Arc::clone(&pending);
    tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            let items = chunk.len();
            let t = std::time::Instant::now();
            send(chunk).await;
            task_pending.fetch_sub(1, Ordering::Relaxed);
            // Same stage name as the old synchronous flush, now measured on the
            // sender task so the transport cost stays visible even though the
            // tick no longer waits for it. `queued` is the backlog behind this
            // chunk: a growing number is the signal that the floor moved here.
            log_stage(
                &FLUSH_STAGE_GATE,
                "flush_outbox",
                &format!("items={items} queued={}", task_pending.load(Ordering::Relaxed)),
                t.elapsed(),
            );
        }
    });
    ConsensusSender { tx, pending }
}

/// Parse a raw pubsub payload (JSON `{ "topic", "data" }`) into a consensus message.
/// Returns None on any malformed input (fail-closed).
pub fn parse_incoming(raw: &str) -> Option<ConsensusMsg> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    ConsensusMsg::decode(&bytes).ok()
}

/// Transaction gossip over infnode pubsub. Anti-flood: only signatures are
/// verified here; the mempool applies the authoritative signature check and
/// per-sender quota, so a flood is bounded there.
pub struct TxGossip {
    pub adapter: Arc<P2pNetworkAdapter>,
    pub topic: String,
    /// Per-peer liveness, same 3-fails/60s rule as the consensus path (see
    /// `peer_health`): without it one slow/dead peer head-of-line-blocks tx
    /// propagation to every later peer (audit-network F5). Mutex-only, never
    /// held across await; shared so detached tasks keep recording outcomes.
    peer_health: Arc<Mutex<HashMap<[u8; 20], PeerHealth>>>,
    /// Per-peer last tx-send time for the pacing floor (see
    /// [`CONS_BCAST_MIN_INTERVAL_MS_DEFAULT`]). Mutex-only, never held across
    /// await.
    bcast_last_ms: Mutex<HashMap<[u8; 20], u64>>,
}

impl TxGossip {
    pub fn new(adapter: Arc<P2pNetworkAdapter>) -> Self {
        let topic = tx_topic(adapter.epoch().as_str());
        Self {
            adapter,
            topic,
            peer_health: Arc::new(Mutex::new(HashMap::new())),
            bcast_last_ms: Mutex::new(HashMap::new()),
        }
    }

    /// Peer ids, node-id first: the same asymmetric-registry trap fixed in
    /// `ConsensusNetwork::peer_ids` lived here too — a failed name lookup
    /// silently sent nothing, starving the peer's mempool (and its blocks)
    /// with no error anywhere (audit 2026-10-06).
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        let mut out = Vec::new();
        for p in &self.adapter.node.cfg.peers {
            let pid = p.node_id_raw().or_else(|_| self.adapter.node.resolve(&p.name));
            match pid {
                Ok(pid) => out.push(pid),
                Err(e) => tracing::warn!("[txgossip] cannot resolve peer {}: {e}", p.name),
            }
        }
        out
    }

    pub async fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        self.adapter.node.register_app_sub(&self.topic).await
    }

    /// Register as a network subscriber on every peer (idempotent).
    ///
    /// Same join backoff as [`ConsensusNetwork::join`]: cooldown peers get no
    /// dial here, so a dead validator endpoint cannot turn every reconnect
    /// tick into a handshake-timeout storm.
     pub async fn join(&self) {
         let payload = serde_json::json!({ "topic": self.topic }).to_string().into_bytes();
        // Concurrent with a bounded join budget (mirrors ConsensusNetwork):
        // serial dials paid a dead peer's full timeout on every window.
        let mut handles = Vec::new();
        for pid in self.peer_ids() {
            if self.peer_skipped(&pid) {
                tracing::debug!(
                    "[txgossip] join {} skipped (failure cooldown, no dial)",
                    hex::encode(pid)
                );
                continue;
            }
            let node = Arc::clone(&self.adapter.node);
            let health = Arc::clone(&self.peer_health);
            let payload = payload.clone();
            handles.push(tokio::spawn(async move {
                let r = tokio::time::timeout(
                    send_timeout(),
                    node.request_to(pid, "pubsub.subscribe", payload),
                )
                .await;
                Self::record_health(&health, pid, matches!(r, Ok(Ok(_))));
            }));
        }
        let budget = std::time::Duration::from_millis(broadcast_join_timeout_ms());
        let (_done, _detached) = join_with_timeout(handles, budget).await;
     }

    /// True when this peer is in failure cooldown (skip it: no dial, no join
    /// tax). Snapshot read, never held across await.
    fn peer_skipped(&self, pid: &[u8; 20]) -> bool {
        let now = std::time::Instant::now();
        match self.peer_health.lock() {
            Ok(h) => match h.get(pid) {
                Some(ph) => peer_in_cooldown(ph.fails, ph.last_fail, now),
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// True when this node has at least one tx peer worth dialing: any known
    /// peer NOT in failure cooldown. Fail-open (`true`) when the peer table is
    /// empty — single-node/dev stands have no peers and must never read that
    /// as "no healthy route". Section-level equivalent of
    /// [`join_should_dial`]: the tick checks this before paying a join dial's
    /// handshake timeout; a returning peer's DHT/probe success clears its
    /// cooldown entry, so the next window re-dials automatically.
    pub fn has_nonskipped_peers(&self) -> bool {
        let peers = self.peer_ids();
        if peers.is_empty() {
            return true;
        }
        peers.iter().any(|pid| !self.peer_skipped(pid))
    }

    /// Bounded wait before the next tx-send to `pid`, stamping this send now.
    /// Same floor as the consensus path: same-peer bursts are spaced, never
    /// dropped.
    fn bcast_wait_and_stamp(&self, pid: &[u8; 20]) -> u64 {
        let now = epoch_ms();
        let floor = cons_bcast_min_interval_ms();
        match self.bcast_last_ms.lock() {
            Ok(mut m) => {
                let wait = pace_wait_ms(m.get(pid).copied(), now, floor);
                m.insert(*pid, now);
                wait.min(floor)
            }
            Err(_) => 0,
        }
    }

    /// One peer's tx-send, self-contained for DETACH: records + logs its own
    /// outcome, so a task detached by the join budget still lands in the
    /// health ledger when it finishes. No outcome is lost.
    async fn send_one_peer(
        adapter: Arc<P2pNetworkAdapter>,
        health: Arc<Mutex<HashMap<[u8; 20], PeerHealth>>>,
        pid: [u8; 20],
        payload: Vec<u8>,
        wait_ms: u64,
    ) {
        if wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
        let t = std::time::Instant::now();
        let r = tokio::time::timeout(
            send_timeout(),
            adapter.node.request_to(pid, "pubsub.msg", payload),
        )
        .await;
        let elapsed = t.elapsed();
        let hexid = hex::encode(pid);
        match r {
            Ok(Ok(_)) => {
                Self::record_health(&health, pid, true);
                if elapsed >= std::time::Duration::from_millis(300) {
                    tracing::warn!("[txgossip] broadcast to {hexid} slow: {elapsed:?} (still under the cap)");
                } else {
                    tracing::debug!("[txgossip] broadcast to {hexid} ok in {elapsed:?}");
                }
            }
            Ok(Err(e)) => {
                Self::record_health(&health, pid, false);
                tracing::warn!("[txgossip] broadcast to {hexid} transport-err in {elapsed:?}: {e}");
            }
            Err(_) => {
                Self::record_health(&health, pid, false);
                tracing::warn!("[txgossip] broadcast to {hexid} TIMEOUT after {elapsed:?}");
            }
        }
    }

    /// Ledger update shared by the inline path and the DETACHED per-peer
    /// tasks, which only hold an `Arc` to the ledger.
    fn record_health(health: &Mutex<HashMap<[u8; 20], PeerHealth>>, pid: [u8; 20], ok: bool) {
        let now = std::time::Instant::now();
        if let Ok(mut h) = health.lock() {
            if ok {
                h.remove(&pid);
            } else {
                let e = h.entry(pid).or_default();
                e.fails = e.fails.saturating_add(1);
                e.last_fail = Some(now);
                if e.fails == PEER_SKIP_THRESHOLD {
                    tracing::warn!(
                        "[txgossip] peer {} failing {}x in a row: skipping sends for {:?}",
                        hex::encode(pid),
                        e.fails,
                        PEER_SKIP_COOLDOWN,
                    );
                }
            }
        }
    }

    /// Broadcast a transaction to all peers (best-effort).
    ///
    /// Fixed shape of the old serial loop (audit-network F5): per-peer sends
    /// run CONCURRENTLY with the same failure-cooldown skip and pacing floor
    /// as the consensus path, bounded by the same join budget
    /// ([`BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`]). One slow/dead peer can no
    /// longer head-of-line-block tx propagation to the rest: stragglers
    /// detach (still sending, still recording) while the flush moves on.
    /// Best-effort still: at most 1 MiB/tx, oversized txs never gossiped.
    pub async fn broadcast(&self, tx: &crate::sharding::Transaction) {
        let Ok(bytes) = bincode::serialize(tx) else { return };
        if bytes.len() > MAX_TX_MSG {
            return; // oversized tx never gossiped
        }
        let payload = serde_json::json!({ "topic": self.topic, "data": hex::encode(bytes) })
            .to_string()
            .into_bytes();
        let mut joined = Vec::new();
        let mut skipped = 0u32;
        for pid in self.peer_ids() {
            if self.peer_skipped(&pid) {
                skipped += 1;
                continue;
            }
            let wait_ms = self.bcast_wait_and_stamp(&pid);
            joined.push(tokio::spawn(Self::send_one_peer(
                Arc::clone(&self.adapter),
                Arc::clone(&self.peer_health),
                pid,
                payload.clone(),
                wait_ms,
            )));
        }
        if skipped > 0 {
            tracing::debug!("[txgossip] broadcast skipped {skipped} peer(s) in failure cooldown");
        }
        let (joined_n, detached_late) =
            join_with_timeout(joined, Duration::from_millis(broadcast_join_timeout_ms())).await;
        if detached_late > 0 {
            tracing::warn!(
                "[txgossip] broadcast join budget ({}ms) exceeded: joined {} peer(s), detached {} slow peer(s) (still recording on completion)",
                broadcast_join_timeout_ms(),
                joined_n.len(),
                detached_late,
            );
        }
    }
}

/// Parse a raw pubsub payload into a Transaction (fail-closed).
pub fn parse_tx_incoming(raw: &str) -> Option<crate::sharding::Transaction> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_TX_MSG {
        return None;
    }
    bincode::deserialize(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::VoteKind;
    use crate::sharding::{Transaction, MASTERCHAIN_SHARD};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn warn_gate_rate_limits_within_window() {
        let gate = AtomicU64::new(0);
        // First slow stage logs; a second one inside the window is suppressed;
        // once the window elapses the next one logs again.
        assert!(warn_allowed(&gate, 1_000));
        assert!(!warn_allowed(&gate, 1_000 + SUBTIMING_WARN_MIN_GAP_MS - 1));
        assert!(warn_allowed(&gate, 1_000 + SUBTIMING_WARN_MIN_GAP_MS));
        // Saturating behaviour: a clock that appears to go backwards must not
        // underflow into a spurious "allowed".
        assert!(!warn_allowed(&gate, 0));
    }

    #[test]
    fn log_stage_never_panics_for_fast_or_slow() {
        // Instrumentation only: both branches must be panic-free and leave the
        // gate usable.
        let gate = AtomicU64::new(0);
        log_stage(&gate, "test", "fast", std::time::Duration::from_micros(1));
        log_stage(&gate, "test", "slow", std::time::Duration::from_millis(250));
        log_stage(&gate, "test", "slow-again", std::time::Duration::from_millis(300));
    }

    #[test]
    fn peer_cooldown_skips_only_inside_the_window() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        // Below threshold: never skip, even with a fresh failure.
        assert!(!peer_in_cooldown(2, Some(now), now));
        // At threshold with a fresh failure: skip.
        assert!(peer_in_cooldown(3, Some(now), now));
        assert!(peer_in_cooldown(9, Some(now), now));
        // Same count but the failure aged out: retry now.
        let old = now - PEER_SKIP_COOLDOWN - Duration::from_secs(1);
        assert!(!peer_in_cooldown(3, Some(old), now));
        // No failure recorded at all: never skip.
        assert!(!peer_in_cooldown(0, None, now));
        assert!(!peer_in_cooldown(99, None, now));
    }

    #[test]
    fn join_dials_skip_cooldown_and_resume_when_cleared() {
        // Join backoff (handshake-storm fix): a peer in failure cooldown gets
        // no join dial on this pass; every other peer does. A returning peer
        // re-announces via DHT/probe (which clears cooldown on success), so
        // `in_cooldown == false` again and join resumes automatically.
        assert!(!join_should_dial(true), "cooldown peer: no dial");
        assert!(join_should_dial(false), "live peer: dial");
        assert!(
            join_should_dial(false),
            "cooldown cleared (returning peer): dial again"
        );
    }

    #[test]
    fn committed_bypasses_peer_skip_votes_and_proposals_do_not() {
        // Transport-audit contract: the Committed live path of a lagging node
        // must not starve for the 60s peer-skip cooldown; votes and proposals
        // stay skippable.
        let commit = ConsensusMsg::Committed {
            height: 9,
            block: sample_block(),
            certificate: crate::consensus::QuorumCertificate {
                height: 9,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: None,
                signatures: vec![],
            },
        };
        assert!(committed_bypasses_skip(&commit));
        assert!(batch_bypasses_skip(std::slice::from_ref(&commit)));
        let proposal =
            ConsensusMsg::Proposal { height: 9, round: 0, block: sample_block() };
        assert!(!committed_bypasses_skip(&proposal));
        assert!(!batch_bypasses_skip(std::slice::from_ref(&proposal)));
        // A batch of only votes/proposals carries no live path.
        let votes = vec![tagged_vote(1), tagged_vote(2)];
        assert!(!batch_bypasses_skip(&votes));
        // A mixed batch carrying a commit still bypasses (the whole payload
        // is the catch-up path); votes alone never do.
        let mut mixed = votes.clone();
        mixed.push(commit);
        assert!(batch_bypasses_skip(&mixed));
    }

    fn sample_block() -> Block {
        let sk = SigningKey::generate(&mut OsRng);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 7,
            prev_hash: [1u8; 32],
            state_root: [2u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 123,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            precommit_qc: None,
        };
        b.sign_block(&sk);
        b
    }

    #[test]
    fn proposal_roundtrip() {
        let msg = ConsensusMsg::Proposal { height: 7, round: 0, block: sample_block() };
        let bytes = msg.encode().unwrap();
        let dec = ConsensusMsg::decode(&bytes).unwrap();
        match dec {
            ConsensusMsg::Proposal { height, round, block } => {
                assert_eq!(height, 7);
                assert_eq!(round, 0);
                assert_eq!(block.height, 7);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vote_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 3, 1, VoteKind::Prevote, Some([9u8; 32]));
        let msg = ConsensusMsg::Vote { vote: v.clone(), locked: None };
        let bytes = msg.encode().unwrap();
        match ConsensusMsg::decode(&bytes).unwrap() {
            ConsensusMsg::Vote { vote: v2, locked } => {
                assert_eq!(locked, None);
                assert_eq!(v2.height, 3);
                assert_eq!(v2.round, 1);
                assert!(v2.verify());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(ConsensusMsg::decode(&[]).is_err(), "empty must be rejected");
        assert!(ConsensusMsg::decode(&[0xFF, 0x00, 0x01]).is_err(), "garbage must be rejected");
    }

    #[test]
    fn decode_rejects_oversized() {
        let big = vec![0u8; MAX_CONSENSUS_MSG + 1];
        assert!(ConsensusMsg::decode(&big).is_err(), "oversized must be rejected");
    }

    #[test]
    fn parse_incoming_fail_closed() {
        assert!(parse_incoming("not json").is_none());
        assert!(parse_incoming("{}").is_none());
        assert!(parse_incoming(r#"{"data": 123}"#).is_none());
        assert!(parse_incoming(r#"{"data": "zzzz"}"#).is_none()); // bad hex

        // a well-formed message parses
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Precommit, None);
        let data = hex::encode(ConsensusMsg::Vote { vote: v, locked: None }.encode().unwrap());
        let raw = serde_json::json!({ "topic": consensus_topic("test"), "data": data }).to_string();
        assert!(matches!(parse_incoming(&raw), Some(ConsensusMsg::Vote { .. })));
    }

    #[test]
    fn tampered_vote_fails_signature_check() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        v.block_hash = Some([2u8; 32]); // tamper after signing
        let msg = ConsensusMsg::Vote { vote: v, locked: None };
        let bytes = msg.encode().unwrap();
        match ConsensusMsg::decode(&bytes).unwrap() {
            ConsensusMsg::Vote { vote: v2, .. } => assert!(!v2.verify(), "tampered vote must fail verification"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn batch_roundtrip_preserves_order() {
        let sk = SigningKey::generate(&mut OsRng);
        let v1 = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let v2 = Vote::sign(&sk, 1, 0, VoteKind::Precommit, None);
        let items = vec![
            ConsensusMsg::Vote { vote: v1, locked: None },
            ConsensusMsg::Vote { vote: v2, locked: Some([2u8; 32]) },
            ConsensusMsg::Proposal { height: 7, round: 0, block: sample_block() },
        ];
        let bytes = ConsensusMsg::batch_encode(&items).unwrap();
        assert!(bytes.len() <= MAX_BATCH_BYTES);
        match ConsensusMsg::decode(&bytes).unwrap() {
            ConsensusMsg::Batch(inner) => {
                assert_eq!(inner.len(), 3);
                assert!(matches!(inner[0], ConsensusMsg::Vote { .. }));
                assert!(matches!(inner[1], ConsensusMsg::Vote { .. }));
                assert!(matches!(inner[2], ConsensusMsg::Proposal { .. }));
            }
            _ => panic!("must decode as Batch"),
        }
        // free-function helper agrees
        let bytes2 = batch_encode(&items).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn batch_rejects_nested() {
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
        let inner = ConsensusMsg::Batch(vec![ConsensusMsg::Vote { vote: v, locked: None }]);
        let outer = ConsensusMsg::Batch(vec![inner]);
        // batch_encode rejects nesting up front
        if let ConsensusMsg::Batch(items) = &outer {
            assert!(ConsensusMsg::batch_encode(items).is_err());
        } else {
            panic!("expected Batch");
        }
        // and decode rejects a nested payload crafted past the encoder
        let raw = bincode::serialize(&outer).unwrap();
        let err = ConsensusMsg::decode(&raw).unwrap_err();
        assert!(err.contains("nested"), "got: {err}");
    }

    #[test]
    fn batch_rejects_over_items() {
        let sk = SigningKey::generate(&mut OsRng);
        let items: Vec<ConsensusMsg> = (0..(MAX_BATCH_ITEMS + 1) as u64)
            .map(|i| ConsensusMsg::Vote {
                vote: Vote::sign(&sk, i, 0, VoteKind::Prevote, None),
                locked: None,
            })
            .collect();
        assert!(ConsensusMsg::batch_encode(&items).is_err());
        // decode path enforces the same bound
        let raw = bincode::serialize(&ConsensusMsg::Batch(items)).unwrap();
        let err = ConsensusMsg::decode(&raw).unwrap_err();
        assert!(err.contains("too many"), "got: {err}");
    }

    #[test]
    fn batch_rejects_over_bytes() {
        // Unsigned dummy txs: only the encoded size matters here.
        let txs: Vec<Transaction> = (0..4000)
            .map(|i| Transaction {
                from: [1u8; 32],
                to: [2u8; 32],
                amount: i,
                gas_limit: 5,
                nonce: i,
                source_shard: 1,
                target_shard: 1,
                signature: vec![0u8; 64],
                payload: vec![],
            })
            .collect();
        let sk = SigningKey::generate(&mut OsRng);
        let mut big = sample_block();
        big.transactions = txs;
        big.sign_block(&sk);
        let msg = ConsensusMsg::Proposal { height: 7, round: 0, block: big };
        assert!(msg.encode().unwrap().len() > MAX_BATCH_BYTES, "fixture must exceed the batch cap");
        let items = vec![msg.clone(), msg];
        assert!(ConsensusMsg::batch_encode(&items).is_err());
        let raw = bincode::serialize(&ConsensusMsg::Batch(items)).unwrap();
        assert!(raw.len() > MAX_BATCH_BYTES);
        let err = ConsensusMsg::decode(&raw).unwrap_err();
        assert!(err.contains("too large"), "got: {err}");
    }

    #[test]
    fn batch_rejects_empty() {
        let empty: Vec<ConsensusMsg> = vec![];
        assert!(ConsensusMsg::batch_encode(&empty).is_err());
        let raw = bincode::serialize(&ConsensusMsg::Batch(empty)).unwrap();
        assert!(ConsensusMsg::decode(&raw).is_err());
    }

    #[test]
    fn old_decoder_rejects_batch() {
        // Pre-batch software has no Batch variant: it must fail closed on
        // batch bytes rather than misreading them as a proposal/vote.
        #[derive(serde::Serialize, serde::Deserialize)]
        enum OldConsensusMsg {
            Proposal { height: u64, round: u32, block: Block },
            Vote { vote: Vote, locked: Option<[u8; 32]> },
            Committed { height: u64, block: Block, certificate: crate::consensus::QuorumCertificate },
        }
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
        let bytes =
            ConsensusMsg::batch_encode(&[ConsensusMsg::Vote { vote: v, locked: None }]).unwrap();
        let res: Result<OldConsensusMsg, _> = bincode::deserialize(&bytes);
        assert!(res.is_err(), "old decoder must reject batch bytes");
    }

    #[test]
    fn is_large_flags_proposals_and_commits() {
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
        let vote = ConsensusMsg::Vote { vote: v, locked: None };
        assert!(!is_large(&vote));
        assert!(!vote.is_large());
        assert!(ConsensusMsg::Proposal { height: 1, round: 0, block: sample_block() }.is_large());
    }

    #[test]
    fn tx_gossip_roundtrip_and_fail_closed() {
        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let bytes = bincode::serialize(&tx).unwrap();
        let raw = serde_json::json!({ "topic": tx_topic("test"), "data": hex::encode(bytes) }).to_string();
        let parsed = parse_tx_incoming(&raw).unwrap();
        assert_eq!(parsed.amount, 10);
        assert!(parsed.verify_signature());

        // fail-closed on garbage
        assert!(parse_tx_incoming("not json").is_none());
        assert!(parse_tx_incoming(r#"{"data":"zz"}"#).is_none());
    }

    /// Build a vote message directly (no signing) whose `height` identifies it.
    /// Structural only: these tests exercise queue ordering, not crypto.
    fn tagged_vote(height: u64) -> ConsensusMsg {
        ConsensusMsg::Vote {
            vote: Vote {
                height,
                round: 0,
                kind: VoteKind::Prevote,
                block_hash: None,
                voter: [height as u8; 32],
                signature: vec![0u8; 64],
            },
            locked: None,
        }
    }

    fn tagged_height(msg: &ConsensusMsg) -> u64 {
        match msg {
            ConsensusMsg::Vote { vote, .. } => vote.height,
            _ => u64::MAX,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ordered_sender_preserves_fifo_order_under_slow_first_send() {
        // Regression for the transport decoupling: chunks must reach the wire in
        // the order they were drained even when the FIRST send is slow (the live
        // case: the peer's handler is not scheduled for hundreds of ms). The
        // sender serializes them, so order is never sacrificed to overlap.
        let seen = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sender = spawn_ordered_sender({
            let seen = Arc::clone(&seen);
            let first = Arc::clone(&first);
            move |chunk: BroadcastChunk| {
                let seen = Arc::clone(&seen);
                let first = Arc::clone(&first);
                async move {
                    let id = tagged_height(&chunk[0]);
                    if first.swap(false, Ordering::SeqCst) {
                        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                    }
                    seen.lock().unwrap().push(id);
                }
            }
        });

        for id in 0u64..5 {
            assert!(sender.enqueue(vec![tagged_vote(id)]), "enqueue {id} must succeed");
        }
        assert_eq!(sender.queued(), 5, "all five chunks are pending before send");

        // The enqueue path is non-blocking: five chunks are already queued while
        // the worker is still sleeping on the first.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while seen.lock().unwrap().len() < 5 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(*seen.lock().unwrap(), vec![0, 1, 2, 3, 4], "FIFO order must hold");
        assert_eq!(sender.queued(), 0, "pending must drain to zero");
    }

    #[test]
    fn superseded_votes_drop_without_touching_proposals_or_commits() {
        // Tail-killer contract: a vote two rounds old at the same height is
        // worthless (no quorum can form there anymore); everything else —
        // proposals, commits, other heights, fresh votes — survives.
        let sk = SigningKey::generate(&mut OsRng);
        let old_prevote = ConsensusMsg::Vote {
            vote: Vote::sign(&sk, 9, 3, VoteKind::Prevote, Some([1u8; 32])),
            locked: None,
        };
        assert!(is_superseded_vote(&old_prevote, 9, 5));
        assert!(is_superseded_vote(&old_prevote, 9, 6));
        assert!(!is_superseded_vote(&old_prevote, 9, 4), "r+1 still counts");
        assert!(!is_superseded_vote(&old_prevote, 10, 5), "other heights never drop");
        assert!(!is_superseded_vote(
            &ConsensusMsg::Proposal { height: 9, round: 0, block: sample_block() },
            9,
            99,
        ));
        let commit = ConsensusMsg::Committed {
            height: 9,
            block: sample_block(),
            certificate: crate::consensus::QuorumCertificate {
                height: 9,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: None,
                signatures: vec![],
            },
        };
        assert!(!is_superseded_vote(&commit, 9, 99));
    }

    #[test]
    fn coalesce_for_send_dedups_and_prunes_in_order() {
        // Duplicate RX coalescing at SEND time: identical votes collapse to
        // the first, superseded ones vanish, proposals keep their slots.
        let sk = SigningKey::generate(&mut OsRng);
        let v = || ConsensusMsg::Vote {
            vote: Vote::sign(&sk, 9, 4, VoteKind::Prevote, Some([1u8; 32])),
            locked: None,
        };
        let stale = ConsensusMsg::Vote {
            vote: Vote::sign(&sk, 9, 1, VoteKind::Prevote, Some([1u8; 32])),
            locked: None,
        };
        let p = ConsensusMsg::Proposal { height: 9, round: 5, block: sample_block() };
        let out = coalesce_for_send(vec![v(), v(), stale, p.clone(), v()], 9, 5);
        assert_eq!(out.len(), 2, "one live vote + the proposal, got {}", out.len());
        assert!(matches!(out[0], ConsensusMsg::Vote { .. }));
        assert!(matches!(out[1], ConsensusMsg::Proposal { .. }));
    }

    #[test]
    fn vote_send_filter_coalesces_duplicates_but_passes_retries_and_nonvotes() {
        // Send-time dedupe across flushes: the second copy inside the window
        // dies, a retry after the window passes, proposals always pass.
        let sk = SigningKey::generate(&mut OsRng);
        let v = ConsensusMsg::Vote {
            vote: Vote::sign(&sk, 9, 4, VoteKind::Prevote, Some([1u8; 32])),
            locked: None,
        };
        let p = ConsensusMsg::Proposal { height: 9, round: 4, block: sample_block() };
        let t0 = Instant::now();
        let mut f = VoteSendFilter::new(Duration::from_millis(200));
        assert!(f.should_send(&v, t0));
        assert!(!f.should_send(&v, t0 + Duration::from_millis(50)), "same-tick dup must coalesce");
        assert!(f.should_send(&p, t0 + Duration::from_millis(50)), "proposals never deduped");
        assert!(f.should_send(&p, t0 + Duration::from_millis(51)), "proposals never deduped twice");
        assert!(
            f.should_send(&v, t0 + Duration::from_millis(1000)),
            "loss-recovery retry past the window must pass"
        );
    }

    #[test]
    fn retransmit_backoff_starts_fast_then_relaxes_without_thundering() {
        // At the live 800ms timeout: fast retries while fresh (loss
        // recovery), then backoff, capped so a wedged round never storms.
        assert_eq!(retransmit_interval_ms(800, 0), 400);
        assert_eq!(retransmit_interval_ms(800, 799), 400);
        assert_eq!(retransmit_interval_ms(800, 800), 800);
        assert_eq!(retransmit_interval_ms(800, 10_000), 1600, "capped at 2x timeout");
        // Small timeouts keep a sane floor instead of a hot loop.
        assert_eq!(retransmit_interval_ms(200, 0), 150);
    }

    #[tokio::test]
    async fn ordered_sender_saturation_returns_false_without_dropping() {
        // Backpressure contract: once the queue is at MAX_PENDING_CHUNKS further
        // enqueues are refused (the caller keeps the message in its outbox) and
        // nothing already accepted is lost. This is what makes an unbounded
        // consensus outbox safe to drain into the sender.
        let sender = spawn_ordered_sender(|_chunk: BroadcastChunk| async {
            // Never completes within the test window: models a wedged transport.
            std::future::pending::<()>().await;
        });

        let cap = MAX_PENDING_CHUNKS;
        for i in 0..cap {
            assert!(
                sender.enqueue(vec![tagged_vote(i as u64)]),
                "chunk {i} within the cap must be accepted"
            );
        }
        assert_eq!(sender.queued(), cap);
        assert!(
            !sender.enqueue(vec![tagged_vote(255)]),
            "enqueue past MAX_PENDING_CHUNKS must be refused, not silently dropped"
        );
        assert_eq!(sender.queued(), cap, "a refused enqueue must not consume a slot");
    }
}

#[cfg(test)]
mod epoch_topic_tests {
    use super::*;

    #[test]
    fn consensus_and_tx_topics_are_scoped_to_the_chain_epoch() {
        // The property that fixes the live symptom: a node on a new genesis must not
        // hear the previous chain's votes and proposals, which were relayed under a
        // fixed topic name and produced endless "wrong height" / state-root rejections.
        let a = consensus_topic("aaaa");
        let b = consensus_topic("bbbb");
        assert_ne!(a, b, "two chains must not share a consensus topic");
        assert_ne!(tx_topic("aaaa"), tx_topic("bbbb"));

        // Distinct namespaces for the two message kinds, so a tx cannot be mistaken
        // for consensus traffic.
        assert_ne!(consensus_topic("aaaa"), tx_topic("aaaa"));

        // Same chain, same topic, every time.
        assert_eq!(consensus_topic("aaaa"), consensus_topic("aaaa"));
    }
}

/// Decoder fuzz regressions (Agent 1): everything a peer sends is untrusted.
/// A panic here is a remote DoS. Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn adversarial_prefixes_never_panic() {
        let mut corpus = vec![vec![], vec![0xFF], vec![0u8; 128]];
        if let Ok(bytes) = (ConsensusMsg::Vote { vote: crate::consensus::Vote::signed_with(
            [7u8; 32],
            1,
            0,
            crate::consensus::VoteKind::Prevote,
            None,
            vec![0u8; 64],
        ), locked: None }
        .encode())
        {
            for n in 0..bytes.len() {
                corpus.push(bytes[..n].to_vec());
            }
            let mut maxed = bytes.clone();
            if !maxed.is_empty() {
                maxed[0] = 0xFF;
                for b in maxed.iter_mut() {
                    *b = 0xFF;
                }
                corpus.push(maxed);
            }
        }
        for input in &corpus {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = ConsensusMsg::decode(input);
            }));
            assert!(r.is_ok(), "ConsensusMsg::decode panicked on len {}", input.len());
        }
        for raw in ["", "not json", "{}", r#"{"data": "zz"}"#] {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_incoming(raw);
                let _ = parse_tx_incoming(raw);
            }));
            assert!(r.is_ok(), "parse_* panicked on {raw:?}");
        }
    }
}

// ==================== Broadcast/probe pacing + inbound bulk guard ====================
//
// Local policy for the 2026-10-14 replication storm (companion to the DHT-store
// pacing in `src/network.rs`). No wire-protocol change: message encodings, topics
// and delivery semantics are untouched; only the TIMING of our own sends/probes
// and the SCHEDULING of bulk inbound work change. Old/new nodes interoperate.
//
// Outbound (this file, wired in):
// * per-peer send floor (`CONS_BCAST_MIN_INTERVAL_MS_DEFAULT`, default 25ms):
//   same-peer bursts are spaced, never dropped — votes keep full priority, only
//   the hammer rate is cut. Broadcasts/probes stay single-attempt (no retry
//   loop anywhere on this path, so there is no retry storm to budget — the
//   bound IS one attempt plus the existing [`PEER_SKIP_THRESHOLD`]/60s failure
//   cooldown across rounds).
// * per-peer probe floor (`CONS_PROBE_MIN_INTERVAL_MS_DEFAULT`, default 5s):
//   overlapping probe ticks defer to the next round instead of re-hammering a
//   peer that is already timing out.
//
// Inbound (policy lives here; the receiver loop in `src/main.rs` owns the call
// site — see [`ConsensusNetwork::admit_inbound`]):
// * per-peer byte-rate accounting for consensus-adjacent traffic. Over-limit
//   peers get DEFERRED (requeue with a bounded wait hint), never dropped — and
//   votes/proposals/commits bypass the limiter entirely, so honest consensus
//   traffic can never starve behind bulk gossip. Only [`ConsensusMsg::Batch`]
//   (bulk gossip) is budget-checked.

/// Min gap between two sends to the same peer in ms (default 25,
/// `STELL_CONS_BCAST_MIN_INTERVAL_MS`). Far below consensus timescales (800ms
/// round timeout), far above hammer rates.
pub const CONS_BCAST_MIN_INTERVAL_MS_DEFAULT: u64 = 25;
/// Min gap between two probes of the same peer in ms (default 5000,
/// `STELL_CONS_PROBE_MIN_INTERVAL_MS`). Probes are full round trips; the live
/// loop already probes on a slow cadence, this only stops overlapping ticks.
pub const CONS_PROBE_MIN_INTERVAL_MS_DEFAULT: u64 = 5_000;
/// Sustained inbound bulk budget per peer in bytes/sec (default 512 KiB,
/// `STELL_INBOUND_BULK_BYTES_PER_SEC`). Bulk gossip above this defers.
pub const INBOUND_BULK_BYTES_PER_SEC_DEFAULT: u64 = 512 * 1024;
/// Burst allowance per peer in bytes (default 1 MiB,
/// `STELL_INBOUND_BULK_BURST_BYTES`). One honest batch always fits.
pub const INBOUND_BULK_BURST_BYTES_DEFAULT: u64 = 1024 * 1024;
/// Cap on the inbound wait hint in ms (default 5000). A deferred peer is
/// requeued after at most this long — deferral is scheduling, not parking.
pub const INBOUND_MAX_DEFER_WAIT_MS: u64 = 5_000;
/// Cap on tracked inbound peers (default 1024). Bounds memory; overflow evicts
/// an arbitrary entry.
pub const INBOUND_MAX_TRACKED_PEERS: usize = 1024;

/// Effective per-peer send floor (`STELL_CONS_BCAST_MIN_INTERVAL_MS`, default 25).
pub fn cons_bcast_min_interval_ms() -> u64 {
    std::env::var("STELL_CONS_BCAST_MIN_INTERVAL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(CONS_BCAST_MIN_INTERVAL_MS_DEFAULT)
}

/// Effective per-peer probe floor (`STELL_CONS_PROBE_MIN_INTERVAL_MS`, default 5000).
pub fn cons_probe_min_interval_ms() -> u64 {
    std::env::var("STELL_CONS_PROBE_MIN_INTERVAL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= 100)
        .unwrap_or(CONS_PROBE_MIN_INTERVAL_MS_DEFAULT)
}

/// Effective inbound bulk rate (`STELL_INBOUND_BULK_BYTES_PER_SEC`, default 512 KiB).
pub fn inbound_bulk_bytes_per_sec() -> u64 {
    std::env::var("STELL_INBOUND_BULK_BYTES_PER_SEC")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= 1024)
        .unwrap_or(INBOUND_BULK_BYTES_PER_SEC_DEFAULT)
}

/// Effective inbound burst (`STELL_INBOUND_BULK_BURST_BYTES`, default 1 MiB).
pub fn inbound_bulk_burst_bytes() -> u64 {
    std::env::var("STELL_INBOUND_BULK_BURST_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= 1024)
        .unwrap_or(INBOUND_BULK_BURST_BYTES_DEFAULT)
}

/// Pure pacing decision: due when never sent (`None`) or the floor elapsed.
/// Shared by the broadcast floor and the probe floor (both are "at most one per
/// interval per peer"). Time-injected for deterministic tests.
pub fn pace_due(last_ms: Option<u64>, now_ms: u64, min_interval_ms: u64) -> bool {
    match last_ms {
        None => true,
        Some(last) => now_ms.saturating_sub(last) >= min_interval_ms,
    }
}

/// Remaining wait in ms before `peer` may be sent to again (0 = now).
/// Pure: the caller stamps the send time separately.
pub fn pace_wait_ms(last_ms: Option<u64>, now_ms: u64, min_interval_ms: u64) -> u64 {
    match last_ms {
        None => 0,
        Some(last) => min_interval_ms.saturating_sub(now_ms.saturating_sub(last)),
    }
}

/// True when a message must bypass the inbound bulk limiter.
///
/// Votes, proposals and commits are the honest-consensus path: they are small,
/// quorum-critical, and must never wait behind bulk gossip. Only [`ConsensusMsg::Batch`]
/// (many messages gossiped as one — the bulk shape) is budget-checked, and even
/// batches are DEFERRED, never dropped.
pub fn inbound_is_critical(msg: &ConsensusMsg) -> bool {
    !matches!(msg, ConsensusMsg::Batch(_))
}

/// Inbound admission outcome. There is deliberately no `Drop` variant: bulk
/// over budget is requeued with a bounded wait hint; honest traffic is never
/// silently discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundDecision {
    /// Handle now.
    Allow,
    /// Requeue and retry after `wait_ms` (bounded by [`INBOUND_MAX_DEFER_WAIT_MS`]).
    Defer { wait_ms: u64 },
}

/// Per-peer byte-rate limiter for inbound bulk traffic.
///
/// Token bucket per peer: `burst` tokens capacity, refilled at `rate_bps`.
/// Critical messages bypass (see [`inbound_is_critical`]) without consuming
/// budget, so votes never starve the bulk lane nor are starved by it. Bulk
/// messages that fit are admitted; the rest defer with a rate-derived wait
/// hint. Bounded to [`INBOUND_MAX_TRACKED_PEERS`] keys.
#[derive(Debug)]
pub struct InboundBulkLimiter {
    rate_bps: f64,
    burst: f64,
    peers: HashMap<String, InboundBucket>,
    max_peers: usize,
}

#[derive(Debug, Clone)]
struct InboundBucket {
    tokens: f64,
    last_ms: u64,
}

impl InboundBulkLimiter {
    /// General constructor: sustained `rate_bps` bytes/sec, `burst` bytes headroom.
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            rate_bps: (rate_bps.max(1)) as f64,
            burst: (burst_bytes.max(1)) as f64,
            peers: HashMap::new(),
            max_peers: INBOUND_MAX_TRACKED_PEERS,
        }
    }

    /// Production shape from the `STELL_INBOUND_*` env.
    pub fn with_defaults() -> Self {
        Self::from_env()
    }

    /// Live shape from the `STELL_INBOUND_*` env (local policy: nodes MAY differ).
    pub fn from_env() -> Self {
        Self::new(inbound_bulk_bytes_per_sec(), inbound_bulk_burst_bytes())
    }

    /// Peers currently tracked (for the memory-bound pin).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Admit `bytes` from `peer` at `now_ms`. Critical traffic always passes
    /// without touching the budget; bulk passes while tokens cover it and
    /// defers with a bounded wait hint otherwise. Never drops.
    pub fn admit(
        &mut self,
        peer: &str,
        bytes: u64,
        critical: bool,
        now_ms: u64,
    ) -> InboundDecision {
        if critical {
            return InboundDecision::Allow;
        }
        if !self.peers.contains_key(peer) && self.peers.len() >= self.max_peers {
            if let Some(k) = self.peers.keys().next().cloned() {
                self.peers.remove(&k);
            }
        }
        let bucket = self.peers.entry(peer.to_string()).or_insert(InboundBucket {
            tokens: self.burst,
            last_ms: now_ms,
        });
        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        if elapsed > 0 {
            bucket.tokens =
                (bucket.tokens + elapsed as f64 / 1000.0 * self.rate_bps).min(self.burst);
            bucket.last_ms = now_ms;
        }
        let need = bytes as f64;
        if bucket.tokens >= need {
            bucket.tokens -= need;
            InboundDecision::Allow
        } else {
            let shortfall = need - bucket.tokens;
            let wait = (shortfall / self.rate_bps * 1000.0).ceil() as u64;
            InboundDecision::Defer { wait_ms: wait.min(INBOUND_MAX_DEFER_WAIT_MS).max(1) }
        }
    }
}

impl ConsensusNetwork {
    /// Bounded wait before the next send to `pid`, stamping this send now.
    /// Returns 0 when the floor already elapsed. Snapshot-then-stamp under one
    /// short lock, never held across await.
    fn bcast_wait_and_stamp(&self, pid: &[u8; 20]) -> u64 {
        let now = epoch_ms();
        let floor = cons_bcast_min_interval_ms();
        match self.bcast_last_ms.lock() {
            Ok(mut m) => {
                let wait = pace_wait_ms(m.get(pid).copied(), now, floor);
                m.insert(*pid, now);
                wait.min(floor)
            }
            Err(_) => 0,
        }
    }

    /// True when `pid` is due for a probe (floor elapsed), stamping this probe.
    /// Snapshot-then-stamp under one short lock, never held across await.
    fn probe_due_and_stamp(&self, pid: &[u8; 20]) -> bool {
        let now = epoch_ms();
        let floor = cons_probe_min_interval_ms();
        match self.probe_last_ms.lock() {
            Ok(mut m) => {
                if !pace_due(m.get(pid).copied(), now, floor) {
                    return false;
                }
                m.insert(*pid, now);
                true
            }
            Err(_) => true,
        }
    }

    /// Inbound admission for one received message from `peer_hex`.
    ///
    /// Hook for the receiver loop: `bytes` is the decoded message size,
    /// `msg` its kind. Votes/proposals/commits always [`InboundDecision::Allow`];
    /// bulk batches [`InboundDecision::Allow`] while the peer is within budget
    /// and [`InboundDecision::Defer`] with a bounded wait hint when over — the
    /// loop requeues deferred batches instead of handling them inline, which
    /// keeps a bulk flood from wedging vote handling. Nothing is ever dropped.
    pub fn admit_inbound(
        &self,
        peer_hex: &str,
        msg: &ConsensusMsg,
        bytes: usize,
    ) -> InboundDecision {
        let now = epoch_ms();
        match self.inbound_bulk.lock() {
            Ok(mut l) => l.admit(peer_hex, bytes as u64, inbound_is_critical(msg), now),
            Err(_) => InboundDecision::Allow,
        }
    }
}
