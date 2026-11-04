//! Consensus P2P transport: carries proposals and votes between validators over
//! the infnode pubsub layer — WITHOUT modifying infnode.
//!
//! Design (per the "blockchain stays outside infnode" rule):
//!  - infnode is used only through its public API:
//!      * `register_app_sub(topic)` to receive app-level messages
//!      * `request_to(peer, "pubsub.msg", {topic,data})` to deliver a message
//!        to the peer's app subscription
//!      * `send_to(peer, "pubsub.msg", {topic,data})` for the fire-and-forget
//!        form of the same delivery (votes/proposals): the frame is written and
//!        the peer's `RESP` is NOT awaited, so the remote round trip leaves
//!        the critical path. See [`message_is_fire_and_forget`].
//!  - Messages are an enum serialized with bincode and hex-encoded into `data`.
//!
//! Security: every inbound message is size-checked and bincode-decoded; malformed
//! or oversized payloads are rejected. Vote signatures are verified downstream by
//! the consensus engine, so a forged vote is dropped there.

use crate::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use crate::network::P2pNetworkAdapter;
use crate::sharding::{Block, ShardRegistry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
///
/// Safety role (DoS bound + liveness): bounds per-batch verify work so one
/// gossip batch cannot force unbounded signature checks; large enough that an
/// honest round's votes still fit in few batches.
pub const MAX_BATCH_ITEMS: usize = 32;

/// Max encoded bytes of a single batch (P3-H4 gossip batching).
///
/// Safety role (DoS bound): caps batch wire size far below
/// [`MAX_CONSENSUS_MSG`] so a single peer cannot force a 32 MiB
/// deserialize/verify from one envelope.
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
            vote.height == height && vote.round.saturating_add(SUPERSEDED_ROUND_LAG) <= round
        }
        _ => false,
    }
}

/// Coalesce one send batch: drop superseded votes for `(height, round)` and
/// collapse duplicate votes to their first occurrence, preserving order.
/// Proposals, commits and batches pass through untouched (order included).
pub fn coalesce_for_send(msgs: Vec<ConsensusMsg>, height: u64, round: u32) -> Vec<ConsensusMsg> {
    let mut seen: std::collections::HashSet<VoteWireKey> = std::collections::HashSet::new();
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
        Self {
            ttl,
            sent: HashMap::new(),
        }
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
    Proposal {
        height: u64,
        round: u32,
        block: Block,
    },
    /// A prevote or precommit. `locked` carries the sender's locked block hash,
    /// and is Some ONLY on nil prevotes cast because of a lock (validRound-lite):
    /// it tells the block's author "I am stuck on YOUR body, re-propose it at
    /// your slot and we converge". Never set on block votes or precommits, so
    /// persisted quorum certificates stay hintless and byte-compatible.
    /// Wire-only (gossip, never persisted): both sides upgrade together.
    Vote {
        vote: Vote,
        locked: Option<[u8; 32]>,
    },
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

/// True when a send outcome may be recorded in the peer-health ledger.
///
/// Only an ACKNOWLEDGED send proves the peer is alive: a fire-and-forget
/// send proves only that the LOCAL write succeeded. Recording the latter as
/// a success RESET the peer's consecutive-failure counter, so a peer that
/// fails intermittently (it accepts the write, never processes the message)
/// was never skipped and never evicted (audit W6.7).
///
/// Pure so the rule is testable without a live peer.
pub fn send_outcome_records_health(fire_and_forget: bool) -> bool {
    !fire_and_forget
}

/// True when a message must be delivered WITHOUT waiting for the peer's ACK.
///
/// Votes and proposals are quorum-critical, small and idempotent: the peer's
/// response is a fixed `{"ok":true,...}` that carries no information the
/// sender needs. But the response is produced by the peer's handler AFTER
/// that handler has been scheduled — 300-1200 ms on a WAN link — and the
/// ordered sender processes chunks one at a time, so every awaited ACK also
/// delays the NEXT chunk. The ACK is therefore pure latency.
///
/// These go out fire-and-forget: only the LOCAL write is awaited (stream open
/// + frame write + finish), so the sender's budget bounds the local spend and
///   the remote round trip leaves the critical path entirely.
///
/// [`ConsensusMsg::Committed`] keeps the acknowledged form: it is the catch-up
/// path (a full block + QC) and its ACK is the sender's proof that the peer
/// really got the block. It is also rare, so it costs nothing to wait for it.
pub fn message_is_fire_and_forget(msg: &ConsensusMsg) -> bool {
    matches!(
        msg,
        ConsensusMsg::Vote { .. } | ConsensusMsg::Proposal { .. }
    )
}

/// True when EVERY member of a chunk is safe to send fire-and-forget.
///
/// A chunk that carries a [`ConsensusMsg::Committed`] keeps the acknowledged
/// path for the WHOLE chunk: the catch-up proof must not be traded away for
/// latency. An empty chunk is never fire-and-forget (nothing to send).
pub fn batch_is_fire_and_forget(msgs: &[ConsensusMsg]) -> bool {
    !msgs.is_empty() && msgs.iter().all(message_is_fire_and_forget)
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
            ConsensusMsg::Vote { .. } => {
                self.encode().map(|b| b.len() >= 64 * 1024).unwrap_or(false)
            }
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
        // Anti-recursion DoS: if top-level is a Batch (variant 3), reject nested batch before deserializing
        if bytes.starts_with(&[3, 0, 0, 0]) && bytes.len() >= 16 && bytes[12..16] == [3, 0, 0, 0] {
            return Err("nested batch".to_string());
        }
        use bincode::Options;
        let msg: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_CONSENSUS_MSG as u64)
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| format!("consensus msg decode: {e}"))?;
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
    /// Global inbound-bandwidth shed meter (see [`InboundShed`]): a per-second
    /// inbound byte counter. Over [`INBOUND_SHED_BYTES_PER_SEC`] new
    /// connection attempts are refused ([`Self::shed_refuse_new`]) while
    /// existing connections keep serving. Mutex-only, never held across await.
    inbound_shed: Mutex<InboundShed>,
    /// Peer evictions imposed by the target policy (see
    /// [`PEER_EVICT_TARGET_MAX`]). Monotonic test/monitoring counter.
    peer_evicted_total: AtomicU64,
}

/// Consecutive-failure counter for one peer (see `peer_health`).
#[derive(Clone, Copy, Default)]
struct PeerHealth {
    /// Consecutive failures (transport error or timeout). Reset on success.
    fails: u32,
    /// When the last failure happened (cooldown measured from here).
    last_fail: Option<std::time::Instant>,
    /// Earliest time a new dial to this peer may be attempted (exponential
    /// dial backoff, see [`dial_backoff_ms`]). Set on each failure once the
    /// skip threshold is reached, cleared on success (entry removed). This
    /// extends the fixed [`PEER_SKIP_COOLDOWN`): a peer that stays dead is
    /// retried on a growing schedule instead of every cooldown window, so a
    /// down peer stops costing a handshake-timeout dial every few seconds.
    backoff_until: Option<std::time::Instant>,
}

/// Skip a peer after this many consecutive failures.
///
/// Safety role (liveness): one slow/dead peer's consecutive timeouts stop
/// stalling the flush once the streak reaches this bound; a single timeout
/// never skips (avoids cascade evictions).
const PEER_SKIP_THRESHOLD: u32 = 3;
/// ...and retry it after this long (short cooldown so reconnects don't stall consensus).
const PEER_SKIP_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3);

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
fn peer_in_cooldown(
    fails: u32,
    last_fail: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
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

/// Base dial-backoff delay in ms (default 2000, `STELL_DIAL_BACKOFF_BASE_MS`):
/// a peer that reaches [`PEER_SKIP_THRESHOLD`] consecutive dial/handshake
/// failures waits this long (jittered, see [`dial_backoff_jittered_ms`])
/// before its first retry, doubling per further consecutive failure.
pub const DIAL_BACKOFF_BASE_MS_DEFAULT: u64 = 2000;
/// Cap for the exponential dial backoff in ms (default 300000 = 5min,
/// `STELL_DIAL_BACKOFF_MAX_MS`). A peer that never recovers is re-dialed at
/// most this rarely — silent for known-dead peers, while a returning peer's
/// first success resets the streak to zero immediately.
pub const DIAL_BACKOFF_MAX_MS_DEFAULT: u64 = 300_000;
/// Process-wide dial budget in dial attempts per second (default 4,
/// `STELL_DIAL_BUDGET_PER_SEC`). A min-interval gate shared by every dial
/// initiation in this process (both joins + probes), so a fleet of dead
/// peers can never turn one tick into a dial storm.
pub const DIAL_BUDGET_PER_SEC_DEFAULT: u32 = 4;

/// Parse helper for [`dial_backoff_base_ms`]: garbage/zero falls back to the
/// default (clamped, never disabled). Time-injected so tests need no env.
pub fn parse_dial_backoff_base_ms(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DIAL_BACKOFF_BASE_MS_DEFAULT)
}

/// Effective dial-backoff base (`STELL_DIAL_BACKOFF_BASE_MS`, default 2000).
pub fn dial_backoff_base_ms() -> u64 {
    parse_dial_backoff_base_ms(std::env::var("STELL_DIAL_BACKOFF_BASE_MS").ok())
}

/// Parse helper for [`dial_backoff_max_ms`]: garbage/zero falls back to the
/// default (clamped, never disabled). Time-injected so tests need no env.
pub fn parse_dial_backoff_max_ms(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DIAL_BACKOFF_MAX_MS_DEFAULT)
}

/// Effective dial-backoff cap (`STELL_DIAL_BACKOFF_MAX_MS`, default 300000).
pub fn dial_backoff_max_ms() -> u64 {
    parse_dial_backoff_max_ms(std::env::var("STELL_DIAL_BACKOFF_MAX_MS").ok())
}

/// Parse helper for [`dial_budget_per_sec`]: garbage/zero falls back to the
/// default (clamped to >= 1, never disabled). Time-injected so tests need
/// no env.
pub fn parse_dial_budget_per_sec(raw: Option<String>) -> u32 {
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(DIAL_BUDGET_PER_SEC_DEFAULT)
}

/// Effective process-wide dial budget (`STELL_DIAL_BUDGET_PER_SEC`, default 4).
pub fn dial_budget_per_sec() -> u32 {
    parse_dial_budget_per_sec(std::env::var("STELL_DIAL_BUDGET_PER_SEC").ok())
}

/// Pure exponential dial backoff (unit-tested): below [`PEER_SKIP_THRESHOLD`]
/// consecutive failures there is no backoff (0 — healthy peers see zero
/// behavior change); at/above it the delay is `base * 2^(fails - THRESHOLD)`
/// capped at `cap`. Success resets the streak to zero, so this is only ever
/// called with a live failure count and a zero count always yields zero.
pub fn dial_backoff_ms(consec_fails: u32, base_ms: u64, cap_ms: u64) -> u64 {
    if consec_fails < PEER_SKIP_THRESHOLD {
        return 0;
    }
    let base = base_ms.max(1);
    let cap = cap_ms.max(1);
    let shift = consec_fails
        .saturating_sub(PEER_SKIP_THRESHOLD)
        .min(20);
    base.saturating_mul(1u64 << shift).min(cap)
}

/// Pure equal-jitter mapping (unit-tested): spreads one backoff level over
/// `[backoff/2, backoff]` using caller-provided randomness (`jitter_seed`,
/// e.g. `rand::random::<u64>()`), so co-dead peers desynchronize their
/// retries instead of re-hammering in lockstep. A zero backoff stays zero.
pub fn dial_backoff_jittered_ms(backoff_ms: u64, jitter_seed: u64) -> u64 {
    if backoff_ms == 0 {
        return 0;
    }
    let half = backoff_ms / 2;
    half + jitter_seed % (backoff_ms - half + 1)
}

/// Pure dial-suppression decision (unit-tested): a peer is suppressed while
/// its fixed failure cooldown holds OR while its exponential backoff has not
/// expired yet. Healthy peers (no backoff, cold cooldown) are never
/// suppressed.
pub fn peer_dial_suppressed(
    fails: u32,
    last_fail: Option<std::time::Instant>,
    backoff_until: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    peer_in_cooldown(fails, last_fail, now)
        || backoff_until.is_some_and(|t| now < t)
}

/// Pure global-budget decision (unit-tested): at most `per_sec` dials per
/// second process-wide, enforced as a min-interval gate
/// (`interval = 1000/per_sec` ms). `None` (no dial yet) always allows.
pub fn dial_budget_should_allow(
    last_ms: Option<u64>,
    now_ms: u64,
    per_sec: u32,
) -> bool {
    let interval = 1000u64 / u64::from(per_sec.max(1));
    match last_ms {
        None => true,
        Some(last) => now_ms.saturating_sub(last) >= interval,
    }
}

/// Stateful min-interval dial-budget gate (the testable core of the
/// process-wide budget; the live gate below is one shared instance of this
/// shape). Mutex-only, never held across await.
pub struct DialBudget {
    per_sec: u32,
    last_ms: Mutex<Option<u64>>,
}

impl DialBudget {
    /// New gate with `per_sec` dial attempts per second (clamped to >= 1).
    pub fn new(per_sec: u32) -> Self {
        Self {
            per_sec: per_sec.max(1),
            last_ms: Mutex::new(None),
        }
    }

    /// Try to take one dial slot at `now_ms` (epoch-ms). Returns true and
    /// stamps the slot when due, false (no stamp, caller must skip the dial)
    /// when the budget is exhausted.
    pub fn try_acquire_at(&self, now_ms: u64) -> bool {
        match self.last_ms.lock() {
            Ok(mut last) => {
                if dial_budget_should_allow(*last, now_ms, self.per_sec) {
                    *last = Some(now_ms);
                    true
                } else {
                    false
                }
            }
            Err(_) => true,
        }
    }
}

/// Process-wide last-dial timestamp backing [`try_acquire_dial_slot`].
static DIAL_BUDGET_LAST_MS: OnceLock<Mutex<Option<u64>>> = OnceLock::new();

/// Try to take one process-wide dial slot now. Returns true when this dial
/// may proceed, false when the global budget (`STELL_DIAL_BUDGET_PER_SEC`,
/// default 4/s) is exhausted and the caller must skip the dial (debug log,
/// never warn: budget deferral is normal backpressure, not failure).
pub(crate) fn try_acquire_dial_slot() -> bool {
    let slot = DIAL_BUDGET_LAST_MS.get_or_init(|| Mutex::new(None));
    match slot.lock() {
        Ok(mut last) => {
            let now = epoch_ms();
            if dial_budget_should_allow(*last, now, dial_budget_per_sec()) {
                *last = Some(now);
                true
            } else {
                false
            }
        }
        Err(_) => true,
    }
}

/// Jittered backoff expiry for a fresh failure at `now` with `fails`
/// consecutive failures (`None` below the skip threshold: healthy peers
/// carry no backoff state at all).
fn peer_backoff_until(now: std::time::Instant, fails: u32) -> Option<std::time::Instant> {
    let backoff = dial_backoff_ms(fails, dial_backoff_base_ms(), dial_backoff_max_ms());
    if backoff == 0 {
        None
    } else {
        Some(
            now + Duration::from_millis(dial_backoff_jittered_ms(
                backoff,
                rand::random::<u64>(),
            )),
        )
    }
}

/// True when `pid` is already a known-dead peer (failure streak at/above the
/// skip threshold). Per-attempt outcome logs consult this to stay quiet for
/// known-dead peers (debug) while staying loud for live ones (warn).
fn health_is_known_dead(health: &Mutex<HashMap<[u8; 20], PeerHealth>>, pid: &[u8; 20]) -> bool {
    match health.lock() {
        Ok(h) => h.get(pid).is_some_and(|e| e.fails >= PEER_SKIP_THRESHOLD),
        Err(_) => false,
    }
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
            inbound_shed: Mutex::new(InboundShed::new(INBOUND_SHED_BYTES_PER_SEC)),
            peer_evicted_total: AtomicU64::new(0),
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
            inbound_shed: Mutex::new(InboundShed::new(INBOUND_SHED_BYTES_PER_SEC)),
            peer_evicted_total: AtomicU64::new(0),
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
                Some(ph) => peer_dial_suppressed(ph.fails, ph.last_fail, ph.backoff_until, now),
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// Record one send/probe outcome for the backoff ledger. Returns the
    /// pre-update failure streak (see [`Self::record_health`]).
    fn peer_record(&self, pid: [u8; 20], ok: bool) -> u32 {
        Self::record_health(&self.peer_health, pid, ok)
    }

    /// Ledger update shared by the inline paths ([`Self::peer_record`]) and
    /// the DETACHED per-peer tasks ([`Self::send_one_peer`]), which only hold
    /// an `Arc` to the ledger — never `&self`, because they may outlive the
    /// flush that spawned them.
    ///
    /// Returns the failure streak BEFORE this update (0 when the peer was
    /// healthy): callers use it to keep per-attempt logs quiet for
    /// known-dead peers (a streak already at/above the threshold logs at
    /// debug) while the ledger itself keeps exactly one loud line per
    /// transition (warn healthy->failing here, info failing->healthy here).
    fn record_health(health: &Mutex<HashMap<[u8; 20], PeerHealth>>, pid: [u8; 20], ok: bool) -> u32 {
        let now = std::time::Instant::now();
        match health.lock() {
            Ok(mut h) => {
                if ok {
                    match h.remove(&pid) {
                        Some(prev) if prev.fails >= PEER_SKIP_THRESHOLD => {
                            tracing::info!(
                                "[net] peer {} recovered after {} consecutive failures: resuming dials",
                                hex::encode(pid),
                                prev.fails,
                            );
                            prev.fails
                        }
                        Some(prev) => prev.fails,
                        None => 0,
                    }
                } else {
                    let fails_before = h.get(&pid).map_or(0, |e| e.fails);
                    let e = h.entry(pid).or_default();
                    e.fails = e.fails.saturating_add(1);
                    e.last_fail = Some(now);
                    e.backoff_until = peer_backoff_until(now, e.fails);
                    if e.fails == PEER_SKIP_THRESHOLD {
                        tracing::warn!(
                            "[net] peer {} failing {}x in a row: skipping sends/probes for {:?}",
                            hex::encode(pid),
                            e.fails,
                            PEER_SKIP_COOLDOWN,
                        );
                    } else if e.fails > PEER_SKIP_THRESHOLD {
                        // Known-dead peer: one debug line per backoff-level
                        // change, never a warn — the loud line already fired
                        // at the healthy->failing transition above.
                        tracing::debug!(
                            "[net] peer {} still failing ({}x in a row): next dial no earlier than {:?}",
                            hex::encode(pid),
                            e.fails,
                            e.backoff_until,
                        );
                    }
                    fails_before
                }
            }
            Err(_) => 0,
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
            let pid = p
                .node_id_raw()
                .or_else(|_| self.adapter.node.resolve(&p.name));
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
            // Global dial budget (see `DIAL_BUDGET_PER_SEC_DEFAULT`): at most
            // N dials/sec process-wide even with many dead peers, so one
            // join window can never become a dial storm. Deferral is normal
            // backpressure (debug), never failure (warn).
            if !try_acquire_dial_slot() {
                tracing::debug!(
                    "[net] join {} deferred (global dial budget {}/s exhausted)",
                    hex::encode(pid),
                    dial_budget_per_sec(),
                );
                continue;
            }
            // Inbound shed (flood control): while the global per-second
            // inbound counter is over budget, refuse NEW dials (counted in
            // the shed meter) and keep serving existing connections —
            // cheapest-first. No-op when not shedding, so honest joins are
            // byte-identical.
            if self.shed_refuse_new() {
                tracing::debug!(
                    "[net] join {} refused (inbound shed active, keeping existing)",
                    hex::encode(pid),
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
            // Backoff suppression (dial-backoff fix): a known-dead peer is
            // not re-probed until its backoff expires — a probe IS a dial
            // (full `request_to` round trip with a handshake-timeout tax to
            // a dead endpoint). Suppressed probes cost nothing and log at
            // debug; the ledger's transition lines stay the only loud ones.
            if self.peer_skipped(&pid) {
                tracing::debug!(
                    "[net] probe {} skipped (dial backoff, no dial)",
                    hex::encode(pid)
                );
                continue;
            }
            // Global dial budget: probes share the process-wide N-dials/sec
            // gate with joins (see `try_acquire_dial_slot`).
            if !try_acquire_dial_slot() {
                tracing::debug!(
                    "[net] probe {} deferred (global dial budget {}/s exhausted)",
                    hex::encode(pid),
                    dial_budget_per_sec(),
                );
                continue;
            }
            let t = std::time::Instant::now();
            let r = tokio::time::timeout(
                send_timeout(),
                self.adapter
                    .node
                    .request_to(pid, "core.ping", b"{}".to_vec()),
            )
            .await;
            match r {
                Ok(Ok(_)) => {
                    let fails_before = self.peer_record(pid, true);
                    self.probe_timeout_clear(&pid);
                    if fails_before >= PEER_SKIP_THRESHOLD {
                        // Recovery already logged its one loud line inside
                        // `record_health`; keep this attempt quiet.
                        tracing::debug!(
                            "[net] probe {} ok in {:?} (recovered)",
                            hex::encode(pid),
                            t.elapsed()
                        );
                    } else {
                        tracing::info!("[net] probe {} ok in {:?}", hex::encode(pid), t.elapsed());
                    }
                }
                Ok(Err(e)) => {
                    self.peer_record(pid, false);
                    // A fast error still proves the connection answers, so it
                    // breaks the TIMEOUT streak: eviction is for consecutive
                    // timeouts, not for any failure.
                    self.probe_timeout_clear(&pid);
                    if health_is_known_dead(&self.peer_health, &pid) {
                        // Known-dead peer: the transition warn already fired;
                        // per-attempt errors stay at debug.
                        tracing::debug!(
                            "[net] probe {} err in {:?}: {e}",
                            hex::encode(pid),
                            t.elapsed()
                        );
                    } else {
                        tracing::warn!(
                            "[net] probe {} err in {:?}: {e}",
                            hex::encode(pid),
                            t.elapsed()
                        );
                    }
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
                    } else if health_is_known_dead(&self.peer_health, &pid) {
                        // Single (or sub-threshold) timeout on a known-dead
                        // peer: record + move on quietly. The connection
                        // stays; a transient stall must not cascade into a
                        // conn-close/redial storm.
                        tracing::debug!(
                            "[net] probe {} TIMEOUT after {:?}; keeping conn ({streak}/{after} consecutive timeouts)",
                            hex::encode(pid),
                            t.elapsed(),
                        );
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
        // Peer-target policy (flood control): no-op at/below target, so the
        // probe cadence is unchanged on honest stands.
        self.enforce_peer_target().await;
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
        // Fire-and-forget for votes/proposals: the peer's ACK carries no
        // information the sender needs, but it costs a full round trip
        // (300-1200 ms on WAN) and the ordered sender is FIFO, so an awaited
        // ACK also delays the NEXT chunk. A chunk carrying a `Committed`
        // keeps the acknowledged form (the catch-up proof).
        let fof = batch_is_fire_and_forget(msgs);
        self.send_payload_with_skip(payload, exempt, fof).await;
    }

    /// Single-encode fallback for a chunk that failed batch encoding (see
    /// `broadcast_batch`): each message goes out alone, so one oversize
    /// member cannot sink its batch-mates. Proposals (which forced the
    /// fallback by their size) travel singleton; small votes regroup in later
    /// flushes. Each singleton is still capped at MAX_CONSENSUS_MSG.
    async fn broadcast_singles(&self, msgs: &[ConsensusMsg]) {
        for m in msgs {
            let exempt = committed_bypasses_skip(m);
            let fof = message_is_fire_and_forget(m);
            match m.encode() {
                Ok(b) => {
                    if b.len() > MAX_CONSENSUS_MSG {
                        tracing::warn!(
                            "[consensus] singleton message too large ({} bytes), dropping",
                            b.len()
                        );
                        continue;
                    }
                    let payload =
                        serde_json::json!({ "topic": self.topic, "data": hex::encode(b) })
                            .to_string()
                            .into_bytes();
                    self.send_payload_with_skip(payload, exempt, fof).await;
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
    ///
    /// `fire_and_forget` sends the frame WITHOUT awaiting the peer's `RESP`
    /// (see [`message_is_fire_and_forget`]): only the local write is awaited,
    /// so the round trip (300-1200 ms on WAN) leaves the critical path. The
    /// join budget below still bounds the LOCAL spend: it caps how long the
    /// flush waits for the per-peer tasks, and a peer that has not even
    /// finished its local write is detached (it keeps sending and still
    /// records its outcome).
    #[allow(dead_code)] // GATE: thin wrapper kept for the catch-up send path; no current caller
    async fn send_payload(&self, payload: Vec<u8>) {
        self.send_payload_with_skip(payload, false, false).await;
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
        fire_and_forget: bool,
    ) {
        if wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
        let t = std::time::Instant::now();
        // Fire-and-forget: write the frame and return — the peer's ACK is not
        // awaited. The acknowledged form keeps `request_to` for the catch-up
        // path, where the ACK is the delivery proof.
        let r = if fire_and_forget {
            tokio::time::timeout(send_timeout(), async {
                adapter
                    .node
                    .send_to(pid, "pubsub.msg", payload)
                    .await
                    .map(|_| Vec::new())
            })
            .await
        } else {
            tokio::time::timeout(
                send_timeout(),
                adapter.node.request_to(pid, "pubsub.msg", payload),
            )
            .await
        };
        let elapsed = t.elapsed();
        // Stage (b): the whole send for this peer. infnode does not
        // expose its internal dial-vs-response split, so (b1)/(b2) are not
        // reachable from here (see the infnode instrumentation note in the
        // report); this names the transport stage vs stage (a).
        log_stage(
            &REQUEST_STAGE_GATE,
            if fire_and_forget {
                "send_to"
            } else {
                "request_to"
            },
            &format!("peer={} total", hex::encode(pid)),
            elapsed,
        );
        let hexid = hex::encode(pid);
        // Quiet-known-dead rule (dial-backoff fix): the ledger keeps exactly
        // one loud line per transition (warn healthy->failing, info
        // failing->healthy inside `record_health`); per-attempt outcomes for
        // an already-known-dead peer log at debug so a down peer stops
        // emitting a warn per broadcast flush.
        let loud_attempt = !health_is_known_dead(&health, &pid);
        match r {
            Ok(Ok(resp)) if resp.starts_with(b"{\"ok\":false") => {
                Self::record_health(&health, pid, false);
                if loud_attempt {
                    tracing::warn!(
                        "[consensus] broadcast to {} denied/fast-fail in {:?}: {}",
                        hexid,
                        elapsed,
                        String::from_utf8_lossy(&resp),
                    );
                } else {
                    tracing::debug!(
                        "[consensus] broadcast to {} denied/fast-fail in {:?} (known-dead peer): {}",
                        hexid,
                        elapsed,
                        String::from_utf8_lossy(&resp),
                    );
                }
            }
            Ok(Ok(_)) => {
                // HEALTH LEDGER (audit W6.7): a FIRE-AND-FORGET send only
                // proves that the LOCAL write succeeded — the peer never
                // acknowledged anything, so this is NOT evidence that the
                // peer is alive. Recording it as a success RESET the peer's
                // consecutive-failure counter, so a peer that fails
                // intermittently (accepts the write, never processes the
                // message) was never skipped and never evicted. Only an
                // ACKNOWLEDGED send may mark a peer healthy; a fire-and-
                // forget success leaves the ledger untouched.
                let mut recovered = false;
                if send_outcome_records_health(fire_and_forget) {
                    let fails_before = Self::record_health(&health, pid, true);
                    recovered = fails_before >= PEER_SKIP_THRESHOLD;
                }
                let took = elapsed;
                // Slow-but-successful is exactly what hid the tick stall:
                // the consensus loop AWAITS every broadcast, so a peer
                // that answers in 1-2s (under the 2s cap, therefore never
                // logged) stretches a tick to seconds with no warning.
                // (A recovery already logged its one loud line; keep that
                // attempt quiet.)
                if took >= std::time::Duration::from_millis(300) && !recovered {
                    tracing::warn!(
                        "[consensus] broadcast to {} slow: {:?} (still under the cap)",
                        hexid,
                        took
                    );
                } else if fire_and_forget {
                    // Fire-and-forget: the local write is all we waited for.
                    // NOT a delivery proof — the retransmit path (the
                    // consensus loop's periodic re-send) and the round
                    // change are what recover a lost message.
                    tracing::debug!(
                        "[consensus] fire-and-forget send to {} handed off in {:?} (no delivery proof)",
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
                if loud_attempt {
                    tracing::warn!(
                        "[consensus] broadcast to {} transport-err in {:?}: {e}",
                        hexid,
                        elapsed,
                    );
                } else {
                    tracing::debug!(
                        "[consensus] broadcast to {} transport-err in {:?} (known-dead peer): {e}",
                        hexid,
                        elapsed,
                    );
                }
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
                if loud_attempt {
                    tracing::warn!(
                        "[consensus] broadcast to {} TIMEOUT after {:?}",
                        hexid,
                        elapsed,
                    );
                } else {
                    tracing::debug!(
                        "[consensus] broadcast to {} TIMEOUT after {:?} (known-dead peer)",
                        hexid,
                        elapsed,
                    );
                }
                // See above: time out, log, move on -- do not evict.
            }
        }
    }

    async fn send_payload_with_skip(
        &self,
        payload: Vec<u8>,
        exempt_skip: bool,
        fire_and_forget: bool,
    ) {
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
                        fire_and_forget,
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
                fire_and_forget,
            )));
        }
        // Never join slow peers past the budget (see
        // [`BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`]): one dead peer's 1.5s "no
        // session key" join used to stall the whole flush. On expiry the rest
        // detach — they still send and still record, just off the queue.
        //
        // SYNC TRAP N7 (R3 CODE-TAILS sweep, slow-peer detachment): detached
        // tasks still SEND and still RECORD, and cooldown peers are still
        // attempted (detached) for EXEMPT payloads (Committed catch-up), so a
        // lagging node is not cut off by this budget — but it IS cut off from
        // NON-exempt broadcasts while in failure cooldown (`plan_peer_send`:
        // `Skipped`). If the neediest peer is starved, the knobs (not the
        // mechanism) are what to change: `BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`
        // (join budget), the cooldown durations in `peer_health`, and which
        // payload classes count as exempt — all without touching this path's
        // fail-open send semantics. Detachment here must never become a drop.
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
            tracing::debug!("[consensus] broadcast skipped {skipped} peer(s) in failure cooldown");
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
    /// The round trip itself is no longer the delivery floor for votes and
    /// proposals: they go out fire-and-forget (see
    /// [`message_is_fire_and_forget`] / [`Self::send_one_peer`]), so only the
    /// LOCAL write is awaited and the remote ACK (300-1200 ms on a WAN link)
    /// stays off the critical path. The catch-up path (`Committed`) still uses
    /// the acknowledged form, because its ACK is the delivery proof.
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
                &format!(
                    "items={items} queued={}",
                    task_pending.load(Ordering::Relaxed)
                ),
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
    /// Per-peer SEND rate limiter for gossip publish (see
    /// [`SendRateLimiter`]): over-budget peers are dropped per-peer, the
    /// publisher is never blocked. Mutex-only, never held across await.
    send_limit: Mutex<SendRateLimiter>,
}

impl TxGossip {
    pub fn new(adapter: Arc<P2pNetworkAdapter>) -> Self {
        let topic = tx_topic(adapter.epoch().as_str());
        Self {
            adapter,
            topic,
            peer_health: Arc::new(Mutex::new(HashMap::new())),
            bcast_last_ms: Mutex::new(HashMap::new()),
            send_limit: Mutex::new(SendRateLimiter::with_defaults()),
        }
    }

    /// Peer ids, node-id first: the same asymmetric-registry trap fixed in
    /// `ConsensusNetwork::peer_ids` lived here too — a failed name lookup
    /// silently sent nothing, starving the peer's mempool (and its blocks)
    /// with no error anywhere (audit 2026-10-06).
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        let mut out = Vec::new();
        for p in &self.adapter.node.cfg.peers {
            let pid = p
                .node_id_raw()
                .or_else(|_| self.adapter.node.resolve(&p.name));
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
        let payload = serde_json::json!({ "topic": self.topic })
            .to_string()
            .into_bytes();
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
            // Global dial budget, shared with the consensus join (see
            // `try_acquire_dial_slot`): deferral is backpressure (debug),
            // never failure (warn).
            if !try_acquire_dial_slot() {
                tracing::debug!(
                    "[txgossip] join {} deferred (global dial budget {}/s exhausted)",
                    hex::encode(pid),
                    dial_budget_per_sec(),
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
                Some(ph) => peer_dial_suppressed(ph.fails, ph.last_fail, ph.backoff_until, now),
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
        // Quiet-known-dead rule (mirrors the consensus path): the ledger
        // keeps exactly one loud line per transition; per-attempt outcomes
        // for an already-known-dead peer log at debug.
        let loud_attempt = !health_is_known_dead(&health, &pid);
        match r {
            Ok(Ok(_)) => {
                let fails_before = Self::record_health(&health, pid, true);
                let recovered = fails_before >= PEER_SKIP_THRESHOLD;
                if elapsed >= std::time::Duration::from_millis(300) && !recovered {
                    tracing::warn!(
                        "[txgossip] broadcast to {hexid} slow: {elapsed:?} (still under the cap)"
                    );
                } else {
                    tracing::debug!("[txgossip] broadcast to {hexid} ok in {elapsed:?}");
                }
            }
            Ok(Err(e)) => {
                Self::record_health(&health, pid, false);
                if loud_attempt {
                    tracing::warn!("[txgossip] broadcast to {hexid} transport-err in {elapsed:?}: {e}");
                } else {
                    tracing::debug!("[txgossip] broadcast to {hexid} transport-err in {elapsed:?} (known-dead peer): {e}");
                }
            }
            Err(_) => {
                Self::record_health(&health, pid, false);
                if loud_attempt {
                    tracing::warn!("[txgossip] broadcast to {hexid} TIMEOUT after {elapsed:?}");
                } else {
                    tracing::debug!("[txgossip] broadcast to {hexid} TIMEOUT after {elapsed:?} (known-dead peer)");
                }
            }
        }
    }

    /// Ledger update shared by the inline path and the DETACHED per-peer
    /// tasks, which only hold an `Arc` to the ledger. Same contract as the
    /// consensus path's ledger (see [`ConsensusNetwork::record_health`]):
    /// returns the pre-update failure streak; exactly one loud line per
    /// transition (warn healthy->failing, info failing->healthy), debug
    /// per backoff-level change afterwards.
    fn record_health(health: &Mutex<HashMap<[u8; 20], PeerHealth>>, pid: [u8; 20], ok: bool) -> u32 {
        let now = std::time::Instant::now();
        match health.lock() {
            Ok(mut h) => {
                if ok {
                    match h.remove(&pid) {
                        Some(prev) if prev.fails >= PEER_SKIP_THRESHOLD => {
                            tracing::info!(
                                "[txgossip] peer {} recovered after {} consecutive failures: resuming dials",
                                hex::encode(pid),
                                prev.fails,
                            );
                            prev.fails
                        }
                        Some(prev) => prev.fails,
                        None => 0,
                    }
                } else {
                    let fails_before = h.get(&pid).map_or(0, |e| e.fails);
                    let e = h.entry(pid).or_default();
                    e.fails = e.fails.saturating_add(1);
                    e.last_fail = Some(now);
                    e.backoff_until = peer_backoff_until(now, e.fails);
                    if e.fails == PEER_SKIP_THRESHOLD {
                        tracing::warn!(
                            "[txgossip] peer {} failing {}x in a row: skipping sends for {:?}",
                            hex::encode(pid),
                            e.fails,
                            PEER_SKIP_COOLDOWN,
                        );
                    } else if e.fails > PEER_SKIP_THRESHOLD {
                        tracing::debug!(
                            "[txgossip] peer {} still failing ({}x in a row): next dial no earlier than {:?}",
                            hex::encode(pid),
                            e.fails,
                            e.backoff_until,
                        );
                    }
                    fails_before
                }
            }
            Err(_) => 0,
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
        let Ok(bytes) = bincode::serialize(tx) else {
            return;
        };
        self.broadcast_bytes(bytes).await;
    }

    /// Broadcast a SEALED transaction (the epoch-seal path).
    ///
    /// What goes on the wire is the CIPHERTEXT: the plaintext never leaves
    /// the sealing wallet. The frame is the magic-prefixed encoding of the
    /// envelope, so a peer that predates the sealed path refuses it
    /// (fail-closed) instead of mis-reading it as a plain transaction.
    pub async fn broadcast_sealed(&self, envelope: &crate::mev_epoch::SealedEnvelope) {
        let Ok(bytes) = crate::mev_epoch::encode_sealed_payload(envelope) else {
            return;
        };
        self.broadcast_bytes(bytes).await;
    }

    /// Broadcast an epoch-seal frame (the DKG contribution, the order
    /// commitment, the share release or the epoch announcement).
    ///
    /// The frame is magic-prefixed, so it can never be mis-read as a plain
    /// transaction by a peer that predates the epoch-seal path.
    pub async fn broadcast_mev_frame(&self, frame: &crate::mev_epoch::MevFrame) {
        let Ok(bytes) = frame.encode() else { return };
        self.broadcast_bytes(bytes).await;
    }

    /// The shared send path of the transaction gossip.
    async fn broadcast_bytes(&self, bytes: Vec<u8>) {
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
            // SEND-side rate limit (flood control): over-budget peers are
            // DROPPED for this publish only (counted in the limiter) while
            // every other peer still sends — the publisher is never blocked
            // and no await rides on the limiter.
            let allowed = match self.send_limit.lock() {
                Ok(mut l) => l.try_send(&pid, payload.len() as u64, epoch_ms()),
                Err(_) => true,
            };
            if !allowed {
                skipped += 1;
                tracing::debug!(
                    "[txgossip] publish to {} dropped (per-peer send budget exceeded)",
                    hex::encode(pid),
                );
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
/// The process-wide transaction-gossip handle.
///
/// The RPC layer needs to publish a SEALED transaction's ciphertext to the
/// peers, and the RPC state is built in a dozen places (every test helper
/// included) — adding a field there would churn all of them for no gain.
/// The handle is therefore a process global, set once by the node's
/// bootstrap and absent in tests and the simulator (where the plain path is
/// the only one that matters).
static GLOBAL_TX_GOSSIP: std::sync::OnceLock<std::sync::RwLock<Option<Arc<TxGossip>>>> =
    std::sync::OnceLock::new();

/// Publish the process-wide transaction-gossip handle.
pub fn set_global_tx_gossip(gossip: Arc<TxGossip>) {
    let slot = GLOBAL_TX_GOSSIP.get_or_init(|| std::sync::RwLock::new(None));
    if let Ok(mut guard) = slot.write() {
        *guard = Some(gossip);
    }
}

/// The process-wide transaction-gossip handle (if the node has one).
pub fn global_tx_gossip() -> Option<Arc<TxGossip>> {
    let slot = GLOBAL_TX_GOSSIP.get()?;
    let guard = slot.read().ok()?;
    guard.clone()
}

pub fn parse_tx_incoming(raw: &str) -> Option<crate::sharding::Transaction> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_TX_MSG {
        return None;
    }
    bincode::deserialize(&bytes).ok()
}

/// What a transaction-gossip frame carries.
///
/// The frame is EITHER a plain transaction (the historical encoding, byte
/// for byte) or a SEALED envelope (the epoch-seal path: the ciphertext
/// only). The two are told apart by a magic prefix, so a node that predates
/// the sealed path still decodes every plain frame and simply refuses the
/// sealed ones (fail-closed).
#[derive(Clone, Debug)]
pub enum TxGossipPayload {
    Plain(crate::sharding::Transaction),
    /// An epoch-seal frame: the sealed ciphertext, the DKG contribution,
    /// the order commitment, the share release or the epoch announcement.
    Mev(crate::mev_epoch::MevFrame),
}

/// Parse a raw pubsub payload into a transaction-gossip frame (fail-closed).
///
/// A malformed frame — bad JSON, bad hex, an oversized body, a truncated
/// sealed payload — is refused here, so nothing malformed ever reaches the
/// mempool.
pub fn parse_tx_gossip_payload(raw: &str) -> Option<TxGossipPayload> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_TX_MSG {
        return None;
    }
    if crate::mev_epoch::is_mev_frame(&bytes) {
        let frame = crate::mev_epoch::MevFrame::decode(&bytes).ok()?;
        return Some(TxGossipPayload::Mev(frame));
    }
    let tx: crate::sharding::Transaction = bincode::deserialize(&bytes).ok()?;
    Some(TxGossipPayload::Plain(tx))
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
        log_stage(
            &gate,
            "test",
            "slow-again",
            std::time::Duration::from_millis(300),
        );
    }

    /// FIRE-AND-FORGET is not a delivery proof: a local write success must
    /// NOT mark the peer healthy, because that RESET its consecutive-failure
    /// counter and a peer that fails intermittently was then never skipped
    /// (audit W6.7).
    #[test]
    fn fire_and_forget_success_does_not_mark_a_peer_healthy() {
        assert!(
            !send_outcome_records_health(true),
            "a fire-and-forget success must not touch the peer-health ledger"
        );
        assert!(
            send_outcome_records_health(false),
            "an acknowledged send must mark the peer healthy"
        );
    }

    /// The per-peer inbound limiter: a noisy neighbour can only defer its OWN
    /// traffic, and the bucket is bounded in count (memory) and in rate.
    #[test]
    fn inbound_limiter_is_per_peer_and_bounded() {
        let mut lim = InboundBulkLimiter::new(1024, 4096);
        let a = "aa";
        let b = "bb";
        // A big burst for peer A is deferred...
        let d = lim.admit(a, 8192, false, 0);
        assert!(
            matches!(d, InboundDecision::Defer { .. }),
            "a peer over its burst budget must be deferred, not dropped"
        );
        // ...and peer B is UNAFFECTED (its own bucket is full).
        assert_eq!(
            lim.admit(b, 100, false, 0),
            InboundDecision::Allow,
            "one peer's over-budget traffic must not defer another peer's"
        );
        // Critical traffic always passes and never spends the budget.
        assert_eq!(lim.admit(a, 1_000_000, true, 0), InboundDecision::Allow);
        // The bucket count is bounded: many peers do not grow it without
        // bound (the overflow evicts an arbitrary entry).
        for i in 0..(INBOUND_MAX_TRACKED_PEERS + 50) {
            lim.admit(&format!("p{i}"), 1, false, 0);
        }
        assert!(
            lim.peer_count() <= INBOUND_MAX_TRACKED_PEERS,
            "the limiter must not grow without bound ({} peers)",
            lim.peer_count()
        );
    }

    #[test]
    fn inbound_peer_key_prefers_src_then_from() {
        // The pubsub envelope infnode delivers carries the SENDER's node id
        // in `src`; `from` is the legacy spelling. `src` wins when both are
        // present.
        let raw = r#"{"topic":"t","data":"00","msg_id":7,"src":"aa","from":"bb"}"#;
        assert_eq!(inbound_peer_key(raw), "aa");
        let legacy = r#"{"topic":"t","data":"00","msg_id":7,"from":"bb"}"#;
        assert_eq!(inbound_peer_key(legacy), "bb");
        // `inf1:` is infnode's canonical node-id prefix: the same peer must
        // key identically no matter which form the sender used.
        let prefixed = r#"{"topic":"t","data":"00","msg_id":7,"src":"inf1:cc"}"#;
        assert_eq!(inbound_peer_key(prefixed), "cc");
        // No sender at all: the shared fallback bucket (and only that one).
        let bare = r#"{"topic":"t","data":"00","msg_id":7}"#;
        assert_eq!(inbound_peer_key(bare), INBOUND_BROADCAST_PEER_KEY);
        // Garbage is not a crash and not a distinct peer.
        assert_eq!(inbound_peer_key("not json"), INBOUND_BROADCAST_PEER_KEY);
        // An empty sender is not a peer either.
        let empty = r#"{"topic":"t","data":"00","msg_id":7,"src":""}"#;
        assert_eq!(inbound_peer_key(empty), INBOUND_BROADCAST_PEER_KEY);
    }

    #[test]
    fn inbound_limiter_buckets_are_per_peer() {
        // The bug this pins: the pubsub envelope used to carry no sender, so
        // EVERY peer's inbound bulk traffic shared ONE token bucket and a
        // single noisy neighbour could exhaust everybody else's budget.
        let peer_a = "aa".repeat(20);
        let peer_b = "bb".repeat(20);
        let raw_a = format!(r#"{{"topic":"t","data":"00","msg_id":1,"src":"{peer_a}"}}"#);
        let raw_b = format!(r#"{{"topic":"t","data":"00","msg_id":2,"src":"{peer_b}"}}"#);
        let key_a = inbound_peer_key(&raw_a);
        let key_b = inbound_peer_key(&raw_b);
        assert_ne!(key_a, key_b, "two peers must key differently");
        assert_eq!(key_a, peer_a);
        assert_eq!(key_b, peer_b);

        // A limiter with a 1 KiB/s rate and a 1 KiB burst: peer A spends its
        // whole burst, peer B still has its own bucket.
        let mut limiter = InboundBulkLimiter::new(1024, 1024);
        let now = 1_000u64;
        assert_eq!(
            limiter.admit(&key_a, 1024, false, now),
            InboundDecision::Allow
        );
        // A is now over budget -> deferred.
        assert!(
            matches!(
                limiter.admit(&key_a, 1024, false, now),
                InboundDecision::Defer { .. }
            ),
            "the noisy peer must be deferred once it is over budget"
        );
        // B is untouched: its own bucket still has the full burst.
        assert_eq!(
            limiter.admit(&key_b, 1024, false, now),
            InboundDecision::Allow,
            "one peer exhausting its budget must not defer another peer's traffic"
        );
        assert_eq!(limiter.peer_count(), 2, "each peer gets its own bucket");
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
    fn dial_backoff_grows_exponentially_and_caps() {
        // Below the skip threshold there is no backoff: healthy peers see
        // zero behavior change.
        assert_eq!(dial_backoff_ms(0, 2000, 300_000), 0);
        assert_eq!(dial_backoff_ms(1, 2000, 300_000), 0);
        assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD - 1, 2000, 300_000), 0);
        // At threshold: base; then doubling per consecutive failure.
        assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD, 2000, 300_000), 2_000);
        assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD + 1, 2000, 300_000), 4_000);
        assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD + 2, 2000, 300_000), 8_000);
        assert_eq!(
            dial_backoff_ms(PEER_SKIP_THRESHOLD + 3, 2000, 300_000),
            16_000
        );
        // The cap binds a long-dead peer: no overflow, no unbounded growth.
        assert_eq!(
            dial_backoff_ms(PEER_SKIP_THRESHOLD + 10, 2000, 300_000),
            300_000
        );
        assert_eq!(dial_backoff_ms(u32::MAX, 2000, 300_000), 300_000);
        // Custom knobs are honored (env parsing below pins the defaults).
        assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD, 500, 10_000), 500);
        assert_eq!(
            dial_backoff_ms(PEER_SKIP_THRESHOLD + 1, 500, 10_000),
            1_000
        );
        assert_eq!(
            dial_backoff_ms(PEER_SKIP_THRESHOLD + 10, 500, 10_000),
            10_000
        );
    }

    #[test]
    fn dial_backoff_jitter_stays_in_bounds() {
        // Equal jitter: every sample lands in [backoff/2, backoff], so
        // co-dead peers desynchronize without ever exceeding the level.
        for backoff in [1u64, 2, 100, 2_000, 16_000, 300_000] {
            for seed in [0u64, 1, 7, 12345, u64::MAX] {
                let j = dial_backoff_jittered_ms(backoff, seed);
                assert!(
                    j >= backoff / 2 && j <= backoff,
                    "jittered {j} out of [{}, {backoff}]",
                    backoff / 2,
                );
            }
        }
        // Zero backoff stays zero (healthy peers never wait).
        assert_eq!(dial_backoff_jittered_ms(0, 999), 0);
        // The seed actually spreads: not every seed maps to the same delay.
        let spread: std::collections::HashSet<u64> =
            (0..32).map(|s| dial_backoff_jittered_ms(2_000, s)).collect();
        assert!(
            spread.len() > 1,
            "jitter must desynchronize retries, got a single value"
        );
    }

    #[test]
    fn dial_backoff_env_parsing_pins_defaults() {
        assert_eq!(
            parse_dial_backoff_base_ms(None),
            DIAL_BACKOFF_BASE_MS_DEFAULT
        );
        assert_eq!(parse_dial_backoff_base_ms(Some("garbage".into())), 2_000);
        assert_eq!(parse_dial_backoff_base_ms(Some("0".into())), 2_000);
        assert_eq!(parse_dial_backoff_base_ms(Some("500".into())), 500);
        assert_eq!(
            parse_dial_backoff_max_ms(None),
            DIAL_BACKOFF_MAX_MS_DEFAULT
        );
        assert_eq!(parse_dial_backoff_max_ms(Some("nope".into())), 300_000);
        assert_eq!(parse_dial_backoff_max_ms(Some("0".into())), 300_000);
        assert_eq!(parse_dial_backoff_max_ms(Some("60_000".into())), 300_000);
        assert_eq!(parse_dial_backoff_max_ms(Some("60000".into())), 60_000);
        assert_eq!(
            parse_dial_budget_per_sec(None),
            DIAL_BUDGET_PER_SEC_DEFAULT
        );
        assert_eq!(parse_dial_budget_per_sec(Some("junk".into())), 4);
        assert_eq!(parse_dial_budget_per_sec(Some("0".into())), 4);
        assert_eq!(parse_dial_budget_per_sec(Some("10".into())), 10);
    }

    #[test]
    fn dial_budget_gate_allows_n_per_second() {
        // 4/s => one slot per 250ms. First dial always allowed.
        assert!(dial_budget_should_allow(None, 1_000, 4));
        assert!(!dial_budget_should_allow(Some(1_000), 1_000, 4));
        assert!(!dial_budget_should_allow(Some(1_000), 1_249, 4));
        assert!(dial_budget_should_allow(Some(1_000), 1_250, 4));
        // A faster budget shortens the interval; a clamped (>= 1) one never
        // divides by zero.
        assert!(dial_budget_should_allow(Some(1_000), 1_100, 10));
        assert!(!dial_budget_should_allow(Some(1_000), 1_000, 0));
        assert!(dial_budget_should_allow(Some(1_000), 2_000, 0));
        // The stateful gate stamps on allow and holds back within the window.
        let gate = DialBudget::new(4);
        assert!(gate.try_acquire_at(5_000));
        assert!(!gate.try_acquire_at(5_100));
        assert!(gate.try_acquire_at(5_250));
        // Independent gates do not share state (regression: one global would
        // serialize unrelated test clocks).
        let other = DialBudget::new(4);
        assert!(other.try_acquire_at(5_100));
    }

    #[test]
    fn dead_peer_dials_back_off() {
        use std::time::{Duration, Instant};
        // A dead peer's dial suppression OUTLIVES the fixed 3s cooldown: the
        // exponential backoff keeps stretching the silence while the peer
        // stays down, and success resets the streak to zero.
        let health = Mutex::new(HashMap::new());
        let pid = [7u8; 20];
        // Healthy peer: no backoff, no suppression.
        assert_eq!(dial_backoff_ms(0, 2000, 300_000), 0);
        // Three consecutive dial failures: threshold reached, suppressed now.
        for _ in 0..PEER_SKIP_THRESHOLD {
            ConsensusNetwork::record_health(&health, pid, false);
        }
        let now = Instant::now();
        let entry = health.lock().unwrap().get(&pid).copied().unwrap();
        assert_eq!(entry.fails, PEER_SKIP_THRESHOLD);
        assert!(peer_dial_suppressed(
            entry.fails,
            entry.last_fail,
            entry.backoff_until,
            now
        ));
        // Keep failing: with defaults (base 2s) the 6th consecutive failure
        // already backs off 16s (jittered to [8s, 16s]) — far past the fixed
        // 3s cooldown, so the peer stays silent after the cooldown ages out.
        for _ in 0..3 {
            ConsensusNetwork::record_health(&health, pid, false);
        }
        let entry = health.lock().unwrap().get(&pid).copied().unwrap();
        assert_eq!(entry.fails, PEER_SKIP_THRESHOLD + 3);
        let past_cooldown = entry.last_fail.unwrap() + PEER_SKIP_COOLDOWN + Duration::from_secs(1);
        assert!(
            !peer_in_cooldown(entry.fails, entry.last_fail, past_cooldown),
            "the fixed cooldown must have aged out here"
        );
        assert!(
            peer_dial_suppressed(entry.fails, entry.last_fail, entry.backoff_until, past_cooldown),
            "but the exponential backoff must still suppress the dial"
        );
        // Success resets to zero: the ledger entry is gone, dials resume.
        let fails_before = ConsensusNetwork::record_health(&health, pid, true);
        assert_eq!(fails_before, PEER_SKIP_THRESHOLD + 3);
        assert!(!health.lock().unwrap().contains_key(&pid));
        assert!(!peer_dial_suppressed(0, None, None, Instant::now()));
    }

    #[tokio::test]
    async fn dead_peer_keeps_flush_latency_bounded() {
        // Flush-latency bound: one dead peer's multi-second stall must not
        // hold the flush past the join budget. The slow task is DETACHED
        // (still runs to completion), only the waiter moves on.
        let fast = tokio::spawn(async { 1u32 });
        let slow = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            2u32
        });
        let t0 = Instant::now();
        let (done, detached) =
            join_with_timeout(vec![fast, slow], Duration::from_millis(50)).await;
        let elapsed = t0.elapsed();
        assert_eq!(done, vec![1u32], "the fast peer must still join");
        assert_eq!(detached, 1, "the dead peer must detach, not block");
        assert!(
            elapsed < Duration::from_secs(2),
            "flush must return on the join budget, not the dead peer (took {elapsed:?})"
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
        let proposal = ConsensusMsg::Proposal {
            height: 9,
            round: 0,
            block: sample_block(),
        };
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

    #[test]
    fn votes_and_proposals_are_fire_and_forget_but_commits_are_not() {
        // Transport-audit contract (D): a vote/proposal is delivered without
        // waiting for the peer's ACK — the ACK is a fixed `{"ok":true,...}`
        // that carries no information, but it costs a full round trip
        // (300-1200 ms on WAN) and the ordered sender is FIFO, so an awaited
        // ACK also delays the NEXT chunk.
        let vote = tagged_vote(1);
        assert!(message_is_fire_and_forget(&vote));
        let proposal = ConsensusMsg::Proposal {
            height: 9,
            round: 0,
            block: sample_block(),
        };
        assert!(message_is_fire_and_forget(&proposal));
        // A chunk of votes/proposals is fire-and-forget.
        assert!(batch_is_fire_and_forget(std::slice::from_ref(&vote)));
        assert!(batch_is_fire_and_forget(std::slice::from_ref(&proposal)));
        assert!(batch_is_fire_and_forget(&[vote.clone(), proposal.clone()]));

        // The catch-up path keeps the acknowledged form: its ACK is the
        // sender's proof that the peer really got the block.
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
        assert!(!message_is_fire_and_forget(&commit));
        assert!(!batch_is_fire_and_forget(std::slice::from_ref(&commit)));
        // A mixed chunk keeps the acknowledged form for the WHOLE chunk.
        assert!(!batch_is_fire_and_forget(&[vote, commit]));
        // An empty chunk is never fire-and-forget (nothing to send).
        assert!(!batch_is_fire_and_forget(&[]));
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
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(&sk);
        b
    }

    #[test]
    fn proposal_roundtrip() {
        let msg = ConsensusMsg::Proposal {
            height: 7,
            round: 0,
            block: sample_block(),
        };
        let bytes = msg.encode().unwrap();
        let dec = ConsensusMsg::decode(&bytes).unwrap();
        match dec {
            ConsensusMsg::Proposal {
                height,
                round,
                block,
            } => {
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
        let msg = ConsensusMsg::Vote {
            vote: v.clone(),
            locked: None,
        };
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
        assert!(
            ConsensusMsg::decode(&[0xFF, 0x00, 0x01]).is_err(),
            "garbage must be rejected"
        );
    }

    #[test]
    fn decode_rejects_oversized() {
        let big = vec![0u8; MAX_CONSENSUS_MSG + 1];
        assert!(
            ConsensusMsg::decode(&big).is_err(),
            "oversized must be rejected"
        );
    }

    /// PENTEST F1 (P1): appended trailing bytes must not ride along a valid
    /// message. Before the fix `decode` used `allow_trailing_bytes`, so an
    /// attacker could pad every vote with megabytes of junk that still
    /// decoded — wire-size accounting (512 KiB batch cap, 32 MiB frame cap)
    /// was bypassed and each tick paid the bandwidth + stream-buffer cost.
    #[test]
    fn pentest_decode_rejects_trailing_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let mut bytes = ConsensusMsg::Vote {
            vote: v,
            locked: None,
        }
        .encode()
        .unwrap();
        bytes.extend_from_slice(&[0xAA; 64]);
        assert!(
            ConsensusMsg::decode(&bytes).is_err(),
            "trailing junk after a valid message must be rejected"
        );
        // A single trailing byte is the same attack at minimum size.
        let mut one = ConsensusMsg::Proposal {
            height: 7,
            round: 0,
            block: sample_block(),
        }
        .encode()
        .unwrap();
        one.push(0x00);
        assert!(
            ConsensusMsg::decode(&one).is_err(),
            "one trailing byte must already fail the decode"
        );
        // Exact bytes still decode (no false positive from the hardening).
        let exact = ConsensusMsg::Proposal {
            height: 7,
            round: 0,
            block: sample_block(),
        }
        .encode()
        .unwrap();
        assert!(ConsensusMsg::decode(&exact).is_ok());
    }

    /// PENTEST F2 (P1): only the Committed catch-up proof bypasses the
    /// inbound bulk limiter. Before the fix every non-Batch message
    /// (votes AND proposals) bypassed it, and the receiver loop only
    /// consulted the limiter for Batch envelopes at all — so an attacker
    /// trickling singleton votes (a few hundred bytes each, never a Batch)
    /// burned an Ed25519 verification per message while the limiter saw
    /// nothing.
    #[test]
    fn pentest_only_committed_bypasses_inbound_limiter() {
        let vote = tagged_vote(1);
        let proposal = ConsensusMsg::Proposal {
            height: 9,
            round: 0,
            block: sample_block(),
        };
        let batch = ConsensusMsg::Batch(vec![vote.clone()]);
        assert!(
            !inbound_is_critical(&vote),
            "a singleton vote must be budget-checked, not exempt"
        );
        assert!(
            !inbound_is_critical(&proposal),
            "a proposal must be budget-checked, not exempt"
        );
        assert!(
            !inbound_is_critical(&batch),
            "bulk gossip must stay budget-checked"
        );
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
        assert!(
            inbound_is_critical(&commit),
            "the catch-up proof is the only exempt shape"
        );
        // Limiter level: a singleton vote spends the sender's budget, and a
        // second over-budget vote from the same peer defers instead of
        // executing inline.
        let mut lim = InboundBulkLimiter::new(1024, 1024);
        let now = 1_000u64;
        assert_eq!(
            lim.admit("flooder", 512, inbound_is_critical(&vote), now),
            InboundDecision::Allow
        );
        assert!(
            matches!(
                lim.admit("flooder", 1024, inbound_is_critical(&vote), now),
                InboundDecision::Defer { .. }
            ),
            "an over-budget singleton vote must defer, not execute inline"
        );
        // The catch-up proof never spends budget, at any size.
        assert_eq!(
            lim.admit("lagging", 1_000_000, inbound_is_critical(&commit), now),
            InboundDecision::Allow
        );
    }

    /// PENTEST F3 (P1): the limiter bucket key is validated. Before the fix
    /// any `src` string — kilobytes long, non-hex — became a distinct
    /// attacker-minted `HashMap` key, so one peer could mint unbounded map
    /// keys (memory) and rotate identities per message (a fresh bucket every
    /// time, i.e. no rate limiting at all).
    #[test]
    fn pentest_inbound_peer_key_validates_sender() {
        // Oversized sender: shared bucket, not a new map key.
        let huge = "ab".repeat(1024);
        let raw = format!(r#"{{"topic":"t","data":"00","msg_id":1,"src":"{huge}"}}"#);
        assert_eq!(
            inbound_peer_key(&raw),
            INBOUND_BROADCAST_PEER_KEY,
            "an oversized src must not become a distinct bucket"
        );
        // Non-hex sender: shared bucket.
        let raw = r#"{"topic":"t","data":"00","msg_id":2,"src":"../../evil"}"#;
        assert_eq!(
            inbound_peer_key(raw),
            INBOUND_BROADCAST_PEER_KEY,
            "a non-hex src must not become a bucket key"
        );
        // Honest forms keep working: short hex, full node id, inf1: prefix.
        assert_eq!(
            inbound_peer_key(r#"{"topic":"t","data":"00","src":"aa"}"#),
            "aa"
        );
        let full = "ab".repeat(20);
        let raw = format!(r#"{{"topic":"t","data":"00","src":"inf1:{full}"}}"#);
        assert_eq!(inbound_peer_key(&raw), full);
        // Distinct honest peers still key distinctly (per-peer isolation kept).
        let ka = inbound_peer_key(r#"{"topic":"t","data":"00","src":"aa"}"#);
        let kb = inbound_peer_key(r#"{"topic":"t","data":"00","src":"bb"}"#);
        assert_ne!(ka, kb);
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
        let data = hex::encode(
            ConsensusMsg::Vote {
                vote: v,
                locked: None,
            }
            .encode()
            .unwrap(),
        );
        let raw = serde_json::json!({ "topic": consensus_topic("test"), "data": data }).to_string();
        assert!(matches!(
            parse_incoming(&raw),
            Some(ConsensusMsg::Vote { .. })
        ));
    }

    #[test]
    fn tampered_vote_fails_signature_check() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        v.block_hash = Some([2u8; 32]); // tamper after signing
        let msg = ConsensusMsg::Vote {
            vote: v,
            locked: None,
        };
        let bytes = msg.encode().unwrap();
        match ConsensusMsg::decode(&bytes).unwrap() {
            ConsensusMsg::Vote { vote: v2, .. } => {
                assert!(!v2.verify(), "tampered vote must fail verification")
            }
            _ => panic!("wrong variant"),
        }
    }

    /// VERIFICATION F1-hardening: the trailing-byte fix must hold for every
    /// envelope shape, not just a singleton vote.
    ///
    /// Stronger exploits than the original pentest:
    /// * trailing junk after a BATCH envelope (the batch path has its own
    ///   length accounting — padding must not ride along);
    /// * trailing junk after a COMMITTED proof (the largest variant: full
    ///   block + QC — padding here is the most expensive to relay);
    /// * a nested Batch in SECOND position (the fast-path prefix check only
    ///   inspects the first item, so this exercises the full-deserialize +
    ///   `check_batch` leg);
    /// * a maximal-size frame plus one byte (the size gate must fire before
    ///   any deserialization work).
    #[test]
    fn verification_decode_rejects_trailing_on_every_shape() {
        // Batch envelope + trailing junk.
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
        let batch_bytes = ConsensusMsg::batch_encode(&[ConsensusMsg::Vote {
            vote: v,
            locked: None,
        }])
        .unwrap();
        let mut padded = batch_bytes.clone();
        padded.extend_from_slice(&[0xBB; 128]);
        assert!(
            ConsensusMsg::decode(&padded).is_err(),
            "trailing junk after a Batch envelope must be rejected"
        );
        assert!(
            ConsensusMsg::decode(&batch_bytes).is_ok(),
            "exact Batch bytes must still decode"
        );
        // Committed proof + one trailing byte (minimum-size padding attack).
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
        let mut cbytes = commit.encode().unwrap();
        cbytes.push(0x00);
        assert!(
            ConsensusMsg::decode(&cbytes).is_err(),
            "one trailing byte after a Committed proof must fail the decode"
        );
        cbytes.pop();
        assert!(ConsensusMsg::decode(&cbytes).is_ok());
        // Nested batch in SECOND position: the prefix fast-path only sees the
        // first item (a Vote), so this must be caught by check_batch.
        let inner = ConsensusMsg::Batch(vec![tagged_vote(2)]);
        let sneaky = ConsensusMsg::Batch(vec![tagged_vote(1), inner]);
        let raw = bincode::serialize(&sneaky).unwrap();
        assert_eq!(raw[0..4], [3, 0, 0, 0], "outer envelope must be a Batch");
        assert_ne!(
            raw[12..16],
            [3, 0, 0, 0],
            "first inner item must be a Vote (fast-path blind spot)"
        );
        let err = ConsensusMsg::decode(&raw).unwrap_err();
        assert!(err.contains("nested"), "got: {err}");
        // Maximal frame + 1 byte: the size gate fires before deserialization.
        let big = vec![0u8; MAX_CONSENSUS_MSG + 1];
        assert!(ConsensusMsg::decode(&big).is_err());
        let edge = vec![0u8; MAX_CONSENSUS_MSG];
        assert!(
            ConsensusMsg::decode(&edge).is_err(),
            "a max-size garbage frame must still fail deserialization"
        );
    }

    /// VERIFICATION F2-hardening: a singleton-vote flood from ONE peer must
    /// not touch an honest peer's budget, sustained across ticks.
    ///
    /// Stronger than the original pentest: the flooder keeps spending (32
    /// back-to-back singleton votes in the same millisecond — a full Batch
    /// worth, never a Batch), while the honest peer sends at the same
    /// instants and after a refill window. Every flooder vote past the burst
    /// defers; every honest vote passes.
    #[test]
    fn verification_singleton_flood_is_per_peer_isolated() {
        let vote = tagged_vote(1);
        assert!(
            !inbound_is_critical(&vote),
            "a singleton vote must be budget-checked, not exempt"
        );
        let mut lim = InboundBulkLimiter::new(1024, 1024);
        let now = 1_000u64;
        // Flooder spends its whole 1 KiB burst on the first vote...
        assert_eq!(
            lim.admit("flooder", 1024, false, now),
            InboundDecision::Allow
        );
        // ...and every further singleton vote in the same tick defers.
        for i in 0..32 {
            assert!(
                matches!(
                    lim.admit("flooder", 300, false, now),
                    InboundDecision::Defer { .. }
                ),
                "flooder vote {i} over budget must defer, not execute inline"
            );
        }
        // The honest peer's traffic passes at the same instant, byte for byte.
        for i in 0..3 {
            assert_eq!(
                lim.admit("honest", 300, false, now),
                InboundDecision::Allow,
                "honest vote {i} must pass while the flooder is over budget"
            );
        }
        // After a refill window the flooder earns budget back (deferral is
        // scheduling, not a ban) and the honest peer is still unaffected.
        let later = now + 2_000;
        assert_eq!(
            lim.admit("flooder", 300, false, later),
            InboundDecision::Allow
        );
        assert_eq!(
            lim.admit("honest", 300, false, later),
            InboundDecision::Allow
        );
    }

    /// VERIFICATION F2-hardening, second half: a giant fake Committed bypasses
    /// the byte limiter by design — so the per-tick verification cap must
    /// bound it instead. The limiter still admits it (documented tradeoff);
    /// the drain policy below caps how many get verified per tick.
    #[test]
    fn verification_committed_bypass_is_capped_per_tick() {
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
        assert!(inbound_is_critical(&commit));
        // Even a maximal fake proof bypasses the byte limiter...
        let mut lim = InboundBulkLimiter::new(1024, 1024);
        assert_eq!(
            lim.admit("attacker", MAX_CONSENSUS_MSG as u64, true, 1_000),
            InboundDecision::Allow,
            "Committed bypasses the byte limiter at any size (by design)"
        );
        // ...so the tick cap is the bound that stops the CPU burn: the live
        // path needs ~1 proof per finalize, the cap is generous, and the 9th
        // proof in one tick is flood tail.
        for i in 0..COMMITTED_INNER_BUDGET_PER_TICK {
            assert!(
                committed_admit_this_tick(i),
                "proof {i} within cap must verify"
            );
        }
        assert!(
            !committed_admit_this_tick(COMMITTED_INNER_BUDGET_PER_TICK),
            "proofs past the per-tick cap must be dropped, not verified"
        );
    }

    /// VERIFICATION F3-hardening: the bucket-key gate must hold against a
    /// MALICIOUS sender, not just a malformed one.
    ///
    /// Stronger than the original pentest: unicode lookalikes, boundary
    /// lengths (128 accepted / 129 shared), non-string JSON values, a bare
    /// `inf1:` prefix, whitespace games — and the key property: two distinct
    /// malicious senders collapse into the SAME shared bucket (no minting),
    /// while honest hex senders keep per-peer isolation.
    #[test]
    fn verification_peer_key_holds_against_malicious_senders() {
        let shared = INBOUND_BROADCAST_PEER_KEY;
        // Unicode lookalike: full-width/cyrillic hex lookalikes are not ASCII hex.
        let uni = "ab".repeat(10) + "аа"; // trailing chars are Cyrillic 'a'
        assert_eq!(
            inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{uni}"}}"#)),
            shared,
            "unicode sender must not become a bucket"
        );
        // Boundary: exactly 128 hex chars is a distinct bucket...
        let k128 = "ab".repeat(64);
        assert_eq!(k128.len(), 128);
        assert_eq!(
            inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{k128}"}}"#)),
            k128
        );
        // ...129 chars collapses to shared.
        let k129 = format!("{k128}ab");
        assert_eq!(
            inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{k129}"}}"#)),
            shared,
            "a 129-char src must not mint a bucket"
        );
        // Non-string JSON values are not senders.
        for raw in [
            r#"{"topic":"t","data":"00","src":12345}"#.to_string(),
            r#"{"topic":"t","data":"00","src":null}"#.to_string(),
            r#"{"topic":"t","data":"00","src":{"x":1}}"#.to_string(),
            r#"{"topic":"t","data":"00","src":["aa"]}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"inf1:"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"   "}"#.to_string(),
            r#"{"topic":"t","data":"00","from":"zz-top"}"#.to_string(),
        ] {
            assert_eq!(inbound_peer_key(&raw), shared, "raw={raw}");
        }
        // `from` fallback is gated identically (non-hex -> shared, hex distinct).
        assert_eq!(
            inbound_peer_key(r#"{"topic":"t","data":"00","from":"cc"}"#),
            "cc"
        );
        // Two distinct malicious senders share ONE bucket: no minting, and the
        // shared bucket still rate-limits the aggregate (it is one token
        // bucket, not an exemption).
        let m1 = inbound_peer_key(r#"{"topic":"t","data":"00","src":"../../evil"}"#);
        let m2 = inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{k129}"}}"#));
        assert_eq!(m1, shared);
        assert_eq!(m2, shared);
        let mut lim = InboundBulkLimiter::new(1024, 1024);
        assert_eq!(lim.admit(&m1, 1024, false, 1_000), InboundDecision::Allow);
        assert!(
            matches!(
                lim.admit(&m2, 1024, false, 1_000),
                InboundDecision::Defer { .. }
            ),
            "malicious senders share one budget: the second must defer"
        );
        assert_eq!(
            lim.peer_count(),
            1,
            "malicious senders must not grow the map"
        );
    }

    /// VERIFICATION G1: only an attributable proposal (valid proposer
    /// signature + a signer with stake) may plant the catch-up hint.
    ///
    /// Exploit: a single FORGED proposal for H+1 (garbage signature, or a
    /// key with no stake) used to set `peer_hint` in the receiver loop
    /// before any verification, forcing the catch-up timer every tick and
    /// keeping the node on loudly-failing DHT walks. The gate below is what
    /// the loop must consult before recording the hint.
    #[test]
    fn verification_only_attributable_proposals_plant_hints() {
        use crate::consensus::ValidatorSet;
        let sk = SigningKey::generate(&mut OsRng);
        let proposer = sk.verifying_key().to_bytes();
        let mut validators = ValidatorSet::new();
        validators.validators.insert(proposer, 100);
        let mut block = sample_block();
        block.proposer = proposer;
        block.sign_block(&sk);
        assert!(
            proposal_hint_admissible(&block, &validators),
            "a genuine member proposal must plant the hint"
        );
        // Tamper after signing: the body no longer matches the signature.
        let mut tampered = block.clone();
        tampered.height += 1;
        assert!(
            !proposal_hint_admissible(&tampered, &validators),
            "a tampered proposal must not plant a hint"
        );
        // Valid signature, zero stake: an outsider must not steer catch-up.
        let outsider_sk = SigningKey::generate(&mut OsRng);
        let mut outsider = sample_block();
        outsider.proposer = outsider_sk.verifying_key().to_bytes();
        outsider.sign_block(&outsider_sk);
        assert!(
            !proposal_hint_admissible(&outsider, &validators),
            "a non-member proposal must not plant a hint"
        );
        // Unsigned block: no signatures at all.
        let mut bare = sample_block();
        bare.proposer = proposer;
        bare.validator_signatures.clear();
        assert!(
            !proposal_hint_admissible(&bare, &validators),
            "an unsigned proposal must not plant a hint"
        );
    }

    /// P1-G2..G4 closure pin (R3 CODE-TAILS sweep): G2–G4 were filed as bare
    /// IDs with no recorded content (see the `P1-G2..G4 — ACCEPTED` note on
    /// [`proposal_hint_admissible`]), so the only verifiable statement is
    /// that the G-series bookends — G1 (hint attribution) and G5 (oracle
    /// fetch re-verification) — hold. This test re-asserts both through the
    /// same pure gates the feature tests use, so a future audit can confirm
    /// the series is closed without re-diagnosing the middle IDs.
    #[test]
    fn report_p1_g2_g4_filed_without_content_is_closed_as_accepted() {
        use crate::consensus::ValidatorSet;
        // Bookend G1: attribution still requires membership, not just a
        // valid signature.
        let sk = SigningKey::generate(&mut OsRng);
        let proposer = sk.verifying_key().to_bytes();
        let mut validators = ValidatorSet::new();
        validators.validators.insert(proposer, 100);
        let mut block = sample_block();
        block.proposer = proposer;
        block.sign_block(&sk);
        assert!(proposal_hint_admissible(&block, &validators));
        let outsider_sk = SigningKey::generate(&mut OsRng);
        let mut outsider = sample_block();
        outsider.proposer = outsider_sk.verifying_key().to_bytes();
        outsider.sign_block(&outsider_sk);
        assert!(!proposal_hint_admissible(&outsider, &validators));
        // Bookend G5: stored oracle bytes are re-verified on the way out —
        // a re-priced feed with the old signature reads as a miss, never as
        // market evidence.
        let feed = crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &sk);
        let stored = hex::encode(bincode::serialize(&feed).unwrap());
        assert!(crate::network::decode_verified_price_feed(&stored).is_some());
        let mut tampered = feed.clone();
        tampered.price_micro_usd = 1;
        let bad = hex::encode(bincode::serialize(&tampered).unwrap());
        assert!(crate::network::decode_verified_price_feed(&bad).is_none());
    }

    #[test]
    fn batch_roundtrip_preserves_order() {
        let sk = SigningKey::generate(&mut OsRng);
        let v1 = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let v2 = Vote::sign(&sk, 1, 0, VoteKind::Precommit, None);
        let items = vec![
            ConsensusMsg::Vote {
                vote: v1,
                locked: None,
            },
            ConsensusMsg::Vote {
                vote: v2,
                locked: Some([2u8; 32]),
            },
            ConsensusMsg::Proposal {
                height: 7,
                round: 0,
                block: sample_block(),
            },
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
        let inner = ConsensusMsg::Batch(vec![ConsensusMsg::Vote {
            vote: v,
            locked: None,
        }]);
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
                priority_fee_per_gas: 0,
            })
            .collect();
        let sk = SigningKey::generate(&mut OsRng);
        let mut big = sample_block();
        big.transactions = txs;
        big.sign_block(&sk);
        let msg = ConsensusMsg::Proposal {
            height: 7,
            round: 0,
            block: big,
        };
        assert!(
            msg.encode().unwrap().len() > MAX_BATCH_BYTES,
            "fixture must exceed the batch cap"
        );
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
            Proposal {
                height: u64,
                round: u32,
                block: Block,
            },
            Vote {
                vote: Vote,
                locked: Option<[u8; 32]>,
            },
            Committed {
                height: u64,
                block: Block,
                certificate: crate::consensus::QuorumCertificate,
            },
        }
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
        let bytes = ConsensusMsg::batch_encode(&[ConsensusMsg::Vote {
            vote: v,
            locked: None,
        }])
        .unwrap();
        let res: Result<OldConsensusMsg, _> = bincode::deserialize(&bytes);
        assert!(res.is_err(), "old decoder must reject batch bytes");
    }

    #[test]
    fn is_large_flags_proposals_and_commits() {
        let sk = SigningKey::generate(&mut OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
        let vote = ConsensusMsg::Vote {
            vote: v,
            locked: None,
        };
        assert!(!is_large(&vote));
        assert!(!vote.is_large());
        assert!(ConsensusMsg::Proposal {
            height: 1,
            round: 0,
            block: sample_block()
        }
        .is_large());
    }

    #[test]
    fn tx_gossip_roundtrip_and_fail_closed() {
        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let bytes = bincode::serialize(&tx).unwrap();
        let raw = serde_json::json!({ "topic": tx_topic("test"), "data": hex::encode(bytes) })
            .to_string();
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
            assert!(
                sender.enqueue(vec![tagged_vote(id)]),
                "enqueue {id} must succeed"
            );
        }
        assert_eq!(
            sender.queued(),
            5,
            "all five chunks are pending before send"
        );

        // The enqueue path is non-blocking: five chunks are already queued while
        // the worker is still sleeping on the first.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while seen.lock().unwrap().len() < 5 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            *seen.lock().unwrap(),
            vec![0, 1, 2, 3, 4],
            "FIFO order must hold"
        );
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
        assert!(
            !is_superseded_vote(&old_prevote, 10, 5),
            "other heights never drop"
        );
        assert!(!is_superseded_vote(
            &ConsensusMsg::Proposal {
                height: 9,
                round: 0,
                block: sample_block()
            },
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
        let p = ConsensusMsg::Proposal {
            height: 9,
            round: 5,
            block: sample_block(),
        };
        let out = coalesce_for_send(vec![v(), v(), stale, p.clone(), v()], 9, 5);
        assert_eq!(
            out.len(),
            2,
            "one live vote + the proposal, got {}",
            out.len()
        );
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
        let p = ConsensusMsg::Proposal {
            height: 9,
            round: 4,
            block: sample_block(),
        };
        let t0 = Instant::now();
        let mut f = VoteSendFilter::new(Duration::from_millis(200));
        assert!(f.should_send(&v, t0));
        assert!(
            !f.should_send(&v, t0 + Duration::from_millis(50)),
            "same-tick dup must coalesce"
        );
        assert!(
            f.should_send(&p, t0 + Duration::from_millis(50)),
            "proposals never deduped"
        );
        assert!(
            f.should_send(&p, t0 + Duration::from_millis(51)),
            "proposals never deduped twice"
        );
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
        assert_eq!(
            retransmit_interval_ms(800, 10_000),
            1600,
            "capped at 2x timeout"
        );
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
        assert_eq!(
            sender.queued(),
            cap,
            "a refused enqueue must not consume a slot"
        );
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
        if let Ok(bytes) = (ConsensusMsg::Vote {
            vote: crate::consensus::Vote::signed_with(
                [7u8; 32],
                1,
                0,
                crate::consensus::VoteKind::Prevote,
                None,
                vec![0u8; 64],
            ),
            locked: None,
        }
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
            assert!(
                r.is_ok(),
                "ConsensusMsg::decode panicked on len {}",
                input.len()
            );
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
/// ONLY [`ConsensusMsg::Committed`] bypasses: it is the live catch-up proof
/// (a full block + QC, rare and self-validating) and must never wait behind
/// bulk gossip. Votes and proposals are quorum-critical but CHEAP to forge in
/// shape (a singleton vote is a few hundred bytes): exempting every
/// non-Batch message let an attacker trickle singleton votes — never a Batch
/// — and burn Ed25519 verifications while the bulk limiter saw nothing. They
/// are budget-checked like any other gossip now; per-peer buckets mean an
/// honest peer's votes still pass while the flooder's own bucket is empty.
///
/// PENTEST F2 (P1): the old predicate was `!matches!(Batch)` — everything but
/// Batch bypassed, and the receiver loop only consulted the limiter FOR Batch
/// envelopes, so the limiter was dead code for the cheapest flood shape.
pub fn inbound_is_critical(msg: &ConsensusMsg) -> bool {
    matches!(msg, ConsensusMsg::Committed { .. })
}

/// Per-tick cap on Committed catch-up proofs admitted to verification.
///
/// VERIFICATION F2-hardening: `Committed` bypasses the inbound byte limiter
/// (it must never wait behind bulk gossip) — which means a single peer can
/// emit UNBOUNDED fake Committed envelopes (up to 32 MiB each) and every one
/// of them used to skip the per-tick verification budget too, burning a full
/// block deserialize + QC quorum-check each. The live path needs ~1 proof per
/// finalize; anything past this cap in one tick is flood tail and is dropped
/// LOUDLY (the sender rebroadcasts every finalize and the DHT walk is the
/// fallback, so no honest catch-up is lost — only delayed past the flood).
pub const COMMITTED_INNER_BUDGET_PER_TICK: u32 = 8;

/// True when one more Committed proof may be verified this tick.
pub fn committed_admit_this_tick(already_admitted: u32) -> bool {
    already_admitted < COMMITTED_INNER_BUDGET_PER_TICK
}

/// True when a proposal may plant the catch-up `peer_hint`.
///
/// VERIFICATION G1-hardening: the receiver loop records `(height-1,
/// prev_hash)` from a proposal for the NEXT height so catch-up can pull the
/// height we missed. That hint forces the catch-up timer every tick, so it
/// must be attributable — a FORGED proposal (bad signature, or a signer with
/// no stake) must never plant it, or one junk envelope per tick keeps a node
/// running loudly-failing DHT walks forever. The runtime's own hint (inside
/// `on_proposal`) already verifies first; this gates the receiver loop's
/// pre-hint on the same two checks (signature + membership).
///
/// P1-G2..G4 — ACCEPTED (no content to verify; R3 CODE-TAILS sweep,
/// 2026-10-26). The P1 wave filed five G-series IDs; G1 (this gate) and G5
/// (oracle-fetch re-verification, `crate::network::decode_verified_price_feed`
/// / `fetch_price_feed`) shipped with content and are pinned by tests. G2, G3
/// and G4 were filed as bare IDs with no recorded content anywhere — confirmed
/// by the closing searches, all empty:
/// `git log --all -S "P1-G2" / -S "P1-G3" / -S "P1-G4"` (no commits),
/// `rg "P1-G"` across the tree (no hits outside this note),
/// `rg "\bG[234]\b"` (only BLS curve points in `src/bls.rs`),
/// `rg -i "filed.?gap"` (no markers), and the P1 wave report itself
/// (`docs/audits/audit-pentest-p2p-mempool.md`, parent dir) contains no
/// G-series content at all. There is nothing to reproduce, nothing to pin,
/// and no future audit may list G2–G4 as "filed": this note is the closure,
/// pinned by `report_p1_g2_g4_filed_without_content_is_closed_as_accepted`
/// below, which re-asserts the two content-bearing bookends (G1, G5).
pub fn proposal_hint_admissible(block: &Block, validators: &ValidatorSet) -> bool {
    crate::consensus::verify_proposer_signature(block) && validators.power_of(&block.proposer) != 0
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

/// Limiter bucket key used when the inbound envelope carries NO sender.
///
/// Only reachable for a foreign/legacy sender that does not put `src`/`from`
/// into the envelope. It is deliberately ONE shared bucket: without an
/// identity there is nothing to key on, and a shared bucket still bounds the
/// aggregate bulk rate (which is the flood shape that wedges vote handling).
pub const INBOUND_BROADCAST_PEER_KEY: &str = "broadcast";

/// Maximum accepted length of an inbound limiter bucket key (hex chars).
///
/// PENTEST F3 (P1): the key is a `HashMap` key allocated per distinct sender.
/// An unvalidated `src` (up to a whole JSON string) lets one peer mint
/// unbounded distinct heap keys. 40 hex chars is a full node id; 128 leaves
/// headroom for future id forms without letting one envelope bloat the map.
pub const INBOUND_PEER_KEY_MAX_LEN: usize = 128;

/// Derive the inbound limiter bucket key from a raw pubsub envelope.
///
/// The envelope delivered by infnode's `pubsub.msg` handler is
/// `{ "topic", "data", "msg_id", "src" }`, where `src` is the node id of the
/// peer that delivered it (infnode adds it — it is the only place that knows
/// the connection's peer id). `from` is accepted as a fallback for senders
/// that use that name.
///
/// WITHOUT a sender the traffic collapses into ONE shared token bucket, so a
/// single chatty peer can exhaust every other peer's budget — the bug this
/// fixes. With `src` present, every peer gets its own bucket and one noisy
/// neighbour can only defer ITS OWN traffic.
///
/// PENTEST F3 (P1): the chosen value is VALIDATED — non-empty ASCII hex of
/// bounded length (after stripping infnode's `inf1:` prefix). Anything else
/// (oversized, non-hex, empty) falls back to the shared broadcast bucket
/// instead of becoming a distinct attacker-minted map key.
///
/// Pure so the contract is testable without a live peer.
pub fn inbound_peer_key(raw: &str) -> String {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return INBOUND_BROADCAST_PEER_KEY.to_string(),
    };
    let sender = v
        .get("src")
        .or_else(|| v.get("from"))
        .and_then(|s| s.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    match sender {
        // `inf1:` is infnode's canonical prefix for a node id; strip it so the
        // same peer keys identically no matter which form the sender used.
        Some(s) => {
            let bare = s.strip_prefix("inf1:").unwrap_or(s);
            let ok = !bare.is_empty()
                && bare.len() <= INBOUND_PEER_KEY_MAX_LEN
                && bare.bytes().all(|b| b.is_ascii_hexdigit());
            if ok {
                bare.to_string()
            } else {
                INBOUND_BROADCAST_PEER_KEY.to_string()
            }
        }
        None => INBOUND_BROADCAST_PEER_KEY.to_string(),
    }
}

/// Per-peer byte-rate limiter for inbound bulk traffic.
///
/// Token bucket per peer: `burst` tokens capacity, refilled at `rate_bps`.
/// Only [`ConsensusMsg::Committed`] bypasses (see [`inbound_is_critical`])
/// without consuming budget, so the live catch-up proof never waits behind
/// bulk gossip. Every other message that fits is admitted; the rest defer
/// with a rate-derived wait hint. Bounded to [`INBOUND_MAX_TRACKED_PEERS`] keys.
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
            InboundDecision::Defer {
                wait_ms: wait.clamp(1, INBOUND_MAX_DEFER_WAIT_MS),
            }
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
    /// `msg` its kind. Only [`ConsensusMsg::Committed`] always
    /// [`InboundDecision::Allow`]s (the catch-up proof must never wait);
    /// every other message [`InboundDecision::Allow`]s while the peer is
    /// within budget and [`InboundDecision::Defer`]s with a bounded wait
    /// hint when over — the loop requeues deferred messages instead of
    /// handling them inline, which keeps a bulk flood from wedging vote
    /// handling. Nothing is ever dropped.
    pub fn admit_inbound(
        &self,
        peer_hex: &str,
        msg: &ConsensusMsg,
        bytes: usize,
    ) -> InboundDecision {
        let now = epoch_ms();
        // Global shed meter observes EVERY inbound byte (allowed or
        // deferred): it is a per-second counter, not a per-message gate, so
        // the per-peer decision below is untouched by it.
        if let Ok(mut shed) = self.inbound_shed.lock() {
            shed.observe(bytes as u64, now);
        }
        match self.inbound_bulk.lock() {
            Ok(mut l) => l.admit(peer_hex, bytes as u64, inbound_is_critical(msg), now),
            Err(_) => InboundDecision::Allow,
        }
    }

    /// True while the node is shedding new connection attempts: the global
    /// per-second inbound byte counter is over [`INBOUND_SHED_BYTES_PER_SEC`].
    /// Callers refuse NEW dials/handshakes (counted) and keep serving
    /// existing connections. Fail-open (`false`) when the meter is poisoned.
    pub fn shed_refuse_new(&self) -> bool {
        match self.inbound_shed.lock() {
            Ok(mut shed) => {
                if shed.shed_active(epoch_ms()) {
                    shed.note_refused();
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Shed refusals imposed so far (over-const inbound windows observed +
    /// new dials refused while shedding). Fail-open 0 when poisoned.
    pub fn shed_refused_total(&self) -> u64 {
        match self.inbound_shed.lock() {
            Ok(shed) => shed.refused_total(),
            Err(_) => 0,
        }
    }

    /// Peer evictions imposed by the target policy so far.
    pub fn peer_evicted_total(&self) -> u64 {
        self.peer_evicted_total.load(Ordering::Relaxed)
    }

    /// Enforce the peer-target policy (see [`PEER_EVICT_TARGET_MAX`]): when
    /// the live peer table (static + dynamic) grows past the target, evict
    /// the worst NON-STATIC peer (see [`evict_candidate`]) and count it.
    /// Static config peers are never evicted (they include every validator:
    /// the validator set is not plumbed to the net layer — [`ValidatorSet`]
    /// is only borrowed at isolated call sites like
    /// [`proposal_hint_admissible`] — so static-membership is the
    /// validator-exemption rule). No-op at/below target: honest stands never
    /// reach it, so their behavior is byte-identical.
    pub async fn enforce_peer_target(&self) {
        let live: Vec<[u8; 20]> = {
            let peers = self.adapter.node.peers.read().await;
            peers.keys().copied().collect()
        };
        if live.len() <= PEER_EVICT_TARGET_MAX {
            return;
        }
        let mut statik = std::collections::HashSet::new();
        for p in &self.adapter.node.cfg.peers {
            if let Ok(pid) = p.node_id_raw() {
                statik.insert(pid);
            }
        }
        let fails: HashMap<[u8; 20], u32> = match self.peer_health.lock() {
            Ok(h) => h.iter().map(|(k, v)| (*k, v.fails)).collect(),
            Err(_) => HashMap::new(),
        };
        let scores: Vec<PeerScore> = live
            .iter()
            .map(|pid| PeerScore {
                id: *pid,
                fails: fails.get(pid).copied().unwrap_or(0),
                is_static: statik.contains(pid),
            })
            .collect();
        if let Some(pid) = evict_candidate(&scores, PEER_EVICT_TARGET_MAX) {
            self.adapter.node.invalidate_peer_conn(pid).await;
            self.peer_evicted_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "[net] peer target {} exceeded ({} live): evicted worst non-static peer {}",
                PEER_EVICT_TARGET_MAX,
                live.len(),
                hex::encode(pid),
            );
        }
    }
}

// ==================== SEND-side flood controls (CometBFT-style) ====================

/// Sustained per-peer SEND budget on gossip publish in bytes/sec. A spammer
/// publisher burning hotter than this is dropped per-peer (see
/// [`SendRateLimiter`]); honest gossip (a few small frames/sec) never reaches
/// it, so honest behavior is unchanged.
pub const SEND_RATE_PER_PEER_BYTES_PER_SEC: u64 = 1024 * 1024;
/// Burst headroom per peer on gossip publish in bytes. One
/// [`MAX_TX_MSG`] frame always fits, so no honest single publish is dropped.
pub const SEND_BURST_PER_PEER_BYTES: u64 = 4 * 1024 * 1024;
/// Cap on tracked send-limiter peers (memory bound, mirrors
/// [`INBOUND_MAX_TRACKED_PEERS`]). Overflow evicts an arbitrary entry.
pub const SEND_MAX_TRACKED_PEERS: usize = 1024;

/// Peer-target ceiling for the live peer table (static + dynamic). Below the
/// infnode hard cap (`MAX_CONN_PEERS_TOTAL = 4096`, read-only): when the live
/// table grows past this, the worst non-static peer is evicted (see
/// [`evict_candidate`]). Honest stands run far below it.
pub const PEER_EVICT_TARGET_MAX: usize = 512;

/// Global inbound-bandwidth shed threshold in bytes/sec. Over this within one
/// wall-clock second the node sheds cheapest-first: NEW connection attempts
/// are refused (counted) while EXISTING connections keep serving (see
/// [`InboundShed`]). Set above the per-peer bulk budget times a healthy peer
/// count, so honest stands never trip it.
pub const INBOUND_SHED_BYTES_PER_SEC: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct SendBucket {
    tokens: f64,
    last_ms: u64,
}

/// Per-peer SEND rate limiter for gossip publish (TxGossip fanout).
///
/// Mirrors the receive-side bucket idiom ([`InboundBulkLimiter`]): sustained
/// `rate_bps` bytes/sec with `burst` headroom, per-peer token buckets keyed
/// by node id, time-injected (`now_ms`) for deterministic tests. Difference:
/// over-budget SENDS are DROPPED for that peer only (with [`Self::dropped_total`]
/// counting) and the publisher is NEVER blocked — the flush moves on to the
/// next peer. A single message larger than the burst never passes.
pub struct SendRateLimiter {
    rate_bps: f64,
    burst: f64,
    buckets: HashMap<[u8; 20], SendBucket>,
    max_peers: usize,
    dropped_total: u64,
}

impl SendRateLimiter {
    /// General constructor: sustained `rate_bps` bytes/sec, `burst` headroom.
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            rate_bps: (rate_bps.max(1)) as f64,
            burst: (burst_bytes.max(1)) as f64,
            buckets: HashMap::new(),
            max_peers: SEND_MAX_TRACKED_PEERS,
            dropped_total: 0,
        }
    }

    /// Production shape from the in-code consts (no env knobs).
    pub fn with_defaults() -> Self {
        Self::new(
            SEND_RATE_PER_PEER_BYTES_PER_SEC,
            SEND_BURST_PER_PEER_BYTES,
        )
    }

    /// Over-budget send drops for one peer so far (monotonic).
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    /// Peers currently tracked (for the memory-bound pin).
    pub fn peer_count(&self) -> usize {
        self.buckets.len()
    }

    /// True when `bytes` for `peer` at `now_ms` may be sent (budget spent).
    /// False when over budget: the caller must DROP that peer's send (counted
    /// here) and move on — never block the publisher, never retry inline.
    pub fn try_send(&mut self, peer: &[u8; 20], bytes: u64, now_ms: u64) -> bool {
        if (bytes as f64) > self.burst {
            self.dropped_total = self.dropped_total.saturating_add(1);
            return false;
        }
        if !self.buckets.contains_key(peer) && self.buckets.len() >= self.max_peers {
            if let Some(k) = self.buckets.keys().next().cloned() {
                self.buckets.remove(&k);
            }
        }
        let bucket = self.buckets.entry(*peer).or_insert(SendBucket {
            tokens: self.burst,
            last_ms: now_ms,
        });
        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        if elapsed > 0 {
            bucket.tokens =
                (bucket.tokens + elapsed as f64 / 1000.0 * self.rate_bps).min(self.burst);
            bucket.last_ms = now_ms;
        }
        if bucket.tokens >= bytes as f64 {
            bucket.tokens -= bytes as f64;
            true
        } else {
            self.dropped_total = self.dropped_total.saturating_add(1);
            false
        }
    }
}

/// One peer's standing for the eviction choice.
#[derive(Debug, Clone, Copy)]
pub struct PeerScore {
    /// Node id ([u8; 20] infnode identity).
    pub id: [u8; 20],
    /// Consecutive send/probe failures (higher = lower reputation = evict first).
    pub fails: u32,
    /// Static config peers are NEVER evicted (validator-exemption rule: the
    /// validator set is not plumbed to the net layer, and every validator is
    /// a static config peer in every deployment).
    pub is_static: bool,
}

/// Pure eviction choice: `None` at/below `target` or when every peer is
/// static; otherwise the non-static peer with the worst (highest) failure
/// streak. Ties break to the first worst in slice order (deterministic for a
/// fixed input order). Never evicts validators: without a validator↔node-id
/// map at the net layer, static-membership is the exemption rule.
pub fn evict_candidate(peers: &[PeerScore], target: usize) -> Option<[u8; 20]> {
    if peers.len() <= target {
        return None;
    }
    let mut best: Option<[u8; 20]> = None;
    let mut best_fails: u32 = 0;
    let mut found = false;
    for p in peers {
        if p.is_static {
            continue;
        }
        if !found || p.fails > best_fails {
            found = true;
            best_fails = p.fails;
            best = Some(p.id);
        }
    }
    best
}

/// Global inbound-bandwidth shed meter: a per-second inbound byte counter.
/// Over `cap_bytes_per_sec` within one wall-clock second the node is shedding:
/// NEW connection attempts are refused (see [`ConsensusNetwork::shed_refuse_new`],
/// counted in [`Self::refused_total`]) while EXISTING connections keep
/// serving. Cheapest-first: unproven newcomers are refused before any proven
/// (existing) route is touched. Time-injected (`now_ms`) for deterministic
/// tests; wall-clock seconds anchor the window.
pub struct InboundShed {
    cap_bytes_per_sec: u64,
    window_sec: u64,
    used: u64,
    refused_total: u64,
}

impl InboundShed {
    /// General constructor: shed while over `cap_bytes_per_sec` per second.
    pub fn new(cap_bytes_per_sec: u64) -> Self {
        Self {
            cap_bytes_per_sec: cap_bytes_per_sec.max(1),
            window_sec: u64::MAX,
            used: 0,
            refused_total: 0,
        }
    }

    /// Observe `bytes` of inbound traffic at `now_ms`. Returns false while
    /// shedding (the caller refuses NEW connection attempts, keeps existing);
    /// every shed observation is counted.
    pub fn observe(&mut self, bytes: u64, now_ms: u64) -> bool {
        let sec = now_ms / 1000;
        if sec != self.window_sec {
            self.window_sec = sec;
            self.used = 0;
        }
        self.used = self.used.saturating_add(bytes);
        if self.used > self.cap_bytes_per_sec {
            self.refused_total = self.refused_total.saturating_add(1);
            false
        } else {
            true
        }
    }

    /// True while the current wall-clock second is over budget (new attempts
    /// must be refused). Pure read: does not count.
    pub fn shed_active(&self, now_ms: u64) -> bool {
        self.window_sec == now_ms / 1000 && self.used > self.cap_bytes_per_sec
    }

    /// Count one refused NEW connection attempt while shedding.
    pub fn note_refused(&mut self) {
        self.refused_total = self.refused_total.saturating_add(1);
    }

    /// Shed refusals so far (over-const observations + refused new attempts).
    pub fn refused_total(&self) -> u64 {
        self.refused_total
    }
}
