use super::compact_prop;
use super::dandelion;
use super::limiter::{admit_critical_predecode, peer_key_from_json};
use crate::consensus::{
    decode_pq_micro_envelope, encode_pq_micro_envelope, PqMicroCertificate, QuorumCertificate,
    Vote, VoteKind, PQ_UQC_MARKER_ID,
};
use crate::sharding::Block;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

/// Maximum raw consensus payload bytes that fit inside one `infnode` pubsub
/// message after hex-encoding (`MAX_PUBSUB_DATA_LEN / 2`).
pub const MAX_CONSENSUS_PUBSUB_BYTES: usize = infnode::proto::MAX_PUBSUB_DATA_LEN / 2;

const _: () = assert!(
    MAX_TX_MSG * 2 <= infnode::proto::MAX_PUBSUB_DATA_LEN,
    "MAX_TX_MSG hex encoding must fit within infnode MAX_PUBSUB_DATA_LEN"
);
const _: () = assert!(
    infnode::proto::MAX_PUBSUB_DATA_LEN < infnode::proto::MAX_FRAME,
    "infnode MAX_PUBSUB_DATA_LEN must fit inside MAX_FRAME"
);

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

/// bincode discriminant of [`ConsensusMsg::Batch`] under the fixint encoding
/// (variant index 3, little-endian u32). Used by the hand-rolled batch decoder
/// and its cheap pre-deserialize size guard (C1-F2).
pub(super) const BATCH_VARIANT_TAG: [u8; 4] = [3, 0, 0, 0];

/// bincode discriminant of [`ConsensusMsg::Committed`] (variant index 2).
/// The critical pre-decode budget only charges this shape (C1-F4).
pub(super) const COMMITTED_VARIANT_TAG: [u8; 4] = [2, 0, 0, 0];

/// Maximum number of drained chunks that may wait in the background broadcast
/// sender before the flush stops draining and applies backpressure (the rest
/// stay in the consensus outbox and are retried/still deduplicated next tick).
/// Bounds sender memory if the transport is wedged; enqueue alone does not
/// guarantee transport delivery or survival of sender task failure.
pub const MAX_PENDING_CHUNKS: usize = 256;

/// Coalescing window for duplicate vote sends (tail-killer, send side).
///
/// The loop re-enqueues the same vote from three paths (periodic retransmit,
/// view-change re-send, timer flush) within ~100-400ms of each other. The
/// outbox dedups only while items are still queued; once a chunk is handed to
/// the background sender a re-enqueue becomes a second wire copy, which is the
/// 3-4x duplicate RX seen live. Suppressing an identical vote re-send inside
/// this window coalesces those copies. It is deliberately SHORTER than the
/// retransmit cadence (the first retransmit is `base = clamp(T/10, 150ms,
/// 350ms)`, see [`retransmit_interval_ms`]): a vote lost in transit is still
/// retried on schedule, only the same-tick duplicates collapse.
pub const VOTE_SEND_DEDUP_TTL_MS: u64 = 200;

/// A vote is superseded once we are two rounds past it: a prevote/precommit
/// for round r at height h can never contribute to a quorum once the node is
/// at (h, r+2), because quorums form per (height, round) and the network has
/// moved on. Dropping such votes under pressure is safe; proposals, commits
/// and finalized artifacts are NEVER droppable (a commit is the only proof a
/// lagging peer learns the outcome from).
pub const SUPERSEDED_ROUND_LAG: u32 = 2;

/// Wire identity of one cast vote: (shard, height, round, kind, voter).
///
/// The shard is part of the identity: one process can run the same validator
/// key on several shards, and the send-time dedup / supersede filters must not
/// collapse a shard-0 vote and a shard-1 vote cast at the same height/round.
pub type VoteWireKey = (u32, u64, u32, u8, [u8; 32]);

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
            vote.shard_id,
            vote.height,
            vote.round,
            vote_kind_tag(vote.kind),
            vote.voter,
        )),
        _ => None,
    }
}

/// True when `msg` is a prevote that is superseded at `(height, round)`: same
/// height, and its round is at least [`SUPERSEDED_ROUND_LAG`] behind.
///
/// `Precommit`s are deliberately EXEMPT (late-polka liveness/safety,
/// `05_LOCK_SAFETY_P0.md` §1.6.2): a valid late-polka `Precommit` at `r0`
/// cast when `hc.round = 11` must reach peers instead of being pruned before
/// wire send. Never true for proposals, commits, or batches.
pub fn is_superseded_vote(msg: &ConsensusMsg, height: u64, round: u32) -> bool {
    match msg {
        ConsensusMsg::Vote { vote, .. } => {
            vote.kind == VoteKind::Prevote
                && vote.height == height
                && vote.round.saturating_add(SUPERSEDED_ROUND_LAG) <= round
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

/// Retransmit interval for the current round, as a function of how long the
/// round has been running. Front-loaded, then exponentially relaxed, capped at
/// `2 * round_timeout`.
///
/// Schedule (`T = round_timeout_ms`), with `base = clamp(T/10, 150ms, 350ms)`
/// and `mid = 2 * base`:
///
/// | elapsed since round start | interval |
/// |---------------------------|----------|
/// | `< T/8`                   | `base`   |
/// | `< T/2`                   | `mid`    |
/// | `< 2T`                    | `T`      |
/// | `>= 2T`                   | `2T`     |
///
/// At the live 3000ms round timeout that is ~300ms for the first retransmit,
/// then ~600ms, then the round timeout, then the cap. A single lost packet
/// therefore costs ~300ms (well under one block at 400ms tempo) instead of
/// the previous `T/2 = 1500ms`, while a genuinely wedged round still backs off
/// to `2T` instead of retrying at full rate forever (the retry storm the old
/// fixed cadence produced).
///
/// DEPENDENCY — vote dedup floor: the send-side coalescing window is
/// [`VOTE_SEND_DEDUP_TTL_MS`] (200ms), and it suppresses an identical vote
/// re-send inside that window. The live first interval is therefore set to
/// 300ms, comfortably ABOVE the dedup window, so the first retransmit is not
/// swallowed (a first interval below ~250ms would be a NO-OP for votes). Only
/// sub-2s timeouts fall back to the 150ms floor, which predates this schedule
/// and is pinned by `bin_tests`; do not lower the live first interval further.
///
/// SCOPE — current round only: the caller uses this cadence only for what it
/// already cast at its CURRENT `(height, round)` (the periodic outbox
/// retransmit). It is not a catch-up throttle and must never be applied to
/// historical heights, so a far-behind node cannot be made to re-flood old
/// rounds faster.
///
/// Pure and time-injected (`elapsed_ms`) so the schedule is testable without a
/// clock; never reads `Instant::now()`.
pub fn retransmit_interval_ms(round_timeout_ms: u64, elapsed_ms: u64) -> u64 {
    let timeout = round_timeout_ms.max(1);
    let base = (timeout / 10).clamp(150, 350);
    let mid = base.saturating_mul(2);
    let cap = timeout.saturating_mul(2).max(base);
    let interval = if elapsed_ms < timeout / 8 {
        base
    } else if elapsed_ms < timeout / 2 {
        mid
    } else if elapsed_ms < timeout.saturating_mul(2) {
        timeout
    } else {
        cap
    };
    interval.min(cap)
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
    // ------------------------------------------------------------------
    // Compact PROPOSAL gossip variants. Deliberately APPENDED after
    // `Batch`: bincode encodes the declaration index, so appending keeps
    // every pre-existing variant (and therefore the whole pre-activation
    // wire format) byte-identical. Inserting these anywhere earlier would
    // renumber `Vote`/`Committed`/`Batch` and break old peers.
    // ------------------------------------------------------------------
    /// Compact announcement of a proposal: the full header + one 6-byte short
    /// id per body slot instead of the body itself.
    ///
    /// GATED: only decodable/emittable once
    /// [`COMPACT_GOSSIP_ACTIVATION_HEIGHT`] is reached at the message's
    /// height. Below the gate this variant never appears on the wire, so the
    /// existing [`ConsensusMsg::Proposal`] path stays byte-identical. The
    /// receiver resolves the ids against its mempool, pulls the misses with a
    /// bounded [`ConsensusMsg::BodyPull`], and prevotes ONLY on a fully
    /// resolved body whose hash matches `proposal.block_hash`.
    CompactProposal {
        proposal: compact_prop::CompactProposal,
    },
    /// Bounded request for the short ids of a compact proposal that were not
    /// in the receiver's mempool (gated like [`ConsensusMsg::CompactProposal`]).
    BodyPull { pull: compact_prop::BodyPull },
    /// Response to a [`ConsensusMsg::BodyPull`]: the requested txs, each bound
    /// to the id it answers (gated like [`ConsensusMsg::CompactProposal`]).
    Body { body: compact_prop::Body },
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
#[cfg(test)]
pub(super) fn batch_bypasses_skip(msgs: &[ConsensusMsg]) -> bool {
    batch_bypasses_skip_refs(msgs.iter())
}

/// Whether the direct mesh may substitute for the per-peer broadcast.
///
/// Exempt payloads (`Committed`, see [`committed_bypasses_skip`]) must NOT
/// use the mesh shortcut: the mesh withholds suspected peers from its direct
/// target set, while the catch-up path deliberately still attempts them
/// (detached, never joined). A `Committed` is exactly the frame a returning /
/// lagging validator needs, so it always takes the per-peer path that
/// addresses cooldown peers too.
pub fn mesh_may_substitute(exempt_skip: bool) -> bool {
    !exempt_skip
}

/// Whether the direct mesh may stand in for the per-peer broadcast.
///
/// All three conditions are load-bearing: the peer set must be mesh-capable,
/// the payload must not be exempt (`Committed` always takes the per-peer
/// path), and the mesh must actually cover every addressed peer.
pub fn mesh_shortcut_allowed(mesh_capable: bool, exempt_skip: bool, covered: bool) -> bool {
    mesh_capable && mesh_may_substitute(exempt_skip) && covered
}

pub(super) fn batch_bypasses_skip_refs<'a>(msgs: impl Iterator<Item = &'a ConsensusMsg>) -> bool {
    msgs.into_iter().any(committed_bypasses_skip)
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
///
/// Compact gossip: `CompactProposal` and `BodyPull` are latency-critical and
/// idempotent (a re-send is harmless and bounded), so they ride the same
/// fire-and-forget path. `Body` keeps the acknowledged form: it is a bulk
/// answer whose delivery the puller's attempt budget cares about.
pub fn message_is_fire_and_forget(msg: &ConsensusMsg) -> bool {
    matches!(
        msg,
        ConsensusMsg::Vote { .. }
            | ConsensusMsg::Proposal { .. }
            | ConsensusMsg::CompactProposal { .. }
            | ConsensusMsg::BodyPull { .. }
    )
}

/// True when EVERY member of a chunk is safe to send fire-and-forget.
///
/// A chunk that carries a [`ConsensusMsg::Committed`] keeps the acknowledged
/// path for the WHOLE chunk: the catch-up proof must not be traded away for
/// latency. An empty chunk is never fire-and-forget (nothing to send).
#[allow(dead_code)] // GATE: public slice-API wrapper; gossip paths use the refs form
pub fn batch_is_fire_and_forget(msgs: &[ConsensusMsg]) -> bool {
    batch_is_fire_and_forget_refs(msgs.iter())
}

pub(super) fn batch_is_fire_and_forget_refs<'a>(
    msgs: impl Iterator<Item = &'a ConsensusMsg>,
) -> bool {
    let mut any = false;
    for m in msgs {
        any = true;
        if !message_is_fire_and_forget(m) {
            return false;
        }
    }
    any
}

/// Encode `items` as one [`ConsensusMsg::Batch`] (P3-H4).
pub fn batch_encode(items: &[ConsensusMsg]) -> Result<Vec<u8>, String> {
    ConsensusMsg::batch_encode(items)
}

/// The live subset of a gossip chunk after the send-time vote dedup, in order.
///
/// Borrows the chunk instead of cloning it: `broadcast_batch` only needs to
/// READ these messages (encode / capability checks), so materializing an owned
/// copy of a 24 MB proposal bought nothing. A `Cow` keeps the fallback path
/// able to hand owned messages where the caller owns them.
pub fn coalesce_live_for_send<'a>(
    msgs: &'a [ConsensusMsg],
    sent_votes: &mut VoteSendFilter,
    now: Instant,
) -> Vec<std::borrow::Cow<'a, ConsensusMsg>> {
    use std::borrow::Cow;
    msgs.iter()
        .filter(|m| sent_votes.should_send(m, now))
        .map(Cow::Borrowed)
        .collect()
}

/// One encoded pubsub frame plus what the stage log reports about it.
#[derive(Debug)]
pub struct BroadcastFrame {
    /// The exact bytes handed to the transport (JSON `{topic,data}` frame).
    pub payload: Vec<u8>,
    /// The hex `data` field (the direct-mesh path wraps it in the same
    /// `{topic,data}` envelope, so it must not be re-framed).
    pub data: String,
    /// Length of the inner (bincode) encoding before hex/JSON framing.
    pub encoded_len: usize,
    /// True when the frame carries a `Batch` of several messages.
    pub is_batch: bool,
}

/// Why a chunk could not be framed. The two classes are handled differently
/// by the caller: a failed SINGLE is dropped, a failed BATCH falls back to
/// one frame per message (so one oversize member cannot sink its batch-mates).
#[derive(Debug)]
pub enum BroadcastEncodeError {
    Single(String),
    Batch(String),
}

impl BroadcastEncodeError {
    pub fn message(&self) -> &str {
        match self {
            Self::Single(e) | Self::Batch(e) => e,
        }
    }

    /// True when the caller may fall back to one frame per message.
    pub fn is_batch(&self) -> bool {
        matches!(self, Self::Batch(_))
    }
}

/// Encode a borrowed chunk as ONE [`ConsensusMsg::Batch`] WITHOUT cloning its
/// members (O7).
///
/// bincode's fixint encoding of `Batch(items)` is exactly
/// `variant tag (u32)` + `Vec length (u64)` + each item's own encoding, so the
/// same bytes can be assembled in a single buffer straight from the borrowed
/// messages. The validation (non-empty, count cap, never nested, byte caps) and
/// the resulting byte string are identical to
/// [`ConsensusMsg::batch_encode_owned`]; only the deep clone of every member
/// (a full block body per proposal) disappears.
fn batch_encode_borrowed(msgs: &[std::borrow::Cow<'_, ConsensusMsg>]) -> Result<Vec<u8>, String> {
    if msgs.is_empty() {
        return Err("empty consensus batch".to_string());
    }
    if msgs.len() > MAX_BATCH_ITEMS {
        return Err(format!("consensus batch too many items: {}", msgs.len()));
    }
    if msgs.iter().any(|m| matches!(&**m, ConsensusMsg::Batch(_))) {
        return Err("nested consensus batch".to_string());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&BATCH_VARIANT_TAG);
    bytes.extend_from_slice(&(msgs.len() as u64).to_le_bytes());
    for m in msgs {
        bytes.extend_from_slice(&m.encode()?);
    }
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(format!("consensus batch too large: {} bytes", bytes.len()));
    }
    if bytes.len() > MAX_CONSENSUS_MSG {
        return Err("consensus message too large".to_string());
    }
    Ok(bytes)
}

/// Build the pubsub frame for a live chunk: bincode encode (single message or
/// one `Batch`), hex, JSON `{"topic", "data"}` — byte-for-byte the framing
/// [`ConsensusNetwork::broadcast_batch`] has always put on the wire.
pub fn encode_broadcast_payload(
    topic: &str,
    msgs: &[std::borrow::Cow<'_, ConsensusMsg>],
) -> Result<BroadcastFrame, BroadcastEncodeError> {
    let (bytes, is_batch) = if msgs.len() == 1 {
        let bytes = msgs[0].encode().map_err(BroadcastEncodeError::Single)?;
        (bytes, false)
    } else {
        let bytes = batch_encode_borrowed(msgs).map_err(BroadcastEncodeError::Batch)?;
        (bytes, true)
    };
    let encoded_len = bytes.len();
    let data = hex::encode(bytes);
    if !infnode::proto::pubsub_data_ok(&data) {
        let err = format!(
            "consensus pubsub data {} bytes exceeds infnode MAX_PUBSUB_DATA_LEN ({})",
            data.len(),
            infnode::proto::MAX_PUBSUB_DATA_LEN,
        );
        return Err(if is_batch {
            BroadcastEncodeError::Batch(err)
        } else {
            BroadcastEncodeError::Single(err)
        });
    }
    let payload = serde_json::json!({ "topic": topic, "data": &data })
        .to_string()
        .into_bytes();
    if payload.len().saturating_add(16) > infnode::proto::MAX_FRAME {
        let err = format!(
            "consensus pubsub frame {} bytes exceeds infnode MAX_FRAME ({})",
            payload.len().saturating_add(16),
            infnode::proto::MAX_FRAME,
        );
        return Err(if is_batch {
            BroadcastEncodeError::Batch(err)
        } else {
            BroadcastEncodeError::Single(err)
        });
    }
    Ok(BroadcastFrame {
        payload,
        data,
        encoded_len,
        is_batch,
    })
}

/// Exact bincode (fixint) length of a `ConsensusMsg::Vote`.
///
/// `bincode::serialize` of the enum writes, in order:
///
/// | field                     | bytes                    |
/// |---------------------------|--------------------------|
/// | variant tag (`u32`)       | 4                        |
/// | `Vote.height` (`u64`)     | 8                        |
/// | `Vote.round` (`u32`)      | 4                        |
/// | `Vote.kind` (enum tag)    | 4                        |
/// | `Vote.block_hash` Option  | 1 (+32 when `Some`)      |
/// | `Vote.voter` (`[u8;32]`)  | 32                       |
/// | `Vote.signature` (`Vec`)  | 8 + `len`                |
/// | `Vote.shard_id` (`u32`)   | 4                        |
/// | `locked` Option           | 1 (+32 when `Some`)      |
///
/// `Vote` carries no maps/strings, so this is the whole encoding; the O8
/// differential test pins it to `encode().len()` for every shape.
pub(super) fn vote_encoded_len(vote: &Vote, locked: &Option<[u8; 32]>) -> usize {
    const FIXED: usize = 4 + 8 + 4 + 4 + 32 + 8 + 4;
    let block_hash = if vote.block_hash.is_some() { 33 } else { 1 };
    let locked = if locked.is_some() { 33 } else { 1 };
    FIXED
        .saturating_add(vote.signature.len())
        .saturating_add(block_hash)
        .saturating_add(locked)
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
        // Compact gossip riding in a batch is still compact gossip: the same
        // activation gate and the same structural caps apply per inner.
        for m in items {
            Self::check_compact_gate(m)?;
        }
        Ok(())
    }

    /// The height a compact-gossip message is bound to, or `None` for every
    /// pre-existing variant. Used by the activation gate and by callers that
    /// route compact traffic separately.
    pub fn compact_gossip_height(&self) -> Option<u64> {
        match self {
            ConsensusMsg::CompactProposal { proposal } => Some(proposal.height),
            ConsensusMsg::BodyPull { pull } => Some(pull.height),
            ConsensusMsg::Body { body } => Some(body.height),
            _ => None,
        }
    }

    /// True for the activation-gated compact-gossip variants.
    pub fn is_compact_gossip(&self) -> bool {
        self.compact_gossip_height().is_some()
    }

    /// Fail-closed admission for compact-gossip messages: activation gate at
    /// the message's height PLUS the structural caps of each payload.
    ///
    /// `Body` is only structurally checked here (its id↔tx binding needs the
    /// answering proposal's salt, which lives in the resolver via
    /// [`open_compact_proposal`]). Pre-activation every compact message is
    /// refused, so the wire is byte-identical and no work is done on one.
    pub fn check_compact_gate(msg: &Self) -> Result<(), String> {
        match msg {
            ConsensusMsg::CompactProposal { proposal } => {
                if !compact_gossip_admits(proposal.height) {
                    return Err("compact gossip inactive".to_string());
                }
                proposal
                    .validate()
                    .map_err(|e| format!("compact proposal: {e}"))?;
            }
            ConsensusMsg::BodyPull { pull } => {
                if !compact_gossip_admits(pull.height) {
                    return Err("compact gossip inactive".to_string());
                }
                pull.validate()
                    .map_err(|e| format!("compact body pull: {e}"))?;
            }
            ConsensusMsg::Body { body } => {
                if !compact_gossip_admits(body.height) {
                    return Err("compact gossip inactive".to_string());
                }
                body.validate_structure()
                    .map_err(|e| format!("compact body: {e}"))?;
            }
            _ => {}
        }
        Ok(())
    }

    /// True when this message should flush the gossip outbox immediately.
    /// Proposals and commits carry full block bodies, so they always flush;
    /// anything else flushes only when its encoding is big (>= 64 KiB).
    pub fn is_large(&self) -> bool {
        match self {
            ConsensusMsg::Proposal { .. } | ConsensusMsg::Committed { .. } => true,
            // Compact gossip frames are consensus-critical (a proposal/flush or
            // a body answer must not wait for the batching window), so they
            // take the same immediate-flush path as a full proposal.
            ConsensusMsg::CompactProposal { .. }
            | ConsensusMsg::BodyPull { .. }
            | ConsensusMsg::Body { .. } => true,
            ConsensusMsg::Batch(..) => true,
            // O8: a Vote's bincode length is fully determined by its scalar
            // header plus the two variable parts (signature bytes and the two
            // Option fields). Decide the 64 KiB flush threshold from that
            // arithmetic instead of materialising the whole encoding just to
            // measure it. `vote_encoded_len` is pinned to `serialize().len()`
            // by the differential test, so the classification is identical.
            ConsensusMsg::Vote { vote, locked } => vote_encoded_len(vote, locked) >= 64 * 1024,
        }
    }

    /// Encode `items` as one [`ConsensusMsg::Batch`].
    pub fn batch_encode(items: &[ConsensusMsg]) -> Result<Vec<u8>, String> {
        Self::batch_encode_owned(items.to_vec())
    }

    /// [`ConsensusMsg::batch_encode`] that takes ownership of the members
    /// instead of cloning them again into the `Batch` (gossip callers already
    /// hold one materialized copy). Same checks, same byte string.
    pub fn batch_encode_owned(items: Vec<ConsensusMsg>) -> Result<Vec<u8>, String> {
        if items.is_empty() {
            return Err("empty consensus batch".to_string());
        }
        if items.len() > MAX_BATCH_ITEMS {
            return Err(format!("consensus batch too many items: {}", items.len()));
        }
        if items.iter().any(|m| matches!(m, Self::Batch(_))) {
            return Err("nested consensus batch".to_string());
        }
        let batch = Self::Batch(items);
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

    /// Decode exactly ONE message from the front of `bytes` (used for batch
    /// elements). Rejects an element whose tag is `Batch` at ANY position, so
    /// nesting can never reach bincode's recursive deserializer.
    fn decode_single_from(bytes: &[u8]) -> Result<(Self, usize), String> {
        if bytes.starts_with(&BATCH_VARIANT_TAG) {
            return Err("nested batch".to_string());
        }
        use bincode::Options;
        let limit = (bytes.len() as u64).min(MAX_CONSENSUS_MSG as u64);
        let mut cursor = std::io::Cursor::new(bytes);
        let msg: Self = bincode::DefaultOptions::new()
            .with_limit(limit)
            .with_fixint_encoding()
            .deserialize_from(&mut cursor)
            .map_err(|e| format!("consensus msg decode: {e}"))?;
        let consumed = cursor.position() as usize;
        if consumed == 0 || consumed > bytes.len() {
            return Err("consensus msg decode: no progress".to_string());
        }
        Ok((msg, consumed))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty consensus message".to_string());
        }
        if bytes.len() > MAX_CONSENSUS_MSG {
            return Err("consensus message too large".to_string());
        }
        // C1-F2: BATCHES ARE DECODED BY HAND, ELEMENT BY ELEMENT. The old
        // pre-check only inspected element 0, so `Batch([Vote, Batch([..])])`
        // reached bincode's recursive `Vec<ConsensusMsg>` deserializer and a
        // deep enough nest aborted the process on stack exhaustion. We parse
        // the fixed header (tag + u64 count), refuse an out-of-cap count
        // BEFORE allocating, and run every element through the SINGLE-message
        // path, which rejects a Batch tag at any position. There is therefore
        // no recursive deserialization left on the peer path.
        if bytes.starts_with(&BATCH_VARIANT_TAG) {
            // Cheap pre-deserialize guard: a Batch can never honestly exceed
            // MAX_BATCH_BYTES, so refuse it before touching bincode.
            if bytes.len() > MAX_BATCH_BYTES {
                return Err(format!("consensus batch too large: {} bytes", bytes.len()));
            }
            const BATCH_HEADER_LEN: usize = 4 + 8; // tag + Vec<u64> length
            if bytes.len() < BATCH_HEADER_LEN {
                return Err("consensus msg decode: truncated batch header".to_string());
            }
            let count = u64::from_le_bytes(
                bytes[4..12]
                    .try_into()
                    .expect("header length checked above"),
            );
            if count == 0 {
                return Err("empty consensus batch".to_string());
            }
            if count > MAX_BATCH_ITEMS as u64 {
                return Err(format!("consensus batch too many items: {count}"));
            }
            let mut items = Vec::with_capacity(count as usize);
            let mut offset = BATCH_HEADER_LEN;
            for _ in 0..count {
                if offset >= bytes.len() {
                    return Err("consensus msg decode: truncated batch".to_string());
                }
                let (item, consumed) = Self::decode_single_from(&bytes[offset..])?;
                offset += consumed;
                items.push(item);
            }
            if offset != bytes.len() {
                return Err("consensus msg decode: trailing bytes after batch".to_string());
            }
            Self::check_batch(&items, bytes.len())?;
            return Ok(Self::Batch(items));
        }
        use bincode::Options;
        let msg: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_CONSENSUS_MSG as u64)
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| format!("consensus msg decode: {e}"))?;
        Self::check_compact_gate(&msg)?;
        Ok(msg)
    }
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

/// Parse a raw pubsub payload (JSON `{ "topic", "data" }`) into a consensus message.
/// Returns None on any malformed input (fail-closed).
pub fn parse_incoming(raw: &str) -> Option<ConsensusMsg> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    ConsensusMsg::decode(&bytes).ok()
}

/// Parse a raw pubsub payload `{ "topic", "data", "src" }` in ONE JSON pass,
/// returning both the decoded `ConsensusMsg` and the validated `inbound_peer_key`.
/// Avoids parsing the JSON envelope twice on the consensus inbound hot path.
pub fn parse_incoming_with_peer_key(raw: &str) -> Option<(ConsensusMsg, String)> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let peer_key = peer_key_from_json(&v);
    // C1-F4: charge the CRITICAL class against its own large per-peer budget
    // BEFORE any hex/bincode decode. `Committed` frames are exactly the class
    // that bypasses the bulk limiter, so without this a peer could make us
    // deserialize unbounded 32 MiB frames per tick. Reading the 4-byte tag from
    // the hex prefix identifies the class without decoding the body; past the
    // budget the frame is DROPPED here (never deferred, never decoded).
    if frame_tag_from_hex(data) == Some(COMMITTED_VARIANT_TAG) {
        let frame_bytes = (data.len() as u64).div_ceil(2);
        if !admit_critical_predecode(peer_key.as_str(), frame_bytes) {
            return None;
        }
    }
    let bytes = hex::decode(data).ok()?;
    let msg = ConsensusMsg::decode(&bytes).ok()?;
    // O10: keep the historical public signature (an owned `String` bucket
    // key) at this boundary; the validated identity itself is now produced
    // allocation-free, and a rejected frame never materialises the String.
    Some((msg, peer_key.as_str().to_string()))
}

/// Read the 4-byte bincode variant tag from a hex `data` field without decoding
/// the body. `None` for a short/non-hex prefix (the full decode will fail).
pub(super) fn frame_tag_from_hex(data: &str) -> Option<[u8; 4]> {
    // Byte slice, not a `&str` slice: `data` is peer-controlled JSON and may
    // contain multi-byte UTF-8, so slicing at byte 8 could split a char.
    let prefix = data.as_bytes().get(..8)?;
    hex::decode(prefix).ok()?.try_into().ok()
}

// ---------------------------------------------------------------------------
// Compact µQC gossip (CODEC WIRED + ADMITTED, emitter call site deferred).
//
// The live path gossips finality as `ConsensusMsg::Committed` (full block +
// full bincode `QuorumCertificate`). This section wires the COMPACT
// alternative: the same certificate content bitfield-indexed in a
// magic-prefixed frame (`compact_prop::COMPACT_QC_MAGIC`), carried in the
// same pubsub `data` field on the same topic. Verification is untouched —
// the receiver rebuilds the identical `QuorumCertificate` and runs the
// unmodified `QuorumCertificate::verify`.
//
// Interop: old software never emits the magic and its bincode-only
// `ConsensusMsg::decode` fails closed on the frame (unknown leading bytes),
// so old nodes IGNORE it, never choke — pinned by
// `old_parser_ignores_compact_qc` below. The gate is now `0`
// (`COMPACT_GOSSIP_ACTIVATION_HEIGHT`), so `compact_gossip_bytes_for` and
// `parse_compact_qc_incoming` are live; the only remaining hookup is the
// broadcast drain calling them (reported below, node-owned).
//
// Deferred hookup (two node call sites):
// * emit: in the broadcast path, `compact_gossip_bytes_for(&msg)` first —
//   `Some(frame)` replaces the full `Committed` encode for that send;
// * admit: in the inbound drain, `parse_compact_qc_incoming(&raw)` alongside
//   `parse_incoming` — `Some(qc)` enters catch-up with the body fetched via
//   the existing sync path. Neither call site is touched by this change.
// ---------------------------------------------------------------------------

/// First height whose proposals AND finality may gossip in compact form.
///
/// `0` = ACTIVE FROM GENESIS. This is a new chain (no pre-activation peers
/// exist), so there is no interoperability window to protect and no reason to
/// spend even the genesis block on the full-body proposal path. The choice is
/// deliberate over `1`: a non-zero gate would leave a special case forever,
/// and the below-gate path is still exercised in tests through
/// [`with_compact_gossip_gate`] (the override installs a temporary concrete
/// gate without writing the compiled production const). The `u64::MAX` sentinel
/// height is still refused by admission regardless of this value.
pub const COMPACT_GOSSIP_ACTIVATION_HEIGHT: u64 = 0;

// Test-only activation override (never set on the live path).
//
// `u64::MAX` means "unset ⇒ use `COMPACT_GOSSIP_ACTIVATION_HEIGHT`". The
// compact-gossip suite drives the REAL emitter/decoder/receiver below a
// concrete gate through `with_compact_gossip_gate` (the production const
// is `0` and is never written). No production code path writes this
// (grep-proof: only the helper below and tests touch it), so the live gate
// remains the const.
thread_local! {
    /// THREAD-LOCAL on purpose: the test matrix runs in parallel, and a
    /// process-wide override let a below-gate test arm `u64::MAX` while an
    /// unrelated test expected the production gate (`receiver_park_budget_is_
    /// bounded` flaked exactly this way). A thread-local override cannot leak
    /// into another test's thread; production never writes it.
    static COMPACT_GOSSIP_TEST_GATE: std::cell::Cell<u64> = const {
        std::cell::Cell::new(u64::MAX)
    };
}

/// Effective gate: the live const unless a test override is installed.
fn compact_gossip_gate() -> u64 {
    COMPACT_GOSSIP_TEST_GATE.with(|g| {
        let over = g.get();
        if over == u64::MAX {
            COMPACT_GOSSIP_ACTIVATION_HEIGHT
        } else {
            over
        }
    })
}

/// True once compact gossip (proposals and µQC) is live for `height`.
#[allow(clippy::absurd_extreme_comparisons)] // GATE: the effective gate is runtime-overridable, so the comparison must stay `>=` even when the compiled const is 0.
pub fn compact_gossip_active(height: u64) -> bool {
    height >= compact_gossip_gate()
}

/// Admission predicate for compact-gossip FRAMES: [`compact_gossip_active`]
/// plus the explicit exclusion of the sentinel height.
///
/// `compact_gossip_active` uses `>=` (so a future coordinated gate keeps
/// working), which means the single value `u64::MAX` compares as "active"
/// against any gate at or below it. No real block exists at that height, so
/// admission must never let a frame named `u64::MAX` slip through.
pub(super) fn compact_gossip_admits(height: u64) -> bool {
    height != u64::MAX && compact_gossip_active(height)
}

/// Run `f` with a temporary compact-gossip activation height.
///
/// Test-only override for the REAL gate: serialized on a process-wide mutex
/// (parallel tests in one binary would otherwise race the global), and always
/// restored, so a panic inside `f` cannot leak an armed gate into the next
/// test. The frozen production const is never written.
pub fn with_compact_gossip_gate<T>(gate: u64, f: impl FnOnce() -> T) -> T {
    let previous = COMPACT_GOSSIP_TEST_GATE.with(|g| g.replace(gate));
    // Restore even if `f` panics, so the override can never leak into a
    // later assertion on this thread.
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    COMPACT_GOSSIP_TEST_GATE.with(|g| g.set(previous));
    match out {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Encode a live QC as a compact gossip frame.
///
/// Extracts the first post-quantum µQC envelope carried under
/// `PQ_UQC_MARKER_ID` (the same entry `QuorumCertificate::verify` consults)
/// and re-frames it bitfield-indexed via `compact_prop`. Epoch/CEC
/// envelopes (`PQ_QC_MARKER_ID`) and marker-less QCs keep the full
/// `Committed` path: this returns `Err` and the caller sends the message
/// unchanged (fail-closed, never half-compact).
pub fn encode_compact_qc_gossip(qc: &QuorumCertificate) -> Result<Vec<u8>, String> {
    let mut micro: Option<PqMicroCertificate> = None;
    for (voter, payload) in &qc.signatures {
        if *voter == PQ_UQC_MARKER_ID {
            if let Some(cert) = decode_pq_micro_envelope(payload) {
                if cert.scheme.is_post_quantum() {
                    micro = Some(cert);
                    break;
                }
            }
        }
    }
    let cert = micro.ok_or_else(|| "compact gossip: QC carries no µQC envelope".to_string())?;
    if cert.height != qc.height || cert.round != qc.round {
        return Err("compact gossip: µQC height/round mismatch".to_string());
    }
    let kind_tag = match qc.kind {
        VoteKind::Prevote => compact_prop::COMPACT_QC_KIND_PREVOTE,
        VoteKind::Precommit => compact_prop::COMPACT_QC_KIND_PRECOMMIT,
    };
    compact_prop::encode_compact_qc(&compact_prop::CompactQc {
        height: qc.height,
        round: qc.round,
        kind_tag,
        block_hash: qc.block_hash,
        scheme_id: cert.scheme.id(),
        committee_size: cert.committee_size,
        sortition_parent: cert.sortition_parent,
        bitfield: cert.signers_bitmask,
        signatures: cert.signatures,
    })
}

/// Decode a compact gossip frame back into the identical live QC shape
/// (µQC envelope under `PQ_UQC_MARKER_ID`, ready for the unmodified
/// `QuorumCertificate::verify`). Pure codec — no activation gate (gating
/// lives at `compact_gossip_bytes_for` / `parse_compact_qc_incoming`).
/// `None` on any malformed frame; non-PQ schemes refuse (FULL-PQ).
pub fn decode_compact_qc_gossip(bytes: &[u8]) -> Option<QuorumCertificate> {
    decode_compact_qc_gossip_in_shard(bytes, crate::sharding::MASTERCHAIN_SHARD)
}

/// [`decode_compact_qc_gossip`] for a known shard. The compact frame is
/// shard-scoped by its topic, so the caller supplies the shard the frame
/// arrived on; the rebuilt certificate's signatures are verified against that
/// shard's vote preimage.
pub fn decode_compact_qc_gossip_in_shard(
    bytes: &[u8],
    shard_id: crate::sharding::ShardId,
) -> Option<QuorumCertificate> {
    if bytes.len() < compact_prop::COMPACT_QC_MAGIC.len()
        || &bytes[..compact_prop::COMPACT_QC_MAGIC.len()] != compact_prop::COMPACT_QC_MAGIC
    {
        return None;
    }
    let compact = compact_prop::decode_compact_qc(bytes)?;
    let scheme = crate::post_quantum::PqScheme::from_id(compact.scheme_id).ok()?;
    if !scheme.is_post_quantum() {
        return None;
    }
    let kind = match compact.kind_tag {
        t if t == compact_prop::COMPACT_QC_KIND_PREVOTE => VoteKind::Prevote,
        t if t == compact_prop::COMPACT_QC_KIND_PRECOMMIT => VoteKind::Precommit,
        _ => return None,
    };
    let cert = PqMicroCertificate::new(
        scheme,
        compact.height,
        compact.round,
        compact.committee_size,
        compact.bitfield,
        compact.signatures,
        compact.sortition_parent,
    );
    let envelope = encode_pq_micro_envelope(&cert);
    Some(QuorumCertificate {
        height: compact.height,
        round: compact.round,
        kind,
        block_hash: compact.block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, envelope)],
        shard_id,
    })
}

/// Live-path emit selector: `Some(compact frame)` IFF `msg` is a
/// `Committed` whose height is compact-active AND whose QC carries a
/// convertible µQC; `None` otherwise (caller sends the message unchanged).
/// Pre-activation this is `None` for every input — the proof the send path
/// is byte-identical while the gate is off.
pub fn compact_gossip_bytes_for(msg: &ConsensusMsg) -> Option<Vec<u8>> {
    match msg {
        ConsensusMsg::Committed {
            height,
            certificate,
            ..
        } => {
            if !compact_gossip_active(*height) {
                return None;
            }
            encode_compact_qc_gossip(certificate).ok()
        }
        _ => None,
    }
}

/// Parse a raw pubsub payload (same JSON `{ "topic", "data" }` framing as
/// [`parse_incoming`]) carrying a compact-µQC frame. Returns the rebuilt QC
/// (body fetched via the existing sync path by the caller) IFF the frame is
/// well-formed AND its height is compact-active; `None` otherwise
/// (fail-closed — pre-activation every input is `None`).
pub fn parse_compact_qc_incoming(raw: &str) -> Option<QuorumCertificate> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    let qc = decode_compact_qc_gossip(&bytes)?;
    if !compact_gossip_active(qc.height) {
        return None;
    }
    Some(qc)
}

// ---------------------------------------------------------------------------
// Compact PROPOSAL gossip (LIVE-PATH WIRING — ACTIVE from genesis).
//
// Proposal gossip used to ship the full `Block` (`ConsensusMsg::Proposal`):
// `366 + 176*N` bytes, i.e. 75_694 B for a 428-tx block. This section wires
// the compact alternative: `CompactProposal { header, block_hash, short_ids }`
// (`366 + 6*N`, ~2_934 B for the same block — measured, see
// `compact_prop` §1/§3), then a bounded `BodyPull`/`Body` exchange for the
// ids a receiver's mempool did not have.
//
// Safety (fail-closed, every step):
// * the announced `block_hash` is the hash of the FULL block; the receiver
//   rebuilds the body in announced slot order and REFUSES a body that does
//   not hash to it (`compact_prop::CompactResolver::complete`);
// * a short-id collision resolves to a MISS, never a guess, so it can only
//   cost a body pull;
// * ids per pull, attempts, response size and the frame ceiling are all
//   bounded (`COMPACT_PULL_*`, `COMPACT_MAX_BYTES` == `MAX_CONSENSUS_MSG`);
// * a proposal whose misses exceed the pull budget falls back to the plain
//   full-proposal fetch — only a FULLY resolved body reaches prevote;
// * parked resolutions and the pull-serving cache have their own count AND
//   byte budgets ([`COMPACT_MAX_PARKED`], [`COMPACT_SERVED_BLOCKS`]).
//
// This section owns the WHOLE mechanism: the emitter selector
// ([`proposal_gossip_msg`]), the receiver state machine
// ([`CompactReceiver`]) and the pull responder ([`CompactBodyServer`]).
// Reported (NOT edited here — `node/**` ownership) node hookup points:
// * sender: `src/node/consensus_driver.rs:1813` — replace the
//   `ConsensusMsg::Proposal { .. }` construction with
//   `proposal_gossip_msg(&block, round)` and call
//   `CompactBodyServer::remember(&block, round)` before enqueueing it;
// * receiver: `src/node/consensus_driver.rs` compact arms feed
//   `CompactReceiver::on_proposal_indexed` / `on_body_indexed` and
//   `CompactBodyServer::serve_for` / `serve_full_for`, and hand
//   `CompactInbound::Ready`'s block to `rt.on_proposal(block.proposer, block,
//   round)` (the full-Proposal arm);
// * outbox policy: `src/node/policy.rs:616-645` — `outbox_has_proposal` and
//   `is_superseded_proposal` must also match `CompactProposal` (helpers
//   [`proposal_gossip_height_round`] / [`is_superseded_proposal`] exist here);
// * compact-µQC emit/admit call sites stay deferred (see the section above).
// ---------------------------------------------------------------------------

/// Emitter: the compact announcement for `block`, or `None` when compact
/// gossip is inactive at its height (caller MUST send the plain `Proposal`
/// then — wire byte-identical) or the block is not compressible.
pub fn compact_proposal_from_block(block: &Block, round: u32) -> Option<ConsensusMsg> {
    compact_proposal_from_block_with_full(block, round, &[])
}

/// Emitter for blocks whose `full_slots` (sealed/private txs peers cannot
/// resolve) must travel inline. Same gate/fallback contract as
/// [`compact_proposal_from_block`].
pub fn compact_proposal_from_block_with_full(
    block: &Block,
    round: u32,
    full_slots: &[u32],
) -> Option<ConsensusMsg> {
    if !compact_gossip_admits(block.height) {
        return None;
    }
    compact_prop::CompactProposal::for_block(block, round, full_slots)
        .ok()
        .map(|proposal| ConsensusMsg::CompactProposal { proposal })
}

/// Receiver: open the resolver for a decoded announcement (structural bounds
/// + activation gate). Live network paths must call
///   [`open_compact_proposal_verified`] (or [`CompactReceiver::on_proposal_indexed`])
///   so proposer signatures are verified before parking or mempool work.
pub fn open_compact_proposal(
    proposal: compact_prop::CompactProposal,
) -> Result<compact_prop::CompactResolver, String> {
    if !compact_gossip_admits(proposal.height) {
        return Err("compact gossip inactive".to_string());
    }
    compact_prop::CompactResolver::new(proposal).map_err(|e| format!("compact proposal: {e}"))
}

/// Receiver: verify the proposer's signature against `(proposal.header,
/// proposal.block_hash)` BEFORE opening/parking the compact resolver.
pub fn open_compact_proposal_verified(
    proposal: compact_prop::CompactProposal,
) -> Result<compact_prop::CompactResolver, String> {
    if !compact_gossip_admits(proposal.height) {
        return Err("compact gossip inactive".to_string());
    }
    if !crate::consensus::verify_proposer_signature_with_hash(
        &proposal.header,
        &proposal.block_hash,
    ) {
        return Err("compact proposal: invalid proposer signature".to_string());
    }
    compact_prop::CompactResolver::new(proposal).map_err(|e| format!("compact proposal: {e}"))
}

/// Receiver: the mempool short-id index for a proposal header.
///
/// `txs` is the caller's local view of the mempool (`Mempool::all()` at the
/// reported call site); the salt is derived from the announced header, so the
/// caller never invents one.
pub fn short_id_index_for(
    header: &Block,
    txs: impl IntoIterator<Item = crate::sharding::Transaction>,
) -> compact_prop::ShortIdIndex {
    compact_prop::ShortIdIndex::from_txs(compact_prop::salt_for_header(header), txs)
}

/// Sender-side selector used by `propose()`.
///
/// Compact when the gate is active and the block compresses, otherwise the
/// plain full [`ConsensusMsg::Proposal`] (below a non-zero gate, or a block
/// whose inline-slot budget would make compression pointless). The full block
/// still reaches lagging peers through the existing DHT/sync catch-up path:
/// this selector only chooses the GOSSIP representation.
pub fn proposal_gossip_msg(block: &Block, round: u32) -> ConsensusMsg {
    // Keep the FULL body reachable for peers that did not negotiate
    // COMPACT_GOSSIP: the compact announcement does not carry the txs, so the
    // sender needs the block to dual-emit a full `Proposal` to those peers at
    // broadcast time. Bounded (4 heights/rounds); a miss degrades to "do not
    // send compact to a peer that cannot decode it" (never the reverse).
    remember_proposal_body(block, round);
    compact_proposal_from_block(block, round).unwrap_or_else(|| ConsensusMsg::Proposal {
        height: block.height,
        round,
        block: block.clone(),
    })
}

// ---------------------------------------------------------------------------
// Dual-emit support: the full body behind the most recent compact proposals.
//
// A compact proposal is header + short ids + inline full slots. To honour the
// capability contract ("a peer without COMPACT_GOSSIP never receives a compact
// frame") the sender must be able to address THOSE peers with the full
// `Proposal`, which needs the block body. `proposal_gossip_msg` caches it here
// (one short-lived entry per emitted proposal), so the broadcast layer can
// build the full form without changing the compact wire format or the node's
// proposal call sites.
// ---------------------------------------------------------------------------

/// Number of recently emitted proposal bodies retained for dual-emit.
pub const PROPOSAL_BODY_CACHE_MAX: usize = 4;

#[derive(Default)]
struct ProposalBodyCache {
    entries: VecDeque<(u64, u32, [u8; 32], Block)>,
}

impl ProposalBodyCache {
    fn insert(&mut self, block: &Block, round: u32) {
        let hash = block.compute_hash();
        self.entries
            .retain(|(h, r, b, _)| !(*h == block.height && *r == round && *b == hash));
        self.entries
            .push_back((block.height, round, hash, block.clone()));
        while self.entries.len() > PROPOSAL_BODY_CACHE_MAX {
            self.entries.pop_front();
        }
    }

    fn get(&self, height: u64, round: u32, hash: &[u8; 32]) -> Option<Block> {
        self.entries
            .iter()
            .find(|(h, r, b, _)| *h == height && *r == round && b == hash)
            .map(|(_, _, _, block)| block.clone())
    }
}

static PROPOSAL_BODIES: OnceLock<Mutex<ProposalBodyCache>> = OnceLock::new();

fn proposal_body_cache() -> &'static Mutex<ProposalBodyCache> {
    PROPOSAL_BODIES.get_or_init(|| Mutex::new(ProposalBodyCache::default()))
}

/// Cache the full body of an emitted proposal for capability-aware dual-emit.
pub fn remember_proposal_body(block: &Block, round: u32) {
    match proposal_body_cache().lock() {
        Ok(mut c) => c.insert(block, round),
        Err(e) => e.into_inner().insert(block, round),
    }
}

/// Retrieve the full `Proposal` equivalent of a compact announcement.
///
/// `None` when the body is no longer cached (or the message is not a compact
/// proposal). Callers MUST treat `None` as "cannot address a non-capable peer
/// with this chunk" and MUST NOT fall back to sending the compact form.
pub fn full_proposal_for_compact(msg: &ConsensusMsg) -> Option<ConsensusMsg> {
    let ConsensusMsg::CompactProposal { proposal } = msg else {
        return None;
    };
    let block = match proposal_body_cache().lock() {
        Ok(c) => c.get(proposal.height, proposal.round, &proposal.block_hash),
        Err(e) => e
            .into_inner()
            .get(proposal.height, proposal.round, &proposal.block_hash),
    }?;
    Some(ConsensusMsg::Proposal {
        height: block.height,
        round: proposal.round,
        block,
    })
}

/// The `(height, round)` a proposal-shaped gossip message announces, compact
/// or full. `None` for every other variant.
///
/// Send-time policy (outbox dedupe, supersede pruning) keys proposals on this
/// pair; keeping it in one place means a compact proposal obeys the same
/// rules as a full one.
pub fn proposal_gossip_height_round(msg: &ConsensusMsg) -> Option<(u64, u32)> {
    match msg {
        ConsensusMsg::Proposal { height, round, .. } => Some((*height, *round)),
        ConsensusMsg::CompactProposal { proposal } => Some((proposal.height, proposal.round)),
        _ => None,
    }
}

/// True when `msg` is a proposal (compact or full) that is superseded at
/// `(height, round)`: a proposal for any other height, or one at least
/// [`SUPERSEDED_ROUND_LAG`] rounds behind. Mirrors the full-only rule the
/// node's outbox policy applies today; compact proposals must prune exactly
/// the same way.
pub fn is_superseded_proposal(msg: &ConsensusMsg, height: u64, round: u32) -> bool {
    match proposal_gossip_height_round(msg) {
        Some((h, r)) => h != height || r.saturating_add(SUPERSEDED_ROUND_LAG) <= round,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Dandelion tx-publish wiring (publish path only; default OFF, no env knob).
//
// The stem/fluff relay POLICY lives in `src/dandelion.rs` (pure, seeded,
// bounded: `MAX_STEM_ENTRIES` / `MAX_SEEN_ENTRIES`, failover via
// `MAX_FAILOVER_RETRIES`, loop budget `r -> r-1`, fluff-wins, fluff timeout).
// It is reused here WITHOUT modification through the module below — the exact
// state machine and the exact params (`DEFAULT_P_CONTINUE`, caps, retry
// budget). This section only ADDS the publish-path glue: tx/peer identity
// mapping, the stem frame codec, the OFF gate, and the decision/inspection
// API the new wiring tests drive.
//
// Status: ORIGINATE-side wiring. `broadcast` (plain transactions only) either
// fans out to all peers (OFF — byte-identical to the historical path) or
// follows the relay decision (ON — tests/sim only): one-peer stem forward
// carrying the remaining budget in a magic-prefixed stem frame, or a normal
// all-peer fluff via the shared `broadcast_bytes` path. Sealed/epoch frames
// (`broadcast_sealed`, `broadcast_mev_frame`) always fluff: consensus-critical
// catch-up traffic never takes the stem.
//
// Explicitly DEFERRED (next audit-gated step, see `docs/DANDELION_PLAN.md`
// section 5): inbound stem dispatch (mapping a received stem frame to
// `on_stem_receive` + relaying), and arming one live fluff-timeout timer per
// held stem entry. The timeout MECHANISM is wired (`dandelion_fluff_timeout`
// force-fluffs a held entry; the publish path falls back to fluff whenever a
// stem cannot be sent), so a swallowed stem can only delay, never suppress —
// but no background timer task is spawned yet.
// ---------------------------------------------------------------------------

/// Dandelion stem/fluff in the tx publish path: default OFF, const-gated.
///
/// OFF (`false`) keeps the publish path byte-identical: `broadcast` serializes
/// and fans out exactly as before. There is deliberately NO env knob — ON is
/// for tests/sim only, driven through the decision API below (plus the
/// `dandelion_reseed` determinism hook), never by operator configuration.
pub const DANDELION_ENABLED: bool = false;

/// Per-stem-entry fluff-timeout budget in ms (stem-blackhole mitigation).
///
/// A held stem entry must force-fluff within this budget; suggested start is
/// single-digit seconds (a few sequential-hop RTTs at the
/// [`BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`] join budget). Live timer arming is
/// deferred (see header); tests drive `dandelion_fluff_timeout` directly.
pub const DANDELION_FLUFF_TIMEOUT_MS: u64 = 3_000;

/// Magic prefix of a Dandelion stem frame on the tx topic.
///
/// Distinct from every epoch-seal magic (`STX1`/`STD1`/`STC1`/`STR1`/`STE1`),
/// so a stem frame is never mis-read as a sealed/DKG/commit/release/announce
/// frame. The historical plain path never emits or parses this prefix: OFF
/// traffic is byte-identical, and an old node fail-closes on a stem frame
/// (its `parse_tx_gossip_payload` bincode-decodes the body and refuses it).
pub const DANDELION_STEM_MAGIC: &[u8; 4] = b"STDL";

/// Dandelion transaction identity: `Sha256` over the gossip-serialised bytes.
///
/// The policy treats identities as opaque; this is the publish path's mapping
/// from wire bytes to that opaque id. `sha2` is already a crate dependency —
/// no new crypto, no new deps.
pub fn dandelion_tx_hash(tx_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tx_bytes);
    h.finalize().into()
}

/// Dandelion peer identity: low 8 bytes (LE) of the 20-byte node id.
///
/// The policy works on abstract `u64`s; this is the publish path's mapping.
/// The reverse lookup (first table entry with a matching low word) lives in
/// the decision helpers; tests use node ids with distinct low words so the
/// mapping is bijective there.
pub fn dandelion_peer_id(pid: &[u8; 20]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&pid[..8]);
    u64::from_le_bytes(b)
}

/// Encode a stem forward: magic + remaining budget (LE u32) + tx bytes.
pub fn encode_dandelion_stem(hops_left: u32, tx_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + tx_bytes.len());
    out.extend_from_slice(DANDELION_STEM_MAGIC);
    out.extend_from_slice(&hops_left.to_le_bytes());
    out.extend_from_slice(tx_bytes);
    out
}

/// Decode a stem forward: `Some((hops_left, tx_bytes))` or `None`.
///
/// Fail-closed: short frames, wrong magic, empty bodies and oversized bodies
/// (past [`MAX_TX_MSG`] plus the 8-byte header) are refused. Never called on
/// the plain fluff path.
pub fn decode_dandelion_stem(bytes: &[u8]) -> Option<(u32, Vec<u8>)> {
    if bytes.len() < 8 || bytes.len() > MAX_TX_MSG + 8 {
        return None;
    }
    if &bytes[..4] != DANDELION_STEM_MAGIC {
        return None;
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[4..8]);
    let inner = bytes[8..].to_vec();
    if inner.is_empty() || inner.len() > MAX_TX_MSG {
        return None;
    }
    Some((u32::from_le_bytes(b), inner))
}

/// What the Dandelion publish path should do with one transaction right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DandelionPublishDecision {
    /// Forward along the stem to exactly one peer, with this remaining budget
    /// (carried in the stem frame header).
    Stem {
        /// The single selected next peer.
        to: [u8; 20],
        /// Stem budget handed to the next hop (`H - 1` at the originator).
        hops_left: u32,
    },
    /// Diffuse with the normal all-peer broadcast (fluff).
    Fluff,
    /// Already seen: send nothing (loop protection / duplicate suppression).
    Drop,
}

/// Map a policy action to a publish decision, resolving the `u64` stem target
/// back to the first peer-table entry with a matching low word.
///
/// Fail-open to fluff: an unresolvable stem target (hash collision between two
/// table entries, or a target that left the table between selection and send)
/// must never blackhole — it fluffs instead.
pub(super) fn map_dandelion_action(
    action: dandelion::RelayAction,
    table: &[([u8; 20], u64)],
) -> DandelionPublishDecision {
    match action {
        dandelion::RelayAction::StemForward { to } => table
            .iter()
            .find(|(_, id)| *id == to)
            .map(|(pid, _)| DandelionPublishDecision::Stem {
                to: *pid,
                hops_left: 0, // filled in by the caller from the held entry
            })
            .unwrap_or(DandelionPublishDecision::Fluff),
        dandelion::RelayAction::FluffBroadcast => DandelionPublishDecision::Fluff,
        dandelion::RelayAction::IgnoreDuplicate => DandelionPublishDecision::Drop,
    }
}

pub fn parse_tx_incoming(raw: &str) -> Option<crate::sharding::Transaction> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_TX_MSG {
        return None;
    }
    crate::network::decode_wire_limited(&bytes, (bytes.len() as u64).min(MAX_TX_MSG as u64)).ok()
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
    let tx: crate::sharding::Transaction =
        crate::network::decode_wire_limited(&bytes, (bytes.len() as u64).min(MAX_TX_MSG as u64))
            .ok()?;
    Some(TxGossipPayload::Plain(tx))
}
