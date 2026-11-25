use super::framing::ConsensusMsg;
use crate::consensus::ValidatorSet;
use crate::sharding::Block;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A broadcast sub-stage slower than this is logged at WARN (rate-limited);
/// anything faster is logged at DEBUG. The point is to name the slow stage
/// (encode vs `request_to`) instead of only the aggregate broadcast time.
pub const SUBTIMING_WARN_MS: u128 = 200;

/// Minimum gap between two WARN lines from the same sub-timing call site, so a
/// persistently slow transport cannot flood the log.
pub const SUBTIMING_WARN_MIN_GAP_MS: u64 = 1000;

pub(super) fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pure rate-limit decision, split out so it is testable with a synthetic clock.
/// Successful (allowed) calls stamp `gate` with `now_ms`.
pub(super) fn warn_allowed(gate: &AtomicU64, now_ms: u64) -> bool {
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
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_CONS_BCAST_MIN_INTERVAL_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(CONS_BCAST_MIN_INTERVAL_MS_DEFAULT)
    })
}

/// Effective per-peer probe floor (`STELL_CONS_PROBE_MIN_INTERVAL_MS`, default 5000).
pub fn cons_probe_min_interval_ms() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_CONS_PROBE_MIN_INTERVAL_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| n >= 100)
            .unwrap_or(CONS_PROBE_MIN_INTERVAL_MS_DEFAULT)
    })
}

/// Effective inbound bulk rate (`STELL_INBOUND_BULK_BYTES_PER_SEC`, default 512 KiB).
pub fn inbound_bulk_bytes_per_sec() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_INBOUND_BULK_BYTES_PER_SEC")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| n >= 1024)
            .unwrap_or(INBOUND_BULK_BYTES_PER_SEC_DEFAULT)
    })
}

/// Effective inbound burst (`STELL_INBOUND_BULK_BURST_BYTES`, default 1 MiB).
pub fn inbound_bulk_burst_bytes() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_INBOUND_BULK_BURST_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| n >= 1024)
            .unwrap_or(INBOUND_BULK_BURST_BYTES_DEFAULT)
    })
}

/// Sustained per-peer budget for CRITICAL inbound bytes, charged BEFORE
/// decode (C1-F4). Default 4 MiB/s.
///
/// `Committed` is the one message class that bypasses the bulk limiter (it is
/// the live catch-up proof and must never wait behind gossip). That exemption
/// was unbounded: a peer could emit any number of 32 MiB `Committed` frames per
/// tick and every one was deserialized before admission. This budget is
/// deliberately LARGE (one honest proof is never blocked) but finite, and it
/// is charged on the RAW frame length before hex/bincode decoding.
pub const INBOUND_CRITICAL_BYTES_PER_SEC_DEFAULT: u64 = 4 * 1024 * 1024;
/// Burst allowance per peer for critical inbound bytes (default 40 MiB):
/// one maximal 32 MiB frame plus headroom for a normal block or two. A second
/// maximal frame in the same burst window is flood tail and is DROPPED (never
/// deferred) before decode.
pub const INBOUND_CRITICAL_BURST_BYTES_DEFAULT: u64 = 40 * 1024 * 1024;

/// Effective critical inbound rate (`STELL_INBOUND_CRITICAL_BYTES_PER_SEC`).
pub fn inbound_critical_bytes_per_sec() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_INBOUND_CRITICAL_BYTES_PER_SEC")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| n >= 1024)
            .unwrap_or(INBOUND_CRITICAL_BYTES_PER_SEC_DEFAULT)
    })
}

/// Effective critical inbound burst (`STELL_INBOUND_CRITICAL_BURST_BYTES`).
pub fn inbound_critical_burst_bytes() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_INBOUND_CRITICAL_BURST_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| n >= 1024)
            .unwrap_or(INBOUND_CRITICAL_BURST_BYTES_DEFAULT)
    })
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
/// `rg "\bG[234]\b"` (no hits outside this note),
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

/// Fixed-size validated inbound limiter key (O10).
///
/// The validated sender id is at most [`INBOUND_PEER_KEY_MAX_LEN`] ASCII hex
/// bytes, so it fits inline. Deriving the key no longer allocates a `String`
/// per frame; [`Self::as_str`] borrows the same bytes, so the limiter sees the
/// EXACT same key string as before (same validation, same case, same
/// `broadcast` fallback).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerKey {
    /// A validated sender id, stored without its `inf1:` prefix.
    Peer {
        bytes: [u8; INBOUND_PEER_KEY_MAX_LEN],
        len: u8,
    },
    /// No usable sender: the shared bucket.
    Broadcast,
}

impl PeerKey {
    fn from_validated_hex(bare: &str) -> Self {
        debug_assert!(!bare.is_empty() && bare.len() <= INBOUND_PEER_KEY_MAX_LEN);
        let mut bytes = [0u8; INBOUND_PEER_KEY_MAX_LEN];
        bytes[..bare.len()].copy_from_slice(bare.as_bytes());
        Self::Peer {
            bytes,
            len: bare.len() as u8,
        }
    }

    /// The bucket key string (borrowed; never allocates).
    pub fn as_str(&self) -> &str {
        match self {
            Self::Peer { bytes, len } => std::str::from_utf8(&bytes[..*len as usize])
                .expect("peer key bytes are validated ASCII hex"),
            Self::Broadcast => INBOUND_BROADCAST_PEER_KEY,
        }
    }

    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast)
    }
}

impl std::fmt::Display for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for PeerKey {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for PeerKey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<PeerKey> for str {
    fn eq(&self, other: &PeerKey) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<PeerKey> for &str {
    fn eq(&self, other: &PeerKey) -> bool {
        *self == other.as_str()
    }
}

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
pub(super) fn peer_key_from_json(v: &serde_json::Value) -> PeerKey {
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
                PeerKey::from_validated_hex(bare)
            } else {
                PeerKey::Broadcast
            }
        }
        None => PeerKey::Broadcast,
    }
}

pub fn inbound_peer_key(raw: &str) -> PeerKey {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return PeerKey::Broadcast,
    };
    peer_key_from_json(&v)
}

/// Per-peer byte-rate limiter for inbound bulk traffic.
///
/// Token bucket per peer: `burst` tokens capacity, refilled at `rate_bps`.
/// Only [`ConsensusMsg::Committed`] bypasses THIS limiter (see
/// [`inbound_is_critical`]) so the live catch-up proof never waits behind
/// bulk gossip; it is still charged against the separate, larger critical
/// pre-decode budget ([`InboundCriticalBudget`], C1-F4). Every other message
/// that fits is admitted; the rest defer with a rate-derived wait hint.
/// Bounded to [`INBOUND_MAX_TRACKED_PEERS`] keys.
#[derive(Debug)]
pub struct InboundBulkLimiter {
    pub(super) rate_bps: f64,
    pub(super) burst: f64,
    pub(super) peers: HashMap<String, InboundBucket>,
    pub(super) max_peers: usize,
}

#[derive(Debug, Clone)]
pub(super) struct InboundBucket {
    pub(super) tokens: f64,
    pub(super) last_ms: u64,
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
        if !self.peers.contains_key(peer) {
            if self.peers.len() >= self.max_peers {
                if let Some(k) = self.peers.keys().next().cloned() {
                    self.peers.remove(&k);
                }
            }
            // O9: allocate the bucket key ONLY on the first sighting of a
            // peer. The old `entry(peer.to_string())` allocated a String on
            // every message of an already-tracked peer just to hand it to
            // `entry` (which then freed it). The eviction decision above is
            // unchanged: it happens exactly when the key is absent and the
            // map is full.
            self.peers.insert(
                peer.to_string(),
                InboundBucket {
                    tokens: self.burst,
                    last_ms: now_ms,
                },
            );
        }
        let bucket = self
            .peers
            .get_mut(peer)
            .expect("bucket present: inserted above when absent");
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

/// Separate, LARGE per-peer byte budget for critical traffic, charged BEFORE
/// decode (C1-F4).
///
/// Semantics are intentionally different from [`InboundBulkLimiter`]:
///
/// * it is consulted on the RAW frame (tag + length) before hex/bincode work;
/// * over-budget frames are DROPPED (`false`), never deferred — a flood tail
///   must not be parked and replayed later;
/// * it never applies to non-critical messages, so bulk gossip keeps its own
///   (much smaller) bucket.
///
/// Implemented over the same token-bucket primitive; the decision is collapsed
/// to allow/drop because deferral is explicitly not wanted here.
#[derive(Debug)]
pub struct InboundCriticalBudget {
    bucket: InboundBulkLimiter,
}

impl InboundCriticalBudget {
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            bucket: InboundBulkLimiter::new(rate_bps, burst_bytes),
        }
    }

    pub fn with_defaults() -> Self {
        Self::from_env()
    }

    pub fn from_env() -> Self {
        Self::new(
            inbound_critical_bytes_per_sec(),
            inbound_critical_burst_bytes(),
        )
    }

    /// Charge `frame_bytes` for `peer`. `true` = may decode; `false` = drop.
    pub fn admit_predecode(&mut self, peer: &str, frame_bytes: u64, now_ms: u64) -> bool {
        matches!(
            self.bucket.admit(peer, frame_bytes, false, now_ms),
            InboundDecision::Allow
        )
    }

    pub fn peer_count(&self) -> usize {
        self.bucket.peer_count()
    }

    pub fn reset(&mut self) {
        *self = Self::with_defaults();
    }
}

/// Process-wide critical pre-decode budget used by the live parse entry point.
///
/// The receiver loop calls [`parse_incoming_with_peer_key`] BEFORE any
/// admission accounting (the old limiter was charged only after the message had
/// already been decoded), so the budget is enforced here, where the peer id and
/// the raw frame length are both available and no decoding has happened yet.
static INBOUND_CRITICAL_PREDECODE: LazyLock<Mutex<InboundCriticalBudget>> =
    LazyLock::new(|| Mutex::new(InboundCriticalBudget::with_defaults()));

/// Test hook: clear the process-wide critical budget (no effect on policy).
pub fn reset_inbound_critical_budget_for_tests() {
    INBOUND_CRITICAL_PREDECODE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reset();
}

/// Charge one inbound frame against the critical pre-decode budget.
/// `frame_bytes` is the DECODED (pre-hex) size estimate; the caller charges
/// before doing the hex decode.
pub fn admit_critical_predecode(peer: &str, frame_bytes: u64) -> bool {
    INBOUND_CRITICAL_PREDECODE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .admit_predecode(peer, frame_bytes, epoch_ms())
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
        Self::new(SEND_RATE_PER_PEER_BYTES_PER_SEC, SEND_BURST_PER_PEER_BYTES)
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
