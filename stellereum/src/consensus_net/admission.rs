use super::compact_prop;
use super::framing::{
    compact_gossip_admits, open_compact_proposal, short_id_index_for, ConsensusMsg,
};
use super::limiter::epoch_ms;
use crate::sharding::Block;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Consecutive-failure counter for one peer (see `peer_health`).
#[derive(Clone, Copy, Default)]
pub(super) struct PeerHealth {
    /// Consecutive failures (transport error or timeout). Reset on success.
    pub(super) fails: u32,
    /// When the last failure happened (cooldown measured from here).
    pub(super) last_fail: Option<std::time::Instant>,
    /// Earliest time a new dial to this peer may be attempted (exponential
    /// dial backoff, see [`dial_backoff_ms`]). Set on each failure once the
    /// skip threshold is reached, cleared on success (entry removed). This
    /// extends the fixed [`PEER_SKIP_COOLDOWN`): a peer that stays dead is
    /// retried on a growing schedule instead of every cooldown window, so a
    /// down peer stops costing a handshake-timeout dial every few seconds.
    pub(super) backoff_until: Option<std::time::Instant>,
}

/// Hard cap on `peer_health` entries (bounds memory against sybil/rotating peer keys).
pub(super) const PEER_HEALTH_MAX_ENTRIES: usize = 1024;

/// Evict expired or oldest failure entries from `peer_health` when at capacity.
pub(super) fn enforce_peer_health_cap(
    h: &mut HashMap<[u8; 20], PeerHealth>,
    now: std::time::Instant,
) {
    if h.len() < PEER_HEALTH_MAX_ENTRIES {
        return;
    }
    h.retain(|_, ph| peer_dial_suppressed(ph.fails, ph.last_fail, ph.backoff_until, now));
    while h.len() >= PEER_HEALTH_MAX_ENTRIES {
        let Some(oldest) = h.iter().min_by_key(|(_, ph)| ph.last_fail).map(|(k, _)| *k) else {
            break;
        };
        h.remove(&oldest);
    }
}

/// Skip a peer after this many consecutive failures.
///
/// Safety role (liveness): one slow/dead peer's consecutive timeouts stop
/// stalling the flush once the streak reaches this bound; a single timeout
/// never skips (avoids cascade evictions).
pub(super) const PEER_SKIP_THRESHOLD: u32 = 3;
/// ...and retry it after this long (short cooldown so reconnects don't stall consensus).
pub(super) const PEER_SKIP_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3);

/// Per-request send/probe budget. Default 2000ms (LAN-speed stands); WAN
/// validators raise it via `STELL_SEND_TIMEOUT_MS` — with an 11s peer, a 2s
/// cap turns every send into a certain timeout and the node can never vote
/// (observed live: a WAN newcomer's votes never landed). Single choke point
/// for all consensus-net request caps; the unit-test deadline below keeps
/// its own literal 2s.
pub(super) fn send_timeout() -> std::time::Duration {
    static CACHED: OnceLock<std::time::Duration> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_SEND_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 500)
            .map(std::time::Duration::from_millis)
            .unwrap_or(std::time::Duration::from_secs(2))
    })
}

/// Pure cooldown decision (unit-tested): skip once the failure count reaches
/// the threshold and the last failure is still inside the cooldown window.
/// An old failure means "retry now" (returns false); a zero count never
/// skips, even with a stale timestamp.
pub(super) fn peer_in_cooldown(
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

/// Grace window in ms after `fast_target` peers have finished in
/// [`join_with_quorum_or_timeout`]: once enough fast peers have responded to
/// satisfy quorum, remaining stragglers get at most this grace before being
/// detached so the FIFO broadcast queue moves on without waiting the full
/// `hard_budget`.
pub const BROADCAST_STRAGGLER_GRACE_MS_DEFAULT: u64 = 35;

/// Parse helper for [`broadcast_join_timeout_ms`]: garbage/zero disables
/// nothing, it falls back to the default (same clamp-instead-of-disable shape
/// as the replication pacing parsers). Time-injected so tests need no env.
pub fn parse_broadcast_join_timeout_ms(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(BROADCAST_JOIN_TIMEOUT_MS_DEFAULT)
}

/// Effective flush join budget (`STELL_BROADCAST_JOIN_MS`, default 500), cached
/// once on first read so consensus flushes do not pay `std::env::var` per packet.
pub fn broadcast_join_timeout_ms() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_broadcast_join_timeout_ms(std::env::var("STELL_BROADCAST_JOIN_MS").ok())
    })
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
    static CACHED: OnceLock<u32> = OnceLock::new();
    *CACHED.get_or_init(|| parse_probe_evict_after(std::env::var("STELL_PROBE_EVICT_AFTER").ok()))
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
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_dial_backoff_base_ms(std::env::var("STELL_DIAL_BACKOFF_BASE_MS").ok())
    })
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
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED
        .get_or_init(|| parse_dial_backoff_max_ms(std::env::var("STELL_DIAL_BACKOFF_MAX_MS").ok()))
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
    static CACHED: OnceLock<u32> = OnceLock::new();
    *CACHED
        .get_or_init(|| parse_dial_budget_per_sec(std::env::var("STELL_DIAL_BUDGET_PER_SEC").ok()))
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
    let shift = consec_fails.saturating_sub(PEER_SKIP_THRESHOLD).min(20);
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
    peer_in_cooldown(fails, last_fail, now) || backoff_until.is_some_and(|t| now < t)
}

/// Pure global-budget decision (unit-tested): at most `per_sec` dials per
/// second process-wide, enforced as a min-interval gate
/// (`interval = 1000/per_sec` ms). `None` (no dial yet) always allows.
pub fn dial_budget_should_allow(last_ms: Option<u64>, now_ms: u64, per_sec: u32) -> bool {
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
pub(super) fn peer_backoff_until(
    now: std::time::Instant,
    fails: u32,
) -> Option<std::time::Instant> {
    let backoff = dial_backoff_ms(fails, dial_backoff_base_ms(), dial_backoff_max_ms());
    if backoff == 0 {
        None
    } else {
        Some(now + Duration::from_millis(dial_backoff_jittered_ms(backoff, rand::random::<u64>())))
    }
}

/// True when `pid` is already a known-dead peer (failure streak at/above the
/// skip threshold). Per-attempt outcome logs consult this to stay quiet for
/// known-dead peers (debug) while staying loud for live ones (warn).
pub(super) fn health_is_known_dead(
    health: &Mutex<HashMap<[u8; 20], PeerHealth>>,
    pid: &[u8; 20],
) -> bool {
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

/// Lifetime of one cached mempool short-id index (pentest-2 F-8/C2).
///
/// Short: the index is a snapshot of `Mempool::all()`, and a tx that arrives
/// after the snapshot is simply a MISS (a pull or the full fallback), never a
/// wrong resolution. Two seconds bounds staleness while still amortizing the
/// whole-pool hash pass across every duplicate announcement inside a round.
pub const COMPACT_INDEX_CACHE_TTL_MS: u64 = 2_000;

/// How many `(height, prev_hash)` short-id indexes are retained.
///
/// One live proposal plus one H+1 (the only heights the receiver accepts) is
/// enough; a third would only be stale mempool state held for two seconds.
pub const COMPACT_INDEX_CACHE_MAX: usize = 2;

/// A tiny TTL cache of [`compact_prop::ShortIdIndex`], keyed by the header
/// salt `(height, prev_hash)`.
///
/// This is the receive-side fix for the amplification finding C2/F-8: the old
/// path called `Mempool::all()` and rebuilt a salted index for EVERY compact
/// frame (a ~400 B frame cost an O(mempool) clone + hash pass). The cache is
/// consulted before touching the mempool at all, so a duplicate/replayed
/// announcement costs one lookup. `builds` is a test/visibility counter (the
/// regression test asserts a burst of frames builds at most once per salt).
#[derive(Debug, Default)]
pub struct CompactIndexCache {
    entries: Vec<([u8; 32], compact_prop::ShortIdIndex, Instant)>,
    builds: u64,
}

impl CompactIndexCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of indexes actually built (cache misses).
    pub fn builds(&self) -> u64 {
        self.builds
    }

    /// Cached index for `header`'s salt, if it is still inside the TTL.
    pub fn get(&self, header: &Block, now: Instant) -> Option<&compact_prop::ShortIdIndex> {
        let salt = compact_prop::salt_for_header(header);
        self.entries
            .iter()
            .find(|(s, _, at)| {
                *s == salt
                    && now.duration_since(*at).as_millis() as u64 <= COMPACT_INDEX_CACHE_TTL_MS
            })
            .map(|(_, index, _)| index)
    }

    /// Build and cache the index for `header` from `txs`, returning a borrow to
    /// the cached entry. Expired entries and any entry beyond
    /// [`COMPACT_INDEX_CACHE_MAX`] are dropped first (oldest first).
    pub fn insert(
        &mut self,
        header: &Block,
        txs: impl IntoIterator<Item = crate::sharding::Transaction>,
        now: Instant,
    ) -> &compact_prop::ShortIdIndex {
        let salt = compact_prop::salt_for_header(header);
        self.entries.retain(|(_, _, at)| {
            now.duration_since(*at).as_millis() as u64 <= COMPACT_INDEX_CACHE_TTL_MS
        });
        self.entries.retain(|(s, _, _)| *s != salt);
        while self.entries.len() >= COMPACT_INDEX_CACHE_MAX {
            self.entries.remove(0);
        }
        self.builds += 1;
        self.entries
            .push((salt, compact_prop::ShortIdIndex::from_txs(salt, txs), now));
        &self.entries.last().expect("just pushed").1
    }
}

/// Maximum compact proposals a [`CompactReceiver`] holds parked while waiting
/// for bodies. One height has at most one live proposal, so this is already
/// several rounds of slack; beyond it the queue is an attacker-controlled
/// memory hold.
pub const COMPACT_MAX_PARKED: usize = 4;

/// Byte budget for parked resolutions, measured by the serialized
/// announcement (the resolved transaction clones are additional but bounded
/// by [`compact_prop::COMPACT_MAX_IDS`] slots).
pub const COMPACT_PARKED_BYTES: usize = 64 * 1024 * 1024;

/// Number of recently announced blocks a [`CompactBodyServer`] keeps so it
/// can answer a bounded [`compact_prop::BodyPull`].
pub const COMPACT_SERVED_BLOCKS: usize = 2;

/// Byte budget for the pull responder's recent-block cache.
pub const COMPACT_SERVED_BYTES: usize = 64 * 1024 * 1024;

/// What the node must do after feeding one compact-gossip frame to a
/// [`CompactReceiver`].
///
/// Every arm is a concrete, bounded action: a verified full block for the
/// proposal path, one bounded pull, a fallback to the plain full proposal, or
/// a fail-closed refusal. Nothing here prevotes on a short id.
#[derive(Debug)]
pub enum CompactInbound {
    /// Every slot resolved and the body hashed to the announcement. The
    /// caller MUST hand `block` to `on_proposal(block.proposer, block, round)`
    /// exactly as the full-Proposal arm does.
    Ready { round: u32, block: Box<Block> },
    /// Missing slots within budget: broadcast this bounded pull.
    Pull(compact_prop::BodyPull),
    /// Resolution cannot proceed within budget: fetch the plain full proposal
    /// through the existing path. NEVER prevote on a partial body.
    FetchFull {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        reason: compact_prop::FallbackReason,
    },
    /// Fail-closed refusal; the caller drops and counts it.
    Refused(String),
}

/// One parked compact proposal awaiting its bounded body response.
#[derive(Debug)]
struct ParkedResolution {
    resolver: compact_prop::CompactResolver,
    weight: usize,
}

/// Receiver-side state machine for compact PROPOSAL gossip.
///
/// Holds at most [`COMPACT_MAX_PARKED`] proposals within
/// [`COMPACT_PARKED_BYTES`], evicting oldest first. Every proposal is opened
/// through [`open_compact_proposal`] (gate + structural bounds) and every
/// body goes through [`compact_prop::CompactResolver::accept_body`], so only a
/// fully resolved body whose hash equals the announcement is ever returned as
/// [`CompactInbound::Ready`].
#[derive(Debug, Default)]
pub struct CompactReceiver {
    parked: HashMap<[u8; 32], ParkedResolution>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
}

impl CompactReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Proposals currently parked for a body.
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// Bytes currently attributed to parked proposals.
    pub fn parked_bytes(&self) -> usize {
        self.bytes
    }

    /// Handle a decoded [`ConsensusMsg::CompactProposal`].
    ///
    /// `local_txs` is the local mempool view (`Mempool::all()` at the reported
    /// call site); the salt is derived from the announced header. The live
    /// driver uses [`Self::on_proposal_indexed`] with
    /// [`CompactIndexCache`] so this whole-pool view is built at most once per
    /// `(height, prev_hash)` instead of once per frame.
    pub fn on_proposal(
        &mut self,
        proposal: compact_prop::CompactProposal,
        local_txs: impl IntoIterator<Item = crate::sharding::Transaction>,
    ) -> CompactInbound {
        let hash = proposal.block_hash;
        if let Some(parked) = self.take(&hash) {
            let mut resolver = parked.resolver;
            let index = short_id_index_for(&resolver.proposal().header, local_txs);
            let result = resolver.resolve_against(&index);
            return self.settle(hash, resolver, result);
        }
        let mut resolver = match open_compact_proposal(proposal) {
            Ok(resolver) => resolver,
            Err(e) => return CompactInbound::Refused(e),
        };
        let index = short_id_index_for(&resolver.proposal().header, local_txs);
        let result = resolver.resolve_against(&index);
        self.settle(hash, resolver, result)
    }

    /// [`Self::on_proposal`] with a caller-supplied (cached) index.
    ///
    /// The index salt must equal the parked/announced header's salt; a mismatch
    /// is a fail-closed refusal, never a wrong resolution. A re-announcement
    /// keeps the EXISTING resolver, so its attempt counter cannot be reset by
    /// repeating the same announcement.
    pub fn on_proposal_indexed(
        &mut self,
        proposal: compact_prop::CompactProposal,
        index: &compact_prop::ShortIdIndex,
    ) -> CompactInbound {
        let hash = proposal.block_hash;
        if let Some(parked) = self.take(&hash) {
            let mut resolver = parked.resolver;
            let result = resolver.resolve_against(index);
            return self.settle(hash, resolver, result);
        }
        let mut resolver = match open_compact_proposal(proposal) {
            Ok(resolver) => resolver,
            Err(e) => return CompactInbound::Refused(e),
        };
        let result = resolver.resolve_against(index);
        self.settle(hash, resolver, result)
    }

    /// Header of the parked proposal for `hash`, if any (cheap pre-check so a
    /// `Body` cannot force a mempool clone when nothing is parked).
    pub fn parked_header(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.parked.get(hash).map(|p| &p.resolver.proposal().header)
    }

    /// True when a resolution for `hash` is parked.
    pub fn is_parked(&self, hash: &[u8; 32]) -> bool {
        self.parked.contains_key(hash)
    }

    /// Handle a decoded [`ConsensusMsg::Body`] for a parked proposal.
    ///
    /// A refused body keeps the proposal parked (an honest retry can still
    /// complete it); a failed completion drops it.
    pub fn on_body(
        &mut self,
        body: &compact_prop::Body,
        local_txs: impl IntoIterator<Item = crate::sharding::Transaction>,
    ) -> CompactInbound {
        let hash = body.block_hash;
        let Some(parked) = self.take(&hash) else {
            return CompactInbound::Refused(format!(
                "compact body: no parked proposal for {}",
                hex::encode(hash)
            ));
        };
        let mut resolver = parked.resolver;
        let index = short_id_index_for(&resolver.proposal().header, local_txs);
        let result = resolver.accept_body(body, &index);
        if let Err(refusal) = &result {
            let message = format!("compact body: {refusal}");
            self.park(hash, resolver);
            return CompactInbound::Refused(message);
        }
        self.settle(hash, resolver, result)
    }

    /// [`Self::on_body`] with a caller-supplied (cached) index.
    pub fn on_body_indexed(
        &mut self,
        body: &compact_prop::Body,
        index: &compact_prop::ShortIdIndex,
    ) -> CompactInbound {
        let hash = body.block_hash;
        let Some(parked) = self.take(&hash) else {
            return CompactInbound::Refused(format!(
                "compact body: no parked proposal for {}",
                hex::encode(hash)
            ));
        };
        let mut resolver = parked.resolver;
        let result = resolver.accept_body(body, index);
        if let Err(refusal) = &result {
            let message = format!("compact body: {refusal}");
            self.park(hash, resolver);
            return CompactInbound::Refused(message);
        }
        self.settle(hash, resolver, result)
    }

    fn settle(
        &mut self,
        hash: [u8; 32],
        resolver: compact_prop::CompactResolver,
        result: Result<compact_prop::Resolution, compact_prop::CompactRefusal>,
    ) -> CompactInbound {
        let height = resolver.proposal().height;
        let round = resolver.proposal().round;
        match result {
            Ok(compact_prop::Resolution::Complete(block)) => CompactInbound::Ready { round, block },
            Ok(compact_prop::Resolution::Pull(pull)) => {
                self.park(hash, resolver);
                CompactInbound::Pull(pull)
            }
            Ok(compact_prop::Resolution::FullProposal(reason)) => CompactInbound::FetchFull {
                height,
                round,
                block_hash: hash,
                reason,
            },
            Err(refusal) => CompactInbound::Refused(format!("compact proposal: {refusal}")),
        }
    }

    fn take(&mut self, hash: &[u8; 32]) -> Option<ParkedResolution> {
        let parked = self.parked.remove(hash)?;
        self.order.retain(|h| h != hash);
        self.bytes = self.bytes.saturating_sub(parked.weight);
        Some(parked)
    }

    fn park(&mut self, hash: [u8; 32], resolver: compact_prop::CompactResolver) {
        let weight = bincode::serialized_size(resolver.proposal())
            .ok()
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(usize::MAX);
        // Evict oldest until BOTH the count and the byte budget admit this
        // announcement. A single over-budget proposal is still parked alone
        // (refusing it would make a legal 32 MiB frame unresolvable).
        while !self.order.is_empty()
            && (self.parked.len() >= COMPACT_MAX_PARKED
                || self.bytes.saturating_add(weight) > COMPACT_PARKED_BYTES)
        {
            if let Some(oldest) = self.order.pop_front() {
                if let Some(old) = self.parked.remove(&oldest) {
                    self.bytes = self.bytes.saturating_sub(old.weight);
                }
            }
        }
        self.bytes = self.bytes.saturating_add(weight);
        self.parked
            .insert(hash, ParkedResolution { resolver, weight });
        self.order.push_back(hash);
    }
}

/// One recently announced block, retained only to answer bounded body pulls.
#[derive(Debug)]
struct ServedBlock {
    round: u32,
    hash: [u8; 32],
    block: Block,
    /// short id -> index into `block.transactions`, built once when the block
    /// is remembered. The old responder rebuilt a whole-mempool salted index
    /// (and scanned the block again) for EVERY pull (H2/R5); this map makes a
    /// served pull O(ids).
    tx_ids: HashMap<[u8; compact_prop::SHORT_ID_LEN], usize>,
    weight: usize,
}

/// Bound on the responder's served-once dedupe set.
pub const COMPACT_SERVED_ONCE_MAX: usize = 512;

/// Per-requester pull rate window and cap. A replayed pull is answered once
/// from the dedupe set; this additionally bounds a peer that varies id order
/// or block hash.
pub const COMPACT_PULL_RATE_WINDOW_MS: u64 = 1_000;
pub const COMPACT_PULL_RATE_MAX: u32 = 8;

/// Pull replay cooldown bucket for FULL-proposal requests. A full body is
/// large, so a requester gets at most one reply per this window; a genuinely
/// lost reply is retried after the window instead of being suppressed forever.
pub const COMPACT_FULL_REPLY_COOLDOWN_MS: u64 = 5_000;

/// Hard cap on per-requester rate entries tracked by [`CompactBodyServer`].
pub const COMPACT_PULL_RATE_MAX_PEERS: usize = 1024;

/// One `(requester, request)` already answered.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ServedKey {
    requester: String,
    block_hash: [u8; 32],
    round: u32,
    ids: Vec<[u8; compact_prop::SHORT_ID_LEN]>,
    full: bool,
    /// Body pulls: the attempt number (a NEW attempt is a new request, so a
    /// lost body is recoverable). Full requests: `now / cooldown` bucket.
    bucket: u64,
}

/// Responder side of compact PROPOSAL gossip: a bounded cache of blocks this
/// node announced (or is willing to serve) plus the bounded
/// [`compact_prop::BodyPull`] resolver.
///
/// Serving is deliberately limited to the block THIS node announced (matched
/// by hash, height and round). The old responder required every requested id
/// to still be in `mempool.all()` as well, which made sealed/MEV slots (and any
/// tx that left the pool) unservable even for its own block; the announced
/// block body is public by construction, so it is the authoritative source.
///
/// Amplification bounds (H2/R5):
/// * one reply per `(requester, block_hash, round, id-set)` — a replayed pull
///   produces NO second reply;
/// * per-requester rate window ([`COMPACT_PULL_RATE_MAX`] / 1 s);
/// * only the current/previous announced blocks are cached.
#[derive(Debug, Default)]
pub struct CompactBodyServer {
    recent: VecDeque<ServedBlock>,
    bytes: usize,
    served: VecDeque<ServedKey>,
    served_set: HashSet<ServedKey>,
    rates: HashMap<String, (u64, u32)>,
    served_total: u64,
}

impl CompactBodyServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember a block this node announced at `round` so its missing slots
    /// can be served. Re-remembering the same hash replaces (moves to newest)
    /// instead of duplicating.
    pub fn remember(&mut self, block: &Block, round: u32) {
        let hash = block.compute_hash();
        if let Some(pos) = self.recent.iter().position(|b| b.hash == hash) {
            if let Some(old) = self.recent.remove(pos) {
                self.bytes = self.bytes.saturating_sub(old.weight);
            }
        }
        let weight = bincode::serialized_size(block)
            .ok()
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(usize::MAX);
        let salt = compact_prop::salt_for_header(block);
        let tx_ids = block
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| (compact_prop::short_id(&tx.compute_tx_hash(), &salt), i))
            .collect();
        while !self.recent.is_empty()
            && (self.recent.len() >= COMPACT_SERVED_BLOCKS
                || self.bytes.saturating_add(weight) > COMPACT_SERVED_BYTES)
        {
            if let Some(old) = self.recent.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.weight);
            }
        }
        self.bytes = self.bytes.saturating_add(weight);
        self.recent.push_back(ServedBlock {
            round,
            hash,
            block: block.clone(),
            tx_ids,
            weight,
        });
    }

    /// Number of blocks currently cached.
    pub fn cached_len(&self) -> usize {
        self.recent.len()
    }

    /// True when this node can answer for `block_hash` (cheap pre-check before
    /// any body/mempool work).
    pub fn knows(&self, block_hash: &[u8; 32]) -> bool {
        self.recent.iter().any(|b| b.hash == *block_hash)
    }

    /// Number of pulls actually answered (visibility/test counter).
    pub fn served_count(&self) -> u64 {
        self.served_total
    }

    fn cached(&self, pull: &compact_prop::BodyPull) -> Option<usize> {
        self.recent.iter().position(|b| {
            b.hash == pull.block_hash && b.block.height == pull.height && b.round == pull.round
        })
    }

    /// Consume one served-once + rate-limit slot for `(requester, pull)`.
    /// `None` means "do not answer" (replay, rate limit, or structurally bad).
    fn admit_request(
        &mut self,
        requester: &str,
        pull: &compact_prop::BodyPull,
        now_ms: u64,
    ) -> bool {
        let mut ids = pull.ids.clone();
        ids.sort_unstable();
        let key = ServedKey {
            requester: requester.to_string(),
            block_hash: pull.block_hash,
            round: pull.round,
            ids,
            full: pull.is_full_request(),
            bucket: if pull.is_full_request() {
                now_ms / COMPACT_FULL_REPLY_COOLDOWN_MS.max(1)
            } else {
                pull.attempt as u64
            },
        };
        if self.served_set.contains(&key) {
            return false;
        }
        if !self.rates.contains_key(requester) && self.rates.len() >= COMPACT_PULL_RATE_MAX_PEERS {
            self.rates
                .retain(|_, (ts, _)| now_ms.saturating_sub(*ts) < COMPACT_PULL_RATE_WINDOW_MS);
            if self.rates.len() >= COMPACT_PULL_RATE_MAX_PEERS {
                if let Some(oldest) = self
                    .rates
                    .iter()
                    .min_by_key(|(_, (ts, _))| *ts)
                    .map(|(k, _)| k.clone())
                {
                    self.rates.remove(&oldest);
                }
            }
        }
        let entry = self
            .rates
            .entry(requester.to_string())
            .or_insert((now_ms, 0));
        if now_ms.saturating_sub(entry.0) >= COMPACT_PULL_RATE_WINDOW_MS {
            *entry = (now_ms, 0);
        }
        if entry.1 >= COMPACT_PULL_RATE_MAX {
            return false;
        }
        entry.1 += 1;
        self.served_set.insert(key.clone());
        self.served.push_back(key);
        while self.served.len() > COMPACT_SERVED_ONCE_MAX {
            if let Some(old) = self.served.pop_front() {
                self.served_set.remove(&old);
            }
        }
        true
    }

    /// Answer one bounded pull from the announced block body.
    ///
    /// `Ok(None)` means "cannot answer" (inactive gate, unknown/stale
    /// proposal, replay, rate limit, or an id the announced block does not
    /// contain): the caller sends nothing rather than a partial or fabricated
    /// body. `Err` is a structurally invalid pull, which the caller drops
    /// loudly.
    pub fn serve_for(
        &mut self,
        requester: &str,
        pull: &compact_prop::BodyPull,
        now_ms: u64,
    ) -> Result<Option<compact_prop::Body>, compact_prop::CompactRefusal> {
        pull.validate()?;
        if !compact_gossip_admits(pull.height) || pull.is_full_request() {
            return Ok(None);
        }
        let Some(pos) = self.cached(pull) else {
            return Ok(None);
        };
        if !self.admit_request(requester, pull, now_ms) {
            return Ok(None);
        }
        let entry = &self.recent[pos];
        let salt = compact_prop::salt_for_header(&entry.block);
        let mut txs = Vec::with_capacity(pull.ids.len());
        for id in &pull.ids {
            let Some(idx) = entry.tx_ids.get(id) else {
                return Ok(None);
            };
            let tx = entry
                .block
                .transactions
                .get(*idx)
                .expect("tx_ids is built from this block");
            txs.push((*id, tx.clone()));
        }
        let body = compact_prop::Body {
            height: pull.height,
            round: pull.round,
            block_hash: pull.block_hash,
            txs,
        };
        body.validate(&salt)?;
        self.served_total = self.served_total.saturating_add(1);
        Ok(Some(body))
    }

    /// Answer a FULL-proposal request (`BodyPull::is_full_request`) with the
    /// exact block this node announced at `(height, round, hash)`.
    ///
    /// This is the F-6/H3 fallback: the resolver could not complete from
    /// bounded pulls (cold/divergent mempool, or more misses than three pages),
    /// so the proposer re-sends the full body it already cached. Same
    /// served-once and rate bounds as a normal pull; `Ok(None)` on replay or
    /// when the block is no longer cached.
    pub fn serve_full_for(
        &mut self,
        requester: &str,
        pull: &compact_prop::BodyPull,
        now_ms: u64,
    ) -> Result<Option<Block>, compact_prop::CompactRefusal> {
        pull.validate()?;
        if !pull.is_full_request() || !compact_gossip_admits(pull.height) {
            return Ok(None);
        }
        let Some(pos) = self.cached(pull) else {
            return Ok(None);
        };
        if !self.admit_request(requester, pull, now_ms) {
            return Ok(None);
        }
        let block = self.recent[pos].block.clone();
        self.served_total = self.served_total.saturating_add(1);
        Ok(Some(block))
    }
}

/// Test-visible accounting for compact-gossip `Body` replies.
///
/// Every answered pull is dispatched exactly once through
/// [`dispatch_compact_body_reply`], which increments ONE of the two counters
/// **at dispatch time**. A unicast reply addresses exactly one peer; a
/// broadcast reply is the bounded, fail-open fallback (unknown requester or a
/// unicast that could not be addressed). This is the measurement the compact
/// path is pinned on: ten requesters must read as ten unicast sends, not as
/// ten broadcasts to ten peers (which would be 100 peer sends).
#[derive(Debug, Default)]
pub struct CompactReplyCounters {
    unicast: AtomicU64,
    broadcast: AtomicU64,
}

impl CompactReplyCounters {
    pub const fn new() -> Self {
        Self {
            unicast: AtomicU64::new(0),
            broadcast: AtomicU64::new(0),
        }
    }

    /// Replies dispatched to exactly ONE peer (the requester).
    pub fn unicast_sends(&self) -> u64 {
        self.unicast.load(Ordering::Relaxed)
    }

    /// Replies dispatched through the bounded all-peer broadcast fallback.
    pub fn broadcast_sends(&self) -> u64 {
        self.broadcast.load(Ordering::Relaxed)
    }

    /// Reset both counters (test/measurement window; never called live).
    pub fn reset(&self) {
        self.unicast.store(0, Ordering::Relaxed);
        self.broadcast.store(0, Ordering::Relaxed);
    }

    fn record_unicast(&self) {
        self.unicast.fetch_add(1, Ordering::Relaxed);
    }

    fn record_broadcast(&self) {
        self.broadcast.fetch_add(1, Ordering::Relaxed);
    }
}

/// Why a compact `Body` reply could not be unicast and took the bounded
/// broadcast fallback instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyReplyFallback {
    /// The inbound envelope carried no usable 20-byte node id (`src`/`from`
    /// missing, non-hex, wrong length, or infnode's shared `broadcast` key).
    UnknownRequester,
    /// The requester WAS known but the unicast hand-off failed (encode /
    /// admission preflight); liveness wins, so the bounded broadcast still
    /// delivers the body.
    UnicastFailed,
}

/// Which route one compact `Body` reply actually took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyReplyRoute {
    /// Delivered to exactly one peer.
    Unicast([u8; 20]),
    /// The bounded fail-open fallback (never unbounded: one broadcast per
    /// served pull, already gated by the served-once set and rate cap).
    BoundedBroadcast(BodyReplyFallback),
}

/// Parse an inbound peer key (the `src`/`from` form normalised by
/// [`inbound_peer_key`]) into the 20-byte node id used by the mesh/direct
/// transports.
///
/// Returns `None` for anything that is not exactly 40 ASCII hex chars: the
/// shared [`INBOUND_BROADCAST_PEER_KEY`] bucket, a legacy short tag, an
/// oversized/non-hex `src`, or an empty key. Never guesses an identity.
pub fn peer_id_from_inbound_key(key: &str) -> Option<[u8; 20]> {
    let bare = key.trim();
    let bare = bare.strip_prefix("inf1:").unwrap_or(bare);
    if bare.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(bare, &mut out).ok()?;
    Some(out)
}

/// Dispatch ONE compact-gossip `Body` reply to the requester only.
///
/// * A requester that parses to a 20-byte node id goes out over `unicast`
///   (see [`ConsensusNetwork::send_to_peer`]) and is counted as a UNICAST
///   send. Nothing is broadcast.
/// * A missing/unknown requester, or a unicast that fails its preflight, is
///   counted as a BROADCAST and handed to `broadcast` — the existing bounded
///   outbox path (served-once + per-requester rate cap already ran in
///   [`CompactBodyServer::serve_for`]), so liveness is never traded for
///   silence and amplification never becomes unbounded.
///
/// Split out from the node driver so the routing contract (and the counter)
/// is directly testable: the driver supplies the two delivery closures.
pub async fn dispatch_compact_body_reply<U, Fut, B>(
    requester_key: &str,
    msg: ConsensusMsg,
    counters: &CompactReplyCounters,
    unicast: U,
    broadcast: B,
) -> BodyReplyRoute
where
    U: FnOnce([u8; 20], ConsensusMsg) -> Fut,
    Fut: Future<Output = Result<(), (ConsensusMsg, String)>>,
    B: FnOnce(ConsensusMsg),
{
    let Some(peer) = peer_id_from_inbound_key(requester_key) else {
        counters.record_broadcast();
        broadcast(msg);
        return BodyReplyRoute::BoundedBroadcast(BodyReplyFallback::UnknownRequester);
    };
    match unicast(peer, msg).await {
        Ok(()) => {
            counters.record_unicast();
            BodyReplyRoute::Unicast(peer)
        }
        Err((msg, why)) => {
            tracing::warn!(
                "[consensus] unicast compact body reply to {} failed ({why}); \
                 falling back to the bounded broadcast",
                hex::encode(peer),
            );
            counters.record_broadcast();
            broadcast(msg);
            BodyReplyRoute::BoundedBroadcast(BodyReplyFallback::UnicastFailed)
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
