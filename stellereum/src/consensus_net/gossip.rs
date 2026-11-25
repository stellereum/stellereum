use super::admission::{
    broadcast_join_timeout_ms, dial_budget_per_sec, enforce_peer_health_cap, evict_candidate,
    health_is_known_dead, peer_backoff_until, peer_dial_suppressed, plan_peer_send,
    probe_evict_after, probe_timeout_should_evict, send_timeout, try_acquire_dial_slot,
    CompactReplyCounters, PeerHealth, PeerScore, SendPlan, BROADCAST_STRAGGLER_GRACE_MS_DEFAULT,
    PEER_HEALTH_MAX_ENTRIES, PEER_SKIP_COOLDOWN, PEER_SKIP_THRESHOLD,
};
use super::dandelion;
use super::framing::{
    batch_bypasses_skip_refs, batch_is_fire_and_forget_refs, coalesce_live_for_send,
    committed_bypasses_skip, consensus_topic, consensus_topic_for_shard, dandelion_peer_id,
    dandelion_tx_hash, encode_broadcast_payload, encode_dandelion_stem, full_proposal_for_compact,
    map_dandelion_action, mesh_shortcut_allowed, message_is_fire_and_forget,
    send_outcome_records_health, tx_topic, ConsensusMsg, DandelionPublishDecision, VoteSendFilter,
    DANDELION_ENABLED, MAX_CONSENSUS_MSG, MAX_PENDING_CHUNKS, MAX_TX_MSG, VOTE_SEND_DEDUP_TTL_MS,
};
use super::limiter::{
    cons_bcast_min_interval_ms, cons_probe_min_interval_ms, epoch_ms, inbound_is_critical,
    log_stage, pace_due, pace_wait_ms, InboundBulkLimiter, InboundDecision, InboundShed,
    SendRateLimiter, INBOUND_SHED_BYTES_PER_SEC, PEER_EVICT_TARGET_MAX,
};
use crate::network::P2pNetworkAdapter;
use crate::protocol::{self, Capabilities};
use crate::sharding::ShardRegistry;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Rate-limit state for the encode sub-stage (one per batch).
static ENCODE_STAGE_GATE: AtomicU64 = AtomicU64::new(0);
/// Rate-limit state for the per-peer `request_to` sub-stage.
static REQUEST_STAGE_GATE: AtomicU64 = AtomicU64::new(0);
/// Rate-limit state for the whole background flush (one per chunk).
static FLUSH_STAGE_GATE: AtomicU64 = AtomicU64::new(0);

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
    probe_timeouts: Arc<Mutex<HashMap<[u8; 20], u32>>>,
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
    /// Compact-gossip `Body` reply routing counters (unicast vs bounded
    /// broadcast). Test/monitoring only; see [`CompactReplyCounters`].
    compact_body_replies: Arc<CompactReplyCounters>,
    /// Resolved static peer ids, cached once every peer resolves. The config
    /// is immutable after construction, so re-decoding every peer's PQ hex on
    /// every frame (the mesh check AND the per-peer send resolve independently)
    /// was pure per-block overhead at ~4 blocks/s. A config with an
    /// unresolved name (asymmetric registry) is NOT cached, so a later
    /// resolution is still picked up.
    peer_ids_cache: std::sync::OnceLock<Vec<[u8; 20]>>,
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

/// Await `handles` up to `hard_budget`, short-circuiting via `straggler_grace`
/// once `fast_target` tasks have completed.
///
/// While fewer than `fast_target` tasks have completed, this waits up to
/// `hard_budget`. As soon as `done.len() >= fast_target` with tasks still
/// pending, the remaining deadline is tightened to `min(remaining, straggler_grace)`,
/// collecting any peers that finish within the grace window and detaching the
/// rest via `JoinSet::detach_all`. Detached tasks keep running to completion in
/// the background (so sends and `peer_health` updates still land) while the
/// FIFO broadcast queue advances immediately.
pub async fn join_with_quorum_or_timeout<T: Send + 'static>(
    handles: Vec<tokio::task::JoinHandle<T>>,
    fast_target: usize,
    straggler_grace: Duration,
    hard_budget: Duration,
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
    let mut deadline = tokio::time::Instant::now() + hard_budget;
    let mut grace_armed = false;
    let mut budget_sleep = Box::pin(tokio::time::sleep_until(deadline));
    loop {
        if set.is_empty() {
            drained = true;
            break;
        }
        if !grace_armed && done.len() >= fast_target {
            grace_armed = true;
            let grace_deadline = tokio::time::Instant::now() + straggler_grace;
            if grace_deadline < deadline {
                deadline = grace_deadline;
                budget_sleep.as_mut().reset(deadline);
            }
        }
        tokio::select! {
            // `biased`: drain every already-ready completion before noticing
            // the expired budget/grace, so fast peers join even in a tight window.
            biased;
            r = set.join_next() => {
                match r {
                    Some(Ok(Some(v))) => done.push(v),
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

/// Record one ANSWERED ping-probe round trip as a per-peer latency sample.
///
/// CALIBRATION FEED (workspace-root `STELLEREUM_BLOCKCHAIN_FIXES.md` §2.12):
/// the `stell_peer_latency_seconds{peer}` samples the calibration runbooks
/// read for the network-delay side. `peer_hex` is the hex peer id (already
/// label-safe; the registry sanitises regardless) and `elapsed` the measured
/// `core.ping` round trip. Called on probe success ONLY: a timeout has no
/// RTT to report and a fast error proves liveness, not speed, so both emit
/// nothing (absent data, never a zero). Emission only: the sample never
/// affects peer selection, backoff or eviction, and when metrics are
/// disabled (nothing scrapes the registry) this is a plain no-op write.
pub(super) fn record_probe_rtt(peer_hex: &str, elapsed: Duration) {
    crate::metrics::global().observe_peer_latency(peer_hex, elapsed.as_secs_f64());
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
            probe_timeouts: Arc::new(Mutex::new(HashMap::new())),
            bcast_last_ms: Mutex::new(HashMap::new()),
            probe_last_ms: Mutex::new(HashMap::new()),
            inbound_bulk: Mutex::new(InboundBulkLimiter::with_defaults()),
            inbound_shed: Mutex::new(InboundShed::new(INBOUND_SHED_BYTES_PER_SEC)),
            peer_evicted_total: AtomicU64::new(0),
            compact_body_replies: Arc::new(CompactReplyCounters::new()),
            peer_ids_cache: std::sync::OnceLock::new(),
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
            probe_timeouts: Arc::new(Mutex::new(HashMap::new())),
            bcast_last_ms: Mutex::new(HashMap::new()),
            probe_last_ms: Mutex::new(HashMap::new()),
            inbound_bulk: Mutex::new(InboundBulkLimiter::with_defaults()),
            inbound_shed: Mutex::new(InboundShed::new(INBOUND_SHED_BYTES_PER_SEC)),
            peer_evicted_total: AtomicU64::new(0),
            compact_body_replies: Arc::new(CompactReplyCounters::new()),
            peer_ids_cache: std::sync::OnceLock::new(),
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

    /// Capabilities negotiated with one peer.
    ///
    /// A peer that has not sent `Hello` yet is a legacy v2 peer and keeps the
    /// pre-negotiation default ([`protocol::unnegotiated_capabilities`]), so
    /// existing deployments see byte-identical traffic.
    fn peer_caps(&self, pid: &[u8; 20]) -> Capabilities {
        self.adapter
            .node
            .peer_capabilities(pid)
            .unwrap_or_else(protocol::unnegotiated_capabilities)
    }

    /// True when consensus traffic may be addressed to this peer. A fork or
    /// two-minor refusal was already logged loudly at Hello time; this gate is
    /// what actually keeps the peer out of the consensus plane while leaving
    /// DHT/storage services untouched.
    fn peer_consensus_admitted(&self, pid: &[u8; 20]) -> bool {
        self.adapter.node.peer_consensus_admitted(pid)
    }

    /// Partition configured peers for a chunk that may contain a compact
    /// proposal: `(compact_ok, full_only)`. Refused peers are in NEITHER set.
    fn proposal_capability_partition(&self) -> (Vec<[u8; 20]>, Vec<[u8; 20]>) {
        let mut compact_ok = Vec::new();
        let mut full_only = Vec::new();
        for pid in self.peer_ids() {
            if !self.peer_consensus_admitted(&pid) {
                continue;
            }
            if protocol::peer_receives_compact(self.peer_caps(&pid)) {
                compact_ok.push(pid);
            } else {
                full_only.push(pid);
            }
        }
        (compact_ok, full_only)
    }

    /// Ledger update shared by the inline paths and the DETACHED per-peer
    /// tasks ([`Self::send_one_peer`]), which only hold an `Arc` to the ledger
    /// — never `&self`, because they may outlive the flush that spawned them.
    ///
    /// Returns the failure streak BEFORE this update (0 when the peer was
    /// healthy): callers use it to keep per-attempt logs quiet for
    /// known-dead peers (a streak already at/above the threshold logs at
    /// debug) while the ledger itself keeps exactly one loud line per
    /// transition (warn healthy->failing here, info failing->healthy here).
    pub(super) fn record_health(
        health: &Mutex<HashMap<[u8; 20], PeerHealth>>,
        pid: [u8; 20],
        ok: bool,
    ) -> u32 {
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
                    if !h.contains_key(&pid) {
                        enforce_peer_health_cap(&mut h, now);
                    }
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
    fn record_probe_timeout_hit(
        probe_timeouts: &Mutex<HashMap<[u8; 20], u32>>,
        pid: [u8; 20],
    ) -> u32 {
        match probe_timeouts.lock() {
            Ok(mut m) => {
                if !m.contains_key(&pid) && m.len() >= PEER_HEALTH_MAX_ENTRIES {
                    if let Some(k) = m.keys().next().copied() {
                        m.remove(&k);
                    }
                }
                let e = m.entry(pid).or_insert(0);
                *e = e.saturating_add(1);
                *e
            }
            Err(_) => 1,
        }
    }

    /// Clear `pid`'s probe-timeout streak: any answering probe (ok or fast
    /// error) proves the connection is alive and breaks the streak.
    fn clear_probe_timeout(probe_timeouts: &Mutex<HashMap<[u8; 20], u32>>, pid: &[u8; 20]) {
        if let Ok(mut m) = probe_timeouts.lock() {
            m.remove(pid);
        }
    }

    /// Resolve every configured peer to a node id.
    ///
    /// The peer's PQ id (`primary_id`) is preferred over its name: name resolution depends
    /// on a name registry that fills in asymmetrically (a node can know the name
    /// of a peer that does not yet know its own), and a failed lookup used to
    /// make `broadcast` silently send nothing — stalling consensus with no error
    /// anywhere. A node id is always resolvable.
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        if let Some(ids) = self.peer_ids_cache.get() {
            return ids.clone();
        }
        let mut out = Vec::with_capacity(self.adapter.node.cfg.peers.len());
        let mut all_resolved = true;
        for p in &self.adapter.node.cfg.peers {
            let pid = p
                .primary_id()
                .or_else(|_| self.adapter.node.resolve(&p.name));
            match pid {
                Ok(pid) => out.push(pid),
                Err(e) => {
                    all_resolved = false;
                    tracing::warn!("[consensus] cannot resolve peer {}: {e}", p.name);
                }
            }
        }
        // The static config never changes after construction, so a fully
        // resolved set can be reused for every frame. A partial set is NOT
        // cached: the name registry may fill in later.
        if all_resolved {
            let _ = self.peer_ids_cache.set(out.clone());
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
        let mut handles = Vec::new();
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
            let node = Arc::clone(&self.adapter.node);
            let health = Arc::clone(&self.peer_health);
            let timeouts = Arc::clone(&self.probe_timeouts);
            handles.push(tokio::spawn(async move {
                let t = std::time::Instant::now();
                let r = tokio::time::timeout(
                    send_timeout(),
                    node.request_to(pid, "core.ping", b"{}".to_vec()),
                )
                .await;
                match r {
                    Ok(Ok(_)) => {
                        let fails_before = Self::record_health(&health, pid, true);
                        Self::clear_probe_timeout(&timeouts, &pid);
                        // EMISSION ONLY (calibration feed, FIXES.md §2.12 peer-
                        // latency series): the just-measured `core.ping` round
                        // trip for this peer. Success arm only — see
                        // `record_probe_rtt`. Never affects the health/backoff
                        // verdicts below, which are computed independently.
                        record_probe_rtt(&hex::encode(pid), t.elapsed());
                        if fails_before >= PEER_SKIP_THRESHOLD {
                            // Recovery already logged its one loud line inside
                            // `record_health`; keep this attempt quiet.
                            tracing::debug!(
                                "[net] probe {} ok in {:?} (recovered)",
                                hex::encode(pid),
                                t.elapsed()
                            );
                        } else {
                            tracing::info!(
                                "[net] probe {} ok in {:?}",
                                hex::encode(pid),
                                t.elapsed()
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        Self::record_health(&health, pid, false);
                        // A fast error still proves the connection answers, so it
                        // breaks the TIMEOUT streak: eviction is for consecutive
                        // timeouts, not for any failure.
                        Self::clear_probe_timeout(&timeouts, &pid);
                        if health_is_known_dead(&health, &pid) {
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
                        Self::record_health(&health, pid, false);
                        let streak = Self::record_probe_timeout_hit(&timeouts, pid);
                        let after = probe_evict_after();
                        if probe_timeout_should_evict(streak, after) {
                            tracing::warn!(
                                "[net] probe {} TIMEOUT after {:?}; evicting conn ({streak} consecutive timeouts >= {after})",
                                hex::encode(pid),
                                t.elapsed(),
                            );
                            node.invalidate_peer_conn(pid).await;
                        } else if health_is_known_dead(&health, &pid) {
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
            }));
        }
        let budget =
            std::time::Duration::from_millis(broadcast_join_timeout_ms().clamp(500, 1_500));
        let (_done, _detached) = join_with_timeout(handles, budget).await;
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

    /// Compact-gossip `Body` reply counters (unicast vs bounded broadcast).
    pub fn compact_reply_counters(&self) -> Arc<CompactReplyCounters> {
        Arc::clone(&self.compact_body_replies)
    }

    /// Deliver ONE consensus message to exactly ONE peer (unicast).
    ///
    /// Routing: when `peer` is a validator-mesh member the frame goes over the
    /// warm direct mesh link; if that copy fails — or the peer is not a mesh
    /// member — the SAME frame is delivered over the existing per-peer direct
    /// transport (`pubsub.msg` addressed to that peer). There is:
    ///
    /// * NO broadcast amplification: exactly one destination, never the peer set;
    /// * NO new wire variant: the bytes are the single-message
    ///   [`ConsensusMsg::encode`] frame wrapped in the historical
    ///   `{topic,data}` envelope, so wire format v2 is unchanged;
    /// * a bounded size ([`MAX_CONSENSUS_MSG`]) and a bounded send (the mesh /
    ///   direct timeout), and the transport work is DETACHED from the consensus
    ///   tick exactly like [`Self::send_payload_to`], so one slow requester can
    ///   never stretch the round clock.
    ///
    /// `Err` therefore reports a PREFLIGHT refusal only: an oversized message,
    /// an encode failure, or a peer refused for consensus (fork/version). Those
    /// are the cases where the caller should take its liveness fallback.
    pub async fn send_to_peer(&self, peer: [u8; 20], msg: &ConsensusMsg) -> Result<(), String> {
        // Same admission gate as the broadcast: a refused peer never receives
        // consensus traffic, addressed or otherwise.
        if !self.peer_consensus_admitted(&peer) {
            return Err(format!(
                "peer {} is refused for consensus (fork/version)",
                hex::encode(peer)
            ));
        }
        let bytes = msg.encode()?;
        if bytes.len() > MAX_CONSENSUS_MSG {
            return Err(format!(
                "unicast consensus message too large: {} bytes",
                bytes.len()
            ));
        }
        let data = hex::encode(bytes);
        let adapter = Arc::clone(&self.adapter);
        let topic = self.topic.clone();
        let health = Arc::clone(&self.peer_health);
        // Detached: the drain loop must never await one peer's transport (see
        // `flush_outbox`). One task per unicast reply, and the mesh/direct
        // transport applies its own bounded timeout.
        tokio::spawn(async move {
            match adapter.deliver_consensus_to_peer(peer, &topic, &data).await {
                Ok(path) => {
                    tracing::debug!(
                        "[consensus] unicast body reply to {} via {:?}",
                        hex::encode(peer),
                        path,
                    );
                }
                Err(e) => {
                    // A failed unicast is not delivery proof either way; it is
                    // still a transport miss for the health ledger.
                    ConsensusNetwork::record_health(&health, peer, false);
                    tracing::warn!(
                        "[consensus] unicast body reply to {} failed on the mesh AND the direct link: {e}",
                        hex::encode(peer),
                    );
                }
            }
        });
        Ok(())
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
        //
        // The live subset BORROWS the chunk (see `coalesce_live_for_send`):
        // the old code deep-cloned every message here, including a full block
        // body on every proposal broadcast, only to read it during encoding.
        let live = {
            let now = Instant::now();
            match self.sent_votes.lock() {
                Ok(mut filter) => coalesce_live_for_send(msgs, &mut filter, now),
                Err(_) => msgs.iter().map(std::borrow::Cow::Borrowed).collect(),
            }
        };
        if live.is_empty() {
            return;
        }
        let msgs = &live;
        let exempt = batch_bypasses_skip_refs(msgs.iter().map(|m| &**m));
        let fof = batch_is_fire_and_forget_refs(msgs.iter().map(|m| &**m));
        // CAPABILITY-AWARE DUAL-EMIT: a compact proposal may only be addressed
        // to peers that negotiated COMPACT_GOSSIP. Peers that did not get the
        // full `Proposal` form instead (the cached body), in the same flush.
        // Peers refused for consensus (fork/version) get neither.
        if self.broadcast_capability_split(msgs, exempt, fof).await {
            return;
        }
        // Stage (a): bincode encode + hex + JSON framing. Timed separately so a
        // live measurement can tell a CPU-bound encode from a slow transport.
        let t_encode = std::time::Instant::now();
        let frame = match encode_broadcast_payload(&self.topic, msgs) {
            Ok(f) => f,
            Err(e) => {
                if !e.is_batch() {
                    tracing::warn!("[consensus] broadcast: encode failed, sending nothing");
                    return;
                }
                // Size-aware fallback (audit: blocks troubles): a fat
                // proposal batched with votes failed the 512KB batch cap
                // and the WHOLE chunk — proposal included — was silently
                // dropped. Fall back to single-encode per message (each
                // still capped at MAX_CONSENSUS_MSG): votes may still drop
                // oversize, but a proposal always goes out alone.
                tracing::warn!(
                    "[consensus] broadcast_batch: {}, falling back to single sends",
                    e.message()
                );
                return self.broadcast_singles(msgs).await;
            }
        };
        let nbytes = frame.encoded_len;
        let data = frame.data;
        let payload_arc = Arc::new(frame.payload);
        log_stage(
            &ENCODE_STAGE_GATE,
            "encode",
            &format!("items={} bytes={nbytes}", msgs.len()),
            t_encode.elapsed(),
        );
        // DIRECT VALIDATOR MESH (pentest-2 R10/M6 wiring): when the mesh covers
        // the complete configured peer set, deliver over the warm direct links
        // first. The mesh publishes ONE overlay fallback when any direct copy
        // fails. If even one direct copy failed (or coverage is partial) the
        // normal per-peer broadcast below still runs, so a lost link can never
        // lose the message; receiver-side dedup makes the duplicate harmless.
        //
        // EXEMPT payloads (`Committed`) never take the shortcut: the mesh
        // withholds suspected peers, while the per-peer path still attempts
        // them (detached) because that is the catch-up frame a lagging
        // validator needs (see [`mesh_may_substitute`]).
        let mesh_peers = self.peer_ids();
        // MESH_DIRECT capability: the direct mesh may substitute for the
        // overlay only when EVERY addressed peer advertised it. A peer without
        // it still receives the overlay broadcast (advisory capability).
        let mesh_capable = mesh_peers.iter().all(|pid| {
            self.peer_consensus_admitted(pid) && protocol::mesh_may_use_direct(self.peer_caps(pid))
        });
        if mesh_shortcut_allowed(
            mesh_capable,
            exempt,
            self.adapter.validator_mesh().covers(&mesh_peers),
        ) {
            let delivery = self
                .adapter
                .deliver_consensus_mesh_frame(&self.topic, &data, Arc::clone(&payload_arc))
                .await;
            // COMPLETE means every ATTEMPTED direct copy succeeded.
            // `direct_targets` already excludes peers the scoring marks dead
            // (suspected, even after their cooldown elapsed), so comparing
            // against the raw config peer count made a healthy mesh look
            // "incomplete" forever whenever one configured peer was down:
            // every consensus frame was sent twice (direct + broadcast) and
            // the warning fired every minute.
            //
            // PARTIAL failure is NOT complete, even if the mesh's overlay
            // fallback accepted a copy: `fallback_ok` is just "some subscriber
            // accepted", not proof that every failed direct target received
            // it. A failed direct copy must still be addressed by the
            // per-peer broadcast below. `MeshDelivery::delivered()` therefore
            // requires every attempted direct copy to succeed.
            if delivery.delivered() {
                return;
            }
            // Mesh coverage is a property of the PEER SET, not of one message:
            // while a configured validator is down, every frame legitimately
            // falls back and warning per frame floods the log at block rate.
            // One line a minute carries the same information.
            const MESH_INCOMPLETE_WARN_GAP_MS: u64 = 60_000;
            static MESH_INCOMPLETE_WARN: AtomicU64 = AtomicU64::new(0);
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if now_ms.saturating_sub(MESH_INCOMPLETE_WARN.load(Ordering::Relaxed))
                >= MESH_INCOMPLETE_WARN_GAP_MS
            {
                MESH_INCOMPLETE_WARN.store(now_ms, Ordering::Relaxed);
                tracing::warn!(
                    "[consensus] mesh direct delivery incomplete (ok={} failed={} targets={} fallback_ok={}): using the per-peer broadcast fallback (throttled to 1/min)",
                    delivery.direct_ok,
                    delivery.direct_failed,
                    delivery.targets,
                    delivery.fallback_ok,
                );
            }
        }
        // Fire-and-forget for votes/proposals: the peer's ACK carries no
        // information the sender needs, but it costs a full round trip
        // (300-1200 ms on WAN) and the ordered sender is FIFO, so an awaited
        // ACK also delays the NEXT chunk. A chunk carrying a `Committed`
        // keeps the acknowledged form (the catch-up proof). `fof`/`exempt`
        // were computed before the capability split above.
        let payload = Arc::try_unwrap(payload_arc).unwrap_or_else(|a| (*a).clone());
        self.send_payload_with_skip(payload, exempt, fof).await;
    }

    /// Dual-emit a chunk that contains a compact proposal.
    ///
    /// Returns `true` when the chunk was fully dispatched here (the caller
    /// must not send the original payload to everybody), `false` when no
    /// capability split is needed (no compact proposal, or every peer can
    /// decode it).
    async fn broadcast_capability_split(
        &self,
        msgs: &[std::borrow::Cow<'_, ConsensusMsg>],
        exempt: bool,
        fire_and_forget: bool,
    ) -> bool {
        if !msgs
            .iter()
            .any(|m| matches!(&**m, ConsensusMsg::CompactProposal { .. }))
        {
            return false;
        }
        let (compact_ok, full_only) = self.proposal_capability_partition();
        if full_only.is_empty() {
            return false;
        }
        // Build the full form for every compact member. A missing cached body
        // must NEVER turn into a compact frame for a non-capable peer: we then
        // address the capable peers only and say so loudly (the others still
        // catch up through `Committed`/DHT, never through an undecodable
        // frame).
        let mut full_msgs: Vec<ConsensusMsg> = Vec::with_capacity(msgs.len());
        for m in msgs {
            match &**m {
                ConsensusMsg::CompactProposal { .. } => match full_proposal_for_compact(m) {
                    Some(full) => full_msgs.push(full),
                    None => {
                        tracing::error!(
                            "[consensus] compact chunk has no cached full body; refusing to send \
                             a compact frame to {} non-COMPACT_GOSSIP peer(s) (they catch up via \
                             Committed/DHT instead)",
                            full_only.len()
                        );
                        if !compact_ok.is_empty() {
                            self.encode_and_send_batch(msgs, compact_ok, exempt, fire_and_forget)
                                .await;
                        }
                        return true;
                    }
                },
                other => full_msgs.push(other.clone()),
            }
        }
        if !compact_ok.is_empty() {
            self.encode_and_send_batch(msgs, compact_ok, exempt, fire_and_forget)
                .await;
        }
        // The full chunk carries the cached `Proposal` plus any votes that
        // travelled with it; receiving both representations is harmless
        // (receiver dedup keeps the first proposal per height/round).
        self.encode_and_send_owned(&full_msgs, full_only, exempt, fire_and_forget)
            .await;
        true
    }

    /// Encode and send an already-materialized chunk to an explicit peer set.
    async fn encode_and_send_owned(
        &self,
        msgs: &[ConsensusMsg],
        peers: Vec<[u8; 20]>,
        exempt: bool,
        fire_and_forget: bool,
    ) {
        if msgs.is_empty() {
            return;
        }
        let owned: Vec<std::borrow::Cow<'_, ConsensusMsg>> =
            msgs.iter().map(std::borrow::Cow::Borrowed).collect();
        self.encode_and_send_batch(&owned, peers, exempt, fire_and_forget)
            .await;
    }

    /// Encode a borrowed chunk exactly like [`Self::broadcast_batch`] does and
    /// send it only to `peers`.
    async fn encode_and_send_batch(
        &self,
        msgs: &[std::borrow::Cow<'_, ConsensusMsg>],
        peers: Vec<[u8; 20]>,
        exempt: bool,
        fire_and_forget: bool,
    ) {
        if peers.is_empty() || msgs.is_empty() {
            return;
        }
        let t_encode = std::time::Instant::now();
        let frame = match encode_broadcast_payload(&self.topic, msgs) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    "[consensus] capability-split encode failed ({}): chunk dropped for {} peer(s)",
                    e.message(),
                    peers.len()
                );
                return;
            }
        };
        log_stage(
            &ENCODE_STAGE_GATE,
            "encode",
            &format!(
                "items={} bytes={} split_peers={}",
                msgs.len(),
                frame.encoded_len,
                peers.len()
            ),
            t_encode.elapsed(),
        );
        self.send_payload_to(peers, frame.payload, exempt, fire_and_forget)
            .await;
    }

    /// Single-encode fallback for a chunk that failed batch encoding (see
    /// `broadcast_batch`): each message goes out alone, so one oversize
    /// member cannot sink its batch-mates. Proposals (which forced the
    /// fallback by their size) travel singleton; small votes regroup in later
    /// flushes. Each singleton is still capped at MAX_CONSENSUS_MSG.
    async fn broadcast_singles(&self, msgs: &[std::borrow::Cow<'_, ConsensusMsg>]) {
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
        self.send_payload_to(peers, payload, exempt_skip, fire_and_forget)
            .await;
    }

    /// Per-peer delivery for an explicit peer set (the capability split sends
    /// different encodings to different peers in the same flush).
    async fn send_payload_to(
        &self,
        peers: Vec<[u8; 20]>,
        payload: Vec<u8>,
        exempt_skip: bool,
        fire_and_forget: bool,
    ) {
        if peers.is_empty() {
            tracing::warn!("[consensus] no resolvable peers to broadcast to");
            return;
        }
        // CONSENSUS-REFUSED PEERS (fork mismatch / two-minor gap): never
        // receive consensus traffic. The refusal was logged once at Hello
        // time; this is the enforcement point. DHT/blob services are a
        // separate frame class and stay available.
        let mut refused = 0u32;
        let peers: Vec<[u8; 20]> = peers
            .into_iter()
            .filter(|pid| {
                if self.peer_consensus_admitted(pid) {
                    true
                } else {
                    refused += 1;
                    false
                }
            })
            .collect();
        if peers.is_empty() {
            if refused > 0 {
                tracing::warn!(
                    "[consensus] all {} peer(s) are refused for consensus (fork/version); \
                     nothing sent",
                    refused
                );
            } else {
                tracing::warn!("[consensus] no resolvable peers to broadcast to");
            }
            return;
        }
        if refused > 0 {
            tracing::debug!(
                "[consensus] skipped {} peer(s) refused for consensus participation",
                refused
            );
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
        let join_budget_ms = broadcast_join_timeout_ms();
        let budget = Duration::from_millis(join_budget_ms);
        let joined_total = joined.len();
        let use_quorum_grace = !exempt_skip && joined_total >= 3;
        let fast_target = joined_total.saturating_sub(1).max(1);
        let (joined_n, detached_late) = if use_quorum_grace {
            join_with_quorum_or_timeout(
                joined,
                fast_target,
                Duration::from_millis(BROADCAST_STRAGGLER_GRACE_MS_DEFAULT),
                budget,
            )
            .await
        } else {
            join_with_timeout(joined, budget).await
        };
        if detached_late > 0 {
            if use_quorum_grace && joined_n.len() >= fast_target {
                tracing::debug!(
                    "[consensus] broadcast fast-quorum ({}/{}, grace {}ms) detached {} slow peer(s) (still recording on completion)",
                    joined_n.len(),
                    joined_total,
                    BROADCAST_STRAGGLER_GRACE_MS_DEFAULT,
                    detached_late,
                );
            } else {
                tracing::warn!(
                    "[consensus] broadcast join budget ({}ms) exceeded: joined {} peer(s), detached {} slow peer(s) (still recording on completion)",
                    join_budget_ms,
                    joined_n.len(),
                    detached_late,
                );
            }
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

/// Owns one pending reservation until processing finishes or the channel
/// discards the entry. This also releases reservations on task cancellation.
pub(super) struct PendingChunk {
    chunk: Option<BroadcastChunk>,
    pending: Arc<AtomicUsize>,
}

impl Drop for PendingChunk {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Handle to the dedicated ordered broadcast sender. Cheap to clone; all clones
/// feed the same FIFO queue and therefore the same wire order.
#[derive(Clone)]
pub struct ConsensusSender {
    pub(super) tx: mpsc::UnboundedSender<PendingChunk>,
    /// Reserved, queued, and in-flight chunks, used for backpressure and
    /// the flush sub-timing line.
    pub(super) pending: Arc<AtomicUsize>,
}

impl ConsensusSender {
    /// Compatibility wrapper that drops the chunk on refusal. Call
    /// [`Self::try_enqueue`] to retain ownership on failure.
    pub fn enqueue(&self, chunk: BroadcastChunk) -> bool {
        self.try_enqueue(chunk).is_ok()
    }

    /// Non-blocking enqueue that returns ownership on saturation or closure.
    pub fn try_enqueue(&self, chunk: BroadcastChunk) -> Result<(), BroadcastChunk> {
        // Reserve before publishing: the receiver may complete immediately,
        // and multiple clones may enqueue concurrently.
        if self
            .pending
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n < MAX_PENDING_CHUNKS {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .is_err()
        {
            return Err(chunk);
        }
        let entry = PendingChunk {
            chunk: Some(chunk),
            pending: Arc::clone(&self.pending),
        };
        match self.tx.send(entry) {
            Ok(()) => Ok(()),
            Err(mut err) => Err(err.0.chunk.take().expect("unsent chunk is present")),
        }
    }

    /// Reserved, queued, and in-flight chunks (for the flush sub-timing line).
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
    let (tx, mut rx) = mpsc::unbounded_channel::<PendingChunk>();
    let pending = Arc::new(AtomicUsize::new(0));
    let task_pending = Arc::clone(&pending);
    tokio::spawn(async move {
        while let Some(mut entry) = rx.recv().await {
            let chunk = entry.chunk.take().expect("queued chunk is present");
            let items = chunk.len();
            let t = std::time::Instant::now();
            send(chunk).await;
            drop(entry);
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
    /// Dandelion stem/fluff relay state (publish-path wiring, default OFF).
    /// Mutex-only, never held across await; the OFF path never touches it.
    dandelion: Mutex<dandelion::DandelionRelay>,
    /// Dandelion decision randomness (seeded from OS at construction; reseeded
    /// deterministically via `dandelion_reseed` in tests/sim). Mutex-only,
    /// never held across await; the OFF path never touches it.
    dandelion_rng: Mutex<dandelion::NodeRng>,
    /// Same resolved-static-peer cache as [`ConsensusNetwork::peer_ids`]:
    /// tx broadcast runs per transaction, and re-decoding every PQ hex each
    /// time is pure overhead on a hot path.
    peer_ids_cache: std::sync::OnceLock<Vec<[u8; 20]>>,
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
            dandelion: Mutex::new(dandelion::DandelionRelay::with_defaults()),
            dandelion_rng: Mutex::new(dandelion::NodeRng::new(rand::random::<u64>())),
            peer_ids_cache: std::sync::OnceLock::new(),
        }
    }

    /// Peer ids, PQ-id first: the same asymmetric-registry trap fixed in
    /// `ConsensusNetwork::peer_ids` lived here too — a failed name lookup
    /// silently sent nothing, starving the peer's mempool (and its blocks)
    /// with no error anywhere (audit 2026-10-06).
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        if let Some(ids) = self.peer_ids_cache.get() {
            return ids.clone();
        }
        let mut out = Vec::with_capacity(self.adapter.node.cfg.peers.len());
        let mut all_resolved = true;
        for p in &self.adapter.node.cfg.peers {
            let pid = p
                .primary_id()
                .or_else(|_| self.adapter.node.resolve(&p.name));
            match pid {
                Ok(pid) => out.push(pid),
                Err(e) => {
                    all_resolved = false;
                    tracing::warn!("[txgossip] cannot resolve peer {}: {e}", p.name);
                }
            }
        }
        if all_resolved {
            let _ = self.peer_ids_cache.set(out.clone());
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
                    tracing::warn!(
                        "[txgossip] broadcast to {hexid} transport-err in {elapsed:?}: {e}"
                    );
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
    fn record_health(
        health: &Mutex<HashMap<[u8; 20], PeerHealth>>,
        pid: [u8; 20],
        ok: bool,
    ) -> u32 {
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
                    if !h.contains_key(&pid) {
                        enforce_peer_health_cap(&mut h, now);
                    }
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
    ///
    /// Dandelion gate: OFF ([`DANDELION_ENABLED`] == false) serializes and fans
    /// out exactly as before (byte-identical); ON (tests/sim only) follows the
    /// stem/fluff decision in [`Self::broadcast_dandelion`].
    pub async fn broadcast(&self, tx: &crate::sharding::Transaction) {
        let Ok(bytes) = bincode::serialize(tx) else {
            return;
        };
        if DANDELION_ENABLED {
            self.broadcast_dandelion(bytes).await;
            return;
        }
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

    /// Dandelion publish path (ON only; tests/sim — see [`DANDELION_ENABLED`]).
    ///
    /// Originates the tx through the relay policy: fluff reuses the shared
    /// all-peer [`Self::broadcast_bytes`] path (identical bytes/fanout), stem
    /// sends one magic-prefixed frame to exactly one peer
    /// ([`Self::unicast_dandelion_stem`]), duplicates are dropped. A stem
    /// target that entered failure cooldown between selection and send runs
    /// the policy failover once; anything un-sendable fluffs (fail-open —
    /// never stall, never blackhole).
    async fn broadcast_dandelion(&self, bytes: Vec<u8>) {
        if bytes.len() > MAX_TX_MSG {
            return; // oversized tx never gossiped
        }
        let txid = dandelion_tx_hash(&bytes);
        match self.dandelion_publish_decision(&txid) {
            DandelionPublishDecision::Drop => {}
            DandelionPublishDecision::Fluff => self.broadcast_bytes(bytes).await,
            DandelionPublishDecision::Stem { to, hops_left } => {
                if self.peer_skipped(&to) {
                    match self.dandelion_failover(&txid) {
                        DandelionPublishDecision::Drop => {}
                        DandelionPublishDecision::Fluff => {
                            self.broadcast_bytes(bytes).await;
                        }
                        DandelionPublishDecision::Stem { to, hops_left } => {
                            self.unicast_dandelion_stem(to, hops_left, bytes).await;
                        }
                    }
                } else {
                    self.unicast_dandelion_stem(to, hops_left, bytes).await;
                }
            }
        }
    }

    /// Send one stem frame to exactly one peer (best-effort).
    ///
    /// Same preamble as [`Self::broadcast_bytes`] (size check, pacing floor,
    /// per-peer send budget, bounded join) for that single peer. A peer lost
    /// to the rate limiter fluffs instead (fail-open): dropping a lone stem
    /// would stall the tx until the fluff timeout, while a fluff still
    /// delivers everywhere reachable.
    async fn unicast_dandelion_stem(&self, pid: [u8; 20], hops_left: u32, tx_bytes: Vec<u8>) {
        let stem = encode_dandelion_stem(hops_left, &tx_bytes);
        if stem.len() > MAX_TX_MSG + 8 {
            self.broadcast_bytes(tx_bytes).await;
            return;
        }
        let payload = serde_json::json!({ "topic": self.topic, "data": hex::encode(stem) })
            .to_string()
            .into_bytes();
        let allowed = match self.send_limit.lock() {
            Ok(mut l) => l.try_send(&pid, payload.len() as u64, epoch_ms()),
            Err(_) => true,
        };
        if !allowed {
            tracing::debug!(
                "[txgossip] stem to {} dropped (per-peer send budget exceeded): fluffing",
                hex::encode(pid),
            );
            self.broadcast_bytes(tx_bytes).await;
            return;
        }
        let wait_ms = self.bcast_wait_and_stamp(&pid);
        let handle = tokio::spawn(Self::send_one_peer(
            Arc::clone(&self.adapter),
            Arc::clone(&self.peer_health),
            pid,
            payload,
            wait_ms,
        ));
        let (_joined, detached) = join_with_timeout(
            vec![handle],
            Duration::from_millis(broadcast_join_timeout_ms()),
        )
        .await;
        if detached > 0 {
            tracing::debug!(
                "[txgossip] stem to {} detached past the join budget (still recording on completion)",
                hex::encode(pid),
            );
        }
    }

    /// This node's Dandelion peer id (mapped from the local node id).
    pub fn dandelion_self_id(&self) -> u64 {
        dandelion_peer_id(&self.adapter.node.id)
    }

    /// Peer-table snapshot as `(node id, mapped peer id)` pairs, in table
    /// order. The decision helpers below map through this table so the policy
    /// (which only sees `u64`s) and the transport (which only dials `[u8; 20]`)
    /// agree on identities.
    fn dandelion_table(&self) -> Vec<([u8; 20], u64)> {
        self.peer_ids()
            .into_iter()
            .map(|pid| (pid, dandelion_peer_id(&pid)))
            .collect()
    }

    /// Decide what to do with one locally-originated transaction, using live
    /// liveness (peers in failure cooldown count as down).
    pub fn dandelion_publish_decision(&self, tx: &[u8; 32]) -> DandelionPublishDecision {
        let table = self.dandelion_table();
        let self_id = self.dandelion_self_id();
        let alive: Vec<u64> = table
            .iter()
            .filter(|(pid, _)| !self.peer_skipped(pid))
            .map(|(_, id)| *id)
            .collect();
        self.dandelion_publish_decision_with_liveness(tx, &table, self_id, &|p| alive.contains(&p))
    }

    /// Decide what to do with one locally-originated transaction, with
    /// caller-supplied liveness (tests/sim: stale views, dead ends,
    /// partitions). `candidates`/`self_id` are the peer table in transport
    /// ids; `is_alive` sees the mapped policy ids.
    pub fn dandelion_publish_decision_with_liveness(
        &self,
        tx: &[u8; 32],
        candidates: &[([u8; 20], u64)],
        self_id: u64,
        is_alive: &impl Fn(u64) -> bool,
    ) -> DandelionPublishDecision {
        let peer_ids: Vec<u64> = candidates.iter().map(|(_, id)| *id).collect();
        let (action, entry) = match (self.dandelion.lock(), self.dandelion_rng.lock()) {
            (Ok(mut relay), Ok(mut rng)) => {
                let action = relay.originate(&mut rng, *tx, &peer_ids, self_id, is_alive);
                let entry = relay.stem_entry(tx).map(|e| e.hops_left);
                (action, entry)
            }
            _ => return DandelionPublishDecision::Fluff,
        };
        match map_dandelion_action(action, candidates) {
            DandelionPublishDecision::Stem { to, .. } => DandelionPublishDecision::Stem {
                to,
                hops_left: entry.unwrap_or(0),
            },
            other => other,
        }
    }

    /// Handle a transaction arriving over the stem with `hops_left` budget,
    /// using live liveness. Returns what to do next (forward once, fluff, or
    /// drop). Inbound stem dispatch is deferred (see module header); this is
    /// the decision hook the wiring tests and the sim drive.
    pub fn dandelion_on_stem(&self, tx: &[u8; 32], hops_left: u32) -> DandelionPublishDecision {
        let table = self.dandelion_table();
        let self_id = self.dandelion_self_id();
        let alive: Vec<u64> = table
            .iter()
            .filter(|(pid, _)| !self.peer_skipped(pid))
            .map(|(_, id)| *id)
            .collect();
        self.dandelion_on_stem_with_liveness(tx, hops_left, &table, self_id, &|p| {
            alive.contains(&p)
        })
    }

    /// [`Self::dandelion_on_stem`] with caller-supplied liveness (tests/sim).
    pub fn dandelion_on_stem_with_liveness(
        &self,
        tx: &[u8; 32],
        hops_left: u32,
        candidates: &[([u8; 20], u64)],
        self_id: u64,
        is_alive: &impl Fn(u64) -> bool,
    ) -> DandelionPublishDecision {
        let peer_ids: Vec<u64> = candidates.iter().map(|(_, id)| *id).collect();
        let (action, entry) = match (self.dandelion.lock(), self.dandelion_rng.lock()) {
            (Ok(mut relay), Ok(mut rng)) => {
                let action =
                    relay.on_stem_receive(&mut rng, *tx, hops_left, &peer_ids, self_id, is_alive);
                let entry = relay.stem_entry(tx).map(|e| e.hops_left);
                (action, entry)
            }
            _ => return DandelionPublishDecision::Fluff,
        };
        match map_dandelion_action(action, candidates) {
            DandelionPublishDecision::Stem { to, .. } => DandelionPublishDecision::Stem {
                to,
                hops_left: entry.unwrap_or(0),
            },
            other => other,
        }
    }

    /// Handle a transaction arriving via fluff broadcast. Returns true when
    /// the caller should relay the fluff onward (exactly once per tx —
    /// storm termination), false when it is a duplicate. Fluff wins: any held
    /// stem state for the tx is dropped.
    pub fn dandelion_on_fluff(&self, tx: &[u8; 32]) -> bool {
        match self.dandelion.lock() {
            Ok(mut relay) => relay.on_fluff_receive(*tx) == dandelion::RelayAction::FluffBroadcast,
            Err(_) => true,
        }
    }

    /// Failover: the stem peer holding `tx` is (now believed) down, using live
    /// liveness. Re-emits, reroutes, or fluffs per policy (never blackholes).
    pub fn dandelion_failover(&self, tx: &[u8; 32]) -> DandelionPublishDecision {
        let table = self.dandelion_table();
        let self_id = self.dandelion_self_id();
        let alive: Vec<u64> = table
            .iter()
            .filter(|(pid, _)| !self.peer_skipped(pid))
            .map(|(_, id)| *id)
            .collect();
        self.dandelion_failover_with_liveness(tx, &table, self_id, &|p| alive.contains(&p))
    }

    /// [`Self::dandelion_failover`] with caller-supplied liveness (tests/sim).
    pub fn dandelion_failover_with_liveness(
        &self,
        tx: &[u8; 32],
        candidates: &[([u8; 20], u64)],
        self_id: u64,
        is_alive: &impl Fn(u64) -> bool,
    ) -> DandelionPublishDecision {
        let peer_ids: Vec<u64> = candidates.iter().map(|(_, id)| *id).collect();
        let (action, entry) = match (self.dandelion.lock(), self.dandelion_rng.lock()) {
            (Ok(mut relay), Ok(mut rng)) => {
                let action = relay.on_peer_down(&mut rng, tx, &peer_ids, self_id, is_alive);
                let entry = relay.stem_entry(tx).map(|e| e.hops_left);
                (action, entry)
            }
            _ => return DandelionPublishDecision::Fluff,
        };
        match map_dandelion_action(action, candidates) {
            DandelionPublishDecision::Stem { to, .. } => DandelionPublishDecision::Stem {
                to,
                hops_left: entry.unwrap_or(0),
            },
            other => other,
        }
    }

    /// Fluff timeout: force-fluff a held stem entry (stem-blackhole
    /// mitigation). Returns `Some(Fluff)` when an entry was held (the caller
    /// broadcasts), `None` otherwise. Live timer arming is deferred (see
    /// module header); tests/sim drive this directly.
    pub fn dandelion_fluff_timeout(&self, tx: &[u8; 32]) -> Option<DandelionPublishDecision> {
        match self.dandelion.lock() {
            Ok(mut relay) => relay
                .fluff_timeout(tx)
                .map(|_| DandelionPublishDecision::Fluff),
            Err(_) => None,
        }
    }

    /// Reseed the decision RNG (tests/sim only — makes ON-path decisions
    /// reproducible; production seeds from OS randomness at construction).
    /// Never consulted when OFF.
    pub fn dandelion_reseed(&self, seed: u64) {
        if let Ok(mut rng) = self.dandelion_rng.lock() {
            *rng = dandelion::NodeRng::new(seed);
        }
    }

    /// Number of currently held stem entries (always `<= MAX_STEM_ENTRIES`).
    pub fn dandelion_stem_len(&self) -> usize {
        self.dandelion.lock().map(|r| r.stem_len()).unwrap_or(0)
    }

    /// Number of seen-set entries (always `<= MAX_SEEN_ENTRIES`).
    pub fn dandelion_seen_len(&self) -> usize {
        self.dandelion.lock().map(|r| r.seen_len()).unwrap_or(0)
    }

    /// Whether a stem entry is currently held for `tx`.
    pub fn dandelion_holds(&self, tx: &[u8; 32]) -> bool {
        self.dandelion
            .lock()
            .map(|r| r.stem_entry(tx).is_some())
            .unwrap_or(false)
    }

    /// Whether `tx` was already fluffed through this node.
    pub fn dandelion_is_fluffed(&self, tx: &[u8; 32]) -> bool {
        self.dandelion
            .lock()
            .map(|r| r.is_fluffed(tx))
            .unwrap_or(false)
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
            if let Ok(pid) = p.primary_id() {
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
