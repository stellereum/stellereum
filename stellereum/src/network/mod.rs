//! P2P Networking Layer Adapter for Stellereum
//! Uses infnode as a transparent P2P transport and DHT storage black box.
//! Does NOT modify infnode core; interacts solely via infnode's public API:
//! - store_blob / fetch_blob for block chunks and state snapshots
//! - kv_store_local / get_local_kv for block headers, latest height, peer routes,
//!   mempool transaction gossip, cross-shard message passing, and oracle updates.

mod fetch;
mod naming;
mod publish;
mod retention;
mod xshard_transport;

pub use fetch::*;
pub use naming::*;
pub use publish::*;
pub use retention::*;
pub use xshard_transport::*;

const _: () = assert!(
    MAX_CROSS_SHARD_MSG * 2 <= infnode::proto::MAX_PUBSUB_DATA_LEN,
    "MAX_CROSS_SHARD_MSG hex encoding must fit within infnode MAX_PUBSUB_DATA_LEN"
);

#[cfg(test)]
mod tests;

use futures::stream::StreamExt;
use infnode::node::Node;
use std::sync::Arc;

/// One direct-mesh transport failure marks a peer suspected after this many
/// CONSECUTIVE failures (transport error, timeout, handshake failure).
pub const VALIDATOR_MESH_EVICT_AFTER: u32 = 3;
/// Default cooldown before one reconnect attempt is allowed again.
pub const VALIDATOR_MESH_COOLDOWN_MS: u64 = 60_000;
/// Upper bound on mesh members (the validator set is <= 250; this is the
/// fail-closed table cap, not a consensus limit).
pub const VALIDATOR_MESH_MAX_MEMBERS: usize = 1024;
/// Heartbeat interval: how often a healthy mesh link is re-probed so the
/// underlying QUIC connection stays warm instead of idling out.
pub const VALIDATOR_MESH_HEARTBEAT_MS: u64 = 10_000;
/// Per-peer direct-send budget. A mesh send must never stall consensus: the
/// DHT fallback takes over at this point.
pub const VALIDATOR_MESH_SEND_TIMEOUT_MS: u64 = 2_000;
/// Bounded concurrency for [`ValidatorMesh::maintain`] peer probes.
pub const VALIDATOR_MESH_PROBE_CONCURRENCY: usize = 8;
/// Bounded timeout for the overlay fallback inside [`ValidatorMesh::deliver_frame`]
/// so a hung overlay publish cannot stall `ConsensusNetwork`'s sender task forever.
pub const VALIDATOR_MESH_OVERLAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Bounded timeout per rotated-out validator connection invalidation.
pub const VALIDATOR_MESH_ROTATE_CLOSE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Boxed future used by [`ValidatorMeshTransport`] (object-safe async).
pub type MeshFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Transport the validator mesh drives. The production implementation is
/// [`InfnodeMeshTransport`] (direct `request_to` / pubsub and the pubsub
/// overlay for the fallback); tests substitute a deterministic fake.
pub trait ValidatorMeshTransport: Send + Sync {
    /// Deliver a consensus payload DIRECTLY to one validator. No DHT lookup:
    /// the peer id is already known and the connection is kept warm by
    /// [`ValidatorMesh::maintain`].
    fn deliver_direct<'a>(
        &'a self,
        peer: [u8; infnode::proto::NODEID_LEN],
        topic: &'a str,
        data: &'a str,
    ) -> MeshFuture<'a, Result<(), String>>;

    /// Deliver a pre-serialized `{topic, data}` JSON frame directly to one
    /// validator so N peers do not re-serialize JSON N times. Default impl
    /// delegates to [`Self::deliver_direct`] for test fakes.
    fn deliver_direct_frame<'a>(
        &'a self,
        peer: [u8; infnode::proto::NODEID_LEN],
        topic: &'a str,
        data: &'a str,
        _frame: &'a [u8],
    ) -> MeshFuture<'a, Result<(), String>> {
        self.deliver_direct(peer, topic, data)
    }

    /// Heartbeat/reconnect attempt: proves the peer is reachable and keeps
    /// its direct link warm.
    fn probe<'a>(
        &'a self,
        peer: [u8; infnode::proto::NODEID_LEN],
    ) -> MeshFuture<'a, Result<(), String>>;

    /// Existing DHT/overlay publish path used as the mesh fallback. Returns
    /// the number of local/relayed deliveries reported by the transport.
    fn publish_overlay<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> MeshFuture<'a, Result<usize, String>>;
}

/// One pinned validator in the direct mesh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorMeshMember {
    pub id: [u8; 20],
    pub endpoints: Vec<String>,
    pub label: String,
}

impl ValidatorMeshMember {
    pub fn new(id: [u8; 20], endpoints: Vec<String>, label: impl Into<String>) -> Self {
        Self {
            id,
            endpoints,
            label: label.into(),
        }
    }

    /// Build a member from a pinned peer config (the identity is the PQ id,
    /// endpoints are the dial targets). `None` when the peer has no pinned
    /// PQ key — such a peer cannot be a direct-mesh member by construction.
    pub fn from_peer(peer: &infnode::config::PeerConfig) -> Option<Self> {
        let id = peer.primary_id().ok()?;
        Some(Self::new(id, peer.endpoints.clone(), peer.name.clone()))
    }
}

/// Result of installing a validator set. `generation` increments on every
/// rotation so a caller can prove the mesh was refreshed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshRotation {
    pub generation: u64,
    pub added: usize,
    pub removed: usize,
    pub updated: usize,
    pub members: usize,
    /// Ids dropped by this rotation; the adapter closes their direct links.
    pub removed_ids: Vec<[u8; 20]>,
}

/// Per-member mesh state (direct-link health only; identity/auth live in
/// infnode).
#[derive(Clone, Debug)]
struct MeshMemberState {
    endpoints: Vec<String>,
    label: String,
    consecutive_failures: u32,
    suspected: bool,
    suspect_until_ms: u64,
    last_ok_ms: u64,
    last_attempt_ms: u64,
    evictions: u32,
}

impl MeshMemberState {
    fn new(member: &ValidatorMeshMember, now_ms: u64) -> Self {
        Self {
            endpoints: member.endpoints.clone(),
            label: member.label.clone(),
            consecutive_failures: 0,
            suspected: false,
            suspect_until_ms: 0,
            last_ok_ms: now_ms,
            last_attempt_ms: now_ms,
            evictions: 0,
        }
    }

    fn routing_allowed(&self) -> bool {
        !self.suspected
    }

    fn reconnect_due(&self, now_ms: u64) -> bool {
        self.suspected && now_ms >= self.suspect_until_ms
    }
}

#[derive(Clone, Debug, Default)]
struct MeshState {
    generation: u64,
    members: std::collections::BTreeMap<[u8; 20], MeshMemberState>,
}

/// Outcome of one mesh delivery attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshDelivery {
    /// Validators in the direct-target set for this delivery.
    pub targets: usize,
    /// Validators reached over a live direct link.
    pub direct_ok: usize,
    /// Validators whose direct link failed (their copy went to the fallback).
    pub direct_failed: usize,
    /// A DHT/overlay publish was attempted for the failed copies.
    pub fallback_used: bool,
    /// Overlay reported at least one delivery.
    pub fallback_ok: bool,
}

impl MeshDelivery {
    /// True only when every targeted validator was reached over a DIRECT
    /// link. The overlay fallback is deliberately NOT delivery proof here.
    ///
    /// `fallback_ok` means `publish_overlay` reported at least one accepted
    /// copy — "SOME subscriber took it", not "every failed target received
    /// it" (the API returns a count, not per-peer coverage). Treating that as
    /// coverage could let ONE overlay publish hide N lost direct copies: the
    /// caller would skip the per-peer broadcast and those validators would
    /// miss the frame. A partial failure therefore stays `false`, so the
    /// normal broadcast (which addresses every peer) still runs; the overlay
    /// publish remains a best-effort extra copy, never a substitute.
    ///
    /// L3 fix: an EMPTY target set is not success either. With no attempted
    /// direct copy there is no proof at all, and "reached nobody" must read
    /// as false so the caller broadcasts.
    pub fn delivered(&self) -> bool {
        self.targets > 0 && self.direct_ok == self.targets
    }
}

/// Outcome of one maintenance pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshMaintenance {
    pub probed: usize,
    pub recovered: usize,
    pub still_down: usize,
    pub skipped_cooldown: usize,
}

/// Direct validator mesh: a set of PERSISTENT direct connections to the
/// pinned validator peers, refreshed on validator-set rotation.
///
/// Routing model: consensus payloads are addressed by validator id and sent
/// over the warm direct link ([`Self::deliver`]); the DHT is only used as a
/// fallback when a direct link fails (and remains the path for discovery,
/// blob storage and non-validator peers).
pub struct ValidatorMesh {
    transport: Arc<dyn ValidatorMeshTransport>,
    state: std::sync::Mutex<MeshState>,
    evict_after: u32,
    cooldown_ms: u64,
    heartbeat_ms: u64,
    evictions_total: std::sync::atomic::AtomicU64,
    direct_total: std::sync::atomic::AtomicU64,
    fallback_total: std::sync::atomic::AtomicU64,
}

impl ValidatorMesh {
    pub fn new(transport: Arc<dyn ValidatorMeshTransport>) -> Self {
        Self::with_policy(
            transport,
            VALIDATOR_MESH_EVICT_AFTER,
            VALIDATOR_MESH_COOLDOWN_MS,
            VALIDATOR_MESH_HEARTBEAT_MS,
        )
    }

    /// Explicit policy (tests use a short cooldown; production keeps the
    /// defaults above).
    pub fn with_policy(
        transport: Arc<dyn ValidatorMeshTransport>,
        evict_after: u32,
        cooldown_ms: u64,
        heartbeat_ms: u64,
    ) -> Self {
        Self {
            transport,
            state: std::sync::Mutex::new(MeshState::default()),
            evict_after: evict_after.max(1),
            cooldown_ms: cooldown_ms.max(1),
            heartbeat_ms: heartbeat_ms.max(1),
            evictions_total: std::sync::atomic::AtomicU64::new(0),
            direct_total: std::sync::atomic::AtomicU64::new(0),
            fallback_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MeshState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Install/replace the member set (validator-set rotation).
    ///
    /// * members still present keep their health counters;
    /// * a member whose endpoint list CHANGED is treated as a new link: the
    ///   failure streak and suspicion flag reset so the new address is tried
    ///   immediately;
    /// * members no longer in the set are dropped (their links are closed by
    ///   the transport on its next reconcile/idle timeout, and no further
    ///   traffic is addressed to them).
    pub fn install(
        &self,
        members: impl IntoIterator<Item = ValidatorMeshMember>,
        now_ms: u64,
    ) -> MeshRotation {
        use std::collections::BTreeMap;
        let mut new_set: BTreeMap<[u8; 20], ValidatorMeshMember> = BTreeMap::new();
        for m in members {
            if new_set.len() >= VALIDATOR_MESH_MAX_MEMBERS {
                break;
            }
            new_set.insert(m.id, m);
        }
        let mut st = self.lock();
        let old_ids: Vec<[u8; 20]> = st.members.keys().copied().collect();
        let mut added = 0usize;
        let mut updated = 0usize;
        for (id, member) in &new_set {
            match st.members.get_mut(id) {
                Some(existing) => {
                    if existing.endpoints != member.endpoints {
                        existing.endpoints = member.endpoints.clone();
                        existing.label = member.label.clone();
                        existing.consecutive_failures = 0;
                        existing.suspected = false;
                        existing.suspect_until_ms = 0;
                        existing.last_ok_ms = now_ms;
                        existing.last_attempt_ms = now_ms;
                        updated += 1;
                    } else if existing.label != member.label {
                        existing.label = member.label.clone();
                    }
                }
                None => {
                    st.members.insert(*id, MeshMemberState::new(member, now_ms));
                    added += 1;
                }
            }
        }
        let removed_ids: Vec<[u8; 20]> = old_ids
            .iter()
            .filter(|id| !new_set.contains_key(*id))
            .copied()
            .collect();
        let removed = removed_ids.len();
        st.members.retain(|id, _| new_set.contains_key(id));
        st.generation = st.generation.saturating_add(1);
        MeshRotation {
            generation: st.generation,
            added,
            removed,
            updated,
            members: st.members.len(),
            removed_ids,
        }
    }

    pub fn generation(&self) -> u64 {
        self.lock().generation
    }

    pub fn len(&self) -> usize {
        self.lock().members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn members(&self) -> Vec<ValidatorMeshMember> {
        self.lock()
            .members
            .iter()
            .map(|(id, st)| ValidatorMeshMember::new(*id, st.endpoints.clone(), st.label.clone()))
            .collect()
    }

    pub fn is_member(&self, id: &[u8; 20]) -> bool {
        self.lock().members.contains_key(id)
    }

    /// Validators eligible for DIRECT sends right now (suspected peers are
    /// withheld until a successful reconnect).
    ///
    /// A peer whose cooldown has elapsed is STILL withheld here. Reconnect is
    /// an explicit, off-tick action ([`Self::maintain`], which probes with an
    /// acknowledged round trip); it must not ride the per-frame send path,
    /// where a dead peer would cost the full mesh timeout on every consensus
    /// frame after each cooldown expires. `now_ms` is kept for API stability.
    pub fn direct_targets(&self, _now_ms: u64) -> Vec<[u8; 20]> {
        let st = self.lock();
        st.members
            .iter()
            .filter(|(_, m)| m.routing_allowed())
            .map(|(id, _)| *id)
            .collect()
    }

    /// All member ids, including suspected ones (explicit-destination set).
    pub fn all_targets(&self) -> Vec<[u8; 20]> {
        self.lock().members.keys().copied().collect()
    }

    /// True when EVERY id in `ids` is a mesh member.
    ///
    /// The consensus send path only substitutes the mesh for the normal
    /// per-peer broadcast when the mesh covers the complete configured peer
    /// set; otherwise a non-member validator would be skipped. Pure state
    /// query, so callers can decide without touching the transport.
    pub fn covers(&self, ids: &[[u8; 20]]) -> bool {
        let st = self.lock();
        !ids.is_empty() && ids.iter().all(|id| st.members.contains_key(id))
    }

    pub fn consecutive_failures(&self, id: &[u8; 20]) -> u32 {
        self.lock()
            .members
            .get(id)
            .map(|m| m.consecutive_failures)
            .unwrap_or(0)
    }

    pub fn is_suspected(&self, id: &[u8; 20]) -> bool {
        self.lock()
            .members
            .get(id)
            .map(|m| m.suspected)
            .unwrap_or(false)
    }

    /// Whether the peer's cooldown elapsed and a reconnect is allowed.
    pub fn reconnect_due(&self, id: &[u8; 20], now_ms: u64) -> bool {
        self.lock()
            .members
            .get(id)
            .map(|m| m.reconnect_due(now_ms))
            .unwrap_or(false)
    }

    pub fn evictions_total(&self) -> u64 {
        self.evictions_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn direct_deliveries_total(&self) -> u64 {
        self.direct_total.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn fallback_deliveries_total(&self) -> u64 {
        self.fallback_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn evict_after(&self) -> u32 {
        self.evict_after
    }

    pub fn cooldown_ms(&self) -> u64 {
        self.cooldown_ms
    }

    pub fn heartbeat_ms(&self) -> u64 {
        self.heartbeat_ms
    }

    /// Record a successful direct interaction: clears the failure streak,
    /// suspicion flag and cooldown.
    pub fn record_success(&self, id: [u8; 20], now_ms: u64) {
        let mut st = self.lock();
        if let Some(m) = st.members.get_mut(&id) {
            let recovered = m.suspected;
            m.consecutive_failures = 0;
            m.suspected = false;
            m.suspect_until_ms = 0;
            m.last_ok_ms = now_ms;
            m.last_attempt_ms = now_ms;
            if recovered {
                tracing::info!(
                    "[mesh] validator {} recovered, direct link restored",
                    hex::encode(id)
                );
            }
        }
    }

    /// Record one consecutive direct failure. At [`Self::evict_after`] the
    /// peer is marked suspected dead and withheld from direct targets for
    /// [`Self::cooldown_ms`]; the loud line fires once per transition.
    pub fn record_failure(&self, id: [u8; 20], now_ms: u64) {
        let mut st = self.lock();
        if let Some(m) = st.members.get_mut(&id) {
            m.consecutive_failures = m.consecutive_failures.saturating_add(1);
            m.last_attempt_ms = now_ms;
            if m.suspected {
                // Already withheld: this was the one allowed post-cooldown
                // attempt (or an explicit retry). Re-arm the cooldown so a
                // dead peer is not dialled on every delivery.
                m.suspect_until_ms = now_ms.saturating_add(self.cooldown_ms);
            } else if m.consecutive_failures >= self.evict_after {
                m.suspected = true;
                m.suspect_until_ms = now_ms.saturating_add(self.cooldown_ms);
                m.evictions = m.evictions.saturating_add(1);
                let total = self
                    .evictions_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                tracing::warn!(
                    "[mesh] validator {} SUSPECTED DEAD after {} consecutive direct failures; \
                     withholding from routing for {} ms (total evictions {})",
                    hex::encode(id),
                    m.consecutive_failures,
                    self.cooldown_ms,
                    total
                );
            }
        }
    }

    /// Direct delivery to one validator (no DHT lookup). Returns the outcome
    /// of that single send; the caller decides whether to use the fallback.
    pub async fn deliver_to(&self, id: [u8; 20], topic: &str, data: &str, now_ms: u64) -> bool {
        if !self.is_member(&id) {
            return false;
        }
        match self.transport.deliver_direct(id, topic, data).await {
            // The production transport's direct send is a fire-and-forget
            // WRITE: it proves the local stream accepted the frame, not that
            // the peer processed it. Treating it as liveness let a peer that
            // accepts writes and never answers stay "healthy" forever (and
            // cleared an existing suspicion). Only an acknowledged probe
            // (see `maintain`) may mark a peer healthy.
            Ok(()) => true,
            Err(_) => {
                self.record_failure(id, now_ms);
                false
            }
        }
    }

    /// Deliver a consensus payload to the whole mesh.
    ///
    /// Direct links are attempted concurrently; any failed copy (or an empty
    /// direct target set) is handed to the DHT/overlay fallback ONCE, so a
    /// message is never dropped merely because the mesh is degraded.
    pub async fn deliver(&self, topic: &str, data: &str, now_ms: u64) -> MeshDelivery {
        let frame = Arc::new(InfnodeMeshTransport::envelope(topic, data));
        self.deliver_frame(topic, data, frame, now_ms).await
    }

    /// Deliver a pre-serialized `{topic, data}` JSON frame to the whole mesh,
    /// avoiding redundant JSON serialization across N peers.
    pub async fn deliver_frame(
        &self,
        topic: &str,
        data: &str,
        frame: Arc<Vec<u8>>,
        now_ms: u64,
    ) -> MeshDelivery {
        let targets = self.direct_targets(now_ms);
        let mut delivery = MeshDelivery {
            targets: targets.len(),
            ..MeshDelivery::default()
        };
        let mut sends = Vec::with_capacity(targets.len());
        for id in targets {
            let frame = Arc::clone(&frame);
            sends.push(async move {
                (
                    id,
                    self.transport
                        .deliver_direct_frame(id, topic, data, &frame)
                        .await,
                )
            });
        }
        let results = futures::future::join_all(sends).await;
        for (id, result) in results {
            match result {
                Ok(()) => {
                    // Fire-and-forget WRITE only: not a delivery proof and not
                    // evidence of peer liveness. The acknowledged heartbeat
                    // ([`Self::maintain`]) owns recovery, so a blackholing
                    // peer cannot be kept healthy (or cleared) by local writes.
                    delivery.direct_ok += 1;
                }
                Err(_) => {
                    self.record_failure(id, now_ms);
                    delivery.direct_failed += 1;
                }
            }
        }
        if delivery.direct_ok > 0 {
            self.direct_total.fetch_add(
                delivery.direct_ok as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        // Fallback rule: any failed copy goes to the overlay; also use it
        // when the mesh has no direct target at all (all suspected/mesh down).
        if delivery.direct_failed > 0 || delivery.direct_ok == 0 {
            delivery.fallback_used = true;
            delivery.fallback_ok = match tokio::time::timeout(
                VALIDATOR_MESH_OVERLAY_TIMEOUT,
                self.transport.publish_overlay(topic, data),
            )
            .await
            {
                Ok(Ok(n)) => n > 0,
                Ok(Err(_)) => false,
                Err(_) => {
                    tracing::warn!(
                        topic = %topic,
                        timeout_secs = VALIDATOR_MESH_OVERLAY_TIMEOUT.as_secs(),
                        "[mesh] overlay fallback publish timed out"
                    );
                    false
                }
            };
            if delivery.fallback_ok {
                self.fallback_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        delivery
    }

    /// Keep the mesh persistent: probe healthy links on the heartbeat and
    /// attempt one reconnect for every suspected peer whose cooldown elapsed.
    pub async fn maintain(&self, now_ms: u64) -> MeshMaintenance {
        let mut report = MeshMaintenance::default();
        let probes: Vec<[u8; 20]> = {
            let st = self.lock();
            st.members
                .iter()
                .filter_map(|(id, m)| {
                    if m.suspected {
                        if m.reconnect_due(now_ms) {
                            Some(*id)
                        } else {
                            None
                        }
                    } else if now_ms.saturating_sub(m.last_attempt_ms) >= self.heartbeat_ms {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect()
        };
        report.skipped_cooldown = {
            let st = self.lock();
            st.members
                .values()
                .filter(|m| m.suspected && !m.reconnect_due(now_ms))
                .count()
        };
        let mut stream = futures::stream::iter(probes.into_iter().map(|id| async move {
            let res = self.transport.probe(id).await;
            (id, res)
        }))
        .buffer_unordered(VALIDATOR_MESH_PROBE_CONCURRENCY);

        while let Some((id, res)) = stream.next().await {
            report.probed += 1;
            match res {
                Ok(()) => {
                    let was_suspected = self.is_suspected(&id);
                    self.record_success(id, now_ms);
                    if was_suspected {
                        report.recovered += 1;
                    }
                }
                Err(_) => {
                    self.record_failure(id, now_ms);
                    report.still_down += 1;
                }
            }
        }
        report
    }
}

/// Production transport: infnode direct sends over the persistent peer
/// connections, with the pubsub overlay as the DHT fallback path.
pub struct InfnodeMeshTransport {
    node: Arc<Node>,
}

impl InfnodeMeshTransport {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    fn envelope(topic: &str, data: &str) -> Vec<u8> {
        serde_json::json!({ "topic": topic, "data": data })
            .to_string()
            .into_bytes()
    }

    /// Pre-flight check ensuring a pubsub payload and its serialized envelope
    /// respect `infnode`'s topic, `MAX_PUBSUB_DATA_LEN`, and `MAX_FRAME` limits.
    pub fn validate_pubsub_frame(topic: &str, data: &str, frame_len: usize) -> Result<(), String> {
        if !infnode::proto::topic_ok(topic) {
            return Err(format!("invalid pubsub topic length ({})", topic.len()));
        }
        if !infnode::proto::pubsub_data_ok(data) {
            return Err(format!(
                "pubsub data {} bytes exceeds infnode MAX_PUBSUB_DATA_LEN ({})",
                data.len(),
                infnode::proto::MAX_PUBSUB_DATA_LEN
            ));
        }
        if frame_len.saturating_add(16) > infnode::proto::MAX_FRAME {
            return Err(format!(
                "pubsub frame {} bytes exceeds infnode MAX_FRAME ({})",
                frame_len.saturating_add(16),
                infnode::proto::MAX_FRAME
            ));
        }
        Ok(())
    }
}

impl ValidatorMeshTransport for InfnodeMeshTransport {
    fn deliver_direct<'a>(
        &'a self,
        peer: [u8; 20],
        topic: &'a str,
        data: &'a str,
    ) -> MeshFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let payload = Self::envelope(topic, data);
            if let Err(why) = Self::validate_pubsub_frame(topic, data, payload.len()) {
                tracing::warn!(
                    peer = %hex::encode(peer),
                    len = payload.len(),
                    err = %why,
                    "[mesh] direct send rejected by transport budget"
                );
                return Err(why);
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(mesh_send_timeout_ms()),
                self.node.send_to(peer, "pubsub.msg", payload),
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        err = %e,
                        "[mesh] direct send rejected by infnode"
                    );
                    Err(e.to_string())
                }
                Err(_) => Err("mesh direct send timeout".to_string()),
            }
        })
    }

    fn deliver_direct_frame<'a>(
        &'a self,
        peer: [u8; 20],
        topic: &'a str,
        data: &'a str,
        frame: &'a [u8],
    ) -> MeshFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if let Err(why) = Self::validate_pubsub_frame(topic, data, frame.len()) {
                tracing::warn!(
                    peer = %hex::encode(peer),
                    len = frame.len(),
                    err = %why,
                    "[mesh] direct frame rejected by transport budget"
                );
                return Err(why);
            }
            let payload = frame.to_vec();
            match tokio::time::timeout(
                std::time::Duration::from_millis(mesh_send_timeout_ms()),
                self.node.send_to(peer, "pubsub.msg", payload),
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        len = frame.len(),
                        err = %e,
                        "[mesh] direct frame rejected by infnode"
                    );
                    Err(e.to_string())
                }
                Err(_) => Err("mesh direct send timeout".to_string()),
            }
        })
    }

    fn probe<'a>(&'a self, peer: [u8; 20]) -> MeshFuture<'a, Result<(), String>> {
        Box::pin(async move {
            match tokio::time::timeout(
                std::time::Duration::from_millis(mesh_send_timeout_ms()),
                self.node.warm_peer(peer),
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("mesh probe timeout".to_string()),
            }
        })
    }

    fn publish_overlay<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> MeshFuture<'a, Result<usize, String>> {
        Box::pin(async move {
            match tokio::time::timeout(
                VALIDATOR_MESH_OVERLAY_TIMEOUT,
                self.node.publish_overlay(topic, data),
            )
            .await
            {
                Ok(n) => Ok(n),
                Err(_) => Err("mesh overlay publish timeout".to_string()),
            }
        })
    }
}

/// Wall clock in ms for mesh bookkeeping (monotonic enough for a cooldown;
/// no test depends on exact epoch values).
pub(super) fn mesh_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Effective direct-mesh send/probe timeout.
///
/// Honours the same `STELL_SEND_TIMEOUT_MS` knob operators already use for
/// WAN links (M6): the fixed 2 s default marked a healthy slow validator dead
/// on every send/probe. Clamped to a sane range; unset/invalid keeps the
/// documented 2 s default.
pub fn mesh_send_timeout_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_SEND_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.clamp(500, 60_000))
            .unwrap_or(VALIDATOR_MESH_SEND_TIMEOUT_MS)
    })
}

/// Mesh membership from operator config.
///
/// When at least one pinned peer carries a consensus key, only those peers
/// are validators and therefore mesh members (storage-only peers stay on the
/// DHT path). A config with no consensus keys at all is a bootstrap/dev set:
/// every pinned peer is treated as a validator.
fn mesh_members_from_config(node: &Node) -> Vec<ValidatorMeshMember> {
    let has_consensus_key = node.cfg.peers.iter().any(|p| p.consensus_pub.is_some());
    node.cfg
        .peers
        .iter()
        .filter(|p| !has_consensus_key || p.consensus_pub.is_some())
        .filter_map(ValidatorMeshMember::from_peer)
        .collect()
}

pub struct P2pNetworkAdapter {
    pub node: Arc<Node>,
    /// Direct validator mesh: persistent links to the pinned validator peers
    /// plus the DHT/overlay fallback for failed direct sends.
    mesh: Arc<ValidatorMesh>,
    /// Chain epoch, from the genesis fingerprint. Mixed into every published name so
    /// blobs from a different chain (or a previous run after a wipe) are invisible.
    ///
    /// Behind a lock because the adapter is constructed before genesis is computed
    /// (the P2P node has to exist to derive the validator set), and because every
    /// reader takes it briefly this costs nothing next to a network round trip.
    pub(super) epoch: std::sync::RwLock<EpochTag>,
    /// Height cursor for the DHT retention prune: the last height already swept
    /// by `maybe_prune_retained` (0 = nothing pruned yet). Monotonic; advanced
    /// at most `STELL_DHT_PRUNE_MAX_PER_RUN` heights per pass so an upgrade
    /// backlog drains gradually on `publish_lane`, never on the consensus tick.
    pub(super) prune_cursor: std::sync::atomic::AtomicU64,
    /// Whether the persisted cursor has been loaded once this process (lazy, on
    /// the first prune pass). The in-memory cursor alone would reset to 0 on
    /// every restart and re-chew the already-pruned low range forever, never
    /// reaching a large backlog — the persisted value lets restarts resume.
    pub(super) prune_cursor_loaded: std::sync::atomic::AtomicBool,
    /// Last finalized height that triggered a prune pass. Passes run at most
    /// every `STELL_DHT_PRUNE_INTERVAL_HEIGHTS` heights (the snapshot cadence).
    pub(super) last_prune_tip: std::sync::atomic::AtomicU64,
    /// Highest head height THIS process has published, per shard. `publish_head`
    /// only moves forward: the shared head key is last-writer-wins by `stored_at`,
    /// so republishing a stale (or genesis) height after a peer advertised the
    /// tip rewinds the network's head for EVERYONE — including ourselves on
    /// read (the local manifest shadows peers). The guard makes each process
    /// publish a strictly increasing sequence; see `head_publish_allowed`.
    pub(super) last_published_head: std::sync::Mutex<std::collections::HashMap<u32, u64>>,
    /// Bounded per-(shard, height) negative cache / exponential backoff for
    /// missing `_hq_` QC sidecars (`fetch_block_qc` / `fetch_block_qc_probe`).
    pub(super) qc_miss_backoff: std::sync::Mutex<QcMissBackoff>,
    /// Recently published `_hq_{shard}_{height}` companion QCs (`(shard, height) -> (block_hash, at)`),
    /// bounded to avoid redundant duplicate `_hq_` DHT stores when both
    /// `retro_publish_blocks` and `persist_block_header` publish the same tip.
    pub(super) recent_hq_published: Arc<RecentHqPublishCache>,
}

pub(super) type RecentHqPublishCache =
    std::sync::Mutex<std::collections::HashMap<(u32, u64), ([u8; 32], std::time::Instant)>>;

/// Result of a UNICAST consensus frame: which transport carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnicastPath {
    /// Delivered over the warm direct validator-mesh link.
    MeshDirect,
    /// Delivered over the existing per-peer direct transport (mesh not a
    /// member, or its direct copy failed).
    PeerDirect,
}

/// Route ONE consensus frame to exactly ONE peer.
///
/// The warm mesh direct link is used when `peer` is a member; any other case
/// (non-member, or a failed direct copy) goes through the supplied per-peer
/// direct transport. Only ONE copy is ever sent — this never falls back to the
/// overlay broadcast, so a per-requester reply cannot become an all-peer fan
/// out. Split out of [`P2pNetworkAdapter::deliver_consensus_to_peer`] so the
/// routing rule is testable with a fake mesh transport.
pub async fn deliver_unicast<F, Fut>(
    mesh: &ValidatorMesh,
    peer: [u8; 20],
    topic: &str,
    data: &str,
    direct: F,
) -> Result<UnicastPath, String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    if mesh.is_member(&peer) && mesh.deliver_to(peer, topic, data, mesh_now_ms()).await {
        return Ok(UnicastPath::MeshDirect);
    }
    // Not a member, or the direct mesh copy failed: the existing per-peer
    // direct transport is the fallback, still addressed to this one peer.
    direct().await?;
    Ok(UnicastPath::PeerDirect)
}

impl P2pNetworkAdapter {
    pub fn new(node: Arc<Node>) -> Self {
        let transport: Arc<dyn ValidatorMeshTransport> =
            Arc::new(InfnodeMeshTransport::new(node.clone()));
        let mesh = Arc::new(ValidatorMesh::new(transport));
        // Bootstrap the mesh from the pinned peer set (the validators this
        // node was configured with). A later validator-set rotation calls
        // `refresh_validator_mesh`.
        let members = mesh_members_from_config(&node);
        mesh.install(members, mesh_now_ms());
        // Persistent-link upkeep: probe healthy links on the heartbeat and
        // retry suspected peers after their cooldown. Spawned only when a
        // runtime is present (constructors used from sync test code stay
        // inert until someone calls `maintain_validator_mesh` explicitly).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let upkeep = Arc::clone(&mesh);
            handle.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        upkeep.heartbeat_ms().max(1),
                    ))
                    .await;
                    // No-op (one empty-map lock) until a validator set is
                    // installed, so a rotation later is picked up by the
                    // already-running loop.
                    let _ = upkeep.maintain(mesh_now_ms()).await;
                }
            });
        }
        Self {
            node,
            mesh,
            epoch: std::sync::RwLock::new(EpochTag::default()),
            prune_cursor: std::sync::atomic::AtomicU64::new(0),
            prune_cursor_loaded: std::sync::atomic::AtomicBool::new(false),
            last_prune_tip: std::sync::atomic::AtomicU64::new(0),
            last_published_head: std::sync::Mutex::new(std::collections::HashMap::new()),
            qc_miss_backoff: std::sync::Mutex::new(QcMissBackoff::default()),
            recent_hq_published: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// The validator mesh handle (direct sends + fallback).
    pub fn validator_mesh(&self) -> Arc<ValidatorMesh> {
        Arc::clone(&self.mesh)
    }

    /// Install a rotated validator set. Members are transport identities
    /// (PQ node ids) with their dial endpoints; the mesh is rebuilt in place
    /// and the next `maintain_validator_mesh` establishes the new links.
    /// Direct links of rotated-out validators are closed immediately.
    pub async fn set_validator_mesh_members(
        &self,
        members: Vec<ValidatorMeshMember>,
    ) -> MeshRotation {
        let rotation = self.mesh.install(members, mesh_now_ms());
        self.close_rotated_out(&rotation).await;
        rotation
    }

    /// Refresh the mesh from the current pinned peer config (the static
    /// validator bootstrap set). Returns the rotation report.
    pub async fn refresh_validator_mesh_from_config(&self) -> MeshRotation {
        let members = mesh_members_from_config(&self.node);
        let rotation = self.mesh.install(members, mesh_now_ms());
        self.close_rotated_out(&rotation).await;
        rotation
    }

    /// Reconcile the mesh with a consensus validator pubkey set.
    ///
    /// Transport identities are PQ ids, so the mapping goes through each
    /// pinned peer's `consensus-pub`: only peers whose consensus key is in
    /// the active set become mesh members. Validators without a pinned peer
    /// entry have no dial target here and are skipped (DHT discovery may
    /// supply it later).
    pub async fn refresh_validator_mesh(&self, validator_pubkeys: &[[u8; 32]]) -> MeshRotation {
        let active: std::collections::HashSet<[u8; 32]> =
            validator_pubkeys.iter().copied().collect();
        let mut members: Vec<ValidatorMeshMember> = Vec::new();
        for peer in &self.node.cfg.peers {
            let Some(pk) = peer.consensus_bytes().ok().flatten() else {
                continue;
            };
            if !active.contains(&pk) {
                continue;
            }
            if let Some(member) = ValidatorMeshMember::from_peer(peer) {
                members.push(member);
            }
        }
        let rotation = self.mesh.install(members, mesh_now_ms());
        self.close_rotated_out(&rotation).await;
        rotation
    }

    /// Close the persistent direct links of validators removed by a rotation
    /// (a warm QUIC connection would otherwise outlive its membership).
    async fn close_rotated_out(&self, rotation: &MeshRotation) {
        if rotation.removed_ids.is_empty() {
            return;
        }
        let futs = rotation.removed_ids.iter().map(|id| async move {
            let _ = tokio::time::timeout(
                VALIDATOR_MESH_ROTATE_CLOSE_TIMEOUT,
                self.node.invalidate_peer_conn(*id),
            )
            .await;
        });
        futures::future::join_all(futs).await;
    }

    /// One maintenance pass (heartbeat/reconnect). Exposed for the driver and
    /// for deterministic tests; the adapter also runs this on a timer.
    pub async fn maintain_validator_mesh(&self) -> MeshMaintenance {
        self.mesh.maintain(mesh_now_ms()).await
    }

    /// Consensus delivery over the mesh: direct links first, DHT/overlay
    /// fallback for any failed copy (or when the mesh is entirely down).
    pub async fn deliver_consensus_mesh(&self, topic: &str, data_hex: &str) -> MeshDelivery {
        self.mesh.deliver(topic, data_hex, mesh_now_ms()).await
    }

    /// Consensus delivery over the mesh using a pre-serialized `{topic, data}`
    /// JSON frame so N peers do not re-serialize JSON.
    pub async fn deliver_consensus_mesh_frame(
        &self,
        topic: &str,
        data_hex: &str,
        frame: Arc<Vec<u8>>,
    ) -> MeshDelivery {
        self.mesh
            .deliver_frame(topic, data_hex, frame, mesh_now_ms())
            .await
    }

    /// Deliver ONE consensus frame to exactly ONE peer (unicast).
    ///
    /// Direct mesh link when the peer is a member, then the existing per-peer
    /// direct transport on any miss. Never the overlay broadcast: a body
    /// reply addressed to its requester must not fan out to the peer set.
    /// Returns which transport carried the frame; `Err` when both failed (the
    /// caller takes its liveness fallback).
    pub async fn deliver_consensus_to_peer(
        &self,
        peer: [u8; 20],
        topic: &str,
        data_hex: &str,
    ) -> Result<UnicastPath, String> {
        let payload = InfnodeMeshTransport::envelope(topic, data_hex);
        InfnodeMeshTransport::validate_pubsub_frame(topic, data_hex, payload.len())?;
        let node = Arc::clone(&self.node);
        let timeout = std::time::Duration::from_millis(mesh_send_timeout_ms());
        deliver_unicast(&self.mesh, peer, topic, data_hex, move || async move {
            match tokio::time::timeout(timeout, node.send_to(peer, "pubsub.msg", payload)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("unicast direct send timeout".to_string()),
            }
        })
        .await
    }

    /// Scope this adapter to a chain epoch. Called once the genesis fingerprint is
    /// known, before anything is published or fetched.
    pub fn set_epoch(&self, epoch: EpochTag) {
        *self.epoch.write().unwrap_or_else(|e| e.into_inner()) = epoch;
    }

    pub fn epoch(&self) -> EpochTag {
        self.epoch.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod wave23c_tests {
    use super::*;

    struct HungOverlayTransport;

    impl ValidatorMeshTransport for HungOverlayTransport {
        fn deliver_direct<'a>(
            &'a self,
            _peer: [u8; infnode::proto::NODEID_LEN],
            _topic: &'a str,
            _data: &'a str,
        ) -> MeshFuture<'a, Result<(), String>> {
            Box::pin(async { Err("direct link down".to_string()) })
        }

        fn probe<'a>(
            &'a self,
            _peer: [u8; infnode::proto::NODEID_LEN],
        ) -> MeshFuture<'a, Result<(), String>> {
            Box::pin(async { Ok(()) })
        }

        fn publish_overlay<'a>(
            &'a self,
            _topic: &'a str,
            _data: &'a str,
        ) -> MeshFuture<'a, Result<usize, String>> {
            Box::pin(std::future::pending::<Result<usize, String>>())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deliver_frame_times_out_on_hung_overlay_publish() {
        let mesh = ValidatorMesh::new(Arc::new(HungOverlayTransport));
        let peer = [0x11u8; 20];
        mesh.install(
            vec![ValidatorMeshMember::new(
                peer,
                vec!["127.0.0.1:9411".to_string()],
                "v1",
            )],
            1_000,
        );

        let delivery = mesh
            .deliver("stell/consensus/test", "deadbeef", 1_000)
            .await;
        assert_eq!(delivery.targets, 1);
        assert_eq!(delivery.direct_ok, 0);
        assert_eq!(delivery.direct_failed, 1);
        assert!(delivery.fallback_used);
        assert!(
            !delivery.fallback_ok,
            "hung overlay publish must time out as fallback_ok = false"
        );
        assert_eq!(
            mesh.fallback_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}
