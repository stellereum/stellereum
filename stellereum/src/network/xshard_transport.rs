use super::fetch::decode_wire_limited;
use super::mesh_send_timeout_ms;
use super::naming::{cross_shard_topic, PREFIX_CROSS_SHARD};
use super::P2pNetworkAdapter;
use crate::sharding::{CrossShardMessage, ShardId};
use infnode::node::Node;
use std::sync::Arc;

impl P2pNetworkAdapter {
    /// Broadcast cross-shard message via infnode overlay
    pub async fn broadcast_cross_shard(&self, msg: &CrossShardMessage) -> Result<(), String> {
        let msg_id_hex = hex::encode(msg.msg_id);
        let msg_bytes = bincode::serialize(msg)
            .map_err(|e| format!("CrossShardMessage serialize error: {:?}", e))?;

        let key = format!("{}{}:{}", PREFIX_CROSS_SHARD, msg.target_shard, msg_id_hex);
        self.node
            .kv_store_local(&key, &hex::encode(&msg_bytes))
            .await;

        let index_key = format!("{}{}:index", PREFIX_CROSS_SHARD, msg.target_shard);
        let current_index = self.node.get_local_kv(&index_key).await.unwrap_or_default();
        let mut ids: Vec<String> = serde_json::from_str(&current_index).unwrap_or_default();
        if !ids.contains(&msg_id_hex) {
            ids.push(msg_id_hex);
            let serialized = serde_json::to_string(&ids).unwrap_or_default();
            self.node.kv_store_local(&index_key, &serialized).await;
        }

        Ok(())
    }

    /// Decode a cross-shard message received from the network.
    ///
    /// SECURITY (critical): the `trusted` flag bypasses Merkle inclusion
    /// verification. A message decoded from the wire ALWAYS has `trusted` cleared,
    /// so an attacker cannot forge a "trusted" message and mint value on the
    /// target shard. Only locally-generated messages (`new_trusted`) are trusted.
    pub fn parse_cross_shard_incoming(bytes: &[u8]) -> Option<CrossShardMessage> {
        let mut msg: CrossShardMessage =
            decode_wire_limited(bytes, MAX_CROSS_SHARD_MSG as u64).ok()?;
        msg.trusted = false;
        Some(msg)
    }

    /// Drop consumed cross-shard entries for `target_shard` by `msg_id`
    /// (§5 M3 pruning; the `Node` half of `CrossShardTransport::prune_consumed`).
    ///
    /// Removes each per-message KV entry and rewrites the node-local index
    /// without the pruned ids. Best-effort and idempotent: missing entries
    /// and a missing index are successes (nothing to remove), never errors,
    /// because pruning rides the apply path and must not fail finalization.
    /// Returns how many per-message entries were dropped (the index rewrite
    /// is not counted; it carries no value on its own).
    pub async fn prune_cross_shard_consumed(
        &self,
        target_shard: u32,
        msg_ids: &[[u8; 32]],
    ) -> usize {
        if msg_ids.is_empty() {
            return 0;
        }
        let drop: std::collections::HashSet<String> = msg_ids.iter().map(hex::encode).collect();
        let mut pruned = 0usize;
        for id_hex in &drop {
            let key = format!("{}{}:{}", PREFIX_CROSS_SHARD, target_shard, id_hex);
            self.node.kv_remove_local(&key).await;
            pruned += 1;
        }
        let index_key = format!("{}{}:index", PREFIX_CROSS_SHARD, target_shard);
        if let Some(index_str) = self.node.get_local_kv(&index_key).await {
            let ids: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
            if ids.iter().any(|i| drop.contains(i)) {
                let kept: Vec<String> = ids.into_iter().filter(|i| !drop.contains(i)).collect();
                let serialized = serde_json::to_string(&kept).unwrap_or_default();
                self.node.kv_store_local(&index_key, &serialized).await;
            }
        }
        pruned
    }

    /// Fetch inbound cross-shard messages destined for this shard
    pub async fn fetch_cross_shard_inbound(&self, target_shard: u32) -> Vec<CrossShardMessage> {
        let index_key = format!("{}{}:index", PREFIX_CROSS_SHARD, target_shard);
        let Some(index_str) = self.node.get_local_kv(&index_key).await else {
            return Vec::new();
        };

        let ids: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
        let mut messages = Vec::with_capacity(ids.len());

        for id_hex in ids {
            let key = format!("{}{}:{}", PREFIX_CROSS_SHARD, target_shard, id_hex);
            if let Some(val_hex) = self.node.get_local_kv(&key).await {
                if let Ok(bytes) = hex::decode(&val_hex) {
                    if let Some(msg) = Self::parse_cross_shard_incoming(&bytes) {
                        messages.push(msg);
                    }
                }
            }
        }

        messages
    }
}

/// In-process cross-shard mailbox with the SAME contract as the infnode KV
/// helpers above (`broadcast_cross_shard` / `fetch_cross_shard_inbound`).
///
/// The real transport is the infnode `Node`'s local KV, and it is NODE-LOCAL:
/// two shards can only exchange messages if they run in ONE process behind ONE
/// node. That is fine for the multi-shard runtime (`STELL_SHARDS=0,1`) but
/// impossible (and unnecessary) to spin up in a unit test, so the simulator
/// uses this in-memory twin. Both are keyed by `msg_id` so a broadcast is
/// idempotent, which matches `P2pNetworkAdapter::broadcast_cross_shard`'s
/// index-based dedupe.
///
/// The node-local KV cannot move a message between two physical servers at
/// all; that is what the gossip variant [`P2pCrossShardTransport`] is for.
#[derive(Default)]
pub struct LocalCrossShardKv {
    inbound: tokio::sync::Mutex<std::collections::HashMap<u32, Vec<CrossShardMessage>>>,
}

impl LocalCrossShardKv {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn broadcast_cross_shard(&self, msg: &CrossShardMessage) -> Result<(), String> {
        let mut map = self.inbound.lock().await;
        let queue = map.entry(msg.target_shard).or_default();
        if !queue.iter().any(|m| m.msg_id == msg.msg_id) {
            queue.push(msg.clone());
        }
        Ok(())
    }

    pub async fn fetch_cross_shard_inbound(&self, target_shard: u32) -> Vec<CrossShardMessage> {
        self.inbound
            .lock()
            .await
            .get(&target_shard)
            .cloned()
            .unwrap_or_default()
    }

    /// Drop consumed entries for `target_shard` by `msg_id` (§5 M3 pruning).
    ///
    /// Node-local KV hygiene, not consensus state: entries a shard already
    /// committed stay in the mailbox forever otherwise (every broadcast is
    /// idempotent and retained), so each apply prunes exactly the records it
    /// consumed. Idempotent: pruning an absent id removes nothing and still
    /// succeeds. Returns how many entries were removed.
    pub async fn prune(&self, target_shard: u32, msg_ids: &[[u8; 32]]) -> usize {
        if msg_ids.is_empty() {
            return 0;
        }
        let mut map = self.inbound.lock().await;
        let Some(queue) = map.get_mut(&target_shard) else {
            return 0;
        };
        let before = queue.len();
        queue.retain(|m| !msg_ids.contains(&m.msg_id));
        before - queue.len()
    }
}

/// Maximum encoded size of one cross-shard gossip payload.
///
/// A cross-shard message carries one transaction plus an optional Merkle
/// proof: kilobytes, not megabytes. The cap keeps a malformed or oversized
/// payload from being pushed into the overlay.
pub const MAX_CROSS_SHARD_MSG: usize = 4 * 1024 * 1024;

/// How many mesh hops a cross-shard gossip message may take.
///
/// The overlay relays a published message to the peers of the peer that
/// handled the publish, TTL hops deep. Three hops cover a small validator
/// mesh; a target shard on a server that is not a DIRECT peer of the sender
/// still hears the message.
pub const CROSS_SHARD_RELAY_TTL: u64 = 3;

/// How many msg_ids the gossip dedupe window remembers.
///
/// Gossip duplicates are normal (the mesh relays, and a peer may re-publish
/// on reconnect), so a message id is remembered for a while. The window is
/// bounded so a long-running node cannot grow the set without limit.
pub const CROSS_SHARD_DEDUPE_WINDOW: usize = 8192;

/// Boxed future returned by the pubsub abstraction.
///
/// The abstraction is a trait OBJECT (the transport lives in an `Arc` inside
/// [`CrossShardTransport`]), so its methods cannot use `async fn` in trait
/// position without losing object safety.
pub type CrossShardPubSubFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The pubsub primitive a cross-shard transport is built on.
///
/// infnode's `Node` is a concrete type, so the transport talks to the overlay
/// through this trait. Production uses [`InfnodeCrossShardPubSub`] (the real
/// QUIC mesh); the simulator and the unit tests use
/// [`InMemoryCrossShardPubSub`]. Both implement the SAME contract, which is
/// what makes the gossip path testable without a live network:
///
///  * `publish(topic, data)` — deliver `data` to every subscriber of `topic`,
///    the local ones included.
///  * `subscribe(topic)` — hand out a receiver of the payloads published to
///    `topic` AFTER the subscription (gossip has NO replay: a message
///    published before the subscription is never delivered).
///
/// `data` is the transport's own encoding (hex of a bincode message); every
/// implementation wraps it in the JSON envelope the decoder expects.
pub trait CrossShardPubSub: Send + Sync {
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<(), String>>;

    fn subscribe<'a>(
        &'a self,
        topic: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<tokio::sync::mpsc::UnboundedReceiver<String>, String>>;
}

/// In-memory twin of the overlay's pubsub: one bus of topics, shared by every
/// transport holding the same instance.
///
/// It models the gossip semantics exactly (publish → every subscriber of the
/// topic receives the payload; NO replay, so a subscription made after a
/// publish never sees that message), so a test that passes here describes the
/// real overlay's behaviour instead of a friendlier fiction.
#[derive(Default)]
pub struct InMemoryCrossShardPubSub {
    topics: std::sync::Mutex<
        std::collections::HashMap<String, Vec<tokio::sync::mpsc::UnboundedSender<String>>>,
    >,
}

impl InMemoryCrossShardPubSub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh bus, to be shared by the transports of one "network".
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl CrossShardPubSub for InMemoryCrossShardPubSub {
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let envelope = serde_json::json!({ "topic": topic, "data": data }).to_string();
            let senders = {
                let map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
                map.get(topic).cloned().unwrap_or_default()
            };
            for tx in senders {
                let _ = tx.send(envelope.clone());
            }
            Ok(())
        })
    }

    fn subscribe<'a>(
        &'a self,
        topic: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<tokio::sync::mpsc::UnboundedReceiver<String>, String>>
    {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let mut map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(topic.to_string()).or_default().push(tx);
            Ok(rx)
        })
    }
}

/// The node-local topic bus: the same-node delivery path of the pubsub layer.
///
/// The overlay cannot loop a published message back to its own publisher (a
/// `pubsub.msg` goes to PEERS), so two shards of one process (the
/// `STELL_SHARDS=0,1` shape) need an explicit same-node path: without it a
/// cross-shard message published by shard 0 would never reach shard 1 running
/// in the same process.
#[derive(Default)]
struct LocalTopicBus {
    topics: std::sync::Mutex<
        std::collections::HashMap<String, Vec<tokio::sync::mpsc::UnboundedSender<String>>>,
    >,
}

impl LocalTopicBus {
    /// The process-wide bus (one node per process, one bus per node).
    fn shared() -> Arc<Self> {
        static BUS: std::sync::OnceLock<Arc<LocalTopicBus>> = std::sync::OnceLock::new();
        Arc::clone(BUS.get_or_init(|| Arc::new(LocalTopicBus::default())))
    }

    fn subscribe(&self, topic: &str) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(topic.to_string()).or_default().push(tx);
        rx
    }

    fn publish(&self, topic: &str, envelope: &str) {
        let senders = {
            let map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
            map.get(topic).cloned().unwrap_or_default()
        };
        for tx in senders {
            let _ = tx.send(envelope.to_string());
        }
    }
}

/// The real overlay path: infnode pubsub over the QUIC mesh.
///
/// Two delivery paths are used, exactly like the consensus gossip:
///
///  * `pubsub.msg` — a direct PUSH to every peer: the payload lands in the
///    peer's local app subscription for that topic immediately (no mesh hop).
///    This is how a peer hosting the target shard receives the message.
///  * `pubsub.publish` — a mesh RELAY: the peer floods the overlay
///    (TTL-bounded), so a target shard that is not a DIRECT peer of this node
///    still hears the message.
///
/// The same-node bus ([`LocalTopicBus`]) covers the two-shards-in-one-process
/// case the overlay cannot express.
pub struct InfnodeCrossShardPubSub {
    node: Arc<Node>,
    local: Arc<LocalTopicBus>,
    peer_ids_cache: std::sync::OnceLock<Vec<[u8; 20]>>,
}

impl InfnodeCrossShardPubSub {
    pub fn new(node: Arc<Node>) -> Self {
        Self {
            node,
            local: LocalTopicBus::shared(),
            peer_ids_cache: std::sync::OnceLock::new(),
        }
    }

    /// Resolve every configured peer to a node id (cached once all resolve).
    ///
    /// Same rule as the consensus path (`consensus_net::ConsensusNetwork`):
    /// the peer-config PQ id first, the name only as a fallback — name
    /// resolution depends on a registry that fills in asymmetrically, and a
    /// failed lookup would silently publish to nobody.
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        if let Some(ids) = self.peer_ids_cache.get() {
            return ids.clone();
        }
        let mut out = Vec::with_capacity(self.node.cfg.peers.len());
        let mut all_resolved = true;
        for p in &self.node.cfg.peers {
            match p.primary_id().or_else(|_| self.node.resolve(&p.name)) {
                Ok(pid) => out.push(pid),
                Err(e) => {
                    all_resolved = false;
                    tracing::warn!("[cross_shard] cannot resolve peer {}: {e}", p.name);
                }
            }
        }
        if all_resolved {
            let _ = self.peer_ids_cache.set(out.clone());
        }
        out
    }
}

impl CrossShardPubSub for InfnodeCrossShardPubSub {
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let envelope = serde_json::json!({ "topic": topic, "data": data }).to_string();
            // Same-node delivery first: it is the only path that works in a
            // single-process deployment and it costs nothing.
            self.local.publish(topic, &envelope);
            let peers = self.peer_ids();
            if peers.is_empty() {
                // No peer to push to (single-node stand): the message stays
                // local. Not an error.
                return Ok(());
            }
            // A DETERMINISTIC overlay message id: every relay of this payload
            // carries the same id, so the overlay's own dedupe collapses the
            // copies the mesh produces.
            let msg_id = {
                let h = blake3::hash(data.as_bytes());
                u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("8 bytes"))
            };

            let req_timeout = std::time::Duration::from_millis(mesh_send_timeout_ms());
            // (a) DIRECT PUSH to every peer — the payload lands in the peer's
            //     app subscription for that topic, exactly like the consensus
            //     gossip. This is the path that reaches a peer hosting the
            //     target shard, with no mesh hop.
            let payload = envelope.clone().into_bytes();
            let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut handles = Vec::new();
            for pid in peers.iter().copied() {
                let node = Arc::clone(&self.node);
                let payload = payload.clone();
                let delivered = Arc::clone(&delivered);
                handles.push(tokio::spawn(async move {
                    match tokio::time::timeout(
                        req_timeout,
                        node.request_to(pid, "pubsub.msg", payload),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => {
                            if resp.starts_with(b"{\"ok\":false") {
                                tracing::warn!(
                                    "[cross_shard] publish to {} denied: {}",
                                    hex::encode(pid),
                                    String::from_utf8_lossy(&resp)
                                );
                            } else {
                                delivered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                "[cross_shard] publish to {} failed: {e}",
                                hex::encode(pid)
                            );
                        }
                        Err(_) => {
                            tracing::warn!(
                                "[cross_shard] publish to {} timed out after {:?}",
                                hex::encode(pid),
                                req_timeout
                            );
                        }
                    }
                }));
            }

            // (b) MESH RELAY — one publish is enough: the peer floods the
            //     overlay (TTL-bounded), so a target shard that is not a
            //     DIRECT peer of this node still hears the message. One
            //     flood, not one per peer: the relay reaches the whole mesh
            //     anyway, and a flood per peer would multiply the traffic.
            let relay_peer = peers[0];
            {
                let node = Arc::clone(&self.node);
                let relay = serde_json::json!({
                    "topic": topic,
                    "data": data,
                    "msg_id": msg_id,
                    "ttl": CROSS_SHARD_RELAY_TTL,
                })
                .to_string()
                .into_bytes();
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        req_timeout,
                        node.request_to(relay_peer, "pubsub.publish", relay),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => tracing::debug!(
                            "[cross_shard] mesh relay through {} failed: {e}",
                            hex::encode(relay_peer)
                        ),
                        Err(_) => tracing::debug!(
                            "[cross_shard] mesh relay through {} timed out",
                            hex::encode(relay_peer)
                        ),
                    }
                });
            }

            // Bounded join: wait up to 500ms for fast peers and detach slow peers
            // so a stalled peer never blocks the caller.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                futures::future::join_all(handles),
            )
            .await;
            if delivered.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                tracing::debug!(
                    "[cross_shard] cross-shard message reached no peer within join window"
                );
            }
            Ok(())
        })
    }

    fn subscribe<'a>(
        &'a self,
        topic: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<tokio::sync::mpsc::UnboundedReceiver<String>, String>>
    {
        Box::pin(async move {
            // The overlay subscription: the terminal `pubsub.msg` delivery
            // lands in this receiver.
            let mut overlay = self.node.register_app_sub(topic).await;
            // The same-process bus.
            let mut local = self.local.subscribe(topic);
            // Merge both into a single stream.
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        msg = overlay.recv() => match msg {
                            Some(m) => {
                                if tx.send(m).is_err() {
                                    return;
                                }
                            }
                            None => return,
                        },
                        msg = local.recv() => match msg {
                            Some(m) => {
                                if tx.send(m).is_err() {
                                    return;
                                }
                            }
                            None => return,
                        },
                    }
                }
            });
            // Network subscription: every peer relays what it publishes on
            // this topic to us (idempotent, safe to repeat).
            let payload = serde_json::json!({ "topic": topic })
                .to_string()
                .into_bytes();
            let req_timeout = std::time::Duration::from_millis(mesh_send_timeout_ms());
            for pid in self.peer_ids() {
                let node = Arc::clone(&self.node);
                let payload = payload.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        req_timeout,
                        node.request_to(pid, "pubsub.subscribe", payload),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => tracing::debug!(
                            "[cross_shard] subscribe to {} failed: {e}",
                            hex::encode(pid)
                        ),
                        Err(_) => tracing::debug!(
                            "[cross_shard] subscribe to {} timed out",
                            hex::encode(pid)
                        ),
                    }
                });
            }
            Ok(rx)
        })
    }
}

/// Hard per-shard cap on buffered inbound cross-shard gossip messages.
pub const MAX_CROSS_SHARD_INBOX: usize = 4096;

/// Decode one gossip payload into a cross-shard message (fail-closed).
///
/// The payload is the JSON envelope every pubsub implementation produces
/// (`{"topic": ..., "data": <hex>}`); `data` is the bincode message. Anything
/// malformed is DROPPED: a gossip channel is attacker-reachable, so a bad
/// payload must never reach the state machine.
///
/// The decoded message is UNTRUSTED by construction (see
/// [`P2pNetworkAdapter::parse_cross_shard_incoming`]): the `trusted` flag
/// bypasses the Merkle inclusion proof and would mint value.
fn decode_cross_shard_payload(payload: &str) -> Option<CrossShardMessage> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_CROSS_SHARD_MSG {
        return None;
    }
    let msg = P2pNetworkAdapter::parse_cross_shard_incoming(&bytes)?;
    if !msg.verify_msg_id() {
        return None;
    }
    Some(msg)
}

/// Inbound state of a [`P2pCrossShardTransport`].
#[derive(Default)]
struct CrossShardInbox {
    /// Buffered inbound messages per target shard, drained by
    /// [`P2pCrossShardTransport::fetch_inbound`].
    inbox: std::collections::HashMap<ShardId, std::collections::VecDeque<CrossShardMessage>>,
    /// msg_ids already accepted (gossip duplicates are dropped).
    seen: std::collections::HashSet<[u8; 32]>,
    /// Insertion order of `seen`, so the window can be trimmed.
    seen_order: std::collections::VecDeque<[u8; 32]>,
    /// Shards this transport is subscribed to.
    subscribed: std::collections::HashSet<ShardId>,
    /// Streaming listeners (see [`P2pCrossShardTransport::listen_inbound`]).
    listeners:
        std::collections::HashMap<ShardId, tokio::sync::mpsc::UnboundedSender<CrossShardMessage>>,
}

/// Cross-shard transport over the P2P gossip layer.
///
/// This is the variant that crosses MACHINE boundaries. A shard publishes its
/// outbound messages to the gossip topic of the TARGET shard
/// ([`cross_shard_topic`]) and every node hosting that shard receives them
/// over the overlay — no shared process memory, no node-local RocksDB/Sled.
///
/// The topic is EPOCH-SCOPED, so two chains running side by side never see
/// each other's cross-shard traffic.
///
/// Two inbound APIs, one queue per shard:
///  * [`Self::listen_inbound`] — a streaming receiver (a consumer that wants
///    messages as they arrive).
///  * [`Self::fetch_inbound`] — a poll (the runtime's propose path, which
///    asks for the pending inbox every round).
///
/// They are mutually exclusive per shard: a message goes to the stream when a
/// listener is registered, and to the buffered inbox otherwise. A dropped
/// listener therefore falls back to the buffered path automatically.
pub struct P2pCrossShardTransport {
    /// The pubsub channel (the overlay in production, the in-memory twin in
    /// tests).
    pubsub: Arc<dyn CrossShardPubSub>,
    /// Chain epoch: every topic this transport uses is scoped by it, so two
    /// chains never share a cross-shard mailbox.
    epoch: String,
    /// Inbound state (inbox, dedupe window, subscriptions, listeners).
    inner: Arc<std::sync::Mutex<CrossShardInbox>>,
}

impl P2pCrossShardTransport {
    /// Build a transport over an arbitrary pubsub channel.
    pub fn new(pubsub: Arc<dyn CrossShardPubSub>, epoch: &str) -> Self {
        Self {
            pubsub,
            epoch: epoch.to_string(),
            inner: Arc::new(std::sync::Mutex::new(CrossShardInbox::default())),
        }
    }

    /// Build a transport over the real overlay, scoped to the adapter's epoch.
    pub fn from_adapter(adapter: &Arc<P2pNetworkAdapter>) -> Self {
        let epoch = adapter.epoch().as_str().to_string();
        let pubsub: Arc<dyn CrossShardPubSub> =
            Arc::new(InfnodeCrossShardPubSub::new(adapter.node.clone()));
        Self::new(pubsub, &epoch)
    }

    /// The chain epoch this transport is scoped to.
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The gossip topic this transport uses for `target_shard`.
    pub fn topic_for(&self, target_shard: ShardId) -> String {
        cross_shard_topic(target_shard, &self.epoch)
    }

    /// Publish `msg` to the gossip topic of its TARGET shard.
    ///
    /// Best-effort, like every gossip send: the payload travels to the peers
    /// hosting that shard. The message is also embedded in the producing
    /// block, so a lost gossip copy is recovered by block propagation.
    pub async fn send_outbound(&self, msg: &CrossShardMessage) -> Result<(), String> {
        let bytes = bincode::serialize(msg)
            .map_err(|e| format!("CrossShardMessage serialize error: {:?}", e))?;
        if bytes.len() > MAX_CROSS_SHARD_MSG {
            return Err(format!(
                "cross-shard message too large: {} bytes (cap {MAX_CROSS_SHARD_MSG})",
                bytes.len()
            ));
        }
        let topic = self.topic_for(msg.target_shard);
        let data = hex::encode(bytes);
        self.pubsub.publish(&topic, &data).await
    }

    /// Subscribe to the topic of `shard_id` and return a receiver of the
    /// inbound messages addressed to that shard.
    ///
    /// Idempotent: subscribing twice returns a second receiver on the SAME
    /// subscription (the overlay subscription itself is made once).
    pub async fn listen_inbound(
        &self,
        shard_id: ShardId,
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<CrossShardMessage>, String> {
        self.ensure_subscribed(shard_id).await?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.listeners.insert(shard_id, tx);
        Ok(rx)
    }

    /// Subscribe to the topic of `shard_id` without consuming the stream.
    ///
    /// Gossip has NO replay: a message published before the subscription is
    /// never delivered. A shard that must not miss traffic therefore
    /// subscribes BEFORE the first message is published.
    pub async fn subscribe(&self, shard_id: ShardId) -> Result<(), String> {
        self.ensure_subscribed(shard_id).await
    }

    /// Drain the buffered inbound messages addressed to `shard_id`.
    ///
    /// Subscribes on first use, so the runtime's poll path works without any
    /// extra wiring.
    pub async fn fetch_inbound(&self, shard_id: ShardId) -> Vec<CrossShardMessage> {
        if let Err(e) = self.ensure_subscribed(shard_id).await {
            tracing::warn!("[cross_shard] subscribe to shard {shard_id} failed: {e}");
            return Vec::new();
        }
        // The raw channel and the inbox are two hops: give the pump task a
        // chance to move a just-delivered payload into the inbox.
        tokio::task::yield_now().await;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .inbox
            .remove(&shard_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Drop the consumed messages from the inbox of `shard_id` (§5 M3 pruning).
    ///
    /// Idempotent, like the other transports: pruning an absent id removes
    /// nothing and still succeeds. Returns how many entries were removed.
    pub async fn prune_consumed(&self, shard_id: ShardId, msg_ids: &[[u8; 32]]) -> usize {
        if msg_ids.is_empty() {
            return 0;
        }
        // The raw channel and the inbox are two hops: give the pump task a
        // chance to move a just-delivered payload into the inbox, so a prune
        // racing a delivery still sees the entry.
        tokio::task::yield_now().await;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(queue) = inner.inbox.get_mut(&shard_id) else {
            return 0;
        };
        let before = queue.len();
        queue.retain(|m| !msg_ids.contains(&m.msg_id));
        before - queue.len()
    }

    /// Make sure the transport is subscribed to the topic of `shard_id`.
    ///
    /// The subscription is claimed BEFORE the await, so two concurrent callers
    /// cannot open two overlay subscriptions for the same shard.
    async fn ensure_subscribed(&self, shard_id: ShardId) -> Result<(), String> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.subscribed.contains(&shard_id) {
                return Ok(());
            }
            inner.subscribed.insert(shard_id);
        }
        let topic = self.topic_for(shard_id);
        let raw = match self.pubsub.subscribe(&topic).await {
            Ok(rx) => rx,
            Err(e) => {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.subscribed.remove(&shard_id);
                return Err(e);
            }
        };
        let mut raw = raw;
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            while let Some(payload) = raw.recv().await {
                if let Some(msg) = decode_cross_shard_payload(&payload) {
                    accept_inbound(&inner, shard_id, msg);
                }
            }
            // The channel closed: the subscription is dead, so a later call
            // may open a new one.
            let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
            g.subscribed.remove(&shard_id);
        });
        Ok(())
    }
}

/// Accept one inbound gossip message (dedupe, address check, delivery).
///
/// SECURITY: the message is forced UNTRUSTED — the `trusted` flag bypasses
/// the Merkle inclusion proof, and a gossip channel is attacker-reachable.
fn accept_inbound(
    inner: &Arc<std::sync::Mutex<CrossShardInbox>>,
    shard_id: ShardId,
    mut msg: CrossShardMessage,
) {
    msg.trusted = false;
    if !msg.verify_msg_id() {
        return;
    }
    // Address check FIRST (security: dedupe poisoning). `msg_id` is
    // `SHA256(source || target || tx_hash || finalized_in_block)` — every field
    // is public — so an attacker who learns a pending transfer can publish the
    // SAME id addressed to another shard. Recording the id before the address
    // check burned it here and the later, correctly addressed copy was dropped
    // as a duplicate (proved by `pentest_network_wave` F2). Only a message this
    // shard will actually consume may enter the dedupe window.
    if !msg.is_inbound_for(shard_id) {
        return;
    }
    let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
    if !g.listeners.contains_key(&shard_id)
        && g.inbox
            .get(&shard_id)
            .is_some_and(|q| q.len() >= MAX_CROSS_SHARD_INBOX)
    {
        return;
    }
    // Gossip duplicates are normal (the mesh relays, a peer may re-publish on
    // reconnect): the first copy wins, the rest are dropped.
    if !g.seen.insert(msg.msg_id) {
        return;
    }
    g.seen_order.push_back(msg.msg_id);
    while g.seen_order.len() > CROSS_SHARD_DEDUPE_WINDOW {
        if let Some(old) = g.seen_order.pop_front() {
            g.seen.remove(&old);
        }
    }
    match g.listeners.get(&shard_id) {
        Some(tx) => match tx.send(msg) {
            Ok(()) => {}
            Err(err) => {
                // The listener is gone: fall back to the buffered inbox (bounded).
                g.listeners.remove(&shard_id);
                let q = g.inbox.entry(shard_id).or_default();
                if q.len() < MAX_CROSS_SHARD_INBOX {
                    q.push_back(err.0);
                }
            }
        },
        None => {
            let q = g.inbox.entry(shard_id).or_default();
            if q.len() < MAX_CROSS_SHARD_INBOX {
                q.push_back(msg);
            }
        }
    }
}

/// Where a shard publishes outbound cross-shard messages and reads inbound ones.
///
/// Three variants, one contract:
///  * `Local` — the in-process mailbox (simulator and tests).
///  * `Node`  — the node-local infnode KV of a live node.
///  * `P2p`   — the P2P GOSSIP layer: the only variant that can move a
///    message between shards running on DIFFERENT physical servers.
///
/// The first two are node-local by construction: two shards can exchange
/// messages only if they run in ONE process behind ONE node. `P2p` is what
/// removes that restriction (see [`P2pCrossShardTransport`]).
pub enum CrossShardTransport {
    Local(Arc<LocalCrossShardKv>),
    Node(Arc<P2pNetworkAdapter>),
    P2p(Arc<P2pCrossShardTransport>),
}

impl CrossShardTransport {
    /// A fresh in-process mailbox, wrapped so several shard runtimes share it.
    pub fn local() -> Arc<Self> {
        Arc::new(Self::Local(Arc::new(LocalCrossShardKv::new())))
    }

    /// Wrap the production infnode adapter as the shared cross-shard transport.
    pub fn from_node(adapter: Arc<P2pNetworkAdapter>) -> Arc<Self> {
        Arc::new(Self::Node(adapter))
    }

    /// Wrap a P2P gossip transport as the shared cross-shard transport.
    ///
    /// Unlike the other two variants this one crosses machine boundaries: a
    /// shard publishes to the gossip topic of its target shard and the node
    /// hosting that shard receives the message over the overlay.
    pub fn p2p(transport: Arc<P2pCrossShardTransport>) -> Arc<Self> {
        Arc::new(Self::P2p(transport))
    }

    pub async fn broadcast_cross_shard(&self, msg: &CrossShardMessage) -> Result<(), String> {
        match self {
            Self::Local(kv) => kv.broadcast_cross_shard(msg).await,
            Self::Node(node) => node.broadcast_cross_shard(msg).await,
            Self::P2p(p2p) => p2p.send_outbound(msg).await,
        }
    }

    pub async fn fetch_cross_shard_inbound(&self, target_shard: u32) -> Vec<CrossShardMessage> {
        match self {
            Self::Local(kv) => kv.fetch_cross_shard_inbound(target_shard).await,
            Self::Node(node) => node.fetch_cross_shard_inbound(target_shard).await,
            Self::P2p(p2p) => p2p.fetch_inbound(target_shard).await,
        }
    }

    /// Drop consumed entries for `target_shard` by `msg_id` (§5 M3 pruning).
    ///
    /// Same contract on both variants: remove the per-message entries the
    /// shard already committed plus their index slots, idempotently. The
    /// `Node` variant rewrites the node-local index without a lock (single
    /// writer per shard: the shard's own apply path), so a concurrent stale
    /// read can only re-add an already-pruned id on the NEXT broadcast, which
    /// the consumed-set filter then skips at proposal time.
    pub async fn prune_consumed(&self, target_shard: u32, msg_ids: &[[u8; 32]]) -> usize {
        match self {
            Self::Local(kv) => kv.prune(target_shard, msg_ids).await,
            Self::Node(node) => node.prune_cross_shard_consumed(target_shard, msg_ids).await,
            Self::P2p(p2p) => p2p.prune_consumed(target_shard, msg_ids).await,
        }
    }
}
