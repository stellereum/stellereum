use super::*;
use axum::{
    extract::{DefaultBodyLimit, Query},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::broadcast;

// the shape both transports emit.
// ===========================================================================

/// Maximum number of live subscriptions on one node (DoS bound).
///
/// A subscription costs one registry entry plus one broadcast slot; an
/// unbounded registry would let a single client exhaust the node's memory.
pub const MAX_SUBSCRIPTIONS: usize = 4096;

/// Maximum number of live subscriptions ONE client may hold (DoS bound).
///
/// The global [`MAX_SUBSCRIPTIONS`] cap bounds the node's memory, but it is
/// GLOBAL: without a per-client cap a single caller can fill the whole
/// registry and deny the service to every other subscriber (audit W6.7).
/// 64 subscriptions per client is far above what a wallet or an indexer
/// needs and far below the global cap.
pub const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 64;

/// A subscription id is 16 random bytes, hex-encoded (32 characters).
pub const SUBSCRIPTION_ID_BYTES: usize = 16;

/// Capacity of the in-process fan-out channel (notifications buffered per
/// transport before the slow consumer is dropped).
pub(super) const STREAM_BROADCAST_CAPACITY: usize = 1024;

/// A subscription created over plain HTTP (no transport attached yet) is
/// swept after this many seconds. Keeps the registry bounded even if a
/// client never unsubscribes. A subscription with a live transport is
/// removed by that transport instead.
pub const SUBSCRIPTION_TTL_SECS: u64 = 3600;

/// What a subscription follows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SubscriptionTopic {
    /// Newly finalized heads of this node's chain (TON `ton_subscribe` to
    /// new blocks, Solana `slotSubscribe`).
    NewHeads,
    /// Transactions included in finalized blocks (Solana `logsSubscribe` for
    /// signatures, EVM `newPendingTransactionFilter` in its confirmed form).
    NewTxs,
    /// Block invalidations: a branch that lost the fork-choice, or a reorg
    /// that rolled a branch back. The blocks named in the signal were NEVER
    /// applied (finality forbids rolling back an applied block), so the
    /// signal tells a subscriber "this block you were told about is not on
    /// the chain" — the honest counterpart of `newHeads`.
    Invalidations,
    /// Contract events, optionally filtered by contract address and topics.
    Events {
        /// Canonical hex (32 bytes) of the contract to watch; `None` = all.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contract: Option<String>,
        /// Event topic ids to watch; empty = all.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        topics: Vec<String>,
    },
}

/// One live subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    /// Hex id (32 characters) handed to the client.
    pub id: String,
    /// What this subscription follows.
    pub topic: SubscriptionTopic,
    /// Unix seconds when the subscription was created.
    pub created_at: u64,
    /// True while a transport (WebSocket / SSE) is streaming this
    /// subscription; such entries are not swept by the TTL.
    #[serde(default)]
    pub attached: bool,
    /// The client that created it (its IP), when the caller was attributed.
    ///
    /// Used for the PER-CLIENT budget (`MAX_SUBSCRIPTIONS_PER_CLIENT`, audit
    /// W6.7) and as the OWNERSHIP check for `stell_unsubscribe` / SSE attach:
    /// the global cap bounds the node's memory, but a single caller could
    /// otherwise take the WHOLE registry and starve every other subscriber.
    /// `None` for a subscription created over a transport that carries no
    /// attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

/// A push notification. This is the exact shape a client receives over
/// WebSocket and over SSE (`data: {"subscription":...,"result":{...}}`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    /// The subscription this notification belongs to.
    pub subscription: String,
    /// The payload: a head, a transaction or a contract event.
    pub result: Value,
}

/// Per-process subscription registry + notification fan-out.
///
/// The registry (`Arc<RwLock<HashMap<String, Subscription>>>`) is the source
/// of truth for "who follows what"; the broadcast channel carries the
/// notifications to the transports.
///
/// The registry uses a *synchronous* `RwLock` on purpose: the publish hook
/// must be callable from the consensus loop without an async runtime and
/// must never block the chain on a slow subscriber (the lock is held for a
/// map lookup only, never across an `.await`).
pub struct SubscriptionHub {
    /// Live subscriptions of this process, keyed by subscription id.
    pub registry: Arc<std::sync::RwLock<HashMap<String, Subscription>>>,
    /// Fan-out channel to the transports.
    tx: broadcast::Sender<Notification>,
    /// Rolling window of the block invalidation signals this node published
    /// (oldest first).
    ///
    /// A node that reorgs (or that loses a fork) must be able to TELL: the
    /// blocks it named earlier are not on the chain. The window is the
    /// read-side of that promise (`stell_getInvalidations`), the fan-out is
    /// the push side (`stell_subscribe` with the `invalidations` topic).
    invalidations:
        Arc<std::sync::Mutex<std::collections::VecDeque<crate::chain::InvalidationSignal>>>,
}

impl std::fmt::Debug for SubscriptionHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionHub")
            .field("live", &self.len())
            .finish()
    }
}

impl SubscriptionHub {
    /// A fresh, empty hub.
    ///
    /// The process-wide instance is [`hub()`]; tests build isolated hubs so
    /// their traffic cannot cross-talk with another test's subscriptions.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(STREAM_BROADCAST_CAPACITY);
        SubscriptionHub {
            registry: Arc::new(std::sync::RwLock::new(HashMap::new())),
            tx,
            invalidations: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    /// Record an invalidation signal in the rolling window (oldest first).
    ///
    /// The window is bounded: the oldest signal is dropped once the cap is
    /// reached, so a fork storm cannot grow the node's memory without
    /// limit.
    pub fn record_invalidation(&self, signal: crate::chain::InvalidationSignal) {
        if signal.is_empty() {
            return;
        }
        let mut win = self.invalidations.lock().unwrap_or_else(|e| e.into_inner());
        win.push_back(signal);
        while win.len() > crate::chain::MAX_INVALIDATION_WINDOW {
            win.pop_front();
        }
    }

    /// The recent invalidation signals (oldest first), at most `limit` of
    /// them (0 = every signal in the window).
    pub fn recent_invalidations(&self, limit: usize) -> Vec<crate::chain::InvalidationSignal> {
        let win = self.invalidations.lock().unwrap_or_else(|e| e.into_inner());
        let all: Vec<crate::chain::InvalidationSignal> = win.iter().cloned().collect();
        if limit == 0 || all.len() <= limit {
            return all;
        }
        all[all.len() - limit..].to_vec()
    }

    /// Drop every recorded invalidation (tests / diagnostics).
    pub fn clear_invalidations(&self) {
        let mut win = self.invalidations.lock().unwrap_or_else(|e| e.into_inner());
        win.clear();
    }

    /// Register a subscription and return its id.
    pub fn subscribe(&self, topic: SubscriptionTopic) -> Result<String, String> {
        self.subscribe_for(topic, None)
    }

    /// Register a subscription on behalf of an attributed client.
    ///
    /// `client` is the caller's identity (its IP) when the transport could
    /// attribute it. The PER-CLIENT budget (`MAX_SUBSCRIPTIONS_PER_CLIENT`)
    /// is enforced here: the global cap bounds the node's MEMORY, but
    /// without a per-client cap one caller could fill the whole registry
    /// and deny the service to everyone else (audit W6.7).
    pub fn subscribe_for(
        &self,
        topic: SubscriptionTopic,
        client: Option<&str>,
    ) -> Result<String, String> {
        let now = unix_now_secs();
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        // Sweep detached leftovers (a client that subscribed over plain HTTP
        // and never came back). Attached subscriptions live with their
        // transport.
        reg.retain(|_, s| s.attached || now.saturating_sub(s.created_at) < SUBSCRIPTION_TTL_SECS);
        if reg.len() >= MAX_SUBSCRIPTIONS {
            return Err(format!(
                "subscription limit reached ({MAX_SUBSCRIPTIONS} live subscriptions)"
            ));
        }
        if let Some(client) = client {
            let held = reg
                .values()
                .filter(|s| s.client.as_deref() == Some(client))
                .count();
            if held >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                return Err(format!(
                    "per-client subscription limit reached ({MAX_SUBSCRIPTIONS_PER_CLIENT} live subscriptions for this client)"
                ));
            }
        }
        let id = loop {
            let candidate = random_subscription_id();
            if !reg.contains_key(&candidate) {
                break candidate;
            }
        };
        reg.insert(
            id.clone(),
            Subscription {
                id: id.clone(),
                topic,
                created_at: now,
                attached: false,
                client: client.map(|c| c.to_string()),
            },
        );
        Ok(id)
    }

    /// Remove a subscription. Returns true when it existed.
    ///
    /// INTERNAL use only (transport guards and tests). Network callers must
    /// use [`Self::unsubscribe_for`] so an id from the listing cannot tear
    /// down another client's stream.
    pub fn unsubscribe(&self, id: &str) -> bool {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        reg.remove(id).is_some()
    }

    /// Remove a subscription only when `client` owns it.
    ///
    /// Subscription ids are returned to their creator, but the registry also
    /// serves a diagnostics listing; binding unsubscribe to the recorded
    /// owner means an id learned out of band (or from a previous listing) is
    /// not a bearer capability for another client's stream.
    pub fn unsubscribe_for(&self, id: &str, client: Option<&str>) -> bool {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        match reg.get(id) {
            Some(s) if s.client.as_deref() == client => reg.remove(id).is_some(),
            _ => false,
        }
    }

    /// The subscription with this id, if it is still live.
    pub fn get(&self, id: &str) -> Option<Subscription> {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        reg.get(id).cloned()
    }

    /// Every live subscription (sorted by id).
    pub fn list(&self) -> Vec<Subscription> {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<Subscription> = reg.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// The live subscriptions owned by `client` (sorted by id).
    ///
    /// The public listing is scoped: ids are capabilities for
    /// `stell_unsubscribe`/SSE attach, so handing every id to every caller
    /// would let any client cancel every stream.
    pub fn list_for(&self, client: Option<&str>) -> Vec<Subscription> {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<Subscription> = reg
            .values()
            .filter(|s| s.client.as_deref() == client)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Number of live subscriptions.
    pub fn len(&self) -> usize {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        reg.len()
    }

    /// True when no subscription is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mark a subscription as served by a live transport (so the TTL sweep
    /// leaves it alone).
    pub fn attach(&self, id: &str) {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.get_mut(id) {
            s.attached = true;
        }
    }

    /// Attach a transport only when `client` owns the subscription.
    /// Returns false for an unknown id or a different owner (no id oracle).
    pub fn attach_for(&self, id: &str, client: Option<&str>) -> bool {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        match reg.get_mut(id) {
            Some(s) if s.client.as_deref() == client => {
                s.attached = true;
                true
            }
            _ => false,
        }
    }

    /// Mark a subscription as no longer served by a transport.
    pub fn detach(&self, id: &str) {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.get_mut(id) {
            s.attached = false;
        }
    }

    /// Subscribe to the notification fan-out (one receiver per transport).
    pub fn notifications(&self) -> broadcast::Receiver<Notification> {
        self.tx.subscribe()
    }

    /// Address a payload to every subscription whose filter matches `event`.
    ///
    /// Returns the number of subscriptions addressed. Delivery itself is
    /// best-effort: a transport that is not attached (or is lagging) simply
    /// misses the notification -- the fan-out never blocks the publisher.
    pub fn publish(&self, event: &SubscriptionTopic, result: Value) -> usize {
        let targets: Vec<String> = {
            let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
            reg.values()
                .filter(|s| topic_matches(&s.topic, event))
                .map(|s| s.id.clone())
                .collect()
        };
        let addressed = targets.len();
        for id in targets {
            // `send` fails only when nobody listens; the registry entry
            // survives, so a client may attach a transport later.
            let _ = self.tx.send(Notification {
                subscription: id,
                result: result.clone(),
            });
        }
        addressed
    }
}

impl Default for SubscriptionHub {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide subscription hub.
pub(super) static SUBSCRIPTION_HUB: std::sync::OnceLock<Arc<SubscriptionHub>> =
    std::sync::OnceLock::new();

/// The process-wide subscription hub.
///
/// Per-process by design: a subscription follows THIS node's finalized chain,
/// so it must not be shared between nodes, and a restart drops every
/// subscriber (clients reconnect and resubscribe).
pub fn hub() -> &'static Arc<SubscriptionHub> {
    // A test that needs an ISOLATED hub (one whose invalidation window it
    // can assert on without seeing the traffic of the tests running next to
    // it) installs one for its own thread; the production build has no such
    // override and always returns the process-wide hub.
    #[cfg(test)]
    if let Some(h) = test_hub_override() {
        return h;
    }
    SUBSCRIPTION_HUB.get_or_init(|| Arc::new(SubscriptionHub::new()))
}

#[cfg(test)]
thread_local! {
    /// The hub this thread sees instead of the process-wide one, if any.
    ///
    /// The hub is ONE PER PROCESS, so a test that asserts on its contents
    /// (the invalidation window) would otherwise see whatever the tests
    /// running next to it published. A test that needs its own hub installs
    /// one here; every [`hub`] call on this thread then returns it.
    static TEST_HUB_OVERRIDE: std::cell::RefCell<Option<&'static Arc<SubscriptionHub>>> =
        const { std::cell::RefCell::new(None) };
}

/// The per-test hub installed on this thread, if any.
#[cfg(test)]
pub(super) fn test_hub_override() -> Option<&'static Arc<SubscriptionHub>> {
    TEST_HUB_OVERRIDE.with(|o| *o.borrow())
}

/// Install a FRESH hub as the one this thread sees, and return it.
///
/// The hub is leaked into a `&'static` because [`hub`] hands out `&'static`
/// references. A test process leaks a handful of hubs — bounded, and the
/// process is short-lived anyway.
#[cfg(test)]
pub(crate) fn install_test_hub() -> &'static Arc<SubscriptionHub> {
    let leaked: &'static Arc<SubscriptionHub> =
        Box::leak(Box::new(Arc::new(SubscriptionHub::new())));
    TEST_HUB_OVERRIDE.with(|o| *o.borrow_mut() = Some(leaked));
    leaked
}

/// Unix seconds (0 when the clock is before the epoch).
pub(super) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh random subscription id: 16 random bytes, hex-encoded.
pub(super) fn random_subscription_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; SUBSCRIPTION_ID_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Normalize a topic id so `1`, `"1"` and `"0x1"` compare equal.
pub(super) fn topic_key(s: &str) -> String {
    let t = s.trim();
    if let Ok(n) = t.parse::<i64>() {
        return n.to_string();
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if let Ok(n) = i64::from_str_radix(h, 16) {
            return n.to_string();
        }
    }
    t.to_lowercase()
}

/// Does a subscriber's filter match an event?
///
/// * `newHeads` matches `newHeads`, `newTxs` matches `newTxs`.
/// * An `events` filter matches when the contract matches (a filter without a
///   contract matches every contract) AND the topic sets intersect (an empty
///   filter matches every topic; `*` / `#` are wildcards).
pub(super) fn topic_matches(filter: &SubscriptionTopic, event: &SubscriptionTopic) -> bool {
    match (filter, event) {
        (SubscriptionTopic::NewHeads, SubscriptionTopic::NewHeads) => true,
        (SubscriptionTopic::NewTxs, SubscriptionTopic::NewTxs) => true,
        (SubscriptionTopic::Invalidations, SubscriptionTopic::Invalidations) => true,
        (
            SubscriptionTopic::Events {
                contract: want_contract,
                topics: want_topics,
            },
            SubscriptionTopic::Events {
                contract: ev_contract,
                topics: ev_topics,
            },
        ) => {
            if let Some(want) = want_contract {
                match ev_contract {
                    Some(have) if have.eq_ignore_ascii_case(want) => {}
                    _ => return false,
                }
            }
            if want_topics.is_empty() {
                return true;
            }
            want_topics.iter().any(|w| {
                let w = w.trim();
                w == "*" || w == "#" || ev_topics.iter().any(|h| topic_key(h) == topic_key(w))
            })
        }
        _ => false,
    }
}

/// Publish a newly finalized head to the `newHeads` subscribers.
///
/// The consensus loop already reaches this through
/// [`RpcState::record_block`] (the finalize and adopt paths both call it), so
/// a subscriber sees every finalized head of this node, in order, tagged
/// `finality: "finalized"`.
pub fn publish_new_head(
    height: u64,
    hash: [u8; 32],
    shard_id: u32,
    tx_count: usize,
    timestamp: u64,
) -> usize {
    hub().publish(
        &SubscriptionTopic::NewHeads,
        json!({
            "height": height,
            "hash": hex::encode(hash),
            "shard_id": shard_id,
            "tx_count": tx_count,
            "timestamp": timestamp,
            "finality": "finalized",
        }),
    )
}

/// Publish an included transaction to the `newTxs` subscribers.
///
/// `status` is `"confirmed"` for an included (successful) transaction and
/// `"failed"` for one that was included but reverted -- an honest report of
/// what the chain decided, never a guess.
pub fn publish_new_tx(
    hash: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    status: &str,
) -> usize {
    hub().publish(
        &SubscriptionTopic::NewTxs,
        json!({
            "hash": hex::encode(hash),
            "from": hex::encode(from),
            "to": hex::encode(to),
            "amount": amount,
            "status": status,
        }),
    )
}

/// Publish a contract event to the `events` subscribers.
///
/// `topics` carries the event topic id (decimal) and `data` the 8-byte
/// big-endian encoding of the event value -- the payload the contract
/// emitted. `block_height` / `tx_hash` locate the event in the chain.
pub fn publish_contract_event(
    event: &crate::contract::ContractEvent,
    block_height: u64,
    tx_hash: [u8; 32],
) -> usize {
    let contract = hex::encode(event.contract);
    let topics = vec![event.topic.to_string()];
    let data = hex::encode((event.value as u64).to_be_bytes());
    hub().publish(
        &SubscriptionTopic::Events {
            contract: Some(contract.clone()),
            topics: topics.clone(),
        },
        json!({
            "contract": contract,
            "topics": topics,
            "data": data,
            "block_height": block_height,
            "tx_hash": hex::encode(tx_hash),
        }),
    )
}

/// The JSON view of an invalidation signal: the orphaned blocks as hex.
///
/// The hashes are hex (not byte arrays) because this is what a client of
/// `stell_getInvalidations` / the `invalidations` subscription reads, and
/// every other hash this RPC serves is hex too.
pub fn invalidation_to_json(signal: &crate::chain::InvalidationSignal) -> Value {
    json!({
        "height": signal.height,
        "reason": signal.reason,
        "orphaned_blocks": signal.orphaned_blocks.iter().map(hex::encode).collect::<Vec<String>>(),
        "orphaned_count": signal.orphaned_blocks.len(),
    })
}

/// Publish a block invalidation: record it in the rolling window and fan it
/// out to the `invalidations` subscribers.
///
/// This is the EVENT HOOK of the reorg path: the consensus runtime calls it
/// (through the invalidation sink) whenever a branch is pruned or a reorg
/// rolls a branch back, so a streaming client learns that the blocks it was
/// told about are not on the chain.
///
/// Returns the number of subscriptions addressed.
pub fn publish_invalidation(signal: &crate::chain::InvalidationSignal) -> usize {
    if signal.is_empty() {
        return 0;
    }
    hub().record_invalidation(signal.clone());
    hub().publish(
        &SubscriptionTopic::Invalidations,
        invalidation_to_json(signal),
    )
}

/// The recent invalidation signals of this node (oldest first), at most
/// `limit` of them (0 = every signal in the window).
pub fn recent_invalidations(limit: usize) -> Vec<crate::chain::InvalidationSignal> {
    hub().recent_invalidations(limit)
}

/// Parse the parameters of `stell_subscribe`.
///
/// Accepted shapes:
/// * `["newHeads"]`
/// * `["newTxs"]`
/// * `["events", { "contract": "<addr>", "topics": ["1", "2"] }]`
/// * `{"type": "events", "contract": "<addr>", "topics": [...]}`
pub(super) fn parse_subscribe_params(params: &Value) -> Result<SubscriptionTopic, String> {
    let (kind, filter) = match params {
        Value::Array(items) => {
            let kind = items
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing subscription type".to_string())?;
            (
                kind.to_string(),
                items.get(1).cloned().unwrap_or(Value::Null),
            )
        }
        Value::Object(_) => {
            let kind = params
                .get("type")
                .or_else(|| params.get("subscription"))
                .or_else(|| params.get("kind"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing subscription type".to_string())?;
            (kind.to_string(), params.clone())
        }
        Value::String(s) => (s.clone(), Value::Null),
        _ => return Err("invalid subscribe parameters".to_string()),
    };
    match kind.trim() {
        "newHeads" | "new_heads" | "heads" => Ok(SubscriptionTopic::NewHeads),
        "newTxs" | "new_txs" | "transactions" => Ok(SubscriptionTopic::NewTxs),
        "invalidations" | "invalidation" | "reorgs" => Ok(SubscriptionTopic::Invalidations),
        "events" | "logs" | "contractEvents" => parse_events_filter(&filter),
        other => Err(format!(
            "unknown subscription type: {}",
            snip_for_error(other)
        )),
    }
}

/// Parse the filter object of an `events` subscription.
///
/// The contract is validated (Stl57 / hex / EVM address) and stored in its
/// canonical 32-byte hex form, so a filter compares byte-exact against the
/// events the chain emits.
/// Maximum event topics one `events` subscription filter may carry.
///
/// Each topic is a heap `String` retained for the subscription's whole
/// lifetime (up to `SUBSCRIPTION_TTL_SECS`) and scanned on every matching
/// notification. An unbounded list inside the 1 MiB body would let one
/// client lodge megabytes per subscription — and, at
/// `MAX_SUBSCRIPTIONS_PER_CLIENT` subscriptions, hundreds of megabytes per
/// IP. 32 is far above legitimate use (a wallet watches a handful of topics)
/// and matches `MAX_PROOF_STORAGE_KEYS`.
pub const MAX_SUBSCRIPTION_TOPICS: usize = 32;

pub(super) fn parse_events_filter(filter: &Value) -> Result<SubscriptionTopic, String> {
    let mut contract = None;
    let mut topics: Vec<String> = Vec::new();
    if let Some(v) = filter.get("contract").or_else(|| filter.get("address")) {
        if !v.is_null() {
            let s = v
                .as_str()
                .ok_or_else(|| "invalid contract parameter: must be a string".to_string())?;
            let addr =
                parse_rpc_address(s).map_err(|e| format!("invalid contract address: {e}"))?;
            contract = Some(hex::encode(addr));
        }
    }
    if let Some(v) = filter.get("topics").or_else(|| filter.get("topic")) {
        match v {
            Value::Null => {}
            Value::Array(items) => {
                if items.len() > MAX_SUBSCRIPTION_TOPICS {
                    return Err(format!(
                        "too many topics: at most {MAX_SUBSCRIPTION_TOPICS} per subscription"
                    ));
                }
                for it in items {
                    let t = match it {
                        Value::String(s) => s.trim().to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => {
                            return Err(
                                "invalid topics entry: expected a string or a number".to_string()
                            )
                        }
                    };
                    if !t.is_empty() {
                        topics.push(t);
                    }
                }
            }
            Value::String(s) => {
                for t in s.split(',') {
                    let t = t.trim();
                    if !t.is_empty() {
                        topics.push(t.to_string());
                    }
                }
                if topics.len() > MAX_SUBSCRIPTION_TOPICS {
                    return Err(format!(
                        "too many topics: at most {MAX_SUBSCRIPTION_TOPICS} per subscription"
                    ));
                }
            }
            _ => return Err("invalid topics parameter".to_string()),
        }
    }
    Ok(SubscriptionTopic::Events { contract, topics })
}

/// Query parameters of the SSE endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct StreamQuery {
    /// Attach to an existing subscription instead of creating one.
    #[serde(alias = "subscription")]
    pub sub_id: Option<String>,
    /// Comma-separated topic kinds: `newHeads`, `newTxs`, `invalidations`,
    /// `events`.
    #[serde(alias = "kind")]
    pub topics: Option<String>,
    /// Contract filter for the `events` topic.
    pub contract: Option<String>,
    /// Comma-separated event topic filter for the `events` topic.
    #[serde(alias = "eventTopics")]
    pub event_topics: Option<String>,
}

/// The topic kinds an SSE stream follows.
pub(super) fn parse_stream_topics(q: &StreamQuery) -> Result<Vec<SubscriptionTopic>, String> {
    let raw = q.topics.as_deref().unwrap_or("newHeads");
    let mut out = Vec::new();
    for kind in raw.split(',') {
        let kind = kind.trim();
        if kind.is_empty() {
            continue;
        }
        let topic = match kind {
            "newHeads" | "new_heads" | "heads" => SubscriptionTopic::NewHeads,
            "newTxs" | "new_txs" | "transactions" => SubscriptionTopic::NewTxs,
            // The invalidation topic: the same set the WebSocket / JSON-RPC
            // `stell_subscribe` knows, so a browser (SSE) and a bot (WS)
            // follow the SAME events.
            "invalidations" | "invalidation" | "reorgs" => SubscriptionTopic::Invalidations,
            "events" | "logs" | "contractEvents" => {
                let mut filter = serde_json::Map::new();
                if let Some(c) = q.contract.as_deref() {
                    filter.insert("contract".to_string(), Value::String(c.to_string()));
                }
                if let Some(t) = q.event_topics.as_deref() {
                    filter.insert("topics".to_string(), Value::String(t.to_string()));
                }
                parse_events_filter(&Value::Object(filter))?
            }
            other => {
                return Err(format!(
                    "unknown subscription type: {}",
                    snip_for_error(other)
                ))
            }
        };
        out.push(topic);
    }
    if out.is_empty() {
        out.push(SubscriptionTopic::NewHeads);
    }
    Ok(out)
}

/// Removes the subscriptions a transport owns when the transport goes away.
pub(super) struct SubscriptionGuard {
    /// Subscriptions this transport created (removed on drop).
    owned: Vec<String>,
    /// Subscriptions this transport attached to (detached on drop).
    attached: Vec<String>,
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        for id in self.owned.drain(..) {
            hub().unsubscribe(&id);
        }
        for id in self.attached.drain(..) {
            hub().detach(&id);
        }
    }
}

/// The SSE body type: a stream of `text/event-stream` frames.
pub(super) type SseStream = std::pin::Pin<
    Box<
        dyn futures::stream::Stream<
                Item = Result<axum::response::sse::Event, std::convert::Infallible>,
            > + Send,
    >,
>;

/// Seconds of inactivity after which an SSE stream is reaped.
///
/// Mirrors [`WS_IDLE_TIMEOUT_SECS`]: a stream that forwards no event for this
/// long is closed, its owned subscriptions are dropped (via the
/// `SubscriptionGuard`) and the HTTP connection — hence the gateway
/// concurrency permit — is released. Without this, 512 one-request SSE
/// clients could hold every permit forever (audit F12). Keep-alive comment
/// frames are transport-level and do NOT count as stream activity; only a
/// forwarded notification resets the window.
pub const SSE_IDLE_TIMEOUT_SECS: u64 = 300;

/// Env override for [`SSE_IDLE_TIMEOUT_SECS`] (seconds; 0/unparsable keeps
/// the default) — the same shape as the WS reaper's window.
pub const SSE_IDLE_TIMEOUT_ENV: &str = "STELL_SSE_IDLE_TIMEOUT_SECS";

// Compile-time shape of the SSE bound (fail the build, not a test, if a
// future edit inverts it).
pub(super) const _: () = assert!(SSE_IDLE_TIMEOUT_SECS > 0);

/// Test-only override of [`SSE_IDLE_TIMEOUT_SECS`] (0 = const/env default).
pub(super) static SSE_IDLE_TIMEOUT_OVERRIDE_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Set the SSE idle timeout for tests (0 restores the configured default).
/// Absent from production builds (`any(test, debug_assertions)` only).
#[cfg(any(test, debug_assertions))]
pub fn set_sse_idle_timeout_for_tests(secs: u64) {
    SSE_IDLE_TIMEOUT_OVERRIDE_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

/// Effective SSE idle timeout: test override, else `STELL_SSE_IDLE_TIMEOUT_SECS`,
/// else the const default.
pub(super) fn sse_idle_timeout() -> std::time::Duration {
    let ov = SSE_IDLE_TIMEOUT_OVERRIDE_SECS.load(std::sync::atomic::Ordering::Relaxed);
    if ov != 0 {
        return std::time::Duration::from_secs(ov);
    }
    idle_timeout_from_env(SSE_IDLE_TIMEOUT_ENV)
        .unwrap_or_else(|| std::time::Duration::from_secs(SSE_IDLE_TIMEOUT_SECS))
}

/// Parse a positive seconds value from `name` (None when unset/garbage/zero).
fn idle_timeout_from_env(name: &str) -> Option<std::time::Duration> {
    std::env::var(name)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|s| *s > 0)
        .map(std::time::Duration::from_secs)
}

/// SSE transport: the same notifications as the WebSocket, framed as
/// `text/event-stream` (`data: {"subscription":...,"result":{...}}\n\n`).
///
/// The stream follows the subscription(s) named by `?sub_id=` (an existing
/// subscription) or creates them from `?topics=newHeads,newTxs,invalidations,events`
/// (+ `?contract=`, `?event_topics=`). The ids of the subscriptions it
/// serves are returned in the `x-stell-subscription-id` header.
///
/// Idle clients are reaped: no forwarded event for [`SSE_IDLE_TIMEOUT_SECS`]
/// (or `STELL_SSE_IDLE_TIMEOUT_SECS`) ends the stream and releases the
/// connection/permit, matching the WS idle rule.
///
/// Public: the gateway mounts the very same handler on `/events`.
pub async fn sse_handler(
    headers: axum::http::HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Query(q): Query<StreamQuery>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let hub = hub();
    // Subscribe to the fan-out BEFORE creating the subscription: a
    // notification published between the two would otherwise be lost.
    let rx = hub.notifications();
    let mut ids: Vec<String> = Vec::new();
    let mut owned: Vec<String> = Vec::new();
    let mut attached: Vec<String> = Vec::new();
    let peer_ip = peer.map(|axum::extract::ConnectInfo(addr)| {
        crate::client_ip::resolve_client_ip(&headers, addr.ip()).addr
    });
    let client = peer_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| LOCAL_SUBSCRIBER_ID.to_string());

    if let Some(want) = q.sub_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        // Attach is owner-bound: the id (and the events on it) belongs to the
        // client that created it. An unknown id and another client's id are
        // indistinguishable (404), so the endpoint is not an id oracle.
        if hub.attach_for(want, Some(client.as_str())) {
            attached.push(want.to_string());
            ids.push(want.to_string());
        } else {
            return Err(axum::http::StatusCode::NOT_FOUND);
        }
    } else {
        let topics = match parse_stream_topics(&q) {
            Ok(t) => t,
            Err(_) => return Err(axum::http::StatusCode::BAD_REQUEST),
        };
        for topic in topics {
            match hub.subscribe_for(topic, Some(client.as_str())) {
                Ok(id) => {
                    hub.attach(&id);
                    owned.push(id.clone());
                    ids.push(id);
                }
                Err(e) => {
                    for id in owned {
                        hub.unsubscribe(&id);
                    }
                    return Err(if e.contains("per-client") {
                        axum::http::StatusCode::TOO_MANY_REQUESTS
                    } else {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    });
                }
            }
        }
    }

    let id_set: HashSet<String> = ids.iter().cloned().collect();
    let guard = SubscriptionGuard { owned, attached };
    let idle = sse_idle_timeout();
    let stream = futures::stream::unfold(
        (rx, id_set, guard, tokio::time::Instant::now() + idle, idle),
        |(mut rx, ids, guard, deadline, idle)| async move {
            loop {
                // Idle reap (audit F12): no forwarded event within the window
                // ends the stream. Transport keep-alive frames are generated
                // by the `Sse` wrapper and deliberately do not reset this.
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Err(_elapsed) => {
                        tracing::debug!(
                            idle_secs = idle.as_secs(),
                            "SSE stream idle past the reap window; closing"
                        );
                        return None;
                    }
                    Ok(Ok(note)) => {
                        if ids.contains(&note.subscription) {
                            let payload =
                                serde_json::to_string(&note).unwrap_or_else(|_| "{}".to_string());
                            let ev = axum::response::sse::Event::default().data(payload);
                            let next_deadline = tokio::time::Instant::now() + idle;
                            return Some((Ok(ev), (rx, ids, guard, next_deadline, idle)));
                        }
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                        tracing::warn!(skipped, "SSE subscriber lagged behind the stream fan-out");
                        continue;
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                }
            }
        },
    );
    let sse = axum::response::sse::Sse::new(Box::pin(stream) as SseStream).keep_alive(
        axum::response::sse::KeepAlive::new().interval(std::time::Duration::from_secs(15)),
    );
    let mut resp = sse.into_response();
    if !ids.is_empty() {
        if let Ok(v) = axum::http::HeaderValue::from_str(&ids.join(",")) {
            resp.headers_mut().insert("x-stell-subscription-id", v);
        }
    }
    Ok(resp)
}

// ===========================================================================
// WS PER-MESSAGE EXPENSIVE-READ BUDGET (audit residual: post-upgrade flood)
//
// The HTTP upgrade request passes the gateway/standalone per-IP limiters
// ONCE, at upgrade time. After that the socket is a loop: every text frame
// dispatches a full JSON-RPC call with NO per-message cost check, so one
// socket could flood expensive reads at frame speed. `dispatch` already caps
// `stell_estimateFee` and per-client subscriptions per message, but the proof
// endpoints and `stell_runGetMethod` had NO per-message cap on ANY transport
// beyond the coarse per-request middleware (which a WS socket bypasses after
// the upgrade).
//
// Heavy methods therefore draw from their OWN per-IP budget on EVERY WS
// message, mirroring the `estimate_fee_budget` pattern (same `RateLimiter`,
// same per-IP fixed window — NOT a redesign). Which methods qualify was
// decided by code reading (cost per call):
//   * `stell_estimateFee` — clones the WHOLE engine state and runs a full
//     SVM execution on the clone (`handle_estimate_fee`); the most expensive
//     read on the node.
//   * `stell_subscribe` — each creation fills the process-wide registry
//     (`subscribe_for`, bounded by `MAX_SUBSCRIPTIONS`); an uncapped socket
//     could eat the node's whole subscription budget.
//   * `stell_getProof` — trie walk plus proof build plus self-verification,
//     up to `MAX_PROOF_STORAGE_KEYS` (32) storage paths (`handle_get_proof`).
//   * `stell_getArchiveProof` — rebuilds a proof from the durable snapshot
//     history (`handle_get_archive_proof`).
//   * `stell_getBalanceSpv` / `stell_tokenBalanceSpv` — account/token proof
//     generation against the live trie.
//   * `stell_runGetMethod` — executes contract code (`run_get_method[_typed]`,
//     fuel-bounded but still execution).
// Cheap lookups (balance, headers, chain id, events, ...) draw nothing.
//
// Over budget → a clean `-32000` error frame on the SAME socket (the socket
// stays open: the existing policy never drops on rate-limit, it answers).
// Keyed by peer IP with the static [`LOCAL_BUCKET_IP`] fallback, so
// unattributed sockets are throttled, never exempt.
// ===========================================================================

/// Default per-IP budget for expensive WS reads (per second).
///
/// 5/s mirrors the estimate-fee budget: a wallet/indexer sends heavy reads
/// rarely, while a flood must not pin the node. Override with
/// `STELL_WS_EXPENSIVE_READ_RATE_LIMIT`. Local policy, not consensus: nodes
/// MAY differ.
pub const WS_EXPENSIVE_READ_RATE_LIMIT_DEFAULT: u32 = 5;

/// Effective WS expensive-read per-IP budget.
pub(super) fn ws_expensive_read_rate_limit() -> u32 {
    std::env::var("STELL_WS_EXPENSIVE_READ_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(WS_EXPENSIVE_READ_RATE_LIMIT_DEFAULT)
}

/// The process-wide WS expensive-read limiter.
pub(super) fn ws_expensive_read_budget() -> &'static crate::explorer::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| crate::explorer::RateLimiter::new(ws_expensive_read_rate_limit()))
}

/// True when a WS message's method is an expensive read (see above).
pub(super) fn is_ws_expensive_method(method: &str) -> bool {
    matches!(
        method,
        "stell_estimateFee"
            | "stell_subscribe"
            | "stell_getProof"
            | "stell_getArchiveProof"
            | "stell_getBalanceSpv"
            | "stell_tokenBalanceSpv"
            | "stell_runGetMethod"
    )
}

// ===========================================================================
// WS HARDENING (audit residual, rpc 8.5->9.0): bounded subscriptions per
// connection, size-capped messages, per-message general budget symmetric to
// the HTTP transport limiters, and stale-connection reaping with a live
// connection count. Message/subscription bounds are consts; only the two
// IDLE WINDOWS (WS + SSE) are env-tunable (`STELL_WS_IDLE_TIMEOUT_SECS`,
// `STELL_SSE_IDLE_TIMEOUT_SECS`, same shape/default).
// ===========================================================================

/// Maximum bytes of one WS message (text or binary, UTF-8 decoded length).
///
/// Mirrors [`MAX_RPC_BODY`] (1 MiB): the HTTP extractor refuses bodies above
/// it before buffering, and a WS frame must not smuggle a bigger request
/// past the upgrade. Oversize frames are refused with a clean `-32600` error
/// frame on the SAME socket (the socket stays open: answers, never drops).
pub const WS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum subscriptions owned by ONE WebSocket connection (DoS bound).
///
/// The global [`MAX_SUBSCRIPTIONS`] cap bounds the node's memory and the
/// per-client ([`MAX_SUBSCRIPTIONS_PER_CLIENT`]) cap bounds one IP, but
/// neither bounds one SOCKET: without this a single connection could hold 64
/// live subscriptions and pin 64 broadcast slots. 16 is far above what one
/// socket needs (heads + txs + invalidations + a handful of event filters)
/// and far below either global cap. The 17th `stell_subscribe` on a full
/// connection is refused fail-closed (`-32000`); the socket stays open.
pub const WS_MAX_SUBS_PER_CONNECTION: usize = 16;

/// Default per-IP budget for ordinary WS messages (per second).
///
/// Symmetric to [`STANDALONE_RATE_LIMIT_DEFAULT`] (300/s): the HTTP upgrade
/// passes the transport limiter once, so every frame after it draws from
/// THIS budget with the same per-IP fixed-window shape instead. Heavy
/// methods draw from the expensive-read budget ON TOP (see above), exactly
/// like an HTTP client sits under both the transport limiter and the
/// `stell_estimateFee` budget. Over budget is a clean `-32000` error frame;
/// the socket stays open.
pub const WS_GENERAL_RATE_LIMIT_DEFAULT: u32 = 300;

/// The process-wide WS general limiter (mirrors `estimate_fee_budget`).
pub(super) fn ws_general_budget() -> &'static crate::explorer::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| crate::explorer::RateLimiter::new(WS_GENERAL_RATE_LIMIT_DEFAULT))
}

/// Live WebSocket sessions on this node (incremented on upgrade, decremented
/// when the session ends for ANY reason: close, error, or idle reap).
///
/// The reaping test and operators use this to prove no connection leaks:
/// after every client goes away the count returns to its baseline.
pub(super) static WS_LIVE_CONNECTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Number of currently live WebSocket sessions (see above).
pub fn ws_live_connections() -> usize {
    WS_LIVE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// RAII guard: the session counts as live until this drops.
pub(super) struct WsLiveGuard;

impl WsLiveGuard {
    fn new() -> Self {
        WS_LIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        WsLiveGuard
    }
}

impl Drop for WsLiveGuard {
    fn drop(&mut self) {
        WS_LIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Seconds of total inactivity after which a WS session is reaped.
///
/// A connection that sees neither a client frame NOR a forwarded
/// notification for this long is stale (a dead peer whose FIN never
/// arrived): the session breaks out of its select loop, drops its owned
/// subscriptions, and the live count drops, so a dead peer cannot leak a
/// registry entry or a counter slot.
pub const WS_IDLE_TIMEOUT_SECS: u64 = 300;

/// Env override for [`WS_IDLE_TIMEOUT_SECS`] (seconds; 0/unparsable keeps the
/// default). Same shape as [`SSE_IDLE_TIMEOUT_ENV`]: local policy, not
/// consensus — nodes MAY differ.
pub const WS_IDLE_TIMEOUT_ENV: &str = "STELL_WS_IDLE_TIMEOUT_SECS";

// Compile-time shape of the WS hardening bounds (fail the build, not a
// test, if a future edit inverts them).
pub(super) const _: () = assert!(WS_MAX_SUBS_PER_CONNECTION > 0);
pub(super) const _: () = assert!(WS_MAX_SUBS_PER_CONNECTION <= MAX_SUBSCRIPTIONS_PER_CLIENT);
pub(super) const _: () = assert!(MAX_SUBSCRIPTIONS_PER_CLIENT < MAX_SUBSCRIPTIONS);
pub(super) const _: () = assert!(WS_GENERAL_RATE_LIMIT_DEFAULT > 0);
pub(super) const _: () = assert!(WS_IDLE_TIMEOUT_SECS > 0);

/// Test-only override of [`WS_IDLE_TIMEOUT_SECS`] (0 = use the env/const
/// default).
///
/// Integration tests cannot wait 300 s, so they set a 1 s timeout, prove the
/// reap, and restore 0. Production never touches this override; operators
/// tune the window with `STELL_WS_IDLE_TIMEOUT_SECS`.
pub(super) static WS_IDLE_TIMEOUT_OVERRIDE_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Set the WS idle timeout for tests (0 restores the const default).
/// Absent from production builds (`any(test, debug_assertions)` only).
#[cfg(any(test, debug_assertions))]
pub fn set_ws_idle_timeout_for_tests(secs: u64) {
    WS_IDLE_TIMEOUT_OVERRIDE_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

/// Effective WS idle timeout: test override, else `STELL_WS_IDLE_TIMEOUT_SECS`,
/// else the const default.
pub(super) fn ws_idle_timeout() -> std::time::Duration {
    let ov = WS_IDLE_TIMEOUT_OVERRIDE_SECS.load(std::sync::atomic::Ordering::Relaxed);
    if ov != 0 {
        return std::time::Duration::from_secs(ov);
    }
    idle_timeout_from_env(WS_IDLE_TIMEOUT_ENV)
        .unwrap_or_else(|| std::time::Duration::from_secs(WS_IDLE_TIMEOUT_SECS))
}

// ===========================================================================
// RATE-LIMIT AUDIT TABLE (rpc 9.0): every public method mapped to a bucket.
//
// Buckets (enforcement — see the code cited, not just this comment):
//   * `transport`    — the per-IP transport limiter: standalone 300/s
// Buckets (enforcement — see the code cited, not just this comment):
//   * `transport`    — the per-IP transport limiter, the outer layer EVERY
//     request sits under: standalone 300/s (`standalone_rate_limit`),
//     gateway 30/s (`explorer`), and the WS per-message general budget
//     mirroring standalone (`ws_general_budget`). Every public method draws
//     from it on every transport (WS draws per frame, not just at upgrade).
//   * `expensive`    — the 5/s per-IP estimate-fee budget enforced in
//     `dispatch` (`estimate_fee_budget`) on ALL transports: `stell_estimateFee`.
//   * `expensive-ws` — the 5/s per-IP WS per-message budget
//     (`ws_expensive_read_budget`, `is_ws_expensive_method`): the 7 heavy
//     methods below, ON WS FRAMES ONLY. On HTTP these same methods have no
//     per-method budget beyond `transport`.
//   * `subscription` — the registry caps in `subscribe_for`: global
//     `MAX_SUBSCRIPTIONS` + per-client `MAX_SUBSCRIPTIONS_PER_CLIENT`,
//     plus per-connection `WS_MAX_SUBS_PER_CONNECTION` on WS frames.
//   * `faucet`       — the hourly per-IP throttle + lifetime caps
//     (`Faucet::check_ip_throttle`, `FAUCET_IP_MAX_PER_HOUR`).
//   * `auth`         — `auth_token`-gated when configured (still under
//     `transport` like everything else).
//
// Method -> buckets (mirrored by `rpc_rate_buckets` below; the coverage test
// `rate_bucket_table_covers_every_public_method` asserts every row):
//   transport only (EVM, 36): eth_chainId, net_version, web3_clientVersion,
//     net_listening, net_peerCount, eth_syncing, eth_gasPrice,
//     eth_maxPriorityFeePerGas, eth_estimateGas, eth_feeHistory, eth_getCode,
//     eth_getBalance, eth_getTransactionCount, eth_blockNumber,
//     eth_getBlockByNumber, eth_getBlockByHash, eth_getTransactionReceipt,
//     eth_getTransactionByHash, eth_getBlockTransactionCountByHash,
//     eth_getBlockTransactionCountByNumber,
//     eth_getTransactionByBlockHashAndIndex,
//     eth_getTransactionByBlockNumberAndIndex, eth_getUncleCountByBlockHash,
//     eth_getUncleCountByBlockNumber, eth_getUncleByBlockHashAndIndex,
//     eth_getUncleByBlockNumberAndIndex, eth_call, eth_newBlockFilter,
//     eth_newPendingTransactionFilter, eth_newFilter, eth_getFilterChanges,
//     eth_getFilterLogs, eth_uninstallFilter, eth_getLogs, eth_getStorageAt,
//     eth_sendRawTransaction.
//   transport only (stell, 53): stell_chainId, stell_nodeId, stell_blockNumber,
//     stell_syncing, stell_getStateRoot, stell_latestBlocks, stell_getShards,
//     stell_getShardTopology, stell_getBlock, stell_getBlockTransactions,
//     stell_epochKey, stell_sendSealedTransaction, stell_mevStats,
//     stell_getBalance, stell_getHistoricalRoot, stell_getFinalizedHeader,
//     stell_getFinalizedCheckpoint, stell_getEpochRoot, stell_bridgeDeposit,
//     stell_bridgeDispute, stell_tokenBalance, stell_tokenSupply,
//     stell_tokenResolve, stell_listTokens, stell_getTransactionReceipt,
//     stell_getEvents, stell_getTransactionStatus, stell_stakeOf,
//     stell_getValidatorStatus, stell_zkmlCapabilities, stell_getValidators,
//     stell_getPqKey, stell_getPqRegistryStatus, stell_proposal,
//     stell_listProposals, stell_governanceParams, stell_mempoolSize,
//     stell_baseFee, stell_verifyMessage, stell_verifyTypedData,
//     stell_sendRawTransaction, stell_pmmState, stell_orderBook,
//     stell_sessionBudget, stell_getContractAbi, stell_verifyContractSource,
//     stell_getContractSource, stell_registerContractSource,
//     stell_getContractReceipt, stell_getInvalidations, stell_invalidationFeed,
//     stell_unsubscribe, stell_getSubscriptions.
//   transport + expensive + expensive-ws (1): stell_estimateFee.
//   transport + expensive-ws (5): stell_getProof, stell_getArchiveProof,
//     stell_getBalanceSpv, stell_tokenBalanceSpv, stell_runGetMethod.
//   transport + expensive-ws + subscription (1): stell_subscribe.
//   transport + faucet (1): stell_faucet.
//   transport + auth (11): stell_mempoolDump, stell_submitProposal, stell_vote,
//     stell_executeProposal, stell_signMessage, stell_signTypedData,
//     stell_deployContract, stell_callContract, stell_submitPriceFeed,
//     stell_pmmBuy, stell_pmmSell.
//   transport only (native namespace, 35, via `is_native_method`):
//     stell_tokenTransfer, stell_tokenBalanceOf, stell_tokenMetadata,
//     stell_tokenAllowance, stell_tokenMint, stell_tokenBurn, stell_tokenApprove,
//     stell_tokenTransferFrom, stell_tokenCreate, stell_stakeBond,
//     stell_stakeUnbond, stell_stakeWithdraw, stell_delegate, stell_undelegate,
//     stell_claimRewards, stell_bridgeDepositPrepare, stell_bridgeWithdraw,
//     stell_bridgeStatus, stell_bridgeAttestStatus, stell_bridgeReleaseEstimate,
//     stell_bridgeDeposits, stell_orderBookPlace, stell_orderBookCancel,
//     stell_orderBookSnapshot, stell_placeOrder, stell_cancelOrder,
//     stell_sessionKeyRegister, stell_sessionKeyRevoke, stell_sessionKeys,
//     stell_oraclePrice, stell_oracleFeeds, stell_nativeApi.
//     (GATE, Ristretto excision: stell_shieldedTransfer,
//     stell_shieldedBalance and stell_unshield were removed with the
//     confidential protocol — no row, no bucket.)
//   (no bucket: unknown method names -> `-32601`; there is no method without
//   a row above.)

/// Buckets rate-limiting a public RPC method (see the audit table above).
///
/// The return is the FULL bucket set: every entry contains `"transport"`
/// (the outer per-IP limiter on every transport), plus the special buckets
/// from the table. Unknown method names map to `&[]` (the `-32601` arm has
/// no bucket). Pure classifier: it drives NO enforcement itself, so HTTP
/// behavior is byte-identical with or without it; the WS path consults it
/// only in comments/tests, enforcement lives in the limiters cited above.
pub fn rpc_rate_buckets(method: &str) -> &'static [&'static str] {
    match method {
        "stell_estimateFee" => &["transport", "expensive", "expensive-ws"],
        "stell_subscribe" => &["transport", "expensive-ws", "subscription"],
        "stell_getProof"
        | "stell_getArchiveProof"
        | "stell_getBalanceSpv"
        | "stell_tokenBalanceSpv"
        | "stell_runGetMethod" => &["transport", "expensive-ws"],
        "stell_faucet" => &["transport", "faucet"],
        "stell_mempoolDump"
        | "stell_submitProposal"
        | "stell_vote"
        | "stell_executeProposal"
        | "stell_signMessage"
        | "stell_signTypedData"
        | "stell_deployContract"
        | "stell_callContract"
        | "stell_submitPriceFeed"
        | "stell_submitPqPriceFeed"
        | "stell_pmmBuy"
        | "stell_pmmSell" => &["transport", "auth"],
        _ if crate::native_api::is_native_method(method) => &["transport"],
        "eth_chainId"
        | "net_version"
        | "web3_clientVersion"
        | "net_listening"
        | "net_peerCount"
        | "eth_syncing"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas"
        | "eth_estimateGas"
        | "eth_feeHistory"
        | "eth_getCode"
        | "eth_getBalance"
        | "eth_getTransactionCount"
        | "eth_blockNumber"
        | "eth_getBlockByNumber"
        | "eth_getBlockByHash"
        | "eth_getTransactionReceipt"
        | "eth_getTransactionByHash"
        | "eth_getBlockTransactionCountByHash"
        | "eth_getBlockTransactionCountByNumber"
        | "eth_getTransactionByBlockHashAndIndex"
        | "eth_getTransactionByBlockNumberAndIndex"
        | "eth_getUncleCountByBlockHash"
        | "eth_getUncleCountByBlockNumber"
        | "eth_getUncleByBlockHashAndIndex"
        | "eth_getUncleByBlockNumberAndIndex"
        | "eth_call"
        | "eth_newBlockFilter"
        | "eth_newPendingTransactionFilter"
        | "eth_newFilter"
        | "eth_getFilterChanges"
        | "eth_getFilterLogs"
        | "eth_uninstallFilter"
        | "eth_getLogs"
        | "eth_getStorageAt"
        | "eth_sendRawTransaction"
        | "stell_chainId"
        | "stell_nodeId"
        | "stell_blockNumber"
        | "stell_syncing"
        | "stell_getStateRoot"
        | "stell_latestBlocks"
        | "stell_getShards"
        | "stell_getShardTopology"
        | "stell_getBlock"
        | "stell_getBlockTransactions"
        | "stell_epochKey"
        | "stell_sendSealedTransaction"
        | "stell_mevStats"
        | "stell_getBalance"
        | "stell_getHistoricalRoot"
        | "stell_getFinalizedHeader"
        | "stell_getFinalizedCheckpoint"
        | "stell_getEpochRoot"
        | "stell_bridgeDeposit"
        | "stell_bridgeDispute"
        | "stell_tokenBalance"
        | "stell_tokenSupply"
        | "stell_tokenResolve"
        | "stell_listTokens"
        | "stell_getTransactionReceipt"
        | "stell_getEvents"
        | "stell_getTransactionStatus"
        | "stell_stakeOf"
        | "stell_getValidatorStatus"
        | "stell_zkmlCapabilities"
        | "stell_getValidators"
        | "stell_getPqKey"
        | "stell_getPqRegistryStatus"
        | "stell_proposal"
        | "stell_listProposals"
        | "stell_governanceParams"
        | "stell_mempoolSize"
        | "stell_baseFee"
        | "stell_verifyMessage"
        | "stell_verifyTypedData"
        | "stell_sendRawTransaction"
        | "stell_pmmState"
        | "stell_orderBook"
        | "stell_sessionBudget"
        | "stell_getContractAbi"
        | "stell_verifyContractSource"
        | "stell_getContractSource"
        | "stell_registerContractSource"
        | "stell_getContractReceipt"
        | "stell_getInvalidations"
        | "stell_invalidationFeed"
        | "stell_unsubscribe"
        | "stell_getSubscriptions" => &["transport"],
        _ => &[],
    }
}

/// WebSocket transport: JSON-RPC requests in, subscription notifications out.
///
/// The socket speaks the SAME JSON-RPC dialect as the HTTP endpoint, so a
/// client may call `stell_subscribe` / `stell_unsubscribe` (and any read
/// method) over the socket. Notifications are pushed as
/// `{"subscription": <id>, "result": {...}}`.
///
/// The credentials of the upgrade request are honoured exactly like on the
/// HTTP endpoint: the API token in the headers gates the same methods, and
/// the peer address feeds the per-IP limits. A WebSocket must never be a way
/// AROUND the auth gate.
pub(super) async fn ws_handler(
    headers: axum::http::HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    ws: axum::extract::ws::WebSocketUpgrade,
    axum::extract::State(st): axum::extract::State<Arc<RpcState>>,
) -> axum::response::Response {
    let header_token = extract_header_token(&headers).map(|s| s.to_string());
    let peer_ip = peer.map(|axum::extract::ConnectInfo(addr)| {
        crate::client_ip::resolve_client_ip(&headers, addr.ip()).addr
    });
    ws.on_upgrade(move |socket| handle_ws(socket, st, header_token, peer_ip))
}

/// One event of the WebSocket select loop.
pub(super) enum WsIn {
    /// A message from the client.
    Message(Option<Result<axum::extract::ws::Message, axum::Error>>),
    /// A notification from the fan-out.
    Note(Result<Notification, broadcast::error::RecvError>),
}

/// The WebSocket session: serve one client until it goes away.
pub(super) async fn handle_ws(
    socket: axum::extract::ws::WebSocket,
    st: Arc<RpcState>,
    header_token: Option<String>,
    peer_ip: Option<std::net::IpAddr>,
) {
    handle_ws_with_timeout(socket, st, header_token, peer_ip, ws_idle_timeout()).await
}

/// The WebSocket session with an explicit idle timeout (the const
/// [`WS_IDLE_TIMEOUT_SECS`] in production; short in tests via
/// [`set_ws_idle_timeout_for_tests`]).
///
/// Reaping: any loop iteration without a client frame AND without a
/// forwarded notification lets the deadline fire, and the session ends —
/// owned subscriptions are removed and the live count drops, so a dead peer
/// cannot leak a registry entry or a counter slot.
pub(super) async fn handle_ws_with_timeout(
    mut socket: axum::extract::ws::WebSocket,
    st: Arc<RpcState>,
    header_token: Option<String>,
    peer_ip: Option<std::net::IpAddr>,
    idle_timeout: std::time::Duration,
) {
    let _live = WsLiveGuard::new();
    let mut rx = hub().notifications();
    // Subscriptions created ON THIS connection (the client may also subscribe
    // over plain HTTP; those are not pushed here).
    let mut owned: HashSet<String> = HashSet::new();
    // Any select arm that fires counts as activity; only the deadline firing
    // means the connection has been fully idle for `idle_timeout`.
    let mut deadline = tokio::time::Instant::now() + idle_timeout;
    loop {
        // The receive future borrows the socket; the send happens after the
        // select, so the two never overlap.
        let next = tokio::select! {
            biased;
            msg = socket.recv() => WsIn::Message(msg),
            note = rx.recv() => WsIn::Note(note),
            _ = tokio::time::sleep_until(deadline) => break,
        };
        deadline = tokio::time::Instant::now() + idle_timeout;
        match next {
            WsIn::Message(Some(Ok(m))) => match m {
                axum::extract::ws::Message::Text(t) => {
                    if !ws_handle_text(
                        &st,
                        &t,
                        &mut owned,
                        &mut socket,
                        header_token.as_deref(),
                        peer_ip,
                    )
                    .await
                    {
                        break;
                    }
                }
                axum::extract::ws::Message::Binary(b) => {
                    let t = String::from_utf8_lossy(&b).to_string();
                    if !ws_handle_text(
                        &st,
                        &t,
                        &mut owned,
                        &mut socket,
                        header_token.as_deref(),
                        peer_ip,
                    )
                    .await
                    {
                        break;
                    }
                }
                axum::extract::ws::Message::Ping(p) => {
                    if socket
                        .send(axum::extract::ws::Message::Pong(p))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                axum::extract::ws::Message::Pong(_) => {}
                axum::extract::ws::Message::Close(_) => break,
            },
            WsIn::Message(Some(Err(_))) | WsIn::Message(None) => break,
            WsIn::Note(Ok(note)) => {
                if !owned.contains(&note.subscription) {
                    continue;
                }
                // A subscription dropped over plain HTTP stops the push.
                if hub().get(&note.subscription).is_none() {
                    owned.remove(&note.subscription);
                    continue;
                }
                let payload = serde_json::to_string(&note).unwrap_or_else(|_| "{}".to_string());
                if socket
                    .send(axum::extract::ws::Message::Text(payload))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            WsIn::Note(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                tracing::warn!(
                    skipped,
                    "WebSocket subscriber lagged behind the stream fan-out"
                );
                continue;
            }
            WsIn::Note(Err(broadcast::error::RecvError::Closed)) => break,
        }
    }
    // The connection's own subscriptions die with the connection.
    for id in owned {
        hub().unsubscribe(&id);
    }
}

/// Serve one JSON-RPC request received over the WebSocket.
///
/// Returns false when the socket must be closed.
pub(super) async fn ws_handle_text(
    st: &Arc<RpcState>,
    text: &str,
    owned: &mut HashSet<String>,
    socket: &mut axum::extract::ws::WebSocket,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> bool {
    // SIZE CAP (see `WS_MAX_MESSAGE_BYTES`): mirror the HTTP body limit
    // BEFORE parsing, so a giant frame cannot buy a giant JSON build.
    if text.len() > WS_MAX_MESSAGE_BYTES {
        let resp = err(
            Value::Null,
            -32600,
            format!(
                "request too large: {} bytes (max {WS_MAX_MESSAGE_BYTES})",
                text.len()
            ),
        );
        let out = serde_json::to_string(&resp.0).unwrap_or_default();
        return socket
            .send(axum::extract::ws::Message::Text(out))
            .await
            .is_ok();
    }
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            let resp = RpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(RpcError {
                    code: -32700,
                    message: format!("parse error: {e}"),
                    data: None,
                }),
            };
            let out = serde_json::to_string(&resp).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    };
    let req: RpcRequest = match serde_json::from_value(parsed) {
        Ok(r) => r,
        Err(e) => {
            let resp = RpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(RpcError {
                    code: -32600,
                    message: format!("invalid request: {e}"),
                    data: None,
                }),
            };
            let out = serde_json::to_string(&resp).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    };
    let id = req.id.clone().unwrap_or(Value::Null);
    let method = req.method.clone();
    let params = req.params.clone();
    // PER-MESSAGE GENERAL BUDGET (see `WS_GENERAL_RATE_LIMIT_DEFAULT`): the
    // upgrade request was checked once, but every ordinary frame after it
    // draws from the per-IP general budget — the same outer layer an HTTP
    // request sits under. Over budget → a clean error frame on the SAME
    // socket (the socket stays open: answers, never drops, on rate-limit).
    {
        let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
        if !ws_general_budget().check(ip) {
            let denied = err(
                id,
                -32000,
                "general budget exhausted for this IP on this socket (retry shortly)",
            );
            let out = serde_json::to_string(&denied.0).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    }
    // PER-MESSAGE expensive-read budget (see above): the upgrade request was
    // checked once, but every heavy frame after it draws from the per-IP WS
    // budget. Over budget → a clean error frame on the SAME socket (the
    // socket stays open: answers, never drops, on rate-limit).
    if is_ws_expensive_method(&method) {
        let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
        if !ws_expensive_read_budget().check(ip) {
            let denied = err(
                id,
                -32000,
                "expensive-read budget exhausted for this IP on this socket (retry shortly)",
            );
            let out = serde_json::to_string(&denied.0).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    }
    // PER-CONNECTION SUBSCRIPTION CAP (see `WS_MAX_SUBS_PER_CONNECTION`):
    // fail-closed BEFORE dispatch so a refused subscribe consumes neither a
    // registry slot nor any per-client budget. Over cap → a clean `-32000`
    // error frame; the socket stays open. On success the new id is tracked
    // below so it is pushed to this socket and dies with it.
    if method == "stell_subscribe" && owned.len() >= WS_MAX_SUBS_PER_CONNECTION {
        let denied = err(
            id,
            -32000,
            format!(
                "per-connection subscription limit reached ({WS_MAX_SUBS_PER_CONNECTION} live subscriptions on this connection)"
            ),
        );
        let out = serde_json::to_string(&denied.0).unwrap_or_default();
        return socket
            .send(axum::extract::ws::Message::Text(out))
            .await
            .is_ok();
    }
    let resp = dispatch(st.as_ref(), id, &method, &params, header_token, peer_ip).await;
    // Track the subscriptions this connection owns: they are pushed to it and
    // they die with it.
    if method == "stell_subscribe" {
        if let Some(sid) = resp.0.result.as_ref().and_then(|v| v.as_str()) {
            owned.insert(sid.to_string());
            hub().attach(sid);
        }
    } else if method == "stell_unsubscribe" {
        if let Some(sid) = params.get(0).and_then(|v| v.as_str()) {
            owned.remove(sid);
        }
    }
    let out = serde_json::to_string(&resp.0).unwrap_or_default();
    socket
        .send(axum::extract::ws::Message::Text(out))
        .await
        .is_ok()
}
/// axum handler for the JSON-RPC endpoint.
///
/// Single calls answer with the single response object, byte-identical to
/// before. Batch arrays answer with the response ARRAY (one entry per
/// non-notification call, request order); a batch that is invalid AS A WHOLE
/// (empty, too many items, too many bytes) is refused with the single
/// `-32600` error object, and an all-notification batch gets `204 No
/// Content` (there is nothing to answer, per spec).
pub(super) async fn rpc_handler(
    axum::extract::State(st): axum::extract::State<Arc<RpcState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if body.len() > MAX_RPC_BODY {
        return err(Value::Null, -32600, "request too large").into_response();
    }
    // A credential in a header rather than in the body, so a client can keep it out
    // of its request logs. `Authorization: Bearer <t>` / `Token <t>`, or the
    // explicit `X-Api-Key` / `X-Stell-Token`.
    let header_token = extract_header_token(&headers);
    // Support both single and batch requests.
    let first: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return err(Value::Null, -32700, format!("parse error: {e}")).into_response(),
    };
    // Real client IP for per-IP faucet throttling: proxy headers only when
    // the TCP peer is a trusted proxy (STELL_TRUSTED_PROXY_CIDRS,
    // loopback-only by default — see crate::client_ip); otherwise the peer.
    // Without this every client behind nginx/Cloudflare shared one bucket.
    let peer_ip = Some(crate::client_ip::resolve_client_ip(&headers, addr.ip()).addr);
    if let Some(arr) = first.as_array() {
        let raw_len = body.len();
        match handle_rpc_batch_call(&st, arr, raw_len, header_token, peer_ip).await {
            Ok(responses) => {
                if responses.is_empty() {
                    // All-notification batch: nothing to answer (JSON-RPC 2.0:
                    // "the Server MUST NOT return an empty array").
                    return axum::http::StatusCode::NO_CONTENT.into_response();
                }
                return axum::Json(responses).into_response();
            }
            Err(refused) => return axum::Json(refused).into_response(),
        }
    }

    let req: RpcRequest = match serde_json::from_value(first) {
        Ok(r) => r,
        Err(e) => return err(Value::Null, -32600, format!("invalid request: {e}")).into_response(),
    };
    let id = req.id.unwrap_or(Value::Null);
    dispatch(&st, id, &req.method, &req.params, header_token, peer_ip)
        .await
        .into_response()
}

/// Pull a token out of the conventional auth headers, if one is present.
pub(crate) fn extract_header_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    for name in ["x-api-key", "x-stell-token"] {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    for prefix in ["Bearer ", "Stell ", "Token "] {
        if let Some(rest) = auth.strip_prefix(prefix) {
            let rest = rest.trim();
            if !rest.is_empty() {
                return Some(rest);
            }
        }
    }
    None
}

/// Build the RPC router (no rate limit here: the gateway nests this router
/// under its own limiter, and tests serve it directly busting any static
/// budget — the standalone server adds the limiter in `serve`).
pub fn router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/", post(rpc_handler))
        // WebSocket transport of the streaming subscriptions: JSON-RPC in,
        // `{"subscription":...,"result":...}` notifications out.
        .route("/ws", get(ws_handler))
        // SSE fallback of the same notifications (`text/event-stream`).
        .route("/events", get(sse_handler))
        // Reject oversized bodies at the extractor, before the body is buffered
        // into memory. The in-handler `MAX_RPC_BODY` check stays as a
        // defense-in-depth for callers that bypass this layer.
        .layer(DefaultBodyLimit::max(MAX_RPC_BODY))
        .with_state(state)
}

/// Per-IP fixed-window limiter for the standalone RPC (see `router`).
/// Budget from `STELL_STANDALONE_RATE_LIMIT` (default 300/s): the 30/s
/// gateway default throttled legitimate single-host bots/harnesses (audit:
/// speed tests — 61x 429 on a 122 tx/s localhost blast). 300/s still stops
/// floods cold while letting real clients through; loopback is NOT exempt
/// (a local flood is still a flood). Legacy `STELL_RPC_RATE_LIMIT_PER_SEC`
/// is still honored when the new name is unset.
pub(super) static STANDALONE_LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> =
    std::sync::OnceLock::new();

/// Default per-IP budget for the standalone RPC (see above). Default 300;
/// override with `STELL_STANDALONE_RATE_LIMIT`. Per-node abuse guard, not
/// consensus — nodes MAY differ.
pub const STANDALONE_RATE_LIMIT_DEFAULT: u32 = 300;

/// Effective standalone-RPC per-IP budget (`STELL_STANDALONE_RATE_LIMIT`,
/// default 300; legacy `STELL_RPC_RATE_LIMIT_PER_SEC` honored as fallback).
pub(super) fn standalone_limit_per_sec() -> u32 {
    std::env::var("STELL_STANDALONE_RATE_LIMIT")
        .ok()
        .or_else(|| std::env::var("STELL_RPC_RATE_LIMIT_PER_SEC").ok())
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(STANDALONE_RATE_LIMIT_DEFAULT)
}

pub(super) async fn standalone_rate_limit(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let limiter = STANDALONE_LIMITER
        .get_or_init(|| crate::explorer::RateLimiter::new(standalone_limit_per_sec()));
    // Real client IP behind a trusted proxy (see crate::client_ip); without
    // this every client behind nginx/Cloudflare shared the 300/s bucket.
    let client = crate::client_ip::resolve_client_ip(req.headers(), addr.ip()).addr;
    if limiter.check(client) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded (per-IP budget on standalone RPC)",
        )
            .into_response()
    }
}

/// Spawn the RPC server on `addr` (e.g. "127.0.0.1:8545").
pub async fn serve(addr: &str, state: Arc<RpcState>) -> anyhow::Result<()> {
    // N-02 fail-LOUD: governance writes and contract previews now require a
    // valid token on EVERY bind (no loopback escape), so a node started
    // without `STELL_RPC_AUTH_TOKEN` refuses those methods outright. Still
    // starts (proxied/dev setups may set the token later), but screams at
    // startup so a missing token is never mistaken for an open dev node.
    if state.auth_token.as_ref().is_none_or(|t| t.is_empty()) {
        let msg = format!(
            "[security] JSON-RPC on {addr} with NO STELL_RPC_AUTH_TOKEN: \
             stell_submitProposal / stell_vote / stell_executeProposal and the \
             stell_deployContract / stell_callContract previews are REFUSED \
             (fail-closed on every bind, loopback included). Set \
             STELL_RPC_AUTH_TOKEN to serve them."
        );
        eprintln!("{msg}");
        tracing::warn!("{msg}");
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // The gateway (:8080) has its own limiter; the standalone RPC (:8545)
    // used to have NONE while being the port compose publishes (audit
    // 2026-10-06). Same 30/s/IP budget here. Plus a request timeout and a
    // concurrency cap so slow-loris / hung bodies cannot hold the server.
    let app = router(state).layer(
        tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(standalone_rate_limit))
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async { axum::http::StatusCode::REQUEST_TIMEOUT },
            ))
            .layer(tower::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(30),
            ))
            .layer(tower::limit::ConcurrencyLimitLayer::new(512)),
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
