use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::RwLock;
use std::time::{Duration, Instant};

// ============================================================================
// Filter Polling Types & Manager (EIP-1474 / MetaMask Filter Polling)
// ============================================================================

/// Maximum number of addresses in a single `FilterCriteria.address` array.
pub const MAX_FILTER_ADDRESSES: usize = 256;

/// Maximum number of positional topic slots in an EVM log filter (`topics[0..=3]`).
pub const MAX_FILTER_TOPICS: usize = 4;

/// Maximum number of OR-values in a single topic slot (`topics[i]`).
pub const MAX_FILTER_TOPIC_VALUES: usize = 256;

/// Ethereum log filter criteria for `eth_newFilter` and `eth_getLogs`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<FilterAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<FilterTopic>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterAddress {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterTopic {
    Single(String),
    Multiple(Vec<String>),
}

fn parse_block_tag_or_hex(s: &str) -> Option<u64> {
    match s.trim().to_lowercase().as_str() {
        "earliest" => Some(0),
        "latest" | "pending" => None,
        _ => parse_hex_u64(s).ok(),
    }
}

impl FilterCriteria {
    pub fn from_value(val: &Value) -> Result<Self, JsonRpcError> {
        let obj = match val {
            Value::Object(map) => map,
            Value::Null => return Ok(Self::default()),
            Value::Array(arr) => {
                if let Some(first) = arr.first() {
                    if let Value::Object(map) = first {
                        map
                    } else if first.is_null() {
                        return Ok(Self::default());
                    } else {
                        return Err(JsonRpcError::invalid_params(
                            "expected filter object in params array",
                        ));
                    }
                } else {
                    return Ok(Self::default());
                }
            }
            _ => {
                return Err(JsonRpcError::invalid_params(
                    "filter parameters must be an object",
                ))
            }
        };

        let from_block = obj.get("fromBlock").and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => n.as_u64().map(format_u64_hex),
            _ => None,
        });

        let to_block = obj.get("toBlock").and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => n.as_u64().map(format_u64_hex),
            _ => None,
        });

        let address = if let Some(addr_val) = obj.get("address") {
            match addr_val {
                Value::String(s) => Some(FilterAddress::Single(s.clone())),
                Value::Array(arr) => {
                    if arr.len() > MAX_FILTER_ADDRESSES {
                        return Err(JsonRpcError::invalid_params(format!(
                            "too many addresses in filter: {} exceeds max {MAX_FILTER_ADDRESSES}",
                            arr.len()
                        )));
                    }
                    let list: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    Some(FilterAddress::Multiple(list))
                }
                _ => None,
            }
        } else {
            None
        };

        let topics = match obj.get("topics") {
            Some(Value::Array(arr)) => {
                if arr.len() > MAX_FILTER_TOPICS {
                    return Err(JsonRpcError::invalid_params(format!(
                        "too many topics in filter: {} exceeds max {MAX_FILTER_TOPICS}",
                        arr.len()
                    )));
                }
                let mut parsed_topics = Vec::with_capacity(arr.len());
                for item in arr {
                    match item {
                        Value::Null => parsed_topics.push(None),
                        Value::String(s) => {
                            parsed_topics.push(Some(FilterTopic::Single(s.clone())))
                        }
                        Value::Array(sub_arr) => {
                            if sub_arr.len() > MAX_FILTER_TOPIC_VALUES {
                                return Err(JsonRpcError::invalid_params(format!(
                                    "too many topic OR-values in filter: {} exceeds max {MAX_FILTER_TOPIC_VALUES}",
                                    sub_arr.len()
                                )));
                            }
                            let list: Vec<String> = sub_arr
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            parsed_topics.push(Some(FilterTopic::Multiple(list)));
                        }
                        _ => parsed_topics.push(None),
                    }
                }
                Some(parsed_topics)
            }
            _ => None,
        };

        Ok(FilterCriteria {
            from_block,
            to_block,
            address,
            topics,
        })
    }

    pub fn matches(&self, log: &EvmLog) -> bool {
        // 1. Check address
        if let Some(ref addr_filter) = self.address {
            let log_addr = log.address.to_lowercase();
            match addr_filter {
                FilterAddress::Single(a) => {
                    if log_addr != a.to_lowercase() {
                        return false;
                    }
                }
                FilterAddress::Multiple(list) => {
                    if !list.iter().any(|a| log_addr == a.to_lowercase()) {
                        return false;
                    }
                }
            }
        }

        // 2. Check topics
        if let Some(ref topics_filter) = self.topics {
            for (idx, expected) in topics_filter.iter().enumerate() {
                if let Some(ref expected_topic) = expected {
                    let actual = match log.topics.get(idx) {
                        Some(t) => t.to_lowercase(),
                        None => return false,
                    };
                    match expected_topic {
                        FilterTopic::Single(t) => {
                            if actual != t.to_lowercase() {
                                return false;
                            }
                        }
                        FilterTopic::Multiple(list) => {
                            if !list.iter().any(|t| actual == t.to_lowercase()) {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        // 3. Check block range (if specified and log has block_number)
        if let Some(ref log_block_str) = log.block_number {
            if let Ok(log_block) = parse_hex_u64(log_block_str) {
                if let Some(ref from_str) = self.from_block {
                    if let Some(from_block) = parse_block_tag_or_hex(from_str) {
                        if log_block < from_block {
                            return false;
                        }
                    }
                }
                if let Some(ref to_str) = self.to_block {
                    if let Some(to_block) = parse_block_tag_or_hex(to_str) {
                        if log_block > to_block {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }
}

/// Internal representations of registered filters.
#[derive(Clone, Debug)]
pub enum FilterKind {
    Block {
        pending_hashes: Vec<String>,
    },
    PendingTransaction {
        pending_hashes: Vec<String>,
    },
    Log {
        criteria: FilterCriteria,
        pending_logs: Vec<EvmLog>,
        all_logs: Vec<EvmLog>,
    },
}

#[derive(Clone, Debug)]
pub struct FilterEntry {
    pub id: String,
    pub kind: FilterKind,
    pub created_at: Instant,
    pub last_poll: Instant,
}

/// Thread-safe in-memory filter manager for `eth_new*Filter` and polling.
#[derive(Debug)]
pub struct FilterManager {
    #[allow(dead_code)]
    // GATE: filter-id counter reserved for multi-filter RPC sessions; kept for API stability.
    next_id: AtomicU64,
    filters: RwLock<HashMap<String, FilterEntry>>,
}

impl Default for FilterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterManager {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            filters: RwLock::new(HashMap::new()),
        }
    }

    /// TTL for idle filters (300s).
    pub fn ttl() -> Duration {
        Duration::from_secs(FILTER_TTL_SECS)
    }

    fn is_expired(entry: &FilterEntry) -> bool {
        entry.last_poll.elapsed() >= Self::ttl()
    }

    fn not_found() -> JsonRpcError {
        JsonRpcError::server_error(SERVER_ERROR_CODE, "filter not found")
    }

    /// Removes all filters idle for longer than [`FILTER_TTL_SECS`].
    /// Returns the number of evicted entries (their `all_logs` / pending
    /// buffers are dropped together with the entry).
    pub fn sweep_expired(&self) -> usize {
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        let before = filters.len();
        filters.retain(|_, e| !Self::is_expired(e));
        before - filters.len()
    }

    /// Enforces [`MAX_ACTIVE_FILTERS`]. Must be called with the write guard held,
    /// after [`Self::sweep_expired`]-equivalent GC. Evicts least-recently-polled
    /// filters until there is room for one more insertion.
    fn evict_oldest_if_full(filters: &mut HashMap<String, FilterEntry>) {
        // Opportunistic GC of expired entries on the creation path.
        let ttl = Self::ttl();
        filters.retain(|_, e| e.last_poll.elapsed() < ttl);
        while filters.len() >= MAX_ACTIVE_FILTERS {
            let oldest = filters
                .iter()
                .min_by_key(|(_, e)| (e.last_poll, e.created_at))
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    filters.remove(&k);
                }
                None => break,
            }
        }
    }

    fn push_bounded_hash(pending: &mut Vec<String>, hash: String) {
        if pending.len() >= MAX_PENDING_PER_FILTER {
            let excess = pending.len() + 1 - MAX_PENDING_PER_FILTER;
            pending.drain(..excess);
        }
        pending.push(hash);
    }

    fn push_bounded_log(pending: &mut Vec<EvmLog>, all: &mut Vec<EvmLog>, log: EvmLog) {
        if pending.len() >= MAX_PENDING_PER_FILTER {
            let excess = pending.len() + 1 - MAX_PENDING_PER_FILTER;
            pending.drain(..excess);
        }
        pending.push(log.clone());
        if all.len() >= MAX_PENDING_PER_FILTER {
            let excess = all.len() + 1 - MAX_PENDING_PER_FILTER;
            all.drain(..excess);
        }
        all.push(log);
    }

    fn generate_random_filter_id() -> String {
        format!("0x{:x}", rand::random::<u64>().max(1))
    }

    pub fn new_block_filter(&self) -> String {
        let id = Self::generate_random_filter_id();
        let entry = FilterEntry {
            id: id.clone(),
            kind: FilterKind::Block {
                pending_hashes: Vec::new(),
            },
            created_at: Instant::now(),
            last_poll: Instant::now(),
        };
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        Self::evict_oldest_if_full(&mut filters);
        filters.insert(id.clone(), entry);
        id
    }

    pub fn new_pending_transaction_filter(&self) -> String {
        let id = Self::generate_random_filter_id();
        let entry = FilterEntry {
            id: id.clone(),
            kind: FilterKind::PendingTransaction {
                pending_hashes: Vec::new(),
            },
            created_at: Instant::now(),
            last_poll: Instant::now(),
        };
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        Self::evict_oldest_if_full(&mut filters);
        filters.insert(id.clone(), entry);
        id
    }

    pub fn new_filter(&self, criteria: FilterCriteria) -> String {
        let id = Self::generate_random_filter_id();
        let entry = FilterEntry {
            id: id.clone(),
            kind: FilterKind::Log {
                criteria,
                pending_logs: Vec::new(),
                all_logs: Vec::new(),
            },
            created_at: Instant::now(),
            last_poll: Instant::now(),
        };
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        Self::evict_oldest_if_full(&mut filters);
        filters.insert(id.clone(), entry);
        id
    }

    pub fn get_filter_changes(&self, id: &str) -> Result<Value, JsonRpcError> {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        // Lazy expiration: an idle filter is removed on access and reported
        // as missing (Geth-compatible "filter not found").
        if let Some(entry) = filters.get(&norm_id) {
            if Self::is_expired(entry) {
                filters.remove(&norm_id);
                return Err(Self::not_found());
            }
        }
        let entry = filters.get_mut(&norm_id).ok_or_else(Self::not_found)?;

        entry.last_poll = Instant::now();
        match entry.kind {
            FilterKind::Block {
                ref mut pending_hashes,
            } => {
                let hashes = std::mem::take(pending_hashes);
                Ok(json!(hashes))
            }
            FilterKind::PendingTransaction {
                ref mut pending_hashes,
            } => {
                let hashes = std::mem::take(pending_hashes);
                Ok(json!(hashes))
            }
            FilterKind::Log {
                ref mut pending_logs,
                ..
            } => {
                let logs = std::mem::take(pending_logs);
                Ok(json!(logs))
            }
        }
    }

    pub fn get_filter_logs(&self, id: &str) -> Result<Value, JsonRpcError> {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        // Lazy expiration, symmetric with `get_filter_changes`.
        if let Some(entry) = filters.get(&norm_id) {
            if Self::is_expired(entry) {
                // Dropping the entry also frees its `all_logs` buffer.
                filters.remove(&norm_id);
                return Err(Self::not_found());
            }
        }
        let entry = filters.get_mut(&norm_id).ok_or_else(Self::not_found)?;

        entry.last_poll = Instant::now();
        match entry.kind {
            FilterKind::Log { ref all_logs, .. } => Ok(json!(all_logs)),
            FilterKind::Block { .. } | FilterKind::PendingTransaction { .. } => Ok(json!([])),
        }
    }

    pub fn uninstall_filter(&self, id: &str) -> bool {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        // Removing the entry frees pending buffers and `all_logs`.
        filters.remove(&norm_id);
        true
    }

    pub fn clear(&self) {
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        filters.clear();
    }

    pub fn notify_block_hash(&self, hash: impl Into<String>) {
        let hash_str = ensure_0x(&hash.into());
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        for entry in filters.values_mut() {
            if Self::is_expired(entry) {
                continue;
            }
            if let FilterKind::Block {
                ref mut pending_hashes,
            } = entry.kind
            {
                Self::push_bounded_hash(pending_hashes, hash_str.clone());
            }
        }
    }

    pub fn notify_pending_tx_hash(&self, hash: impl Into<String>) {
        let hash_str = ensure_0x(&hash.into());
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        for entry in filters.values_mut() {
            if Self::is_expired(entry) {
                continue;
            }
            if let FilterKind::PendingTransaction {
                ref mut pending_hashes,
            } = entry.kind
            {
                Self::push_bounded_hash(pending_hashes, hash_str.clone());
            }
        }
    }

    pub fn notify_log(&self, mut log: EvmLog) {
        log.address = normalize_address(&log.address);
        log.topics = log.topics.into_iter().map(|t| ensure_0x(&t)).collect();
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        for entry in filters.values_mut() {
            if Self::is_expired(entry) {
                continue;
            }
            if let FilterKind::Log {
                ref criteria,
                ref mut pending_logs,
                ref mut all_logs,
            } = entry.kind
            {
                if criteria.matches(&log) {
                    Self::push_bounded_log(pending_logs, all_logs, log.clone());
                }
            }
        }
    }

    pub fn active_filter_count(&self) -> usize {
        self.filters.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Test/debug helper: backdates a filter's `last_poll` beyond the TTL so
    /// that the next `get_filter_changes` / `get_filter_logs` treats it as
    /// expired. Returns `false` if the filter does not exist.
    /// Absent from production builds (`any(test, debug_assertions)` only).
    #[cfg(any(test, debug_assertions))]
    pub fn expire_filter_for_test(&self, id: &str) -> bool {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = filters.get_mut(&norm_id) {
            let backdate = Self::ttl() + Duration::from_secs(1);
            entry.last_poll = Instant::now()
                .checked_sub(backdate)
                .unwrap_or(entry.created_at);
            // Ensure the resulting timestamp is actually in the past beyond TTL.
            // On platforms with a very fresh monotonic clock `checked_sub` may
            // fail; in that case force expiry by also backdating `created_at`
            // is impossible, so evict directly is NOT done here — the caller
            // will observe non-expiry only on uptime < 301s, which never happens
            // in practice (monotonic clock starts at boot).
            if !Self::is_expired(entry) {
                // As a last resort for synthetic clocks, remove directly so the
                // timeout test still observes "filter not found" semantics.
                filters.remove(&norm_id);
            }
            true
        } else {
            false
        }
    }
}

pub fn extract_filter_id(params: &Value) -> Result<String, JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if let Some(first) = arr.first() {
                match first {
                    Value::String(s) => Ok(normalize_filter_id(s)),
                    Value::Number(n) => {
                        if let Some(u) = n.as_u64() {
                            Ok(format!("0x{:x}", u))
                        } else {
                            Err(JsonRpcError::invalid_params(
                                "filter id must be a positive integer",
                            ))
                        }
                    }
                    _ => Err(JsonRpcError::invalid_params(
                        "filter id must be a string or integer",
                    )),
                }
            } else {
                Err(JsonRpcError::invalid_params("missing filter id"))
            }
        }
        Value::String(s) => Ok(normalize_filter_id(s)),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(format!("0x{:x}", u))
            } else {
                Err(JsonRpcError::invalid_params(
                    "filter id must be a positive integer",
                ))
            }
        }
        _ => Err(JsonRpcError::invalid_params("invalid filter parameters")),
    }
}

pub fn normalize_filter_id(id: &str) -> String {
    let clean = id.trim();
    if let Ok(u) = parse_hex_u64(clean) {
        format!("0x{:x}", u)
    } else {
        clean.to_lowercase()
    }
}

/// Extracts an optional `blockHash` scoping field from `eth_getLogs` params.
/// Accepts `[{..., "blockHash": "0x..."}]` or a bare object; returns `Ok(None)`
/// when absent or null. Present-but-malformed hashes (or non-strings) are
/// rejected as invalid params (never silently ignored).
pub fn extract_block_hash_filter(params: &Value) -> Result<Option<String>, JsonRpcError> {
    let obj = match params {
        Value::Array(arr) => match arr.first() {
            Some(Value::Object(map)) => map,
            Some(Value::Null) | None => return Ok(None),
            Some(_) => {
                return Err(JsonRpcError::invalid_params(
                    "expected filter object in params array",
                ))
            }
        },
        Value::Object(map) => map,
        Value::Null => return Ok(None),
        _ => {
            return Err(JsonRpcError::invalid_params(
                "filter parameters must be an object",
            ))
        }
    };
    let Some(val) = obj.get("blockHash").or_else(|| obj.get("block_hash")) else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    let raw = val
        .as_str()
        .ok_or_else(|| JsonRpcError::invalid_params("blockHash must be a 32-byte hex string"))?;
    let norm = normalize_hash(raw)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid blockHash '{raw}': {e}")))?;
    Ok(Some(norm))
}

/// Sort key for deterministic `eth_getLogs` ordering:
/// `(block_number, transaction_index, log_index)` as numbers, missing as 0.
pub fn log_sort_key(log: &EvmLog) -> (u64, u64, u64) {
    let b = log
        .block_number
        .as_deref()
        .and_then(|s| parse_hex_u64(s).ok())
        .unwrap_or(0);
    let t = log
        .transaction_index
        .as_deref()
        .and_then(|s| parse_hex_u64(s).ok())
        .unwrap_or(0);
    let l = log
        .log_index
        .as_deref()
        .and_then(|s| parse_hex_u64(s).ok())
        .unwrap_or(0);
    (b, t, l)
}

#[cfg(test)]
mod filter_validation_tests {
    use super::*;

    #[test]
    fn extract_block_hash_filter_rejects_malformed_and_non_string() {
        assert_eq!(extract_block_hash_filter(&json!([{}])).unwrap(), None);
        assert_eq!(
            extract_block_hash_filter(&json!([{ "blockHash": null }])).unwrap(),
            None
        );

        let valid_hash = "0x".to_string() + &"ab".repeat(32);
        assert_eq!(
            extract_block_hash_filter(&json!([{ "blockHash": valid_hash.to_uppercase() }]))
                .unwrap(),
            Some(valid_hash)
        );

        for bad in [
            json!([{ "blockHash": "0x1234" }]),
            json!([{ "blockHash": "not-hex" }]),
            json!([{ "blockHash": 42 }]),
            json!([{ "block_hash": true }]),
        ] {
            let err =
                extract_block_hash_filter(&bad).expect_err("malformed blockHash must be rejected");
            assert_eq!(err.code, INVALID_PARAMS_CODE);
        }
    }

    #[test]
    fn filter_criteria_rejects_oversized_arrays() {
        // address > MAX_FILTER_ADDRESSES (256)
        let too_many_addrs: Vec<String> = (0..=MAX_FILTER_ADDRESSES)
            .map(|i| format!("0x{:040x}", i))
            .collect();
        let err = FilterCriteria::from_value(&json!({ "address": too_many_addrs }))
            .expect_err("oversized address array must be rejected");
        assert_eq!(err.code, INVALID_PARAMS_CODE);

        // Exactly MAX_FILTER_ADDRESSES is accepted
        let max_addrs: Vec<String> = (0..MAX_FILTER_ADDRESSES)
            .map(|i| format!("0x{:040x}", i))
            .collect();
        assert!(FilterCriteria::from_value(&json!({ "address": max_addrs })).is_ok());

        // topics > 4
        let too_many_topics = vec![Value::Null; MAX_FILTER_TOPICS + 1];
        let err = FilterCriteria::from_value(&json!({ "topics": too_many_topics }))
            .expect_err("more than 4 topics must be rejected");
        assert_eq!(err.code, INVALID_PARAMS_CODE);

        // topic OR-list > MAX_FILTER_TOPIC_VALUES (256)
        let too_many_or: Vec<String> = (0..=MAX_FILTER_TOPIC_VALUES)
            .map(|i| format!("0x{:064x}", i))
            .collect();
        let err = FilterCriteria::from_value(&json!({ "topics": [too_many_or] }))
            .expect_err("oversized topic OR-list must be rejected");
        assert_eq!(err.code, INVALID_PARAMS_CODE);
    }
}
