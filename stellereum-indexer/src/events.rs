//! Contract events for the explorer: the stored shape, the ABI decoder and
//! the ABI cache.
//!
//! # What an event is here
//!
//! A contract event is a log emitted by a contract during a transaction. The
//! node persists them in the transaction's receipt, so the indexer can pick
//! them up per transaction and store them per contract / per block range.
//!
//! # Decoding
//!
//! An event is only useful if a reader can tell WHAT it means. Stellereum
//! contracts carry a typed ABI manifest (committed to the state trie and
//! served by `stell_getContractAbi`), and that manifest names the event and
//! types every one of its fields. When the ABI is known, the event is
//! DECODED: its topic and data values become named fields
//! (`{"topics": {"from": "0x…"}, "data": {"amount": "1000"}}`).
//!
//! When the ABI is NOT known (no manifest attached, or the indexer has not
//! fetched it yet) the event is still stored and still served — as its raw
//! parts, never as an opaque blob and never as a guess.
//!
//! # The legacy event shape
//!
//! The native VM emits `host.emit(contract, topic, value)`: a contract
//! address, an integer topic id and one integer value. The decoder accepts
//! that shape as well as the richer typed one, and the numeric topic id is
//! resolved against the contract's ABI event list (the id is the index of the
//! event in the manifest).

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::RwLock;

use stellereum::contract_abi::{AbiEvent, AbiType, ContractAbi};

/// Normalize an address for storage and lookup: lowercase hex, no `0x`.
///
/// The indexer stores addresses in one canonical form so that `0xABC…`,
/// `abc…` and `0xabc…` all hit the same row.
pub fn normalize_address(addr: &str) -> String {
    let clean = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .unwrap_or(addr);
    clean.trim().to_lowercase()
}

/// One contract event as the node reports it inside a receipt.
///
/// Both shapes are accepted: the typed one (`topic0` / `topics` / `data`) and
/// the legacy native one (`topic` / `value`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawEvent {
    /// The emitting contract.
    #[serde(default)]
    pub contract: String,
    /// The event signature word (32 bytes, hex) when the node reports one.
    #[serde(default)]
    pub topic0: Option<String>,
    /// The indexed fields, in order.
    #[serde(default)]
    pub topics: Vec<Value>,
    /// The non-indexed fields.
    #[serde(default)]
    pub data: Option<Value>,
    /// The legacy numeric topic id.
    #[serde(default)]
    pub topic: Option<i64>,
    /// The legacy single value.
    #[serde(default)]
    pub value: Option<i64>,
    /// The event name, when the node reports one.
    #[serde(default)]
    pub event_name: Option<String>,
}

/// Parse one event out of a receipt's `events` entry.
pub fn event_from_json(v: &Value) -> Option<RawEvent> {
    let obj = v.as_object()?;
    let contract = obj
        .get("contract")
        .or_else(|| obj.get("address"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    if contract.is_empty() {
        return None;
    }
    Some(RawEvent {
        contract,
        topic0: obj
            .get("topic0")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string()),
        topics: obj
            .get("topics")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default(),
        data: obj.get("data").cloned(),
        topic: obj.get("topic").and_then(|t| t.as_i64()),
        value: obj.get("value").and_then(|t| t.as_i64()),
        event_name: obj
            .get("event_name")
            .or_else(|| obj.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string()),
    })
}

/// The decoded form of an event.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedEvent {
    /// The event signature word (hex, `0x` prefixed) or `""` when unknown.
    pub topic0: String,
    /// The indexed fields (raw values).
    pub topics: Vec<Value>,
    /// The non-indexed fields (raw value).
    pub data: Value,
    /// The event name, when the ABI resolved it.
    pub event_name: Option<String>,
    /// The NAMED fields, when the ABI resolved it.
    pub args: Option<Value>,
}

/// Decode one event against a contract's ABI.
///
/// `abi` is `None` when the contract has no manifest (or the indexer has not
/// fetched it): the event is then returned with its raw parts and no named
/// fields — never with invented ones.
pub fn decode_event(abi: Option<&ContractAbi>, raw: &RawEvent) -> DecodedEvent {
    // ---- topic0 ----
    let topic0 = match raw.topic0.as_ref() {
        Some(t) if !t.trim().is_empty() => normalize_hex_word(t),
        _ => match raw.topic {
            Some(t) => format!("0x{:064x}", t as u64),
            None => String::new(),
        },
    };

    // ---- raw parts ----
    let topics = raw.topics.clone();
    let data = match raw.data.clone() {
        Some(d) => d,
        None => match raw.value {
            Some(v) => json!({ "value": v }),
            None => Value::Null,
        },
    };

    // ---- resolve the ABI event ----
    let abi_event: Option<&AbiEvent> = abi.and_then(|a| resolve_abi_event(a, raw, &topics, &data));

    let (event_name, args) = match abi_event {
        Some(e) => {
            let topic_fields = decode_topics(e, raw, &topics);
            let data_fields = decode_data(e, raw, &data);
            (
                Some(e.name.clone()),
                Some(json!({ "topics": topic_fields, "data": data_fields })),
            )
        }
        None => (raw.event_name.clone(), None),
    };

    DecodedEvent {
        topic0,
        topics,
        data,
        event_name,
        args,
    }
}

/// Find the ABI event an emitted event refers to.
///
/// Three ways, in order of certainty:
///
/// 1. **by name** — the node named the event;
/// 2. **by the numeric topic id** — the native VM's event id, which is the
///    index of the event in the contract's manifest;
/// 3. **by shape, but only when UNAMBIGUOUS** — the event carries exactly as
///    many indexed and non-indexed fields as one candidate of the manifest.
///    When two candidates fit, the event is NOT decoded: an explorer that
///    guesses which of two events fired is worse than one that says "the
///    manifest does not identify this".
fn resolve_abi_event<'a>(
    abi: &'a ContractAbi,
    raw: &RawEvent,
    topics: &[Value],
    data: &Value,
) -> Option<&'a AbiEvent> {
    if let Some(name) = raw.event_name.as_ref() {
        return abi.event(name);
    }
    if let Some(idx) = raw.topic {
        if idx >= 0 {
            if let Some(e) = abi.events.get(idx as usize) {
                return Some(e);
            }
        }
    }

    let legacy = raw.value.is_some() && topics.is_empty();
    let data_fields = match data {
        Value::Object(m) => Some(m.len()),
        Value::Array(a) => Some(a.len()),
        _ => None,
    };
    let mut candidates: Vec<&AbiEvent> = Vec::new();
    for e in abi.events.iter() {
        let topics_ok = if legacy {
            e.topics.len() <= 1
        } else {
            topics.len() == e.topics.len()
        };
        let data_ok = match data_fields {
            Some(n) if legacy => e.data.len() <= 1 && (n <= 1 || e.data.len() == n),
            Some(n) => n == e.data.len(),
            None => true,
        };
        if topics_ok && data_ok {
            candidates.push(e);
        }
    }
    if candidates.len() == 1 {
        Some(candidates[0])
    } else {
        None
    }
}

/// Decode the indexed fields into named values.
fn decode_topics(e: &AbiEvent, raw: &RawEvent, topics: &[Value]) -> Map<String, Value> {
    let mut out = Map::new();
    for (i, p) in e.topics.iter().enumerate() {
        let value = if let Some(v) = topics.get(i) {
            v.clone()
        } else if e.topics.len() == 1 {
            // The legacy shape carries ONE value; it is the single indexed
            // field when the event declares exactly one.
            match raw.value {
                Some(v) => json!(v),
                None => Value::Null,
            }
        } else {
            Value::Null
        };
        out.insert(p.name.clone(), coerce(&value, p.ty));
    }
    out
}

/// Decode the non-indexed fields into named values.
fn decode_data(e: &AbiEvent, raw: &RawEvent, data: &Value) -> Map<String, Value> {
    let legacy = raw.value.map(|v| json!(v));
    let mut out = Map::new();
    for (i, p) in e.data.iter().enumerate() {
        let direct = match data {
            Value::Object(map) => map.get(&p.name).cloned(),
            Value::Array(items) => items.get(i).cloned(),
            _ => None,
        };
        let value = match direct {
            Some(v) if !v.is_null() => v,
            _ => {
                if e.data.len() == 1 {
                    match &legacy {
                        Some(v) => v.clone(),
                        None => match data {
                            Value::Object(map) => map.get("value").cloned().unwrap_or(Value::Null),
                            _ => Value::Null,
                        },
                    }
                } else {
                    Value::Null
                }
            }
        };
        out.insert(p.name.clone(), coerce(&value, p.ty));
    }
    out
}

/// Coerce a raw value into the type the ABI declares for it.
///
/// A 32-byte word is the canonical carrier: an address becomes a hex string,
/// an integer becomes its numeric value (big-endian), a boolean becomes
/// `true`/`false`, a blob stays hex.
pub fn coerce(v: &Value, ty: AbiType) -> Value {
    match ty {
        AbiType::Address => match v.as_str() {
            Some(s) => Value::String(normalize_hex_word(s)),
            None => v.clone(),
        },
        AbiType::U64 | AbiType::I64 | AbiType::I32 => match v {
            Value::Number(_) => v.clone(),
            Value::String(s) => match word_to_u64(s) {
                Some(n) => json!(n),
                None => match s.trim().parse::<u64>() {
                    Ok(n) => json!(n),
                    Err(_) => Value::String(s.clone()),
                },
            },
            _ => v.clone(),
        },
        AbiType::Bool => match v {
            Value::Bool(_) => v.clone(),
            Value::Number(n) => Value::Bool(n.as_i64().unwrap_or(0) != 0),
            Value::String(s) => match word_to_u64(s) {
                Some(n) => Value::Bool(n != 0),
                None => Value::Bool(s == "true"),
            },
            _ => v.clone(),
        },
        AbiType::Bytes | AbiType::String => match v {
            Value::String(s) => Value::String(s.clone()),
            _ => v.clone(),
        },
    }
}

/// Read a hex word as a big-endian unsigned integer.
///
/// A 32-byte word is the canonical carrier for a scalar: only the LOW 8
/// bytes carry the value, and the upper bytes must be zero — a word whose
/// value does not fit into a `u64` is NOT silently truncated (the raw string
/// is kept instead, so a reader sees the truth).
fn word_to_u64(s: &str) -> Option<u64> {
    let clean = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))?;
    if clean.is_empty() || clean.len() % 2 != 0 || clean.len() > 64 {
        return None;
    }
    let bytes = hex::decode(clean).ok()?;
    if bytes.is_empty() {
        return None;
    }
    if bytes.len() > 8 && bytes[..bytes.len() - 8].iter().any(|b| *b != 0) {
        return None;
    }
    let tail = &bytes[bytes.len().saturating_sub(8)..];
    let mut buf = [0u8; 8];
    buf[8 - tail.len()..].copy_from_slice(tail);
    Some(u64::from_be_bytes(buf))
}

/// Normalize a hex word to a lowercase `0x`-prefixed string.
fn normalize_hex_word(s: &str) -> String {
    let clean = s.trim();
    let body = clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
        .unwrap_or(clean);
    if body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit()) {
        format!("0x{}", body.to_lowercase())
    } else {
        clean.to_string()
    }
}

// ---------------------------------------------------------------------------
// ABI cache
// ---------------------------------------------------------------------------

/// The ABIs the indexer knows about, keyed by contract address.
///
/// The syncer fills it from `stell_getContractAbi` (the ABI is committed to
/// the state trie, so it is the SAME manifest every node serves) and the API
/// reads it to decode events.
#[derive(Default)]
pub struct AbiCache {
    inner: RwLock<HashMap<String, Option<ContractAbi>>>,
}

impl AbiCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The ABI of a contract, if the indexer knows it.
    pub fn get(&self, contract: &str) -> Option<ContractAbi> {
        let key = normalize_address(contract);
        let guard = self.inner.read().ok()?;
        guard.get(&key).cloned().flatten()
    }

    /// Does the indexer know (the ABI of) this contract?
    ///
    /// `true` also for a contract the node answered "no manifest" for, so a
    /// manifest-less contract is asked about ONCE, not once per event.
    pub fn contains(&self, contract: &str) -> bool {
        let key = normalize_address(contract);
        self.inner
            .read()
            .map(|g| g.contains_key(&key))
            .unwrap_or(false)
    }

    /// Remember the ABI of a contract (`None` = "known to have no manifest").
    pub fn put(&self, contract: &str, abi: Option<ContractAbi>) {
        let key = normalize_address(contract);
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(key, abi);
        }
    }

    /// How many contracts the cache knows about.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parse an ABI manifest out of the node's `stell_getContractAbi` answer.
    ///
    /// The answer nests the manifest under `abi`; a bare manifest is accepted
    /// too. A malformed manifest is refused (`None`), never half-applied.
    pub fn parse_abi(answer: &Value) -> Option<ContractAbi> {
        let manifest = match answer.get("abi") {
            // The node answered "this contract has no manifest": that is a
            // KNOWN absence, not a malformed manifest.
            Some(Value::Null) => return None,
            Some(v) => v,
            None => answer,
        };
        if !manifest.is_object() {
            return None;
        }
        let abi = ContractAbi::from_json_value(manifest).ok()?;
        if abi.methods.is_empty() && abi.events.is_empty() {
            return None;
        }
        Some(abi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum::contract_abi::{AbiParam, AbiType};

    fn abi_with_transfer() -> ContractAbi {
        let mut abi = ContractAbi::default();
        abi.add_event(AbiEvent::new(
            "Transfer",
            vec![
                AbiParam::new("from", AbiType::Address),
                AbiParam::new("to", AbiType::Address),
            ],
            vec![AbiParam::new("amount", AbiType::U64)],
        ));
        abi
    }

    #[test]
    fn normalizes_addresses() {
        assert_eq!(normalize_address("0xABC"), "abc");
        assert_eq!(normalize_address("AbC"), "abc");
        assert_eq!(normalize_address("0x"), "");
    }

    #[test]
    fn parses_the_legacy_event_shape() {
        let v = json!({ "contract": "0xAABB", "topic": 3, "value": 42 });
        let e = event_from_json(&v).unwrap();
        assert_eq!(e.contract, "0xAABB");
        assert_eq!(e.topic, Some(3));
        assert_eq!(e.value, Some(42));
    }

    #[test]
    fn parses_the_typed_event_shape() {
        let v = json!({
            "contract": "0xaabb",
            "topic0": "0x11",
            "topics": ["0xaa"],
            "data": { "amount": 5 },
            "event_name": "Transfer",
        });
        let e = event_from_json(&v).unwrap();
        assert_eq!(e.topic0.as_deref(), Some("0x11"));
        assert_eq!(e.topics.len(), 1);
        assert_eq!(e.event_name.as_deref(), Some("Transfer"));
    }

    #[test]
    fn decodes_named_fields_with_the_abi() {
        let abi = abi_with_transfer();
        let raw = RawEvent {
            contract: "0xaa".to_string(),
            topic0: Some("0x".to_string() + &"11".repeat(32)),
            topics: vec![
                json!(format!("0x{}", "aa".repeat(32))),
                json!(format!("0x{}", "bb".repeat(32))),
            ],
            data: Some(json!({ "amount": 1000 })),
            ..Default::default()
        };
        let d = decode_event(Some(&abi), &raw);
        assert_eq!(d.event_name.as_deref(), Some("Transfer"));
        let args = d.args.unwrap();
        assert_eq!(args["topics"]["from"], format!("0x{}", "aa".repeat(32)));
        assert_eq!(args["topics"]["to"], format!("0x{}", "bb".repeat(32)));
        assert_eq!(args["data"]["amount"], 1000);
    }

    #[test]
    fn decodes_the_legacy_shape_by_topic_index() {
        let abi = abi_with_transfer();
        let raw = RawEvent {
            contract: "0xaa".to_string(),
            topic: Some(0),
            value: Some(77),
            ..Default::default()
        };
        let d = decode_event(Some(&abi), &raw);
        assert_eq!(d.event_name.as_deref(), Some("Transfer"));
        // The single legacy value lands on the single data field.
        let args = d.args.unwrap();
        assert_eq!(args["data"]["amount"], 77);
        // topic0 is the numeric topic rendered as a 32-byte word.
        assert_eq!(d.topic0, format!("0x{:064x}", 0));
    }

    #[test]
    fn an_unknown_abi_leaves_the_event_undecoded() {
        let raw = RawEvent {
            contract: "0xaa".to_string(),
            topic0: Some("0x11".to_string()),
            topics: vec![json!("0x22")],
            data: Some(json!({"amount": 1})),
            ..Default::default()
        };
        let d = decode_event(None, &raw);
        assert!(d.args.is_none());
        assert!(d.event_name.is_none());
        // The raw parts survive: the event is never an opaque blob.
        assert_eq!(d.topics.len(), 1);
        assert_eq!(d.data["amount"], 1);
    }

    #[test]
    fn coerces_hex_words_into_typed_values() {
        // A u64 in a 32-byte word: the value sits in the low 8 bytes.
        let word = format!("0x{:064x}", u64::MAX);
        assert_eq!(coerce(&json!(word.clone()), AbiType::U64), json!(u64::MAX));
        assert_eq!(
            coerce(&json!(word.clone()), AbiType::Address),
            json!(word.clone())
        );
        assert_eq!(coerce(&json!(word), AbiType::Bool), json!(true));
        assert_eq!(coerce(&json!("0x01"), AbiType::Bool), json!(true));
        assert_eq!(coerce(&json!("42"), AbiType::U64), json!(42));
        // A word whose value does NOT fit into 64 bits is kept raw instead of
        // being silently truncated.
        let big = format!("0x{}", "ff".repeat(32));
        assert_eq!(coerce(&json!(big), AbiType::U64), json!(big));
    }

    #[test]
    fn the_cache_round_trips_an_abi() {
        let cache = AbiCache::new();
        assert!(cache.is_empty());
        cache.put("0xAA", Some(abi_with_transfer()));
        assert!(cache.get("0xaa").is_some());
        assert!(cache.get("0xbb").is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn parses_an_abi_out_of_the_node_answer() {
        let abi = abi_with_transfer();
        let answer = json!({ "contract": "0xaa", "abi": abi.to_json_value() });
        let parsed = AbiCache::parse_abi(&answer).unwrap();
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].name, "Transfer");
        // A manifest-less answer parses to "no ABI", not to a broken one.
        assert!(AbiCache::parse_abi(&json!({ "abi": Value::Null })).is_none());
    }
}
