use super::*;
use crate::network::decode_wire_limited;
use crate::sharding::{ShardId, Transaction};
use crate::state_engine::{token_balance_key, AccountState};
use crate::storage::{STORAGE_HISTORY_MAX_LIMIT, STORAGE_SCAN_HARD_CAP};
use axum::Json;
use serde_json::{json, Value};

pub(super) fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err("expected 32 bytes (64 hex characters)".to_string());
    }
    let b = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
    b.try_into().map_err(|_| "expected 32 bytes".to_string())
}

/// Parse a 32-byte address (accepts `Stl57...` branded addresses as well as `0x`/64-hex).
pub(super) fn parse_addr_or_hash(s: &str) -> Result<[u8; 32], String> {
    crate::address::parse_address(s).map_err(|e| format!("{e}"))
}

/// Extract a transaction hash from the accepted parameter shapes of the
/// receipt/status reads:
/// * `{ "hash": "<hex>" }` (object form)
/// * `"<hex>"` (bare string)
/// * `["<hex>"]` (standard JSON-RPC positional form)
fn tx_hash_param(params: &Value) -> Option<[u8; 32]> {
    params
        .get("hash")
        .and_then(Value::as_str)
        .or_else(|| params.as_str())
        .or_else(|| params.get(0).and_then(Value::as_str))
        .and_then(|s| parse_hash(s).ok())
}

/// Parse the block selector of `stell_getBlock` using the SAME rule set as
/// the `eth_*` adapter: `{"height": <n|tag>}`, a bare number/tag, or a
/// positional array (`[<n|tag>]`). Tags are resolved against the node's tip.
fn stell_block_tag_param(params: &Value) -> Result<crate::evm_adapter::BlockTag, String> {
    use crate::evm_adapter::BlockTag;
    let selector = match params {
        Value::Array(arr) => arr.first().ok_or_else(|| "missing height".to_string())?,
        Value::Object(obj) => obj
            .get("height")
            .or_else(|| obj.get("blockNumber"))
            .or_else(|| obj.get("number"))
            .ok_or_else(|| "missing height".to_string())?,
        Value::String(_) | Value::Number(_) => params,
        _ => return Err("missing height".to_string()),
    };
    BlockTag::parse(selector).map_err(|e| e.message)
}

/// Project an `EvmBlock` from the shared adapter into the compact
/// `stell_getBlock` summary shape (the same shape the recent window and the
/// archive store serve). Used only as a fallback so every read path answers
/// from the same committed source.
fn evm_block_to_stell_summary(
    b: &crate::evm_adapter::EvmBlock,
) -> Option<crate::rpc::BlockSummary> {
    let height = crate::evm_adapter::parse_hex_u64(b.number.as_deref()?).ok()?;
    let hash = b
        .hash
        .as_deref()
        .map(|h| h.strip_prefix("0x").unwrap_or(h).to_string())?;
    let timestamp = crate::evm_adapter::parse_hex_u64(&b.timestamp).ok()?;
    let tx_count = match &b.transactions {
        crate::evm_adapter::BlockTransactions::Hashes(v) => v.len(),
        crate::evm_adapter::BlockTransactions::Full(v) => v.len(),
    };
    Some(crate::rpc::BlockSummary {
        height,
        hash,
        tx_count,
        timestamp,
    })
}

/// The native transaction body behind a receipt, if this node still holds it.
///
/// Receipts filed live carry the bincode bytes; receipts hydrated after a
/// restart do not (`StoredReceipt` has no raw_tx). In that case the committed
/// block body in the archive store is the authoritative source. `None` means
/// this node cannot reconstruct the body — callers must say so instead of
/// synthesising zero-valued fields.
async fn receipt_body_tx(st: &RpcState, r: &TxReceipt) -> Option<Transaction> {
    if let Some(ref raw_hex) = r.raw_tx {
        let stripped = raw_hex
            .strip_prefix("0x")
            .or_else(|| raw_hex.strip_prefix("0X"))
            .unwrap_or(raw_hex);
        if let Ok(bytes) = hex::decode(stripped) {
            if let Ok(tx) = bincode::deserialize::<Transaction>(&bytes) {
                return Some(tx);
            }
        }
    }
    let store = st.archive_store.as_ref()?;
    let block = store.get_block(&r.block_hash).ok().flatten()?;
    block
        .transactions
        .into_iter()
        .find(|tx| tx.compute_tx_hash() == r.tx_hash)
}

/// Parse a 32-byte hex address (with or without 0x).
#[allow(dead_code)]
pub fn parse_addr(s: &str) -> Result<[u8; 32], String> {
    parse_addr_or_hash(s)
}

// ===========================================================================
// W4 E3 — cursor pagination limits (shared by the history / program-account /
// token-account reads; defined in `rpc/cache.rs` next to `MAX_EVENTS_RETURNED`
// and re-exported through the rpc module).
// ===========================================================================

/// The params object of a call: bare object, or the first element of the
/// standard positional array form.
fn params_object(params: &Value) -> &Value {
    if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    }
}

/// `limit` with a default and a hard cap (never 0).
fn page_limit_param(p: &Value, default: usize, max: usize) -> usize {
    p.get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(default)
        .clamp(1, max)
}

fn parse_u64_loose(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?.trim();
    let (radix, digits) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, s),
    };
    u64::from_str_radix(digits, radix).ok()
}

fn parse_i64_loose(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    let s = v.as_str()?.trim();
    let (sign, body) = match s.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, s),
    };
    let (radix, digits) = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, body),
    };
    i64::from_str_radix(digits, radix).ok().map(|n| n * sign)
}

fn optional_u64_param(p: &Value, names: &[&str]) -> Result<Option<u64>, String> {
    for name in names {
        match p.get(*name) {
            None | Some(Value::Null) => continue,
            Some(v) => {
                return parse_u64_loose(v).map(Some).ok_or_else(|| {
                    format!("invalid {name}: expected an unsigned integer or hex string")
                })
            }
        }
    }
    Ok(None)
}

fn optional_i64_param(p: &Value, names: &[&str]) -> Result<Option<i64>, String> {
    for name in names {
        match p.get(*name) {
            None | Some(Value::Null) => continue,
            Some(v) => {
                return parse_i64_loose(v)
                    .map(Some)
                    .ok_or_else(|| format!("invalid {name}: expected an integer or hex string"))
            }
        }
    }
    Ok(None)
}

fn optional_addr_param(p: &Value, name: &str) -> Result<Option<[u8; 32]>, String> {
    match p.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => parse_rpc_address(s)
            .map(Some)
            .map_err(|e| format!("invalid {name}: {e}")),
        Some(_) => Err(format!("invalid {name}: expected a hex/Stl57 string")),
    }
}

fn bool_param(p: &Value, name: &str, default: bool) -> bool {
    p.get(name).and_then(Value::as_bool).unwrap_or(default)
}

/// Rebuild the participant metadata of an in-memory receipt from its raw
/// transaction bytes. Restart-hydrated receipts carry no `raw_tx`, so the
/// participant fields are honestly absent (`None`) there.
fn receipt_history_meta(r: &TxReceipt) -> Option<crate::storage::StoredReceiptMetaV2> {
    let raw = r.raw_tx.as_ref()?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw).ok()?;
    let tx = bincode::deserialize::<Transaction>(&bytes).ok()?;
    Some(crate::storage::StoredReceiptMetaV2 {
        from: tx.from,
        to: tx.to,
        amount: tx.amount,
        shard_id: tx.target_shard,
        // No block timestamp in the in-memory index; the RPC arm fills it
        // from the store header when one is attached.
        timestamp: 0,
    })
}

/// Role test shared by the archive and in-memory history sources.
fn history_role_matches(
    role: crate::storage::HistoryRole,
    addr: &[u8; 32],
    meta: Option<&crate::storage::StoredReceiptMetaV2>,
) -> bool {
    use crate::storage::HistoryRole;
    match role {
        HistoryRole::All => true,
        HistoryRole::Sender => meta.map(|m| m.from == *addr).unwrap_or(false),
        HistoryRole::Recipient => meta.map(|m| m.to == *addr).unwrap_or(false),
    }
}

/// Decode `cursor` for `stell_getAddressHistory`.
fn history_cursor_param(p: &Value) -> Result<Option<crate::storage::HistoryCursor>, String> {
    match p.get("cursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => crate::storage::HistoryCursor::from_hex(s)
            .map(Some)
            .ok_or_else(|| "invalid cursor: expected 12 bytes of hex".to_string()),
        Some(_) => Err("invalid cursor: expected a hex string".to_string()),
    }
}

/// Decode `cursor` for paginated `stell_getEvents`.
fn event_cursor_param(p: &Value) -> Result<Option<crate::storage::EventCursor>, String> {
    match p.get("cursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => crate::storage::EventCursor::from_hex(s)
            .map(Some)
            .ok_or_else(|| "invalid cursor: expected 16 bytes of hex".to_string()),
        Some(_) => Err("invalid cursor: expected a hex string".to_string()),
    }
}

/// `(height, tx_index)` strictly older than `cursor` (tip-first order).
fn older_than_history(
    cursor: Option<crate::storage::HistoryCursor>,
    height: u64,
    tx_index: u32,
) -> bool {
    cursor
        .map(|c| (height, tx_index) < (c.height, c.tx_index))
        .unwrap_or(true)
}

/// `(height, tx_index, log_index)` strictly older than `cursor`.
fn older_than_event(
    cursor: Option<crate::storage::EventCursor>,
    height: u64,
    tx_index: u32,
    log_index: u32,
) -> bool {
    cursor
        .map(|c| (height, tx_index, log_index) < (c.height, c.tx_index, c.log_index))
        .unwrap_or(true)
}

/// One merged event row used by paginated `stell_getEvents`:
/// `(height, tx_index, log_index, tx_hash, topic, value)`.
type EventHistoryRow = (u64, u32, u32, [u8; 32], i64, i64);

/// Parse a single argument value for `stell_runGetMethod` into an `i64`.
pub(super) fn parse_single_getter_arg(val: &Value) -> Result<i64, String> {
    if let Some(n) = val.as_i64() {
        return Ok(n);
    }
    if let Some(u) = val.as_u64() {
        return Ok(u as i64);
    }
    if let Some(b) = val.as_bool() {
        return Ok(if b { 1 } else { 0 });
    }
    if val.is_null() {
        return Ok(0);
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        if let Some(hex_part) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            if hex_part.is_empty() {
                return Ok(0);
            }
            if hex_part.len() <= 16 {
                let n = u64::from_str_radix(hex_part, 16)
                    .map_err(|e| format!("invalid hex argument: {e}"))?;
                return Ok(n as i64);
            } else {
                let bytes =
                    hex::decode(hex_part).map_err(|e| format!("invalid hex argument: {e}"))?;
                if bytes.len() <= 8 {
                    let mut buf = [0u8; 8];
                    buf[8 - bytes.len()..].copy_from_slice(&bytes);
                    return Ok(i64::from_be_bytes(buf));
                } else {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[..8]);
                    return Ok(i64::from_be_bytes(buf));
                }
            }
        }
        if let Ok(n) = trimmed.parse::<i64>() {
            return Ok(n);
        }
        if trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            if trimmed.len() <= 16 {
                let n = u64::from_str_radix(trimmed, 16)
                    .map_err(|e| format!("invalid hex argument: {e}"))?;
                return Ok(n as i64);
            } else if let Ok(bytes) = hex::decode(trimmed) {
                if bytes.len() <= 8 {
                    let mut buf = [0u8; 8];
                    buf[8 - bytes.len()..].copy_from_slice(&bytes);
                    return Ok(i64::from_be_bytes(buf));
                }
            }
        }
        return Err(format!(
            "cannot parse argument into integer: {}",
            snip_for_error(s)
        ));
    }
    Err(format!("unsupported argument type: {val}"))
}

/// Parse `args` field for `stell_runGetMethod`, accepting a JSON array, number, or hex string.
pub(super) fn parse_get_method_args(val: &Value) -> Result<Vec<i64>, String> {
    if val.is_null() {
        return Ok(Vec::new());
    }
    if let Some(arr) = val.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            out.push(parse_single_getter_arg(item)?);
        }
        return Ok(out);
    }
    let arg = parse_single_getter_arg(val)?;
    Ok(vec![arg])
}

pub(super) fn parse_opcode_value(val: &Value) -> Result<crate::svm::OpCode, String> {
    if let Ok(op) = serde_json::from_value::<crate::svm::OpCode>(val.clone()) {
        return Ok(op);
    }
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            match k.as_str() {
                "SysCallTokenTransfer" | "token_transfer" => {
                    let token_id =
                        parse_addr_from_val(v.get("token_id").or_else(|| v.get("token")))?;
                    let to = parse_addr_from_val(v.get("to").or_else(|| v.get("recipient")))?;
                    let amount = v
                        .get("amount")
                        .and_then(|a| {
                            a.as_u64()
                                .or_else(|| a.as_str().and_then(|s| s.parse().ok()))
                        })
                        .unwrap_or(0);
                    return Ok(crate::svm::OpCode::SysCallTokenTransfer {
                        token_id,
                        to,
                        amount,
                    });
                }
                "SysCallCallContract" | "call_contract" => {
                    let contract =
                        parse_addr_from_val(v.get("contract").or_else(|| v.get("address")))?;
                    let method = match v.get("method") {
                        Some(m) if m.is_string() => m.as_str().unwrap().as_bytes().to_vec(),
                        Some(m) if m.is_array() => serde_json::from_value(m.clone())
                            .map_err(|e: serde_json::Error| e.to_string())?,
                        _ => return Err("missing contract method".to_string()),
                    };
                    let arg = if let Some(a) = v.get("arg").or_else(|| v.get("args")) {
                        parse_contract_call_arg(a)?
                    } else {
                        0i64
                    };
                    return Ok(crate::svm::OpCode::SysCallCallContract {
                        contract,
                        method,
                        arg,
                    });
                }
                "SysCallDeployContract" | "deploy_contract" => {
                    let code = match v.get("code") {
                        Some(c) if c.is_string() => {
                            let s = c.as_str().unwrap();
                            let s_clean = s.strip_prefix("0x").unwrap_or(s);
                            hex::decode(s_clean).map_err(|e| e.to_string())?
                        }
                        Some(c) if c.is_array() => serde_json::from_value(c.clone())
                            .map_err(|e: serde_json::Error| e.to_string())?,
                        _ => return Err("missing contract code".to_string()),
                    };
                    return Ok(crate::svm::OpCode::SysCallDeployContract { code });
                }
                _ => {}
            }
        }
    }
    Err(format!(
        "unrecognized opcode format: {}",
        snip_for_error(&format!("{val:?}"))
    ))
}

pub(super) fn parse_estimate_payload(
    p: &Value,
    to_addr: [u8; 32],
) -> Result<Vec<crate::svm::OpCode>, String> {
    if let Some(payload_val) = p.get("payload").or_else(|| p.get("data")) {
        if let Some(s) = payload_val.as_str() {
            if s.is_empty() || s == "0x" {
                return Ok(Vec::new());
            }
            let clean = s.strip_prefix("0x").unwrap_or(s);
            if let Ok(bytes) = hex::decode(clean) {
                if let Ok(ops) =
                    decode_wire_limited::<Vec<crate::svm::OpCode>>(&bytes, MAX_RPC_BODY as u64)
                {
                    return Ok(ops);
                }
                if let Ok(op) =
                    decode_wire_limited::<crate::svm::OpCode>(&bytes, MAX_RPC_BODY as u64)
                {
                    return Ok(vec![op]);
                }
                return Ok(vec![crate::svm::OpCode::SysCallCallContract {
                    contract: to_addr,
                    method: bytes,
                    arg: 0,
                }]);
            }
            // Audit F2: a non-hex `method` is a NAME, never code — bound it
            // (a 200KB method string is parse-level DoS before gas applies).
            if s.len() > 1024 {
                return Err(format!("method exceeds cap 1024 bytes (got {})", s.len()));
            }
            return Ok(vec![crate::svm::OpCode::SysCallCallContract {
                contract: to_addr,
                method: s.as_bytes().to_vec(),
                arg: 0,
            }]);
        }
        if let Some(arr) = payload_val.as_array() {
            if arr.is_empty() {
                return Ok(Vec::new());
            }
            // Audit F2: bound the opcode count pre-parse (allocation + sim
            // setup happen before the gas budget binds).
            if arr.len() > 1024 {
                return Err(format!("payload ops exceed cap 1024 (got {})", arr.len()));
            }
            if let Ok(ops) = serde_json::from_value::<Vec<crate::svm::OpCode>>(payload_val.clone())
            {
                return Ok(ops);
            }
            let mut ops = Vec::with_capacity(arr.len());
            for item in arr {
                ops.push(parse_opcode_value(item)?);
            }
            return Ok(ops);
        }
        if payload_val.is_object() {
            return Ok(vec![parse_opcode_value(payload_val)?]);
        }
    }

    if let Some(tok_val) = p.get("token_id").or_else(|| p.get("token")) {
        let tok_str = tok_val
            .as_str()
            .ok_or_else(|| "token_id must be a string".to_string())?;
        let token_id = parse_rpc_address(tok_str)?;
        let amount = p
            .get("amount")
            .or_else(|| p.get("value"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        return Ok(vec![crate::svm::OpCode::SysCallTokenTransfer {
            token_id,
            to: to_addr,
            amount,
        }]);
    }

    if let Some(method_val) = p.get("method") {
        // Audit F2: a `method` param is a NAME, never code — bound both
        // shapes (string bytes and byte-array) before simulation.
        let method = match method_val {
            Value::String(s) => {
                if s.len() > 1024 {
                    return Err(format!("method exceeds cap 1024 bytes (got {})", s.len()));
                }
                s.as_bytes().to_vec()
            }
            Value::Array(arr) => {
                if arr.len() > 1024 {
                    return Err(format!("method bytes exceed cap 1024 (got {})", arr.len()));
                }
                serde_json::from_value(method_val.clone())
                    .map_err(|e: serde_json::Error| e.to_string())?
            }
            _ => return Err("invalid method in contract call".to_string()),
        };
        let arg = if let Some(a) = p.get("arg").or_else(|| p.get("args")) {
            parse_contract_call_arg(a)?
        } else {
            0i64
        };
        return Ok(vec![crate::svm::OpCode::SysCallCallContract {
            contract: to_addr,
            method,
            arg,
        }]);
    }

    Ok(Vec::new())
}

pub(super) async fn handle_estimate_fee(
    st: &RpcState,
    id: Value,
    params: &Value,
) -> Json<RpcResponse> {
    let p = if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    };

    // The gas budget the simulation runs with. The caller's DECLARED limit
    // is not the budget (see `estimate_fee_gas_budget`): the estimate must be
    // able to discover what the call NEEDS. A caller may LOWER the budget
    // with `max_gas`; it may never raise it above the fixed ceiling.
    let requested_max_gas = match p.get("max_gas") {
        None => None,
        Some(v) => match v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
        {
            Some(n) => Some(n),
            None => {
                return err(id, -32602, "max_gas must be an unsigned integer");
            }
        },
    };
    let gas_budget = match estimate_fee_gas_budget(requested_max_gas) {
        Ok(b) => b,
        Err(e) => return err(id, -32602, e),
    };

    // 1. Raw transaction support: { "tx": <raw hex> }
    let raw_tx_opt = p.get("tx").and_then(|v| v.as_str()).or_else(|| p.as_str());

    let sim_tx = if let Some(raw_hex) = raw_tx_opt {
        let clean = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
        let bytes = match hex::decode(clean) {
            Ok(b) => b,
            Err(e) => return err(id, -32602, format!("invalid hex: {e}")),
        };
        match decode_wire_limited::<Transaction>(&bytes, MAX_RPC_BODY as u64) {
            Ok(t) => t,
            Err(_) => match crate::evm_adapter::evm_raw_to_stell_transaction(&bytes) {
                Ok(t) => t,
                Err(e) => return err(id, -32602, format!("failed to decode transaction: {e}")),
            },
        }
    } else {
        let from_str = match p
            .get("from")
            .or_else(|| p.get("sender"))
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return err(id, -32602, "missing 'from' parameter"),
        };
        let (from_addr, from_shard_hint) = match parse_rpc_address_with_shard_hint(from_str) {
            Ok(res) => res,
            Err(e) => return err(id, -32602, format!("invalid 'from' address: {e}")),
        };

        let to_str = match p
            .get("to")
            .or_else(|| p.get("recipient"))
            .or_else(|| p.get("contract"))
            .or_else(|| p.get("address"))
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return err(id, -32602, "missing 'to' parameter"),
        };
        let (to_addr, to_shard_hint) = match parse_rpc_address_with_shard_hint(to_str) {
            Ok(res) => res,
            Err(e) => return err(id, -32602, format!("invalid 'to' address: {e}")),
        };

        let amount = p
            .get("amount")
            .or_else(|| p.get("value"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);

        let source_shard = p
            .get("source_shard")
            .and_then(|v| v.as_u64().map(|n| n as u32))
            .or(from_shard_hint)
            .unwrap_or_else(|| {
                st.engine
                    .shard_id
                    .load(std::sync::atomic::Ordering::Relaxed)
            });

        // THE address→shard rule (see `crate::sharding::ROUTING_RULE`): an
        // explicit `target_shard` wins, then the shard the caller NAMED in
        // the address form (`-1:` / `N:`), and otherwise the routing rule
        // over this node's topology. One rule, one source of truth — the
        // same rule `stell_runGetMethod` and the topology itself use.
        let target_shard = match p.get("target_shard").and_then(|v| v.as_u64()) {
            Some(n) => n as u32,
            None => resolve_shard_for_address(st, to_addr, to_shard_hint).await,
        };

        let payload = match parse_estimate_payload(p, to_addr) {
            Ok(pl) => pl,
            Err(e) => return err(id, -32602, format!("invalid payload: {e}")),
        };

        Transaction {
            from: from_addr,
            to: to_addr,
            amount,
            gas_limit: 10_000_000,
            nonce: 0,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload,
            priority_fee_per_gas: 0,
        }
    };

    simulate_and_estimate_fee(st, id, sim_tx, gas_budget).await
}

pub(super) async fn simulate_and_estimate_fee(
    st: &RpcState,
    id: Value,
    mut sim_tx: Transaction,
    gas_budget: u64,
) -> Json<RpcResponse> {
    let is_cross_shard = sim_tx.source_shard != sim_tx.target_shard;
    let is_plain_fast_path = sim_tx.payload.is_empty()
        && !crate::evm_adapter::is_evm_carrier_tx(&sim_tx)
        && !crate::evm_adapter::is_evm_binding_tx(&sim_tx);

    let (surcharge, base_fee, gas_consumed) = if is_plain_fast_path {
        // Fast path for plain transfers (`payload.is_empty()`, neither EVM
        // carrier nor binding): `consensus_floor_parts` reads only
        // `governance.applied.min_gas_limit`, `consensus_penalty[from]` (D2),
        // and `Mempool::surcharges_for_tx(tx)` (PQ activation / EVM carrier);
        // `execute_payload` is never called and `gas_consumed` is always
        // `GAS_BASIC_TRANSFER`. Reading directly from `st.engine` avoids
        // deep-cloning 20+ subsystems via `clone_for_simulation()` and is
        // byte-identical to the full simulation path.
        let (floor_base, surcharge) = st.engine.consensus_floor_parts(&sim_tx).await;
        let pool_floor = st.mempool.read().await.base_fee;
        let base_fee = pool_floor
            .max(floor_base)
            .max(crate::svm::GAS_BASIC_TRANSFER);
        (surcharge, base_fee, crate::svm::GAS_BASIC_TRANSFER)
    } else {
        let sim_engine = st.engine.clone_for_simulation_for_tx(&sim_tx).await;

        // Consensus floor and surcharge (e.g. PQ activation or penalties)
        let (floor_base, surcharge) = sim_engine.consensus_floor_parts(&sim_tx).await;
        let pool_floor = st.mempool.read().await.base_fee;
        let base_fee = pool_floor
            .max(floor_base)
            .max(crate::svm::GAS_BASIC_TRANSFER);

        // Provide test/simulation funds for sender in case account is unfunded in simulation
        {
            let mut map = sim_engine.accounts.write().await;
            let entry = map
                .entry(sim_tx.from)
                .or_insert_with(|| AccountState::new(sim_tx.from, 0));
            if entry.balance < 100_000_000_000 {
                entry.balance = 100_000_000_000;
            }
        }
        // Also if token transfer, ensure sender has tokens in cloned engine
        for op in &sim_tx.payload {
            if let crate::svm::OpCode::SysCallTokenTransfer {
                token_id, amount, ..
            } = op
            {
                let mut tokens = sim_engine.tokens_write().await;
                if let Some(tok) = tokens.tokens.get_mut(token_id) {
                    let cur = tok.balance_of(&sim_tx.from);
                    if cur < *amount {
                        tok.balances
                            .insert(sim_tx.from, cur.saturating_add(*amount));
                    }
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // BOUNDED FUEL (audit W6.7): the estimate used to raise the
        // simulation's gas limit to `MAX_CONTRACT_FUEL` (50 000 000) — the
        // contract-execution ceiling — so an UNAUTHENTICATED read could burn
        // the full contract budget on every request. The estimate only needs
        // enough gas to price a normal call, so the ceiling is
        // `ESTIMATE_FEE_GAS_CEILING`; the answer for a normal transaction is
        // unchanged and a pathological payload can no longer burn the whole
        // contract ceiling per request.
        //
        // HONEST BUDGET (audit W7.2): the budget is the caller's `max_gas`
        // when it asked for one, and the FIXED ceiling otherwise. The
        // transaction's DECLARED `gas_limit` is deliberately NOT used as the
        // budget (it would answer "out of gas" instead of the requirement),
        // and the old `gas_limit.max(10_000_000).min(5_000_000)` expression is
        // gone: it could only ever evaluate to 5 000 000, so the `.max()` was
        // dead code pretending to be a caller-controllable floor.
        sim_tx.gas_limit = gas_budget;
        let gas_consumed = match sim_engine.execute_payload(&sim_tx, now).await {
            Ok((crate::svm::VmExecutionResult::Success { gas_used, .. }, _)) => gas_used,
            Ok((crate::svm::VmExecutionResult::OutOfGas, _)) => {
                return err(id, -32000, "simulation out of gas");
            }
            Ok((crate::svm::VmExecutionResult::Reverted(reason), _)) => {
                return err(id, -32000, format!("simulation reverted: {reason}"));
            }
            Err(e) => {
                return err(id, -32000, format!("simulation failed: {e}"));
            }
        };
        (surcharge, base_fee, gas_consumed)
    };

    let effective_gas = gas_consumed.max(base_fee);
    let estimated_fee = effective_gas.saturating_add(surcharge);
    let gas_limit = estimated_fee;

    ok(
        id,
        json!({
            "gas_limit": gas_limit,
            "estimated_fee": estimated_fee,
            "base_fee": base_fee,
            "source_shard": sim_tx.source_shard,
            "target_shard": sim_tx.target_shard,
            "is_cross_shard": is_cross_shard,
            // The gas budget the simulation actually ran with, and the fixed
            // ceiling it can never exceed (audit W7.2): a caller can see the
            // bound it is working under instead of guessing it.
            "gas_budget": gas_budget,
            "gas_ceiling": ESTIMATE_FEE_GAS_CEILING,
            "status": "ok"
        }),
    )
}

/// Shared admission path for the WRITE-shaped `stell_submit*` arms.
///
/// THIN by design: it token-gates, decodes and verifies the wrapping
/// transaction, checks that the payload actually carries the thing the method
/// name promises, and admits it to the mempool. It never writes consensus
/// state - a price, a swap or an order only exists once a proposer includes the
/// transaction in a block and every node re-runs the opcode against
/// `block.timestamp`. Writing here would make the result node-local, which is
/// exactly the bug each of these arms exists to avoid.
///
/// `carries` is the payload-shape predicate; `wrong_payload` is what a caller
/// that sent some other transaction under this method name is told.
pub const MAX_PROOF_STORAGE_KEYS: usize = 32;

/// `stell_getProof` — Merkle inclusion/exclusion proofs against the state root.
///
/// Params: `{ "address": <hex | Stl57>, "storage_keys": [<hex>, ...], "block_height": <u64> }`.
///
/// The answer carries the account's balance and nonce, the account's Merkle
/// proof, one proof per requested storage key, and the state root the proofs
/// are anchored to.
///
/// Two properties matter here and both are the reason this is not just
/// `stell_getBalanceSpv` with extra fields:
///
///  * **Inclusion AND exclusion.** A key that is *not* in the trie gets an
///    exclusion proof, not an empty answer. "This account does not exist" is
///    a claim about the world, and it is provable against the same root as
///    "this account has this balance" — a client that can only check
///    inclusion has to take the server's word for absence, which is the trust
///    assumption an SPV client exists to remove.
///  * **The proof carries the value.** The leaf value is inside the proof
///    (not merely alongside it), so a light client recomputes the leaf hash
///    from the proof's own bytes. A server cannot pair a real balance with a
///    proof of something else.
///
/// `storage_keys` are raw 32-byte state-trie keys (hex). This chain has no
/// EVM storage trie, so there is nothing else they could mean.
pub(super) async fn handle_get_proof(
    st: &RpcState,
    id: Value,
    params: &Value,
) -> Json<RpcResponse> {
    let p = if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    };

    let addr_raw = match p
        .get("address")
        .and_then(|v| v.as_str())
        .or_else(|| p.as_str())
    {
        Some(a) => a,
        None => return err(id, -32602, "missing address"),
    };
    let address = match crate::address::parse_address(addr_raw) {
        Ok(a) => a,
        Err(e) => return err(id, -32602, format!("bad address: {e}")),
    };

    // Optional height. This node keeps no historical state, so the only
    // height it can answer for is the one it is currently serving — saying
    // so is better than serving today's proof under an old height's label.
    let cur_height = st.height.load(std::sync::atomic::Ordering::Relaxed);
    let want_height = p
        .get("block_height")
        .or_else(|| p.get("height"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            p.get("block_height")
                .or_else(|| p.get("height"))
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        u64::from_str_radix(h, 16).ok()
                    } else {
                        s.parse::<u64>().ok()
                    }
                })
        });
    if let Some(want) = want_height {
        if want != cur_height {
            return err(
                id,
                -32004,
                format!(
                    "historical state is not available on this node: it serves height {cur_height}, not {want}"
                ),
            );
        }
    }

    let storage_keys: Vec<[u8; 32]> = match p.get("storage_keys") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_PROOF_STORAGE_KEYS {
                return err(
                    id,
                    -32602,
                    format!("too many storage keys: at most {MAX_PROOF_STORAGE_KEYS} per request"),
                );
            }
            let mut out = Vec::with_capacity(arr.len());
            for k in arr {
                let s = match k.as_str() {
                    Some(s) => s,
                    None => return err(id, -32602, "storage key must be a hex string"),
                };
                match parse_hash(s) {
                    Ok(k) => out.push(k),
                    Err(e) => return err(id, -32602, format!("bad storage key: {e}")),
                }
            }
            out
        }
        Some(_) => return err(id, -32602, "storage_keys must be an array of hex strings"),
    };

    // Fold the consensus-domain digest first: it is the canonical root, and
    // the fold is a write, so it must not happen while the read lock below
    // is held.
    let _ = st.engine.get_state_root().await;
    let trie = st.engine.state_trie.read().await;
    // The root is read from the SAME trie snapshot the proofs come from, so
    // the answer can never mix a root from one state with a proof from
    // another.
    let root = trie.root_hash();

    // Account: inclusion proof when the account is in the trie, exclusion
    // proof when it is not. Both are anchored at the same root.
    let account_proof = trie
        .compressed()
        .generate_proof(&address)
        .or_else(|| trie.compressed().generate_exclusion_proof(&address));
    let (account_nodes, balance, nonce, account_exists) = match &account_proof {
        Some(p) if p.kind == crate::cpat2::ProofKind::Inclusion => {
            let (b, n) = decode_account_leaf(&p.value);
            // Fail closed: never serve a proof this node cannot verify
            // against the root it is serving. A broken proof is worse than
            // no proof, because the client would believe it.
            if !crate::cpat2::verify_proof(&root, &address, &p.value, p) {
                return err(
                    id,
                    -32000,
                    "internal error: generated account proof does not verify",
                );
            }
            (p.to_nodes(), b, n, true)
        }
        Some(p) => {
            if !crate::cpat2::verify_exclusion_proof(&root, &address, p) {
                return err(
                    id,
                    -32000,
                    "internal error: generated exclusion proof does not verify",
                );
            }
            (p.to_nodes(), 0u64, 0u64, false)
        }
        // An empty trie has nothing to prove against.
        None => (Vec::new(), 0u64, 0u64, false),
    };

    let mut storage_proofs: Vec<Value> = Vec::with_capacity(storage_keys.len());
    for k in &storage_keys {
        let proof = trie
            .compressed()
            .generate_proof(k)
            .or_else(|| trie.compressed().generate_exclusion_proof(k));
        match proof {
            Some(p) if p.kind == crate::cpat2::ProofKind::Inclusion => {
                if !crate::cpat2::verify_proof(&root, k, &p.value, &p) {
                    return err(
                        id,
                        -32000,
                        "internal error: generated storage proof does not verify",
                    );
                }
                storage_proofs.push(json!({
                    "key": hex::encode(k),
                    "value": hex::encode(&p.value),
                    "exists": true,
                    "proof": p.to_nodes(),
                }));
            }
            Some(p) => {
                if !crate::cpat2::verify_exclusion_proof(&root, k, &p) {
                    return err(
                        id,
                        -32000,
                        "internal error: generated storage exclusion proof does not verify",
                    );
                }
                storage_proofs.push(json!({
                    "key": hex::encode(k),
                    "value": Value::Null,
                    "exists": false,
                    "proof": p.to_nodes(),
                }));
            }
            None => {
                storage_proofs.push(json!({
                    "key": hex::encode(k),
                    "value": Value::Null,
                    "exists": false,
                    "proof": Vec::<String>::new(),
                }));
            }
        }
    }
    drop(trie);

    let root_hex = hex::encode(root);
    ok(
        id,
        json!({
            "address": hex::encode(address),
            "balance": balance,
            "nonce": nonce,
            "account_proof": account_nodes,
            "storage_proofs": storage_proofs,
            "state_root": root_hex,
            // Aliases: `stateRoot` matches `stell_getBalanceSpv`, `height` lets a
            // client line the answer up with the header it trusts.
            "stateRoot": root_hex,
            "height": cur_height,
            "exists": account_exists,
        }),
    )
}

/// Decode `balance` and `nonce` out of a committed account leaf.
///
/// The leaf is `balance(8, BE) || nonce(8, BE)` for a dormant account and
/// `balance(8) || nonce(8) || scheme(1) || pubkey_hash(32)` for a pinned
/// post-quantum one. A leaf too short to hold a balance is reported as
/// zeros rather than panicking: the proof still authenticates it, so the
/// honest answer is "this leaf does not carry a balance".
pub(super) fn decode_account_leaf(value: &[u8]) -> (u64, u64) {
    if value.len() < 16 {
        return (0, 0);
    }
    let mut balance = [0u8; 8];
    balance.copy_from_slice(&value[..8]);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&value[8..16]);
    (u64::from_be_bytes(balance), u64::from_be_bytes(nonce))
}

/// `stell_getArchiveProof` — a per-key proof against a HISTORICAL state root.
///
/// Params: `{ "address": <hex | Stl57>, "key": <hex, optional>, "height": <u64> }`.
///
/// * `address` selects the account (parsed exactly like `stell_getProof`).
/// * `key`, when present, is the RAW 32-byte state-trie key to prove (a slot
///   from the slot model in `crate::storage`: STS balance cell, contract
///   code hash, ...). When absent the account leaf itself (`address`) is
///   proven.
/// * `height` is the historical height whose post-state is proven.
///
/// The answer is `{ "height", "state_root", "key", "value", "proof",
/// "proof_type" }` (`value` is `null` with `proof_type: "exclusion"` when
/// the key did not exist at that height). The proof verifies with
/// `cpat2::ArchiveProof::verify` — and the root is authenticated separately
/// with `stell_getHistoricalRoot`, whose QC the client checks against its
/// own validator set.
///
/// Fail closed: no durable store attached, a height above the tip, an
/// unknown height, a pruned height, or a snapshot the node cannot anchor is
/// a `-32004` error — never an empty answer, never a live-trie proof
/// relabeled as history.
pub(super) async fn handle_get_archive_proof(
    st: &RpcState,
    id: Value,
    params: &Value,
) -> Json<RpcResponse> {
    let p = if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    };

    let addr_raw = match p
        .get("address")
        .and_then(|v| v.as_str())
        .or_else(|| p.as_str())
    {
        Some(a) => a,
        None => return err(id, -32602, "missing address"),
    };
    let address = match crate::address::parse_address(addr_raw) {
        Ok(a) => a,
        Err(e) => return err(id, -32602, format!("bad address: {e}")),
    };
    let key: [u8; 32] = match p.get("key") {
        None | Some(Value::Null) => address,
        Some(Value::String(s)) => match parse_hash(s) {
            Ok(k) => k,
            Err(e) => return err(id, -32602, format!("bad key: {e}")),
        },
        Some(_) => return err(id, -32602, "key must be a hex string"),
    };
    let height = match p.get("height").and_then(|v| v.as_u64()).or_else(|| {
        p.get("height").and_then(|v| v.as_str()).and_then(|s| {
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(h, 16).ok()
            } else {
                s.parse::<u64>().ok()
            }
        })
    }) {
        Some(h) => h,
        None => return err(id, -32602, "missing height"),
    };

    let Some(store) = st.archive_store.clone() else {
        return err(
            id,
            -32004,
            "archive proofs are not available on this node (no durable store attached): \
             it cannot consult its snapshot history, so it refuses rather than proving from memory",
        );
    };
    let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
    match store.serve_archive_proof(height, &key, tip).await {
        Ok(proof) => ok(id, proof.to_json()),
        Err(e) => err(id, -32004, format!("{e:#}")),
    }
}

/// `stell_getHistoricalRoot` — the authenticated historical state root.
///
/// Params: `{ "height": <u64> }`.
///
/// The answer is `{ "height", "state_root", "anchor_height", "anchor_hash",
/// "prev_hash", "cert", "finalized": true }` where `state_root` is the
/// post-`height` state and `cert` is the precommit QC on the anchoring
/// block (`height + 1`), in the same shape as
/// `FinalizedHeaderRecord::to_json` so the client reuses one parser. The
/// client verifies the QC against its OWN validator set
/// (`Checkpoint::from_historical_root_json` + `Checkpoint::verify`) and only
/// then trusts the root — without the QC the root is just a number.
///
/// Fail closed: a height above the tip, an unknown height, or a height whose
/// anchoring body's QC was pruned is a `-32004` error. A header record alone
/// never authenticates (it carries no certificate).
pub(super) async fn handle_get_historical_root(
    st: &RpcState,
    id: Value,
    params: &Value,
) -> Json<RpcResponse> {
    let height = match params
        .get("height")
        .and_then(|v| v.as_u64())
        .or_else(|| params.as_u64())
        .or_else(|| {
            params.get("height").and_then(|v| v.as_str()).and_then(|s| {
                if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    u64::from_str_radix(h, 16).ok()
                } else {
                    s.parse::<u64>().ok()
                }
            })
        }) {
        Some(h) => h,
        None => return err(id, -32602, "missing height"),
    };

    let Some(store) = st.archive_store.clone() else {
        return err(
            id,
            -32004,
            "historical roots are not available on this node (no durable store attached)",
        );
    };
    let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
    match store.historical_root(height, tip) {
        Ok(record) => ok(
            id,
            json!({
                "height": record.height,
                "state_root": hex::encode(record.state_root),
                "stateRoot": hex::encode(record.state_root),
                "anchor_height": record.anchor_height,
                "anchor_hash": hex::encode(record.anchor_hash),
                "prev_hash": hex::encode(record.anchor_prev_hash),
                "shard_id": record.anchor_shard_id,
                "round": record.anchor_round,
                "body_commitment": record.anchor_body_commitment.map(hex::encode),
                "mmr_epoch_root": hex::encode(record.anchor_mmr_epoch_root),
                "epoch_key_commitment": hex::encode(record.anchor_epoch_key_commitment),
                "timestamp": record.anchor_timestamp,
                "proposer": hex::encode(record.anchor_proposer),
                "cert": {
                    "height": record.cert.height,
                    "round": record.cert.round,
                    "kind": format!("{:?}", record.cert.kind),
                    "block_hash": record.cert.block_hash.map(hex::encode),
                    "shard_id": record.cert.shard_id,
                    "signatures": record.cert.signatures.iter().map(|(v, s)| json!({
                        "validator": hex::encode(v),
                        "signature": hex::encode(s),
                    })).collect::<Vec<Value>>(),
                },
                "finalized": record.finalized,
            }),
        ),
        Err(e) => err(id, -32004, format!("{e:#}")),
    }
}

/// The kind of chain a shard id names: `0` is the masterchain (global state,
/// consensus), everything `>= 1` is a workchain (user state).
pub fn shard_type_of(shard_id: ShardId) -> &'static str {
    if shard_id == crate::sharding::MASTERCHAIN_SHARD {
        "masterchain"
    } else {
        "workchain"
    }
}

/// How many bits of an address's routing prefix a layout of `shards` shards
/// needs: `ceil(log2(shards))`.
///
/// One shard needs no routing at all (the pre-sharding single-chain layout),
/// two need exactly one bit (masterchain vs workchain), four need two. Integer
/// math only — no float rounding at the boundary.
pub fn routing_prefix_bits(shards: usize) -> u32 {
    let mut bits = 0u32;
    while (1usize << bits) < shards {
        bits += 1;
    }
    bits
}

/// Attach the resolved shard to a JSON-RPC result, so a client can see
/// WHICH shard the answer came from without re-deriving the rule.
///
/// `shard` is the shard the address→shard rule resolved the address to;
/// `local_shard` is the shard this node runs. `shard_is_local` is false when
/// the address belongs to another shard — the node then answers from its
/// own state only, which is the honest answer for a node that does not
/// hold that shard.
pub(super) fn with_shard_info(mut value: Value, shard: u32, local_shard: u32) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("shard".to_string(), json!(shard));
        obj.insert("local_shard".to_string(), json!(local_shard));
        obj.insert("shard_is_local".to_string(), json!(shard == local_shard));
    }
    value
}

/// The shard topology this node can prove, one entry per shard it has a
/// committed head for, in ascending shard id.///
/// Two sources, in this order:
///
/// 1. the process-shared finalized-header registry (`FinalizedHeaderRegistry`),
///    which the block-application paths (finalize / adopt / walk) fill with the
///    full header of every shard this process committed. It is NEVER written
///    from gossip, RPC or DHT blobs, so a head listed here is a head this node
///    applied — the same trust basis as `stell_getStateRoot`.
/// 2. the shard THIS node's own engine runs, when the registry holds no head
///    for it (a single-shard node whose runtime has no registry attached, or a
///    node that has not finalized a block yet): its height comes from
///    `st.height`, its hash from the committed-window head, its state root
///    from the live trie.
///
/// A shard with neither source is NOT listed: an unknown shard is a miss, not
/// an entry with zeroed fields.
pub async fn collect_shard_heads(st: &RpcState) -> Vec<ShardHead> {
    use std::collections::BTreeMap;
    let mut heads: BTreeMap<ShardId, ShardHead> = BTreeMap::new();
    let local_shard = st.engine.shard_id();

    // 1. The committed heads of every shard this process finalized.
    if let Some(reg) = st.engine.finalized_headers() {
        if let Ok(reg) = reg.read() {
            let mut push = |h: &crate::sharding::ShardHeaderCommitment| {
                heads.insert(
                    h.shard_id,
                    ShardHead {
                        shard_id: h.shard_id,
                        shard_type: shard_type_of(h.shard_id).to_string(),
                        tip_height: h.height,
                        tip_hash: Some(hex::encode(h.block_hash)),
                        state_root: Some(hex::encode(h.state_root)),
                        local: h.shard_id == local_shard,
                    },
                );
            };
            if let Some(mc) = reg.latest_header(crate::sharding::MASTERCHAIN_SHARD) {
                push(mc);
            }
            for wc in reg.workchain_headers() {
                push(&wc);
            }
        }
    }

    // 2. The shard this node runs itself, when the registry has no head for it.
    if let std::collections::btree_map::Entry::Vacant(e) = heads.entry(local_shard) {
        let tip_hash = st
            .recent_blocks
            .read()
            .await
            .front()
            .map(|b| b.hash.clone());
        let state_root = hex::encode(st.engine.get_state_root().await);
        e.insert(ShardHead {
            shard_id: local_shard,
            shard_type: shard_type_of(local_shard).to_string(),
            tip_height: st.height.load(std::sync::atomic::Ordering::Relaxed),
            tip_hash,
            state_root: Some(state_root),
            local: true,
        });
    }

    heads.into_values().collect()
}

// ============================================================================
// Wallet signature standard (docs/WALLET_SIGNING.md, audit P2 item 15).
//
// `stell_signMessage` / `stell_signTypedData` sign with a SEPARATE ephemeral
// dev-only key (NEVER the validator key — see `dev_msg_signing_seed_from_env`)
// and are fail-closed: they require (a) the key to be configured (explicit
// dev mode at startup), (b) a configured `auth_token` presented by the caller
// (in `params.token` / `params.apiKey` / a header), and (c) a loopback peer
// (in-process `None` callers are the test harness). Otherwise they refuse.
// They exist for TESTING/DEVNET ONLY — a production wallet MUST sign locally
// and never ship its key to a node.
// `stell_verifyMessage` / `stell_verifyTypedData` are public (no secret, no
// auth): verification is total and side-effect free.
//
// The node signs Ed25519 only. Falcon-512/Hybrid signing is a wallet-side
// operation (see the `stellereum wallet sign` CLI); the VERIFY arms accept all
// three live schemes.
// ============================================================================

pub(super) async fn dispatch_reads(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Json<RpcResponse> {
    match method {
        // ---- chain / node info ----
        "stell_chainId" => ok(id, json!(st.chain_id)),
        "stell_nodeId" => ok(id, json!(st.node_id)),
        // ---- EVM JSON-RPC adapter network info & state ----
        "stell_blockNumber" => {
            let h = st.height.load(std::sync::atomic::Ordering::Relaxed);
            ok(id, json!(format!("0x{:x}", h)))
        }
        "stell_syncing" => {
            // True while a RECENT verified sighting names a height above ours
            // (audit 2026-10-06 + follow-up: was hardcoded false; then a bare
            // max that pinned true forever on one faulty vote). Vantage-local.
            let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let syncing = fresh_peer_height().map(|peer| peer > ours).unwrap_or(false);
            ok(id, json!(syncing))
        }
        "stell_getStateRoot" => {
            // DELIBERATE read-with-fold (audit 2026-10-14 F2/I3): `get_state_root`
            // folds exactly one deterministic commitment key when the commitment
            // digest is stale, under the trie write lock. The fold is a pure
            // function of committed subsystems, so every node that applied the
            // same blocks serves the same root — a reader-observable write, not
            // a divergence. Hot scrapes briefly serialize on the lock; the
            // per-IP limiters bound scrape storms.
            let root = st.engine.get_state_root().await;
            ok(id, json!(hex::encode(root)))
        }
        "stell_latestBlocks" => {
            let limit = params["limit"]
                .as_u64()
                .or_else(|| params.as_u64())
                .or_else(|| params.get(0).and_then(|v| v.as_u64()))
                .map(|l| (l as usize).min(MAX_RECENT_BLOCKS))
                .unwrap_or(MAX_RECENT_BLOCKS);
            let rb = st.recent_blocks.read().await;
            let mut list: Vec<Value> = rb
                .iter()
                .take(limit)
                .map(|b| {
                    json!({
                        "height": b.height,
                        "hash": b.hash,
                        "txs": b.tx_count,
                        "timestamp": b.timestamp,
                    })
                })
                .collect();
            drop(rb);
            if list.is_empty() && limit > 0 {
                if let Some(store) = st.archive_store.as_ref() {
                    if let Ok(Some(tip_rec)) = store.latest_header() {
                        let tip = tip_rec.height;
                        let lo = tip.saturating_sub(limit as u64 - 1);
                        for h in (lo..=tip).rev() {
                            if let Ok(Some(rec)) = store.header_at(h) {
                                list.push(json!({
                                    "height": rec.height,
                                    "hash": hex::encode(rec.block_hash),
                                    "txs": rec.tx_count,
                                    "timestamp": rec.timestamp,
                                }));
                            }
                        }
                    }
                }
            }
            ok(id, json!(list))
        }
        "stell_getShards" => {
            // Shard topology (the TON `liteServer.getShards` / Near
            // `shard_layout` analogue). A wallet or an indexer asks which
            // shards exist and where each one is, instead of assuming one
            // global chain.
            //
            // `height` is optional and is a BOUND, not a selector: the shard
            // SET is a property of the network configuration, not of a
            // height, and this node keeps no per-height history of it. A
            // height at or below our tip is accepted and answered with the
            // current topology; a height ABOVE our tip is refused rather
            // than answered with a head we have not committed (never
            // fabricate a shard tip).
            let want_height = params
                .get("height")
                .and_then(|v| v.as_u64())
                .or_else(|| params.as_u64())
                .or_else(|| params.get(0).and_then(|v| v.as_u64()));
            if let Some(h) = want_height {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                if h > tip {
                    return err(
                        id,
                        -32004,
                        format!("requested height {h} is above this node's tip ({tip})"),
                    );
                }
            }
            let heads = collect_shard_heads(st).await;
            let total = heads.len();
            // The published sharding parameters and the address→shard rule,
            // read from the node's OWN topology (the single source of truth).
            let topology = st.engine.shard_topology().await;
            let parameters = topology.parameters();
            let sharding = serde_json::to_value(&parameters).unwrap_or(Value::Null);
            drop(topology);
            ok(
                id,
                json!({
                    "shards": heads,
                    "total_shards": total,
                    "routing_prefix_bits": routing_prefix_bits(total),
                    "sharding": sharding,
                }),
            )
        }
        // The full shard topology: the active shard set with their routing
        // prefixes and account counts, plus the published thresholds and the
        // parameters of the address→shard rule.
        //
        // `stell_getShards` answers "which shards have a committed head";
        // this one answers "how is the address space laid out right now".
        "stell_getShardTopology" => {
            let topology = st.engine.shard_topology().await;
            let report = topology.report();
            drop(topology);
            ok(id, serde_json::to_value(&report).unwrap_or(Value::Null))
        }
        "stell_getBlock" => {
            // Serve order: local committed window (fed by finalize AND adopt via
            // `record_adopted_block`, so any node serves adopted heights) ->
            // durable header store -> the same shared adapter `eth_getBlockBy*`
            // reads -> honest "not available yet". Never fabricated: a height
            // outside every source is a miss, not a zero-tx fabrication.
            //
            // The selector accepts everything the `eth_*` path accepts:
            // `{"height": 42}`, `{"height": "latest"}`, `"latest"`, `42`,
            // `["0x2a"]`, ... Tags resolve against this node's finalized tip.
            //
            // Finalized-read cache: the summary for a finalized height is
            // immutable (any republish evicts via `record_block`), so a fresh
            // `Ok` is cached keyed by (method, height, params-hash). Errors
            // bypass: an unknown height can still arrive via replication.
            let tag = match stell_block_tag_param(params) {
                Ok(t) => t,
                Err(e) if e == "missing height" => return err(id, -32602, e),
                Err(e) => return err(id, -32602, e),
            };
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let want = tag.resolve(tip);
            // Only finalized heights may consult the cache. An above-tip read
            // is an error, and errors bypass the cache entirely (no lookup, no
            // miss counter): it may resolve as replication catches up.
            if want <= tip {
                if let Some(hit) = finalized_read_cache_get("stell_getBlock", want, params, tip) {
                    return ok(id, hit);
                }
            }
            let rb = st.recent_blocks.read().await;
            let found = rb.iter().find(|b| b.height == want);
            if let Some(b) = found {
                let v = json!({
                    "height": b.height,
                    "hash": b.hash,
                    "txs": b.tx_count,
                    "timestamp": b.timestamp,
                });
                drop(rb);
                finalized_read_cache_put("stell_getBlock", want, params, tip, v.clone());
                return ok(id, v);
            }
            drop(rb);
            if let Some(rec) = st
                .archive_store
                .as_ref()
                .and_then(|s| s.header_at(want).ok().flatten())
            {
                let v = json!({
                    "height": rec.height,
                    "hash": hex::encode(rec.block_hash),
                    "txs": rec.tx_count,
                    "timestamp": rec.timestamp,
                });
                finalized_read_cache_put("stell_getBlock", want, params, tip, v.clone());
                return ok(id, v);
            }
            // Same source the `eth_*` adapter serves: the shared adapter maps.
            let numeric_tag = format!("0x{want:x}");
            if let Ok(Some(b)) = st.eth_get_block_by_number(&numeric_tag, false).await {
                if let Some(mut summary) = evm_block_to_stell_summary(&b) {
                    // An adapter block summary can carry an empty hashes list;
                    // the receipt index is the authoritative tx count for a
                    // height this node committed.
                    if summary.tx_count == 0 {
                        summary.tx_count = st.receipts.read().await.for_height(want).len();
                    }
                    let v = json!({
                        "height": summary.height,
                        "hash": summary.hash,
                        "txs": summary.tx_count,
                        "timestamp": summary.timestamp,
                    });
                    finalized_read_cache_put("stell_getBlock", want, params, tip, v.clone());
                    return ok(id, v);
                }
            }
            if want > tip {
                return err(
                    id,
                    -32004,
                    format!(
                        "block not available yet: height {want} is above this node's tip \
                         ({tip}); replication runs behind finalization"
                    ),
                );
            }
            err(id, -32004, "block not available yet (not in recent window; replication runs behind finalization)")
        }
        // Block transactions, served from the SAME receipt index as
        // `stell_getTransactionReceipt` (filed by the single real application on
        // finalize AND on adopt -- so any node serves adopted heights). Fallback
        // order: local committed receipts -> honest "not available yet", never
        // fabricated (an empty list is only returned when the block is KNOWN
        // with zero transactions, not when it is unknown).
        "stell_getBlockTransactions" => {
            // Same selector shapes as `stell_getBlock` (number, hex, tag,
            // positional): a client should not need two different height
            // dialects for two reads of the same block.
            let tag = match stell_block_tag_param(params) {
                Ok(t) => t,
                Err(e) => return err(id, -32602, e),
            };
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let want = tag.resolve(tip);
            // Known height = in the recent window (committed locally or adopted).
            let known_mem = st
                .recent_blocks
                .read()
                .await
                .iter()
                .any(|b| b.height == want);
            let known = known_mem
                || st
                    .archive_store
                    .as_ref()
                    .and_then(|s| s.header_at(want).ok().flatten())
                    .is_some();
            if !known {
                return err(id, -32004, "block transactions not available yet (height not adopted/replicated on this node)");
            }
            // Finalized-read cache: receipts for a finalized height are filed
            // once (before the height publishes — see `record_*` ordering) and
            // any late filing evicts via `record_receipts_with_events`. Only
            // non-empty answers are cached: a cached empty list could freeze
            // the window between "height known" and "receipts filed" (a late
            // adopted body only ever ADDS receipts). Errors bypass.
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            if want <= tip {
                if let Some(hit) =
                    finalized_read_cache_get("stell_getBlockTransactions", want, params, tip)
                {
                    return ok(id, hit);
                }
            }
            let idx = st.receipts.read().await;
            let mut rows: Vec<&TxReceipt> = idx.map.values().filter(|r| r.height == want).collect();
            rows.sort_by_key(|r| r.index);
            let list: Vec<Value> = rows
                .iter()
                .map(|r| {
                    let mut obj = json!({
                        "tx_hash": hex::encode(r.tx_hash),
                        "index": r.index,
                        "status": if r.success { "success" } else { "failed" },
                        "gas_limit": r.gas_limit.to_string(),
                        "fee_charged": r.fee_charged.to_string(),
                    });
                    if let Some(ref raw) = r.raw_tx {
                        obj["raw_tx"] = json!(raw);
                    }
                    obj
                })
                .collect();
            let v = json!({ "height": want, "txs": list });
            if want <= tip && !rows.is_empty() {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                finalized_read_cache_put(
                    "stell_getBlockTransactions",
                    want,
                    params,
                    tip,
                    v.clone(),
                );
            }
            ok(id, v)
        }

        // ---- epoch seal (asymmetric, threshold-sealed transactions) ----
        //
        // `stell_epochKey` is what a WALLET (or a light client) needs to
        // seal a transaction: the epoch's public key, the committee it is
        // bound to and the threshold that has to be met to unseal it. The
        // key is PUBLIC: it is what the wallet encrypts TO.
        "stell_epochKey" => {
            let pool = st.mempool.read().await;
            let manager = &pool.mev_seal;
            let Some(material) = manager.material() else {
                return err(
                    id,
                    -32010,
                    "no epoch key is available yet: the committee's key generation has not completed",
                );
            };
            let committee = manager.committee();
            let members: Vec<serde_json::Value> = committee
                .map(|c| {
                    c.members
                        .iter()
                        .map(|m| {
                            json!({
                                "validator_id": hex::encode(m.validator_id),
                                "enc_pk": hex::encode(m.enc_pk),
                                "contributor": c.is_contributor(c.index_of(&m.validator_id).unwrap_or(0)),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let contributors: Vec<u32> = committee
                .map(|c| c.contributors.clone())
                .unwrap_or_default();
            ok(
                id,
                json!({
                    "epoch": material.epoch,
                    "epoch_blocks": crate::mev_epoch::EPOCH_BLOCKS,
                    "public_key": hex::encode(material.public_key),
                    "committee_hash": hex::encode(material.committee_hash),
                    "transcript_root": hex::encode(material.transcript_root),
                    "threshold": material.threshold,
                    "committee": members,
                    "contributors": contributors,
                    // The commitment the BLOCK carries: a wallet (or a light
                    // client) checks the key it got here against the chain
                    // and refuses a key the network never committed to.
                    "commitment": hex::encode(material.commitment()),
                    "committed_by_chain": manager.committed_epoch_key.map(hex::encode),
                    "diverged": manager.epoch_key_diverged,
                    // The committee's AGREEMENT: the announcement carries the
                    // member signatures, so a client can check the quorum
                    // against the validator set and the commitment against
                    // the block.
                    "announcement_signatures": manager
                        .announcement()
                        .map(|a| a.valid_signature_count())
                        .unwrap_or(0),
                    "announcement_quorum": manager
                        .announcement()
                        .map(|a| a.has_quorum(a.threshold))
                        .unwrap_or(false),
                    "scheme": "stell-epoch-seal-v1 (ristretto255 threshold ECDH + xchacha20poly1305)",
                }),
            )
        }
        "stell_getBalance" => {
            let addr = match params.as_str().or_else(|| params["address"].as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            let a = match parse_addr_or_hash(addr) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let acc = st.engine.get_account(&a).await;
            let (bal, nonce) = acc.map(|x| (x.balance, x.nonce)).unwrap_or((0, 0));
            ok(id, json!({ "balance": bal.to_string(), "nonce": nonce }))
        }
        "stell_getBalanceSpv" => {
            // Returns balance + Merkle proof + state root so a light client can verify.
            let addr = match params["address"].as_str() {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            let a = match parse_addr_or_hash(addr) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let acc = st.engine.get_account(&a).await;
            let (balance, nonce) = acc.as_ref().map(|x| (x.balance, x.nonce)).unwrap_or((0, 0));
            let root = st.engine.get_state_root().await;
            let root_hex = hex::encode(root);
            let proof = st.engine.get_account_proof(&a).await;
            let leaf_data = acc.as_ref().map(|x| hex::encode(x.to_trie_bytes()));
            ok(
                id,
                json!({
                    "address": hex::encode(a),
                    "balance": balance.to_string(),
                    "nonce": nonce,
                    "stateRoot": root_hex,
                    "state_root": root_hex,
                    "leafData": leaf_data,
                    "leaf_data": leaf_data,
                    "proof": proof,
                }),
            )
        }
        // Merkle inclusion/exclusion proofs for an account and any number of
        // state-trie keys, anchored at the state root.
        "stell_getProof" => handle_get_proof(st, id, params).await,

        // ---- archive proofs: history, not the live trie ----
        //
        // `stell_getProof` answers for the CURRENT state only. These two arms
        // answer for HISTORY: a per-key proof rebuilt from the persisted
        // snapshot history, and the quorum-certified root that makes the
        // proof worth anything. Both fail closed (unknown / pruned /
        // above-tip heights are errors, never empty answers).
        "stell_getArchiveProof" => handle_get_archive_proof(st, id, params).await,
        "stell_getHistoricalRoot" => handle_get_historical_root(st, id, params).await,

        // ---- light client: the quorum-certified chain (audit W8.3) ----
        //
        // A light client needs the HEADER (with its precommit quorum
        // certificate) to make a served proof meaningful: the root a proof
        // authenticates against is only trustworthy if a QUORUM committed to
        // it, and the only evidence of that is the certificate on the header
        // that commits to it.
        //
        // The chain's convention: a header commits to the state BEFORE its own
        // block, so the header at height H commits to the state at H-1. The
        // node's live proofs are served against the CURRENT state, so the
        // header that commits to them is the one at height+1 — which is why
        // the CLI anchors a served proof with the header at `h+1`.
        "stell_getFinalizedHeader" => {
            let want = match params["height"].as_u64().or_else(|| params.as_u64()) {
                Some(h) => h,
                None => return err(id, -32602, "missing height"),
            };
            // Finalized-read cache: a quorum-certified header is immutable (any
            // republish evicts via `record_finalized_header`). Errors bypass:
            // a pruned/too-old height stays an honest miss.
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            if want <= tip {
                if let Some(hit) =
                    finalized_read_cache_get("stell_getFinalizedHeader", want, params, tip)
                {
                    return ok(id, hit);
                }
            }
            let store = finalized_headers();
            let hs = store.read().await;
            match hs.iter().find(|h| h.height == want) {
                Some(h) => {
                    let v = h.to_json();
                    if want <= tip {
                        let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                        finalized_read_cache_put(
                            "stell_getFinalizedHeader",
                            want,
                            params,
                            tip,
                            v.clone(),
                        );
                    }
                    ok(id, v)
                }
                None => err(
                    id,
                    -32004,
                    format!(
                        "finalized header at height {want} is not available on this node \
                         (it keeps the most recent {MAX_FINALIZED_HEADERS})"
                    ),
                ),
            }
        }
        // The node's LIGHT CLIENT anchor: the newest finalized header this
        // node has, with the quorum certificate that decided it. A client
        // that verifies this certificate against its own validator set has a
        // TRUSTED root — and the anchor is what it re-anchors on.
        "stell_getFinalizedCheckpoint" => {
            let store = finalized_headers();
            let hs = store.read().await;
            match hs.front() {
                Some(h) => ok(
                    id,
                    json!({
                        "height": h.height,
                        "block_hash": hex::encode(h.block_hash),
                        "prev_hash": hex::encode(h.prev_hash),
                        // The state root this header COMMITS TO (the state as
                        // of height-1 — see the chain convention above).
                        "state_root": hex::encode(h.state_root),
                        "proposer": hex::encode(h.proposer),
                        "timestamp": h.timestamp,
                        "shard_id": h.shard_id,
                        "round": h.round,
                        "body_commitment": h.body_commitment.map(hex::encode),
                        "mmr_epoch_root": hex::encode(h.mmr_epoch_root),
                        "epoch_key_commitment": hex::encode(h.epoch_key_commitment),
                        "cert": serde_json::to_value(&h.cert).unwrap_or(Value::Null),
                        // The node's own light-client view, for reference.
                        "trusted_root": hex::encode(h.state_root),
                        "trusted_height": h.height,
                    }),
                ),
                None => err(
                    id,
                    -32004,
                    "this node has not finalized a quorum-certified header yet",
                ),
            }
        }
        // The epoch MMR root (V5 Tier-2): the Merkle-Mountain-Range root over
        // one epoch's 128 finalized block hashes.
        //
        // `stell_getEpochRoot { epoch }` (or `{ height }`, which selects the
        // epoch containing that height, or a bare number, read as an epoch)
        // answers:
        //
        // ```json
        // { "epoch": 3, "start_height": 384, "end_height": 511,
        //   "mmr_root": "<hex>", "peaks": ["<hex>", ...],
        //   "complete": true, "leaves": 128,
        //   "committed_root": "<hex>|null", "committed_in_height": 512|null }
        // ```
        //
        // The root and peaks are RECOMPUTED here from this node's finalized
        // headers — they are only as trustworthy as this node. A light client
        // must check `mmr_root` against the quorum-signed commitment carried
        // by the first masterchain block of the NEXT epoch
        // (`Block::mmr_epoch_root`, served as `mmr_epoch_root` by
        // `stell_getFinalizedHeader` at `end_height + 1` and reported here as
        // `committed_root` when this node knows that header), and verify the
        // boundary block's QC against its OWN validator set first
        // (`light_client::verify_mmr_inclusion` does the proof half of this).
        //
        // `complete` is false while the epoch is still finalizing (or when
        // this node is missing heights): the root then covers only `leaves`
        // hashes and is NOT the epoch root. An epoch with no known heights
        // at all is refused with `-32004`, never fabricated.
        "stell_getEpochRoot" => {
            let epoch = match params
                .get("epoch")
                .and_then(|v| v.as_u64())
                .or_else(|| params.as_u64())
            {
                Some(e) => e,
                None => match params
                    .get("height")
                    .and_then(|v| v.as_u64())
                    .or_else(|| params.get(0).and_then(|v| v.as_u64()))
                {
                    Some(h) => crate::mmr::epoch_of_height(h),
                    None => return err(id, -32602, "missing epoch or height"),
                },
            };
            let start = crate::mmr::epoch_start(epoch);
            let end = crate::mmr::epoch_end(epoch);
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            // Finalized-read cache: a COMPLETE epoch with its quorum-signed
            // boundary commitment is immutable (any new header evicts all
            // epoch roots via `record_finalized_header`). Incomplete epochs
            // still finalize and errors can resolve, so only
            // complete-with-commitment answers are cached. Key height is the
            // epoch start (params-hash pins the exact request shape).
            if let Some(hit) = finalized_read_cache_get("stell_getEpochRoot", start, params, tip) {
                return ok(id, hit);
            }
            let store = finalized_headers();
            let hs = store.read().await;
            // The finalized block hashes of the epoch, in height order.
            let mut leaves: Vec<[u8; 32]> = Vec::new();
            for h in start..=end {
                if let Some(rec) = hs.iter().find(|r| r.height == h) {
                    leaves.push(rec.block_hash);
                }
            }
            if leaves.is_empty() {
                return err(
                    id,
                    -32004,
                    format!(
                        "epoch {epoch} (heights {start}..={end}) is not available on this node \
                         (it keeps the most recent {MAX_FINALIZED_HEADERS} finalized headers)"
                    ),
                );
            }
            let complete = leaves.len() == crate::mmr::MMR_EPOCH_BLOCKS as usize && tip >= end;
            let (root, peaks) = crate::mmr::mmr_root_for_leaves(&leaves);
            // The quorum-signed commitment, when this node knows the header
            // that carries it (the first block of the next epoch).
            let committed = hs.iter().find(|r| r.height == end + 1);
            let committed_root = committed.map(|r| hex::encode(r.mmr_epoch_root));
            let v = json!({
                "epoch": epoch,
                "start_height": start,
                "end_height": end,
                "mmr_root": hex::encode(root),
                "peaks": peaks.iter().map(hex::encode).collect::<Vec<_>>(),
                "complete": complete,
                "leaves": leaves.len(),
                "committed_root": committed_root,
                "committed_in_height": committed.map(|r| r.height),
            });
            if complete && committed.is_some() {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                finalized_read_cache_put("stell_getEpochRoot", start, params, tip, v.clone());
            }
            ok(id, v)
        }

        // ---- bridge disputes (optimistic L1; read-only for watchers) ----
        "stell_bridgeDeposit" => {
            // Deposit acceptance record by source-chain tx hash: recipient,
            // amount, admission path (quorum vs evidence), age, disputed flag.
            // No record (pre-dispute deposits) = unchallengeable, not missing.
            //
            // NAME (audit W7.2): this arm is the CANONICAL `stell_bridgeDeposit`
            // — the RECORD read. The native namespace's PREPARE of the same
            // deposit is `stell_bridgeDepositPrepare` (a different method
            // name), so the two can never shadow each other: the prepare arm
            // is reachable over JSON-RPC, and this one keeps its meaning.
            //
            // The guard below makes the split FAIL-CLOSED for a caller that
            // sends the PREPARE's parameters here: the read ignores unknown
            // parameters, so without it a prepare-shaped call would answer
            // `{"found": false}` — a plausible-looking answer for a deposit
            // that was never claimed. Refusing is the honest answer.
            const PREPARE_ONLY_PARAMS: &[&str] = &["chain", "recipient", "amount"];
            let prepare_shaped: Vec<&str> = PREPARE_ONLY_PARAMS
                .iter()
                .copied()
                .filter(|k| params.get(*k).is_some())
                .collect();
            if !prepare_shaped.is_empty() {
                return err(
                    id,
                    -32602,
                    format!(
                        "stell_bridgeDeposit is the deposit RECORD read; the parameters {} belong to the prepare method stell_bridgeDepositPrepare",
                        prepare_shaped.join(", ")
                    ),
                );
            }
            let h = match params
                .as_str()
                .or_else(|| params["source_tx_hash"].as_str())
            {
                Some(a) => a,
                None => return err(id, -32602, "missing source_tx_hash"),
            };
            let hash = match parse_hash(h) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let br = st.engine.bridge_read().await;
            match br.deposit_records.get(&hash) {
                None => ok(id, json!({ "found": false })),
                Some(r) => ok(
                    id,
                    json!({
                        "found": true,
                        "recipient": hex::encode(r.recipient),
                        "amount": r.amount.to_string(),
                        "chain": format!("{:?}", r.chain),
                        "via_quorum": r.via_quorum,
                        "deposited_at": r.deposited_at,
                        "disputed": r.disputed,
                    }),
                ),
            }
        }
        "stell_bridgeDispute" => {
            // Open or resolved dispute by id: full state for watcher
            // dashboards (deadline countdown, outcome).
            let did = match params.as_str().or_else(|| params["dispute_id"].as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing dispute_id"),
            };
            let did: u64 = match did.parse() {
                Ok(v) => v,
                Err(_) => return err(id, -32602, "bad dispute_id"),
            };
            let br = st.engine.bridge_read().await;
            match br.disputes.get(&did) {
                None => ok(id, json!({ "found": false })),
                Some(d) => ok(
                    id,
                    json!({
                        "found": true,
                        "dispute_id": did,
                        "source_tx_hash": hex::encode(d.source_tx_hash),
                        "challenger": hex::encode(d.challenger),
                        "recipient": hex::encode(d.recipient),
                        "amount": d.amount.to_string(),
                        "bond": d.bond.to_string(),
                        "deadline": d.deadline,
                        "resolved": d.resolved,
                        "confirmed": d.confirmed,
                    }),
                ),
            }
        }

        // ---- tokens ----
        "stell_tokenBalance" => {
            let token = params["token"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok());
            let account = params["account"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok());
            match (token, account) {
                (Some(t), Some(a)) => {
                    let bal = st.engine.token_balance(&t, &a).await;
                    ok(id, json!(bal.to_string()))
                }
                _ => err(id, -32602, "missing token/account"),
            }
        }
        "stell_tokenSupply" => {
            let token = match params["token"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok())
            {
                Some(t) => t,
                None => return err(id, -32602, "missing token"),
            };
            ok(
                id,
                json!(st
                    .engine
                    .token_total_supply(&token)
                    .await
                    .unwrap_or(0)
                    .to_string()),
            )
        }
        "stell_tokenResolve" => {
            // Read-only id discovery for tokens created on chain: the
            // create-tx receipt carries no token id, and the id commits the
            // registry nonce (unpredictable off chain), so clients resolve by
            // the (creator, name, symbol) they chose at creation.
            let creator = params["creator"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok());
            let name = params["name"].as_str().unwrap_or("");
            let symbol = params["symbol"].as_str().unwrap_or("");
            // Empty names widen collision/phishing surface (audit follow-up);
            // real tokens always carry both.
            if name.is_empty() || symbol.is_empty() {
                return err(id, -32602, "missing name/symbol");
            }
            match creator {
                Some(c) => match st.engine.token_resolve(&c, name, symbol).await {
                    Some(tid) => ok(id, json!({ "token": hex::encode(tid) })),
                    None => err(id, -32004, "token not found"),
                },
                None => err(id, -32602, "missing creator"),
            }
        }
        "stell_tokenBalanceSpv" => {
            let token = params["token"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok());
            let account = params["account"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok());
            match (token, account) {
                (Some(t), Some(a)) => {
                    let bal = st.engine.token_balance(&t, &a).await;
                    let root = st.engine.get_state_root().await;
                    let proof = st.engine.get_token_balance_proof(&t, &a).await;
                    let key = hex::encode(token_balance_key(&t, &a));
                    ok(
                        id,
                        json!({
                            "balance": bal.to_string(),
                            "stateRoot": hex::encode(root),
                            "key": key,
                            "proof": proof,
                        }),
                    )
                }
                _ => err(id, -32602, "missing token/account"),
            }
        }
        "stell_listTokens" => {
            // Paginated (audit 2026-10-06): creation is permissionless so the
            // registry is attacker-growable; an unbounded dump is a DoS
            // amplifier. Legacy default stays 100 (backward compatible), hard
            // cap is the shared `MAX_PAGE_LIMIT` (200). Cursor pages are a
            // strict keyset over the deterministic `BTreeMap`; `offset` stays
            // supported for old clients but is bounded by
            // `MAX_TOKENS_SORT_CAP`.
            let p = params_object(params);
            let limit = page_limit_param(p, 100, MAX_PAGE_LIMIT);
            let cursor: Option<[u8; 32]> = match p.get("cursor").or_else(|| p.get("last_token_id"))
            {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_str() {
                    Some(s) => match parse_hash(s) {
                        Ok(c) => Some(c),
                        Err(e) => return err(id, -32602, format!("invalid cursor: {e}")),
                    },
                    None => return err(id, -32602, "invalid cursor: expected hex string"),
                },
            };
            let offset = p.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

            let tokens = st.engine.tokens_read().await;
            let total = tokens.token_count();
            let page = tokens.token_ids_page(cursor, offset, limit);
            let ids: Vec<String> = page.items.iter().map(hex::encode).collect();
            let next_cursor = page.next_cursor.map(hex::encode);
            if cursor.is_some() {
                ok(
                    id,
                    json!({
                        "tokens": ids,
                        "total": total,
                        "next_cursor": next_cursor,
                        "has_more": page.has_more,
                        "truncated": page.truncated,
                    }),
                )
            } else {
                ok(
                    id,
                    json!({
                        "tokens": ids,
                        "total": total,
                        "offset": offset,
                        "next_cursor": next_cursor,
                        "has_more": page.has_more,
                        "truncated": page.truncated,
                    }),
                )
            }
        }

        // ---- receipts (P0-3) ----
        // Without these a wallet can only ask "is my hash in the mempool", and
        // can never learn whether its transaction was finalised or failed.
        // Params accept all three common shapes: `{"hash": h}`, `h`, `[h]`.
        "stell_getTransactionReceipt" => {
            let h = match tx_hash_param(params) {
                Some(h) => h,
                None => return err(id, -32602, "missing tx hash"),
            };
            let idx = st.receipts.read().await;
            match idx.get(&h) {
                Some(r) => {
                    // E1 confirmations rule: depth of the inclusion block
                    // under the node's current finalized head, inclusion
                    // block included (1 at finality — single-block BFT
                    // finality means finality already holds there; depth
                    // buys operational assurance, never safety — see the
                    // "Confirmations" tiers in RPC.md).
                    let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
                    let confirmations = head.saturating_sub(r.height).saturating_add(1);
                    let mut obj = json!({
                        "tx_hash": hex::encode(r.tx_hash),
                        "height": r.height,
                        "block_hash": hex::encode(r.block_hash),
                        "index": r.index,
                        "status": if r.success { "success" } else { "failed" },
                        "gas_limit": r.gas_limit.to_string(),
                        "fee_charged": r.fee_charged.to_string(),
                        "confirmations": confirmations,
                    });
                    if let Some(ref raw) = r.raw_tx {
                        obj["raw_tx"] = json!(raw);
                    }
                    if let Some(ref addr) = r.contract_address {
                        obj["contract_address"] = json!(hex::encode(addr));
                        obj["contract_address_stl57"] =
                            json!(crate::address::encode_stl57_address(addr));
                    }
                    if r.return_value.is_some() || r.gas_used.is_some() {
                        obj["return_value"] = match r.return_value {
                            Some(val) => json!(val),
                            None => Value::Null,
                        };
                        obj["gas_used"] = json!(r.gas_used.unwrap_or(0));
                    }
                    let events_view: Vec<Value> = r
                        .events
                        .iter()
                        .map(|e| {
                            json!({
                                "contract": hex::encode(e.contract),
                                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                                "topic": e.topic,
                                "value": e.value,
                            })
                        })
                        .collect();
                    obj["events"] = json!(events_view);
                    ok(id, obj)
                }
                None => {
                    drop(idx);
                    if let Some(sr) = st
                        .archive_store
                        .as_ref()
                        .and_then(|s| s.get_receipt(&h).ok().flatten())
                    {
                        let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
                        let confirmations = head.saturating_sub(sr.height).saturating_add(1);
                        return ok(
                            id,
                            json!({
                                "tx_hash": hex::encode(sr.tx_hash),
                                "height": sr.height,
                                "block_hash": hex::encode(sr.block_hash),
                                "index": sr.index,
                                "status": if sr.success { "success" } else { "failed" },
                                "gas_limit": sr.gas_limit.to_string(),
                                "fee_charged": sr.fee_charged.to_string(),
                                "confirmations": confirmations,
                                "events": [],
                            }),
                        );
                    }
                    let pending = st.mempool.read().await.contains(&h);
                    ok(
                        id,
                        json!({ "status": if pending { "pending" } else { "unknown" } }),
                    )
                }
            }
        }
        // Transaction lookup by hash (native namespace).
        //
        // Without this a wallet had to use `eth_getTransactionByHash`, whose
        // shape is EVM-only. Serve the native view from the SAME sources the
        // receipt/status reads use: finalized receipt index (live filings carry
        // the body; restart-hydrated receipts resolve it from the committed
        // block body), then the mempool, else an honest `unknown`.
        //
        // Never fabricates: if the receipt exists but this node holds neither
        // the raw bytes nor the block body (e.g. the body was pruned), the
        // identity fields are `null` and `body_available: false` says why.
        // EVM intent hashes are accepted too and resolve through the same
        // bidirectional settlement map as `eth_getTransactionReceipt`.
        "stell_getTransactionByHash" => {
            let h = match tx_hash_param(params) {
                Some(h) => h,
                None => return err(id, -32602, "missing tx hash"),
            };
            let queried = format!("0x{}", hex::encode(h));
            let lookup = crate::evm_adapter::evm_to_stell_hash(&queried).unwrap_or(h);
            let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let receipt = st.receipts.read().await.get(&lookup).cloned();
            if let Some(r) = receipt {
                let body = receipt_body_tx(st, &r).await;
                let confirmations = head.saturating_sub(r.height).saturating_add(1);
                let mut obj = json!({
                    "tx_hash": hex::encode(r.tx_hash),
                    "status": if r.success { "success" } else { "failed" },
                    "height": r.height,
                    "block_hash": hex::encode(r.block_hash),
                    "index": r.index,
                    "confirmations": confirmations,
                    "gas_limit": r.gas_limit.to_string(),
                    "fee_charged": r.fee_charged.to_string(),
                    "body_available": body.is_some(),
                });
                if queried != format!("0x{}", hex::encode(r.tx_hash)) {
                    obj["evm_hash"] = json!(queried);
                }
                if let Some(ref raw) = r.raw_tx {
                    obj["raw_tx"] = json!(raw);
                }
                match body {
                    Some(tx) => {
                        obj["from"] = json!(hex::encode(tx.from));
                        obj["to"] = json!(hex::encode(tx.to));
                        obj["amount"] = json!(tx.amount.to_string());
                        obj["nonce"] = json!(tx.nonce);
                        obj["source_shard"] = json!(tx.source_shard);
                        obj["target_shard"] = json!(tx.target_shard);
                        obj["payload_ops"] = json!(tx.payload.len());
                    }
                    None => {
                        obj["from"] = Value::Null;
                        obj["to"] = Value::Null;
                        obj["amount"] = Value::Null;
                        obj["nonce"] = Value::Null;
                    }
                }
                return ok(id, obj);
            }
            let pending_tx = st.mempool.read().await.get(&lookup).cloned();
            if let Some(tx) = pending_tx {
                return ok(
                    id,
                    json!({
                        "tx_hash": hex::encode(lookup),
                        "status": "pending",
                        "height": Value::Null,
                        "block_hash": Value::Null,
                        "index": Value::Null,
                        "confirmations": 0,
                        "from": hex::encode(tx.from),
                        "to": hex::encode(tx.to),
                        "amount": tx.amount.to_string(),
                        "nonce": tx.nonce,
                        "gas_limit": tx.gas_limit.to_string(),
                        "fee_charged": Value::Null,
                        "source_shard": tx.source_shard,
                        "target_shard": tx.target_shard,
                        "payload_ops": tx.payload.len(),
                        "body_available": true,
                    }),
                );
            }
            ok(id, json!({ "status": "unknown" }))
        }
        "stell_getEvents" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };

            let tx_hash_opt = p
                .get("tx_hash")
                .or_else(|| p.get("txHash"))
                .or_else(|| p.get("hash"))
                .and_then(|v| v.as_str())
                .or_else(|| p.as_str());

            if let Some(hash_str) = tx_hash_opt {
                let h = match parse_hash(hash_str) {
                    Ok(h) => h,
                    Err(e) => return err(id, -32602, format!("invalid tx_hash: {e}")),
                };
                let idx = st.receipts.read().await;
                if let Some(r) = idx.get(&h) {
                    let events_view: Vec<Value> = r
                        .events
                        .iter()
                        .map(|e| {
                            json!({
                                "contract": hex::encode(e.contract),
                                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                                "topic": e.topic,
                                "value": e.value,
                            })
                        })
                        .collect();
                    return ok(id, json!(events_view));
                }
                return ok(id, json!([]));
            }

            if let Some(contract_val) = p.get("contract").or_else(|| p.get("address")) {
                let contract_str = match contract_val.as_str() {
                    Some(s) => s,
                    None => return err(id, -32602, "invalid contract parameter: must be a string"),
                };
                let contract_addr = match parse_rpc_address(contract_str) {
                    Ok(a) => a,
                    Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
                };

                let parse_block_num = |val: Option<&Value>| -> Option<u64> {
                    val.and_then(|v| {
                        v.as_u64().or_else(|| {
                            v.as_str().and_then(|s| {
                                let s = s
                                    .strip_prefix("0x")
                                    .or_else(|| s.strip_prefix("0X"))
                                    .unwrap_or(s);
                                u64::from_str_radix(s, 16)
                                    .ok()
                                    .or_else(|| s.parse::<u64>().ok())
                            })
                        })
                    })
                };

                let from_block =
                    parse_block_num(p.get("from_block").or_else(|| p.get("fromBlock")))
                        .unwrap_or(0);
                let to_block = parse_block_num(p.get("to_block").or_else(|| p.get("toBlock")))
                    .unwrap_or(u64::MAX);
                let topic_filter = p.get("topic").and_then(parse_i64_loose);
                let cursor = match event_cursor_param(p) {
                    Ok(c) => c,
                    Err(e) => return err(id, -32602, e),
                };
                let paginated = cursor.is_some() || bool_param(p, "paginated", false);

                if paginated {
                    // Cursor pagination (W4 E3): merge the fresh in-memory
                    // receipt index with the durable `events_by_contract`
                    // index, tip-first, dedupe by `(height, tx_index,
                    // log_index)` and resume strictly older than `cursor`.
                    let limit = page_limit_param(p, DEFAULT_PAGE_LIMIT, STORAGE_HISTORY_MAX_LIMIT);
                    let mut combined: Vec<EventHistoryRow> = Vec::new();
                    let mut scanned = 0usize;
                    let mut mem_truncated = false;
                    {
                        let idx = st.receipts.read().await;
                        'receipts: for r in
                            idx.for_contract_events(&contract_addr, from_block, to_block, true)
                        {
                            for (log_index, e) in r.events.iter().enumerate() {
                                if scanned >= STORAGE_SCAN_HARD_CAP {
                                    mem_truncated = true;
                                    break 'receipts;
                                }
                                scanned += 1;
                                if e.contract != contract_addr {
                                    continue;
                                }
                                if topic_filter.map(|t| t != e.topic).unwrap_or(false) {
                                    continue;
                                }
                                if !older_than_event(cursor, r.height, r.index, log_index as u32) {
                                    continue;
                                }
                                combined.push((
                                    r.height,
                                    r.index,
                                    log_index as u32,
                                    r.tx_hash,
                                    e.topic,
                                    e.value,
                                ));
                            }
                        }
                    }
                    let mut archive_more = false;
                    let mut archive_truncated = false;
                    let mut archive_next = None;
                    if let Some(store) = st.archive_store.as_ref() {
                        match store.events_by_contract_range(
                            &contract_addr,
                            from_block,
                            to_block,
                            topic_filter,
                            cursor,
                            limit,
                        ) {
                            Ok(page) => {
                                archive_more = page.has_more;
                                archive_truncated = page.scan_truncated;
                                archive_next = page.next_cursor;
                                scanned += page.scanned;
                                for item in page.items {
                                    combined.push((
                                        item.height,
                                        item.tx_index,
                                        item.log_index,
                                        item.tx_hash,
                                        item.topic,
                                        item.value,
                                    ));
                                }
                            }
                            Err(e) => {
                                return err(id, -32000, format!("event index read failed: {e}"))
                            }
                        }
                    }
                    combined.sort_unstable_by_key(|r| {
                        (
                            std::cmp::Reverse(r.0),
                            std::cmp::Reverse(r.1),
                            std::cmp::Reverse(r.2),
                        )
                    });
                    combined.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2);
                    let more_local = combined.len() > limit;
                    combined.truncate(limit);
                    let scan_truncated = archive_truncated || mem_truncated;
                    let has_more = more_local || archive_more || scan_truncated;
                    let next_cursor = if has_more {
                        combined
                            .last()
                            .map(|(h, i, l, _, _, _)| {
                                crate::storage::EventCursor {
                                    height: *h,
                                    tx_index: *i,
                                    log_index: *l,
                                }
                                .to_hex()
                            })
                            .or_else(|| archive_next.map(|c| c.to_hex()))
                    } else {
                        None
                    };
                    let events_view: Vec<Value> = combined
                        .into_iter()
                        .map(|(_, _, _, tx_hash, topic, value)| {
                            json!({
                                "contract": hex::encode(contract_addr),
                                "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                                "tx_hash": hex::encode(tx_hash),
                                "topic": topic,
                                "value": value,
                            })
                        })
                        .collect();
                    return ok(
                        id,
                        json!({
                            "events": events_view,
                            "next_cursor": next_cursor,
                            "has_more": has_more,
                            "scanned": scanned,
                            "scan_truncated": scan_truncated,
                        }),
                    );
                }

                // Optional answer cap. The receipt index holds up to
                // `MAX_RECEIPTS` (50 000) receipts and every receipt can carry
                // up to `MAX_CONTRACT_EVENTS` (256) events, so an unfiltered
                // contract query could answer with MILLIONS of events — an
                // unbounded response body and an unbounded JSON build on an
                // unauthenticated read. The ANSWER is capped (the response
                // shape stays the documented ARRAY), and the caller may ask
                // for a different cap with `limit`.
                let limit = p
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
                    .unwrap_or(MAX_EVENTS_RETURNED)
                    .min(MAX_EVENTS_RETURNED);

                let idx = st.receipts.read().await;
                let matched_receipts =
                    idx.for_contract_events(&contract_addr, from_block, to_block, false);

                let mut matched_events: Vec<Value> = Vec::new();
                'scan: for r in matched_receipts {
                    for e in &r.events {
                        if e.contract != contract_addr {
                            continue;
                        }
                        if topic_filter.map(|t| t != e.topic).unwrap_or(false) {
                            continue;
                        }
                        if matched_events.len() >= limit {
                            break 'scan;
                        }
                        matched_events.push(json!({
                            "contract": hex::encode(e.contract),
                            "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                            "topic": e.topic,
                            "value": e.value,
                        }));
                    }
                }
                drop(idx);
                // Cold node (no in-memory events for this range): backfill the
                // legacy ARRAY answer from the durable index, oldest first, so
                // the historical shape and ordering stay unchanged.
                if matched_events.is_empty() {
                    let backfill = st.archive_store.as_ref().and_then(|store| {
                        store
                            .events_by_contract_range(
                                &contract_addr,
                                from_block,
                                to_block,
                                topic_filter,
                                None,
                                limit,
                            )
                            .ok()
                    });
                    if let Some(page) = backfill {
                        matched_events = page
                            .items
                            .into_iter()
                            .rev()
                            .map(|item| {
                                json!({
                                    "contract": hex::encode(item.contract),
                                    "contract_stl57": crate::address::encode_stl57_address(&item.contract),
                                    "topic": item.topic,
                                    "value": item.value,
                                })
                            })
                            .collect();
                    }
                }
                return ok(id, json!(matched_events));
            }

            err(id, -32602, "missing 'tx_hash' or 'contract' parameter")
        }
        "stell_getAddressHistory" => {
            // Read-only address history: durable `tx_by_addr` (tip-first) merged
            // with the fresh in-memory receipt window, deduped by tx hash.
            let p = params_object(params);
            let address = match p.get("address").or_else(|| p.get("addr")) {
                Some(Value::String(s)) => match parse_rpc_address(s) {
                    Ok(a) => a,
                    Err(e) => return err(id, -32602, format!("invalid address: {e}")),
                },
                _ => return err(id, -32602, "missing address"),
            };
            let from_height = match optional_u64_param(p, &["from_height", "fromHeight"]) {
                Ok(v) => v.unwrap_or(0),
                Err(e) => return err(id, -32602, e),
            };
            let to_height = match optional_u64_param(p, &["to_height", "toHeight"]) {
                Ok(v) => v.unwrap_or(u64::MAX),
                Err(e) => return err(id, -32602, e),
            };
            let role = match p.get("role").and_then(Value::as_str) {
                None | Some("all") => crate::storage::HistoryRole::All,
                Some(s) => match crate::storage::HistoryRole::parse(s) {
                    Some(r) => r,
                    None => {
                        return err(
                            id,
                            -32602,
                            "invalid role: expected all | sender | recipient",
                        )
                    }
                },
            };
            let cursor = match history_cursor_param(p) {
                Ok(c) => c,
                Err(e) => return err(id, -32602, e),
            };
            let limit = page_limit_param(p, DEFAULT_PAGE_LIMIT, STORAGE_HISTORY_MAX_LIMIT);

            let mut items: Vec<crate::storage::AddressHistoryItem> = Vec::new();
            let mut scanned = 0usize;
            let mut scan_truncated = false;
            let mut archive_more = false;
            let mut archive_next = None;
            if let Some(store) = st.archive_store.as_ref() {
                match store.address_history(&address, from_height, to_height, role, cursor, limit) {
                    Ok(page) => {
                        scanned += page.scanned;
                        scan_truncated = page.scan_truncated;
                        archive_more = page.has_more;
                        archive_next = page.next_cursor;
                        items.extend(page.items);
                    }
                    Err(e) => return err(id, -32000, format!("address history read failed: {e}")),
                }
            }
            // Fresh in-memory window: receipts filed since the last durable
            // flush (or on a node with no archive store attached at all).
            let fresh: Vec<TxReceipt> = {
                let idx = st.receipts.read().await;
                idx.map
                    .values()
                    .filter(|r| r.height >= from_height && r.height <= to_height)
                    .take(STORAGE_SCAN_HARD_CAP)
                    .cloned()
                    .collect()
            };
            for r in fresh {
                scanned += 1;
                if r.height < from_height || r.height > to_height {
                    continue;
                }
                if !older_than_history(cursor, r.height, r.index) {
                    continue;
                }
                let meta = receipt_history_meta(&r);
                if !history_role_matches(role, &address, meta.as_ref()) {
                    continue;
                }
                items.push(crate::storage::AddressHistoryItem {
                    tx_hash: r.tx_hash,
                    height: r.height,
                    tx_index: r.index,
                    meta,
                });
            }
            items.sort_by_key(|item| {
                (
                    std::cmp::Reverse(item.height),
                    std::cmp::Reverse(item.tx_index),
                )
            });
            items.dedup_by(|a, b| a.tx_hash == b.tx_hash);
            let more_local = items.len() > limit;
            items.truncate(limit);
            // Fill a missing in-memory timestamp from the prune-surviving
            // header record (bounded by the page size).
            if let Some(store) = st.archive_store.as_ref() {
                for item in items.iter_mut() {
                    let Some(meta) = item.meta.as_mut() else {
                        continue;
                    };
                    if meta.timestamp == 0 {
                        meta.timestamp = store
                            .header_at(item.height)
                            .ok()
                            .flatten()
                            .map(|h| h.timestamp)
                            .unwrap_or(0);
                    }
                }
            }
            let has_more = more_local || archive_more || scan_truncated;
            let next_cursor = if has_more {
                items
                    .last()
                    .map(|item| {
                        crate::storage::HistoryCursor {
                            height: item.height,
                            tx_index: item.tx_index,
                        }
                        .to_hex()
                    })
                    .or_else(|| archive_next.map(|c| c.to_hex()))
            } else {
                None
            };
            let items_view: Vec<Value> = items
                .iter()
                .map(|item| {
                    json!({
                        "tx_hash": hex::encode(item.tx_hash),
                        "height": item.height,
                        "tx_index": item.tx_index,
                        "from": item.meta.map(|m| hex::encode(m.from)),
                        "to": item.meta.map(|m| hex::encode(m.to)),
                        "amount": item.meta.map(|m| m.amount.to_string()),
                        "shard_id": item.meta.map(|m| m.shard_id),
                        "timestamp": item.meta.map(|m| m.timestamp),
                    })
                })
                .collect();
            ok(
                id,
                json!({
                    "address": hex::encode(address),
                    "address_stl57": crate::address::encode_stl57_address(&address),
                    "items": items_view,
                    "next_cursor": next_cursor,
                    "has_more": has_more,
                    "scanned": scanned,
                    "scan_truncated": scan_truncated,
                }),
            )
        }
        "stell_getProgramAccounts" => {
            // Bounded `getProgramAccounts` analogue. Every branch is a
            // deterministic keyset page; the unfiltered `system` dump is
            // REFUSED because it would be an account enumeration oracle.
            let p = params_object(params);
            let program = match p.get("program").and_then(Value::as_str) {
                Some(s) if s == "token" || s == "contract" || s == "system" => s,
                Some(_) => {
                    return err(
                        id,
                        -32602,
                        "invalid program: expected token | contract | system",
                    )
                }
                None => return err(id, -32602, "missing program"),
            };
            let with_proof = bool_param(p, "with_proof", false);
            let mut limit = page_limit_param(p, DEFAULT_PAGE_LIMIT, MAX_PROGRAM_ACCOUNTS_LIMIT);
            if with_proof {
                limit = limit.min(MAX_PROGRAM_ACCOUNTS_PROOFS);
            }
            let include_zero = bool_param(p, "include_zero", false);

            let mut entries: Vec<(Value, String)> = Vec::new();
            let mut has_more: bool;
            let mut scanned: usize;
            let mut scan_truncated: bool;
            let next_in: Option<String>;

            if program == "token" {
                let token_filter = match optional_addr_param(p, "token") {
                    Ok(v) => v,
                    Err(e) => return err(id, -32602, e),
                };
                let owner_filter = match optional_addr_param(p, "owner") {
                    Ok(v) => v,
                    Err(e) => return err(id, -32602, e),
                };
                if token_filter.is_none() && owner_filter.is_none() {
                    return err(id, -32602, "token program requires `token` or `owner`");
                }
                let min_balance = match optional_u64_param(p, &["min_balance", "minBalance"]) {
                    Ok(v) => v.unwrap_or(0),
                    Err(e) => return err(id, -32602, e),
                };
                let cursor = match p.get("cursor") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => match parse_hash(s) {
                        Ok(c) => Some(c),
                        Err(e) => return err(id, -32602, format!("invalid cursor: {e}")),
                    },
                    Some(_) => return err(id, -32602, "invalid cursor: expected hex string"),
                };
                let tokens = st.engine.tokens_read().await;
                if let Some(tid) = token_filter {
                    let Some(actor) = tokens.get(&tid) else {
                        return err(id, -32004, "unknown token");
                    };
                    let page = tokens.token_holders_page(
                        &tid,
                        min_balance,
                        include_zero,
                        cursor,
                        limit,
                        MAX_PROGRAM_ACCOUNTS_SCAN,
                    );
                    scanned = page.scanned;
                    scan_truncated = page.truncated;
                    has_more = page.has_more;
                    next_in = page.next_cursor.map(hex::encode);
                    for holding in page.items {
                        if owner_filter.is_some_and(|owner| holding.holder != owner) {
                            continue;
                        }
                        let mut item = json!({
                            "program": "token",
                            "token": hex::encode(tid),
                            "token_stl57": crate::address::encode_stl57_address(&tid),
                            "owner": hex::encode(holding.holder),
                            "owner_stl57": crate::address::encode_stl57_address(&holding.holder),
                            "balance": holding.balance.to_string(),
                            "decimals": actor.metadata.decimals,
                            "symbol": actor.metadata.symbol,
                            "name": actor.metadata.name,
                        });
                        if with_proof {
                            item["proof"] = serde_json::to_value(
                                st.engine
                                    .get_token_balance_proof(&tid, &holding.holder)
                                    .await,
                            )
                            .unwrap_or(Value::Null);
                        }
                        entries.push((item, hex::encode(holding.holder)));
                    }
                } else {
                    let owner = owner_filter.expect("checked above");
                    let page = tokens.owner_token_page(
                        &owner,
                        None,
                        include_zero,
                        cursor,
                        limit,
                        MAX_PROGRAM_ACCOUNTS_SCAN,
                    );
                    scanned = page.scanned;
                    scan_truncated = page.truncated;
                    has_more = page.has_more;
                    next_in = page.next_cursor.map(hex::encode);
                    for holding in page.items {
                        let Some(actor) = tokens.get(&holding.token_id) else {
                            continue;
                        };
                        let mut item = json!({
                            "program": "token",
                            "token": hex::encode(holding.token_id),
                            "token_stl57": crate::address::encode_stl57_address(&holding.token_id),
                            "owner": hex::encode(owner),
                            "owner_stl57": crate::address::encode_stl57_address(&owner),
                            "balance": holding.balance.to_string(),
                            "decimals": actor.metadata.decimals,
                            "symbol": actor.metadata.symbol,
                            "name": actor.metadata.name,
                        });
                        if with_proof {
                            item["proof"] = serde_json::to_value(
                                st.engine
                                    .get_token_balance_proof(&holding.token_id, &owner)
                                    .await,
                            )
                            .unwrap_or(Value::Null);
                        }
                        entries.push((item, hex::encode(holding.token_id)));
                    }
                }
            } else if program == "contract" {
                let contract_filter = match optional_addr_param(p, "contract") {
                    Ok(v) => v,
                    Err(e) => return err(id, -32602, e),
                };
                let creator_filter = match optional_addr_param(p, "creator") {
                    Ok(v) => v,
                    Err(e) => return err(id, -32602, e),
                };
                let include_code = bool_param(p, "include_code", false);
                let contracts = st.engine.contracts_read().await;
                if let Some(addr) = contract_filter {
                    if !contracts.contracts.contains_key(&addr) {
                        return err(id, -32004, "unknown contract");
                    }
                    let slot_from = match optional_i64_param(p, &["slot_from", "slotFrom"]) {
                        Ok(v) => v,
                        Err(e) => return err(id, -32602, e),
                    };
                    let slot_to = match optional_i64_param(p, &["slot_to", "slotTo"]) {
                        Ok(v) => v,
                        Err(e) => return err(id, -32602, e),
                    };
                    let cursor = match p.get("cursor") {
                        None | Some(Value::Null) => None,
                        Some(v) => match parse_i64_loose(v) {
                            Some(c) => Some(c),
                            None => {
                                return err(
                                    id,
                                    -32602,
                                    "invalid cursor: expected an integer slot key",
                                )
                            }
                        },
                    };
                    let page = contracts.storage_page(
                        &addr,
                        slot_from,
                        slot_to,
                        cursor,
                        limit,
                        MAX_PROGRAM_ACCOUNTS_SCAN,
                    );
                    scanned = page.scanned;
                    scan_truncated = page.truncated;
                    has_more = page.has_more;
                    next_in = page.next_cursor.map(|c| c.to_string());
                    for slot in page.items {
                        let mut item = json!({
                            "program": "contract",
                            "contract": hex::encode(addr),
                            "contract_stl57": crate::address::encode_stl57_address(&addr),
                            "slot": slot.slot.to_string(),
                            "value": slot.value.to_string(),
                        });
                        if with_proof {
                            // Storage slots are committed by the contract
                            // digest, not individual trie leaves: say so
                            // instead of attaching a proof that does not
                            // cover the slot.
                            item["proof"] = Value::Null;
                            item["proof_note"] = json!(
                                "storage slots are committed by the contract digest; use stell_getArchiveProof for the contract code/ABI leaf"
                            );
                        }
                        entries.push((item, slot.slot.to_string()));
                    }
                } else if let Some(creator) = creator_filter {
                    let cursor = match p.get("cursor") {
                        None | Some(Value::Null) => None,
                        Some(Value::String(s)) => match parse_hash(s) {
                            Ok(c) => Some(c),
                            Err(e) => return err(id, -32602, format!("invalid cursor: {e}")),
                        },
                        Some(_) => return err(id, -32602, "invalid cursor: expected hex string"),
                    };
                    let page = contracts.contracts_by_creator_page(
                        &creator,
                        cursor,
                        limit,
                        MAX_PROGRAM_ACCOUNTS_SCAN,
                    );
                    scanned = page.scanned;
                    scan_truncated = page.truncated;
                    has_more = page.has_more;
                    next_in = page.next_cursor.map(hex::encode);
                    for summary in page.items {
                        let mut item = json!({
                            "program": "contract",
                            "contract": hex::encode(summary.address),
                            "contract_stl57": crate::address::encode_stl57_address(&summary.address),
                            "creator": hex::encode(summary.creator),
                            "creator_stl57": crate::address::encode_stl57_address(&summary.creator),
                            "code_hash": hex::encode(summary.code_hash),
                            "created_at": summary.created_at,
                            "paused": summary.paused,
                            "balance": summary.balance.to_string(),
                            "storage_len": summary.storage_len,
                            "has_abi": summary.has_abi,
                            "source_hash": summary.source_hash.map(hex::encode),
                        });
                        if include_code {
                            let code = contracts
                                .contracts
                                .get(&summary.address)
                                .map(|c| hex::encode(&c.code));
                            item["code"] = code.map(Value::String).unwrap_or(Value::Null);
                        }
                        if with_proof {
                            item["proof"] = serde_json::to_value(
                                st.engine.get_account_proof(&summary.address).await,
                            )
                            .unwrap_or(Value::Null);
                        }
                        entries.push((item, hex::encode(summary.address)));
                    }
                } else {
                    return err(
                        id,
                        -32602,
                        "contract program requires `contract` or `creator`",
                    );
                }
            } else {
                // system
                let owner = match optional_addr_param(p, "owner") {
                    Ok(v) => v,
                    Err(e) => return err(id, -32602, e),
                };
                let min_balance = match optional_u64_param(p, &["min_balance", "minBalance"]) {
                    Ok(v) => v.unwrap_or(0),
                    Err(e) => return err(id, -32602, e),
                };
                let cursor = match optional_addr_param(p, "cursor") {
                    Ok(v) => v,
                    Err(e) => return err(id, -32602, e),
                };
                if owner.is_none() && min_balance == 0 && cursor.is_none() {
                    return err(
                        id,
                        -32602,
                        "refusing an unfiltered system dump: pass `owner`, `min_balance` > 0, or an explicit `cursor`",
                    );
                }
                has_more = false;
                scanned = 0;
                scan_truncated = false;
                let snapshot = st.engine.capture_state_snapshot().await;
                let mut last_scanned: Option<String> = None;
                for account in snapshot.accounts {
                    if scanned >= MAX_PROGRAM_ACCOUNTS_SCAN {
                        scan_truncated = true;
                        break;
                    }
                    scanned += 1;
                    last_scanned = Some(hex::encode(account.address));
                    if cursor.map(|c| account.address <= c).unwrap_or(false) {
                        continue;
                    }
                    if owner.is_some_and(|owner| account.address != owner) {
                        continue;
                    }
                    if account.balance < min_balance {
                        continue;
                    }
                    if entries.len() >= limit {
                        has_more = true;
                        break;
                    }
                    let mut item = json!({
                        "program": "system",
                        "address": hex::encode(account.address),
                        "address_stl57": crate::address::encode_stl57_address(&account.address),
                        "balance": account.balance.to_string(),
                        "nonce": account.nonce,
                        "scheme": account.scheme,
                        "code_hash": account.code_hash.map(hex::encode),
                    });
                    if with_proof {
                        item["proof"] = serde_json::to_value(
                            st.engine.get_account_proof(&account.address).await,
                        )
                        .unwrap_or(Value::Null);
                    }
                    entries.push((item, hex::encode(account.address)));
                }
                if scan_truncated {
                    has_more = true;
                }
                next_in = if has_more {
                    entries.last().map(|(_, c)| c.clone()).or(last_scanned)
                } else {
                    None
                };
            }

            // Response-size cap: drop trailing items rather than build an
            // unbounded body; a dropped tail flips `has_more` on.
            let mut items_view: Vec<Value> = Vec::new();
            let mut bytes = 0usize;
            let mut trimmed = false;
            let mut last_cursor: Option<String> = None;
            for (item, cursor) in entries {
                let n = serde_json::to_vec(&item).map_or(0, |b| b.len());
                if bytes + n > MAX_PROGRAM_ACCOUNTS_RESPONSE_BYTES {
                    trimmed = true;
                    break;
                }
                bytes += n;
                last_cursor = Some(cursor);
                items_view.push(item);
            }
            if trimmed && items_view.is_empty() {
                return err(
                    id,
                    -32602,
                    "response exceeds MAX_PROGRAM_ACCOUNTS_RESPONSE_BYTES; reduce limit or disable include_code",
                );
            }
            let has_more = has_more || trimmed;
            let next_cursor = if has_more {
                last_cursor.or(next_in)
            } else {
                None
            };
            ok(
                id,
                json!({
                    "program": program,
                    "items": items_view,
                    "next_cursor": next_cursor,
                    "has_more": has_more,
                    "scanned": scanned,
                    "scan_truncated": scan_truncated,
                }),
            )
        }
        "stell_getTokenAccountsByOwner" => {
            let p = params_object(params);
            let owner = match optional_addr_param(p, "owner") {
                Ok(Some(a)) => a,
                Ok(None) => return err(id, -32602, "missing owner"),
                Err(e) => return err(id, -32602, e),
            };
            let token = match optional_addr_param(p, "token") {
                Ok(v) => v,
                Err(e) => return err(id, -32602, e),
            };
            let include_zero = bool_param(p, "include_zero", false);
            let cursor = match p.get("cursor") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => match parse_hash(s) {
                    Ok(c) => Some(c),
                    Err(e) => return err(id, -32602, format!("invalid cursor: {e}")),
                },
                Some(_) => return err(id, -32602, "invalid cursor: expected hex string"),
            };
            let limit = page_limit_param(p, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
            let tokens = st.engine.tokens_read().await;
            let page = tokens.owner_token_page(
                &owner,
                token,
                include_zero,
                cursor,
                limit,
                MAX_PROGRAM_ACCOUNTS_SCAN,
            );
            let items_view: Vec<Value> = page
                .items
                .iter()
                .filter_map(|holding| {
                    let actor = tokens.get(&holding.token_id)?;
                    Some(json!({
                        "token": hex::encode(holding.token_id),
                        "token_stl57": crate::address::encode_stl57_address(&holding.token_id),
                        "owner": hex::encode(owner),
                        "owner_stl57": crate::address::encode_stl57_address(&owner),
                        "balance": holding.balance.to_string(),
                        "decimals": actor.metadata.decimals,
                        "symbol": actor.metadata.symbol,
                        "name": actor.metadata.name,
                    }))
                })
                .collect();
            ok(
                id,
                json!({
                    "owner": hex::encode(owner),
                    "owner_stl57": crate::address::encode_stl57_address(&owner),
                    "items": items_view,
                    "next_cursor": page.next_cursor.map(hex::encode),
                    "has_more": page.has_more,
                    "scanned": page.scanned,
                    "scan_truncated": page.truncated,
                }),
            )
        }
        "stell_getTransactionStatus" => {
            let h = match tx_hash_param(params) {
                Some(h) => h,
                None => return err(id, -32602, "missing tx hash"),
            };
            let idx = st.receipts.read().await;
            let status = match idx.get(&h) {
                Some(r) if r.success => "success",
                Some(_) => "failed",
                None => "unknown",
            };
            let height = idx.get(&h).map(|r| r.height);
            drop(idx);
            let pending = status == "unknown" && st.mempool.read().await.contains(&h);
            // E1 confirmations rule (same definition as the receipt above):
            // included -> head - height + 1; mempool-pending -> 0 (accepted
            // locally, finalized nowhere); unknown -> null (this node holds
            // no verdict at all).
            let confirmations = match (height, pending) {
                (Some(tx_h), _) => {
                    let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
                    json!(head.saturating_sub(tx_h).saturating_add(1))
                }
                (None, true) => json!(0),
                (None, false) => Value::Null,
            };
            ok(
                id,
                json!({
                    "status": if pending { "pending" } else { status },
                    "height": height,
                    "confirmations": confirmations,
                }),
            )
        }
        // ---- staking ----
        // Read from the STATE ENGINE, not from a node-local copy: the validator
        // set is derived from this ledger at every height boundary, so a value
        // that existed only on this node would make it propose a different chain.
        "stell_stakeOf" => {
            let v = match params["validator"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok())
            {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let l = st.engine.staking_read().await;
            ok(
                id,
                json!({
                    "total": l.total_stake(&v).to_string(),
                    "self_bond": l.validators.get(&v).map(|x| x.self_bond).unwrap_or(0).to_string(),
                    "delegated": l.validators.get(&v).map(|x| x.delegated).unwrap_or(0).to_string(),
                }),
            )
        }
        // ---- validator UX (unjail / redelegate / commission schedule) ----
        // Read-only: serves the jail record and the commission schedule so
        // operators and wallets can see release heights, pending raises and
        // the delegator-exit window without touching state.
        "stell_getValidatorStatus" => {
            let v = match params["validator"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok())
            {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let l = st.engine.staking_read().await;
            let reg = st.engine.pq_registry_read().await;
            let rec = l.validators.get(&v);
            let jail = l.jail_record(&v);
            let sched = l.commission_schedule_of(&v);
            ok(
                id,
                json!({
                    "validator": hex::encode(v),
                    "known": rec.is_some(),
                    "jailed": jail.is_some(),
                    "jailed_at_height": jail.map(|j| j.jailed_at_height),
                    "release_height": jail.map(|j| j.release_height),
                    "in_set": l.to_validator_set().validators.contains_key(&v),
                    "self_bond": rec.map(|r| r.self_bond.to_string()),
                    "commission_bps": rec.map(|r| r.commission_bps),
                    "withdrawal_address": rec.and_then(|r| r.withdrawal_address.map(hex::encode)),
                    "rotation_seq": reg.record_of(&v).map(|r| r.next_seq),
                    "pending_commission": sched.and_then(|s| s.pending.map(|p| json!({
                        "new_bps": p.new_bps,
                        "announced_height": p.announced_height,
                        "effective_height": p.effective_height,
                    }))),
                    "last_commission_change_height": sched.and_then(|s| s.last_effective_height),
                }),
            )
        }
        // ---- zkML capability statement (audit W8.3 / blocker A5) ----
        //
        // The zkML opcodes are a sound RE-EXECUTION attestation, NOT a
        // zero-knowledge proof system. An integrator must be able to learn
        // that from DATA instead of from a marketing name, so the chain
        // states it: every flag is the conservative truth, and the per-opcode
        // detail says what each one really does.
        "stell_zkmlCapabilities" => ok(
            id,
            serde_json::to_value(crate::zkml::zkml_capabilities()).unwrap_or_else(
                |e| json!({ "error": format!("capability statement unavailable: {e}") }),
            ),
        ),

        "stell_getValidators" => {
            let ledger = st.engine.staking_read().await;
            let vs = ledger.to_validator_set();
            let list: Vec<Value> = vs
                .validators
                .iter()
                .map(|(k, p)| json!({ "validator": hex::encode(k), "power": p.to_string() }))
                .collect();
            // Quorum-safety (урок ночи C): `fragile` is true when the quorum
            // needs 100% of the set — notably any N=3 equal-stake set (3/3) —
            // so any single halt stops the chain. Advisory only (fail-open);
            // `fragile_reason` explains, null when healthy.
            let fragility = ledger.quorum_fragility();
            ok(
                id,
                json!({ "validators": list, "total_power": vs.total_power().to_string(), "quorum": vs.quorum_power().to_string(), "fragile": fragility.is_some(), "fragile_reason": fragility }),
            )
        }

        // ---- PQ registry visibility (rotation story) ----
        // Read-only projections of the on-chain PQ key registry for wallets,
        // explorers and rotation watchers: the authoritative key AT a height
        // plus the pending rotation, and the registry-level constants. Mirrors
        // the `stell_getValidatorStatus` idiom: public read (no `auth_token`
        // gate) over the state engine's staking ledger + committed PQ registry
        // (`st.engine.pq_registry_read()`). Cheap BTreeMap lookups with
        // a small bounded hex encoding, so these ride the standard per-IP
        // standalone limiter like every other cheap read — NOT the
        // expensive-read family (no new budget, no new env knob). Fail-closed:
        // unknown validator, a height outside every validity window, or a
        // height above this node's tip is a JSON-RPC error, never fabricated
        // data. No state mutation on any path (registry `.read()` only).
        "stell_getPqKey" => {
            let v = match params["validator"]
                .as_str()
                .and_then(|s| parse_addr_or_hash(s).ok())
            {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let h = match params.get("height") {
                None | Some(Value::Null) => tip,
                Some(hv) => match hv.as_u64() {
                    Some(h) => h,
                    None => return err(id, -32602, "invalid height (must be an unsigned integer)"),
                },
            };
            if h > tip {
                return err(
                    id,
                    -32004,
                    format!(
                        "height {h} is above this node's tip ({tip}): no future keys, refusing"
                    ),
                );
            }
            let ledger = st.engine.staking_read().await;
            let reg = st.engine.pq_registry_read().await;
            // Membership-gated height-indexed read (the same `pq_active_key`
            // the consensus verification paths use): unknown validator or a
            // height outside every validity window is `None` → error.
            let Some((scheme, pubkey)) = ledger.pq_active_key(&reg, &v, h) else {
                return err(
                    id,
                    -32004,
                    "unknown validator or no PQ key at that height: refusing",
                );
            };
            // `pq_active_key` delegates to the record, so it must exist; a
            // missing record here is an internal inconsistency, still refused
            // fail-closed (never fabricate the metadata around a real key).
            let Some(rec) = reg.record_of(&v) else {
                return err(
                    id,
                    -32004,
                    "unknown validator or no PQ key at that height: refusing",
                );
            };
            ok(
                id,
                json!({
                    "validator": hex::encode(v),
                    "scheme": scheme.name(),
                    "scheme_id": scheme.id(),
                    "pubkey_hex": hex::encode(&pubkey),
                    "activated_at": rec.activated_at,
                    "pending": rec.pending.as_ref().map(|p| json!({
                        "scheme": p.scheme.name(),
                        "scheme_id": p.scheme.id(),
                        "pubkey_hex": hex::encode(&p.pubkey),
                        "announced_height": p.announced_height,
                        "effective_height": p.effective_height,
                    })),
                }),
            )
        }
        "stell_getPqRegistryStatus" => {
            let reg = st.engine.pq_registry_read().await;
            ok(
                id,
                json!({
                    "count": reg.len(),
                    "delay_heights": crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS,
                    "history_limit": crate::pq_registry::PQ_KEY_HISTORY_LIMIT,
                }),
            )
        }

        // ---- governance ----
        "stell_proposal" => {
            let pid = match params["id"].as_u64().or_else(|| params.as_u64()) {
                Some(p) => p,
                None => {
                    return err(
                        id,
                        -32602,
                        "missing or invalid proposal id (must be an unsigned integer)",
                    )
                }
            };
            let g = st.governance.read().await;
            match g.get(pid) {
                Some(p) => ok(
                    id,
                    json!({
                        "id": p.id,
                        "title": p.title,
                        "action": format!("{:?}", p.action),
                        // The CANONICAL action string of the proposal (the same
                        // `type` `stell_submitProposal` accepts) — audit W7.2.
                        "action_type": p.action.action_type(),
                        "status": format!("{:?}", p.status),
                        "voting_end": p.voting_end,
                        "yes": p.yes.to_string(),
                        "no": p.no.to_string(),
                        "abstain": p.abstain.to_string(),
                        "turnout": p.turnout().to_string(),
                    }),
                ),
                None => err(id, -32004, "proposal not found"),
            }
        }
        "stell_listProposals" => {
            let g = st.governance.read().await;
            let mut list: Vec<serde_json::Value> = g
                .proposals
                .values()
                .map(|p| {
                    json!({
                        "id": p.id,
                        "title": p.title,
                        "action": format!("{:?}", p.action),
                        "action_type": p.action.action_type(),
                        "status": format!("{:?}", p.status),
                        "voting_end": p.voting_end,
                        "turnout": p.turnout().to_string(),
                        "yes": p.yes.to_string(),
                        "no": p.no.to_string(),
                        "abstain": p.abstain.to_string(),
                    })
                })
                .collect();
            list.sort_by_key(|p| p["id"].as_u64().unwrap_or(0));
            ok(id, json!(list))
        }
        "stell_governanceParams" => {
            let g = st.governance.read().await;
            ok(
                id,
                json!({
                    "quorum_bps": g.quorum_bps,
                    "next_id": g.next_id,
                    "applied": g.applied,
                }),
            )
        }
        // ---- mempool ----
        "stell_mempoolSize" => {
            let n = st.mempool.read().await.len();
            ok(id, json!(n))
        }
        // Admission floor for wallets and harnesses: the minimum declared
        // `gas_limit` this node currently accepts into its mempool (and the
        // floor its proposer filter skips below). Read-only; refreshed from
        // max(frozen, governed) every finalized height, so a wallet asserts this
        // BEFORE blasting, not after its transactions bounce.
        "stell_baseFee" => {
            let floor = st.mempool.read().await.base_fee;
            ok(id, json!({ "base_fee": floor.to_string() }))
        }
        "stell_estimateFee" => {
            // EXPENSIVE-READ BUDGET (audit W6.7): the estimate clones the WHOLE
            // engine state and runs a full SVM execution, so it is orders of
            // magnitude more expensive than any other read. It is still
            // unauthenticated (a wallet must be able to estimate before it
            // has a token), so its rate is capped SEPARATELY and far below
            // the generic per-IP budget. Without this cap a single client
            // could keep the node cloning state at the generic limit.
            // Fail-closed attribution (audit residual): `None` (in-process
            // dispatch) used to skip the budget entirely. It now draws from
            // the static local bucket ([`LOCAL_BUCKET_IP`]) with the SAME
            // per-IP caps — throttled, never exempt.
            let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
            if !estimate_fee_budget().check(ip) {
                return err(
                    id,
                    -32000,
                    "estimate-fee budget exhausted for this IP (the simulation is expensive; retry shortly)",
                );
            }
            handle_estimate_fee(st, id, params).await
        }
        // Pending mempool contents are non-public: they can aid front-running,
        // so listing them requires the deployment's `auth_token` (when
        // configured), like the signed-payload arms. (The send paths stay OPEN
        // — see the module docs.)
        "stell_mempoolDump" => {
            let Some(expected) = &st.auth_token else {
                return err(
                    id,
                    -32001,
                    "unauthorized: stell_mempoolDump is disabled when auth_token is not configured",
                );
            };
            let provided = params["token"]
                .as_str()
                .or_else(|| params["apiKey"].as_str())
                .or(header_token);
            if !provided
                .map(|p| constant_time_eq(p, expected))
                .unwrap_or(false)
            {
                return err(id, -32001, "unauthorized: missing or invalid API token");
            }
            let list: Vec<Value> = st
                .mempool
                .read()
                .await
                .all()
                .iter()
                .map(|t| {
                    json!({
                        "sender": hex::encode(&t.from[..6]),
                        "nonce": t.nonce,
                        "hash": hex::encode(&t.compute_tx_hash()[..6]),
                    })
                })
                .collect();
            ok(id, json!(list))
        }
        // Read-only view of the committed curve. Nothing is written: the
        // governed buffer is reported from governance (where a passed
        // `SetPmmRedemptionBufferBps` actually lands), not from a copy the PMM
        // might be holding stale.
        "stell_pmmState" => {
            let (pmm, quote_token, treasury) = st.engine.pmm_state().await;
            let governed_buffer_bps = st
                .governance
                .read()
                .await
                .applied
                .pmm_redemption_buffer_bps
                .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS);
            ok(
                id,
                json!({
                    "price_micro_usd": pmm.price_micro_usd(),
                    "minted_nano": pmm.minted_nano.to_string(),
                    "reserve_micro": pmm.reserve_micro.to_string(),
                    "redemption_buffer_micro": pmm.redemption_buffer_micro.to_string(),
                    "usable_reserve_micro": pmm.usable_reserve_micro().to_string(),
                    "max_redeemable_stell": pmm.max_redeemable_stell().to_string(),
                    "quote_token": quote_token.map(hex::encode),
                    "treasury": hex::encode(treasury),
                    "governed_buffer_bps": governed_buffer_bps,
                }),
            )
        }

        // ---- orderbook (read-only) ------------------------------------
        // Depth must come from the COMMITTED book, not from a fresh local one:
        // a CLI that prints a book it just made up is reporting a market that
        // does not exist on any node.
        "stell_orderBook" => {
            let pair = if params.is_null() || params.as_object().is_some_and(|o| o.is_empty()) {
                1u32
            } else {
                let raw = match params["pair"].as_u64().or_else(|| params.as_u64()) {
                    Some(p) => p,
                    None => {
                        return err(
                            id,
                            -32602,
                            "missing or invalid pair id (must be an integer)",
                        )
                    }
                };
                match u32::try_from(raw) {
                    Ok(p) => p,
                    Err(_) => {
                        return err(id, -32602, format!("pair id {raw} out of bounds for u32"))
                    }
                }
            };
            let books = st.engine.orderbooks_read().await;
            let Some(book) = books.get_book(pair) else {
                return err(id, -32004, format!("unknown pair {pair}"));
            };
            let (best_bid, best_ask) = book.get_best_bid_ask();
            let (bid_levels, ask_levels) = book.depth();
            let mut bids: Vec<Value> = book
                .bids
                .iter()
                .take(20)
                .map(|(price, orders)| {
                    let available: u64 = orders.iter().map(|o| o.amount - o.filled).sum();
                    json!({
                        "price_micro_usd": price.0,
                        "orders": orders.len(),
                        "available_nano_stell": available,
                    })
                })
                .collect();
            let asks: Vec<Value> = book
                .asks
                .iter()
                .take(20)
                .map(|(price, orders)| {
                    let available: u64 = orders.iter().map(|o| o.amount - o.filled).sum();
                    json!({
                        "price_micro_usd": price,
                        "orders": orders.len(),
                        "available_nano_stell": available,
                    })
                })
                .collect();
            bids.sort_by_key(|v| v["price_micro_usd"].as_u64().unwrap_or(0));
            // `version` is the book's mutation sequence (placements AND
            // cancels): poll-based quoters compare it against the last read
            // and re-render only when it moved. `next_order_id` moves on
            // placement only and is kept for id assignment.
            let version = book.version;
            let next_order_id = book.next_order_id;
            ok(
                id,
                json!({
                    "pair": pair,
                    "version": version,
                    "seq": version,
                    "best_bid_micro_usd": best_bid,
                    "best_ask_micro_usd": best_ask,
                    "bid_levels": bid_levels,
                    "ask_levels": ask_levels,
                    "bids": bids,
                    "asks": asks,
                    "next_order_id": next_order_id,
                }),
            )
        }

        // ---- session-key budget (read-only) ----------------------------
        // Bot visibility into the COMMITTED `SessionKeyRegistry`: how much of
        // a session key's cumulative gas budget is spent. Read-only: no auth
        // token, like every other read method here (only writes are gated).
        // Source of truth is `st.engine.session_keys_read()` — the same
        // in-memory engine handle the execution path commits to — never a
        // parallel copy.
        //
        // Params: `{"session": "<64-hex session pubkey>"}` (also accepts the
        // bare hex string). Numbers are JSON numbers, matching the
        // small-counter convention elsewhere in this file (`stell_chainId`,
        // `height`, `nonce`, `timestamp`); `master` is 64-char hex.
        // Unknown key: zeros + `registered: false`. `chain_id` is the node's
        // chain id (replay context the bot needs; the registry record itself
        // does not store it).
        "stell_sessionBudget" => {
            let sess_hex = if let Some(s) = params.as_str() {
                s.to_string()
            } else if let Some(s) = params["session"].as_str() {
                s.to_string()
            } else {
                return err(id, -32602, "missing session");
            };
            let pk = match parse_hash(&sess_hex) {
                Ok(p) => p,
                Err(e) => return err(id, -32602, e),
            };
            let reg = st.engine.session_keys_read().await;
            match reg.get(&pk) {
                None => ok(
                    id,
                    json!({
                        "registered": false,
                        "revoked": false,
                        "valid_until": 0,
                        "scope": 0,
                        "max_gas_spend": 0,
                        "spent": 0,
                        "remaining_gas": 0,
                        "master": "0".repeat(64),
                        "chain_id": st.chain_id,
                    }),
                ),
                Some(rec) => ok(
                    id,
                    json!({
                        "registered": true,
                        "revoked": rec.revoked,
                        "valid_until": rec.valid_until,
                        "scope": rec.scope,
                        "max_gas_spend": rec.max_gas_spend,
                        "spent": rec.gas_spent,
                        "remaining_gas": rec.max_gas_spend.saturating_sub(rec.gas_spent),
                        "master": hex::encode(rec.master),
                        "chain_id": st.chain_id,
                    }),
                ),
            }
        }

        // ---- block invalidations (reorg / lost fork) ----
        // The blocks this node told the world about and then could NOT keep:
        // a candidate branch that lost the fork-choice, or a reorg that
        // rolled a branch back. None of these blocks were ever APPLIED
        // (BFT finality forbids rolling back an applied block), so the
        // signal is a "your view of these blocks is wrong" notice.
        //
        // `limit` is optional and caps how many of the most recent signals
        // are returned (0 / absent = the whole window). The window is
        // bounded, so an unbounded answer is bounded by construction.
        "stell_getInvalidations" | "stell_invalidationFeed" => {
            let limit = params
                .get("limit")
                .and_then(|v| v.as_u64())
                .or_else(|| params.as_u64())
                .or_else(|| params.get(0).and_then(|v| v.as_u64()))
                .unwrap_or(0) as usize;
            let sigs = recent_invalidations(limit);
            let list: Vec<Value> = sigs.iter().map(invalidation_to_json).collect();
            ok(
                id,
                json!({
                    "invalidations": list,
                    "count": list.len(),
                }),
            )
        }

        // ---- streaming subscriptions (WebSocket / SSE) ----
        // Register a subscription and return its id (16 random bytes, hex).
        // The notifications are pushed over the WebSocket transport (`/ws`)
        // or the SSE transport (`/events`).
        "stell_subscribe" => match parse_subscribe_params(params) {
            Ok(topic) => {
                // PER-CLIENT BUDGET (audit W6.7): the global
                // `MAX_SUBSCRIPTIONS` cap bounds the node's MEMORY, but
                // without a per-client cap a single caller can fill the whole
                // registry and starve every other subscriber (the cap is
                // global, so the flood is a denial of service for everyone
                // else). The per-IP cap keeps one client from taking the
                // node's whole budget.
                // Fail-closed attribution (audit residual): `None`
                // (in-process dispatch) used to create UNATTRIBUTED
                // subscriptions that skipped the per-client cap. They now
                // share the static "local" bucket ([`LOCAL_SUBSCRIBER_ID`])
                // with the same cap — throttled, never exempt.
                let client = peer_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| LOCAL_SUBSCRIBER_ID.to_string());
                match hub().subscribe_for(topic, Some(client.as_str())) {
                    Ok(sub_id) => ok(id, json!(sub_id)),
                    Err(e) => err(id, -32000, e),
                }
            }
            Err(e) => err(id, -32602, e),
        },
        // Remove a subscription. `true` when it existed AND belongs to the
        // calling client, `false` for an unknown id or another client's id
        // (indistinguishable, so the method is not an id oracle).
        "stell_unsubscribe" => {
            let sub_id = params
                .get(0)
                .and_then(|v| v.as_str())
                .or_else(|| params.get("subscription").and_then(|v| v.as_str()))
                .or_else(|| params.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            match sub_id {
                Some(s) => {
                    let client = peer_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| LOCAL_SUBSCRIBER_ID.to_string());
                    ok(id, json!(hub().unsubscribe_for(s, Some(client.as_str()))))
                }
                None => err(id, -32602, "missing subscription id"),
            }
        }
        // The live subscriptions of THIS client (diagnostics / introspection).
        //
        // Subscription ids are capabilities for unsubscribe and SSE attach, so
        // the listing is scoped to the caller's own subscriptions: an
        // unauthenticated caller cannot enumerate another client's ids and
        // tear its streams down. The owner field (client IP) is never served.
        "stell_getSubscriptions" => {
            let client = peer_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| LOCAL_SUBSCRIBER_ID.to_string());
            let view: Vec<Value> = hub()
                .list_for(Some(client.as_str()))
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "topic": s.topic,
                        "created_at": s.created_at,
                        "attached": s.attached,
                    })
                })
                .collect();
            ok(id, json!(view))
        }

        // ---- the native interface namespace ------------------------------
        // ONE stable, wallet-facing namespace over the native capabilities
        // (token / staking / bridge / order book / session keys / oracle).
        // Every method in it is a thin, fail-closed wrapper over the state
        // engine that owns the state; see `crate::native_api` for the shapes.
        //
        // The write methods do NOT write: they answer with the transaction
        // the wallet has to sign, so the state still only moves when a signed
        // transaction lands in a block.
        _ if crate::native_api::is_native_method(method) => {
            match crate::native_api::dispatch(&st.engine, method, params).await {
                Ok(result) => ok(id, result),
                Err(e) => err(id, e.code(), e.message()),
            }
        }

        _ => err(
            id,
            -32601,
            format!("method not found: {}", snip_for_error(method)),
        ),
    }
}
