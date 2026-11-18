use super::*;
use crate::contract_abi::{AbiType, AbiValue, ContractAbi};
use crate::network::decode_wire_limited;
use crate::sharding::Transaction;
use axum::Json;
use serde_json::{json, Value};

pub(super) fn parse_contract_call_arg(val: &Value) -> Result<i64, String> {
    if let Some(arr) = val.as_array() {
        if let Some(first) = arr.first() {
            return parse_single_getter_arg(first);
        } else {
            return Ok(0);
        }
    }
    parse_single_getter_arg(val)
}

/// Parse every argument of a contract call from a Value.
///
/// An array carries one argument per element (multi-argument methods), a
/// scalar is a single argument.
pub(super) fn parse_contract_call_args(val: &Value) -> Result<Vec<i64>, String> {
    if let Some(arr) = val.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            out.push(parse_single_getter_arg(item)?);
        }
        return Ok(out);
    }
    Ok(vec![parse_single_getter_arg(val)?])
}

/// Convert a JSON value into a typed ABI value of the declared type.
pub(super) fn json_to_abi_value(ty: AbiType, val: &Value, param: &str) -> Result<AbiValue, String> {
    match ty {
        AbiType::I64 => {
            let n = val
                .as_i64()
                .or_else(|| val.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
                .ok_or_else(|| format!("parameter '{param}' must be an i64"))?;
            Ok(AbiValue::I64(n))
        }
        AbiType::U64 => {
            let n = val
                .as_u64()
                .or_else(|| val.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                .ok_or_else(|| format!("parameter '{param}' must be a u64"))?;
            Ok(AbiValue::U64(n))
        }
        AbiType::I32 => {
            let n = val
                .as_i64()
                .or_else(|| val.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
                .ok_or_else(|| format!("parameter '{param}' must be an i32"))?;
            if n < i32::MIN as i64 || n > i32::MAX as i64 {
                return Err(format!("parameter '{param}' does not fit into an i32"));
            }
            Ok(AbiValue::I32(n as i32))
        }
        AbiType::Bool => match val {
            Value::Bool(b) => Ok(AbiValue::Bool(*b)),
            Value::Number(n) => Ok(AbiValue::Bool(n.as_i64().unwrap_or(0) != 0)),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => Ok(AbiValue::Bool(true)),
                "false" | "0" => Ok(AbiValue::Bool(false)),
                _ => Err(format!("parameter '{param}' must be a boolean")),
            },
            _ => Err(format!("parameter '{param}' must be a boolean")),
        },
        AbiType::Bytes => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("parameter '{param}' must be a hex string"))?;
            let clean = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            let bytes = hex::decode(clean)
                .map_err(|e| format!("parameter '{param}' is not valid hex: {e}"))?;
            Ok(AbiValue::Bytes(bytes))
        }
        AbiType::Address => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("parameter '{param}' must be an address"))?;
            let addr = crate::address::parse_address(s)
                .map_err(|e| format!("parameter '{param}' is not a valid address: {e}"))?;
            Ok(AbiValue::Address(addr))
        }
        AbiType::String => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("parameter '{param}' must be a string"))?;
            Ok(AbiValue::String(s.to_string()))
        }
    }
}

/// Parse the optional `abi` parameter of a deployment: either a JSON object
/// (the manifest itself) or a string containing the JSON manifest.
pub(super) fn parse_abi_manifest_param(p: &Value) -> Result<Option<ContractAbi>, String> {
    let raw = match p.get("abi").or_else(|| p.get("abi_json")) {
        Some(v) => v,
        None => return Ok(None),
    };
    if raw.is_null() {
        return Ok(None);
    }
    let text = match raw {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let abi = ContractAbi::from_json(&text).map_err(|e| e.to_string())?;
    Ok(Some(abi))
}

/// Parse the arguments of a call against an ABI manifest.
///
/// The manifest is authoritative: the method must exist and the number of
/// arguments must match the declaration exactly.
pub(super) fn parse_abi_args(
    abi: &ContractAbi,
    method: &str,
    val: Option<&Value>,
) -> Result<Vec<AbiValue>, String> {
    let m = abi
        .method(method)
        .ok_or_else(|| format!("method '{method}' is not declared in the contract ABI"))?;
    let items: Vec<Value> = match val {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => arr.clone(),
        Some(other) => vec![other.clone()],
    };
    if items.len() != m.params.len() {
        return Err(format!(
            "method '{method}' expects {} argument(s), got {}",
            m.params.len(),
            items.len()
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for (p, v) in m.params.iter().zip(items.iter()) {
        out.push(json_to_abi_value(p.ty, v, &p.name)?);
    }
    Ok(out)
}

/// Parse address for RPC methods, accepting Stl57, 64-hex, or 40-hex (EVM address).
pub(super) fn parse_rpc_address(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    if let Ok(addr) = crate::address::parse_address(trimmed) {
        return Ok(addr);
    }
    if let Some(hex_clean) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if hex_clean.len() == 40 {
            if let Ok(evm_b) = hex::decode(hex_clean) {
                if let Ok(evm_arr) = <[u8; 20]>::try_from(evm_b.as_slice()) {
                    return Ok(crate::evm_adapter::evm_to_stell_address(&evm_arr));
                }
            }
        }
        if hex_clean.len() == 64 {
            if let Ok(b) = hex::decode(hex_clean) {
                if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
                    return Ok(arr);
                }
            }
        }
    }
    Err(format!("invalid address: {}", snip_for_error(s)))
}

/// A call-like opcode extracted from a sealed tx for preview/admission.
pub(super) struct ExtractedCall {
    contract: [u8; 32],
    method: Vec<u8>,
    args: Vec<i64>,
    calldata: Vec<u8>,
}

/// The call shape a contract-call preview executes on the registry clone.
pub(super) enum PreviewCall<'a> {
    /// Plain wasm arguments (`call_args` path).
    Plain(&'a [i64]),
    /// Raw multi-argument form with the canonical ABI calldata blob
    /// (`call_with_context_args_calldata` path — the exact opcode a
    /// `SysCallCallContractArgs` carries).
    RawArgs(&'a [i64], &'a [u8]),
    /// Typed ABI arguments (`call_abi` path).
    Abi(&'a [AbiValue]),
}

/// The execution context a PREVIEW shares with block application.
///
/// Block application (`svm::OpCode::SysCallCallContract` /
/// `SysCallCallContractArgs`) executes with `caller = tx.from`, `value = 0`
/// (the value leg is a separate debit/credit, never visible as `host.value`),
/// `block_time = the block timestamp` and `block_hash = [0u8; 32]`. A preview
/// MUST use the same shape, because `caller` is authenticated input to the
/// contract: a zero caller turns an owner-guarded method into a FALSE REVERT
/// (F3) and a `caller == 0x00..`-guarded method into a FALSE SUCCESS (F4).
pub(super) fn preview_call_context(
    caller: [u8; 32],
    block_time: u64,
) -> crate::contract::ContractCallContext {
    crate::contract::ContractCallContext {
        caller,
        value: 0,
        block_time,
        block_hash: [0u8; 32],
    }
}

/// The timestamp a preview executes with: the head block's committed
/// timestamp (what the next block is closest to). `0` on a node with no
/// committed block — never a wall-clock value the chain did not commit.
pub(super) async fn preview_block_time(st: &RpcState) -> u64 {
    st.recent_blocks
        .read()
        .await
        .front()
        .map(|b| b.timestamp)
        .unwrap_or(0)
}

/// H-03: read-only contract-call preview executed on a CLONE of the contract
/// registry. Returns the same
/// [`crate::state_engine::ContractCallOutcome`] the block-applied execution
/// would report (same return value, gas and events), but touches NO live
/// state: no debit/credit, no balance syncs, no outbound-message routing, no
/// trie writes, and NO receipt (a preview is not an inclusion). State changes
/// happen exclusively when a transaction submitted via
/// `stell_sendRawTransaction` is applied by a block (N-03: the previewed tx
/// itself is dropped, never admitted).
///
/// `caller` is the transaction's real `from` — the same address block
/// application passes as `ctx.sender` — so an owner-authenticated call
/// previews exactly as it would apply. The caller is never a default/zero
/// address and never a node-chosen one (see [`preview_call_context`]).
///
/// The `value` leg is simulated on the clone with the same failure modes the
/// old direct path had: a sender that cannot cover `value` fails with
/// `insufficient funds to transfer value: …` and nothing moves.
#[allow(clippy::too_many_arguments)]
// GATE: preview needs the registry, the call shape, the caller, the value leg, gas and the block clock.
pub(super) async fn preview_contract_call(
    st: &RpcState,
    contract_addr: &[u8; 32],
    method: &str,
    call: PreviewCall<'_>,
    value: u64,
    sender: &[u8; 32],
    gas_limit: u64,
    block_time: u64,
) -> crate::state_engine::ContractCallOutcome {
    let failed = |msg: String, gas_used: u64| crate::state_engine::ContractCallOutcome {
        status: "failed".to_string(),
        return_value: None,
        gas_used,
        events: Vec::new(),
        error: Some(msg),
    };
    // Same failure modes as the retired direct debit, evaluated read-only.
    if value > 0 {
        match st.engine.get_account(sender).await {
            None => {
                return failed(
                    "insufficient funds to transfer value: account does not exist".to_string(),
                    0,
                );
            }
            Some(a) if a.balance < value => {
                return failed(
                    "insufficient funds to transfer value: Insufficient native STELL balance"
                        .to_string(),
                    0,
                );
            }
            Some(_) => {}
        }
    }
    let mut work = st.engine.contracts_read().await.clone();
    // Read-only mirror of `sync_contract_balance` plus the value leg: the
    // contract observes the live account balance plus the transferred value.
    // Applied to the CLONE only; the live registry and accounts are untouched.
    if work.contracts.contains_key(contract_addr) {
        let acct_bal = st
            .engine
            .get_account(contract_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        if let Some(c) = work.contracts.get_mut(contract_addr) {
            c.balance = c.balance.max(acct_bal).saturating_add(value);
        }
    }
    let ctx = preview_call_context(*sender, block_time);
    let exec: Result<
        (i64, u64, Vec<crate::contract::ContractEvent>),
        crate::contract::ContractError,
    > = match call {
        PreviewCall::Plain(args) => work
            .call_with_context_args(contract_addr, method, args, gas_limit, &ctx)
            .map(|o| (o.result, o.fuel_used, o.events)),
        PreviewCall::RawArgs(args, calldata) => work
            .call_with_context_args_calldata(contract_addr, method, args, calldata, gas_limit, &ctx)
            .map(|o| (o.result, o.fuel_used, o.events)),
        PreviewCall::Abi(args) => work
            .call_abi_with_context(contract_addr, method, args, gas_limit, &ctx)
            .map(|o| (o.result, o.fuel_used, o.events)),
    };
    // Same outcome mapping as the engine's structured-call helpers.
    match exec {
        Ok((ret, used, events)) => crate::state_engine::ContractCallOutcome {
            status: "success".to_string(),
            return_value: Some(ret),
            gas_used: used,
            events,
            error: None,
        },
        Err(e) => {
            let (gas_used, msg) = match &e {
                crate::contract::ContractError::OutOfFuel => (gas_limit, e.to_string()),
                _ => (0, e.to_string()),
            };
            failed(msg, gas_used)
        }
    }
}

/// N-03: the single choke point through which the contract arms answer a
/// preview. It renders the canonical response shape and NOTHING else:
///
/// * NO receipt is written — a preview is not an inclusion, and the receipt
///   index answers `eth_getTransactionReceipt` for MINED transactions only
///   (F5/F5b: the old shape filed a fake receipt with `blockHash = 0x00…` and
///   `blockNumber = head` into the same ring that serves real chain history,
///   so a preview could both lie about inclusion and evict real receipts);
/// * NO mempool admission and NO gossip — the preview tx is dropped here;
/// * state changes happen exclusively when a block applies a transaction
///   submitted via `stell_sendRawTransaction`.
///
/// `tx_hash` is the hash of the transaction the caller previewed, when the
/// request carried one (the signed `tx` form). For the direct form there is
/// no transaction at all, so the hash is `null` instead of a fabricated one.
/// `"preview_only": true` and `"mined": false` make the absence of a receipt
/// explicit in the response itself.
pub(super) fn preview_outcome_response(
    id: Value,
    outcome: crate::state_engine::ContractCallOutcome,
    tx_hash: Option<[u8; 32]>,
) -> Json<RpcResponse> {
    let events_view: Vec<Value> = outcome
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

    ok(
        id,
        json!({
            "tx_hash": tx_hash.map(|h| json!(hex::encode(h))).unwrap_or(Value::Null),
            "status": outcome.status,
            "return_value": outcome.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
            "gas_used": outcome.gas_used,
            "events": events_view,
            "preview_only": true,
            "mined": false,
            "outcome": {
                "status": outcome.status,
                "return_value": outcome.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
                "gas_used": outcome.gas_used,
                "events": events_view,
                "error": outcome.error
            }
        }),
    )
}

pub(super) async fn dispatch_contracts(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
) -> Option<Json<RpcResponse>> {
    if !matches!(
        method,
        "stell_runGetMethod"
            | "stell_deployContract"
            | "stell_callContract"
            | "stell_getContractAbi"
            | "stell_verifyContractSource"
            | "stell_getContractSource"
            | "stell_registerContractSource"
            | "stell_getContractReceipt"
    ) {
        return None;
    }
    Some(dispatch_contracts_inner(st, id, method, params, header_token).await)
}

async fn dispatch_contracts_inner(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
) -> Json<RpcResponse> {
    match method {
        // ---- read-only contract getter (TON runGetMethod / Near call_function) ----
        "stell_runGetMethod" => {
            let height_pin = if let Some(h) = params.get("height") {
                if h.is_null() {
                    None
                } else if let Some(u) = h.as_u64() {
                    Some(u)
                } else if let Some(s) = h.as_str() {
                    let s = s.trim();
                    if let Some(hex_part) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        match u64::from_str_radix(hex_part, 16) {
                            Ok(u) => Some(u),
                            Err(e) => {
                                return ok(
                                    id,
                                    json!({
                                        "success": false,
                                        "error": format!("invalid height parameter: {e}"),
                                        "fuel_used": 0,
                                    }),
                                );
                            }
                        }
                    } else {
                        match s.parse::<u64>() {
                            Ok(u) => Some(u),
                            Err(e) => {
                                return ok(
                                    id,
                                    json!({
                                        "success": false,
                                        "error": format!("invalid height parameter: {e}"),
                                        "fuel_used": 0,
                                    }),
                                );
                            }
                        }
                    }
                } else {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": "invalid height parameter: must be an unsigned integer or hex string",
                            "fuel_used": 0,
                        }),
                    );
                }
            } else if let Some(arr) = params.as_array() {
                if arr.len() > 3 && !arr[3].is_null() {
                    match arr[3].as_u64() {
                        Some(u) => Some(u),
                        None => {
                            return ok(
                                id,
                                json!({
                                    "success": false,
                                    "error": "invalid height parameter: must be an unsigned integer",
                                    "fuel_used": 0,
                                }),
                            );
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(pin) = height_pin {
                let current_h = st.height.load(std::sync::atomic::Ordering::Relaxed);
                if pin > current_h {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": format!("pinned block height {pin} exceeds current finalized height {current_h}"),
                            "fuel_used": 0,
                        }),
                    );
                }
            }

            let addr_val = params.get("address").or_else(|| {
                if let Some(arr) = params.as_array() {
                    if arr.len() == 1 && arr[0].is_object() {
                        arr[0].get("address")
                    } else {
                        arr.first()
                    }
                } else {
                    None
                }
            });

            let addr_str = match addr_val.and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": "missing or invalid address",
                            "fuel_used": 0,
                        }),
                    );
                }
            };

            // ONE parse of the address, in the form the RPC accepts: the
            // bare 32-byte form, or the TON-style `<shard>:<addr>` form
            // (`-1:` for the masterchain). The shard the caller NAMED is a
            // hint; the rule below is what actually resolves the shard when
            // no shard was named.
            //
            // THE address→shard rule (see `crate::sharding::ROUTING_RULE`).
            // The same rule `stell_estimateFee` and the topology itself
            // apply, so a client that asks "which shard holds this
            // contract?" gets the same answer the chain would route to.
            let (contract_addr, shard_hint) = match parse_rpc_address_with_shard_hint(addr_str) {
                Ok(v) => v,
                Err(e) => {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": e,
                            "fuel_used": 0,
                        }),
                    );
                }
            };
            let resolved_shard = resolve_shard_for_address(st, contract_addr, shard_hint).await;
            let local_shard = st
                .engine
                .shard_id
                .load(std::sync::atomic::Ordering::Relaxed);
            let _shard_is_local = resolved_shard == local_shard;

            let method_val = params.get("method").or_else(|| {
                if let Some(arr) = params.as_array() {
                    if arr.len() == 1 && arr[0].is_object() {
                        arr[0].get("method")
                    } else {
                        arr.get(1)
                    }
                } else {
                    None
                }
            });

            let method_str = match method_val.and_then(|v| v.as_str()) {
                Some(m) => m,
                None => {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": "missing or invalid method name",
                            "fuel_used": 0,
                        }),
                    );
                }
            };

            let args_val = params.get("args").or_else(|| {
                if let Some(arr) = params.as_array() {
                    if arr.len() == 1 && arr[0].is_object() {
                        arr[0].get("args")
                    } else {
                        arr.get(2)
                    }
                } else {
                    None
                }
            });

            let fuel_limit = params.get("fuel").and_then(|v| v.as_u64());

            // When the contract carries an ABI manifest the manifest is
            // authoritative: the method and its arguments are validated and
            // the return value is decoded with the declared type.
            let abi = st.engine.get_contract_abi(&contract_addr).await;
            if let Some(abi) = abi {
                let typed_args = match parse_abi_args(&abi, method_str, args_val) {
                    Ok(a) => a,
                    Err(e) => {
                        return ok(
                            id,
                            json!({
                                "success": false,
                                "error": e,
                                "fuel_used": 0,
                            }),
                        );
                    }
                };
                let res = st
                    .engine
                    .run_get_method_typed(&contract_addr, method_str, &typed_args, fuel_limit)
                    .await;
                return ok(
                    id,
                    with_shard_info(
                        serde_json::to_value(res).unwrap_or(Value::Null),
                        resolved_shard,
                        local_shard,
                    ),
                );
            }

            let parsed_args = match args_val {
                Some(v) => match parse_get_method_args(v) {
                    Ok(a) => a,
                    Err(e) => {
                        return ok(
                            id,
                            json!({
                                "success": false,
                                "error": e,
                                "fuel_used": 0,
                            }),
                        );
                    }
                },
                None => Vec::new(),
            };

            let res = st
                .engine
                .run_get_method(&contract_addr, method_str, &parsed_args, fuel_limit)
                .await;
            ok(
                id,
                with_shard_info(
                    serde_json::to_value(res).unwrap_or(Value::Null),
                    resolved_shard,
                    local_shard,
                ),
            )
        }

        // ---- contract deployment (TON StateInit / deterministic BLAKE3) ----
        "stell_deployContract" => {
            // N-02/N-03: this arm deploys nothing itself (prediction only),
            // but it validates untrusted code and hands out chain addresses —
            // so it takes the same fail-closed token gate as the governance
            // writes: a valid token ALWAYS, on every bind. Without a token it
            // is refused before parsing (same refusal properties as the gov
            // arms).
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };

            // H-03/H-04: `private_key` over RPC leaks key material and
            // `from` without a key cannot be honored (the node cannot sign
            // as the caller). Both are refused fail-closed: fund and sign
            // locally (SDK `TxBuilder::contract_deploy` + `sign`, or the
            // wallet) and submit the sealed transaction via the `tx` form.
            if p.get("private_key").is_some() {
                return err(
                    id,
                    -32602,
                    "private_key is no longer accepted: sign the deploy transaction locally and submit it via the `tx` form",
                );
            }
            if p.get("from").is_some() {
                return err(
                    id,
                    -32602,
                    "`from` is no longer accepted: the transaction signer (tx.from) is the deploy creator; sign locally and submit via the `tx` form",
                );
            }

            // Check if wrapped in signed raw tx wrapper
            if let Some(raw_tx_str) = p.get("tx").and_then(|v| v.as_str()) {
                let raw_bytes =
                    match hex::decode(raw_tx_str.strip_prefix("0x").unwrap_or(raw_tx_str)) {
                        Ok(b) => b,
                        Err(e) => return err(id, -32602, format!("invalid raw tx hex: {e}")),
                    };
                let tx: Transaction = match decode_wire_limited(&raw_bytes, MAX_RPC_BODY as u64) {
                    Ok(t) => t,
                    Err(e) => return err(id, -32602, format!("failed to decode transaction: {e}")),
                };
                // P5 FIX: the wrapped path admitted an UNSIGNED tx straight
                // into the engine + mempool (no verify_signature). A forged
                // `from` deploys as the victim. Verify like sendRawTransaction.
                // FULL-PQ: classical envelopes refused at intake, before crypto.
                {
                    let pq_ok = match tx.pq_envelope() {
                        Some(env) => env.scheme.is_post_quantum(),
                        None => false,
                    };
                    if !pq_ok {
                        return err(
                            id,
                            -32000,
                            "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
                        );
                    }
                }
                if !tx.verify_signature() {
                    return err(id, -32000, "invalid transaction signature");
                }
                let deploy_code = tx.payload.iter().find_map(|op| {
                    if let crate::svm::OpCode::SysCallDeployContract { code } = op {
                        Some(code.clone())
                    } else {
                        None
                    }
                });
                let code = match deploy_code {
                    Some(c) => c,
                    None => {
                        return err(
                            id,
                            -32602,
                            "transaction does not contain SysCallDeployContract payload",
                        )
                    }
                };
                // H-04: validate read-only. The contract is NOT deployed here:
                // this arm only previews the signed tx (state changes
                // exclusively when a block applies a tx submitted via
                // `stell_sendRawTransaction` — N-03: this preview is NOT
                // admitted to the mempool, NOT gossipped; the tx is dropped).
                if let Err(e) = crate::contract::ContractRegistry::validate_code(&code) {
                    return err(id, -32000, format!("deploy contract failed: {e}"));
                }
                // H-04: the `init_data`/`salt` parameter is retired. It is not
                // part of the replayable `SysCallDeployContract` payload, so
                // no block-applied transaction could ever observe it; keeping
                // it would promise an address determinism the chain cannot
                // deliver (the old BLAKE3(code_hash || salt) address was a
                // phantom the block path never recreated — the second half of
                // the double-deploy). The predicted address below is the
                // SDK-canonical `contract_address(tx.from, tx.nonce)`: exactly
                // what block application derives when this tx applies first
                // for its sender.
                let predicted = crate::contract::contract_address(&tx.from, tx.nonce);
                if st.engine.get_contract(&predicted).await.is_some() {
                    return err(
                        id,
                        -32000,
                        "deploy contract failed: contract already exists",
                    );
                }
                let code_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&code).into();
                let predicted_stl57 = crate::address::encode_stl57_address(&predicted);
                let tx_hash = tx.compute_tx_hash();

                // N-03: the signed preview tx is DROPPED here — no mempool
                // admission, no gossip broadcast, and NO receipt. A deploy
                // that was never sent must never be reported as MINED (F5):
                // the receipt index is reserved for block application.
                return ok(
                    id,
                    json!({
                        "contract_address": hex::encode(predicted),
                        "contract_address_stl57": predicted_stl57,
                        "code_hash": hex::encode(code_hash),
                        "tx_hash": hex::encode(tx_hash),
                        "predicted": true,
                        "deployed": false,
                        "preview_only": true,
                        "address_derivation": "contract_address(tx.from, tx.nonce)",
                        "note": "prediction only: the contract exists once a block applies this signed transaction",
                    }),
                );
            }

            // Direct parameters: validated + previewed, never deployed here.
            // The node signs the preview vehicle with a fresh ephemeral key
            // (it can never leak a user key — none is accepted) and predicts
            // the SDK-canonical address. State changes exclusively when a
            // block applies a tx submitted via `stell_sendRawTransaction`
            // (H-04/C-01; N-03: the preview vehicle is dropped, not admitted).
            let code_str = match p.get("code").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(id, -32602, "missing 'code' parameter"),
            };
            let code_clean = code_str.strip_prefix("0x").unwrap_or(code_str);
            let code = match hex::decode(code_clean) {
                Ok(c) => c,
                Err(e) => return err(id, -32602, format!("invalid code hex: {e}")),
            };
            if let Err(e) = crate::contract::ContractRegistry::validate_code(&code) {
                return err(id, -32000, format!("deploy contract failed: {e}"));
            }

            // Optional typed ABI manifest: validated here (it would travel
            // inside a submitted tx's execution path at apply time, committed
            // next to the code hash by block application — never by this arm).
            if let Err(e) = parse_abi_manifest_param(p) {
                return err(id, -32602, format!("invalid abi parameter: {e}"));
            }

            // F6: the address is `contract_address(sender, nonce)` — a
            // function of the SIGNER, never of a node-chosen random key. This
            // form carries no signer (`from` is refused: the node cannot sign
            // as the caller), so the address is predicted ONLY when the
            // request names `sender` (plus an optional `nonce`, defaulting to
            // that account's committed nonce — the position its next tx
            // occupies). Without a sender the answer is `contract_address:
            // null`, so two identical requests always return the SAME answer
            // and the node never hands out an address nobody can deploy at.
            let code_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&code).into();
            let sender = match p.get("sender").and_then(|v| v.as_str()) {
                Some(s) => match parse_rpc_address(s) {
                    Ok(a) => Some(a),
                    Err(e) => return err(id, -32602, format!("invalid sender address: {e}")),
                },
                None => None,
            };
            let requested_nonce = match p.get("nonce") {
                None | Some(Value::Null) => None,
                Some(v) => match v
                    .as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                {
                    Some(n) => Some(n),
                    None => return err(id, -32602, "invalid nonce: must be an unsigned integer"),
                },
            };
            let prediction: Option<([u8; 32], u64)> = match sender {
                Some(sender_addr) => {
                    let nonce = match requested_nonce {
                        Some(n) => n,
                        None => st
                            .engine
                            .get_account(&sender_addr)
                            .await
                            .map(|a| a.nonce)
                            .unwrap_or(0),
                    };
                    let predicted = crate::contract::contract_address(&sender_addr, nonce);
                    // Only block application can create the contract, so an
                    // existing entry here is a real refusal (never a preview
                    // write).
                    if st.engine.get_contract(&predicted).await.is_some() {
                        return err(
                            id,
                            -32000,
                            "deploy contract failed: contract already exists",
                        );
                    }
                    Some((predicted, nonce))
                }
                None => None,
            };

            // Nothing is deployed, signed or receipted here: this arm only
            // validates the code and predicts where a signed
            // `SysCallDeployContract` from `sender` at `nonce` would land.
            let gas_cost = crate::svm::contract_deploy_gas(code.len());
            let predicted_hex = prediction.map(|(a, _)| hex::encode(a));
            let predicted_stl57 = prediction.map(|(a, _)| crate::address::encode_stl57_address(&a));
            let predicted_nonce = prediction.map(|(_, n)| n);
            ok(
                id,
                json!({
                    "contract_address": predicted_hex,
                    "contract_address_stl57": predicted_stl57,
                    "code_hash": hex::encode(code_hash),
                    "sender": sender.map(hex::encode).unwrap_or_default(),
                    "nonce": predicted_nonce,
                    "gas_estimate": gas_cost,
                    "predicted": prediction.is_some(),
                    "deployed": false,
                    "preview_only": true,
                    "tx_hash": Value::Null,
                    "address_derivation": "contract_address(tx.from, tx.nonce)",
                    "note": if prediction.is_some() {
                        "prediction only: the contract exists once a block applies a signed SysCallDeployContract transaction from `sender` at `nonce`"
                    } else {
                        "no sender in this request, so no address can be predicted: pass `sender` (and optional `nonce`), or sign the deploy locally and submit it via the `tx` form"
                    },
                }),
            )
        }
        "stell_callContract" => {
            // N-02/N-03: this arm runs the call on a CLONE of the registry
            // for a result preview and DROPS the tx (never admitted, never
            // gossipped — state changes exclusively when a block applies a
            // tx submitted via `stell_sendRawTransaction`). It takes the same
            // fail-closed token gate as the governance writes: a valid token
            // ALWAYS, on every bind.
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };

            // H-04: `private_key` over RPC leaks key material and `from`
            // without a key cannot be honored. Both are refused fail-closed:
            // sign locally (SDK `TxBuilder::contract_call` + `sign`) and
            // submit the sealed transaction via the `tx` form, or use the
            // direct parameters with an explicit `caller` (the address the
            // call would execute as — never a zero/random stand-in).
            if p.get("private_key").is_some() {
                return err(
                    id,
                    -32602,
                    "private_key is no longer accepted: sign the call transaction locally and submit it via the `tx` form",
                );
            }
            if p.get("from").is_some() {
                return err(
                    id,
                    -32602,
                    "`from` is no longer accepted: the transaction signer (tx.from) is the caller; sign locally and submit via the `tx` form",
                );
            }

            // Signed-tx form: a sealed `SysCallCallContract` /
            // `SysCallCallContractArgs` transaction. Verified exactly like
            // `stell_sendRawTransaction`, previewed on a registry clone with
            // `tx.from` as the caller, and DROPPED — never executed against
            // live state, never admitted, never receipted.
            if let Some(raw_tx_str) = p.get("tx").and_then(|v| v.as_str()) {
                let raw_bytes =
                    match hex::decode(raw_tx_str.strip_prefix("0x").unwrap_or(raw_tx_str)) {
                        Ok(b) => b,
                        Err(e) => return err(id, -32602, format!("invalid raw tx hex: {e}")),
                    };
                let tx: Transaction = match decode_wire_limited(&raw_bytes, MAX_RPC_BODY as u64) {
                    Ok(t) => t,
                    Err(e) => return err(id, -32602, format!("failed to decode transaction: {e}")),
                };
                // FULL-PQ: classical envelopes refused at intake, before crypto.
                {
                    let pq_ok = match tx.pq_envelope() {
                        Some(env) => env.scheme.is_post_quantum(),
                        None => false,
                    };
                    if !pq_ok {
                        return err(
                            id,
                            -32000,
                            "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
                        );
                    }
                }
                if !tx.verify_signature() {
                    return err(id, -32000, "invalid transaction signature");
                }
                let mut found: Option<ExtractedCall> = None;
                for op in &tx.payload {
                    match op {
                        crate::svm::OpCode::SysCallCallContract {
                            contract,
                            method,
                            arg,
                        } => {
                            found = Some(ExtractedCall {
                                contract: *contract,
                                method: method.clone(),
                                args: vec![*arg],
                                calldata: Vec::new(),
                            });
                            break;
                        }
                        crate::svm::OpCode::SysCallCallContractArgs {
                            contract,
                            method,
                            args,
                            calldata,
                        } => {
                            found = Some(ExtractedCall {
                                contract: *contract,
                                method: method.clone(),
                                args: args.clone(),
                                calldata: calldata.clone(),
                            });
                            break;
                        }
                        _ => {}
                    }
                }
                let extracted = match found {
                    Some(f) => f,
                    None => {
                        return err(
                            id,
                            -32602,
                            "transaction does not contain SysCallCallContract payload",
                        )
                    }
                };
                let (contract_addr, method_bytes, tx_args, tx_calldata) = (
                    extracted.contract,
                    extracted.method,
                    extracted.args,
                    extracted.calldata,
                );
                let method_str = match std::str::from_utf8(&method_bytes) {
                    Ok(m) => m.to_string(),
                    Err(_) => return err(id, -32602, "invalid contract method name"),
                };
                let outcome = preview_contract_call(
                    st,
                    &contract_addr,
                    &method_str,
                    PreviewCall::RawArgs(&tx_args, &tx_calldata),
                    tx.amount,
                    &tx.from,
                    tx.gas_limit,
                    preview_block_time(st).await,
                )
                .await;
                let tx_hash = tx.compute_tx_hash();
                // No receipt is filed (F5): the signed tx is returned with its
                // real hash so the caller can submit it, but it is NOT mined.
                return preview_outcome_response(id, outcome, Some(tx_hash));
            }

            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };

            let method_str = match p.get("method").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(id, -32602, "missing 'method' parameter"),
            };

            let args_param = p.get("args").or_else(|| p.get("arg"));

            // Multi-argument calls: every element of an argument array is one
            // parameter of the method. A missing `args` keeps the legacy
            // single-argument behaviour.
            let call_args = match args_param {
                Some(v) => match parse_contract_call_args(v) {
                    Ok(a) => a,
                    Err(e) => return err(id, -32602, format!("invalid args parameter: {e}")),
                },
                None => vec![0i64],
            };

            let value = p
                .get("value")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0);

            let gas_limit = p
                .get("gas_limit")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(crate::contract::MAX_CONTRACT_FUEL);

            // Execute the contract call. When the contract carries an ABI
            // manifest the manifest is authoritative: the method and its
            // arguments are validated and typed before execution.
            let abi = st.engine.get_contract_abi(&contract_addr).await;
            let typed_args = match &abi {
                Some(a) => match parse_abi_args(a, method_str, args_param) {
                    Ok(v) => Some(v),
                    Err(e) => return err(id, -32602, format!("ABI validation failed: {e}")),
                },
                None => None,
            };

            // F3/F4: `caller` is authenticated input to the contract. This
            // form carries no signed transaction, so the caller must be
            // named explicitly (`from` stays refused: the node cannot sign as
            // it). Without a caller the preview is REFUSED — the node never
            // falls back to the zero address (which inverts every
            // owner-guarded contract) and never invents a random one.
            let caller = match p.get("caller").and_then(|v| v.as_str()) {
                Some(s) => match parse_rpc_address(s) {
                    Ok(a) => a,
                    Err(e) => return err(id, -32602, format!("invalid caller address: {e}")),
                },
                None => {
                    return err(
                        id,
                        -32602,
                        "missing 'caller': a preview needs the address the call would execute as; pass `caller`, or sign the call locally and preview it via the `tx` form",
                    )
                }
            };

            // The ABI encoding is validated here so an unencodable call is a
            // strict parameter error (-32602), never a preview "failure". No
            // transaction is built (this form has no signer), so the encoded
            // blob is discarded after validation.
            if let (Some(a), Some(args)) = (&abi, &typed_args) {
                if let Err(e) = a.encode_args(method_str, args) {
                    return err(id, -32602, format!("ABI encoding failed: {e}"));
                }
            }

            // H-03: the preview runs on a registry CLONE (see
            // `preview_contract_call`): the `value` leg is simulated with
            // the same failure modes, but no account, contract, trie or
            // mailbox state moves. The previewed call is never admitted and
            // never produces a receipt — only a `stell_sendRawTransaction`
            // submission can change state, when a block applies it.
            let block_time = preview_block_time(st).await;
            let outcome = match &typed_args {
                Some(args) => {
                    preview_contract_call(
                        st,
                        &contract_addr,
                        method_str,
                        PreviewCall::Abi(args),
                        value,
                        &caller,
                        gas_limit,
                        block_time,
                    )
                    .await
                }
                None => {
                    preview_contract_call(
                        st,
                        &contract_addr,
                        method_str,
                        PreviewCall::Plain(&call_args),
                        value,
                        &caller,
                        gas_limit,
                        block_time,
                    )
                    .await
                }
            };

            // No transaction exists for this form (the node cannot sign as
            // the caller), so `tx_hash` is null rather than the hash of a
            // fabricated ephemeral vehicle.
            preview_outcome_response(id, outcome, None)
        }
        // ---- the ABI manifest of a contract (typed interface discovery) ----
        "stell_getContractAbi" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            match st.engine.get_contract_abi_json(&contract_addr).await {
                Some(json_abi) => ok(
                    id,
                    json!({
                        "contract": hex::encode(contract_addr),
                        "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                        "abi": serde_json::from_str::<Value>(&json_abi).unwrap_or(Value::Null),
                        "abi_json": json_abi,
                    }),
                ),
                None => ok(
                    id,
                    json!({
                        "contract": hex::encode(contract_addr),
                        "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                        "abi": Value::Null,
                    }),
                ),
            }
        }

        // ---- contract source verification (audit P2-15, Sourcify-style) ----
        // `stell_verifyContractSource` recompiles the claimed `.wat` source
        // with the deploy-time pipeline and compares the rebuilt bytecode
        // hash to the on-chain `code_hash`. Strictly READ-ONLY: it never
        // mutates state (in particular it never sets `source_hash` — that is
        // the signed `stell_registerContractSource` action below).
        "stell_verifyContractSource" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            let onchain = match st.engine.get_contract_code_hash(&contract_addr).await {
                Some(h) => h,
                None => return err(id, -32602, "contract not found"),
            };
            let compiler = p
                .get("compiler")
                .and_then(|v| v.as_str())
                .unwrap_or("wat2wasm-1.0");
            let flags = p
                .get("compiler_flags")
                .or_else(|| p.get("flags"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let source_opt = p.get("source").and_then(|v| v.as_str());
            let source_hex_opt = p.get("source_hex").and_then(|v| v.as_str());
            let claimed_hash_opt = p.get("source_hash").and_then(|v| v.as_str());

            // Hash-only check: no source text submitted. It answers whether
            // the claimed fingerprint is the REGISTERED one and NOTHING
            // else: no bytecode was rebuilt, so it can never report
            // `verified: true` (F7 — a hash claim is not a verification).
            if source_opt.is_none() && source_hex_opt.is_none() {
                match claimed_hash_opt {
                    Some(h) => {
                        let clean = h.trim().strip_prefix("0x").unwrap_or(h.trim());
                        let claimed = match hex::decode(clean) {
                            Ok(b) if b.len() == 32 => {
                                let mut a = [0u8; 32];
                                a.copy_from_slice(&b);
                                a
                            }
                            _ => return err(id, -32602, "invalid source_hash: expected 32 bytes hex"),
                        };
                        let registered = st.engine.get_contract_source_hash(&contract_addr).await;
                        let hash_matches = registered == Some(claimed);
                        return ok(id, json!({
                            "contract": hex::encode(contract_addr),
                            "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                            // `verified` is a BUILD attestation: a hash
                            // comparison never earns it.
                            "verified": false,
                            "hash_matches_registered": hash_matches,
                            "onchain_code_hash": hex::encode(onchain),
                            "rebuilt_code_hash": Value::Null,
                            "source_hash": hex::encode(claimed),
                            "compiler": compiler,
                            "compiler_flags": flags,
                            "reason": if hash_matches {
                                "hash-only check: matches the registered source hash, but NO rebuild was performed — submit the source text to verify"
                            } else {
                                "claimed source hash does not match the registered one (no rebuild performed)"
                            },
                            "registered": registered.is_some(),
                        }));
                    }
                    None => return err(id, -32602, "missing source: provide 'source' (wat text), 'source_hex', or 'source_hash'"),
                }
            }

            let source_bytes =
                match crate::contract_source::decode_source_bytes(source_opt, source_hex_opt) {
                    Ok(b) => b,
                    Err(e) => return err(id, -32602, e),
                };
            let v = crate::contract_source::verify_source_for_code_hash(
                &onchain,
                &source_bytes,
                compiler,
                flags,
            );
            let registered = st.engine.get_contract_source_hash(&contract_addr).await;
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "verified": v.verified,
                    "onchain_code_hash": v.onchain_code_hash,
                    "rebuilt_code_hash": v.rebuilt_code_hash,
                    "source_hash": v.source_hash,
                    "compiler": v.compiler,
                    "compiler_flags": v.compiler_flags,
                    "reason": v.reason,
                    "registered": registered.is_some(),
                    "registered_source_hash": registered.map(hex::encode).unwrap_or_default(),
                }),
            )
        }

        // Read the registered source fingerprint of a contract (`null` =
        // unverified). The node stores only the fingerprint, never the text;
        // the verified text lives in the indexer
        // (`GET /api/v2/contract/:address/source`).
        //
        // F7: `verified: true` here is a BUILD attestation, not a bare hash
        // claim — `stell_registerContractSource` only accepts a fingerprint
        // after REBUILDING the submitted source and matching the deployed
        // code hash, so a registered fingerprint is one the node reproduced.
        "stell_getContractSource" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            let onchain = match st.engine.get_contract_code_hash(&contract_addr).await {
                Some(h) => h,
                None => return err(id, -32602, "contract not found"),
            };
            let registered = st.engine.get_contract_source_hash(&contract_addr).await;
            let verified = registered.is_some();
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "code_hash": hex::encode(onchain),
                    "source_hash": registered.map(hex::encode).unwrap_or_default(),
                    "verified": verified,
                    "verification": if verified {
                        "rebuild_at_registration"
                    } else {
                        "none"
                    },
                    "verified_means": "the node rebuilt the registered source and matched this code_hash; a hash claim alone is never verified",
                }),
            )
        }

        // Register a verified-source fingerprint. The ONLY state-changing half
        // of source verification, and it moves ONLY by an explicit,
        // creator-signed action: `signature` is the contract creator's PQ
        // signature over `b"STELL_REGISTER_SOURCE" || contract || source_hash`.
        // Self-authenticating like `stell_sendRawTransaction` (no API token —
        // the signature IS the authority); anyone may submit, only the
        // creator's signature verifies.
        //
        // F7: the signature alone is NOT verification — it only proves the
        // creator chose the fingerprint. Registration therefore ALSO requires
        // the source text and REBUILDS it: the rebuilt bytecode hash must
        // equal the deployed `code_hash`, and the claimed `source_hash` must
        // be the digest of exactly that text. A hash that was never compared
        // to the code is REFUSED, so `verified: true` (here and in
        // `stell_getContractSource`) always means "this node reproduced the
        // deployed bytes from the registered source".
        "stell_registerContractSource" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            let hash_str = match p.get("source_hash").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(id, -32602, "missing 'source_hash' parameter"),
            };
            let clean = hash_str
                .trim()
                .strip_prefix("0x")
                .unwrap_or(hash_str.trim());
            let shash: [u8; 32] = match hex::decode(clean) {
                Ok(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => return err(id, -32602, "invalid source_hash: expected 32 bytes hex"),
            };
            let sig_str = match p.get("signature").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(
                    id,
                    -32602,
                    "missing 'signature' parameter: registration requires the creator's signature",
                ),
            };
            let pubkey_str = p
                .get("pubkey")
                .or_else(|| p.get("public_key"))
                .and_then(|v| v.as_str());
            let creator = match st.engine.contracts_read().await.get(&contract_addr) {
                Some(c) => c.creator,
                None => return err(id, -32602, "contract not found"),
            };
            if let Err(e) = crate::contract_source::verify_register_signature_with_pubkey(
                &creator,
                &contract_addr,
                &shash,
                sig_str,
                pubkey_str,
            ) {
                return err(id, -32602, e);
            }

            // The rebuild half: without it the badge would be a signature
            // over an unconstrained 32-byte claim.
            let source_opt = p.get("source").and_then(|v| v.as_str());
            let source_hex_opt = p.get("source_hex").and_then(|v| v.as_str());
            if source_opt.is_none() && source_hex_opt.is_none() {
                return err(
                    id,
                    -32602,
                    "missing source: registration requires 'source' (wat text) or 'source_hex' so the node can rebuild it against the deployed code hash; a hash-only claim is not verifiable",
                );
            }
            let source_bytes =
                match crate::contract_source::decode_source_bytes(source_opt, source_hex_opt) {
                    Ok(b) => b,
                    Err(e) => return err(id, -32602, e),
                };
            let onchain = match st.engine.get_contract_code_hash(&contract_addr).await {
                Some(h) => h,
                None => return err(id, -32602, "contract not found"),
            };
            let compiler = p
                .get("compiler")
                .and_then(|v| v.as_str())
                .unwrap_or("wat2wasm-1.0");
            let flags = p
                .get("compiler_flags")
                .or_else(|| p.get("flags"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let verification = match crate::contract_source::verify_registration(
                &onchain,
                &source_bytes,
                &shash,
                compiler,
                flags,
            ) {
                Ok(v) => v,
                Err(e) => return err(id, -32000, e),
            };
            if !verification.verified {
                return err(
                    id,
                    -32000,
                    format!("registration refused: {}", verification.reason),
                );
            }

            if let Err(e) = st
                .engine
                .register_contract_source(&contract_addr, shash, creator)
                .await
            {
                return err(id, -32602, e.to_string());
            }
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "source_hash": hex::encode(shash),
                    "onchain_code_hash": verification.onchain_code_hash,
                    "rebuilt_code_hash": verification.rebuilt_code_hash,
                    "compiler": verification.compiler,
                    "compiler_flags": verification.compiler_flags,
                    "registered": true,
                    "verified": true,
                    "rebuilt": true,
                }),
            )
        }

        // Explicit receipt endpoint for contract calls (Near / TON receipt fetching)
        "stell_getContractReceipt" => {
            let h = match params["hash"]
                .as_str()
                .or_else(|| params.as_str())
                .and_then(|s| parse_hash(s).ok())
            {
                Some(h) => h,
                None => return err(id, -32602, "missing tx hash"),
            };
            let idx = st.receipts.read().await;
            match idx.get(&h) {
                Some(r) => {
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
                    ok(
                        id,
                        json!({
                            "status": if r.success { "success" } else { "failed" },
                            "return_value": r.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
                            "gas_used": r.gas_used.unwrap_or(0),
                            "events": events_view,
                            "tx_hash": hex::encode(r.tx_hash),
                        }),
                    )
                }
                None => {
                    let pending = st.mempool.read().await.contains(&h);
                    ok(
                        id,
                        json!({ "status": if pending { "pending" } else { "unknown" } }),
                    )
                }
            }
        }

        _ => unreachable!(),
    }
}
