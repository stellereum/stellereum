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

/// H-03: read-only contract-call preview executed on a CLONE of the contract
/// registry. Returns the same
/// [`crate::state_engine::ContractCallOutcome`] the block-applied execution
/// would report (same return value, gas and events), but touches NO live
/// state: no debit/credit, no balance syncs, no outbound-message routing, no
/// trie writes. State changes happen exclusively when a transaction submitted
/// via `stell_sendRawTransaction` is applied by a block (N-03: the previewed
/// tx itself is dropped, never admitted).
///
/// The `value` leg is simulated on the clone with the same failure modes the
/// old direct path had: a sender that cannot cover `value` fails with
/// `insufficient funds to transfer value: …` and nothing moves. Execution
/// uses the default call context, exactly like the engine's structured-call
/// helpers did, so previews are result-identical to the pre-fix answers.
pub(super) async fn preview_contract_call(
    st: &RpcState,
    contract_addr: &[u8; 32],
    method: &str,
    call: PreviewCall<'_>,
    value: u64,
    sender: &[u8; 32],
    gas_limit: u64,
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
    let exec: Result<
        (i64, u64, Vec<crate::contract::ContractEvent>),
        crate::contract::ContractError,
    > = match call {
        PreviewCall::Plain(args) => work
            .call_args(contract_addr, method, args, gas_limit)
            .map(|(r, u, e, _)| (r, u, e)),
        PreviewCall::RawArgs(args, calldata) => work
            .call_with_context_args_calldata(
                contract_addr,
                method,
                args,
                calldata,
                gas_limit,
                &crate::contract::ContractCallContext::default(),
            )
            .map(|o| (o.result, o.fuel_used, o.events)),
        PreviewCall::Abi(args) => work
            .call_abi(contract_addr, method, args, gas_limit)
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
/// preview. It files the node-local receipt for the CLONE preview `outcome`
/// and renders the canonical response shape — and NOTHING else: the
/// transaction is DROPPED (never admitted to the mempool, never gossipped).
/// State changes happen exclusively when a block applies a transaction
/// submitted via `stell_sendRawTransaction`. It never touches consensus
/// state itself.
///
/// (N-03 mempool-DoS fix: the old shape admitted every preview — including
/// keyless ephemeral-vehicle txs the caller never funded — into the mempool,
/// so an unauthenticated caller could fill the pool with unexecutable
/// transactions at zero cost. Previews now return the result and drop the
/// tx; callers that want on-chain execution sign locally and submit the
/// sealed tx via `stell_sendRawTransaction`.)
pub(super) async fn preview_contract_tx_and_respond(
    st: &RpcState,
    id: Value,
    tx: Transaction,
    contract_addr: [u8; 32],
    raw_tx_hex: String,
    outcome: crate::state_engine::ContractCallOutcome,
) -> Json<RpcResponse> {
    let gas_limit = tx.gas_limit;
    let tx_hash = tx.compute_tx_hash();

    // N-03: NO mempool admission, NO gossip broadcast — the preview tx is
    // dropped here. (The receipt below is a node-local preview record, not
    // an admission.)

    let is_success = outcome.status == "success";
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

    // Record receipt in receipt index
    st.receipts.write().await.insert(TxReceipt {
        tx_hash,
        height: st.height.load(std::sync::atomic::Ordering::Relaxed),
        block_hash: [0u8; 32],
        index: 0,
        success: is_success,
        gas_limit,
        fee_charged: outcome.gas_used,
        raw_tx: Some(raw_tx_hex),
        return_value: outcome.return_value,
        gas_used: Some(outcome.gas_used),
        events: outcome.events.clone(),
        contract_address: Some(contract_addr),
    });

    ok(
        id,
        json!({
            "tx_hash": hex::encode(tx_hash),
            "status": outcome.status,
            "return_value": outcome.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
            "gas_used": outcome.gas_used,
            "events": events_view,
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
            // N-02/N-03: this arm deploys nothing itself (preview only), but
            // it executes contract code on a clone and hands out chain
            // predictions — so it takes the same fail-closed token gate as
            // the governance writes: a valid token ALWAYS, on every bind.
            // Without a token it is refused before parsing (same refusal
            // properties as the gov arms).
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
                // admission, no gossip broadcast. On-chain execution needs a
                // `stell_sendRawTransaction` submission of the same sealed tx.

                let gas_cost = crate::svm::contract_deploy_gas(code.len());
                st.receipts.write().await.insert(TxReceipt {
                    tx_hash,
                    height: st.height.load(std::sync::atomic::Ordering::Relaxed),
                    block_hash: [0u8; 32],
                    index: 0,
                    success: true,
                    gas_limit: tx.gas_limit,
                    fee_charged: gas_cost,
                    raw_tx: Some(raw_tx_str.to_string()),
                    return_value: None,
                    gas_used: Some(gas_cost),
                    events: Vec::new(),
                    contract_address: Some(predicted),
                });

                return ok(
                    id,
                    json!({
                        "contract_address": hex::encode(predicted),
                        "contract_address_stl57": predicted_stl57,
                        "code_hash": hex::encode(code_hash),
                        "tx_hash": hex::encode(tx_hash),
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

            let gas_limit = p
                .get("gas_limit")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(crate::contract::MAX_CONTRACT_FUEL);

            // Optional typed ABI manifest: validated here (it would travel
            // inside a submitted tx's execution path at apply time, committed
            // next to the code hash by block application — never by this arm).
            if let Err(e) = parse_abi_manifest_param(p) {
                return err(id, -32602, format!("invalid abi parameter: {e}"));
            }

            // Ephemeral vehicle only: the node cannot sign as the caller (no
            // key is accepted), so the preview tx is signed by a fresh
            // random key. Its only purpose is to carry the deploy through
            // the CLONE preview; it is DROPPED afterwards (N-03: never
            // admitted, never gossipped). The predicted address is what block
            // application would derive for it.
            // FULL-PQ: the vehicle is an explicit Falcon-512 tx
            // (self-contained: verifies with no registry and no funding —
            // the preview authenticates the envelope, as with the old ed25519
            // vehicle; execution still fails closed on the unfunded balance).
            let eph_key = crate::post_quantum::FalconKeypair::generate();
            let from_addr = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &eph_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            );
            let nonce = st
                .engine
                .get_account(&from_addr)
                .await
                .map(|a| a.nonce)
                .unwrap_or(0);
            let predicted = crate::contract::contract_address(&from_addr, nonce);
            if st.engine.get_contract(&predicted).await.is_some() {
                return err(
                    id,
                    -32000,
                    "deploy contract failed: contract already exists",
                );
            }
            let predicted_stl57 = crate::address::encode_stl57_address(&predicted);
            let code_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&code).into();

            let mut tx = Transaction {
                from: from_addr,
                to: predicted,
                amount: 0,
                gas_limit,
                nonce,
                source_shard: 0,
                target_shard: 0,
                signature: Vec::new(),
                payload: vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = eph_key.sign(&msg);
            tx.signature = crate::sharding::PqSignatureEnvelope::new_explicit(
                crate::post_quantum::PqScheme::Falcon512,
                eph_key.public_key.clone(),
                sig,
            )
            .encode();
            let tx_hash = tx.compute_tx_hash();
            let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());

            // N-03: the ephemeral preview tx is DROPPED here — no mempool
            // admission, no gossip broadcast. On-chain execution needs a
            // locally-signed `stell_sendRawTransaction` submission.

            let gas_cost = crate::svm::contract_deploy_gas(code.len());
            st.receipts.write().await.insert(TxReceipt {
                tx_hash,
                height: st.height.load(std::sync::atomic::Ordering::Relaxed),
                block_hash: [0u8; 32],
                index: 0,
                success: true,
                gas_limit,
                fee_charged: gas_cost,
                raw_tx: Some(raw_tx_hex),
                return_value: None,
                gas_used: Some(gas_cost),
                events: Vec::new(),
                contract_address: Some(predicted),
            });

            ok(
                id,
                json!({
                    "contract_address": hex::encode(predicted),
                    "contract_address_stl57": predicted_stl57,
                    "code_hash": hex::encode(code_hash),
                    "tx_hash": hex::encode(tx_hash),
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
            // direct parameters for a keyless preview (an ephemeral vehicle
            // carries the call through the CLONE preview; DROPPED afterwards).
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
            // `stell_sendRawTransaction`, previewed on a registry clone, and
            // DROPPED — never executed against live state, never admitted.
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
                )
                .await;
                let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());
                return preview_contract_tx_and_respond(
                    st,
                    id,
                    tx,
                    contract_addr,
                    raw_tx_hex,
                    outcome,
                )
                .await;
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
            let arg = if let Some(v) = args_param {
                match parse_contract_call_arg(v) {
                    Ok(n) => n,
                    Err(e) => return err(id, -32602, format!("invalid args parameter: {e}")),
                }
            } else {
                0i64
            };

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

            // Ephemeral vehicle only (see above: no key is accepted). The
            // preview tx is signed by a fresh random key and carries the
            // call through the CLONE preview below; it is DROPPED afterwards
            // (N-03: never admitted, never gossipped).
            // FULL-PQ: explicit Falcon-512 vehicle (self-contained).
            let eph_key = crate::post_quantum::FalconKeypair::generate();
            let from_addr = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &eph_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            );

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

            // The replayable payload of the call: the wasm arguments plus the
            // canonical ABI encoding of the arguments (the calldata blob a
            // contract reads blob parameters from). Both are derived from the
            // SAME values the execution below uses, so a node replaying the
            // transaction executes exactly the same call.
            let (payload_args, payload_calldata): (Vec<i64>, Vec<u8>) = match (&abi, &typed_args) {
                (Some(a), Some(args)) => {
                    let calldata = match a.encode_args(method_str, args) {
                        Ok(c) => c,
                        Err(e) => return err(id, -32602, format!("ABI encoding failed: {e}")),
                    };
                    let scalars = args.iter().map(|v| v.as_i64().unwrap_or(0)).collect();
                    (scalars, calldata)
                }
                _ => (call_args.clone(), Vec::new()),
            };

            // H-03: the preview runs on a registry CLONE (see
            // `preview_contract_call`): the `value` leg is simulated with
            // the same failure modes, but no account, contract, trie or
            // mailbox state moves. The previewed tx is DROPPED (N-03); only
            // a `stell_sendRawTransaction` submission can change state, when
            // a block applies it.
            let outcome = match &typed_args {
                Some(args) => {
                    preview_contract_call(
                        st,
                        &contract_addr,
                        method_str,
                        PreviewCall::Abi(args),
                        value,
                        &from_addr,
                        gas_limit,
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
                        &from_addr,
                        gas_limit,
                    )
                    .await
                }
            };

            let sender_acc = st.engine.get_account(&from_addr).await;
            let nonce = sender_acc.map(|a| a.nonce).unwrap_or(0);

            // The transaction payload carries the call: a multi-argument
            // method (or an ABI-typed call) uses the argument-carrying opcode
            // so every node replays exactly the same parameter list.
            let call_opcode = if typed_args.is_some() || payload_args.len() > 1 {
                crate::svm::OpCode::SysCallCallContractArgs {
                    contract: contract_addr,
                    method: method_str.as_bytes().to_vec(),
                    args: payload_args,
                    calldata: payload_calldata,
                }
            } else {
                crate::svm::OpCode::SysCallCallContract {
                    contract: contract_addr,
                    method: method_str.as_bytes().to_vec(),
                    arg,
                }
            };

            let mut tx = Transaction {
                from: from_addr,
                to: contract_addr,
                amount: value,
                gas_limit,
                nonce,
                source_shard: 0,
                target_shard: 0,
                signature: Vec::new(),
                payload: vec![call_opcode],
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = eph_key.sign(&msg);
            tx.signature = crate::sharding::PqSignatureEnvelope::new_explicit(
                crate::post_quantum::PqScheme::Falcon512,
                eph_key.public_key.clone(),
                sig,
            )
            .encode();
            let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());

            preview_contract_tx_and_respond(st, id, tx, contract_addr, raw_tx_hex, outcome).await
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

            // Hash-only check: no source text submitted (the indexer-fetched
            // text path submits inline instead). Answers whether the claimed
            // fingerprint is the registered one — it performs NO rebuild.
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
                        let verified = registered == Some(claimed);
                        return ok(id, json!({
                            "contract": hex::encode(contract_addr),
                            "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                            "verified": verified,
                            "onchain_code_hash": hex::encode(onchain),
                            "rebuilt_code_hash": Value::Null,
                            "source_hash": hex::encode(claimed),
                            "compiler": compiler,
                            "compiler_flags": flags,
                            "reason": if verified { "ok: matches the registered source hash (no rebuild performed)" } else { "claimed source hash does not match the registered one" },
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
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "code_hash": hex::encode(onchain),
                    "source_hash": registered.map(hex::encode).unwrap_or_default(),
                    "verified": registered.is_some(),
                }),
            )
        }

        // Register a verified-source fingerprint. The ONLY state-changing half
        // of source verification, and it moves ONLY by an explicit,
        // creator-signed action: `signature` is the contract creator's ed25519
        // signature over `b"STELL_REGISTER_SOURCE" || contract || source_hash`.
        // Self-authenticating like `stell_sendRawTransaction` (no API token —
        // the signature IS the authority); anyone may submit, only the
        // creator's signature verifies. Call `stell_verifyContractSource`
        // first and register the `source_hash` it returns.
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
                    "registered": true,
                    "verified": true,
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
