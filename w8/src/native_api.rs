//! ONE stable, wallet-facing namespace for Stellereum's native capabilities.
//!
//! # Why
//!
//! The chain has always had native actors — an STS-20 token ledger, a staking
//! ledger, the Teleport bridge, a CLOB order book, session keys and an oracle
//! — but each one was reachable through its own ad-hoc RPC method with its own
//! parameter names and its own answer shape (`stell_tokenBalance`,
//! `stell_stakeOf`, `stell_orderBook`, `stell_sessionBudget`, …). A wallet
//! therefore had to learn N dialects and could not implement ONE adapter.
//!
//! This module is the single namespace that fixes that: every native
//! capability is reachable under `stell_<domain><Action>`, every method
//! answers with one documented, typed JSON shape, and every method is a
//! **thin, fail-closed wrapper over the state engine that already owns the
//! state**.
//!
//! The model follows the standards the ecosystem converged on:
//!
//! * NEAR `NEP-141` (fungible tokens) / `NEP-171` (staking) — named methods
//!   with named arguments and a typed answer per method;
//! * TON `TEP-74` (jetton) — a token "getter" surface a wallet binds to once;
//! * Solana's SPL token accounts — one interface per native capability.
//!
//! # The rule that keeps this layer honest
//!
//! **No new state. No new consensus rules.**
//!
//! * READ methods answer straight from the committed state the engine holds
//!   (`tokens_read`, `staking_read`, `bridge_read`, `orderbooks_read`,
//!   `session_keys_read`, `oracle_read`). They never invent a value and never
//!   cache one: a wallet that reads here and reads again after a block sees
//!   the same answer every node would.
//! * WRITE methods do NOT write. They answer with the **exact transaction the
//!   wallet has to sign** — the `OpCode` payload, its arguments and its gas —
//!   after checking, against committed state, the preconditions the
//!   execution path would check anyway. The wallet signs that payload and
//!   submits it through `stell_sendRawTransaction`; the state moves when (and
//!   only when) the transaction lands in a block.
//!
//! That is why a write method here cannot fork the chain: it produces bytes,
//! not state. It also means the preconditions are *surfaced early* — a wallet
//! that asks `stell_stakeBond` learns the bond is below the floor before it
//! signs, instead of after the transaction reverts.
//!
//! # Fail-closed
//!
//! Every method refuses rather than guesses:
//!
//! * a missing or malformed parameter is an error, never a default;
//! * an unknown token / validator / pair / session key / asset is an error,
//!   never a zero that reads like "the balance is zero";
//! * a precondition the execution path would reject (insufficient balance,
//!   a paused token, a bond under the floor, a replayed bridge deposit, a
//!   revoked session key) is an error here too.
//!
//! The JSON-RPC error codes are the standard ones: `-32602` for invalid
//! parameters, `-32004` for "not found", `-32003` for "the state says no".
//!
//! # One name, one meaning
//!
//! A JSON-RPC method name may have exactly ONE meaning, so a method of this
//! namespace never collides with a method the node exposes elsewhere. The one
//! collision that existed — the bridge deposit — is resolved by giving the two
//! halves DIFFERENT names:
//!
//! * `stell_bridgeDeposit` — the **record** read: the acceptance record of an
//!   inbound deposit (the node's long-standing RPC arm, used by the TVL probe
//!   and the watcher dashboards).
//! * `stell_bridgeDepositPrepare` — the **prepare**: the deposit-claim
//!   transaction the wallet has to sign.
//!
//! The name says which half it is, so a caller can never ask for the prepare
//! and silently receive the record (or the other way round).

use serde_json::{json, Value};

use crate::state_engine::InMemoryStateEngine;

// ---------------------------------------------------------------------------
// Version & manifest
// ---------------------------------------------------------------------------

/// Version of the native interface contract.
///
/// Bumped only when an existing method's ANSWER SHAPE changes. New methods do
/// not bump it: a wallet that integrates against `1.0.0` keeps working.
pub const NATIVE_API_VERSION: &str = "1.0.0";

/// What a method in the namespace does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodKind {
    /// Answers from committed state; mutates nothing.
    Read,
    /// Produces the transaction the wallet must sign; mutates nothing.
    Prepare,
}

/// One method of the namespace.
#[derive(Clone, Copy, Debug)]
pub struct MethodSpec {
    /// The JSON-RPC method name.
    pub name: &'static str,
    /// Read or prepare.
    pub kind: MethodKind,
    /// One-line human description.
    pub summary: &'static str,
    /// The parameters the method accepts, required ones first.
    pub params: &'static [&'static str],
    /// How many of `params` are REQUIRED.
    ///
    /// A method with `required == 0` answers an empty call (every parameter
    /// it takes has a default or is a filter). A method with `required > 0`
    /// REFUSES an empty call with `-32602` — never a default.
    pub required: usize,
}

/// Every method of the namespace, in a stable order.
///
/// `stell_nativeApi` serves this list, so a wallet can discover the whole
/// interface with ONE call instead of hard-coding it.
pub const METHODS: &[MethodSpec] = &[
    // --- token (NEP-141-like) ---
    MethodSpec {
        name: "stell_tokenTransfer",
        kind: MethodKind::Prepare,
        summary: "Prepare an STS-20 token transfer (NEP-141 `ft_transfer`).",
        params: &["token", "from", "to", "amount"],
        required: 4,
    },
    MethodSpec {
        name: "stell_tokenBalanceOf",
        kind: MethodKind::Read,
        summary: "Token balance of an account (NEP-141 `ft_balance_of`).",
        params: &["token", "account"],
        required: 2,
    },
    MethodSpec {
        name: "stell_tokenMetadata",
        kind: MethodKind::Read,
        summary: "Token metadata: name, symbol, decimals, supply, minter.",
        params: &["token"],
        required: 1,
    },
    MethodSpec {
        name: "stell_tokenAllowance",
        kind: MethodKind::Read,
        summary: "Allowance granted by an owner to a spender.",
        params: &["token", "owner", "spender"],
        required: 3,
    },
    // --- staking (NEP-171-like) ---
    MethodSpec {
        name: "stell_stakeBond",
        kind: MethodKind::Prepare,
        summary: "Prepare a validator self-bond (or a top-up).",
        params: &["validator", "amount"],
        required: 2,
    },
    MethodSpec {
        name: "stell_stakeUnbond",
        kind: MethodKind::Prepare,
        summary: "Prepare the start of an unbonding period.",
        params: &["validator", "amount"],
        required: 2,
    },
    MethodSpec {
        name: "stell_stakeWithdraw",
        kind: MethodKind::Prepare,
        summary: "Prepare the withdrawal of a matured self-bond.",
        params: &["validator"],
        required: 1,
    },
    MethodSpec {
        name: "stell_delegate",
        kind: MethodKind::Prepare,
        summary: "Prepare a delegation to a validator.",
        params: &["validator", "amount", "delegator"],
        required: 2,
    },
    MethodSpec {
        name: "stell_undelegate",
        kind: MethodKind::Prepare,
        summary: "Prepare the start of an undelegation (delegator exit).",
        params: &["validator", "amount", "delegator"],
        required: 2,
    },
    MethodSpec {
        name: "stell_claimRewards",
        kind: MethodKind::Prepare,
        summary: "Prepare a staking-rewards claim (validator or delegator arm).",
        params: &["validator", "role", "delegator"],
        required: 1,
    },
    // --- bridge ---
    // NOTE the name: the PREPARE method is `stell_bridgeDepositPrepare`, NOT
    // `stell_bridgeDeposit`. The node's JSON-RPC surface already answers
    // `stell_bridgeDeposit` with the deposit RECORD (a read, used by the
    // TVL probe and the watcher dashboards), and a JSON-RPC method name may
    // only have ONE meaning. The prepare therefore carries an explicit
    // `Prepare` suffix — see the module docs and `docs/RPC.md`.
    MethodSpec {
        name: "stell_bridgeDepositPrepare",
        kind: MethodKind::Prepare,
        summary: "Prepare an inbound Teleport deposit claim.",
        params: &["chain", "source_tx_hash", "recipient", "amount"],
        required: 4,
    },
    MethodSpec {
        name: "stell_bridgeWithdraw",
        kind: MethodKind::Prepare,
        summary: "Prepare an outbound Teleport withdrawal request.",
        params: &["chain", "target_address", "amount", "sender"],
        required: 3,
    },
    MethodSpec {
        name: "stell_bridgeStatus",
        kind: MethodKind::Read,
        summary: "Status of a settled deposit (`source_tx_hash`) or a parked withdrawal (`request_id`).",
        params: &["source_tx_hash", "request_id"],
        required: 1,
    },
    // --- order book (CLOB) ---
    MethodSpec {
        name: "stell_orderBookPlace",
        kind: MethodKind::Prepare,
        summary: "Prepare a limit/market order on a CLOB pair.",
        params: &["side", "price", "amount", "pair", "trader"],
        required: 3,
    },
    MethodSpec {
        name: "stell_orderBookCancel",
        kind: MethodKind::Prepare,
        summary: "Prepare the cancellation of a resting order.",
        params: &["order_id", "pair", "trader"],
        required: 1,
    },
    MethodSpec {
        name: "stell_orderBookSnapshot",
        kind: MethodKind::Read,
        summary: "Committed depth of a CLOB pair.",
        params: &["pair"],
        required: 0,
    },
    // --- session keys ---
    MethodSpec {
        name: "stell_sessionKeyRegister",
        kind: MethodKind::Prepare,
        summary: "Prepare a session-key grant (the master still has to sign it).",
        params: &[
            "session_pubkey",
            "master",
            "valid_until",
            "max_gas_spend",
            "scope",
            "max_value_per_tx",
        ],
        required: 5,
    },
    MethodSpec {
        name: "stell_sessionKeyRevoke",
        kind: MethodKind::Prepare,
        summary: "Prepare the revocation of a registered session key.",
        params: &["session_pubkey", "master"],
        required: 1,
    },
    MethodSpec {
        name: "stell_sessionKeys",
        kind: MethodKind::Read,
        summary: "The committed session-key registry (optionally by master).",
        params: &["master"],
        required: 0,
    },
    // --- oracle ---
    MethodSpec {
        name: "stell_oraclePrice",
        kind: MethodKind::Read,
        summary: "The committed oracle price of an asset.",
        params: &["asset"],
        required: 1,
    },
    MethodSpec {
        name: "stell_oracleFeeds",
        kind: MethodKind::Read,
        summary: "Every committed oracle feed.",
        params: &["asset"],
        required: 0,
    },
    // --- discovery ---
    MethodSpec {
        name: "stell_nativeApi",
        kind: MethodKind::Read,
        summary: "The manifest of this namespace (methods, kinds, parameters).",
        params: &[],
        required: 0,
    },
];

/// Is `method` part of this namespace?
pub fn is_native_method(method: &str) -> bool {
    METHODS.iter().any(|m| m.name == method)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything this layer can refuse with.
///
/// The variants map onto standard JSON-RPC error codes, so a wallet can treat
/// them like any other RPC failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeApiError {
    /// A parameter is missing, malformed or out of range.
    InvalidParams(String),
    /// The named token / validator / pair / key / asset does not exist.
    NotFound(String),
    /// Committed state says this operation would be refused.
    PreconditionFailed(String),
    /// The method is not part of this namespace.
    UnknownMethod(String),
}

impl NativeApiError {
    /// The JSON-RPC error code for this refusal.
    pub fn code(&self) -> i64 {
        match self {
            NativeApiError::InvalidParams(_) => -32602,
            NativeApiError::NotFound(_) => -32004,
            NativeApiError::PreconditionFailed(_) => -32003,
            NativeApiError::UnknownMethod(_) => -32601,
        }
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        match self {
            NativeApiError::InvalidParams(m)
            | NativeApiError::NotFound(m)
            | NativeApiError::PreconditionFailed(m)
            | NativeApiError::UnknownMethod(m) => m,
        }
    }
}

impl std::fmt::Display for NativeApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

fn invalid(msg: impl Into<String>) -> NativeApiError {
    NativeApiError::InvalidParams(msg.into())
}

fn not_found(msg: impl Into<String>) -> NativeApiError {
    NativeApiError::NotFound(msg.into())
}

fn refused(msg: impl Into<String>) -> NativeApiError {
    NativeApiError::PreconditionFailed(msg.into())
}

// ---------------------------------------------------------------------------
// Parameter helpers
// ---------------------------------------------------------------------------

/// The parameter object of a call.
///
/// Accepts the three dialects a wallet may use: an object (`{"token": …}`),
/// a one-element array (`[{…}]`) and a bare string / number (meaning the
/// single positional argument).
fn param_obj(params: &Value) -> Value {
    match params {
        Value::Array(a) => a.first().cloned().unwrap_or_else(|| json!({})),
        Value::Null => json!({}),
        other => other.clone(),
    }
}

/// Read a required string parameter.
fn need_str(p: &Value, key: &str) -> Result<String, NativeApiError> {
    match p.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        Some(Value::String(_)) => Err(invalid(format!("parameter '{key}' must not be empty"))),
        Some(_) => Err(invalid(format!("parameter '{key}' must be a string"))),
        None => Err(invalid(format!("missing parameter '{key}'"))),
    }
}

/// Read an optional string parameter.
fn opt_str(p: &Value, key: &str) -> Option<String> {
    p.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read a required unsigned integer parameter.
///
/// Accepts a JSON number or a decimal string (the convention used everywhere
/// else in this node for amounts), never a float and never a negative value.
fn need_u64(p: &Value, key: &str) -> Result<u64, NativeApiError> {
    let v = p
        .get(key)
        .ok_or_else(|| invalid(format!("missing parameter '{key}'")))?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return Err(invalid(format!("parameter '{key}' must not be empty")));
        }
        return s
            .parse::<u64>()
            .map_err(|_| invalid(format!("parameter '{key}' must be an unsigned integer")));
    }
    Err(invalid(format!("parameter '{key}' must be an unsigned integer")))
}

/// Read an optional unsigned integer parameter.
fn opt_u64(p: &Value, key: &str) -> Option<u64> {
    p.get(key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
    })
}

/// Read a required 32-byte address parameter.
///
/// Accepts the hex (64 or 40 characters) and the Stl57 forms a wallet may
/// hold; both resolve to the same 32-byte account id.
fn need_addr(p: &Value, key: &str) -> Result<[u8; 32], NativeApiError> {
    let s = need_str(p, key)?;
    parse_address(&s).map_err(|e| invalid(format!("parameter '{key}': {e}")))
}

/// Parse an address in any of the forms a wallet may hold.
fn parse_address(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    if let Ok(a) = crate::address::parse_address(trimmed) {
        return Ok(a);
    }
    let hex_clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    match hex_clean.len() {
        64 => hex::decode(hex_clean)
            .map_err(|e| format!("bad hex: {e}"))
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).map_err(|_| "expected 32 bytes".to_string())),
        40 => hex::decode(hex_clean)
            .map_err(|e| format!("bad hex: {e}"))
            .and_then(|b| <[u8; 20]>::try_from(b.as_slice()).map_err(|_| "expected 20 bytes".to_string()))
            .map(|a| crate::evm_adapter::evm_to_stell_address(&a)),
        _ => Err("expected a 64-hex address or a Stl57 address".to_string()),
    }
}

/// Hex address + its Stl57 form, the pair every answer in this namespace uses.
fn addr_pair(a: &[u8; 32]) -> (String, String) {
    (
        hex::encode(a),
        crate::address::encode_stl57_address(a),
    )
}

/// The wrapper every prepared transaction carries: what to sign and how to
/// submit it. This is what makes the namespace a ONE-TIME integration.
fn prepared(
    action: &str,
    gas_limit: u64,
    op: &str,
    args: Value,
    signer: Option<&[u8; 32]>,
) -> Value {
    let signer_json = match signer {
        Some(s) => {
            let (hex, stl57) = addr_pair(s);
            json!({ "address": hex, "stl57": stl57 })
        }
        None => Value::Null,
    };
    json!({
        "action": action,
        "gas_limit": gas_limit,
        "signer": signer_json,
        "transaction": {
            "op": op,
            "args": args,
        },
        "submit_with": "stell_sendRawTransaction",
    })
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch one native-API method.
///
/// `engine` is the node's own state engine — the single source of truth for
/// every answer below. The function never writes to it.
pub async fn dispatch(
    engine: &InMemoryStateEngine,
    method: &str,
    params: &Value,
) -> Result<Value, NativeApiError> {
    let p = param_obj(params);
    match method {
        // ---- token (NEP-141-like) ----
        "stell_tokenTransfer" => token_transfer(engine, &p).await,
        "stell_tokenBalanceOf" => token_balance_of(engine, &p).await,
        "stell_tokenMetadata" => token_metadata(engine, &p).await,
        "stell_tokenAllowance" => token_allowance(engine, &p).await,
        // ---- staking (NEP-171-like) ----
        "stell_stakeBond" => stake_bond(engine, &p).await,
        "stell_stakeUnbond" => stake_unbond(engine, &p).await,
        "stell_stakeWithdraw" => stake_withdraw(engine, &p).await,
        "stell_delegate" => delegate(engine, &p).await,
        "stell_undelegate" => undelegate(engine, &p).await,
        "stell_claimRewards" => claim_rewards(engine, &p).await,
        // ---- bridge ----
        "stell_bridgeDepositPrepare" => bridge_deposit(engine, &p).await,
        "stell_bridgeWithdraw" => bridge_withdraw(engine, &p).await,
        "stell_bridgeStatus" => bridge_status(engine, &p).await,
        // ---- order book ----
        "stell_orderBookPlace" => order_book_place(engine, &p).await,
        "stell_orderBookCancel" => order_book_cancel(engine, &p).await,
        "stell_orderBookSnapshot" => order_book_snapshot(engine, &p).await,
        // ---- session keys ----
        "stell_sessionKeyRegister" => session_key_register(engine, &p).await,
        "stell_sessionKeyRevoke" => session_key_revoke(engine, &p).await,
        "stell_sessionKeys" => session_keys(engine, &p).await,
        // ---- oracle ----
        "stell_oraclePrice" => oracle_price(engine, &p).await,
        "stell_oracleFeeds" => oracle_feeds(engine, &p).await,
        // ---- discovery ----
        "stell_nativeApi" => Ok(native_api_manifest()),
        other => Err(NativeApiError::UnknownMethod(format!(
            "method not found: {other}"
        ))),
    }
}

/// The manifest of the namespace: the whole interface in one answer.
pub fn native_api_manifest() -> Value {
    let methods: Vec<Value> = METHODS
        .iter()
        .map(|m| {
            json!({
                "name": m.name,
                "kind": match m.kind {
                    MethodKind::Read => "read",
                    MethodKind::Prepare => "prepare",
                },
                "summary": m.summary,
                "params": m.params,
                "required": m.required,
            })
        })
        .collect();
    json!({
        "version": NATIVE_API_VERSION,
        "namespace": "stell",
        "methods": methods,
        "method_count": methods.len(),
        "conventions": {
            "amounts": "unsigned integer base units (nano-STELL for STELL, base units for a token) encoded as decimal strings",
            "addresses": "64-char lowercase hex; Stl57 forms are accepted on input",
            "write_methods": "prepare-only: they return the transaction to sign and never mutate state",
            "errors": "-32602 invalid params, -32004 not found, -32003 refused by committed state",
        }
    })
}

// ---------------------------------------------------------------------------
// Token (over `crate::token`, the STS-20 ledger)
// ---------------------------------------------------------------------------

/// Look the token up, refusing an unknown id.
///
/// An unknown token is an ERROR, never a zero balance: a wallet that reads
/// "0" for a token id it mistyped would show an empty balance instead of a
/// failure, and the difference is the whole point of fail-closed.
async fn require_token(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<[u8; 32], NativeApiError> {
    let id = need_addr(p, "token")?;
    let reg = engine.tokens_read().await;
    if !reg.exists(&id) {
        return Err(not_found(format!(
            "token not found: {}",
            hex::encode(id)
        )));
    }
    Ok(id)
}

async fn token_balance_of(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    let account = need_addr(p, "account")?;
    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    let (acc_hex, acc_stl57) = addr_pair(&account);
    let (tok_hex, tok_stl57) = addr_pair(&token);
    Ok(json!({
        "token": tok_hex,
        "token_stl57": tok_stl57,
        "account": acc_hex,
        "account_stl57": acc_stl57,
        "balance": actor.balance_of(&account).to_string(),
        "decimals": actor.metadata.decimals,
        "symbol": actor.metadata.symbol,
        "name": actor.metadata.name,
        "total_supply": actor.metadata.total_supply.to_string(),
    }))
}

async fn token_metadata(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    let (tok_hex, tok_stl57) = addr_pair(&token);
    let (minter_hex, _) = addr_pair(&actor.metadata.minter);
    Ok(json!({
        "token": tok_hex,
        "token_stl57": tok_stl57,
        "name": actor.metadata.name,
        "symbol": actor.metadata.symbol,
        "decimals": actor.metadata.decimals,
        "total_supply": actor.metadata.total_supply.to_string(),
        "max_supply": actor.metadata.max_supply.map(|s| s.to_string()),
        "minter": minter_hex,
        "paused": actor.metadata.paused,
        "description": actor.metadata.description,
    }))
}

async fn token_allowance(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    let owner = need_addr(p, "owner")?;
    let spender = need_addr(p, "spender")?;
    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    let (tok_hex, _) = addr_pair(&token);
    let (owner_hex, _) = addr_pair(&owner);
    let (spender_hex, _) = addr_pair(&spender);
    Ok(json!({
        "token": tok_hex,
        "owner": owner_hex,
        "spender": spender_hex,
        "allowance": actor.allowance(&owner, &spender).to_string(),
    }))
}

async fn token_transfer(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    // `from` is the signer of the prepared transaction; `owner` is accepted as
    // an alias so a wallet that speaks NEP-141 vocabulary does not have to
    // rename anything.
    let from = match p.get("from").or_else(|| p.get("owner")) {
        Some(_) => need_addr(p, "from").or_else(|_| need_addr(p, "owner"))?,
        None => return Err(invalid("missing parameter 'from'")),
    };
    let to = need_addr(p, "to")?;
    let amount = need_u64(p, "amount")?;

    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if to == crate::token::ZERO_ADDRESS {
        return Err(refused("the zero address cannot receive tokens"));
    }
    if from == to {
        return Err(refused("cannot transfer to self"));
    }

    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    if actor.metadata.paused {
        return Err(refused("token is paused"));
    }
    let balance = actor.balance_of(&from);
    if balance < amount {
        return Err(refused(format!(
            "insufficient token balance: have {balance}, need {amount}"
        )));
    }
    let decimals = actor.metadata.decimals;
    let symbol = actor.metadata.symbol.clone();
    drop(reg);

    let (tok_hex, tok_stl57) = addr_pair(&token);
    let (from_hex, from_stl57) = addr_pair(&from);
    let (to_hex, to_stl57) = addr_pair(&to);
    let mut out = prepared(
        "token_transfer",
        crate::token::GAS_TOKEN_TRANSFER,
        "SysCallTokenTransfer",
        json!({
            "token_id": tok_hex,
            "to": to_hex,
            "amount": amount,
        }),
        Some(&from),
    );
    out["token"] = json!(tok_hex);
    out["token_stl57"] = json!(tok_stl57);
    out["from"] = json!(from_hex);
    out["from_stl57"] = json!(from_stl57);
    out["to"] = json!(to_hex);
    out["to_stl57"] = json!(to_stl57);
    out["amount"] = json!(amount.to_string());
    out["sender_balance"] = json!(balance.to_string());
    out["decimals"] = json!(decimals);
    out["symbol"] = json!(symbol);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Staking (over `crate::staking`)
// ---------------------------------------------------------------------------

async fn stake_bond(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let validator = need_addr(p, "validator")?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let floor = crate::staking::required_bond_floor_nano();
    let ledger = engine.staking_read().await;
    let existing = ledger.validators.get(&validator);
    let is_topup = existing.is_some();
    if !is_topup && amount < floor {
        return Err(refused(format!(
            "bond below the required minimum validator bond plus buffer (required {floor} nano-STELL)"
        )));
    }
    if let Some(v) = existing {
        if amount < floor {
            return Err(refused(format!(
                "bond below the required minimum validator bond plus buffer (required {floor} nano-STELL)"
            )));
        }
        if amount > v.self_bond {
            return Err(refused(format!(
                "top-up exceeds the current self-bond: have {}, top-up {}",
                v.self_bond, amount
            )));
        }
    }
    drop(ledger);

    let (v_hex, v_stl57) = addr_pair(&validator);
    let mut out = prepared(
        "stake_bond",
        crate::svm::GAS_STAKE_BOND,
        "SysCallStake",
        json!({ "validator": v_hex, "amount": amount }),
        Some(&validator),
    );
    out["validator"] = json!(v_hex);
    out["validator_stl57"] = json!(v_stl57);
    out["amount"] = json!(amount.to_string());
    out["min_bond"] = json!(floor.to_string());
    out["top_up"] = json!(is_topup);
    Ok(out)
}

async fn stake_unbond(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let validator = need_addr(p, "validator")?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let ledger = engine.staking_read().await;
    let stake = ledger
        .validators
        .get(&validator)
        .ok_or_else(|| not_found(format!("unknown validator: {}", hex::encode(validator))))?;
    if amount > stake.self_bond {
        return Err(refused(format!(
            "insufficient self-bond: have {}, unbond {}",
            stake.self_bond, amount
        )));
    }
    let remaining = stake.self_bond - amount;
    let floor = crate::staking::required_bond_floor_nano();
    if remaining != 0 && remaining < floor {
        return Err(refused(format!(
            "unbonding would leave the validator below the minimum bond (needs {floor} nano-STELL)"
        )));
    }
    drop(ledger);

    let (v_hex, v_stl57) = addr_pair(&validator);
    let mut out = prepared(
        "stake_unbond",
        crate::svm::GAS_STAKE_UNBOND,
        "SysCallUnbond",
        json!({ "validator": v_hex, "amount": amount }),
        Some(&validator),
    );
    out["validator"] = json!(v_hex);
    out["validator_stl57"] = json!(v_stl57);
    out["amount"] = json!(amount.to_string());
    out["cooldown_secs"] = json!(crate::staking::UNBONDING_PERIOD_SECS);
    Ok(out)
}

async fn stake_withdraw(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let validator = need_addr(p, "validator")?;
    let ledger = engine.staking_read().await;
    if !ledger.validators.contains_key(&validator) {
        return Err(not_found(format!(
            "unknown validator: {}",
            hex::encode(validator)
        )));
    }
    let withdrawable = ledger.withdrawable_of(&validator);
    if withdrawable == 0 {
        return Err(refused(
            "no matured self-bond is withdrawable (the unbonding cooldown has not elapsed)",
        ));
    }
    drop(ledger);

    let (v_hex, v_stl57) = addr_pair(&validator);
    let mut out = prepared(
        "stake_withdraw",
        crate::svm::GAS_STAKE_UNBOND,
        "SysCallWithdrawSelfBond",
        json!({ "validator": v_hex }),
        Some(&validator),
    );
    out["validator"] = json!(v_hex);
    out["validator_stl57"] = json!(v_stl57);
    out["withdrawable"] = json!(withdrawable.to_string());
    Ok(out)
}

async fn delegate(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let validator = need_addr(p, "validator")?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let ledger = engine.staking_read().await;
    let stake = ledger
        .validators
        .get(&validator)
        .ok_or_else(|| not_found(format!("unknown validator: {}", hex::encode(validator))))?;
    if stake.self_bond < crate::staking::MIN_VALIDATOR_BOND {
        return Err(refused("validator is not an active validator"));
    }
    drop(ledger);

    let delegator = opt_str(p, "delegator")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'delegator': {e}")))?;

    let (v_hex, v_stl57) = addr_pair(&validator);
    let mut out = prepared(
        "delegate",
        crate::svm::GAS_STAKE_BOND,
        "SysCallDelegate",
        json!({ "validator": v_hex, "amount": amount }),
        delegator.as_ref(),
    );
    out["validator"] = json!(v_hex);
    out["validator_stl57"] = json!(v_stl57);
    out["amount"] = json!(amount.to_string());
    out["min_delegation"] = json!(crate::staking::MIN_DELEGATION.to_string());
    Ok(out)
}

async fn undelegate(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let validator = need_addr(p, "validator")?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let delegator = opt_str(p, "delegator")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'delegator': {e}")))?;

    let ledger = engine.staking_read().await;
    if !ledger.validators.contains_key(&validator) {
        return Err(not_found(format!(
            "unknown validator: {}",
            hex::encode(validator)
        )));
    }
    if let Some(d) = delegator.as_ref() {
        let held = ledger
            .delegations
            .get(&(validator, *d))
            .copied()
            .unwrap_or(0);
        if held == 0 {
            return Err(refused(format!(
                "no delegation to validator {}",
                hex::encode(validator)
            )));
        }
        if amount > held {
            return Err(refused(format!(
                "insufficient delegated stake: have {held}, undelegate {amount}"
            )));
        }
    }
    drop(ledger);

    let (v_hex, v_stl57) = addr_pair(&validator);
    let mut out = prepared(
        "undelegate",
        crate::svm::GAS_STAKE_UNBOND,
        "SysCallBeginUndelegate",
        json!({ "validator": v_hex, "amount": amount }),
        delegator.as_ref(),
    );
    out["validator"] = json!(v_hex);
    out["validator_stl57"] = json!(v_stl57);
    out["amount"] = json!(amount.to_string());
    out["cooldown_secs"] = json!(crate::staking::UNBONDING_PERIOD_SECS);
    Ok(out)
}

async fn claim_rewards(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let validator = need_addr(p, "validator")?;
    let role = opt_str(p, "role").unwrap_or_else(|| "validator".to_string());
    let role = role.to_lowercase();
    if role != "validator" && role != "delegator" {
        return Err(invalid(
            "parameter 'role' must be either \"validator\" or \"delegator\"",
        ));
    }
    let delegator = opt_str(p, "delegator")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'delegator': {e}")))?;

    let ledger = engine.staking_read().await;
    if !ledger.validators.contains_key(&validator) {
        return Err(not_found(format!(
            "unknown validator: {}",
            hex::encode(validator)
        )));
    }
    let claimable = match role.as_str() {
        "validator" => ledger
            .validators
            .get(&validator)
            .map(|v| v.pending_rewards)
            .unwrap_or(0),
        _ => match delegator.as_ref() {
            Some(d) => ledger.delegator_rewards_of(*d, validator),
            None => 0,
        },
    };
    if role == "delegator" && delegator.is_none() {
        return Err(invalid(
            "the delegator arm of claim rewards needs a 'delegator' address",
        ));
    }
    drop(ledger);
    if claimable == 0 {
        return Err(refused("nothing to claim: no rewards accrued"));
    }

    let (v_hex, v_stl57) = addr_pair(&validator);
    let op = if role == "validator" {
        "SysCallClaimRewards"
    } else {
        "SysCallClaimDelegatorRewards"
    };
    let mut out = prepared(
        "claim_rewards",
        crate::svm::GAS_STAKE_CLAIM,
        op,
        json!({ "validator": v_hex }),
        delegator.as_ref(),
    );
    out["validator"] = json!(v_hex);
    out["validator_stl57"] = json!(v_stl57);
    out["role"] = json!(role);
    out["claimable"] = json!(claimable.to_string());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Bridge (over `crate::bridge`)
// ---------------------------------------------------------------------------

/// Parse a chain label into the committed `SupportedChain`.
fn parse_chain(s: &str) -> Result<crate::bridge::SupportedChain, NativeApiError> {
    use crate::bridge::SupportedChain;
    match s.trim().to_lowercase().as_str() {
        "ton" | "the_open_network" => Ok(SupportedChain::Ton),
        "arbitrum" | "arb" => Ok(SupportedChain::Arbitrum),
        "ethereum" | "eth" => Ok(SupportedChain::Ethereum),
        "solana" | "sol" => Ok(SupportedChain::Solana),
        other => Err(invalid(format!(
            "unknown chain '{other}' (expected ton | arbitrum | ethereum | solana)"
        ))),
    }
}

fn chain_name(c: crate::bridge::SupportedChain) -> String {
    use crate::bridge::SupportedChain;
    match c {
        SupportedChain::Ton => "ton".to_string(),
        SupportedChain::Arbitrum => "arbitrum".to_string(),
        SupportedChain::Ethereum => "ethereum".to_string(),
        SupportedChain::Solana => "solana".to_string(),
    }
}

async fn bridge_deposit(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let chain = parse_chain(&need_str(p, "chain")?)?;
    let source = need_addr(p, "source_tx_hash")?;
    let recipient = need_addr(p, "recipient")?;
    let amount = need_u64(p, "amount")?;

    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if recipient == crate::token::ZERO_ADDRESS {
        return Err(refused("a bridge deposit needs a recipient"));
    }
    let br = engine.bridge_read().await;
    if br.processed_source_txs.contains(&source) {
        return Err(refused(format!(
            "source transaction already credited: {}",
            hex::encode(source)
        )));
    }
    if let Some(rec) = br.deposit_records.get(&source) {
        // A record without the hash in the replay set is a partially applied
        // deposit; refuse rather than risk a second credit.
        return Err(refused(format!(
            "source transaction already has a deposit record (recipient {}, amount {})",
            hex::encode(rec.recipient),
            rec.amount
        )));
    }
    drop(br);

    let (src_hex, _) = addr_pair(&source);
    let (rec_hex, rec_stl57) = addr_pair(&recipient);
    let mut out = prepared(
        "bridge_deposit",
        crate::svm::GAS_BRIDGE_INTENT,
        "SysCallBridge",
        json!({
            "intent": "Deposit",
            "chain": chain_name(chain),
            "source_tx_hash": src_hex,
            "recipient": rec_hex,
            "amount": amount,
        }),
        Some(&recipient),
    );
    out["chain"] = json!(chain_name(chain));
    out["source_tx_hash"] = json!(src_hex);
    out["recipient"] = json!(rec_hex);
    out["recipient_stl57"] = json!(rec_stl57);
    out["amount"] = json!(amount.to_string());
    out["asset"] = json!(crate::bridge::LIVE_DEPOSIT_ASSET);
    Ok(out)
}

async fn bridge_withdraw(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let chain = parse_chain(&need_str(p, "chain")?)?;
    let target = need_str(p, "target_address")?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if target.trim().is_empty() {
        return Err(refused("a bridge withdrawal needs a target address"));
    }
    let sender = opt_str(p, "sender")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'sender': {e}")))?;

    let br = engine.bridge_read().await;
    // The escrow is reported so a wallet can show the coverage, but a thin
    // escrow is NOT a refusal: the deposit leg fills it, and the execution
    // path is the one that decides whether a withdrawal is fundable.
    let escrow_balance = br.escrow_balance;
    drop(br);

    let mut out = prepared(
        "bridge_withdraw",
        crate::svm::GAS_BRIDGE_INTENT,
        "SysCallBridge",
        json!({
            "intent": "Withdraw",
            "chain": chain_name(chain),
            "target_address": target,
            "amount": amount,
        }),
        sender.as_ref(),
    );
    out["chain"] = json!(chain_name(chain));
    out["target_address"] = json!(target);
    out["amount"] = json!(amount.to_string());
    out["asset"] = json!(crate::bridge::LIVE_DEPOSIT_ASSET);
    out["escrow_balance"] = json!(escrow_balance.to_string());
    Ok(out)
}

async fn bridge_status(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let br = engine.bridge_read().await;
    if let Some(src) = opt_str(p, "source_tx_hash") {
        let src = parse_address(&src).map_err(|e| invalid(format!("parameter 'source_tx_hash': {e}")))?;
        if let Some(rec) = br.deposit_records.get(&src) {
            let (src_hex, _) = addr_pair(&src);
            let (rec_hex, rec_stl57) = addr_pair(&rec.recipient);
            return Ok(json!({
                "found": true,
                "kind": "deposit",
                "source_tx_hash": src_hex,
                "recipient": rec_hex,
                "recipient_stl57": rec_stl57,
                "amount": rec.amount.to_string(),
                "chain": chain_name(rec.chain),
                "via_quorum": rec.via_quorum,
                "deposited_at": rec.deposited_at,
                "disputed": rec.disputed,
            }));
        }
        return Ok(json!({
            "found": false,
            "kind": "deposit",
            "source_tx_hash": hex::encode(src),
        }));
    }
    if let Some(req) = opt_u64(p, "request_id") {
        if let Some(w) = br.pending_withdrawals.get(&req) {
            let (sender_hex, _) = addr_pair(&w.sender);
            return Ok(json!({
                "found": true,
                "kind": "withdrawal",
                "request_id": w.req_id,
                "chain": chain_name(w.target_chain),
                "target_address": w.target_address,
                "amount": w.amount.to_string(),
                "sender": sender_hex,
                "requested_at": w.requested_at,
                "unlock_at": w.unlock_at,
                "executed": w.executed,
            }));
        }
        return Ok(json!({
            "found": false,
            "kind": "withdrawal",
            "request_id": req,
        }));
    }
    Err(invalid(
        "missing parameter: pass 'source_tx_hash' (a deposit) or 'request_id' (a withdrawal)",
    ))
}

// ---------------------------------------------------------------------------
// Order book (over `crate::orderbook`)
// ---------------------------------------------------------------------------

async fn order_book_place(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let pair = opt_u64(p, "pair").unwrap_or(crate::orderbook::PAIR_STELL_USDT as u64);
    let pair = u32::try_from(pair)
        .map_err(|_| invalid("parameter 'pair' is out of range for a pair id"))?;
    let side_raw = need_str(p, "side")?.to_lowercase();
    let is_buy = match side_raw.as_str() {
        "buy" | "bid" => true,
        "sell" | "ask" => false,
        _ => return Err(invalid("parameter 'side' must be \"buy\" or \"sell\"")),
    };
    let price = need_u64(p, "price")?;
    let amount = need_u64(p, "amount")?;
    if price == 0 {
        return Err(refused("price must be greater than zero"));
    }
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let books = engine.orderbooks_read().await;
    if books.get_book(pair).is_none() {
        return Err(not_found(format!("unknown pair {pair}")));
    }
    drop(books);

    let trader = opt_str(p, "trader")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'trader': {e}")))?;

    let mut out = prepared(
        "order_book_place",
        crate::svm::GAS_ORDER_PLACE,
        "SysCallPlaceOrder",
        json!({ "pair_id": pair, "is_buy": is_buy, "price": price, "amount": amount }),
        trader.as_ref(),
    );
    out["pair"] = json!(pair);
    out["side"] = json!(if is_buy { "buy" } else { "sell" });
    out["price"] = json!(price.to_string());
    out["amount"] = json!(amount.to_string());
    Ok(out)
}

async fn order_book_cancel(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let order_id = need_u64(p, "order_id")?;
    let pair = opt_u64(p, "pair").map(|v| v as u32);
    let books = engine.orderbooks_read().await;
    let mut found: Option<(u32, crate::orderbook::Order)> = None;
    for (pid, book) in books.books.iter() {
        if let Some(pid_filter) = pair {
            if *pid != pid_filter {
                continue;
            }
        }
        if let Some(o) = book.find_order(order_id) {
            found = Some((*pid, o.clone()));
            break;
        }
    }
    let (pid, order) = found.ok_or_else(|| {
        not_found(format!("unknown order id {order_id}"))
    })?;
    drop(books);

    let trader = opt_str(p, "trader")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'trader': {e}")))?;
    if let Some(t) = trader.as_ref() {
        if order.trader != *t {
            return Err(refused(
                "an order can only be cancelled by the trader that placed it",
            ));
        }
    }

    let (trader_hex, _) = addr_pair(&order.trader);
    let mut out = prepared(
        "order_book_cancel",
        crate::svm::GAS_ORDER_CANCEL,
        "SysCallCancelOrder",
        json!({ "order_id": order_id }),
        trader.as_ref(),
    );
    out["order_id"] = json!(order_id);
    out["pair"] = json!(pid);
    out["trader"] = json!(trader_hex);
    out["side"] = json!(match order.side {
        crate::orderbook::OrderSide::Buy => "buy",
        crate::orderbook::OrderSide::Sell => "sell",
    });
    out["price"] = json!(order.price.to_string());
    out["amount"] = json!(order.amount.to_string());
    out["filled"] = json!(order.filled.to_string());
    Ok(out)
}

async fn order_book_snapshot(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let pair = opt_u64(p, "pair").unwrap_or(crate::orderbook::PAIR_STELL_USDT as u64);
    let pair = u32::try_from(pair)
        .map_err(|_| invalid("parameter 'pair' is out of range for a pair id"))?;
    let books = engine.orderbooks_read().await;
    let book = books
        .get_book(pair)
        .ok_or_else(|| not_found(format!("unknown pair {pair}")))?;
    let (best_bid, best_ask) = book.get_best_bid_ask();
    let (bid_levels, ask_levels) = book.depth();

    let bids: Vec<Value> = book
        .bids
        .iter()
        .take(20)
        .map(|(price, orders)| {
            let available: u64 = orders.iter().map(|o| o.amount - o.filled).sum();
            json!({
                "price": price.0.to_string(),
                "orders": orders.len(),
                "available": available.to_string(),
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
                "price": price.to_string(),
                "orders": orders.len(),
                "available": available.to_string(),
            })
        })
        .collect();

    Ok(json!({
        "pair": pair,
        "best_bid": best_bid.map(|p| p.to_string()),
        "best_ask": best_ask.map(|p| p.to_string()),
        "bid_levels": bid_levels,
        "ask_levels": ask_levels,
        "bids": bids,
        "asks": asks,
        "next_order_id": book.next_order_id,
    }))
}

// ---------------------------------------------------------------------------
// Session keys (over `crate::zkml::SessionKeyRegistry`)
// ---------------------------------------------------------------------------

async fn session_key_register(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    let session = need_addr(p, "session_pubkey")?;
    let master = need_addr(p, "master")?;
    let valid_until = need_u64(p, "valid_until")?;
    let max_gas_spend = need_u64(p, "max_gas_spend")?;
    let scope = need_u64(p, "scope")?;
    let max_value_per_tx = opt_u64(p, "max_value_per_tx").unwrap_or(0);

    if session == crate::token::ZERO_ADDRESS {
        return Err(refused("the session key must not be the zero address"));
    }
    if master == crate::token::ZERO_ADDRESS {
        return Err(refused("the master must not be the zero address"));
    }
    if max_gas_spend == 0 {
        return Err(refused("max_gas_spend must be greater than zero"));
    }
    if scope == 0 {
        return Err(refused("scope must name at least one capability"));
    }
    if valid_until == 0 {
        return Err(refused("valid_until must be a non-zero unix timestamp"));
    }

    let reg = engine.session_keys_read().await;
    if let Some(rec) = reg.get(&session) {
        if rec.revoked {
            return Err(refused(
                "this session key was revoked: a revocation is terminal",
            ));
        }
        if rec.master != master {
            return Err(refused(format!(
                "this session key is already registered to another master ({})",
                hex::encode(rec.master)
            )));
        }
    }
    drop(reg);

    let chain_id = engine.chain_id;
    let message = crate::zkml::SessionKeyAuthorization::grant_message(
        &master,
        &session,
        valid_until,
        max_gas_spend,
        scope,
        max_value_per_tx,
        chain_id,
    );

    let (session_hex, session_stl57) = addr_pair(&session);
    let (master_hex, _) = addr_pair(&master);
    let mut out = prepared(
        "session_key_register",
        crate::svm::GAS_PUBLISH_SESSION_GRANT,
        "SysCallPublishSessionGrant",
        json!({
            "grant": {
                "master_address": master_hex,
                "session_pubkey": session_hex,
                "valid_until": valid_until,
                "max_gas_spend": max_gas_spend,
                "gas_spent": 0,
                "scope": scope,
                "max_value_per_tx": max_value_per_tx,
                "chain_id": chain_id,
                "master_signature": "",
                "master_scheme": "Ed25519",
                "session_scheme": "Ed25519",
            }
        }),
        Some(&master),
    );
    out["session_pubkey"] = json!(session_hex);
    out["session_pubkey_stl57"] = json!(session_stl57);
    out["master"] = json!(master_hex);
    out["valid_until"] = json!(valid_until);
    out["max_gas_spend"] = json!(max_gas_spend);
    out["scope"] = json!(scope);
    out["max_value_per_tx"] = json!(max_value_per_tx);
    out["chain_id"] = json!(chain_id);
    out["grant_message"] = json!(format!("0x{}", hex::encode(&message)));
    out["grant_message_hex"] = json!(hex::encode(&message));
    out["sign_hint"] = json!(
        "sign 'grant_message' with the master key and put the signature in \
         transaction.args.grant.master_signature before submitting"
    );
    Ok(out)
}

async fn session_key_revoke(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let session = need_addr(p, "session_pubkey")?;
    let reg = engine.session_keys_read().await;
    let rec = reg
        .get(&session)
        .ok_or_else(|| not_found(format!("unknown session key: {}", hex::encode(session))))?;
    if rec.revoked {
        return Err(refused("this session key is already revoked"));
    }
    let master = rec.master;
    let master_req = opt_str(p, "master")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'master': {e}")))?;
    if let Some(m) = master_req.as_ref() {
        if *m != master {
            return Err(refused(
                "only the master that owns a session key may revoke it",
            ));
        }
    }
    drop(reg);

    let (session_hex, _) = addr_pair(&session);
    let (master_hex, _) = addr_pair(&master);
    let mut out = prepared(
        "session_key_revoke",
        crate::svm::GAS_SESSION_REVOKE,
        "SysCallRevokeSession",
        json!({ "session_pubkey": session_hex }),
        Some(&master),
    );
    out["session_pubkey"] = json!(session_hex);
    out["master"] = json!(master_hex);
    Ok(out)
}

async fn session_keys(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let filter = opt_str(p, "master")
        .map(|s| parse_address(&s))
        .transpose()
        .map_err(|e| invalid(format!("parameter 'master': {e}")))?;
    let reg = engine.session_keys_read().await;
    let mut list: Vec<Value> = Vec::new();
    for (pk, rec) in reg.entries.iter() {
        if let Some(m) = filter.as_ref() {
            if rec.master != *m {
                continue;
            }
        }
        let (pk_hex, pk_stl57) = addr_pair(pk);
        let (master_hex, _) = addr_pair(&rec.master);
        list.push(json!({
            "session_pubkey": pk_hex,
            "session_pubkey_stl57": pk_stl57,
            "master": master_hex,
            "valid_until": rec.valid_until,
            "max_gas_spend": rec.max_gas_spend,
            "gas_spent": rec.gas_spent,
            "remaining_gas": rec.max_gas_spend.saturating_sub(rec.gas_spent),
            "scope": rec.scope,
            "max_value_per_tx": rec.max_value_per_tx,
            "revoked": rec.revoked,
        }));
    }
    let count = list.len();
    Ok(json!({
        "session_keys": list,
        "count": count,
    }))
}

// ---------------------------------------------------------------------------
// Oracle (over `crate::oracle`)
// ---------------------------------------------------------------------------

async fn oracle_price(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let asset = need_str(p, "asset")?;
    let oracle = engine.oracle_read().await;
    let feed = oracle.feeds.get(&asset).ok_or_else(|| {
        not_found(format!("no committed price feed for asset '{asset}'"))
    })?;
    let (pub_hex, _) = addr_pair(&feed.publisher);
    Ok(json!({
        "asset": asset,
        "price_micro_usd": feed.price_micro_usd.to_string(),
        "timestamp": feed.timestamp,
        "publisher": pub_hex,
        "breaker_tripped": oracle.breaker_tripped,
    }))
}

async fn oracle_feeds(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let filter = opt_str(p, "asset");
    let oracle = engine.oracle_read().await;
    let mut feeds: Vec<Value> = Vec::new();
    for (asset, feed) in oracle.feeds.iter() {
        if let Some(f) = filter.as_ref() {
            if f != asset {
                continue;
            }
        }
        let (pub_hex, _) = addr_pair(&feed.publisher);
        feeds.push(json!({
            "asset": asset,
            "price_micro_usd": feed.price_micro_usd.to_string(),
            "timestamp": feed.timestamp,
            "publisher": pub_hex,
        }));
    }
    let publishers: Vec<String> = oracle.publishers.iter().map(hex::encode).collect();
    let count = feeds.len();
    Ok(json!({
        "feeds": feeds,
        "count": count,
        "publishers": publishers,
        "breaker_tripped": oracle.breaker_tripped,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{TokenMetadata, TokenRegistry};

    fn addr(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn meta(name: &str, symbol: &str) -> TokenMetadata {
        TokenMetadata {
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: crate::token::ZERO_ADDRESS,
            paused: false,
            description: String::new(),
        }
    }

    async fn engine_with_token() -> (InMemoryStateEngine, [u8; 32]) {
        let engine = InMemoryStateEngine::new();
        let creator = addr(1);
        let id = {
            let mut reg = TokenRegistry::new();
            let id = reg
                .create_token(creator, meta("Tether USD", "wUSDT"), 1_000_000)
                .unwrap();
            *engine.tokens_write().await = reg;
            id
        };
        (engine, id)
    }

    #[tokio::test]
    async fn manifest_lists_every_domain() {
        let m = native_api_manifest();
        assert_eq!(m["version"], NATIVE_API_VERSION);
        let names: Vec<&str> = m["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap())
            .collect();
        for expected in [
            "stell_tokenTransfer",
            "stell_tokenBalanceOf",
            "stell_tokenMetadata",
            "stell_tokenAllowance",
            "stell_stakeBond",
            "stell_stakeUnbond",
            "stell_stakeWithdraw",
            "stell_delegate",
            "stell_undelegate",
            "stell_claimRewards",
            "stell_bridgeDepositPrepare",
            "stell_bridgeWithdraw",
            "stell_bridgeStatus",
            "stell_orderBookPlace",
            "stell_orderBookCancel",
            "stell_orderBookSnapshot",
            "stell_sessionKeyRegister",
            "stell_sessionKeyRevoke",
            "stell_sessionKeys",
            "stell_oraclePrice",
            "stell_oracleFeeds",
        ] {
            assert!(names.contains(&expected), "manifest is missing {expected}");
            assert!(is_native_method(expected));
        }
    }

    #[tokio::test]
    async fn unknown_method_is_refused() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_notAMethod", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32601);
    }

    #[tokio::test]
    async fn token_balance_of_has_the_documented_shape() {
        let (engine, id) = engine_with_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenBalanceOf",
            &json!({ "token": hex::encode(id), "account": hex::encode(addr(1)) }),
        )
        .await
        .unwrap();
        assert_eq!(v["balance"], "1000000");
        assert_eq!(v["decimals"], 6);
        assert_eq!(v["symbol"], "wUSDT");
        assert_eq!(v["token"], hex::encode(id));
        assert!(v["account_stl57"].is_string());
    }

    #[tokio::test]
    async fn token_balance_of_unknown_token_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_tokenBalanceOf",
            &json!({ "token": hex::encode(addr(9)), "account": hex::encode(addr(1)) }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn token_balance_of_missing_parameter_fails_closed() {
        let (engine, id) = engine_with_token().await;
        let err = dispatch(
            &engine,
            "stell_tokenBalanceOf",
            &json!({ "token": hex::encode(id) }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32602);
    }

    #[tokio::test]
    async fn token_metadata_reports_the_ledger_metadata() {
        let (engine, id) = engine_with_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenMetadata",
            &json!({ "token": hex::encode(id) }),
        )
        .await
        .unwrap();
        assert_eq!(v["name"], "Tether USD");
        assert_eq!(v["symbol"], "wUSDT");
        assert_eq!(v["total_supply"], "1000000");
        assert_eq!(v["paused"], false);
        assert!(v["max_supply"].is_null());
    }

    #[tokio::test]
    async fn token_allowance_is_zero_for_an_unset_pair() {
        let (engine, id) = engine_with_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenAllowance",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(addr(1)),
                "spender": hex::encode(addr(2)),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["allowance"], "0");
    }

    #[tokio::test]
    async fn token_transfer_prepares_a_transaction() {
        let (engine, id) = engine_with_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenTransfer",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "to": hex::encode(addr(2)),
                "amount": "400",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_transfer");
        assert_eq!(v["amount"], "400");
        assert_eq!(v["transaction"]["op"], "SysCallTokenTransfer");
        assert_eq!(v["transaction"]["args"]["amount"], 400);
        assert_eq!(v["transaction"]["args"]["to"], hex::encode(addr(2)));
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        assert_eq!(v["signer"]["address"], hex::encode(addr(1)));
    }

    #[tokio::test]
    async fn token_transfer_beyond_the_balance_fails_closed() {
        let (engine, id) = engine_with_token().await;
        let err = dispatch(
            &engine,
            "stell_tokenTransfer",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "to": hex::encode(addr(2)),
                "amount": "9999999999",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_transfer_to_zero_address_fails_closed() {
        let (engine, id) = engine_with_token().await;
        let err = dispatch(
            &engine,
            "stell_tokenTransfer",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "to": hex::encode([0u8; 32]),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn stake_bond_below_the_floor_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_stakeBond",
            &json!({ "validator": hex::encode(addr(7)), "amount": "1" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn stake_bond_prepares_a_transaction() {
        let engine = InMemoryStateEngine::new();
        let amount = crate::staking::required_bond_floor_nano();
        let v = dispatch(
            &engine,
            "stell_stakeBond",
            &json!({ "validator": hex::encode(addr(7)), "amount": amount.to_string() }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "stake_bond");
        assert_eq!(v["transaction"]["op"], "SysCallStake");
        assert_eq!(v["transaction"]["args"]["amount"], amount);
    }

    #[tokio::test]
    async fn stake_unbond_of_an_unknown_validator_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_stakeUnbond",
            &json!({ "validator": hex::encode(addr(7)), "amount": "1" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn delegate_to_an_unknown_validator_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_delegate",
            &json!({ "validator": hex::encode(addr(7)), "amount": "1" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn claim_rewards_without_a_validator_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_claimRewards",
            &json!({ "validator": hex::encode(addr(7)) }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn bridge_deposit_rejects_a_replayed_source_hash() {
        let engine = InMemoryStateEngine::new();
        let src = addr(5);
        {
            let mut br = engine.bridge_write().await;
            br.processed_source_txs.insert(src);
        }
        let err = dispatch(
            &engine,
            "stell_bridgeDepositPrepare",
            &json!({
                "chain": "ton",
                "source_tx_hash": hex::encode(src),
                "recipient": hex::encode(addr(2)),
                "amount": "10",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn bridge_deposit_with_an_unknown_chain_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_bridgeDepositPrepare",
            &json!({
                "chain": "dogecoin",
                "source_tx_hash": hex::encode(addr(5)),
                "recipient": hex::encode(addr(2)),
                "amount": "10",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32602);
    }

    #[tokio::test]
    async fn bridge_status_without_a_selector_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_bridgeStatus", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32602);
    }

    #[tokio::test]
    async fn bridge_status_reports_a_settled_deposit() {
        let engine = InMemoryStateEngine::new();
        let src = addr(5);
        {
            let mut br = engine.bridge_write().await;
            br.deposit_records.insert(
                src,
                crate::bridge::DepositRecord {
                    recipient: addr(2),
                    amount: 42,
                    chain: crate::bridge::SupportedChain::Ton,
                    via_quorum: true,
                    deposited_at: 7,
                    disputed: false,
                },
            );
        }
        let v = dispatch(
            &engine,
            "stell_bridgeStatus",
            &json!({ "source_tx_hash": hex::encode(src) }),
        )
        .await
        .unwrap();
        assert_eq!(v["found"], true);
        assert_eq!(v["kind"], "deposit");
        assert_eq!(v["amount"], "42");
        assert_eq!(v["chain"], "ton");
    }

    #[tokio::test]
    async fn order_book_snapshot_has_the_documented_shape() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(&engine, "stell_orderBookSnapshot", &json!({ "pair": 1 }))
            .await
            .unwrap();
        assert_eq!(v["pair"], 1);
        assert!(v["best_bid"].is_null());
        assert!(v["best_ask"].is_null());
        assert_eq!(v["bid_levels"], 0);
        assert!(v["bids"].is_array());
        assert!(v["asks"].is_array());
    }

    #[tokio::test]
    async fn order_book_snapshot_of_an_unknown_pair_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_orderBookSnapshot", &json!({ "pair": 4242 }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn order_book_cancel_of_an_unknown_order_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_orderBookCancel", &json!({ "order_id": 7 }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn order_book_place_prepares_a_transaction() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(
            &engine,
            "stell_orderBookPlace",
            &json!({ "pair": 1, "side": "buy", "price": "250000", "amount": "10" }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallPlaceOrder");
        assert_eq!(v["transaction"]["args"]["is_buy"], true);
        assert_eq!(v["side"], "buy");
    }

    #[tokio::test]
    async fn order_book_place_with_a_bad_side_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_orderBookPlace",
            &json!({ "pair": 1, "side": "sideways", "price": "1", "amount": "1" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32602);
    }

    #[tokio::test]
    async fn session_key_register_prepares_a_grant_to_sign() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(
            &engine,
            "stell_sessionKeyRegister",
            &json!({
                "session_pubkey": hex::encode(addr(2)),
                "master": hex::encode(addr(1)),
                "valid_until": 1_900_000_000u64,
                "max_gas_spend": 1_000_000u64,
                "scope": 3u64,
                "max_value_per_tx": 5u64,
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallPublishSessionGrant");
        assert!(v["grant_message"].as_str().unwrap().starts_with("0x"));
        assert_eq!(v["chain_id"], engine.chain_id);
    }

    #[tokio::test]
    async fn session_key_register_without_a_scope_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_sessionKeyRegister",
            &json!({
                "session_pubkey": hex::encode(addr(2)),
                "master": hex::encode(addr(1)),
                "valid_until": 1_900_000_000u64,
                "max_gas_spend": 1_000_000u64,
                "scope": 0u64,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn session_key_revoke_of_an_unknown_key_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_sessionKeyRevoke",
            &json!({ "session_pubkey": hex::encode(addr(2)) }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn session_keys_lists_the_registry() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(&engine, "stell_sessionKeys", &json!({})).await.unwrap();
        assert_eq!(v["count"], 0);
        assert!(v["session_keys"].is_array());
    }

    #[tokio::test]
    async fn oracle_price_of_an_unknown_asset_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_oraclePrice", &json!({ "asset": "STELL" }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn oracle_feeds_reports_the_committed_feeds() {
        let engine = InMemoryStateEngine::new();
        {
            let mut o = engine.oracle_write().await;
            o.feeds.insert(
                "STELL".to_string(),
                crate::oracle::CommittedFeed {
                    price_micro_usd: 250_000,
                    timestamp: 7,
                    publisher: addr(3),
                },
            );
        }
        let v = dispatch(&engine, "stell_oracleFeeds", &json!({})).await.unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["feeds"][0]["price_micro_usd"], "250000");
        let p = dispatch(&engine, "stell_oraclePrice", &json!({ "asset": "STELL" }))
            .await
            .unwrap();
        assert_eq!(p["price_micro_usd"], "250000");
        assert_eq!(p["timestamp"], 7);
    }

    #[tokio::test]
    async fn every_method_is_dispatchable_or_fails_closed() {
        let engine = InMemoryStateEngine::new();
        for m in METHODS {
            // With empty parameters every method must either answer or
            // refuse — never panic and never invent an answer.
            let r = dispatch(&engine, m.name, &json!({})).await;
            match r {
                Ok(v) => assert!(v.is_object(), "{} must answer with an object", m.name),
                Err(e) => assert!(
                    e.code() == -32602 || e.code() == -32004 || e.code() == -32003,
                    "{} refused with an unexpected code {}",
                    m.name,
                    e.code()
                ),
            }
        }
    }

    /// A missing parameter is an INVALID-PARAM error, never a default.
    ///
    /// The methods that need no parameter at all are the only ones that
    /// answer an empty call.
    #[tokio::test]
    async fn a_missing_parameter_fails_closed() {
        let engine = InMemoryStateEngine::new();
        for m in METHODS {
            let r = dispatch(&engine, m.name, &json!({})).await;
            if m.required == 0 {
                assert!(
                    r.is_ok(),
                    "{} takes no required parameter and must answer: {:?}",
                    m.name,
                    r.err()
                );
            } else {
                let e = r.expect_err(&format!("{} must refuse an empty call", m.name));
                assert_eq!(
                    e.code(),
                    -32602,
                    "{} must refuse with invalid params",
                    m.name
                );
            }
        }
    }
}
