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

use curve25519_dalek::scalar::Scalar;

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
    MethodSpec {
        name: "stell_tokenMint",
        kind: MethodKind::Prepare,
        summary: "Prepare an STS-20 mint (the token minter only).",
        params: &["token", "to", "amount", "from"],
        required: 3,
    },
    MethodSpec {
        name: "stell_tokenBurn",
        kind: MethodKind::Prepare,
        summary: "Prepare an STS-20 burn of the holder's own balance (or a minter admin-burn via `signer`).",
        params: &["token", "from", "amount", "signer"],
        required: 3,
    },
    MethodSpec {
        name: "stell_tokenApprove",
        kind: MethodKind::Prepare,
        summary: "Prepare an STS-20 approval (grant an allowance to a spender).",
        params: &["token", "owner", "spender", "amount"],
        required: 4,
    },
    MethodSpec {
        name: "stell_tokenTransferFrom",
        kind: MethodKind::Prepare,
        summary: "Prepare an STS-20 delegated transfer against an existing allowance.",
        params: &["token", "from", "to", "amount", "spender"],
        required: 5,
    },
    MethodSpec {
        name: "stell_tokenCreate",
        kind: MethodKind::Prepare,
        summary: "Prepare an STS-20 token creation (the caller becomes the minter).",
        params: &["creator", "name", "symbol", "decimals", "initial_supply", "max_supply"],
        required: 4,
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
    // --- bridge observability (reads over committed bridge state) ---
    // Attestation / release / history views are READS: they surface the
    // quorum, timelock and dispute rules — they never bypass them. The
    // engine stores no per-deposit PARTIAL attestation count (attestations
    // ride in-payload with the deposit they authorize and are counted at
    // settlement), so a settled deposit reports the quorum it was admitted
    // under; anything pre-commit is `found: false`, never an invented count.
    MethodSpec {
        name: "stell_bridgeAttestStatus",
        kind: MethodKind::Read,
        summary: "Committed attestation state of a deposit claim (`source_tx_hash`).",
        params: &["source_tx_hash"],
        required: 1,
    },
    MethodSpec {
        name: "stell_bridgeReleaseEstimate",
        kind: MethodKind::Read,
        summary: "Release readiness of a parked withdrawal (`request_id`): unlock time, quorum/escrow state, unmet conditions.",
        params: &["request_id"],
        required: 1,
    },
    MethodSpec {
        name: "stell_bridgeDeposits",
        kind: MethodKind::Read,
        summary: "Paginated deposit history of an address with per-deposit status and dispute countdown.",
        params: &["address", "limit"],
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
    // --- one-call order placement (market-maker surface) ---
    // Same prepare envelope as `stell_orderBookPlace`/`stell_orderBookCancel`,
    // but with the pair up front, an explicit `order_type` slot and the
    // escrow/ownership checks a quoter needs before it signs: one round trip
    // from quote to signable transaction.
    MethodSpec {
        name: "stell_placeOrder",
        kind: MethodKind::Prepare,
        summary: "Prepare a one-call limit order on a CLOB pair (validates pair, price, amount and the escrow lock).",
        params: &["pair", "side", "price", "amount", "order_type", "trader"],
        required: 4,
    },
    MethodSpec {
        name: "stell_cancelOrder",
        kind: MethodKind::Prepare,
        summary: "Prepare the cancellation of a resting order (only the placing trader).",
        params: &["order_id", "pair", "trader"],
        required: 1,
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
    // --- shielded path (privacy-by-default PATH, not a consensus flip) ---
    // Transparent stays the base layer: these are the first-class entry/exit
    // arms over the EXISTING confidential opcodes (shield entry +
    // SysCallConfidentialTransfer2 + unshield exit). Same envelope rule as
    // every other write method: prepare-only, the wallet signs, the state
    // moves only when the transaction lands in a block.
    MethodSpec {
        name: "stell_shieldedTransfer",
        kind: MethodKind::Prepare,
        summary: "Prepare a shielded transfer (native -> shielded coin to `to`, stealth or plain).",
        params: &["to", "amount", "fee", "sender"],
        required: 2,
    },
    MethodSpec {
        name: "stell_shieldedBalance",
        kind: MethodKind::Read,
        summary: "Scan viewing payloads with a viewing key and sum the spendable shielded balance.",
        params: &["viewing_key", "payloads"],
        required: 1,
    },
    MethodSpec {
        name: "stell_unshield",
        kind: MethodKind::Prepare,
        summary: "Prepare a shielded exit back to transparent (pays the signer).",
        params: &["to", "amount", "inputs", "sender"],
        required: 3,
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
    Err(invalid(format!(
        "parameter '{key}' must be an unsigned integer"
    )))
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
            .and_then(|b| {
                <[u8; 32]>::try_from(b.as_slice()).map_err(|_| "expected 32 bytes".to_string())
            }),
        40 => hex::decode(hex_clean)
            .map_err(|e| format!("bad hex: {e}"))
            .and_then(|b| {
                <[u8; 20]>::try_from(b.as_slice()).map_err(|_| "expected 20 bytes".to_string())
            })
            .map(|a| crate::evm_adapter::evm_to_stell_address(&a)),
        _ => Err("expected a 64-hex address or a Stl57 address".to_string()),
    }
}

/// Hex address + its Stl57 form, the pair every answer in this namespace uses.
fn addr_pair(a: &[u8; 32]) -> (String, String) {
    (hex::encode(a), crate::address::encode_stl57_address(a))
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
        "stell_tokenMint" => token_mint(engine, &p).await,
        "stell_tokenBurn" => token_burn(engine, &p).await,
        "stell_tokenApprove" => token_approve(engine, &p).await,
        "stell_tokenTransferFrom" => token_transfer_from(engine, &p).await,
        "stell_tokenCreate" => token_create(engine, &p).await,
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
        "stell_bridgeAttestStatus" => bridge_attest_status(engine, &p).await,
        "stell_bridgeReleaseEstimate" => bridge_release_estimate(engine, &p).await,
        "stell_bridgeDeposits" => bridge_deposits(engine, &p).await,
        // ---- order book ----
        "stell_orderBookPlace" => order_book_place(engine, &p).await,
        "stell_orderBookCancel" => order_book_cancel(engine, &p).await,
        "stell_orderBookSnapshot" => order_book_snapshot(engine, &p).await,
        // ---- one-call order placement (same envelope, stricter checks) ----
        "stell_placeOrder" => place_order(engine, &p).await,
        "stell_cancelOrder" => cancel_order(engine, &p).await,
        // ---- session keys ----
        "stell_sessionKeyRegister" => session_key_register(engine, &p).await,
        "stell_sessionKeyRevoke" => session_key_revoke(engine, &p).await,
        "stell_sessionKeys" => session_keys(engine, &p).await,
        // ---- oracle ----
        "stell_oraclePrice" => oracle_price(engine, &p).await,
        "stell_oracleFeeds" => oracle_feeds(engine, &p).await,
        // ---- shielded path (first-class, prepare-only where money moves) ----
        "stell_shieldedTransfer" => shielded_transfer(engine, &p).await,
        "stell_shieldedBalance" => shielded_balance(engine, &p).await,
        "stell_unshield" => unshield(engine, &p).await,
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
        return Err(not_found(format!("token not found: {}", hex::encode(id))));
    }
    Ok(id)
}

async fn token_balance_of(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
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

/// Read the minter-side signer of a mint: `from`, with `minter` accepted as
/// an alias (mirroring `token_transfer`'s `from`/`owner` alias pair).
/// `None` when the caller did not name one — the ledger minter is then the
/// signer by construction.
fn opt_minter(p: &Value) -> Result<Option<[u8; 32]>, NativeApiError> {
    match p.get("from").or_else(|| p.get("minter")) {
        Some(_) => Ok(Some(
            need_addr(p, "from").or_else(|_| need_addr(p, "minter"))?,
        )),
        None => Ok(None),
    }
}

async fn token_mint(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    let to = need_addr(p, "to")?;
    let amount = need_u64(p, "amount")?;
    let caller = opt_minter(p)?;

    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if to == crate::token::ZERO_ADDRESS {
        return Err(refused("the zero address cannot receive tokens"));
    }

    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    if actor.metadata.paused {
        return Err(refused("token is paused"));
    }
    if actor.metadata.minter == crate::token::ZERO_ADDRESS {
        return Err(refused(
            "minter authority has been renounced: no more minting is possible",
        ));
    }
    // Authority pin: when the caller names itself, it must BE the minter.
    // When it names no one, the signer below is the ledger minter anyway, so
    // only that key can ever use the answer. Either way a non-minter gets
    // nothing signable here, and execution (`TokenOp::Mint`) reverts a forged
    // caller regardless.
    if let Some(c) = caller.as_ref() {
        if *c != actor.metadata.minter {
            return Err(refused("caller is not the token minter"));
        }
    }
    let new_total = actor
        .metadata
        .total_supply
        .checked_add(amount)
        .ok_or_else(|| refused("mint would overflow the total supply"))?;
    if let Some(cap) = actor.metadata.max_supply {
        if new_total > cap {
            return Err(refused(format!(
                "mint would exceed maximum supply cap ({} + {} > {})",
                actor.metadata.total_supply, amount, cap
            )));
        }
    }
    let minter = actor.metadata.minter;
    let decimals = actor.metadata.decimals;
    let symbol = actor.metadata.symbol.clone();
    let total_supply = actor.metadata.total_supply;
    let max_supply = actor.metadata.max_supply;
    drop(reg);

    let (tok_hex, tok_stl57) = addr_pair(&token);
    let (minter_hex, minter_stl57) = addr_pair(&minter);
    let (to_hex, to_stl57) = addr_pair(&to);
    let mut out = prepared(
        "token_mint",
        crate::token::GAS_TOKEN_MINT,
        "SysCallTokenMint",
        json!({
            "token_id": tok_hex,
            "to": to_hex,
            "amount": amount,
        }),
        Some(&minter),
    );
    out["token"] = json!(tok_hex);
    out["token_stl57"] = json!(tok_stl57);
    out["minter"] = json!(minter_hex);
    out["minter_stl57"] = json!(minter_stl57);
    out["to"] = json!(to_hex);
    out["to_stl57"] = json!(to_stl57);
    out["amount"] = json!(amount.to_string());
    out["total_supply"] = json!(total_supply.to_string());
    out["max_supply"] = match max_supply {
        Some(cap) => json!(cap.to_string()),
        None => Value::Null,
    };
    out["decimals"] = json!(decimals);
    out["symbol"] = json!(symbol);
    Ok(out)
}

async fn token_burn(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    // `from` is the source account whose balance burns. By default it is also
    // the signer (self-burn, mirroring `token_transfer`). A minter admin-burn
    // (burning another account's tokens, which the ledger allows) names the
    // minter key explicitly via `signer` (aliases `caller`/`minter`, mirroring
    // `token_mint`'s `from`/`minter` alias pair); execution (`TokenOp::Burn`)
    // enforces the authority either way.
    let from = need_addr(p, "from")?;
    let amount = need_u64(p, "amount")?;
    let signer = match p
        .get("signer")
        .or_else(|| p.get("caller"))
        .or_else(|| p.get("minter"))
    {
        Some(_) => need_addr(p, "signer")
            .or_else(|_| need_addr(p, "caller"))
            .or_else(|_| need_addr(p, "minter"))?,
        None => from,
    };

    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if from == crate::token::ZERO_ADDRESS {
        return Err(refused("operation on the zero address is forbidden"));
    }
    if signer == crate::token::ZERO_ADDRESS {
        return Err(refused("operation on the zero address is forbidden"));
    }

    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    if actor.metadata.paused {
        return Err(refused("token is paused"));
    }
    // Authority pin (mirrors the ledger's `burn`: caller == from OR caller is
    // the minter). A third key gets nothing signable here, and execution
    // (`TokenOp::Burn`) reverts a forged caller regardless.
    if signer != from && signer != actor.metadata.minter {
        return Err(refused("caller is not the token holder or minter"));
    }
    let balance = actor.balance_of(&from);
    if balance < amount {
        return Err(refused(format!(
            "insufficient token balance: have {balance}, need {amount}"
        )));
    }
    let minter = actor.metadata.minter;
    let total_supply = actor.metadata.total_supply;
    drop(reg);

    let (tok_hex, tok_stl57) = addr_pair(&token);
    let (from_hex, from_stl57) = addr_pair(&from);
    let (minter_hex, _) = addr_pair(&minter);
    let mut out = prepared(
        "token_burn",
        crate::token::GAS_TOKEN_BURN,
        "SysCallTokenBurn",
        json!({
            "token_id": tok_hex,
            "from": from_hex,
            "amount": amount,
        }),
        Some(&signer),
    );
    out["token"] = json!(tok_hex);
    out["token_stl57"] = json!(tok_stl57);
    out["from"] = json!(from_hex);
    out["from_stl57"] = json!(from_stl57);
    out["amount"] = json!(amount.to_string());
    out["balance_before"] = json!(balance.to_string());
    out["total_supply"] = json!(total_supply.to_string());
    out["minter"] = json!(minter_hex);
    Ok(out)
}

async fn token_approve(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    // The owner grants; `from` is accepted as an alias (mirroring
    // `token_transfer`'s `from`/`owner` pair, with the primary name flipped
    // to the NEP-141 vocabulary this method speaks).
    let owner = match p.get("owner").or_else(|| p.get("from")) {
        Some(_) => need_addr(p, "owner").or_else(|_| need_addr(p, "from"))?,
        None => return Err(invalid("missing parameter 'owner'")),
    };
    let spender = need_addr(p, "spender")?;
    let amount = need_u64(p, "amount")?;

    if owner == crate::token::ZERO_ADDRESS || spender == crate::token::ZERO_ADDRESS {
        return Err(refused("operation on the zero address is forbidden"));
    }
    if owner == spender {
        return Err(refused("cannot approve self"));
    }
    // Deliberately NO paused check: approvals are allowance bookkeeping, not
    // value movement (same as ERC-20 Pausable) — the ledger's `approve`
    // refuses neither paused tokens nor zero amounts (zero revokes), and this
    // arm mirrors it exactly instead of inventing a refusal execution would
    // not make.

    let reg = engine.tokens_read().await;
    let actor = reg
        .get(&token)
        .ok_or_else(|| not_found(format!("token not found: {}", hex::encode(token))))?;
    let previous = actor.allowance(&owner, &spender);
    drop(reg);

    let (tok_hex, tok_stl57) = addr_pair(&token);
    let (owner_hex, owner_stl57) = addr_pair(&owner);
    let (spender_hex, spender_stl57) = addr_pair(&spender);
    let mut out = prepared(
        "token_approve",
        crate::token::GAS_TOKEN_APPROVE,
        "SysCallTokenApprove",
        json!({
            "token_id": tok_hex,
            "spender": spender_hex,
            "amount": amount,
        }),
        Some(&owner),
    );
    out["token"] = json!(tok_hex);
    out["token_stl57"] = json!(tok_stl57);
    out["owner"] = json!(owner_hex);
    out["owner_stl57"] = json!(owner_stl57);
    out["spender"] = json!(spender_hex);
    out["spender_stl57"] = json!(spender_stl57);
    out["amount"] = json!(amount.to_string());
    out["previous_allowance"] = json!(previous.to_string());
    Ok(out)
}

async fn token_transfer_from(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    let token = require_token(engine, p).await?;
    let from = need_addr(p, "from")?;
    let to = need_addr(p, "to")?;
    let amount = need_u64(p, "amount")?;
    let spender = need_addr(p, "spender")?;

    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if to == crate::token::ZERO_ADDRESS || from == crate::token::ZERO_ADDRESS {
        return Err(refused("operation on the zero address is forbidden"));
    }
    if spender == crate::token::ZERO_ADDRESS {
        return Err(refused("operation on the zero address is forbidden"));
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
    let allowance = actor.allowance(&from, &spender);
    if allowance < amount {
        return Err(refused(format!(
            "insufficient allowance: have {allowance}, need {amount}"
        )));
    }
    let balance = actor.balance_of(&from);
    if balance < amount {
        return Err(refused(format!(
            "insufficient token balance: have {balance}, need {amount}"
        )));
    }
    drop(reg);

    let (tok_hex, tok_stl57) = addr_pair(&token);
    let (from_hex, from_stl57) = addr_pair(&from);
    let (to_hex, to_stl57) = addr_pair(&to);
    let (spender_hex, spender_stl57) = addr_pair(&spender);
    let mut out = prepared(
        "token_transfer_from",
        crate::token::GAS_TOKEN_TRANSFER,
        "SysCallTokenTransferFrom",
        json!({
            "token_id": tok_hex,
            "from": from_hex,
            "to": to_hex,
            "amount": amount,
        }),
        Some(&spender),
    );
    out["token"] = json!(tok_hex);
    out["token_stl57"] = json!(tok_stl57);
    out["from"] = json!(from_hex);
    out["from_stl57"] = json!(from_stl57);
    out["to"] = json!(to_hex);
    out["to_stl57"] = json!(to_stl57);
    out["spender"] = json!(spender_hex);
    out["spender_stl57"] = json!(spender_stl57);
    out["amount"] = json!(amount.to_string());
    out["allowance_before"] = json!(allowance.to_string());
    out["sender_balance"] = json!(balance.to_string());
    Ok(out)
}

async fn token_create(_engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    // The creator is the future minter and the signer (mirroring
    // `token_transfer`'s `from`/`owner` alias pair, with the primary name
    // flipped to the ledger's `create_token(creator, …)` vocabulary).
    let creator = match p.get("creator").or_else(|| p.get("from")) {
        Some(_) => need_addr(p, "creator").or_else(|_| need_addr(p, "from"))?,
        None => return Err(invalid("missing parameter 'creator'")),
    };
    let name = need_str(p, "name")?;
    let symbol = need_str(p, "symbol")?;
    let decimals = need_u64(p, "decimals")?;
    let initial_supply = opt_u64(p, "initial_supply").unwrap_or(0);
    let max_supply = opt_u64(p, "max_supply");

    // Mirror `TokenMetadata::validate` exactly: execution reverts anything
    // outside these bounds, so the prepare refuses it first.
    if name.len() > 64 {
        return Err(invalid("parameter 'name' must be at most 64 bytes"));
    }
    if symbol.len() > 16 {
        return Err(invalid("parameter 'symbol' must be at most 16 bytes"));
    }
    if decimals > 18 {
        return Err(invalid("parameter 'decimals' must be at most 18"));
    }
    if let Some(cap) = max_supply {
        if initial_supply > cap {
            return Err(refused(format!(
                "initial supply exceeds maximum supply cap ({initial_supply} > {cap})"
            )));
        }
    }

    let (creator_hex, creator_stl57) = addr_pair(&creator);
    let mut out = prepared(
        "token_create",
        crate::token::GAS_TOKEN_CREATE,
        "SysCallTokenCreate",
        json!({
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "initial_supply": initial_supply,
            "max_supply": max_supply,
        }),
        Some(&creator),
    );
    out["creator"] = json!(creator_hex);
    out["creator_stl57"] = json!(creator_stl57);
    out["name"] = json!(name);
    out["symbol"] = json!(symbol);
    out["decimals"] = json!(decimals);
    out["initial_supply"] = json!(initial_supply.to_string());
    out["max_supply"] = match max_supply {
        Some(cap) => json!(cap.to_string()),
        None => Value::Null,
    };
    out["note"] = json!(
        "the token id commits the registry nonce and is not predictable: resolve it with stell_tokenResolve (creator, name, symbol) after inclusion"
    );
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
        let src =
            parse_address(&src).map_err(|e| invalid(format!("parameter 'source_tx_hash': {e}")))?;
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
// Bridge observability (reads over committed bridge state — W7 truth gate
// intact: these methods surface quorum / timelock / dispute rules, they never
// weaken them and they mutate nothing).
// ---------------------------------------------------------------------------

/// Committed validator/relayer ids the bridge quorum counts DISTINCT signers
/// from (the same set `settle_bridge_native` counts against).
async fn bridge_validator_set(engine: &InMemoryStateEngine) -> Vec<[u8; 32]> {
    engine
        .staking_read()
        .await
        .validators
        .keys()
        .copied()
        .collect()
}

/// Wall-clock second for DISPLAY countdowns only. The authoritative clock is
/// the block timestamp (`block.timestamp`, PROTOCOL.md I12): a countdown here
/// is an estimate, while every absolute deadline returned alongside it
/// (`deadline`, `unlock_at`, `refund_at`, `challengeable_until`) is the exact
/// value settlement compares against the block clock.
fn display_now_secs() -> u64 {
    crate::zkml::now_secs()
}

/// Open (unresolved) dispute for `hash`, if any.
fn open_dispute_for(
    br: &crate::bridge::BridgeState,
    hash: &[u8; 32],
) -> Option<(u64, crate::bridge::Dispute)> {
    br.disputes
        .iter()
        .find(|(_, d)| !d.resolved && d.source_tx_hash == *hash)
        .map(|(id, d)| (*id, d.clone()))
}

/// Most recent resolved dispute for `hash`, if any.
fn resolved_dispute_for(
    br: &crate::bridge::BridgeState,
    hash: &[u8; 32],
) -> Option<(u64, crate::bridge::Dispute)> {
    br.disputes
        .iter()
        .filter(|(_, d)| d.resolved && d.source_tx_hash == *hash)
        .max_by_key(|(id, _)| **id)
        .map(|(id, d)| (*id, d.clone()))
}

/// Lifecycle status of a settled deposit, derived from the committed record
/// plus the committed dispute map. `released` / `refunded` are withdrawal
/// states (see `stell_bridgeStatus` / `stell_bridgeReleaseEstimate`); a
/// deposit is `confirmed` unless an open dispute freezes it (`challenged`)
/// or a verified fraud proof burned it (`revoked`).
fn deposit_lifecycle_status(
    rec: &crate::bridge::DepositRecord,
    open: &Option<(u64, crate::bridge::Dispute)>,
    resolved: &Option<(u64, crate::bridge::Dispute)>,
) -> &'static str {
    if open.is_some() {
        return "challenged";
    }
    if rec.disputed {
        if let Some((_, d)) = resolved {
            if !d.confirmed {
                return "revoked";
            }
        }
    }
    "confirmed"
}

async fn bridge_attest_status(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    let src = match opt_str(p, "source_tx_hash") {
        Some(s) => {
            parse_address(&s).map_err(|e| invalid(format!("parameter 'source_tx_hash': {e}")))?
        }
        None => return Err(invalid("missing parameter 'source_tx_hash'")),
    };
    let validators = bridge_validator_set(engine).await;
    let required = crate::bridge::quorum_threshold(validators.len());
    let br = engine.bridge_read().await;
    let now = display_now_secs();
    let (src_hex, _) = addr_pair(&src);
    let quorum_met_committee = !validators.is_empty();
    match br.deposit_records.get(&src) {
        None => Ok(json!({
            "found": false,
            "source_tx_hash": src_hex,
            // Pre-commit attestations ride in-payload with the deposit claim
            // and are NOT committed state: nothing settled exists to count.
            // `required` is still reported so the wallet knows the threshold
            // the claim must reach; `remaining` equals it in full.
            "attestations": 0,
            "required": required,
            "remaining": required,
            "validator_count": validators.len(),
            "quorum_met": false,
            "disputed": false,
        })),
        Some(rec) => {
            let (rec_hex, rec_stl57) = addr_pair(&rec.recipient);
            let open = open_dispute_for(&br, &src);
            let resolved = resolved_dispute_for(&br, &src);
            let status = deposit_lifecycle_status(rec, &open, &resolved);
            // The engine stores no partial attestation count per deposit:
            // a settled quorum-path deposit was admitted BECAUSE the
            // threshold was met; an evidence-path deposit was admitted by
            // math (no attestations involved). Report exactly that.
            let (attestations, remaining) = if rec.via_quorum {
                (required, 0)
            } else {
                (0, 0)
            };
            let dispute = match open {
                Some((dispute_id, d)) => {
                    let (challenger_hex, _) = addr_pair(&d.challenger);
                    json!({
                        "dispute_id": dispute_id,
                        "challenger": challenger_hex,
                        "deadline": d.deadline,
                        "remaining_secs": d.deadline.saturating_sub(now),
                        "bond": d.bond.to_string(),
                        "resolved": false,
                    })
                }
                None => Value::Null,
            };
            Ok(json!({
                "found": true,
                "source_tx_hash": src_hex,
                "recipient": rec_hex,
                "recipient_stl57": rec_stl57,
                "amount": rec.amount.to_string(),
                "chain": chain_name(rec.chain),
                "path": if rec.via_quorum { "quorum" } else { "evidence" },
                "via_quorum": rec.via_quorum,
                "attestations": attestations,
                "required": required,
                "remaining": remaining,
                "validator_count": validators.len(),
                "quorum_met": quorum_met_committee,
                "deposited_at": rec.deposited_at,
                "disputed": rec.disputed,
                "status": status,
                "dispute": dispute,
            }))
        }
    }
}

async fn bridge_release_estimate(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    let req = match p.get("request_id") {
        Some(v) => {
            if let Some(n) = v.as_u64() {
                n
            } else if let Some(s) = v.as_str() {
                s.trim()
                    .parse::<u64>()
                    .map_err(|_| invalid("parameter 'request_id' must be an unsigned integer"))?
            } else {
                return Err(invalid(
                    "parameter 'request_id' must be an unsigned integer",
                ));
            }
        }
        None => return Err(invalid("missing parameter 'request_id'")),
    };
    let validators = bridge_validator_set(engine).await;
    let required = crate::bridge::quorum_threshold(validators.len());
    let br = engine.bridge_read().await;
    let now = display_now_secs();
    match br.pending_withdrawals.get(&req) {
        None => Ok(json!({
            "found": false,
            "request_id": req,
        })),
        Some(w) => {
            let (sender_hex, _) = addr_pair(&w.sender);
            let escrow_funded = br.escrow_balance >= w.amount;
            let timelock_matured_estimate = now >= w.unlock_at;
            let quorum_met = !validators.is_empty();
            let refund_at = w.unlock_at.saturating_add(crate::bridge::REFUND_GRACE_SECS);
            let refundable_estimate = !w.executed && now >= refund_at;
            // Unmet conditions for a successful `Release`, in settlement
            // order. `timelock` / `already-executed` are what settlement
            // refuses on; `escrow-shortfall` flags the refund leg (refunds
            // fail closed when the escrow cannot cover them); `no-validator-set`
            // is context (an empty set fails deposits closed, never releases).
            let mut missing: Vec<String> = Vec::new();
            if w.executed {
                missing.push("already-executed".to_string());
            } else if !timelock_matured_estimate {
                missing.push("timelock".to_string());
            }
            if !escrow_funded {
                missing.push("escrow-shortfall".to_string());
            }
            if !quorum_met {
                missing.push("no-validator-set".to_string());
            }
            Ok(json!({
                "found": true,
                "request_id": w.req_id,
                "chain": chain_name(w.target_chain),
                "target_address": w.target_address,
                "amount": w.amount.to_string(),
                "sender": sender_hex,
                "requested_at": w.requested_at,
                "unlock_at": w.unlock_at,
                "refund_at": refund_at,
                "executed": w.executed,
                "escrow_balance": br.escrow_balance.to_string(),
                "escrow_funded": escrow_funded,
                "validator_count": validators.len(),
                "required": required,
                "quorum_met": quorum_met,
                "timelock_matured_estimate": timelock_matured_estimate,
                "remaining_secs_estimate": w.unlock_at.saturating_sub(now),
                "refundable_estimate": refundable_estimate,
                "missing": missing,
                "clock_note": "remaining/refundable/matured are wall-clock estimates; settlement enforces unlock_at and refund_at against the block timestamp",
            }))
        }
    }
}

async fn bridge_deposits(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let address = need_addr(p, "address")?;
    let limit = opt_u64(p, "limit").unwrap_or(100).min(1000) as usize;
    if limit == 0 {
        return Err(invalid("parameter 'limit' must be greater than zero"));
    }
    let br = engine.bridge_read().await;
    let now = display_now_secs();
    let mut entries: Vec<([u8; 32], crate::bridge::DepositRecord)> = br
        .deposit_records
        .iter()
        .filter(|(_, rec)| rec.recipient == address)
        .map(|(h, rec)| (*h, rec.clone()))
        .collect();
    entries.sort_by(|a, b| {
        a.1.deposited_at
            .cmp(&b.1.deposited_at)
            .then_with(|| a.0.cmp(&b.0))
    });
    let total = entries.len();
    let mut deposits: Vec<Value> = Vec::new();
    for (hash, rec) in entries.into_iter().take(limit) {
        let open = open_dispute_for(&br, &hash);
        let resolved = resolved_dispute_for(&br, &hash);
        let status = deposit_lifecycle_status(&rec, &open, &resolved);
        // The dispute countdown exists ONLY while a dispute is open: past
        // resolution (or with no dispute at all) there is no deadline to
        // count down to.
        let dispute = match open {
            Some((dispute_id, d)) => {
                let (challenger_hex, _) = addr_pair(&d.challenger);
                json!({
                    "dispute_id": dispute_id,
                    "challenger": challenger_hex,
                    "deadline": d.deadline,
                    "remaining_secs": d.deadline.saturating_sub(now),
                    "bond": d.bond.to_string(),
                })
            }
            None => Value::Null,
        };
        let challengeable_until = rec
            .deposited_at
            .saturating_add(crate::bridge::CHALLENGE_MAX_AGE_SECS);
        deposits.push(json!({
            "source_tx_hash": hex::encode(hash),
            "amount": rec.amount.to_string(),
            "chain": chain_name(rec.chain),
            "via_quorum": rec.via_quorum,
            "deposited_at": rec.deposited_at,
            "disputed": rec.disputed,
            "status": status,
            "dispute": dispute,
            "challengeable_until": if rec.via_quorum && !rec.disputed { json!(challengeable_until) } else { Value::Null },
        }));
    }
    let count = deposits.len();
    let (addr_hex, addr_stl57) = addr_pair(&address);
    Ok(json!({
        "address": addr_hex,
        "address_stl57": addr_stl57,
        "deposits": deposits,
        "count": count,
        "total": total,
        "limit": limit,
    }))
}

// ---------------------------------------------------------------------------
// Order book (over `crate::orderbook`)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Order book (over `crate::orderbook`) + one-call placement surface
// ---------------------------------------------------------------------------
//
// Two spellings, one envelope. `stell_orderBookPlace`/`stell_orderBookCancel`
// are the original method names; `stell_placeOrder`/`stell_cancelOrder` are
// the market-maker one-call surface: the pair comes first, `order_type` is an
// explicit slot, and the escrow/ownership preconditions the execution path
// would check anyway are surfaced BEFORE the wallet signs. Both spellings
// answer with the same prepare envelope (`prepared(...)`) and NEITHER mutates
// state: the wallet signs `transaction` and submits it with
// `stell_sendRawTransaction`, and the book moves when (and only when) the
// transaction lands in a block.

/// `buy`/`bid` or `sell`/`ask` (case-insensitive), as `(is_buy, side)`.
fn parse_order_side(p: &Value) -> Result<(bool, &'static str), NativeApiError> {
    let side_raw = need_str(p, "side")?.to_lowercase();
    match side_raw.as_str() {
        "buy" | "bid" => Ok((true, "buy")),
        "sell" | "ask" => Ok((false, "sell")),
        _ => Err(invalid("parameter 'side' must be \"buy\" or \"sell\"")),
    }
}

/// The order-type slot. The execution path (`SysCallPlaceOrder`) settles
/// LIMIT semantics only — there is no market-order encoding on the wire — so
/// `market` is REFUSED (fail-closed: silently downgrading it to a limit
/// resting order would leave a quoter exposed), and anything else is invalid.
fn parse_order_type(p: &Value) -> Result<&'static str, NativeApiError> {
    let raw = opt_str(p, "order_type")
        .unwrap_or_else(|| "limit".to_string())
        .to_lowercase();
    match raw.as_str() {
        "limit" => Ok("limit"),
        "market" => Err(refused(
            "order_type \"market\" is not encodable: SysCallPlaceOrder settles limit semantics only; submit a limit order instead",
        )),
        _ => Err(invalid("parameter 'order_type' must be \"limit\"")),
    }
}

/// The calling trader, if the wallet named one. `trader` is canonical;
/// `sender`/`owner` are accepted as aliases so a market-maker adapter does
/// not have to rename its identity field per method.
fn opt_caller(p: &Value, canonical: &str) -> Result<Option<[u8; 32]>, NativeApiError> {
    for key in [canonical, "sender", "owner"] {
        if let Some(s) = p
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return parse_address(&s)
                .map(Some)
                .map_err(|e| invalid(format!("parameter '{key}': {e}")));
        }
    }
    Ok(None)
}

/// The native escrow lock a placement must fund, in the units the live
/// settlement charges (`ClobQuoteMode::NativeSvm`, the `SysCallPlaceOrder`
/// path): a sell locks its base STELL, a buy locks
/// `price * amount / 1_000_000` nano-STELL. Same arithmetic as the SVM
/// affordability check, so a prepare that passes here cannot fail there for
/// funds (a later opcode in the same payload can still spend first — the
/// check is against COMMITTED state, and the block decides).
fn native_order_lock(is_buy: bool, price: u64, amount: u64) -> u64 {
    if is_buy {
        let prod = (price as u128) * (amount as u128);
        (prod / 1_000_000u128).min(u64::MAX as u128) as u64
    } else {
        amount
    }
}

/// Refuse when the named trader cannot fund the escrow lock. Skipped when the
/// wallet did not name a trader (no signer, nothing to check against).
async fn check_order_funds(
    engine: &InMemoryStateEngine,
    trader: Option<[u8; 32]>,
    is_buy: bool,
    price: u64,
    amount: u64,
) -> Result<(), NativeApiError> {
    let Some(t) = trader else { return Ok(()) };
    let lock = native_order_lock(is_buy, price, amount);
    let bal = engine.get_account(&t).await.map(|a| a.balance).unwrap_or(0);
    if bal < lock {
        return Err(refused(format!(
            "insufficient native balance for the escrow lock: have {bal}, need {lock}"
        )));
    }
    Ok(())
}

/// Surface the execution path's admission gate BEFORE the wallet signs: the
/// breaker latch, the USDT peg and the deviation of the limit price from the
/// committed oracle price (`OracleState::gate_order`, the same call
/// `SysCallPlaceOrder` and `place_order_settled` make). With no committed
/// feeds the gate admits — there is no price to deviate from.
async fn check_oracle_gate(
    engine: &InMemoryStateEngine,
    pair: u32,
    price: u64,
) -> Result<(), NativeApiError> {
    let oracle = engine.oracle_read().await;
    oracle.gate_order(pair, price).map_err(refused)
}

/// Shared placement core. `require_pair`: the one-call spelling requires an
/// explicit `pair` (fail-closed against trading the wrong book by default);
/// the legacy spelling keeps its default of 1. `action` selects the envelope
/// label; `echo_order_type` keeps the legacy answer shape byte-identical.
async fn place_validated(
    engine: &InMemoryStateEngine,
    p: &Value,
    pair: u32,
    action: &str,
    echo_order_type: bool,
) -> Result<Value, NativeApiError> {
    let (is_buy, side) = parse_order_side(p)?;
    let price = need_u64(p, "price")?;
    let amount = need_u64(p, "amount")?;
    if price == 0 {
        return Err(refused("price must be greater than zero"));
    }
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let order_type = parse_order_type(p)?;
    let books = engine.orderbooks_read().await;
    if books.get_book(pair).is_none() {
        return Err(not_found(format!("unknown pair {pair}")));
    }
    drop(books);
    check_oracle_gate(engine, pair, price).await?;

    let trader = opt_caller(p, "trader")?;
    check_order_funds(engine, trader, is_buy, price, amount).await?;

    let mut out = prepared(
        action,
        crate::svm::GAS_ORDER_PLACE,
        "SysCallPlaceOrder",
        json!({ "pair_id": pair, "is_buy": is_buy, "price": price, "amount": amount }),
        trader.as_ref(),
    );
    out["pair"] = json!(pair);
    out["side"] = json!(side);
    out["price"] = json!(price.to_string());
    out["amount"] = json!(amount.to_string());
    if echo_order_type {
        out["order_type"] = json!(order_type);
    }
    Ok(out)
}

/// Shared cancellation core. Unknown id is `-32004`; a named caller that is
/// not the placing trader is `-32003`. An unnamed caller prepares the
/// cancellation with the owner's address echoed (the wallet still signs as
/// the owner — the chain re-checks ownership at execution).
async fn cancel_validated(
    engine: &InMemoryStateEngine,
    p: &Value,
    action: &str,
) -> Result<Value, NativeApiError> {
    let order_id = need_u64(p, "order_id")?;
    let pair = opt_u64(p, "pair")
        .map(|v| {
            u32::try_from(v).map_err(|_| invalid("parameter 'pair' is out of range for a pair id"))
        })
        .transpose()?;
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
    let (pid, order) = found.ok_or_else(|| not_found(format!("unknown order id {order_id}")))?;
    drop(books);

    let trader = opt_caller(p, "trader")?;
    if let Some(t) = trader.as_ref() {
        if order.trader != *t {
            return Err(refused(
                "an order can only be cancelled by the trader that placed it",
            ));
        }
    }

    let (trader_hex, _) = addr_pair(&order.trader);
    let mut out = prepared(
        action,
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

async fn order_book_place(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    let pair = opt_u64(p, "pair").unwrap_or(crate::orderbook::PAIR_STELL_USDT as u64);
    let pair = u32::try_from(pair)
        .map_err(|_| invalid("parameter 'pair' is out of range for a pair id"))?;
    place_validated(engine, p, pair, "order_book_place", false).await
}

/// One-call placement: `stell_placeOrder {pair, side, price, amount,
/// order_type?, trader?}`. The pair is REQUIRED (no silent default book);
/// `order_type` defaults to `limit` (the only encodable semantics).
async fn place_order(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    let raw = p
        .get("pair")
        .ok_or_else(|| invalid("missing parameter 'pair'"))?;
    let pair_u64 = raw
        .as_u64()
        .or_else(|| raw.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
        .ok_or_else(|| invalid("parameter 'pair' must be an unsigned integer"))?;
    let pair = u32::try_from(pair_u64)
        .map_err(|_| invalid("parameter 'pair' is out of range for a pair id"))?;
    place_validated(engine, p, pair, "place_order", true).await
}

async fn order_book_cancel(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    cancel_validated(engine, p, "order_book_cancel").await
}

/// One-call cancellation: `stell_cancelOrder {order_id, [pair], [trader]}`.
async fn cancel_order(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    cancel_validated(engine, p, "cancel_order").await
}

async fn order_book_snapshot(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
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
        // Snapshot sequence: bumped on every accepted placement AND every
        // successful cancellation. A quoter polls this snapshot and re-reads
        // the levels only when `version` moved — `next_order_id` alone is NOT
        // sufficient (it moves on placement only, so cancel-only activity is
        // invisible under it). `seq` is the same number under the name
        // poll-loop authors reach for first.
        "version": book.version,
        "seq": book.version,
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

async fn session_key_revoke(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
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
    // Audit F4: honor `limit` (default 100, cap 1000 — same convention as
    // bridge deposits); an unbounded registry dump is unauth CPU/bandwidth DoS.
    let limit = opt_u64(p, "limit").unwrap_or(100).min(1000) as usize;
    let reg = engine.session_keys_read().await;
    let mut list: Vec<Value> = Vec::new();
    for (pk, rec) in reg.entries.iter().take(limit) {
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
    let feed = oracle
        .feeds
        .get(&asset)
        .ok_or_else(|| not_found(format!("no committed price feed for asset '{asset}'")))?;
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

// ---------------------------------------------------------------------------
// Shielded path (privacy-by-default PATH, not a consensus flip)
// ---------------------------------------------------------------------------
//
// Transparent stays the base layer: these methods are the first-class
// entry/exit arms over the EXISTING confidential opcodes — shield entry,
// `SysCallConfidentialTransfer2` (range-proof-enforced; V1 stays refused),
// unshield exit. No new curves, no new proofs, no consensus change.
//
// * `stell_shieldedTransfer` / `stell_unshield` are PREPARE-only: they return
//   the exact payload to sign (plus the fee BEFORE signing) and never mutate.
// * `stell_shieldedBalance` is a READ: it decrypts caller-supplied viewing
//   payloads with the viewing key and checks each coin against the committed
//   `spent` nullifier set. Amounts are hidden in Pedersen commitments, so a
//   viewing key alone cannot sum anything — the wallet holds the payloads
//   (its shielded inventory) and the chain holds the spend flags.

/// Parse a 32-byte hex string (`0x` optional) for a named parameter.
fn need_bytes32(p: &Value, key: &str) -> Result<[u8; 32], NativeApiError> {
    let s = need_str(p, key)?;
    parse_bytes32(&s).map_err(|e| invalid(format!("parameter '{key}': {e}")))
}

fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let clean = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    if clean.len() != 64 {
        return Err("expected 32 bytes (64 hex characters)".to_string());
    }
    let b = hex::decode(clean).map_err(|e| format!("bad hex: {e}"))?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| "expected 32 bytes".to_string())
}

/// Parse variable-length hex for a named parameter.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let clean = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    hex::decode(clean).map_err(|e| format!("bad hex: {e}"))
}

/// The `to` of a shielded transfer: a plain address string (hex or Stl57) or
/// a stealth object `{view_pub, spend_pub}` (both 64-hex) whose one-time
/// address becomes the recipient.
#[allow(clippy::type_complexity)] // GATE: recipient triple is local to this parser; alias churns the shielded path
fn parse_shielded_recipient(
    p: &Value,
) -> Result<([u8; 32], Value, Option<[u8; 32]>), NativeApiError> {
    match p.get("to") {
        Some(Value::String(s)) => {
            let a = parse_address(s).map_err(|e| invalid(format!("parameter 'to': {e}")))?;
            Ok((a, Value::Null, None))
        }
        Some(Value::Object(_)) => {
            let obj = p.get("to").unwrap();
            let view_pub = obj
                .get("view_pub")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid("parameter 'to.view_pub' must be a 64-hex string"))?;
            let spend_pub = obj
                .get("spend_pub")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid("parameter 'to.spend_pub' must be a 64-hex string"))?;
            let view_pub = parse_bytes32(view_pub)
                .map_err(|e| invalid(format!("parameter 'to.view_pub': {e}")))?;
            let spend_pub = parse_bytes32(spend_pub)
                .map_err(|e| invalid(format!("parameter 'to.spend_pub': {e}")))?;
            let stealth = crate::crypto_privacy::StealthAddress::generate(&view_pub, &spend_pub)
                .ok_or_else(|| invalid("parameter 'to': invalid stealth keys"))?;
            let info = json!({
                "one_time_pub": hex::encode(stealth.one_time_pub),
                "ephemeral_pub": hex::encode(stealth.ephemeral_pub),
            });
            Ok((stealth.one_time_pub, info, Some(view_pub)))
        }
        Some(_) => Err(invalid(
            "parameter 'to' must be an address string or a stealth object {view_pub, spend_pub}",
        )),
        None => Err(invalid("missing parameter 'to'")),
    }
}

fn range_proof_json(p: &crate::crypto_privacy::RangeProof) -> Value {
    json!({
        "bits": p.bits,
        "bit_commitments": p.bit_commitments.iter().map(|c| hex::encode(c.commitment)).collect::<Vec<_>>(),
        "bit_proofs": p.bit_proofs.iter().map(|b| json!({
            "e0": hex::encode(b.e0),
            "s0": hex::encode(b.s0),
            "e1": hex::encode(b.e1),
            "s1": hex::encode(b.s1),
        })).collect::<Vec<_>>(),
    })
}

async fn shielded_transfer(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    use crate::crypto_privacy::{RangeProof, ViewingKey, SHIELD_ESCROW};
    use crate::svm::{
        confidential_transfer2_gas, GAS_CONFIDENTIAL_SHIELD, GAS_CONFIDENTIAL_T2_PER_BIT,
        GAS_CONFIDENTIAL_T2_PER_COMMITMENT, GAS_CONFIDENTIAL_TRANSFER2,
    };

    let (recipient, stealth_info, recipient_view_pub) = parse_shielded_recipient(p)?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    let fee = opt_u64(p, "fee").unwrap_or(0);
    let shield_total = amount
        .checked_add(fee)
        .ok_or_else(|| invalid("amount + fee overflows u64"))?;

    // The execution path refuses protocol-owned recipients (outputs there
    // freeze forever): surface it here instead of after signing.
    if recipient == SHIELD_ESCROW
        || recipient == crate::staking::STAKING_POOL
        || recipient == crate::bridge::BRIDGE_ESCROW
    {
        return Err(refused(
            "shielded transfer refused: recipient is a protocol account",
        ));
    }

    // THE shared wallet builder path (same blinding-conservation equation the
    // wallet uses) — no reimplemented crypto. Range proofs attach here with
    // the existing `prove_auto` (auto 32/64-bit width, never 0/1).
    let (transfer, blinding) =
        crate::wallet::WalletAccount::build_confidential_transfer(amount, fee);
    let input_ranges = vec![RangeProof::prove_auto(
        &transfer.input_commitments[0],
        shield_total,
        &blinding,
    )];
    let output_ranges = vec![RangeProof::prove_auto(
        &transfer.output_commitments[0],
        amount,
        &blinding,
    )];
    let bits: u64 = input_ranges
        .iter()
        .chain(output_ranges.iter())
        .map(|r| r.bits as u64)
        .sum();
    let transfer_gas = confidential_transfer2_gas(&input_ranges, &output_ranges);
    let gas_limit = GAS_CONFIDENTIAL_SHIELD.saturating_add(transfer_gas);

    // Funding precondition mirrors admission + the shield debit: the sender
    // must cover the shielded total AND the declared gas.
    let sender = match p.get("sender").or_else(|| p.get("from")) {
        Some(_) => Some(
            need_addr(p, "sender")
                .or_else(|_| need_addr(p, "from"))
                .map_err(|_| invalid("parameter 'sender' must be an address"))?,
        ),
        None => None,
    };
    if let Some(s) = sender.as_ref() {
        let have = engine.get_account(s).await.map(|a| a.balance).unwrap_or(0);
        let need = shield_total
            .checked_add(gas_limit)
            .ok_or_else(|| invalid("shield total + gas overflows u64"))?;
        if have < need {
            return Err(refused(format!(
                "insufficient native balance: have {have}, shield needs {shield_total} + {gas_limit} gas"
            )));
        }
    }

    // Auditor payload: stealth recipients carry their own view_pub; plain
    // recipients may name one via `view_pub`. Without either there is nothing
    // to encrypt to — the openings below are the sender's inventory instead.
    let auditor_view_pub: Option<[u8; 32]> =
        recipient_view_pub.or_else(|| opt_str(p, "view_pub").and_then(|s| parse_bytes32(&s).ok()));
    let viewing_payload = match auditor_view_pub.as_ref() {
        Some(vp) => match ViewingKey::encrypt_amount_for_auditor(vp, amount, &blinding) {
            Ok(enc) => json!({
                "ephemeral_pub": hex::encode(enc.ephemeral_pub),
                "ciphertext": hex::encode(&enc.ciphertext),
                "nonce": hex::encode(enc.nonce),
                "recipient_view_pub": hex::encode(vp),
            }),
            Err(e) => return Err(invalid(format!("auditor payload: {e}"))),
        },
        None => Value::Null,
    };

    let (to_hex, to_stl57) = addr_pair(&recipient);
    let mut out = prepared(
        "shielded_transfer",
        gas_limit,
        "SysCallConfidentialShield+SysCallConfidentialTransfer2",
        json!({
            "recipient": to_hex,
            "shield": {
                "commitment": hex::encode(transfer.input_commitments[0].commitment),
                "amount": shield_total,
                "blinding": hex::encode(blinding.to_bytes()),
            },
            "transfer": {
                "recipient": to_hex,
                "input_commitments": transfer.input_commitments.iter().map(|c| hex::encode(c.commitment)).collect::<Vec<_>>(),
                "output_commitments": transfer.output_commitments.iter().map(|c| hex::encode(c.commitment)).collect::<Vec<_>>(),
                "fee": transfer.fee,
                "input_ranges": input_ranges.iter().map(range_proof_json).collect::<Vec<_>>(),
                "output_ranges": output_ranges.iter().map(range_proof_json).collect::<Vec<_>>(),
            },
        }),
        sender.as_ref(),
    );
    out["to"] = json!(to_hex);
    out["to_stl57"] = if stealth_info.is_null() {
        json!(to_stl57)
    } else {
        Value::Null
    };
    out["stealth"] = stealth_info;
    out["amount"] = json!(amount.to_string());
    out["confidential_fee"] = json!(fee.to_string());
    out["gas_breakdown"] = json!({
        "shield_gas": GAS_CONFIDENTIAL_SHIELD,
        "transfer2_base": GAS_CONFIDENTIAL_TRANSFER2,
        "per_commitment": GAS_CONFIDENTIAL_T2_PER_COMMITMENT,
        "commitments": 2,
        "per_bit": GAS_CONFIDENTIAL_T2_PER_BIT,
        "bits": bits,
        "transfer_gas": transfer_gas,
        "gas_limit": gas_limit,
    });
    out["fee_preview"] = json!(format!(
        "signing this pays up to {gas_limit} gas (1.75x confidential surcharge included) \
         plus a {fee} inner confidential fee burned to the shielded total"
    ));
    out["openings"] = json!([
        {
            "commitment": hex::encode(transfer.input_commitments[0].commitment),
            "amount": shield_total.to_string(),
            "blinding": hex::encode(blinding.to_bytes()),
            "role": "shield input (spent by the transfer)",
        },
        {
            "commitment": hex::encode(transfer.output_commitments[0].commitment),
            "amount": amount.to_string(),
            "blinding": hex::encode(blinding.to_bytes()),
            "role": "recipient output (spendable with this opening)",
        },
    ]);
    out["viewing_payload"] = viewing_payload;
    out["custody_warning"] = json!(
        "blindings are spend secrets: anyone holding an opening can spend the coin. \
         Store them like private keys; the viewing payload reveals amount+blinding to its viewing key only."
    );
    Ok(out)
}

async fn shielded_balance(
    engine: &InMemoryStateEngine,
    p: &Value,
) -> Result<Value, NativeApiError> {
    use crate::crypto_privacy::{
        ConfidentialState, EncryptedViewingPayload, PedersenCommitment, ViewingKey,
    };

    // The viewing key is a SECRET (it decrypts every payload ever encrypted
    // to it — past and future, no forward secrecy). It is parsed, used, and
    // dropped here; it is never logged and never echoed (only the public
    // half is returned). `ViewingKey`'s Debug impl redacts it for the same
    // reason.
    let vk_bytes = need_bytes32(p, "viewing_key")?;
    let vk = ViewingKey::from_scalar(&Scalar::from_bytes_mod_order(vk_bytes));

    let shielded = engine.confidential_read().await;
    let owned_outputs = shielded.owned.len();
    // THE double-spend guard, exposed exactly as stored: `spent` is the
    // nullifier set (consumed commitment bytes). There is no separate
    // nullifier field — membership here IS the spent flag.
    let spent_nullifiers = shielded.spent.len();
    let total_fees = shielded.total_fees;

    let mut coins: Vec<Value> = Vec::new();
    let mut spendable_sum: u64 = 0;
    let mut undecryptable: u64 = 0;
    if let Some(arr) = p.get("payloads").and_then(|v| v.as_array()) {
        // Audit F1: bound the scan (unauth CPU DoS otherwise); see
        // `MAX_SHIELDED_SCAN_PAYLOADS`. Larger histories paginate client-side.
        if arr.len() > crate::svm::MAX_SHIELDED_SCAN_PAYLOADS {
            return Err(NativeApiError::InvalidParams(format!(
                "payloads exceeds cap {} (got {})",
                crate::svm::MAX_SHIELDED_SCAN_PAYLOADS,
                arr.len()
            )));
        }
        for (i, item) in arr.iter().enumerate() {
            let parsed = (|| -> Result<EncryptedViewingPayload, String> {
                let obj = item
                    .as_object()
                    .ok_or_else(|| "must be an object".to_string())?;
                let get = |k: &str| {
                    obj.get(k)
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("missing '{k}'"))
                };
                let ephem = parse_bytes32(get("ephemeral_pub")?)?;
                let ct = parse_hex_bytes(get("ciphertext")?)?;
                let nonce_s = get("nonce")?;
                let nonce_clean = nonce_s
                    .trim()
                    .strip_prefix("0x")
                    .or_else(|| nonce_s.trim().strip_prefix("0X"))
                    .unwrap_or(nonce_s.trim());
                let nonce_b =
                    hex::decode(nonce_clean).map_err(|e| format!("bad nonce hex: {e}"))?;
                if nonce_b.len() != 24 {
                    return Err("nonce must be 24 bytes".to_string());
                }
                let mut nonce = [0u8; 24];
                nonce.copy_from_slice(&nonce_b);
                Ok(EncryptedViewingPayload {
                    ephemeral_pub: ephem,
                    ciphertext: ct,
                    nonce,
                })
            })();
            let payload = match parsed {
                Ok(pl) => pl,
                Err(e) => {
                    undecryptable += 1;
                    coins.push(json!({ "index": i, "decrypted": false, "error": e }));
                    continue;
                }
            };
            // A wrong viewing key fails HERE: nothing is revealed, the coin
            // is counted as undecryptable, never as zero-valued.
            let (value, blinding) = match vk.decrypt_amount(&payload) {
                Ok(v) => v,
                Err(_) => {
                    undecryptable += 1;
                    coins.push(json!({ "index": i, "decrypted": false }));
                    continue;
                }
            };
            let commitment = PedersenCommitment::commit(value, &blinding).commitment;
            let opening_ok =
                ConfidentialState::verify_opening(&commitment, value, &blinding.to_bytes());
            let owner = shielded.owned.get(&commitment).map(hex::encode);
            let spent = shielded.is_spent(&commitment);
            let spendable = opening_ok && owner.is_some() && !spent;
            if spendable {
                spendable_sum = spendable_sum
                    .checked_add(value)
                    .ok_or_else(|| refused("spendable sum overflows u64"))?;
            }
            coins.push(json!({
                "index": i,
                "decrypted": true,
                "commitment": hex::encode(commitment),
                "amount": value.to_string(),
                "owner": owner,
                "spent": spent,
                "spendable": spendable,
            }));
        }
    }
    drop(shielded);

    Ok(json!({
        "view_pub": hex::encode(vk.view_pub),
        "coins": coins,
        "coin_count": coins.len(),
        "undecryptable": undecryptable,
        "spendable_sum": spendable_sum.to_string(),
        "chain": {
            "owned_outputs": owned_outputs,
            "spent_nullifiers": spent_nullifiers,
            "total_fees": total_fees.to_string(),
        },
        "spend_tracking": "the `spent` set (consumed commitment bytes) is the nullifier set — \
            membership refuses a double-spend, no separate nullifier field exists",
        "note": "amounts are hidden in Pedersen commitments: only payloads encrypted to this \
            viewing key can be summed; a wrong key decrypts nothing and sums zero",
    }))
}

async fn unshield(engine: &InMemoryStateEngine, p: &Value) -> Result<Value, NativeApiError> {
    use crate::crypto_privacy::{ConfidentialState, UnshieldInput, SHIELD_ESCROW};
    use crate::svm::{
        GAS_CONFIDENTIAL_UNSHIELD, GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT, MAX_UNSHIELD_INPUTS_PER_TX,
    };

    // The exit pays the SIGNER (the opcode has no recipient field): `to` must
    // name the account that will sign, never a third party. A mismatch is a
    // caller error, refused before anything is built.
    let to = need_addr(p, "to")?;
    let amount = need_u64(p, "amount")?;
    if amount == 0 {
        return Err(refused("amount must be greater than zero"));
    }
    if let Some(s) = opt_str(p, "sender").or_else(|| opt_str(p, "from")) {
        let sender = parse_address(&s).map_err(|e| invalid(format!("parameter 'sender': {e}")))?;
        if sender != to {
            return Err(invalid(
                "unshield pays the signer: `to` must equal the signing account (`sender`)",
            ));
        }
    }
    let raw = p
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid("missing parameter 'inputs'"))?;
    if raw.is_empty() {
        return Err(invalid("parameter 'inputs' must not be empty"));
    }
    if raw.len() > MAX_UNSHIELD_INPUTS_PER_TX {
        return Err(invalid(format!(
            "too many unshield inputs (max {MAX_UNSHIELD_INPUTS_PER_TX})"
        )));
    }

    // Read-only re-verification of exactly what `retire_for_unshield` will
    // enforce at execution: opening recompute, sender-ownership, unspent.
    // Anything the chain would refuse is refused here with the same reason.
    let shielded = engine.confidential_read().await;
    let mut inputs: Vec<UnshieldInput> = Vec::with_capacity(raw.len());
    let mut total: u64 = 0;
    for item in raw {
        let obj = item
            .as_object()
            .ok_or_else(|| invalid("each input must be an object"))?;
        let get = |k: &str| {
            obj.get(k)
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid(format!("each input needs '{k}'")))
        };
        let commitment = parse_bytes32(get("commitment")?)
            .map_err(|e| invalid(format!("input commitment: {e}")))?;
        let value: u64 = get("amount")?
            .trim()
            .parse()
            .map_err(|_| invalid("input amount must be an unsigned integer"))?;
        let blinding =
            parse_bytes32(get("blinding")?).map_err(|e| invalid(format!("input blinding: {e}")))?;
        if !ConfidentialState::verify_opening(&commitment, value, &blinding) {
            return Err(refused(format!(
                "unshield rejected: opening does not match commitment {}",
                hex::encode(commitment)
            )));
        }
        match shielded.owned.get(&commitment) {
            Some(owner) if *owner == to => {}
            _ => {
                return Err(refused(format!(
                    "unshield rejected: commitment {} is not owned by {}",
                    hex::encode(commitment),
                    hex::encode(to)
                )))
            }
        }
        if shielded.is_spent(&commitment) {
            return Err(refused(format!(
                "unshield rejected: commitment {} already spent",
                hex::encode(commitment)
            )));
        }
        if inputs
            .iter()
            .any(|inp: &UnshieldInput| inp.commitment == commitment)
        {
            return Err(refused(format!(
                "unshield rejected: duplicate input {}",
                hex::encode(commitment)
            )));
        }
        total = total
            .checked_add(value)
            .ok_or_else(|| refused("unshield total overflows u64"))?;
        inputs.push(UnshieldInput {
            commitment,
            amount: value,
            blinding,
        });
    }
    drop(shielded);

    if total != amount {
        return Err(invalid(format!(
            "inputs sum to {total}, not the requested amount {amount}"
        )));
    }
    let gas_limit = GAS_CONFIDENTIAL_UNSHIELD
        .saturating_add((inputs.len() as u64).saturating_mul(GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT));

    // Escrow precondition: the exit draws native from SHIELD_ESCROW, so an
    // underfunded escrow would revert at execution — surface it now.
    let escrow_balance = engine
        .get_account(&SHIELD_ESCROW)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    if escrow_balance < total {
        return Err(refused(format!(
            "shield escrow holds {escrow_balance}, the exit needs {total}"
        )));
    }
    let have = engine
        .get_account(&to)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    if have < gas_limit {
        return Err(refused(format!(
            "insufficient native balance for gas: have {have}, need {gas_limit}"
        )));
    }

    let (to_hex, to_stl57) = addr_pair(&to);
    let mut out = prepared(
        "unshield",
        gas_limit,
        "SysCallConfidentialUnshield",
        json!({
            "inputs": inputs.iter().map(|i| json!({
                "commitment": hex::encode(i.commitment),
                "amount": i.amount,
                "blinding": hex::encode(i.blinding),
            })).collect::<Vec<_>>(),
            "total": total,
            "to": to_hex,
        }),
        Some(&to),
    );
    out["to"] = json!(to_hex);
    out["to_stl57"] = json!(to_stl57);
    out["amount"] = json!(total.to_string());
    out["gas_breakdown"] = json!({
        "base": GAS_CONFIDENTIAL_UNSHIELD,
        "per_input": GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT,
        "inputs": inputs.len(),
        "gas_limit": gas_limit,
    });
    out["fee_preview"] = json!(format!(
        "signing this pays up to {gas_limit} gas and releases exactly {total} native to the signer"
    ));
    out["escrow_balance"] = json!(escrow_balance.to_string());
    Ok(out)
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
            "stell_tokenMint",
            "stell_tokenBurn",
            "stell_tokenApprove",
            "stell_tokenTransferFrom",
            "stell_tokenCreate",
            "stell_stakeBond",
            "stell_stakeUnbond",
            "stell_stakeWithdraw",
            "stell_delegate",
            "stell_undelegate",
            "stell_claimRewards",
            "stell_bridgeDepositPrepare",
            "stell_bridgeWithdraw",
            "stell_bridgeStatus",
            "stell_bridgeAttestStatus",
            "stell_bridgeReleaseEstimate",
            "stell_bridgeDeposits",
            "stell_orderBookPlace",
            "stell_orderBookCancel",
            "stell_orderBookSnapshot",
            "stell_placeOrder",
            "stell_cancelOrder",
            "stell_sessionKeyRegister",
            "stell_sessionKeyRevoke",
            "stell_sessionKeys",
            "stell_oraclePrice",
            "stell_oracleFeeds",
            "stell_shieldedTransfer",
            "stell_shieldedBalance",
            "stell_unshield",
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

    async fn engine_with_validators(n: u8) -> InMemoryStateEngine {
        let engine = InMemoryStateEngine::new();
        let stake = crate::staking::MIN_VALIDATOR_BOND + crate::staking::STELL_MIN_BOND_BUFFER;
        for i in 0..n {
            let pk = addr(0xA0 + i);
            engine
                .credit_native(&pk, 10 * stake)
                .await
                .expect("fund the validator");
            engine
                .staking_write()
                .await
                .bond(pk, stake, 0)
                .expect("bond it into the committed ledger");
        }
        engine
    }

    fn quorum_record(
        recipient: [u8; 32],
        amount: u64,
        deposited_at: u64,
    ) -> crate::bridge::DepositRecord {
        crate::bridge::DepositRecord {
            recipient,
            amount,
            chain: crate::bridge::SupportedChain::Ton,
            via_quorum: true,
            deposited_at,
            disputed: false,
        }
    }

    #[tokio::test]
    async fn bridge_attest_status_counts_match_the_committed_threshold() {
        // 3 committed validators -> bridge-domain threshold (2n+2)/3 = 2.
        let engine = engine_with_validators(3).await;
        let src = addr(5);
        {
            let mut br = engine.bridge_write().await;
            br.processed_source_txs.insert(src);
            br.deposit_records
                .insert(src, quorum_record(addr(2), 42, 7));
        }
        let v = dispatch(
            &engine,
            "stell_bridgeAttestStatus",
            &json!({ "source_tx_hash": hex::encode(src) }),
        )
        .await
        .unwrap();
        assert_eq!(v["found"], true);
        assert_eq!(v["required"], 2);
        // Settled via quorum: the deposit was admitted BECAUSE the threshold
        // was met — the committed state stores the verdict, not a partial
        // count, so attestations == required and nothing remains.
        assert_eq!(v["attestations"], 2);
        assert_eq!(v["remaining"], 0);
        assert_eq!(v["via_quorum"], true);
        assert_eq!(v["path"], "quorum");
        assert_eq!(v["disputed"], false);
        assert_eq!(v["status"], "confirmed");
        assert!(v["dispute"].is_null());
    }

    #[tokio::test]
    async fn bridge_attest_status_of_an_unknown_hash_is_not_found() {
        let engine = engine_with_validators(3).await;
        let v = dispatch(
            &engine,
            "stell_bridgeAttestStatus",
            &json!({ "source_tx_hash": hex::encode(addr(9)) }),
        )
        .await
        .unwrap();
        assert_eq!(v["found"], false);
        // Pre-commit attestations are in-payload, not committed state: zero
        // settled attestations with the full threshold still to go.
        assert_eq!(v["attestations"], 0);
        assert_eq!(v["required"], 2);
        assert_eq!(v["remaining"], 2);
    }

    #[tokio::test]
    async fn bridge_attest_status_of_evidence_path_reports_no_attestations() {
        let engine = engine_with_validators(3).await;
        let src = addr(6);
        {
            let mut br = engine.bridge_write().await;
            br.processed_source_txs.insert(src);
            br.deposit_records.insert(
                src,
                crate::bridge::DepositRecord {
                    recipient: addr(2),
                    amount: 11,
                    chain: crate::bridge::SupportedChain::Ton,
                    via_quorum: false,
                    deposited_at: 7,
                    disputed: false,
                },
            );
        }
        let v = dispatch(
            &engine,
            "stell_bridgeAttestStatus",
            &json!({ "source_tx_hash": hex::encode(src) }),
        )
        .await
        .unwrap();
        assert_eq!(v["found"], true);
        assert_eq!(v["path"], "evidence");
        assert_eq!(v["attestations"], 0);
        assert_eq!(v["remaining"], 0);
        assert_eq!(v["status"], "confirmed");
    }

    #[tokio::test]
    async fn bridge_attest_status_of_a_challenged_deposit_shows_the_countdown() {
        let engine = engine_with_validators(3).await;
        let src = addr(5);
        let now = crate::zkml::now_secs();
        {
            let mut br = engine.bridge_write().await;
            let mut rec = quorum_record(addr(2), 42, now);
            rec.disputed = true;
            br.processed_source_txs.insert(src);
            br.deposit_records.insert(src, rec);
            br.disputes.insert(
                0,
                crate::bridge::Dispute {
                    source_tx_hash: src,
                    challenger: addr(8),
                    recipient: addr(2),
                    amount: 42,
                    bond: crate::bridge::CHALLENGE_BOND_NANO,
                    deadline: now + crate::bridge::DISPUTE_WINDOW_SECS,
                    resolved: false,
                    confirmed: false,
                },
            );
            br.next_dispute_id = 1;
        }
        let v = dispatch(
            &engine,
            "stell_bridgeAttestStatus",
            &json!({ "source_tx_hash": hex::encode(src) }),
        )
        .await
        .unwrap();
        assert_eq!(v["found"], true);
        assert_eq!(v["disputed"], true);
        assert_eq!(v["status"], "challenged");
        assert_eq!(v["dispute"]["dispute_id"], 0);
        assert_eq!(
            v["dispute"]["deadline"],
            now + crate::bridge::DISPUTE_WINDOW_SECS
        );
        let remaining = v["dispute"]["remaining_secs"].as_u64().unwrap();
        assert!(remaining > 0 && remaining <= crate::bridge::DISPUTE_WINDOW_SECS);
    }

    #[tokio::test]
    async fn bridge_attest_status_countdown_disappears_after_resolve() {
        let engine = engine_with_validators(3).await;
        let src = addr(5);
        let now = crate::zkml::now_secs();
        {
            let mut br = engine.bridge_write().await;
            let mut rec = quorum_record(addr(2), 42, now);
            rec.disputed = true;
            br.processed_source_txs.insert(src);
            br.deposit_records.insert(src, rec);
            br.disputes.insert(
                0,
                crate::bridge::Dispute {
                    source_tx_hash: src,
                    challenger: addr(8),
                    recipient: addr(2),
                    amount: 42,
                    bond: crate::bridge::CHALLENGE_BOND_NANO,
                    deadline: now.saturating_sub(10),
                    resolved: true,
                    confirmed: true,
                },
            );
            br.next_dispute_id = 1;
        }
        let v = dispatch(
            &engine,
            "stell_bridgeAttestStatus",
            &json!({ "source_tx_hash": hex::encode(src) }),
        )
        .await
        .unwrap();
        assert_eq!(v["status"], "confirmed");
        assert!(v["dispute"].is_null());
    }

    #[tokio::test]
    async fn bridge_release_estimate_matches_pre_and_post_unlock() {
        let engine = engine_with_validators(3).await;
        let now = crate::zkml::now_secs();
        {
            let mut br = engine.bridge_write().await;
            br.escrow_balance = 1_000_000 * 1_000_000_000;
            br.pending_withdrawals.insert(
                0,
                crate::bridge::TeleportWithdrawalRequest {
                    req_id: 0,
                    sender: addr(2),
                    target_chain: crate::bridge::SupportedChain::Ton,
                    target_address: "ton-recipient".to_string(),
                    amount: 10,
                    requested_at: now.saturating_sub(100),
                    unlock_at: now.saturating_sub(100),
                    executed: false,
                },
            );
            br.pending_withdrawals.insert(
                1,
                crate::bridge::TeleportWithdrawalRequest {
                    req_id: 1,
                    sender: addr(2),
                    target_chain: crate::bridge::SupportedChain::Ton,
                    target_address: "ton-recipient".to_string(),
                    amount: 60_000 * 1_000_000_000,
                    requested_at: now,
                    unlock_at: now + 7200,
                    executed: false,
                },
            );
            br.next_withdrawal_id = 2;
        }
        // Matured small withdrawal: nothing missing.
        let ready = dispatch(
            &engine,
            "stell_bridgeReleaseEstimate",
            &json!({ "request_id": 0 }),
        )
        .await
        .unwrap();
        assert_eq!(ready["found"], true);
        assert_eq!(ready["executed"], false);
        assert_eq!(ready["quorum_met"], true);
        assert_eq!(ready["escrow_funded"], true);
        assert!(ready["missing"].as_array().unwrap().is_empty());
        // Large withdrawal still inside the 1h timelock: timelock missing,
        // with a positive countdown; the request itself is untouched.
        let locked = dispatch(
            &engine,
            "stell_bridgeReleaseEstimate",
            &json!({ "request_id": 1 }),
        )
        .await
        .unwrap();
        assert_eq!(locked["found"], true);
        let missing: Vec<String> = locked["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(missing.contains(&"timelock".to_string()), "{missing:?}");
        assert!(locked["remaining_secs_estimate"].as_u64().unwrap() > 0);
        assert_eq!(locked["executed"], false);
    }

    #[tokio::test]
    async fn bridge_release_estimate_flags_executed_and_escrow_shortfall() {
        let engine = engine_with_validators(1).await;
        let now = crate::zkml::now_secs();
        {
            let mut br = engine.bridge_write().await;
            br.escrow_balance = 5;
            br.pending_withdrawals.insert(
                0,
                crate::bridge::TeleportWithdrawalRequest {
                    req_id: 0,
                    sender: addr(2),
                    target_chain: crate::bridge::SupportedChain::Ton,
                    target_address: "ton-recipient".to_string(),
                    amount: 10_000,
                    requested_at: now.saturating_sub(100),
                    unlock_at: now.saturating_sub(100),
                    executed: true,
                },
            );
            br.next_withdrawal_id = 1;
        }
        let v = dispatch(
            &engine,
            "stell_bridgeReleaseEstimate",
            &json!({ "request_id": 0 }),
        )
        .await
        .unwrap();
        let missing: Vec<String> = v["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            missing.contains(&"already-executed".to_string()),
            "{missing:?}"
        );
        assert!(
            missing.contains(&"escrow-shortfall".to_string()),
            "{missing:?}"
        );
        assert_eq!(v["escrow_funded"], false);
    }

    #[tokio::test]
    async fn bridge_release_estimate_of_an_unknown_request_is_not_found() {
        let engine = engine_with_validators(1).await;
        let v = dispatch(
            &engine,
            "stell_bridgeReleaseEstimate",
            &json!({ "request_id": 4242 }),
        )
        .await
        .unwrap();
        assert_eq!(v["found"], false);
        assert_eq!(v["request_id"], 4242);
    }

    #[tokio::test]
    async fn bridge_release_estimate_surfaces_an_empty_validator_set() {
        let engine = InMemoryStateEngine::new();
        let now = crate::zkml::now_secs();
        {
            let mut br = engine.bridge_write().await;
            br.escrow_balance = u64::MAX;
            br.pending_withdrawals.insert(
                0,
                crate::bridge::TeleportWithdrawalRequest {
                    req_id: 0,
                    sender: addr(2),
                    target_chain: crate::bridge::SupportedChain::Ton,
                    target_address: "ton-recipient".to_string(),
                    amount: 10,
                    requested_at: now.saturating_sub(100),
                    unlock_at: now.saturating_sub(100),
                    executed: false,
                },
            );
            br.next_withdrawal_id = 1;
        }
        let v = dispatch(
            &engine,
            "stell_bridgeReleaseEstimate",
            &json!({ "request_id": 0 }),
        )
        .await
        .unwrap();
        assert_eq!(v["quorum_met"], false);
        let missing: Vec<String> = v["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            missing.contains(&"no-validator-set".to_string()),
            "{missing:?}"
        );
    }

    #[tokio::test]
    async fn bridge_deposits_lists_status_and_countdown_with_pagination() {
        let engine = engine_with_validators(3).await;
        let now = crate::zkml::now_secs();
        let src_a = addr(21);
        let src_b = addr(22);
        {
            let mut br = engine.bridge_write().await;
            br.processed_source_txs.insert(src_a);
            br.processed_source_txs.insert(src_b);
            br.processed_source_txs.insert(addr(23));
            br.deposit_records
                .insert(src_a, quorum_record(addr(2), 42, now - 100));
            let mut challenged = quorum_record(addr(2), 43, now - 50);
            challenged.disputed = true;
            br.deposit_records.insert(src_b, challenged);
            br.deposit_records
                .insert(addr(23), quorum_record(addr(3), 44, now - 10));
            br.disputes.insert(
                0,
                crate::bridge::Dispute {
                    source_tx_hash: src_b,
                    challenger: addr(8),
                    recipient: addr(2),
                    amount: 43,
                    bond: crate::bridge::CHALLENGE_BOND_NANO,
                    deadline: now + 1800,
                    resolved: false,
                    confirmed: false,
                },
            );
            br.next_dispute_id = 1;
        }
        let v = dispatch(
            &engine,
            "stell_bridgeDeposits",
            &json!({ "address": hex::encode(addr(2)), "limit": 100 }),
        )
        .await
        .unwrap();
        assert_eq!(v["total"], 2);
        assert_eq!(v["count"], 2);
        let list = v["deposits"].as_array().unwrap();
        // Sorted oldest first.
        assert_eq!(list[0]["source_tx_hash"], hex::encode(src_a));
        assert_eq!(list[0]["status"], "confirmed");
        assert!(list[0]["dispute"].is_null());
        assert!(list[0]["challengeable_until"].is_number());
        // Open dispute: countdown present.
        assert_eq!(list[1]["status"], "challenged");
        assert_eq!(list[1]["dispute"]["dispute_id"], 0);
        assert!(list[1]["dispute"]["remaining_secs"].as_u64().unwrap() > 0);
        // Pagination: limit 1 keeps the oldest only, total unchanged.
        let page = dispatch(
            &engine,
            "stell_bridgeDeposits",
            &json!({ "address": hex::encode(addr(2)), "limit": 1 }),
        )
        .await
        .unwrap();
        assert_eq!(page["count"], 1);
        assert_eq!(page["total"], 2);
        assert_eq!(page["deposits"][0]["source_tx_hash"], hex::encode(src_a));
    }

    #[tokio::test]
    async fn bridge_deposits_reports_a_revoked_deposit_without_a_countdown() {
        let engine = engine_with_validators(1).await;
        let now = crate::zkml::now_secs();
        let src = addr(31);
        {
            let mut br = engine.bridge_write().await;
            br.processed_source_txs.insert(src);
            let mut rec = quorum_record(addr(2), 42, now - 7200);
            rec.disputed = true;
            br.deposit_records.insert(src, rec);
            br.disputes.insert(
                0,
                crate::bridge::Dispute {
                    source_tx_hash: src,
                    challenger: addr(8),
                    recipient: addr(2),
                    amount: 42,
                    bond: crate::bridge::CHALLENGE_BOND_NANO,
                    deadline: now.saturating_sub(10),
                    resolved: true,
                    confirmed: false,
                },
            );
            br.next_dispute_id = 1;
        }
        let v = dispatch(
            &engine,
            "stell_bridgeDeposits",
            &json!({ "address": hex::encode(addr(2)) }),
        )
        .await
        .unwrap();
        assert_eq!(v["deposits"][0]["status"], "revoked");
        assert!(v["deposits"][0]["dispute"].is_null());
    }

    #[tokio::test]
    async fn bridge_deposits_requires_an_address() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_bridgeDeposits", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32602);
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
    async fn order_book_snapshot_carries_a_stale_read_version() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(&engine, "stell_orderBookSnapshot", &json!({ "pair": 1 }))
            .await
            .unwrap();
        assert_eq!(v["version"], 0);
        assert_eq!(v["seq"], 0);
        assert_eq!(v["next_order_id"], 1);
    }

    #[tokio::test]
    async fn snapshot_version_moves_on_cancel_but_next_order_id_does_not() {
        let engine = InMemoryStateEngine::new();
        let trader = addr(4);
        {
            let mut books = engine.orderbooks_write().await;
            let book = books.get_book_mut(1);
            book.submit_order(trader, crate::orderbook::OrderSide::Buy, 250_000, 10, 0);
            assert_eq!(book.version, 1);
            assert_eq!(book.next_order_id, 2);
            book.cancel_order(1).expect("resting order cancels");
            // The cancel is a book mutation too: the snapshot sequence moves
            // while the placement counter stays put — the reason `version`
            // (not `next_order_id`) is the stale-read signal.
            assert_eq!(book.version, 2);
            assert_eq!(book.next_order_id, 2);
        }
        let v = dispatch(&engine, "stell_orderBookSnapshot", &json!({ "pair": 1 }))
            .await
            .unwrap();
        assert_eq!(v["version"], 2);
        assert_eq!(v["seq"], 2);
        assert_eq!(v["next_order_id"], 2);
    }

    #[tokio::test]
    async fn place_order_prepares_the_same_envelope() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(
            &engine,
            "stell_placeOrder",
            &json!({ "pair": 1, "side": "sell", "price": "250000", "amount": "10" }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "place_order");
        assert_eq!(v["transaction"]["op"], "SysCallPlaceOrder");
        assert_eq!(v["transaction"]["args"]["pair_id"], 1);
        assert_eq!(v["transaction"]["args"]["is_buy"], false);
        assert_eq!(v["side"], "sell");
        assert_eq!(v["order_type"], "limit");
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
    }

    #[tokio::test]
    async fn place_order_requires_an_explicit_pair() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_placeOrder",
            &json!({ "side": "buy", "price": "1", "amount": "1" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32602);
    }

    #[tokio::test]
    async fn place_order_with_a_bad_pair_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_placeOrder",
            &json!({ "pair": 4242, "side": "buy", "price": "1", "amount": "1" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn place_order_with_a_market_type_is_refused() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(
            &engine,
            "stell_placeOrder",
            &json!({ "pair": 1, "side": "buy", "price": "1", "amount": "1", "order_type": "market" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn place_order_without_funds_for_the_escrow_lock_is_refused() {
        let engine = InMemoryStateEngine::new();
        // A fresh engine holds no native balance for this trader: a sell of
        // 10 base cannot lock its escrow.
        let err = dispatch(
            &engine,
            "stell_placeOrder",
            &json!({ "pair": 1, "side": "sell", "price": "250000", "amount": "10", "trader": hex::encode(addr(6)) }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn place_order_with_a_funded_trader_prepares() {
        let engine = InMemoryStateEngine::new();
        let trader = addr(6);
        engine
            .update_account(crate::state_engine::AccountState::new(trader, 1_000_000))
            .await;
        let v = dispatch(
            &engine,
            "stell_placeOrder",
            &json!({ "pair": 1, "side": "sell", "price": "250000", "amount": "10", "trader": hex::encode(trader) }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "place_order");
        assert_eq!(v["signer"]["address"], hex::encode(trader));
    }

    #[tokio::test]
    async fn cancel_order_of_an_unknown_id_fails_closed() {
        let engine = InMemoryStateEngine::new();
        let err = dispatch(&engine, "stell_cancelOrder", &json!({ "order_id": 7 }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32004);
    }

    #[tokio::test]
    async fn cancel_order_by_a_non_owner_is_refused() {
        let engine = InMemoryStateEngine::new();
        let owner = addr(4);
        {
            let mut books = engine.orderbooks_write().await;
            books.get_book_mut(1).submit_order(
                owner,
                crate::orderbook::OrderSide::Sell,
                250_000,
                10,
                0,
            );
        }
        let err = dispatch(
            &engine,
            "stell_cancelOrder",
            &json!({ "order_id": 1, "trader": hex::encode(addr(5)) }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn cancel_order_by_the_owner_prepares() {
        let engine = InMemoryStateEngine::new();
        let owner = addr(4);
        {
            let mut books = engine.orderbooks_write().await;
            books.get_book_mut(1).submit_order(
                owner,
                crate::orderbook::OrderSide::Sell,
                250_000,
                10,
                0,
            );
        }
        let v = dispatch(
            &engine,
            "stell_cancelOrder",
            &json!({ "order_id": 1, "trader": hex::encode(owner) }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "cancel_order");
        assert_eq!(v["transaction"]["op"], "SysCallCancelOrder");
        assert_eq!(v["transaction"]["args"]["order_id"], 1);
        assert_eq!(v["pair"], 1);
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
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
        let v = dispatch(&engine, "stell_sessionKeys", &json!({}))
            .await
            .unwrap();
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
        let v = dispatch(&engine, "stell_oracleFeeds", &json!({}))
            .await
            .unwrap();
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

    async fn engine_with_capped_token() -> (InMemoryStateEngine, [u8; 32]) {
        let engine = InMemoryStateEngine::new();
        let minter = addr(1);
        let mut m = meta("Capped", "CAP");
        m.max_supply = Some(1_000);
        let id = {
            let mut reg = TokenRegistry::new();
            let id = reg.create_token(minter, m, 900).unwrap();
            *engine.tokens_write().await = reg;
            id
        };
        (engine, id)
    }

    #[tokio::test]
    async fn token_mint_prepares_for_the_minter() {
        let (engine, id) = engine_with_capped_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "to": hex::encode(addr(2)),
                "amount": "100",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_mint");
        assert_eq!(v["transaction"]["op"], "SysCallTokenMint");
        assert_eq!(v["transaction"]["args"]["token_id"], hex::encode(id));
        assert_eq!(v["transaction"]["args"]["to"], hex::encode(addr(2)));
        assert_eq!(v["transaction"]["args"]["amount"], 100);
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        // The signer is pinned to the ledger minter, never the caller.
        assert_eq!(v["signer"]["address"], hex::encode(addr(1)));
        assert_eq!(v["minter"], hex::encode(addr(1)));
        assert_eq!(v["amount"], "100");
        assert_eq!(v["max_supply"], "1000");
    }

    #[tokio::test]
    async fn token_mint_with_matching_minter_param_prepares() {
        let (engine, id) = engine_with_capped_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "to": hex::encode(addr(2)),
                "amount": "10",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallTokenMint");
        // The `minter` spelling is accepted as an alias of `from`.
        let v = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "minter": hex::encode(addr(1)),
                "to": hex::encode(addr(2)),
                "amount": "10",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallTokenMint");
    }

    #[tokio::test]
    async fn token_mint_by_a_non_minter_fails_closed() {
        let (engine, id) = engine_with_capped_token().await;
        let err = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(9)),
                "to": hex::encode(addr(2)),
                "amount": "10",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_mint_beyond_the_cap_fails_closed() {
        let (engine, id) = engine_with_capped_token().await;
        // 900 + 101 > 1000: execution would revert with SupplyCapExceeded.
        let err = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "to": hex::encode(addr(2)),
                "amount": "101",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_mint_guards_mirror_the_transfer_guards() {
        let (engine, id) = engine_with_capped_token().await;
        // Zero amount.
        let err = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "to": hex::encode(addr(2)),
                "amount": "0",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Mint to the zero address.
        let err = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "to": hex::encode([0u8; 32]),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Paused token.
        {
            let mut reg = engine.tokens_write().await;
            reg.get_mut(&id).unwrap().metadata.paused = true;
        }
        let err = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "to": hex::encode(addr(2)),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Renounced minter: minting is irreversibly over.
        {
            let mut reg = engine.tokens_write().await;
            let t = reg.get_mut(&id).unwrap();
            t.metadata.paused = false;
            t.metadata.minter = crate::token::ZERO_ADDRESS;
        }
        let err = dispatch(
            &engine,
            "stell_tokenMint",
            &json!({
                "token": hex::encode(id),
                "to": hex::encode(addr(2)),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_burn_prepares_a_self_burn() {
        let (engine, id) = engine_with_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "amount": "400",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_burn");
        assert_eq!(v["transaction"]["op"], "SysCallTokenBurn");
        assert_eq!(v["transaction"]["args"]["token_id"], hex::encode(id));
        assert_eq!(v["transaction"]["args"]["from"], hex::encode(addr(1)));
        assert_eq!(v["transaction"]["args"]["amount"], 400);
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        assert_eq!(v["signer"]["address"], hex::encode(addr(1)));
        assert_eq!(v["balance_before"], "1000000");
        assert_eq!(v["total_supply"], "1000000");
    }

    #[tokio::test]
    async fn token_burn_guards_mirror_the_transfer_guards() {
        let (engine, id) = engine_with_token().await;
        // Beyond the holder's balance.
        let err = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(2)),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Zero amount.
        let err = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "amount": "0",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // The zero address holds nothing and burns nothing.
        let err = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode([0u8; 32]),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Paused token: burns are value movement and freeze with it.
        {
            let mut reg = engine.tokens_write().await;
            reg.get_mut(&id).unwrap().metadata.paused = true;
        }
        let err = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_burn_supports_the_minter_admin_path() {
        // The ledger's `burn` allows caller == from (self-burn) OR caller is
        // the minter (admin-burn); the prepare mirrors both, fail-closed.
        let (engine, id) = engine_with_token().await;
        // Fund a victim holding: minter(1) -> holder(2) 300.
        {
            let mut reg = engine.tokens_write().await;
            reg.execute(
                &id,
                addr(1),
                crate::token::TokenOp::Transfer {
                    to: addr(2),
                    amount: 300,
                },
            )
            .unwrap();
        }
        // Admin-burn: from = victim, signer = minter.
        let v = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(2)),
                "signer": hex::encode(addr(1)),
                "amount": "100",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_burn");
        assert_eq!(v["transaction"]["op"], "SysCallTokenBurn");
        assert_eq!(v["transaction"]["args"]["from"], hex::encode(addr(2)));
        assert_eq!(v["signer"]["address"], hex::encode(addr(1)));
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        // Inclusion under the minter key burns the victim's balance.
        {
            let mut reg = engine.tokens_write().await;
            reg.execute(
                &id,
                addr(1),
                crate::token::TokenOp::Burn {
                    from: addr(2),
                    amount: 100,
                },
            )
            .unwrap();
        }
        assert_eq!(engine.tokens_read().await.balance_of(&id, &addr(2)), 200);
        // The `caller` / `minter` spellings are accepted as aliases of `signer`.
        for key in ["caller", "minter"] {
            let v = dispatch(
                &engine,
                "stell_tokenBurn",
                &json!({
                    "token": hex::encode(id),
                    "from": hex::encode(addr(2)),
                    key: hex::encode(addr(1)),
                    "amount": "10",
                }),
            )
            .await
            .unwrap();
            assert_eq!(v["transaction"]["op"], "SysCallTokenBurn");
            assert_eq!(v["signer"]["address"], hex::encode(addr(1)));
        }
        // A third key is neither holder nor minter: nothing signable.
        let err = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(2)),
                "signer": hex::encode(addr(9)),
                "amount": "10",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Omitting `signer` keeps the self-burn default (signer == from).
        let v = dispatch(
            &engine,
            "stell_tokenBurn",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(2)),
                "amount": "10",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["signer"]["address"], hex::encode(addr(2)));
    }

    #[tokio::test]
    async fn token_approve_prepares_an_allowance_grant() {
        let (engine, id) = engine_with_token().await;
        let v = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(addr(1)),
                "spender": hex::encode(addr(2)),
                "amount": "500",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_approve");
        assert_eq!(v["transaction"]["op"], "SysCallTokenApprove");
        assert_eq!(v["transaction"]["args"]["token_id"], hex::encode(id));
        assert_eq!(v["transaction"]["args"]["spender"], hex::encode(addr(2)));
        assert_eq!(v["transaction"]["args"]["amount"], 500);
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        assert_eq!(v["signer"]["address"], hex::encode(addr(1)));
        assert_eq!(v["previous_allowance"], "0");
        // The `from` spelling is accepted as an alias of `owner`.
        let v = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "spender": hex::encode(addr(2)),
                "amount": "500",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallTokenApprove");
    }

    #[tokio::test]
    async fn token_approve_refuses_self_and_zero_spender() {
        let (engine, id) = engine_with_token().await;
        // Owner == spender: the ledger's SelfTransfer, surfaced early.
        let err = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(addr(1)),
                "spender": hex::encode(addr(1)),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
        // Zero spender: the ledger's ZeroAddress, surfaced early.
        let err = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(addr(1)),
                "spender": hex::encode([0u8; 32]),
                "amount": "1",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_approve_is_not_gated_on_pause_and_zero_revokes() {
        let (engine, id) = engine_with_token().await;
        {
            let mut reg = engine.tokens_write().await;
            reg.get_mut(&id).unwrap().metadata.paused = true;
        }
        // Approvals are allowance bookkeeping, not value movement (the same
        // rule the ledger pins): a paused token still grants, and amount
        // zero still revokes.
        let v = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(addr(1)),
                "spender": hex::encode(addr(2)),
                "amount": "500",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallTokenApprove");
        let v = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(addr(1)),
                "spender": hex::encode(addr(2)),
                "amount": "0",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["amount"], "0");
    }

    #[tokio::test]
    async fn token_approve_transfer_from_allowance_round_trip() {
        let (engine, id) = engine_with_token().await;
        let owner = addr(1);
        let spender = addr(2);
        let dest = addr(3);
        // 1. Approve prepare: the wallet's signable grant.
        let v = dispatch(
            &engine,
            "stell_tokenApprove",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(owner),
                "spender": hex::encode(spender),
                "amount": "500",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallTokenApprove");
        // 2. Inclusion (the prepare mutates nothing; the block does).
        {
            let mut reg = engine.tokens_write().await;
            reg.execute(
                &id,
                owner,
                crate::token::TokenOp::Approve {
                    spender,
                    amount: 500,
                },
            )
            .unwrap();
        }
        // 3. Allowance read shows the grant.
        let v = dispatch(
            &engine,
            "stell_tokenAllowance",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(owner),
                "spender": hex::encode(spender),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["allowance"], "500");
        // 4. Transfer-from prepare against that allowance.
        let v = dispatch(
            &engine,
            "stell_tokenTransferFrom",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(owner),
                "to": hex::encode(dest),
                "amount": "300",
                "spender": hex::encode(spender),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_transfer_from");
        assert_eq!(v["transaction"]["op"], "SysCallTokenTransferFrom");
        assert_eq!(v["transaction"]["args"]["from"], hex::encode(owner));
        assert_eq!(v["transaction"]["args"]["to"], hex::encode(dest));
        assert_eq!(v["transaction"]["args"]["amount"], 300);
        assert_eq!(v["signer"]["address"], hex::encode(spender));
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        assert_eq!(v["allowance_before"], "500");
        // 5. Inclusion consumes the allowance atomically.
        {
            let mut reg = engine.tokens_write().await;
            reg.execute(
                &id,
                spender,
                crate::token::TokenOp::TransferFrom {
                    from: owner,
                    to: dest,
                    amount: 300,
                },
            )
            .unwrap();
        }
        let v = dispatch(
            &engine,
            "stell_tokenAllowance",
            &json!({
                "token": hex::encode(id),
                "owner": hex::encode(owner),
                "spender": hex::encode(spender),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["allowance"], "200");
        let v = dispatch(
            &engine,
            "stell_tokenBalanceOf",
            &json!({ "token": hex::encode(id), "account": hex::encode(dest) }),
        )
        .await
        .unwrap();
        assert_eq!(v["balance"], "300");
        // 6. The remainder is spendable, a unit more is not.
        let err = dispatch(
            &engine,
            "stell_tokenTransferFrom",
            &json!({
                "token": hex::encode(id),
                "from": hex::encode(owner),
                "to": hex::encode(dest),
                "amount": "201",
                "spender": hex::encode(spender),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_transfer_from_guards_mirror_transfer_guards() {
        let (engine, id) = engine_with_token().await;
        {
            let mut reg = engine.tokens_write().await;
            reg.execute(
                &id,
                addr(1),
                crate::token::TokenOp::Approve {
                    spender: addr(2),
                    amount: 50,
                },
            )
            .unwrap();
        }
        let base = || {
            json!({
                "token": hex::encode(id),
                "from": hex::encode(addr(1)),
                "to": hex::encode(addr(3)),
                "amount": "10",
                "spender": hex::encode(addr(2)),
            })
        };
        // Zero amount.
        let mut bad = base();
        bad["amount"] = json!("0");
        assert_eq!(
            dispatch(&engine, "stell_tokenTransferFrom", &bad)
                .await
                .unwrap_err()
                .code(),
            -32003
        );
        // To the zero address.
        let mut bad = base();
        bad["to"] = json!(hex::encode([0u8; 32]));
        assert_eq!(
            dispatch(&engine, "stell_tokenTransferFrom", &bad)
                .await
                .unwrap_err()
                .code(),
            -32003
        );
        // To self.
        let mut bad = base();
        bad["to"] = json!(hex::encode(addr(1)));
        assert_eq!(
            dispatch(&engine, "stell_tokenTransferFrom", &bad)
                .await
                .unwrap_err()
                .code(),
            -32003
        );
        // Paused token.
        {
            let mut reg = engine.tokens_write().await;
            reg.get_mut(&id).unwrap().metadata.paused = true;
        }
        assert_eq!(
            dispatch(&engine, "stell_tokenTransferFrom", &base())
                .await
                .unwrap_err()
                .code(),
            -32003
        );
    }

    #[tokio::test]
    async fn token_create_prepares_and_mirrors_ledger_validation() {
        let engine = InMemoryStateEngine::new();
        let v = dispatch(
            &engine,
            "stell_tokenCreate",
            &json!({
                "creator": hex::encode(addr(9)),
                "name": "Tether USD",
                "symbol": "wUSDT",
                "decimals": 6,
                "initial_supply": "1000",
                "max_supply": "1000000",
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["action"], "token_create");
        assert_eq!(v["transaction"]["op"], "SysCallTokenCreate");
        assert_eq!(v["transaction"]["args"]["name"], "Tether USD");
        assert_eq!(v["transaction"]["args"]["symbol"], "wUSDT");
        assert_eq!(v["transaction"]["args"]["decimals"], 6);
        assert_eq!(v["transaction"]["args"]["initial_supply"], 1000);
        assert_eq!(v["transaction"]["args"]["max_supply"], 1000000);
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");
        assert_eq!(v["signer"]["address"], hex::encode(addr(9)));
        assert_eq!(v["creator"], hex::encode(addr(9)));
        // The id commits the registry nonce: not predictable, resolvable.
        assert!(v["note"].as_str().unwrap().contains("stell_tokenResolve"));
        // The `from` spelling is accepted as an alias of `creator`.
        let v = dispatch(
            &engine,
            "stell_tokenCreate",
            &json!({
                "from": hex::encode(addr(9)),
                "name": "T",
                "symbol": "T",
                "decimals": 6,
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["transaction"]["op"], "SysCallTokenCreate");
        assert!(v["transaction"]["args"]["max_supply"].is_null());
        assert_eq!(v["max_supply"], Value::Null);
        // Empty name: the ledger would revert with MetadataInvalid.
        let err = dispatch(
            &engine,
            "stell_tokenCreate",
            &json!({
                "creator": hex::encode(addr(9)),
                "name": "",
                "symbol": "T",
                "decimals": 6,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32602);
        // Decimals above 18: out of range.
        let err = dispatch(
            &engine,
            "stell_tokenCreate",
            &json!({
                "creator": hex::encode(addr(9)),
                "name": "T",
                "symbol": "T",
                "decimals": 19,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32602);
        // Initial supply above the cap: execution would revert.
        let err = dispatch(
            &engine,
            "stell_tokenCreate",
            &json!({
                "creator": hex::encode(addr(9)),
                "name": "T",
                "symbol": "T",
                "decimals": 6,
                "initial_supply": "1001",
                "max_supply": "1000",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), -32003);
    }

    #[tokio::test]
    async fn token_prepares_mutate_no_state() {
        let (engine, id) = engine_with_capped_token().await;
        let before_balance = {
            let reg = engine.tokens_read().await;
            let t = reg.get(&id).unwrap();
            (
                t.balance_of(&addr(1)),
                t.metadata.total_supply,
                t.allowance(&addr(1), &addr(2)),
            )
        };
        // Every prepare arm answers bytes, never state.
        for (method, params) in [
            (
                "stell_tokenTransfer",
                json!({"token": hex::encode(id), "from": hex::encode(addr(1)), "to": hex::encode(addr(2)), "amount": "10"}),
            ),
            (
                "stell_tokenMint",
                json!({"token": hex::encode(id), "to": hex::encode(addr(2)), "amount": "10"}),
            ),
            (
                "stell_tokenBurn",
                json!({"token": hex::encode(id), "from": hex::encode(addr(1)), "amount": "10"}),
            ),
            (
                "stell_tokenApprove",
                json!({"token": hex::encode(id), "owner": hex::encode(addr(1)), "spender": hex::encode(addr(2)), "amount": "10"}),
            ),
            (
                "stell_tokenCreate",
                json!({"creator": hex::encode(addr(9)), "name": "N", "symbol": "S", "decimals": 6}),
            ),
        ] {
            dispatch(&engine, method, &params).await.unwrap();
        }
        {
            let mut reg = engine.tokens_write().await;
            reg.execute(
                &id,
                addr(1),
                crate::token::TokenOp::Approve {
                    spender: addr(2),
                    amount: 50,
                },
            )
            .unwrap();
        }
        dispatch(
            &engine,
            "stell_tokenTransferFrom",
            &json!({"token": hex::encode(id), "from": hex::encode(addr(1)), "to": hex::encode(addr(2)), "amount": "10", "spender": hex::encode(addr(2))}),
        )
        .await
        .unwrap();
        let after_balance = {
            let reg = engine.tokens_read().await;
            let t = reg.get(&id).unwrap();
            (
                t.balance_of(&addr(1)),
                t.metadata.total_supply,
                t.allowance(&addr(1), &addr(2)),
            )
        };
        assert_eq!(
            before_balance.0, after_balance.0,
            "balance moved under a prepare"
        );
        assert_eq!(
            before_balance.1, after_balance.1,
            "supply moved under a prepare"
        );
        // The allowance moved only because the TEST executed an approve
        // directly (inclusion), never because a prepare wrote it.
        assert_eq!(after_balance.2, 50);
    }
}
