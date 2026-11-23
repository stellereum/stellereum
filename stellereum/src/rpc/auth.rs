use super::*;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Constant-time byte comparison, so comparing a caller-supplied secret against
/// the configured token does not leak its length/prefix through timing.
/// Both inputs are hashed with SHA-256 to a fixed 32-byte digest to prevent secret
/// length discovery and branch timing side-channels, and the digests are compared
/// in constant time.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    let mut diff = 0u8;
    for (&x, &y) in ha.iter().zip(hb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The EFFECTIVE value of an optional configured secret.
///
/// An empty or whitespace-only `STELL_RPC_AUTH_TOKEN` / `STELL_FAUCET_TOKEN`
/// is a misconfiguration (the common `TOKEN=$UNSET_VAR` compose expansion),
/// not a credential. Treating it as configured would make the empty string a
/// matchable password: every gate's `constant_time_eq("", "")` succeeds, so a
/// fail-closed gate (governance writes, wallet signing, faucet, mempool dump)
/// would open to any caller that sends `"token": ""`. Every consumer must
/// therefore go through this helper:
///
/// * `require_gov_write_auth` / `require_wallet_sign_auth` / faucet /
///   `mempoolDump` treat `None` as "not configured" and REFUSE (fail closed);
/// * the locally-open arms (`admit_signed_payload_tx` when no token is
///   configured) treat it exactly like an unset variable — no stronger than
///   the documented local/dev default, never a secret of "".
pub fn configured_secret(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.trim().is_empty())
}

// GATE: H-02 — SIGN arms are fail-closed without a configured `auth_token`
// (unlike the mempool/payload arms which stay open in local/dev mode). A
// dev signing key must never be anonymously reachable.
pub(super) fn require_wallet_sign_auth(
    st: &RpcState,
    id: &Value,
    params: &Value,
    header_token: Option<&str>,
) -> Option<Json<RpcResponse>> {
    let Some(expected) = configured_secret(st.auth_token.as_deref()) else {
        return Some(err(
            id.clone(),
            -32001,
            "unauthorized: message signing is disabled without STELL_RPC_AUTH_TOKEN \
             (devnet-only; production wallets must sign locally)",
        ));
    };
    let provided = params["token"]
        .as_str()
        .or_else(|| params["apiKey"].as_str())
        .or(header_token);
    if !provided
        .map(|p| constant_time_eq(p, expected))
        .unwrap_or(false)
    {
        return Some(err(
            id.clone(),
            -32001,
            "unauthorized: missing or invalid API token",
        ));
    }
    None
}

// GATE: H-02 — SIGN arms serve DIRECT loopback peers only (audit: "only on
// loopback"). `None` is the in-process test harness (production transports
// always resolve an address); any other client is refused. The provenance
// matters: a proxied request whose `X-Forwarded-For` claims loopback is
// `Forwarded`/`ForwardedLoopbackRejected` and is NEVER local, so handing the
// bare `IpAddr` here (which lost the source) used to let a remote caller
// reach the dev signing key through a same-host proxy.
pub(super) fn require_wallet_sign_loopback(
    id: &Value,
    client: Option<crate::client_ip::ClientIp>,
) -> Option<Json<RpcResponse>> {
    match client {
        None => None,
        Some(client) if client.is_local_client() => None,
        Some(_) => Some(err(
            id.clone(),
            -32001,
            "unauthorized: message signing is loopback-only (devnet-only)",
        )),
    }
}

// ============================================================================
// Governance-write auth gate (neural audit 2026-11-04 H-01/C-02, hardened
// N-02 2026-11-05).
//
// `stell_submitProposal` / `stell_vote` / `stell_executeProposal` mutate the
// committed staking/governance domains, so they require a valid `auth_token`
// ALWAYS — regardless of the `STELL_RPC_LISTEN` bind address. There is no
// loopback escape: an operator that publishes the RPC port without
// `STELL_RPC_AUTH_TOKEN` gets refusals, not open gov writes, on every bind
// including loopback. `stell_sendRawTransaction` stays OPEN by design
// (self-authenticating signed txs — see the module docs). No new env knob:
// the token is the existing `STELL_RPC_AUTH_TOKEN`.
//
// Why token-always instead of a real-client (peer-IP) check: `dispatch`
// DOES see the peer (`peer_ip`, resolved via `crate::client_ip` / axum
// `ConnectInfo`), so a peer-loopback exception would be implementable
// without framework surgery — but it would still be wrong. The node sits
// behind reverse proxies (nginx on the same host is a loopback TCP peer
// while the real client is remote), so a loopback peer is not proof of a
// local caller; trusting `X-Forwarded-For` instead leans on
// `STELL_TRUSTED_PROXY_CIDRS` configuration. A token is independent of
// proxy topology, so the gate consults neither bind nor peer.
// ============================================================================

/// Pure loopback check over a bind string (`STELL_RPC_LISTEN` form, e.g.
/// `127.0.0.1:8545`, `localhost:8545`, `[::1]:8545`, bare `::1`). Anything
/// that is not provably loopback — `0.0.0.0`, LAN/WAN IPs, other hostnames,
/// unparseable input — answers `false` (fail closed).
pub(super) fn bind_addr_is_loopback(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    // Otherwise expect `host:port` (or `[v6]:port`); what remains after
    // stripping the port must itself be loopback. A `[` without `]` is
    // malformed (could never bind) — fail closed.
    let host = if addr.starts_with('[') {
        if !addr.contains(']') {
            return false;
        }
        addr.strip_prefix('[')
            .and_then(|h| h.split(']').next())
            .unwrap_or(addr)
    } else {
        match addr.rsplit_once(':') {
            // A non-numeric tail is a bare hostname, not `host:port`.
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => addr,
        }
    };
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    matches!(host.parse::<std::net::IpAddr>(), Ok(ip) if ip.is_loopback())
}

/// Effective bind loopback-ness for the unsigned-dev-test escape below: the
/// existing `STELL_RPC_LISTEN`, defaulting to loopback when unset (local/dev).
/// N-02: the gov-write/preview token gate NO LONGER consults this — a token
/// is required on every bind. Only the explicit
/// `STELL_DEV_UNSAFE_TESTKEY=1` dev-test escape still checks the bind.
pub(super) fn rpc_bind_is_loopback() -> bool {
    #[cfg(test)]
    if let Some(v) = test_bind_loopback_override() {
        return v;
    }
    match std::env::var("STELL_RPC_LISTEN") {
        Err(_) => true,
        Ok(s) => bind_addr_is_loopback(&s),
    }
}

#[cfg(test)]
pub(super) static TEST_BIND_LOOPBACK: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

/// Test-only mock for the bind check ("mock bind"): `Some(v)` forces the
/// gate's view of the bind, `None` restores the env/default path. A mutex
/// (not the env) so parallel tests cannot disturb each other.
#[cfg(test)]
pub(crate) fn set_test_bind_loopback(v: Option<bool>) {
    *TEST_BIND_LOOPBACK.lock().unwrap() = v;
}

#[cfg(test)]
pub(super) fn test_bind_loopback_override() -> Option<bool> {
    *TEST_BIND_LOOPBACK.lock().unwrap()
}

/// Fail-closed gate for the three governance WRITE arms (N-02) and the two
/// contract PREVIEW arms (N-03). Returns `Some(err)` when the call must be
/// refused: a valid token is required ALWAYS.
///
/// Token configured: the caller must present it (unchanged). No token
/// configured: REFUSE on every bind, loopback included (N-02: the old
/// loopback escape is deleted; configure `STELL_RPC_AUTH_TOKEN`).
///
/// The gate deliberately consults neither the bind address nor the peer IP
/// (see the section comment above): a loopback bind/peer is not proof of a
/// local caller behind a proxy, so any such exception would be spoofable.
pub(super) fn require_gov_write_auth(
    st: &RpcState,
    id: &Value,
    params: &Value,
    header_token: Option<&str>,
) -> Option<Json<RpcResponse>> {
    let Some(expected) = configured_secret(st.auth_token.as_deref()) else {
        return Some(err(
            id.clone(),
            -32001,
            "unauthorized: this method requires STELL_RPC_AUTH_TOKEN (fail-closed without a token on every bind, loopback included; configure STELL_RPC_AUTH_TOKEN and present it as `token`, `apiKey`, or header)",
        ));
    };
    let provided = params["token"]
        .as_str()
        .or_else(|| params["apiKey"].as_str())
        .or(header_token);
    if !provided
        .map(|p| constant_time_eq(p, expected))
        .unwrap_or(false)
    {
        return Some(err(
            id.clone(),
            -32001,
            "unauthorized: missing or invalid API token",
        ));
    }
    None
}

/// Bumped write guard for the shared governance object (C-01 staleness half).
///
/// In production `st.governance` aliases the engine's committed governance
/// (same `Arc`), so the write must go through `engine.governance_write()` —
/// a bare `Arc` write skips the commitment-generation bump and the state root
/// goes stale. Test fixtures keep a detached governance object, so fall back
/// to the direct lock when the handles do not alias (zero behavior change
/// there). // GATE: C-01 staleness fix; prod path bumped, test path untouched.
pub(super) async fn gov_write(
    st: &RpcState,
) -> tokio::sync::RwLockWriteGuard<'_, crate::governance::Governance> {
    if Arc::ptr_eq(&st.governance, &st.engine.governance_handle()) {
        st.engine.governance_write().await
    } else {
        st.governance.write().await
    }
}

/// Single-node write guard for the DIRECT governance-mutation RPC paths
/// (`stell_submitProposal` / `stell_vote` / `stell_executeProposal` without
/// a `tx`: they mutate governance state in this process only).
///
/// Returns the refusal body when a local-only mutation would fork a
/// multi-node deployment (`validator_count > 1` without the documented
/// escape env, default OFF); `None` on solo sets (no peer to diverge from)
/// or when the escape is explicitly armed. The count is the ELECTED set
/// derived from the engine's committed staking ledger — the same
/// `ValidatorSet::len` the runtime gates on, read from the same ledger the
/// direct paths mutate (never the detached `st.staking` fixture handle).
///
/// Call FIRST in the direct form — before parsing, locks, or lookups — so a
/// multi-node write is refused as multi-node, never as some downstream
/// error (same gate-first discipline as the runtime `gov_propose` /
/// `gov_vote`). The block-carried `tx` forms NEVER call this: admitting a
/// caller-signed transaction mutates nothing, so multi-node nodes admit
/// freely (that is how multi-node governance works now) and diverge never.
pub(super) async fn multinode_gov_write_refusal(st: &RpcState) -> Option<String> {
    let n = st.engine.staking_read().await.to_validator_set().len();
    crate::governance::governance_write_allowed_from_env(n).err()
}

/// Loopback-dev escape for UNSIGNED gov writes: ONLY when the existing
/// dev-test flag is armed (`STELL_DEV_UNSAFE_TESTKEY=1`, the same flag the
/// wallet SIGN arms and the faucet test key use) AND the bind is loopback.
/// No new env knob is introduced: without the flag, an unsigned proposal or
/// vote is refused fail-closed on every bind (including loopback).
pub(super) fn gov_unsigned_dev_escape() -> bool {
    is_dev_unsafe_testkey_env() && rpc_bind_is_loopback()
}

/// Effective chain id for a wallet-signing call: explicit `chain_id` wins,
/// otherwise the node's own chain id. The preimage is ALWAYS rebuilt with this
/// value on both sign and verify, so a signature minted for one chain never
/// verifies on another.
pub(super) fn wallet_sign_chain_id(st: &RpcState, params: &Value) -> Result<u64, String> {
    match params.get("chain_id") {
        None | Some(Value::Null) => Ok(st.chain_id),
        Some(v) => {
            crate::wallet_signing::parse_u64_param(v).map_err(|e| format!("bad chain_id: {e}"))
        }
    }
}

/// Parse the shared typed-data params into a [`crate::wallet_signing::TypedCallData`].
pub(super) fn parse_typed_data_params(
    params: &Value,
    default_chain_id: u64,
) -> Result<crate::wallet_signing::TypedCallData, String> {
    let contract_str = params
        .get("contract")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing contract (32-byte hex)".to_string())?;
    let contract = parse_addr_or_hash(contract_str).map_err(|e| format!("bad contract: {e}"))?;
    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing method".to_string())?;
    let args = params.get("args").cloned().unwrap_or(Value::Null);
    let value = match params.get("value") {
        None | Some(Value::Null) => 0,
        Some(v) => {
            crate::wallet_signing::parse_u64_param(v).map_err(|e| format!("bad value: {e}"))?
        }
    };
    let nonce = match params.get("nonce") {
        None | Some(Value::Null) => 0,
        Some(v) => {
            crate::wallet_signing::parse_u64_param(v).map_err(|e| format!("bad nonce: {e}"))?
        }
    };
    let chain_id = match params.get("chain_id") {
        None | Some(Value::Null) => default_chain_id,
        Some(v) => {
            crate::wallet_signing::parse_u64_param(v).map_err(|e| format!("bad chain_id: {e}"))?
        }
    };
    crate::wallet_signing::TypedCallData::new(&contract, method, args, value, nonce, chain_id)
}

pub(super) fn handle_sign_message(
    st: &RpcState,
    id: Value,
    params: &Value,
    header_token: Option<&str>,
    client: Option<crate::client_ip::ClientIp>,
) -> Json<RpcResponse> {
    if let Some(denied) = require_wallet_sign_auth(st, &id, params, header_token) {
        return denied;
    }
    if let Some(denied) = require_wallet_sign_loopback(&id, client) {
        return denied;
    }
    let Some(seed) = st.msg_signing_seed else {
        return err(
            id,
            -32000,
            "message signing is not configured on this node (devnet-only; \
             production wallets must sign locally, never ask a node to sign)",
        );
    };
    let chain_id = match wallet_sign_chain_id(st, params) {
        Ok(c) => c,
        Err(e) => return err(id, -32602, e),
    };
    let message = match crate::wallet_signing::parse_message_param(
        params.get("message").and_then(|v| v.as_str()),
        params.get("message_hex").and_then(|v| v.as_str()),
    ) {
        Ok(m) => m,
        Err(e) => return err(id, -32602, e),
    };
    // FULL-PQ: the node's dev-mode message signer is Falcon-512, derived
    // deterministically from the configured seed. There is no classical
    // Ed25519 arm left to fall back to.
    let key = crate::wallet_signing::WalletSigningKey::falcon_from_seed(&seed);
    let sig = match key.sign_message(chain_id, &message) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, e),
    };
    ok(
        id,
        json!({
            "address": hex::encode(key.address()),
            "scheme": sig.scheme.name(),
            "scheme_id": sig.scheme.id(),
            "signature": sig.to_hex(),
            "preimage": hex::encode(crate::wallet_signing::message_preimage(chain_id, &message)),
            "chain_id": chain_id,
        }),
    )
}

pub(super) fn handle_verify_message(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
    let address = match params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing address".to_string())
        .and_then(parse_hash)
    {
        Ok(a) => a,
        Err(e) => return err(id, -32602, e),
    };
    let chain_id = match wallet_sign_chain_id(st, params) {
        Ok(c) => c,
        Err(e) => return err(id, -32602, e),
    };
    let message = match crate::wallet_signing::parse_message_param(
        params.get("message").and_then(|v| v.as_str()),
        params.get("message_hex").and_then(|v| v.as_str()),
    ) {
        Ok(m) => m,
        Err(e) => return err(id, -32602, e),
    };
    let sig = match params
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing signature (standard envelope hex)".to_string())
        .and_then(|s| {
            crate::wallet_signing::WalletSignature::from_hex(s).map_err(|e| e.to_string())
        }) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, format!("bad signature envelope: {e}")),
    };
    let valid = crate::wallet_signing::verify_message(&address, chain_id, &message, &sig);
    ok(
        id,
        json!({
            "valid": valid,
            "address": hex::encode(address),
            "scheme": sig.scheme.name(),
            "scheme_id": sig.scheme.id(),
            "chain_id": chain_id,
        }),
    )
}

pub(super) fn handle_sign_typed_data(
    st: &RpcState,
    id: Value,
    params: &Value,
    header_token: Option<&str>,
    client: Option<crate::client_ip::ClientIp>,
) -> Json<RpcResponse> {
    if let Some(denied) = require_wallet_sign_auth(st, &id, params, header_token) {
        return denied;
    }
    if let Some(denied) = require_wallet_sign_loopback(&id, client) {
        return denied;
    }
    let Some(seed) = st.msg_signing_seed else {
        return err(
            id,
            -32000,
            "message signing is not configured on this node (devnet-only; \
             production wallets must sign locally, never ask a node to sign)",
        );
    };
    let data = match parse_typed_data_params(params, st.chain_id) {
        Ok(d) => d,
        Err(e) => return err(id, -32602, e),
    };
    // FULL-PQ: node-side typed-data signing is Falcon-512 only (see
    // `handle_sign_message`).
    let key = crate::wallet_signing::WalletSigningKey::falcon_from_seed(&seed);
    let (sig, canonical) = match key.sign_typed_data(&data) {
        Ok(r) => r,
        Err(e) => return err(id, -32602, e),
    };
    let chain_id = data.chain_id_u64().unwrap_or(st.chain_id);
    ok(
        id,
        json!({
            "address": hex::encode(key.address()),
            "scheme": sig.scheme.name(),
            "scheme_id": sig.scheme.id(),
            "signature": sig.to_hex(),
            "canonical": canonical,
            "chain_id": chain_id,
        }),
    )
}

pub(super) fn handle_verify_typed_data(
    st: &RpcState,
    id: Value,
    params: &Value,
) -> Json<RpcResponse> {
    let address = match params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing address".to_string())
        .and_then(parse_hash)
    {
        Ok(a) => a,
        Err(e) => return err(id, -32602, e),
    };
    // For verify the chain id comes from the STRUCTURED data itself (it is
    // part of what was signed and displayed); absent, the node's chain id is
    // assumed — the same default the SIGN arm uses.
    let data = match parse_typed_data_params(params, st.chain_id) {
        Ok(d) => d,
        Err(e) => return err(id, -32602, e),
    };
    let sig = match params
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing signature (standard envelope hex)".to_string())
        .and_then(|s| {
            crate::wallet_signing::WalletSignature::from_hex(s).map_err(|e| e.to_string())
        }) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, format!("bad signature envelope: {e}")),
    };
    let valid = crate::wallet_signing::verify_typed_data(&address, &data, &sig);
    ok(
        id,
        json!({
            "valid": valid,
            "address": hex::encode(address),
            "scheme": sig.scheme.name(),
            "scheme_id": sig.scheme.id(),
            "canonical": crate::wallet_signing::canonical_typed_data_json(&data),
        }),
    )
}
