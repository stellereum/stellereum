//! JSON-RPC 2.0 API for wallets, block explorers and bots.
//!
//! Runs an axum HTTP server exposing a `/` endpoint that accepts standard
//! JSON-RPC requests (`{"jsonrpc":"2.0","id":..,"method":..,"params":{..}}`).
//!
//! Read methods never mutate state. The write methods (`sendRawTransaction`,
//! `submitPriceFeed`) only *validate and admit* a signed transaction into the
//! mempool — they cannot forge signatures, bypass nonce/balance rules (those
//! are enforced at execution) or write consensus state: a price feed becomes
//! state only when a block carries it.
//!
//! Streaming: the node also PUSHES chain events instead of forcing every
//! client to poll.
//!
//! * `stell_subscribe` / `stell_unsubscribe` register and drop a
//!   subscription (`newHeads`, `newTxs`, `invalidations`, `events`).
//! * `GET /ws` (WebSocket) carries the notifications, and speaks the same
//!   JSON-RPC dialect as `POST /`.
//! * `GET /events` (SSE, `text/event-stream`) is the fallback transport for
//!   browsers and proxies that cannot speak WebSocket.
//!
//! A notification is always `{"subscription": <id>, "result": {...}}`.
//!
//! Block invalidations (the "your view of these blocks was wrong" signal):
//!
//! * `stell_getInvalidations` serves the recent invalidation signals of
//!   this node from a BOUNDED ring buffer.
//! * The `invalidations` subscription topic streams them as they happen.
//!
//! The blocks named in a signal were NEVER applied (BFT finality forbids
//! rolling back an applied block), so the signal is a retraction notice for
//! indexers, wallets and light clients — not a state rollback.
//!
//! Auth-token coverage (audit 2026-10-14 F1 — the old header wrongly said the
//! send paths are "gated by the same API token"; they are not, by design):
//!
//! * OPEN submission (no token, even when one is configured): `stell_sendRawTransaction`
//!   and `eth_sendRawTransaction`. An unauthenticated caller can only submit a
//!   validly signed, funded, nonce-sane transaction (signature check, strict EVM
//!   verification, nonce-gap fail-fast, solvency + per-sender quota in the pool).
//!   The transaction authenticates itself; a token would add no authority. Spam is
//!   bounded by the per-IP limiters plus pool caps — see `router`/`serve`.
//! * GATED by `auth_token` (when `Some`): `stell_mempoolDump` (pending pool contents
//!   aid front-running), the `admit_signed_payload_tx` arms `stell_submitPriceFeed`,
//!   `stell_pmmBuy`, `stell_pmmSell`.
//!   Without a token configured these stay open (local/dev mode) — EXCEPT the
//!   governance writes and the contract previews below, which are fail-closed
//!   without a token on EVERY bind (N-02/N-03; see `require_gov_write_auth`).
//! * The governance writes `stell_submitProposal`, `stell_vote`,
//!   `stell_executeProposal` require a valid `auth_token` ALWAYS (N-02): no
//!   token configured, or a missing/invalid presented token, is refused with
//!   `-32001`, regardless of the `STELL_RPC_LISTEN` bind address. There is no
//!   loopback escape: a loopback bind is not proof of a loopback peer (the
//!   node sits behind proxies — nginx on the same host IS a loopback TCP
//!   peer while the real client is remote — and `X-Forwarded-For` is only
//!   trustworthy under `STELL_TRUSTED_PROXY_CIDRS`), so any bind- or
//!   peer-based exception would be a loopback illusion. `dispatch` DOES see
//!   the real client IP (`peer_ip` via `resolve_client_ip`/`ConnectInfo`),
//!   but the gate deliberately consults neither bind nor peer: token-always
//!   is strictly stronger and independent of proxy topology.
//!   `stell_sendRawTransaction` stays OPEN by design (self-authenticating
//!   signed txs — see the module docs).
//! * The contract previews `stell_deployContract` / `stell_callContract`
//!   require the same token (N-03) and NEVER enter the mempool: they execute
//!   on a state clone, return the result, and drop the transaction. State
//!   changes exclusively when a block applies a transaction submitted via
//!   `stell_sendRawTransaction`.
//! * The wallet SIGN arms `stell_signMessage`, `stell_signTypedData` are
//!   SEPARATELY fail-closed (GATE: H-02): they sign with an ephemeral dev-only
//!   key that exists only when explicit dev mode is on
//!   (`STELL_DEV_UNSAFE_TESTKEY=1`), and additionally require a configured
//!   `auth_token` presented by the caller plus a loopback peer. Otherwise they
//!   refuse. Production wallets sign locally and never ask a node to sign.
//! * GATED by the SEPARATE `faucet_token` (fail-closed — an enabled faucet with no
//!   token refuses to dispense): `stell_faucet` and the explorer `POST /api/faucet/:address`.
//!
//! Security:
//!  - params are size-bounded; malformed requests are rejected, never panic
//!  - `sendRawTransaction` / `submitPriceFeed` reject bad signatures before
//!    touching the mempool
//!  - unknown methods return a JSON-RPC error, not a crash

use axum::Json;
use serde_json::Value;

mod auth;
mod cache;
mod contracts;
mod eth;
mod faucet;
mod reads;
mod state;
mod streams;
mod writes;

#[cfg(test)]
mod tests;

pub use auth::*;
pub use cache::*;
use contracts::*;
pub(crate) use faucet::resolve_faucet_recipient;
pub use faucet::*;
pub use reads::*;
pub use state::*;
pub(crate) use streams::extract_header_token;
pub use streams::*;
use writes::*;

/// Dispatch a single RPC call to its handler.
/// `header_token` is a token presented in an HTTP header, if any. Write methods
/// accept the token either in `params` or in a header, so a caller does not have
/// to put a credential in the request body.
pub(super) async fn dispatch(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Json<RpcResponse> {
    if let Some(resp) = eth::dispatch_eth(st, id.clone(), method, params).await {
        return resp;
    }
    if let Some(resp) =
        contracts::dispatch_contracts(st, id.clone(), method, params, header_token).await
    {
        return resp;
    }
    if let Some(resp) =
        writes::dispatch_writes(st, id.clone(), method, params, header_token, peer_ip).await
    {
        return resp;
    }
    reads::dispatch_reads(st, id, method, params, header_token, peer_ip).await
}
