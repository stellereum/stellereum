//! Synchronous JSON-RPC client for the node's `stell_*` surface.
//!
//! Method names and parameter/result shapes are pinned to
//! `stellereum/src/rpc/reads.rs` and `stellereum/src/rpc/writes.rs`; each
//! typed helper cites its dispatch arm. The client is deliberately
//! synchronous (`ureq`) so a wallet binary does not need a tokio runtime.
//!
//! # Retry contract
//!
//! [`RpcClient::send_with_retry`] takes an already-signed [`SignedTx`] and
//! resends the SAME bytes. It never rebuilds, re-prices or re-signs, so a
//! retry can never consume a second nonce or produce a second transaction.
//! A node answer "already in mempool" is treated as success because the
//! caller's goal (the transaction is pooled) is already true.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Result, RpcErrorBody, SdkError};
use crate::tx::SignedTx;

/// A pending/committed transaction receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: String,
    pub height: u64,
    pub block_hash: String,
    pub index: u64,
    pub status: String,
    pub gas_limit: u64,
    pub fee_charged: u64,
    pub confirmations: u64,
    #[serde(default)]
    pub contract_address: Option<String>,
    #[serde(default)]
    pub return_value: Option<Value>,
    #[serde(default)]
    pub gas_used: Option<u64>,
    #[serde(default)]
    pub events: Vec<Value>,
}

impl Receipt {
    /// `true` for a committed success.
    pub fn succeeded(&self) -> bool {
        self.status.eq_ignore_ascii_case("success")
    }
}

/// Account view served by `stell_getBalance`
/// (`stellereum/src/rpc/reads.rs:1404-1416`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}

/// Block summary served by `stell_getBlock`
/// (`stellereum/src/rpc/reads.rs:1197-1268`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub hash: String,
    pub txs: u64,
    pub timestamp: u64,
}

/// Validator set served by `stell_getValidators`
/// (`stellereum/src/rpc/reads.rs:2168-2198`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub validator: String,
    pub power: u64,
}

/// Fee answer from `stell_estimateFee`
/// (`stellereum/src/rpc/reads.rs:295-420, 528-545`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeEstimate {
    pub gas_limit: u64,
    pub estimated_fee: u64,
    pub base_fee: u64,
    pub source_shard: u32,
    pub target_shard: u32,
    pub is_cross_shard: bool,
    pub gas_budget: Option<u64>,
    pub gas_ceiling: Option<u64>,
}

/// Result of a submission, including whether a retry hit the node's
/// "already in mempool" answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitOutcome {
    pub tx_hash: String,
    pub attempts: u32,
    pub already_in_mempool: bool,
}

/// Retry policy for submission. Backoff is exponential and capped.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
        }
    }
}

/// A `stell_*` JSON-RPC client.
#[derive(Clone)]
pub struct RpcClient {
    url: String,
    agent: ureq::Agent,
    headers: Vec<(String, String)>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient").field("url", &self.url).finish()
    }
}

impl RpcClient {
    /// Build a client with a 15-second per-request timeout.
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_timeout(url, Duration::from_secs(15))
    }

    /// Build a client with an explicit timeout.
    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        Self {
            url: url.into(),
            agent,
            headers: Vec::new(),
        }
    }

    /// Add a static HTTP header (for example a bearer token for a
    /// token-gated deployment).
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The configured endpoint.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// One raw JSON-RPC call. `params` may be an object or an array.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut req = self.agent.post(&self.url);
        for (k, v) in &self.headers {
            req = req.set(k, v);
        }
        let response = match req.send_json(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                // A JSON-RPC error can arrive with a non-2xx status. Parse it
                // first; only a non-JSON body becomes a transport failure.
                let retryable = code == 408 || code == 429 || code >= 500;
                match r.into_json::<Value>() {
                    Ok(v) => return Self::parse_response(method, v),
                    Err(_) => {
                        return Err(SdkError::Transport {
                            method: method.to_string(),
                            message: format!("HTTP {code}"),
                            retryable,
                        })
                    }
                }
            }
            Err(ureq::Error::Transport(e)) => {
                return Err(SdkError::Transport {
                    method: method.to_string(),
                    message: e.to_string(),
                    // Connection reset/timeout means the request MAY have
                    // landed; resending identical bytes is safe.
                    retryable: true,
                });
            }
        };
        let v: Value = response
            .into_json()
            .map_err(|e| SdkError::Decode(format!("{method}: invalid JSON: {e}")))?;
        Self::parse_response(method, v)
    }

    fn parse_response(method: &str, v: Value) -> Result<Value> {
        if let Some(err) = v.get("error") {
            let body: RpcErrorBody = serde_json::from_value(err.clone())
                .map_err(|e| SdkError::Decode(format!("{method}: bad error object: {e}")))?;
            return Err(map_rpc_error(method, body));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| SdkError::Decode(format!("{method}: response has no result")))
    }

    /// `stell_chainId` -> chain id (`reads.rs:1072`).
    pub fn chain_id(&self) -> Result<u64> {
        parse_u64(&self.call("stell_chainId", json!([]))?)
            .ok_or_else(|| SdkError::Decode("stell_chainId: not a u64".into()))
    }

    /// `stell_getBalance` -> `{ balance, nonce }` (`reads.rs:1404`).
    pub fn account(&self, address: &[u8; 32]) -> Result<Account> {
        let v = self.call("stell_getBalance", json!([crate::address::to_hex(address)]))?;
        Ok(Account {
            balance: v
                .get("balance")
                .and_then(parse_u64)
                .ok_or_else(|| SdkError::Decode("stell_getBalance: bad balance".into()))?,
            nonce: v
                .get("nonce")
                .and_then(parse_u64)
                .ok_or_else(|| SdkError::Decode("stell_getBalance: bad nonce".into()))?,
        })
    }

    /// Balance only.
    pub fn balance(&self, address: &[u8; 32]) -> Result<u64> {
        Ok(self.account(address)?.balance)
    }

    /// Current account nonce.
    pub fn nonce(&self, address: &[u8; 32]) -> Result<u64> {
        Ok(self.account(address)?.nonce)
    }

    /// `stell_baseFee` -> the node's current admission base floor
    /// (`reads.rs:2355-2358`). The D2 failure penalty is per-sender and is
    /// only included by `stell_estimateFee`.
    pub fn base_fee(&self) -> Result<u64> {
        let v = self.call("stell_baseFee", json!([]))?;
        v.get("base_fee")
            .and_then(parse_u64)
            .ok_or_else(|| SdkError::Decode("stell_baseFee: bad base_fee".into()))
    }

    /// `stell_getValidators` (`reads.rs:2168`).
    pub fn validators(&self) -> Result<Vec<Validator>> {
        let v = self.call("stell_getValidators", json!([]))?;
        let list = v
            .get("validators")
            .and_then(Value::as_array)
            .ok_or_else(|| SdkError::Decode("stell_getValidators: missing list".into()))?;
        list.iter()
            .map(|x| {
                Ok(Validator {
                    validator: x
                        .get("validator")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            SdkError::Decode("stell_getValidators: bad validator".into())
                        })?
                        .to_string(),
                    power: x
                        .get("power")
                        .and_then(parse_u64)
                        .ok_or_else(|| SdkError::Decode("stell_getValidators: bad power".into()))?,
                })
            })
            .collect()
    }

    /// `stell_getBlock` for one height (`reads.rs:1197`).
    pub fn block(&self, height: u64) -> Result<Block> {
        let v = self.call("stell_getBlock", json!({ "height": height }))?;
        Ok(Block {
            height: v
                .get("height")
                .and_then(parse_u64)
                .ok_or_else(|| SdkError::Decode("stell_getBlock: bad height".into()))?,
            hash: v
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| SdkError::Decode("stell_getBlock: bad hash".into()))?
                .to_string(),
            txs: v.get("txs").and_then(parse_u64).unwrap_or(0),
            timestamp: v.get("timestamp").and_then(parse_u64).unwrap_or(0),
        })
    }

    /// Latest block number (`stell_blockNumber`, `reads.rs:1075`).
    pub fn block_number(&self) -> Result<u64> {
        parse_u64(&self.call("stell_blockNumber", json!([]))?)
            .ok_or_else(|| SdkError::Decode("stell_blockNumber: not a u64".into()))
    }

    /// `stell_getTransactionReceipt` (`reads.rs:1852-1943`).
    ///
    /// Returns `Ok(None)` for a hash the node reports as `pending` or
    /// `unknown`; committed receipts (including failed ones) are `Some`.
    pub fn receipt(&self, tx_hash_hex: &str) -> Result<Option<Receipt>> {
        let v = self.call(
            "stell_getTransactionReceipt",
            json!({ "hash": tx_hash_hex }),
        )?;
        match v.get("status").and_then(Value::as_str) {
            Some(s) if s.eq_ignore_ascii_case("pending") || s.eq_ignore_ascii_case("unknown") => {
                Ok(None)
            }
            _ => {
                let r: Receipt = serde_json::from_value(v)
                    .map_err(|e| SdkError::Decode(format!("receipt: {e}")))?;
                Ok(Some(r))
            }
        }
    }

    /// `stell_getTransactionStatus` (`reads.rs:2057`).
    pub fn transaction_status(&self, tx_hash_hex: &str) -> Result<Value> {
        self.call("stell_getTransactionStatus", json!({ "hash": tx_hash_hex }))
    }

    /// `stell_estimateFee` with the exact `{ "tx": <hex> }` shape the
    /// raw-transaction arm accepts (`reads.rs:327-342`).
    pub fn estimate_fee(&self, signed: &SignedTx) -> Result<FeeEstimate> {
        let v = self.call("stell_estimateFee", json!({ "tx": signed.to_hex() }))?;
        Ok(FeeEstimate {
            gas_limit: v
                .get("gas_limit")
                .and_then(parse_u64)
                .ok_or_else(|| SdkError::Decode("estimateFee: gas_limit".into()))?,
            estimated_fee: v
                .get("estimated_fee")
                .and_then(parse_u64)
                .ok_or_else(|| SdkError::Decode("estimateFee: estimated_fee".into()))?,
            base_fee: v
                .get("base_fee")
                .and_then(parse_u64)
                .ok_or_else(|| SdkError::Decode("estimateFee: base_fee".into()))?,
            source_shard: v.get("source_shard").and_then(parse_u64).unwrap_or(0) as u32,
            target_shard: v.get("target_shard").and_then(parse_u64).unwrap_or(0) as u32,
            is_cross_shard: v
                .get("is_cross_shard")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            gas_budget: v.get("gas_budget").and_then(parse_u64),
            gas_ceiling: v.get("gas_ceiling").and_then(parse_u64),
        })
    }

    /// `stell_sendRawTransaction` with `{ "tx": <hex> }`
    /// (`writes.rs:695-751`). Returns the node's hex transaction hash.
    pub fn send_raw(&self, signed: &SignedTx) -> Result<String> {
        let v = self.call("stell_sendRawTransaction", json!({ "tx": signed.to_hex() }))?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| SdkError::Decode("sendRawTransaction: result is not a string".into()))
    }

    /// Send a pre-encoded transaction hex (advanced use).
    pub fn send_raw_hex(&self, hex_tx: &str) -> Result<String> {
        let v = self.call("stell_sendRawTransaction", json!({ "tx": hex_tx }))?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| SdkError::Decode("sendRawTransaction: result is not a string".into()))
    }

    /// Submit with retries. The `signed` bytes are immutable across attempts.
    ///
    /// * retryable transport failures are retried with exponential backoff;
    /// * `rejected: transaction already in mempool` is success;
    /// * every other node rejection is returned immediately (retrying cannot
    ///   fix a bad signature, fee or nonce).
    pub fn send_with_retry(
        &self,
        signed: &SignedTx,
        policy: &RetryPolicy,
    ) -> Result<SubmitOutcome> {
        let mut backoff = policy.initial_backoff;
        let mut last = String::new();
        for attempt in 1..=policy.max_attempts.max(1) {
            match self.send_raw(signed) {
                Ok(hash) => {
                    return Ok(SubmitOutcome {
                        tx_hash: hash,
                        attempts: attempt,
                        already_in_mempool: false,
                    })
                }
                Err(e) if e.is_duplicate_submission() => {
                    return Ok(SubmitOutcome {
                        // The node's duplicate answer carries no hash; the hash
                        // is a pure function of the signed bytes we sent.
                        tx_hash: signed.tx_hash_hex(),
                        attempts: attempt,
                        already_in_mempool: true,
                    });
                }
                Err(e) if e.is_retryable() => {
                    last = e.to_string();
                    if attempt < policy.max_attempts {
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(policy.max_backoff);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(SdkError::RetryExhausted {
            attempts: policy.max_attempts,
            last,
        })
    }

    /// Poll `stell_getTransactionReceipt` until a committed receipt appears or
    /// the deadline passes.
    pub fn wait_for_receipt(
        &self,
        tx_hash_hex: &str,
        timeout: Duration,
        poll: Duration,
    ) -> Result<Receipt> {
        let started = std::time::Instant::now();
        loop {
            if let Some(r) = self.receipt(tx_hash_hex)? {
                return Ok(r);
            }
            if started.elapsed() >= timeout {
                return Err(SdkError::NotFound(tx_hash_hex.to_string()));
            }
            std::thread::sleep(poll.min(timeout.saturating_sub(started.elapsed())));
        }
    }

    /// Submit (with retries) and wait for the committed receipt.
    pub fn send_and_wait(
        &self,
        signed: &SignedTx,
        policy: &RetryPolicy,
        timeout: Duration,
        poll: Duration,
    ) -> Result<(SubmitOutcome, Receipt)> {
        let outcome = self.send_with_retry(signed, policy)?;
        let receipt = self.wait_for_receipt(&outcome.tx_hash, timeout, poll)?;
        Ok((outcome, receipt))
    }

    /// Raw `stell_getPqKey` lookup (`reads.rs:2200`).
    pub fn pq_key(&self, validator_hex: &str) -> Result<Value> {
        self.call("stell_getPqKey", json!({ "validator": validator_hex }))
    }
}

fn parse_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

fn map_rpc_error(method: &str, body: RpcErrorBody) -> SdkError {
    let m = &body.message;
    if let Some(rest) = m.split("nonce gap: sender can execute ").nth(1) {
        // "nonce gap: sender can execute 7, got 9 (...)"
        let mut parts = rest.split(',');
        if let (Some(expected), Some(got)) = (parts.next(), parts.next()) {
            let expected = expected.trim().parse::<u64>();
            let got = got
                .trim()
                .strip_prefix("got ")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok());
            if let (Ok(expected), Some(got)) = (expected, got) {
                return SdkError::NonceGap { expected, got };
            }
        }
    }
    SdkError::Rpc {
        method: method.to_string(),
        code: body.code,
        message: body.message,
        data: body.data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_and_number_u64() {
        assert_eq!(parse_u64(&json!("280000")), Some(280_000));
        assert_eq!(parse_u64(&json!(280000)), Some(280_000));
    }

    #[test]
    fn nonce_gap_is_typed() {
        let e = map_rpc_error(
            "stell_sendRawTransaction",
            RpcErrorBody {
                code: -32000,
                message: "rejected: nonce gap: sender can execute 7, got 9 (fill the gap first)"
                    .into(),
                data: None,
            },
        );
        assert_eq!(
            e,
            SdkError::NonceGap {
                expected: 7,
                got: 9
            }
        );
    }
}
