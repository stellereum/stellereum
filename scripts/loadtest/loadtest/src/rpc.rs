//! Minimal JSON-RPC 2.0 client for the node's real dialect.
//!
//! Only methods the node actually implements are used:
//!
//! * writes: `stell_sendRawTransaction`
//! * reads: `stell_chainId`, `eth_chainId`, `stell_blockNumber`,
//!   `stell_baseFee`, `stell_getBalance`, `stell_latestBlocks`,
//!   `stell_getBlock`, `stell_getValidators`, `stell_mempoolSize`,
//!   `stell_getTransactionStatus`, `stell_getTransactionReceipt`.
//!
//! Transport retries are offered here, but the harness NEVER retries a write
//! with new bytes: the sender caches the exact signed wire bytes for a nonce
//! and resends those bytes, so a retry can only be an idempotent duplicate.

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum RpcError {
    Transport(String),
    Http(u16, String),
    Rpc { code: i64, message: String },
    Shape(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "transport: {m}"),
            Self::Http(code, body) => write!(f, "http {code}: {}", truncate(body, 300)),
            Self::Rpc { code, message } => write!(f, "rpc {code}: {message}"),
            Self::Shape(m) => write!(f, "shape: {m}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<RpcError> for String {
    fn from(e: RpcError) -> Self {
        e.to_string()
    }
}

impl RpcError {
    pub fn retryable(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::Http(code, _) => *code == 408 || *code == 429 || (500..=599).contains(code),
            Self::Rpc { message, .. } => message.to_ascii_lowercase().contains("rate limit"),
            Self::Shape(_) => false,
        }
    }

    pub fn is_duplicate(&self) -> bool {
        match self {
            Self::Rpc { message, .. } => {
                let m = message.to_ascii_lowercase();
                m.contains("already in mempool") || m.contains("duplicate")
            }
            _ => false,
        }
    }

    pub fn is_bad_signature(&self) -> bool {
        match self {
            Self::Rpc { message, .. } => {
                let m = message.to_ascii_lowercase();
                m.contains("invalid transaction signature") || m.contains("bad signature")
            }
            _ => false,
        }
    }

    pub fn is_fee_too_low(&self) -> bool {
        match self {
            Self::Rpc { message, .. } => {
                let m = message.to_ascii_lowercase();
                m.contains("below the base fee") || m.contains("fee too low")
            }
            _ => false,
        }
    }

    pub fn is_insufficient_balance(&self) -> bool {
        match self {
            Self::Rpc { message, .. } => {
                let m = message.to_ascii_lowercase();
                m.contains("cannot pay amount") || m.contains("insufficient balance")
            }
            _ => false,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Transport(m) | Self::Shape(m) => m.clone(),
            Self::Http(_, b) => b.clone(),
            Self::Rpc { message, .. } => message.clone(),
        }
    }

    pub fn class(&self) -> String {
        match self {
            Self::Transport(_) => "transport".to_string(),
            Self::Http(429, _) => "http-429".to_string(),
            Self::Http(code, _) => format!("http-{code}"),
            Self::Shape(_) => "shape".to_string(),
            Self::Rpc { message, .. } => classify_message(message),
        }
    }
}

pub fn classify_message(message: &str) -> String {
    let m = message.to_ascii_lowercase();
    if m.contains("rate limit") {
        "rate-limit".to_string()
    } else if m.contains("already in mempool") || m.contains("duplicate") {
        "duplicate".to_string()
    } else if m.contains("below the base fee") || m.contains("fee too low") {
        "fee-too-low".to_string()
    } else if m.contains("cannot pay amount") || m.contains("insufficient balance") {
        "insufficient-balance".to_string()
    } else if m.contains("nonce") {
        "nonce".to_string()
    } else if m.contains("invalid transaction signature") || m.contains("bad signature") {
        "bad-signature".to_string()
    } else if m.contains("unbound transaction refused") {
        "unbound".to_string()
    } else if m.contains("chain_id mismatch") || m.contains("does not match this chain") {
        "chain-id-mismatch".to_string()
    } else if m.contains("mempool is full") {
        "mempool-full".to_string()
    } else if m.contains("exceeds mempool quota") {
        "sender-quota".to_string()
    } else if m.contains("transaction too large") {
        "tx-too-large".to_string()
    } else {
        "other".to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        out.push_str("...");
    }
    out
}

#[derive(Clone)]
pub struct RpcClient {
    url: String,
    agent: ureq::Agent,
    timeout: Duration,
}

impl RpcClient {
    pub fn new(url: &str, timeout_ms: u64) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .build();
        Self {
            url: url.to_string(),
            agent,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// One JSON-RPC call. `params` is the exact JSON value the node's handler
    /// expects (`[]` for parameterless methods, an object otherwise).
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.call_with_timeout(method, params, self.timeout)
    }

    pub fn call_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        })
        .to_string();

        let response = self
            .agent
            .post(&self.url)
            .timeout(timeout.min(self.timeout))
            .set("content-type", "application/json")
            .send_string(&body);

        let text = match response {
            Ok(resp) => resp
                .into_string()
                .map_err(|e| RpcError::Transport(format!("read body: {e}")))?,
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                return Err(RpcError::Http(code, body));
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(RpcError::Transport(t.to_string()));
            }
        };

        let value: Value = serde_json::from_str(&text)
            .map_err(|e| RpcError::Shape(format!("invalid JSON response: {e}")))?;
        if let Some(err) = value.get("error") {
            if !err.is_null() {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(-1);
                let message = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown JSON-RPC error")
                    .to_string();
                return Err(RpcError::Rpc { code, message });
            }
        }
        match value.get("result") {
            Some(result) => Ok(result.clone()),
            None => Err(RpcError::Shape(
                "response has neither result nor error".to_string(),
            )),
        }
    }

    pub fn call_retry(
        &self,
        method: &str,
        params: Value,
        attempts: u32,
        base_ms: u64,
    ) -> Result<Value, RpcError> {
        let mut last: Option<RpcError> = None;
        for attempt in 0..attempts.max(1) {
            match self.call(method, params.clone()) {
                Ok(v) => return Ok(v),
                Err(e) if e.retryable() && attempt + 1 < attempts => {
                    sleep_backoff(base_ms, attempt);
                    last = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| RpcError::Transport("retry budget exhausted".to_string())))
    }

    /// Submit exactly one transaction. No internal retry: the sender owns the
    /// idempotent same-bytes retry loop so a nonce can never be double-spent.
    pub fn send_raw_once(&self, wire_hex: &str) -> Result<String, RpcError> {
        let result = self.call("stell_sendRawTransaction", json!({ "tx": wire_hex }))?;
        match result.as_str() {
            Some(h) => {
                let stripped = h.strip_prefix("0x").unwrap_or(h);
                if stripped.len() != 64 || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(RpcError::Shape(format!(
                        "node returned a malformed tx hash: {h:?}"
                    )));
                }
                Ok(stripped.to_ascii_lowercase())
            }
            None => Err(RpcError::Shape(format!(
                "sendRawTransaction result is not a string: {result}"
            ))),
        }
    }

    pub fn get_text(&self, url: &str) -> Result<String, RpcError> {
        match self.agent.get(url).call() {
            Ok(resp) => resp
                .into_string()
                .map_err(|e| RpcError::Transport(format!("read metrics: {e}"))),
            Err(ureq::Error::Status(code, resp)) => {
                Err(RpcError::Http(code, resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => Err(RpcError::Transport(t.to_string())),
        }
    }
}

pub fn sleep_backoff(base_ms: u64, attempt: u32) {
    let exp = base_ms.saturating_mul(1u64 << attempt.min(6));
    let capped = exp.min(5_000);
    // Cheap jitter derived from the clock: spread retries from many senders.
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % (capped.max(2) / 2 + 1))
        .unwrap_or(0);
    std::thread::sleep(Duration::from_millis(capped + jitter));
}

pub fn parse_hex_u64(v: &Value) -> Option<u64> {
    v.as_str()
        .map(|s| s.trim())
        .and_then(|s| s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")))
        .and_then(|s| u64::from_str_radix(s, 16).ok())
}

pub fn parse_u64_any(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
        .or_else(|| parse_hex_u64(v))
}

/// `stell_getBalance` -> `(balance, nonce)`.
pub fn parse_balance(result: &Value) -> Option<(u64, u64)> {
    let balance = result.get("balance").and_then(parse_u64_any)?;
    let nonce = result.get("nonce").and_then(parse_u64_any)?;
    Some((balance, nonce))
}

pub fn parse_chain_id(result: &Value) -> Option<u64> {
    parse_u64_any(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_decimal_parse() {
        assert_eq!(parse_hex_u64(&json!("0x10")), Some(16));
        assert_eq!(parse_u64_any(&json!("0x10")), Some(16));
        assert_eq!(parse_u64_any(&json!("280000")), Some(280_000));
        assert_eq!(parse_u64_any(&json!(7)), Some(7));
    }

    #[test]
    fn balance_shape_matches_the_node() {
        let v = json!({"balance":"12345","nonce":9});
        assert_eq!(parse_balance(&v), Some((12_345, 9)));
        assert_eq!(parse_balance(&json!({"balance":"x"})), None);
    }

    #[test]
    fn error_classification_is_stable() {
        assert_eq!(
            classify_message("rejected: transaction already in mempool"),
            "duplicate"
        );
        assert_eq!(
            classify_message("rejected: offered fee is below the base fee"),
            "fee-too-low"
        );
        assert_eq!(
            classify_message("rejected: sender cannot pay amount + gas_limit"),
            "insufficient-balance"
        );
        assert_eq!(
            classify_message(
                "rejected: nonce gap: sender can execute 3, got 9 (fill the gap first)"
            ),
            "nonce"
        );
        assert_eq!(
            classify_message("rejected: unbound transaction refused: chain binding enforced"),
            "unbound"
        );
        assert_eq!(
            classify_message(
                "Transaction chain_id mismatch: chain id 1 does not match this chain (5757)"
            ),
            "chain-id-mismatch"
        );
    }

    #[test]
    fn retry_classes_are_narrow() {
        let t = RpcError::Transport("reset".into());
        assert!(t.retryable());
        assert!(RpcError::Http(429, "slow down".into()).retryable());
        assert!(RpcError::Http(503, "down".into()).retryable());
        assert!(!RpcError::Http(400, "bad".into()).retryable());
        let rate = RpcError::Rpc {
            code: -32000,
            message: "rate limit exceeded (per-IP budget on standalone RPC)".into(),
        };
        assert!(rate.retryable());
        let rejection = RpcError::Rpc {
            code: -32000,
            message: "rejected: sender cannot pay amount + gas_limit".into(),
        };
        assert!(!rejection.retryable());
        assert!(rejection.is_insufficient_balance());
    }
}
