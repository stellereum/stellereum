//! Minimal HTTP JSON-RPC client for Stellereum nodes.
//!
//! Deliberately stdlib-only (`std::net::TcpStream` + manual HTTP/1.1):
//! no new heavy dependencies. Modelled on
//! `~/stellereum/scripts/tps_load.py`, which does the same calls with
//! Python's `urllib`.
//!
//! Supported methods (see `~/stellereum/src/rpc.rs`):
//! - `stell_getBalance` -> `{balance, nonce}`
//! - `stell_getBalanceSpv` -> `{address, balance, nonce, stateRoot, proof}`
//! - `stell_tokenBalance` -> `"123"`
//! - `stell_tokenBalanceSpv` -> `{balance, stateRoot, key, proof}`
//! - `stell_sendRawTransaction` params `{tx: hex(bincode(Transaction))}`
//! - `stell_getTransactionReceipt` -> receipt or `{status: pending|unknown}`
//! - `stell_getTransactionStatus` -> `{status, height}`
//! - `stell_faucet` params `{address, token, amount?}`
//! - `stell_chainId`

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Finality of a submitted transaction, resolved by polling
/// `stell_getTransactionReceipt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxFinality {
    /// Node knows the tx (mempool) but it is not in a finalized block yet.
    Pending,
    /// Finalized in a block (`success` receipt).
    Confirmed {
        height: u64,
        block_hash: String,
        index: u64,
    },
    /// Finalized but FAILED (receipt `success == false`), or otherwise dead.
    Failed { height: Option<u64>, detail: String },
    /// Node has never seen this hash (not in mempool, no receipt).
    Unknown,
}

impl TxFinality {
    pub fn status_label(&self) -> String {
        match self {
            TxFinality::Pending => "Pending (in mempool, NOT finalized)".to_string(),
            TxFinality::Confirmed { height, .. } => {
                format!("Confirmed (finalized in block height {height})")
            }
            TxFinality::Failed { height, .. } => match height {
                Some(h) => format!("Failed (finalized as FAILED in block height {h})"),
                None => "Failed".to_string(),
            },
            TxFinality::Unknown => "Unknown (node has no record of this tx)".to_string(),
        }
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(self, TxFinality::Confirmed { .. })
    }

    #[allow(dead_code)]
    pub fn is_failed(&self) -> bool {
        matches!(self, TxFinality::Failed { .. })
    }
}

/// Connection + credential configuration for one node.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub url: String,
    pub auth_token: Option<String>,
    pub faucet_token: Option<String>,
}

impl RpcConfig {
    /// Build from CLI flags, falling back to the standard env vars
    /// (`STELL_RPC_AUTH_TOKEN`, `STELL_FAUCET_TOKEN`).
    pub fn from_opts(url: &str, auth_token: Option<String>, faucet_token: Option<String>) -> Self {
        let auth = match auth_token {
            Some(t) if !t.is_empty() => Some(t),
            _ => std::env::var("STELL_RPC_AUTH_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
        };
        let faucet = match faucet_token {
            Some(t) if !t.is_empty() => Some(t),
            _ => std::env::var("STELL_FAUCET_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
        };
        Self {
            url: url.to_string(),
            auth_token: auth,
            faucet_token: faucet,
        }
    }
}

/// Split `http://host:port/path` or `https://host:port/path` into `("host:port", "/path")`.
pub fn parse_http_url(url: &str) -> Result<(String, String), String> {
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if let Some(r) = url.strip_prefix("https://") {
        r
    } else {
        return Err(format!(
            "only http:// and https:// URLs are supported, got {url:?}"
        ));
    };
    let (host_port, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    if host_port.is_empty() {
        return Err(format!("invalid RPC URL {url:?}: empty host"));
    }
    Ok((host_port, path))
}

/// Build a JSON-RPC 2.0 request body.
pub fn build_jsonrpc_body(method: &str, params: &Value, id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

fn resolve_addr(host_port: &str) -> Result<SocketAddr, String> {
    let mut addrs = host_port
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host_port:?}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| format!("cannot resolve {host_port:?}: no addresses"))
}

/// Policy: an API token must never travel over cleartext HTTP to a REMOTE
/// host. Loopback (`127.0.0.1`/`localhost`/`::1`) is exempt: the bytes never
/// leave the host (secure-context model — same as Bitcoin Core's localhost
/// RPC), and the token still authenticates the client to the node.
/// Token-less http stays allowed everywhere (nothing secret). Pure function
/// so the rule is unit-pinned (audit B-WALLET-5). Residual: a sniffer in the
/// same network namespace sees loopback (shared-host threat only).
pub fn check_http_token_policy(url: &str, api_token: Option<&str>) -> Result<(), String> {
    let Some(token) = api_token else {
        return Ok(());
    };
    if token.is_empty() {
        return Ok(());
    }
    if !url.starts_with("http://") {
        return Ok(()); // https: encrypted transport
    }
    // Loopback exemption: EXACT host match (never substring — a
    // `localhost.evil.com` DNS-rebinding name must not pass).
    let host = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host_only = host
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host)
        .trim_matches(|c| c == '[' || c == ']');
    if host_only == "127.0.0.1" || host_only == "localhost" || host_only == "::1" {
        return Ok(());
    }
    Err(
        "refusing to send API token over cleartext http to a non-loopback host: \
         use https or unset the token"
            .to_string(),
    )
}

/// Raw HTTP/1.1 POST with HTTPS and HTTP support.
fn http_post(url: &str, body: &str, api_token: Option<&str>) -> Result<String, String> {
    check_http_token_policy(url, api_token)?;
    if url.starts_with("https://") {
        let mut req = ureq::post(url)
            .timeout(Duration::from_secs(15))
            .set("Content-Type", "application/json");
        if let Some(t) = api_token {
            req = req.set("X-Api-Key", t);
        }
        let resp = req
            .send_string(body)
            .map_err(|e| format!("HTTPS request to {url} failed: {e}"))?;
        let text = resp
            .into_string()
            .map_err(|e| format!("Failed to read response body: {e}"))?;
        Ok(text)
    } else {
        let (host_port, path) = parse_http_url(url)?;
        let addr = resolve_addr(&host_port)?;
        let timeout = Duration::from_secs(15);
        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| format!("cannot connect to {host_port}: {e}"))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("socket setup failed: {e}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("socket setup failed: {e}"))?;

        let mut req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(t) = api_token {
            req.push_str(&format!("X-Api-Key: {t}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("HTTP write to {host_port} failed: {e}"))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| format!("HTTP read from {host_port} failed: {e}"))?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, response_body) = match text.find("\r\n\r\n") {
            Some(i) => (text[..i].to_string(), text[i + 4..].to_string()),
            None => return Err("malformed HTTP response (no header/body split)".to_string()),
        };
        let status_line = head.lines().next().unwrap_or("");
        if !status_line.contains(" 200") {
            return Err(format!(
                "HTTP {} from {host_port}: {}",
                status_line.trim(),
                response_body.chars().take(300).collect::<String>()
            ));
        }
        Ok(response_body)
    }
}

/// Single JSON-RPC call. Returns the `result` field, or the node's
/// `error.message` as `Err`.
pub fn rpc_call(cfg: &RpcConfig, method: &str, params: Value) -> Result<Value, String> {
    static IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let body = build_jsonrpc_body(method, &params, id);
    let resp_text = http_post(&cfg.url, &body, cfg.auth_token.as_deref())?;
    let resp: Value =
        serde_json::from_str(&resp_text).map_err(|e| format!("invalid JSON from node: {e}"))?;
    // Audit B-WALLET-5: verify the response id echoes the request (replay
    // mixing across concurrent calls otherwise).
    match resp.get("id") {
        Some(rid) if *rid == serde_json::json!(id) => {}
        _ => {
            return Err(format!(
                "node response id mismatch for {method} (replay refused)"
            ))
        }
    }
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown RPC error");
        return Err(format!("node rejected {method}: {msg}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| format!("node returned no result for {method}"))
}

/// `stell_chainId` (read-only, no auth needed).
pub fn chain_id(cfg: &RpcConfig) -> Result<u64, String> {
    let v = rpc_call(cfg, "stell_chainId", serde_json::json!({}))?;
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        .ok_or_else(|| format!("node returned bad chainId: {v}"))
}

/// `stell_blockNumber` -> height u64 (hex `"0x..."` or number).
pub fn chain_height(cfg: &RpcConfig) -> Result<u64, String> {
    let v = rpc_call(cfg, "stell_blockNumber", serde_json::json!({}))?;
    v.as_u64()
        .or_else(|| {
            v.as_str().and_then(|s| {
                s.strip_prefix("0x")
                    .and_then(|h| u64::from_str_radix(h, 16).ok())
                    .or_else(|| s.parse::<u64>().ok())
            })
        })
        .ok_or_else(|| format!("node returned bad blockNumber: {v}"))
}

/// `stell_syncing` -> bool.
pub fn is_syncing(cfg: &RpcConfig) -> Result<bool, String> {
    let v = rpc_call(cfg, "stell_syncing", serde_json::json!({}))?;
    v.as_bool()
        .ok_or_else(|| format!("node returned bad syncing: {v}"))
}

#[allow(dead_code)] // GATE: public RPC block summary struct retained for wallet queries
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcBlockSummary {
    pub height: u64,
    pub hash: String,
    pub txs: u64,
    pub timestamp: u64,
}

#[allow(dead_code)] // GATE: public RPC block tx struct retained for wallet queries
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcBlockTx {
    pub tx_hash: String,
    pub index: u32,
    pub status: String,
    pub gas_limit: String,
    pub fee_charged: String,
    #[serde(default)]
    pub raw_tx: Option<String>,
}

/// `stell_latestBlocks` -> list of latest blocks
#[allow(dead_code)] // GATE: public RPC helper retained for wallet queries
pub fn latest_blocks(cfg: &RpcConfig) -> Result<Vec<RpcBlockSummary>, String> {
    let v = rpc_call(cfg, "stell_latestBlocks", serde_json::json!({}))?;
    let arr = v
        .as_array()
        .ok_or_else(|| format!("node returned non-array latestBlocks: {v}"))?;
    let mut list = Vec::new();
    for item in arr {
        let height = item.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
        let hash = item
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        let txs = item.get("txs").and_then(|t| t.as_u64()).unwrap_or(0);
        let timestamp = item.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0);
        list.push(RpcBlockSummary {
            height,
            hash,
            txs,
            timestamp,
        });
    }
    Ok(list)
}

/// `stell_getBlockTransactions` -> list of transactions for a block height
#[allow(dead_code)] // GATE: public RPC helper retained for wallet queries
pub fn get_block_transactions(cfg: &RpcConfig, height: u64) -> Result<Vec<RpcBlockTx>, String> {
    let v = rpc_call(
        cfg,
        "stell_getBlockTransactions",
        serde_json::json!({ "height": height }),
    )?;
    let txs_val = v.get("txs").unwrap_or(&v);
    let arr = txs_val
        .as_array()
        .ok_or_else(|| format!("node returned non-array block transactions: {v}"))?;
    let mut list = Vec::new();
    for item in arr {
        let tx_hash = item
            .get("tx_hash")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        let index = item.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
        let status = item
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let gas_limit = item
            .get("gas_limit")
            .and_then(|g| {
                g.as_str()
                    .map(String::from)
                    .or_else(|| g.as_u64().map(|n| n.to_string()))
            })
            .unwrap_or_default();
        let fee_charged = item
            .get("fee_charged")
            .and_then(|f| {
                f.as_str()
                    .map(String::from)
                    .or_else(|| f.as_u64().map(|n| n.to_string()))
            })
            .unwrap_or_default();
        let raw_tx = item
            .get("raw_tx")
            .and_then(|r| r.as_str())
            .map(String::from);
        list.push(RpcBlockTx {
            tx_hash,
            index,
            status,
            gas_limit,
            fee_charged,
            raw_tx,
        });
    }
    Ok(list)
}

/// Fetch raw transaction for a hash from `stell_getTransactionReceipt`
#[allow(dead_code)] // GATE: public RPC helper retained for wallet queries
pub fn get_transaction_raw(cfg: &RpcConfig, tx_hash: &str) -> Result<Option<String>, String> {
    let v = rpc_call(
        cfg,
        "stell_getTransactionReceipt",
        serde_json::json!(tx_hash),
    )?;
    Ok(v.get("raw_tx").and_then(|r| r.as_str()).map(String::from))
}

/// `stell_getBalance` -> `(balance_nano, nonce)`.
pub fn get_balance(cfg: &RpcConfig, address_hex: &str) -> Result<(u64, u64), String> {
    let v = rpc_call(cfg, "stell_getBalance", serde_json::json!(address_hex))?;
    let bal = v
        .get("balance")
        .and_then(|b| {
            b.as_str()
                .unwrap_or("")
                .parse::<u64>()
                .ok()
                .or_else(|| b.as_u64())
        })
        .ok_or_else(|| format!("node returned bad balance: {v}"))?;
    let nonce = v
        .get("nonce")
        .and_then(|n| {
            n.as_u64()
                .or_else(|| n.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(0);
    Ok((bal, nonce))
}

/// Raw `stell_getBalanceSpv` answer: verified by the CALLER against the
/// returned root with `PatriciaTrie::verify_merkle_proof`.
#[derive(Clone, Debug)]
pub struct SpvAnswer {
    pub balance: u64,
    pub nonce: u64,
    pub state_root: [u8; 32],
    pub proof: Option<stellereum::cell::MerkleProof>,
    pub leaf_data: Option<Vec<u8>>,
}

pub fn get_balance_spv(cfg: &RpcConfig, address_hex: &str) -> Result<SpvAnswer, String> {
    let v = rpc_call(
        cfg,
        "stell_getBalanceSpv",
        serde_json::json!({ "address": address_hex }),
    )?;
    parse_spv_answer(&v)
}

fn parse_hex32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad hex from node: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("bad 32-byte hash from node: {} bytes", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_spv_answer(v: &Value) -> Result<SpvAnswer, String> {
    let balance = v
        .get("balance")
        .and_then(|b| {
            b.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| b.as_u64())
        })
        .ok_or_else(|| format!("node returned bad SPV balance: {v}"))?;
    let nonce = v
        .get("nonce")
        .and_then(|n| {
            n.as_u64()
                .or_else(|| n.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(0);
    let root_hex = v
        .get("stateRoot")
        .and_then(|r| r.as_str())
        .ok_or_else(|| format!("node returned no stateRoot: {v}"))?;
    let state_root = parse_hex32(root_hex)?;
    let proof = match v.get("proof") {
        None | Some(Value::Null) => None,
        Some(p) => Some(
            serde_json::from_value::<stellereum::cell::MerkleProof>(p.clone())
                .map_err(|e| format!("node returned undecodable proof: {e}"))?,
        ),
    };
    let leaf_data = v
        .get("leafData")
        .or_else(|| v.get("leaf_data"))
        .and_then(|l| l.as_str())
        .and_then(|s| hex::decode(s).ok());
    Ok(SpvAnswer {
        balance,
        nonce,
        state_root,
        proof,
        leaf_data,
    })
}

/// Verify an SPV answer locally: `balance||nonce` (both big-endian, the
/// account leaf encoding) must be included under `address` at `state_root`.
/// How far local verification got for a node-served balance answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpvVerdict {
    /// A proof was served and checks against the chain root.
    Verified,
    /// No proof was served AND the claimed balance/nonce are both zero: the
    /// account simply has no on-chain record, which MEANS zero by protocol
    /// semantics (absent accounts hold nothing). Not cryptographic proof, but
    /// not a failure either - there is nothing to prove.
    Absent,
    /// A proof was served and does NOT check, or a nonzero balance came with
    /// no proof (a balance that must have a record behind it). Do not trust.
    Failed,
}

pub fn verify_spv_balance_answer(address: &[u8; 32], answer: &SpvAnswer) -> SpvVerdict {
    let proof = match &answer.proof {
        Some(p) => p,
        None => {
            return if answer.balance == 0 && answer.nonce == 0 {
                SpvVerdict::Absent
            } else {
                SpvVerdict::Failed
            };
        }
    };
    if let Some(leaf) = &answer.leaf_data {
        if stellereum::cell::PatriciaTrie::verify_merkle_proof(
            &answer.state_root,
            address,
            leaf,
            proof,
        ) {
            return SpvVerdict::Verified;
        }
    }
    let mut expected = Vec::with_capacity(16);
    expected.extend_from_slice(&answer.balance.to_be_bytes());
    expected.extend_from_slice(&answer.nonce.to_be_bytes());
    if stellereum::cell::PatriciaTrie::verify_merkle_proof(
        &answer.state_root,
        address,
        &expected,
        proof,
    ) {
        SpvVerdict::Verified
    } else {
        SpvVerdict::Failed
    }
}

/// Raw `stell_tokenBalanceSpv` answer.
#[derive(Clone, Debug)]
pub struct TokenSpvAnswer {
    pub balance: u64,
    pub state_root: [u8; 32],
    pub key: [u8; 32],
    pub proof: Option<stellereum::cell::MerkleProof>,
}

pub fn get_token_balance_spv(
    cfg: &RpcConfig,
    token_hex: &str,
    account_hex: &str,
) -> Result<TokenSpvAnswer, String> {
    let v = rpc_call(
        cfg,
        "stell_tokenBalanceSpv",
        serde_json::json!({ "token": token_hex, "account": account_hex }),
    )?;
    let balance = v
        .get("balance")
        .and_then(|b| {
            b.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| b.as_u64())
        })
        .ok_or_else(|| format!("node returned bad token SPV balance: {v}"))?;
    let root_hex = v
        .get("stateRoot")
        .and_then(|r| r.as_str())
        .ok_or_else(|| format!("node returned no stateRoot: {v}"))?;
    let key_hex = v
        .get("key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| format!("node returned no key: {v}"))?;
    let proof = match v.get("proof") {
        None | Some(Value::Null) => None,
        Some(p) => Some(
            serde_json::from_value::<stellereum::cell::MerkleProof>(p.clone())
                .map_err(|e| format!("node returned undecodable token proof: {e}"))?,
        ),
    };
    Ok(TokenSpvAnswer {
        balance,
        state_root: parse_hex32(root_hex)?,
        key: parse_hex32(key_hex)?,
        proof,
    })
}

/// Verify a token SPV answer: the namespaced key is recomputed locally
/// (never taken from the server) and the 8-byte big-endian balance leaf
/// must verify against the returned root.
pub fn verify_token_spv_answer(
    token_id: &[u8; 32],
    account: &[u8; 32],
    answer: &TokenSpvAnswer,
) -> bool {
    let proof = match &answer.proof {
        Some(p) => p,
        None => return false,
    };
    let expected_key = stellereum::state_engine::token_balance_key(token_id, account);
    if expected_key != answer.key {
        return false;
    }
    let value = answer.balance.to_be_bytes();
    stellereum::cell::PatriciaTrie::verify_merkle_proof(
        &answer.state_root,
        &expected_key,
        &value,
        proof,
    )
}

/// Plain (non-proof) token balance via `stell_tokenBalance`.
pub fn get_token_balance(
    cfg: &RpcConfig,
    token_hex: &str,
    account_hex: &str,
) -> Result<u64, String> {
    let v = rpc_call(
        cfg,
        "stell_tokenBalance",
        serde_json::json!({ "token": token_hex, "account": account_hex }),
    )?;
    v.as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| v.as_u64())
        .ok_or_else(|| format!("node returned bad token balance: {v}"))
}

/// Resolve a token id by (creator, name, symbol) (`stell_tokenResolve`).
/// Needed because the create-tx receipt carries no token id.
pub fn get_token_resolve(
    cfg: &RpcConfig,
    creator_hex: &str,
    name: &str,
    symbol: &str,
) -> Result<String, String> {
    let v = rpc_call(
        cfg,
        "stell_tokenResolve",
        serde_json::json!({ "creator": creator_hex, "name": name, "symbol": symbol }),
    )?;
    v.get("token")
        .and_then(|t| t.as_str())
        .map(String::from)
        .ok_or_else(|| format!("node returned bad token resolve: {v}"))
}

/// Paginated token registry listing (`stell_listTokens`).
/// The chain returns an OBJECT `{tokens, total, offset}` (not a bare array).
#[derive(Clone, Debug)]
pub struct TokenListAnswer {
    pub tokens: Vec<String>,
    pub total: u64,
    pub offset: u64,
}

/// Parse the `{tokens, total, offset}` object shape. A bare array (the old
/// shape) is rejected loudly so callers never misread it as "all tokens".
pub fn parse_token_list_answer(v: &Value) -> Result<TokenListAnswer, String> {
    let obj = v.as_object().ok_or_else(|| {
        format!("node returned bad token list (expected object with tokens/total/offset): {v}")
    })?;
    let tokens = obj
        .get("tokens")
        .and_then(|t| t.as_array())
        .ok_or_else(|| format!("node returned bad token list (missing tokens array): {v}"))?
        .iter()
        .map(|t| {
            t.as_str()
                .map(String::from)
                .ok_or_else(|| format!("node returned bad token id entry: {t}"))
        })
        .collect::<Result<Vec<String>, String>>()?;
    let num = |k: &str| -> Result<u64, String> {
        obj.get(k)
            .and_then(|n| {
                n.as_u64().or_else(|| {
                    n.as_str().and_then(|s| {
                        s.strip_prefix("0x")
                            .and_then(|h| u64::from_str_radix(h, 16).ok())
                            .or_else(|| s.parse::<u64>().ok())
                    })
                })
            })
            .ok_or_else(|| format!("node returned bad token list (missing {k}): {v}"))
    };
    Ok(TokenListAnswer {
        tokens,
        total: num("total")?,
        offset: num("offset")?,
    })
}

/// `stell_listTokens` with `{limit, offset}` pagination (read-only, no auth).
/// `limit` is clamped to 1..=1000 (chain hard max); `offset` is passed as-is.
pub fn list_tokens(cfg: &RpcConfig, limit: u64, offset: u64) -> Result<TokenListAnswer, String> {
    let limit = limit.clamp(1, 1000);
    let v = rpc_call(
        cfg,
        "stell_listTokens",
        serde_json::json!({ "limit": limit, "offset": offset }),
    )?;
    parse_token_list_answer(&v)
}

/// Submit a signed transaction (`bincode(Transaction)` hex) to the mempool.
/// Returns the mempool tx hash hex. This is ADMISSION ONLY — finality must
/// be established by polling the receipt (see `poll_receipt`).
pub fn send_raw_transaction(cfg: &RpcConfig, tx_bincode_hex: &str) -> Result<String, String> {
    let mut params = serde_json::json!({ "tx": tx_bincode_hex });
    if let Some(t) = &cfg.auth_token {
        params["token"] = serde_json::json!(t);
    }
    let v = rpc_call(cfg, "stell_sendRawTransaction", params)?;
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("node returned bad tx hash: {v}"))
}

/// Interpret one `stell_getTransactionReceipt` result value.
pub fn parse_receipt_status(v: &Value) -> TxFinality {
    match v.get("status").and_then(|s| s.as_str()) {
        Some("success") => {
            // Audit B-WALLET-1: a bare `success` (no height/hash) is NOT
            // finality — a malicious node forges "Confirmed" otherwise.
            // Both height AND non-empty block_hash required; else Pending.
            let height = v.get("height").and_then(|h| h.as_u64());
            let block_hash = v
                .get("block_hash")
                .and_then(|h| h.as_str())
                .filter(|h| !h.is_empty())
                .map(|h| h.to_string());
            match (height, block_hash) {
                (Some(height), Some(block_hash)) => {
                    let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    TxFinality::Confirmed {
                        height,
                        block_hash,
                        index,
                    }
                }
                _ => TxFinality::Pending,
            }
        }
        Some("failed") => {
            let height = v.get("height").and_then(|h| h.as_u64());
            TxFinality::Failed {
                height,
                detail: "transaction receipt reports failure".to_string(),
            }
        }
        Some("pending") => TxFinality::Pending,
        _ => TxFinality::Unknown,
    }
}

/// Poll `stell_getTransactionReceipt` until the tx is finalized
/// (success/failed) or the timeout expires (returns Pending/Unknown as-is).
///
/// Async twin for use inside async contexts (audit 2026-10-06): the sync
/// version parks the thread with `std::thread::sleep`, which blocks a tokio
/// worker when called from `broadcast_tx`. Same polling logic, same honesty.
pub async fn poll_receipt_async(
    cfg: &RpcConfig,
    tx_hash_hex: &str,
    timeout_secs: u64,
    poll_secs: u64,
) -> TxFinality {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let step = Duration::from_secs(poll_secs.clamp(1, 10));
    let mut last = TxFinality::Unknown;
    loop {
        match rpc_call(
            cfg,
            "stell_getTransactionReceipt",
            serde_json::json!(tx_hash_hex),
        ) {
            Ok(v) => {
                last = parse_receipt_status(&v);
                match &last {
                    TxFinality::Confirmed { .. } | TxFinality::Failed { .. } => return last,
                    _ => {}
                }
            }
            Err(_) => {
                // Transient network error: keep polling until the deadline.
            }
        }
        if std::time::Instant::now() >= deadline {
            return last;
        }
        tokio::time::sleep(step).await;
    }
}

pub fn poll_receipt(
    cfg: &RpcConfig,
    tx_hash_hex: &str,
    timeout_secs: u64,
    poll_secs: u64,
) -> TxFinality {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let step = Duration::from_secs(poll_secs.clamp(1, 10));
    let mut last = TxFinality::Unknown;
    loop {
        match rpc_call(
            cfg,
            "stell_getTransactionReceipt",
            serde_json::json!(tx_hash_hex),
        ) {
            Ok(v) => {
                last = parse_receipt_status(&v);
                match &last {
                    TxFinality::Confirmed { .. } | TxFinality::Failed { .. } => return last,
                    _ => {}
                }
            }
            Err(_) => {
                // Transient network error: keep polling until the deadline.
            }
        }
        if std::time::Instant::now() >= deadline {
            return last;
        }
        std::thread::sleep(step);
    }
}

/// Request testnet funds. Returns `(credited_nano, tx_hash_hex)`.
pub fn faucet_drip(
    cfg: &RpcConfig,
    address_hex: &str,
    amount_nano: Option<u64>,
) -> Result<(u64, String), String> {
    let token = cfg.faucet_token.clone().ok_or_else(|| {
        "no faucet token: pass --faucet-token or set STELL_FAUCET_TOKEN".to_string()
    })?;
    let mut params = serde_json::json!({ "address": address_hex, "token": token });
    if let Some(a) = amount_nano {
        params["amount"] = serde_json::json!(a);
    }
    let v = rpc_call(cfg, "stell_faucet", params)?;
    let credited = v
        .get("credited_nano")
        .and_then(|c| {
            c.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| c.as_u64())
        })
        .ok_or_else(|| format!("node returned bad faucet answer: {v}"))?;
    let tx_hash = v
        .get("tx_hash")
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string();
    Ok((credited, tx_hash))
}
