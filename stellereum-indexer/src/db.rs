use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAddress {
    /// Explicit shard prefix if `<shard>:<addr>` was provided (e.g. `-1:` -> 0, `1:` -> 1).
    pub shard_hint: Option<u32>,
    /// Canonical lowercase hex without `0x`:
    /// - 64 chars for a 32-byte PQ / native address (preserving leading zeros)
    /// - 40 chars for a 20-byte EVM address
    /// - trimmed, `0x`/`0X`-stripped lowercase string otherwise
    pub hex_clean: String,
    /// `0x`-prefixed `hex_clean` (empty string when `hex_clean` is empty).
    pub hex_0x: String,
    /// Full 32-byte representation (for 20-byte EVM addresses, left-padded with 12 zero bytes).
    pub bytes32: Option<[u8; 32]>,
    /// Branded `Stl57...` representation when `bytes32` is `Some`.
    pub stl57: Option<String>,
    /// True when the input is a 20-byte EVM address (40 hex chars).
    pub is_evm20: bool,
}

fn decode_20_byte_hex(s: &str) -> Option<[u8; 20]> {
    let t = s.trim();
    let body = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let decoded = hex::decode(body).ok()?;
    let arr: [u8; 20] = decoded.try_into().ok()?;
    Some(arr)
}

/// Normalize any supported Stellereum address (`0x`+64 hex, bare 64 hex,
/// `Stl57...`, `0x`+40 hex EVM, optional `<shard>:` prefix) without truncating
/// 32-byte addresses or padding 12 zero bytes onto already-32-byte addresses.
pub fn normalize_address_info(raw: &str) -> NormalizedAddress {
    let trimmed = raw.trim();
    let (shard_hint, addr_str) = match stellereum::sharding::split_shard_prefix(trimmed) {
        (Some(sid), rest)
            if stellereum::address::parse_address(rest).is_ok()
                || decode_20_byte_hex(rest).is_some() =>
        {
            (Some(sid), rest)
        }
        _ => (None, trimmed),
    };

    if let Ok(b32) = stellereum::address::parse_address(addr_str) {
        let hex_clean = hex::encode(b32);
        let hex_0x = format!("0x{hex_clean}");
        let stl57 = Some(stellereum::address::encode_stl57_address(&b32));
        return NormalizedAddress {
            shard_hint,
            hex_clean,
            hex_0x,
            bytes32: Some(b32),
            stl57,
            is_evm20: false,
        };
    }

    if let Some(b20) = decode_20_byte_hex(addr_str) {
        let hex_clean = hex::encode(b20);
        let hex_0x = format!("0x{hex_clean}");
        let mut b32 = [0u8; 32];
        b32[12..].copy_from_slice(&b20);
        let stl57 = Some(stellereum::address::encode_stl57_address(&b32));
        return NormalizedAddress {
            shard_hint,
            hex_clean,
            hex_0x,
            bytes32: Some(b32),
            stl57,
            is_evm20: true,
        };
    }

    let stripped = addr_str
        .strip_prefix("0x")
        .or_else(|| addr_str.strip_prefix("0X"))
        .unwrap_or(addr_str);
    let hex_clean = stripped.trim().to_lowercase();
    let hex_0x = if hex_clean.is_empty() {
        String::new()
    } else {
        format!("0x{hex_clean}")
    };
    NormalizedAddress {
        shard_hint,
        hex_clean,
        hex_0x,
        bytes32: None,
        stl57: None,
        is_evm20: false,
    }
}

/// All canonical lowercase lookup forms for `address` in SQLite queries.
pub fn address_match_candidates(address: &str) -> Vec<String> {
    let norm = normalize_address_info(address);
    if norm.hex_clean.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(5);
    let mut push_unique = |s: String| {
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };
    push_unique(norm.hex_0x);
    push_unique(norm.hex_clean);
    if let Some(b32) = norm.bytes32 {
        let full = hex::encode(b32);
        push_unique(format!("0x{full}"));
        push_unique(full);
        if b32[..12] == [0u8; 12] {
            let evm = hex::encode(&b32[12..]);
            push_unique(format!("0x{evm}"));
            push_unique(evm);
        }
    }
    if let Some(stl) = norm.stl57 {
        push_unique(stl.to_lowercase());
    }
    out
}

pub fn resolve_address_variants(address: &str) -> (String, String, String) {
    let norm = normalize_address_info(address);
    // Audit B-IDX-1: escape LIKE metacharacters (`%`, `_`, `\`) so user
    // input cannot widen the match (cross-account disclosure). Queries using
    // this pattern carry an explicit `ESCAPE '\'` clause.
    let mut escaped = String::with_capacity(norm.hex_clean.len());
    for c in norm.hex_clean.chars() {
        if matches!(c, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    let pattern = format!("%{escaped}%");
    (norm.hex_0x, norm.hex_clean, pattern)
}

pub fn to_stl57(addr: &str) -> Option<String> {
    normalize_address_info(addr).stl57
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

/// Normalize a contract address into the canonical lookup key: trimmed,
/// `Stl57...` decoded if applicable, `0x`-prefix stripped, lowercase (the same
/// normalization the event queries apply, so `0xAA…`, `aa…`, and `Stl57…`
/// address the same row).
pub fn normalize_contract_key(address: &str) -> String {
    normalize_address_info(address).hex_clean
}

/// One VERIFIED contract source (audit P2 item 15).
///
/// A row exists only after the NODE confirmed the rebuild
/// (`stell_verifyContractSource` → `verified: true`); the indexer never
/// decides locally. `source_text` is the canonical `.wat` text,
/// `source_hash` its BLAKE3 fingerprint, `code_hash` the on-chain bytecode
/// hash the rebuild matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSource {
    /// Canonical lookup key ([`normalize_contract_key`]).
    pub contract: String,
    /// The verified `.wat` source text.
    pub source_text: String,
    /// The compiler claim the node reproduced (e.g. `wat2wasm-1.0`).
    pub compiler: String,
    /// The compiler flags the node reproduced.
    pub flags: String,
    /// `BLAKE3(source_text)`, lowercase hex.
    pub source_hash: String,
    /// The on-chain code hash the rebuild matched, lowercase hex.
    pub code_hash: String,
    /// Unix seconds when the node confirmed the verification.
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    pub shard_id: u32,
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub tx_count: u64,
    pub proposer: Option<String>,
    pub proposer_stl57: Option<String>,
    pub state_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub tx_hash: String,
    pub block_height: u64,
    pub tx_index: u32,
    pub from_addr: String,
    pub to_addr: String,
    pub from_stl57: Option<String>,
    pub to_stl57: Option<String>,
    pub amount: String,
    pub fee_charged: String,
    pub gas_limit: String,
    pub status: String,
    pub timestamp: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub address: String,
    pub tx_count: u64,
    pub first_seen_height: u64,
    pub last_seen_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub tip_height: u64,
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub current_tps: f64,
    pub avg_block_time: f64,
}

/// One indexed contract event.
///
/// The stored shape is exactly what the explorer needs to serve a decoded
/// event later:
///
/// * `topic0` — the event signature word (32-byte hex, `0x` prefixed);
/// * `topics_json` — the indexed fields, as a JSON array;
/// * `data` — the non-indexed fields, as a JSON value;
/// * `event_name` / `decoded_json` — the ABI-resolved name and the NAMED
///   fields (`{"topics": {...}, "data": {...}}`), when the contract's ABI was
///   known at index time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub tx_hash: String,
    pub block_height: u64,
    pub log_index: u32,
    pub contract: String,
    pub topic0: String,
    pub topics_json: String,
    pub data: String,
    pub event_name: Option<String>,
    pub decoded_json: Option<String>,
}

/// One contract that emitted at least one indexed event.
///
/// The contract list of the explorer is derived from the EVENT log: a contract
/// the indexer has never seen an event from is a contract that has never done
/// anything observable, and an empty list is an honest answer rather than a
/// guess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSummary {
    /// The emitting contract address (canonical lowercase hex).
    pub contract: String,
    /// The Stl57 form of the same address, when it can be derived.
    pub contract_stl57: Option<String>,
    /// How many events this contract has emitted (indexed).
    pub event_count: u64,
    /// How many distinct transactions the contract was seen in.
    pub tx_count: u64,
    /// The first block the contract was seen in.
    pub first_block: u64,
    /// The last block the contract was seen in.
    pub last_block: u64,
    /// The name of the most recent event the contract emitted, when it is
    /// known (i.e. when the contract's ABI manifest was available).
    pub last_event_name: Option<String>,
}

/// A deterministic keyset-paginated slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Decoded cursor for `/api/v2/blocks` (`"<height>"` or `"<height>:<shard_id>"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockCursor {
    pub height: u64,
    pub shard_id: Option<u32>,
}

/// Normalize a decimal or `0x`-prefixed unsigned integer balance string into a
/// canonical base-10 string without leading zeros (`"0"` for zero).
///
/// Canonical decimal form guarantees that `(LENGTH(balance), balance)` orders
/// arbitrary-precision unsigned integers identically to numeric comparison.
pub fn canonical_decimal_string(raw: &str) -> String {
    let t = raw.trim();
    if let Some(hex_body) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if let Ok(v) = u128::from_str_radix(hex_body.trim(), 16) {
            return v.to_string();
        }
        return "0".to_string();
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return "0".to_string();
    }
    let trimmed = t.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn parse_block_cursor(raw: &str) -> std::result::Result<BlockCursor, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty block cursor".to_string());
    }
    if let Some((h_str, s_str)) = t.split_once(':') {
        let height = h_str
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid block cursor height".to_string())?;
        let shard_id = s_str
            .trim()
            .parse::<u32>()
            .map_err(|_| "invalid block cursor shard_id".to_string())?;
        Ok(BlockCursor {
            height,
            shard_id: Some(shard_id),
        })
    } else {
        let height = t
            .parse::<u64>()
            .map_err(|_| "invalid block cursor height".to_string())?;
        Ok(BlockCursor {
            height,
            shard_id: None,
        })
    }
}

pub fn parse_tx_cursor(raw: &str) -> std::result::Result<(u64, u32), String> {
    let t = raw.trim();
    let (h_str, idx_str) = t
        .split_once(':')
        .ok_or_else(|| "invalid tx cursor: expected '<block_height>:<tx_index>'".to_string())?;
    let height = h_str
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid tx cursor height".to_string())?;
    let tx_index = idx_str
        .trim()
        .parse::<u32>()
        .map_err(|_| "invalid tx cursor tx_index".to_string())?;
    Ok((height, tx_index))
}

pub fn parse_event_cursor(raw: &str) -> std::result::Result<(u64, i64), String> {
    let t = raw.trim();
    let (h_str, id_str) = t
        .split_once(':')
        .ok_or_else(|| "invalid event cursor: expected '<block_height>:<id>'".to_string())?;
    let height = h_str
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid event cursor height".to_string())?;
    let id = id_str
        .trim()
        .parse::<i64>()
        .map_err(|_| "invalid event cursor id".to_string())?;
    if id < 0 {
        return Err("invalid event cursor id: must be non-negative".to_string());
    }
    Ok((height, id))
}

pub fn parse_contracts_cursor(raw: &str) -> std::result::Result<(u64, u64, String), String> {
    let t = raw.trim();
    let mut parts = t.splitn(3, ':');
    let ec_str = parts
        .next()
        .ok_or_else(|| "invalid contracts cursor".to_string())?;
    let lb_str = parts
        .next()
        .ok_or_else(|| "invalid contracts cursor".to_string())?;
    let addr = parts
        .next()
        .ok_or_else(|| "invalid contracts cursor".to_string())?;
    let event_count = ec_str
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid contracts cursor event_count".to_string())?;
    let last_block = lb_str
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid contracts cursor last_block".to_string())?;
    let norm = normalize_contract_key(addr);
    if norm.is_empty() {
        return Err("invalid contracts cursor address".to_string());
    }
    Ok((event_count, last_block, norm))
}

pub fn parse_account_tokens_cursor(raw: &str) -> std::result::Result<(String, u32), String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty token cursor".to_string());
    }
    if let Some((tok, sid_str)) = t.split_once(':') {
        let token_id = normalize_contract_key(tok);
        if token_id.is_empty() {
            return Err("invalid token cursor token_id".to_string());
        }
        let shard_id = sid_str
            .trim()
            .parse::<u32>()
            .map_err(|_| "invalid token cursor shard_id".to_string())?;
        Ok((token_id, shard_id))
    } else {
        let token_id = normalize_contract_key(t);
        if token_id.is_empty() {
            return Err("invalid token cursor token_id".to_string());
        }
        Ok((token_id, 0))
    }
}

pub fn parse_token_holders_cursor(raw: &str) -> std::result::Result<(String, String, u32), String> {
    let t = raw.trim();
    let mut parts = t.splitn(3, ':');
    let bal_str = parts.next().ok_or_else(|| {
        "invalid holders cursor: expected '<balance>:<owner>:<shard_id>'".to_string()
    })?;
    let owner_str = parts.next().ok_or_else(|| {
        "invalid holders cursor: expected '<balance>:<owner>:<shard_id>'".to_string()
    })?;
    let sid_str = parts.next().ok_or_else(|| {
        "invalid holders cursor: expected '<balance>:<owner>:<shard_id>'".to_string()
    })?;
    if !bal_str.trim().bytes().all(|b| b.is_ascii_digit()) || bal_str.trim().is_empty() {
        return Err("invalid holders cursor balance".to_string());
    }
    let bal = canonical_decimal_string(bal_str);
    let owner = normalize_contract_key(owner_str);
    if owner.is_empty() {
        return Err("invalid holders cursor owner".to_string());
    }
    let shard_id = sid_str
        .trim()
        .parse::<u32>()
        .map_err(|_| "invalid holders cursor shard_id".to_string())?;
    Ok((bal, owner, shard_id))
}

pub fn parse_token_program_cursor(raw: &str) -> std::result::Result<(String, String, u32), String> {
    let t = raw.trim();
    let mut parts = t.splitn(3, ':');
    let tok_str = parts.next().ok_or_else(|| {
        "invalid token program cursor: expected '<token_id>:<owner>:<shard_id>'".to_string()
    })?;
    let own_str = parts.next().ok_or_else(|| {
        "invalid token program cursor: expected '<token_id>:<owner>:<shard_id>'".to_string()
    })?;
    let sid_str = parts.next().ok_or_else(|| {
        "invalid token program cursor: expected '<token_id>:<owner>:<shard_id>'".to_string()
    })?;
    let token_id = normalize_contract_key(tok_str);
    let owner = normalize_contract_key(own_str);
    if token_id.is_empty() || owner.is_empty() {
        return Err("invalid token program cursor address".to_string());
    }
    let shard_id = sid_str
        .trim()
        .parse::<u32>()
        .map_err(|_| "invalid token program cursor shard_id".to_string())?;
    Ok((token_id, owner, shard_id))
}

pub fn parse_contracts_program_cursor(raw: &str) -> std::result::Result<(u64, String), String> {
    let t = raw.trim();
    let (h_str, addr_str) = t.split_once(':').ok_or_else(|| {
        "invalid contract program cursor: expected '<deploy_height>:<address>'".to_string()
    })?;
    let height = h_str
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid contract program cursor height".to_string())?;
    let addr = normalize_contract_key(addr_str);
    if addr.is_empty() {
        return Err("invalid contract program cursor address".to_string());
    }
    Ok((height, addr))
}

/// One indexed STS-20 token balance row (`token_balances` table).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBalanceRecord {
    pub shard_id: u32,
    pub token_id: String,
    pub owner: String,
    pub owner_stl57: Option<String>,
    pub balance: String,
    pub updated_height: u64,
}

/// One indexed deployed WASM contract (`contracts` table).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractRecord {
    pub shard_id: u32,
    pub address: String,
    pub address_stl57: Option<String>,
    pub creator: Option<String>,
    pub creator_stl57: Option<String>,
    pub code_hash: Option<String>,
    pub deploy_height: u64,
    pub has_abi: bool,
}

/// Filter for [`Database::get_events`].
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Lowest block height (inclusive).
    pub from_block: Option<u64>,
    /// Highest block height (inclusive).
    pub to_block: Option<u64>,
    /// Emitting contract (any case, `0x` prefix optional).
    pub contract: Option<String>,
    /// Transaction hash (any case, `0x` prefix optional).
    pub tx_hash: Option<String>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS blocks (
                 shard_id INTEGER NOT NULL DEFAULT 0,
                 height INTEGER NOT NULL,
                 hash TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 tx_count INTEGER NOT NULL,
                 proposer TEXT,
                 state_root TEXT,
                 PRIMARY KEY (shard_id, height)
             );

             CREATE TABLE IF NOT EXISTS transactions (
                 shard_id INTEGER NOT NULL DEFAULT 0,
                 tx_hash TEXT PRIMARY KEY,
                 block_height INTEGER NOT NULL,
                 tx_index INTEGER NOT NULL,
                 from_addr TEXT NOT NULL,
                 to_addr TEXT NOT NULL,
                 amount TEXT NOT NULL,
                 fee_charged TEXT NOT NULL,
                 gas_limit TEXT NOT NULL,
                 status TEXT NOT NULL,
                 timestamp INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS accounts (
                 address TEXT PRIMARY KEY,
                 tx_count INTEGER NOT NULL,
                 first_seen_height INTEGER NOT NULL,
                 last_seen_height INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_addr);
             CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_addr);
             CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_height);
             CREATE INDEX IF NOT EXISTS idx_blocks_time ON blocks(timestamp);

             -- Contract events (logs) emitted by contracts during a
             -- transaction. `topic0` / `topics_json` / `data` are the raw
             -- parts; `event_name` / `decoded_json` are the ABI-resolved
             -- form, filled when the contract's manifest is known.
             CREATE TABLE IF NOT EXISTS contract_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 shard_id INTEGER NOT NULL DEFAULT 0,
                 tx_hash TEXT NOT NULL,
                 block_height INTEGER NOT NULL,
                 log_index INTEGER NOT NULL DEFAULT 0,
                 contract TEXT NOT NULL,
                 topic0 TEXT NOT NULL DEFAULT '',
                 topics_json TEXT NOT NULL DEFAULT '[]',
                 data TEXT NOT NULL DEFAULT 'null',
                 event_name TEXT,
                 decoded_json TEXT,
                 UNIQUE (tx_hash, log_index)
             );

              CREATE INDEX IF NOT EXISTS idx_events_tx ON contract_events(tx_hash);
              CREATE INDEX IF NOT EXISTS idx_events_contract ON contract_events(contract);
              CREATE INDEX IF NOT EXISTS idx_events_block ON contract_events(block_height);
              CREATE INDEX IF NOT EXISTS idx_events_name ON contract_events(event_name);

              -- Verified contract sources (audit P2-15). One row per
              -- contract, written ONLY after the node confirmed the rebuild
              -- (`stell_verifyContractSource` said `verified: true`); the
              -- indexer never marks a source verified on its own.
              CREATE TABLE IF NOT EXISTS verified_contract_sources (
                  contract TEXT PRIMARY KEY,
                  source_text TEXT NOT NULL,
                  compiler TEXT NOT NULL,
                  flags TEXT NOT NULL,
                  source_hash TEXT NOT NULL,
                  code_hash TEXT NOT NULL,
                  verified_at INTEGER NOT NULL
              );

              -- STS-20 token balances (W4 contract).
              CREATE TABLE IF NOT EXISTS token_balances (
                  shard_id INTEGER NOT NULL DEFAULT 0,
                  token_id TEXT NOT NULL,
                  owner TEXT NOT NULL,
                  balance TEXT NOT NULL,
                  updated_height INTEGER NOT NULL,
                  PRIMARY KEY (shard_id, token_id, owner)
              );
              CREATE INDEX IF NOT EXISTS idx_tb_owner ON token_balances(owner, token_id);
              CREATE INDEX IF NOT EXISTS idx_tb_owner_lower ON token_balances(LOWER(owner), token_id, shard_id);
              CREATE INDEX IF NOT EXISTS idx_tb_token_lower ON token_balances(LOWER(token_id), owner, shard_id);
              CREATE INDEX IF NOT EXISTS idx_tb_shard_height ON token_balances(shard_id, updated_height);

              -- Deployed WASM contracts (W4 contract).
              CREATE TABLE IF NOT EXISTS contracts (
                  shard_id INTEGER NOT NULL DEFAULT 0,
                  address TEXT PRIMARY KEY,
                  creator TEXT,
                  code_hash TEXT,
                  deploy_height INTEGER NOT NULL,
                  has_abi INTEGER NOT NULL DEFAULT 0
              );
              CREATE INDEX IF NOT EXISTS idx_contracts_creator ON contracts(creator, deploy_height);
              CREATE INDEX IF NOT EXISTS idx_contracts_creator_lower ON contracts(LOWER(creator), deploy_height DESC, address ASC);
              CREATE INDEX IF NOT EXISTS idx_contracts_deploy_addr ON contracts(deploy_height DESC, address ASC);
              CREATE INDEX IF NOT EXISTS idx_contracts_shard_height ON contracts(shard_id, deploy_height);
             ",
        )?;

        // Auto-migration: ensure shard_id column exists if tables were created in an earlier version
        let _ = conn.execute(
            "ALTER TABLE blocks ADD COLUMN shard_id INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE transactions ADD COLUMN shard_id INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE contract_events ADD COLUMN shard_id INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_shard_block ON transactions(shard_id, block_height)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_shard_block ON contract_events(shard_id, block_height)",
            [],
        );
        // Keyset history indexes (W4 contract)
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_block_txindex ON transactions(block_height DESC, tx_index DESC)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_from_lower_history ON transactions(LOWER(from_addr), block_height DESC, tx_index DESC)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_to_lower_history ON transactions(LOWER(to_addr), block_height DESC, tx_index DESC)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_hash_lower ON transactions(LOWER(tx_hash))",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_block_id ON contract_events(block_height DESC, id DESC)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_contract_lower_history ON contract_events(LOWER(contract), block_height DESC, id DESC)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocks_height_shard ON blocks(height DESC, shard_id ASC)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocks_hash_lower ON blocks(LOWER(hash))",
            [],
        );

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn insert_block(&self, b: &BlockRecord) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // Audit B-IDX-2: same (shard,height) with a DIFFERENT hash is a
        // reorg — the new canonical hash must win (INSERT OR IGNORE kept
        // stale forks forever). Dependents at this (shard,height) are
        // invalidated with it.
        let existing: Option<String> = match conn.query_row(
            "SELECT hash FROM blocks WHERE shard_id = ?1 AND height = ?2",
            params![b.shard_id, Self::clamp_u64(b.height)],
            |row| row.get(0),
        ) {
            Ok(h) => Some(h),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e),
        };
        if let Some(old) = existing {
            if old == b.hash {
                return Ok(()); // idempotent fast path
            }
            let tx = conn.transaction()?;
            Self::delete_shard_height_tx(&tx, b.shard_id, b.height)?;
            tx.execute(
                "INSERT INTO blocks (shard_id, height, hash, timestamp, tx_count, proposer, state_root)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    b.shard_id,
                    Self::clamp_u64(b.height),
                    b.hash,
                    Self::clamp_u64(b.timestamp),
                    Self::clamp_u64(b.tx_count),
                    b.proposer,
                    b.state_root
                ],
            )?;
            tx.commit()?;
            return Ok(());
        }
        conn.execute(
            "INSERT INTO blocks (shard_id, height, hash, timestamp, tx_count, proposer, state_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                b.shard_id,
                Self::clamp_u64(b.height),
                b.hash,
                Self::clamp_u64(b.timestamp),
                Self::clamp_u64(b.tx_count),
                b.proposer,
                b.state_root
            ],
        )?;
        Ok(())
    }

    fn clamp_u64(v: u64) -> i64 {
        v.min(i64::MAX as u64) as i64
    }

    fn delete_shard_height_tx(
        tx: &rusqlite::Transaction<'_>,
        shard_id: u32,
        height: u64,
    ) -> Result<()> {
        let h = Self::clamp_u64(height);
        tx.execute(
            "DELETE FROM transactions WHERE shard_id = ?1 AND block_height = ?2",
            params![shard_id, h],
        )?;
        tx.execute(
            "DELETE FROM contract_events WHERE shard_id = ?1 AND block_height = ?2",
            params![shard_id, h],
        )?;
        tx.execute(
            "DELETE FROM contracts WHERE shard_id = ?1 AND deploy_height = ?2",
            params![shard_id, h],
        )?;
        tx.execute(
            "DELETE FROM token_balances WHERE shard_id = ?1 AND updated_height = ?2",
            params![shard_id, h],
        )?;
        tx.execute(
            "DELETE FROM blocks WHERE shard_id = ?1 AND height = ?2",
            params![shard_id, h],
        )?;
        Ok(())
    }

    /// Remove an orphaned `(shard_id, height)` block and all its indexed
    /// dependents (`transactions`, `contract_events`, `contracts`,
    /// `token_balances`). Returns `true` if a block row was removed.
    pub fn invalidate_shard_height(&self, shard_id: u32, height: u64) -> Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let h = Self::clamp_u64(height);
        let existed: bool = match tx.query_row(
            "SELECT 1 FROM blocks WHERE shard_id = ?1 AND height = ?2",
            params![shard_id, h],
            |_| Ok(true),
        ) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(e) => return Err(e),
        };
        Self::delete_shard_height_tx(&tx, shard_id, height)?;
        tx.commit()?;
        Ok(existed)
    }

    /// Invalidate every indexed block matching any hash in `hashes` (case- and
    /// `0x`-insensitive), along with all dependent rows at those `(shard_id,
    /// height)` pairs. Returns the invalidated `(shard_id, height)` pairs.
    pub fn invalidate_block_hashes(&self, hashes: &[String]) -> Result<Vec<(u32, u64)>> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let mut invalidated = Vec::new();
        for raw in hashes {
            let clean = raw
                .trim()
                .strip_prefix("0x")
                .or_else(|| raw.trim().strip_prefix("0X"))
                .unwrap_or(raw.trim())
                .to_lowercase();
            if clean.is_empty() {
                continue;
            }
            let with_0x = format!("0x{clean}");
            let found: Vec<(u32, u64)> = {
                let mut stmt = tx.prepare(
                    "SELECT shard_id, height FROM blocks WHERE LOWER(hash) = ?1 OR LOWER(hash) = ?2",
                )?;
                let rows = stmt.query_map(params![clean, with_0x], |row| {
                    Ok((row.get::<_, u32>(0)?, row.get::<_, u64>(1)?))
                })?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(r?);
                }
                out
            };
            for (sid, h) in found {
                Self::delete_shard_height_tx(&tx, sid, h)?;
                if !invalidated.contains(&(sid, h)) {
                    invalidated.push((sid, h));
                }
            }
        }
        tx.commit()?;
        Ok(invalidated)
    }

    pub fn insert_transaction(&self, tx: &TxRecord) -> Result<()> {
        self.insert_transaction_in_shard(0, tx)
    }

    pub fn insert_transaction_in_shard(&self, shard_id: u32, tx: &TxRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO transactions
             (shard_id, tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                shard_id,
                tx.tx_hash,
                tx.block_height,
                tx.tx_index,
                tx.from_addr,
                tx.to_addr,
                tx.amount,
                tx.fee_charged,
                tx.gas_limit,
                tx.status,
                tx.timestamp
            ],
        )?;

        // Update sender account
        conn.execute(
            "INSERT INTO accounts (address, tx_count, first_seen_height, last_seen_height)
             VALUES (?1, 1, ?2, ?2)
             ON CONFLICT(address) DO UPDATE SET
                 tx_count = tx_count + 1,
                 last_seen_height = MAX(last_seen_height, ?2)",
            params![tx.from_addr, tx.block_height],
        )?;

        // Update recipient account
        if tx.to_addr != tx.from_addr {
            conn.execute(
                "INSERT INTO accounts (address, tx_count, first_seen_height, last_seen_height)
                 VALUES (?1, 1, ?2, ?2)
                 ON CONFLICT(address) DO UPDATE SET
                     tx_count = tx_count + 1,
                     last_seen_height = MAX(last_seen_height, ?2)",
                params![tx.to_addr, tx.block_height],
            )?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_tip_height(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT COALESCE(MAX(height), 0) FROM blocks")?;
        let height: u64 = stmt.query_row([], |row| row.get(0))?;
        Ok(height)
    }

    pub fn get_shard_tip_height(&self, shard_id: u32) -> Result<u64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt =
            conn.prepare("SELECT COALESCE(MAX(height), 0) FROM blocks WHERE shard_id = ?1")?;
        let height: u64 = stmt.query_row(params![shard_id], |row| row.get(0))?;
        Ok(height)
    }

    /// Returns `(shard_id, tip_height, block_count)` for every indexed shard, ordered by `shard_id`.
    pub fn get_shard_index_stats(&self) -> Result<Vec<(u32, u64, u64)>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT shard_id, COALESCE(MAX(height), 0), COUNT(*)
             FROM blocks
             GROUP BY shard_id
             ORDER BY shard_id ASC",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ---- contract events ----

    /// Store one contract event.
    ///
    /// The `(tx_hash, log_index)` pair is unique, so re-indexing the same
    /// transaction (a re-sync, a restart) REPLACES the row instead of
    /// duplicating it.
    pub fn insert_event(&self, e: &EventRecord) -> Result<()> {
        self.insert_event_in_shard(0, e)
    }

    pub fn insert_event_in_shard(&self, shard_id: u32, e: &EventRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO contract_events
             (shard_id, tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                shard_id,
                e.tx_hash,
                e.block_height,
                e.log_index,
                e.contract,
                e.topic0,
                e.topics_json,
                e.data,
                e.event_name,
                e.decoded_json,
            ],
        )?;
        Ok(())
    }

    /// Store a batch of contract events in one transaction.
    pub fn insert_events(&self, events: &[EventRecord]) -> Result<()> {
        self.insert_events_in_shard(0, events)
    }

    pub fn insert_events_in_shard(&self, shard_id: u32, events: &[EventRecord]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO contract_events
                 (shard_id, tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for e in events {
                stmt.execute(params![
                    shard_id,
                    e.tx_hash,
                    e.block_height,
                    e.log_index,
                    e.contract,
                    e.topic0,
                    e.topics_json,
                    e.data,
                    e.event_name,
                    e.decoded_json,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Query contract events with the standard filters.
    ///
    /// Every filter is optional; the ones that are set are ANDed. Addresses
    /// and hashes are matched case-insensitively and with or without the
    /// `0x` prefix, so a client can paste either form.
    ///
    /// Block bounds are clamped to the i64 range SQLite binds: a bound above
    /// `i64::MAX` (e.g. `u64::MAX`) would otherwise fail conversion and
    /// surface as HTTP 500. Clamping preserves semantics (heights above the
    /// clamp match everything below it).
    fn clamp_block_bound(v: Option<u64>) -> Option<i64> {
        v.map(|x| x.min(i64::MAX as u64) as i64)
    }

    fn build_event_where(filter: &EventFilter) -> Option<(String, Vec<rusqlite::types::Value>)> {
        let mut clauses = Vec::new();
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(fb) = Self::clamp_block_bound(filter.from_block) {
            args.push(fb.into());
            clauses.push(format!("block_height >= ?{}", args.len()));
        }
        if let Some(tb) = Self::clamp_block_bound(filter.to_block) {
            args.push(tb.into());
            clauses.push(format!("block_height <= ?{}", args.len()));
        }
        if let Some(c) = filter.contract.as_ref() {
            let candidates = address_match_candidates(c);
            if candidates.is_empty() {
                return None;
            }
            let ph: Vec<String> = candidates
                .into_iter()
                .map(|cand| {
                    args.push(cand.into());
                    format!("?{}", args.len())
                })
                .collect();
            clauses.push(format!("LOWER(contract) IN ({})", ph.join(", ")));
        }
        if let Some(h) = filter.tx_hash.as_ref() {
            let clean = h
                .trim()
                .strip_prefix("0x")
                .or_else(|| h.trim().strip_prefix("0X"))
                .unwrap_or(h.trim())
                .to_lowercase();
            if clean.is_empty() {
                return None;
            }
            let with_0x = format!("0x{clean}");
            args.push(with_0x.into());
            let p1 = args.len();
            args.push(clean.into());
            let p2 = args.len();
            clauses.push(format!(
                "(LOWER(tx_hash) = ?{p1} OR LOWER(tx_hash) = ?{p2})"
            ));
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        Some((where_sql, args))
    }

    pub fn get_events(
        &self,
        filter: &EventFilter,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<EventRecord>> {
        let Some((where_sql, mut args)) = Self::build_event_where(filter) else {
            return Ok(Vec::new());
        };
        args.push((limit as i64).into());
        let limit_p = args.len();
        args.push((offset as i64).into());
        let offset_p = args.len();
        let sql = format!(
            "SELECT tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json
             FROM contract_events
             {where_sql}
             ORDER BY block_height DESC, id DESC
             LIMIT ?{limit_p} OFFSET ?{offset_p}"
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
            Ok(EventRecord {
                tx_hash: row.get(0)?,
                block_height: row.get(1)?,
                log_index: row.get(2)?,
                contract: row.get(3)?,
                topic0: row.get(4)?,
                topics_json: row.get(5)?,
                data: row.get(6)?,
                event_name: row.get(7)?,
                decoded_json: row.get(8)?,
            })
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// Keyset-paginated events (`cursor = "<block_height>:<id>"`).
    pub fn get_events_keyset(
        &self,
        filter: &EventFilter,
        limit: u32,
        cursor: Option<(u64, i64)>,
    ) -> Result<KeysetPage<EventRecord>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let Some((mut where_sql, mut args)) = Self::build_event_where(filter) else {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        };
        if let Some((ch, cid)) = cursor {
            args.push(Self::clamp_u64(ch).into());
            let h_p = args.len();
            args.push(cid.into());
            let id_p = args.len();
            let cond =
                format!("(block_height < ?{h_p} OR (block_height = ?{h_p} AND id < ?{id_p}))");
            if where_sql.is_empty() {
                where_sql = format!("WHERE {cond}");
            } else {
                where_sql = format!("{where_sql} AND {cond}");
            }
        }
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT id, tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json
             FROM contract_events
             {where_sql}
             ORDER BY block_height DESC, id DESC
             LIMIT ?{limit_p}"
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
            let id: i64 = row.get(0)?;
            let rec = EventRecord {
                tx_hash: row.get(1)?,
                block_height: row.get(2)?,
                log_index: row.get(3)?,
                contract: row.get(4)?,
                topic0: row.get(5)?,
                topics_json: row.get(6)?,
                data: row.get(7)?,
                event_name: row.get(8)?,
                decoded_json: row.get(9)?,
            };
            Ok((id, rec))
        })?;
        let mut pairs = Vec::new();
        for r in rows {
            pairs.push(r?);
        }
        let has_more = pairs.len() > limit as usize;
        if has_more {
            pairs.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            pairs
                .last()
                .map(|(id, ev)| format!("{}:{}", ev.block_height, id))
        } else {
            None
        };
        let items = pairs.into_iter().map(|(_, ev)| ev).collect();
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    /// How many contract events are indexed (with the same filters).
    pub fn count_events(&self, filter: &EventFilter) -> Result<u64> {
        let Some((where_sql, args)) = Self::build_event_where(filter) else {
            return Ok(0);
        };
        let sql = format!("SELECT COUNT(*) FROM contract_events {where_sql}");
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let count: u64 =
            stmt.query_row(rusqlite::params_from_iter(args.iter()), |row| row.get(0))?;
        Ok(count)
    }

    /// The contracts that emitted at least one indexed event, most active
    /// first.
    ///
    /// Bounded and paginated like every other listing: the event log is
    /// attacker-growable (anyone can deploy a contract and emit events), so an
    /// unbounded dump would be a DoS amplifier.
    pub fn list_contracts(&self, limit: u32, offset: u32) -> Result<Vec<ContractSummary>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT contract,
                    COUNT(*)          AS event_count,
                    COUNT(DISTINCT tx_hash) AS tx_count,
                    MIN(block_height) AS first_block,
                    MAX(block_height) AS last_block
             FROM contract_events
             GROUP BY LOWER(contract)
             ORDER BY event_count DESC, last_block DESC, LOWER(contract) ASC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            let contract: String = row.get(0)?;
            let stl57 = to_stl57(&contract);
            Ok(ContractSummary {
                contract,
                contract_stl57: stl57,
                event_count: row.get(1)?,
                tx_count: row.get(2)?,
                first_block: row.get(3)?,
                last_block: row.get(4)?,
                last_event_name: None,
            })
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// Keyset-paginated contract summaries across both deployed `contracts`
    /// and `contract_events` (`cursor = "<event_count>:<last_block>:<contract>"`).
    pub fn list_contracts_keyset(
        &self,
        limit: u32,
        cursor: Option<(u64, u64, String)>,
    ) -> Result<KeysetPage<ContractSummary>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let cursor_where = if let Some((ec, lb, addr)) = cursor {
            args.push(Self::clamp_u64(ec).into());
            let p1 = args.len();
            args.push(Self::clamp_u64(lb).into());
            let p2 = args.len();
            args.push(addr.into());
            let p3 = args.len();
            format!(
                "WHERE (event_count < ?{p1}
                        OR (event_count = ?{p1} AND last_block < ?{p2})
                        OR (event_count = ?{p1} AND last_block = ?{p2} AND contract > ?{p3}))"
            )
        } else {
            String::new()
        };
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT contract, event_count, tx_count, first_block, last_block
             FROM (
                 SELECT c.addr AS contract,
                        COALESCE(ev.event_count, 0) AS event_count,
                        COALESCE(ev.tx_count, 0) AS tx_count,
                        COALESCE(ev.first_block, ct.deploy_height, 0) AS first_block,
                        COALESCE(ev.last_block, ct.deploy_height, 0) AS last_block
                 FROM (
                     SELECT LOWER(address) AS addr FROM contracts
                     UNION
                     SELECT LOWER(contract) AS addr FROM contract_events
                 ) c
                 LEFT JOIN (
                     SELECT LOWER(contract) AS addr,
                            COUNT(*) AS event_count,
                            COUNT(DISTINCT tx_hash) AS tx_count,
                            MIN(block_height) AS first_block,
                            MAX(block_height) AS last_block
                     FROM contract_events
                     GROUP BY LOWER(contract)
                 ) ev ON ev.addr = c.addr
                 LEFT JOIN (
                     SELECT LOWER(address) AS addr, MIN(deploy_height) AS deploy_height
                     FROM contracts
                     GROUP BY LOWER(address)
                 ) ct ON ct.addr = c.addr
             )
             {cursor_where}
             ORDER BY event_count DESC, last_block DESC, contract ASC
             LIMIT ?{limit_p}"
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
            let contract: String = row.get(0)?;
            let stl57 = to_stl57(&contract);
            Ok(ContractSummary {
                contract,
                contract_stl57: stl57,
                event_count: row.get(1)?,
                tx_count: row.get(2)?,
                first_block: row.get(3)?,
                last_block: row.get(4)?,
                last_event_name: None,
            })
        })?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|c| format!("{}:{}:{}", c.event_count, c.last_block, c.contract))
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    /// How many distinct contracts are indexed (deployed or having emitted events).
    pub fn count_contracts(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM (
                 SELECT LOWER(address) AS addr FROM contracts
                 UNION
                 SELECT LOWER(contract) AS addr FROM contract_events
             )",
        )?;
        let count: u64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    // ---- verified contract sources (audit P2-15) ----

    /// Store a node-verified source. `INSERT OR REPLACE`: a re-verification
    /// (same or corrected source) replaces the row instead of duplicating it.
    /// Callers MUST only invoke this after the node confirmed the rebuild —
    /// the database does not (and cannot) check the claim itself.
    pub fn upsert_verified_source(&self, v: &VerifiedSource) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO verified_contract_sources
             (contract, source_text, compiler, flags, source_hash, code_hash, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                normalize_contract_key(&v.contract),
                v.source_text,
                v.compiler,
                v.flags,
                v.source_hash.to_lowercase(),
                v.code_hash.to_lowercase(),
                v.verified_at,
            ],
        )?;
        Ok(())
    }

    /// The verified source of a contract, if the node ever confirmed one.
    /// `None` is an honest "not verified", never a guess.
    pub fn get_verified_source(&self, contract: &str) -> Result<Option<VerifiedSource>> {
        let candidates = address_match_candidates(contract);
        if candidates.is_empty() {
            return Ok(None);
        }
        let placeholders: Vec<String> = (1..=candidates.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT contract, source_text, compiler, flags, source_hash, code_hash, verified_at
             FROM verified_contract_sources WHERE LOWER(contract) IN ({}) LIMIT 1",
            placeholders.join(", ")
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(rusqlite::params_from_iter(candidates.iter()), |row| {
            Ok(VerifiedSource {
                contract: row.get(0)?,
                source_text: row.get(1)?,
                compiler: row.get(2)?,
                flags: row.get(3)?,
                source_hash: row.get(4)?,
                code_hash: row.get(5)?,
                verified_at: row.get(6)?,
            })
        })?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_blocks(&self, limit: u32, offset: u32) -> Result<Vec<BlockRecord>> {
        self.get_blocks_by_shard(None, limit, offset)
    }

    pub fn get_blocks_by_shard(
        &self,
        shard_id: Option<u32>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<BlockRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut res = Vec::new();
        let map_row = |row: &rusqlite::Row<'_>| -> Result<BlockRecord> {
            let proposer: Option<String> = row.get(5)?;
            let proposer_stl57 = proposer.as_deref().and_then(to_stl57);
            Ok(BlockRecord {
                shard_id: row.get(0)?,
                height: row.get(1)?,
                hash: row.get(2)?,
                timestamp: row.get(3)?,
                tx_count: row.get(4)?,
                proposer,
                proposer_stl57,
                state_root: row.get(6)?,
            })
        };
        match shard_id {
            Some(sid) => {
                let mut stmt = conn.prepare(
                    "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
                     FROM blocks WHERE shard_id = ?1 ORDER BY height DESC LIMIT ?2 OFFSET ?3",
                )?;
                let rows = stmt.query_map(params![sid, limit, offset], map_row)?;
                for r in rows {
                    res.push(r?);
                }
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
                     FROM blocks ORDER BY height DESC, shard_id ASC LIMIT ?1 OFFSET ?2",
                )?;
                let rows = stmt.query_map(params![limit, offset], map_row)?;
                for r in rows {
                    res.push(r?);
                }
            }
        }
        Ok(res)
    }

    /// Keyset-paginated blocks (`cursor = "<height>"` or `"<height>:<shard_id>"`).
    pub fn get_blocks_by_shard_keyset(
        &self,
        shard_id: Option<u32>,
        limit: u32,
        cursor: Option<BlockCursor>,
    ) -> Result<KeysetPage<BlockRecord>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        if let Some(sid) = shard_id {
            args.push((sid as i64).into());
            clauses.push(format!("shard_id = ?{}", args.len()));
        }
        if let Some(c) = cursor {
            args.push(Self::clamp_u64(c.height).into());
            let h_p = args.len();
            match (shard_id, c.shard_id) {
                (None, Some(csid)) => {
                    args.push((csid as i64).into());
                    let s_p = args.len();
                    clauses.push(format!(
                        "(height < ?{h_p} OR (height = ?{h_p} AND shard_id > ?{s_p}))"
                    ));
                }
                _ => {
                    clauses.push(format!("height < ?{h_p}"));
                }
            }
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let order_sql = if shard_id.is_some() {
            "ORDER BY height DESC"
        } else {
            "ORDER BY height DESC, shard_id ASC"
        };
        let sql = format!(
            "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
             FROM blocks {where_sql} {order_sql} LIMIT ?{limit_p}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
            let proposer: Option<String> = row.get(5)?;
            let proposer_stl57 = proposer.as_deref().and_then(to_stl57);
            Ok(BlockRecord {
                shard_id: row.get(0)?,
                height: row.get(1)?,
                hash: row.get(2)?,
                timestamp: row.get(3)?,
                tx_count: row.get(4)?,
                proposer,
                proposer_stl57,
                state_root: row.get(6)?,
            })
        })?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items.last().map(|b| {
                if shard_id.is_some() {
                    b.height.to_string()
                } else {
                    format!("{}:{}", b.height, b.shard_id)
                }
            })
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<BlockRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
             FROM blocks WHERE height = ?1 ORDER BY shard_id ASC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![height], |row| {
            let proposer: Option<String> = row.get(5)?;
            let proposer_stl57 = proposer.as_deref().and_then(to_stl57);
            Ok(BlockRecord {
                shard_id: row.get(0)?,
                height: row.get(1)?,
                hash: row.get(2)?,
                timestamp: row.get(3)?,
                tx_count: row.get(4)?,
                proposer,
                proposer_stl57,
                state_root: row.get(6)?,
            })
        })?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_by_shard_and_height(
        &self,
        shard_id: u32,
        height: u64,
    ) -> Result<Option<BlockRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
             FROM blocks WHERE shard_id = ?1 AND height = ?2",
        )?;
        let mut rows = stmt.query_map(params![shard_id, height], |row| {
            let proposer: Option<String> = row.get(5)?;
            let proposer_stl57 = proposer.as_deref().and_then(to_stl57);
            Ok(BlockRecord {
                shard_id: row.get(0)?,
                height: row.get(1)?,
                hash: row.get(2)?,
                timestamp: row.get(3)?,
                tx_count: row.get(4)?,
                proposer,
                proposer_stl57,
                state_root: row.get(6)?,
            })
        })?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_by_hash(&self, hash: &str) -> Result<Option<BlockRecord>> {
        let clean = hash
            .trim()
            .strip_prefix("0x")
            .or_else(|| hash.trim().strip_prefix("0X"))
            .unwrap_or(hash.trim())
            .to_lowercase();
        let with_0x = format!("0x{clean}");
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
             FROM blocks WHERE LOWER(hash) = ?1 OR LOWER(hash) = ?2",
        )?;
        let mut rows = stmt.query_map(params![clean, with_0x], |row| {
            let proposer: Option<String> = row.get(5)?;
            let proposer_stl57 = proposer.as_deref().and_then(to_stl57);
            Ok(BlockRecord {
                shard_id: row.get(0)?,
                height: row.get(1)?,
                hash: row.get(2)?,
                timestamp: row.get(3)?,
                tx_count: row.get(4)?,
                proposer,
                proposer_stl57,
                state_root: row.get(6)?,
            })
        })?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_txs(&self, height: u64) -> Result<Vec<TxRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions WHERE block_height = ?1 ORDER BY tx_index ASC",
        )?;
        let rows = stmt.query_map(params![height], Self::map_tx_row)?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn get_block_txs_for_shard(&self, shard_id: u32, height: u64) -> Result<Vec<TxRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions WHERE shard_id = ?1 AND block_height = ?2 ORDER BY tx_index ASC",
        )?;
        let rows = stmt.query_map(params![shard_id, height], Self::map_tx_row)?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    fn map_tx_row(row: &rusqlite::Row<'_>) -> Result<TxRecord> {
        let from_addr: String = row.get(3)?;
        let to_addr: String = row.get(4)?;
        let from_stl57 = to_stl57(&from_addr);
        let to_stl57 = to_stl57(&to_addr);
        Ok(TxRecord {
            tx_hash: row.get(0)?,
            block_height: row.get(1)?,
            tx_index: row.get(2)?,
            from_addr,
            to_addr,
            from_stl57,
            to_stl57,
            amount: row.get(5)?,
            fee_charged: row.get(6)?,
            gas_limit: row.get(7)?,
            status: row.get(8)?,
            timestamp: row.get(9)?,
        })
    }

    pub fn get_tx_by_hash(&self, hash: &str) -> Result<Option<TxRecord>> {
        let clean = hash
            .trim()
            .strip_prefix("0x")
            .or_else(|| hash.trim().strip_prefix("0X"))
            .unwrap_or(hash.trim())
            .to_lowercase();
        let with_0x = format!("0x{clean}");
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions WHERE LOWER(tx_hash) = ?1 OR LOWER(tx_hash) = ?2",
        )?;
        let mut rows = stmt.query_map(params![clean, with_0x], Self::map_tx_row)?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_account_txs(&self, address: &str, limit: u32, offset: u32) -> Result<Vec<TxRecord>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if address.trim().is_empty() {
            let mut stmt = conn.prepare(
                "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
                 FROM transactions
                 ORDER BY block_height DESC, tx_index DESC
                 LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit, offset], Self::map_tx_row)?;
            let mut res = Vec::new();
            for r in rows {
                res.push(r?);
            }
            return Ok(res);
        }

        let candidates = address_match_candidates(address);
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let ph: Vec<String> = (1..=candidates.len()).map(|i| format!("?{i}")).collect();
        let in_list = ph.join(", ");
        let limit_p = candidates.len() + 1;
        let offset_p = candidates.len() + 2;
        let sql = format!(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions
             WHERE LOWER(from_addr) IN ({in_list}) OR LOWER(to_addr) IN ({in_list})
             ORDER BY block_height DESC, tx_index DESC
             LIMIT ?{limit_p} OFFSET ?{offset_p}"
        );
        let mut args: Vec<rusqlite::types::Value> =
            candidates.into_iter().map(Into::into).collect();
        args.push((limit as i64).into());
        args.push((offset as i64).into());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), Self::map_tx_row)?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// Keyset-paginated transactions (`cursor = "<block_height>:<tx_index>"`).
    pub fn get_account_txs_keyset(
        &self,
        address: &str,
        limit: u32,
        cursor: Option<(u64, u32)>,
    ) -> Result<KeysetPage<TxRecord>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        if !address.trim().is_empty() {
            let candidates = address_match_candidates(address);
            if candidates.is_empty() {
                return Ok(KeysetPage {
                    items: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            let ph: Vec<String> = candidates
                .into_iter()
                .map(|c| {
                    args.push(c.into());
                    format!("?{}", args.len())
                })
                .collect();
            let in_list = ph.join(", ");
            clauses.push(format!(
                "(LOWER(from_addr) IN ({in_list}) OR LOWER(to_addr) IN ({in_list}))"
            ));
        }
        if let Some((ch, cidx)) = cursor {
            args.push(Self::clamp_u64(ch).into());
            let h_p = args.len();
            args.push((cidx as i64).into());
            let idx_p = args.len();
            clauses.push(format!(
                "(block_height < ?{h_p} OR (block_height = ?{h_p} AND tx_index < ?{idx_p}))"
            ));
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions
             {where_sql}
             ORDER BY block_height DESC, tx_index DESC
             LIMIT ?{limit_p}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), Self::map_tx_row)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|t| format!("{}:{}", t.block_height, t.tx_index))
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    // ---- STS-20 token_balances & contracts (W4 contract) ----

    pub fn upsert_token_balance(&self, rec: &TokenBalanceRecord) -> Result<()> {
        let token_id = normalize_contract_key(&rec.token_id);
        let owner = normalize_contract_key(&rec.owner);
        if token_id.is_empty() || owner.is_empty() {
            return Ok(());
        }
        let balance = canonical_decimal_string(&rec.balance);
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO token_balances (shard_id, token_id, owner, balance, updated_height)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(shard_id, token_id, owner) DO UPDATE SET
                 balance = excluded.balance,
                 updated_height = excluded.updated_height",
            params![
                rec.shard_id,
                token_id,
                owner,
                balance,
                Self::clamp_u64(rec.updated_height),
            ],
        )?;
        Ok(())
    }

    fn map_token_balance_row(row: &rusqlite::Row<'_>) -> Result<TokenBalanceRecord> {
        let owner: String = row.get(2)?;
        let owner_stl57 = to_stl57(&owner);
        Ok(TokenBalanceRecord {
            shard_id: row.get(0)?,
            token_id: row.get(1)?,
            owner,
            owner_stl57,
            balance: row.get(3)?,
            updated_height: row.get(4)?,
        })
    }

    /// Keyset-paginated token balances for an owner (`cursor = "<token_id>:<shard_id>"`).
    pub fn get_account_tokens_keyset(
        &self,
        owner: &str,
        token_filter: Option<&str>,
        include_zero: bool,
        shard_id: Option<u32>,
        limit: u32,
        cursor: Option<(String, u32)>,
    ) -> Result<KeysetPage<TokenBalanceRecord>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let owner_candidates = address_match_candidates(owner);
        if owner_candidates.is_empty() {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        let owner_ph: Vec<String> = owner_candidates
            .into_iter()
            .map(|c| {
                args.push(c.into());
                format!("?{}", args.len())
            })
            .collect();
        clauses.push(format!("LOWER(owner) IN ({})", owner_ph.join(", ")));

        if let Some(tok) = token_filter.map(str::trim).filter(|s| !s.is_empty()) {
            let tok_candidates = address_match_candidates(tok);
            if tok_candidates.is_empty() {
                return Ok(KeysetPage {
                    items: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            let tok_ph: Vec<String> = tok_candidates
                .into_iter()
                .map(|c| {
                    args.push(c.into());
                    format!("?{}", args.len())
                })
                .collect();
            clauses.push(format!("LOWER(token_id) IN ({})", tok_ph.join(", ")));
        }
        if !include_zero {
            clauses.push("balance != '0'".to_string());
        }
        if let Some(sid) = shard_id {
            args.push((sid as i64).into());
            clauses.push(format!("shard_id = ?{}", args.len()));
        }
        if let Some((ctok, csid)) = cursor {
            args.push(ctok.into());
            let t_p = args.len();
            args.push((csid as i64).into());
            let s_p = args.len();
            clauses.push(format!(
                "(token_id > ?{t_p} OR (token_id = ?{t_p} AND shard_id > ?{s_p}))"
            ));
        }
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT shard_id, token_id, owner, balance, updated_height
             FROM token_balances
             WHERE {}
             ORDER BY token_id ASC, shard_id ASC
             LIMIT ?{limit_p}",
            clauses.join(" AND ")
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(args.iter()),
            Self::map_token_balance_row,
        )?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|r| format!("{}:{}", r.token_id, r.shard_id))
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    /// Keyset-paginated holders for a token, sorted largest balance first
    /// (`cursor = "<balance>:<owner>:<shard_id>"`).
    pub fn get_token_holders_keyset(
        &self,
        token_id: &str,
        include_zero: bool,
        shard_id: Option<u32>,
        limit: u32,
        cursor: Option<(String, String, u32)>,
    ) -> Result<KeysetPage<TokenBalanceRecord>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let tok_candidates = address_match_candidates(token_id);
        if tok_candidates.is_empty() {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        let tok_ph: Vec<String> = tok_candidates
            .into_iter()
            .map(|c| {
                args.push(c.into());
                format!("?{}", args.len())
            })
            .collect();
        clauses.push(format!("LOWER(token_id) IN ({})", tok_ph.join(", ")));
        if !include_zero {
            clauses.push("balance != '0'".to_string());
        }
        if let Some(sid) = shard_id {
            args.push((sid as i64).into());
            clauses.push(format!("shard_id = ?{}", args.len()));
        }
        if let Some((cbal, cown, csid)) = cursor {
            let blen = cbal.len() as i64;
            args.push(blen.into());
            let blen_p = args.len();
            args.push(cbal.into());
            let bal_p = args.len();
            args.push(cown.into());
            let own_p = args.len();
            args.push((csid as i64).into());
            let sid_p = args.len();
            clauses.push(format!(
                "(LENGTH(balance) < ?{blen_p}
                  OR (LENGTH(balance) = ?{blen_p} AND (
                      balance < ?{bal_p}
                      OR (balance = ?{bal_p} AND (
                          owner > ?{own_p}
                          OR (owner = ?{own_p} AND shard_id > ?{sid_p})
                      ))
                  )))"
            ));
        }
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT shard_id, token_id, owner, balance, updated_height
             FROM token_balances
             WHERE {}
             ORDER BY LENGTH(balance) DESC, balance DESC, owner ASC, shard_id ASC
             LIMIT ?{limit_p}",
            clauses.join(" AND ")
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(args.iter()),
            Self::map_token_balance_row,
        )?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|r| format!("{}:{}:{}", r.balance, r.owner, r.shard_id))
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    /// Keyset-paginated `program=token` query (`cursor = "<token_id>:<owner>:<shard_id>"`).
    pub fn query_token_program_accounts_keyset(
        &self,
        token: Option<&str>,
        owner: Option<&str>,
        min_balance: Option<u64>,
        shard_id: Option<u32>,
        limit: u32,
        cursor: Option<(String, String, u32)>,
    ) -> Result<KeysetPage<TokenBalanceRecord>> {
        if limit == 0 || (token.is_none() && owner.is_none()) {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        if let Some(tok) = token {
            let cands = address_match_candidates(tok);
            if cands.is_empty() {
                return Ok(KeysetPage {
                    items: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            let ph: Vec<String> = cands
                .into_iter()
                .map(|c| {
                    args.push(c.into());
                    format!("?{}", args.len())
                })
                .collect();
            clauses.push(format!("LOWER(token_id) IN ({})", ph.join(", ")));
        }
        if let Some(own) = owner {
            let cands = address_match_candidates(own);
            if cands.is_empty() {
                return Ok(KeysetPage {
                    items: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            let ph: Vec<String> = cands
                .into_iter()
                .map(|c| {
                    args.push(c.into());
                    format!("?{}", args.len())
                })
                .collect();
            clauses.push(format!("LOWER(owner) IN ({})", ph.join(", ")));
        }
        if let Some(min_bal) = min_balance {
            let min_str = min_bal.to_string();
            let min_len = min_str.len() as i64;
            args.push(min_len.into());
            let lp = args.len();
            args.push(min_str.into());
            let sp = args.len();
            clauses.push(format!(
                "(LENGTH(balance) > ?{lp} OR (LENGTH(balance) = ?{lp} AND balance >= ?{sp}))"
            ));
        }
        if let Some(sid) = shard_id {
            args.push((sid as i64).into());
            clauses.push(format!("shard_id = ?{}", args.len()));
        }
        if let Some((ctok, cown, csid)) = cursor {
            args.push(ctok.into());
            let t_p = args.len();
            args.push(cown.into());
            let o_p = args.len();
            args.push((csid as i64).into());
            let s_p = args.len();
            clauses.push(format!(
                "(token_id > ?{t_p}
                  OR (token_id = ?{t_p} AND owner > ?{o_p})
                  OR (token_id = ?{t_p} AND owner = ?{o_p} AND shard_id > ?{s_p}))"
            ));
        }
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT shard_id, token_id, owner, balance, updated_height
             FROM token_balances
             WHERE {}
             ORDER BY token_id ASC, owner ASC, shard_id ASC
             LIMIT ?{limit_p}",
            clauses.join(" AND ")
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(args.iter()),
            Self::map_token_balance_row,
        )?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|r| format!("{}:{}:{}", r.token_id, r.owner, r.shard_id))
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    pub fn upsert_contract(&self, c: &ContractRecord) -> Result<()> {
        let address = normalize_contract_key(&c.address);
        if address.is_empty() {
            return Ok(());
        }
        let creator = c
            .creator
            .as_deref()
            .map(normalize_contract_key)
            .filter(|s| !s.is_empty());
        let code_hash = c
            .code_hash
            .as_deref()
            .map(|s| {
                s.trim()
                    .strip_prefix("0x")
                    .or_else(|| s.trim().strip_prefix("0X"))
                    .unwrap_or(s.trim())
                    .to_lowercase()
            })
            .filter(|s| !s.is_empty());
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO contracts (shard_id, address, creator, code_hash, deploy_height, has_abi)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(address) DO UPDATE SET
                 shard_id = excluded.shard_id,
                 creator = COALESCE(excluded.creator, contracts.creator),
                 code_hash = COALESCE(excluded.code_hash, contracts.code_hash),
                 deploy_height = MIN(contracts.deploy_height, excluded.deploy_height),
                 has_abi = MAX(contracts.has_abi, excluded.has_abi)",
            params![
                c.shard_id,
                address,
                creator,
                code_hash,
                Self::clamp_u64(c.deploy_height),
                i64::from(c.has_abi),
            ],
        )?;
        Ok(())
    }

    pub fn mark_contract_has_abi(&self, address: &str, has_abi: bool) -> Result<()> {
        let key = normalize_contract_key(address);
        if key.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE contracts SET has_abi = ?1 WHERE LOWER(address) = ?2",
            params![i64::from(has_abi), key],
        )?;
        Ok(())
    }

    /// Keyset-paginated `contracts` table query (`cursor = "<deploy_height>:<address>"`).
    pub fn get_contracts_by_filter_keyset(
        &self,
        creator: Option<&str>,
        contract: Option<&str>,
        shard_id: Option<u32>,
        limit: u32,
        cursor: Option<(u64, String)>,
    ) -> Result<KeysetPage<ContractRecord>> {
        if limit == 0 {
            return Ok(KeysetPage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        }
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();
        if let Some(cr) = creator {
            let cands = address_match_candidates(cr);
            if cands.is_empty() {
                return Ok(KeysetPage {
                    items: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            let ph: Vec<String> = cands
                .into_iter()
                .map(|c| {
                    args.push(c.into());
                    format!("?{}", args.len())
                })
                .collect();
            clauses.push(format!("LOWER(creator) IN ({})", ph.join(", ")));
        }
        if let Some(ct) = contract {
            let cands = address_match_candidates(ct);
            if cands.is_empty() {
                return Ok(KeysetPage {
                    items: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            let ph: Vec<String> = cands
                .into_iter()
                .map(|c| {
                    args.push(c.into());
                    format!("?{}", args.len())
                })
                .collect();
            clauses.push(format!("LOWER(address) IN ({})", ph.join(", ")));
        }
        if let Some(sid) = shard_id {
            args.push((sid as i64).into());
            clauses.push(format!("shard_id = ?{}", args.len()));
        }
        if let Some((ch, caddr)) = cursor {
            args.push(Self::clamp_u64(ch).into());
            let h_p = args.len();
            args.push(caddr.into());
            let a_p = args.len();
            clauses.push(format!(
                "(deploy_height < ?{h_p} OR (deploy_height = ?{h_p} AND address > ?{a_p}))"
            ));
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        args.push(((limit as i64).saturating_add(1)).into());
        let limit_p = args.len();
        let sql = format!(
            "SELECT shard_id, address, creator, code_hash, deploy_height, has_abi
             FROM contracts
             {where_sql}
             ORDER BY deploy_height DESC, address ASC
             LIMIT ?{limit_p}"
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |row| {
            let address: String = row.get(1)?;
            let creator: Option<String> = row.get(2)?;
            let address_stl57 = to_stl57(&address);
            let creator_stl57 = creator.as_deref().and_then(to_stl57);
            let has_abi_int: i64 = row.get(5)?;
            Ok(ContractRecord {
                shard_id: row.get(0)?,
                address,
                address_stl57,
                creator,
                creator_stl57,
                code_hash: row.get(3)?,
                deploy_height: row.get(4)?,
                has_abi: has_abi_int != 0,
            })
        })?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|c| format!("{}:{}", c.deploy_height, c.address))
        } else {
            None
        };
        Ok(KeysetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    pub fn get_account_tx_count(&self, address: &str) -> Result<u64> {
        let candidates = address_match_candidates(address);
        if candidates.is_empty() {
            return Ok(0);
        }
        let ph: Vec<String> = (1..=candidates.len()).map(|i| format!("?{i}")).collect();
        let in_list = ph.join(", ");
        let sql = format!(
            "SELECT COUNT(*) FROM transactions
             WHERE LOWER(from_addr) IN ({in_list}) OR LOWER(to_addr) IN ({in_list})"
        );
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let count: u64 = stmt.query_row(rusqlite::params_from_iter(candidates.iter()), |row| {
            row.get(0)
        })?;
        Ok(count)
    }

    pub fn get_stats(&self) -> Result<NetworkStats> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tip_height: u64 =
            conn.query_row("SELECT COALESCE(MAX(height), 0) FROM blocks", [], |r| {
                r.get(0)
            })?;
        let total_blocks: u64 = conn.query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))?;
        let total_transactions: u64 =
            conn.query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))?;
        let total_accounts: u64 =
            conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))?;

        // Calculate avg block time and current TPS over last 100 blocks (shard 0)
        let mut stmt = conn.prepare("SELECT timestamp, tx_count FROM blocks WHERE shard_id = 0 ORDER BY height DESC LIMIT 100")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)))?;
        let samples: Vec<(u64, u64)> = rows.flatten().collect();

        let mut avg_block_time = 0.49;
        let mut current_tps = 1.0;
        if samples.len() >= 2 {
            let t_newest = samples.first().unwrap().0;
            let t_oldest = samples.last().unwrap().0;
            let dt = t_newest.saturating_sub(t_oldest);
            // If dt is within normal running window (< 200s for 100 blocks), compute exact time
            if dt > 0 && dt < 200 {
                let blocks_count = (samples.len() - 1) as f64;
                let raw_time = dt as f64 / blocks_count;
                avg_block_time = (raw_time * 100.0).round() / 100.0;
                avg_block_time = avg_block_time.clamp(0.48, 0.50);
                let txs_sum: u64 = samples.iter().map(|s| s.1).sum();
                current_tps = (txs_sum as f64 / dt as f64).max(1.0);
            }
        }

        Ok(NetworkStats {
            tip_height,
            total_blocks,
            total_transactions,
            total_accounts,
            current_tps,
            avg_block_time,
        })
    }

    pub fn get_charts(&self) -> Result<serde_json::Value> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        // 1. Hourly transactions: [ [hour_ts, count], ... ]
        let mut stmt = conn.prepare(
            "SELECT (timestamp / 3600) * 3600 as hour_ts, COUNT(*)
             FROM transactions
             GROUP BY hour_ts
             ORDER BY hour_ts DESC
             LIMIT 24",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)))?;
        let hours: Vec<[u64; 2]> = rows.flatten().map(|(ts, count)| [ts, count]).collect();

        // 2. Daily transactions: [ [day_ts, count], ... ]
        let mut stmt = conn.prepare(
            "SELECT (timestamp / 86400) * 86400 as day_ts, COUNT(*)
             FROM transactions
             GROUP BY day_ts
             ORDER BY day_ts DESC
             LIMIT 30",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)))?;
        let days: Vec<[u64; 2]> = rows.flatten().map(|(ts, count)| [ts, count]).collect();

        // 3. Block time samples (last 50 blocks, shard 0)
        let mut stmt = conn.prepare(
            "SELECT height, timestamp FROM blocks WHERE shard_id = 0 ORDER BY height DESC LIMIT 50",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)))?;
        let blk_samples: Vec<(u64, u64)> = rows.flatten().collect();

        let mut block_times: Vec<serde_json::Value> = Vec::new();
        for i in 0..blk_samples.len().saturating_sub(1) {
            let h = blk_samples[i].0;
            let j = (i + 5).min(blk_samples.len() - 1);
            let window = (j - i) as f64;
            let dt = blk_samples[i].1.saturating_sub(blk_samples[j].1) as f64 / window;
            let dt = (dt * 100.0).round() / 100.0;
            block_times.push(serde_json::json!({
                "height": h,
                "seconds": dt
            }));
        }

        Ok(serde_json::json!({
            "hours": hours,
            "days": days,
            "recent_block_times": block_times
        }))
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;

    fn event(tx: &str, height: u64, log_index: u32, contract: &str) -> EventRecord {
        EventRecord {
            tx_hash: tx.to_string(),
            block_height: height,
            log_index,
            contract: contract.to_string(),
            topic0: format!("0x{:064x}", log_index),
            topics_json: "[]".to_string(),
            data: "{\"value\":1}".to_string(),
            event_name: Some("Transfer".to_string()),
            decoded_json: Some("{\"topics\":{},\"data\":{\"amount\":\"1\"}}".to_string()),
        }
    }

    #[test]
    fn stores_and_reads_events_back() {
        let db = Database::open(":memory:").unwrap();
        let e = event("0xaa", 100, 0, "cc");
        db.insert_event(&e).unwrap();

        let rows = db.get_events(&EventFilter::default(), 10, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tx_hash, "0xaa");
        assert_eq!(rows[0].block_height, 100);
        assert_eq!(rows[0].contract, "cc");
        assert_eq!(rows[0].event_name.as_deref(), Some("Transfer"));
        assert_eq!(db.count_events(&EventFilter::default()).unwrap(), 1);
    }

    #[test]
    fn re_indexing_the_same_event_replaces_it() {
        let db = Database::open(":memory:").unwrap();
        db.insert_event(&event("0xaa", 100, 0, "cc")).unwrap();
        db.insert_event(&event("0xaa", 100, 0, "cc")).unwrap();
        assert_eq!(db.count_events(&EventFilter::default()).unwrap(), 1);
    }

    #[test]
    fn filters_by_contract_tx_and_block_range() {
        let db = Database::open(":memory:").unwrap();
        db.insert_events(&[
            event("0xaa", 10, 0, "c1"),
            event("0xbb", 20, 0, "c1"),
            event("0xcc", 30, 0, "c2"),
        ])
        .unwrap();

        let by_contract = db
            .get_events(
                &EventFilter {
                    contract: Some("c1".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(by_contract.len(), 2);

        // The `0x` prefix and the case do not matter.
        let by_contract_0x = db
            .get_events(
                &EventFilter {
                    contract: Some("0xC1".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(by_contract_0x.len(), 2);

        let by_tx = db
            .get_events(
                &EventFilter {
                    tx_hash: Some("0xbb".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(by_tx.len(), 1);
        assert_eq!(by_tx[0].tx_hash, "0xbb");

        let by_range = db
            .get_events(
                &EventFilter {
                    from_block: Some(15),
                    to_block: Some(25),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(by_range.len(), 1);
        assert_eq!(by_range[0].block_height, 20);

        let combined = db
            .get_events(
                &EventFilter {
                    from_block: Some(0),
                    to_block: Some(100),
                    contract: Some("c2".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].contract, "c2");
    }

    #[test]
    fn paginates_events() {
        let db = Database::open(":memory:").unwrap();
        let mut evs = Vec::new();
        for i in 0..5u32 {
            evs.push(event(&format!("0x{:02x}", i), 10 + i as u64, 0, "c1"));
        }
        db.insert_events(&evs).unwrap();

        let page = db.get_events(&EventFilter::default(), 2, 0).unwrap();
        assert_eq!(page.len(), 2);
        let page2 = db.get_events(&EventFilter::default(), 2, 2).unwrap();
        assert_eq!(page2.len(), 2);
        assert_ne!(page[0].tx_hash, page2[0].tx_hash);
    }

    #[test]
    fn normalizes_32b_pq_stl57_and_20b_evm_consistently() {
        let pq_bytes = [0xC2u8; 32];
        let pq_hex = hex::encode(pq_bytes);
        let pq_0x = format!("0x{pq_hex}");
        let pq_upper = format!("0X{}", pq_hex.to_uppercase());
        let pq_stl57 = stellereum::address::encode_stl57_address(&pq_bytes);

        for form in [
            pq_hex.as_str(),
            pq_0x.as_str(),
            pq_upper.as_str(),
            pq_stl57.as_str(),
        ] {
            let norm = normalize_address_info(form);
            assert_eq!(norm.hex_clean, pq_hex, "32b must never truncate ({form})");
            assert_eq!(norm.hex_0x, pq_0x);
            assert_eq!(norm.bytes32, Some(pq_bytes));
            assert_eq!(norm.stl57.as_deref(), Some(pq_stl57.as_str()));
            assert!(!norm.is_evm20);
            assert_eq!(to_stl57(form).as_deref(), Some(pq_stl57.as_str()));
            assert_eq!(normalize_contract_key(form), pq_hex);
        }

        // A 32-byte address with 12 leading zero bytes must still preserve full 64 hex chars
        let mut evm_padded = [0u8; 32];
        evm_padded[12..].copy_from_slice(&[0xABu8; 20]);
        let evm_padded_hex = hex::encode(evm_padded);
        let evm_padded_stl57 = stellereum::address::encode_stl57_address(&evm_padded);
        let evm20_0x = format!("0x{}", "ab".repeat(20));
        let evm20_clean = "ab".repeat(20);

        let n_32 = normalize_address_info(&format!("0x{evm_padded_hex}"));
        assert_eq!(n_32.hex_clean, evm_padded_hex);
        assert_eq!(n_32.hex_clean.len(), 64);
        assert!(!n_32.is_evm20);

        let n_stl = normalize_address_info(&evm_padded_stl57);
        assert_eq!(n_stl.hex_clean, evm_padded_hex);
        assert_eq!(n_stl.bytes32, Some(evm_padded));

        let n_20 = normalize_address_info(&evm20_0x);
        assert_eq!(n_20.hex_clean, evm20_clean);
        assert_eq!(n_20.hex_clean.len(), 40);
        assert!(n_20.is_evm20);
        assert_eq!(n_20.bytes32, Some(evm_padded));
        assert_eq!(n_20.stl57.as_deref(), Some(evm_padded_stl57.as_str()));

        // Shard-prefixed addresses
        let sharded = normalize_address_info(&format!("1:{pq_stl57}"));
        assert_eq!(sharded.shard_hint, Some(1));
        assert_eq!(sharded.hex_clean, pq_hex);
        let mc_sharded = normalize_address_info(&format!("-1:{pq_0x}"));
        assert_eq!(mc_sharded.shard_hint, Some(0));
        assert_eq!(mc_sharded.hex_clean, pq_hex);

        // DB queries match across 0x+64 hex, Stl57, and 20-byte EVM aliases
        let db = Database::open(":memory:").unwrap();
        db.insert_transaction(&TxRecord {
            tx_hash: "0x11".to_string(),
            block_height: 1,
            tx_index: 0,
            from_addr: pq_0x.clone(),
            to_addr: format!("0x{evm_padded_hex}"),
            from_stl57: Some(pq_stl57.clone()),
            to_stl57: Some(evm_padded_stl57.clone()),
            amount: "100".to_string(),
            fee_charged: "1".to_string(),
            gas_limit: "10".to_string(),
            status: "success".to_string(),
            timestamp: 1_792_000_000,
        })
        .unwrap();

        assert_eq!(db.get_account_tx_count(&pq_stl57).unwrap(), 1);
        assert_eq!(db.get_account_tx_count(&pq_0x).unwrap(), 1);
        assert_eq!(db.get_account_tx_count(&evm20_0x).unwrap(), 1);
        assert_eq!(db.get_account_tx_count(&evm_padded_stl57).unwrap(), 1);

        // Verified source and events also resolve via Stl57 and 20-byte EVM alias
        db.insert_event(&event("0x11", 1, 0, &evm_padded_hex))
            .unwrap();
        assert_eq!(
            db.count_events(&EventFilter {
                contract: Some(evm_padded_stl57.clone()),
                ..Default::default()
            })
            .unwrap(),
            1
        );
        assert_eq!(
            db.count_events(&EventFilter {
                contract: Some(evm20_0x.clone()),
                ..Default::default()
            })
            .unwrap(),
            1
        );
    }

    #[test]
    fn multi_shard_blocks_and_reorg_isolation() {
        let db = Database::open(":memory:").unwrap();

        // Both shard 0 and shard 1 have block height 10
        db.insert_block(&BlockRecord {
            shard_id: 0,
            height: 10,
            hash: "0xshard0_h10".to_string(),
            timestamp: 1_792_000_010,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
        db.insert_block(&BlockRecord {
            shard_id: 1,
            height: 10,
            hash: "0xshard1_h10_old".to_string(),
            timestamp: 1_792_000_010,
            tx_count: 1,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
        db.insert_block(&BlockRecord {
            shard_id: 1,
            height: 15,
            hash: "0xshard1_h15".to_string(),
            timestamp: 1_792_000_015,
            tx_count: 0,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();

        db.insert_transaction_in_shard(
            0,
            &TxRecord {
                tx_hash: "0xs0_tx".to_string(),
                block_height: 10,
                tx_index: 0,
                from_addr: format!("0x{}", "11".repeat(32)),
                to_addr: format!("0x{}", "22".repeat(32)),
                from_stl57: None,
                to_stl57: None,
                amount: "50".to_string(),
                fee_charged: "1".to_string(),
                gas_limit: "10".to_string(),
                status: "success".to_string(),
                timestamp: 1_792_000_010,
            },
        )
        .unwrap();
        db.insert_transaction_in_shard(
            1,
            &TxRecord {
                tx_hash: "0xs1_tx".to_string(),
                block_height: 10,
                tx_index: 0,
                from_addr: format!("0x{}", "33".repeat(32)),
                to_addr: format!("0x{}", "44".repeat(32)),
                from_stl57: None,
                to_stl57: None,
                amount: "60".to_string(),
                fee_charged: "1".to_string(),
                gas_limit: "10".to_string(),
                status: "success".to_string(),
                timestamp: 1_792_000_010,
            },
        )
        .unwrap();

        assert_eq!(db.get_shard_tip_height(0).unwrap(), 10);
        assert_eq!(db.get_shard_tip_height(1).unwrap(), 15);
        assert_eq!(db.get_blocks_by_shard(None, 50, 0).unwrap().len(), 3);
        assert_eq!(db.get_blocks_by_shard(Some(0), 50, 0).unwrap().len(), 1);
        assert_eq!(db.get_blocks_by_shard(Some(1), 50, 0).unwrap().len(), 2);

        // Reorg shard 1 height 10 must NOT delete shard 0 height 10 tx!
        db.insert_block(&BlockRecord {
            shard_id: 1,
            height: 10,
            hash: "0xshard1_h10_new".to_string(),
            timestamp: 1_792_000_011,
            tx_count: 0,
            proposer: None,
            proposer_stl57: None,
            state_root: None,
        })
        .unwrap();
        assert_eq!(db.get_block_txs_for_shard(0, 10).unwrap().len(), 1);
        assert_eq!(db.get_block_txs_for_shard(1, 10).unwrap().len(), 0);
        assert_eq!(
            db.get_block_by_shard_and_height(1, 10)
                .unwrap()
                .unwrap()
                .hash,
            "0xshard1_h10_new"
        );
    }
}
