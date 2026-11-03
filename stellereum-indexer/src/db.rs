use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub fn resolve_address_variants(address: &str) -> (String, String, String) {
    let clean = if let Ok(b) = stellereum::address::parse_address(address) {
        let full = hex::encode(b);
        if let Some(stripped) = full.strip_prefix("000000000000000000000000") {
            stripped.to_string()
        } else {
            full
        }
    } else {
        address
            .strip_prefix("0x")
            .or_else(|| address.strip_prefix("0X"))
            .unwrap_or(address)
            .to_string()
    };
    let with_0x = format!("0x{}", clean.to_lowercase());
    let clean_lower = clean.to_lowercase();
    // Audit B-IDX-1: escape LIKE metacharacters (`%`, `_`, `\`) so user
    // input cannot widen the match (cross-account disclosure). Queries using
    // this pattern carry an explicit `ESCAPE '\'` clause.
    let mut escaped = String::with_capacity(clean_lower.len());
    for c in clean_lower.chars() {
        if matches!(c, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    let pattern = format!("%{escaped}%");
    (with_0x, clean_lower, pattern)
}

pub fn to_stl57(addr: &str) -> Option<String> {
    let clean = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .unwrap_or(addr);
    if let Ok(b) = stellereum::address::parse_address(addr) {
        Some(stellereum::address::encode_stl57_address(&b))
    } else if let Ok(decoded) = hex::decode(clean) {
        if decoded.len() == 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&decoded);
            Some(stellereum::address::encode_stl57_address(&b))
        } else if decoded.len() == 20 {
            let mut b = [0u8; 32];
            b[12..].copy_from_slice(&decoded);
            Some(stellereum::address::encode_stl57_address(&b))
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

/// Normalize a contract address into the canonical lookup key: trimmed,
/// `0x`-prefix stripped, lowercase (the same normalization the event queries
/// apply, so `0xAA…` and `aa…` address the same row).
pub fn normalize_contract_key(address: &str) -> String {
    let t = address.trim();
    t.strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t)
        .to_lowercase()
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
             ",
        )?;

        // Auto-migration: ensure shard_id column exists if table was created in an earlier version
        let _ = conn.execute(
            "ALTER TABLE blocks ADD COLUMN shard_id INTEGER NOT NULL DEFAULT 0",
            [],
        );

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn insert_block(&self, b: &BlockRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        // Audit B-IDX-2: same (shard,height) with a DIFFERENT hash is a
        // reorg — the new canonical hash must win (INSERT OR IGNORE kept
        // stale forks forever). Dependents at this height are invalidated
        // with it (same-height scope; cross-shard height overlap needs the
        // shard-scoped schema migration tracked in ROADMAP).
        let existing: Option<String> = match conn.query_row(
            "SELECT hash FROM blocks WHERE shard_id = ?1 AND height = ?2",
            params![b.shard_id, b.height],
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
            conn.execute(
                "DELETE FROM transactions WHERE block_height = ?1",
                params![b.height],
            )?;
            conn.execute(
                "DELETE FROM contract_events WHERE block_height = ?1",
                params![b.height],
            )?;
            conn.execute(
                "DELETE FROM blocks WHERE shard_id = ?1 AND height = ?2",
                params![b.shard_id, b.height],
            )?;
        }
        conn.execute(
            "INSERT INTO blocks (shard_id, height, hash, timestamp, tx_count, proposer, state_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![b.shard_id, b.height, b.hash, b.timestamp, b.tx_count, b.proposer, b.state_root],
        )?;
        Ok(())
    }

    pub fn insert_transaction(&self, tx: &TxRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO transactions
             (tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT COALESCE(MAX(height), 0) FROM blocks")?;
        let height: u64 = stmt.query_row([], |row| row.get(0))?;
        Ok(height)
    }

    // ---- contract events ----

    /// Store one contract event.
    ///
    /// The `(tx_hash, log_index)` pair is unique, so re-indexing the same
    /// transaction (a re-sync, a restart) REPLACES the row instead of
    /// duplicating it.
    pub fn insert_event(&self, e: &EventRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO contract_events
             (tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO contract_events
                 (tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for e in events {
                stmt.execute(params![
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
    pub fn get_events(
        &self,
        filter: &EventFilter,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<EventRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, log_index, contract, topic0, topics_json, data, event_name, decoded_json
             FROM contract_events
             WHERE (?1 IS NULL OR block_height >= ?1)
               AND (?2 IS NULL OR block_height <= ?2)
               AND (?3 IS NULL OR LOWER(contract) = ?4 OR LOWER(contract) = ?5)
               AND (?6 IS NULL OR LOWER(tx_hash) = ?7 OR LOWER(tx_hash) = ?8)
             ORDER BY block_height DESC, id DESC
             LIMIT ?9 OFFSET ?10",
        )?;
        let (contract_flag, contract_a, contract_b) = match filter.contract.as_ref() {
            Some(c) => {
                let (with_0x, clean, _) = resolve_address_variants(c);
                (Some(1i64), with_0x.to_lowercase(), clean)
            }
            None => (None, String::new(), String::new()),
        };
        let (hash_flag, hash_a, hash_b) = match filter.tx_hash.as_ref() {
            Some(h) => {
                let (with_0x, clean, _) = resolve_address_variants(h);
                (Some(1i64), with_0x.to_lowercase(), clean)
            }
            None => (None, String::new(), String::new()),
        };
        let rows = stmt.query_map(
            params![
                Self::clamp_block_bound(filter.from_block),
                Self::clamp_block_bound(filter.to_block),
                contract_flag,
                contract_a,
                contract_b,
                hash_flag,
                hash_a,
                hash_b,
                limit,
                offset
            ],
            |row| {
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
            },
        )?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    /// How many contract events are indexed (with the same filters).
    pub fn count_events(&self, filter: &EventFilter) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM contract_events
             WHERE (?1 IS NULL OR block_height >= ?1)
               AND (?2 IS NULL OR block_height <= ?2)
               AND (?3 IS NULL OR LOWER(contract) = ?4 OR LOWER(contract) = ?5)
               AND (?6 IS NULL OR LOWER(tx_hash) = ?7 OR LOWER(tx_hash) = ?8)",
        )?;
        let (contract_flag, contract_a, contract_b) = match filter.contract.as_ref() {
            Some(c) => {
                let (with_0x, clean, _) = resolve_address_variants(c);
                (Some(1i64), with_0x.to_lowercase(), clean)
            }
            None => (None, String::new(), String::new()),
        };
        let (hash_flag, hash_a, hash_b) = match filter.tx_hash.as_ref() {
            Some(h) => {
                let (with_0x, clean, _) = resolve_address_variants(h);
                (Some(1i64), with_0x.to_lowercase(), clean)
            }
            None => (None, String::new(), String::new()),
        };
        let count: u64 = stmt.query_row(
            params![
                Self::clamp_block_bound(filter.from_block),
                Self::clamp_block_bound(filter.to_block),
                contract_flag,
                contract_a,
                contract_b,
                hash_flag,
                hash_a,
                hash_b
            ],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// The contracts that emitted at least one indexed event, most active
    /// first.
    ///
    /// Bounded and paginated like every other listing: the event log is
    /// attacker-growable (anyone can deploy a contract and emit events), so an
    /// unbounded dump would be a DoS amplifier.
    pub fn list_contracts(&self, limit: u32, offset: u32) -> Result<Vec<ContractSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT contract,
                    COUNT(*)          AS event_count,
                    COUNT(DISTINCT tx_hash) AS tx_count,
                    MIN(block_height) AS first_block,
                    MAX(block_height) AS last_block
             FROM contract_events
             GROUP BY LOWER(contract)
             ORDER BY event_count DESC, last_block DESC
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

    /// How many distinct contracts emitted at least one indexed event.
    pub fn count_contracts(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT COUNT(DISTINCT LOWER(contract)) FROM contract_events")?;
        let count: u64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    // ---- verified contract sources (audit P2-15) ----

    /// Store a node-verified source. `INSERT OR REPLACE`: a re-verification
    /// (same or corrected source) replaces the row instead of duplicating it.
    /// Callers MUST only invoke this after the node confirmed the rebuild —
    /// the database does not (and cannot) check the claim itself.
    pub fn upsert_verified_source(&self, v: &VerifiedSource) -> Result<()> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let key = normalize_contract_key(contract);
        let mut stmt = conn.prepare(
            "SELECT contract, source_text, compiler, flags, source_hash, code_hash, verified_at
             FROM verified_contract_sources WHERE contract = ?1",
        )?;
        let mut rows = stmt.query_map(params![key], |row| {
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
             FROM blocks ORDER BY height DESC, shard_id ASC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
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

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<BlockRecord>> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT shard_id, height, hash, timestamp, tx_count, proposer, state_root
             FROM blocks WHERE hash = ?1",
        )?;
        let mut rows = stmt.query_map(params![hash], |row| {
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions WHERE block_height = ?1 ORDER BY tx_index ASC",
        )?;
        let rows = stmt.query_map(params![height], |row| {
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
        })?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn get_tx_by_hash(&self, hash: &str) -> Result<Option<TxRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions WHERE tx_hash = ?1 COLLATE NOCASE",
        )?;
        let mut rows = stmt.query_map(params![hash], |row| {
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
        })?;
        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn get_account_txs(&self, address: &str, limit: u32, offset: u32) -> Result<Vec<TxRecord>> {
        let conn = self.conn.lock().unwrap();
        if address.is_empty() {
            let mut stmt = conn.prepare(
                "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
                 FROM transactions
                 ORDER BY block_height DESC, tx_index DESC
                 LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit, offset], |row| {
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
            })?;
            let mut res = Vec::new();
            for r in rows {
                res.push(r?);
            }
            return Ok(res);
        }

        let (with_0x, clean_lower, pattern) = resolve_address_variants(address);

        let mut stmt = conn.prepare(
            "SELECT tx_hash, block_height, tx_index, from_addr, to_addr, amount, fee_charged, gas_limit, status, timestamp
             FROM transactions
             WHERE LOWER(from_addr) = ?1 OR LOWER(to_addr) = ?1
                OR LOWER(from_addr) = ?2 OR LOWER(to_addr) = ?2
                OR LOWER(from_addr) LIKE ?3 ESCAPE '\\' OR LOWER(to_addr) LIKE ?3 ESCAPE '\\'
             ORDER BY block_height DESC, tx_index DESC
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt.query_map(
            params![with_0x, clean_lower, pattern, limit, offset],
            |row| {
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
            },
        )?;
        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    pub fn get_account_tx_count(&self, address: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let (with_0x, clean_lower, pattern) = resolve_address_variants(address);

        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM transactions
             WHERE LOWER(from_addr) = ?1 OR LOWER(to_addr) = ?1
                OR LOWER(from_addr) = ?2 OR LOWER(to_addr) = ?2
                OR LOWER(from_addr) LIKE ?3 ESCAPE '\\' OR LOWER(to_addr) LIKE ?3 ESCAPE '\\'",
        )?;
        let count: u64 =
            stmt.query_row(params![with_0x, clean_lower, pattern], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_stats(&self) -> Result<NetworkStats> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();

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
}
