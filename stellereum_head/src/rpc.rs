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
//!   aid front-running) and the `admit_signed_payload_tx` arms `stell_submitPriceFeed`,
//!   `stell_pmmBuy`, `stell_pmmSell`. Without a token configured these stay open
//!   (local/dev mode).
//! * GATED by the SEPARATE `faucet_token` (fail-closed — an enabled faucet with no
//!   token refuses to dispense): `stell_faucet` and the explorer `POST /api/faucet/:address`.
//!
//! Security:
//!  - params are size-bounded; malformed requests are rejected, never panic
//!  - `sendRawTransaction` / `submitPriceFeed` reject bad signatures before
//!    touching the mempool
//!  - unknown methods return a JSON-RPC error, not a crash

use crate::mempool::{AdmissionCtx, Mempool};
use crate::sharding::{ShardId, Transaction};
use crate::state_engine::{token_balance_key, InMemoryStateEngine};
use axum::{extract::DefaultBodyLimit, response::IntoResponse, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Max JSON body accepted by the RPC server (1 MiB is plenty for a signed tx).
const MAX_RPC_BODY: usize = 1024 * 1024;

/// Constant-time byte comparison, so comparing a caller-supplied secret against
/// the configured token does not leak its length/prefix through timing. The
/// loop always runs `max(a.len(), b.len())` iterations and folds both the
/// length and content differences into a single accumulator, then tests it once.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let max = ab.len().max(bb.len());
    let mut diff = ab.len() ^ bb.len();
    for i in 0..max {
        let x = ab.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// Compact summary of a finalized block (for the explorer / RPC).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSummary {
    pub height: u64,
    pub hash: String,
    pub tx_count: usize,
    pub timestamp: u64,
}

/// Read-only view of the node that the RPC layer serves.
pub struct RpcState {
    pub engine: Arc<InMemoryStateEngine>,
    pub mempool: Arc<RwLock<Mempool>>,
    /// current finalized height (shared with consensus)
    pub height: Arc<std::sync::atomic::AtomicU64>,
    /// node id (hex)
    pub node_id: String,
    pub chain_id: u64,
    /// Shared on-chain staking ledger (mutated by staking RPC methods).
    pub staking: Arc<RwLock<crate::staking::StakingLedger>>,
    /// Shared on-chain governance engine.
    pub governance: Arc<RwLock<crate::governance::Governance>>,
    /// Rolling window of the most recent finalized blocks (newest first).
    pub recent_blocks: Arc<RwLock<std::collections::VecDeque<BlockSummary>>>,
    /// Inclusion receipts by transaction hash, so a wallet can ask what happened
    /// to its transaction instead of guessing from the mempool.
    pub receipts: Arc<RwLock<ReceiptIndex>>,
    /// Optional API token gating the NON-public introspection/payload arms
    /// (`stell_mempoolDump`, `stell_submitPriceFeed`, `stell_pmmBuy`,
    /// `stell_pmmSell`). The submission paths (`stell_sendRawTransaction`,
    /// `eth_sendRawTransaction`) are OPEN by design — a caller can only submit
    /// a validly signed, funded, nonce-sane tx — and the faucet has its own
    /// fail-closed `faucet_token`. When `None`, the gated arms stay open
    /// (local/dev mode).
    pub auth_token: Option<String>,

    /// Optional channel to forward validated raw transactions into P2P gossip
    pub tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<Transaction>>,
    /// Optional testnet faucet. `None` (the default, and on mainnet) the faucet
    /// RPC method is disabled entirely, so no node can mint out of thin air.
    pub faucet: Option<Arc<Faucet>>,
    /// Token that must be presented to use the faucet. Unlike `auth_token`
    /// this one is **fail-closed**: an enabled faucet with no token refuses to
    /// dispense, because "no token configured" must never mean "anyone who can
    /// reach the port may mint".
    pub faucet_token: Option<String>,
}

/// Testnet-only token faucet.
///
/// Faucet funds are **not** written straight into the state engine: that would be
/// node-local and therefore non-deterministic across a multi-node network. The
/// faucet instead signs ordinary transfers from a dedicated, pre-funded genesis
/// account and submits them to the mempool, so the value movement is decided by
/// consensus exactly like any other transaction.
///
/// On top of that it keeps a hard *lifetime* cap per recipient, so the faucet
/// treasury can never be drained by simply repeating the request.
pub struct Faucet {
    /// Amount credited per request.
    pub drip: u64,
    /// Lifetime maximum creditable amount for a single address.
    pub max_per_address: u64,
    /// Shard the faucet account lives on.
    shard: ShardId,
    /// SEED LIFETIME (audit: faucet zeroize): this signing key — and the
    /// `pq_key` below derived from the same seed — MUST live as long as the
    /// faucet itself (every drip is signed with it), so the seed material is
    /// process-lifetime by design, not a leak to fix. What IS wiped: every
    /// INTERMEDIATE copy on the load path (file bytes, parsed hex line, env
    /// string — see `load_faucet_seed_from_file` / `load_faucet_seed`, all
    /// `Zeroizing` or explicitly zeroized) and the `Faucet::new` frame copy
    /// (wiped before return). Callers: `[u8; 32]` is `Copy`, so YOUR stack
    /// binding still holds the seed after `Faucet::new(seed, ..)` returns —
    /// zeroize it at the call site once the faucet owns it. No behavior
    /// change: signing bytes are identical, only dead copies are wiped.
    key: ed25519_dalek::SigningKey,
    /// Falcon-512 keypair derived from the same seed (pure-PQ drip path).
    /// Same process-lifetime rule as `key`.
    pq_key: crate::post_quantum::FalconKeypair,
    state: tokio::sync::Mutex<FaucetState>,
    /// Called with the serialized state after every mutation, so the lifetime
    /// caps and the nonce survive a restart. `None` (tests, disabled faucet)
    /// keeps the previous in-memory-only behaviour.
    persist: Option<std::sync::Arc<dyn Fn(&[u8]) + Send + Sync>>,
    // NOTE: there is deliberately NO process-local rate-limit map here. The
    // per-source hourly budgets live in FaucetState (persisted): the token +
    // per-address lifetime cap do not stop a token holder from draining the
    // treasury by rotating addresses, and a volatile budget would hand back a
    // fresh hourly allowance on every restart. Hourly budget, not a cooldown,
    // so legit bursts (tests, harnesses) pass; rotation-drain stops at the cap.
}

/// Drips per client IP per hour (both faucet paths). Default 20; override
/// with `STELL_FAUCET_IP_MAX_PER_HOUR`. Per-node anti-abuse budget, not
/// consensus — nodes MAY differ; same value recommended so every node's
/// faucet enforces the same budget.
pub const FAUCET_IP_MAX_PER_HOUR: u32 = 20;

/// Effective per-IP hourly budget (`STELL_FAUCET_IP_MAX_PER_HOUR`, default 20).
pub fn faucet_ip_max_per_hour() -> u32 {
    std::env::var("STELL_FAUCET_IP_MAX_PER_HOUR")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(FAUCET_IP_MAX_PER_HOUR)
}

/// Env var carrying the faucet ed25519 seed inline (64-char hex, cleartext in
/// the process environment — prefer [`FAUCET_KEY_FILE_ENV`]).
pub const FAUCET_KEY_ENV: &str = "STELL_FAUCET_KEY";
/// Env var naming a FILE that carries the faucet ed25519 seed (hex, first
/// line). The file MUST be owner-only (`0600`) or loading fails closed.
pub const FAUCET_KEY_FILE_ENV: &str = "STELL_FAUCET_KEY_FILE";
/// Env var that explicitly authorises running the faucet with the well-known
/// built-in test key. `1` / case-insensitive `true` opts in; anything else
/// (including unset) refuses the test key fail-closed.
pub const DEV_UNSAFE_TESTKEY_ENV: &str = "STELL_DEV_UNSAFE_TESTKEY";
/// The well-known public test seed (`0x11..11`). It appears in tests and docs,
/// so anyone can derive its private key: running money-printing with it on a
/// live network hands every reader a mint key.
pub const TEST_FAUCET_SEED: [u8; 32] = [0x11u8; 32];

/// Parse the dev-unsafe-testkey flag: `1` or case-insensitive `true` only.
pub fn is_dev_unsafe_testkey(v: Option<&str>) -> bool {
    matches!(v, Some(s) if s == "1" || s.eq_ignore_ascii_case("true"))
}

/// [`is_dev_unsafe_testkey`] over the live process environment.
pub fn is_dev_unsafe_testkey_env() -> bool {
    is_dev_unsafe_testkey(std::env::var(DEV_UNSAFE_TESTKEY_ENV).ok().as_deref())
}

/// True when `seed` is the well-known public test key.
pub fn is_test_key_seed(seed: &[u8; 32]) -> bool {
    seed == &TEST_FAUCET_SEED
}

/// Parse one faucet seed from hex text (trims whitespace, accepts an optional
/// `0x` prefix). The input buffer is zeroized before returning.
pub fn parse_faucet_seed_hex(raw: &str) -> Result<[u8; 32], String> {
    let owned = zeroize::Zeroizing::new(raw.trim().to_string());
    let hex_part: &str = owned.strip_prefix("0x").unwrap_or(owned.as_str()).trim();
    let mut bytes = zeroize::Zeroizing::new(
        hex::decode(hex_part).map_err(|e| format!("[faucet] invalid faucet seed hex: {e}"))?,
    );
    if bytes.len() != 32 {
        return Err(format!(
            "[faucet] invalid faucet seed length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    zeroize::Zeroize::zeroize(&mut *bytes);
    Ok(seed)
}

/// Load a faucet seed from a file: 0600-checked (owner-only, fail-closed),
/// first non-empty line, hex. File bytes are zeroized after parsing.
pub fn load_faucet_seed_from_file(path: &std::path::Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::metadata(path).map_err(|e| format!("[faucet] cannot stat faucet key file {}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!(
                "[faucet] REFUSING: faucet key path {} is not a file",
                path.display()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "[faucet] REFUSING: faucet key file {} has insecure permissions 0o{:03o} \
                 (group/other must have NO access — chmod 0600 {})",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        if !path.is_file() {
            return Err(format!(
                "[faucet] REFUSING: faucet key path {} is not a file",
                path.display()
            ));
        }
    }
    let mut raw = zeroize::Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| format!("[faucet] cannot read faucet key file {}: {e}", path.display()))?,
    );
    // The parsed line is a SECOND copy of the secret (the file buffer above
    // is wiped on the next line): it must be a `Zeroizing` too, or the key
    // hex survives in a plain `String` after this function returns.
    let line = zeroize::Zeroizing::new(
        raw.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string(),
    );
    zeroize::Zeroize::zeroize(&mut *raw);
    if line.is_empty() {
        return Err(format!(
            "[faucet] REFUSING: faucet key file {} is empty",
            path.display()
        ));
    }
    // `line` wipes itself on drop (`Zeroizing`); the returned seed's lifetime
    // is documented on [`Faucet::new`].
    load_faucet_seed_from_file_content(&line, path)
}

/// Helper so the parsed line (not the whole file buffer) is what gets an error
/// context. Separated for tests.
fn load_faucet_seed_from_file_content(line: &str, path: &std::path::Path) -> Result<[u8; 32], String> {
    parse_faucet_seed_hex(line)
        .map_err(|e| format!("{} (in {})", e, path.display()))
}

/// Fail-closed test-key gate: running the faucet with the well-known public
/// test key is REFUSED unless `STELL_DEV_UNSAFE_TESTKEY=1` explicitly opts in.
/// The error is loud and names the exact unsafe override (dev only).
pub fn check_faucet_seed_allows_startup(seed: &[u8; 32]) -> Result<(), String> {
    if is_test_key_seed(seed) && !is_dev_unsafe_testkey_env() {
        return Err(format!(
            "[faucet] REFUSING: faucet key is the well-known PUBLIC test key (0x11..11) — \
             anyone can derive its private key, so starting the faucet with it would run \
             money-printing on a guessable key. Set a real {}=/{} (0600 file preferred) \
             with a fresh random seed. Dev-only override (NEVER on a live network): \
             {}=1",
            FAUCET_KEY_ENV,
            FAUCET_KEY_FILE_ENV,
            DEV_UNSAFE_TESTKEY_ENV
        ));
    }
    Ok(())
}

/// True when either faucet-key source is configured (inline env or key file).
pub fn faucet_key_present_from_env() -> bool {
    let inline = std::env::var(FAUCET_KEY_ENV).ok().is_some_and(|s| !s.trim().is_empty());
    let file = std::env::var(FAUCET_KEY_FILE_ENV).ok().is_some_and(|s| !s.trim().is_empty());
    inline || file
}

/// Load the faucet seed for startup: `STELL_FAUCET_KEY_FILE` wins when set
/// (0600-checked, zeroized after load), else `STELL_FAUCET_KEY`.
///
/// * `Ok(seed)` — exactly one source configured and parsed, test-key gate passed.
/// * `Err(msg)` — fail-closed loud error: misconfigured file (missing /
///   bad perms / bad hex), bad inline hex, or the public test key without the
///   dev override. Callers must refuse to start the faucet on `Err`.
pub fn load_faucet_seed() -> Result<[u8; 32], String> {
    if let Some(path) = std::env::var(FAUCET_KEY_FILE_ENV).ok().filter(|s| !s.trim().is_empty()) {
        let path_buf = zeroize::Zeroizing::new(path);
        let seed = load_faucet_seed_from_file(std::path::Path::new(path_buf.as_str()))?;
        check_faucet_seed_allows_startup(&seed)?;
        return Ok(seed);
    }
    if let Some(mut hex_str) = std::env::var(FAUCET_KEY_ENV).ok().filter(|s| !s.trim().is_empty()) {
        let seed = parse_faucet_seed_hex(&hex_str)?;
        use zeroize::Zeroize;
        hex_str.zeroize();
        check_faucet_seed_allows_startup(&seed)?;
        return Ok(seed);
    }
    Err(format!(
        "[faucet] no faucet key configured (set {} or {}); refusing to start the faucet",
        FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV
    ))
}

/// Optional variant for genesis-funding paths: `Ok(None)` when NEITHER source
/// is configured (no faucet funding, same as before); `Err` on any
/// misconfiguration (fail-closed, loud); `Ok(Some(seed))` on success.
pub fn try_load_faucet_seed_opt() -> Result<Option<[u8; 32]>, String> {
    if !faucet_key_present_from_env() {
        return Ok(None);
    }
    load_faucet_seed().map(Some)
}

/// Genesis-RECOMPUTE variant: byte-identical derivation to the v1 genesis
/// (`c840d1dc...` funds the faucet account from the then-configured seed),
/// which the stored-root guard compares against on every boot of existing
/// data. A test-key seed is therefore LOUDLY WARNED but RETURNED here —
/// recompute moves no money, it only re-derives an address. SERVING drips
/// from it stays hard-refused via `load_faucet_seed()`. Without this split,
/// any existing chain founded with the test key could never boot again.
pub fn load_faucet_seed_for_genesis() -> Result<[u8; 32], String> {
    let seed = load_faucet_seed_for_genesis_inner()?;
    if is_test_key_seed(&seed) && !is_dev_unsafe_testkey_env() {
        let msg = "[genesis] WARN faucet key is the well-known PUBLIC test key (0x11..11): \
            genesis funding reproduced for root determinism ONLY — serving drips from it \
            stays REFUSED. Rotate to a fresh STELL_FAUCET_KEY_FILE.";
        eprintln!("{msg}");
        tracing::warn!("{msg}");
    }
    Ok(seed)
}

fn load_faucet_seed_for_genesis_inner() -> Result<[u8; 32], String> {
    if let Some(path) = std::env::var(FAUCET_KEY_FILE_ENV).ok().filter(|s| !s.trim().is_empty()) {
        let path_buf = zeroize::Zeroizing::new(path);
        return load_faucet_seed_from_file(std::path::Path::new(path_buf.as_str()));
    }
    if let Some(mut hex_str) = std::env::var(FAUCET_KEY_ENV).ok().filter(|s| !s.trim().is_empty()) {
        let seed = parse_faucet_seed_hex(&hex_str)?;
        use zeroize::Zeroize;
        hex_str.zeroize();
        return Ok(seed);
    }
    Err(format!(
        "[faucet] no faucet key configured (set {} or {}); no genesis faucet funding",
        FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV
    ))
}

/// Optional genesis variant of the above: `Ok(None)` when unconfigured.
pub fn try_load_faucet_seed_opt_for_genesis() -> Result<Option<[u8; 32]>, String> {
    if !faucet_key_present_from_env() {
        return Ok(None);
    }
    load_faucet_seed_for_genesis().map(Some)
}

/// Meta key under which a node persists its faucet state.
pub const FAUCET_STATE_META_KEY: &str = "faucet_state_v1";

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
struct FaucetState {
    next_nonce: u64,
    dispensed: std::collections::HashMap<[u8; 32], u64>,
    /// Hourly drip budgets per source, `(hour, count)` keyed by source-IP
    /// string (`"unknown"` when the caller could not attribute one). Lives in
    /// the persisted state — NOT in a process-local map — so a restart does
    /// not reset rate limits (hunt D5: lifetime caps and the nonce were
    /// already persisted for exactly this reason; the budget was not).
    #[serde(default)]
    ip_buckets: std::collections::HashMap<String, (u64, u32)>,
    /// Last public (tokenless) drip timestamp per address, in unix seconds.
    /// Enforces the TON-style cooldown: one public drip per address per
    /// `PUBLIC_DRIP_COOLDOWN_SECS`. Persisted, so restarts do not reopen it.
    #[serde(default)]
    last_public_drip: std::collections::HashMap<[u8; 32], u64>,
}

/// Public testnet drip: 5 STELL per address (TON-style onboarding drip).
/// Default 5 STELL; override with `STELL_PUBLIC_DRIP_NANO`. Faucet policy,
/// not consensus — nodes MAY differ; same value recommended so every node's
/// faucet credits the same amount.
pub const PUBLIC_DRIP_NANO: u64 = 5 * 1_000_000_000;
/// Public drip cooldown: 45 minutes per address. Default 2700 s; override
/// with `STELL_PUBLIC_DRIP_COOLDOWN_SECS`. Faucet policy, not consensus —
/// nodes MAY differ; same value recommended so every node's faucet enforces
/// the same cooldown.
pub const PUBLIC_DRIP_COOLDOWN_SECS: u64 = 45 * 60;

/// Effective public drip amount (`STELL_PUBLIC_DRIP_NANO`, default 5 STELL).
pub fn public_drip_nano() -> u64 {
    std::env::var("STELL_PUBLIC_DRIP_NANO")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PUBLIC_DRIP_NANO)
}

/// Effective public drip cooldown (`STELL_PUBLIC_DRIP_COOLDOWN_SECS`, default 2700).
pub fn public_drip_cooldown_secs() -> u64 {
    std::env::var("STELL_PUBLIC_DRIP_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PUBLIC_DRIP_COOLDOWN_SECS)
}

/// Pre-persistence layout (nonce + per-address totals only). A node upgrading
/// with a record written by the old code must keep its caps: decode falls back
/// to this shape and migrates it (fresh, empty rate buckets), instead of
/// failing closed to empty and re-opening every capped address.
#[derive(serde::Deserialize)]
struct LegacyFaucetState {
    next_nonce: u64,
    dispensed: std::collections::HashMap<[u8; 32], u64>,
}

impl Faucet {
    /// Default drip, in nano-STELL: 10 STELL unless `STELL_FAUCET_DRIP_STELL`
    /// carries a whole-STELL override. The single default every node binary
    /// uses, so the drip amount is one definition, not three hardcodings.
    pub fn default_drip_nano() -> u64 {
        let stell: u64 = std::env::var("STELL_FAUCET_DRIP_STELL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        stell.saturating_mul(1_000_000_000)
    }

    /// `key_seed` is the 32-byte seed of the pre-funded faucet account.
    /// See the seed-lifetime note on the struct: the frame copy is wiped
    /// before return; zeroize YOUR stack copy at the call site.
    pub fn new(mut key_seed: [u8; 32], shard: ShardId, drip: u64, max_per_address: u64) -> Self {
        let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
        let key = ed25519_dalek::SigningKey::from_bytes(&key_seed);
        // Wipe the frame copy: the live material now lives in `key`/`pq_key`
        // (process-lifetime by design). The caller's `Copy` binding is theirs
        // to wipe.
        zeroize::Zeroize::zeroize(&mut key_seed);
        Self {
            drip,
            max_per_address,
            shard,
            key,
            pq_key,
            state: tokio::sync::Mutex::new(FaucetState::default()),
            persist: None,
        }
    }

    /// Attach a durability hook, returning the faucet for builder-style use.
    pub fn with_persist(
        mut self,
        persist: std::sync::Arc<dyn Fn(&[u8]) + Send + Sync>,
    ) -> Self {
        self.persist = Some(persist);
        self
    }

    /// Serialize the mutable state (nonce + per-address dispensed totals +
    /// per-source rate buckets).
    pub async fn save_bytes(&self) -> Vec<u8> {
        let st = self.state.lock().await;
        bincode::serialize(&*st).unwrap_or_default()
    }

    /// Restore previously saved state. Unknown bytes fail closed to empty
    /// (a corrupt record must not mint extra lifetime credit). Records written
    /// before the rate buckets existed migrate with empty budgets; stale
    /// buckets (older than the previous UTC hour) are dropped so a long-offline
    /// node does not carry dead entries back.
    pub async fn load_bytes(&self, bytes: &[u8]) {
        let now_hour = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 3600)
            .unwrap_or(0);
        if let Ok(mut st) = bincode::deserialize::<FaucetState>(bytes) {
            st.ip_buckets.retain(|_, (h, _)| now_hour.saturating_sub(*h) <= 1);
            *self.state.lock().await = st;
        } else if let Ok(legacy) = bincode::deserialize::<LegacyFaucetState>(bytes) {
            *self.state.lock().await = FaucetState {
                next_nonce: legacy.next_nonce,
                dispensed: legacy.dispensed,
                ip_buckets: std::collections::HashMap::new(),
                last_public_drip: std::collections::HashMap::new(),
            };
        }
    }

    /// Clamp a diverged durable nonce DOWN to the on-chain nonce. See the
    /// startup reconciliation in main.rs for why only downward moves here.
    pub async fn clamp_nonce_down(&self, onchain_nonce: u64) {
        let mut st = self.state.lock().await;
        if st.next_nonce > onchain_nonce {
            st.next_nonce = onchain_nonce;
            self.persist_locked(&st);
        }
    }

    fn persist_locked(&self, st: &FaucetState) {
        if let Some(persist) = &self.persist {
            persist(&bincode::serialize(st).unwrap_or_default());
        }
    }

    /// The (pre-funded) account the faucet transfers from.
    pub fn account(&self) -> [u8; 32] {
        if crate::post_quantum::is_pure_pq_enforced() {
            crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &self.pq_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            )
        } else {
            self.key.verifying_key().to_bytes()
        }
    }

    /// Build a signed transfer for `who`, or `None` when their lifetime cap is
    /// already exhausted. The returned amount is already reserved against the cap.
    pub async fn build_transfer(
        &self,
        who: [u8; 32],
        requested: Option<u64>,
        reconcile: Option<(u64, Vec<u64>)>,
    ) -> Option<(Transaction, u64)> {
        let mut st = self.state.lock().await;
        let already = st.dispensed.get(&who).copied().unwrap_or(0);
        let remaining = self.max_per_address.saturating_sub(already);
        if remaining == 0 {
            return None;
        }
        let amount = requested.unwrap_or(self.drip).min(self.drip).min(remaining);
        st.dispensed.insert(who, already + amount);
        // Reconcile under the same lock (atomic with assignment): reserved
        // nonces lost with a wiped mempool leave a permanent gap (new drips
        // wait behind phantom predecessors forever). `reconcile` carries
        // (on-chain nonce, pending nonces); we take the smallest nonce that is
        // neither executed nor pending (mex) -- filling gaps instead of
        // waiting behind them, never duplicating. None keeps pure increment
        // (tests, explorer, single-shot uses).
        if let Some((onchain, mut pending)) = reconcile {
            pending.sort_unstable();
            let mut want = onchain;
            for n in pending {
                if n < want {
                    continue;
                }
                if n == want {
                    want += 1;
                } else {
                    break;
                }
            }
            // Max, not overwrite (audit follow-up): two concurrent drips with
            // the same stale `pending` snapshot compute the same `want`; the
            // second must not clobber the first's increment (duplicate nonce).
            if want > st.next_nonce {
                st.next_nonce = want;
            }
        }
        let nonce = st.next_nonce;
        st.next_nonce += 1;
        // Durable before returning: a crash between here and the transfer must not
        // resurrect spent lifetime credit.
        self.persist_locked(&st);
        // Faucet drips go through mempool admission like any other tx, so the
        // declared gas must clear the base fee (raised x500 with the base
        // transfer fee - a hardcoded 21_000 here silently broke every drip).
        let tx = if crate::post_quantum::is_pure_pq_enforced() {
            let from = self.account();
            let mut unsigned_tx = Transaction {
                from,
                to: who,
                amount,
                gas_limit: crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
                nonce,
                source_shard: self.shard,
                target_shard: self.shard,
                signature: Vec::new(),
                payload: Vec::new(),
            };
            let msg = unsigned_tx.signing_message();
            let sig = self.pq_key.sign(&msg);
            let env = crate::sharding::PqSignatureEnvelope::new_explicit(
                crate::post_quantum::PqScheme::Falcon512,
                self.pq_key.public_key.clone(),
                sig,
            );
            unsigned_tx.signature = env.encode();
            unsigned_tx
        } else {
            Transaction::sign(
                &self.key,
                who,
                amount,
                crate::svm::GAS_BASIC_TRANSFER,
                nonce,
                self.shard,
                self.shard,
            )
        };
        Some((tx, amount))
    }

    /// Public testnet drip (TON-style, tokenless): fixed 5 STELL per address
    /// per 45 minutes. Cooldown is checked AND recorded atomically under the
    /// same lock before any nonce/mint logic runs, so concurrent requests for
    /// the same address cannot both pass. Persisted: restarts do not reopen it.
    /// Returns `None` with the seconds remaining when still cooling down.
    pub async fn build_public_transfer(
        &self,
        who: [u8; 32],
        now_secs: u64,
        reconcile: Option<(u64, Vec<u64>)>,
    ) -> Result<(Transaction, u64), u64> {
        {
            let mut st = self.state.lock().await;
            if let Some(last) = st.last_public_drip.get(&who) {
                let elapsed = now_secs.saturating_sub(*last);
                let cooldown = public_drip_cooldown_secs();
                if elapsed < cooldown {
                    return Err(cooldown - elapsed);
                }
            }
            st.last_public_drip.insert(who, now_secs);
            self.persist_locked(&st);
        }
        match self
            .build_transfer(who, Some(public_drip_nano()), reconcile)
            .await
        {
            Some(v) => Ok(v),
            None => Err(public_drip_cooldown_secs()),
        }
    }
    /// Give a nonce back when the transfer could not be admitted.
    ///
    /// Rewinds to the failed nonce (not just the tip): with mex-reconcile at
    /// every build site, a lower `next_nonce` is always safe (the next build
    /// recomputes the mex around still-pending nonces, so nothing duplicates),
    /// while the old tip-only rewind left permanent gaps under interleaved
    /// admissions (audit 2026-10-06).
    pub async fn rollback(&self, tx: &Transaction, who: [u8; 32], amount: u64) {
        let mut st = self.state.lock().await;
        if tx.nonce < st.next_nonce {
            st.next_nonce = tx.nonce;
        }
        let already = st.dispensed.get(&who).copied().unwrap_or(0);
        st.dispensed.insert(who, already.saturating_sub(amount));
        self.persist_locked(&st);
    }

    /// Lifetime amount already credited to `who`.
    pub async fn dispensed_to(&self, who: [u8; 32]) -> u64 {
        self.state.lock().await.dispensed.get(&who).copied().unwrap_or(0)
    }

    /// Per-source drip throttle: at most FAUCET_IP_MAX_PER_HOUR drips per UTC
    /// hour. Returns true when the drip may proceed (and records it).
    /// Loopback is NOT exempt — a leaked token + rotation script is local too.
    ///
    /// `ip` is `None` when the caller could not attribute a source (direct
    /// dispatch in unit tests): those drips share ONE fallback budget instead
    /// of bypassing the throttle entirely. Buckets live in the persisted
    /// [`FaucetState`] and every granted drip re-persists, so restarts do not
    /// reset budgets (hunt D5).
    pub async fn check_ip_throttle(&self, ip: Option<std::net::IpAddr>, now_secs: u64) -> bool {
        let key = ip.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
        let mut st = self.state.lock().await;
        if st.ip_buckets.len() > 100_000 {
            // Hour-unit comparison: entries store the UTC hour number, not a
            // timestamp (the old seconds-based retain wiped live buckets).
            let now_hour = now_secs / 3600;
            st.ip_buckets.retain(|_, (h, _)| now_hour.saturating_sub(*h) <= 1);
        }
        let hour = now_secs / 3600;
        let ip_max = faucet_ip_max_per_hour();
        let allowed = match st.ip_buckets.get_mut(&key) {
            Some((h, n)) if *h == hour => {
                if *n >= ip_max {
                    false
                } else {
                    *n += 1;
                    true
                }
            }
            _ => {
                st.ip_buckets.insert(key, (hour, 1));
                true
            }
        };
        if allowed {
            self.persist_locked(&st);
        }
        allowed
    }
}

/// Highest VERIFIED peer height + when it was seen (audit follow-up: a bare
/// max pinned `stell_syncing==true` forever on one faulty vote, and reset to
/// 0 on restart). Entries older than PEER_HEIGHT_STALE_SECS are ignored.
/// Vantage-local by design.
pub static PEER_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PEER_HEIGHT_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub const PEER_HEIGHT_STALE_SECS: u64 = 300;

/// Record a verified peer height (monotonic max; never moves backwards).
/// Every sighting refreshes the freshness stamp, so a stale faulty vote
/// stops pinning `stell_syncing` after PEER_HEIGHT_STALE_SECS.
pub fn note_peer_height(h: u64) {
    PEER_HEIGHT.fetch_max(h, std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PEER_HEIGHT_AT.store(now, std::sync::atomic::Ordering::Relaxed);
}

/// Fresh peer height, if any sighting is recent.
pub fn fresh_peer_height() -> Option<u64> {
    let h = PEER_HEIGHT.load(std::sync::atomic::Ordering::Relaxed);
    let at = PEER_HEIGHT_AT.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if h == 0 || now.saturating_sub(at) > PEER_HEIGHT_STALE_SECS {
        None
    } else {
        Some(h)
    }
}

/// Last connected-peer-reported chain id + when it was seen (0 = none yet).
/// A peer reporting a different chain id than ours is on a DIFFERENT network:
/// recording the sighting is not enough — the observer must abort (fail-closed,
/// loud), never silently partition. See [`note_peer_chain_id`].
pub static PEER_CHAIN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PEER_CHAIN_ID_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record a connected peer's reported chain id and enforce the fail-closed
/// mismatch rule (task (c)): `Ok` records and returns when `peer == local`;
/// `Err` (loud, must abort the caller — at startup: refuse to start) when the
/// peer is on a different chain. The sighting is stored either way, so
/// [`fresh_peer_chain_id`] stays diagnostic.
pub fn note_peer_chain_id(local: u64, peer: u64) -> Result<(), String> {
    PEER_CHAIN_ID.store(peer, std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PEER_CHAIN_ID_AT.store(now, std::sync::atomic::Ordering::Relaxed);
    crate::zkml::check_peer_chain_id(local, peer)
}

/// Fresh peer-reported chain id, if any sighting is recent (`Some(0)`/stale =
/// `None`: no usable report, not evidence of anything).
pub fn fresh_peer_chain_id() -> Option<u64> {
    let id = PEER_CHAIN_ID.load(std::sync::atomic::Ordering::Relaxed);
    let at = PEER_CHAIN_ID_AT.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if id == 0 || now.saturating_sub(at) > PEER_HEIGHT_STALE_SECS {
        None
    } else {
        Some(id)
    }
}

/// Max number of recent blocks retained for the explorer.
pub const MAX_RECENT_BLOCKS: usize = 100;

/// Max receipts retained; bounded so a busy chain cannot exhaust memory.
pub const MAX_RECEIPTS: usize = 50_000;

/// What a wallet gets back for a transaction it submitted.
///
/// `gas_limit` is the DECLARED limit; `fee_charged` is what the single real
/// application actually debited (0 for a failed transaction, whose commit is
/// atomic - it paid nothing). Wallets must account on `fee_charged`: the
/// limit overstates the cost of every failed transaction.
#[derive(Clone, Debug, Serialize)]
pub struct TxReceipt {
    pub tx_hash: [u8; 32],
    pub height: u64,
    pub block_hash: [u8; 32],
    pub index: u32,
    pub success: bool,
    pub gas_limit: u64,
    pub fee_charged: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_tx: Option<String>,
}

/// Bounded LRU-ish index of transaction receipts, ordered by inclusion.
#[derive(Default)]
pub struct ReceiptIndex {
    pub order: std::collections::VecDeque<[u8; 32]>,
    pub map: HashMap<[u8; 32], TxReceipt>,
}

impl ReceiptIndex {
    pub fn insert(&mut self, r: TxReceipt) {
        let hash = r.tx_hash;
        if self.map.insert(hash, r).is_none() {
            self.order.push_back(hash);
            while self.order.len() > MAX_RECEIPTS {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    pub fn get(&self, hash: &[u8; 32]) -> Option<&TxReceipt> {
        self.map.get(hash)
    }

    pub fn values(&self) -> impl Iterator<Item = &TxReceipt> {
        self.map.values()
    }

    pub fn for_height(&self, height: u64) -> Vec<&TxReceipt> {
        let mut rows: Vec<&TxReceipt> = self.map.values().filter(|r| r.height == height).collect();
        rows.sort_by_key(|r| r.index);
        rows
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl RpcState {
    /// Best-effort mempool durability after admissions: restarts between the
    /// 15s periodic save and execution silently drop fresh transactions
    /// (observed live: 1000-tx blasts vanishing). Throttled to once per 2s so
    /// a burst doesn't fsync per tx; the shutdown hook and periodic saver
    /// cover the rest. Path matches the loader in main.rs.
    pub async fn save_mempool_throttled(&self) {
        static LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now.saturating_sub(LAST_MS.load(std::sync::atomic::Ordering::Relaxed)) < 2000 {
            return;
        }
        LAST_MS.store(now, std::sync::atomic::Ordering::Relaxed);
        let path = std::path::PathBuf::from("./data/mempool.bin");
        self.mempool.read().await.save(&path);
    }

    /// Record a newly finalized block. Called by the consensus loop.
    pub async fn record_block(&self, height: u64, hash: [u8; 32], tx_count: usize, timestamp: u64) {
        self.height.store(height, std::sync::atomic::Ordering::Relaxed);
        let mut rb = self.recent_blocks.write().await;
        rb.push_front(BlockSummary { height, hash: hex::encode(hash), tx_count, timestamp });
        while rb.len() > MAX_RECENT_BLOCKS {
            rb.pop_back();
        }
        drop(rb);
        crate::evm_adapter::notify_block(crate::evm_adapter::stell_hash_to_evm(&hash));
    }

    /// Record inclusion receipts for a finalized block's transactions.
    ///
    /// `fees` carries the nano-STELL each transaction was actually charged
    /// (parallel to `statuses`, in block order, from the single real
    /// application); a short `fees` falls back to `gas_limit`-on-success /
    /// 0-on-fail, which is exactly what the block path charged.
    pub async fn record_receipts(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
    ) {
        // Link EVM intents settled via secp envelopes BEFORE filing receipts,
        // so a reader that observes the receipt also observes the mapping.
        for tx in txs.iter() {
            crate::evm_adapter::link_secp_settlement(tx);
        }
        let mut idx = self.receipts.write().await;
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let raw_tx = bincode::serialize(tx).ok().map(hex::encode);
            idx.insert(TxReceipt {
                tx_hash: tx.compute_tx_hash(),
                height,
                block_hash,
                index: i as u32,
                success,
                gas_limit: tx.gas_limit,
                fee_charged: fees
                    .get(i)
                    .copied()
                    .unwrap_or(if success { tx.gas_limit } else { 0 }),
                raw_tx,
            });
        }
    }

    /// Record an ADOPTED (or walked) block: the hook the adopt_committed /
    /// walk_chain paths call so a non-proposer serves identical bodies+receipts
    /// as the proposer (no more `txs=0` views, no missing receipts).
    ///
    /// Mechanics only: `txs` is the verified body the adopter already holds
    /// (hash-checked against the committed header before this is called) and
    /// `statuses` is the outcome of the SINGLE real application on this node
    /// (never re-execution output, never wire data -- see the parity test).
    /// Ordering matches the finalize path exactly (receipts before the block
    /// summary) so readers that observe height H see every receipt of H.
    /// `tx_count` is derived from the body (`txs.len()`), never passed as 0
    /// while a body is present -- that 0 is the exact `txs=0` view observed
    /// live. Runs behind/parallel to finalization; never blocks it.
    pub async fn record_adopted_block(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        timestamp: u64,
    ) {
        self.record_receipts(height, block_hash, txs, statuses, fees).await;
        self.record_block(height, block_hash, txs.len(), timestamp).await;
    }

    /// Import one durably stored receipt (restart hydration). Bounded by the
    /// same `MAX_RECEIPTS` cap as live inserts (oldest evicted first).
    pub async fn import_stored_receipt(&self, r: &crate::storage::StoredReceipt) {
        self.receipts.write().await.insert(TxReceipt {
            tx_hash: r.tx_hash,
            height: r.height,
            block_hash: r.block_hash,
            index: r.index,
            success: r.success,
            gas_limit: r.gas_limit,
            fee_charged: r.fee_charged,
            raw_tx: None,
        });
    }

    /// Returns the current finalized block height in hex quantity.
    pub fn eth_block_number(&self) -> String {
        let h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        crate::evm_adapter::eth_block_number(h)
    }

    /// Alias matching JSON-RPC casing for `eth_block_number`.
    #[allow(non_snake_case)]
    pub fn eth_blockNumber(&self) -> String {
        self.eth_block_number()
    }

    /// Translates a block by number or tag ("latest", "earliest", "pending", hex) to `EvmBlock`.
    pub async fn eth_get_block_by_number(
        &self,
        block_tag: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let tag = crate::evm_adapter::BlockTag::parse_str(block_tag)?;
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| b.height == want) {
            let parent_hash = if b.height > 0 {
                rb.iter().find(|p| p.height == b.height - 1).map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            let evm_block = crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full_tx);
            Ok(Some(evm_block))
        } else {
            Ok(crate::evm_adapter::global_adapter().get_block_by_number(&tag, full_tx))
        }
    }

    /// Alias matching JSON-RPC casing for `eth_get_block_by_number`.
    #[allow(non_snake_case)]
    pub async fn eth_getBlockByNumber(
        &self,
        block_tag: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_block_by_number(block_tag, full_tx).await
    }

    /// Translates a block by hash to `EvmBlock`.
    pub async fn eth_get_block_by_hash(
        &self,
        hash: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            let parent_hash = if b.height > 0 {
                rb.iter().find(|p| p.height == b.height - 1).map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(b.height);
            let evm_block = crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full_tx);
            Ok(Some(evm_block))
        } else {
            Ok(crate::evm_adapter::global_adapter().get_block_by_hash(&norm, full_tx))
        }
    }

    /// Alias matching JSON-RPC casing for `eth_get_block_by_hash`.
    #[allow(non_snake_case)]
    pub async fn eth_getBlockByHash(
        &self,
        hash: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_block_by_hash(hash, full_tx).await
    }

    /// Translates a transaction receipt by transaction hash to standard `EvmReceipt`.
    ///
    /// Accepts BOTH stell hashes and EVM intent hashes (`keccak(EVM raw)`):
    /// an EVM hash settled via a secp envelope resolves through the
    /// bidirectional map to its L1 receipt and is reported with the QUERIED
    /// (EVM) `transactionHash`, full `blockNumber`/`blockHash`, `status`
    /// (`0x1`/`0x0`) and `gasUsed` — never null once finalized.
    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmReceipt>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(tx_hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let h_bytes = crate::evm_adapter::parse_hash_bytes(&norm).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        // Resolve EVM intent -> stell tx hash for the lookup, keeping the
        // queried (EVM) hash for the response body.
        let lookup_bytes: [u8; 32] = crate::evm_adapter::evm_to_stell_hash(&norm).unwrap_or(h_bytes);
        let is_settled_evm = lookup_bytes != h_bytes;
        let idx = self.receipts.read().await;
        if let Some(r) = idx.get(&lookup_bytes) {
            let mut receipt = if is_settled_evm {
                crate::evm_adapter::settled_receipt_for_evm(&norm, r)
            } else {
                crate::evm_adapter::stell_receipt_to_evm(r)
            };
            let block_receipts = idx.for_height(r.height);
            let cumulative: u64 = block_receipts
                .iter()
                .filter(|br| br.index <= r.index)
                .map(|br| br.fee_charged)
                .sum();
            receipt.cumulative_gas_used = crate::evm_adapter::format_u64_hex(cumulative);
            if receipt.from == "0x0000000000000000000000000000000000000000" {
                drop(idx);
                let mp = self.mempool.read().await;
                if let Some(tx) = mp.get(&lookup_bytes) {
                    receipt.from = crate::evm_adapter::stell_address_to_evm(&tx.from);
                    receipt.to = Some(crate::evm_adapter::stell_address_to_evm(&tx.to));
                }
            }
            Ok(Some(receipt))
        } else {
            // Global adapter fallback (direct hit, then settled-EVM rewrite).
            if let Some(r) = crate::evm_adapter::global_adapter().get_transaction_receipt(&norm) {
                return Ok(Some(r.clone()));
            }
            if let Some(r) = crate::evm_adapter::global_adapter().get_settled_receipt(&norm) {
                return Ok(Some(r));
            }
            Ok(None)
        }
    }

    /// Alias matching JSON-RPC casing for `eth_get_transaction_receipt`.
    #[allow(non_snake_case)]
    pub async fn eth_getTransactionReceipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmReceipt>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_transaction_receipt(tx_hash).await
    }

    /// Translates a transaction by transaction hash to standard `EvmTransaction`.
    ///
    /// Accepts BOTH stell hashes and EVM intent hashes: a settled EVM hash
    /// resolves to its mined L1 transaction (with `blockNumber`/`blockHash`),
    /// which takes precedence over the pending intent view.
    pub async fn eth_get_transaction_by_hash(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(tx_hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let h_bytes = crate::evm_adapter::parse_hash_bytes(&norm).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let lookup_bytes: [u8; 32] = crate::evm_adapter::evm_to_stell_hash(&norm).unwrap_or(h_bytes);
        let is_settled_evm = lookup_bytes != h_bytes;
        let idx = self.receipts.read().await;
        // Mined view first (settled EVM intents included): pending must not
        // shadow a finalized transaction.
        if let Some(r) = idx.get(&lookup_bytes) {
            if is_settled_evm {
                if let Some(evm_tx) =
                    crate::evm_adapter::settled_tx_for_evm(&norm, r, self.chain_id)
                {
                    return Ok(Some(evm_tx));
                }
            } else if let Some(evm_tx) = crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id) {
                return Ok(Some(evm_tx));
            }
        }
        drop(idx);
        let mp = self.mempool.read().await;
        if let Some(tx) = mp.get(&lookup_bytes) {
            let mut evm_tx = crate::evm_adapter::stell_tx_to_evm_with_chain(tx, None, None, None, self.chain_id);
            if is_settled_evm {
                evm_tx.hash = norm.clone();
            }
            return Ok(Some(evm_tx));
        }
        drop(mp);
        if let Some(cached) = crate::evm_adapter::global_adapter().get_settled_transaction(&norm) {
            return Ok(Some(cached));
        }
        // Phase 1 EVM intent pool (eth_sendRawTransaction pending).
        if let Some(pending) = crate::evm_adapter::eth_pending_tx(&norm) {
            return Ok(Some(pending));
        }
        Ok(None)
    }

    /// Alias matching JSON-RPC casing for `eth_get_transaction_by_hash`.
    #[allow(non_snake_case)]
    pub async fn eth_getTransactionByHash(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_transaction_by_hash(tx_hash).await
    }

    pub async fn handle_get_block_by_number(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let (tag, full) = crate::evm_adapter::parse_get_block_by_number_params(params)?;
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| b.height == want) {
            let parent_hash = if b.height > 0 {
                rb.iter().find(|p| p.height == b.height - 1).map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            let evm_block = crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full);
            Ok(Some(evm_block))
        } else {
            Ok(crate::evm_adapter::global_adapter().get_block_by_number(&tag, full))
        }
    }

    pub async fn handle_get_block_by_hash(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let (hash_str, full) = crate::evm_adapter::parse_get_block_by_hash_params(params)?;
        self.eth_get_block_by_hash(&hash_str, full).await
    }

    pub async fn handle_get_transaction_receipt(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmReceipt>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_transaction_receipt(&hash_str).await
    }

    pub async fn handle_get_transaction_by_hash(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_transaction_by_hash(&hash_str).await
    }

    /// Number of transactions in a block looked up by hash.
    /// Serve order: recent window (`tx_count`) -> global adapter maps -> null.
    pub async fn eth_get_block_transaction_count_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            return Ok(Some(crate::evm_adapter::format_u64_hex(b.tx_count as u64)));
        }
        drop(rb);
        Ok(crate::evm_adapter::global_adapter()
            .get_block_transaction_count_by_hash(&norm)
            .map_err(|e| e)?)
    }

    /// Number of transactions in a block looked up by tag/number.
    /// Serve order: recent window (`tx_count`) -> global adapter maps -> null.
    pub async fn eth_get_block_transaction_count_by_number(
        &self,
        tag: &crate::evm_adapter::BlockTag,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| b.height == want) {
            return Ok(Some(crate::evm_adapter::format_u64_hex(b.tx_count as u64)));
        }
        drop(rb);
        Ok(crate::evm_adapter::global_adapter().get_block_transaction_count_by_number(tag)?)
    }

    /// Transaction at `index` inside the block looked up by hash.
    /// Serve order: recent window receipts -> global adapter maps -> null.
    pub async fn eth_get_transaction_by_block_hash_and_index(
        &self,
        hash: &str,
        index: u64,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let (height, block_hash_bytes) = {
            let rb = self.recent_blocks.read().await;
            match rb.iter().find(|b| {
                let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
                b_stripped.eq_ignore_ascii_case(stripped)
            }) {
                Some(b) => {
                    let h = b.height;
                    let hb = hex::decode(b.hash.strip_prefix("0x").unwrap_or(&b.hash))
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok());
                    (Some(h), hb)
                }
                None => (None, None),
            }
        };
        if let Some(h) = height {
            let idx = self.receipts.read().await;
            let rows = idx.for_height(h);
            if let Some(r) = rows.iter().find(|r| r.index as u64 == index) {
                let _ = block_hash_bytes;
                if let Some(evm_tx) =
                    crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id)
                {
                    return Ok(Some(evm_tx));
                }
                return Ok(None);
            }
            // Known block but index out of range (or no receipts yet): null.
            // Fall through to the global adapter only when the block itself is unknown.
            if rows.is_empty() {
                let rb = self.recent_blocks.read().await;
                let known_tx_count = rb.iter().find(|b| b.height == h).map(|b| b.tx_count).unwrap_or(0);
                if known_tx_count == 0 {
                    return Ok(None);
                }
                // Non-zero tx_count but no receipts indexed yet: honest null.
                return Ok(None);
            }
            return Ok(None);
        }
        Ok(crate::evm_adapter::global_adapter()
            .get_transaction_by_block_hash_and_index(&norm, index)?)
    }

    /// Transaction at `index` inside the block looked up by tag/number.
    /// Serve order: recent window receipts -> global adapter maps -> null.
    pub async fn eth_get_transaction_by_block_number_and_index(
        &self,
        tag: &crate::evm_adapter::BlockTag,
        index: u64,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let known = {
            let rb = self.recent_blocks.read().await;
            rb.iter().any(|b| b.height == want)
        };
        if known {
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            if let Some(r) = rows.iter().find(|r| r.index as u64 == index) {
                if let Some(evm_tx) =
                    crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id)
                {
                    return Ok(Some(evm_tx));
                }
                return Ok(None);
            }
            return Ok(None);
        }
        Ok(crate::evm_adapter::global_adapter()
            .get_transaction_by_block_number_and_index(tag, index)?)
    }

    /// Uncle count by block hash. Stellereum never produces uncles:
    /// known block -> `"0x0"`, unknown block -> null.
    pub async fn eth_get_uncle_count_by_block_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if rb.iter().any(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            return Ok(Some("0x0".to_string()));
        }
        drop(rb);
        Ok(crate::evm_adapter::global_adapter().get_uncle_count_by_block_hash(&norm)?)
    }

    /// Uncle count by tag/number. See [`Self::eth_get_uncle_count_by_block_hash`].
    pub async fn eth_get_uncle_count_by_block_number(
        &self,
        tag: &crate::evm_adapter::BlockTag,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if rb.iter().any(|b| b.height == want) {
            return Ok(Some("0x0".to_string()));
        }
        drop(rb);
        Ok(crate::evm_adapter::global_adapter().get_uncle_count_by_block_number(tag)?)
    }

    /// Uncle at `index` by block hash. Stellereum never produces uncles: always null.
    /// The block hash is still validated so malformed requests error with -32602.
    pub async fn eth_get_uncle_by_block_hash_and_index(
        &self,
        hash: &str,
        _index: u64,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        crate::evm_adapter::normalize_hash(hash).map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        Ok(None)
    }

    /// Uncle at `index` by tag/number. Always null (no uncles on Stellereum).
    pub async fn eth_get_uncle_by_block_number_and_index(
        &self,
        _tag: &crate::evm_adapter::BlockTag,
        _index: u64,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        Ok(None)
    }

    pub async fn handle_get_block_transaction_count_by_hash(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_block_transaction_count_by_hash(&hash_str).await
    }

    pub async fn handle_get_block_transaction_count_by_number(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let tag = crate::evm_adapter::parse_single_block_tag_param(params)?;
        self.eth_get_block_transaction_count_by_number(&tag).await
    }

    pub async fn handle_get_transaction_by_block_hash_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let (hash_str, index) = crate::evm_adapter::parse_block_hash_and_index_params(params)?;
        self.eth_get_transaction_by_block_hash_and_index(&hash_str, index).await
    }

    pub async fn handle_get_transaction_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let (tag, index) = crate::evm_adapter::parse_block_number_and_index_params(params)?;
        self.eth_get_transaction_by_block_number_and_index(&tag, index).await
    }

    pub async fn handle_get_uncle_count_by_block_hash(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_uncle_count_by_block_hash(&hash_str).await
    }

    pub async fn handle_get_uncle_count_by_block_number(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let tag = crate::evm_adapter::parse_single_block_tag_param(params)?;
        self.eth_get_uncle_count_by_block_number(&tag).await
    }

    pub async fn handle_get_uncle_by_block_hash_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        let (hash_str, index) = crate::evm_adapter::parse_block_hash_and_index_params(params)?;
        self.eth_get_uncle_by_block_hash_and_index(&hash_str, index).await
    }

    pub async fn handle_get_uncle_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        let (tag, index) = crate::evm_adapter::parse_block_number_and_index_params(params)?;
        self.eth_get_uncle_by_block_number_and_index(&tag, index).await
    }

    /// One-shot `eth_getLogs` over the node's committed history.
    ///
    /// Serve order: local committed (`recent_blocks` window + `receipts`
    /// index, via [`crate::evm_adapter::stell_receipt_to_evm`]) merged with
    /// the global EVM adapter's committed receipts, filtered by
    /// `fromBlock` / `toBlock` / `address` / `topics` through
    /// [`crate::evm_adapter::FilterCriteria::matches`], sorted
    /// deterministically and capped at 1000 logs.
    ///
    /// Honest emptiness: Stellereum executes no EVM logs today, so
    /// [`crate::evm_adapter::stell_receipt_to_evm`] carries `logs: []` and a
    /// node with no EVM receipts returns `[]` (never fabricated logs).
    pub async fn eth_get_logs(
        &self,
        params: &Value,
    ) -> Result<Value, crate::evm_adapter::JsonRpcError> {
        use crate::evm_adapter as evm;
        let criteria = evm::FilterCriteria::from_value(params)?;
        let block_hash_filter = evm::extract_block_hash_filter(params);
        // Touch the recent window so the query is scoped to committed history
        // (heights outside it are still served via the global adapter below).
        let _head = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let _window_len = self.recent_blocks.read().await.len();
        // Local committed receipts (currently log-free, kept for when execution emits logs).
        let mut out: Vec<evm::EvmLog> = {
            let idx = self.receipts.read().await;
            let mut local = Vec::new();
            for r in idx.map.values() {
                let evm_receipt = evm::stell_receipt_to_evm(r);
                for log in &evm_receipt.logs {
                    if let Some(ref want) = block_hash_filter {
                        match &log.block_hash {
                            Some(have) if have.to_lowercase() == want.to_lowercase() => {}
                            _ => continue,
                        }
                    }
                    if criteria.matches(log) {
                        local.push(log.clone());
                        if local.len() >= evm::MAX_GET_LOGS_RESULTS {
                            break;
                        }
                    }
                }
                if local.len() >= evm::MAX_GET_LOGS_RESULTS {
                    break;
                }
            }
            local
        };
        // Global EVM adapter receipts (EVM intents / bridged logs).
        if out.len() < evm::MAX_GET_LOGS_RESULTS {
            let mut global =
                evm::global_adapter().collect_matching_logs(&criteria, block_hash_filter.as_deref());
            out.append(&mut global);
        }
        out.sort_by(|a, b| evm::log_sort_key(a).cmp(&evm::log_sort_key(b)));
        out.truncate(evm::MAX_GET_LOGS_RESULTS);
        Ok(serde_json::json!(out))
    }

    /// Alias matching JSON-RPC casing for `eth_get_logs`.
    #[allow(non_snake_case)]
    pub async fn eth_getLogs(
        &self,
        params: &Value,
    ) -> Result<Value, crate::evm_adapter::JsonRpcError> {
        self.eth_get_logs(params).await
    }

    /// `eth_getStorageAt(address, position, tag)`: no EVM state trie exists,
    /// so every slot honestly reads as empty (32 zero bytes). Validates params,
    /// never fabricates state.
    pub async fn eth_get_storage_at(
        &self,
        params: &Value,
    ) -> Result<String, crate::evm_adapter::JsonRpcError> {
        crate::evm_adapter::global_adapter()
            .eth_get_storage_at(params)
    }

    /// Alias matching JSON-RPC casing for `eth_get_storage_at`.
    #[allow(non_snake_case)]
    pub async fn eth_getStorageAt(
        &self,
        params: &Value,
    ) -> Result<String, crate::evm_adapter::JsonRpcError> {
        self.eth_get_storage_at(params).await
    }

    /// Programmatic RPC call helper (for testing and embedded harnesses).
    pub async fn call(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let r = dispatch(self, serde_json::Value::from(1), method, &params, None, None).await;
        r.0.error
            .map(|e| serde_json::json!({"error": e.message}))
            .unwrap_or(r.0.result.unwrap_or(serde_json::Value::Null))
    }
}

/// Refill an RPC index from the durable receipt store (restart hydration).
///
/// Reads at most `MAX_RECEIPTS` receipts tip-ward (highest height first, so a
/// cold index serves the tip first) and imports them into `st`. Bounded:
/// never more than the in-memory cap. Pure orchestration over the two stores;
/// the durable side stays the source of truth.
pub async fn hydrate_rpc_from_store(st: &RpcState, store: &crate::storage::Storage) {
    let mut all = store.all_receipts_capped(MAX_RECEIPTS).unwrap_or_default();
    all.sort_by_key(|r| std::cmp::Reverse((r.height, r.index)));
    all.truncate(MAX_RECEIPTS);
    // Insert oldest-first so the index's VecDeque order ends tip-last like the
    // live path (insertion order = inclusion order within the window).
    all.reverse();
    for r in &all {
        st.import_stored_receipt(r).await;
    }
    // Rebuild the explorer window from header records (which survive body
    // pruning), tip-ward, newest-first like `record_block` maintains.
    if let Ok(Some(tip_rec)) = store.latest_header() {
        let tip = tip_rec.height;
        let mut summaries: Vec<BlockSummary> = Vec::new();
        let lo = tip.saturating_sub(MAX_RECENT_BLOCKS as u64 - 1);
        for h in (lo..=tip).rev() {
            if let Ok(Some(rec)) = store.header_at(h) {
                summaries.push(BlockSummary {
                    height: rec.height,
                    hash: hex::encode(rec.block_hash),
                    tx_count: rec.tx_count as usize,
                    timestamp: rec.timestamp,
                });
            }
        }
        let mut rb = st.recent_blocks.write().await;
        rb.clear();
        for s in summaries {
            rb.push_back(s);
            while rb.len() > MAX_RECENT_BLOCKS {
                rb.pop_back();
            }
        }
        st.height.store(tip, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Serve fallback order for receipts and block-txs (documented, pinned by tests):
/// 1. local committed (in-memory receipts / recent window, fed by the single
///    real application via `record_receipts`/`record_block`/`record_adopted_block`);
/// 2. durable store import (`hydrate_rpc_from_store` after a restart);
/// 3. honest "not available yet" (`unknown` / `not available yet` error) --
///    never fabricated data, never a consensus stall.
pub const SERVE_FALLBACK_ORDER_DOC: &str =
    "local committed -> durable store -> honest not-available-yet (never fabricated)";

#[derive(Deserialize)]
pub struct RpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// Handles a parsed RPC request directly against an `RpcState`.
pub async fn handle_rpc_call(st: &RpcState, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone().unwrap_or(Value::Null);
    let res = dispatch(st, id, &req.method, &req.params, None, None).await;
    res.0
}

#[derive(Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

fn ok(id: Value, result: Value) -> Json<RpcResponse> {
    Json(RpcResponse { jsonrpc: "2.0", id, result: Some(result), error: None })
}

fn err(id: Value, code: i64, message: impl Into<String>) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError { code, message: message.into(), data: None }),
    })
}

/// Parse a 32-byte hex string (with or without 0x).
fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
    b.try_into().map_err(|_| "expected 32 bytes".to_string())
}

/// Shared admission path for the WRITE-shaped `stell_submit*` arms.
///
/// THIN by design: it token-gates, decodes and verifies the wrapping
/// transaction, checks that the payload actually carries the thing the method
/// name promises, and admits it to the mempool. It never writes consensus
/// state - a price, a swap or an order only exists once a proposer includes the
/// transaction in a block and every node re-runs the opcode against
/// `block.timestamp`. Writing here would make the result node-local, which is
/// exactly the bug each of these arms exists to avoid.
///
/// `carries` is the payload-shape predicate; `wrong_payload` is what a caller
/// that sent some other transaction under this method name is told.
async fn admit_signed_payload_tx(
    st: &RpcState,
    id: Value,
    params: &Value,
    header_token: Option<&str>,
    method: &str,
    carries: impl Fn(&crate::svm::OpCode) -> bool,
    wrong_payload: &str,
) -> Json<RpcResponse> {
    // Gated by the deployment's `auth_token` (when configured): pending
    // mempool contents are non-public, and these arms also tell a caller
    // what the payload is about to do. NOTE: this is NOT "the same gate as
    // sendRawTransaction" — the send paths (`stell_sendRawTransaction`,
    // `eth_sendRawTransaction`) are OPEN submission by design (self-
    // authenticating signed txs); only these introspection/payload arms plus
    // `stell_mempoolDump` take the token.
    if let Some(expected) = &st.auth_token {
        let provided = params["token"]
            .as_str()
            .or_else(|| params["apiKey"].as_str())
            .or(header_token);
        if !provided
            .map(|p| constant_time_eq(p, expected.as_str()))
            .unwrap_or(false)
        {
            return err(id, -32001, "unauthorized: missing or invalid API token");
        }
    }
    // params: { "tx": <hex of bincode(Transaction)> }
    let raw = match params["tx"].as_str() {
        Some(s) => s,
        None => return err(id, -32602, "missing tx"),
    };
    let s = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = match hex::decode(s) {
        Ok(b) => b,
        Err(e) => return err(id, -32602, format!("bad hex: {e}")),
    };
    if bytes.len() > MAX_RPC_BODY {
        return err(id, -32602, "transaction too large");
    }
    let tx: Transaction = match bincode::deserialize(&bytes) {
        Ok(t) => t,
        Err(e) => return err(id, -32602, format!("decode: {e}")),
    };
    if !tx.verify_signature() {
        return err(id, -32000, "invalid transaction signature");
    }
    if !tx.payload.iter().any(|op| carries(op)) {
        return err(id, -32602, wrong_payload);
    }
    let acct = st.engine.get_account(&tx.from).await;
    let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
    let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
    // The write guard must be released BEFORE `save_mempool_throttled`, which
    // takes the same lock for reading: keeping it as a `match` scrutinee
    // temporary would hold it for the whole body and self-deadlock on the first
    // admission of a fresh process (the throttle is only skipped once some
    // admission has already saved).
    let admitted = {
        let mut pool = st.mempool.write().await;
        // Nonce-gap fail-fast, same as `stell_sendRawTransaction` (audit:
        // blocks troubles): far-future nonces sat in the pool forever behind
        // an unreachable head.
        if let Some(gap) = pool.check_nonce_gap(&tx.from, tx.nonce, onchain_nonce) {
            tracing::warn!(
                "[mempool] rejecting gapped payload tx from {}: {gap}",
                hex::encode(&tx.from[..6])
            );
            return err(id, -32000, format!("rejected: {gap}"));
        }
        pool.add_checked_ctx(tx.clone(), balance, AdmissionCtx::wall_now())
    };
    match admitted {
        Ok(hash) => {
            // Propagate verified transaction to P2P peers via gossip.
            if let Some(bcast) = &st.tx_broadcast {
                let _ = bcast.send(tx);
            }
            crate::evm_adapter::notify_pending_tx(crate::evm_adapter::stell_hash_to_evm(&hash));
            st.save_mempool_throttled().await;
            let _ = method;
            ok(id, json!(hex::encode(hash)))
        }
        Err(e) => err(id, -32000, format!("rejected: {e}")),
    }
}

/// Dispatch a single RPC call to its handler.
/// `header_token` is a token presented in an HTTP header, if any. Write methods
/// accept the token either in `params` or in a header, so a caller does not have
/// to put a credential in the request body.
async fn dispatch(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Json<RpcResponse> {
    match method {
        // ---- chain / node info ----
        "stell_chainId" => ok(id, json!(st.chain_id)),
        "stell_nodeId" => ok(id, json!(st.node_id)),
        // ---- EVM JSON-RPC adapter network info & state ----
        "eth_chainId" => ok(id, json!(crate::evm_adapter::eth_chain_id())),
        "net_version" => ok(id, json!(crate::evm_adapter::net_version())),
        "web3_clientVersion" => ok(id, json!(crate::evm_adapter::web3_client_version())),
        "net_listening" => ok(id, json!(crate::evm_adapter::net_listening())),
        // TESTNET-KNOWN default ("0x2"): `RpcState` carries no peer table, so
        // there is no live count to format here. The stateful `EvmAdapter`
        // (`with_peer_count` + `format_peer_count_hex`) is the live path.
        "net_peerCount" => ok(id, json!(crate::evm_adapter::net_peer_count())),
        // LIVE (cheap): same rule as `stell_syncing` — a recent verified peer
        // height above ours means syncing. Was a hardcoded `false`.
        "eth_syncing" => {
            let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
            ok(id, json!(crate::evm_adapter::eth_syncing_for_heights(ours, fresh_peer_height())))
        }
        // TESTNET-KNOWN default: the mempool `base_fee` is an admission floor
        // in gas units, not a wei price — mapping it here would mix units.
        "eth_gasPrice" => ok(id, json!(crate::evm_adapter::eth_gas_price())),
        "eth_maxPriorityFeePerGas" => ok(id, json!(crate::evm_adapter::eth_max_priority_fee_per_gas())),
        // Floor-aware admission estimate (audit 2026-10-14 F4): the EVM
        // 21k-style figure alone disagrees with the mempool's declared-gas
        // floor (`stell_baseFee`), so wallets are told the max of the two —
        // the least gas this node will currently admit. Still an admission
        // estimate, not execution metering (calldata is never executed).
        "eth_estimateGas" => {
            let floor = st.mempool.read().await.base_fee;
            match crate::evm_adapter::eth_estimate_gas_with_floor(params, floor) {
                Ok(gas) => ok(id, json!(gas)),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_feeHistory" => {
            let cur_h = st.height.load(std::sync::atomic::Ordering::Relaxed);
            match crate::evm_adapter::eth_fee_history_with_head(params, cur_h) {
                Ok(fh) => match serde_json::to_value(fh) {
                    Ok(v) => ok(id, v),
                    Err(e) => err(id, crate::evm_adapter::INTERNAL_ERROR_CODE, e.to_string()),
                },
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getCode" => match crate::evm_adapter::handle_eth_get_code(params) {
            Ok(code) => ok(id, json!(code)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getBalance" => match crate::evm_adapter::eth_get_balance(&st.engine, params).await {
            Ok(bal) => ok(id, json!(bal)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getTransactionCount" => match crate::evm_adapter::eth_get_transaction_count(&st.engine, params).await {
            Ok(cnt) => ok(id, json!(cnt)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_blockNumber" => {
            ok(id, json!(st.eth_block_number()))
        }
        "eth_getBlockByNumber" => {
            match st.handle_get_block_by_number(params).await {
                Ok(Some(b)) => ok(id, json!(b)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getBlockByHash" => {
            match st.handle_get_block_by_hash(params).await {
                Ok(Some(b)) => ok(id, json!(b)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionReceipt" => {
            match st.handle_get_transaction_receipt(params).await {
                Ok(Some(r)) => ok(id, json!(r)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByHash" => {
            match st.handle_get_transaction_by_hash(params).await {
                Ok(Some(tx)) => ok(id, json!(tx)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        },
        "eth_getBlockTransactionCountByHash" => {
            match st.handle_get_block_transaction_count_by_hash(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getBlockTransactionCountByNumber" => {
            match st.handle_get_block_transaction_count_by_number(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            match st.handle_get_transaction_by_block_hash_and_index(params).await {
                Ok(Some(tx)) => ok(id, json!(tx)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            match st.handle_get_transaction_by_block_number_and_index(params).await {
                Ok(Some(tx)) => ok(id, json!(tx)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleCountByBlockHash" => {
            match st.handle_get_uncle_count_by_block_hash(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleCountByBlockNumber" => {
            match st.handle_get_uncle_count_by_block_number(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleByBlockHashAndIndex" => {
            match st.handle_get_uncle_by_block_hash_and_index(params).await {
                Ok(_) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleByBlockNumberAndIndex" => {
            match st.handle_get_uncle_by_block_number_and_index(params).await {
                Ok(_) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_call" => match crate::evm_adapter::eth_call_with_engine(&st.engine, params).await {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_newBlockFilter" => ok(id, json!(crate::evm_adapter::eth_new_block_filter())),
        "eth_newPendingTransactionFilter" => {
            ok(id, json!(crate::evm_adapter::eth_new_pending_transaction_filter()))
        }
        "eth_newFilter" => match crate::evm_adapter::eth_new_filter(params) {
            Ok(v) => ok(id, json!(v)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getFilterChanges" => match crate::evm_adapter::eth_get_filter_changes(params) {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getFilterLogs" => match crate::evm_adapter::eth_get_filter_logs(params) {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_uninstallFilter" => match crate::evm_adapter::eth_uninstall_filter(params) {
            Ok(v) => ok(id, json!(v)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getLogs" => match st.eth_get_logs(params).await {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getStorageAt" => match st.eth_get_storage_at(params).await {
            Ok(v) => ok(id, json!(v)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_sendRawTransaction" => {
            // Phase-2 settlement: the SAME bytes feed the intent pool AND the
            // consensus mempool. Order matters: build the L1 leg and admit it
            // via `add_checked_ctx` FIRST (pure + balance/nonce-gated, no side
            // effects on failure), and only then file the EVM intent — so a
            // mempool rejection never leaves a stale pending intent behind.
            // Returns the EVM keccak hash, as MetaMask expects.
            let raw = match crate::evm_adapter::extract_raw_evm_bytes(params) {
                Ok(raw) => raw,
                Err(e) => return err(id, e.code, e.message),
            };
            let stell_tx = match crate::evm_adapter::evm_raw_to_stell_transaction(&raw) {
                Ok(tx) => tx,
                Err(reason) => return err(id, -32603, reason),
            };
            let acct = st.engine.get_account(&stell_tx.from).await;
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            // The write guard must be released BEFORE `save_mempool_throttled`
            // (same deadlock discipline as `stell_sendRawTransaction`).
            let admitted = {
                let mut pool = st.mempool.write().await;
                // Nonce-gap fail-fast: a far-future EVM nonce would sit in the
                // pool forever behind an unreachable head.
                if let Some(gap) = pool.check_nonce_gap(&stell_tx.from, stell_tx.nonce, onchain_nonce) {
                    tracing::warn!(
                        "[mempool] rejecting gapped EVM tx from {}: {gap}",
                        hex::encode(&stell_tx.from[..6])
                    );
                    return err(id, -32000, format!("rejected: {gap}"));
                }
                pool.add_checked_ctx(stell_tx.clone(), balance, AdmissionCtx::wall_now())
            };
            let _stell_hash = match admitted {
                Ok(h) => h,
                Err(e) => return err(id, -32000, format!("rejected: {e}")),
            };
            // L1 leg admitted: file the intent (re-verifies the same bytes,
            // so this cannot fail after the conversion above passed).
            let evm_hash = match crate::evm_adapter::eth_send_raw_transaction_bytes(&raw) {
                Ok(h) => h,
                Err(e) => return err(id, e.code, e.message),
            };
            // Propagate the settled transaction to P2P peers via gossip.
            if let Some(bcast) = &st.tx_broadcast {
                let _ = bcast.send(stell_tx);
            }
            st.save_mempool_throttled().await;
            ok(id, json!(evm_hash))
        }
        "stell_blockNumber" => {
            let h = st.height.load(std::sync::atomic::Ordering::Relaxed);
            ok(id, json!(format!("0x{:x}", h)))
        }
        "stell_syncing" => {
            // True while a RECENT verified sighting names a height above ours
            // (audit 2026-10-06 + follow-up: was hardcoded false; then a bare
            // max that pinned true forever on one faulty vote). Vantage-local.
            let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let syncing = fresh_peer_height().map(|peer| peer > ours).unwrap_or(false);
            ok(id, json!(syncing))
        }
        "stell_getStateRoot" => {
            // DELIBERATE read-with-fold (audit 2026-10-14 F2/I3): `get_state_root`
            // folds exactly one deterministic commitment key when the commitment
            // digest is stale, under the trie write lock. The fold is a pure
            // function of committed subsystems, so every node that applied the
            // same blocks serves the same root — a reader-observable write, not
            // a divergence. Hot scrapes briefly serialize on the lock; the
            // per-IP limiters bound scrape storms.
            let root = st.engine.get_state_root().await;
            ok(id, json!(hex::encode(root)))
        }
        "stell_latestBlocks" => {
            let rb = st.recent_blocks.read().await;
            let list: Vec<Value> = rb
                .iter()
                .map(|b| json!({
                    "height": b.height,
                    "hash": b.hash,
                    "txs": b.tx_count,
                    "timestamp": b.timestamp,
                }))
                .collect();
            ok(id, json!(list))
        }
        "stell_getBlock" => {
            // Serve order: local committed window (fed by finalize AND adopt via
            // `record_adopted_block`, so any node serves adopted heights) ->
            // honest "not available yet". Never fabricated: a height outside the
            // window is a miss, not a zero-tx fabrication.
            let want = params["height"].as_u64();
            let rb = st.recent_blocks.read().await;
            let found = rb.iter().find(|b| Some(b.height) == want);
            match found {
                Some(b) => ok(id, json!({
                    "height": b.height,
                    "hash": b.hash,
                    "txs": b.tx_count,
                    "timestamp": b.timestamp,
                })),
                None => err(id, -32004, "block not available yet (not in recent window; replication runs behind finalization)"),
            }
        }
        // Block transactions, served from the SAME receipt index as
        // `stell_getTransactionReceipt` (filed by the single real application on
        // finalize AND on adopt -- so any node serves adopted heights). Fallback
        // order: local committed receipts -> honest "not available yet", never
        // fabricated (an empty list is only returned when the block is KNOWN
        // with zero transactions, not when it is unknown).
        "stell_getBlockTransactions" => {
            let want = match params["height"].as_u64().or_else(|| params.as_u64()) {
                Some(h) => h,
                None => return err(id, -32602, "missing height"),
            };
            // Known height = in the recent window (committed locally or adopted).
            let known = st.recent_blocks.read().await.iter().any(|b| b.height == want);
            if !known {
                return err(id, -32004, "block transactions not available yet (height not adopted/replicated on this node)");
            }
            let idx = st.receipts.read().await;
            let mut rows: Vec<&TxReceipt> =
                idx.map.values().filter(|r| r.height == want).collect();
            rows.sort_by_key(|r| r.index);
            let list: Vec<Value> = rows
                .iter()
                .map(|r| {
                    let mut obj = json!({
                        "tx_hash": hex::encode(r.tx_hash),
                        "index": r.index,
                        "status": if r.success { "success" } else { "failed" },
                        "gas_limit": r.gas_limit.to_string(),
                        "fee_charged": r.fee_charged.to_string(),
                    });
                    if let Some(ref raw) = r.raw_tx {
                        obj["raw_tx"] = json!(raw);
                    }
                    obj
                })
                .collect();
            ok(id, json!({ "height": want, "txs": list }))
        }

        // ---- accounts ----
        "stell_faucet" => {
            let Some(faucet) = st.faucet.clone() else {
                return err(id, -32601, "faucet is disabled on this node");
            };
            // Fail-closed: the faucet mints money, so "no token configured" must
            // never degrade into "anyone who can reach this port may mint".
            // The faucet token is separate from the general write token so that
            // a public testnet can offer read-only queries freely while still
            // rationing who may draw from the treasury.
            let Some(expected) = st.faucet_token.as_deref() else {
                return err(
                    id,
                    -32001,
                    "faucet is enabled but STELL_FAUCET_TOKEN is not set; refusing to dispense",
                );
            };
            let provided = params["token"]
                .as_str()
                .or_else(|| params["apiKey"].as_str())
                .or(header_token);
            if !provided.map(|p| constant_time_eq(p, expected)).unwrap_or(false) {
                return err(id, -32001, "unauthorized: missing or invalid faucet token");
            }
            // Per-source throttle, same budget as the explorer path (audit
            // follow-up: this path skipped it entirely, so the token holder
            // could rotate addresses without limit here). Unattributed callers
            // share the fallback bucket — they are throttled, not exempt.
            {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if !faucet.check_ip_throttle(peer_ip, now_secs).await {
                    return err(id, -32000, "per-IP faucet budget exhausted for this hour");
                }
            }
            let addr = match params["address"].as_str().or_else(|| params.as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            let a = match parse_hash(addr) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            // Reconcile inputs for the atomic mex inside build_transfer: the
            // on-chain nonce plus our own pending nonces from the shared
            // mempool. Without this, reserved-but-never-executed drips (wiped
            // mempool across a restart) leave a permanent gap that new drips
            // wait behind forever.
            let faucet_addr = faucet.account();
            let onchain = st
                .engine
                .get_account(&faucet_addr)
                .await
                .map(|acc| acc.nonce)
                .unwrap_or(0);
            let pending: Vec<u64> = st
                .mempool
                .read()
                .await
                .all()
                .iter()
                .filter(|t| t.from == faucet_addr)
                .map(|t| t.nonce)
                .collect();
            let Some((tx, amount)) = faucet
                .build_transfer(a, params["amount"].as_u64(), Some((onchain, pending)))
                .await
            else {
                return err(id, -32000, "faucet limit reached for this address");
            };
            let balance = st
                .engine
                .get_account(&faucet.account())
                .await
                .map(|acc| acc.balance)
                .unwrap_or(0);
            let tx_hash = match st.mempool.write().await.add_checked_ctx(tx.clone(), balance, AdmissionCtx::wall_now()) {
                Ok(h) => h,
                Err(e) => {
                    faucet.rollback(&tx, a, amount).await;
                    return err(id, -32000, format!("faucet transfer rejected: {e}"));
                }
            };
            st.save_mempool_throttled().await;
            if let Some(bcast) = &st.tx_broadcast {
                let _ = bcast.send(tx);
            }
            ok(id, json!({
                "credited_nano": amount.to_string(),
                "recipient": hex::encode(a),
                "tx_hash": hex::encode(tx_hash),
            }))
        }
        "stell_getBalance" => {
            let addr = match params.as_str().or_else(|| params["address"].as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            let a = match parse_hash(addr) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let acc = st.engine.get_account(&a).await;
            let (bal, nonce) = acc.map(|x| (x.balance, x.nonce)).unwrap_or((0, 0));
            ok(id, json!({ "balance": bal.to_string(), "nonce": nonce }))
        }
        "stell_getBalanceSpv" => {
            // Returns balance + Merkle proof + state root so a light client can verify.
            let addr = match params["address"].as_str() {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            let a = match parse_hash(addr) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let acc = st.engine.get_account(&a).await;
            let (balance, nonce) = acc.as_ref().map(|x| (x.balance, x.nonce)).unwrap_or((0, 0));
            let root = st.engine.get_state_root().await;
            let root_hex = hex::encode(root);
            let proof = st.engine.get_account_proof(&a).await;
            let leaf_data = acc.as_ref().map(|x| hex::encode(x.to_trie_bytes()));
            ok(id, json!({
                "address": hex::encode(a),
                "balance": balance.to_string(),
                "nonce": nonce,
                "stateRoot": root_hex,
                "state_root": root_hex,
                "leafData": leaf_data,
                "leaf_data": leaf_data,
                "proof": proof,
            }))
        }

        // ---- bridge disputes (optimistic L1; read-only for watchers) ----
        "stell_bridgeDeposit" => {
            // Deposit acceptance record by source-chain tx hash: recipient,
            // amount, admission path (quorum vs evidence), age, disputed flag.
            // No record (pre-dispute deposits) = unchallengeable, not missing.
            let h = match params.as_str().or_else(|| params["source_tx_hash"].as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing source_tx_hash"),
            };
            let hash = match parse_hash(h) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let br = st.engine.bridge_read().await;
            match br.deposit_records.get(&hash) {
                None => ok(id, json!({ "found": false })),
                Some(r) => ok(id, json!({
                    "found": true,
                    "recipient": hex::encode(r.recipient),
                    "amount": r.amount.to_string(),
                    "chain": format!("{:?}", r.chain),
                    "via_quorum": r.via_quorum,
                    "deposited_at": r.deposited_at,
                    "disputed": r.disputed,
                })),
            }
        }
        "stell_bridgeDispute" => {
            // Open or resolved dispute by id: full state for watcher
            // dashboards (deadline countdown, outcome).
            let did = match params.as_str().or_else(|| params["dispute_id"].as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing dispute_id"),
            };
            let did: u64 = match did.parse() {
                Ok(v) => v,
                Err(_) => return err(id, -32602, "bad dispute_id"),
            };
            let br = st.engine.bridge_read().await;
            match br.disputes.get(&did) {
                None => ok(id, json!({ "found": false })),
                Some(d) => ok(id, json!({
                    "found": true,
                    "dispute_id": did,
                    "source_tx_hash": hex::encode(d.source_tx_hash),
                    "challenger": hex::encode(d.challenger),
                    "recipient": hex::encode(d.recipient),
                    "amount": d.amount.to_string(),
                    "bond": d.bond.to_string(),
                    "deadline": d.deadline,
                    "resolved": d.resolved,
                    "confirmed": d.confirmed,
                })),
            }
        }

        // ---- tokens ----
        "stell_tokenBalance" => {
            let token = params["token"].as_str().and_then(|s| parse_hash(s).ok());
            let account = params["account"].as_str().and_then(|s| parse_hash(s).ok());
            match (token, account) {
                (Some(t), Some(a)) => {
                    let bal = st.engine.token_balance(&t, &a).await;
                    ok(id, json!(bal.to_string()))
                }
                _ => err(id, -32602, "missing token/account"),
            }
        }
        "stell_tokenSupply" => {
            let token = match params["token"].as_str().and_then(|s| parse_hash(s).ok()) {
                Some(t) => t,
                None => return err(id, -32602, "missing token"),
            };
            ok(id, json!(st.engine.token_total_supply(&token).await.unwrap_or(0).to_string()))
        }
        "stell_tokenResolve" => {
            // Read-only id discovery for tokens created on chain: the
            // create-tx receipt carries no token id, and the id commits the
            // registry nonce (unpredictable off chain), so clients resolve by
            // the (creator, name, symbol) they chose at creation.
            let creator = params["creator"].as_str().and_then(|s| parse_hash(s).ok());
            let name = params["name"].as_str().unwrap_or("");
            let symbol = params["symbol"].as_str().unwrap_or("");
            // Empty names widen collision/phishing surface (audit follow-up);
            // real tokens always carry both.
            if name.is_empty() || symbol.is_empty() {
                return err(id, -32602, "missing name/symbol");
            }
            match creator {
                Some(c) => match st.engine.token_resolve(&c, name, symbol).await {
                    Some(tid) => ok(id, json!({ "token": hex::encode(tid) })),
                    None => err(id, -32004, "token not found"),
                },
                None => err(id, -32602, "missing creator"),
            }
        }
        "stell_tokenBalanceSpv" => {
            let token = params["token"].as_str().and_then(|s| parse_hash(s).ok());
            let account = params["account"].as_str().and_then(|s| parse_hash(s).ok());
            match (token, account) {
                (Some(t), Some(a)) => {
                    let bal = st.engine.token_balance(&t, &a).await;
                    let root = st.engine.get_state_root().await;
                    let proof = st.engine.get_token_balance_proof(&t, &a).await;
                    let key = hex::encode(token_balance_key(&t, &a));
                    ok(id, json!({
                        "balance": bal.to_string(),
                        "stateRoot": hex::encode(root),
                        "key": key,
                        "proof": proof,
                    }))
                }
                _ => err(id, -32602, "missing token/account"),
            }
        }
        "stell_listTokens" => {
            // Paginated (audit 2026-10-06): creation is permissionless so the
            // registry is attacker-growable; an unbounded dump is a DoS
            // amplifier. `limit` default 100, hard max 1000.
            let limit = params["limit"].as_u64().unwrap_or(100).min(1000) as usize;
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            // Bounded iteration (audit 2026-10-06): creation is permissionless
            // so the registry is attacker-growable. Walk the registry directly
            // and stop after offset+limit instead of materializing every id;
            // skip/take semantics (and `total`) are unchanged.
            let tokens = st.engine.tokens_read().await;
            let total = tokens.token_count();
            let ids: Vec<String> =
                tokens.tokens.keys().skip(offset).take(limit).map(hex::encode).collect();
            ok(id, json!({ "tokens": ids, "total": total, "offset": offset }))
        }

        // ---- receipts (P0-3) ----
        // Without these a wallet can only ask "is my hash in the mempool", and
        // can never learn whether its transaction was finalised or failed.
        "stell_getTransactionReceipt" => {
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
                    let mut obj = json!({
                        "tx_hash": hex::encode(r.tx_hash),
                        "height": r.height,
                        "block_hash": hex::encode(r.block_hash),
                        "index": r.index,
                        "status": if r.success { "success" } else { "failed" },
                        "gas_limit": r.gas_limit.to_string(),
                        "fee_charged": r.fee_charged.to_string(),
                    });
                    if let Some(ref raw) = r.raw_tx {
                        obj["raw_tx"] = json!(raw);
                    }
                    ok(id, obj)
                }
                None => {
                    let pending = st.mempool.read().await.contains(&h);
                    ok(id, json!({ "status": if pending { "pending" } else { "unknown" } }))
                }
            }
        }
        "stell_getTransactionStatus" => {
            let h = match params["hash"]
                .as_str()
                .or_else(|| params.as_str())
                .and_then(|s| parse_hash(s).ok())
            {
                Some(h) => h,
                None => return err(id, -32602, "missing tx hash"),
            };
            let idx = st.receipts.read().await;
            let status = match idx.get(&h) {
                Some(r) if r.success => "success",
                Some(_) => "failed",
                None => "unknown",
            };
            let height = idx.get(&h).map(|r| r.height);
            drop(idx);
            let pending = status == "unknown" && st.mempool.read().await.contains(&h);
            ok(id, json!({
                "status": if pending { "pending" } else { status },
                "height": height,
            }))
        }
        // ---- staking ----
        // Read from the STATE ENGINE, not from a node-local copy: the validator
        // set is derived from this ledger at every height boundary, so a value
        // that existed only on this node would make it propose a different chain.
        "stell_stakeOf" => {
            let v = match params["validator"].as_str().and_then(|s| parse_hash(s).ok()) {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let l = st.engine.staking_read().await;
            ok(id, json!({
                "total": l.total_stake(&v).to_string(),
                "self_bond": l.validators.get(&v).map(|x| x.self_bond).unwrap_or(0).to_string(),
                "delegated": l.validators.get(&v).map(|x| x.delegated).unwrap_or(0).to_string(),
            }))
        }
        "stell_getValidators" => {
            let ledger = st.engine.staking_read().await;
            let vs = ledger.to_validator_set();
            let list: Vec<Value> = vs
                .validators
                .iter()
                .map(|(k, p)| json!({ "validator": hex::encode(k), "power": p.to_string() }))
                .collect();
            // Quorum-safety (урок ночи C): `fragile` is true when the quorum
            // needs 100% of the set — notably any N=3 equal-stake set (3/3) —
            // so any single halt stops the chain. Advisory only (fail-open);
            // `fragile_reason` explains, null when healthy.
            let fragility = ledger.quorum_fragility();
            ok(id, json!({ "validators": list, "total_power": vs.total_power().to_string(), "quorum": vs.quorum_power().to_string(), "fragile": fragility.is_some(), "fragile_reason": fragility }))
        }

        // ---- governance ----
        "stell_proposal" => {
            let pid = match params["id"].as_u64().or_else(|| params.as_u64()) {
                Some(p) => p,
                None => return err(id, -32602, "missing or invalid proposal id (must be an unsigned integer)"),
            };
            let g = st.governance.read().await;
            match g.get(pid) {
                Some(p) => ok(id, json!({
                    "id": p.id,
                    "title": p.title,
                    "status": format!("{:?}", p.status),
                    "yes": p.yes.to_string(),
                    "no": p.no.to_string(),
                    "abstain": p.abstain.to_string(),
                    "turnout": p.turnout().to_string(),
                })),
                None => err(id, -32004, "proposal not found"),
            }
        }
        "stell_governanceParams" => {
            let g = st.governance.read().await;
            ok(id, json!({
                "quorum_bps": g.quorum_bps,
                "next_id": g.next_id,
                "applied": g.applied,
            }))
        }

        // ---- mempool ----
        "stell_mempoolSize" => {
            let n = st.mempool.read().await.len();
            ok(id, json!(n))
        }
        // Admission floor for wallets and harnesses: the minimum declared
        // `gas_limit` this node currently accepts into its mempool (and the
        // floor its proposer filter skips below). Read-only; refreshed from
        // max(env, governed) every finalized height, so a wallet asserts this
        // BEFORE blasting, not after its transactions bounce.
        "stell_baseFee" => {
            let floor = st.mempool.read().await.base_fee;
            ok(id, json!({ "base_fee": floor.to_string() }))
        }
        // TEMPORARY diagnostic for the empty-blocks hunt: list pending
        // (sender, nonce, hash). No signatures or amounts leave the node.
        // Gated by the deployment's `auth_token` (when configured) like the
        // signed-payload arms: pending mempool contents are non-public and
        // can aid front-running, so they must not be readable by an anonymous
        // caller. (The send paths stay OPEN — see the module docs.)
        "stell_mempoolDump" => {
            let Some(expected) = &st.auth_token else {
                return err(id, -32001, "unauthorized: stell_mempoolDump is disabled when auth_token is not configured");
            };
            let provided = params["token"]
                .as_str()
                .or_else(|| params["apiKey"].as_str())
                .or(header_token);
            if !provided.map(|p| constant_time_eq(p, expected)).unwrap_or(false) {
                return err(id, -32001, "unauthorized: missing or invalid API token");
            }
            let list: Vec<Value> = st
                .mempool
                .read()
                .await
                .all()
                .iter()
                .map(|t| {
                    json!({
                        "sender": hex::encode(&t.from[..6]),
                        "nonce": t.nonce,
                        "hash": hex::encode(&t.compute_tx_hash()[..6]),
                    })
                })
                .collect();
            ok(id, json!(list))
        }
        "stell_sendRawTransaction" => {
            // params: { "tx": <hex of bincode(Transaction)> }
            let raw = match params["tx"].as_str() {
                Some(s) => s,
                None => return err(id, -32602, "missing tx"),
            };
            let s = raw.strip_prefix("0x").unwrap_or(raw);
            let bytes = match hex::decode(s) {
                Ok(b) => b,
                Err(e) => return err(id, -32602, format!("bad hex: {e}")),
            };
            if bytes.len() > MAX_RPC_BODY {
                return err(id, -32602, "transaction too large");
            }
            let tx: Transaction = match bincode::deserialize(&bytes) {
                Ok(t) => t,
                Err(e) => return err(id, -32602, format!("decode: {e}")),
            };
            if !tx.verify_signature() {
                return err(id, -32000, "invalid transaction signature");
            }
            let acct = st.engine.get_account(&tx.from).await;
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            // Release the mempool write guard before the throttled save, which
            // reads the same lock; a `match` scrutinee temporary would hold it
            // through the body and deadlock the first admission in a process.
            // (Engine reads happen ABOVE, outside the pool guard: pool-then-
            // engine nesting the other way would deadlock against paths that
            // take them in the opposite order.)
            let admitted = {
                let mut pool = st.mempool.write().await;
                // Nonce-gap fail-fast (audit: blocks troubles): far-future
                // nonces sat in the pool forever behind an unreachable head.
                if let Some(gap) = pool.check_nonce_gap(&tx.from, tx.nonce, onchain_nonce) {
                    tracing::warn!(
                        "[mempool] rejecting gapped tx from {}: {gap}",
                        hex::encode(&tx.from[..6])
                    );
                    return err(id, -32000, format!("rejected: {gap}"));
                }
                pool.add_checked_ctx(tx.clone(), balance, AdmissionCtx::wall_now())
            };
            match admitted {
                Ok(hash) => {
                    // Propagate verified transaction to P2P peers via gossip:
                    if let Some(bcast) = &st.tx_broadcast {
                        let _ = bcast.send(tx);
                    }
                    crate::evm_adapter::notify_pending_tx(crate::evm_adapter::stell_hash_to_evm(&hash));
                    st.save_mempool_throttled().await;
                    ok(id, json!(hex::encode(hash)))
                }
                Err(e) => {
                    // Admission verdicts are node-local diagnostics gold (audit:
                    // blocks troubles — 76 silent rejections with no log line
                    // anywhere). Log every refusal with sender/nonce/fee.
                    tracing::warn!(
                        "[mempool] admission refused tx from {} nonce={} gas={}: {e}",
                        hex::encode(&tx.from[..6]),
                        tx.nonce,
                        tx.gas_limit
                    );
                    err(id, -32000, format!("rejected: {e}"))
                }
            }
        }
        // Submit a signed oracle price feed for block inclusion. THIN by
        // design: it decodes and verifies the wrapping transaction and admits
        // it to the mempool, nothing else. It does NOT write oracle state -
        // the price only becomes consensus state when a PROPOSER includes the
        // transaction in a block and every node re-runs
        // `OpCode::SysCallSubmitPriceFeed` against `block.timestamp`. Writing
        // here would make the price node-local (non-deterministic), which is
        // exactly the bug the block-time commit path exists to prevent.
        "stell_submitPriceFeed" => {
            admit_signed_payload_tx(
                st,
                id,
                params,
                header_token,
                method,
                |op| matches!(op, crate::svm::OpCode::SysCallSubmitPriceFeed(feed) if feed.verify()),
                "payload does not carry a validly signed price feed",
            )
            .await
        }

        // ---- Primary Market Maker -------------------------------------
        // Both swap arms are the same THIN admission path as
        // `stell_submitPriceFeed`: verify the wrapping transaction, check it
        // actually carries the opcode the method name promises, admit it. The
        // swap itself is applied by `execute_payload` when a proposer includes
        // the transaction, so no node can mint STELL or burn wUSDT by asking
        // for it over RPC - and two nodes cannot disagree about the curve,
        // because neither of them moved it yet.
        "stell_pmmBuy" => {
            admit_signed_payload_tx(
                st,
                id,
                params,
                header_token,
                method,
                |op| matches!(op, crate::svm::OpCode::SysCallPmmBuy { .. }),
                "payload does not carry SysCallPmmBuy",
            )
            .await
        }
        "stell_pmmSell" => {
            admit_signed_payload_tx(
                st,
                id,
                params,
                header_token,
                method,
                |op| matches!(op, crate::svm::OpCode::SysCallPmmSell { .. }),
                "payload does not carry SysCallPmmSell",
            )
            .await
        }
        // Read-only view of the committed curve. Nothing is written: the
        // governed buffer is reported from governance (where a passed
        // `SetPmmRedemptionBufferBps` actually lands), not from a copy the PMM
        // might be holding stale.
        "stell_pmmState" => {
            let (pmm, quote_token, treasury) = st.engine.pmm_state().await;
            let governed_buffer_bps = st
                .governance
                .read()
                .await
                .applied
                .pmm_redemption_buffer_bps
                .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS);
            ok(id, json!({
                "price_micro_usd": pmm.price_micro_usd(),
                "minted_nano": pmm.minted_nano.to_string(),
                "reserve_micro": pmm.reserve_micro.to_string(),
                "redemption_buffer_micro": pmm.redemption_buffer_micro.to_string(),
                "usable_reserve_micro": pmm.usable_reserve_micro().to_string(),
                "max_redeemable_stell": pmm.max_redeemable_stell().to_string(),
                "quote_token": quote_token.map(|t| hex::encode(t)),
                "treasury": hex::encode(treasury),
                "governed_buffer_bps": governed_buffer_bps,
            }))
        }

        // ---- orderbook (read-only) ------------------------------------
        // Depth must come from the COMMITTED book, not from a fresh local one:
        // a CLI that prints a book it just made up is reporting a market that
        // does not exist on any node.
        "stell_orderBook" => {
            let pair = if params.is_null() || params.as_object().map_or(false, |o| o.is_empty()) {
                1u32
            } else {
                let raw = match params["pair"].as_u64().or_else(|| params.as_u64()) {
                    Some(p) => p,
                    None => return err(id, -32602, "missing or invalid pair id (must be an integer)"),
                };
                match u32::try_from(raw) {
                    Ok(p) => p,
                    Err(_) => return err(id, -32602, format!("pair id {raw} out of bounds for u32")),
                }
            };
            let books = st.engine.orderbooks_read().await;
            let Some(book) = books.get_book(pair) else {
                return err(id, -32004, format!("unknown pair {pair}"));
            };
            let (best_bid, best_ask) = book.get_best_bid_ask();
            let (bid_levels, ask_levels) = book.depth();
            let mut bids: Vec<Value> = book
                .bids
                .iter()
                .take(20)
                .map(|(price, orders)| {
                    let available: u64 = orders.iter().map(|o| o.amount - o.filled).sum();
                    json!({
                        "price_micro_usd": price.0,
                        "orders": orders.len(),
                        "available_nano_stell": available,
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
                        "price_micro_usd": price,
                        "orders": orders.len(),
                        "available_nano_stell": available,
                    })
                })
                .collect();
            bids.sort_by_key(|v| v["price_micro_usd"].as_u64().unwrap_or(0));
            ok(id, json!({
                "pair": pair,
                "best_bid_micro_usd": best_bid,
                "best_ask_micro_usd": best_ask,
                "bid_levels": bid_levels,
                "ask_levels": ask_levels,
                "bids": bids,
                "asks": asks,
            }))
        }

        // ---- session-key budget (read-only) ----------------------------
        // Bot visibility into the COMMITTED `SessionKeyRegistry`: how much of
        // a session key's cumulative gas budget is spent. Read-only: no auth
        // token, like every other read method here (only writes are gated).
        // Source of truth is `st.engine.session_keys_read()` — the same
        // in-memory engine handle the execution path commits to — never a
        // parallel copy.
        //
        // Params: `{"session": "<64-hex session pubkey>"}` (also accepts the
        // bare hex string). Numbers are JSON numbers, matching the
        // small-counter convention elsewhere in this file (`stell_chainId`,
        // `height`, `nonce`, `timestamp`); `master` is 64-char hex.
        // Unknown key: zeros + `registered: false`. `chain_id` is the node's
        // chain id (replay context the bot needs; the registry record itself
        // does not store it).
        "stell_sessionBudget" => {
            let sess_hex = if let Some(s) = params.as_str() {
                s.to_string()
            } else if let Some(s) = params["session"].as_str() {
                s.to_string()
            } else {
                return err(id, -32602, "missing session");
            };
            let pk = match parse_hash(&sess_hex) {
                Ok(p) => p,
                Err(e) => return err(id, -32602, e),
            };
            let reg = st.engine.session_keys_read().await;
            match reg.get(&pk) {
                None => ok(id, json!({
                    "registered": false,
                    "revoked": false,
                    "valid_until": 0,
                    "scope": 0,
                    "max_gas_spend": 0,
                    "spent": 0,
                    "remaining_gas": 0,
                    "master": "0".repeat(64),
                    "chain_id": st.chain_id,
                })),
                Some(rec) => ok(id, json!({
                    "registered": true,
                    "revoked": rec.revoked,
                    "valid_until": rec.valid_until,
                    "scope": rec.scope,
                    "max_gas_spend": rec.max_gas_spend,
                    "spent": rec.gas_spent,
                    "remaining_gas": rec.max_gas_spend.saturating_sub(rec.gas_spent),
                    "master": hex::encode(rec.master),
                    "chain_id": st.chain_id,
                })),
            }
        }

        _ => err(id, -32601, format!("method not found: {method}")),
    }
}

/// axum handler for the JSON-RPC endpoint.
async fn rpc_handler(
    axum::extract::State(st): axum::extract::State<Arc<RpcState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Json<RpcResponse> {
    if body.len() > MAX_RPC_BODY {
        return err(Value::Null, -32600, "request too large");
    }
    // A credential in a header rather than in the body, so a client can keep it out
    // of its request logs. `Authorization: Bearer <t>` / `Token <t>`, or the
    // explicit `X-Api-Key` / `X-Stell-Token`.
    let header_token = extract_header_token(&headers);
    // Support both single and batch requests.
    let first: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return err(Value::Null, -32700, format!("parse error: {e}")),
    };
    if let Some(arr) = first.as_array() {
        // Batches are refused loudly (audit 2026-10-06): the old code silently
        // processed ONLY the first element and dropped the rest — clients
        // lost requests without any error. -32600 (invalid request) until
        // array responses are implemented.
        if arr.is_empty() {
            return err(Value::Null, -32600, "empty batch");
        }
        return err(
            Value::Null,
            -32600,
            "batch requests are not supported: send requests individually",
        );
    }

    let req: RpcRequest = match serde_json::from_value(first) {
        Ok(r) => r,
        Err(e) => return err(Value::Null, -32600, format!("invalid request: {e}")),
    };
    let id = req.id.unwrap_or(Value::Null);
    // Real client IP for per-IP faucet throttling: proxy headers only when
    // the TCP peer is a trusted proxy (STELL_TRUSTED_PROXY_CIDRS,
    // loopback-only by default — see crate::client_ip); otherwise the peer.
    // Without this every client behind nginx/Cloudflare shared one bucket.
    let peer_ip = Some(crate::client_ip::resolve_client_ip(&headers, addr.ip()));
    dispatch(&st, id, &req.method, &req.params, header_token, peer_ip).await
}

/// Pull a token out of the conventional auth headers, if one is present.
pub(crate) fn extract_header_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    for name in ["x-api-key", "x-stell-token"] {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?.trim();
    for prefix in ["Bearer ", "Stell ", "Token "] {
        if let Some(rest) = auth.strip_prefix(prefix) {
            let rest = rest.trim();
            if !rest.is_empty() {
                return Some(rest);
            }
        }
    }
    None
}

/// Build the RPC router (no rate limit here: the gateway nests this router
/// under its own limiter, and tests serve it directly busting any static
/// budget — the standalone server adds the limiter in `serve`).
pub fn router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/", post(rpc_handler))
        // Reject oversized bodies at the extractor, before the body is buffered
        // into memory. The in-handler `MAX_RPC_BODY` check stays as a
        // defense-in-depth for callers that bypass this layer.
        .layer(DefaultBodyLimit::max(MAX_RPC_BODY))
        .with_state(state)
}

/// Per-IP fixed-window limiter for the standalone RPC (see `router`).
/// Budget from `STELL_STANDALONE_RATE_LIMIT` (default 300/s): the 30/s
/// gateway default throttled legitimate single-host bots/harnesses (audit:
/// speed tests — 61x 429 on a 122 tx/s localhost blast). 300/s still stops
/// floods cold while letting real clients through; loopback is NOT exempt
/// (a local flood is still a flood). Legacy `STELL_RPC_RATE_LIMIT_PER_SEC`
/// is still honored when the new name is unset.
static STANDALONE_LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> =
    std::sync::OnceLock::new();

/// Default per-IP budget for the standalone RPC (see above). Default 300;
/// override with `STELL_STANDALONE_RATE_LIMIT`. Per-node abuse guard, not
/// consensus — nodes MAY differ.
pub const STANDALONE_RATE_LIMIT_DEFAULT: u32 = 300;

/// Effective standalone-RPC per-IP budget (`STELL_STANDALONE_RATE_LIMIT`,
/// default 300; legacy `STELL_RPC_RATE_LIMIT_PER_SEC` honored as fallback).
fn standalone_limit_per_sec() -> u32 {
    std::env::var("STELL_STANDALONE_RATE_LIMIT")
        .ok()
        .or_else(|| std::env::var("STELL_RPC_RATE_LIMIT_PER_SEC").ok())
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(STANDALONE_RATE_LIMIT_DEFAULT)
}

async fn standalone_rate_limit(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let limiter = STANDALONE_LIMITER
        .get_or_init(|| crate::explorer::RateLimiter::new(standalone_limit_per_sec()));
    // Real client IP behind a trusted proxy (see crate::client_ip); without
    // this every client behind nginx/Cloudflare shared the 300/s bucket.
    let client = crate::client_ip::resolve_client_ip(req.headers(), addr.ip());
    if limiter.check(client) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded (per-IP budget on standalone RPC)",
        )
            .into_response()
    }
}

/// Spawn the RPC server on `addr` (e.g. "127.0.0.1:8545").
pub async fn serve(addr: &str, state: Arc<RpcState>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // The gateway (:8080) has its own limiter; the standalone RPC (:8545)
    // used to have NONE while being the port compose publishes (audit
    // 2026-10-06). Same 30/s/IP budget here. Plus a request timeout and a
    // concurrency cap so slow-loris / hung bodies cannot hold the server.
    let app = router(state).layer(
        tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(standalone_rate_limit))
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async { axum::http::StatusCode::REQUEST_TIMEOUT },
            ))
            .layer(tower::timeout::TimeoutLayer::new(std::time::Duration::from_secs(30)))
            .layer(tower::limit::ConcurrencyLimitLayer::new(512)),
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The token the test faucet expects; mirrors `STELL_FAUCET_TOKEN`.
    const FAUCET_TOKEN: &str = "faucet-secret";

    use super::*;
    use crate::state_engine::AccountState;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    async fn test_state() -> Arc<RpcState> {
        let engine = Arc::new(InMemoryStateEngine::new());
        let mempool = Arc::new(RwLock::new(Mempool::default()));
        Arc::new(RpcState {
            engine,
            mempool,
            height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
            node_id: "inf1:test".to_string(),
            chain_id: 777,
            staking: Arc::new(RwLock::new(crate::staking::StakingLedger::new())),
            governance: Arc::new(RwLock::new(crate::governance::Governance::new())),
            recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: None,
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
        })
    }

    /// Same as `test_state`, but with the testnet faucet enabled and its account
    /// pre-funded, mirroring a real testnet genesis.
    /// A `stell_faucet` request that presents the correct token.
    fn drip_req(address: &str) -> serde_json::Value {
        json!({ "address": address, "token": FAUCET_TOKEN })
    }

    /// Same, but with the faucet left unconfigured: the operator forgot
    /// `STELL_FAUCET_TOKEN`.
    async fn test_state_with_untokened_faucet(drip: u64, cap: u64) -> Arc<RpcState> {
        let key_seed = [0x11u8; 32];
        let faucet_key = ed25519_dalek::SigningKey::from_bytes(&key_seed);
        let faucet_addr = faucet_key.verifying_key().to_bytes();
        let st = test_state().await;
        st.engine.update_account(AccountState::new(faucet_addr, 1_000_000)).await;
        Arc::new(RpcState {
            faucet: Some(Arc::new(Faucet::new(key_seed, 1, drip, cap))),
            faucet_token: None,
            engine: st.engine.clone(),
            mempool: st.mempool.clone(),
            height: st.height.clone(),
            node_id: st.node_id.clone(),
            chain_id: st.chain_id,
            auth_token: st.auth_token.clone(),
            staking: st.staking.clone(),
            governance: st.governance.clone(),
            recent_blocks: st.recent_blocks.clone(),
            receipts: st.receipts.clone(),
            tx_broadcast: st.tx_broadcast.clone(),
        })
    }

    async fn test_state_with_faucet(drip: u64, cap: u64) -> Arc<RpcState> {
        let key_seed = [0x11u8; 32];
        let faucet_key = ed25519_dalek::SigningKey::from_bytes(&key_seed);
        let faucet_addr = faucet_key.verifying_key().to_bytes();
        let st = test_state().await;
        st.engine.update_account(AccountState::new(faucet_addr, 1_000_000)).await;
        Arc::new(RpcState {
            faucet: Some(Arc::new(Faucet::new(key_seed, 1, drip, cap))),
            faucet_token: Some(FAUCET_TOKEN.to_string()),
            engine: st.engine.clone(),
            mempool: st.mempool.clone(),
            height: st.height.clone(),
            node_id: st.node_id.clone(),
            chain_id: st.chain_id,
            staking: st.staking.clone(),
            governance: st.governance.clone(),
            recent_blocks: st.recent_blocks.clone(),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: st.auth_token.clone(),
            tx_broadcast: st.tx_broadcast.clone(),
        })
    }

    async fn call(st: &Arc<RpcState>, method: &str, params: Value) -> Value {
        let r = dispatch(st, Value::from(1), method, &params, None, None).await;
        r.0.error.map(|e| json!({"error": e.message})).unwrap_or(r.0.result.unwrap_or(Value::Null))
    }

    fn receipt_tx(from: [u8; 32], nonce: u64) -> crate::sharding::Transaction {
        let key = ed25519_dalek::SigningKey::from_bytes(&from);
        crate::sharding::Transaction::sign(&key, [0xEE; 32], 10, 1, nonce, 0, 0)
    }

    #[tokio::test]
    async fn receipt_reports_height_block_index_and_status() {
        let st = test_state().await;
        let txs = vec![receipt_tx([1u8; 32], 0), receipt_tx([2u8; 32], 0)];
        st.record_receipts(77, [0xAB; 32], &txs, &[true, false], &[1, 0]).await;

        let ok_tx = call(&st, "stell_getTransactionReceipt", json!(hex::encode(txs[0].compute_tx_hash()))).await;
        assert_eq!(ok_tx["height"], json!(77));
        assert_eq!(ok_tx["block_hash"], json!(hex::encode([0xABu8; 32])));
        assert_eq!(ok_tx["index"], json!(0));
        assert_eq!(ok_tx["status"], json!("success"));
        assert_eq!(ok_tx["fee_charged"], json!("1"), "receipt files the actual charge");
        assert!(ok_tx["gas_limit"].as_str().is_some(), "limit is kept alongside");

        let bad_tx = call(&st, "stell_getTransactionReceipt", json!(hex::encode(txs[1].compute_tx_hash()))).await;
        assert_eq!(bad_tx["status"], json!("failed"));
        assert_eq!(bad_tx["index"], json!(1));
        assert_eq!(bad_tx["fee_charged"], json!("0"), "a failed tx paid nothing");
    }

    #[tokio::test]
    async fn receipt_distinguishes_pending_from_unknown() {
        let st = test_state().await;
        let tx = receipt_tx([3u8; 32], 0);
        let h = hex::encode(tx.compute_tx_hash());
        assert_eq!(
            call(&st, "stell_getTransactionStatus", json!(h)).await["status"],
            json!("unknown")
        );

        st.mempool.write().await.add(tx.clone()).unwrap();
        assert_eq!(
            call(&st, "stell_getTransactionStatus", json!(h)).await["status"],
            json!("pending")
        );

        st.record_receipts(5, [0x01; 32], std::slice::from_ref(&tx), &[true], &[1]).await;
        let done = call(&st, "stell_getTransactionStatus", json!(h)).await;
        assert_eq!(done["status"], json!("success"));
        assert_eq!(done["height"], json!(5));
    }

    #[tokio::test]
    async fn receipt_status_and_block_are_consistent() {
        // Guards the invariant main.rs relies on: statuses are captured during
        // the single real application, never produced by re-applying the block
        // (which would execute every transfer a second time).
        let engine = Arc::new(InMemoryStateEngine::new());
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let from = key.verifying_key().to_bytes();
        engine.update_account(AccountState::new(from, 1_000)).await;

        let tx = crate::sharding::Transaction::sign(&key, [0xEE; 32], 100, 1, 0, 0, 0);
        let (applied, _failed, _fees, statuses, tx_fees) =
            engine.apply_block_parallel_fees(std::slice::from_ref(&tx), 0).await;

        assert_eq!(applied, 1);
        assert_eq!(statuses, vec![true], "one status per transaction, in block order");
        assert_eq!(tx_fees, vec![1], "the receipt files what commit_native charged");

        let balance_after = engine.get_account(&from).await.unwrap().balance;
        assert_eq!(balance_after, 1_000 - 101, "value moved exactly once");

        // Statuses must describe the block, not a second execution: re-running
        // admission against post-state makes the spent nonce fail, so a naive
        // recompute would flip this successful tx to "failed".
        let (_a2, _f2, _fees2, again, again_fees) =
            engine.apply_block_parallel_fees(std::slice::from_ref(&tx), 0).await;
        assert_eq!(again, vec![false], "replay of a spent nonce is rejected, as it must be");
        assert_eq!(again_fees, vec![0], "a refused transaction is charged nothing");
    }

    #[tokio::test]
    async fn receipt_index_is_bounded() {
        let mut idx = ReceiptIndex::default();
        for i in 0..(MAX_RECEIPTS + 10) {
            let h: [u8; 32] = blake3::hash(&(i as u64).to_be_bytes()).into();
            idx.insert(TxReceipt {
                tx_hash: h,
                height: i as u64,
                block_hash: [0u8; 32],
                index: 0,
                success: true,
                gas_limit: 0,
                fee_charged: 0,
                raw_tx: None,
            });
        }
        assert_eq!(idx.len(), MAX_RECEIPTS, "a busy chain cannot exhaust memory");
        let oldest: [u8; 32] = blake3::hash(&0u64.to_be_bytes()).into();
        assert!(idx.get(&oldest).is_none(), "oldest receipts are evicted");
        let newest: [u8; 32] = blake3::hash(&(MAX_RECEIPTS as u64 + 9).to_be_bytes()).into();
        assert!(idx.get(&newest).is_some(), "newest receipt is retained");
    }

    #[tokio::test]
    async fn receipt_rejects_malformed_hash() {
        let st = test_state().await;
        let r = call(&st, "stell_getTransactionReceipt", json!("not-a-hash")).await;
        assert!(r.get("error").is_some(), "garbage hash is a client error, not a panic");
    }

    #[tokio::test]
    async fn evm_adapter_network_info_methods_through_rpc() {
        let st = test_state().await;
        assert_eq!(call(&st, "eth_chainId", json!([])).await, json!("0x167d"));
        assert_eq!(call(&st, "net_version", json!([])).await, json!("5757"));
        assert_eq!(call(&st, "web3_clientVersion", json!([])).await, json!("Stellereum/v5.0.0-evm-adapter"));
        assert_eq!(call(&st, "net_listening", json!([])).await, json!(true));
        assert_eq!(call(&st, "net_peerCount", json!([])).await, json!("0x2"));
        // LIVE: same rule as `stell_syncing` — a recent verified peer height
        // above ours means syncing. `PEER_HEIGHT` is process-global and
        // monotonic, so the expectation is computed, not hardcoded.
        let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
        let expect_syncing = crate::evm_adapter::eth_syncing_for_heights(ours, fresh_peer_height());
        assert_eq!(call(&st, "eth_syncing", json!([])).await, json!(expect_syncing));
        assert_eq!(
            call(&st, "stell_syncing", json!([])).await,
            json!(expect_syncing),
            "eth_syncing and stell_syncing must agree on the same heights"
        );
        assert_eq!(call(&st, "eth_gasPrice", json!([])).await, json!("0x3eb2788000"));
        assert_eq!(call(&st, "eth_maxPriorityFeePerGas", json!([])).await, json!("0x3b9aca00"));
        assert_eq!(call(&st, "eth_estimateGas", json!([])).await, json!("0x5208"));
        let fh = call(&st, "eth_feeHistory", json!([4, "latest", [25.0, 75.0]])).await;
        assert_eq!(fh["oldestBlock"], json!("0x27"));
        assert_eq!(fh["baseFeePerGas"].as_array().unwrap().len(), 5);
        assert_eq!(fh["gasUsedRatio"].as_array().unwrap().len(), 4);
        assert_eq!(fh["reward"].as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn bridge_dispute_reads_report_records_and_disputes() {
        use crate::bridge::{DepositRecord, Dispute, SupportedChain};
        let st = test_state().await;
        let hash = hex::encode([0x77u8; 32]);
        let r = call(&st, "stell_bridgeDeposit", json!({ "source_tx_hash": hash })).await;
        assert_eq!(r["found"], false, "no record on a fresh engine");
        let r = call(&st, "stell_bridgeDispute", json!({ "dispute_id": "0" })).await;
        assert_eq!(r["found"], false, "no dispute on a fresh engine");

        {
            let mut br = st.engine.bridge_write().await;
            br.deposit_records.insert(
                [0x77u8; 32],
                DepositRecord {
                    recipient: [0x78u8; 32],
                    amount: 100,
                    chain: SupportedChain::Ton,
                    via_quorum: true,
                    deposited_at: 1000,
                    disputed: true,
                },
            );
            br.disputes.insert(
                0,
                Dispute {
                    source_tx_hash: [0x77u8; 32],
                    challenger: [0x79u8; 32],
                    recipient: [0x78u8; 32],
                    amount: 100,
                    bond: 200,
                    deadline: 4600,
                    resolved: false,
                    confirmed: false,
                },
            );
        }
        let r = call(&st, "stell_bridgeDeposit", json!({ "source_tx_hash": hash })).await;
        assert_eq!(r["found"], true);
        assert_eq!(r["amount"], "100");
        assert_eq!(r["via_quorum"], true);
        assert_eq!(r["disputed"], true);
        let r = call(&st, "stell_bridgeDispute", json!({ "dispute_id": "0" })).await;
        assert_eq!(r["found"], true);
        assert_eq!(r["deadline"], 4600);
        assert_eq!(r["resolved"], false);
        let r = call(&st, "stell_bridgeDeposit", json!("not-a-hash")).await;
        assert!(r.get("error").is_some(), "garbage hash is a client error");
    }

    #[tokio::test]
    async fn chain_info_methods() {
        let st = test_state().await;
        assert_eq!(call(&st, "stell_chainId", json!({})).await, json!(777));
        assert_eq!(call(&st, "stell_nodeId", json!({})).await, json!("inf1:test"));
        assert_eq!(call(&st, "stell_blockNumber", json!({})).await, json!("0x2a"));
    }

    #[tokio::test]
    async fn faucet_is_disabled_by_default() {
        let st = test_state().await;
        let r = call(&st, "stell_faucet", json!({ "address": hex::encode([0x42u8; 32]) })).await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("disabled"),
            "faucet must be off unless explicitly enabled: {r}"
        );
        assert!(st.engine.get_account(&[0x42u8; 32]).await.is_none(), "no account may be created");
    }

    #[tokio::test]
    async fn faucet_caps_survive_a_restart() {
        // The Wave-5 finding: lifetime caps lived in a bare in-process Mutex, so a
        // restart resurrected every capped address's full allowance (1000 STELL per
        // address per restart at production defaults, unbounded). Caps and the nonce
        // are now persisted on every mutation; a fresh Faucet over the saved bytes
        // must pick up exactly where the old one left off.
        use std::sync::{Arc, Mutex};
        let saved: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let saver = {
            let saved = Arc::clone(&saved);
            Arc::new(move |bytes: &[u8]| {
                *saved.lock().unwrap() = bytes.to_vec();
            }) as Arc<dyn Fn(&[u8]) + Send + Sync>
        };
        let key_seed = [0x11u8; 32];
        let old = Faucet::new(key_seed, 1, 10, 25).with_persist(saver);
        let who = [0x42u8; 32];

        // Exhaust the address: 10 + 10 + 5 == cap 25.
        assert!(old.build_transfer(who, None, None).await.is_some());
        assert!(old.build_transfer(who, None, None).await.is_some());
        assert!(old.build_transfer(who, None, None).await.is_some());
        assert_eq!(old.dispensed_to(who).await, 25);
        assert!(old.build_transfer(who, None, None).await.is_none(), "capped");

        // "Restart": a fresh Faucet over the persisted bytes.
        let bytes = saved.lock().unwrap().clone();
        assert!(!bytes.is_empty(), "every drip must have persisted state");
        let new = Faucet::new(key_seed, 1, 10, 25);
        new.load_bytes(&bytes).await;
        assert_eq!(new.dispensed_to(who).await, 25, "cap must survive the restart");
        assert!(
            new.build_transfer(who, None, None).await.is_none(),
            "a capped address must stay capped after a restart"
        );

        // And a corrupt record fails closed to empty (under-serves, never over-mints).
        let broken = Faucet::new(key_seed, 1, 10, 25);
        broken.load_bytes(b"not-a-faucet-state").await;
        assert_eq!(broken.dispensed_to(who).await, 0);
    }

    #[tokio::test]
    async fn faucet_caps_lifetime_credit_per_address() {
        // Small cap so the test can exhaust it: drips of 10, lifetime cap 25.
        let st = test_state_with_faucet(10, 25).await;
        let who = [0x42u8; 32];
        let hexa = hex::encode(who);

        // Requesting more than a drip can never exceed the drip amount.
        let r = call(&st, "stell_faucet", json!({ "address": hexa.clone(), "amount": u64::MAX, "token": FAUCET_TOKEN })).await;
        assert_eq!(r["credited_nano"], "10");
        assert_eq!(call(&st, "stell_faucet", drip_req(&hexa)).await["credited_nano"], "10");
        // 3rd call is clamped by the lifetime cap to the remaining 5.
        let r3 = call(&st, "stell_faucet", drip_req(&hexa)).await;
        assert_eq!(r3["credited_nano"], "5");
        // 4th call: exhausted.
        let r4 = call(&st, "stell_faucet", drip_req(&hexa)).await;
        assert!(r4["error"].as_str().unwrap_or_default().contains("limit"), "{r4}");

        // Every drip is a real, correctly signed transfer from the faucet account
        // sitting in the mempool — nothing was written straight into state.
        let pending = st.mempool.read().await.len();
        assert_eq!(pending, 3);
        for tx in st.mempool.read().await.all() {
            assert!(tx.verify_signature(), "faucet tx must carry a valid signature");
            assert_eq!(tx.to, [0x42u8; 32]);
        }
    }

    #[tokio::test]
    async fn public_drip_is_5_stell_per_45_minutes_per_address() {
        // TON-style public drip: fixed 5 STELL, one per address per 45 minutes.
        let faucet = Faucet::new([0x77u8; 32], 0, 10 * 1_000_000_000, 1_000_000_000_000);
        let who = [0x42u8; 32];
        let t0 = 1_700_000_000u64;

        // First drip succeeds with exactly 5 STELL.
        let (tx1, amount1) = faucet
            .build_public_transfer(who, t0, None)
            .await
            .expect("first public drip must succeed");
        assert_eq!(amount1, PUBLIC_DRIP_NANO);
        assert_eq!(amount1, 5 * 1_000_000_000);
        assert_eq!(tx1.to, who);
        assert!(tx1.verify_signature(), "public drip must carry a valid signature");

        // Immediate retry is cooling down with seconds remaining.
        let err = faucet
            .build_public_transfer(who, t0 + 60, None)
            .await
            .expect_err("second drip within 45 minutes must cool down");
        assert_eq!(err, PUBLIC_DRIP_COOLDOWN_SECS - 60);

        // A different address is unaffected.
        let (tx2, amount2) = faucet
            .build_public_transfer([0x43u8; 32], t0 + 60, None)
            .await
            .expect("other address must not share cooldown");
        assert_eq!(amount2, PUBLIC_DRIP_NANO);
        assert_eq!(tx2.nonce, tx1.nonce + 1);

        // After exactly 45 minutes the same address may drip again.
        let (tx3, _) = faucet
            .build_public_transfer(who, t0 + PUBLIC_DRIP_COOLDOWN_SECS, None)
            .await
            .expect("drip after cooldown must succeed");
        assert_eq!(tx3.nonce, tx2.nonce + 1);
    }

    #[tokio::test]
    async fn faucet_uses_increasing_nonces() {
        let st = test_state_with_faucet(10, 100).await;
        call(&st, "stell_faucet", drip_req(&hex::encode([1u8; 32]))).await;
        call(&st, "stell_faucet", drip_req(&hex::encode([2u8; 32]))).await;
        let mut nonces: Vec<u64> = st.mempool.read().await.all().iter().map(|t| t.nonce).collect();
        nonces.sort_unstable();
        assert_eq!(nonces, vec![0, 1], "faucet txs must not reuse a nonce");
    }

    #[tokio::test]
    async fn faucet_refuses_without_a_token() {
        // The regression that matters: an unauthenticated caller must not be
        // able to draw from the treasury, and a *misconfigured* node (faucet on,
        // token unset) must fail closed rather than mint for anyone.
        let st = test_state_with_faucet(10, 25).await;
        let who = hex::encode([0x42u8; 32]);

        // No token at all.
        let r = call(&st, "stell_faucet", json!({ "address": who.clone() })).await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("unauthorized"),
            "a tokenless faucet request must be refused: {r}"
        );
        // Wrong token.
        let r2 = call(
            &st,
            "stell_faucet",
            json!({ "address": who.clone(), "token": "guess" }),
        )
        .await;
        assert!(
            r2["error"].as_str().unwrap_or_default().contains("unauthorized"),
            "a wrong token must be refused: {r2}"
        );
        // Neither attempt may have touched the mempool or the recipient.
        assert_eq!(st.mempool.read().await.len(), 0, "no unsigned tx may be queued");
        assert!(st.engine.get_account(&[0x42u8; 32]).await.is_none());

        // And with the right token it works, so this is auth and not a freeze.
        let ok2 = call(&st, "stell_faucet", drip_req(&who)).await;
        assert_eq!(ok2["credited_nano"], "10");
    }

    #[tokio::test]
    async fn enabled_faucet_without_a_configured_token_fails_closed() {
        // Same helper, but the operator forgot STELL_FAUCET_TOKEN. Dispensing
        // must be impossible, not silently open.
        let st = test_state_with_untokened_faucet(10, 25).await;
        let r = call(&st, "stell_faucet", drip_req(&hex::encode([0x42u8; 32]))).await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("refusing to dispense"),
            "a faucet with no token must refuse even a well-formed request: {r}"
        );
        assert_eq!(st.mempool.read().await.len(), 0);
    }

    #[tokio::test]
    async fn faucet_rejects_malformed_address() {
        let st = test_state_with_faucet(10, 25).await;
        let r = call(&st, "stell_faucet", json!({ "address": "zz", "token": FAUCET_TOKEN })).await;
        assert!(r["error"].is_string());
        let r2 = call(&st, "stell_faucet", json!({ "token": FAUCET_TOKEN })).await;
        assert!(r2["error"].is_string());
    }

    #[tokio::test]
    async fn balance_query() {
        let st = test_state().await;
        let who = [3u8; 32];
        st.engine.update_account(AccountState::new(who, 5000)).await;
        let r = call(&st, "stell_getBalance", json!(hex::encode(who))).await;
        assert_eq!(r["balance"], "5000");
    }

    #[tokio::test]
    async fn unknown_method_is_error() {
        let st = test_state().await;
        let r = call(&st, "does_not_exist", json!({})).await;
        assert!(r["error"].as_str().unwrap().contains("method not found"));
    }

    #[tokio::test]
    async fn send_raw_transaction_valid_and_forged() {
        let st = test_state().await;
        let sk = SigningKey::generate(&mut OsRng);
        // fund the sender so the balance check at admission passes
        let from = sk.verifying_key().to_bytes();
        st.engine.update_account(AccountState::new(from, 1_000_000)).await;
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let raw = hex::encode(bincode::serialize(&tx).unwrap());
        let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
        assert!(r.as_str().is_some(), "valid tx must be accepted: {r}");
        assert_eq!(st.mempool.read().await.len(), 1);

        // forged signature must be rejected
        let mut bad = tx.clone();
        bad.signature[0] ^= 0xFF;
        let raw_bad = hex::encode(bincode::serialize(&bad).unwrap());
        let r2 = call(&st, "stell_sendRawTransaction", json!({ "tx": raw_bad })).await;
        assert!(r2["error"].as_str().unwrap().contains("signature"));
        assert_eq!(st.mempool.read().await.len(), 1, "forged tx must not enter mempool");
    }

    #[tokio::test]
    async fn send_raw_transaction_forwards_to_gossip_channel() {
        let base = test_state().await;
        let (tx_out, mut tx_rx) = tokio::sync::mpsc::unbounded_channel();
        let st = Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: None,
            tx_broadcast: Some(tx_out),
            faucet: None,
            faucet_token: None,
        });
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        st.engine.update_account(AccountState::new(from, 1_000_000)).await;
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let raw = hex::encode(bincode::serialize(&tx).unwrap());

        let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
        assert!(r.as_str().is_some());

        // Must have been forwarded to the P2P gossip channel:
        let forwarded = tx_rx.try_recv().expect("must receive forwarded tx");
        assert_eq!(forwarded.amount, 10);
        assert_eq!(forwarded.from, from);
    }

    /// Phase-2 EVM settlement: `eth_sendRawTransaction` admits the mapped
    /// consensus transaction to the REAL mempool (not just the intent pool),
    /// so the tx reaches block production. Strict chain_id/low-s/ecrecover
    /// plus nonce/balance gating through the `evm_to_stell` mapping.
    #[tokio::test]
    async fn eth_send_raw_transaction_settles_into_mempool() {
        use crate::evm_adapter::{
            evm_to_stell_address, pubkey_to_address, wei_to_nano, LegacyTransaction, CHAIN_ID,
        };

        fn secp_key() -> k256::ecdsa::SigningKey {
            let bytes =
                hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                    .unwrap();
            k256::ecdsa::SigningKey::from_slice(&bytes).unwrap()
        }

        // Sign a legacy EIP-155 tx on chain 5757 (low-s normalized).
        fn sign_raw(nonce: u64, value_wei: u128) -> Vec<u8> {
            let key = secp_key();
            let unsigned = LegacyTransaction {
                nonce,
                gas_price: 20_000_000_000,
                gas_limit: 21_000,
                to: Some([0x35u8; 20]),
                value: value_wei,
                data: Vec::new(),
                v: 0,
                r: [0u8; 32],
                s: [0u8; 32],
                chain_id: Some(CHAIN_ID),
            };
            let sighash = unsigned.signing_hash();
            let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&sig.to_bytes()[0..32]);
            s.copy_from_slice(&sig.to_bytes()[32..64]);
            let (s, recid_b) = if crate::evm_adapter::is_low_s(&s) {
                (s, recid.to_byte())
            } else {
                // N - s, flip recovery bit (same normalization the
                // settlement builder applies).
                let n = crate::evm_adapter::SECP256K1_N;
                let mut out = [0u8; 32];
                let mut borrow: i32 = 0;
                for i in (0..32).rev() {
                    let v = n[i] as i32 - s[i] as i32 - borrow;
                    if v < 0 {
                        out[i] = (v + 256) as u8;
                        borrow = 1;
                    } else {
                        out[i] = v as u8;
                        borrow = 0;
                    }
                }
                (out, recid.to_byte() ^ 1)
            };
            LegacyTransaction {
                v: CHAIN_ID * 2 + 35 + recid_b as u64,
                r,
                s,
                ..unsigned
            }
            .encode()
        }

        let key = secp_key();
        let sender20 =
            pubkey_to_address(key.verifying_key().to_encoded_point(false).as_bytes()).unwrap();
        let sender32 = evm_to_stell_address(&sender20);
        let value_wei: u128 = 1_000_000_000_000_000_000;

        let st = test_state().await;
        st.engine
            .update_account(AccountState::new(sender32, wei_to_nano(value_wei) + 1_000_000))
            .await;

        // 1. Funded sender: admitted to the real mempool, EVM hash returned.
        let raw = hex::encode(sign_raw(0, value_wei));
        let r = call(&st, "eth_sendRawTransaction", json!([format!("0x{raw}")])).await;
        let evm_hash = r.as_str().expect("EVM tx must be accepted: {r}");
        assert!(evm_hash.starts_with("0x"));
        assert_eq!(st.mempool.read().await.len(), 1);
        let pooled: Vec<Transaction> = st.mempool.read().await.all();
        assert_eq!(pooled.len(), 1);
        assert!(pooled[0].is_evm());
        assert_eq!(pooled[0].from, sender32);
        assert_eq!(pooled[0].nonce, 0);
        assert!(pooled[0].verify_signature());

        // 2. Wrong chain (chain-1 vector) is rejected, pool unchanged.
        let chain1 = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let r2 = call(&st, "eth_sendRawTransaction", json!([format!("0x{chain1}")])).await;
        assert!(r2.get("error").is_some(), "foreign chain must be rejected: {r2}");
        assert_eq!(st.mempool.read().await.len(), 1);

        // 3. Unfunded sender is rejected by the balance gate, pool unchanged.
        let st_broke = test_state().await;
        let r3 = call(
            &st_broke,
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(sign_raw(0, value_wei)))]),
        )
        .await;
        assert!(
            r3.get("error").is_some(),
            "unfunded EVM tx must be rejected: {r3}"
        );
        assert_eq!(st_broke.mempool.read().await.len(), 0);
    }

    #[tokio::test]
    async fn write_methods_require_auth_token() {
        let base = test_state().await;
        let st = Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: Some("secret".to_string()),
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
        });
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        st.engine.update_account(AccountState::new(from, 1_000_000)).await;
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let raw = hex::encode(bincode::serialize(&tx).unwrap());

        let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw.clone() })).await;
        assert!(r.as_str().is_some(), "public signed transaction must succeed without auth token");

        // Admin methods like mempool dump still require the token
        let r_dump = call(&st, "stell_mempoolDump", json!({})).await;
        assert!(r_dump["error"].as_str().unwrap().contains("unauthorized"));
        let r_dump2 = call(&st, "stell_mempoolDump", json!({ "token": "secret" })).await;
        assert!(r_dump2.as_array().is_some(), "authorized dump must succeed");
    }

    /// A feed submission is a WRITE-shaped method: same token gate as
    /// `stell_sendRawTransaction`, and it is THIN - it admits the wrapping
    /// transaction to the mempool and must not touch consensus state. The
    /// price only exists once a block carries it.
    #[tokio::test]
    async fn submit_price_feed_admits_without_writing_state_and_requires_token() {
        let base = test_state().await;
        let st = Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: Some("secret".to_string()),
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
        });
        let sender = SigningKey::from_bytes(&[0x07u8; 32]);
        let from = sender.verifying_key().to_bytes();
        st.engine.update_account(AccountState::new(from, 1_000_000)).await;
        let publisher = SigningKey::from_bytes(&[0x42u8; 32]);
        let feed = crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
        let tx = Transaction::sign_with_payload(
            &sender,
            from,
            0,
            10_000,
            0,
            1,
            1,
            vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
        );
        let raw = hex::encode(bincode::serialize(&tx).unwrap());

        // Gated by the SAME token as sendRawTransaction.
        let denied = call(&st, "stell_submitPriceFeed", json!({ "tx": raw.clone() })).await;
        assert!(denied["error"].as_str().unwrap().contains("unauthorized"));
        let denied2 = call(&st, "stell_submitPriceFeed", json!({ "tx": raw.clone(), "token": "nope" })).await;
        assert!(denied2["error"].as_str().unwrap().contains("unauthorized"));

        // Thin: admitted, gossiped, and NOT written into state.
        let root_before = st.engine.get_state_root().await;
        let ok = call(&st, "stell_submitPriceFeed", json!({ "tx": raw.clone(), "token": "secret" })).await;
        assert!(ok.as_str().is_some(), "authorized submission must be admitted: {ok}");
        assert_eq!(st.mempool.read().await.len(), 1, "it belongs in the mempool");
        assert_eq!(
            st.engine.get_state_root().await,
            root_before,
            "submitting a feed must NOT write consensus state"
        );
        assert!(
            st.engine.oracle_read().await.feeds.is_empty(),
            "no price may exist before a block carries the feed"
        );

        // Only a payload that actually carries a signed feed may use this method.
        let plain = Transaction::sign(&sender, from, 1, 1_000, 1, 1, 1);
        let wrong = call(
            &st,
            "stell_submitPriceFeed",
            json!({ "tx": hex::encode(bincode::serialize(&plain).unwrap()), "token": "secret" }),
        )
        .await;
        assert!(
            wrong["error"].as_str().unwrap().contains("price feed"),
            "a non-feed transaction must not be admitted under this method: {wrong}"
        );

        // And a feed whose SIGNATURE does not check out is refused the same way.
        let mut tampered = tx.clone();
        tampered.payload = vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(
            crate::oracle::PriceFeedUpdate::sign("STELL", 1, 1_700_000_000, &publisher),
        ))];
        let bad = call(
            &st,
            "stell_submitPriceFeed",
            json!({ "tx": hex::encode(bincode::serialize(&tampered).unwrap()), "token": "secret" }),
        )
        .await;
        assert!(
            bad["error"].as_str().unwrap().contains("signature"),
            "a payload swapped after signing must fail verification: {bad}"
        );
        assert_eq!(st.mempool.read().await.len(), 1, "nothing else got in");
    }

    /// Nonce-gap fail-fast must cover the shared `stell_submit*` admission
    /// helper too (audit: blocks troubles): a far-future nonce via
    /// `stell_submitPriceFeed` is refused exactly like via
    /// `stell_sendRawTransaction`, instead of clogging the pool behind an
    /// unreachable head.
    #[tokio::test]
    async fn submit_price_feed_rejects_far_future_nonce() {
        let st = test_state().await;
        let sender = SigningKey::from_bytes(&[0x07u8; 32]);
        let from = sender.verifying_key().to_bytes();
        st.engine.update_account(AccountState::new(from, 1_000_000)).await;
        let publisher = SigningKey::from_bytes(&[0x42u8; 32]);
        let feed = crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
        let gapped = Transaction::sign_with_payload(
            &sender,
            from,
            0,
            10_000,
            crate::mempool::Mempool::NONCE_FUTURE_WINDOW + 5,
            1,
            1,
            vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
        );
        let r = call(
            &st,
            "stell_submitPriceFeed",
            json!({ "tx": hex::encode(bincode::serialize(&gapped).unwrap()) }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("nonce gap"),
            "far-future-nonce payload tx must be refused: {r}"
        );
        assert_eq!(st.mempool.read().await.len(), 0, "gapped tx must not enter mempool");
    }

    #[tokio::test]
    async fn mempool_dump_requires_auth_token() {
        let base = test_state().await;
        let st = Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: Some("secret".to_string()),
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
        });
        let r = call(&st, "stell_mempoolDump", json!({})).await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("unauthorized"),
            "anonymous mempool dump must be refused: {r}"
        );
        let r2 = call(&st, "stell_mempoolDump", json!({ "token": "secret" })).await;
        assert!(r2.is_array(), "authorized dump must return the list: {r2}");

        // Fail-closed test: when auth_token is None, mempoolDump MUST refuse
        let st_no_token = test_state().await;
        let r_fail_closed = call(&st_no_token, "stell_mempoolDump", json!({})).await;
        assert!(
            r_fail_closed["error"].as_str().unwrap_or_default().contains("unauthorized"),
            "mempool dump must fail closed when auth_token is None: {r_fail_closed}"
        );
    }

    #[test]
    fn constant_time_eq_behaves_like_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(constant_time_eq("", ""));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("ab", "abc"));
        assert!(!constant_time_eq("", "x"));
    }

    #[tokio::test]
    async fn malformed_request_rejected() {
        let st = test_state().await;
        // missing address
        let r = call(&st, "stell_getBalance", json!({})).await;
        assert!(r["error"].is_string());
        // bad hex address
        let r2 = call(&st, "stell_getBalance", json!("zzzz")).await;
        assert!(r2["error"].is_string());
    }

    #[tokio::test]
    async fn token_methods() {
        let st = test_state().await;
        let who = [4u8; 32];
        let meta = crate::token::TokenMetadata {
            name: "Wrapped USDT".to_string(),
            symbol: "wUSDT".to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: [0u8; 32],
            paused: false,
            description: String::new(),
        };
        let id = st.engine.create_token(who, meta, 1000).await.unwrap();
        let r = call(&st, "stell_tokenSupply", json!({ "token": hex::encode(id) })).await;
        assert_eq!(r, "1000");
        let rb = call(&st, "stell_tokenBalance", json!({ "token": hex::encode(id), "account": hex::encode(who) })).await;
        assert_eq!(rb, "1000");
    }

    #[tokio::test]
    async fn faucet_reconcile_fills_gaps_atomically() {
        // Reserved-but-never-executed nonces (wiped mempool) must not strand
        // later drips: reconcile takes mex(on-chain, pending).
        let f = Faucet::new([9u8; 32], 1, 10, 25);
        // Gap: on-chain 5, pending {7} (5,6 lost) -> must take 5, then 6.
        let (t1, _) = f.build_transfer([1u8; 32], None, Some((5, vec![7]))).await.unwrap();
        assert_eq!(t1.nonce, 5);
        // Pending {5} now (just built, pretend admitted): next is 6.
        let (t2, _) = f.build_transfer([2u8; 32], None, Some((5, vec![5, 7]))).await.unwrap();
        assert_eq!(t2.nonce, 6);
        // No reconcile info: pure increment (legacy behavior preserved).
        let (t3, _) = f.build_transfer([3u8; 32], None, None).await.unwrap();
        assert_eq!(t3.nonce, 7);
    }

    /// The PMM arms are WRITE-shaped: same token gate as
    /// `stell_sendRawTransaction`, and THIN - they admit the wrapping
    /// transaction to the mempool and must not touch consensus state. The curve
    /// only moves when a block carries the syscall, so no node can mint STELL
    /// or burn wUSDT by asking for it over RPC.
    #[tokio::test]
    async fn pmm_arms_admit_without_writing_state_and_require_token() {
        let base = test_state().await;
        let st = Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
            auth_token: Some("secret".to_string()),
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
        });
        let sender = SigningKey::from_bytes(&[0x07u8; 32]);
        let from = sender.verifying_key().to_bytes();
        st.engine.update_account(AccountState::new(from, 1_000_000)).await;

        let buy = Transaction::sign_with_payload(
            &sender,
            from,
            0,
            crate::svm::GAS_PMM_BUY,
            0,
            1,
            1,
            vec![crate::svm::OpCode::SysCallPmmBuy { usdt_micro: 250_000 }],
        );
        let buy_raw = hex::encode(bincode::serialize(&buy).unwrap());

        // Gated by the SAME token as sendRawTransaction.
        let denied = call(&st, "stell_pmmBuy", json!({ "tx": buy_raw.clone() })).await;
        assert!(denied["error"].as_str().unwrap().contains("unauthorized"));
        let denied2 =
            call(&st, "stell_pmmBuy", json!({ "tx": buy_raw.clone(), "token": "nope" })).await;
        assert!(denied2["error"].as_str().unwrap().contains("unauthorized"));

        // Thin: admitted and NOT written into state - the curve has not moved.
        let root_before = st.engine.get_state_root().await;
        let ok =
            call(&st, "stell_pmmBuy", json!({ "tx": buy_raw.clone(), "token": "secret" })).await;
        assert!(ok.as_str().is_some(), "authorized buy must be admitted: {ok}");
        assert_eq!(st.mempool.read().await.len(), 1, "it belongs in the mempool");
        assert_eq!(
            st.engine.get_state_root().await,
            root_before,
            "submitting a PMM buy must NOT write consensus state"
        );
        assert_eq!(
            st.engine.pmm_read().await.minted_nano,
            0,
            "no curve movement may exist before a block carries the swap"
        );

        // A buy payload under the sell method is refused by its own predicate.
        let wrong =
            call(&st, "stell_pmmSell", json!({ "tx": buy_raw.clone(), "token": "secret" })).await;
        assert!(
            wrong["error"].as_str().unwrap().contains("SysCallPmmSell"),
            "a non-sell transaction must not be admitted under stell_pmmSell: {wrong}"
        );
        assert_eq!(st.mempool.read().await.len(), 1, "the wrong arm admitted nothing");

        // The matching sell payload is admitted the same thin way.
        let sell = Transaction::sign_with_payload(
            &sender,
            from,
            0,
            crate::svm::GAS_PMM_SELL,
            1,
            1,
            1,
            vec![crate::svm::OpCode::SysCallPmmSell { stell_nano: 1_000 }],
        );
        let ok2 = call(
            &st,
            "stell_pmmSell",
            json!({ "tx": hex::encode(bincode::serialize(&sell).unwrap()), "token": "secret" }),
        )
        .await;
        assert!(ok2.as_str().is_some(), "authorized sell must be admitted: {ok2}");
        assert_eq!(st.mempool.read().await.len(), 2);

        // `stell_pmmState` is a pure read: it reports the committed curve and
        // changes neither the root nor the mempool.
        let state = call(&st, "stell_pmmState", json!({})).await;
        assert!(state["price_micro_usd"].is_u64());
        assert_eq!(
            st.engine.get_state_root().await,
            root_before,
            "a state read must not move the root"
        );
        assert_eq!(st.mempool.read().await.len(), 2);
    }

    // ==================== Adopter replication: RPC serves adopted heights ===

    #[tokio::test]
    async fn adopter_records_serve_identical_receipts_and_no_txs_zero_view() {
        // The live bug: the proposer filed receipts + a real tx count while the
        // adopter filed nothing (txs=0, no receipts). `record_adopted_block` is
        // the adopt/walk hook; after it, receipt + block + block-txs reads must
        // match the proposer exactly.
        let proposer = test_state().await;
        let adopter = test_state().await;
        let txs = vec![receipt_tx([11u8; 32], 0), receipt_tx([12u8; 32], 1)];
        let bh = [0xBBu8; 32];
        proposer.record_receipts(77, bh, &txs, &[true, false], &[1, 0]).await;
        proposer.record_block(77, bh, txs.len(), 1_000).await;
        // Adopter path (verified body + single-apply statuses, behind finalization).
        adopter.record_adopted_block(77, bh, &txs, &[true, false], &[1, 0], 1_000).await;

        for st in [&proposer, &adopter] {
            let blk = call(st, "stell_getBlock", json!({ "height": 77 })).await;
            assert_eq!(blk["txs"], json!(2), "no txs=0 view on either node");
            assert_eq!(blk["hash"], json!(hex::encode(bh)));
            let r0 =
                call(st, "stell_getTransactionReceipt", json!(hex::encode(txs[0].compute_tx_hash())))
                    .await;
            assert_eq!((r0["height"].as_u64(), r0["status"].as_str()), (Some(77), Some("success")));
            let txs_r = call(st, "stell_getBlockTransactions", json!({ "height": 77 })).await;
            assert_eq!(txs_r["txs"].as_array().map(|a| a.len()), Some(2));
        }
        // Byte-level receipt equality between the two nodes.
        let p = proposer.receipts.read().await.get(&txs[1].compute_tx_hash()).unwrap().clone();
        let a = adopter.receipts.read().await.get(&txs[1].compute_tx_hash()).unwrap().clone();
        assert_eq!(p.height, a.height);
        assert_eq!(p.block_hash, a.block_hash);
        assert_eq!((p.index, p.success), (a.index, a.success));
        assert_eq!((p.fee_charged, a.fee_charged), (0, 0), "failed txs carry a zero charge on both");
        assert_eq!(
            call(&proposer, "stell_getTransactionReceipt", json!(hex::encode(txs[0].compute_tx_hash())))
                .await["fee_charged"],
            json!("1"),
            "block-txs and receipt views agree on the charge"
        );
    }

    #[tokio::test]
    async fn base_fee_read_reports_the_live_admission_floor() {
        // Wallet pre-blast assertion: the read mirrors the mempool's floor.
        let st = test_state().await;
        let r = call(&st, "stell_baseFee", json!({})).await;
        assert_eq!(r["base_fee"], json!("0"), "library default floor is 0: {r}");
        st.mempool.write().await.base_fee = 560;
        let r = call(&st, "stell_baseFee", json!({})).await;
        assert_eq!(r["base_fee"], json!("560"), "floor tracks the live mempool: {r}");
    }

    #[tokio::test]
    async fn faucet_default_drip_is_10_stell_with_env_override() {
        // The compiled default funds 10 STELL per drip; operators override via
        // STELL_FAUCET_DRIP_STELL (whole STELL). Env is process-global, so this
        // test saves and restores it.
        let saved = std::env::var("STELL_FAUCET_DRIP_STELL").ok();
        std::env::remove_var("STELL_FAUCET_DRIP_STELL");
        assert_eq!(Faucet::default_drip_nano(), 10 * 1_000_000_000);
        std::env::set_var("STELL_FAUCET_DRIP_STELL", "25");
        assert_eq!(Faucet::default_drip_nano(), 25 * 1_000_000_000);
        match saved {
            Some(v) => std::env::set_var("STELL_FAUCET_DRIP_STELL", v),
            None => std::env::remove_var("STELL_FAUCET_DRIP_STELL"),
        }
    }

    #[tokio::test]
    async fn unavailable_body_is_honest_unavailability_not_a_stall() {
        // Replication must NEVER block finalization and must never fabricate:
        // unknown heights/readers get an honest miss, and consensus state is
        // untouched by the read.
        let st = test_state().await;
        let h_before = st.height.load(std::sync::atomic::Ordering::Relaxed);
        let blk = call(&st, "stell_getBlock", json!({ "height": 999_999 })).await;
        assert!(blk["error"].as_str().unwrap_or_default().contains("not available yet"), "{blk}");
        let txs = call(&st, "stell_getBlockTransactions", json!({ "height": 999_999 })).await;
        assert!(txs["error"].as_str().unwrap_or_default().contains("not available yet"), "{txs}");
        let rcpt =
            call(&st, "stell_getTransactionReceipt", json!(hex::encode([0xDDu8; 32]))).await;
        assert_eq!(rcpt["status"], json!("unknown"), "unknown tx is honestly unknown");
        assert_eq!(st.height.load(std::sync::atomic::Ordering::Relaxed), h_before);
    }

    #[tokio::test]
    async fn rpc_hydrates_from_the_durable_receipt_store() {
        // Restart path: the in-memory index is cold, the durable store holds the
        // adopter's filed receipts + header records; hydration restores serving.
        let dir = std::env::temp_dir().join(format!(
            "stell_rpc_hyd_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let store = crate::storage::Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let tx = receipt_tx(sk.verifying_key().to_bytes(), 0);
        let mut b = crate::sharding::Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 31,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![tx.clone()],
            cross_shard_out: vec![],
            timestamp: 555,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            precommit_qc: None,
        };
        b.sign_block(&sk);
        let bh = b.compute_hash();
        store.put_block(&b).unwrap();
        store.put_receipts_for_block(31, &bh, &b.transactions, &[true], &[1]).unwrap();

        let st = test_state().await;
        hydrate_rpc_from_store(&st, &store).await;
        let r = call(&st, "stell_getTransactionReceipt", json!(hex::encode(tx.compute_tx_hash()))).await;
        assert_eq!((r["height"].as_u64(), r["status"].as_str()), (Some(31), Some("success")));
        let blk = call(&st, "stell_getBlock", json!({ "height": 31 })).await;
        assert_eq!(blk["txs"], json!(1), "hydrated window serves the real tx count");
        std::fs::remove_dir_all(&dir).ok();
    }
}
