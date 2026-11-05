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

use crate::contract_abi::{AbiType, AbiValue, ContractAbi};
use crate::mempool::{AdmissionCtx, Mempool};
use crate::network::decode_wire_limited;
use crate::sharding::{ShardId, ShardRegistry, Transaction};
use crate::state_engine::{token_balance_key, AccountState, InMemoryStateEngine};
use axum::{
    extract::{DefaultBodyLimit, Query},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Max JSON body accepted by the RPC server (1 MiB is plenty for a signed tx).
const MAX_RPC_BODY: usize = 1024 * 1024;

/// Max calls in one JSON-RPC batch array (overall cap, fail-closed).
///
/// Each batch item is a FULL `dispatch` (own auth check, own rate-budget
/// draws, own error shape), so the fan-out is bounded here: without a cap a
/// single HTTP request could buy unbounded expensive-read simulations.
pub const MAX_RPC_BATCH_ITEMS: usize = 64;

/// Max bytes of one batch request body, as a multiple of [`MAX_RPC_BODY`].
///
/// Kept at 1x on purpose: the axum extractor (`DefaultBodyLimit`) and the
/// in-handler check already refuse every body above [`MAX_RPC_BODY`], so a
/// batch can never be bigger than a single call's bound — no new DoS surface.
/// The named const makes the overall byte cap explicit next to the item cap
/// (and is the defense-in-depth check for callers that bypass the layer).
pub const MAX_RPC_BATCH_BYTES: usize = MAX_RPC_BODY;

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

/// Compact summary of a finalized block (for the explorer / RPC).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSummary {
    pub height: u64,
    pub hash: String,
    pub tx_count: usize,
    pub timestamp: u64,
}

/// One shard of the network as `stell_getShards` reports it.
///
/// The analogue of TON's `liteServer.getShards` / Near's `shard_layout`: a
/// wallet or an indexer asks the node which shards exist, which chain each
/// one is, and where its head is — instead of assuming a single global chain
/// and guessing where a balance lives.
///
/// Every field is either a fact this node COMMITTED or `null`. A tip is never
/// invented for a shard this node has no committed block for (the audit rule
/// the rest of this file follows: never fabricate, answer "not available").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardHead {
    /// Shard id: `0` is the masterchain, `>= 1` are workchain shards.
    pub shard_id: ShardId,
    /// `"masterchain"` or `"workchain"` (JSON key `type`).
    #[serde(rename = "type")]
    pub shard_type: String,
    /// Height of this shard's committed head.
    pub tip_height: u64,
    /// Hash of this shard's committed head block, or `null` when this node
    /// has no committed head for the shard.
    pub tip_hash: Option<String>,
    /// State root after applying the head block, or `null` when unknown.
    pub state_root: Option<String>,
    /// True when this shard is the one THIS node's own engine runs.
    pub local: bool,
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
    /// a validly signed, funded, nonce-sane transaction — and the faucet has its
    /// own fail-closed `faucet_token`. When `None`, the gated arms stay open
    /// (local/dev mode) — EXCEPT the governance writes (`stell_submitProposal`,
    /// `stell_vote`, `stell_executeProposal`) and the contract previews
    /// (`stell_deployContract`, `stell_callContract`), which require a valid
    /// token on EVERY bind (N-02/N-03; see `require_gov_write_auth`).
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
    /// Ed25519 seed the `stell_signMessage` / `stell_signTypedData` arms sign
    /// with: a SEPARATE ephemeral dev-only key (see
    /// [`dev_msg_signing_seed_from_env`]), NEVER the validator/consensus key.
    /// `None` (production default, and any node without explicit dev mode)
    /// makes both arms refuse fail-closed with `-32000`. Testing/devnet ONLY:
    /// a production wallet signs locally and never ships its key to a node.
    pub msg_signing_seed: Option<[u8; 32]>,
    /// Durable store handle serving per-key ARCHIVE proofs and historical
    /// roots (`stell_getArchiveProof`, `stell_getHistoricalRoot`).
    ///
    /// Archive proofs are rebuilt from the persisted snapshot history, never
    /// from the live trie. `None` (unit tests that never attach a store)
    /// makes both arms refuse fail-closed: a node that cannot consult its
    /// snapshots must say so, not prove from memory and label it history.
    pub archive_store: Option<Arc<crate::storage::Storage>>,
    /// The set of shards this process runs. Gated shard-aware admission on it:
    /// when [`ShardRegistry::is_sharded`] is false (the default, every
    /// pre-sharding test) the faucet serves any well-formed address exactly as
    /// before; when true, the faucet serves ONLY recipients that route to its
    /// own shard and refuses the rest at admission (a drip for another shard
    /// would be dropped by that shard's proposer as shard-filtered and could
    /// never execute).
    pub shard_registry: ShardRegistry,
}

/// One FINALIZED header, with the quorum certificate that decided it.
///
/// This is what an external light client needs: the header carries the
/// precommit quorum certificate, and the certificate is what makes the state
/// root the header commits to TRUSTWORTHY (a root the server merely asserts
/// is worth nothing — see the audit that added this).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FinalizedHeaderRecord {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    /// The state root this header COMMITS TO. Chain convention: a header
    /// commits to the state BEFORE its own block, so this is the root of the
    /// state as of `height - 1`.
    pub state_root: [u8; 32],
    pub proposer: [u8; 32],
    pub timestamp: u64,
    pub cert: crate::consensus::QuorumCertificate,
    /// The epoch-MMR root this block committed to (`Block::mmr_epoch_root`,
    /// V5 Tier-2): non-zero only on the first masterchain block of an epoch
    /// (committing the PREVIOUS epoch). Zero everywhere else — including on
    /// every record predating the MMR (`#[serde(default)]`).
    #[serde(default)]
    pub mmr_epoch_root: [u8; 32],
}

impl FinalizedHeaderRecord {
    /// The wire form: every hash is HEX (the RPC's convention) and the
    /// certificate is spelled out, so a light client can rebuild the
    /// [`crate::consensus::QuorumCertificate`] and verify it.
    pub fn to_json(&self) -> Value {
        json!({
            "height": self.height,
            "block_hash": hex::encode(self.block_hash),
            "prev_hash": hex::encode(self.prev_hash),
            "state_root": hex::encode(self.state_root),
            "proposer": hex::encode(self.proposer),
            "timestamp": self.timestamp,
            // The epoch-MMR root this block committed (V5 Tier-2): the MMR
            // root over the PREVIOUS epoch's finalized hashes on an
            // epoch-boundary block, zero everywhere else. A light client
            // checks a `stell_getEpochRoot` answer against THIS value (it is
            // inside the quorum-signed block hash) instead of trusting the
            // serving node.
            "mmr_epoch_root": hex::encode(self.mmr_epoch_root),
            "cert": {
                "height": self.cert.height,
                "round": self.cert.round,
                "kind": format!("{:?}", self.cert.kind),
                "block_hash": self.cert.block_hash.map(hex::encode),
                "signatures": self.cert.signatures.iter().map(|(v, s)| json!({
                    "validator": hex::encode(v),
                    "signature": hex::encode(s),
                })).collect::<Vec<Value>>(),
            },
        })
    }
}

/// Testnet-only token faucet.
///
/// Faucet funds are **not** written straight into the state engine: that would be
/// node-local and therefore non-deterministic across a multi-node network. The
/// faucet instead signs ordinary transfers from a dedicated, pre-funded genesis
/// account and submits them to the mempool, so the value movement is decided by
/// consensus exactly like any other transaction.
///
/// SHARD SCOPE (sharded networks): one faucet serves exactly ONE shard — the
/// shard in [`Faucet::shard`]. Every drip it builds is a same-shard transfer
/// (`source_shard == target_shard == shard`), so it executes on the chain the
/// recipient lives on. A drip for any other shard is REFUSED at admission
/// (see [`resolve_faucet_recipient`]), never queued: a sharded proposer drops
/// any transaction whose `source_shard` is not its own shard, so queuing it
/// would only burn the faucet's nonce sequence on a drip that can never
/// execute. A sharded process serves a shard's recipients from the faucet
/// whose shard is that shard; the faucet key (and therefore the faucet
/// account) is the SAME on every shard, genesis-funded on each one, so each
/// shard's faucet draws on its own shard's funding with its own nonce
/// sequence.
///
/// On top of that it keeps a hard *lifetime* cap per recipient, so the faucet
/// treasury can never be drained by simply repeating the request.
#[allow(clippy::type_complexity)]
// GATE: faucet persist callback type is fixed by durability hook; alias would churn public builder API.
pub struct Faucet {
    /// Drip amount (`STELL_FAUCET_DRIP_STELL`, default 10 STELL).
    pub drip: u64,
    /// Lifetime maximum creditable amount for a single address.
    pub max_per_address: u64,
    /// The shard this faucet SERVES. Every drip it builds is a same-shard
    /// transfer on this shard (`source_shard == target_shard == shard`); the
    /// faucet account that signs must be genesis-funded on THIS shard (the
    /// masterchain genesis and every workchain genesis both fund the same
    /// faucet address — see `fund_shard_genesis` — so each shard's faucet
    /// draws on its own shard's funding). Must equal the shard of the node
    /// endpoint that serves it: a drip built for any other shard would be
    /// dropped by that shard's proposer as shard-filtered.
    shard: ShardId,
    /// SEED LIFETIME (audit: faucet zeroize): the `pq_key` below derived
    /// from the seed MUST live as long as the faucet itself (every drip is
    /// signed with it), so the seed material is process-lifetime by design,
    /// not a leak to fix. What IS wiped: every INTERMEDIATE copy on the load
    /// path (file bytes, parsed hex line, env string — see
    /// `load_faucet_seed_from_file` / `load_faucet_seed`, all `Zeroizing` or
    /// explicitly zeroized) and the `Faucet::new` frame copy (wiped before
    /// return). Callers: `[u8; 32]` is `Copy`, so YOUR stack binding still
    /// holds the seed after `Faucet::new(seed, ..)` returns — zeroize it at
    /// the call site once the faucet owns it. No behavior change: signing
    /// bytes are identical, only dead copies are wiped.
    ///
    /// FULL-PQ (no compat): the classical ed25519 faucet key is deleted; the
    /// Falcon-512 `pq_key` is the sole signing key.
    /// Falcon-512 keypair derived from the seed (sole PQ drip path).
    /// Same process-lifetime rule as above.
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
/// Genesis-funding ONLY: serving the faucet ([`load_faucet_seed`]) requires
/// the key file and ignores this var fail-closed.
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

// GATE: H-02 fix — the wallet SIGN arms NEVER use the validator key. This is
// the ONLY production constructor for `RpcState::msg_signing_seed`: an
// ephemeral random seed minted in-memory when explicit dev mode is on
// (`STELL_DEV_UNSAFE_TESTKEY=1`, reusing the existing dev-mode flag — no new
// env knob), else `None` (SIGN arms refuse fail-closed). Never persisted,
// never derived from node/validator key material.
pub fn dev_msg_signing_seed_from_env() -> Option<[u8; 32]> {
    if !is_dev_unsafe_testkey_env() {
        return None;
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    Some(seed)
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
        let meta = std::fs::metadata(path).map_err(|e| {
            format!(
                "[faucet] cannot stat faucet key file {}: {e}",
                path.display()
            )
        })?;
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
    let mut raw = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        format!(
            "[faucet] cannot read faucet key file {}: {e}",
            path.display()
        )
    })?);
    // The parsed line is a SECOND copy of the secret (the file buffer above
    // is wiped on the next line): it must be a `Zeroizing` too, or the key
    // hex survives in a plain `String` after this function returns.
    let line = zeroize::Zeroizing::new(
        raw.lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string(),
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
fn load_faucet_seed_from_file_content(
    line: &str,
    path: &std::path::Path,
) -> Result<[u8; 32], String> {
    parse_faucet_seed_hex(line).map_err(|e| format!("{} (in {})", e, path.display()))
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
            FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV, DEV_UNSAFE_TESTKEY_ENV
        ));
    }
    Ok(())
}

/// True when either faucet-key source is configured (inline env or key file).
pub fn faucet_key_present_from_env() -> bool {
    let inline = std::env::var(FAUCET_KEY_ENV)
        .ok()
        .is_some_and(|s| !s.trim().is_empty());
    let file = std::env::var(FAUCET_KEY_FILE_ENV)
        .ok()
        .is_some_and(|s| !s.trim().is_empty());
    inline || file
}

/// Load the faucet seed for SERVING drips: `STELL_FAUCET_KEY_FILE` is
/// REQUIRED (0600-checked, zeroized after load).
///
/// LEAD (no test keys, no defaults in public paths): serving NEVER falls
/// back to inline `STELL_FAUCET_KEY` — an inline seed alone leaves the
/// faucet disabled fail-closed with a loud error pointing at the file.
/// Inline seeds remain valid ONLY for genesis-funding reproducibility via
/// [`load_faucet_seed_for_genesis`] (root determinism for existing chains).
///
/// * `Ok(seed)` — file configured and parsed, test-key gate passed.
/// * `Err(msg)` — fail-closed loud error: missing file (faucet stays
///   DISABLED), bad file (missing / bad perms / bad hex), or the public
///   test key without the dev override. Callers must refuse to serve the
///   faucet on `Err`.
pub fn load_faucet_seed() -> Result<[u8; 32], String> {
    if let Some(path) = std::env::var(FAUCET_KEY_FILE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let path_buf = zeroize::Zeroizing::new(path);
        let seed = load_faucet_seed_from_file(std::path::Path::new(path_buf.as_str()))?;
        check_faucet_seed_allows_startup(&seed)?;
        return Ok(seed);
    }
    if faucet_key_present_from_env() {
        return Err(format!(
            "[faucet] REFUSING: serving the faucet from inline {} is disabled — \
             set {} to a 0600 file carrying the seed (inline seeds are genesis-only, \
             see load_faucet_seed_for_genesis); faucet stays DISABLED",
            FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV
        ));
    }
    Err(format!(
        "[faucet] no faucet key file configured (set {} to a 0600 file); \
         refusing to start the faucet — faucet stays DISABLED",
        FAUCET_KEY_FILE_ENV
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
    if let Some(path) = std::env::var(FAUCET_KEY_FILE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let path_buf = zeroize::Zeroizing::new(path);
        return load_faucet_seed_from_file(std::path::Path::new(path_buf.as_str()));
    }
    if let Some(mut hex_str) = std::env::var(FAUCET_KEY_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
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

/// Build + sign a post-quantum EXPLICIT-envelope transfer (PQ1, Falcon-512)
/// from a raw Falcon-512 keypair.
///
/// This is the single definition of the faucet-shaped PQ transfer: the sender
/// is `derive_pq_address(Falcon512, pubkey, DEFAULT_SALT)` (== `Faucet::account()`
/// under pure-PQ for the faucet's own keypair), the signature covers the
/// UNBOUND `signing_message()` (byte-identical to every drip the faucet has
/// ever built — unbound admission is active while
/// `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` is unset), and the pubkey rides
/// EXPLICITLY so the very first spend from a fresh account verifies with no
/// registry state (always-explicit = no activation tracking needed).
///
/// Callers: `Faucet::build_transfer` (same-shard drips, `source == target ==
/// self.shard`) and the `wallet send-pq` CLI (masterchain source, any target
/// shard). The keypair MUST be derived with
/// `FalconKeypair::generate_from_seed_bytes` on the RAW 32-byte seed — the
/// same derivation `Faucet::new` uses. (The light-wallet KDF derivation
/// produces a DIFFERENT keypair/address from the same seed and cannot spend
/// faucet-genesis funds.)
pub fn sign_pq_explicit_transfer(
    pq_key: &crate::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: ShardId,
    target_shard: ShardId,
) -> Transaction {
    let from = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &pq_key.public_key,
        &crate::post_quantum::DEFAULT_SALT,
    );
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = pq_key.sign(&msg);
    let env = crate::sharding::PqSignatureEnvelope::new_explicit(
        crate::post_quantum::PqScheme::Falcon512,
        pq_key.public_key.clone(),
        sig,
    );
    tx.signature = env.encode();
    tx
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
        // Wipe the frame copy: the live material now lives in `pq_key`
        // (process-lifetime by design). The caller's `Copy` binding is theirs
        // to wipe.
        zeroize::Zeroize::zeroize(&mut key_seed);
        Self {
            drip,
            max_per_address,
            shard,
            pq_key,
            state: tokio::sync::Mutex::new(FaucetState::default()),
            persist: None,
        }
    }

    /// Attach a durability hook, returning the faucet for builder-style use.
    #[allow(clippy::type_complexity)]
    // GATE: persist callback signature is part of public builder API; boxing/aliasing would break callers.
    pub fn with_persist(mut self, persist: std::sync::Arc<dyn Fn(&[u8]) + Send + Sync>) -> Self {
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
            st.ip_buckets
                .retain(|_, (h, _)| now_hour.saturating_sub(*h) <= 1);
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
    ///
    /// FULL-PQ (no compat): always the Falcon-512 PQ address. The classical
    /// ed25519 allowance branch is deleted.
    pub fn account(&self) -> [u8; 32] {
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &self.pq_key.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        )
    }

    /// The shard this faucet serves: every drip it builds executes there
    /// (`source_shard == target_shard == shard`). A recipient that routes to
    /// any other shard is refused at admission (see
    /// [`resolve_faucet_recipient`]), never queued.
    pub fn shard(&self) -> ShardId {
        self.shard
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
        // FULL-PQ (no compat): drips are always PQ-explicit transfers. The
        // classical `Transaction::sign` branch is deleted.
        let tx = sign_pq_explicit_transfer(
            &self.pq_key,
            who,
            amount,
            crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
            nonce,
            self.shard,
            self.shard,
        );
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
            None => {
                let mut st = self.state.lock().await;
                st.last_public_drip.remove(&who);
                self.persist_locked(&st);
                Err(public_drip_cooldown_secs())
            }
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
        st.last_public_drip.remove(&who);
        self.persist_locked(&st);
    }

    /// Lifetime amount already credited to `who`.
    pub async fn dispensed_to(&self, who: [u8; 32]) -> u64 {
        self.state
            .lock()
            .await
            .dispensed
            .get(&who)
            .copied()
            .unwrap_or(0)
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
        let key = ip
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let mut st = self.state.lock().await;
        if st.ip_buckets.len() > 100_000 {
            // Hour-unit comparison: entries store the UTC hour number, not a
            // timestamp (the old seconds-based retain wiped live buckets).
            let now_hour = now_secs / 3600;
            st.ip_buckets
                .retain(|_, (h, _)| now_hour.saturating_sub(*h) <= 1);
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

/// The process-wide window of FINALIZED HEADERS (with their quorum
/// certificates), newest first.
///
/// This is the LIGHT CLIENT's view of the chain (audit W8.3 / production
/// blocker A10): an external verifier fetches a header here, checks its
/// quorum certificate against its OWN validator set, and only then trusts
/// the state root the header commits to. Without it the node could hand out
/// any root it liked and call it a proof.
///
/// It is process-wide (like the invalidation window) because a node has ONE
/// chain: the header stream is a property of the node, not of an RPC
/// instance. Bounded by [`MAX_FINALIZED_HEADERS`]; a header that is too old
/// to be served is an honest "not available" (the client re-anchors on a
/// newer one).
static FINALIZED_HEADERS: std::sync::OnceLock<
    Arc<RwLock<std::collections::VecDeque<FinalizedHeaderRecord>>>,
> = std::sync::OnceLock::new();

/// The process-wide finalized-header window.
pub fn finalized_headers() -> Arc<RwLock<std::collections::VecDeque<FinalizedHeaderRecord>>> {
    FINALIZED_HEADERS
        .get_or_init(|| Arc::new(RwLock::new(std::collections::VecDeque::new())))
        .clone()
}

/// The process-wide PQ key registry view served by `stell_getPqKey` /
/// `stell_getPqRegistryStatus`.
///
/// A node has ONE PQ rotation story (like it has ONE header chain, see
/// [`finalized_headers`]): the registry is a property of the node, not of an
/// RPC instance, so the read arms consult this handle instead of a per-state
/// copy. The arms take only `.read()` — they never mutate. Writes arrive
/// through the staking hooks / future announcement wiring (and tests), never
/// through RPC: there is deliberately no state-mutating PQ endpoint.
pub fn pq_registry_handle() -> &'static RwLock<crate::pq_registry::PqRegistry> {
    static PQ_REGISTRY: std::sync::OnceLock<RwLock<crate::pq_registry::PqRegistry>> =
        std::sync::OnceLock::new();
    PQ_REGISTRY.get_or_init(|| RwLock::new(crate::pq_registry::PqRegistry::new()))
}

/// Max number of FINALIZED HEADERS (with their quorum certificates) retained
/// for the light client.
///
/// Bounded so a busy chain cannot exhaust memory. A light client that needs
/// an older header re-anchors on a newer one; the anchor only ever moves
/// forward.
pub const MAX_FINALIZED_HEADERS: usize = 512;

/// Max receipts retained; bounded so a busy chain cannot exhaust memory.
pub const MAX_RECEIPTS: usize = 50_000;

// ===========================================================================
// FINALIZED-READ CACHE (perf, safety-first)
//
// Hot finalized reads (explorers/wallets poll the same heights) are served
// from a small bounded cache keyed by `(method, height, params-hash)`:
//
// * SOUND because finalized data is immutable: a finalized block, its
//   receipts, its quorum-certified header and a complete epoch root never
//   change. The ONLY invalidation triggers are a height move (entries are
//   tagged with the tip they were filled at and a lookup hits only when the
//   tip is unchanged, so any advance — forward OR a catch-up backward step —
//   is a miss and recomputes), the TTL below, and fail-closed eviction when
//   full. Reads, mempool churn and unfinalized data NEVER invalidate and
//   NEVER change a finalized key.
// * Surgical eviction on the finalize/adopt publish paths (`record_block`,
//   `record_receipts_with_events`, `record_finalized_header`): a late body
//   arriving for an already-published height (txs `0` -> real count, empty
//   receipts -> filed) drops that height's keys, so the next read recomputes.
//   Eviction only ever drops entries (a miss recomputes byte-identical data),
//   so it is fail-closed by construction.
// * Only successful (`Ok`) responses of explicitly height-pinned methods are
//   cached. Errors ("not available yet", "above tip") are NEVER cached: they
//   can resolve as replication catches up. Live/tip-relative reads
//   (`stell_getBalance`, `stell_getBalanceSpv`, `stell_getProof`,
//   `stell_getValidators`, `stell_stakeOf`, receipts with `confirmations`,
//   every `eth_*` tag/latest read, every mempool-dependent read) BYPASS the
//   cache always: caching them would risk serving non-finalized data.
// * `stell_getEpochRoot` is cached ONLY when the served epoch is complete
//   AND carries its quorum-signed boundary commitment; an incomplete epoch
//   still finalizes and would otherwise freeze a stale `complete: false`.
// ===========================================================================

/// Max entries in the finalized-read cache. Const cap: no unbounded growth.
/// 512 matches [`MAX_FINALIZED_HEADERS`], the largest per-height window.
pub const FINALIZED_READ_CACHE_CAP: usize = 512;

/// Time-to-live of a cache entry, in seconds. Second invalidation axis next
/// to height moves; small enough that a pathological stale entry cannot live
/// long, large enough to cover hot-poll windows.
pub const FINALIZED_READ_CACHE_TTL_SECS: u64 = 60;

/// Methods served from the finalized-read cache. Every other method bypasses
/// it (see the module docs above). Deliberately `stell_*` height-pinned reads
/// only: no `eth_*` (adapter-side mutable state, `latest`/`pending` tags),
/// no mempool-dependent reads, no live-state reads.
fn finalized_read_cacheable(method: &str) -> bool {
    matches!(
        method,
        "stell_getBlock"
            | "stell_getBlockTransactions"
            | "stell_getFinalizedHeader"
            | "stell_getEpochRoot"
    )
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FinalizedReadKey {
    method: String,
    height: u64,
    params_hash: [u8; 32],
}

struct FinalizedReadEntry {
    result: Value,
    filled_tip: u64,
    filled_at: std::time::Instant,
}

#[derive(Default)]
struct FinalizedReadCache {
    map: HashMap<FinalizedReadKey, FinalizedReadEntry>,
    hits: u64,
    misses: u64,
}

static FINALIZED_READ_CACHE: std::sync::OnceLock<std::sync::Mutex<FinalizedReadCache>> =
    std::sync::OnceLock::new();

fn finalized_read_cache() -> &'static std::sync::Mutex<FinalizedReadCache> {
    FINALIZED_READ_CACHE.get_or_init(|| std::sync::Mutex::new(FinalizedReadCache::default()))
}

/// Canonical hash of the request params: two byte-identical requests share a
/// key; anything else (even an ignored extra field) is a separate key holding
/// the same bytes — fail-closed towards extra entries, never wrong bytes.
pub fn finalized_read_cache_params_hash(params: &Value) -> [u8; 32] {
    let bytes = serde_json::to_vec(params).unwrap_or_default();
    *blake3::hash(&bytes).as_bytes()
}

fn finalized_read_cache_fresh(entry: &FinalizedReadEntry, tip: u64) -> bool {
    entry.filled_tip == tip
        && entry.filled_at.elapsed().as_secs() < FINALIZED_READ_CACHE_TTL_SECS
}

/// Cached finalized response, if any. `None` (miss) means "recompute and
/// consider filling via [`finalized_read_cache_put`]". Pure read path: no
/// auth, no budgets, no mutation beyond hit/miss counters.
pub fn finalized_read_cache_get(method: &str, height: u64, params: &Value, tip: u64) -> Option<Value> {
    if !finalized_read_cacheable(method) {
        return None;
    }
    let key = FinalizedReadKey {
        method: method.to_string(),
        height,
        params_hash: finalized_read_cache_params_hash(params),
    };
    let mut cache = finalized_read_cache().lock().expect("finalized-read cache lock");
    let hit = match cache.map.get(&key) {
        Some(entry) if finalized_read_cache_fresh(entry, tip) => Some(entry.result.clone()),
        _ => None,
    };
    match hit {
        Some(v) => {
            cache.hits += 1;
            Some(v)
        }
        None => {
            cache.misses += 1;
            None
        }
    }
}

/// Fill the cache after a fresh successful computation. No-op for non-listed
/// methods, for heights above the tip (not finalized), and when full the
/// oldest/expired entries are evicted first (fail-closed: a miss recomputes).
pub fn finalized_read_cache_put(
    method: &str,
    height: u64,
    params: &Value,
    tip: u64,
    result: Value,
) {
    if !finalized_read_cacheable(method) || height > tip {
        return;
    }
    let key = FinalizedReadKey {
        method: method.to_string(),
        height,
        params_hash: finalized_read_cache_params_hash(params),
    };
    let mut cache = finalized_read_cache().lock().expect("finalized-read cache lock");
    if cache.map.len() >= FINALIZED_READ_CACHE_CAP && !cache.map.contains_key(&key) {
        // Fail-closed eviction: expired entries first, else the oldest fill.
        // Only entry DROPS happen here — correctness never depends on them.
        cache.map.retain(|_, e| e.filled_at.elapsed().as_secs() < FINALIZED_READ_CACHE_TTL_SECS);
        if cache.map.len() >= FINALIZED_READ_CACHE_CAP {
            let mut oldest: Option<(FinalizedReadKey, std::time::Instant)> = None;
            for (k, e) in cache.map.iter() {
                let replace = match &oldest {
                    None => true,
                    Some((_, t)) => e.filled_at < *t,
                };
                if replace {
                    oldest = Some((k.clone(), e.filled_at));
                }
            }
            if let Some((k, _)) = oldest {
                cache.map.remove(&k);
            }
        }
    }
    cache.map.insert(
        key,
        FinalizedReadEntry {
            result,
            filled_tip: tip,
            filled_at: std::time::Instant::now(),
        },
    );
}

/// Drop every cached response that a finalize/adopt publish for `height` can
/// change (block summary, block transactions, finalized header). Called from
/// the `record_*` publish paths only — never from reads, never from the
/// mempool, never from auth/rate code.
pub fn finalized_read_cache_evict_height(height: u64) {
    let Ok(mut cache) = finalized_read_cache().lock() else {
        return;
    };
    cache.map.retain(|k, _| k.height != height);
}

/// Drop every cached epoch root: any new finalized header can complete an
/// epoch or supply its boundary commitment. Epoch keys are few; a full-method
/// drop is cheaper than range tracking and equally fail-closed.
pub fn finalized_read_cache_evict_epoch_roots() {
    let Ok(mut cache) = finalized_read_cache().lock() else {
        return;
    };
    cache.map.retain(|k, _| k.method != "stell_getEpochRoot");
}

/// Read-only introspection for tests/monitoring: `(entries, hits, misses)`.
pub fn finalized_read_cache_stats() -> (usize, u64, u64) {
    let cache = finalized_read_cache().lock().expect("finalized-read cache lock");
    (cache.map.len(), cache.hits, cache.misses)
}

/// Read-only entry count for the bounded-growth gate.
pub fn finalized_read_cache_len() -> usize {
    finalized_read_cache_stats().0
}

/// Test hook: force every entry stale so the next lookup recomputes (proves
/// expiry is fail-closed). `#[doc(hidden)]`, used by the cache tests only.
#[doc(hidden)]
pub fn finalized_read_cache_expire_all_for_tests() {
    let Ok(mut cache) = finalized_read_cache().lock() else {
        return;
    };
    for (_, e) in cache.map.iter_mut() {
        e.filled_at = e.filled_at
            .checked_sub(std::time::Duration::from_secs(FINALIZED_READ_CACHE_TTL_SECS + 1))
            .unwrap_or(std::time::Instant::now());
    }
}

// ===========================================================================
// EXPENSIVE-READ BUDGET (audit W6.7)
//
// `stell_estimateFee` clones the WHOLE engine state (accounts, trie, tokens,
// contracts, bridge, PQ db) and runs a full SVM execution on the clone. That
// is orders of magnitude more expensive than any other read method, and it is
// UNAUTHENTICATED (a wallet must be able to estimate its fee before it holds
// any token). The generic per-IP budget (300/s by default) is far too
// generous for it: at that rate a single client can keep the node cloning
// state continuously.
//
// The estimate therefore gets its OWN, much smaller per-IP budget. Local
// policy, not consensus: nodes MAY differ.
// ===========================================================================

/// Default per-IP budget for `stell_estimateFee` (per second).
///
/// 5/s is generous for a wallet (a form sends one estimate) and small enough
/// that a flood cannot pin the node's CPU. Override with
/// `STELL_ESTIMATE_FEE_RATE_LIMIT`.
pub const ESTIMATE_FEE_RATE_LIMIT_DEFAULT: u32 = 5;

/// Effective estimate-fee per-IP budget.
fn estimate_fee_rate_limit() -> u32 {
    std::env::var("STELL_ESTIMATE_FEE_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(ESTIMATE_FEE_RATE_LIMIT_DEFAULT)
}

/// The process-wide estimate-fee limiter.
fn estimate_fee_budget() -> &'static crate::explorer::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| crate::explorer::RateLimiter::new(estimate_fee_rate_limit()))
}

/// Static attribution for callers without a peer IP (audit residual: the
/// `peer_ip=None` bypass).
///
/// `dispatch` is reached with `peer_ip=None` only from in-process callers
/// (`RpcState::call`, `handle_rpc_call` — tests and in-tree dispatch): both
/// production transports always resolve an IP (`rpc_handler` via
/// `resolve_client_ip`, `ws_handler` via the upgrade peer, see below). The
/// old code SKIPPED the estimate-fee and per-client subscription caps for
/// `None`, so an unattributed caller was exempt. Unattributed callers now
/// share ONE static bucket with the SAME caps — throttled, never exempt
/// (same shape as the faucet's `"unknown"` fallback in
/// `Faucet::check_ip_throttle`).
///
/// The key is `0.0.0.0` (unspecified): it can never be a real TCP peer
/// address, so it can never collide with — or be chosen by — a real client's
/// bucket. Normal clients (`Some(ip)`) take the exact same path as before.
pub const LOCAL_BUCKET_IP: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

/// Static client identity for unattributed subscription creators (see
/// [`LOCAL_BUCKET_IP`]): in-process `stell_subscribe` calls share one
/// per-client budget (`MAX_SUBSCRIPTIONS_PER_CLIENT`) instead of bypassing it.
pub const LOCAL_SUBSCRIBER_ID: &str = "local";

/// Hard ceiling on the gas a fee ESTIMATE may burn.
///
/// The estimate path used to raise the simulation's gas limit to
/// `MAX_CONTRACT_FUEL` (50 000 000) — the contract-execution ceiling — which
/// is 10x the ordinary transaction budget. An estimate only needs enough gas
/// to price a normal call, so the ceiling is 5 000 000: the answer for a
/// normal transaction is unchanged, and a pathological payload cannot burn
/// the full contract ceiling on an unauthenticated read.
///
/// FIXED (audit W7.2): this is the MAXIMUM the estimate simulation may ever
/// be given, and it is NOT caller-raisable. A caller may ask for LESS (see
/// [`estimate_fee_gas_budget`]), never for more: the estimate is an
/// UNAUTHENTICATED read, so its cost per request has to stay bounded no
/// matter what the caller asks for.
pub const ESTIMATE_FEE_GAS_CEILING: u64 = 5_000_000;

/// The smallest gas budget an estimate simulation may be given.
///
/// A basic transfer already costs [`crate::svm::GAS_BASIC_TRANSFER`] gas, so
/// a budget below that cannot answer anything: it is refused rather than
/// silently rounded up.
pub const ESTIMATE_FEE_MIN_GAS: u64 = crate::svm::GAS_BASIC_TRANSFER;

/// The gas budget the estimate simulation runs with.
///
/// HONEST SEMANTICS (audit W7.2). The estimate answers "how much gas does
/// this call NEED", so the budget it simulates with must be able to hold the
/// answer:
///
/// * the caller's DECLARED limit (the transaction's own `gas_limit`) is NOT
///   the simulation budget. Simulating with a limit the caller happened to
///   declare would answer "out of gas" instead of the requirement, so the
///   declared limit is ignored and the simulation runs with the FULL ceiling;
/// * a caller MAY lower the budget with `max_gas`: it is honoured, and the
///   answer is then "what fits in that budget" (or "out of gas");
/// * a caller may NEVER raise it above [`ESTIMATE_FEE_GAS_CEILING`]: a
///   request above the ceiling is REFUSED, never clamped silently, so the
///   bounded cost of an unauthenticated read cannot be reopened by a caller.
///
/// `Ok(budget)` is the gas the simulation may burn; `Err(msg)` is the
/// refusal (answered as `-32602`).
pub fn estimate_fee_gas_budget(requested_max_gas: Option<u64>) -> Result<u64, String> {
    match requested_max_gas {
        None => Ok(ESTIMATE_FEE_GAS_CEILING),
        Some(v) if v > ESTIMATE_FEE_GAS_CEILING => Err(format!(
            "max_gas {v} exceeds the estimate gas ceiling ({ESTIMATE_FEE_GAS_CEILING}); \
             the ceiling is fixed and cannot be raised"
        )),
        Some(v) if v < ESTIMATE_FEE_MIN_GAS => Err(format!(
            "max_gas {v} is below the minimum estimate gas budget ({ESTIMATE_FEE_MIN_GAS})"
        )),
        Some(v) => Ok(v),
    }
}

/// Max number of events `stell_getEvents` returns for one contract query.///
/// BOUNDED ANSWER (audit W6.7): the receipt index holds up to
/// [`MAX_RECEIPTS`] (50 000) receipts and every receipt can carry up to
/// `crate::contract::MAX_CONTRACT_EVENTS` (256) events, so an unfiltered
/// contract query could answer with MILLIONS of events — an unbounded
/// response body and an unbounded JSON build on an unauthenticated read.
/// The cap is generous for a real query (a contract emits a handful of
/// events per transaction) and the caller may lower it with `limit`.
pub const MAX_EVENTS_RETURNED: usize = 1_000;

/// What a wallet gets back for a transaction it submitted.
///
/// `gas_limit` is the DECLARED limit; `fee_charged` is what the single real
/// application actually debited (0 for a failed transaction, whose commit is
/// atomic - it paid nothing). Wallets must account on `fee_charged`: the
/// limit overstates the cost of every failed transaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    #[serde(default)]
    pub events: Vec<crate::contract::ContractEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<[u8; 32]>,
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
        // Finalized-read cache: a (re)publish for this height (finalize, or a
        // late adopted body upgrading txs `0` to the real count) drops that
        // height's cached responses so the next read recomputes. Fail-closed.
        finalized_read_cache_evict_height(height);
        self.height
            .store(height, std::sync::atomic::Ordering::Relaxed);
        let mut rb = self.recent_blocks.write().await;
        rb.push_front(BlockSummary {
            height,
            hash: hex::encode(hash),
            tx_count,
            timestamp,
        });
        while rb.len() > MAX_RECENT_BLOCKS {
            rb.pop_back();
        }
        drop(rb);
        crate::evm_adapter::notify_block(crate::evm_adapter::stell_hash_to_evm(&hash));
        // Streaming: this IS the consensus finalize hook, so the `newHeads`
        // subscribers are notified here -- a subscriber sees every finalized
        // head of this node, in order, tagged `finality: "finalized"`.
        publish_new_head(
            height,
            hash,
            crate::sharding::MASTERCHAIN_SHARD,
            tx_count,
            timestamp,
        );
    }

    /// Record a FINALIZED header together with the quorum certificate that
    /// decided it.
    ///
    /// This is what makes the node's chain externally verifiable (audit W8.3 /
    /// production blocker A10): a light client fetches the header, checks the
    /// certificate against its OWN validator set, and only then believes the
    /// state root the header commits to.
    ///
    /// A block with NO precommit quorum certificate is not DECIDED, so it is
    /// not recorded: there is no evidence to serve, and serving a header
    /// without one would be exactly the "the node hands out the root it
    /// believes in" hole this closes.
    pub async fn record_finalized_header(&self, block: &crate::sharding::Block) {
        let Some(cert) = block.precommit_qc.clone() else {
            return;
        };
        let record = FinalizedHeaderRecord {
            height: block.height,
            block_hash: block.compute_hash(),
            prev_hash: block.prev_hash,
            state_root: block.state_root,
            proposer: block.proposer,
            timestamp: block.timestamp,
            cert,
            mmr_epoch_root: block.mmr_epoch_root,
        };
        let store = finalized_headers();
        let mut hs = store.write().await;
        // The newest first, like `recent_blocks`.
        hs.push_front(record);
        while hs.len() > MAX_FINALIZED_HEADERS {
            hs.pop_back();
        }
        drop(hs);
        // Finalized-read cache: this header can complete an epoch or supply
        // its boundary commitment, so cached epoch roots are dropped (they
        // recompute) and this height's cached header is dropped too.
        finalized_read_cache_evict_height(block.height);
        finalized_read_cache_evict_epoch_roots();
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
        self.record_receipts_with_events(height, block_hash, txs, statuses, fees, &[])
            .await;
    }

    /// Record inclusion receipts for a finalized block's transactions, including contract events.
    pub async fn record_receipts_with_events(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        events: &[Vec<crate::contract::ContractEvent>],
    ) {
        // Link EVM intents settled via secp envelopes BEFORE filing receipts,
        // so a reader that observes the receipt also observes the mapping.
        for tx in txs.iter() {
            crate::evm_adapter::link_secp_settlement(tx);
        }
        // Finalized-read cache: newly filed receipts change this height's
        // block-transactions answer (absent -> filed, e.g. a late adopted
        // body), so that height's cached responses are dropped. Fail-closed.
        finalized_read_cache_evict_height(height);
        let mut idx = self.receipts.write().await;
        // Batched hashing in a SINGLE pass: one reused hasher + one reused
        // payload scratch buffer + one reused serialization buffer, with the
        // hash output pre-sized — instead of one hasher + two payload buffers
        // per transaction. The hashes are byte-identical to per-transaction
        // `compute_tx_hash` (shared `hash_into` code, `finalize_reset`
        // restarts the hasher to the same initial state), and the raw-tx hex
        // is byte-identical to `bincode::serialize` (same options, cleared
        // scratch). Only the stored hex `String` itself is allocated per
        // transaction (it has to be: it is stored in the receipt).
        let mut batcher = crate::sharding::Transaction::batch_hasher();
        let mut raw_buf: Vec<u8> = Vec::new();
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            raw_buf.clear();
            let raw_tx = bincode::serialize_into(&mut raw_buf, tx)
                .ok()
                .map(|_| hex::encode(&raw_buf));
            let h = batcher.hash_one(tx);
            hashes.push(h);
            let (rv, gu, ev, ca) = if let Some(existing) = idx.get(&h) {
                let evs = if !existing.events.is_empty() {
                    existing.events.clone()
                } else {
                    events.get(i).cloned().unwrap_or_default()
                };
                (
                    existing.return_value,
                    existing.gas_used,
                    evs,
                    existing.contract_address,
                )
            } else {
                (None, None, events.get(i).cloned().unwrap_or_default(), None)
            };
            idx.insert(TxReceipt {
                tx_hash: h,
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
                return_value: rv,
                gas_used: gu,
                events: ev,
                contract_address: ca,
            });
        }
        // Streaming: fan the included transactions out to the `newTxs`
        // subscribers and the emitted contract events to the `events`
        // subscribers. Done AFTER the receipt lock is released -- the fan-out
        // must never hold the receipt index while a subscriber is slow, and
        // the receipt index stays the source of truth for the RPC reads.
        drop(idx);
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let hash = hashes[i];
            publish_new_tx(
                hash,
                tx.from,
                tx.to,
                tx.amount,
                if success { "confirmed" } else { "failed" },
            );
            if let Some(evs) = events.get(i) {
                for e in evs {
                    publish_contract_event(e, height, hash);
                }
            }
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
        self.record_adopted_block_with_events(
            height,
            block_hash,
            txs,
            statuses,
            fees,
            &[],
            timestamp,
        )
        .await;
    }

    /// Record an adopted block including emitted contract events.
    #[allow(clippy::too_many_arguments)]
    // GATE: 8 receipt fields are required together; grouping would change index/record call sites.
    pub async fn record_adopted_block_with_events(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        events: &[Vec<crate::contract::ContractEvent>],
        timestamp: u64,
    ) {
        self.record_receipts_with_events(height, block_hash, txs, statuses, fees, events)
            .await;
        self.record_block(height, block_hash, txs.len(), timestamp)
            .await;
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
            return_value: None,
            gas_used: None,
            events: r.events.clone(),
            contract_address: None,
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
                rb.iter()
                    .find(|p| p.height == b.height - 1)
                    .map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            let evm_block =
                crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full_tx);
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
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            let parent_hash = if b.height > 0 {
                rb.iter()
                    .find(|p| p.height == b.height - 1)
                    .map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(b.height);
            let evm_block =
                crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full_tx);
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
        let norm = crate::evm_adapter::normalize_hash(tx_hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let h_bytes = crate::evm_adapter::parse_hash_bytes(&norm)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        // Resolve EVM intent -> stell tx hash for the lookup, keeping the
        // queried (EVM) hash for the response body.
        let lookup_bytes: [u8; 32] =
            crate::evm_adapter::evm_to_stell_hash(&norm).unwrap_or(h_bytes);
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
                .fold(0u64, |acc, br| acc.saturating_add(br.fee_charged));
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
        let norm = crate::evm_adapter::normalize_hash(tx_hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let h_bytes = crate::evm_adapter::parse_hash_bytes(&norm)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let lookup_bytes: [u8; 32] =
            crate::evm_adapter::evm_to_stell_hash(&norm).unwrap_or(h_bytes);
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
            } else if let Some(evm_tx) =
                crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id)
            {
                return Ok(Some(evm_tx));
            }
        }
        drop(idx);
        let mp = self.mempool.read().await;
        if let Some(tx) = mp.get(&lookup_bytes) {
            let mut evm_tx =
                crate::evm_adapter::stell_tx_to_evm_with_chain(tx, None, None, None, self.chain_id);
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
                rb.iter()
                    .find(|p| p.height == b.height - 1)
                    .map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            let evm_block =
                crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full);
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
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            return Ok(Some(crate::evm_adapter::format_u64_hex(b.tx_count as u64)));
        }
        drop(rb);
        crate::evm_adapter::global_adapter().get_block_transaction_count_by_hash(&norm)
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
        crate::evm_adapter::global_adapter().get_block_transaction_count_by_number(tag)
    }

    /// Transaction at `index` inside the block looked up by hash.
    /// Serve order: recent window receipts -> global adapter maps -> null.
    pub async fn eth_get_transaction_by_block_hash_and_index(
        &self,
        hash: &str,
        index: u64,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
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
                let known_tx_count = rb
                    .iter()
                    .find(|b| b.height == h)
                    .map(|b| b.tx_count)
                    .unwrap_or(0);
                if known_tx_count == 0 {
                    return Ok(None);
                }
                // Non-zero tx_count but no receipts indexed yet: honest null.
                return Ok(None);
            }
            return Ok(None);
        }
        crate::evm_adapter::global_adapter().get_transaction_by_block_hash_and_index(&norm, index)
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
        crate::evm_adapter::global_adapter().get_transaction_by_block_number_and_index(tag, index)
    }

    /// Uncle count by block hash. Stellereum never produces uncles:
    /// known block -> `"0x0"`, unknown block -> null.
    pub async fn eth_get_uncle_count_by_block_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if rb.iter().any(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            return Ok(Some("0x0".to_string()));
        }
        drop(rb);
        crate::evm_adapter::global_adapter().get_uncle_count_by_block_hash(&norm)
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
        crate::evm_adapter::global_adapter().get_uncle_count_by_block_number(tag)
    }

    /// Uncle at `index` by block hash. Stellereum never produces uncles: always null.
    /// The block hash is still validated so malformed requests error with -32602.
    pub async fn eth_get_uncle_by_block_hash_and_index(
        &self,
        hash: &str,
        _index: u64,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
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
        self.eth_get_block_transaction_count_by_hash(&hash_str)
            .await
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
        self.eth_get_transaction_by_block_hash_and_index(&hash_str, index)
            .await
    }

    pub async fn handle_get_transaction_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let (tag, index) = crate::evm_adapter::parse_block_number_and_index_params(params)?;
        self.eth_get_transaction_by_block_number_and_index(&tag, index)
            .await
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
        self.eth_get_uncle_by_block_hash_and_index(&hash_str, index)
            .await
    }

    pub async fn handle_get_uncle_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        let (tag, index) = crate::evm_adapter::parse_block_number_and_index_params(params)?;
        self.eth_get_uncle_by_block_number_and_index(&tag, index)
            .await
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
            let mut global = evm::global_adapter()
                .collect_matching_logs(&criteria, block_hash_filter.as_deref());
            out.append(&mut global);
        }
        out.sort_by_key(evm::log_sort_key);
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
        crate::evm_adapter::global_adapter().eth_get_storage_at(params)
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
        let r = dispatch(
            self,
            serde_json::Value::from(1),
            method,
            &params,
            None,
            None,
        )
        .await;
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

/// Whole-batch refusal: the single error object the batch path answers when
/// the batch ITSELF is invalid (empty, too many items, too many bytes).
/// Per-item failures never come here — they are per-item `-32601`/`-32602`/
/// `-32000` entries inside the array (see [`handle_rpc_batch_call`]).
fn batch_refused(message: impl Into<String>) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id: Value::Null,
        result: None,
        error: Some(RpcError {
            code: -32600,
            message: message.into(),
            data: None,
        }),
    }
}

/// Dispatch one parsed JSON-RPC batch array.
///
/// * Overall caps (fail-closed, whole-batch refusal as a single `-32600`
///   error object): more than [`MAX_RPC_BATCH_ITEMS`] items, or a body over
///   [`MAX_RPC_BATCH_BYTES`], refuses the WHOLE batch.
/// * Per-item isolation: every item is parsed and dispatched independently
///   through the SAME `dispatch` as a single call (same `header_token`,
///   same `peer_ip`, same auth checks, same per-IP budgets, same error
///   shapes) — one bad/unknown/over-budget call never fails its siblings.
/// * Ordering: responses come back in request order, whatever the ids are.
/// * Notifications (no `id`, or `id: null`) get NO response entry, per the
///   JSON-RPC 2.0 spec (an all-notification batch yields an empty vec — the
///   HTTP handler answers that with `204 No Content`).
pub async fn handle_rpc_batch_call(
    st: &RpcState,
    items: &[Value],
    raw_len: usize,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<Vec<RpcResponse>, RpcResponse> {
    if items.is_empty() {
        return Err(batch_refused("empty batch"));
    }
    if items.len() > MAX_RPC_BATCH_ITEMS {
        return Err(batch_refused(format!(
            "batch too large: {} items (max {MAX_RPC_BATCH_ITEMS})",
            items.len()
        )));
    }
    if raw_len > MAX_RPC_BATCH_BYTES {
        return Err(batch_refused(format!(
            "batch too large: {raw_len} bytes (max {MAX_RPC_BATCH_BYTES})"
        )));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let req: RpcRequest = match serde_json::from_value(item.clone()) {
            Ok(r) => r,
            Err(e) => {
                out.push(batch_refused(format!("invalid request: {e}")));
                continue;
            }
        };
        // Notification: no response entry, per spec (siblings unaffected).
        let id = req.id.clone().unwrap_or(Value::Null);
        if id.is_null() {
            continue;
        }
        // Per-item transport budget: the HTTP middleware charged the batch
        // request once; every item draws the per-IP standalone budget again,
        // exactly as N single calls would. Over budget fails THIS item with
        // the per-item `-32000` rate shape (the socket stays answerable, the
        // siblings are unaffected) — never the whole batch.
        let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
        let limiter = STANDALONE_LIMITER
            .get_or_init(|| crate::explorer::RateLimiter::new(standalone_limit_per_sec()));
        if !limiter.check(ip) {
            out.push(RpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: "rate limit exceeded (per-IP budget on standalone RPC)".to_string(),
                    data: None,
                }),
            });
            continue;
        }
        out.push(
            dispatch(st, id, &req.method, &req.params, header_token, peer_ip)
                .await
                .0,
        );
    }
    Ok(out)
}

#[derive(Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

fn ok(id: Value, result: Value) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    })
}

fn err(id: Value, code: i64, message: impl Into<String>) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.into(),
            data: None,
        }),
    })
}

/// Truncate caller-controlled text reflected in an error message.
///
/// Error strings are served back over the network, so reflecting an unbounded
/// caller string verbatim lets one request turn a ~1 MiB body into a ~1 MiB
/// error (bandwidth amplification and log bloat). Short legitimate inputs
/// (typos, wrong names) pass through byte-identical; only over-long
/// reflections are shortened, with an explicit marker.
fn snip_for_error(s: &str) -> String {
    const MAX_REFLECTED_ERROR_CHARS: usize = 256;
    if s.len() <= MAX_REFLECTED_ERROR_CHARS {
        s.to_string()
    } else {
        let mut end = MAX_REFLECTED_ERROR_CHARS;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...[truncated {} chars]", &s[..end], s.len())
    }
}

/// Parse a 32-byte hex string (with or without 0x).
fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err("expected 32 bytes (64 hex characters)".to_string());
    }
    let b = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
    b.try_into().map_err(|_| "expected 32 bytes".to_string())
}

/// Parse a 32-byte hex address (with or without 0x).
#[allow(dead_code)]
pub fn parse_addr(s: &str) -> Result<[u8; 32], String> {
    parse_hash(s)
}

/// Parse a single argument value for `stell_runGetMethod` into an `i64`.
fn parse_single_getter_arg(val: &Value) -> Result<i64, String> {
    if let Some(n) = val.as_i64() {
        return Ok(n);
    }
    if let Some(u) = val.as_u64() {
        return Ok(u as i64);
    }
    if let Some(b) = val.as_bool() {
        return Ok(if b { 1 } else { 0 });
    }
    if val.is_null() {
        return Ok(0);
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        if let Some(hex_part) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            if hex_part.is_empty() {
                return Ok(0);
            }
            if hex_part.len() <= 16 {
                let n = u64::from_str_radix(hex_part, 16)
                    .map_err(|e| format!("invalid hex argument: {e}"))?;
                return Ok(n as i64);
            } else {
                let bytes =
                    hex::decode(hex_part).map_err(|e| format!("invalid hex argument: {e}"))?;
                if bytes.len() <= 8 {
                    let mut buf = [0u8; 8];
                    buf[8 - bytes.len()..].copy_from_slice(&bytes);
                    return Ok(i64::from_be_bytes(buf));
                } else {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[..8]);
                    return Ok(i64::from_be_bytes(buf));
                }
            }
        }
        if let Ok(n) = trimmed.parse::<i64>() {
            return Ok(n);
        }
        if trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            if trimmed.len() <= 16 {
                let n = u64::from_str_radix(trimmed, 16)
                    .map_err(|e| format!("invalid hex argument: {e}"))?;
                return Ok(n as i64);
            } else if let Ok(bytes) = hex::decode(trimmed) {
                if bytes.len() <= 8 {
                    let mut buf = [0u8; 8];
                    buf[8 - bytes.len()..].copy_from_slice(&bytes);
                    return Ok(i64::from_be_bytes(buf));
                }
            }
        }
        return Err(format!(
            "cannot parse argument into integer: {}",
            snip_for_error(s)
        ));
    }
    Err(format!("unsupported argument type: {val}"))
}

/// Parse `args` field for `stell_runGetMethod`, accepting a JSON array, number, or hex string.
fn parse_get_method_args(val: &Value) -> Result<Vec<i64>, String> {
    if val.is_null() {
        return Ok(Vec::new());
    }
    if let Some(arr) = val.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            out.push(parse_single_getter_arg(item)?);
        }
        return Ok(out);
    }
    let arg = parse_single_getter_arg(val)?;
    Ok(vec![arg])
}

/// Parse a contract call argument from a Value (supports number, hex string, boolean, or 1-element array).
#[allow(dead_code)]
fn parse_contract_call_arg(val: &Value) -> Result<i64, String> {
    if let Some(arr) = val.as_array() {
        if let Some(first) = arr.first() {
            return parse_single_getter_arg(first);
        } else {
            return Ok(0);
        }
    }
    parse_single_getter_arg(val)
}

/// Parse every argument of a contract call from a Value.
///
/// An array carries one argument per element (multi-argument methods), a
/// scalar is a single argument.
fn parse_contract_call_args(val: &Value) -> Result<Vec<i64>, String> {
    if let Some(arr) = val.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            out.push(parse_single_getter_arg(item)?);
        }
        return Ok(out);
    }
    Ok(vec![parse_single_getter_arg(val)?])
}

/// Convert a JSON value into a typed ABI value of the declared type.
fn json_to_abi_value(ty: AbiType, val: &Value, param: &str) -> Result<AbiValue, String> {
    match ty {
        AbiType::I64 => {
            let n = val
                .as_i64()
                .or_else(|| val.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
                .ok_or_else(|| format!("parameter '{param}' must be an i64"))?;
            Ok(AbiValue::I64(n))
        }
        AbiType::U64 => {
            let n = val
                .as_u64()
                .or_else(|| val.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                .ok_or_else(|| format!("parameter '{param}' must be a u64"))?;
            Ok(AbiValue::U64(n))
        }
        AbiType::I32 => {
            let n = val
                .as_i64()
                .or_else(|| val.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
                .ok_or_else(|| format!("parameter '{param}' must be an i32"))?;
            if n < i32::MIN as i64 || n > i32::MAX as i64 {
                return Err(format!("parameter '{param}' does not fit into an i32"));
            }
            Ok(AbiValue::I32(n as i32))
        }
        AbiType::Bool => match val {
            Value::Bool(b) => Ok(AbiValue::Bool(*b)),
            Value::Number(n) => Ok(AbiValue::Bool(n.as_i64().unwrap_or(0) != 0)),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => Ok(AbiValue::Bool(true)),
                "false" | "0" => Ok(AbiValue::Bool(false)),
                _ => Err(format!("parameter '{param}' must be a boolean")),
            },
            _ => Err(format!("parameter '{param}' must be a boolean")),
        },
        AbiType::Bytes => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("parameter '{param}' must be a hex string"))?;
            let clean = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            let bytes = hex::decode(clean)
                .map_err(|e| format!("parameter '{param}' is not valid hex: {e}"))?;
            Ok(AbiValue::Bytes(bytes))
        }
        AbiType::Address => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("parameter '{param}' must be an address"))?;
            let addr = crate::address::parse_address(s)
                .map_err(|e| format!("parameter '{param}' is not a valid address: {e}"))?;
            Ok(AbiValue::Address(addr))
        }
        AbiType::String => {
            let s = val
                .as_str()
                .ok_or_else(|| format!("parameter '{param}' must be a string"))?;
            Ok(AbiValue::String(s.to_string()))
        }
    }
}

/// Parse the optional `abi` parameter of a deployment: either a JSON object
/// (the manifest itself) or a string containing the JSON manifest.
fn parse_abi_manifest_param(p: &Value) -> Result<Option<ContractAbi>, String> {
    let raw = match p.get("abi").or_else(|| p.get("abi_json")) {
        Some(v) => v,
        None => return Ok(None),
    };
    if raw.is_null() {
        return Ok(None);
    }
    let text = match raw {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let abi = ContractAbi::from_json(&text).map_err(|e| e.to_string())?;
    Ok(Some(abi))
}

/// Parse the arguments of a call against an ABI manifest.
///
/// The manifest is authoritative: the method must exist and the number of
/// arguments must match the declaration exactly.
fn parse_abi_args(
    abi: &ContractAbi,
    method: &str,
    val: Option<&Value>,
) -> Result<Vec<AbiValue>, String> {
    let m = abi
        .method(method)
        .ok_or_else(|| format!("method '{method}' is not declared in the contract ABI"))?;
    let items: Vec<Value> = match val {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => arr.clone(),
        Some(other) => vec![other.clone()],
    };
    if items.len() != m.params.len() {
        return Err(format!(
            "method '{method}' expects {} argument(s), got {}",
            m.params.len(),
            items.len()
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for (p, v) in m.params.iter().zip(items.iter()) {
        out.push(json_to_abi_value(p.ty, v, &p.name)?);
    }
    Ok(out)
}

/// Parse address for RPC methods, accepting Stl57, 64-hex, or 40-hex (EVM address).
fn parse_rpc_address(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    if let Ok(addr) = crate::address::parse_address(trimmed) {
        return Ok(addr);
    }
    if let Some(hex_clean) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if hex_clean.len() == 40 {
            if let Ok(evm_b) = hex::decode(hex_clean) {
                if let Ok(evm_arr) = <[u8; 20]>::try_from(evm_b.as_slice()) {
                    return Ok(crate::evm_adapter::evm_to_stell_address(&evm_arr));
                }
            }
        }
        if hex_clean.len() == 64 {
            if let Ok(b) = hex::decode(hex_clean) {
                if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
                    return Ok(arr);
                }
            }
        }
    }
    Err(format!("invalid address: {}", snip_for_error(s)))
}

/// A call-like opcode extracted from a sealed tx for preview/admission.
struct ExtractedCall {
    contract: [u8; 32],
    method: Vec<u8>,
    args: Vec<i64>,
    calldata: Vec<u8>,
}

/// The call shape a contract-call preview executes on the registry clone.
enum PreviewCall<'a> {
    /// Plain wasm arguments (`call_args` path).
    Plain(&'a [i64]),
    /// Raw multi-argument form with the canonical ABI calldata blob
    /// (`call_with_context_args_calldata` path — the exact opcode a
    /// `SysCallCallContractArgs` carries).
    RawArgs(&'a [i64], &'a [u8]),
    /// Typed ABI arguments (`call_abi` path).
    Abi(&'a [AbiValue]),
}

/// H-03: read-only contract-call preview executed on a CLONE of the contract
/// registry. Returns the same
/// [`crate::state_engine::ContractCallOutcome`] the block-applied execution
/// would report (same return value, gas and events), but touches NO live
/// state: no debit/credit, no balance syncs, no outbound-message routing, no
/// trie writes. State changes happen exclusively when a transaction submitted
/// via `stell_sendRawTransaction` is applied by a block (N-03: the previewed
/// tx itself is dropped, never admitted).
///
/// The `value` leg is simulated on the clone with the same failure modes the
/// old direct path had: a sender that cannot cover `value` fails with
/// `insufficient funds to transfer value: …` and nothing moves. Execution
/// uses the default call context, exactly like the engine's structured-call
/// helpers did, so previews are result-identical to the pre-fix answers.
async fn preview_contract_call(
    st: &RpcState,
    contract_addr: &[u8; 32],
    method: &str,
    call: PreviewCall<'_>,
    value: u64,
    sender: &[u8; 32],
    gas_limit: u64,
) -> crate::state_engine::ContractCallOutcome {
    let failed = |msg: String, gas_used: u64| crate::state_engine::ContractCallOutcome {
        status: "failed".to_string(),
        return_value: None,
        gas_used,
        events: Vec::new(),
        error: Some(msg),
    };
    // Same failure modes as the retired direct debit, evaluated read-only.
    if value > 0 {
        match st.engine.get_account(sender).await {
            None => {
                return failed(
                    "insufficient funds to transfer value: account does not exist".to_string(),
                    0,
                );
            }
            Some(a) if a.balance < value => {
                return failed(
                    "insufficient funds to transfer value: Insufficient native STELL balance"
                        .to_string(),
                    0,
                );
            }
            Some(_) => {}
        }
    }
    let mut work = st.engine.contracts_read().await.clone();
    // Read-only mirror of `sync_contract_balance` plus the value leg: the
    // contract observes the live account balance plus the transferred value.
    // Applied to the CLONE only; the live registry and accounts are untouched.
    if work.contracts.contains_key(contract_addr) {
        let acct_bal = st
            .engine
            .get_account(contract_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        if let Some(c) = work.contracts.get_mut(contract_addr) {
            c.balance = c.balance.max(acct_bal).saturating_add(value);
        }
    }
    let exec: Result<
        (i64, u64, Vec<crate::contract::ContractEvent>),
        crate::contract::ContractError,
    > = match call {
        PreviewCall::Plain(args) => work
            .call_args(contract_addr, method, args, gas_limit)
            .map(|(r, u, e, _)| (r, u, e)),
        PreviewCall::RawArgs(args, calldata) => work
            .call_with_context_args_calldata(
                contract_addr,
                method,
                args,
                calldata,
                gas_limit,
                &crate::contract::ContractCallContext::default(),
            )
            .map(|o| (o.result, o.fuel_used, o.events)),
        PreviewCall::Abi(args) => work
            .call_abi(contract_addr, method, args, gas_limit)
            .map(|o| (o.result, o.fuel_used, o.events)),
    };
    // Same outcome mapping as the engine's structured-call helpers.
    match exec {
        Ok((ret, used, events)) => crate::state_engine::ContractCallOutcome {
            status: "success".to_string(),
            return_value: Some(ret),
            gas_used: used,
            events,
            error: None,
        },
        Err(e) => {
            let (gas_used, msg) = match &e {
                crate::contract::ContractError::OutOfFuel => (gas_limit, e.to_string()),
                _ => (0, e.to_string()),
            };
            failed(msg, gas_used)
        }
    }
}

/// N-03: the single choke point through which the contract arms answer a
/// preview. It files the node-local receipt for the CLONE preview `outcome`
/// and renders the canonical response shape — and NOTHING else: the
/// transaction is DROPPED (never admitted to the mempool, never gossipped).
/// State changes happen exclusively when a block applies a transaction
/// submitted via `stell_sendRawTransaction`. It never touches consensus
/// state itself.
///
/// (N-03 mempool-DoS fix: the old shape admitted every preview — including
/// keyless ephemeral-vehicle txs the caller never funded — into the mempool,
/// so an unauthenticated caller could fill the pool with unexecutable
/// transactions at zero cost. Previews now return the result and drop the
/// tx; callers that want on-chain execution sign locally and submit the
/// sealed tx via `stell_sendRawTransaction`.)
async fn preview_contract_tx_and_respond(
    st: &RpcState,
    id: Value,
    tx: Transaction,
    contract_addr: [u8; 32],
    raw_tx_hex: String,
    outcome: crate::state_engine::ContractCallOutcome,
) -> Json<RpcResponse> {
    let gas_limit = tx.gas_limit;
    let tx_hash = tx.compute_tx_hash();

    // N-03: NO mempool admission, NO gossip broadcast — the preview tx is
    // dropped here. (The receipt below is a node-local preview record, not
    // an admission.)

    let is_success = outcome.status == "success";
    let events_view: Vec<Value> = outcome
        .events
        .iter()
        .map(|e| {
            json!({
                "contract": hex::encode(e.contract),
                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                "topic": e.topic,
                "value": e.value,
            })
        })
        .collect();

    // Record receipt in receipt index
    st.receipts.write().await.insert(TxReceipt {
        tx_hash,
        height: st.height.load(std::sync::atomic::Ordering::Relaxed),
        block_hash: [0u8; 32],
        index: 0,
        success: is_success,
        gas_limit,
        fee_charged: outcome.gas_used,
        raw_tx: Some(raw_tx_hex),
        return_value: outcome.return_value,
        gas_used: Some(outcome.gas_used),
        events: outcome.events.clone(),
        contract_address: Some(contract_addr),
    });

    ok(
        id,
        json!({
            "tx_hash": hex::encode(tx_hash),
            "status": outcome.status,
            "return_value": outcome.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
            "gas_used": outcome.gas_used,
            "events": events_view,
            "outcome": {
                "status": outcome.status,
                "return_value": outcome.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
                "gas_used": outcome.gas_used,
                "events": events_view,
                "error": outcome.error
            }
        }),
    )
}

/// Parse address for RPC methods, supporting TON-style workchain / shard prefixes (e.g. "-1:<addr>", "0:<addr>", "1:<addr>").
/// (crate-visible: the explorer gateway enforces the same faucet shard rule.)
///
/// The `<shard>:<addr>` FORM is parsed by [`crate::sharding::split_shard_prefix`],
/// the single source of truth of that form:
/// * `-1:` -> the masterchain (shard 0)
/// * `0:`  -> the masterchain as well (shard 0 IS the masterchain id)
/// * `N:`  -> workchain shard N, named explicitly
///
/// The returned hint is an EXPLICIT pin by the caller. It never overrides
/// the routing rule by accident: an address with no prefix is routed by the
/// rule, and the rule never returns the masterchain for a bare address.
pub(crate) fn parse_rpc_address_with_shard_hint(
    s: &str,
) -> Result<([u8; 32], Option<u32>), String> {
    let (shard, rest) = crate::sharding::split_shard_prefix(s);
    let addr = parse_rpc_address(rest)?;
    Ok((addr, shard))
}

/// Resolve an address to its shard under the node's topology, applying the
/// documented address→shard rule (see `crate::sharding::ROUTING_RULE`).
/// (crate-visible: the explorer gateway enforces the same faucet shard rule.)
///
/// `hint` is the EXPLICIT shard the caller named (`-1:` / `0:` / `N:`).
/// * `Some(0)` (the masterchain form) -> shard 0, always;
/// * `Some(n)` (an explicit workchain pin) -> shard n, as named;
/// * `None` -> the routing rule over the node's topology.
pub(crate) async fn resolve_shard_for_address(
    st: &RpcState,
    address: [u8; 32],
    hint: Option<u32>,
) -> u32 {
    match hint {
        Some(shard) => shard,
        None => {
            let topology = st.engine.shard_topology().await;
            crate::sharding::route_shard(
                &topology,
                &crate::sharding::ShardAddress::Workchain(address),
            )
        }
    }
}

/// Parse a faucet recipient and enforce the faucet's shard scope.
///
/// Returns the recipient address and the shard it lives on. The shard is the
/// documented address→shard rule ([`crate::sharding::ROUTING_RULE`]): the
/// masterchain form (`-1:<addr>` / `0:<addr>`) names shard 0, a bare address
/// routes by prefix (never the masterchain), an explicit `N:<addr>` pin names
/// shard N.
///
/// On a sharded node ([`ShardRegistry::is_sharded`]) a recipient that routes
/// to any shard OTHER than the faucet's own is an `Err`: the drip would be a
/// `source_shard != shard` transaction, which that shard's proposer drops as
/// shard-filtered, so it could sit in the mempool but never execute — while
/// holding the faucet nonce it reserved. Refusing BEFORE any nonce is
/// reserved keeps the faucet's nonce sequence (and lifetime caps) intact for
/// the next, servable drip. On a single-shard node the rule is not enforced
/// (the pre-sharding path admits and executes regardless of the tags).
///
/// (crate-visible: the explorer gateway's token and public faucet paths
/// enforce exactly this rule.)
pub(crate) async fn resolve_faucet_recipient(
    st: &RpcState,
    faucet: &Faucet,
    raw: &str,
) -> Result<([u8; 32], ShardId), String> {
    let (addr, hint) =
        parse_rpc_address_with_shard_hint(raw).map_err(|e| format!("invalid address: {e}"))?;
    let shard = resolve_shard_for_address(st, addr, hint).await;
    if st.shard_registry.is_sharded() && shard != faucet.shard() {
        return Err(format!(
            "faucet on shard {} cannot serve an address on shard {shard} \
             (a drip built for another shard would be dropped as shard-filtered \
             and could never execute); fund this address from the faucet serving \
             shard {shard}",
            faucet.shard(),
        ));
    }
    Ok((addr, shard))
}

fn parse_addr_from_val(val: Option<&Value>) -> Result<[u8; 32], String> {
    match val {
        Some(v) if v.is_string() => parse_rpc_address(v.as_str().unwrap()),
        Some(v) if v.is_array() => {
            serde_json::from_value::<[u8; 32]>(v.clone()).map_err(|e| e.to_string())
        }
        _ => Err("missing or invalid address in opcode".to_string()),
    }
}

fn parse_opcode_value(val: &Value) -> Result<crate::svm::OpCode, String> {
    if let Ok(op) = serde_json::from_value::<crate::svm::OpCode>(val.clone()) {
        return Ok(op);
    }
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            match k.as_str() {
                "SysCallTokenTransfer" | "token_transfer" => {
                    let token_id =
                        parse_addr_from_val(v.get("token_id").or_else(|| v.get("token")))?;
                    let to = parse_addr_from_val(v.get("to").or_else(|| v.get("recipient")))?;
                    let amount = v
                        .get("amount")
                        .and_then(|a| {
                            a.as_u64()
                                .or_else(|| a.as_str().and_then(|s| s.parse().ok()))
                        })
                        .unwrap_or(0);
                    return Ok(crate::svm::OpCode::SysCallTokenTransfer {
                        token_id,
                        to,
                        amount,
                    });
                }
                "SysCallCallContract" | "call_contract" => {
                    let contract =
                        parse_addr_from_val(v.get("contract").or_else(|| v.get("address")))?;
                    let method = match v.get("method") {
                        Some(m) if m.is_string() => m.as_str().unwrap().as_bytes().to_vec(),
                        Some(m) if m.is_array() => serde_json::from_value(m.clone())
                            .map_err(|e: serde_json::Error| e.to_string())?,
                        _ => return Err("missing contract method".to_string()),
                    };
                    let arg = if let Some(a) = v.get("arg").or_else(|| v.get("args")) {
                        parse_contract_call_arg(a)?
                    } else {
                        0i64
                    };
                    return Ok(crate::svm::OpCode::SysCallCallContract {
                        contract,
                        method,
                        arg,
                    });
                }
                "SysCallDeployContract" | "deploy_contract" => {
                    let code = match v.get("code") {
                        Some(c) if c.is_string() => {
                            let s = c.as_str().unwrap();
                            let s_clean = s.strip_prefix("0x").unwrap_or(s);
                            hex::decode(s_clean).map_err(|e| e.to_string())?
                        }
                        Some(c) if c.is_array() => serde_json::from_value(c.clone())
                            .map_err(|e: serde_json::Error| e.to_string())?,
                        _ => return Err("missing contract code".to_string()),
                    };
                    return Ok(crate::svm::OpCode::SysCallDeployContract { code });
                }
                _ => {}
            }
        }
    }
    Err(format!(
        "unrecognized opcode format: {}",
        snip_for_error(&format!("{val:?}"))
    ))
}

fn parse_estimate_payload(p: &Value, to_addr: [u8; 32]) -> Result<Vec<crate::svm::OpCode>, String> {
    if let Some(payload_val) = p.get("payload").or_else(|| p.get("data")) {
        if let Some(s) = payload_val.as_str() {
            if s.is_empty() || s == "0x" {
                return Ok(Vec::new());
            }
            let clean = s.strip_prefix("0x").unwrap_or(s);
            if let Ok(bytes) = hex::decode(clean) {
                if let Ok(ops) =
                    decode_wire_limited::<Vec<crate::svm::OpCode>>(&bytes, MAX_RPC_BODY as u64)
                {
                    return Ok(ops);
                }
                if let Ok(op) =
                    decode_wire_limited::<crate::svm::OpCode>(&bytes, MAX_RPC_BODY as u64)
                {
                    return Ok(vec![op]);
                }
                return Ok(vec![crate::svm::OpCode::SysCallCallContract {
                    contract: to_addr,
                    method: bytes,
                    arg: 0,
                }]);
            }
            // Audit F2: a non-hex `method` is a NAME, never code — bound it
            // (a 200KB method string is parse-level DoS before gas applies).
            if s.len() > 1024 {
                return Err(format!(
                    "method exceeds cap 1024 bytes (got {})",
                    s.len()
                ));
            }
            return Ok(vec![crate::svm::OpCode::SysCallCallContract {
                contract: to_addr,
                method: s.as_bytes().to_vec(),
                arg: 0,
            }]);
        }
        if let Some(arr) = payload_val.as_array() {
            if arr.is_empty() {
                return Ok(Vec::new());
            }
            // Audit F2: bound the opcode count pre-parse (allocation + sim
            // setup happen before the gas budget binds).
            if arr.len() > 1024 {
                return Err(format!(
                    "payload ops exceed cap 1024 (got {})",
                    arr.len()
                ));
            }
            if let Ok(ops) = serde_json::from_value::<Vec<crate::svm::OpCode>>(payload_val.clone())
            {
                return Ok(ops);
            }
            let mut ops = Vec::with_capacity(arr.len());
            for item in arr {
                ops.push(parse_opcode_value(item)?);
            }
            return Ok(ops);
        }
        if payload_val.is_object() {
            return Ok(vec![parse_opcode_value(payload_val)?]);
        }
    }

    if let Some(tok_val) = p.get("token_id").or_else(|| p.get("token")) {
        let tok_str = tok_val
            .as_str()
            .ok_or_else(|| "token_id must be a string".to_string())?;
        let token_id = parse_rpc_address(tok_str)?;
        let amount = p
            .get("amount")
            .or_else(|| p.get("value"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        return Ok(vec![crate::svm::OpCode::SysCallTokenTransfer {
            token_id,
            to: to_addr,
            amount,
        }]);
    }

    if let Some(method_val) = p.get("method") {
        // Audit F2: a `method` param is a NAME, never code — bound both
        // shapes (string bytes and byte-array) before simulation.
        let method = match method_val {
            Value::String(s) => {
                if s.len() > 1024 {
                    return Err(format!(
                        "method exceeds cap 1024 bytes (got {})",
                        s.len()
                    ));
                }
                s.as_bytes().to_vec()
            }
            Value::Array(arr) => {
                if arr.len() > 1024 {
                    return Err(format!(
                        "method bytes exceed cap 1024 (got {})",
                        arr.len()
                    ));
                }
                serde_json::from_value(method_val.clone())
                    .map_err(|e: serde_json::Error| e.to_string())?
            }
            _ => return Err("invalid method in contract call".to_string()),
        };
        let arg = if let Some(a) = p.get("arg").or_else(|| p.get("args")) {
            parse_contract_call_arg(a)?
        } else {
            0i64
        };
        return Ok(vec![crate::svm::OpCode::SysCallCallContract {
            contract: to_addr,
            method,
            arg,
        }]);
    }

    Ok(Vec::new())
}

async fn handle_estimate_fee(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
    let p = if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    };

    // The gas budget the simulation runs with. The caller's DECLARED limit
    // is not the budget (see `estimate_fee_gas_budget`): the estimate must be
    // able to discover what the call NEEDS. A caller may LOWER the budget
    // with `max_gas`; it may never raise it above the fixed ceiling.
    let requested_max_gas = match p.get("max_gas") {
        None => None,
        Some(v) => match v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
        {
            Some(n) => Some(n),
            None => {
                return err(id, -32602, "max_gas must be an unsigned integer");
            }
        },
    };
    let gas_budget = match estimate_fee_gas_budget(requested_max_gas) {
        Ok(b) => b,
        Err(e) => return err(id, -32602, e),
    };

    // 1. Raw transaction support: { "tx": <raw hex> }
    let raw_tx_opt = p.get("tx").and_then(|v| v.as_str()).or_else(|| p.as_str());

    let sim_tx = if let Some(raw_hex) = raw_tx_opt {
        let clean = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
        let bytes = match hex::decode(clean) {
            Ok(b) => b,
            Err(e) => return err(id, -32602, format!("invalid hex: {e}")),
        };
        match decode_wire_limited::<Transaction>(&bytes, MAX_RPC_BODY as u64) {
            Ok(t) => t,
            Err(_) => match crate::evm_adapter::evm_raw_to_stell_transaction(&bytes) {
                Ok(t) => t,
                Err(e) => return err(id, -32602, format!("failed to decode transaction: {e}")),
            },
        }
    } else {
        let from_str = match p
            .get("from")
            .or_else(|| p.get("sender"))
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return err(id, -32602, "missing 'from' parameter"),
        };
        let (from_addr, from_shard_hint) = match parse_rpc_address_with_shard_hint(from_str) {
            Ok(res) => res,
            Err(e) => return err(id, -32602, format!("invalid 'from' address: {e}")),
        };

        let to_str = match p
            .get("to")
            .or_else(|| p.get("recipient"))
            .or_else(|| p.get("contract"))
            .or_else(|| p.get("address"))
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return err(id, -32602, "missing 'to' parameter"),
        };
        let (to_addr, to_shard_hint) = match parse_rpc_address_with_shard_hint(to_str) {
            Ok(res) => res,
            Err(e) => return err(id, -32602, format!("invalid 'to' address: {e}")),
        };

        let amount = p
            .get("amount")
            .or_else(|| p.get("value"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);

        let source_shard = p
            .get("source_shard")
            .and_then(|v| v.as_u64().map(|n| n as u32))
            .or(from_shard_hint)
            .unwrap_or_else(|| {
                st.engine
                    .shard_id
                    .load(std::sync::atomic::Ordering::Relaxed)
            });

        // THE address→shard rule (see `crate::sharding::ROUTING_RULE`): an
        // explicit `target_shard` wins, then the shard the caller NAMED in
        // the address form (`-1:` / `N:`), and otherwise the routing rule
        // over this node's topology. One rule, one source of truth — the
        // same rule `stell_runGetMethod` and the topology itself use.
        let target_shard = match p.get("target_shard").and_then(|v| v.as_u64()) {
            Some(n) => n as u32,
            None => resolve_shard_for_address(st, to_addr, to_shard_hint).await,
        };

        let payload = match parse_estimate_payload(p, to_addr) {
            Ok(pl) => pl,
            Err(e) => return err(id, -32602, format!("invalid payload: {e}")),
        };

        Transaction {
            from: from_addr,
            to: to_addr,
            amount,
            gas_limit: 10_000_000,
            nonce: 0,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload,
            priority_fee_per_gas: 0,
        }
    };

    simulate_and_estimate_fee(st, id, sim_tx, gas_budget).await
}

async fn simulate_and_estimate_fee(
    st: &RpcState,
    id: Value,
    mut sim_tx: Transaction,
    gas_budget: u64,
) -> Json<RpcResponse> {
    let is_cross_shard = sim_tx.source_shard != sim_tx.target_shard;
    let sim_engine = st.engine.clone_for_simulation().await;

    // Consensus floor and surcharge (e.g. PQ activation or penalties)
    let (floor_base, surcharge) = sim_engine.consensus_floor_parts(&sim_tx).await;
    let pool_floor = st.mempool.read().await.base_fee;
    let base_fee = pool_floor
        .max(floor_base)
        .max(crate::svm::GAS_BASIC_TRANSFER);

    // Provide test/simulation funds for sender in case account is unfunded in simulation
    {
        let mut map = sim_engine.accounts.write().await;
        let entry = map
            .entry(sim_tx.from)
            .or_insert_with(|| AccountState::new(sim_tx.from, 0));
        if entry.balance < 100_000_000_000 {
            entry.balance = 100_000_000_000;
        }
    }
    // Also if token transfer, ensure sender has tokens in cloned engine
    for op in &sim_tx.payload {
        if let crate::svm::OpCode::SysCallTokenTransfer {
            token_id, amount, ..
        } = op
        {
            let mut tokens = sim_engine.tokens_write().await;
            if let Some(tok) = tokens.tokens.get_mut(token_id) {
                let cur = tok.balance_of(&sim_tx.from);
                if cur < *amount {
                    tok.balances
                        .insert(sim_tx.from, cur.saturating_add(*amount));
                }
            }
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let gas_consumed = if sim_tx.payload.is_empty() {
        crate::svm::GAS_BASIC_TRANSFER
    } else {
        // BOUNDED FUEL (audit W6.7): the estimate used to raise the
        // simulation's gas limit to `MAX_CONTRACT_FUEL` (50 000 000) — the
        // contract-execution ceiling — so an UNAUTHENTICATED read could burn
        // the full contract budget on every request. The estimate only needs
        // enough gas to price a normal call, so the ceiling is
        // `ESTIMATE_FEE_GAS_CEILING`; the answer for a normal transaction is
        // unchanged and a pathological payload can no longer burn the whole
        // contract ceiling per request.
        //
        // HONEST BUDGET (audit W7.2): the budget is the caller's `max_gas`
        // when it asked for one, and the FIXED ceiling otherwise. The
        // transaction's DECLARED `gas_limit` is deliberately NOT used as the
        // budget (it would answer "out of gas" instead of the requirement),
        // and the old `gas_limit.max(10_000_000).min(5_000_000)` expression is
        // gone: it could only ever evaluate to 5 000 000, so the `.max()` was
        // dead code pretending to be a caller-controllable floor.
        sim_tx.gas_limit = gas_budget;
        match sim_engine.execute_payload(&sim_tx, now).await {
            Ok((crate::svm::VmExecutionResult::Success { gas_used, .. }, _)) => gas_used,
            Ok((crate::svm::VmExecutionResult::OutOfGas, _)) => {
                return err(id, -32000, "simulation out of gas");
            }
            Ok((crate::svm::VmExecutionResult::Reverted(reason), _)) => {
                return err(id, -32000, format!("simulation reverted: {reason}"));
            }
            Err(e) => {
                return err(id, -32000, format!("simulation failed: {e}"));
            }
        }
    };

    let effective_gas = gas_consumed.max(base_fee);
    let estimated_fee = effective_gas.saturating_add(surcharge);
    let gas_limit = estimated_fee;

    ok(
        id,
        json!({
            "gas_limit": gas_limit,
            "estimated_fee": estimated_fee,
            "base_fee": base_fee,
            "source_shard": sim_tx.source_shard,
            "target_shard": sim_tx.target_shard,
            "is_cross_shard": is_cross_shard,
            // The gas budget the simulation actually ran with, and the fixed
            // ceiling it can never exceed (audit W7.2): a caller can see the
            // bound it is working under instead of guessing it.
            "gas_budget": gas_budget,
            "gas_ceiling": ESTIMATE_FEE_GAS_CEILING,
            "status": "ok"
        }),
    )
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
/// A14 chain-binding rollout, phase 1 (warn+meter): an UNBOUND (replayable,
/// no chain id) transaction is still ADMITTED, but the admission is LOUD (a
/// `tracing::warn!` with sender/nonce) and METERED
/// (`stell_unbound_tx_total`). Bound envelopes — CH1 (`is_chain_id_bound`),
/// session grants (`delegation`), PQ chain binding, EVM settlement — are
/// silent. Phase 2 flips wallets to bound-by-default; phase 3 refuses
/// unbound admission outright.
fn note_unbound_admission(tx: &Transaction) {
    if tx.chain_id().is_some() {
        return;
    }
    tracing::warn!(
        "[mempool] admitting UNBOUND (replayable, no chain id) tx from {} nonce={} gas={} — rollout phase 1: admitted + metered, will be refused in phase 3",
        hex::encode(&tx.from[..6]),
        tx.nonce,
        tx.gas_limit
    );
    crate::metrics::global().inc_unbound_tx();
}

/// A14 phase 3 (chain binding) enforcement at RPC ingress: `Some` carries the
/// stable [`crate::chain_binding::UNBOUND_REFUSED_ERR_PREFIX`] refusal the
/// wallet matches on. Call sites pass finalized-tip+1 as `next_height` (see
/// their `// GATE:` comments) and always refuse with this message verbatim —
/// no extra prefix, so the pinned string stays matchable. Default-off (the
/// activation env unset) always returns `None`.
fn chain_binding_refusal(tx: &Transaction, next_height: u64, chain_id: u64) -> Option<String> {
    crate::chain_binding::check_admission_from_env(
        tx.chain_id().is_some(),
        next_height,
        chain_id,
    )
    .err()
}

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
    let tx: Transaction = match decode_wire_limited(&bytes, MAX_RPC_BODY as u64) {
        Ok(t) => t,
        Err(e) => return err(id, -32602, format!("decode: {e}")),
    };
    // FULL-PQ (no compat): classical envelopes refused at intake, before any
    // crypto. PQ verify/admission below is unchanged.
    {
        let pq_ok = match tx.pq_envelope() {
            Some(env) => env.scheme.is_post_quantum(),
            None => false,
        };
        if !pq_ok {
            return err(
                id,
                -32000,
                "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
            );
        }
    }
    if !tx.verify_signature() {
        return err(id, -32000, "invalid transaction signature");
    }
    // A14 phase 3: refuse unbound envelopes at/after activation, with the
    // check's message verbatim. A refused tx is never admitted, so it counts
    // as refused (`stell_unbound_refused_total`), not as metered admission.
    // GATE: height is finalized-tip+1 — the earliest height this tx could be
    // included at — derived from COMMITTED `st.height`, never caller params.
    // Default-off (env unset) always passes, so phase-1 admit+meter below is
    // byte-identical.
    let next_height = st
        .height
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    if let Some(reason) = chain_binding_refusal(&tx, next_height, st.chain_id) {
        crate::metrics::global().inc_unbound_refused();
        return err(id, -32000, reason);
    }
    // A14 phase 1: unbound admission is loud + metered, never silent.
    note_unbound_admission(&tx);
    if !tx.payload.iter().any(carries) {
        return err(id, -32602, wrong_payload);
    }
    let acct = st.engine.get_account(&tx.from).await;
    let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
    let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
    // PAYMASTER: a sponsored transaction funds its fee from the sponsor, so
    // admission carries the sponsor's balance head too (fail-closed: a
    // sponsored transaction with no head is refused). Legacy transactions
    // carry no head and behave exactly as before.
    let mut actx = AdmissionCtx::wall_now().with_chain_height(next_height);
    if let Some(sbal) = st.engine.sponsor_balance_of(&tx).await {
        actx = actx.with_sponsor_balance(sbal);
    }
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
        pool.add_checked_ctx(tx.clone(), balance, actx)
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

/// Maximum number of `storage_keys` one `stell_getProof` call may ask for.
///
/// Each key is a Merkle path, and a path is up to 256 branch hashes — a
/// caller-supplied list is therefore an amplification vector unless it is
/// bounded. The cap is generous for a real query (a handful of slots) and
/// small enough that one request cannot ask for the whole state.
pub const MAX_PROOF_STORAGE_KEYS: usize = 32;

/// `stell_getProof` — Merkle inclusion/exclusion proofs against the state root.
///
/// Params: `{ "address": <hex | Stl57>, "storage_keys": [<hex>, ...], "block_height": <u64> }`.
///
/// The answer carries the account's balance and nonce, the account's Merkle
/// proof, one proof per requested storage key, and the state root the proofs
/// are anchored to.
///
/// Two properties matter here and both are the reason this is not just
/// `stell_getBalanceSpv` with extra fields:
///
///  * **Inclusion AND exclusion.** A key that is *not* in the trie gets an
///    exclusion proof, not an empty answer. "This account does not exist" is
///    a claim about the world, and it is provable against the same root as
///    "this account has this balance" — a client that can only check
///    inclusion has to take the server's word for absence, which is the trust
///    assumption an SPV client exists to remove.
///  * **The proof carries the value.** The leaf value is inside the proof
///    (not merely alongside it), so a light client recomputes the leaf hash
///    from the proof's own bytes. A server cannot pair a real balance with a
///    proof of something else.
///
/// `storage_keys` are raw 32-byte state-trie keys (hex). This chain has no
/// EVM storage trie, so there is nothing else they could mean.
async fn handle_get_proof(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
    let p = if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    };

    let addr_raw = match p
        .get("address")
        .and_then(|v| v.as_str())
        .or_else(|| p.as_str())
    {
        Some(a) => a,
        None => return err(id, -32602, "missing address"),
    };
    let address = match crate::address::parse_address(addr_raw) {
        Ok(a) => a,
        Err(e) => return err(id, -32602, format!("bad address: {e}")),
    };

    // Optional height. This node keeps no historical state, so the only
    // height it can answer for is the one it is currently serving — saying
    // so is better than serving today's proof under an old height's label.
    let cur_height = st.height.load(std::sync::atomic::Ordering::Relaxed);
    let want_height = p
        .get("block_height")
        .or_else(|| p.get("height"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            p.get("block_height")
                .or_else(|| p.get("height"))
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        u64::from_str_radix(h, 16).ok()
                    } else {
                        s.parse::<u64>().ok()
                    }
                })
        });
    if let Some(want) = want_height {
        if want != cur_height {
            return err(
                id,
                -32004,
                format!(
                    "historical state is not available on this node: it serves height {cur_height}, not {want}"
                ),
            );
        }
    }

    let storage_keys: Vec<[u8; 32]> = match p.get("storage_keys") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_PROOF_STORAGE_KEYS {
                return err(
                    id,
                    -32602,
                    format!("too many storage keys: at most {MAX_PROOF_STORAGE_KEYS} per request"),
                );
            }
            let mut out = Vec::with_capacity(arr.len());
            for k in arr {
                let s = match k.as_str() {
                    Some(s) => s,
                    None => return err(id, -32602, "storage key must be a hex string"),
                };
                match parse_hash(s) {
                    Ok(k) => out.push(k),
                    Err(e) => return err(id, -32602, format!("bad storage key: {e}")),
                }
            }
            out
        }
        Some(_) => return err(id, -32602, "storage_keys must be an array of hex strings"),
    };

    // Fold the consensus-domain digest first: it is the canonical root, and
    // the fold is a write, so it must not happen while the read lock below
    // is held.
    let _ = st.engine.get_state_root().await;
    let trie = st.engine.state_trie.read().await;
    // The root is read from the SAME trie snapshot the proofs come from, so
    // the answer can never mix a root from one state with a proof from
    // another.
    let root = trie.root_hash();

    // Account: inclusion proof when the account is in the trie, exclusion
    // proof when it is not. Both are anchored at the same root.
    let account_proof = trie
        .compressed()
        .generate_proof(&address)
        .or_else(|| trie.compressed().generate_exclusion_proof(&address));
    let (account_nodes, balance, nonce, account_exists) = match &account_proof {
        Some(p) if p.kind == crate::cpat2::ProofKind::Inclusion => {
            let (b, n) = decode_account_leaf(&p.value);
            // Fail closed: never serve a proof this node cannot verify
            // against the root it is serving. A broken proof is worse than
            // no proof, because the client would believe it.
            if !crate::cpat2::verify_proof(&root, &address, &p.value, p) {
                return err(
                    id,
                    -32000,
                    "internal error: generated account proof does not verify",
                );
            }
            (p.to_nodes(), b, n, true)
        }
        Some(p) => {
            if !crate::cpat2::verify_exclusion_proof(&root, &address, p) {
                return err(
                    id,
                    -32000,
                    "internal error: generated exclusion proof does not verify",
                );
            }
            (p.to_nodes(), 0u64, 0u64, false)
        }
        // An empty trie has nothing to prove against.
        None => (Vec::new(), 0u64, 0u64, false),
    };

    let mut storage_proofs: Vec<Value> = Vec::with_capacity(storage_keys.len());
    for k in &storage_keys {
        let proof = trie
            .compressed()
            .generate_proof(k)
            .or_else(|| trie.compressed().generate_exclusion_proof(k));
        match proof {
            Some(p) if p.kind == crate::cpat2::ProofKind::Inclusion => {
                if !crate::cpat2::verify_proof(&root, k, &p.value, &p) {
                    return err(
                        id,
                        -32000,
                        "internal error: generated storage proof does not verify",
                    );
                }
                storage_proofs.push(json!({
                    "key": hex::encode(k),
                    "value": hex::encode(&p.value),
                    "exists": true,
                    "proof": p.to_nodes(),
                }));
            }
            Some(p) => {
                if !crate::cpat2::verify_exclusion_proof(&root, k, &p) {
                    return err(
                        id,
                        -32000,
                        "internal error: generated storage exclusion proof does not verify",
                    );
                }
                storage_proofs.push(json!({
                    "key": hex::encode(k),
                    "value": Value::Null,
                    "exists": false,
                    "proof": p.to_nodes(),
                }));
            }
            None => {
                storage_proofs.push(json!({
                    "key": hex::encode(k),
                    "value": Value::Null,
                    "exists": false,
                    "proof": Vec::<String>::new(),
                }));
            }
        }
    }
    drop(trie);

    let root_hex = hex::encode(root);
    ok(
        id,
        json!({
            "address": hex::encode(address),
            "balance": balance,
            "nonce": nonce,
            "account_proof": account_nodes,
            "storage_proofs": storage_proofs,
            "state_root": root_hex,
            // Aliases: `stateRoot` matches `stell_getBalanceSpv`, `height` lets a
            // client line the answer up with the header it trusts.
            "stateRoot": root_hex,
            "height": cur_height,
            "exists": account_exists,
        }),
    )
}

/// Decode `balance` and `nonce` out of a committed account leaf.
///
/// The leaf is `balance(8, BE) || nonce(8, BE)` for a dormant account and
/// `balance(8) || nonce(8) || scheme(1) || pubkey_hash(32)` for a pinned
/// post-quantum one. A leaf too short to hold a balance is reported as
/// zeros rather than panicking: the proof still authenticates it, so the
/// honest answer is "this leaf does not carry a balance".
fn decode_account_leaf(value: &[u8]) -> (u64, u64) {
    if value.len() < 16 {
        return (0, 0);
    }
    let mut balance = [0u8; 8];
    balance.copy_from_slice(&value[..8]);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&value[8..16]);
    (u64::from_be_bytes(balance), u64::from_be_bytes(nonce))
}

/// `stell_getArchiveProof` — a per-key proof against a HISTORICAL state root.
///
/// Params: `{ "address": <hex | Stl57>, "key": <hex, optional>, "height": <u64> }`.
///
/// * `address` selects the account (parsed exactly like `stell_getProof`).
/// * `key`, when present, is the RAW 32-byte state-trie key to prove (a slot
///   from the slot model in `crate::storage`: STS balance cell, contract
///   code hash, ...). When absent the account leaf itself (`address`) is
///   proven.
/// * `height` is the historical height whose post-state is proven.
///
/// The answer is `{ "height", "state_root", "key", "value", "proof",
/// "proof_type" }` (`value` is `null` with `proof_type: "exclusion"` when
/// the key did not exist at that height). The proof verifies with
/// `cpat2::ArchiveProof::verify` — and the root is authenticated separately
/// with `stell_getHistoricalRoot`, whose QC the client checks against its
/// own validator set.
///
/// Fail closed: no durable store attached, a height above the tip, an
/// unknown height, a pruned height, or a snapshot the node cannot anchor is
/// a `-32004` error — never an empty answer, never a live-trie proof
/// relabeled as history.
async fn handle_get_archive_proof(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
    let p = if params.is_array() {
        params.get(0).unwrap_or(params)
    } else {
        params
    };

    let addr_raw = match p
        .get("address")
        .and_then(|v| v.as_str())
        .or_else(|| p.as_str())
    {
        Some(a) => a,
        None => return err(id, -32602, "missing address"),
    };
    let address = match crate::address::parse_address(addr_raw) {
        Ok(a) => a,
        Err(e) => return err(id, -32602, format!("bad address: {e}")),
    };
    let key: [u8; 32] = match p.get("key") {
        None | Some(Value::Null) => address,
        Some(Value::String(s)) => match parse_hash(s) {
            Ok(k) => k,
            Err(e) => return err(id, -32602, format!("bad key: {e}")),
        },
        Some(_) => return err(id, -32602, "key must be a hex string"),
    };
    let height = match p.get("height").and_then(|v| v.as_u64()).or_else(|| {
        p.get("height").and_then(|v| v.as_str()).and_then(|s| {
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(h, 16).ok()
            } else {
                s.parse::<u64>().ok()
            }
        })
    }) {
        Some(h) => h,
        None => return err(id, -32602, "missing height"),
    };

    let Some(store) = st.archive_store.clone() else {
        return err(
            id,
            -32004,
            "archive proofs are not available on this node (no durable store attached): \
             it cannot consult its snapshot history, so it refuses rather than proving from memory",
        );
    };
    let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
    match store.serve_archive_proof(height, &key, tip).await {
        Ok(proof) => ok(id, proof.to_json()),
        Err(e) => err(id, -32004, format!("{e:#}")),
    }
}

/// `stell_getHistoricalRoot` — the authenticated historical state root.
///
/// Params: `{ "height": <u64> }`.
///
/// The answer is `{ "height", "state_root", "anchor_height", "anchor_hash",
/// "prev_hash", "cert", "finalized": true }` where `state_root` is the
/// post-`height` state and `cert` is the precommit QC on the anchoring
/// block (`height + 1`), in the same shape as
/// `FinalizedHeaderRecord::to_json` so the client reuses one parser. The
/// client verifies the QC against its OWN validator set
/// (`Checkpoint::from_historical_root_json` + `Checkpoint::verify`) and only
/// then trusts the root — without the QC the root is just a number.
///
/// Fail closed: a height above the tip, an unknown height, or a height whose
/// anchoring body's QC was pruned is a `-32004` error. A header record alone
/// never authenticates (it carries no certificate).
async fn handle_get_historical_root(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
    let height = match params
        .get("height")
        .and_then(|v| v.as_u64())
        .or_else(|| params.as_u64())
        .or_else(|| {
            params.get("height").and_then(|v| v.as_str()).and_then(|s| {
                if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    u64::from_str_radix(h, 16).ok()
                } else {
                    s.parse::<u64>().ok()
                }
            })
        }) {
        Some(h) => h,
        None => return err(id, -32602, "missing height"),
    };

    let Some(store) = st.archive_store.clone() else {
        return err(
            id,
            -32004,
            "historical roots are not available on this node (no durable store attached)",
        );
    };
    let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
    match store.historical_root(height, tip) {
        Ok(record) => ok(
            id,
            json!({
                "height": record.height,
                "state_root": hex::encode(record.state_root),
                "stateRoot": hex::encode(record.state_root),
                "anchor_height": record.anchor_height,
                "anchor_hash": hex::encode(record.anchor_hash),
                "prev_hash": hex::encode(record.anchor_prev_hash),
                "cert": {
                    "height": record.cert.height,
                    "round": record.cert.round,
                    "kind": format!("{:?}", record.cert.kind),
                    "block_hash": record.cert.block_hash.map(hex::encode),
                    "signatures": record.cert.signatures.iter().map(|(v, s)| json!({
                        "validator": hex::encode(v),
                        "signature": hex::encode(s),
                    })).collect::<Vec<Value>>(),
                },
                "finalized": record.finalized,
            }),
        ),
        Err(e) => err(id, -32004, format!("{e:#}")),
    }
}

/// The kind of chain a shard id names: `0` is the masterchain (global state,
/// consensus), everything `>= 1` is a workchain (user state).
pub fn shard_type_of(shard_id: ShardId) -> &'static str {
    if shard_id == crate::sharding::MASTERCHAIN_SHARD {
        "masterchain"
    } else {
        "workchain"
    }
}

/// How many bits of an address's routing prefix a layout of `shards` shards
/// needs: `ceil(log2(shards))`.
///
/// One shard needs no routing at all (the pre-sharding single-chain layout),
/// two need exactly one bit (masterchain vs workchain), four need two. Integer
/// math only — no float rounding at the boundary.
pub fn routing_prefix_bits(shards: usize) -> u32 {
    let mut bits = 0u32;
    while (1usize << bits) < shards {
        bits += 1;
    }
    bits
}

/// Attach the resolved shard to a JSON-RPC result, so a client can see
/// WHICH shard the answer came from without re-deriving the rule.
///
/// `shard` is the shard the address→shard rule resolved the address to;
/// `local_shard` is the shard this node runs. `shard_is_local` is false when
/// the address belongs to another shard — the node then answers from its
/// own state only, which is the honest answer for a node that does not
/// hold that shard.
fn with_shard_info(mut value: Value, shard: u32, local_shard: u32) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("shard".to_string(), json!(shard));
        obj.insert("local_shard".to_string(), json!(local_shard));
        obj.insert("shard_is_local".to_string(), json!(shard == local_shard));
    }
    value
}

/// The shard topology this node can prove, one entry per shard it has a
/// committed head for, in ascending shard id.///
/// Two sources, in this order:
///
/// 1. the process-shared finalized-header registry (`FinalizedHeaderRegistry`),
///    which the block-application paths (finalize / adopt / walk) fill with the
///    full header of every shard this process committed. It is NEVER written
///    from gossip, RPC or DHT blobs, so a head listed here is a head this node
///    applied — the same trust basis as `stell_getStateRoot`.
/// 2. the shard THIS node's own engine runs, when the registry holds no head
///    for it (a single-shard node whose runtime has no registry attached, or a
///    node that has not finalized a block yet): its height comes from
///    `st.height`, its hash from the committed-window head, its state root
///    from the live trie.
///
/// A shard with neither source is NOT listed: an unknown shard is a miss, not
/// an entry with zeroed fields.
pub async fn collect_shard_heads(st: &RpcState) -> Vec<ShardHead> {
    use std::collections::BTreeMap;
    let mut heads: BTreeMap<ShardId, ShardHead> = BTreeMap::new();
    let local_shard = st.engine.shard_id();

    // 1. The committed heads of every shard this process finalized.
    if let Some(reg) = st.engine.finalized_headers() {
        if let Ok(reg) = reg.read() {
            let mut push = |h: &crate::sharding::ShardHeaderCommitment| {
                heads.insert(
                    h.shard_id,
                    ShardHead {
                        shard_id: h.shard_id,
                        shard_type: shard_type_of(h.shard_id).to_string(),
                        tip_height: h.height,
                        tip_hash: Some(hex::encode(h.block_hash)),
                        state_root: Some(hex::encode(h.state_root)),
                        local: h.shard_id == local_shard,
                    },
                );
            };
            if let Some(mc) = reg.latest_header(crate::sharding::MASTERCHAIN_SHARD) {
                push(mc);
            }
            for wc in reg.workchain_headers() {
                push(&wc);
            }
        }
    }

    // 2. The shard this node runs itself, when the registry has no head for it.
    if let std::collections::btree_map::Entry::Vacant(e) = heads.entry(local_shard) {
        let tip_hash = st
            .recent_blocks
            .read()
            .await
            .front()
            .map(|b| b.hash.clone());
        let state_root = hex::encode(st.engine.get_state_root().await);
        e.insert(ShardHead {
            shard_id: local_shard,
            shard_type: shard_type_of(local_shard).to_string(),
            tip_height: st.height.load(std::sync::atomic::Ordering::Relaxed),
            tip_hash,
            state_root: Some(state_root),
            local: true,
        });
    }

    heads.into_values().collect()
}

// ============================================================================
// Wallet signature standard (docs/WALLET_SIGNING.md, audit P2 item 15).
//
// `stell_signMessage` / `stell_signTypedData` sign with a SEPARATE ephemeral
// dev-only key (NEVER the validator key — see `dev_msg_signing_seed_from_env`)
// and are fail-closed: they require (a) the key to be configured (explicit
// dev mode at startup), (b) a configured `auth_token` presented by the caller
// (in `params.token` / `params.apiKey` / a header), and (c) a loopback peer
// (in-process `None` callers are the test harness). Otherwise they refuse.
// They exist for TESTING/DEVNET ONLY — a production wallet MUST sign locally
// and never ship its key to a node.
// `stell_verifyMessage` / `stell_verifyTypedData` are public (no secret, no
// auth): verification is total and side-effect free.
//
// The node signs Ed25519 only. Falcon-512/Hybrid signing is a wallet-side
// operation (see the `stellereum wallet sign` CLI); the VERIFY arms accept all
// three live schemes.
// ============================================================================

// GATE: H-02 — SIGN arms are fail-closed without a configured `auth_token`
// (unlike the mempool/payload arms which stay open in local/dev mode). A
// dev signing key must never be anonymously reachable.
fn require_wallet_sign_auth(
    st: &RpcState,
    id: &Value,
    params: &Value,
    header_token: Option<&str>,
) -> Option<Json<RpcResponse>> {
    let Some(expected) = &st.auth_token else {
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
        .map(|p| constant_time_eq(p, expected.as_str()))
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

// GATE: H-02 — SIGN arms serve loopback peers only (audit: "only on
// loopback"). `None` is the in-process test harness (production transports
// always resolve an IP); any non-loopback `Some(ip)` is refused.
fn require_wallet_sign_loopback(
    id: &Value,
    peer_ip: Option<std::net::IpAddr>,
) -> Option<Json<RpcResponse>> {
    match peer_ip {
        None => None,
        Some(ip) if ip.is_loopback() => None,
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
fn bind_addr_is_loopback(addr: &str) -> bool {
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
fn rpc_bind_is_loopback() -> bool {
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
static TEST_BIND_LOOPBACK: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

/// Test-only mock for the bind check ("mock bind"): `Some(v)` forces the
/// gate's view of the bind, `None` restores the env/default path. A mutex
/// (not the env) so parallel tests cannot disturb each other.
#[cfg(test)]
pub(crate) fn set_test_bind_loopback(v: Option<bool>) {
    *TEST_BIND_LOOPBACK.lock().unwrap() = v;
}

#[cfg(test)]
fn test_bind_loopback_override() -> Option<bool> {
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
fn require_gov_write_auth(
    st: &RpcState,
    id: &Value,
    params: &Value,
    header_token: Option<&str>,
) -> Option<Json<RpcResponse>> {
    let Some(expected) = &st.auth_token else {
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
        .map(|p| constant_time_eq(p, expected.as_str()))
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
async fn gov_write(
    st: &RpcState,
) -> tokio::sync::RwLockWriteGuard<'_, crate::governance::Governance> {
    if Arc::ptr_eq(&st.governance, &st.engine.governance_handle()) {
        st.engine.governance_write().await
    } else {
        st.governance.write().await
    }
}

/// Loopback-dev escape for UNSIGNED gov writes: ONLY when the existing
/// dev-test flag is armed (`STELL_DEV_UNSAFE_TESTKEY=1`, the same flag the
/// wallet SIGN arms and the faucet test key use) AND the bind is loopback.
/// No new env knob is introduced: without the flag, an unsigned proposal or
/// vote is refused fail-closed on every bind (including loopback).
fn gov_unsigned_dev_escape() -> bool {
    is_dev_unsafe_testkey_env() && rpc_bind_is_loopback()
}

/// Effective chain id for a wallet-signing call: explicit `chain_id` wins,
/// otherwise the node's own chain id. The preimage is ALWAYS rebuilt with this
/// value on both sign and verify, so a signature minted for one chain never
/// verifies on another.
fn wallet_sign_chain_id(st: &RpcState, params: &Value) -> Result<u64, String> {
    match params.get("chain_id") {
        None | Some(Value::Null) => Ok(st.chain_id),
        Some(v) => {
            crate::wallet_signing::parse_u64_param(v).map_err(|e| format!("bad chain_id: {e}"))
        }
    }
}

/// Parse the shared typed-data params into a [`crate::wallet_signing::TypedCallData`].
fn parse_typed_data_params(
    params: &Value,
    default_chain_id: u64,
) -> Result<crate::wallet_signing::TypedCallData, String> {
    let contract_str = params
        .get("contract")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing contract (32-byte hex)".to_string())?;
    let contract = parse_hash(contract_str).map_err(|e| format!("bad contract: {e}"))?;
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

fn handle_sign_message(
    st: &RpcState,
    id: Value,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Json<RpcResponse> {
    if let Some(denied) = require_wallet_sign_auth(st, &id, params, header_token) {
        return denied;
    }
    if let Some(denied) = require_wallet_sign_loopback(&id, peer_ip) {
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
    let key = crate::wallet_signing::WalletSigningKey::ed25519(seed);
    let sig = match key.sign_message(chain_id, &message) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, e),
    };
    ok(
        id,
        json!({
            "address": hex::encode(key.address()),
            "scheme": "Ed25519",
            "scheme_id": sig.scheme.id(),
            "signature": sig.to_hex(),
            "preimage": hex::encode(crate::wallet_signing::message_preimage(chain_id, &message)),
            "chain_id": chain_id,
        }),
    )
}

fn handle_verify_message(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
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

fn handle_sign_typed_data(
    st: &RpcState,
    id: Value,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Json<RpcResponse> {
    if let Some(denied) = require_wallet_sign_auth(st, &id, params, header_token) {
        return denied;
    }
    if let Some(denied) = require_wallet_sign_loopback(&id, peer_ip) {
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
    let key = crate::wallet_signing::WalletSigningKey::ed25519(seed);
    let (sig, canonical) = match key.sign_typed_data(&data) {
        Ok(r) => r,
        Err(e) => return err(id, -32602, e),
    };
    let chain_id = data.chain_id_u64().unwrap_or(st.chain_id);
    ok(
        id,
        json!({
            "address": hex::encode(key.address()),
            "scheme": "Ed25519",
            "scheme_id": sig.scheme.id(),
            "signature": sig.to_hex(),
            "canonical": canonical,
            "chain_id": chain_id,
        }),
    )
}

fn handle_verify_typed_data(st: &RpcState, id: Value, params: &Value) -> Json<RpcResponse> {
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
            ok(
                id,
                json!(crate::evm_adapter::eth_syncing_for_heights(
                    ours,
                    fresh_peer_height()
                )),
            )
        }
        // TESTNET-KNOWN default: the mempool `base_fee` is an admission floor
        // in gas units, not a wei price — mapping it here would mix units.
        "eth_gasPrice" => ok(id, json!(crate::evm_adapter::eth_gas_price())),
        "eth_maxPriorityFeePerGas" => ok(
            id,
            json!(crate::evm_adapter::eth_max_priority_fee_per_gas()),
        ),
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
        "eth_getTransactionCount" => {
            match crate::evm_adapter::eth_get_transaction_count(&st.engine, params).await {
                Ok(cnt) => ok(id, json!(cnt)),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_blockNumber" => ok(id, json!(st.eth_block_number())),
        "eth_getBlockByNumber" => match st.handle_get_block_by_number(params).await {
            Ok(Some(b)) => ok(id, json!(b)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getBlockByHash" => match st.handle_get_block_by_hash(params).await {
            Ok(Some(b)) => ok(id, json!(b)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getTransactionReceipt" => match st.handle_get_transaction_receipt(params).await {
            Ok(Some(r)) => ok(id, json!(r)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getTransactionByHash" => match st.handle_get_transaction_by_hash(params).await {
            Ok(Some(tx)) => ok(id, json!(tx)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getBlockTransactionCountByHash" => {
            match st.handle_get_block_transaction_count_by_hash(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getBlockTransactionCountByNumber" => {
            match st
                .handle_get_block_transaction_count_by_number(params)
                .await
            {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            match st
                .handle_get_transaction_by_block_hash_and_index(params)
                .await
            {
                Ok(Some(tx)) => ok(id, json!(tx)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            match st
                .handle_get_transaction_by_block_number_and_index(params)
                .await
            {
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
        "eth_newPendingTransactionFilter" => ok(
            id,
            json!(crate::evm_adapter::eth_new_pending_transaction_filter()),
        ),
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
            // A14 phase 3: the mapped L1 leg passes the same admission gate
            // as every other submit path, with the check's message verbatim.
            // GATE: height is finalized-tip+1 from COMMITTED `st.height`,
            // never caller params. Default-off always passes.
            let next_height = st
                .height
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            if let Some(reason) = chain_binding_refusal(&stell_tx, next_height, st.chain_id) {
                crate::metrics::global().inc_unbound_refused();
                return err(id, -32000, reason);
            }
            let acct = st.engine.get_account(&stell_tx.from).await;
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            // The write guard must be released BEFORE `save_mempool_throttled`
            // (same deadlock discipline as `stell_sendRawTransaction`).
            let admitted = {
                let mut pool = st.mempool.write().await;
                // Nonce-gap fail-fast: a far-future EVM nonce would sit in the
                // pool forever behind an unreachable head.
                if let Some(gap) =
                    pool.check_nonce_gap(&stell_tx.from, stell_tx.nonce, onchain_nonce)
                {
                    tracing::warn!(
                        "[mempool] rejecting gapped EVM tx from {}: {gap}",
                        hex::encode(&stell_tx.from[..6])
                    );
                    return err(id, -32000, format!("rejected: {gap}"));
                }
                pool.add_checked_ctx(
                    stell_tx.clone(),
                    balance,
                    AdmissionCtx::wall_now().with_chain_height(next_height),
                )
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
                .map(|b| {
                    json!({
                        "height": b.height,
                        "hash": b.hash,
                        "txs": b.tx_count,
                        "timestamp": b.timestamp,
                    })
                })
                .collect();
            ok(id, json!(list))
        }
        "stell_getShards" => {
            // Shard topology (the TON `liteServer.getShards` / Near
            // `shard_layout` analogue). A wallet or an indexer asks which
            // shards exist and where each one is, instead of assuming one
            // global chain.
            //
            // `height` is optional and is a BOUND, not a selector: the shard
            // SET is a property of the network configuration, not of a
            // height, and this node keeps no per-height history of it. A
            // height at or below our tip is accepted and answered with the
            // current topology; a height ABOVE our tip is refused rather
            // than answered with a head we have not committed (never
            // fabricate a shard tip).
            let want_height = params
                .get("height")
                .and_then(|v| v.as_u64())
                .or_else(|| params.as_u64())
                .or_else(|| params.get(0).and_then(|v| v.as_u64()));
            if let Some(h) = want_height {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                if h > tip {
                    return err(
                        id,
                        -32004,
                        format!("requested height {h} is above this node's tip ({tip})"),
                    );
                }
            }
            let heads = collect_shard_heads(st).await;
            let total = heads.len();
            // The published sharding parameters and the address→shard rule,
            // read from the node's OWN topology (the single source of truth).
            let topology = st.engine.shard_topology().await;
            let parameters = topology.parameters();
            let sharding = serde_json::to_value(&parameters).unwrap_or(Value::Null);
            drop(topology);
            ok(
                id,
                json!({
                    "shards": heads,
                    "total_shards": total,
                    "routing_prefix_bits": routing_prefix_bits(total),
                    "sharding": sharding,
                }),
            )
        }
        // The full shard topology: the active shard set with their routing
        // prefixes and account counts, plus the published thresholds and the
        // parameters of the address→shard rule.
        //
        // `stell_getShards` answers "which shards have a committed head";
        // this one answers "how is the address space laid out right now".
        "stell_getShardTopology" => {
            let topology = st.engine.shard_topology().await;
            let report = topology.report();
            drop(topology);
            ok(id, serde_json::to_value(&report).unwrap_or(Value::Null))
        }
        "stell_getBlock" => {
            // Serve order: local committed window (fed by finalize AND adopt via
            // `record_adopted_block`, so any node serves adopted heights) ->
            // honest "not available yet". Never fabricated: a height outside the
            // window is a miss, not a zero-tx fabrication.
            //
            // Finalized-read cache: the summary for a finalized height is
            // immutable (any republish evicts via `record_block`), so a fresh
            // `Ok` is cached keyed by (method, height, params-hash). Errors
            // bypass: an unknown height can still arrive via replication.
            let want = params["height"].as_u64();
            if let Some(h) = want {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                if h <= tip {
                    if let Some(hit) = finalized_read_cache_get("stell_getBlock", h, params, tip) {
                        return ok(id, hit);
                    }
                }
            }
            let rb = st.recent_blocks.read().await;
            let found = rb.iter().find(|b| Some(b.height) == want);
            match found {
                Some(b) => {
                    let v = json!({
                        "height": b.height,
                        "hash": b.hash,
                        "txs": b.tx_count,
                        "timestamp": b.timestamp,
                    });
                    if let Some(h) = want {
                        let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                        finalized_read_cache_put("stell_getBlock", h, params, tip, v.clone());
                    }
                    ok(id, v)
                }
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
            let known = st
                .recent_blocks
                .read()
                .await
                .iter()
                .any(|b| b.height == want);
            if !known {
                return err(id, -32004, "block transactions not available yet (height not adopted/replicated on this node)");
            }
            // Finalized-read cache: receipts for a finalized height are filed
            // once (before the height publishes — see `record_*` ordering) and
            // any late filing evicts via `record_receipts_with_events`. Only
            // non-empty answers are cached: a cached empty list could freeze
            // the window between "height known" and "receipts filed" (a late
            // adopted body only ever ADDS receipts). Errors bypass.
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            if want <= tip {
                if let Some(hit) =
                    finalized_read_cache_get("stell_getBlockTransactions", want, params, tip)
                {
                    return ok(id, hit);
                }
            }
            let idx = st.receipts.read().await;
            let mut rows: Vec<&TxReceipt> = idx.map.values().filter(|r| r.height == want).collect();
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
            let v = json!({ "height": want, "txs": list });
            if want <= tip && !rows.is_empty() {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                finalized_read_cache_put("stell_getBlockTransactions", want, params, tip, v.clone());
            }
            ok(id, v)
        }

        // ---- epoch seal (asymmetric, threshold-sealed transactions) ----
        //
        // `stell_epochKey` is what a WALLET (or a light client) needs to
        // seal a transaction: the epoch's public key, the committee it is
        // bound to and the threshold that has to be met to unseal it. The
        // key is PUBLIC: it is what the wallet encrypts TO.
        "stell_epochKey" => {
            let pool = st.mempool.read().await;
            let manager = &pool.mev_seal;
            let Some(material) = manager.material() else {
                return err(
                    id,
                    -32010,
                    "no epoch key is available yet: the committee's key generation has not completed",
                );
            };
            let committee = manager.committee();
            let members: Vec<serde_json::Value> = committee
                .map(|c| {
                    c.members
                        .iter()
                        .map(|m| {
                            json!({
                                "validator_id": hex::encode(m.validator_id),
                                "enc_pk": hex::encode(m.enc_pk),
                                "contributor": c.is_contributor(c.index_of(&m.validator_id).unwrap_or(0)),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let contributors: Vec<u32> = committee
                .map(|c| c.contributors.clone())
                .unwrap_or_default();
            ok(
                id,
                json!({
                    "epoch": material.epoch,
                    "epoch_blocks": crate::mev_epoch::EPOCH_BLOCKS,
                    "public_key": hex::encode(material.public_key),
                    "committee_hash": hex::encode(material.committee_hash),
                    "transcript_root": hex::encode(material.transcript_root),
                    "threshold": material.threshold,
                    "committee": members,
                    "contributors": contributors,
                    // The commitment the BLOCK carries: a wallet (or a light
                    // client) checks the key it got here against the chain
                    // and refuses a key the network never committed to.
                    "commitment": hex::encode(material.commitment()),
                    "committed_by_chain": manager.committed_epoch_key.map(hex::encode),
                    "diverged": manager.epoch_key_diverged,
                    // The committee's AGREEMENT: the announcement carries the
                    // member signatures, so a client can check the quorum
                    // against the validator set and the commitment against
                    // the block.
                    "announcement_signatures": manager
                        .announcement()
                        .map(|a| a.valid_signature_count())
                        .unwrap_or(0),
                    "announcement_quorum": manager
                        .announcement()
                        .map(|a| a.has_quorum(a.threshold))
                        .unwrap_or(false),
                    "scheme": "stell-epoch-seal-v1 (ristretto255 threshold ECDH + xchacha20poly1305)",
                }),
            )
        }
        // Submit a SEALED transaction. The parameter is the hex-encoded
        // sealed envelope (the wire frame: MAGIC || bincode(envelope)); the
        // node stores the CIPHERTEXT only.
        "stell_sendSealedTransaction" => {
            let Some(hex_payload) = params["payload"]
                .as_str()
                .or_else(|| params["data"].as_str())
            else {
                return err(id, -32602, "missing payload");
            };
            let Ok(bytes) = hex::decode(hex_payload.trim_start_matches("0x")) else {
                return err(id, -32602, "payload is not valid hex");
            };
            let envelope = match crate::mev_epoch::decode_sealed_payload(&bytes) {
                Ok(e) => e,
                Err(e) => return err(id, -32602, format!("refusing the sealed transaction: {e}")),
            };
            let mut pool = st.mempool.write().await;
            match pool.add_sealed(envelope) {
                Ok(hash) => {
                    let hash_hex = hex::encode(hash);
                    // Gossip the sealed frame to the peers (the ciphertext
                    // only).
                    if let Some(gossip) = crate::consensus_net::global_tx_gossip().as_ref() {
                        if let Some(env) = pool.sealed_envelope(&hash).cloned() {
                            gossip.broadcast_sealed(&env).await;
                        }
                    }
                    ok(id, json!({ "tx_hash": hash_hex, "sealed": true }))
                }
                Err(e) => err(id, -32011, format!("sealed transaction refused: {e}")),
            }
        }
        // The sealed/plain share of the pool (the operator's view of how
        // much of the traffic takes the private path).
        "stell_mevStats" => {
            let pool = st.mempool.read().await;
            let manager = &pool.mev_seal;
            ok(
                id,
                json!({
                    "epoch": pool.sealed_epoch(),
                    "sealed": pool.sealed_count(),
                    "plain": pool.len(),
                    "sealed_share": pool.sealed_share(),
                    "unsealed": manager.unsealed,
                    "unseal_failures": manager.unseal_failures,
                    "threshold": manager.material().map(|m| m.threshold).unwrap_or(0),
                    "epoch_key": manager.public_key().map(|k| hex::encode(k.public_key)),
                    "epoch_key_commitment": manager.epoch_commitment().map(hex::encode),
                    "committed_epoch_key": manager.committed_epoch_key.map(hex::encode),
                    "diverged": manager.epoch_key_diverged,
                }),
            )
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
            if !provided
                .map(|p| constant_time_eq(p, expected))
                .unwrap_or(false)
            {
                return err(id, -32001, "unauthorized: missing or invalid faucet token");
            }
            // A zero drip is meaningless but would still burn a faucet nonce,
            // IP-budget quota and a mempool slot. Refuse it before anything
            // is reserved or counted.
            if params["amount"].as_u64() == Some(0) {
                return err(id, -32602, "invalid amount: must be a positive integer");
            }
            let addr = match params["address"].as_str().or_else(|| params.as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            // Shard scope BEFORE any nonce is reserved: a recipient that
            // routes to another shard is refused here (not queued), so the
            // refusal burns no nonce and touches no lifetime cap — the next
            // servable drip keeps the exact nonce it would have had.
            // Address validation also runs BEFORE the per-IP throttle below:
            // validation is free, quota is not — malformed requests must
            // never consume budget (same order as the public faucet path).
            let (a, drip_shard) = match resolve_faucet_recipient(st, &faucet, addr).await {
                Ok(v) => v,
                Err(e) => {
                    if e.starts_with("invalid address") {
                        return err(id, -32602, e);
                    }
                    return err(id, -32000, e);
                }
            };
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
            let tx_hash = match st.mempool.write().await.add_checked_ctx(
                tx.clone(),
                balance,
                AdmissionCtx::wall_now(),
            ) {
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
            ok(
                id,
                json!({
                    "credited_nano": amount.to_string(),
                    "recipient": hex::encode(a),
                    "tx_hash": hex::encode(tx_hash),
                    "shard": drip_shard,
                }),
            )
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
            ok(
                id,
                json!({
                    "address": hex::encode(a),
                    "balance": balance.to_string(),
                    "nonce": nonce,
                    "stateRoot": root_hex,
                    "state_root": root_hex,
                    "leafData": leaf_data,
                    "leaf_data": leaf_data,
                    "proof": proof,
                }),
            )
        }
        // Merkle inclusion/exclusion proofs for an account and any number of
        // state-trie keys, anchored at the state root.
        "stell_getProof" => handle_get_proof(st, id, params).await,

        // ---- archive proofs: history, not the live trie ----
        //
        // `stell_getProof` answers for the CURRENT state only. These two arms
        // answer for HISTORY: a per-key proof rebuilt from the persisted
        // snapshot history, and the quorum-certified root that makes the
        // proof worth anything. Both fail closed (unknown / pruned /
        // above-tip heights are errors, never empty answers).
        "stell_getArchiveProof" => handle_get_archive_proof(st, id, params).await,
        "stell_getHistoricalRoot" => handle_get_historical_root(st, id, params).await,

        // ---- light client: the quorum-certified chain (audit W8.3) ----
        //
        // A light client needs the HEADER (with its precommit quorum
        // certificate) to make a served proof meaningful: the root a proof
        // authenticates against is only trustworthy if a QUORUM committed to
        // it, and the only evidence of that is the certificate on the header
        // that commits to it.
        //
        // The chain's convention: a header commits to the state BEFORE its own
        // block, so the header at height H commits to the state at H-1. The
        // node's live proofs are served against the CURRENT state, so the
        // header that commits to them is the one at height+1 — which is why
        // the CLI anchors a served proof with the header at `h+1`.
        "stell_getFinalizedHeader" => {
            let want = match params["height"].as_u64().or_else(|| params.as_u64()) {
                Some(h) => h,
                None => return err(id, -32602, "missing height"),
            };
            // Finalized-read cache: a quorum-certified header is immutable (any
            // republish evicts via `record_finalized_header`). Errors bypass:
            // a pruned/too-old height stays an honest miss.
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            if want <= tip {
                if let Some(hit) =
                    finalized_read_cache_get("stell_getFinalizedHeader", want, params, tip)
                {
                    return ok(id, hit);
                }
            }
            let store = finalized_headers();
            let hs = store.read().await;
            match hs.iter().find(|h| h.height == want) {
                Some(h) => {
                    let v = h.to_json();
                    if want <= tip {
                        let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                        finalized_read_cache_put(
                            "stell_getFinalizedHeader",
                            want,
                            params,
                            tip,
                            v.clone(),
                        );
                    }
                    ok(id, v)
                }
                None => err(
                    id,
                    -32004,
                    format!(
                        "finalized header at height {want} is not available on this node \
                         (it keeps the most recent {MAX_FINALIZED_HEADERS})"
                    ),
                ),
            }
        }
        // The node's LIGHT CLIENT anchor: the newest finalized header this
        // node has, with the quorum certificate that decided it. A client
        // that verifies this certificate against its own validator set has a
        // TRUSTED root — and the anchor is what it re-anchors on.
        "stell_getFinalizedCheckpoint" => {
            let store = finalized_headers();
            let hs = store.read().await;
            match hs.front() {
                Some(h) => ok(
                    id,
                    json!({
                        "height": h.height,
                        "block_hash": hex::encode(h.block_hash),
                        "prev_hash": hex::encode(h.prev_hash),
                        // The state root this header COMMITS TO (the state as
                        // of height-1 — see the chain convention above).
                        "state_root": hex::encode(h.state_root),
                        "proposer": hex::encode(h.proposer),
                        "timestamp": h.timestamp,
                        "cert": serde_json::to_value(&h.cert).unwrap_or(Value::Null),
                        // The node's own light-client view, for reference.
                        "trusted_root": hex::encode(h.state_root),
                        "trusted_height": h.height,
                    }),
                ),
                None => err(
                    id,
                    -32004,
                    "this node has not finalized a quorum-certified header yet",
                ),
            }
        }
        // The epoch MMR root (V5 Tier-2): the Merkle-Mountain-Range root over
        // one epoch's 128 finalized block hashes.
        //
        // `stell_getEpochRoot { epoch }` (or `{ height }`, which selects the
        // epoch containing that height, or a bare number, read as an epoch)
        // answers:
        //
        // ```json
        // { "epoch": 3, "start_height": 384, "end_height": 511,
        //   "mmr_root": "<hex>", "peaks": ["<hex>", ...],
        //   "complete": true, "leaves": 128,
        //   "committed_root": "<hex>|null", "committed_in_height": 512|null }
        // ```
        //
        // The root and peaks are RECOMPUTED here from this node's finalized
        // headers — they are only as trustworthy as this node. A light client
        // must check `mmr_root` against the quorum-signed commitment carried
        // by the first masterchain block of the NEXT epoch
        // (`Block::mmr_epoch_root`, served as `mmr_epoch_root` by
        // `stell_getFinalizedHeader` at `end_height + 1` and reported here as
        // `committed_root` when this node knows that header), and verify the
        // boundary block's QC against its OWN validator set first
        // (`light_client::verify_mmr_inclusion` does the proof half of this).
        //
        // `complete` is false while the epoch is still finalizing (or when
        // this node is missing heights): the root then covers only `leaves`
        // hashes and is NOT the epoch root. An epoch with no known heights
        // at all is refused with `-32004`, never fabricated.
        "stell_getEpochRoot" => {
            let epoch = match params
                .get("epoch")
                .and_then(|v| v.as_u64())
                .or_else(|| params.as_u64())
            {
                Some(e) => e,
                None => match params
                    .get("height")
                    .and_then(|v| v.as_u64())
                    .or_else(|| params.get(0).and_then(|v| v.as_u64()))
                {
                    Some(h) => crate::mmr::epoch_of_height(h),
                    None => return err(id, -32602, "missing epoch or height"),
                },
            };
            let start = crate::mmr::epoch_start(epoch);
            let end = crate::mmr::epoch_end(epoch);
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            // Finalized-read cache: a COMPLETE epoch with its quorum-signed
            // boundary commitment is immutable (any new header evicts all
            // epoch roots via `record_finalized_header`). Incomplete epochs
            // still finalize and errors can resolve, so only
            // complete-with-commitment answers are cached. Key height is the
            // epoch start (params-hash pins the exact request shape).
            if let Some(hit) = finalized_read_cache_get("stell_getEpochRoot", start, params, tip) {
                return ok(id, hit);
            }
            let store = finalized_headers();
            let hs = store.read().await;
            // The finalized block hashes of the epoch, in height order.
            let mut leaves: Vec<[u8; 32]> = Vec::new();
            for h in start..=end {
                if let Some(rec) = hs.iter().find(|r| r.height == h) {
                    leaves.push(rec.block_hash);
                }
            }
            if leaves.is_empty() {
                return err(
                    id,
                    -32004,
                    format!(
                        "epoch {epoch} (heights {start}..={end}) is not available on this node \
                         (it keeps the most recent {MAX_FINALIZED_HEADERS} finalized headers)"
                    ),
                );
            }
            let complete = leaves.len() == crate::mmr::MMR_EPOCH_BLOCKS as usize && tip >= end;
            let (root, peaks) = crate::mmr::mmr_root_for_leaves(&leaves);
            // The quorum-signed commitment, when this node knows the header
            // that carries it (the first block of the next epoch).
            let committed = hs.iter().find(|r| r.height == end + 1);
            let committed_root = committed.map(|r| hex::encode(r.mmr_epoch_root));
            let v = json!({
                    "epoch": epoch,
                    "start_height": start,
                    "end_height": end,
                    "mmr_root": hex::encode(root),
                    "peaks": peaks.iter().map(hex::encode).collect::<Vec<_>>(),
                    "complete": complete,
                    "leaves": leaves.len(),
                    "committed_root": committed_root,
                    "committed_in_height": committed.map(|r| r.height),
                });
            if complete && committed.is_some() {
                let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
                finalized_read_cache_put("stell_getEpochRoot", start, params, tip, v.clone());
            }
            ok(id, v)
        }

        // ---- bridge disputes (optimistic L1; read-only for watchers) ----
        "stell_bridgeDeposit" => {
            // Deposit acceptance record by source-chain tx hash: recipient,
            // amount, admission path (quorum vs evidence), age, disputed flag.
            // No record (pre-dispute deposits) = unchallengeable, not missing.
            //
            // NAME (audit W7.2): this arm is the CANONICAL `stell_bridgeDeposit`
            // — the RECORD read. The native namespace's PREPARE of the same
            // deposit is `stell_bridgeDepositPrepare` (a different method
            // name), so the two can never shadow each other: the prepare arm
            // is reachable over JSON-RPC, and this one keeps its meaning.
            //
            // The guard below makes the split FAIL-CLOSED for a caller that
            // sends the PREPARE's parameters here: the read ignores unknown
            // parameters, so without it a prepare-shaped call would answer
            // `{"found": false}` — a plausible-looking answer for a deposit
            // that was never claimed. Refusing is the honest answer.
            const PREPARE_ONLY_PARAMS: &[&str] = &["chain", "recipient", "amount"];
            let prepare_shaped: Vec<&str> = PREPARE_ONLY_PARAMS
                .iter()
                .copied()
                .filter(|k| params.get(*k).is_some())
                .collect();
            if !prepare_shaped.is_empty() {
                return err(
                    id,
                    -32602,
                    format!(
                        "stell_bridgeDeposit is the deposit RECORD read; the parameters {} belong to the prepare method stell_bridgeDepositPrepare",
                        prepare_shaped.join(", ")
                    ),
                );
            }
            let h = match params
                .as_str()
                .or_else(|| params["source_tx_hash"].as_str())
            {
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
                Some(r) => ok(
                    id,
                    json!({
                        "found": true,
                        "recipient": hex::encode(r.recipient),
                        "amount": r.amount.to_string(),
                        "chain": format!("{:?}", r.chain),
                        "via_quorum": r.via_quorum,
                        "deposited_at": r.deposited_at,
                        "disputed": r.disputed,
                    }),
                ),
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
                Some(d) => ok(
                    id,
                    json!({
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
                    }),
                ),
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
            ok(
                id,
                json!(st
                    .engine
                    .token_total_supply(&token)
                    .await
                    .unwrap_or(0)
                    .to_string()),
            )
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
                    ok(
                        id,
                        json!({
                            "balance": bal.to_string(),
                            "stateRoot": hex::encode(root),
                            "key": key,
                            "proof": proof,
                        }),
                    )
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
            let ids: Vec<String> = tokens
                .tokens
                .keys()
                .skip(offset)
                .take(limit)
                .map(hex::encode)
                .collect();
            ok(
                id,
                json!({ "tokens": ids, "total": total, "offset": offset }),
            )
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
                    // E1 confirmations rule: depth of the inclusion block
                    // under the node's current finalized head, inclusion
                    // block included (1 at finality — single-block BFT
                    // finality means finality already holds there; depth
                    // buys operational assurance, never safety — see the
                    // "Confirmations" tiers in RPC.md).
                    let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
                    let confirmations = head.saturating_sub(r.height).saturating_add(1);
                    let mut obj = json!({
                        "tx_hash": hex::encode(r.tx_hash),
                        "height": r.height,
                        "block_hash": hex::encode(r.block_hash),
                        "index": r.index,
                        "status": if r.success { "success" } else { "failed" },
                        "gas_limit": r.gas_limit.to_string(),
                        "fee_charged": r.fee_charged.to_string(),
                        "confirmations": confirmations,
                    });
                    if let Some(ref raw) = r.raw_tx {
                        obj["raw_tx"] = json!(raw);
                    }
                    if let Some(ref addr) = r.contract_address {
                        obj["contract_address"] = json!(hex::encode(addr));
                        obj["contract_address_stl57"] =
                            json!(crate::address::encode_stl57_address(addr));
                    }
                    if r.return_value.is_some() || r.gas_used.is_some() {
                        obj["return_value"] = match r.return_value {
                            Some(val) => json!(val),
                            None => Value::Null,
                        };
                        obj["gas_used"] = json!(r.gas_used.unwrap_or(0));
                    }
                    let events_view: Vec<Value> = r
                        .events
                        .iter()
                        .map(|e| {
                            json!({
                                "contract": hex::encode(e.contract),
                                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                                "topic": e.topic,
                                "value": e.value,
                            })
                        })
                        .collect();
                    obj["events"] = json!(events_view);
                    ok(id, obj)
                }
                None => {
                    let pending = st.mempool.read().await.contains(&h);
                    ok(
                        id,
                        json!({ "status": if pending { "pending" } else { "unknown" } }),
                    )
                }
            }
        }
        "stell_getEvents" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };

            let tx_hash_opt = p
                .get("tx_hash")
                .or_else(|| p.get("txHash"))
                .or_else(|| p.get("hash"))
                .and_then(|v| v.as_str())
                .or_else(|| p.as_str());

            if let Some(hash_str) = tx_hash_opt {
                let h = match parse_hash(hash_str) {
                    Ok(h) => h,
                    Err(e) => return err(id, -32602, format!("invalid tx_hash: {e}")),
                };
                let idx = st.receipts.read().await;
                if let Some(r) = idx.get(&h) {
                    let events_view: Vec<Value> = r
                        .events
                        .iter()
                        .map(|e| {
                            json!({
                                "contract": hex::encode(e.contract),
                                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                                "topic": e.topic,
                                "value": e.value,
                            })
                        })
                        .collect();
                    return ok(id, json!(events_view));
                }
                return ok(id, json!([]));
            }

            if let Some(contract_val) = p.get("contract").or_else(|| p.get("address")) {
                let contract_str = match contract_val.as_str() {
                    Some(s) => s,
                    None => return err(id, -32602, "invalid contract parameter: must be a string"),
                };
                let contract_addr = match parse_rpc_address(contract_str) {
                    Ok(a) => a,
                    Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
                };

                let parse_block_num = |val: Option<&Value>| -> Option<u64> {
                    val.and_then(|v| {
                        v.as_u64().or_else(|| {
                            v.as_str().and_then(|s| {
                                let s = s
                                    .strip_prefix("0x")
                                    .or_else(|| s.strip_prefix("0X"))
                                    .unwrap_or(s);
                                u64::from_str_radix(s, 16)
                                    .ok()
                                    .or_else(|| s.parse::<u64>().ok())
                            })
                        })
                    })
                };

                let from_block =
                    parse_block_num(p.get("from_block").or_else(|| p.get("fromBlock")))
                        .unwrap_or(0);
                let to_block = parse_block_num(p.get("to_block").or_else(|| p.get("toBlock")))
                    .unwrap_or(u64::MAX);
                // Optional answer cap. The receipt index holds up to
                // `MAX_RECEIPTS` (50 000) receipts and every receipt can carry
                // up to `MAX_CONTRACT_EVENTS` (256) events, so an unfiltered
                // contract query could answer with MILLIONS of events — an
                // unbounded response body and an unbounded JSON build on an
                // unauthenticated read. The ANSWER is capped (the response
                // shape stays the documented ARRAY), and the caller may ask
                // for a different cap with `limit`.
                let limit = p
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
                    .unwrap_or(MAX_EVENTS_RETURNED)
                    .min(MAX_EVENTS_RETURNED);

                let idx = st.receipts.read().await;
                let mut matched_receipts: Vec<&TxReceipt> = idx
                    .map
                    .values()
                    .filter(|r| r.height >= from_block && r.height <= to_block)
                    .collect();
                matched_receipts.sort_by_key(|r| (r.height, r.index));

                let mut matched_events: Vec<Value> = Vec::new();
                'scan: for r in matched_receipts {
                    for e in &r.events {
                        if e.contract == contract_addr {
                            if matched_events.len() >= limit {
                                break 'scan;
                            }
                            matched_events.push(json!({
                                "contract": hex::encode(e.contract),
                                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                                "topic": e.topic,
                                "value": e.value,
                            }));
                        }
                    }
                }
                return ok(id, json!(matched_events));
            }

            err(id, -32602, "missing 'tx_hash' or 'contract' parameter")
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
            // E1 confirmations rule (same definition as the receipt above):
            // included -> head - height + 1; mempool-pending -> 0 (accepted
            // locally, finalized nowhere); unknown -> null (this node holds
            // no verdict at all).
            let confirmations = match (height, pending) {
                (Some(tx_h), _) => {
                    let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
                    json!(head.saturating_sub(tx_h).saturating_add(1))
                }
                (None, true) => json!(0),
                (None, false) => Value::Null,
            };
            ok(
                id,
                json!({
                    "status": if pending { "pending" } else { status },
                    "height": height,
                    "confirmations": confirmations,
                }),
            )
        }
        // ---- staking ----
        // Read from the STATE ENGINE, not from a node-local copy: the validator
        // set is derived from this ledger at every height boundary, so a value
        // that existed only on this node would make it propose a different chain.
        "stell_stakeOf" => {
            let v = match params["validator"]
                .as_str()
                .and_then(|s| parse_hash(s).ok())
            {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let l = st.engine.staking_read().await;
            ok(
                id,
                json!({
                    "total": l.total_stake(&v).to_string(),
                    "self_bond": l.validators.get(&v).map(|x| x.self_bond).unwrap_or(0).to_string(),
                    "delegated": l.validators.get(&v).map(|x| x.delegated).unwrap_or(0).to_string(),
                }),
            )
        }
        // ---- validator UX (unjail / redelegate / commission schedule) ----
        // Read-only: serves the jail record and the commission schedule so
        // operators and wallets can see release heights, pending raises and
        // the delegator-exit window without touching state.
        "stell_getValidatorStatus" => {
            let v = match params["validator"]
                .as_str()
                .and_then(|s| parse_hash(s).ok())
            {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let l = st.engine.staking_read().await;
            let rec = l.validators.get(&v);
            let jail = l.jail_record(&v);
            let sched = l.commission_schedule_of(&v);
            ok(
                id,
                json!({
                    "validator": hex::encode(v),
                    "known": rec.is_some(),
                    "jailed": jail.is_some(),
                    "jailed_at_height": jail.map(|j| j.jailed_at_height),
                    "release_height": jail.map(|j| j.release_height),
                    "in_set": l.to_validator_set().validators.contains_key(&v),
                    "self_bond": rec.map(|r| r.self_bond.to_string()),
                    "commission_bps": rec.map(|r| r.commission_bps),
                    "pending_commission": sched.and_then(|s| s.pending.map(|p| json!({
                        "new_bps": p.new_bps,
                        "announced_height": p.announced_height,
                        "effective_height": p.effective_height,
                    }))),
                    "last_commission_change_height": sched.and_then(|s| s.last_effective_height),
                }),
            )
        }
        // ---- zkML capability statement (audit W8.3 / blocker A5) ----
        //
        // The zkML opcodes are a sound RE-EXECUTION attestation, NOT a
        // zero-knowledge proof system. An integrator must be able to learn
        // that from DATA instead of from a marketing name, so the chain
        // states it: every flag is the conservative truth, and the per-opcode
        // detail says what each one really does.
        "stell_zkmlCapabilities" => ok(
            id,
            serde_json::to_value(crate::zkml::zkml_capabilities()).unwrap_or_else(
                |e| json!({ "error": format!("capability statement unavailable: {e}") }),
            ),
        ),

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
            ok(
                id,
                json!({ "validators": list, "total_power": vs.total_power().to_string(), "quorum": vs.quorum_power().to_string(), "fragile": fragility.is_some(), "fragile_reason": fragility }),
            )
        }

        // ---- PQ registry visibility (rotation story) ----
        // Read-only projections of the on-chain PQ key registry for wallets,
        // explorers and rotation watchers: the authoritative key AT a height
        // plus the pending rotation, and the registry-level constants. Mirrors
        // the `stell_getValidatorStatus` idiom: public read (no `auth_token`
        // gate) over the state engine's staking ledger + the process-wide
        // registry view ([`pq_registry_handle`]). Cheap BTreeMap lookups with
        // a small bounded hex encoding, so these ride the standard per-IP
        // standalone limiter like every other cheap read — NOT the
        // expensive-read family (no new budget, no new env knob). Fail-closed:
        // unknown validator, a height outside every validity window, or a
        // height above this node's tip is a JSON-RPC error, never fabricated
        // data. No state mutation on any path (registry `.read()` only).
        "stell_getPqKey" => {
            let v = match params["validator"]
                .as_str()
                .and_then(|s| parse_hash(s).ok())
            {
                Some(v) => v,
                None => return err(id, -32602, "missing validator"),
            };
            let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
            let h = match params.get("height") {
                None | Some(Value::Null) => tip,
                Some(hv) => match hv.as_u64() {
                    Some(h) => h,
                    None => {
                        return err(id, -32602, "invalid height (must be an unsigned integer)")
                    }
                },
            };
            if h > tip {
                return err(
                    id,
                    -32004,
                    format!(
                        "height {h} is above this node's tip ({tip}): no future keys, refusing"
                    ),
                );
            }
            let ledger = st.engine.staking_read().await;
            let reg = pq_registry_handle().read().await;
            // Membership-gated height-indexed read (the same `pq_active_key`
            // the consensus verification paths use): unknown validator or a
            // height outside every validity window is `None` → error.
            let Some((scheme, pubkey)) = ledger.pq_active_key(&reg, &v, h) else {
                return err(
                    id,
                    -32004,
                    "unknown validator or no PQ key at that height: refusing",
                );
            };
            // `pq_active_key` delegates to the record, so it must exist; a
            // missing record here is an internal inconsistency, still refused
            // fail-closed (never fabricate the metadata around a real key).
            let Some(rec) = reg.record_of(&v) else {
                return err(
                    id,
                    -32004,
                    "unknown validator or no PQ key at that height: refusing",
                );
            };
            ok(
                id,
                json!({
                    "validator": hex::encode(v),
                    "scheme": scheme.name(),
                    "scheme_id": scheme.id(),
                    "pubkey_hex": hex::encode(&pubkey),
                    "activated_at": rec.activated_at,
                    "pending": rec.pending.as_ref().map(|p| json!({
                        "scheme": p.scheme.name(),
                        "scheme_id": p.scheme.id(),
                        "pubkey_hex": hex::encode(&p.pubkey),
                        "announced_height": p.announced_height,
                        "effective_height": p.effective_height,
                    })),
                }),
            )
        }
        "stell_getPqRegistryStatus" => {
            let reg = pq_registry_handle().read().await;
            ok(
                id,
                json!({
                    "count": reg.len(),
                    "delay_heights": crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS,
                    "history_limit": crate::pq_registry::PQ_KEY_HISTORY_LIMIT,
                }),
            )
        }

        // ---- governance ----
        "stell_proposal" => {
            let pid = match params["id"].as_u64().or_else(|| params.as_u64()) {
                Some(p) => p,
                None => {
                    return err(
                        id,
                        -32602,
                        "missing or invalid proposal id (must be an unsigned integer)",
                    )
                }
            };
            let g = st.governance.read().await;
            match g.get(pid) {
                Some(p) => ok(
                    id,
                    json!({
                        "id": p.id,
                        "title": p.title,
                        "action": format!("{:?}", p.action),
                        // The CANONICAL action string of the proposal (the same
                        // `type` `stell_submitProposal` accepts) — audit W7.2.
                        "action_type": p.action.action_type(),
                        "status": format!("{:?}", p.status),
                        "voting_end": p.voting_end,
                        "yes": p.yes.to_string(),
                        "no": p.no.to_string(),
                        "abstain": p.abstain.to_string(),
                        "turnout": p.turnout().to_string(),
                    }),
                ),
                None => err(id, -32004, "proposal not found"),
            }
        }
        "stell_listProposals" => {
            let g = st.governance.read().await;
            let mut list: Vec<serde_json::Value> = g
                .proposals
                .values()
                .map(|p| {
                    json!({
                        "id": p.id,
                        "title": p.title,
                        "action": format!("{:?}", p.action),
                        "action_type": p.action.action_type(),
                        "status": format!("{:?}", p.status),
                        "voting_end": p.voting_end,
                        "turnout": p.turnout().to_string(),
                        "yes": p.yes.to_string(),
                        "no": p.no.to_string(),
                        "abstain": p.abstain.to_string(),
                    })
                })
                .collect();
            list.sort_by_key(|p| p["id"].as_u64().unwrap_or(0));
            ok(id, json!(list))
        }
        "stell_governanceParams" => {
            let g = st.governance.read().await;
            ok(
                id,
                json!({
                    "quorum_bps": g.quorum_bps,
                    "next_id": g.next_id,
                    "applied": g.applied,
                }),
            )
        }
        "stell_submitProposal" => {
            // GATE: N-02 — token required ALWAYS, on every bind (the old
            // loopback escape is deleted; sendRawTransaction stays open).
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let title = match params["title"].as_str() {
                Some(t) => t.to_string(),
                None => return err(id, -32602, "missing proposal title"),
            };
            let action_type =
                match params["type"].as_str() {
                    Some(t) => t,
                    None => return err(
                        id,
                        -32602,
                        "missing action type (e.g. software_upgrade, set_min_gas_limit, signal)",
                    ),
                };
            // EXPLICIT, TYPED ACTIONS (audit W7.2): every `GovAction` variant
            // has exactly one canonical action string, and the mapping lives
            // next to the enum (`crate::governance::gov_action_from_params`).
            //
            // FAIL CLOSED: an unknown action string used to fall into a
            // catch-all arm that turned it into a `Signal` — a silent no-op
            // that made a typo look like an accepted proposal. It is now
            // refused, and the refusal names the known vocabulary.
            let action = match crate::governance::gov_action_from_params(action_type, params) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut g = gov_write(st).await;
            let mut ledger = st.engine.staking_write().await;
            // Operator-signed identity: the proposer MUST be explicit (no
            // default identity — a default would let any caller propose as
            // an address whose key they do not hold).
            let proposer = match params["proposer"].as_str().and_then(|s| parse_addr(s).ok()) {
                Some(p) => p,
                None => return err(id, -32602, "missing or invalid proposer address"),
            };
            // Unsigned legacy path: refused fail-closed unless the loopback
            // dev-test escape is armed (existing STELL_DEV_UNSAFE_TESTKEY=1
            // flag AND a loopback bind — no new knob).
            let sig_hex = params["signature"].as_str();
            if sig_hex.is_none() && gov_unsigned_dev_escape() {
                match g.propose(&mut ledger, proposer, title, action, now) {
                    Ok(pid) => return ok(id, json!({ "proposal_id": pid, "status": "Open" })),
                    Err(e) => return err(id, -32000, format!("propose failed: {e}")),
                }
            }
            let Some(sig_hex) = sig_hex else {
                return err(
                    id,
                    -32001,
                    "missing gov signature: stell_submitProposal requires an operator signature over (chain_id || proposer || title || action || nonce) verifiable against the proposer's staking key; pass 'signature' (wallet envelope hex) and 'nonce' (u64)",
                );
            };
            let nonce = match params.get("nonce") {
                Some(v) => match crate::wallet_signing::parse_u64_param(v) {
                    Ok(n) => n,
                    Err(e) => return err(id, -32602, format!("bad gov nonce: {e}")),
                },
                None => {
                    return err(
                        id,
                        -32602,
                        "missing gov nonce: pass 'nonce' (u64, fresh per proposer; consumed on success)",
                    )
                }
            };
            let sig = match crate::wallet_signing::WalletSignature::from_hex(sig_hex) {
                Ok(s) => s,
                Err(e) => return err(id, -32602, format!("bad gov signature envelope: {e}")),
            };
            if sig.claimed_address() != proposer {
                return err(
                    id,
                    -32000,
                    "gov signature wrong key: the envelope's claimed address is not the proposer",
                );
            }
            match g.propose_signed(
                &mut ledger,
                proposer,
                title,
                action,
                now,
                st.chain_id,
                nonce,
                &sig,
            ) {
                Ok(pid) => ok(id, json!({ "proposal_id": pid, "status": "Open" })),
                Err(e) => err(id, -32000, format!("propose failed: {e}")),
            }
        }
        "stell_vote" => {
            // GATE: N-02 — token required ALWAYS, on every bind (the old
            // loopback escape is deleted; sendRawTransaction stays open).
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let pid = match params["id"].as_u64() {
                Some(p) => p,
                None => return err(id, -32602, "missing proposal id"),
            };
            let voter = match params["voter"].as_str().and_then(|s| parse_addr(s).ok()) {
                Some(v) => v,
                None => return err(id, -32602, "missing or invalid voter address"),
            };
            let choice = match params["choice"]
                .as_str()
                .unwrap_or("yes")
                .to_lowercase()
                .as_str()
            {
                "yes" | "y" | "1" => crate::governance::VoteChoice::Yes,
                "no" | "n" | "0" => crate::governance::VoteChoice::No,
                _ => crate::governance::VoteChoice::Abstain,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut g = gov_write(st).await;
            let mut ledger = st.engine.staking_write().await;
            // Operator-signed identity: the envelope must verify against the
            // claimed voter STAKING key (the same key whose stake is
            // locked/voted — checked by `vote_signed` against the ledger
            // snapshot, so a stakeless signature lands on NotStaker).
            // Unsigned legacy path: refused fail-closed unless the loopback
            // dev-test escape is armed (existing STELL_DEV_UNSAFE_TESTKEY=1
            // flag AND a loopback bind — no new knob).
            let sig_hex = params["signature"].as_str();
            if sig_hex.is_none() && gov_unsigned_dev_escape() {
                match g.vote(&mut ledger, voter, pid, choice, now) {
                    Ok(weight) => {
                        return ok(
                            id,
                            json!({ "voted": true, "proposal_id": pid, "weight": weight.to_string() }),
                        )
                    }
                    Err(e) => return err(id, -32000, format!("vote failed: {e}")),
                }
            }
            let Some(sig_hex) = sig_hex else {
                return err(
                    id,
                    -32001,
                    "missing gov signature: stell_vote requires an operator signature over (chain_id || proposal_id || choice) verifiable against the voter's staking key; pass 'signature' (wallet envelope hex)",
                );
            };
            let sig = match crate::wallet_signing::WalletSignature::from_hex(sig_hex) {
                Ok(s) => s,
                Err(e) => return err(id, -32602, format!("bad gov signature envelope: {e}")),
            };
            if sig.claimed_address() != voter {
                return err(
                    id,
                    -32000,
                    "gov signature wrong key: the envelope's claimed address is not the voter",
                );
            }
            match g.vote_signed(&mut ledger, voter, pid, choice, now, st.chain_id, &sig) {
                Ok(weight) => ok(
                    id,
                    json!({ "voted": true, "proposal_id": pid, "weight": weight.to_string() }),
                ),
                Err(e) => err(id, -32000, format!("vote failed: {e}")),
            }
        }
        "stell_executeProposal" => {
            // AUTH (audit W6.7): this arm was the ONLY governance write with
            // NO token gate. It applies the action of a PASSED proposal, and
            // one of the actions is `SoftwareUpgrade` — the path that ends
            // in an `execve` of a new binary. `stell_submitProposal` and
            // `stell_vote` are gated; this one was not. Same gate, same
            // token, same constant-time comparison.
            //
            // NOTE: the gate is on the CALLER, not on the proposal: the
            // proposal still needs its quorum (the ledger decides that), and
            // "anyone may execute" (no proposer-only rule) is preserved so a
            // lost proposer key cannot brick execution — the operator's
            // token is enough.
            // GATE: N-02 — same fail-closed rule as the sibling gov
            // writes: token required ALWAYS, on every bind.
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let pid = match params["id"].as_u64() {
                Some(p) => p,
                None => return err(id, -32602, "missing proposal id"),
            };
            let executor = params["executor"]
                .as_str()
                .and_then(|s| parse_addr(s).ok())
                .unwrap_or_default();
            let mut g = gov_write(st).await;
            // Height-aware execution (KI-23): legacy unscheduled passes
            // execute immediately (unchanged); proposals scheduled by the
            // live-path `finalize_at_height` enforce pass_height + 7200
            // maturity fail-closed. `st.height` is the finalized height.
            let cur_height = st.height.load(std::sync::atomic::Ordering::Relaxed);
            match g.execute_at_height(executor, pid, cur_height) {
                Ok(applied) => ok(id, json!({ "executed": true, "applied": applied })),
                Err(e) => err(id, -32000, format!("execute failed: {:?}", e)),
            }
        }

        // ---- mempool ----
        "stell_mempoolSize" => {
            let n = st.mempool.read().await.len();
            ok(id, json!(n))
        }
        // Admission floor for wallets and harnesses: the minimum declared
        // `gas_limit` this node currently accepts into its mempool (and the
        // floor its proposer filter skips below). Read-only; refreshed from
        // max(frozen, governed) every finalized height, so a wallet asserts this
        // BEFORE blasting, not after its transactions bounce.
        "stell_baseFee" => {
            let floor = st.mempool.read().await.base_fee;
            ok(id, json!({ "base_fee": floor.to_string() }))
        }
        "stell_estimateFee" => {
            // EXPENSIVE-READ BUDGET (audit W6.7): the estimate clones the WHOLE
            // engine state and runs a full SVM execution, so it is orders of
            // magnitude more expensive than any other read. It is still
            // unauthenticated (a wallet must be able to estimate before it
            // has a token), so its rate is capped SEPARATELY and far below
            // the generic per-IP budget. Without this cap a single client
            // could keep the node cloning state at the generic limit.
            // Fail-closed attribution (audit residual): `None` (in-process
            // dispatch) used to skip the budget entirely. It now draws from
            // the static local bucket ([`LOCAL_BUCKET_IP`]) with the SAME
            // per-IP caps — throttled, never exempt.
            let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
            if !estimate_fee_budget().check(ip) {
                return err(
                    id,
                    -32000,
                    "estimate-fee budget exhausted for this IP (the simulation is expensive; retry shortly)",
                );
            }
            handle_estimate_fee(st, id, params).await
        }
        // TEMPORARY diagnostic for the empty-blocks hunt: list pending
        // (sender, nonce, hash). No signatures or amounts leave the node.
        // Gated by the deployment's `auth_token` (when configured) like the
        // signed-payload arms: pending mempool contents are non-public and
        // can aid front-running, so they must not be readable by an anonymous
        // caller. (The send paths stay OPEN — see the module docs.)
        "stell_mempoolDump" => {
            let Some(expected) = &st.auth_token else {
                return err(
                    id,
                    -32001,
                    "unauthorized: stell_mempoolDump is disabled when auth_token is not configured",
                );
            };
            let provided = params["token"]
                .as_str()
                .or_else(|| params["apiKey"].as_str())
                .or(header_token);
            if !provided
                .map(|p| constant_time_eq(p, expected))
                .unwrap_or(false)
            {
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
        // ---- wallet signature standard (docs/WALLET_SIGNING.md) ----
        // SIGN arms: fail-closed devnet-only (GATE: H-02) — separate ephemeral
        // dev key, configured `auth_token` required, loopback-only. Production
        // wallets must never use them. VERIFY arms: public, no auth
        // (verification is total and side-effect free). The node signs
        // Ed25519 only; VERIFY accepts all three live schemes (Ed25519,
        // Falcon-512, Hybrid).
        "stell_signMessage" => handle_sign_message(st, id, params, header_token, peer_ip),
        "stell_verifyMessage" => handle_verify_message(st, id, params),
        "stell_signTypedData" => handle_sign_typed_data(st, id, params, header_token, peer_ip),
        "stell_verifyTypedData" => handle_verify_typed_data(st, id, params),
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
            let tx: Transaction = match decode_wire_limited(&bytes, MAX_RPC_BODY as u64) {
                Ok(t) => t,
                Err(e) => return err(id, -32602, format!("decode: {e}")),
            };
            // FULL-PQ (no compat): classical envelopes refused at intake,
            // before any crypto. PQ verify/admission below is unchanged.
            {
                let pq_ok = match tx.pq_envelope() {
                    Some(env) => env.scheme.is_post_quantum(),
                    None => false,
                };
                if !pq_ok {
                    return err(
                        id,
                        -32000,
                        "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
                    );
                }
            }
            if !tx.verify_signature() {
                return err(id, -32000, "invalid transaction signature");
            }
            // A14 phase 3: refuse unbound envelopes at/after activation, with
            // the check's message verbatim (refused counts as refused, not as
            // metered admission).
            // GATE: height is finalized-tip+1 — the earliest height this tx
            // could be included at — derived from COMMITTED `st.height`,
            // never caller params. Default-off always passes: phase-1
            // admit+meter below is byte-identical.
            let next_height = st
                .height
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            if let Some(reason) = chain_binding_refusal(&tx, next_height, st.chain_id) {
                crate::metrics::global().inc_unbound_refused();
                return err(id, -32000, reason);
            }
            // A14 phase 1: unbound admission is loud + metered, never silent.
            note_unbound_admission(&tx);
            let acct = st.engine.get_account(&tx.from).await;
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            // PAYMASTER: carry the sponsor's balance head for sponsored
            // transactions (fail-closed without it); legacy ignores it.
            let mut actx = AdmissionCtx::wall_now().with_chain_height(next_height);
            if let Some(sbal) = st.engine.sponsor_balance_of(&tx).await {
                actx = actx.with_sponsor_balance(sbal);
            }
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
                pool.add_checked_ctx(tx.clone(), balance, actx)
            };
            match admitted {
                Ok(hash) => {
                    // Propagate verified transaction to P2P peers via gossip:
                    if let Some(bcast) = &st.tx_broadcast {
                        let _ = bcast.send(tx);
                    }
                    crate::evm_adapter::notify_pending_tx(crate::evm_adapter::stell_hash_to_evm(
                        &hash,
                    ));
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
        "stell_submitPriceFeed" => admit_signed_payload_tx(
            st,
            id,
            params,
            header_token,
            method,
            |op| matches!(op, crate::svm::OpCode::SysCallSubmitPriceFeed(feed) if feed.verify()),
            "payload does not carry a validly signed price feed",
        )
        .await,

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
            ok(
                id,
                json!({
                    "price_micro_usd": pmm.price_micro_usd(),
                    "minted_nano": pmm.minted_nano.to_string(),
                    "reserve_micro": pmm.reserve_micro.to_string(),
                    "redemption_buffer_micro": pmm.redemption_buffer_micro.to_string(),
                    "usable_reserve_micro": pmm.usable_reserve_micro().to_string(),
                    "max_redeemable_stell": pmm.max_redeemable_stell().to_string(),
                    "quote_token": quote_token.map(hex::encode),
                    "treasury": hex::encode(treasury),
                    "governed_buffer_bps": governed_buffer_bps,
                }),
            )
        }

        // ---- orderbook (read-only) ------------------------------------
        // Depth must come from the COMMITTED book, not from a fresh local one:
        // a CLI that prints a book it just made up is reporting a market that
        // does not exist on any node.
        "stell_orderBook" => {
            let pair = if params.is_null() || params.as_object().is_some_and(|o| o.is_empty()) {
                1u32
            } else {
                let raw = match params["pair"].as_u64().or_else(|| params.as_u64()) {
                    Some(p) => p,
                    None => {
                        return err(
                            id,
                            -32602,
                            "missing or invalid pair id (must be an integer)",
                        )
                    }
                };
                match u32::try_from(raw) {
                    Ok(p) => p,
                    Err(_) => {
                        return err(id, -32602, format!("pair id {raw} out of bounds for u32"))
                    }
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
            // `version` is the book's mutation sequence (placements AND
            // cancels): poll-based quoters compare it against the last read
            // and re-render only when it moved. `next_order_id` moves on
            // placement only and is kept for id assignment.
            let version = book.version;
            let next_order_id = book.next_order_id;
            ok(
                id,
                json!({
                    "pair": pair,
                    "version": version,
                    "seq": version,
                    "best_bid_micro_usd": best_bid,
                    "best_ask_micro_usd": best_ask,
                    "bid_levels": bid_levels,
                    "ask_levels": ask_levels,
                    "bids": bids,
                    "asks": asks,
                    "next_order_id": next_order_id,
                }),
            )
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
                None => ok(
                    id,
                    json!({
                        "registered": false,
                        "revoked": false,
                        "valid_until": 0,
                        "scope": 0,
                        "max_gas_spend": 0,
                        "spent": 0,
                        "remaining_gas": 0,
                        "master": "0".repeat(64),
                        "chain_id": st.chain_id,
                    }),
                ),
                Some(rec) => ok(
                    id,
                    json!({
                        "registered": true,
                        "revoked": rec.revoked,
                        "valid_until": rec.valid_until,
                        "scope": rec.scope,
                        "max_gas_spend": rec.max_gas_spend,
                        "spent": rec.gas_spent,
                        "remaining_gas": rec.max_gas_spend.saturating_sub(rec.gas_spent),
                        "master": hex::encode(rec.master),
                        "chain_id": st.chain_id,
                    }),
                ),
            }
        }

        // ---- read-only contract getter (TON runGetMethod / Near call_function) ----
        "stell_runGetMethod" => {
            let height_pin = if let Some(h) = params.get("height") {
                if h.is_null() {
                    None
                } else if let Some(u) = h.as_u64() {
                    Some(u)
                } else if let Some(s) = h.as_str() {
                    let s = s.trim();
                    if let Some(hex_part) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        match u64::from_str_radix(hex_part, 16) {
                            Ok(u) => Some(u),
                            Err(e) => {
                                return ok(
                                    id,
                                    json!({
                                        "success": false,
                                        "error": format!("invalid height parameter: {e}"),
                                        "fuel_used": 0,
                                    }),
                                );
                            }
                        }
                    } else {
                        match s.parse::<u64>() {
                            Ok(u) => Some(u),
                            Err(e) => {
                                return ok(
                                    id,
                                    json!({
                                        "success": false,
                                        "error": format!("invalid height parameter: {e}"),
                                        "fuel_used": 0,
                                    }),
                                );
                            }
                        }
                    }
                } else {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": "invalid height parameter: must be an unsigned integer or hex string",
                            "fuel_used": 0,
                        }),
                    );
                }
            } else if let Some(arr) = params.as_array() {
                if arr.len() > 3 && !arr[3].is_null() {
                    match arr[3].as_u64() {
                        Some(u) => Some(u),
                        None => {
                            return ok(
                                id,
                                json!({
                                    "success": false,
                                    "error": "invalid height parameter: must be an unsigned integer",
                                    "fuel_used": 0,
                                }),
                            );
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(pin) = height_pin {
                let current_h = st.height.load(std::sync::atomic::Ordering::Relaxed);
                if pin > current_h {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": format!("pinned block height {pin} exceeds current finalized height {current_h}"),
                            "fuel_used": 0,
                        }),
                    );
                }
            }

            let addr_val = params.get("address").or_else(|| {
                if let Some(arr) = params.as_array() {
                    if arr.len() == 1 && arr[0].is_object() {
                        arr[0].get("address")
                    } else {
                        arr.first()
                    }
                } else {
                    None
                }
            });

            let addr_str = match addr_val.and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": "missing or invalid address",
                            "fuel_used": 0,
                        }),
                    );
                }
            };

            // ONE parse of the address, in the form the RPC accepts: the
            // bare 32-byte form, or the TON-style `<shard>:<addr>` form
            // (`-1:` for the masterchain). The shard the caller NAMED is a
            // hint; the rule below is what actually resolves the shard when
            // no shard was named.
            //
            // THE address→shard rule (see `crate::sharding::ROUTING_RULE`).
            // The same rule `stell_estimateFee` and the topology itself
            // apply, so a client that asks "which shard holds this
            // contract?" gets the same answer the chain would route to.
            let (contract_addr, shard_hint) = match parse_rpc_address_with_shard_hint(addr_str) {
                Ok(v) => v,
                Err(e) => {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": e,
                            "fuel_used": 0,
                        }),
                    );
                }
            };
            let resolved_shard = resolve_shard_for_address(st, contract_addr, shard_hint).await;
            let local_shard = st
                .engine
                .shard_id
                .load(std::sync::atomic::Ordering::Relaxed);
            let _shard_is_local = resolved_shard == local_shard;

            let method_val = params.get("method").or_else(|| {
                if let Some(arr) = params.as_array() {
                    if arr.len() == 1 && arr[0].is_object() {
                        arr[0].get("method")
                    } else {
                        arr.get(1)
                    }
                } else {
                    None
                }
            });

            let method_str = match method_val.and_then(|v| v.as_str()) {
                Some(m) => m,
                None => {
                    return ok(
                        id,
                        json!({
                            "success": false,
                            "error": "missing or invalid method name",
                            "fuel_used": 0,
                        }),
                    );
                }
            };

            let args_val = params.get("args").or_else(|| {
                if let Some(arr) = params.as_array() {
                    if arr.len() == 1 && arr[0].is_object() {
                        arr[0].get("args")
                    } else {
                        arr.get(2)
                    }
                } else {
                    None
                }
            });

            let fuel_limit = params.get("fuel").and_then(|v| v.as_u64());

            // When the contract carries an ABI manifest the manifest is
            // authoritative: the method and its arguments are validated and
            // the return value is decoded with the declared type.
            let abi = st.engine.get_contract_abi(&contract_addr).await;
            if let Some(abi) = abi {
                let typed_args = match parse_abi_args(&abi, method_str, args_val) {
                    Ok(a) => a,
                    Err(e) => {
                        return ok(
                            id,
                            json!({
                                "success": false,
                                "error": e,
                                "fuel_used": 0,
                            }),
                        );
                    }
                };
                let res = st
                    .engine
                    .run_get_method_typed(&contract_addr, method_str, &typed_args, fuel_limit)
                    .await;
                return ok(
                    id,
                    with_shard_info(
                        serde_json::to_value(res).unwrap_or(Value::Null),
                        resolved_shard,
                        local_shard,
                    ),
                );
            }

            let parsed_args = match args_val {
                Some(v) => match parse_get_method_args(v) {
                    Ok(a) => a,
                    Err(e) => {
                        return ok(
                            id,
                            json!({
                                "success": false,
                                "error": e,
                                "fuel_used": 0,
                            }),
                        );
                    }
                },
                None => Vec::new(),
            };

            let res = st
                .engine
                .run_get_method(&contract_addr, method_str, &parsed_args, fuel_limit)
                .await;
            ok(
                id,
                with_shard_info(
                    serde_json::to_value(res).unwrap_or(Value::Null),
                    resolved_shard,
                    local_shard,
                ),
            )
        }

        // ---- contract deployment (TON StateInit / deterministic BLAKE3) ----
        "stell_deployContract" => {
            // N-02/N-03: this arm deploys nothing itself (preview only), but
            // it executes contract code on a clone and hands out chain
            // predictions — so it takes the same fail-closed token gate as
            // the governance writes: a valid token ALWAYS, on every bind.
            // Without a token it is refused before parsing (same refusal
            // properties as the gov arms).
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };

            // H-03/H-04: `private_key` over RPC leaks key material and
            // `from` without a key cannot be honored (the node cannot sign
            // as the caller). Both are refused fail-closed: fund and sign
            // locally (SDK `TxBuilder::contract_deploy` + `sign`, or the
            // wallet) and submit the sealed transaction via the `tx` form.
            if p.get("private_key").is_some() {
                return err(
                    id,
                    -32602,
                    "private_key is no longer accepted: sign the deploy transaction locally and submit it via the `tx` form",
                );
            }
            if p.get("from").is_some() {
                return err(
                    id,
                    -32602,
                    "`from` is no longer accepted: the transaction signer (tx.from) is the deploy creator; sign locally and submit via the `tx` form",
                );
            }

            // Check if wrapped in signed raw tx wrapper
            if let Some(raw_tx_str) = p.get("tx").and_then(|v| v.as_str()) {
                let raw_bytes =
                    match hex::decode(raw_tx_str.strip_prefix("0x").unwrap_or(raw_tx_str)) {
                        Ok(b) => b,
                        Err(e) => return err(id, -32602, format!("invalid raw tx hex: {e}")),
                    };
                let tx: Transaction =
                    match decode_wire_limited(&raw_bytes, MAX_RPC_BODY as u64) {
                    Ok(t) => t,
                    Err(e) => return err(id, -32602, format!("failed to decode transaction: {e}")),
                };
                // P5 FIX: the wrapped path admitted an UNSIGNED tx straight
                // into the engine + mempool (no verify_signature). A forged
                // `from` deploys as the victim. Verify like sendRawTransaction.
                // FULL-PQ: classical envelopes refused at intake, before crypto.
                {
                    let pq_ok = match tx.pq_envelope() {
                        Some(env) => env.scheme.is_post_quantum(),
                        None => false,
                    };
                    if !pq_ok {
                        return err(
                            id,
                            -32000,
                            "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
                        );
                    }
                }
                if !tx.verify_signature() {
                    return err(id, -32000, "invalid transaction signature");
                }
                let deploy_code = tx.payload.iter().find_map(|op| {
                    if let crate::svm::OpCode::SysCallDeployContract { code } = op {
                        Some(code.clone())
                    } else {
                        None
                    }
                });
                let code = match deploy_code {
                    Some(c) => c,
                    None => {
                        return err(
                            id,
                            -32602,
                            "transaction does not contain SysCallDeployContract payload",
                        )
                    }
                };
                // H-04: validate read-only. The contract is NOT deployed here:
                // this arm only previews the signed tx (state changes
                // exclusively when a block applies a tx submitted via
                // `stell_sendRawTransaction` — N-03: this preview is NOT
                // admitted to the mempool, NOT gossipped; the tx is dropped).
                if let Err(e) = crate::contract::ContractRegistry::validate_code(&code) {
                    return err(id, -32000, format!("deploy contract failed: {e}"));
                }
                // H-04: the `init_data`/`salt` parameter is retired. It is not
                // part of the replayable `SysCallDeployContract` payload, so
                // no block-applied transaction could ever observe it; keeping
                // it would promise an address determinism the chain cannot
                // deliver (the old BLAKE3(code_hash || salt) address was a
                // phantom the block path never recreated — the second half of
                // the double-deploy). The predicted address below is the
                // SDK-canonical `contract_address(tx.from, tx.nonce)`: exactly
                // what block application derives when this tx applies first
                // for its sender.
                let predicted = crate::contract::contract_address(&tx.from, tx.nonce);
                if st.engine.get_contract(&predicted).await.is_some() {
                    return err(id, -32000, "deploy contract failed: contract already exists");
                }
                let code_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&code).into();
                let predicted_stl57 = crate::address::encode_stl57_address(&predicted);
                let tx_hash = tx.compute_tx_hash();

                // N-03: the signed preview tx is DROPPED here — no mempool
                // admission, no gossip broadcast. On-chain execution needs a
                // `stell_sendRawTransaction` submission of the same sealed tx.

                let gas_cost = crate::svm::contract_deploy_gas(code.len());
                st.receipts.write().await.insert(TxReceipt {
                    tx_hash,
                    height: st.height.load(std::sync::atomic::Ordering::Relaxed),
                    block_hash: [0u8; 32],
                    index: 0,
                    success: true,
                    gas_limit: tx.gas_limit,
                    fee_charged: gas_cost,
                    raw_tx: Some(raw_tx_str.to_string()),
                    return_value: None,
                    gas_used: Some(gas_cost),
                    events: Vec::new(),
                    contract_address: Some(predicted),
                });

                return ok(
                    id,
                    json!({
                        "contract_address": hex::encode(predicted),
                        "contract_address_stl57": predicted_stl57,
                        "code_hash": hex::encode(code_hash),
                        "tx_hash": hex::encode(tx_hash),
                    }),
                );
            }

            // Direct parameters: validated + previewed, never deployed here.
            // The node signs the preview vehicle with a fresh ephemeral key
            // (it can never leak a user key — none is accepted) and predicts
            // the SDK-canonical address. State changes exclusively when a
            // block applies a tx submitted via `stell_sendRawTransaction`
            // (H-04/C-01; N-03: the preview vehicle is dropped, not admitted).
            let code_str = match p.get("code").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(id, -32602, "missing 'code' parameter"),
            };
            let code_clean = code_str.strip_prefix("0x").unwrap_or(code_str);
            let code = match hex::decode(code_clean) {
                Ok(c) => c,
                Err(e) => return err(id, -32602, format!("invalid code hex: {e}")),
            };
            if let Err(e) = crate::contract::ContractRegistry::validate_code(&code) {
                return err(id, -32000, format!("deploy contract failed: {e}"));
            }

            let gas_limit = p
                .get("gas_limit")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(crate::contract::MAX_CONTRACT_FUEL);

            // Optional typed ABI manifest: validated here (it would travel
            // inside a submitted tx's execution path at apply time, committed
            // next to the code hash by block application — never by this arm).
            if let Err(e) = parse_abi_manifest_param(p) {
                return err(id, -32602, format!("invalid abi parameter: {e}"));
            }

            // Ephemeral vehicle only: the node cannot sign as the caller (no
            // key is accepted), so the preview tx is signed by a fresh
            // random key. Its only purpose is to carry the deploy through
            // the CLONE preview; it is DROPPED afterwards (N-03: never
            // admitted, never gossipped). The predicted address is what block
            // application would derive for it.
            // FULL-PQ: the vehicle is an explicit Falcon-512 tx
            // (self-contained: verifies with no registry and no funding —
            // the preview authenticates the envelope, as with the old ed25519
            // vehicle; execution still fails closed on the unfunded balance).
            let eph_key = crate::post_quantum::FalconKeypair::generate();
            let from_addr = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &eph_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            );
            let nonce = st
                .engine
                .get_account(&from_addr)
                .await
                .map(|a| a.nonce)
                .unwrap_or(0);
            let predicted = crate::contract::contract_address(&from_addr, nonce);
            if st.engine.get_contract(&predicted).await.is_some() {
                return err(id, -32000, "deploy contract failed: contract already exists");
            }
            let predicted_stl57 = crate::address::encode_stl57_address(&predicted);
            let code_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&code).into();

            let mut tx = Transaction {
                from: from_addr,
                to: predicted,
                amount: 0,
                gas_limit,
                nonce,
                source_shard: 0,
                target_shard: 0,
                signature: Vec::new(),
                payload: vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = eph_key.sign(&msg);
            tx.signature = crate::sharding::PqSignatureEnvelope::new_explicit(
                crate::post_quantum::PqScheme::Falcon512,
                eph_key.public_key.clone(),
                sig,
            )
            .encode();
            let tx_hash = tx.compute_tx_hash();
            let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());

            // N-03: the ephemeral preview tx is DROPPED here — no mempool
            // admission, no gossip broadcast. On-chain execution needs a
            // locally-signed `stell_sendRawTransaction` submission.

            let gas_cost = crate::svm::contract_deploy_gas(code.len());
            st.receipts.write().await.insert(TxReceipt {
                tx_hash,
                height: st.height.load(std::sync::atomic::Ordering::Relaxed),
                block_hash: [0u8; 32],
                index: 0,
                success: true,
                gas_limit,
                fee_charged: gas_cost,
                raw_tx: Some(raw_tx_hex),
                return_value: None,
                gas_used: Some(gas_cost),
                events: Vec::new(),
                contract_address: Some(predicted),
            });

            ok(
                id,
                json!({
                    "contract_address": hex::encode(predicted),
                    "contract_address_stl57": predicted_stl57,
                    "code_hash": hex::encode(code_hash),
                    "tx_hash": hex::encode(tx_hash),
                }),
            )
        }
        "stell_callContract" => {
            // N-02/N-03: this arm runs the call on a CLONE of the registry
            // for a result preview and DROPS the tx (never admitted, never
            // gossipped — state changes exclusively when a block applies a
            // tx submitted via `stell_sendRawTransaction`). It takes the same
            // fail-closed token gate as the governance writes: a valid token
            // ALWAYS, on every bind.
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };

            // H-04: `private_key` over RPC leaks key material and `from`
            // without a key cannot be honored. Both are refused fail-closed:
            // sign locally (SDK `TxBuilder::contract_call` + `sign`) and
            // submit the sealed transaction via the `tx` form, or use the
            // direct parameters for a keyless preview (an ephemeral vehicle
            // carries the call through mempool/block admission).
            if p.get("private_key").is_some() {
                return err(
                    id,
                    -32602,
                    "private_key is no longer accepted: sign the call transaction locally and submit it via the `tx` form",
                );
            }
            if p.get("from").is_some() {
                return err(
                    id,
                    -32602,
                    "`from` is no longer accepted: the transaction signer (tx.from) is the caller; sign locally and submit via the `tx` form",
                );
            }

            // Signed-tx form: a sealed `SysCallCallContract` /
            // `SysCallCallContractArgs` transaction. Verified exactly like
            // `stell_sendRawTransaction`, previewed on a registry clone, and
            // DROPPED — never executed against live state, never admitted.
            if let Some(raw_tx_str) = p.get("tx").and_then(|v| v.as_str()) {
                let raw_bytes =
                    match hex::decode(raw_tx_str.strip_prefix("0x").unwrap_or(raw_tx_str)) {
                        Ok(b) => b,
                        Err(e) => return err(id, -32602, format!("invalid raw tx hex: {e}")),
                    };
                let tx: Transaction =
                    match decode_wire_limited(&raw_bytes, MAX_RPC_BODY as u64) {
                    Ok(t) => t,
                    Err(e) => return err(id, -32602, format!("failed to decode transaction: {e}")),
                };
                // FULL-PQ: classical envelopes refused at intake, before crypto.
                {
                    let pq_ok = match tx.pq_envelope() {
                        Some(env) => env.scheme.is_post_quantum(),
                        None => false,
                    };
                    if !pq_ok {
                        return err(
                            id,
                            -32000,
                            "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
                        );
                    }
                }
                if !tx.verify_signature() {
                    return err(id, -32000, "invalid transaction signature");
                }
                let mut found: Option<ExtractedCall> = None;
                for op in &tx.payload {
                    match op {
                        crate::svm::OpCode::SysCallCallContract {
                            contract,
                            method,
                            arg,
                        } => {
                            found = Some(ExtractedCall {
                                contract: *contract,
                                method: method.clone(),
                                args: vec![*arg],
                                calldata: Vec::new(),
                            });
                            break;
                        }
                        crate::svm::OpCode::SysCallCallContractArgs {
                            contract,
                            method,
                            args,
                            calldata,
                        } => {
                            found = Some(ExtractedCall {
                                contract: *contract,
                                method: method.clone(),
                                args: args.clone(),
                                calldata: calldata.clone(),
                            });
                            break;
                        }
                        _ => {}
                    }
                }
                let extracted = match found {
                    Some(f) => f,
                    None => {
                        return err(
                            id,
                            -32602,
                            "transaction does not contain SysCallCallContract payload",
                        )
                    }
                };
                let (contract_addr, method_bytes, tx_args, tx_calldata) = (
                    extracted.contract,
                    extracted.method,
                    extracted.args,
                    extracted.calldata,
                );
                let method_str = match std::str::from_utf8(&method_bytes) {
                    Ok(m) => m.to_string(),
                    Err(_) => return err(id, -32602, "invalid contract method name"),
                };
                let outcome = preview_contract_call(
                    st,
                    &contract_addr,
                    &method_str,
                    PreviewCall::RawArgs(&tx_args, &tx_calldata),
                    tx.amount,
                    &tx.from,
                    tx.gas_limit,
                )
                .await;
                let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());
                return preview_contract_tx_and_respond(
                    st,
                    id,
                    tx,
                    contract_addr,
                    raw_tx_hex,
                    outcome,
                )
                .await;
            }

            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };

            let method_str = match p.get("method").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(id, -32602, "missing 'method' parameter"),
            };

            let args_param = p.get("args").or_else(|| p.get("arg"));
            let arg = if let Some(v) = args_param {
                match parse_contract_call_arg(v) {
                    Ok(n) => n,
                    Err(e) => return err(id, -32602, format!("invalid args parameter: {e}")),
                }
            } else {
                0i64
            };

            // Multi-argument calls: every element of an argument array is one
            // parameter of the method. A missing `args` keeps the legacy
            // single-argument behaviour.
            let call_args = match args_param {
                Some(v) => match parse_contract_call_args(v) {
                    Ok(a) => a,
                    Err(e) => return err(id, -32602, format!("invalid args parameter: {e}")),
                },
                None => vec![0i64],
            };

            let value = p
                .get("value")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0);

            let gas_limit = p
                .get("gas_limit")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(crate::contract::MAX_CONTRACT_FUEL);

            // Ephemeral vehicle only (see above: no key is accepted). The
            // preview tx is signed by a fresh random key and carries the
            // call through the CLONE preview below; it is DROPPED afterwards
            // (N-03: never admitted, never gossipped).
            // FULL-PQ: explicit Falcon-512 vehicle (self-contained).
            let eph_key = crate::post_quantum::FalconKeypair::generate();
            let from_addr = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &eph_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            );

            // Execute the contract call. When the contract carries an ABI
            // manifest the manifest is authoritative: the method and its
            // arguments are validated and typed before execution.
            let abi = st.engine.get_contract_abi(&contract_addr).await;
            let typed_args = match &abi {
                Some(a) => match parse_abi_args(a, method_str, args_param) {
                    Ok(v) => Some(v),
                    Err(e) => return err(id, -32602, format!("ABI validation failed: {e}")),
                },
                None => None,
            };

            // The replayable payload of the call: the wasm arguments plus the
            // canonical ABI encoding of the arguments (the calldata blob a
            // contract reads blob parameters from). Both are derived from the
            // SAME values the execution below uses, so a node replaying the
            // transaction executes exactly the same call.
            let (payload_args, payload_calldata): (Vec<i64>, Vec<u8>) = match (&abi, &typed_args) {
                (Some(a), Some(args)) => {
                    let calldata = match a.encode_args(method_str, args) {
                        Ok(c) => c,
                        Err(e) => return err(id, -32602, format!("ABI encoding failed: {e}")),
                    };
                    let scalars = args.iter().map(|v| v.as_i64().unwrap_or(0)).collect();
                    (scalars, calldata)
                }
                _ => (call_args.clone(), Vec::new()),
            };

            // H-03: the preview runs on a registry CLONE (see
            // `preview_contract_call`): the `value` leg is simulated with
            // the same failure modes, but no account, contract, trie or
            // mailbox state moves. The previewed tx is DROPPED (N-03); only
            // a `stell_sendRawTransaction` submission can change state, when
            // a block applies it.
            let outcome = match &typed_args {
                Some(args) => {
                    preview_contract_call(
                        st,
                        &contract_addr,
                        method_str,
                        PreviewCall::Abi(args),
                        value,
                        &from_addr,
                        gas_limit,
                    )
                    .await
                }
                None => {
                    preview_contract_call(
                        st,
                        &contract_addr,
                        method_str,
                        PreviewCall::Plain(&call_args),
                        value,
                        &from_addr,
                        gas_limit,
                    )
                    .await
                }
            };

            let sender_acc = st.engine.get_account(&from_addr).await;
            let nonce = sender_acc.map(|a| a.nonce).unwrap_or(0);

            // The transaction payload carries the call: a multi-argument
            // method (or an ABI-typed call) uses the argument-carrying opcode
            // so every node replays exactly the same parameter list.
            let call_opcode = if typed_args.is_some() || payload_args.len() > 1 {
                crate::svm::OpCode::SysCallCallContractArgs {
                    contract: contract_addr,
                    method: method_str.as_bytes().to_vec(),
                    args: payload_args,
                    calldata: payload_calldata,
                }
            } else {
                crate::svm::OpCode::SysCallCallContract {
                    contract: contract_addr,
                    method: method_str.as_bytes().to_vec(),
                    arg,
                }
            };

            let mut tx = Transaction {
                from: from_addr,
                to: contract_addr,
                amount: value,
                gas_limit,
                nonce,
                source_shard: 0,
                target_shard: 0,
                signature: Vec::new(),
                payload: vec![call_opcode],
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = eph_key.sign(&msg);
            tx.signature = crate::sharding::PqSignatureEnvelope::new_explicit(
                crate::post_quantum::PqScheme::Falcon512,
                eph_key.public_key.clone(),
                sig,
            )
            .encode();
            let raw_tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());

            preview_contract_tx_and_respond(st, id, tx, contract_addr, raw_tx_hex, outcome).await
        }
        // ---- the ABI manifest of a contract (typed interface discovery) ----
        "stell_getContractAbi" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            match st.engine.get_contract_abi_json(&contract_addr).await {
                Some(json_abi) => ok(
                    id,
                    json!({
                        "contract": hex::encode(contract_addr),
                        "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                        "abi": serde_json::from_str::<Value>(&json_abi).unwrap_or(Value::Null),
                        "abi_json": json_abi,
                    }),
                ),
                None => ok(
                    id,
                    json!({
                        "contract": hex::encode(contract_addr),
                        "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                        "abi": Value::Null,
                    }),
                ),
            }
        }

        // ---- contract source verification (audit P2-15, Sourcify-style) ----
        // `stell_verifyContractSource` recompiles the claimed `.wat` source
        // with the deploy-time pipeline and compares the rebuilt bytecode
        // hash to the on-chain `code_hash`. Strictly READ-ONLY: it never
        // mutates state (in particular it never sets `source_hash` — that is
        // the signed `stell_registerContractSource` action below).
        "stell_verifyContractSource" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            let onchain = match st.engine.get_contract_code_hash(&contract_addr).await {
                Some(h) => h,
                None => return err(id, -32602, "contract not found"),
            };
            let compiler = p
                .get("compiler")
                .and_then(|v| v.as_str())
                .unwrap_or("wat2wasm-1.0");
            let flags = p
                .get("compiler_flags")
                .or_else(|| p.get("flags"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let source_opt = p.get("source").and_then(|v| v.as_str());
            let source_hex_opt = p.get("source_hex").and_then(|v| v.as_str());
            let claimed_hash_opt = p.get("source_hash").and_then(|v| v.as_str());

            // Hash-only check: no source text submitted (the indexer-fetched
            // text path submits inline instead). Answers whether the claimed
            // fingerprint is the registered one — it performs NO rebuild.
            if source_opt.is_none() && source_hex_opt.is_none() {
                match claimed_hash_opt {
                    Some(h) => {
                        let clean = h.trim().strip_prefix("0x").unwrap_or(h.trim());
                        let claimed = match hex::decode(clean) {
                            Ok(b) if b.len() == 32 => {
                                let mut a = [0u8; 32];
                                a.copy_from_slice(&b);
                                a
                            }
                            _ => return err(id, -32602, "invalid source_hash: expected 32 bytes hex"),
                        };
                        let registered = st.engine.get_contract_source_hash(&contract_addr).await;
                        let verified = registered == Some(claimed);
                        return ok(id, json!({
                            "contract": hex::encode(contract_addr),
                            "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                            "verified": verified,
                            "onchain_code_hash": hex::encode(onchain),
                            "rebuilt_code_hash": Value::Null,
                            "source_hash": hex::encode(claimed),
                            "compiler": compiler,
                            "compiler_flags": flags,
                            "reason": if verified { "ok: matches the registered source hash (no rebuild performed)" } else { "claimed source hash does not match the registered one" },
                            "registered": registered.is_some(),
                        }));
                    }
                    None => return err(id, -32602, "missing source: provide 'source' (wat text), 'source_hex', or 'source_hash'"),
                }
            }

            let source_bytes =
                match crate::contract_source::decode_source_bytes(source_opt, source_hex_opt) {
                    Ok(b) => b,
                    Err(e) => return err(id, -32602, e),
                };
            let v = crate::contract_source::verify_source_for_code_hash(
                &onchain,
                &source_bytes,
                compiler,
                flags,
            );
            let registered = st.engine.get_contract_source_hash(&contract_addr).await;
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "verified": v.verified,
                    "onchain_code_hash": v.onchain_code_hash,
                    "rebuilt_code_hash": v.rebuilt_code_hash,
                    "source_hash": v.source_hash,
                    "compiler": v.compiler,
                    "compiler_flags": v.compiler_flags,
                    "reason": v.reason,
                    "registered": registered.is_some(),
                    "registered_source_hash": registered.map(hex::encode).unwrap_or_default(),
                }),
            )
        }

        // Read the registered source fingerprint of a contract (`null` =
        // unverified). The node stores only the fingerprint, never the text;
        // the verified text lives in the indexer
        // (`GET /api/v2/contract/:address/source`).
        "stell_getContractSource" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            let onchain = match st.engine.get_contract_code_hash(&contract_addr).await {
                Some(h) => h,
                None => return err(id, -32602, "contract not found"),
            };
            let registered = st.engine.get_contract_source_hash(&contract_addr).await;
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "code_hash": hex::encode(onchain),
                    "source_hash": registered.map(hex::encode).unwrap_or_default(),
                    "verified": registered.is_some(),
                }),
            )
        }

        // Register a verified-source fingerprint. The ONLY state-changing half
        // of source verification, and it moves ONLY by an explicit,
        // creator-signed action: `signature` is the contract creator's ed25519
        // signature over `b"STELL_REGISTER_SOURCE" || contract || source_hash`.
        // Self-authenticating like `stell_sendRawTransaction` (no API token —
        // the signature IS the authority); anyone may submit, only the
        // creator's signature verifies. Call `stell_verifyContractSource`
        // first and register the `source_hash` it returns.
        "stell_registerContractSource" => {
            let p = if params.is_array() {
                params.get(0).unwrap_or(params)
            } else {
                params
            };
            let contract_str = match p
                .get("contract")
                .or_else(|| p.get("address"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return err(id, -32602, "missing 'contract' parameter"),
            };
            let contract_addr = match parse_rpc_address(contract_str) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, format!("invalid contract address: {e}")),
            };
            let hash_str = match p.get("source_hash").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(id, -32602, "missing 'source_hash' parameter"),
            };
            let clean = hash_str
                .trim()
                .strip_prefix("0x")
                .unwrap_or(hash_str.trim());
            let shash: [u8; 32] = match hex::decode(clean) {
                Ok(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => return err(id, -32602, "invalid source_hash: expected 32 bytes hex"),
            };
            let sig_str = match p.get("signature").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return err(
                    id,
                    -32602,
                    "missing 'signature' parameter: registration requires the creator's signature",
                ),
            };
            let creator = match st.engine.contracts_read().await.get(&contract_addr) {
                Some(c) => c.creator,
                None => return err(id, -32602, "contract not found"),
            };
            if let Err(e) = crate::contract_source::verify_register_signature(
                &creator,
                &contract_addr,
                &shash,
                sig_str,
            ) {
                return err(id, -32602, e);
            }
            if let Err(e) = st
                .engine
                .register_contract_source(&contract_addr, shash, creator)
                .await
            {
                return err(id, -32602, e.to_string());
            }
            ok(
                id,
                json!({
                    "contract": hex::encode(contract_addr),
                    "contract_stl57": crate::address::encode_stl57_address(&contract_addr),
                    "source_hash": hex::encode(shash),
                    "registered": true,
                    "verified": true,
                }),
            )
        }

        // Explicit receipt endpoint for contract calls (Near / TON receipt fetching)
        "stell_getContractReceipt" => {
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
                    let events_view: Vec<Value> = r
                        .events
                        .iter()
                        .map(|e| {
                            json!({
                                "contract": hex::encode(e.contract),
                                "contract_stl57": crate::address::encode_stl57_address(&e.contract),
                                "topic": e.topic,
                                "value": e.value,
                            })
                        })
                        .collect();
                    ok(
                        id,
                        json!({
                            "status": if r.success { "success" } else { "failed" },
                            "return_value": r.return_value.map(|v| json!(v)).unwrap_or(Value::Null),
                            "gas_used": r.gas_used.unwrap_or(0),
                            "events": events_view,
                            "tx_hash": hex::encode(r.tx_hash),
                        }),
                    )
                }
                None => {
                    let pending = st.mempool.read().await.contains(&h);
                    ok(
                        id,
                        json!({ "status": if pending { "pending" } else { "unknown" } }),
                    )
                }
            }
        }

        // ---- block invalidations (reorg / lost fork) ----
        // The blocks this node told the world about and then could NOT keep:
        // a candidate branch that lost the fork-choice, or a reorg that
        // rolled a branch back. None of these blocks were ever APPLIED
        // (BFT finality forbids rolling back an applied block), so the
        // signal is a "your view of these blocks is wrong" notice.
        //
        // `limit` is optional and caps how many of the most recent signals
        // are returned (0 / absent = the whole window). The window is
        // bounded, so an unbounded answer is bounded by construction.
        "stell_getInvalidations" | "stell_invalidationFeed" => {
            let limit = params
                .get("limit")
                .and_then(|v| v.as_u64())
                .or_else(|| params.as_u64())
                .or_else(|| params.get(0).and_then(|v| v.as_u64()))
                .unwrap_or(0) as usize;
            let sigs = recent_invalidations(limit);
            let list: Vec<Value> = sigs.iter().map(invalidation_to_json).collect();
            ok(
                id,
                json!({
                    "invalidations": list,
                    "count": list.len(),
                }),
            )
        }

        // ---- streaming subscriptions (WebSocket / SSE) ----
        // Register a subscription and return its id (16 random bytes, hex).
        // The notifications are pushed over the WebSocket transport (`/ws`)
        // or the SSE transport (`/events`).
        "stell_subscribe" => match parse_subscribe_params(params) {
            Ok(topic) => {
                // PER-CLIENT BUDGET (audit W6.7): the global
                // `MAX_SUBSCRIPTIONS` cap bounds the node's MEMORY, but
                // without a per-client cap a single caller can fill the whole
                // registry and starve every other subscriber (the cap is
                // global, so the flood is a denial of service for everyone
                // else). The per-IP cap keeps one client from taking the
                // node's whole budget.
                // Fail-closed attribution (audit residual): `None`
                // (in-process dispatch) used to create UNATTRIBUTED
                // subscriptions that skipped the per-client cap. They now
                // share the static "local" bucket ([`LOCAL_SUBSCRIBER_ID`])
                // with the same cap — throttled, never exempt.
                let client = peer_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| LOCAL_SUBSCRIBER_ID.to_string());
                match hub().subscribe_for(topic, Some(client.as_str())) {
                    Ok(sub_id) => ok(id, json!(sub_id)),
                    Err(e) => err(id, -32000, e),
                }
            }
            Err(e) => err(id, -32602, e),
        },
        // Remove a subscription. `true` when it existed, `false` when the id
        // was unknown (idempotent, like the EVM `eth_uninstallFilter`).
        "stell_unsubscribe" => {
            let sub_id = params
                .get(0)
                .and_then(|v| v.as_str())
                .or_else(|| params.get("subscription").and_then(|v| v.as_str()))
                .or_else(|| params.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            match sub_id {
                Some(s) => ok(id, json!(hub().unsubscribe(s))),
                None => err(id, -32602, "missing subscription id"),
            }
        }
        // The live subscriptions of this node (diagnostics / introspection).
        // Privacy: the registry records which client (IP) owns each
        // subscription for the per-client budget, and the ids are bearer
        // capabilities for the unauthenticated `stell_unsubscribe`. Neither
        // is enumerable here: serve the diagnostics shape (id, filter,
        // age, attachment) without the owner field.
        "stell_getSubscriptions" => {
            let view: Vec<Value> = hub()
                .list()
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "topic": s.topic,
                        "created_at": s.created_at,
                        "attached": s.attached,
                    })
                })
                .collect();
            ok(id, json!(view))
        }

        // ---- the native interface namespace ------------------------------
        // ONE stable, wallet-facing namespace over the native capabilities
        // (token / staking / bridge / order book / session keys / oracle).
        // Every method in it is a thin, fail-closed wrapper over the state
        // engine that owns the state; see `crate::native_api` for the shapes.
        //
        // The write methods do NOT write: they answer with the transaction
        // the wallet has to sign, so the state still only moves when a signed
        // transaction lands in a block.
        _ if crate::native_api::is_native_method(method) => {
            match crate::native_api::dispatch(&st.engine, method, params).await {
                Ok(result) => ok(id, result),
                Err(e) => err(id, e.code(), e.message()),
            }
        }

        _ => err(
            id,
            -32601,
            format!("method not found: {}", snip_for_error(method)),
        ),
    }
}

// ===========================================================================
// Streaming subscriptions: WebSocket + SSE
//
// The node used to speak JSON-RPC over HTTP POST only -- there was NO way to
// be told about a new head, a new transaction or a contract event without
// polling. That is the gap TON Streaming v2 (SSE + WebSocket with finality
// tags), Solana's `logsSubscribe` and Near's `query` subscriptions close, and
// this section closes it here:
//
//   * `stell_subscribe`  -> registers a subscription, returns a hex id
//   * `stell_unsubscribe`-> removes it
//   * WebSocket (`/ws`)  -> JSON-RPC in, notifications out
//   * SSE (`/events`)    -> the same notifications as `text/event-stream`
//
// The topics are `newHeads`, `newTxs`, `invalidations` and `events`.
//
// The `invalidations` topic carries the block-invalidation signals (a branch
// that lost the fork-choice, a reorg that rolled a branch back) — the honest
// counterpart of `newHeads`: the blocks named in a signal were never applied
// (finality forbids rolling back an applied block), so the signal tells a
// subscriber "that block you were told about is not on the chain".
//
// A notification is always `{"subscription": <id>, "result": {...}}`, exactly
// the shape both transports emit.
// ===========================================================================

/// Maximum number of live subscriptions on one node (DoS bound).
///
/// A subscription costs one registry entry plus one broadcast slot; an
/// unbounded registry would let a single client exhaust the node's memory.
pub const MAX_SUBSCRIPTIONS: usize = 4096;

/// Maximum number of live subscriptions ONE client may hold (DoS bound).
///
/// The global [`MAX_SUBSCRIPTIONS`] cap bounds the node's memory, but it is
/// GLOBAL: without a per-client cap a single caller can fill the whole
/// registry and deny the service to every other subscriber (audit W6.7).
/// 64 subscriptions per client is far above what a wallet or an indexer
/// needs and far below the global cap.
pub const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 64;

/// A subscription id is 16 random bytes, hex-encoded (32 characters).
pub const SUBSCRIPTION_ID_BYTES: usize = 16;

/// Capacity of the in-process fan-out channel (notifications buffered per
/// transport before the slow consumer is dropped).
const STREAM_BROADCAST_CAPACITY: usize = 1024;

/// A subscription created over plain HTTP (no transport attached yet) is
/// swept after this many seconds. Keeps the registry bounded even if a
/// client never unsubscribes. A subscription with a live transport is
/// removed by that transport instead.
pub const SUBSCRIPTION_TTL_SECS: u64 = 3600;

/// What a subscription follows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SubscriptionTopic {
    /// Newly finalized heads of this node's chain (TON `ton_subscribe` to
    /// new blocks, Solana `slotSubscribe`).
    NewHeads,
    /// Transactions included in finalized blocks (Solana `logsSubscribe` for
    /// signatures, EVM `newPendingTransactionFilter` in its confirmed form).
    NewTxs,
    /// Block invalidations: a branch that lost the fork-choice, or a reorg
    /// that rolled a branch back. The blocks named in the signal were NEVER
    /// applied (finality forbids rolling back an applied block), so the
    /// signal tells a subscriber "this block you were told about is not on
    /// the chain" — the honest counterpart of `newHeads`.
    Invalidations,
    /// Contract events, optionally filtered by contract address and topics.
    Events {
        /// Canonical hex (32 bytes) of the contract to watch; `None` = all.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contract: Option<String>,
        /// Event topic ids to watch; empty = all.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        topics: Vec<String>,
    },
}

/// One live subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    /// Hex id (32 characters) handed to the client.
    pub id: String,
    /// What this subscription follows.
    pub topic: SubscriptionTopic,
    /// Unix seconds when the subscription was created.
    pub created_at: u64,
    /// True while a transport (WebSocket / SSE) is streaming this
    /// subscription; such entries are not swept by the TTL.
    #[serde(default)]
    pub attached: bool,
    /// The client that created it (its IP), when the caller was attributed.
    ///
    /// Used only for the PER-CLIENT budget (`MAX_SUBSCRIPTIONS_PER_CLIENT`,
    /// audit W6.7): the global cap bounds the node's memory, but a single
    /// caller could otherwise take the WHOLE registry and starve every other
    /// subscriber. `None` for a subscription created over a transport that
    /// carries no attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

/// A push notification. This is the exact shape a client receives over
/// WebSocket and over SSE (`data: {"subscription":...,"result":{...}}`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    /// The subscription this notification belongs to.
    pub subscription: String,
    /// The payload: a head, a transaction or a contract event.
    pub result: Value,
}

/// Per-process subscription registry + notification fan-out.
///
/// The registry (`Arc<RwLock<HashMap<String, Subscription>>>`) is the source
/// of truth for "who follows what"; the broadcast channel carries the
/// notifications to the transports.
///
/// The registry uses a *synchronous* `RwLock` on purpose: the publish hook
/// must be callable from the consensus loop without an async runtime and
/// must never block the chain on a slow subscriber (the lock is held for a
/// map lookup only, never across an `.await`).
pub struct SubscriptionHub {
    /// Live subscriptions of this process, keyed by subscription id.
    pub registry: Arc<std::sync::RwLock<HashMap<String, Subscription>>>,
    /// Fan-out channel to the transports.
    tx: broadcast::Sender<Notification>,
    /// Rolling window of the block invalidation signals this node published
    /// (oldest first).
    ///
    /// A node that reorgs (or that loses a fork) must be able to TELL: the
    /// blocks it named earlier are not on the chain. The window is the
    /// read-side of that promise (`stell_getInvalidations`), the fan-out is
    /// the push side (`stell_subscribe` with the `invalidations` topic).
    invalidations:
        Arc<std::sync::Mutex<std::collections::VecDeque<crate::chain::InvalidationSignal>>>,
}

impl std::fmt::Debug for SubscriptionHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionHub")
            .field("live", &self.len())
            .finish()
    }
}

impl SubscriptionHub {
    /// A fresh, empty hub.
    ///
    /// The process-wide instance is [`hub()`]; tests build isolated hubs so
    /// their traffic cannot cross-talk with another test's subscriptions.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(STREAM_BROADCAST_CAPACITY);
        SubscriptionHub {
            registry: Arc::new(std::sync::RwLock::new(HashMap::new())),
            tx,
            invalidations: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    /// Record an invalidation signal in the rolling window (oldest first).
    ///
    /// The window is bounded: the oldest signal is dropped once the cap is
    /// reached, so a fork storm cannot grow the node's memory without
    /// limit.
    pub fn record_invalidation(&self, signal: crate::chain::InvalidationSignal) {
        if signal.is_empty() {
            return;
        }
        let mut win = self.invalidations.lock().unwrap_or_else(|e| e.into_inner());
        win.push_back(signal);
        while win.len() > crate::chain::MAX_INVALIDATION_WINDOW {
            win.pop_front();
        }
    }

    /// The recent invalidation signals (oldest first), at most `limit` of
    /// them (0 = every signal in the window).
    pub fn recent_invalidations(&self, limit: usize) -> Vec<crate::chain::InvalidationSignal> {
        let win = self.invalidations.lock().unwrap_or_else(|e| e.into_inner());
        let all: Vec<crate::chain::InvalidationSignal> = win.iter().cloned().collect();
        if limit == 0 || all.len() <= limit {
            return all;
        }
        all[all.len() - limit..].to_vec()
    }

    /// Drop every recorded invalidation (tests / diagnostics).
    pub fn clear_invalidations(&self) {
        let mut win = self.invalidations.lock().unwrap_or_else(|e| e.into_inner());
        win.clear();
    }

    /// Register a subscription and return its id.
    pub fn subscribe(&self, topic: SubscriptionTopic) -> Result<String, String> {
        self.subscribe_for(topic, None)
    }

    /// Register a subscription on behalf of an attributed client.
    ///
    /// `client` is the caller's identity (its IP) when the transport could
    /// attribute it. The PER-CLIENT budget (`MAX_SUBSCRIPTIONS_PER_CLIENT`)
    /// is enforced here: the global cap bounds the node's MEMORY, but
    /// without a per-client cap one caller could fill the whole registry
    /// and deny the service to everyone else (audit W6.7).
    pub fn subscribe_for(
        &self,
        topic: SubscriptionTopic,
        client: Option<&str>,
    ) -> Result<String, String> {
        let now = unix_now_secs();
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        // Sweep detached leftovers (a client that subscribed over plain HTTP
        // and never came back). Attached subscriptions live with their
        // transport.
        reg.retain(|_, s| s.attached || now.saturating_sub(s.created_at) < SUBSCRIPTION_TTL_SECS);
        if reg.len() >= MAX_SUBSCRIPTIONS {
            return Err(format!(
                "subscription limit reached ({MAX_SUBSCRIPTIONS} live subscriptions)"
            ));
        }
        if let Some(client) = client {
            let held = reg
                .values()
                .filter(|s| s.client.as_deref() == Some(client))
                .count();
            if held >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                return Err(format!(
                    "per-client subscription limit reached ({MAX_SUBSCRIPTIONS_PER_CLIENT} live subscriptions for this client)"
                ));
            }
        }
        let id = loop {
            let candidate = random_subscription_id();
            if !reg.contains_key(&candidate) {
                break candidate;
            }
        };
        reg.insert(
            id.clone(),
            Subscription {
                id: id.clone(),
                topic,
                created_at: now,
                attached: false,
                client: client.map(|c| c.to_string()),
            },
        );
        Ok(id)
    }

    /// Remove a subscription. Returns true when it existed.
    pub fn unsubscribe(&self, id: &str) -> bool {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        reg.remove(id).is_some()
    }

    /// The subscription with this id, if it is still live.
    pub fn get(&self, id: &str) -> Option<Subscription> {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        reg.get(id).cloned()
    }

    /// Every live subscription (sorted by id).
    pub fn list(&self) -> Vec<Subscription> {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<Subscription> = reg.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Number of live subscriptions.
    pub fn len(&self) -> usize {
        let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
        reg.len()
    }

    /// True when no subscription is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mark a subscription as served by a live transport (so the TTL sweep
    /// leaves it alone).
    pub fn attach(&self, id: &str) {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.get_mut(id) {
            s.attached = true;
        }
    }

    /// Mark a subscription as no longer served by a transport.
    pub fn detach(&self, id: &str) {
        let mut reg = self.registry.write().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.get_mut(id) {
            s.attached = false;
        }
    }

    /// Subscribe to the notification fan-out (one receiver per transport).
    pub fn notifications(&self) -> broadcast::Receiver<Notification> {
        self.tx.subscribe()
    }

    /// Address a payload to every subscription whose filter matches `event`.
    ///
    /// Returns the number of subscriptions addressed. Delivery itself is
    /// best-effort: a transport that is not attached (or is lagging) simply
    /// misses the notification -- the fan-out never blocks the publisher.
    pub fn publish(&self, event: &SubscriptionTopic, result: Value) -> usize {
        let targets: Vec<String> = {
            let reg = self.registry.read().unwrap_or_else(|e| e.into_inner());
            reg.values()
                .filter(|s| topic_matches(&s.topic, event))
                .map(|s| s.id.clone())
                .collect()
        };
        let addressed = targets.len();
        for id in targets {
            // `send` fails only when nobody listens; the registry entry
            // survives, so a client may attach a transport later.
            let _ = self.tx.send(Notification {
                subscription: id,
                result: result.clone(),
            });
        }
        addressed
    }
}

impl Default for SubscriptionHub {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide subscription hub.
static SUBSCRIPTION_HUB: std::sync::OnceLock<Arc<SubscriptionHub>> = std::sync::OnceLock::new();

/// The process-wide subscription hub.
///
/// Per-process by design: a subscription follows THIS node's finalized chain,
/// so it must not be shared between nodes, and a restart drops every
/// subscriber (clients reconnect and resubscribe).
pub fn hub() -> &'static Arc<SubscriptionHub> {
    // A test that needs an ISOLATED hub (one whose invalidation window it
    // can assert on without seeing the traffic of the tests running next to
    // it) installs one for its own thread; the production build has no such
    // override and always returns the process-wide hub.
    #[cfg(test)]
    if let Some(h) = test_hub_override() {
        return h;
    }
    SUBSCRIPTION_HUB.get_or_init(|| Arc::new(SubscriptionHub::new()))
}

#[cfg(test)]
thread_local! {
    /// The hub this thread sees instead of the process-wide one, if any.
    ///
    /// The hub is ONE PER PROCESS, so a test that asserts on its contents
    /// (the invalidation window) would otherwise see whatever the tests
    /// running next to it published. A test that needs its own hub installs
    /// one here; every [`hub`] call on this thread then returns it.
    static TEST_HUB_OVERRIDE: std::cell::RefCell<Option<&'static Arc<SubscriptionHub>>> =
        const { std::cell::RefCell::new(None) };
}

/// The per-test hub installed on this thread, if any.
#[cfg(test)]
fn test_hub_override() -> Option<&'static Arc<SubscriptionHub>> {
    TEST_HUB_OVERRIDE.with(|o| *o.borrow())
}

/// Install a FRESH hub as the one this thread sees, and return it.
///
/// The hub is leaked into a `&'static` because [`hub`] hands out `&'static`
/// references. A test process leaks a handful of hubs — bounded, and the
/// process is short-lived anyway.
#[cfg(test)]
pub(crate) fn install_test_hub() -> &'static Arc<SubscriptionHub> {
    let leaked: &'static Arc<SubscriptionHub> =
        Box::leak(Box::new(Arc::new(SubscriptionHub::new())));
    TEST_HUB_OVERRIDE.with(|o| *o.borrow_mut() = Some(leaked));
    leaked
}

/// Unix seconds (0 when the clock is before the epoch).
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh random subscription id: 16 random bytes, hex-encoded.
fn random_subscription_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; SUBSCRIPTION_ID_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Normalize a topic id so `1`, `"1"` and `"0x1"` compare equal.
fn topic_key(s: &str) -> String {
    let t = s.trim();
    if let Ok(n) = t.parse::<i64>() {
        return n.to_string();
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if let Ok(n) = i64::from_str_radix(h, 16) {
            return n.to_string();
        }
    }
    t.to_lowercase()
}

/// Does a subscriber's filter match an event?
///
/// * `newHeads` matches `newHeads`, `newTxs` matches `newTxs`.
/// * An `events` filter matches when the contract matches (a filter without a
///   contract matches every contract) AND the topic sets intersect (an empty
///   filter matches every topic; `*` / `#` are wildcards).
fn topic_matches(filter: &SubscriptionTopic, event: &SubscriptionTopic) -> bool {
    match (filter, event) {
        (SubscriptionTopic::NewHeads, SubscriptionTopic::NewHeads) => true,
        (SubscriptionTopic::NewTxs, SubscriptionTopic::NewTxs) => true,
        (SubscriptionTopic::Invalidations, SubscriptionTopic::Invalidations) => true,
        (
            SubscriptionTopic::Events {
                contract: want_contract,
                topics: want_topics,
            },
            SubscriptionTopic::Events {
                contract: ev_contract,
                topics: ev_topics,
            },
        ) => {
            if let Some(want) = want_contract {
                match ev_contract {
                    Some(have) if have.eq_ignore_ascii_case(want) => {}
                    _ => return false,
                }
            }
            if want_topics.is_empty() {
                return true;
            }
            want_topics.iter().any(|w| {
                let w = w.trim();
                w == "*" || w == "#" || ev_topics.iter().any(|h| topic_key(h) == topic_key(w))
            })
        }
        _ => false,
    }
}

/// Publish a newly finalized head to the `newHeads` subscribers.
///
/// The consensus loop already reaches this through
/// [`RpcState::record_block`] (the finalize and adopt paths both call it), so
/// a subscriber sees every finalized head of this node, in order, tagged
/// `finality: "finalized"`.
pub fn publish_new_head(
    height: u64,
    hash: [u8; 32],
    shard_id: u32,
    tx_count: usize,
    timestamp: u64,
) -> usize {
    hub().publish(
        &SubscriptionTopic::NewHeads,
        json!({
            "height": height,
            "hash": hex::encode(hash),
            "shard_id": shard_id,
            "tx_count": tx_count,
            "timestamp": timestamp,
            "finality": "finalized",
        }),
    )
}

/// Publish an included transaction to the `newTxs` subscribers.
///
/// `status` is `"confirmed"` for an included (successful) transaction and
/// `"failed"` for one that was included but reverted -- an honest report of
/// what the chain decided, never a guess.
pub fn publish_new_tx(
    hash: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    status: &str,
) -> usize {
    hub().publish(
        &SubscriptionTopic::NewTxs,
        json!({
            "hash": hex::encode(hash),
            "from": hex::encode(from),
            "to": hex::encode(to),
            "amount": amount,
            "status": status,
        }),
    )
}

/// Publish a contract event to the `events` subscribers.
///
/// `topics` carries the event topic id (decimal) and `data` the 8-byte
/// big-endian encoding of the event value -- the payload the contract
/// emitted. `block_height` / `tx_hash` locate the event in the chain.
pub fn publish_contract_event(
    event: &crate::contract::ContractEvent,
    block_height: u64,
    tx_hash: [u8; 32],
) -> usize {
    let contract = hex::encode(event.contract);
    let topics = vec![event.topic.to_string()];
    let data = hex::encode((event.value as u64).to_be_bytes());
    hub().publish(
        &SubscriptionTopic::Events {
            contract: Some(contract.clone()),
            topics: topics.clone(),
        },
        json!({
            "contract": contract,
            "topics": topics,
            "data": data,
            "block_height": block_height,
            "tx_hash": hex::encode(tx_hash),
        }),
    )
}

/// The JSON view of an invalidation signal: the orphaned blocks as hex.
///
/// The hashes are hex (not byte arrays) because this is what a client of
/// `stell_getInvalidations` / the `invalidations` subscription reads, and
/// every other hash this RPC serves is hex too.
pub fn invalidation_to_json(signal: &crate::chain::InvalidationSignal) -> Value {
    json!({
        "height": signal.height,
        "reason": signal.reason,
        "orphaned_blocks": signal.orphaned_blocks.iter().map(hex::encode).collect::<Vec<String>>(),
        "orphaned_count": signal.orphaned_blocks.len(),
    })
}

/// Publish a block invalidation: record it in the rolling window and fan it
/// out to the `invalidations` subscribers.
///
/// This is the EVENT HOOK of the reorg path: the consensus runtime calls it
/// (through the invalidation sink) whenever a branch is pruned or a reorg
/// rolls a branch back, so a streaming client learns that the blocks it was
/// told about are not on the chain.
///
/// Returns the number of subscriptions addressed.
pub fn publish_invalidation(signal: &crate::chain::InvalidationSignal) -> usize {
    if signal.is_empty() {
        return 0;
    }
    hub().record_invalidation(signal.clone());
    hub().publish(
        &SubscriptionTopic::Invalidations,
        invalidation_to_json(signal),
    )
}

/// The recent invalidation signals of this node (oldest first), at most
/// `limit` of them (0 = every signal in the window).
pub fn recent_invalidations(limit: usize) -> Vec<crate::chain::InvalidationSignal> {
    hub().recent_invalidations(limit)
}

/// Parse the parameters of `stell_subscribe`.
///
/// Accepted shapes:
/// * `["newHeads"]`
/// * `["newTxs"]`
/// * `["events", { "contract": "<addr>", "topics": ["1", "2"] }]`
/// * `{"type": "events", "contract": "<addr>", "topics": [...]}`
fn parse_subscribe_params(params: &Value) -> Result<SubscriptionTopic, String> {
    let (kind, filter) = match params {
        Value::Array(items) => {
            let kind = items
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing subscription type".to_string())?;
            (
                kind.to_string(),
                items.get(1).cloned().unwrap_or(Value::Null),
            )
        }
        Value::Object(_) => {
            let kind = params
                .get("type")
                .or_else(|| params.get("subscription"))
                .or_else(|| params.get("kind"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing subscription type".to_string())?;
            (kind.to_string(), params.clone())
        }
        Value::String(s) => (s.clone(), Value::Null),
        _ => return Err("invalid subscribe parameters".to_string()),
    };
    match kind.trim() {
        "newHeads" | "new_heads" | "heads" => Ok(SubscriptionTopic::NewHeads),
        "newTxs" | "new_txs" | "transactions" => Ok(SubscriptionTopic::NewTxs),
        "invalidations" | "invalidation" | "reorgs" => Ok(SubscriptionTopic::Invalidations),
        "events" | "logs" | "contractEvents" => parse_events_filter(&filter),
        other => Err(format!(
            "unknown subscription type: {}",
            snip_for_error(other)
        )),
    }
}

/// Parse the filter object of an `events` subscription.
///
/// The contract is validated (Stl57 / hex / EVM address) and stored in its
/// canonical 32-byte hex form, so a filter compares byte-exact against the
/// events the chain emits.
/// Maximum event topics one `events` subscription filter may carry.
///
/// Each topic is a heap `String` retained for the subscription's whole
/// lifetime (up to `SUBSCRIPTION_TTL_SECS`) and scanned on every matching
/// notification. An unbounded list inside the 1 MiB body would let one
/// client lodge megabytes per subscription — and, at
/// `MAX_SUBSCRIPTIONS_PER_CLIENT` subscriptions, hundreds of megabytes per
/// IP. 32 is far above legitimate use (a wallet watches a handful of topics)
/// and matches `MAX_PROOF_STORAGE_KEYS`.
pub const MAX_SUBSCRIPTION_TOPICS: usize = 32;

fn parse_events_filter(filter: &Value) -> Result<SubscriptionTopic, String> {
    let mut contract = None;
    let mut topics: Vec<String> = Vec::new();
    if let Some(v) = filter.get("contract").or_else(|| filter.get("address")) {
        if !v.is_null() {
            let s = v
                .as_str()
                .ok_or_else(|| "invalid contract parameter: must be a string".to_string())?;
            let addr =
                parse_rpc_address(s).map_err(|e| format!("invalid contract address: {e}"))?;
            contract = Some(hex::encode(addr));
        }
    }
    if let Some(v) = filter.get("topics").or_else(|| filter.get("topic")) {
        match v {
            Value::Null => {}
            Value::Array(items) => {
                if items.len() > MAX_SUBSCRIPTION_TOPICS {
                    return Err(format!(
                        "too many topics: at most {MAX_SUBSCRIPTION_TOPICS} per subscription"
                    ));
                }
                for it in items {
                    let t = match it {
                        Value::String(s) => s.trim().to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => {
                            return Err(
                                "invalid topics entry: expected a string or a number".to_string()
                            )
                        }
                    };
                    if !t.is_empty() {
                        topics.push(t);
                    }
                }
            }
            Value::String(s) => {
                for t in s.split(',') {
                    let t = t.trim();
                    if !t.is_empty() {
                        topics.push(t.to_string());
                    }
                }
                if topics.len() > MAX_SUBSCRIPTION_TOPICS {
                    return Err(format!(
                        "too many topics: at most {MAX_SUBSCRIPTION_TOPICS} per subscription"
                    ));
                }
            }
            _ => return Err("invalid topics parameter".to_string()),
        }
    }
    Ok(SubscriptionTopic::Events { contract, topics })
}

/// Query parameters of the SSE endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct StreamQuery {
    /// Attach to an existing subscription instead of creating one.
    #[serde(alias = "subscription")]
    pub sub_id: Option<String>,
    /// Comma-separated topic kinds: `newHeads`, `newTxs`, `invalidations`,
    /// `events`.
    #[serde(alias = "kind")]
    pub topics: Option<String>,
    /// Contract filter for the `events` topic.
    pub contract: Option<String>,
    /// Comma-separated event topic filter for the `events` topic.
    #[serde(alias = "eventTopics")]
    pub event_topics: Option<String>,
}

/// The topic kinds an SSE stream follows.
fn parse_stream_topics(q: &StreamQuery) -> Result<Vec<SubscriptionTopic>, String> {
    let raw = q.topics.as_deref().unwrap_or("newHeads");
    let mut out = Vec::new();
    for kind in raw.split(',') {
        let kind = kind.trim();
        if kind.is_empty() {
            continue;
        }
        let topic = match kind {
            "newHeads" | "new_heads" | "heads" => SubscriptionTopic::NewHeads,
            "newTxs" | "new_txs" | "transactions" => SubscriptionTopic::NewTxs,
            // The invalidation topic: the same set the WebSocket / JSON-RPC
            // `stell_subscribe` knows, so a browser (SSE) and a bot (WS)
            // follow the SAME events.
            "invalidations" | "invalidation" | "reorgs" => SubscriptionTopic::Invalidations,
            "events" | "logs" | "contractEvents" => {
                let mut filter = serde_json::Map::new();
                if let Some(c) = q.contract.as_deref() {
                    filter.insert("contract".to_string(), Value::String(c.to_string()));
                }
                if let Some(t) = q.event_topics.as_deref() {
                    filter.insert("topics".to_string(), Value::String(t.to_string()));
                }
                parse_events_filter(&Value::Object(filter))?
            }
            other => {
                return Err(format!(
                    "unknown subscription type: {}",
                    snip_for_error(other)
                ))
            }
        };
        out.push(topic);
    }
    if out.is_empty() {
        out.push(SubscriptionTopic::NewHeads);
    }
    Ok(out)
}

/// Removes the subscriptions a transport owns when the transport goes away.
struct SubscriptionGuard {
    /// Subscriptions this transport created (removed on drop).
    owned: Vec<String>,
    /// Subscriptions this transport attached to (detached on drop).
    attached: Vec<String>,
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        for id in self.owned.drain(..) {
            hub().unsubscribe(&id);
        }
        for id in self.attached.drain(..) {
            hub().detach(&id);
        }
    }
}

/// The SSE body type: a stream of `text/event-stream` frames.
type SseStream = std::pin::Pin<
    Box<
        dyn futures::stream::Stream<
                Item = Result<axum::response::sse::Event, std::convert::Infallible>,
            > + Send,
    >,
>;

/// SSE transport: the same notifications as the WebSocket, framed as
/// `text/event-stream` (`data: {"subscription":...,"result":{...}}\n\n`).
///
/// The stream follows the subscription(s) named by `?sub_id=` (an existing
/// subscription) or creates them from `?topics=newHeads,newTxs,invalidations,events`
/// (+ `?contract=`, `?event_topics=`). The ids of the subscriptions it
/// serves are returned in the `x-stell-subscription-id` header.
///
/// Public: the gateway mounts the very same handler on `/events`.
pub async fn sse_handler(
    Query(q): Query<StreamQuery>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let hub = hub();
    // Subscribe to the fan-out BEFORE creating the subscription: a
    // notification published between the two would otherwise be lost.
    let rx = hub.notifications();
    let mut ids: Vec<String> = Vec::new();
    let mut owned: Vec<String> = Vec::new();
    let mut attached: Vec<String> = Vec::new();

    if let Some(want) = q.sub_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        match hub.get(want) {
            Some(s) => {
                hub.attach(&s.id);
                attached.push(s.id.clone());
                ids.push(s.id);
            }
            None => return Err(axum::http::StatusCode::NOT_FOUND),
        }
    } else {
        let topics = match parse_stream_topics(&q) {
            Ok(t) => t,
            Err(_) => return Err(axum::http::StatusCode::BAD_REQUEST),
        };
        for topic in topics {
            match hub.subscribe(topic) {
                Ok(id) => {
                    hub.attach(&id);
                    owned.push(id.clone());
                    ids.push(id);
                }
                Err(_) => return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
            }
        }
    }

    let id_set: HashSet<String> = ids.iter().cloned().collect();
    let guard = SubscriptionGuard { owned, attached };
    let stream = futures::stream::unfold((rx, id_set, guard), |(mut rx, ids, guard)| async move {
        loop {
            match rx.recv().await {
                Ok(note) => {
                    if ids.contains(&note.subscription) {
                        let payload =
                            serde_json::to_string(&note).unwrap_or_else(|_| "{}".to_string());
                        let ev = axum::response::sse::Event::default().data(payload);
                        return Some((Ok(ev), (rx, ids, guard)));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "SSE subscriber lagged behind the stream fan-out");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let sse = axum::response::sse::Sse::new(Box::pin(stream) as SseStream).keep_alive(
        axum::response::sse::KeepAlive::new().interval(std::time::Duration::from_secs(15)),
    );
    let mut resp = sse.into_response();
    if !ids.is_empty() {
        if let Ok(v) = axum::http::HeaderValue::from_str(&ids.join(",")) {
            resp.headers_mut().insert("x-stell-subscription-id", v);
        }
    }
    Ok(resp)
}

// ===========================================================================
// WS PER-MESSAGE EXPENSIVE-READ BUDGET (audit residual: post-upgrade flood)
//
// The HTTP upgrade request passes the gateway/standalone per-IP limiters
// ONCE, at upgrade time. After that the socket is a loop: every text frame
// dispatches a full JSON-RPC call with NO per-message cost check, so one
// socket could flood expensive reads at frame speed. `dispatch` already caps
// `stell_estimateFee` and per-client subscriptions per message, but the proof
// endpoints and `stell_runGetMethod` had NO per-message cap on ANY transport
// beyond the coarse per-request middleware (which a WS socket bypasses after
// the upgrade).
//
// Heavy methods therefore draw from their OWN per-IP budget on EVERY WS
// message, mirroring the `estimate_fee_budget` pattern (same `RateLimiter`,
// same per-IP fixed window — NOT a redesign). Which methods qualify was
// decided by code reading (cost per call):
//   * `stell_estimateFee` — clones the WHOLE engine state and runs a full
//     SVM execution on the clone (`handle_estimate_fee`); the most expensive
//     read on the node.
//   * `stell_subscribe` — each creation fills the process-wide registry
//     (`subscribe_for`, bounded by `MAX_SUBSCRIPTIONS`); an uncapped socket
//     could eat the node's whole subscription budget.
//   * `stell_getProof` — trie walk plus proof build plus self-verification,
//     up to `MAX_PROOF_STORAGE_KEYS` (32) storage paths (`handle_get_proof`).
//   * `stell_getArchiveProof` — rebuilds a proof from the durable snapshot
//     history (`handle_get_archive_proof`).
//   * `stell_getBalanceSpv` / `stell_tokenBalanceSpv` — account/token proof
//     generation against the live trie.
//   * `stell_runGetMethod` — executes contract code (`run_get_method[_typed]`,
//     fuel-bounded but still execution).
// Cheap lookups (balance, headers, chain id, events, ...) draw nothing.
//
// Over budget → a clean `-32000` error frame on the SAME socket (the socket
// stays open: the existing policy never drops on rate-limit, it answers).
// Keyed by peer IP with the static [`LOCAL_BUCKET_IP`] fallback, so
// unattributed sockets are throttled, never exempt.
// ===========================================================================

/// Default per-IP budget for expensive WS reads (per second).
///
/// 5/s mirrors the estimate-fee budget: a wallet/indexer sends heavy reads
/// rarely, while a flood must not pin the node. Override with
/// `STELL_WS_EXPENSIVE_READ_RATE_LIMIT`. Local policy, not consensus: nodes
/// MAY differ.
pub const WS_EXPENSIVE_READ_RATE_LIMIT_DEFAULT: u32 = 5;

/// Effective WS expensive-read per-IP budget.
fn ws_expensive_read_rate_limit() -> u32 {
    std::env::var("STELL_WS_EXPENSIVE_READ_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(WS_EXPENSIVE_READ_RATE_LIMIT_DEFAULT)
}

/// The process-wide WS expensive-read limiter.
fn ws_expensive_read_budget() -> &'static crate::explorer::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| crate::explorer::RateLimiter::new(ws_expensive_read_rate_limit()))
}

/// True when a WS message's method is an expensive read (see above).
fn is_ws_expensive_method(method: &str) -> bool {
    matches!(
        method,
        "stell_estimateFee"
            | "stell_subscribe"
            | "stell_getProof"
            | "stell_getArchiveProof"
            | "stell_getBalanceSpv"
            | "stell_tokenBalanceSpv"
            | "stell_runGetMethod"
    )
}

// ===========================================================================
// WS HARDENING (audit residual, rpc 8.5->9.0): bounded subscriptions per
// connection, size-capped messages, per-message general budget symmetric to
// the HTTP transport limiters, and stale-connection reaping with a live
// connection count. No new env knobs: every bound is a const below.
// ===========================================================================

/// Maximum bytes of one WS message (text or binary, UTF-8 decoded length).
///
/// Mirrors [`MAX_RPC_BODY`] (1 MiB): the HTTP extractor refuses bodies above
/// it before buffering, and a WS frame must not smuggle a bigger request
/// past the upgrade. Oversize frames are refused with a clean `-32600` error
/// frame on the SAME socket (the socket stays open: answers, never drops).
pub const WS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum subscriptions owned by ONE WebSocket connection (DoS bound).
///
/// The global [`MAX_SUBSCRIPTIONS`] cap bounds the node's memory and the
/// per-client ([`MAX_SUBSCRIPTIONS_PER_CLIENT`]) cap bounds one IP, but
/// neither bounds one SOCKET: without this a single connection could hold 64
/// live subscriptions and pin 64 broadcast slots. 16 is far above what one
/// socket needs (heads + txs + invalidations + a handful of event filters)
/// and far below either global cap. The 17th `stell_subscribe` on a full
/// connection is refused fail-closed (`-32000`); the socket stays open.
pub const WS_MAX_SUBS_PER_CONNECTION: usize = 16;

/// Default per-IP budget for ordinary WS messages (per second).
///
/// Symmetric to [`STANDALONE_RATE_LIMIT_DEFAULT`] (300/s): the HTTP upgrade
/// passes the transport limiter once, so every frame after it draws from
/// THIS budget with the same per-IP fixed-window shape instead. Heavy
/// methods draw from the expensive-read budget ON TOP (see above), exactly
/// like an HTTP client sits under both the transport limiter and the
/// `stell_estimateFee` budget. Over budget is a clean `-32000` error frame;
/// the socket stays open.
pub const WS_GENERAL_RATE_LIMIT_DEFAULT: u32 = 300;

/// The process-wide WS general limiter (mirrors `estimate_fee_budget`).
fn ws_general_budget() -> &'static crate::explorer::RateLimiter {
    static LIMITER: std::sync::OnceLock<crate::explorer::RateLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| {
        crate::explorer::RateLimiter::new(WS_GENERAL_RATE_LIMIT_DEFAULT)
    })
}

/// Live WebSocket sessions on this node (incremented on upgrade, decremented
/// when the session ends for ANY reason: close, error, or idle reap).
///
/// The reaping test and operators use this to prove no connection leaks:
/// after every client goes away the count returns to its baseline.
static WS_LIVE_CONNECTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Number of currently live WebSocket sessions (see above).
pub fn ws_live_connections() -> usize {
    WS_LIVE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// RAII guard: the session counts as live until this drops.
struct WsLiveGuard;

impl WsLiveGuard {
    fn new() -> Self {
        WS_LIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        WsLiveGuard
    }
}

impl Drop for WsLiveGuard {
    fn drop(&mut self) {
        WS_LIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Seconds of total inactivity after which a WS session is reaped.
///
/// A connection that sees neither a client frame NOR a forwarded
/// notification for this long is stale (a dead peer whose FIN never
/// arrived): the session breaks out of its select loop, drops its owned
/// subscriptions, and the live count drops, so a dead peer cannot leak a
/// registry entry or a counter slot.
pub const WS_IDLE_TIMEOUT_SECS: u64 = 300;

// Compile-time shape of the WS hardening bounds (fail the build, not a
// test, if a future edit inverts them).
const _: () = assert!(WS_MAX_SUBS_PER_CONNECTION > 0);
const _: () = assert!(WS_MAX_SUBS_PER_CONNECTION <= MAX_SUBSCRIPTIONS_PER_CLIENT);
const _: () = assert!(MAX_SUBSCRIPTIONS_PER_CLIENT < MAX_SUBSCRIPTIONS);
const _: () = assert!(WS_GENERAL_RATE_LIMIT_DEFAULT > 0);
const _: () = assert!(WS_IDLE_TIMEOUT_SECS > 0);

/// Test-only override of [`WS_IDLE_TIMEOUT_SECS`] (0 = use the const).
///
/// Integration tests cannot wait 300 s, so they set a 1 s timeout, prove the
/// reap, and restore 0. Production never touches this: no env knob, no
/// config, no HTTP behavior change.
static WS_IDLE_TIMEOUT_OVERRIDE_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Set the WS idle timeout for tests (0 restores the const default).
/// Absent from production builds (`any(test, debug_assertions)` only).
#[cfg(any(test, debug_assertions))]
pub fn set_ws_idle_timeout_for_tests(secs: u64) {
    WS_IDLE_TIMEOUT_OVERRIDE_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

/// Effective WS idle timeout (the const, unless a test overrode it).
fn ws_idle_timeout() -> std::time::Duration {
    let ov = WS_IDLE_TIMEOUT_OVERRIDE_SECS.load(std::sync::atomic::Ordering::Relaxed);
    std::time::Duration::from_secs(if ov == 0 { WS_IDLE_TIMEOUT_SECS } else { ov })
}

// ===========================================================================
// RATE-LIMIT AUDIT TABLE (rpc 9.0): every public method mapped to a bucket.
//
// Buckets (enforcement — see the code cited, not just this comment):
//   * `transport`    — the per-IP transport limiter: standalone 300/s
// Buckets (enforcement — see the code cited, not just this comment):
//   * `transport`    — the per-IP transport limiter, the outer layer EVERY
//     request sits under: standalone 300/s (`standalone_rate_limit`),
//     gateway 30/s (`explorer`), and the WS per-message general budget
//     mirroring standalone (`ws_general_budget`). Every public method draws
//     from it on every transport (WS draws per frame, not just at upgrade).
//   * `expensive`    — the 5/s per-IP estimate-fee budget enforced in
//     `dispatch` (`estimate_fee_budget`) on ALL transports: `stell_estimateFee`.
//   * `expensive-ws` — the 5/s per-IP WS per-message budget
//     (`ws_expensive_read_budget`, `is_ws_expensive_method`): the 7 heavy
//     methods below, ON WS FRAMES ONLY. On HTTP these same methods have no
//     per-method budget beyond `transport`.
//   * `subscription` — the registry caps in `subscribe_for`: global
//     `MAX_SUBSCRIPTIONS` + per-client `MAX_SUBSCRIPTIONS_PER_CLIENT`,
//     plus per-connection `WS_MAX_SUBS_PER_CONNECTION` on WS frames.
//   * `faucet`       — the hourly per-IP throttle + lifetime caps
//     (`Faucet::check_ip_throttle`, `FAUCET_IP_MAX_PER_HOUR`).
//   * `auth`         — `auth_token`-gated when configured (still under
//     `transport` like everything else).
//
// Method -> buckets (mirrored by `rpc_rate_buckets` below; the coverage test
// `rate_bucket_table_covers_every_public_method` asserts every row):
//   transport only (EVM, 36): eth_chainId, net_version, web3_clientVersion,
//     net_listening, net_peerCount, eth_syncing, eth_gasPrice,
//     eth_maxPriorityFeePerGas, eth_estimateGas, eth_feeHistory, eth_getCode,
//     eth_getBalance, eth_getTransactionCount, eth_blockNumber,
//     eth_getBlockByNumber, eth_getBlockByHash, eth_getTransactionReceipt,
//     eth_getTransactionByHash, eth_getBlockTransactionCountByHash,
//     eth_getBlockTransactionCountByNumber,
//     eth_getTransactionByBlockHashAndIndex,
//     eth_getTransactionByBlockNumberAndIndex, eth_getUncleCountByBlockHash,
//     eth_getUncleCountByBlockNumber, eth_getUncleByBlockHashAndIndex,
//     eth_getUncleByBlockNumberAndIndex, eth_call, eth_newBlockFilter,
//     eth_newPendingTransactionFilter, eth_newFilter, eth_getFilterChanges,
//     eth_getFilterLogs, eth_uninstallFilter, eth_getLogs, eth_getStorageAt,
//     eth_sendRawTransaction.
//   transport only (stell, 53): stell_chainId, stell_nodeId, stell_blockNumber,
//     stell_syncing, stell_getStateRoot, stell_latestBlocks, stell_getShards,
//     stell_getShardTopology, stell_getBlock, stell_getBlockTransactions,
//     stell_epochKey, stell_sendSealedTransaction, stell_mevStats,
//     stell_getBalance, stell_getHistoricalRoot, stell_getFinalizedHeader,
//     stell_getFinalizedCheckpoint, stell_getEpochRoot, stell_bridgeDeposit,
//     stell_bridgeDispute, stell_tokenBalance, stell_tokenSupply,
//     stell_tokenResolve, stell_listTokens, stell_getTransactionReceipt,
//     stell_getEvents, stell_getTransactionStatus, stell_stakeOf,
//     stell_getValidatorStatus, stell_zkmlCapabilities, stell_getValidators,
//     stell_getPqKey, stell_getPqRegistryStatus, stell_proposal,
//     stell_listProposals, stell_governanceParams, stell_mempoolSize,
//     stell_baseFee, stell_verifyMessage, stell_verifyTypedData,
//     stell_sendRawTransaction, stell_pmmState, stell_orderBook,
//     stell_sessionBudget, stell_getContractAbi, stell_verifyContractSource,
//     stell_getContractSource, stell_registerContractSource,
//     stell_getContractReceipt, stell_getInvalidations, stell_invalidationFeed,
//     stell_unsubscribe, stell_getSubscriptions.
//   transport + expensive + expensive-ws (1): stell_estimateFee.
//   transport + expensive-ws (5): stell_getProof, stell_getArchiveProof,
//     stell_getBalanceSpv, stell_tokenBalanceSpv, stell_runGetMethod.
//   transport + expensive-ws + subscription (1): stell_subscribe.
//   transport + faucet (1): stell_faucet.
//   transport + auth (11): stell_mempoolDump, stell_submitProposal, stell_vote,
//     stell_executeProposal, stell_signMessage, stell_signTypedData,
//     stell_deployContract, stell_callContract, stell_submitPriceFeed,
//     stell_pmmBuy, stell_pmmSell.
//   transport only (native namespace, 35, via `is_native_method`):
//     stell_tokenTransfer, stell_tokenBalanceOf, stell_tokenMetadata,
//     stell_tokenAllowance, stell_tokenMint, stell_tokenBurn, stell_tokenApprove,
//     stell_tokenTransferFrom, stell_tokenCreate, stell_stakeBond,
//     stell_stakeUnbond, stell_stakeWithdraw, stell_delegate, stell_undelegate,
//     stell_claimRewards, stell_bridgeDepositPrepare, stell_bridgeWithdraw,
//     stell_bridgeStatus, stell_bridgeAttestStatus, stell_bridgeReleaseEstimate,
//     stell_bridgeDeposits, stell_orderBookPlace, stell_orderBookCancel,
//     stell_orderBookSnapshot, stell_placeOrder, stell_cancelOrder,
//     stell_sessionKeyRegister, stell_sessionKeyRevoke, stell_sessionKeys,
//     stell_oraclePrice, stell_oracleFeeds, stell_nativeApi.
//     (GATE, Ristretto excision: stell_shieldedTransfer,
//     stell_shieldedBalance and stell_unshield were removed with the
//     confidential protocol — no row, no bucket.)
//   (no bucket: unknown method names -> `-32601`; there is no method without
//   a row above.)

/// Buckets rate-limiting a public RPC method (see the audit table above).
///
/// The return is the FULL bucket set: every entry contains `"transport"`
/// (the outer per-IP limiter on every transport), plus the special buckets
/// from the table. Unknown method names map to `&[]` (the `-32601` arm has
/// no bucket). Pure classifier: it drives NO enforcement itself, so HTTP
/// behavior is byte-identical with or without it; the WS path consults it
/// only in comments/tests, enforcement lives in the limiters cited above.
pub fn rpc_rate_buckets(method: &str) -> &'static [&'static str] {
    match method {
        "stell_estimateFee" => &["transport", "expensive", "expensive-ws"],
        "stell_subscribe" => &["transport", "expensive-ws", "subscription"],
        "stell_getProof"
        | "stell_getArchiveProof"
        | "stell_getBalanceSpv"
        | "stell_tokenBalanceSpv"
        | "stell_runGetMethod" => &["transport", "expensive-ws"],
        "stell_faucet" => &["transport", "faucet"],
        "stell_mempoolDump"
        | "stell_submitProposal"
        | "stell_vote"
        | "stell_executeProposal"
        | "stell_signMessage"
        | "stell_signTypedData"
        | "stell_deployContract"
        | "stell_callContract"
        | "stell_submitPriceFeed"
        | "stell_pmmBuy"
        | "stell_pmmSell" => &["transport", "auth"],
        _ if crate::native_api::is_native_method(method) => &["transport"],
        "eth_chainId"
        | "net_version"
        | "web3_clientVersion"
        | "net_listening"
        | "net_peerCount"
        | "eth_syncing"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas"
        | "eth_estimateGas"
        | "eth_feeHistory"
        | "eth_getCode"
        | "eth_getBalance"
        | "eth_getTransactionCount"
        | "eth_blockNumber"
        | "eth_getBlockByNumber"
        | "eth_getBlockByHash"
        | "eth_getTransactionReceipt"
        | "eth_getTransactionByHash"
        | "eth_getBlockTransactionCountByHash"
        | "eth_getBlockTransactionCountByNumber"
        | "eth_getTransactionByBlockHashAndIndex"
        | "eth_getTransactionByBlockNumberAndIndex"
        | "eth_getUncleCountByBlockHash"
        | "eth_getUncleCountByBlockNumber"
        | "eth_getUncleByBlockHashAndIndex"
        | "eth_getUncleByBlockNumberAndIndex"
        | "eth_call"
        | "eth_newBlockFilter"
        | "eth_newPendingTransactionFilter"
        | "eth_newFilter"
        | "eth_getFilterChanges"
        | "eth_getFilterLogs"
        | "eth_uninstallFilter"
        | "eth_getLogs"
        | "eth_getStorageAt"
        | "eth_sendRawTransaction"
        | "stell_chainId"
        | "stell_nodeId"
        | "stell_blockNumber"
        | "stell_syncing"
        | "stell_getStateRoot"
        | "stell_latestBlocks"
        | "stell_getShards"
        | "stell_getShardTopology"
        | "stell_getBlock"
        | "stell_getBlockTransactions"
        | "stell_epochKey"
        | "stell_sendSealedTransaction"
        | "stell_mevStats"
        | "stell_getBalance"
        | "stell_getHistoricalRoot"
        | "stell_getFinalizedHeader"
        | "stell_getFinalizedCheckpoint"
        | "stell_getEpochRoot"
        | "stell_bridgeDeposit"
        | "stell_bridgeDispute"
        | "stell_tokenBalance"
        | "stell_tokenSupply"
        | "stell_tokenResolve"
        | "stell_listTokens"
        | "stell_getTransactionReceipt"
        | "stell_getEvents"
        | "stell_getTransactionStatus"
        | "stell_stakeOf"
        | "stell_getValidatorStatus"
        | "stell_zkmlCapabilities"
        | "stell_getValidators"
        | "stell_getPqKey"
        | "stell_getPqRegistryStatus"
        | "stell_proposal"
        | "stell_listProposals"
        | "stell_governanceParams"
        | "stell_mempoolSize"
        | "stell_baseFee"
        | "stell_verifyMessage"
        | "stell_verifyTypedData"
        | "stell_sendRawTransaction"
        | "stell_pmmState"
        | "stell_orderBook"
        | "stell_sessionBudget"
        | "stell_getContractAbi"
        | "stell_verifyContractSource"
        | "stell_getContractSource"
        | "stell_registerContractSource"
        | "stell_getContractReceipt"
        | "stell_getInvalidations"
        | "stell_invalidationFeed"
        | "stell_unsubscribe"
        | "stell_getSubscriptions" => &["transport"],
        _ => &[],
    }
}

/// WebSocket transport: JSON-RPC requests in, subscription notifications out.
///
/// The socket speaks the SAME JSON-RPC dialect as the HTTP endpoint, so a
/// client may call `stell_subscribe` / `stell_unsubscribe` (and any read
/// method) over the socket. Notifications are pushed as
/// `{"subscription": <id>, "result": {...}}`.
///
/// The credentials of the upgrade request are honoured exactly like on the
/// HTTP endpoint: the API token in the headers gates the same methods, and
/// the peer address feeds the per-IP limits. A WebSocket must never be a way
/// AROUND the auth gate.
async fn ws_handler(
    headers: axum::http::HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    ws: axum::extract::ws::WebSocketUpgrade,
    axum::extract::State(st): axum::extract::State<Arc<RpcState>>,
) -> axum::response::Response {
    let header_token = extract_header_token(&headers).map(|s| s.to_string());
    let peer_ip = peer.map(|axum::extract::ConnectInfo(addr)| {
        crate::client_ip::resolve_client_ip(&headers, addr.ip())
    });
    ws.on_upgrade(move |socket| handle_ws(socket, st, header_token, peer_ip))
}

/// One event of the WebSocket select loop.
enum WsIn {
    /// A message from the client.
    Message(Option<Result<axum::extract::ws::Message, axum::Error>>),
    /// A notification from the fan-out.
    Note(Result<Notification, broadcast::error::RecvError>),
}

/// The WebSocket session: serve one client until it goes away.
async fn handle_ws(
    socket: axum::extract::ws::WebSocket,
    st: Arc<RpcState>,
    header_token: Option<String>,
    peer_ip: Option<std::net::IpAddr>,
) {
    handle_ws_with_timeout(socket, st, header_token, peer_ip, ws_idle_timeout()).await
}

/// The WebSocket session with an explicit idle timeout (the const
/// [`WS_IDLE_TIMEOUT_SECS`] in production; short in tests via
/// [`set_ws_idle_timeout_for_tests`]).
///
/// Reaping: any loop iteration without a client frame AND without a
/// forwarded notification lets the deadline fire, and the session ends —
/// owned subscriptions are removed and the live count drops, so a dead peer
/// cannot leak a registry entry or a counter slot.
async fn handle_ws_with_timeout(
    mut socket: axum::extract::ws::WebSocket,
    st: Arc<RpcState>,
    header_token: Option<String>,
    peer_ip: Option<std::net::IpAddr>,
    idle_timeout: std::time::Duration,
) {
    let _live = WsLiveGuard::new();
    let mut rx = hub().notifications();
    // Subscriptions created ON THIS connection (the client may also subscribe
    // over plain HTTP; those are not pushed here).
    let mut owned: HashSet<String> = HashSet::new();
    // Any select arm that fires counts as activity; only the deadline firing
    // means the connection has been fully idle for `idle_timeout`.
    let mut deadline = tokio::time::Instant::now() + idle_timeout;
    loop {
        // The receive future borrows the socket; the send happens after the
        // select, so the two never overlap.
        let next = tokio::select! {
            biased;
            msg = socket.recv() => WsIn::Message(msg),
            note = rx.recv() => WsIn::Note(note),
            _ = tokio::time::sleep_until(deadline) => break,
        };
        deadline = tokio::time::Instant::now() + idle_timeout;
        match next {
            WsIn::Message(Some(Ok(m))) => match m {
                axum::extract::ws::Message::Text(t) => {
                    if !ws_handle_text(
                        &st,
                        &t,
                        &mut owned,
                        &mut socket,
                        header_token.as_deref(),
                        peer_ip,
                    )
                    .await
                    {
                        break;
                    }
                }
                axum::extract::ws::Message::Binary(b) => {
                    let t = String::from_utf8_lossy(&b).to_string();
                    if !ws_handle_text(
                        &st,
                        &t,
                        &mut owned,
                        &mut socket,
                        header_token.as_deref(),
                        peer_ip,
                    )
                    .await
                    {
                        break;
                    }
                }
                axum::extract::ws::Message::Ping(p) => {
                    if socket
                        .send(axum::extract::ws::Message::Pong(p))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                axum::extract::ws::Message::Pong(_) => {}
                axum::extract::ws::Message::Close(_) => break,
            },
            WsIn::Message(Some(Err(_))) | WsIn::Message(None) => break,
            WsIn::Note(Ok(note)) => {
                if !owned.contains(&note.subscription) {
                    continue;
                }
                // A subscription dropped over plain HTTP stops the push.
                if hub().get(&note.subscription).is_none() {
                    owned.remove(&note.subscription);
                    continue;
                }
                let payload = serde_json::to_string(&note).unwrap_or_else(|_| "{}".to_string());
                if socket
                    .send(axum::extract::ws::Message::Text(payload))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            WsIn::Note(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                tracing::warn!(
                    skipped,
                    "WebSocket subscriber lagged behind the stream fan-out"
                );
                continue;
            }
            WsIn::Note(Err(broadcast::error::RecvError::Closed)) => break,
        }
    }
    // The connection's own subscriptions die with the connection.
    for id in owned {
        hub().unsubscribe(&id);
    }
}

/// Serve one JSON-RPC request received over the WebSocket.
///
/// Returns false when the socket must be closed.
async fn ws_handle_text(
    st: &Arc<RpcState>,
    text: &str,
    owned: &mut HashSet<String>,
    socket: &mut axum::extract::ws::WebSocket,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> bool {
    // SIZE CAP (see `WS_MAX_MESSAGE_BYTES`): mirror the HTTP body limit
    // BEFORE parsing, so a giant frame cannot buy a giant JSON build.
    if text.len() > WS_MAX_MESSAGE_BYTES {
        let resp = err(
            Value::Null,
            -32600,
            format!(
                "request too large: {} bytes (max {WS_MAX_MESSAGE_BYTES})",
                text.len()
            ),
        );
        let out = serde_json::to_string(&resp.0).unwrap_or_default();
        return socket
            .send(axum::extract::ws::Message::Text(out))
            .await
            .is_ok();
    }
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            let resp = RpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(RpcError {
                    code: -32700,
                    message: format!("parse error: {e}"),
                    data: None,
                }),
            };
            let out = serde_json::to_string(&resp).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    };
    let req: RpcRequest = match serde_json::from_value(parsed) {
        Ok(r) => r,
        Err(e) => {
            let resp = RpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(RpcError {
                    code: -32600,
                    message: format!("invalid request: {e}"),
                    data: None,
                }),
            };
            let out = serde_json::to_string(&resp).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    };
    let id = req.id.clone().unwrap_or(Value::Null);
    let method = req.method.clone();
    let params = req.params.clone();
    // PER-MESSAGE GENERAL BUDGET (see `WS_GENERAL_RATE_LIMIT_DEFAULT`): the
    // upgrade request was checked once, but every ordinary frame after it
    // draws from the per-IP general budget — the same outer layer an HTTP
    // request sits under. Over budget → a clean error frame on the SAME
    // socket (the socket stays open: answers, never drops, on rate-limit).
    {
        let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
        if !ws_general_budget().check(ip) {
            let denied = err(
                id,
                -32000,
                "general budget exhausted for this IP on this socket (retry shortly)",
            );
            let out = serde_json::to_string(&denied.0).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    }
    // PER-MESSAGE expensive-read budget (see above): the upgrade request was
    // checked once, but every heavy frame after it draws from the per-IP WS
    // budget. Over budget → a clean error frame on the SAME socket (the
    // socket stays open: answers, never drops, on rate-limit).
    if is_ws_expensive_method(&method) {
        let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
        if !ws_expensive_read_budget().check(ip) {
            let denied = err(
                id,
                -32000,
                "expensive-read budget exhausted for this IP on this socket (retry shortly)",
            );
            let out = serde_json::to_string(&denied.0).unwrap_or_default();
            return socket
                .send(axum::extract::ws::Message::Text(out))
                .await
                .is_ok();
        }
    }
    // PER-CONNECTION SUBSCRIPTION CAP (see `WS_MAX_SUBS_PER_CONNECTION`):
    // fail-closed BEFORE dispatch so a refused subscribe consumes neither a
    // registry slot nor any per-client budget. Over cap → a clean `-32000`
    // error frame; the socket stays open. On success the new id is tracked
    // below so it is pushed to this socket and dies with it.
    if method == "stell_subscribe" && owned.len() >= WS_MAX_SUBS_PER_CONNECTION {
        let denied = err(
            id,
            -32000,
            format!(
                "per-connection subscription limit reached ({WS_MAX_SUBS_PER_CONNECTION} live subscriptions on this connection)"
            ),
        );
        let out = serde_json::to_string(&denied.0).unwrap_or_default();
        return socket
            .send(axum::extract::ws::Message::Text(out))
            .await
            .is_ok();
    }
    let resp = dispatch(st.as_ref(), id, &method, &params, header_token, peer_ip).await;
    // Track the subscriptions this connection owns: they are pushed to it and
    // they die with it.
    if method == "stell_subscribe" {
        if let Some(sid) = resp.0.result.as_ref().and_then(|v| v.as_str()) {
            owned.insert(sid.to_string());
            hub().attach(sid);
        }
    } else if method == "stell_unsubscribe" {
        if let Some(sid) = params.get(0).and_then(|v| v.as_str()) {
            owned.remove(sid);
        }
    }
    let out = serde_json::to_string(&resp.0).unwrap_or_default();
    socket
        .send(axum::extract::ws::Message::Text(out))
        .await
        .is_ok()
}
/// axum handler for the JSON-RPC endpoint.
///
/// Single calls answer with the single response object, byte-identical to
/// before. Batch arrays answer with the response ARRAY (one entry per
/// non-notification call, request order); a batch that is invalid AS A WHOLE
/// (empty, too many items, too many bytes) is refused with the single
/// `-32600` error object, and an all-notification batch gets `204 No
/// Content` (there is nothing to answer, per spec).
async fn rpc_handler(
    axum::extract::State(st): axum::extract::State<Arc<RpcState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if body.len() > MAX_RPC_BODY {
        return err(Value::Null, -32600, "request too large").into_response();
    }
    // A credential in a header rather than in the body, so a client can keep it out
    // of its request logs. `Authorization: Bearer <t>` / `Token <t>`, or the
    // explicit `X-Api-Key` / `X-Stell-Token`.
    let header_token = extract_header_token(&headers);
    // Support both single and batch requests.
    let first: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return err(Value::Null, -32700, format!("parse error: {e}")).into_response(),
    };
    // Real client IP for per-IP faucet throttling: proxy headers only when
    // the TCP peer is a trusted proxy (STELL_TRUSTED_PROXY_CIDRS,
    // loopback-only by default — see crate::client_ip); otherwise the peer.
    // Without this every client behind nginx/Cloudflare shared one bucket.
    let peer_ip = Some(crate::client_ip::resolve_client_ip(&headers, addr.ip()));
    if let Some(arr) = first.as_array() {
        let raw_len = body.len();
        match handle_rpc_batch_call(&st, arr, raw_len, header_token, peer_ip).await {
            Ok(responses) => {
                if responses.is_empty() {
                    // All-notification batch: nothing to answer (JSON-RPC 2.0:
                    // "the Server MUST NOT return an empty array").
                    return axum::http::StatusCode::NO_CONTENT.into_response();
                }
                return axum::Json(responses).into_response();
            }
            Err(refused) => return axum::Json(refused).into_response(),
        }
    }

    let req: RpcRequest = match serde_json::from_value(first) {
        Ok(r) => r,
        Err(e) => return err(Value::Null, -32600, format!("invalid request: {e}")).into_response(),
    };
    let id = req.id.unwrap_or(Value::Null);
    dispatch(&st, id, &req.method, &req.params, header_token, peer_ip).await.into_response()
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
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
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
        // WebSocket transport of the streaming subscriptions: JSON-RPC in,
        // `{"subscription":...,"result":...}` notifications out.
        .route("/ws", get(ws_handler))
        // SSE fallback of the same notifications (`text/event-stream`).
        .route("/events", get(sse_handler))
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
    // N-02 fail-LOUD: governance writes and contract previews now require a
    // valid token on EVERY bind (no loopback escape), so a node started
    // without `STELL_RPC_AUTH_TOKEN` refuses those methods outright. Still
    // starts (proxied/dev setups may set the token later), but screams at
    // startup so a missing token is never mistaken for an open dev node.
    if state.auth_token.as_ref().is_none_or(|t| t.is_empty()) {
        let msg = format!(
            "[security] JSON-RPC on {addr} with NO STELL_RPC_AUTH_TOKEN: \
             stell_submitProposal / stell_vote / stell_executeProposal and the \
             stell_deployContract / stell_callContract previews are REFUSED \
             (fail-closed on every bind, loopback included). Set \
             STELL_RPC_AUTH_TOKEN to serve them."
        );
        eprintln!("{msg}");
        tracing::warn!("{msg}");
    }
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
            .layer(tower::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(30),
            ))
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
    /// The token N-02/N-03 tests configure and present; mirrors
    /// `STELL_RPC_AUTH_TOKEN`. Gov writes and contract previews require it
    /// ALWAYS (no loopback escape), so happy-path tests use a state built by
    /// `test_state_with_token` plus this token in params, while refusal tests
    /// use plain `test_state()` (no token configured at all).
    const TEST_TOKEN: &str = "test-token";

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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
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
        // FULL-PQ: the faucet account is the Falcon-512 address derived from
        // the seed (Faucet::account); fund that address, never a classical one.
        // Funded for the PQ drip cost (amount + gas + activation surcharge,
        // reserved jointly per pooled tx) across a full lifetime-cap burst.
        let faucet_addr = {
            let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
            crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pq_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            )
        };
        let st = test_state().await;
        st.engine
            .update_account(AccountState::new(faucet_addr, 100_000_000))
            .await;
        Arc::new(RpcState {
            faucet: Some(Arc::new(Faucet::new(key_seed, 1, drip, cap))),
            faucet_token: None,
            msg_signing_seed: None,
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
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        })
    }

    async fn test_state_with_faucet(drip: u64, cap: u64) -> Arc<RpcState> {
        let key_seed = [0x11u8; 32];
        // FULL-PQ: the faucet account is the Falcon-512 address derived from
        // the seed (Faucet::account); fund that address, never a classical one.
        // Funded for the PQ drip cost (amount + gas + activation surcharge,
        // reserved jointly per pooled tx) across a full lifetime-cap burst.
        let faucet_addr = {
            let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
            crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pq_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            )
        };
        let st = test_state().await;
        st.engine
            .update_account(AccountState::new(faucet_addr, 100_000_000))
            .await;
        Arc::new(RpcState {
            faucet: Some(Arc::new(Faucet::new(key_seed, 1, drip, cap))),
            faucet_token: Some(FAUCET_TOKEN.to_string()),
            msg_signing_seed: None,
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
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        })
    }

    async fn call(st: &Arc<RpcState>, method: &str, params: Value) -> Value {
        let r = dispatch(st, Value::from(1), method, &params, None, None).await;
        r.0.error
            .map(|e| json!({"error": e.message}))
            .unwrap_or(r.0.result.unwrap_or(Value::Null))
    }

    /// Same empty node as `test_state`, but with an RPC auth token configured
    /// (N-02/N-03 fixture): the only state on which gov writes and contract
    /// previews are served. Present `TEST_TOKEN` in params (see
    /// `call_with_token`); without it every such call is refused.
    async fn test_state_with_token() -> Arc<RpcState> {
        let base = test_state().await;
        Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: base.receipts.clone(),
            auth_token: Some(TEST_TOKEN.to_string()),
            tx_broadcast: base.tx_broadcast.clone(),
            faucet: base.faucet.clone(),
            faucet_token: base.faucet_token.clone(),
            msg_signing_seed: base.msg_signing_seed,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        })
    }

    /// `call` with the fixture token injected into object params (N-02/N-03
    /// happy-path helper). Non-object params pass through untouched; refusal
    /// tests keep using `call` directly (no token, or an explicitly wrong one).
    async fn call_with_token(st: &Arc<RpcState>, method: &str, mut params: Value) -> Value {
        if let Value::Object(map) = &mut params {
            map.insert("token".to_string(), json!(TEST_TOKEN));
        }
        call(st, method, params).await
    }

    /// `call` with an explicit peer IP. Tests that hammer the per-IP
    /// estimate-fee budget use DISTINCT loopback IPs so they don't share one
    /// 5/s bucket and flake in parallel runs — same production path, same
    /// caps, just attributed separately (mirrors distinct real clients).
    async fn call_as(
        st: &Arc<RpcState>,
        peer_ip: std::net::IpAddr,
        method: &str,
        params: Value,
    ) -> Value {
        let r = dispatch(st, Value::from(1), method, &params, None, Some(peer_ip)).await;
        r.0.error
            .map(|e| json!({"error": e.message}))
            .unwrap_or(r.0.result.unwrap_or(Value::Null))
    }

    /// Mint a process-unique loopback IP for estimate-fee tests.
    ///
    /// The estimate-fee budget is a process-global per-IP fixed-window (1s)
    /// limiter, so two tests sharing one IP in the same second share one
    /// bucket. Hand-picked constants (`.11`/`.12`/...) isolate by convention;
    /// a minted IP isolates by construction: its bucket is empty no matter
    /// what else runs in this process, in any order, on any thread. Tests
    /// still go through [`call_as`] (same production path, same caps).
    fn fresh_estimate_ip() -> std::net::IpAddr {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x010100);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127,
            ((n >> 16) & 0xFF) as u8,
            ((n >> 8) & 0xFF) as u8,
            (n & 0xFF) as u8,
        ))
    }

    // GATE: operator-signed governance — deterministic test keys stand in
    // for operator staking keys (never validator/consensus keys). The
    // helpers sign EXACTLY what the production handlers verify.
    use crate::wallet_signing::WalletSigningKey as TestGovKey;

    /// Sign a gov proposal envelope for tests (chain-bound, minted by `key`
    /// for `proposer` over the exact action the handler will apply).
    fn sign_test_proposal(
        chain_id: u64,
        key: &TestGovKey,
        proposer: &[u8; 32],
        title: &str,
        action: &crate::governance::GovAction,
        nonce: u64,
    ) -> String {
        let msg = crate::governance::Governance::gov_propose_message(
            chain_id, proposer, title, action, nonce,
        );
        key.sign_message(chain_id, &msg).unwrap().to_hex()
    }

    /// Sign a gov vote envelope for tests.
    fn sign_test_vote(
        chain_id: u64,
        key: &TestGovKey,
        voter: &[u8; 32],
        proposal_id: u64,
        choice: crate::governance::VoteChoice,
    ) -> String {
        let msg =
            crate::governance::Governance::gov_vote_message(chain_id, proposal_id, choice, voter);
        key.sign_message(chain_id, &msg).unwrap().to_hex()
    }

    // GATE: H-02 — fixed test seed 0x42 stands in for the ephemeral dev-only
    // key (`dev_msg_signing_seed_from_env`); it is NOT the validator key and
    // no test may wire a validator/consensus key here. Justification: the
    // address pin below needs a deterministic seed, while production mints a
    // fresh random seed per boot.
    async fn signing_state(token: Option<&str>) -> Arc<RpcState> {
        let base = test_state().await;
        Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: base.height.clone(),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: base.receipts.clone(),
            auth_token: token.map(|t| t.to_string()),
            tx_broadcast: base.tx_broadcast.clone(),
            faucet: base.faucet.clone(),
            faucet_token: base.faucet_token.clone(),
            msg_signing_seed: Some([0x42u8; 32]),
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        })
    }

    #[tokio::test]
    async fn sign_and_verify_message_round_trip() {
        // GATE: H-02 — dev-mode works only with a presented token (SIGN arms
        // are fail-closed without STELL_RPC_AUTH_TOKEN). Justification: this
        // test previously used an open tokenless node; updated to the gated
        // dev-mode path. The seed is the fixed test stand-in, not a
        // validator key.
        let st = signing_state(Some("secret")).await;
        let signed = call(
            &st,
            "stell_signMessage",
            json!({"message": "hello stellereum", "token": "secret"}),
        )
        .await;
        assert!(signed.get("error").is_none(), "sign must succeed: {signed}");
        // The node signs with its own key: seed 0x42, whose address is pinned
        // by the wallet_signing test vector.
        assert_eq!(
            signed["address"],
            json!("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
        );
        assert_eq!(signed["scheme"], json!("Ed25519"));
        assert_eq!(signed["scheme_id"], json!(1));
        assert_eq!(signed["chain_id"], json!(777));
        let sig = signed["signature"]
            .as_str()
            .expect("signature hex")
            .to_string();
        let verified = call(
            &st,
            "stell_verifyMessage",
            json!({
                "address": signed["address"],
                "message": "hello stellereum",
                "signature": sig,
            }),
        )
        .await;
        assert_eq!(
            verified["valid"],
            json!(true),
            "round trip must verify: {verified}"
        );
        // Same bytes, hex form.
        let verified_hex = call(
            &st,
            "stell_verifyMessage",
            json!({
                "address": signed["address"],
                "message_hex": format!("0x{}", hex::encode("hello stellereum")),
                "signature": sig,
            }),
        )
        .await;
        assert_eq!(verified_hex["valid"], json!(true));
    }

    #[tokio::test]
    async fn sign_needs_token_but_verify_is_public() {
        let st = signing_state(Some("secret")).await;
        let denied = call(&st, "stell_signMessage", json!({"message": "hi"})).await;
        assert!(
            denied.get("error").is_some(),
            "sign without a token must be refused: {denied}"
        );
        let signed = call(
            &st,
            "stell_signMessage",
            json!({"message": "hi", "token": "secret"}),
        )
        .await;
        assert!(
            signed.get("error").is_none(),
            "sign with a token must succeed: {signed}"
        );
        // VERIFY stays public even on a token-gated node.
        let verified = call(
            &st,
            "stell_verifyMessage",
            json!({
                "address": signed["address"],
                "message": "hi",
                "signature": signed["signature"],
            }),
        )
        .await;
        assert_eq!(verified["valid"], json!(true));
        // Typed-data arms follow the same gate split.
        let typed_denied = call(
            &st,
            "stell_signTypedData",
            json!({"contract": hex::encode([0x01u8; 32]), "method": "ping"}),
        )
        .await;
        assert!(typed_denied.get("error").is_some());
        let typed = call(
            &st,
            "stell_signTypedData",
            json!({"contract": hex::encode([0x01u8; 32]), "method": "ping", "token": "secret"}),
        )
        .await;
        assert!(
            typed.get("error").is_none(),
            "typed sign with token: {typed}"
        );
        let tverified = call(
            &st,
            "stell_verifyTypedData",
            json!({
                "address": typed["address"],
                "contract": hex::encode([0x01u8; 32]),
                "method": "ping",
                "signature": typed["signature"],
            }),
        )
        .await;
        assert_eq!(tverified["valid"], json!(true));
    }

    #[tokio::test]
    async fn sign_refuses_fail_closed_without_a_key() {
        // GATE: H-02 — prod-mode refused: token configured but no dev key
        // (production default) must refuse with "not configured", not sign.
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
            receipts: base.receipts.clone(),
            auth_token: Some("secret".to_string()),
            tx_broadcast: base.tx_broadcast.clone(),
            faucet: base.faucet.clone(),
            faucet_token: base.faucet_token.clone(),
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        let r = call(
            &st,
            "stell_signMessage",
            json!({"message": "hi", "token": "secret"}),
        )
        .await;
        assert!(r.get("error").is_some(), "keyless sign must fail: {r}");
        assert!(
            r["error"].as_str().unwrap().contains("not configured"),
            "{r}"
        );
        let t = call(
            &st,
            "stell_signTypedData",
            json!({"contract": hex::encode([0x01u8; 32]), "method": "ping", "token": "secret"}),
        )
        .await;
        assert!(t.get("error").is_some());
    }

    #[tokio::test]
    async fn sign_refuses_without_token_even_with_key() {
        // GATE: H-02 — dev key present but no token configured/presented:
        // SIGN arms stay fail-closed (anonymous signing oracle refused).
        let st = signing_state(None).await;
        let r = call(&st, "stell_signMessage", json!({"message": "hi"})).await;
        assert!(r.get("error").is_some(), "tokenless sign must fail: {r}");
        assert!(
            r["error"].as_str().unwrap().contains("STELL_RPC_AUTH_TOKEN"),
            "{r}"
        );
        let t = call(
            &st,
            "stell_signTypedData",
            json!({"contract": hex::encode([0x01u8; 32]), "method": "ping"}),
        )
        .await;
        assert!(t.get("error").is_some(), "{t}");
    }

    #[tokio::test]
    async fn sign_refuses_non_loopback_peer() {
        // GATE: H-02 — loopback-only: a routable peer IP is refused even with
        // a valid token; loopback succeeds on the same state.
        let st = signing_state(Some("secret")).await;
        let params = json!({"message": "hi", "token": "secret"});
        let remote: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let denied = call_as(&st, remote, "stell_signMessage", params.clone()).await;
        assert!(
            denied.get("error").is_some(),
            "non-loopback sign must fail: {denied}"
        );
        assert!(
            denied["error"].as_str().unwrap().contains("loopback"),
            "{denied}"
        );
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let allowed = call_as(&st, loopback, "stell_signMessage", params).await;
        assert!(
            allowed.get("error").is_none(),
            "loopback sign must succeed: {allowed}"
        );
    }

    #[tokio::test]
    async fn rpc_signature_does_not_verify_on_another_chain() {
        // GATE: H-02 — updated to the gated dev-mode path (token required);
        // domain assertions unchanged.
        let st = signing_state(Some("secret")).await;
        let signed = call(
            &st,
            "stell_signMessage",
            json!({"message": "move 1 STELL", "token": "secret"}),
        )
        .await;
        assert!(signed.get("error").is_none(), "sign must succeed: {signed}");
        let params = |chain: u64| {
            json!({
                "address": signed["address"],
                "message": "move 1 STELL",
                "signature": signed["signature"],
                "chain_id": chain,
            })
        };
        assert_eq!(
            call(&st, "stell_verifyMessage", params(777)).await["valid"],
            json!(true)
        );
        assert_eq!(
            call(&st, "stell_verifyMessage", params(778)).await["valid"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn rpc_tampered_message_and_bad_envelope_fail() {
        // GATE: H-02 — updated to the gated dev-mode path (token required);
        // tamper/envelope assertions unchanged.
        let st = signing_state(Some("secret")).await;
        let signed = call(
            &st,
            "stell_signMessage",
            json!({"message": "pay alice 1", "token": "secret"}),
        )
        .await;
        assert!(signed.get("error").is_none(), "sign must succeed: {signed}");
        let bad_msg = call(
            &st,
            "stell_verifyMessage",
            json!({
                "address": signed["address"],
                "message": "pay alice 2",
                "signature": signed["signature"],
            }),
        )
        .await;
        assert_eq!(bad_msg["valid"], json!(false), "{bad_msg}");
        // Malformed envelope is a params error, not "invalid".
        let bad_env = call(
            &st,
            "stell_verifyMessage",
            json!({
                "address": signed["address"],
                "message": "pay alice 1",
                "signature": "0x0102",
            }),
        )
        .await;
        assert!(bad_env.get("error").is_some(), "{bad_env}");
        // Both message forms at once is ambiguous.
        let both = call(
            &st,
            "stell_verifyMessage",
            json!({
                "address": signed["address"],
                "message": "pay alice 1",
                "message_hex": "0x01",
                "signature": signed["signature"],
            }),
        )
        .await;
        assert!(both.get("error").is_some(), "{both}");
    }

    #[tokio::test]
    async fn typed_data_is_canonical_over_rpc() {
        // GATE: H-02 — updated to the gated dev-mode path (token required);
        // canonicalization assertions unchanged.
        let st = signing_state(Some("secret")).await;
        let contract = hex::encode([0xABu8; 32]);
        let args_a = json!({"to": "alice", "amount": 100});
        let args_b = json!({"amount": 100, "to": "alice"});
        let sign = |args: Value| {
            let st = st.clone();
            let contract = contract.clone();
            async move {
                call(
                    &st,
                    "stell_signTypedData",
                    json!({
                        "contract": contract,
                        "method": "transfer",
                        "args": args,
                        "value": "1000",
                        "nonce": "7",
                        "token": "secret",
                    }),
                )
                .await
            }
        };
        let a = sign(args_a).await;
        let b = sign(args_b).await;
        assert!(a.get("error").is_none(), "{a}");
        // The node signs Ed25519 deterministically: identical content in
        // different key order yields the SAME signature and canonical JSON.
        assert_eq!(a["signature"], b["signature"]);
        assert_eq!(a["canonical"], b["canonical"]);
        assert_eq!(
            a["canonical"],
            json!(format!(
                "{{\"args\":{{\"amount\":100,\"to\":\"alice\"}},\"chain_id\":\"777\",\"contract\":\"0x{contract}\",\"method\":\"transfer\",\"nonce\":\"7\",\"value\":\"1000\"}}"
            ))
        );
        // And the canonical bytes verify.
        for s in [&a, &b] {
            let v = call(
                &st,
                "stell_verifyTypedData",
                json!({
                    "address": s["address"],
                    "contract": contract,
                    "method": "transfer",
                    "args": {"to": "alice", "amount": 100},
                    "value": "1000",
                    "nonce": "7",
                    "signature": s["signature"],
                }),
            )
            .await;
            assert_eq!(v["valid"], json!(true), "{v}");
        }
        // Same fields on another chain do not verify.
        let other = call(
            &st,
            "stell_verifyTypedData",
            json!({
                "address": a["address"],
                "contract": contract,
                "method": "transfer",
                "args": {"to": "alice", "amount": 100},
                "value": "1000",
                "nonce": "7",
                "chain_id": 778,
                "signature": a["signature"],
            }),
        )
        .await;
        assert_eq!(other["valid"], json!(false));
    }

    /// A hub ISOLATED from every other test's traffic.
    ///
    /// The subscription hub is one per process, so a test that asserts on
    /// its contents (the invalidation window) would otherwise see whatever
    /// the tests running next to it published. Installing a fresh hub for
    /// this thread makes the assertion about the node's own history.
    fn isolated_hub() -> &'static Arc<SubscriptionHub> {
        install_test_hub()
    }

    fn receipt_tx(seed: u8, nonce: u64) -> crate::sharding::Transaction {
        // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge),
        // shard 0 like the old fixture.
        pq_tx_shard(seed, [0xEE; 32], 10, 1, nonce, 0, 0)
    }

    /// FULL-PQ test helper: implicit Falcon-512 tx (no activation surcharge,
    /// so fee/balance assertions match the old classical fixtures exactly).
    /// The key is pre-registered globally (idempotent) for intake/apply
    /// verification. `seed` must be distinct per sender within a test.
    fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
        let pk = crate::sharding::Transaction::sample_falcon512_pubkey(seed);
        let from = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        crate::sharding::Transaction::global_implicit_registry()
            .register(
                from,
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            )
            .expect("PQ test key must register");
        (from, pk)
    }

    fn pq_tx_payload(
        seed: u8,
        to: [u8; 32],
        amount: u64,
        gas: u64,
        nonce: u64,
        payload: Vec<crate::svm::OpCode>,
    ) -> crate::sharding::Transaction {
        let (from, pk) = pq_pair(seed);
        let mut tx = crate::sharding::Transaction {
            from,
            to,
            amount,
            gas_limit: gas,
            nonce,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload,
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig =
            crate::sharding::Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
            crate::post_quantum::PqScheme::Falcon512,
            sig,
        )
        .encode();
        tx
    }

    fn pq_tx(
        seed: u8,
        to: [u8; 32],
        amount: u64,
        gas: u64,
        nonce: u64,
    ) -> crate::sharding::Transaction {
        pq_tx_chain(seed, to, amount, gas, nonce, None)
    }

    /// FULL-PQ replacement for `Transaction::sign_with_chain_id` in tests.
    fn pq_tx_chain(
        seed: u8,
        to: [u8; 32],
        amount: u64,
        gas: u64,
        nonce: u64,
        chain: Option<u64>,
    ) -> crate::sharding::Transaction {
        pq_tx_shard_chain(seed, to, amount, gas, nonce, 1, 1, chain)
    }

    fn pq_tx_shard(
        seed: u8,
        to: [u8; 32],
        amount: u64,
        gas: u64,
        nonce: u64,
        s1: crate::sharding::ShardId,
        s2: crate::sharding::ShardId,
    ) -> crate::sharding::Transaction {
        pq_tx_shard_chain(seed, to, amount, gas, nonce, s1, s2, None)
    }

    // GATE: test-only PQ fixture helper with shard+chain params; splitting it
    // would churn all callers for zero benefit.
    #[allow(clippy::too_many_arguments)]
    fn pq_tx_shard_chain(
        seed: u8,
        to: [u8; 32],
        amount: u64,
        gas: u64,
        nonce: u64,
        s1: crate::sharding::ShardId,
        s2: crate::sharding::ShardId,
        chain: Option<u64>,
    ) -> crate::sharding::Transaction {
        let pk = crate::sharding::Transaction::sample_falcon512_pubkey(seed);
        let from = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        crate::sharding::Transaction::global_implicit_registry()
            .register(
                from,
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            )
            .expect("PQ test key must register");
        let mut tx = crate::sharding::Transaction {
            from,
            to,
            amount,
            gas_limit: gas,
            nonce,
            source_shard: s1,
            target_shard: s2,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        // Chain-bound envelopes commit the chain id in the signed message:
        // sign the probe message that already carries it (dummy sig of
        // pinned length — never decoded, only its chain field is read).
        if let Some(c) = chain {
            tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit_with_chain(
                crate::post_quantum::PqScheme::Falcon512,
                vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
                c,
            )
            .encode();
        }
        let msg = tx.signing_message();
        let sig =
            crate::sharding::Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let env = match chain {
            Some(c) => crate::sharding::PqSignatureEnvelope::new_implicit_with_chain(
                crate::post_quantum::PqScheme::Falcon512,
                sig,
                c,
            ),
            None => crate::sharding::PqSignatureEnvelope::new_implicit(
                crate::post_quantum::PqScheme::Falcon512,
                sig,
            ),
        };
        tx.signature = env.encode();
        tx
    }

    #[tokio::test]
    async fn receipt_reports_height_block_index_and_status() {
        let st = test_state().await;
        let txs = vec![receipt_tx(0xA1, 0), receipt_tx(0xA2, 0)];
        st.record_receipts(77, [0xAB; 32], &txs, &[true, false], &[1, 0])
            .await;

        let ok_tx = call(
            &st,
            "stell_getTransactionReceipt",
            json!(hex::encode(txs[0].compute_tx_hash())),
        )
        .await;
        assert_eq!(ok_tx["height"], json!(77));
        assert_eq!(ok_tx["block_hash"], json!(hex::encode([0xABu8; 32])));
        assert_eq!(ok_tx["index"], json!(0));
        assert_eq!(ok_tx["status"], json!("success"));
        assert_eq!(
            ok_tx["fee_charged"],
            json!("1"),
            "receipt files the actual charge"
        );
        assert!(
            ok_tx["gas_limit"].as_str().is_some(),
            "limit is kept alongside"
        );

        let bad_tx = call(
            &st,
            "stell_getTransactionReceipt",
            json!(hex::encode(txs[1].compute_tx_hash())),
        )
        .await;
        assert_eq!(bad_tx["status"], json!("failed"));
        assert_eq!(bad_tx["index"], json!(1));
        assert_eq!(
            bad_tx["fee_charged"],
            json!("0"),
            "a failed tx paid nothing"
        );
    }

    #[tokio::test]
    async fn receipt_distinguishes_pending_from_unknown() {
        let st = test_state().await;
        let tx = receipt_tx(0xA3, 0);
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

        st.record_receipts(5, [0x01; 32], std::slice::from_ref(&tx), &[true], &[1])
            .await;
        let done = call(&st, "stell_getTransactionStatus", json!(h)).await;
        assert_eq!(done["status"], json!("success"));
        assert_eq!(done["height"], json!(5));
    }

    #[tokio::test]
    async fn receipt_status_and_block_are_consistent() {
        // Guards the invariant main.rs relies on: statuses are captured during
        // the single real application, never produced by re-applying the block
        // (which would execute every transfer a second time).
        // FULL-PQ: implicit Falcon-512 (no surcharge).
        let engine = Arc::new(InMemoryStateEngine::new());
        let tx = pq_tx_shard(0xA4, [0xEE; 32], 100, 1, 0, 0, 0);
        engine.update_account(AccountState::new(tx.from, 1_000)).await;
        let (applied, _failed, _fees, statuses, tx_fees) = engine
            .apply_block_parallel_fees(std::slice::from_ref(&tx), 0)
            .await;

        assert_eq!(applied, 1);
        assert_eq!(
            statuses,
            vec![true],
            "one status per transaction, in block order"
        );
        assert_eq!(
            tx_fees,
            vec![1],
            "the receipt files what commit_native charged"
        );

        let balance_after = engine.get_account(&tx.from).await.unwrap().balance;
        assert_eq!(balance_after, 1_000 - 101, "value moved exactly once");

        // Statuses must describe the block, not a second execution: re-running
        // admission against post-state makes the spent nonce fail, so a naive
        // recompute would flip this successful tx to "failed".
        let (_a2, _f2, _fees2, again, again_fees) = engine
            .apply_block_parallel_fees(std::slice::from_ref(&tx), 0)
            .await;
        assert_eq!(
            again,
            vec![false],
            "replay of a spent nonce is rejected, as it must be"
        );
        assert_eq!(
            again_fees,
            vec![0],
            "a refused transaction is charged nothing"
        );
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
                return_value: None,
                gas_used: None,
                events: Vec::new(),
                contract_address: None,
            });
        }
        assert_eq!(
            idx.len(),
            MAX_RECEIPTS,
            "a busy chain cannot exhaust memory"
        );
        let oldest: [u8; 32] = blake3::hash(&0u64.to_be_bytes()).into();
        assert!(idx.get(&oldest).is_none(), "oldest receipts are evicted");
        let newest: [u8; 32] = blake3::hash(&(MAX_RECEIPTS as u64 + 9).to_be_bytes()).into();
        assert!(idx.get(&newest).is_some(), "newest receipt is retained");
    }

    #[tokio::test]
    async fn receipt_rejects_malformed_hash() {
        let st = test_state().await;
        let r = call(&st, "stell_getTransactionReceipt", json!("not-a-hash")).await;
        assert!(
            r.get("error").is_some(),
            "garbage hash is a client error, not a panic"
        );
    }

    #[tokio::test]
    async fn evm_adapter_network_info_methods_through_rpc() {
        let st = test_state().await;
        assert_eq!(call(&st, "eth_chainId", json!([])).await, json!("0x167d"));
        assert_eq!(call(&st, "net_version", json!([])).await, json!("5757"));
        assert_eq!(
            call(&st, "web3_clientVersion", json!([])).await,
            json!("Stellereum/v5.0.0-evm-adapter")
        );
        assert_eq!(call(&st, "net_listening", json!([])).await, json!(true));
        assert_eq!(call(&st, "net_peerCount", json!([])).await, json!("0x2"));
        // LIVE: same rule as `stell_syncing` — a recent verified peer height
        // above ours means syncing. `PEER_HEIGHT` is process-global and
        // monotonic, so the expectation is computed, not hardcoded.
        let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
        let expect_syncing = crate::evm_adapter::eth_syncing_for_heights(ours, fresh_peer_height());
        assert_eq!(
            call(&st, "eth_syncing", json!([])).await,
            json!(expect_syncing)
        );
        assert_eq!(
            call(&st, "stell_syncing", json!([])).await,
            json!(expect_syncing),
            "eth_syncing and stell_syncing must agree on the same heights"
        );
        assert_eq!(
            call(&st, "eth_gasPrice", json!([])).await,
            json!("0x3eb2788000")
        );
        assert_eq!(
            call(&st, "eth_maxPriorityFeePerGas", json!([])).await,
            json!("0x3b9aca00")
        );
        assert_eq!(
            call(&st, "eth_estimateGas", json!([])).await,
            json!("0x5208")
        );
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
        let r = call(
            &st,
            "stell_bridgeDeposit",
            json!({ "source_tx_hash": hash }),
        )
        .await;
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
        let r = call(
            &st,
            "stell_bridgeDeposit",
            json!({ "source_tx_hash": hash }),
        )
        .await;
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

    /// The bridge deposit's two halves must not shadow each other (audit W7.2).
    ///
    /// `stell_bridgeDeposit` is the RECORD read; the native namespace's
    /// PREPARE of the same deposit is `stell_bridgeDepositPrepare`. Before
    /// the split, the read arm was matched FIRST, so the prepare was
    /// unreachable over JSON-RPC.
    #[tokio::test]
    async fn bridge_deposit_read_and_prepare_have_distinct_names() {
        let st = test_state().await;

        // 1. The READ is still the read.
        let r = call(
            &st,
            "stell_bridgeDeposit",
            json!({ "source_tx_hash": hex::encode([0x77u8; 32]) }),
        )
        .await;
        assert_eq!(r["found"], false);

        // 2. A PREPARE-shaped call to the read is refused with a pointer to
        //    the prepare method — never a plausible-looking `found: false`.
        let r = call(
            &st,
            "stell_bridgeDeposit",
            json!({
                "chain": "ton",
                "source_tx_hash": hex::encode([0x77u8; 32]),
                "recipient": hex::encode([0x78u8; 32]),
                "amount": "10",
            }),
        )
        .await;
        let msg = r["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains("stell_bridgeDepositPrepare"),
            "the refusal must name the prepare method, got: {msg}"
        );

        // 3. The PREPARE is reachable over JSON-RPC and answers with the
        //    transaction to sign.
        let r = call(
            &st,
            "stell_bridgeDepositPrepare",
            json!({
                "chain": "ton",
                "source_tx_hash": hex::encode([0x77u8; 32]),
                "recipient": hex::encode([0x78u8; 32]),
                "amount": "10",
            }),
        )
        .await;
        assert!(r.get("error").is_none(), "prepare must answer: {r}");
        assert_eq!(r["action"], "bridge_deposit");
        assert_eq!(r["transaction"]["op"], "SysCallBridge");
        assert_eq!(r["transaction"]["args"]["intent"], "Deposit");
        assert_eq!(r["submit_with"], "stell_sendRawTransaction");
    }

    /// The manifest must advertise BOTH halves under their own names, with
    /// their own kinds (audit W7.2).
    #[tokio::test]
    async fn native_api_manifest_names_the_bridge_deposit_halves_unambiguously() {
        let st = test_state().await;
        let m = call(&st, "stell_nativeApi", json!({})).await;
        let methods = m["methods"].as_array().unwrap().clone();
        let find = |name: &str| {
            methods
                .iter()
                .find(|v| v["name"].as_str() == Some(name))
                .cloned()
        };
        let read = find("stell_bridgeDeposit");
        assert!(
            read.is_none(),
            "the record read is not part of the native namespace"
        );
        let prep = find("stell_bridgeDepositPrepare").expect("the prepare is advertised");
        assert_eq!(prep["kind"], "prepare");
        // No name in the namespace may be advertised twice.
        let mut names: Vec<&str> = methods
            .iter()
            .map(|v| v["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "the manifest lists a method twice");
    }

    /// Every `GovAction` is reachable through `stell_submitProposal`, and an
    /// UNKNOWN action string is refused (audit W7.2).
    ///
    /// The dispatcher used to answer an unrecognised `type` with a `Signal`
    /// action — a silent no-op that made a typo look like an accepted
    /// proposal. It now fails closed.
    ///
    /// GATE (operator-signed governance): every accepted proposal below is
    /// submitted with a wallet signature over
    /// (chain_id || proposer || title || action || nonce), bound to a staked
    /// proposer key. Justification for touching this test: the handler now
    /// refuses unsigned proposals fail-closed, so the reachability pins must
    /// sign; the unknown-type and missing-param refusals still fire BEFORE
    /// any signature check (unchanged fail-closed vocabulary gate).
    #[tokio::test]
    async fn submit_proposal_reaches_every_action_and_refuses_an_unknown_type() {
        // N-02: gov writes require a token on every bind, so this
        // reachability pin runs on the token fixture (refusal cases still pin
        // their own errors — the gate passes, then the vocabulary gate fires).
        let st = test_state_with_token().await;
        // The proposer is a real signing key: the handler binds the envelope
        // to the claimed staking address, so an arbitrary 0xA1 address can no
        // longer propose.
        let proposer_key = TestGovKey::ed25519([0xA1u8; 32]);
        let proposer_addr = proposer_key.address();
        let proposer = hex::encode(proposer_addr);

        // 1. An unknown action type is REFUSED, and nothing is recorded.
        let res = call_with_token(
            &st,
            "stell_submitProposal",
            json!({
                "title": "typo",
                "type": "set_min_validator_bondd",
                "value": 1,
                "proposer": proposer,
            }),
        )
        .await;
        let msg = res["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains("unknown governance action type"),
            "unexpected error: {msg}"
        );
        assert!(
            st.governance.read().await.proposals.is_empty(),
            "a refused proposal must not be recorded"
        );

        // 2. A known type with a MISSING parameter is refused too (no
        //    defaults: a governance parameter is never silently invented).
        let res = call_with_token(
            &st,
            "stell_submitProposal",
            json!({ "title": "no value", "type": "set_min_gas_limit", "proposer": proposer }),
        )
        .await;
        let msg = res["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains("missing parameter 'value'"),
            "unexpected error: {msg}"
        );

        // 3. Every canonical action type is accepted (the proposer is staked,
        //    otherwise the proposal is refused for the stake and not for the
        //    action). Each envelope carries a fresh nonce (replay protection).
        {
            let mut ledger = st.engine.staking_write().await;
            ledger
                .bond(proposer_addr, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                .unwrap();
        }
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "set_min_validator_bond",
                json!({ "value": 20_000_000_000_000u64 }),
            ),
            ("set_equivocation_slash_bps", json!({ "value": 500 })),
            ("set_default_commission_bps", json!({ "value": 100 })),
            ("set_block_reward", json!({ "value": 1_000_000_000 })),
            ("set_pmm_redemption_buffer_bps", json!({ "value": 250 })),
            ("set_governance_quorum_bps", json!({ "value": 5_000 })),
            ("signal", json!({ "text": "hello governance" })),
            (
                "register_oracle_publisher",
                json!({ "publisher": hex::encode([0xB2u8; 32]) }),
            ),
            (
                "unregister_oracle_publisher",
                json!({ "publisher": hex::encode([0xB3u8; 32]) }),
            ),
            ("reset_oracle_breaker", json!({})),
            ("set_min_gas_limit", json!({ "value": 21_000 })),
            (
                "software_upgrade",
                json!({ "name": "v0.2.0", "height": 500, "sha256": hex::encode([0xC4u8; 32]) }),
            ),
            ("cancel_upgrade", json!({})),
        ];
        assert_eq!(
            cases.len(),
            crate::governance::GovAction::ACTION_TYPES.len(),
            "every documented action type must be covered by this test"
        );
        for (i, (action_type, extra)) in cases.iter().enumerate() {
            let title = format!("proposal {action_type}");
            let mut params = json!({ "title": title.clone(), "type": action_type, "proposer": proposer });
            if let serde_json::Value::Object(map) = extra {
                for (k, v) in map {
                    params[k] = v.clone();
                }
            }
            // Sign EXACTLY what the handler will apply (same params shape).
            let action = crate::governance::gov_action_from_params(action_type, &params)
                .expect("test action must parse");
            let nonce = 1000u64 + i as u64;
            params["nonce"] = json!(nonce);
            params["signature"] = json!(sign_test_proposal(
                st.chain_id,
                &proposer_key,
                &proposer_addr,
                &title,
                &action,
                nonce
            ));
            let res = call_with_token(&st, "stell_submitProposal", params).await;
            assert!(
                res.get("error").is_none(),
                "action '{action_type}' must be reachable: {res}"
            );
            assert!(res["proposal_id"].is_u64(), "no proposal id: {res}");
        }

        // 4. The proposals carry the action types they were created with.
        let list = call(&st, "stell_listProposals", json!({})).await;
        let types: Vec<String> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["action_type"].as_str().unwrap_or_default().to_string())
            .collect();
        for (action_type, _) in &cases {
            assert!(
                types.contains(&action_type.to_string()),
                "the proposal for '{action_type}' is missing from {types:?}"
            );
        }
    }

    #[tokio::test]
    async fn faucet_is_disabled_by_default() {
        let st = test_state().await;
        let r = call(
            &st,
            "stell_faucet",
            json!({ "address": hex::encode([0x42u8; 32]) }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("disabled"),
            "faucet must be off unless explicitly enabled: {r}"
        );
        assert!(
            st.engine.get_account(&[0x42u8; 32]).await.is_none(),
            "no account may be created"
        );
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
        assert!(
            old.build_transfer(who, None, None).await.is_none(),
            "capped"
        );

        // "Restart": a fresh Faucet over the persisted bytes.
        let bytes = saved.lock().unwrap().clone();
        assert!(!bytes.is_empty(), "every drip must have persisted state");
        let new = Faucet::new(key_seed, 1, 10, 25);
        new.load_bytes(&bytes).await;
        assert_eq!(
            new.dispensed_to(who).await,
            25,
            "cap must survive the restart"
        );
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
        let r = call(
            &st,
            "stell_faucet",
            json!({ "address": hexa.clone(), "amount": u64::MAX, "token": FAUCET_TOKEN }),
        )
        .await;
        assert_eq!(r["credited_nano"], "10");
        assert_eq!(
            call(&st, "stell_faucet", drip_req(&hexa)).await["credited_nano"],
            "10"
        );
        // 3rd call is clamped by the lifetime cap to the remaining 5.
        let r3 = call(&st, "stell_faucet", drip_req(&hexa)).await;
        assert_eq!(r3["credited_nano"], "5");
        // 4th call: exhausted.
        let r4 = call(&st, "stell_faucet", drip_req(&hexa)).await;
        assert!(
            r4["error"].as_str().unwrap_or_default().contains("limit"),
            "{r4}"
        );

        // Every drip is a real, correctly signed transfer from the faucet account
        // sitting in the mempool — nothing was written straight into state.
        let pending = st.mempool.read().await.len();
        assert_eq!(pending, 3);
        for tx in st.mempool.read().await.all() {
            assert!(
                tx.verify_signature(),
                "faucet tx must carry a valid signature"
            );
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
        assert!(
            tx1.verify_signature(),
            "public drip must carry a valid signature"
        );

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

        // If rollback is called on a failed transaction, cooldown is cleared.
        faucet.rollback(&tx3, who, PUBLIC_DRIP_NANO).await;
        // Address can immediately request public drip again.
        let (tx4, _) = faucet
            .build_public_transfer(who, t0 + PUBLIC_DRIP_COOLDOWN_SECS + 5, None)
            .await
            .expect("drip after rollback must succeed immediately");
        assert_eq!(tx4.nonce, tx3.nonce);
    }

    #[tokio::test]
    async fn faucet_uses_increasing_nonces() {
        let st = test_state_with_faucet(10, 100).await;
        call(&st, "stell_faucet", drip_req(&hex::encode([1u8; 32]))).await;
        call(&st, "stell_faucet", drip_req(&hex::encode([2u8; 32]))).await;
        let mut nonces: Vec<u64> = st
            .mempool
            .read()
            .await
            .all()
            .iter()
            .map(|t| t.nonce)
            .collect();
        nonces.sort_unstable();
        assert_eq!(nonces, vec![0, 1], "faucet txs must not reuse a nonce");
    }

    /// Fail-safe pure-PQ override: resets on drop so a panicking assertion
    /// cannot leak enforcement into unrelated tests on this thread.
    struct PurePqGuard;
    impl PurePqGuard {
        fn enforce() -> Self {
            crate::post_quantum::set_pure_pq_override(Some(true));
            Self
        }
    }
    impl Drop for PurePqGuard {
        fn drop(&mut self) {
            crate::post_quantum::set_pure_pq_override(None);
        }
    }

    fn faucet_pq_keypair() -> crate::post_quantum::FalconKeypair {
        crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x11u8; 32])
    }

    #[test]
    fn pq_explicit_transfer_verifies_under_pure_pq() {
        let _guard = PurePqGuard::enforce();
        let kp = faucet_pq_keypair();
        let to = [0xABu8; 32];
        let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
        let tx = sign_pq_explicit_transfer(&kp, to, 1_000_000_000, gas, 0, 0, 0);
        // The sender is the faucet's own PQ account: this tx spends genesis
        // funds, which is exactly what `wallet send-pq --falcon-seed` relies on.
        let faucet = Faucet::new([0x11u8; 32], 0, 10, 25);
        assert_eq!(
            tx.from,
            faucet.account(),
            "helper sender must equal the pure-PQ faucet account"
        );
        assert_eq!(tx.to, to);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.gas_limit, gas, "activation surcharge must ride the tx");
        assert!(
            tx.is_pq(),
            "the tx must carry a PQ1 envelope, never bare ed"
        );
        let env = tx.pq_envelope().expect("PQ envelope decodes");
        assert_eq!(env.scheme, crate::post_quantum::PqScheme::Falcon512);
        assert!(
            !env.is_implicit,
            "always explicit: first spend needs no registry"
        );
        assert!(
            env.pubkey.is_some(),
            "explicit carrier must embed the pubkey"
        );
        assert!(
            tx.verify_signature(),
            "faucet-shaped PQ tx must verify under PURE_PQ"
        );
    }

    #[tokio::test]
    async fn pq_explicit_transfer_matches_faucet_drip_shape() {
        // The refactor pin: `Faucet::build_transfer` must build the same tx
        // SHAPE the shared helper builds (same fields, same envelope, both
        // verify). Signatures legitimately differ: Falcon signing is
        // randomized (`test_falcon_nonces_never_repeat`), so byte-equality of
        // the sig is the wrong assertion — structural identity is the pin.
        let _guard = PurePqGuard::enforce();
        let seed = [0x11u8; 32];
        let faucet = Faucet::new(seed, 0, 10_000_000_000, 1_000_000_000_000);
        let who = [0xCDu8; 32];
        let (drip_tx, amount) = faucet
            .build_transfer(who, Some(1_000_000_000), None)
            .await
            .expect("first drip fits the cap");
        let kp = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
        let helper_tx = sign_pq_explicit_transfer(
            &kp,
            who,
            amount,
            crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
            0,
            0,
            0,
        );
        for (field, a, b) in [
            ("from", drip_tx.from.to_vec(), helper_tx.from.to_vec()),
            ("to", drip_tx.to.to_vec(), helper_tx.to.to_vec()),
        ] {
            assert_eq!(a, b, "field {field} must match");
        }
        assert_eq!(drip_tx.amount, helper_tx.amount);
        assert_eq!(drip_tx.gas_limit, helper_tx.gas_limit);
        assert_eq!(drip_tx.nonce, helper_tx.nonce);
        assert_eq!(drip_tx.source_shard, helper_tx.source_shard);
        assert_eq!(drip_tx.target_shard, helper_tx.target_shard);
        assert_eq!(drip_tx.payload.len(), helper_tx.payload.len());
        let drip_env = drip_tx.pq_envelope().expect("drip envelope decodes");
        let helper_env = helper_tx.pq_envelope().expect("helper envelope decodes");
        assert_eq!(drip_env.scheme, helper_env.scheme);
        assert_eq!(drip_env.is_implicit, helper_env.is_implicit);
        assert_eq!(drip_env.pubkey, helper_env.pubkey);
        assert!(drip_tx.verify_signature());
        assert!(helper_tx.verify_signature());
    }

    #[test]
    fn ed_signed_transfer_is_refused_under_pure_pq() {
        let _guard = PurePqGuard::enforce();
        let ed = SigningKey::from_bytes(&[0x22u8; 32]);
        let tx = crate::sharding::Transaction::sign(&ed, [0xABu8; 32], 1_000, 1000, 0, 0, 0);
        assert!(
            !tx.verify_signature(),
            "legacy ed25519 txs must be refused when PURE_PQ is enforced"
        );
    }

    #[test]
    fn tampered_pq_transfer_is_refused() {
        let _guard = PurePqGuard::enforce();
        let kp = faucet_pq_keypair();
        let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
        let tx = sign_pq_explicit_transfer(&kp, [0xABu8; 32], 1_000_000_000, gas, 0, 0, 0);
        assert!(tx.verify_signature(), "baseline must verify");

        let mut bad_sig = tx.clone();
        let last = bad_sig.signature.len() - 1;
        bad_sig.signature[last] ^= 0x01;
        assert!(
            !bad_sig.verify_signature(),
            "a tampered PQ signature must be refused"
        );

        let mut bad_amt = tx.clone();
        bad_amt.amount += 1;
        assert!(
            !bad_amt.verify_signature(),
            "a tampered amount must be refused"
        );

        let mut bad_to = tx.clone();
        bad_to.to[0] ^= 0xFF;
        assert!(
            !bad_to.verify_signature(),
            "a tampered recipient must be refused"
        );
    }

    #[test]
    fn cross_shard_pq_shape_verifies_under_pure_pq() {
        // The 2PC demo's first leg: source = masterchain, target = workchain 1.
        let _guard = PurePqGuard::enforce();
        let kp = faucet_pq_keypair();
        let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
        let tx = sign_pq_explicit_transfer(&kp, [0xABu8; 32], 1_000_000_000, gas, 0, 0, 1);
        assert_eq!(tx.source_shard, 0);
        assert_eq!(tx.target_shard, 1);
        assert!(
            tx.verify_signature(),
            "cross-shard PQ tx must verify under PURE_PQ"
        );
    }

    #[test]
    fn pq_explicit_transfer_admits_under_pure_pq() {
        // The one mempool gate the in-process e2e cannot cover (it must run
        // with pure-PQ off so the harness's ed votes verify): under
        // enforcement the pool REQUIRES a PQ envelope with a post-quantum
        // scheme. The `send-pq` shape passes; a bare ed tx is refused.
        let _guard = PurePqGuard::enforce();
        let kp = faucet_pq_keypair();
        let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
        let tx = sign_pq_explicit_transfer(&kp, [0xABu8; 32], 1_000_000_000, gas, 0, 0, 0);
        let mut pool = crate::mempool::Mempool::default();
        let ctx = crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(0);
        assert!(
            pool.add_checked_ctx(tx, 1_000_000_000_000_000u64, ctx)
                .is_ok(),
            "faucet-shaped PQ tx must admit under PURE_PQ"
        );

        let ed = SigningKey::from_bytes(&[0x22u8; 32]);
        let ed_tx = crate::sharding::Transaction::sign(&ed, [0xABu8; 32], 1_000, 1000, 0, 0, 0);
        let mut pool2 = crate::mempool::Mempool::default();
        let ctx2 = crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(0);
        assert!(
            pool2
                .add_checked_ctx(ed_tx, 1_000_000_000_000_000u64, ctx2)
                .is_err(),
            "bare ed tx must NOT admit under PURE_PQ"
        );
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
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
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
            r2["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "a wrong token must be refused: {r2}"
        );
        // Neither attempt may have touched the mempool or the recipient.
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "no unsigned tx may be queued"
        );
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
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("refusing to dispense"),
            "a faucet with no token must refuse even a well-formed request: {r}"
        );
        assert_eq!(st.mempool.read().await.len(), 0);
    }

    #[tokio::test]
    async fn faucet_rejects_malformed_address() {
        let st = test_state_with_faucet(10, 25).await;
        let r = call(
            &st,
            "stell_faucet",
            json!({ "address": "zz", "token": FAUCET_TOKEN }),
        )
        .await;
        assert!(r["error"].is_string());
        let r2 = call(&st, "stell_faucet", json!({ "token": FAUCET_TOKEN })).await;
        assert!(r2["error"].is_string());
    }

    /// Sharded faucet harness: the faucet serves `shard`, the engine runs
    /// that shard, the registry is `{0, 1}` (sharded), and the faucet account
    /// is genesis-funded — mirroring a sharded testnet node.
    async fn test_state_with_faucet_on_shard(drip: u64, cap: u64, shard: ShardId) -> Arc<RpcState> {
        let key_seed = [0x11u8; 32];
        // FULL-PQ: the faucet account is the Falcon-512 address derived from
        // the seed (Faucet::account); fund that address, never a classical one.
        // Funded for the PQ drip cost (amount + gas + activation surcharge,
        // reserved jointly per pooled tx) across a full lifetime-cap burst.
        let faucet_addr = {
            let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
            crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pq_key.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            )
        };
        let st = test_state().await;
        st.engine.set_shard_id(shard);
        st.engine
            .update_account(AccountState::new(faucet_addr, 100_000_000))
            .await;
        Arc::new(RpcState {
            faucet: Some(Arc::new(Faucet::new(key_seed, shard, drip, cap))),
            faucet_token: Some(FAUCET_TOKEN.to_string()),
            msg_signing_seed: None,
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
            archive_store: None,
            shard_registry: ShardRegistry::from_ids([0, 1]),
        })
    }

    /// A drip to a masterchain (`-1:`) account is a same-shard transfer on
    /// shard 0 and finalizes there: the recipient is credited through the
    /// shared `apply_block_transition` core (the live consensus path).
    #[tokio::test]
    async fn faucet_masterchain_drip_finalizes_on_shard_0() {
        let st = test_state_with_faucet_on_shard(10, 100, 0).await;
        let who = [0x42u8; 32];
        let r = call(
            &st,
            "stell_faucet",
            drip_req(&format!("-1:{}", hex::encode(who))),
        )
        .await;
        assert_eq!(
            r["credited_nano"], "10",
            "masterchain drip must be served: {r}"
        );
        assert_eq!(r["shard"], 0);
        {
            let pool = st.mempool.read().await;
            assert_eq!(pool.len(), 1);
            let tx = &pool.all()[0];
            assert_eq!(tx.to, who);
            assert_eq!(
                tx.source_shard, 0,
                "drip must execute where the recipient lives"
            );
            assert_eq!(tx.target_shard, 0);
            assert_eq!(tx.nonce, 0);
            assert!(tx.verify_signature(), "drip must carry a valid signature");
        }
        let block = crate::sharding::Block {
            shard_id: 0,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: st.mempool.read().await.all().to_vec(),
            cross_shard_out: vec![],
            timestamp: 1_700_000_000,
            proposer: [0u8; 32],
            validator_signatures: vec![],
            precommit_qc: None,
            last_qc: None,
            shard_headers: vec![],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        let outcome = st.engine.apply_block_transition(&block, 0).await;
        assert_eq!(outcome.applied, 1, "the drip must apply on shard 0");
        assert_eq!(outcome.failed, 0);
        let acc = st
            .engine
            .get_account(&who)
            .await
            .expect("recipient must exist");
        assert_eq!(acc.balance, 10, "recipient must be credited the drip");
    }

    /// A drip to a workchain (bare) account is a same-shard transfer on the
    /// shard the routing rule selects and finalizes there.
    #[tokio::test]
    async fn faucet_workchain_drip_finalizes_on_its_shard() {
        let st = test_state_with_faucet_on_shard(10, 100, 1).await;
        let who = [0x43u8; 32];
        let r = call(&st, "stell_faucet", drip_req(&hex::encode(who))).await;
        assert_eq!(
            r["credited_nano"], "10",
            "workchain drip must be served: {r}"
        );
        assert_eq!(
            r["shard"], 1,
            "bare address must route to the workchain shard: {r}"
        );
        {
            let pool = st.mempool.read().await;
            assert_eq!(pool.len(), 1);
            let tx = &pool.all()[0];
            assert_eq!(tx.to, who);
            assert_eq!(
                tx.source_shard, 1,
                "drip must execute where the recipient lives"
            );
            assert_eq!(tx.target_shard, 1);
        }
        let block = crate::sharding::Block {
            shard_id: 1,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: st.mempool.read().await.all().to_vec(),
            cross_shard_out: vec![],
            timestamp: 1_700_000_000,
            proposer: [0u8; 32],
            validator_signatures: vec![],
            precommit_qc: None,
            last_qc: None,
            shard_headers: vec![],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        let outcome = st.engine.apply_block_transition(&block, 0).await;
        assert_eq!(outcome.applied, 1, "the drip must apply on shard 1");
        let acc = st
            .engine
            .get_account(&who)
            .await
            .expect("recipient must exist");
        assert_eq!(acc.balance, 10, "recipient must be credited the drip");
    }

    /// A drip that would be shard-filtered is refused AT ADMISSION with a
    /// clear error — never queued — and the refusal burns no nonce: the next
    /// servable drip keeps the exact nonce sequence as if the refusal never
    /// happened (the live failure mode was stuck nonces 4,5,6 on source=1 for
    /// masterchain recipients).
    #[tokio::test]
    async fn faucet_refuses_shard_mismatched_drip_without_burning_nonce() {
        // Faucet serves shard 0 (masterchain); the bare address routes to
        // shard 1 under the documented rule.
        let st = test_state_with_faucet_on_shard(10, 100, 0).await;
        let faucet = st.faucet.clone().expect("faucet enabled");
        let r = call(&st, "stell_faucet", drip_req(&hex::encode([0x42u8; 32]))).await;
        let err = r["error"]
            .as_str()
            .expect("shard-mismatched drip must be refused");
        assert!(
            err.contains("shard 1") && err.contains("shard 0"),
            "refusal must name both shards, not just fail: {err}"
        );
        // Nothing queued, nothing reserved, nonce untouched.
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "refused drip must not pend"
        );
        assert_eq!(faucet.dispensed_to([0x42u8; 32]).await, 0);
        // The next servable drips take nonces 0 and 1 — the refusal burned none.
        let ok = call(
            &st,
            "stell_faucet",
            drip_req(&format!("-1:{}", hex::encode([0x42u8; 32]))),
        )
        .await;
        assert_eq!(ok["credited_nano"], "10", "{ok}");
        let ok2 = call(
            &st,
            "stell_faucet",
            drip_req(&format!("-1:{}", hex::encode([0x44u8; 32]))),
        )
        .await;
        assert_eq!(ok2["credited_nano"], "10", "{ok2}");
        let mut nonces: Vec<u64> = st
            .mempool
            .read()
            .await
            .all()
            .iter()
            .map(|t| t.nonce)
            .collect();
        nonces.sort_unstable();
        assert_eq!(nonces, vec![0, 1], "refused drip must not burn a nonce");
    }

    /// VERIFICATION W10.2-hardening: the recipient-shard admission rule must
    /// refuse a cross-shard drip BEFORE any nonce/cap reservation, and the
    /// `-1:`/`0:` workchain prefixes must route exactly like the rule says.
    ///
    /// Stronger than the existing refusal test: it pins the prefix matrix
    /// directly against `resolve_faucet_recipient` —
    /// * a `-1:`-prefixed address on a shard-0 faucet is ADMITTED (it IS the
    ///   masterchain form, not a bypass);
    /// * a `0:`-prefixed address behaves identically (same shard, no alias);
    /// * the SAME `-1:` address against a shard-1 faucet is REFUSED (the
    ///   prefix cannot smuggle a masterchain recipient onto a workchain
    ///   faucet, and vice versa);
    /// * and the full RPC path still admits no mempool entry and burns no
    ///   nonce for the refused shape.
    #[tokio::test]
    async fn faucet_prefix_matrix_routes_before_nonce_reservation() {
        let st0 = test_state_with_faucet_on_shard(10, 100, 0).await;
        let faucet0 = st0.faucet.clone().expect("faucet enabled");
        let addr = hex::encode([0x42u8; 32]);
        // `-1:` names the masterchain: admitted on the shard-0 faucet.
        let (a, s) = resolve_faucet_recipient(&st0, &faucet0, &format!("-1:{addr}"))
            .await
            .expect("masterchain form must be servable by the shard-0 faucet");
        assert_eq!((a, s), ([0x42u8; 32], 0));
        // `0:` is the same shard, no alias, no bypass.
        let (a0, s0) = resolve_faucet_recipient(&st0, &faucet0, &format!("0:{addr}"))
            .await
            .expect("0: form must behave like -1:");
        assert_eq!((a0, s0), ([0x42u8; 32], 0));
        // Same `-1:` address against a shard-1 faucet: refused, not queued.
        let st1 = test_state_with_faucet_on_shard(10, 100, 1).await;
        let faucet1 = st1.faucet.clone().expect("faucet enabled");
        let err = resolve_faucet_recipient(&st1, &faucet1, &format!("-1:{addr}"))
            .await
            .expect_err("a masterchain recipient must be refused by the shard-1 faucet");
        assert!(err.contains("shard 1") && err.contains("shard 0"), "{err}");
        // Full RPC path: the refused shape reserves nothing.
        let r = call(&st1, "stell_faucet", drip_req(&format!("-1:{addr}"))).await;
        assert!(r["error"].is_string(), "refused drip must error: {r}");
        assert_eq!(
            st1.mempool.read().await.len(),
            0,
            "refused drip must not pend"
        );
        assert_eq!(faucet1.dispensed_to([0x42u8; 32]).await, 0);
        // ...while the servable shape on the matching faucet still works.
        let ok = call(&st0, "stell_faucet", drip_req(&format!("-1:{addr}"))).await;
        assert_eq!(ok["credited_nano"], "10", "{ok}");
        assert_eq!(ok["shard"], 0);
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
        // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
        let tx = pq_tx(0xB1, [1u8; 32], 10, 5, 0);
        // fund the sender so the balance check at admission passes
        st.engine
            .update_account(AccountState::new(tx.from, 1_000_000))
            .await;
        let raw = hex::encode(bincode::serialize(&tx).unwrap());
        let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
        assert!(r.as_str().is_some(), "valid tx must be accepted: {r}");
        assert_eq!(st.mempool.read().await.len(), 1);

        // forged signature must be rejected (tamper the trailing signature
        // bytes so the PQ envelope still parses and the verdict is the
        // signature failure, not a decode refusal).
        let mut bad = tx.clone();
        let last = bad.signature.len() - 1;
        bad.signature[last] ^= 0xFF;
        let raw_bad = hex::encode(bincode::serialize(&bad).unwrap());
        let r2 = call(&st, "stell_sendRawTransaction", json!({ "tx": raw_bad })).await;
        assert!(r2["error"].as_str().unwrap().contains("signature"));
        assert_eq!(
            st.mempool.read().await.len(),
            1,
            "forged tx must not enter mempool"
        );
    }

    /// A14 phase 1: an UNBOUND admission is still accepted, but it is
    /// metered (`stell_unbound_tx_total` +1); a BOUND admission is silent
    /// (meter untouched). The diff-based assertion is parallel-safe: the
    /// global counter moves under every test admitting unbound txs, but
    /// each test's own admissions add exactly their own count.
    #[tokio::test]
    async fn unbound_admission_is_metered_and_bound_is_silent() {
        let st = test_state().await;
        let meter = || crate::metrics::global().snapshot().unbound_tx as u64;

        // UNBOUND: admitted, metered. FULL-PQ: implicit Falcon-512, no chain.
        let tx = pq_tx(0xB2, [1u8; 32], 10, 100_000, 0);
        assert!(tx.chain_id().is_none(), "unbound PQ envelope has no chain");
        st.engine
            .update_account(AccountState::new(tx.from, 10_000_000))
            .await;
        let before = meter();
        let raw = hex::encode(bincode::serialize(&tx).unwrap());
        let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
        assert!(r.as_str().is_some(), "phase 1 still admits unbound: {r}");
        assert_eq!(
            meter(),
            before + 1,
            "one unbound admission meters exactly once"
        );

        // BOUND (PQ chain envelope): admitted, meter silent.
        // FULL-PQ: implicit Falcon-512 bound to the consensus chain id.
        let bound = pq_tx_chain(0xB3, [1u8; 32], 10, 100_000, 0, Some(5757));
        assert_eq!(bound.chain_id(), Some(5757));
        st.engine
            .update_account(AccountState::new(bound.from, 10_000_000))
            .await;
        let before2 = meter();
        let raw2 = hex::encode(bincode::serialize(&bound).unwrap());
        let r2 = call(&st, "stell_sendRawTransaction", json!({ "tx": raw2 })).await;
        assert!(r2.as_str().is_some(), "bound txs admit cleanly: {r2}");
        assert_eq!(meter(), before2, "bound admission must not touch the meter");
    }

    /// E1 confirmations rule: inclusion at height H under head N reports
    /// N - H + 1 on both `stell_getTransactionStatus` and
    /// `stell_getTransactionReceipt`; mempool-pending reports 0 on status;
    /// unknown reports null.
    #[tokio::test]
    async fn status_and_receipt_report_confirmations() {
        let st = test_state().await;
        let tx = receipt_tx(0x09, 0);
        let h = hex::encode(tx.compute_tx_hash());

        // Unknown: null confirmations.
        let unknown = call(&st, "stell_getTransactionStatus", json!(h)).await;
        assert_eq!(unknown["status"], json!("unknown"));
        assert!(
            unknown["confirmations"].is_null(),
            "unknown has no depth: {unknown}"
        );

        // Pending: 0 confirmations.
        st.mempool.write().await.add(tx.clone()).unwrap();
        let pending = call(&st, "stell_getTransactionStatus", json!(h)).await;
        assert_eq!(pending["status"], json!("pending"));
        assert_eq!(pending["confirmations"], json!(0));

        // Included at 5, head at 7 -> 3 confirmations, on both methods.
        st.record_receipts(5, [0x01; 32], std::slice::from_ref(&tx), &[true], &[1])
            .await;
        st.height.store(7, std::sync::atomic::Ordering::Relaxed);
        let done = call(&st, "stell_getTransactionStatus", json!(h)).await;
        assert_eq!(done["status"], json!("success"));
        assert_eq!(done["height"], json!(5));
        assert_eq!(done["confirmations"], json!(3), "7 - 5 + 1");
        let receipt = call(&st, "stell_getTransactionReceipt", json!(h)).await;
        assert_eq!(receipt["status"], json!("success"));
        assert_eq!(receipt["confirmations"], json!(3), "7 - 5 + 1");

        // Head advances -> depth grows.
        st.height.store(10, std::sync::atomic::Ordering::Relaxed);
        let deeper = call(&st, "stell_getTransactionStatus", json!(h)).await;
        assert_eq!(deeper["confirmations"], json!(6), "10 - 5 + 1");
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
        let tx = pq_tx(0xB4, [1u8; 32], 10, 5, 0);
        st.engine
            .update_account(AccountState::new(tx.from, 1_000_000))
            .await;
        let raw = hex::encode(bincode::serialize(&tx).unwrap());

        let r = call(&st, "stell_sendRawTransaction", json!({ "tx": raw })).await;
        assert!(r.as_str().is_some());

        // Must have been forwarded to the P2P gossip channel:
        let forwarded = tx_rx.try_recv().expect("must receive forwarded tx");
        assert_eq!(forwarded.amount, 10);
        // FULL-PQ sender: the PQ address derived from the test seed.
        let (want_from, _) = {
            let pk = crate::sharding::Transaction::sample_falcon512_pubkey(0xB4);
            (
                crate::post_quantum::derive_pq_address(
                    crate::post_quantum::PqScheme::Falcon512,
                    &pk,
                    &crate::post_quantum::DEFAULT_SALT,
                ),
                pk,
            )
        };
        assert_eq!(forwarded.from, want_from);
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
            .update_account(AccountState::new(
                sender32,
                wei_to_nano(value_wei) + 1_000_000,
            ))
            .await;

        // 1. FULL-PQ: the EVM settlement shape carries no PQ envelope, so
        // even a funded EVM tx is refused at admission (EVM settlement is
        // excised from the PQ-only intake path).
        let raw = hex::encode(sign_raw(0, value_wei));
        let r = call(&st, "eth_sendRawTransaction", json!([format!("0x{raw}")])).await;
        assert!(
            r.get("error").is_some(),
            "EVM tx must be refused in FULL-PQ mode: {r}"
        );
        assert_eq!(st.mempool.read().await.len(), 0);

        // 2. Wrong chain (chain-1 vector) is rejected, pool unchanged.
        let chain1 = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let r2 = call(
            &st,
            "eth_sendRawTransaction",
            json!([format!("0x{chain1}")]),
        )
        .await;
        assert!(
            r2.get("error").is_some(),
            "foreign chain must be rejected: {r2}"
        );
        assert_eq!(st.mempool.read().await.len(), 0);

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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
        let tx = pq_tx(0xB5, [1u8; 32], 10, 5, 0);
        st.engine
            .update_account(AccountState::new(tx.from, 1_000_000))
            .await;
        let raw = hex::encode(bincode::serialize(&tx).unwrap());

        let r = call(
            &st,
            "stell_sendRawTransaction",
            json!({ "tx": raw.clone() }),
        )
        .await;
        assert!(
            r.as_str().is_some(),
            "public signed transaction must succeed without auth token"
        );

        // Admin methods like mempool dump still require the token
        let r_dump = call(&st, "stell_mempoolDump", json!({})).await;
        assert!(r_dump["error"].as_str().unwrap().contains("unauthorized"));
        let r_dump2 = call(&st, "stell_mempoolDump", json!({ "token": "secret" })).await;
        assert!(r_dump2.as_array().is_some(), "authorized dump must succeed");
    }

    /// P5 EXPLOIT (Critical, rpc.rs `stell_deployContract` /
    /// `stell_callContract`): both arms wrote consensus state DIRECTLY over an
    /// unauthenticated RPC — `deploy_contract_deterministic` minted a contract
    /// into the engine, and `stell_callContract` ran `debit_native` /
    /// `credit_native` + executed the call inline, bypassing mempool
    /// admission, nonces and blocks entirely — with NO `auth_token` gate, while
    /// every sibling write arm (`stell_submitProposal`, `stell_vote`,
    /// `stell_submitPriceFeed`, `stell_pmmBuy/Sell`, `stell_signMessage`)
    /// required one. An unauthenticated caller minted contracts and moved
    /// native value whenever a token was configured. Fixed by gating both arms
    /// with the same token check (fail-open when unconfigured, like the rest).
    #[tokio::test]
    async fn p5_contract_arms_require_auth_token_when_configured() {
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        // No token: must be refused as unauthorized (pre-fix: fell through to
        // "missing 'code' parameter" / "missing 'contract' parameter", i.e. no
        // gate at all).
        let r_deploy = call(&st, "stell_deployContract", json!({})).await;
        assert!(
            r_deploy["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "deploy without token must be refused: {r_deploy}"
        );
        let r_call = call(&st, "stell_callContract", json!({})).await;
        assert!(
            r_call["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "call without token must be refused: {r_call}"
        );
        // Wrong token: same refusal (constant-time comparison, no oracle).
        let r_bad = call(&st, "stell_deployContract", json!({ "token": "nope" })).await;
        assert!(
            r_bad["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "deploy with wrong token must be refused: {r_bad}"
        );
        // Correct token: passes the gate (fails later on params, not on auth).
        let r_ok = call(&st, "stell_deployContract", json!({ "token": "secret" })).await;
        assert!(
            !r_ok["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "deploy with correct token must pass the gate: {r_ok}"
        );
    }

    /// N-02/N-03: contract previews require a valid token ALWAYS (no token
    /// configured at all is refused, on every bind), and a successful preview
    /// NEVER enters the mempool — it executes on a state clone, returns the
    /// result, and the tx is dropped. On-chain execution needs a separate
    /// `stell_sendRawTransaction` submission of a locally-signed tx.
    /// // GATE: N-02 token-always + N-03 preview mempool-DoS fix.
    #[tokio::test]
    async fn contract_previews_require_token_and_never_enter_mempool() {
        // 1. No token configured at all: both preview arms refuse (even the
        // keyless direct-params form), and nothing is pooled.
        let st = test_state().await;
        for (method, params) in [
            (
                "stell_deployContract",
                json!({ "code": hex::encode(sample_getter_wasm()) }),
            ),
            (
                "stell_callContract",
                json!({
                    "contract": hex::encode([0x99u8; 32]),
                    "method": "get",
                    "value": 0u64,
                }),
            ),
        ] {
            let r = call(&st, method, params).await;
            assert!(
                r["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("unauthorized"),
                "{method} with no token configured must be refused: {r}"
            );
        }
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "refused previews must not pool anything"
        );
        assert!(
            st.governance.read().await.proposals.is_empty(),
            "refused calls must not record anything"
        );

        // 2. Token configured + presented: previews succeed AND still pool
        // nothing. Fixture contract deployed engine-side (the way block
        // application materializes it).
        let st = test_state_with_token().await;
        let creator = [0xABu8; 32];
        let deployed = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();
        let root_before = st.engine.get_state_root().await;

        let deploy = call_with_token(
            &st,
            "stell_deployContract",
            json!({ "code": hex::encode(sample_getter_wasm()) }),
        )
        .await;
        assert!(
            deploy["contract_address"].is_string(),
            "token-authed deploy preview must succeed: {deploy}"
        );
        assert!(
            deploy["tx_hash"].is_string(),
            "token-authed deploy preview must return its (dropped) tx hash: {deploy}"
        );

        let previewed = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": hex::encode(deployed),
                "method": "double",
                "args": 21,
            }),
        )
        .await;
        assert_eq!(previewed["status"], json!("success"));
        assert_eq!(previewed["return_value"], json!(42));

        // The mempool is STILL empty (both previews dropped their txs) and
        // the state root is untouched (clone-only execution).
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "successful previews must never enter the mempool"
        );
        assert_eq!(
            st.engine.get_state_root().await,
            root_before,
            "previews must not move the state root"
        );

        // 3. Wrong token: same refusal, nothing pooled.
        let st2 = test_state_with_token().await;
        let r = call(
            &st2,
            "stell_callContract",
            json!({
                "contract": hex::encode(deployed),
                "method": "double",
                "args": 21,
                "token": "wrong",
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("unauthorized"),
            "wrong-token preview must be refused: {r}"
        );
        assert_eq!(st2.mempool.read().await.len(), 0);
    }

    /// H-03/H-04 (rpc.rs `stell_callContract` / `stell_deployContract`):
    /// the old `from` + `private_key` pair let a caller debit ANY account
    /// (`from=victim + private_key=attacker + value=N` drained the victim
    /// straight into the contract, even when the call itself failed). The
    /// whole key-accepting shape is gone: `private_key` is refused
    /// fail-closed on both arms, `from` is refused too (without a key the
    /// node cannot sign as the caller, so honoring it is impossible), and
    /// the arms never debit — previews simulate `value` on a clone.
    #[tokio::test]
    async fn p5_call_contract_rejects_key_material_and_spoofed_sender() {
        // N-02: previews require a token on every bind, so the key-material
        // pins run on the token fixture (the gate passes, then the
        // no-key-material checks fire).
        let st = test_state_with_token().await;
        let victim = SigningKey::from_bytes(&[0x51u8; 32]);
        let victim_addr = victim.verifying_key().to_bytes();
        st.engine
            .update_account(AccountState::new(victim_addr, 1_000_000))
            .await;
        let attacker = SigningKey::from_bytes(&[0xA7u8; 32]);
        let contract = [0x99u8; 32];
        let before = st
            .engine
            .get_account(&victim_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        assert_eq!(before, 1_000_000);
        // `private_key` is refused on the call arm (it used to select the
        // debit victim's fate via `from` + attacker key).
        let r = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": hex::encode(contract),
                "method": "get",
                "from": hex::encode(victim_addr),
                "private_key": hex::encode(attacker.to_bytes()),
                "value": 500u64,
            }),
        )
        .await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("no longer accepted"),
            "key material over RPC must be refused: {r}"
        );
        // `from` alone is refused too: without a key it cannot be honored.
        let r_from = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": hex::encode(contract),
                "method": "get",
                "from": hex::encode(victim_addr),
                "value": 500u64,
            }),
        )
        .await;
        assert!(
            r_from["error"]
                .as_str()
                .unwrap_or_default()
                .contains("no longer accepted"),
            "spoofable sender must be refused: {r_from}"
        );
        // And on the deploy arm.
        let r_deploy = call_with_token(
            &st,
            "stell_deployContract",
            json!({
                "code": hex::encode(counter_getter_wasm()),
                "private_key": hex::encode(attacker.to_bytes()),
            }),
        )
        .await;
        assert!(
            r_deploy["error"]
                .as_str()
                .unwrap_or_default()
                .contains("no longer accepted"),
            "deploy must refuse key material: {r_deploy}"
        );
        let after = st
            .engine
            .get_account(&victim_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        assert_eq!(
            after, before,
            "victim balance must be untouched by the refused calls"
        );
        // Sanity: the keyless preview is still admitted past the key checks
        // (it fails later on the unknown contract — a clone-exec failure,
        // never a signer error — and files nothing that moves value).
        let r_self = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": hex::encode(contract),
                "method": "get",
                "value": 0u64,
            }),
        )
        .await;
        assert!(
            !r_self["error"].is_string(),
            "keyless preview must pass the key checks: {r_self}"
        );
        assert_eq!(r_self["status"], json!("failed"));
        assert!(
            r_self["outcome"]["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not found"),
            "unknown contract must fail in preview: {r_self}"
        );
    }

    /// P5 EXPLOIT (Critical, rpc.rs `stell_deployContract` wrapped-tx path):
    /// the `{tx}` branch decoded the tx, deployed it as `tx.from` and admitted
    /// it to the mempool WITHOUT `verify_signature` — a forged `from` (bytes
    /// flipped after signing) deployed a contract AS THE VICTIM. Fixed by
    /// verifying the signature exactly like `stell_sendRawTransaction`.
    #[tokio::test]
    async fn p5_wrapped_deploy_rejects_forged_signature() {
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        let (victim_addr, _) = pq_pair(0xC1);
        st.engine
            .update_account(AccountState::new(victim_addr, 1_000_000))
            .await;
        let code = wat::parse_str(
            r#"(module (memory 1) (func (export "get") (param i64) (result i64) (local.get 0)))"#,
        )
        .expect("test wat compiles");
        // FULL-PQ: implicit Falcon-512 deploy vehicle.
        let mut forged = pq_tx_payload(
            0xC1,
            victim_addr,
            0,
            10_000,
            0,
            vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
        );
        // Flip the claimed sender AFTER signing: the bytes no longer match the
        // signature. Pre-fix this deployed as [0x52; 32] with no complaint.
        forged.from = [0x52u8; 32];
        let raw = hex::encode(bincode::serialize(&forged).unwrap());
        let r = call(
            &st,
            "stell_deployContract",
            json!({ "tx": raw, "token": "secret" }),
        )
        .await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("signature"),
            "forged wrapped deploy must fail signature verification: {r}"
        );
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "forged deploy must not land in the mempool"
        );
    }

    /// A feed submission is a WRITE-shaped method: same token gate as
    /// `stell_sendRawTransaction`, and it is THIN - it admits the wrapping
    /// transaction to the mempool and must not touch consensus state. The
    /// price only exists once a block carries it.
    /// FULL-PQ: classical ed25519 feed verification is REMOVED (no PQ feed
    /// path exists in this zone; `PriceFeedUpdate::verify` is always false),
    /// so even a well-formed classical feed is refused fail-closed. The
    /// token gate still fires first, and the refusal still writes nothing.
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        // FULL-PQ: the wrapping tx is implicit Falcon-512; the feed itself
        // stays publisher-signed (oracle path, outside tx admission).
        let (from, _) = pq_pair(0xC2);
        st.engine
            .update_account(AccountState::new(from, 1_000_000))
            .await;
        let publisher = SigningKey::from_bytes(&[0x42u8; 32]);
        let feed =
            crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
        let tx = pq_tx_payload(
            0xC2,
            from,
            0,
            10_000,
            0,
            vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
        );
        let raw = hex::encode(bincode::serialize(&tx).unwrap());

        // Gated by the SAME token as sendRawTransaction.
        let denied = call(&st, "stell_submitPriceFeed", json!({ "tx": raw.clone() })).await;
        assert!(denied["error"].as_str().unwrap().contains("unauthorized"));
        let denied2 = call(
            &st,
            "stell_submitPriceFeed",
            json!({ "tx": raw.clone(), "token": "nope" }),
        )
        .await;
        assert!(denied2["error"].as_str().unwrap().contains("unauthorized"));

        // Thin: admitted, gossiped, and NOT written into state.
        // FULL-PQ: the classical feed never verifies, so the authorized
        // submission is refused fail-closed (nothing admitted, nothing
        // written) — the THIN half of the property survives.
        let root_before = st.engine.get_state_root().await;
        let ok = call(
            &st,
            "stell_submitPriceFeed",
            json!({ "tx": raw.clone(), "token": "secret" }),
        )
        .await;
        assert!(
            ok["error"]
                .as_str()
                .unwrap_or_default()
                .contains("validly signed price feed"),
            "FULL-PQ: classical feed must be refused fail-closed: {ok}"
        );
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "refused feed must not enter the mempool"
        );
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
        let plain = pq_tx(0xC2, from, 1, 1_000, 1);
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
        // FULL-PQ: swapping the payload after the wrapper was signed breaks
        // the WRAPPER signature, so the wrapper check fires first — still a
        // refusal with nothing pooled.
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
        assert_eq!(st.mempool.read().await.len(), 0, "nothing else got in");
    }

    /// Nonce-gap fail-fast must cover the shared `stell_submit*` admission
    /// helper too (audit: blocks troubles): a far-future nonce via
    /// `stell_submitPriceFeed` is refused exactly like via
    /// `stell_sendRawTransaction`, instead of clogging the pool behind an
    /// unreachable head.
    /// FULL-PQ: no classical feed verifies (no PQ feed path in this zone),
    /// so the signed-feed gate fires BEFORE the nonce-gap check — the gapped
    /// wrapper is refused as an unsigned feed, still with nothing pooled.
    /// Nonce-gap ordering itself stays pinned at the mempool choke point
    /// (`nonce_gap_rejects_far_future_at_admission`).
    #[tokio::test]
    async fn submit_price_feed_rejects_far_future_nonce() {
        let st = test_state().await;
        // FULL-PQ: implicit Falcon-512 wrapper; feed stays publisher-signed.
        let (from, _) = pq_pair(0xC3);
        st.engine
            .update_account(AccountState::new(from, 1_000_000))
            .await;
        let publisher = SigningKey::from_bytes(&[0x42u8; 32]);
        let feed =
            crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &publisher);
        let gapped = pq_tx_payload(
            0xC3,
            from,
            0,
            10_000,
            crate::mempool::Mempool::NONCE_FUTURE_WINDOW + 5,
            vec![crate::svm::OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
        );
        let r = call(
            &st,
            "stell_submitPriceFeed",
            json!({ "tx": hex::encode(bincode::serialize(&gapped).unwrap()) }),
        )
        .await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("validly signed price feed"),
            "far-future-nonce payload tx must be refused: {r}"
        );
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "gapped tx must not enter mempool"
        );
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        let r = call(&st, "stell_mempoolDump", json!({})).await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
            "anonymous mempool dump must be refused: {r}"
        );
        let r2 = call(&st, "stell_mempoolDump", json!({ "token": "secret" })).await;
        assert!(r2.is_array(), "authorized dump must return the list: {r2}");

        // Fail-closed test: when auth_token is None, mempoolDump MUST refuse
        let st_no_token = test_state().await;
        let r_fail_closed = call(&st_no_token, "stell_mempoolDump", json!({})).await;
        assert!(
            r_fail_closed["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unauthorized"),
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

    #[test]
    fn parse_hash_and_addr_validate_length() {
        assert!(parse_hash("0x00").is_err());
        assert!(parse_hash("00").is_err());
        assert!(parse_addr("0x00").is_err());
        assert!(parse_addr("00").is_err());
        let good = hex::encode([7u8; 32]);
        assert_eq!(parse_hash(&good).unwrap(), [7u8; 32]);
        assert_eq!(parse_hash(&format!("0x{good}")).unwrap(), [7u8; 32]);
        assert_eq!(parse_addr(&good).unwrap(), [7u8; 32]);
        assert_eq!(parse_addr(&format!("0x{good}")).unwrap(), [7u8; 32]);
    }

    // ------------------------------------------------------------------
    // `stell_getProof`
    // ------------------------------------------------------------------

    /// FULL-PQ anchoring QC for the light-client fixtures: a Falcon µQC
    /// envelope (the green `qc_verification_*` idiom from the consensus
    /// tests) plus the plain voter entry the light-client power pre-check
    /// counts. The entry payload is inert metadata — the envelope is the
    /// proof. Single-member set: the committee IS the validator.
    fn pq_anchor_cert(
        val_id: [u8; 32],
        fk: &crate::post_quantum::FalconKeypair,
        validators: &crate::consensus::ValidatorSet,
        height: u64,
        block_hash: [u8; 32],
    ) -> crate::consensus::QuorumCertificate {
        use crate::consensus::{
            derive_sortition_committee, encode_pq_micro_envelope, micro_committee_size,
            vote_sign_bytes, PqMicroCertificate, QuorumCertificate, VoteKind,
            PQ_UQC_MARKER_ID,
        };
        let parent = [0u8; 32];
        let committee_size = micro_committee_size(validators.len());
        let committee =
            derive_sortition_committee(validators, height, 0, committee_size, &parent);
        let msg = vote_sign_bytes(height, 0, VoteKind::Precommit, &Some(block_hash));
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut msigs = Vec::new();
        for (i, id) in committee.iter().enumerate() {
            assert_eq!(
                *id, val_id,
                "single-member fixture: the committee is the validator"
            );
            bitmask[i / 8] |= 1 << (i % 8);
            msigs.push(fk.sign(&msg));
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            0,
            committee_size,
            bitmask,
            msigs,
            parent,
        );
        QuorumCertificate {
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: vec![
                (val_id, fk.sign(&msg)),
                (PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc)),
            ],
        }
    }

    /// A light client that trusts `state_root` — the same root the node
    /// serves — so the node's answer can be checked against a trusted header.
    /// FULL-PQ: the anchor carries the Falcon µQC above (a classical
    /// vote-list QC no longer verifies).
    fn light_client_for(state_root: [u8; 32]) -> crate::light_client::LightClient {
        use crate::consensus::ValidatorSet;
        let fk = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
        let val_id = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        );
        crate::consensus::register_validator_pq_key(
            val_id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        let validators = ValidatorSet::from_list(vec![(val_id, 1)]);
        let block_hash = [0x88u8; 32];
        let cert = pq_anchor_cert(val_id, &fk, &validators, 1, block_hash);
        let checkpoint =
            crate::light_client::Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
        crate::light_client::LightClient::new(validators, checkpoint).expect("light client")
    }

    #[tokio::test]
    async fn get_proof_serves_an_account_proof_that_a_light_client_verifies() {
        let st = test_state().await;
        let who = [0x42u8; 32];
        st.engine
            .update_account(AccountState::new(who, 1_000_000_000_000))
            .await;

        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode(who) }),
        )
        .await;
        assert!(r.get("error").is_none(), "proof request must succeed: {r}");
        assert_eq!(r["address"], json!(hex::encode(who)));
        assert_eq!(r["balance"], json!(1_000_000_000_000u64));
        assert_eq!(r["nonce"], json!(0u64));
        let root_hex = r["state_root"].as_str().expect("state root");
        assert_eq!(root_hex.len(), 64, "state root is 32 bytes of hex");
        assert!(r["storage_proofs"].as_array().is_some());

        // The proof nodes are hex strings, and the leaf node carries the value
        // the proof commits to.
        let nodes: Vec<String> = r["account_proof"]
            .as_array()
            .expect("account proof array")
            .iter()
            .map(|n| n.as_str().expect("hex node").to_string())
            .collect();
        assert!(!nodes.is_empty(), "an account in the trie has a proof");
        let proof = crate::cpat2::MerkleProof::from_nodes(&nodes).expect("proof parses");
        assert_eq!(proof.kind, crate::cpat2::ProofKind::Inclusion);
        assert_eq!(proof.key, who);

        // It verifies against the root the node reported ...
        let root: [u8; 32] = hex::decode(root_hex).unwrap().try_into().unwrap();
        assert!(crate::cpat2::verify_proof(
            &root,
            &who,
            &proof.value,
            &proof
        ));

        // ... and a light client that trusts that root reaches the same
        // conclusion from the same answer.
        let lc = light_client_for(root);
        let answer = crate::light_client::ProofAnswer::from_json(&r).expect("answer parses");
        let proven = lc.verify_proof_answer(&answer).expect("answer must verify");
        assert_eq!(proven.balance, 1_000_000_000_000);
        assert_eq!(proven.nonce, 0);
        assert!(proven.exists);
        assert_eq!(proven.height, 1);
    }

    #[tokio::test]
    async fn get_proof_proves_absence_for_an_unknown_account() {
        let st = test_state().await;
        let known = [0x42u8; 32];
        st.engine.update_account(AccountState::new(known, 7)).await;

        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode([0x99u8; 32]) }),
        )
        .await;
        assert!(r.get("error").is_none(), "proof request must succeed: {r}");
        assert_eq!(r["balance"], json!(0u64));
        assert_eq!(r["nonce"], json!(0u64));
        assert_eq!(r["exists"], json!(false));

        // The absence is PROVEN, not merely reported: the proof is an
        // exclusion proof and it verifies against the served root.
        let root: [u8; 32] = hex::decode(r["state_root"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nodes: Vec<String> = r["account_proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        assert!(
            !nodes.is_empty(),
            "an absent key still gets an exclusion proof"
        );
        let proof = crate::cpat2::MerkleProof::from_nodes(&nodes).expect("proof parses");
        assert_eq!(proof.kind, crate::cpat2::ProofKind::Exclusion);
        assert!(crate::cpat2::verify_exclusion_proof(
            &root,
            &[0x99u8; 32],
            &proof
        ));

        // And the light client agrees: the account is absent, with a proven
        // zero rather than a shrug.
        let lc = light_client_for(root);
        let answer = crate::light_client::ProofAnswer::from_json(&r).expect("answer parses");
        let proven = lc.verify_proof_answer(&answer).expect("answer must verify");
        assert!(!proven.exists);
        assert_eq!(proven.balance, 0);
    }

    #[tokio::test]
    async fn get_proof_accepts_a_branded_address() {
        let st = test_state().await;
        let who = [0x42u8; 32];
        st.engine.update_account(AccountState::new(who, 5)).await;
        let branded = crate::address::encode_stl57_address(&who);

        let r = call(&st, "stell_getProof", json!({ "address": branded })).await;
        assert!(
            r.get("error").is_none(),
            "branded address must be accepted: {r}"
        );
        assert_eq!(r["address"], json!(hex::encode(who)));
        assert_eq!(r["balance"], json!(5u64));
    }

    #[tokio::test]
    async fn get_proof_rejects_a_bad_address() {
        let st = test_state().await;
        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": "not-an-address" }),
        )
        .await;
        assert!(r["error"].as_str().unwrap().contains("bad address"));
        let r2 = call(&st, "stell_getProof", json!({})).await;
        assert!(r2["error"].as_str().unwrap().contains("missing address"));
    }

    #[tokio::test]
    async fn get_proof_serves_storage_proofs() {
        let st = test_state().await;
        let who = [0x42u8; 32];
        st.engine.update_account(AccountState::new(who, 1)).await;
        // A raw state-trie key, the way a caller would name a storage slot.
        let slot = [0x5Au8; 32];
        st.engine
            .state_trie
            .write()
            .await
            .insert(&slot, b"slot-value");

        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode(who), "storage_keys": [hex::encode(slot)] }),
        )
        .await;
        assert!(r.get("error").is_none(), "proof request must succeed: {r}");
        let sp = &r["storage_proofs"][0];
        assert_eq!(sp["key"], json!(hex::encode(slot)));
        assert_eq!(sp["exists"], json!(true));
        assert_eq!(sp["value"], json!(hex::encode(b"slot-value")));

        let root: [u8; 32] = hex::decode(r["state_root"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let lc = light_client_for(root);
        let answer = crate::light_client::ProofAnswer::from_json(&r).expect("answer parses");
        let proven = lc.verify_proof_answer(&answer).expect("answer must verify");
        assert_eq!(proven.storage.len(), 1);
        assert!(proven.storage[0].exists);
        assert_eq!(proven.storage[0].value.as_deref(), Some(&b"slot-value"[..]));
    }

    #[tokio::test]
    async fn get_proof_proves_an_absent_storage_key() {
        let st = test_state().await;
        let who = [0x42u8; 32];
        st.engine.update_account(AccountState::new(who, 1)).await;
        let missing = [0x6Bu8; 32];

        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode(who), "storage_keys": [hex::encode(missing)] }),
        )
        .await;
        let sp = &r["storage_proofs"][0];
        assert_eq!(sp["exists"], json!(false));
        assert!(sp["value"].is_null());
        assert!(
            !sp["proof"].as_array().unwrap().is_empty(),
            "absence is proven"
        );
    }

    #[tokio::test]
    async fn get_proof_refuses_a_height_it_cannot_serve() {
        let st = test_state().await;
        // The node serves height 42 and keeps no historical state.
        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode([0x42u8; 32]), "block_height": 7 }),
        )
        .await;
        assert!(r["error"].as_str().unwrap().contains("historical state"));

        // The height it does serve is accepted.
        let ok_r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode([0x42u8; 32]), "block_height": 42 }),
        )
        .await;
        assert!(
            ok_r.get("error").is_none(),
            "current height must be served: {ok_r}"
        );
        assert_eq!(ok_r["height"], json!(42u64));
    }

    #[tokio::test]
    async fn get_proof_caps_the_number_of_storage_keys() {
        let st = test_state().await;
        let keys: Vec<String> = (0..=MAX_PROOF_STORAGE_KEYS)
            .map(|i| hex::encode([i as u8; 32]))
            .collect();
        let r = call(
            &st,
            "stell_getProof",
            json!({ "address": hex::encode([0x42u8; 32]), "storage_keys": keys }),
        )
        .await;
        assert!(r["error"]
            .as_str()
            .unwrap()
            .contains("too many storage keys"));
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
        let r = call(
            &st,
            "stell_tokenSupply",
            json!({ "token": hex::encode(id) }),
        )
        .await;
        assert_eq!(r, "1000");
        let rb = call(
            &st,
            "stell_tokenBalance",
            json!({ "token": hex::encode(id), "account": hex::encode(who) }),
        )
        .await;
        assert_eq!(rb, "1000");
    }

    #[tokio::test]
    async fn faucet_reconcile_fills_gaps_atomically() {
        // Reserved-but-never-executed nonces (wiped mempool) must not strand
        // later drips: reconcile takes mex(on-chain, pending).
        let f = Faucet::new([9u8; 32], 1, 10, 25);
        // Gap: on-chain 5, pending {7} (5,6 lost) -> must take 5, then 6.
        let (t1, _) = f
            .build_transfer([1u8; 32], None, Some((5, vec![7])))
            .await
            .unwrap();
        assert_eq!(t1.nonce, 5);
        // Pending {5} now (just built, pretend admitted): next is 6.
        let (t2, _) = f
            .build_transfer([2u8; 32], None, Some((5, vec![5, 7])))
            .await
            .unwrap();
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });
        // FULL-PQ: implicit Falcon-512 wrapper (registered globally).
        let (from, _) = pq_pair(0xC8);
        st.engine
            .update_account(AccountState::new(from, 1_000_000))
            .await;

        let buy = pq_tx_payload(
            0xC8,
            from,
            0,
            crate::svm::GAS_PMM_BUY,
            0,
            vec![crate::svm::OpCode::SysCallPmmBuy {
                usdt_micro: 250_000,
            }],
        );
        let buy_raw = hex::encode(bincode::serialize(&buy).unwrap());

        // Gated by the SAME token as sendRawTransaction.
        let denied = call(&st, "stell_pmmBuy", json!({ "tx": buy_raw.clone() })).await;
        assert!(denied["error"].as_str().unwrap().contains("unauthorized"));
        let denied2 = call(
            &st,
            "stell_pmmBuy",
            json!({ "tx": buy_raw.clone(), "token": "nope" }),
        )
        .await;
        assert!(denied2["error"].as_str().unwrap().contains("unauthorized"));

        // Thin: admitted and NOT written into state - the curve has not moved.
        let root_before = st.engine.get_state_root().await;
        let ok = call(
            &st,
            "stell_pmmBuy",
            json!({ "tx": buy_raw.clone(), "token": "secret" }),
        )
        .await;
        assert!(
            ok.as_str().is_some(),
            "authorized buy must be admitted: {ok}"
        );
        assert_eq!(
            st.mempool.read().await.len(),
            1,
            "it belongs in the mempool"
        );
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
        let wrong = call(
            &st,
            "stell_pmmSell",
            json!({ "tx": buy_raw.clone(), "token": "secret" }),
        )
        .await;
        assert!(
            wrong["error"].as_str().unwrap().contains("SysCallPmmSell"),
            "a non-sell transaction must not be admitted under stell_pmmSell: {wrong}"
        );
        assert_eq!(
            st.mempool.read().await.len(),
            1,
            "the wrong arm admitted nothing"
        );

        // The matching sell payload is admitted the same thin way.
        let sell = pq_tx_payload(
            0xC8,
            from,
            0,
            crate::svm::GAS_PMM_SELL,
            1,
            vec![crate::svm::OpCode::SysCallPmmSell { stell_nano: 1_000 }],
        );
        let ok2 = call(
            &st,
            "stell_pmmSell",
            json!({ "tx": hex::encode(bincode::serialize(&sell).unwrap()), "token": "secret" }),
        )
        .await;
        assert!(
            ok2.as_str().is_some(),
            "authorized sell must be admitted: {ok2}"
        );
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
        let txs = vec![receipt_tx(11, 0), receipt_tx(12, 1)];
        let bh = [0xBBu8; 32];
        proposer
            .record_receipts(77, bh, &txs, &[true, false], &[1, 0])
            .await;
        proposer.record_block(77, bh, txs.len(), 1_000).await;
        // Adopter path (verified body + single-apply statuses, behind finalization).
        adopter
            .record_adopted_block(77, bh, &txs, &[true, false], &[1, 0], 1_000)
            .await;

        for st in [&proposer, &adopter] {
            let blk = call(st, "stell_getBlock", json!({ "height": 77 })).await;
            assert_eq!(blk["txs"], json!(2), "no txs=0 view on either node");
            assert_eq!(blk["hash"], json!(hex::encode(bh)));
            let r0 = call(
                st,
                "stell_getTransactionReceipt",
                json!(hex::encode(txs[0].compute_tx_hash())),
            )
            .await;
            assert_eq!(
                (r0["height"].as_u64(), r0["status"].as_str()),
                (Some(77), Some("success"))
            );
            let txs_r = call(st, "stell_getBlockTransactions", json!({ "height": 77 })).await;
            assert_eq!(txs_r["txs"].as_array().map(|a| a.len()), Some(2));
        }
        // Byte-level receipt equality between the two nodes.
        let p = proposer
            .receipts
            .read()
            .await
            .get(&txs[1].compute_tx_hash())
            .unwrap()
            .clone();
        let a = adopter
            .receipts
            .read()
            .await
            .get(&txs[1].compute_tx_hash())
            .unwrap()
            .clone();
        assert_eq!(p.height, a.height);
        assert_eq!(p.block_hash, a.block_hash);
        assert_eq!((p.index, p.success), (a.index, a.success));
        assert_eq!(
            (p.fee_charged, a.fee_charged),
            (0, 0),
            "failed txs carry a zero charge on both"
        );
        assert_eq!(
            call(
                &proposer,
                "stell_getTransactionReceipt",
                json!(hex::encode(txs[0].compute_tx_hash()))
            )
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
        assert_eq!(
            r["base_fee"],
            json!("560"),
            "floor tracks the live mempool: {r}"
        );
    }

    #[tokio::test]
    async fn get_shards_serves_the_local_chain_topology() {
        // The wallet/indexer question the audit flagged: "which shards are
        // there, and where is each one?". On a single-chain node the answer is
        // the one shard this node runs, at this node's own head.
        let st = test_state().await;
        st.record_block(42, [0xAAu8; 32], 3, 1_000).await;

        let r = call(&st, "stell_getShards", json!({})).await;
        assert_eq!(r["total_shards"], json!(1), "one chain => one shard: {r}");
        assert_eq!(
            r["routing_prefix_bits"],
            json!(0),
            "a single shard needs no routing bit"
        );
        let shards = r["shards"].as_array().expect("shards array").clone();
        assert_eq!(shards.len(), 1);
        let s0 = &shards[0];
        assert_eq!(s0["shard_id"], json!(0));
        assert_eq!(s0["type"], json!("masterchain"));
        assert_eq!(
            s0["tip_height"],
            json!(42),
            "the tip height is the node's own height"
        );
        assert_eq!(
            s0["tip_hash"],
            json!(hex::encode([0xAAu8; 32])),
            "the tip hash is the committed head"
        );
        assert_eq!(
            s0["state_root"],
            json!(hex::encode(st.engine.get_state_root().await)),
            "the state root is the live trie root"
        );
        assert_eq!(
            s0["local"],
            json!(true),
            "the shard this node runs is marked local"
        );
    }

    #[tokio::test]
    async fn get_shards_reports_every_committed_shard_head() {
        // Two shards committed by THIS process (the masterchain and a
        // workchain): both must be listed with their own committed head, and
        // the layout must report the routing width a client needs.
        let st = test_state().await;
        let reg = Arc::new(std::sync::RwLock::new(
            crate::sharding::FinalizedHeaderRegistry::default(),
        ));
        st.engine.with_finalized_headers(reg.clone());
        {
            let mut w = reg.write().unwrap();
            w.note_finalized_commitment(crate::sharding::ShardHeaderCommitment {
                shard_id: crate::sharding::MASTERCHAIN_SHARD,
                height: 285_028,
                block_hash: [0x11u8; 32],
                state_root: [0x22u8; 32],
                timestamp: 1_700_000_000,
            });
            w.note_finalized_commitment(crate::sharding::ShardHeaderCommitment {
                shard_id: crate::sharding::BASE_WORKCHAIN_SHARD_INITIAL,
                height: 63_400,
                block_hash: [0x33u8; 32],
                state_root: [0x44u8; 32],
                timestamp: 1_700_000_001,
            });
        }

        let r = call(&st, "stell_getShards", json!({})).await;
        assert_eq!(
            r["total_shards"],
            json!(2),
            "both committed shards are listed: {r}"
        );
        assert_eq!(
            r["routing_prefix_bits"],
            json!(1),
            "two shards need exactly one routing bit"
        );
        let shards = r["shards"].as_array().expect("shards array").clone();
        assert_eq!(shards.len(), 2);

        let mc = &shards[0];
        assert_eq!(mc["shard_id"], json!(0));
        assert_eq!(mc["type"], json!("masterchain"));
        assert_eq!(mc["tip_height"], json!(285_028));
        assert_eq!(mc["tip_hash"], json!(hex::encode([0x11u8; 32])));
        assert_eq!(mc["state_root"], json!(hex::encode([0x22u8; 32])));

        let wc = &shards[1];
        assert_eq!(wc["shard_id"], json!(1));
        assert_eq!(wc["type"], json!("workchain"));
        assert_eq!(wc["tip_height"], json!(63_400));
        assert_eq!(wc["tip_hash"], json!(hex::encode([0x33u8; 32])));
        assert_eq!(wc["state_root"], json!(hex::encode([0x44u8; 32])));
        assert_eq!(
            wc["local"],
            json!(false),
            "the sibling shard is not the local one"
        );
    }

    #[tokio::test]
    async fn get_shards_refuses_a_height_above_the_tip() {
        // Never fabricate: a height this node has not reached is a miss, not
        // an answer with the current head pasted into it.
        let st = test_state().await;
        st.record_block(42, [0xAAu8; 32], 0, 1_000).await;

        let bad = call(&st, "stell_getShards", json!({ "height": 999_999 })).await;
        let msg = bad["error"]
            .as_str()
            .unwrap_or_else(|| panic!("expected an error, got {bad}"));
        assert!(
            msg.contains("above this node's tip"),
            "unexpected message: {msg}"
        );

        // A height at or below the tip is accepted and answered with the
        // current topology.
        let ok_r = call(&st, "stell_getShards", json!({ "height": 42 })).await;
        assert_eq!(
            ok_r["total_shards"],
            json!(1),
            "the topology is still served: {ok_r}"
        );
        assert!(
            ok_r.get("error").is_none(),
            "no error for a reachable height"
        );
    }

    /// A finalized two-height chain with a full snapshot at `H`: the state
    /// this test's archive RPC arms prove history from.
    struct ArchiveFixture {
        dir: std::path::PathBuf,
        store: Arc<crate::storage::Storage>,
        height: u64,
        tip: u64,
        root: [u8; 32],
        account: [u8; 32],
        signer: SigningKey,
    }

    async fn archive_fixture() -> (Arc<RpcState>, ArchiveFixture) {
        use crate::sharding::{Block, MASTERCHAIN_SHARD};
        use crate::state_engine::AccountState;

        let dir = std::env::temp_dir().join(format!(
            "stell_rpc_archive_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let store = Arc::new(crate::storage::Storage::open(&dir).unwrap());
        let signer = SigningKey::generate(&mut OsRng);
        // FULL-PQ: the proposer id's Falcon key is registered globally so
        // the anchoring µQC below verifies (the `qc_verification_*` idiom
        // from the consensus tests).
        let falcon = crate::post_quantum::FalconKeypair::generate();
        crate::consensus::register_validator_pq_key(
            signer.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            falcon.public_key.clone(),
        );

        let engine = Arc::new(InMemoryStateEngine::new());
        let account = [0xA1u8; 32];
        engine
            .update_account(AccountState::new(account, 1_000))
            .await;
        engine
            .update_account(AccountState::new([0xB2u8; 32], 7))
            .await;
        let root = engine.get_state_root().await;

        let height = 10u64;
        let tip = height + 1;
        store
            .put_state(height, &engine.create_snapshot().await)
            .unwrap();
        let domains = crate::storage::DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        store
            .put_domains(height, &bincode::serialize(&domains).unwrap())
            .unwrap();
        store
            .put_session_keys(height, &engine.session_keys_snapshot().await)
            .unwrap();
        store
            .put_bridge(height, &engine.bridge_snapshot().await)
            .unwrap();
        store
            .put_zkml_models(height, &engine.zkml_models_snapshot().await)
            .unwrap();

        let mk = |h: u64, prev: [u8; 32], state_root: [u8; 32]| {
            let order_root = crate::mev::compute_order_merkle_root(&[]);
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height: h,
                prev_hash: prev,
                state_root,
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: h,
                proposer: signer.verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: order_root,
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            b.sign_block(&signer);
            b
        };
        let b_h = mk(height, [0u8; 32], [0xAAu8; 32]);
        let h_h = store.put_block(&b_h).unwrap();
        let mut b_next = mk(tip, h_h, root);
        let h_next = b_next.compute_hash();
        // FULL-PQ: the anchoring QC is the Falcon µQC (a classical
        // vote-list QC no longer verifies).
        let val_id = signer.verifying_key().to_bytes();
        let vset =
            crate::consensus::ValidatorSet::from_list(vec![(val_id, 1)]);
        let cert = pq_anchor_cert(val_id, &falcon, &vset, tip, h_next);
        b_next.precommit_qc = Some(cert);
        store.put_block(&b_next).unwrap();
        store.set_finalized(tip, &h_next).unwrap();

        let base = test_state().await;
        let st = Arc::new(RpcState {
            engine: base.engine.clone(),
            mempool: base.mempool.clone(),
            height: Arc::new(std::sync::atomic::AtomicU64::new(tip)),
            node_id: base.node_id.clone(),
            chain_id: base.chain_id,
            staking: base.staking.clone(),
            governance: base.governance.clone(),
            recent_blocks: base.recent_blocks.clone(),
            receipts: base.receipts.clone(),
            auth_token: base.auth_token.clone(),
            tx_broadcast: base.tx_broadcast.clone(),
            faucet: None,
            faucet_token: None,
            msg_signing_seed: None,
            archive_store: Some(store.clone()),
            shard_registry: ShardRegistry::single(),
        });
        (
            st,
            ArchiveFixture {
                dir,
                store,
                height,
                tip,
                root,
                account,
                signer,
            },
        )
    }

    #[tokio::test]
    async fn archive_proof_rpc_serves_history_and_root_authenticates_it() {
        use crate::consensus::ValidatorSet;
        use crate::light_client::{Checkpoint, LightClient};

        let (st, f) = archive_fixture().await;

        // Inclusion proof for the snapshotted account.
        let r = call(
            &st,
            "stell_getArchiveProof",
            json!({ "address": hex::encode(f.account), "height": f.height }),
        )
        .await;
        assert!(
            r.get("error").is_none(),
            "archive proof must be served: {r}"
        );
        assert_eq!(r["height"], json!(f.height));
        assert_eq!(r["state_root"], json!(hex::encode(f.root)));
        assert_eq!(r["proof_type"], json!("inclusion"));
        let proof = crate::cpat2::ArchiveProof::from_json(&r).expect("parse");
        assert!(
            proof.verify(),
            "served proof must verify against the historical root"
        );

        // Exclusion proof for an absent key, via the explicit `key` slot.
        let missing = [0xEEu8; 32];
        let r = call(
            &st,
            "stell_getArchiveProof",
            json!({
                "address": hex::encode(f.account),
                "key": hex::encode(missing),
                "height": f.height,
            }),
        )
        .await;
        assert_eq!(
            r["proof_type"],
            json!("exclusion"),
            "absent key proves absence: {r}"
        );
        let proof = crate::cpat2::ArchiveProof::from_json(&r).expect("parse");
        assert!(proof.verify());

        // The historical root, authenticated by the anchoring QC: parse into
        // a checkpoint, verify under OUR OWN validator set, adopt it, then
        // verify the archive proof against it — the full client path.
        let r = call(
            &st,
            "stell_getHistoricalRoot",
            json!({ "height": f.height }),
        )
        .await;
        assert!(
            r.get("error").is_none(),
            "historical root must be served: {r}"
        );
        assert_eq!(r["height"], json!(f.height));
        assert_eq!(r["state_root"], json!(hex::encode(f.root)));
        assert_eq!(r["finalized"], json!(true));
        let cp = Checkpoint::from_historical_root_json(&r).expect("parse checkpoint");
        let val_id = f.signer.verifying_key().to_bytes();
        let vset = ValidatorSet::from_list(vec![(val_id, 1)]);
        cp.verify(&vset)
            .expect("the QC must verify under our own set");
        let lc = LightClient::new(vset, cp).expect("anchor");
        let proven = lc
            .verify_archive_proof_json(
                &call(
                    &st,
                    "stell_getArchiveProof",
                    json!({ "address": hex::encode(f.account), "height": f.height }),
                )
                .await,
            )
            .expect("archive proof must verify against the adopted historical root");
        assert!(proven.exists);
        assert_eq!(proven.archive_height, f.height);

        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[tokio::test]
    async fn archive_arms_fail_closed_without_a_store_and_above_the_tip() {
        let (st, f) = archive_fixture().await;

        // No store attached: honest refusal, not a memory proof relabeled.
        let bare = test_state().await;
        let r = call(
            &bare,
            "stell_getArchiveProof",
            json!({ "address": hex::encode(f.account), "height": f.height }),
        )
        .await;
        assert!(r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no durable store"));
        let r = call(
            &bare,
            "stell_getHistoricalRoot",
            json!({ "height": f.height }),
        )
        .await;
        assert!(r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no durable store"));

        // Above the tip: refused, never fabricated.
        let r = call(
            &st,
            "stell_getArchiveProof",
            json!({ "address": hex::encode(f.account), "height": f.tip + 100 }),
        )
        .await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("above the tip"),
            "{r}"
        );
        let r = call(
            &st,
            "stell_getHistoricalRoot",
            json!({ "height": f.tip + 100 }),
        )
        .await;
        assert!(
            r["error"]
                .as_str()
                .unwrap_or_default()
                .contains("above the tip"),
            "{r}"
        );

        // Unknown height (never snapshotted, nothing retained): refused.
        let r = call(
            &st,
            "stell_getHistoricalRoot",
            json!({ "height": f.tip + 1 }),
        )
        .await;
        assert!(
            r["error"].is_string(),
            "an unanchored height must be an error: {r}"
        );

        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[tokio::test]
    async fn archive_proof_rpc_refuses_a_pruned_height() {
        use crate::state_engine::AccountState;

        let (st, f) = archive_fixture().await;
        // Age the chain past the fixture snapshot, then prune below the new
        // snapshot: the old height's data is gone for good.
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new([0x77u8; 32], 5))
            .await;
        let later = f.height + 10;
        f.store
            .put_state(later, &engine.create_snapshot().await)
            .unwrap();
        let domains = crate::storage::DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        f.store
            .put_domains(later, &bincode::serialize(&domains).unwrap())
            .unwrap();
        f.store.prune_state_below(later).unwrap();
        f.store.prune_domains_below(later).unwrap();

        let r = call(
            &st,
            "stell_getArchiveProof",
            json!({ "address": hex::encode(f.account), "height": f.height }),
        )
        .await;
        let msg = r["error"]
            .as_str()
            .unwrap_or_else(|| panic!("a pruned height must be refused, got {r}"));
        assert!(
            msg.contains("pruned") || msg.contains("no state snapshot"),
            "refusal must say the height is pruned, got: {msg}"
        );
        std::fs::remove_dir_all(&f.dir).ok();
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
        assert!(
            blk["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not available yet"),
            "{blk}"
        );
        let txs = call(
            &st,
            "stell_getBlockTransactions",
            json!({ "height": 999_999 }),
        )
        .await;
        assert!(
            txs["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not available yet"),
            "{txs}"
        );
        let rcpt = call(
            &st,
            "stell_getTransactionReceipt",
            json!(hex::encode([0xDDu8; 32])),
        )
        .await;
        assert_eq!(
            rcpt["status"],
            json!("unknown"),
            "unknown tx is honestly unknown"
        );
        assert_eq!(
            st.height.load(std::sync::atomic::Ordering::Relaxed),
            h_before
        );
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
        // FULL-PQ: receipt fixture is implicit Falcon-512; the block
        // proposer key stays classical (block path untouched).
        let tx = receipt_tx(0xC5, 0);
        let transactions = vec![tx.clone()];
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut b = crate::sharding::Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 31,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: 555,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(&sk);
        let bh = b.compute_hash();
        store.put_block(&b).unwrap();
        store
            .put_receipts_for_block(31, &bh, &b.transactions, &[true], &[1])
            .unwrap();

        let st = test_state().await;
        hydrate_rpc_from_store(&st, &store).await;
        let r = call(
            &st,
            "stell_getTransactionReceipt",
            json!(hex::encode(tx.compute_tx_hash())),
        )
        .await;
        assert_eq!(
            (r["height"].as_u64(), r["status"].as_str()),
            (Some(31), Some("success"))
        );
        let blk = call(&st, "stell_getBlock", json!({ "height": 31 })).await;
        assert_eq!(
            blk["txs"],
            json!(1),
            "hydrated window serves the real tx count"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ==================== stell_runGetMethod Tests ====================

    fn sample_getter_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (func (export "double") (param $x i64) (result i64)
                   (i64.mul (local.get $x) (i64.const 2)))
                 (func (export "answer") (result i64)
                   (i64.const 42))
                 (func (export "add") (param $a i64) (param $b i64) (result i64)
                   (i64.add (local.get $a) (local.get $b)))
                 (func (export "trap") (param $x i64) (result i64)
                   (unreachable)))"#,
        )
        .unwrap()
    }

    fn counter_getter_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "host" "sload" (func $sload (param i64) (result i64)))
                 (import "host" "sstore" (func $sstore (param i64 i64)))
                 (func (export "inc") (param $key i64) (result i64)
                   (call $sstore (local.get $key) (i64.add (call $sload (local.get $key)) (i64.const 1)))
                   (call $sload (local.get $key)))
                 (func (export "get") (param $key i64) (result i64)
                   (call $sload (local.get $key))))"#,
        )
        .unwrap()
    }

    fn event_getter_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "host" "emit" (func $emit (param i64 i64)))
                 (func (export "emit_test") (param $val i64) (result i64)
                   (call $emit (i64.const 777) (local.get $val))
                   (local.get $val)))"#,
        )
        .unwrap()
    }

    fn loop_getter_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (func (export "loop") (param $x i64) (result i64)
                   (loop (br 0))
                   (i64.const 0)))"#,
        )
        .unwrap()
    }

    /// A contract with a two- and a three-parameter method, deployed together
    /// with a typed ABI manifest.
    fn abi_contract_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (func (export "add") (param $a i64) (param $b i64) (result i64)
                   (i64.add (local.get $a) (local.get $b)))
                 (func (export "sum3") (param $a i64) (param $b i64) (param $c i64) (result i64)
                   (i64.add (i64.add (local.get $a) (local.get $b)) (local.get $c))))"#,
        )
        .unwrap()
    }

    fn abi_contract_manifest() -> crate::contract_abi::ContractAbi {
        use crate::contract_abi::{AbiMethod, AbiParam, AbiType};
        crate::contract_abi::ContractAbi {
            methods: vec![
                AbiMethod::view(
                    "add",
                    vec![
                        AbiParam::new("a", AbiType::I64),
                        AbiParam::new("b", AbiType::I64),
                    ],
                    AbiType::I64,
                ),
                AbiMethod::view(
                    "sum3",
                    vec![
                        AbiParam::new("a", AbiType::I64),
                        AbiParam::new("b", AbiType::I64),
                        AbiParam::new("c", AbiType::I64),
                    ],
                    AbiType::I64,
                ),
            ],
            events: vec![],
        }
    }

    // ==================== stell_verifyContractSource Tests (P2-15) ====================

    /// The canonical source form is `.wat` text; this one is also deployed
    /// from `contracts/`-style text in the test below.
    const VERIFY_WAT: &str = r#"(module
      (import "host" "sload" (func $sload (param i64) (result i64)))
      (import "host" "sstore" (func $sstore (param i64 i64)))
      (import "host" "emit" (func $emit (param i64 i64)))
      (func (export "get") (param i64) (result i64) (call $sload (local.get 0)))
      (func (export "set") (param i64) (result i64)
        (call $sstore (i64.const 0) (local.get 0))
        (call $emit (i64.const 1) (local.get 0))
        (local.get 0)))"#;

    #[tokio::test]
    async fn verify_contract_source_round_trip() {
        use ed25519_dalek::Signer;
        let st = test_state().await;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xABu8; 32]);
        let creator = sk.verifying_key().to_bytes();
        let wasm = wat::parse_str(VERIFY_WAT).unwrap();
        let addr = st.engine.deploy_contract(creator, wasm, 0).await.unwrap();
        let addr_hex = hex::encode(addr);

        // 1. The known `.wat` verifies (deployed bytes == rebuilt bytes).
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": addr_hex, "source": VERIFY_WAT, "compiler": "wat2wasm-1.0" }),
        )
        .await;
        assert_eq!(r["verified"], json!(true), "known source must verify: {r}");
        assert_eq!(r["reason"], json!("ok"));
        let source_hash = r["source_hash"].as_str().unwrap().to_string();
        assert_eq!(source_hash.len(), 64);

        // The `source_hex` spelling answers identically.
        let r_hex = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": addr_hex, "source_hex": hex::encode(VERIFY_WAT.as_bytes()), "compiler": "wat" }),
        )
        .await;
        assert_eq!(
            r_hex["verified"],
            json!(true),
            "hex form must verify: {r_hex}"
        );
        assert_eq!(r_hex["source_hash"], json!(source_hash));

        // 2. A tampered source is REFUSED (rebuilt hash mismatches).
        let tampered = VERIFY_WAT.replace("i64.const 1", "i64.const 2");
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": addr_hex, "source": tampered, "compiler": "wat2wasm-1.0" }),
        )
        .await;
        assert_eq!(
            r["verified"],
            json!(false),
            "tampered source must be refused: {r}"
        );

        // 3. A wrong-compiler claim is REFUSED (fail-closed, never guessed).
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": addr_hex, "source": VERIFY_WAT, "compiler": "solc-0.8.24" }),
        )
        .await;
        assert_eq!(
            r["verified"],
            json!(false),
            "foreign compiler must be refused: {r}"
        );

        // 4. Fresh contract: no source registered yet (absent = unverified).
        let r = call(
            &st,
            "stell_getContractSource",
            json!({ "contract": addr_hex }),
        )
        .await;
        assert_eq!(r["verified"], json!(false), "nothing registered yet: {r}");

        // 5. Registration without (or with a wrong) signature is refused.
        let r = call(
            &st,
            "stell_registerContractSource",
            json!({ "contract": addr_hex, "source_hash": source_hash }),
        )
        .await;
        assert!(
            r["error"].is_string(),
            "missing signature must be refused: {r}"
        );
        let bad_sig = hex::encode([0u8; 64]);
        let r = call(
            &st,
            "stell_registerContractSource",
            json!({ "contract": addr_hex, "source_hash": source_hash, "signature": bad_sig }),
        )
        .await;
        assert!(
            r["error"].is_string(),
            "forged signature must be refused: {r}"
        );

        // 6. The creator's signature registers the fingerprint.
        let shash_bytes = hex::decode(&source_hash).unwrap();
        let mut shash = [0u8; 32];
        shash.copy_from_slice(&shash_bytes);
        let msg = crate::contract_source::register_message(&addr, &shash);
        let sig = sk.sign(&msg);
        let r = call(
            &st,
            "stell_registerContractSource",
            json!({ "contract": addr_hex, "source_hash": source_hash, "signature": hex::encode(sig.to_bytes()) }),
        )
        .await;
        assert_eq!(
            r["registered"],
            json!(true),
            "signed registration must land: {r}"
        );

        // 7. The label is now readable; verification itself never set it
        // (it was `false` in step 4 before any registration).
        let r = call(
            &st,
            "stell_getContractSource",
            json!({ "contract": addr_hex }),
        )
        .await;
        assert_eq!(
            r["verified"],
            json!(true),
            "registered source reads back: {r}"
        );
        assert_eq!(r["source_hash"], json!(source_hash));

        // 8. Hash-only check against the registered fingerprint.
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": addr_hex, "source_hash": source_hash }),
        )
        .await;
        assert_eq!(
            r["verified"],
            json!(true),
            "registered hash must match: {r}"
        );
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": addr_hex, "source_hash": hex::encode([9u8; 32]) }),
        )
        .await;
        assert_eq!(
            r["verified"],
            json!(false),
            "foreign hash must not match: {r}"
        );
    }

    #[tokio::test]
    async fn verify_contract_source_rejects_unknown_contract_and_flags() {
        let st = test_state().await;
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": hex::encode([9u8; 32]), "source": VERIFY_WAT }),
        )
        .await;
        assert_eq!(
            r["error"],
            json!("contract not found"),
            "unknown contract: {r}"
        );

        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xCDu8; 32]);
        let creator = sk.verifying_key().to_bytes();
        let wasm = wat::parse_str(VERIFY_WAT).unwrap();
        let addr = st.engine.deploy_contract(creator, wasm, 0).await.unwrap();
        let r = call(
            &st,
            "stell_verifyContractSource",
            json!({ "contract": hex::encode(addr), "source": VERIFY_WAT, "compiler_flags": "--lto=fat" }),
        )
        .await;
        assert_eq!(
            r["verified"],
            json!(false),
            "unreproducible flags refused: {r}"
        );
    }

    #[tokio::test]
    async fn run_get_method_with_abi_validates_and_types_the_call() {
        let st = test_state().await;
        let creator = [0x44u8; 32];
        let addr = st
            .engine
            .deploy_contract_with_abi(creator, abi_contract_wasm(), 0, abi_contract_manifest())
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);

        // The manifest is discoverable.
        let res = call(&st, "stell_getContractAbi", json!({ "contract": addr_hex })).await;
        assert_eq!(res["abi"]["methods"].as_array().unwrap().len(), 2);

        // A two-argument method is callable and the return value is typed.
        let res = call(
            &st,
            "stell_runGetMethod",
            json!({ "address": addr_hex, "method": "add", "args": [15, 27] }),
        )
        .await;
        assert_eq!(res["success"], json!(true));
        assert_eq!(res["return_value"], json!(42));
        assert_eq!(res["return_typed"], json!(42));

        // A three-argument method too.
        let res = call(
            &st,
            "stell_runGetMethod",
            json!({ "address": addr_hex, "method": "sum3", "args": [10, 20, 12] }),
        )
        .await;
        assert_eq!(res["success"], json!(true));
        assert_eq!(res["return_value"], json!(42));

        // The manifest is authoritative: a wrong argument count is refused.
        let res = call(
            &st,
            "stell_runGetMethod",
            json!({ "address": addr_hex, "method": "add", "args": [15] }),
        )
        .await;
        assert_eq!(res["success"], json!(false));
        assert!(res["error"]
            .as_str()
            .unwrap()
            .contains("expects 2 argument"));

        // So is an unknown method.
        let res = call(
            &st,
            "stell_runGetMethod",
            json!({ "address": addr_hex, "method": "nope", "args": [] }),
        )
        .await;
        assert_eq!(res["success"], json!(false));
    }

    #[tokio::test]
    async fn call_contract_with_multi_argument_method() {
        // N-02: previews require a token on every bind.
        let st = test_state_with_token().await;
        let creator = [0x55u8; 32];
        let addr = st
            .engine
            .deploy_contract(creator, abi_contract_wasm(), 0)
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);

        // Three arguments reach a three-parameter method.
        let res = call_with_token(
            &st,
            "stell_callContract",
            json!({ "contract": addr_hex, "method": "sum3", "args": [10, 20, 12] }),
        )
        .await;
        assert_eq!(res["status"], json!("success"));
        assert_eq!(res["return_value"], json!(42));

        // A parameter is never dropped: the arity must match.
        let res = call_with_token(
            &st,
            "stell_callContract",
            json!({ "contract": addr_hex, "method": "sum3", "args": [10, 20] }),
        )
        .await;
        assert_eq!(res["status"], json!("failed"));
    }

    #[tokio::test]
    async fn run_get_method_basic_execution_and_arg_formats() {
        let st = test_state().await;
        let creator = [0x11u8; 32];
        let addr = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);
        let addr_stl57 = crate::address::encode_stl57_address(&addr);

        // 1. Argument as integer number
        let res1 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": 21
            }),
        )
        .await;
        assert_eq!(res1["success"], json!(true));
        assert_eq!(res1["return_value"], json!(42));
        assert_eq!(res1["return_bytes"], json!("000000000000002a"));
        assert!(res1["fuel_used"].as_u64().unwrap() > 0);
        assert_eq!(res1["events"], json!([]));

        // 2. Argument as hex string with 0x prefix
        let res2 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": format!("0x{}", addr_hex),
                "method": "double",
                "args": "0x15"
            }),
        )
        .await;
        assert_eq!(res2["success"], json!(true));
        assert_eq!(res2["return_value"], json!(42));
        assert_eq!(res2["return_bytes"], json!("000000000000002a"));

        // 3. Argument as decimal string "21"
        let res3 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": "21"
            }),
        )
        .await;
        assert_eq!(res3["success"], json!(true));
        assert_eq!(res3["return_value"], json!(42));

        // 4. Argument as JSON array: [21]
        let res4 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": [21]
            }),
        )
        .await;
        assert_eq!(res4["success"], json!(true));
        assert_eq!(res4["return_value"], json!(42));

        // 5. Argument as JSON array of hex: ["0x15"]
        let res5 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": ["0x15"]
            }),
        )
        .await;
        assert_eq!(res5["success"], json!(true));
        assert_eq!(res5["return_value"], json!(42));

        // 6. Address in Stl57 format
        let res6 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_stl57,
                "method": "double",
                "args": 21
            }),
        )
        .await;
        assert_eq!(res6["success"], json!(true));
        assert_eq!(res6["return_value"], json!(42));

        // 7. 0-argument method "answer"
        let res7 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "answer",
                "args": []
            }),
        )
        .await;
        assert_eq!(res7["success"], json!(true));
        assert_eq!(res7["return_value"], json!(42));
        assert_eq!(res7["return_bytes"], json!("000000000000002a"));

        // 8. 2-argument method "add"
        let res8 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "add",
                "args": [15, 27]
            }),
        )
        .await;
        assert_eq!(res8["success"], json!(true));
        assert_eq!(res8["return_value"], json!(42));
    }

    #[tokio::test]
    async fn run_get_method_zero_state_changes_and_zero_gas_fees() {
        let st = test_state().await;
        let creator = [0x22u8; 32];
        let addr = st
            .engine
            .deploy_contract(creator, counter_getter_wasm(), 0)
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);

        // Account balance setup to verify zero gas fees
        let caller_acc = [0x33u8; 32];
        let initial_balance = 5_000_000_000u64;
        st.engine
            .update_account(AccountState::new(caller_acc, initial_balance))
            .await;

        // 1. First getMethod call invokes inc(10)
        let r1 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "inc",
                "args": 10
            }),
        )
        .await;
        assert_eq!(r1["success"], json!(true));
        assert_eq!(r1["return_value"], json!(1));

        // Verify storage in state engine is COMPLETELY unmodified (zero state changes)
        let contract = st.engine.get_contract(&addr).await.unwrap();
        assert!(
            contract.storage.is_empty(),
            "contract storage must remain empty after getter invocation"
        );

        // Verify caller's account balance is completely untouched (zero gas fee charged)
        let acc_after = st.engine.get_account(&caller_acc).await.unwrap();
        assert_eq!(
            acc_after.balance, initial_balance,
            "no gas fees may be charged to any account for read-only getter"
        );

        // 2. Second getMethod call invokes inc(10) again: must return 1 again (not 2)
        let r2 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "inc",
                "args": 10
            }),
        )
        .await;
        assert_eq!(r2["success"], json!(true));
        assert_eq!(
            r2["return_value"],
            json!(1),
            "state must not have persisted from call 1"
        );

        // Verify storage in engine is still empty
        let contract2 = st.engine.get_contract(&addr).await.unwrap();
        assert!(contract2.storage.is_empty());

        // 3. Mutate consensus state deliberately via real call_contract
        st.engine
            .call_contract(&addr, "inc", 10, 50_000)
            .await
            .unwrap();
        let contract3 = st.engine.get_contract(&addr).await.unwrap();
        assert_eq!(contract3.storage.get(&10), Some(&1));

        // 4. Getter read "get" now sees the committed storage value 1
        let r_get = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "get",
                "args": 10
            }),
        )
        .await;
        assert_eq!(r_get["success"], json!(true));
        assert_eq!(r_get["return_value"], json!(1));

        // 5. Getter "inc" calculates 1 + 1 = 2 on the working copy
        let r3 = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "inc",
                "args": 10
            }),
        )
        .await;
        assert_eq!(r3["success"], json!(true));
        assert_eq!(r3["return_value"], json!(2));

        // But committed storage in engine is STILL 1 (the increment to 2 was discarded)
        let contract4 = st.engine.get_contract(&addr).await.unwrap();
        assert_eq!(contract4.storage.get(&10), Some(&1));
    }

    #[tokio::test]
    async fn run_get_method_events_and_no_receipt_storage() {
        let st = test_state().await;
        let creator = [0x44u8; 32];
        let addr = st
            .engine
            .deploy_contract(creator, event_getter_wasm(), 0)
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);

        let res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "emit_test",
                "args": 999
            }),
        )
        .await;
        assert_eq!(res["success"], json!(true));
        assert_eq!(res["return_value"], json!(999));
        assert_eq!(res["return_bytes"], json!("00000000000003e7"));

        let events = res["events"].as_array().expect("events must be an array");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["contract"], json!(addr_hex));
        assert_eq!(events[0]["topic"], json!(777));
        assert_eq!(events[0]["value"], json!(999));

        // Receipts index should NOT contain any new receipts
        assert_eq!(st.receipts.read().await.len(), 0);
    }

    #[tokio::test]
    async fn run_get_method_safety_fuel_limit_and_error_handling() {
        let st = test_state().await;
        let creator = [0x55u8; 32];
        let sample_addr = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();
        let loop_addr = st
            .engine
            .deploy_contract(creator, loop_getter_wasm(), 0)
            .await
            .unwrap();

        // 1. Infinite loop is bounded by safety fuel limit (5,000,000)
        let loop_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": hex::encode(loop_addr),
                "method": "loop",
                "args": 0
            }),
        )
        .await;
        assert_eq!(loop_res["success"], json!(false));
        assert_eq!(loop_res["error"], json!("contract ran out of fuel"));
        assert!(loop_res["fuel_used"].as_u64().unwrap() >= 4_999_000);
        assert!(
            loop_res["fuel_used"].as_u64().unwrap()
                <= crate::contract::GET_METHOD_SAFETY_FUEL_LIMIT
        );

        // 2. Trapping contract (unreachable)
        let trap_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": hex::encode(sample_addr),
                "method": "trap",
                "args": 0
            }),
        )
        .await;
        assert_eq!(trap_res["success"], json!(false));
        assert_eq!(
            trap_res["error"],
            json!("contract trapped during execution")
        );
        assert!(trap_res["fuel_used"].as_u64().unwrap() > 0);

        // 3. Unknown contract
        let unknown_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": hex::encode([0xEEu8; 32]),
                "method": "double",
                "args": 10
            }),
        )
        .await;
        assert_eq!(unknown_res["success"], json!(false));
        assert_eq!(unknown_res["error"], json!("contract not found"));
        assert_eq!(unknown_res["fuel_used"], json!(0));

        // 4. Unknown method
        let no_method_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": hex::encode(sample_addr),
                "method": "non_existent_method",
                "args": 10
            }),
        )
        .await;
        assert_eq!(no_method_res["success"], json!(false));
        assert_eq!(
            no_method_res["error"],
            json!("contract does not export the requested method")
        );
        assert_eq!(no_method_res["fuel_used"], json!(0));

        // 5. Paused contract cannot be called
        st.engine
            .contracts_write()
            .await
            .pause(&sample_addr, creator)
            .unwrap();
        let paused_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": hex::encode(sample_addr),
                "method": "double",
                "args": 10
            }),
        )
        .await;
        assert_eq!(paused_res["success"], json!(false));
        assert_eq!(paused_res["error"], json!("contract is paused"));
        assert_eq!(paused_res["fuel_used"], json!(0));

        // 6. Invalid address format
        let invalid_addr_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": "not_an_address",
                "method": "double",
                "args": 10
            }),
        )
        .await;
        assert_eq!(invalid_addr_res["success"], json!(false));
        assert!(invalid_addr_res["error"]
            .as_str()
            .unwrap()
            .contains("invalid address"));
        assert_eq!(invalid_addr_res["fuel_used"], json!(0));

        // 7. Missing address
        let missing_addr_res = call(
            &st,
            "stell_runGetMethod",
            json!({
                "method": "double",
                "args": 10
            }),
        )
        .await;
        assert_eq!(missing_addr_res["success"], json!(false));
        assert!(missing_addr_res["error"]
            .as_str()
            .unwrap()
            .contains("missing"));
        assert_eq!(missing_addr_res["fuel_used"], json!(0));
    }

    #[tokio::test]
    async fn run_get_method_block_height_pinning() {
        let st = test_state().await;
        let creator = [0x66u8; 32];
        let addr = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);

        // Height in test_state() is 42
        // 1. Height pin at current height (42) succeeds
        let res_curr = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": 21,
                "height": 42
            }),
        )
        .await;
        assert_eq!(res_curr["success"], json!(true));
        assert_eq!(res_curr["return_value"], json!(42));

        // 2. Height pin at past height (10) succeeds
        let res_past = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": 21,
                "height": 10
            }),
        )
        .await;
        assert_eq!(res_past["success"], json!(true));
        assert_eq!(res_past["return_value"], json!(42));

        // 3. Height pin in future (100 > 42) fails with descriptive error
        let res_future = call(
            &st,
            "stell_runGetMethod",
            json!({
                "address": addr_hex,
                "method": "double",
                "args": 21,
                "height": 100
            }),
        )
        .await;
        assert_eq!(res_future["success"], json!(false));
        assert!(
            res_future["error"]
                .as_str()
                .unwrap()
                .contains("pinned block height 100 exceeds current finalized height 42"),
            "future height pin must be rejected"
        );
        assert_eq!(res_future["fuel_used"], json!(0));
    }

    // ==================== stell_deployContract & stell_callContract Tests ====================

    /// H-04/C-01 + N-03: the deploy arms validate + preview but never deploy
    /// and never admit. The returned address is the SDK-canonical prediction
    /// (`contract_address(tx.from, tx.nonce)` — exactly what block
    /// application derives when this tx applies first for its sender), and
    /// nothing is visible in state until a block carries the tx — which must
    /// arrive via `stell_sendRawTransaction`, because the preview tx is
    /// DROPPED (mempool stays empty).
    /// (The old BLAKE3(code_hash || salt) address was a phantom the block
    /// path never recreated — `init_data`/`salt` is retired: not part of the
    /// replayable payload, so it cannot influence the chain.)
    #[tokio::test]
    async fn deploy_contract_predicts_address_and_admits_without_writing_state() {
        // N-02: previews require a token on every bind.
        let st = test_state_with_token().await;
        let code = sample_getter_wasm();
        let root_before = st.engine.get_state_root().await;

        let res = call_with_token(
            &st,
            "stell_deployContract",
            json!({
                "code": hex::encode(&code),
                "init_data": hex::encode(vec![0x12, 0x34, 0x56, 0x78]),
                "gas_limit": 10_000_000,
            }),
        )
        .await;

        let tx_hash = res["tx_hash"].as_str().expect("tx_hash present");
        assert_eq!(tx_hash.len(), 64);
        // N-03: the preview tx is dropped — the mempool stays EMPTY.
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "a deploy preview must never enter the mempool"
        );
        // The predicted vehicle is a validly signed ephemeral tx; the
        // prediction is derived from it, independent of the retired salt.
        // The vehicle is recovered from the node-local preview receipt (the
        // mempool no longer carries it).
        let receipt = call(
            &st,
            "stell_getTransactionReceipt",
            json!({ "hash": tx_hash }),
        )
        .await;
        assert_eq!(receipt["status"], json!("success"));
        let raw_hex = receipt["raw_tx"]
            .as_str()
            .expect("preview receipt carries the raw preview tx");
        let vehicle: Transaction =
            bincode::deserialize(&hex::decode(raw_hex).expect("raw_tx hex")).expect("raw_tx decodes");
        assert!(vehicle.verify_signature());
        let expected_addr = crate::contract::contract_address(&vehicle.from, vehicle.nonce);
        assert_eq!(res["contract_address"], json!(hex::encode(expected_addr)));
        assert_eq!(
            res["contract_address_stl57"],
            json!(crate::address::encode_stl57_address(&expected_addr))
        );
        assert_eq!(
            res["code_hash"],
            json!(hex::encode(
                <sha2::Sha256 as sha2::Digest>::digest(&code).as_slice()
            ))
        );

        // Nothing is visible in consensus state before a block applies it.
        assert_eq!(
            st.engine.get_state_root().await,
            root_before,
            "a preview must not move the state root"
        );
        assert!(st.engine.get_contract(&expected_addr).await.is_none());
        assert!(
            st.engine
                .get_contract_code_hash(&expected_addr)
                .await
                .is_none()
        );

        // Verify receipt is recorded in st.receipts
        assert_eq!(
            receipt["contract_address"],
            json!(hex::encode(expected_addr))
        );
        assert_eq!(
            receipt["contract_address_stl57"],
            json!(crate::address::encode_stl57_address(&expected_addr))
        );

        // The state change happens exactly once, at block application: fund
        // the vehicle, apply it, and the predicted address materializes.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        st.engine
            .update_account(AccountState::new(vehicle.from, 1_000_000_000))
            .await;
        st.engine.apply_transaction(&vehicle, now).await.unwrap();
        // Block application materializes the contract in the registry and
        // commits its code hash (the code bytes live in the registry; the
        // trie carries the code hash under the namespaced contract key —
        // the raw-address code blob was deterministic-path-only).
        let stored = st
            .engine
            .get_contract(&expected_addr)
            .await
            .expect("applied deploy must materialize the contract");
        assert_eq!(stored.code, code);
        assert_eq!(
            st.engine.get_contract_code_hash(&expected_addr).await,
            Some(
                <sha2::Sha256 as sha2::Digest>::digest(&code).as_slice().try_into().unwrap()
            )
        );
        // Re-applying the same tx is refused (nonce consumed): apply-once.
        let again = st.engine.apply_transaction(&vehicle, now).await;
        assert!(
            again.is_err(),
            "double application must be refused: {again:?}"
        );
        assert_eq!(
            st.engine
                .get_contract(&expected_addr)
                .await
                .map(|c| c.code),
            Some(code),
            "the refused re-application must not disturb the deployed code"
        );
    }

    #[tokio::test]
    async fn deploy_contract_with_signed_raw_tx_wrapper() {
        // N-02: previews require a token on every bind.
        let st = test_state_with_token().await;
        let code = counter_getter_wasm();

        // FULL-PQ: implicit Falcon-512 wrapper (registered globally).
        let (from, _) = pq_pair(0xC6);
        // Funded, so the admitted tx can actually apply at block time.
        st.engine
            .update_account(AccountState::new(from, 1_000_000_000))
            .await;
        let tx = pq_tx_payload(
            0xC6,
            [0u8; 32],
            0,
            15_000_000,
            0,
            vec![crate::svm::OpCode::SysCallDeployContract { code: code.clone() }],
        );
        let tx_hash = tx.compute_tx_hash();
        let raw_hex = hex::encode(bincode::serialize(&tx).unwrap());
        // `init_data` is retired (not part of the payload): passing it must
        // not change the predicted address.
        let salt = vec![0xAB, 0xCD];

        let res = call_with_token(
            &st,
            "stell_deployContract",
            json!({
                "tx": raw_hex,
                "init_data": hex::encode(&salt),
            }),
        )
        .await;

        // SDK-canonical prediction: what block application derives.
        let expected_addr = crate::contract::contract_address(&from, 0);
        let root_after_funding = st.engine.get_state_root().await;
        assert_eq!(res["contract_address"], json!(hex::encode(expected_addr)));
        assert_eq!(res["tx_hash"], json!(hex::encode(tx_hash)));
        // N-03: the preview tx is dropped — the mempool stays EMPTY.
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "a deploy preview must never enter the mempool"
        );
        assert_eq!(
            st.engine.get_state_root().await,
            root_after_funding,
            "a preview must not move the state root"
        );
        assert!(st.engine.get_contract(&expected_addr).await.is_none());

        // Only block application materializes the contract — then the
        // contract is callable, exactly once.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        st.engine.apply_transaction(&tx, now).await.unwrap();
        let call_res = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": hex::encode(expected_addr),
                "method": "inc",
                "args": 10
            }),
        )
        .await;
        assert_eq!(call_res["status"], json!("success"));
        assert_eq!(call_res["return_value"], json!(1));
        let again = st.engine.apply_transaction(&tx, now).await;
        assert!(
            again.is_err(),
            "double application must be refused: {again:?}"
        );
    }

    #[tokio::test]
    async fn deploy_contract_rejects_invalid_wasm() {
        // N-02: the token gate runs before validation, so the fixture token
        // is presented and the refusal below pins the wasm check (never auth).
        let st = test_state_with_token().await;
        let res = call_with_token(
            &st,
            "stell_deployContract",
            json!({
                "code": "deadbeef",
                "gas_limit": 5_000_000,
            }),
        )
        .await;
        assert!(res.get("error").is_some());
    }

    #[tokio::test]
    async fn call_contract_execution_and_receipt_structured_outcomes() {
        // N-02: previews require a token on every bind.
        let st = test_state_with_token().await;
        // H-03 fixture setup deploys through the engine directly: the RPC
        // no longer deploys out-of-block, so tests materialize contracts the
        // way block application does.
        let creator = [0x11u8; 32];
        let deployed = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();

        let contract_addr_hex = hex::encode(deployed);
        let contract_addr = contract_addr_hex.as_str();
        let contract_stl57_hex = crate::address::encode_stl57_address(&deployed);
        let contract_stl57 = contract_stl57_hex.as_str();

        // 1. Call with integer argument
        let call1 = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_addr,
                "method": "double",
                "args": 21,
                "gas_limit": 1_000_000
            }),
        )
        .await;

        assert_eq!(call1["status"], json!("success"));
        assert_eq!(call1["return_value"], json!(42));
        assert!(call1["gas_used"].as_u64().unwrap() > 0);
        assert_eq!(call1["events"], json!([]));
        assert_eq!(call1["outcome"]["status"], json!("success"));
        assert_eq!(call1["outcome"]["return_value"], json!(42));

        let tx_hash = call1["tx_hash"].as_str().unwrap();

        // 2. Fetch receipt via stell_getTransactionReceipt
        let receipt = call(
            &st,
            "stell_getTransactionReceipt",
            json!({ "hash": tx_hash }),
        )
        .await;
        assert_eq!(receipt["status"], json!("success"));
        assert_eq!(receipt["return_value"], json!(42));
        assert!(receipt["gas_used"].as_u64().unwrap() > 0);
        assert_eq!(receipt["events"], json!([]));

        // 3. Fetch receipt via stell_getContractReceipt
        let c_receipt = call(&st, "stell_getContractReceipt", json!({ "hash": tx_hash })).await;
        assert_eq!(c_receipt["status"], json!("success"));
        assert_eq!(c_receipt["return_value"], json!(42));
        assert!(c_receipt["gas_used"].as_u64().unwrap() > 0);
        assert_eq!(c_receipt["events"], json!([]));

        // 4. Call using branded Stl57 address format and hex args ("0x15")
        let call2 = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_stl57,
                "method": "double",
                "args": "0x15"
            }),
        )
        .await;
        assert_eq!(call2["status"], json!("success"));
        assert_eq!(call2["return_value"], json!(42));

        // 5. Call using decimal string ("15")
        let call3 = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_addr,
                "method": "double",
                "args": "15"
            }),
        )
        .await;
        assert_eq!(call3["status"], json!("success"));
        assert_eq!(call3["return_value"], json!(30));

        // 5b. Call using hex string ("0x10" = 16)
        let call3b = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_addr,
                "method": "double",
                "args": "0x10"
            }),
        )
        .await;
        assert_eq!(call3b["status"], json!("success"));
        assert_eq!(call3b["return_value"], json!(32));

        // 6. Call using array args: [21]
        let call4 = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_addr,
                "method": "double",
                "args": [21]
            }),
        )
        .await;
        assert_eq!(call4["status"], json!("success"));
        assert_eq!(call4["return_value"], json!(42));
    }

    /// H-03 + N-03: previews are result-identical but state-free, and the
    /// previewed tx is dropped (never admitted). The counter contract is the
    /// proof: two identical previews return the SAME value (the old suite
    /// asserted 1-then-2, i.e. live mutation per call), storage stays empty
    /// until a block applies the tx, and re-application is refused by the
    /// nonce rule.
    #[tokio::test]
    async fn call_contract_state_mutations_and_events() {
        // N-02: previews require a token on every bind.
        let st = test_state_with_token().await;
        let creator = [0x33u8; 32];

        // 1. Counter contract (persistent storage), deployed engine-side.
        let counter = st
            .engine
            .deploy_contract(creator, counter_getter_wasm(), 0)
            .await
            .unwrap();
        let counter_hex = hex::encode(counter);
        let counter_addr = counter_hex.as_str();

        // Preview twice: same answer both times, nothing persisted, nothing
        // admitted (N-03: the mempool stays empty).
        for _ in 0..2 {
            let inc = call_with_token(
                &st,
                "stell_callContract",
                json!({ "contract": counter_addr, "method": "inc", "args": 7 }),
            )
            .await;
            assert_eq!(inc["status"], json!("success"));
            assert_eq!(inc["return_value"], json!(1));
        }
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "previews must never enter the mempool"
        );
        let get = call_with_token(
            &st,
            "stell_callContract",
            json!({ "contract": counter_addr, "method": "get", "args": 7 }),
        )
        .await;
        assert_eq!(get["status"], json!("success"));
        assert_eq!(
            get["return_value"],
            json!(0),
            "previews must not persist storage"
        );
        assert!(
            st.engine
                .get_contract(&counter)
                .await
                .map(|c| c.storage.is_empty())
                .unwrap_or(false),
            "registry storage must be untouched by previews"
        );

        // 2. The funded `tx` form previews the same answer, drops the tx,
        // and still changes nothing — until block application.
        // FULL-PQ: implicit Falcon-512 caller.
        let (caller_addr, _) = pq_pair(0xC7);
        st.engine
            .update_account(AccountState::new(caller_addr, 1_000_000_000))
            .await;
        let root_after_funding = st.engine.get_state_root().await;
        let call_tx = pq_tx_payload(
            0xC7,
            counter,
            0,
            1_000_000,
            0,
            vec![crate::svm::OpCode::SysCallCallContract {
                contract: counter,
                method: b"inc".to_vec(),
                arg: 7,
            }],
        );
        let preview = call_with_token(
            &st,
            "stell_callContract",
            json!({ "tx": hex::encode(bincode::serialize(&call_tx).unwrap()) }),
        )
        .await;
        assert_eq!(preview["status"], json!("success"));
        assert_eq!(preview["return_value"], json!(1));
        assert_eq!(
            st.mempool.read().await.len(),
            0,
            "a signed-tx preview must never enter the mempool"
        );
        assert_eq!(
            st.engine.get_state_root().await,
            root_after_funding,
            "a preview must not move the state root"
        );

        // 3. Apply-once: the first application persists exactly one
        // increment; the replay is refused and changes nothing.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        st.engine.apply_transaction(&call_tx, now).await.unwrap();
        let stored = st
            .engine
            .get_contract(&counter)
            .await
            .and_then(|c| c.storage.get(&7).copied());
        assert_eq!(stored, Some(1), "exactly one increment must apply");
        let replay = st.engine.apply_transaction(&call_tx, now).await;
        assert!(replay.is_err(), "double application must be refused");
        let stored_again = st
            .engine
            .get_contract(&counter)
            .await
            .and_then(|c| c.storage.get(&7).copied());
        assert_eq!(stored_again, Some(1), "the refused replay must not execute");
        // And the post-apply preview observes the applied state.
        let get_after = call_with_token(
            &st,
            "stell_callContract",
            json!({ "contract": counter_addr, "method": "get", "args": 7 }),
        )
        .await;
        assert_eq!(get_after["return_value"], json!(1));

        // 4. Event emission contract: the clone preview still reports events.
        let event_contract = st
            .engine
            .deploy_contract(creator, event_getter_wasm(), 0)
            .await
            .unwrap();
        let event_hex = hex::encode(event_contract);
        let event_addr = event_hex.as_str();

        let emit_call = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": event_addr,
                "method": "emit_test",
                "args": 888
            }),
        )
        .await;
        assert_eq!(emit_call["status"], json!("success"));
        assert_eq!(emit_call["return_value"], json!(888));
        let events = emit_call["events"].as_array().expect("events array");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["contract"], json!(event_addr));
        assert_eq!(events[0]["topic"], json!(777));
        assert_eq!(events[0]["value"], json!(888));

        // Verify events in receipt
        let tx_hash = emit_call["tx_hash"].as_str().unwrap();
        let receipt = call(
            &st,
            "stell_getTransactionReceipt",
            json!({ "hash": tx_hash }),
        )
        .await;
        let r_events = receipt["events"].as_array().expect("receipt events array");
        assert_eq!(r_events.len(), 1);
        assert_eq!(r_events[0]["topic"], json!(777));
        assert_eq!(r_events[0]["value"], json!(888));
    }

    /// H-03 result-equivalence: the clone preview reports byte-identical
    /// failure shapes (trap, unknown method/contract, out-of-fuel) without
    /// executing against live state. Fixtures deploy engine-side (the RPC no
    /// longer deploys out-of-block).
    #[tokio::test]
    async fn call_contract_observable_failures() {
        // N-02: previews require a token on every bind.
        let st = test_state_with_token().await;
        let creator = [0x77u8; 32];
        let sample = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();
        let sample_hex = hex::encode(sample);
        let contract_addr = sample_hex.as_str();

        // 1. Trap failure
        let trap_res = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_addr,
                "method": "trap",
                "args": 0
            }),
        )
        .await;
        assert_eq!(trap_res["status"], json!("failed"));
        assert_eq!(trap_res["return_value"], Value::Null);
        let trap_hash = trap_res["tx_hash"].as_str().unwrap();
        let trap_receipt = call(
            &st,
            "stell_getTransactionReceipt",
            json!({ "hash": trap_hash }),
        )
        .await;
        assert_eq!(trap_receipt["status"], json!("failed"));

        // 2. Unknown method failure
        let unknown_res = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": contract_addr,
                "method": "no_such_method",
                "args": 0
            }),
        )
        .await;
        assert_eq!(unknown_res["status"], json!("failed"));
        assert!(unknown_res["outcome"]["error"]
            .as_str()
            .unwrap()
            .contains("does not export"));

        // 3. Unknown contract address failure
        let unknown_c = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": hex::encode([0xEEu8; 32]),
                "method": "double",
                "args": 10
            }),
        )
        .await;
        assert_eq!(unknown_c["status"], json!("failed"));
        assert!(unknown_c["outcome"]["error"]
            .as_str()
            .unwrap()
            .contains("not found"));

        // 4. Out of fuel failure
        let loop_contract = st
            .engine
            .deploy_contract(creator, loop_getter_wasm(), 0)
            .await
            .unwrap();
        let loop_hex = hex::encode(loop_contract);
        let loop_addr = loop_hex.as_str();
        let oof_res = call_with_token(
            &st,
            "stell_callContract",
            json!({
                "contract": loop_addr,
                "method": "loop",
                "args": 0,
                "gas_limit": 500
            }),
        )
        .await;
        assert_eq!(oof_res["status"], json!("failed"));
        assert_eq!(oof_res["gas_used"], json!(500));
        assert!(oof_res["outcome"]["error"]
            .as_str()
            .unwrap()
            .contains("ran out of fuel"));
    }

    /// The estimate's gas ceiling is FIXED and the budget is HONEST (audit W7.2).
    ///
    /// The old expression `gas_limit.max(10_000_000).min(5_000_000)` could
    /// only ever evaluate to 5 000 000: the `.max()` was dead code that
    /// pretended a caller could raise the ceiling. The semantics are now
    /// explicit — the ceiling is a fixed maximum the caller may NOT raise, and
    /// the caller MAY lower the budget with `max_gas`.
    #[test]
    fn estimate_fee_gas_budget_is_fixed_and_honoured_downwards() {
        // No request: the full (fixed) ceiling.
        assert_eq!(estimate_fee_gas_budget(None), Ok(ESTIMATE_FEE_GAS_CEILING));
        // A caller may lower it, and the request is HONOURED (not clamped up
        // to the ceiling).
        assert_eq!(
            estimate_fee_gas_budget(Some(ESTIMATE_FEE_MIN_GAS)),
            Ok(ESTIMATE_FEE_MIN_GAS)
        );
        assert_eq!(estimate_fee_gas_budget(Some(1_000_000)), Ok(1_000_000));
        // A caller may NEVER raise it: the refusal is explicit, and the
        // ceiling is never silently widened.
        let too_high = estimate_fee_gas_budget(Some(ESTIMATE_FEE_GAS_CEILING + 1)).unwrap_err();
        assert!(
            too_high.contains("exceeds the estimate gas ceiling"),
            "unexpected refusal: {too_high}"
        );
        assert_eq!(
            estimate_fee_gas_budget(Some(ESTIMATE_FEE_GAS_CEILING)),
            Ok(ESTIMATE_FEE_GAS_CEILING)
        );
        // A budget below one basic transfer cannot answer anything: refused,
        // not rounded up.
        let too_low = estimate_fee_gas_budget(Some(ESTIMATE_FEE_MIN_GAS - 1)).unwrap_err();
        assert!(
            too_low.contains("below the minimum estimate gas budget"),
            "unexpected refusal: {too_low}"
        );
    }

    #[tokio::test]
    async fn estimate_fee_reports_its_budget_and_refuses_to_raise_the_ceiling() {
        let st = test_state().await;
        let from = hex::encode([1u8; 32]);
        let to = hex::encode([2u8; 32]);

        // 1. No `max_gas`: the budget IS the fixed ceiling, and the answer
        //    says so.
        let res = call(
            &st,
            "stell_estimateFee",
            json!({ "from": from, "to": to, "amount": 1000 }),
        )
        .await;
        assert_eq!(res["status"], json!("ok"));
        assert_eq!(res["gas_budget"], json!(ESTIMATE_FEE_GAS_CEILING));
        assert_eq!(res["gas_ceiling"], json!(ESTIMATE_FEE_GAS_CEILING));

        // 2. A LOWER `max_gas` is honoured.
        let res = call(
            &st,
            "stell_estimateFee",
            json!({ "from": from, "to": to, "amount": 1000, "max_gas": 1_000_000 }),
        )
        .await;
        assert_eq!(res["status"], json!("ok"));
        assert_eq!(res["gas_budget"], json!(1_000_000));

        // 3. A `max_gas` ABOVE the ceiling is refused — the caller cannot
        //    reopen the bounded cost of an unauthenticated read.
        let res = call(
            &st,
            "stell_estimateFee",
            json!({
                "from": from,
                "to": to,
                "amount": 1000,
                "max_gas": ESTIMATE_FEE_GAS_CEILING + 1,
            }),
        )
        .await;
        let msg = res["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains("exceeds the estimate gas ceiling"),
            "unexpected error: {msg}"
        );

        // 4. A `max_gas` below the minimum is refused too.
        let res = call(
            &st,
            "stell_estimateFee",
            json!({
                "from": from,
                "to": to,
                "amount": 1000,
                "max_gas": ESTIMATE_FEE_MIN_GAS - 1,
            }),
        )
        .await;
        let msg = res["error"].as_str().unwrap_or_default();
        assert!(
            msg.contains("below the minimum estimate gas budget"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_estimate_fee_plain_transfer() {
        let st = test_state().await;
        let from = [1u8; 32];
        let to = [2u8; 32];
        // Own bucket (see `fresh_estimate_ip`): the 4 estimates below must
        // never share a 5/s window with another test, in any run order.
        let ip = fresh_estimate_ip();

        // 1. Plain transfer with explicit shards
        let res = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": hex::encode(from),
                "to": hex::encode(to),
                "amount": 1000,
                "source_shard": 0,
                "target_shard": 0
            }),
        )
        .await;

        assert_eq!(res["gas_limit"], json!(280000));
        assert_eq!(res["estimated_fee"], json!(280000));
        assert_eq!(res["base_fee"], json!(280000));
        assert_eq!(res["source_shard"], json!(0));
        assert_eq!(res["target_shard"], json!(0));
        assert_eq!(res["is_cross_shard"], json!(false));
        assert_eq!(res["status"], json!("ok"));

        // 2. TON workchain prefix rules: "-1:..." routes to masterchain (shard 0)
        let res_ton = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": format!("-1:{}", hex::encode(from)),
                "to": format!("-1:{}", hex::encode(to)),
                "amount": 500
            }),
        )
        .await;
        assert_eq!(res_ton["source_shard"], json!(0));
        assert_eq!(res_ton["target_shard"], json!(0));
        assert_eq!(res_ton["is_cross_shard"], json!(false));
        assert_eq!(res_ton["status"], json!("ok"));

        // 3. Cross-shard prefix: "1:..." routes to shard 1
        let res_cross = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": format!("-1:{}", hex::encode(from)),
                "to": format!("1:{}", hex::encode(to)),
                "amount": 500
            }),
        )
        .await;
        assert_eq!(res_cross["source_shard"], json!(0));
        assert_eq!(res_cross["target_shard"], json!(1));
        assert_eq!(res_cross["is_cross_shard"], json!(true));

        // 4. Raw transaction format: { "tx": <hex> }
        let key = ed25519_dalek::SigningKey::from_bytes(&from);
        let raw_tx = crate::sharding::Transaction::sign(&key, to, 1000, 280000, 0, 0, 0);
        let tx_hex = hex::encode(bincode::serialize(&raw_tx).unwrap());
        let res_raw = call_as(&st, ip, "stell_estimateFee", json!({ "tx": tx_hex })).await;
        assert_eq!(res_raw["gas_limit"], json!(280000));
        assert_eq!(res_raw["estimated_fee"], json!(280000));
        assert_eq!(res_raw["base_fee"], json!(280000));
        assert_eq!(res_raw["source_shard"], json!(0));
        assert_eq!(res_raw["target_shard"], json!(0));
        assert_eq!(res_raw["is_cross_shard"], json!(false));
        assert_eq!(res_raw["status"], json!("ok"));
    }

    #[tokio::test]
    async fn test_estimate_fee_token_transfer() {
        let st = test_state().await;
        let who = [4u8; 32];
        let recipient = [5u8; 32];
        let meta = crate::token::TokenMetadata {
            name: "USD Tether".to_string(),
            symbol: "USDT".to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: [0u8; 32],
            paused: false,
            description: String::new(),
        };
        let token_id = st.engine.create_token(who, meta, 50_000).await.unwrap();
        // Own bucket (see `fresh_estimate_ip`).
        let ip = fresh_estimate_ip();

        // 1. Estimate fee with opcode array payload
        let res_op = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": hex::encode(who),
                "to": hex::encode(recipient),
                "source_shard": 0,
                "target_shard": 0,
                "payload": [
                    {
                        "SysCallTokenTransfer": {
                            "token_id": token_id,
                            "to": recipient,
                            "amount": 250
                        }
                    }
                ]
            }),
        )
        .await;

        assert_eq!(res_op["status"], json!("ok"));
        assert_eq!(res_op["gas_limit"], json!(280000));
        assert_eq!(res_op["estimated_fee"], json!(280000));
        assert_eq!(res_op["base_fee"], json!(280000));
        assert_eq!(res_op["source_shard"], json!(0));
        assert_eq!(res_op["target_shard"], json!(0));
        assert_eq!(res_op["is_cross_shard"], json!(false));

        // 2. Estimate fee with friendly token_id parameter
        let res_friendly = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": hex::encode(who),
                "to": hex::encode(recipient),
                "token_id": hex::encode(token_id),
                "amount": 500,
                "source_shard": 0,
                "target_shard": 0
            }),
        )
        .await;

        assert_eq!(res_friendly["status"], json!("ok"));
        assert_eq!(res_friendly["gas_limit"], json!(280000));
        assert_eq!(res_friendly["estimated_fee"], json!(280000));
        assert_eq!(res_friendly["base_fee"], json!(280000));
        assert_eq!(res_friendly["is_cross_shard"], json!(false));
    }

    #[tokio::test]
    async fn test_estimate_fee_contract_call() {
        let st = test_state().await;
        let creator = [0x11u8; 32];
        let contract_addr = st
            .engine
            .deploy_contract(creator, sample_getter_wasm(), 0)
            .await
            .unwrap();
        let caller = [0x99u8; 32];
        // Own bucket (see `fresh_estimate_ip`).
        let ip = fresh_estimate_ip();

        // 1. Estimate fee with OpCode array
        let res = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": hex::encode(caller),
                "to": hex::encode(contract_addr),
                "source_shard": 0,
                "target_shard": 0,
                "payload": [
                    {
                        "SysCallCallContract": {
                            "contract": contract_addr,
                            "method": "double",
                            "arg": 21
                        }
                    }
                ]
            }),
        )
        .await;

        assert_eq!(res["status"], json!("ok"));
        assert_eq!(res["base_fee"], json!(280000));
        assert_eq!(res["source_shard"], json!(0));
        assert_eq!(res["target_shard"], json!(0));
        assert_eq!(res["is_cross_shard"], json!(false));
        // Gas limit and estimated fee must be at least the base fee floor (280k)
        assert!(res["gas_limit"].as_u64().unwrap() >= 280000);
        assert!(res["estimated_fee"].as_u64().unwrap() >= 280000);

        // 2. Estimate fee with friendly method parameter
        let res_friendly = call_as(&st, ip,
            "stell_estimateFee",
            json!({
                "from": hex::encode(caller),
                "to": hex::encode(contract_addr),
                "method": "double",
                "arg": 42,
                "source_shard": 0,
                "target_shard": 0
            }),
        )
        .await;

        assert_eq!(res_friendly["status"], json!("ok"));
        assert_eq!(res_friendly["base_fee"], json!(280000));
        assert_eq!(res_friendly["source_shard"], json!(0));
        assert_eq!(res_friendly["target_shard"], json!(0));
        assert_eq!(res_friendly["is_cross_shard"], json!(false));
        assert!(res_friendly["gas_limit"].as_u64().unwrap() >= 280000);
        assert!(res_friendly["estimated_fee"].as_u64().unwrap() >= 280000);
    }

    #[tokio::test]
    async fn test_stell_get_events_endpoint_and_receipt_events() {
        let st = test_state().await;
        let contract_addr = [0x77u8; 32];
        let contract_hex = hex::encode(contract_addr);

        let tx = receipt_tx(0x33, 0);
        let tx_hash = tx.compute_tx_hash();
        let tx_hash_hex = hex::encode(tx_hash);

        let plain_tx = receipt_tx(0x44, 0);
        let plain_tx_hash = plain_tx.compute_tx_hash();
        let plain_tx_hex = hex::encode(plain_tx_hash);

        let txs = vec![tx.clone(), plain_tx.clone()];
        let events = vec![
            vec![
                crate::contract::ContractEvent {
                    contract: contract_addr,
                    topic: 1001,
                    value: 2002,
                },
                crate::contract::ContractEvent {
                    contract: contract_addr,
                    topic: 1003,
                    value: 2004,
                },
            ],
            vec![], // plain_tx has no events
        ];

        // Record receipts on block path (height 10)
        st.record_receipts_with_events(10, [0xAA; 32], &txs, &[true, true], &[1000, 500], &events)
            .await;

        // 1. stell_getTransactionReceipt includes events array
        let receipt = call(
            &st,
            "stell_getTransactionReceipt",
            json!({ "hash": tx_hash_hex }),
        )
        .await;
        assert_eq!(receipt["status"], json!("success"));
        let r_events = receipt["events"]
            .as_array()
            .expect("events must be an array");
        assert_eq!(r_events.len(), 2);
        assert_eq!(r_events[0]["contract"], json!(contract_hex));
        assert_eq!(r_events[0]["topic"], json!(1001));
        assert_eq!(r_events[0]["value"], json!(2002));
        assert_eq!(r_events[1]["contract"], json!(contract_hex));
        assert_eq!(r_events[1]["topic"], json!(1003));
        assert_eq!(r_events[1]["value"], json!(2004));

        // Plain tx receipt also has empty events array
        let plain_receipt = call(
            &st,
            "stell_getTransactionReceipt",
            json!({ "hash": plain_tx_hex }),
        )
        .await;
        assert_eq!(plain_receipt["events"], json!([]));

        // 2. stell_getEvents by tx_hash
        let evs_by_hash = call(&st, "stell_getEvents", json!({ "tx_hash": tx_hash_hex })).await;
        let arr = evs_by_hash.as_array().expect("must return event array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["topic"], json!(1001));
        assert_eq!(arr[0]["value"], json!(2002));
        assert_eq!(arr[1]["topic"], json!(1003));
        assert_eq!(arr[1]["value"], json!(2004));

        // Unknown tx_hash returns empty array
        let unknown = call(
            &st,
            "stell_getEvents",
            json!({ "tx_hash": hex::encode([0xFFu8; 32]) }),
        )
        .await;
        assert_eq!(unknown, json!([]));

        // 3. stell_getEvents by contract and block range
        let evs_by_contract = call(
            &st,
            "stell_getEvents",
            json!({
                "contract": contract_hex,
                "from_block": 5,
                "to_block": 15
            }),
        )
        .await;
        let arr_contract = evs_by_contract.as_array().expect("must return event array");
        assert_eq!(arr_contract.len(), 2);
        assert_eq!(arr_contract[0]["topic"], json!(1001));
        assert_eq!(arr_contract[0]["value"], json!(2002));

        // Outside block range (e.g. from 20 to 30) returns empty array
        let evs_out_of_range = call(
            &st,
            "stell_getEvents",
            json!({
                "contract": contract_hex,
                "from_block": 20,
                "to_block": 30
            }),
        )
        .await;
        assert_eq!(evs_out_of_range, json!([]));

        // Non-matching contract address returns empty array
        let evs_other_contract = call(
            &st,
            "stell_getEvents",
            json!({
                "contract": hex::encode([0x88u8; 32]),
                "from_block": 0,
                "to_block": 100
            }),
        )
        .await;
        assert_eq!(evs_other_contract, json!([]));

        // Missing parameters returns error
        let err_res = call(&st, "stell_getEvents", json!({})).await;
        assert!(err_res["error"].is_string());
    }

    // ===================================================================
    // Streaming subscriptions (WebSocket + SSE)
    // ===================================================================

    /// A subscription id is 16 random bytes, hex-encoded.
    fn assert_is_subscription_id(v: &Value) -> String {
        let s = v.as_str().expect("subscription id must be a string");
        assert_eq!(
            s.len(),
            SUBSCRIPTION_ID_BYTES * 2,
            "subscription id must be 16 bytes hex"
        );
        assert!(
            s.chars().all(|c| c.is_ascii_hexdigit()),
            "subscription id must be hex"
        );
        s.to_string()
    }

    #[tokio::test]
    async fn subscribe_returns_a_hex_id_and_registers_it() {
        let st = test_state().await;
        let id = call(&st, "stell_subscribe", json!(["newHeads"])).await;
        let sub_id = assert_is_subscription_id(&id);
        assert!(
            hub().get(&sub_id).is_some(),
            "subscription must be in the registry"
        );
        let sub = hub().get(&sub_id).expect("subscription");
        assert_eq!(sub.topic, SubscriptionTopic::NewHeads);
        // Every subscribe returns a DISTINCT id.
        let other = call(&st, "stell_subscribe", json!(["newTxs"])).await;
        let other_id = assert_is_subscription_id(&other);
        assert_ne!(other_id, sub_id);
        hub().unsubscribe(&sub_id);
        hub().unsubscribe(&other_id);
    }

    #[tokio::test]
    async fn unsubscribe_removes_the_subscription_and_is_idempotent() {
        let st = test_state().await;
        let sub_id =
            assert_is_subscription_id(&call(&st, "stell_subscribe", json!(["newHeads"])).await);
        assert_eq!(
            call(&st, "stell_unsubscribe", json!([sub_id])).await,
            json!(true)
        );
        assert!(hub().get(&sub_id).is_none(), "subscription must be gone");
        // Unsubscribing again is not an error, it just reports "not there".
        assert_eq!(
            call(&st, "stell_unsubscribe", json!([sub_id])).await,
            json!(false)
        );
        // A missing id is a parameter error.
        assert!(call(&st, "stell_unsubscribe", json!([])).await["error"].is_string());
    }

    #[tokio::test]
    async fn subscribe_rejects_an_unknown_type() {
        let st = test_state().await;
        let r = call(&st, "stell_subscribe", json!(["notAThing"])).await;
        assert!(
            r["error"].is_string(),
            "unknown subscription type must be refused"
        );
        let r = call(&st, "stell_subscribe", json!([])).await;
        assert!(
            r["error"].is_string(),
            "missing subscription type must be refused"
        );
    }

    #[tokio::test]
    async fn subscribe_events_normalizes_the_contract_and_topics() {
        let st = test_state().await;
        let id = call(
            &st,
            "stell_subscribe",
            json!(["events", { "contract": hex::encode([0x7Au8; 32]), "topics": ["1", "0x2"] }]),
        )
        .await;
        let sub_id = assert_is_subscription_id(&id);
        let sub = hub().get(&sub_id).expect("subscription");
        match sub.topic {
            SubscriptionTopic::Events { contract, topics } => {
                assert_eq!(contract, Some(hex::encode([0x7Au8; 32])));
                assert_eq!(topics, vec!["1".to_string(), "0x2".to_string()]);
            }
            other => panic!("expected an events subscription, got {other:?}"),
        }
        // A broken contract address is refused, not silently ignored.
        let bad = call(
            &st,
            "stell_subscribe",
            json!(["events", { "contract": "not-an-address" }]),
        )
        .await;
        assert!(bad["error"].is_string());
        hub().unsubscribe(&sub_id);
    }

    #[tokio::test]
    async fn fanout_reaches_only_the_matching_subscriptions() {
        // An ISOLATED hub: the test's traffic cannot cross-talk with another
        // test's subscriptions on the process-wide hub.
        let h = SubscriptionHub::new();
        let heads = h.subscribe(SubscriptionTopic::NewHeads).expect("subscribe");
        let txs = h.subscribe(SubscriptionTopic::NewTxs).expect("subscribe");
        let evs = h
            .subscribe(SubscriptionTopic::Events {
                contract: Some(hex::encode([0x11u8; 32])),
                topics: vec!["7".to_string()],
            })
            .expect("subscribe");
        let other_evs = h
            .subscribe(SubscriptionTopic::Events {
                contract: Some(hex::encode([0x22u8; 32])),
                topics: vec![],
            })
            .expect("subscribe");

        // A new head addresses the `newHeads` subscriber only.
        let addressed = h.publish(
            &SubscriptionTopic::NewHeads,
            json!({ "height": 5, "hash": hex::encode([0x01u8; 32]) }),
        );
        assert_eq!(addressed, 1, "exactly one `newHeads` subscriber");

        // A contract event addresses the subscribers whose filter matches.
        let ev = crate::contract::ContractEvent {
            contract: [0x11u8; 32],
            topic: 7,
            value: 9,
        };
        let addressed = h.publish(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode(ev.contract)),
                topics: vec![ev.topic.to_string()],
            },
            json!({ "contract": hex::encode(ev.contract) }),
        );
        assert_eq!(addressed, 1, "only the matching `events` subscriber");
        assert!(h.get(&evs).is_some());
        assert!(h.get(&other_evs).is_some());
        assert!(h.get(&heads).is_some());
        assert!(h.get(&txs).is_some());
    }

    #[tokio::test]
    async fn fanout_notifications_carry_the_subscription_id_and_the_payload() {
        let h = SubscriptionHub::new();
        let sub_id = h.subscribe(SubscriptionTopic::NewHeads).expect("subscribe");
        let mut rx = h.notifications();
        let addressed = h.publish(
            &SubscriptionTopic::NewHeads,
            json!({ "height": 9, "hash": hex::encode([0x02u8; 32]), "finality": "finalized" }),
        );
        assert_eq!(addressed, 1);
        let note = rx.recv().await.expect("notification");
        assert_eq!(note.subscription, sub_id);
        assert_eq!(note.result["height"], json!(9));
        assert_eq!(note.result["finality"], json!("finalized"));
        // The wire shape is exactly {"subscription":..., "result":...}.
        let wire = serde_json::to_value(&note).expect("serialize");
        assert!(wire.get("subscription").is_some());
        assert!(wire.get("result").is_some());
        assert_eq!(wire.as_object().expect("object").len(), 2);
    }

    #[tokio::test]
    async fn event_filter_matches_by_contract_and_topic() {
        let ev = SubscriptionTopic::Events {
            contract: Some(hex::encode([0x11u8; 32])),
            topics: vec!["7".to_string()],
        };
        // No filter: matches everything.
        assert!(topic_matches(
            &SubscriptionTopic::Events {
                contract: None,
                topics: vec![]
            },
            &ev
        ));
        // Same contract, same topic.
        assert!(topic_matches(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode([0x11u8; 32])),
                topics: vec!["7".to_string()]
            },
            &ev
        ));
        // Same contract, topic given in hex.
        assert!(topic_matches(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode([0x11u8; 32])),
                topics: vec!["0x7".to_string()]
            },
            &ev
        ));
        // Wildcard topic.
        assert!(topic_matches(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode([0x11u8; 32])),
                topics: vec!["*".to_string()]
            },
            &ev
        ));
        // Other contract: no match.
        assert!(!topic_matches(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode([0x22u8; 32])),
                topics: vec!["7".to_string()]
            },
            &ev
        ));
        // Other topic: no match.
        assert!(!topic_matches(
            &SubscriptionTopic::Events {
                contract: Some(hex::encode([0x11u8; 32])),
                topics: vec!["8".to_string()]
            },
            &ev
        ));
        // A `newHeads` filter never matches an event.
        assert!(!topic_matches(&SubscriptionTopic::NewHeads, &ev));
    }

    #[tokio::test]
    async fn publish_hook_emits_the_documented_payload_shapes() {
        let h = SubscriptionHub::new();
        let heads = h.subscribe(SubscriptionTopic::NewHeads).expect("subscribe");
        let txs = h.subscribe(SubscriptionTopic::NewTxs).expect("subscribe");
        let evs = h
            .subscribe(SubscriptionTopic::Events {
                contract: None,
                topics: vec![],
            })
            .expect("subscribe");
        let mut rx = h.notifications();

        // newHeads
        let payload = json!({
            "height": 42u64,
            "hash": hex::encode([0x33u8; 32]),
            "shard_id": 0u32,
            "tx_count": 2usize,
            "timestamp": 1700000000u64,
            "finality": "finalized",
        });
        assert_eq!(h.publish(&SubscriptionTopic::NewHeads, payload.clone()), 1);
        let note = rx.recv().await.expect("head notification");
        assert_eq!(note.subscription, heads);
        assert_eq!(note.result, payload);

        // newTxs
        let payload = json!({
            "hash": hex::encode([0x44u8; 32]),
            "from": hex::encode([0x55u8; 32]),
            "to": hex::encode([0x66u8; 32]),
            "amount": 100u64,
            "status": "confirmed",
        });
        assert_eq!(h.publish(&SubscriptionTopic::NewTxs, payload.clone()), 1);
        let note = rx.recv().await.expect("tx notification");
        assert_eq!(note.subscription, txs);
        assert_eq!(note.result, payload);

        // events
        let ev = crate::contract::ContractEvent {
            contract: [0x77u8; 32],
            topic: 3,
            value: 4,
        };
        let payload = json!({
            "contract": hex::encode(ev.contract),
            "topics": vec!["3".to_string()],
            "data": hex::encode((ev.value as u64).to_be_bytes()),
            "block_height": 42u64,
            "tx_hash": hex::encode([0x88u8; 32]),
        });
        assert_eq!(
            h.publish(
                &SubscriptionTopic::Events {
                    contract: Some(hex::encode(ev.contract)),
                    topics: vec!["3".to_string()]
                },
                payload.clone()
            ),
            1
        );
        let note = rx.recv().await.expect("event notification");
        assert_eq!(note.subscription, evs);
        assert_eq!(note.result, payload);
    }

    #[tokio::test]
    async fn consensus_finalize_publishes_a_head_and_a_transaction() {
        // The consensus hook: `record_block` (finalize / adopt path) and
        // `record_receipts_with_events` are what the chain calls, so a
        // subscriber sees the finalized head and the included transaction.
        let st = test_state().await;
        let mut rx = hub().notifications();
        let head_sub = hub()
            .subscribe(SubscriptionTopic::NewHeads)
            .expect("subscribe");
        let tx_sub = hub()
            .subscribe(SubscriptionTopic::NewTxs)
            .expect("subscribe");
        let ev_sub = hub()
            .subscribe(SubscriptionTopic::Events {
                contract: None,
                topics: vec![],
            })
            .expect("subscribe");

        let tx = receipt_tx(7, 0);
        let tx_hash = tx.compute_tx_hash();
        st.record_receipts_with_events(
            77,
            [0xAB; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[1],
            &[vec![crate::contract::ContractEvent {
                contract: [0x99u8; 32],
                topic: 1,
                value: 2,
            }]],
        )
        .await;
        st.record_block(77, [0xAB; 32], 1, 1_700_000_000).await;

        // Collect the notifications addressed to OUR subscriptions. The hub is
        // process-wide, so a concurrent test may publish other heads/txs on
        // it: pick the ones that carry OUR payload, never "the first one".
        let is_head =
            |r: &Value| r["height"] == json!(77) && r["hash"] == json!(hex::encode([0xAB; 32]));
        let is_tx = |r: &Value| r["hash"] == json!(hex::encode(tx_hash));
        let is_event = |r: &Value| r["contract"] == json!(hex::encode([0x99u8; 32]));
        let mut head: Option<Value> = None;
        let mut tx_notif: Option<Value> = None;
        let mut ev_notif: Option<Value> = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline
            && (head.is_none() || tx_notif.is_none() || ev_notif.is_none())
        {
            let note = match tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
                .await
            {
                Ok(Ok(n)) => n,
                _ => continue,
            };
            if head.is_none() && is_head(&note.result) {
                head = Some(note.result.clone());
            }
            if tx_notif.is_none() && is_tx(&note.result) {
                tx_notif = Some(note.result.clone());
            }
            if ev_notif.is_none() && is_event(&note.result) {
                ev_notif = Some(note.result.clone());
            }
        }

        let head = head.as_ref().expect("head notification");
        assert_eq!(head["height"], json!(77));
        assert_eq!(head["hash"], hex::encode([0xAB; 32]));
        assert_eq!(head["shard_id"], json!(0));
        assert_eq!(head["tx_count"], json!(1));
        assert_eq!(head["timestamp"], json!(1_700_000_000u64));
        assert_eq!(head["finality"], json!("finalized"));

        let tx_notif = tx_notif.as_ref().expect("tx notification");
        assert_eq!(tx_notif["hash"], hex::encode(tx_hash));
        assert_eq!(tx_notif["from"], hex::encode(tx.from));
        assert_eq!(tx_notif["to"], hex::encode([0xEE; 32]));
        assert_eq!(tx_notif["amount"], json!(10u64));
        assert_eq!(tx_notif["status"], json!("confirmed"));

        let ev_notif = ev_notif.as_ref().expect("event notification");
        assert_eq!(ev_notif["contract"], hex::encode([0x99u8; 32]));
        assert_eq!(ev_notif["topics"], json!(["1"]));
        assert_eq!(ev_notif["block_height"], json!(77));
        assert_eq!(ev_notif["tx_hash"], hex::encode(tx_hash));

        hub().unsubscribe(&head_sub);
        hub().unsubscribe(&tx_sub);
        hub().unsubscribe(&ev_sub);
    }

    #[tokio::test]
    async fn sse_stream_emits_data_frames() {
        use futures::StreamExt;
        let contract = hex::encode([0xEEu8; 32]);
        let resp = sse_handler(Query(StreamQuery {
            sub_id: None,
            topics: Some("events".to_string()),
            contract: Some(contract.clone()),
            event_topics: None,
        }))
        .await
        .expect("sse handler");
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        let sub_id = resp
            .headers()
            .get("x-stell-subscription-id")
            .and_then(|v| v.to_str().ok())
            .expect("subscription id header")
            .to_string();
        let mut body = resp.into_body().into_data_stream();

        publish_contract_event(
            &crate::contract::ContractEvent {
                contract: [0xEEu8; 32],
                topic: 7,
                value: 42,
            },
            100,
            [0x11; 32],
        );

        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let chunk = body.next().await.expect("sse stream ended");
                let text = String::from_utf8_lossy(&chunk.expect("chunk")).to_string();
                if let Some(pos) = text.find("data: ") {
                    return text[pos + "data: ".len()..].trim().to_string();
                }
            }
        })
        .await
        .expect("sse frame timeout");

        let note: Value = serde_json::from_str(&frame).expect("json frame");
        assert_eq!(note["subscription"], json!(sub_id));
        assert_eq!(note["result"]["contract"], json!(contract));
        assert_eq!(note["result"]["topics"], json!(["7"]));
        assert_eq!(note["result"]["block_height"], json!(100));
        assert_eq!(note["result"]["tx_hash"], hex::encode([0x11u8; 32]));
    }

    #[tokio::test]
    async fn websocket_transport_pushes_notifications() {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let st = test_state().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = router(st.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .expect("websocket handshake");
        // Subscribe over the socket.
        ws.send(Message::Text(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "stell_subscribe",
                "params": ["newHeads"]
            })
            .to_string(),
        ))
        .await
        .expect("send subscribe");
        let reply = ws.next().await.expect("reply").expect("frame");
        let reply: Value = serde_json::from_str(reply.to_text().expect("text")).expect("json");
        assert_eq!(reply["id"], json!(1));
        let sub_id = assert_is_subscription_id(&reply["result"]);

        // A finalized head is pushed to the socket.
        publish_new_head(4242, [0x42u8; 32], 0, 3, 1_700_000_123);
        let pushed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let frame = ws.next().await.expect("frame").expect("msg");
                let text = frame.to_text().expect("text").to_string();
                let v: Value = serde_json::from_str(&text).expect("json");
                // The hub is process-wide: other heads may be pushed to the
                // same subscription, so pick the one we published.
                if v["subscription"] == json!(sub_id) && v["result"]["height"] == json!(4242) {
                    return v;
                }
            }
        })
        .await
        .expect("push timeout");
        assert_eq!(pushed["subscription"], json!(sub_id));
        assert_eq!(pushed["result"]["height"], json!(4242));
        assert_eq!(pushed["result"]["hash"], hex::encode([0x42u8; 32]));
        assert_eq!(pushed["result"]["finality"], json!("finalized"));

        // Unsubscribing over the socket removes the subscription.
        ws.send(Message::Text(
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "stell_unsubscribe",
                "params": [sub_id]
            })
            .to_string(),
        ))
        .await
        .expect("send unsubscribe");
        let reply = ws.next().await.expect("reply").expect("frame");
        let reply: Value = serde_json::from_str(reply.to_text().expect("text")).expect("json");
        assert_eq!(reply["result"], json!(true));
        assert!(hub().get(&sub_id).is_none(), "subscription must be gone");

        let _ = ws.close(None).await;
        server.abort();
    }

    // ------------------------------------------------------------------
    // Block invalidations: the read side (`stell_getInvalidations`) and
    // the push side (the `invalidations` subscription topic).
    // ------------------------------------------------------------------

    /// The invalidation feed: what this node invalidated, and why.
    #[tokio::test]
    async fn get_invalidations_returns_the_published_signals() {
        let st = test_state().await;
        // An ISOLATED hub: the process-wide one carries the traffic of every
        // other test, so the window this test asserts on must be its own.
        let h = isolated_hub();
        let sig = crate::chain::InvalidationSignal {
            orphaned_blocks: vec![[0xA1u8; 32], [0xA2u8; 32]],
            reason: "candidate branch superseded at height 7".to_string(),
            height: 7,
        };
        publish_invalidation(&sig);

        let r = call(&st, "stell_getInvalidations", json!({})).await;
        let list = r["invalidations"].as_array().expect("array");
        assert_eq!(r["count"], json!(list.len()));
        assert_eq!(r["count"], json!(1), "only OUR signal is in the window");
        let found = list
            .iter()
            .find(|s| s["reason"] == json!("candidate branch superseded at height 7"))
            .expect("the published signal must be served");
        assert_eq!(found["height"], json!(7));
        assert_eq!(found["orphaned_count"], json!(2));
        assert_eq!(
            found["orphaned_blocks"][0],
            json!(hex::encode([0xA1u8; 32]))
        );
        assert_eq!(
            found["orphaned_blocks"][1],
            json!(hex::encode([0xA2u8; 32]))
        );
        // The window is the read side of the same promise the fan-out makes.
        assert_eq!(h.recent_invalidations(0).len(), 1);
    }

    /// The feed is EMPTY when nothing was invalidated: a node that never
    /// forked has nothing to retract.
    ///
    /// The hub is process-wide, so this test installs an ISOLATED one: the
    /// assertion is then about the node's own history, not about the tests
    /// running next to it.
    #[tokio::test]
    async fn get_invalidations_is_empty_when_nothing_was_invalidated() {
        let st = test_state().await;
        let h = isolated_hub();
        assert!(
            h.recent_invalidations(0).is_empty(),
            "a fresh hub knows no invalidation"
        );
        let r = call(&st, "stell_getInvalidations", json!({})).await;
        assert_eq!(r["count"], json!(0));
        assert_eq!(r["invalidations"], json!([]));
    }

    /// The feed's shape is stable: `count` always matches the list it
    /// serves.
    #[tokio::test]
    async fn get_invalidations_answers_with_a_matching_count() {
        let st = test_state().await;
        isolated_hub();
        let r = call(&st, "stell_getInvalidations", json!({})).await;
        let n = r["invalidations"].as_array().map(|a| a.len()).unwrap_or(0);
        assert_eq!(r["count"], json!(n));
        assert_eq!(r["count"], json!(0));
    }

    /// The feed is a RING BUFFER: the oldest signals are dropped and the
    /// newest are served, and a limit returns the newest ones.
    #[tokio::test]
    async fn get_invalidations_serves_the_newest_signals_within_the_limit() {
        let st = test_state().await;
        let h = isolated_hub();
        for i in 0..(crate::chain::MAX_INVALIDATION_WINDOW + 5) {
            h.record_invalidation(crate::chain::InvalidationSignal {
                orphaned_blocks: vec![[i as u8; 32]],
                reason: format!("signal {i}"),
                height: i as u64,
            });
        }
        let r = call(&st, "stell_getInvalidations", json!({})).await;
        let list = r["invalidations"].as_array().expect("array");
        assert_eq!(list.len(), crate::chain::MAX_INVALIDATION_WINDOW);
        assert_eq!(
            list[0]["height"],
            json!(5u64),
            "the oldest signals are dropped"
        );
        assert_eq!(
            list[list.len() - 1]["height"],
            json!((crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64),
            "the newest signal is kept"
        );
        // A limit returns the newest signals only.
        let limited = call(&st, "stell_getInvalidations", json!({ "limit": 2 })).await;
        let limited = limited["invalidations"].as_array().expect("array");
        assert_eq!(limited.len(), 2);
        assert_eq!(
            limited[1]["height"],
            json!((crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64)
        );
    }

    /// The SSE transport knows the `invalidations` topic too: a browser
    /// (which cannot speak WebSocket) follows the SAME signals a bot does.
    #[tokio::test]
    async fn the_sse_transport_streams_invalidations() {
        use futures::StreamExt;
        isolated_hub();
        let resp = sse_handler(Query(StreamQuery {
            sub_id: None,
            topics: Some("invalidations".to_string()),
            contract: None,
            event_topics: None,
        }))
        .await
        .expect("sse handler");
        let sub_id = resp
            .headers()
            .get("x-stell-subscription-id")
            .and_then(|v| v.to_str().ok())
            .expect("subscription id header")
            .to_string();
        let mut body = resp.into_body().into_data_stream();

        publish_invalidation(&crate::chain::InvalidationSignal {
            orphaned_blocks: vec![[0xC3u8; 32]],
            reason: "candidate branch superseded at height 5".to_string(),
            height: 5,
        });

        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let chunk = body.next().await.expect("sse stream ended");
                let text = String::from_utf8_lossy(&chunk.expect("chunk")).to_string();
                if let Some(pos) = text.find("data: ") {
                    return text[pos + "data: ".len()..].trim().to_string();
                }
            }
        })
        .await
        .expect("sse frame timeout");

        let note: Value = serde_json::from_str(&frame).expect("json frame");
        assert_eq!(note["subscription"], json!(sub_id));
        assert_eq!(note["result"]["height"], json!(5));
        assert_eq!(
            note["result"]["orphaned_blocks"][0],
            json!(hex::encode([0xC3u8; 32]))
        );
        assert_eq!(note["result"]["orphaned_count"], json!(1));
    }

    /// The EVENT HOOK: a streaming subscriber of the `invalidations` topic
    /// receives the signal.
    #[tokio::test]
    async fn invalidation_subscribers_receive_the_signal() {
        let st = test_state().await;
        isolated_hub();
        let sub_id = assert_is_subscription_id(
            &call(&st, "stell_subscribe", json!(["invalidations"])).await,
        );
        let mut rx = hub().notifications();
        let sig = crate::chain::InvalidationSignal {
            orphaned_blocks: vec![[0xB1u8; 32]],
            reason: "reorg: candidate branch superseded".to_string(),
            height: 3,
        };
        publish_invalidation(&sig);
        // The hub is process-wide: other notifications may arrive first, so
        // pick the one that belongs to OUR subscription.
        let note = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let n = rx.recv().await.expect("notification");
                if n.subscription == sub_id {
                    break n;
                }
            }
        })
        .await
        .expect("push timeout");
        assert_eq!(note.result["height"], json!(3));
        assert_eq!(
            note.result["orphaned_blocks"][0],
            json!(hex::encode([0xB1u8; 32]))
        );
        assert_eq!(note.result["orphaned_count"], json!(1));
        hub().unsubscribe(&sub_id);
    }

    /// END TO END: the consensus runtime invalidates a losing branch, and
    /// the signal reaches the RPC feed a client reads.
    #[tokio::test]
    async fn a_runtime_invalidation_reaches_the_rpc_feed() {
        use crate::consensus::ValidatorSet;
        use crate::runtime::ValidatorRuntime;
        use crate::sharding::{Block, MASTERCHAIN_SHARD};
        use crate::state_engine::InMemoryStateEngine;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let st = test_state().await;
        // An ISOLATED hub: the runtime publishes through the sink below, and
        // the window this test asserts on must hold nothing else.
        isolated_hub();

        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let mk = |height: u64, prev: [u8; 32], tag: u8| {
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                state_root: [tag; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: height,
                proposer: key.verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            b.sign_block(&key);
            b
        };

        let mut rt = ValidatorRuntime::new(
            key.clone(),
            ValidatorSet::from_list(vec![(me, 1)]),
            Arc::new(InMemoryStateEngine::new()),
            1,
        )
        .with_invalidation_sink(Arc::new(|sig: crate::chain::InvalidationSignal| {
            publish_invalidation(&sig);
        }));

        // A finalized block anchors the fork-choice, then two candidates
        // compete at the next height, and a third block is finalized there:
        // the two candidates lose and are invalidated.
        let f1 = mk(1, [0u8; 32], 0xF1);
        let f1h = f1.compute_hash();
        rt.note_finalized_block(&f1);
        let c1 = mk(2, f1h, 0xC1);
        let c2 = mk(2, f1h, 0xC2);
        assert!(rt.record_candidate_block(&c1));
        assert!(rt.record_candidate_block(&c2));
        let w = mk(2, f1h, 0xA7);
        rt.note_finalized_block(&w);

        let r = call(&st, "stell_getInvalidations", json!({})).await;
        assert_eq!(r["count"], json!(2), "both losing candidates are reported");
        let mut hashes: Vec<String> = r["invalidations"]
            .as_array()
            .expect("array")
            .iter()
            .map(|s| {
                s["orphaned_blocks"][0]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        hashes.sort();
        let mut expected = vec![
            hex::encode(c1.compute_hash()),
            hex::encode(c2.compute_hash()),
        ];
        expected.sort();
        assert_eq!(hashes, expected);
        assert_eq!(r["invalidations"][0]["height"], json!(2));
    }

    /// The invalidation window is bounded and keeps the NEWEST signals.
    #[tokio::test]
    async fn the_invalidation_window_is_bounded_and_ordered() {
        let h = SubscriptionHub::new();
        for i in 0..(crate::chain::MAX_INVALIDATION_WINDOW + 5) {
            h.record_invalidation(crate::chain::InvalidationSignal {
                orphaned_blocks: vec![[i as u8; 32]],
                reason: format!("signal {i}"),
                height: i as u64,
            });
        }
        let win = h.recent_invalidations(0);
        assert_eq!(win.len(), crate::chain::MAX_INVALIDATION_WINDOW);
        assert_eq!(
            win.last().unwrap().height,
            (crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64
        );
        // A limit returns the NEWEST signals.
        let last_two = h.recent_invalidations(2);
        assert_eq!(last_two.len(), 2);
        assert_eq!(
            last_two[1].height,
            (crate::chain::MAX_INVALIDATION_WINDOW + 4) as u64
        );
        // A signal without orphaned blocks carries no information: it is
        // never recorded.
        let before = h.recent_invalidations(0).len();
        h.record_invalidation(crate::chain::InvalidationSignal {
            orphaned_blocks: vec![],
            reason: "nothing".to_string(),
            height: 0,
        });
        assert_eq!(h.recent_invalidations(0).len(), before);
    }

    // ---- the native interface namespace (JSON-RPC level) ----

    /// The native namespace is REACHABLE through the JSON-RPC dispatcher and
    /// answers with its documented shape.
    #[tokio::test]
    async fn native_api_namespace_is_reachable_over_json_rpc() {
        let st = test_state().await;

        // The manifest: the whole interface in one call.
        let v = call(&st, "stell_nativeApi", json!({})).await;
        assert_eq!(v["version"], crate::native_api::NATIVE_API_VERSION);
        let methods = v["methods"].as_array().expect("methods array");
        assert!(methods.len() >= 21);
        assert!(methods.iter().any(|m| m["name"] == "stell_tokenTransfer"));
        assert!(methods.iter().any(|m| m["name"] == "stell_oracleFeeds"));

        // A read method answers with its documented shape.
        let v = call(
            &st,
            "stell_tokenBalanceOf",
            json!({ "token": hex::encode([9u8; 32]), "account": hex::encode([1u8; 32]) }),
        )
        .await;
        // The token does not exist: an error, never a zero balance.
        assert!(v["error"].is_string(), "unknown token must fail closed");

        // A missing parameter is an error too.
        let v = call(&st, "stell_tokenBalanceOf", json!({})).await;
        assert!(v["error"].is_string());

        // An unknown method is still "method not found".
        let v = call(&st, "stell_notARealMethod", json!({})).await;
        assert!(v["error"].is_string());
    }

    /// The native write methods produce a transaction to sign and never
    /// mutate the state they read.
    #[tokio::test]
    async fn native_api_prepare_methods_do_not_mutate_state() {
        let st = test_state().await;
        let before = st.engine.get_state_root().await;

        let v = call(
            &st,
            "stell_orderBookPlace",
            json!({ "pair": 1, "side": "buy", "price": "250000", "amount": "10" }),
        )
        .await;
        assert_eq!(v["action"], "order_book_place");
        assert_eq!(v["transaction"]["op"], "SysCallPlaceOrder");
        assert_eq!(v["submit_with"], "stell_sendRawTransaction");

        let after = st.engine.get_state_root().await;
        assert_eq!(
            before, after,
            "a prepared transaction must not touch the state"
        );
    }

    /// `stell_runGetMethod` must be bounded in BOTH fuel and arity: the
    /// getter's "legacy tolerance" fallback walks the whole argument list
    /// looking for a matching export, so an unbounded argument array turns
    /// one request into hundreds of thousands of export lookups.
    #[tokio::test]
    async fn run_get_method_refuses_an_unbounded_argument_list() {
        let st = test_state().await;
        let creator = [0x55u8; 32];
        let addr = st
            .engine
            .deploy_contract(creator, abi_contract_wasm(), 0)
            .await
            .unwrap();
        let addr_hex = hex::encode(addr);
        let many: Vec<i64> = (0..(crate::contract::MAX_CONTRACT_CALL_ARGS as i64 + 50)).collect();
        let r = call(
            &st,
            "stell_runGetMethod",
            json!({ "address": addr_hex, "method": "get", "args": many }),
        )
        .await;
        assert!(
            r["success"] == json!(false),
            "an oversized argument list must be refused: {r}"
        );
        let msg = r["error"].as_str().unwrap_or("");
        assert!(
            msg.contains("too many arguments") || msg.contains("argument"),
            "the refusal must name the argument problem: {msg}"
        );
    }

    // ===================================================================
    // RPC SURFACE HARDENING (audit W6.7)
    // ===================================================================

    /// A call attributed to a client IP (the per-IP budgets need one).
    async fn call_from(
        st: &Arc<RpcState>,
        method: &str,
        params: Value,
        ip: std::net::IpAddr,
    ) -> Value {
        let r = dispatch(st, Value::from(1), method, &params, None, Some(ip)).await;
        r.0.error
            .map(|e| json!({"error": e.message}))
            .unwrap_or(r.0.result.unwrap_or(Value::Null))
    }

    /// `stell_executeProposal` applies the action of a PASSED proposal — and
    /// one of the actions is `SoftwareUpgrade`, the path that ends in an
    /// `execve` of a new binary. It was the ONLY governance write arm with no
    /// token gate, while `stell_submitProposal` and `stell_vote` were gated.
    #[tokio::test]
    async fn execute_proposal_requires_the_auth_token() {
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
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        });

        // A proposal that is already PASSED (the quorum is the ledger's job).
        {
            let mut g = st.governance.write().await;
            g.next_id = 7;
            g.proposals.insert(
                7,
                crate::governance::Proposal {
                    id: 7,
                    proposer: [0x01u8; 32],
                    title: "t".into(),
                    action: crate::governance::GovAction::Signal("hello".into()),
                    created_at: 0,
                    voting_end: 1,
                    yes: 1,
                    no: 0,
                    abstain: 0,
                    voters: Default::default(),
                    status: crate::governance::ProposalStatus::Passed,
                    electorate: 1,
                    electorate_weights: None,
                    proposer_lock: 0,
                    weights: Default::default(),
                },
            );
        }

        // WITHOUT the token: refused.
        let r = call(&st, "stell_executeProposal", json!({ "id": 7 })).await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("unauthorized"),
            "stell_executeProposal must require the auth token: {r}"
        );
        assert_eq!(
            st.governance.read().await.get(7).map(|p| p.status),
            Some(crate::governance::ProposalStatus::Passed),
            "a refused execution must not change the proposal"
        );

        // WITH the token: executed.
        let r = call(
            &st,
            "stell_executeProposal",
            json!({ "id": 7, "token": "secret" }),
        )
        .await;
        assert_eq!(
            r["executed"],
            json!(true),
            "an authorized execution must run: {r}"
        );
        assert_eq!(
            st.governance.read().await.get(7).map(|p| p.status),
            Some(crate::governance::ProposalStatus::Executed)
        );
    }

    /// The bind parser: only provably-loopback binds read as loopback, so the
    /// gov-write gate fails closed on anything else.
    /// // GATE: fail-closed direction of H-01 (unparseable → refused).
    #[test]
    fn bind_addr_loopback_parser_is_fail_closed() {
        for good in [
            "127.0.0.1:8545",
            "127.0.0.1",
            "127.2.3.4:1",
            "localhost:8545",
            "localhost",
            "[::1]:8545",
            "::1",
            "  127.0.0.1:8545  ",
        ] {
            assert!(bind_addr_is_loopback(good), "{good} must read as loopback");
        }
        for bad in [
            "0.0.0.0:8545",
            "0.0.0.0",
            "192.168.1.10:8545",
            "10.0.0.5:8545",
            "example.com:8545",
            "example.com",
            "",
            "garbage",
            ":8545",
            "[::1",
            "127.0.0.1:abc",
        ] {
            assert!(
                !bind_addr_is_loopback(bad),
                "{bad} must NOT read as loopback"
            );
        }
    }

    /// N-02: gov writes require a valid token ALWAYS, on EVERY bind — the
    /// loopback escape is deleted. A missing/unconfigured token refuses on
    /// both a loopback and a non-loopback bind (mock bind proves
    /// bind-independence); a correct token serves on both binds.
    /// // GATE: N-02 token-always; same refusal properties, never weakened.
    #[tokio::test]
    async fn gov_writes_require_token_on_every_bind() {
        // Panic-safe mock guard: the override is process-wide (a mutex, never
        // the env), so it must reset even when an assert below fails. The
        // mock now only steers the unsigned-dev-test escape — the token gate
        // ignores it, which is exactly what this test pins.
        struct BindGuard;
        impl Drop for BindGuard {
            fn drop(&mut self) {
                set_test_bind_loopback(None);
            }
        }
        let _guard = BindGuard;

        // 1. No token configured: all three gov writes refuse on a
        //    non-loopback bind AND on a loopback bind. The gate runs before
        //    payload parsing, so garbage params are still unauthorized
        //    (never a parse error).
        let st = test_state().await;
        for mock in [Some(false), Some(true)] {
            set_test_bind_loopback(mock);
            for (method, params) in [
                (
                    "stell_submitProposal",
                    json!({"title": "t", "type": "signal", "proposer": hex::encode([9u8; 32])}),
                ),
                (
                    "stell_vote",
                    json!({"id": 1, "voter": hex::encode([9u8; 32])}),
                ),
                ("stell_executeProposal", json!({"id": 1})),
            ] {
                let r = call(&st, method, params).await;
                assert!(
                    r["error"].as_str().unwrap_or("").contains("unauthorized"),
                    "{method} without a token (bind loopback={mock:?}) must refuse: {r}"
                );
            }
        }
        assert!(
            st.governance.read().await.proposals.is_empty(),
            "refused writes must not record anything"
        );

        // 2. Token configured but missing/wrong: still refused, on both binds.
        let st = test_state_with_token().await;
        for mock in [Some(false), Some(true)] {
            set_test_bind_loopback(mock);
            let r = call(&st, "stell_executeProposal", json!({ "id": 1 })).await;
            assert!(
                r["error"].as_str().unwrap_or("").contains("unauthorized"),
                "missing token (bind loopback={mock:?}) must refuse: {r}"
            );
            let r = call(
                &st,
                "stell_executeProposal",
                json!({ "id": 1, "token": "wrong" }),
            )
            .await;
            assert!(
                r["error"].as_str().unwrap_or("").contains("unauthorized"),
                "wrong token (bind loopback={mock:?}) must refuse: {r}"
            );
        }

        // 3. Correct token: signed flows work end to end on BOTH binds.
        // GATE (operator-signed governance): both writes are signed with the
        // stakers' own keys (the unsigned legacy path stays refused without
        // STELL_DEV_UNSAFE_TESTKEY=1, which this test does not set).
        for mock in [Some(false), Some(true)] {
            set_test_bind_loopback(mock);
            let st = test_state_with_token().await;
            let proposer_key = TestGovKey::ed25519([0xA1u8; 32]);
            let proposer = proposer_key.address();
            let voter_key = TestGovKey::ed25519([0xB2u8; 32]);
            let voter = voter_key.address();
            {
                let mut ledger = st.engine.staking_write().await;
                ledger
                    .bond(proposer, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                    .unwrap();
                ledger
                    .bond(voter, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                    .unwrap();
            }
            let title = "dev".to_string();
            let action = crate::governance::GovAction::Signal("hi".to_string());
            let r = call_with_token(
                &st,
                "stell_submitProposal",
                json!({
                    "title": title,
                    "type": "signal",
                    "text": "hi",
                    "proposer": hex::encode(proposer),
                    "nonce": 1u64,
                    "signature": sign_test_proposal(st.chain_id, &proposer_key, &proposer, &title, &action, 1),
                }),
            )
            .await;
            let pid = r["proposal_id"]
                .as_u64()
                .unwrap_or_else(|| panic!("token-authed submit (bind loopback={mock:?}) must work: {r}"));
            assert!(
                r.get("error").is_none(),
                "token-authed submit (bind loopback={mock:?}) must work: {r}"
            );
            let r = call_with_token(
                &st,
                "stell_vote",
                json!({
                    "id": pid,
                    "voter": hex::encode(voter),
                    "choice": "yes",
                    "signature": sign_test_vote(st.chain_id, &voter_key, &voter, pid, crate::governance::VoteChoice::Yes),
                }),
            )
            .await;
            assert_eq!(r["voted"], json!(true), "token-authed vote (bind loopback={mock:?}) must work: {r}");
        }
    }

    /// Operator-signed governance ingest: valid envelopes are accepted;
    /// unsigned, wrong-key, tampered, cross-chain, and replayed envelopes
    /// are refused fail-closed. Same-choice vote replay is idempotent;
    /// different-choice replay is refused (first choice wins).
    ///
    /// // GATE: new-path pins for operator-signed gov identity; extends, never weakens.
    #[tokio::test]
    async fn gov_writes_require_operator_signatures() {
        use crate::governance::{GovAction, VoteChoice};
        // N-02: the signature pins below run on the token fixture — the auth
        // gate passes, then the operator-signature checks fire.
        let st = test_state_with_token().await;
        let chain = st.chain_id;
        let proposer_key = TestGovKey::ed25519([0xA1u8; 32]);
        let proposer = proposer_key.address();
        let voter_key = TestGovKey::ed25519([0xB2u8; 32]);
        let voter = voter_key.address();
        let lone_key = TestGovKey::ed25519([0xC3u8; 32]);
        let lone = lone_key.address();
        {
            let mut ledger = st.engine.staking_write().await;
            ledger
                .bond(proposer, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                .unwrap();
            ledger
                .bond(voter, crate::governance::PROPOSAL_MIN_STAKE_NANO, 0)
                .unwrap();
        }
        let title = "sig test".to_string();
        let action = GovAction::Signal("hi".to_string());
        let submit = |title: &str, _action: &GovAction, nonce: u64, sig_hex: &str| {
            call_with_token(
                &st,
                "stell_submitProposal",
                json!({
                    "title": title,
                    "type": "signal",
                    "text": "hi",
                    "proposer": hex::encode(proposer),
                    "nonce": nonce,
                    "signature": sig_hex,
                }),
            )
        };

        // 1. Unsigned proposal: refused fail-closed (no new knob involved;
        //    this test process does not arm STELL_DEV_UNSAFE_TESTKEY).
        let r = call_with_token(
            &st,
            "stell_submitProposal",
            json!({
                "title": title,
                "type": "signal",
                "text": "hi",
                "proposer": hex::encode(proposer),
                "nonce": 1u64,
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("missing gov signature"),
            "unsigned proposal must be refused: {r}"
        );

        // 2. Valid signed proposal: accepted.
        let sig = sign_test_proposal(chain, &proposer_key, &proposer, &title, &action, 1);
        let r = submit(&title, &action, 1, &sig).await;
        assert!(r.get("error").is_none(), "valid signed proposal: {r}");
        let pid = r["proposal_id"].as_u64().expect("proposal id");

        // 3. Exact replay of the envelope: refused (nonce consumed).
        let r = submit(&title, &action, 1, &sig).await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("already consumed"),
            "replayed proposal nonce must be refused: {r}"
        );

        // 4. Wrong key: the voter's envelope presented as the proposer.
        let wrong_msg = crate::governance::Governance::gov_propose_message(
            chain,
            &proposer,
            &title,
            &action,
            2,
        );
        let wrong = voter_key.sign_message(chain, &wrong_msg).unwrap().to_hex();
        let r = submit(&title, &action, 2, &wrong).await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("wrong key"),
            "wrong-key proposal must be refused: {r}"
        );

        // 5. Tampered title: signed "sig test", submitted as something else.
        let r = submit("tampered title", &action, 3, &sig).await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("propose failed"),
            "tampered proposal must be refused: {r}"
        );

        // 6. Cross-chain envelope: minted for another chain.
        let cross_msg = crate::governance::Governance::gov_propose_message(
            chain + 1,
            &proposer,
            &title,
            &action,
            4,
        );
        let cross = proposer_key.sign_message(chain + 1, &cross_msg).unwrap().to_hex();
        let r = submit(&title, &action, 4, &cross).await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("propose failed"),
            "cross-chain proposal must be refused: {r}"
        );

        // 7. Stakeless key, perfectly valid signature: refused (NotStaker).
        let lone_msg = crate::governance::Governance::gov_propose_message(
            chain,
            &lone,
            &title,
            &action,
            5,
        );
        let lone_sig = lone_key.sign_message(chain, &lone_msg).unwrap().to_hex();
        let r = call_with_token(
            &st,
            "stell_submitProposal",
            json!({
                "title": title,
                "type": "signal",
                "text": "hi",
                "proposer": hex::encode(lone),
                "nonce": 5u64,
                "signature": lone_sig,
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("no staked balance"),
            "stakeless proposer must be refused: {r}"
        );

        // 8. Unsigned vote: refused fail-closed.
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({"id": pid, "voter": hex::encode(voter), "choice": "yes"}),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or("").contains("missing gov signature"),
            "unsigned vote must be refused: {r}"
        );

        // 9. Valid signed vote: accepted.
        let vsig = sign_test_vote(chain, &voter_key, &voter, pid, VoteChoice::Yes);
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(voter),
                "choice": "yes",
                "signature": vsig,
            }),
        )
        .await;
        assert_eq!(r["voted"], json!(true), "valid signed vote: {r}");
        let weight = r["weight"].as_str().unwrap_or("").to_string();

        // 10. Same-choice replay: idempotent, same weight.
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(voter),
                "choice": "yes",
                "signature": vsig,
            }),
        )
        .await;
        assert_eq!(r["voted"], json!(true), "same-choice replay: {r}");
        assert_eq!(r["weight"].as_str().unwrap_or(""), weight);

        // 11. Different choice with a fresh valid signature: refused.
        let flip = sign_test_vote(chain, &voter_key, &voter, pid, VoteChoice::No);
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(voter),
                "choice": "no",
                "signature": flip,
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("already voted"),
            "different-choice replay must be refused: {r}"
        );

        // 12. Tampered choice: Yes-envelope presented as No.
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(voter),
                "choice": "no",
                "signature": vsig,
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("vote failed"),
            "tampered vote must be refused: {r}"
        );

        // 13. Cross-chain vote.
        let cross_vmsg =
            crate::governance::Governance::gov_vote_message(chain + 1, pid, VoteChoice::Yes, &voter);
        let cross_vsig = voter_key.sign_message(chain + 1, &cross_vmsg).unwrap().to_hex();
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(voter),
                "choice": "yes",
                "signature": cross_vsig,
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("vote failed"),
            "cross-chain vote must be refused: {r}"
        );

        // 14. Stakeless key, valid vote signature: refused (NotStaker).
        let lone_vmsg =
            crate::governance::Governance::gov_vote_message(chain, pid, VoteChoice::Yes, &lone);
        let lone_vsig = lone_key.sign_message(chain, &lone_vmsg).unwrap().to_hex();
        let r = call_with_token(
            &st,
            "stell_vote",
            json!({
                "id": pid,
                "voter": hex::encode(lone),
                "choice": "yes",
                "signature": lone_vsig,
            }),
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or_default().contains("no staked balance"),
            "stakeless voter must be refused: {r}"
        );
    }

    /// `stell_getEvents` must answer a BOUNDED list: the receipt index holds
    /// up to 50 000 receipts and every receipt can carry up to 256 events, so
    /// an unfiltered contract query could otherwise answer with millions of
    /// events — an unbounded response body on an unauthenticated read.
    #[tokio::test]
    async fn get_events_answer_is_bounded() {
        let st = test_state().await;
        let contract = [0x77u8; 32];
        {
            let mut idx = st.receipts.write().await;
            // 200 receipts x 20 events = 4 000 events for ONE contract.
            for i in 0..200u64 {
                let events: Vec<crate::contract::ContractEvent> = (0..20)
                    .map(|j| crate::contract::ContractEvent {
                        contract,
                        topic: j as i64,
                        value: i as i64,
                    })
                    .collect();
                idx.insert(TxReceipt {
                    tx_hash: [i as u8; 32],
                    height: 1 + i,
                    block_hash: [0u8; 32],
                    index: 0,
                    success: true,
                    gas_limit: 0,
                    fee_charged: 0,
                    raw_tx: None,
                    return_value: None,
                    gas_used: None,
                    contract_address: None,
                    events,
                });
            }
        }
        let r = call(
            &st,
            "stell_getEvents",
            json!({ "contract": hex::encode(contract), "from_block": 0, "to_block": 1000 }),
        )
        .await;
        let arr = r.as_array().expect("must return an event array");
        assert_eq!(
            arr.len(),
            MAX_EVENTS_RETURNED,
            "the answer must be capped at MAX_EVENTS_RETURNED"
        );
        assert!(
            arr.len() < 4_000,
            "the answer must be far smaller than the stored event count"
        );
    }

    /// The subscription registry is bounded GLOBALLY, but one client must not
    /// be able to take the WHOLE registry and starve every other subscriber.
    #[tokio::test]
    async fn subscriptions_are_bounded_per_client() {
        let hub = isolated_hub();
        // The per-client cap.
        for _ in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
            hub.subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.1"))
                .expect("a client must be able to hold its own subscriptions");
        }
        let err = hub
            .subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.1"))
            .expect_err("the per-client cap must refuse the next one");
        assert!(
            err.contains("per-client"),
            "the error must name the cap: {err}"
        );
        // A DIFFERENT client is unaffected.
        hub.subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.2"))
            .expect("another client must not be starved by the first one");
        // An unattributed subscription is not charged to anybody.
        hub.subscribe(SubscriptionTopic::NewHeads)
            .expect("an unattributed subscription must work");
    }

    /// `stell_estimateFee` clones the WHOLE engine state and runs a full SVM
    /// execution, so it gets its OWN (much smaller) per-IP budget instead of
    /// the generic one.
    #[tokio::test]
    async fn estimate_fee_has_its_own_per_ip_budget() {
        let st = test_state().await;
        // Own bucket (see `fresh_estimate_ip`): the hammering must start from
        // an empty window no matter what else runs in this process.
        let ip = fresh_estimate_ip();
        // The budget is finite: after it is exhausted the call is refused.
        // The limiter is a per-second fixed window on wall-clock seconds, so
        // ONE hammer of budget+1 rapid calls can straddle a second boundary,
        // take a fresh window, and see no refusal. Rapid consecutive rounds
        // cannot ALL straddle (boundaries are 1s apart, a round is
        // milliseconds), so repeating the hammer on the SAME ip forces the
        // refusal without weakening the limit: every round still allows at
        // most ESTIMATE_FEE_RATE_LIMIT_DEFAULT per window. (The exact
        // in-window 5-ok/6th-refused threshold is pinned deterministically by
        // the `check_at` unit test; this test pins the production path.)
        let mut refused = false;
        for _ in 0..4 {
            for _ in 0..(ESTIMATE_FEE_RATE_LIMIT_DEFAULT as usize + 1) {
                let r = call_from(
                    &st,
                    "stell_estimateFee",
                    json!({ "from": hex::encode([0x11u8; 32]), "to": hex::encode([0x22u8; 32]) }),
                    ip,
                )
                .await;
                if r["error"]
                    .as_str()
                    .unwrap_or("")
                    .contains("budget exhausted")
                {
                    refused = true;
                    break;
                }
            }
            if refused {
                break;
            }
        }
        assert!(
            refused,
            "the estimate-fee budget must be enforced per IP (it clones the whole state)"
        );
        // A DIFFERENT IP is unaffected by the first one's exhaustion.
        let other = fresh_estimate_ip();
        let r = call_from(
            &st,
            "stell_estimateFee",
            json!({ "from": hex::encode([0x11u8; 32]), "to": hex::encode([0x22u8; 32]) }),
            other,
        )
        .await;
        assert!(
            r["error"].as_str().unwrap_or("").is_empty(),
            "another IP must not be starved by the first one's budget: {r}"
        );
    }

    // -----------------------------------------------------------------------
    // TAIL-1: batched receipt hashing.
    //
    // `record_receipts_with_events` hashes with one reused hasher and one
    // reused scratch buffer (pre-sized output). The receipts it files must be
    // byte-identical to the old per-transaction path: the test below pins the
    // old logic as a reference implementation and compares every filed field,
    // including the pre-existing-receipt merge branch. No wire-format,
    // quorum or state-transition change: receipts are RPC views, and these
    // tests prove the views are unchanged.
    // -----------------------------------------------------------------------

    /// The pre-batch receipt logic, frozen as the differential reference:
    /// one hasher + one payload buffer per transaction, one bincode alloc per
    /// receipt, and the same publish fan-out. Any divergence from
    /// `record_receipts_with_events` fails.
    async fn reference_record_receipts(
        st: &Arc<RpcState>,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        events: &[Vec<crate::contract::ContractEvent>],
    ) {
        let mut idx = st.receipts.write().await;
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let raw_tx = bincode::serialize(tx).ok().map(hex::encode);
            let h = tx.compute_tx_hash();
            hashes.push(h);
            let (rv, gu, ev, ca) = if let Some(existing) = idx.get(&h) {
                let evs = if !existing.events.is_empty() {
                    existing.events.clone()
                } else {
                    events.get(i).cloned().unwrap_or_default()
                };
                (
                    existing.return_value,
                    existing.gas_used,
                    evs,
                    existing.contract_address,
                )
            } else {
                (None, None, events.get(i).cloned().unwrap_or_default(), None)
            };
            idx.insert(TxReceipt {
                tx_hash: h,
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
                return_value: rv,
                gas_used: gu,
                events: ev,
                contract_address: ca,
            });
        }
        drop(idx);
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let hash = hashes[i];
            publish_new_tx(
                hash,
                tx.from,
                tx.to,
                tx.amount,
                if success { "confirmed" } else { "failed" },
            );
            if let Some(evs) = events.get(i) {
                for e in evs {
                    publish_contract_event(e, height, hash);
                }
            }
        }
    }

    fn assert_receipts_equal(a: &TxReceipt, b: &TxReceipt, ctx: &str) {
        assert_eq!(a.tx_hash, b.tx_hash, "{ctx}: tx_hash");
        assert_eq!(a.height, b.height, "{ctx}: height");
        assert_eq!(a.block_hash, b.block_hash, "{ctx}: block_hash");
        assert_eq!(a.index, b.index, "{ctx}: index");
        assert_eq!(a.success, b.success, "{ctx}: success");
        assert_eq!(a.gas_limit, b.gas_limit, "{ctx}: gas_limit");
        assert_eq!(a.fee_charged, b.fee_charged, "{ctx}: fee_charged");
        assert_eq!(a.raw_tx, b.raw_tx, "{ctx}: raw_tx");
        assert_eq!(a.return_value, b.return_value, "{ctx}: return_value");
        assert_eq!(a.gas_used, b.gas_used, "{ctx}: gas_used");
        assert_eq!(a.events, b.events, "{ctx}: events");
        assert_eq!(
            a.contract_address, b.contract_address,
            "{ctx}: contract_address"
        );
    }

    fn receipt_batch_txs(n: usize) -> Vec<crate::sharding::Transaction> {
        (0..n)
            .map(|i| {
                let mut from = [0u8; 32];
                from[0..8]
                    .copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
                receipt_tx(from[0].wrapping_add(from[7]).wrapping_add(i as u8), i as u64)
            })
            .collect()
    }

    #[tokio::test]
    async fn record_receipts_batched_is_byte_identical_to_reference() {
        let txs = receipt_batch_txs(256);
        let statuses: Vec<bool> = (0..txs.len()).map(|i| i % 3 != 0).collect();
        let fees: Vec<u64> = (0..txs.len()).map(|i| 1000 + i as u64).collect();
        let events: Vec<Vec<crate::contract::ContractEvent>> = (0..txs.len())
            .map(|i| {
                if i % 2 == 0 {
                    vec![crate::contract::ContractEvent {
                        contract: [i as u8; 32],
                        topic: i as i64,
                        value: -(i as i64),
                    }]
                } else {
                    vec![]
                }
            })
            .collect();

        // Pre-existing receipts on BOTH states: exercises the merge branch
        // (kept return_value/gas_used/contract_address, kept non-empty events).
        for st in [test_state().await, test_state().await] {
            let _ = st;
        }
        let batched_st = test_state().await;
        let ref_st = test_state().await;
        for st in [&batched_st, &ref_st] {
            st.receipts.write().await.insert(TxReceipt {
                tx_hash: txs[0].compute_tx_hash(),
                height: 1,
                block_hash: [0xAA; 32],
                index: 0,
                success: true,
                gas_limit: txs[0].gas_limit,
                fee_charged: 7,
                raw_tx: None,
                return_value: Some(42),
                gas_used: Some(9000),
                events: vec![crate::contract::ContractEvent {
                    contract: [0xE0; 32],
                    topic: 1,
                    value: 2,
                }],
                contract_address: Some([0xC0; 32]),
            });
        }

        batched_st
            .record_receipts_with_events(77, [0xAB; 32], &txs, &statuses, &fees, &events)
            .await;
        reference_record_receipts(&ref_st, 77, [0xAB; 32], &txs, &statuses, &fees, &events).await;

        let b = batched_st.receipts.read().await;
        let r = ref_st.receipts.read().await;
        assert_eq!(b.len(), r.len(), "same number of receipts filed");
        for tx in &txs {
            let h = tx.compute_tx_hash();
            let rb = b
                .get(&h)
                .unwrap_or_else(|| panic!("batched missing {}", hex::encode(h)));
            let rr = r
                .get(&h)
                .unwrap_or_else(|| panic!("reference missing {}", hex::encode(h)));
            assert_receipts_equal(rb, rr, &hex::encode(h));
        }
        // The pre-existing receipt's carried fields survive on both paths.
        let kept = b.get(&txs[0].compute_tx_hash()).unwrap();
        assert_eq!(kept.return_value, Some(42));
        assert_eq!(kept.gas_used, Some(9000));
        assert_eq!(kept.contract_address, Some([0xC0; 32]));
        assert_eq!(kept.events.len(), 1, "non-empty existing events are kept");
    }

    /// Perf: batched vs reference receipt recording over a block-sized batch.
    /// Best-of-N per path (interleaved) to ride out allocator noise; prints
    /// measured ms for the report. The hard assertion is byte equality.
    #[tokio::test]
    async fn perf_record_receipts_batched_vs_reference() {
        let txs = receipt_batch_txs(20_000);
        let statuses: Vec<bool> = (0..txs.len()).map(|i| i % 2 == 0).collect();
        let fees: Vec<u64> = (0..txs.len()).map(|i| 1000 + i as u64).collect();
        let events: Vec<Vec<crate::contract::ContractEvent>> = vec![vec![]; txs.len()];

        // Interleaved best-of-5: each iteration files into a FRESH state so
        // the receipt index starts empty every time.
        let mut best_reference = f64::INFINITY;
        let mut best_batched = f64::INFINITY;
        for _ in 0..5 {
            let ref_st = test_state().await;
            let t0 = std::time::Instant::now();
            reference_record_receipts(&ref_st, 77, [0xAB; 32], &txs, &statuses, &fees, &events)
                .await;
            best_reference = best_reference.min(t0.elapsed().as_secs_f64() * 1000.0);

            let batched_st = test_state().await;
            let t0 = std::time::Instant::now();
            batched_st
                .record_receipts_with_events(77, [0xAB; 32], &txs, &statuses, &fees, &events)
                .await;
            best_batched = best_batched.min(t0.elapsed().as_secs_f64() * 1000.0);
        }

        let ref_st = test_state().await;
        reference_record_receipts(&ref_st, 77, [0xAB; 32], &txs, &statuses, &fees, &events).await;
        let batched_st = test_state().await;
        batched_st
            .record_receipts_with_events(77, [0xAB; 32], &txs, &statuses, &fees, &events)
            .await;
        let b = batched_st.receipts.read().await;
        let r = ref_st.receipts.read().await;
        assert_eq!(b.len(), r.len());
        for tx in &txs {
            let h = tx.compute_tx_hash();
            assert_receipts_equal(b.get(&h).unwrap(), r.get(&h).unwrap(), &hex::encode(h));
        }
        eprintln!(
            "[perf] record_receipts 20k txs (best of 5): reference={best_reference:.2}ms batched={best_batched:.2}ms speedup={:.2}x",
            if best_batched > 0.0 { best_reference / best_batched } else { f64::INFINITY },
        );
    }

    /// WS hardening consts stay consistent with the HTTP surface they mirror.
    /// (The positivity/ordering shape is enforced at compile time next to
    /// the consts; this test pins the cross-surface equalities.)
    #[test]
    fn ws_hardening_consts_are_sane() {
        // The WS frame cap mirrors the HTTP body cap: no transport smuggles
        // a bigger request than the other.
        assert_eq!(WS_MAX_MESSAGE_BYTES, MAX_RPC_BODY);
        // The per-message general budget mirrors the standalone transport
        // budget: same per-IP fixed-window shape, same ceiling.
        assert_eq!(
            WS_GENERAL_RATE_LIMIT_DEFAULT, STANDALONE_RATE_LIMIT_DEFAULT,
            "WS general budget must stay symmetric to the standalone HTTP budget"
        );
    }

    /// Batch caps stay consistent with the single-call bounds they mirror.
    #[test]
    fn rpc_batch_consts_are_sane() {
        // GATE: black_box defeats const-folding; pins must fail loudly if changed.
        assert!(std::hint::black_box(MAX_RPC_BATCH_ITEMS) > 0);
        // The total batch byte bound is a multiple of the single-call body
        // bound (currently 1x: a batch can never exceed a single call's
        // bound, so batches add no new DoS surface).
        assert_eq!(MAX_RPC_BATCH_BYTES, MAX_RPC_BODY);
        assert!(std::hint::black_box(MAX_RPC_BATCH_BYTES) <= MAX_RPC_BODY);
    }

    /// Same as `test_state`, but with an API token configured so the gated
    /// arms can prove per-item auth inside a batch.
    async fn test_state_authed() -> Arc<RpcState> {
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
            auth_token: Some("test-token".to_string()),
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: ShardRegistry::single(),
        })
    }

    /// Happy batch: mixed methods (incl. 1 bad-params + 1 unknown + 1
    /// malformed item + 1 notification) — every item answers independently,
    /// one bad call never fails its siblings, order is preserved.
    #[tokio::test]
    async fn rpc_batch_happy_mixed_per_item_isolation() {
        let st = test_state().await;
        let items = vec![
            json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "stell_chainId", "params": []}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "stell_nopeNotReal", "params": []}),
            json!({"jsonrpc": "2.0", "id": 4, "method": "stell_sendRawTransaction", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 5}),
            json!({"jsonrpc": "2.0", "method": "eth_chainId", "params": []}),
        ];
        let raw = serde_json::to_string(&items).unwrap();
        let out = match handle_rpc_batch_call(&st, &items, raw.len(), None, None).await {
            Ok(v) => v,
            Err(_) => panic!("valid batch must dispatch"),
        };
        // 6 items minus 1 notification = 5 responses, in request order.
        assert_eq!(out.len(), 5);
        let body = serde_json::to_value(&out).unwrap();
        assert_eq!(body[0]["id"], 1);
        assert_eq!(body[0]["result"], "0x167d");
        assert_eq!(body[1]["id"], 2);
        assert_eq!(body[1]["result"], 777);
        assert_eq!(body[2]["id"], 3);
        assert_eq!(body[2]["error"]["code"], -32601);
        assert_eq!(body[3]["id"], 4);
        assert_eq!(body[3]["error"]["code"], -32602);
        // Malformed item: per-item `-32600` with a null id (spec: the id
        // could not be detected), siblings unaffected.
        assert_eq!(body[4]["id"], Value::Null);
        assert_eq!(body[4]["error"]["code"], -32600);
    }

    /// Batch ordering follows REQUEST order, not id order.
    #[tokio::test]
    async fn rpc_batch_preserves_request_order() {
        let st = test_state().await;
        let items = vec![
            json!({"jsonrpc": "2.0", "id": 30, "method": "stell_chainId", "params": []}),
            json!({"jsonrpc": "2.0", "id": 10, "method": "eth_chainId", "params": []}),
            json!({"jsonrpc": "2.0", "id": 20, "method": "stell_chainId", "params": []}),
        ];
        let raw = serde_json::to_string(&items).unwrap();
        let out = match handle_rpc_batch_call(&st, &items, raw.len(), None, None).await {
            Ok(v) => v,
            Err(_) => panic!("valid batch must dispatch"),
        };
        let ids: Vec<i64> = out
            .iter()
            .map(|r| serde_json::to_value(r).unwrap()["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, vec![30, 10, 20]);
    }

    /// Overall caps fail closed on the WHOLE batch (single `-32600` object,
    /// no partial answers): empty, too many items, too many bytes.
    #[tokio::test]
    async fn rpc_batch_caps_refuse_whole_batch() {
        let st = test_state().await;
        // Empty batch.
        let empty: Vec<Value> = vec![];
        let refused = match handle_rpc_batch_call(&st, &empty, 2, None, None).await {
            Err(e) => e,
            Ok(_) => panic!("empty batch must be refused"),
        };
        assert_eq!(serde_json::to_value(&refused).unwrap()["error"]["code"], -32600);
        // One item over the item cap.
        let big: Vec<Value> = (0..MAX_RPC_BATCH_ITEMS + 1)
            .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}))
            .collect();
        let raw = serde_json::to_string(&big).unwrap();
        let refused =
            match handle_rpc_batch_call(&st, &big, raw.len(), None, None).await {
                Err(e) => e,
                Ok(_) => panic!("over-cap batch must be refused whole"),
            };
        assert_eq!(serde_json::to_value(&refused).unwrap()["error"]["code"], -32600);
        // At exactly the cap it dispatches (responses may be rate-shaped but
        // the batch itself is accepted).
        let at_cap: Vec<Value> = (0..MAX_RPC_BATCH_ITEMS)
            .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}))
            .collect();
        let raw = serde_json::to_string(&at_cap).unwrap();
        assert!(raw.len() <= MAX_RPC_BATCH_BYTES);
        let out = match handle_rpc_batch_call(&st, &at_cap, raw.len(), None, None).await {
            Ok(v) => v,
            Err(_) => panic!("at-cap batch must dispatch"),
        };
        assert_eq!(out.len(), MAX_RPC_BATCH_ITEMS);
        // Byte cap: same items, lied-about body length over the bound.
        let refused = match handle_rpc_batch_call(
            &st,
            &at_cap,
            MAX_RPC_BATCH_BYTES + 1,
            None,
            None,
        )
        .await {
            Err(e) => e,
            Ok(_) => panic!("over-bytes batch must be refused whole"),
        };
        assert_eq!(serde_json::to_value(&refused).unwrap()["error"]["code"], -32600);
    }

    /// Auth is per-item and mirrors the single-call shape exactly: a gated
    /// arm without its token fails with `-32001` while its siblings succeed,
    /// and a per-item params token opens just that item.
    #[tokio::test]
    async fn rpc_batch_auth_is_per_item() {
        let st = test_state_authed().await;
        let items = vec![
            json!({"jsonrpc": "2.0", "id": 1, "method": "stell_mempoolDump", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "stell_chainId", "params": []}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "stell_mempoolDump", "params": {"token": "test-token"}}),
        ];
        let raw = serde_json::to_string(&items).unwrap();
        let out = match handle_rpc_batch_call(&st, &items, raw.len(), None, None).await {
            Ok(v) => v,
            Err(_) => panic!("valid batch must dispatch"),
        };
        assert_eq!(out.len(), 3);
        let body = serde_json::to_value(&out).unwrap();
        // No token -> same `-32001` as the single call, sibling unaffected.
        assert_eq!(body[0]["error"]["code"], -32001);
        assert_eq!(body[1]["result"], 777);
        // Per-item params token opens just that item.
        assert!(body[2]["error"].is_null());
        assert!(body[2]["result"].is_array());
    }

    /// Rate-limit audit: EVERY public method maps to at least one bucket —
    /// no unbucketed method. The list below is the full `dispatch` surface
    /// (EVM + stell arms, both invalidation aliases) plus the whole native
    /// namespace; if a method is added to `dispatch` without a bucket entry
    /// here, extend BOTH the table and this list.
    #[test]
    fn rate_bucket_table_covers_every_public_method() {
        const TRANSPORT_ONLY: &[&str] = &[
            // EVM adapter surface (all sit under the transport limiter only).
            "eth_chainId",
            "net_version",
            "web3_clientVersion",
            "net_listening",
            "net_peerCount",
            "eth_syncing",
            "eth_gasPrice",
            "eth_maxPriorityFeePerGas",
            "eth_estimateGas",
            "eth_feeHistory",
            "eth_getCode",
            "eth_getBalance",
            "eth_getTransactionCount",
            "eth_blockNumber",
            "eth_getBlockByNumber",
            "eth_getBlockByHash",
            "eth_getTransactionReceipt",
            "eth_getTransactionByHash",
            "eth_getBlockTransactionCountByHash",
            "eth_getBlockTransactionCountByNumber",
            "eth_getTransactionByBlockHashAndIndex",
            "eth_getTransactionByBlockNumberAndIndex",
            "eth_getUncleCountByBlockHash",
            "eth_getUncleCountByBlockNumber",
            "eth_getUncleByBlockHashAndIndex",
            "eth_getUncleByBlockNumberAndIndex",
            "eth_call",
            "eth_newBlockFilter",
            "eth_newPendingTransactionFilter",
            "eth_newFilter",
            "eth_getFilterChanges",
            "eth_getFilterLogs",
            "eth_uninstallFilter",
            "eth_getLogs",
            "eth_getStorageAt",
            "eth_sendRawTransaction",
            // stell reads/writes under the transport limiter only.
            "stell_chainId",
            "stell_nodeId",
            "stell_blockNumber",
            "stell_syncing",
            "stell_getStateRoot",
            "stell_latestBlocks",
            "stell_getShards",
            "stell_getShardTopology",
            "stell_getBlock",
            "stell_getBlockTransactions",
            "stell_epochKey",
            "stell_sendSealedTransaction",
            "stell_mevStats",
            "stell_getBalance",
            "stell_getHistoricalRoot",
            "stell_getFinalizedHeader",
            "stell_getFinalizedCheckpoint",
            "stell_getEpochRoot",
            "stell_bridgeDeposit",
            "stell_bridgeDispute",
            "stell_tokenBalance",
            "stell_tokenSupply",
            "stell_tokenResolve",
            "stell_listTokens",
            "stell_getTransactionReceipt",
            "stell_getEvents",
            "stell_getTransactionStatus",
            "stell_stakeOf",
            "stell_getValidatorStatus",
            "stell_zkmlCapabilities",
            "stell_getValidators",
            "stell_getPqKey",
            "stell_getPqRegistryStatus",
            "stell_proposal",
            "stell_listProposals",
            "stell_governanceParams",
            "stell_mempoolSize",
            "stell_baseFee",
            "stell_verifyMessage",
            "stell_verifyTypedData",
            "stell_sendRawTransaction",
            "stell_pmmState",
            "stell_orderBook",
            "stell_sessionBudget",
            "stell_getContractAbi",
            "stell_verifyContractSource",
            "stell_getContractSource",
            "stell_registerContractSource",
            "stell_getContractReceipt",
            "stell_getInvalidations",
            "stell_invalidationFeed",
            "stell_unsubscribe",
            "stell_getSubscriptions",
        ];
        const EXPENSIVE_HTTP_AND_WS: &[&str] = &["stell_estimateFee"];
        const EXPENSIVE_WS_EXTRA: &[&str] = &[
            "stell_getProof",
            "stell_getArchiveProof",
            "stell_getBalanceSpv",
            "stell_tokenBalanceSpv",
            "stell_runGetMethod",
        ];
        const SUBSCRIPTION_CAPPED: &[&str] = &["stell_subscribe"];
        const FAUCET_CAPPED: &[&str] = &["stell_faucet"];
        const AUTH_GATED: &[&str] = &[
            "stell_mempoolDump",
            "stell_submitProposal",
            "stell_vote",
            "stell_executeProposal",
            "stell_signMessage",
            "stell_signTypedData",
            "stell_deployContract",
            "stell_callContract",
            "stell_submitPriceFeed",
            "stell_pmmBuy",
            "stell_pmmSell",
        ];
        const NATIVE_NAMESPACE: &[&str] = &[
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
            "stell_nativeApi",
        ];
        // Every native method the dispatcher knows must be transport-bucketed.
        for m in crate::native_api::METHODS {
            assert!(
                NATIVE_NAMESPACE.contains(&m.name),
                "native method `{}` missing from the audit list",
                m.name
            );
            assert!(
                crate::native_api::is_native_method(m.name),
                "audit list entry `{}` is not a native method",
                m.name
            );
        }
        let mut all: Vec<&str> = Vec::new();
        all.extend_from_slice(TRANSPORT_ONLY);
        all.extend_from_slice(EXPENSIVE_HTTP_AND_WS);
        all.extend_from_slice(EXPENSIVE_WS_EXTRA);
        all.extend_from_slice(SUBSCRIPTION_CAPPED);
        all.extend_from_slice(FAUCET_CAPPED);
        all.extend_from_slice(AUTH_GATED);
        all.extend_from_slice(NATIVE_NAMESPACE);
        // No method listed twice under two categories (the bucket SETS may
        // overlap, but each method has exactly one audit row).
        let mut seen = std::collections::HashSet::new();
        for m in &all {
            assert!(seen.insert(*m), "method `{m}` listed in two audit rows");
        }
        // The table covers 140 public methods (143 minus the 3 removed
        // shielded methods); a dispatch arm added without updating the table
        // keeps this count stale on purpose — bump it.
        // GATE (Ristretto excision): shieldedTransfer/shieldedBalance/unshield gone.
        assert_eq!(all.len(), 140, "audit list size drifted: recount dispatch");
        for m in &all {
            let buckets = rpc_rate_buckets(m);
            assert!(
                !buckets.is_empty(),
                "public method `{m}` has no rate-limit bucket"
            );
            assert!(
                buckets.contains(&"transport"),
                "public method `{m}` must sit under the transport limiter"
            );
            for b in buckets {
                assert!(
                    ["transport", "expensive", "expensive-ws", "subscription", "faucet", "auth"]
                        .contains(b),
                    "method `{m}` names an unknown bucket `{b}`"
                );
            }
        }
        // Spot-check the special rows (the table is not just "transport").
        assert!(rpc_rate_buckets("stell_estimateFee").contains(&"expensive"));
        assert!(rpc_rate_buckets("stell_getProof").contains(&"expensive-ws"));
        assert!(!rpc_rate_buckets("stell_getProof").contains(&"expensive"));
        assert!(rpc_rate_buckets("stell_subscribe").contains(&"subscription"));
        assert!(rpc_rate_buckets("stell_faucet").contains(&"faucet"));
        assert!(rpc_rate_buckets("stell_mempoolDump").contains(&"auth"));
        assert!(!rpc_rate_buckets("stell_getBalance").contains(&"auth"));
        // Unknown methods map to nothing (the `-32601` arm has no bucket).
        assert!(rpc_rate_buckets("stell_nopeNotReal").is_empty());
        assert!(rpc_rate_buckets("").is_empty());
    }
}
