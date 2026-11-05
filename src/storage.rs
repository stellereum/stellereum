//! Persistent storage for blocks and state, backed by `sled` (embedded ACID KV).
//!
//! Design goals (Stage 4):
//!  - Consensus never blocks on disk. Finalized blocks and state snapshots are
//!    written through a background flusher; the hot path only enqueues.
//!  - Blocks are content-addressed by their hash, plus a height index for the
//!    canonical chain, so a node can rebuild its chain on restart.
//!  - State snapshots are stored per height; the latest is loaded on boot.
//!
//! Tree layout inside one sled DB:
//!   "blocks"      : block_hash (32B) -> bincode(Block)
//!   "by_height"   : height(8B BE) + block_hash(32B) -> block_hash
//!   "meta"        : "finalized_height"/"finalized_hash"/"canonical_tip" -> bytes
//!   "state"       : height(8B BE) -> bincode(snapshot)
//!   "domains"     : height(8B BE) -> bincode(DomainSnapshot)
//!   "headers"     : height(8B BE) -> bincode(BlockHeaderRecord)
//!   "session_keys": height(8B BE) -> bincode(SessionKeyRegistry)
//!   "bridge"      : height(8B BE) -> bincode(BridgeState)
//!   "zkml_models" : height(8B BE) -> bincode(ZkMlModelRegistry)  [audit F-B]
//!   "cross_shard" : height(8B BE) -> bincode(CrossShardReplaySnapshot) [audit F-I]
//!   "receipts_v1" : tx_hash (32B) -> bincode(StoredReceipt)   [NEW, additive only]
//!   "pq_keys"     : b"a:"+address (32B) -> bincode(scheme, pubkey, salt) / b"h:"+pk_hash (32B) -> pubkey
//!
//! The receipts tree is ADDITIVE: no existing tree's key/value format is
//! changed. Bodies stay content-addressed by hash; receipts are keyed by tx
//! hash and carry their (height, block_hash, index, success) so an adopter can
//! persist exactly what the proposer's single real application produced and an
//! RPC reader can serve `stell_getTransactionReceipt` on any node after adopt.
//!
//! Session keys and the bridge domain get their OWN trees rather than a field
//! on `DomainSnapshot` on purpose: `DomainSnapshot` is a bincode struct whose
//! restore path hard-errors, so appending a field would stop every pre-session-key
//! (and every pre-bridge) domain snapshot from decoding - a silent wipe of the
//! whole non-account state of every existing node. Keyed by height like
//! `state`/`domains` and captured in the same snapshot job, so the four stay
//! paired across restarts; an absent entry simply means "empty", which is what
//! both conditional digest domains hash as.

use crate::sharding::Block;
use crate::state_engine::InMemoryStateEngine;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub type BlockHash = [u8; 32];

/// Durable store for blocks, chain metadata and state snapshots.
#[derive(Clone)]
pub struct Storage {
    db: sled::Db,
    blocks: sled::Tree,
    by_height: sled::Tree,
    meta: sled::Tree,
    state: sled::Tree,
    /// Non-account consensus domains (tokens/contracts/orderbooks/PMM/staking/gov)
    /// keyed by height.
    domains: sled::Tree,
    /// Compact per-height header record, kept even when a block body is pruned.
    ///
    /// This is what makes pruning safe rather than merely destructive: the body
    /// is only needed to re-execute a block, while the chain can still be walked
    /// and re-derived from these records alone.
    headers: sled::Tree,
    /// Session-key registry snapshots (phase 2), keyed by height and written
    /// with the domain snapshot of the same height.
    session_keys: sled::Tree,
    /// Committed bridge domain (`BridgeState`: the source-tx replay set, the
    /// parked withdrawal queue, the rate-limit window and the escrow mirror),
    /// keyed by height and written with the domain snapshot of the same
    /// height. Its own tree for the same reason as `session_keys`: a field on
    /// `DomainSnapshot` would stop every older snapshot from decoding. This is
    /// what makes a restored node still refuse a replayed `source_tx_hash`.
    bridge: sled::Tree,
    /// Committed zkML model registry (models + VKs), keyed by height. Own
    /// tree for the same reason: a restart must not un-register models the
    /// chain agreed on, nor move the root.
    zkml_models: sled::Tree,
    /// Cross-shard replay state (audit F-I): engine consumed set + runtime
    /// produced/completed/consumed mirrors, keyed by height. Own tree: without
    /// it a restart wiped all four sets and a replayed message passed every
    /// check (target credited twice / bounce refunded twice). COMMITTED into
    /// the digest (`commitment::write_cross_shard_domain`, conditional on
    /// non-emptiness): restoring a different set than the anchor committed
    /// moves the root and is refused, so replay safety comes from the sets
    /// being BOTH consulted AND hashed.
    cross_shard: sled::Tree,
    /// Execution receipts, keyed by tx hash. NEW tree (additive only): existing
    /// trees are untouched, so pre-existing data directories open unchanged and
    /// simply report no receipts until heights are adopted/replicated.
    receipts: sled::Tree,
    /// Post-quantum public keys tree.
    pub pq_keys: sled::Tree,
}

/// FREEZE RULE (audit follow-up, chain-down incident): NEVER add fields to
/// this struct. A bincode struct cannot decode older bytes, so every added
/// field bricks restarts on pre-existing data directories (observed live:
/// `min_gas_limit` in governance-applied params made every snapshot
/// undecodable). New committed domains get their OWN tree + snapshot/restore
/// pair (the session/bridge/zkml pattern) — never a struct
/// extension. If this rule must ever break, ship a versioned upgrade wrapper
/// (the `BridgeStateV1`/`ConfidentialStateV1` pattern) in the SAME commit.
///
/// What survives pruning of a block body.
///
/// `block_hash` is the value `Block::compute_hash` produced, so a verifier can
/// check a retained record against a hash it was given without the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderRecord {
    pub height: u64,
    pub prev_hash: BlockHash,
    pub state_root: [u8; 32],
    pub proposer: [u8; 32],
    pub timestamp: u64,
    pub tx_count: u32,
    pub gas_used: u64,
    pub block_hash: BlockHash,
}

impl BlockHeaderRecord {
    pub fn of(b: &Block) -> Self {
        let gas_used: u64 = b.transactions.iter().map(|t| t.gas_limit).sum();
        Self {
            height: b.height,
            prev_hash: b.prev_hash,
            state_root: b.state_root,
            proposer: b.proposer,
            timestamp: b.timestamp,
            tx_count: b.transactions.len() as u32,
            gas_used,
            block_hash: b.compute_hash(),
        }
    }
}

/// One durably stored execution receipt.
///
/// Produced ONLY by the single real application of its block on this node
/// (never from the wire: success flags are not hash-committed, so a fetched
/// receipt cannot be verified and must not be trusted). Persisting them here is
/// what lets an adopter serve `stell_getTransactionReceipt` after a restart,
/// instead of answering from a cold in-memory index.
///
/// `fee_charged` is the nano-STELL the single real application actually
/// debited from the sender (what `commit_native` took: the declared
/// `gas_limit` on the block path, `min(gas_used, gas_limit)` on the
/// single-transaction path). It is 0 for a failed transaction: the commit is
/// atomic, so a refused transaction moved no native value at all, and showing
/// the declared limit there overstated what the wallet paid. `gas_limit` is
/// kept alongside so wallets can still reconcile limit-vs-charged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReceipt {
    pub tx_hash: BlockHash,
    pub height: u64,
    pub block_hash: BlockHash,
    pub index: u32,
    pub success: bool,
    pub gas_limit: u64,
    pub fee_charged: u64,
    #[serde(default)]
    pub events: Vec<crate::contract::ContractEvent>,
}

/// Pre-`events` receipt shape with `fee_charged` (7 fields). Receipts written
/// before events existed still decode with an empty event list.
#[derive(Serialize, Deserialize)]
struct LegacyStoredReceiptWithFee {
    tx_hash: BlockHash,
    height: u64,
    block_hash: BlockHash,
    index: u32,
    success: bool,
    gas_limit: u64,
    fee_charged: u64,
}

/// Pre-`fee_charged` receipt shape (6 fields). Receipts written before the
/// field existed still decode: a legacy success charged the declared limit on
/// the block path (the only path that filed receipts then), a legacy failure
/// charged nothing, so the migration maps exactly to the new semantics.
#[derive(Serialize, Deserialize)]
struct LegacyStoredReceipt {
    tx_hash: BlockHash,
    height: u64,
    block_hash: BlockHash,
    index: u32,
    success: bool,
    gas_limit: u64,
}

pub fn decode_receipt(bytes: &[u8]) -> Result<StoredReceipt> {
    if let Ok(r) = bincode::deserialize::<StoredReceipt>(bytes) {
        return Ok(r);
    }
    if let Ok(l) = bincode::deserialize::<LegacyStoredReceiptWithFee>(bytes) {
        return Ok(StoredReceipt {
            tx_hash: l.tx_hash,
            height: l.height,
            block_hash: l.block_hash,
            index: l.index,
            success: l.success,
            gas_limit: l.gas_limit,
            fee_charged: l.fee_charged,
            events: Vec::new(),
        });
    }
    let l: LegacyStoredReceipt = bincode::deserialize(bytes)?;
    Ok(StoredReceipt {
        tx_hash: l.tx_hash,
        height: l.height,
        block_hash: l.block_hash,
        index: l.index,
        success: l.success,
        gas_limit: l.gas_limit,
        fee_charged: if l.success { l.gas_limit } else { 0 },
        events: Vec::new(),
    })
}

/// Disk retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Keep every block body forever. The default, because it is the only mode
    /// that allows re-executing a historical block for an audit.
    pub archive: bool,
    /// In prune mode, how many recent blocks keep their full body.
    pub keep_blocks: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            archive: true,
            keep_blocks: 50_000,
        }
    }
}

impl RetentionConfig {
    /// Read the retention policy from the environment, with the same semantics
    /// the live node uses (`STELL_ARCHIVE`, `STELL_KEEP_BLOCKS`).
    ///
    /// `STELL_ARCHIVE=0/false` opts into pruning; anything else (including
    /// unset) is archive mode. `STELL_KEEP_BLOCKS=<n>` bounds the body window
    /// in prune mode (default 50 000).
    pub fn from_env() -> Self {
        let archive = std::env::var("STELL_ARCHIVE")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let keep_blocks = std::env::var("STELL_KEEP_BLOCKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50_000);
        Self {
            archive,
            keep_blocks,
        }
    }

    /// Whether this node retains the data needed to serve per-key archive
    /// proofs for every snapshot height it ever takes.
    ///
    /// Archive mode never calls `prune_blocks_below` / `prune_state_below` /
    /// `prune_domains_below` (see the finalize path in `main.rs`), so every
    /// persisted snapshot stays servable. Prune mode keeps only the recent
    /// window (see the retention rule in the archive-proofs section below)
    /// and must refuse older heights honestly.
    pub fn keeps_snapshots_forever(&self) -> bool {
        self.archive
    }
}

/// The provable "slots" of the state: which trie keys carry a per-key
/// archive proof, and which domains are only folded into the commitment
/// digest (see the slot model in the archive-proofs section below).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveSlot {
    /// A native account leaf, keyed by the 32-byte address.
    Account([u8; 32]),
    /// An STS token balance cell.
    TokenBalance {
        token_id: [u8; 32],
        account: [u8; 32],
    },
    /// An STS token total-supply cell.
    TokenSupply([u8; 32]),
    /// A contract's committed code hash.
    ContractCode([u8; 32]),
    /// A contract's committed ABI manifest (when one is attached).
    ContractAbi([u8; 32]),
    /// The single consensus-commitment digest leaf (proves the digest as a
    /// whole, never a single folded entry — see the slot model below).
    CommitmentDigest,
}

/// The state-trie key a slot is proven at.
pub fn archive_slot_key(slot: &ArchiveSlot) -> [u8; 32] {
    match *slot {
        ArchiveSlot::Account(addr) => addr,
        ArchiveSlot::TokenBalance { token_id, account } => {
            crate::state_engine::token_balance_key(&token_id, &account)
        }
        ArchiveSlot::TokenSupply(token_id) => crate::state_engine::token_supply_key(&token_id),
        ArchiveSlot::ContractCode(addr) => crate::state_engine::contract_key(&addr),
        ArchiveSlot::ContractAbi(addr) => crate::state_engine::contract_abi_key(&addr),
        ArchiveSlot::CommitmentDigest => crate::commitment::commitment_key(),
    }
}

/// An authenticated historical root: the post-`height` state root together
/// with the quorum certificate that commits to it.
///
/// The root is the `state_root` of the finalized block at `height + 1` (a
/// header commits to the state BEFORE its own block), and `cert` is that
/// block's precommit QC. A client verifies `cert` against its own validator
/// set before trusting `state_root` — without the QC the root is just a
/// number the server asserts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalRoot {
    /// Height whose post-state `state_root` is.
    pub height: u64,
    /// The historical state root.
    pub state_root: [u8; 32],
    /// The anchoring finalized block: `height + 1`.
    pub anchor_height: u64,
    /// Hash of the anchoring block (`cert` is bound to it).
    pub anchor_hash: [u8; 32],
    /// Hash of the anchoring block's parent (so the answer converts
    /// losslessly into a light-client checkpoint).
    pub anchor_prev_hash: [u8; 32],
    /// The precommit quorum certificate that decided the anchoring block.
    pub cert: crate::consensus::QuorumCertificate,
    /// Always true when served: the anchor is a finalized block.
    pub finalized: bool,
}

/// Maximum blocks removed by one prune job.
///
/// The flusher task is a single writer, so a prune that scanned a multi-gigabyte
/// tree inline would stall every other write behind it. Work is bounded per job
/// and the next prune is scheduled from the regular snapshot cadence instead.
const PRUNE_BATCH: usize = 20_000;

/// Default sled page-cache ceiling in bytes: 1 GiB, exactly the sled 0.34
/// default — made explicit and tunable rather than inherited silently. The
/// 1 GiB default is itself an OOM contributor on small (2–4 GB) nodes; lower
/// it there, raise it on big iron. Pure memory/perf knob, no format effect.
pub const DEFAULT_SLED_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

/// Effective page-cache ceiling: `STELL_SLED_CACHE_BYTES`, default 1 GiB.
pub fn sled_cache_capacity_bytes() -> u64 {
    crate::state_engine::memory_bounds::env_u64("STELL_SLED_CACHE_BYTES", DEFAULT_SLED_CACHE_BYTES)
}

/// Default background-flush cadence in ms: 500, exactly the sled 0.34 default.
pub const DEFAULT_SLED_FLUSH_MS: u64 = 500;

/// Effective flush cadence: `STELL_SLED_FLUSH_MS`, default 500. Only changes
/// how often sled flushes in the background (durability window vs write-amp),
/// never correctness.
pub fn sled_flush_every_ms() -> u64 {
    crate::state_engine::memory_bounds::env_u64("STELL_SLED_FLUSH_MS", DEFAULT_SLED_FLUSH_MS)
}

/// Whether sled zstd-compresses pages: `STELL_SLED_COMPRESSION=1/true/yes`,
/// default off (= sled default). Parsed and exposed for the migration design,
/// but NOT applied yet: this build compiles sled without its `compression`
/// cargo feature, so requesting it fails `open` with `Unsupported` (verified
/// by test). Phase 2 enables the cargo feature first, then wires this into
/// `sled_config_for`. Safe to parse now: no behavior effect either way.
pub fn sled_use_compression() -> bool {
    matches!(
        std::env::var("STELL_SLED_COMPRESSION")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Previous behavior was bare `sled::open(path)` (all sled defaults); with no
/// env overrides this returns exactly those defaults — no behavior change
/// unless the operator opts in via `STELL_SLED_CACHE_BYTES` /
/// `STELL_SLED_FLUSH_MS`. (`STELL_SLED_COMPRESSION` is parsed but
/// deliberately not applied: see [`sled_use_compression`].)
pub fn sled_config_for(path: &std::path::Path) -> sled::Config {
    sled::Config::new()
        .path(path)
        .cache_capacity(sled_cache_capacity_bytes())
        .flush_every_ms(Some(sled_flush_every_ms()))
}

impl Storage {
    /// Open (or create) the store at `path`.
    ///
    /// Runs the crash-recovery sweep before returning: any `by_height` index
    /// entry whose body is absent is removed (see
    /// [`Self::sweep_dangling_indexes`]). sled is ACID per key, not across
    /// the 2–3 inserts of [`Self::put_block`], so a crash can leave an index
    /// entry without its body; the sweep makes that debris unobservable at
    /// startup instead of on first read. Bodies without an index entry are
    /// harmless orphans (still servable by hash via [`Self::committed_body`])
    /// and are kept.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let db = sled_config_for(path).open()?;
        let blocks = db.open_tree("blocks")?;
        let by_height = db.open_tree("by_height")?;
        let meta = db.open_tree("meta")?;
        let state = db.open_tree("state")?;
        let domains = db.open_tree("domains")?;
        let headers = db.open_tree("headers")?;
        let session_keys = db.open_tree("session_keys")?;
        let bridge = db.open_tree("bridge")?;
        let zkml_models = db.open_tree("zkml_models")?;
        let cross_shard = db.open_tree("cross_shard")?;
        let receipts = db.open_tree("receipts_v1")?;
        let pq_keys = db.open_tree("pq_keys")?;
        let this = Self {
            db,
            blocks,
            by_height,
            meta,
            state,
            domains,
            headers,
            session_keys,
            bridge,
            zkml_models,
            cross_shard,
            receipts,
            pq_keys,
        };
        let swept = this.sweep_dangling_indexes().unwrap_or(0);
        if swept > 0 {
            eprintln!(
                "[storage] open: swept {swept} dangling by_height index entries (crash debris)"
            );
        }
        Ok(this)
    }

    /// Crash-recovery sweep: remove every `by_height` index entry whose block
    /// body is absent from `blocks`.
    ///
    /// Fail-closed direction: a dangling index entry makes
    /// [`Self::hashes_at_height`] report a hash no body backs, so
    /// [`Self::committed_body`] would answer an honest miss only after
    /// probing a hash lookup that also misses. Removing the entry at open
    /// restores the invariant "every indexed hash has a body" that
    /// [`Self::put_block`]'s data-before-index order establishes on the
    /// write path (body first, indexes after: a crash can only leave a body
    /// without an index, never an index without a body — except for a crash
    /// *inside* the prune path, which removes the index first; the sweep
    /// covers that window too). Bodies without index entries are NOT touched:
    /// they are still servable by hash and deleting user data at open would
    /// be the fail-open direction.
    ///
    /// Runs at startup ([`Self::open`]), never on the hot path: the scan is
    /// keys-only and removals are batched per entry (sled per-key ACID), so
    /// an interrupted sweep simply resumes next open.
    pub fn sweep_dangling_indexes(&self) -> Result<usize> {
        let mut dangling: Vec<sled::IVec> = Vec::new();
        for kv in self.by_height.iter() {
            let (k, v) = kv?;
            if k.len() != 40 || v.len() != 32 {
                continue;
            }
            if self.blocks.get(v.as_ref())?.is_none() {
                dangling.push(k);
            }
        }
        let n = dangling.len();
        for k in dangling {
            self.by_height.remove(k)?;
        }
        Ok(n)
    }

    // ---------- Blocks ----------

    /// Persist a block (idempotent).
    ///
    /// Data-before-index (audit F8): the body lands in `blocks` FIRST, then
    /// the header record, then the `by_height` index. sled is ACID per key,
    /// not across these three inserts, so a crash can interrupt the sequence —
    /// and every interruption state is safe by construction:
    /// * body only (no header/index): an orphan body, still servable by hash
    ///   via [`Self::committed_body`]'s hash-lookup fallback; the next
    ///   `put_block` of the same block re-inserts the missing index entries
    ///   (idempotent), and [`Self::sweep_dangling_indexes`] never deletes
    ///   bodies, so nothing is lost.
    /// * body + header (no index): same as above; headers are ALSO the prune-
    ///   surviving chain record, so a header without an index entry is the
    ///   normal pruned shape, not corruption.
    /// * all three: the steady state.
    ///   The one state this order NEVER produces is an index entry without a
    ///   body (that would make [`Self::hashes_at_height`] lie); a crash inside
    ///   the prune path (which removes the index first) can still produce it,
    ///   and the open-time sweep covers that window.
    pub fn put_block(&self, block: &Block) -> Result<BlockHash> {
        let hash = block.compute_hash();
        let bytes = bincode::serialize(block)?;
        self.blocks.insert(hash, bytes)?;
        // The header record is written for every block regardless of retention
        // mode, so switching a node from archive to pruning never loses the chain.
        self.put_header(&BlockHeaderRecord::of(block))?;
        let mut hk = Vec::with_capacity(40);
        hk.extend_from_slice(&block.height.to_be_bytes());
        hk.extend_from_slice(&hash);
        self.by_height.insert(hk, hash.as_slice())?;
        Ok(hash)
    }

    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        match self.blocks.get(hash)? {
            // The STORE tolerates the legacy body shape (a block persisted
            // before the trailing commitment fields existed). The WIRE does
            // NOT: there a truncated body must fail closed, not be
            // reinterpreted as a different block (audit W6.4b).
            Some(v) => Ok(Some(crate::sharding::with_legacy_block_tolerance(|| {
                bincode::deserialize::<Block>(&v)
            })?)),
            None => Ok(None),
        }
    }

    /// All block hashes at a given height (may be several across forks).
    pub fn hashes_at_height(&self, height: u64) -> Result<Vec<BlockHash>> {
        let prefix = height.to_be_bytes();
        let mut out = Vec::new();
        for kv in self.by_height.scan_prefix(prefix) {
            let (_, v) = kv?;
            if v.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&v);
                out.push(h);
            }
        }
        Ok(out)
    }

    // ---------- Chain metadata ----------

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.meta.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.meta.get(key.as_bytes())?.map(|v| v.to_vec()))
    }

    /// Finality pointer: `(height, hash)` of the last finalized block.
    ///
    /// Crash ordering (audit F8): sled is ACID per key, so the two legacy
    /// meta keys cannot be updated atomically — a crash between them leaves
    /// `finalized_height` without `finalized_hash` (or vice versa). Every
    /// such half-state reads as `None` (see [`Self::finalized`]), which is
    /// the SAFE direction: the node re-heals the tip from peers (slow) rather
    /// than believing a half-pointer (fork). To shrink the window to a single
    /// key, the pointer is ALSO written as one bincode blob under
    /// `"finalized_blob"` AFTER the two legacy keys: a crash can then only
    /// leave a STALE blob (older height) beside newer half-keys, and readers
    /// prefer the blob — reporting an older finalized height is the safe
    /// direction (re-walk forward), while reporting a newer half-pointer
    /// would be belief without both halves. Legacy keys are kept so
    /// pre-upgrade data dirs keep decoding; new writes always refresh all
    /// three, in legacy-first/blob-last order.
    pub fn set_finalized(&self, height: u64, hash: &BlockHash) -> Result<()> {
        let blob = bincode::serialize(&(height, *hash))?;
        let mut batch = sled::Batch::default();
        batch.insert(b"finalized_height".as_ref(), height.to_be_bytes().as_ref());
        batch.insert(b"finalized_hash".as_ref(), hash.as_ref());
        batch.insert(b"finalized_blob".as_ref(), blob.as_slice());
        self.meta.apply_batch(batch)?;
        Ok(())
    }

    pub fn finalized(&self) -> Result<Option<(u64, BlockHash)>> {
        // Prefer the single-key blob (one sled insert = one ACID unit): when
        // present it is always a complete pointer, never a half-write.
        if let Some(blob) = self.get_meta("finalized_blob")? {
            if let Ok((height, hash)) = bincode::deserialize::<(u64, BlockHash)>(&blob) {
                return Ok(Some((height, hash)));
            }
            // Corrupt blob (torn write is impossible for a single key, but a
            // bit-rotted value must not brick boot): fall through to the
            // legacy pair rather than erroring.
        }
        let h = self.get_meta("finalized_height")?;
        let hash = self.get_meta("finalized_hash")?;
        match (h, hash) {
            (Some(hb), Some(hash)) if hb.len() == 8 && hash.len() == 32 => {
                let mut height = [0u8; 8];
                height.copy_from_slice(&hb);
                let mut hh = [0u8; 32];
                hh.copy_from_slice(&hash);
                Ok(Some((u64::from_be_bytes(height), hh)))
            }
            _ => Ok(None),
        }
    }

    // ---------- Headers (survive body pruning) ----------

    pub fn put_header(&self, rec: &BlockHeaderRecord) -> Result<()> {
        self.headers
            .insert(rec.height.to_be_bytes(), bincode::serialize(rec)?)?;
        Ok(())
    }

    pub fn header_at(&self, height: u64) -> Result<Option<BlockHeaderRecord>> {
        match self.headers.get(height.to_be_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// The highest header retained, if any.
    pub fn latest_header(&self) -> Result<Option<BlockHeaderRecord>> {
        match self.headers.last()? {
            Some((_, v)) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    pub fn header_count(&self) -> Result<usize> {
        Ok(self.headers.len())
    }

    pub fn block_count(&self) -> Result<usize> {
        Ok(self.blocks.len())
    }

    /// Test-only handle to the raw block-body tree (differential tests
    /// replicate the pre-batch per-key prune loop against it). `sled::Tree`
    /// is a cheap cloneable handle, not a copy of the data.
    #[doc(hidden)]
    pub fn blocks_tree_for_test(&self) -> sled::Tree {
        self.blocks.clone()
    }

    /// Test-only handle to the raw height-index tree (see above).
    #[doc(hidden)]
    pub fn by_height_tree_for_test(&self) -> sled::Tree {
        self.by_height.clone()
    }

    /// Test-only handle to the raw receipts tree (see above).
    #[doc(hidden)]
    pub fn receipts_tree_for_test(&self) -> sled::Tree {
        self.receipts.clone()
    }

    // ---------- Verified body ingest (adopter replication) ----------
    //
    // Bodies/receipts are ALREADY committed by the proposer; replication must
    // not alter what is committed, only who holds it. The verification rule per
    // artifact:
    // * BODY: `block.compute_hash()` MUST equal the already-committed
    //   `expected_hash` (from the commit certificate / header record / height
    //   index). `compute_hash` commits to every tx hash, so equality proves
    //   byte-identical transactions to what the proposer committed. Mismatch =
    //   discard + Err (caller logs; no peer down-score infra exists).
    // * RECEIPT: NOT hash-committed (success flags live outside the block
    //   hash), so receipts are NEVER fetched-and-trusted. They are produced by
    //   the single real application (`apply_block_transition`, the
    //   block_apply_parity-tested path) on the adopter, and `put_receipts_*`
    //   below only persists that locally-produced outcome. No wire receipt is
    //   ever treated as authoritative.

    /// Persist `block` only if it hashes to `expected_hash`. A body filed under
    /// a hash it does not compute to is discarded (Err, nothing written).
    pub fn put_verified_block(
        &self,
        block: &Block,
        expected_hash: &BlockHash,
    ) -> Result<BlockHash> {
        let computed = block.compute_hash();
        if computed != *expected_hash {
            return Err(anyhow!(
                "replicated body rejected: hashes to {} but was committed as {}",
                hex::encode(computed),
                hex::encode(expected_hash)
            ));
        }
        self.put_block(block)
    }

    /// The locally committed body for `(height, expected_hash)`, if held.
    /// This is the FIRST step of the RPC/serve fallback order (local committed
    /// before any fetch): a present body whose hash matches is returned, anything
    /// else is `None` (honest miss, never fabricated).
    pub fn committed_body(&self, height: u64, expected_hash: &BlockHash) -> Result<Option<Block>> {
        // Prefer the height index (canonical chain), fall back to hash lookup.
        for hash in self.hashes_at_height(height)? {
            if hash == *expected_hash {
                if let Some(b) = self.get_block(&hash)? {
                    if b.compute_hash() == *expected_hash {
                        return Ok(Some(b));
                    }
                }
            }
        }
        // Non-canonical / pre-index body: accept only on hash match.
        if let Some(b) = self.get_block(expected_hash)? {
            if b.height == height && b.compute_hash() == *expected_hash {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }

    // ---------- Receipts (durable, adopter-persisted) ----------

    /// Persist one receipt (idempotent by tx hash).
    pub fn put_receipt(&self, r: &StoredReceipt) -> Result<()> {
        self.receipts.insert(r.tx_hash, bincode::serialize(r)?)?;
        Ok(())
    }

    /// Persist the receipt set for one applied block. `statuses` MUST come from
    /// the single real application of `txs` (never from re-execution or the
    /// wire); a short `statuses` marks missing entries as failed, exactly like
    /// the in-memory RPC index does. `fees` carries the nano-STELL each
    /// transaction was actually charged (parallel to `statuses`, in block
    /// order); a short `fees` falls back to `gas_limit`-on-success / 0-on-fail,
    /// which is exactly what the block path charged.
    ///
    /// Fallback audit (F11 nit): the `gas_limit`-on-success fallback matches
    /// the BLOCK path (`commit_native` charges the declared limit there) and
    /// deliberately NOT the single-transaction path (`min(gas_used,
    /// gas_limit)`). That is correct because receipts are filed ONLY for
    /// applied blocks (`enqueue_receipts` callers pass the block path's
    /// `tx_fees` verbatim — the live paths never rely on the fallback); the
    /// single-tx path never files receipts at all. The fallback therefore
    /// overstates nothing on any live path — it only decodes truncated legacy
    /// vectors — and changing it to the single-tx rule would UNDERSTATE what
    /// the block path actually debited. Pinned by test (short-`fees`
    /// block case asserts `gas_limit`-on-success).
    pub fn put_receipts_for_block(
        &self,
        height: u64,
        block_hash: &BlockHash,
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
    ) -> Result<usize> {
        self.put_receipts_for_block_with_events(height, block_hash, txs, statuses, fees, &[])
    }

    pub fn put_receipts_for_block_with_events(
        &self,
        height: u64,
        block_hash: &BlockHash,
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        events: &[Vec<crate::contract::ContractEvent>],
    ) -> Result<usize> {
        // Per-transaction inserts (deliberately NOT a sled::Batch): the
        // single-batch variant was measured 0.3x-0.9x (slower, never faster
        // across 9 release reps at N=428 — batch machinery exceeds 428 x
        // ~4us pagecache inserts) and reverted. No durability delta either
        // way: neither path flushes; the barrier is `flush()` (every 25
        // heights, shutdown, upgrade — untouched).
        let mut n = 0;
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let fee_charged =
                fees.get(i)
                    .copied()
                    .unwrap_or(if success { tx.gas_limit } else { 0 });
            let evts = events.get(i).cloned().unwrap_or_default();
            self.put_receipt(&StoredReceipt {
                tx_hash: tx.compute_tx_hash(),
                height,
                block_hash: *block_hash,
                index: i as u32,
                success,
                gas_limit: tx.gas_limit,
                fee_charged,
                events: evts,
            })?;
            n += 1;
        }
        Ok(n)
    }

    /// Receipt for one transaction hash, if durably stored.
    pub fn get_receipt(&self, tx_hash: &BlockHash) -> Result<Option<StoredReceipt>> {
        match self.receipts.get(tx_hash)? {
            Some(v) => Ok(Some(decode_receipt(&v)?)),
            None => Ok(None),
        }
    }

    /// Drop receipts below the retention window (audit 2026-10-06: the tree
    /// grew forever — one entry per tx, no prune path). Keyed by tx hash, so
    /// this scans values in batches; bounded by PRUNE_BATCH per call like the
    /// body prune. Wallet receipts older than the window read as "unknown"
    /// (same honest answer as an evicted in-memory receipt).
    pub fn prune_receipts_below(&self, keep_from: u64) -> Result<usize> {
        // Filter FIRST, take after (audit follow-up): iteration is tx-hash
        // order (random vs height), so take-first grabbed an arbitrary prefix
        // and could delete 0 forever while stale entries sat beyond it.
        // Scan in bounded chunks to avoid one giant pass on huge trees.
        let mut removed = 0;
        loop {
            let stale: Vec<sled::IVec> = self
                .receipts
                .iter()
                .filter_map(|kv| kv.ok())
                .filter_map(|(k, v)| {
                    let r: StoredReceipt = decode_receipt(&v).ok()?;
                    (r.height < keep_from).then_some(k)
                })
                .take(PRUNE_BATCH)
                .collect();
            if stale.is_empty() {
                break;
            }
            for k in stale {
                self.receipts.remove(k)?;
                removed += 1;
            }
            if removed >= PRUNE_BATCH * 4 {
                break; // one pass drains 80k; the rest next cadence
            }
        }
        Ok(removed)
    }

    pub fn receipt_count(&self) -> Result<usize> {
        Ok(self.receipts.len())
    }

    /// Bounded scan of stored receipts (tip hydration / tests). `limit` caps
    /// memory; iteration order is tx-hash order, so callers needing tip-ward
    /// priority must sort/filter by height themselves.
    pub fn all_receipts_capped(&self, limit: usize) -> Result<Vec<StoredReceipt>> {
        let mut out = Vec::new();
        for kv in self.receipts.iter().filter_map(|k| k.ok()) {
            if out.len() >= limit {
                break;
            }
            out.push(decode_receipt(&kv.1)?);
        }
        Ok(out)
    }

    // ---------- Retention ----------

    /// Whether a block body at `height` may be removed given a cursor.
    ///
    /// The boundary rule is the whole point: a block may go only if its child
    /// stays, otherwise the retained suffix no longer links back to genesis and
    /// the chain cannot be walked at all.
    ///
    /// `prune_blocks_below` and `has_blocks_below` share this so they cannot
    /// disagree. They did once: the predicate ignored the boundary, so a caller
    /// asking "is there more to do" was told yes forever by blocks that were
    /// deliberately being kept, and the prune loop never terminated.
    fn body_is_removable(height: u64, keep_from: u64) -> bool {
        height + 1 < keep_from
    }

    /// Delete block bodies below `keep_from`, keeping their header records.
    ///
    /// Returns how many bodies were removed. Bounded by `PRUNE_BATCH` per call
    /// because the flusher task is the only writer and an unbounded scan would
    /// stall every other write behind it.
    pub fn prune_blocks_below(&self, keep_from: u64) -> Result<usize> {
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .by_height
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .take(PRUNE_BATCH)
            .filter(|k| k.len() == 40)
            .filter(|k| {
                let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
                Self::body_is_removable(h, keep_from)
            })
            .collect();
        for hk in keys {
            if let Some(hash) = self.by_height.remove(&hk)? {
                self.blocks.remove(hash)?;
            }
            removed += 1;
        }
        Ok(removed)
    }

    /// True when another prune pass would remove something.
    pub fn has_blocks_below(&self, keep_from: u64) -> Result<bool> {
        for k in self.by_height.iter().keys().filter_map(|k| k.ok()) {
            if k.len() == 40 {
                let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
                if Self::body_is_removable(h, keep_from) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Total live entries across the block trees, for metrics and warnings.
    ///
    /// sled 0.34 does not expose a per-tree `size_on_disk`, so this counts keys
    /// rather than bytes. It answers "is the store growing without bound", which
    /// is the question a retention policy has to be able to answer.
    pub fn stored_block_entries(&self) -> usize {
        self.blocks.len() + self.by_height.len()
    }

    // ---------- Consensus checkpoint (safety across restarts) ----------

    /// Persist the consensus safety state (height, round, lock, finality).
    pub fn set_consensus(&self, cp: &ConsensusCheckpoint) -> Result<()> {
        let bytes = bincode::serialize(cp)?;
        self.set_meta("consensus", &bytes)
    }

    pub fn consensus(&self) -> Result<Option<ConsensusCheckpoint>> {
        match self.get_meta("consensus")? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None),
        }
    }

    // ---------- State snapshots ----------

    pub fn put_state(&self, height: u64, snapshot: &[u8]) -> Result<()> {
        self.state.insert(height.to_be_bytes(), snapshot)?;
        Ok(())
    }

    pub fn get_state(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.state.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    /// The most recent state snapshot (highest height) and its height.
    pub fn latest_state(&self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.state.last()? {
            Some((k, v)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some((u64::from_be_bytes(h), v.to_vec())))
            }
            _ => Ok(None),
        }
    }

    /// Drop state snapshots older than `keep_from` (retain the last few for reorgs).
    /// Never drops the latest snapshot (max height) to guarantee bootability across retentions.
    pub fn prune_state_below(&self, keep_from: u64) -> Result<usize> {
        let max_h = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && Some(h) != max_h
            })
            .collect();
        for k in keys {
            self.state.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Domain snapshots (tokens/contracts/orderbooks/PMM/staking/gov) ----------

    pub fn put_domains(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.domains.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The domain snapshot exactly as it stood after `height`, when one was stored.
    ///
    /// Strictly paired read: callers holding a paired height (see
    /// `latest_paired_snapshot`) must use this instead of `latest_domains`,
    /// so state@H is never combined with domains@D!=H from an unpaired tail
    /// left by a crash between the two snapshot jobs.
    pub fn domain_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.domains.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    /// Newest height holding BOTH a state and a domains snapshot.
    ///
    /// State and domain snapshots are enqueued as separate jobs, so a crash can leave
    /// an unpaired tail (state@H with no domains@H, or vice versa). Loading such a
    /// pair builds engine state no anchor can validate. Callers must use this, never
    /// `latest_state` alone, when they need a restorable snapshot.
    pub fn latest_paired_snapshot(&self) -> Result<Option<(u64, Vec<u8>)>> {
        let state_heights: std::collections::BTreeSet<u64> = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        let domain_heights: std::collections::BTreeSet<u64> = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        let Some(height) = state_heights.intersection(&domain_heights).copied().max() else {
            return Ok(None);
        };
        let Some(bytes) = self.state.get(height.to_be_bytes())? else {
            return Ok(None);
        };
        Ok(Some((height, bytes.to_vec())))
    }

    pub fn latest_domains(&self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.domains.last()? {
            Some((k, v)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some((u64::from_be_bytes(h), v.to_vec())))
            }
            _ => Ok(None),
        }
    }

    /// Drop domain snapshots older than `keep_from`.
    /// Never drops the latest snapshot (max height) to preserve bootability.
    pub fn prune_domains_below(&self, keep_from: u64) -> Result<usize> {
        let max_h = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && Some(h) != max_h
            })
            .collect();
        for k in keys {
            self.domains.remove(k)?;
            removed += 1;
        }
        self.prune_session_keys_below(keep_from)?;
        self.prune_bridge_below(keep_from)?;
        self.prune_zkml_models_below(keep_from)?;
        self.prune_cross_shard_below(keep_from)?;
        Ok(removed)
    }

    // ---------- Session-key registry snapshots (phase 2) ----------

    pub fn put_session_keys(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.session_keys.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The registry exactly as it stood after `height`, when one was stored.
    ///
    /// `None` for a data directory written before phase 2 - which is
    /// CORRECT, not a gap: an empty registry contributes nothing to the
    /// commitment digest, so a pre-phase-2 snapshot restores to the same root
    /// it was written with (that is what makes the genesis KAT survive).
    pub fn session_keys_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .session_keys
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    pub fn latest_session_keys(&self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.session_keys.last()? {
            Some((k, v)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some((u64::from_be_bytes(h), v.to_vec())))
            }
            _ => Ok(None),
        }
    }

    /// Heights whose auxiliary domain snapshots must survive any prune:
    /// every height holding a state or a domains snapshot. The loader only
    /// ever reads an aux blob at a height it also reads state+domains from
    /// (`load_full_state_into` at the paired height, `rebuild_historical_trie`
    /// at the proven height), so an aux row is live exactly when its height
    /// is snapshotted — and deleting the aux row of a retained snapshot
    /// height strands that height (the restored root no longer matches, or a
    /// committed replay set is silently dropped). State/domains preserve their
    /// own newest entry; the aux trees preserve every snapshotted height, and
    /// only prune rows no snapshot height needs.
    fn aux_retained_heights(&self) -> std::collections::BTreeSet<u64> {
        let mut keep = std::collections::BTreeSet::new();
        for tree in [&self.state, &self.domains] {
            for k in tree.iter().keys().filter_map(|k| k.ok()) {
                if k.len() == 8 {
                    keep.insert(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
                }
            }
        }
        keep
    }

    /// Drop session-key snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so the third tree follows the same window. Never
    /// drops a row at a snapshotted height (see [`Self::aux_retained_heights`]):
    /// state/domains preserve their newest entry so a node always stays
    /// bootable, and the aux trees must keep the rows those heights restore
    /// with — deleting the newest aux blob while state/domains keep theirs
    /// would strand the retained height behind a root mismatch.
    pub fn prune_session_keys_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .session_keys
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.session_keys.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Bridge domain snapshots (the §8 replay set / queue) ----------

    pub fn put_bridge(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.bridge.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The committed bridge domain exactly as it stood after `height`, when
    /// one was stored.
    ///
    /// `None` for a directory written before the bridge landed - which is
    /// CORRECT, not a gap: an empty domain contributes nothing to the
    /// commitment digest, so a pre-bridge snapshot restores to the same root it
    /// was written with (that is what keeps the genesis KAT alive). `Some`
    /// means the replay set and the withdrawal queue come back with the node,
    /// so a restored node still refuses a `source_tx_hash` it already credited
    /// instead of minting it a second time.
    pub fn bridge_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.bridge.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    /// Drop bridge snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_bridge_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .bridge
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.bridge.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- zkML model registry snapshots (audit F-B) ----------

    pub fn put_zkml_models(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.zkml_models.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The committed zkML model registry exactly as it stood after `height`.
    /// `None` for older directories means "empty" (zero digest bytes), which
    /// restores to the written root.
    pub fn zkml_models_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .zkml_models
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    /// Drop registry snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_zkml_models_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .zkml_models
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.zkml_models.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Cross-shard replay snapshots (audit F-I) ----------

    pub fn put_cross_shard(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.cross_shard.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The cross-shard replay state exactly as it stood after `height`.
    /// `None` for older directories (or single-shard chains that never used
    /// it) means "empty sets", which is also what a fresh process holds.
    ///
    /// COMMITTED domain (audit F1): the three replay sets are folded into
    /// the state digest by `commitment::write_cross_shard_domain`
    /// (conditional on non-emptiness, so pre-cross-shard snapshots root
    /// identically to before). A stored snapshot whose blob is absent
    /// therefore restores to a DIFFERENT root than an anchor that committed
    /// replay state — the root check refuses it loudly instead of silently
    /// re-opening consumed inbounds (see [`load_full_state_into`], which
    /// installs the FULL snapshot: engine + runtime consumed halves,
    /// produced heights and completed lifecycles).
    pub fn cross_shard_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .cross_shard
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    /// Drop replay snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height (see [`Self::aux_retained_heights`]):
    /// deleting the replay blob of a retained paired height would leave a
    /// bootable-looking snapshot whose restore roots differently (or silently
    /// re-opens consumed inbounds) — a self-inflicted refusal at best, a
    /// double-mint at worst.
    pub fn prune_cross_shard_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .cross_shard
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.cross_shard.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// The trusted state root a snapshot at `snapshot_height` must hash to.
    ///
    /// A block header commits to the state BEFORE the block applies it (the
    /// proposer reads the live root in `propose`, and `validate_proposal`,
    /// `adopt_committed` and the sync replay loop all check the header against
    /// the pre-apply root). A snapshot at height S is written AFTER block S is
    /// finalized and applied, so it holds the post-S state -- which is exactly
    /// the pre-state of block S+1. The expected root is therefore the
    /// `state_root` of the block at S+1, never of the block at S: comparing
    /// against S would reject every valid restore on a chain whose block S
    /// changed any state.
    ///
    /// The anchor comes from the already-persisted finalized chain data (the
    /// header record, which survives body pruning, falling back to a retained
    /// block body), NOT from the snapshot itself -- comparing the snapshot
    /// against anything derived from the snapshot would verify nothing.
    ///
    /// Returns `None` when no block at S+1 is persisted (a snapshot at the
    /// finalized tip with no successor yet, or a data directory from before
    /// headers were written): there is nothing independent to compare against.
    pub fn expected_restore_root(&self, snapshot_height: u64) -> Result<Option<[u8; 32]>> {
        let next = snapshot_height
            .checked_add(1)
            .ok_or_else(|| anyhow!("snapshot height overflows u64"))?;
        if let Some(rec) = self.header_at(next)? {
            return Ok(Some(rec.state_root));
        }
        for hash in self.hashes_at_height(next)? {
            if let Some(block) = self.get_block(&hash)? {
                return Ok(Some(block.state_root));
            }
        }
        Ok(None)
    }

    /// Compare a restored engine's root against the trusted root for
    /// `snapshot_height`. Missing anchor ==> `Ok(())` (nothing to compare, see
    /// `expected_restore_root`); a present-but-different anchor ==> `Err`
    /// naming both roots so the operator can see what diverged.
    pub async fn verify_restored_root(
        &self,
        engine: &InMemoryStateEngine,
        snapshot_height: u64,
    ) -> Result<()> {
        let Some(expected) = self.expected_restore_root(snapshot_height)? else {
            // No anchor (no header or body for snapshot_height+1). If we finalized
            // beyond the snapshot, loading it blind would resume consensus on state
            // nothing vouches for -- exactly the fork observed live. Refuse instead;
            // the operator repairs by wiping or by restoring a verified backup.
            // The only exception is tip state (snapshot == finalized head): there is
            // nothing newer to disagree with, so there is nothing to prove.
            let tip = self.finalized()?.map(|(h, _)| h).unwrap_or(snapshot_height);
            if snapshot_height < tip {
                return Err(anyhow!(
                    "no anchor to verify snapshot at height {snapshot_height} (finalized head is {tip}); \
                     refusing to resume on unprovable state -- wipe the data directory or restore a verified backup"
                ));
            }
            return Ok(());
        };
        let computed = engine.get_state_root().await;
        if computed != expected {
            // No height-0 exception: a genesis snapshot whose bytes hash
            // differently from what the finalized block at height 1 commits
            // to is corrupt, stale, or mislabeled, and accepting it installs
            // unverified genesis state under a chain that already disagrees.
            // The old path purged the height-0 trees and returned Ok, which
            // both destroyed evidence AND installed the same mismatched bytes
            // into the live engine (the caller holds them in hand) — a
            // fail-open bypass of this very check. Refuse loudly instead; the
            // operator wipes or restores a verified backup.
            return Err(anyhow!(
                "restore root mismatch at height {snapshot_height}: snapshot hashes to {} but the finalized block at {} commits to {} (truncated, corrupt or wrong-height snapshot rejected)",
                hex::encode(computed),
                snapshot_height + 1,
                hex::encode(expected),
            ));
        }
        Ok(())
    }

    // ---------- Per-key ARCHIVE proofs + state proofs by "slot" ----------
    //
    // WHAT THIS IS. The node has always been able to prove the CURRENT state
    // (`stell_getProof`: account + storage proofs against the live trie root).
    // What was missing (storage audit: "no per-key archive proofs, no SPV
    // proofs by slot"): proving what key K held at a HISTORICAL height H long
    // after the node pruned the live trie forward, and saying precisely WHICH
    // keys are provable at all.
    //
    // PROOF FORMAT. An archive proof is
    // `{ height, state_root, key, value_or_absence, proof_nodes }` where
    // `proof_nodes` is the canonical `cpat2::MerkleProof::to_nodes` hex-node
    // list (leaf first) and `value_or_absence` is the proven leaf value
    // (`None` for an exclusion proof). It verifies with
    // `cpat2::ArchiveProof::verify` against the HISTORICAL root — a root the
    // node no longer holds in memory. The root itself is authenticated by
    // `stell_getHistoricalRoot` (a quorum certificate on the anchoring block);
    // a proof against an untrusted root proves nothing, so the two RPCs are
    // one unit: the proof and its anchor.
    //
    // WHERE IT COMES FROM. The archive node rebuilds the historical trie from
    // its persisted snapshot history (the `state` / `domains` / aux trees),
    // NOT from the live trie: the live trie has moved on and must never be
    // rewound (rewinding it would fork a validating node). The rebuild runs
    // in a throwaway engine, the recomputed root is checked against the
    // finalized header that anchors it (fail closed on mismatch), and only
    // then is the proof generated. The live trie is untouched.
    //
    // SLOT MODEL. Provability is per trie key:
    //
    // * DIRECTLY PROVABLE (one trie leaf each, inclusion AND exclusion):
    //   - account leaf: `address` -> `balance_be || nonce_be[ || scheme ||
    //     pubkey_hash]` (16 or 49 bytes);
    //   - STS balance cell: `sha256("STS_BAL" || token_id || account)` ->
    //     `balance_be`;
    //   - STS supply cell: `sha256("STS_SUPPLY" || token_id)` ->
    //     `total_supply_be`;
    //   - contract code hash: `sha256("STELL_CONTRACT_CODE" || addr)` ->
    //     `code_hash`;
    //   - contract ABI manifest: `sha256("STELL_CONTRACT_ABI" || addr)` ->
    //     `abi_json` (when a manifest is attached);
    //   - consensus commitment leaf:
    //     `sha256("STELL_CONSENSUS_COMMITMENT_V1")` -> `digest` (proves the
    //     digest as a whole, not any field inside it).
    //   See `ArchiveSlot` for the key derivation of each slot.
    //
    // * DIGEST-FOLDED (NOT per-key provable): everything committed only
    //   through the consensus commitment digest — the staking ledger
    //   (validators, delegations, rewards, unbonding, ...), order books and
    //   every order's fields, order escrow, the PMM state, contract STORAGE
    //   slots, governance proposals and voters, the oracle feeds, the
    //   session-key registry, the bridge queue, the shielded ledger, the zkML
    //   registries and the cross-shard replay sets. For these the node can
    //   only prove the digest, never a single entry: the trie holds one leaf
    //   for all of them together. WHAT WOULD MAKE THEM PROVABLE: committing
    //   each entry under its own namespaced trie key (the way STS balances
    //   are committed under `STS_BAL` keys) instead of folding them into one
    //   digest — a consensus format change, deliberately NOT done here.
    //
    // RETENTION RULE (explicit and bounded). Snapshots are taken every
    // `STELL_SNAPSHOT_INTERVAL` heights (default 1000, minimum 50).
    //
    // * ARCHIVE mode (`STELL_ARCHIVE=1`, the default): the node never prunes
    //   block bodies, state snapshots, domain snapshots or aux-domain
    //   snapshots. It serves archive proofs and historical roots for EVERY
    //   snapshot height it ever took. The cost is explicit and unbounded:
    //   roughly one full state + domain snapshot per snapshot interval,
    //   forever. Operators who cannot pay it run prune mode.
    // * PRUNE mode (`STELL_ARCHIVE=0` + `STELL_KEEP_BLOCKS=<n>`, default
    //   50 000): the node keeps the last `keep_blocks` block bodies, all
    //   header records (they survive body pruning), the last three snapshot
    //   intervals of state/domain/aux snapshots, and the last 512
    //   quorum-certified headers in memory. It serves archive proofs ONLY
    //   for retained snapshot heights and historical roots ONLY while the
    //   anchoring body's quorum certificate is retained; anything older is
    //   refused with a `pruned` error — never fabricated, never an empty
    //   answer.
    //
    // The live trie is never rewound and pruning is never weakened: serving
    // archive proofs costs MORE retained data in archive mode, and an honest
    // refusal in prune mode.

    /// Every height holding BOTH a state and a domains snapshot (the heights
    /// an archive proof can be served for), oldest first.
    pub fn retained_archive_heights(&self) -> Result<Vec<u64>> {
        let state_heights: std::collections::BTreeSet<u64> = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        let domain_heights: std::collections::BTreeSet<u64> = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        Ok(state_heights
            .intersection(&domain_heights)
            .copied()
            .collect())
    }

    /// Bounded one-line summary of the archive coverage, for fail-closed
    /// error messages (never dumps the full height list: an archive node
    /// holds thousands).
    fn archive_coverage_summary(&self) -> String {
        match self.retained_archive_heights() {
            Ok(h) if h.is_empty() => "no snapshots retained".to_string(),
            Ok(h) => {
                let lo = h[0];
                let hi = h[h.len() - 1];
                format!("{} paired snapshot(s), heights {lo}..={hi}", h.len())
            }
            Err(_) => "snapshot index unreadable".to_string(),
        }
    }

    /// Nearest retained snapshot heights around `height` (below, above), for
    /// fail-closed error messages.
    fn nearest_retained_heights(&self, height: u64) -> (Option<u64>, Option<u64>) {
        let mut below = None;
        let mut above = None;
        if let Ok(h) = self.retained_archive_heights() {
            for v in h {
                if v < height {
                    below = Some(v);
                } else if v > height && above.is_none() {
                    above = Some(v);
                }
            }
        }
        (below, above)
    }

    /// Rebuild the historical state trie at `height` from the persisted
    /// snapshot history and return it with the state root it computes to.
    ///
    /// The rebuild runs in a throwaway engine (the live trie is never
    /// touched) and the recomputed root is checked against the finalized
    /// header anchoring it (`expected_restore_root`, i.e. the `state_root`
    /// of the block at `height + 1`). Fail closed at every step: a height
    /// above the tip, an unknown height, a pruned height, an unpaired
    /// snapshot or a root mismatch is an error, never an empty proof.
    ///
    /// `tip` is the node's current finalized height, used to tell "above the
    /// tip" (retry later) apart from "pruned" (never coming back).
    pub async fn rebuild_historical_trie(
        &self,
        height: u64,
        tip: u64,
    ) -> Result<(crate::cpat2::CompressedTrie, [u8; 32])> {
        if height > tip {
            return Err(anyhow!(
                "height {height} is above the tip ({tip}): refusing to prove the future"
            ));
        }
        let state_bytes = self.get_state(height)?.ok_or_else(|| {
            let (below, above) = self.nearest_retained_heights(height);
            let coverage = self.archive_coverage_summary();
            // Below the oldest retained snapshot the data is gone for good;
            // inside the retained span a missing snapshot means this height
            // was never snapshotted (snapshots are taken every
            // `STELL_SNAPSHOT_INTERVAL` heights, not every height).
            let reason = match below {
                None => format!("pruned or never snapshotted ({coverage})"),
                Some(lo) if height < lo => {
                    format!("pruned on this node (oldest retained snapshot is at {lo}; {coverage})")
                }
                _ => format!(
                    "no snapshot at this height (snapshots are taken every `STELL_SNAPSHOT_INTERVAL` heights; nearest retained: below={below:?}, above={above:?}; {coverage})"
                ),
            };
            anyhow!("no state snapshot at height {height}: {reason}")
        })?;
        let domains_bytes = self.domain_at(height)?.ok_or_else(|| {
            anyhow!(
                "state snapshot at height {height} has no paired domains snapshot (unpaired snapshot, possible crash between the snapshot jobs): refusing rather than proving from half a state"
            )
        })?;

        // Phase 1 (throwaway): restore + verify before proving anything, the
        // same shape as `load_full_state_into`.
        let tmp = InMemoryStateEngine::new();
        tmp.attach_pq_tree(self.pq_keys.clone());
        tmp.restore_snapshot_preserve_replay_sets(&state_bytes)
            .await
            .map_err(|e| anyhow!("restore state snapshot at height {height}: {e}"))?;
        let snap = decode_domain_snapshot(&domains_bytes)?;
        snap.apply(&tmp).await;
        if let Some(bytes) = self.session_keys_at(height)? {
            tmp.restore_session_keys(&bytes)
                .await
                .map_err(|e| anyhow!("restore session keys at height {height}: {e}"))?;
        }
        if let Some(bytes) = self.bridge_at(height)? {
            tmp.restore_bridge(&bytes)
                .await
                .map_err(|e| anyhow!("restore bridge domain at height {height}: {e}"))?;
        }
        // Ristretto deletion wave: confidential/shielded ledger removed with
        // crypto_privacy; no restore (transparent paths unchanged).
        if let Some(bytes) = self.zkml_models_at(height)? {
            tmp.restore_zkml_models(&bytes)
                .await
                .map_err(|e| anyhow!("restore zkML models at height {height}: {e}"))?;
        }
        if let Some(bytes) = self.cross_shard_at(height)? {
            let replay: crate::sharding::CrossShardReplaySnapshot =
                crate::sharding::with_legacy_block_tolerance(|| bincode::deserialize(&bytes))
                    .map_err(|e| anyhow!("restore cross-shard replay at height {height}: {e:?}"))?;
            tmp.restore_cross_shard_replay(&replay).await;
        }

        // Anchor the recomputed root: the header at height+1 commits to the
        // post-`height` state. At the tip (no successor yet) there is nothing
        // newer to disagree with, mirroring `verify_restored_root`.
        let computed = tmp.get_state_root().await;
        match self.expected_restore_root(height)? {
            Some(expected) if computed != expected => {
                return Err(anyhow!(
                    "snapshot at height {height} hashes to {} but the finalized block at {} commits to {} (truncated, corrupt or wrong-height snapshot): refusing to prove from it",
                    hex::encode(computed),
                    height + 1,
                    hex::encode(expected),
                ));
            }
            Some(_) => {}
            None => {
                let finalized_tip = self.finalized()?.map(|(h, _)| h).unwrap_or(tip);
                if height < finalized_tip {
                    return Err(anyhow!(
                        "no anchor to verify snapshot at height {height} (finalized head is {finalized_tip}): refusing to prove from unanchored state"
                    ));
                }
            }
        }
        let trie = tmp.state_trie.read().await.compressed().clone();
        Ok((trie, computed))
    }

    /// Serve a per-key archive proof for `key` at `height` from the persisted
    /// snapshot history.
    ///
    /// Inclusion when the key is in the historical trie, exclusion when it is
    /// provably absent. Fail closed: unknown, pruned and above-tip heights
    /// are errors (see `rebuild_historical_trie`), never empty answers.
    pub async fn serve_archive_proof(
        &self,
        height: u64,
        key: &[u8; 32],
        tip: u64,
    ) -> Result<crate::cpat2::ArchiveProof> {
        let (trie, root) = self.rebuild_historical_trie(height, tip).await?;
        if let Some(p) = trie.generate_proof(key) {
            crate::cpat2::ArchiveProof::inclusion(height, root, *key, &p).ok_or_else(|| {
                anyhow!("internal error: generated inclusion proof is not for the queried key")
            })
        } else if let Some(p) = trie.generate_exclusion_proof(key) {
            crate::cpat2::ArchiveProof::exclusion(height, root, *key, &p).ok_or_else(|| {
                anyhow!("internal error: generated exclusion proof is not for the queried key")
            })
        } else {
            // An empty historical trie has nothing to prove against. The
            // snapshot exists but holds no keys (genesis): absence is still
            // answered as an error rather than an unprovable empty proof,
            // because an empty proof is not evidence of absence.
            Err(anyhow!(
                "historical trie at height {height} is empty: no proof can be served for it"
            ))
        }
    }

    /// The authenticated historical root for `height`: the post-`height`
    /// state root together with the quorum certificate that commits to it.
    ///
    /// The root is the `state_root` of the finalized block at `height + 1`
    /// (a header commits to the state BEFORE its own block), and the proof
    /// is that block's precommit QC. Without the QC the root is just a
    /// number the server asserts — the client verifies the QC against its
    /// own validator set before trusting the root.
    ///
    /// Fail closed: a height above the tip, an unknown height, or a height
    /// whose anchoring body (and hence its QC) was pruned is an error.
    /// Header records alone do not authenticate: they carry no certificate.
    pub fn historical_root(&self, height: u64, tip: u64) -> Result<HistoricalRoot> {
        if height > tip {
            return Err(anyhow!(
                "height {height} is above the tip ({tip}): refusing to authenticate the future"
            ));
        }
        let anchor_height = height
            .checked_add(1)
            .ok_or_else(|| anyhow!("height {height} overflows: no successor can anchor it"))?;
        // The anchor: header record first (survives body pruning), falling
        // back to the block body. But only the BODY carries the quorum
        // certificate, so a header without its body authenticates nothing.
        let anchor_hash = if let Some(rec) = self.header_at(anchor_height)? {
            rec.block_hash
        } else {
            let hashes = self.hashes_at_height(anchor_height)?;
            let hash = hashes.into_iter().next().ok_or_else(|| {
                anyhow!(
                    "no record of height {anchor_height} (and hence no authenticated root for height {height}): unknown height on this node"
                )
            })?;
            hash
        };
        // The QC must come from a retained body. A pruned body leaves the
        // header record behind, and serving the root on the header's word
        // alone would be exactly the hole this closes.
        let mut cert = None;
        for hash in self.hashes_at_height(anchor_height)? {
            if hash != anchor_hash {
                continue;
            }
            if let Some(block) = self.get_block(&hash)? {
                if block.height != anchor_height {
                    continue;
                }
                if block.compute_hash() != anchor_hash {
                    continue;
                }
                cert = block.precommit_qc.clone();
                break;
            }
        }
        // Hash-index miss (pruned index entry): try the body by hash in case
        // the index is what is gone.
        if cert.is_none() {
            if let Some(block) = self.get_block(&anchor_hash)? {
                if block.height == anchor_height && block.compute_hash() == anchor_hash {
                    cert = block.precommit_qc.clone();
                }
            }
        }
        let cert = cert.ok_or_else(|| {
            anyhow!(
                "quorum certificate for the anchoring block at height {anchor_height} is not retained on this node (body pruned or never finalized with a certificate): refusing to authenticate the root for height {height}"
            )
        })?;
        // The root the anchor commits to. Taken from the header record when
        // present (it is the canonical chain record), else from the body.
        let (state_root, anchor_prev_hash) = if let Some(rec) = self.header_at(anchor_height)? {
            (rec.state_root, rec.prev_hash)
        } else if let Some(block) = self.get_block(&anchor_hash)? {
            (block.state_root, block.prev_hash)
        } else {
            return Err(anyhow!(
                "anchoring block at height {anchor_height} names a body this node no longer holds: refusing"
            ));
        };
        Ok(HistoricalRoot {
            height,
            state_root,
            anchor_height,
            anchor_hash,
            anchor_prev_hash,
            cert,
            finalized: true,
        })
    }

    // ---------- Validator-set freshness (stale-ledger guard, node C) ----------
    //
    // A restored node derives its validator set (proposer schedule, quorum)
    // from the staking ledger inside the domain snapshot. When the ledger
    // snapshot is far older than the state snapshot, the derived set is a
    // FOREIGN set: the node neither votes (its bond is missing) nor verifies
    // quorums against the right keys, and the block walk can never teach it
    // (the bond height is outside every walk/body window, and peer domain
    // snapshots are probed separately). Fail CLOSED: refuse the stale set
    // for quorum use and run as observer instead, LOUDLY.
    //
    // Ledger height = height of the domains snapshot the ledger was loaded
    // from; state height = height of the state snapshot. Both are storage
    // keys, never ledger content (the ledger carries no height).

    /// The newest height holding a domains (= ledger) snapshot, if any.
    pub fn latest_ledger_height(&self) -> Result<Option<u64>> {
        Ok(self.latest_domains()?.map(|(h, _)| h))
    }

    /// Gap between the newest state snapshot and the newest domains snapshot.
    ///
    /// `Ok(None)` when either side is missing (nothing to compare — the
    /// caller treats it as "no ledger yet", not as stale).
    pub fn ledger_state_gap(&self) -> Result<Option<(u64, u64)>> {
        let state_h = self.latest_state()?.map(|(h, _)| h);
        let ledger_h = self.latest_ledger_height()?;
        match (state_h, ledger_h) {
            (Some(s), Some(l)) => Ok(Some((s, l))),
            _ => Ok(None),
        }
    }

    // ---------- Post-quantum public keys (pq_keys) ----------
    //
    // Namespaced keys: `a:<address>` holds bincode(scheme, pubkey, salt),
    // `h:<pk_hash>` holds the raw pubkey. The two namespaces share one tree
    // but never collide: a 32-byte address can equal a 32-byte pk hash, and
    // without the prefix the second insert would overwrite the first.

    fn pq_addr_key(address: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(34);
        k.extend_from_slice(b"a:");
        k.extend_from_slice(address);
        k
    }

    fn pq_hash_key(pk_hash: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(34);
        k.extend_from_slice(b"h:");
        k.extend_from_slice(pk_hash);
        k
    }

    fn decode_pq_value(bytes: &[u8]) -> Option<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])> {
        if let Ok((scheme, pk, salt)) =
            bincode::deserialize::<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])>(bytes)
        {
            return Some((scheme, pk, salt));
        }
        if let Ok((scheme, pk)) =
            bincode::deserialize::<(crate::post_quantum::PqScheme, Vec<u8>)>(bytes)
        {
            return Some((scheme, pk, crate::post_quantum::DEFAULT_SALT));
        }
        if bytes.len() > 1 {
            if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(bytes[0]) {
                return Some((
                    scheme,
                    bytes[1..].to_vec(),
                    crate::post_quantum::DEFAULT_SALT,
                ));
            }
        }
        None
    }

    pub fn put_pq_key(
        &self,
        address: &[u8; 32],
        scheme: crate::post_quantum::PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
    ) -> Result<()> {
        let val = bincode::serialize(&(scheme, pubkey, *salt))?;
        self.pq_keys
            .insert(Self::pq_addr_key(address), val.as_slice())?;
        let pk_hash = *blake3::hash(pubkey).as_bytes();
        self.pq_keys.insert(Self::pq_hash_key(&pk_hash), pubkey)?;
        self.pq_keys.flush()?;
        Ok(())
    }

    pub fn get_pq_key(
        &self,
        address: &[u8; 32],
    ) -> Result<Option<(crate::post_quantum::PqScheme, Vec<u8>)>> {
        // Namespaced read first, legacy 32-byte fallback for pre-prefix data dirs.
        let key = Self::pq_addr_key(address);
        let bytes_opt = match self.pq_keys.get(&key)? {
            Some(v) => Some(v),
            None => self.pq_keys.get(address)?,
        };
        if let Some(bytes) = bytes_opt {
            if let Some((scheme, pk, _salt)) = Self::decode_pq_value(&bytes) {
                return Ok(Some((scheme, pk)));
            }
        }
        Ok(None)
    }

    pub fn pq_key_count(&self) -> usize {
        self.pq_keys.len()
    }

    /// Hydrate `GLOBAL_IMPLICIT_KEY_REGISTRY` by iterating all `(address, data)`
    /// pairs in `storage.pq_keys` and registering them into `sharding::global_implicit_key_registry()`.
    /// Guarantees that upon node reboot, all previously activated accounts are
    /// immediately available in memory for steady-state transaction verification.
    pub fn hydrate_implicit_pq_keys(&self) -> Result<usize> {
        let registry = crate::sharding::global_implicit_key_registry();
        let mut count = 0;
        for kv in self.pq_keys.iter() {
            let (k, v) = kv?;
            // Namespaced layout: `a:<addr>` carries the key record, `h:<hash>`
            // carries the raw pubkey for hash lookup and must be skipped here.
            // Legacy 32-byte keys (pre-prefix data dirs) are address records.
            let addr_bytes: Option<&[u8]> = if k.len() == 34 && k[0] == b'a' && k[1] == b':' {
                Some(&k[2..])
            } else if k.len() == 34 && k[0] == b'h' && k[1] == b':' {
                continue;
            } else if k.len() == 32 {
                Some(&k)
            } else {
                continue;
            };
            let addr_bytes = addr_bytes.expect("branch guarantees Some");
            let mut address = [0u8; 32];
            address.copy_from_slice(addr_bytes);

            let registered = if let Some((scheme, pk, salt)) = Self::decode_pq_value(&v) {
                registry.register(address, scheme, &pk, &salt).is_ok()
            } else {
                false
            };

            if registered {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Export all persistent `pq_keys` as (address, data) pairs for backup and migration flows.
    pub fn export_pq_keys(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        for kv in self.pq_keys.iter() {
            let (k, v) = kv?;
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }

    /// Snapshot-sync wire encoding of the `pq_keys` domain (audit F7): the
    /// bincode of [`Self::export_pq_keys`]'s pairs. Published beside the
    /// state snapshot under `kind == "pq_keys"` and installed by
    /// `InMemoryStateEngine::restore_pq_keys` on the sync path, so the fetch
    /// set (`sync::SYNC_DOMAIN_KINDS`) finally equals the install set. Absent
    /// blob (pre-publisher directory) installs as nothing — keys then heal
    /// via gossip re-pin + the accounts snapshot's pinned `pubkey_hash`
    /// (admission refuses PQ-gated txs until healed: availability, never a
    /// fork, and the root check already passed without this domain).
    pub fn export_pq_keys_blob(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&self.export_pq_keys()?)?)
    }

    /// Import `pq_keys` from backup data into persistent storage.
    pub fn import_pq_keys(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        for (k, v) in entries {
            self.pq_keys.insert(k.as_slice(), v.as_slice())?;
        }
        self.pq_keys.flush()?;
        Ok(())
    }

    /// Flush all trees to disk (durability barrier).
    ///
    /// Single `db.flush()`: every tree in this store (including `pq_keys`,
    /// opened via `db.open_tree`) shares the Db's pagecache, and sled 0.34
    /// `Tree::flush` flushes exactly that shared pagecache — so a separate
    /// `pq_keys.flush()` ahead of it re-flushed the same already-clean pages
    /// (a second fsync for zero new bytes). One barrier call keeps the
    /// identical durability guarantee (all prior writes on ALL trees are
    /// fsynced before return) with one fewer fsync per barrier. The barrier
    /// itself is never skipped or weakened: every-25-heights, shutdown and
    /// upgrade call sites are untouched.
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

/// Consensus safety checkpoint. Persisted so that a validator which restarted
/// mid-height does NOT prevote a conflicting value for a height it already
/// locked (Tendermint safety survives a crash).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct ConsensusCheckpoint {
    pub height: u64,
    pub round: u32,
    pub locked_hash: Option<[u8; 32]>,
    pub locked_round: u32,
    pub finalized_height: u64,
    pub finalized_hash: [u8; 32],
}

/// A full snapshot of every non-account consensus domain. Persisted alongside the
/// account snapshot so a node restores the COMPLETE state after a restart (A9):
/// previously tokens, contracts, orderbooks, the PMM, staking and governance were
/// lost on restart while only account balances survived.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct DomainSnapshot {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedger,
    pub governance: crate::governance::Governance,
    /// Committed oracle state. APPENDED to the end of the struct: the field is
    /// part of the state root, so a snapshot without it would restore to a
    /// different root and be rejected by `verify_restored_root` anyway - but
    /// bincode has no field names, so this also changes the on-disk format and
    /// old domain snapshots no longer decode (a wipe, which the
    /// `COMMITMENT_VERSION` 3 -> 4 bump already requires).
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshot {
    /// Capture the live domains from an engine + the runtime ledgers.
    pub async fn capture(
        engine: &InMemoryStateEngine,
        staking: &crate::staking::StakingLedger,
        governance: &crate::governance::Governance,
    ) -> Self {
        Self {
            tokens: engine.tokens_read().await.clone(),
            contracts: engine.contracts_read().await.clone(),
            orderbooks: engine.orderbooks_read().await.clone(),
            pmm: engine.pmm_read().await.clone(),
            pmm_usdt_token: *engine.pmm_usdt_token_read().await,
            pmm_treasury: *engine.pmm_treasury_read().await,
            order_escrow: engine.order_escrow_read().await.clone(),
            staking: staking.clone(),
            governance: governance.clone(),
            oracle: engine.oracle_read().await.clone(),
        }
    }

    /// Install the domains into the engine and return (staking, governance) for
    /// the caller to place into its shared locks.
    ///
    /// Staking and governance are ALSO installed into the engine itself: both
    /// are folded into the state-root commitment, so a restored engine whose
    /// staking/governance were left empty would compute a different root from
    /// the one the chain committed to, and root verification would false-reject
    /// every valid restore on a chain with any staking activity.
    pub async fn apply(
        self,
        engine: &InMemoryStateEngine,
    ) -> (crate::staking::StakingLedger, crate::governance::Governance) {
        *engine.tokens_write().await = self.tokens;
        *engine.contracts_write().await = self.contracts;
        *engine.orderbooks_write().await = self.orderbooks;
        *engine.pmm_write().await = self.pmm;
        *engine.pmm_usdt_token_write().await = self.pmm_usdt_token;
        *engine.pmm_treasury_write().await = self.pmm_treasury;
        *engine.order_escrow_write().await = self.order_escrow;
        *engine.staking_write().await = self.staking.clone();
        *engine.governance_write().await = self.governance.clone();
        *engine.oracle_write().await = self.oracle;
        // Re-commit token + contract entries to the state trie so SPV proofs for
        // balances and contract code keep working after a restore.
        engine.sync_aux_trie().await;
        (self.staking, self.governance)
    }
}

/// `DomainSnapshot` as written before the E2 rewards-pool fix / E7
/// governance locks changed `StakingLedger` (see
/// [`crate::staking::StakingLedgerV1`]). Kept ONLY for reading old snapshots:
/// every other domain is byte-identical, so the V1 shape differs solely in
/// the `staking` field. NEVER written; `upgrade` carries every domain across
/// and zeroes the new staking counters (see `StakingLedgerV1` for the
/// headroom caveat).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DomainSnapshotV1 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedgerV1,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV1 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-`equivocation_dedup`/`vesting_schedules` domain shape: identical to
/// [`DomainSnapshot`] except the staking ledger is [`crate::staking::StakingLedgerV2`]
/// (everything the live network persisted before the coordinated upgrade that
/// appended those two trailing ledger fields). Upgrades with both new sets
/// empty — exact, since neither registry existed when those bytes were
/// written (see `StakingLedgerV2`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV2 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedgerV2,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV2 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-lazy-accumulator domain shape: identical to [`DomainSnapshot`]
/// except the staking ledger is [`crate::staking::StakingLedgerV3`] (the
/// shape the live network persisted before the F1 lazy delegator-reward
/// accumulator appended its two trailing maps). Upgrades with both new maps
/// empty — EXACT: the eager implementation credited every delegator at
/// distribution time, so every reward a pre-upgrade ledger knows about is
/// already materialised and no accumulator state has to be reconstructed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV3 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedgerV3,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV3 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-jail/commission/lock ledger shape: identical to
/// [`crate::staking::StakingLedger`] except WITHOUT the three trailing maps
/// (`jail`, `commission_schedule`, `redelegation_lock`) appended after the
/// lazy delegator-reward accumulator.
///
/// This is what the live network persisted between the F1 lazy-accumulator
/// upgrade and the downtime-jail/commission/lock upgrade: bincode has no
/// field names, so those bytes do not decode as the current struct
/// (`UnexpectedEof` on the missing trailing maps) and must not be decoded as
/// [`DomainSnapshotV3`] either (a shorter ledger shape would read the two
/// accumulator maps as governance — refused loudly instead). NEVER written;
/// `upgrade` fills the three new maps EMPTY, which is EXACT: none of the
/// paths that create a jail record, a commission schedule or a redelegation
/// lock existed when those bytes were written.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV4 {
    pub validators: HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorStake>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    #[serde(default)]
    pub rewards_pool: u64,
    #[serde(default)]
    pub rewards_minted: u64,
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    #[serde(default)]
    pub min_validator_bond: Option<u64>,
    #[serde(default)]
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    #[serde(default)]
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    #[serde(default)]
    pub delegator_reward_checkpoints:
        HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
}

impl StakingLedgerV4 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self.validators,
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            // Exact: no jail, commission-schedule or redelegation-lock rows
            // can exist in pre-feature bytes (the paths that create them did
            // not exist), so empty is not a guess.
            jail: HashMap::new(),
            commission_schedule: HashMap::new(),
            redelegation_lock: HashMap::new(),
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: self.vesting_schedules,
            min_validator_bond: self.min_validator_bond,
        }
    }
}

/// Pre-jail/commission/lock domain shape: identical to [`DomainSnapshot`]
/// except the staking ledger is [`StakingLedgerV4`] (the shape the live
/// network persisted after the F1 lazy accumulator and before the
/// downtime-jail/commission/lock maps). Upgrades with the three new maps
/// empty — EXACT, since none of the paths that create them existed when
/// those bytes were written (see [`StakingLedgerV4`]).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV7 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV4,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV7 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy contract / governance shapes.
//
// The contract registry grew two trailing fields (a per-contract `balance` and
// an optional typed `abi` manifest) and the registry itself grew
// `last_return_data`; the governance applied-params grew `upgrade_plan`. All
// three are APPENDED, so the ON-DISK bytes of a chain written before them are
// a strict PREFIX of the current ones — but bincode has no field names and no
// "missing trailing field" rule, so the current types CANNOT read them: the
// decoder runs off the end of the appended field into the next struct and
// finally mis-reads a byte string as an enum discriminant ("invalid value:
// integer N, expected variant index 0 <= i < 2").
//
// `#[serde(default)]` does NOT help here: it is a JSON/self-describing-format
// feature, and bincode (a non-self-describing format) has no way to know a
// field is absent.
//
// The shadow types below reproduce the OLD layout byte-for-byte so a legacy
// domain snapshot decodes, and `upgrade` fills the appended fields with their
// exact pre-upgrade meaning:
//   * `Contract.balance` = 0  — the field did not exist, so no contract held
//     a balance in the old chain; the balance lives in the contract's storage
//     slots, which ARE carried across.
//   * `Contract.abi` = None   — no manifest was stored, so no manifest is
//     claimed. (The ABI is committed to the state trie next to the code hash
//     when present; an absent manifest contributes the same bytes as before.)
//   * `ContractRegistry.last_return_data` = empty — a transient per-call
//     value, never consensus state.
//   * `AppliedParams.upgrade_plan` = None — no coordinated upgrade plan was
//     ratified in the old chain.
//
// The commitments are unaffected by the upgrade of these four fields: none of
// them is hashed into the state root (the ABI manifest is, but only when it
// is present, and the old chain has none), so a legacy restore reproduces the
// SAME state root the old chain committed to.
// ---------------------------------------------------------------------------

/// Pre-ABI contract shape (7 fields, the layout before `balance` and `abi`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractLegacy {
    pub address: [u8; 32],
    pub creator: [u8; 32],
    pub code_hash: [u8; 32],
    pub code: Vec<u8>,
    pub storage: HashMap<i64, i64>,
    pub created_at: u64,
    pub paused: bool,
}

impl ContractLegacy {
    pub fn upgrade(self) -> crate::contract::Contract {
        crate::contract::Contract {
            address: self.address,
            creator: self.creator,
            code_hash: self.code_hash,
            code: self.code,
            storage: self.storage,
            created_at: self.created_at,
            paused: self.paused,
            balance: 0,
            abi: None,
            // No source was ever registered on the old chain: absent =
            // unverified, which contributes nothing to the state digest, so
            // the restored root is byte-identical to the legacy one.
            source_hash: None,
        }
    }
}

/// Pre-`last_return_data` contract registry (2 fields).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContractRegistryLegacy {
    pub contracts: HashMap<[u8; 32], ContractLegacy>,
    pub next_nonce: u64,
}

impl ContractRegistryLegacy {
    pub fn upgrade(self) -> crate::contract::ContractRegistry {
        crate::contract::ContractRegistry {
            contracts: self
                .contracts
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            next_nonce: self.next_nonce,
            last_return_data: Vec::new(),
        }
    }
}

/// Pre-`upgrade_plan` applied-params shape (7 fields).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppliedParamsLegacy {
    pub min_validator_bond: Option<u64>,
    pub equivocation_slash_bps: Option<u64>,
    pub default_commission_bps: Option<u64>,
    pub block_reward: Option<u64>,
    pub pmm_redemption_buffer_bps: Option<u64>,
    pub min_gas_limit: Option<u64>,
    pub signal: Option<String>,
}

impl AppliedParamsLegacy {
    pub fn upgrade(self) -> crate::governance::AppliedParams {
        crate::governance::AppliedParams {
            min_validator_bond: self.min_validator_bond,
            equivocation_slash_bps: self.equivocation_slash_bps,
            default_commission_bps: self.default_commission_bps,
            block_reward: self.block_reward,
            pmm_redemption_buffer_bps: self.pmm_redemption_buffer_bps,
            min_gas_limit: self.min_gas_limit,
            signal: self.signal,
            upgrade_plan: None,
        }
    }
}

/// Pre-`upgrade_plan` governance shape (the proposals map is unchanged: the
/// `GovAction` variants added since then were APPENDED, so the existing
/// discriminants — and therefore the persisted bytes — are identical).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceLegacy {
    pub proposals: HashMap<u64, crate::governance::Proposal>,
    pub next_id: u64,
    pub quorum_bps: u64,
    pub applied: AppliedParamsLegacy,
}

impl GovernanceLegacy {
    pub fn upgrade(self) -> crate::governance::Governance {
        crate::governance::Governance {
            proposals: self.proposals,
            next_id: self.next_id,
            quorum_bps: self.quorum_bps,
            applied: self.applied.upgrade(),
            // KI-23: legacy storage predates the timelock map — no maturities
            // (pre-timelock Passed executes immediately, one-time migration).
            timelocks: Default::default(),
            // Operator-signed governance: legacy storage predates signed
            // nonces — the set starts empty (exact: no signed nonce existed
            // when those bytes were written, so nothing can be replayed).
            gov_propose_nonces: Default::default(),
        }
    }
}

/// A domain snapshot whose CONTRACT REGISTRY and GOVERNANCE are in the legacy
/// layout, parameterised over the staking-ledger shape.
macro_rules! legacy_contract_domain_snapshot {
    ($name:ident, $staking:ty) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize)]
        pub struct $name {
            pub tokens: crate::token::TokenRegistry,
            pub contracts: ContractRegistryLegacy,
            pub orderbooks: crate::orderbook::OrderbookManager,
            pub pmm: crate::pmm::PrimaryMarketMaker,
            pub pmm_usdt_token: Option<[u8; 32]>,
            pub pmm_treasury: [u8; 32],
            pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
            pub staking: $staking,
            pub governance: GovernanceLegacy,
            pub oracle: crate::oracle::OracleState,
        }
        impl $name {
            pub fn upgrade(self) -> DomainSnapshot {
                DomainSnapshot {
                    tokens: self.tokens,
                    contracts: self.contracts.upgrade(),
                    orderbooks: self.orderbooks,
                    pmm: self.pmm,
                    pmm_usdt_token: self.pmm_usdt_token,
                    pmm_treasury: self.pmm_treasury,
                    order_escrow: self.order_escrow,
                    staking: self.staking.upgrade(),
                    governance: self.governance.upgrade(),
                    oracle: self.oracle,
                }
            }
        }
    };
}

legacy_contract_domain_snapshot!(DomainSnapshotV4, crate::staking::StakingLedgerV3);
legacy_contract_domain_snapshot!(DomainSnapshotV5, crate::staking::StakingLedgerV2);
legacy_contract_domain_snapshot!(DomainSnapshotV6, crate::staking::StakingLedgerV1);

/// Decode a persisted domain snapshot, accepting the pre-E2/E7 V1 shape.
///
/// Current bytes decode directly. Older bytes (a `StakingLedger` without the
/// rewards counters and governance locks) fail the direct decode with
/// `UnexpectedEof` and are retried as `DomainSnapshotV1`, whose staking
/// ledger upgrades with zeroed counters. LOUD on fallback — the same
/// contract as the bridge V1 upgrade (`restore_bridge`): a zeroed
/// `rewards_minted` overstates emission-cap headroom on a chain that minted
/// pre-upgrade, so operators must see this line and verify real minted
/// supply out-of-band (exact on fresh/test chains).
///
/// The LEGACY CONTRACT/GOVERNANCE shapes are tried BEFORE the current-shape
/// variants: a snapshot written before the contract ABI manifest and the
/// coordinated upgrade plan existed cannot be read by the current types at
/// all (bincode has no field names), so without this leg EVERY node of a
/// running cluster would refuse to start after the binary swap.
pub fn decode_domain_snapshot(bytes: &[u8]) -> Result<DomainSnapshot> {
    if let Ok(snap) = bincode::deserialize::<DomainSnapshot>(bytes) {
        return Ok(snap);
    }
    // LEGACY CONTRACTS + GOVERNANCE (the live-cluster shape): the contract
    // registry without the per-contract balance/ABI and without
    // `last_return_data`, and the applied params without `upgrade_plan`.
    if let Ok(v4) = bincode::deserialize::<DomainSnapshotV4>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state: contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v4.upgrade());
    }
    if let Ok(v5) = bincode::deserialize::<DomainSnapshotV5>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (older staking ledger): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v5.upgrade());
    }
    if let Ok(v6) = bincode::deserialize::<DomainSnapshotV6>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (oldest staking ledger): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v6.upgrade());
    }
    // V7: pre-jail/commission/lock ledger shape (current contracts, the
    // ledger with the lazy accumulator but without the three trailing maps).
    // Upgrades with the three new maps empty — EXACT: none of the paths that
    // create them existed when those bytes were written. Tried here, at the
    // head of the current-contract group (after the legacy-contract V4/V5/V6
    // legs, before V3): the grouping rule above (legacy contracts first)
    // decides the position, and closeness to the current shape decides the
    // order within the group. LOUD so operators see the migration.
    if let Ok(v7) = bincode::deserialize::<DomainSnapshotV7>(bytes) {
        tracing::warn!(
            "[domains] restored pre-jail/commission/lock V7 staking state: the jail records, the commission schedules and the redelegation locks start EMPTY (exact — none of the paths that create them existed when written)"
        );
        return Ok(v7.upgrade());
    }
    // V3: pre-lazy-accumulator ledger shape (what the live network persisted
    // before the F1 delegator-reward accumulator appended its two trailing
    // maps). Upgrades with both maps empty — EXACT: the eager implementation
    // materialised every delegator reward at distribution time, so nothing has
    // to be reconstructed. LOUD so operators see the migration.
    if let Ok(v3) = bincode::deserialize::<DomainSnapshotV3>(bytes) {
        tracing::warn!(
            "[domains] restored pre-lazy-accumulator V3 staking state: the reward accumulator and the delegator checkpoints start EMPTY (exact — the eager implementation materialised every delegator reward)"
        );
        return Ok(v3.upgrade());
    }
    // V2: pre-equivocation-dedup/vesting ledger shape (what the live network
    // persisted before the coordinated upgrade appending those two trailing
    // fields). Upgrades with both new sets empty — exact, neither registry
    // existed. LOUD so operators see the migration.
    if let Ok(v2) = bincode::deserialize::<DomainSnapshotV2>(bytes) {
        tracing::warn!(
            "[domains] restored pre-dedup/vesting V2 staking state: equivocation_dedup and vesting_schedules start EMPTY (exact — neither registry existed when written)"
        );
        return Ok(v2.upgrade());
    }
    // Fall through to the older format below.
    let v1: DomainSnapshotV1 =
        bincode::deserialize(bytes).map_err(|e| anyhow!("restore domains: {e}"))?;
    tracing::warn!(
        "[domains] restored pre-E2 V1 staking state: rewards counters start at ZERO — verify real minted supply out-of-band before trusting emission-cap headroom (exact on fresh/test chains)"
    );
    Ok(v1.upgrade())
}

/// Maximum bytes [`decode_domain_snapshot_strict`] accepts for one domain
/// blob (fail-closed anti-DoS on peer-supplied input: a snapshot is tens of
/// MB; 512 MiB is two orders of magnitude above any honest blob and bounds
/// the allocator before the first field decodes).
pub const DOMAIN_SNAPSHOT_STRICT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Strict trust-anchor parser for a persisted/fetched domain snapshot.
///
/// Accepts ONLY the current [`DomainSnapshot`] shape, with trailing bytes
/// rejected (same wire contract as `ConsensusMsg::decode`: fixint bincode,
/// exact-length). Any legacy shape (`DomainSnapshotV1`..`V7`, pre-ABI
/// governance, pre-lazy ledgers) or unknown/future version is a hard `Err`
/// naming the refusal — NO warn-and-upgrade fallback, NO silent skip.
///
/// Split from [`decode_domain_snapshot`] on purpose: the LOCAL restore path
/// keeps the lenient decoder so pre-upgrade data directories still boot
/// (pinned by `staking_ledger_migration_tests` and the `pre_e2`/`pre_lazy`
/// unit tests), while every path that treats a snapshot as a TRUST ANCHOR
/// (sync `install_bundle`, [`crate::sync::check_snapshot_set_binding`])
/// uses this strict parser, so a legacy blob can never become quorum state.
/// A legacy snapshot is re-published from a current binary, never upgraded
/// in place on the trust path.
pub fn decode_domain_snapshot_strict(bytes: &[u8]) -> Result<DomainSnapshot, String> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(DOMAIN_SNAPSHOT_STRICT_MAX_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| {
            format!(
                "refusing domain snapshot: not a current-shape DomainSnapshot \
                 (legacy or unknown version — no downgrade applied, refusing \
                 fail-closed; re-publish the snapshot from a current binary): {e}"
            )
        })
}

/// Validator set committed by the domain snapshot at `snapshot_height`.
///
/// Strict-decodes `domain_bytes` (see [`decode_domain_snapshot_strict`]) and
/// derives the consensus set from the enclosed staking ledger. This is the
/// F5 set-at-height commitment: a snapshot used as a trust anchor MUST carry
/// the set in force at its height, so the anchor proof (QCs verified under a
/// resolved set) and the adopted set (installed from this ledger) agree.
/// Returns the derived set (possibly empty — the caller decides whether an
/// empty commitment is usable; [`crate::sync::check_snapshot_set_binding`]
/// refuses it as a trust anchor).
pub fn snapshot_validator_set_strict(
    snapshot_height: u64,
    domain_bytes: &[u8],
) -> Result<crate::consensus::ValidatorSet, String> {
    let snap = decode_domain_snapshot_strict(domain_bytes).map_err(|e| {
        format!("snapshot at height {snapshot_height} commits to no usable validator set: {e}")
    })?;
    Ok(snap.staking.to_validator_set())
}

/// Default ceiling for how far the ledger (domains) snapshot may lag the
/// state snapshot before the derived validator set is refused as STALE.
///
/// The local snapshot ring keeps `height - 300` and newer (see the prune
/// window in `main.rs`: snapshots every 100 heights, three kept), so a lag
/// beyond one full ring means the ledger predates every locally retained
/// snapshot — exactly the node-C shape (bond outside every window).
pub const VALIDATOR_SET_FRESHNESS_DEFAULT_LAG: u64 = 300;

/// Effective ceiling for [`check_validator_set_freshness`].
///
/// Env `STELL_VALIDATOR_SET_MAX_LAG` (alias `STELL_LEDGER_FRESHNESS_MAX_LAG`),
/// default [`VALIDATOR_SET_FRESHNESS_DEFAULT_LAG`]. Unparseable/zero values
/// fall back to the default (zero would mark every paired restore stale).
pub fn validator_set_freshness_max_lag() -> u64 {
    for key in [
        "STELL_VALIDATOR_SET_MAX_LAG",
        "STELL_LEDGER_FRESHNESS_MAX_LAG",
    ] {
        if let Ok(raw) = std::env::var(key) {
            if let Ok(v) = raw.trim().parse::<u64>() {
                if v > 0 {
                    return v;
                }
            }
        }
    }
    VALIDATOR_SET_FRESHNESS_DEFAULT_LAG
}

/// Pure core of [`check_validator_set_freshness`] over an explicit ceiling.
/// `Ok(())` when fresh; `Err(reason)` naming both heights and the ceiling
/// when the ledger lags the state by more than `max_lag`, or when the ledger
/// claims to be AHEAD of the state (clock/label corruption — never trusted).
pub fn check_validator_set_freshness_with_lag(
    state_height: u64,
    ledger_height: u64,
    max_lag: u64,
) -> Result<(), String> {
    if ledger_height > state_height {
        return Err(format!(
            "STALE validator set: ledger height {ledger_height} is AHEAD of state height {state_height} (label corruption — refusing the set for quorum use)"
        ));
    }
    let lag = state_height.saturating_sub(ledger_height);
    if lag > max_lag {
        return Err(format!(
            "STALE validator set: ledger height {ledger_height} lags state height {state_height} by {lag} heights (max {max_lag}) — bond history outside every window, refusing the set for quorum use"
        ));
    }
    Ok(())
}

/// Freshness gate for a restored / snapshot-refreshed validator set.
///
/// Compares the ledger height (domains-snapshot height) against the state
/// height and, on staleness, logs a LOUD warn on BOTH channels
/// (`tracing::warn!` + `eprintln!`) before returning `Err`. Callers must
/// treat `Err` as fail-closed: do NOT install the stale set for quorum use,
/// run as observer instead. `Ok(())` means the set may be used.
pub fn check_validator_set_freshness(state_height: u64, ledger_height: u64) -> Result<(), String> {
    let max_lag = validator_set_freshness_max_lag();
    match check_validator_set_freshness_with_lag(state_height, ledger_height, max_lag) {
        Ok(()) => Ok(()),
        Err(reason) => {
            tracing::warn!("[validator-set] WARN {reason}");
            eprintln!("[validator-set] WARN {reason}");
            Err(reason)
        }
    }
}

/// Load the full node state (accounts + all domains). Returns the height and the
/// restored staking/governance ledgers, or None if nothing is stored.
///
/// The whole restore is first performed in a throwaway engine and its root is
/// verified against the finalized block at height+1 (see
/// `Storage::verify_restored_root`). Only on success is the live engine
/// touched. A mismatch therefore returns `Err` LOUDLY -- the corrupt state is
/// never installed -- while leaving both the live engine and the disk
/// untouched, so the operator can inspect, replace, or wipe the snapshot and
/// retry instead of being stranded on poisoned state (or on a wiped data
/// directory: nothing here deletes).
///
/// Verification is enforced when the domain snapshot is paired with the state
/// snapshot (same height) or when no domains are stored at all; a domain
/// snapshot from a different height is a partial write from a crash between
/// the two enqueues, and rejecting it would brick nodes for a pre-existing
/// crash-window quirk rather than for snapshot corruption.
pub async fn load_full_state_into(
    storage: &Storage,
    engine: &InMemoryStateEngine,
) -> Result<
    Option<(
        u64,
        crate::staking::StakingLedger,
        crate::governance::Governance,
    )>,
> {
    engine.attach_pq_tree(storage.pq_keys.clone());
    storage.hydrate_implicit_pq_keys()?;
    // Take the newest height at which BOTH a state and a domains snapshot exist.
    // A crash between the two writes (they are separate enqueued jobs) can leave an
    // unpaired tail; loading state@H with domains@D!=H builds a frankestate no anchor
    // can validate. Pairing is the precondition for everything below.
    let Some((height, state_bytes)) = storage.latest_paired_snapshot()? else {
        // Distinguish "nothing stored" (genuine fresh start) from "snapshots exist
        // but none are paired" (a crash between the two snapshot jobs, or corruption).
        // The latter must NOT silently start fresh: finalized metadata may claim a
        // head whose state we cannot reconstruct, and starting from genesis while
        // believing we resumed would fork. Refuse loudly instead.
        if storage.latest_state()?.is_some() || storage.latest_domains()?.is_some() {
            return Err(anyhow!(
                "snapshots exist but no height holds both a state and a domains snapshot                  (crashed mid-snapshot or corrupt); wipe the data directory or restore a                  verified backup -- refusing to resume on half a snapshot"
            ));
        }
        return Ok(None);
    };
    let domains_opt: Option<Vec<u8>> = storage.domain_at(height)?;

    // Phase 1 (throwaway): restore + verify without touching live state. The
    // verification is MANDATORY whenever an anchor exists: a snapshot labeled H whose
    // bytes decode to other state is exactly how a node starts on a fork while
    // believing it resumed (observed live: label 367, content of ~290).
    {
        let tmp = InMemoryStateEngine::new();
        tmp.attach_pq_tree(storage.pq_keys.clone());
        tmp.restore_snapshot_preserve_replay_sets(&state_bytes)
            .await
            .map_err(|e| anyhow!("restore state: {e}"))?;
        if let Some(bytes) = &domains_opt {
            let snap = decode_domain_snapshot(bytes)?;
            snap.apply(&tmp).await;
        }
        // Session-key registry of the SAME height, into the throwaway engine
        // too: it is part of the state root (conditional on being non-empty),
        // so verifying without it would reject every honest restore on a chain
        // that has ever registered a session key. Absent (pre-phase-2
        // directory) simply means "empty", which hashes to the same digest an
        // old node computed.
        if let Some(bytes) = storage.session_keys_at(height)? {
            tmp.restore_session_keys(&bytes)
                .await
                .map_err(|e| anyhow!("restore session keys: {e}"))?;
        }
        // Bridge domain of the SAME height, into the throwaway engine too: the
        // replay set and the withdrawal queue are part of the state root
        // (conditionally, on being non-empty), so verifying without it would
        // reject every honest restore on a chain that has ever bridged - and a
        // restore that quietly DROPPED it would re-root the chain while still
        // re-opening the source-tx replay. Absent (pre-bridge directory) simply
        // means "empty", which hashes to the digest an old node computed.
        if let Some(bytes) = storage.bridge_at(height)? {
            tmp.restore_bridge(&bytes)
                .await
                .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
        }
        // Ristretto deletion wave: confidential ledger removed; no restore.
        if let Some(bytes) = storage.zkml_models_at(height)? {
            tmp.restore_zkml_models(&bytes)
                .await
                .map_err(|e| anyhow!("restore zkML models: {e}"))?;
        }
        if let Some(bytes) = storage.cross_shard_at(height)? {
            // The STORE tolerates the legacy shape (a snapshot persisted
            // before the 2PC records existed).
            let snap: crate::sharding::CrossShardReplaySnapshot =
                crate::sharding::with_legacy_block_tolerance(|| bincode::deserialize(&bytes))
                    .map_err(|e| anyhow!("restore cross-shard replay: {e:?}"))?;
            // FULL replay install (audit F1): consumed halves + produced +
            // completed, extend-only. Restoring only `engine_consumed` here
            // used to drop the produced/completed halves on every restart:
            // the produced map gates timeout-bounce linkage and the completed
            // set gates ack/bounce completion, so a restarted node derived a
            // different root than its anchor (refused when an anchor exists)
            // or, at the tip with no anchor, silently re-opened lifecycles.
            tmp.restore_cross_shard_replay(&snap).await;
        }
        storage.verify_restored_root(&tmp, height).await?;
    }

    // Phase 2 (commit): the snapshot is genuine; install it into the live engine.
    engine
        .restore_snapshot_preserve_replay_sets(&state_bytes)
        .await
        .map_err(|e| anyhow!("restore state: {e}"))?;
    if let Some(bytes) = storage.session_keys_at(height)? {
        engine
            .restore_session_keys(&bytes)
            .await
            .map_err(|e| anyhow!("restore session keys: {e}"))?;
    }
    if let Some(bytes) = storage.bridge_at(height)? {
        engine
            .restore_bridge(&bytes)
            .await
            .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
    }
    // Ristretto deletion wave: confidential ledger removed; no restore.
    if let Some(bytes) = storage.zkml_models_at(height)? {
        engine
            .restore_zkml_models(&bytes)
            .await
            .map_err(|e| anyhow!("restore zkML models: {e}"))?;
    }
    if let Some(bytes) = storage.cross_shard_at(height)? {
        // The STORE tolerates the legacy shape (a snapshot persisted before
        // the 2PC records existed).
        let snap: crate::sharding::CrossShardReplaySnapshot =
            crate::sharding::with_legacy_block_tolerance(|| bincode::deserialize(&bytes))
                .map_err(|e| anyhow!("restore cross-shard replay: {e:?}"))?;
        // Same FULL install as the throwaway phase above: the two phases must
        // install byte-identical replay state, or the verified root would not
        // describe the live engine.
        engine.restore_cross_shard_replay(&snap).await;
    }
    match domains_opt {
        Some(bytes) => {
            let snap = decode_domain_snapshot(&bytes)?;
            let (staking, gov) = snap.apply(engine).await;
            Ok(Some((height, staking, gov)))
        }
        None => Ok(Some((
            height,
            crate::staking::StakingLedger::new(),
            crate::governance::Governance::new(),
        ))),
    }
}

/// A background flusher that decouples the consensus hot path from disk I/O.
///
/// Finalized blocks and periodic state snapshots are pushed into an unbounded
/// channel; a spawned task writes them. The hot path never waits on `sled`.
/// Max pending persist jobs. Bounds memory so a slow disk cannot grow the queue
/// without limit (anti-DoS).
pub const PERSIST_QUEUE_CAP: usize = 8192;

pub struct AsyncPersistence {
    tx: tokio::sync::mpsc::Sender<PersistJob>,
    storage: Arc<Storage>,
    /// Jobs pushed but not yet dequeued by the background writer. Drives the
    /// `stell_persist_queue_depth` gauge (F2: previously declared but unwired
    /// — the queue existed, the producer did not). Atomic: `push` (hot path)
    /// and the writer task update it without locking.
    queue_depth: Arc<std::sync::atomic::AtomicU64>,
}

/// Persist work items. `pub` so the drop-policy classifier
/// ([`persist_push_policy`]) can name the type it matches on; constructed
/// only inside this module.
#[allow(clippy::large_enum_variant)]
// GATE: Block variant dominates by design; jobs are short-lived queue items, boxing would add alloc overhead.
pub enum PersistJob {
    Block(Block),
    State {
        height: u64,
        snapshot: Vec<u8>,
    },
    /// Domain + session-key + bridge snapshots of the SAME height, carried in
    /// one job so they are enqueued (and therefore ordered/dropped) together:
    /// two jobs could be split by a full queue or a crash, leaving a registry
    /// from a different height than the domains it must restore alongside - or
    /// a bridge replay set paired with accounts that already credited it.
    Domains {
        height: u64,
        bytes: Vec<u8>,
        session_keys: Vec<u8>,
        bridge: Vec<u8>,
        zkml_models: Vec<u8>,
        cross_shard: Vec<u8>,
    },
    Consensus(Box<ConsensusCheckpoint>),
    Finalized {
        height: u64,
        hash: BlockHash,
    },
    Prune {
        keep_from: u64,
    },
    /// Durable receipts for one applied block. Carries the tx hashes + statuses
    /// from the single real application (never wire data); the worker persists
    /// them alongside the body so an adopter serves receipts after a restart.
    /// One job per height, bounded by the block's own tx count.
    Receipts {
        height: u64,
        hash: BlockHash,
        txs: Vec<crate::sharding::Transaction>,
        statuses: Vec<bool>,
        fees: Vec<u64>,
        events: Vec<Vec<crate::contract::ContractEvent>>,
    },
    Flush,
}

/// How [`AsyncPersistence::push`] treats a job when the bounded queue is full
/// (audit F2 drop-policy by job class).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistPushPolicy {
    /// Drop immediately (logged + counted): re-runnable work whose loss is
    /// a no-op — the prune pass is re-scheduled from the regular snapshot
    /// cadence.
    DropFirst,
    /// Wait (bounded) for the writer to drain before dropping: every job
    /// class carrying consensus-relevant data (see `push`'s loss assessment).
    BoundedWait,
}

/// Pure classifier for the push drop-policy: which job classes may be
/// dropped outright when the persist queue is full, and which must wait out
/// a bounded drain first. Pure so the policy is test-pinned without timing.
pub fn persist_push_policy(job: &PersistJob) -> PersistPushPolicy {
    match job {
        PersistJob::Prune { .. } => PersistPushPolicy::DropFirst,
        _ => PersistPushPolicy::BoundedWait,
    }
}

/// Total time a `BoundedWait` push waits for queue space before dropping
/// (audit F2 bounded-blocking): 200ms. Long enough for the writer to drain
/// several sled batches on a slow disk, short enough that a wedged disk
/// costs the tick a bounded delay, never a hang.
pub const PERSIST_BLOCKING_WAIT_MS: u64 = 200;

/// Pace between queue-space retries inside the bounded wait: 5ms (up to ~40
/// retries per wait). Yields the thread instead of spinning.
pub const PERSIST_RETRY_PACE_MS: u64 = 5;

impl AsyncPersistence {
    /// Start the background writer. Returns a handle for enqueuing jobs and the
    /// shared storage for reads.
    pub fn start(storage: Arc<Storage>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PersistJob>(PERSIST_QUEUE_CAP);
        let st = storage.clone();
        let depth = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let depth_worker = depth.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                // Dequeued: one fewer job waiting, even before the write
                // lands. `saturating` — a missed count must never wrap the
                // gauge to u64::MAX.
                let now_depth = depth_worker
                    .fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |d| Some(d.saturating_sub(1)),
                    )
                    .unwrap_or(0)
                    .saturating_sub(1);
                crate::metrics::global().set_persist_queue_depth(now_depth);
                let res = match job {
                    PersistJob::Block(b) => st.put_block(&b).map(|_| ()),
                    PersistJob::State { height, snapshot } => st.put_state(height, &snapshot),
                    // Audit F1(c): `cross_shard` is written FIRST. The old
                    // order wrote it LAST (domains→session→bridge→
                    // zkml→cross_shard), so an I/O error anywhere
                    // in the chain silently skipped the replay set while
                    // keeping the rest — the exact partial write that
                    // re-opens consumed inbounds. Replay-first inverts the
                    // failure shape: a later error now leaves replay state
                    // WITHOUT its domains, which the paired-snapshot loader
                    // REFUSES loudly (unpaired/half snapshot) instead of
                    // installing a double-mint. Replay data without domains
                    // is fail-closed; domains without replay data was the
                    // corruption.
                    PersistJob::Domains {
                        height,
                        bytes,
                        session_keys,
                        bridge,
                        zkml_models,
                        cross_shard,
                    } => st
                        .put_cross_shard(height, &cross_shard)
                        .and_then(|()| st.put_domains(height, &bytes))
                        .and_then(|()| st.put_session_keys(height, &session_keys))
                        .and_then(|()| st.put_bridge(height, &bridge))
                        .and_then(|()| st.put_zkml_models(height, &zkml_models)),
                    PersistJob::Consensus(cp) => st.set_consensus(&cp),
                    PersistJob::Finalized { height, hash } => st.set_finalized(height, &hash),
                    PersistJob::Receipts {
                        height,
                        hash,
                        txs,
                        statuses,
                        fees,
                        events,
                    } => st
                        .put_receipts_for_block_with_events(
                            height, &hash, &txs, &statuses, &fees, &events,
                        )
                        .map(|_| ()),
                    // Bounded per job: the flusher is the only writer, so an
                    // unbounded scan here would stall every other write.
                    // Receipts ride the same retention window (audit 2026-10-06).
                    PersistJob::Prune { keep_from } => st
                        .prune_blocks_below(keep_from)
                        .and_then(|_| st.prune_receipts_below(keep_from))
                        .map(|_| ()),
                    PersistJob::Flush => st.flush(),
                };
                if let Err(e) = res {
                    eprintln!("[storage] persist error: {e}");
                }
            }
        });
        Self {
            tx,
            storage,
            queue_depth: depth,
        }
    }

    pub fn storage(&self) -> Arc<Storage> {
        self.storage.clone()
    }

    /// Non-blocking enqueue. Never grows memory without bound: if the bounded
    /// queue is full the job is either waited out (bounded) or dropped
    /// (logged AND counted) according to its class — see
    /// [`persist_push_policy`]. F2: the drop path increments
    /// `stell_persist_queue_dropped_total` and every push/dequeue refreshes
    /// the `stell_persist_queue_depth` gauge, so the declared metrics finally
    /// have a producer.
    ///
    /// What a drop LOSES, per class (assessed audit F2):
    /// * `Prune`: nothing durable — the next snapshot cadence re-schedules
    ///   it. Always droppable, dropped first.
    /// * `State` / `Domains`: one periodic snapshot (every ~100 heights).
    ///   The next cadence re-captures a NEWER height, so a drop only widens
    ///   the crash-recovery gap by one interval; the paired-snapshot loader
    ///   refuses half-pairs loudly rather than installing them.
    /// * `Block`: one finalized body. Healable via adopter replication
    ///   (`put_verified_block` re-fetches by hash), but a missing body is
    ///   serving-visible until healed — hence bounded-wait, not drop-first.
    /// * `Finalized`: the tip pointer. Loss forces a full re-walk at next
    ///   boot (safe but slow) — hence bounded-wait, not drop-first.
    /// * `Receipts` / `Consensus`: per-height durable indexes / safety
    ///   checkpoint. Re-derivable (receipts by re-application, consensus by
    ///   re-locking) but safety-relevant — hence bounded-wait.
    /// * `Flush`: a durability barrier with no data — dropping it only
    ///   widens the fsync window; still bounded-waited (cheap) for uniformity.
    fn push(&self, job: PersistJob) {
        let droppable = persist_push_policy(&job) == PersistPushPolicy::DropFirst;
        match self.tx.try_send(job) {
            Ok(()) => {
                let d = self
                    .queue_depth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(1);
                crate::metrics::global().set_persist_queue_depth(d);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(job)) => {
                if droppable {
                    eprintln!("[storage] persist queue full; dropping a prune job (re-scheduled next cadence)");
                    crate::metrics::global().inc_persist_queue_dropped();
                    return;
                }
                // Bounded blocking for consensus-relevant jobs (audit F2):
                // wait up to `PERSIST_BLOCKING_WAIT_MS` for the writer to
                // drain, then drop loudly with a metric. The wait is BOUNDED
                // (never indefinite), so a wedged disk delays the tick by at
                // most this budget instead of growing memory without limit.
                //
                // NO-DEADLOCK PROOF: the only waiter here is the producer
                // (consensus tick / RPC), and the only drain is the background
                // writer task, which performs PURE sled I/O (`put_*`,
                // `prune_*`, `flush`) and never sends on this channel, never
                // awaits a consensus lock, and never awaits the producer.
                // The wait-for graph is therefore producer → writer → disk,
                // with no edge back to the producer: no cycle, no deadlock.
                // Worst case is a bounded tick delay followed by a counted
                // drop (whose loss class is documented above), never a hang
                // and never silent loss.
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_millis(PERSIST_BLOCKING_WAIT_MS);
                let mut job = Some(job);
                let mut retry_fn = || {
                    while std::time::Instant::now() < deadline {
                        std::thread::sleep(std::time::Duration::from_millis(PERSIST_RETRY_PACE_MS));
                        match self
                            .tx
                            .try_send(job.take().expect("job held across retries"))
                        {
                            Ok(()) => {
                                let d = self
                                    .queue_depth
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                    .saturating_add(1);
                                crate::metrics::global().set_persist_queue_depth(d);
                                return true;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(j)) => {
                                job = Some(j);
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return true,
                        }
                    }
                    false
                };

                // `block_in_place` is what lets the WRITER task drain the
                // queue while this thread waits - but it PANICS on a
                // current-thread runtime ("can call blocking only when
                // running on the multi-threaded runtime"), and a panic in the
                // persistence path is a node-killer, not a hiccup. So the
                // runtime FLAVOUR decides:
                //
                //   * MultiThread: `block_in_place` hands the thread to the
                //     scheduler, the writer drains in parallel, and the
                //     bounded wait can actually succeed.
                //   * CurrentThread: the writer runs ONLY when the producer
                //     awaits, and this is a SYNCHRONOUS push - so the writer
                //     cannot drain while we wait. The bounded wait could
                //     never succeed: skip it and drop now (loudly, counted)
                //     instead of burning the whole budget on a guaranteed
                //     timeout.
                //   * No runtime at all: nothing can drain either; keep the
                //     historical bounded wait.
                let flavor = tokio::runtime::Handle::try_current()
                    .ok()
                    .map(|h| h.runtime_flavor());
                let ok = match flavor {
                    Some(tokio::runtime::RuntimeFlavor::MultiThread) => {
                        tokio::task::block_in_place(retry_fn)
                    }
                    Some(tokio::runtime::RuntimeFlavor::CurrentThread) => {
                        eprintln!(
                            "[storage] persist queue full on a current-thread runtime: \
                             the writer cannot drain while this thread holds it - \
                             dropping the job now (counted)"
                        );
                        false
                    }
                    // `RuntimeFlavor` is `#[non_exhaustive]`: a future tokio
                    // could add a flavour whose drain semantics we do not
                    // know. Fail SAFE (counted drop, never a silent loss) and
                    // never call `block_in_place` on it.
                    Some(_) => false,
                    None => retry_fn(),
                };

                if !ok {
                    eprintln!("[storage] persist queue full for {PERSIST_BLOCKING_WAIT_MS}ms; dropping a consensus-relevant job (disk too slow? — counted, alert on stell_persist_queue_dropped_total)");
                    crate::metrics::global().inc_persist_queue_dropped();
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Non-blocking: enqueue a finalized block for writing.
    pub fn enqueue_block(&self, block: Block) {
        self.push(PersistJob::Block(block));
    }

    /// Non-blocking: enqueue a state snapshot.
    pub fn enqueue_state(&self, height: u64, snapshot: Vec<u8>) {
        self.push(PersistJob::State { height, snapshot });
    }

    /// Non-blocking: enqueue a domain snapshot (tokens/contracts/...), together
    /// with the session-key registry, the bridge domain,
    /// the zkML registry and the cross-shard replay snapshot of the same
    /// height.
    #[allow(clippy::too_many_arguments)]
    // GATE: domain-enqueue batches all same-height snapshots in one call; a params struct would churn storage callers.
    pub fn enqueue_domains(
        &self,
        height: u64,
        bytes: Vec<u8>,
        session_keys: Vec<u8>,
        bridge: Vec<u8>,
        zkml_models: Vec<u8>,
        cross_shard: Vec<u8>,
    ) {
        self.push(PersistJob::Domains {
            height,
            bytes,
            session_keys,
            bridge,
            zkml_models,
            cross_shard,
        });
    }

    /// Capture + enqueue the full domain snapshot (A9), plus the session-key
    /// registry AND the committed bridge domain captured from the SAME engine
    /// in the SAME job.
    ///
    /// The capture (clone under the read locks) happens before this returns --
    /// that is the snapshot instant -- while the bincode serialization runs on
    /// the BLOCKING POOL via [`serialize_off_tick`], so a consensus tick that
    /// calls this pays only for the clones and never for the encode.
    ///
    /// The registry and the bridge domain deliberately do NOT become fields of
    /// `DomainSnapshot`: that struct is bincode with a hard-erroring restore
    /// path, so a new field would stop every pre-session-key (and every
    /// pre-bridge) domain snapshot from decoding. Their own trees keep old
    /// snapshots loadable while still pairing with the height they were
    /// written at - and make a restored node keep refusing replayed source
    /// transactions, which is the whole point of committing the replay set.
    pub async fn snapshot_domains(
        &self,
        engine: &InMemoryStateEngine,
        staking: &crate::staking::StakingLedger,
        governance: &crate::governance::Governance,
        height: u64,
    ) {
        let snap = DomainSnapshot::capture(engine, staking, governance).await;
        let session_keys = engine.session_keys_snapshot().await;
        let bridge = engine.bridge_snapshot().await;
        let zkml_models = engine.zkml_models_snapshot().await;
        // Cross-shard replay, engine half (audit F-I): the runtime mirrors are
        // empty wherever this runs (startup healing with a fresh runtime, or
        // tests) - and that is CORRECT here, because there is nothing live to
        // protect yet. The periodic path (main.rs) snapshots the full struct
        // including the live runtime mirrors. Either way the engine credit
        // gate - the part that stops a double mint - always travels.
        //
        // §9 2PC: the engine's COMMITTED two-phase-commit records travel with
        // it too. They are the decision state of every cross-shard transfer
        // (PREPARED / COMMITTED / ABORTED), and they are part of the
        // commitment digest - so a blob without them would (a) re-open a
        // decided transfer on the next restart (the phase decides where the
        // value is) and (b) move the digest of a restarted node away from the
        // digest of a node that did not restart. The engine's completed set
        // travels for the same reason (it is what refuses a second
        // completion).
        let cross_shard = {
            use crate::sharding::CrossShardReplaySnapshot;
            let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
            engine_consumed.sort();
            let mut completed = engine.cross_shard_completed_snapshot().await;
            completed.sort();
            let xpc = engine.xpc_snapshot().await;
            bincode::serialize(&CrossShardReplaySnapshot {
                engine_consumed,
                completed,
                xpc,
                ..Default::default()
            })
            .unwrap_or_default()
        };
        // Serialize OFF the executor (bincode of every domain is real CPU work);
        // skip on error exactly like the old inline `if let Ok(bytes)` did.
        if let Some(bytes) = serialize_off_tick(snap).await {
            self.enqueue_domains(
                height,
                bytes,
                session_keys,
                bridge,
                zkml_models,
                cross_shard,
            );
        }
    }

    /// Non-blocking: persist the consensus safety checkpoint.
    pub fn enqueue_consensus(&self, cp: ConsensusCheckpoint) {
        self.push(PersistJob::Consensus(Box::new(cp)));
    }

    /// Non-blocking: record finality.
    pub fn enqueue_finalized(&self, height: u64, hash: BlockHash) {
        self.push(PersistJob::Finalized { height, hash });
    }

    /// Non-blocking: durably file the receipt set for one APPLIED block.
    ///
    /// `statuses` must be the outcome of the single real application of `txs`
    /// (the adopter's `apply_and_advance` / the proposer's finalize worker),
    /// never re-execution output or wire data. Fire-and-forget like every
    /// other enqueue: consensus never waits on disk.
    pub fn enqueue_receipts(
        &self,
        height: u64,
        hash: BlockHash,
        txs: Vec<crate::sharding::Transaction>,
        statuses: Vec<bool>,
        fees: Vec<u64>,
    ) {
        self.enqueue_receipts_with_events(height, hash, txs, statuses, fees, Vec::new());
    }

    pub fn enqueue_receipts_with_events(
        &self,
        height: u64,
        hash: BlockHash,
        txs: Vec<crate::sharding::Transaction>,
        statuses: Vec<bool>,
        fees: Vec<u64>,
        events: Vec<Vec<crate::contract::ContractEvent>>,
    ) {
        self.push(PersistJob::Receipts {
            height,
            hash,
            txs,
            statuses,
            fees,
            events,
        });
    }

    /// Ask the background writer to drop block bodies below `keep_from`.
    ///
    /// Fire-and-forget: consensus must never wait on disk.
    pub fn enqueue_prune(&self, keep_from: u64) {
        self.push(PersistJob::Prune { keep_from });
    }

    /// Request a durability barrier (processed after queued jobs).
    pub fn request_flush(&self) {
        self.push(PersistJob::Flush);
    }

    /// Jobs pushed but not yet dequeued by the background writer.
    ///
    /// Shutdown-path seam: the graceful-shutdown handler polls this until it
    /// reads empty (see [`wait_for_persist_drain`]). Reads zero at DEQUEUE —
    /// the dequeued job's own sled write (in particular the trailing `Flush`
    /// barrier's fsync) is still in flight at that instant, which is why the
    /// drain wait adds a bounded settle grace after observing zero rather
    /// than exiting immediately.
    pub fn pending(&self) -> u64 {
        self.queue_depth
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Snapshot the current state of an engine and enqueue it (convenience).
    ///
    /// Byte-identical to `engine.create_snapshot()`: the capture is the SAME
    /// canonical one (`InMemoryStateEngine::capture_state_snapshot` - the
    /// accounts PLUS the D2 consensus penalty map, address-sorted), so the
    /// bytes this path writes are the bytes `create_snapshot` produces and the
    /// bytes `restore_snapshot` reads back. Only the encode moves to the
    /// blocking pool (see [`serialize_off_tick`]).
    pub async fn snapshot_state(&self, engine: &InMemoryStateEngine, height: u64) {
        let accounts = clone_account_snapshot(engine).await;
        let snap = serialize_off_tick(accounts).await.unwrap_or_default();
        self.enqueue_state(height, snap);
    }
}

/// Graceful-shutdown drain budget: overall cap on waiting for the persist
/// queue to empty (shutdown path only).
///
/// The units carry `TimeoutStopSec=300s`: the process must be gone well
/// inside it, or systemd SIGKILLs it mid-write — the torn-sled brick this
/// replaces (fixed 15s sleep, then `exit(0)` mid-flush). Worst case below is
/// `SHUTDOWN_DRAIN_CAP_SECS + SHUTDOWN_SETTLE_GRACE_SECS` = 250s < 300s.
pub const SHUTDOWN_DRAIN_CAP_SECS: u64 = 240;
/// Poll cadence while waiting for the queue to drain. The query is one
/// atomic load, so sub-second polling costs nothing and exits promptly on
/// drain instead of sleeping past it.
pub const SHUTDOWN_DRAIN_POLL_MS: u64 = 500;
/// Operator-visible progress cadence while waiting for the drain.
pub const SHUTDOWN_DRAIN_LOG_EVERY_SECS: u64 = 15;
/// Extra grace AFTER the queue reads empty. [`AsyncPersistence::pending`]
/// hits zero at DEQUEUE — the trailing `Flush` barrier's own sled fsync is
/// still in flight at that instant — and the runtime snapshot worker
/// (`submit_snapshot`/`poll_snapshot`) is not queryable from the shutdown
/// path (no runtime handle is captured there), so a bounded settle covers
/// both without refactoring unrelated code.
pub const SHUTDOWN_SETTLE_GRACE_SECS: u64 = 10;

/// Tuning for [`wait_for_persist_drain`]. `Default` is the production
/// shutdown budget above; the struct (not loose args) exists so tests can
/// shrink every knob to milliseconds without touching production values.
#[derive(Clone, Copy, Debug)]
pub struct ShutdownDrainConfig {
    /// Give up and report `drained: false` after this long.
    pub cap: std::time::Duration,
    /// Delay between queue-depth polls.
    pub poll: std::time::Duration,
    /// Minimum gap between `[storage] shutdown drain` progress lines.
    pub log_every: std::time::Duration,
    /// Extra wait after the queue first reads empty (see
    /// [`SHUTDOWN_SETTLE_GRACE_SECS`]).
    pub settle_grace: std::time::Duration,
}

impl Default for ShutdownDrainConfig {
    fn default() -> Self {
        Self {
            cap: std::time::Duration::from_secs(SHUTDOWN_DRAIN_CAP_SECS),
            poll: std::time::Duration::from_millis(SHUTDOWN_DRAIN_POLL_MS),
            log_every: std::time::Duration::from_secs(SHUTDOWN_DRAIN_LOG_EVERY_SECS),
            settle_grace: std::time::Duration::from_secs(SHUTDOWN_SETTLE_GRACE_SECS),
        }
    }
}

/// Outcome of [`wait_for_persist_drain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownDrainOutcome {
    /// True when the queue read empty before the cap (settle grace included
    /// in the wait); false when the cap fired first — e.g. consensus kept
    /// finalizing (and enqueueing) during the wait, or the disk is wedged.
    /// The caller still exits: the cap is the bounded worst case inside the
    /// systemd stop timeout.
    pub drained: bool,
    /// Queue depth observed when the wait ended (0 when drained).
    pub last_pending: u64,
}

/// Wait until `pending` reports an empty persist queue, then observe the
/// settle grace and report. `pending` is any queue-depth query — in
/// production `|| ap.pending()`, in tests a fake counter.
///
/// Evidence contract for operators: while waiting, one
/// `[storage] shutdown drain: N blocks pending...` line every `log_every`.
pub async fn wait_for_persist_drain_with(
    pending: impl Fn() -> u64,
    cfg: ShutdownDrainConfig,
) -> ShutdownDrainOutcome {
    let start = std::time::Instant::now();
    let mut last_log = start;
    loop {
        let n = pending();
        if n == 0 {
            tokio::time::sleep(cfg.settle_grace).await;
            return ShutdownDrainOutcome {
                drained: true,
                last_pending: 0,
            };
        }
        if start.elapsed() >= cfg.cap {
            return ShutdownDrainOutcome {
                drained: false,
                last_pending: n,
            };
        }
        if last_log.elapsed() >= cfg.log_every {
            eprintln!("[storage] shutdown drain: {n} blocks pending...");
            last_log = std::time::Instant::now();
        }
        tokio::time::sleep(cfg.poll).await;
    }
}

/// Production-budget [`wait_for_persist_drain_with`]: the shared shutdown
/// helper every graceful-shutdown site calls after `request_flush()`.
/// Keeps `exit(0)` semantics at the call site; worst case
/// cap + settle grace, comfortably inside the 300s stop timeout.
pub async fn wait_for_persist_drain(pending: impl Fn() -> u64) -> ShutdownDrainOutcome {
    wait_for_persist_drain_with(pending, ShutdownDrainConfig::default()).await
}

/// The engine's consensus state, cloned under the read lock and NOT serialized.
///
/// This clone IS the snapshot instant: every byte that follows (bincode, the
/// disk queue, the DHT publish) happens after it, off the caller's await point,
/// so a snapshot labeled `height` still holds exactly the state `height`
/// finalized even if `height+1` is applied before the encode runs.
///
/// It is the CANONICAL capture (`InMemoryStateEngine::capture_state_snapshot`):
/// the accounts (address-sorted) AND the D2 consensus penalty map. The
/// penalty is consensus-critical (it enters the charged fee), so a snapshot
/// that dropped it would restore a node that charges a DIFFERENT fee than a
/// node that applied the blocks - a different state root, i.e. a consensus
/// split (audit W6.6). The same function backs
/// `InMemoryStateEngine::create_snapshot`, so the off-tick bytes and the
/// inline bytes are identical by construction, not by coincidence.
pub async fn clone_account_snapshot(
    engine: &InMemoryStateEngine,
) -> crate::state_engine::StateSnapshotV2 {
    engine.capture_state_snapshot().await
}

/// bincode-serialize `value` on the BLOCKING POOL (never on a consensus tick).
///
/// §7 Phase 1: a full account or domain snapshot is thousands of allocations
/// plus one large buffer, and doing that inline kept a non-transport millisecond
/// cost on the very loop that drives consensus (and, in `create_snapshot`, under
/// the engine's read lock, which then blocked writers). Returns `None` when
/// bincode refuses the value, so callers keep whatever skip/fallback behaviour
/// they had with an inline `bincode::serialize`.
pub async fn serialize_off_tick<T: Serialize + Send + 'static>(value: T) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking(move || bincode::serialize(&value).ok())
        .await
        .unwrap_or(None)
}

/// Load a node's state from storage into a fresh engine, returning the height
/// it corresponds to. Falls back to an empty state if nothing is stored.
///
/// Like `fast_sync_state`, the snapshot is first restored into a throwaway
/// engine whose root must exactly match the finalized block at height+1 (see
/// `Storage::verify_restored_root`); only then is the live engine written. A
/// truncated, corrupt, or wrong-height snapshot returns `Err` and leaves the
/// engine untouched.
///
/// When a domain snapshot is paired with this state snapshot (same height) the
/// account-only root is only part of the committed state, so verification is
/// deferred to `load_full_state_into`, which checks the complete root after
/// the domains are applied.
/// TEST-ONLY legacy restore (audit 2026-10-06): restores state +
/// session-keys + bridge, omitting confidential/zkml/cross-shard — on a chain
/// with shielded/zkml activity the root check false-rejects. Live boot uses
/// `load_full_state_into` (paired snapshots); this exists for unit tests that
/// pin the legacy path. MUST NOT be wired into boot.
#[cfg(any(test, debug_assertions))]
pub async fn load_state_into(
    storage: &Storage,
    engine: &InMemoryStateEngine,
) -> Result<Option<u64>> {
    engine.attach_pq_tree(storage.pq_keys.clone());
    let _ = storage.hydrate_implicit_pq_keys();
    match storage.latest_state()? {
        Some((height, snap)) => {
            let tmp = InMemoryStateEngine::new();
            tmp.attach_pq_tree(storage.pq_keys.clone());
            tmp.restore_snapshot(&snap)
                .await
                .map_err(|e| anyhow!("restore state: {e}"))?;
            // The session-key registry AND the bridge domain are part of the
            // committed state, so both engines (the verifying throwaway and
            // the live one) get them - see `load_full_state_into` for why
            // absence simply means "empty".
            if let Some(bytes) = storage.session_keys_at(height)? {
                tmp.restore_session_keys(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore session keys: {e}"))?;
            }
            if let Some(bytes) = storage.bridge_at(height)? {
                tmp.restore_bridge(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
            }
            let domains_paired = matches!(storage.latest_domains()?, Some((dh, _)) if dh == height);
            if !domains_paired {
                storage.verify_restored_root(&tmp, height).await?;
            }
            engine
                .restore_snapshot(&snap)
                .await
                .map_err(|e| anyhow!("restore state: {e}"))?;
            if let Some(bytes) = storage.session_keys_at(height)? {
                engine
                    .restore_session_keys(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore session keys: {e}"))?;
            }
            if let Some(bytes) = storage.bridge_at(height)? {
                engine
                    .restore_bridge(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
            }
            Ok(Some(height))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
    use crate::state_engine::AccountState;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "stell_store_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ))
    }

    fn block(height: u64, prev: [u8; 32], signer: &SigningKey, tx: Option<Transaction>) -> Block {
        let transactions: Vec<Transaction> = tx.into_iter().collect();
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [height as u8; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: height,
            proposer: signer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(signer);
        b
    }

    #[test]
    fn block_store_roundtrip_and_height_index() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);

        let b0 = block(0, [0u8; 32], &sk, None);
        let h0 = st.put_block(&b0).unwrap();
        let b1 = block(1, h0, &sk, None);
        let h1 = st.put_block(&b1).unwrap();

        assert_eq!(st.block_count().expect("count"), 2);
        let got = st.get_block(&h1).unwrap().unwrap();
        assert_eq!(got.height, 1);
        assert_eq!(st.hashes_at_height(1).unwrap(), vec![h1]);
        assert_eq!(st.hashes_at_height(5).unwrap().len(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finalized_meta_roundtrip() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        assert!(st.finalized().unwrap().is_none());
        st.set_finalized(7, &[9u8; 32]).unwrap();
        let (h, hash) = st.finalized().unwrap().unwrap();
        assert_eq!(h, 7);
        assert_eq!(hash, [9u8; 32]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn consensus_checkpoint_roundtrip() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        assert!(st.consensus().unwrap().is_none());
        let cp = ConsensusCheckpoint {
            height: 11,
            round: 2,
            locked_hash: Some([7u8; 32]),
            locked_round: 1,
            finalized_height: 10,
            finalized_hash: [9u8; 32],
        };
        st.set_consensus(&cp).unwrap();
        let got = st.consensus().unwrap().unwrap();
        assert_eq!(got.height, 11);
        assert_eq!(got.round, 2);
        assert_eq!(got.locked_hash, Some([7u8; 32]));
        assert_eq!(got.finalized_height, 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_snapshot_roundtrip_and_prune() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        st.put_state(1, b"one").unwrap();
        st.put_state(2, b"two").unwrap();
        st.put_state(3, b"three").unwrap();
        assert_eq!(st.latest_state().unwrap().unwrap(), (3, b"three".to_vec()));
        let pruned = st.prune_state_below(3).unwrap();
        assert_eq!(pruned, 2);
        assert_eq!(st.latest_state().unwrap().unwrap(), (3, b"three".to_vec()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn async_persistence_writes_blocks_and_state() {
        let dir = tmp();
        let st = Arc::new(Storage::open(&dir).unwrap());
        let ap = AsyncPersistence::start(st.clone());
        let sk = SigningKey::generate(&mut OsRng);

        let b = block(0, [0u8; 32], &sk, None);
        let bh = b.compute_hash();
        ap.enqueue_block(b);
        ap.enqueue_finalized(0, bh);

        // snapshot of an engine with one funded account
        let engine = InMemoryStateEngine::new();
        let who = sk.verifying_key().to_bytes();
        engine.update_account(AccountState::new(who, 42)).await;
        ap.snapshot_state(&engine, 0).await;

        // flush barrier: everything enqueued before it must be durable
        ap.request_flush();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            st.get_block(&bh).unwrap().is_some(),
            "block must be persisted"
        );
        assert_eq!(st.finalized().unwrap().unwrap().0, 0);
        assert!(
            st.latest_state().unwrap().is_some(),
            "state must be persisted"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    fn fast_drain_cfg() -> ShutdownDrainConfig {
        ShutdownDrainConfig {
            cap: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
            log_every: std::time::Duration::from_secs(60),
            settle_grace: std::time::Duration::from_millis(1),
        }
    }

    #[tokio::test]
    async fn shutdown_drain_returns_at_once_when_queue_empty() {
        let out = wait_for_persist_drain_with(|| 0, fast_drain_cfg()).await;
        assert_eq!(
            out,
            ShutdownDrainOutcome {
                drained: true,
                last_pending: 0
            }
        );
    }

    #[tokio::test]
    async fn shutdown_drain_waits_until_queue_empties() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let depth = Arc::new(AtomicU64::new(3));
        let writer = depth.clone();
        tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                writer.fetch_sub(1, Ordering::Relaxed);
            }
        });
        let out =
            wait_for_persist_drain_with(|| depth.load(Ordering::Relaxed), fast_drain_cfg()).await;
        assert_eq!(
            out,
            ShutdownDrainOutcome {
                drained: true,
                last_pending: 0
            }
        );
    }

    #[tokio::test]
    async fn shutdown_drain_caps_when_queue_never_empties() {
        let cfg = ShutdownDrainConfig {
            cap: std::time::Duration::from_millis(50),
            ..fast_drain_cfg()
        };
        let start = std::time::Instant::now();
        let out = wait_for_persist_drain_with(|| 7, cfg).await;
        assert_eq!(
            out,
            ShutdownDrainOutcome {
                drained: false,
                last_pending: 7
            }
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "cap must bound the wait"
        );
    }

    #[tokio::test]
    async fn async_persistence_pending_starts_empty() {
        let dir = tmp();
        let st = Arc::new(Storage::open(&dir).unwrap());
        let ap = AsyncPersistence::start(st);
        assert_eq!(ap.pending(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn load_state_restores_balances() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let engine = InMemoryStateEngine::new();
        let who = [7u8; 32];
        engine.update_account(AccountState::new(who, 1234)).await;
        let snap = engine.create_snapshot().await;
        st.put_state(5, &snap).unwrap();

        let engine2 = InMemoryStateEngine::new();
        let h = load_state_into(&st, &engine2).await.unwrap();
        assert_eq!(h, Some(5));
        assert_eq!(engine2.get_account(&who).await.unwrap().balance, 1234);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn full_state_restore_preserves_accounts_tokens_and_contracts() {
        use crate::token::TokenMetadata;

        // (func (export "double") (param i64) (result i64) local.get 0; i64.const 2; i64.mul)
        const DOUBLE_WASM: &[u8] = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7e,
            0x01, 0x7e, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x64, 0x6f, 0x75, 0x62,
            0x6c, 0x65, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x42, 0x02, 0x7e,
            0x0b,
        ];

        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let engine = InMemoryStateEngine::new();
        let who = [7u8; 32];
        engine.update_account(AccountState::new(who, 5_000)).await;

        let meta = TokenMetadata {
            name: "Wrapped".into(),
            symbol: "W".into(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: [0u8; 32],
            paused: false,
            description: String::new(),
        };
        let tid = engine.create_token(who, meta, 1_000).await.unwrap();
        let caddr = engine
            .deploy_contract(who, DOUBLE_WASM.to_vec(), 0)
            .await
            .unwrap();

        // Persist accounts + domains at height 9.
        st.put_state(9, &engine.create_snapshot().await).unwrap();
        let snap = DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        st.put_domains(9, &bincode::serialize(&snap).unwrap())
            .unwrap();

        // Restore into a fresh engine.
        let engine2 = InMemoryStateEngine::new();
        let loaded = load_full_state_into(&st, &engine2).await.unwrap().unwrap();
        assert_eq!(loaded.0, 9);
        assert_eq!(engine2.get_account(&who).await.unwrap().balance, 5_000);
        assert_eq!(
            engine2.token_balance(&tid, &who).await,
            1_000,
            "token registry restored"
        );
        assert!(
            engine2.get_contract(&caddr).await.is_some(),
            "contract registry restored"
        );
        // SPV proof for the restored token balance still verifies against the root.
        assert!(engine2.get_token_balance_proof(&tid, &who).await.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Snapshot label/content binding (restart crash-loop regression).
    ///
    /// Live shape: a snapshot labeled S must hold ONLY post-S state, because
    /// the boot check (`verify_restored_root`) compares it against
    /// `header(S+1).state_root`. The old poll-time cross-shard capture read a
    /// replay set advanced by later heights and persisted it under label S;
    /// the restored engine then rooted differently from the anchor and every
    /// restart died with `restore root mismatch`. The fix (main.rs snapshot
    /// block) captures the replay bytes at submit quiescence and reuses them
    /// verbatim at poll, so this test pins the healthy end-to-end shape:
    /// persist a fully consistent snapshot for S (accounts, domains, aux AND
    /// the replay set, all captured pre-apply), anchor it with the S+1 header
    /// committing to the pre-apply root, advance the live engine with a REAL
    /// block apply, then reboot-load from the store and require the verify to
    /// pass. Non-empty replay sets throughout: empty sets are
    /// digest-invisible and would make this test vacuous.
    #[tokio::test]
    async fn snapshot_at_s_verifies_after_real_apply_to_s_plus_1() {
        use crate::sharding::{CrossShardKey, CrossShardReplaySnapshot};

        const S: u64 = 100;
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);

        // Live engine at post-S state, with NON-EMPTY replay sets.
        let engine = InMemoryStateEngine::new();
        let who = [11u8; 32];
        engine.update_account(AccountState::new(who, 1_000_000)).await;
        engine
            .restore_cross_shard_replay(&CrossShardReplaySnapshot {
                engine_consumed: vec![CrossShardKey {
                    source_shard: 1,
                    finalized_in_block: [2u8; 32],
                    msg_id: [3u8; 32],
                }],
                completed: vec![[4u8; 32]],
                ..Default::default()
            })
            .await;
        let root_s = engine.get_state_root().await;

        // Capture the FULL snapshot exactly as the live path does (accounts +
        // domains + every aux domain + the replay set, all pre-apply).
        let accounts = clone_account_snapshot(&engine).await;
        let state_bytes = serialize_off_tick(accounts)
            .await
            .expect("encode accounts");
        let staking = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();
        let domains = DomainSnapshot::capture(&engine, &staking, &gov).await;
        let domain_bytes = serialize_off_tick(domains)
            .await
            .expect("encode domains");
        let session_keys = engine.session_keys_snapshot().await;
        let bridge = engine.bridge_snapshot().await;
        let zkml_models = engine.zkml_models_snapshot().await;
        let cross_shard = {
            let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
            engine_consumed.sort();
            let mut completed = engine.cross_shard_completed_snapshot().await;
            completed.sort();
            let xpc = engine.xpc_snapshot().await;
            bincode::serialize(&CrossShardReplaySnapshot {
                engine_consumed,
                completed,
                xpc,
                ..Default::default()
            })
            .expect("encode cross-shard")
        };
        st.put_state(S, &state_bytes).unwrap();
        st.put_domains(S, &domain_bytes).unwrap();
        st.put_session_keys(S, &session_keys).unwrap();
        st.put_bridge(S, &bridge).unwrap();
        st.put_zkml_models(S, &zkml_models).unwrap();
        st.put_cross_shard(S, &cross_shard).unwrap();

        // Anchor: the S+1 header commits to the PRE-apply (post-S) root — the
        // proposer rule `expected_restore_root` relies on.
        let mut anchor = block(S + 1, [9u8; 32], &sk, None);
        anchor.state_root = root_s;
        let anchor_hash = anchor.compute_hash();
        st.put_header(&BlockHeaderRecord::of(&anchor)).unwrap();
        st.set_finalized(S + 1, &anchor_hash).unwrap();

        // Advance the live engine with a REAL block apply (the block reward
        // moves the root) plus newer replay activity, the way S+1
        // finalization would: the persisted snapshot must stay S-pinned
        // regardless.
        let mut next = block(S + 1, [9u8; 32], &sk, None);
        next.state_root = root_s;
        engine.apply_block_transition(&next, 500).await;
        engine
            .restore_cross_shard_replay(&CrossShardReplaySnapshot {
                engine_consumed: vec![CrossShardKey {
                    source_shard: 1,
                    finalized_in_block: [5u8; 32],
                    msg_id: [6u8; 32],
                }],
                completed: vec![[7u8; 32]],
                ..Default::default()
            })
            .await;
        assert_ne!(
            engine.get_state_root().await,
            root_s,
            "the S+1 apply must move the live root, or the test proves nothing"
        );

        // Reboot: fresh engine, load from the store, verify must pass.
        let fresh = InMemoryStateEngine::new();
        let loaded = load_full_state_into(&st, &fresh)
            .await
            .expect("consistent snapshot S must restore");
        assert_eq!(loaded.map(|(h, _, _)| h), Some(S));
        assert_eq!(fresh.get_state_root().await, root_s);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Mixed-height snapshot must fail the restore verify: accounts/domains at
    /// S, replay bytes from post-S+1 activity, label S. This is the exact
    /// persisted shape the old poll-time cross-shard capture produced (see the
    /// test above for the fixed shape). `load_full_state_into` must refuse it
    /// with `restore root mismatch` instead of installing a forked engine.
    #[tokio::test]
    async fn mixed_height_cross_shard_snapshot_fails_restore_verify() {
        use crate::sharding::{CrossShardKey, CrossShardReplaySnapshot};

        const S: u64 = 100;
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);

        let engine = InMemoryStateEngine::new();
        let who = [11u8; 32];
        engine.update_account(AccountState::new(who, 1_000_000)).await;
        engine
            .restore_cross_shard_replay(&CrossShardReplaySnapshot {
                engine_consumed: vec![CrossShardKey {
                    source_shard: 1,
                    finalized_in_block: [2u8; 32],
                    msg_id: [3u8; 32],
                }],
                completed: vec![[4u8; 32]],
                ..Default::default()
            })
            .await;
        let root_s = engine.get_state_root().await;

        // Accounts/domains/aux captured at S (pre-apply), exactly as live.
        let accounts = clone_account_snapshot(&engine).await;
        let state_bytes = serialize_off_tick(accounts)
            .await
            .expect("encode accounts");
        let staking = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();
        let domains = DomainSnapshot::capture(&engine, &staking, &gov).await;
        let domain_bytes = serialize_off_tick(domains)
            .await
            .expect("encode domains");
        let session_keys = engine.session_keys_snapshot().await;
        let bridge = engine.bridge_snapshot().await;
        let zkml_models = engine.zkml_models_snapshot().await;
        let cross_shard_s = {
            let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
            engine_consumed.sort();
            let mut completed = engine.cross_shard_completed_snapshot().await;
            completed.sort();
            let xpc = engine.xpc_snapshot().await;
            bincode::serialize(&CrossShardReplaySnapshot {
                engine_consumed,
                completed,
                xpc,
                ..Default::default()
            })
            .expect("encode cross-shard")
        };

        // S+1 activity moves the engine on (real apply + newer replay set).
        let mut next = block(S + 1, [9u8; 32], &sk, None);
        next.state_root = root_s;
        engine.apply_block_transition(&next, 500).await;
        engine
            .restore_cross_shard_replay(&CrossShardReplaySnapshot {
                engine_consumed: vec![CrossShardKey {
                    source_shard: 1,
                    finalized_in_block: [5u8; 32],
                    msg_id: [6u8; 32],
                }],
                completed: vec![[7u8; 32]],
                ..Default::default()
            })
            .await;
        // Replay bytes captured AFTER the advance (the old poll-time bug).
        let cross_shard_newer = {
            let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
            engine_consumed.sort();
            let mut completed = engine.cross_shard_completed_snapshot().await;
            completed.sort();
            let xpc = engine.xpc_snapshot().await;
            bincode::serialize(&CrossShardReplaySnapshot {
                engine_consumed,
                completed,
                xpc,
                ..Default::default()
            })
            .expect("encode cross-shard")
        };
        assert_ne!(
            cross_shard_newer, cross_shard_s,
            "the replay set must advance, or the mixed-height shape is vacuous"
        );

        // Persisted under label S with the S+1 anchor, like the old bug did.
        st.put_state(S, &state_bytes).unwrap();
        st.put_domains(S, &domain_bytes).unwrap();
        st.put_session_keys(S, &session_keys).unwrap();
        st.put_bridge(S, &bridge).unwrap();
        st.put_zkml_models(S, &zkml_models).unwrap();
        st.put_cross_shard(S, &cross_shard_newer).unwrap();
        let mut anchor = block(S + 1, [9u8; 32], &sk, None);
        anchor.state_root = root_s;
        st.put_header(&BlockHeaderRecord::of(&anchor)).unwrap();
        st.set_finalized(S + 1, &anchor.compute_hash()).unwrap();

        let fresh = InMemoryStateEngine::new();
        let err = load_full_state_into(&st, &fresh)
            .await
            .expect_err("mixed-height snapshot must be refused");
        assert!(
            err.to_string()
                .contains(&format!("restore root mismatch at height {S}")),
            "unexpected error: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pre_e2_domain_snapshot_upgrades_staking_counters_to_zero() {
        use crate::staking::{
            StakingLedger, StakingLedgerV1, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
        };

        // A ledger with real content, as a pre-E2 node would have held it.
        let val = [0xA1u8; 32];
        let delegator = [0xB2u8; 32];
        let mut ledger = StakingLedger::new();
        ledger
            .bond(val, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .unwrap();
        ledger.delegate(delegator, val, 2_000_000_000).unwrap();
        ledger.slash(val, 1_000).unwrap(); // 10%: total_burned is non-zero
        assert!(ledger.total_burned > 0);

        // The CURRENT shape round-trips through the primary path untouched.
        let fresh = DomainSnapshot {
            staking: ledger.clone(),
            ..Default::default()
        };
        let fresh_bytes = bincode::serialize(&fresh).unwrap();
        let back = decode_domain_snapshot(&fresh_bytes).unwrap();
        assert_eq!(back.staking.total_burned, ledger.total_burned);
        assert_eq!(back.staking.rewards_pool, 0);
        assert_eq!(back.staking.rewards_minted, 0);

        // The OLD shape: same six staking fields, no rewards counters, no
        // governance locks — byte-identical to what a pre-E2 node wrote.
        let old = DomainSnapshotV1 {
            tokens: fresh.tokens.clone(),
            contracts: fresh.contracts.clone(),
            orderbooks: fresh.orderbooks.clone(),
            pmm: fresh.pmm.clone(),
            pmm_usdt_token: fresh.pmm_usdt_token,
            pmm_treasury: fresh.pmm_treasury,
            order_escrow: fresh.order_escrow.clone(),
            staking: StakingLedgerV1 {
                validators: ledger.validators.clone(),
                delegations: ledger.delegations.clone(),
                delegator_rewards: ledger.delegator_rewards.clone(),
                unbonding: ledger.unbonding.clone(),
                withdrawable: ledger.withdrawable.clone(),
                total_burned: ledger.total_burned,
            },
            governance: fresh.governance.clone(),
            oracle: fresh.oracle.clone(),
        };
        let old_bytes = bincode::serialize(&old).unwrap();
        // The old bytes genuinely do NOT decode as the current struct (this
        // is the brick the fallback exists for — without it the restore path
        // hard-errors on every pre-E2 data directory).
        assert!(
            bincode::deserialize::<DomainSnapshot>(&old_bytes).is_err(),
            "pre-E2 bytes must fail the direct decode, or the fallback is untested"
        );
        // ... but the restore helper upgrades them.
        let up = decode_domain_snapshot(&old_bytes).unwrap();
        assert_eq!(up.staking.validators, ledger.validators, "bonds survive");
        assert_eq!(
            up.staking.delegations, ledger.delegations,
            "positions survive"
        );
        assert_eq!(
            up.staking.delegator_rewards, ledger.delegator_rewards,
            "reward entries survive"
        );
        assert_eq!(up.staking.unbonding, ledger.unbonding, "unbondings survive");
        assert_eq!(
            up.staking.withdrawable, ledger.withdrawable,
            "matured funds survive"
        );
        assert_eq!(
            up.staking.total_burned, ledger.total_burned,
            "burn history survives"
        );
        assert_eq!(up.staking.rewards_pool, 0, "new counter starts at zero");
        assert_eq!(up.staking.rewards_minted, 0, "new counter starts at zero");
        assert!(up.staking.locked_governance.is_empty(), "no phantom locks");
        assert_eq!(
            up.governance.next_id, fresh.governance.next_id,
            "sibling domains survive"
        );
        assert_eq!(
            up.governance.quorum_bps, fresh.governance.quorum_bps,
            "sibling domains survive"
        );
        assert_eq!(
            up.governance.proposals.len(),
            fresh.governance.proposals.len(),
            "sibling domains survive"
        );
    }

    /// The pre-lazy-accumulator snapshot shape (V3) upgrades with an EMPTY
    /// accumulator and EMPTY checkpoints — EXACT, because the eager
    /// implementation materialised every delegator reward at distribution
    /// time, so there is no lazy state to reconstruct.
    #[test]
    fn pre_lazy_accumulator_domain_snapshot_upgrades_with_empty_accumulator() {
        use crate::staking::{
            StakingLedger, StakingLedgerV3, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
        };

        let val = [0xA3u8; 32];
        let delegator = [0xB4u8; 32];
        let mut ledger = StakingLedger::new();
        ledger
            .bond(val, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .unwrap();
        ledger.delegate(delegator, val, 2_000_000_000).unwrap();
        ledger.distribute_reward(val, 1_000_000_000).unwrap();
        // The lazy path keeps the reward UNSETTLED (that is the whole point):
        // it lives in the accumulator, not in the map.
        assert!(ledger.delegator_rewards.is_empty());
        assert_eq!(ledger.reward_accumulators.len(), 1);

        let fresh = DomainSnapshot {
            staking: ledger.clone(),
            ..Default::default()
        };
        let fresh_bytes = bincode::serialize(&fresh).unwrap();
        let back = decode_domain_snapshot(&fresh_bytes).unwrap();
        assert_eq!(
            back.staking.reward_accumulators.len(),
            1,
            "the accumulator survives"
        );

        // The OLD shape: the ledger WITHOUT the two lazy maps — byte-identical
        // to what a pre-upgrade node wrote.
        let old = DomainSnapshotV3 {
            tokens: fresh.tokens.clone(),
            contracts: fresh.contracts.clone(),
            orderbooks: fresh.orderbooks.clone(),
            pmm: fresh.pmm.clone(),
            pmm_usdt_token: fresh.pmm_usdt_token,
            pmm_treasury: fresh.pmm_treasury,
            order_escrow: fresh.order_escrow.clone(),
            staking: StakingLedgerV3 {
                validators: ledger.validators.clone(),
                delegations: ledger.delegations.clone(),
                delegator_rewards: ledger.delegator_rewards.clone(),
                unbonding: ledger.unbonding.clone(),
                withdrawable: ledger.withdrawable.clone(),
                total_burned: ledger.total_burned,
                rewards_pool: ledger.rewards_pool,
                rewards_minted: ledger.rewards_minted,
                locked_governance: ledger.locked_governance.clone(),
                pq_equivocation_dedup: ledger.pq_equivocation_dedup.clone(),
                equivocation_dedup: ledger.equivocation_dedup.clone(),
                validator_pq_keys: ledger.validator_pq_keys.clone(),
                min_validator_bond: ledger.min_validator_bond,
                vesting_schedules: ledger.vesting_schedules.clone(),
            },
            governance: fresh.governance.clone(),
            oracle: fresh.oracle.clone(),
        };
        let old_bytes = bincode::serialize(&old).unwrap();
        assert!(
            bincode::deserialize::<DomainSnapshot>(&old_bytes).is_err(),
            "pre-lazy-accumulator bytes must fail the direct decode, or the fallback \
             is untested"
        );
        // ... but the restore helper upgrades them.
        let up = decode_domain_snapshot(&old_bytes).unwrap();
        assert_eq!(up.staking.validators, ledger.validators, "bonds survive");
        assert_eq!(
            up.staking.delegations, ledger.delegations,
            "positions survive"
        );
        assert_eq!(
            up.staking.rewards_minted, ledger.rewards_minted,
            "the mint counter survives"
        );
        assert!(
            up.staking.reward_accumulators.is_empty(),
            "no phantom accumulator: the eager ledger had none"
        );
        assert!(
            up.staking.delegator_reward_checkpoints.is_empty(),
            "no phantom checkpoints: the eager ledger had none"
        );
    }

    // ==================== Adopter replication: verified bodies + durable receipts ===

    fn repl_block(height: u64, signer: &SigningKey, tx: Option<Transaction>) -> Block {
        block(height, [height as u8; 32], signer, tx)
    }

    #[test]
    fn verified_body_ingest_rejects_tamper_and_stores_honest() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let b = repl_block(9, &sk, None);
        let h = b.compute_hash();
        // Honest: stored.
        st.put_verified_block(&b, &h).unwrap();
        assert!(st.get_block(&h).unwrap().is_some());
        // Tampered body under the committed hash: rejected, nothing overwritten.
        let mut tampered = b.clone();
        tampered.timestamp ^= 0x01;
        assert!(st.put_verified_block(&tampered, &h).is_err());
        let kept = st.get_block(&h).unwrap().unwrap();
        assert_eq!(
            kept.timestamp, b.timestamp,
            "tamper must not overwrite the committed body"
        );
        // Filed under a wrong hash: rejected too.
        assert!(st.put_verified_block(&b, &[0xEEu8; 32]).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn receipts_are_durable_and_height_indexed() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        let tx = Transaction::sign(&sk, from, 10, 1, 0, 0, 0);
        let b = repl_block(11, &sk, Some(tx.clone()));
        let bh = b.compute_hash();
        st.put_block(&b).unwrap();
        let n = st
            .put_receipts_for_block(11, &bh, &b.transactions, &[true], &[1])
            .unwrap();
        assert_eq!(n, 1);
        let got = st
            .get_receipt(&tx.compute_tx_hash())
            .unwrap()
            .expect("receipt filed");
        assert_eq!(
            (got.height, got.block_hash, got.index, got.success),
            (11, bh, 0, true)
        );
        assert_eq!(
            got.fee_charged, 1,
            "actual charged fee is filed, not just the limit"
        );
        assert_eq!(st.receipt_count().unwrap(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_receipts_decode_with_honest_fee_mapping() {
        // Receipts written before `fee_charged` existed still decode, with the
        // fee mapped to what the block path actually charged then.
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        for (hash, success) in [([1u8; 32], true), ([2u8; 32], false)] {
            let legacy = LegacyStoredReceipt {
                tx_hash: hash,
                height: 3,
                block_hash: [0xAA; 32],
                index: 0,
                success,
                gas_limit: 560,
            };
            st.receipts
                .insert(hash, bincode::serialize(&legacy).unwrap())
                .unwrap();
        }
        let ok = st
            .get_receipt(&[1u8; 32])
            .unwrap()
            .expect("legacy success decodes");
        assert_eq!(
            ok.fee_charged, 560,
            "legacy success charged the declared limit"
        );
        assert_eq!(ok.gas_limit, 560, "limit is preserved");
        assert!(ok.events.is_empty(), "legacy receipt has empty events");
        let bad = st
            .get_receipt(&[2u8; 32])
            .unwrap()
            .expect("legacy failure decodes");
        assert_eq!(bad.fee_charged, 0, "legacy failure charged nothing");
        assert!(bad.events.is_empty(), "legacy receipt has empty events");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_receipts_with_fee_decode_with_empty_events() {
        // Receipts written with fee_charged but before `events` existed (7 fields)
        // must decode cleanly with empty events.
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let hash = [3u8; 32];
        let legacy = LegacyStoredReceiptWithFee {
            tx_hash: hash,
            height: 4,
            block_hash: [0xBB; 32],
            index: 1,
            success: true,
            gas_limit: 1000,
            fee_charged: 500,
        };
        st.receipts
            .insert(hash, bincode::serialize(&legacy).unwrap())
            .unwrap();

        let r = st
            .get_receipt(&hash)
            .unwrap()
            .expect("7-field receipt decodes");
        assert_eq!(r.height, 4);
        assert_eq!(r.fee_charged, 500);
        assert_eq!(r.gas_limit, 1000);
        assert!(r.events.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn receipts_persist_and_decode_contract_events() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        let tx = Transaction::sign(&sk, from, 10, 1, 0, 0, 0);
        let bh = [0xCC; 32];
        let contract = [0x55; 32];
        let events = vec![vec![crate::contract::ContractEvent {
            contract,
            topic: 1234,
            value: 5678,
        }]];

        let n = st
            .put_receipts_for_block_with_events(
                12,
                &bh,
                std::slice::from_ref(&tx),
                &[true],
                &[100],
                &events,
            )
            .unwrap();
        assert_eq!(n, 1);

        let r = st
            .get_receipt(&tx.compute_tx_hash())
            .unwrap()
            .expect("receipt exists");
        assert_eq!(r.height, 12);
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.events[0].contract, contract);
        assert_eq!(r.events[0].topic, 1234);
        assert_eq!(r.events[0].value, 5678);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adopter_ends_with_byte_identical_bodies_and_receipts_as_proposer() {
        // Proposer commits a body + its single-apply receipt set; the adopter
        // replicates via hash-verified ingest + locally-filed receipts and must
        // hold byte-identical artifacts (no txs=0, no missing receipts).
        let dir_p = tmp();
        let dir_a = tmp();
        let proposer = Storage::open(&dir_p).unwrap();
        let adopter = Storage::open(&dir_a).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, sk.verifying_key().to_bytes(), 50, 1, 7, 0, 0);
        let b = repl_block(21, &sk, Some(tx.clone()));
        let bh = b.compute_hash();
        proposer.put_block(&b).unwrap();
        proposer
            .put_receipts_for_block(21, &bh, &b.transactions, &[true], &[1])
            .unwrap();

        // Wire-equivalent: proposer bytes -> adopter verifies against committed hash.
        let wire = bincode::serialize(&b).unwrap();
        let fetched: Block = bincode::deserialize(&wire).unwrap();
        adopter.put_verified_block(&fetched, &bh).unwrap();
        adopter
            .put_receipts_for_block(21, &bh, &fetched.transactions, &[true], &[1])
            .unwrap();

        let pb = proposer.get_block(&bh).unwrap().unwrap();
        let ab = adopter
            .committed_body(21, &bh)
            .unwrap()
            .expect("adopter holds the body");
        assert_eq!(
            bincode::serialize(&pb).unwrap(),
            bincode::serialize(&ab).unwrap(),
            "byte equality"
        );
        assert_eq!(ab.transactions.len(), 1, "no txs=0 view on the adopter");
        let pr = proposer
            .get_receipt(&tx.compute_tx_hash())
            .unwrap()
            .unwrap();
        let ar = adopter.get_receipt(&tx.compute_tx_hash()).unwrap().unwrap();
        assert_eq!(pr, ar, "identical receipts");
        std::fs::remove_dir_all(&dir_p).ok();
        std::fs::remove_dir_all(&dir_a).ok();
    }

    #[tokio::test]
    async fn load_full_state_into_wires_pq_keys_tree() {
        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let engine = InMemoryStateEngine::new();
        let who = [8u8; 32];
        engine.update_account(AccountState::new(who, 10_000)).await;
        st.put_state(1, &engine.create_snapshot().await).unwrap();
        let snap = DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        st.put_domains(1, &bincode::serialize(&snap).unwrap())
            .unwrap();

        let engine2 = InMemoryStateEngine::new();
        assert!(engine2.pq_tree.read().unwrap().is_none());
        load_full_state_into(&st, &engine2).await.unwrap().unwrap();
        assert!(
            engine2.pq_tree.read().unwrap().is_some(),
            "load_full_state_into must attach pq_keys tree"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn load_full_state_into_hydrates_global_implicit_key_registry() {
        use crate::post_quantum::{derive_pq_address, PqScheme};

        let dir = tmp();
        let st = Storage::open(&dir).unwrap();
        let engine = InMemoryStateEngine::new();

        let scheme = PqScheme::Falcon512;
        let pubkey = crate::sharding::Transaction::sample_falcon512_pubkey(0x9A);
        let salt = [0x55u8; 16];
        let address = derive_pq_address(scheme, &pubkey, &salt);

        // Verify that before loading state, this specific address is not in the registry
        let registry = crate::sharding::global_implicit_key_registry();
        assert!(
            registry.lookup(&address).is_none(),
            "unregistered key must not exist prior to hydration"
        );

        // Store persistent key directly into st.pq_keys
        st.put_pq_key(&address, scheme, &pubkey, &salt).unwrap();
        assert_eq!(st.pq_key_count(), 2); // address and pk_hash entries

        // Setup snapshot so load_full_state_into succeeds
        engine
            .update_account(AccountState::new(address, 100_000))
            .await;
        st.put_state(1, &engine.create_snapshot().await).unwrap();
        let snap = DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        st.put_domains(1, &bincode::serialize(&snap).unwrap())
            .unwrap();

        let engine2 = InMemoryStateEngine::new();
        let (height, _, _) = load_full_state_into(&st, &engine2)
            .await
            .unwrap()
            .expect("state restored");
        assert_eq!(height, 1);

        // Verify that GLOBAL_IMPLICIT_KEY_REGISTRY has been hydrated from storage.pq_keys
        let looked_up = registry.lookup(&address);
        assert_eq!(
            looked_up,
            Some((scheme, pubkey.clone())),
            "load_full_state_into must hydrate GLOBAL_IMPLICIT_KEY_REGISTRY from storage.pq_keys"
        );

        // Verify that engine2 reads the key from the attached pq_keys tree
        assert_eq!(
            engine2.get_pinned_pubkey(&address),
            Some((scheme, pubkey)),
            "attached pq_keys tree must be readable via engine2"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pq_keys_backup_export_and_import() {
        use crate::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};

        let dir1 = tmp();
        let st1 = Storage::open(&dir1).unwrap();
        let scheme = PqScheme::Falcon512;
        let pubkey = crate::sharding::Transaction::sample_falcon512_pubkey(0x4B);
        let address = derive_pq_address(scheme, &pubkey, &DEFAULT_SALT);

        st1.put_pq_key(&address, scheme, &pubkey, &DEFAULT_SALT)
            .unwrap();
        assert_eq!(st1.pq_key_count(), 2);

        let exported = st1.export_pq_keys().unwrap();
        assert_eq!(exported.len(), 2);

        let dir2 = tmp();
        let st2 = Storage::open(&dir2).unwrap();
        assert_eq!(st2.pq_key_count(), 0);

        st2.import_pq_keys(&exported).unwrap();
        assert_eq!(st2.pq_key_count(), 2);
        assert_eq!(st2.get_pq_key(&address).unwrap(), Some((scheme, pubkey)));

        std::fs::remove_dir_all(&dir1).ok();
        std::fs::remove_dir_all(&dir2).ok();
    }
}

#[cfg(test)]
mod archive_proof_tests {
    //! Per-key archive proofs served from the persisted snapshot history.
    use super::*;
    use crate::consensus::{FalconKeypair, QuorumCertificate, ValidatorSet, Vote, VoteKind};
    use crate::sharding::{Block, MASTERCHAIN_SHARD};
    use crate::state_engine::AccountState;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "stell_archive_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ))
    }

    /// FULL-PQ QC (mirrors `consensus::tests::fvote` + `VoteSet::certificate`
    /// idiom): Ed list for membership/power plus Falcon µQC envelope for
    /// crypto — exactly what `QuorumCertificate::verify` requires.
    fn pq_cert_for(
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        parent: [u8; 32],
        vs: &ValidatorSet,
        keys: &[(SigningKey, FalconKeypair)],
    ) -> QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for (sk, fk) in keys {
            let v =
                Vote::sign_with_falcon(sk, fk, height, round, VoteKind::Precommit, Some(block_hash));
            set.add(v, vs, height, round, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some(block_hash), vs, Some(&parent))
            .expect("quorum must compile a Falcon µQC")
    }

    fn test_block(height: u64, prev: [u8; 32], state_root: [u8; 32], signer: &SigningKey) -> Block {
        let order_merkle_root = crate::mev::compute_order_merkle_root(&[]);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: height,
            proposer: signer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(signer);
        b
    }

    /// A finalized two-block chain with a full snapshot at height `H`:
    /// engine state (two funded accounts) + domains + aux domains persisted,
    /// header+QC-anchored at `H + 1`.
    struct Fixture {
        dir: std::path::PathBuf,
        store: Storage,
        height: u64,
        tip: u64,
        root: [u8; 32],
        account_a: [u8; 32],
        missing: [u8; 32],
        validator: SigningKey,
        falcon: FalconKeypair,
    }

    async fn fixture() -> Fixture {
        let dir = tmp();
        let store = Storage::open(&dir).unwrap();
        let validator = SigningKey::generate(&mut OsRng);
        // Deterministic Falcon key per validator id would collide across
        // parallel tests sharing the global PQ registry; generate fresh and
        // register under this fixture's unique Ed id.
        let falcon = FalconKeypair::generate();
        crate::consensus::register_validator_pq_key(
            validator.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            falcon.public_key.clone(),
        );

        let engine = InMemoryStateEngine::new();
        let account_a = [0xA1u8; 32];
        let account_b = [0xB2u8; 32];
        engine
            .update_account(AccountState::new(account_a, 1_000))
            .await;
        engine.update_account(AccountState::new(account_b, 7)).await;
        let root = engine.get_state_root().await;

        let height = 10u64;
        let tip = height + 1;
        store
            .put_state(height, &engine.create_snapshot().await)
            .unwrap();
        let domains = DomainSnapshot::capture(
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

        // Block H (pre-state, arbitrary) and the anchoring block H+1 whose
        // state_root is the post-H root and whose QC authenticates it.
        let b_h = test_block(height, [0u8; 32], [0xAAu8; 32], &validator);
        let h_h = store.put_block(&b_h).unwrap();
        let mut b_next = test_block(tip, h_h, root, &validator);
        let h_next = b_next.compute_hash();
        let vs = ValidatorSet::from_list(vec![(validator.verifying_key().to_bytes(), 1)]);
        b_next.precommit_qc = Some(pq_cert_for(
            tip,
            0,
            h_next,
            h_h,
            &vs,
            &[(validator.clone(), falcon.clone())],
        ));
        store.put_block(&b_next).unwrap();
        store.set_finalized(tip, &h_next).unwrap();

        Fixture {
            dir,
            store,
            height,
            tip,
            root,
            account_a,
            missing: [0xEEu8; 32],
            validator,
            falcon,
        }
    }

    #[test]
    fn archive_slot_keys_match_the_live_trie_derivations() {
        // The slot model must name the SAME keys the live trie commits, or an
        // archive proof would be about a key the chain never wrote.
        let addr = [0x11u8; 32];
        let token = [0x22u8; 32];
        assert_eq!(archive_slot_key(&ArchiveSlot::Account(addr)), addr);
        assert_eq!(
            archive_slot_key(&ArchiveSlot::TokenBalance {
                token_id: token,
                account: addr
            }),
            crate::state_engine::token_balance_key(&token, &addr)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::TokenSupply(token)),
            crate::state_engine::token_supply_key(&token)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::ContractCode(addr)),
            crate::state_engine::contract_key(&addr)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::ContractAbi(addr)),
            crate::state_engine::contract_abi_key(&addr)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::CommitmentDigest),
            crate::commitment::commitment_key()
        );
    }

    #[tokio::test]
    async fn archive_proof_served_from_snapshot_verifies_after_restart() {
        let f = fixture().await;
        // "Restart": drop everything but the directory, reopen the store.
        let dir = f.dir.clone();
        let (height, tip, root, account_a) = (f.height, f.tip, f.root, f.account_a);
        drop(f);
        // GUARD policy: restart-reopen is timing-sensitive under full-parallel
        // `cargo test` (sled lock file may linger briefly after drop on loaded
        // CI hosts). Retry the reopen with backoff instead of asserting on the
        // first WouldBlock; this pins test-only flakiness, not storage logic.
        let mut store = None;
        for _ in 0..20 {
            match Storage::open(&dir) {
                Ok(s) => {
                    store = Some(s);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
        let store = store.expect("storage must reopen after restart (retried 2s)");

        let proof = store
            .serve_archive_proof(height, &account_a, tip)
            .await
            .unwrap();
        assert_eq!(proof.height, height);
        assert_eq!(proof.state_root, root);
        assert!(
            proof.verify(),
            "archive proof must verify against the historical root"
        );
        // The proven leaf carries the account that was snapshotted.
        let value = proof.value.expect("inclusion proof carries the value");
        assert!(value.len() >= 16);
        assert_eq!(u64::from_be_bytes(value[0..8].try_into().unwrap()), 1_000);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn archive_exclusion_proof_verifies_for_a_key_absent_at_that_height() {
        let f = fixture().await;
        let proof = f
            .store
            .serve_archive_proof(f.height, &f.missing, f.tip)
            .await
            .unwrap();
        assert_eq!(proof.proof_type, crate::cpat2::ArchiveProofType::Exclusion);
        assert_eq!(proof.value, None);
        assert_eq!(proof.state_root, f.root);
        assert!(
            proof.verify(),
            "exclusion proof must verify against the historical root"
        );
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[tokio::test]
    async fn archive_proof_for_a_pruned_height_is_refused_not_fabricated() {
        let f = fixture().await;
        // Age the chain: a snapshot at a later height, then prune below it.
        // (Pruning never drops the LATEST snapshot, so the prune must have
        // something newer to keep.)
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new([0x77u8; 32], 5))
            .await;
        let later = f.height + 10;
        f.store
            .put_state(later, &engine.create_snapshot().await)
            .unwrap();
        let domains = DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        f.store
            .put_domains(later, &bincode::serialize(&domains).unwrap())
            .unwrap();
        assert!(f.store.prune_state_below(later).unwrap() > 0);
        assert!(f.store.prune_domains_below(later).unwrap() > 0);

        let err = f
            .store
            .serve_archive_proof(f.height, &f.account_a, later)
            .await
            .expect_err("a pruned height must be refused");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("pruned") || msg.contains("no state snapshot"),
            "refusal must say the height is pruned, got: {msg}"
        );
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[tokio::test]
    async fn archive_proofs_fail_closed_above_the_tip_and_at_unknown_heights() {
        let f = fixture().await;
        let err = f
            .store
            .serve_archive_proof(f.tip + 100, &f.account_a, f.tip)
            .await
            .expect_err("above-tip height must be refused");
        assert!(format!("{err:?}").contains("above the tip"));

        // Inside the retained span but never snapshotted (snapshots are
        // periodic, not per height).
        let err = f
            .store
            .serve_archive_proof(f.height + 1, &f.account_a, f.tip)
            .await
            .expect_err("a non-snapshot height must be refused");
        assert!(format!("{err:?}").contains("no snapshot"));

        let err = f
            .store
            .historical_root(f.tip + 100, f.tip)
            .expect_err("historical root above the tip must be refused");
        assert!(format!("{err:?}").contains("above the tip"));
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[test]
    fn historical_root_is_authenticated_by_the_quorum_certificate() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let f = rt.block_on(fixture());
        let record = f.store.historical_root(f.height, f.tip).unwrap();
        assert_eq!(record.height, f.height);
        assert_eq!(record.state_root, f.root);
        assert_eq!(record.anchor_height, f.height + 1);
        assert!(record.finalized);

        // The anchor's QC verifies against the validator set that decided
        // it — this is what makes the root trustworthy, and it is checked
        // client-side against the client's OWN set.
        let val_id = f.validator.verifying_key().to_bytes();
        // Re-pin the Falcon key: the PQ registry is process-global and other
        // parallel tests may have registered other ids (never this id, which
        // is unique per fixture) — this keeps the verify path on this
        // fixture's key.
        crate::consensus::register_validator_pq_key(
            val_id,
            crate::post_quantum::PqScheme::Falcon512,
            f.falcon.public_key.clone(),
        );
        let vset = ValidatorSet::from_list(vec![(val_id, 1)]);
        assert!(
            record.cert.verify(&vset),
            "the anchoring QC must carry a real quorum of the validator set"
        );
        // Bound to the anchor: a QC for another block must not authenticate
        // this root.
        let mut wrong = record.cert.clone();
        wrong.block_hash = Some([0x99u8; 32]);
        assert!(!wrong.verify(&vset));
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[test]
    fn historical_root_without_a_retained_qc_is_refused() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let f = rt.block_on(fixture());
        // Simulate a pruned body: the header record survives body pruning,
        // the body (and hence the QC) does not. A header alone must not
        // authenticate.
        let anchor = f.height + 1;
        let removed = f.store.prune_blocks_below(anchor + 2).unwrap();
        assert!(removed > 0, "the prune must take the anchoring body");
        assert!(
            f.store.header_at(anchor).unwrap().is_some(),
            "the header record survives body pruning"
        );
        let err = f
            .store
            .historical_root(f.height, f.tip)
            .expect_err("a QC-less anchor must be refused");
        assert!(
            format!("{err:?}").contains("quorum certificate"),
            "refusal must name the missing QC, got: {err:?}"
        );
        std::fs::remove_dir_all(&f.dir).ok();
    }
}
