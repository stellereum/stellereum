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
//!   "cnvrf_v3"    : height(8B BE) -> bincode(CnVrfV3EngineSnapshot)
//!   "cnvrf_freeze_inputs": height(8B BE) -> bincode(BTreeMap<u64, ([u8; 32], [u8; 48])>) [additive CN-VRF v3 freeze inputs]
//!   "xshard_headers": b"latest" -> bincode(FinalizedHeaderRegistry snapshot) [durable C1 anchors]
//!   "receipts_v1" : tx_hash (32B) -> bincode(StoredReceipt)   [NEW, additive only]
//!   "receipts_by_height": height(8B BE)+index(4B BE)+tx_hash(32B) -> b"" [NEW, additive only]
//!   "tx_by_addr"  : addr(32B)+!height(8B)+!tx_index(4B) -> tx_hash(32B) [W4 E3, additive]
//!   "events_by_contract": contract(32B)+!height(8B)+!tx_index(4B)+!log_index(4B)
//!                   -> bincode(StoredContractEvent)          [W4 E3, additive]
//!   "receipt_meta_v2": tx_hash(32B) -> bincode(StoredReceiptMetaV2) [W4 E3, additive]
//!   "pq_keys"     : b"a:"+address (32B) -> bincode(scheme, pubkey, salt) / b"h:"+pk_hash (32B) -> pubkey
//!   "headers_v2"  : height(8B BE) -> bincode(BlockHeaderRecordV2) [additive v4 BlockHeader]
//!   "evm_bindings_state": height(8B BE) -> bincode(EvmBindingsSnapshot) [additive root-committed domain]
//!   "evm_bindings": b"e:"||evm(20)->pq(32), b"p:"||pq(32)->evm(20), b"meta:cursor"->u64 BE [never pruned]
//!   "pq_registry" : height(8B BE) -> bincode(PqRegistry) [additive root-committed domain]
//!   "evm_settled_state": height(8B BE) -> bincode(BTreeSet<[u8; 32]>) [additive settled EVM intent nullifier set]
//!   "snap_units"  : unit_hash(32B) -> raw SnapV4 unit/chunk bytes
//!   "snap_manifests": height(8B BE) -> canonical SnapshotManifestV1 bytes
//!   "snap_committed": height(8B BE) -> bincode(SnapCommitMarker)
//!   "snap_staging": height(8B BE)||unit_tag(2B BE)||sub_index(2B BE) -> chunk bytes
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

use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};

pub type BlockHash = [u8; 32];

mod archive;
mod blocks;
mod persistence;
mod retention;
mod safety_store;
mod state;

#[cfg(test)]
mod tests;

pub use archive::{archive_slot_key, ArchiveSlot, HistoricalRoot};
pub use blocks::{
    decode_receipt, events_by_contract_key, events_by_contract_key_parts, receipt_meta_v2_key,
    tx_by_addr_key, tx_by_addr_key_parts, AddressHistoryItem, AddressHistoryPage,
    BlockHeaderRecord, BlockHeaderRecordV2, ContractEventRecord, ContractEventsPage, EventCursor,
    HistoryCursor, HistoryRole, StoredContractEvent, StoredReceipt, StoredReceiptMetaV2,
    EVENTS_BY_CONTRACT_KEY_LEN, RECEIPTS_BY_HEIGHT_READY_META_KEY, RECEIPT_META_V2_KEY_LEN,
    STORAGE_HISTORY_MAX_LIMIT, STORAGE_SCAN_HARD_CAP, TX_BY_ADDR_KEY_LEN,
};
pub use persistence::{
    clone_account_snapshot, persist_drop_consequence, persist_job_label, persist_push_policy,
    serialize_off_tick, wait_for_persist_drain, wait_for_persist_drain_with, AsyncPersistence,
    PersistJob, PersistPushPolicy, ShutdownDrainConfig, ShutdownDrainOutcome,
    PERSIST_BLOCKING_WAIT_MS, PERSIST_QUEUE_CAP, PERSIST_RETRY_PACE_MS, SHUTDOWN_DRAIN_CAP_SECS,
    SHUTDOWN_DRAIN_LOG_EVERY_SECS, SHUTDOWN_DRAIN_POLL_MS, SHUTDOWN_SETTLE_GRACE_SECS,
};
pub use retention::RetentionConfig;
pub use safety_store::{
    schema_decision, SafetyRecord, SafetyRecordIdentity, SafetyRecordStore, SchemaDecision,
    SCHEMA_VERSION,
};
#[cfg(any(test, debug_assertions))]
pub use state::load_state_into;
pub use state::{
    check_validator_set_freshness, check_validator_set_freshness_with_lag, decode_domain_snapshot,
    decode_domain_snapshot_strict, decode_pq_registry, load_full_state_into,
    snapshot_validator_set_strict, validator_set_freshness_max_lag, AppliedParamsLegacy,
    ConsensusCheckpoint, ContractLegacy, ContractRegistryLegacy, DomainSnapshot, DomainSnapshotV1,
    DomainSnapshotV10, DomainSnapshotV2, DomainSnapshotV3, DomainSnapshotV4, DomainSnapshotV5,
    DomainSnapshotV6, DomainSnapshotV7, DomainSnapshotV8, DomainSnapshotV9, GovernanceLegacy,
    SnapCommitMarker, StakingLedgerV4, StakingLedgerV5, StakingLedgerV6, StakingLedgerV7,
    ValidatorStakeV1, VoteWatermark, VoteWatermarkEntry, DOMAIN_SNAPSHOT_STRICT_MAX_BYTES,
    VALIDATOR_SET_FRESHNESS_DEFAULT_LAG,
};

use safety_store::{SAFETY_KEY, SAFETY_TREE};

/// Durable store for blocks, chain metadata and state snapshots.
#[derive(Clone)]
pub struct Storage {
    pub(super) db: sled::Db,
    pub(super) blocks: sled::Tree,
    pub(super) by_height: sled::Tree,
    pub(super) meta: sled::Tree,
    pub(super) state: sled::Tree,
    /// Non-account consensus domains (tokens/contracts/orderbooks/PMM/staking/gov)
    /// keyed by height.
    pub(super) domains: sled::Tree,
    /// Compact per-height header record, kept even when a block body is pruned.
    ///
    /// This is what makes pruning safe rather than merely destructive: the body
    /// is only needed to re-execute a block, while the chain can still be walked
    /// and re-derived from these records alone.
    pub(super) headers: sled::Tree,
    /// Session-key registry snapshots (phase 2), keyed by height and written
    /// with the domain snapshot of the same height.
    pub(super) session_keys: sled::Tree,
    /// Committed bridge domain (`BridgeState`: the source-tx replay set, the
    /// parked withdrawal queue, the rate-limit window and the escrow mirror),
    /// keyed by height and written with the domain snapshot of the same
    /// height. Its own tree for the same reason as `session_keys`: a field on
    /// `DomainSnapshot` would stop every older snapshot from decoding. This is
    /// what makes a restored node still refuse a replayed `source_tx_hash`.
    pub(super) bridge: sled::Tree,
    /// Committed zkML model registry (models + VKs), keyed by height. Own
    /// tree for the same reason: a restart must not un-register models the
    /// chain agreed on, nor move the root.
    pub(super) zkml_models: sled::Tree,
    /// Cross-shard replay state (audit F-I): engine consumed set + runtime
    /// produced/completed/consumed mirrors, keyed by height. Own tree: without
    /// it a restart wiped all four sets and a replayed message passed every
    /// check (target credited twice / bounce refunded twice). COMMITTED into
    /// the digest (`commitment::write_cross_shard_domain`, conditional on
    /// non-emptiness): restoring a different set than the anchor committed
    /// moves the root and is refused, so replay safety comes from the sets
    /// being BOTH consulted AND hashed.
    pub(super) cross_shard: sled::Tree,
    /// CN-VRF v3 subsystem state (`v3_state`, `abort_state`, `epoch_beacons`),
    /// keyed by height and written alongside the domain snapshot. Own tree for
    /// the same reason as `session_keys`/`bridge`/`zkml_models`: `DomainSnapshot`
    /// is frozen, and an absent/empty entry means `CnVrfV3EngineSnapshot::default()`.
    pub(super) cnvrf_v3: sled::Tree,
    /// CN-VRF v3 `H_freeze` boundary inputs (`epoch -> (freeze_block_hash, rolling_mix)`),
    /// keyed by height and written alongside the domain snapshot. Own tree so
    /// `CnVrfV3EngineSnapshot` bincode layout remains 100% backwards-compatible.
    pub(super) cnvrf_freeze_inputs: sled::Tree,
    /// Durable cross-shard finalized-header registry
    /// ([`crate::sharding::FinalizedHeaderRegistry`]): the latest shard heads
    /// plus the bounded `(shard, block_hash) -> post-apply root` anchor window.
    ///
    /// ONE latest-state row (`b"latest"`), not a height-keyed history: the blob
    /// is self-contained and already bounded by `REGISTRY_ANCHOR_WINDOW`, so a
    /// single row both bounds disk and makes hydration one atomic read. Without
    /// this tree every anchor died with the process and a restart made every
    /// cross-shard message produced before it unverifiable.
    pub(super) xshard_headers: sled::Tree,
    /// Execution receipts, keyed by tx hash. NEW tree (additive only): existing
    /// trees are untouched, so pre-existing data directories open unchanged and
    /// simply report no receipts until heights are adopted/replicated.
    pub(super) receipts: sled::Tree,
    /// Tip-ordered receipt index: `height(8B BE) || index(4B BE) || tx_hash(32B)`
    /// -> empty. NEW additive tree. `receipts` is keyed by the (random) tx hash,
    /// so a lexicographic prefix of it is NOT a height window; restart hydration
    /// that capped a `receipts` scan therefore lost the newest receipts once the
    /// store exceeded the cap. This index makes the same cap a genuine
    /// tip-window (`iter().rev()` is `(height, index)`-descending) with no
    /// change to `StoredReceipt` or `receipts_v1` bytes.
    pub(super) receipts_by_height: sled::Tree,
    /// W4 E3 address history index: `addr || !height || !tx_index -> tx_hash`.
    /// Additive tree, tip-first by construction.
    pub(super) tx_by_addr: sled::Tree,
    /// W4 E3 contract event history index:
    /// `contract || !height || !tx_index || !log_index -> bincode(StoredContractEvent)`.
    pub(super) events_by_contract: sled::Tree,
    /// W4 E3 per-transaction metadata (from/to/amount/shard/timestamp) keyed by
    /// tx hash. Separate from the frozen `StoredReceipt` shape.
    pub(super) receipt_meta_v2: sled::Tree,
    /// Post-quantum public keys tree.
    pub pq_keys: sled::Tree,
    /// Two-level v4 block header records (`BlockHeaderRecordV2`), keyed by height.
    pub(super) headers_v2: sled::Tree,
    /// Canonical `Domain::EvmBindings` snapshot tree, keyed by height.
    pub(super) evm_bindings_state: sled::Tree,
    /// Non-consensus crash-safe EVM ↔ PQ bijection index (never pruned).
    pub(super) evm_bindings: sled::Tree,
    /// Canonical `Domain::PqRegistry` snapshot tree, keyed by height.
    pub(super) pq_registry: sled::Tree,
    /// Committed settled EVM carrier intent digests (`STELL_EVM_SETTLED_V1`),
    /// keyed by height.
    pub(super) evm_settled_state: sled::Tree,
    /// W1 SnapV4 content-addressed unit/chunk store (`unit_hash -> bytes`).
    pub(super) snap_units: sled::Tree,
    /// W1 SnapV4 manifests keyed by height (`height_be -> canonical bytes`).
    pub(super) snap_manifests: sled::Tree,
    /// W1 SnapV4 atomic commit markers keyed by height (`height_be -> SnapCommitMarker`).
    pub(super) snap_committed: sled::Tree,
    /// W1 SnapV4 resumable staging chunks (`height || unit_tag || sub_index -> bytes`).
    pub(super) snap_staging: sled::Tree,
    pub(super) safety_failed: Arc<Mutex<bool>>,
}

/// Decode a small self-describing record with the shared per-record byte
/// ceiling, so a corrupt length prefix cannot drive an OOM.
pub(super) fn decode_small_record<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &str,
) -> Result<T> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(crate::state_engine::MAX_SMALL_RECORD_DECODE_BYTES)
        .deserialize(bytes)
        .map_err(|e| anyhow!("{what}: record does not decode within the size limit: {e}"))
}

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
        // Schema guard (see SCHEMA_VERSION). A store written by a newer binary
        // is refused unless the operator opts in: misreading newer keys is worse
        // than refusing to start.
        {
            let stored = meta
                .get("schema_version")?
                .map(|v| {
                    let bytes: [u8; 4] = v.as_ref().try_into().map_err(|_| {
                        anyhow!("store meta schema_version has invalid length {}", v.len())
                    })?;
                    Ok::<u32, anyhow::Error>(u32::from_be_bytes(bytes))
                })
                .transpose()?;
            let allow = std::env::var("STELL_ALLOW_SCHEMA_DOWNGRADE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            match schema_decision(stored, SCHEMA_VERSION, allow) {
                SchemaDecision::Initialize => {
                    meta.insert("schema_version", &SCHEMA_VERSION.to_be_bytes())?;
                    meta.flush()?;
                }
                SchemaDecision::Accept => {
                    if let Some(v) = stored {
                        if v < SCHEMA_VERSION {
                            tracing::warn!(
                                stored = v,
                                current = SCHEMA_VERSION,
                                "[storage] store schema is older than this binary; older keys are read as-is"
                            );
                        }
                    }
                }
                SchemaDecision::DowngradeBlocked => {
                    return Err(anyhow!(
                        "store schema version {} is NEWER than this binary ({}); refusing to start. \
                         Run the newer binary, or set STELL_ALLOW_SCHEMA_DOWNGRADE=1 only if you \
                         knowingly downgrade (newer keys may be misread).",
                        stored.unwrap_or(0),
                        SCHEMA_VERSION
                    ));
                }
            }
        }
        let state = db.open_tree("state")?;
        let domains = db.open_tree("domains")?;
        let headers = db.open_tree("headers")?;
        let session_keys = db.open_tree("session_keys")?;
        let bridge = db.open_tree("bridge")?;
        let zkml_models = db.open_tree("zkml_models")?;
        let cross_shard = db.open_tree("cross_shard")?;
        let cnvrf_v3 = db.open_tree("cnvrf_v3")?;
        let cnvrf_freeze_inputs = db.open_tree("cnvrf_freeze_inputs")?;
        let xshard_headers = db.open_tree("xshard_headers")?;
        let receipts = db.open_tree("receipts_v1")?;
        let receipts_by_height = db.open_tree("receipts_by_height")?;
        let tx_by_addr = db.open_tree("tx_by_addr")?;
        let events_by_contract = db.open_tree("events_by_contract")?;
        let receipt_meta_v2 = db.open_tree("receipt_meta_v2")?;
        let pq_keys = db.open_tree("pq_keys")?;
        let headers_v2 = db.open_tree("headers_v2")?;
        let evm_bindings_state = db.open_tree("evm_bindings_state")?;
        let evm_bindings = db.open_tree("evm_bindings")?;
        let pq_registry = db.open_tree("pq_registry")?;
        let evm_settled_state = db.open_tree("evm_settled_state")?;
        let snap_units = db.open_tree("snap_units")?;
        let snap_manifests = db.open_tree("snap_manifests")?;
        let snap_committed = db.open_tree("snap_committed")?;
        let snap_staging = db.open_tree("snap_staging")?;
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
            cnvrf_v3,
            cnvrf_freeze_inputs,
            xshard_headers,
            receipts,
            receipts_by_height,
            tx_by_addr,
            events_by_contract,
            receipt_meta_v2,
            pq_keys,
            headers_v2,
            evm_bindings_state,
            evm_bindings,
            pq_registry,
            evm_settled_state,
            snap_units,
            snap_manifests,
            snap_committed,
            snap_staging,
            safety_failed: Arc::new(Mutex::new(false)),
        };
        let swept = this.sweep_dangling_indexes().unwrap_or(0);
        if swept > 0 {
            eprintln!(
                "[storage] open: swept {swept} dangling by_height index entries (crash debris)"
            );
        }
        // Derived, additive index: a failure here must not brick the store. The
        // marker stays unset, so `latest_receipts_capped` keeps using the
        // legacy tx-hash scan (the pre-fix behaviour) until a later open
        // completes the backfill.
        if let Err(e) = this.ensure_receipt_height_index() {
            tracing::warn!("[storage] receipt height index unavailable: {e}");
            eprintln!("[storage] receipt height index unavailable (using legacy scan): {e}");
        }
        Ok(this)
    }

    /// Open the isolated safety record for the expected validator/chain/shard.
    /// Fails closed immediately if any prior safety read/write/flush error
    /// poisoned this `Storage` instance.
    /// Operator recovery for a safety record that can no longer be decoded
    /// (`safety store requires recovery`): delete `safety_record_v1` so
    /// [`Self::safety_record_store`] loads `None` and `stellereum safety-init`
    /// can write generation 1 again.
    ///
    /// OFFLINE ONLY. The caller must have stopped and fenced the node, every
    /// legacy process and every remote signer for the key: the record carries
    /// the durable prevote/precommit watermarks, and losing them while a signer
    /// is still live could allow a double vote. Returns whether a record was
    /// present.
    pub fn reset_safety_record_for_recovery(&self) -> Result<bool> {
        let tree = self.db.open_tree(SAFETY_TREE)?;
        let removed = tree.remove(SAFETY_KEY)?.is_some();
        tree.flush()?;
        self.db.flush()?;
        Ok(removed)
    }

    pub fn safety_record_store(&self, identity: SafetyRecordIdentity) -> Result<SafetyRecordStore> {
        let mut failed = self
            .safety_failed
            .lock()
            .map_err(|_| anyhow!("safety lock poisoned"))?;
        if *failed {
            return Err(anyhow!("safety store requires recovery"));
        }
        let tree = match self.db.open_tree(SAFETY_TREE) {
            Ok(tree) => tree,
            Err(error) => {
                *failed = true;
                return Err(error.into());
            }
        };
        Ok(SafetyRecordStore {
            db: self.db.clone(),
            tree,
            identity,
            failed: self.safety_failed.clone(),
        })
    }

    /// True when `headers` or `by_height` contains any entry at `height > 0`.
    /// Used by the clean-genesis safety-record auto-initialization gate.
    pub fn has_non_genesis_blocks_or_headers(&self) -> Result<bool> {
        for kv in self.headers.iter() {
            let (k, _) = kv?;
            if k.len() != 8 {
                return Ok(true);
            }
            let h = u64::from_be_bytes(k.as_ref().try_into()?);
            if h > 0 {
                return Ok(true);
            }
        }
        for kv in self.by_height.iter() {
            let (k, _) = kv?;
            if k.len() < 8 {
                return Ok(true);
            }
            let h = u64::from_be_bytes(k[..8].try_into()?);
            if h > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[doc(hidden)]
    pub fn safety_record_tree_for_test(&self) -> sled::Result<sled::Tree> {
        self.db.open_tree(SAFETY_TREE)
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
