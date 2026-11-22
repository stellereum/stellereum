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

use crate::sharding::{Block, FinalizedHeaderRegistry, FinalizedHeaderSink};
use crate::state_engine::InMemoryStateEngine;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sled::transaction::Transactional;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type BlockHash = [u8; 32];

/// Identity of the single safety-record owner of a storage directory.
/// `chain` must be a stable, collision-resistant chain identifier (for example
/// the genesis hash), not an operator-selected display name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyRecordIdentity {
    pub validator: [u8; 32],
    pub chain: [u8; 32],
    pub shard: u32,
}

/// Opaque application state: this primitive does not validate consensus rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyRecord {
    pub identity: SafetyRecordIdentity,
    pub generation: u64,
    pub payload: Vec<u8>,
}

const SAFETY_TREE: &str = "safety_record_v1";
const SAFETY_KEY: &[u8] = b"record";
const SAFETY_MAGIC: &[u8; 8] = b"STSAFETY";
const SAFETY_VERSION: u16 = 1;
const SAFETY_MAX_PAYLOAD: usize = 1024 * 1024;
const SAFETY_HEADER: usize = 8 + 2 + 32 + 32 + 4 + 8 + 4;
const SAFETY_HASH: usize = 32;

impl SafetyRecord {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.generation == 0 || self.payload.len() > SAFETY_MAX_PAYLOAD {
            return Err(anyhow!(
                "invalid safety record generation or payload length"
            ));
        }
        let mut bytes = Vec::with_capacity(SAFETY_HEADER + self.payload.len() + SAFETY_HASH);
        bytes.extend_from_slice(SAFETY_MAGIC);
        bytes.extend_from_slice(&SAFETY_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.identity.validator);
        bytes.extend_from_slice(&self.identity.chain);
        bytes.extend_from_slice(&self.identity.shard.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        let hash = blake3::hash(&bytes);
        bytes.extend_from_slice(hash.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8], identity: &SafetyRecordIdentity) -> Result<Self> {
        if bytes.len() < SAFETY_HEADER + SAFETY_HASH
            || &bytes[..8] != SAFETY_MAGIC
            || u16::from_be_bytes(bytes[8..10].try_into()?) != SAFETY_VERSION
        {
            return Err(anyhow!("invalid or unsupported safety record"));
        }
        let payload_len = u32::from_be_bytes(bytes[86..90].try_into()?) as usize;
        if payload_len > SAFETY_MAX_PAYLOAD
            || bytes.len() != SAFETY_HEADER + payload_len + SAFETY_HASH
        {
            return Err(anyhow!("invalid safety record length"));
        }
        let hash_offset = SAFETY_HEADER + payload_len;
        if blake3::hash(&bytes[..hash_offset]).as_bytes() != &bytes[hash_offset..] {
            return Err(anyhow!("safety record checksum mismatch"));
        }
        let stored_identity = SafetyRecordIdentity {
            validator: bytes[10..42].try_into()?,
            chain: bytes[42..74].try_into()?,
            shard: u32::from_be_bytes(bytes[74..78].try_into()?),
        };
        let generation = u64::from_be_bytes(bytes[78..86].try_into()?);
        if &stored_identity != identity || generation == 0 {
            return Err(anyhow!("safety record identity or generation mismatch"));
        }
        Ok(Self {
            identity: stored_identity,
            generation,
            payload: bytes[SAFETY_HEADER..hash_offset].to_vec(),
        })
    }
}

/// Isolated single-record storage primitive, not connected to consensus or a
/// signer. Calls through clones of the same `Storage` serialize read, update,
/// and flush. sled's exclusive database lock is required; raw tree writes or
/// other access bypassing this API invalidate its guarantees.
///
/// A successful update means sled's synchronous flush completed. This relies
/// on sled, the filesystem and hardware honoring their durability contracts;
/// provisioning and syncing the database directory and its ancestors is the
/// operator's responsibility. A failed write/flush is indeterminate: callers
/// must halt, not sign, and recover explicitly. Read, decode, identity, write,
/// flush, and tree-open errors quarantine all handles sharing this `Storage`
/// until it is dropped and explicitly recovered. Reopening alone is not proof
/// of recovery. Neither a checksum nor a local generation counter detects
/// deletion, a restored old directory, a cloned directory, or malicious
/// rewriting. Absence must not be interpreted as permission to initialize a
/// previously used validator. This is not a migration or anti-rollback scheme.
/// Decoding bounds the payload before copying it, but sled materializes the
/// whole stored value in `get` first; this API cannot bound that allocation
/// when the database has been corrupted or modified outside this API.
#[derive(Clone)]
pub struct SafetyRecordStore {
    db: sled::Db,
    tree: sled::Tree,
    identity: SafetyRecordIdentity,
    failed: Arc<Mutex<bool>>,
}

impl SafetyRecordStore {
    /// Read and validate the current record. `None` is ambiguous: it may also
    /// mean lost or deleted state, not a safe fresh validator.
    pub fn load(&self) -> Result<Option<SafetyRecord>> {
        self.load_with_read(|| self.tree.get(SAFETY_KEY))
    }

    fn load_with_read(
        &self,
        read: impl FnOnce() -> sled::Result<Option<sled::IVec>>,
    ) -> Result<Option<SafetyRecord>> {
        let mut failed = self
            .failed
            .lock()
            .map_err(|_| anyhow!("safety lock poisoned"))?;
        if *failed {
            return Err(anyhow!("safety store requires recovery"));
        }
        self.read_current(&mut failed, read)
    }

    fn read_current(
        &self,
        failed: &mut bool,
        read: impl FnOnce() -> sled::Result<Option<sled::IVec>>,
    ) -> Result<Option<SafetyRecord>> {
        let result = read().map_err(anyhow::Error::from).and_then(|current| {
            current
                .map(|bytes| SafetyRecord::decode(&bytes, &self.identity))
                .transpose()
        });
        if result.is_err() {
            *failed = true;
        }
        result
    }

    /// Atomically replace exactly the expected generation and flush before
    /// returning success. `None` initializes generation 1; subsequent writes
    /// must supply the observed generation and advance it exactly once.
    /// Never retry an indeterminate I/O error as though no write occurred.
    pub fn persist(&self, expected: Option<u64>, payload: Vec<u8>) -> Result<SafetyRecord> {
        self.persist_with_flush(expected, payload, || self.db.flush().map(|_| ()))
    }

    fn persist_with_flush(
        &self,
        expected: Option<u64>,
        payload: Vec<u8>,
        flush: impl FnOnce() -> sled::Result<()>,
    ) -> Result<SafetyRecord> {
        self.persist_with_read_and_flush(expected, payload, || self.tree.get(SAFETY_KEY), flush)
    }

    fn persist_with_read_and_flush(
        &self,
        expected: Option<u64>,
        payload: Vec<u8>,
        read: impl FnOnce() -> sled::Result<Option<sled::IVec>>,
        flush: impl FnOnce() -> sled::Result<()>,
    ) -> Result<SafetyRecord> {
        let mut failed = self
            .failed
            .lock()
            .map_err(|_| anyhow!("safety lock poisoned"))?;
        if *failed {
            return Err(anyhow!("safety store requires recovery"));
        }
        let actual = self
            .read_current(&mut failed, read)?
            .map(|record| record.generation);
        if actual != expected {
            return Err(anyhow!("stale safety record generation"));
        }
        let generation = match actual {
            Some(n) => n
                .checked_add(1)
                .ok_or_else(|| anyhow!("safety generation exhausted"))?,
            None => 1,
        };
        let record = SafetyRecord {
            identity: self.identity.clone(),
            generation,
            payload,
        };
        let bytes = record.encode()?;
        if let Err(error) = self.tree.insert(SAFETY_KEY, bytes) {
            *failed = true;
            return Err(error.into());
        }
        if let Err(error) = flush() {
            *failed = true;
            return Err(error.into());
        }
        Ok(record)
    }
}

#[cfg(test)]
mod safety_record_unit_tests {
    use super::*;

    #[test]
    fn read_errors_quarantine_all_handles_without_false_success() {
        for fail_load in [true, false] {
            let dir = std::env::temp_dir().join(format!(
                "stell-safety-read-{}-{}-{}",
                std::process::id(),
                fail_load,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            assert!(!dir.exists());
            let storage = Storage::open(&dir).unwrap();
            let identity = SafetyRecordIdentity {
                validator: [1; 32],
                chain: [2; 32],
                shard: 3,
            };
            let first = storage.safety_record_store(identity.clone()).unwrap();
            let second = storage
                .clone()
                .safety_record_store(identity.clone())
                .unwrap();
            first.persist(None, vec![1]).unwrap();
            let read = || Err(sled::Error::Unsupported("injected read error".into()));
            if fail_load {
                assert!(first.load_with_read(read).is_err());
            } else {
                assert!(first
                    .persist_with_read_and_flush(Some(1), vec![2], read, || {
                        panic!("flush must not run after a read error")
                    })
                    .is_err());
            }
            for handle in [&first, &second] {
                assert!(handle
                    .load()
                    .unwrap_err()
                    .to_string()
                    .contains("requires recovery"));
                assert!(handle
                    .persist(Some(1), vec![3])
                    .unwrap_err()
                    .to_string()
                    .contains("requires recovery"));
            }
            assert!(storage
                .safety_record_store(identity)
                .err()
                .expect("poisoned storage must refuse new safety handle")
                .to_string()
                .contains("requires recovery"));
            assert_eq!(
                SafetyRecord::decode(
                    &first.tree.get(SAFETY_KEY).unwrap().unwrap(),
                    &first.identity
                )
                .unwrap()
                .payload,
                vec![1]
            );
            drop(first);
            drop(second);
            drop(storage);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn decode_failure_remains_quarantined_even_if_bytes_are_repaired() {
        let dir = std::env::temp_dir().join(format!(
            "stell-safety-decode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let storage = Storage::open(&dir).unwrap();
        let identity = SafetyRecordIdentity {
            validator: [1; 32],
            chain: [2; 32],
            shard: 3,
        };
        let first = storage.safety_record_store(identity.clone()).unwrap();
        let second = storage.clone().safety_record_store(identity).unwrap();
        first.persist(None, vec![1]).unwrap();
        let original = first.tree.get(SAFETY_KEY).unwrap().unwrap();
        first.tree.insert(SAFETY_KEY, &[0u8][..]).unwrap();
        assert!(first.persist(Some(1), vec![2]).is_err());
        first.tree.insert(SAFETY_KEY, original).unwrap();
        assert!(second
            .load()
            .unwrap_err()
            .to_string()
            .contains("requires recovery"));
        assert!(second
            .persist(Some(1), vec![2])
            .unwrap_err()
            .to_string()
            .contains("requires recovery"));
        drop(first);
        drop(second);
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_flush_result_poison_is_shared_by_all_handles() {
        let dir = std::env::temp_dir().join(format!(
            "stell-safety-flush-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let storage = Storage::open(&dir).unwrap();
        let identity = SafetyRecordIdentity {
            validator: [1; 32],
            chain: [2; 32],
            shard: 3,
        };
        let first = storage.safety_record_store(identity.clone()).unwrap();
        let second = storage
            .clone()
            .safety_record_store(identity.clone())
            .unwrap();
        first.persist(None, vec![1]).unwrap();
        let error = first.persist_with_flush(Some(1), vec![2], || {
            let bytes = first.tree.get(SAFETY_KEY).unwrap().unwrap();
            let record = SafetyRecord::decode(&bytes, &identity).unwrap();
            assert_eq!(record.generation, 2);
            assert_eq!(record.payload, vec![2]);
            Err(sled::Error::Unsupported(
                "injected unknown flush outcome".into(),
            ))
        });
        assert!(error.is_err());
        for handle in [first, second] {
            assert!(handle
                .load()
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
            assert!(handle
                .persist(Some(2), vec![3])
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
        }
        assert!(storage
            .safety_record_store(identity)
            .err()
            .expect("poisoned storage must refuse new safety handle")
            .to_string()
            .contains("requires recovery"));
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn error_after_successful_flush_is_fail_closed_for_all_handles() {
        let dir = std::env::temp_dir().join(format!(
            "stell-safety-post-flush-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let storage = Storage::open(&dir).unwrap();
        let identity = SafetyRecordIdentity {
            validator: [1; 32],
            chain: [2; 32],
            shard: 3,
        };
        let first = storage.safety_record_store(identity.clone()).unwrap();
        let second = storage
            .clone()
            .safety_record_store(identity.clone())
            .unwrap();
        first.persist(None, vec![1]).unwrap();
        let result = first.persist_with_flush(Some(1), vec![2], || {
            let bytes = first.tree.get(SAFETY_KEY).unwrap().unwrap();
            let record = SafetyRecord::decode(&bytes, &identity).unwrap();
            assert_eq!(record.generation, 2);
            assert_eq!(record.payload, vec![2]);
            first.db.flush()?;
            Err(sled::Error::Unsupported(
                "injected error after successful flush".into(),
            ))
        });
        assert!(result.is_err());
        for handle in [first, second] {
            assert!(handle
                .load()
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
            assert!(handle
                .persist(Some(2), vec![3])
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
        }
        assert!(storage
            .safety_record_store(identity)
            .err()
            .expect("poisoned storage must refuse new safety handle")
            .to_string()
            .contains("requires recovery"));
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

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
    /// CN-VRF v3 subsystem state (`v3_state`, `abort_state`, `epoch_beacons`),
    /// keyed by height and written alongside the domain snapshot. Own tree for
    /// the same reason as `session_keys`/`bridge`/`zkml_models`: `DomainSnapshot`
    /// is frozen, and an absent/empty entry means `CnVrfV3EngineSnapshot::default()`.
    cnvrf_v3: sled::Tree,
    /// Durable cross-shard finalized-header registry
    /// ([`crate::sharding::FinalizedHeaderRegistry`]): the latest shard heads
    /// plus the bounded `(shard, block_hash) -> post-apply root` anchor window.
    ///
    /// ONE latest-state row (`b"latest"`), not a height-keyed history: the blob
    /// is self-contained and already bounded by `REGISTRY_ANCHOR_WINDOW`, so a
    /// single row both bounds disk and makes hydration one atomic read. Without
    /// this tree every anchor died with the process and a restart made every
    /// cross-shard message produced before it unverifiable.
    xshard_headers: sled::Tree,
    /// Execution receipts, keyed by tx hash. NEW tree (additive only): existing
    /// trees are untouched, so pre-existing data directories open unchanged and
    /// simply report no receipts until heights are adopted/replicated.
    receipts: sled::Tree,
    /// Tip-ordered receipt index: `height(8B BE) || index(4B BE) || tx_hash(32B)`
    /// -> empty. NEW additive tree. `receipts` is keyed by the (random) tx hash,
    /// so a lexicographic prefix of it is NOT a height window; restart hydration
    /// that capped a `receipts` scan therefore lost the newest receipts once the
    /// store exceeded the cap. This index makes the same cap a genuine
    /// tip-window (`iter().rev()` is `(height, index)`-descending) with no
    /// change to `StoredReceipt` or `receipts_v1` bytes.
    receipts_by_height: sled::Tree,
    /// W4 E3 address history index: `addr || !height || !tx_index -> tx_hash`.
    /// Additive tree, tip-first by construction.
    tx_by_addr: sled::Tree,
    /// W4 E3 contract event history index:
    /// `contract || !height || !tx_index || !log_index -> bincode(StoredContractEvent)`.
    events_by_contract: sled::Tree,
    /// W4 E3 per-transaction metadata (from/to/amount/shard/timestamp) keyed by
    /// tx hash. Separate from the frozen `StoredReceipt` shape.
    receipt_meta_v2: sled::Tree,
    /// Post-quantum public keys tree.
    pub pq_keys: sled::Tree,
    /// Two-level v4 block header records (`BlockHeaderRecordV2`), keyed by height.
    headers_v2: sled::Tree,
    /// Canonical `Domain::EvmBindings` snapshot tree, keyed by height.
    evm_bindings_state: sled::Tree,
    /// Non-consensus crash-safe EVM ↔ PQ bijection index (never pruned).
    evm_bindings: sled::Tree,
    /// Canonical `Domain::PqRegistry` snapshot tree, keyed by height.
    pq_registry: sled::Tree,
    /// W1 SnapV4 content-addressed unit/chunk store (`unit_hash -> bytes`).
    snap_units: sled::Tree,
    /// W1 SnapV4 manifests keyed by height (`height_be -> canonical bytes`).
    snap_manifests: sled::Tree,
    /// W1 SnapV4 atomic commit markers keyed by height (`height_be -> SnapCommitMarker`).
    snap_committed: sled::Tree,
    /// W1 SnapV4 resumable staging chunks (`height || unit_tag || sub_index -> bytes`).
    snap_staging: sled::Tree,
    safety_failed: Arc<Mutex<bool>>,
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

/// Additive v4 header record carrying the full [`crate::sharding::BlockHeader`]
/// (including `shard_id`, `round`, `body_commitment`, `mmr_epoch_root`, and
/// `epoch_key_commitment`). Kept in its own `"headers_v2"` tree so the frozen
/// `BlockHeaderRecord` bincode schema remains untouched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderRecordV2 {
    pub header: crate::sharding::BlockHeader,
    pub tx_count: u32,
    pub gas_used: u64,
    pub block_hash: BlockHash,
}

impl BlockHeaderRecordV2 {
    pub fn of(b: &Block) -> Self {
        let gas_used: u64 = b.transactions.iter().map(|t| t.gas_limit).sum();
        Self {
            header: b.header(),
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
    /// Anchoring block's shard id (v4 header commitment).
    #[serde(default)]
    pub anchor_shard_id: u32,
    /// Anchoring block's round (v4 header commitment).
    #[serde(default)]
    pub anchor_round: u32,
    /// Anchoring block's body commitment (`Some` at `anchor_height >= H`, `None` below `H`).
    #[serde(default)]
    pub anchor_body_commitment: Option<[u8; 32]>,
    /// Anchoring block's MMR epoch root (v4 header commitment).
    #[serde(default)]
    pub anchor_mmr_epoch_root: [u8; 32],
    /// Anchoring block's epoch key commitment (v4 header commitment).
    #[serde(default)]
    pub anchor_epoch_key_commitment: [u8; 32],
    /// Anchoring block's timestamp (v4 header commitment).
    #[serde(default)]
    pub anchor_timestamp: u64,
    /// Anchoring block's proposer (v4 header commitment).
    #[serde(default)]
    pub anchor_proposer: [u8; 32],
}

/// Atomic commit marker for W1 `SnapV4` checkpoints in `"snap_committed"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapCommitMarker {
    pub height: u64,
    pub state_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub is_base: bool,
    pub base_height: Option<u64>,
}

/// Maximum blocks removed by one prune job.
///
/// The flusher task is a single writer, so a prune that scanned a multi-gigabyte
/// tree inline would stall every other write behind it. Work is bounded per job
/// and the next prune is scheduled from the regular snapshot cadence instead.
const PRUNE_BATCH: usize = 20_000;

/// Meta key marking the `receipts_by_height` index as COMPLETE for this store.
///
/// Absent means the index cannot be trusted (pre-upgrade directory, or a
/// backfill that was interrupted): readers then fall back to the legacy
/// `receipts` scan and keep their pre-fix behaviour instead of silently
/// serving a partial window. `Storage::open` sets it after a full backfill.
pub const RECEIPTS_BY_HEIGHT_READY_META_KEY: &str = "receipts_by_height_v1";

/// Fixed width of one `receipts_by_height` key:
/// `height(8B BE) || index(4B BE) || tx_hash(32B)`.
const RECEIPT_INDEX_KEY_LEN: usize = 44;

/// Rows applied per backfill batch: bounds the write burst on first open of an
/// existing multi-million-receipt directory.
const RECEIPT_INDEX_BACKFILL_BATCH: usize = 10_000;

/// Tip-ordered receipt index key. The tx hash is part of the key so a reverse
/// slice of the tree yields the newest `(height, index)` rows directly.
fn receipt_index_key(r: &StoredReceipt) -> [u8; RECEIPT_INDEX_KEY_LEN] {
    let mut key = [0u8; RECEIPT_INDEX_KEY_LEN];
    key[0..8].copy_from_slice(&r.height.to_be_bytes());
    key[8..12].copy_from_slice(&r.index.to_be_bytes());
    key[12..RECEIPT_INDEX_KEY_LEN].copy_from_slice(&r.tx_hash);
    key
}

// ===========================================================================
// W4 E3 — SECONDARY HISTORY INDEXES (additive, read-only consumers)
//
// Three NEW trees, keyed so a plain ascending iteration is TIP-FIRST
// (`!height` in the key inverts the numeric order). Existing `data/`
// directories open unchanged: `Storage::open` creates the trees empty and a
// missing row simply means "not indexed yet". `prune_receipts_below` drops
// rows below the same retention window as the receipts, so a pruning node
// does not grow a second forever-tree.
// ===========================================================================

/// Hard per-request cap for the history reads (`stell_getAddressHistory`,
/// `stell_getEvents` pagination).
pub const STORAGE_HISTORY_MAX_LIMIT: usize = 200;

/// Maximum number of index keys INSPECTED by one history read, including rows
/// filtered out by `role` / height window / topic. Bounds CPU on an
/// unauthenticated read; when it is hit the page says so and returns a
/// continuation cursor.
pub const STORAGE_SCAN_HARD_CAP: usize = 10_000;

/// Fixed width of one `tx_by_addr` key: `addr(32) || !height(8) || !tx_index(4)`.
pub const TX_BY_ADDR_KEY_LEN: usize = 44;
/// Fixed width of one `events_by_contract` key:
/// `contract(32) || !height(8) || !tx_index(4) || !log_index(4)`.
pub const EVENTS_BY_CONTRACT_KEY_LEN: usize = 48;
/// Fixed width of one `receipt_meta_v2` key (`tx_hash(32)`).
pub const RECEIPT_META_V2_KEY_LEN: usize = 32;

/// Which side of a transaction an address-history query is interested in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryRole {
    /// Sender, recipient or sponsor of the transaction.
    All,
    /// `tx.from == address` only.
    Sender,
    /// `tx.to == address` only.
    Recipient,
}

impl HistoryRole {
    /// Parse the RPC spelling (`"all" | "sender" | "recipient"`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "sender" => Some(Self::Sender),
            "recipient" => Some(Self::Recipient),
            _ => None,
        }
    }
}

/// Keyset cursor for `tx_by_addr` / `stell_getAddressHistory`:
/// `(height, tx_index)` of the last row already served. The next page resumes
/// STRICTLY older than this position, so no row is duplicated or skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HistoryCursor {
    pub height: u64,
    pub tx_index: u32,
}

impl HistoryCursor {
    /// Wire form: 12 bytes `height(8 BE) || tx_index(4 BE)`.
    pub fn encode(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..8].copy_from_slice(&self.height.to_be_bytes());
        out[8..12].copy_from_slice(&self.tx_index.to_be_bytes());
        out
    }

    /// Decode the 12-byte wire form; `None` on a wrong length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 12 {
            return None;
        }
        Some(Self {
            height: u64::from_be_bytes(bytes[0..8].try_into().ok()?),
            tx_index: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
        })
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.encode())
    }

    /// Accepts the 24-hex-character wire form with or without `0x`.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        Self::decode(&hex::decode(s).ok()?)
    }
}

/// Keyset cursor for `events_by_contract` / paginated `stell_getEvents`:
/// `(height, tx_index, log_index)` of the last row already served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventCursor {
    pub height: u64,
    pub tx_index: u32,
    pub log_index: u32,
}

impl EventCursor {
    /// Wire form: 16 bytes
    /// `height(8 BE) || tx_index(4 BE) || log_index(4 BE)`.
    pub fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.height.to_be_bytes());
        out[8..12].copy_from_slice(&self.tx_index.to_be_bytes());
        out[12..16].copy_from_slice(&self.log_index.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        Some(Self {
            height: u64::from_be_bytes(bytes[0..8].try_into().ok()?),
            tx_index: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
            log_index: u32::from_be_bytes(bytes[12..16].try_into().ok()?),
        })
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.encode())
    }

    /// Accepts the 32-hex-character wire form with or without `0x`.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        Self::decode(&hex::decode(s).ok()?)
    }
}

/// Self-contained value of one `events_by_contract` row.
///
/// The contract, height, tx index and log index live in the KEY, so the value
/// only has to carry the transaction identity and the event payload. Decoding
/// is bounded by [`crate::state_engine::MAX_SMALL_RECORD_DECODE_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredContractEvent {
    pub tx_hash: [u8; 32],
    pub topic: i64,
    pub value: i64,
}

/// Per-transaction metadata the address history needs but `StoredReceipt`
/// (frozen) does not carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReceiptMetaV2 {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub shard_id: u32,
    pub timestamp: u64,
}

/// One address-history row. `meta` is `None` only for an index row whose
/// metadata row is missing (crash window / pre-index data): the transaction
/// hash and inclusion position are still real, the participant fields are
/// honestly absent instead of fabricated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressHistoryItem {
    pub tx_hash: [u8; 32],
    pub height: u64,
    pub tx_index: u32,
    pub meta: Option<StoredReceiptMetaV2>,
}

/// Bounded page of [`Storage::address_history`], tip-first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressHistoryPage {
    pub items: Vec<AddressHistoryItem>,
    pub next_cursor: Option<HistoryCursor>,
    pub has_more: bool,
    pub scanned: usize,
    pub scan_truncated: bool,
}

/// One contract event as read from `events_by_contract`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractEventRecord {
    pub contract: [u8; 32],
    pub tx_hash: [u8; 32],
    pub height: u64,
    pub tx_index: u32,
    pub log_index: u32,
    pub topic: i64,
    pub value: i64,
}

/// Bounded page of [`Storage::events_by_contract_range`], tip-first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractEventsPage {
    pub items: Vec<ContractEventRecord>,
    pub next_cursor: Option<EventCursor>,
    pub has_more: bool,
    pub scanned: usize,
    pub scan_truncated: bool,
}

/// `tx_by_addr` key: `addr || !height || !tx_index` (44 bytes).
///
/// The bitwise-not height/index make lexicographic order equal to
/// `(height DESC, tx_index DESC)`, so `iter()` is a tip-first range scan.
pub fn tx_by_addr_key(addr: &[u8; 32], height: u64, tx_index: u32) -> [u8; TX_BY_ADDR_KEY_LEN] {
    let mut key = [0u8; TX_BY_ADDR_KEY_LEN];
    key[0..32].copy_from_slice(addr);
    key[32..40].copy_from_slice(&(!height).to_be_bytes());
    key[40..44].copy_from_slice(&(!tx_index).to_be_bytes());
    key
}

/// Inverse of [`tx_by_addr_key`]; `None` on a malformed key.
pub fn tx_by_addr_key_parts(key: &[u8]) -> Option<([u8; 32], u64, u32)> {
    if key.len() != TX_BY_ADDR_KEY_LEN {
        return None;
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&key[0..32]);
    let height = u64::from_be_bytes(key[32..40].try_into().ok()?);
    let tx_index = u32::from_be_bytes(key[40..44].try_into().ok()?);
    Some((addr, !height, !tx_index))
}

/// `events_by_contract` key:
/// `contract || !height || !tx_index || !log_index` (48 bytes).
pub fn events_by_contract_key(
    contract: &[u8; 32],
    height: u64,
    tx_index: u32,
    log_index: u32,
) -> [u8; EVENTS_BY_CONTRACT_KEY_LEN] {
    let mut key = [0u8; EVENTS_BY_CONTRACT_KEY_LEN];
    key[0..32].copy_from_slice(contract);
    key[32..40].copy_from_slice(&(!height).to_be_bytes());
    key[40..44].copy_from_slice(&(!tx_index).to_be_bytes());
    key[44..48].copy_from_slice(&(!log_index).to_be_bytes());
    key
}

/// Inverse of [`events_by_contract_key`]; `None` on a malformed key.
pub fn events_by_contract_key_parts(key: &[u8]) -> Option<([u8; 32], u64, u32, u32)> {
    if key.len() != EVENTS_BY_CONTRACT_KEY_LEN {
        return None;
    }
    let mut contract = [0u8; 32];
    contract.copy_from_slice(&key[0..32]);
    let height = u64::from_be_bytes(key[32..40].try_into().ok()?);
    let tx_index = u32::from_be_bytes(key[40..44].try_into().ok()?);
    let log_index = u32::from_be_bytes(key[44..48].try_into().ok()?);
    Some((contract, !height, !tx_index, !log_index))
}

/// `receipt_meta_v2` key: the transaction hash (32 bytes).
pub fn receipt_meta_v2_key(tx_hash: &[u8; 32]) -> [u8; RECEIPT_META_V2_KEY_LEN] {
    *tx_hash
}

/// Decode a small self-describing record with the shared per-record byte
/// ceiling, so a corrupt length prefix cannot drive an OOM.
fn decode_small_record<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
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
        let state = db.open_tree("state")?;
        let domains = db.open_tree("domains")?;
        let headers = db.open_tree("headers")?;
        let session_keys = db.open_tree("session_keys")?;
        let bridge = db.open_tree("bridge")?;
        let zkml_models = db.open_tree("zkml_models")?;
        let cross_shard = db.open_tree("cross_shard")?;
        let cnvrf_v3 = db.open_tree("cnvrf_v3")?;
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
        self.put_header_v2(&BlockHeaderRecordV2::of(block))?;
        if block.height > 0 {
            self.put_finalized_post_root(block.height - 1, block.state_root)?;
        }
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

    /// Durable `set_meta`: insert + `flush()` (fsync barrier) before returning.
    ///
    /// Used for state whose loss would change policy (faucet lifetime caps /
    /// nonce, faucet init marker). A plain [`Self::set_meta`] only lands in the
    /// page cache until the next barrier, so a crash could resurrect spent
    /// credit; callers that need "durable before the next step" use this.
    pub fn set_meta_durable(&self, key: &str, value: &[u8]) -> Result<()> {
        self.meta.insert(key.as_bytes(), value)?;
        self.meta.flush()?;
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

    // ---------- Headers V2 (`BlockHeader` v4, additive) ----------

    pub fn put_header_v2(&self, rec: &BlockHeaderRecordV2) -> Result<()> {
        self.headers_v2
            .insert(rec.header.height.to_be_bytes(), bincode::serialize(rec)?)?;
        Ok(())
    }

    pub fn header_v2_at(&self, height: u64) -> Result<Option<BlockHeaderRecordV2>> {
        if let Some(v) = self.headers_v2.get(height.to_be_bytes())? {
            let rec: BlockHeaderRecordV2 = bincode::deserialize(&v)?;
            if rec.header.height != height {
                return Err(anyhow!(
                    "header_v2 height mismatch at key {height}: record reports {}",
                    rec.header.height
                ));
            }
            if crate::sharding::header_commit_active_at(height)
                && rec.header.compute_hash() != rec.block_hash
            {
                return Err(anyhow!(
                    "header_v2 at height {height} failed compute_hash() == block_hash binding"
                ));
            }
            return Ok(Some(rec));
        }
        // Fallback: reconstruct from retained block body if available.
        let mut candidate_hashes = self.hashes_at_height(height)?;
        if let Some(legacy) = self.header_at(height)? {
            if !candidate_hashes.contains(&legacy.block_hash) {
                candidate_hashes.push(legacy.block_hash);
            }
        }
        for hash in candidate_hashes {
            if let Some(block) = self.get_block(&hash)? {
                if block.height == height {
                    let rec = BlockHeaderRecordV2::of(&block);
                    if crate::sharding::header_commit_active_at(height)
                        && rec.header.compute_hash() != rec.block_hash
                    {
                        return Err(anyhow!(
                            "reconstructed header_v2 at height {height} failed compute_hash() binding"
                        ));
                    }
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }

    /// The highest v2 header retained, if any.
    pub fn latest_header_v2(&self) -> Result<Option<BlockHeaderRecordV2>> {
        if let Some((_, v)) = self.headers_v2.last()? {
            let rec: BlockHeaderRecordV2 = bincode::deserialize(&v)?;
            if crate::sharding::header_commit_active_at(rec.header.height)
                && rec.header.compute_hash() != rec.block_hash
            {
                return Err(anyhow!(
                    "latest header_v2 at height {} failed compute_hash() == block_hash binding",
                    rec.header.height
                ));
            }
            return Ok(Some(rec));
        }
        if let Some(legacy) = self.latest_header()? {
            return self.header_v2_at(legacy.height);
        }
        Ok(None)
    }

    /// Prune stored header records (both legacy `headers` and `headers_v2`)
    /// below `keep_from`, always retaining the highest header for bootability.
    pub fn prune_headers_below(&self, keep_from: u64) -> Result<usize> {
        let max_v1 = self
            .headers
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let max_v2 = self
            .headers_v2
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let max_h = match (max_v1, max_v2) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let mut removed = 0usize;
        let v1_keys: Vec<sled::IVec> = self
            .headers
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
        for k in v1_keys {
            self.headers.remove(k)?;
            removed += 1;
        }
        let v2_keys: Vec<sled::IVec> = self
            .headers_v2
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
        for k in v2_keys {
            self.headers_v2.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Finalized post-state roots (SNAP-TIP-SKIP) ----------

    fn finalized_post_root_key(height: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(20 + 8);
        k.extend_from_slice(b"finalized_post_root_v1");
        k.extend_from_slice(&height.to_be_bytes());
        k
    }

    /// Record the finalized post-state root for `height` in `"meta"` so
    /// [`Self::verify_restored_root`] can still verify a snapshot at the tip
    /// when no successor block at `height + 1` exists yet (`SNAP-TIP-SKIP`).
    pub fn put_finalized_post_root(&self, height: u64, root: [u8; 32]) -> Result<()> {
        self.meta
            .insert(Self::finalized_post_root_key(height), &root[..])?;
        Ok(())
    }

    /// Read the recorded finalized post-state root for `height`, if present.
    pub fn finalized_post_root_at(&self, height: u64) -> Result<Option<[u8; 32]>> {
        match self.meta.get(Self::finalized_post_root_key(height))? {
            Some(v) => {
                if v.len() != 32 {
                    return Err(anyhow!(
                        "corrupt finalized_post_root_v1 at height {height}: {} bytes",
                        v.len()
                    ));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                Ok(Some(out))
            }
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

    /// Test-only handle to the raw tip-ordered receipt index.
    #[doc(hidden)]
    pub fn receipts_by_height_tree_for_test(&self) -> sled::Tree {
        self.receipts_by_height.clone()
    }

    /// Test-only: force the "index complete" marker on/off. `false` simulates a
    /// pre-upgrade directory so the next `open` exercises the one-time backfill.
    #[doc(hidden)]
    pub fn set_receipt_index_ready_for_test(&self, ready: bool) -> Result<()> {
        if ready {
            self.meta.insert(RECEIPTS_BY_HEIGHT_READY_META_KEY, b"1")?;
        } else {
            self.meta.remove(RECEIPTS_BY_HEIGHT_READY_META_KEY)?;
        }
        self.meta.flush()?;
        Ok(())
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

    /// Complete the additive `receipts_by_height` index and set its durable
    /// "complete" marker (one-time per store).
    ///
    /// Chosen over a permanent fallback to the tx-hash scan: the backfill is a
    /// single streaming pass over `receipts` (bounded batches, one decoded
    /// receipt in RAM), idempotent and resumable — a crash before the marker
    /// write simply redoes it on the next open, and until then readers keep the
    /// legacy behaviour. Undecodable bodies are logged and skipped: they are
    /// already unreadable to every consumer, so they cannot be indexed.
    fn ensure_receipt_height_index(&self) -> Result<()> {
        if self.meta.get(RECEIPTS_BY_HEIGHT_READY_META_KEY)?.is_some() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let mut scanned = 0usize;
        let mut indexed = 0usize;
        let mut pending = 0usize;
        let mut batch = sled::Batch::default();
        for kv in self.receipts.iter() {
            let (_, value) = kv?;
            scanned += 1;
            match decode_receipt(&value) {
                Ok(r) => {
                    batch.insert(&receipt_index_key(&r)[..], &[] as &[u8]);
                    indexed += 1;
                    pending += 1;
                }
                Err(e) => tracing::warn!(
                    "[storage] receipt index backfill: skipping undecodable receipt: {e}"
                ),
            }
            if pending >= RECEIPT_INDEX_BACKFILL_BATCH {
                self.receipts_by_height
                    .apply_batch(std::mem::take(&mut batch))?;
                pending = 0;
            }
        }
        if pending > 0 {
            self.receipts_by_height.apply_batch(batch)?;
        }
        self.receipts_by_height.flush()?;
        self.meta.insert(RECEIPTS_BY_HEIGHT_READY_META_KEY, b"1")?;
        self.meta.flush()?;
        if scanned > 0 {
            let msg = format!(
                "[storage] receipt height index backfilled: {indexed}/{scanned} receipts in {:?}",
                started.elapsed()
            );
            tracing::info!("{msg}");
            eprintln!("{msg}");
        }
        Ok(())
    }

    /// Persist one receipt (idempotent by tx hash).
    ///
    /// The body and its tip-ordered index row are written in ONE sled
    /// transaction: a crash can never leave a body invisible to
    /// [`Self::latest_receipts_capped`], nor an index row pointing at a body
    /// that was never filed.
    pub fn put_receipt(&self, r: &StoredReceipt) -> Result<()> {
        let body = bincode::serialize(r)?;
        let tx_hash = r.tx_hash;
        let index_key = receipt_index_key(r);
        (&self.receipts, &self.receipts_by_height)
            .transaction(
                |(receipts, index)| -> sled::transaction::ConflictableTransactionResult<(), ()> {
                    receipts.insert(&tx_hash[..], body.clone())?;
                    index.insert(&index_key[..], &[] as &[u8])?;
                    Ok(())
                },
            )
            .map_err(|e| anyhow!("receipt transaction failed: {e:?}"))?;
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
        // heights, shutdown, upgrade — untouched). Each `put_receipt` also
        // writes the tip-ordered row, atomically with the body (one two-tree
        // sled transaction per receipt — still a per-tx cost, no block batch).
        let mut n = 0;
        // Block-level dimensions for `receipt_meta_v2` (from/to/amount/shard/
        // timestamp). The header is written by `put_block` BEFORE the receipt
        // job in the single-writer queue; a missing header (crash, hand-built
        // store) leaves honest zero defaults instead of failing the receipts.
        let (timestamp, shard_id) = self.block_stamp(height);
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let fee_charged =
                fees.get(i)
                    .copied()
                    .unwrap_or(if success { tx.gas_limit } else { 0 });
            let evts = events.get(i).cloned().unwrap_or_default();
            let tx_hash = tx.compute_tx_hash();
            self.put_receipt(&StoredReceipt {
                tx_hash,
                height,
                block_hash: *block_hash,
                index: i as u32,
                success,
                gas_limit: tx.gas_limit,
                fee_charged,
                events: evts.clone(),
            })?;
            // DATA BEFORE INDEX (same discipline as `put_block`): the receipt
            // body is durable before any history row points at it, so a crash
            // can only leave history rows missing, never a row naming a
            // transaction this store never filed.
            self.index_tx_history(height, i as u32, timestamp, shard_id, tx, &tx_hash, &evts)?;
            n += 1;
        }
        Ok(n)
    }

    /// Header-derived `(timestamp, shard_id)` for the history metadata.
    ///
    /// `timestamp` comes from the prune-surviving `headers` record; `shard_id`
    /// only exists in the additive v2 header, so it defaults to `0`
    /// (masterchain) when that record is absent — the same value every
    /// pre-v4 store observed.
    fn block_stamp(&self, height: u64) -> (u64, u32) {
        let timestamp = self
            .headers
            .get(height.to_be_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<BlockHeaderRecord>(&v).ok())
            .map(|h| h.timestamp)
            .unwrap_or(0);
        let shard_id = self
            .headers_v2
            .get(height.to_be_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<BlockHeaderRecordV2>(&v).ok())
            .map(|h| h.header.shard_id)
            .unwrap_or(0);
        (timestamp, shard_id)
    }

    /// Write the three additive history rows for one transaction.
    ///
    /// `tx_by_addr` gets one row for the sender, one for a distinct recipient
    /// and one for a third-party sponsor (a self-sponsored transaction already
    /// collapses to the sender via `effective_sponsor`). A row collision (same
    /// address twice in one transaction) is idempotent: the key is identical
    /// and the value is the same transaction hash.
    #[allow(clippy::too_many_arguments)]
    // GATE: the row needs the block position, the transaction and its event
    // list together; grouping them would just move the same fields.
    fn index_tx_history(
        &self,
        height: u64,
        tx_index: u32,
        timestamp: u64,
        shard_id: u32,
        tx: &crate::sharding::Transaction,
        tx_hash: &[u8; 32],
        events: &[crate::contract::ContractEvent],
    ) -> Result<()> {
        let meta = StoredReceiptMetaV2 {
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
            shard_id,
            timestamp,
        };
        self.receipt_meta_v2
            .insert(receipt_meta_v2_key(tx_hash), bincode::serialize(&meta)?)?;

        let mut addresses = vec![tx.from];
        if tx.to != tx.from {
            addresses.push(tx.to);
        }
        if let Some(sponsor) = tx.effective_sponsor() {
            addresses.push(sponsor);
        }
        for addr in addresses {
            self.tx_by_addr
                .insert(tx_by_addr_key(&addr, height, tx_index), tx_hash.as_slice())?;
        }

        for (log_index, event) in events.iter().enumerate() {
            let record = StoredContractEvent {
                tx_hash: *tx_hash,
                topic: event.topic,
                value: event.value,
            };
            self.events_by_contract.insert(
                events_by_contract_key(&event.contract, height, tx_index, log_index as u32),
                bincode::serialize(&record)?,
            )?;
        }
        Ok(())
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
        // The tip-ordered index row of every removed receipt goes in the same
        // chunk (per-tree atomic batches), so the index cannot grow forever.
        let mut removed = 0;
        loop {
            let stale: Vec<(sled::IVec, StoredReceipt)> = self
                .receipts
                .iter()
                .filter_map(|kv| kv.ok())
                .filter_map(|(k, v)| {
                    let r: StoredReceipt = decode_receipt(&v).ok()?;
                    (r.height < keep_from).then_some((k, r))
                })
                .take(PRUNE_BATCH)
                .collect();
            if stale.is_empty() {
                break;
            }
            let mut bodies = sled::Batch::default();
            let mut index_rows = sled::Batch::default();
            let mut meta_rows = sled::Batch::default();
            for (k, r) in &stale {
                bodies.remove(k);
                index_rows.remove(&receipt_index_key(r)[..]);
                // `receipt_meta_v2` is keyed by the SAME tx hash, so the meta
                // row is removed in this pass instead of growing a separate
                // forever-tree.
                meta_rows.remove(&receipt_meta_v2_key(&r.tx_hash)[..]);
            }
            self.receipts.apply_batch(bodies)?;
            self.receipts_by_height.apply_batch(index_rows)?;
            self.receipt_meta_v2.apply_batch(meta_rows)?;
            removed += stale.len();
            if removed >= PRUNE_BATCH * 4 {
                break; // one pass drains 80k; the rest next cadence
            }
        }
        // The address/event indexes encode the height IN THE KEY, so they are
        // pruned by a bounded height scan (filter-then-take, never a prefix:
        // the key starts with the address/contract, not the height).
        self.prune_history_below(keep_from)?;
        Ok(removed)
    }

    /// Drop `tx_by_addr` / `events_by_contract` rows below `keep_from`.
    ///
    /// Bounded by [`PRUNE_BATCH`] per tree per call, matching the receipt and
    /// body prunes: the flusher is the only writer, so one giant inline scan
    /// would stall every other write. Rows whose key cannot be decoded are
    /// left untouched (never deleted blind).
    fn prune_history_below(&self, keep_from: u64) -> Result<usize> {
        let mut removed = 0;
        let stale_addr: Vec<sled::IVec> = self
            .tx_by_addr
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                tx_by_addr_key_parts(k)
                    .map(|(_, height, _)| height < keep_from)
                    .unwrap_or(false)
            })
            .take(PRUNE_BATCH)
            .collect();
        for k in stale_addr {
            if self.tx_by_addr.remove(k)?.is_some() {
                removed += 1;
            }
        }
        let stale_events: Vec<sled::IVec> = self
            .events_by_contract
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                events_by_contract_key_parts(k)
                    .map(|(_, height, _, _)| height < keep_from)
                    .unwrap_or(false)
            })
            .take(PRUNE_BATCH)
            .collect();
        for k in stale_events {
            if self.events_by_contract.remove(k)?.is_some() {
                removed += 1;
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
    ///
    /// Kept as the compatibility fallback for stores whose `receipts_by_height`
    /// index is absent or incomplete; new readers use
    /// [`Self::latest_receipts_capped`].
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

    /// The newest `limit` receipts, ordered `(height, index)` DESCENDING.
    ///
    /// Reads the additive `receipts_by_height` index in reverse, so the slice
    /// is a genuine tip window instead of a random tx-hash prefix: `O(limit)`
    /// reads, independent of how large `receipts` has grown. Dangling index
    /// rows (body already pruned) are skipped.
    ///
    /// Fallback: when the index is not marked complete (pre-upgrade store), its
    /// meta read fails, or the index is empty while receipts exist, this warns
    /// and returns [`Self::all_receipts_capped`] — the exact pre-fix behaviour,
    /// never a silently partial window.
    pub fn latest_receipts_capped(&self, limit: usize) -> Result<Vec<StoredReceipt>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ready = match self.meta.get(RECEIPTS_BY_HEIGHT_READY_META_KEY) {
            Ok(ready) => ready.is_some(),
            Err(e) => {
                tracing::warn!(
                    "[storage] receipts_by_height marker unreadable ({e}); using legacy receipt scan"
                );
                return self.all_receipts_capped(limit);
            }
        };
        if !ready {
            tracing::warn!(
                "[storage] receipts_by_height index is not complete; using the legacy tx-hash-ordered receipt scan (newest receipts may be missed)"
            );
            return self.all_receipts_capped(limit);
        }
        if self.receipts_by_height.is_empty() && !self.receipts.is_empty() {
            tracing::warn!(
                "[storage] receipts_by_height index is empty while receipts exist; using the legacy tx-hash-ordered receipt scan"
            );
            return self.all_receipts_capped(limit);
        }
        let mut out = Vec::new();
        for kv in self.receipts_by_height.iter().rev() {
            if out.len() >= limit {
                break;
            }
            let (key, _) = kv?;
            if key.len() != RECEIPT_INDEX_KEY_LEN {
                tracing::warn!(
                    "[storage] receipts_by_height: ignoring malformed {}B key",
                    key.len()
                );
                continue;
            }
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&key[12..RECEIPT_INDEX_KEY_LEN]);
            // Dangling row: the body was pruned between the index write and now.
            if let Some(value) = self.receipts.get(tx_hash)? {
                match decode_receipt(&value) {
                    Ok(receipt) => out.push(receipt),
                    Err(e) => tracing::warn!(
                        "[storage] latest_receipts_capped: skipping undecodable receipt {}: {e}",
                        hex::encode(tx_hash)
                    ),
                }
            }
        }
        Ok(out)
    }

    // ---------- W4 E3: secondary history reads (tip-first, bounded) ----------

    /// Per-transaction metadata written alongside the receipt (from / to /
    /// amount / shard / timestamp), if this store has indexed it.
    pub fn receipt_meta(&self, tx_hash: &BlockHash) -> Result<Option<StoredReceiptMetaV2>> {
        match self.receipt_meta_v2.get(receipt_meta_v2_key(tx_hash))? {
            Some(v) => Ok(Some(decode_small_record(&v, "receipt_meta_v2")?)),
            None => Ok(None),
        }
    }

    /// Address history from `tx_by_addr`, tip-first.
    ///
    /// `from_height..=to_height` is INCLUSIVE; `role` filters by the participant
    /// side recorded in `receipt_meta_v2` (`All` includes the sponsor, because
    /// the sponsor address is indexed too). `cursor` resumes STRICTLY older than
    /// its `(height, tx_index)` position, so a page walk cannot duplicate or
    /// skip a row even when new blocks arrive between requests.
    ///
    /// Bounded twice: at most `limit` (capped at
    /// [`STORAGE_HISTORY_MAX_LIMIT`]) rows are returned, and at most
    /// [`STORAGE_SCAN_HARD_CAP`] index keys are inspected. Hitting the scan cap
    /// sets `scan_truncated` and still returns a `next_cursor` positioned past
    /// the inspected keys, so a caller can continue honestly.
    pub fn address_history(
        &self,
        addr: &[u8; 32],
        from_height: u64,
        to_height: u64,
        role: HistoryRole,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<AddressHistoryPage> {
        let limit = limit.clamp(1, STORAGE_HISTORY_MAX_LIMIT);
        let mut page = AddressHistoryPage::default();
        if from_height > to_height {
            return Ok(page);
        }
        // `!height`/`!tx_index` invert the order: the FIRST key of a height is
        // its HIGHEST tx index, the LAST key its lowest.
        let window_start = tx_by_addr_key(addr, to_height, u32::MAX);
        let window_end = tx_by_addr_key(addr, from_height, 0);
        let start = match cursor {
            Some(c) => {
                let ck = tx_by_addr_key(addr, c.height, c.tx_index);
                if ck >= window_start {
                    std::ops::Bound::Excluded(ck)
                } else {
                    std::ops::Bound::Included(window_start)
                }
            }
            None => std::ops::Bound::Included(window_start),
        };
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut last_scanned: Option<HistoryCursor> = None;
        let mut more = false;
        for kv in self
            .tx_by_addr
            .range((start, std::ops::Bound::Included(window_end)))
        {
            if page.scanned >= STORAGE_SCAN_HARD_CAP {
                page.scan_truncated = true;
                break;
            }
            let (key, value) = kv?;
            page.scanned += 1;
            let Some((key_addr, height, tx_index)) = tx_by_addr_key_parts(&key) else {
                continue;
            };
            if key_addr != *addr {
                break;
            }
            last_scanned = Some(HistoryCursor { height, tx_index });
            if height < from_height || height > to_height || value.len() != 32 {
                continue;
            }
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&value);
            let meta = self.receipt_meta(&tx_hash)?;
            let role_matches = match role {
                HistoryRole::All => true,
                HistoryRole::Sender => meta.map(|m| m.from == *addr).unwrap_or(false),
                HistoryRole::Recipient => meta.map(|m| m.to == *addr).unwrap_or(false),
            };
            if !role_matches {
                continue;
            }
            if !seen.insert(tx_hash) {
                continue;
            }
            if page.items.len() >= limit {
                more = true;
                break;
            }
            page.items.push(AddressHistoryItem {
                tx_hash,
                height,
                tx_index,
                meta,
            });
        }
        page.has_more = more || page.scan_truncated;
        page.next_cursor = if more {
            page.items.last().map(|item| HistoryCursor {
                height: item.height,
                tx_index: item.tx_index,
            })
        } else if page.scan_truncated {
            last_scanned
        } else {
            None
        };
        Ok(page)
    }

    /// Contract events from `events_by_contract`, tip-first.
    ///
    /// `from_height..=to_height` is inclusive and `topic` is an optional exact
    /// match (`None` = any topic). Cursor/limit/scan caps are the same contract
    /// as [`Self::address_history`].
    #[allow(clippy::too_many_arguments)]
    // GATE: contract + range + topic + cursor + limit are the documented RPC
    // parameter set; grouping them would only rename the same fields.
    pub fn events_by_contract_range(
        &self,
        contract: &[u8; 32],
        from_height: u64,
        to_height: u64,
        topic: Option<i64>,
        cursor: Option<EventCursor>,
        limit: usize,
    ) -> Result<ContractEventsPage> {
        let limit = limit.clamp(1, STORAGE_HISTORY_MAX_LIMIT);
        let mut page = ContractEventsPage::default();
        if from_height > to_height {
            return Ok(page);
        }
        let window_start = events_by_contract_key(contract, to_height, u32::MAX, u32::MAX);
        let window_end = events_by_contract_key(contract, from_height, 0, 0);
        let start = match cursor {
            Some(c) => {
                let ck = events_by_contract_key(contract, c.height, c.tx_index, c.log_index);
                if ck >= window_start {
                    std::ops::Bound::Excluded(ck)
                } else {
                    std::ops::Bound::Included(window_start)
                }
            }
            None => std::ops::Bound::Included(window_start),
        };
        let mut last_scanned: Option<EventCursor> = None;
        let mut more = false;
        for kv in self
            .events_by_contract
            .range((start, std::ops::Bound::Included(window_end)))
        {
            if page.scanned >= STORAGE_SCAN_HARD_CAP {
                page.scan_truncated = true;
                break;
            }
            let (key, value) = kv?;
            page.scanned += 1;
            let Some((key_contract, height, tx_index, log_index)) =
                events_by_contract_key_parts(&key)
            else {
                continue;
            };
            if key_contract != *contract {
                break;
            }
            last_scanned = Some(EventCursor {
                height,
                tx_index,
                log_index,
            });
            if height < from_height || height > to_height {
                continue;
            }
            let record: StoredContractEvent = decode_small_record(&value, "events_by_contract")?;
            if topic.map(|t| t != record.topic).unwrap_or(false) {
                continue;
            }
            if page.items.len() >= limit {
                more = true;
                break;
            }
            page.items.push(ContractEventRecord {
                contract: key_contract,
                tx_hash: record.tx_hash,
                height,
                tx_index,
                log_index,
                topic: record.topic,
                value: record.value,
            });
        }
        page.has_more = more || page.scan_truncated;
        page.next_cursor = if more {
            page.items.last().map(|item| EventCursor {
                height: item.height,
                tx_index: item.tx_index,
                log_index: item.log_index,
            })
        } else if page.scan_truncated {
            last_scanned
        } else {
            None
        };
        Ok(page)
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

    /// Persist the write-ahead vote watermark (one sled ACID insert).
    ///
    /// Callers MUST call this BEFORE broadcasting the vote. It is a separate
    /// meta key from the consensus checkpoint on purpose: finalization rewrites
    /// the checkpoint, and the watermark must survive that.
    pub fn set_vote_watermark(&self, wm: &VoteWatermark) -> Result<()> {
        let bytes = bincode::serialize(wm)?;
        self.set_meta("vote_watermark", &bytes)
    }

    /// Write-ahead vote watermark: insert + durability barrier.
    ///
    /// The barrier is what makes the record survive a power loss, not just a
    /// process crash, so the node can never re-vote a round it already used.
    /// A vote is cast at most once per round and kind, so the fsync cost is
    /// bounded by the round cadence (seconds), not by transaction throughput.
    pub fn persist_vote_watermark(&self, wm: &VoteWatermark) -> Result<()> {
        self.set_vote_watermark(wm)?;
        self.flush()
    }

    pub fn vote_watermark(&self) -> Result<Option<VoteWatermark>> {
        match self.get_meta("vote_watermark")? {
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

    /// Height of the most recent state snapshot, WITHOUT copying the blob.
    ///
    /// Boot-time predicates (the upgrade-halt guard) only need "how far has
    /// applied state advanced". [`Self::latest_state`] clones the whole
    /// snapshot value (`v.to_vec()`), which can be tens of megabytes, just to
    /// read the 8-byte key. This reads the same key ordering but drops the
    /// value IVec immediately, so the whole blob is never materialised.
    pub fn latest_state_height(&self) -> Result<Option<u64>> {
        // `keys()` (unlike `last()`) never hands the stored value to this
        // caller at all, so boot cost is one key read regardless of snapshot
        // size.
        match self.state.iter().keys().next_back() {
            Some(Ok(k)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some(u64::from_be_bytes(h)))
            }
            Some(Ok(_)) => Ok(None),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
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
        let mut candidates: Vec<u64> = state_heights
            .intersection(&domain_heights)
            .copied()
            .collect();
        if !self.pq_registry.is_empty() {
            let pq_heights: std::collections::BTreeSet<u64> = self
                .pq_registry
                .iter()
                .keys()
                .filter_map(|k| k.ok())
                .filter(|k| k.len() == 8)
                .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
                .collect();
            let with_pq: Vec<u64> = candidates
                .iter()
                .copied()
                .filter(|h| pq_heights.contains(h))
                .collect();
            if !with_pq.is_empty() {
                candidates = with_pq;
            }
        }
        let Some(height) = candidates.into_iter().max() else {
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
        self.prune_cnvrf_v3_below(keep_from)?;
        self.prune_evm_bindings_state_below(keep_from)?;
        self.prune_pq_registry_below(keep_from)?;
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

    // ---------- CN-VRF v3 domain snapshots ----------

    pub fn put_cnvrf_v3(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.cnvrf_v3.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The committed CN-VRF v3 subsystem state exactly as it stood after
    /// `height`, when one was stored. `None` (or empty bytes) for older
    /// directories means `CnVrfV3EngineSnapshot::default()` (empty), which
    /// contributes zero bytes to the commitment digest.
    pub fn cnvrf_v3_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.cnvrf_v3.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    /// Drop CN-VRF v3 snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never drops
    /// a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_cnvrf_v3_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .cnvrf_v3
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
            self.cnvrf_v3.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Canonical EVM bindings domain snapshots (`Domain::EvmBindings`) ----------

    pub fn put_evm_bindings_state(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.evm_bindings_state
            .insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The canonical `Domain::EvmBindings` snapshot at `height`, when stored.
    /// `None` (or empty bytes) on older directories means empty `EvmBindingsState`
    /// (contributes 0 bytes to the commitment digest).
    pub fn evm_bindings_state_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .evm_bindings_state
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    /// Drop `evm_bindings_state` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_evm_bindings_state_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .evm_bindings_state
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
            self.evm_bindings_state.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Canonical PQ key registry domain snapshots (`Domain::PqRegistry`) ----------

    pub fn put_pq_registry(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.pq_registry.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The canonical `Domain::PqRegistry` snapshot at `height`, when stored.
    /// `None` (or empty bytes) on older directories means empty `PqRegistry`
    /// (contributes 0 bytes to the commitment digest).
    pub fn pq_registry_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .pq_registry
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    /// Drop `pq_registry` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_pq_registry_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .pq_registry
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
            self.pq_registry.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Non-consensus crash-safe EVM bindings index (`"evm_bindings"`) ----------
    //
    // Key layout:
    //   b"e:" || evm(20)  -> pq(32)
    //   b"p:" || pq(32)   -> evm(20)
    //   b"meta:cursor"    -> u64 BE
    //
    // NEVER pruned by `prune_blocks_below` / `prune_receipts_below`!

    const EVM_BINDING_CURSOR_KEY: &'static [u8] = b"meta:cursor";

    fn evm_binding_e_key(evm: &[u8; 20]) -> Vec<u8> {
        let mut k = Vec::with_capacity(22);
        k.extend_from_slice(b"e:");
        k.extend_from_slice(evm);
        k
    }

    fn evm_binding_p_key(pq: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(34);
        k.extend_from_slice(b"p:");
        k.extend_from_slice(pq);
        k
    }

    /// Atomically record `(evm, pq)` under strict first-writer-wins semantics:
    /// - If `(evm, pq)` is already identically mapped -> `Ok(false)` (idempotent).
    /// - If either `evm` or `pq` is already mapped to a different address -> `Err`
    ///   without overwriting.
    /// - Otherwise inserts both `b"e:"` and `b"p:"` in one sled transaction -> `Ok(true)`.
    pub fn put_evm_binding_if_absent(&self, evm: &[u8; 20], pq: &[u8; 32]) -> Result<bool> {
        let e_key = Self::evm_binding_e_key(evm);
        let p_key = Self::evm_binding_p_key(pq);
        let evm_val = *evm;
        let pq_val = *pq;
        let inserted = self
            .evm_bindings
            .transaction(
                |tree| -> sled::transaction::ConflictableTransactionResult<bool, String> {
                    let existing_e = tree.get(&e_key)?;
                    let existing_p = tree.get(&p_key)?;
                    match (existing_e, existing_p) {
                        (Some(epq), Some(eevm)) => {
                            if epq.as_ref() == &pq_val[..] && eevm.as_ref() == &evm_val[..] {
                                Ok(false)
                            } else {
                                Err(sled::transaction::ConflictableTransactionError::Abort(
                                    format!(
                                        "evm_bindings conflict for evm=0x{} / pq={}",
                                        hex::encode(evm_val),
                                        hex::encode(pq_val)
                                    ),
                                ))
                            }
                        }
                        (Some(_), None) | (None, Some(_)) => Err(
                            sled::transaction::ConflictableTransactionError::Abort(format!(
                                "evm_bindings first-writer-wins conflict for evm=0x{} / pq={}",
                                hex::encode(evm_val),
                                hex::encode(pq_val)
                            )),
                        ),
                        (None, None) => {
                            tree.insert(e_key.as_slice(), &pq_val[..])?;
                            tree.insert(p_key.as_slice(), &evm_val[..])?;
                            Ok(true)
                        }
                    }
                },
            )
            .map_err(|e| match e {
                sled::transaction::TransactionError::Abort(msg) => anyhow!(msg),
                sled::transaction::TransactionError::Storage(err) => {
                    anyhow!("evm_bindings sled error: {err}")
                }
            })?;
        Ok(inserted)
    }

    pub fn evm_binding_by_evm(&self, evm: &[u8; 20]) -> Result<Option<[u8; 32]>> {
        match self.evm_bindings.get(Self::evm_binding_e_key(evm))? {
            Some(v) => {
                if v.len() != 32 {
                    return Err(anyhow!(
                        "corrupt evm_bindings e: value length {} != 32",
                        v.len()
                    ));
                }
                let mut pq = [0u8; 32];
                pq.copy_from_slice(&v);
                Ok(Some(pq))
            }
            None => Ok(None),
        }
    }

    pub fn evm_binding_by_pq(&self, pq: &[u8; 32]) -> Result<Option<[u8; 20]>> {
        match self.evm_bindings.get(Self::evm_binding_p_key(pq))? {
            Some(v) => {
                if v.len() != 20 {
                    return Err(anyhow!(
                        "corrupt evm_bindings p: value length {} != 20",
                        v.len()
                    ));
                }
                let mut evm = [0u8; 20];
                evm.copy_from_slice(&v);
                Ok(Some(evm))
            }
            None => Ok(None),
        }
    }

    pub fn evm_bindings_cursor(&self) -> Result<Option<u64>> {
        match self.evm_bindings.get(Self::EVM_BINDING_CURSOR_KEY)? {
            Some(v) => {
                if v.len() != 8 {
                    return Err(anyhow!(
                        "corrupt evm_bindings meta:cursor length {} != 8",
                        v.len()
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&v);
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    pub fn set_evm_bindings_cursor(&self, height: u64) -> Result<()> {
        self.evm_bindings
            .insert(Self::EVM_BINDING_CURSOR_KEY, &height.to_be_bytes())?;
        Ok(())
    }

    pub fn iter_evm_bindings(&self) -> Result<Vec<([u8; 20], [u8; 32])>> {
        let mut out = Vec::new();
        for kv in self.evm_bindings.scan_prefix(b"e:") {
            let (k, v) = kv?;
            if k.len() != 22 || v.len() != 32 {
                return Err(anyhow!(
                    "corrupt evm_bindings entry: key_len={} val_len={}",
                    k.len(),
                    v.len()
                ));
            }
            let mut evm = [0u8; 20];
            evm.copy_from_slice(&k[2..22]);
            let mut pq = [0u8; 32];
            pq.copy_from_slice(&v);
            out.push((evm, pq));
        }
        Ok(out)
    }

    #[doc(hidden)]
    pub fn evm_bindings_tree_for_test(&self) -> sled::Tree {
        self.evm_bindings.clone()
    }

    // ---------- W1 SnapV4 persistent trees (never touch safety_record_v1/meta) ----------

    fn snap_staging_key(height: u64, unit_tag: u16, sub_index: u16) -> [u8; 12] {
        let mut k = [0u8; 12];
        k[0..8].copy_from_slice(&height.to_be_bytes());
        k[8..10].copy_from_slice(&unit_tag.to_be_bytes());
        k[10..12].copy_from_slice(&sub_index.to_be_bytes());
        k
    }

    pub fn put_snap_unit(&self, chunk_hash: &[u8; 32], bytes: &[u8]) -> Result<()> {
        self.snap_units.insert(&chunk_hash[..], bytes)?;
        Ok(())
    }

    pub fn snap_unit(&self, chunk_hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.snap_units.get(&chunk_hash[..])?.map(|v| v.to_vec()))
    }

    pub fn has_snap_unit(&self, chunk_hash: &[u8; 32]) -> Result<bool> {
        Ok(self.snap_units.contains_key(&chunk_hash[..])?)
    }

    pub fn put_snap_manifest(&self, height: u64, manifest_bytes: &[u8]) -> Result<()> {
        self.snap_manifests
            .insert(height.to_be_bytes(), manifest_bytes)?;
        Ok(())
    }

    pub fn snap_manifest(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .snap_manifests
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    pub fn put_snap_staging_chunk(
        &self,
        height: u64,
        unit_tag: u16,
        sub_index: u16,
        bytes: &[u8],
    ) -> Result<()> {
        let key = Self::snap_staging_key(height, unit_tag, sub_index);
        self.snap_staging.insert(key, bytes)?;
        Ok(())
    }

    pub fn snap_staging_chunk(
        &self,
        height: u64,
        unit_tag: u16,
        sub_index: u16,
    ) -> Result<Option<Vec<u8>>> {
        let key = Self::snap_staging_key(height, unit_tag, sub_index);
        Ok(self.snap_staging.get(key)?.map(|v| v.to_vec()))
    }

    pub fn clear_snap_staging(&self, height: u64) -> Result<usize> {
        let keys: Vec<sled::IVec> = self
            .snap_staging
            .scan_prefix(height.to_be_bytes())
            .keys()
            .filter_map(|k| k.ok())
            .collect();
        let n = keys.len();
        for k in keys {
            self.snap_staging.remove(k)?;
        }
        Ok(n)
    }

    pub fn sweep_all_snap_staging(&self) -> Result<usize> {
        let n = self.snap_staging.len();
        self.snap_staging.clear()?;
        Ok(n)
    }

    /// Atomically commit a verified `SnapV4` checkpoint (data-before-index):
    /// 1. Write all content-addressed units into `snap_units`.
    /// 2. Write the canonical manifest into `snap_manifests`.
    /// 3. Flush to disk (`db.flush()`).
    /// 4. Insert the commit marker into `snap_committed` + `finalized_post_root_v1`.
    /// 5. Clear `snap_staging` for `marker.height`.
    ///
    /// Never reads or modifies `safety_record_v1`, `meta["consensus"]`, or
    /// `meta["vote_watermark"]`.
    pub fn commit_snap_v4(
        &self,
        marker: &SnapCommitMarker,
        manifest_bytes: &[u8],
        units: &[([u8; 32], &[u8])],
    ) -> Result<()> {
        for (hash, bytes) in units {
            self.snap_units.insert(&hash[..], *bytes)?;
        }
        self.snap_manifests
            .insert(marker.height.to_be_bytes(), manifest_bytes)?;
        self.db.flush()?;
        let marker_bytes = bincode::serialize(marker)?;
        self.snap_committed
            .insert(marker.height.to_be_bytes(), marker_bytes)?;
        self.put_finalized_post_root(marker.height, marker.state_root)?;
        let _ = self.clear_snap_staging(marker.height);
        Ok(())
    }

    pub fn snap_committed_at(&self, height: u64) -> Result<Option<SnapCommitMarker>> {
        match self.snap_committed.get(height.to_be_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    pub fn latest_snap_committed(&self) -> Result<Option<SnapCommitMarker>> {
        match self.snap_committed.last()? {
            Some((_, v)) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Reconstruct a committed `SnapV4` state at `height` (resolving any
    /// `Base -> Δ_1 -> ... -> Δ_k` chain up to `MAX_DELTA_CHAIN_LEN`).
    pub async fn load_snap_v4_state(
        &self,
        height: u64,
    ) -> Result<Option<crate::snapshot_v4::SnapStateV4>> {
        use crate::snapshot_v4::{
            apply_delta_state, assemble_base_state, decode_manifest_strict, verify_unit_chunk,
            SnapshotKind, SnapshotManifestV1, MAX_DELTA_CHAIN_LEN, UNIT_ENC_UNCHANGED,
        };
        use std::collections::BTreeMap;

        let Some(marker) = self.snap_committed_at(height)? else {
            return Ok(None);
        };
        if marker.height != height {
            return Err(anyhow!(
                "snap_committed marker height {} != key {height}",
                marker.height
            ));
        }

        let mut chain: Vec<SnapshotManifestV1> = Vec::new();
        let mut cur_h = height;
        let mut expected_root = marker.state_root;
        loop {
            let mbytes = self.snap_manifest(cur_h)?.ok_or_else(|| {
                anyhow!("missing snap_manifests entry for committed height {cur_h}")
            })?;
            let manifest = decode_manifest_strict(&mbytes)
                .map_err(|e| anyhow!("decode snap_manifest at height {cur_h}: {e}"))?;
            if manifest.target_height != cur_h || manifest.target_state_root != expected_root {
                return Err(anyhow!(
                    "snap_manifest mismatch at height {cur_h}: target=({}, {}), expected=({cur_h}, {})",
                    manifest.target_height,
                    hex::encode(manifest.target_state_root),
                    hex::encode(expected_root)
                ));
            }
            match manifest.kind {
                SnapshotKind::Base => {
                    chain.push(manifest);
                    break;
                }
                SnapshotKind::Delta {
                    base_height,
                    base_state_root,
                } => {
                    if base_height >= cur_h {
                        return Err(anyhow!(
                            "non-monotonic snap_v4 delta chain: base={base_height} >= target={cur_h}"
                        ));
                    }
                    if chain.len() >= MAX_DELTA_CHAIN_LEN {
                        return Err(anyhow!(
                            "snap_v4 delta chain exceeds MAX_DELTA_CHAIN_LEN ({MAX_DELTA_CHAIN_LEN})"
                        ));
                    }
                    chain.push(manifest);
                    cur_h = base_height;
                    expected_root = base_state_root;
                }
            }
        }
        chain.reverse();

        let load_chunks = |m: &SnapshotManifestV1| -> Result<BTreeMap<(u16, u16), Vec<u8>>> {
            let mut map = BTreeMap::new();
            for desc in &m.units {
                if desc.encoding == UNIT_ENC_UNCHANGED {
                    continue;
                }
                let raw = self.snap_unit(&desc.chunk_hash)?.ok_or_else(|| {
                    anyhow!(
                        "missing snap_unit {} for ({}, {}) at height {}",
                        hex::encode(desc.chunk_hash),
                        desc.unit_tag,
                        desc.sub_index,
                        m.target_height
                    )
                })?;
                verify_unit_chunk(desc, &raw)
                    .map_err(|e| anyhow!("verify snap_unit at {}: {e}", m.target_height))?;
                map.insert((desc.unit_tag, desc.sub_index), raw);
            }
            Ok(map)
        };

        let base_manifest = &chain[0];
        let base_chunks = load_chunks(base_manifest)?;
        let mut state = assemble_base_state(base_manifest, &base_chunks)
            .await
            .map_err(|e| {
                anyhow!(
                    "assemble base snap_v4 at {}: {e}",
                    base_manifest.target_height
                )
            })?;
        let mut prev_h = base_manifest.target_height;
        let mut prev_root = base_manifest.target_state_root;
        for delta_manifest in &chain[1..] {
            let delta_chunks = load_chunks(delta_manifest)?;
            state = apply_delta_state(&state, prev_h, prev_root, delta_manifest, &delta_chunks)
                .await
                .map_err(|e| {
                    anyhow!(
                        "apply delta snap_v4 at {}: {e}",
                        delta_manifest.target_height
                    )
                })?;
            prev_h = delta_manifest.target_height;
            prev_root = delta_manifest.target_state_root;
        }
        Ok(Some(state))
    }

    /// Prune old `SnapV4` committed checkpoints, manifests, and unreferenced
    /// content-addressed units below `keep_from`, keeping the newest committed
    /// checkpoint and any `Base`/intermediate deltas it depends on.
    ///
    /// Never touches `safety_record_v1`, `meta["consensus"]`, or `meta["vote_watermark"]`.
    pub fn prune_deltas_below(&self, keep_from: u64) -> Result<usize> {
        use crate::snapshot_v4::{decode_manifest_strict, SnapshotKind, UNIT_ENC_UNCHANGED};
        use std::collections::{BTreeMap, BTreeSet};

        let mut committed_heights = BTreeSet::new();
        for kv in self.snap_committed.iter().keys() {
            let k = kv?;
            if k.len() == 8 {
                committed_heights.insert(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
            }
        }
        if committed_heights.is_empty() {
            return Ok(0);
        }
        let max_h = committed_heights.iter().copied().max();
        let mut manifests: BTreeMap<u64, crate::snapshot_v4::SnapshotManifestV1> = BTreeMap::new();
        for kv in self.snap_manifests.iter() {
            let (k, v) = kv?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                if let Ok(m) = decode_manifest_strict(&v) {
                    manifests.insert(h, m);
                }
            }
        }

        let mut retain: BTreeSet<u64> = BTreeSet::new();
        for &h in &committed_heights {
            if h >= keep_from || Some(h) == max_h {
                retain.insert(h);
            }
        }
        // Transitive dependency closure: any retained Delta must retain its Base chain.
        let mut work: Vec<u64> = retain.iter().copied().collect();
        while let Some(h) = work.pop() {
            if let Some(m) = manifests.get(&h) {
                if let SnapshotKind::Delta { base_height, .. } = m.kind {
                    if retain.insert(base_height) {
                        work.push(base_height);
                    }
                }
            }
        }

        let mut removed = 0usize;
        for &h in &committed_heights {
            if !retain.contains(&h) {
                self.snap_committed.remove(h.to_be_bytes())?;
                removed += 1;
            }
        }
        for &h in manifests.keys() {
            if !retain.contains(&h) {
                self.snap_manifests.remove(h.to_be_bytes())?;
            }
        }
        let mut live_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
        for h in &retain {
            if let Some(m) = manifests.get(h) {
                for d in &m.units {
                    if d.encoding != UNIT_ENC_UNCHANGED {
                        live_hashes.insert(d.chunk_hash);
                    }
                }
            }
        }
        let dead_units: Vec<sled::IVec> = self
            .snap_units
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 32 {
                    return true;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(k);
                !live_hashes.contains(&h)
            })
            .collect();
        for k in dead_units {
            self.snap_units.remove(k)?;
        }
        Ok(removed)
    }

    // ---------- Durable cross-shard finalized-header registry ----------

    /// The single row holding the latest registry snapshot.
    const XSHARD_HEADERS_KEY: &'static [u8] = b"latest";

    /// Write one complete registry snapshot. Additive tree: an older data
    /// directory simply has no row and hydrates as an empty registry, exactly
    /// like a fresh process.
    pub fn put_xshard_headers(&self, bytes: &[u8]) -> Result<()> {
        self.xshard_headers
            .insert(Self::XSHARD_HEADERS_KEY, bytes)?;
        Ok(())
    }

    /// The latest persisted registry blob, if any. `None` means "never
    /// written" (fresh directory / single-shard chain), which hydrates as the
    /// empty registry — the same fail-closed start a cold process has.
    pub fn xshard_headers(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .xshard_headers
            .get(Self::XSHARD_HEADERS_KEY)?
            .map(|v| v.to_vec()))
    }

    /// Hydrate `registry` from this store BEFORE the runtime starts voting or
    /// syncing. Called at startup.
    ///
    /// FAIL CLOSED: a corrupt blob (or an I/O error) clears the registry and
    /// returns the error, so the node starts with NO anchors — it can re-anchor
    /// blocks it finalizes from now on, but it never accepts an anchor it could
    /// not verify from disk. The caller logs the error loudly; silence would
    /// hide the difference between "restart lost history" and "restart trusted
    /// forged history".
    pub fn hydrate_finalized_headers(&self, registry: &mut FinalizedHeaderRegistry) -> Result<()> {
        let bytes = match self.xshard_headers() {
            Ok(bytes) => bytes,
            Err(e) => {
                registry.clear_anchors();
                return Err(anyhow!("read xshard_headers: {e}"));
            }
        };
        let Some(bytes) = bytes else {
            return Ok(());
        };
        registry
            .restore_from_bytes(&bytes)
            .map_err(|e| anyhow!("xshard_headers blob rejected (registry left EMPTY): {e}"))
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
        let expected = match self.expected_restore_root(snapshot_height)? {
            Some(root) => root,
            None => {
                let tip = self.finalized()?.map(|(h, _)| h).unwrap_or(snapshot_height);
                if snapshot_height < tip {
                    return Err(anyhow!(
                        "no anchor to verify snapshot at height {snapshot_height} (finalized head is {tip}); \
                         refusing to resume on unprovable state -- wipe the data directory or restore a verified backup"
                    ));
                }
                // SNAP-TIP-SKIP: when at the tip (no successor block yet), check
                // the durable finalized_post_root_v1 meta entry if present.
                // Legacy directories and unit tests without it keep Ok(()) compat.
                match self.finalized_post_root_at(snapshot_height)? {
                    Some(root) => root,
                    None => return Ok(()),
                }
            }
        };
        if let Some(bytes) = self.cnvrf_v3_at(snapshot_height)? {
            if !bytes.is_empty() {
                let snap: crate::state_engine::CnVrfV3EngineSnapshot = bincode::deserialize(&bytes)
                    .map_err(|e| anyhow!("restore cnvrf_v3 at height {snapshot_height}: {e}"))?;
                engine.restore_cnvrf_v3_snapshot(&snap).await;
            }
        }
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
        if let Some(bytes) = self.cnvrf_v3_at(height)? {
            if !bytes.is_empty() {
                let snap: crate::state_engine::CnVrfV3EngineSnapshot = bincode::deserialize(&bytes)
                    .map_err(|e| anyhow!("restore cnvrf_v3 at height {height}: {e}"))?;
                tmp.restore_cnvrf_v3_snapshot(&snap).await;
            }
        }
        if let Some(bytes) = self.evm_bindings_state_at(height)? {
            tmp.restore_evm_bindings(&bytes)
                .await
                .map_err(|e| anyhow!("restore evm_bindings_state at height {height}: {e}"))?;
        }
        if let Some(bytes) = self.pq_registry_at(height)? {
            let _pq_reg = decode_pq_registry(&bytes)
                .map_err(|e| anyhow!("restore pq_registry at height {height}: {e}"))?;
            tmp.restore_pq_registry(&bytes)
                .await
                .map_err(|e| anyhow!("restore pq_registry at height {height}: {e}"))?;
        }

        // Anchor the recomputed root: the header at height+1 commits to the
        // post-`height` state. At the tip (no successor yet) check
        // `finalized_post_root_at(height)` if present, else skip for compat.
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
                if let Some(expected) = self.finalized_post_root_at(height)? {
                    if computed != expected {
                        return Err(anyhow!(
                            "snapshot at tip height {height} hashes to {} but finalized_post_root_v1 commits to {}: refusing to prove from it",
                            hex::encode(computed),
                            hex::encode(expected),
                        ));
                    }
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
        let (state_root, anchor_prev_hash, legacy_ts, legacy_proposer) = if let Some(rec) =
            self.header_at(anchor_height)?
        {
            (rec.state_root, rec.prev_hash, rec.timestamp, rec.proposer)
        } else if let Some(block) = self.get_block(&anchor_hash)? {
            (
                block.state_root,
                block.prev_hash,
                block.timestamp,
                block.proposer,
            )
        } else {
            return Err(anyhow!(
                    "anchoring block at height {anchor_height} names a body this node no longer holds: refusing"
                ));
        };
        let v2_opt = self.header_v2_at(anchor_height)?;
        let (
            anchor_shard_id,
            anchor_round,
            anchor_body_commitment,
            anchor_mmr_epoch_root,
            anchor_epoch_key_commitment,
            anchor_timestamp,
            anchor_proposer,
        ) = if crate::sharding::header_commit_active_at(anchor_height) {
            let v2 = v2_opt.ok_or_else(|| {
                anyhow!(
                    "missing v2 header record for anchoring height {anchor_height} under v4 header commitment: refusing fail-closed"
                )
            })?;
            if v2.block_hash != anchor_hash
                || v2.header.compute_hash() != anchor_hash
                || v2.header.state_root != state_root
                || v2.header.prev_hash != anchor_prev_hash
            {
                return Err(anyhow!(
                    "anchoring header v2 at height {anchor_height} failed BlockHeader::compute_hash() binding against anchor_hash"
                ));
            }
            (
                v2.header.shard_id,
                v2.header.round,
                Some(v2.header.body_commitment),
                v2.header.mmr_epoch_root,
                v2.header.epoch_key_commitment,
                v2.header.timestamp,
                v2.header.proposer,
            )
        } else if let Some(v2) = v2_opt {
            (
                v2.header.shard_id,
                v2.header.round,
                None,
                v2.header.mmr_epoch_root,
                v2.header.epoch_key_commitment,
                v2.header.timestamp,
                v2.header.proposer,
            )
        } else {
            (0, 0, None, [0u8; 32], [0u8; 32], legacy_ts, legacy_proposer)
        };
        Ok(HistoricalRoot {
            height,
            state_root,
            anchor_height,
            anchor_hash,
            anchor_prev_hash,
            cert,
            finalized: true,
            anchor_shard_id,
            anchor_round,
            anchor_body_commitment,
            anchor_mmr_epoch_root,
            anchor_epoch_key_commitment,
            anchor_timestamp,
            anchor_proposer,
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

/// One write-ahead vote watermark entry: the EXACT `(height, round, kind,
/// target, shard)` the node signed.
///
/// Persisted BEFORE the vote is broadcast, so a crash between the vote and the
/// next consensus checkpoint can never lose it and let the node re-vote in a
/// round it already used (Finding C).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoteWatermarkEntry {
    pub height: u64,
    pub round: u32,
    /// 0 = prevote, 1 = precommit (same tag as the signed preimage).
    pub kind: u8,
    /// `None` is a NIL vote — a real, signed statement, not "no vote".
    pub target: Option<[u8; 32]>,
    pub shard_id: u32,
}

/// Write-ahead vote watermark for ONE height: the last prevote and the last
/// precommit this node signed, each with its exact target and shard.
///
/// Stored under its own meta key (NOT inside [`ConsensusCheckpoint`]) for two
/// reasons:
///  * the checkpoint is rewritten with `round: 0` on every finalize; sharing
///    the record would erase the watermark for the new height's first round;
///  * the vote must be durable BEFORE it is broadcast, while the checkpoint is
///    written after finality — different durability points.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoteWatermark {
    pub prevote: Option<VoteWatermarkEntry>,
    pub precommit: Option<VoteWatermarkEntry>,
}

impl VoteWatermark {
    /// Record a signed vote (overwrites the entry of the same kind).
    pub fn note(&mut self, entry: VoteWatermarkEntry) {
        match entry.kind {
            0 => self.prevote = Some(entry),
            1 => self.precommit = Some(entry),
            _ => {}
        }
    }

    /// The highest round at which this node signed ANY vote at `height`.
    ///
    /// `None` means no recorded vote at that height. Used as the round FLOOR
    /// on restore and as the "never vote below" guard.
    pub fn floor_round(&self, height: u64) -> Option<u32> {
        [self.prevote, self.precommit]
            .into_iter()
            .flatten()
            .filter(|e| e.height == height)
            .map(|e| e.round)
            .max()
    }

    /// The prevote entry recorded at `height`, if any.
    pub fn prevote_at(&self, height: u64) -> Option<VoteWatermarkEntry> {
        self.prevote.filter(|e| e.height == height)
    }

    /// The precommit entry recorded at `height`, if any.
    pub fn precommit_at(&self, height: u64) -> Option<VoteWatermarkEntry> {
        self.precommit.filter(|e| e.height == height)
    }
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

/// Pre-W3 [`crate::staking::ValidatorStake`] shape (7 fields, before
/// `withdrawal_address: Option<[u8; 32]>` was appended).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorStakeV1 {
    pub self_bond: u64,
    pub delegated: u64,
    pub commission_bps: u64,
    pub pending_rewards: u64,
    pub total_slashed: u64,
    pub missed: u32,
    pub last_downtime_penalty: u64,
}

impl ValidatorStakeV1 {
    pub fn upgrade(self) -> crate::staking::ValidatorStake {
        crate::staking::ValidatorStake {
            self_bond: self.self_bond,
            delegated: self.delegated,
            commission_bps: self.commission_bps,
            pending_rewards: self.pending_rewards,
            total_slashed: self.total_slashed,
            missed: self.missed,
            last_downtime_penalty: self.last_downtime_penalty,
            withdrawal_address: None,
        }
    }
}

/// Pre-jail/commission/lock ledger shape: identical to
/// [`crate::staking::StakingLedger`] except WITHOUT `withdrawal_address` on
/// validator rows and WITHOUT the trailing maps (`jail`, `commission_schedule`,
/// `redelegation_lock`, `recent_full_exits`) appended after the lazy
/// delegator-reward accumulator.
///
/// This is what the live network persisted between the F1 lazy-accumulator
/// upgrade and the downtime-jail/commission/lock upgrade: bincode has no
/// field names, so those bytes do not decode as the current struct
/// (`UnexpectedEof` on the missing trailing maps) and must not be decoded as
/// [`DomainSnapshotV3`] either (a shorter ledger shape would read the two
/// accumulator maps as governance — refused loudly instead). NEVER written;
/// `upgrade` fills the new maps EMPTY and sets `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV4 {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
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
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
}

impl StakingLedgerV4 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
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
            // Exact: pre-change bytes cannot carry a full-exit record (the
            // recorder is applied per block and the map holds only the
            // current + previous height), so empty is not a guess.
            recent_full_exits: std::collections::HashMap::new(),
            emission_carry_q64: 0,
        }
    }
}

/// Ledger shape written after the downtime-jail/commission/lock upgrade but
/// BEFORE the forensic `recent_full_exits` map and `ValidatorStake::withdrawal_address`
/// were appended.
///
/// bincode has no field names and no "missing trailing field" rule, so those
/// bytes do not decode as the current struct. NEVER written; `upgrade` fills
/// `recent_full_exits` EMPTY and `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV5 {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: HashMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
    pub jail: HashMap<crate::consensus::ValidatorId, crate::staking::JailRecord>,
    pub commission_schedule:
        HashMap<crate::consensus::ValidatorId, crate::staking::CommissionSchedule>,
    pub redelegation_lock: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
}

impl StakingLedgerV5 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            jail: self.jail,
            commission_schedule: self.commission_schedule,
            redelegation_lock: self.redelegation_lock,
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
            recent_full_exits: HashMap::new(),
            emission_carry_q64: 0,
        }
    }
}

/// Pre-W3 ledger shape: identical to [`crate::staking::StakingLedger`]
/// (including `recent_full_exits`) except validator entries use the 7-field
/// [`ValidatorStakeV1`] without `withdrawal_address`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV6 {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: HashMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
    pub jail: HashMap<crate::consensus::ValidatorId, crate::staking::JailRecord>,
    pub commission_schedule:
        HashMap<crate::consensus::ValidatorId, crate::staking::CommissionSchedule>,
    pub redelegation_lock: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub recent_full_exits: HashMap<crate::consensus::ValidatorId, (u64, u64)>,
}

impl StakingLedgerV6 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            jail: self.jail,
            commission_schedule: self.commission_schedule,
            redelegation_lock: self.redelegation_lock,
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
            recent_full_exits: self.recent_full_exits,
            emission_carry_q64: 0,
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

/// Domain shape written immediately before the forensic `recent_full_exits`
/// ledger map was appended (pentest F6). Identical to the current
/// [`DomainSnapshot`] except the staking ledger is [`StakingLedgerV5`].
///
/// This is the fallback that keeps an EXISTING current-shape data dir
/// bootable: without it the added trailing map makes bincode run off the end
/// of the ledger into `governance`. Upgrade fills the map empty (exact — it
/// only ever holds the current + previous block's exits).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV8 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV5,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV8 {
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

/// Pre-W3 domain shape: identical to [`DomainSnapshot`] except the staking
/// ledger is [`StakingLedgerV6`] (which uses 7-field [`ValidatorStakeV1`]
/// without `withdrawal_address`). Upgrade fills `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV9 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV6,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV9 {
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

/// Pre-W4 `emission_carry_q64` ledger shape: identical to
/// [`crate::staking::StakingLedger`] (including 8-field `ValidatorStake` and
/// `recent_full_exits`) without the trailing `emission_carry_q64: u64`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV7 {
    pub validators: HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorStake>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: HashMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
    pub jail: HashMap<crate::consensus::ValidatorId, crate::staking::JailRecord>,
    pub commission_schedule:
        HashMap<crate::consensus::ValidatorId, crate::staking::CommissionSchedule>,
    pub redelegation_lock: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub recent_full_exits: HashMap<crate::consensus::ValidatorId, (u64, u64)>,
}

impl StakingLedgerV7 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self.validators,
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            jail: self.jail,
            commission_schedule: self.commission_schedule,
            redelegation_lock: self.redelegation_lock,
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
            recent_full_exits: self.recent_full_exits,
            emission_carry_q64: 0,
        }
    }
}

/// Pre-W4 `emission_carry_q64` domain shape: identical to [`DomainSnapshot`]
/// except the staking ledger is [`StakingLedgerV7`]. Upgrade sets
/// `emission_carry_q64: 0`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV10 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV7,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV10 {
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
    ($vis:vis $name:ident, $staking:ty) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize)]
        $vis struct $name {
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
            $vis fn upgrade(self) -> DomainSnapshot {
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

legacy_contract_domain_snapshot!(pub DomainSnapshotV4, crate::staking::StakingLedgerV3);
legacy_contract_domain_snapshot!(pub DomainSnapshotV5, crate::staking::StakingLedgerV2);
legacy_contract_domain_snapshot!(pub DomainSnapshotV6, crate::staking::StakingLedgerV1);

// Private 7-field `ValidatorStakeV1` shadow shapes for V1..V3 ledgers (which live
// in `staking.rs` with 8-field `ValidatorStake`) so real pre-W3 V1..V6 domain
// snapshots on disk also decode cleanly with `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StakingLedgerV1WithV1Stake {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
}

impl StakingLedgerV1WithV1Stake {
    fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedgerV1 {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
        }
        .upgrade()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StakingLedgerV2WithV1Stake {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
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
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
}

impl StakingLedgerV2WithV1Stake {
    fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedgerV2 {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
        }
        .upgrade()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StakingLedgerV3WithV1Stake {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
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
}

impl StakingLedgerV3WithV1Stake {
    fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedgerV3 {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            min_validator_bond: self.min_validator_bond,
            vesting_schedules: self.vesting_schedules,
        }
        .upgrade()
    }
}

macro_rules! current_contract_v1_stake_domain_snapshot {
    ($name:ident, $staking:ty) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize)]
        struct $name {
            pub tokens: crate::token::TokenRegistry,
            pub contracts: crate::contract::ContractRegistry,
            pub orderbooks: crate::orderbook::OrderbookManager,
            pub pmm: crate::pmm::PrimaryMarketMaker,
            pub pmm_usdt_token: Option<[u8; 32]>,
            pub pmm_treasury: [u8; 32],
            pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
            pub staking: $staking,
            pub governance: crate::governance::Governance,
            pub oracle: crate::oracle::OracleState,
        }
        impl $name {
            fn upgrade(self) -> DomainSnapshot {
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
    };
}

legacy_contract_domain_snapshot!(DomainSnapshotV4WithV1Stake, StakingLedgerV3WithV1Stake);
legacy_contract_domain_snapshot!(DomainSnapshotV5WithV1Stake, StakingLedgerV2WithV1Stake);
legacy_contract_domain_snapshot!(DomainSnapshotV6WithV1Stake, StakingLedgerV1WithV1Stake);
current_contract_v1_stake_domain_snapshot!(DomainSnapshotV3WithV1Stake, StakingLedgerV3WithV1Stake);
current_contract_v1_stake_domain_snapshot!(DomainSnapshotV2WithV1Stake, StakingLedgerV2WithV1Stake);
current_contract_v1_stake_domain_snapshot!(DomainSnapshotV1WithV1Stake, StakingLedgerV1WithV1Stake);

/// Decode a persisted [`crate::pq_registry::PqRegistry`] snapshot blob.
///
/// Empty bytes decode to an empty registry; non-empty bytes require exact
/// fixint bincode decoding with trailing bytes rejected.
pub fn decode_pq_registry(bytes: &[u8]) -> Result<crate::pq_registry::PqRegistry> {
    use bincode::Options;
    if bytes.is_empty() {
        return Ok(crate::pq_registry::PqRegistry::default());
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(DOMAIN_SNAPSHOT_STRICT_MAX_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| anyhow!("decode pq_registry: {e}"))
}

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
    // V10: pre-W4 current-shape domains (`StakingLedgerV7`), identical to
    // current except `emission_carry_q64` was appended last. Upgrade sets
    // `emission_carry_q64: 0` (exact for any pre-W4 snapshot).
    if let Ok(v10) = bincode::deserialize::<DomainSnapshotV10>(bytes) {
        tracing::warn!(
            "[domains] restored pre-W4 V10 staking state: emission_carry_q64 starts at 0"
        );
        return Ok(v10.upgrade());
    }
    // V9: pre-W3 current-shape domains (`StakingLedgerV6`, including
    // `recent_full_exits`), with 7-field `ValidatorStakeV1` (no
    // `withdrawal_address`). Upgrade sets `withdrawal_address: None`.
    if let Ok(v9) = bincode::deserialize::<DomainSnapshotV9>(bytes) {
        tracing::warn!(
            "[domains] restored pre-W3 V9 staking state: validator withdrawal_address starts as None until claimed via SysCallClaimWithdrawal"
        );
        return Ok(v9.upgrade());
    }
    // V8: current domains written before the forensic `recent_full_exits`
    // ledger map was appended. Closest to the current shape, so tried next.
    // The map is empty on upgrade, which is exact at a snapshot boundary (it
    // only ever holds the current + previous block's exits).
    if let Ok(v8) = bincode::deserialize::<DomainSnapshotV8>(bytes) {
        tracing::warn!(
            "[domains] restored pre-full-exit-record V8 staking state: the forensic recent-full-exit map starts EMPTY (exact — it is repopulated by the next applied block)"
        );
        return Ok(v8.upgrade());
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
    if let Ok(v4) = bincode::deserialize::<DomainSnapshotV4WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (pre-W3 ValidatorStakeV1): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY"
        );
        return Ok(v4.upgrade());
    }
    if let Ok(v5) = bincode::deserialize::<DomainSnapshotV5>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (older staking ledger): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v5.upgrade());
    }
    if let Ok(v5) = bincode::deserialize::<DomainSnapshotV5WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (older staking ledger, pre-W3 ValidatorStakeV1): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY"
        );
        return Ok(v5.upgrade());
    }
    if let Ok(v6) = bincode::deserialize::<DomainSnapshotV6>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (oldest staking ledger): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v6.upgrade());
    }
    if let Ok(v6) = bincode::deserialize::<DomainSnapshotV6WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (oldest staking ledger, pre-W3 ValidatorStakeV1): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY"
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
    if let Ok(v3) = bincode::deserialize::<DomainSnapshotV3WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-lazy-accumulator V3 staking state (pre-W3 ValidatorStakeV1): the reward accumulator and the delegator checkpoints start EMPTY"
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
    if let Ok(v2) = bincode::deserialize::<DomainSnapshotV2WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-dedup/vesting V2 staking state (pre-W3 ValidatorStakeV1): equivocation_dedup and vesting_schedules start EMPTY"
        );
        return Ok(v2.upgrade());
    }
    // Fall through to the oldest format below.
    if let Ok(v1) = bincode::deserialize::<DomainSnapshotV1>(bytes) {
        tracing::warn!(
            "[domains] restored pre-E2 V1 staking state: rewards counters start at ZERO — verify real minted supply out-of-band before trusting emission-cap headroom (exact on fresh/test chains)"
        );
        return Ok(v1.upgrade());
    }
    let v1: DomainSnapshotV1WithV1Stake =
        bincode::deserialize(bytes).map_err(|e| anyhow!("restore domains: {e}"))?;
    tracing::warn!(
        "[domains] restored pre-E2 V1 staking state (pre-W3 ValidatorStakeV1): rewards counters start at ZERO — verify real minted supply out-of-band before trusting emission-cap headroom (exact on fresh/test chains)"
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
/// exact-length). Any legacy shape (`DomainSnapshotV1`..`V9`, pre-ABI
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
    let paired_opt = storage.latest_paired_snapshot()?;
    let snap_v4_opt = storage.latest_snap_committed()?;
    if let Some(marker) = snap_v4_opt {
        if paired_opt
            .as_ref()
            .is_none_or(|(ph, _)| marker.height > *ph)
        {
            if let Some(snap_v4) = storage.load_snap_v4_state(marker.height).await? {
                let tmp = InMemoryStateEngine::new();
                tmp.attach_pq_tree(storage.pq_keys.clone());
                snap_v4
                    .apply_to_engine(&tmp)
                    .await
                    .map_err(|e| anyhow!("restore snap_v4 throwaway at {}: {e}", marker.height))?;
                storage.verify_restored_root(&tmp, marker.height).await?;
                let (staking, gov) = snap_v4
                    .apply_to_engine(engine)
                    .await
                    .map_err(|e| anyhow!("restore snap_v4 live at {}: {e}", marker.height))?;
                return Ok(Some((marker.height, staking, gov)));
            }
        }
    }
    // Take the newest height at which BOTH a state and a domains snapshot exist.
    // A crash between the two writes (they are separate enqueued jobs) can leave an
    // unpaired tail; loading state@H with domains@D!=H builds a frankestate no anchor
    // can validate. Pairing is the precondition for everything below.
    let Some((height, state_bytes)) = paired_opt else {
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

    // Aux-domain blobs are read ONCE and shared by the verify (throwaway) and
    // commit (live) phases below. Both phases install byte-identical state, so
    // the second sled read was pure duplication: each read is a tree lookup
    // plus decompression plus a full copy, and on an active chain the
    // cross-shard replay set, the zkML model registry and the CN-VRF v3 chain
    // are megabytes. Read order is unchanged (same keys, same sequence).
    //
    // Residency: these are the AUX domains only (a small fraction of the state
    // snapshot that is held by `state_bytes` across both phases regardless), so
    // keeping them for the commit phase costs a few MB at most and removes the
    // duplicate I/O.
    let session_keys_opt: Option<Vec<u8>>;
    let bridge_opt: Option<Vec<u8>>;
    let zkml_opt: Option<Vec<u8>>;
    // Decoded ONCE as well: `restore_cross_shard_replay` /
    // `restore_cnvrf_v3_snapshot` take `&snap`, so the commit phase reuses the
    // verify phase's decoded value instead of paying a second bincode pass
    // over the same multi-MB bytes.
    let cross_shard_snap: Option<crate::sharding::CrossShardReplaySnapshot>;
    let cnvrf_snap: Option<crate::state_engine::CnVrfV3EngineSnapshot>;
    let evm_bindings_opt: Option<Vec<u8>>;
    let pq_registry_opt: Option<Vec<u8>>;

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
        session_keys_opt = storage.session_keys_at(height)?;
        if let Some(bytes) = &session_keys_opt {
            tmp.restore_session_keys(bytes)
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
        bridge_opt = storage.bridge_at(height)?;
        if let Some(bytes) = &bridge_opt {
            tmp.restore_bridge(bytes)
                .await
                .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
        }
        // Ristretto deletion wave: confidential ledger removed; no restore.
        zkml_opt = storage.zkml_models_at(height)?;
        if let Some(bytes) = &zkml_opt {
            tmp.restore_zkml_models(bytes)
                .await
                .map_err(|e| anyhow!("restore zkML models: {e}"))?;
        }
        let cross_shard_bytes = storage.cross_shard_at(height)?;
        cross_shard_snap = match &cross_shard_bytes {
            // The STORE tolerates the legacy shape (a snapshot persisted
            // before the 2PC records existed).
            Some(bytes) => Some(
                crate::sharding::with_legacy_block_tolerance(|| bincode::deserialize(bytes))
                    .map_err(|e| anyhow!("restore cross-shard replay: {e:?}"))?,
            ),
            None => None,
        };
        if let Some(snap) = &cross_shard_snap {
            // FULL replay install (audit F1): consumed halves + produced +
            // completed, extend-only. Restoring only `engine_consumed` here
            // used to drop the produced/completed halves on every restart:
            // the produced map gates timeout-bounce linkage and the completed
            // set gates ack/bounce completion, so a restarted node derived a
            // different root than its anchor (refused when an anchor exists)
            // or, at the tip with no anchor, silently re-opened lifecycles.
            tmp.restore_cross_shard_replay(snap).await;
        }
        let cnvrf_bytes = storage.cnvrf_v3_at(height)?;
        cnvrf_snap = match &cnvrf_bytes {
            Some(bytes) if !bytes.is_empty() => {
                Some(bincode::deserialize(bytes).map_err(|e| anyhow!("restore cnvrf_v3: {e}"))?)
            }
            _ => None,
        };
        if let Some(snap) = &cnvrf_snap {
            tmp.restore_cnvrf_v3_snapshot(snap).await;
        }
        evm_bindings_opt = storage.evm_bindings_state_at(height)?;
        if let Some(bytes) = &evm_bindings_opt {
            tmp.restore_evm_bindings(bytes)
                .await
                .map_err(|e| anyhow!("restore evm_bindings_state: {e}"))?;
        }
        pq_registry_opt = storage.pq_registry_at(height)?;
        if let Some(bytes) = &pq_registry_opt {
            let _pq_reg =
                decode_pq_registry(bytes).map_err(|e| anyhow!("restore pq_registry: {e}"))?;
            tmp.restore_pq_registry(bytes)
                .await
                .map_err(|e| anyhow!("restore pq_registry: {e}"))?;
        }
        storage.verify_restored_root(&tmp, height).await?;
    }

    // Phase 2 (commit): the snapshot is genuine; install it into the live engine.
    // Same blobs as phase 1, from the copies read there — no second sled read.
    engine
        .restore_snapshot_preserve_replay_sets(&state_bytes)
        .await
        .map_err(|e| anyhow!("restore state: {e}"))?;
    if let Some(bytes) = &session_keys_opt {
        engine
            .restore_session_keys(bytes)
            .await
            .map_err(|e| anyhow!("restore session keys: {e}"))?;
    }
    if let Some(bytes) = &bridge_opt {
        engine
            .restore_bridge(bytes)
            .await
            .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
    }
    // Ristretto deletion wave: confidential ledger removed; no restore.
    if let Some(bytes) = &zkml_opt {
        engine
            .restore_zkml_models(bytes)
            .await
            .map_err(|e| anyhow!("restore zkML models: {e}"))?;
    }
    if let Some(snap) = &cross_shard_snap {
        // Same FULL install as the throwaway phase above: the two phases must
        // install byte-identical replay state, or the verified root would not
        // describe the live engine.
        engine.restore_cross_shard_replay(snap).await;
    }
    if let Some(snap) = &cnvrf_snap {
        engine.restore_cnvrf_v3_snapshot(snap).await;
    }
    if let Some(bytes) = &evm_bindings_opt {
        engine
            .restore_evm_bindings(bytes)
            .await
            .map_err(|e| anyhow!("restore evm_bindings_state: {e}"))?;
    }
    if let Some(bytes) = &pq_registry_opt {
        let _pq_reg = decode_pq_registry(bytes).map_err(|e| anyhow!("restore pq_registry: {e}"))?;
        engine
            .restore_pq_registry(bytes)
            .await
            .map_err(|e| anyhow!("restore pq_registry: {e}"))?;
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
    CnVrfV3 {
        height: u64,
        bytes: Vec<u8>,
    },
    EvmBindingsState {
        height: u64,
        bytes: Vec<u8>,
    },
    PqRegistry {
        height: u64,
        bytes: Vec<u8>,
    },
    /// Complete cross-shard finalized-header registry snapshot (latest shard
    /// heads + bounded anchor window). Latest-state, so a later job replaces an
    /// earlier one; enqueued from the registry's finalize path, never read from
    /// the network.
    XshardHeaders {
        bytes: Vec<u8>,
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
    /// Consensus-critical class (`Consensus` safety checkpoint / `Finalized`
    /// tip pointer): ALWAYS attempt the bounded drain, including on a
    /// current-thread runtime where the synchronous producer cannot hand the
    /// thread to the writer. The wait is deferred to a spawned task instead
    /// of dropping immediately. A drop is still possible after the budget
    /// expires (wedged disk) but is LOUD, counted, and names the recovery
    /// consequence — never silent.
    CriticalWait,
}

/// Pure classifier for the push drop-policy: which job classes may be
/// dropped outright when the persist queue is full, and which must wait out
/// a bounded drain first. Pure so the policy is test-pinned without timing.
///
/// Audit F2 (mainnet blocker): `Consensus` carries the per-height BFT safety
/// checkpoint and `Finalized` the durable tip pointer. Neither may be
/// dropped just because the producer happens to run on a current-thread
/// runtime, so both are `CriticalWait` (deferred drain) rather than the
/// generic `BoundedWait`.
pub fn persist_push_policy(job: &PersistJob) -> PersistPushPolicy {
    match job {
        PersistJob::Prune { .. } => PersistPushPolicy::DropFirst,
        PersistJob::Consensus(_) | PersistJob::Finalized { .. } => PersistPushPolicy::CriticalWait,
        _ => PersistPushPolicy::BoundedWait,
    }
}

/// Human label for a job class, used by the drop log so an operator can name
/// exactly what was lost without decoding an enum.
pub fn persist_job_label(job: &PersistJob) -> &'static str {
    match job {
        PersistJob::Block(_) => "Block (finalized body)",
        PersistJob::State { .. } => "State snapshot",
        PersistJob::Domains { .. } => "Domains snapshot",
        PersistJob::CnVrfV3 { .. } => "CN-VRF v3 snapshot",
        PersistJob::EvmBindingsState { .. } => "EVM bindings state snapshot",
        PersistJob::PqRegistry { .. } => "PQ registry snapshot",
        PersistJob::XshardHeaders { .. } => "cross-shard header registry",
        PersistJob::Consensus(_) => "Consensus safety checkpoint",
        PersistJob::Finalized { .. } => "Finalized tip pointer",
        PersistJob::Prune { .. } => "Prune pass",
        PersistJob::Receipts { .. } => "Receipts",
        PersistJob::Flush => "Flush barrier",
    }
}

/// Documented recovery consequence of losing one job of this class. Shown
/// verbatim in the LOUD drop path: a critical drop must never be a bare
/// counter bump that leaves the operator guessing whether finality is safe.
pub fn persist_drop_consequence(job: &PersistJob) -> &'static str {
    match job {
        PersistJob::Prune { .. } => {
            "nothing durable is lost; the next snapshot cadence re-schedules the prune"
        }
        PersistJob::State { .. } | PersistJob::Domains { .. } => {
            "one periodic snapshot is lost; the next cadence captures a newer height, widening the crash-recovery gap by at most one interval (half-pairs are refused loudly on restore)"
        }
        PersistJob::Block(_) => {
            "one finalized body is missing until adopter replication re-fetches it by hash"
        }
        PersistJob::Finalized { .. } => {
            "the durable tip pointer lags; the next boot re-walks from the last persisted finalized height (safe, slower). Finality itself is unaffected"
        }
        PersistJob::Consensus(_) => {
            "this height's BFT safety checkpoint is not durable; the node re-locks/re-derives it on restart and finality remains protected by the consensus certificate"
        }
        PersistJob::Receipts { .. } => {
            "receipts for this height are re-derivable by re-application; RPC serves no receipt until then"
        }
        PersistJob::CnVrfV3 { .. }
        | PersistJob::EvmBindingsState { .. }
        | PersistJob::PqRegistry { .. }
        | PersistJob::XshardHeaders { .. }
        | PersistJob::Flush => {
            "recoverable auxiliary state; the next cadence/finalize refreshes it"
        }
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

/// Record one persist-job drop: always counted, always LOUD, and — for a
/// consensus-critical class — names the exact recovery consequence. Kept in
/// one place so the synchronous and deferred (current-thread) drop paths can
/// never diverge in either metric or message.
fn record_persist_drop(policy: PersistPushPolicy, label: &'static str, consequence: &'static str) {
    match policy {
        PersistPushPolicy::CriticalWait => {
            tracing::error!(
                "[storage] CRITICAL persist job DROPPED after {PERSIST_BLOCKING_WAIT_MS}ms \
                 of bounded drain: {label}. Consequence: {consequence}. Counted in \
                 stell_persist_queue_dropped_total — a repeating drop means the disk is too \
                 slow or wedged; recover by restoring from a verified snapshot and fixing I/O."
            );
            eprintln!(
                "[storage] CRITICAL persist job DROPPED ({label}) after \
                 {PERSIST_BLOCKING_WAIT_MS}ms; consequence: {consequence} \
                 (counted: stell_persist_queue_dropped_total)"
            );
        }
        _ => {
            eprintln!(
                "[storage] persist queue full; dropping {label} (disk too slow? — counted, \
                 alert on stell_persist_queue_dropped_total; consequence: {consequence})"
            );
        }
    }
    crate::metrics::global().inc_persist_queue_dropped();
}

/// Decrement the live queue-depth gauge exactly once, saturating at zero.
/// Used by the writer on dequeue and by the deferred current-thread send when
/// a reservation is abandoned (drop or closed writer), so `pending()` never
/// leaks a phantom job — or hides a real one.
fn decrement_queue_depth(depth: &std::sync::atomic::AtomicU64) -> u64 {
    let mut prev = depth.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = prev.saturating_sub(1);
        match depth.compare_exchange_weak(
            prev,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => prev = actual,
        }
    }
    let now_depth = prev.saturating_sub(1);
    crate::metrics::global().set_persist_queue_depth(now_depth);
    now_depth
}

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
                // L-04: `fetch_update` is deprecated on newer toolchains; the
                // explicit CAS loop in `decrement_queue_depth` is exactly its
                // body for an always-Some closure (same race-safety:
                // concurrent dequeues serialize on the compare-exchange, the
                // counter saturates at 0 instead of wrapping).
                decrement_queue_depth(&depth_worker);
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
                    PersistJob::CnVrfV3 { height, bytes } => st.put_cnvrf_v3(height, &bytes),
                    PersistJob::EvmBindingsState { height, bytes } => {
                        st.put_evm_bindings_state(height, &bytes)
                    }
                    PersistJob::PqRegistry { height, bytes } => st.put_pq_registry(height, &bytes),
                    PersistJob::XshardHeaders { bytes } => st.put_xshard_headers(&bytes),
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
    ///   boot (safe but slow) — CRITICAL, so it is always granted a bounded
    ///   drain (deferred on a current-thread runtime) before any drop.
    /// * `Consensus`: the per-height BFT safety checkpoint. Re-derivable by
    ///   re-locking, but consensus-critical — same deferred bounded drain as
    ///   `Finalized`.
    /// * `Receipts`: per-height durable indexes. Re-derivable by
    ///   re-application — hence bounded-wait.
    /// * `Flush`: a durability barrier with no data — dropping it only
    ///   widens the fsync window; still bounded-waited (cheap) for uniformity.
    fn push(&self, job: PersistJob) {
        let policy = persist_push_policy(&job);
        let label = persist_job_label(&job);
        let consequence = persist_drop_consequence(&job);
        match self.tx.try_send(job) {
            Ok(()) => {
                self.bump_queue_depth();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(job)) => {
                if policy == PersistPushPolicy::DropFirst {
                    record_persist_drop(policy, label, consequence);
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
                //
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
                //     cannot drain while we wait. For a CRITICAL job the wait
                //     is DEFERRED to a spawned task (which the runtime polls
                //     as soon as the producer yields) instead of dropping
                //     immediately; a non-critical BoundedWait job keeps the
                //     historical immediate counted drop.
                //   * No runtime at all: nothing can drain either; keep the
                //     historical bounded wait.
                let flavor = tokio::runtime::Handle::try_current()
                    .ok()
                    .map(|h| h.runtime_flavor());
                match flavor {
                    Some(tokio::runtime::RuntimeFlavor::MultiThread) => {
                        if !tokio::task::block_in_place(|| self.bounded_wait_send(job)) {
                            record_persist_drop(policy, label, consequence);
                        }
                    }
                    Some(tokio::runtime::RuntimeFlavor::CurrentThread) => {
                        if policy == PersistPushPolicy::CriticalWait {
                            // Deferred bounded drain: the current-thread
                            // writer cannot run while the producer blocks on
                            // this synchronous call, but it WILL run at the
                            // producer's next await. The spawned send waits
                            // for capacity under the same bounded budget and
                            // only then records a drop — never an immediate,
                            // silent loss of the safety checkpoint/tip.
                            let tx = self.tx.clone();
                            let depth = self.queue_depth.clone();
                            // Reserve the gauge slot NOW: `pending()` drives
                            // graceful shutdown, and a deferred job that is
                            // not yet in the channel must still keep the drain
                            // waiting. The writer removes this reservation
                            // when it dequeues; an abandoned send removes it
                            // here.
                            self.bump_queue_depth();
                            tokio::spawn(async move {
                                match tokio::time::timeout(
                                    std::time::Duration::from_millis(PERSIST_BLOCKING_WAIT_MS),
                                    tx.send(job),
                                )
                                .await
                                {
                                    // Accepted: the writer owns the
                                    // reservation and decrements on dequeue.
                                    Ok(Ok(())) => {}
                                    // Writer gone: shutdown, no persistence
                                    // target left to lose.
                                    Ok(Err(_)) => {
                                        decrement_queue_depth(&depth);
                                    }
                                    Err(_) => {
                                        decrement_queue_depth(&depth);
                                        record_persist_drop(policy, label, consequence);
                                    }
                                }
                            });
                        } else {
                            record_persist_drop(policy, label, consequence);
                        }
                    }
                    // `RuntimeFlavor` is `#[non_exhaustive]`: a future tokio
                    // could add a flavour whose drain semantics we do not
                    // know. Fail SAFE (counted drop, never a silent loss) and
                    // never call `block_in_place` on it.
                    Some(_) => {
                        record_persist_drop(policy, label, consequence);
                    }
                    None => {
                        if !self.bounded_wait_send(job) {
                            record_persist_drop(policy, label, consequence);
                        }
                    }
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Bump the live queue-depth gauge after a successful push.
    fn bump_queue_depth(&self) -> u64 {
        let d = self
            .queue_depth
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        crate::metrics::global().set_persist_queue_depth(d);
        d
    }

    /// Retry `try_send` until the bounded budget expires. Returns `true` when
    /// the job was accepted (or the writer is gone, so there is nothing left
    /// to persist), `false` when the budget expired with the queue still full.
    fn bounded_wait_send(&self, mut job: PersistJob) -> bool {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(PERSIST_BLOCKING_WAIT_MS);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(PERSIST_RETRY_PACE_MS));
            match self.tx.try_send(job) {
                Ok(()) => {
                    self.bump_queue_depth();
                    return true;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(j)) => {
                    job = j;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return true,
            }
        }
        false
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

    /// Non-blocking: enqueue a CN-VRF v3 subsystem snapshot for `height`
    /// (`BoundedWait` policy, matching `Domains`/`Bridge`).
    pub fn enqueue_cnvrf_v3(&self, height: u64, bytes: Vec<u8>) {
        self.push(PersistJob::CnVrfV3 { height, bytes });
    }

    /// Non-blocking: enqueue a canonical `Domain::EvmBindings` snapshot for `height`.
    pub fn enqueue_evm_bindings_state(&self, height: u64, bytes: Vec<u8>) {
        self.push(PersistJob::EvmBindingsState { height, bytes });
    }

    /// Non-blocking: enqueue a canonical `Domain::PqRegistry` snapshot for `height`.
    pub fn enqueue_pq_registry(&self, height: u64, bytes: Vec<u8>) {
        self.push(PersistJob::PqRegistry { height, bytes });
    }

    /// Non-blocking: enqueue a complete cross-shard finalized-header registry
    /// snapshot. Latest-state (a later job replaces an earlier one), so the
    /// queue-under-pressure drop of one snapshot is recovered by the next
    /// finalize; `BoundedWait` keeps that window as small as the disk allows.
    pub fn enqueue_xshard_headers(&self, bytes: Vec<u8>) {
        self.push(PersistJob::XshardHeaders { bytes });
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
        let cnvrf_v3 = bincode::serialize(&engine.cnvrf_v3_snapshot().await).unwrap_or_default();
        let evm_bindings = engine.evm_bindings_snapshot().await;
        let pq_registry = engine.pq_registry_snapshot().await;
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
            self.enqueue_cnvrf_v3(height, cnvrf_v3);
            self.enqueue_evm_bindings_state(height, evm_bindings);
            self.enqueue_pq_registry(height, pq_registry);
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
        self.queue_depth.load(std::sync::atomic::Ordering::Relaxed)
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

/// Durability sink for the process-shared cross-shard finalized-header
/// registry: the registry hands us one complete snapshot per mutation and we
/// only ENQUEUE it, so the finalize path never touches disk.
impl FinalizedHeaderSink for AsyncPersistence {
    fn persist_finalized_headers(&self, bytes: Vec<u8>) {
        self.enqueue_xshard_headers(bytes);
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
            cnvrf_v3: None,
            round: 0,
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

    /// FINDING C: the write-ahead vote watermark is a SEPARATE durable record
    /// (one fsynced meta key), so it survives a crash between the vote and the
    /// next consensus checkpoint. The checkpoint stays at round 0 while the
    /// watermark says round 300 — which is exactly the state a restart must
    /// restore from.
    #[test]
    fn vote_watermark_survives_a_crash_before_the_checkpoint() {
        let dir = tmp();
        {
            let st = Storage::open(&dir).unwrap();
            st.set_consensus(&ConsensusCheckpoint {
                height: 7,
                round: 0,
                locked_hash: None,
                locked_round: 0,
                finalized_height: 6,
                finalized_hash: [3u8; 32],
            })
            .unwrap();
            let mut wm = VoteWatermark::default();
            wm.note(VoteWatermarkEntry {
                height: 7,
                round: 300,
                kind: 0,
                target: Some([4u8; 32]),
                shard_id: 1,
            });
            st.persist_vote_watermark(&wm).unwrap();
        }
        let st = Storage::open(&dir).unwrap();
        let wm = st.vote_watermark().unwrap().unwrap();
        assert_eq!(wm.floor_round(7), Some(300));
        assert_eq!(wm.prevote_at(7).unwrap().shard_id, 1);
        // The checkpoint rewrite path cannot erase it (separate key).
        st.set_consensus(&ConsensusCheckpoint {
            height: 8,
            round: 0,
            locked_hash: None,
            locked_round: 0,
            finalized_height: 7,
            finalized_hash: [5u8; 32],
        })
        .unwrap();
        assert_eq!(
            st.vote_watermark().unwrap().unwrap().floor_round(7),
            Some(300)
        );
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
        // Key-only read used by the upgrade-halt boot guard: same height as
        // `latest_state`, without materialising the snapshot value.
        assert_eq!(st.latest_state_height().unwrap(), Some(3));
        let pruned = st.prune_state_below(3).unwrap();
        assert_eq!(pruned, 2);
        assert_eq!(st.latest_state().unwrap().unwrap(), (3, b"three".to_vec()));
        assert_eq!(st.latest_state_height().unwrap(), Some(3));
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
        engine
            .update_account(AccountState::new(who, 1_000_000))
            .await;
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
        let state_bytes = serialize_off_tick(accounts).await.expect("encode accounts");
        let staking = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();
        let domains = DomainSnapshot::capture(&engine, &staking, &gov).await;
        let domain_bytes = serialize_off_tick(domains).await.expect("encode domains");
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
        engine
            .update_account(AccountState::new(who, 1_000_000))
            .await;
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
        let state_bytes = serialize_off_tick(accounts).await.expect("encode accounts");
        let staking = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();
        let domains = DomainSnapshot::capture(&engine, &staking, &gov).await;
        let domain_bytes = serialize_off_tick(domains).await.expect("encode domains");
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

    #[tokio::test]
    async fn cnvrf_v3_snapshot_roundtrip_verify_and_prune() {
        use crate::cn_vrf::{CnVrfV3Chain, EPOCH_LEN};
        use crate::consensus::FalconKeypair;
        use crate::staking::CnVrfAbortCounter;
        use crate::state_engine::CnVrfV3EngineSnapshot;

        let dir = tmp();
        let st = Arc::new(Storage::open(&dir).unwrap());
        let sk = SigningKey::generate(&mut OsRng);

        // Build an engine with non-empty account + non-empty CN-VRF v3 state
        // across all three sub-fields (v3_state, abort_state, epoch_beacons).
        let engine = InMemoryStateEngine::new();
        let who = [0x33u8; 32];
        engine.update_account(AccountState::new(who, 7_500)).await;

        let val_kp = FalconKeypair::generate_from_seed(77);
        let val_id = sk.verifying_key().to_bytes();
        let chain = CnVrfV3Chain::generate(engine.chain_id, &val_id, 1, &[0x5Bu8; 48]);
        let carrier = chain.commit_carrier(&val_kp);
        {
            let mut v3 = engine.cnvrf_v3_write().await;
            v3.admit_commit(&carrier, 0, engine.chain_id, val_kp.public_key())
                .expect("valid commit");
            let rev = chain.reveal_for_slot(0).expect("slot 0 reveal");
            v3.apply_slot_reveal(engine.chain_id, &val_id, EPOCH_LEN, Some(&rev));
        }
        {
            let mut abort = engine.cnvrf_abort_write().await;
            abort.counters.insert(
                val_id,
                CnVrfAbortCounter {
                    misses: 2,
                    recovery_streak: 1,
                },
            );
        }
        {
            let mut beacons = engine.epoch_vdf_beacons_write().await;
            beacons.insert(1, [0x42u8; 48]);
        }

        let expected_snap = engine.cnvrf_v3_snapshot().await;
        assert!(!expected_snap.is_empty());
        let root_10 = engine.get_state_root().await;

        // Persist via AsyncPersistence::snapshot_domains + enqueue_state at H=10,
        // and anchor H=11 with root_10.
        const H: u64 = 10;
        let ap = AsyncPersistence::start(st.clone());
        ap.enqueue_state(H, engine.create_snapshot().await);
        ap.snapshot_domains(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
            H,
        )
        .await;
        ap.request_flush();
        for _ in 0..200 {
            if st.cnvrf_v3_at(H).unwrap().is_some() && st.domain_at(H).unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(st.cnvrf_v3_at(H).unwrap().is_some(), "cnvrf_v3 persisted");

        let mut anchor = block(H + 1, [0x99u8; 32], &sk, None);
        anchor.state_root = root_10;
        let anchor_hash = anchor.compute_hash();
        st.put_header(&BlockHeaderRecord::of(&anchor)).unwrap();
        st.set_finalized(H + 1, &anchor_hash).unwrap();

        // Full restore into a fresh engine must match root and CnVrfV3EngineSnapshot.
        let fresh = InMemoryStateEngine::new();
        let (loaded_h, _, _) = load_full_state_into(&st, &fresh)
            .await
            .expect("load_full_state_into must verify")
            .expect("snapshot must exist");
        assert_eq!(loaded_h, H);
        assert_eq!(fresh.get_state_root().await, root_10);
        assert_eq!(fresh.cnvrf_v3_snapshot().await, expected_snap);

        // Direct verify_restored_root on an engine with accounts+domains restored
        // (even without manually calling restore_cnvrf_v3_snapshot) restores & passes.
        let direct = InMemoryStateEngine::new();
        direct
            .restore_snapshot_preserve_replay_sets(&st.get_state(H).unwrap().unwrap())
            .await
            .unwrap();
        let dom = decode_domain_snapshot(&st.domain_at(H).unwrap().unwrap()).unwrap();
        dom.apply(&direct).await;
        st.verify_restored_root(&direct, H)
            .await
            .expect("verify_restored_root must restore cnvrf_v3 and pass");
        assert_eq!(direct.cnvrf_v3_snapshot().await, expected_snap);

        // Enqueue path + prune behavior:
        // Add a stale unreferenced cnvrf_v3 row at height 5 and a newer snapshot at height 20.
        let stale_bytes = bincode::serialize(&CnVrfV3EngineSnapshot::default()).unwrap();
        ap.enqueue_cnvrf_v3(5, stale_bytes.clone());
        ap.request_flush();
        for _ in 0..200 {
            if st.cnvrf_v3_at(5).unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(st.cnvrf_v3_at(5).unwrap().is_some());

        st.put_state(20, &engine.create_snapshot().await).unwrap();
        st.put_domains(20, &st.domain_at(H).unwrap().unwrap())
            .unwrap();
        st.put_cnvrf_v3(20, &st.cnvrf_v3_at(H).unwrap().unwrap())
            .unwrap();

        // Prune below 15: height 5 (unretained) is dropped; height 10 (still in
        // state/domains) is retained; height 20 is retained.
        let pruned_cnvrf = st.prune_cnvrf_v3_below(15).unwrap();
        assert_eq!(pruned_cnvrf, 1);
        assert!(st.cnvrf_v3_at(5).unwrap().is_none());
        assert!(st.cnvrf_v3_at(H).unwrap().is_some());
        assert!(st.cnvrf_v3_at(20).unwrap().is_some());

        // After state/domains at H=10 are pruned via prune_state_below + prune_domains_below,
        // cnvrf_v3 at H=10 is also pruned cleanly while H=20 survives.
        assert_eq!(st.prune_state_below(15).unwrap(), 1);
        assert_eq!(st.prune_domains_below(15).unwrap(), 1);
        assert!(st.cnvrf_v3_at(H).unwrap().is_none());
        assert!(st.cnvrf_v3_at(20).unwrap().is_some());

        drop(ap);
        drop(st);
        std::fs::remove_dir_all(&dir).ok();
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
            let v = Vote::sign_with_falcon(
                sk,
                fk,
                height,
                round,
                VoteKind::Precommit,
                Some(block_hash),
            );
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
            cnvrf_v3: None,
            round: 0,
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

#[cfg(test)]
mod persist_policy_tests {
    //! Audit F2 (mainnet blocker): a full persist queue must never silently
    //! drop a consensus-critical job. These pin the classifier AND the
    //! current-thread deferred-drain path (the one that used to drop
    //! immediately).
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Async-aware twin of `SERIAL` for the two tests that must `await` while
    /// holding the guard.
    fn serial_async() -> &'static tokio::sync::Mutex<()> {
        static SERIAL_ASYNC: std::sync::OnceLock<tokio::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        SERIAL_ASYNC.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "stell_persist_policy_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn handle_with_capacity(
        dir: &std::path::Path,
        cap: usize,
    ) -> (AsyncPersistence, tokio::sync::mpsc::Receiver<PersistJob>) {
        let storage = Arc::new(Storage::open(dir).expect("temp storage opens"));
        let (tx, rx) = tokio::sync::mpsc::channel::<PersistJob>(cap);
        (
            AsyncPersistence {
                tx,
                storage,
                queue_depth: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    #[test]
    fn consensus_and_finalized_are_critical_wait_not_bounded_wait() {
        assert_eq!(
            persist_push_policy(&PersistJob::Consensus(Box::default())),
            PersistPushPolicy::CriticalWait
        );
        assert_eq!(
            persist_push_policy(&PersistJob::Finalized {
                height: 7,
                hash: [7u8; 32]
            }),
            PersistPushPolicy::CriticalWait
        );
        assert_eq!(
            persist_push_policy(&PersistJob::Prune { keep_from: 3 }),
            PersistPushPolicy::DropFirst
        );
        // Everything else stays bounded-wait (never drop-first).
        assert_eq!(
            persist_push_policy(&PersistJob::Flush),
            PersistPushPolicy::BoundedWait
        );
        // Every critical class has a documented, non-empty consequence.
        for job in [
            PersistJob::Consensus(Box::default()),
            PersistJob::Finalized {
                height: 1,
                hash: [1u8; 32],
            },
        ] {
            assert!(!persist_drop_consequence(&job).is_empty());
            assert!(!persist_job_label(&job).is_empty());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_queue_defers_critical_job_then_delivers_it() {
        // ASYNC-AWARE serialisation (a std guard across an await is both a
        // clippy error and a real hazard: it may drop on another thread).
        let _g = serial_async().lock().await;
        let dir = tmpdir("defer");
        let (ap, mut rx) = handle_with_capacity(&dir, 1);
        // One job fills the single slot; the writer is not running (we hold
        // the only receiver), so the next push hits `Full`.
        ap.enqueue_finalized(1, [1u8; 32]);
        let before = crate::metrics::global().snapshot().persist_queue_dropped;
        ap.enqueue_finalized(2, [2u8; 32]);
        // The old current-thread path dropped this synchronously.
        assert_eq!(
            crate::metrics::global().snapshot().persist_queue_dropped,
            before,
            "a critical job must never be dropped before its bounded drain"
        );
        // Free the slot: the deferred send must complete and deliver height 2.
        let first = rx.recv().await.expect("first job");
        assert!(matches!(first, PersistJob::Finalized { height: 1, .. }));
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("deferred critical send must not hang")
            .expect("deferred critical job delivered");
        assert!(matches!(second, PersistJob::Finalized { height: 2, .. }));
        assert_eq!(
            crate::metrics::global().snapshot().persist_queue_dropped,
            before,
            "delivered critical job is not a drop"
        );
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn critical_drop_after_budget_is_counted_never_silent() {
        let _g = serial_async().lock().await;
        let dir = tmpdir("counted");
        let (ap, _rx) = handle_with_capacity(&dir, 1);
        ap.enqueue_finalized(1, [1u8; 32]);
        let before = crate::metrics::global().snapshot().persist_queue_dropped;
        ap.enqueue_finalized(2, [2u8; 32]);
        // Never drain: the deferred send must expire and COUNT the loss.
        tokio::time::sleep(std::time::Duration::from_millis(
            PERSIST_BLOCKING_WAIT_MS.saturating_mul(3),
        ))
        .await;
        let after = crate::metrics::global().snapshot().persist_queue_dropped;
        assert_eq!(
            after - before,
            1.0,
            "a critical job that expires its bounded drain must be counted once"
        );
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_depth_gauge_counts_successful_push_only() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("depth");
        let (ap, _rx) = handle_with_capacity(&dir, 2);
        assert_eq!(ap.pending(), 0);
        ap.enqueue_finalized(1, [1u8; 32]);
        assert_eq!(ap.pending(), 1, "accepted job increments the gauge");
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn snapshot_domains_persists_pq_registry_and_latest_paired_skips_missing_pq_tail() {
        let dir = tmpdir("pq_snap_domains");
        let st = Arc::new(Storage::open(&dir).expect("open storage"));
        let engine = InMemoryStateEngine::new();
        let vid = [0x44u8; 32];
        let pk = crate::sharding::Transaction::sample_falcon512_pubkey(0x44);
        {
            let mut reg = engine.pq_registry_write().await;
            reg.adopt_legacy_key_at(vid, crate::post_quantum::PqScheme::Falcon512, pk, 0, true)
                .expect("seed pq key");
        }
        let ledger = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();

        let ap = AsyncPersistence::start(Arc::clone(&st));
        ap.snapshot_state(&engine, 10).await;
        ap.snapshot_domains(&engine, &ledger, &gov, 10).await;
        let _ = wait_for_persist_drain(|| ap.pending()).await;
        let _ = st.flush();

        // Simulate an older incomplete tail at height 20 missing pq_registry:
        // `latest_paired_snapshot` must skip 20 and return the complete 10.
        ap.snapshot_state(&engine, 20).await;
        let snap20 = DomainSnapshot::capture(&engine, &ledger, &gov).await;
        ap.enqueue_domains(
            20,
            bincode::serialize(&snap20).unwrap(),
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let _ = wait_for_persist_drain(|| ap.pending()).await;
        let _ = st.flush();

        let paired = st
            .latest_paired_snapshot()
            .expect("latest_paired_snapshot")
            .expect("some paired");
        assert_eq!(
            paired.0, 10,
            "paired snapshot with pq_registry must win over incomplete tail"
        );
        assert!(st.pq_registry_at(10).expect("read pq 10").is_some());

        let restored_engine = InMemoryStateEngine::new();
        let (rh, _, _) = load_full_state_into(&st, &restored_engine)
            .await
            .expect("load_full_state_into")
            .expect("some state");
        assert_eq!(rh, 10);
        assert_eq!(
            restored_engine.get_state_root().await,
            engine.get_state_root().await
        );
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
