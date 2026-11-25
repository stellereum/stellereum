use super::{decode_small_record, BlockHash, Storage};
use crate::sharding::Block;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sled::transaction::Transactional;

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
pub(super) struct LegacyStoredReceiptWithFee {
    pub(super) tx_hash: BlockHash,
    pub(super) height: u64,
    pub(super) block_hash: BlockHash,
    pub(super) index: u32,
    pub(super) success: bool,
    pub(super) gas_limit: u64,
    pub(super) fee_charged: u64,
}

/// Pre-`fee_charged` receipt shape (6 fields). Receipts written before the
/// field existed still decode: a legacy success charged the declared limit on
/// the block path (the only path that filed receipts then), a legacy failure
/// charged nothing, so the migration maps exactly to the new semantics.
#[derive(Serialize, Deserialize)]
pub(super) struct LegacyStoredReceipt {
    pub(super) tx_hash: BlockHash,
    pub(super) height: u64,
    pub(super) block_hash: BlockHash,
    pub(super) index: u32,
    pub(super) success: bool,
    pub(super) gas_limit: u64,
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

/// Meta key marking the `receipts_by_height` index as COMPLETE for this store.
///
/// Absent means the index cannot be trusted (pre-upgrade directory, or a
/// backfill that was interrupted): readers then fall back to the legacy
/// `receipts` scan and keep their pre-fix behaviour instead of silently
/// serving a partial window. `Storage::open` sets it after a full backfill.
pub const RECEIPTS_BY_HEIGHT_READY_META_KEY: &str = "receipts_by_height_v1";

/// Fixed width of one `receipts_by_height` key:
/// `height(8B BE) || index(4B BE) || tx_hash(32B)`.
pub(super) const RECEIPT_INDEX_KEY_LEN: usize = 44;

/// Rows applied per backfill batch: bounds the write burst on first open of an
/// existing multi-million-receipt directory.
const RECEIPT_INDEX_BACKFILL_BATCH: usize = 10_000;

/// Tip-ordered receipt index key. The tx hash is part of the key so a reverse
/// slice of the tree yields the newest `(height, index)` rows directly.
pub(super) fn receipt_index_key(r: &StoredReceipt) -> [u8; RECEIPT_INDEX_KEY_LEN] {
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

impl Storage {
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

    // ---------- Validator-set activation history (P0-PEER-SNAPSHOT-ANCHOR) ----------

    const VALIDATOR_SET_HISTORY_META_KEY: &'static [u8] = b"validator_set_history_v1";

    /// Persist the ordered `(activation_height, ValidatorSet)` history in `"meta"`
    /// so restarts retain exact per-height validator sets for snapshot anchor
    /// and tip-QC verification.
    pub fn put_validator_set_history(
        &self,
        history: &[(u64, crate::consensus::ValidatorSet)],
    ) -> Result<()> {
        let encoded = bincode::serialize(history)?;
        self.meta
            .insert(Self::VALIDATOR_SET_HISTORY_META_KEY, encoded.as_slice())?;
        Ok(())
    }

    /// Load persisted `(activation_height, ValidatorSet)` history from `"meta"`,
    /// if present.
    pub fn load_validator_set_history(
        &self,
    ) -> Result<Option<Vec<(u64, crate::consensus::ValidatorSet)>>> {
        let Some(bytes) = self.meta.get(Self::VALIDATOR_SET_HISTORY_META_KEY)? else {
            return Ok(None);
        };
        let mut entries: Vec<(u64, crate::consensus::ValidatorSet)> = bincode::deserialize(&bytes)?;
        entries.sort_by_key(|(h, _)| *h);
        Ok(Some(entries))
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
    pub(super) fn ensure_receipt_height_index(&self) -> Result<()> {
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
}
