use super::mesh_now_ms;
use super::naming::{
    block_body_blob_name, block_name, head_name, header_index_name, header_name, header_qc_name,
    header_v2_name, snapshot_latest_name, snapshot_name, snapv4_manifest_name, snapv4_unit_name,
    MempoolEntry, BUCKET_STELLEREUM_BLOCKS, BUCKET_STELLEREUM_HEAD, BUCKET_STELLEREUM_HEADERS,
    BUCKET_STELLEREUM_STATE, PREFIX_LATEST_HEIGHT, PREFIX_MEMPOOL_TX, PREFIX_MEV_COMMIT,
    PREFIX_ORACLE, PREFIX_SHARD_MEMPOOL,
};
use super::retention::parse_header_index;
use super::P2pNetworkAdapter;
use crate::mev::BlindRoundCommitment;
use crate::oracle::PriceFeedUpdate;
use crate::sharding::{Block, Transaction};
use infnode::node::Node;
use std::sync::Arc;

/// Decode one hex-encoded oracle feed from local KV and re-verify the
/// publisher signature before serving it.
///
/// Pure so the G5 fail-closed rule is testable without a live DHT: malformed
/// bytes, a tampered price, or a forged publisher key all read as `None`
/// (a miss), never as market evidence.
pub fn decode_verified_price_feed(val_hex: &str) -> Option<PriceFeedUpdate> {
    let bytes = hex::decode(val_hex.trim()).ok()?;
    let feed: PriceFeedUpdate = decode_wire_limited(&bytes, MAX_WIRE_SMALL_BYTES).ok()?;
    feed.verify().then_some(feed)
}

/// Bounded per-(shard, height) exponential miss backoff for `fetch_block_qc`.
///
/// Prevents a node stuck one block behind from hammering peers with repeated
/// `dht.find_value` calls on the same missing `_hq_{shard}_{height}` sidecar
/// every reactive catch-up tick (~500ms-1.4s). First probe for `(shard, height)`
/// is always immediate; consecutive misses back off `300ms -> 600ms -> 1.2s ->
/// 2.4s -> 4.8s -> 5s`, and any hit clears the entry.
///
/// The base used to be 2000ms, which charged a full 2s for the FIRST miss even
/// when the QC demonstrably existed (the proposer had quorum precommits and was
/// merely slower than the reader). The live cost was a 2s+ stall per missed
/// sidecar (block #21508: `fetch_block_qc ... failed; backing off 2000ms`).
/// A sub-second first cooldown keeps the anti-hammer property without pricing
/// a single lost packet at five blocks.
#[derive(Debug, Clone, Default)]
pub struct QcMissBackoff {
    entries: std::collections::HashMap<(u32, u64), QcMissEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QcMissEntry {
    misses: u32,
    next_probe_at_ms: u64,
}

impl QcMissBackoff {
    pub const BASE_MS: u64 = 300;
    pub const MAX_MS: u64 = 5_000;
    pub const CAP: usize = 128;

    /// Returns `true` when `(shard_id, height)` is still inside its cooldown
    /// window at `now_ms` and should skip querying the DHT.
    pub fn should_skip(&self, shard_id: u32, height: u64, now_ms: u64) -> bool {
        self.entries
            .get(&(shard_id, height))
            .is_some_and(|e| now_ms < e.next_probe_at_ms)
    }

    /// Record a QC fetch miss for `(shard_id, height)` at `now_ms`, returning
    /// the applied backoff duration in milliseconds.
    pub fn record_miss(&mut self, shard_id: u32, height: u64, now_ms: u64) -> u64 {
        let misses = self
            .entries
            .get(&(shard_id, height))
            .map(|e| e.misses.saturating_add(1))
            .unwrap_or(1);
        // Doubling tiers: 300, 600, 1200, 2400, 4800, then clamped to MAX_MS.
        let shift = misses.saturating_sub(1).min(8);
        let backoff_ms = Self::BASE_MS
            .saturating_mul(1u64 << shift)
            .min(Self::MAX_MS);
        if self.entries.len() >= Self::CAP && !self.entries.contains_key(&(shard_id, height)) {
            // Evict the oldest/earliest-expiring entry to stay strictly bounded.
            if let Some(evict_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.next_probe_at_ms)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&evict_key);
            }
        }
        self.entries.insert(
            (shard_id, height),
            QcMissEntry {
                misses,
                next_probe_at_ms: now_ms.saturating_add(backoff_ms),
            },
        );
        backoff_ms
    }

    /// Drop any miss backoff for `(shard_id, height)`.
    ///
    /// Called when a QC for that height is obtained by ANY path: a successful
    /// `_hq_` fetch (`record_hit`), a QC carried by a consensus `Committed`
    /// message, or one read from local storage. The next probe of this height
    /// must be immediate — carrying a stale cooldown past a known QC could
    /// delay a catch-up for no reason.
    pub fn clear(&mut self, shard_id: u32, height: u64) {
        self.entries.remove(&(shard_id, height));
    }

    /// Clear any miss backoff for `(shard_id, height)` once a QC is obtained.
    pub fn record_hit(&mut self, shard_id: u32, height: u64) {
        self.clear(shard_id, height);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Whether a peer-advertised head is actionable for a node at `our_height`.
///
/// The shared head key carries no author, so our own last publish reads back as
/// "a peer head". Only a STRICTLY ahead head means someone knows more than us;
/// anything else (own echo, stale peer) is "nothing to do", never a reason to
/// move. Pure so tests pin it without a live DHT.
pub fn peer_head_is_ahead(our_height: u64, peer_height: u64) -> bool {
    peer_height > our_height
}

/// Process-wide bound on concurrent DHT fetches (storm guard 2026-10-13).
///
/// Every `fetch_*` below funnels through `fetch_blob`, and each `fetch_blob`
/// fans out to manifest + per-chunk lookups. Without a cap, overlapping
/// catch-up subtasks (128 snapshot probes, 8-height tail anchor × 3 fetches,
/// 7 domain blobs, body walk) plus background replication pushes exceed the
/// 256-stream per-connection limit, get dropped (`too many concurrent
/// streams`), time out at ~2.5s, retry, and re-flood. The cap mirrors
/// `sync::ADOPT_REPL_MAX_CONCURRENCY` (8): the sequential hot path holds 1
/// permit and is unaffected; only parallel bursts queue.
///
/// Follow-up: entry is not enough for tens-of-MB snapshots (tens of chunks
/// per blob hold their streams for whole chunk bodies), so snapshot/domain
/// fetches additionally take the narrow [`snapshot_fetch_sem`] lane
/// (`sync::SNAPSHOT_FETCH_MAX_CONCURRENCY`), and retries sleep a jittered
/// backoff (`sync::fetch_retry_backoff_with_jitter_ms`) instead of
/// re-flooding on the same tick.
pub(super) fn fetch_sem() -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| tokio::sync::Semaphore::new(crate::sync::FETCH_MAX_CONCURRENCY.max(1)))
}

/// Process-wide lane for LARGE-blob (snapshot/domain) fetches: at most
/// [`crate::sync::SNAPSHOT_FETCH_MAX_CONCURRENCY`] snapshot-sized blobs
/// assemble at once.
///
/// Nesting order is ALWAYS fetch-permit first, snapshot-lane second (see
/// `fetch_state_snapshot`): a consistent global order, so two lanes can never
/// deadlock. Small fetches never touch this lane.
pub(super) fn snapshot_fetch_sem() -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| {
        tokio::sync::Semaphore::new(crate::sync::SNAPSHOT_FETCH_MAX_CONCURRENCY.max(1))
    })
}

/// Hard bound on chunk count in a snapshot manifest (`SNAP-MANIFEST-DOS`).
pub const MAX_BLOB_CHUNKS: usize = infnode::node::MAX_BLOB_CHUNKS;
/// Hard bound on single-chunk wire length (`1 MiB`).
pub const BLOB_CHUNK_BYTES: usize = infnode::node::BLOB_CHUNK_BYTES;
/// Hard bound on total snapshot blob bytes (`512 MiB`, `MAX_SNAPSHOT_DECODE_BYTES`).
pub const MAX_BLOB_BYTES: usize = crate::snapshot_v4::MAX_SNAPSHOT_DECODE_BYTES as usize;
/// Hard bound on raw JSON manifest string size (`4 MiB`).
pub const MAX_SNAPSHOT_JSON_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

const _: () = assert!(
    MAX_WIRE_BLOCK_BYTES as usize <= infnode::node::MAX_UNSEALED_BLOB_BYTES,
    "MAX_WIRE_BLOCK_BYTES must fit within infnode MAX_UNSEALED_BLOB_BYTES"
);

/// One chunk entry of a snapshot manifest, resolved for resumable fetch.
///
/// `id` addresses the chunk bytes (`fetch_chunk_net`); `hash` is the mandatory
/// 32-byte BLAKE3 integrity commitment from the manifest (`SNAP-MANIFEST-DOS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotChunkMeta {
    pub id: String,
    pub hash: String,
}

/// Verify that `blake3(bytes) == expected_hash`.
pub fn verify_bytes_blake3_hash(bytes: &[u8], expected_hash: &[u8; 32]) -> bool {
    *blake3::hash(bytes).as_bytes() == *expected_hash
}

/// Parse and strictly validate a snapshot blob JSON manifest BEFORE allocating
/// chunk tables or issuing chunk fetches (`SNAP-MANIFEST-DOS`).
///
/// Enforces:
/// - `manifest_str.len() <= MAX_SNAPSHOT_JSON_MANIFEST_BYTES`
/// - `size <= MAX_BLOB_BYTES` (`512 MiB`)
/// - `chunks.len() <= MAX_BLOB_CHUNKS` (`4096`) and `<= size.div_ceil(1 MiB) + 2`
/// - non-empty safe `id` and mandatory valid 32-byte hex `hash` on EVERY chunk
/// - contiguous `off` / bounded `len` when `off`/`len` fields are present
#[allow(clippy::type_complexity)]
// GATE: 4-tuple return preserves existing parse_and_validate_snapshot_manifest public signature without churn.
pub fn parse_and_validate_snapshot_manifest(
    manifest_str: &str,
) -> Result<(Vec<SnapshotChunkMeta>, [u8; 32], Vec<u8>, usize), String> {
    if manifest_str.len() > MAX_SNAPSHOT_JSON_MANIFEST_BYTES {
        return Err(format!(
            "manifest string length {} exceeds max {}",
            manifest_str.len(),
            MAX_SNAPSHOT_JSON_MANIFEST_BYTES
        ));
    }
    let manifest: serde_json::Value =
        serde_json::from_str(manifest_str).map_err(|e| format!("manifest undecodable: {e:?}"))?;
    let nonce_str = manifest["nonce"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing or empty nonce".to_string())?;
    let nonce = hex::decode(nonce_str).map_err(|_| "bad nonce hex".to_string())?;
    let key = hex::decode(manifest["key"].as_str().unwrap_or(""))
        .map_err(|_| "bad key hex".to_string())?;
    if key.len() != 32 {
        return Err(format!("key is {} bytes, want 32", key.len()));
    }
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&key);

    let size_u64 = manifest["size"]
        .as_u64()
        .ok_or_else(|| "missing u64 size".to_string())?;
    if size_u64 > MAX_BLOB_BYTES as u64 {
        return Err(format!(
            "declared size {size_u64} exceeds MAX_BLOB_BYTES ({MAX_BLOB_BYTES})"
        ));
    }
    let size = usize::try_from(size_u64).map_err(|_| "size overflows usize".to_string())?;

    let chunks = manifest["chunks"]
        .as_array()
        .ok_or_else(|| "missing chunks array".to_string())?;
    if chunks.len() > MAX_BLOB_CHUNKS {
        return Err(format!(
            "chunk count {} exceeds MAX_BLOB_CHUNKS ({MAX_BLOB_CHUNKS})",
            chunks.len()
        ));
    }
    let max_by_size = size.div_ceil(BLOB_CHUNK_BYTES).saturating_add(2);
    if (chunks.is_empty() && size > 0) || chunks.len() > max_by_size {
        return Err(format!(
            "chunk count {} inconsistent with declared size {size} (max {max_by_size})",
            chunks.len()
        ));
    }

    let mut metas = Vec::with_capacity(chunks.len());
    let mut expected_off = 0usize;
    for (idx, c) in chunks.iter().enumerate() {
        let id = c["id"]
            .as_str()
            .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains('\\') && !s.contains(".."))
            .ok_or_else(|| format!("chunk {idx} has missing or unsafe id"))?;
        let hash_str = c
            .get("hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| format!("chunk {idx} missing mandatory hash"))?;
        let hash_bytes =
            hex::decode(hash_str).map_err(|_| format!("chunk {idx} has invalid hex hash"))?;
        if hash_bytes.len() != 32 {
            return Err(format!(
                "chunk {idx} hash is {} bytes, want 32",
                hash_bytes.len()
            ));
        }
        if c.get("off").is_some() || c.get("len").is_some() {
            let off_u64 = c
                .get("off")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("chunk {idx} has malformed off"))?;
            let len_u64 = c
                .get("len")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("chunk {idx} has malformed len"))?;
            let off = usize::try_from(off_u64).map_err(|_| "chunk off overflow".to_string())?;
            let len = usize::try_from(len_u64).map_err(|_| "chunk len overflow".to_string())?;
            if off != expected_off || len == 0 || len > BLOB_CHUNK_BYTES {
                return Err(format!(
                    "chunk {idx} non-contiguous or oversized (off={off}, expected={expected_off}, len={len})"
                ));
            }
            expected_off = expected_off
                .checked_add(len)
                .ok_or_else(|| "chunk table total length overflow".to_string())?;
            if expected_off > MAX_BLOB_BYTES + 64 {
                return Err(format!(
                    "chunk table total length {expected_off} exceeds MAX_BLOB_BYTES ({MAX_BLOB_BYTES})"
                ));
            }
        }
        metas.push(SnapshotChunkMeta {
            id: id.to_string(),
            hash: hash_str.to_string(),
        });
    }
    Ok((metas, dk, nonce, size))
}

impl P2pNetworkAdapter {
    /// Fetch a block from the P2P overlay network by hash
    pub async fn fetch_block(&self, block_hash: &[u8; 32]) -> Option<Block> {
        let permit = fetch_sem().acquire().await.ok()?;
        let hash_hex = hex::encode(block_hash);
        let bytes = tokio::time::timeout(
            std::time::Duration::from_millis(15_000),
            self.node.fetch_blob(
                BUCKET_STELLEREUM_BLOCKS,
                &block_name(&self.epoch(), &hash_hex),
            ),
        )
        .await
        .ok()
        .flatten()?;
        drop(permit);

        decode_wire_limited(&bytes, MAX_WIRE_BLOCK_BYTES).ok()
    }

    /// Query the latest block height and hash for a given shard from the DHT
    pub async fn get_latest_shard_height(&self, shard_id: u32) -> Option<(u64, [u8; 32])> {
        let height_kv_key = format!("{}{}", PREFIX_LATEST_HEIGHT, shard_id);
        let val_str = self.node.get_local_kv(&height_kv_key).await?;

        let parts: Vec<&str> = val_str.split(':').collect();
        if parts.len() == 2 {
            let height = parts[0].parse::<u64>().ok()?;
            let hash_vec = hex::decode(parts[1]).ok()?;
            if hash_vec.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_vec);
                return Some((height, hash));
            }
        }
        None
    }

    /// Read the most recently published shard head from the network.
    ///
    /// This is a best-effort "somebody told us about a head". It may well be our
    /// own, so callers must treat a result that is not strictly ahead of their own
    /// finalized height as "nothing to do" rather than as a peer being ahead.
    pub async fn fetch_head(&self, shard_id: u32) -> Option<(u64, [u8; 32])> {
        let permit = fetch_sem().acquire().await.ok()?;
        let bytes = tokio::time::timeout(
            std::time::Duration::from_millis(10_000),
            self.node
                .fetch_blob(BUCKET_STELLEREUM_HEAD, &head_name(&self.epoch(), shard_id)),
        )
        .await
        .ok()
        .flatten()?;
        drop(permit);
        let s = String::from_utf8(bytes).ok()?;
        let mut it = s.split(':');
        let height = it.next()?.parse::<u64>().ok()?;
        let raw = hex::decode(it.next()?).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw);
        Some((height, hash))
    }

    /// Fetch the block hash published for `height`, or `None` if nobody published it.
    ///
    /// Retried (3 attempts, backoff) with one loud line on final failure:
    /// header index blobs are tiny, so a miss is either pruning or a weak
    /// link — both worth exactly one line, never silence (a silent miss here
    /// kills a whole snapshot-sync attempt with zero trace).
    pub async fn fetch_head_hash(&self, shard_id: u32, height: u64) -> Option<[u8; 32]> {
        self.fetch_head_hash_inner(shard_id, height, 3, 10_000, true)
            .await
    }

    /// Lightweight 1-attempt height-index lookup for concurrent catch-up prefetch
    /// (3s timeout, no sleep backoff; misses fall back seamlessly to backward `prev_hash` walk).
    pub async fn fetch_head_hash_probe(&self, shard_id: u32, height: u64) -> Option<[u8; 32]> {
        self.fetch_head_hash_inner(shard_id, height, 1, 3_000, false)
            .await
    }

    async fn fetch_head_hash_inner(
        &self,
        shard_id: u32,
        height: u64,
        max_attempts: u32,
        timeout_ms: u64,
        log_failure: bool,
    ) -> Option<[u8; 32]> {
        let name = header_index_name(&self.epoch(), shard_id, height);
        let mut last_err = "missing";
        let attempts = max_attempts.max(1);
        for attempt in 1..=attempts {
            let permit = fetch_sem().acquire().await.ok()?;
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
            drop(permit);
            if let Some(bytes) = blob_res {
                // VERIFICATION F4-hardening: parse through the VALIDATED
                // index parser (`parse_header_index`), not an ad-hoc split.
                // The old inline parse took the first two `:` segments and
                // accepted anything `hex::decode` swallowed — so a malicious
                // index blob `"5:<64hex>:evil"` (or any trailing segment)
                // parsed as a clean height/hash pair, while the prune path
                // (which uses the validated parser) refused it. One parser,
                // one verdict everywhere.
                if let Some((_h, hash_hex)) = parse_header_index(&bytes) {
                    if let Ok(raw) = hex::decode(&hash_hex) {
                        if raw.len() == 32 {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&raw);
                            return Some(out);
                        }
                        last_err = "bad length";
                    } else {
                        last_err = "bad hex";
                    }
                } else {
                    last_err = "bad format";
                }
            } else {
                last_err = "fetch miss/timeout";
            }
            if attempt < attempts {
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt as u64)).await;
            }
        }
        if log_failure {
            eprintln!("[sync] fetch_head_hash shard={shard_id} height={height} name={name}: failed ({last_err})");
        }
        None
    }

    /// Fetch a v2 header record by shard, height, and expected hash.
    ///
    /// When `header_commit_active_at(height)` is true, fails closed unless
    /// `rec.header.compute_hash() == expected_hash`.
    pub async fn fetch_block_header_v2(
        &self,
        shard_id: u32,
        height: u64,
        expected_hash: [u8; 32],
    ) -> Option<crate::storage::BlockHeaderRecordV2> {
        let name = header_v2_name(&self.epoch(), shard_id, height);
        let mut last_err = "missing";
        for attempt in 1..=3u32 {
            let permit = fetch_sem().acquire().await.ok()?;
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
            drop(permit);
            if let Some(bytes) = blob_res {
                match decode_wire_limited::<crate::storage::BlockHeaderRecordV2>(
                    &bytes,
                    MAX_WIRE_SMALL_BYTES,
                ) {
                    Ok(rec) => {
                        if rec.header.shard_id == shard_id
                            && rec.header.height == height
                            && rec.block_hash == expected_hash
                        {
                            if !crate::sharding::header_commit_active_at(height)
                                || rec.header.compute_hash() == expected_hash
                            {
                                return Some(rec);
                            }
                            last_err = "v4 compute_hash mismatch";
                        } else {
                            last_err = "shard/hash/height mismatch";
                        }
                    }
                    Err(_) => last_err = "bad bincode",
                }
            } else {
                last_err = "fetch miss/timeout";
            }
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt as u64)).await;
            }
        }
        eprintln!("[sync] fetch_block_header_v2 shard={shard_id} height={height} name={name}: failed ({last_err})");
        None
    }

    /// Fetch a header by height AND hash, refusing one that does not match the hash.
    ///
    /// The hash argument is what makes this trustworthy: a peer cannot hand us a
    /// header for a different block under this height, because the record's own
    /// `block_hash` must equal the hash we asked for. At `header_commit_active_at(height)`,
    /// requires [`Self::fetch_block_header_v2`] and `rec.header.compute_hash() == expected_hash`.
    pub async fn fetch_block_header(
        &self,
        shard_id: u32,
        height: u64,
        expected_hash: [u8; 32],
    ) -> Option<crate::storage::BlockHeaderRecord> {
        if crate::sharding::header_commit_active_at(height) {
            let v2 = self
                .fetch_block_header_v2(shard_id, height, expected_hash)
                .await?;
            return Some(crate::storage::BlockHeaderRecord {
                height: v2.header.height,
                prev_hash: v2.header.prev_hash,
                state_root: v2.header.state_root,
                proposer: v2.header.proposer,
                timestamp: v2.header.timestamp,
                tx_count: v2.tx_count,
                gas_used: v2.gas_used,
                block_hash: v2.block_hash,
            });
        }
        let name = header_name(&self.epoch(), height);
        let mut last_err = "missing";
        for attempt in 1..=3u32 {
            let permit = fetch_sem().acquire().await.ok()?;
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
            drop(permit);
            if let Some(bytes) = blob_res {
                match decode_wire_limited::<crate::storage::BlockHeaderRecord>(
                    &bytes,
                    MAX_WIRE_SMALL_BYTES,
                ) {
                    Ok(rec) => {
                        if rec.height == height && rec.block_hash == expected_hash {
                            return Some(rec);
                        }
                        last_err = "hash/height mismatch";
                    }
                    Err(_) => last_err = "bad bincode",
                }
            } else {
                last_err = "fetch miss/timeout";
            }
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt as u64)).await;
            }
        }
        eprintln!("[sync] fetch_block_header shard={shard_id} height={height} name={name}: failed ({last_err})");
        None
    }

    /// Fetch a height's precommit-QC sidecar (A1 anchor). Fail-closed `None`
    /// on any error: corrupt bytes, missing blob (pruned, or published by a
    /// pre-sidecar node), or a QC that does not bind this height. Callers
    /// treat `None` as "not anchorable here", never as trusted.
    pub async fn fetch_block_qc(
        &self,
        shard_id: u32,
        height: u64,
    ) -> Option<crate::consensus::QuorumCertificate> {
        self.fetch_block_qc_inner(shard_id, height, 3).await
    }

    /// Drop any `_hq_` miss cooldown for `(shard, height)`.
    ///
    /// For callers that obtained the QC by a path OTHER than
    /// [`Self::fetch_block_qc`] — a consensus `Committed` message, or a QC
    /// read from local storage. PRECONDITION: the QC must have been decoded
    /// and validated for exactly this `(shard, height)`; this is never called
    /// on a hint or a "maybe". The next probe of this height then becomes
    /// immediate; `fetch_block_qc` clears the entry itself on a decoded,
    /// height-bound hit.
    pub fn clear_qc_backoff(&self, shard_id: u32, height: u64) {
        if let Ok(mut g) = self.qc_miss_backoff.lock() {
            g.clear(shard_id, height);
        }
    }

    /// Lightweight 1-attempt precommit-QC sidecar probe for `blind-QC-probe`.
    /// Shares the per-`(shard_id, height)` exponential miss backoff with
    /// [`Self::fetch_block_qc`] so repeated catch-up ticks never flood peers
    /// with `dht.find_value` requests for a missing `_hq_` sidecar.
    pub async fn fetch_block_qc_probe(
        &self,
        shard_id: u32,
        height: u64,
    ) -> Option<crate::consensus::QuorumCertificate> {
        self.fetch_block_qc_inner(shard_id, height, 1).await
    }

    async fn fetch_block_qc_inner(
        &self,
        shard_id: u32,
        height: u64,
        max_attempts: u32,
    ) -> Option<crate::consensus::QuorumCertificate> {
        let now_ms = mesh_now_ms();
        if self
            .qc_miss_backoff
            .lock()
            .is_ok_and(|g| g.should_skip(shard_id, height, now_ms))
        {
            return None;
        }
        let name = header_qc_name(&self.epoch(), shard_id, height);
        let mut last_err = "missing";
        let attempts = max_attempts.max(1);
        for attempt in 1..=attempts {
            let permit = fetch_sem().acquire().await.ok()?;
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
            drop(permit);
            if let Some(bytes) = blob_res {
                match decode_wire_limited::<crate::consensus::QuorumCertificate>(
                    &bytes,
                    MAX_WIRE_SMALL_BYTES,
                ) {
                    Ok(qc) => {
                        // Clear the miss cooldown only for a QC that DECODED
                        // and binds THIS height. A corrupt/foreign sidecar is
                        // a miss, not a hit, and must not lift the backoff
                        // (callers still run full quorum verification).
                        if qc.height == height {
                            if let Ok(mut g) = self.qc_miss_backoff.lock() {
                                g.record_hit(shard_id, height);
                            }
                        }
                        return Some(qc);
                    }
                    Err(_) => last_err = "bad bincode",
                }
            } else {
                last_err = "fetch miss/timeout";
            }
            if attempt < attempts {
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt as u64)).await;
            }
        }
        let backoff_ms = self
            .qc_miss_backoff
            .lock()
            .map(|mut g| g.record_miss(shard_id, height, mesh_now_ms()))
            .unwrap_or(QcMissBackoff::BASE_MS);
        eprintln!(
            "[sync] fetch_block_qc shard={shard_id} height={height} name={name}: failed ({last_err}); backing off {backoff_ms}ms"
        );
        None
    }

    /// Read the latest-snapshot pointer (exact height of the newest published
    /// state snapshot), if any peer published one. Returns `None` on miss —
    /// callers fall back to the %100 probe walk.
    pub async fn fetch_latest_snapshot(&self, shard_id: u32) -> Option<u64> {
        let name = snapshot_latest_name(&self.epoch(), shard_id);
        for attempt in 1..=3u32 {
            let permit = fetch_sem().acquire().await.ok()?;
            let bytes_opt = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_STATE, &name),
            )
            .await
            .ok()
            .flatten();
            drop(permit);
            if let Some(bytes) = bytes_opt {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    let h = u64::from_le_bytes(arr);
                    if h > 0 {
                        tracing::info!(
                            "[sync] fetch_latest_snapshot {name}: pointer={h} (attempt {attempt})"
                        );
                        return Some(h);
                    }
                }
            }
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(150 * attempt as u64)).await;
            }
        }
        tracing::debug!("[sync] fetch_latest_snapshot {name}: missed after 3 attempts");
        None
    }

    /// Fetch in-memory state snapshot by shard ID and block height
    ///
    /// Large-blob lane: takes the narrow snapshot semaphore INSIDE the
    /// process-wide fetch permit, so tens-of-MB snapshots assemble at most
    /// [`crate::sync::SNAPSHOT_FETCH_MAX_CONCURRENCY`] at a time while small
    /// fetches keep the full 8. Yields once on return so a just-assembled
    /// multi-megabyte body does not hand the executor straight to the next
    /// heavy fetch on a 1-vCPU node.
    ///
    /// Resumable assembly ([`Self::fetch_large_blob_resumable`]): one dropped
    /// chunk retries just that chunk (completed chunks are never re-ordered),
    /// under the generous snapshot budget (tens of MB is normal). A `None`
    /// is always logged loudly with size/chunk/budget — never silent.
    pub async fn fetch_state_snapshot(&self, shard_id: u32, height: u64) -> Option<Vec<u8>> {
        let name = snapshot_name(&self.epoch(), shard_id, height);
        let out =
            Self::fetch_large_blob_resumable(&self.node, BUCKET_STELLEREUM_STATE, &name).await;
        if out.is_none() {
            eprintln!(
                "[sync] fetch_state_snapshot shard={shard_id} height={height} name={name}: \
                 unavailable (see [sync] snapshot-fetch lines above for size/chunk/budget)"
            );
        }
        tokio::task::yield_now().await;
        out
    }

    /// Fetch a blob manifest (small) under its own budget, separate from chunks.
    ///
    /// One attempt: local manifest first, then the DHT `dht.find_value`
    /// sweep — the same two sources `fetch_blob` consults, but wrapped in
    /// [`crate::sync::SNAPSHOT_MANIFEST_TIMEOUT_MS`] so a missing manifest
    /// ("boundary not published") fails fast instead of burning the chunk
    /// budget. Returns the parsed chunk metas plus the decryption key, nonce
    /// and declared plaintext size. Loud `None`: every miss logs
    /// bucket/name/attempt/timeout.
    async fn fetch_snapshot_manifest(
        node: &Arc<Node>,
        bucket: &str,
        name: &str,
    ) -> Option<(Vec<SnapshotChunkMeta>, [u8; 32], Vec<u8>, usize)> {
        use futures::stream::{FuturesUnordered, StreamExt};
        let mkey = Node::blob_manifest_key(bucket, name);
        let attempt = tokio::time::timeout(
            std::time::Duration::from_millis(crate::sync::SNAPSHOT_MANIFEST_TIMEOUT_MS),
            async {
                if let Some(local) = node.get_local_kv(&mkey).await {
                    return Some(local);
                }
                let h = blake3::hash(mkey.as_bytes());
                let mut target = [0u8; infnode::proto::NODEID_LEN];
                target.copy_from_slice(&h.as_bytes()[..infnode::proto::NODEID_LEN]);
                let closest = node.dht_find_node(&target).await;
                let q = serde_json::json!({ "key": mkey }).to_string().into_bytes();
                const MANIFEST_PROBE_CONCURRENCY: usize = 4;
                const MANIFEST_PEER_TIMEOUT_MS: u64 = 2_500;
                let mut iter = closest.into_iter();
                let mut in_flight = FuturesUnordered::new();
                let spawn_probe = |n: infnode::dht::NodeInfo| {
                    let node = Arc::clone(node);
                    let q = q.clone();
                    async move {
                        tokio::time::timeout(
                            std::time::Duration::from_millis(MANIFEST_PEER_TIMEOUT_MS),
                            async move {
                                if node.ensure_dht_peer(&n).await.is_ok() {
                                    if let Ok(resp) =
                                        node.request_to(n.id, "dht.find_value", q).await
                                    {
                                        if let Ok(v) =
                                            serde_json::from_slice::<serde_json::Value>(&resp)
                                        {
                                            if v["found"].as_bool().unwrap_or(false) {
                                                if let Some(s) = v["value"].as_str() {
                                                    return Some(s.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                                None
                            },
                        )
                        .await
                        .ok()
                        .flatten()
                    }
                };
                for _ in 0..MANIFEST_PROBE_CONCURRENCY {
                    if let Some(n) = iter.next() {
                        in_flight.push(spawn_probe(n));
                    }
                }
                while let Some(res) = in_flight.next().await {
                    if let Some(s) = res {
                        return Some(s);
                    }
                    if let Some(n) = iter.next() {
                        in_flight.push(spawn_probe(n));
                    }
                }
                None
            },
        )
        .await;
        let manifest_str = match attempt {
            Ok(Some(s)) => s,
            Ok(None) => {
                eprintln!(
                    "[sync] snapshot-fetch manifest miss: {bucket}/{name} \
                     (no local manifest, DHT sweep found nothing; boundary likely unpublished)"
                );
                return None;
            }
            Err(_) => {
                eprintln!(
                    "[sync] snapshot-fetch manifest timeout: {bucket}/{name} \
                     (no manifest within {}ms; weak link or unpublished boundary)",
                    crate::sync::SNAPSHOT_MANIFEST_TIMEOUT_MS
                );
                return None;
            }
        };
        match parse_and_validate_snapshot_manifest(&manifest_str) {
            Ok(parsed) => Some(parsed),
            Err(reason) => {
                eprintln!(
                    "[sync] snapshot-fetch manifest rejected: {bucket}/{name}: {reason} (treating as miss)"
                );
                None
            }
        }
    }

    /// Resumable large-blob fetch: manifest + per-chunk assembly with resume.
    ///
    /// WHERE THE OLD PATH DIED: `fetch_blob` walks chunks serially and `got?`
    /// aborts the WHOLE blob on the first missing chunk — on a weak link
    /// (RTT 2.5s+, jitter, drops) a 50-chunk snapshot almost surely loses ≥1
    /// chunk, so every attempt returned a silent `None` and the observer sat
    /// ~1500 behind forever while small fetches (1 chunk) sailed through.
    ///
    /// This keeps the serial shape (exactly one chunk stream at a time — the
    /// semaphore/batch discipline is untouched) but:
    /// * the manifest is fetched under its own small budget
    ///   ([`crate::sync::SNAPSHOT_MANIFEST_TIMEOUT_MS`]);
    /// * chunks assemble via [`crate::sync::assemble_chunks_resumable`]: a
    ///   dropped chunk retries JUST that chunk (up to
    ///   [`crate::sync::SNAPSHOT_CHUNK_RETRIES`], each attempt bounded by
    ///   [`crate::sync::SNAPSHOT_CHUNK_TIMEOUT_MS`]); completed chunks are
    ///   never re-requested within an attempt;
    /// * the whole blob is bounded by [`crate::sync::snapshot_blob_budget_ms`]
    ///   and retried at most [`crate::sync::SNAPSHOT_BLOB_ATTEMPTS`] times;
    /// * every `None` is loud (bucket/name/size/chunk-index/attempt/budget);
    /// * a `yield_now` runs after every chunk and every backoff so the tick
    ///   never hangs on a 1-vCPU node.
    async fn fetch_large_blob_resumable(
        node: &Arc<Node>,
        bucket: &str,
        name: &str,
    ) -> Option<Vec<u8>> {
        for blob_attempt in 1..=crate::sync::SNAPSHOT_BLOB_ATTEMPTS {
            let permit = fetch_sem().acquire().await.ok()?;
            let snap_permit = snapshot_fetch_sem().acquire().await.ok()?;
            let Some((metas, dk, nonce, size)) =
                Self::fetch_snapshot_manifest(node, bucket, name).await
            else {
                drop(snap_permit);
                drop(permit);
                eprintln!(
                    "[sync] snapshot-fetch {bucket}/{name}: manifest attempt \
                     {blob_attempt}/{} missed (see manifest line above)",
                    crate::sync::SNAPSHOT_BLOB_ATTEMPTS
                );
                if blob_attempt < crate::sync::SNAPSHOT_BLOB_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        crate::sync::fetch_retry_backoff_with_jitter_ms(
                            blob_attempt,
                            rand::random::<u64>(),
                        ),
                    ))
                    .await;
                    tokio::task::yield_now().await;
                    continue;
                }
                return None;
            };
            let n_chunks = metas.len();
            eprintln!(
                "[sync] snapshot-fetch {bucket}/{name}: manifest ok, {size} bytes in \
                 {n_chunks} chunks (attempt {blob_attempt}/{}; per-chunk timeout {}ms, \
                 {} retries/chunk)",
                crate::sync::SNAPSHOT_BLOB_ATTEMPTS,
                crate::sync::SNAPSHOT_CHUNK_TIMEOUT_MS,
                crate::sync::SNAPSHOT_CHUNK_RETRIES
            );
            let budget = crate::sync::snapshot_blob_budget_ms(n_chunks);
            let assembled = tokio::time::timeout(
                std::time::Duration::from_millis(budget),
                crate::sync::assemble_chunks_resumable(
                    n_chunks,
                    crate::sync::SNAPSHOT_CHUNK_RETRIES,
                    |i| {
                        let node = node.clone();
                        let meta = &metas[i];
                        let cid = meta.id.clone();
                        let expected = meta.hash.clone();
                        let bucket = bucket.to_string();
                        async move {
                            let got = tokio::time::timeout(
                                std::time::Duration::from_millis(
                                    crate::sync::SNAPSHOT_CHUNK_TIMEOUT_MS,
                                ),
                                node.fetch_chunk_net(&bucket, &cid, Some(expected.as_str())),
                            )
                            .await;
                            match got {
                                Ok(Some(bytes)) => {
                                    if bytes.len() > BLOB_CHUNK_BYTES {
                                        eprintln!(
                                            "[sync] snapshot-fetch {bucket}/{cid}: chunk {i} length {} exceeds BLOB_CHUNK_BYTES ({BLOB_CHUNK_BYTES}); discarding",
                                            bytes.len()
                                        );
                                        return None;
                                    }
                                    Some(bytes)
                                }
                                Ok(None) => {
                                    tracing::debug!(
                                        "[sync] snapshot-fetch {bucket}/{cid}: chunk {i} \
                                         miss this attempt (drop/slow peer/tamper)"
                                    );
                                    None
                                }
                                Err(_) => {
                                    tracing::debug!(
                                        "[sync] snapshot-fetch {bucket}/{cid}: chunk {i} \
                                         timed out after {}ms this attempt",
                                        crate::sync::SNAPSHOT_CHUNK_TIMEOUT_MS
                                    );
                                    None
                                }
                            }
                        }
                    },
                ),
            )
            .await;
            match assembled {
                Err(_) => {
                    eprintln!(
                        "[sync] snapshot-fetch {bucket}/{name}: blob timeout after {budget}ms \
                         for {size} bytes in {n_chunks} chunks (attempt {blob_attempt}/{}; \
                         weak link stalled harder than the generous budget)",
                        crate::sync::SNAPSHOT_BLOB_ATTEMPTS
                    );
                }
                Ok(Err(fail)) => {
                    eprintln!(
                        "[sync] snapshot-fetch {bucket}/{name}: {fail} (blob {size} bytes; \
                         attempt {blob_attempt}/{})",
                        crate::sync::SNAPSHOT_BLOB_ATTEMPTS
                    );
                }
                Ok(Ok(chunks)) => {
                    let total_ct: Option<usize> = chunks
                        .iter()
                        .try_fold(0usize, |acc, c| acc.checked_add(c.len()));
                    let Some(total_ct) = total_ct else {
                        eprintln!(
                            "[sync] snapshot-fetch {bucket}/{name}: assembled ciphertext length overflows usize; rejecting"
                        );
                        return None;
                    };
                    if total_ct > MAX_BLOB_BYTES.saturating_add(64) {
                        eprintln!(
                            "[sync] snapshot-fetch {bucket}/{name}: assembled ciphertext {total_ct} bytes exceeds MAX_BLOB_BYTES ({MAX_BLOB_BYTES}); rejecting"
                        );
                        return None;
                    }
                    let mut ct = Vec::with_capacity(total_ct);
                    for c in &chunks {
                        ct.extend_from_slice(c);
                    }
                    match infnode::node::e2e_decrypt(&dk, &nonce, &ct) {
                        Ok(plain) => {
                            if plain.len() > MAX_BLOB_BYTES || plain.len() != size {
                                eprintln!(
                                    "[sync] snapshot-fetch {bucket}/{name}: decrypted length {} invalid (declared {size}, max {MAX_BLOB_BYTES}); rejecting",
                                    plain.len()
                                );
                                return None;
                            }
                            eprintln!(
                                "[sync] snapshot-fetch {bucket}/{name}: assembled {size} bytes \
                                 from {n_chunks} chunks (attempt {blob_attempt})"
                            );
                            tokio::task::yield_now().await;
                            return Some(plain);
                        }
                        Err(e) => {
                            eprintln!(
                                "[sync] snapshot-fetch {bucket}/{name}: decrypt failed for \
                                 {size} bytes in {n_chunks} chunks: {e:?} (tamper?; not retried \
                                 as new peers would serve the same manifest)"
                            );
                            return None;
                        }
                    }
                }
            }
            drop(snap_permit);
            drop(permit);
            if blob_attempt < crate::sync::SNAPSHOT_BLOB_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_millis(
                    crate::sync::fetch_retry_backoff_with_jitter_ms(
                        blob_attempt,
                        rand::random::<u64>(),
                    ),
                ))
                .await;
                tokio::task::yield_now().await;
            }
        }
        eprintln!(
            "[sync] snapshot-fetch {bucket}/{name}: unavailable after {} attempts \
             (loud miss: manifest and chunk causes logged above)",
            crate::sync::SNAPSHOT_BLOB_ATTEMPTS
        );
        None
    }

    /// Fetch one committed-domain blob published by `persist_domain_snapshot`.
    ///
    /// Same large-blob lane as [`Self::fetch_state_snapshot`]: the domain
    /// bundle is up to 7 large blobs beside the state blob, and the pull is
    /// sequential, so the lane only ever binds when SEVERAL catch-up subtasks
    /// overlap (probe + anchor + bundle + walk).
    pub async fn fetch_domain_snapshot(
        &self,
        shard_id: u32,
        height: u64,
        kind: &str,
    ) -> Option<Vec<u8>> {
        let name = format!(
            "{}_dom_{kind}",
            snapshot_name(&self.epoch(), shard_id, height)
        );
        let out =
            Self::fetch_large_blob_resumable(&self.node, BUCKET_STELLEREUM_STATE, &name).await;
        if out.is_none() {
            eprintln!(
                "[sync] fetch_domain_snapshot shard={shard_id} height={height} kind={kind} \
                 name={name}: unavailable (see [sync] snapshot-fetch lines above for \
                 size/chunk/budget)"
            );
        }
        tokio::task::yield_now().await;
        out
    }

    /// Fetch a `SnapV4` manifest by `(shard_id, height, state_root)`.
    /// If `expected_hash` is `Some`, verifies `blake3(bytes) == expected_hash`.
    /// Always checks `decode_manifest_strict` and `(shard_id, target_height, target_state_root)`.
    pub async fn fetch_snapv4_manifest(
        &self,
        shard_id: u32,
        height: u64,
        state_root: &[u8; 32],
        expected_hash: Option<&[u8; 32]>,
    ) -> Option<crate::snapshot_v4::SnapshotManifestV1> {
        let permit = fetch_sem().acquire().await.ok()?;
        let name = snapv4_manifest_name(&self.epoch(), shard_id, height, state_root);
        let bytes = tokio::time::timeout(
            std::time::Duration::from_millis(crate::sync::SNAPSHOT_MANIFEST_TIMEOUT_MS),
            self.node.fetch_blob(BUCKET_STELLEREUM_STATE, &name),
        )
        .await
        .ok()
        .flatten()?;
        drop(permit);
        if let Some(exp) = expected_hash {
            if !verify_bytes_blake3_hash(&bytes, exp) {
                eprintln!(
                    "[sync] fetch_snapv4_manifest {name}: blake3 mismatch against expected_hash; rejecting"
                );
                return None;
            }
        }
        let manifest = match crate::snapshot_v4::decode_manifest_strict(&bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[sync] fetch_snapv4_manifest {name}: strict decode failed: {e}");
                return None;
            }
        };
        if manifest.shard_id != shard_id
            || manifest.target_height != height
            || manifest.target_state_root != *state_root
        {
            eprintln!(
                "[sync] fetch_snapv4_manifest {name}: target mismatch (shard={}, height={})",
                manifest.shard_id, manifest.target_height
            );
            return None;
        }
        Some(manifest)
    }

    /// Fetch a single `SnapV4` unit/chunk by `expected_hash`, enforcing
    /// `fetch_sem -> snapshot_fetch_sem`, `MAX_SNAP_CHUNK_BYTES`, and
    /// `blake3(bytes) == expected_hash`.
    pub async fn fetch_snapv4_unit(
        &self,
        shard_id: u32,
        expected_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let name = snapv4_unit_name(&self.epoch(), shard_id, expected_hash);
        let bytes =
            Self::fetch_large_blob_resumable(&self.node, BUCKET_STELLEREUM_STATE, &name).await?;
        if bytes.len() > crate::snapshot_v4::MAX_SNAP_CHUNK_BYTES {
            eprintln!(
                "[sync] fetch_snapv4_unit {name}: len {} exceeds MAX_SNAP_CHUNK_BYTES; rejecting",
                bytes.len()
            );
            return None;
        }
        if !verify_bytes_blake3_hash(&bytes, expected_hash) {
            eprintln!("[sync] fetch_snapv4_unit {name}: blake3(bytes) != expected_hash; rejecting");
            return None;
        }
        tokio::task::yield_now().await;
        Some(bytes)
    }

    /// Fetch pending mempool transactions for a given shard
    pub async fn fetch_mempool_transactions(&self, shard_id: u32) -> Vec<Transaction> {
        self.fetch_mempool_entries(shard_id)
            .await
            .into_iter()
            .filter_map(|e| match e {
                MempoolEntry::Plain(tx) => Some(tx),
                MempoolEntry::Sealed(_) => None,
            })
            .collect()
    }

    /// Fetch the pending mempool entries of a shard: the plain transactions
    /// AND the sealed envelopes.
    ///
    /// The DHT value under `PREFIX_MEMPOOL_TX` is either the historical
    /// plain encoding or the magic-prefixed sealed encoding; the shard index
    /// does not need to change, so a node that predates the sealed path
    /// keeps working (it simply skips the frames it cannot read).
    pub async fn fetch_mempool_entries(&self, shard_id: u32) -> Vec<MempoolEntry> {
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, shard_id);
        let Some(index_str) = self.node.get_local_kv(&shard_key).await else {
            return Vec::new();
        };

        let hashes: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
        let mut entries = Vec::with_capacity(hashes.len());

        for hash_hex in hashes {
            let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, hash_hex);
            if let Some(val_hex) = self.node.get_local_kv(&tx_key).await {
                if let Ok(bytes) = hex::decode(&val_hex) {
                    if crate::mev_epoch::is_sealed_payload(&bytes) {
                        match crate::mev_epoch::decode_sealed_payload(&bytes) {
                            Ok(envelope) => entries.push(MempoolEntry::Sealed(envelope)),
                            Err(e) => {
                                tracing::warn!(
                                    hash = %hash_hex,
                                    error = %e,
                                    "network: malformed sealed mempool entry dropped"
                                );
                            }
                        }
                    } else if let Ok(tx) =
                        decode_wire_limited::<Transaction>(&bytes, MAX_WIRE_SMALL_BYTES)
                    {
                        entries.push(MempoolEntry::Plain(tx));
                    }
                }
            }
        }

        entries
    }

    /// Fetch latest price feed for an asset from P2P network.
    ///
    /// VERIFICATION G5: the stored bytes are re-verified on the way out.
    /// `broadcast_price_feed` verifies before storing, but the local KV is
    /// also writable through `dht.sync` replication from UNTRUSTED peers — a
    /// forged feed planted there must never be served as market evidence.
    /// Fail-closed: bad signature (or bad bytes) reads as "no feed", exactly
    /// like a miss.
    pub async fn fetch_price_feed(&self, asset: &str) -> Option<PriceFeedUpdate> {
        let key = format!("{}{}", PREFIX_ORACLE, asset);
        let val_hex = self.node.get_local_kv(&key).await?;
        decode_verified_price_feed(&val_hex)
    }

    /// Fetch MEV blind round commitment by round number
    pub async fn fetch_blind_round(&self, round: u64) -> Option<BlindRoundCommitment> {
        let key = format!("{}{}", PREFIX_MEV_COMMIT, round);
        let val_hex = self.node.get_local_kv(&key).await?;
        let bytes = hex::decode(&val_hex).ok()?;
        decode_wire_limited(&bytes, MAX_WIRE_SMALL_BYTES).ok()
    }

    /// Discover known peers and active endpoints in the infnode overlay
    pub async fn discover_peers(&self) -> Vec<String> {
        let mut endpoints = Vec::new();
        for peer in self.node.known_peers().await {
            endpoints.extend(peer.endpoints);
        }
        if endpoints.is_empty() {
            for p in &self.node.cfg.peers {
                endpoints.extend(p.endpoints.clone());
            }
        }
        endpoints
    }
}

// ==================== Adopter replication: fetch-and-verify bodies ====================
//
// Mechanics only, no consensus change: the heights here are already committed
// (commit certificate over the block hash). Fetching only decides who HOLDS the
// body, never what is committed. Runs behind/parallel to finalization -- never
// on the finalization critical path -- with bounded concurrency, per-height
// timeouts and bounded retries. Unavailability is honest (`None` /
// `ReplicateOutcome::Unavailable`), never fabricated data.
//
// Verification rule (bodies): `block.compute_hash()` MUST equal the requested
// hash (`crate::sync::verify_replicated_body`). A mismatch is discarded and
// logged via `eprintln!`. There is no peer down-score table in this codebase,
// so "down-scored/logged" degrades to logged -- stated explicitly so a future
// reputation system has a named hook.

/// Fetch one body and verify it against the requested hash before returning.
///
/// `None` means honestly unavailable OR tampered (discarded + logged): either
/// way the caller must not persist or apply anything.
pub async fn fetch_verified_body(
    adapter: &P2pNetworkAdapter,
    expected_hash: &[u8; 32],
) -> Option<Block> {
    // Same process-wide cap as every other fetch: verified body fetches
    // (walk, heal, backfill) share the 8 slots with snapshot/header probes
    // instead of adding an unbounded second lane.
    let permit = fetch_sem().acquire().await.ok()?;
    let bytes = tokio::time::timeout(
        std::time::Duration::from_millis(15_000),
        adapter.node.fetch_blob(
            BUCKET_STELLEREUM_BLOCKS,
            &block_body_blob_name(&adapter.epoch(), expected_hash),
        ),
    )
    .await
    .ok()
    .flatten()?;
    drop(permit);
    // A body fetched from a PEER is wire data: it must decode STRICTLY. The
    // legacy tolerance (a body persisted before the trailing commitment
    // fields existed) applies to the LOCAL STORE only — otherwise a
    // truncated peer body would be silently reinterpreted as a different
    // block (audit W6.4b).
    let block: Block = match decode_wire_limited(&bytes, MAX_WIRE_BLOCK_BYTES) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[repl] discarding undecodable body for {}: {e:?}",
                hex::encode(expected_hash)
            );
            return None;
        }
    };
    if let Err(e) = crate::sync::verify_replicated_body(expected_hash, &block) {
        eprintln!("[repl] {e} (peer served a body under the wrong hash; discarded)");
        return None;
    }
    Some(block)
}

impl P2pNetworkAdapter {
    /// Bounded-retry verified fetch of one body: up to `attempts` tries, each
    /// under `timeout_ms`. Returns the verified body or `None` (honest
    /// unavailability after bounded work -- never a stall).
    pub async fn fetch_verified_with_retries(
        &self,
        expected_hash: [u8; 32],
        attempts: u32,
        timeout_ms: u64,
    ) -> Option<Block> {
        let tries = attempts.clamp(1, 16);
        for attempt in 1..=tries {
            let got = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms.max(1)),
                fetch_verified_body(self, &expected_hash),
            )
            .await
            .ok()
            .flatten();
            if got.is_some() {
                return got;
            }
            if attempt < tries {
                // Jittered exponential backoff between retries (100ms base ×
                // 2^(attempt-1), capped at 1s, plus a 0..=100ms draw): paces
                // the DHT instead of hammering it inside the timeout window,
                // and the draw de-synchronizes nodes that timed out on the
                // same slow peer so their retries do not re-flood together
                // (storm guard 2026-10-13 follow-up: the bare ladder still
                // re-flooded on the same tick). The floor is always the base —
                // a timed-out fetch never retries sooner than 100ms.
                // Runs off the finalization path.
                tokio::time::sleep(std::time::Duration::from_millis(
                    crate::sync::fetch_retry_backoff_with_jitter_ms(attempt, rand::random::<u64>()),
                ))
                .await;
            }
        }
        None
    }

    /// Fetch one missing body by its COMMITTED hash and persist it locally via
    /// the existing blob store path (`Storage::put_verified_block`, which
    /// re-checks the hash at the store boundary -- defense in depth).
    ///
    /// Returns a [`crate::sync::ReplicateOutcome`]: `Stored` (byte-identical to
    /// the proposer's body), `RejectedTamper` (served bytes failed verification,
    /// discarded + logged), or `Unavailable` (honest miss after bounded retries).
    /// Never blocks finalization: the caller runs this behind/parallel.
    pub async fn replicate_one_body(
        &self,
        storage: &crate::storage::Storage,
        expected_hash: [u8; 32],
    ) -> crate::sync::ReplicateOutcome {
        use crate::sync::ReplicateOutcome;
        match self
            .fetch_verified_with_retries(
                expected_hash,
                crate::sync::ADOPT_REPL_MAX_RETRIES,
                crate::sync::ADOPT_REPL_PER_HEIGHT_TIMEOUT_MS,
            )
            .await
        {
            None => ReplicateOutcome::Unavailable(format!(
                "body {} not available after bounded retries",
                hex::encode(expected_hash)
            )),
            Some(block) => match storage.put_verified_block(&block, &expected_hash) {
                Ok(_) => ReplicateOutcome::Stored,
                Err(e) => {
                    eprintln!("[repl] {e}");
                    ReplicateOutcome::RejectedTamper(e.to_string())
                }
            },
        }
    }

    /// Bounded concurrent backfill of missing bodies, tip-ward.
    ///
    /// `missing` is (height, committed-hash) pairs in ANY order; this sorts
    /// tip-ward (highest first, so RPCs serve the tip first), caps concurrency
    /// at `ADOPT_REPL_MAX_CONCURRENCY` via a semaphore, and applies the same
    /// per-height timeout + bounded retries as `replicate_one_body`. At most
    /// `missing.len()` heights are touched -- callers pace with
    /// `sync::plan_backfill_tip_ward` (cap `ADOPT_REPL_BACKFILL_MAX_PER_PASS`)
    /// so a 1000-height gap never becomes 1000 concurrent fetches.
    pub async fn replicate_bodies(
        self: &std::sync::Arc<Self>,
        storage: std::sync::Arc<crate::storage::Storage>,
        mut missing: Vec<(u64, [u8; 32])>,
    ) -> Vec<(u64, crate::sync::ReplicateOutcome)> {
        use crate::sync::ReplicateOutcome;
        missing.sort_by_key(|(h, _)| std::cmp::Reverse(*h));
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(
            crate::sync::ADOPT_REPL_MAX_CONCURRENCY.max(1),
        ));
        let mut handles = Vec::with_capacity(missing.len());
        for (height, hash) in missing {
            let me = self.clone();
            let st = storage.clone();
            let permit_sem = sem.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit_sem.acquire_owned().await.ok()?;
                let out = me.replicate_one_body(&st, hash).await;
                Some((height, out))
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            match h.await {
                Ok(Some(pair)) => out.push(pair),
                _ => out.push((
                    u64::MAX,
                    ReplicateOutcome::Unavailable("join failed".into()),
                )),
            }
        }
        out.sort_by_key(|(h, _)| *h);
        out
    }
}

/// Bound for single DHT blobs carrying full block bodies (L-01).
/// Blocks hold up to 10k txs; 32 MiB mirrors `consensus_net::MAX_CONSENSUS_MSG`
/// and is two orders above any honest body.
pub const MAX_WIRE_BLOCK_BYTES: u64 = 32 * 1024 * 1024;

/// Bound for small wire values (price feeds, mempool txs, blind commits).
/// 1 MiB matches `rpc::MAX_RPC_BODY`-class inputs; honest values are bytes.
pub const MAX_WIRE_SMALL_BYTES: u64 = 1024 * 1024;

/// Strict decoder for untrusted wire/DHT bytes (L-01).
///
/// Wire-compatible with `bincode::deserialize` (fixint, little-endian) but
/// bounded (`with_limit`) and trailing-rejecting, so a pathological
/// length-prefix cannot drive allocation and padded re-framings are refused.
/// Pure so the pathological-prefix fuzz test pins it without a live DHT.
pub fn decode_wire_limited<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: u64,
) -> Result<T, String> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("wire decode: {e}"))
}

// ==================== Eclipse-resistant discovery (additive) ====================
//
// Threat: today's `discover_peers` (above) returns every endpoint the DHT view
// (`known_peers`: routing table + configured peers) claims, with no check on
// WHO the endpoint claims to be. The routing table itself is fed by
// unauthenticated peer gossip (`dht.find_node` responses, `dht.update` route
// merges), so an attacker who controls a node's DHT view can make discovery
// return attacker-chosen identities — the first step of an eclipse.
//
// Rule enforced here: IDENTITY comes from the local static config (`peers:`
// entries, whose Falcon-512 pq-pub is pinned and TLS-verified); the network
// may only supply fresh ENDPOINTS for those already-pinned identities.
// Discovery can therefore never introduce a new key into any path the node
// trusts.

/// Cap on retained per-endpoint freshness records.
///
/// Bounds memory no matter how many distinct endpoints the network advertises:
/// once full, the worst record (most failures, stalest) is evicted to make
/// room. A large-enough constant that a healthy network never evicts.
pub const MAX_ENDPOINT_RECORDS: usize = 512;

/// Consecutive dial failures after which an endpoint is deprioritized.
///
/// The record is KEPT (a dead endpoint may come back), it just sorts last in
/// `PeerEndpointTable::preferred_order` until a success resets it.
pub const ENDPOINT_BACKOFF_THRESHOLD: u32 = 5;

/// Normalize a PQ transport identity (hex Falcon-512 pq-pub) for comparison.
///
/// Hex case is not canonical across producers (config files vs DHT gossip),
/// so comparison is case-insensitive. Empty/whitespace input normalizes to an
/// empty string, which `pinned_identity_set` never contains — a discovered
/// record with no key is therefore always dropped, never admitted.
pub fn canonical_pq_pub(pq_hex: &str) -> String {
    pq_hex.trim().to_ascii_lowercase()
}

/// Build the set of pinned PQ transport identities from the local static
/// config.
///
/// This is the ONLY source of trusted identity: every entry's Falcon-512
/// `pq-pub` is pinned into the TLS verifier at startup, so a peer presenting
/// a different key for one of these endpoints fails the handshake.
pub fn pinned_identity_set(
    peers: &[infnode::config::PeerConfig],
) -> std::collections::HashSet<String> {
    peers
        .iter()
        .filter_map(|p| p.pq_pub.as_deref())
        .map(canonical_pq_pub)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Filter DHT-discovered peers down to already-pinned identities.
///
/// Returns the subset of `discovered` whose Falcon-512 `pq-pub` is in
/// `pinned_pq_pub`, preserving each record (including any NEW endpoints the
/// network reported for that identity). Everything else — unknown keys,
/// empty/malformed keys — is dropped. Pure function over data so it is
/// unit-testable without a live DHT; `discover_peers_filtered` is the thin live
/// wrapper over it.
pub fn filter_discovered_to_pinned(
    discovered: Vec<infnode::dht::NodeInfo>,
    pinned_pq_pub: &std::collections::HashSet<String>,
) -> Vec<infnode::dht::NodeInfo> {
    discovered
        .into_iter()
        .filter(|n| pinned_pq_pub.contains(&canonical_pq_pub(&n.pq_hex)))
        .collect()
}

/// Freshness record for one dialable endpoint of a PINNED peer.
///
/// Only endpoints that survived `filter_discovered_to_pinned` (or came from
/// the static config) should ever get a record here: this table ranks
/// endpoints, it does not vet identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEndpoint {
    /// Dial target as advertised, e.g. `"127.0.0.1:9411"`.
    pub endpoint: String,
    /// Last time a dial to this endpoint succeeded (ms since Unix epoch).
    /// `0` means "never seen live" (record created by a failure).
    pub last_seen_ms: u64,
    /// Consecutive dial failures since the last success. Saturates instead of
    /// wrapping, so a permanently dead endpoint cannot overflow the counter.
    pub consecutive_failures: u32,
}

impl PeerEndpoint {
    /// New record for an endpoint just observed live.
    pub fn new(endpoint: &str, now_ms: u64) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            last_seen_ms: now_ms,
            consecutive_failures: 0,
        }
    }

    /// Record a successful dial: refresh last-seen and clear the failure streak.
    pub fn mark_success(&mut self, now_ms: u64) {
        self.last_seen_ms = now_ms;
        self.consecutive_failures = 0;
    }

    /// Record a failed dial: extend the failure streak, keep last-seen.
    ///
    /// Deliberately does NOT delete the record: a peer that fails N times is
    /// deprioritized via `backed_off`, not forgotten — it may come back, and
    /// `mark_success` restores it to full standing immediately.
    pub fn mark_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Whether this endpoint is currently deprioritized for dialing.
    pub fn backed_off(&self) -> bool {
        self.consecutive_failures >= ENDPOINT_BACKOFF_THRESHOLD
    }
}

/// Bounded per-endpoint freshness table backing the dialer.
///
/// Unbounded growth is the failure mode being avoided: every gossip round can
/// advertise new endpoints, so the table evicts its worst record once `cap`
/// is reached instead of growing. Failure streaks only reorder dialing —
/// eviction is by cap pressure alone, never by failure count.
#[derive(Clone, Debug)]
pub struct PeerEndpointTable {
    entries: std::collections::HashMap<String, PeerEndpoint>,
    cap: usize,
}

impl PeerEndpointTable {
    /// Empty table holding at most `cap` records (`cap` saturates to >= 1).
    pub fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Empty table with the production cap.
    pub fn with_default_cap() -> Self {
        Self::new(MAX_ENDPOINT_RECORDS)
    }

    /// Maximum records retained.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Records currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up one endpoint's record, if retained.
    pub fn get(&self, endpoint: &str) -> Option<&PeerEndpoint> {
        self.entries.get(endpoint)
    }

    /// Record a successful dial to `endpoint`, creating the record if needed.
    pub fn record_success(&mut self, endpoint: &str, now_ms: u64) {
        match self.entries.get_mut(endpoint) {
            Some(rec) => rec.mark_success(now_ms),
            None => {
                self.entries
                    .insert(endpoint.to_string(), PeerEndpoint::new(endpoint, now_ms));
            }
        }
        self.enforce_cap();
    }

    /// Record a failed dial to `endpoint`, creating the record if needed.
    ///
    /// A first-seen failure creates a never-live record (`last_seen_ms == 0`)
    /// with a streak of 1: deprioritized from the start, but present so a
    /// later success can rehabilitate it.
    pub fn record_failure(&mut self, endpoint: &str) {
        match self.entries.get_mut(endpoint) {
            Some(rec) => rec.mark_failure(),
            None => {
                let mut rec = PeerEndpoint::new(endpoint, 0);
                rec.last_seen_ms = 0;
                rec.mark_failure();
                self.entries.insert(endpoint.to_string(), rec);
            }
        }
        self.enforce_cap();
    }

    /// Endpoints ordered for dialing: live/healthy first (most recently seen),
    /// backed-off endpoints last (fewest failures first among those).
    pub fn preferred_order(&self) -> Vec<String> {
        let mut recs: Vec<&PeerEndpoint> = self.entries.values().collect();
        recs.sort_by(|a, b| {
            (
                a.backed_off(),
                a.consecutive_failures,
                std::cmp::Reverse(a.last_seen_ms),
            )
                .cmp(&(
                    b.backed_off(),
                    b.consecutive_failures,
                    std::cmp::Reverse(b.last_seen_ms),
                ))
        });
        recs.into_iter().map(|r| r.endpoint.clone()).collect()
    }

    /// Evict worst-first until within `cap`: highest failure streak first,
    /// stalest last-seen to break ties. Never evicts by failure count alone —
    /// only cap pressure removes records.
    fn enforce_cap(&mut self) {
        while self.entries.len() > self.cap {
            let victim = self
                .entries
                .iter()
                .max_by(|(ka, a), (kb, b)| {
                    (
                        a.consecutive_failures,
                        std::cmp::Reverse(a.last_seen_ms),
                        kb,
                    )
                        .cmp(&(
                            b.consecutive_failures,
                            std::cmp::Reverse(b.last_seen_ms),
                            ka,
                        ))
                })
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
    }
}

impl P2pNetworkAdapter {
    /// Eclipse-resistant peer discovery.
    ///
    /// Like `discover_peers`, but the DHT view (`known_peers`) may only
    /// contribute ENDPOINTS for identities already pinned in the local static
    /// config — never new identities. Static config endpoints are pinned by
    /// definition and always included; discovered records for unknown PQ keys
    /// (the exact thing a poisoned DHT view or a TOFU stranger would supply)
    /// are dropped by `filter_discovered_to_pinned`.
    pub async fn discover_peers_filtered(&self) -> Vec<String> {
        let pinned = pinned_identity_set(&self.node.cfg.peers);
        let mut endpoints: Vec<String> = Vec::new();
        // Static config: pinned identity AND pinned endpoints. Always dialable.
        for p in &self.node.cfg.peers {
            endpoints.extend(p.endpoints.clone());
        }
        // Network view: pinned identities only; new endpoints welcome, new keys not.
        for peer in filter_discovered_to_pinned(self.node.known_peers().await, &pinned) {
            endpoints.extend(peer.endpoints);
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    /// Live connected-peer count, read from the node's peer table, and
    /// published to the RPC layer so `net_peerCount` reflects an OBSERVED
    /// number instead of the process-wide counter's initial `0x0`.
    ///
    /// This is the single hook the task requires: callers with the adapter in
    /// hand (the consensus driver's periodic probe / supervisor loop) call it
    /// once per tick and pay one `RwLock` read plus an `AtomicU64` store.
    /// `rpc::note_peer_count` is the source of truth for
    /// `eth`/`net_peerCount`; nothing here invents peers — an empty table
    /// publishes 0.
    pub async fn publish_live_peer_count(&self) -> u64 {
        let n = self.node.peers_ready().await as u64;
        crate::rpc::note_peer_count(n);
        n
    }

    /// The observed live peer count without publishing it (diagnostics).
    pub async fn live_peer_count(&self) -> u64 {
        self.node.peers_ready().await as u64
    }
}
