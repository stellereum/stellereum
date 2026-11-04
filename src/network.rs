//! P2P Networking Layer Adapter for Stellereum
//! Uses infnode as a transparent P2P transport and DHT storage black box.
//! Does NOT modify infnode core; interacts solely via infnode's public API:
//! - store_blob / fetch_blob for block chunks and state snapshots
//! - kv_store_local / get_local_kv for block headers, latest height, peer routes,
//!   mempool transaction gossip, cross-shard message passing, and oracle updates.

use crate::mev::BlindRoundCommitment;
use crate::oracle::PriceFeedUpdate;
use crate::sharding::{Block, CrossShardMessage, ShardId, Transaction};
use infnode::node::Node;
use std::sync::Arc;

pub const BUCKET_STELLEREUM_BLOCKS: &str = "stell_blocks";
pub const BUCKET_STELLEREUM_STATE: &str = "stell_state";
/// Replicated bucket holding each shard's published head pointer.
pub const BUCKET_STELLEREUM_HEAD: &str = "stell_head";
/// Replicated bucket holding published block HEADERS, so a cold node can chain from
/// a state snapshot up to the head using headers only (small, published every block)
/// rather than bodies (large, kept for a bounded window).
pub const BUCKET_STELLEREUM_HEADERS: &str = "stell_headers";

/// Chain epoch: a short tag derived from the genesis fingerprint, mixed into every
/// blob name this node publishes or reads.
///
/// Without it, a data wipe does NOT wipe the network: the DHT still holds the old
/// chain's head pointer, headers and snapshots under the same well-known names, and a
/// freshly-started node honestly tries to follow a chain that no longer exists. That
/// was observed live -- after wiping both data directories, a new node started at
/// height 1 and then went looking for the previous run's height-488 head, because the
/// blobs survived in the overlay.
///
/// Namespacing by epoch makes a wiped node unable to see the old chain at all, so
/// "start fresh" actually means fresh. Two networks with different genesis parameters
/// also cannot contaminate each other, which is the same property that makes a public
/// testnet safe to run beside a private one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTag(String);

impl EpochTag {
    /// Build a tag from a genesis fingerprint. Short, hex, filesystem- and
    /// blob-name-safe.
    pub fn from_genesis(fingerprint: &[u8; 32]) -> Self {
        Self(hex::encode(&fingerprint[..8]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EpochTag {
    /// Before a genesis fingerprint exists (early startup, unit tests) fall back to a
    /// fixed tag rather than an empty string, so names stay well-formed.
    fn default() -> Self {
        Self("genesis".to_string())
    }
}

fn header_name(epoch: &EpochTag, height: u64) -> String {
    format!("{}_h_{height}", epoch.as_str())
}

fn header_index_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_hi_{shard_id}_{height}", epoch.as_str())
}

/// Well-known blob name for a height's precommit-QC sidecar (A1 anchor).
/// SHARD-SCOPED (unlike `header_name`): a cross-shard QC splice at the same
/// height must be impossible by construction — binding checks cover height
/// and hash, never shard.
fn header_qc_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_hq_{shard_id}_{height}", epoch.as_str())
}

/// Well-known blob name for a shard's head pointer, scoped to a chain epoch.
fn head_name(epoch: &EpochTag, shard_id: u32) -> String {
    format!("{}_shard_{shard_id}_head", epoch.as_str())
}

/// Block bodies and state snapshots are content-addressed by hash/height, but they are
/// still scoped so a wiped node does not read a previous chain's state.
fn block_name(epoch: &EpochTag, hash_hex: &str) -> String {
    format!("{}_blk_{hash_hex}", epoch.as_str())
}

fn snapshot_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_snap_{shard_id}_{height}", epoch.as_str())
}

/// Well-known blob name for the "latest state snapshot" pointer: the exact
/// height of the most recently published state snapshot. Snapshots land on
/// arbitrary heights (capture completes when the worker finishes, not on
/// %100), so probing round hundreds systematically misses them. The pointer
/// (a few bytes, FOREVER TTL like the snapshots) lets a catcher read one
/// tiny blob and fetch the exact boundary first.
fn snapshot_latest_name(epoch: &EpochTag, shard_id: u32) -> String {
    format!("{}_snap_latest_{shard_id}", epoch.as_str())
}

pub const PREFIX_LATEST_HEIGHT: &str = "stell:height:";
pub const PREFIX_BLOCK_HASH: &str = "stell:block:";
pub const PREFIX_MEMPOOL_TX: &str = "stell:mempool:";
pub const PREFIX_SHARD_MEMPOOL: &str = "stell:shard_mempool:";
pub const PREFIX_CROSS_SHARD: &str = "stell:cross_shard:";
pub const PREFIX_ORACLE: &str = "stell:oracle:";
pub const PREFIX_MEV_COMMIT: &str = "stell:mev:commit:";

/// One entry of the DHT mempool store: a plain transaction or a SEALED
/// envelope (the epoch-seal path — the ciphertext only).
#[derive(Clone, Debug)]
pub enum MempoolEntry {
    Plain(Transaction),
    Sealed(crate::mev_epoch::SealedEnvelope),
}

/// Base name of the P2P gossip topic that carries cross-shard messages.
pub const CROSS_SHARD_TOPIC_BASE: &str = "stell/cross_shard";

/// The gossip topic carrying the cross-shard messages addressed to
/// `target_shard`.
///
/// EPOCH-SCOPED (not optional): a pubsub topic is a GLOBAL name in the
/// overlay — every node subscribed to it receives what is published under it,
/// and the message is relayed across the mesh. A fixed topic name would let a
/// node of one chain receive another chain's cross-shard messages and try to
/// credit them: the same namespace leak that epoch-scoped consensus topics
/// already fixed (see [`crate::consensus_net::consensus_topic`]).
///
/// SHARD-SCOPED as well: the topic is a per-shard mailbox, not a global
/// firehose that every shard then filters. A shard must only ever hear the
/// messages addressed to IT, so the routing is by construction rather than by
/// a filter a future bug could skip.
pub fn cross_shard_topic(target_shard: ShardId, epoch: &str) -> String {
    format!("{CROSS_SHARD_TOPIC_BASE}/{epoch}/{target_shard}")
}

/// DHT retention for published chain data.
///
/// `kv.json` on a live node grows ~1MB/min because every finalized height
/// publishes three blob manifests that never expire: one body
/// (`stell_blocks/*`) plus a header and a height→hash index
/// (`stell_headers/*`, two writes in `persist_block_header`). At 42k+ heights
/// that is 127k+ kv entries / ~85MB, and serializing the whole map (~1.3s)
/// re-creates the OOM pressure the persist path just stopped paying per write.
///
/// Retention is therefore HEIGHT-based, not time-based: whatever is below
/// `finalized − KEEP` is deleted by the publisher itself (`maybe_prune_retained`,
/// driven by the per-height publish traffic, throttled and capped), and every
/// body/header blob additionally carries a generous TTL
/// (`dht_blob_ttl_ms`) so replicas and strays die in the sweep even on nodes
/// that never prune. `kv` here is node-local DHT storage, NOT consensus state:
/// pruning never touches a state root.
///
/// Sync-safety (why KEEP keeps catch-up working):
/// * bodies are fetched only (i) inside the retro window
///   (`RETRO_PUBLISH_DEPTH = 4096`, `src/main.rs`) plus the tip-8 supplement,
///   and (ii) for the short post-snapshot remainder (`try_snapshot_sync` →
///   `walk_chain` → `fetch_block`, i.e. `collect_missing_blocks` in
///   `src/sync.rs`). KEEP ≫ 4096 + remainder, so every body sync may ask for
///   is retained;
/// * headers are walked contiguously from our anchor to the snapshot successor
///   (`verify_snapshot_anchor` in `src/sync.rs` via `fetch_head_hash` +
///   `fetch_block_header`). Pruning them below `finalized − KEEP` bounds a full
///   header-anchored catch-up to nodes ≤ KEEP behind — the window the task
///   scopes retention to;
/// * the head pointer (republished every finalize and every ~30s probe) and
///   state snapshots (every 100 heights) carry `STELL_DHT_FOREVER_TTL_MS` and
///   are never pruned, so a lagging node always finds a recent head and a
///   recent snapshot to anchor on.
///
/// Local horizons stay coherent: the same `STELL_KEEP_BLOCKS` env feeds the
/// sled prune in `src/main.rs` (default 50_000 there); the DHT horizon defaults
/// to 8000 and is documented where it diverges.
///
/// Steady state: ≤ KEEP heights × 3 manifests + snapshots (1/100 heights,
/// forever) + 1 head/shard — at ~670B/entry ≈ 16MB at KEEP=8000 instead of
/// unbounded growth.
///
/// Default 8000; override with `STELL_DHT_KEEP_BLOCKS_DEFAULT`. Node-local
/// DHT retention, not consensus — nodes MAY differ (a smaller KEEP only
/// bounds how far behind this node can still serve bodies).
pub const STELL_DHT_KEEP_BLOCKS_DEFAULT: u64 = 8_000;
/// Run a prune pass at most this often (in finalized heights). Pruning rides
/// the snapshot cadence so it costs no extra wakeup. Default 100; override
/// with `STELL_DHT_PRUNE_INTERVAL_HEIGHTS`. Node-local DHT housekeeping, not
/// consensus — nodes MAY differ.
pub const STELL_DHT_PRUNE_INTERVAL_HEIGHTS: u64 = 100;
/// Cap deletes per pass so the backlog after an upgrade (tens of thousands of
/// heights) drains across passes instead of stalling `publish_lane`.
/// Sized (2048) to drain a ~170k-height backlog in under a day at one pass per
/// 100 heights; passes are local-only kv/chunk deletes, no network fan-out.
/// Default 2048; override with `STELL_DHT_PRUNE_MAX_PER_RUN`. Node-local DHT
/// housekeeping, not consensus — nodes MAY differ.
pub const STELL_DHT_PRUNE_MAX_PER_RUN: usize = 2048;
/// Effectively non-expiring TTL for the head pointer and state snapshots (ms).
/// Far beyond any chain lifetime, far below i64 overflow in `now_ms() + ttl`.
/// Default 100 years; override with `STELL_DHT_FOREVER_TTL_MS`. Node-local
/// DHT retention, not consensus — nodes MAY differ.
pub const STELL_DHT_FOREVER_TTL_MS: i64 = 100 * 365 * 24 * 3600 * 1000;

/// Effective DHT keep-blocks fallback (`STELL_DHT_KEEP_BLOCKS_DEFAULT`,
/// default 8000).
pub fn dht_keep_blocks_default() -> u64 {
    std::env::var("STELL_DHT_KEEP_BLOCKS_DEFAULT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STELL_DHT_KEEP_BLOCKS_DEFAULT)
}

/// Effective prune-pass cadence in heights (`STELL_DHT_PRUNE_INTERVAL_HEIGHTS`,
/// default 100).
pub fn dht_prune_interval_heights() -> u64 {
    std::env::var("STELL_DHT_PRUNE_INTERVAL_HEIGHTS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STELL_DHT_PRUNE_INTERVAL_HEIGHTS)
}

/// Effective delete cap per prune pass (`STELL_DHT_PRUNE_MAX_PER_RUN`, default 2048).
pub fn dht_prune_max_per_run() -> usize {
    std::env::var("STELL_DHT_PRUNE_MAX_PER_RUN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STELL_DHT_PRUNE_MAX_PER_RUN)
}

/// Effectively non-expiring TTL for head/snapshot blobs (`STELL_DHT_FOREVER_TTL_MS`,
/// default 100 years in ms).
pub fn dht_forever_ttl_ms() -> i64 {
    std::env::var("STELL_DHT_FOREVER_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STELL_DHT_FOREVER_TTL_MS)
}

/// How many recent heights the DHT retains (bodies, headers, indices).
/// Same env name the consensus loop uses for the local store
/// (`STELL_KEEP_BLOCKS` in `src/main.rs`), so one knob moves both horizons.
pub fn retention_keep_blocks() -> u64 {
    std::env::var("STELL_KEEP_BLOCKS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(dht_keep_blocks_default)
}

/// Parse the `STELL_KEEP_BLOCKS` value; pure so tests need no env mutation.
pub fn parse_keep_blocks(v: Option<String>) -> u64 {
    v.and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STELL_DHT_KEEP_BLOCKS_DEFAULT)
}

/// TTL (ms) for body/header/index blobs holding `keep_blocks` heights.
///
/// Deliberately GENEROUS, not tight: the height prune above is the real bound
/// (deterministic under any block pace), while this only collects what the
/// prune cannot reach — replica copies on peers, heights published before the
/// index existed (hash unknown, unaddressable), and leftovers on nodes that
/// were offline during pruning. `keep * 120s` assumes a pace no slower than
/// one block per two minutes (a live chain is orders of magnitude faster, so
/// the prune always wins on it); clamped to [7d, 30d] so a tiny KEEP cannot
/// outrun the prune horizon and a huge KEEP cannot disable expiry entirely.
pub fn dht_blob_ttl_ms(keep_blocks: u64) -> i64 {
    const DAY_MS: i64 = 24 * 3600 * 1000;
    // NOTE: `keep_blocks as i64` would WRAP on absurd values (int→int `as`
    // casts wrap); `try_from` saturates instead, so the clamp below holds.
    let want = i64::try_from(keep_blocks)
        .unwrap_or(i64::MAX)
        .saturating_mul(120_000);
    want.clamp(7 * DAY_MS, 30 * DAY_MS)
}

/// Exclusive prune bound: heights `H < prune_below_exclusive(tip, keep)` are
/// below `finalized − KEEP` and may be deleted from the DHT.
pub fn prune_below_exclusive(tip_height: u64, keep_blocks: u64) -> u64 {
    tip_height.saturating_sub(keep_blocks)
}

/// The next prune batch: heights `(cursor..bound)` capped at `max`, plus the
/// cursor to store afterwards. `cursor` is the last height already pruned
/// (0 = nothing pruned yet; height 0 itself is never touched — the genesis
/// header stays as anchor material).
pub fn prune_batch(cursor: u64, bound: u64, max: usize) -> (Vec<u64>, u64) {
    let mut out = Vec::new();
    let mut cur = cursor;
    while cur < bound && out.len() < max {
        cur += 1;
        if cur == 0 {
            continue;
        }
        out.push(cur);
    }
    (out, cur.min(bound))
}

/// Local-kv key holding the persisted prune cursor for one (epoch, shard).
/// Epoch-scoped so a wiped/re-genesis chain never resumes a foreign cursor;
/// shard-scoped because each shard advances its own heights.
pub fn prune_cursor_key(epoch: &EpochTag, shard_id: u32) -> String {
    format!("stell_prune/cursor/{}/{}", epoch.as_str(), shard_id)
}

/// Parse a persisted cursor value back; `None` = missing or corrupt, start over.
pub fn parse_prune_cursor(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// Parse an index blob body (`"<height>:<hashhex>"`, written by
/// `persist_block_header`) back into its height and hash hex.
///
/// PENTEST F4 (P0): the hash is VALIDATED — exactly 64 ASCII-hex chars (a
/// blake3 body hash). Before the fix any string after the colon was accepted
/// and flowed into blob names / kv keys (`block_name`, `PREFIX_BLOCK_HASH`),
/// so a malicious index blob served over the DHT (`"5:../../evil"`,
/// `"5:<64 KiB of garbage>"`) turned the prune/fetch path into a confused
/// deputy: unvalidated attacker bytes became filesystem-adjacent names and
/// unbounded kv keys. Height and hash mismatches against the fetched header
/// record are still checked by the caller; this closes the name-confusion.
pub fn parse_header_index(bytes: &[u8]) -> Option<(u64, String)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let (h, hash_hex) = s.split_once(':')?;
    let height = h.parse::<u64>().ok()?;
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((height, hash_hex.to_string()))
}

/// Decode one hex-encoded oracle feed from local KV and re-verify the
/// publisher signature before serving it.
///
/// Pure so the G5 fail-closed rule is testable without a live DHT: malformed
/// bytes, a tampered price, or a forged publisher key all read as `None`
/// (a miss), never as market evidence.
pub fn decode_verified_price_feed(val_hex: &str) -> Option<PriceFeedUpdate> {
    let bytes = hex::decode(val_hex.trim()).ok()?;
    let feed: PriceFeedUpdate = bincode::deserialize(&bytes).ok()?;
    feed.verify().then_some(feed)
}

/// Everything the DHT holds for one retained height: the blobs to delete and
/// the local kv keys to drop. Pure data (same pattern as `PublishWrite`) so
/// the prune set is inspectable and test-pinned without a live DHT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneDeletes {
    /// (bucket, blob name) pairs for `delete_blob_local`.
    pub blobs: Vec<(&'static str, String)>,
    /// Local kv keys for `kv_remove_local`.
    pub kv: Vec<String>,
}

/// Plan the DHT deletes for height `height` on `shard`.
///
/// `body_hash_hex` comes from the height→hash index (without it the body is
/// hash-addressed and unfindable — then only the header blobs and kv entries
/// are planned and the TTL backstop collects the body). The head pointer and
/// state snapshots are NEVER planned: they stay forever.
pub fn plan_retained_prune(
    epoch: &EpochTag,
    shard_id: u32,
    height: u64,
    body_hash_hex: Option<&str>,
) -> PruneDeletes {
    let mut blobs = vec![
        (BUCKET_STELLEREUM_HEADERS, header_name(epoch, height)),
        (
            BUCKET_STELLEREUM_HEADERS,
            header_index_name(epoch, shard_id, height),
        ),
        // A1 anchor: QC sidecar retention == header retention (KEEP window,
        // same TTL backstop). A pruned QC simply reads as missing (fail
        // closed to "skip this boundary").
        (
            BUCKET_STELLEREUM_HEADERS,
            header_qc_name(epoch, shard_id, height),
        ),
    ];
    let mut kv = Vec::new();
    if let Some(hash_hex) = body_hash_hex {
        blobs.push((BUCKET_STELLEREUM_BLOCKS, block_name(epoch, hash_hex)));
        kv.push(format!("{}{}", PREFIX_BLOCK_HASH, hash_hex));
    }
    PruneDeletes { blobs, kv }
}

pub struct P2pNetworkAdapter {
    pub node: Arc<Node>,
    /// Chain epoch, from the genesis fingerprint. Mixed into every published name so
    /// blobs from a different chain (or a previous run after a wipe) are invisible.
    ///
    /// Behind a lock because the adapter is constructed before genesis is computed
    /// (the P2P node has to exist to derive the validator set), and because every
    /// reader takes it briefly this costs nothing next to a network round trip.
    epoch: std::sync::RwLock<EpochTag>,
    /// Height cursor for the DHT retention prune: the last height already swept
    /// by `maybe_prune_retained` (0 = nothing pruned yet). Monotonic; advanced
    /// at most `STELL_DHT_PRUNE_MAX_PER_RUN` heights per pass so an upgrade
    /// backlog drains gradually on `publish_lane`, never on the consensus tick.
    prune_cursor: std::sync::atomic::AtomicU64,
    /// Whether the persisted cursor has been loaded once this process (lazy, on
    /// the first prune pass). The in-memory cursor alone would reset to 0 on
    /// every restart and re-chew the already-pruned low range forever, never
    /// reaching a large backlog — the persisted value lets restarts resume.
    prune_cursor_loaded: std::sync::atomic::AtomicBool,
    /// Last finalized height that triggered a prune pass. Passes run at most
    /// every `STELL_DHT_PRUNE_INTERVAL_HEIGHTS` heights (the snapshot cadence).
    last_prune_tip: std::sync::atomic::AtomicU64,
    /// Highest head height THIS process has published, per shard. `publish_head`
    /// only moves forward: the shared head key is last-writer-wins by `stored_at`,
    /// so republishing a stale (or genesis) height after a peer advertised the
    /// tip rewinds the network's head for EVERYONE — including ourselves on
    /// read (the local manifest shadows peers). The guard makes each process
    /// publish a strictly increasing sequence; see `head_publish_allowed`.
    last_published_head: std::sync::Mutex<std::collections::HashMap<u32, u64>>,
}

/// Whether publishing `height` as a shard head is safe, given `last_published`
/// is the highest head this process has advertised before.
///
/// Two refusals, both fail-closed:
/// * `height == 0`: a node that knows only genesis has no tip to advertise. Its
///   height-0 write would last-writer-win over a live tip and strand every
///   catching-up node (including itself) on "peer height 0".
/// * `height <= last_published`: a stale republish rewinds the advertised head.
///   Pure so tests pin it without a live DHT.
pub fn head_publish_allowed(height: u64, last_published: u64) -> bool {
    height > 0 && height > last_published
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

/// Committed-domain kinds published beside every state snapshot (see
/// `P2pNetworkAdapter::persist_domain_snapshot`). The single source of truth
/// for the publish path in `src/main.rs`: adding a kind here publishes it,
/// removing one stops. Must stay a SUPERSET of what a synced node needs to
/// re-root, minus the documented gap: `sync::SYNC_DOMAIN_KINDS` additionally
/// fetches `pq_keys` (forward-compatible — absent means empty), which has no
/// publisher yet because raw PQ pins are auxiliary to the state root (the
/// accounts snapshot already commits to every pin's hash). Pinned by
/// `tests/observer_and_recovery_tests.rs`.
pub const SNAPSHOT_PUBLISH_DOMAIN_KINDS: &[&str] = &[
    "domains",
    "session",
    "bridge",
    "confidential",
    "zkml",
    "cross_shard",
];

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
fn fetch_sem() -> &'static tokio::sync::Semaphore {
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
fn snapshot_fetch_sem() -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| {
        tokio::sync::Semaphore::new(crate::sync::SNAPSHOT_FETCH_MAX_CONCURRENCY.max(1))
    })
}

/// Pacing between retro-publish bodies (ms). Each `store_blob` spawns a
/// background `replicate_blob` (up to 20s, fanning out to K peers), so a
/// 128-body pass fired back-to-back spawns 128 concurrent replicators.
/// 5ms spreads the burst (~0.64s per full pass) without slowing the window.
pub const RETRO_PUBLISH_PACE_MS: u64 = 5;

/// One chunk entry of a snapshot manifest, resolved for resumable fetch.
///
/// `id` addresses the chunk bytes (`fetch_chunk_net`); `hash` is the
/// integrity commitment from the manifest (a mismatch discards the chunk
/// as tamper, exactly like `fetch_blob` does). Module-level (not an
/// associated item) so the resumable helpers below can name it.
struct SnapshotChunkMeta {
    id: String,
    hash: Option<String>,
}

impl P2pNetworkAdapter {
    pub fn new(node: Arc<Node>) -> Self {
        Self {
            node,
            epoch: std::sync::RwLock::new(EpochTag::default()),
            prune_cursor: std::sync::atomic::AtomicU64::new(0),
            prune_cursor_loaded: std::sync::atomic::AtomicBool::new(false),
            last_prune_tip: std::sync::atomic::AtomicU64::new(0),
            last_published_head: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Scope this adapter to a chain epoch. Called once the genesis fingerprint is
    /// known, before anything is published or fetched.
    pub fn set_epoch(&self, epoch: EpochTag) {
        *self.epoch.write().unwrap_or_else(|e| e.into_inner()) = epoch;
    }

    pub fn epoch(&self) -> EpochTag {
        self.epoch.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Broadcast a newly finalized block to the P2P overlay network
    pub async fn broadcast_block(&self, block: &Block) -> Result<[u8; 32], String> {
        let block_hash = block.compute_hash();
        let hash_hex = hex::encode(block_hash);

        let block_bytes =
            bincode::serialize(block).map_err(|e| format!("Serialization failed: {:?}", e))?;

        // 1. Store block binary chunks in infnode blob storage. The manifest
        // carries the retention-window TTL (`dht_blob_ttl_ms`): bodies below
        // finalized − KEEP are pruned by `maybe_prune_retained`, and this TTL
        // collects replicas/strays in the sweep even where no prune runs.
        // Paced (backpressure 2026-10-14): bounded concurrency + min interval +
        // bounded retries + circuit breaker, so a slow peer cannot turn this
        // into a mutual-DDoS retry storm.
        paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_BLOCKS,
            &block_name(&self.epoch(), &hash_hex),
            &block_bytes,
            dht_blob_ttl_ms(retention_keep_blocks()),
            ReplStoreKind::Bulk,
        )
        .await;

        // 2. Publish block hash to DHT KV for discovery by peers
        let block_kv_key = format!("{}{}", PREFIX_BLOCK_HASH, hash_hex);
        self.node.kv_store_local(&block_kv_key, &hash_hex).await;

        // 3. Update shard latest height in DHT KV
        let height_kv_key = format!("{}{}", PREFIX_LATEST_HEIGHT, block.shard_id);
        let height_val = format!("{}:{}", block.height, hash_hex);
        self.node.kv_store_local(&height_kv_key, &height_val).await;

        Ok(block_hash)
    }

    /// Fetch a block from the P2P overlay network by hash
    pub async fn fetch_block(&self, block_hash: &[u8; 32]) -> Option<Block> {
        let _permit = fetch_sem().acquire().await.ok()?;
        let hash_hex = hex::encode(block_hash);
        let bytes = self
            .node
            .fetch_blob(
                BUCKET_STELLEREUM_BLOCKS,
                &block_name(&self.epoch(), &hash_hex),
            )
            .await?;

        bincode::deserialize(&bytes).ok()
    }

    // ==================== Retro-publish of already-finalized bodies ====================
    //
    // A body is only ever written to the DHT by `broadcast_block`, which runs at
    // the moment of finalization. So a body finalized by an earlier run, or
    // before retro-publishing existed, exists only in this node's local disk
    // store, and a fresh or lagging node can never fetch it: `collect_missing_blocks`
    // walks `prev_hash` and dies with `block sync: missing block <hash>` no matter
    // how far ahead the advertised head is. That is exactly the 1007-block catch-up
    // failure on the live stand.
    //
    // The fix is to push this node's recent history back onto the DHT after the
    // fact, WITHOUT repeating what `broadcast_block` does. Only the body is
    // republished: the height pointer and the block-hash index are head
    // announcements, and replaying them from a stale node would rewind the
    // network's advertised head to the middle of the stale node's own chain.

    /// Publish one already-finalized block body, by hash, for peers to fetch.
    ///
    /// Same bucket and name convention as `broadcast_block`, so `fetch_block`
    /// finds it — but it writes NO `PREFIX_LATEST_HEIGHT` and NO
    /// `PREFIX_BLOCK_HASH` entry. See `plan_block_body_publish` for why those two
    /// writes must not be replayed from a re-publish.
    pub async fn retro_publish_block(&self, block: &Block) -> Result<[u8; 32], String> {
        let writes = plan_block_body_publish(&self.epoch(), block)?;
        apply_publish_plan(&self.node, &writes).await?;
        Ok(block.compute_hash())
    }

    /// Publish one already-finalized block body from its stored bytes, addressed
    /// by the hash a peer will ask for.
    ///
    /// For a caller reading raw bodies off disk, so the body is never
    /// re-serialized through a `Block` it had to decode first. The bytes are
    /// checked against `block_hash` before anything is written: a body filed
    /// under the wrong hash is a body `fetch_block` will hand to a peer as if it
    /// were the block that peer asked for, and the resulting `prev_hash` walk
    /// would follow a chain that does not exist.
    ///
    /// Like every other re-publish path this touches no head pointer and no
    /// block-hash index entry.
    pub async fn retro_publish_block_by_hash(
        &self,
        block_hash: [u8; 32],
        body: &[u8],
    ) -> Result<(), String> {
        let write = plan_block_body_publish_bytes(&self.epoch(), block_hash, body)?;
        apply_publish_plan(&self.node, &[write]).await
    }

    /// Re-publish a BOUNDED window of already-finalized block bodies.
    ///
    /// `blocks` is any iterator of block references — the caller decides which
    /// ones (e.g. the most recent N of `rt.finalized`, read back out of the local
    /// block store). `max` caps how many bodies this pass may touch, so a node
    /// with a long history never builds one enormous DHT write nor holds an
    /// unbounded amount of serialized state in memory: the caller runs pass after
    /// pass, feeding the remainder back in, while `report.maybe_more` is true.
    ///
    /// Tolerant by design: one body failing (a local block that is gone, a blob
    /// that reached neither local storage nor a replica) must not abandon the
    /// other N-1, because those are the ones that unblock the peer. The failures
    /// are counted and the first reason kept in `report.first_error` — never
    /// swallowed.
    pub async fn retro_publish_blocks<'a, I>(&self, blocks: I, max: usize) -> RetroPublishReport
    where
        I: IntoIterator<Item = &'a Block>,
    {
        let shared = self.node.clone();
        let mut it = blocks.into_iter();
        retro_publish_chunk(&mut it, max, move |b| {
            let node = shared.clone();
            async move {
                match plan_block_body_publish(&self.epoch(), b) {
                    Ok(writes) => apply_publish_plan(&node, &writes).await,
                    Err(e) => Err(e),
                }
            }
        })
        .await
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

    /// Overwrite a fixed-name pointer blob without orphaning its chunks.
    ///
    /// Chunk ids are content-addressed (every id mixes `H(plaintext)`), so ANY
    /// content change retires the WHOLE old chunk set, while the kv sweep only
    /// collects EXPIRED manifests — never an overwritten one. Without this, the
    /// head pointer (`{epoch}_shard_{n}_head`, rewritten every finalize and
    /// every ~30s probe) and the snapshot pointer (`{epoch}_snap_latest_{n}`,
    /// rewritten every snapshot) leak one chunk set per rewrite. Deleting the
    /// old blob first keeps the steady state at one live chunk set.
    ///
    /// LOCAL-ONLY (`delete_blob_local`, no replica fan-out) on purpose: the
    /// per-finalize path must not gain DHT traffic, the wire format is
    /// unchanged (old/new nodes interoperate), and the store below rewrites
    /// the manifest synchronously on the same FIFO lane, so readers see at
    /// most a momentary miss, repaired by the next finalize/probe republish.
    /// A failed store leaves the same state as before this change (the
    /// overwrite itself already replaced the manifest).
    async fn store_pointer_overwrite(&self, bucket: &str, name: &str, payload: &[u8], ttl_ms: i64) {
        self.node.delete_blob_local(bucket, name).await;
        // Same backpressure as every other publish (bounded, never infinite);
        // charged as a Pointer (small floor) rather than Bulk so the per-finalize
        // head republish cannot lag the tip behind the bulk lane.
        paced_store_blob(
            &self.node,
            bucket,
            name,
            payload,
            ttl_ms,
            ReplStoreKind::Pointer,
        )
        .await;
    }

    /// Publish this node's finalized head so a peer can discover it.
    ///
    /// This exists because the shard head pointer kept in DHT KV is written with
    /// `kv_store_local` and read back with `get_local_kv` — both strictly local.
    /// So `get_latest_shard_height` could only ever return *this* node's own
    /// published height, and a node asking "is a peer ahead of me?" was really
    /// asking "am I ahead of myself?". Block sync therefore never fired, and a
    /// node that fell behind had no way to learn that anyone was ahead of it.
    ///
    /// The head is stored as a blob in the replicated DHT bucket instead, which
    /// is the same path `fetch_block` uses, so a peer can actually read it.
    ///
    /// SELF-SHADOW GUARD: the head key is shared and last-writer-wins, so this
    /// refuses anything that is not a forward move of THIS process
    /// (`head_publish_allowed`): height 0 (genesis-only nodes have no tip to
    /// advertise — their write would bury a live tip) and heights at or below
    /// what this process already published (a stale republish rewinds the
    /// advertised head for every reader, including ourselves: the local
    /// manifest shadows peers on read). Returns true when published.
    pub async fn publish_head(&self, shard_id: u32, height: u64, hash: [u8; 32]) -> bool {
        let last = self
            .last_published_head
            .lock()
            .map(|m| m.get(&shard_id).copied().unwrap_or(0))
            .unwrap_or(0);
        if !head_publish_allowed(height, last) {
            tracing::debug!(
                "head publish refused: shard={shard_id} height={height} last_published={last} \
                 (genesis-only or stale; refusing to rewind the shared head key)"
            );
            return false;
        }
        if let Ok(mut m) = self.last_published_head.lock() {
            m.insert(shard_id, height);
        }
        let payload = format!("{height}:{}", hex::encode(hash));
        // The head pointer stays FOREVER: it is one entry per shard (overwritten
        // every finalize and every ~30s probe), and a lagging node needs a live
        // head to discover the tip at all. Overwrite via `store_pointer_overwrite`
        // so the retired chunk set is deleted instead of orphaned (chunk ids are
        // content-addressed: every rewrite would otherwise leak one file set).
        self.store_pointer_overwrite(
            BUCKET_STELLEREUM_HEAD,
            &head_name(&self.epoch(), shard_id),
            payload.as_bytes(),
            dht_forever_ttl_ms(),
        )
        .await;
        true
    }

    /// Read the most recently published shard head from the network.
    ///
    /// This is a best-effort "somebody told us about a head". It may well be our
    /// own, so callers must treat a result that is not strictly ahead of their own
    /// finalized height as "nothing to do" rather than as a peer being ahead.
    pub async fn fetch_head(&self, shard_id: u32) -> Option<(u64, [u8; 32])> {
        let _permit = fetch_sem().acquire().await.ok()?;
        let bytes = self
            .node
            .fetch_blob(BUCKET_STELLEREUM_HEAD, &head_name(&self.epoch(), shard_id))
            .await?;
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

    /// Publish a finalized block's HEADER so a cold node can chain from a snapshot.
    ///
    /// A header is small (no transactions) and is published every block, unlike the
    /// bounded body window, which is what lets recovery work for a gap of any size:
    /// the walk needs headers all the way, and bodies only above the snapshot.
    pub async fn persist_block_header(&self, shard_id: u32, block: &Block) {
        let rec = crate::storage::BlockHeaderRecord::of(block);
        if let Ok(bytes) = bincode::serialize(&rec) {
            let ttl = dht_blob_ttl_ms(retention_keep_blocks());
            // One logical publish: only the header body charges the pacing gate;
            // the index + QC sidecar ride along (same bounded store, no extra
            // interval charge) so a 3-blob header never pays 3x the floor.
            //
            // LANE (see [`header_publish_slots`]): all three blobs ride the
            // header's Pointer lane, so the per-lane circuit breaker treats
            // them as ONE unit. They used to split: the header went to the
            // Pointer lane while the sidecars went to the Bulk lane, so a
            // bulk-lane cooldown shed the QC sidecar while the header still
            // landed — and a catch-up node reads "header present, QC missing"
            // as "not anchorable" and rejects the header as unanchored. A
            // split pair is worse than a missing pair: a missing pair is
            // skipped consistently, a split pair looks like an unanchored
            // header.
            let slots = header_publish_slots();
            paced_store_blob_in_lane(
                &self.node,
                BUCKET_STELLEREUM_HEADERS,
                &header_name(&self.epoch(), block.height),
                &bytes,
                ttl,
                slots[0].charge,
                slots[0].lane,
            )
            .await;
            // And the height -> hash pointer, so a caller can ask for "the header at
            // height N" without already knowing the hash.
            let idx = format!("{}:{}", block.height, hex::encode(block.compute_hash()));
            paced_store_blob_in_lane(
                &self.node,
                BUCKET_STELLEREUM_HEADERS,
                &header_index_name(&self.epoch(), shard_id, block.height),
                idx.as_bytes(),
                ttl,
                slots[1].charge,
                slots[1].lane,
            )
            .await;
            // A1 anchor: QC sidecar beside the header (same bucket, same
            // TTL, SAME LANE). Blocks without a QC (e.g. genesis) publish no
            // sidecar; readers treat a missing sidecar as "not anchorable",
            // never as trusted. Header first, then QC: a crash between writes
            // yields "missing QC → skip", never a half-trusted header.
            if let Some(qc) = block.precommit_qc.as_ref() {
                if let Ok(qc_bytes) = bincode::serialize(qc) {
                    paced_store_blob_in_lane(
                        &self.node,
                        BUCKET_STELLEREUM_HEADERS,
                        &header_qc_name(&self.epoch(), shard_id, block.height),
                        &qc_bytes,
                        ttl,
                        slots[2].charge,
                        slots[2].lane,
                    )
                    .await;
                }
            }
        }
        // Retention rides the per-height publish traffic: this runs on
        // `publish_lane` (never the consensus tick), throttled to the snapshot
        // cadence and capped per pass inside `maybe_prune_retained`.
        self.maybe_prune_retained(shard_id, block.height).await;
    }

    /// Delete this node's own DHT publishes below `finalized − KEEP`.
    ///
    /// Driven by the per-height header publish (i.e. by every finalize/adopt on
    /// `publish_lane`): no new task, no `main.rs` change, no extra wakeup.
    /// Each pass deletes at most `STELL_DHT_PRUNE_MAX_PER_RUN` heights and runs
    /// at most every `STELL_DHT_PRUNE_INTERVAL_HEIGHTS` heights, so the steady
    /// cost is ~one height's worth of local deletes per height, and an upgrade
    /// backlog (tens of thousands of heights) drains gradually.
    ///
    /// LOCAL-ONLY deletes (`delete_blob_local` / `kv_remove_local`): every
    /// node prunes what it published on its own schedule, so no replica fan-out
    /// and no new network delete service (and its auth surface) is needed.
    /// Replica copies carry the same window TTL (`dht_blob_ttl_ms`) and die in
    /// the sweep; the peer's own prune removes the rest.
    pub async fn maybe_prune_retained(&self, shard_id: u32, tip_height: u64) -> usize {
        let keep = retention_keep_blocks();
        let bound = prune_below_exclusive(tip_height, keep);
        // Resume across restarts: the first pass in this process picks up the
        // persisted cursor (a restart otherwise rewinds to 0 and the backlog
        // is never reached). Epoch-scoped key, so a new chain starts clean.
        if !self
            .prune_cursor_loaded
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let epoch = self.epoch();
            let key = prune_cursor_key(&epoch, shard_id);
            if let Some(raw) = self.node.get_local_kv(&key).await {
                if let Some(saved) = parse_prune_cursor(&raw) {
                    self.prune_cursor
                        .fetch_max(saved, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(
                        "prune resumed: cursor={} tip={} bound={}",
                        saved,
                        tip_height,
                        bound
                    );
                }
            }
        }
        let last_tip = self
            .last_prune_tip
            .load(std::sync::atomic::Ordering::Relaxed);
        if tip_height < last_tip + dht_prune_interval_heights() && bound > 0 {
            return 0;
        }
        let cursor = self.prune_cursor.load(std::sync::atomic::Ordering::Relaxed);
        if cursor >= bound {
            self.last_prune_tip
                .store(tip_height, std::sync::atomic::Ordering::Relaxed);
            return 0;
        }
        let (batch, next) = prune_batch(cursor, bound, dht_prune_max_per_run());
        let epoch = self.epoch();
        let mut pruned = 0usize;
        for h in batch {
            // The body is hash-addressed: resolve it through the height→hash
            // index. Only the LOCAL manifest is consulted first — if we never
            // published this height (e.g. snapshot-skipped) there is nothing of
            // ours to delete and no network fetch is spent looking.
            let idx_name = header_index_name(&epoch, shard_id, h);
            let idx_mkey =
                infnode::node::Node::blob_manifest_key(BUCKET_STELLEREUM_HEADERS, &idx_name);
            let body_hash_hex: Option<String> = if self.node.get_local_kv(&idx_mkey).await.is_some()
            {
                let Ok(_permit) = fetch_sem().acquire().await else {
                    return pruned;
                };
                self.node
                    .fetch_blob(BUCKET_STELLEREUM_HEADERS, &idx_name)
                    .await
                    .and_then(|b| parse_header_index(&b))
                    .and_then(|(ih, hex)| (ih == h).then_some(hex))
            } else {
                None
            };
            let plan = plan_retained_prune(&epoch, shard_id, h, body_hash_hex.as_deref());
            for (bucket, name) in &plan.blobs {
                self.node.delete_blob_local(bucket, name).await;
            }
            for k in &plan.kv {
                self.node.kv_remove_local(k).await;
            }
            pruned += 1;
        }
        self.prune_cursor
            .store(next, std::sync::atomic::Ordering::Relaxed);
        self.last_prune_tip
            .store(tip_height, std::sync::atomic::Ordering::Relaxed);
        // Persist the cursor so the next restart resumes instead of rewinding
        // to 0. One kv write per pass (every ~100 heights): negligible next
        // to the deletes themselves. Best-effort; a lost write only repeats
        // idempotent deletes.
        let epoch = self.epoch();
        let key = prune_cursor_key(&epoch, shard_id);
        self.node
            .kv_store_local_with_ttl(&key, &next.to_string(), dht_forever_ttl_ms())
            .await;
        tracing::info!(
            "prune pass: tip={} bound={} pruned={} cursor={}",
            tip_height,
            bound,
            pruned,
            next
        );
        pruned
    }

    /// Fetch the block hash published for `height`, or `None` if nobody published it.
    ///
    /// Retried (3 attempts, backoff) with one loud line on final failure:
    /// header index blobs are tiny, so a miss is either pruning or a weak
    /// link — both worth exactly one line, never silence (a silent miss here
    /// kills a whole snapshot-sync attempt with zero trace).
    pub async fn fetch_head_hash(&self, shard_id: u32, height: u64) -> Option<[u8; 32]> {
        let _permit = fetch_sem().acquire().await.ok()?;
        let name = header_index_name(&self.epoch(), shard_id, height);
        let mut last_err = "missing";
        for attempt in 1..=3u32 {
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
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
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt as u64)).await;
            }
        }
        eprintln!("[sync] fetch_head_hash shard={shard_id} height={height} name={name}: failed ({last_err})");
        None
    }

    /// Fetch a header by height AND hash, refusing one that does not match the hash.
    ///
    /// The hash argument is what makes this trustworthy: a peer cannot hand us a
    /// header for a different block under this height, because the record's own
    /// `block_hash` must equal the hash we asked for.
    pub async fn fetch_block_header(
        &self,
        shard_id: u32,
        height: u64,
        expected_hash: [u8; 32],
    ) -> Option<crate::storage::BlockHeaderRecord> {
        let _permit = fetch_sem().acquire().await.ok()?;
        let name = header_name(&self.epoch(), height);
        let mut last_err = "missing";
        for attempt in 1..=3u32 {
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
            if let Some(bytes) = blob_res {
                match bincode::deserialize::<crate::storage::BlockHeaderRecord>(&bytes) {
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
        let _permit = fetch_sem().acquire().await.ok()?;
        let name = header_qc_name(&self.epoch(), shard_id, height);
        let mut last_err = "missing";
        for attempt in 1..=3u32 {
            let blob_res = tokio::time::timeout(
                std::time::Duration::from_millis(10_000),
                self.node.fetch_blob(BUCKET_STELLEREUM_HEADERS, &name),
            )
            .await
            .ok()
            .flatten();
            if let Some(bytes) = blob_res {
                match bincode::deserialize::<crate::consensus::QuorumCertificate>(&bytes) {
                    Ok(qc) => return Some(qc),
                    Err(_) => last_err = "bad bincode",
                }
            } else {
                last_err = "fetch miss/timeout";
            }
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt as u64)).await;
            }
        }
        eprintln!("[sync] fetch_block_qc shard={shard_id} height={height} name={name}: failed ({last_err})");
        None
    }

    /// Persist in-memory state snapshot to P2P network
    ///
    /// FAIL-CLOSED POINTER (fix 2026-10-15, live incident): the state blob and
    /// the latest-snapshot pointer used to publish independently — a shed or
    /// dropped Bulk store (backpressure SHED/DROP, 5s-timeout exhaustion on a
    /// tens-of-MB blob) left NO manifest anywhere while the Pointer-lane
    /// pointer write still succeeded, so the pointer advertised heights whose
    /// manifests every fetcher then missed ("boundary likely unpublished").
    /// The pointer now advances ONLY when the state blob demonstrably landed
    /// (`paced_store_blob` > 0, i.e. local chunks or at least one replica);
    /// otherwise the pointer stays at the last GOOD height and the failure is
    /// LOUD on both channels. Returns true when the snapshot (and pointer)
    /// published.
    pub async fn persist_state_snapshot(
        &self,
        shard_id: u32,
        height: u64,
        snapshot_data: &[u8],
    ) -> bool {
        let name = snapshot_name(&self.epoch(), shard_id, height);
        // Snapshots stay FOREVER (one per 100 heights): `try_snapshot_sync`
        // probes recent 100-height boundaries downward, and the snapshot at the
        // boundary plus the header above it is what lets a node thousands of
        // blocks behind skip execution. Pruning them would strand far-behind
        // nodes with no in-band recovery.
        // Paced as Bulk: a tens-of-MB snapshot fans out to a per-chunk
        // `replicate_blob` burst, the exact hammer shape of 2026-10-14.
        {
            let line = format!(
                "[snapshot-publish] state snapshot shard={shard_id} height={height} \
                 publishing {} bytes as {name}",
                snapshot_data.len()
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        let stored = paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_STATE,
            &name,
            snapshot_data,
            dht_forever_ttl_ms(),
            ReplStoreKind::Bulk,
        )
        .await;
        if stored == 0 {
            // The Bulk store shed/dropped (LOUD line already emitted by
            // `paced_store_blob`): there is no manifest anywhere, so the
            // pointer MUST NOT move — otherwise every catcher probes a
            // boundary that can never resolve.
            let line = format!(
                "[snapshot-publish] state snapshot shard={shard_id} height={height} \
                 FAILED to land (store reached nobody; see [repl-backpressure] line above); \
                 pointer NOT advancing (fail-closed)"
            );
            eprintln!("{line}");
            tracing::error!("{line}");
            return false;
        }
        {
            let line = format!(
                "[snapshot-publish] state snapshot shard={shard_id} height={height} \
                 manifest landed (store count {stored}); advancing latest pointer"
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        // Latest-snapshot pointer (same FOREVER TTL): snapshots complete on
        // worker timing, so their heights are arbitrary (78519, 78620, ...),
        // not round hundreds. A catcher reading this pointer fetches the exact
        // boundary first instead of missing 128 round-hundred probes.
        let ptr_name = snapshot_latest_name(&self.epoch(), shard_id);
        // Fixed-name pointer, rewritten on every snapshot (same orphan rule as
        // the head pointer: without the delete-first overwrite each rewrite
        // would leak its content-addressed chunk set).
        self.store_pointer_overwrite(
            BUCKET_STELLEREUM_STATE,
            &ptr_name,
            &height.to_le_bytes(),
            dht_forever_ttl_ms(),
        )
        .await;
        {
            let line = format!(
                "[snapshot-publish] latest-snapshot pointer shard={shard_id} advanced to {height}"
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        true
    }

    /// Read the latest-snapshot pointer (exact height of the newest published
    /// state snapshot), if any peer published one. Returns `None` on miss —
    /// callers fall back to the %100 probe walk.
    pub async fn fetch_latest_snapshot(&self, shard_id: u32) -> Option<u64> {
        let _permit = fetch_sem().acquire().await.ok()?;
        let name = snapshot_latest_name(&self.epoch(), shard_id);
        for attempt in 1..=3u32 {
            if let Some(bytes) = self.node.fetch_blob(BUCKET_STELLEREUM_STATE, &name).await {
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
        let _permit = fetch_sem().acquire().await.ok()?;
        let _snap = snapshot_fetch_sem().acquire().await.ok()?;
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
                for n in closest.iter() {
                    if node.ensure_dht_peer(n).await.is_ok() {
                        if let Ok(resp) = node.request_to(n.id, "dht.find_value", q.clone()).await {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                                if v["found"].as_bool().unwrap_or(false) {
                                    if let Some(s) = v["value"].as_str() {
                                        return Some(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                    // Yield between peers: a manifest sweep over a slow peer
                    // set must not wedge the 1-vCPU tick.
                    tokio::task::yield_now().await;
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
        let manifest: serde_json::Value = serde_json::from_str(&manifest_str)
            .map_err(|e| {
                eprintln!(
                    "[sync] snapshot-fetch manifest undecodable: {bucket}/{name}: {e:?} \
                 (treating as miss, not trusted)"
                );
            })
            .ok()?;
        let nonce = hex::decode(manifest["nonce"].as_str().unwrap_or(""))
            .map_err(|_| {
                eprintln!(
                    "[sync] snapshot-fetch manifest {bucket}/{name}: bad nonce (treating as miss)"
                );
            })
            .ok()?;
        let key = hex::decode(manifest["key"].as_str().unwrap_or(""))
            .map_err(|_| {
                eprintln!(
                    "[sync] snapshot-fetch manifest {bucket}/{name}: bad key (treating as miss)"
                );
            })
            .ok()?;
        if key.len() != 32 {
            eprintln!(
                "[sync] snapshot-fetch manifest {bucket}/{name}: key is {} bytes, want 32 \
                 (treating as miss)",
                key.len()
            );
            return None;
        }
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&key);
        let size = manifest["size"].as_u64().unwrap_or(0) as usize;
        let mut metas = Vec::new();
        if let Some(chunks) = manifest["chunks"].as_array() {
            for c in chunks {
                metas.push(SnapshotChunkMeta {
                    id: c["id"].as_str().unwrap_or("").to_string(),
                    hash: c["hash"].as_str().map(|s| s.to_string()),
                });
            }
        }
        if metas.is_empty() && size > 0 {
            eprintln!(
                "[sync] snapshot-fetch manifest {bucket}/{name}: declares {size} bytes \
                 but lists no chunks (treating as miss)"
            );
            return None;
        }
        Some((metas, dk, nonce, size))
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
            let Some((metas, dk, nonce, size)) =
                Self::fetch_snapshot_manifest(node, bucket, name).await
            else {
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
                                node.fetch_chunk_net(&bucket, &cid, expected.as_deref()),
                            )
                            .await;
                            match got {
                                Ok(Some(bytes)) => Some(bytes),
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
                    let mut ct = Vec::with_capacity(chunks.iter().map(|c| c.len()).sum());
                    for c in &chunks {
                        ct.extend_from_slice(c);
                    }
                    match infnode::node::e2e_decrypt(&dk, &nonce, &ct) {
                        Ok(plain) => {
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

    /// Publish one committed-domain blob beside the state snapshot (audit
    /// follow-up F-J): snapshot-sync restored ACCOUNTS ONLY, so a far-behind
    /// node on a live chain could never fast-sync (root check failed on any
    /// staking/token/bridge activity). `kind` is one of: domains, session,
    /// bridge, confidential, zkml, cross_shard. Same FOREVER retention as the
    /// state blob (one set per 100 heights).
    ///
    /// Fail-closed (fix 2026-10-15): a shed/dropped Bulk store is LOUD (not
    /// silent) and reported to the caller. Returns true when the blob landed.
    pub async fn persist_domain_snapshot(
        &self,
        shard_id: u32,
        height: u64,
        kind: &str,
        data: &[u8],
    ) -> bool {
        let name = format!(
            "{}_dom_{kind}",
            snapshot_name(&self.epoch(), shard_id, height)
        );
        // Paced as Bulk like the state blob it rides beside (same fan-out shape).
        let stored = paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_STATE,
            &name,
            data,
            dht_forever_ttl_ms(),
            ReplStoreKind::Bulk,
        )
        .await;
        if stored == 0 {
            let line = format!(
                "[snapshot-publish] domain snapshot shard={shard_id} height={height} kind={kind} \
                 FAILED to land (store reached nobody; see [repl-backpressure] line above)"
            );
            eprintln!("{line}");
            tracing::error!("{line}");
            return false;
        }
        {
            let line = format!(
                "[snapshot-publish] domain snapshot shard={shard_id} height={height} kind={kind} \
                 published {} bytes (store count {stored})",
                data.len()
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        true
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
        let _permit = fetch_sem().acquire().await.ok()?;
        let _snap = snapshot_fetch_sem().acquire().await.ok()?;
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

    /// Broadcast transaction into mempool over infnode DHT KV
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<[u8; 32], String> {
        if !tx.verify_signature() {
            return Err("Invalid transaction signature".to_string());
        }
        let tx_hash = tx.compute_tx_hash();
        let hash_hex = hex::encode(tx_hash);
        let tx_bytes =
            bincode::serialize(tx).map_err(|e| format!("Tx serialize error: {:?}", e))?;

        let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, hash_hex);
        self.node
            .kv_store_local(&tx_key, &hex::encode(&tx_bytes))
            .await;

        // Append to shard mempool index
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, tx.source_shard);
        let current_index = self.node.get_local_kv(&shard_key).await.unwrap_or_default();
        let mut hashes: Vec<String> = serde_json::from_str(&current_index).unwrap_or_default();
        if !hashes.contains(&hash_hex) {
            hashes.push(hash_hex);
            let serialized = serde_json::to_string(&hashes).unwrap_or_default();
            self.node.kv_store_local(&shard_key, &serialized).await;
        }

        Ok(tx_hash)
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
                    } else if let Ok(tx) = bincode::deserialize::<Transaction>(&bytes) {
                        entries.push(MempoolEntry::Plain(tx));
                    }
                }
            }
        }

        entries
    }

    /// Broadcast a SEALED transaction into the mempool over infnode DHT KV.
    ///
    /// Only the CIPHERTEXT is written to the DHT: the plaintext of a sealed
    /// transaction never touches the network store.
    pub async fn broadcast_sealed_transaction(
        &self,
        envelope: &crate::mev_epoch::SealedEnvelope,
    ) -> Result<[u8; 32], String> {
        envelope
            .validate()
            .map_err(|e| format!("refusing to broadcast a malformed sealed transaction: {e}"))?;
        let tx_hash = envelope.tx_hash;
        let hash_hex = hex::encode(tx_hash);
        let tx_bytes = crate::mev_epoch::encode_sealed_payload(envelope)?;

        let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, hash_hex);
        self.node
            .kv_store_local(&tx_key, &hex::encode(&tx_bytes))
            .await;

        // Append to shard mempool index
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, envelope.meta.source_shard);
        let current_index = self.node.get_local_kv(&shard_key).await.unwrap_or_default();
        let mut hashes: Vec<String> = serde_json::from_str(&current_index).unwrap_or_default();
        if !hashes.contains(&hash_hex) {
            hashes.push(hash_hex);
            let serialized = serde_json::to_string(&hashes).unwrap_or_default();
            self.node.kv_store_local(&shard_key, &serialized).await;
        }

        Ok(tx_hash)
    }

    /// Clear confirmed transactions from mempool
    pub async fn clear_mempool_transactions(&self, shard_id: u32, confirmed_hashes: &[[u8; 32]]) {
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, shard_id);
        let Some(index_str) = self.node.get_local_kv(&shard_key).await else {
            return;
        };

        let mut hashes: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
        let confirmed_hexes: Vec<String> = confirmed_hashes.iter().map(hex::encode).collect();

        hashes.retain(|h| !confirmed_hexes.contains(h));

        for h in &confirmed_hexes {
            let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, h);
            self.node.kv_remove_local(&tx_key).await;
        }

        let serialized = serde_json::to_string(&hashes).unwrap_or_default();
        self.node.kv_store_local(&shard_key, &serialized).await;
    }

    /// Broadcast cross-shard message via infnode overlay
    pub async fn broadcast_cross_shard(&self, msg: &CrossShardMessage) -> Result<(), String> {
        let msg_id_hex = hex::encode(msg.msg_id);
        let msg_bytes = bincode::serialize(msg)
            .map_err(|e| format!("CrossShardMessage serialize error: {:?}", e))?;

        let key = format!("{}{}:{}", PREFIX_CROSS_SHARD, msg.target_shard, msg_id_hex);
        self.node
            .kv_store_local(&key, &hex::encode(&msg_bytes))
            .await;

        let index_key = format!("{}{}:index", PREFIX_CROSS_SHARD, msg.target_shard);
        let current_index = self.node.get_local_kv(&index_key).await.unwrap_or_default();
        let mut ids: Vec<String> = serde_json::from_str(&current_index).unwrap_or_default();
        if !ids.contains(&msg_id_hex) {
            ids.push(msg_id_hex);
            let serialized = serde_json::to_string(&ids).unwrap_or_default();
            self.node.kv_store_local(&index_key, &serialized).await;
        }

        Ok(())
    }

    /// Decode a cross-shard message received from the network.
    ///
    /// SECURITY (critical): the `trusted` flag bypasses Merkle inclusion
    /// verification. A message decoded from the wire ALWAYS has `trusted` cleared,
    /// so an attacker cannot forge a "trusted" message and mint value on the
    /// target shard. Only locally-generated messages (`new_trusted`) are trusted.
    pub fn parse_cross_shard_incoming(bytes: &[u8]) -> Option<CrossShardMessage> {
        let mut msg: CrossShardMessage = bincode::deserialize(bytes).ok()?;
        msg.trusted = false;
        Some(msg)
    }

    /// Drop consumed cross-shard entries for `target_shard` by `msg_id`
    /// (§5 M3 pruning; the `Node` half of `CrossShardTransport::prune_consumed`).
    ///
    /// Removes each per-message KV entry and rewrites the node-local index
    /// without the pruned ids. Best-effort and idempotent: missing entries
    /// and a missing index are successes (nothing to remove), never errors,
    /// because pruning rides the apply path and must not fail finalization.
    /// Returns how many per-message entries were dropped (the index rewrite
    /// is not counted; it carries no value on its own).
    pub async fn prune_cross_shard_consumed(
        &self,
        target_shard: u32,
        msg_ids: &[[u8; 32]],
    ) -> usize {
        if msg_ids.is_empty() {
            return 0;
        }
        let drop: std::collections::HashSet<String> = msg_ids.iter().map(hex::encode).collect();
        let mut pruned = 0usize;
        for id_hex in &drop {
            let key = format!("{}{}:{}", PREFIX_CROSS_SHARD, target_shard, id_hex);
            self.node.kv_remove_local(&key).await;
            pruned += 1;
        }
        let index_key = format!("{}{}:index", PREFIX_CROSS_SHARD, target_shard);
        if let Some(index_str) = self.node.get_local_kv(&index_key).await {
            let ids: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
            if ids.iter().any(|i| drop.contains(i)) {
                let kept: Vec<String> = ids.into_iter().filter(|i| !drop.contains(i)).collect();
                let serialized = serde_json::to_string(&kept).unwrap_or_default();
                self.node.kv_store_local(&index_key, &serialized).await;
            }
        }
        pruned
    }

    /// Fetch inbound cross-shard messages destined for this shard
    pub async fn fetch_cross_shard_inbound(&self, target_shard: u32) -> Vec<CrossShardMessage> {
        let index_key = format!("{}{}:index", PREFIX_CROSS_SHARD, target_shard);
        let Some(index_str) = self.node.get_local_kv(&index_key).await else {
            return Vec::new();
        };

        let ids: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
        let mut messages = Vec::with_capacity(ids.len());

        for id_hex in ids {
            let key = format!("{}{}:{}", PREFIX_CROSS_SHARD, target_shard, id_hex);
            if let Some(val_hex) = self.node.get_local_kv(&key).await {
                if let Ok(bytes) = hex::decode(&val_hex) {
                    if let Some(msg) = Self::parse_cross_shard_incoming(&bytes) {
                        messages.push(msg);
                    }
                }
            }
        }

        messages
    }

    /// Publish oracle price update to P2P network
    pub async fn broadcast_price_feed(&self, update: &PriceFeedUpdate) -> Result<(), String> {
        if !update.verify() {
            return Err("Invalid oracle signature".to_string());
        }
        let update_bytes = bincode::serialize(update)
            .map_err(|e| format!("PriceFeedUpdate serialize error: {:?}", e))?;
        let key = format!("{}{}", PREFIX_ORACLE, update.asset);
        self.node
            .kv_store_local(&key, &hex::encode(&update_bytes))
            .await;
        Ok(())
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

    /// Broadcast MEV blind round commitment
    pub async fn broadcast_blind_round(&self, commit: &BlindRoundCommitment) -> Result<(), String> {
        let commit_bytes = bincode::serialize(commit)
            .map_err(|e| format!("BlindRoundCommitment serialize error: {:?}", e))?;
        let key = format!("{}{}", PREFIX_MEV_COMMIT, commit.round_number);
        self.node
            .kv_store_local(&key, &hex::encode(&commit_bytes))
            .await;
        Ok(())
    }

    /// Fetch MEV blind round commitment by round number
    pub async fn fetch_blind_round(&self, round: u64) -> Option<BlindRoundCommitment> {
        let key = format!("{}{}", PREFIX_MEV_COMMIT, round);
        let val_hex = self.node.get_local_kv(&key).await?;
        let bytes = hex::decode(&val_hex).ok()?;
        bincode::deserialize(&bytes).ok()
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

/// One network write performed by a block publish: a blob into `bucket` named
/// `name`, plus any local DHT KV entries committed alongside it.
///
/// A publish is PLANNED as data and then applied, so the complete set of network
/// effects is inspectable without a live DHT. That matters most for the
/// retro-publish path, whose safety property is "this writes no KV at all" — a
/// property that is only checkable if the effects are values rather than a
/// sequence of `await`s buried in a method body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishWrite {
    pub bucket: &'static str,
    pub name: String,
    pub bytes: Vec<u8>,
    /// Local DHT KV entries committed together with the blob. A BODY publish
    /// carries none of these; see `plan_block_body_publish`.
    pub kv: Vec<(String, String)>,
}

/// The blob name a block body is stored under.
///
/// This MUST stay byte-identical to the name `fetch_block` looks up, or a body is
/// published into a bucket slot nobody will ever ask for and the peer stays stuck on
/// `block sync: missing block`. Exposed as a function so a test can pin the
/// convention instead of trusting a comment to keep it.
///
/// Takes the epoch, because bisecting the name and the reader is exactly the failure
/// this exists to prevent: `broadcast_block` wrote under an epoch-scoped name while
/// the retro-publish path wrote the bare hash, so the two produced different slots for
/// the same block and neither could find the other's body.
pub fn block_body_blob_name(epoch: &EpochTag, block_hash: &[u8; 32]) -> String {
    block_name(epoch, &hex::encode(block_hash))
}

/// Plan the network writes that publish `block`'s BODY, and nothing else.
///
/// Deliberately carries no `PREFIX_LATEST_HEIGHT` and no `PREFIX_BLOCK_HASH`
/// write, because those two are head ANNOUNCEMENTS rather than body storage.
/// Replaying them from a re-publish is actively harmful: a node 1000 blocks
/// behind that re-published its own history would overwrite the advertised head
/// with `height:hash` from the middle of its own chain, so every peer would watch
/// the network's head rewind by a thousand blocks and the lagging node would
/// stop being able to find the very tip it is trying to catch. The body is what
/// the peer is missing; the pointer is not.
pub fn plan_block_body_publish(
    epoch: &EpochTag,
    block: &Block,
) -> Result<Vec<PublishWrite>, String> {
    let block_hash = block.compute_hash();
    let bytes = bincode::serialize(block).map_err(|e| format!("block serialize failed: {e:?}"))?;
    Ok(vec![body_write(epoch, block_hash, bytes)])
}

/// The same single body write, from stored bytes addressed by a hash the caller
/// already has.
///
/// The body is decoded and re-hashed, and a mismatch is refused rather than
/// published: the DHT name IS the hash, so a body filed under a hash it does
/// not compute to is a permanently poisoned slot — `fetch_block` would return
/// it to a peer as the block that peer requested. Cheap relative to the write,
/// and it makes the "publish by hash" entry point safe to drive from a disk
/// scan without trusting the scan.
pub fn plan_block_body_publish_bytes(
    epoch: &EpochTag,
    block_hash: [u8; 32],
    body: &[u8],
) -> Result<PublishWrite, String> {
    let block: Block =
        bincode::deserialize(body).map_err(|e| format!("block body deserialize failed: {e:?}"))?;
    let computed = block.compute_hash();
    if computed != block_hash {
        return Err(format!(
            "block body hashes to {} but was addressed as {}",
            hex::encode(computed),
            hex::encode(block_hash)
        ));
    }
    Ok(body_write(epoch, block_hash, body.to_vec()))
}

/// The one write a body publish is: a blob in the block bucket, named by hash,
/// with no local KV riding along.
fn body_write(epoch: &EpochTag, block_hash: [u8; 32], bytes: Vec<u8>) -> PublishWrite {
    PublishWrite {
        bucket: BUCKET_STELLEREUM_BLOCKS,
        name: block_body_blob_name(epoch, &block_hash),
        bytes,
        kv: Vec::new(),
    }
}

/// Apply a publish plan against the DHT.
///
/// A `store_blob` that landed on neither local storage nor a replica is reported
/// as a failure rather than ignored the way `broadcast_block` ignores it: it
/// means the body exists on nobody's disk, which is the exact condition this
/// whole path exists to repair, so it must never be counted as a success.
async fn apply_publish_plan(node: &Arc<Node>, writes: &[PublishWrite]) -> Result<(), String> {
    // Retro-published bodies are the same bodies `broadcast_block` publishes,
    // so they carry the same retention-window TTL (see `dht_blob_ttl_ms`).
    let ttl = dht_blob_ttl_ms(retention_keep_blocks());
    for w in writes {
        // Bounded publish (backpressure 2026-10-14): retries + circuit breaking
        // live inside `paced_store_blob`. A body that reaches nobody after the
        // full budget is still an Err here (the repair condition), counted by
        // the caller — never retried unboundedly.
        let stored =
            paced_store_blob(node, w.bucket, &w.name, &w.bytes, ttl, ReplStoreKind::Bulk).await;
        if stored == 0 {
            return Err(format!(
                "block body {}/{} reached no local chunk and no replica",
                w.bucket, w.name
            ));
        }
        for (k, v) in &w.kv {
            node.kv_store_local(k, v).await;
        }
    }
    Ok(())
}

/// What one bounded retro-publish pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetroPublishReport {
    /// Bodies taken from the caller's iterator during this pass.
    pub attempted: usize,
    /// Bodies that reached the DHT.
    pub published: usize,
    /// Bodies that did not. Counted and reported, never silently swallowed, and
    /// never fatal to the rest of the pass.
    pub failed: usize,
    /// The pass stopped because it hit `max`, so the iterator MAY still hold
    /// bodies and the caller should run another pass. An over-approximation on
    /// purpose: a window that exactly filled with nothing left over still
    /// reports `true`, and the extra pass publishes 0 and returns immediately.
    pub maybe_more: bool,
    /// The first failure's reason, so a log line can say WHY and not only how
    /// many. Later failures are counted but not retained, so a fully broken
    /// pass cannot grow without bound either.
    pub first_error: Option<String>,
}

/// Take at most `max` items from `iter` and `publish` each one, tolerantly.
///
/// The transport is the caller's closure, so this bounded-chunking and
/// failure-accounting logic is the same code both the live batch method and a
/// unit test drive — the bound cannot drift between them. One failing item is
/// recorded and the walk continues: aborting would forfeit the N-1 bodies that
/// are precisely the ones a lagging peer needs.
pub async fn retro_publish_chunk<I, T, F, Fut>(
    iter: &mut I,
    max: usize,
    mut publish: F,
) -> RetroPublishReport
where
    I: Iterator<Item = T>,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut report = RetroPublishReport::default();
    let mut taken = 0usize;
    while taken < max {
        let Some(item) = iter.next() else { break };
        taken += 1;
        report.attempted += 1;
        match publish(item).await {
            Ok(()) => report.published += 1,
            Err(e) => {
                report.failed += 1;
                if report.first_error.is_none() {
                    report.first_error = Some(e);
                }
            }
        }
        if taken < max {
            // Jittered pacing: the base 5ms spread plus a 0..=5ms draw so
            // publishers that woke on the same cadence do not re-synchronize
            // their `replicate_blob` bursts onto the same newcomer. Floor is
            // always the base pace — pushes never fire faster than before.
            tokio::time::sleep(std::time::Duration::from_millis(
                crate::sync::retro_publish_pace_with_jitter_ms(rand::random::<u64>()),
            ))
            .await;
        }
    }
    // `max == 0` is a no-op pass and NOT "there may be more", so a caller that
    // loops on `maybe_more` can never spin.
    report.maybe_more = max > 0 && taken == max;
    report
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
    let _permit = fetch_sem().acquire().await.ok()?;
    let bytes = adapter
        .node
        .fetch_blob(
            BUCKET_STELLEREUM_BLOCKS,
            &block_body_blob_name(&adapter.epoch(), expected_hash),
        )
        .await?;
    // A body fetched from a PEER is wire data: it must decode STRICTLY. The
    // legacy tolerance (a body persisted before the trailing commitment
    // fields existed) applies to the LOCAL STORE only — otherwise a
    // truncated peer body would be silently reinterpreted as a different
    // block (audit W6.4b).
    let block: Block = match bincode::deserialize(&bytes) {
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

/// In-process cross-shard mailbox with the SAME contract as the infnode KV
/// helpers above (`broadcast_cross_shard` / `fetch_cross_shard_inbound`).
///
/// The real transport is the infnode `Node`'s local KV, and it is NODE-LOCAL:
/// two shards can only exchange messages if they run in ONE process behind ONE
/// node. That is fine for the multi-shard runtime (`STELL_SHARDS=0,1`) but
/// impossible (and unnecessary) to spin up in a unit test, so the simulator
/// uses this in-memory twin. Both are keyed by `msg_id` so a broadcast is
/// idempotent, which matches `P2pNetworkAdapter::broadcast_cross_shard`'s
/// index-based dedupe.
///
/// The node-local KV cannot move a message between two physical servers at
/// all; that is what the gossip variant [`P2pCrossShardTransport`] is for.
#[derive(Default)]
pub struct LocalCrossShardKv {
    inbound: tokio::sync::Mutex<std::collections::HashMap<u32, Vec<CrossShardMessage>>>,
}

impl LocalCrossShardKv {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn broadcast_cross_shard(&self, msg: &CrossShardMessage) -> Result<(), String> {
        let mut map = self.inbound.lock().await;
        let queue = map.entry(msg.target_shard).or_default();
        if !queue.iter().any(|m| m.msg_id == msg.msg_id) {
            queue.push(msg.clone());
        }
        Ok(())
    }

    pub async fn fetch_cross_shard_inbound(&self, target_shard: u32) -> Vec<CrossShardMessage> {
        self.inbound
            .lock()
            .await
            .get(&target_shard)
            .cloned()
            .unwrap_or_default()
    }

    /// Drop consumed entries for `target_shard` by `msg_id` (§5 M3 pruning).
    ///
    /// Node-local KV hygiene, not consensus state: entries a shard already
    /// committed stay in the mailbox forever otherwise (every broadcast is
    /// idempotent and retained), so each apply prunes exactly the records it
    /// consumed. Idempotent: pruning an absent id removes nothing and still
    /// succeeds. Returns how many entries were removed.
    pub async fn prune(&self, target_shard: u32, msg_ids: &[[u8; 32]]) -> usize {
        if msg_ids.is_empty() {
            return 0;
        }
        let mut map = self.inbound.lock().await;
        let Some(queue) = map.get_mut(&target_shard) else {
            return 0;
        };
        let before = queue.len();
        queue.retain(|m| !msg_ids.contains(&m.msg_id));
        before - queue.len()
    }
}

/// Maximum encoded size of one cross-shard gossip payload.
///
/// A cross-shard message carries one transaction plus an optional Merkle
/// proof: kilobytes, not megabytes. The cap keeps a malformed or oversized
/// payload from being pushed into the overlay.
pub const MAX_CROSS_SHARD_MSG: usize = 4 * 1024 * 1024;

/// How many mesh hops a cross-shard gossip message may take.
///
/// The overlay relays a published message to the peers of the peer that
/// handled the publish, TTL hops deep. Three hops cover a small validator
/// mesh; a target shard on a server that is not a DIRECT peer of the sender
/// still hears the message.
pub const CROSS_SHARD_RELAY_TTL: u64 = 3;

/// How many msg_ids the gossip dedupe window remembers.
///
/// Gossip duplicates are normal (the mesh relays, and a peer may re-publish
/// on reconnect), so a message id is remembered for a while. The window is
/// bounded so a long-running node cannot grow the set without limit.
pub const CROSS_SHARD_DEDUPE_WINDOW: usize = 8192;

/// Boxed future returned by the pubsub abstraction.
///
/// The abstraction is a trait OBJECT (the transport lives in an `Arc` inside
/// [`CrossShardTransport`]), so its methods cannot use `async fn` in trait
/// position without losing object safety.
pub type CrossShardPubSubFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The pubsub primitive a cross-shard transport is built on.
///
/// infnode's `Node` is a concrete type, so the transport talks to the overlay
/// through this trait. Production uses [`InfnodeCrossShardPubSub`] (the real
/// QUIC mesh); the simulator and the unit tests use
/// [`InMemoryCrossShardPubSub`]. Both implement the SAME contract, which is
/// what makes the gossip path testable without a live network:
///
///  * `publish(topic, data)` — deliver `data` to every subscriber of `topic`,
///    the local ones included.
///  * `subscribe(topic)` — hand out a receiver of the payloads published to
///    `topic` AFTER the subscription (gossip has NO replay: a message
///    published before the subscription is never delivered).
///
/// `data` is the transport's own encoding (hex of a bincode message); every
/// implementation wraps it in the JSON envelope the decoder expects.
pub trait CrossShardPubSub: Send + Sync {
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<(), String>>;

    fn subscribe<'a>(
        &'a self,
        topic: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<tokio::sync::mpsc::UnboundedReceiver<String>, String>>;
}

/// In-memory twin of the overlay's pubsub: one bus of topics, shared by every
/// transport holding the same instance.
///
/// It models the gossip semantics exactly (publish → every subscriber of the
/// topic receives the payload; NO replay, so a subscription made after a
/// publish never sees that message), so a test that passes here describes the
/// real overlay's behaviour instead of a friendlier fiction.
#[derive(Default)]
pub struct InMemoryCrossShardPubSub {
    topics: std::sync::Mutex<
        std::collections::HashMap<String, Vec<tokio::sync::mpsc::UnboundedSender<String>>>,
    >,
}

impl InMemoryCrossShardPubSub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh bus, to be shared by the transports of one "network".
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl CrossShardPubSub for InMemoryCrossShardPubSub {
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let envelope = serde_json::json!({ "topic": topic, "data": data }).to_string();
            let senders = {
                let map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
                map.get(topic).cloned().unwrap_or_default()
            };
            for tx in senders {
                let _ = tx.send(envelope.clone());
            }
            Ok(())
        })
    }

    fn subscribe<'a>(
        &'a self,
        topic: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<tokio::sync::mpsc::UnboundedReceiver<String>, String>>
    {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let mut map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(topic.to_string()).or_default().push(tx);
            Ok(rx)
        })
    }
}

/// The node-local topic bus: the same-node delivery path of the pubsub layer.
///
/// The overlay cannot loop a published message back to its own publisher (a
/// `pubsub.msg` goes to PEERS), so two shards of one process (the
/// `STELL_SHARDS=0,1` shape) need an explicit same-node path: without it a
/// cross-shard message published by shard 0 would never reach shard 1 running
/// in the same process.
#[derive(Default)]
struct LocalTopicBus {
    topics: std::sync::Mutex<
        std::collections::HashMap<String, Vec<tokio::sync::mpsc::UnboundedSender<String>>>,
    >,
}

impl LocalTopicBus {
    /// The process-wide bus (one node per process, one bus per node).
    fn shared() -> Arc<Self> {
        static BUS: std::sync::OnceLock<Arc<LocalTopicBus>> = std::sync::OnceLock::new();
        Arc::clone(BUS.get_or_init(|| Arc::new(LocalTopicBus::default())))
    }

    fn subscribe(&self, topic: &str) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(topic.to_string()).or_default().push(tx);
        rx
    }

    fn publish(&self, topic: &str, envelope: &str) {
        let senders = {
            let map = self.topics.lock().unwrap_or_else(|e| e.into_inner());
            map.get(topic).cloned().unwrap_or_default()
        };
        for tx in senders {
            let _ = tx.send(envelope.to_string());
        }
    }
}

/// The real overlay path: infnode pubsub over the QUIC mesh.
///
/// Two delivery paths are used, exactly like the consensus gossip:
///
///  * `pubsub.msg` — a direct PUSH to every peer: the payload lands in the
///    peer's local app subscription for that topic immediately (no mesh hop).
///    This is how a peer hosting the target shard receives the message.
///  * `pubsub.publish` — a mesh RELAY: the peer floods the overlay
///    (TTL-bounded), so a target shard that is not a DIRECT peer of this node
///    still hears the message.
///
/// The same-node bus ([`LocalTopicBus`]) covers the two-shards-in-one-process
/// case the overlay cannot express.
pub struct InfnodeCrossShardPubSub {
    node: Arc<Node>,
    local: Arc<LocalTopicBus>,
}

impl InfnodeCrossShardPubSub {
    pub fn new(node: Arc<Node>) -> Self {
        Self {
            node,
            local: LocalTopicBus::shared(),
        }
    }

    /// Resolve every configured peer to a node id.
    ///
    /// Same rule as the consensus path (`consensus_net::ConsensusNetwork`):
    /// the peer-config node id first, the name only as a fallback — name
    /// resolution depends on a registry that fills in asymmetrically, and a
    /// failed lookup would silently publish to nobody.
    fn peer_ids(&self) -> Vec<[u8; 20]> {
        let mut out = Vec::new();
        for p in &self.node.cfg.peers {
            match p.node_id_raw().or_else(|_| self.node.resolve(&p.name)) {
                Ok(pid) => out.push(pid),
                Err(e) => tracing::warn!("[cross_shard] cannot resolve peer {}: {e}", p.name),
            }
        }
        out
    }
}

impl CrossShardPubSub for InfnodeCrossShardPubSub {
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        data: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let envelope = serde_json::json!({ "topic": topic, "data": data }).to_string();
            // Same-node delivery first: it is the only path that works in a
            // single-process deployment and it costs nothing.
            self.local.publish(topic, &envelope);
            let peers = self.peer_ids();
            if peers.is_empty() {
                // No peer to push to (single-node stand): the message stays
                // local. Not an error.
                return Ok(());
            }
            // A DETERMINISTIC overlay message id: every relay of this payload
            // carries the same id, so the overlay's own dedupe collapses the
            // copies the mesh produces.
            let msg_id = {
                let h = blake3::hash(data.as_bytes());
                u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("8 bytes"))
            };

            // (a) DIRECT PUSH to every peer — the payload lands in the peer's
            //     app subscription for that topic, exactly like the consensus
            //     gossip. This is the path that reaches a peer hosting the
            //     target shard, with no mesh hop.
            let payload = envelope.clone().into_bytes();
            let mut handles = Vec::new();
            for pid in peers.iter().copied() {
                let node = Arc::clone(&self.node);
                let payload = payload.clone();
                handles.push(tokio::spawn(async move {
                    let r = node.request_to(pid, "pubsub.msg", payload).await;
                    (pid, r)
                }));
            }

            // (b) MESH RELAY — one publish is enough: the peer floods the
            //     overlay (TTL-bounded), so a target shard that is not a
            //     DIRECT peer of this node still hears the message. One
            //     flood, not one per peer: the relay reaches the whole mesh
            //     anyway, and a flood per peer would multiply the traffic.
            let relay_peer = peers[0];
            {
                let node = Arc::clone(&self.node);
                let relay = serde_json::json!({
                    "topic": topic,
                    "data": data,
                    "msg_id": msg_id,
                    "ttl": CROSS_SHARD_RELAY_TTL,
                })
                .to_string()
                .into_bytes();
                tokio::spawn(async move {
                    if let Err(e) = node.request_to(relay_peer, "pubsub.publish", relay).await {
                        tracing::debug!(
                            "[cross_shard] mesh relay through {} failed: {e}",
                            hex::encode(relay_peer)
                        );
                    }
                });
            }

            let mut delivered = 0usize;
            for h in handles {
                match h.await {
                    Ok((pid, Ok(resp))) => {
                        if resp.starts_with(b"{\"ok\":false") {
                            tracing::warn!(
                                "[cross_shard] publish to {} denied: {}",
                                hex::encode(pid),
                                String::from_utf8_lossy(&resp)
                            );
                        } else {
                            delivered += 1;
                        }
                    }
                    Ok((pid, Err(e))) => {
                        tracing::warn!("[cross_shard] publish to {} failed: {e}", hex::encode(pid))
                    }
                    Err(_) => tracing::warn!("[cross_shard] publish task failed"),
                }
            }
            if delivered == 0 {
                tracing::warn!("[cross_shard] cross-shard message reached no peer");
            }
            Ok(())
        })
    }

    fn subscribe<'a>(
        &'a self,
        topic: &'a str,
    ) -> CrossShardPubSubFuture<'a, Result<tokio::sync::mpsc::UnboundedReceiver<String>, String>>
    {
        Box::pin(async move {
            // The overlay subscription: the terminal `pubsub.msg` delivery
            // lands in this receiver.
            let mut overlay = self.node.register_app_sub(topic).await;
            // The same-process bus.
            let mut local = self.local.subscribe(topic);
            // Merge both into a single stream.
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        msg = overlay.recv() => match msg {
                            Some(m) => {
                                if tx.send(m).is_err() {
                                    return;
                                }
                            }
                            None => return,
                        },
                        msg = local.recv() => match msg {
                            Some(m) => {
                                if tx.send(m).is_err() {
                                    return;
                                }
                            }
                            None => return,
                        },
                    }
                }
            });
            // Network subscription: every peer relays what it publishes on
            // this topic to us (idempotent, safe to repeat).
            let payload = serde_json::json!({ "topic": topic })
                .to_string()
                .into_bytes();
            for pid in self.peer_ids() {
                let node = Arc::clone(&self.node);
                let payload = payload.clone();
                tokio::spawn(async move {
                    if let Err(e) = node.request_to(pid, "pubsub.subscribe", payload).await {
                        tracing::debug!(
                            "[cross_shard] subscribe to {} failed: {e}",
                            hex::encode(pid)
                        );
                    }
                });
            }
            Ok(rx)
        })
    }
}

/// Decode one gossip payload into a cross-shard message (fail-closed).
///
/// The payload is the JSON envelope every pubsub implementation produces
/// (`{"topic": ..., "data": <hex>}`); `data` is the bincode message. Anything
/// malformed is DROPPED: a gossip channel is attacker-reachable, so a bad
/// payload must never reach the state machine.
///
/// The decoded message is UNTRUSTED by construction (see
/// [`P2pNetworkAdapter::parse_cross_shard_incoming`]): the `trusted` flag
/// bypasses the Merkle inclusion proof and would mint value.
fn decode_cross_shard_payload(payload: &str) -> Option<CrossShardMessage> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    let data = v["data"].as_str()?;
    let bytes = hex::decode(data).ok()?;
    if bytes.is_empty() || bytes.len() > MAX_CROSS_SHARD_MSG {
        return None;
    }
    P2pNetworkAdapter::parse_cross_shard_incoming(&bytes)
}

/// Inbound state of a [`P2pCrossShardTransport`].
#[derive(Default)]
struct CrossShardInbox {
    /// Buffered inbound messages per target shard, drained by
    /// [`P2pCrossShardTransport::fetch_inbound`].
    inbox: std::collections::HashMap<ShardId, std::collections::VecDeque<CrossShardMessage>>,
    /// msg_ids already accepted (gossip duplicates are dropped).
    seen: std::collections::HashSet<[u8; 32]>,
    /// Insertion order of `seen`, so the window can be trimmed.
    seen_order: std::collections::VecDeque<[u8; 32]>,
    /// Shards this transport is subscribed to.
    subscribed: std::collections::HashSet<ShardId>,
    /// Streaming listeners (see [`P2pCrossShardTransport::listen_inbound`]).
    listeners:
        std::collections::HashMap<ShardId, tokio::sync::mpsc::UnboundedSender<CrossShardMessage>>,
}

/// Cross-shard transport over the P2P gossip layer.
///
/// This is the variant that crosses MACHINE boundaries. A shard publishes its
/// outbound messages to the gossip topic of the TARGET shard
/// ([`cross_shard_topic`]) and every node hosting that shard receives them
/// over the overlay — no shared process memory, no node-local RocksDB/Sled.
///
/// The topic is EPOCH-SCOPED, so two chains running side by side never see
/// each other's cross-shard traffic.
///
/// Two inbound APIs, one queue per shard:
///  * [`Self::listen_inbound`] — a streaming receiver (a consumer that wants
///    messages as they arrive).
///  * [`Self::fetch_inbound`] — a poll (the runtime's propose path, which
///    asks for the pending inbox every round).
///
/// They are mutually exclusive per shard: a message goes to the stream when a
/// listener is registered, and to the buffered inbox otherwise. A dropped
/// listener therefore falls back to the buffered path automatically.
pub struct P2pCrossShardTransport {
    /// The pubsub channel (the overlay in production, the in-memory twin in
    /// tests).
    pubsub: Arc<dyn CrossShardPubSub>,
    /// Chain epoch: every topic this transport uses is scoped by it, so two
    /// chains never share a cross-shard mailbox.
    epoch: String,
    /// Inbound state (inbox, dedupe window, subscriptions, listeners).
    inner: Arc<std::sync::Mutex<CrossShardInbox>>,
}

impl P2pCrossShardTransport {
    /// Build a transport over an arbitrary pubsub channel.
    pub fn new(pubsub: Arc<dyn CrossShardPubSub>, epoch: &str) -> Self {
        Self {
            pubsub,
            epoch: epoch.to_string(),
            inner: Arc::new(std::sync::Mutex::new(CrossShardInbox::default())),
        }
    }

    /// Build a transport over the real overlay, scoped to the adapter's epoch.
    pub fn from_adapter(adapter: &Arc<P2pNetworkAdapter>) -> Self {
        let epoch = adapter.epoch().as_str().to_string();
        let pubsub: Arc<dyn CrossShardPubSub> =
            Arc::new(InfnodeCrossShardPubSub::new(adapter.node.clone()));
        Self::new(pubsub, &epoch)
    }

    /// The chain epoch this transport is scoped to.
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The gossip topic this transport uses for `target_shard`.
    pub fn topic_for(&self, target_shard: ShardId) -> String {
        cross_shard_topic(target_shard, &self.epoch)
    }

    /// Publish `msg` to the gossip topic of its TARGET shard.
    ///
    /// Best-effort, like every gossip send: the payload travels to the peers
    /// hosting that shard. The message is also embedded in the producing
    /// block, so a lost gossip copy is recovered by block propagation.
    pub async fn send_outbound(&self, msg: &CrossShardMessage) -> Result<(), String> {
        let bytes = bincode::serialize(msg)
            .map_err(|e| format!("CrossShardMessage serialize error: {:?}", e))?;
        if bytes.len() > MAX_CROSS_SHARD_MSG {
            return Err(format!(
                "cross-shard message too large: {} bytes (cap {MAX_CROSS_SHARD_MSG})",
                bytes.len()
            ));
        }
        let topic = self.topic_for(msg.target_shard);
        let data = hex::encode(bytes);
        self.pubsub.publish(&topic, &data).await
    }

    /// Subscribe to the topic of `shard_id` and return a receiver of the
    /// inbound messages addressed to that shard.
    ///
    /// Idempotent: subscribing twice returns a second receiver on the SAME
    /// subscription (the overlay subscription itself is made once).
    pub async fn listen_inbound(
        &self,
        shard_id: ShardId,
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<CrossShardMessage>, String> {
        self.ensure_subscribed(shard_id).await?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.listeners.insert(shard_id, tx);
        Ok(rx)
    }

    /// Subscribe to the topic of `shard_id` without consuming the stream.
    ///
    /// Gossip has NO replay: a message published before the subscription is
    /// never delivered. A shard that must not miss traffic therefore
    /// subscribes BEFORE the first message is published.
    pub async fn subscribe(&self, shard_id: ShardId) -> Result<(), String> {
        self.ensure_subscribed(shard_id).await
    }

    /// Drain the buffered inbound messages addressed to `shard_id`.
    ///
    /// Subscribes on first use, so the runtime's poll path works without any
    /// extra wiring.
    pub async fn fetch_inbound(&self, shard_id: ShardId) -> Vec<CrossShardMessage> {
        if let Err(e) = self.ensure_subscribed(shard_id).await {
            tracing::warn!("[cross_shard] subscribe to shard {shard_id} failed: {e}");
            return Vec::new();
        }
        // The raw channel and the inbox are two hops: give the pump task a
        // chance to move a just-delivered payload into the inbox.
        tokio::task::yield_now().await;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .inbox
            .remove(&shard_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Drop the consumed messages from the inbox of `shard_id` (§5 M3 pruning).
    ///
    /// Idempotent, like the other transports: pruning an absent id removes
    /// nothing and still succeeds. Returns how many entries were removed.
    pub async fn prune_consumed(&self, shard_id: ShardId, msg_ids: &[[u8; 32]]) -> usize {
        if msg_ids.is_empty() {
            return 0;
        }
        // The raw channel and the inbox are two hops: give the pump task a
        // chance to move a just-delivered payload into the inbox, so a prune
        // racing a delivery still sees the entry.
        tokio::task::yield_now().await;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(queue) = inner.inbox.get_mut(&shard_id) else {
            return 0;
        };
        let before = queue.len();
        queue.retain(|m| !msg_ids.contains(&m.msg_id));
        before - queue.len()
    }

    /// Make sure the transport is subscribed to the topic of `shard_id`.
    ///
    /// The subscription is claimed BEFORE the await, so two concurrent callers
    /// cannot open two overlay subscriptions for the same shard.
    async fn ensure_subscribed(&self, shard_id: ShardId) -> Result<(), String> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.subscribed.contains(&shard_id) {
                return Ok(());
            }
            inner.subscribed.insert(shard_id);
        }
        let topic = self.topic_for(shard_id);
        let raw = match self.pubsub.subscribe(&topic).await {
            Ok(rx) => rx,
            Err(e) => {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.subscribed.remove(&shard_id);
                return Err(e);
            }
        };
        let mut raw = raw;
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            while let Some(payload) = raw.recv().await {
                if let Some(msg) = decode_cross_shard_payload(&payload) {
                    accept_inbound(&inner, shard_id, msg);
                }
            }
            // The channel closed: the subscription is dead, so a later call
            // may open a new one.
            let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
            g.subscribed.remove(&shard_id);
        });
        Ok(())
    }
}

/// Accept one inbound gossip message (dedupe, address check, delivery).
///
/// SECURITY: the message is forced UNTRUSTED — the `trusted` flag bypasses
/// the Merkle inclusion proof, and a gossip channel is attacker-reachable.
fn accept_inbound(
    inner: &Arc<std::sync::Mutex<CrossShardInbox>>,
    shard_id: ShardId,
    mut msg: CrossShardMessage,
) {
    msg.trusted = false;
    let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
    // Gossip duplicates are normal (the mesh relays, a peer may re-publish on
    // reconnect): the first copy wins, the rest are dropped.
    if !g.seen.insert(msg.msg_id) {
        return;
    }
    g.seen_order.push_back(msg.msg_id);
    while g.seen_order.len() > CROSS_SHARD_DEDUPE_WINDOW {
        if let Some(old) = g.seen_order.pop_front() {
            g.seen.remove(&old);
        }
    }
    // Address check: a shard must only ever consume the messages addressed to
    // it.
    if !msg.is_inbound_for(shard_id) {
        return;
    }
    match g.listeners.get(&shard_id) {
        Some(tx) => match tx.send(msg) {
            Ok(()) => {}
            Err(err) => {
                // The listener is gone: fall back to the buffered inbox.
                g.listeners.remove(&shard_id);
                g.inbox.entry(shard_id).or_default().push_back(err.0);
            }
        },
        None => {
            g.inbox.entry(shard_id).or_default().push_back(msg);
        }
    }
}

/// Where a shard publishes outbound cross-shard messages and reads inbound ones.
///
/// Three variants, one contract:
///  * `Local` — the in-process mailbox (simulator and tests).
///  * `Node`  — the node-local infnode KV of a live node.
///  * `P2p`   — the P2P GOSSIP layer: the only variant that can move a
///    message between shards running on DIFFERENT physical servers.
///
/// The first two are node-local by construction: two shards can exchange
/// messages only if they run in ONE process behind ONE node. `P2p` is what
/// removes that restriction (see [`P2pCrossShardTransport`]).
pub enum CrossShardTransport {
    Local(Arc<LocalCrossShardKv>),
    Node(Arc<P2pNetworkAdapter>),
    P2p(Arc<P2pCrossShardTransport>),
}

impl CrossShardTransport {
    /// A fresh in-process mailbox, wrapped so several shard runtimes share it.
    pub fn local() -> Arc<Self> {
        Arc::new(Self::Local(Arc::new(LocalCrossShardKv::new())))
    }

    /// Wrap the production infnode adapter as the shared cross-shard transport.
    pub fn from_node(adapter: Arc<P2pNetworkAdapter>) -> Arc<Self> {
        Arc::new(Self::Node(adapter))
    }

    /// Wrap a P2P gossip transport as the shared cross-shard transport.
    ///
    /// Unlike the other two variants this one crosses machine boundaries: a
    /// shard publishes to the gossip topic of its target shard and the node
    /// hosting that shard receives the message over the overlay.
    pub fn p2p(transport: Arc<P2pCrossShardTransport>) -> Arc<Self> {
        Arc::new(Self::P2p(transport))
    }

    pub async fn broadcast_cross_shard(&self, msg: &CrossShardMessage) -> Result<(), String> {
        match self {
            Self::Local(kv) => kv.broadcast_cross_shard(msg).await,
            Self::Node(node) => node.broadcast_cross_shard(msg).await,
            Self::P2p(p2p) => p2p.send_outbound(msg).await,
        }
    }

    pub async fn fetch_cross_shard_inbound(&self, target_shard: u32) -> Vec<CrossShardMessage> {
        match self {
            Self::Local(kv) => kv.fetch_cross_shard_inbound(target_shard).await,
            Self::Node(node) => node.fetch_cross_shard_inbound(target_shard).await,
            Self::P2p(p2p) => p2p.fetch_inbound(target_shard).await,
        }
    }

    /// Drop consumed entries for `target_shard` by `msg_id` (§5 M3 pruning).
    ///
    /// Same contract on both variants: remove the per-message entries the
    /// shard already committed plus their index slots, idempotently. The
    /// `Node` variant rewrites the node-local index without a lock (single
    /// writer per shard: the shard's own apply path), so a concurrent stale
    /// read can only re-add an already-pruned id on the NEXT broadcast, which
    /// the consumed-set filter then skips at proposal time.
    pub async fn prune_consumed(&self, target_shard: u32, msg_ids: &[[u8; 32]]) -> usize {
        match self {
            Self::Local(kv) => kv.prune(target_shard, msg_ids).await,
            Self::Node(node) => node.prune_cross_shard_consumed(target_shard, msg_ids).await,
            Self::P2p(p2p) => p2p.prune_consumed(target_shard, msg_ids).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn prune_fetch_lane_is_bounded_and_released() {
        // Transport-audit regression: `maybe_prune_retained` resolves its
        // header-index lookup through `fetch_sem` — the same lane as every
        // other fetch — so prune traffic can never exceed
        // `FETCH_MAX_CONCURRENCY` concurrent streams.
        let max = crate::sync::FETCH_MAX_CONCURRENCY.max(1);
        let held = fetch_sem()
            .acquire()
            .await
            .expect("fetch lane must grant permits");
        let during = fetch_sem().available_permits();
        assert!(
            during < max,
            "one held permit must reduce availability below the cap {max}"
        );
        drop(held);
        let after = fetch_sem().available_permits();
        assert!(
            after <= max,
            "permits must never exceed the cap {max}, got {after}"
        );
        assert!(
            after > during,
            "dropping the permit must return it to the lane"
        );
    }

    #[test]
    fn network_cross_shard_message_is_never_trusted() {
        // A locally trusted message, once serialized and decoded from the wire,
        // must come back UNtrusted so the inclusion proof is enforced.
        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [9u8; 32], 10, 0, 0, 1, 2);
        let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
        assert!(msg.trusted);
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded = P2pNetworkAdapter::parse_cross_shard_incoming(&bytes).unwrap();
        assert!(!decoded.trusted, "wire message must never be trusted");
        // malformed input is rejected (fail-closed)
        assert!(P2pNetworkAdapter::parse_cross_shard_incoming(&[0xff, 0x00]).is_none());
    }

    #[test]
    fn replication_bounds_are_sane_and_pinned() {
        // Guards the "no backfill storm" invariant: bounded concurrency, bounded
        // retries, bounded pass size, and reuse of the existing retro/KEEP
        // windows (4096 / 8000) so retention and replication cannot disagree.
        assert_eq!(crate::sync::ADOPT_REPL_MAX_CONCURRENCY, 8);
        assert_eq!(crate::sync::ADOPT_REPL_MAX_RETRIES, 3);
        assert_eq!(crate::sync::ADOPT_REPL_BACKFILL_MAX_PER_PASS, 64);
        assert_eq!(crate::sync::ADOPT_REPL_RETRO_DEPTH, 4096);
        assert_eq!(crate::sync::ADOPT_REPL_KEEP_WINDOW, 8000);
        assert_eq!(
            crate::sync::ADOPT_REPL_KEEP_WINDOW,
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
    }

    #[test]
    fn verified_fetch_names_the_same_slot_it_publishes() {
        // The fetch boundary (`fetch_verified_body`) must look up the exact blob
        // name the publish paths write, or replication fetches a slot nobody
        // fills. Pinned here, not trusted to a comment.
        let epoch = EpochTag::default();
        let hash = [0x42u8; 32];
        assert_eq!(
            block_body_blob_name(&epoch, &hash),
            format!("{}_blk_{}", epoch.as_str(), hex::encode(hash))
        );
    }

    #[tokio::test]
    async fn p2p_cross_shard_message_is_broadcast_and_received() {
        // The cross-shard gossip path: shard 1 publishes to the topic of
        // shard 2 and the transport hosting shard 2 receives the message over
        // the pubsub channel. The received copy must be UNTRUSTED: the
        // inclusion proof is enforced on everything that arrives over the
        // wire, whatever the publisher claimed.
        let bus = InMemoryCrossShardPubSub::shared();
        let sender = P2pCrossShardTransport::new(bus.clone(), "epoch-a");
        let receiver = P2pCrossShardTransport::new(bus.clone(), "epoch-a");

        let mut inbound = receiver
            .listen_inbound(2)
            .await
            .expect("subscribe to the cross-shard topic");

        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [9u8; 32], 10, 0, 0, 1, 2);
        let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
        assert!(msg.trusted, "the locally produced message is trusted");

        sender.send_outbound(&msg).await.expect("publish");

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), inbound.recv())
            .await
            .expect("inbound message within the timeout")
            .expect("inbound channel open");
        assert_eq!(got.msg_id, msg.msg_id);
        assert_eq!(got.source_shard, 1);
        assert_eq!(got.target_shard, 2);
        assert!(
            !got.trusted,
            "a gossiped message must never be trusted (inclusion proof enforced)"
        );
    }

    #[tokio::test]
    async fn p2p_cross_shard_topic_is_epoch_scoped() {
        // The topic name is part of the routing contract: epoch first (two
        // chains must not share a mailbox), target shard second (each shard
        // has its own mailbox).
        assert_eq!(cross_shard_topic(2, "abc"), "stell/cross_shard/abc/2");
        assert_ne!(
            cross_shard_topic(2, "abc"),
            cross_shard_topic(2, "def"),
            "two chains must not share a cross-shard mailbox"
        );
        assert_ne!(
            cross_shard_topic(1, "abc"),
            cross_shard_topic(2, "abc"),
            "each shard must have its own mailbox"
        );

        // And the isolation is real, not only in the name: a transport of
        // another epoch must never hear the message.
        let bus = InMemoryCrossShardPubSub::shared();
        let sender = P2pCrossShardTransport::new(bus.clone(), "epoch-a");
        let other_chain = P2pCrossShardTransport::new(bus.clone(), "epoch-b");
        let mut inbound = other_chain
            .listen_inbound(2)
            .await
            .expect("subscribe to the cross-shard topic");

        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [4u8; 32], 10, 0, 0, 1, 2);
        let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
        sender.send_outbound(&msg).await.expect("publish");

        let leaked =
            tokio::time::timeout(std::time::Duration::from_millis(250), inbound.recv()).await;
        assert!(
            leaked.is_err(),
            "a different chain epoch must never receive the message"
        );
    }

    #[tokio::test]
    async fn p2p_cross_shard_transport_variant_polls_and_prunes() {
        // The poll path the runtime uses: `fetch_cross_shard_inbound` drains
        // the inbox, `prune_consumed` drops the entries the shard already
        // committed (idempotently).
        let bus = InMemoryCrossShardPubSub::shared();
        let sender = CrossShardTransport::p2p(Arc::new(P2pCrossShardTransport::new(
            bus.clone(),
            "epoch-a",
        )));
        let receiver = CrossShardTransport::p2p(Arc::new(P2pCrossShardTransport::new(
            bus.clone(),
            "epoch-a",
        )));

        // Subscribe BEFORE the publish: gossip has no replay.
        assert!(receiver.fetch_cross_shard_inbound(2).await.is_empty());

        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [5u8; 32], 10, 0, 0, 1, 2);
        let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
        sender.broadcast_cross_shard(&msg).await.expect("publish");

        let inbound = receiver.fetch_cross_shard_inbound(2).await;
        assert_eq!(inbound.len(), 1, "the published message must be received");
        assert_eq!(inbound[0].msg_id, msg.msg_id);
        assert!(!inbound[0].trusted);

        // A second copy of the same message is dropped (gossip dedupe).
        sender.broadcast_cross_shard(&msg).await.expect("republish");
        assert!(receiver.fetch_cross_shard_inbound(2).await.is_empty());

        // Pruning a consumed entry removes it exactly once.
        let tx2 = Transaction::sign(&sk, [6u8; 32], 10, 0, 1, 1, 2);
        let msg2 = CrossShardMessage::new_trusted(1, 2, tx2, [0u8; 32], [4u8; 32]);
        sender.broadcast_cross_shard(&msg2).await.expect("publish");
        assert_eq!(receiver.prune_consumed(2, &[msg2.msg_id]).await, 1);
        assert_eq!(receiver.prune_consumed(2, &[msg2.msg_id]).await, 0);
        assert!(receiver.fetch_cross_shard_inbound(2).await.is_empty());
    }
}

/// The header group (header + height index + QC sidecar) must ride ONE
/// rate-limit lane.
///
/// Regression (audit P2P C): the header was published as `Pointer` while its
/// QC sidecar rode the Bulk lane. A bulk-lane cooldown therefore shed the QC
/// while the header still landed, and every catch-up node reads "header
/// present, QC missing" as "not anchorable" — the header is rejected as
/// unanchored even though it was published correctly.
#[cfg(test)]
mod header_lane_tests {
    use super::*;

    #[test]
    fn qc_sidecar_rides_the_header_lane_not_the_bulk_lane() {
        let slots = header_publish_slots();
        assert_eq!(slots.len(), 3, "header, height index and QC sidecar");

        // Every blob of the group rides the SAME lane: the per-lane circuit
        // breaker then treats them as one unit and can never shed the QC
        // while the header lands.
        let lanes: Vec<String> = slots
            .iter()
            .map(|s| repl_lane_key(BUCKET_STELLEREUM_HEADERS, s.lane))
            .collect();
        assert!(
            lanes.windows(2).all(|w| w[0] == w[1]),
            "the header group must ride ONE lane, got {lanes:?}"
        );
        // And that lane is the Pointer lane, NOT the Bulk lane the sidecars
        // used to ride.
        assert_eq!(
            lanes[0],
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Pointer)
        );
        assert_ne!(
            lanes[0],
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Bulk),
            "the header lane must not be the bulk lane"
        );

        // The sidecars still ride along without charging the pacing gate, so
        // one header never pays 3x the publish floor.
        assert_eq!(slots[0].charge, ReplStoreKind::Pointer);
        assert_eq!(slots[1].charge, ReplStoreKind::Companion);
        assert_eq!(slots[2].charge, ReplStoreKind::Companion);
    }

    #[test]
    fn companion_kind_still_rides_a_pointer_lane_when_asked() {
        // `paced_store_blob_in_lane` decouples "does this publish charge the
        // pacing gate" (kind) from "which lane does it ride" (lane_kind): a
        // Companion in a Pointer lane is exactly the header-group sidecar.
        assert!(!matches!(
            ReplStoreKind::Companion,
            ReplStoreKind::Bulk | ReplStoreKind::Pointer
        ));
        // The default (charge-derived) companion lane is the split lane the
        // fix moved away from.
        assert_ne!(
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Companion),
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Pointer),
            "the default (charge-derived) companion lane is the split lane"
        );
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    #[test]
    fn epoch_from_genesis_is_deterministic_and_short() {
        let root = [0xABu8; 32];
        let a = EpochTag::from_genesis(&root);
        let b = EpochTag::from_genesis(&root);
        assert_eq!(a, b, "the same chain must always name the same epoch");
        assert_eq!(a.as_str().len(), 16, "short and blob-name-safe");
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_different_genesis_is_a_different_epoch() {
        let a = EpochTag::from_genesis(&[0x01u8; 32]);
        let b = EpochTag::from_genesis(&[0x02u8; 32]);
        assert_ne!(a, b, "two chains must not share a namespace");
    }

    #[test]
    fn every_published_name_is_scoped_to_the_epoch() {
        let e1 = EpochTag::from_genesis(&[0x11u8; 32]);
        let e2 = EpochTag::from_genesis(&[0x22u8; 32]);

        // The property that fixes the wipe problem: no name can collide across chains,
        // so a fresh node cannot read a previous run's head, header or snapshot.
        assert_ne!(head_name(&e1, 1), head_name(&e2, 1));
        assert_ne!(header_name(&e1, 7), header_name(&e2, 7));
        assert_ne!(header_index_name(&e1, 1, 7), header_index_name(&e2, 1, 7));
        assert_ne!(block_name(&e1, "deadbeef"), block_name(&e2, "deadbeef"));
        assert_ne!(snapshot_name(&e1, 1, 100), snapshot_name(&e2, 1, 100));

        // And the same chain always agrees on them.
        assert_eq!(
            head_name(&e1, 1),
            head_name(&EpochTag::from_genesis(&[0x11u8; 32]), 1)
        );
    }

    #[test]
    fn the_default_epoch_is_well_formed() {
        // Before genesis exists the tag is a fixed placeholder, not an empty string,
        // so early publishes produce valid names instead of colliding on "".
        let d = EpochTag::default();
        assert!(!d.as_str().is_empty());
        assert!(!head_name(&d, 1).starts_with('_'));
    }
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
// entries, whose ed-pub is pinned and TLS-verified); the network may only
// supply fresh ENDPOINTS for those already-pinned identities. Discovery can
// therefore never introduce a new key into any path the node trusts.

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

/// Normalize an Ed25519 transport identity (hex ed-pub) for comparison.
///
/// Hex case is not canonical across producers (config files vs DHT gossip),
/// so comparison is case-insensitive. Empty/whitespace input normalizes to an
/// empty string, which `pinned_identity_set` never contains — a discovered
/// record with no key is therefore always dropped, never admitted.
pub fn canonical_ed_pub(ed_hex: &str) -> String {
    ed_hex.trim().to_ascii_lowercase()
}

/// Build the set of pinned transport identities from the local static config.
///
/// This is the ONLY source of trusted identity: every entry's ed-pub is pinned
/// into the TLS verifier at startup, so a peer presenting a different key for
/// one of these endpoints fails the handshake.
pub fn pinned_identity_set(
    peers: &[infnode::config::PeerConfig],
) -> std::collections::HashSet<String> {
    peers
        .iter()
        .map(|p| canonical_ed_pub(&p.ed_pub))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Filter DHT-discovered peers down to already-pinned identities.
///
/// Returns the subset of `discovered` whose ed-pub is in `pinned_ed_pub`,
/// preserving each record (including any NEW endpoints the network reported
/// for that identity). Everything else — unknown keys, empty/malformed keys —
/// is dropped. Pure function over data so it is unit-testable without a live
/// DHT; `discover_peers_filtered` is the thin live wrapper over it.
pub fn filter_discovered_to_pinned(
    discovered: Vec<infnode::dht::NodeInfo>,
    pinned_ed_pub: &std::collections::HashSet<String>,
) -> Vec<infnode::dht::NodeInfo> {
    discovered
        .into_iter()
        .filter(|n| pinned_ed_pub.contains(&canonical_ed_pub(&n.ed_hex)))
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
    /// definition and always included; discovered records for unknown ed-pubs
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
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn keep_blocks_parses_env_and_defaults() {
        assert_eq!(parse_keep_blocks(None), STELL_DHT_KEEP_BLOCKS_DEFAULT);
        assert_eq!(parse_keep_blocks(Some("8000".into())), 8000);
        assert_eq!(parse_keep_blocks(Some("50000".into())), 50_000);
        // Garbage and non-positive values fall back instead of disabling prune.
        assert_eq!(
            parse_keep_blocks(Some("".into())),
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
        assert_eq!(
            parse_keep_blocks(Some("nope".into())),
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
        assert_eq!(
            parse_keep_blocks(Some("0".into())),
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
    }

    #[test]
    fn blob_ttl_is_a_generous_backstop_not_a_tight_bound() {
        const DAY: i64 = 24 * 3600 * 1000;
        // At the live KEEP=8000 the TTL is ~11 days: the height prune (which
        // deletes below finalized−8000 within minutes on a live chain) always
        // wins, and this only collects replicas/strays in the sweep.
        assert_eq!(dht_blob_ttl_ms(8000), 8000 * 120_000);
        assert!(dht_blob_ttl_ms(8000) > 7 * DAY);
        // Clamped on both ends: a tiny KEEP cannot expire the sync window, a
        // huge KEEP cannot disable expiry.
        assert_eq!(dht_blob_ttl_ms(1), 7 * DAY);
        assert_eq!(dht_blob_ttl_ms(100), 7 * DAY);
        assert_eq!(dht_blob_ttl_ms(1_000_000), 30 * DAY);
        assert_eq!(
            dht_blob_ttl_ms(u64::MAX),
            30 * DAY,
            "no overflow on absurd KEEP"
        );
    }

    #[test]
    fn prune_cursor_key_is_epoch_and_shard_scoped() {
        // A wiped chain (new epoch) must never resume a foreign cursor, and
        // shards must not share one. Pinned: restart-resume relies on it.
        let a = EpochTag::from_genesis(&[0x01u8; 32]);
        let b = EpochTag::from_genesis(&[0x02u8; 32]);
        assert_ne!(prune_cursor_key(&a, 0), prune_cursor_key(&b, 0));
        assert_ne!(prune_cursor_key(&a, 0), prune_cursor_key(&a, 1));
        assert!(prune_cursor_key(&a, 0).starts_with("stell_prune/cursor/"));
    }

    #[test]
    fn prune_cursor_value_round_trips_and_rejects_garbage() {
        assert_eq!(parse_prune_cursor("171234"), Some(171234));
        assert_eq!(parse_prune_cursor("  42\n"), Some(42));
        assert_eq!(parse_prune_cursor(""), None);
        assert_eq!(parse_prune_cursor("abc"), None);
        assert_eq!(parse_prune_cursor("-1"), None);
    }

    #[test]
    fn prune_pass_is_sized_to_drain_a_big_backlog() {
        // Live lesson 2026-10-06: 512/pass drains a 170k backlog in ~5 days
        // while the disk sits at 95%. 2048/pass brings it under a day.
        assert_eq!(STELL_DHT_PRUNE_MAX_PER_RUN, 2048);
    }

    #[test]
    fn prune_bound_keeps_exactly_keep_heights() {
        assert_eq!(prune_below_exclusive(9000, 8000), 1000);
        // Heights below the bound are exactly the prunable ones; the KEEP
        // window itself (bound..=tip) is untouched.
        assert_eq!(
            prune_below_exclusive(8000, 8000),
            0,
            "nothing to prune at exactly KEEP"
        );
        assert_eq!(
            prune_below_exclusive(100, 8000),
            0,
            "young chain prunes nothing"
        );
        assert_eq!(prune_below_exclusive(0, 8000), 0);
    }

    #[test]
    fn prune_batch_is_capped_monotonic_and_skips_genesis() {
        // Fresh cursor, bound beyond the cap: one capped batch, cursor advances.
        let (b, next) = prune_batch(0, 10_000, 512);
        assert_eq!(b.len(), 512);
        assert_eq!(b[0], 1, "height 0 (genesis) is never pruned");
        assert_eq!(*b.last().unwrap(), 512);
        assert_eq!(next, 512);
        // Continuation resumes where the last batch stopped...
        let (b2, next2) = prune_batch(next, 10_000, 512);
        assert_eq!(b2[0], 513);
        assert_eq!(next2, 1024);
        // ...and the tail batch stops exactly at the bound.
        let (b3, next3) = prune_batch(9_900, 10_000, 512);
        assert_eq!(
            b3,
            vec![
                9901, 9902, 9903, 9904, 9905, 9906, 9907, 9908, 9909, 9910, 9911, 9912, 9913, 9914,
                9915, 9916, 9917, 9918, 9919, 9920, 9921, 9922, 9923, 9924, 9925, 9926, 9927, 9928,
                9929, 9930, 9931, 9932, 9933, 9934, 9935, 9936, 9937, 9938, 9939, 9940, 9941, 9942,
                9943, 9944, 9945, 9946, 9947, 9948, 9949, 9950, 9951, 9952, 9953, 9954, 9955, 9956,
                9957, 9958, 9959, 9960, 9961, 9962, 9963, 9964, 9965, 9966, 9967, 9968, 9969, 9970,
                9971, 9972, 9973, 9974, 9975, 9976, 9977, 9978, 9979, 9980, 9981, 9982, 9983, 9984,
                9985, 9986, 9987, 9988, 9989, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998,
                9999, 10000
            ]
        );
        assert_eq!(next3, 10_000);
        // Caught-up cursor prunes nothing.
        let (b4, next4) = prune_batch(10_000, 10_000, 512);
        assert!(b4.is_empty());
        assert_eq!(next4, 10_000);
    }

    #[test]
    fn header_index_roundtrips_and_rejects_garbage() {
        let good_hash = "ab".repeat(32);
        let good = format!("42000:{good_hash}");
        assert_eq!(
            parse_header_index(good.as_bytes()),
            Some((42000, good_hash.clone()))
        );
        assert_eq!(parse_header_index(b"not-an-index"), None);
        assert_eq!(parse_header_index(b"abc:deadbeef"), None);
        assert_eq!(parse_header_index(b""), None);
    }

    /// PENTEST F4 (P0): a hostile index blob must not smuggle names/keys.
    /// Before the fix every one of these parsed `Some` and its hash half
    /// flowed into blob names and kv keys on the prune/fetch path.
    #[test]
    fn pentest_header_index_rejects_hostile_hashes() {
        // Path traversal: would escape the blob namespace on the prune path.
        assert_eq!(parse_header_index(b"5:../../evil"), None);
        assert_eq!(parse_header_index(b"5:..\\..\\evil"), None);
        assert_eq!(parse_header_index(b"5:/etc/passwd"), None);
        // Wrong shape: short, empty, too long, non-hex, embedded whitespace.
        assert_eq!(parse_header_index(b"5:deadbeef"), None);
        assert_eq!(parse_header_index(b"5:"), None);
        let long = format!("5:{}", "ab".repeat(64));
        assert_eq!(parse_header_index(long.as_bytes()), None);
        let nonhex = format!("5:{}", "zz".repeat(32));
        assert_eq!(parse_header_index(nonhex.as_bytes()), None);
        let spaced = format!("5:{}", "ab ".repeat(32));
        assert_eq!(parse_header_index(spaced.as_bytes()), None);
        // Uppercase hex is still hex: honest publishers interoperate.
        let upper = format!("5:{}", "AB".repeat(32));
        assert!(parse_header_index(upper.as_bytes()).is_some());
    }

    /// VERIFICATION F4-hardening: case, prefixes, trailing bytes and extra
    /// segments — which of these pass, and is that correct?
    ///
    /// * mixed-case 64-hex PASSES (correct: `hex::decode` accepts it, and our
    ///   own publishers emit lowercase — interop, not confusion);
    /// * `0x`-prefixed FAILS (correct: 66 chars, not 64 — no silent prefix
    ///   stripping that could alias two names);
    /// * 64-hex plus a trailing newline FAILS (correct: overlong);
    /// * a second `:segment` after the hash FAILS (correct: this exact shape
    ///   used to be ACCEPTED by `fetch_head_hash`'s ad-hoc split, which took
    ///   the first two segments — the inconsistency the F4 fix closes);
    /// * no blob name can be smuggled through the height field: heights are
    ///   `u64` and format as decimal (`header_index_name`/`header_name` only
    ///   ever interpolate the parsed integer, never the raw string).
    #[test]
    fn verification_header_index_case_prefix_and_segments() {
        let good = "ab".repeat(32);
        // Mixed case passes (canonical hex alphabet, both cases).
        let mixed = format!("5:{}", "aB".repeat(32));
        assert_eq!(
            parse_header_index(mixed.as_bytes()),
            Some((5, "aB".repeat(32))),
            "mixed-case 64-hex must parse (hex::decode accepts it)"
        );
        // `0x` prefix: 66 chars -> rejected, never stripped.
        let prefixed = format!("5:0x{good}");
        assert_eq!(parse_header_index(prefixed.as_bytes()), None);
        // Trailing newline: overlong -> rejected.
        let newline = format!("5:{good}\n");
        assert_eq!(parse_header_index(newline.as_bytes()), None);
        // Trailing segment: the shape fetch_head_hash used to accept.
        let extra = format!("5:{good}:evil");
        assert_eq!(
            parse_header_index(extra.as_bytes()),
            None,
            "an extra segment after the hash must be refused"
        );
        // Height field: only a decimal u64 parses; blob-name smuggling
        // (`..`, `/`, hex-looking path bytes) cannot survive the parse, and
        // the name builders below only interpolate the parsed integer.
        assert_eq!(parse_header_index(format!("..:{good}").as_bytes()), None);
        assert_eq!(parse_header_index(format!("-1:{good}").as_bytes()), None);
        assert_eq!(parse_header_index(format!("0x5:{good}").as_bytes()), None);
        let epoch = EpochTag::from_genesis(&[0x11u8; 32]);
        let name = super::header_index_name(&epoch, 0, 5);
        assert!(!name.contains("..") && !name.contains('/'));
        assert!(name.ends_with("_5"));
        // Exact good input still parses (no false positive).
        assert_eq!(
            parse_header_index(format!("5:{good}").as_bytes()),
            Some((5, good))
        );
    }

    /// VERIFICATION G5: a forged oracle feed planted in local KV (via
    /// `dht.sync` replication from an untrusted peer) must never be served
    /// as market evidence. Only a correctly signed feed decodes.
    #[test]
    fn verification_oracle_fetch_reverifies_signature() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let feed = PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &sk);
        let stored = hex::encode(bincode::serialize(&feed).unwrap());
        // Genuine feed: served.
        let back = decode_verified_price_feed(&stored).expect("signed feed must decode");
        assert_eq!(back.price_micro_usd, 250_000);
        // Tampered price bytes: signature no longer matches -> miss.
        let mut tampered = feed.clone();
        tampered.price_micro_usd = 1;
        let bad_price = hex::encode(bincode::serialize(&tampered).unwrap());
        assert!(
            decode_verified_price_feed(&bad_price).is_none(),
            "a re-priced feed with the old signature must read as a miss"
        );
        // Forged publisher key (attacker signs with their own key but claims
        // the asset): structurally valid, cryptographically foreign.
        // `verify` only checks the signature against the ATTACHED key, so a
        // self-consistent forgery verifies here — publisher-set membership is
        // enforced one layer up (`OracleState::apply_update`). The fetch gate
        // guarantees integrity (bytes == publisher's words), not membership.
        let attacker = SigningKey::generate(&mut OsRng);
        let forged = PriceFeedUpdate::sign("STELL", 1, 1_700_000_000, &attacker);
        let forged_hex = hex::encode(bincode::serialize(&forged).unwrap());
        assert!(
            decode_verified_price_feed(&forged_hex).is_some(),
            "a self-consistent signature passes the integrity gate (membership is checked by OracleState)"
        );
        // Garbage: miss, never a panic or a fabricated feed.
        assert!(decode_verified_price_feed("zzzz").is_none());
        assert!(decode_verified_price_feed("").is_none());
    }

    #[test]
    fn prune_plan_covers_body_header_index_and_kv_but_never_head_or_snapshot() {
        let epoch = EpochTag::from_genesis(&[0x11u8; 32]);
        let hash_hex = "ab".repeat(32);
        let plan = plan_retained_prune(&epoch, 0, 1000, Some(&hash_hex));
        // Three header blobs (header + height→hash index + A1 QC sidecar,
        // same retention window) plus the hash-addressed
        // body resolved through that index...
        assert_eq!(plan.blobs.len(), 4);
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_HEADERS && n.contains("_h_1000")));
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_HEADERS && n.contains("_hi_0_1000")));
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_HEADERS && n.contains("_hq_0_1000")));
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_BLOCKS && n.contains(&hash_hex)));
        // ...and the per-hash kv index `broadcast_block` wrote alongside it.
        assert_eq!(plan.kv, vec![format!("{}{}", PREFIX_BLOCK_HASH, hash_hex)]);
        // The head pointer and snapshots are never planned: they stay forever.
        for (_, name) in &plan.blobs {
            assert!(!name.contains("_head"), "head pointer must never be pruned");
            assert!(!name.contains("_snap_"), "snapshots must never be pruned");
        }
        for k in &plan.kv {
            assert!(!k.starts_with(PREFIX_LATEST_HEIGHT), "height pointer stays");
        }
        // Without the index the body is unaddressable: headers are still
        // planned, the body falls back to the TTL backstop.
        let plan2 = plan_retained_prune(&epoch, 0, 1000, None);
        assert_eq!(plan2.blobs.len(), 3);
        assert!(plan2.kv.is_empty());
        // Epoch-scoped: a wipes-and-restart chain never prunes the old chain.
        let other = EpochTag::from_genesis(&[0x22u8; 32]);
        let plan3 = plan_retained_prune(&other, 0, 1000, Some(&hash_hex));
        assert_ne!(plan.blobs, plan3.blobs);
    }

    #[test]
    fn sync_paths_do_not_change_with_retention() {
        // The retention change is strictly additive on the publish side: the
        // fetch surface sync depends on is untouched. Pin the plan shape the
        // retro path relies on (body-only, no kv) so a future edit cannot
        // silently couple retention to sync correctness.
        let epoch = EpochTag::default();
        let sk = {
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng;
            SigningKey::generate(&mut OsRng)
        };
        let block = crate::sharding::Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 7,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 0,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        let writes = plan_block_body_publish(&epoch, &block).expect("plan");
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].bucket, BUCKET_STELLEREUM_BLOCKS);
        assert!(writes[0].kv.is_empty(), "retro publish still writes no kv");
        assert_eq!(
            writes[0].name,
            block_body_blob_name(&epoch, &block.compute_hash())
        );
    }
}

#[cfg(test)]
mod pointer_overwrite_tests {
    //! Orphan-chunk regression for fixed-name pointer overwrites.
    //!
    //! Chunk ids are content-addressed, so every head/snapshot-pointer rewrite
    //! retires its whole chunk set, while the kv sweep only collects EXPIRED
    //! manifests — never an overwritten one. A bare `store_blob_with_ttl` on
    //! the head key therefore leaks one chunk file per finalize (~130k/day).
    //! `store_pointer_overwrite` (delete-first) must keep the chunk count flat.
    //! These tests run against a REAL `Node` (like infnode's own
    //! `disk_growth_tests`): the leak is chunk FILES, invisible to any fake.
    use super::*;
    use std::sync::Arc;

    static TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    async fn test_adapter(tag: &str) -> (P2pNetworkAdapter, std::path::PathBuf) {
        let n = TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "stell-pointer-orphan-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let cfg = infnode::config::NodeConfig {
            name: "test".to_string(),
            listen: "127.0.0.1:0".to_string(),
            client_listen: None,
            advertise: None,
            peers: vec![],
            allow_unknown: false,
            unknown_allow: vec![],
            metrics_listen: None,
            log_level: Some(0),
            roles: Default::default(),
            outbox_ttl_secs: 3600,
            storage_roles: vec![],
            validators: vec![],
            domain: None,
            web_listen: None,
            wallet: None,
            web_static: None,
        };
        let node = infnode::node::Node::new(
            cfg,
            infnode::keyring::NodeKeys::generate(),
            dir.clone(),
            std::path::PathBuf::new(),
        )
        .await
        .expect("test node");
        let adapter = P2pNetworkAdapter::new(node);
        adapter.set_epoch(EpochTag::from_genesis(&[0x77u8; 32]));
        (adapter, dir)
    }

    /// Live (non-hidden) chunk files under `<data_dir>/chunks`, all buckets.
    /// Hidden `.*.tmp.*` files are atomic-write leftovers, counted separately.
    fn chunk_files(
        data_dir: &std::path::Path,
    ) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
        let mut live = Vec::new();
        let mut hidden = Vec::new();
        let mut stack = vec![data_dir.join("chunks")];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if e.file_name().to_string_lossy().starts_with('.') {
                    hidden.push(p);
                } else {
                    live.push(p);
                }
            }
        }
        (live, hidden)
    }

    /// Live cadence between pointer overwrites in the regression tests.
    ///
    /// WHY PACED: every `store_blob_with_ttl` spawns a background
    /// `replicate_blob` task, which — with no peers to take the replica —
    /// falls back to a LOCAL chunk write (`store_chunk_replicated`). At
    /// production cadence (a finalize/probe per seconds) that task is long
    /// done before the next overwrite's delete, so delete-first is exact.
    /// Hammered back-to-back, the previous task can land AFTER the next
    /// delete and resurrect its version's file — an artifact of the
    /// no-peer fallback, not of the overwrite logic. Pacing each publish
    /// past the task's sub-ms work keeps the test on the production
    /// regime it is supposed to pin.
    const POINTER_REPUBLISH_PACE_MS: u64 = 5;

    #[tokio::test]
    async fn head_pointer_1000_overwrites_do_not_grow_chunks() {
        let (adapter, dir) = test_adapter("head").await;
        let adapter = Arc::new(adapter);
        let (base_live, _) = chunk_files(&dir);
        assert!(base_live.is_empty(), "fresh node holds no chunks");

        for h in 1..=1000u64 {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&h.to_le_bytes());
            assert!(
                adapter.publish_head(0, h, hash).await,
                "height {h} must publish (strictly increasing)"
            );
            // Production-regime pacing (see `POINTER_REPUBLISH_PACE_MS`).
            tokio::time::sleep(std::time::Duration::from_millis(POINTER_REPUBLISH_PACE_MS)).await;
        }
        // Drain the last publishes' background replication tasks before
        // counting (and before removing the temp dir, so no straggler
        // recreates files under it afterwards).
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let (live, hidden) = chunk_files(&dir);
        assert!(
            hidden.is_empty(),
            "no atomic-write leftovers after 1000 overwrites: {hidden:?}"
        );
        // Steady state is ONE live chunk set (the tiny head payload is 1 chunk);
        // without delete-first cleanup this would be 1000 orphaned files.
        // +1 slack for a straggler replication task under parallel-test load
        // (it writes exactly one version's file, once).
        assert!(
            live.len() <= base_live.len() + 2,
            "1000 head overwrites grew chunks {} -> {} (orphan leak)",
            base_live.len(),
            live.len()
        );

        // The pointer itself is still live and correct: overwrite cleanup must
        // never cost the latest value.
        let (h, hash) = adapter.fetch_head(0).await.expect("head must read back");
        assert_eq!(h, 1000);
        assert_eq!(&hash[..8], &1000u64.to_le_bytes());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn snapshot_pointer_overwrites_do_not_orphan_chunks() {
        let (adapter, dir) = test_adapter("snapptr").await;
        const N: u64 = 25;
        for h in 1..=N {
            // Small but height-distinct snapshot bodies (1 chunk each at 256B).
            let mut snap = vec![0u8; 256];
            snap[..8].copy_from_slice(&h.to_le_bytes());
            adapter.persist_state_snapshot(0, h * 100, &snap).await;
            // Production-regime pacing (see `POINTER_REPUBLISH_PACE_MS`).
            tokio::time::sleep(std::time::Duration::from_millis(POINTER_REPUBLISH_PACE_MS)).await;
        }
        // Drain background replication before counting (see head test).
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let (live, hidden) = chunk_files(&dir);
        assert!(
            hidden.is_empty(),
            "no atomic-write leftovers after {N} snapshots: {hidden:?}"
        );
        // N height-scoped snapshots (kept FOREVER by design) + exactly ONE live
        // pointer chunk; without delete-first cleanup the pointer alone would
        // add N orphaned files (2N total). +1 slack for a straggler task.
        assert!(
            live.len() <= N as usize + 2,
            "{N} snapshot publishes hold {} chunk files, want <= {} (pointer orphans?)",
            live.len(),
            N + 2
        );

        let latest = adapter
            .fetch_latest_snapshot(0)
            .await
            .expect("pointer must read back");
        assert_eq!(latest, N * 100);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ==================== Replication backpressure (local policy, 2026-10-14) ====================
//
// Live symptom: validator A was hammered by B with ~10-20 `dht.store` reqs/sec
// sustained; every store that timed out was retried, the retries added load,
// the load caused more timeouts — a mutual-DDoS feedback loop between two
// honest nodes that stalled consensus. Earlier storm bounds (fetch lane 8,
// snapshot lane 2) capped the FETCH side; replication PUBLISHES had no pacing:
// every `store_blob_with_ttl` spawns a background `replicate_blob` (up to 20s,
// fanning out to K peers), so back-to-back publishes spawn unbounded
// concurrent replicators.
//
// This section is LOCAL POLICY ONLY — no wire-protocol change, no infnode
// change, old/new nodes interoperate byte-for-byte. Every DHT store in this
// file funnels through [`paced_store_blob`], which enforces, in order:
//   1. circuit breaker (consecutive timeouts → short bounded cooldown, shed+LOUD),
//   2. concurrency cap (at most N stores in flight; bounded queue wait, then shed+LOUD),
//   3. per-overlay token-bucket pacing + min publish interval (burst-tolerant,
//      sustained-rate-capped; charged once per LOGICAL publish),
//   4. retry budget (bounded attempts, jittered backoff, then drop+LOUD warn —
//      never infinite, never silent).
//
// Per-peer granularity: infnode's `store_blob_with_ttl` hides the peer fan-out
// (the DHT key, not a peer id, is the only address), so per-peer buckets live in
// `src/consensus_net.rs`, where peer ids are visible on every send/probe. On
// the DHT path the breaker/pacing key is per (bucket, kind) lane (see
// [`repl_lane_key`]): bulk bodies, headers, snapshots and pointers each carry
// their own consecutive-timeout streak and cooldown, so one slow lane sheds
// only itself. The [`ReplBackpressure`] structure is per-key either way, so the
// DHT path gains per-peer granularity for free if infnode ever exposes the
// fan-out. Shed visibility: every SHED/DROP bumps `repl_shed_total()` (plus
// the per-kind breakdown) in addition to the LOUD stderr/WARN line.

/// Overlay key the DHT publish path paces under (see module docs: infnode hides
/// the per-peer fan-out of `store_blob_with_ttl`, so the overlay is one bucket).
pub const REPL_OVERLAY_KEY: &str = "dht-overlay";

/// Per-lane breaker key (audit-network F7 cheap isolation): the overlay-global
/// breaker shed ALL publishes (bodies, headers, snapshots, pointers) when one
/// slow replica set timed out 5x. Keys are `overlay:<bucket>:<kind>`, so a slow
/// body lane sheds bodies while head/snapshot pointers (different bucket or
/// kind) keep their own streak and cooldown. Buckets already separate bodies
/// (`stell_blocks`), headers (`stell_headers`), state (`stell_state`) and head
/// pointers (`stell_head`); kinds further separate Bulk from Pointer within one
/// bucket. Pure so tests pin the lane split without a live DHT.
pub fn repl_lane_key(bucket: &str, kind: ReplStoreKind) -> String {
    format!("{REPL_OVERLAY_KEY}:{bucket}:{}", kind.as_str())
}

/// Total replication sheds/DROPs since process start (fail-open visibility,
/// audit-network open risk 4): every SHED/DROP below bumps this (and the
/// per-kind breakdown), so `repl_shed_total` + a log scrape alerts before
/// mainnet instead of stderr alone.
static REPL_SHED_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static REPL_SHED_BULK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static REPL_SHED_POINTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static REPL_SHED_COMPANION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Total sheds/DROPs so far (all kinds).
pub fn repl_shed_total() -> u64 {
    REPL_SHED_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Sheds/DROPs for one store kind.
pub fn repl_shed_for_kind(kind: ReplStoreKind) -> u64 {
    let c = match kind {
        ReplStoreKind::Bulk => &REPL_SHED_BULK,
        ReplStoreKind::Pointer => &REPL_SHED_POINTER,
        ReplStoreKind::Companion => &REPL_SHED_COMPANION,
    };
    c.load(std::sync::atomic::Ordering::Relaxed)
}

fn repl_note_shed(kind: ReplStoreKind) {
    REPL_SHED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    match kind {
        ReplStoreKind::Bulk => &REPL_SHED_BULK,
        ReplStoreKind::Pointer => &REPL_SHED_POINTER,
        ReplStoreKind::Companion => &REPL_SHED_COMPANION,
    }
    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Max concurrent DHT stores process-wide (default 4, `STELL_REPL_MAX_CONCURRENT`).
/// Each store spawns a background `replicate_blob`; 4 bounds the replicator
/// fan-out instead of letting a retro pass spawn 128 concurrent ones.
pub const REPL_PUBLISH_MAX_CONCURRENT_DEFAULT: usize = 4;
/// Min interval between BULK publishes in ms (default 100, `STELL_REPL_MIN_INTERVAL_MS`).
/// Caps sustained bulk replication at ~10/sec with burst headroom from the bucket;
/// the observed hammer ran 10-20/sec with zero spacing, so even the burst-absorbed
/// floor breaks the re-synchronization shape. Charged once per logical publish.
pub const REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT: u64 = 100;
/// Min interval between POINTER publishes in ms (default 10, `STELL_REPL_HEAD_MIN_INTERVAL_MS`).
/// Head/snapshot pointers are single-chunk and already monotonic-guarded; they get a
/// light floor (desync jitter) rather than the bulk floor so the per-finalize head
/// republish never lags the tip.
pub const REPL_HEAD_MIN_INTERVAL_MS_DEFAULT: u64 = 10;
/// Foreground store timeout in ms (default 5000, `STELL_REPL_STORE_TIMEOUT_MS`).
/// The slow part of a store is synchronous chunk replication when this node holds
/// no role for the bucket; beyond this budget the attempt counts as a timeout.
pub const REPL_STORE_TIMEOUT_MS_DEFAULT: u64 = 5_000;
/// Total store attempts per publish (1 initial + retries; default 3,
/// `STELL_REPL_STORE_MAX_ATTEMPTS`). Exhaustion drops with a LOUD warn — the
/// caller (retro pass, tip publish) accounts the failure; nothing retries forever.
pub const REPL_STORE_MAX_ATTEMPTS_DEFAULT: u32 = 3;
/// Retry backoff base in ms (attempt `n` waits `base * 2^(n-1)`, capped).
pub const REPL_RETRY_BASE_MS: u64 = 200;
/// Retry backoff cap in ms.
pub const REPL_RETRY_CAP_MS: u64 = 2_000;
/// Max jitter added on top of the backoff in ms (uniform draw `0..=250`).
/// De-synchronizes publishers that timed out on the same slow peer so their
/// retries do not re-flood on the same tick.
pub const REPL_RETRY_JITTER_MAX_MS: u64 = 250;
/// Consecutive store timeouts that open the circuit (default 5,
/// `STELL_REPL_CIRCUIT_THRESHOLD`).
pub const REPL_CIRCUIT_THRESHOLD_DEFAULT: u32 = 5;
/// Circuit cooldown in ms (default 5000, `STELL_REPL_CIRCUIT_COOLDOWN_MS`).
/// Short and bounded: publishes shed during the window, then half-open (the next
/// publish is attempted; success closes immediately).
pub const REPL_CIRCUIT_COOLDOWN_MS_DEFAULT: u64 = 5_000;
/// Max wait to acquire the concurrency slot in ms (default 10000,
/// `STELL_REPL_QUEUE_WAIT_MS`). Beyond it the publish sheds with a LOUD warn
/// instead of queueing forever behind a wedged store.
pub const REPL_QUEUE_WAIT_MS_DEFAULT: u64 = 10_000;
/// Max wait for the pacing gate (token + interval) in ms (default 5000,
/// `STELL_REPL_PACE_WAIT_MS`). Beyond it the publish sheds with a LOUD warn;
/// under normal load the gate grants immediately or within one interval.
pub const REPL_PACE_WAIT_MS_DEFAULT: u64 = 5_000;
/// Cap on tracked pacing keys (default 256). Bounds memory; overflow evicts an
/// arbitrary entry ( Overlay path holds exactly one key, so this never fires there).
pub const REPL_MAX_TRACKED_PEERS: usize = 256;

fn parse_env_usize(raw: Option<String>, dflt: usize, min: usize) -> usize {
    raw.and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= min)
        .unwrap_or(dflt)
}

fn parse_env_u64(raw: Option<String>, dflt: u64, min: u64) -> u64 {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n >= min)
        .unwrap_or(dflt)
}

fn parse_env_u32(raw: Option<String>, dflt: u32, min: u32, max: u32) -> u32 {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n >= min && n <= max)
        .unwrap_or(dflt)
}

/// Parse `STELL_REPL_MAX_CONCURRENT` (pure so tests need no env mutation).
pub fn parse_repl_max_concurrent(v: Option<String>) -> usize {
    parse_env_usize(v, REPL_PUBLISH_MAX_CONCURRENT_DEFAULT, 1)
}
/// Parse `STELL_REPL_MIN_INTERVAL_MS` (bulk floor).
pub fn parse_repl_min_interval_ms(v: Option<String>) -> u64 {
    parse_env_u64(v, REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT, 1)
}
/// Parse `STELL_REPL_HEAD_MIN_INTERVAL_MS` (pointer floor).
pub fn parse_repl_head_min_interval_ms(v: Option<String>) -> u64 {
    parse_env_u64(v, REPL_HEAD_MIN_INTERVAL_MS_DEFAULT, 1)
}
/// Parse `STELL_REPL_STORE_TIMEOUT_MS`.
pub fn parse_repl_store_timeout_ms(v: Option<String>) -> u64 {
    parse_env_u64(v, REPL_STORE_TIMEOUT_MS_DEFAULT, 500)
}
/// Parse `STELL_REPL_STORE_MAX_ATTEMPTS` (total tries, clamped to 1..=8).
pub fn parse_repl_max_attempts(v: Option<String>) -> u32 {
    parse_env_u32(v, REPL_STORE_MAX_ATTEMPTS_DEFAULT, 1, 8)
}
/// Parse `STELL_REPL_CIRCUIT_THRESHOLD`.
pub fn parse_repl_circuit_threshold(v: Option<String>) -> u32 {
    parse_env_u32(v, REPL_CIRCUIT_THRESHOLD_DEFAULT, 1, 64)
}
/// Parse `STELL_REPL_CIRCUIT_COOLDOWN_MS`.
pub fn parse_repl_circuit_cooldown_ms(v: Option<String>) -> u64 {
    parse_env_u64(v, REPL_CIRCUIT_COOLDOWN_MS_DEFAULT, 500)
}

/// Effective concurrency cap (`STELL_REPL_MAX_CONCURRENT`, default 4).
pub fn repl_publish_max_concurrent() -> usize {
    parse_repl_max_concurrent(std::env::var("STELL_REPL_MAX_CONCURRENT").ok())
}
/// Effective bulk floor (`STELL_REPL_MIN_INTERVAL_MS`, default 100).
pub fn repl_bulk_min_interval_ms() -> u64 {
    parse_repl_min_interval_ms(std::env::var("STELL_REPL_MIN_INTERVAL_MS").ok())
}
/// Effective pointer floor (`STELL_REPL_HEAD_MIN_INTERVAL_MS`, default 10).
pub fn repl_head_min_interval_ms() -> u64 {
    parse_repl_head_min_interval_ms(std::env::var("STELL_REPL_HEAD_MIN_INTERVAL_MS").ok())
}
/// Effective store timeout (`STELL_REPL_STORE_TIMEOUT_MS`, default 5000).
pub fn repl_store_timeout_ms() -> u64 {
    parse_repl_store_timeout_ms(std::env::var("STELL_REPL_STORE_TIMEOUT_MS").ok())
}
/// Effective attempt budget (`STELL_REPL_STORE_MAX_ATTEMPTS`, default 3).
pub fn repl_store_max_attempts() -> u32 {
    parse_repl_max_attempts(std::env::var("STELL_REPL_STORE_MAX_ATTEMPTS").ok())
}
/// Effective circuit threshold (`STELL_REPL_CIRCUIT_THRESHOLD`, default 5).
pub fn repl_circuit_threshold() -> u32 {
    parse_repl_circuit_threshold(std::env::var("STELL_REPL_CIRCUIT_THRESHOLD").ok())
}
/// Effective circuit cooldown (`STELL_REPL_CIRCUIT_COOLDOWN_MS`, default 5000).
pub fn repl_circuit_cooldown_ms() -> u64 {
    parse_repl_circuit_cooldown_ms(std::env::var("STELL_REPL_CIRCUIT_COOLDOWN_MS").ok())
}
/// Effective queue-wait bound (`STELL_REPL_QUEUE_WAIT_MS`, default 10000).
pub fn repl_queue_wait_ms() -> u64 {
    parse_env_u64(
        std::env::var("STELL_REPL_QUEUE_WAIT_MS").ok(),
        REPL_QUEUE_WAIT_MS_DEFAULT,
        1_000,
    )
}
/// Effective gate-wait bound (`STELL_REPL_PACE_WAIT_MS`, default 5000).
pub fn repl_pace_wait_ms() -> u64 {
    parse_env_u64(
        std::env::var("STELL_REPL_PACE_WAIT_MS").ok(),
        REPL_PACE_WAIT_MS_DEFAULT,
        500,
    )
}

/// Backoff before retry attempt `attempt` (1-based: attempt 1 just failed).
/// `200 * 2^(attempt-1)` capped at 2000: 200, 400, 800, 1600, 2000, ...
/// The floor is always the base — a timed-out store never retries sooner.
pub fn repl_retry_backoff_ms(attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(4);
    REPL_RETRY_BASE_MS
        .saturating_mul(1u64 << shift)
        .min(REPL_RETRY_CAP_MS)
}

/// Backoff plus a uniform jitter draw `0..=250` (caller passes `rand::random::<u64>()`).
pub fn repl_retry_backoff_with_jitter_ms(attempt: u32, jitter: u64) -> u64 {
    repl_retry_backoff_ms(attempt).saturating_add(jitter % (REPL_RETRY_JITTER_MAX_MS + 1))
}

/// Whether another attempt is left: `completed` tries done out of `max_attempts`.
/// Total tries never exceed `max_attempts` — the anti-feedback-loop bound.
pub fn repl_should_retry(completed_attempts: u32, max_attempts: u32) -> bool {
    completed_attempts < max_attempts.max(1)
}

/// What kind of publish a store belongs to: the pacing gate charges once per
/// LOGICAL publish, not once per blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplStoreKind {
    /// Bodies, headers, snapshots, domain blobs, retro re-publishes: full pacing
    /// (token bucket + bulk floor). These fan out to per-chunk replicators.
    Bulk,
    /// Index/QC sidecars riding beside a Bulk publish: bounded store (semaphore +
    /// timeout + retry + circuit) but no extra gate charge, so one header never
    /// pays 3x the floor.
    Companion,
    /// Fixed-name head/snapshot pointers: bounded store + light pointer floor.
    Pointer,
}

impl ReplStoreKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplStoreKind::Bulk => "bulk",
            ReplStoreKind::Companion => "companion",
            ReplStoreKind::Pointer => "pointer",
        }
    }
}

/// One publish-pacing policy bundle (env-configured, snapshot per call site).
#[derive(Debug, Clone, Copy)]
pub struct ReplPublishConfig {
    pub max_concurrent: usize,
    pub bulk_min_interval_ms: u64,
    pub head_min_interval_ms: u64,
    pub store_timeout_ms: u64,
    pub max_attempts: u32,
    pub queue_wait_ms: u64,
    pub pace_wait_ms: u64,
    pub circuit_threshold: u32,
    pub circuit_cooldown_ms: u64,
}

impl ReplPublishConfig {
    /// Sane defaults (pinned by `tests/replication_backpressure_tests.rs`).
    #[allow(clippy::should_implement_trait)] // GATE: renaming churns call sites; Default-trait impl is out of scope
    pub fn default() -> Self {
        Self {
            max_concurrent: REPL_PUBLISH_MAX_CONCURRENT_DEFAULT,
            bulk_min_interval_ms: REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT,
            head_min_interval_ms: REPL_HEAD_MIN_INTERVAL_MS_DEFAULT,
            store_timeout_ms: REPL_STORE_TIMEOUT_MS_DEFAULT,
            max_attempts: REPL_STORE_MAX_ATTEMPTS_DEFAULT,
            queue_wait_ms: REPL_QUEUE_WAIT_MS_DEFAULT,
            pace_wait_ms: REPL_PACE_WAIT_MS_DEFAULT,
            circuit_threshold: REPL_CIRCUIT_THRESHOLD_DEFAULT,
            circuit_cooldown_ms: REPL_CIRCUIT_COOLDOWN_MS_DEFAULT,
        }
    }

    /// Live configuration from the `STELL_REPL_*` env (local policy: nodes MAY differ).
    pub fn from_env() -> Self {
        Self {
            max_concurrent: repl_publish_max_concurrent(),
            bulk_min_interval_ms: repl_bulk_min_interval_ms(),
            head_min_interval_ms: repl_head_min_interval_ms(),
            store_timeout_ms: repl_store_timeout_ms(),
            max_attempts: repl_store_max_attempts(),
            queue_wait_ms: repl_queue_wait_ms(),
            pace_wait_ms: repl_pace_wait_ms(),
            circuit_threshold: repl_circuit_threshold(),
            circuit_cooldown_ms: repl_circuit_cooldown_ms(),
        }
    }
}

/// Per-key pacing state: token bucket + min-interval + timeout circuit.
///
/// Time is injected (`now_ms`) so the whole policy is deterministic under test.
/// `tokens`/`last_refill_ms` implement the bucket (burst-tolerant, sustained-rate
/// capped); `last_publish_ms` enforces spacing even inside the burst allowance;
/// `consec_timeouts`/`cooldown_until_ms` implement the breaker.
#[derive(Debug, Clone)]
struct ReplPeerGate {
    tokens: f64,
    last_refill_ms: u64,
    last_publish_ms: Option<u64>,
    consec_timeouts: u32,
    cooldown_until_ms: u64,
}

/// Per-peer token-bucket pacing + consecutive-timeout circuit breaking.
///
/// Keyed by peer (or by bucket, e.g. [`REPL_OVERLAY_KEY`], where the transport
/// hides peer identity). Bounded: at most `max_peers` keys, then an arbitrary
/// entry is evicted to make room — memory cannot grow with attacker-chosen keys.
#[derive(Debug)]
pub struct ReplBackpressure {
    capacity: f64,
    refill_per_sec: f64,
    min_interval_ms: u64,
    circuit_threshold: u32,
    circuit_cooldown_ms: u64,
    max_peers: usize,
    peers: std::collections::HashMap<String, ReplPeerGate>,
}

impl ReplBackpressure {
    /// General constructor: `capacity` burst tokens, sustained `refill_per_sec`,
    /// spacing floor `min_interval_ms`, breaker (`circuit_threshold` consecutive
    /// timeouts → `circuit_cooldown_ms` shed window).
    pub fn new(
        capacity: usize,
        refill_per_sec: f64,
        min_interval_ms: u64,
        circuit_threshold: u32,
        circuit_cooldown_ms: u64,
        max_peers: usize,
    ) -> Self {
        Self {
            capacity: capacity.max(1) as f64,
            refill_per_sec: refill_per_sec.max(0.0),
            min_interval_ms,
            circuit_threshold: circuit_threshold.max(1),
            circuit_cooldown_ms,
            max_peers: max_peers.max(1),
            peers: std::collections::HashMap::new(),
        }
    }

    /// Bulk-lane shape: burst 4, sustained 1 per bulk floor, breaker 5 → 5s.
    /// Matches [`ReplPublishConfig::default`]; prefer `from_env_bulk` live.
    pub fn with_defaults() -> Self {
        Self::new(
            REPL_PUBLISH_MAX_CONCURRENT_DEFAULT,
            1000.0 / REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT as f64,
            REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT,
            REPL_CIRCUIT_THRESHOLD_DEFAULT,
            REPL_CIRCUIT_COOLDOWN_MS_DEFAULT,
            REPL_MAX_TRACKED_PEERS,
        )
    }

    /// Live bulk-lane shape from the `STELL_REPL_*` env.
    pub fn from_env_bulk() -> Self {
        let interval = repl_bulk_min_interval_ms().max(1);
        Self::new(
            repl_publish_max_concurrent(),
            1000.0 / interval as f64,
            interval,
            repl_circuit_threshold(),
            repl_circuit_cooldown_ms(),
            REPL_MAX_TRACKED_PEERS,
        )
    }

    /// Live pointer-lane shape from the `STELL_REPL_*` env (lighter floor).
    pub fn from_env_head() -> Self {
        let interval = repl_head_min_interval_ms().max(1);
        Self::new(
            repl_publish_max_concurrent().max(4),
            1000.0 / interval as f64,
            interval,
            repl_circuit_threshold(),
            repl_circuit_cooldown_ms(),
            REPL_MAX_TRACKED_PEERS,
        )
    }

    /// Keys currently tracked (for the memory bound pin).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Consecutive timeouts recorded for `peer` (breaker input pin).
    pub fn consec_timeouts(&self, peer: &str) -> u32 {
        self.peers.get(peer).map(|g| g.consec_timeouts).unwrap_or(0)
    }

    /// True while `peer` sits in its post-timeout cooldown (shed now, half-open later).
    pub fn in_cooldown(&self, peer: &str, now_ms: u64) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|g| now_ms < g.cooldown_until_ms)
    }

    fn gate_for<'a>(
        peers: &'a mut std::collections::HashMap<String, ReplPeerGate>,
        max_peers: usize,
        capacity: f64,
        peer: &str,
        now_ms: u64,
    ) -> &'a mut ReplPeerGate {
        if !peers.contains_key(peer) && peers.len() >= max_peers.max(1) {
            if let Some(k) = peers.keys().next().cloned() {
                peers.remove(&k);
            }
        }
        peers.entry(peer.to_string()).or_insert(ReplPeerGate {
            tokens: capacity,
            last_refill_ms: now_ms,
            last_publish_ms: None,
            consec_timeouts: 0,
            cooldown_until_ms: 0,
        })
    }

    /// Whether `peer` may publish NOW. On true a token is consumed and the publish
    /// is stamped (drives both the bucket and the spacing floor). Denials are
    /// cheap and side-effect-free apart from the refill accounting.
    pub fn publish_allowed(&mut self, peer: &str, now_ms: u64) -> bool {
        let gate = Self::gate_for(&mut self.peers, self.max_peers, self.capacity, peer, now_ms);
        let refill = self.refill_per_sec;
        let capacity = self.capacity;
        let interval = self.min_interval_ms;
        let elapsed = now_ms.saturating_sub(gate.last_refill_ms);
        if elapsed > 0 {
            gate.tokens = (gate.tokens + elapsed as f64 / 1000.0 * refill).min(capacity);
            gate.last_refill_ms = now_ms;
        }
        if now_ms < gate.cooldown_until_ms {
            return false;
        }
        if gate.tokens < 1.0 {
            return false;
        }
        if let Some(last) = gate.last_publish_ms {
            if now_ms.saturating_sub(last) < interval {
                return false;
            }
        }
        gate.tokens -= 1.0;
        gate.last_publish_ms = Some(now_ms);
        true
    }

    /// Record a successful store: clears the timeout streak (closes the breaker).
    pub fn record_success(&mut self, peer: &str) {
        if let Some(g) = self.peers.get_mut(peer) {
            g.consec_timeouts = 0;
        }
    }

    /// Record a timed-out (or reached-nobody) store: extends the streak, and at
    /// `circuit_threshold` opens a bounded shed window. Never infinite: the window
    /// always expires and the next publish half-opens.
    pub fn record_timeout(&mut self, peer: &str, now_ms: u64) {
        let threshold = self.circuit_threshold;
        let cooldown = self.circuit_cooldown_ms;
        let max_peers = self.max_peers;
        let capacity = self.capacity;
        let gate = Self::gate_for(&mut self.peers, max_peers, capacity, peer, now_ms);
        gate.consec_timeouts = gate.consec_timeouts.saturating_add(1);
        if gate.consec_timeouts >= threshold {
            gate.cooldown_until_ms = now_ms.saturating_add(cooldown);
        }
    }
}

fn repl_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-wide concurrency slot for DHT stores (default 4, sized once from env).
fn repl_store_sem() -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| tokio::sync::Semaphore::new(repl_publish_max_concurrent().max(1)))
}

/// Process-wide bulk pacing gate (token bucket + interval + breaker).
fn repl_bulk_gate() -> &'static std::sync::Mutex<ReplBackpressure> {
    static GATE: std::sync::OnceLock<std::sync::Mutex<ReplBackpressure>> =
        std::sync::OnceLock::new();
    GATE.get_or_init(|| std::sync::Mutex::new(ReplBackpressure::from_env_bulk()))
}

/// Process-wide pointer pacing gate (lighter floor).
fn repl_head_gate() -> &'static std::sync::Mutex<ReplBackpressure> {
    static GATE: std::sync::OnceLock<std::sync::Mutex<ReplBackpressure>> =
        std::sync::OnceLock::new();
    GATE.get_or_init(|| std::sync::Mutex::new(ReplBackpressure::from_env_head()))
}

fn repl_loud(action: &str, bucket: &str, name: &str, kind: ReplStoreKind, reason: &str) {
    let line = format!(
        "[repl-backpressure] {action} {bucket}/{name} ({}): {reason} \
         (never infinite: bounded attempts, bounded waits, bounded cooldown)",
        kind.as_str()
    );
    eprintln!("{line}");
    tracing::warn!("{line}");
}

/// One slot of the header-group publish: the blob's role, whether it charges
/// the pacing gate, and which rate-limit LANE it rides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderPublishSlot {
    /// `header`, `index` or `qc`.
    pub role: &'static str,
    /// Whether this publish consumes a pacing token (`Pointer`/`Bulk` charge
    /// the gate, `Companion` rides along without an extra interval charge).
    pub charge: ReplStoreKind,
    /// The lane (gate + per-lane circuit breaker) this publish rides.
    pub lane: ReplStoreKind,
}

/// The publish plan for ONE header group: the header body, the height→hash
/// index and the A1 QC sidecar.
///
/// All three ride the SAME lane (`Pointer`). They used to split: the header
/// went to the Pointer lane while the index and the QC sidecar went to the
/// Bulk lane. A bulk-lane cooldown then shed the QC sidecar while the header
/// still landed — and a catch-up node reads "header present, QC missing" as
/// "not anchorable", so the header is rejected as unanchored even though it
/// was published correctly.
///
/// With one lane the per-lane circuit breaker treats the group as a single
/// unit: either the whole group is shed (a missing pair, consistently
/// skipped) or the whole group lands (a complete, anchorable header).
///
/// The sidecars still do NOT charge the pacing gate (`Companion`), so a
/// 3-blob header never pays 3x the publish floor.
pub fn header_publish_slots() -> [HeaderPublishSlot; 3] {
    [
        HeaderPublishSlot {
            role: "header",
            charge: ReplStoreKind::Pointer,
            lane: ReplStoreKind::Pointer,
        },
        HeaderPublishSlot {
            role: "index",
            charge: ReplStoreKind::Companion,
            lane: ReplStoreKind::Pointer,
        },
        HeaderPublishSlot {
            role: "qc",
            charge: ReplStoreKind::Companion,
            lane: ReplStoreKind::Pointer,
        },
    ]
}

/// Bounded DHT store: the single choke point for every replication publish in
/// this file (block bodies, headers + sidecars, snapshots + domains, head and
/// snapshot pointers, retro re-publishes).
///
/// Order: circuit check → bounded concurrency slot → pacing gate (Bulk/Pointer
/// charge it; Companion rides the same bounded store without charging) → bounded
/// attempts with jittered backoff. Returns the infnode store count (0 = shed or
/// exhausted: LOUD-warned, never silent, never blocking the caller past the
/// configured bounds).
pub async fn paced_store_blob(
    node: &std::sync::Arc<infnode::node::Node>,
    bucket: &str,
    name: &str,
    payload: &[u8],
    ttl_ms: i64,
    kind: ReplStoreKind,
) -> usize {
    paced_store_blob_in_lane(node, bucket, name, payload, ttl_ms, kind, kind).await
}

/// Bounded DHT store in an EXPLICIT rate-limit lane.
///
/// `kind` decides whether the publish charges the pacing gate (Bulk/Pointer
/// charge it, Companion rides along without an extra interval charge);
/// `lane_kind` decides WHICH lane the publish rides — the gate (bulk vs
/// pointer) and the per-lane circuit breaker / streak / cooldown key.
///
/// Why the split exists: a header and its sidecars (height index, QC
/// sidecar) are ONE logical publish and MUST NOT be splittable. The header
/// rides the Pointer lane; if its sidecars rode the Bulk lane, a bulk-lane
/// cooldown would shed the QC while the header still landed, and every
/// catch-up node would then reject that header as unanchored ("missing QC →
/// skip"). With the sidecar in the header's own lane the breaker treats them
/// as one unit: either the whole group is shed, or the whole group lands.
pub async fn paced_store_blob_in_lane(
    node: &std::sync::Arc<infnode::node::Node>,
    bucket: &str,
    name: &str,
    payload: &[u8],
    ttl_ms: i64,
    kind: ReplStoreKind,
    lane_kind: ReplStoreKind,
) -> usize {
    let cfg = ReplPublishConfig::from_env();
    let gate = match lane_kind {
        ReplStoreKind::Bulk | ReplStoreKind::Companion => repl_bulk_gate(),
        ReplStoreKind::Pointer => repl_head_gate(),
    };
    // Per-lane isolation (audit-network F7): the breaker/pacing key includes
    // the bucket AND the kind, so a slow body lane sheds bodies while
    // pointers (and other buckets) keep their own streak/cooldown. Same
    // bounded consecutive-timeout breaker per lane, just no longer
    // overlay-global.
    let lane = repl_lane_key(bucket, lane_kind);
    // 1. Circuit breaker: shed fast while this LANE cannot take replicas.
    if gate
        .lock()
        .map(|g| g.in_cooldown(&lane, repl_now_ms()))
        .unwrap_or(false)
    {
        repl_note_shed(kind);
        repl_loud(
            "SHED",
            bucket,
            name,
            kind,
            &format!(
                "replication circuit open for lane {lane} after {} consecutive timeouts; \
                 half-opens automatically after cooldown (other lanes unaffected)",
                cfg.circuit_threshold
            ),
        );
        return 0;
    }
    // 2. Concurrency cap: bounded wait for a slot, then shed (never queue forever).
    let _permit = match tokio::time::timeout(
        std::time::Duration::from_millis(cfg.queue_wait_ms),
        repl_store_sem().acquire(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            repl_note_shed(kind);
            repl_loud(
                "SHED",
                bucket,
                name,
                kind,
                &format!(
                    "no store slot within {}ms ({} in flight); shedding instead of queueing",
                    cfg.queue_wait_ms, cfg.max_concurrent
                ),
            );
            return 0;
        }
    };
    // 3. Pacing gate: charged once per logical publish. Companions (index/QC
    // sidecars) skip the charge — they share the bounded store below, not the rate.
    if matches!(kind, ReplStoreKind::Bulk | ReplStoreKind::Pointer) {
        let deadline = repl_now_ms().saturating_add(cfg.pace_wait_ms);
        loop {
            let allowed = gate
                .lock()
                .map(|mut g| g.publish_allowed(&lane, repl_now_ms()))
                .unwrap_or(true);
            if allowed {
                break;
            }
            if repl_now_ms() >= deadline {
                repl_note_shed(kind);
                repl_loud(
                    "SHED",
                    bucket,
                    name,
                    kind,
                    &format!(
                        "pacing gate held past {}ms; shedding instead of lagging the lane",
                        cfg.pace_wait_ms
                    ),
                );
                return 0;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
    }
    // 4. Retry budget: bounded attempts, jittered backoff, then drop+LOUD.
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(cfg.store_timeout_ms),
            node.store_blob_with_ttl(bucket, name, payload, ttl_ms),
        )
        .await;
        match res {
            Ok(n) if n > 0 => {
                if let Ok(mut g) = gate.lock() {
                    g.record_success(&lane);
                }
                return n;
            }
            Ok(_) => {
                if let Ok(mut g) = gate.lock() {
                    g.record_timeout(&lane, repl_now_ms());
                }
                if !repl_should_retry(attempt, cfg.max_attempts) {
                    repl_note_shed(kind);
                    repl_loud(
                        "DROP",
                        bucket,
                        name,
                        kind,
                        &format!(
                            "store reached no local chunk and no replica after {attempt} attempts; \
                             counted by the caller, never retried infinitely"
                        ),
                    );
                    return 0;
                }
            }
            Err(_) => {
                if let Ok(mut g) = gate.lock() {
                    g.record_timeout(&lane, repl_now_ms());
                }
                if !repl_should_retry(attempt, cfg.max_attempts) {
                    repl_note_shed(kind);
                    repl_loud(
                        "DROP",
                        bucket,
                        name,
                        kind,
                        &format!(
                            "store timed out (>{}ms) on all {attempt} attempts; \
                             breaker streak extended, never retried infinitely",
                            cfg.store_timeout_ms
                        ),
                    );
                    return 0;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            repl_retry_backoff_with_jitter_ms(attempt, rand::random::<u64>()),
        ))
        .await;
        tokio::task::yield_now().await;
    }
}
