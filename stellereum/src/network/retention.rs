use super::fetch::fetch_sem;
use super::naming::{
    block_name, header_index_name, header_name, header_qc_name, header_v2_name, EpochTag,
    BUCKET_STELLEREUM_BLOCKS, BUCKET_STELLEREUM_HEADERS, PREFIX_BLOCK_HASH,
};
use super::P2pNetworkAdapter;

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
    static CACHED: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_DHT_FOREVER_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(STELL_DHT_FOREVER_TTL_MS)
    })
}

/// How many recent heights the DHT retains (bodies, headers, indices).
/// Same env name the consensus loop uses for the local store
/// (`STELL_KEEP_BLOCKS` in `src/main.rs`), so one knob moves both horizons.
pub fn retention_keep_blocks() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("STELL_KEEP_BLOCKS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(dht_keep_blocks_default)
    })
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

impl P2pNetworkAdapter {
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
            self.node
                .delete_blob_local(
                    BUCKET_STELLEREUM_HEADERS,
                    &header_v2_name(&epoch, shard_id, h),
                )
                .await;
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
    static CACHED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHED
        .get_or_init(|| parse_repl_max_concurrent(std::env::var("STELL_REPL_MAX_CONCURRENT").ok()))
}
/// Effective bulk floor (`STELL_REPL_MIN_INTERVAL_MS`, default 100).
pub fn repl_bulk_min_interval_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_repl_min_interval_ms(std::env::var("STELL_REPL_MIN_INTERVAL_MS").ok())
    })
}
/// Effective pointer floor (`STELL_REPL_HEAD_MIN_INTERVAL_MS`, default 10).
pub fn repl_head_min_interval_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_repl_head_min_interval_ms(std::env::var("STELL_REPL_HEAD_MIN_INTERVAL_MS").ok())
    })
}
/// Effective store timeout (`STELL_REPL_STORE_TIMEOUT_MS`, default 5000).
pub fn repl_store_timeout_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_repl_store_timeout_ms(std::env::var("STELL_REPL_STORE_TIMEOUT_MS").ok())
    })
}
/// Effective attempt budget (`STELL_REPL_STORE_MAX_ATTEMPTS`, default 3).
pub fn repl_store_max_attempts() -> u32 {
    static CACHED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_repl_max_attempts(std::env::var("STELL_REPL_STORE_MAX_ATTEMPTS").ok())
    })
}
/// Effective circuit threshold (`STELL_REPL_CIRCUIT_THRESHOLD`, default 5).
pub fn repl_circuit_threshold() -> u32 {
    static CACHED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_repl_circuit_threshold(std::env::var("STELL_REPL_CIRCUIT_THRESHOLD").ok())
    })
}
/// Effective circuit cooldown (`STELL_REPL_CIRCUIT_COOLDOWN_MS`, default 5000).
pub fn repl_circuit_cooldown_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_repl_circuit_cooldown_ms(std::env::var("STELL_REPL_CIRCUIT_COOLDOWN_MS").ok())
    })
}
/// Effective queue-wait bound (`STELL_REPL_QUEUE_WAIT_MS`, default 10000).
pub fn repl_queue_wait_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_env_u64(
            std::env::var("STELL_REPL_QUEUE_WAIT_MS").ok(),
            REPL_QUEUE_WAIT_MS_DEFAULT,
            1_000,
        )
    })
}
/// Effective gate-wait bound (`STELL_REPL_PACE_WAIT_MS`, default 5000).
pub fn repl_pace_wait_ms() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        parse_env_u64(
            std::env::var("STELL_REPL_PACE_WAIT_MS").ok(),
            REPL_PACE_WAIT_MS_DEFAULT,
            500,
        )
    })
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
        static CACHED: std::sync::OnceLock<ReplPublishConfig> = std::sync::OnceLock::new();
        *CACHED.get_or_init(|| Self {
            max_concurrent: repl_publish_max_concurrent(),
            bulk_min_interval_ms: repl_bulk_min_interval_ms(),
            head_min_interval_ms: repl_head_min_interval_ms(),
            store_timeout_ms: repl_store_timeout_ms(),
            max_attempts: repl_store_max_attempts(),
            queue_wait_ms: repl_queue_wait_ms(),
            pace_wait_ms: repl_pace_wait_ms(),
            circuit_threshold: repl_circuit_threshold(),
            circuit_cooldown_ms: repl_circuit_cooldown_ms(),
        })
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
