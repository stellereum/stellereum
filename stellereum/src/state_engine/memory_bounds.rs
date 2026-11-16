use std::collections::{BTreeMap, HashMap, VecDeque};

/// Read a `usize` cap from the environment; unparseable/zero → default.
/// Zero can never mean "store nothing" (that would fail closed), so it
/// falls back to the default like any other bad value.
pub fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// `u64` variant of [`env_usize`].
pub fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// Minimum milliseconds between two loud warnings from one source.
pub const EVICT_WARN_INTERVAL_MS: u64 = 60_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Emit `msg` at warn level at most once per `interval_ms` (per counter).
/// Lock-free; a lost CAS race only ever SKIPS a duplicate line.
pub fn warn_throttled(last_ms: &std::sync::atomic::AtomicU64, interval_ms: u64, msg: &str) {
    let now = now_ms();
    let last = last_ms.load(std::sync::atomic::Ordering::Relaxed);
    if now.saturating_sub(last) < interval_ms {
        return;
    }
    if last_ms
        .compare_exchange_weak(
            last,
            now,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
    {
        tracing::warn!("[memory-bounds] {msg}");
    }
}

/// A bounded LRU cache with loud, throttled eviction and disk read-through.
///
/// * Inserting past `cap` evicts the least-recently-used live entry and
///   warns (throttled) — the "eviction LOUD" rule.
/// * `get_or_load` consults `loader` (the disk side) on a miss; a loader
///   miss or error yields `None` — reads fail OPEN, never closed.
/// * Recency is sequence-based with lazy queue deletion: every op is
///   amortized O(1); the order queue holds at most (#inserts) stale
///   entries, reclaimed by the eviction scan.
#[derive(Debug)]
pub struct BoundedLruCache<K, V> {
    name: &'static str,
    cap: usize,
    map: HashMap<K, CacheEntry<V>>,
    order: VecDeque<(u64, K)>,
    next_seq: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
    last_warn_ms: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    seq: u64,
}

impl<K, V> Clone for BoundedLruCache<K, V>
where
    K: Clone,
    V: Clone,
{
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            cap: self.cap,
            map: self.map.clone(),
            order: self.order.clone(),
            next_seq: self.next_seq,
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            last_warn_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl<K, V> BoundedLruCache<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    /// Create with an explicit cap (clamped to ≥ 1 — a zero cap would fail
    /// closed on every insert, which this module never does).
    pub fn new(name: &'static str, cap: usize) -> Self {
        Self {
            name,
            cap: cap.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
            last_warn_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create with the cap read from `env_key` (fallback `default`).
    pub fn with_env(name: &'static str, env_key: &str, default: usize) -> Self {
        Self::new(name, env_usize(env_key, default))
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Resize the cap (env reload path); evicts down immediately if over.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap.max(1);
        while self.map.len() > self.cap {
            if !self.evict_oldest() {
                break;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }

    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// LRU-get: returns a clone and refreshes recency. Needs `&mut`
    /// (recency is a write); use `peek` for a lock-free read.
    pub fn get(&mut self, key: &K) -> Option<V> {
        let seq = self.next_seq.wrapping_add(1);
        if let Some(e) = self.map.get_mut(key) {
            self.next_seq = seq;
            e.seq = seq;
            self.order.push_back((seq, key.clone()));
            self.hits += 1;
            return Some(e.value.clone());
        }
        None
    }

    /// Read without touching recency.
    pub fn peek(&self, key: &K) -> Option<V> {
        self.map.get(key).map(|e| e.value.clone())
    }

    /// Insert, evicting the coldest entry when over cap. Eviction warns
    /// (throttled) naming the cache, the cap and the lifetime count.
    pub fn insert(&mut self, key: K, value: V) {
        let seq = self.next_seq.wrapping_add(1);
        self.next_seq = seq;
        if let Some(e) = self.map.get_mut(&key) {
            e.value = value;
            e.seq = seq;
        } else {
            if self.map.len() >= self.cap {
                self.evict_oldest();
            }
            self.map.insert(key.clone(), CacheEntry { value, seq });
        }
        self.order.push_back((seq, key));
    }

    /// Read-through: hit serves from memory; miss calls `loader` (the
    /// disk side) and admits what it returns. Loader miss/error → `None`
    /// (fail-open). An entry the loader serves is never treated as a
    /// failure even if it was previously evicted.
    pub fn get_or_load<E>(
        &mut self,
        key: K,
        loader: impl FnOnce(&K) -> Result<Option<V>, E>,
    ) -> Option<V> {
        if let Some(v) = self.get(&key) {
            return Some(v);
        }
        self.misses += 1;
        match loader(&key) {
            Ok(Some(v)) => {
                self.insert(key, v.clone());
                Some(v)
            }
            Ok(None) => None,
            Err(_) => None,
        }
    }

    /// Evict the oldest LIVE entry. Returns false when nothing evictable
    /// was found (stale queue drained without a live hit — cannot happen
    /// while `map.len() > 0`, but the loop must terminate regardless).
    fn evict_oldest(&mut self) -> bool {
        while let Some((seq, key)) = self.order.pop_front() {
            let live = self.map.get(&key).map(|e| e.seq) == Some(seq);
            if live {
                self.map.remove(&key);
                self.evictions += 1;
                let n = self.evictions;
                let name = self.name;
                let cap = self.cap;
                warn_throttled(
                    &self.last_warn_ms,
                    EVICT_WARN_INTERVAL_MS,
                    &format!(
                        "{name} over cap ({cap}): evicted coldest entry \
                         (lifetime evictions {n}) — size stays bounded, \
                         evicted entries are re-served from disk on demand"
                    ),
                );
                return true;
            }
        }
        false
    }
}

// ---------- block / body cache ----------

/// Default cap for cached block bodies (bytes per body are whatever the
/// chain produces; count-bound like every other Phase-1 cap).
pub const DEFAULT_MAX_CACHED_BLOCKS: usize = 2048;

/// Effective cap: `STELL_MAX_CACHED_BLOCKS`, default 2048.
pub fn max_cached_blocks() -> usize {
    env_usize("STELL_MAX_CACHED_BLOCKS", DEFAULT_MAX_CACHED_BLOCKS)
}

/// Bounded LRU for block bodies keyed by block hash, with disk fallback
/// read-through: a lookup the disk can serve never fails just because the
/// entry was evicted. Phase-2 wiring target for `ValidatorRuntime.blocks`
/// / `BlockTree` (out of Phase-1 file scope).
#[derive(Debug, Clone)]
pub struct BlockBodyCache {
    inner: BoundedLruCache<[u8; 32], Vec<u8>>,
}

impl BlockBodyCache {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: BoundedLruCache::new("block_body_cache", cap),
        }
    }

    pub fn with_env() -> Self {
        Self::new(max_cached_blocks())
    }

    pub fn cap(&self) -> usize {
        self.inner.cap()
    }

    pub fn set_cap(&mut self, cap: usize) {
        self.inner.set_cap(cap);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn evictions(&self) -> u64 {
        self.inner.evictions()
    }

    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.inner.contains(hash)
    }

    pub fn insert(&mut self, hash: [u8; 32], body: Vec<u8>) {
        self.inner.insert(hash, body);
    }

    /// `loader` is the disk side (e.g. `Storage::get_block` bytes). Disk
    /// miss/error → `None`, never an error.
    pub fn get_or_load_block<E>(
        &mut self,
        hash: [u8; 32],
        loader: impl FnOnce(&[u8; 32]) -> Result<Option<Vec<u8>>, E>,
    ) -> Option<Vec<u8>> {
        self.inner.get_or_load(hash, loader)
    }
}

// ---------- PQ-key fallback bound ----------

/// Default cap for the sled-less PQ-key fallback map.
pub const DEFAULT_MAX_PQ_FALLBACK_ENTRIES: usize = 65_536;

/// Effective cap: `STELL_MAX_PQ_FALLBACK_ENTRIES`, default 65536.
pub fn max_pq_fallback_entries() -> usize {
    env_usize(
        "STELL_MAX_PQ_FALLBACK_ENTRIES",
        DEFAULT_MAX_PQ_FALLBACK_ENTRIES,
    )
}

// ---------- vote-set / round history ----------

/// Rounds retained behind the current one: `current-2..=current`.
pub const VOTE_HISTORY_KEEP_ROUNDS: u64 = 2;

/// Bounded per-height round history. Inserting or advancing past the
/// window prunes rounds older than `current - KEEP` while `lock_info`
/// (the Tendermint lock: value + round) survives the prune untouched.
/// `reset_for_height` drops every round bucket so history can never
/// accumulate across heights; the lock record is kept for the caller to
/// carry or clear explicitly.
#[derive(Debug, Clone, Default)]
pub struct VoteRoundHistory<V> {
    rounds: BTreeMap<u64, V>,
    current: u64,
    lock_info: Option<([u8; 32], u64)>,
}

impl<V> VoteRoundHistory<V> {
    pub fn new() -> Self {
        Self {
            rounds: BTreeMap::new(),
            current: 0,
            lock_info: None,
        }
    }

    pub fn current(&self) -> u64 {
        self.current
    }

    pub fn len(&self) -> usize {
        self.rounds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rounds.is_empty()
    }

    pub fn oldest(&self) -> Option<u64> {
        self.rounds.keys().next().copied()
    }

    /// Record the lock (value voted + round locked). Survives pruning.
    pub fn set_lock(&mut self, hash: [u8; 32], round: u64) {
        self.lock_info = Some((hash, round));
    }

    pub fn clear_lock(&mut self) {
        self.lock_info = None;
    }

    pub fn lock_info(&self) -> Option<([u8; 32], u64)> {
        self.lock_info
    }

    /// Move `current` forward (never backward) and prune everything older
    /// than `current - KEEP`. Late/backward calls only prune.
    pub fn advance_to(&mut self, round: u64) {
        if round > self.current {
            self.current = round;
        }
        self.prune();
    }

    /// Insert a round bucket. Returns false (dropped) when the round is
    /// already outside the retention window — history never grows it back.
    pub fn insert(&mut self, round: u64, votes: V) -> bool {
        let floor = self.current.saturating_sub(VOTE_HISTORY_KEEP_ROUNDS);
        if round < floor {
            return false;
        }
        if round > self.current {
            self.current = round;
        }
        self.rounds.insert(round, votes);
        self.prune();
        true
    }

    pub fn get(&self, round: u64) -> Option<&V> {
        self.rounds.get(&round)
    }

    /// New height: drop every round bucket. The lock record is preserved
    /// for the caller (height-scoped callers should `clear_lock` too).
    pub fn reset_for_height(&mut self) {
        self.rounds.clear();
        self.current = 0;
    }

    fn prune(&mut self) {
        let floor = self.current.saturating_sub(VOTE_HISTORY_KEEP_ROUNDS);
        self.rounds.retain(|&r, _| r >= floor);
    }
}

// ---------- account / trie hot-state accounting ----------

/// Warn threshold for live account count (soft watermark — consensus state
/// is NEVER evicted; evicting it would fork the chain).
pub const DEFAULT_MAX_ACCOUNTS_WARN: u64 = 5_000_000;

/// Effective watermark: `STELL_MAX_ACCOUNTS_WARN`, default 5_000_000.
pub fn accounts_memory_warn_threshold() -> u64 {
    env_u64("STELL_MAX_ACCOUNTS_WARN", DEFAULT_MAX_ACCOUNTS_WARN)
}

/// Rough bytes per live account: 32 B key + ~200 B value + HashMap slot +
/// heap + amortized compressed-trie path (~50–150 B). Deliberately coarse:
/// it sizes orders of magnitude, not pages.
pub const EST_BYTES_PER_ACCOUNT: u64 = 384;

/// Rough hot-state bytes for `n_accounts` live accounts (map + trie).
pub fn estimate_accounts_bytes(n_accounts: u64) -> u64 {
    n_accounts.saturating_mul(EST_BYTES_PER_ACCOUNT)
}

/// Pure watermark check (testable): true at/above the threshold.
pub fn accounts_over_watermark(n_accounts: u64) -> bool {
    n_accounts >= accounts_memory_warn_threshold()
}

// ---------- snapshot chunking ----------

/// Accounts serialized per snapshot chunk (peak ≈ one chunk in RAM).
pub const DEFAULT_SNAPSHOT_CHUNK_ACCOUNTS: usize = 50_000;

/// Effective chunk size: `STELL_SNAPSHOT_CHUNK_ACCOUNTS`, default 50_000.
pub fn snapshot_chunk_accounts() -> usize {
    env_usize(
        "STELL_SNAPSHOT_CHUNK_ACCOUNTS",
        DEFAULT_SNAPSHOT_CHUNK_ACCOUNTS,
    )
}

static ACCOUNTS_WARN_LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl super::InMemoryStateEngine {
    /// Live PQ-fallback occupancy (bounded LRU size, not the disk tree).
    pub fn pq_fallback_len(&self) -> usize {
        self.pq_keys_fallback
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Lifetime PQ-fallback evictions (0 while under cap / disk-attached).
    pub fn pq_fallback_evictions(&self) -> u64 {
        self.pq_keys_fallback
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .evictions()
    }

    /// Soft-watermark check over live account count: LOUD (throttled)
    /// warn past `STELL_MAX_ACCOUNTS_WARN`, never an eviction — consensus
    /// state cannot be dropped. Returns the live count.
    pub async fn check_accounts_watermark(&self) -> usize {
        let n = self.accounts.read().await.len();
        if (n as u64) >= accounts_memory_warn_threshold() {
            warn_throttled(
                &ACCOUNTS_WARN_LAST_MS,
                EVICT_WARN_INTERVAL_MS,
                &format!(
                    "live accounts {n} at/above STELL_MAX_ACCOUNTS_WARN watermark \
                     (~{} bytes hot state by estimate) — unbounded growth, \
                     Phase-2 disk-backed store required; NOT evicting (consensus state)",
                    estimate_accounts_bytes(n as u64),
                ),
            );
        }
        n
    }

    /// Serialize accounts in address-sorted chunks of `chunk_accounts`
    /// (default `STELL_SNAPSHOT_CHUNK_ACCOUNTS`): peak transient memory is
    /// ≈ one chunk, not full state + all domains at once. Each chunk is an
    /// independent length-delimited unit; restore with
    /// [`Self::restore_snapshot_chunked`]. NOT byte-compatible with the
    /// monolithic [`Self::create_snapshot`] (which is kept for readers).
    ///
    /// The FIRST chunk carries the D2 consensus penalty map (the
    /// [`StateSnapshotV2`] shape); the rest are bare account chunks. The
    /// penalty is consensus-critical (it enters the charged fee), so it
    /// must travel with the state (audit W6.6).
    pub async fn create_snapshot_chunked(&self, chunk_accounts: Option<usize>) -> Vec<Vec<u8>> {
        let per = chunk_accounts.unwrap_or(snapshot_chunk_accounts()).max(1);
        let map = self.accounts.read().await;
        let mut addrs: Vec<[u8; 32]> = map.keys().copied().collect();
        addrs.sort();
        let mut out = Vec::new();
        for (i, group) in addrs.chunks(per).enumerate() {
            let states: Vec<super::AccountState> =
                group.iter().filter_map(|a| map.get(a).cloned()).collect();
            if i == 0 {
                // The first chunk also carries the penalty map.
                let penalty = self.consensus_penalty.read().await.clone();
                out.push(
                    bincode::serialize(&super::StateSnapshotV2 {
                        accounts: states,
                        penalty,
                    })
                    .unwrap_or_default(),
                );
            } else {
                out.push(bincode::serialize(&states).unwrap_or_default());
            }
        }
        out
    }

    /// Install chunks produced by [`Self::create_snapshot_chunked`].
    /// Same restore semantics as [`Self::restore_snapshot`] (generation
    /// bump, replay-set clear, accounts→tokens→trie lock order, token
    /// entries re-synced) but inserts chunk by chunk, so peak transient
    /// memory stays ≈ one chunk plus the live map itself.
    ///
    /// Validate-then-commit (audit F10): EVERY chunk is deserialized
    /// BEFORE live state is touched. The old code cleared the map, the
    /// trie AND the replay sets first, so a corrupt middle chunk returned
    /// `Err` with live state already wiped — a local state-corruption
    /// primitive on the very path meant to recover state. Now a poisoned
    /// chunk leaves accounts, trie and replay sets byte-identical.
    ///
    /// Like `restore_snapshot` this is the REORG path: all three committed
    /// replay sets are cleared and rebuilt from replayed blocks. A sync
    /// caller must use `restore_snapshot_chunked_preserve_replay_sets`
    /// with the coverage gate.
    pub async fn restore_snapshot_chunked(&self, chunks: &[Vec<u8>]) -> Result<(), String> {
        // Phase 1 (validate): decode every chunk with no locks held and
        // no mutation. Any failure returns with live state untouched.
        let (decoded, penalty) = Self::decode_snapshot_chunks(chunks)?;
        // Phase 2 (commit): all chunks are known-good; install.
        // The replay sets below are CLEARED (a committed domain), so this
        // is a domain bump, not a bare global one.
        self.bump_domain_generation(crate::commitment::Domain::CrossShard);
        self.cross_shard_consumed.write().await.clear();
        self.cross_shard_produced.write().await.clear();
        self.cross_shard_completed.write().await.clear();
        // The penalty travels with the state; install it BEFORE the
        // accounts lock (documented lock order: penalty -> accounts).
        *self.consensus_penalty.write().await = penalty;

        let mut map = self.accounts.write().await;
        let tokens = self.tokens.read().await;
        let mut trie = self.state_trie.write().await;
        map.clear();
        *trie = crate::cell::PatriciaTrie::new();

        for states in decoded {
            for acc in states {
                let data = acc.to_trie_bytes();
                trie.insert(&acc.address, &data);
                map.insert(acc.address, acc);
            }
        }

        super::types::write_token_trie_entries(&mut trie, &tokens);
        Ok(())
    }

    /// Chunked twin of [`Self::restore_snapshot_preserve_replay_sets`]
    /// for future snapshot-sync callers (audit F1+F10): validate-then-
    /// commit like [`Self::restore_snapshot_chunked`], but the cross-
    /// shard replay sets are PRESERVED, not cleared — the caller installs
    /// the snapshot's replay blob afterwards via
    /// `restore_cross_shard_replay` (extend-only) behind the fail-closed
    /// coverage gate (`cross_shard_replay_covers`). Two methods, not a
    /// flag, for the same reason as the monolithic pair: a flag at this
    /// call site is how a future caller silently picks the reorg
    /// semantics on the sync path and re-opens the double mint.
    pub async fn restore_snapshot_chunked_preserve_replay_sets(
        &self,
        chunks: &[Vec<u8>],
    ) -> Result<(), String> {
        let (decoded, penalty) = Self::decode_snapshot_chunks(chunks)?;
        // Same generation bump as the reorg twin; NO replay-set clear, so
        // only the global moves (committed subsystem state is unchanged:
        // the next root read replays every cached preimage).
        self.force_commitment_recompute();
        // The penalty travels with the state (see `create_snapshot`).
        *self.consensus_penalty.write().await = penalty;

        let mut map = self.accounts.write().await;
        let tokens = self.tokens.read().await;
        let mut trie = self.state_trie.write().await;
        map.clear();
        *trie = crate::cell::PatriciaTrie::new();

        for states in decoded {
            for acc in states {
                let data = acc.to_trie_bytes();
                trie.insert(&acc.address, &data);
                map.insert(acc.address, acc);
            }
        }

        super::types::write_token_trie_entries(&mut trie, &tokens);
        Ok(())
    }
}
