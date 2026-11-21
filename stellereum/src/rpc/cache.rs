use serde_json::Value;
use std::collections::HashMap;

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
pub(super) fn finalized_read_cache_method(method: &str) -> Option<&'static str> {
    match method {
        "stell_getBlock" => Some("stell_getBlock"),
        "stell_getBlockTransactions" => Some("stell_getBlockTransactions"),
        "stell_getFinalizedHeader" => Some("stell_getFinalizedHeader"),
        "stell_getEpochRoot" => Some("stell_getEpochRoot"),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct FinalizedReadKey {
    method: &'static str,
    height: u64,
    params_hash: [u8; 32],
}

pub(super) struct FinalizedReadEntry {
    result: Value,
    filled_tip: u64,
    filled_at: std::time::Instant,
}

#[derive(Default)]
pub(super) struct FinalizedReadCache {
    map: HashMap<FinalizedReadKey, FinalizedReadEntry>,
    hits: u64,
    misses: u64,
}

pub(super) static FINALIZED_READ_CACHE: std::sync::OnceLock<std::sync::Mutex<FinalizedReadCache>> =
    std::sync::OnceLock::new();

pub(super) fn finalized_read_cache() -> &'static std::sync::Mutex<FinalizedReadCache> {
    FINALIZED_READ_CACHE.get_or_init(|| std::sync::Mutex::new(FinalizedReadCache::default()))
}

struct Blake3IoWriter<'a>(&'a mut blake3::Hasher);

impl std::io::Write for Blake3IoWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Canonical hash of the request params: two byte-identical requests share a
/// key; anything else (even an ignored extra field) is a separate key holding
/// the same bytes — fail-closed towards extra entries, never wrong bytes.
pub fn finalized_read_cache_params_hash(params: &Value) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    if serde_json::to_writer(Blake3IoWriter(&mut hasher), params).is_err() {
        hasher.reset();
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn finalized_read_cache_fresh(entry: &FinalizedReadEntry, tip: u64) -> bool {
    entry.filled_tip == tip && entry.filled_at.elapsed().as_secs() < FINALIZED_READ_CACHE_TTL_SECS
}

/// Cached finalized response, if any. `None` (miss) means "recompute and
/// consider filling via [`finalized_read_cache_put`]". Pure read path: no
/// auth, no budgets, no mutation beyond hit/miss counters.
pub fn finalized_read_cache_get(
    method: &str,
    height: u64,
    params: &Value,
    tip: u64,
) -> Option<Value> {
    let method = finalized_read_cache_method(method)?;
    let key = FinalizedReadKey {
        method,
        height,
        params_hash: finalized_read_cache_params_hash(params),
    };
    let mut cache = finalized_read_cache()
        .lock()
        .expect("finalized-read cache lock");
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
    if height > tip {
        return;
    }
    let Some(method) = finalized_read_cache_method(method) else {
        return;
    };
    let key = FinalizedReadKey {
        method,
        height,
        params_hash: finalized_read_cache_params_hash(params),
    };
    let mut cache = finalized_read_cache()
        .lock()
        .expect("finalized-read cache lock");
    if cache.map.len() >= FINALIZED_READ_CACHE_CAP && !cache.map.contains_key(&key) {
        // Fail-closed eviction: expired entries first, else the oldest fill.
        // Only entry DROPS happen here — correctness never depends on them.
        cache
            .map
            .retain(|_, e| e.filled_at.elapsed().as_secs() < FINALIZED_READ_CACHE_TTL_SECS);
        if cache.map.len() >= FINALIZED_READ_CACHE_CAP {
            let mut oldest: Option<(FinalizedReadKey, std::time::Instant)> = None;
            for (k, e) in cache.map.iter() {
                let replace = match &oldest {
                    None => true,
                    Some((_, t)) => e.filled_at < *t,
                };
                if replace {
                    oldest = Some((*k, e.filled_at));
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
    let cache = finalized_read_cache()
        .lock()
        .expect("finalized-read cache lock");
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
        e.filled_at = e
            .filled_at
            .checked_sub(std::time::Duration::from_secs(
                FINALIZED_READ_CACHE_TTL_SECS + 1,
            ))
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
pub(super) fn estimate_fee_rate_limit() -> u32 {
    std::env::var("STELL_ESTIMATE_FEE_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(ESTIMATE_FEE_RATE_LIMIT_DEFAULT)
}

/// The process-wide estimate-fee limiter.
pub fn estimate_fee_budget() -> &'static crate::explorer::RateLimiter {
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
pub const LOCAL_BUCKET_IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

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
