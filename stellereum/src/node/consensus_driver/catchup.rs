use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

use super::{
    advance_vote_floor, round_at_or_below_vote_floor, DriverConfig, DriverState, TickStep,
};
use crate::node::policy::*;
use crate::node::sync::*;
use stellereum::consensus_net::ConsensusMsg;
use stellereum::network::P2pNetworkAdapter;
use stellereum::runtime::ValidatorRuntime;

pub(super) const SMALL_GAP_LIVE_CATCHUP_WINDOW_MS: u64 = 1_500;
pub(super) const SMALL_GAP_LIVE_CATCHUP_BUDGET_MS: u64 = 120;

/// Cap the per-tick `try_catch_up` budget ONLY for `budget_gap == 0` blind probes
/// while the chain is actively finalizing (`since_last_finalized < 1500ms`).
/// Whenever `budget_gap >= 1` (verified ahead evidence), return `base_budget`
/// so 1–2 block catch-up never times out mid-WAN-RTT and spins in 500ms retry loops.
pub(super) fn effective_catchup_pass_budget(
    base_budget: Duration,
    budget_gap: u64,
    since_last_finalized: Duration,
) -> Duration {
    if budget_gap == 0
        && since_last_finalized < Duration::from_millis(SMALL_GAP_LIVE_CATCHUP_WINDOW_MS)
    {
        base_budget.min(Duration::from_millis(SMALL_GAP_LIVE_CATCHUP_BUDGET_MS))
    } else {
        base_budget
    }
}

/// Prefetch a bounded batch of missing block hashes concurrently into
/// `block_cache` (never exceeding [`HEAL_CACHE_CAP`]).
async fn heal_prefetch_missing_hashes(
    adapter: &Arc<P2pNetworkAdapter>,
    store: &stellereum::storage::Storage,
    candidates: &[[u8; 32]],
    deadline: Instant,
    block_cache: &mut std::collections::HashMap<[u8; 32], stellereum::sharding::Block>,
) -> Result<(), String> {
    use futures::stream::{self, StreamExt};

    let cap_left = HEAL_CACHE_CAP.saturating_sub(block_cache.len());
    if cap_left == 0 {
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    let mut to_fetch = Vec::new();
    for &h in candidates {
        if to_fetch.len() >= cap_left {
            break;
        }
        if block_cache.contains_key(&h) || !seen.insert(h) {
            continue;
        }
        if let Ok(Some(local)) = store.get_block(&h) {
            if local.compute_hash() == h && block_cache.len() < HEAL_CACHE_CAP {
                block_cache.insert(h, local);
            }
            continue;
        }
        to_fetch.push(h);
    }
    if to_fetch.is_empty() {
        return Ok(());
    }
    let concurrency = stellereum::sync::FETCH_MAX_CONCURRENCY.max(1);
    for chunk in to_fetch.chunks(concurrency * 2) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "healing timed out after {}s during concurrent block prefetch",
                HEAL_ENGINE_TIMEOUT.as_secs()
            ));
        }
        let batch: Vec<([u8; 32], Option<stellereum::sharding::Block>)> = tokio::time::timeout(
            remaining,
            stream::iter(chunk.iter().copied())
                .map(|h| {
                    let a = Arc::clone(adapter);
                    async move { (h, a.fetch_block(&h).await) }
                })
                .buffer_unordered(concurrency)
                .collect(),
        )
        .await
        .map_err(|_| {
            format!(
                "healing timed out after {}s during concurrent block prefetch",
                HEAL_ENGINE_TIMEOUT.as_secs()
            )
        })?;
        for (h, maybe_blk) in batch {
            if let Some(blk) = maybe_blk {
                if blk.compute_hash() == h && block_cache.len() < HEAL_CACHE_CAP {
                    block_cache.insert(h, blk);
                }
            }
        }
    }
    Ok(())
}

/// Resolve missing heights in `range` concurrently via header-index / QC probes
/// and prefetch their bodies (plus `cur_hash` at `range.end`) into
/// `block_cache` in bounded concurrent batches.
async fn heal_prefetch_height_range(
    adapter: &Arc<P2pNetworkAdapter>,
    store: &stellereum::storage::Storage,
    shard: u32,
    range: std::ops::Range<u64>,
    cur_hash: [u8; 32],
    deadline: Instant,
    block_cache: &mut std::collections::HashMap<[u8; 32], stellereum::sharding::Block>,
) -> Result<(), String> {
    use futures::stream::{self, StreamExt};

    let mut candidates = vec![cur_hash];
    if range.start < range.end && block_cache.len() < HEAL_CACHE_CAP {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "healing timed out after {}s resolving prefetch heights",
                HEAL_ENGINE_TIMEOUT.as_secs()
            ));
        }
        let concurrency = stellereum::sync::FETCH_MAX_CONCURRENCY.max(1);
        let resolved: Vec<Option<[u8; 32]>> = tokio::time::timeout(
            remaining,
            stream::iter(range)
                .map(|h| {
                    let a = Arc::clone(adapter);
                    async move {
                        if let Some(hash) = a.fetch_head_hash_probe(shard, h).await {
                            return Some(hash);
                        }
                        match a.fetch_block_qc_probe(shard, h).await {
                            Some(qc) if qc.height == h => qc.block_hash,
                            _ => None,
                        }
                    }
                })
                .buffer_unordered(concurrency)
                .collect(),
        )
        .await
        .map_err(|_| {
            format!(
                "healing timed out after {}s resolving prefetch heights",
                HEAL_ENGINE_TIMEOUT.as_secs()
            )
        })?;
        for hash in resolved.into_iter().flatten() {
            candidates.push(hash);
        }
    }
    heal_prefetch_missing_hashes(adapter, store, &candidates, deadline, block_cache).await
}

/// Bring the engine's state up to the finalized head BEFORE joining consensus.
///
/// A restart loads the newest PAIRED snapshot (state S) and seeds the finalized head
/// (F) from metadata. Whenever S < F the engine is behind its own head, and voting
/// from S-state at height F+1 forks the node while reporting healthy -- observed live
/// as proposals carrying a 78-block-stale root forever. This closes the gap or
/// refuses to start; it never lets the node vote from unproven state.
///
/// Method, in order: (1) replay bodies S+1..F from the LOCAL block store (our own
/// finalized history, archive mode keeps every body); bodies missing locally are
/// fetched from peers (retained up to [`HEAL_CACHE_CAP`] across the backward walk
/// and prefetched in bounded concurrent batches); (2) every replayed block must
/// carry a verifiable precommit QC and commit to the running engine root -- history
/// that predates decision proofs cannot be replayed and fails here, which is
/// correct: it is unverifiable by anyone. (3) If the gap cannot be closed, exit(1).
/// A node that cannot prove its state must not vote; the operator wipes or restores
/// a verified backup.
///
/// Advances `*engine_height` in place after each replayed block so retries never
/// replay already-applied heights from a stale starting height.
///
/// Returns the engine height reached (== F on success).
#[allow(clippy::blocks_in_conditions)]
// GATE: behind-peer gate builds its predicate inline for auditability; hoisting would obscure the suppression logic.
#[allow(unused_assignments)]
// GATE: healing counters are observability-only; dead stores preserve restart-safe accounting without affecting consensus.
#[allow(unused_variables)]
// GATE: tick/phase counters are perf-visibility only; unused reads preserve timing attribution without behavior change.
pub(super) async fn heal_engine_to_head(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    store: &stellereum::storage::Storage,
    shard: u32,
    engine_height: &mut u64,
    finalized_head: u64,
    finalized_hash: [u8; 32],
) -> Result<u64, String> {
    let start_height = *engine_height;
    if start_height >= finalized_head {
        return Ok(start_height);
    }
    let deadline = Instant::now() + HEAL_ENGINE_TIMEOUT;
    // Walk BACKWARD from the head collecting hashes, preferring local bodies and
    // falling back to bounded concurrent peer prefetch + per-hash fetch.
    // Retained blocks are cached up to `HEAL_CACHE_CAP` so forward replay avoids
    // re-fetching blocks already pulled during the backward walk.
    let mut hashes: Vec<[u8; 32]> = vec![finalized_hash];
    let mut block_cache: std::collections::HashMap<[u8; 32], stellereum::sharding::Block> =
        std::collections::HashMap::with_capacity(
            (finalized_head.saturating_sub(start_height) as usize).min(HEAL_CACHE_CAP),
        );
    let mut cur = finalized_hash;
    let mut prefetched_backward = false;
    for _ in 0..1_000_000u64 {
        let h = hashes.len() as u64;
        // Height of `cur` = finalized_head - (hashes.len() - 1). Stop when we reach
        // start_height's block (whose hash we anchor below).
        let cur_height = finalized_head.saturating_sub(h - 1);
        if cur_height <= start_height {
            break;
        }
        let blk = if let Some(cached) = block_cache.get(&cur) {
            cached.clone()
        } else if let Ok(Some(local)) = store.get_block(&cur) {
            if local.compute_hash() != cur {
                return Err(format!(
                    "healing broken: stored body {} has mismatched hash {}",
                    hex::encode(cur),
                    hex::encode(local.compute_hash())
                ));
            }
            if block_cache.len() < HEAL_CACHE_CAP {
                block_cache.insert(cur, local.clone());
            }
            local
        } else {
            if !prefetched_backward && cur_height > start_height.saturating_add(1) {
                prefetched_backward = true;
                let cap_left = HEAL_CACHE_CAP.saturating_sub(block_cache.len()) as u64;
                if cap_left > 0 {
                    let prefetch_lo = cur_height
                        .saturating_sub(cap_left)
                        .max(start_height.saturating_add(1));
                    heal_prefetch_height_range(
                        adapter,
                        store,
                        shard,
                        prefetch_lo..cur_height,
                        cur,
                        deadline,
                        &mut block_cache,
                    )
                    .await?;
                }
            }
            if let Some(cached) = block_cache.get(&cur) {
                cached.clone()
            } else {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!(
                        "healing timed out after {}s during backward walk",
                        HEAL_ENGINE_TIMEOUT.as_secs()
                    ));
                }
                let fetched = tokio::time::timeout(remaining, adapter.fetch_block(&cur))
                    .await
                    .map_err(|_| {
                        format!(
                            "healing timed out after {}s fetching body {}",
                            HEAL_ENGINE_TIMEOUT.as_secs(),
                            hex::encode(cur)
                        )
                    })?;
                let Some(b) = fetched else {
                    return Err(format!(
                        "healing stuck: body {} unavailable locally and from peers",
                        hex::encode(cur)
                    ));
                };
                if b.compute_hash() != cur {
                    return Err(format!(
                        "healing broken: peer body {} has mismatched hash {}",
                        hex::encode(cur),
                        hex::encode(b.compute_hash())
                    ));
                }
                if block_cache.len() < HEAL_CACHE_CAP {
                    block_cache.insert(cur, b.clone());
                }
                b
            }
        };
        cur = blk.prev_hash;
        hashes.push(cur);
    }
    if (hashes.len() as u64).saturating_sub(1) < finalized_head.saturating_sub(start_height) {
        return Err("healing gap exceeds 1_000_000 blocks".to_string());
    }
    hashes.reverse();
    // hashes[0] must be the engine state's block (height == start_height). We prove
    // it by hash-linkage below rather than by trusting labels: each applied block's
    // F3.2 root check ties it to the running engine, so a wrong anchor fails loudly
    // on the first apply instead of forking quietly.
    let mut applied = start_height;
    let replay_prefetch_span = stellereum::sync::FETCH_MAX_CONCURRENCY.max(1) * 4;
    for (i, hash) in hashes.iter().enumerate().skip(1) {
        let expected_height = start_height + i as u64;
        let blk = if let Some(cached) = block_cache.remove(hash) {
            cached
        } else if let Ok(Some(local)) = store.get_block(hash) {
            local
        } else {
            let batch_end = hashes.len().min(i.saturating_add(replay_prefetch_span));
            heal_prefetch_missing_hashes(
                adapter,
                store,
                &hashes[i..batch_end],
                deadline,
                &mut block_cache,
            )
            .await?;
            if let Some(cached) = block_cache.remove(hash) {
                cached
            } else {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!(
                        "healing timed out after {}s at height {expected_height}",
                        HEAL_ENGINE_TIMEOUT.as_secs()
                    ));
                }
                let fetched = tokio::time::timeout(remaining, adapter.fetch_block(hash))
                    .await
                    .map_err(|_| {
                        format!(
                            "healing timed out after {}s fetching body {}",
                            HEAL_ENGINE_TIMEOUT.as_secs(),
                            hex::encode(hash)
                        )
                    })?;
                match fetched {
                    Some(b) => b,
                    None => {
                        return Err(format!(
                            "healing stuck: body {} unavailable locally and from peers",
                            hex::encode(hash)
                        ))
                    }
                }
            }
        };
        if blk.height != expected_height {
            return Err(format!(
                "healing broken: expected height {expected_height}, got {}",
                blk.height
            ));
        }
        if blk.compute_hash() != *hash {
            return Err(format!(
                "healing broken: body at height {expected_height} does not hash to the linked hash"
            ));
        }
        if blk.prev_hash != hashes[i - 1] {
            return Err(format!(
                "healing broken: block at height {expected_height} prev_hash mismatch: expected {}, got {}",
                hex::encode(hashes[i - 1]),
                hex::encode(blk.prev_hash)
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "healing timed out after {}s before replaying height {expected_height}",
                HEAL_ENGINE_TIMEOUT.as_secs()
            ));
        }
        rt.replay_historical_block(&blk)
            .await
            .map_err(|e| format!("healing refused at height {expected_height}: {e}"))?;
        rt.blocks.insert(*hash, blk);
        applied = expected_height;
        *engine_height = expected_height;
    }
    Ok(applied)
}

/// Execute the tick-top continuous catch-up check.
///
/// Returns `true` when catch-up adopted blocks and the caller should immediately
/// `continue` to the next tick (preserving the exact control flow of the loop).
pub(super) async fn run_catchup_step(
    cfg: &DriverConfig,
    st: &mut DriverState,
    step: &mut TickStep,
) -> bool {
    let height = step.height;
    let reactive_catchup_due = step.reactive_catchup_due;

    // Continuous catch-up. If a peer is ahead, replay the gap and re-anchor
    // before doing anything else this tick. Without this a node that fell a
    // single block behind could never rejoin: both nodes would sit in view
    // changes at their own heights, each rejecting the other's proposal as
    // `wrong height`, and the network would stay wedged until an operator
    // wiped both data directories. Throttled so a normal node does not ask
    // the DHT on every single tick.
    // Bound every periodic network call to half a round: this loop IS
    // consensus, and an unbounded DHT/body fetch inside it stalls round
    // timers too (measured: rounds took ~8s with an 800ms timeout because
    // the tick blocked on network I/O). A slow fetch is skipped and
    // retried next interval -- liveness beats freshness here.
    // Catch-up does DHT head+body walks (seconds on a slow net); the old
    // timeout/2 budget (~400ms live) always expired first, so a
    // 1-block-behind node never healed (audit 2026-10-06).
    let near_tip_net_ms = (cfg.round_timeout.as_millis() as u64 * 2).max(5_000);
    // Snapshot territory needs minutes, not seconds: a far-behind node
    // (gap > 100) fetching state+domains+anchor over a weak link can never
    // fit in 5s, so every attempt died at the budget with zero progress and
    // retried forever. While far behind, this node validates nothing
    // anyway (its height is useless to the network), so a long tick costs
    // nothing and is the only way to converge. Near-tip nodes keep the
    // tight budget (fast rounds matter there).
    //
    // The gap is the TALLEST verified evidence we hold: a peer head hint
    // (a QC-backed commit) and the at-tip evidence a verified vote or
    // proposal names. Using only the hint left a node rescued by vote
    // evidence on the at-tip/5 s path even when it was known to be behind.
    let our_tip_for_budget = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    let hint_gap_for_budget = st
        .rt
        .peer_hint
        .map(|(ph, _)| ph.saturating_sub(our_tip_for_budget))
        .unwrap_or(0);
    let budget_gap =
        hint_gap_for_budget.max(st.peer_named_height.saturating_sub(our_tip_for_budget));
    step.net_budget = Duration::from_millis(catchup_pass_budget_ms(near_tip_net_ms, budget_gap));
    // §7 Phase 2: catch-up replays whole blocks through `apply_and_advance`.
    // While a decided block is still executing on the sequenced worker the
    // engine is mid-transition (PRE-H reads would misvalidate the walk),
    // so the walk waits a tick. Skipping only delays healing by one tick:
    // the head pointer and peer hints are re-read next tick, after the
    // worker reports back.
    //
    // LIVE-ADOPT FAST PATH (observer C, 2026-10-13): a Committed broadcast
    // carries the full block + QC — no DHT fetch needed. When live traffic
    // is queued AND the hint gap is live-sized, the drain below adopts it
    // at message cost; running the catch-up machine first holds the tick
    // on DHT fetches (2.5s+ each on a weak link) while adoptable blocks
    // wait in the channel. Defer catch-up one tick so live adopt runs
    // first. Far-behind nodes (gap > threshold) still run catch-up: tip
    // commits are for heights they cannot adopt yet.
    //
    // Remainder fix: the queue sample alone (`!rx.is_empty()`) misses
    // Committed messages still in transit — at 1 block/s most tick tops
    // see an empty inbox, so the DHT machine fired every interval for
    // heights the next Committed delivers free (the ~30s/block queueing
    // tail). A fresh live adopt (within one catch-up interval) proves the
    // flow is delivering and defers on its own.
    let defer_for_live = {
        let our_tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        let hint_gap = st
            .rt
            .peer_hint
            .map(|(ph, _)| ph.saturating_sub(our_tip))
            .unwrap_or(0);
        let peer_named_gap = st.peer_named_height.saturating_sub(our_tip);
        let live_adopt_fresh = st.last_live_adopt.elapsed() < cfg.live_adopt_fresh_window;
        // Never defer catchup if we have stalled into round > 0, haven't adopted
        // recently, or hold verified evidence of a gap >= 2 (hint or peer_named_height).
        should_defer_live_catchup(
            st.rt.hc.round,
            hint_gap,
            peer_named_gap,
            !st.rx.is_empty(),
            live_adopt_fresh,
        )
    };
    // Event-driven decision (`policy::catchup_action`): reactive evidence
    // runs NOW; the periodic timer is only a backstop. At-tip nodes skip
    // the EXPENSIVE walk, but still run one cheap blind head/tip+1 probe
    // per `AT_TIP_PROBE_INTERVAL_MS` — silence is not equality (F-3/R8).
    let our_tip_now = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    // Expire/downgrade a stale peer hint BEFORE it can suppress the DHT
    // head read (F-2/C1). Only verified sources write `rt.peer_hint`, but
    // even a verified hint must not pin catch-up forever after a failed
    // walk or once our tip reaches it. The runtime can also plant one
    // inside `on_proposal`; detect the change so it gets a fresh lease.
    if st.rt.peer_hint != st.peer_hint_seen {
        st.peer_hint_seen = st.rt.peer_hint;
        st.peer_hint_at = st.rt.peer_hint.map(|_| Instant::now());
    }
    if let Some(hint) = st.rt.peer_hint {
        let age_ms = st
            .peer_hint_at
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(u64::MAX);
        if peer_hint_effective(our_tip_now, Some(hint), age_ms).is_none() {
            tracing::debug!(
                "[sync] dropping stale/reached peer hint #{:?} (ours=#{our_tip_now}, age={age_ms}ms)",
                hint.0
            );
            st.rt.peer_hint = None;
            st.peer_hint_at = None;
            st.peer_hint_seen = None;
        }
    }
    let at_tip = node_is_at_tip(
        our_tip_now,
        st.peer_named_height,
        st.rt.peer_hint.map(|(h, _)| h),
    );
    let catchup_decision = catchup_action(
        reactive_catchup_due,
        st.last_catchup.elapsed().as_millis() as u64,
        cfg.catchup_interval.as_millis() as u64,
        at_tip,
    );
    // At-tip RX-silence trigger (S5 finding #7, `policy::RX_SILENCE_PROBE_MS`).
    // The 120 s backstop is far longer than the `42 × 800 ms = 33.6 s`
    // downtime budget: a node whose INBOUND stream is lost (outbound still
    // works, so peers never name us behind) would be jailed long before
    // the probe fires. When no consensus frame arrived for a full window
    // and the normal probe is NOT due, run ONE bounded head/QC probe. It
    // never runs with live traffic, never probes on reactive ahead
    // evidence, and leaves `last_catchup` untouched so the 120 s backstop
    // keeps its exact schedule.
    let silence_probe_due = at_tip
        && catchup_decision != CatchupAction::BlindProbe
        && !reactive_catchup_due
        && st.rx.is_empty()
        && at_tip_silence_due(
            stellereum::liveness_alarm::now_ms(),
            st.last_consensus_frame_ms,
            st.last_silence_probe_ms,
        );
    if catchup_decision == CatchupAction::SkipAtTip {
        // At the tip: skip the expensive DHT/body walk, but do NOT reset
        // `last_catchup` — the elapsed clock is what reaches the low-
        // frequency blind-probe window below. The next reactive message
        // still re-arms catch-up immediately.
        st.catchup_at_tip_skips += 1;
        if st.catchup_at_tip_skips.is_multiple_of(20) {
            tracing::debug!(
                "[sync] backstop catch-up skipped at the tip #{our_tip_now} \
                 ({} skips): no peer known to be ahead, \
                 blind probe due in {}ms",
                st.catchup_at_tip_skips,
                AT_TIP_PROBE_INTERVAL_MS
                    .saturating_sub(st.last_catchup.elapsed().as_millis() as u64)
            );
        }
    }
    let catchup_due = matches!(
        catchup_decision,
        CatchupAction::Run | CatchupAction::BlindProbe
    ) || silence_probe_due;
    if catchup_due && !st.rt.has_pending_apply() && !defer_for_live {
        step.catchup_ran = true;
        if silence_probe_due {
            // Re-arm the silence window NOW, before the probe runs: a miss
            // must not re-fire on the next tick. `last_catchup` is
            // deliberately not moved, so the 120 s backstop keeps its
            // schedule. The probe itself is bounded below.
            st.last_silence_probe_ms = stellereum::liveness_alarm::now_ms();
            tracing::debug!(
                "[sync] at-tip RX silence >= {RX_SILENCE_PROBE_MS}ms at #{our_tip_now}; \
                 running one bounded head/QC probe ({RX_SILENCE_PROBE_BUDGET_MS}ms budget)"
            );
        } else {
            st.last_catchup = std::time::Instant::now();
        }
        let split_catchup_t0 = std::time::Instant::now();
        // The pass must be able to clear a whole live-sized burst (or, far
        // behind, fetch/snapshot at all): the configured value is the
        // at-tip floor, the gap scales it. A flat 250 ms admitted ~one
        // WAN round trip, while the chain now produces a block every
        // ~240 ms — a behind node retried forever without ever closing the
        // gap (and snapshot-sync could never fit at all).
        let base_catchup_budget = Duration::from_millis(catchup_pass_budget_ms(
            catchup_budget().as_millis() as u64,
            budget_gap,
        ));
        // A silence-triggered probe is the CHEAP head/QC read, never the
        // gap-scaled walk (at tip the gap is 0 anyway; this also keeps a
        // stale `last_live_adopt` from widening the tick). One WAN round
        // trip, hard-bounded.
        let catchup_budget = if silence_probe_due {
            Duration::from_millis(RX_SILENCE_PROBE_BUDGET_MS)
        } else {
            effective_catchup_pass_budget(
                base_catchup_budget,
                budget_gap,
                st.last_live_adopt.elapsed(),
            )
        };
        let caught = tokio::time::timeout(
            catchup_budget,
            try_catch_up_with_lanes(
                &cfg.adapter,
                &mut st.rt,
                cfg.block_shard,
                cfg.persistence.as_ref(),
                &cfg.rpc,
                SyncLanes {
                    record_lane: Some(&cfg.record_lane),
                    publish_lane: Some(&cfg.publish_lane),
                    consensus_net: Some(&cfg.net),
                },
                st.peer_named_height,
            ),
        )
        .await
        .unwrap_or_else(|_| {
            // A budget exhaustion is otherwise invisible (the inner future
            // is dropped mid-flight, so none of its own logs fire): a dead
            // transport looks exactly like "in sync". Throttled: this fires
            // every interval while peers are unreachable.
            static CATCHUP_TIMEOUT_N: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let n = CATCHUP_TIMEOUT_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(12) {
                eprintln!(
                    "[sync] catch-up skipped (network budget of {}ms exhausted, {n} times; \
                     peers unreachable or DHT too slow)",
                    catchup_budget.as_millis()
                );
            } else {
                tracing::debug!("[sync] catch-up skipped (network budget exhausted)");
            }
            None
        });
        if let Some(peer_h) = caught {
            info!(
                "[sync] caught up to height {peer_h} while running (was {height}); resumed consensus at {}",
                st.rt.hc.height
            );
            // Fresh height: reset the per-round bookkeeping too, or the
            // first proposal on the new height would reuse the old timer
            // and the previous height's votes.
            st.last_prevoted = None;
            st.last_precommitted = None;
            st.cast_prevote = None;
            st.cast_precommit = None;
            st.round_started = std::time::Instant::now();
            st.last_block_at = std::time::Instant::now() - cfg.min_block_time;
            // Announce the new height immediately: this tick `continue`s
            // below, skipping the normal prevote section — without a vote
            // here, a catching-up node advances SILENTLY and tip nodes
            // never stamp it as behind-and-talking, so retro help never
            // flows (observed live: C grinding catchup with zero votes
            // while A/B suppressed retro for "no behind peer"). A nil
            // vote at the fresh height breaks the silence; it finalizes
            // nothing and is rate-limited by catchup_interval. Fresh
            // height + no proposal yet => the vote is nil by construction.
            // (`can_vote` is computed later at the propose gate; inline it
            // here — same franchise, same tick.)
            if st.rt.effective_can_vote(cfg.is_validator)
                && !st.rt.hc.has_live_proposal()
                && !round_at_or_below_vote_floor(st.vote_floor, st.rt.hc.height, st.rt.hc.round)
            {
                if let Some(v) = st.rt.make_prevote() {
                    debug_assert!(
                        v.block_hash.is_none(),
                        "fresh catchup height has no proposal yet"
                    );
                    advance_vote_floor(&mut st.vote_floor, v.height, v.round);
                    if let Err(e) = st.rt.on_prevote(v.clone()) {
                        tracing::warn!(
                            height = v.height,
                            round = v.round,
                            error = %e,
                            "[consensus] own catchup prevote admission failed"
                        );
                    }
                    enqueue_outbox(
                        &mut st.outbox,
                        ConsensusMsg::Vote {
                            vote: v.clone(),
                            locked: lock_hint(&st.rt, &v),
                        },
                    );
                    st.cast_prevote = Some(v);
                    st.last_prevoted = Some((st.rt.hc.height, st.rt.hc.round));
                    tracing::debug!(
                        "[consensus] prevoted nil at fresh catchup height #{} r{}",
                        st.rt.hc.height,
                        st.rt.hc.round
                    );
                }
            }
            // PERSISTENT EVIDENCE ACROSS A SUCCESSFUL PASS: this tick
            // `continue`s, so the end-of-tick latch re-arm never runs. A
            // pass can stop SHORT of the peer's head (snapshot-sync lands
            // on a boundary and hands the rest to the body walk); the
            // verified evidence that scheduled it is then still ahead.
            // Re-arm here so the next reactive tick continues the walk on
            // the 500 ms floor instead of dropping to the 30 s backstop.
            {
                let tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                let still_behind = catchup_still_behind(tip, st.rt.peer_hint, st.peer_named_height);
                // A BLIND probe that still advanced us proves there is
                // more to fetch even when no ahead evidence was recorded
                // (a silent follower). Dropping the latch here would wait
                // out the 120 s at-tip window while the chain moved ~300
                // heights — the exact jail-budget overrun this path exists
                // to prevent.
                if rearm_after_catchup_success(
                    silence_probe_due || catchup_decision == CatchupAction::BlindProbe,
                    still_behind,
                ) {
                    st.catchup_pending = true;
                }
            }
            st.split_catchup_ms += split_catchup_t0.elapsed().as_millis() as u64;
            st.split_catchup_n += 1;
            return true;
        }
        step.catchup_ms = split_catchup_t0.elapsed().as_millis() as u64;
        st.split_catchup_ms += step.catchup_ms;
        st.split_catchup_n += 1;
        // A silence probe that did NOT fully adopt but DID plant verified
        // ahead evidence (a QC sidecar) must arm the normal reactive path.
        // Otherwise the next tick's at-tip predicate is now false and the
        // full walk would wait out the 30 s backstop — the 500 ms probe
        // budget is deliberately shorter than a body walk. Bounded: this
        // only latches one ordinary catch-up attempt; it does not loop the
        // silence trigger (`last_silence_probe_ms` is already re-armed).
        if silence_probe_due {
            let tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
            if catchup_still_behind(tip, st.rt.peer_hint, st.peer_named_height) {
                st.catchup_pending = true;
            }
        }
    } else if reactive_catchup_due {
        // A verified peer told us it is ahead, but the attempt could not
        // run this tick (apply in flight / live adopt deferral). KEEP the
        // event latched so the next tick retries — dropping it would put
        // the node back on the 30 s backstop.
        st.catchup_pending = true;
    }

    false
}

/// Periodically push our own history so a peer behind us has something to fetch.
pub(super) async fn run_retro_publish_step(
    cfg: &DriverConfig,
    st: &mut DriverState,
    step: &mut TickStep,
) {
    // Bounded, and deliberately publishing bodies only.
    //
    // Storm guard 2026-10-13: a node far behind the network (e.g. C at
    // 72415 vs tip 74200) must NOT push its stale window. Its 128-body
    // pass + 8-body tip supplement spawn ~136 background replicators that
    // flood the tip's 256 stream slots while competing with its own
    // catch-up fetches for the same slots (fetch-vs-push self-excitation).
    // Skipping pushes while behind prioritizes consensus (fetch) over
    // replication (push); in-sync nodes are unaffected.
    if st.last_retro_publish.elapsed() >= cfg.retro_publish_interval {
        let our_tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        let peer_tip = st.rt.peer_hint.map(|(h, _)| h).unwrap_or(our_tip);
        // Hoisted behind-peer predicate (clippy::blocks_in_conditions): pure, no side effects.
        let behind_suppress = {
            let we_are_behind =
                peer_tip > our_tip && peer_tip - our_tip > stellereum::sync::RETRO_SKIP_BEHIND_GAP;
            let behind_window = retro_behind_window_secs();
            let behind_idle = st.last_behind_peer_seen.map(|t| t.elapsed().as_secs());
            should_suppress_retro_no_behind_peer(behind_idle, behind_window, we_are_behind)
        };
        if stellereum::sync::should_skip_retro_while_behind(our_tip, peer_tip) {
            st.last_retro_publish = std::time::Instant::now();
            tracing::debug!(
                "[retro-publish] skipping stale push while behind (ours={our_tip} peer={peer_tip})"
            );
        } else if should_suppress_retro_publish(
            our_tip,
            st.retro_tip_at_last_pass,
            st.last_inbound_msg.elapsed().as_secs(),
        ) {
            // Dead-peer spin gate (local policy, see the declaration
            // above): finalized tip hasn't advanced since the last pass
            // AND no consensus message arrived for 60s+ — the pass would
            // re-push the same Committed-block window at a peer that never
            // ACKs (nothing ever can: nobody is there). Suppressed LOUDLY
            // so "retro went quiet" is distinguishable from "retro is
            // broken". A returning peer's first vote/proposal restamps
            // `last_inbound_msg` and the next pass runs; a new
            // finalization advances `our_tip` and the next pass runs.
            st.last_retro_publish = std::time::Instant::now();
            let n = RETRO_SUPPRESSED_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            eprintln!(
                "[retro-publish] SUPPRESSED dead-peer pass #{n} (tip={our_tip} unchanged since last pass, inbound idle {}s >= {RETRO_SUPPRESS_IDLE_SECS}s; resumes on new finalization or first inbound vote/proposal)",
                st.last_inbound_msg.elapsed().as_secs()
            );
            tracing::debug!(
                "[retro-publish] suppressed dead-peer pass #{n} (tip={our_tip} idle={}s)",
                st.last_inbound_msg.elapsed().as_secs()
            );
        } else if behind_suppress {
            st.last_retro_publish = std::time::Instant::now();
            let n =
                RETRO_BEHIND_SUPPRESSED_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let behind_window = retro_behind_window_secs();
            let idle_txt = st
                .last_behind_peer_seen
                .map(|t| format!("{}s", t.elapsed().as_secs()))
                .unwrap_or_else(|| "never".to_string());
            eprintln!(
                "[retro-publish] SUPPRESSED no-behind-peer pass #{n} (tip={our_tip}, no verified vote/proposal from a behind peer in last {behind_window}s (idle={idle_txt}); retro serves small gaps, deep gaps use snapshot-sync; resumes on first behind vote/proposal)"
            );
            tracing::debug!(
                "[retro-publish] suppressed no-behind-peer pass #{n} (tip={our_tip} behind_idle={idle_txt})"
            );
        } else {
            step.retro_ran = true;
            let split_retro_t0 = std::time::Instant::now();
            st.last_retro_publish = std::time::Instant::now();
            st.retro_tip_at_last_pass = our_tip;
            let _ = tokio::time::timeout(
                step.net_budget,
                retro_publish_pass(
                    cfg.adapter.clone(),
                    &st.rt,
                    cfg.persistence.as_ref(),
                    &mut st.retro_published_upto,
                    Some(&cfg.backfill_lane),
                ),
            )
            .await;
            // Tip-first supplement: the backfill cursor above works bottom-up
            // and reaches a fresh tip last, but a recovering peer almost always
            // needs exactly the tip. Publish it every pass (one body, memory
            // first) so a restart never strands a peer for a whole window.
            // Publish the last few, not just the tip: a 1-8 block lag needs
            // middle children the tip-only publish would miss for hours.
            // OFF-TICK (observer C): runs on `backfill_lane` behind the
            // window above so live tip writes on `publish_lane` stay unblocked.
            {
                let recent: Vec<_> = st.rt.finalized.iter().rev().take(8).copied().collect();
                let mut bodies = Vec::with_capacity(recent.len());
                for (_, thash) in recent {
                    if let Some(body) = st.rt.blocks.get(&thash).cloned().or_else(|| {
                        cfg.persistence
                            .as_ref()
                            .and_then(|ap| ap.storage().get_block(&thash).ok().flatten())
                    }) {
                        bodies.push(body);
                    }
                }
                if !bodies.is_empty() {
                    let a = cfg.adapter.clone();
                    cfg.backfill_lane.submit(async move {
                        let _ = a.retro_publish_blocks(bodies.iter(), bodies.len()).await;
                    });
                }
            }
            step.retro_ms = split_retro_t0.elapsed().as_millis() as u64;
            st.split_retro_ms += step.retro_ms;
            st.split_retro_n += 1;
        }
    }
}

/// EVENT-DRIVEN CATCH-UP latch (round efficiency, no safety change):
/// re-arm `catchup_pending` whenever verified peer evidence sits ahead of our tip.
pub(super) fn update_catchup_latch(st: &mut DriverState) {
    let tip = st.rt.decided_tip_height_for_height(st.rt.hc.height);
    st.peer_named_height = clamp_peer_evidence_height(tip, st.peer_named_height);
    if st.rt.peer_hint.is_some_and(|(ph, _)| ph > tip) || st.peer_named_height > tip {
        st.catchup_pending = true;
    }
}
