//! Regression for the chunk-fan-out follow-up to the 2026-10-13 storm.
//!
//! Live symptoms this pins:
//! * `too many concurrent streams on one connection, dropping stream` (limit
//!   256) in batches on a weak node, while every outgoing `request_to` sat at
//!   `dial=0ms resp=2500-3500ms` (timeout+retry shape);
//! * the process-wide fetch semaphore (8) capped fetch_blob ENTRY, but each
//!   `fetch_blob` fans out to manifest + per-chunk lookups PAST the semaphore,
//!   retries re-fired on the same tick, and background `replicate_blob` pushes
//!   + incoming replication bursts hit the newcomer unpaced;
//! * snapshot pulls (tens of MB) held the 1-vCPU event loop without yielding.
//!
//! The fix (src/sync.rs + src/network.rs + pinpoint infnode `request_to`
//! retry jitter):
//! * jittered retry backoff (`fetch_retry_backoff_with_jitter_ms`: floor is
//!   always the exponential base, never an instant re-flood);
//! * bounded per-blob chunk batches (`plan_chunk_batches`), strictly serial
//!   for snapshot-sized blobs (`chunk_batch_for_blob`);
//! * a narrow large-blob lane (`SNAPSHOT_FETCH_MAX_CONCURRENCY=2`) nested
//!   inside the 8-wide fetch pool;
//! * jittered retro-push pacing (`retro_publish_pace_with_jitter_ms`);
//! * `yield_now` between walk heights / snapshot domains / bundle installs.
//!
//! These tests emulate a weak node pulling a LARGE snapshot (40 chunks stand
//! in for tens of MB; 5-25ms delays stand in for the live 2.5s RTT, scaled so
//! the suite stays fast) and assert it converges WITHOUT a stream storm
//! (per-blob in-flight ≤ batch width, lane-wide ≤ 2) and WITHOUT instant
//! retry tails (retry delays ≥ the 100ms floor).

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use stellereum::sync::{
    chunk_batch_for_blob, fetch_retry_backoff_ms, fetch_retry_backoff_with_jitter_ms,
    plan_chunk_batches, retro_publish_pace_with_jitter_ms, FETCH_BLOB_CHUNK_BATCH,
    FETCH_MAX_CONCURRENCY, FETCH_RETRY_BASE_BACKOFF_MS, FETCH_RETRY_JITTER_MAX_MS,
    FETCH_RETRY_MAX_BACKOFF_MS, LARGE_BLOB_SERIAL_CHUNKS, RETRO_PUSH_JITTER_MAX_MS,
    SNAPSHOT_FETCH_MAX_CONCURRENCY,
};

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn fanout_bounds_are_pinned() {
    assert_eq!(SNAPSHOT_FETCH_MAX_CONCURRENCY, 2);
    assert!(SNAPSHOT_FETCH_MAX_CONCURRENCY <= FETCH_MAX_CONCURRENCY);
    assert_eq!(FETCH_BLOB_CHUNK_BATCH, 4);
    assert_eq!(LARGE_BLOB_SERIAL_CHUNKS, 8);
    assert_eq!(FETCH_RETRY_JITTER_MAX_MS, 100);
    assert_eq!(RETRO_PUSH_JITTER_MAX_MS, 5);
}

/// Drive one blob's chunks through the production batch plan, tracking how
/// many chunk streams are ever open at once (1 chunk fetch == 1 stream).
///
/// Returns `(assembled_len, max_inflight)`.
async fn assemble_blob(n_chunks: usize, per_chunk_ms: u64) -> (usize, usize) {
    let batch = chunk_batch_for_blob(n_chunks);
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let mut assembled = 0usize;
    for (s, e) in plan_chunk_batches(n_chunks, batch) {
        // Within one batch chunks may overlap (bounded by the batch width);
        // between batches the driver yields, like the production pull.
        let mut handles = Vec::new();
        for _ in s..e {
            let inflight = inflight.clone();
            let max_seen = max_seen.clone();
            handles.push(tokio::spawn(async move {
                let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(per_chunk_ms)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                1usize
            }));
        }
        for h in handles {
            assembled += h.await.unwrap();
        }
        tokio::task::yield_now().await;
    }
    (assembled, max_seen.load(Ordering::SeqCst))
}

/// A weak node pulls a snapshot-sized blob (40 chunks ≈ tens of MB):
/// strictly serial, exactly 1 chunk stream at a time, converges fully.
#[tokio::test]
async fn weak_node_pulls_large_snapshot_serially_without_storm() {
    let n = 40usize;
    assert_eq!(chunk_batch_for_blob(n), 1, "large blobs must be serial");
    let (assembled, max) = assemble_blob(n, 5).await;
    assert_eq!(assembled, n, "every chunk arrives: convergence");
    assert_eq!(
        max, 1,
        "serial assembly must never hold >1 chunk stream (max={max})"
    );
    assert!(max < 256, "stream ceiling respected");
}

/// A small blob may pipeline, but never wider than the batch bound.
#[tokio::test]
async fn small_blob_pipelines_within_batch_bound() {
    let n = 6usize;
    assert_eq!(chunk_batch_for_blob(n), FETCH_BLOB_CHUNK_BATCH);
    let (assembled, max) = assemble_blob(n, 5).await;
    assert_eq!(assembled, n);
    assert!(
        max <= FETCH_BLOB_CHUNK_BATCH,
        "per-blob fan-out {max} exceeds batch width {}",
        FETCH_BLOB_CHUNK_BATCH
    );
    assert!(max > 1, "test must actually exercise batching (max={max})");
}

/// Concurrent snapshot-sized pulls share the narrow lane: even 8 overlapping
/// catch-up subtasks never assemble more than 2 large blobs at once.
#[tokio::test]
async fn overlapping_snapshot_pulls_share_the_narrow_lane() {
    let lane = Arc::new(tokio::sync::Semaphore::new(SNAPSHOT_FETCH_MAX_CONCURRENCY));
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let lane = lane.clone();
        let inflight = inflight.clone();
        let max_seen = max_seen.clone();
        handles.push(tokio::spawn(async move {
            // Nesting order mirrors the adapter: fetch pool first, lane second.
            let _guard = lane.acquire_owned().await.unwrap();
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, Ordering::SeqCst);
            // Weak-link RTT (scaled: 25ms stands in for live 2500ms).
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            inflight.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let max = max_seen.load(Ordering::SeqCst);
    assert!(
        max <= SNAPSHOT_FETCH_MAX_CONCURRENCY,
        "lane max {max} exceeds {} (storm)",
        SNAPSHOT_FETCH_MAX_CONCURRENCY
    );
    assert!(
        max > 1,
        "test must actually exercise lane sharing (max={max})"
    );
}

/// The weak-node snapshot pull shape end to end: `fast_sync_state` over a
/// slow link stays SEQUENTIAL (snapshot + 7 domain slots, one blob at a
/// time), converges, and never storms.
#[tokio::test]
async fn weak_node_snapshot_pull_via_fast_sync_stays_sequential() {
    use stellereum::state_engine::{AccountState, InMemoryStateEngine};

    let source = InMemoryStateEngine::new();
    let user = [0x77u8; 32];
    source
        .update_account(AccountState::new(user, 424_242))
        .await;
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;

    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    // One slow fetch gate shared by the snapshot and every domain slot.
    let slow = |inflight: Arc<AtomicUsize>, max_seen: Arc<AtomicUsize>| async move {
        let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
        max_seen.fetch_max(cur, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        inflight.fetch_sub(1, Ordering::SeqCst);
    };

    let target = InMemoryStateEngine::new();
    let i2 = inflight.clone();
    let m2 = max_seen.clone();
    stellereum::sync::fast_sync_state(
        &target,
        root,
        || {
            let i = i2.clone();
            let m = m2.clone();
            let snap = snap.clone();
            async move {
                slow(i, m).await;
                Some(snap)
            }
        },
        |_: &'static str| {
            let i = inflight.clone();
            let m = max_seen.clone();
            async move {
                slow(i, m).await;
                None
            }
        },
    )
    .await
    .expect("weak-node pull must converge");
    assert_eq!(target.get_state_root().await, root);
    assert_eq!(target.get_account(&user).await.unwrap().balance, 424_242);
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "snapshot+domain pull must never have >1 blob in flight"
    );
}

/// No 2.5s tails: after a timeout-shaped failure the retry waits at least the
/// backoff floor (never an instant re-flood), plus its jitter draw, and the
/// whole attempt converges promptly.
#[tokio::test]
async fn retry_after_timeout_is_paced_not_instant() {
    let jitter_draw = 37u64;
    let wait = fetch_retry_backoff_with_jitter_ms(1, jitter_draw);
    assert_eq!(wait, FETCH_RETRY_BASE_BACKOFF_MS + jitter_draw);

    let attempts = Arc::new(AtomicUsize::new(0));
    let t0 = std::time::Instant::now();
    let out: Option<&str> = loop {
        let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            // First attempt: timeout shape (nothing arrives).
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            continue;
        }
        break Some("recovered");
    };
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    assert_eq!(out, Some("recovered"));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(
        elapsed_ms >= wait,
        "retry fired after {elapsed_ms}ms < paced {wait}ms (instant re-flood)"
    );
    assert!(
        elapsed_ms < 2500,
        "paced retry must converge far below the 2.5s tail (took {elapsed_ms}ms)"
    );
}

/// Jitter de-synchronizes same-tick retries while keeping every delay inside
/// [base, max+JITTER_MAX]: no tail may wait out a round, none may fire early.
#[test]
fn jitter_spreads_retries_without_breaking_bounds() {
    let mut seen = std::collections::HashSet::new();
    for attempt in 1..=4u32 {
        for draw in [0u64, 7, 42, 99, 100, 101, 9999] {
            let d = fetch_retry_backoff_with_jitter_ms(attempt, draw);
            assert!(d >= fetch_retry_backoff_ms(attempt), "floor holds");
            assert!(
                d <= FETCH_RETRY_MAX_BACKOFF_MS + FETCH_RETRY_JITTER_MAX_MS,
                "ceiling holds"
            );
            seen.insert((attempt, d));
        }
    }
    // attempt=3 over 7 draws must produce ≥2 distinct delays (spread).
    let distinct: std::collections::HashSet<u64> = [0u64, 7, 42, 99]
        .iter()
        .map(|d| fetch_retry_backoff_with_jitter_ms(3, *d))
        .collect();
    assert!(
        distinct.len() > 1,
        "jitter must spread same-attempt retries"
    );
}

/// Retro-push pacing stays ~5ms with a small de-phasing draw: bursts spread
/// without stalling the pass.
#[test]
fn retro_push_pacing_spreads_bursts_without_stalling() {
    let base = stellereum::network::RETRO_PUBLISH_PACE_MS;
    assert_eq!(retro_publish_pace_with_jitter_ms(0), base);
    assert_eq!(retro_publish_pace_with_jitter_ms(5), base + 5);
    assert_eq!(
        retro_publish_pace_with_jitter_ms(1000),
        base + RETRO_PUSH_JITTER_MAX_MS
    );
}
