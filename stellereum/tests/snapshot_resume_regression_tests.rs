//! Regression for the weak-link snapshot death (observer, 1vCPU/60%).
//!
//! Live symptoms pinned here:
//! * `try_snapshot_sync` found boundaries, but `fetch_state_snapshot` /
//!   `fetch_domain_snapshot` (tens of MB in ONE blob, ~50 chunks) always
//!   returned `None` — chunk-assembly timeouts/breaks — while small fetches
//!   (headers, ~320KB bodies, 1 chunk) sailed through;
//! * the old path (`fetch_blob`: serial `got?` over chunks) aborted the WHOLE
//!   blob on the FIRST missing chunk — one drop under jitter restarted tens
//!   of MB from zero, so a 50-chunk snapshot with a 5%-drop link failed ~92%
//!   of attempts and the node sat ~1500 behind forever with a silent `None`.
//!
//! The fix (src/sync.rs + src/network.rs):
//! * per-chunk resume (`assemble_chunks_resumable`): a dropped chunk retries
//!   JUST that chunk; completed chunks are never re-ordered (serial shape and
//!   both semaphores untouched);
//! * generous snapshot-only budgets (tens of MB is normal, not an anomaly):
//!   20s per chunk attempt, 6 retries/chunk, 15s manifest budget separate from
//!   chunk bodies, 300s per-blob cap;
//! * every `None` is loud (size / chunk index / attempts / timeout);
//! * `yield_now` after every chunk and every backoff so the tick never hangs.
//!
//! These tests drive the PRODUCTION assembler (`assemble_chunks_resumable`)
//! through a simulated weak link (jitter + drops, scaled to ms so the suite
//! stays fast) and assert a 50MB snapshot converges in a bounded number of
//! chunk fetches, resume never re-orders ready chunks, and permanent failure
//! names the dead chunk instead of a silent `None`.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use stellereum::sync::{
    assemble_chunks_resumable, snapshot_blob_budget_ms, SNAPSHOT_BLOB_ATTEMPTS,
    SNAPSHOT_BLOB_TIMEOUT_MS, SNAPSHOT_CHUNK_RETRIES, SNAPSHOT_CHUNK_TIMEOUT_MS,
    SNAPSHOT_MANIFEST_TIMEOUT_MS,
};

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn snapshot_budgets_are_generous_and_manifest_has_its_own() {
    // Tens of MB is the NORMAL snapshot size: per-chunk budget must dwarf the
    // small-fetch (~5s) window, or every slow chunk becomes a whole-blob miss.
    assert!(
        SNAPSHOT_CHUNK_TIMEOUT_MS >= 15_000,
        "per-chunk timeout {SNAPSHOT_CHUNK_TIMEOUT_MS}ms is not generous for a weak link"
    );
    assert!(
        SNAPSHOT_CHUNK_RETRIES >= 4,
        "per-chunk retries {} cannot survive a 20%-drop link",
        SNAPSHOT_CHUNK_RETRIES
    );
    // Manifest (one small KV lookup) has a SEPARATE, smaller budget than chunk
    // bodies: an unpublished boundary must fail fast, not burn megabytes.
    assert!(SNAPSHOT_MANIFEST_TIMEOUT_MS > 0);
    assert!(
        SNAPSHOT_MANIFEST_TIMEOUT_MS <= SNAPSHOT_CHUNK_TIMEOUT_MS,
        "manifest budget {}ms must not exceed the chunk budget {}ms",
        SNAPSHOT_MANIFEST_TIMEOUT_MS,
        SNAPSHOT_CHUNK_TIMEOUT_MS
    );
    assert!(
        SNAPSHOT_BLOB_TIMEOUT_MS >= 120_000,
        "per-blob budget {}ms cannot cover 50 serial chunks at 2.5s RTT",
        SNAPSHOT_BLOB_TIMEOUT_MS
    );
    assert!(
        (1..=5).contains(&SNAPSHOT_BLOB_ATTEMPTS),
        "blob attempts {} must be bounded (never infinite None-retries)",
        SNAPSHOT_BLOB_ATTEMPTS
    );
}

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn snapshot_blob_budget_scales_with_size_and_is_capped() {
    // Floor: even a 1-chunk blob gets a sane minimum, never ~0.
    assert!(snapshot_blob_budget_ms(0) >= 60_000);
    assert!(snapshot_blob_budget_ms(1) >= 60_000);
    // Monotonic: more chunks (more MB) get more budget — size is normal.
    assert!(snapshot_blob_budget_ms(50) > snapshot_blob_budget_ms(8));
    assert!(snapshot_blob_budget_ms(8) > snapshot_blob_budget_ms(1));
    // Capped: a huge blob cannot wedge the tick forever.
    assert_eq!(
        snapshot_blob_budget_ms(usize::MAX),
        SNAPSHOT_BLOB_TIMEOUT_MS
    );
    assert_eq!(snapshot_blob_budget_ms(10_000), SNAPSHOT_BLOB_TIMEOUT_MS);
    // A 50-chunk (~50MB) snapshot budget covers serial 2.5s-RTT movement
    // (~125s) with headroom, inside the cap.
    let b50 = snapshot_blob_budget_ms(50);
    assert!(
        (120_000..=SNAPSHOT_BLOB_TIMEOUT_MS).contains(&b50),
        "50-chunk budget {b50}ms"
    );
}

/// Weak link pulls a 50MB snapshot (50 × 1MB chunks, 20% drops + jitter) to
/// completion WITHOUT a permanent `None`, in a bounded number of fetches.
///
/// Shape under test is the production one: strictly serial, resume keeps
/// ready chunks, retries only miss. Delays are scaled (0-3ms stand in for the
/// live 70-300ms/2.5s RTT) so the suite stays fast; the drop rate is live-grade.
#[tokio::test]
async fn weak_link_pulls_50mb_snapshot_to_completion_with_resume() {
    const N: usize = 50; // 50 chunks ≈ 50MB snapshot
    const CHUNK: usize = 1024 * 1024;
    let expected: Vec<Vec<u8>> = (0..N).map(|i| vec![(i & 0xFF) as u8; CHUNK]).collect();

    let total_calls = Arc::new(AtomicUsize::new(0));
    // Deterministic weak link: LCG, 20% drops, 0..=3ms jitter per attempt.
    let state = Arc::new(std::sync::Mutex::new(0x9E3779B97F4A7C15u64));
    let next_rand = |st: &Arc<std::sync::Mutex<u64>>| {
        let mut g = st.lock().unwrap();
        *g = g
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *g >> 33
    };

    let out = assemble_chunks_resumable(N, SNAPSHOT_CHUNK_RETRIES, |i| {
        let expected = expected.clone();
        let total_calls = total_calls.clone();
        let state = state.clone();
        async move {
            total_calls.fetch_add(1, Ordering::SeqCst);
            let r = next_rand(&state);
            // Jitter: 0..=3ms stand-in for live RTT jitter.
            tokio::time::sleep(std::time::Duration::from_millis(r % 4)).await;
            // Drop: ~20% of attempts never arrive (timeout/break shape).
            if r % 5 == 0 {
                tokio::task::yield_now().await;
                return None;
            }
            tokio::task::yield_now().await;
            Some(expected[i].clone())
        }
    })
    .await
    .expect("weak link with per-chunk resume must converge, never a permanent None");

    assert_eq!(out.len(), N);
    for (i, got) in out.iter().enumerate() {
        assert_eq!(got.len(), CHUNK, "chunk {i} must arrive whole");
        assert_eq!(*got, expected[i], "chunk {i} bytes must be exact");
    }
    // Bounded work: 20% drops need ~1.25x fetches on average; 3x is generous
    // headroom, while the OLD whole-blob restart needed unbounded attempts
    // (0.8^50 ≈ 1.4% success per attempt → ~70 whole-blob retries on average).
    let calls = total_calls.load(Ordering::SeqCst);
    assert!(
        calls <= N * 3,
        "resume converged in {calls} chunk fetches for {N} chunks (must be ≤ {})",
        N * 3
    );
    assert!(
        calls >= N,
        "every chunk must be fetched at least once (calls={calls})"
    );
}

/// Resume never re-orders ready chunks: a chunk that fails twice is retried
/// alone while chunks that already arrived are NOT fetched again.
#[tokio::test]
async fn resume_retries_only_the_missing_chunk() {
    const N: usize = 10;
    let per_chunk_calls = Arc::new(std::sync::Mutex::new(vec![0usize; N]));
    let out = assemble_chunks_resumable(N, SNAPSHOT_CHUNK_RETRIES, |i| {
        let per_chunk_calls = per_chunk_calls.clone();
        async move {
            let attempt = {
                let mut c = per_chunk_calls.lock().unwrap();
                c[i] += 1;
                c[i]
            };
            tokio::task::yield_now().await;
            // Chunk 7 drops its first two attempts (weak-link shape), then moves.
            if i == 7 && attempt <= 2 {
                return None;
            }
            Some(vec![i as u8; 16])
        }
    })
    .await
    .expect("one flaky chunk must not fail the blob");

    assert_eq!(out.len(), N);
    assert_eq!(out[7], vec![7u8; 16]);
    let counts = per_chunk_calls.lock().unwrap().clone();
    for (i, c) in counts.iter().enumerate() {
        if i == 7 {
            assert_eq!(*c, 3, "flaky chunk retried until it arrived");
        } else {
            assert_eq!(
                *c, 1,
                "ready chunk {i} must never be re-ordered (got {c} fetches)"
            );
        }
    }
}

/// Permanent failure is LOUD: names the dead chunk, the size class, the
/// attempts and the timeout — never a silent `None`.
#[tokio::test]
async fn permanent_chunk_loss_reports_which_chunk_died() {
    const N: usize = 50;
    let err = assemble_chunks_resumable(N, SNAPSHOT_CHUNK_RETRIES, |_| async { None })
        .await
        .expect_err("an always-dead link must fail loudly, not hang");
    assert_eq!(err.chunk_index, 0);
    assert_eq!(err.n_chunks, N);
    assert_eq!(err.attempts, SNAPSHOT_CHUNK_RETRIES + 1);
    assert_eq!(err.timeout_ms, SNAPSHOT_CHUNK_TIMEOUT_MS);
    let msg = err.to_string();
    assert!(msg.contains('0'), "message names the chunk: {msg}");
    assert!(
        msg.contains(&N.to_string()),
        "message names the size class: {msg}"
    );
    assert!(
        msg.contains(&SNAPSHOT_CHUNK_TIMEOUT_MS.to_string()),
        "message names the budget: {msg}"
    );
}

/// Empty blob (all domain slots absent, size 0) is success with no fetches.
#[tokio::test]
async fn empty_blob_needs_no_fetches() {
    let calls = Arc::new(AtomicUsize::new(0));
    let out = assemble_chunks_resumable(0, SNAPSHOT_CHUNK_RETRIES, |_| {
        let calls = calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(vec![])
        }
    })
    .await
    .expect("empty blob must succeed");
    assert!(out.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no chunk exists to fetch");
}
