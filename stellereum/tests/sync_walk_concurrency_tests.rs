//! Sync walk FETCH concurrency: bounded parallel chunk assembly (sync.rs zone).
//!
//! Scope: `assemble_chunks_resumable` fetch path ONLY. Anchor verification,
//! QC checks and set-binding logic are untouched (this file never imports
//! them). `collect_missing_blocks` stays strictly serial (pinned by
//! `catchup_storm_regression_tests::slow_walk_converges_with_no_parallelism`);
//! only the CHUNK walk batches, bounded by `chunk_batch_for_blob` (width 4
//! for small blobs, strictly serial width 1 above `LARGE_BLOB_SERIAL_CHUNKS`).
//!
//! Pins:
//! * (before/after) fixed N=8 fixture, 25ms/chunk: serial reference (the old
//!   algorithm, copied verbatim) vs production batched — wall ms printed,
//!   bytes identical, batched ≥2x faster;
//! * equivalence incl. adversarial shapes (honest / forged-bytes /
//!   tamper-as-miss / out-of-order completion): production verdict == serial
//!   verdict, assembly order canonical by index;
//! * bounded: small-blob max in-flight ≤ FETCH_BLOB_CHUNK_BATCH (and >1, so
//!   the test really exercises parallelism); snapshot-sized (N=50) max == 1
//!   (weak-node serial shape preserved);
//! * per-peer fairness: slow-peer chunks still arrive (no starvation), every
//!   index attempted, bound held.

use std::future::Future;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use stellereum::sync::{
    assemble_chunks_resumable, chunk_batch_for_blob, SnapshotChunkFailure, FETCH_BLOB_CHUNK_BATCH,
    LARGE_BLOB_SERIAL_CHUNKS, SNAPSHOT_CHUNK_RETRIES,
};

/// VERBATIM copy of the pre-change (serial) assembly algorithm: one chunk
/// per await in index order, resume across passes, same failure shape.
/// Used as the "before" reference for wall-ms and verdict equivalence.
async fn serial_reference<F, Fut>(
    n_chunks: usize,
    max_retries: u32,
    mut fetch_chunk: F,
) -> Result<Vec<Vec<u8>>, SnapshotChunkFailure>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Option<Vec<u8>>>,
{
    use std::collections::BTreeSet;
    let mut slots: Vec<Option<Vec<u8>>> = (0..n_chunks).map(|_| None).collect();
    let passes = max_retries.saturating_add(1);
    for _pass in 0..passes {
        let mut missing: BTreeSet<usize> = slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_none() { Some(i) } else { None })
            .collect();
        if missing.is_empty() {
            break;
        }
        let round: Vec<usize> = missing.iter().copied().collect();
        for i in round {
            if slots[i].is_some() {
                continue;
            }
            if let Some(bytes) = fetch_chunk(i).await {
                slots[i] = Some(bytes);
                missing.remove(&i);
            }
            tokio::task::yield_now().await;
        }
        if missing.is_empty() && slots.iter().all(|s| s.is_some()) {
            break;
        }
    }
    if let Some(idx) = slots.iter().position(|s| s.is_none()) {
        return Err(SnapshotChunkFailure {
            chunk_index: idx,
            n_chunks,
            attempts: passes,
            timeout_ms: stellereum::sync::SNAPSHOT_CHUNK_TIMEOUT_MS,
        });
    }
    Ok(slots
        .into_iter()
        .map(|s| s.expect("all slots filled"))
        .collect())
}

fn fixture_bytes(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| vec![(i & 0xFF) as u8; 64]).collect()
}

/// Timed run of the fixed small-blob fixture under the SERIAL reference:
/// every chunk pays `delay_ms` (weak-link RTT stand-in), always hits.
async fn run_serial_fixed(
    n: usize,
    delay_ms: u64,
    expected: Vec<Vec<u8>>,
) -> (Vec<Vec<u8>>, u128) {
    let e = expected.clone();
    let t0 = std::time::Instant::now();
    let out = serial_reference(n, SNAPSHOT_CHUNK_RETRIES, move |i| {
        let b = e[i].clone();
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            Some(b)
        }
    })
    .await
    .expect("serial reference converges");
    (out, t0.elapsed().as_millis())
}

/// Timed run of the fixed small-blob fixture under PRODUCTION batched
/// assembly: identical latency shape to [`run_serial_fixed`].
async fn run_batched_fixed(
    n: usize,
    delay_ms: u64,
    expected: Vec<Vec<u8>>,
) -> (Vec<Vec<u8>>, u128) {
    let e = expected.clone();
    let t0 = std::time::Instant::now();
    let out = assemble_chunks_resumable(n, SNAPSHOT_CHUNK_RETRIES, move |i| {
        let b = e[i].clone();
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            Some(b)
        }
    })
    .await
    .expect("batched production converges");
    (out, t0.elapsed().as_millis())
}

/// BEFORE/AFTER on a fixed N=8 fixture (max small-blob width): serial
/// reference vs production batched. Prints both wall-ms; asserts identical
/// bytes and ≥2x speedup (ideal 4x at width 4; 2x leaves headroom for CI
/// jitter), plus canonical index order.
#[tokio::test]
async fn before_after_fixed_8chunk_fixture() {
    const N: usize = 8; // == LARGE_BLOB_SERIAL_CHUNKS: largest batched shape
    const DELAY_MS: u64 = 25;
    assert_eq!(
        chunk_batch_for_blob(N),
        FETCH_BLOB_CHUNK_BATCH,
        "fixture must use the batched width"
    );
    let expected = fixture_bytes(N);

    let (before, before_ms) = run_serial_fixed(N, DELAY_MS, expected.clone()).await;
    let (after, after_ms) = run_batched_fixed(N, DELAY_MS, expected.clone()).await;

    eprintln!("[walk-concurrency] BEFORE (serial) {before_ms}ms vs AFTER (batched) {after_ms}ms on fixed N={N}x{DELAY_MS}ms fixture");
    assert_eq!(before, expected, "serial reference is byte-exact");
    assert_eq!(after, expected, "batched production is byte-exact");
    assert_eq!(before, after, "synced roots equal serial-walk roots: identical bytes");
    for (i, chunk) in after.iter().enumerate() {
        assert_eq!(*chunk, expected[i], "canonical index order at {i}");
    }
    assert!(
        after_ms * 2 <= before_ms,
        "batched ({after_ms}ms) must be ≥2x faster than serial ({before_ms}ms)"
    );
}

/// Adversarial equivalence: forged-bytes pass through BOTH shapes identically
/// (tamper-as-bytes is detected downstream by the expected-hash/root check,
/// never by the assembler — the assembler must not DIVERGE on it).
#[tokio::test]
async fn adversarial_forged_bytes_identical_both_shapes() {
    const N: usize = 8;
    let mut forged = fixture_bytes(N);
    forged[5] = vec![0xEEu8; 64]; // attacker-supplied bytes under chunk 5
    let f1 = forged.clone();
    let f2 = forged.clone();
    let before = serial_reference(N, 0, move |i| {
        let b = f1[i].clone();
        async move { Some(b) }
    })
    .await
    .expect("serial assembles forged bytes verbatim");
    let after = assemble_chunks_resumable(N, 0, move |i| {
        let b = f2[i].clone();
        async move { Some(b) }
    })
    .await
    .expect("batched assembles forged bytes verbatim");
    assert_eq!(before, after, "forged-bytes verdict identical");
    assert_eq!(after[5], vec![0xEEu8; 64]);
}

/// Adversarial equivalence: tamper-as-miss (production `fetch_chunk_net`
/// reports an expected-hash mismatch as `None`, exactly like a drop) fails
/// LOUDLY and IDENTICALLY in both shapes: same dead index, same attempts.
#[tokio::test]
async fn adversarial_tamper_as_miss_fails_identically() {
    const N: usize = 8;
    // Chunk 3 always misses (tampered: hash mismatch reported as miss).
    let miss = |i: usize| async move { if i == 3 { None } else { Some(vec![i as u8; 16]) } };
    let before = serial_reference(N, 2, miss).await.expect_err("serial must fail loud");
    let miss2 = |i: usize| async move { if i == 3 { None } else { Some(vec![i as u8; 16]) } };
    let after = assemble_chunks_resumable(N, 2, miss2)
        .await
        .expect_err("batched must fail loud");
    assert_eq!(before, after, "loud failure identical: {before} vs {after}");
    assert_eq!(before.chunk_index, 3);
    assert_eq!(before.attempts, 3);
    assert_eq!(before.n_chunks, N);
}

/// Adversarial equivalence: out-of-order completion (chunk 0 slowest) still
/// assembles in canonical index order, byte-identical to serial.
#[tokio::test]
async fn adversarial_out_of_order_completion_stays_canonical() {
    const N: usize = 8;
    let expected = fixture_bytes(N);
    // Reverse-latency shape: low indices arrive LAST.
    let e1 = expected.clone();
    let slow_first = move |i: usize| {
        let b = e1[i].clone();
        async move {
            let delay = ((N - i) as u64) * 10;
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            Some(b)
        }
    };
    let e2 = expected.clone();
    let slow_first2 = move |i: usize| {
        let b = e2[i].clone();
        async move {
            let delay = ((N - i) as u64) * 10;
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            Some(b)
        }
    };
    let before = serial_reference(N, 0, slow_first)
        .await
        .expect("serial converges");
    let after = assemble_chunks_resumable(N, 0, slow_first2)
        .await
        .expect("batched converges");
    assert_eq!(before, after);
    assert_eq!(after, expected, "canonical index order despite skew");
}

/// BOUNDED (small blob): max in-flight ≤ FETCH_BLOB_CHUNK_BATCH, and >1 so
/// the test genuinely exercises parallelism.
#[tokio::test]
async fn small_blob_concurrency_bounded_by_const() {
    const N: usize = 8;
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let out = assemble_chunks_resumable(N, SNAPSHOT_CHUNK_RETRIES, |i| {
        let inflight = inflight.clone();
        let max_seen = max_seen.clone();
        async move {
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            Some(vec![i as u8; 16])
        }
    })
    .await
    .expect("small blob converges");
    assert_eq!(out.len(), N);
    let max = max_seen.load(Ordering::SeqCst);
    eprintln!("[walk-concurrency] small-blob N={N} max in-flight={max} (cap={FETCH_BLOB_CHUNK_BATCH})");
    assert!(
        max <= FETCH_BLOB_CHUNK_BATCH,
        "max in-flight {max} exceeds const cap {FETCH_BLOB_CHUNK_BATCH} (unbounded fan-out)"
    );
    assert!(max > 1, "test must exercise parallelism (max={max})");
}

/// BOUNDED (snapshot-sized): N=50 stays strictly serial (max == 1) — the
/// weak-node pull shape is unchanged for large blobs.
#[tokio::test]
async fn large_blob_stays_serial_width_one() {
    const N: usize = 50;
    assert_eq!(
        chunk_batch_for_blob(N),
        1,
        "snapshot-sized blobs must use serial width"
    );
    // GATE: black_box defeats const-folding; documents the test's precondition.
    assert!(std::hint::black_box(N) > LARGE_BLOB_SERIAL_CHUNKS);
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let out = assemble_chunks_resumable(N, SNAPSHOT_CHUNK_RETRIES, |i| {
        let inflight = inflight.clone();
        let max_seen = max_seen.clone();
        async move {
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, Ordering::SeqCst);
            tokio::task::yield_now().await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            Some(vec![i as u8; 8])
        }
    })
    .await
    .expect("large blob converges");
    assert_eq!(out.len(), N);
    for (i, chunk) in out.iter().enumerate() {
        assert_eq!(*chunk, vec![i as u8; 8], "canonical order at {i}");
    }
    let max = max_seen.load(Ordering::SeqCst);
    eprintln!("[walk-concurrency] large-blob N={N} max in-flight={max} (must stay 1)");
    assert_eq!(max, 1, "snapshot-sized assembly must stay serial (max={max})");
}

/// PER-PEER FAIRNESS: even indices from a fast peer (5ms), odd from a slow
/// peer (40ms). No index starves: all arrive, each attempted, bound held,
// and output is canonical by index.
#[tokio::test]
async fn slow_peer_chunks_not_starved() {
    const N: usize = 8;
    let per_index_calls = Arc::new(std::sync::Mutex::new(vec![0usize; N]));
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let out = assemble_chunks_resumable(N, SNAPSHOT_CHUNK_RETRIES, |i| {
        let per_index_calls = per_index_calls.clone();
        let inflight = inflight.clone();
        let max_seen = max_seen.clone();
        async move {
            {
                let mut c = per_index_calls.lock().unwrap();
                c[i] += 1;
            }
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, Ordering::SeqCst);
            // Slow peer serves odd chunks 8x slower — must still arrive.
            let delay = if i % 2 == 0 { 5 } else { 40 };
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            Some(vec![i as u8; 16])
        }
    })
    .await
    .expect("mixed-peer blob converges: no starvation");
    assert_eq!(out.len(), N);
    for (i, chunk) in out.iter().enumerate() {
        assert_eq!(*chunk, vec![i as u8; 16], "canonical order at {i}");
    }
    let counts = per_index_calls.lock().unwrap().clone();
    for (i, c) in counts.iter().enumerate() {
        assert!(*c >= 1, "index {i} starved ({c} attempts)");
    }
    let max = max_seen.load(Ordering::SeqCst);
    eprintln!("[walk-concurrency] fairness N={N} max in-flight={max}, per-index calls={counts:?}");
    assert!(
        max <= FETCH_BLOB_CHUNK_BATCH,
        "fairness run exceeded the const bound (max={max})"
    );
}
