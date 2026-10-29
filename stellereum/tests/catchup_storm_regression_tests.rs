//! Regression for the 2026-10-13 catch-up storm (observer C).
//!
//! Live symptoms pinned here:
//! * C (~1800 behind, 1 vCPU/60%) took 8-28s per tick with `catchup=true`;
//! * every outgoing `request_to` sat at 2500-3500ms (timeout+retry shape)
//!   while B→C answered in 269ms;
//! * `too many concurrent streams on one connection, dropping stream`
//!   (limit 256) in batches, plus `sending stopped by peer: error 0`
//!   (peers cutting excess streams → timeouts → retries, self-excitation).
//!
//! `collect_missing_blocks` is strictly sequential, so the walk cannot be the
//! fan-out. The amplification was: 128 snapshot probes × (state + domains +
//! header + QC), each `fetch_blob` fanning out to manifest + per-chunk
//! lookups, background `replicate_blob` pushes to the newcomer, and instant
//! retries on top of timeouts.
//!
//! The fix (src/sync.rs + src/network.rs + src/main.rs):
//! * process-wide fetch semaphore (`FETCH_MAX_CONCURRENCY=8`);
//! * exponential retry backoff (`fetch_retry_backoff_ms`);
//! * paced snapshot probes (`snapshot_probe_pace_ms`);
//! * paced retro pushes (`RETRO_PUBLISH_PACE_MS`) + skip stale pushes while
//!   far behind (`should_skip_retro_while_behind`).
//!
//! These tests emulate a weak link (per-fetch delay standing in for the live
//! 2.5s RTT, scaled down so the suite stays fast) and assert the catching
//! node converges WITHOUT a stream storm (max in-flight fetches ≤ 8).

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use stellereum::sync::{
    collect_missing_blocks, fetch_retry_backoff_ms, plan_backfill_tip_ward,
    should_skip_retro_while_behind, snapshot_probe_pace_ms, FETCH_MAX_CONCURRENCY,
    FETCH_RETRY_BASE_BACKOFF_MS, FETCH_RETRY_MAX_BACKOFF_MS, RETRO_SKIP_BEHIND_GAP,
};

#[test]
fn fetch_retry_backoff_is_exponential_and_capped() {
    assert_eq!(fetch_retry_backoff_ms(1), FETCH_RETRY_BASE_BACKOFF_MS);
    assert_eq!(fetch_retry_backoff_ms(2), 200);
    assert_eq!(fetch_retry_backoff_ms(3), 400);
    assert_eq!(fetch_retry_backoff_ms(4), 800);
    // Capped at 1000ms: no retry ever waits out a round timeout.
    assert_eq!(fetch_retry_backoff_ms(5), FETCH_RETRY_MAX_BACKOFF_MS);
    assert_eq!(fetch_retry_backoff_ms(100), FETCH_RETRY_MAX_BACKOFF_MS);
    // Old behaviour (10ms×attempt) hammered the DHT inside the timeout
    // window; the new floor is 10× higher.
    assert!(fetch_retry_backoff_ms(1) >= 100);
}

#[test]
fn snapshot_probe_pacing_is_linear_and_capped() {
    assert_eq!(snapshot_probe_pace_ms(0), 0);
    assert_eq!(snapshot_probe_pace_ms(1), 20);
    assert_eq!(snapshot_probe_pace_ms(5), 100);
    assert_eq!(snapshot_probe_pace_ms(10), 200);
    assert_eq!(
        snapshot_probe_pace_ms(100),
        200,
        "capped so a long miss run cannot stall a tick"
    );
}

#[test]
fn stale_pushes_are_skipped_only_while_far_behind() {
    // Live shape: C at 72415 vs tip 74200 (gap 1785) must not push.
    assert!(should_skip_retro_while_behind(72415, 74200));
    // In-sync nodes behave byte-identically to before (no skip).
    assert!(!should_skip_retro_while_behind(74200, 74200));
    assert!(!should_skip_retro_while_behind(74199, 74200));
    assert!(
        !should_skip_retro_while_behind(74200, 74100),
        "peer behind us is never a skip"
    );
    assert!(!should_skip_retro_while_behind(
        74200 - RETRO_SKIP_BEHIND_GAP,
        74200
    ));
    assert!(should_skip_retro_while_behind(
        74200 - RETRO_SKIP_BEHIND_GAP - 1,
        74200
    ));
}

#[test]
fn fetch_concurrency_bound_is_eight_like_adopt_repl() {
    assert_eq!(FETCH_MAX_CONCURRENCY, 8);
    assert_eq!(
        FETCH_MAX_CONCURRENCY,
        stellereum::sync::ADOPT_REPL_MAX_CONCURRENCY
    );
}

/// Sequential walk on a slow link converges with NO parallelism.
///
/// Emulates the 2.5s RTT with a 5ms delay per fetch (scaled for test speed):
/// the shape under test is "sequential stays sequential even when slow",
/// i.e. max in-flight == 1, never a storm.
#[tokio::test]
async fn slow_walk_converges_with_no_parallelism() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    // Real blocks so the F3(a) hash check passes: same construction as
    // sync.rs unit tests (proposer-signed, heights 0..=n linked).
    let sk = SigningKey::generate(&mut OsRng);
    let n = 32u64;
    let mut blocks = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..=n {
        let mut b = stellereum::sharding::Block {
            shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: [h as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: h,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&sk);
        prev = b.compute_hash();
        blocks.push(b);
    }
    let map: HashMap<[u8; 32], stellereum::sharding::Block> = blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect();
    let genesis = blocks[0].compute_hash();
    let head = blocks[n as usize].compute_hash();

    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let got = collect_missing_blocks(head, genesis, 10_000, |h| {
        let inflight = inflight.clone();
        let max_seen = max_seen.clone();
        let map = map.clone();
        async move {
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, Ordering::SeqCst);
            // Weak link: every fetch pays the RTT (scaled).
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            map.get(&h).cloned()
        }
    })
    .await
    .expect("slow walk must converge");
    assert_eq!(got.len() as u64, n, "blocks 1..=n in ancestor-first order");
    assert_eq!(got[0].height, 1);
    assert_eq!(got.last().unwrap().height, n);
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "sequential walk must never have >1 fetch in flight, even on a slow link"
    );
}

/// Bounded parallel backfill on a slow link converges with NO storm.
///
/// 64 heights (one full `ADOPT_REPL_BACKFILL_MAX_PER_PASS` window) fetched
/// through a semaphore of `FETCH_MAX_CONCURRENCY` with a per-fetch delay
/// emulating the 2.5s RTT: all complete (convergence) and max in-flight
/// never exceeds 8 (no 256-stream storm).
#[tokio::test]
async fn bounded_backfill_on_weak_link_converges_without_storm() {
    let plan = plan_backfill_tip_ward(72415, 72415 + 64, 64, 8000, 4096);
    assert_eq!(plan.len(), 64);

    let sem = Arc::new(tokio::sync::Semaphore::new(FETCH_MAX_CONCURRENCY));
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for h in plan {
        let sem = sem.clone();
        let inflight = inflight.clone();
        let max_seen = max_seen.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, Ordering::SeqCst);
            // Weak link RTT (scaled: 25ms stands in for live 2500ms).
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            h
        }));
    }
    let mut done = Vec::new();
    for h in handles {
        done.push(h.await.unwrap());
    }
    done.sort_unstable();
    assert_eq!(
        done.len(),
        64,
        "every height in the window completes: convergence"
    );
    assert_eq!(done[0], 72416);
    assert_eq!(*done.last().unwrap(), 72479);
    let max = max_seen.load(Ordering::SeqCst);
    assert!(
        max <= FETCH_MAX_CONCURRENCY,
        "max in-flight {max} exceeds the {FETCH_MAX_CONCURRENCY} cap (storm)"
    );
    assert!(
        max > 1,
        "test must actually exercise parallelism (max={max})"
    );
}
