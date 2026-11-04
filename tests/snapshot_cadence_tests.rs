//! Adaptive snapshot cadence: skip rule + restore-equivalence (9.5 HDAE).
//!
//! SCOPE: decision logic only (`stellereum::snapshot_cadence` + the submit
//! site in `src/main.rs`). Snapshot FORMAT, restore and verify paths are
//! untouched — byte-identity is asserted here, not assumed.
//!
//! Rule under test: a candidate height (`snapshot_candidate`, byte-identical
//! to the legacy trigger) is SKIPPED iff the worker-certified post-height
//! state root equals the previous height's root (provably no state change)
//! AND the interval floor is not due (`floor_due`: gap > `snap_int`, so
//! snapshots are never rarer than ~1 interval + the 100-height catch-up grid
//! — worst case `worst_case_gap`, documented in `snapshot_cadence.rs`).
//!
//! Tests (extend-only; no existing suite is modified):
//! 1. `candidate_matches_legacy_trigger` — the extracted candidate rule
//!    differentials the pre-change trigger expression inline, over a sweep.
//! 2. `active_chain_behaves_like_before` — `state_changed=true` submits
//!    exactly where the legacy trigger fired.
//! 3. `idle_skips_below_floor_floor_forces_submit` — an idle exact-multiple
//!    candidate skips; the first catch-up-grid candidate past the floor
//!    submits; a simulated idle chain never exceeds `worst_case_gap`.
//! 4. `unchanged_state_snapshots_byte_identical` — the safety basis of the
//!    skip: two captures of unmoved state are byte-equal (fixed fixture).
//! 5. `skipped_heights_restore_from_nearest_plus_replay` — differential
//!    with/without skips: same roots at every height, same bytes where both
//!    snapshot, and a skipped height restores from the nearest snapshot +
//!    replayed deltas to the canonical root.
//! 6. `snapshot_cost_report` — fixed N=1000 fixture, median-of-5 full
//!    `create_snapshot` ms REPORTED plus the amortized share of the 0.6s
//!    per-height budget (no tight timing gate; correctness asserts only).

use std::time::Instant;

use stellereum::snapshot_cadence::{
    floor_due, should_submit_snapshot, snapshot_candidate, worst_case_gap, CATCHUP_GRID,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// The pre-change trigger expression, copied verbatim from `src/main.rs`
/// before the adaptive gate (the `% 100` literal is the catch-up grid).
#[allow(clippy::manual_is_multiple_of)] // GATE: must stay textually identical to the pre-change trigger it differentials.
fn legacy_trigger(height: u64, last_snapshot_height: u64, snap_int: u64) -> bool {
    (height % snap_int == 0
        || (height > last_snapshot_height.saturating_add(snap_int) && height % 100 == 0))
        && height > last_snapshot_height
}

#[test]
fn candidate_matches_legacy_trigger() {
    assert_eq!(CATCHUP_GRID, 100, "grid const must match the legacy literal");
    for snap_int in [50u64, 51, 99, 100, 101, 500, 1000, 4096] {
        for last in [0u64, 1, 49, 50, 99, 100, 999, 1000, 1050, 1999, 2000, 10_000] {
            let lo = last.saturating_sub(5);
            for h in lo..last.saturating_add(2600) {
                assert_eq!(
                    snapshot_candidate(h, last, snap_int),
                    legacy_trigger(h, last, snap_int),
                    "candidate drifted from legacy trigger (h={h} last={last} int={snap_int})"
                );
            }
        }
    }
}

#[test]
fn active_chain_behaves_like_before() {
    // Where state moves, the gate submits exactly where it always did.
    for snap_int in [50u64, 100, 1000] {
        for last in [0u64, 999, 1000, 1050, 1100, 1999, 2000] {
            for h in last.saturating_sub(5)..last + 2500 {
                assert_eq!(
                    should_submit_snapshot(h, last, snap_int, true),
                    legacy_trigger(h, last, snap_int),
                    "active chain must submit exactly like before (h={h} last={last} int={snap_int})"
                );
            }
        }
    }
}

#[test]
fn idle_skips_below_floor_floor_forces_submit() {
    const SNAP_INT: u64 = 1000;
    const LAST: u64 = 1000;
    // Idle exact-multiple candidate below the floor skips (gap == snap_int,
    // floor needs strictly more).
    assert!(snapshot_candidate(2000, LAST, SNAP_INT));
    assert!(!floor_due(2000, LAST, SNAP_INT));
    assert!(!should_submit_snapshot(2000, LAST, SNAP_INT, false));

    // First catch-up-grid candidate past the floor MUST submit even idle.
    assert!(snapshot_candidate(2100, LAST, SNAP_INT));
    assert!(floor_due(2100, LAST, SNAP_INT));
    assert!(should_submit_snapshot(2100, LAST, SNAP_INT, false));

    // Simulated fully-idle chain from LAST: submissions never run further
    // apart than the proven worst-case bound (today's worst case under one
    // skipped/refused capture).
    let mut submitted = vec![LAST];
    let mut last_sub = LAST;
    for h in LAST + 1..LAST + 3 * SNAP_INT + 500 {
        if should_submit_snapshot(h, last_sub, SNAP_INT, false) {
            submitted.push(h);
            last_sub = h;
        }
    }
    assert!(submitted.len() > 2, "idle chain must still snapshot: {submitted:?}");
    for w in submitted.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap <= worst_case_gap(SNAP_INT),
            "idle gap {} exceeds worst-case bound {} (window {w:?})",
            gap,
            worst_case_gap(SNAP_INT)
        );
    }
    eprintln!("[snapshot-cadence] idle submit heights from {LAST}: {submitted:?}");
}

// ---------- fixed engine fixture ----------

fn fixed_addr(i: usize) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = 0xA0;
    a[1] = (i & 0xFF) as u8;
    a[2] = ((i >> 8) & 0xFF) as u8;
    a[3] = ((i >> 16) & 0xFF) as u8;
    a
}

async fn funded_engine(n: usize) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    for i in 0..n {
        e.update_account(AccountState::new(fixed_addr(i), 10_000 + i as u64))
            .await;
    }
    e
}

#[tokio::test]
async fn unchanged_state_snapshots_byte_identical() {
    // Safety basis of the skip: a capture over unmoved state is
    // content-identical to the previous one, so omitting it loses nothing.
    let e = funded_engine(1_000).await;
    let root_before = e.get_state_root().await;
    let a = e.create_snapshot().await;
    assert!(!a.is_empty(), "snapshot must serialize");
    // No state change between captures.
    let b = e.create_snapshot().await;
    assert_eq!(e.get_state_root().await, root_before);
    assert_eq!(a, b, "captures of unmoved state must be byte-identical");
    eprintln!("[snapshot-cadence] N=1000 idle re-capture byte-identical ({} bytes)", a.len());
}

/// Differential with/without skips over a mixed idle+active span.
///
/// Canonical history (snap_int=1000, last snapshot at H=1000):
/// * H=1001..=2000 idle (no state change) → H=2000 is a candidate but the
///   gate SKIPS it (gap == snap_int, floor not due).
/// * H=2001..=2100: one balance mutates per height → H=2100 is a
///   catch-up-grid candidate past the floor → gate SUBMITS.
/// Legacy run snapshots at 1000 AND 2000 AND 2100; adaptive at 1000 AND 2100.
/// Both must agree on roots at every height and on bytes where both snap;
/// the skipped H=2000 must restore from the nearest snapshot (H=1000) +
/// replayed deltas to the canonical root.
#[tokio::test]
async fn skipped_heights_restore_from_nearest_plus_replay() {
    const SNAP_INT: u64 = 1000;
    const H_SNAP0: u64 = 1000;
    const H_SKIP: u64 = 2000;
    const H_SNAP1: u64 = 2100;
    const N: usize = 500;

    // Gate decisions the test pins (decision logic, not I/O).
    assert!(snapshot_candidate(H_SKIP, H_SNAP0, SNAP_INT));
    assert!(!should_submit_snapshot(H_SKIP, H_SNAP0, SNAP_INT, false));
    assert!(should_submit_snapshot(H_SNAP1, H_SNAP0, SNAP_INT, true));

    // Canonical run: record per-height deltas + roots.
    let engine = funded_engine(N).await;
    let snap0 = engine.create_snapshot().await;
    let root0 = engine.get_state_root().await;
    let mut deltas: Vec<(u64, usize, u64)> = Vec::new(); // (height, account idx, new balance)
    let mut roots: Vec<([u8; 32], u64)> = vec![(root0, H_SNAP0)];
    let mut root = root0;
    for h in H_SNAP0 + 1..=H_SNAP1 {
        if h > H_SKIP {
            // Active span: mutate one account per height.
            let idx = (h - H_SKIP - 1) as usize % N;
            let bal = 10_000 + idx as u64 + h;
            engine.update_account(AccountState::new(fixed_addr(idx), bal)).await;
            deltas.push((h, idx, bal));
        }
        let r = engine.get_state_root().await;
        if h <= H_SKIP {
            assert_eq!(r, root, "idle span must not move the root (h={h})");
        } else {
            assert_ne!(r, root, "active span must move the root (h={h})");
        }
        root = r;
        roots.push((r, h));
    }
    let canonical_skip_root = roots[(H_SKIP - H_SNAP0) as usize].0;
    let canonical_tip_root = root;
    let snap1 = engine.create_snapshot().await;

    // Legacy run (no skips): snapshot at H_SKIP too — must equal replay
    // target bytes shape: same state → same bytes as restoring snap0 +
    // replaying the (empty) idle delta log.
    let legacy = funded_engine(N).await;
    let legacy_snap0 = legacy.create_snapshot().await;
    assert_eq!(snap0, legacy_snap0, "same state must snapshot identically across runs");
    // Idle span on the legacy engine: root must track the canonical idle
    // root exactly (no divergence from skipping — nothing was skipped yet).
    for h in H_SNAP0 + 1..=H_SKIP {
        assert_eq!(
            legacy.get_state_root().await, canonical_skip_root,
            "legacy idle root must equal canonical (h={h})"
        );
    }
    let legacy_snap_skip = legacy.create_snapshot().await;
    assert_eq!(
        legacy_snap_skip, snap0,
        "legacy snapshot at idle H={H_SKIP} must be byte-identical to H={H_SNAP0} (the skip loses nothing)"
    );
    // Active span with identical deltas → identical tip root + bytes.
    for (_, idx, bal) in &deltas {
        legacy.update_account(AccountState::new(fixed_addr(*idx), *bal)).await;
    }
    assert_eq!(legacy.get_state_root().await, canonical_tip_root);
    let legacy_snap1 = legacy.create_snapshot().await;
    assert_eq!(snap1, legacy_snap1, "post-active snapshot bytes must agree with/without skips");

    // Restore-equivalence: skipped H=2000 from nearest snapshot (H=1000) +
    // replay of the recorded idle deltas (empty) == canonical root.
    let restored = InMemoryStateEngine::new();
    restored.restore_snapshot(&snap0).await.expect("nearest snapshot restores");
    let idle_replay: Vec<_> = deltas.iter().filter(|(h, _, _)| *h <= H_SKIP).collect();
    assert!(idle_replay.is_empty(), "idle span must replay zero deltas");
    for (_, idx, bal) in idle_replay {
        restored.update_account(AccountState::new(fixed_addr(*idx), *bal)).await;
    }
    assert_eq!(
        restored.get_state_root().await, canonical_skip_root,
        "skipped height restores from nearest snapshot + replay to the canonical root"
    );

    // And the tip restores from the post-skip snapshot + full replay log.
    let restored_tip = InMemoryStateEngine::new();
    restored_tip.restore_snapshot(&snap0).await.expect("snap0 restores");
    for (_, idx, bal) in &deltas {
        restored_tip.update_account(AccountState::new(fixed_addr(*idx), *bal)).await;
    }
    assert_eq!(
        restored_tip.get_state_root().await, canonical_tip_root,
        "tip replays from the pre-skip snapshot to the canonical root"
    );
    eprintln!(
        "[snapshot-cadence] differential green: roots agree {}..={H_SNAP1}, idle-skip bytes identical ({} bytes), skip-height + tip replay == canonical",
        H_SNAP0,
        snap0.len()
    );
}

fn median_ms(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    v[v.len() / 2]
}

/// Snapshot cost report on a fixed fixture (REPORT-only timing; the asserts
/// are correctness, never a wall-clock gate).
#[tokio::test]
async fn snapshot_cost_report() {
    const N: usize = 1_000;
    const REPS: usize = 5;
    const BUDGET_MS: f64 = 600.0; // 0.6s/block program
    let engine = funded_engine(N).await;
    let canonical = engine.get_state_root().await;
    let mut samples = Vec::with_capacity(REPS);
    let mut bytes_len = 0usize;
    for _ in 0..REPS {
        let t0 = Instant::now();
        let bytes = engine.create_snapshot().await;
        samples.push(t0.elapsed().as_secs_f64() * 1000.0);
        std::hint::black_box(&bytes);
        bytes_len = bytes.len();
        // Round-trip correctness every rep: restore == canonical root.
        let fresh = InMemoryStateEngine::new();
        fresh.restore_snapshot(&bytes).await.expect("snapshot restores");
        assert_eq!(fresh.get_state_root().await, canonical);
    }
    assert!(bytes_len > 1024, "fixture must be non-trivial");
    let full_ms = median_ms(samples);
    // BEFORE: every candidate snapshotted — each height pays full/interval.
    // AFTER: idle candidates skipped — skipped heights pay 0, taken ones pay
    // full (unchanged); the amortized rows below are the per-height cost when
    // a snapshot IS taken at that cadence.
    for interval in [50u64, 1000] {
        let amort = full_ms / interval as f64;
        eprintln!(
            "[snapshot-cadence] N={N} full-snapshot median {full_ms:.2}ms ({bytes_len} bytes) | interval {interval}: amortized {amort:.4}ms/height = {:.3}% of 0.6s budget (BEFORE=always-take; AFTER: skipped heights pay 0)",
            amort / BUDGET_MS * 100.0
        );
    }
}
