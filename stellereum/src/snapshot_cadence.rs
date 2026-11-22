//! Adaptive snapshot cadence gate (pure decision logic, no I/O).
//!
//! The snapshot TRIGGER (which heights are candidates) is unchanged: every
//! `snap_int` heights, plus every multiple of [`CATCHUP_GRID`] once the gap
//! since the last snapshot exceeds `snap_int` (the pre-existing catch-up rule
//! that also covers a worker-refused capture). What this gate adds is a
//! SKIP: a candidate height whose certified post-height state root equals the
//! previous height's root provably brought no state change, so the snapshot
//! that would be written there is content-identical to the previous one and
//! the capture can be skipped — unless the interval FLOOR is due.
//!
//! FLOOR (worst-case restore distance is never exceeded): a candidate with
//! `height - last_snapshot_height > snap_int` is ALWAYS submitted, idle or
//! not. Bound (proved by `worst_case_gap_bound_*` tests in
//! `tests/snapshot_cadence_tests.rs`): consecutive submitted snapshots are at
//! most `snap_int + CATCHUP_GRID` apart — exactly today's worst case under a
//! single skipped/refused capture, which lands on the same catch-up grid
//! (see the "skipped capture simply snapshots a later height" note at the
//! submit site in `src/main.rs`).
//!
//! The emptiness predicate is a comparison of two worker-certified roots, never
//! an assumption (no tx-count heuristic: a block full of failing transactions
//! that moves no state is equally safe to skip, and a zero-tx block that pays
//! rewards or matures unbondings moves the root and is never skipped).

/// Snapshot boundary grid the catch-up rule (and `try_snapshot_sync` probes)
/// align to. Mirrors the `% 100` literal at the submit site in `src/main.rs`;
/// kept as a named const so the worst-case bound below cannot drift from it.
pub const CATCHUP_GRID: u64 = 100;

/// Today's candidate rule, extracted from the submit site in `src/main.rs`
/// (behavior-identical: `candidate_matches_legacy_trigger` differentials this
/// against the original expression; `is_multiple_of` spells the same `%`
/// tests to satisfy the `manual_is_multiple_of` lint).
pub fn snapshot_candidate(height: u64, last_snapshot_height: u64, snap_int: u64) -> bool {
    if snap_int == 0 {
        return false;
    }
    (height.is_multiple_of(snap_int)
        || (height > last_snapshot_height.saturating_add(snap_int)
            && height.is_multiple_of(CATCHUP_GRID)))
        && height > last_snapshot_height
}

/// Interval floor: once more than a full `snap_int` has passed without a
/// snapshot, the next candidate MUST be submitted even if the height is idle.
/// (`>` — strictly beyond one interval — so an idle exact multiple is still
/// skippable while the gap can never run away.)
pub fn floor_due(height: u64, last_snapshot_height: u64, snap_int: u64) -> bool {
    height.saturating_sub(last_snapshot_height) > snap_int
}

/// Should a snapshot capture be submitted at `height`?
///
/// * `state_changed`: `certified_post_height_root != previous_height_root`
///   (both worker-certified post-apply roots — the caller asserts the
///   comparison on real roots, never assumes idleness).
/// * On an active chain (`state_changed == true`) this is exactly
///   [`snapshot_candidate`] — zero behavior change where state moves.
pub fn should_submit_snapshot(
    height: u64,
    last_snapshot_height: u64,
    snap_int: u64,
    state_changed: bool,
) -> bool {
    snapshot_candidate(height, last_snapshot_height, snap_int)
        && (state_changed || floor_due(height, last_snapshot_height, snap_int))
}

/// Proven worst-case gap between consecutive submitted snapshots, in heights.
///
/// Proof: let the last submitted snapshot be at `L`. The catch-up clause makes
/// every multiple of [`CATCHUP_GRID`] strictly above `L + snap_int` a
/// candidate; the first such height `H0` satisfies `H0 <= L + snap_int +
/// CATCHUP_GRID`, and `floor_due(H0, L, snap_int)` holds there
/// (`H0 - L > snap_int`), so a submission happens at or before `H0`
/// regardless of idleness. Hence the next submission is at most
/// `snap_int + CATCHUP_GRID` heights after `L`.
pub fn worst_case_gap(snap_int: u64) -> u64 {
    snap_int.saturating_add(CATCHUP_GRID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_interval_never_submits_but_never_panics() {
        for h in 0..300 {
            assert!(!snapshot_candidate(h, 0, 0));
            assert!(!should_submit_snapshot(h, 0, 0, true));
            assert!(!should_submit_snapshot(h, 0, 0, false));
        }
    }

    #[test]
    fn active_chain_is_exactly_today_candidate() {
        for snap_int in [50u64, 100, 500, 1000] {
            for last in [0u64, 999, 1000, 1050, 1100, 1999, 2000] {
                for h in last.saturating_sub(5)..last + 2500 {
                    assert_eq!(
                        should_submit_snapshot(h, last, snap_int, true),
                        snapshot_candidate(h, last, snap_int),
                        "active chain must behave exactly like today (h={h} last={last} int={snap_int})"
                    );
                }
            }
        }
    }

    #[test]
    fn floor_forces_idle_submit_and_only_idle_below_floor_skips() {
        for snap_int in [50u64, 100, 1000] {
            for last in [0u64, 100, 1100, 2050] {
                for h in last + 1..last + snap_int + 250 {
                    let cand = snapshot_candidate(h, last, snap_int);
                    let floor = floor_due(h, last, snap_int);
                    let submit_idle = should_submit_snapshot(h, last, snap_int, false);
                    // Floor ⇒ candidate submissions can never be skipped.
                    if cand && floor {
                        assert!(
                            submit_idle,
                            "floor due must force submit (h={h} last={last} int={snap_int})"
                        );
                    }
                    // A skip (candidate + no submit) is ONLY an idle
                    // below-floor height — never an assumption, never overdue.
                    if cand && !submit_idle {
                        assert!(
                            !floor,
                            "skip past the floor is forbidden (h={h} last={last} int={snap_int})"
                        );
                    }
                    // Non-candidates never submit, active or idle.
                    if !cand {
                        assert!(!should_submit_snapshot(h, last, snap_int, true));
                        assert!(!submit_idle);
                    }
                }
            }
        }
    }

    #[test]
    fn worst_case_gap_matches_proven_bound_shape() {
        // The bound must exceed one bare interval (the catch-up grid adds up
        // to CATCHUP_GRID) but never by more than the grid.
        for snap_int in [50u64, 51, 99, 100, 101, 500, 1000] {
            assert_eq!(worst_case_gap(snap_int), snap_int + CATCHUP_GRID);
        }
    }
}
