//! LIVENESS-REVIEW S5 pins for the node loop / catch-up policy.
//!
//! These are the production predicates the consensus driver and the
//! blind-QC-probe path call, included by path so the tests exercise the exact
//! shipped arithmetic instead of re-deriving it:
//!
//! * a verified peer vote whose future-round chase ALREADY ran inside the
//!   runtime must still restart the per-round timer (otherwise the next tick
//!   view-changes straight past the round just aligned with);
//! * during an apply-in-flight window only the NEXT height's commit is
//!   parkable (a current/far height would evict the single useful slot);
//! * a successful catch-up pass re-arms the reactive latch, and a BLIND probe
//!   that advanced re-arms it even without ahead evidence;
//! * the blind-probe ladder has the small rungs a silent follower needs to
//!   prove more than `tip+1`.

#[path = "../src/node/policy.rs"]
#[allow(dead_code)]
mod node_policy;

mod round_timer {
    use super::node_policy::round_timer_should_restart;

    /// REGRESSION: the runtime's `on_prevote`/`on_precommit` already ran the
    /// future-round chase, so the driver's follow-up reports "already there"
    /// (`drain_moved == false`) while `hc.round` moved. The timer must restart
    /// anyway.
    #[test]
    fn runtime_performed_chase_still_restarts_the_timer() {
        assert!(
            round_timer_should_restart(3, 4, false),
            "a round moved by the runtime's own chase must restart the timer"
        );
        assert!(round_timer_should_restart(0, 11, false));
    }

    /// The same rule applies when a genuine near-future PROPOSAL carries us to
    /// its signed round inside `on_proposal` (`sync_round_to`): the timer must
    /// restart before the next elapsed-time check, or the node view-changes
    /// past the proposal it just voted.
    #[test]
    fn proposal_alignment_is_a_round_change_too() {
        assert!(round_timer_should_restart(2, 3, false));
        assert!(!round_timer_should_restart(3, 3, false));
    }

    #[test]
    fn follow_up_chase_and_no_movement() {
        // The driver's follow-up moved us (runtime could not finish the jump).
        assert!(round_timer_should_restart(3, 4, true));
        // Nothing moved: never restart (a healthy round keeps its clock).
        assert!(!round_timer_should_restart(7, 7, false));
    }
}

mod commit_parking {
    use super::node_policy::commit_parkable_during_apply;

    /// REGRESSION: while H is executing (`hc.height == H`) the only commit the
    /// replay can adopt after the install is H+1.
    #[test]
    fn only_the_next_height_is_parkable() {
        assert!(commit_parkable_during_apply(1, 2));
        assert!(commit_parkable_during_apply(92078, 92079));
        assert!(
            !commit_parkable_during_apply(1, 1),
            "the height already executing is redundant and would evict H+1"
        );
        assert!(!commit_parkable_during_apply(1, 3));
        assert!(!commit_parkable_during_apply(1, 0));
    }

    #[test]
    fn saturating_top_of_chain_never_panics() {
        // A MAX-height tip cannot advance; only MAX itself could ever be
        // "next", and the walk/adopt still refuses it on continuity.
        assert!(commit_parkable_during_apply(u64::MAX, u64::MAX));
        assert!(!commit_parkable_during_apply(u64::MAX - 1, u64::MAX - 1));
    }
}

mod catchup_rearm {
    use super::node_policy::rearm_after_catchup_success;

    /// REGRESSION: a blind probe with no ahead evidence that still advanced us
    /// must keep the latch armed; otherwise the next attempt is 120 s away.
    #[test]
    fn blind_probe_progress_keeps_retrying() {
        assert!(rearm_after_catchup_success(true, false));
        // A blind probe that made NO progress is the at-tip case: stop.
        assert!(!rearm_after_catchup_success(false, false));
        // Evidence-backed progress is handled by the still-behind predicate.
        assert!(rearm_after_catchup_success(false, true));
    }
}

mod blind_probe_ladder {
    use super::node_policy::BLIND_PROBE_LADDER;

    /// The caller's anchor after probing ascending and stopping at the first
    /// miss, with `tip+1` always known (the initial probe) and no knowledge
    /// beyond the gap.
    fn anchor_for_gap(gap: u64) -> u64 {
        let mut anchor = 1;
        for &step in BLIND_PROBE_LADDER {
            if step > gap {
                break;
            }
            anchor = step;
        }
        anchor
    }

    #[test]
    fn ladder_is_strictly_ascending_and_keeps_the_far_rungs() {
        for w in BLIND_PROBE_LADDER.windows(2) {
            assert!(w[0] < w[1], "ladder must ascend: {BLIND_PROBE_LADDER:?}");
        }
        for far in [64u64, 256, 1024] {
            assert!(
                BLIND_PROBE_LADDER.contains(&far),
                "far rung +{far} dropped from {BLIND_PROBE_LADDER:?}"
            );
        }
    }

    /// REGRESSION: with only `+64/+256/+1024`, a silent follower 2..=63
    /// heights behind proved just `tip+1` and adopted ONE height per pass
    /// (next pass 120 s later) — slower than the live tempo, i.e. a jail.
    /// Every sub-64 gap must now be halved by the anchor in one pass.
    #[test]
    fn every_small_gap_is_at_least_halved_by_one_pass() {
        for gap in 2u64..=64 {
            let anchor = anchor_for_gap(gap);
            assert!(
                anchor * 2 >= gap,
                "gap {gap} anchors at +{anchor}: one pass leaves more than half"
            );
        }
    }

    #[test]
    fn one_and_two_height_gaps_are_covered() {
        assert_eq!(anchor_for_gap(1), 1);
        assert_eq!(anchor_for_gap(2), 2);
        assert_eq!(anchor_for_gap(3), 2);
        assert_eq!(anchor_for_gap(4), 4);
        assert_eq!(anchor_for_gap(63), 32);
        assert_eq!(anchor_for_gap(64), 64);
        // Far gaps still leap to the batched/snapshot path.
        assert_eq!(anchor_for_gap(1000), 256);
        assert_eq!(anchor_for_gap(1024), 1024);
    }
}
