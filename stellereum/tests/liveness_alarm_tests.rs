//! Fail-loud liveness alarm: pure decision-function matrix + counter.
//!
//! The alarm itself lives in the production drain loop (`src/main.rs`,
//! backed by `src/liveness_alarm.rs`). An end-to-end test through the real
//! loop is deliberately NOT attempted here: the existing harness
//! (`tests/support/consensus_cluster.rs`) drives `ValidatorRuntime`
//! directly on a virtual clock and never runs `run_consensus_node` (no
//! pubsub transport, no wall clock, no `adapter.node.cfg.peers`), so an
//! "isolated node fires the alarm" scenario would require running the full
//! binary loop with a real/mocked network — not trivial with the existing
//! harness, which must not be rewritten. The pure functions below ARE the
//! alarm decision, and this matrix pins every gate plus the boundary.
//!
//! NOTE on harness integration: not trivial (see above) — pure-fn tests
//! suffice per the task brief.

#[path = "../src/liveness_alarm.rs"]
mod liveness_alarm;

use liveness_alarm::{
    liveness_alarm_count, liveness_alarm_due, liveness_alarm_silence_ms, note_liveness_alarm,
    now_ms as alarm_now_ms, should_liveness_alarm, LIVENESS_ALARM_SILENCE_MS,
    LIVENESS_ALARM_THROTTLE_MS,
};

const THRESHOLD: u64 = LIVENESS_ALARM_SILENCE_MS;

/// One alarm-decision case: inputs plus the expected verdict.
struct AlarmCase {
    last_rx: u64,
    now: u64,
    is_validator: bool,
    peers: usize,
    threshold: u64,
    want: bool,
}

#[test]
fn default_silence_is_five_minutes() {
    assert_eq!(LIVENESS_ALARM_SILENCE_MS, 300_000);
    assert_eq!(LIVENESS_ALARM_THROTTLE_MS, 60_000);
}

#[test]
fn env_override_is_honored_and_nothing_else_touches_env() {
    // This is the ONLY test in this file that touches the process
    // environment (all other tests pass explicit thresholds, so parallel
    // execution cannot race them through the env).
    unsafe {
        std::env::set_var("STELL_LIVENESS_ALARM_MS", "1000");
    }
    assert_eq!(liveness_alarm_silence_ms(), 1000);
    unsafe {
        std::env::set_var("STELL_LIVENESS_ALARM_MS", "not-a-number");
    }
    assert_eq!(liveness_alarm_silence_ms(), LIVENESS_ALARM_SILENCE_MS);
    unsafe {
        std::env::set_var("STELL_LIVENESS_ALARM_MS", "0");
    }
    assert_eq!(liveness_alarm_silence_ms(), LIVENESS_ALARM_SILENCE_MS);
    unsafe {
        std::env::remove_var("STELL_LIVENESS_ALARM_MS");
    }
    assert_eq!(liveness_alarm_silence_ms(), LIVENESS_ALARM_SILENCE_MS);
}

#[test]
fn alarm_decision_matrix() {
    let cases = [
        // Fresh traffic: silent.
        AlarmCase { last_rx: 1_000, now: 1_000, is_validator: true, peers: 2, threshold: THRESHOLD, want: false },
        // Recent traffic, well under the threshold: silent.
        AlarmCase { last_rx: 1_000, now: 1_000 + 60_000, is_validator: true, peers: 2, threshold: THRESHOLD, want: false },
        // BOUNDARY: silence exactly == threshold stays silent (strict `>`).
        AlarmCase { last_rx: 0, now: THRESHOLD, is_validator: true, peers: 2, threshold: THRESHOLD, want: false },
        // BOUNDARY + 1ms: screams. This is the 18-day-isolation line.
        AlarmCase { last_rx: 0, now: THRESHOLD + 1, is_validator: true, peers: 2, threshold: THRESHOLD, want: true },
        // Long silence, validator, peers: screams.
        AlarmCase { last_rx: 0, now: 18 * 24 * 3_600_000, is_validator: true, peers: 2, threshold: THRESHOLD, want: true },
        // Single configured peer is enough to arm the alarm.
        AlarmCase { last_rx: 0, now: THRESHOLD + 1, is_validator: true, peers: 1, threshold: THRESHOLD, want: true },
        // Observer / non-validator with peers and total silence: silent.
        AlarmCase { last_rx: 0, now: 18 * 24 * 3_600_000, is_validator: false, peers: 2, threshold: THRESHOLD, want: false },
        // Solo/dev stand (no configured peers) with total silence: silent.
        AlarmCase { last_rx: 0, now: 18 * 24 * 3_600_000, is_validator: true, peers: 0, threshold: THRESHOLD, want: false },
        // Non-validator AND no peers: silent.
        AlarmCase { last_rx: 0, now: 18 * 24 * 3_600_000, is_validator: false, peers: 0, threshold: THRESHOLD, want: false },
        // Clock skew (now < last_rx): saturates to zero silence, silent.
        AlarmCase { last_rx: 5_000, now: 1_000, is_validator: true, peers: 2, threshold: THRESHOLD, want: false },
        // Custom small threshold via env knob is honored as a parameter.
        AlarmCase { last_rx: 0, now: 1_001, is_validator: true, peers: 3, threshold: 1_000, want: true },
        AlarmCase { last_rx: 0, now: 1_000, is_validator: true, peers: 3, threshold: 1_000, want: false },
    ];
    for c in &cases {
        assert_eq!(
            should_liveness_alarm(c.last_rx, c.now, c.is_validator, c.peers, c.threshold),
            c.want,
            "last_rx={} now={} is_validator={} peers={} threshold={}",
            c.last_rx,
            c.now,
            c.is_validator,
            c.peers,
            c.threshold
        );
    }
}

#[test]
fn throttle_allows_one_line_per_minute() {
    // Never emitted: always due.
    assert!(liveness_alarm_due(None, 0));
    assert!(liveness_alarm_due(None, u64::MAX));
    // Just emitted: held.
    assert!(!liveness_alarm_due(Some(1_000), 1_000));
    assert!(!liveness_alarm_due(Some(1_000), 1_000 + 59_999));
    // BOUNDARY: a full throttle window elapsed is due again.
    assert!(liveness_alarm_due(
        Some(1_000),
        1_000 + LIVENESS_ALARM_THROTTLE_MS
    ));
    assert!(liveness_alarm_due(
        Some(1_000),
        1_000 + LIVENESS_ALARM_THROTTLE_MS + 1
    ));
    // Clock skew (now < last emit): saturates, held.
    assert!(!liveness_alarm_due(Some(5_000), 1_000));
}

#[test]
fn counter_increments_process_wide() {
    // Relative assertion: no reset helper exists (and none is needed), so
    // parallel tests sharing the process counter cannot break this.
    let before = liveness_alarm_count();
    let n = note_liveness_alarm();
    assert_eq!(n, before + 1);
    assert_eq!(liveness_alarm_count(), before + 1);
    let m = note_liveness_alarm();
    assert_eq!(m, before + 2);
    assert_eq!(liveness_alarm_count(), before + 2);
}

#[test]
fn wall_clock_is_sane_and_monotonic() {
    let a = alarm_now_ms();
    let b = alarm_now_ms();
    // Past the epoch, and non-decreasing across consecutive reads.
    assert!(a > 0);
    assert!(b >= a);
}
