//! S9 / S5 finding #7: at-tip RX-silence trigger.
//!
//! A validator at the tip that loses its INBOUND consensus stream keeps the
//! 120 s `AT_TIP_PROBE_INTERVAL_MS` backstop, but the downtime budget is
//! `42 × 800 ms = 33.6 s`, so it is jailed long before the probe fires. The
//! trigger under test (`policy::RX_SILENCE_PROBE_MS` /
//! `policy::at_tip_silence_due`) runs ONE bounded head/QC probe after a short
//! silence window and re-arms at most once per window.
//!
//! These are fake-clock tests: the helper is pure and takes `now_ms`, so no
//! node, runtime or wall-clock sleep is involved. The regressions they pin:
//!  * silence fires exactly once per window (not per tick);
//!  * steady traffic never fires;
//!  * a probe that found nothing does not loop;
//!  * the cadence is above zero and strictly faster than the 120 s backstop,
//!    with a bounded probe budget.
//!
//! `policy` is normally a binary module (`src/main.rs`); the `#[path]` include
//! is the same pattern other integration tests use for bin-only policy code.

#[allow(dead_code)]
#[path = "../src/node/policy.rs"]
mod policy;

use policy::{
    at_tip_silence_due, AT_TIP_PROBE_INTERVAL_MS, RX_SILENCE_PROBE_BUDGET_MS, RX_SILENCE_PROBE_MS,
};

/// Tick cadence used by the fake clock (a tick is far shorter than a window).
const TICK_MS: u64 = 50;

/// Run a fake tick loop, stamping a probe whenever the helper says it is due.
/// Returns the firing instants. `traffic_every_ms` (when `Some(n)`) models a
/// consensus frame every `n` ms; `None` models a silent inbound stream.
fn simulate(duration_ms: u64, traffic_every_ms: Option<u64>) -> Vec<u64> {
    let mut now = 0u64;
    let mut last_rx = 0u64;
    let mut last_probe = 0u64;
    let mut fires = Vec::new();
    while now <= duration_ms {
        if traffic_every_ms.is_some_and(|every| every > 0 && now.is_multiple_of(every)) {
            last_rx = now;
        }
        if at_tip_silence_due(now, last_rx, last_probe) {
            fires.push(now);
            last_probe = now;
        }
        now += TICK_MS;
    }
    fires
}

#[test]
fn h9_silence_triggers_exactly_once_per_window() {
    let fires = simulate(RX_SILENCE_PROBE_MS * 3 + 2 * TICK_MS, None);
    assert_eq!(
        fires,
        vec![
            RX_SILENCE_PROBE_MS,
            RX_SILENCE_PROBE_MS * 2,
            RX_SILENCE_PROBE_MS * 3,
        ],
        "one probe per full silence window, never one per tick"
    );
    for pair in fires.windows(2) {
        assert!(
            pair[1] - pair[0] >= RX_SILENCE_PROBE_MS,
            "two silence probes fired inside one window: {pair:?}"
        );
    }
}

#[test]
fn h9_steady_traffic_never_triggers() {
    // Frames every 400 ms: far inside the silence window, as on a live chain.
    let fires = simulate(10 * AT_TIP_PROBE_INTERVAL_MS, Some(400));
    assert!(
        fires.is_empty(),
        "a node receiving consensus frames must never run the silence probe: {fires:?}"
    );
}

#[test]
fn h9_a_probe_that_finds_nothing_does_not_loop() {
    // A probe at the first window boundary finds nothing. The next tick (and
    // every tick until the window rolls over) must stay quiet instead of
    // re-firing at tick cadence.
    let probe_at = RX_SILENCE_PROBE_MS;
    let mut last_probe = probe_at;
    let mut fires = 0u64;
    let mut now = probe_at;
    while now + TICK_MS < RX_SILENCE_PROBE_MS * 2 {
        now += TICK_MS;
        if at_tip_silence_due(now, 0, last_probe) {
            fires += 1;
            last_probe = now;
        }
    }
    assert_eq!(
        fires, 0,
        "a miss must not re-fire before the next window (got {fires} probes)"
    );
    assert!(
        at_tip_silence_due(RX_SILENCE_PROBE_MS * 2, 0, last_probe),
        "the next window boundary must be allowed to probe again"
    );
}

#[test]
#[allow(clippy::assertions_on_constants)] // GATE: this test pins compile-time policy bounds on purpose.
fn h9_bound_is_respected_and_bounded_below_the_backstop() {
    // Exact boundary: one window of silence is due, one millisecond less is not.
    assert!(!at_tip_silence_due(RX_SILENCE_PROBE_MS - 1, 0, 0));
    assert!(at_tip_silence_due(RX_SILENCE_PROBE_MS, 0, 0));

    // The probe re-arm is a full window, not the tick cadence.
    assert!(!at_tip_silence_due(
        RX_SILENCE_PROBE_MS * 2 - 1,
        0,
        RX_SILENCE_PROBE_MS
    ));
    assert!(at_tip_silence_due(
        RX_SILENCE_PROBE_MS * 2,
        0,
        RX_SILENCE_PROBE_MS
    ));

    // A backwards clock (now < last_rx / last_probe) is never due: the
    // fail-safe direction, so a clock jump cannot cause a probe storm.
    assert!(!at_tip_silence_due(5, 100, 0));
    assert!(!at_tip_silence_due(5, 0, 100));

    // The trigger is a bound, not a hot loop: it is strictly faster than the
    // 120 s backstop (the jail budget is 33.6 s) and the probe budget is one
    // bounded WAN round trip.
    assert!(RX_SILENCE_PROBE_MS > 0);
    assert!(
        RX_SILENCE_PROBE_MS < AT_TIP_PROBE_INTERVAL_MS,
        "silence trigger must fire before the 120 s at-tip backstop"
    );
    assert!(
        RX_SILENCE_PROBE_MS * 3 < AT_TIP_PROBE_INTERVAL_MS,
        "the trigger must leave the 120 s backstop as the only long cadence"
    );
    assert!(RX_SILENCE_PROBE_BUDGET_MS > 0);
    assert!(
        RX_SILENCE_PROBE_BUDGET_MS <= 1_000,
        "the silence probe must stay a bounded head/QC read, got {RX_SILENCE_PROBE_BUDGET_MS}ms"
    );
}

#[test]
fn h9_a_frame_inside_the_window_resets_the_silence_clock() {
    // The last frame landed at window - 1ms: not due at the boundary, due only
    // one full window after the FRAME (not after the previous probe).
    let last_rx = RX_SILENCE_PROBE_MS - 1;
    assert!(!at_tip_silence_due(RX_SILENCE_PROBE_MS, last_rx, 0));
    assert!(!at_tip_silence_due(RX_SILENCE_PROBE_MS * 2 - 2, last_rx, 0));
    assert!(at_tip_silence_due(RX_SILENCE_PROBE_MS * 2 - 1, last_rx, 0));
}
