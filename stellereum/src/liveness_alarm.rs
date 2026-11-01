//! Fail-loud consensus-traffic liveness alarm (pure decision + counter).
//!
//! AUDIT NOTE: a production validator was silently isolated from consensus
//! for 18 days — wrong pubsub topic (single-shard vs sharded), zero
//! votes/proposals received, and NOTHING in any log indicated the isolation.
//! This module is the fail-loud answer: a validator with configured peers
//! that consumes no consensus Proposal/Vote traffic for
//! [`LIVENESS_ALARM_SILENCE_MS`] screams on stderr instead of churning
//! silently.
//!
//! LIVENESS-ONLY BY CONSTRUCTION: everything here reads clocks and an
//! in-memory counter. Nothing here touches consensus state, the wire format,
//! quorum accounting, or the catch-up path. The drain loop in `src/main.rs`
//! owns all state and wiring; this file only decides and counts so the
//! decision is unit-testable without a node.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Silence without ANY consumed consensus Proposal/Vote before a validator
/// with configured peers screams. Default 300_000 ms (5 minutes); override
/// with `STELL_LIVENESS_ALARM_MS` (a positive integer, same env-knob shape
/// as `STELL_CATCHUP_BUDGET_MS` — node-local policy, nodes MAY differ).
pub const LIVENESS_ALARM_SILENCE_MS: u64 = 300_000;

/// At most one alarm line per this interval (60s), so a days-long isolation
/// is one line a minute, not one per 50ms tick.
pub const LIVENESS_ALARM_THROTTLE_MS: u64 = 60_000;

/// Effective silence threshold: `STELL_LIVENESS_ALARM_MS` when set to a
/// positive integer, else [`LIVENESS_ALARM_SILENCE_MS`].
pub fn liveness_alarm_silence_ms() -> u64 {
    std::env::var("STELL_LIVENESS_ALARM_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(LIVENESS_ALARM_SILENCE_MS)
}

/// Wall-clock milliseconds since the UNIX epoch (saturates to 0 before it).
/// Only used to difference two nearby stamps; wrap/skew is absorbed by the
/// saturating subtraction in [`should_liveness_alarm`].
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Process-wide count of emitted liveness alarm lines (visibility only).
static LIVENESS_ALARM_N: AtomicU64 = AtomicU64::new(0);

/// How many liveness alarm lines this process has emitted so far.
pub fn liveness_alarm_count() -> u64 {
    LIVENESS_ALARM_N.load(Ordering::Relaxed)
}

/// Record one emitted liveness alarm line; returns the new process total.
pub fn note_liveness_alarm() -> u64 {
    LIVENESS_ALARM_N.fetch_add(1, Ordering::Relaxed) + 1
}

/// Pure alarm decision: scream only when ALL hold —
///  * `is_validator`: the node is a validator (the caller passes the same
///    `can_vote` franchise the consensus loop already computed — config OR
///    ledger membership minus the stale gate — never a reinvented role);
///  * `peer_count > 0`: at least one peer is configured (a solo/dev stand
///    with no peers must never alarm);
///  * `now_ms - last_rx_ms > silence_threshold_ms`: no Proposal/Vote envelope
///    was consumed for longer than the threshold. `last_rx_ms` stamps EVERY
///    consumed Proposal/Vote — accepted OR refused — because receipt alone
///    proves the transport delivers; strictly-greater so the boundary itself
///    stays silent.
pub fn should_liveness_alarm(
    last_rx_ms: u64,
    now_ms: u64,
    is_validator: bool,
    peer_count: usize,
    silence_threshold_ms: u64,
) -> bool {
    if !is_validator {
        return false;
    }
    if peer_count == 0 {
        return false;
    }
    now_ms.saturating_sub(last_rx_ms) > silence_threshold_ms
}

/// Pure throttle decision: at most one alarm line per
/// [`LIVENESS_ALARM_THROTTLE_MS`]. `None` (never emitted) is always due.
pub fn liveness_alarm_due(last_emit_ms: Option<u64>, now_ms: u64) -> bool {
    match last_emit_ms {
        None => true,
        Some(prev) => now_ms.saturating_sub(prev) >= LIVENESS_ALARM_THROTTLE_MS,
    }
}
