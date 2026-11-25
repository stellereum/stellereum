use super::InMemoryStateEngine;
use std::sync::atomic::{AtomicU64, Ordering};

mod actor;
mod block;
mod fees_rewards;
mod governance_pq;
mod hashpool_ops;
mod tx_exec;

// ============================================================================
// S4 perf instrumentation (observational only)
// ============================================================================
//
// These counters exist so the regression tests can PIN a structural property
// of the execution hot path ("one governed-policy snapshot per payload", "the
// actor mailbox pass takes no write lock on the common block") instead of
// relying on wall-clock timings. They are plain relaxed atomics on cold
// branches - no ordering, no state root, no return value depends on them - and
// are only ever read by `#[doc(hidden)]` accessors below.

/// How many times one PAYLOAD resolved its governed policy snapshot.
pub(super) static GOV_PAYLOAD_SNAPSHOTS: AtomicU64 = AtomicU64::new(0);
/// How many blocks took the read-only "no queued actor message" fast path.
pub(super) static ACTOR_MAILBOX_READ_FAST_PATHS: AtomicU64 = AtomicU64::new(0);

impl InMemoryStateEngine {
    /// S4 perf instrumentation: governed-policy snapshots taken per payload
    /// execution (must be exactly one - `tests/perf_s4_execution_hot_path.rs`).
    #[doc(hidden)]
    pub fn perf_s4_gov_payload_snapshots() -> u64 {
        GOV_PAYLOAD_SNAPSHOTS.load(Ordering::Relaxed)
    }

    /// S4 perf instrumentation: block mailbox passes that returned from the
    /// read-only "nothing queued" check without taking the accounts write
    /// lock.
    #[doc(hidden)]
    pub fn perf_s4_actor_mailbox_read_fast_paths() -> u64 {
        ACTOR_MAILBOX_READ_FAST_PATHS.load(Ordering::Relaxed)
    }
}
