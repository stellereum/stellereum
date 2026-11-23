//! Tokio runtime sizing for the node binary (single-vCPU sane defaults).
//!
//! Live evidence (2026-11-23): a node on a ONE-vCPU host ran with 539 threads
//! (528 named `tokio-rt-worker`, 7 `sled-io-*`). Tokio's blocking pool is
//! created with `max_blocking_threads = 512` by default and every idle/blocked
//! task in it keeps a thread, so the process paid scheduler and stack costs
//! for a pool sized for a 512-core machine. `#[tokio::main(worker_threads = 4)]`
//! was also hard-coded regardless of the host's core count.
//!
//! These limits are PURELY scheduling resources. They are not consensus
//! inputs: no wire byte, signature domain, block hash, quorum rule or state
//! root reads a thread count, and every task that runs on a worker or blocking
//! thread produces the same bytes no matter which thread executes it. Shrinking
//! the pool can only change WHEN work runs, never WHAT it computes.
//!
//! Sizing rules (derived from `available_parallelism`):
//! * async workers: `cores` clamped to `2..=4`. The floor of two keeps the
//!   consensus tick from starving the transport on a single-vCPU box (the
//!   starvation this binary's multi-thread runtime was introduced to fix);
//!   the ceiling of four is exactly today's behaviour on every host with four
//!   or more cores.
//! * blocking threads: `cores * 8` clamped to `16..=64`. Blocking work here is
//!   file I/O and serialization (sled persist, snapshot encode, sync walks).
//!   The floor of 16 keeps the consensus apply lane — itself a blocking task —
//!   from queueing behind a burst of network/storage writes on a one-vCPU box,
//!   while 64 keeps multi-core hosts far above any real fan-out and still
//!   bounds the pathological growth seen live.
//!
//! Both values can be overridden for an operator-side experiment with
//! `STELL_RUNTIME_WORKERS` / `STELL_RUNTIME_MAX_BLOCKING` (clamped to the same
//! bounds); unset means the host-derived value.

/// Runtime pool sizes derived from a host's usable core count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    /// Tokio async worker threads.
    pub worker_threads: usize,
    /// Tokio blocking-pool threads (in addition to the async workers).
    pub max_blocking_threads: usize,
}

/// Minimum async workers: one tick + one I/O worker on a single-vCPU host.
pub const MIN_WORKERS: usize = 2;
/// Upper bound on async workers (today's hard-coded value).
pub const MAX_WORKERS: usize = 4;
/// Minimum blocking-pool threads (apply lane must not queue behind I/O).
pub const MIN_BLOCKING: usize = 16;
/// Upper bound on blocking-pool threads.
pub const MAX_BLOCKING: usize = 64;

/// Derive the pool sizes from `cores` (clamped to at least one core).
pub fn from_core_count(cores: usize) -> RuntimeLimits {
    let cores = cores.max(1);
    RuntimeLimits {
        worker_threads: cores.clamp(MIN_WORKERS, MAX_WORKERS),
        max_blocking_threads: cores.saturating_mul(8).clamp(MIN_BLOCKING, MAX_BLOCKING),
    }
}

fn env_clamped(name: &str, min: usize, max: usize) -> Option<usize> {
    let parsed = std::env::var(name).ok()?.trim().parse::<usize>().ok()?;
    Some(parsed.clamp(min, max))
}

/// [`from_core_count`] for this host, with optional clamped env overrides.
pub fn detect() -> RuntimeLimits {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let mut limits = from_core_count(cores);
    if let Some(workers) = env_clamped("STELL_RUNTIME_WORKERS", MIN_WORKERS, MAX_WORKERS) {
        limits.worker_threads = workers;
    }
    if let Some(blocking) = env_clamped("STELL_RUNTIME_MAX_BLOCKING", MIN_BLOCKING, MAX_BLOCKING) {
        limits.max_blocking_threads = blocking;
    }
    limits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_cpu_no_longer_gets_a_512_thread_blocking_pool() {
        let l = from_core_count(1);
        assert_eq!(l.worker_threads, 2, "single core keeps two async workers");
        assert_eq!(l.max_blocking_threads, 16);
        assert!(
            l.max_blocking_threads < 512,
            "the live 528-thread process must not be reproducible"
        );
    }

    #[test]
    fn four_or_more_cores_keep_todays_worker_count() {
        for cores in [4usize, 8, 12, 64] {
            assert_eq!(from_core_count(cores).worker_threads, 4, "cores={cores}");
        }
    }

    #[test]
    fn blocking_pool_is_bounded_on_every_core_count() {
        for cores in 1..=256 {
            let l = from_core_count(cores);
            assert!((MIN_BLOCKING..=MAX_BLOCKING).contains(&l.max_blocking_threads));
            assert!((MIN_WORKERS..=MAX_WORKERS).contains(&l.worker_threads));
        }
    }

    #[test]
    fn zero_cores_is_treated_as_one() {
        assert_eq!(from_core_count(0), from_core_count(1));
    }
}
