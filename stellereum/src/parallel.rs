//! Shared Rayon gate for the verification hot paths.
//!
//! Every existing parallel screen uses `par_iter()`/`par_chunks()` with a
//! fixed small-item threshold. On a single-vCPU node the global Rayon pool has
//! exactly one worker: the split/join machinery and the cross-thread task
//! hand-off buy nothing, while the sequential iterator short-circuits in the
//! same order and returns the identical verdict. This module is the one place
//! that answers "is a parallel split actually available?" so each call site
//! keeps its own item threshold but never pays the pool overhead when there is
//! no second core to use.
//!
//! Determinism: `par_iter().all(f)` and `iter().all(f)` agree for every `f`
//! (both are the AND of the per-item predicates; `all` may stop early in
//! either mode, which cannot change a boolean verdict), and
//! `par_iter().map(f).collect()` preserves input order just like the
//! sequential iterator. Choosing the path therefore cannot change a signal,
//! a verdict, an ordering or any wire/hash bytes.

/// True when the current Rayon context can actually run items on more than
/// one worker.
///
/// `rayon::current_num_threads()` is the authoritative answer: it returns the
/// size of the ambient pool inside `pool.install(...)`, and the global pool
/// size otherwise. The first call initializes the global pool exactly like
/// the first `par_iter()` would, so this does not add a thread that the
/// parallel path would not already have created.
#[inline]
pub fn multi_threaded() -> bool {
    rayon::current_num_threads() > 1
}

/// True when `items` is large enough to be worth splitting AND more than one
/// Rayon worker exists.
#[inline]
pub fn split_worthwhile(items: usize, min_items: usize) -> bool {
    items >= min_items && multi_threaded()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_worker_pool_answers_no_even_for_large_inputs() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("one-thread pool builds");
        pool.install(|| {
            assert!(!multi_threaded(), "one-worker pool must not split");
            assert!(!split_worthwhile(10_000, 4));
        });
    }

    #[test]
    fn multi_worker_pool_answers_yes_and_honours_the_item_floor() {
        let available = rayon::current_num_threads();
        if available < 2 {
            return; // this host cannot exercise the positive case
        }
        assert!(multi_threaded());
        assert!(!split_worthwhile(3, 4));
        assert!(split_worthwhile(4, 4));
    }

    #[test]
    fn sequential_and_parallel_verdicts_agree_inside_a_one_worker_pool() {
        // The predicate mirrors the vote screens: a mix of true/false items,
        // a short-circuiting `all`, and an order-preserving `map`.
        let items: Vec<u64> = (0..64).collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("one-thread pool builds");
        let (all_par, all_seq, mapped_par, mapped_seq) = pool.install(|| {
            use rayon::prelude::*;
            let par = if split_worthwhile(items.len(), 4) {
                items.par_iter().all(|v| v % 5 != 4)
            } else {
                items.iter().all(|v| v % 5 != 4)
            };
            let seq = items.iter().all(|v| v % 5 != 4);
            let mpar: Vec<bool> = if split_worthwhile(items.len(), 4) {
                items.par_iter().map(|v| v % 5 != 4).collect()
            } else {
                items.iter().map(|v| v % 5 != 4).collect()
            };
            let mseq: Vec<bool> = items.iter().map(|v| v % 5 != 4).collect();
            (par, seq, mpar, mseq)
        });
        assert_eq!(all_par, all_seq);
        assert_eq!(mapped_par, mapped_seq);
        assert!(!all_seq, "the mixed fixture must hit a false item");
    }
}
