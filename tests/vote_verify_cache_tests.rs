//! Verified-vote cache (verify-once for votes): fixed-fixture ingest probe +
//! cache-behavior suites.
//!
//! * `vote_ingest_baseline_timing_reports`: fixed-fixture `VoteSet::add`
//!   ingest timing (first pass = full verify, second pass = cache hits).
//! * hit path, stale-entry-after-set-change MUST miss, cross-round confusion
//!   misses, equivocating votes never counted twice, forgery fail-closed,
//!   batch hit path, invalidation hook.
//!
//! The cache is process-global, so the tests serialize on `TEST_LOCK` and use
//! fresh random keys per test; stats are asserted as deltas.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{
    Vote, VoteKind, VoteSet, ValidatorSet, clear_verified_vote_cache,
    invalidate_verified_vote_cache, verified_vote_cache_len, verified_vote_cache_reset_stats,
    verified_vote_cache_stats,
};
use std::time::Instant;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixture(n: usize) -> (Vec<SigningKey>, ValidatorSet, Vec<Vote>) {
    let keys: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let vs = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let votes: Vec<Vote> = keys
        .iter()
        .map(|k| Vote::sign(k, 1, 0, VoteKind::Prevote, Some([7u8; 32])))
        .collect();
    (keys, vs, votes)
}

fn clean() {
    clear_verified_vote_cache();
    invalidate_verified_vote_cache();
    verified_vote_cache_reset_stats();
}

#[test]
fn vote_ingest_baseline_timing_reports() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let n = 2000usize;
    let (_keys, vs, votes) = fixture(n);
    // Warm up (page in code, settle allocator).
    {
        let mut warm = VoteSet::new();
        for v in votes.iter().take(10).cloned() {
            let _ = warm.add(v, &vs, 1, 0, VoteKind::Prevote);
        }
    }
    clean();
    // Pass 1: cold cache — every vote fully verifies (misses).
    let mut set = VoteSet::new();
    let t = Instant::now();
    for v in votes.clone() {
        let _ = set.add(v, &vs, 1, 0, VoteKind::Prevote);
    }
    let secs_cold = t.elapsed().as_secs_f64();
    let (hits1, misses1) = verified_vote_cache_stats();
    assert_eq!(set.len(), n);
    assert_eq!(hits1, 0, "cold pass must not hit");
    assert!(misses1 >= n as u64, "cold pass must fully verify every vote");

    // Pass 2: same bytes, fresh set, same validators — cache hits, no crypto.
    verified_vote_cache_reset_stats();
    let mut set2 = VoteSet::new();
    let t2 = Instant::now();
    for v in votes {
        let _ = set2.add(v, &vs, 1, 0, VoteKind::Prevote);
    }
    let secs_hot = t2.elapsed().as_secs_f64();
    let (hits2, misses2) = verified_vote_cache_stats();
    assert_eq!(set2.len(), n);
    assert_eq!(misses2, 0, "hot pass must skip crypto entirely");
    assert!(hits2 >= n as u64, "hot pass must hit for every vote");

    eprintln!(
        "VOTE-INGEST-PROBE n={n} cold={secs_cold:.3}s ({:.1}us/vote, {:.0} vote/s) hot={secs_hot:.3}s ({:.1}us/vote, {:.0} vote/s) speedup={:.1}x",
        secs_cold * 1e6 / n as f64,
        n as f64 / secs_cold,
        secs_hot * 1e6 / n as f64,
        n as f64 / secs_hot,
        secs_cold / secs_hot.max(1e-9),
    );
    assert!(
        secs_hot <= secs_cold,
        "never-slower gate: hot ingest ({secs_hot:.3}s) must not exceed cold ({secs_cold:.3}s)"
    );
}

#[test]
fn verified_vote_hit_path_skips_crypto() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let sk = SigningKey::generate(&mut OsRng);
    let vote = Vote::sign(&sk, 11, 3, VoteKind::Prevote, Some([9u8; 32]));
    assert!(vote.verify(), "fixture must verify");
    let (hits, misses) = verified_vote_cache_stats();
    assert_eq!((hits, misses), (0, 1));
    // Identical bytes under identical context: hit, same verdict, no crypto.
    assert!(vote.verify());
    assert!(vote.verify());
    let (hits2, misses2) = verified_vote_cache_stats();
    assert_eq!(hits2, 2, "re-verifies must hit");
    assert_eq!(misses2, 1, "re-verifies must not re-verify");
    assert!(verified_vote_cache_len() >= 1);
}

#[test]
fn stale_entry_after_set_change_must_miss() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let sk = SigningKey::generate(&mut OsRng);
    let voter = sk.verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(voter, 1)]);
    let vote = Vote::sign(&sk, 21, 0, VoteKind::Prevote, Some([1u8; 32]));

    let mut set = VoteSet::new();
    assert!(set.add(vote.clone(), &vs, 21, 0, VoteKind::Prevote).is_ok());
    assert_eq!(verified_vote_cache_stats().1, 1);

    // Membership revoked: same bytes must MISS (set digest changed → clear)
    // and must be REFUSED (membership re-checked outside the cache).
    verified_vote_cache_reset_stats();
    let vs_empty = ValidatorSet::new();
    let mut set2 = VoteSet::new();
    let res = set2.add(vote.clone(), &vs_empty, 21, 0, VoteKind::Prevote);
    assert!(res.is_err(), "non-member vote must be refused after set change");
    let (hits, misses) = verified_vote_cache_stats();
    assert_eq!(hits, 0, "stale entry must not hit after set change");
    assert!(misses >= 1, "set change must force full re-verify");

    // Power change (still a member): MISS + admit with the NEW power.
    verified_vote_cache_reset_stats();
    let vs_big = ValidatorSet::from_list(vec![(voter, 42)]);
    let mut set3 = VoteSet::new();
    assert!(set3.add(vote.clone(), &vs_big, 21, 0, VoteKind::Prevote).is_ok());
    let (hits3, misses3) = verified_vote_cache_stats();
    assert_eq!(hits3, 0, "power change must miss");
    assert!(misses3 >= 1);
    assert_eq!(set3.power_for(Some([1u8; 32])), 42);
}

#[test]
fn cross_round_confusion_misses() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let sk = SigningKey::generate(&mut OsRng);
    let va = Vote::sign(&sk, 31, 0, VoteKind::Prevote, Some([5u8; 32]));
    let vb = Vote::sign(&sk, 31, 1, VoteKind::Prevote, Some([5u8; 32]));
    assert!(va.verify());
    assert_eq!(verified_vote_cache_stats(), (0, 1));
    // Same voter, same target, different round: different key → miss.
    assert!(vb.verify());
    assert_eq!(verified_vote_cache_stats(), (0, 2));
    // And the round-0 verdict is still cached intact.
    assert!(va.verify());
    assert_eq!(verified_vote_cache_stats(), (1, 2));

    // Same round, different target (equivocating shape): also a miss.
    let vc = Vote::sign(&sk, 31, 0, VoteKind::Prevote, Some([6u8; 32]));
    assert!(vc.verify());
    assert_eq!(verified_vote_cache_stats(), (1, 3));
}

#[test]
fn equivocating_votes_never_count_twice_from_cache() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let sk = SigningKey::generate(&mut OsRng);
    let voter = sk.verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(voter, 7)]);
    let a = Vote::sign(&sk, 41, 2, VoteKind::Precommit, Some([0xAAu8; 32]));
    let b = Vote::sign(&sk, 41, 2, VoteKind::Precommit, Some([0xBBu8; 32]));
    assert!(a.verify() && b.verify(), "both equivocating votes are genuinely signed");

    let mut set = VoteSet::new();
    assert!(set.add(a.clone(), &vs, 41, 2, VoteKind::Precommit).is_ok());
    // Second, conflicting vote: signature valid (possibly a cache hit), but
    // first-vote-wins — power counted ONCE, equivocation recorded ONCE.
    assert!(set.add(b.clone(), &vs, 41, 2, VoteKind::Precommit).is_ok());
    assert_eq!(set.power_for(Some([0xAAu8; 32])), 7);
    assert_eq!(set.power_for(Some([0xBBu8; 32])), 0);
    assert_eq!(set.equivocations().len(), 1);
    // Rebroadcasting the same pair records nothing new (no 0.95^N drain).
    assert!(set.add(b.clone(), &vs, 41, 2, VoteKind::Precommit).is_ok());
    assert!(set.add(a.clone(), &vs, 41, 2, VoteKind::Precommit).is_ok());
    assert_eq!(set.equivocations().len(), 1);
    assert_eq!(set.len(), 1);
}

#[test]
fn forged_vote_fail_closed_and_never_valid() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let sk = SigningKey::generate(&mut OsRng);
    let voter = sk.verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(voter, 1)]);
    let mut bad = Vote::sign(&sk, 51, 0, VoteKind::Prevote, Some([3u8; 32]));
    bad.signature[7] ^= 0xFF;
    assert!(!bad.verify(), "forgery must not verify");
    assert_eq!(verified_vote_cache_stats(), (0, 1));
    // Cached refusal: still false, served as a hit — never as valid.
    assert!(!bad.verify());
    assert_eq!(verified_vote_cache_stats(), (1, 1));
    let mut set = VoteSet::new();
    assert!(set.add(bad, &vs, 51, 0, VoteKind::Prevote).is_err());
    assert_eq!(set.len(), 0);
}

#[test]
fn batch_path_hits_and_matches_scalar() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let (_keys, vs, votes) = fixture(64);
    let flags = Vote::partition_valid(&votes);
    assert!(flags.iter().all(|b| *b));
    let (h1, m1) = verified_vote_cache_stats();
    assert_eq!(h1, 0);
    assert!(m1 >= votes.len() as u64);

    // Same batch again: all cached, identical flags, zero crypto.
    verified_vote_cache_reset_stats();
    let flags2 = Vote::partition_valid(&votes);
    assert_eq!(flags, flags2);
    let (h2, m2) = verified_vote_cache_stats();
    assert_eq!(m2, 0, "cached batch must skip crypto");
    assert_eq!(h2, votes.len() as u64);

    // VoteSet::add_batch agrees with sequential add on the same input.
    let mut batched = VoteSet::new();
    let res = batched.add_batch(votes.clone(), &vs, 1, 0, VoteKind::Prevote);
    assert!(res.iter().all(|r| r.is_ok()));
    assert_eq!(batched.len(), votes.len());
}

#[test]
fn invalidation_hook_forces_reverify() {
    let _guard = TEST_LOCK.lock().unwrap();
    clean();
    let sk = SigningKey::generate(&mut OsRng);
    let vote = Vote::sign(&sk, 61, 0, VoteKind::Prevote, None);
    assert!(vote.verify());
    assert!(vote.verify());
    assert_eq!(verified_vote_cache_stats(), (1, 1));
    invalidate_verified_vote_cache();
    assert_eq!(verified_vote_cache_len(), 0);
    assert!(vote.verify(), "verdict unchanged after invalidation");
    assert_eq!(verified_vote_cache_stats(), (1, 2), "invalidation must force a miss");
}
