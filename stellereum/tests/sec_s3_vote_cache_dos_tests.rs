//! SEC-S3 regression: the verified-vote cache must not retain attacker-sized
//! signature blobs.
//!
//! `Vote::verify` caches a verdict keyed on the vote's ENTIRE `signature`
//! vector, while `VERIFIED_VOTE_CACHE_CAP` bounds entry COUNT (65,536), not
//! bytes. Vote signatures arrive over the consensus wire (up to
//! `MAX_CONSENSUS_MSG` = 32 MiB per message) and member validator ids are
//! public, so before this fix a handful of messages carrying huge, never-
//! verifiable signatures could pin hundreds of MiB in every node's cache.
//!
//! The fix refuses an over-long signature BEFORE building a cache key: an
//! oversized signature can never verify (`falcon_signature()` is `None`), so
//! the verdict is unchanged — only the retention is gone. Small invalid
//! shapes are still cached, so the fail-closed verdict cache behavior is
//! untouched.

use stellereum::consensus::{
    clear_verified_vote_cache, verified_vote_cache_len, Vote, VoteKind, VOTE_FALCON_PART_LEN,
};

#[test]
fn oversized_vote_signature_is_refused_without_entering_the_verdict_cache() {
    // This binary is its own test process, and this is its only test touching
    // the process-global vote cache.
    clear_verified_vote_cache();

    let voter = [0x11u8; 32];
    let oversized = vec![0x5Au8; 4 * 1024 * 1024];
    let mut vote = Vote::signed_with(
        voter,
        1,
        0,
        VoteKind::Prevote,
        Some([0xABu8; 32]),
        oversized,
    );
    assert!(
        vote.signature.len() > VOTE_FALCON_PART_LEN,
        "fixture precondition: signature exceeds the canonical envelope"
    );
    assert!(
        !vote.verify(),
        "an oversized vote signature can never verify"
    );
    assert_eq!(
        verified_vote_cache_len(),
        0,
        "the verdict cache must not retain the attacker-sized signature blob (entry-count cap is not a byte cap)"
    );

    // The fix is narrow: a bounded invalid signature is still cached (verdict
    // false, repeated work deduped), exactly as before.
    vote.signature = vec![0x5Au8; 64];
    assert!(!vote.verify(), "a bare 64-byte blob is not a Falcon half");
    assert_eq!(
        verified_vote_cache_len(),
        1,
        "bounded invalid votes keep the pre-existing fail-closed cache behavior"
    );
}
