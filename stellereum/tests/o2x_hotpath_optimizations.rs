//! Differential tests for O2x measurement-driven optimisations.
//!
//! Each test pins an observable that MUST NOT move when the optimisation is
//! active: the vote verdict (and the no-crypto cache-hit property), the
//! transaction-batch verdict on a one-worker Rayon pool, and the state root
//! when the tokens-domain SHA-256 midstate is reused.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::commitment::Domain;
use stellereum::consensus::{
    clear_verified_vote_cache, register_validator_pq_key, verified_vote_cache_reset_stats,
    verified_vote_cache_stats, ValidatorSet, Vote, VoteKind, VoteSet,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const SHARD: u32 = MASTERCHAIN_SHARD;

fn seed32(tag: u64) -> [u8; 32] {
    let mut s = [0x6Bu8; 32];
    s[..8].copy_from_slice(&tag.to_le_bytes());
    s[31] = (tag >> 8) as u8;
    s
}

fn fixture() -> (SigningKey, FalconKeypair, ValidatorSet, [u8; 32]) {
    let sk = SigningKey::from_bytes(&seed32(0x0201));
    let fk = FalconKeypair::generate_from_seed_bytes(&seed32(0x0202));
    let id = sk.verifying_key().to_bytes();
    register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());
    let mut vs = ValidatorSet::new();
    vs.add(id, 1);
    (sk, fk, vs, id)
}

/// A vote verified once by `VoteSet::add` must NOT be re-verified by
/// `observe_peer_vote`: both consult the same process-wide verdict cache, so
/// the second look is a HIT with zero misses (no Falcon verify at all).
#[test]
fn o2x_observe_peer_vote_shares_the_add_verdict_cache() {
    clear_verified_vote_cache();
    let (sk, fk, vs, _id) = fixture();
    let vote = Vote::sign_with_falcon_in_shard(
        &sk,
        &fk,
        SHARD,
        1,
        0,
        VoteKind::Prevote,
        Some(seed32(0x0303)),
    );

    // First admission: cold (full Falcon verify).
    verified_vote_cache_reset_stats();
    let mut set = VoteSet::new();
    set.add(vote.clone(), &vs, 1, 0, VoteKind::Prevote)
        .expect("honest vote is admitted");
    let (_hits, misses) = verified_vote_cache_stats();
    assert!(misses >= 1, "the first admission must verify crypto");

    // `observe_peer_vote` on the SAME bytes: shared-cache hit, no miss.
    let engine = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(sk.clone(), vs.clone(), engine, 1);
    verified_vote_cache_reset_stats();
    assert!(rt.observe_peer_vote(&vote), "member vote is observed");
    let (hits, misses) = verified_vote_cache_stats();
    assert_eq!(misses, 0, "observe_peer_vote must not re-run Falcon verify");
    assert_eq!(
        hits, 1,
        "the shared verdict cache must serve the observe path"
    );

    // And a second VoteSet admission of the same bytes is also a hit.
    verified_vote_cache_reset_stats();
    let mut set2 = VoteSet::new();
    set2.add(vote, &vs, 1, 0, VoteKind::Prevote)
        .expect("re-admission keeps the verdict");
    let (hits, misses) = verified_vote_cache_stats();
    assert_eq!(misses, 0, "re-admission must be a cache hit");
    assert!(hits >= 1);
    assert_eq!(set.len(), 1);
    assert_eq!(set2.len(), 1);
}

/// The tiny-batch / one-worker sequential paths must return exactly the
/// sequential verdicts: same `all` result, same per-item vector, same order.
#[test]
fn o2x_one_worker_rayon_paths_match_sequential_verdicts() {
    let (sk, fk, _vs, id) = fixture();
    // Mixed valid/invalid votes (an invalid signature in the middle must be
    // found by both paths).
    let mut votes: Vec<Vote> = (0..24u64)
        .map(|i| {
            Vote::sign_with_falcon_in_shard(
                &sk,
                &fk,
                SHARD,
                1,
                i as u32,
                VoteKind::Prevote,
                Some(seed32(0x0400 + i)),
            )
        })
        .collect();
    votes[7].signature[100] ^= 0xFF; // corrupt one Falcon signature byte

    clear_verified_vote_cache();
    let sequential_all = votes.iter().all(|v| v.verify());
    clear_verified_vote_cache();
    let sequential_partition: Vec<bool> = votes.iter().map(|v| v.verify()).collect();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("one-thread pool");
    clear_verified_vote_cache();
    let (parallel_all, parallel_partition) =
        pool.install(|| (Vote::verify_batch(&votes), Vote::partition_valid(&votes)));
    assert_eq!(parallel_all, sequential_all);
    assert_eq!(parallel_partition, sequential_partition);
    assert!(!sequential_all, "the corrupted vote must fail the batch");
    assert_eq!(sequential_partition.iter().filter(|v| **v).count(), 23);
    // Member id sanity (the fixture key is the voter for every vote).
    assert!(votes.iter().all(|v| v.voter == id));
}

/// Transaction batch screens: 20 PQ transactions is above the 16-item chunk
/// threshold, so the one-worker pool takes the sequential fallback. Verdict
/// and partition must equal the serial reference exactly.
#[test]
fn o2x_one_worker_transaction_screen_matches_serial() {
    let fk = FalconKeypair::generate_from_seed_bytes(&seed32(0x0505));
    let txs: Vec<Transaction> = (0..20u64).map(|i| make_pq_tx(&fk, i)).collect();
    let serial_all = Transaction::verify_signatures_batch(&txs);
    let serial_partition: Vec<bool> = txs.iter().map(Transaction::verify_signature).collect();
    assert!(serial_all);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("one-thread pool");
    let (parallel_all, parallel_partition) = pool.install(|| {
        (
            Transaction::verify_signatures_batch_parallel(&txs),
            Transaction::verify_signatures_partitioned(&txs),
        )
    });
    assert_eq!(parallel_all, serial_all);
    assert_eq!(parallel_partition, serial_partition);
}

fn make_pq_tx(fk: &FalconKeypair, nonce: u64) -> Transaction {
    use stellereum::post_quantum::derive_pq_address;
    let addr = derive_pq_address(
        PqScheme::Falcon512,
        &fk.public_key,
        &stellereum::post_quantum::DEFAULT_SALT,
    );
    let skeleton = Transaction {
        from: addr,
        to: [9u8; 32],
        amount: 1,
        gas_limit: 3_000_000,
        nonce,
        source_shard: SHARD,
        target_shard: SHARD,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = skeleton.signing_message();
    let sig = fk.sign(&msg);
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        fk.public_key.clone(),
        sig,
        [9u8; 32],
        1,
        3_000_000,
        nonce,
        SHARD,
        SHARD,
        Vec::new(),
        &stellereum::post_quantum::DEFAULT_SALT,
    )
}

/// State-root differential for the tokens-midstate fold: rebuilding the
/// STAKING domain (which is what a block reward does) while the token
/// registry is unchanged must leave the root exactly where it was, and a real
/// token change must move it. That is precisely the case the cached
/// `version || tokens` SHA-256 state is allowed to skip.
#[test]
fn o2x_tokens_midstate_preserves_state_root_across_unchanged_folds() {
    use stellereum::token::{TokenActor, TokenMetadata, TokenRegistry};
    let paul = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let engine = Arc::new(InMemoryStateEngine::new());
    paul.block_on(async {
        let mut reg = TokenRegistry::new();
        for i in 0..64u64 {
            let id = seed32(0x0700 + i);
            let md = TokenMetadata {
                name: format!("tok{i}"),
                symbol: format!("T{i}"),
                decimals: 8,
                total_supply: 1_000_000,
                max_supply: None,
                minter: [i as u8; 32],
                paused: false,
                description: String::new(),
            };
            let mut actor = TokenActor::new(id, md, 1_000_000).expect("metadata");
            for j in 0..8u64 {
                actor.balances.insert(seed32(0x0800 + j), i * 1000 + j);
            }
            reg.tokens.insert(id, actor);
        }
        reg.next_nonce = 64;
        *engine.tokens_write().await = reg;
    });

    let r1 = paul.block_on(async { engine.get_state_root().await });
    // Build the midstate with a fold that sees the tokens domain as a cache
    // hit on the next call.
    let r1_again = paul.block_on(async { engine.get_state_root().await });
    assert_eq!(r1, r1_again, "repeat root reads must be stable");
    let hits_before = engine.commitment_midstate_reuse_hits();

    // A staking generation bump with UNCHANGED ledger bytes: the staking
    // preimage is rebuilt from identical content, tokens is unchanged and the
    // cached midstate is eligible. The root is a pure function of content, so
    // it must not move.
    engine.bump_domain_generation(Domain::Staking);
    let r2 = paul.block_on(async { engine.get_state_root().await });
    assert_eq!(
        r1, r2,
        "unchanged staking content must not move the root through the midstate path"
    );
    assert!(
        engine.commitment_midstate_reuse_hits() > hits_before,
        "the staking-only fold must actually reuse the tokens midstate"
    );

    // Now change real token content: the generation moves, the midstate is
    // not eligible, and the root MUST move.
    paul.block_on(async {
        let mut reg = engine.tokens_write().await;
        let id = seed32(0x0700);
        if let Some(actor) = reg.tokens.get_mut(&id) {
            actor.balances.insert([0x77; 32], 42);
        }
    });
    let r3 = paul.block_on(async { engine.get_state_root().await });
    assert_ne!(r1, r3, "a real token change must move the root");

    // One more unchanged staking fold after the token change: stable again.
    engine.bump_domain_generation(Domain::Staking);
    let r4 = paul.block_on(async { engine.get_state_root().await });
    assert_eq!(
        r3, r4,
        "root is stable again after the token change settles"
    );
}
