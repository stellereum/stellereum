//! Measurement for the O2x tokens-midstate fold (report, not a gate).
//!
//!     cargo test --release --offline --test o2x_tokens_midstate_bench -- --nocapture
//!
//! The engine's per-block commitment fold is
//! `SHA-256(version || tokens || staking || ... )`. Tokens is the first and
//! normally largest domain; staking is the one that moves every block (the
//! proposer's pending reward). Resuming from the cached `version || tokens`
//! SHA-256 state skips re-hashing a token registry that did not change.
//!
//! This file prices exactly that skip on two registry sizes. No timing
//! assertion: the digest equality assertion is the correctness gate.

use std::time::Instant;
use stellereum::commitment::{
    assemble_cached_digest_with_all_domains, assemble_cached_digest_with_all_domains_midstate,
};

fn det32(seed: u8, i: u64) -> [u8; 32] {
    let mut b = [seed; 32];
    b[..8].copy_from_slice(&i.to_be_bytes());
    b
}

/// A token preimage with `n` tokens x 8 balances: the same shape the live
/// `tokens_preimage` builds (per-token metadata + sorted balances).
fn tokens_preimage_bytes(n: u64) -> Vec<u8> {
    use stellereum::token::{TokenActor, TokenMetadata, TokenRegistry};
    let mut reg = TokenRegistry::new();
    for i in 0..n {
        let id = det32(0x70, i);
        let md = TokenMetadata {
            name: format!("token-{i}"),
            symbol: format!("T{i}"),
            decimals: 8,
            total_supply: 1_000_000 + i,
            max_supply: None,
            minter: [i as u8; 32],
            paused: false,
            description: String::new(),
        };
        let mut actor = TokenActor::new(id, md, 1_000_000).expect("valid metadata");
        for j in 0..8u64 {
            actor.balances.insert(det32(0xA1, j), i * 1000 + j);
        }
        reg.tokens.insert(id, actor);
    }
    reg.next_nonce = n;
    stellereum::commitment::tokens_preimage(&reg)
}

fn median_ns(reps: usize, mut f: impl FnMut()) -> f64 {
    f(); // warm up
    let mut v = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        f();
        v.push(t.elapsed().as_nanos() as f64);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn domains_of(tokens: &[u8]) -> [&[u8]; 13] {
    [
        tokens,
        b"staking-preimage",
        b"pmm",
        b"contracts",
        b"escrow",
        b"governance",
        b"oracle",
        b"",
        b"books",
        b"",
        b"cross-shard",
        b"",
        b"zkml",
    ]
}

#[test]
fn o2x_tokens_midstate_bench_small_and_large_registries() {
    for n in [200u64, 5_000] {
        let tokens = tokens_preimage_bytes(n);
        let domains = domains_of(&tokens);
        let full = median_ns(15, || {
            let d = assemble_cached_digest_with_all_domains(domains, b"cnvrf", 7, b"evm", b"pq");
            std::hint::black_box(d);
        });
        let (_, midstate) = assemble_cached_digest_with_all_domains_midstate(
            None, domains, b"cnvrf", 7, b"evm", b"pq",
        );
        // The steady-state call: tokens unchanged, everything after it may be
        // re-hashed. `domains[0]` is empty on purpose — the prefix comes from
        // the midstate.
        let resumed_domains = domains_of(&[]);
        let resumed = median_ns(15, || {
            let (d, _) = assemble_cached_digest_with_all_domains_midstate(
                Some(midstate.clone()),
                resumed_domains,
                b"cnvrf",
                7,
                b"evm",
                b"pq",
            );
            std::hint::black_box(d);
        });
        // Correctness: both produce the identical digest.
        let (resumed_digest, _) = assemble_cached_digest_with_all_domains_midstate(
            Some(midstate),
            resumed_domains,
            b"cnvrf",
            7,
            b"evm",
            b"pq",
        );
        assert_eq!(
            resumed_digest,
            assemble_cached_digest_with_all_domains(domains, b"cnvrf", 7, b"evm", b"pq")
        );
        let saved = (full - resumed) / full * 100.0;
        println!(
            "[o2x][midstate] tokens={n:>5} preimage_bytes={:>9} full={full:>10.0}ns resumed={resumed:>10.0}ns saved={saved:5.1}%",
            tokens.len()
        );
    }
}

/// Single-worker Rayon gate: on a one-thread pool the new sequential branch
/// must beat the old forced `par_iter` for a vote batch. Verdicts are equal
/// (asserted); the numbers are the report.
#[test]
fn o2x_one_worker_vote_screen_bench() {
    use ed25519_dalek::SigningKey;
    use stellereum::consensus::{
        clear_verified_vote_cache, register_validator_pq_key, Vote, VoteKind,
    };
    use stellereum::post_quantum::{FalconKeypair, PqScheme};

    let sk = SigningKey::from_bytes(&det32(0x31, 7));
    let fk = FalconKeypair::generate_from_seed_bytes(&det32(0x32, 7));
    let id = sk.verifying_key().to_bytes();
    register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());
    let votes: Vec<Vote> = (0..64u64)
        .map(|i| {
            Vote::sign_with_falcon_in_shard(
                &sk,
                &fk,
                0,
                1,
                i as u32,
                VoteKind::Prevote,
                Some(det32(0x33, i)),
            )
        })
        .collect();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("one-thread pool");
    let sequential = pool.install(|| {
        median_ns(7, || {
            clear_verified_vote_cache();
            let ok = Vote::verify_batch(&votes);
            std::hint::black_box(ok);
        })
    });
    let old_forced_parallel = pool.install(|| {
        use rayon::prelude::*;
        median_ns(7, || {
            clear_verified_vote_cache();
            let ok = votes.par_iter().all(|v| v.verify());
            std::hint::black_box(ok);
        })
    });
    // Equal verdicts on a cold cache.
    clear_verified_vote_cache();
    let gate = Vote::verify_batch(&votes);
    clear_verified_vote_cache();
    let old = votes.iter().all(|v| v.verify());
    assert_eq!(gate, old);
    assert!(gate);
    println!(
        "[o2x][vote-screen] n=64 one_worker sequential={sequential:>10.0}ns forced_par={old_forced_parallel:>10.0}ns saved={:5.1}%",
        (old_forced_parallel - sequential) / old_forced_parallel * 100.0
    );
}

/// Cost of the per-verify `pq_key_at_height` clone: what an `Arc<[u8]>`
/// refactor would remove. Falcon verify on the same host is the denominator.
#[test]
fn o2x_pq_key_clone_bench() {
    use ed25519_dalek::SigningKey;
    use stellereum::consensus::{pq_key_at_height, register_validator_pq_key};
    use stellereum::post_quantum::{FalconKeypair, PqScheme};

    let sk = SigningKey::from_bytes(&det32(0x41, 9));
    let fk = FalconKeypair::generate_from_seed_bytes(&det32(0x42, 9));
    let id = sk.verifying_key().to_bytes();
    register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());

    let key_ns = median_ns(51, || {
        let k = pq_key_at_height(&id, 1);
        std::hint::black_box(k);
    });
    println!(
        "[o2x][pq-key] one pq_key_at_height clone={key_ns:>8.0}ns (pubkey={}B)",
        fk.public_key.len()
    );
    assert!(pq_key_at_height(&id, 1).is_some());
}
