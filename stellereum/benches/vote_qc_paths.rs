//! Vote/QC path probe (measurement only; REPORT, not a gate).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench vote_qc_paths -- --nocapture
//!
//! What is measured (wall ms, median of `REPS`):
//! * `vote_ingest` — `VoteSet::add` for n=2000 votes, cold (empty verdict
//!   cache: every vote fully verifies) vs hot (same bytes: cache hits).
//! * `qc_verify` / `qc_signers_set` / `qc_signed_power` for k=7/64/100
//!   signer µQC fixtures built with the PRODUCTION APIs only.
//! * `uqc_decode` — `decode_pq_micro_envelope` of the same k=100 payload
//!   (the verify/attribution paths each decode the marker; this is the
//!   allocation cost a single decode pays).
//!
//! Correctness asserts only (verdicts/exact signer count); no timing asserts.

use std::collections::HashSet;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    clear_verified_vote_cache, decode_pq_micro_envelope, register_validator_pq_key,
    verified_vote_cache_reset_stats, verified_vote_cache_stats, QuorumCertificate, ValidatorId,
    ValidatorSet, Vote, VoteKind, VoteSet, PQ_UQC_MARKER_ID,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};

const REPS: usize = 5;

fn median_ms(reps: usize, mut f: impl FnMut()) -> f64 {
    // Warm up once (page in code, settle allocator).
    f();
    let mut v = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        f();
        v.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn seed32(tag: u64) -> [u8; 32] {
    let mut s = [0x5Au8; 32];
    s[..8].copy_from_slice(&tag.to_le_bytes());
    s[31] = (tag >> 8) as u8;
    s
}

fn fixtures(k: usize, tag: u64) -> (ValidatorSet, Vec<(SigningKey, FalconKeypair)>) {
    let mut vs = ValidatorSet::new();
    let mut keys = Vec::with_capacity(k);
    for i in 0..k {
        let sk = SigningKey::from_bytes(&seed32(tag + i as u64));
        let fk = FalconKeypair::generate_from_seed_bytes(&seed32(tag + 100_000 + i as u64));
        let id = sk.verifying_key().to_bytes();
        vs.add(id, 1);
        register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());
        keys.push((sk, fk));
    }
    (vs, keys)
}

fn build_qc(
    vs: &ValidatorSet,
    keys: &[(SigningKey, FalconKeypair)],
    height: u64,
    round: u32,
    target: [u8; 32],
) -> QuorumCertificate {
    let parent = seed32(9_000 + height + round as u64);
    let mut set = VoteSet::new();
    for (sk, fk) in keys {
        set.add(
            Vote::sign_with_falcon(sk, fk, height, round, VoteKind::Precommit, Some(target)),
            vs,
            height,
            round,
            VoteKind::Precommit,
        )
        .expect("Falcon vote must be admitted");
    }
    set.certificate(Some(target), vs, &parent)
        .expect("full set must form a QC")
}

fn qc_row(k: usize, iters: usize) {
    let tag = 0x7100 + k as u64 * 1000;
    let (vs, keys) = fixtures(k, tag);
    let qc = build_qc(&vs, &keys, 1, 0, seed32(tag + 7));
    assert!(qc.verify(&vs), "k={k} fixture must verify");

    let verify_ms = median_ms(REPS, || {
        assert!(qc.verify(&vs));
    });
    let signers_ms = median_ms(REPS, || {
        let s: HashSet<ValidatorId> = qc.signers_set(&vs);
        assert_eq!(s.len(), k);
    });
    let power_ms = median_ms(REPS, || {
        assert_eq!(vs.qc_signed_power(&qc), k as u64);
    });
    // Adoption-path fusion: separate verify + attribution vs the single-pass
    // API that replaced it in `consensus_step`.
    let separate_ms = median_ms(REPS, || {
        assert!(qc.verify(&vs));
        assert_eq!(vs.qc_signed_power(&qc), k as u64);
    });
    let fused_ms = median_ms(REPS, || {
        let (ok, power) = qc.verify_and_signed_power(&vs);
        assert!(ok);
        assert_eq!(power, k as u64);
    });
    println!(
        "[vote-qc][qc] k={k:<3} iters/reps={iters:<4} verify={verify_ms:8.3}ms signers_set={signers_ms:8.3}ms signed_power={power_ms:8.3}ms verify+power={separate_ms:8.3}ms fused={fused_ms:8.3}ms"
    );

    // Decode cost of the µQC marker payload (one decode).
    let payload = qc
        .signatures
        .iter()
        .find(|(v, _)| *v == PQ_UQC_MARKER_ID)
        .map(|(_, p)| p)
        .expect("µQC marker present");
    let decode_ms = median_ms(REPS, || {
        assert!(decode_pq_micro_envelope(payload).is_some());
    });
    println!(
        "[vote-qc][decode] k={k:<3} payload={}B decode={decode_ms:8.3}ms",
        payload.len()
    );
}

fn vote_ingest_row(n: usize) {
    let (vs, keys) = fixtures(n, 0x5100 + n as u64 * 1000);
    let votes: Vec<Vote> = keys
        .iter()
        .map(|(sk, fk)| {
            Vote::sign_with_falcon(sk, fk, 1, 0, VoteKind::Prevote, Some(seed32(0x7777)))
        })
        .collect();

    let cold_ms = median_ms(REPS, || {
        clear_verified_vote_cache();
        verified_vote_cache_reset_stats();
        let mut set = VoteSet::new();
        for v in votes.iter().cloned() {
            set.add(v, &vs, 1, 0, VoteKind::Prevote).unwrap();
        }
        assert_eq!(set.len(), n);
        let (hits, misses) = verified_vote_cache_stats();
        assert_eq!(hits, 0, "cold pass must not hit");
        assert!(misses >= n as u64);
    });

    // Warm the cache once, then measure the hit path.
    {
        clear_verified_vote_cache();
        let mut set = VoteSet::new();
        for v in votes.iter().cloned() {
            set.add(v, &vs, 1, 0, VoteKind::Prevote).unwrap();
        }
        assert_eq!(set.len(), n);
    }
    let hot_ms = median_ms(REPS, || {
        verified_vote_cache_reset_stats();
        let mut set = VoteSet::new();
        for v in votes.iter().cloned() {
            set.add(v, &vs, 1, 0, VoteKind::Prevote).unwrap();
        }
        assert_eq!(set.len(), n);
        let (hits, misses) = verified_vote_cache_stats();
        assert_eq!(misses, 0, "hot pass must skip crypto");
        assert!(hits >= n as u64);
    });
    println!(
        "[vote-qc][ingest] n={n} cold={cold_ms:8.3}ms hot={hot_ms:8.3}ms speedup={:.2}x",
        cold_ms / hot_ms.max(1e-9)
    );
}

fn vote_batch_ingest_row(n: usize) {
    let (vs, keys) = fixtures(n, 0x6200 + n as u64 * 1000);
    let votes: Vec<Vote> = keys
        .iter()
        .map(|(sk, fk)| {
            Vote::sign_with_falcon(sk, fk, 1, 0, VoteKind::Prevote, Some(seed32(0x7788)))
        })
        .collect();

    let cold_ms = median_ms(REPS, || {
        clear_verified_vote_cache();
        verified_vote_cache_reset_stats();
        let input = votes.clone();
        let mut set = VoteSet::new();
        let out = set.add_batch(input, &vs, 1, 0, VoteKind::Prevote);
        assert!(out.iter().all(|r| r.is_ok()));
        assert_eq!(set.len(), n);
        let (hits, misses) = verified_vote_cache_stats();
        assert_eq!(hits, 0, "cold batch pass must not hit");
        assert!(misses >= n as u64);
    });

    {
        clear_verified_vote_cache();
        let mut set = VoteSet::new();
        let out = set.add_batch(votes.clone(), &vs, 1, 0, VoteKind::Prevote);
        assert!(out.iter().all(|r| r.is_ok()));
        assert_eq!(set.len(), n);
    }
    let hot_ms = median_ms(REPS, || {
        verified_vote_cache_reset_stats();
        let input = votes.clone();
        let mut set = VoteSet::new();
        let out = set.add_batch(input, &vs, 1, 0, VoteKind::Prevote);
        assert!(out.iter().all(|r| r.is_ok()));
        assert_eq!(set.len(), n);
        let (hits, misses) = verified_vote_cache_stats();
        assert_eq!(misses, 0, "hot batch pass must skip crypto");
        assert!(hits >= n as u64);
    });
    println!(
        "[vote-qc][ingest-batch] n={n} cold={cold_ms:8.3}ms hot={hot_ms:8.3}ms speedup={:.2}x",
        cold_ms / hot_ms.max(1e-9)
    );
}

#[test]
fn vote_qc_paths_probe() {
    vote_ingest_row(2000);
    vote_ingest_row(64);
    vote_batch_ingest_row(2000);
    for (k, iters) in [(7usize, 200usize), (64, 50), (100, 30)] {
        qc_row(k, iters);
    }
}
