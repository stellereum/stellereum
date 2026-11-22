//! Falcon vote fixtures for integration tests (FULL-PQ: votes verify
//! Falcon-only; voter identity stays the Ed key). Mirrors
//! `consensus::tests::vset_with_falcon`.
//!
//! Usage from any `tests/*.rs` file (no shared `mod` wiring needed):
//! ```ignore
//! #[path = "support/falcon_votes.rs"]
//! mod falcon_votes;
//! ```
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use stellereum::consensus::{
    register_validator_pq_key, vote_sign_bytes, Vote, VoteKind, VOTE_FALCON_MAGIC,
    VOTE_FALCON_PART_LEN,
};
use stellereum::post_quantum::{verify_pq_signature, FalconKeypair, PqScheme};

/// Deterministic Ed + Falcon key sets with every Falcon key registered in
/// the global validator-PQ registry that `Vote::verify` reads. Same seeds
/// give the same keys (registry insert is idempotent), so parallel tests
/// sharing a binary cannot collide.
#[allow(dead_code)] // GATE: shared helper — used by most includers; crates with local key patterns use only `fvote`.
pub fn falcon_set(n: usize) -> (Vec<SigningKey>, Vec<FalconKeypair>) {
    let ks: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[i as u8; 32]))
        .collect();
    let fks: Vec<FalconKeypair> = ks
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = FalconKeypair::generate_from_seed(i as u8);
            register_validator_pq_key(
                k.verifying_key().to_bytes(),
                PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect();
    (ks, fks)
}

/// FULL-PQ replacement for `Vote::sign` in fixtures (keeps the Ed voter id).
pub fn fvote(
    sk: &SigningKey,
    fk: &FalconKeypair,
    height: u64,
    round: u32,
    kind: VoteKind,
    bh: Option<[u8; 32]>,
) -> Vote {
    Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
}

/// TEST-ONLY deterministic vote signer for replay-determinism tests.
///
/// Mirrors `Transaction::create_falcon512_test_signature(&pk, &msg, seed)`:
/// the Falcon keypair is re-derived from `seed` via
/// `FalconKeypair::generate_from_seed(seed)` and the caller-supplied `fk`
/// must be that keypair (fail-fast `assert_eq!` on the public key, like the
/// tx helper's pubkey check — a wrong key would not verify and the test
/// would fail for the wrong reason).
///
/// Determinism comes from a process-global signature cache keyed by
/// `(seed, voter, height, round, kind, block_hash)`: the FIRST signing of a
/// given vote content produces a REAL FIPS 206 Falcon signature (fresh OS
/// randomness, verified via `verify_pq_signature` like the tx helper's
/// self-check) and stores its bytes; every LATER signing of the SAME content
/// (e.g. the second run of a replay test in the same process) reuses the
/// stored bytes instead of drawing fresh randomness. Reused bytes verify
/// (same message, same key — verification is deterministic), so the votes,
/// the QCs built from them, and the block hashes committing those QCs are
/// byte-identical across runs.
///
/// Production is unaffected: `fvote` and `Vote::sign_with_falcon` are
/// untouched and still draw fresh OS randomness per signature (audit W4.1 —
/// REQUIRED; a deterministic production signer would leak the private key
/// via the Nguyen-Regev parallelepiped attack). Only tests that explicitly
/// opt into `fvote_deterministic` get cached (deterministic) signatures;
/// every other suite keeps randomized `fvote` (realism preserved).
/// The cache is test-process-local (no cross-process state, no production
/// path reads it).
#[allow(dead_code)] // GATE: shared helper — used only by replay-determinism suites; other includers use `fvote`/`falcon_set`.
pub fn fvote_deterministic(
    seed: u8,
    sk: &SigningKey,
    fk: &FalconKeypair,
    height: u64,
    round: u32,
    kind: VoteKind,
    bh: Option<[u8; 32]>,
) -> Vote {
    // Mirror `create_falcon512_test_signature`: the keypair is seed-derived,
    // so the caller must hand in that keypair (fail fast on mismatch).
    let expected = FalconKeypair::generate_from_seed(seed);
    assert_eq!(
        fk.public_key, expected.public_key,
        "fvote_deterministic: fk must be FalconKeypair::generate_from_seed(seed)"
    );
    let voter = sk.verifying_key().to_bytes();
    let msg = vote_sign_bytes(height, round, kind, &bh);
    let kind_tag = match kind {
        VoteKind::Prevote => 0u8,
        VoteKind::Precommit => 1u8,
    };
    let key = (seed, voter, height, round, kind_tag, bh);
    // Cache hit: rebuild the envelope around the stored Falcon bytes (Ed
    // half is deterministic anyway — RFC 8032 — so re-signing it is free
    // and identical).
    if let Some(cached) = det_sig_cache().lock().unwrap().get(&key).cloned() {
        let ed_sig = sk.sign(&msg).to_bytes();
        let mut signature = Vec::with_capacity(VOTE_FALCON_PART_LEN);
        signature.extend_from_slice(VOTE_FALCON_MAGIC);
        signature.extend_from_slice(&ed_sig);
        signature.extend_from_slice(&cached);
        return Vote {
            height,
            round,
            kind,
            block_hash: bh,
            voter,
            signature,
            // This fixture signs the masterchain preimage (`vote_sign_bytes`).
            shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        };
    }
    // Cache miss: real FIPS 206 signing (fresh OS randomness), self-checked
    // like `create_falcon512_test_signature`, then stored for replay.
    let v = Vote::sign_with_falcon(sk, fk, height, round, kind, bh);
    let falcon_sig = v
        .falcon_signature()
        .expect("sign_with_falcon must carry a Falcon half")
        .to_vec();
    assert!(
        verify_pq_signature(PqScheme::Falcon512, &fk.public_key, &msg, &falcon_sig),
        "fvote_deterministic: the produced signature must verify"
    );
    det_sig_cache().lock().unwrap().insert(key, falcon_sig);
    v
}

/// Cache key for `fvote_deterministic`: the seed identifying the Falcon
/// keypair plus the full vote contents. Same key = same vote = same bytes.
#[allow(dead_code)] // GATE: with `fvote_deterministic` (shared-helper note above).
type DetVoteKey = (u8, [u8; 32], u64, u32, u8, Option<[u8; 32]>);

/// Process-global cache of Falcon vote-signature bytes for
/// `fvote_deterministic` (see docs there). Test-only; never read by
/// production paths.
#[allow(dead_code)] // GATE: with `fvote_deterministic` (shared-helper note above).
fn det_sig_cache() -> &'static Mutex<HashMap<DetVoteKey, Vec<u8>>> {
    static CACHE: OnceLock<Mutex<HashMap<DetVoteKey, Vec<u8>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
