//! Falcon vote fixtures for integration tests (FULL-PQ: votes verify
//! Falcon-only; voter identity stays the Ed key). Mirrors
//! `consensus::tests::vset_with_falcon`.
//!
//! Usage from any `tests/*.rs` file (no shared `mod` wiring needed):
//! ```ignore
//! #[path = "support/falcon_votes.rs"]
//! mod falcon_votes;
//! ```
use ed25519_dalek::SigningKey;
use stellereum::consensus::{register_validator_pq_key, Vote, VoteKind};
use stellereum::post_quantum::{FalconKeypair, PqScheme};

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
