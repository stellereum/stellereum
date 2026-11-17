//! MEV PQ migration — DELIVERED TRANSPORT + REMAINING AUDITED REPLACEMENT.
//!
//! STATUS (2026-11-17, FULL-PQ transport): the DKG share-package transport is
//! ML-KEM-768 + Falcon-512 ONLY. The classical X25519 leg, the
//! Edwards-to-Montgomery transport-key derivation and the unauthenticated
//! `EpochDkg::ingest` entry point are DELETED. There is no pre-activation
//! window and no silent fallback.
//!
//! This module is compiled ONLY under `#[cfg(test)]` (declared in `lib.rs` as
//! `#[cfg(test)] mod mev_pq_plan;`) and is a MECHANICS MODEL for the epoch
//! randomness commit/reveal shape. Nothing in production calls it. The KATs
//! run in `cargo test --lib mev`.
//!
//! # 1. Delivered state (what the MEV epoch path does today)
//!
//! DKG PRODUCES (all in `stellereum/src/mev_epoch.rs`):
//! * `EpochPublicKey`: epoch `P_e`, a Ristretto255 point that is the AGGREGATE
//!   of contributors' constant-term Feldman commitments
//!   (`EpochDkg::finalize`). This layer is CLASSICAL and is the outstanding
//!   audited-replacement item (see §3).
//! * `EpochKeyMaterial`: per-member Shamir share = sum of contributors'
//!   evaluations at our index, plus `transcript_root`, `committee_hash` and
//!   `threshold`.
//! * DKG inputs: `EpochCommittee` (derived contributor set); `DkgContribution`
//!   carries Feldman `commitments` + per-recipient `EncryptedShare` packages;
//!   `EpochDkg::{contribution_pq, ingest_pq, finalize}` enforce Feldman VSS +
//!   exact-contributor-set finalization.
//!
//! TRANSPORT (delivered, PQ-only):
//! * `EncryptedShare.ciphertext = ML-KEM-768.Encaps(ek_recipient) || AEAD(share)`
//!   = 1136 bytes. `ephemeral_pk` is always zero (no DH ephemeral).
//! * Key = SHA-256(SEAL_KDF_DOMAIN || len(ss) || ss || epoch || tx_hash);
//!   AEAD = XChaCha20-Poly1305; implicit rejection surfaces as an AEAD tag
//!   failure (no distinguisher).
//! * Falcon-512 signs the canonical contribution bytes
//!   (`pq_transport_seal` / `pq_transport_verify`); a mutation anywhere fails
//!   verification before ingest.
//! * Key sourcing: `MevKemRegistry` (validator id -> ML-KEM-768 ek, delayed
//!   rotation). `CommitteeMember.enc_pk` is the 32-byte BLAKE3 tag of the ek
//!   (`kem_member_tag`), so the committee hash binds every transport key.
//!
//! CONSUMERS of the DKG output (unchanged):
//! * Wallet sealing: `seal_transaction` (ephemeral Ristretto DH `e * P_e`) +
//!   XChaCha20-Poly1305; entry via `seal_transaction_for_epoch` (wallet.rs).
//! * Threshold unseal: `compute_partial` (`C^x_i`), `combine_partials`
//!   (Lagrange-in-the-exponent), `unseal_transaction`; proposer path and
//!   `EpochSealManager::release_partial`.
//! * Chain binding: `epoch_key_commitment` carried by the block, checked by
//!   `verify_epoch_key_against_block` (light_client.rs).
//!
//! FAIL-CLOSED node wiring:
//! * `EpochSealManager::sync_epoch` and `ingest_contribution` are explicit
//!   `Err`s: a node-side DKG needs the KEM registry and a 64-byte ML-KEM seed
//!   (not derivable from an Ed25519 seed). The registry-wired entry points are
//!   `sync_epoch_pq` / `ingest_contribution_pq`; the runtime is not wired to
//!   them yet, so no node derives an epoch key today. That is the deliberate
//!   no-fallback state, not a silent downgrade.
//! * `ingest_classical_at_h` is an unconditional `Err` at every height;
//!   `is_pq_transport_active` is true at every height.
//! * X25519 appears NOWHERE in the MEV epoch path.
//!
//! # 2. Why the Feldman/sealing layer was NOT replaced in the same step
//!
//! Feldman VSS needs a prime-order group because verification is the
//! homomorphic equation `prod_k C_k^{i^k} == g^{f(i)}` and the public key is
//! `P_e = sum_j g^{a_{j,0}}`. Replacing `g^x` with `H(x)` destroys it:
//! `H(x+y)` is not a function of `H(x)`, `H(y)`, so shares cannot be verified
//! against a public commitment and sealing to `P_e` would need the secret in
//! the clear. Threshold ML-KEM decapsulation is not Shamir-linear either (NTT,
//! compression and message rounding are non-linear). A one-step swap would be
//! unaudited crypto or a security downgrade, so it is NOT done here.
//!
//! # 3. What an audited replacement MUST provide
//!
//! 1. A threshold KEM whose decapsulation is a function of `t`-of-`n` shares
//!    (lattice threshold decryption with audited MPC), IND-CCA2 under MLWE.
//! 2. OR wallet-side per-ciphertext sharing: sample a fresh AEAD key `k`,
//!    Shamir-split `k` over a prime field, ML-KEM-encapsulate share `i` to
//!    member `i`, and publish the `n` packages with the ciphertext. `t`
//!    released shares reconstruct `k`; `t-1` learn nothing. This changes
//!    wallet/RPC/wire shapes (deliberately untouched here).
//! 3. Public verifiability without a pairing/group: an audited lattice VSS, or
//!    hash commitments to each share plus an audited dispute/attribution
//!    protocol. Hash-only VSS is NOT publicly verifiable and must say so.
//! 4. A KAT + differential test that the replacement preserves every
//!    accept/refuse decision pinned in `tests/mev_pq_transport_tests.rs` and
//!    `tests/pentest_mev_kem.rs`.
//!
//! # 4. Prototype scope in THIS file
//!
//! `pq_plan_digest` is a MECHANICS MODEL (FNV-1a-64 x4 lanes, `std` only) —
//! NOT production crypto. At wiring time it is replaced 1:1 by BLAKE3
//! (`TRANSCRIPT_DOMAIN` pattern) / SHAKE-256 and the open message gains a
//! Falcon-512 signature. What the KATs pin is the SHAPE: domain separation,
//! length-prefix framing, order sensitivity, verify binding.
//!
// ---------------------------------------------------------------------------
// Domains (mirroring the production `*_DOMAIN` pattern, plan-only tags)
// ---------------------------------------------------------------------------

/// Domain separator of the PQ-plan commitment preimage.
pub const PQ_PLAN_COMMIT_DOMAIN: &[u8] = b"STELL_MEV_PQ_COMMIT_V1";
/// Domain separator of the PQ-plan beta (reveal output) derivation.
pub const PQ_PLAN_BETA_DOMAIN: &[u8] = b"STELL_MEV_PQ_BETA_V1";
/// Domain separator of the PQ-plan transcript root.
pub const PQ_PLAN_TRANSCRIPT_DOMAIN: &[u8] = b"STELL_MEV_PQ_TRANSCRIPT_V1";

const PQ_PLAN_FNV_OFFSET: u64 = 0xcbf29ce484222325;
const PQ_PLAN_FNV_PRIME: u64 = 0x100000001b3;
const PQ_PLAN_LANE_GOLDEN: u64 = 0x9e3779b97f4a7c15;

// ---------------------------------------------------------------------------
// Mechanics model: domain-separated, length-prefixed digest (NOT production crypto)
// ---------------------------------------------------------------------------

fn pq_plan_feed(state: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *state ^= *byte as u64;
        *state = state.wrapping_mul(PQ_PLAN_FNV_PRIME);
    }
}

/// Domain-separated digest over length-prefixed parts, expanded to 32 bytes.
///
/// MODEL ONLY: FNV-1a-64 over 4 golden-ratio-separated lanes. Production replaces this
/// 1:1 with BLAKE3 (see `TRANSCRIPT_DOMAIN`, `mev_epoch.rs`) or SHAKE-256 (see `cn_vrf.rs`
/// O8). The framing contract pinned here — domain first, every part `u32-BE-len || bytes` —
/// is what carries over.
pub fn pq_plan_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (lane, slot) in out.chunks_mut(8).enumerate() {
        let mut state: u64 =
            PQ_PLAN_FNV_OFFSET ^ PQ_PLAN_LANE_GOLDEN.wrapping_mul((lane as u64) + 1);
        pq_plan_feed(&mut state, &(domain.len() as u32).to_be_bytes());
        pq_plan_feed(&mut state, domain);
        for part in parts {
            pq_plan_feed(&mut state, &(part.len() as u32).to_be_bytes());
            pq_plan_feed(&mut state, part);
        }
        slot.copy_from_slice(&state.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Commit-reveal (CN-VRF shape): commit in epoch N-1, open+verify in epoch N
// ---------------------------------------------------------------------------

/// Commit to `(validator_id, epoch, nonce)` — the epoch N-1 commitment.
///
/// Production binds a Falcon-512 signature over the open message at reveal time
/// (`cn_vrf.rs` `CNVRF_OPEN_DST` pattern); this model binds the nonce preimage.
pub fn pq_plan_commit(validator_id: &[u8; 32], epoch: u64, nonce: &[u8; 32]) -> [u8; 32] {
    pq_plan_digest(
        PQ_PLAN_COMMIT_DOMAIN,
        &[
            validator_id.as_slice(),
            &epoch.to_be_bytes(),
            nonce.as_slice(),
        ],
    )
}

/// Verify a reveal against a prior commitment. Fail-closed: any mismatch refuses.
pub fn pq_plan_open_verify(
    commitment: &[u8; 32],
    validator_id: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 32],
) -> bool {
    pq_plan_commit(validator_id, epoch, nonce) == *commitment
}

/// Derive the reveal output (`beta`) from the commitment + nonce.
///
/// Production derives beta via SHAKE-256 over `(commitment, signature, ...)`; the model
/// derives it from `(commitment, nonce)` to pin the binding shape: no commitment, no beta.
pub fn pq_plan_beta(commitment: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    pq_plan_digest(
        PQ_PLAN_BETA_DOMAIN,
        &[commitment.as_slice(), nonce.as_slice()],
    )
}

// ---------------------------------------------------------------------------
// Transcript root (DKG-transcript shape): binds every contribution in order
// ---------------------------------------------------------------------------

/// Bind `(epoch, contributions...)` into a transcript root.
///
/// Mirrors `EpochDkg::finalize` (mev_epoch.rs): `epoch || canonical(contribution_i...)`
/// under a domain. Order-sensitive by construction: swapping two contributions changes the root.
pub fn pq_plan_transcript(epoch: u64, contributions: &[&[u8]]) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(contributions.len() + 1);
    let epoch_bytes = epoch.to_be_bytes();
    parts.push(epoch_bytes.as_slice());
    parts.extend_from_slice(contributions);
    pq_plan_digest(PQ_PLAN_TRANSCRIPT_DOMAIN, &parts)
}

/// Verify a transcript root against the exact ordered contribution set.
pub fn pq_plan_transcript_verify(root: &[u8; 32], epoch: u64, contributions: &[&[u8]]) -> bool {
    pq_plan_transcript(epoch, contributions) == *root
}

// ---------------------------------------------------------------------------
// KATs (fixed vectors; run via `rustc --test`, see file header)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pq_plan_kat {
    use super::{
        pq_plan_beta, pq_plan_commit, pq_plan_digest, pq_plan_open_verify, pq_plan_transcript,
        pq_plan_transcript_verify, PQ_PLAN_BETA_DOMAIN, PQ_PLAN_COMMIT_DOMAIN,
        PQ_PLAN_TRANSCRIPT_DOMAIN,
    };

    fn hex_to_32(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("kat hex parses"))
            .collect();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn kat_validator_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, slot) in id.iter_mut().enumerate() {
            *slot = i as u8;
        }
        id
    }

    #[test]
    fn kat_commit_vector() {
        let id = kat_validator_id();
        let nonce = [0x99u8; 32];
        let got = pq_plan_commit(&id, 7, &nonce);
        assert_eq!(
            got,
            hex_to_32("e2ae7e8d91597c426dd305ee7e9e6aacb8f555c1addb007d8b66a2281daaa2ce")
        );
    }

    #[test]
    fn kat_beta_vector() {
        let commitment =
            hex_to_32("e2ae7e8d91597c426dd305ee7e9e6aacb8f555c1addb007d8b66a2281daaa2ce");
        let nonce = [0x99u8; 32];
        let got = pq_plan_beta(&commitment, &nonce);
        assert_eq!(
            got,
            hex_to_32("56e79d2a10a26d5a1dd58046d16cfc35a86aa62757034896e75dd45521c2d978")
        );
    }

    #[test]
    fn kat_transcript_vector() {
        let contributions: &[&[u8]] = &[b"contribution-1", b"contribution-2"];
        let got = pq_plan_transcript(7, contributions);
        assert_eq!(
            got,
            hex_to_32("9a3cae87628f7737ed77e692b85c8dc958e84afd27627d7ecb84571a0356ae50")
        );
    }

    #[test]
    fn open_verify_roundtrip_accepts() {
        let id = kat_validator_id();
        let nonce = [0x42u8; 32];
        let commitment = pq_plan_commit(&id, 11, &nonce);
        assert!(pq_plan_open_verify(&commitment, &id, 11, &nonce));
    }

    #[test]
    fn open_verify_rejects_any_tamper() {
        let id = kat_validator_id();
        let nonce = [0x42u8; 32];
        let commitment = pq_plan_commit(&id, 11, &nonce);
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0x01;
        assert!(!pq_plan_open_verify(&commitment, &id, 11, &bad_nonce));
        assert!(!pq_plan_open_verify(&commitment, &id, 12, &nonce));
        let mut bad_id = id;
        bad_id[31] ^= 0x01;
        assert!(!pq_plan_open_verify(&commitment, &bad_id, 11, &nonce));
        let mut bad_commitment = commitment;
        bad_commitment[0] ^= 0x01;
        assert!(!pq_plan_open_verify(&bad_commitment, &id, 11, &nonce));
    }

    #[test]
    fn transcript_is_order_sensitive() {
        let fwd: &[&[u8]] = &[b"contribution-1", b"contribution-2"];
        let rev: &[&[u8]] = &[b"contribution-2", b"contribution-1"];
        assert_ne!(pq_plan_transcript(7, fwd), pq_plan_transcript(7, rev));
    }

    #[test]
    fn transcript_verify_binds_exact_set() {
        let full: &[&[u8]] = &[b"contribution-1", b"contribution-2"];
        let root = pq_plan_transcript(7, full);
        assert!(pq_plan_transcript_verify(&root, 7, full));
        let short: &[&[u8]] = &[b"contribution-1"];
        assert!(!pq_plan_transcript_verify(&root, 7, short));
        assert!(!pq_plan_transcript_verify(&root, 8, full));
    }

    #[test]
    fn domains_are_separated() {
        let id = kat_validator_id();
        let nonce = [0x99u8; 32];
        let commit = pq_plan_commit(&id, 7, &nonce);
        let beta = pq_plan_beta(&commit, &nonce);
        assert_ne!(commit, beta);
        let same_parts = pq_plan_digest(PQ_PLAN_COMMIT_DOMAIN, &[b"x"]);
        let other_domain_beta = pq_plan_digest(PQ_PLAN_BETA_DOMAIN, &[b"x"]);
        let other_domain_transcript = pq_plan_digest(PQ_PLAN_TRANSCRIPT_DOMAIN, &[b"x"]);
        assert_ne!(same_parts, other_domain_beta);
        assert_ne!(same_parts, other_domain_transcript);
    }

    #[test]
    fn digest_is_deterministic_and_framed() {
        let a = pq_plan_digest(b"DOM", &[b"part-1", b"part-2"]);
        let b = pq_plan_digest(b"DOM", &[b"part-1", b"part-2"]);
        assert_eq!(a, b);
        // Length-prefix framing: ("ab","c") != ("a","bc").
        let ab_c = pq_plan_digest(b"DOM", &[b"ab", b"c"]);
        let a_bc = pq_plan_digest(b"DOM", &[b"a", b"bc"]);
        assert_ne!(ab_c, a_bc);
    }
}
