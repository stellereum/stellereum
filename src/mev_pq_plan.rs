//! MEV PQ migration PLAN — design + KAT prototype, UNWIRED.
//!
//! UNWIRED: this file is NOT declared in `lib.rs` (`mod mev_pq_plan` does not
//! exist) and NOTHING in production calls it. The `_pq_plan` suffix marks
//! plan-only code. To run the KATs: `rustc --edition 2021 --test
//! stellereum/src/mev_pq_plan.rs -o /tmp/mev_pq_plan_kat && /tmp/mev_pq_plan_kat`.
//! No new dependencies: `std` only. Production keeps using BLAKE3 (`TRANSCRIPT_DOMAIN`),
//! SHA-256 (`derive_seal_key`), Falcon-512 (`crate::post_quantum`) — named, not imported.
//!
//! # 1. Audit (read-only): what the MEV DKG produces, who consumes it, X25519's role
//!
//! DKG PRODUCES (all in `stellereum/src/mev_epoch.rs`):
//! * `EpochPublicKey` (`mev_epoch.rs:331`): epoch `P_e`, a Ristretto255 point that is the
//!   AGGREGATE of contributors' constant-term Feldman commitments (`finalize`, `:981-988`).
//! * `EpochKeyMaterial` (`mev_epoch.rs:426`): per-member Shamir share = sum of contributors'
//!   evaluations at our index (`:955-971`), plus `transcript_root` binding every accepted
//!   contribution (`:989-999`), plus `committee_hash` + `threshold`.
//! * DKG inputs: `EpochCommittee` (`:239`) with DERIVED contributor set (`contributor_set`, `:184`);
//!   `DkgContribution` (`:528`) carries Feldman `commitments` + per-recipient `EncryptedShare`
//!   packages (`:515`); `EpochDkg::{contribution, ingest, finalize}` (`:671, :744, :929`) enforce
//!   Feldman VSS + exact-contributor-set finalization (`can_finalize`, `:911`).
//!
//! CONSUMERS of the DKG output:
//! * Wallet sealing: `seal_transaction` (`:1257`) — ephemeral Ristretto DH `e * P_e` (`:1268-1272`)
//!   + XChaCha20-Poly1305; entry via `wallet.rs:55` `seal_transaction_for_epoch`.
//! * Threshold unseal: `compute_partial` (`:1334`, `C^x_i`), `combine_partials` (`:1351`,
//!   Lagrange-in-the-exponent), `unseal_transaction` (`:1405`); called by the proposer path
//!   `runtime.rs:3336`, partial release `runtime.rs:3200` (`EpochSealManager::release_partial`,
//!   `mev_epoch.rs:2242`), gossip `MevFrame::Dkg` (`runtime.rs:3056`), sealed pool
//!   (`mempool.rs:626,642`), broadcast (`consensus_net.rs:2087`).
//! * Chain binding: `epoch_key_commitment` (`:493`) carried by the block, checked by
//!   `light_client.rs:719` `verify_epoch_key_against_block`.
//!
//! X25519'S EXACT ROLE — transport encryption of DKG share packages ONLY:
//! * `encrypt_share_package` (`:1094`): ephemeral `XStaticSecret::random_from_rng` + DH
//!   `ephemeral.diffie_hellman(recipient_pk)` (`:1099-1102`), key via `derive_seal_key`, XChaCha seal.
//! * `decrypt_share_package` (`:1115`): `secret.diffie_hellman(ephemeral_pk)` (`:1119-1121`).
//! * Key derivation: `encryption_secret_from_ed25519` (`:1060`), `encryption_public_key_from_ed25519`
//!   (`:1078`, birational map, keeps DKG to ONE round), `encryption_public_key` (`:1086-1088`);
//!   `CommitteeMember.enc_pk` (`:232-235`); `committee_for` derives `enc_pk` (`:1906`).
//! * X25519 is NOT the sealing primitive (sealing is Ristretto DH + XChaCha, `:1268-1286`),
//!   NOT the threshold arithmetic (Ristretto is linear, X25519 clamping is not — `:49-56`),
//!   and NOT the E2E transport (`node_keys.rs:629-630` `e2e.key` is a separate channel).
//!
//! # 2. Design: ranked PQ replacement (honest fit assessment)
//!
//! The DKG's production/consumption shape is THRESHOLD DECRYPTION: `t`-of-`n` partials must
//! reconstruct the SAME DH shared point for an arbitrary wallet-chosen ephemeral `C`
//! (`combine_partials`, `:1351`). Any replacement must preserve that shape.
//!
//! * RANK 1 (fits): Falcon-authenticated PQ-KEM transport swap. Keep Feldman VSS + Ristretto
//!   threshold exactly as-is; replace ONLY the X25519 package encryption (`:1094-1136`) with a
//!   PQ KEM encaps (e.g. ML-KEM-768) to each recipient's PQ transport key, and sign each
//!   `DkgContribution` with the contributor's Falcon-512 key over the contribution
//!   bytes (the old `VrfBinding::verify` pattern was deleted with ECVRF;
//!   keygen `post_quantum.rs:1959` `FalconKeypair::generate_from_seed_bytes`).
//!   Production/consumption unchanged: same `P_e`, same partials, same `unseal_transaction`.
//! * RANK 2 (partial fit): Falcon-signed commit-reveal per the CN-VRF pattern (`cn_vrf.rs:1-43`,
//!   `cnvrf_commit`/`cnvrf_open`/`cnvrf_verify`, domains `CNVRF_COMMIT_DST`/`CNVRF_OPEN_DST`)
//!   for the EPOCH SEED / public randomness only (replacing `EPOCH_SEED_DOMAIN` `:90` +
//!   `DKG_POLY_DOMAIN` `:92` determinism). It removes DKG input bias surface but has NO threshold
//!   decryption property: alone it CANNOT unseal wallet ciphertexts.
//! * RANK 3 / REJECTED for this path: pure hash-DRB replacing the DKG. A DRB outputs public
//!   randomness, not a threshold-shared secret; it cannot produce `t`-of-`n` decryption partials
//!   for arbitrary ephemerals, so the sealed-mempool liveness/fail-closed semantics die with it.
//!
//! This file prototypes the RANK-2 mechanics shape (commit/reveal/verify + transcript binding)
//! because that is what is KAT-testable in `std` today; RANK-1 needs the PQ KEM primitive + audit
//! before any code lands (see `docs/MEV_PQ_PLAN.md`).
//!
//! # 3. Prototype scope
//!
//! `pq_plan_digest` is a MECHANICS MODEL (FNV-1a-64 x4 lanes, `std` only) — NOT production crypto.
//! At wiring time it is replaced 1:1 by BLAKE3 (`TRANSCRIPT_DOMAIN` pattern, `:101`) / SHAKE-256
//! (`cn_vrf.rs` O8 pattern) and the open message gains a Falcon-512 signature. What the KATs pin
//! is the SHAPE: domain separation, length-prefix framing, order sensitivity, verify binding.

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
/// 1:1 with BLAKE3 (see `TRANSCRIPT_DOMAIN`, `mev_epoch.rs:101`) or SHAKE-256 (see `cn_vrf.rs`
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
        &[validator_id.as_slice(), &epoch.to_be_bytes(), nonce.as_slice()],
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
/// Mirrors `EpochDkg::finalize` (`mev_epoch.rs:989-999`): `epoch || canonical(contribution_i...)`
/// under a domain. Order-sensitive by construction: swapping two contributions changes the root.
pub fn pq_plan_transcript(epoch: u64, contributions: &[&[u8]]) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(contributions.len() + 1);
    let epoch_bytes = epoch.to_be_bytes();
    parts.push(epoch_bytes.as_slice());
    parts.extend_from_slice(contributions);
    pq_plan_digest(PQ_PLAN_TRANSCRIPT_DOMAIN, &parts)
}

/// Verify a transcript root against the exact ordered contribution set.
pub fn pq_plan_transcript_verify(
    root: &[u8; 32],
    epoch: u64,
    contributions: &[&[u8]],
) -> bool {
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
