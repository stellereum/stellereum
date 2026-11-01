//! Crypto-primitive audit tests for `stellereum::vrf` (deterministic-Schnorr VRF).
//!
//! Scope: the CRYPTO PRIMITIVE ONLY (`vrf_prove` / `vrf_verify`, nonce
//! derivation, key handling, activation-gate math, election-seed binding).
//! Activation wiring in `main.rs` / `consensus.rs` belongs to another worker
//! and is not touched here.
//!
//! What this file pins:
//! * determinism — 100 seeds x 8 inputs, re-prove is byte-identical;
//! * soundness — honestly-generated proofs verify; every tamper class
//!   (proof-byte flips at all 64 positions, output swap, wrong key,
//!   wrong input, identity key, non-canonical `z`, all-zero proof) refuses;
//! * nonce diversity — different inputs under one key give different nonces
//!   (observed via distinct `R`), so no catastrophic nonce reuse;
//! * edge cases — zero seed, zero/0xFF inputs, activation boundaries,
//!   election-seed height/round binding, registry-gated minting;
//! * documented ECVRF gap — NO uniqueness: the secret holder can mint a
//!   second, distinct, VALID proof for the same input (Schnorr signatures
//!   admit many valid `(R, z)` per message; ECVRF uniqueness does not hold).
//!   This is a construction limitation slated for the phase-2 audited-ECVRF
//!   swap, not an implementation bug — the test characterizes it explicitly.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use stellereum::post_quantum::FalconKeypair;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_binding_preimage, vrf_election_seed, vrf_prove, vrf_verify,
    VrfActivation, VrfBinding, VrfPublicKey, VrfRegistry, VrfSecret, VRF_OUTPUT_DOMAIN,
    VRF_PROOF_DOMAIN, VRF_PROOF_LEN, VRF_SCALAR_DOMAIN,
};

// --- deterministic fixtures (no OS randomness, no wall clock) ----------------

/// 100 pairwise-distinct secret seeds.
fn audit_seed(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    s[8] = 0x3C;
    s[31] = (i as u8).wrapping_add(0x51);
    s
}

/// 8 pairwise-distinct seed inputs.
fn audit_input(j: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(j as u64).wrapping_add(0xD1B5).to_le_bytes());
    s[8] = 0xA7;
    s[31] = 0xE3;
    s
}

fn r_bytes_of(secret: &VrfSecret, input: &[u8; 32]) -> [u8; 32] {
    let p = vrf_prove(secret, input);
    let mut r = [0u8; 32];
    r.copy_from_slice(&p.proof[..32]);
    r
}

// --- audit helpers: public-algorithm recomputation (RFC-style check) ---------
// These mirror the documented derivations using only PUBLIC values
// (domain tags are `pub`; the test knows its own fixture seeds).

/// Recompute the secret scalar exactly as `VrfSecret::scalar` documents.
fn audit_scalar(seed: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(VRF_SCALAR_DOMAIN);
    h.update(seed);
    let d = h.finalize();
    let mut h2 = Sha512::new();
    h2.update(VRF_SCALAR_DOMAIN);
    h2.update(b"hi");
    h2.update(seed);
    let d2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d[..32]);
    wide[32..].copy_from_slice(&d2[..32]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Recompute the Schnorr challenge exactly as `vrf.rs` documents.
fn audit_challenge(r: &[u8; 32], pk: &[u8; 32], input: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(VRF_PROOF_DOMAIN);
    h.update(b"challenge");
    h.update(r);
    h.update(pk);
    h.update(input);
    let d = h.finalize();
    let mut h2 = Sha512::new();
    h2.update(VRF_PROOF_DOMAIN);
    h2.update(b"wide-hi");
    h2.update(b"challenge");
    h2.update(r);
    h2.update(pk);
    h2.update(input);
    let d2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d[..32]);
    wide[32..].copy_from_slice(&d2[..32]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn audit_output(r: &[u8; 32], pk: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_OUTPUT_DOMAIN);
    hasher.update(r);
    hasher.update(pk);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

// --- 1. determinism: 100 seeds x 8 inputs ------------------------------------

#[test]
fn determinism_100_seeds_x_8_inputs() {
    assert_eq!(VRF_PROOF_LEN, 64);
    for i in 0..100usize {
        let secret = VrfSecret::from_seed(&audit_seed(i));
        let pk = secret.public_key().to_bytes();
        for j in 0..8usize {
            let input = audit_input(j);
            let a = vrf_prove(&secret, &input);
            let b = vrf_prove(&secret, &input);
            assert_eq!(a, b, "same key+input must re-prove byte-identically (i={i} j={j})");
            assert_eq!(a.proof.len(), VRF_PROOF_LEN);
            assert_eq!(
                vrf_verify(&pk, &input, &a),
                Some(a.output),
                "honest proof must verify (i={i} j={j})"
            );
        }
    }
}

// --- 2. nonce diversity: distinct inputs => distinct nonces (via R) ----------

#[test]
fn nonce_diversity_distinct_inputs_give_distinct_nonces() {
    for i in [0usize, 1, 7, 42, 99] {
        let secret = VrfSecret::from_seed(&audit_seed(i));
        let mut seen = Vec::new();
        for j in 0..8usize {
            let r = r_bytes_of(&secret, &audit_input(j));
            assert!(
                !seen.contains(&r),
                "nonce reuse across inputs would be catastrophic (seed {i} input {j})"
            );
            seen.push(r);
            // Re-proving the same input reuses the SAME nonce (determinism).
            assert_eq!(r, r_bytes_of(&secret, &audit_input(j)));
        }
        // Distinct keys also separate nonces for a fixed input.
        let other = VrfSecret::from_seed(&audit_seed(i + 1000));
        assert_ne!(
            r_bytes_of(&secret, &audit_input(0)),
            r_bytes_of(&other, &audit_input(0)),
            "distinct keys must not share nonces"
        );
    }
}

// --- 3. soundness: tamper classes all refuse ---------------------------------

#[test]
fn roundtrip_verifies_and_every_tamper_class_refuses() {
    let secret = VrfSecret::from_seed(&audit_seed(7));
    let pk = secret.public_key().to_bytes();
    let input = audit_input(3);
    let good = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &good), Some(good.output));

    // Every single-bit flip at every proof position refuses (64-position sweep).
    for pos in 0..VRF_PROOF_LEN {
        let mut bad = good.clone();
        bad.proof[pos] ^= 0x01;
        assert_eq!(
            vrf_verify(&pk, &input, &bad),
            None,
            "flipped proof byte {pos} must refuse"
        );
    }

    // Swapped output refuses (output bound to proof bytes).
    for pos in 0..32usize {
        let mut bad_out = good.clone();
        bad_out.output[pos] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &input, &bad_out), None);
    }

    // Wrong seed input refuses.
    for j in 0..8usize {
        if audit_input(j) == input {
            continue;
        }
        assert_eq!(vrf_verify(&pk, &audit_input(j), &good), None);
    }

    // Wrong key refuses.
    for i in [0usize, 1, 8, 99] {
        let other_pk = VrfSecret::from_seed(&audit_seed(i + 500)).public_key().to_bytes();
        assert_eq!(vrf_verify(&other_pk, &input, &good), None);
    }

    // Identity key refuses.
    assert_eq!(vrf_verify(&[0u8; 32], &input, &good), None);

    // Non-canonical `z` refuses (canonical scalar encoding is enforced).
    let mut bad_z = good.clone();
    bad_z.proof[32..].copy_from_slice(&[0xFFu8; 32]);
    assert_eq!(vrf_verify(&pk, &input, &bad_z), None);

    // All-zero proof bytes refuse (identity R + zero z satisfies nothing).
    let zero = stellereum::vrf::VrfProof {
        output: [0u8; 32],
        proof: [0u8; VRF_PROOF_LEN],
    };
    assert_eq!(vrf_verify(&pk, &input, &zero), None);
}

// --- 4. edge cases: zero keys, zero/0xFF inputs, key parsing ------------------

#[test]
fn edge_zero_keys_and_extreme_inputs() {
    // Zero seed still derives a usable (non-identity) key and round-trips.
    let zero_secret = VrfSecret::from_seed(&[0u8; 32]);
    let zero_pk = zero_secret.public_key().to_bytes();
    assert!(
        VrfPublicKey::from_bytes(&zero_pk).is_some(),
        "zero seed must still derive a valid non-identity key"
    );
    let input = audit_input(0);
    let proof = vrf_prove(&zero_secret, &input);
    assert_eq!(vrf_verify(&zero_pk, &input, &proof), Some(proof.output));

    // 0xFF seed round-trips.
    let ff_secret = VrfSecret::from_seed(&[0xFFu8; 32]);
    let ff_pk = ff_secret.public_key().to_bytes();
    assert!(VrfPublicKey::from_bytes(&ff_pk).is_some());
    assert_eq!(
        vrf_verify(&ff_pk, &input, &vrf_prove(&ff_secret, &input)),
        Some(vrf_prove(&ff_secret, &input).output)
    );

    // All-zero and all-0xFF inputs are ordinary domain points: round-trip.
    for extreme in [[0u8; 32], [0xFFu8; 32]] {
        let p = vrf_prove(&zero_secret, &extreme);
        assert_eq!(vrf_verify(&zero_pk, &extreme, &p), Some(p.output));
    }

    // Key parsing: valid parses, identity and garbage refuse.
    assert!(VrfPublicKey::from_bytes(&zero_pk).is_some());
    assert!(VrfPublicKey::from_bytes(&[0u8; 32]).is_none());
    assert!(VrfPublicKey::from_bytes(&[0xFFu8; 32]).is_none());

    // Distinct seeds give distinct keys (injective key derivation on fixtures).
    let a = VrfSecret::from_seed(&audit_seed(0)).public_key();
    let b = VrfSecret::from_seed(&audit_seed(1)).public_key();
    assert_ne!(a, b);
}

// --- 5. activation boundary math ----------------------------------------------

#[test]
fn activation_boundaries_u64_edges() {
    assert_eq!(VrfActivation::default(), VrfActivation::Disabled);
    assert!(!VrfActivation::Disabled.is_active_at(0));
    assert!(!VrfActivation::Disabled.is_active_at(u64::MAX));
    assert_eq!(VrfActivation::Disabled.boundary(), None);

    // FromHeight(0): active from genesis.
    let genesis = VrfActivation::FromHeight(0);
    assert!(genesis.is_active_at(0));
    assert!(genesis.is_active_at(u64::MAX));
    assert_eq!(genesis.boundary(), Some(0));

    // FromHeight(MAX): inactive until the last representable height.
    let last = VrfActivation::FromHeight(u64::MAX);
    assert!(!last.is_active_at(0));
    assert!(!last.is_active_at(u64::MAX - 1));
    assert!(last.is_active_at(u64::MAX));
    assert_eq!(last.boundary(), Some(u64::MAX));

    // Interior boundary: h-1 off, h on, h+1 on.
    let mid = VrfActivation::FromHeight(1_000_000);
    assert!(!mid.is_active_at(999_999));
    assert!(mid.is_active_at(1_000_000));
    assert!(mid.is_active_at(1_000_001));
    assert_eq!(mid.boundary(), Some(1_000_000));
}

// --- 6. election seed binding --------------------------------------------------

#[test]
fn election_seed_deterministic_and_binds_height_round_output() {
    let out = [0xABu8; 32];
    assert_eq!(
        vrf_election_seed(&out, 7, 0),
        vrf_election_seed(&out, 7, 0)
    );
    assert_ne!(
        vrf_election_seed(&out, 7, 0),
        vrf_election_seed(&[0xACu8; 32], 7, 0),
        "output must move the seed"
    );
    assert_ne!(
        vrf_election_seed(&out, 7, 0),
        vrf_election_seed(&out, 8, 0),
        "height must move the seed"
    );
    assert_ne!(
        vrf_election_seed(&out, 7, 0),
        vrf_election_seed(&out, 7, 1),
        "round must move the seed"
    );
    // Extreme heights/rounds are well-defined (no panic, deterministic).
    assert_eq!(
        vrf_election_seed(&out, u64::MAX, u32::MAX),
        vrf_election_seed(&out, u64::MAX, u32::MAX)
    );
    assert_ne!(
        vrf_election_seed(&out, 0, 0),
        vrf_election_seed(&out, u64::MAX, u32::MAX)
    );
}

// --- 7. registry-gated minting --------------------------------------------------

#[test]
fn registry_binding_gates_seed_minting() {
    let falcon = FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
    let secret = VrfSecret::from_seed(&audit_seed(3));
    let vrf_pk = secret.public_key().to_bytes();
    let validator_id = [0x11u8; 32];
    let sig = falcon.sign(&vrf_binding_preimage(&validator_id, &vrf_pk));
    let mut reg = VrfRegistry::new();
    assert!(reg.is_empty());
    reg.register(
        &VrfBinding {
            validator_id,
            vrf_pk,
            falcon_sig: sig,
        },
        falcon.public_key(),
    )
    .expect("honest binding registers");
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.get(&validator_id), Some(vrf_pk));

    let input = audit_input(5);
    let proof = vrf_prove(&secret, &input);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &validator_id, &input, &proof),
        Some(proof.output),
        "registered validator mints a verified seed"
    );
    // Unknown validator, foreign proof, and wrong input all refuse.
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &[0x22u8; 32], &input, &proof),
        None
    );
    let foreign = vrf_prove(&VrfSecret::from_seed(&audit_seed(77)), &input);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &validator_id, &input, &foreign),
        None
    );
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &validator_id, &audit_input(6), &proof),
        None
    );
}

// --- 8. documented ECVRF gap: NO uniqueness ------------------------------------
// A Schnorr signature admits many valid `(R, z)` per message, so the secret
// holder can mint a SECOND valid proof for the same input with a different
// output. ECVRF uniqueness (RFC 9381: exactly one verifiable output per
// pk+input) does NOT hold for this construction. This test characterizes the
// gap constructively using an independently-derived nonce; it PASSES by
// demonstrating the second proof verifies. Phase 2 (audited-ECVRF swap)
// closes it; no fail-closed tweak inside Schnorr can.

#[test]
fn documented_gap_no_uniqueness_second_valid_proof_exists() {
    let seed = audit_seed(11);
    let secret = VrfSecret::from_seed(&seed);
    let pk = secret.public_key().to_bytes();
    let input = audit_input(2);

    // Recompute the secret scalar via the public derivation and cross-check
    // against the crate's own key (validates this test's replication).
    let s = audit_scalar(&seed);
    assert_eq!(
        RistrettoPoint::mul_base(&s).compress().to_bytes(),
        pk,
        "audit scalar replication must match the crate key"
    );

    let first = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &first), Some(first.output));

    // Holder crafts an alternate proof under a fresh, independently-chosen
    // nonce `k2` (any nonzero scalar; the deterministic `vrf_prove` uses one
    // derived `k`, but nothing in verification pins the prover to it).
    let k2 = Scalar::from(0x9E37_79B9_7F4A_7C15u64);
    let r2 = RistrettoPoint::mul_base(&k2).compress().to_bytes();
    assert_ne!(r2, first.proof[..32], "alternate nonce must give alternate R");
    let c2 = audit_challenge(&r2, &pk, &input);
    let z2 = k2 + c2 * s;
    let mut proof2 = [0u8; VRF_PROOF_LEN];
    proof2[..32].copy_from_slice(&r2);
    proof2[32..].copy_from_slice(&z2.to_bytes());
    let output2 = audit_output(&r2, &pk, &input);
    let alt = stellereum::vrf::VrfProof {
        output: output2,
        proof: proof2,
    };
    assert_eq!(
        vrf_verify(&pk, &input, &alt),
        Some(output2),
        "second honestly-constructed proof must also verify"
    );
    assert_ne!(
        alt.output, first.output,
        "gap demonstrated: two valid proofs, two outputs, one (pk, input)"
    );
}
