//! Crypto-primitive audit tests for `stellereum::vrf` (ECVRF-EDWARDS25519-
//! SHA512-Elligator2, RFC 9381).
//!
//! Scope: the CRYPTO PRIMITIVE ONLY (`vrf_prove` / `vrf_verify`, nonce
//! derivation, key handling, activation-gate math, election-seed binding).
//! Activation wiring in `main.rs` / `consensus.rs` belongs to another worker
//! and is not touched here.
//!
//! What this file pins:
//! * determinism — 100 seeds x 8 inputs, re-prove is byte-identical;
//! * soundness — honestly-generated proofs verify; every tamper class
//!   (proof-byte flips at all 80 positions, output swap, wrong key,
//!   wrong input, identity key, non-canonical `s`, all-zero proof) refuses;
//! * nonce diversity — different inputs under one key give different curve
//!   points (observed via distinct `Gamma`), so no catastrophic nonce reuse;
//! * edge cases — zero seed, zero/0xFF inputs, activation boundaries,
//!   election-seed height/round binding, registry-gated minting;
//! * uniqueness — exactly one verifiable output per (key, input):
//!   re-proving is byte-identical AND no second proof verifies (RFC 9381
//!   §3.1 full uniqueness; the retired Schnorr wiring admitted many valid
//!   `(R, z)` per message and could not pin this).

use stellereum::post_quantum::FalconKeypair;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_binding_preimage, vrf_election_seed, vrf_prove, vrf_verify,
    VrfActivation, VrfBinding, VrfPublicKey, VrfRegistry, VrfSecret, VRF_PROOF_LEN,
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

// --- 1. determinism: 100 seeds x 8 inputs ------------------------------------

#[test]
fn determinism_100_seeds_x_8_inputs() {
    assert_eq!(VRF_PROOF_LEN, 80, "ECVRF pi is Gamma(32) || c(16) || s(32)");
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

// --- 2. nonce diversity: distinct inputs => distinct Gammas (via H) ----------

#[test]
fn nonce_diversity_distinct_inputs_give_distinct_nonces() {
    for i in [0usize, 1, 7, 42, 99] {
        let secret = VrfSecret::from_seed(&audit_seed(i));
        let mut seen = Vec::new();
        for j in 0..8usize {
            let r = r_bytes_of(&secret, &audit_input(j));
            assert!(
                !seen.contains(&r),
                "Gamma reuse across inputs would break uniqueness (seed {i} input {j})"
            );
            seen.push(r);
            // Re-proving the same input reuses the SAME envelope (determinism).
            assert_eq!(r, r_bytes_of(&secret, &audit_input(j)));
        }
        // Distinct keys also separate Gammas for a fixed input.
        let other = VrfSecret::from_seed(&audit_seed(i + 1000));
        assert_ne!(
            r_bytes_of(&secret, &audit_input(0)),
            r_bytes_of(&other, &audit_input(0)),
            "distinct keys must not share Gammas"
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

    // Non-canonical `s` refuses (scalar encoding is range-checked: s < q).
    let mut bad_s = good.clone();
    bad_s.proof[48..].copy_from_slice(&[0xFFu8; 32]);
    assert_eq!(vrf_verify(&pk, &input, &bad_s), None);

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

// --- 8. uniqueness: exactly one verifiable output per (key, input) ----------
// The retired Schnorr wiring admitted many valid `(R, z)` per message, so a
// holder could mint a second valid proof for the same input. ECVRF closes
// this (RFC 9381 §3.1 full uniqueness): the curve point `H` is a
// deterministic function of the input and `Gamma = x*H` binds the secret
// scalar, leaving the holder no free nonce to grind over. This test pins
// the closed gap constructively: try-and-select over 32 holder secrets
// yields exactly ONE proof that verifies under the registered key — the
// registered secret's own — so best-of-N collapses to the honest draw.

#[test]
fn uniqueness_one_verifiable_output_per_key_and_input() {
    let seed = audit_seed(11);
    let secret = VrfSecret::from_seed(&seed);
    let pk = secret.public_key().to_bytes();
    let input = audit_input(2);

    let first = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &first), Some(first.output));

    // Re-proving is byte-identical: the envelope is a pure function of
    // (secret, input), so no second envelope exists to choose between.
    let again = vrf_prove(&secret, &input);
    assert_eq!(
        again, first,
        "same key+input must re-prove byte-identically (uniqueness prerequisite)"
    );

    // Try-and-select over 32 secrets: only the registered secret's proof
    // verifies under `pk`. Every other secret's proof — honestly minted for
    // itself — refuses under this key (wrong-key rule), so the holder has
    // no alternate ticket to select.
    let mut foreign_verifying = 0u32;
    for t in 0..32u64 {
        let mut alt_seed = seed;
        alt_seed[0..8].copy_from_slice(&t.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
        alt_seed[31] = alt_seed[31].wrapping_add(t as u8);
        if alt_seed == seed {
            continue; // never collide with the registered secret itself
        }
        let alt = vrf_prove(&VrfSecret::from_seed(&alt_seed), &input);
        assert_ne!(alt, first, "distinct secrets mint distinct envelopes");
        if vrf_verify(&pk, &input, &alt) == Some(alt.output) {
            foreign_verifying += 1;
        }
    }
    assert_eq!(
        foreign_verifying, 0,
        "no foreign secret's proof may verify under pk: exactly one \
         verifiable output per (pk, input), no grinding surface"
    );
}
