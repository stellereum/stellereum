//! Grinding measurement for the deterministic-Schnorr VRF (`stellereum::vrf`).
//!
//! CONTEXT: `vrf_prove` is a deterministic Schnorr signature used AS a VRF
//! (`output = BLAKE3(R || pk || seed)`, proof = `(R, z)`). The audit suite
//! (`tests/vrf_audit_tests.rs`, `documented_gap_no_uniqueness_...`) proves a
//! second valid proof exists for one input. THIS file quantifies the damage:
//! for K keys x M inputs, an adversarial holder mints best-of-N proofs
//! (N = 2, 8, 32) and keeps the output most favourable to sortition.
//!
//! DEGREES OF FREEDOM (exact, from `src/vrf.rs:499-511`):
//! * FIXED by others: the seed input (beacon / `sortition_seed` output — the
//!   holder cannot change it), the secret scalar `s` (fixing implies the pk),
//!   the challenge/output hash structure (verification pins them).
//! * FREE: exactly one scalar — the nonce `k`. `vrf_prove` derives
//!   `k = H(secret || seed_input)`, but NOTHING in `vrf_verify`
//!   (`src/vrf.rs:518-546`) pins the prover to that `k`: for ANY nonzero `k'`,
//!   `R' = k'G`, `c' = H(R', pk, seed)`, `z' = k' + c's` satisfies
//!   `z'G == R' + c'PK` and mints `output' = BLAKE3(R' || pk || seed)` which
//!   verifies. So the grinder's search space is the full 256-bit nonce field:
//!   every fresh `k'` is one fresh i.i.d.-uniform output candidate, at the
//!   cost of one scalar mul + two hashes. Key grinding (many registered keys)
//!   is NOT available per-input: one `VrfBinding` per validator id, each
//!   Falcon-signed and visible — the nonce is the whole surface.
//!
//! MEASUREMENT (all deterministic fixtures — no OS randomness, no wall clock,
//! except the timing test which reports, never asserts, wall time):
//! * uniformity: chi-square (16 bins over output[0] high nibble) of honest
//!   outputs vs best-of-N minima (min ticket = optimal lottery strategy);
//! * committee lift: equal-stake sets n in {3,4,8,16}, one expected seat,
//!   `lottery_threshold(1, n, 1)`; measured P(elected) for honest vs
//!   best-of-N, against closed form `1-(1-p)^N` with `p = threshold/2^128`;
//! * cost: wall time per extra (alternate-proof) mint.
//!
//! CONSTRAINT NOTE: zero `src/` changes. The alternate-proof minter below
//! duplicates the ~5-line Schnorr derivation from `src/vrf.rs` in-test
//! (same domains, fresh nonce tag) — a measurement copy, not a fork.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use stellereum::vrf::{
    lottery_threshold, vrf_prove, vrf_verify, VrfProof, VrfSecret, VRF_OUTPUT_DOMAIN,
    VRF_PROOF_DOMAIN, VRF_PROOF_LEN, VRF_SCALAR_DOMAIN,
};
use std::time::Instant;

// --- deterministic fixtures (no OS randomness) --------------------------------

/// K distinct secret seeds.
fn fixture_seed(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    s[8] = 0x3C;
    s[31] = (i as u8).wrapping_add(0x51);
    s
}

/// M distinct seed inputs.
fn fixture_input(j: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(j as u64).wrapping_add(0xD1B5).to_le_bytes());
    s[8] = 0xA7;
    s[31] = 0xE3;
    s
}

// --- measurement-local Schnorr replicas ---------------------------------------
// DUPLICATED from `src/vrf.rs` (scalar/challenge/output derivations) with ONE
// change: the nonce is freshly sampled per grind attempt `t` instead of the
// deterministic `vrf_prove` nonce. Same domains, same equations — so every
// minted proof verifies under the real `vrf_verify`. Test-only copy.

/// Replica of `VrfSecret::scalar` (`src/vrf.rs:198-211`).
fn replica_scalar(seed: &[u8; 32]) -> Scalar {
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

/// Replica of the challenge scalar (`src/vrf.rs:463-481`).
fn replica_challenge(r: &[u8; 32], pk: &[u8; 32], input: &[u8; 32]) -> Scalar {
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

/// Replica of the output hash (`src/vrf.rs:483-493`).
fn replica_output(r: &[u8; 32], pk: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_OUTPUT_DOMAIN);
    hasher.update(r);
    hasher.update(pk);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

/// Fresh grind nonce `k_t`: same wide-hash pattern as `vrf_scalar`, fresh tag.
/// Models the adversary sampling one fresh uniform nonce per attempt.
fn grind_nonce(seed: &[u8; 32], input: &[u8; 32], t: u64) -> Scalar {
    let mut h = Sha512::new();
    h.update(VRF_PROOF_DOMAIN);
    h.update(b"grind-nonce");
    h.update(seed);
    h.update(input);
    h.update(t.to_le_bytes());
    let d = h.finalize();
    let mut h2 = Sha512::new();
    h2.update(VRF_PROOF_DOMAIN);
    h2.update(b"grind-nonce");
    h2.update(seed);
    h2.update(input);
    h2.update(t.to_le_bytes());
    let d2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d[..32]);
    wide[32..].copy_from_slice(&d2[..32]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Mint alternate proof #`t` for (`seed`, `input`) under a fresh nonce.
/// Every output verifies under the real `vrf_verify` against the matching pk.
fn mint_grind_proof(seed: &[u8; 32], input: &[u8; 32], t: u64) -> VrfProof {
    let s = replica_scalar(seed);
    let pk = RistrettoPoint::mul_base(&s).compress().to_bytes();
    let k = grind_nonce(seed, input, t);
    let r = RistrettoPoint::mul_base(&k).compress().to_bytes();
    let c = replica_challenge(&r, &pk, input);
    let z = k + c * s;
    let mut proof = [0u8; VRF_PROOF_LEN];
    proof[..32].copy_from_slice(&r);
    proof[32..].copy_from_slice(&z.to_bytes());
    let output = replica_output(&r, &pk, input);
    VrfProof { output, proof }
}

/// Lottery ticket: low 128 bits of the VRF output, LE (matches the
/// `lottery_threshold` 128-bit ticket model in `src/vrf.rs:611-644`).
/// Grinder strategy: keep the MINIMUM ticket over N attempts.
fn ticket(output: &[u8; 32]) -> u128 {
    let bytes: [u8; 16] = output[0..16]
        .try_into()
        .expect("first 16 output bytes form the ticket");
    u128::from_le_bytes(bytes)
}

/// Chi-square over 16 bins against the uniform expectation.
fn chi_square_16(counts: &[usize; 16]) -> f64 {
    let total: usize = counts.iter().sum();
    let exp = total as f64 / 16.0;
    counts
        .iter()
        .map(|c| {
            let d = *c as f64 - exp;
            d * d / exp
        })
        .sum()
}

// --- 1. degrees of freedom: nonce is the whole surface -------------------------

#[test]
fn grinding_nonce_is_the_only_degree_of_freedom() {
    let seed = fixture_seed(11);
    let secret = VrfSecret::from_seed(&seed);
    let pk = secret.public_key().to_bytes();
    let input = fixture_input(2);

    // Honest path is deterministic (pins the construction under test).
    let honest = vrf_prove(&secret, &input);
    assert_eq!(vrf_prove(&secret, &input), honest);
    assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));

    // Three fresh nonces -> three further VALID proofs, pairwise-distinct R.
    let mut seen_r = vec![honest.proof[..32].to_vec()];
    let mut seen_out = vec![honest.output];
    for t in 0..3u64 {
        let alt = mint_grind_proof(&seed, &input, t);
        assert_eq!(
            vrf_verify(&pk, &input, &alt),
            Some(alt.output),
            "grind attempt {t} must verify (Schnorr admits any nonce)"
        );
        assert!(
            !seen_r.contains(&alt.proof[..32].to_vec()),
            "fresh nonce must give fresh R"
        );
        assert!(
            !seen_out.contains(&alt.output),
            "fresh R must give a fresh output candidate"
        );
        seen_r.push(alt.proof[..32].to_vec());
        seen_out.push(alt.output);
    }
    // Nothing else varies: seed input, secret scalar, pk, challenge and output
    // structure are all pinned by verification — the nonce is the surface.
}

// --- 2. best-of-N: uniformity loss + committee-inclusion lift --------------------

#[test]
fn grinding_best_of_n_distribution_and_committee_lift() {
    const K: usize = 16;
    const M: usize = 16;
    const N_MAX: u64 = 32;
    const GRIND_NS: [u64; 3] = [2, 8, 32];
    const SET_SIZES: [u64; 4] = [3, 4, 8, 16];
    const BINS: usize = 16;

    // Per (key, input): honest ticket + running best-of-N minima.
    // Bins are keyed on output[15] (high nibble): the ticket is the LE u128
    // of output[0..16], so output[15] is the ticket's MOST significant byte —
    // the byte min-selection pressures hardest. (Binning output[0], the LSB,
    // stays near-uniform even under grinding and would hide the skew.)
    let mut honest_bins = [0usize; 16];
    let mut best_bins: [[usize; 16]; 3] = [[0usize; 16]; 3];
    let mut honest_tickets: Vec<u128> = Vec::with_capacity(K * M);
    let mut best_tickets: [Vec<u128>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for b in best_tickets.iter_mut() {
        b.reserve(K * M);
    }

    for i in 0..K {
        let seed = fixture_seed(i);
        let secret = VrfSecret::from_seed(&seed);
        let pk = secret.public_key().to_bytes();
        for j in 0..M {
            let input = fixture_input(j);
            let honest = vrf_prove(&secret, &input);
            assert_eq!(
                vrf_verify(&pk, &input, &honest),
                Some(honest.output),
                "honest proof must verify (key {i} input {j})"
            );
            honest_bins[(honest.output[15] >> 4) as usize] += 1;
            honest_tickets.push(ticket(&honest.output));

            // Mint N_MAX alternates; the best-of-N ticket is the running min.
            // Track the winning OUTPUT bytes so binning sees the real minima.
            let mut best: [u128; 3] = [u128::MAX; 3];
            let mut best_out: [[u8; 32]; 3] = [[0u8; 32]; 3];
            for t in 0..N_MAX {
                let alt = mint_grind_proof(&seed, &input, t);
                assert_eq!(
                    vrf_verify(&pk, &input, &alt),
                    Some(alt.output),
                    "grind proof {t} must verify (key {i} input {j})"
                );
                let ct = ticket(&alt.output);
                for (gi, g) in GRIND_NS.iter().enumerate() {
                    if t < *g && ct < best[gi] {
                        best[gi] = ct;
                        best_out[gi] = alt.output;
                    }
                }
            }
            for (gi, bmin) in best.iter().enumerate() {
                assert_ne!(*bmin, u128::MAX, "best-of-N must observe a ticket");
                best_tickets[gi].push(*bmin);
                best_bins[gi][(best_out[gi][15] >> 4) as usize] += 1;
            }
        }
    }
    let trials = (K * M) as f64;

    // --- uniformity: chi-square (15 dof; uniform expectation = 15) ---
    let honest_chi = chi_square_16(&honest_bins);
    eprintln!("[grinding] honest output chi-square (15 dof, K*M={}): {honest_chi:.2}", K * M);
    assert!(
        honest_chi < 40.0,
        "honest outputs must look uniform (chi-square {honest_chi:.2})"
    );
    for (gi, g) in GRIND_NS.iter().enumerate() {
        let chi = chi_square_16(&best_bins[gi]);
        let bin0 = best_bins[gi][0] as f64 / trials;
        eprintln!("[grinding] best-of-{g} chosen-output chi-square (15 dof): {chi:.2} (bin0 share={bin0:.3})");
        let _ = BINS;
    }
    // Best-of-32 minima must be violently non-uniform (stacked in low bins).
    assert!(
        chi_square_16(&best_bins[2]) > 500.0,
        "best-of-32 minima must be skewed, chi-square = {:.2}",
        chi_square_16(&best_bins[2])
    );

    // --- committee lift: measured vs closed form 1-(1-p)^N ---
    for n in SET_SIZES {
        let threshold = lottery_threshold(1, n, 1);
        assert_ne!(threshold, 0, "one seat of {n} must be winnable");
        let p = threshold as f64 / 2f64.powi(128);
        eprintln!("[grinding] set n={n}: threshold={threshold} p_honest={p:.6}");
        let honest_hit = honest_tickets
            .iter()
            .filter(|t| **t < threshold)
            .count() as f64
            / trials;
        eprintln!("[grinding]   honest measured P(elected)={honest_hit:.4} closed-form p={p:.4}");
        assert!(
            (honest_hit - p).abs() < 0.09,
            "honest rate {honest_hit:.3} must track p={p:.3} (n={n})"
        );
        for (gi, g) in GRIND_NS.iter().enumerate() {
            let measured = best_tickets[gi]
                .iter()
                .filter(|t| **t < threshold)
                .count() as f64
                / trials;
            let closed = 1.0 - (1.0 - p).powi(*g as i32);
            let lift = measured / honest_hit.max(1e-9);
            eprintln!(
                "[grinding]   best-of-{g}: measured P={measured:.4} closed-form={closed:.4} lift=x{lift:.2}"
            );
            assert!(
                (measured - closed).abs() < 0.12,
                "best-of-{g} measured {measured:.3} must track closed form {closed:.3} (n={n})"
            );
        }
    }

    // Ordering: more grinding never hurts the grinder.
    for n in SET_SIZES {
        let threshold = lottery_threshold(1, n, 1);
        let count = |v: &[u128]| v.iter().filter(|t| **t < threshold).count();
        let h = count(&honest_tickets);
        let b2 = count(&best_tickets[0]);
        let b8 = count(&best_tickets[1]);
        let b32 = count(&best_tickets[2]);
        assert!(
            b32 >= b8 && b8 >= b2 && b2 >= h,
            "grinding must be monotone: honest={h} b2={b2} b8={b8} b32={b32} (n={n})"
        );
    }
}

// --- 3. cost per extra proof ------------------------------------------------------

#[test]
fn grinding_cost_per_extra_proof() {
    const ATTEMPTS: u64 = 320;
    let seed = fixture_seed(3);
    let secret = VrfSecret::from_seed(&seed);
    let pk = secret.public_key().to_bytes();
    let input = fixture_input(5);

    // Warm up (page in code, settle caches), then time mint-only.
    for t in 0..8u64 {
        let p = mint_grind_proof(&seed, &input, t);
        assert_eq!(vrf_verify(&pk, &input, &p), Some(p.output));
    }
    let start = Instant::now();
    let mut distinct = 0usize;
    let mut prev = honest_output_of(&seed, &input);
    for t in 0..ATTEMPTS {
        let p = mint_grind_proof(&seed, &input, 1000 + t);
        assert_eq!(
            vrf_verify(&pk, &input, &p),
            Some(p.output),
            "timed grind proof must verify"
        );
        if p.output != prev {
            distinct += 1;
        }
        prev = p.output;
    }
    let elapsed = start.elapsed();
    let per_proof_ns = elapsed.as_nanos() / u128::from(ATTEMPTS);
    eprintln!(
        "[grinding] {ATTEMPTS} extra proofs in {}ms => {per_proof_ns}ns/proof (distinct-output rate {distinct}/{ATTEMPTS})",
        elapsed.as_millis()
    );
    // Every extra proof is a fresh candidate: outputs must (almost) all differ.
    assert!(
        distinct as f64 / ATTEMPTS as f64 > 0.95,
        "extra proofs must mint fresh candidates, distinct={distinct}/{ATTEMPTS}"
    );
    // Guardrail only: grinding must be cheap (microseconds), i.e. no defence
    // by cost is available — the number itself is the finding.
    assert!(
        per_proof_ns < 50_000_000,
        "extra-proof cost {per_proof_ns}ns exceeds the cheap-grinding guardrail"
    );
}

/// Honest output for the timing test's pair (keeps the distinctness check
/// anchored to the real construction, not the replica).
fn honest_output_of(seed: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    vrf_prove(&VrfSecret::from_seed(seed), input).output
}
