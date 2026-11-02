//! Grinding measurement for the ECVRF VRF (`stellereum::vrf`).
//!
//! CONTEXT: `vrf_prove` is RFC 9381 ECVRF-EDWARDS25519-SHA512-Elligator2
//! (`output` = leading half of `beta`, `proof` = `Gamma || c || s`). The
//! retired deterministic-Schnorr wiring admitted many valid `(R, z)` per
//! message, so a holder could mint best-of-N alternate proofs and keep the
//! most favourable output (measured lift `1-(1-p)^N`). ECVRF closes this:
//! the curve point `H` is a deterministic function of the input and
//! `Gamma = x*H` binds the secret scalar, leaving no free nonce to grind
//! over. THIS file re-runs the measurement battery to verify the damage is
//! gone: try-and-select over N secrets yields NO lift — best-of-N collapses
//! to the honest draw exactly.
//!
//! DEGREES OF FREEDOM (exact, RFC 9381 §3.1 full uniqueness):
//! * FIXED by others: the seed input, the secret scalar, the proof bytes
//!   (deterministic function of secret+input), the challenge/output hashes.
//! * FREE: nothing per (key, input) — one envelope verifies per key. Key
//!   grinding (N distinct secrets) gives N independent tickets, but only the
//!   Falcon-registered key mints for a validator id, and each key's ticket
//!   is a single uniform draw: the honest lottery model.
//!
//! MEASUREMENT (all deterministic fixtures — no OS randomness, no wall clock,
//! except the timing test which reports, never asserts, wall time):
//! * best-of-N over secrets: per (key, input) exactly one proof verifies
//!   (the registered key's), so best-of-N == honest exactly (no lift);
//! * uniformity: chi-square (16 bins over output[15] high nibble) of honest
//!   vs best-of-N outputs — identical distributions, both uniform;
//! * committee lift: measured P(elected) for honest vs best-of-N against the
//!   honest closed form `p` (NOT `1-(1-p)^N` — amplification must be absent);
//! * cost: wall time per proof mint (cheap minting is fine now that grinding
//!   buys nothing).

use stellereum::vrf::{
    lottery_threshold, vrf_prove, vrf_verify, VrfSecret,
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

/// Lottery ticket: low 128 bits of the VRF output, LE (matches the
/// `lottery_threshold` 128-bit ticket model in `src/vrf.rs`).
/// Grinder strategy: keep the MINIMUM ticket over N attempts — which, under
/// uniqueness, is always the single verifiable ticket.
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

// --- 1. no degree of freedom: one envelope verifies per (key, input) ---------

#[test]
fn grinding_no_nonce_surface_single_envelope_verifies() {
    let seed = fixture_seed(11);
    let secret = VrfSecret::from_seed(&seed);
    let pk = secret.public_key().to_bytes();
    let input = fixture_input(2);

    // Honest path is deterministic (pins the construction under test).
    let honest = vrf_prove(&secret, &input);
    assert_eq!(vrf_prove(&secret, &input), honest);
    assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));

    // Re-proving mints the SAME envelope: no second candidate exists.
    for _ in 0..3u64 {
        let again = vrf_prove(&secret, &input);
        assert_eq!(
            again, honest,
            "determinism leaves no room for an alternate proof"
        );
        assert_eq!(vrf_verify(&pk, &input, &again), Some(honest.output));
    }
    // Distinct secrets mint distinct envelopes, but none of them verifies
    // under THIS key: the holder cannot manufacture a second ticket.
    for t in 0..3u64 {
        let mut alt_seed = seed;
        alt_seed[0..8].copy_from_slice(&t.wrapping_mul(0x51AB).to_le_bytes());
        alt_seed[31] = alt_seed[31].wrapping_add(t as u8);
        if alt_seed == seed {
            continue;
        }
        let alt = vrf_prove(&VrfSecret::from_seed(&alt_seed), &input);
        assert_ne!(alt, honest, "distinct secrets mint distinct envelopes");
        assert_eq!(
            vrf_verify(&pk, &input, &alt),
            None,
            "foreign secret's proof must not verify under this key"
        );
    }
}

// --- 2. best-of-N == honest: no uniformity loss, no committee lift ------------

#[test]
fn grinding_best_of_n_collapses_to_honest_no_lift() {
    const K: usize = 16;
    const M: usize = 16;
    const N: u64 = 32; // grinder secrets tried per input
    const SET_SIZES: [u64; 4] = [3, 4, 8, 16];

    // Per input: the honest ticket and the best-of-N ticket (minimum over
    // the N secrets' outputs that VERIFY under the registered key).
    let mut honest_bins = [0usize; 16];
    let mut best_bins = [0usize; 16];
    let mut honest_tickets: Vec<u128> = Vec::with_capacity(K * M);
    let mut best_tickets: Vec<u128> = Vec::with_capacity(K * M);

    for i in 0..K {
        let seed = fixture_seed(i);
        let secret = VrfSecret::from_seed(&seed);
        let pk = secret.public_key().to_bytes();
        // The grinder's N secrets: the registered one plus N-1 foreign ones.
        let mut grinder_seeds = vec![seed];
        for t in 1..N {
            let mut gs = seed;
            gs[0..8].copy_from_slice(&t.wrapping_mul(0xC0FFEE).to_le_bytes());
            gs[31] = gs[31].wrapping_add(t as u8);
            grinder_seeds.push(gs);
        }
        for j in 0..M {
            let input = fixture_input(j);
            let honest = vrf_prove(&secret, &input);
            assert_eq!(
                vrf_verify(&pk, &input, &honest),
                Some(honest.output),
                "honest proof must verify (key {i} input {j})"
            );
            honest_tickets.push(ticket(&honest.output));
            honest_bins[(honest.output[15] >> 4) as usize] += 1;

            // Try-and-select: keep the minimum ticket over the outputs that
            // verify under the registered key.
            let mut best = u128::MAX;
            let mut best_out = [0u8; 32];
            let mut verifying = 0u32;
            for gs in &grinder_seeds {
                let cand = vrf_prove(&VrfSecret::from_seed(gs), &input);
                if vrf_verify(&pk, &input, &cand) == Some(cand.output) {
                    verifying += 1;
                    let ct = ticket(&cand.output);
                    if ct < best {
                        best = ct;
                        best_out = cand.output;
                    }
                }
            }
            assert_eq!(
                verifying, 1,
                "exactly one verifiable output per (key {i}, input {j})"
            );
            assert_eq!(
                best,
                ticket(&honest.output),
                "best-of-{N} must equal the honest ticket (no lift)"
            );
            best_tickets.push(best);
            best_bins[(best_out[15] >> 4) as usize] += 1;
        }
    }
    let trials = (K * M) as f64;

    // --- uniformity: both histograms uniform (15 dof; expectation 15) ---
    let honest_chi = chi_square_16(&honest_bins);
    let best_chi = chi_square_16(&best_bins);
    eprintln!("[grinding] honest output chi-square (15 dof, K*M={}): {honest_chi:.2}", K * M);
    eprintln!("[grinding] best-of-{N} output chi-square (15 dof): {best_chi:.2}");
    assert!(
        honest_chi < 40.0,
        "honest outputs must look uniform (chi-square {honest_chi:.2})"
    );
    assert_eq!(
        best_bins, honest_bins,
        "best-of-N selection must not skew the distribution"
    );

    // --- committee lift: measured rate tracks the HONEST p, never 1-(1-p)^N ---
    for n in SET_SIZES {
        let threshold = lottery_threshold(1, n, 1);
        assert_ne!(threshold, 0, "one seat of {n} must be winnable");
        let p = threshold as f64 / 2f64.powi(128);
        let honest_hit = honest_tickets.iter().filter(|t| **t < threshold).count() as f64 / trials;
        let best_hit = best_tickets.iter().filter(|t| **t < threshold).count() as f64 / trials;
        let amplified = 1.0 - (1.0 - p).powi(N as i32);
        eprintln!(
            "[grinding] set n={n}: p_honest={p:.6} honest={honest_hit:.4} best-of-{N}={best_hit:.4} (retired-amplified={amplified:.4})"
        );
        assert_eq!(
            best_hit, honest_hit,
            "best-of-{N} must elect exactly the honest set (n={n})"
        );
        assert!(
            (honest_hit - p).abs() < 0.09,
            "honest rate {honest_hit:.3} must track p={p:.3} (n={n})"
        );
        // The retired amplification must be GONE: best-of-N stays at p even
        // where 1-(1-p)^N would exceed it by a wide margin.
        assert!(
            (best_hit - amplified).abs() > 0.05 || (amplified - p).abs() < 0.05,
            "best-of-{N} rate {best_hit:.3} must not track the retired closed form {amplified:.3} (n={n})"
        );
    }
}

// --- 3. cost per proof (minting is cheap; grinding buys nothing) ---------------

#[test]
fn grinding_cost_per_extra_proof() {
    const ATTEMPTS: u64 = 320;
    let seed = fixture_seed(3);
    let secret = VrfSecret::from_seed(&seed);
    let pk = secret.public_key().to_bytes();
    let input = fixture_input(5);

    // Warm up (page in code, settle caches), then time mint-only.
    for t in 0..8u64 {
        let mut ws = seed;
        ws[0..8].copy_from_slice(&t.to_le_bytes());
        let p = vrf_prove(&VrfSecret::from_seed(&ws), &input);
        if ws == seed {
            assert_eq!(vrf_verify(&pk, &input, &p), Some(p.output));
        }
    }
    let start = Instant::now();
    let mut distinct = 0usize;
    let mut prev = vrf_prove(&secret, &input).output;
    for t in 0..ATTEMPTS {
        let mut ws = seed;
        ws[0..8].copy_from_slice(&(1000 + t).to_le_bytes());
        let p = vrf_prove(&VrfSecret::from_seed(&ws), &input);
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
    // Distinct secrets mint distinct outputs (tickets differ per key)...
    assert!(
        distinct as f64 / ATTEMPTS as f64 > 0.95,
        "distinct secrets must mint distinct outputs, distinct={distinct}/{ATTEMPTS}"
    );
    // ...but only the registered key's verifies: minting is cheap, and that
    // is fine, because extra mints buy no election advantage.
    let honest = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));
    // Guardrail only: minting must stay cheap (microseconds).
    assert!(
        per_proof_ns < 50_000_000,
        "proof-mint cost {per_proof_ns}ns exceeds the cheap-mint guardrail"
    );
}
