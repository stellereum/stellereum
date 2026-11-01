//! Cryptanalysis track for `stellereum::vrf` (deterministic-Schnorr VRF).
//!
//! Extends — never duplicates — `vrf_audit_tests.rs` (determinism, soundness
//! sweep, nonce diversity, uniqueness gap) and `vrf_bls_adversarial_tests.rs`
//! (fail-closed battery). New games here:
//!
//! * (a) key substitution: adversary keypair + victim identity — the proof
//!   verifies under the ATTACKER key but registry-gated minting refuses,
//!   pinning the trust boundary (identity lives in the Falcon binding only);
//! * (b) grinding quantification: M inputs x N holder-ground alternate proofs,
//!   output-uniformity statistic (chi-square over the first byte) plus the
//!   measured best-of-N committee bias vs the closed form `1-(1-p)^N`;
//! * (c) domain separation: nonce/challenge/output/election/beacon tags are
//!   pairwise distinct AND behaviorally binding (any tag flip breaks verify);
//! * (d) small-subgroup / identity / edge keys: Ristretto rejects everything
//!   below the prime-order group; identity refuses at every layer;
//! * (e) malleability on a FRESH proof: all 512 single-bit mutants refuse,
//!   plus halves-swap/duplication, cross-proof splices, output-bit sweep,
//!   and serde truncation/extension refusal.
//!
//! All fixtures are deterministic (no OS randomness, no wall clock).

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use stellereum::post_quantum::FalconKeypair;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_binding_preimage, vrf_election_seed, vrf_prove, vrf_verify,
    VrfBinding, VrfPublicKey, VrfRegistry, VrfSecret, VRF_BEACON_DOMAIN, VRF_BINDING_DST,
    VRF_ELECTION_DOMAIN, VRF_OUTPUT_DOMAIN, VRF_PROOF_DOMAIN, VRF_PROOF_LEN, VRF_SCALAR_DOMAIN,
};

// --- deterministic fixtures (disjoint multipliers from the audit file) --------

fn cry_seed(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(i as u64).wrapping_mul(0xD134_2547_6A35_1F09).to_le_bytes());
    s[8] = 0x6D;
    s[31] = (i as u8).wrapping_add(0x2A);
    s
}

fn cry_input(j: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(j as u64).wrapping_add(0x51AB).to_le_bytes());
    s[8] = 0xC4;
    s[31] = 0x7E;
    s
}

// --- public-algorithm replicas (mirror src/vrf.rs derivations) ----------------

fn cry_scalar(seed: &[u8; 32]) -> Scalar {
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

fn cry_challenge(r: &[u8; 32], pk: &[u8; 32], input: &[u8; 32]) -> Scalar {
    cry_challenge_under(VRF_PROOF_DOMAIN, b"challenge", r, pk, input)
}

fn cry_challenge_under(
    domain: &[u8],
    tag: &[u8],
    r: &[u8; 32],
    pk: &[u8; 32],
    input: &[u8; 32],
) -> Scalar {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(tag);
    h.update(r);
    h.update(pk);
    h.update(input);
    let d = h.finalize();
    let mut h2 = Sha512::new();
    h2.update(domain);
    h2.update(b"wide-hi");
    h2.update(tag);
    h2.update(r);
    h2.update(pk);
    h2.update(input);
    let d2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d[..32]);
    wide[32..].copy_from_slice(&d2[..32]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn cry_output(r: &[u8; 32], pk: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_OUTPUT_DOMAIN);
    hasher.update(r);
    hasher.update(pk);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

/// Adversary nonce `k_j`: a PRF over (secret seed, input, j). Any scalar is a
/// valid Schnorr nonce at verify time — nothing pins the prover to the crate's
/// derived `k` — so this models exactly what a grinding holder can mint.
fn grind_scalar(secret_seed: &[u8; 32], input: &[u8; 32], j: u64) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"STELL_VRF_GRIND_V1");
    h.update(secret_seed);
    h.update(input);
    h.update(j.to_le_bytes());
    let d = h.finalize();
    let mut h2 = Sha512::new();
    h2.update(b"STELL_VRF_GRIND_V1");
    h2.update(b"hi");
    h2.update(secret_seed);
    h2.update(input);
    h2.update(j.to_le_bytes());
    let d2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d[..32]);
    wide[32..].copy_from_slice(&d2[..32]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Build an alternate valid proof under nonce `k` (holder-only: needs `s`).
fn alt_proof(s: &Scalar, pk: &[u8; 32], input: &[u8; 32], k: Scalar) -> stellereum::vrf::VrfProof {
    let r = RistrettoPoint::mul_base(&k).compress().to_bytes();
    let c = cry_challenge(&r, pk, input);
    let z = k + c * s;
    let mut proof = [0u8; VRF_PROOF_LEN];
    proof[..32].copy_from_slice(&r);
    proof[32..].copy_from_slice(&z.to_bytes());
    let output = cry_output(&r, pk, input);
    stellereum::vrf::VrfProof { output, proof }
}

fn ticket_u128(output: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&output[..16]);
    u128::from_le_bytes(b)
}

fn best_of_n(p: f64, n: u64) -> f64 {
    1.0 - (1.0 - p).powi(n as i32)
}

// --- (a) key substitution: proof verifies under attacker key, never identity -

#[test]
fn key_substitution_proof_binds_key_not_identity() {
    // Victim registers honestly: (victim_id -> victim_pk) under victim Falcon.
    let victim_falcon = FalconKeypair::generate_from_seed_bytes(&cry_seed(900));
    let victim_secret = VrfSecret::from_seed(&cry_seed(901));
    let victim_pk = victim_secret.public_key().to_bytes();
    let victim_id = [0x51u8; 32];
    let sig = victim_falcon.sign(&vrf_binding_preimage(&victim_id, &victim_pk));
    let mut reg = VrfRegistry::new();
    reg.register(
        &VrfBinding {
            validator_id: victim_id,
            vrf_pk: victim_pk,
            falcon_sig: sig,
        },
        victim_falcon.public_key(),
    )
    .expect("honest binding registers");

    // Adversary mints their OWN keypair and proves the same seed input.
    let attacker_secret = VrfSecret::from_seed(&cry_seed(902));
    let attacker_pk = attacker_secret.public_key().to_bytes();
    assert_ne!(attacker_pk, victim_pk);
    let input = cry_input(41);
    let attacker_proof = vrf_prove(&attacker_secret, &input);

    // TRUST BOUNDARY, part 1: the attacker's proof is CRYPTOGRAPHICALLY VALID
    // under the attacker's key. Raw `vrf_verify` authenticates the KEY, not
    // the validator identity — anyone can mint valid proofs for themselves.
    assert_eq!(
        vrf_verify(&attacker_pk, &input, &attacker_proof),
        Some(attacker_proof.output),
        "attacker proof verifies under attacker key (proof binds key only)"
    );

    // TRUST BOUNDARY, part 2: claiming the VICTIM identity fails at the
    // registry layer — the attacker's proof does not verify under the
    // victim's registered key, so no seed mints for the victim id.
    assert_eq!(
        vrf_verify(&victim_pk, &input, &attacker_proof),
        None,
        "attacker proof must not verify under victim key"
    );
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &victim_id, &input, &attacker_proof),
        None,
        "attacker proof must not mint a seed for the victim identity"
    );

    // TRUST BOUNDARY, part 3: the attacker cannot register their key under
    // the victim id either — the binding needs the VICTIM Falcon signature
    // over (victim_id || attacker_pk), which the attacker cannot forge.
    let attacker_falcon = FalconKeypair::generate_from_seed_bytes(&cry_seed(903));
    let forged_sig = attacker_falcon.sign(&vrf_binding_preimage(&victim_id, &attacker_pk));
    let forged = VrfBinding {
        validator_id: victim_id,
        vrf_pk: attacker_pk,
        falcon_sig: forged_sig,
    };
    // Attacker-signed binding fails against the VICTIM Falcon key...
    assert!(!forged.verify(victim_falcon.public_key()));
    assert!(reg.register(&forged, victim_falcon.public_key()).is_err());
    // ...and registry contents are untouched: victim key still bound.
    assert_eq!(reg.get(&victim_id), Some(victim_pk));

    // Completeness control: the victim's own proof still mints.
    let victim_proof = vrf_prove(&victim_secret, &input);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &victim_id, &input, &victim_proof),
        Some(victim_proof.output)
    );
    // And the victim cannot claim an unregistered identity either.
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &[0x99u8; 32], &input, &victim_proof),
        None
    );
}

// --- (b) grinding quantification: uniformity + best-of-N bias -----------------

#[test]
fn grinding_uniformity_and_best_of_n_bias() {
    const M: usize = 128; // distinct seed inputs
    const N: u64 = 32; // holder-ground alternates per input
    let secret_seed = cry_seed(500);
    let secret = VrfSecret::from_seed(&secret_seed);
    let pk = secret.public_key().to_bytes();
    let s = cry_scalar(&secret_seed);
    assert_eq!(
        RistrettoPoint::mul_base(&s).compress().to_bytes(),
        pk,
        "replica scalar must match crate key"
    );

    // Mint M x N alternate outputs (plus the M honest ones for the control).
    let mut first_bytes: Vec<u8> = Vec::with_capacity(M * N as usize);
    let mut bit_balance = 0usize; // outputs with output[0] < 128
    let mut best_tickets = Vec::with_capacity(M);
    let mut honest_tickets = Vec::with_capacity(M);
    for j in 0..M {
        let input = cry_input(j);
        let honest = vrf_prove(&secret, &input);
        assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));
        honest_tickets.push(ticket_u128(&honest.output));
        let mut best = u128::MAX;
        for g in 0..N {
            let k = grind_scalar(&secret_seed, &input, g);
            // Grind nonces must be usable (non-identity R) and pairwise
            // distinct per input, else the "N candidates" model collapses.
            let r = RistrettoPoint::mul_base(&k).compress().to_bytes();
            let dec = curve25519_dalek::ristretto::CompressedRistretto(r).decompress();
            assert!(
                dec.map(|p| !p.is_identity()).unwrap_or(false),
                "grind nonce must give non-identity R"
            );
            let alt = alt_proof(&s, &pk, &input, k);
            assert_eq!(
                vrf_verify(&pk, &input, &alt),
                Some(alt.output),
                "holder-ground alternate must verify (no uniqueness)"
            );
            first_bytes.push(alt.output[0]);
            if alt.output[0] < 128 {
                bit_balance += 1;
            }
            best = best.min(ticket_u128(&alt.output));
        }
        best_tickets.push(best);
    }
    let total = first_bytes.len();
    assert_eq!(total, M * N as usize);

    // Uniformity: first-byte histogram over all M*N outputs, chi-square with
    // 255 df (uniform expectation: total/256 per bin, mean stat = 255).
    let mut bins = [0u32; 256];
    for b in &first_bytes {
        bins[*b as usize] += 1;
    }
    let expected = total as f64 / 256.0;
    let mut chi2 = 0.0f64;
    let (mut lo, mut hi) = (u32::MAX, 0u32);
    for b in bins {
        let d = b as f64 - expected;
        chi2 += d * d / expected;
        lo = lo.min(b);
        hi = hi.max(b);
    }
    let balance_frac = bit_balance as f64 / total as f64;
    // Mean best-ticket fraction of the 2^128 range (honest mean is 0.5;
    // best-of-32 uniform order stat mean is 1/33 ≈ 0.0303).
    let mean_best =
        best_tickets.iter().map(|t| *t as f64 / u128::MAX as f64).sum::<f64>() / M as f64;

    // Committee bias: thresholds straight from `lottery_threshold`
    // (p ≈ 0.05 / 0.25 / 0.50), honest single-draw rate vs measured
    // best-of-32 rate vs closed form 1-(1-p)^32.
    let configs: [(&str, u64, u64, u64, f64); 3] = [
        ("stake1/total100/exp5", 1, 100, 5, 0.05),
        ("stake1/total4/exp1", 1, 4, 1, 0.25),
        ("stake1/total2/exp1", 1, 2, 1, 0.50),
    ];
    eprintln!("GRIND: M={M} inputs x N={N} alternates = {total} outputs");
    eprintln!("GRIND: first-byte chi2={chi2:.1} (df=255, uniform mean 255)");
    eprintln!("GRIND: first-byte bin min={lo} max={hi} expected={expected:.1}");
    eprintln!("GRIND: first-bit balance frac={balance_frac:.4} (uniform 0.5)");
    eprintln!("GRIND: mean best-of-{N} ticket frac={mean_best:.5} (uniform-order-stat 0.03030)");
    for (name, stake, total_stake, exp_seats, p) in configs {
        let thr = stellereum::vrf::lottery_threshold(stake, total_stake, exp_seats);
        assert!(thr > 0 && thr < u128::MAX, "config must be a strict interior threshold");
        let honest_rate = honest_tickets.iter().filter(|t| **t < thr).count() as f64 / M as f64;
        let best_rate = best_tickets.iter().filter(|t| **t < thr).count() as f64 / M as f64;
        let closed = best_of_n(p, N);
        eprintln!(
            "GRIND: {name} p={p:.2} thr-top-half={:032x} honest-rate={honest_rate:.4} \
             measured-best-of-{N}={best_rate:.4} closed-form={closed:.4}",
            thr >> 64
        );
        // Grinding never hurts the holder: best <= honest ticket per input,
        // so every honestly-elected input stays elected when grinding.
        assert!(
            best_rate >= honest_rate,
            "best-of-N must elect a superset of the honest draw ({name})"
        );
        // Measured amplification tracks the closed form (loose band: M=128
        // sampling noise at p=0.05 is ~0.035 sigma; 0.20 is ~6 sigma).
        assert!(
            (best_rate - closed).abs() < 0.20,
            "measured best-of-N rate must track 1-(1-p)^N ({name})"
        );
        // Honest rate tracks the nominal p (loose band, same noise scale).
        assert!(
            (honest_rate - p).abs() < 0.15,
            "honest single-draw rate must track p ({name})"
        );
    }

    // Uniformity gates (generous: chi2 mean 255, sd ~22.6; 500 is +10 sd —
    // a failure here means the output hash is structurally broken).
    assert!(chi2 < 500.0, "output first byte must be ~uniform, chi2={chi2:.1}");
    assert!(lo > 0, "with {expected:.0}/bin no bin should be empty (min={lo})");
    assert!(
        (balance_frac - 0.5).abs() < 0.10,
        "first bit must be balanced, frac={balance_frac:.4}"
    );
    // Grinding buys a real downward shift of the ticket (holder advantage is
    // constructive, not theoretical): mean best far below the honest 0.5.
    assert!(
        mean_best < 0.15,
        "best-of-{N} must shift the ticket down hard, mean={mean_best:.5}"
    );
    assert!(mean_best > 0.0, "tickets must not collapse to zero");
}

// --- (c) domain separation: tags distinct AND behaviorally binding ------------

#[test]
fn domain_tags_distinct_and_binding() {
    // Code-inspection pin: every domain tag in the construction is distinct,
    // so no two hash roles can collide by construction.
    let domains: Vec<&[u8]> = vec![
        VRF_PROOF_DOMAIN,
        VRF_SCALAR_DOMAIN,
        VRF_BINDING_DST,
        VRF_OUTPUT_DOMAIN.as_bytes(),
        VRF_ELECTION_DOMAIN.as_bytes(),
        VRF_BEACON_DOMAIN.as_bytes(),
    ];
    for (i, a) in domains.iter().enumerate() {
        for (j, b) in domains.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "domain tags {i} and {j} must differ");
            }
        }
    }
    // Role tags inside the proof domain are distinct too.
    assert_ne!(b"nonce".as_slice(), b"challenge".as_slice());

    let secret_seed = cry_seed(600);
    let secret = VrfSecret::from_seed(&secret_seed);
    let pk = secret.public_key().to_bytes();
    let s = cry_scalar(&secret_seed);
    let input = cry_input(60);
    let honest = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));

    // 1. Proof built with nonce/challenge role tags SWAPPED refuses: the
    //    "nonce" preimage hashed with b"challenge" (and vice versa) yields a
    //    Schnorr equation the real verifier (correct tags) rejects.
    {
        let k_bad = cry_challenge_under(VRF_PROOF_DOMAIN, b"challenge", &secret_seed, &pk, &input);
        // NOTE: deliberately feeds (secret_seed, pk, input) where the nonce
        // derivation expects (secret, input) — any tag/position confusion
        // must break the proof, whichever way it is wired.
        let r_bad = RistrettoPoint::mul_base(&k_bad).compress().to_bytes();
        let c_bad = cry_challenge_under(VRF_PROOF_DOMAIN, b"nonce", &r_bad, &pk, &input);
        let z_bad = k_bad + c_bad * s;
        let mut proof = [0u8; VRF_PROOF_LEN];
        proof[..32].copy_from_slice(&r_bad);
        proof[32..].copy_from_slice(&z_bad.to_bytes());
        let swapped = stellereum::vrf::VrfProof {
            output: cry_output(&r_bad, &pk, &input),
            proof,
        };
        assert_eq!(
            vrf_verify(&pk, &input, &swapped),
            None,
            "nonce/challenge tag confusion must break verification"
        );
    }

    // 2. Challenge built under a one-bit-flipped proof domain refuses.
    {
        let mut bad_domain = VRF_PROOF_DOMAIN.to_vec();
        bad_domain[0] ^= 0x01;
        let k = grind_scalar(&secret_seed, &input, 7);
        let r = RistrettoPoint::mul_base(&k).compress().to_bytes();
        let c_bad = cry_challenge_under(&bad_domain, b"challenge", &r, &pk, &input);
        let z_bad = k + c_bad * s;
        let mut proof = [0u8; VRF_PROOF_LEN];
        proof[..32].copy_from_slice(&r);
        proof[32..].copy_from_slice(&z_bad.to_bytes());
        let bad = stellereum::vrf::VrfProof {
            output: cry_output(&r, &pk, &input),
            proof,
        };
        assert_eq!(
            vrf_verify(&pk, &input, &bad),
            None,
            "flipped proof-domain challenge must not verify under the real domain"
        );
    }

    // 3. Output built under a flipped output domain refuses (output binding).
    {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&honest.proof[..32]);
        let mut hasher = blake3::Hasher::new_derive_key("STELL_VRF_OUTPUT_V2");
        hasher.update(&r_bytes);
        hasher.update(&pk);
        hasher.update(&input);
        let wrong_out = *hasher.finalize().as_bytes();
        assert_ne!(wrong_out, honest.output, "fixture needs distinct domains");
        let mut bad = honest.clone();
        bad.output = wrong_out;
        assert_eq!(
            vrf_verify(&pk, &input, &bad),
            None,
            "output from a foreign domain must refuse"
        );
    }

    // 4. Election seed and beacon chain live in disjoint domains: swapping
    //    roles (beacon bytes as election output and vice versa) never
    //    collides, and height/round still bind under the election domain.
    {
        let prev = [0x11u8; 32];
        let beacon = stellereum::vrf::beacon_next(&prev, &honest.output);
        let elect = vrf_election_seed(&honest.output, 7, 0);
        assert_ne!(beacon, elect, "beacon/election domains must separate");
        assert_ne!(
            elect,
            vrf_election_seed(&beacon, 7, 0),
            "role-swapped bytes must give a different seed"
        );
        assert_ne!(
            elect,
            stellereum::vrf::beacon_next(&prev, &elect),
            "election bytes fed back to the beacon must move it"
        );
    }
}

// --- (d) small-subgroup / identity / edge keys --------------------------------

#[test]
fn edge_keys_identity_small_subgroup_and_extremes() {
    let secret = VrfSecret::from_seed(&cry_seed(700));
    let pk = secret.public_key().to_bytes();
    let input = cry_input(70);
    let honest = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));

    // Identity refuses at parse AND at verify (both spellings).
    assert!(VrfPublicKey::from_bytes(&[0u8; 32]).is_none());
    let id_pt = RistrettoPoint::mul_base(&Scalar::from(0u64))
        .compress()
        .to_bytes();
    assert!(VrfPublicKey::from_bytes(&id_pt).is_none());
    assert_eq!(vrf_verify(&[0u8; 32], &input, &honest), None);
    assert_eq!(vrf_verify(&id_pt, &input, &honest), None);

    // Garbage / non-canonical encodings refuse at parse and at verify.
    assert!(VrfPublicKey::from_bytes(&[0xFFu8; 32]).is_none());
    let mut non_canonical = pk;
    non_canonical[31] |= 0x80; // high-bit set: outside the canonical range
    // (may or may not parse; either way the honest proof must not verify)
    assert_eq!(vrf_verify(&non_canonical, &input, &honest), None);

    // Low-order-candidate sweep: every single-byte-pattern key either fails
    // to parse (Ristretto has no small-subgroup encodings that decompress)
    // or parses to a wrong key under which the honest proof refuses.
    // Either outcome is fail-closed; none may accept.
    let mut parsed_count = 0u32;
    for b in 0u8..=255u8 {
        let cand = [b; 32];
        if cand == pk {
            continue; // fixture sanity: honest key is not a flat pattern
        }
        if VrfPublicKey::from_bytes(&cand).is_some() {
            parsed_count += 1;
        }
        assert_eq!(
            vrf_verify(&cand, &input, &honest),
            None,
            "flat-pattern key {b:#04x} must never accept an honest proof"
        );
    }
    eprintln!("EDGE: flat-pattern keys that parse as valid Ristretto: {parsed_count}/256");
    // NOTE: a nonzero parse count is EXPECTED, not a weakness — Ristretto
    // encodings are dense, and every successfully-decompressed point lies in
    // the prime-order group by construction (no cofactor subgroup exists to
    // smuggle in). The fail-closed pin is above: every one of the 256
    // candidates refuses the honest proof, parsed or not.

    // Proof carrying R = identity refuses (identity-R equation cannot hold
    // for an honestly-derived z/output pair).
    {
        let mut bad_r = honest.clone();
        bad_r.proof[..32].copy_from_slice(&[0u8; 32]);
        assert_eq!(vrf_verify(&pk, &input, &bad_r), None);
        let mut bad_r2 = honest.clone();
        bad_r2.proof[..32].copy_from_slice(&[0xFFu8; 32]);
        assert_eq!(vrf_verify(&pk, &input, &bad_r2), None);
    }

    // Edge secrets still derive usable non-identity keys (no degenerate
    // accept-all path): zero, 0xFF, and near-zero seeds round-trip, and
    // their keys are pairwise distinct.
    for edge in [[0u8; 32], [0xFFu8; 32], {
        let mut e = [0u8; 32];
        e[31] = 0x01;
        e
    }] {
        let sk = VrfSecret::from_seed(&edge);
        let edge_pk = sk.public_key().to_bytes();
        assert!(
            VrfPublicKey::from_bytes(&edge_pk).is_some(),
            "edge seed must derive a valid non-identity key"
        );
        let p = vrf_prove(&sk, &input);
        assert_eq!(vrf_verify(&edge_pk, &input, &p), Some(p.output));
    }
    assert_ne!(
        VrfSecret::from_seed(&[0u8; 32]).public_key(),
        VrfSecret::from_seed(&[0xFFu8; 32]).public_key()
    );

    // Cofactor note pinned behaviorally: honest R values are prime-order
    // multiples of the basepoint, hence never identity for nonzero nonce.
    for j in 0..16usize {
        let r = RistrettoPoint::mul_base(&grind_scalar(&cry_seed(700), &cry_input(j), 0));
        assert!(!r.is_identity(), "nonzero nonce must give non-identity R");
    }
}

// --- (e) malleability on a FRESH proof ----------------------------------------

#[test]
fn malleability_fresh_proof_all_single_bits_plus_shape_attacks() {
    // FRESH fixtures (disjoint from every prior sweep).
    let secret = VrfSecret::from_seed(&cry_seed(800));
    let pk = secret.public_key().to_bytes();
    let input = cry_input(80);
    let good = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &good), Some(good.output));

    // Exhaustive single-bit sweep: all 64 proof bytes x all 8 bit positions.
    // (Prior battery flipped only 0x01 per position on a different proof.)
    let mut checked = 0u32;
    for pos in 0..VRF_PROOF_LEN {
        for bit in 0..8u32 {
            let mut bad = good.clone();
            bad.proof[pos] ^= 1u8 << bit;
            assert_eq!(
                vrf_verify(&pk, &input, &bad),
                None,
                "proof byte {pos} bit {bit} flip must refuse"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 512);

    // Exhaustive single-bit sweep over the bound output field too.
    for pos in 0..32usize {
        for bit in 0..8u32 {
            let mut bad = good.clone();
            bad.output[pos] ^= 1u8 << bit;
            assert_eq!(
                vrf_verify(&pk, &input, &bad),
                None,
                "output byte {pos} bit {bit} flip must refuse"
            );
        }
    }

    // Full-byte flips at every proof position (stronger per-position fault).
    for pos in 0..VRF_PROOF_LEN {
        let mut bad = good.clone();
        bad.proof[pos] ^= 0xFF;
        assert_eq!(vrf_verify(&pk, &input, &bad), None);
    }

    // Shape attacks: halves swapped / duplicated (R||z -> z||R, R||R, z||z).
    {
        let mut r_half = [0u8; 32];
        let mut z_half = [0u8; 32];
        r_half.copy_from_slice(&good.proof[..32]);
        z_half.copy_from_slice(&good.proof[32..]);
        assert_ne!(r_half, z_half, "fixture needs distinct halves");

        let mut swapped = good.clone();
        swapped.proof[..32].copy_from_slice(&z_half);
        swapped.proof[32..].copy_from_slice(&r_half);
        swapped.output = cry_output(&z_half, &pk, &input);
        assert_eq!(vrf_verify(&pk, &input, &swapped), None);

        let mut rr = good.clone();
        rr.proof[32..].copy_from_slice(&r_half);
        rr.output = cry_output(&r_half, &pk, &input);
        assert_eq!(vrf_verify(&pk, &input, &rr), None);

        let mut zz = good.clone();
        zz.proof[..32].copy_from_slice(&z_half);
        zz.output = cry_output(&z_half, &pk, &input);
        assert_eq!(vrf_verify(&pk, &input, &zz), None);
    }

    // Cross-proof splice: R from proof A + z from proof B (same key, two
    // inputs) refuses in both directions, as do cross-wired outputs.
    {
        let other = vrf_prove(&secret, &cry_input(81));
        assert_ne!(good.proof, other.proof);
        let mut splice = good.clone();
        splice.proof[32..].copy_from_slice(&other.proof[32..]);
        assert_eq!(vrf_verify(&pk, &input, &splice), None);
        let mut splice2 = other.clone();
        splice2.proof[..32].copy_from_slice(&good.proof[..32]);
        assert_eq!(vrf_verify(&pk, &cry_input(81), &splice2), None);
        let mut xout = good.clone();
        xout.output = other.output;
        assert_eq!(vrf_verify(&pk, &input, &xout), None);
    }

    // Truncation / extension at the ENVELOPE layer (serde JSON): any dropped
    // or appended byte breaks decoding, so a short/long envelope can never
    // smuggle the same 64 proof bytes past the verifier.
    {
        let json = serde_json::to_string(&good).expect("envelope serializes");
        let rt: stellereum::vrf::VrfProof =
            serde_json::from_str(&json).expect("envelope round-trips");
        assert_eq!(rt, good);
        // Truncations at several cut points all fail.
        for cut in [1usize, 8, 32, 64] {
            let trunc = &json[..json.len() - cut];
            assert!(
                serde_json::from_str::<stellereum::vrf::VrfProof>(trunc).is_err(),
                "truncated envelope (cut {cut}) must not decode"
            );
        }
        // Extensions (trailing garbage) fail: serde_json rejects trailing chars.
        let extended2 = format!("{json}x");
        assert!(
            serde_json::from_str::<stellereum::vrf::VrfProof>(&extended2).is_err(),
            "garbage-extended envelope must not decode"
        );
        // Empty / null / wrong-shape payloads fail.
        for bad in ["", "null", "[]", "{}", "[1,2,3]"] {
            assert!(
                serde_json::from_str::<stellereum::vrf::VrfProof>(bad).is_err(),
                "payload {bad:?} must not decode as an envelope"
            );
        }
    }
    eprintln!("MALLEABILITY: 512 proof-bit + 256 output-bit + shape/splice/serde mutants all refuse");
}
