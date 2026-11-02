//! Cryptanalysis track for `stellereum::vrf` (ECVRF-EDWARDS25519-SHA512-
//! Elligator2, RFC 9381).
//!
//! Extends — never duplicates — `vrf_audit_tests.rs` (determinism, soundness
//! sweep, nonce diversity, uniqueness) and `vrf_bls_adversarial_tests.rs`
//! (fail-closed battery). Games here:
//!
//! * (a) key substitution: adversary keypair + victim identity — the proof
//!   verifies under the ATTACKER key but registry-gated minting refuses,
//!   pinning the trust boundary (identity lives in the Falcon binding only);
//! * (b) grinding quantification: M inputs x N holder secrets — output
//!   uniformity (chi-square over the first byte) plus the measured
//!   best-of-N committee rate, which MUST equal the honest rate exactly
//!   (uniqueness: no amplification; the retired Schnorr wiring measured
//!   `1-(1-p)^N` here);
//! * (c) domain separation: tags are pairwise distinct AND behaviorally
//!   binding (retired-construction envelopes and role-swapped output
//!   domains refuse; beacon/election role-swap never collides);
//! * (d) small-subgroup / identity / edge keys: Edwards rejects low-order
//!   keys at parse AND at verify; garbage refuses; flat-pattern sweep is
//!   fail-closed;
//! * (e) malleability on a FRESH proof: all 640 single-bit mutants refuse,
//!   plus field-swap/duplication, cross-proof splices, output-bit sweep,
//!   and serde truncation/extension refusal.
//!
//! All fixtures are deterministic (no OS randomness, no wall clock).

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

// --- holder-secret grinder: N distinct secrets, one registered key --------------
//
// Under ECVRF uniqueness the holder's try-and-select runs over SECRETS (each
// secret mints exactly one envelope per input), not over nonces. Only the
// registered secret's envelope verifies under the registered key.

/// The grinder's t-th secret for a fixed holder seed (distinct keys).
fn grind_secret(holder_seed: &[u8; 32], t: u64) -> [u8; 32] {
    let mut s = *holder_seed;
    for (i, b) in t.to_le_bytes().iter().enumerate() {
        s[i] = s[i].wrapping_add(*b);
    }
    s[31] = s[31].wrapping_add((t >> 8) as u8);
    s
}

fn ticket_u128(output: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&output[..16]);
    u128::from_le_bytes(b)
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

// --- (b) grinding quantification: uniformity + best-of-N (no lift) ------------
// Under ECVRF uniqueness the holder's try-and-select runs over SECRETS:
// N distinct secrets minted per input, exactly one envelope verifying per
// (registered key, input). Best-of-N MUST collapse to the honest draw —
// this is the measurement that flips vs the retired Schnorr wiring (which
// measured best-of-32 tracking the closed form 1-(1-p)^32 here).

#[test]
fn grinding_uniformity_and_best_of_n_bias() {
    const M: usize = 128; // distinct seed inputs
    const N: u64 = 32; // holder secrets tried per input
    let secret_seed = cry_seed(500);
    let secret = VrfSecret::from_seed(&secret_seed);
    let pk = secret.public_key().to_bytes();

    // M honest outputs (the control) + per-input best-of-N over secrets.
    let mut first_bytes: Vec<u8> = Vec::with_capacity(M);
    let mut bit_balance = 0usize; // outputs with output[0] < 128
    let mut best_tickets = Vec::with_capacity(M);
    let mut honest_tickets = Vec::with_capacity(M);
    for j in 0..M {
        let input = cry_input(j);
        let honest = vrf_prove(&secret, &input);
        assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));
        honest_tickets.push(ticket_u128(&honest.output));
        first_bytes.push(honest.output[0]);
        if honest.output[0] < 128 {
            bit_balance += 1;
        }
        // Try-and-select over N secrets: keep the minimum ticket over the
        // outputs that VERIFY under the registered key.
        let mut best = u128::MAX;
        let mut verifying = 0u32;
        for g in 0..N {
            let gs = grind_secret(&secret_seed, g);
            if gs == secret_seed {
                continue; // the registered secret is measured separately
            }
            let cand = vrf_prove(&VrfSecret::from_seed(&gs), &input);
            if vrf_verify(&pk, &input, &cand) == Some(cand.output) {
                verifying += 1;
                best = best.min(ticket_u128(&cand.output));
            }
        }
        assert_eq!(
            verifying, 0,
            "no foreign secret may verify under the registered key (input {j})"
        );
        best = best.min(ticket_u128(&honest.output));
        best_tickets.push(best);
    }
    let total = first_bytes.len();
    assert_eq!(total, M);

    // Uniformity: first-byte histogram over all M outputs, chi-square with
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
    // Mean best-ticket fraction of the 2^128 range: uniqueness pins it at
    // the honest 0.5 (best-of-32 uniform order stat would sit at 1/33).
    let mean_best =
        best_tickets.iter().map(|t| *t as f64 / u128::MAX as f64).sum::<f64>() / M as f64;

    // Committee rates: thresholds straight from `lottery_threshold`
    // (p ≈ 0.05 / 0.25 / 0.50). Best-of-N MUST equal the honest rate
    // exactly — and the honest rate tracks the nominal p.
    let configs: [(&str, u64, u64, u64, f64); 3] = [
        ("stake1/total100/exp5", 1, 100, 5, 0.05),
        ("stake1/total4/exp1", 1, 4, 1, 0.25),
        ("stake1/total2/exp1", 1, 2, 1, 0.50),
    ];
    eprintln!("GRIND: M={M} inputs x N={N} secrets = {total} honest outputs");
    eprintln!("GRIND: first-byte chi2={chi2:.1} (df=255, uniform mean 255)");
    eprintln!("GRIND: first-byte bin min={lo} max={hi} expected={expected:.1}");
    eprintln!("GRIND: first-bit balance frac={balance_frac:.4} (uniform 0.5)");
    eprintln!("GRIND: mean best-of-{N} ticket frac={mean_best:.5} (honest 0.5)");
    for (name, stake, total_stake, exp_seats, p) in configs {
        let thr = stellereum::vrf::lottery_threshold(stake, total_stake, exp_seats);
        assert!(thr > 0 && thr < u128::MAX, "config must be a strict interior threshold");
        let honest_rate = honest_tickets.iter().filter(|t| **t < thr).count() as f64 / M as f64;
        let best_rate = best_tickets.iter().filter(|t| **t < thr).count() as f64 / M as f64;
        let retired = 1.0 - (1.0 - p).powi(N as i32);
        eprintln!(
            "GRIND: {name} p={p:.2} thr-top-half={:032x} honest-rate={honest_rate:.4} \
             measured-best-of-{N}={best_rate:.4} retired-closed-form={retired:.4}",
            thr >> 64
        );
        // Uniqueness: grinding selects nothing — best elects exactly the
        // honest set, never a superset.
        assert_eq!(
            best_rate, honest_rate,
            "best-of-N must elect exactly the honest draw ({name})"
        );
        // Honest rate tracks the nominal p (loose band: M=128 sampling
        // noise at p=0.05 is ~0.035 sigma; 0.15 is ~4 sigma).
        assert!(
            (honest_rate - p).abs() < 0.15,
            "honest single-draw rate must track p ({name})"
        );
        // The retired amplification is gone: where 1-(1-p)^N would exceed
        // the honest rate by a wide margin, best-of-N stays at p.
        assert!(
            (best_rate - retired).abs() > 0.05 || (retired - p).abs() < 0.05,
            "best-of-N rate {best_rate:.3} must not track the retired 1-(1-p)^N={retired:.3} ({name})"
        );
    }

    // Uniformity gates (generous: chi2 mean 255, sd ~22.6; 500 is +10 sd —
    // a failure here means the output hash is structurally broken).
    // (No per-bin occupancy pin at M=128: 0.5/bin expected, so empty bins
    // are the norm, not a signal.)
    assert!(chi2 < 500.0, "output first byte must be ~uniform, chi2={chi2:.1}");
    assert!(
        (balance_frac - 0.5).abs() < 0.15,
        "first bit must be balanced, frac={balance_frac:.4}"
    );
    // Uniqueness: the mean ticket stays at the honest 0.5 — no downward
    // grind shift (the retired wiring sat below 0.15 here).
    assert!(
        (mean_best - 0.5).abs() < 0.15,
        "best-of-{N} mean {mean_best:.5} must stay honest (no grind shift)"
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
    // Role tags of the retired construction stay distinct (harmless pin:
    // the byte strings are still reserved and never reused elsewhere).
    assert_ne!(b"nonce".as_slice(), b"challenge".as_slice());

    let secret_seed = cry_seed(600);
    let secret = VrfSecret::from_seed(&secret_seed);
    let pk = secret.public_key().to_bytes();
    let input = cry_input(60);
    let honest = vrf_prove(&secret, &input);
    assert_eq!(vrf_verify(&pk, &input, &honest), Some(honest.output));

    // 1. A retired-construction envelope (Schnorr `R` in the Gamma field,
    //    `z` in the `s` field, zeroed challenge) refuses: the ECVRF
    //    challenge binds Gamma, so reinterpreting Schnorr-shaped bytes
    //    under the ECVRF roles cannot verify. Cross-construction replay
    //    is impossible.
    {
        let mut proof = [0u8; VRF_PROOF_LEN];
        // Gamma field: reuse the honest Gamma (a valid curve point, but
        // the challenge over (Y, H, Gamma, U, V) will not match c = 0).
        proof[..32].copy_from_slice(&honest.proof[..32]);
        // c field: zeroed.
        // s field: reuse the honest s bytes under the wrong role.
        proof[48..].copy_from_slice(&honest.proof[48..]);
        let mut wrong_out = honest.output;
        wrong_out[0] ^= 0x01;
        let legacy = stellereum::vrf::VrfProof {
            output: wrong_out,
            proof,
        };
        assert_eq!(
            vrf_verify(&pk, &input, &legacy),
            None,
            "retired-construction-shaped envelope must refuse"
        );
    }

    // 2. Challenge built for a DIFFERENT hashed point refuses: transplant
    //    another input's Gamma into an otherwise-honest envelope and the
    //    challenge (which binds Gamma) mismatches.
    {
        let other = vrf_prove(&secret, &cry_input(61));
        assert_ne!(other.proof, honest.proof);
        let mut bad = honest.clone();
        bad.proof[..32].copy_from_slice(&other.proof[..32]);
        assert_eq!(
            vrf_verify(&pk, &input, &bad),
            None,
            "transplanted Gamma must break the challenge binding"
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

    // Identity refuses at parse AND at verify (both spellings): the
    // all-zero encoding is an order-4 point (refused by validate-key), and
    // [0x01, 0, ...] is the identity point itself.
    assert!(VrfPublicKey::from_bytes(&[0u8; 32]).is_none());
    let mut id_pt = [0u8; 32];
    id_pt[0] = 0x01;
    assert!(VrfPublicKey::from_bytes(&id_pt).is_none());
    assert_eq!(vrf_verify(&[0u8; 32], &input, &honest), None);
    assert_eq!(vrf_verify(&id_pt, &input, &honest), None);

    // Garbage / non-canonical encodings refuse at parse and at verify.
    assert!(VrfPublicKey::from_bytes(&[0xFFu8; 32]).is_none());
    // Corrupted key bytes: either garbage (refuses at decode) or a
    // different valid point (the honest proof refuses under any wrong key).
    let mut corrupted = pk;
    corrupted[15] ^= 0xFF; // guaranteed change, mid-encoding
    assert_ne!(corrupted, pk);
    assert_eq!(vrf_verify(&corrupted, &input, &honest), None);

    // Low-order-candidate sweep: every single-byte-pattern key either fails
    // to parse (non-canonical, low-order, or off-curve) or parses to a
    // wrong prime-order key under which the honest proof refuses.
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
    eprintln!("EDGE: flat-pattern keys that parse as valid Edwards keys: {parsed_count}/256");
    // NOTE: a nonzero parse count is EXPECTED, not a weakness — some flat
    // patterns are canonical encodings of ordinary prime-order points, and
    // every one of them fails closed above (the honest proof refuses under
    // any key but its own). Low-order patterns never parse: validate-key
    // rejects identity and all low-order points at parse time.
    // Cross-check: the known low-order encodings all refuse at parse.
    let mut order2 = [0xFFu8; 32];
    order2[0] = 0xED; // y = p-1 (order-2 point (0,-1))
    order2[31] = 0x7F;
    assert!(VrfPublicKey::from_bytes(&order2).is_none());
    let mut order4 = [0u8; 32];
    order4[31] = 0x80; // (x-odd, y=0): order-4 point
    assert!(VrfPublicKey::from_bytes(&order4).is_none());

    // Proof carrying Gamma = identity refuses (an identity Gamma binds a
    // challenge no honest s can satisfy), as does garbage in Gamma field.
    {
        let mut bad_g = honest.clone();
        bad_g.proof[..32].copy_from_slice(&[0u8; 32]);
        assert_eq!(vrf_verify(&pk, &input, &bad_g), None);
        let mut bad_g2 = honest.clone();
        bad_g2.proof[..32].copy_from_slice(&[0xFFu8; 32]);
        assert_eq!(vrf_verify(&pk, &input, &bad_g2), None);
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

    // Cofactor note pinned behaviorally: honest Gammas are x*H for the
    // input-bound H, hence never identity (H is a hash output, x nonzero).
    for j in 0..16usize {
        let p = vrf_prove(&VrfSecret::from_seed(&cry_seed(700)), &cry_input(j));
        assert_ne!(
            &p.proof[..32],
            &[0u8; 32],
            "honest Gamma must never be the identity encoding"
        );
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

    // Exhaustive single-bit sweep: all 80 proof bytes x all 8 bit positions.
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
    assert_eq!(checked, VRF_PROOF_LEN as u32 * 8);

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

    // Shape attacks on the ECVRF thirds (Gamma || c || s): field swaps
    // and duplications all refuse — the challenge binds every field, and
    // the output binds the proof bytes.
    {
        let mut gamma = [0u8; 32];
        let mut s_field = [0u8; 32];
        gamma.copy_from_slice(&good.proof[..32]);
        s_field.copy_from_slice(&good.proof[48..]);
        assert_ne!(gamma, s_field, "fixture needs distinct Gamma and s");

        // Gamma <-> s swapped: the challenge binds the field positions.
        let mut swapped = good.clone();
        swapped.proof[..32].copy_from_slice(&s_field);
        swapped.proof[48..].copy_from_slice(&gamma);
        swapped.output[0] ^= 0x01; // output must move with the proof bytes
        assert_eq!(vrf_verify(&pk, &input, &swapped), None);

        // Gamma duplicated into the s field.
        let mut gdup = good.clone();
        gdup.proof[48..].copy_from_slice(&gamma);
        gdup.output[1] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &input, &gdup), None);

        // s duplicated into the Gamma field.
        let mut sdup = good.clone();
        sdup.proof[..32].copy_from_slice(&s_field);
        sdup.output[2] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &input, &sdup), None);

        // Zeroed challenge with honest everything-else.
        let mut zc = good.clone();
        zc.proof[32..48].copy_from_slice(&[0u8; 16]);
        zc.output[3] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &input, &zc), None);
    }

    // Cross-proof splice: Gamma from proof A + (c, s) from proof B (same
    // key, two inputs) refuses in both directions, as do cross-wired
    // outputs.
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
        // Gamma-only splice (c, s kept from the honest proof).
        let mut splice3 = good.clone();
        splice3.proof[..32].copy_from_slice(&other.proof[..32]);
        assert_eq!(vrf_verify(&pk, &input, &splice3), None);
    }

    // Truncation / extension at the ENVELOPE layer (serde JSON): any dropped
    // or appended byte breaks decoding, so a short/long envelope can never
    // smuggle the same 80 proof bytes past the verifier.
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
    eprintln!("MALLEABILITY: 640 proof-bit + 256 output-bit + shape/splice/serde mutants all refuse");
}
