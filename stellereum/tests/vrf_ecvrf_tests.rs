//! ECVRF-EDWARDS25519-SHA512-Elligator2 conformance + uniqueness battery.
//!
//! What this file pins (all deterministic fixtures — no OS randomness):
//! * RFC 9381 Appendix B.4 test vectors (Examples 19–21): secret key ->
//!   public key, `vrf_prove` bytes (`pi` = `Gamma || c || s`), and the VRF
//!   output (leading half of the 64-byte `beta`) reproduce the RFC exactly;
//! * determinism: same (secret, input) re-proves byte-identically (uniqueness
//!   prerequisite: exactly one envelope per key+input);
//! * uniqueness / no-lift: try-and-select over N=32 secrets yields NO
//!   election lift — for a fixed registered key exactly one proof verifies
//!   per input, so best-of-N collapses to the honest draw (statistical bound:
//!   committee rate tracks the honest `p`, mean ticket stays ~0.5);
//! * fail-closed edges: wrong input/key, flipped bytes, low-order keys.

use stellereum::vrf::{
    lottery_threshold, vrf_verify, VrfPublicKey, VrfSecret, VRF_PROOF_LEN,
};

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.replace(char::is_whitespace, "")).expect("valid test hex")
}

fn h32(hex_str: &str) -> [u8; 32] {
    h(hex_str).try_into().expect("32-byte test vector")
}

// --- RFC 9381 Appendix B.4 vectors -------------------------------------------

struct RfcVector {
    sk: &'static str,
    pk: &'static str,
    alpha: &'static str,
    pi: &'static str,
    beta: &'static str,
}

// Examples 19, 20, 21 (SK/PK/alpha/pi/beta from RFC 9381 §B.4).
const VECTORS: [RfcVector; 3] = [
    RfcVector {
        sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        alpha: "",
        pi: "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
        beta: "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
    },
    RfcVector {
        sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        alpha: "72",
        pi: "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
        beta: "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
    },
    RfcVector {
        sk: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        alpha: "af82",
        pi: "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
        beta: "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
    },
];

#[test]
fn rfc9381_appendix_b4_keygen_matches() {
    for (i, v) in VECTORS.iter().enumerate() {
        let sk = VrfSecret::from_seed(&h32(v.sk));
        assert_eq!(
            sk.public_key().to_bytes(),
            h32(v.pk),
            "vector {i}: RFC 8032 key expansion must reproduce the RFC public key"
        );
    }
}

#[test]
fn rfc9381_appendix_b4_prove_matches() {
    assert_eq!(VRF_PROOF_LEN, 80, "ECVRF pi is Gamma(32) || c(16) || s(32)");
    for (i, v) in VECTORS.iter().enumerate() {
        let sk = VrfSecret::from_seed(&h32(v.sk));
        let alpha = h(v.alpha);
        let proof = stellereum::vrf::vrf_prove(&sk, &alpha);
        let pi = h(v.pi);
        assert_eq!(
            proof.proof.as_slice(),
            pi.as_slice(),
            "vector {i}: proof bytes must match the RFC pi"
        );
        let beta = h(v.beta);
        assert_eq!(
            proof.output.as_slice(),
            &beta[..32],
            "vector {i}: output must be the leading half of the RFC beta"
        );
        // And the RFC proof verifies under the RFC key.
        assert_eq!(
            vrf_verify(&h32(v.pk), &alpha, &proof),
            Some(proof.output),
            "vector {i}: RFC proof must verify"
        );
    }
}

// --- determinism (uniqueness prerequisite) ------------------------------------

#[test]
fn ecvrf_determinism_same_secret_and_input_same_bytes() {
    for (i, v) in VECTORS.iter().enumerate() {
        let sk = VrfSecret::from_seed(&h32(v.sk));
        let alpha = h(v.alpha);
        let a = stellereum::vrf::vrf_prove(&sk, &alpha);
        let b = stellereum::vrf::vrf_prove(&sk, &alpha);
        assert_eq!(a, b, "vector {i}: re-prove must be byte-identical");
    }
    // Fresh fixtures beyond the RFC set, incl. empty and long inputs.
    for i in 0..8usize {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
        seed[31] = i as u8;
        let sk = VrfSecret::from_seed(&seed);
        for alpha in [&[][..], &[0x72u8][..], &[0xabu8; 32][..], &[0x11u8; 97][..]] {
            let a = stellereum::vrf::vrf_prove(&sk, alpha);
            let b = stellereum::vrf::vrf_prove(&sk, alpha);
            assert_eq!(a, b, "determinism (seed {i}, alpha len {})", alpha.len());
            assert_eq!(
                vrf_verify(&sk.public_key().to_bytes(), alpha, &a),
                Some(a.output),
                "honest proof verifies (seed {i})"
            );
        }
    }
}

// --- uniqueness: try-and-select over N secrets gives NO lift -----------------

fn grind_seed(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(i as u64).wrapping_mul(0xD134_2547_6A35_1F09).to_le_bytes());
    s[8] = 0x6D;
    s[31] = (i as u8).wrapping_add(0x2A);
    s
}

fn grind_input(j: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&(j as u64).wrapping_add(0x51AB).to_le_bytes());
    s[8] = 0xC4;
    s[31] = 0x7E;
    s
}

fn ticket_u128(output: &[u8; 32]) -> u128 {
    u128::from_le_bytes(output[..16].try_into().expect("16 ticket bytes"))
}

#[test]
fn ecvrf_uniqueness_try_and_select_over_secrets_gives_no_lift() {
    const N: usize = 32; // grinder secrets tried per input
    const M: usize = 128; // distinct inputs
    let registered = VrfSecret::from_seed(&grind_seed(0));
    let registered_pk = registered.public_key().to_bytes();
    let secrets: Vec<VrfSecret> = (0..N).map(|i| VrfSecret::from_seed(&grind_seed(i))).collect();

    let mut honest_tickets = Vec::with_capacity(M);
    let mut best_tickets = Vec::with_capacity(M);
    let mut first_bytes: Vec<u8> = Vec::with_capacity(M);
    for j in 0..M {
        let input = grind_input(j);
        // Every secret mints for itself...
        let mut verifying = 0usize;
        let mut best = u128::MAX;
        for (i, sk) in secrets.iter().enumerate() {
            let p = stellereum::vrf::vrf_prove(sk, &input);
            if vrf_verify(&registered_pk, &input, &p) == Some(p.output) {
                verifying += 1;
                best = best.min(ticket_u128(&p.output));
                // ...and the only proof that verifies under the registered
                // key is the registered key's own (uniqueness).
                assert_eq!(i, 0, "only the registered secret verifies under pk0");
            }
        }
        assert_eq!(verifying, 1, "exactly one verifiable output per (pk, input)");
        let honest = stellereum::vrf::vrf_prove(&registered, &input);
        assert_eq!(
            vrf_verify(&registered_pk, &input, &honest),
            Some(honest.output)
        );
        honest_tickets.push(ticket_u128(&honest.output));
        best_tickets.push(best);
        first_bytes.push(honest.output[0]);
    }
    // Best-of-N IS the honest draw: no lift whatsoever.
    assert_eq!(best_tickets, honest_tickets, "grinding must not move any ticket");

    // Statistical bound: the (single) ticket per input is uniform, so the
    // committee rate tracks the honest p instead of 1-(1-p)^N.
    let (stake, total, seats, p) = (1u64, 4u64, 1u64, 0.25f64);
    let thr = lottery_threshold(stake, total, seats);
    let honest_rate = honest_tickets.iter().filter(|t| **t < thr).count() as f64 / M as f64;
    eprintln!("ECVRF: honest/best-of-{N} rate={honest_rate:.4} nominal p={p:.2}");
    assert!(
        (honest_rate - p).abs() < 0.12,
        "single-draw rate {honest_rate:.3} must track p={p}"
    );
    // Uniformity of the honest outputs (chi-square, 255 df; mean 255).
    let mut bins = [0u32; 256];
    for b in &first_bytes {
        bins[*b as usize] += 1;
    }
    let expected = M as f64 / 256.0;
    let chi2: f64 = bins
        .iter()
        .map(|b| {
            let d = *b as f64 - expected;
            d * d / expected
        })
        .sum();
    eprintln!("ECVRF: first-byte chi2={chi2:.1} (df=255, uniform mean 255)");
    assert!(chi2 < 500.0, "outputs must look uniform, chi2={chi2:.1}");
    // Mean ticket must stay at the honest 0.5 (best-of-32 uniform order stat
    // would sit at 1/33 ≈ 0.03 — the retired construction's signature).
    let mean = best_tickets.iter().map(|t| *t as f64 / u128::MAX as f64).sum::<f64>() / M as f64;
    eprintln!("ECVRF: mean best-of-{N} ticket frac={mean:.5} (honest 0.5)");
    assert!(
        (mean - 0.5).abs() < 0.15,
        "mean ticket {mean:.5} must stay honest (no downward grind shift)"
    );
}

// --- fail-closed edges ---------------------------------------------------------

#[test]
fn ecvrf_verify_refuses_wrong_input_key_and_flips() {
    let sk = VrfSecret::from_seed(&grind_seed(7));
    let pk = sk.public_key().to_bytes();
    let input = grind_input(3);
    let good = stellereum::vrf::vrf_prove(&sk, &input);
    assert_eq!(vrf_verify(&pk, &input, &good), Some(good.output));

    // Full single-bit sweep over the 80 proof bytes + 32 output bytes.
    for pos in 0..VRF_PROOF_LEN {
        let mut bad = good.clone();
        bad.proof[pos] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &input, &bad), None, "proof byte {pos} flip refuses");
    }
    for pos in 0..32usize {
        let mut bad = good.clone();
        bad.output[pos] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &input, &bad), None, "output byte {pos} flip refuses");
    }
    // Wrong input / wrong key.
    assert_eq!(vrf_verify(&pk, &grind_input(4), &good), None);
    let other_pk = VrfSecret::from_seed(&grind_seed(8)).public_key().to_bytes();
    assert_eq!(vrf_verify(&other_pk, &input, &good), None);
    // Empty-alpha proof does not verify under a non-empty alpha and back.
    let empty_proof = stellereum::vrf::vrf_prove(&sk, &[]);
    assert_eq!(vrf_verify(&pk, &[], &empty_proof), Some(empty_proof.output));
    assert_eq!(vrf_verify(&pk, &input, &empty_proof), None);
    assert_eq!(vrf_verify(&pk, &[], &good), None);
}

#[test]
fn ecvrf_low_order_and_identity_keys_refuse_everywhere() {
    let sk = VrfSecret::from_seed(&grind_seed(9));
    let input = grind_input(9);
    let good = stellereum::vrf::vrf_prove(&sk, &input);
    // Identity (0,1).
    let mut identity = [0u8; 32];
    identity[0] = 0x01;
    assert!(VrfPublicKey::from_bytes(&identity).is_none());
    assert_eq!(vrf_verify(&identity, &input, &good), None);
    // All-zero encoding (order-4 point) and high-bit-set garbage.
    assert!(VrfPublicKey::from_bytes(&[0u8; 32]).is_none());
    assert_eq!(vrf_verify(&[0u8; 32], &input, &good), None);
    assert!(VrfPublicKey::from_bytes(&[0xFFu8; 32]).is_none());
    // Order-2 point (0,-1): y = p-1 = 0x7FFF...FFED.
    let mut order2 = [0xFFu8; 32];
    order2[0] = 0xED;
    order2[31] = 0x7F;
    assert!(VrfPublicKey::from_bytes(&order2).is_none());
    assert_eq!(vrf_verify(&order2, &input, &good), None);
    // Edge seeds still derive usable prime-order keys.
    for edge in [[0u8; 32], [0xFFu8; 32]] {
        let esk = VrfSecret::from_seed(&edge);
        let epk = esk.public_key().to_bytes();
        assert!(VrfPublicKey::from_bytes(&epk).is_some());
        let p = stellereum::vrf::vrf_prove(&esk, &input);
        assert_eq!(vrf_verify(&epk, &input, &p), Some(p.output));
    }
    // Honest key parses.
    assert!(VrfPublicKey::from_bytes(&sk.public_key().to_bytes()).is_some());
}
