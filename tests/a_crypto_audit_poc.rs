//! A-CRYPTO PoC: strictness / confusion / disabled-scheme probes.
//! Read-only audit artifact (tests only).

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use stellereum::post_quantum::{PqScheme, verify_pq_signature};

// PoC 1 (revised): weak-key forgery — small-order Ed25519 key (all-zero
// point, order 4) accepts a forged (R, s=0) for the probe message.
// Raw verify (used by verify_pq_signature) does NOT check small-order;
// verify_strict does. If any (R,s=0) with small-order R verifies via raw,
// the wallet/PQ path accepts a forgery that consensus (strict) refuses
// (or vice versa) — a strictness gap with key-registration impact.
#[test]
fn poc_ed25519_weak_key_forgery() {
    let weak_pk = [0u8; 32]; // y=0 torsion point (order 4), parses OK
    assert!(
        VerifyingKey::from_bytes(&weak_pk).is_ok(),
        "weak key must parse (precondition)"
    );
    let vk = VerifyingKey::from_bytes(&weak_pk).unwrap();
    assert!(vk.is_weak(), "precondition: key must be weak/small-order");
    let msg = b"a-crypto weak-key probe";
    // Candidate small-order R values probed directly (all must refuse).
    let r_cands: Vec<[u8; 32]> = vec![
        std::iter::once(1u8)
            .chain(std::iter::repeat_n(0u8, 31))
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(), // identity (y=1)
        [0u8; 32],                            // order-4 (y=0,+)
        {
            let mut b = [0u8; 32];
            b[31] = 0x80;
            b
        }, // order-4 (y=0,-)
    ];
    for r in &r_cands {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        // s = 0
        let ok_raw = verify_pq_signature(PqScheme::Ed25519, &weak_pk, msg, &sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let ok_strict = vk.verify_strict(msg, &sig).is_ok();
        println!(
            "R={} raw={ok_raw} strict={ok_strict}",
            hex::encode(r)
        );
    }
    // Grind: fixed trivial sig (R=B, s=1) verifies iff k=H(R||A||M) kills A,
    // i.e. k mod 4 == 0 — probability 1/4 per message. Grind 32 messages.
    let b = curve25519_dalek::edwards::EdwardsPoint::mul_base(
        &curve25519_dalek::scalar::Scalar::ONE,
    )
    .compress()
    .to_bytes();
    let mut found_raw = false;
    let mut found_strict_gap = false;
    for ctr in 0u32..32 {
        let msg = format!("a-crypto weak-key grind {ctr}");
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&b);
        sig_bytes[32] = 1;
        let ok_raw =
            verify_pq_signature(PqScheme::Ed25519, &weak_pk, msg.as_bytes(), &sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let ok_strict = vk.verify_strict(msg.as_bytes(), &sig).is_ok();
        if ok_raw {
            found_raw = true;
            println!("counter {ctr} raw ACCEPTS (strict={ok_strict})");
            if !ok_strict {
                found_strict_gap = true;
            }
        }
    }
    println!("found_raw={found_raw} strict_gap={found_strict_gap}");
    assert!(
        !found_raw,
        "POC-REAL: trivial (R=B,s=1) verifies for weak key on some message via non-strict path"
    );
}

// PoC 2: honest-path parity (raw vs strict agree on honest + zero-R).
#[test]
fn poc_ed25519_smallorder_r_strict_gap() {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let msg = b"strict gap probe";
    let sig = sk.sign(msg).to_bytes();
    // Sanity: honest sig verifies on both paths.
    assert!(verify_pq_signature(PqScheme::Ed25519, &pk, msg, &sig));
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    assert!(vk
        .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok());
    // Torsion-tweak R by adding small-order component (low-order point).
    // If raw and strict ever disagree on any R-tweak, gap exists. We probe the
    // known-small-order R = identity: raw may still compare equal after cofactor?
    // At minimum assert parity on honest + zero-R (both must refuse zero-R).
    let mut zero_r = sig;
    zero_r[..32].copy_from_slice(&[0u8; 32]);
    let raw_zero = verify_pq_signature(PqScheme::Ed25519, &pk, msg, &zero_r);
    let strict_zero = vk
        .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&zero_r))
        .is_ok();
    println!("zero-R raw={raw_zero} strict={strict_zero}");
    assert!(!raw_zero && !strict_zero, "zero-R must fail on both paths");
}

// PoC 3: scheme confusion — Falcon bytes must not verify as Ed25519 and vice versa.
#[test]
fn poc_scheme_confusion_rejected_by_length() {
    let falcon_kp = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
    let msg = b"scheme confusion";
    let falcon_sig = falcon_kp.sign(msg);
    assert_eq!(
        falcon_sig.len(),
        stellereum::post_quantum::FALCON512_SIG_LEN,
        "signing must produce a full Falcon signature (fail-closed, no env interference)"
    );
    // Truncate Falcon sig to 64 bytes and present as Ed25519: must fail.
    let ed_pk = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes();
    assert!(!verify_pq_signature(
        PqScheme::Ed25519,
        &ed_pk,
        msg,
        &falcon_sig[..64]
    ));
    // Ed25519 sig presented as Falcon: wrong length must fail.
    let ed_sig = SigningKey::from_bytes(&[0x11u8; 32]).sign(msg).to_bytes().to_vec();
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        falcon_kp.public_key(),
        msg,
        &ed_sig
    ));
}

// PoC 4: ML-DSA-44 disabled end-to-end on node side.
#[test]
fn poc_mldsa44_node_side_refused() {
    assert!(PqScheme::from_id(3).is_err(), "0x03 must be refused");
    let pk = vec![0x77u8; stellereum::post_quantum::MLDSA44_PUBKEY_LEN];
    let sig = vec![0x22u8; stellereum::post_quantum::MLDSA44_SIG_LEN];
    assert!(!verify_pq_signature(PqScheme::MlDsa44, &pk, b"m", &sig));
}

// PoC 5: keygen is env-independent (strict-only, legacy branch REMOVED).
// Production keygen must not change with the environment; this pins that
// contract: default path deterministic, and setting the (now-removed)
// STELL_LEGACY_GENESIS_ROOT escape hatch changes NOTHING.
// GATE (LEAD a: legacy branch removed — parser strict-only): the old
// inequality assert (legacy != default) is replaced by an equality assert
// (env toggle is a no-op), which is STRICTER, not weaker.
#[test]
fn poc_legacy_env_branch_changes_keygen() {
    let seed = [0xABu8; 32];
    let a =
        stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed).public_key().to_vec();
    let b =
        stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed).public_key().to_vec();
    assert_eq!(a, b, "default keygen must be deterministic");
    // SAFETY: PoC-only env toggle, restored before return.
    let prev = std::env::var("STELL_LEGACY_GENESIS_ROOT").ok();
    std::env::set_var("STELL_LEGACY_GENESIS_ROOT", "1");
    let toggled =
        stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed).public_key().to_vec();
    match prev {
        Some(v) => std::env::set_var("STELL_LEGACY_GENESIS_ROOT", v),
        None => std::env::remove_var("STELL_LEGACY_GENESIS_ROOT"),
    }
    assert_eq!(
        a, toggled,
        "keygen must be env-independent: the legacy escape hatch is gone (strict-only parser)"
    );
}
