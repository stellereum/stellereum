//! Phase-3 VRF threading — assembly↔verify agreement, byte-identity, fallback,
//! determinism.
//!
//! Gate: `stellereum::vrf::VrfActivation` (default `Disabled` — pre-activation
//! output byte-identical) threaded with the proposer's self-verified
//! [`VrfBeaconSeal`] through `VoteSet::certificate_with_parent_vrf`
//! (assembly) and `QuorumCertificate::{verify_micro_cert_with_vrf,
//! micro_cert_valid_signers_with_vrf}` (verify).
//!
//! What this pins:
//! * assembly↔verify agreement post-activation: the proposer builds with a
//!   self-verified seal and the verifier re-derives the SAME committee;
//! * pre-activation byte-identity: built certs (struct AND canonical envelope
//!   bytes, including a pinned deterministic-prefix vector) equal the legacy
//!   path;
//! * fallback matrix: None / missing / forged × assembly / verify;
//! * determinism: same key + height + round ⇒ same seal, same committee;
//! * uniqueness: the ECVRF construction admits exactly ONE valid proof per
//!   input — the verifier accepts any proof that verifies (there is only
//!   one), and the election is a pure function of that output. A second,
//!   holder-crafted envelope for the same input refuses, so no alternate
//!   committee can be smuggled through a valid-looking seal.
//!
//! No quorum, timeout, or vote changes: election seeds and the trailing
//! serde-defaulted cert field only.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, decode_pq_micro_envelope, derive_sortition_committee,
    derive_sortition_committee_gated, encode_pq_micro_envelope, micro_committee_size,
    register_validator_pq_key, sortition_seed, sortition_seed_gated, vote_sign_bytes,
    PqMicroCertificate, QuorumCertificate, ValidatorSet, Vote, VoteKind, VrfBeaconSeal,
    QC_UQC_MAGIC,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_binding_preimage, vrf_election_seed, vrf_prove,
    vrf_verify, VrfActivation, VrfBinding, VrfRegistry, VrfSecret, VRF_PROOF_LEN,
};

const ACTIVATION_H: u64 = 1_000_000;
const ROUND: u32 = 0;
const KIND: VoteKind = VoteKind::Precommit;

// --- fixtures ----------------------------------------------------------------

struct Net {
    vs: ValidatorSet,
    ids: Vec<[u8; 32]>,
    ed: Vec<SigningKey>,
    falcon: Vec<FalconKeypair>,
    vrf: Vec<VrfSecret>,
    reg: VrfRegistry,
    parent: [u8; 32],
    block_hash: Option<[u8; 32]>,
}

fn ed_seed(tag: u8, i: usize) -> [u8; 32] {
    let mut s = [tag; 32];
    s[0] = i as u8;
    s[31] ^= i as u8;
    s
}

/// Deterministic N-validator network: Ed25519 vote keys, Falcon vote keys
/// (registered globally), and Falcon-bound registered VRF keys. No OS
/// randomness, no wall clock — except `FalconKeypair::sign`, which randomizes
/// SIGNATURE bytes (never compared across runs here, only verified).
fn setup_net(n: usize, tag: u8, power: u64) -> Net {
    clear_validator_pq_keys_for_tests();
    let mut vs = ValidatorSet::new();
    let mut ids = Vec::new();
    let mut ed = Vec::new();
    let mut falcon = Vec::new();
    let mut vrf = Vec::new();
    let mut reg = VrfRegistry::new();
    for i in 0..n {
        let sk = SigningKey::from_bytes(&ed_seed(tag, i));
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed_bytes(&ed_seed(tag.wrapping_add(0x50), i));
        vs.add(id, power);
        register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key().to_vec());
        let sk_vrf = VrfSecret::from_seed(&ed_seed(tag.wrapping_add(0xA0), i));
        let vrf_pk = sk_vrf.public_key().to_bytes();
        let sig = fk.sign(&vrf_binding_preimage(&id, &vrf_pk));
        reg.register(
            &VrfBinding {
                validator_id: id,
                vrf_pk,
                falcon_sig: sig,
            },
            fk.public_key(),
        )
        .expect("honest binding registers");
        ids.push(id);
        ed.push(sk);
        falcon.push(fk);
        vrf.push(sk_vrf);
    }
    Net {
        vs,
        ids,
        ed,
        falcon,
        vrf,
        reg,
        parent: [0x5Au8; 32],
        block_hash: Some([0xABu8; 32]),
    }
}

fn seal_for(net: &Net, i: usize, height: u64, round: u32) -> VrfBeaconSeal {
    let seed_input = sortition_seed(&net.parent, height, round);
    let proof = vrf_prove(&net.vrf[i], &seed_input);
    assert_eq!(
        verify_vrf_seed_for_validator(&net.reg, &net.ids[i], &seed_input, &proof),
        Some(proof.output),
        "fixture seal must self-verify"
    );
    VrfBeaconSeal::new(net.ids[i], proof)
}

fn vote_set_for(net: &Net, height: u64, round: u32) -> stellereum::consensus::VoteSet {
    let mut set = stellereum::consensus::VoteSet::new();
    for i in 0..net.ids.len() {
        let v = Vote::sign_with_falcon(
            &net.ed[i],
            &net.falcon[i],
            height,
            round,
            KIND,
            net.block_hash,
        );
        set.add(v, &net.vs, height, round, KIND)
            .expect("honest vote admits");
    }
    set
}

fn msg_for(height: u64, round: u32, block_hash: &Option<[u8; 32]>) -> Vec<u8> {
    vote_sign_bytes(height, round, KIND, block_hash)
}

// --- 1. assembly↔verify agreement post-activation ------------------------------

#[test]
fn assembly_verify_agreement_post_activation() {
    let net = setup_net(4, 0x11, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    assert!(active.is_active_at(ACTIVATION_H));

    let seal = seal_for(&net, 0, ACTIVATION_H, ROUND);
    let output = seal.proof.output;
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal.clone()),
        )
        .expect("quorum present: certificate must form");

    // The seal travels with the certificate (bincode envelope) and survives
    // the decode round-trip byte-identically.
    let cert = qc.pq_micro_certificate().expect("µQC must be attached");
    assert_eq!(cert.vrf_beacon, Some(seal.clone()));
    assert_eq!(cert.sortition_parent, net.parent);

    // The verifier re-derives the SAME committee the proposer used.
    let expected =
        derive_sortition_committee_gated(&net.vs, ACTIVATION_H, ROUND, 4, &net.parent, &active, Some(&output));
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "sealed certificate must verify against the registry"
    );
    assert_eq!(
        qc.micro_cert_valid_signers_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        Some(expected.clone()),
        "verifier must land on the proposer's committee"
    );

    // The VRF path is genuinely engaged: the election seed left the
    // parent-hash seed (N=4 elects the full set either way, so the committee
    // coincides here — the seed proves the entropy switched).
    assert_eq!(
        sortition_seed_gated(&net.parent, ACTIVATION_H, ROUND, &active, Some(&output)),
        vrf_election_seed(&output, ACTIVATION_H, ROUND)
    );
    assert_ne!(
        sortition_seed_gated(&net.parent, ACTIVATION_H, ROUND, &active, Some(&output)),
        sortition_seed(&net.parent, ACTIVATION_H, ROUND),
        "post-activation must leave the parent-hash seed"
    );

    // Mixed-version compat at small N: the sealed cert ALSO verifies under
    // the legacy draw (same full-set committee), so old nodes accept it.
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &VrfActivation::Disabled, None),
        "sealed cert on a full-set committee must verify as legacy too"
    );
}

// --- 2. pre-activation byte-identity --------------------------------------------

#[test]
fn pre_activation_cert_byte_identical_to_legacy() {
    let net = setup_net(4, 0x22, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let h = 9u64;
    assert!(!active.is_active_at(h));

    let set = vote_set_for(&net, h, ROUND);
    let legacy_qc = set
        .certificate(net.block_hash, &net.vs, &net.parent)
        .expect("legacy certificate must form");

    // Same VoteSet, VRF-threaded entry with an armed activation AND a valid
    // seal: pre-activation the seal is ignored (height gate decides).
    let seal = seal_for(&net, 0, h, ROUND);
    let threaded_qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal),
        )
        .expect("threaded certificate must form");
    // And the fully-unthreaded call.
    let disabled_qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &VrfActivation::Disabled,
            None,
            None,
        )
        .expect("disabled certificate must form");

    for qc in [&threaded_qc, &disabled_qc] {
        assert_eq!(*qc, legacy_qc, "pre-activation must be struct-identical");
    }
    let legacy_cert = legacy_qc.pq_micro_certificate().expect("µQC attached");
    assert_eq!(legacy_cert.vrf_beacon, None);
    let threaded_cert = threaded_qc.pq_micro_certificate().expect("µQC attached");
    assert_eq!(threaded_cert, legacy_cert);
    assert_eq!(
        encode_pq_micro_envelope(&threaded_cert),
        encode_pq_micro_envelope(&legacy_cert),
        "canonical envelope bytes must be identical"
    );

    // Pinned deterministic-prefix vector: MAGIC(16) || parent(32) ||
    // scheme(1) || height(8) || round(4) || ksize(4) || bitmask_len(4) ||
    // bitmask — every byte before the (randomized) Falcon signatures.
    // Fixture: 4 validators power 10, parent [0x5A;32], height 9, round 0,
    // Falcon512, full-set committee (bitmask 0x0F).
    let env = encode_pq_micro_envelope(&legacy_cert);
    let prefix_hex = hex::encode(&env[..16 + 32 + 1 + 8 + 4 + 4 + 4 + 1]);
    let mut expected = String::new();
    expected.push_str("5354454c4c5f5551435f50515f56355f"); // QC_UQC_MAGIC ("STELL_UQC_PQ_V5_")
    expected.push_str(&"5a".repeat(32)); // sortition_parent
    expected.push_str("02"); // scheme id (Falcon512)
    expected.push_str("0900000000000000"); // height 9 le
    expected.push_str("00000000"); // round 0 le
    expected.push_str("04000000"); // committee_size 4 le
    expected.push_str("01000000"); // bitmask_len 1 le
    expected.push_str("0f"); // full-set bitmask
    assert_eq!(prefix_hex, expected, "deterministic envelope prefix vector");
    assert!(env.starts_with(QC_UQC_MAGIC));
    // The canonical envelope decodes with no seal (legacy bytes).
    assert_eq!(
        decode_pq_micro_envelope(&env).expect("decodes").vrf_beacon,
        None
    );
}

// --- 3. fallback matrix ----------------------------------------------------------

/// Build one honest legacy-path QC at `height` (all validators vote).
fn legacy_qc_at(net: &Net, height: u64, round: u32) -> QuorumCertificate {
    vote_set_for(net, height, round)
        .certificate(net.block_hash, &net.vs, &net.parent)
        .expect("legacy certificate must form")
}

#[test]
fn fallback_matrix_none_missing_forged() {
    let net = setup_net(4, 0x33, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let h = ACTIVATION_H;
    let msg = msg_for(h, ROUND, &net.block_hash);
    let legacy_committee = derive_sortition_committee(&net.vs, h, ROUND, 4, &net.parent);

    // (a) No seal + armed + registry ⇒ legacy fallback, verifies.
    let set = vote_set_for(&net, h, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            None,
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, None, "None seal embeds nothing");
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "None seal verifies under legacy"
    );
    assert_eq!(
        qc.micro_cert_valid_signers_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        Some(legacy_committee.clone())
    );

    // (b) Valid seal + Disabled ⇒ seal ignored, legacy everywhere.
    let seal = seal_for(&net, 0, h, ROUND);
    let set = vote_set_for(&net, h, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &VrfActivation::Disabled,
            Some(&net.reg),
            Some(seal.clone()),
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, None, "Disabled activation drops the seal");
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &VrfActivation::Disabled, Some(&net.reg)),
        "Disabled activation verifies legacy even with a seal present"
    );

    // (c) Valid seal + armed + NO registry ⇒ legacy fallback, verifies.
    let set = vote_set_for(&net, h, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            None,
            Some(seal.clone()),
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, None, "no registry ⇒ nothing to check ⇒ legacy");
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, None),
        "missing registry verifies legacy"
    );

    // (d) Seal from an UNKNOWN validator + armed + registry ⇒ legacy
    // fallback (rollout gap: the key is missing, not forged), verifies.
    let foreign_secret = VrfSecret::from_seed(&[0xEEu8; 32]);
    let seed_input = sortition_seed(&net.parent, h, ROUND);
    let foreign_proof = vrf_prove(&foreign_secret, &seed_input);
    let unknown_seal = VrfBeaconSeal::new([0x99u8; 32], foreign_proof);
    let set = vote_set_for(&net, h, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(unknown_seal.clone()),
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, None, "unknown key never elects VRF");
    // A cert that (hypothetically) carried the unknown seal still verifies
    // legacy — the missing key is not evidence of forgery.
    let legacy = legacy_qc_at(&net, h, ROUND);
    let legacy_cert = legacy.pq_micro_certificate().expect("attached");
    let with_unknown = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(unknown_seal);
    assert!(
        legacy.verify_micro_cert_with_vrf(
            &with_unknown,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        "unknown-key seal falls back to legacy"
    );

    // (e) FORGED proof bytes + armed + known key ⇒ assembly falls back to
    // legacy, but verification REFUSES the forged cert fail-closed.
    let mut bad_proof = seal.proof.clone();
    bad_proof.proof[7] ^= 0x01;
    let forged_seal = VrfBeaconSeal::new(net.ids[0], bad_proof);
    let set = vote_set_for(&net, h, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(forged_seal.clone()),
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(
        cert.vrf_beacon, None,
        "assembly never embeds an unverified seal: legacy bytes"
    );
    let forged_cert = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(forged_seal);
    assert!(
        !legacy.verify_micro_cert_with_vrf(
            &forged_cert,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        "forged proof bytes must refuse the whole certificate"
    );
    assert_eq!(
        legacy.micro_cert_valid_signers_with_vrf(
            &forged_cert,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        None,
        "forged proof attributes nobody"
    );

    // (f) Proof verifies but `output` field substituted ⇒ refuse (the output
    // is bound to the proof bytes; a mismatch is a forgery, not a fallback).
    let mut bad_out = seal.proof.clone();
    bad_out.output[3] ^= 0x40;
    let swapped_seal = VrfBeaconSeal::new(net.ids[0], bad_out);
    let swapped_cert = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(swapped_seal);
    assert!(
        !legacy.verify_micro_cert_with_vrf(
            &swapped_cert,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        "substituted output must refuse the whole certificate"
    );

    // (g) Old-version cert (serde field absent) verifies under legacy.
    let json = serde_json::to_value(&legacy_cert).expect("serializes");
    let mut obj = json.as_object().expect("object").clone();
    assert!(
        obj.remove("vrf_beacon").is_some(),
        "legacy-shaped JSON must drop the seal field"
    );
    let old_cert: PqMicroCertificate =
        serde_json::from_value(serde_json::Value::Object(obj)).expect("decodes without the field");
    assert_eq!(old_cert.vrf_beacon, None, "#[serde(default)] reads None");
    assert_eq!(old_cert, legacy_cert, "old cert equals the new legacy cert");
    assert!(
        legacy.verify_micro_cert_with_vrf(&old_cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "old cert verifies under legacy even at an armed height"
    );
}

// --- 4. determinism ----------------------------------------------------------------

#[test]
fn determinism_same_key_and_height_same_outcome() {
    let net = setup_net(4, 0x44, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);

    let first_seal = seal_for(&net, 1, ACTIVATION_H, ROUND);
    let first_committee = derive_sortition_committee_gated(
        &net.vs,
        ACTIVATION_H,
        ROUND,
        4,
        &net.parent,
        &active,
        Some(&first_seal.proof.output),
    );
    for _ in 0..25 {
        // Proving is pure: identical bytes every run (no wall clock, no OS
        // randomness in the election path — Falcon SIGNATURE bytes are the
        // only randomized material and are never compared here).
        let seal = seal_for(&net, 1, ACTIVATION_H, ROUND);
        assert_eq!(seal, first_seal, "same key+height+round ⇒ same seal");
        assert_eq!(
            derive_sortition_committee_gated(
                &net.vs,
                ACTIVATION_H,
                ROUND,
                4,
                &net.parent,
                &active,
                Some(&seal.proof.output)
            ),
            first_committee
        );
        // Assembly is a pure function of (votes, activation, seal): same
        // VoteSet rebuilds the same certificate (Falcon signatures are minted
        // once per vote and stored in the set).
        let set = vote_set_for(&net, ACTIVATION_H, ROUND);
        let qc = set
            .certificate_with_parent_vrf(
                net.block_hash,
                &net.vs,
                Some(&net.parent),
                &active,
                Some(&net.reg),
                Some(seal.clone()),
            )
            .expect("forms");
        let cert = qc.pq_micro_certificate().expect("attached");
        assert_eq!(cert.vrf_beacon, Some(seal));
        assert!(
            qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg))
        );
    }
}

// --- 5. uniqueness: one input, one proof, one committee -------------------------

/// The ECVRF construction admits exactly one valid proof per input (RFC 9381
/// §3.1 full uniqueness; the retired Schnorr wiring admitted several). The
/// verifier accepts any proof that verifies — and there is only one — and
/// the election is a pure function of that output. A holder-crafted second
/// envelope for the same input refuses at every layer: raw verify, the
/// registry mint, and cert verification, so no alternate committee can be
/// smuggled through a valid-looking seal.
#[test]
fn verifier_accepts_unique_proof_second_envelope_refuses() {
    use stellereum::vrf::VrfProof;

    let net = setup_net(4, 0x55, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let seed_input = sortition_seed(&net.parent, ACTIVATION_H, ROUND);
    let first = vrf_prove(&net.vrf[0], &seed_input);
    let pk = net.vrf[0].public_key().to_bytes();
    assert_eq!(vrf_verify(&pk, &seed_input, &first), Some(first.output));

    // Craft an alternate envelope by reinterpreting the honest proof's
    // fields under swapped roles (Gamma <-> s, zeroed challenge): the
    // ECVRF challenge binds every field position, so no byte shuffle of a
    // valid proof can verify.
    let mut proof2 = [0u8; VRF_PROOF_LEN];
    proof2[..32].copy_from_slice(&first.proof[48..]);
    proof2[48..].copy_from_slice(&first.proof[..32]);
    let mut output2 = first.output;
    output2[0] ^= 0x01;
    let alt = VrfProof {
        output: output2,
        proof: proof2,
    };
    assert_eq!(
        vrf_verify(&pk, &seed_input, &alt),
        None,
        "second envelope for the same input must refuse (uniqueness)"
    );
    assert_ne!(
        alt.proof, first.proof,
        "the refused envelope must differ from the honest one"
    );

    // The registry mints ONLY the honest envelope.
    assert_eq!(
        verify_vrf_seed_for_validator(&net.reg, &net.ids[0], &seed_input, &first),
        Some(first.output)
    );
    assert_eq!(
        verify_vrf_seed_for_validator(&net.reg, &net.ids[0], &seed_input, &alt),
        None
    );

    // And the election is a pure function of the unique verified output:
    // the seal-carrying cert verifies for the honest proof and refuses for
    // the alternate.
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    let legacy = legacy_qc_at(&net, ACTIVATION_H, ROUND);
    let legacy_cert = legacy.pq_micro_certificate().expect("attached");
    let cert = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(VrfBeaconSeal::new(net.ids[0], first.clone()));
    assert!(
        legacy.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "the unique verifying proof elects its committee"
    );
    let committee = derive_sortition_committee_gated(
        &net.vs,
        ACTIVATION_H,
        ROUND,
        4,
        &net.parent,
        &active,
        Some(&first.output),
    );
    assert_eq!(
        legacy.micro_cert_valid_signers_with_vrf(
            &cert,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        Some(committee)
    );
    // The alternate seal refuses the whole certificate.
    let bad_cert = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(VrfBeaconSeal::new(net.ids[0], alt));
    assert!(
        !legacy.verify_micro_cert_with_vrf(&bad_cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "an alternate-unique envelope must refuse the whole certificate"
    );
}

// --- 6. committee divergence at scale + runtime seam -----------------------------------

/// With a non-trivial draw (N=65, k=64) the VRF committee diverges from the
/// legacy committee for this fixture (pinned), while full-set small networks
/// elect identically on both paths (see the N=4 tests above). This pins the
/// flag-day shape: post-activation sealed certs verify on new code and refuse
/// on the legacy draw when the draw actually differs.
#[test]
fn large_committee_diverges_post_activation() {
    let net = setup_net(65, 0x66, 10);
    assert_eq!(micro_committee_size(65), 64);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let seal = seal_for(&net, 0, ACTIVATION_H, ROUND);
    let output = seal.proof.output;

    let vrf_committee = derive_sortition_committee_gated(
        &net.vs,
        ACTIVATION_H,
        ROUND,
        64,
        &net.parent,
        &active,
        Some(&output),
    );
    let legacy_committee = derive_sortition_committee(&net.vs, ACTIVATION_H, ROUND, 64, &net.parent);
    assert_eq!(vrf_committee.len(), 64);
    assert_ne!(
        vrf_committee, legacy_committee,
        "this fixture must exercise a real draw divergence"
    );

    // Full assembly↔verify at scale: all 65 vote, the 64-member VRF committee
    // is covered, quorum power is met.
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal.clone()),
        )
        .expect("scaled certificate must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, Some(seal));
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "scaled sealed certificate must verify"
    );
    assert_eq!(
        qc.micro_cert_valid_signers_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        Some(vrf_committee)
    );
    // …while the legacy draw refuses it (the committees genuinely differ):
    // this is the post-activation flag-day shape for non-trivial draws.
    assert!(
        !qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &VrfActivation::Disabled, None),
        "legacy draw must refuse a diverged VRF committee"
    );
}

/// The runtime proof seam: `ValidatorRuntime::vrf_beacon_seal_for` mints the
/// seal where the secret lives and falls back to `None` (→ legacy) whenever
/// the gate, the seed, or self-verification says so. Startup defaults
/// (env-unset `Disabled`, no seed) assemble legacy bytes.
#[tokio::test]
async fn runtime_proof_seam_mints_and_falls_back() {
    let net = setup_net(4, 0x77, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let me = net.ids[0];
    let sk = SigningKey::from_bytes(&ed_seed(0x77, 0));
    assert_eq!(sk.verifying_key().to_bytes(), me);
    let state = Arc::new(InMemoryStateEngine::new());
    let base = ValidatorRuntime::new(sk, net.vs.clone(), state, 1);

    // Startup default: Disabled, no seed ⇒ None (legacy bytes, like the
    // env-unset binary).
    assert_eq!(base.vrf_activation(), VrfActivation::Disabled);
    assert_eq!(base.vrf_beacon_seal_for(ACTIVATION_H, ROUND, &net.parent), None);

    // Armed but seedless (e.g. a remote-signer deployment with no local VRF
    // seed provisioned) ⇒ None: legacy fallback, never a bypass.
    let armed_naked = ValidatorRuntime::new(
        SigningKey::from_bytes(&ed_seed(0x77, 0)),
        net.vs.clone(),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_vrf_activation(active);
    assert_eq!(armed_naked.vrf_beacon_seal_for(ACTIVATION_H, ROUND, &net.parent), None);

    // Armed + seeded ⇒ minted, self-verified, attributed to us.
    let armed = ValidatorRuntime::new(
        SigningKey::from_bytes(&ed_seed(0x77, 0)),
        net.vs.clone(),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_vrf_activation(active)
    .with_vrf_secret_seed(ed_seed(0x77u8.wrapping_add(0xA0), 0));
    let seal = armed
        .vrf_beacon_seal_for(ACTIVATION_H, ROUND, &net.parent)
        .expect("armed + seeded must mint");
    assert_eq!(seal.validator_id, me);
    let seed_input = sortition_seed(&net.parent, ACTIVATION_H, ROUND);
    assert_eq!(
        verify_vrf_seed_for_validator(&net.reg, &me, &seed_input, &seal.proof),
        Some(seal.proof.output),
        "runtime-minted seal must verify under the registry binding"
    );
    assert_eq!(seal, seal_for(&net, 0, ACTIVATION_H, ROUND));

    // Pre-activation height even when armed + seeded ⇒ None (height gate).
    assert_eq!(armed.vrf_beacon_seal_for(9, ROUND, &net.parent), None);
    // `FromHeight(0)` arms from genesis.
    let genesis = ValidatorRuntime::new(
        SigningKey::from_bytes(&ed_seed(0x77, 0)),
        net.vs.clone(),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_vrf_activation(VrfActivation::FromHeight(0))
    .with_vrf_secret_seed(ed_seed(0x77u8.wrapping_add(0xA0), 0));
    assert!(genesis.vrf_beacon_seal_for(0, ROUND, &net.parent).is_some());
}

// --- 7. activation-boundary exact (H-1 vs H) + old wire bytes ---------------
//
// Missing behavior-matrix cells: the height gate decides, not proof presence.
// At `H-1` a VALID seal + armed activation + live registry still assembles
// legacy (`None`, byte-identical) and a hand-sealed cert still verifies
// legacy (seal ignored). At `H` the same inputs embed and elect VRF. And old
// WIRE bytes (canonical envelope, no seal field on the wire) decode to `None`
// and verify legacy at an armed height with a live registry — the
// mixed-version new-node + old-cert cell over bytes, not JSON.
#[test]
fn activation_boundary_exact_h_minus_one_vs_h() {
    let net = setup_net(4, 0x99, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let h_before = ACTIVATION_H - 1;

    // Assembly at H-1 with a VALID seal for H-1: seal ignored, legacy bytes.
    // NOTE: one shared VoteSet — Falcon signatures randomize per signing, so
    // two separately-built sets differ in signature bytes, not in election.
    let seal_before = seal_for(&net, 0, h_before, ROUND);
    let set = vote_set_for(&net, h_before, ROUND);
    let threaded = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal_before),
        )
        .expect("must form");
    let legacy = set
        .certificate(net.block_hash, &net.vs, &net.parent)
        .expect("legacy certificate must form");
    assert_eq!(threaded, legacy, "H-1 assembly must be struct-identical");
    let threaded_cert = threaded.pq_micro_certificate().expect("attached");
    assert_eq!(threaded_cert.vrf_beacon, None);
    assert_eq!(
        encode_pq_micro_envelope(&threaded_cert),
        encode_pq_micro_envelope(&legacy.pq_micro_certificate().expect("attached")),
        "H-1 canonical bytes must be legacy bytes"
    );

    // Verify at H-1 IGNORES a hand-attached valid seal (legacy committee).
    let msg_before = msg_for(h_before, ROUND, &net.block_hash);
    let legacy_committee_before =
        derive_sortition_committee(&net.vs, h_before, ROUND, 4, &net.parent);
    let legacy_cert = legacy.pq_micro_certificate().expect("attached");
    let sealed_before = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(seal_for(&net, 0, h_before, ROUND));
    assert!(
        legacy.verify_micro_cert_with_vrf(
            &sealed_before,
            &net.vs,
            &msg_before,
            None,
            &active,
            Some(&net.reg)
        ),
        "H-1 verify must ignore the seal and accept legacy"
    );
    assert_eq!(
        legacy.micro_cert_valid_signers_with_vrf(
            &sealed_before,
            &net.vs,
            &msg_before,
            None,
            &active,
            Some(&net.reg)
        ),
        Some(legacy_committee_before)
    );

    // Assembly at H with the same shape EMBEDS the seal (control: gate flips).
    let seal_at = seal_for(&net, 0, ACTIVATION_H, ROUND);
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc_at = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal_at.clone()),
        )
        .expect("must form");
    assert_eq!(
        qc_at.pq_micro_certificate().expect("attached").vrf_beacon,
        Some(seal_at)
    );
}

#[test]
fn old_wire_bytes_verify_legacy_at_armed_height() {
    let net = setup_net(4, 0x9A, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    let legacy = legacy_qc_at(&net, ACTIVATION_H, ROUND);
    let legacy_cert = legacy.pq_micro_certificate().expect("attached");

    // Old WIRE bytes: the canonical envelope carries no seal field at all.
    let wire = encode_pq_micro_envelope(&legacy_cert);
    let decoded =
        decode_pq_micro_envelope(&wire).expect("old canonical wire must decode");
    assert_eq!(decoded.vrf_beacon, None);
    assert_eq!(decoded, legacy_cert);
    let legacy_committee =
        derive_sortition_committee(&net.vs, ACTIVATION_H, ROUND, 4, &net.parent);

    // New node at an ARMED height with a LIVE registry still verifies old
    // wire bytes under the legacy draw (mixed-version new-node + old-cert cell).
    assert!(
        legacy.verify_micro_cert_with_vrf(
            &decoded,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        "old wire bytes must verify legacy at an armed height"
    );
    assert_eq!(
        legacy.micro_cert_valid_signers_with_vrf(
            &decoded,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        Some(legacy_committee)
    );
}

// --- 8. live-site agreement (verify_unified/signers_set read env + registry) ---
//
// The two live sites (`pq_path_verify`, used by `verify_unified`, and the
// micro-cert branch of `signers_set`) resolve the election from the process
// environment (`STELL_VRF_ACTIVATION_HEIGHT`) plus the startup-loaded global
// registry (`set_live_vrf_registry`) — the same fallback matrix as
// `vrf_output_for_cert`. These cases pin the live path against the explicit
// (activation, registry) path: post-activation they agree on the VRF
// committee, pre-activation they are byte-identical legacy, and a forged seal
// from a known key refuses fail-closed.
//
// Process-global state (env var, PQ-key registry, live VRF registry) is
// shared by every test in this binary, so the live cases below serialize on
// `SERIAL_LIVE` and restore env on drop. Marker-only QCs (a single
// `PQ_UQC_MARKER_ID` envelope entry, no classical signatures) isolate the
// micro-cert path through the live sites: a full assembly QC would still pass
// `verify_unified` on its classical Ed25519 quorum even when the micro-cert
// branch refuses, which would mask a live-site regression here.

static SERIAL_LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvRestoreLive {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestoreLive {
    fn save(keys: &[&'static str]) -> Self {
        let saved = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        Self { saved }
    }
}

impl Drop for EnvRestoreLive {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// Marker-only QC: the micro-cert envelope alone, so `verify_unified` (via
/// `pq_path_verify`) and `signers_set` (via the micro-cert branch) decide on
/// the envelope path only.
///
/// The payload is attached with `attach_pq_micro_certificate` (the same
/// function assembly uses): unsealed certs encode to the canonical envelope,
/// sealed ones travel as `MAGIC || bincode(cert)`. Hand-rolling the payload
/// with `encode_pq_micro_envelope` would silently DROP the seal (the
/// canonical envelope has no seal field) and every sealed case would exercise
/// the legacy fallback instead of the VRF path.
fn marker_only_qc_live(cert: &PqMicroCertificate, block_hash: Option<[u8; 32]>) -> QuorumCertificate {
    let mut qc = QuorumCertificate {
        height: cert.height,
        round: cert.round,
        kind: KIND,
        block_hash,
        signatures: Vec::new(),
    };
    qc.attach_pq_micro_certificate(cert);
    qc
}

fn live_env_key() -> &'static str {
    stellereum::vrf::VRF_ACTIVATION_HEIGHT_ENV
}

#[test]
fn live_sites_agree_post_activation_small_and_scaled() {
    let _guard = SERIAL_LIVE.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestoreLive::save(&[live_env_key()]);
    stellereum::consensus::clear_live_vrf_registry_for_tests();

    // Small network: full-set committee on both draws.
    let net = setup_net(4, 0xA1, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let seal = seal_for(&net, 0, ACTIVATION_H, ROUND);
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal.clone()),
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, Some(seal.clone()));

    std::env::set_var(live_env_key(), ACTIVATION_H.to_string());
    assert_eq!(stellereum::vrf::vrf_activation_from_env(), active);
    stellereum::consensus::set_live_vrf_registry(net.reg.clone());

    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    let expected = derive_sortition_committee_gated(
        &net.vs,
        ACTIVATION_H,
        ROUND,
        4,
        &net.parent,
        &active,
        Some(&seal.proof.output),
    );
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "explicit path must verify the sealed certificate"
    );
    let marker = marker_only_qc_live(&cert, net.block_hash);
    assert!(
        marker.verify_unified(&net.vs),
        "live pq path must accept the sealed certificate post-activation"
    );
    let expected_set: std::collections::HashSet<[u8; 32]> =
        expected.iter().copied().collect();
    assert_eq!(
        marker.signers_set(&net.vs),
        expected_set,
        "live attribution must land on the proposer's VRF committee"
    );
    // Full assembly QC agrees through the live sites as well (classical +
    // envelope union covers the VRF committee here).
    assert!(qc.verify_unified(&net.vs));
    let live_full: std::collections::HashSet<[u8; 32]> =
        qc.signers_set(&net.vs).into_iter().collect();
    for id in &expected {
        assert!(live_full.contains(id), "full-QC live attribution must cover {id:?}");
    }

    stellereum::consensus::clear_live_vrf_registry_for_tests();

    // Scaled network: the VRF draw genuinely diverges from the legacy draw.
    let net = setup_net(65, 0xA2, 10);
    assert_eq!(micro_committee_size(65), 64);
    let seal = seal_for(&net, 0, ACTIVATION_H, ROUND);
    let vrf_committee = derive_sortition_committee_gated(
        &net.vs,
        ACTIVATION_H,
        ROUND,
        64,
        &net.parent,
        &active,
        Some(&seal.proof.output),
    );
    let legacy_committee =
        derive_sortition_committee(&net.vs, ACTIVATION_H, ROUND, 64, &net.parent);
    assert_eq!(vrf_committee.len(), 64);
    assert_ne!(
        vrf_committee, legacy_committee,
        "fixture must exercise a real draw divergence"
    );
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal.clone()),
        )
        .expect("scaled certificate must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, Some(seal.clone()));
    std::env::set_var(live_env_key(), ACTIVATION_H.to_string());
    stellereum::consensus::set_live_vrf_registry(net.reg.clone());
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "scaled sealed certificate must verify on the explicit path"
    );
    let marker = marker_only_qc_live(&cert, net.block_hash);
    assert!(
        marker.verify_unified(&net.vs),
        "live pq path must accept the diverged VRF committee"
    );
    let vrf_set: std::collections::HashSet<[u8; 32]> =
        vrf_committee.iter().copied().collect();
    assert_eq!(
        marker.signers_set(&net.vs),
        vrf_set,
        "live attribution must match the diverged VRF committee"
    );
    // …while the legacy draw refuses it (flag-day shape for non-trivial draws).
    assert!(
        !qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &VrfActivation::Disabled, None),
        "legacy draw must refuse a diverged VRF committee"
    );

    stellereum::consensus::clear_live_vrf_registry_for_tests();
}

#[test]
fn live_sites_pre_activation_byte_identical() {
    let _guard = SERIAL_LIVE.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestoreLive::save(&[live_env_key()]);
    stellereum::consensus::clear_live_vrf_registry_for_tests();

    // Armed env + loaded registry, but the height is pre-activation: the
    // height gate (not proof presence) decides — legacy bytes.
    let net = setup_net(4, 0xA3, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let h_before = ACTIVATION_H - 1;
    std::env::set_var(live_env_key(), ACTIVATION_H.to_string());
    stellereum::consensus::set_live_vrf_registry(net.reg.clone());

    let seal_before = seal_for(&net, 0, h_before, ROUND);
    let set = vote_set_for(&net, h_before, ROUND);
    let threaded = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal_before),
        )
        .expect("must form");
    let legacy = set
        .certificate(net.block_hash, &net.vs, &net.parent)
        .expect("legacy certificate must form");
    assert_eq!(threaded, legacy, "H-1 assembly must be struct-identical");
    let threaded_cert = threaded.pq_micro_certificate().expect("attached");
    let legacy_cert = legacy.pq_micro_certificate().expect("attached");
    assert_eq!(threaded_cert.vrf_beacon, None);
    assert_eq!(
        encode_pq_micro_envelope(&threaded_cert),
        encode_pq_micro_envelope(&legacy_cert),
        "H-1 canonical bytes must be legacy bytes"
    );

    // The live sites agree on the legacy draw at H-1.
    assert!(
        threaded.verify_unified(&net.vs),
        "live verify must accept the H-1 certificate"
    );
    let legacy_committee = derive_sortition_committee(&net.vs, h_before, ROUND, 4, &net.parent);
    let legacy_set: std::collections::HashSet<[u8; 32]> =
        legacy_committee.iter().copied().collect();
    let marker = marker_only_qc_live(&legacy_cert, net.block_hash);
    assert!(
        marker.verify_unified(&net.vs),
        "live pq path must verify legacy at H-1"
    );
    assert_eq!(marker.signers_set(&net.vs), legacy_set);

    // Default-off live path (env unset, registry cleared) agrees too.
    std::env::remove_var(live_env_key());
    stellereum::consensus::clear_live_vrf_registry_for_tests();
    assert_eq!(
        stellereum::vrf::vrf_activation_from_env(),
        VrfActivation::Disabled
    );
    assert!(threaded.verify_unified(&net.vs));
    assert_eq!(marker.signers_set(&net.vs), legacy_set);
}

#[test]
fn live_sites_fallback_matrix_and_forged_refuse() {
    let _guard = SERIAL_LIVE.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestoreLive::save(&[live_env_key()]);
    stellereum::consensus::clear_live_vrf_registry_for_tests();

    let net = setup_net(4, 0xA4, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let h = ACTIVATION_H;
    assert!(active.is_active_at(h), "fixture height must be armed");
    std::env::set_var(live_env_key(), ACTIVATION_H.to_string());
    stellereum::consensus::set_live_vrf_registry(net.reg.clone());

    let legacy = legacy_qc_at(&net, h, ROUND);
    let legacy_cert = legacy.pq_micro_certificate().expect("attached");
    let legacy_committee = derive_sortition_committee(&net.vs, h, ROUND, 4, &net.parent);
    let legacy_set: std::collections::HashSet<[u8; 32]> =
        legacy_committee.iter().copied().collect();
    let base = || {
        PqMicroCertificate::new(
            legacy_cert.scheme,
            legacy_cert.height,
            legacy_cert.round,
            legacy_cert.committee_size,
            legacy_cert.signers_bitmask.clone(),
            legacy_cert.signatures.clone(),
            legacy_cert.sortition_parent,
        )
    };

    // Unknown-key seal + armed env + loaded registry ⇒ legacy fallback: the
    // missing key is a rollout gap, not evidence of forgery.
    let foreign_secret = VrfSecret::from_seed(&[0xEEu8; 32]);
    let seed_input = sortition_seed(&net.parent, h, ROUND);
    let foreign_proof = vrf_prove(&foreign_secret, &seed_input);
    let unknown_seal = VrfBeaconSeal::new([0x99u8; 32], foreign_proof);
    let with_unknown = base().with_vrf_beacon(unknown_seal);
    let marker = marker_only_qc_live(&with_unknown, net.block_hash);
    assert!(
        marker.verify_unified(&net.vs),
        "unknown-key seal must fall back to legacy on the live path"
    );
    assert_eq!(marker.signers_set(&net.vs), legacy_set);

    // FORGED proof bytes under a KNOWN key ⇒ the whole micro-cert refuses.
    let seal = seal_for(&net, 0, h, ROUND);
    let mut bad_proof = seal.proof.clone();
    bad_proof.proof[7] ^= 0x01;
    let forged_seal = VrfBeaconSeal::new(net.ids[0], bad_proof);
    let forged_cert = base().with_vrf_beacon(forged_seal);
    let marker = marker_only_qc_live(&forged_cert, net.block_hash);
    assert!(
        !marker.verify_unified(&net.vs),
        "forged proof bytes must refuse on the live path"
    );
    assert!(
        marker.signers_set(&net.vs).is_empty(),
        "forged proof must attribute nobody on the live path"
    );

    // Substituted `output` (proof verifies, field mismatches) ⇒ refuse too.
    let mut bad_out = seal.proof.clone();
    bad_out.output[3] ^= 0x40;
    let swapped_seal = VrfBeaconSeal::new(net.ids[0], bad_out);
    let swapped_cert = base().with_vrf_beacon(swapped_seal);
    let marker = marker_only_qc_live(&swapped_cert, net.block_hash);
    assert!(
        !marker.verify_unified(&net.vs),
        "substituted output must refuse on the live path"
    );
    assert!(
        marker.signers_set(&net.vs).is_empty(),
        "substituted output must attribute nobody on the live path"
    );

    // Missing registry (nothing to check against) + armed env + valid seal ⇒
    // legacy fallback, verifies.
    stellereum::consensus::clear_live_vrf_registry_for_tests();
    let with_valid = base().with_vrf_beacon(seal);
    let marker = marker_only_qc_live(&with_valid, net.block_hash);
    assert!(
        marker.verify_unified(&net.vs),
        "missing registry must fall back to legacy on the live path"
    );
    assert_eq!(marker.signers_set(&net.vs), legacy_set);
}

