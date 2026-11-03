//! Hostile battery for the default-off VRF + BLS paths (activation unwired).
//!
//! Every case below must FAIL CLOSED: `None` / `Err` / `false`, never `Some` /
//! `Ok(true)` / accept, never panic. VRF is ECVRF-EDWARDS25519-SHA512-
//! Elligator2 (RFC 9381, full uniqueness); BLS QC counting is hard-refused
//! at startup. These tests pin the refusal posture so activation cannot
//! silently widen it.

use stellereum::bls::{
    aggregate_signatures, bls_pop_preimage, bls_sign_pop, bls_verify_pop, is_bls_active,
    parse_registry_entries_strict_pop, parse_registry_entries_v2, verify_aggregate_signature,
    BlsAggregateSignature, BlsKeyRegistry, BlsPublicKey, BlsRegistryStats, BlsSecretKey, BlsSignature,
    HybridCertificate, SignerBitVector,
};
use stellereum::consensus::{
    decode_qc_bls_envelope, derive_sortition_committee_gated, encode_qc_bls_envelope,
    sortition_seed, sortition_seed_gated, ValidatorSet, VoteKind, BLS_QC_MARKER_ID,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_activation_from_env, vrf_binding_preimage,
    vrf_election_seed, vrf_prove, vrf_verify, VrfActivation, VrfBinding, VrfRegistry, VrfSecret,
    VRF_ACTIVATION_HEIGHT_ENV, VRF_PROOF_LEN,
};

// --- fixtures (copied patterns from vrf_sortition_gate_tests / bls_pop_tests) ---

fn fixture_ids() -> Vec<[u8; 32]> {
    (1u8..=4).map(|i| [i; 32]).collect()
}

fn registered_registry(ids: &[[u8; 32]]) -> (VrfRegistry, Vec<VrfSecret>) {
    let mut reg = VrfRegistry::new();
    let mut secrets = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let falcon_seed = [(i as u8).wrapping_add(0x70); 32];
        let falcon = FalconKeypair::generate_from_seed_bytes(&falcon_seed);
        let sk = VrfSecret::from_seed(&[(i as u8).wrapping_add(0x42); 32]);
        let vrf_pk = sk.public_key().to_bytes();
        let sig = falcon.sign(&vrf_binding_preimage(id, &vrf_pk));
        reg.register(
            &VrfBinding {
                validator_id: *id,
                vrf_pk,
                falcon_sig: sig,
            },
            falcon.public_key(),
        )
        .expect("honest binding registers");
        secrets.push(sk);
    }
    (reg, secrets)
}

fn ed(id: u8) -> [u8; 32] {
    [id; 32]
}

fn pop_line(ed_id: &[u8; 32], sk: &BlsSecretKey) -> String {
    format!(
        "{} {} {}",
        hex::encode(ed_id),
        hex::encode(sk.public_key().to_bytes()),
        hex::encode(bls_sign_pop(sk, ed_id).to_bytes())
    )
}

fn legacy_line(ed_id: &[u8; 32], sk: &BlsSecretKey) -> String {
    format!(
        "{} {}",
        hex::encode(ed_id),
        hex::encode(sk.public_key().to_bytes())
    )
}

// --- VRF: forged random proof bytes refuse ---

#[test]
fn forged_vrf_proof_random_bytes_refused() {
    let ids = fixture_ids();
    let (reg, secrets) = registered_registry(&ids);
    let seed = [0x5Au8; 32];
    let good = vrf_prove(&secrets[0], &seed);
    let pk = secrets[0].public_key().to_bytes();
    assert_eq!(vrf_verify(&pk, &seed, &good), Some(good.output));

    // Deterministic "random" corpora: all-zeros, all-ones, patterned, flipped.
    let mut forged = good.clone();
    forged.proof.copy_from_slice(&[0x77u8; VRF_PROOF_LEN]);
    forged.output = [0x88u8; 32];
    assert_eq!(vrf_verify(&pk, &seed, &forged), None);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed, &forged),
        None
    );

    let mut zeros = good.clone();
    zeros.proof = [0u8; VRF_PROOF_LEN];
    zeros.output = [0u8; 32];
    assert_eq!(vrf_verify(&pk, &seed, &zeros), None);

    let mut ones = good;
    ones.proof = [0xFFu8; VRF_PROOF_LEN];
    ones.output = [0xFFu8; 32];
    assert_eq!(vrf_verify(&pk, &seed, &ones), None);
}

// --- VRF: replay across inputs / heights / rounds refuses ---

#[test]
fn vrf_proof_replay_across_inputs_refused() {
    let ids = fixture_ids();
    let (reg, secrets) = registered_registry(&ids);
    let parent = [0x5Au8; 32];
    let active = VrfActivation::FromHeight(1_000_000);
    let seed_a = sortition_seed(&parent, 1_000_000, 2);
    let seed_b = sortition_seed(&parent, 1_000_001, 2);
    assert_ne!(seed_a, seed_b);

    let proof_a = vrf_prove(&secrets[0], &seed_a);
    // Same proof bytes under another seed input: refuse.
    assert_eq!(vrf_verify(&secrets[0].public_key().to_bytes(), &seed_b, &proof_a), None);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed_b, &proof_a),
        None
    );
    // Round-bound seed input differs too.
    let seed_r3 = sortition_seed(&parent, 1_000_000, 3);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed_r3, &proof_a),
        None
    );
    // Election seeds are height/round bound: a replayed output cannot reuse a seed.
    assert_ne!(
        vrf_election_seed(&proof_a.output, 1_000_000, 2),
        vrf_election_seed(&proof_a.output, 1_000_001, 2)
    );
    assert_ne!(
        vrf_election_seed(&proof_a.output, 1_000_000, 2),
        vrf_election_seed(&proof_a.output, 1_000_000, 3)
    );
    // Gated election with no minted output falls back to the parent seed.
    assert_eq!(
        sortition_seed_gated(&parent, 1_000_000, 2, &active, None),
        sortition_seed(&parent, 1_000_000, 2)
    );
}

// --- VRF: wrong-key proof refuses ---

#[test]
fn vrf_wrong_key_proof_refused() {
    let ids = fixture_ids();
    let (reg, secrets) = registered_registry(&ids);
    let seed = [0x5Au8; 32];
    let proof = vrf_prove(&secrets[0], &seed);

    // Valid proof under the wrong registered key: refuse.
    let other_pk = secrets[1].public_key().to_bytes();
    assert_eq!(vrf_verify(&other_pk, &seed, &proof), None);
    // Foreign secret's proof under an honest id: refuse.
    let foreign = vrf_prove(&VrfSecret::from_seed(&[0x99u8; 32]), &seed);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed, &foreign),
        None
    );
    // Unknown validator id: refuse (never registered).
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &[0x22u8; 32], &seed, &proof),
        None
    );
    // Swapped registry key: a proof for id[0] under id[1]'s key refuses.
    let proof1 = vrf_prove(&secrets[1], &seed);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed, &proof1),
        None
    );
}

// --- VRF: tampered election seed / output refuses ---

#[test]
fn vrf_tampered_election_seed_refused() {
    let ids = fixture_ids();
    let (reg, secrets) = registered_registry(&ids);
    let seed = [0x5Au8; 32];
    let pk = secrets[0].public_key().to_bytes();
    let good = vrf_prove(&secrets[0], &seed);

    // Flipped proof byte refuses.
    let mut bad_byte = good.clone();
    bad_byte.proof[7] ^= 0x01;
    assert_eq!(vrf_verify(&pk, &seed, &bad_byte), None);

    // Substituted output refuses (output bound to proof bytes).
    let mut bad_out = good.clone();
    bad_out.output[0] ^= 0x01;
    assert_eq!(vrf_verify(&pk, &seed, &bad_out), None);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed, &bad_out),
        None
    );

    // Identity public key refuses even with an honest proof.
    assert_eq!(vrf_verify(&[0u8; 32], &seed, &good), None);

    // Non-canonical s refuses (s >= q is rejected at decode).
    let mut bad_s = good.clone();
    bad_s.proof[48..].copy_from_slice(&[0xFFu8; 32]);
    assert_eq!(vrf_verify(&pk, &seed, &bad_s), None);
}

// --- BLS: forged PoP refuses ---

#[test]
fn forged_bls_pop_refused() {
    let sk = BlsSecretKey::from_seed(&[0x51u8; 32]);
    let pk = sk.public_key();
    let id = ed(0x11);
    let good = bls_sign_pop(&sk, &id);
    assert!(bls_verify_pop(&pk, &id, &good));

    // Wrong identity / wrong key refuse.
    assert!(!bls_verify_pop(&pk, &ed(0x12), &good));
    let other = BlsSecretKey::from_seed(&[0x52u8; 32]).public_key();
    assert!(!bls_verify_pop(&other, &id, &good));

    // Message signature over a truncated preimage is not a PoP.
    let msg_sig = sk.sign(&bls_pop_preimage(&id)[1..]);
    assert!(!bls_verify_pop(&pk, &id, &msg_sig));

    // Random 96 bytes (likely off-curve) never parse as a PoP entry.
    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    let line = format!(
        "{} {} {}",
        hex::encode(id),
        hex::encode(pk.to_bytes()),
        hex::encode([0x77u8; 96])
    );
    parse_registry_entries_strict_pop(&line, &mut reg, &mut stats);
    assert_eq!(stats.pop_verified, 0);
    assert_eq!(stats.rejected, 1);
    assert!(!reg.contains_key(&id));

    // Forged PoP (signed for another identity) refuses.
    let forged = bls_sign_pop(&sk, &ed(0x99));
    assert!(!bls_verify_pop(&pk, &id, &forged));
}

// --- BLS: aggregate with one rogue member refuses ---

#[test]
fn bls_aggregate_with_rogue_member_refused() {
    let honest: Vec<BlsSecretKey> = (0..2)
        .map(|i| BlsSecretKey::from_seed(&[0x60u8 + i; 32]))
        .collect();
    let honest_ids = [ed(0xA1), ed(0xA2)];
    let rogue_sk = BlsSecretKey::from_seed(&[0xEBu8; 32]);
    let rogue_id = ed(0xB0);

    // Strict registry: honest PoPs accept, rogue (PoP for another id) refuses.
    let rogue_line = format!(
        "{} {} {}",
        hex::encode(rogue_id),
        hex::encode(rogue_sk.public_key().to_bytes()),
        hex::encode(bls_sign_pop(&rogue_sk, &ed(0x00)).to_bytes())
    );
    let mut text = String::new();
    for (id, sk) in honest_ids.iter().zip(&honest) {
        text.push_str(&pop_line(id, sk));
        text.push('\n');
    }
    text.push_str(&rogue_line);
    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&text, &mut reg, &mut stats);
    assert_eq!(stats.pop_verified, 2);
    assert_eq!(stats.rejected, 1);
    assert!(!reg.contains_key(&rogue_id));

    // Honest aggregate verifies over honest keys.
    let msg = b"rogue-member-probe";
    let keys: Vec<BlsPublicKey> = honest.iter().map(|k| k.public_key()).collect();
    let sigs: Vec<(usize, BlsSignature)> =
        honest.iter().enumerate().map(|(i, k)| (i, k.sign(msg))).collect();
    let agg = aggregate_signatures(&sigs, 2).expect("honest aggregate builds");
    assert!(verify_aggregate_signature(&keys, msg, &agg));

    // Substituted rogue key: same aggregate bytes, rogue in the key list refuse.
    let mut tampered = keys.clone();
    tampered[0] = rogue_sk.public_key();
    assert!(!verify_aggregate_signature(&tampered, msg, &agg));

    // Aggregate that actually includes the rogue signature under an honest-framed
    // key list refuses (pairing mismatch: keys say honest, sigs say rogue).
    let mixed: Vec<(usize, BlsSignature)> =
        vec![(0, honest[0].sign(msg)), (1, rogue_sk.sign(msg))];
    let mixed_agg = aggregate_signatures(&mixed, 2).expect("mixed aggregate builds");
    assert!(!verify_aggregate_signature(&keys, msg, &mixed_agg));

    // Validator set containing the refused rogue cannot resolve keys at all.
    let vs_rogue =
        ValidatorSet::from_list(vec![(honest_ids[0], 1), (honest_ids[1], 1), (rogue_id, 1)]);
    let cfg = stellereum::bls::QcBlsConfig {
        enabled: true,
        registry: reg,
        local_vote_seed: None,
    };
    assert!(cfg.canonical_keys(&vs_rogue).is_none());
}

// --- Mixed-version envelopes: v1 bytes into the strict parser refuse ---

#[test]
fn mixed_version_envelopes_strict_parser_refused() {
    // Bare v1 (2-token legacy) lines refuse under the strict gate.
    let sk = BlsSecretKey::from_seed(&[0x52u8; 32]);
    let id = ed(0x22);
    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&legacy_line(&id, &sk), &mut reg, &mut stats);
    assert_eq!(stats.rejected, 1);
    assert_eq!(stats.legacy, 0);
    assert!(!reg.contains_key(&id));

    // The same line stays accepted by the lenient v2 reader (compat posture).
    let mut reg_v2 = BlsKeyRegistry::new();
    let mut stats_v2 = BlsRegistryStats::default();
    parse_registry_entries_v2(&legacy_line(&id, &sk), &mut reg_v2, &mut stats_v2);
    assert_eq!(stats_v2.legacy, 1);

    // QC BLS envelope: garbage / truncated / wrong-magic payloads refuse.
    let bh = [0x44u8; 32];
    let msg = stellereum::consensus::vote_sign_bytes(9, 2, VoteKind::Precommit, &Some(bh));
    let keys: Vec<BlsSecretKey> =
        (0..3).map(|i| BlsSecretKey::from_seed(&[0x10u8 + i; 32])).collect();
    let sigs: Vec<(usize, BlsSignature)> =
        keys.iter().enumerate().map(|(i, k)| (i, k.sign(&msg))).collect();
    let agg = aggregate_signatures(&sigs, 3).expect("aggregate builds");
    let good_payload = encode_qc_bls_envelope(&agg, 9, 2, VoteKind::Precommit, Some(bh));
    assert!(decode_qc_bls_envelope(&good_payload).is_some());

    // Truncated (simulated v0/v1 short envelope).
    assert!(decode_qc_bls_envelope(&good_payload[..32]).is_none());
    // Wrong magic.
    let mut bad_magic = good_payload.clone();
    bad_magic[0] ^= 0xFF;
    assert!(decode_qc_bls_envelope(&bad_magic).is_none());
    // Trailing byte (oversized envelope).
    let mut oversized = good_payload.clone();
    oversized.push(0x00);
    assert!(decode_qc_bls_envelope(&oversized).is_none());
    // Empty payload.
    assert!(decode_qc_bls_envelope(&[]).is_none());

    // Hybrid format gate: version confusion refuses in both directions.
    let pre_ed = HybridCertificate::Ed25519 {
        height: 500,
        round: 0,
        block_hash: [1u8; 32],
        signatures: vec![([0u8; 32], [0u8; 64])],
    };
    assert!(pre_ed.is_format_valid(10_000));
    let pre_bls = HybridCertificate::BlsAggregate {
        height: 500,
        round: 0,
        block_hash: [1u8; 32],
        aggregate: BlsAggregateSignature {
            signature: keys[0].sign(b"format-check"),
            participants: SignerBitVector::new(4),
        },
    };
    assert!(!pre_bls.is_format_valid(10_000));
    // Marker id is not a validator: marker-only bytes count for nothing.
    assert_eq!(
        ValidatorSet::from_list(vec![(ed(0x01), 1), (ed(0x02), 1)]).power_of(&BLS_QC_MARKER_ID),
        0
    );
}

// --- Empty / oversized inputs refuse without panic ---

#[test]
fn empty_and_oversized_inputs_refused() {
    // Empty aggregate construction refuses.
    assert!(aggregate_signatures(&[], 4).is_err());

    // Out-of-range and duplicate indices refuse.
    let k = BlsSecretKey::from_seed(&[0x99u8; 32]);
    assert!(aggregate_signatures(&[(9, k.sign(b"m"))], 4).is_err());
    assert!(aggregate_signatures(&[(0, k.sign(b"m")), (0, k.sign(b"m"))], 4).is_err());

    // Identity key / signature never parse.
    let id_g1 = bls12_381::G1Affine::identity().to_compressed();
    assert!(BlsPublicKey::from_bytes(&id_g1).is_none());
    let id_g2 = bls12_381::G2Affine::identity().to_compressed();
    assert!(BlsSignature::from_bytes(&id_g2).is_none());

    // Bitmask length confusion refuses; trailing pad bits grant no power.
    assert!(SignerBitVector::from_bitmask(vec![0u8; 2], 4).is_none());
    assert!(SignerBitVector::from_bitmask(vec![], 4).is_none());
    let mut pad = SignerBitVector::new(5);
    pad.set(5, true);
    pad.set(6, true);
    pad.set(7, true);
    assert_eq!(pad.signed_count(), 0);

    // Empty registry text parses to nothing (no panic, no entry).
    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop("", &mut reg, &mut stats);
    assert!(reg.is_empty());
    assert_eq!(stats.pop_verified, 0);

    // Zero-participant aggregate refuses at verify.
    let keys: Vec<BlsSecretKey> = (0..3).map(|_| BlsSecretKey::generate()).collect();
    let pks: Vec<BlsPublicKey> = keys.iter().map(|x| x.public_key()).collect();
    let agg = aggregate_signatures(&[(1, keys[1].sign(b"m"))], 3).expect("builds");
    let mut none = agg;
    none.participants.set(1, false);
    assert!(!verify_aggregate_signature(&pks, b"m", &none));

    // Oversized envelope (u32::MAX validators claim) refuses at decode.
    let keys2: Vec<BlsSecretKey> = (0..2).map(|_| BlsSecretKey::generate()).collect();
    let pks2: Vec<BlsPublicKey> = keys2.iter().map(|x| x.public_key()).collect();
    let sigs: Vec<(usize, BlsSignature)> =
        keys2.iter().enumerate().map(|(i, x)| (i, x.sign(b"m"))).collect();
    let agg2 = aggregate_signatures(&sigs, 2).expect("builds");
    let mut payload = encode_qc_bls_envelope(&agg2, 9, 0, VoteKind::Precommit, Some([9u8; 32]));
    payload[61..65].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_qc_bls_envelope(&payload).is_none());

    // VRF identity key refuses.
    let seed = [0x5Au8; 32];
    let sk = VrfSecret::from_seed(&[0x42u8; 32]);
    let proof = vrf_prove(&sk, &seed);
    assert_eq!(vrf_verify(&[0u8; 32], &seed, &proof), None);
    let _ = pks2;
}

// --- Boundary activation heights never panic, gate exactly ---

#[test]
fn boundary_activation_heights_fail_closed() {
    // VRF gate boundaries.
    assert!(!VrfActivation::Disabled.is_active_at(0));
    assert!(!VrfActivation::Disabled.is_active_at(1));
    assert!(!VrfActivation::Disabled.is_active_at(u64::MAX));
    assert_eq!(VrfActivation::Disabled.boundary(), None);

    let at_max = VrfActivation::FromHeight(u64::MAX);
    assert!(!at_max.is_active_at(u64::MAX - 1));
    assert!(at_max.is_active_at(u64::MAX));
    assert_eq!(at_max.boundary(), Some(u64::MAX));

    let at_zero = VrfActivation::FromHeight(0);
    assert!(at_zero.is_active_at(0));
    assert!(at_zero.is_active_at(1));
    assert!(at_zero.is_active_at(u64::MAX));

    let at_one = VrfActivation::FromHeight(1);
    assert!(!at_one.is_active_at(0));
    assert!(at_one.is_active_at(1));
    assert!(at_one.is_active_at(u64::MAX));

    // BLS height helper at the same boundaries.
    assert!(is_bls_active(0, 0));
    assert!(!is_bls_active(0, 1));
    assert!(is_bls_active(1, 1));
    assert!(is_bls_active(u64::MAX, u64::MAX));
    assert!(!is_bls_active(0, u64::MAX));

    // Env parsing never panics on boundary spellings — and (GATE: VRF arming
    // retired) every configured value reads `Disabled`, never a boundary.
    let saved = std::env::var(VRF_ACTIVATION_HEIGHT_ENV).ok();
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, u64::MAX.to_string());
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, "0");
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, "1");
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, "not-a-height");
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    match saved {
        Some(v) => std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, v),
        None => std::env::remove_var(VRF_ACTIVATION_HEIGHT_ENV),
    }

    // Election at u64::MAX height: gated-with-output differs from parent seed
    // (deterministic, no overflow), gated-without-output falls back safely.
    let vs = ValidatorSet::from_list(vec![([0x01u8; 32], 10), ([0x02u8; 32], 10)]);
    let parent = [0x5Au8; 32];
    let active_max = VrfActivation::FromHeight(u64::MAX);
    let out = [0xABu8; 32];
    let seed_max = vrf_election_seed(&out, u64::MAX, u32::MAX);
    assert_eq!(seed_max, vrf_election_seed(&out, u64::MAX, u32::MAX));
    assert_ne!(seed_max, vrf_election_seed(&out, u64::MAX, 0));
    assert_eq!(
        sortition_seed_gated(&parent, u64::MAX, 0, &active_max, None),
        sortition_seed(&parent, u64::MAX, 0)
    );
    let committee = derive_sortition_committee_gated(
        &vs,
        u64::MAX,
        0,
        1,
        &parent,
        &active_max,
        Some(&out),
    );
    assert!(committee.len() <= 1);
}
