//! Hostile battery for the default-off VRF + BLS paths (activation unwired).
//!
//! Every case below must FAIL CLOSED. The ECVRF prove/verify bodies are
//! removed (classical, retired) and BLS QC counting is removed
//! (refused-forever); what stays pinned here: parse refusals, registry
//! gating, inert envelopes, the retired-flag shape, and canonical-draw
//! fallback. Removed-body tests were deleted with the code (reported).

use stellereum::bls::{
    bls_pop_preimage, bls_sign_pop, bls_verify_pop, parse_registry_entries_strict_pop,
    parse_registry_entries_v2, BlsAggregateSignature, BlsKeyRegistry, BlsPublicKey, BlsRegistryStats,
    BlsSecretKey, BlsSignature, SignerBitVector,
};
use stellereum::consensus::{
    decode_qc_bls_envelope, derive_sortition_committee_gated,
    sortition_seed, sortition_seed_gated, ValidatorSet, VoteKind, BLS_QC_MARKER_ID, QC_BLS_MAGIC,
};
use stellereum::vrf::{
    vrf_activation_from_env, vrf_election_seed, VrfActivation, VRF_ACTIVATION_HEIGHT_ENV,
};

// --- fixtures (bls_pop_tests patterns) ---

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

/// Build a structurally valid (decodable) QC-BLS envelope without aggregation:
/// a single real BLS signature plus the caller-chosen bitvector. Decode must
/// accept it (`Some`); counting never runs (removed), so acceptance here pins
/// only the wire parser.
/// GATE (HDAE wire-EMIT cut): hand-built READ bytes inline — the retired
/// `encode_qc_bls_envelope` (empty) is NOT used.
#[allow(clippy::too_many_arguments)] // GATE: envelope fixture mirrors the wire layout field-for-field; a struct would hide the field order under test.
fn handbuilt_envelope(
    height: u64,
    round: u32,
    kind: VoteKind,
    bh: [u8; 32],
    signers: std::ops::Range<usize>,
    total: usize,
    keys: &[BlsSecretKey],
    msg: &[u8],
) -> Vec<u8> {
    let mut participants = SignerBitVector::new(total);
    for i in signers.clone() {
        participants.set(i, true);
    }
    let agg = BlsAggregateSignature {
        signature: keys[signers.start].sign(msg),
        participants,
    };
    let (sig, bits) = agg.to_bytes();
    let mut out = Vec::with_capacity(16 + 8 + 4 + 1 + 32 + 4 + 96 + bits.len());
    out.extend_from_slice(QC_BLS_MAGIC);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.push(match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    });
    out.extend_from_slice(&bh);
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&sig);
    out.extend_from_slice(bits);
    out
}

// --- REMOVED (ECVRF-body tests): `forged_vrf_proof_random_bytes_refused`,
// --- `vrf_proof_replay_across_inputs_refused`, `vrf_wrong_key_proof_refused`,
// --- and `vrf_tampered_election_seed_refused` tested the removed `vrf_prove`
// --- / `vrf_verify` / `verify_vrf_seed_for_validator` bodies (plus the
// --- `registered_registry` fixture that minted them) — deleted with the code
// --- they pinned (reported). Retry/output-shape pins that survive
// --- (election-seed binding, gated fallback) live in the boundary test.



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

// --- BLS: rogue registry entry refuses (parse-time rogue-key gate) ---

#[test]
fn bls_rogue_registry_entry_refused() {
    // Strict registry: honest PoPs accept, rogue (PoP for another id) refuses.
    // (The aggregate-verify half of this probe was deleted with
    // `aggregate_signatures` / `verify_aggregate_signature` / `canonical_keys`.)
    let honest: Vec<BlsSecretKey> = (0..2)
        .map(|i| BlsSecretKey::from_seed(&[0x60u8 + i; 32]))
        .collect();
    let honest_ids = [ed(0xA1), ed(0xA2)];
    let rogue_sk = BlsSecretKey::from_seed(&[0xEBu8; 32]);
    let rogue_id = ed(0xB0);
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
    // The registry pins exactly the two honest keys: the rogue never enters,
    // so no power-count path (removed) could ever resolve it.
    assert!(reg.contains_key(&honest_ids[0]));
    assert!(reg.contains_key(&honest_ids[1]));
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
    // (Hand-built decodable envelope: no aggregation — counting removed.)
    let bh = [0x44u8; 32];
    let msg = stellereum::consensus::vote_sign_bytes(9, 2, VoteKind::Precommit, &Some(bh));
    let keys: Vec<BlsSecretKey> =
        (0..3).map(|i| BlsSecretKey::from_seed(&[0x10u8 + i; 32])).collect();
    let good_payload = handbuilt_envelope(9, 2, VoteKind::Precommit, bh, 0..3, 3, &keys, &msg);
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

    // REMOVED (hybrid format gate): the `HybridCertificate` version-confusion
    // block lived here — deleted with `HybridCertificate` / `is_bls_active`.
    // Marker id is not a validator: marker-only bytes count for nothing.
    assert_eq!(
        ValidatorSet::from_list(vec![(ed(0x01), 1), (ed(0x02), 1)]).power_of(&BLS_QC_MARKER_ID),
        0
    );
}

// --- Empty / oversized inputs refuse without panic ---

// --- Parse-level refusals without panic ---

#[test]
fn parse_level_refusals_without_panic() {
    // REMOVED (aggregate-construction refusals): empty/out-of-range/duplicate
    // and zero-participant cases tested `aggregate_signatures` /
    // `verify_aggregate_signature` — deleted with those bodies. What stays are
    // the parse-layer pins (inert envelope inputs must never panic).

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

    // Oversized envelope (u32::MAX validators claim) refuses at decode.
    // (Hand-built decodable base: no aggregation — counting removed.)
    let keys: Vec<BlsSecretKey> = (0..2)
        .map(|i| BlsSecretKey::from_seed(&[0x30u8 + i; 32]))
        .collect();
    let msg = stellereum::consensus::vote_sign_bytes(9, 0, VoteKind::Precommit, &Some([9u8; 32]));
    let mut payload = handbuilt_envelope(9, 0, VoteKind::Precommit, [9u8; 32], 0..2, 2, &keys, &msg);
    payload[61..65].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_qc_bls_envelope(&payload).is_none());
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

    // REMOVED (BLS height helper): the `is_bls_active` boundary block lived
    // here — deleted with `is_bls_active` / `HybridCertificate`.

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
