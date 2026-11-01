//! BLS registry / proof-of-possession audit tests.
//!
//! Scope: `src/bls.rs` registry parsing and PoP gating ONLY (VRF/sortition and
//! the consensus QC wiring belong to other audits and are not touched here).
//!
//! What this pins:
//! * STRICT-vs-LENIENT differential: the same registry text parses to
//!   different registries under `parse_registry_entries_strict_pop` (gated,
//!   default OFF) and `parse_registry_entries_v2` (lenient). The v2 reader
//!   keeps a compatibility fallback — a third token that is not a 96-byte
//!   value is IGNORED and the line is accepted as legacy — while the strict
//!   reader refuses it. Both readings are pinned exactly so a future edit
//!   cannot silently move an entry from one class to the other.
//! * FORGED-PoP REFUSAL (rogue-key negative test): spliced, wrong-key,
//!   truncated-preimage and identity-point PoPs never enter the strict
//!   registry, so `canonical_keys` — and therefore any BLS power count — is
//!   unavailable for any set containing the refused identity, while the
//!   honest quorum still verifies.
//! * SKIP-METERING: every skipped entry is observable in
//!   `bls_registry_migration_counts`. This covers the fix that the live
//!   default-off v1 parse (`QcBlsConfig::from_env` without
//!   `STELL_BLS_POP_REQUIRED`) now feeds the legacy/rejected counters —
//!   before the fix its warn-and-skip path incremented nothing, leaving the
//!   documented phase-2 readiness signal (`legacy == 0 && rejected == 0`)
//!   blind on the only path production parses take.
//! * CERT-CONFUSION REFUSAL: `HybridCertificate` (soft-fork format vehicle)
//!   and the live `QuorumCertificate` BLS-envelope path cannot be mistaken
//!   for each other — the envelope is cryptographically bound to its
//!   certificate's (height, round, kind, target) while the hybrid height is
//!   an unbound format field, and a spliced binding is refused.

use stellereum::bls::*;
use stellereum::consensus::{
    BLS_QC_MARKER_ID, QuorumCertificate, ValidatorSet, VoteKind, decode_qc_bls_envelope,
    encode_qc_bls_envelope, vote_sign_bytes,
};

// Serializes every test in this file that observes process-wide state: the
// migration counters (bumped by all three registry parsers), the process
// environment (read by `QcBlsConfig::from_env`), and the process-global QC
// config. Without this, parallel test threads would pollute each other's
// counter deltas and env windows.
static AUDIT_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ed(id: u8) -> [u8; 32] {
    [id; 32]
}

fn seed(b: u8) -> [u8; 32] {
    [b; 32]
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

struct EnvRestore {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestore {
    fn save(keys: &[&'static str]) -> Self {
        Self {
            saved: keys.iter().map(|k| (*k, std::env::var(k).ok())).collect(),
        }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Strict-vs-lenient differential
// ---------------------------------------------------------------------------

/// The same 8-line registry under both readers. L1 is the only line both
/// accept; L2–L4 expose the lenient fallback (bare legacy, non-hex third
/// token, short third token); L5–L8 are refused by both (forged PoP,
/// malformed, non-hex keys, identity-point PoP).
fn differential_registry() -> (Vec<[u8; 32]>, Vec<BlsSecretKey>, String) {
    let ids = [ed(0xA1), ed(0xA2), ed(0xA3), ed(0xA4), ed(0xA5)];
    let sks: Vec<BlsSecretKey> = (0..5).map(|i| BlsSecretKey::from_seed(&seed(0x10 + i))).collect();

    let l1 = pop_line(&ids[0], &sks[0]); // valid PoP: accepted by both
    let l2 = legacy_line(&ids[1], &sks[1]); // bare legacy: strict refuses, v2 accepts
    let l3 = format!(
        "{} {} zzzz",
        hex::encode(ids[2]),
        hex::encode(sks[2].public_key().to_bytes())
    ); // non-hex 3rd token: strict refuses, v2 IGNORES it (legacy)
    let l4 = format!(
        "{} {} deadbeef",
        hex::encode(ids[3]),
        hex::encode(sks[3].public_key().to_bytes())
    ); // short 3rd token: strict refuses, v2 IGNORES it (legacy)
    let l5 = format!(
        "{} {} {}",
        hex::encode(ids[4]),
        hex::encode(sks[4].public_key().to_bytes()),
        // Forged PoP: a real signature, but minted for another identity.
        hex::encode(bls_sign_pop(&sks[4], &ed(0x00)).to_bytes())
    );
    let l6 = "not-a-key".to_string(); // malformed: both refuse
    let l7 = format!("zzzz {}", hex::encode(sks[0].public_key().to_bytes())); // non-hex: both refuse
    let identity_pop = hex::encode(bls12_381::G2Affine::identity().to_compressed());
    let l8 = format!(
        "{} {} {identity_pop}",
        hex::encode(ids[0]),
        hex::encode(sks[0].public_key().to_bytes())
    ); // identity-point PoP: not a G2 point per from_bytes, both refuse

    (
        ids.to_vec(),
        sks,
        [l1, l2, l3, l4, l5, l6, l7, l8].join("\n"),
    )
}

#[test]
fn strict_vs_lenient_differential_is_pinned() {
    let _gate = AUDIT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let (ids, sks, text) = differential_registry();

    // Strict gate: exactly the valid-PoP line registers; everything else is
    // refused and metered — legacy is NEVER counted here.
    let (v0, l0, r0) = bls_registry_migration_counts();
    let mut strict_reg = BlsKeyRegistry::new();
    let mut strict_stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&text, &mut strict_reg, &mut strict_stats);
    let (v1, l1, r1) = bls_registry_migration_counts();
    assert_eq!(
        strict_stats,
        BlsRegistryStats {
            pop_verified: 1,
            legacy: 0,
            rejected: 7,
        },
        "strict reading must accept only L1 and refuse L2..L8"
    );
    assert_eq!(strict_reg.len(), 1);
    assert_eq!(strict_reg.get(&ids[0]), Some(&sks[0].public_key()));
    for id in &ids[1..] {
        assert!(
            !strict_reg.contains_key(id),
            "refused identity must never register"
        );
    }
    assert_eq!((v1 - v0, l1 - l0, r1 - r0), (1, 0, 7));

    // Lenient v2 reader: the SAME bytes accept four lines. L3/L4 are the
    // compatibility fallback — a third token that is not a 96-byte value is
    // ignored and the line degrades to legacy, NOT to a refusal.
    let (v2a, l2a, r2a) = bls_registry_migration_counts();
    let mut lenient_reg = BlsKeyRegistry::new();
    let mut lenient_stats = BlsRegistryStats::default();
    parse_registry_entries_v2(&text, &mut lenient_reg, &mut lenient_stats);
    let (v2b, l2b, r2b) = bls_registry_migration_counts();
    assert_eq!(
        lenient_stats,
        BlsRegistryStats {
            pop_verified: 1,
            legacy: 3,
            rejected: 4,
        },
        "lenient reading: L1 verified; L2/L3/L4 legacy (L3/L4 via the \
         non-96-byte fallback); L5/L6/L7/L8 rejected"
    );
    assert_eq!(lenient_reg.len(), 4);
    for id in &ids[0..4] {
        assert!(lenient_reg.contains_key(id), "L1..L4 must all register");
    }
    assert!(!lenient_reg.contains_key(&ids[4]), "forged PoP must not register");
    assert_eq!((v2b - v2a, l2b - l2a, r2b - r2a), (1, 3, 4));

    // The differential itself: strict output is a strict subset of lenient
    // output, and the gap is exactly the PoP-less lines.
    assert!(
        strict_reg.keys().all(|k| lenient_reg.contains_key(k)),
        "strict registry must be a subset of the lenient registry"
    );
    assert_eq!(
        lenient_reg.len() - strict_reg.len(),
        3,
        "the gap is exactly L2/L3/L4"
    );
    // Every stored PoP re-verifies against the stored key (no spliced entry
    // smuggles in through either path).
    assert!(bls_verify_pop(
        lenient_reg.get(&ids[0]).unwrap(),
        &ids[0],
        &bls_sign_pop(&sks[0], &ids[0])
    ));
}

// ---------------------------------------------------------------------------
// 2. Forged-PoP refusal (rogue-key negative test)
// ---------------------------------------------------------------------------

#[test]
fn forged_pop_shapes_refuse_and_yield_no_bls_power() {
    let _gate = AUDIT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let honest: Vec<BlsSecretKey> = (0..2).map(|i| BlsSecretKey::from_seed(&seed(0x40 + i))).collect();
    let honest_ids = [ed(0xC1), ed(0xC2)];
    let rogue_sk = BlsSecretKey::from_seed(&seed(0xEB));
    let rogue_id = ed(0xD0);
    let rogue_pk_hex = hex::encode(rogue_sk.public_key().to_bytes());
    let rogue_ed_hex = hex::encode(rogue_id);

    // Four forgery shapes, all over well-formed (ed, bls) pairs:
    // spliced (another identity's PoP), wrong-key (another secret's PoP for
    // THIS identity), truncated-preimage signature (a vote-shaped signature,
    // domain-separated away from PoP), and the identity point.
    let spliced = hex::encode(bls_sign_pop(&rogue_sk, &ed(0x00)).to_bytes());
    let other_sk = BlsSecretKey::from_seed(&seed(0xEC));
    let wrong_key = hex::encode(bls_sign_pop(&other_sk, &rogue_id).to_bytes());
    let truncated = hex::encode(
        rogue_sk
            .sign(&bls_pop_preimage(&rogue_id)[1..])
            .to_bytes(),
    );
    let identity = hex::encode(bls12_381::G2Affine::identity().to_compressed());
    let forgery_lines = [
        format!("{rogue_ed_hex} {rogue_pk_hex} {spliced}"),
        format!("{rogue_ed_hex} {rogue_pk_hex} {wrong_key}"),
        format!("{rogue_ed_hex} {rogue_pk_hex} {truncated}"),
        format!("{rogue_ed_hex} {rogue_pk_hex} {identity}"),
    ];

    let mut text = String::new();
    for (id, sk) in honest_ids.iter().zip(&honest) {
        text.push_str(&pop_line(id, sk));
        text.push('\n');
    }
    for line in &forgery_lines {
        text.push_str(line);
        text.push('\n');
    }

    let (v0, _, r0) = bls_registry_migration_counts();
    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&text, &mut reg, &mut stats);
    let (v1, _, r1) = bls_registry_migration_counts();
    assert_eq!(stats.pop_verified, 2, "honest PoPs accept");
    assert_eq!(stats.rejected, 4, "every forgery shape refuses");
    assert_eq!(stats.legacy, 0);
    assert!(!reg.contains_key(&rogue_id), "rogue key must never register");
    assert_eq!((v1 - v0, r1 - r0), (2, 4));

    // Any validator set containing the refused identity resolves NO BLS keys
    // at all: one missing member disables counting for the whole certificate
    // (fallback), so the forgery buys zero BLS power.
    let vs_with_rogue = ValidatorSet::from_list(vec![
        (honest_ids[0], 1),
        (honest_ids[1], 1),
        (rogue_id, 1),
    ]);
    let cfg = QcBlsConfig {
        enabled: true,
        registry: reg.clone(),
        local_vote_seed: None,
    };
    assert!(
        cfg.canonical_keys(&vs_with_rogue).is_none(),
        "a set containing the refused rogue resolves no keys"
    );

    // The honest-only set still resolves, and its aggregate verifies — the
    // gate removes the attacker without breaking honest quorum math.
    let vs_honest =
        ValidatorSet::from_list(vec![(honest_ids[0], 1), (honest_ids[1], 1)]);
    let keys = cfg
        .canonical_keys(&vs_honest)
        .expect("honest set must resolve");
    let msg = b"audit-forged-pop-negative";
    let sigs: Vec<(usize, BlsSignature)> = honest
        .iter()
        .enumerate()
        .map(|(i, k)| (i, k.sign(msg)))
        .collect();
    let agg = aggregate_signatures(&sigs, 2).expect("honest aggregate builds");
    assert!(verify_aggregate_signature(&keys, msg, &agg));
    // And the same bytes do NOT verify with the rogue key substituted in.
    let mut tampered = keys.clone();
    tampered[0] = rogue_sk.public_key();
    assert!(
        !verify_aggregate_signature(&tampered, msg, &agg),
        "aggregate must not verify under a substituted rogue key"
    );
}

// ---------------------------------------------------------------------------
// 3. Skip-metering on the live default-off path (regression test for the fix)
// ---------------------------------------------------------------------------

#[test]
fn default_path_skips_are_metered_in_migration_counts() {
    let _gate = AUDIT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore =
        EnvRestore::save(&[BLS_KEYS_FILE_ENV, BLS_KEYS_INLINE_ENV, BLS_POP_REQUIRED_ENV, BLS_QC_ENV]);

    let sk_a = BlsSecretKey::from_seed(&seed(0x71));
    let sk_b = BlsSecretKey::from_seed(&seed(0x72));
    let (id_a, id_b) = (ed(0xE1), ed(0xE2));
    // Two good legacy lines plus three skips: malformed (single token),
    // non-hex, and wrong-length BLS key. All three are warn-and-skip shapes
    // the live registry file can actually contain.
    let body = format!(
        "{}\n{}\n{}\n{} {}\n{} {}\n",
        legacy_line(&id_a, &sk_a),
        legacy_line(&id_b, &sk_b),
        "not-a-key",
        hex::encode(id_a),
        "zzzz",
        hex::encode(id_b),
        "ab",
    );
    let path = std::env::temp_dir().join(format!(
        "stell-bls-audit-meter-{}-{}.reg",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::write(&path, &body).expect("write temp registry");
    std::env::set_var(BLS_KEYS_FILE_ENV, &path);
    std::env::remove_var(BLS_KEYS_INLINE_ENV);
    std::env::remove_var(BLS_QC_ENV);

    // Default OFF: the pre-PoP v1 parse runs. Both good lines register; all
    // three bad lines skip — AND the skips are now metered (the fix: before,
    // this parse touched no counter, so silent BLS-power loss was invisible
    // to `bls_registry_migration_counts`).
    std::env::remove_var(BLS_POP_REQUIRED_ENV);
    assert!(!bls_pop_required());
    let (v0, l0, r0) = bls_registry_migration_counts();
    let off = QcBlsConfig::from_env();
    let (v1, l1, r1) = bls_registry_migration_counts();
    assert_eq!(off.registry.len(), 2, "good legacy entries must register");
    assert!(off.registry.contains_key(&id_a));
    assert!(off.registry.contains_key(&id_b));
    assert_eq!(
        (v1 - v0, l1 - l0, r1 - r0),
        (0, 2, 3),
        "default-off parse must meter 2 legacy + 3 rejected"
    );

    // Gate ON: the same bytes refuse every line (no valid PoP anywhere), so
    // nothing registers and all five lines count rejected.
    std::env::set_var(BLS_POP_REQUIRED_ENV, "1");
    let (v2a, l2a, r2a) = bls_registry_migration_counts();
    let on = QcBlsConfig::from_env();
    let (v2b, l2b, r2b) = bls_registry_migration_counts();
    assert!(
        on.registry.is_empty(),
        "strict gate must refuse keys without a valid PoP"
    );
    assert_eq!(
        (v2b - v2a, l2b - l2a, r2b - r2a),
        (0, 0, 5),
        "strict parse must meter 5 rejected"
    );

    // Counters never move backwards.
    let (v3, l3, r3) = bls_registry_migration_counts();
    assert!(v3 >= v2b && l3 >= l2b && r3 >= r2b);

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 4. Aggregate soundness over registry-resolved keys (composition)
// ---------------------------------------------------------------------------

#[test]
fn registry_resolved_keys_verify_and_tampering_fails_closed() {
    // Registry built by direct insert (no parse, no counters): this test pins
    // the verify composition, not the metering.
    let sks: Vec<BlsSecretKey> = (0..3).map(|i| BlsSecretKey::from_seed(&seed(0x20 + i))).collect();
    let ids = [ed(0xB1), ed(0xB2), ed(0xB3)];
    let mut reg = BlsKeyRegistry::new();
    for (id, sk) in ids.iter().zip(&sks) {
        reg.insert(*id, sk.public_key());
    }
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1)).collect());
    let cfg = QcBlsConfig {
        enabled: true,
        registry: reg,
        local_vote_seed: None,
    };
    let keys = cfg.canonical_keys(&vs).expect("full registry resolves");
    let msg = b"audit-registry-verify-composition";
    let sigs: Vec<(usize, BlsSignature)> = sks
        .iter()
        .enumerate()
        .map(|(i, k)| (i, k.sign(msg)))
        .collect();
    let agg = aggregate_signatures(&sigs, 3).expect("aggregate builds");
    assert!(verify_aggregate_signature(&keys, msg, &agg));

    // Soundness on the resolved path: every tamper fails closed.
    assert!(!verify_aggregate_signature(&keys, b"other message", &agg));
    let mut wrong_key = keys.clone();
    wrong_key[1] = BlsSecretKey::from_seed(&seed(0xFF)).public_key();
    assert!(!verify_aggregate_signature(&wrong_key, msg, &agg));
    let mut silent = agg.clone();
    silent.participants.set(0, false);
    assert!(
        !verify_aggregate_signature(&keys, msg, &silent),
        "muted bitvector member must fail: the signature covers 3, the set claims 2"
    );
    assert!(
        !verify_aggregate_signature(&keys[..2], msg, &agg),
        "key list measured against the wrong set must refuse"
    );
    // A set with one member rotated out of the registry resolves nothing:
    // partial key lists are never summed.
    let vs_rotated = ValidatorSet::from_list(vec![(ids[0], 1), (ids[1], 1), (ed(0x00), 1)]);
    assert!(cfg.canonical_keys(&vs_rotated).is_none());
}

// ---------------------------------------------------------------------------
// 5. HybridCertificate vs live-QC confusion refusal
// ---------------------------------------------------------------------------

#[test]
fn hybrid_format_gate_pins_activation_boundary() {
    let activation = 10_000u64;
    assert!(!is_bls_active(activation - 1, activation));
    assert!(is_bls_active(activation, activation));
    assert!(is_bls_active(activation + 1, activation));

    let ed_cert = |height| HybridCertificate::Ed25519 {
        height,
        round: 0,
        block_hash: [1u8; 32],
        signatures: vec![([0u8; 32], [0u8; 64])],
    };
    let dummy_agg = || {
        let sig = BlsSecretKey::from_seed(&seed(0x99)).sign(b"format-check");
        BlsAggregateSignature {
            signature: sig,
            participants: SignerBitVector::new(2),
        }
    };
    let bls_cert = |height| HybridCertificate::BlsAggregate {
        height,
        round: 0,
        block_hash: [2u8; 32],
        aggregate: dummy_agg(),
    };

    // Exact boundary: pre-activation is Ed25519-only, activation is BLS-only.
    assert!(ed_cert(activation - 1).is_format_valid(activation));
    assert!(!ed_cert(activation).is_format_valid(activation));
    assert!(!bls_cert(activation - 1).is_format_valid(activation));
    assert!(bls_cert(activation).is_format_valid(activation));
    assert!(bls_cert(activation + 1).is_format_valid(activation));

    // Accessors report the certificate's OWN fields, independent of variant.
    assert_eq!(bls_cert(7).height(), 7);
    assert_eq!(bls_cert(7).round(), 0);
    assert_eq!(bls_cert(7).block_hash(), [2u8; 32]);
    assert_eq!(ed_cert(9).height(), 9);
}

#[test]
fn hybrid_height_is_unbound_while_qc_envelope_binding_refuses_splice() {
    // The two "heights" live in different domains: the hybrid height is a
    // plain field that only drives the FORMAT verdict, while the QC envelope
    // height is cryptographically bound to the aggregate and refused on
    // mismatch. Neither can be mistaken for the other.
    //
    // Takes AUDIT_GUARD: installing the test config lazy-initializes the
    // process-global `qc_bls()` cell via `QcBlsConfig::from_env`, which reads
    // the registry env vars — so this must never overlap the env windows of
    // the metering tests.
    let _audit_gate = AUDIT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _qc_guard = set_qc_bls_for_tests(QcBlsConfig {
        enabled: true,
        registry: {
            let sks: Vec<BlsSecretKey> =
                (0..2).map(|i| BlsSecretKey::from_seed(&seed(0x30 + i))).collect();
            sks.iter()
                .enumerate()
                .map(|(i, sk)| (ed(0xF0 + i as u8), sk.public_key()))
                .collect()
        },
        local_vote_seed: None,
    });
    // Rebuild the same keys/ids the guard registry was built from.
    let sks: Vec<BlsSecretKey> = (0..2).map(|i| BlsSecretKey::from_seed(&seed(0x30 + i))).collect();
    let ids = [ed(0xF0), ed(0xF1)];
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1)).collect());

    let height = 41u64;
    let bh = [0xABu8; 32];
    let msg = vote_sign_bytes(height, 0, VoteKind::Precommit, &Some(bh));
    let sigs: Vec<(usize, BlsSignature)> = sks
        .iter()
        .enumerate()
        .map(|(i, k)| (i, k.sign(&msg)))
        .collect();
    let agg = aggregate_signatures(&sigs, 2).expect("aggregate builds");

    // QC side: a BLS-only certificate verifies, and ONLY with its bound height.
    let good_qc = QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![(
            BLS_QC_MARKER_ID,
            encode_qc_bls_envelope(&agg, height, 0, VoteKind::Precommit, Some(bh)),
        )],
    };
    assert!(good_qc.verify(&vs), "bound envelope must verify");
    let (dh, dr, dkind, dbh, _) =
        decode_qc_bls_envelope(&good_qc.signatures[0].1).expect("envelope decodes");
    assert_eq!((dh, dr, dkind, dbh), (height, 0, VoteKind::Precommit, bh));

    // Spliced binding, same aggregate bytes, envelope re-bound to height+1
    // while the certificate still claims height: refused.
    let spliced_qc = QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![(
            BLS_QC_MARKER_ID,
            encode_qc_bls_envelope(&agg, height + 1, 0, VoteKind::Precommit, Some(bh)),
        )],
    };
    assert!(
        !spliced_qc.verify(&vs),
        "envelope bound to another height must refuse"
    );

    // Hybrid side: the SAME aggregate in a HybridCertificate verifies
    // independently of the height field — the field only drives the format
    // verdict, never the pairing. Flipping height flips format validity and
    // leaves crypto untouched, the exact opposite coupling from the QC path.
    let activation = 10_000u64;
    let keys: Vec<BlsPublicKey> = sks.iter().map(|k| k.public_key()).collect();
    let hybrid_at = |h| HybridCertificate::BlsAggregate {
        height: h,
        round: 0,
        block_hash: bh,
        aggregate: agg.clone(),
    };
    assert!(verify_aggregate_signature(&keys, &msg, &hybrid_at(height).as_aggregate()));
    assert!(!hybrid_at(height).is_format_valid(activation));
    assert!(hybrid_at(activation).is_format_valid(activation));
    assert!(verify_aggregate_signature(&keys, &msg, &hybrid_at(activation).as_aggregate()));
}

/// Test-only accessor: unwrap the aggregate out of a hybrid certificate.
///
/// (There is deliberately no such helper in production code — nothing on the
/// live path converts a `HybridCertificate` into signature bytes, which is
/// part of why the two certificate shapes cannot be confused.)
trait HybridAggregate {
    fn as_aggregate(&self) -> BlsAggregateSignature;
}

impl HybridAggregate for HybridCertificate {
    fn as_aggregate(&self) -> BlsAggregateSignature {
        match self {
            HybridCertificate::BlsAggregate { aggregate, .. } => aggregate.clone(),
            HybridCertificate::Ed25519 { .. } => {
                panic!("no aggregate in the Ed25519 variant")
            }
        }
    }
}
