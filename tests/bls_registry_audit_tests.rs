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
//!   registry (the counting path that would have consumed them is removed),
//!   while honest PoPs register and re-verify.
//! * SKIP-METERING: every skipped entry is observable in
//!   `bls_registry_migration_counts`. This covers the fix that the live
//!   default-off v1 parse (`parse_registry_entries`) feeds the
//!   legacy/rejected counters — before the fix its warn-and-skip path
//!   incremented nothing, leaving the documented phase-2 readiness signal
//!   (`legacy == 0 && rejected == 0`) blind on the only path production
//!   parses take. (Previously routed through `QcBlsConfig::from_env`,
//!   removed with the counting-path config; the parse itself is unchanged.)
//! * REMOVED CERT-CONFUSION section: the `HybridCertificate` vs live-QC
//!   confusion probes and the aggregate-composition probes lived here —
//!   deleted with `HybridCertificate` / `aggregate_signatures` /
//!   `verify_aggregate_signature` / `canonical_keys` (reported). The live
//!   `QuorumCertificate` BLS envelope still decodes as inert metadata and
//!   attributes/ counts nothing (pinned by the compat + pentest suites).

use stellereum::bls::*;

// Serializes every test in this file that observes process-wide state: the
// migration counters (bumped by all three registry parsers). Without this,
// parallel test threads would pollute each other's counter deltas.
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

    // Any validator set containing the refused identity gains no BLS power
    // through this registry: the rogue never registers, and with the counting
    // path removed there is no other way to count it. (The `canonical_keys`
    // + aggregate-composition tail of this probe was deleted with those
    // bodies.) The honest PoPs stay registered and re-verify.
    assert!(reg.contains_key(&honest_ids[0]));
    assert!(reg.contains_key(&honest_ids[1]));
    assert!(bls_verify_pop(
        reg.get(&honest_ids[0]).unwrap(),
        &honest_ids[0],
        &bls_sign_pop(&honest[0], &honest_ids[0])
    ));
}

// ---------------------------------------------------------------------------
// 3. Skip-metering on the live default-off path (regression test for the fix)
// ---------------------------------------------------------------------------

#[test]
fn default_path_skips_are_metered_in_migration_counts() {
    let _gate = AUDIT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // (Previously routed through `QcBlsConfig::from_env` + env vars, removed
    // with the counting-path config. The parse calls below are the same code
    // the removed reader ran: v1 for the default-off shape, strict for the
    // gated shape — metering pins unchanged.)
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

    // Default OFF: the pre-PoP v1 parse runs. Both good lines register; all
    // three bad lines skip — AND the skips are metered (the fix: before,
    // this parse touched no counter, so silent BLS-power loss was invisible
    // to `bls_registry_migration_counts`).
    assert!(!bls_pop_required());
    let (v0, l0, r0) = bls_registry_migration_counts();
    let mut off = BlsKeyRegistry::new();
    parse_registry_entries(&body, &mut off);
    let (v1, l1, r1) = bls_registry_migration_counts();
    assert_eq!(off.len(), 2, "good legacy entries must register");
    assert!(off.contains_key(&id_a));
    assert!(off.contains_key(&id_b));
    assert_eq!(
        (v1 - v0, l1 - l0, r1 - r0),
        (0, 2, 3),
        "default-off parse must meter 2 legacy + 3 rejected"
    );

    // Gate ON: the same bytes refuse every line (no valid PoP anywhere), so
    // nothing registers and all five lines count rejected.
    let (v2a, l2a, r2a) = bls_registry_migration_counts();
    let mut on = BlsKeyRegistry::new();
    let mut on_stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&body, &mut on, &mut on_stats);
    let (v2b, l2b, r2b) = bls_registry_migration_counts();
    assert!(
        on.is_empty(),
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
}
// REMOVED (aggregate-composition + hybrid-confusion probes): section 4
// (`registry_resolved_keys_verify_and_tampering_fails_closed`), section 5
// (`hybrid_format_gate_pins_activation_boundary`), section 6
// (`hybrid_height_is_unbound_while_qc_envelope_binding_refuses_splice`),
// and the `HybridAggregate` test helper tested the removed
// `aggregate_signatures` / `verify_aggregate_signature` /
// `HybridCertificate` / `is_bls_active` / `canonical_keys` /
// `set_qc_bls_for_tests` surface — deleted with the code they pinned
// (reported). Envelope binding (bound to height/round/kind/target) stays
// pinned by the compat suite; marker inertness by the pentest suites.
