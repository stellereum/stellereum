//! BLS proof-of-possession: gated strict registry path (PLAN-POP phase 1).
//!
//! The live QC path is untouched here: the startup refusal
//! (`refuse_bls_qc_if_enabled`) keeps refusing `STELL_BLS_QC=1`, the default
//! (gate off) parses byte-identically through the v1 reader, and no quorum,
//! wire, or signature-scheme behavior changes. What this pins:
//! * a valid PoP accepts under the strict gate;
//! * a missing (legacy 2-token) or garbage PoP refuses under the strict gate;
//! * the rogue-key shape from PLAN-POP fails closed (a key without a valid
//!   PoP never enters the registry, so `canonical_keys` — and therefore any
//!   BLS power count — is unavailable for it);
//! * the default-off path still accepts the legacy registry (byte-identical).

use stellereum::bls::*;
use stellereum::consensus::ValidatorSet;

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

#[test]
fn pop_valid_accepts_under_strict_gate() {
    let sk = BlsSecretKey::from_seed(&[0x51u8; 32]);
    let id = ed(0x11);
    let text = pop_line(&id, &sk);

    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&text, &mut reg, &mut stats);

    assert_eq!(stats.pop_verified, 1, "valid PoP must be counted");
    assert_eq!(stats.rejected, 0);
    assert_eq!(stats.legacy, 0, "strict parse never counts legacy");
    let pk = reg.get(&id).expect("valid PoP entry must be registered");
    assert_eq!(*pk, sk.public_key());
    assert!(
        bls_verify_pop(pk, &id, &bls_sign_pop(&sk, &id)),
        "stored key must re-verify a fresh PoP for the same identity"
    );
}

#[test]
fn pop_missing_refused_under_strict_gate() {
    // A bare legacy 2-token entry carries no PoP: refused under the gate.
    let sk = BlsSecretKey::from_seed(&[0x52u8; 32]);
    let id = ed(0x22);
    let text = legacy_line(&id, &sk);

    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&text, &mut reg, &mut stats);

    assert_eq!(stats.pop_verified, 0);
    assert_eq!(stats.legacy, 0, "strict parse never counts legacy");
    assert_eq!(stats.rejected, 1, "missing PoP must be refused");
    assert!(!reg.contains_key(&id), "refused key must not register");

    // The lenient v2 reader still accepts the same line as legacy (that is
    // the phase-1 accept-new + emit-old posture the default path keeps).
    let mut reg_v2 = BlsKeyRegistry::new();
    let mut stats_v2 = BlsRegistryStats::default();
    parse_registry_entries_v2(&text, &mut reg_v2, &mut stats_v2);
    assert_eq!(stats_v2.legacy, 1);
    assert!(reg_v2.contains_key(&id));
}

#[test]
fn pop_garbage_refused_under_strict_gate() {
    let sk = BlsSecretKey::from_seed(&[0x53u8; 32]);
    let id = ed(0x33);
    let pk_hex = hex::encode(sk.public_key().to_bytes());
    let ed_hex = hex::encode(id);
    let good_pop_hex = hex::encode(bls_sign_pop(&sk, &id).to_bytes());

    // Each case is a single registry line whose third token (or binding) is
    // wrong in a different way. All must refuse under the strict gate.
    let forged = hex::encode(bls_sign_pop(&sk, &ed(0x99)).to_bytes());
    let cases: Vec<(&str, String)> = vec![
        ("non-hex pop", format!("{ed_hex} {pk_hex} zzzz")),
        ("short pop", format!("{ed_hex} {pk_hex} deadbeef")),
        (
            "random 96 bytes (off-curve)",
            format!("{ed_hex} {pk_hex} {}", hex::encode([0x77u8; 96])),
        ),
        (
            "forged pop (signed for another identity)",
            format!("{ed_hex} {pk_hex} {forged}"),
        ),
        ("wrong-key pop (valid sig, wrong registry key)", {
            let other = BlsSecretKey::from_seed(&[0x54u8; 32]);
            let other_pop = hex::encode(bls_sign_pop(&other, &id).to_bytes());
            format!("{ed_hex} {pk_hex} {other_pop}")
        }),
        ("message sig over a truncated preimage is not a PoP", {
            let msg_sig = sk.sign(&bls_pop_preimage(&id)[1..]);
            format!("{ed_hex} {pk_hex} {}", hex::encode(msg_sig.to_bytes()))
        }),
    ];

    for (name, line) in &cases {
        let mut reg = BlsKeyRegistry::new();
        let mut stats = BlsRegistryStats::default();
        parse_registry_entries_strict_pop(line, &mut reg, &mut stats);
        assert_eq!(stats.pop_verified, 0, "{name}: must not verify");
        assert_eq!(stats.rejected, 1, "{name}: must be refused");
        assert!(!reg.contains_key(&id), "{name}: must not register");
    }

    // Sanity: the well-formed line for the same key still accepts.
    let mut reg = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(
        &format!("{ed_hex} {pk_hex} {good_pop_hex}"),
        &mut reg,
        &mut stats,
    );
    assert_eq!(stats.pop_verified, 1);
    assert!(reg.contains_key(&id));
}

#[test]
fn rogue_key_scenario_fails_closed() {
    // PLAN-POP §1: without a PoP, an attacker registers a key crafted
    // against honest keys and forges same-message aggregates. The gate
    // answers at parse time: no valid PoP, no registry entry, no BLS power.
    let honest: Vec<BlsSecretKey> = (0..2)
        .map(|i| BlsSecretKey::from_seed(&[0x60u8 + i; 32]))
        .collect();
    let honest_ids = [ed(0xA1), ed(0xA2)];
    let rogue_sk = BlsSecretKey::from_seed(&[0xEBu8; 32]);
    let rogue_id = ed(0xB0);

    // The attacker cannot produce a PoP binding the rogue key to its claimed
    // identity (it splices a PoP minted for another identity instead).
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
    assert_eq!(stats.pop_verified, 2, "honest PoPs accept");
    assert_eq!(stats.rejected, 1, "rogue entry refuses");
    assert!(!reg.contains_key(&rogue_id));

    // The validator set containing the rogue identity cannot resolve BLS
    // keys at all: one missing member disables the path (fallback), exactly
    // the safe direction — power is never counted for the rogue.
    let vs_rogue =
        ValidatorSet::from_list(vec![(honest_ids[0], 1), (honest_ids[1], 1), (rogue_id, 1)]);
    let cfg = QcBlsConfig {
        enabled: true,
        registry: reg.clone(),
        local_vote_seed: None,
    };
    assert!(
        cfg.canonical_keys(&vs_rogue).is_none(),
        "a set containing the refused rogue must not resolve keys"
    );

    // The honest-only set still resolves, and its aggregate verifies —
    // gating removes the attacker, it does not break honest quorum math.
    let vs_honest = ValidatorSet::from_list(vec![(honest_ids[0], 1), (honest_ids[1], 1)]);
    let keys = cfg
        .canonical_keys(&vs_honest)
        .expect("honest set must resolve");
    let msg = b"rogue-fail-closed-probe";
    let sigs: Vec<(usize, BlsSignature)> = honest
        .iter()
        .enumerate()
        .map(|(i, k)| (i, k.sign(msg)))
        .collect();
    let agg = aggregate_signatures(&sigs, 2).expect("honest aggregate builds");
    assert!(verify_aggregate_signature(&keys, msg, &agg));

    // And the same aggregate bytes do NOT verify when measured against a key
    // list with the rogue substituted in (the forgery the PoP removes).
    let mut tampered = keys.clone();
    tampered[0] = rogue_sk.public_key();
    assert!(
        !verify_aggregate_signature(&tampered, msg, &agg),
        "aggregate must not verify under a substituted key"
    );
}

// Env-touching tests share one process-wide guard so parallel threads never
// observe each other's temporary `set_var`/`remove_var` windows.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

#[test]
fn default_off_path_still_accepts_legacy_registry() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[
        BLS_KEYS_FILE_ENV,
        BLS_KEYS_INLINE_ENV,
        BLS_POP_REQUIRED_ENV,
        BLS_QC_ENV,
    ]);

    // Two legacy 2-token lines on disk — the live registry shape.
    let sk_a = BlsSecretKey::from_seed(&[0x71u8; 32]);
    let sk_b = BlsSecretKey::from_seed(&[0x72u8; 32]);
    let (id_a, id_b) = (ed(0xC1), ed(0xC2));
    let body = format!(
        "{}\n{}\n",
        legacy_line(&id_a, &sk_a),
        legacy_line(&id_b, &sk_b)
    );
    let path = std::env::temp_dir().join(format!(
        "stell-bls-pop-{}-{}.reg",
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

    // Gate OFF (default): the pre-PoP v1 parse runs — legacy accepted.
    std::env::remove_var(BLS_POP_REQUIRED_ENV);
    assert!(!bls_pop_required(), "the PoP gate defaults OFF");
    let off = QcBlsConfig::from_env();
    assert_eq!(
        off.registry.len(),
        2,
        "default-off must keep legacy entries"
    );
    assert!(off.registry.contains_key(&id_a));
    assert!(off.registry.contains_key(&id_b));

    // Gate ON: the same bytes refuse every legacy line — nothing registers.
    std::env::set_var(BLS_POP_REQUIRED_ENV, "1");
    assert!(bls_pop_required());
    let on = QcBlsConfig::from_env();
    assert!(
        on.registry.is_empty(),
        "strict gate must refuse keys without a valid PoP"
    );

    // Explicitly-off spellings stay off.
    for off_spelling in ["0", "false", "no", ""] {
        std::env::set_var(BLS_POP_REQUIRED_ENV, off_spelling);
        assert!(!bls_pop_required(), "{off_spelling:?} must mean OFF");
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn bls_qc_startup_refusal_is_unchanged() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[BLS_QC_ENV]);

    // Default (unset): no refusal — the Ed25519 baseline starts as before.
    std::env::remove_var(BLS_QC_ENV);
    assert!(refuse_bls_qc_if_enabled().is_ok());

    // Enabled still hard-refuses: counting BLS power stays unsound until a
    // PoP-carrying registry lands. This test FAILS if anyone enables the
    // path instead of gating it.
    for on_spelling in ["1", "true", "TRUE", "on", "ON"] {
        std::env::set_var(BLS_QC_ENV, on_spelling);
        let err = refuse_bls_qc_if_enabled()
            .expect_err(&format!("{on_spelling:?} must still be refused at startup"));
        assert!(
            err.contains("proof-of-possession") || err.contains("PoP"),
            "refusal must name the missing PoP: {err}"
        );
    }

    // Anything else stays OFF (and therefore unrefused).
    for off_spelling in ["0", "false", "yes", ""] {
        std::env::set_var(BLS_QC_ENV, off_spelling);
        assert!(
            refuse_bls_qc_if_enabled().is_ok(),
            "{off_spelling:?} must mean OFF"
        );
    }
}

// ---- Phase 2 API: PoP-bound registration + aggregate-verify ----------------
//
// These pin the new `src/bls.rs` surface (`BlsRegistration`, `BlsRegistry`,
// `aggregate_verify`, `BlsRegistry::verify_aggregate_qc`) WITHOUT touching
// consensus counting: every assertion here calls the new API directly, and
// the startup refusal above still holds.

#[test]
fn registration_carries_live_pop_and_refuses_forgeries() {
    let sk = BlsSecretKey::from_seed(&[0x51u8; 32]);
    let other_sk = BlsSecretKey::from_seed(&[0x52u8; 32]);
    let id = ed(0x11);
    let good_pop = bls_sign_pop(&sk, &id);

    // Happy: minted registration verifies, and `from_parts` accepts the same
    // material back.
    let reg = BlsRegistration::register(&sk, &id);
    assert!(reg.verify_pop(), "freshly minted PoP must verify");
    assert_eq!(reg.public_key(), sk.public_key());
    assert_eq!(*reg.ed_id(), id);
    assert!(
        BlsRegistration::from_parts(&id, Some(sk.public_key().to_bytes()), Some(good_pop.to_bytes()))
            .is_some(),
        "well-formed (pk, pop) must construct"
    );

    // Missing PoP refuses (no "register now, prove later" state).
    assert!(
        BlsRegistration::from_parts(&id, Some(sk.public_key().to_bytes()), None).is_none(),
        "missing PoP must refuse"
    );
    // Missing key refuses.
    assert!(
        BlsRegistration::from_parts(&id, None, Some(good_pop.to_bytes())).is_none(),
        "missing key must refuse"
    );

    // Wrong sk: a PoP minted by another secret refuses against this key.
    let wrong_sk_pop = bls_sign_pop(&other_sk, &id);
    assert!(
        BlsRegistration::from_parts(
            &id,
            Some(sk.public_key().to_bytes()),
            Some(wrong_sk_pop.to_bytes())
        )
        .is_none(),
        "PoP from the wrong secret must refuse"
    );

    // Tampered pk: a flipped byte refuses — whether the bytes fall off the
    // curve (parse refusal) or land on another point (verify refusal), the
    // outcome is `None` either way.
    let mut tampered = sk.public_key().to_bytes();
    tampered[0] ^= 0xFF;
    assert!(
        BlsRegistration::from_parts(&id, Some(tampered), Some(good_pop.to_bytes())).is_none(),
        "tampered pk must refuse"
    );

    // Replayed pop on a different pk: the PoP is key-bound, so a valid PoP
    // for `other_sk` refuses when presented under `sk`'s key...
    let other_pk = other_sk.public_key();
    let pop_for_other = bls_sign_pop(&other_sk, &id);
    assert!(
        BlsRegistration::from_parts(
            &id,
            Some(other_pk.to_bytes()),
            Some(pop_for_other.to_bytes())
        )
        .is_some(),
        "sanity: the replayed PoP is valid for its own pair"
    );
    assert!(
        BlsRegistration::from_parts(
            &id,
            Some(sk.public_key().to_bytes()),
            Some(pop_for_other.to_bytes())
        )
        .is_none(),
        "replayed PoP on a different pk must refuse"
    );

    // Registry admission mirrors construction: admits good, refuses bad.
    let mut reg_store = BlsRegistry::new();
    assert!(reg_store.is_empty());
    assert!(reg_store.insert(&reg), "valid registration must admit");
    assert!(reg_store.contains(&id));
    assert_eq!(reg_store.len(), 1);
    assert_eq!(reg_store.get(&id), Some(sk.public_key()));
    assert!(
        !reg_store.insert_verified(&id, &sk.public_key(), &wrong_sk_pop),
        "registry must refuse a spliced (pk, pop) pair"
    );
    assert_eq!(reg_store.len(), 1, "refusal must leave the registry unchanged");
}

#[test]
fn aggregate_verify_happy_path_and_qc_wrapper() {
    let sks: Vec<BlsSecretKey> = (0u8..5u8).map(|i| BlsSecretKey::from_seed(&[i; 32])).collect();
    let pks: Vec<BlsPublicKey> = sks.iter().map(|k| k.public_key()).collect();
    let msg = b"qc-aggregate-happy";
    let sigs: Vec<(usize, BlsSignature)> =
        sks.iter().enumerate().map(|(i, k)| (i, k.sign(msg))).collect();
    let agg = aggregate_signatures(&sigs, sks.len()).expect("honest aggregate builds");

    // Raw primitive: verifies for the exact signer set and message.
    assert!(aggregate_verify(&pks, msg, &agg.signature));
    // Wrong message refuses.
    assert!(!aggregate_verify(&pks, b"tampered message", &agg.signature));
    // A different key list (subset) refuses: the pairing binds the sum.
    assert!(!aggregate_verify(&pks[..4], msg, &agg.signature));

    // Registry-gated QC wrapper: honest set verifies through admitted keys.
    let mut reg = BlsRegistry::new();
    for (i, sk) in sks.iter().enumerate() {
        assert!(reg.insert(&BlsRegistration::register(sk, &ed(i as u8))));
    }
    let ids: Vec<[u8; 32]> = (0u8..5u8).map(ed).collect();
    assert!(reg.verify_aggregate_qc(&ids, msg, &agg.signature));
    // Unknown id refuses (missing member, no guessing).
    assert!(!reg.verify_aggregate_qc(&[[0xFFu8; 32]], msg, &agg.signature));
    // Duplicate id refuses (one validator's power must never count twice).
    let mut dup = ids.clone();
    dup[0] = dup[1];
    assert!(!reg.verify_aggregate_qc(&dup, msg, &agg.signature));
    // Empty signer set refuses (no vacuous truth).
    assert!(!reg.verify_aggregate_qc(&[], msg, &agg.signature));
    assert!(reg.keys_for(&[]).is_none());
}

#[test]
fn rogue_key_attack_fails_against_pop_gated_api() {
    // Cancellation forgery (the textbook rogue-key attack): with honest keys
    // pk1, pk2 and the attacker's own secret t, register
    // pk_rogue = t*G - pk1 - pk2. Then the attacker's lone signature
    // sigma = t*H(m), claimed as "all three signed m", satisfies
    // e(G, sigma) == e(pk1 + pk2 + pk_rogue, H(m)) because the key sum is t*G.
    use bls12_381::{G1Affine, G1Projective};

    fn proj(pk: &BlsPublicKey) -> G1Projective {
        let aff: Option<G1Affine> = Option::from(G1Affine::from_compressed(&pk.to_bytes()));
        G1Projective::from(aff.expect("honest key must decompress"))
    }

    let sk1 = BlsSecretKey::from_seed(&[0xA1u8; 32]);
    let sk2 = BlsSecretKey::from_seed(&[0xA2u8; 32]);
    let rogue_sk = BlsSecretKey::from_seed(&[0xADu8; 32]);
    let (pk1, pk2) = (sk1.public_key(), sk2.public_key());
    let (id1, id2, rogue_id) = (ed(0x11), ed(0x12), ed(0x99));

    let rogue_pt = proj(&rogue_sk.public_key()) - proj(&pk1) - proj(&pk2);
    let rogue_pk = BlsPublicKey::from_bytes(&G1Affine::from(rogue_pt).to_compressed())
        .expect("cancellation key must be a valid non-identity point");

    let msg = b"rogue-key-forgery-probe";
    let forged = rogue_sk.sign(msg);
    // Sanity: the raw pairing check ALONE cannot see the fraud — this is the
    // attack working, and exactly why registration must gate rogue keys out.
    assert!(
        aggregate_verify(&[pk1, pk2, rogue_pk], msg, &forged),
        "sanity: the cancellation forgery defeats the raw pairing check"
    );

    // The PoP gate defeats it: a PoP for pk_rogue needs its discrete log
    // (t - sk1 - sk2), which the attacker does not know. The best forgery —
    // the attacker's own signature over the rogue preimage — refuses.
    let forged_pop = bls_sign_pop(&rogue_sk, &rogue_id);
    assert!(!bls_verify_pop(&rogue_pk, &rogue_id, &forged_pop));
    assert!(
        BlsRegistration::from_parts(
            &rogue_id,
            Some(rogue_pk.to_bytes()),
            Some(forged_pop.to_bytes())
        )
        .is_none(),
        "rogue key must not construct a registration"
    );
    let mut reg = BlsRegistry::new();
    assert!(
        !reg.insert_verified(&rogue_id, &rogue_pk, &forged_pop),
        "rogue key must not enter the registry"
    );
    assert!(!reg.contains(&rogue_id));

    // Honest validators register fine...
    assert!(reg.insert(&BlsRegistration::register(&sk1, &id1)));
    assert!(reg.insert(&BlsRegistration::register(&sk2, &id2)));

    // ...but any set containing the rogue never resolves: QC verify refuses
    // (missing member => no BLS power counted, the safe direction).
    assert!(reg.keys_for(&[id1, id2, rogue_id]).is_none());
    assert!(!reg.verify_aggregate_qc(&[id1, id2, rogue_id], msg, &forged));

    // And the honest-only QC still verifies through the gated API — gating
    // removes the attacker without breaking honest quorum math.
    let honest_sigs: Vec<(usize, BlsSignature)> =
        [&sk1, &sk2].iter().enumerate().map(|(i, k)| (i, k.sign(msg))).collect();
    let honest_agg = aggregate_signatures(&honest_sigs, 2).expect("honest aggregate builds");
    assert!(reg.verify_aggregate_qc(&[id1, id2], msg, &honest_agg.signature));
}

#[test]
fn aggregate_verify_empty_and_overcap_fail_closed() {
    let sk = BlsSecretKey::from_seed(&[0xD0u8; 32]);
    let sig = sk.sign(b"m");

    // Empty key list refuses: no vacuous truth, no identity bypass.
    assert!(!aggregate_verify(&[], b"m", &sig));
    assert!(BlsRegistry::new().keys_for(&[]).is_none());

    // Over-cap refuses BEFORE any pairing work (DoS bound).
    let too_many = vec![sk.public_key(); MAX_BLS_AGGREGATE_KEYS + 1];
    assert!(
        !aggregate_verify(&too_many, b"m", &sig),
        "over-cap key list must refuse"
    );
    assert!(
        BlsRegistry::new()
            .keys_for(&vec![[0x01u8; 32]; MAX_BLS_AGGREGATE_KEYS + 1])
            .is_none(),
        "over-cap id list must not resolve"
    );

    // At-cap still verifies: the cap is a bound, not a ban. (4096 keygens +
    // signs + one pairing; deterministic seeds, no OsRng.)
    let many_sks: Vec<BlsSecretKey> = (0..MAX_BLS_AGGREGATE_KEYS)
        .map(|i| {
            let mut seed = [0xE0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            BlsSecretKey::from_seed(&seed)
        })
        .collect();
    let many_pks: Vec<BlsPublicKey> = many_sks.iter().map(|k| k.public_key()).collect();
    let many_sigs: Vec<(usize, BlsSignature)> = many_sks
        .iter()
        .enumerate()
        .map(|(i, k)| (i, k.sign(b"cap")))
        .collect();
    let many_agg =
        aggregate_signatures(&many_sigs, MAX_BLS_AGGREGATE_KEYS).expect("at-cap aggregate builds");
    assert!(aggregate_verify(&many_pks, b"cap", &many_agg.signature));
    assert!(
        !aggregate_verify(&many_pks, b"other", &many_agg.signature),
        "at-cap aggregate must still bind the message"
    );
}
