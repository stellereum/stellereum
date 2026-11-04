//! BLS proof-of-possession: gated strict registry path (PLAN-POP phase 1).
//!
//! The live QC path is untouched here: the startup refusal
//! (`refuse_bls_qc_if_enabled`) keeps refusing `STELL_BLS_QC=1`, the default
//! (gate off) parses byte-identically through the v1 reader, and no quorum,
//! wire, or signature-scheme behavior changes. What this pins:
//! * a valid PoP accepts under the strict gate;
//! * a missing (legacy 2-token) or garbage PoP refuses under the strict gate;
//! * the rogue-key shape from PLAN-POP fails closed (a key without a valid
//!   PoP never enters the registry, and the aggregate-counting path that
//!   would have counted it is removed — power for a rogue is unavailable.
//! * the default-off path still accepts the legacy registry (byte-identical).

use stellereum::bls::*;

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

    // The validator set containing the rogue identity cannot gain BLS power
    // through this registry: the rogue never registers, and with the
    // counting path removed there is no other way to count it. (The
    // `canonical_keys` + aggregate tail of this probe was deleted with those
    // bodies.) The honest keys stay registered and re-verify their PoPs.
    assert!(reg.contains_key(&honest_ids[0]));
    assert!(reg.contains_key(&honest_ids[1]));
    assert!(bls_verify_pop(
        reg.get(&honest_ids[0]).unwrap(),
        &honest_ids[0],
        &bls_sign_pop(&honest[0], &honest_ids[0])
    ));
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
    // The live registry shape (bare 2-token lines) parses through the v1
    // reader with no PoP gate: legacy accepted. Under the strict gate the
    // same bytes refuse (no valid PoP anywhere). (Previously routed through
    // `QcBlsConfig::from_env`, removed with the counting-path config.)
    let sk_a = BlsSecretKey::from_seed(&[0x71u8; 32]);
    let sk_b = BlsSecretKey::from_seed(&[0x72u8; 32]);
    let (id_a, id_b) = (ed(0xC1), ed(0xC2));
    let body = format!("{}\n{}\n", legacy_line(&id_a, &sk_a), legacy_line(&id_b, &sk_b));

    // Gate OFF (default): the pre-PoP v1 parse runs — legacy accepted.
    assert!(!bls_pop_required(), "the PoP gate defaults OFF");
    let mut off = BlsKeyRegistry::new();
    parse_registry_entries(&body, &mut off);
    assert_eq!(off.len(), 2, "default-off must keep legacy entries");
    assert!(off.contains_key(&id_a));
    assert!(off.contains_key(&id_b));

    // Gate ON: the same bytes refuse every legacy line — nothing registers.
    let mut on = BlsKeyRegistry::new();
    let mut stats = BlsRegistryStats::default();
    parse_registry_entries_strict_pop(&body, &mut on, &mut stats);
    assert!(on.is_empty(), "strict gate must refuse keys without a valid PoP");
    assert_eq!(stats.rejected, 2);
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

// REMOVED (Phase-2 future-counting API tests):
// `registration_carries_live_pop_and_refuses_forgeries`,
// `aggregate_verify_happy_path_and_qc_wrapper`,
// `rogue_key_attack_fails_against_pop_gated_api`, and
// `aggregate_verify_empty_and_overcap_fail_closed` tested the removed
// `BlsRegistration` / `BlsRegistry` / `aggregate_verify` /
// `MAX_BLS_AGGREGATE_KEYS` surface — deleted with the code they pinned
// (reported). Rogue-key resistance stays pinned at parse time above.
