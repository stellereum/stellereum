//! VRF secret provisioning + registry loader (startup seam).
//!
//! What this pins:
//! * Precedence: `STELL_VRF_SECRET_FILE` (0600-checked) wins over
//!   `STELL_VRF_SECRET` (inline hex), which wins over the deterministic
//!   `BLAKE3("VRF_SUBSEED_V1" || ed_seed)` fallback; remote-signer
//!   deployments (no local seed, no explicit source) provision `None`
//!   (legacy fallback).
//! * Fall-through, never fatal: a broken explicit source (missing file, bad
//!   perms, bad hex, empty file) warns loudly and falls through to the next
//!   source instead of refusing startup.
//! * Determinism: the same ed seed derives the same VRF keypair twice
//!   (across restarts, no new secret to distribute).
//! * Registry hygiene: `parse_vrf_keys_config` skips garbage entries
//!   (malformed shape, bad hex, wrong lengths, non-curve vrf keys) loudly
//!   and keeps the valid ones; empty input stays empty.
//! * Readiness helper: `vrf_registry_ready_for_power` is true only when
//!   every nonzero-power validator has a registry key (advisory — no global
//!   height H is set anywhere).

use stellereum::vrf::{
    derive_vrf_secret_seed, load_vrf_secret_from_file, parse_vrf_keys_config,
    parse_vrf_secret_hex, provision_vrf_secret_seed, resolve_vrf_secret_seed,
    vrf_registered_power, vrf_registry_from_env, vrf_registry_ready_for_power, VrfRegistry,
    VrfSecret, VRF_SECRET_ENV, VRF_SECRET_FILE_ENV,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

// --- helpers ---------------------------------------------------------------

static TMP_CTR: AtomicU64 = AtomicU64::new(0);

fn tmp_path(tag: &str) -> PathBuf {
    let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "stell_vrf_prov_test_{}_{}_{}",
        std::process::id(),
        n,
        tag
    ))
}

fn write_secret_file(path: &std::path::Path, contents: &str, #[allow(unused_variables)] mode: u32) {
    std::fs::write(path, contents).expect("test secret file must be writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("test secret file perms must be settable");
    }
}

fn remove_quiet(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

const ED_A: [u8; 32] = [0xA1u8; 32];
const SECRET_FILE_HEX: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SECRET_ENV_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn secret_bytes(hex_str: &str) -> [u8; 32] {
    let v = hex::decode(hex_str).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// --- precedence matrix (pure core: no process-env races) --------------------

#[test]
fn file_wins_over_env_and_derived() {
    let p = tmp_path("filewins");
    write_secret_file(&p, &format!("{SECRET_FILE_HEX}\n"), 0o600);
    let got = resolve_vrf_secret_seed(
        Some(&ED_A),
        Some(p.to_str().unwrap()),
        Some(SECRET_ENV_HEX),
    );
    remove_quiet(&p);
    assert_eq!(got, Some(secret_bytes(SECRET_FILE_HEX)));
}

#[test]
fn env_wins_over_derived() {
    let got = resolve_vrf_secret_seed(Some(&ED_A), None, Some(SECRET_ENV_HEX));
    assert_eq!(got, Some(secret_bytes(SECRET_ENV_HEX)));
}

#[test]
fn derived_fallback_matches_subseed() {
    let got = resolve_vrf_secret_seed(Some(&ED_A), None, None);
    assert_eq!(got, Some(derive_vrf_secret_seed(&ED_A)));
    // Blank-but-set sources are treated as unset (whitespace-only file path
    // must not attempt IO, whitespace-only hex must not parse).
    let blank = resolve_vrf_secret_seed(Some(&ED_A), Some("   "), Some("  "));
    assert_eq!(blank, Some(derive_vrf_secret_seed(&ED_A)));
}

#[test]
fn remote_signer_without_sources_provisions_none() {
    // No local seed (remote signer) + no explicit source => None + loud
    // warn (legacy fallback). Must NOT derive from thin air.
    assert_eq!(resolve_vrf_secret_seed(None, None, None), None);
    assert_eq!(resolve_vrf_secret_seed(None, Some("   "), Some("")), None);
}

// --- fall-through (broken explicit source never kills startup) --------------

#[test]
fn garbage_inline_hex_falls_through_to_derived() {
    let got = resolve_vrf_secret_seed(Some(&ED_A), None, Some("not-hex!!"));
    assert_eq!(
        got,
        Some(derive_vrf_secret_seed(&ED_A)),
        "bad inline hex must fall through to the derived subseed"
    );
    let short = resolve_vrf_secret_seed(Some(&ED_A), None, Some("abcd"));
    assert_eq!(short, Some(derive_vrf_secret_seed(&ED_A)));
    // ... and to None when there is no local seed to derive from.
    assert_eq!(resolve_vrf_secret_seed(None, None, Some("not-hex!!")), None);
}

#[test]
fn missing_file_falls_through_to_env() {
    let missing = tmp_path("missing").join("does-not-exist.key");
    let got = resolve_vrf_secret_seed(
        Some(&ED_A),
        Some(missing.to_str().unwrap()),
        Some(SECRET_ENV_HEX),
    );
    assert_eq!(
        got,
        Some(secret_bytes(SECRET_ENV_HEX)),
        "missing file must fall through to the inline env source"
    );
    let derived = resolve_vrf_secret_seed(Some(&ED_A), Some(missing.to_str().unwrap()), None);
    assert_eq!(derived, Some(derive_vrf_secret_seed(&ED_A)));
}

#[test]
fn empty_file_falls_through_to_derived() {
    let p = tmp_path("empty");
    write_secret_file(&p, "  \n", 0o600);
    let got = resolve_vrf_secret_seed(Some(&ED_A), Some(p.to_str().unwrap()), None);
    remove_quiet(&p);
    assert_eq!(got, Some(derive_vrf_secret_seed(&ED_A)));
}

#[cfg(unix)]
#[test]
fn bad_perms_file_falls_through_to_env() {
    let p = tmp_path("badperms");
    write_secret_file(&p, &format!("{SECRET_FILE_HEX}\n"), 0o644);
    // Sanity: the loader itself refuses group/other-readable files.
    assert!(load_vrf_secret_from_file(&p).is_err());
    let got = resolve_vrf_secret_seed(
        Some(&ED_A),
        Some(p.to_str().unwrap()),
        Some(SECRET_ENV_HEX),
    );
    remove_quiet(&p);
    assert_eq!(
        got,
        Some(secret_bytes(SECRET_ENV_HEX)),
        "group-readable file must be refused and fall through to env"
    );
}

// --- hex parser matrix ------------------------------------------------------

#[test]
fn parse_vrf_secret_hex_matrix() {
    let want = secret_bytes(SECRET_FILE_HEX);
    // Optional 0x prefix + surrounding whitespace are accepted.
    assert_eq!(
        parse_vrf_secret_hex(&format!("  0x{SECRET_FILE_HEX}  \n")),
        Ok(want)
    );
    assert_eq!(parse_vrf_secret_hex(SECRET_FILE_HEX), Ok(want));
    // Bad hex / wrong length refuse.
    assert!(parse_vrf_secret_hex("not-hex!!").is_err());
    assert!(parse_vrf_secret_hex("abcd").is_err());
    assert!(parse_vrf_secret_hex("").is_err());
    assert!(parse_vrf_secret_hex(&format!("{SECRET_FILE_HEX}00")).is_err());
}

// --- determinism ------------------------------------------------------------

#[test]
fn same_ed_seed_derives_same_vrf_keypair_twice() {
    let s1 = derive_vrf_secret_seed(&ED_A);
    let s2 = derive_vrf_secret_seed(&ED_A);
    assert_eq!(s1, s2);
    let pk1 = VrfSecret::from_seed(&s1).public_key().to_bytes();
    let pk2 = VrfSecret::from_seed(&s2).public_key().to_bytes();
    assert_eq!(pk1, pk2, "same ed seed => same VRF pubkey, every restart");
    // A different ed seed derives a different VRF key.
    let other = VrfSecret::from_seed(&derive_vrf_secret_seed(&[0xB2u8; 32]))
        .public_key()
        .to_bytes();
    assert_ne!(pk1, other);
}

// --- registry garbage handling ----------------------------------------------

fn vrf_pk_hex(seed: &[u8; 32]) -> String {
    hex::encode(VrfSecret::from_seed(seed).public_key().to_bytes())
}

#[test]
fn registry_skips_garbage_loudly_keeps_valid() {
    let good_ed = hex::encode([0x11u8; 32]);
    let good_vrf = vrf_pk_hex(&[0x42u8; 32]);
    let raw = format!(
        "{good_ed}:{good_vrf},no-colon-here,zzzz:{good_vrf},\
         {good_ed}:abcd,{good_ed}:{},{}:{},{}:{}, : ,",
        hex::encode([0u8; 32]), // identity point: not a usable key
        hex::encode([0x22u8; 32]),
        "ff", // wrong length (1 byte)
        hex::encode([0x33u8; 32]),
        hex::encode([0x44u8; 31]), // wrong length (31 bytes)
    );
    let reg = parse_vrf_keys_config(&raw);
    assert_eq!(reg.len(), 1, "only the well-formed entry survives: {raw}");
    assert_eq!(
        reg.get(&[0x11u8; 32]),
        Some(secret_bytes(&good_vrf)),
        "the valid entry must be retrievable"
    );
}

#[test]
fn registry_empty_inputs_stay_empty() {
    assert!(parse_vrf_keys_config("").is_empty());
    assert!(parse_vrf_keys_config("   ").is_empty());
    assert!(parse_vrf_keys_config(",,,").is_empty());
}

// --- readiness helper --------------------------------------------------------

fn reg_with(ids: &[[u8; 32]]) -> VrfRegistry {
    let mut reg = VrfRegistry::new();
    for id in ids {
        let vrf_pk = VrfSecret::from_seed(id).public_key().to_bytes();
        assert!(
            reg.insert_config_key(*id, vrf_pk),
            "derived test key must be a valid curve point"
        );
    }
    reg
}

#[test]
fn readiness_all_power_registered_true() {
    let ids = [[0x01u8; 32], [0x02u8; 32]];
    let reg = reg_with(&ids);
    let power = vec![(ids[0], 10u64), (ids[1], 20u64)];
    assert!(vrf_registry_ready_for_power(&reg, &power));
    assert_eq!(vrf_registered_power(&reg, &power), (30, 30));
}

#[test]
fn readiness_missing_power_false() {
    let ids = [[0x01u8; 32], [0x02u8; 32]];
    let reg = reg_with(&ids[..1]);
    let power = vec![(ids[0], 10u64), (ids[1], 20u64)];
    assert!(
        !vrf_registry_ready_for_power(&reg, &power),
        "one unregistered validator vetoes readiness"
    );
    assert_eq!(vrf_registered_power(&reg, &power), (10, 30));
    // A fully-empty registry covers nothing.
    let empty = VrfRegistry::new();
    assert!(!vrf_registry_ready_for_power(&empty, &power));
    assert_eq!(vrf_registered_power(&empty, &power), (0, 30));
}

#[test]
fn readiness_zero_power_exempt_and_empty_ready() {
    let ids = [[0x01u8; 32], [0x02u8; 32]];
    let reg = reg_with(&ids[..1]);
    // Zero-power entries need no key (they elect nothing).
    let power = vec![(ids[0], 10u64), (ids[1], 0u64)];
    assert!(vrf_registry_ready_for_power(&reg, &power));
    assert_eq!(vrf_registered_power(&reg, &power), (10, 10));
    // No validators: nothing to cover.
    let empty_power: Vec<([u8; 32], u64)> = vec![];
    assert!(vrf_registry_ready_for_power(&VrfRegistry::new(), &empty_power));
    assert_eq!(
        vrf_registered_power(&VrfRegistry::new(), &empty_power),
        (0, 0)
    );
}

// --- live-env seam (serialized: process env is global) -----------------------

static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn live_env_provisioning_and_registry_loader() {
    let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let saved_secret = std::env::var(VRF_SECRET_ENV).ok();
    let saved_file = std::env::var(VRF_SECRET_FILE_ENV).ok();
    let saved_keys = std::env::var("STELL_VRF_KEYS").ok();
    std::env::remove_var(VRF_SECRET_ENV);
    std::env::remove_var(VRF_SECRET_FILE_ENV);
    std::env::remove_var("STELL_VRF_KEYS");

    // Inline env provisions the exact seed (remote-signer style: no ed seed).
    std::env::set_var(VRF_SECRET_ENV, SECRET_ENV_HEX);
    assert_eq!(
        provision_vrf_secret_seed(None),
        Some(secret_bytes(SECRET_ENV_HEX))
    );
    // Registry loader picks up operator config (garbage skipped).
    let good_ed = hex::encode([0x11u8; 32]);
    let good_vrf = vrf_pk_hex(&[0x42u8; 32]);
    std::env::set_var("STELL_VRF_KEYS", format!("{good_ed}:{good_vrf},junk"));
    let reg = vrf_registry_from_env();
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.get(&[0x11u8; 32]), Some(secret_bytes(&good_vrf)));
    // File wins over the inline env on the live path too.
    let p = tmp_path("livewins");
    write_secret_file(&p, &format!("{SECRET_FILE_HEX}\n"), 0o600);
    std::env::set_var(VRF_SECRET_FILE_ENV, p.to_str().unwrap());
    assert_eq!(
        provision_vrf_secret_seed(Some(&ED_A)),
        Some(secret_bytes(SECRET_FILE_HEX))
    );
    remove_quiet(&p);

    // Restore the ambient environment.
    std::env::remove_var(VRF_SECRET_ENV);
    std::env::remove_var(VRF_SECRET_FILE_ENV);
    std::env::remove_var("STELL_VRF_KEYS");
    if let Some(v) = saved_secret {
        std::env::set_var(VRF_SECRET_ENV, v);
    }
    if let Some(v) = saved_file {
        std::env::set_var(VRF_SECRET_FILE_ENV, v);
    }
    if let Some(v) = saved_keys {
        std::env::set_var("STELL_VRF_KEYS", v);
    }
}
