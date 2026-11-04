//! Startup guards (fail-closed, loud): tasks (a) (b) (c).
//!
//! * (a) fresh/empty data dir + peers/DNS seeds configured (JOIN intent) must
//!   REFUSE to mint a new genesis unless `STELL_NEW_CHAIN=1`.
//! * (b) faucet SERVING key loads from `STELL_FAUCET_KEY_FILE` (0600-checked,
//!   zeroized) — inline `STELL_FAUCET_KEY` alone leaves serving DISABLED
//!   (genesis-funding only); the well-known public test key (`0x11..11`) is
//!   refused unless `STELL_DEV_UNSAFE_TESTKEY=1`.
//! * (c) chain id reads `STELL_CHAIN_ID` (default 5757) and a peer reporting a
//!   different id aborts loudly (no silent partition).
//!
//! Env vars and the peer-chain sighting are process-global, so every test here
//! serializes on one mutex and restores the environment on drop.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

const TRACKED_VARS: &[&str] = &[
    "STELL_NEW_CHAIN",
    "STELL_CHAIN_ID",
    "STELL_FAUCET_KEY",
    "STELL_FAUCET_KEY_FILE",
    "STELL_DEV_UNSAFE_TESTKEY",
];

struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn lock() -> Self {
        let lock = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let saved = TRACKED_VARS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        // Start clean: no test inherits ambient config.
        for k in TRACKED_VARS {
            std::env::remove_var(k);
        }
        // Peer-chain sighting is global too; reset it while serialized.
        stellereum::rpc::PEER_CHAIN_ID.store(0, std::sync::atomic::Ordering::Relaxed);
        stellereum::rpc::PEER_CHAIN_ID_AT.store(0, std::sync::atomic::Ordering::Relaxed);
        Self { saved, _lock: lock }
    }

    fn set(&self, k: &str, v: &str) {
        std::env::set_var(k, v);
    }

    fn remove(&self, k: &str) {
        std::env::remove_var(k);
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(s) => std::env::set_var(k, s),
                None => std::env::remove_var(k),
            }
        }
        stellereum::rpc::PEER_CHAIN_ID.store(0, std::sync::atomic::Ordering::Relaxed);
        stellereum::rpc::PEER_CHAIN_ID_AT.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

static TMP_CTR: AtomicU64 = AtomicU64::new(0);

fn tmp_path(tag: &str) -> PathBuf {
    let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "stell_startup_guards_{}_{}_{}",
        std::process::id(),
        tag,
        n
    ))
}

fn write_key_file(path: &std::path::Path, contents: &str, mode: u32) {
    std::fs::write(path, contents).expect("write temp key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("chmod temp key file");
    }
}

const GOOD_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2d4449c5697b326597703fae7a3c8a354c70";
const TEST_SEED_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

// ==================== (a) fresh-join guard ====================

#[test]
fn new_chain_flag_parses_strictly() {
    let _g = EnvGuard::lock();
    assert!(stellereum::bootstrap::is_new_chain_explicit(Some("1")));
    assert!(stellereum::bootstrap::is_new_chain_explicit(Some("true")));
    assert!(stellereum::bootstrap::is_new_chain_explicit(Some("TRUE")));
    assert!(!stellereum::bootstrap::is_new_chain_explicit(None));
    assert!(!stellereum::bootstrap::is_new_chain_explicit(Some("0")));
    assert!(!stellereum::bootstrap::is_new_chain_explicit(Some("yes")));
    assert!(!stellereum::bootstrap::is_new_chain_explicit(Some("")));
}

#[test]
fn fresh_join_guard_refuses_silent_fork_but_allows_restart_founding_and_opt_in() {
    let _g = EnvGuard::lock();
    use stellereum::bootstrap::guard_fresh_data_dir;
    // Dirty dir = restart: owned by the genesis-fingerprint guard, not this gate.
    assert!(guard_fresh_data_dir(false, true, false).is_ok());
    assert!(guard_fresh_data_dir(false, false, false).is_ok());
    // Clean dir, nobody to join: genuine founding.
    assert!(guard_fresh_data_dir(true, false, false).is_ok());
    // Clean dir + peers + explicit opt-in: confirmed founding.
    assert!(guard_fresh_data_dir(true, true, true).is_ok());
    // Clean dir + peers, no opt-in: REFUSE (would fork silently).
    let err = guard_fresh_data_dir(true, true, false).expect_err("must refuse a silent fork");
    assert!(err.contains("REFUSING"), "loud: {err}");
    assert!(
        err.contains("STELL_NEW_CHAIN=1"),
        "must name the exact recovery flag: {err}"
    );
    assert!(
        err.contains("node-bootstrap"),
        "must give the exact recovery command: {err}"
    );
}

#[test]
fn fresh_join_refusal_message_names_recovery() {
    let _g = EnvGuard::lock();
    let msg = stellereum::bootstrap::fresh_join_refusal_message();
    assert!(msg.contains("REFUSING"));
    assert!(msg.contains("STELL_NEW_CHAIN=1"));
    assert!(msg.contains("node-bootstrap"));
}

#[test]
fn fresh_join_guard_from_env_reads_the_flag() {
    let g = EnvGuard::lock();
    use stellereum::bootstrap::guard_fresh_data_dir_from_env;
    // No flag: refuse the join-shaped fresh start.
    assert!(guard_fresh_data_dir_from_env(true, true).is_err());
    // Flag set: allow.
    g.set("STELL_NEW_CHAIN", "1");
    assert!(guard_fresh_data_dir_from_env(true, true).is_ok());
    // Flag set to junk: still refuse (fail-closed).
    g.set("STELL_NEW_CHAIN", "yes");
    assert!(guard_fresh_data_dir_from_env(true, true).is_err());
    g.remove("STELL_NEW_CHAIN");
    // Non-fresh shapes never refuse regardless of the flag.
    assert!(guard_fresh_data_dir_from_env(false, true).is_ok());
    assert!(guard_fresh_data_dir_from_env(true, false).is_ok());
}

#[test]
fn missing_data_dir_counts_as_fresh_clean() {
    let _g = EnvGuard::lock();
    let missing = tmp_path("missing").join("nope").join("nothing");
    assert!(!missing.exists());
    assert!(
        stellereum::bootstrap::data_dir_is_clean_fs(&missing),
        "a missing dir is a fresh machine, i.e. clean"
    );
    // ... and therefore guarded on the join path.
    assert!(stellereum::bootstrap::guard_fresh_data_dir(true, true, false).is_err());
}

#[test]
fn dirty_data_dir_counts_as_not_clean() {
    let _g = EnvGuard::lock();
    let dir = tmp_path("dirty");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(stellereum::bootstrap::data_dir_is_clean_fs(&dir));
    std::fs::write(dir.join("store"), b"x").unwrap();
    assert!(!stellereum::bootstrap::data_dir_is_clean_fs(&dir));
    std::fs::remove_dir_all(&dir).ok();
}

// ==================== (b) faucet key ====================

#[test]
fn faucet_seed_hex_parses_and_rejects() {
    let _g = EnvGuard::lock();
    use stellereum::rpc::parse_faucet_seed_hex;
    let seed = parse_faucet_seed_hex(GOOD_SEED_HEX).expect("valid hex");
    assert_eq!(hex::encode(seed), GOOD_SEED_HEX);
    // 0x prefix + surrounding whitespace are accepted.
    let prefixed = parse_faucet_seed_hex(&format!("  0x{GOOD_SEED_HEX}\n")).expect("0x hex");
    assert_eq!(prefixed, seed);
    // Garbage fails closed.
    assert!(parse_faucet_seed_hex("zzzz").is_err());
    assert!(
        parse_faucet_seed_hex("abcd").is_err(),
        "wrong length must fail"
    );
    assert!(parse_faucet_seed_hex("").is_err());
}

#[test]
fn test_key_is_recognised() {
    let _g = EnvGuard::lock();
    let test_seed = [0x11u8; 32];
    assert!(stellereum::rpc::is_test_key_seed(&test_seed));
    assert_eq!(stellereum::rpc::TEST_FAUCET_SEED, test_seed);
    assert!(!stellereum::rpc::is_test_key_seed(&[0x12u8; 32]));
}

#[test]
fn dev_unsafe_testkey_flag_parses_strictly() {
    let _g = EnvGuard::lock();
    assert!(stellereum::rpc::is_dev_unsafe_testkey(Some("1")));
    assert!(stellereum::rpc::is_dev_unsafe_testkey(Some("true")));
    assert!(stellereum::rpc::is_dev_unsafe_testkey(Some("TRUE")));
    assert!(!stellereum::rpc::is_dev_unsafe_testkey(None));
    assert!(!stellereum::rpc::is_dev_unsafe_testkey(Some("0")));
    assert!(!stellereum::rpc::is_dev_unsafe_testkey(Some("yes")));
}

#[test]
fn faucet_refuses_public_test_key_unless_dev_override() {
    let g = EnvGuard::lock();
    use stellereum::rpc::check_faucet_seed_allows_startup;
    let test_seed = [0x11u8; 32];
    // No override: loud refusal naming the exact unsafe flag.
    let err = check_faucet_seed_allows_startup(&test_seed).expect_err("test key must be refused");
    assert!(err.contains("REFUSING"), "loud: {err}");
    assert!(
        err.contains("STELL_DEV_UNSAFE_TESTKEY"),
        "must name the override: {err}"
    );
    // Dev override: allowed.
    g.set("STELL_DEV_UNSAFE_TESTKEY", "1");
    assert!(check_faucet_seed_allows_startup(&test_seed).is_ok());
    g.remove("STELL_DEV_UNSAFE_TESTKEY");
    // A real key never needs the override.
    let real = stellereum::rpc::parse_faucet_seed_hex(GOOD_SEED_HEX).unwrap();
    assert!(check_faucet_seed_allows_startup(&real).is_ok());
}

#[test]
fn faucet_key_file_loads_when_0600_and_refuses_otherwise() {
    let _g = EnvGuard::lock();
    use stellereum::rpc::load_faucet_seed_from_file;
    // 0600 file loads.
    let ok_path = tmp_path("faucet0600");
    write_key_file(&ok_path, &format!("{GOOD_SEED_HEX}\n"), 0o600);
    let seed = load_faucet_seed_from_file(&ok_path).expect("0600 file must load");
    assert_eq!(hex::encode(seed), GOOD_SEED_HEX);
    // Group-readable file is refused (fail-closed).
    let bad_path = tmp_path("faucet0640");
    write_key_file(&bad_path, &format!("{GOOD_SEED_HEX}\n"), 0o640);
    #[cfg(unix)]
    {
        let err = load_faucet_seed_from_file(&bad_path).expect_err("0640 must be refused");
        assert!(
            err.contains("0600") || err.contains("permissions"),
            "loud perms error: {err}"
        );
    }
    // Empty file is refused.
    let empty_path = tmp_path("faucetempty");
    write_key_file(&empty_path, "\n", 0o600);
    assert!(load_faucet_seed_from_file(&empty_path).is_err());
    // Bad hex is refused.
    let badhex_path = tmp_path("faucetbadhex");
    write_key_file(&badhex_path, "not-hex\n", 0o600);
    assert!(load_faucet_seed_from_file(&badhex_path).is_err());
    // Missing file is refused.
    assert!(load_faucet_seed_from_file(&tmp_path("missing").join("k")).is_err());
    for p in [&ok_path, &bad_path, &empty_path, &badhex_path] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn faucet_key_file_wins_over_inline_env() {
    let g = EnvGuard::lock();
    let path = tmp_path("faucetpref");
    write_key_file(&path, GOOD_SEED_HEX, 0o600);
    g.set("STELL_FAUCET_KEY_FILE", path.to_str().unwrap());
    g.set("STELL_FAUCET_KEY", TEST_SEED_HEX);
    // File wins: the inline test key must NOT leak in.
    let seed = stellereum::rpc::load_faucet_seed().expect("file source must load");
    assert_eq!(hex::encode(seed), GOOD_SEED_HEX);
    std::fs::remove_file(&path).ok();
}

#[test]
fn faucet_load_is_fail_closed_end_to_end() {
    // GATE (LEAD b: serving requires STELL_FAUCET_KEY_FILE — inline alone
    // leaves the faucet DISABLED fail-closed): file-real loads; neither
    // source refuses; inline-real without the file refuses (file required);
    // file-test-key refuses without the dev override and loads with it.
    // No assert weakened — every refusal still names its exact cause.
    let g = EnvGuard::lock();
    // Neither source: loud refusal, and the optional variant reports absence.
    assert!(stellereum::rpc::load_faucet_seed().is_err());
    assert_eq!(stellereum::rpc::try_load_faucet_seed_opt().unwrap(), None);
    assert!(!stellereum::rpc::faucet_key_present_from_env());
    // File with a real key: loads, presence reported.
    let path = tmp_path("faucetreal");
    write_key_file(&path, GOOD_SEED_HEX, 0o600);
    g.set("STELL_FAUCET_KEY_FILE", path.to_str().unwrap());
    assert!(stellereum::rpc::faucet_key_present_from_env());
    let seed = stellereum::rpc::load_faucet_seed().expect("real file key loads");
    assert_eq!(hex::encode(seed), GOOD_SEED_HEX);
    assert_eq!(
        stellereum::rpc::try_load_faucet_seed_opt().unwrap(),
        Some(seed)
    );
    std::fs::remove_file(&path).ok();
    g.remove("STELL_FAUCET_KEY_FILE");
    // Inline real key WITHOUT the file: refused (serving is file-only).
    g.set("STELL_FAUCET_KEY", GOOD_SEED_HEX);
    let err = stellereum::rpc::load_faucet_seed().expect_err("inline alone must be refused");
    assert!(
        err.contains("STELL_FAUCET_KEY_FILE") && err.contains("DISABLED"),
        "loud file-required refusal: {err}"
    );
    g.remove("STELL_FAUCET_KEY");
    // File with the public test key, no override: loud refusal naming the override.
    let tpath = tmp_path("faucettest");
    write_key_file(&tpath, TEST_SEED_HEX, 0o600);
    g.set("STELL_FAUCET_KEY_FILE", tpath.to_str().unwrap());
    let err = stellereum::rpc::load_faucet_seed().expect_err("test key must be refused");
    assert!(err.contains("STELL_DEV_UNSAFE_TESTKEY"), "loud: {err}");
    assert!(stellereum::rpc::try_load_faucet_seed_opt().is_err());
    // With the dev override: allowed (dev only).
    g.set("STELL_DEV_UNSAFE_TESTKEY", "1");
    assert!(stellereum::rpc::load_faucet_seed().is_ok());
    std::fs::remove_file(&tpath).ok();
}

// ==================== (c) chain id ====================

#[test]
fn chain_id_defaults_and_env_override() {
    let g = EnvGuard::lock();
    assert_eq!(stellereum::zkml::DEFAULT_CHAIN_ID, 5757);
    assert_eq!(stellereum::zkml::effective_chain_id(), 5757);
    assert_eq!(stellereum::evm_adapter::effective_chain_id(), 5757);
    g.set("STELL_CHAIN_ID", "1234");
    assert_eq!(stellereum::zkml::effective_chain_id(), 1234);
    assert_eq!(
        stellereum::evm_adapter::effective_chain_id(),
        1234,
        "both hardcoded sites follow the env"
    );
    // Garbage / zero fall back to the default (fail-closed, never 0).
    g.set("STELL_CHAIN_ID", "not-a-number");
    assert_eq!(stellereum::zkml::effective_chain_id(), 5757);
    g.set("STELL_CHAIN_ID", "0");
    assert_eq!(stellereum::zkml::effective_chain_id(), 5757);
    g.set("STELL_CHAIN_ID", "  777  ");
    assert_eq!(stellereum::zkml::parse_chain_id_env(Some("  777  ")), 777);
    assert_eq!(stellereum::zkml::parse_chain_id_env(None), 5757);
}

#[test]
fn peer_chain_id_mismatch_aborts_loudly() {
    let _g = EnvGuard::lock();
    // Match: fine.
    assert!(stellereum::zkml::check_peer_chain_id(5757, 5757).is_ok());
    assert!(stellereum::evm_adapter::check_peer_chain_id(9, 9).is_ok());
    // Mismatch: loud abort naming both ids — never a silent partition.
    let err = stellereum::zkml::check_peer_chain_id(5757, 1234).expect_err("mismatch must abort");
    assert!(err.contains("REFUSING"), "loud: {err}");
    assert!(
        err.contains("5757") && err.contains("1234"),
        "both ids: {err}"
    );
    let err2 = stellereum::evm_adapter::check_peer_chain_id(1234, 5757)
        .expect_err("evm site enforces the same rule");
    assert!(err2.contains("REFUSING"), "loud: {err2}");
    // Multi-peer: first mismatch aborts.
    assert!(stellereum::zkml::verify_peer_chain_ids(7, &[7, 7]).is_ok());
    assert!(stellereum::zkml::verify_peer_chain_ids(7, &[7, 8]).is_err());
}

#[test]
fn evm_chain_id_formatting_follows_the_effective_id() {
    let _g = EnvGuard::lock();
    assert_eq!(stellereum::evm_adapter::eth_chain_id_for(5757), "0x167d");
    assert_eq!(stellereum::evm_adapter::net_version_for(5757), "5757");
    assert_eq!(stellereum::evm_adapter::eth_chain_id_for(1234), "0x4d2");
    assert_eq!(stellereum::evm_adapter::net_version_for(1234), "1234");
}

#[test]
fn peer_chain_id_sighting_aborts_on_mismatch() {
    let _g = EnvGuard::lock();
    // Matching report records cleanly.
    assert!(stellereum::rpc::note_peer_chain_id(5757, 5757).is_ok());
    assert_eq!(stellereum::rpc::fresh_peer_chain_id(), Some(5757));
    // Foreign report aborts loudly (startup must refuse to start on this).
    let err =
        stellereum::rpc::note_peer_chain_id(5757, 9999).expect_err("foreign chain must abort");
    assert!(err.contains("REFUSING"), "loud: {err}");
    assert!(err.contains("9999"), "names the peer id: {err}");
    // The sighting is still recorded for diagnostics.
    assert_eq!(stellereum::rpc::fresh_peer_chain_id(), Some(9999));
}
