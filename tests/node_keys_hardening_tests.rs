//! Security hardening tests for Stellereum node keys (`identity.key`, `falcon.key`, `e2e.key`).
//! Verifies:
//! - Strict POSIX permissions (0600 on files, 0700 on directories) enforced at load time.
//! - Rejection of insecure permissions (e.g. 0644 or 0755).
//! - Passphrase encryption/decryption via STELL_NODE_PASSPHRASE using Argon2id + XChaCha20-Poly1305 (`enc2:` format).
//! - NEW KEYS ARE ENCRYPTED BY DEFAULT (`enc2:` on disk), not plaintext.
//! - Rejection of wrong passphrase on encrypted keys.
//! - Rejection when keys are encrypted but no passphrase is available (fail-closed).
//! - Refusal to write a NEW key when no passphrase is available (fail-closed).
//! - Backward compatibility: plaintext keys on disk still load.
//! - Explicit operator opt-out via `STELL_KEY_PLAINTEXT=1` writes plaintext keys.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use stellereum::node_keys::{
    load_falcon_key, load_node_keys, save_falcon_key, save_node_keys, ENV_PASSPHRASE,
    ENV_PASSPHRASE_ALT, ENV_PLAINTEXT, FALLBACK_ENV_PASSPHRASE,
};
use stellereum::post_quantum::FalconKeypair;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Every environment variable that steers the key-storage policy.
const KEY_ENV_VARS: &[&str] = &[
    ENV_PASSPHRASE,
    ENV_PASSPHRASE_ALT,
    FALLBACK_ENV_PASSPHRASE,
    ENV_PLAINTEXT,
];

/// Clear all key-policy env vars so a test starts from a known state.
fn clear_key_env() {
    for var in KEY_ENV_VARS {
        std::env::remove_var(var);
    }
}

fn temp_keystore_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stell_{prefix}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn test_node_keys_plaintext_permissions_and_roundtrip() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    // Explicit operator opt-out: plaintext key files.
    std::env::set_var(ENV_PLAINTEXT, "1");

    let dir = temp_keystore_dir("plain_roundtrip");
    let keys = infnode::keyring::NodeKeys::generate();
    let id_bytes = keys.signing.verifying_key().to_bytes();

    save_node_keys(&dir, &keys).expect("save_node_keys");

    // Verify file and dir modes on disk
    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "directory must be 0700");

    let id_mode = std::fs::metadata(dir.join("identity.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(id_mode, 0o600, "identity.key must be 0600");

    let e2e_mode = std::fs::metadata(dir.join("e2e.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(e2e_mode, 0o600, "e2e.key must be 0600");

    // The opt-out really means plaintext on disk.
    let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(
        !raw.starts_with("enc2:"),
        "STELL_KEY_PLAINTEXT=1 must write plaintext keys"
    );

    // Plaintext load must succeed
    let loaded = load_node_keys(&dir).expect("load_node_keys");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_bytes);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_new_node_keys_are_encrypted_by_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    std::env::set_var(ENV_PASSPHRASE_ALT, "default-encryption-passphrase");

    let dir = temp_keystore_dir("default_encrypted");
    let keys = infnode::keyring::NodeKeys::generate();
    let id_pub = keys.signing.verifying_key().to_bytes();
    let id_hex = hex::encode(keys.signing.to_bytes());

    save_node_keys(&dir, &keys).expect("save_node_keys");

    let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(
        raw.starts_with("enc2:"),
        "new keys must be encrypted by default"
    );
    assert!(
        !raw.contains(&id_hex),
        "encrypted key must not leak the seed"
    );

    let loaded = load_node_keys(&dir).expect("load_node_keys");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_pub);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_no_passphrase_refuses_to_write_new_key() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();

    let dir = temp_keystore_dir("refuse_write");
    let keys = infnode::keyring::NodeKeys::generate();

    let err = save_node_keys(&dir, &keys).expect_err("must refuse to write without a passphrase");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(ENV_PASSPHRASE_ALT) || msg.contains(ENV_PASSPHRASE),
        "error must document the passphrase env var: {msg}"
    );
    assert!(
        msg.contains(ENV_PLAINTEXT),
        "error must document the plaintext escape hatch: {msg}"
    );
    assert!(
        !dir.join("identity.key").exists(),
        "no key file may be written when the write is refused"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_falcon_key_plaintext_permissions_and_roundtrip() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    std::env::set_var(ENV_PLAINTEXT, "1");

    let dir = temp_keystore_dir("falcon_plain");
    let falcon_path = dir.join("falcon.key");
    let fk = FalconKeypair::generate();
    let pub_key = fk.public_key.clone();

    save_falcon_key(&falcon_path, &fk).expect("save_falcon_key");

    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "dir must be 0700");

    let file_mode = std::fs::metadata(&falcon_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600, "falcon.key must be 0600");

    let loaded = load_falcon_key(&falcon_path).expect("load_falcon_key");
    assert_eq!(loaded.public_key, pub_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_strict_permissions_rejection_on_node_keys() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    std::env::set_var(ENV_PLAINTEXT, "1");

    let dir = temp_keystore_dir("perm_node");
    let keys = infnode::keyring::NodeKeys::generate();
    save_node_keys(&dir, &keys).unwrap();

    // 1. Insecure directory permissions (0755)
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("must reject 0755 directory"),
    };
    assert!(
        err.to_string().contains("insecure"),
        "error must mention insecure perms: {err}"
    );

    // Restore dir to 0700
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // 2. Insecure identity.key permissions (0644)
    std::fs::set_permissions(
        dir.join("identity.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("must reject 0644 identity.key"),
    };
    assert!(
        err.to_string().contains("insecure"),
        "error must mention insecure perms: {err}"
    );

    // Restore identity.key to 0600
    std::fs::set_permissions(
        dir.join("identity.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    // 3. Insecure e2e.key permissions (0644)
    std::fs::set_permissions(dir.join("e2e.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("must reject 0644 e2e.key"),
    };
    assert!(
        err.to_string().contains("insecure"),
        "error must mention insecure perms: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_strict_permissions_rejection_on_falcon_key() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    std::env::set_var(ENV_PLAINTEXT, "1");

    let dir = temp_keystore_dir("perm_falcon");
    let falcon_path = dir.join("falcon.key");
    let fk = FalconKeypair::generate();
    save_falcon_key(&falcon_path, &fk).unwrap();

    // Insecure falcon.key file (0644)
    std::fs::set_permissions(&falcon_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = load_falcon_key(&falcon_path).expect_err("must reject 0644 falcon.key");
    assert!(err.to_string().contains("insecure"), "error: {err}");

    // Restore file, break dir
    std::fs::set_permissions(&falcon_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = load_falcon_key(&falcon_path).expect_err("must reject 0755 parent dir");
    assert!(err.to_string().contains("insecure"), "error: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_encrypted_node_keys_roundtrip_and_passphrase_rejection() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    let pass = "correct-horse-battery-staple-node-key";
    std::env::set_var(ENV_PASSPHRASE, pass);

    let dir = temp_keystore_dir("enc_node");
    let keys = infnode::keyring::NodeKeys::generate();
    let id_pub = keys.signing.verifying_key().to_bytes();
    let id_hex = hex::encode(keys.signing.to_bytes());

    save_node_keys(&dir, &keys).expect("save encrypted node keys");

    // File content must be encrypted with enc2: prefix and not leak plaintext hex
    let raw_id = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(
        raw_id.starts_with("enc2:"),
        "must use enc2: Argon2id format"
    );
    assert!(!raw_id.contains(&id_hex), "must not leak plaintext hex");

    let raw_e2e = std::fs::read_to_string(dir.join("e2e.key")).unwrap();
    assert!(
        raw_e2e.starts_with("enc2:"),
        "must use enc2: Argon2id format"
    );

    // 1. Correct passphrase decrypts
    let loaded = load_node_keys(&dir).expect("load with correct passphrase");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_pub);

    // 2. Wrong passphrase fails
    std::env::set_var(ENV_PASSPHRASE, "wrong-password");
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("wrong passphrase must fail"),
    };
    assert!(
        err.to_string().contains("passphrase") || err.to_string().contains("пассфраза"),
        "error must indicate passphrase failure: {err}"
    );

    // 3. Unset passphrase fails
    clear_key_env();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("missing passphrase on encrypted key must fail"),
    };
    assert!(
        err.to_string().contains(ENV_PASSPHRASE) || err.to_string().contains("encrypted"),
        "error must indicate missing passphrase: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_encrypted_falcon_key_roundtrip_and_passphrase_rejection() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();
    let pass = "falcon-passphrase-pq-bft-2026";
    std::env::set_var(ENV_PASSPHRASE, pass);

    let dir = temp_keystore_dir("enc_falcon");
    let falcon_path = dir.join("falcon.key");
    let fk = FalconKeypair::generate();
    let pub_key = fk.public_key.clone();

    save_falcon_key(&falcon_path, &fk).expect("save encrypted falcon key");

    // Raw file must start with enc2:
    let raw = std::fs::read(&falcon_path).unwrap();
    assert!(
        raw.starts_with(b"enc2:"),
        "falcon key must start with enc2:"
    );

    // 1. Load with correct passphrase
    let loaded = load_falcon_key(&falcon_path).expect("load with correct passphrase");
    assert_eq!(loaded.public_key, pub_key);

    // 2. Load with wrong passphrase
    std::env::set_var(ENV_PASSPHRASE, "wrong-passphrase");
    let err = load_falcon_key(&falcon_path).expect_err("wrong passphrase must fail");
    assert!(err.to_string().contains("passphrase"), "error: {err}");

    // 3. Load with missing passphrase
    clear_key_env();
    let err = load_falcon_key(&falcon_path).expect_err("missing passphrase must fail");
    assert!(
        err.to_string().contains(ENV_PASSPHRASE) || err.to_string().contains("encrypted"),
        "error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Backward compatibility: a plaintext key that is already on disk (the live
/// testnet nodes) must keep loading — and gets re-encrypted in place once a
/// passphrase is available.
#[test]
fn test_existing_plaintext_key_still_loads_and_is_upgraded() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_key_env();

    let dir = temp_keystore_dir("plain_compat");
    let keys = infnode::keyring::NodeKeys::generate();
    let id_pub = keys.signing.verifying_key().to_bytes();
    let id_hex = hex::encode(keys.signing.to_bytes());
    let e2e_hex = hex::encode(keys.e2e_sec.to_bytes());

    // Exactly what the live nodes have: raw hex, 0600, in a 0700 dir.
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    stellereum::node_keys::write_private_file(&dir.join("identity.key"), id_hex.as_bytes())
        .unwrap();
    stellereum::node_keys::write_private_file(&dir.join("e2e.key"), e2e_hex.as_bytes()).unwrap();

    // No passphrase: the plaintext key still loads.
    let loaded = load_node_keys(&dir).expect("plaintext key must still load");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_pub);
    let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(!raw.starts_with("enc2:"), "no passphrase -> file untouched");

    // With a passphrase: transparent in-place upgrade.
    std::env::set_var(ENV_PASSPHRASE, "upgrade-passphrase");
    let loaded = load_node_keys(&dir).expect("plaintext key must load and be upgraded");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_pub);
    let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(raw.starts_with("enc2:"), "key must be upgraded to enc2:");
    assert!(
        !raw.contains(&id_hex),
        "upgraded key must not leak the seed"
    );
    let raw_e2e = std::fs::read_to_string(dir.join("e2e.key")).unwrap();
    assert!(
        raw_e2e.starts_with("enc2:"),
        "e2e key must be upgraded to enc2:"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
