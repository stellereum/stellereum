//! Security hardening tests for Stellereum node keys (`identity.key`, `falcon.key`, `e2e.key`).
//! Verifies:
//! - Strict POSIX permissions (0600 on files, 0700 on directories) enforced at load time.
//! - Rejection of insecure permissions (e.g. 0644 or 0755).
//! - Passphrase encryption/decryption via STELL_NODE_PASSPHRASE using Argon2id + XChaCha20-Poly1305 (`enc2:` format).
//! - Rejection of wrong passphrase on encrypted keys.
//! - Rejection when keys are encrypted but STELL_NODE_PASSPHRASE is not set.
//! - Backward compatibility: plaintext keys on disk load with warning when STELL_NODE_PASSPHRASE is unset.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use stellereum::node_keys::{
    load_falcon_key, load_node_keys, save_falcon_key, save_node_keys,
};
use stellereum::post_quantum::FalconKeypair;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_keystore_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stell_{prefix}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn test_node_keys_plaintext_permissions_and_roundtrip() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("STELL_NODE_PASSPHRASE");
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");

    let dir = temp_keystore_dir("plain_roundtrip");
    let keys = infnode::keyring::NodeKeys::generate();
    let id_bytes = keys.signing.verifying_key().to_bytes();

    save_node_keys(&dir, &keys).expect("save_node_keys");

    // Verify file and dir modes on disk
    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "directory must be 0700");

    let id_mode = std::fs::metadata(dir.join("identity.key")).unwrap().permissions().mode() & 0o777;
    assert_eq!(id_mode, 0o600, "identity.key must be 0600");

    let e2e_mode = std::fs::metadata(dir.join("e2e.key")).unwrap().permissions().mode() & 0o777;
    assert_eq!(e2e_mode, 0o600, "e2e.key must be 0600");

    // Plaintext load must succeed
    let loaded = load_node_keys(&dir).expect("load_node_keys");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_bytes);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_falcon_key_plaintext_permissions_and_roundtrip() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("STELL_NODE_PASSPHRASE");
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");

    let dir = temp_keystore_dir("falcon_plain");
    let falcon_path = dir.join("falcon.key");
    let fk = FalconKeypair::generate();
    let pub_key = fk.public_key.clone();

    save_falcon_key(&falcon_path, &fk).expect("save_falcon_key");

    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "dir must be 0700");

    let file_mode = std::fs::metadata(&falcon_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600, "falcon.key must be 0600");

    let loaded = load_falcon_key(&falcon_path).expect("load_falcon_key");
    assert_eq!(loaded.public_key, pub_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_strict_permissions_rejection_on_node_keys() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("STELL_NODE_PASSPHRASE");
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");

    let dir = temp_keystore_dir("perm_node");
    let keys = infnode::keyring::NodeKeys::generate();
    save_node_keys(&dir, &keys).unwrap();

    // 1. Insecure directory permissions (0755)
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("must reject 0755 directory"),
    };
    assert!(err.to_string().contains("insecure"), "error must mention insecure perms: {err}");

    // Restore dir to 0700
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // 2. Insecure identity.key permissions (0644)
    std::fs::set_permissions(dir.join("identity.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("must reject 0644 identity.key"),
    };
    assert!(err.to_string().contains("insecure"), "error must mention insecure perms: {err}");

    // Restore identity.key to 0600
    std::fs::set_permissions(dir.join("identity.key"), std::fs::Permissions::from_mode(0o600)).unwrap();

    // 3. Insecure e2e.key permissions (0644)
    std::fs::set_permissions(dir.join("e2e.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("must reject 0644 e2e.key"),
    };
    assert!(err.to_string().contains("insecure"), "error must mention insecure perms: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_strict_permissions_rejection_on_falcon_key() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("STELL_NODE_PASSPHRASE");
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");

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
    let pass = "correct-horse-battery-staple-node-key";
    std::env::set_var("STELL_NODE_PASSPHRASE", pass);

    let dir = temp_keystore_dir("enc_node");
    let keys = infnode::keyring::NodeKeys::generate();
    let id_pub = keys.signing.verifying_key().to_bytes();
    let id_hex = hex::encode(keys.signing.to_bytes());

    save_node_keys(&dir, &keys).expect("save encrypted node keys");

    // File content must be encrypted with enc2: prefix and not leak plaintext hex
    let raw_id = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(raw_id.starts_with("enc2:"), "must use enc2: Argon2id format");
    assert!(!raw_id.contains(&id_hex), "must not leak plaintext hex");

    let raw_e2e = std::fs::read_to_string(dir.join("e2e.key")).unwrap();
    assert!(raw_e2e.starts_with("enc2:"), "must use enc2: Argon2id format");

    // 1. Correct passphrase decrypts
    let loaded = load_node_keys(&dir).expect("load with correct passphrase");
    assert_eq!(loaded.signing.verifying_key().to_bytes(), id_pub);

    // 2. Wrong passphrase fails
    std::env::set_var("STELL_NODE_PASSPHRASE", "wrong-password");
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("wrong passphrase must fail"),
    };
    assert!(
        err.to_string().contains("passphrase") || err.to_string().contains("пассфраза"),
        "error must indicate passphrase failure: {err}"
    );

    // 3. Unset passphrase fails
    std::env::remove_var("STELL_NODE_PASSPHRASE");
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");
    let err = match load_node_keys(&dir) {
        Err(e) => e,
        Ok(_) => panic!("missing passphrase on encrypted key must fail"),
    };
    assert!(
        err.to_string().contains("STELL_NODE_PASSPHRASE") || err.to_string().contains("encrypted"),
        "error must indicate missing passphrase: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_encrypted_falcon_key_roundtrip_and_passphrase_rejection() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pass = "falcon-passphrase-pq-bft-2026";
    std::env::set_var("STELL_NODE_PASSPHRASE", pass);

    let dir = temp_keystore_dir("enc_falcon");
    let falcon_path = dir.join("falcon.key");
    let fk = FalconKeypair::generate();
    let pub_key = fk.public_key.clone();

    save_falcon_key(&falcon_path, &fk).expect("save encrypted falcon key");

    // Raw file must start with enc2:
    let raw = std::fs::read(&falcon_path).unwrap();
    assert!(raw.starts_with(b"enc2:"), "falcon key must start with enc2:");

    // 1. Load with correct passphrase
    let loaded = load_falcon_key(&falcon_path).expect("load with correct passphrase");
    assert_eq!(loaded.public_key, pub_key);

    // 2. Load with wrong passphrase
    std::env::set_var("STELL_NODE_PASSPHRASE", "wrong-passphrase");
    let err = load_falcon_key(&falcon_path).expect_err("wrong passphrase must fail");
    assert!(err.to_string().contains("passphrase"), "error: {err}");

    // 3. Load with missing passphrase
    std::env::remove_var("STELL_NODE_PASSPHRASE");
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");
    let err = load_falcon_key(&falcon_path).expect_err("missing passphrase must fail");
    assert!(err.to_string().contains("STELL_NODE_PASSPHRASE"), "error: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}
