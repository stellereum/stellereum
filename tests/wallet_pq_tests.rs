//! Phase-2 wallet track: PQ-first signing in the wallet library.
//!
//! * keygen defaults to Falcon-512 (deterministic-from-seed preserved);
//! * key files accept both PQ and legacy Ed25519 (auto-detect, PQ preferred);
//! * the sign path dispatches on the loaded key and refuses cross-scheme
//!   requests fail-closed (legacy Ed25519 flows unchanged);
//! * key files (and the keystore) are owner-only (0600).
//!
//! No wire change: the PQ shape asserted here is the `send-pq` / faucet
//! explicit-PQ1 envelope the network already verifies.

use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::wallet::{
    default_wallet_key_scheme, load_wallet_key, save_wallet_key, Keystore, WalletAccount,
    WalletKeyMaterial,
};

const TEST_CHAIN_ID: u64 = 5757;
const OTHER_CHAIN_ID: u64 = 9999;

/// Unique scratch dir per test (this binary runs tests in parallel).
fn scratch_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell-wallet-pq-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[cfg(unix)]
fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

// ============================================================================
// 1. PQ keygen / sign / verify round-trip.
// ============================================================================

#[test]
fn pq_keygen_sign_verify_round_trip() {
    assert_eq!(default_wallet_key_scheme(), PqScheme::Falcon512);
    // Deterministic-from-seed: the same seed reproduces the same address.
    let a = WalletKeyMaterial::from_seed(&[0x42u8; 32]);
    let b = WalletKeyMaterial::from_seed(&[0x42u8; 32]);
    assert_eq!(a.scheme(), PqScheme::Falcon512);
    assert!(a.is_post_quantum());
    assert_eq!(a.address(), b.address());

    // Unbound transfer (the `send-pq` shape): PQ envelope, verifies.
    let tx = a.sign_transfer([0x99u8; 32], 1_000, 50_000, 0, 0, 0);
    assert!(tx.is_pq());
    assert!(tx.is_pq_activation(), "first-send shape carries the key");
    assert_eq!(tx.chain_id(), None);
    assert_eq!(tx.from, a.address());
    assert!(tx.verify_signature(), "PQ transfer must verify");

    // Bound transfer: chain id committed, strict check passes only at home.
    let btx = a.sign_bound_transfer([0x99u8; 32], 1_000, 50_000, 0, 0, 0, TEST_CHAIN_ID);
    assert!(btx.is_pq());
    assert_eq!(btx.chain_id(), Some(TEST_CHAIN_ID));
    assert!(btx.verify_signature());
    assert!(btx.verify_signature_for_chain(TEST_CHAIN_ID, true));
    assert!(!btx.verify_signature_for_chain(OTHER_CHAIN_ID, true));

    // Payload legs verify too (both bound and unbound).
    let payload = vec![stellereum::svm::OpCode::Nop];
    let ptx = a.sign_payload_transfer(payload.clone(), 100_000, 1);
    assert!(ptx.is_pq());
    assert!(ptx.verify_signature());
    let bptx = a.sign_bound_payload_transfer(payload, 100_000, 2, TEST_CHAIN_ID);
    assert!(bptx.is_pq());
    assert_eq!(bptx.chain_id(), Some(TEST_CHAIN_ID));
    assert!(bptx.verify_signature_for_chain(TEST_CHAIN_ID, true));
    assert!(!bptx.verify_signature_for_chain(OTHER_CHAIN_ID, true));
}

// ============================================================================
// 2. Legacy Ed25519 still loads and signs (no flag-day).
// ============================================================================

#[test]
fn legacy_ed_still_loads_and_signs() {
    let ed = WalletKeyMaterial::ed25519_from_seed(&[0x42u8; 32]);
    assert_eq!(ed.scheme(), PqScheme::Ed25519);
    assert!(!ed.is_post_quantum());
    // Same address the historical wallet derives from this seed.
    assert_eq!(
        ed.address(),
        WalletAccount::from_seed(&[0x42u8; 32]).address
    );

    // File round-trip preserves the legacy key.
    let dir = scratch_dir("legacy-ed");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("ed.key");
    save_wallet_key(&path, &ed).expect("save");
    let back = load_wallet_key(&path).expect("load");
    assert_eq!(back.scheme(), PqScheme::Ed25519);
    assert_eq!(back.address(), ed.address());

    // Legacy hex fallback: a bare 32-byte seed in hex loads as Ed25519.
    let hex_path = dir.join("legacy-hex.key");
    std::fs::write(&hex_path, hex::encode([0x42u8; 32])).expect("write");
    #[cfg(unix)]
    chmod(&hex_path, 0o600);
    let hex_back = load_wallet_key(&hex_path).expect("legacy hex loads");
    assert_eq!(hex_back.scheme(), PqScheme::Ed25519);
    assert_eq!(hex_back.address(), ed.address());

    // Raw 32-byte fallback loads as Ed25519 too.
    let raw_path = dir.join("legacy-raw.key");
    std::fs::write(&raw_path, [0x42u8; 32]).expect("write");
    #[cfg(unix)]
    chmod(&raw_path, 0o600);
    let raw_back = load_wallet_key(&raw_path).expect("legacy raw loads");
    assert_eq!(raw_back.address(), ed.address());

    // Legacy signing is byte-shape-identical: 64-byte signature, verifies.
    let tx = back.sign_transfer([0x99u8; 32], 1_000, 50_000, 0, 0, 0);
    assert!(!tx.is_pq());
    assert_eq!(tx.signature.len(), 64);
    assert_eq!(tx.from, ed.address());
    assert!(tx.verify_signature());
    let btx = back.sign_bound_transfer([0x99u8; 32], 1_000, 50_000, 0, 0, 0, TEST_CHAIN_ID);
    assert!(!btx.is_pq());
    assert!(btx.is_chain_id_bound());
    assert!(btx.verify_signature_for_chain(TEST_CHAIN_ID, true));
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// 3. Mixed wallet: each key signs with its own correct scheme.
// ============================================================================

#[test]
fn mixed_wallet_signs_with_correct_scheme_per_key() {
    let keys = [
        WalletKeyMaterial::from_seed(&[0xA1u8; 32]),
        WalletKeyMaterial::ed25519_from_seed(&[0xB2u8; 32]),
        WalletKeyMaterial::from_seed(&[0xC3u8; 32]),
        WalletKeyMaterial::ed25519_from_seed(&[0xD4u8; 32]),
    ];
    for (i, key) in keys.iter().enumerate() {
        let to = [i as u8; 32];
        let tx = key.sign_transfer(to, 500 + i as u64, 50_000, i as u64, 0, 0);
        assert_eq!(tx.from, key.address(), "key {i} must sign as itself");
        assert!(tx.verify_signature(), "key {i} signature must verify");
        match key.scheme() {
            PqScheme::Falcon512 => {
                assert!(tx.is_pq(), "Falcon key {i} must build the PQ envelope");
            }
            PqScheme::Ed25519 => {
                assert!(!tx.is_pq(), "Ed25519 key {i} must stay legacy");
                assert_eq!(tx.signature.len(), 64);
            }
            PqScheme::MlDsa44 | PqScheme::Hybrid => {
                panic!("mixed-wallet fixture uses only live wallet schemes")
            }
        }
        // The scheme-pinned entry point accepts the key's own scheme and
        // refuses the other one fail-closed.
        assert!(key
            .sign_transfer_as(key.scheme(), to, 500, 50_000, 0, 0, 0)
            .is_ok());
        let other = if key.scheme() == PqScheme::Falcon512 {
            PqScheme::Ed25519
        } else {
            PqScheme::Falcon512
        };
        assert!(key
            .sign_transfer_as(other, to, 500, 50_000, 0, 0, 0)
            .is_err());
    }
}

// ============================================================================
// 4. File-permission posture (0600) + fail-closed loads.
// ============================================================================

#[test]
fn wallet_key_files_are_owner_only_0600() {
    let dir = scratch_dir("perms");
    std::fs::create_dir_all(&dir).expect("temp dir");
    for (name, key) in [
        ("pq.key", WalletKeyMaterial::from_seed(&[0x51u8; 32])),
        ("ed.key", WalletKeyMaterial::ed25519_from_seed(&[0x52u8; 32])),
    ] {
        let path = dir.join(name);
        save_wallet_key(&path, &key).expect("save");
        #[cfg(unix)]
        assert_eq!(
            mode_of(&path),
            0o600,
            "key file {name} must be owner-only"
        );
        let back = load_wallet_key(&path).expect("load");
        assert_eq!(back.address(), key.address());
    }

    // Corrupt / unknown / empty inputs refuse fail-closed (never a guess).
    let bad = dir.join("bad.key");
    std::fs::write(&bad, b"not a key").expect("write");
    #[cfg(unix)]
    chmod(&bad, 0o600);
    assert!(load_wallet_key(&bad).is_err());
    let unknown = dir.join("unknown.key");
    std::fs::write(&unknown, r#"{"scheme":"mldsa","key_hex":"00"}"#).expect("write");
    #[cfg(unix)]
    chmod(&unknown, 0o600);
    assert!(load_wallet_key(&unknown).is_err());
    let empty = dir.join("empty.key");
    std::fs::write(&empty, b"").expect("write");
    #[cfg(unix)]
    chmod(&empty, 0o600);
    assert!(load_wallet_key(&empty).is_err());

    #[cfg(unix)]
    {
        // Group/world-readable key files are refused, never loaded.
        let path = dir.join("pq.key");
        chmod(&path, 0o644);
        assert!(load_wallet_key(&path).is_err());
        chmod(&path, 0o600);
        assert!(load_wallet_key(&path).is_ok());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pq_encoding_is_preferred_on_autodetect() {
    let pq = WalletKeyMaterial::from_seed(&[0x61u8; 32]);
    let keypair_bytes = match &pq {
        WalletKeyMaterial::Falcon { keypair } => keypair.to_bytes(),
        WalletKeyMaterial::Ed25519 { .. } => panic!("fixture must be Falcon"),
    };
    let dir = scratch_dir("autodetect");
    std::fs::create_dir_all(&dir).expect("temp dir");

    // Raw Falcon bytes (no JSON tag) still load as Falcon (PQ preferred).
    let raw = dir.join("raw-falcon.key");
    std::fs::write(&raw, &keypair_bytes).expect("write");
    #[cfg(unix)]
    chmod(&raw, 0o600);
    let back = load_wallet_key(&raw).expect("raw Falcon loads");
    assert_eq!(back.scheme(), PqScheme::Falcon512);
    assert_eq!(back.address(), pq.address());

    // Hex of the Falcon bytes loads as Falcon too.
    let hexed = dir.join("hex-falcon.key");
    std::fs::write(&hexed, hex::encode(&keypair_bytes)).expect("write");
    #[cfg(unix)]
    chmod(&hexed, 0o600);
    let back_hex = load_wallet_key(&hexed).expect("hex Falcon loads");
    assert_eq!(back_hex.address(), pq.address());

    // A truncated Falcon blob is corrupt: refused, never downgraded to Ed.
    let trunc = dir.join("trunc.key");
    std::fs::write(&trunc, &keypair_bytes[..keypair_bytes.len() / 2]).expect("write");
    #[cfg(unix)]
    chmod(&trunc, 0o600);
    assert!(load_wallet_key(&trunc).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn send_pq_shape_matches_the_faucet_convention() {
    // The wallet PQ transfer must be the exact shape `send-pq` submits:
    // sender is the zero-salt Falcon address, the pubkey rides explicitly,
    // the message is the unbound signing message (no chain binding unless
    // the bound constructor is used).
    let pq = WalletKeyMaterial::from_seed(&[0x11u8; 32]);
    let pubkey = match &pq {
        WalletKeyMaterial::Falcon { keypair } => keypair.public_key.clone(),
        WalletKeyMaterial::Ed25519 { .. } => panic!("fixture must be Falcon"),
    };
    let tx = pq.sign_transfer([0xABu8; 32], 1_000_000_000, 325_000, 0, 0, 0);
    assert_eq!(
        tx.from,
        derive_pq_address(PqScheme::Falcon512, &pubkey, &DEFAULT_SALT)
    );
    let env = tx.pq_envelope().expect("PQ envelope decodes");
    assert!(!env.is_implicit);
    assert_eq!(env.pubkey.as_deref(), Some(pubkey.as_slice()));
    assert_eq!(env.salt, DEFAULT_SALT);
    assert!(tx.verify_signature());
}

#[test]
fn keystore_save_is_owner_only_and_round_trips() {
    let dir = scratch_dir("keystore");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let seed = [0x77u8; 32];
    let ks = Keystore::encrypt(&seed, "ab".repeat(32).as_str(), "correct-horse")
        .expect("encrypt");
    let path = dir.join("wallet.json");
    ks.save_to_file(&path).expect("save");
    #[cfg(unix)]
    assert_eq!(mode_of(&path), 0o600, "keystore must be owner-only");
    let loaded = Keystore::load_from_file(&path).expect("load");
    assert_eq!(loaded.decrypt("correct-horse").expect("decrypt"), seed);
    assert!(loaded.decrypt("wrong-password").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
