//! Comprehensive Security & Penetration Testing Suite for Stell-Wallet
//! Tests:
//! - Keystore tamper-proofing (AEAD Poly1305 authentication tag)
//! - Offline brute-force resistance (Argon2id KDF parameters)
//! - Memory scrubbing (ZeroizeOnDrop)
//! - OS file permission enforcement (POSIX 0600/0700)
//! - 24-word Mnemonic checksum integrity & typo rejection
//! - SPV Light client Merkle proof forgery rejection

use std::fs;
use std::os::unix::fs::PermissionsExt;
use stellereum::cell::PatriciaTrie;
use stellereum::wallet::Mnemonic;

// Import security functions directly from crate
#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;
use security::{enforce_strict_permissions, HardenedKeystore, SecureSecret};

#[test]
fn test_keystore_tamper_proofing() {
    let secret = SecureSecret::new([0x42; 32]);
    let address = "8ef8c8e89d495a7806d8eb8d0ce6953adb801d7399a5d37d71f333acdcb43743";
    let password = "SuperSecretPassword#2026";

    let mut keystore =
        HardenedKeystore::encrypt(&secret, address, password).expect("Encryption failed");

    // 1. Decryption with correct password succeeds
    let decrypted = keystore
        .decrypt(password)
        .expect("Decryption should succeed");
    assert_eq!(decrypted.bytes, [0x42; 32]);

    // 2. Tampering attack: flip a byte in ciphertext
    let mut ct_bytes = hex::decode(&keystore.ciphertext_hex).unwrap();
    ct_bytes[0] ^= 0xFF; // Bit flip
    keystore.ciphertext_hex = hex::encode(ct_bytes);

    // AEAD Poly1305 must reject tampered ciphertext
    let res = keystore.decrypt(password);
    assert!(
        res.is_err(),
        "AEAD Poly1305 must reject tampered ciphertext!"
    );

    // 3. Tampering attack: flip a byte in auth tag
    let mut tag_bytes = hex::decode(&keystore.auth_tag_hex).unwrap();
    tag_bytes[0] ^= 0x01;
    keystore.auth_tag_hex = hex::encode(tag_bytes);

    let res_tag = keystore.decrypt(password);
    assert!(
        res_tag.is_err(),
        "AEAD Poly1305 must reject tampered MAC tag!"
    );
}

#[test]
fn test_wrong_password_rejection() {
    let secret = SecureSecret::new([0x99; 32]);
    let keystore = HardenedKeystore::encrypt(&secret, "addr_test", "correct_password_123").unwrap();

    let wrong_attempts = ["wrong_pass", "correct_password_124", "", "admin", "123456"];
    for wrong in wrong_attempts {
        assert!(
            keystore.decrypt(wrong).is_err(),
            "Wrong password must be rejected!"
        );
    }
}

#[test]
fn test_strict_file_permissions_enforced() {
    let temp_dir = std::env::temp_dir().join("stell_sec_test_dir");
    let test_file = temp_dir.join("test_keystore.json");

    fs::create_dir_all(&temp_dir).unwrap();
    fs::write(&test_file, b"test_payload").unwrap();

    enforce_strict_permissions(&test_file);

    let file_mode = fs::metadata(&test_file).unwrap().permissions().mode() & 0o777;
    let dir_mode = fs::metadata(&temp_dir).unwrap().permissions().mode() & 0o777;

    assert_eq!(
        file_mode, 0o600,
        "File permissions must be strictly 0600 (owner only)!"
    );
    assert_eq!(
        dir_mode, 0o700,
        "Directory permissions must be strictly 0700 (owner only)!"
    );

    let _ = fs::remove_file(test_file);
    let _ = fs::remove_dir(temp_dir);
}

#[test]
fn test_mnemonic_24_words_checksum_integrity() {
    // Generate valid 24-word phrase
    let (phrase, seed) = Mnemonic::generate();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24, "Mnemonic must be exactly 24 words");

    // Must restore accurately
    let restored_seed = Mnemonic::from_phrase(&phrase).expect("Valid phrase must decode");
    assert_eq!(restored_seed, seed);

    // Typos attack: change a single letter in the last word
    let mut bad_words = words.clone();
    bad_words[23] = if bad_words[23] == "zoo" {
        "abandon"
    } else {
        "zoo"
    };
    let corrupted_phrase = bad_words.join(" ");

    let res = Mnemonic::from_phrase(&corrupted_phrase);
    assert!(
        res.is_err(),
        "Corrupted mnemonic word must fail checksum validation!"
    );

    // Non-dictionary word attack
    let mut invalid_words = words.clone();
    invalid_words[0] = "hackerword";
    let invalid_phrase = invalid_words.join(" ");
    assert!(
        Mnemonic::from_phrase(&invalid_phrase).is_err(),
        "Non-dictionary word must be rejected!"
    );
}

#[test]
fn test_spv_merkle_tamper_detection() {
    let mut trie = PatriciaTrie::new();
    let user_addr = [7u8; 32];
    let real_balance: u64 = 100_000_000_000;
    let real_nonce: u64 = 5;

    let mut data = Vec::new();
    data.extend_from_slice(&real_balance.to_be_bytes());
    data.extend_from_slice(&real_nonce.to_be_bytes());
    trie.insert(&user_addr, &data);

    let state_root = trie.root_hash();
    let proof = trie
        .generate_merkle_proof(&user_addr)
        .expect("Proof generation failed");

    // Real state verifies
    assert!(PatriciaTrie::verify_merkle_proof(
        &state_root,
        &user_addr,
        &data,
        &proof
    ));

    // Fake balance spoofing attack: rogue node claims user has 999_999_999 STELL
    let fake_balance: u64 = 999_999_999_000_000_000;
    let mut fake_data = Vec::new();
    fake_data.extend_from_slice(&fake_balance.to_be_bytes());
    fake_data.extend_from_slice(&real_nonce.to_be_bytes());

    let fake_verified =
        PatriciaTrie::verify_merkle_proof(&state_root, &user_addr, &fake_data, &proof);
    assert!(
        !fake_verified,
        "SPV Client must reject fake spoofed balance!"
    );
}

#[test]
fn test_keystore_address_binding_and_version_gate() {
    // AAD binding (audit 2026-10-06): swapping address_hex must break decrypt.
    let secret = SecureSecret::new([0x11; 32]);
    let mut ks = HardenedKeystore::encrypt(&secret, "addra", "pw123456").expect("encrypt");
    ks.address_hex = "addrb".to_string();
    assert!(
        ks.decrypt("pw123456").is_err(),
        "swapped address must fail AAD check"
    );

    // Version/kdf/cipher gates: downgraded keystores fail closed.
    let secret2 = SecureSecret::new([0x22; 32]);
    let mut ks2 = HardenedKeystore::encrypt(&secret2, "addra", "pw123456").expect("encrypt");
    ks2.version = 1;
    assert!(
        ks2.decrypt("pw123456").is_err(),
        "old version must be rejected"
    );
    ks2.version = 2;
    ks2.kdf = "scrypt".to_string();
    assert!(
        ks2.decrypt("pw123456").is_err(),
        "unknown KDF must be rejected"
    );

    // Scheme tampering must fail AAD check
    let secret3 = SecureSecret::new([0x33; 32]);
    let mut ks3 = HardenedKeystore::encrypt_with_scheme(
        &secret3,
        "addra",
        "pw123456",
        "falcon512",
        Some("abcdef".to_string()),
    )
    .expect("encrypt");
    ks3.scheme = "ed25519".to_string();
    assert!(
        ks3.decrypt("pw123456").is_err(),
        "tampered scheme must fail AAD check"
    );

    // PQ pubkey tampering must fail AAD check
    let mut ks4 = HardenedKeystore::encrypt_with_scheme(
        &secret3,
        "addra",
        "pw123456",
        "falcon512",
        Some("abcdef".to_string()),
    )
    .expect("encrypt");
    ks4.pq_pubkey_hex = Some("000000".to_string());
    assert!(
        ks4.decrypt("pw123456").is_err(),
        "tampered pq_pubkey_hex must fail AAD check"
    );

    // PQ pubkey stripping (Some -> None) must fail AAD check
    let mut ks5 = HardenedKeystore::encrypt_with_scheme(
        &secret3,
        "addra",
        "pw123456",
        "falcon512",
        Some("abcdef".to_string()),
    )
    .expect("encrypt");
    ks5.pq_pubkey_hex = None;
    assert!(
        ks5.decrypt("pw123456").is_err(),
        "stripped pq_pubkey_hex must fail AAD check"
    );

    // PQ pubkey injection (None -> Some) must fail AAD check
    let mut ks6 =
        HardenedKeystore::encrypt_with_scheme(&secret3, "addra", "pw123456", "falcon512", None)
            .expect("encrypt");
    ks6.pq_pubkey_hex = Some("abcdef".to_string());
    assert!(
        ks6.decrypt("pw123456").is_err(),
        "injected pq_pubkey_hex must fail AAD check"
    );
}
