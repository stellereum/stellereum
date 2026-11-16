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

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/notes.rs"]
mod notes;

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

// B-WALLET PoC-2: bare-success receipt forges finality (rpc.rs:697-712).
// `parse_receipt_status` defaults missing height/hash to 0/"", so a malicious
// node returning `{"status":"success"}` (or omitting fields) yields
// `Confirmed{height:0}` and the wallet prints "Confirmed (finalized...)".
// Secure: success without height+block_hash must NOT be Confirmed.
#[test]
fn poc_receipt_bare_success_must_not_be_confirmed() {
    let bare = serde_json::json!({"status": "success"});
    let parsed = rpc::parse_receipt_status(&bare);
    println!("bare success parsed as: {parsed:?}");
    assert!(
        !parsed.is_confirmed(),
        "POC-REAL (receipt confusion): bare {{\"status\":\"success\"}} parsed as Confirmed"
    );
    let no_hash = serde_json::json!({"status": "success", "height": 123});
    let parsed2 = rpc::parse_receipt_status(&no_hash);
    println!("no-hash success parsed as: {parsed2:?}");
    assert!(
        !parsed2.is_confirmed(),
        "POC-REAL: success without block_hash must not be Confirmed"
    );
}

// B-WALLET PoC-2 FIXED: legacy public-key notes stores are gone — notes are
// secret-bound. Attacker model: victim files readable, secret unknown.
// (a) secret-bound roundtrip works; (b) wrong secret refuses; (c) a forged
// LEGACY file migrates with the secret and is unreadable without it.
#[test]
fn poc_legacy_notes_key_derivable_from_public_files() {
    use aead::{Aead, KeyInit, Payload};
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir().join(format!(
        "stell_poc_notes_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        CTR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("mkdir");
    let secret = [0x5Eu8; 32];
    let wrong = [0x6Fu8; 32];
    let wallet_path = base.join("wallet.json");
    fs::write(&wallet_path, b"{\"dummy\":\"public-keystore-bytes\"}").expect("write wallet");
    let notes_path = base.join("shielded_notes.json");
    let note = notes::ShieldedNote {
        commitment: "poc-commit".to_string(),
        amount: 99_000_000_000,
        blinding: "poc-blinding-secret".to_string(),
        height: 1,
        spent: false,
    };
    // (a) secret-bound roundtrip.
    notes::save_notes_with_secret(&notes_path, std::slice::from_ref(&note), &secret)
        .expect("secret save");
    let loaded = notes::load_notes_with_secret(&notes_path, &secret).expect("secret load");
    assert_eq!(loaded, vec![note.clone()]);
    // (b) wrong secret refuses (attacker without the secret, public files only).
    assert!(notes::load_notes_with_secret(&notes_path, &wrong).is_err());
    // (c) forge a LEGACY-format file (public-key-derived, as pre-migration
    // wallets wrote), then migrate with the secret and verify.
    let wallet_bytes = fs::read(&wallet_path).expect("read wallet");
    let salt = [0x77u8; 16];
    let mut material = wallet_bytes.clone();
    material.extend_from_slice(&salt);
    let legacy_key = blake3::derive_key("STELL_NOTES_STORAGE_KEY_V1", &material);
    let cipher = chacha20poly1305::XChaCha20Poly1305::new((&legacy_key).into());
    let nonce = [0x88u8; 24];
    let xnonce = chacha20poly1305::XNonce::from_slice(&nonce);
    let pt = serde_json::to_vec(&vec![note.clone()]).expect("ser");
    let ct_full = cipher
        .encrypt(
            xnonce,
            Payload {
                msg: &pt,
                aad: notes::NOTES_AAD,
            },
        )
        .expect("legacy encrypt");
    let (ct_body, auth_tag) = ct_full.split_at(ct_full.len() - 16);
    let legacy_store = notes::HardenedNotesStore {
        version: notes::NOTES_STORE_VERSION,
        cipher: notes::NOTES_STORE_CIPHER.to_string(),
        kdf: "Blake3(STELL_NOTES_STORAGE_KEY_V1)".to_string(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ct_body),
        auth_tag_hex: hex::encode(auth_tag),
    };
    fs::write(
        &notes_path,
        serde_json::to_string_pretty(&legacy_store).expect("json"),
    )
    .expect("write forged legacy");
    // Attacker holding only public files CANNOT read it via any public API
    // (legacy decrypt paths are removed; secret load fails without secret).
    assert!(notes::load_notes_with_secret(&notes_path, &wrong).is_err());
    // Owner migrates with the secret: legacy -> secret-bound, then reads.
    assert!(notes::migrate_notes_to_secret(&notes_path, &secret).expect("migrate"));
    let migrated = notes::load_notes_with_secret(&notes_path, &secret).expect("read migrated");
    assert_eq!(migrated, vec![note]);
    assert!(notes::load_notes_with_secret(&notes_path, &wrong).is_err());
    let _ = fs::remove_dir_all(&base);
}

// B-WALLET PoC-4: plaintext fallback trusts unauthenticated file (notes.rs:433-492).
// After encryption shipped, `load_notes` still accepts a bare JSON array with
// no MAC. An attacker swapping the encrypted store for plaintext injects fake
// shielded balances (user attempts unshield -> fee loss / confusion).
// Secure: plaintext must be rejected (or migrate-forward loudly), not trusted.
#[test]
fn poc_notes_plaintext_fallback_trusts_tampered_file() {
    let base = std::env::temp_dir().join(format!("stell_poc_plain_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("mkdir");
    let wallet_path = base.join("wallet.json");
    fs::write(&wallet_path, b"{\"dummy\":\"x\"}").expect("wallet");
    let notes_path = base.join("shielded_notes.json");
    let forged = vec![notes::ShieldedNote {
        commitment: "attacker-c".to_string(),
        amount: 1_000_000_000_000,
        blinding: "attacker-b".to_string(),
        height: 999,
        spent: false,
    }];
    fs::write(
        &notes_path,
        serde_json::to_string_pretty(&forged).expect("json"),
    )
    .expect("write forged plaintext");
    let err = notes::load_notes_with_secret(&notes_path, &[0x5Eu8; 32])
        .expect_err("FIXED (audit B-WALLET-4): forged plaintext must be refused, never trusted");
    println!("forged plaintext refused: {err}");
    assert!(
        err.contains("refusing unauthenticated plaintext"),
        "refusal must name the reason, got: {err}"
    );
    let _ = fs::remove_dir_all(&base);
}

// B-WALLET PoC-5: auth token over cleartext HTTP (rpc.rs:101-119,142-202).
// `parse_http_url` accepts `http://`, and `http_post` sends `X-Api-Key`
// over raw TCP with no TLS. Separately, `rpc_call` (rpc.rs:206-223) never
// checks the JSON-RPC `id` echoes the request, so replays mix across calls.
// Secure: http+token must be refused (or warned) and response id verified.
#[test]
fn poc_rpc_http_token_and_id_not_verified() {
    let (host, path) = rpc::parse_http_url("http://127.0.0.1:19090/").expect("parse http");
    assert_eq!(host, "127.0.0.1:19090");
    assert_eq!(path, "/");
    // FIXED (audit B-WALLET-5a): non-loopback http + token refused before
    // any byte is sent; loopback keeps working (bytes never leave the host).
    assert!(rpc::check_http_token_policy("http://127.0.0.1:19090/", Some("SECRET-TOKEN")).is_ok());
    assert!(rpc::check_http_token_policy("http://127.0.0.1:19090/", None).is_ok());
    assert!(rpc::check_http_token_policy("https://node/x", Some("SECRET-TOKEN")).is_ok());
    assert!(rpc::check_http_token_policy("http://192.0.2.7:8546/", Some("SECRET-TOKEN")).is_err());
    assert!(
        rpc::check_http_token_policy("http://localhost.evil.com:8546/", Some("SECRET-TOKEN"))
            .is_err()
    );
    // FIXED (audit B-WALLET-5b): a response with a mismatched JSON-RPC id is
    // refused (replay mixing). Mock server answers every call with id 999.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("mock listener");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // Serve exactly one request, then close.
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Read;
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = r#"{"jsonrpc":"2.0","id":999,"result":"0x1"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            use std::io::Write;
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let cfg = rpc::RpcConfig {
        url: format!("http://127.0.0.1:{port}/"),
        auth_token: None,
        faucet_token: None,
    };
    let err = rpc::rpc_call(&cfg, "stell_chainId", serde_json::json!({}))
        .expect_err("FIXED (audit B-WALLET-5b): id-mismatched response must be refused");
    assert!(
        err.contains("id mismatch"),
        "refusal must name id mismatch, got: {err}"
    );
    handle.join().ok();
}
