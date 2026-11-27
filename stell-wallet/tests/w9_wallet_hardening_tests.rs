//! Wave 9C regression tests for deferred wallet security & UX fixes:
//! - W6-A6-1: SPV balance verification checks leaf_data encodes claimed balance||nonce
//! - W6-A6-5: load_stealth_outputs_with_password refuses unauthenticated plaintext JSON
//! - W6-A6-7: faucet_drip enforces HTTP token policy before sending STELL_FAUCET_TOKEN
//! - W6-A6-10: `stell aa` subcommands fail closed instead of printing fake on-chain success
//! - W6-A6-11: local simulation checks arithmetic overflow + writes private files as 0600
//! - UX: `stell pay` accepts `Stl57...` recipient addresses via `parse_hex32`

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/notes.rs"]
mod notes;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/pq.rs"]
mod pq;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

use client::{LightClient, TxRecord};
use pq::{generate_sample_keypair, PqScheme, DEFAULT_SALT};
use rpc::{RpcConfig, SpvAnswer, SpvVerdict};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use stellereum::cell::PatriciaTrie;
use stellereum::state_engine::AccountState;

fn isolated_home() -> PathBuf {
    static HOME: OnceLock<String> = OnceLock::new();
    let dir = HOME
        .get_or_init(|| {
            let d = std::env::temp_dir().join(format!(
                "stell_w9_hardening_{}_{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&d).expect("create isolated test home");
            std::env::set_var("HOME", &d);
            d.to_string_lossy().into_owned()
        })
        .clone();
    PathBuf::from(dir)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// ---------------------------------------------------------------------------
// W6-A6-1: SPV leaf_data must match claimed balance || nonce
// ---------------------------------------------------------------------------

#[test]
fn w6_a6_1_spv_rejects_forged_balance_with_real_16_byte_leaf_data() {
    let address = [0x11u8; 32];
    let real_balance = 100u64;
    let real_nonce = 2u64;

    let mut leaf = Vec::with_capacity(16);
    leaf.extend_from_slice(&real_balance.to_be_bytes());
    leaf.extend_from_slice(&real_nonce.to_be_bytes());

    let mut trie = PatriciaTrie::new();
    trie.insert(&address, &leaf);
    let state_root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&address).unwrap();

    // Honest claim verifies.
    let honest = SpvAnswer {
        balance: real_balance,
        nonce: real_nonce,
        state_root,
        proof: Some(proof.clone()),
        leaf_data: Some(leaf.clone()),
    };
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &honest),
        SpvVerdict::Verified
    );

    // Malicious node keeps genuine leaf_data + proof but claims inflated balance.
    let forged_balance = SpvAnswer {
        balance: 999_999_999_999,
        nonce: real_nonce,
        state_root,
        proof: Some(proof.clone()),
        leaf_data: Some(leaf.clone()),
    };
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &forged_balance),
        SpvVerdict::Failed
    );

    // Malicious node keeps genuine leaf_data + proof but claims different nonce.
    let forged_nonce = SpvAnswer {
        balance: real_balance,
        nonce: real_nonce + 1,
        state_root,
        proof: Some(proof),
        leaf_data: Some(leaf),
    };
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &forged_nonce),
        SpvVerdict::Failed
    );
}

#[test]
fn w6_a6_1_spv_supports_49_byte_pq_leaf_and_rejects_forged_balance() {
    let address = [0x22u8; 32];
    let real_balance = 5_000_000_000u64;
    let real_nonce = 7u64;

    // 49-byte PQ-pinned leaf: balance (8B BE) || nonce (8B BE) || scheme (1B) || pubkey_hash (32B)
    let mut leaf_49 = Vec::with_capacity(stellereum::cpat2::ACCOUNT_LEAF_LEN_PQ);
    leaf_49.extend_from_slice(&real_balance.to_be_bytes());
    leaf_49.extend_from_slice(&real_nonce.to_be_bytes());
    leaf_49.push(stellereum::post_quantum::PqScheme::Falcon512.id());
    leaf_49.extend_from_slice(&[0xABu8; 32]);
    assert_eq!(leaf_49.len(), stellereum::cpat2::ACCOUNT_LEAF_LEN_PQ);

    let mut trie = PatriciaTrie::new();
    trie.insert(&address, &leaf_49);
    let state_root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&address).unwrap();

    let honest = SpvAnswer {
        balance: real_balance,
        nonce: real_nonce,
        state_root,
        proof: Some(proof.clone()),
        leaf_data: Some(leaf_49.clone()),
    };
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &honest),
        SpvVerdict::Verified
    );

    let forged = SpvAnswer {
        balance: real_balance + 1,
        nonce: real_nonce,
        state_root,
        proof: Some(proof.clone()),
        leaf_data: Some(leaf_49),
    };
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &forged),
        SpvVerdict::Failed
    );

    // Malformed leaf length is also rejected.
    let bad_len = SpvAnswer {
        balance: real_balance,
        nonce: real_nonce,
        state_root,
        proof: Some(proof),
        leaf_data: Some(vec![0u8; 8]),
    };
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &bad_len),
        SpvVerdict::Failed
    );
}

// ---------------------------------------------------------------------------
// W6-A6-5: load_stealth_outputs_with_password refuses plaintext JSON
// ---------------------------------------------------------------------------

#[test]
fn w6_a6_5_plaintext_stealth_outputs_rejected_with_password() {
    let dir = unique_temp_dir("stell_w9_stealth");
    let path = dir.join("stealth_outputs.json");
    let forged = vec![notes::StealthOutput {
        one_time_pub: "aa".repeat(32),
        ephemeral_pub: "bb".repeat(32),
        shared_secret: "cc".repeat(32),
        amount: 999_000_000_000,
        height: 42,
        tx_hash: "dd".repeat(32),
        spent: false,
    }];
    let plaintext = serde_json::to_string_pretty(&forged).expect("serialize stealth outputs");
    std::fs::write(&path, plaintext).expect("write plaintext stealth file");

    let err = notes::load_stealth_outputs_with_password(&path, "any_password")
        .expect_err("unauthenticated plaintext stealth JSON must be rejected");
    assert!(
        err.contains("unauthenticated plaintext stealth outputs"),
        "unexpected error: {err}"
    );

    // Authenticated password-bound store still round-trips.
    let auth_path = dir.join("stealth_outputs_auth.json");
    notes::save_stealth_outputs_with_password(&auth_path, &forged, "strong_pass_123")
        .expect("save encrypted stealth outputs");
    let loaded = notes::load_stealth_outputs_with_password(&auth_path, "strong_pass_123")
        .expect("load encrypted stealth outputs");
    assert_eq!(loaded, forged);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// W6-A6-7: faucet_drip refuses non-loopback cleartext http://
// ---------------------------------------------------------------------------

#[test]
fn w6_a6_7_faucet_drip_refuses_non_loopback_http() {
    for url in [
        "http://rpc.example.com:8545",
        "http://localhost.evil.com:8545",
        "http://192.168.1.50:8545",
    ] {
        let cfg = RpcConfig {
            url: url.to_string(),
            auth_token: None,
            faucet_token: Some("secret_faucet_token".to_string()),
        };
        let err = rpc::faucet_drip(&cfg, &"aa".repeat(32), None)
            .expect_err("non-loopback cleartext http must refuse sending faucet token");
        assert!(
            err.contains("cleartext http"),
            "unexpected error for {url}: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// W6-A6-11: overflow checks + 0600 private file persistence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w6_a6_11_local_broadcast_rejects_overflow_atomically() {
    let _home = isolated_home();
    let client = LightClient::connect(None).await.expect("local connect");
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let sender = kp.derive_address(&DEFAULT_SALT);
    let recipient = [0x44u8; 32];

    // 1. amount + gas_limit overflow must return Err instead of wrapping/panicking.
    client
        .state_engine
        .update_account(AccountState::new(sender, u64::MAX))
        .await;
    let tx_amt_overflow = LightClient::build_pq_transfer_tx_bound(
        &kp,
        recipient,
        u64::MAX,
        500_000,
        0,
        0,
        0,
        true,
        5757,
    )
    .expect("build amount-overflow tx");
    let err_amt = client
        .broadcast_tx(&tx_amt_overflow)
        .await
        .expect_err("amount + gas_limit overflow must fail");
    assert!(
        err_amt.contains("overflow"),
        "expected overflow error, got: {err_amt}"
    );

    // 2. Recipient balance overflow must return Err AND roll back sender debit/nonce.
    let initial_sender_bal = 10_000_000u64;
    client
        .state_engine
        .update_account(AccountState::new(sender, initial_sender_bal))
        .await;
    client
        .state_engine
        .update_account(AccountState::new(recipient, u64::MAX - 10))
        .await;
    let tx_rec_overflow = LightClient::build_pq_transfer_tx_bound(
        &kp, recipient, 1_000_000, 500_000, 0, 0, 0, true, 5757,
    )
    .expect("build recipient-overflow tx");
    let err_rec = client
        .broadcast_tx(&tx_rec_overflow)
        .await
        .expect_err("recipient balance overflow must fail");
    assert!(
        err_rec.contains("Recipient balance overflows"),
        "expected recipient overflow error, got: {err_rec}"
    );
    let sender_after = client
        .state_engine
        .get_account(&sender)
        .await
        .expect("sender exists");
    assert_eq!(sender_after.balance, initial_sender_bal);
    assert_eq!(sender_after.nonce, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn w6_a6_11_private_files_written_with_0600_mode() {
    use std::os::unix::fs::PermissionsExt;

    let home = isolated_home();
    let dir = unique_temp_dir("stell_w9_perms");
    let custom_file = dir.join("cache_test.bin");

    // Pre-create with 0o644 to verify write_private_file tightens permissions to 0o600.
    std::fs::write(&custom_file, b"stale").expect("write stale");
    std::fs::set_permissions(&custom_file, std::fs::Permissions::from_mode(0o644))
        .expect("set 0644");

    client::write_private_file(&custom_file, b"private-data").expect("write_private_file");
    let mode = std::fs::metadata(&custom_file)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "write_private_file must enforce 0600 mode");

    // Also verify LightClient state_cache.bin, tx_history.json, local_txs.bin get 0600.
    let client = LightClient::connect(None).await.expect("local connect");
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let sender = kp.derive_address(&DEFAULT_SALT);
    client
        .state_engine
        .update_account(AccountState::new(sender, 10_000_000_000))
        .await;
    client.persist_cache().await;
    client.record_tx(TxRecord {
        timestamp: 1,
        tx_hash: "aa".repeat(32),
        from: hex::encode(sender),
        to: "bb".repeat(32),
        amount_stell: 1.0,
        fee_stell: 0.000325,
        is_confidential: false,
        status: "test".to_string(),
    });
    let tx = LightClient::build_pq_transfer_tx_bound(
        &kp,
        [0x55u8; 32],
        1_000_000,
        500_000,
        0,
        0,
        0,
        true,
        5757,
    )
    .expect("build private-files tx");
    let _ = client.broadcast_tx(&tx).await.expect("local broadcast");

    let stell_dir = home.join(".stellereum");
    for name in ["state_cache.bin", "tx_history.json", "local_txs.bin"] {
        let p = stell_dir.join(name);
        assert!(p.exists(), "expected {p:?} to exist");
        let file_mode = std::fs::metadata(&p)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "{name} must have mode 0600");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// UX + W6-A6-10: `stell pay` accepts `Stl57...` & `stell aa` fails closed
// ---------------------------------------------------------------------------

#[test]
fn ux_pay_accepts_stl57_address_and_aa_fails_closed() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let dir = unique_temp_dir("stell_w9_cli");
    let wallet = dir.join("wallet.json");
    let password = "test_password_12345";

    let create = Command::new(bin)
        .env("HOME", &dir)
        .env_remove("STELL_RPC_URL")
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "new",
            "--password",
            password,
        ])
        .output()
        .expect("create wallet");
    assert!(
        create.status.success(),
        "wallet creation failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    // `stell pay` must accept an Stl57... recipient address.
    let recipient = [0x57u8; 32];
    let stl57_addr = stellereum::address::encode_stl57_address(&recipient);
    let pay_out = Command::new(bin)
        .env("HOME", &dir)
        .env_remove("STELL_RPC_URL")
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "pay",
            &stl57_addr,
            "1.5",
            "--password",
            password,
            "--dry-run",
        ])
        .output()
        .expect("run pay with Stl57 address");
    assert!(
        pay_out.status.success(),
        "pay with Stl57 address failed: {}",
        String::from_utf8_lossy(&pay_out.stderr)
    );
    let pay_stdout = String::from_utf8_lossy(&pay_out.stdout);
    assert!(pay_stdout.contains("DRY RUN"), "{pay_stdout}");
    assert!(
        pay_stdout.contains(&hex::encode(recipient)),
        "decoded recipient hex missing from dry-run output: {pay_stdout}"
    );

    // `stell aa` subcommands must fail closed rather than printing fake on-chain success.
    for args in [
        vec!["aa", "list"],
        vec!["aa", "new", "--name", "test", "--password", password],
        vec![
            "aa",
            "session",
            "obj1",
            "--service",
            "dex.stl",
            "--budget",
            "1.0",
            "--password",
            password,
        ],
        vec![
            "aa",
            "adjust-budget",
            "obj1",
            "--session",
            "1",
            "--budget",
            "2.0",
            "--password",
            password,
        ],
        vec![
            "aa",
            "rent",
            "obj1",
            "--tenant",
            "00",
            "--password",
            password,
        ],
        vec!["aa", "revoke-rent", "obj1", "--password", password],
    ] {
        let aa_out = Command::new(bin)
            .env("HOME", &dir)
            .env_remove("STELL_RPC_URL")
            .arg("--wallet")
            .arg(wallet.to_str().unwrap())
            .args(&args)
            .output()
            .expect("run aa subcommand");
        assert!(!aa_out.status.success(), "aa {:?} must fail closed", args);
        let stdout = String::from_utf8_lossy(&aa_out.stdout);
        let stderr = String::from_utf8_lossy(&aa_out.stderr);
        assert!(!stdout.contains("ACTIVE"), "{stdout}");
        assert!(!stdout.contains("BUDGET UPDATED ON-CHAIN"), "{stdout}");
        assert!(!stdout.contains("RENTAL DELEGATED"), "{stdout}");
        assert!(
            stderr.contains("SysCallCallContractArgs"),
            "expected explicit contract/RPC error for {:?}: {stderr}",
            args
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// W6-A6-8: memory zeroization on drop & HardenedNotesStore secret roundtrip
// ---------------------------------------------------------------------------

#[test]
fn w6_a6_8_notes_encrypt_decrypt_and_zeroization_on_drop() {
    let secret = [0x42u8; 32];
    let wrong_secret = [0x99u8; 32];
    let sample_notes = vec![notes::ShieldedNote {
        commitment: "aa".repeat(32),
        amount: 12_345_678_900,
        blinding: "bb".repeat(32),
        height: 17,
        spent: false,
    }];

    let store = notes::HardenedNotesStore::encrypt_with_secret(&sample_notes, &secret)
        .expect("encrypt_with_secret");
    let decrypted = store
        .decrypt_with_secret(&secret)
        .expect("decrypt_with_secret");
    assert_eq!(decrypted, sample_notes);
    assert!(
        store.decrypt_with_secret(&wrong_secret).is_err(),
        "wrong secret must fail"
    );

    // Early-error path (bad nonce length) must fail cleanly without panicking.
    let mut bad_nonce = store.clone();
    bad_nonce.nonce_hex = "00".repeat(12);
    assert!(bad_nonce.decrypt_with_secret(&secret).is_err());

    // Verify stack `Zeroizing<[u8; 48]>` (notes KDF material) scrubs on drop.
    let mut mat_slot = std::mem::MaybeUninit::new(zeroize::Zeroizing::new([0x5Au8; 48]));
    // SAFETY: `mat_slot` is initialized above and stays live on the stack across drop_in_place.
    let mat_ptr: *const u8 = unsafe { (*mat_slot.as_ptr()).as_ptr() };
    for i in 0..48 {
        // SAFETY: `mat_ptr.add(i)` is within the initialized 48-byte stack slot.
        assert_eq!(unsafe { std::ptr::read_volatile(mat_ptr.add(i)) }, 0x5A);
    }
    // SAFETY: `mat_slot` is initialized; dropping in place runs `Zeroizing::drop`.
    unsafe { std::ptr::drop_in_place(mat_slot.as_mut_ptr()) };
    for i in 0..48 {
        // SAFETY: `mat_slot` stack memory remains allocated; reading volatile checks scrubbing.
        assert_eq!(
            unsafe { std::ptr::read_volatile(mat_ptr.add(i)) },
            0,
            "Zeroizing<[u8; 48]> byte {i} was not scrubbed on drop"
        );
    }

    // Verify `SecureSecret` scrubs its 32-byte key buffer on drop.
    let mut sec_slot = std::mem::MaybeUninit::new(security::SecureSecret::new([0xA5u8; 32]));
    // SAFETY: `sec_slot` is initialized above and stays live on the stack across drop_in_place.
    let sec_ptr: *const u8 = unsafe { (*sec_slot.as_ptr()).bytes.as_ptr() };
    for i in 0..32 {
        // SAFETY: `sec_ptr.add(i)` is within the initialized 32-byte stack slot.
        assert_eq!(unsafe { std::ptr::read_volatile(sec_ptr.add(i)) }, 0xA5);
    }
    // SAFETY: `sec_slot` is initialized; dropping in place runs `SecureSecret::drop`.
    unsafe { std::ptr::drop_in_place(sec_slot.as_mut_ptr()) };
    for i in 0..32 {
        // SAFETY: `sec_slot` stack memory remains allocated; reading volatile checks scrubbing.
        assert_eq!(
            unsafe { std::ptr::read_volatile(sec_ptr.add(i)) },
            0,
            "SecureSecret byte {i} was not scrubbed on drop"
        );
    }
}

// ---------------------------------------------------------------------------
// Wave 19D: Falcon-512-only error handling (no panics) + PqStatus / REPL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w19d_falcon512_only_error_handling_no_panics() {
    let seed = [0x33u8; 32];
    let to = [0x77u8; 32];

    for bad_scheme in [PqScheme::Hybrid, PqScheme::Ed25519, PqScheme::MlDsa44] {
        let kp = pq::PqKeyPair::from_seed(bad_scheme, &seed);
        assert!(
            bad_scheme.try_consensus_scheme().is_err(),
            "{bad_scheme} must be refused by try_consensus_scheme"
        );

        let err1 = LightClient::build_pq_transfer_tx(&kp, to, 1_000, 0, 0, true)
            .expect_err("non-Falcon512 transfer must return Err, not panic");
        assert!(err1.contains("Falcon512"), "unexpected err: {err1}");

        let err2 =
            LightClient::build_pq_transfer_tx_with_gas(&kp, to, 1_000, 325_000, 0, 0, 0, true)
                .expect_err("non-Falcon512 transfer_with_gas must return Err");
        assert!(err2.contains("Falcon512"), "unexpected err: {err2}");

        let err3 =
            LightClient::build_pq_transfer_tx_bound(&kp, to, 1_000, 325_000, 0, 0, 0, true, 5757)
                .expect_err("non-Falcon512 transfer_bound must return Err");
        assert!(err3.contains("Falcon512"), "unexpected err: {err3}");

        let err4 = LightClient::build_pq_payload_tx(&kp, to, 0, 325_000, 0, 0, 0, true, Vec::new())
            .expect_err("non-Falcon512 payload must return Err");
        assert!(err4.contains("Falcon512"), "unexpected err: {err4}");

        let err5 = LightClient::build_pq_payload_tx_bound(
            &kp,
            to,
            0,
            325_000,
            0,
            0,
            0,
            true,
            Vec::new(),
            5757,
        )
        .expect_err("non-Falcon512 payload_bound must return Err");
        assert!(err5.contains("Falcon512"), "unexpected err: {err5}");
    }

    assert!(PqScheme::Falcon512.try_consensus_scheme().is_ok());

    // TryFrom<WalletScheme> refuses Hybrid/Ed25519 cleanly without panicking.
    assert!(stellereum::post_quantum::PqScheme::try_from(pq::WalletScheme::Falcon512).is_ok());
    assert!(stellereum::post_quantum::PqScheme::try_from(pq::WalletScheme::Hybrid).is_err());
    assert!(stellereum::post_quantum::PqScheme::try_from(pq::WalletScheme::Ed25519).is_err());

    // PqKeyPair::try_sign and sign_hybrid return Err on disabled/short inputs instead of panicking.
    let mldsa_kp = pq::PqKeyPair::from_seed(PqScheme::MlDsa44, &seed);
    assert!(mldsa_kp.try_sign(b"msg").is_err());
    assert!(pq::sign_hybrid(&[0u8; 16], &[0u8; 32], b"msg").is_err());
    assert!(pq::sign_hybrid(&[0u8; 64], &[0u8; 8], b"msg").is_err());

    // LightClient::chain_id propagates RPC lookup error instead of panicking.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let closed_port = listener.local_addr().expect("local addr").port();
    drop(listener);
    let _home = isolated_home();
    let rpc_client = LightClient::connect_rpc(
        &format!("http://127.0.0.1:{closed_port}/"),
        None,
        None,
        1,
        1,
    )
    .await
    .expect("connect_rpc");
    assert!(
        rpc_client.chain_id().is_err(),
        "chain_id must return Err when node RPC is unreachable"
    );
}

#[test]
fn w19d_pq_status_repl_defaults_and_activation_flag() {
    use std::io::Write;
    use std::process::Stdio;

    let bin = env!("CARGO_BIN_EXE_stell");
    let dir = unique_temp_dir("stell_w19d_cli");
    let wallet = dir.join("wallet.json");
    let password = "w19d_test_password";

    // 1. PqStatus honestly reports ML-DSA-44 and Hybrid as disabled/refused (Falcon-512 only).
    let status_out = Command::new(bin)
        .env("HOME", &dir)
        .env_remove("STELL_RPC_URL")
        .args(["pq-status"])
        .output()
        .expect("run pq-status");
    assert!(status_out.status.success());
    let status_stdout = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        status_stdout.contains("DISABLED / REFUSED"),
        "pq-status must report disabled schemes honestly:\n{status_stdout}"
    );
    assert!(
        status_stdout.contains("Falcon-512 only"),
        "pq-status must report Falcon-512 only enforcement:\n{status_stdout}"
    );

    // 2. Create wallet and verify REPL defaults (shard 0 / pair 0) match CLI defaults.
    let create = Command::new(bin)
        .env("HOME", &dir)
        .env_remove("STELL_RPC_URL")
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "new",
            "--password",
            password,
        ])
        .output()
        .expect("create wallet");
    assert!(
        create.status.success(),
        "wallet creation failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let mut repl = Command::new(bin)
        .env("HOME", &dir)
        .env_remove("STELL_RPC_URL")
        .args(["--wallet", wallet.to_str().unwrap(), "console"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn console");
    {
        let stdin = repl.stdin.as_mut().expect("stdin");
        stdin
            .write_all(b"balance\nbook\nexit\n")
            .expect("write repl commands");
    }
    let repl_out = repl.wait_with_output().expect("wait console");
    assert!(
        repl_out.status.success(),
        "console exited with error: {}",
        String::from_utf8_lossy(&repl_out.stderr)
    );
    let repl_stdout = String::from_utf8_lossy(&repl_out.stdout);
    assert!(
        repl_stdout.contains("Shard:         #0"),
        "REPL balance must default to shard #0:\n{repl_stdout}"
    );
    assert!(
        repl_stdout.contains("Trading Pair: #1"),
        "REPL book must default to pair #1 (STELL/USDT):\n{repl_stdout}"
    );

    // 3. `pq-transfer` auto-activates at `nonce == 0` and honors `is_activation = false` for steady-state (`nonce > 0`).
    let to_hex = "ab".repeat(32);
    let tx0_out = Command::new(bin)
        .env("HOME", &dir)
        .env_remove("STELL_RPC_URL")
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "pq-transfer",
            &to_hex,
            "1.0",
            "--scheme",
            "falcon512",
            "--dry-run",
            "--password",
            password,
        ])
        .output()
        .expect("run pq-transfer at nonce 0");
    assert!(tx0_out.status.success());
    let tx0_stdout = String::from_utf8_lossy(&tx0_out.stdout);
    assert!(
        tx0_stdout.contains("Explicit Carrier (Tx #1 Account Activation)"),
        "nonce == 0 pq-transfer must auto-select explicit carrier:\n{tx0_stdout}"
    );
    assert!(
        tx0_stdout.contains("325000 nano-STELL"),
        "explicit pq-transfer should include activation surcharge (325000):\n{tx0_stdout}"
    );

    let kp = pq::PqKeyPair::from_seed(pq::PqScheme::Falcon512, &[0x5Au8; 32]);
    let implicit_tx = client::LightClient::build_pq_transfer_tx_bound(
        &kp,
        [0xABu8; 32],
        1_000_000_000,
        stellereum::svm::GAS_BASIC_TRANSFER,
        1,
        0,
        0,
        false,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("steady-state implicit pq transfer");
    assert!(implicit_tx.is_pq_implicit());
    assert_eq!(implicit_tx.gas_limit, 280_000);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Wave 22A: canonical salted PQ1, bounded HTTP/IPv6 token policy, bounded cache
// ---------------------------------------------------------------------------

#[test]
fn w22a_pq_transfer_with_gas_and_payload_tx_emit_canonical_salted_pq1() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let from_addr = kp.derive_address(&DEFAULT_SALT);
    let to = [0x88u8; 32];

    // 1. build_pq_transfer_tx_with_gas: explicit activation carrier includes 16-byte salt.
    let tx_explicit =
        LightClient::build_pq_transfer_tx_with_gas(&kp, to, 1_000_000, 325_000, 0, 0, 0, true)
            .expect("build explicit transfer_with_gas");
    let env_explicit =
        stellereum::sharding::PqSignatureEnvelope::decode_canonical(&tx_explicit.signature)
            .expect("explicit transfer_with_gas must decode canonically");
    assert!(!env_explicit.is_implicit);
    assert_eq!(
        env_explicit.scheme,
        stellereum::post_quantum::PqScheme::Falcon512
    );
    assert_eq!(env_explicit.salt, DEFAULT_SALT);
    assert_eq!(env_explicit.pubkey.as_deref(), Some(kp.public_key()));
    assert!(tx_explicit.pq_envelope_canonical().is_some());
    assert!(
        tx_explicit.verify_signature(),
        "explicit transfer_with_gas signature must verify"
    );

    // 2. build_pq_transfer_tx_with_gas: implicit steady-state carrier.
    let tx_implicit =
        LightClient::build_pq_transfer_tx_with_gas(&kp, to, 1_000_000, 280_000, 1, 0, 0, false)
            .expect("build implicit transfer_with_gas");
    let env_implicit =
        stellereum::sharding::PqSignatureEnvelope::decode_canonical(&tx_implicit.signature)
            .expect("implicit transfer_with_gas must decode canonically");
    assert!(env_implicit.is_implicit);
    assert_eq!(
        env_implicit.scheme,
        stellereum::post_quantum::PqScheme::Falcon512
    );
    assert_eq!(env_implicit.pubkey, None);
    assert!(tx_implicit.pq_envelope_canonical().is_some());
    assert!(
        tx_implicit.verify_signature(),
        "implicit transfer_with_gas signature must verify"
    );

    // 3. build_pq_payload_tx: explicit activation carrier includes 16-byte salt.
    let payload = vec![stellereum::svm::OpCode::SysCallStake {
        validator: [0x99u8; 32],
        amount: 5_000_000_000,
    }];
    let ptx_explicit = LightClient::build_pq_payload_tx(
        &kp,
        from_addr,
        0,
        500_000,
        2,
        0,
        0,
        true,
        payload.clone(),
    )
    .expect("build explicit payload tx");
    let penv_explicit =
        stellereum::sharding::PqSignatureEnvelope::decode_canonical(&ptx_explicit.signature)
            .expect("explicit payload tx must decode canonically");
    assert!(!penv_explicit.is_implicit);
    assert_eq!(
        penv_explicit.scheme,
        stellereum::post_quantum::PqScheme::Falcon512
    );
    assert_eq!(penv_explicit.salt, DEFAULT_SALT);
    assert_eq!(penv_explicit.pubkey.as_deref(), Some(kp.public_key()));
    assert!(ptx_explicit.pq_envelope_canonical().is_some());
    assert!(
        ptx_explicit.verify_signature(),
        "explicit payload tx signature must verify"
    );

    // 4. build_pq_payload_tx: implicit steady-state carrier.
    let ptx_implicit =
        LightClient::build_pq_payload_tx(&kp, from_addr, 0, 500_000, 3, 0, 0, false, payload)
            .expect("build implicit payload tx");
    let penv_implicit =
        stellereum::sharding::PqSignatureEnvelope::decode_canonical(&ptx_implicit.signature)
            .expect("implicit payload tx must decode canonically");
    assert!(penv_implicit.is_implicit);
    assert_eq!(
        penv_implicit.scheme,
        stellereum::post_quantum::PqScheme::Falcon512
    );
    assert_eq!(penv_implicit.pubkey, None);
    assert!(ptx_implicit.pq_envelope_canonical().is_some());
    assert!(
        ptx_implicit.verify_signature(),
        "implicit payload tx signature must verify"
    );
}

#[test]
fn w22a_http_token_policy_and_bounded_http_read() {
    let tok = Some("secret-api-token");
    for allowed in [
        "http://[::1]/",
        "http://[::1]:8545/",
        "http://[::1]",
        "http://[::1]:8545",
        "http://127.0.0.1:8545/",
        "http://localhost:8545/",
    ] {
        assert!(
            rpc::check_http_token_policy(allowed, tok).is_ok(),
            "loopback URL {allowed} should be allowed with API token"
        );
    }

    for refused in [
        "http://127.0.0.1:x@evil.com/",
        "http://127.0.0.1:8545@evil.com/",
        "http://[::1]@evil.com/",
        "http://[::2]:8545/",
        "http://[::1]:badport/",
        "http://[::1]evil.com/",
        "http://localhost.evil.com:8545/",
    ] {
        let err = rpc::check_http_token_policy(refused, tok)
            .expect_err("non-loopback or userinfo-confused URL must be refused");
        assert!(
            err.contains("cleartext http"),
            "unexpected error for {refused}: {err}"
        );
    }

    // Strict HTTP 200 status-line parsing (reject 400 containing " 200" or 2000).
    for bad_status in ["HTTP/1.1 400 Bad 200", "HTTP/1.1 2000 OK"] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let status_line = bad_status.to_string();
        let handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 1024];
                let _ = stream.read(&mut req_buf);
                let resp = format!(
                    "{status_line}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfail"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let cfg = RpcConfig {
            url: format!("http://127.0.0.1:{port}/"),
            auth_token: None,
            faucet_token: None,
        };
        let err = rpc::chain_id(&cfg).expect_err("non-200 HTTP status must fail");
        assert!(
            err.contains("HTTP "),
            "expected HTTP status error for {bad_status}, got: {err}"
        );
        let _ = handle.join();
    }

    // Bounded HTTP read (> MAX_RPC_RESPONSE_BYTES must fail cleanly).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock listener");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
            let chunk = vec![b' '; 64 * 1024];
            let target = rpc::MAX_RPC_RESPONSE_BYTES + 1024;
            let mut sent = 0usize;
            while sent < target {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
                sent += chunk.len();
            }
        }
    });
    let cfg = RpcConfig {
        url: format!("http://127.0.0.1:{port}/"),
        auth_token: None,
        faucet_token: None,
    };
    let err = rpc::chain_id(&cfg).expect_err("oversized HTTP response must fail");
    assert!(
        err.contains("exceeded max size"),
        "expected max size error, got: {err}"
    );
    let _ = handle.join();
}

#[tokio::test]
async fn w22a_recent_local_txs_bounded_at_max_history() {
    let home = isolated_home();
    let client = LightClient::connect(None).await.expect("local connect");
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let sender = kp.derive_address(&DEFAULT_SALT);
    let recipient = [0x5Au8; 32];

    client
        .state_engine
        .update_account(AccountState::new(sender, 1_000_000_000_000))
        .await;

    let start_nonce = client::MAX_LOCAL_TX_HISTORY as u64 - 2;
    {
        let mut list = client
            .recent_local_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        list.clear();
        for nonce in 0..start_nonce {
            list.push(stellereum::sharding::Transaction {
                from: sender,
                to: recipient,
                amount: 1_000,
                gas_limit: stellereum::svm::GAS_BASIC_TRANSFER,
                nonce,
                source_shard: 0,
                target_shard: 0,
                signature: Vec::new(),
                payload: Vec::new(),
                priority_fee_per_gas: 0,
            });
        }
    }

    for i in 0..5u64 {
        let tx = LightClient::build_pq_transfer_tx_bound(
            &kp,
            recipient,
            1_000_000,
            500_000,
            start_nonce + i,
            0,
            0,
            true,
            stellereum::zkml::DEFAULT_CHAIN_ID,
        )
        .expect("build tx");
        client.broadcast_tx(&tx).await.expect("local broadcast");
    }

    {
        let list = client
            .recent_local_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(list.len(), client::MAX_LOCAL_TX_HISTORY);
        assert_eq!(list.first().unwrap().nonce, 3);
        assert_eq!(list.last().unwrap().nonce, start_nonce + 4);
    }

    // Verify LightClient::connect also caps oversized local_txs.bin on load.
    let local_txs_path = home.join(".stellereum").join("local_txs.bin");
    let oversized: Vec<stellereum::sharding::Transaction> =
        (0..(client::MAX_LOCAL_TX_HISTORY as u64 + 10))
            .map(|nonce| stellereum::sharding::Transaction {
                from: sender,
                to: recipient,
                amount: 1_000,
                gas_limit: stellereum::svm::GAS_BASIC_TRANSFER,
                nonce,
                source_shard: 0,
                target_shard: 0,
                signature: Vec::new(),
                payload: Vec::new(),
                priority_fee_per_gas: 0,
            })
            .collect();
    let bytes = bincode::serialize(&oversized).expect("serialize oversized local_txs");
    client::write_private_file(&local_txs_path, &bytes).expect("write oversized local_txs.bin");

    let reloaded = LightClient::connect(None)
        .await
        .expect("reload local client");
    let reloaded_list = reloaded
        .recent_local_txs
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert_eq!(reloaded_list.len(), client::MAX_LOCAL_TX_HISTORY);
    assert!(reloaded_list.first().unwrap().nonce >= 10);
}
