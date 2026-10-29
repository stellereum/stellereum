//! Comprehensive Integration Test Suite for Wallet Privacy Features
//!
//! Tests:
//! 1. Automated note saving on shield (`stell shield` / `ConfidentialShield`)
//! 2. Balance calculation of shielded notes (`stell shield-balance` / `confidential-balance`)
//! 3. Automatic note selection on unshield (`stell unshield` / `ConfidentialUnshield`)
//! 4. Real stealth address pay (`stell stealth-pay`) and derived one-time key spending

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/pq.rs"]
mod pq;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/notes.rs"]
mod notes;

use client::LightClient;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use notes::{
    add_note, calculate_shielded_balance, get_unspent_notes, load_notes, mark_notes_spent,
    select_notes_for_unshield, ShieldedNote,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use stellereum::crypto_privacy::{verify_stealth_signature, PedersenCommitment, StealthAddress};
use stellereum::wallet::WalletAccount;

fn make_temp_dir(label: &str) -> std::path::PathBuf {
    let rand_suffix: u64 = rand::random();
    let dir = std::env::temp_dir().join(format!("stell_test_{label}_{rand_suffix}"));
    fs::create_dir_all(&dir).expect("Failed to create temp directory");
    dir
}

/// Binds a temp notes/stealth store to a dummy wallet keystore: the legacy
/// wallet-bound KDF is fail-closed without it (never a salt-only key).
fn bind_dummy_wallet(dir: &std::path::Path) {
    let wallet_path = dir.join("wallet.json");
    if !wallet_path.exists() {
        fs::write(&wallet_path, b"{\"dummy\":\"wallet-binding-for-tests\"}")
            .expect("Failed to write dummy wallet binding");
    }
}

// =============================================================================
// 1. Automated Note Saving on Shield
// =============================================================================

#[tokio::test]
async fn test_automated_note_saving_on_shield() {
    let dir = make_temp_dir("shield_save");
    bind_dummy_wallet(&dir);
    let notes_path = dir.join("shielded_notes.json");
    let client = LightClient::connect(None).await.expect("connect client");

    let seed = [0x11u8; 32];
    let account = WalletAccount::from_seed(&seed);

    // Initial funding
    let initial_balance = 50_000_000_000u64; // 50 STELL
    client
        .set_balance(account.address, initial_balance, 0)
        .await;

    // Shield 15 STELL
    let shield_amount = 15_000_000_000u64;
    let blinding = PedersenCommitment::random_blinding().to_bytes();
    let nonce = client.nonce_of(&account.address).await.unwrap();

    let (tx_hash, finality, commitment_hex) = client
        .broadcast_shield_tx(&account.signing_key, shield_amount, blinding, nonce, 0)
        .await
        .expect("broadcast_shield_tx must succeed");

    assert!(!tx_hash.is_empty());
    assert!(!finality.is_failed());
    assert!(!commitment_hex.is_empty());

    // Automatically record note in store
    let note = ShieldedNote {
        commitment: commitment_hex.clone(),
        amount: shield_amount,
        blinding: hex::encode(blinding),
        height: 1,
        spent: false,
    };
    add_note(&notes_path, note).expect("add_note must succeed");

    // Verify stored note integrity
    let loaded = load_notes(&notes_path).expect("load_notes must succeed");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].commitment, commitment_hex);
    assert_eq!(loaded[0].amount, shield_amount);
    assert_eq!(loaded[0].blinding, hex::encode(blinding));
    assert_eq!(loaded[0].height, 1);
    assert!(!loaded[0].spent);

    // Verify strict file permissions (0600)
    let meta = fs::metadata(&notes_path).expect("metadata must exist");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Notes file must be chmod 0600 (owner only)");

    // Clean up
    let _ = fs::remove_dir_all(&dir);
}

// =============================================================================
// 2. Balance Calculation of Shielded Notes
// =============================================================================

#[test]
fn test_balance_calculation_of_shielded_notes() {
    let dir = make_temp_dir("shield_balance");
    bind_dummy_wallet(&dir);
    let notes_path = dir.join("shielded_notes.json");

    let n1 = ShieldedNote {
        commitment: "0101010101010101010101010101010101010101010101010101010101010101".to_string(),
        amount: 5_000_000_000, // 5 STELL
        blinding: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        height: 100,
        spent: false,
    };
    let n2 = ShieldedNote {
        commitment: "0202020202020202020202020202020202020202020202020202020202020202".to_string(),
        amount: 10_000_000_000, // 10 STELL
        blinding: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        height: 101,
        spent: false,
    };
    let n3 = ShieldedNote {
        commitment: "0303030303030303030303030303030303030303030303030303030303030303".to_string(),
        amount: 25_000_000_000, // 25 STELL
        blinding: "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        height: 102,
        spent: false,
    };

    add_note(&notes_path, n1).unwrap();
    add_note(&notes_path, n2.clone()).unwrap();
    add_note(&notes_path, n3).unwrap();

    let unspent = get_unspent_notes(&notes_path).unwrap();
    assert_eq!(unspent.len(), 3);
    assert_eq!(calculate_shielded_balance(&unspent), 40_000_000_000);

    // Spend n2 (10 STELL)
    mark_notes_spent(&notes_path, &[n2.commitment]).unwrap();

    let unspent_after = get_unspent_notes(&notes_path).unwrap();
    assert_eq!(unspent_after.len(), 2);
    assert_eq!(calculate_shielded_balance(&unspent_after), 30_000_000_000);

    // All notes loaded includes spent one
    let all_notes = load_notes(&notes_path).unwrap();
    assert_eq!(all_notes.len(), 3);
    assert!(
        all_notes
            .iter()
            .find(|n| n.amount == 10_000_000_000)
            .unwrap()
            .spent
    );

    let _ = fs::remove_dir_all(&dir);
}

// =============================================================================
// 3. Automatic Note Selection on Unshield
// =============================================================================

#[tokio::test]
async fn test_automatic_note_selection_on_unshield() {
    let dir = make_temp_dir("unshield_auto");
    bind_dummy_wallet(&dir);
    let notes_path = dir.join("shielded_notes.json");
    let client = LightClient::connect(None).await.expect("connect client");

    let seed = [0x22u8; 32];
    let account = WalletAccount::from_seed(&seed);

    // Fund account
    client
        .set_balance(account.address, 100_000_000_000, 0)
        .await;

    // Shield 3 distinct notes on-chain
    let amt1 = 4_000_000_000u64; // 4 STELL
    let amt2 = 6_000_000_000u64; // 6 STELL
    let amt3 = 15_000_000_000u64; // 15 STELL

    let b1 = PedersenCommitment::random_blinding().to_bytes();
    let b2 = PedersenCommitment::random_blinding().to_bytes();
    let b3 = PedersenCommitment::random_blinding().to_bytes();

    let n_nonce = client.nonce_of(&account.address).await.unwrap();
    let (_, _, c1) = client
        .broadcast_shield_tx(&account.signing_key, amt1, b1, n_nonce, 0)
        .await
        .unwrap();
    let (_, _, c2) = client
        .broadcast_shield_tx(&account.signing_key, amt2, b2, n_nonce + 1, 0)
        .await
        .unwrap();
    let (_, _, c3) = client
        .broadcast_shield_tx(&account.signing_key, amt3, b3, n_nonce + 2, 0)
        .await
        .unwrap();

    add_note(
        &notes_path,
        ShieldedNote {
            commitment: c1.clone(),
            amount: amt1,
            blinding: hex::encode(b1),
            height: 1,
            spent: false,
        },
    )
    .unwrap();
    add_note(
        &notes_path,
        ShieldedNote {
            commitment: c2.clone(),
            amount: amt2,
            blinding: hex::encode(b2),
            height: 1,
            spent: false,
        },
    )
    .unwrap();
    add_note(
        &notes_path,
        ShieldedNote {
            commitment: c3.clone(),
            amount: amt3,
            blinding: hex::encode(b3),
            height: 1,
            spent: false,
        },
    )
    .unwrap();

    // Test 1: Single exact note match for 15 STELL
    let sel_single = select_notes_for_unshield(&notes_path, 15_000_000_000)
        .expect("Must find exact 15 STELL note");
    assert_eq!(sel_single.len(), 1);
    assert_eq!(sel_single[0].amount, 15_000_000_000);
    assert_eq!(sel_single[0].commitment, c3);

    // Test 2: Multi-note combination match for 10 STELL (4 STELL + 6 STELL)
    let sel_combo =
        select_notes_for_unshield(&notes_path, 10_000_000_000).expect("Must combine 4 + 6 STELL");
    assert_eq!(sel_combo.len(), 2);
    let total_combo: u64 = sel_combo.iter().map(|n| n.amount).sum();
    assert_eq!(total_combo, 10_000_000_000);

    // Test 3: Perform on-chain unshield with the auto-selected notes (4 + 6 STELL)
    let cs = sel_combo
        .iter()
        .map(|n| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hex::decode(&n.commitment).unwrap());
            arr
        })
        .collect::<Vec<_>>();
    let ams = sel_combo.iter().map(|n| n.amount).collect::<Vec<_>>();
    let bs = sel_combo
        .iter()
        .map(|n| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hex::decode(&n.blinding).unwrap());
            arr
        })
        .collect::<Vec<_>>();

    let unshield_nonce = client.nonce_of(&account.address).await.unwrap();
    let (tx_hash, finality) = client
        .broadcast_unshield_tx(
            &account.signing_key,
            cs.clone(),
            ams.clone(),
            bs.clone(),
            unshield_nonce,
            0,
        )
        .await
        .expect("broadcast_unshield_tx must succeed");

    assert!(!tx_hash.is_empty());
    assert!(!finality.is_failed());

    // Mark the auto-selected notes spent in the store
    let spent_comms: Vec<String> = sel_combo.iter().map(|n| n.commitment.clone()).collect();
    mark_notes_spent(&notes_path, &spent_comms).unwrap();

    // Verify remaining unspent notes in store
    let remaining_unspent = get_unspent_notes(&notes_path).unwrap();
    assert_eq!(remaining_unspent.len(), 1);
    assert_eq!(remaining_unspent[0].commitment, c3);
    assert_eq!(
        calculate_shielded_balance(&remaining_unspent),
        15_000_000_000
    );

    // Test 4: Insufficient funds rejection
    let err_exceed = select_notes_for_unshield(&notes_path, 20_000_000_000);
    assert!(err_exceed.is_err());
    assert!(err_exceed
        .unwrap_err()
        .contains("Insufficient shielded balance"));

    // Test 5: Exact combination unattainable rejection (only 15 STELL remains, request 7 STELL)
    let err_no_subset = select_notes_for_unshield(&notes_path, 7_000_000_000);
    assert!(err_no_subset.is_err());
    assert!(err_no_subset
        .unwrap_err()
        .contains("No combination of unspent shielded notes"));

    let _ = fs::remove_dir_all(&dir);
}

// =============================================================================
// 4. Real Stealth Address Pay and Derived One-Time Key Spending
// =============================================================================

#[tokio::test]
async fn test_real_stealth_address_pay_and_derived_spending() {
    let client = LightClient::connect(None).await.expect("connect client");

    // Alice (Sender)
    let alice_seed = [0xAAu8; 32];
    let alice = WalletAccount::from_seed(&alice_seed);
    client.set_balance(alice.address, 50_000_000_000, 0).await; // 50 STELL

    // Bob (Recipient)
    let bob_seed = [0xBBu8; 32];
    let bob = WalletAccount::from_seed(&bob_seed);

    let bob_view_pub = bob.viewing_key.view_pub;
    let bob_spend_pub = bob.spend_pub;

    let bob_view_priv = Scalar::from_bytes_mod_order(bob.viewing_key.view_priv);
    let bob_spend_priv = bob.spend_priv;

    // 1. Alice derives StealthAddress using Bob's view_pub and spend_pub
    let stealth = StealthAddress::generate(&bob_view_pub, &bob_spend_pub)
        .expect("StealthAddress::generate must succeed");

    assert_ne!(stealth.one_time_pub, [0u8; 32]);
    assert_ne!(stealth.ephemeral_pub, [0u8; 32]);
    assert_ne!(stealth.one_time_pub, bob.address);

    // 2. Alice sends a real on-chain transaction to stealth.one_time_pub
    let transfer_amount = 25_000_000_000u64; // 25 STELL
    let nonce = client.nonce_of(&alice.address).await.unwrap();

    let (tx, derived_stealth) = LightClient::build_stealth_pay_tx(
        &alice,
        &bob_view_pub,
        &bob_spend_pub,
        transfer_amount,
        nonce,
        0,
    )
    .expect("build_stealth_pay_tx must succeed");

    assert_eq!(tx.to, derived_stealth.one_time_pub);
    assert_eq!(tx.amount, transfer_amount);
    assert_eq!(
        LightClient::extract_ephemeral_pub(&tx.payload),
        Some(derived_stealth.ephemeral_pub)
    );

    let (tx_hash, finality) = client
        .broadcast_tx(&tx)
        .await
        .expect("broadcast_tx must succeed");
    assert!(!tx_hash.is_empty());
    assert!(!finality.is_failed());

    // 3. Verify on-chain ledger: stealth.one_time_pub received real spendable balance
    let (stealth_balance, _, verified) = client
        .get_balance_spv(&derived_stealth.one_time_pub, 0)
        .await
        .unwrap();
    assert_eq!(stealth_balance, transfer_amount);
    assert!(verified, "Balance in local state cache must be verified");

    // 4. Bob identifies the stealth transaction belongs to him using view private key
    assert_eq!(
        derived_stealth.is_for_recipient(&bob_view_priv, &bob_spend_pub),
        Some(true),
        "Bob must recognize the stealth payment"
    );

    // Charlie (outsider) cannot claim the transaction
    let charlie_seed = [0xCCu8; 32];
    let charlie = WalletAccount::from_seed(&charlie_seed);
    let charlie_view_priv = Scalar::from_bytes_mod_order(charlie.viewing_key.view_priv);
    assert_eq!(
        derived_stealth.is_for_recipient(&charlie_view_priv, &charlie.spend_pub),
        Some(false),
        "Charlie must NOT recognize Bob's stealth payment"
    );

    // 5. Bob derives the one-time private key
    let one_time_priv = derived_stealth
        .derive_one_time_private_key(&bob_view_priv, &bob_spend_priv)
        .expect("Bob must derive one-time private key");

    // Verify cryptographic correspondence: RISTRETTO_BASEPOINT * one_time_priv == stealth.one_time_pub
    let derived_pub = (RISTRETTO_BASEPOINT_POINT * one_time_priv)
        .compress()
        .to_bytes();
    assert_eq!(
        derived_pub, derived_stealth.one_time_pub,
        "Derived one-time public point must match one_time_pub"
    );

    // 6. Bob spends / authorizes spending from stealth.one_time_pub using one_time_priv
    let spend_auth_message = b"Transfer 25 STELL from stealth.one_time_pub to Bob cold storage";
    let sig = derived_stealth.sign(&one_time_priv, spend_auth_message);

    // Verify valid signature against the one-time public key
    assert!(
        StealthAddress::verify_one_time_signature(
            &derived_stealth.one_time_pub,
            spend_auth_message,
            &sig
        ),
        "Signature must verify against one_time_pub"
    );
    assert!(
        verify_stealth_signature(&derived_stealth.one_time_pub, spend_auth_message, &sig),
        "Signature must verify via verify_stealth_signature"
    );

    // Tampered payload rejected
    assert!(
        !verify_stealth_signature(
            &derived_stealth.one_time_pub,
            b"Altered transfer memo",
            &sig
        ),
        "Tampered spend payload must fail verification"
    );

    // 7. Bob scans stealth payments from blockchain
    let scanned = client
        .scan_stealth_payments(&bob_view_priv, &bob_spend_pub)
        .await
        .expect("scan_stealth_payments must succeed");
    assert!(
        !scanned.is_empty(),
        "Bob must discover at least 1 stealth payment"
    );
    let matching = scanned
        .iter()
        .find(|(s, _, _, _)| s.one_time_pub == derived_stealth.one_time_pub);
    assert!(
        matching.is_some(),
        "Bob must find the payment to derived_stealth"
    );
    assert_eq!(
        matching.unwrap().0.ephemeral_pub,
        derived_stealth.ephemeral_pub
    );
    assert_eq!(matching.unwrap().1, transfer_amount);

    let charlie_scanned = client
        .scan_stealth_payments(&charlie_view_priv, &charlie.spend_pub)
        .await
        .expect("charlie scan must succeed");
    assert!(
        charlie_scanned.is_empty(),
        "Charlie must discover 0 stealth payments"
    );

    // 8. Bob spends from stealth.one_time_pub to Bob's main address
    let (bob_before, _, _) = client.get_balance_spv(&bob.address, 0).await.unwrap();
    let spend_gas = 10_000u64;
    let spend_amount = transfer_amount - spend_gas;
    let spend_tx = LightClient::build_stealth_spend_tx(
        &one_time_priv,
        derived_stealth.one_time_pub,
        bob.address,
        spend_amount,
        spend_gas,
        0,
        0,
    );
    assert!(
        spend_tx.verify_signature(),
        "Stealth spend transaction signature must verify via Schnorr stealth signature"
    );
    let (spend_hash, spend_finality) = client
        .broadcast_tx(&spend_tx)
        .await
        .expect("spend broadcast must succeed");
    assert!(!spend_hash.is_empty());
    assert!(!spend_finality.is_failed());

    let (bob_final_bal, _, _) = client.get_balance_spv(&bob.address, 0).await.unwrap();
    assert_eq!(bob_final_bal, bob_before + spend_amount);
}

// =============================================================================
// 5. CLI Command Integration Tests
// =============================================================================

#[test]
fn test_cli_stealth_pay_and_shield_balance_workflow() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let dir = make_temp_dir("cli_privacy");
    let wallet_path = dir.join("wallet.json");

    // 1. Initialize new wallet
    let init_out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "new",
            "--password",
            "TestPass#2026",
            "--scheme",
            "ed25519",
        ])
        .output()
        .expect("exec new");
    assert!(init_out.status.success());

    // 2. Fund via faucet (simulated)
    let faucet_out = Command::new(bin)
        .args(["--wallet", wallet_path.to_str().unwrap(), "faucet", "100"])
        .output()
        .expect("exec faucet");
    assert!(faucet_out.status.success());

    // 3. Shield 20 STELL
    let shield_out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "shield",
            "20",
            "--password",
            "TestPass#2026",
        ])
        .output()
        .expect("exec shield");
    assert!(shield_out.status.success());
    let shield_stdout = String::from_utf8_lossy(&shield_out.stdout);
    assert!(shield_stdout.contains("SHIELDED (SUBMITTED)"));
    assert!(shield_stdout.contains("Commitment:"));
    assert!(shield_stdout.contains("Note Store:"));

    // 4. Check shield-balance
    let bal_out = Command::new(bin)
        .args(["--wallet", wallet_path.to_str().unwrap(), "shield-balance"])
        .output()
        .expect("exec shield-balance");
    assert!(bal_out.status.success());
    let bal_stdout = String::from_utf8_lossy(&bal_out.stdout);
    assert!(bal_stdout.contains("SHIELDED POOL BALANCE"));
    assert!(bal_stdout.contains("Total Shielded:"));
    assert!(bal_stdout.contains("20.000000 STELL"));

    // 5. Check confidential-balance alias
    let conf_bal_out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "confidential-balance",
        ])
        .output()
        .expect("exec confidential-balance");
    assert!(conf_bal_out.status.success());
    assert!(String::from_utf8_lossy(&conf_bal_out.stdout).contains("20.000000 STELL"));

    // 6. Execute stealth-pay to a recipient
    let recipient_account = WalletAccount::from_seed(&[0x77u8; 32]);
    let view_hex = hex::encode(recipient_account.viewing_key.view_pub);
    let spend_hex = hex::encode(recipient_account.spend_pub);

    let stealth_out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "stealth-pay",
            "--view-key",
            &view_hex,
            "--spend-key",
            &spend_hex,
            "10.0",
            "--password",
            "TestPass#2026",
        ])
        .output()
        .expect("exec stealth-pay");
    assert!(stealth_out.status.success());
    let stealth_stdout = String::from_utf8_lossy(&stealth_out.stdout);
    assert!(stealth_stdout.contains("STEALTH PAYMENT BROADCAST"));
    assert!(stealth_stdout.contains("Destination Stealth:"));
    assert!(stealth_stdout.contains("Ephemeral PubKey:"));
    assert!(stealth_stdout.contains("10.0 STELL"));

    // 6.1 Recipient restores wallet and scans for stealth payments
    let recipient_wallet_path = dir.join("rec_wallet.json");
    let rec_restore_out = Command::new(bin)
        .args([
            "--wallet",
            recipient_wallet_path.to_str().unwrap(),
            "restore",
            "--key",
            &hex::encode([0x77u8; 32]),
            "--password",
            "RecPass#2026",
        ])
        .output()
        .expect("exec restore recipient");
    assert!(rec_restore_out.status.success());

    let scan_out = Command::new(bin)
        .args([
            "--wallet",
            recipient_wallet_path.to_str().unwrap(),
            "stealth-scan",
            "--password",
            "RecPass#2026",
        ])
        .output()
        .expect("exec stealth-scan");
    assert!(scan_out.status.success());
    let scan_stdout = String::from_utf8_lossy(&scan_out.stdout);
    assert!(scan_stdout.contains("STEALTH PAYMENTS SCANNER"));
    assert!(scan_stdout.contains("stealth output(s) on-chain"));
    assert!(scan_stdout.contains("10.000000 STELL"));

    // 6.2 Recipient spends from stealth output back to main address
    let spend_out = Command::new(bin)
        .args([
            "--wallet",
            recipient_wallet_path.to_str().unwrap(),
            "stealth-spend",
            "--password",
            "RecPass#2026",
        ])
        .output()
        .expect("exec stealth-spend");
    assert!(spend_out.status.success());
    let spend_stdout = String::from_utf8_lossy(&spend_out.stdout);
    assert!(spend_stdout.contains("STEALTH OUTPUT SPENT & BROADCAST"));
    assert!(spend_stdout.contains("Amount Sent:"));

    // 7. Unshield 20 STELL automatically from notes
    let unshield_out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "unshield",
            "--amount",
            "20",
            "--password",
            "TestPass#2026",
        ])
        .output()
        .expect("exec unshield");
    assert!(unshield_out.status.success());
    let unshield_stdout = String::from_utf8_lossy(&unshield_out.stdout);
    assert!(unshield_stdout.contains("UNSHIELDED (SUBMITTED)"));
    assert!(unshield_stdout.contains("20.000000 STELL"));

    // 8. Shield balance is now 0 STELL
    let bal_after = Command::new(bin)
        .args(["--wallet", wallet_path.to_str().unwrap(), "shield-balance"])
        .output()
        .expect("exec shield-balance after");
    assert!(bal_after.status.success());
    let bal_after_stdout = String::from_utf8_lossy(&bal_after.stdout);
    assert!(bal_after_stdout.contains("0.000000 STELL"));
    assert!(bal_after_stdout.contains("Unspent Notes:   0"));

    let _ = fs::remove_dir_all(&dir);
}
