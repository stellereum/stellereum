//! Comprehensive Tests for Multi-Wallet Management Engine
//!
//! Tests:
//! - Wallet name sanitization and security boundary validation
//! - Creating multiple named wallets (e.g. trading, savings)
//! - Listing all available wallets and active marker integrity
//! - Switching wallets with Argon2id + XChaCha20Poly1305 password verification
//! - Password rejection on wrong credentials (state unchanged)
//! - Switching by address (both raw hex and visual prefix)
//! - Automatic legacy migration from `wallet.json` to `wallets/default.json`
//! - Synchronization with `wallet.json` for backward compatibility

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;
use security::{HardenedKeystore, SecureSecret};

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/wallets.rs"]
mod wallets;
use wallets::{
    get_active_wallet_name, list_wallets, sanitize_wallet_name, save_named_wallet, switch_wallet,
    wallets_dir,
};

fn create_temp_env(test_name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "stell_test_multi_{}_{}",
        test_name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("Failed to create tempdir");
    base
}

#[test]
fn test_wallet_name_sanitization() {
    assert_eq!(sanitize_wallet_name("trading").unwrap(), "trading");
    assert_eq!(sanitize_wallet_name("my-vault").unwrap(), "my-vault");
    assert_eq!(sanitize_wallet_name("account_1").unwrap(), "account_1");
    assert_eq!(sanitize_wallet_name("  savings  ").unwrap(), "savings");

    // Traversal and illegal characters
    assert!(sanitize_wallet_name("").is_err());
    assert!(sanitize_wallet_name("   ").is_err());
    assert!(sanitize_wallet_name(".").is_err());
    assert!(sanitize_wallet_name("..").is_err());
    assert!(sanitize_wallet_name("foo/bar").is_err());
    assert!(sanitize_wallet_name("foo\\bar").is_err());
    assert!(sanitize_wallet_name("hello world").is_err());
    assert!(sanitize_wallet_name("wallet$").is_err());
    assert!(sanitize_wallet_name(&"a".repeat(33)).is_err());
}

#[test]
fn test_multi_wallet_create_list_and_switch_security() {
    let base = create_temp_env("create_switch");

    // 1. Initially empty
    let list0 = list_wallets(Some(&base)).expect("Listing failed");
    assert!(list0.is_empty());

    // 2. Create wallet "savings"
    let secret1 = SecureSecret::new([0x11; 32]);
    let addr1 = "1111111111111111111111111111111111111111111111111111111111111111";
    let pass1 = "SavingsPassword#2026";
    let ks1 = HardenedKeystore::encrypt(&secret1, addr1, pass1).expect("Encrypt 1 failed");
    save_named_wallet("savings", &ks1, Some(&base)).expect("Save savings failed");

    // Active should now be savings
    assert_eq!(
        get_active_wallet_name(Some(&base)),
        Some("savings".to_string())
    );

    // 3. Create wallet "trading"
    let secret2 = SecureSecret::new([0x22; 32]);
    let addr2 = "2222222222222222222222222222222222222222222222222222222222222222";
    let pass2 = "TradingPassword#2026";
    let ks2 = HardenedKeystore::encrypt(&secret2, addr2, pass2).expect("Encrypt 2 failed");
    save_named_wallet("trading", &ks2, Some(&base)).expect("Save trading failed");

    // Active should now be trading
    assert_eq!(
        get_active_wallet_name(Some(&base)),
        Some("trading".to_string())
    );

    // 4. List wallets: both exist, trading is active
    let list1 = list_wallets(Some(&base)).expect("Listing failed");
    assert_eq!(list1.len(), 2);
    let active_entry = list1
        .iter()
        .find(|w| w.is_active)
        .expect("No active wallet");
    assert_eq!(active_entry.name, "trading");
    assert_eq!(active_entry.address_hex, addr2);

    // 5. Try switching to "savings" with WRONG password -> MUST FAIL and keep "trading" active!
    let bad_switch = switch_wallet("savings", "WrongPassword#999", Some(&base));
    assert!(bad_switch.is_err(), "Switch with wrong password must fail");
    assert_eq!(
        get_active_wallet_name(Some(&base)),
        Some("trading".to_string())
    );

    // 6. Switch to "savings" with CORRECT password -> MUST SUCCEED
    let good_switch = switch_wallet("savings", pass1, Some(&base)).expect("Switch failed");
    assert_eq!(good_switch.name, "savings");
    assert_eq!(good_switch.address_hex, addr1);
    assert_eq!(
        get_active_wallet_name(Some(&base)),
        Some("savings".to_string())
    );

    // Legacy `wallet.json` must now match savings
    let legacy = base.join("wallet.json");
    assert!(legacy.exists());
    let legacy_ks = HardenedKeystore::load(&legacy).expect("Load legacy failed");
    assert_eq!(legacy_ks.address_hex, addr1);

    // 7. Switch back to "trading" by address with correct password
    let switch_by_addr = switch_wallet(addr2, pass2, Some(&base)).expect("Switch by addr failed");
    assert_eq!(switch_by_addr.name, "trading");
    assert_eq!(
        get_active_wallet_name(Some(&base)),
        Some("trading".to_string())
    );

    // Legacy `wallet.json` must now match trading
    let legacy_ks2 = HardenedKeystore::load(&legacy).expect("Load legacy failed");
    assert_eq!(legacy_ks2.address_hex, addr2);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_legacy_wallet_auto_migration() {
    let base = create_temp_env("legacy_migration");

    // Simulate pre-existing legacy `wallet.json`
    let secret = SecureSecret::new([0x33; 32]);
    let addr = "3333333333333333333333333333333333333333333333333333333333333333";
    let pass = "LegacyPass#2026";
    let ks = HardenedKeystore::encrypt(&secret, addr, pass).expect("Encrypt failed");

    let legacy = base.join("wallet.json");
    ks.save(&legacy).expect("Save legacy failed");

    // At first, `wallets/` dir does not exist
    assert!(!wallets_dir(Some(&base)).exists());

    // When list_wallets is called, it auto-migrates to `wallets/default.json`
    let list = list_wallets(Some(&base)).expect("Listing failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "default");
    assert_eq!(list[0].address_hex, addr);
    assert!(list[0].is_active);

    // Check that `wallets/default.json` was created with 0600
    let default_path = wallets_dir(Some(&base)).join("default.json");
    assert!(default_path.exists());
    let perms = fs::metadata(&default_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(perms, 0o600);

    let _ = fs::remove_dir_all(&base);
}
