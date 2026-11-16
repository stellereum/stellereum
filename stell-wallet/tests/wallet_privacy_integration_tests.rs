//! Integration tests for wallet notes store & PQ excision guards.

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/notes.rs"]
mod notes;

use notes::{
    add_note_with_secret, calculate_shielded_balance, get_unspent_notes_with_secret,
    load_notes_with_secret, mark_notes_spent_with_secret, select_notes_for_unshield_with_secret,
    ShieldedNote,
};
use std::fs;
use std::process::Command;

const TEST_SECRET: [u8; 32] = [0x5Eu8; 32];

fn make_temp_dir(label: &str) -> std::path::PathBuf {
    let rand_suffix: u64 = rand::random();
    let dir = std::env::temp_dir().join(format!("stell_test_{label}_{rand_suffix}"));
    fs::create_dir_all(&dir).expect("Failed to create temp directory");
    dir
}

fn bind_dummy_wallet(dir: &std::path::Path) {
    let wallet_path = dir.join("wallet.json");
    if !wallet_path.exists() {
        fs::write(&wallet_path, b"{\"dummy\":\"wallet-binding-for-tests\"}")
            .expect("Failed to write dummy wallet binding");
    }
}

#[test]
fn test_note_store_save_balance_selection_and_spend() {
    let dir = make_temp_dir("notes_lifecycle");
    bind_dummy_wallet(&dir);
    let notes_path = dir.join("shielded_notes.json");

    add_note_with_secret(
        &notes_path,
        ShieldedNote {
            commitment: hex::encode([1u8; 32]),
            amount: 4_000_000_000,
            blinding: hex::encode([0xA1u8; 32]),
            height: 1,
            spent: false,
        },
        &TEST_SECRET,
    )
    .expect("add note 1");
    add_note_with_secret(
        &notes_path,
        ShieldedNote {
            commitment: hex::encode([2u8; 32]),
            amount: 6_000_000_000,
            blinding: hex::encode([0xA2u8; 32]),
            height: 2,
            spent: false,
        },
        &TEST_SECRET,
    )
    .expect("add note 2");

    let all = load_notes_with_secret(&notes_path, &TEST_SECRET).expect("load notes");
    assert_eq!(all.len(), 2);
    assert_eq!(calculate_shielded_balance(&all), 10_000_000_000);

    let selected = select_notes_for_unshield_with_secret(&notes_path, 6_000_000_000, &TEST_SECRET)
        .expect("select notes");
    assert!(!selected.is_empty());
    let spent_commitments: Vec<String> = selected.iter().map(|n| n.commitment.clone()).collect();
    mark_notes_spent_with_secret(&notes_path, &spent_commitments, &TEST_SECRET)
        .expect("mark spent");

    let unspent = get_unspent_notes_with_secret(&notes_path, &TEST_SECRET).expect("unspent");
    assert!(unspent.len() < all.len());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cli_excised_privacy_commands_fail_closed() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let dir = make_temp_dir("cli_excised");
    let wallet_path = dir.join("wallet.json");

    for sub in [
        &["stealth-scan"][..],
        &["shield", "--amount", "1"][..],
        &["unshield", "--amount", "1"][..],
    ] {
        let out = Command::new(bin)
            .arg("--wallet")
            .arg(&wallet_path)
            .args(sub)
            .output()
            .expect("run stell");
        assert!(
            !out.status.success(),
            "excised privacy command {:?} must fail closed",
            sub
        );
    }
    let _ = fs::remove_dir_all(&dir);
}
