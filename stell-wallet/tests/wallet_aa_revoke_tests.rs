use std::process::Command;

// Regression: with a valid unlocked wallet the old command returned success and
// printed "SESSION PERMANENTLY REVOKED" without constructing a transaction.
#[test]
fn revoke_session_fails_closed_even_with_a_valid_wallet() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let home = std::env::temp_dir().join(format!(
        "stell_aa_revoke_test_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&home).expect("create isolated test home");
    let wallet = home.join("wallet.json");
    let password = "test_password_12345";
    let create = Command::new(bin)
        .env("HOME", &home)
        .env_remove("STELL_RPC_URL")
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "new",
            "--password",
            password,
        ])
        .output()
        .expect("create isolated test wallet");
    assert!(
        create.status.success(),
        "wallet setup failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let result = Command::new(bin)
        .env("HOME", &home)
        .env_remove("STELL_RPC_URL")
        .args([
            "--wallet",
            wallet.to_str().unwrap(),
            "aa",
            "revoke-session",
            "test-object",
            "--session",
            "1",
            "--password",
            password,
        ])
        .output()
        .expect("run revoke-session");
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "revocation must not report success"
    );
    assert!(stderr.contains("no transaction was sent"), "{stderr}");
    assert!(stderr.contains("session was not revoked"), "{stderr}");
    assert!(!stdout.contains("SESSION PERMANENTLY REVOKED"));
    assert!(!stdout.contains("COMMITTED TERMINAL"));
    assert!(!home.join(".stellereum/local_txs.bin").exists());
}
