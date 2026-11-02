//! Faucet on the post-quantum path (Falcon-512), end to end.
//!
//! Scope: the faucet key loading (`STELL_FAUCET_KEY_FILE`, 0600 posture),
//! genesis-style funding of the PQ faucet account from a fixed-seed test key,
//! and payouts that verify on the PQ path and finalize through the engine.
//!
//! Conventions (deliberate):
//! * Fixed seed `[0x11; 32]` — the well-known public test seed. `Faucet::new`
//!   itself does not gate it (the startup gate lives in
//!   `load_faucet_seed`, which these tests never call), so it is safe to use
//!   for deterministic key derivation here.
//! * NO process-environment mutation: `load_faucet_seed_from_file` takes a
//!   path directly, and pure-PQ mode is flipped via the public
//!   `set_pure_pq_override` (process-wide in integration builds), serialized
//!   by `SERIAL` and always reset to `None` on guard drop.
//! * Default-mode behavior is pinned by `default_test_key_behavior_unchanged`:
//!   without the override the faucet account is the classical ed25519 address.

use std::sync::Mutex;
use stellereum::post_quantum::{is_pure_pq_enforced, set_pure_pq_override, PqScheme};
use stellereum::rpc::Faucet;
use stellereum::state_engine::InMemoryStateEngine;

/// Fixed-seed test key shared by every test in this file.
const PQ_FAUCET_SEED: [u8; 32] = [0x11u8; 32];
/// Genesis-style funding for the PQ faucet account (mirrors the
/// `GENESIS_FAUCET_BALANCE` credit in `src/main.rs`).
const PQ_GENESIS_BALANCE: u64 = 1_000_000_000_000_000;
const DRIP: u64 = 10_000_000_000;
const CAP: u64 = 1_000_000_000_000;

/// Serializes every test in this binary: the pure-PQ override is a
/// process-wide atomic in integration builds, so two tests must never hold
/// different modes at once.
static SERIAL: Mutex<()> = Mutex::new(());

/// Fail-safe pure-PQ override: resets to `None` on drop so a panicking
/// assertion cannot leak enforcement into the next test.
struct PurePqGuard {
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl PurePqGuard {
    fn enforce() -> Self {
        let guard = SERIAL.lock().expect("faucet-pq serial mutex poisoned");
        set_pure_pq_override(Some(true));
        assert!(
            is_pure_pq_enforced(),
            "pure-PQ override must be visible on this thread"
        );
        Self { _serial: guard }
    }

    fn disabled() -> Self {
        let guard = SERIAL.lock().expect("faucet-pq serial mutex poisoned");
        set_pure_pq_override(None);
        assert!(
            !is_pure_pq_enforced(),
            "default mode must be classical (no override, no env)"
        );
        Self { _serial: guard }
    }
}

impl Drop for PurePqGuard {
    fn drop(&mut self) {
        set_pure_pq_override(None);
    }
}

fn scratch_key_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell-faucet-pq-{}-{}-{}.key",
        std::process::id(),
        name,
        // Unique per test so parallel file creation never collides even
        // before the serial mutex is taken (writes happen outside the guard).
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

#[cfg(unix)]
fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("chmod scratch key file");
}

// 1. Key loading accepts the PQ seed at 0600, and the loaded seed drives the
//    PQ faucet account (the same raw derivation `Faucet::new` uses — NOT the
//    light-wallet KDF, which derives a different address from the same seed).
#[tokio::test]
async fn pq_key_file_loads_at_0600_and_drives_pq_account() {
    let _guard = PurePqGuard::enforce();
    let path = scratch_key_path("load0600");
    std::fs::write(&path, "1111111111111111111111111111111111111111111111111111111111111111\n")
        .expect("write scratch key file");
    chmod(&path, 0o600);

    let seed = stellereum::rpc::load_faucet_seed_from_file(&path)
        .expect("0600 hex seed file must load");
    assert_eq!(seed, PQ_FAUCET_SEED, "loaded seed must be the fixed test key");
    assert!(
        stellereum::rpc::is_test_key_seed(&seed),
        "the fixed seed must be recognized as the public test key"
    );

    // The loaded seed feeds the PQ path: the serving account is the Falcon
    // address, derived exactly as `Faucet::new` derives it.
    let faucet = Faucet::new(seed, 0, DRIP, CAP);
    let expected =
        InMemoryStateEngine::faucet_pq_account_from_seed(&PQ_FAUCET_SEED);
    assert_eq!(
        faucet.account(),
        expected,
        "serving account must be the PQ faucet address from the key file seed"
    );

    let _ = std::fs::remove_file(&path);
}

// 2. 0600 posture: group/other-readable key files are refused fail-closed.
#[cfg(unix)]
#[tokio::test]
async fn pq_key_file_refuses_insecure_permissions() {
    let _serial = SERIAL.lock().expect("faucet-pq serial mutex poisoned");
    let path = scratch_key_path("perms0644");
    std::fs::write(&path, "1111111111111111111111111111111111111111111111111111111111111111\n")
        .expect("write scratch key file");
    chmod(&path, 0o644);

    let err = stellereum::rpc::load_faucet_seed_from_file(&path)
        .expect_err("0644 key file must be refused");
    assert!(
        err.contains("REFUSING") && err.contains("0600"),
        "refusal must name the 0600 rule: {err}"
    );

    let _ = std::fs::remove_file(&path);
}

// 3. Missing and empty key files fail closed (no silent unfunded faucet).
#[cfg(unix)]
#[tokio::test]
async fn pq_key_file_refuses_missing_and_empty() {
    let _serial = SERIAL.lock().expect("faucet-pq serial mutex poisoned");
    let missing = scratch_key_path("missing");
    let _ = std::fs::remove_file(&missing);
    assert!(
        stellereum::rpc::load_faucet_seed_from_file(&missing).is_err(),
        "missing key file must fail closed"
    );

    let empty = scratch_key_path("empty");
    std::fs::write(&empty, "\n").expect("write scratch key file");
    chmod(&empty, 0o600);
    let err = stellereum::rpc::load_faucet_seed_from_file(&empty)
        .expect_err("empty key file must be refused");
    assert!(err.contains("empty"), "refusal must name the problem: {err}");
    let _ = std::fs::remove_file(&empty);
}

// 4. Genesis funding with the PQ faucet key + payout + verify + finalize:
//    credit the PQ faucet account (genesis step), drip to a recipient, check
//    the PQ envelope verifies, apply the block, check balances and nonce.
#[tokio::test]
async fn pq_genesis_funds_payout_account_and_drip_verifies_and_applies() {
    let _guard = PurePqGuard::enforce();
    let engine = InMemoryStateEngine::new();
    let faucet = Faucet::new(PQ_FAUCET_SEED, 0, DRIP, CAP);

    // Genesis funding with the PQ faucet key: the funded account IS the
    // serving PQ account (not the classical ed25519 one).
    let pq_account = faucet.account();
    assert_eq!(
        pq_account,
        InMemoryStateEngine::faucet_pq_account_from_seed(&PQ_FAUCET_SEED),
        "helper derivation must match the serving faucet account"
    );
    let classical = ed25519_dalek::SigningKey::from_bytes(&PQ_FAUCET_SEED)
        .verifying_key()
        .to_bytes();
    assert_ne!(
        pq_account, classical,
        "PQ and classical faucet accounts must differ (else the test proves nothing)"
    );
    engine
        .fund_faucet_genesis_pq(&PQ_FAUCET_SEED, PQ_GENESIS_BALANCE)
        .await
        .expect("genesis credit must succeed");
    assert_eq!(
        engine
            .get_account(&pq_account)
            .await
            .expect("funded PQ faucet account must exist")
            .balance,
        PQ_GENESIS_BALANCE
    );

    // Payout on the PQ path.
    let who = [0x42u8; 32];
    let (tx, amount) = faucet
        .build_transfer(who, None, None)
        .await
        .expect("first drip must fit the cap");
    assert_eq!(amount, DRIP);
    assert_eq!(tx.from, pq_account, "drip must spend the funded PQ account");
    assert_eq!(tx.to, who);
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.source_shard, 0);
    assert_eq!(tx.target_shard, 0);
    assert_eq!(
        tx.gas_limit,
        stellereum::svm::GAS_BASIC_TRANSFER
            + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
        "PQ drip must carry the activation surcharge"
    );
    assert!(tx.is_pq(), "drip must ride a PQ1 envelope, never bare ed");
    let env = tx.pq_envelope().expect("PQ envelope must decode");
    assert_eq!(env.scheme, PqScheme::Falcon512);
    assert!(!env.is_implicit, "always explicit: first spend needs no registry");
    assert!(env.pubkey.is_some(), "explicit carrier must embed the pubkey");
    assert!(
        tx.verify_signature(),
        "PQ drip must verify on the PQ path before admission"
    );

    // Finalize through the live execution path.
    let (applied, failed, _fees, status, tx_fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 1_700_000_000)
        .await;
    assert_eq!((applied, failed), (1, 0), "PQ drip must apply, not fail");
    assert_eq!(status.as_slice(), &[true]);
    let recipient = engine
        .get_account(&who)
        .await
        .expect("recipient must exist after apply");
    assert_eq!(recipient.balance, amount, "recipient must be credited the drip");
    assert_eq!(recipient.nonce, 0, "recipient nonce untouched by a credit");
    let sender = engine
        .get_account(&pq_account)
        .await
        .expect("faucet account must exist after apply");
    assert_eq!(sender.nonce, 1, "faucet nonce must advance exactly once");
    assert_eq!(
        sender.balance,
        PQ_GENESIS_BALANCE - amount - tx_fees[0],
        "faucet pays amount + fee, nothing else"
    );
}

// 5. Nonces increase across PQ drips and the lifetime cap holds on the PQ path.
#[tokio::test]
async fn pq_drip_nonces_increase_and_lifetime_cap_holds() {
    let _guard = PurePqGuard::enforce();
    let engine = InMemoryStateEngine::new();
    let faucet = Faucet::new(PQ_FAUCET_SEED, 0, DRIP, CAP);
    engine
        .credit_native(&faucet.account(), PQ_GENESIS_BALANCE)
        .await
        .expect("genesis credit must succeed");

    let (tx1, _) = faucet
        .build_transfer([0x01u8; 32], None, None)
        .await
        .expect("drip 1 must succeed");
    let (tx2, _) = faucet
        .build_transfer([0x02u8; 32], None, None)
        .await
        .expect("drip 2 must succeed");
    assert_eq!(
        (tx1.nonce, tx2.nonce),
        (0, 1),
        "PQ drips must not reuse a nonce"
    );
    assert!(tx1.verify_signature() && tx2.verify_signature());

    // A faucet whose cap equals one drip serves once, then refuses.
    let capped = Faucet::new(PQ_FAUCET_SEED, 0, DRIP, DRIP);
    capped
        .build_transfer([0x03u8; 32], None, None)
        .await
        .expect("capped first drip must succeed");
    assert!(
        capped
            .build_transfer([0x03u8; 32], None, None)
            .await
            .is_none(),
        "lifetime cap must hold on the PQ path"
    );
}

// 6. Default test-key behavior is UNCHANGED: without pure-PQ the faucet
//    account is the classical ed25519 address (no flag day), the fixed seed
//    parses with and without `0x`, and it is still the public test key.
#[tokio::test]
async fn default_test_key_behavior_unchanged() {
    let _guard = PurePqGuard::disabled();
    let faucet = Faucet::new(PQ_FAUCET_SEED, 0, DRIP, CAP);
    let classical = ed25519_dalek::SigningKey::from_bytes(&PQ_FAUCET_SEED)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        faucet.account(),
        classical,
        "default faucet account must stay the classical ed25519 address"
    );

    for raw in [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        "  1111111111111111111111111111111111111111111111111111111111111111\n",
    ] {
        assert_eq!(
            stellereum::rpc::parse_faucet_seed_hex(raw).expect("test-key hex must parse"),
            PQ_FAUCET_SEED,
            "seed parsing must accept the test key as before: {raw:?}"
        );
    }
}
