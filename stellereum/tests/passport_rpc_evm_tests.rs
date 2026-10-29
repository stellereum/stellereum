//! Passport-agents closeout — EVM chain-identity serving completeness
//! (`audit-rpc-evm.md` F3, 2026-10-14).
//!
//! NEW-FILE-ONLY: pins the follow-up delta (served identity threaded into the
//! adapter instance default and the `stell_tx_to_evm` view builder) without
//! touching any shared test. Uses only the public API.
//!
//! Contract under test:
//! * SERVING is dynamic (`STELL_CHAIN_ID`-aware) everywhere: free
//!   `eth_chain_id()` / `net_version()`, `EvmAdapter::new()` views, and the
//!   `stell_tx_to_evm` view builder. Live default (env unset) is 5757 — zero
//!   behavior change on the stand.
//! * VERIFICATION stays pinned to `CHAIN_ID == 5757` deliberately: every node
//!   admitting the same raw bytes must reach the same verdict, and a
//!   per-process env read at each verification site would let validators with
//!   different environments admit different tx sets. A deployment on another
//!   chain id changes the constant at build/deploy time, identically on all
//!   nodes — never per process at runtime.

use std::sync::{Mutex, MutexGuard};

use serde_json::json;
use stellereum::evm_adapter as evm;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard<'a> {
    _lock: MutexGuard<'a, ()>,
    saved: Vec<(String, Option<String>)>,
}

impl<'a> EnvGuard<'a> {
    fn take(names: &[&str]) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = names
            .iter()
            .map(|n| (n.to_string(), std::env::var(n).ok()))
            .collect();
        Self { _lock: lock, saved }
    }
}

impl Drop for EnvGuard<'_> {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
    }
}

fn dummy_tx() -> stellereum::sharding::Transaction {
    stellereum::sharding::Transaction {
        from: [1u8; 32],
        to: [2u8; 32],
        amount: 5,
        gas_limit: 1000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: vec![0u8; 64],
        payload: vec![],

        priority_fee_per_gas: 0,
    }
}

/// Build a VALID 5757-signed legacy raw tx (EIP-155 signing hash +
/// recoverable secp256k1 + low-s normalize), mirroring the in-tree vectors.
fn sign_5757_legacy(nonce: u64, value_wei: u128) -> Vec<u8> {
    let key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let unsigned = evm::LegacyTransaction {
        nonce,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some([0x35u8; 20]),
        value: value_wei,
        data: Vec::new(),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(evm::CHAIN_ID),
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[0..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let (s, recid_b) = if evm::is_low_s(&s) {
        (s, recid.to_byte())
    } else {
        let n = evm::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        (out, recid.to_byte() ^ 1)
    };
    let signed = evm::LegacyTransaction {
        v: evm::CHAIN_ID * 2 + 35 + recid_b as u64,
        r,
        s,
        ..unsigned
    };
    signed.encode()
}

// ---------------------------------------------------------------------------
// Serving tracks the effective id everywhere, including net_version.
// ---------------------------------------------------------------------------

#[test]
fn serving_identity_tracks_effective_id_default_5757() {
    let _env = EnvGuard::take(&["STELL_CHAIN_ID"]);
    std::env::remove_var("STELL_CHAIN_ID");
    assert_eq!(evm::effective_chain_id(), 5757);
    assert_eq!(evm::eth_chain_id(), "0x167d");
    assert_eq!(evm::net_version(), "5757");
    assert_eq!(
        evm::eth_chain_id(),
        evm::eth_chain_id_for(evm::effective_chain_id())
    );
    assert_eq!(
        evm::net_version(),
        evm::net_version_for(evm::effective_chain_id())
    );
    // Instance default agrees with the free functions out of the box.
    let adapter = evm::EvmAdapter::new();
    assert_eq!(adapter.chain_id, 5757);
    assert_eq!(adapter.eth_chain_id(), "0x167d");
    assert_eq!(adapter.net_version(), "5757");
    // Explicit override still wins (tests, multi-chain harnesses).
    let custom = evm::EvmAdapter::new().with_chain_id(1337);
    assert_eq!(custom.eth_chain_id(), "0x539");
    assert_eq!(custom.net_version(), "1337");
    // `Default` stays the pinned protocol constant for deterministic contexts.
    assert_eq!(evm::EvmAdapter::default().chain_id, evm::CHAIN_ID);
}

#[test]
fn serving_identity_follows_env_override_everywhere() {
    let _env = EnvGuard::take(&["STELL_CHAIN_ID"]);
    std::env::set_var("STELL_CHAIN_ID", "1234");
    assert_eq!(evm::effective_chain_id(), 1234);
    assert_eq!(evm::eth_chain_id(), "0x4d2");
    assert_eq!(evm::net_version(), "1234");
    // Instance default picks it up too (views agree with eth_chainId).
    let adapter = evm::EvmAdapter::new();
    assert_eq!(adapter.chain_id, 1234);
    assert_eq!(adapter.eth_chain_id(), "0x4d2");
    assert_eq!(adapter.net_version(), "1234");
    // View builder follows as well.
    let view = evm::stell_tx_to_evm(&dummy_tx(), None, None, None);
    let v = serde_json::to_value(&view).unwrap();
    assert_eq!(v["chainId"], json!("0x4d2"));
    // Garbage / zero / blank fall back to the default (fail-closed, never 0).
    for bad in ["not-a-number", "0", "   ", ""] {
        std::env::set_var("STELL_CHAIN_ID", bad);
        assert_eq!(
            evm::effective_chain_id(),
            5757,
            "input {bad:?} must fall back"
        );
        assert_eq!(evm::eth_chain_id(), "0x167d");
        assert_eq!(evm::net_version(), "5757");
    }
}

// ---------------------------------------------------------------------------
// View builder: default follows effective; explicit chain is exact.
// ---------------------------------------------------------------------------

#[test]
fn tx_view_chain_id_matches_served_identity() {
    let _env = EnvGuard::take(&["STELL_CHAIN_ID"]);
    std::env::remove_var("STELL_CHAIN_ID");
    let view = evm::stell_tx_to_evm(&dummy_tx(), Some([9u8; 32]), Some(77), Some(3));
    let v = serde_json::to_value(&view).unwrap();
    assert_eq!(v["chainId"], json!(evm::eth_chain_id()));
    assert_eq!(v["chainId"], json!("0x167d"));
    // Explicit chain passes through exactly (EIP-155 v = {0,1} + chain*2 + 35).
    let one = evm::stell_tx_to_evm_with_chain(&dummy_tx(), None, None, None, 1);
    let v1 = serde_json::to_value(&one).unwrap();
    assert_eq!(v1["chainId"], json!("0x1"));
    assert_eq!(v1["v"], json!("0x25"), "v = chain*2+35 base leg");
}

// ---------------------------------------------------------------------------
// Verification pins stay on 5757 even when serving reports another chain.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RLP adversarial re-verification (F5) with CORRECTLY-encoded nesting.
//
// NOTE (existing-test bug, reported not edited): the sibling closeout file's
// `f5_rlp_deep_nesting_rejected` builds nesting by prepending `0xc1` without
// updating outer length prefixes, so every depth ≥ 2 is malformed RLP
// (`UnexpectedEof`, not a depth refusal) and its "depth-64 decodes"
// assertion fails for that reason. The depth cap itself is intact (two
// enforced sites: `decode_with_remainder_depth` + the payload-items loop).
// Here the nesting is encoded properly via `rlp_encode_list`, so the test
// exercises the cap, not the length checker.
// ---------------------------------------------------------------------------

#[test]
fn rlp_depth_cap_enforced_on_well_formed_nesting() {
    fn nest(levels: usize) -> Vec<u8> {
        let mut inner = vec![0x01u8];
        for _ in 0..levels {
            inner = evm::rlp_encode_list(&[inner]);
        }
        inner
    }
    // 64 levels: at the cap, must decode (cap is `depth > 64`, not `>=`).
    let ok = evm::RlpItem::decode(&nest(64)).expect("depth-64 well-formed nest must decode");
    // Spot-check structure survived (64 single-item lists around 0x01).
    let mut cur = &ok;
    for _ in 0..64 {
        let kids = cur.as_list().expect("list level");
        assert_eq!(kids.len(), 1);
        cur = &kids[0];
    }
    assert_eq!(cur.as_bytes().unwrap(), &[0x01u8]);
    // 65 levels: refused by the cap, allocating nothing unbounded.
    assert!(
        evm::RlpItem::decode(&nest(65)).is_err(),
        "depth-65 nest must be refused"
    );
    assert!(
        evm::RlpItem::decode(&nest(200)).is_err(),
        "depth-200 nest must be refused"
    );
}

// ---------------------------------------------------------------------------
// Turnstile secret redaction (F9), asserted on the VALUE not the field name.
//
// NOTE (existing-test bug, reported not edited): the sibling closeout file's
// `f9_turnstile_misconfiguration_fails_closed` uses the literal secret
// `"secret"` and asserts `!Debug.contains("secret")`, which fails on the
// FIELD NAME `secret_key` in `Enabled { site_key, secret_key: "<redacted>" }`
// — the value itself is redacted. Pin the real property here.
// ---------------------------------------------------------------------------

#[test]
fn turnstile_debug_redacts_secret_value_but_keeps_site_key() {
    use stellereum::turnstile as ts;
    let cfg = ts::CaptchaConfig::Enabled {
        site_key: "site-abc".to_string(),
        secret_key: "super-secret-xyz".to_string(),
    };
    let rendered = format!("{cfg:?}");
    assert!(
        !rendered.contains("super-secret-xyz"),
        "secret value must not leak via Debug: {rendered}"
    );
    assert!(
        rendered.contains("site-abc"),
        "public site key may appear: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// /metrics exposure (F10): precise no-leak pin.
//
// NOTE (existing-test bug, reported not edited): the sibling closeout file's
// `f10_metrics_exposes_nothing_sensitive` needles for bare `"token"`, which
// collides with public-by-design exposition: the metric NAME
// `stellereum_tokens_total`-family vocabulary and HELP prose mentioning
// tokens. Those are dashboard data (counts), never secrets. This test pins
// the precise property: every series is a known `stell_*` family and no line
// carries secret-class vocabulary.
// ---------------------------------------------------------------------------

#[test]
fn metrics_exposition_carries_no_secrets() {
    use stellereum::metrics::Registry;
    let reg = Registry::new();
    reg.observe_peer_latency("peer-1", 0.5);
    reg.set_peer_round_lag("peer-1", 3);
    let text = reg.render();
    assert!(!text.is_empty());
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            line.starts_with("stell_"),
            "every series must be a known stell_* family, got: {line}"
        );
    }
    for needle in [
        "secret",
        "private_key",
        "private-key",
        "mnemonic",
        "faucet_key",
        "api_key",
        "apikey",
        "bearer",
        "password",
    ] {
        assert!(
            !text.to_lowercase().contains(needle),
            "scrape must not expose {needle}"
        );
    }
}

#[test]
fn verification_pins_stay_5757_under_custom_env() {
    let _env = EnvGuard::take(&["STELL_CHAIN_ID"]);
    std::env::set_var("STELL_CHAIN_ID", "1234");
    // Serving says 1234 ...
    assert_eq!(evm::eth_chain_id(), "0x4d2");
    // ... but a valid 5757-signed tx still verifies (pinned, by design: all
    // nodes must reach the same verdict on the same bytes).
    let raw = sign_5757_legacy(41, 7);
    let decoded = evm::parse_legacy_transaction(&raw).expect("decodes");
    assert_eq!(decoded.chain_id, Some(5757));
    decoded
        .verify_signature()
        .expect("pinned verifier accepts 5757 under any env");
    // And the admission gate still files it (idempotent on re-admission).
    let h1 = evm::eth_send_raw_transaction_bytes(&raw).expect("gate admits pinned 5757 tx");
    let h2 = evm::eth_send_raw_transaction_bytes(&raw).expect("re-admission is idempotent");
    assert_eq!(h1, h2);
    assert!(h1.starts_with("0x") && h1.len() == 66);
}
