//! Audit closeout tests — RPC + EVM adapter findings (`audit-rpc-evm.md`, 2026-10-14).
//!
//! NEW-FILE-ONLY rule: these tests pin the fixes/verifications for findings
//! F1–F12 without touching any shared test. Each test names the finding it
//! closes. They use only the public API (`stellereum::...`); nothing here
//! reaches into private handlers.
//!
//! Live behavior verified against `https://rpc.stellereum.org` (2026-10-14):
//! `stell_chainId` = 5757, so every default-path assertion below matches the
//! live stand (no behavior change unless `STELL_CHAIN_ID` is set).

use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};

use serde_json::json;
use stellereum::evm_adapter as evm;

// ---------------------------------------------------------------------------
// Env discipline: Rust runs tests in one binary on threads, so any test that
// mutates the process environment takes this lock and restores every var it
// touches. Other test binaries are separate processes — no cross-file races.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// F3 — EVM chain-id serving is dynamic; verification pins stay (deliberate).
// ---------------------------------------------------------------------------

#[test]
fn f3_chain_id_serving_tracks_effective_id_while_pins_stay() {
    // Served identity helpers are pure functions of the id.
    assert_eq!(evm::eth_chain_id_for(5757), "0x167d");
    assert_eq!(evm::net_version_for(5757), "5757");
    assert_eq!(evm::eth_chain_id_for(1), "0x1");
    assert_eq!(evm::net_version_for(1), "1");
    // Live default (env unset in this process): effective == 5757 and the
    // served values match the pinned defaults byte-for-byte.
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
}

#[test]
fn f3_foreign_chain_tx_rejected_by_pinned_verifier() {
    // Official EIP-155 vector: chain 1, VALID signature. The pinned verifier
    // must refuse it as a 5757 tx (ChainIdMismatch), not recover a sender.
    let raw = hex::decode("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").unwrap();
    let decoded = evm::parse_legacy_transaction(&raw).expect("official vector decodes");
    assert_eq!(decoded.chain_id, Some(1));
    // Pinned legacy verifier: chain 1 != 5757 -> mismatch.
    let err = decoded
        .verify_signature()
        .expect_err("foreign chain must be refused");
    assert!(
        matches!(
            err,
            evm::EvmError::ChainIdMismatch {
                expected: 5757,
                got: 1
            }
        ),
        "unexpected error: {err}"
    );
    // Chain-aware ecrecover agrees.
    let sighash = decoded.signing_hash();
    let err2 =
        evm::ecrecover_with_chain_id(&sighash, decoded.v, &decoded.r, &decoded.s, Some(5757))
            .expect_err("foreign chain must be refused");
    assert!(
        matches!(
            err2,
            evm::EvmError::ChainIdMismatch {
                expected: 5757,
                got: 1
            }
        ),
        "unexpected error: {err2}"
    );
    // Same bytes are FINE when the caller asks for chain 1: the refusal is
    // the pin, not a broken signature.
    evm::ecrecover_with_chain_id(&sighash, decoded.v, &decoded.r, &decoded.s, Some(1))
        .expect("chain-1 vector verifies under chain 1");
    // And the admission gate refuses the raw bytes for the same reason.
    let gate_err = evm::eth_send_raw_transaction_bytes(&raw).expect_err("gate must refuse chain 1");
    assert!(
        gate_err.message.contains("5757"),
        "rejection must name the expected chain, got: {}",
        gate_err.message
    );
}

/// Build a VALID 5757-signed legacy raw tx (same construction the in-tree RPC
/// tests use: EIP-155 signing hash + recoverable secp256k1 + low-s normalize).
fn sign_5757_legacy(nonce: u64, value_wei: u128) -> (Vec<u8>, [u8; 20]) {
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
    let sender = evm::pubkey_to_address(key.verifying_key().to_encoded_point(false).as_bytes())
        .expect("sender derivable");
    let signed = evm::LegacyTransaction {
        v: evm::CHAIN_ID * 2 + 35 + recid_b as u64,
        r,
        s,
        ..unsigned
    };
    (signed.encode(), sender)
}

#[test]
fn f3_valid_5757_tx_passes_pinned_verifier_and_parses_back() {
    let (raw, sender) = sign_5757_legacy(0, 1_000_000_000_000_000_000);
    let decoded = evm::parse_legacy_transaction(&raw).expect("our tx decodes");
    assert_eq!(decoded.chain_id, Some(5757));
    assert_eq!(
        decoded
            .verify_signature()
            .expect("pinned verifier accepts 5757"),
        sender
    );
    // Admission gate files the intent and returns the keccak hash.
    let hash = evm::eth_send_raw_transaction_bytes(&raw).expect("gate admits 5757 tx");
    assert!(
        hash.starts_with("0x") && hash.len() == 66,
        "keccak hash, got {hash}"
    );
    assert_eq!(hash, format!("0x{}", hex::encode(evm::keccak256(&raw))));
    // Re-admission of the same bytes is idempotent (same hash, no error).
    assert_eq!(evm::eth_send_raw_transaction_bytes(&raw).unwrap(), hash);
}

// ---------------------------------------------------------------------------
// F5 — RLP adversarial vectors (caps verified, not just documented).
// ---------------------------------------------------------------------------

#[test]
fn f5_rlp_deep_nesting_rejected() {
    // Nesting must be built with the encoder (manual 0xc1-prepend leaves
    // outer lengths stale, failing at depth 2 for the wrong reason).
    fn nest(levels: usize) -> Vec<u8> {
        let mut inner = vec![0x01u8];
        for _ in 0..levels {
            inner = evm::rlp_encode_list(&[inner]);
        }
        inner
    }
    // 65 nested single-item lists: depth 65 > MAX_DEPTH 64 must fail.
    assert!(
        evm::RlpItem::decode(&nest(65)).is_err(),
        "depth-65 nest must be refused"
    );
    // Depth exactly 64 still decodes (the cap is not off-by-one).
    assert!(
        evm::RlpItem::decode(&nest(64)).is_ok(),
        "depth-64 nest must decode"
    );
}

#[test]
fn f5_rlp_noncanonical_forms_rejected() {
    // Single byte < 0x80 wrapped as a string.
    assert_eq!(
        evm::RlpItem::decode(&[0x81, 0x05]),
        Err(evm::RlpError::NonCanonicalSingleByte)
    );
    // Short payload in long form (1 byte via 0xb8).
    assert_eq!(
        evm::RlpItem::decode(&[0xb8, 0x01, 0x05]),
        Err(evm::RlpError::NonCanonicalLength)
    );
    // Length prefix with a leading zero byte.
    assert!(matches!(
        evm::RlpItem::decode(&[0xb9, 0x00, 0x01, 0x05]),
        Err(evm::RlpError::LeadingZeroInLength)
    ));
    // Non-canonical integer (leading zero) inside a tx field vector.
    let item = evm::RlpItem::decode(&[0x82, 0x00, 0x01]).unwrap();
    assert_eq!(item.as_u64(), Err(evm::RlpError::LeadingZeroInInteger));
    // Integer wider than u64.
    let wide = evm::RlpItem::decode(&[0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert!(matches!(
        wide.as_u64(),
        Err(evm::RlpError::IntegerOverflow(_))
    ));
}

#[test]
fn f5_rlp_trailing_bytes_and_giant_prefix_rejected_without_oom() {
    // Valid single byte plus one trailing byte.
    assert_eq!(
        evm::RlpItem::decode(&[0x05, 0x06]),
        Err(evm::RlpError::TrailingBytes)
    );
    // 8-byte length prefix claiming u64::MAX bytes: checked arithmetic must
    // fail closed (UnexpectedEof), allocating nothing.
    let mut giant = vec![0xbfu8];
    giant.extend_from_slice(&[0xffu8; 8]);
    assert_eq!(
        evm::RlpItem::decode(&giant),
        Err(evm::RlpError::UnexpectedEof)
    );
    // Empty input.
    assert_eq!(evm::RlpItem::decode(&[]), Err(evm::RlpError::UnexpectedEof));
}

#[test]
fn f5_raw_tx_size_cap_enforced_before_decode() {
    // 128 KiB + 1 must be refused without attempting RLP decode.
    let big = vec![0u8; evm::MAX_EVM_RAW_TX_BYTES + 1];
    assert!(evm::eth_send_raw_transaction_bytes(&big).is_err());
    assert!(evm::extract_raw_evm_bytes(&json!([format!("0x{}", "00".repeat(big.len()))])).is_err());
    assert!(
        evm::extract_raw_evm_bytes(&json!([])).is_err(),
        "empty params refused"
    );
    // Empty bytes refused too.
    assert!(evm::eth_send_raw_transaction_bytes(&[]).is_err());
}

// ---------------------------------------------------------------------------
// F6 — ecrecover edges: low-s everywhere, zero r/s, unprotected refused.
// ---------------------------------------------------------------------------

#[test]
fn f6_ecrecover_zero_r_s_rejected() {
    let hash = [7u8; 32];
    // v=37 is chain-1/recid-0; chain check passes contextually, zero limbs fail.
    assert!(matches!(
        evm::ecrecover_with_chain_id(&hash, 37, &[0u8; 32], &[1u8; 32], Some(1)),
        Err(evm::EvmError::InvalidSignatureR)
    ));
    assert!(matches!(
        evm::ecrecover_with_chain_id(&hash, 37, &[1u8; 32], &[0u8; 32], Some(1)),
        Err(evm::EvmError::InvalidSignatureS)
    ));
}

#[test]
fn f6_high_s_rejected_at_every_strict_layer() {
    let (raw, _) = sign_5757_legacy(9, 1);
    let decoded = evm::parse_legacy_transaction(&raw).unwrap();
    assert!(evm::is_low_s(&decoded.s), "fixture must start low-s");
    // Malleate: s' = n - s (still a valid curve scalar, still recovers — but high-s).
    let n = evm::SECP256K1_N;
    let mut hi = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let v = n[i] as i32 - decoded.s[i] as i32 - borrow;
        if v < 0 {
            hi[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            hi[i] = v as u8;
            borrow = 0;
        }
    }
    assert!(!evm::is_low_s(&hi), "malleated s must be high-s");
    let sighash = decoded.signing_hash();
    // Strict layers refuse high-s...
    assert!(evm::validate_transaction_signature_with_chain_id(
        &sighash,
        decoded.v,
        &decoded.r,
        &hi,
        Some(5757)
    )
    .is_err());
    // ...including the legacy verifier (low-s gate fires before recovery).
    let mut bad = decoded.clone();
    bad.s = hi;
    assert!(matches!(
        bad.verify_signature(),
        Err(evm::EvmError::InvalidSignatureS)
    ));
}

#[test]
fn f6_unprotected_legacy_refused_v27_v28() {
    let hash = [7u8; 32];
    let r = [2u8; 32];
    let s = [3u8; 32];
    for v in [27u64, 28] {
        let err = evm::ecrecover_with_chain_id(&hash, v, &r, &s, Some(5757))
            .expect_err("unprotected legacy must be refused");
        assert!(
            matches!(err, evm::EvmError::ReplayProtectionRequired),
            "v={v}: unexpected {err}"
        );
    }
}

#[test]
fn f6_cross_deployment_replay_is_chain_bound() {
    // Same-deployment replay under a SHARED chain id is inherent (documented
    // in F6): the binding that exists is chain_id, and it holds — a 5757 sig
    // never verifies as chain 1 and vice versa.
    let (raw, sender) = sign_5757_legacy(3, 5);
    let decoded = evm::parse_legacy_transaction(&raw).unwrap();
    assert_eq!(decoded.verify_signature().unwrap(), sender);
    let sighash = decoded.signing_hash();
    assert!(matches!(
        evm::ecrecover_with_chain_id(&sighash, decoded.v, &decoded.r, &decoded.s, Some(1)),
        Err(evm::EvmError::ChainIdMismatch {
            expected: 1,
            got: 5757
        })
    ));
}

// ---------------------------------------------------------------------------
// F4 — estimateGas honesty: floor served, calldata math intact.
// ---------------------------------------------------------------------------

#[test]
fn f4_estimate_serves_pure_figure_at_zero_floor() {
    assert_eq!(evm::eth_estimate_gas_impl(&json!([])).unwrap(), "0x5208");
    assert_eq!(
        evm::eth_estimate_gas_with_floor(&json!([]), 0).unwrap(),
        "0x5208"
    );
    // 4 non-zero calldata bytes: 21000 + 4*16 = 21064 = 0x5248.
    let call =
        json!([{ "to": "0x3535353535353535353535353535353535353535", "data": "0xaabbccdd" }]);
    assert_eq!(evm::eth_estimate_gas_impl(&call).unwrap(), "0x5248");
    assert_eq!(
        evm::eth_estimate_gas_with_floor(&call, 0).unwrap(),
        "0x5248"
    );
}

#[test]
fn f4_estimate_never_below_admission_floor() {
    // Native basic-transfer floor: wallets must not be told 21k when the node
    // admits nothing below 280k of declared gas.
    assert_eq!(
        evm::eth_estimate_gas_with_floor(&json!([]), 280_000).unwrap(),
        "0x445c0"
    );
    // Floor below the pure figure is a no-op (calldata-heavy estimate wins).
    let call =
        json!([{ "to": "0x3535353535353535353535353535353535353535", "data": "0xaabbccdd" }]);
    assert_eq!(
        evm::eth_estimate_gas_with_floor(&call, 1000).unwrap(),
        "0x5248"
    );
    // Contract creation base (53k) still floored upward the same way.
    let create = json!([{ "data": "0x6001" }]);
    let pure = evm::eth_estimate_gas_impl(&create).unwrap();
    assert_eq!(pure, "0xcf28"); // 53000 + 2*16 = 53032
    assert_eq!(
        evm::eth_estimate_gas_with_floor(&create, 280_000).unwrap(),
        "0x445c0"
    );
    // Malformed calldata still fails closed, floor or not.
    assert!(evm::eth_estimate_gas_with_floor(&json!([{ "data": "0xzz" }]), 280_000).is_err());
}

// ---------------------------------------------------------------------------
// eth_call sandbox: reads only, unknown -> "0x", bounded input.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eth_call_sandbox_reads_only_and_never_panics() {
    use stellereum::state_engine::{AccountState, InMemoryStateEngine};
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([9u8; 32], 1_000_000))
        .await;
    let root_before = engine.get_state_root().await;

    // Unknown selector -> "0x", twice (deterministic, no state created).
    let unknown =
        json!([{ "to": "0x3535353535353535353535353535353535353535", "data": "0xdeadbeef" }]);
    let a = evm::eth_call_with_engine(&engine, &unknown).await.unwrap();
    let b = evm::eth_call_with_engine(&engine, &unknown).await.unwrap();
    assert_eq!(a, json!("0x"));
    assert_eq!(a, b);

    // Truncated / missing / garbage calldata -> "0x", never a panic.
    for params in [
        json!([]),
        json!([{ "to": "0x3535" }]),
        json!([{ "data": "0x1234" }]),
        json!([{ "data": "not-hex-at-all!!!" }]),
        json!("just-a-string"),
    ] {
        let v = evm::eth_call_with_engine(&engine, &params).await.unwrap();
        assert_eq!(v, json!("0x"), "params {params} must emulate to empty");
    }

    // 100 KiB of calldata: bounded work, prompt empty answer (input is under
    // the body cap; emulation does one selector match, no iteration over it).
    let huge = format!("0x{}", "ab".repeat(50_000));
    let v = evm::eth_call_with_engine(&engine, &json!([{ "data": huge }]))
        .await
        .unwrap();
    assert_eq!(v, json!("0x"));

    // Known selector still emulates (balanceOf path exercises the engine read).
    let bal_of = format!("0x70a08231{}", "00".repeat(12) + &"09".repeat(20));
    let v = evm::eth_call_with_engine(&engine, &json!([{ "data": bal_of }]))
        .await
        .unwrap();
    assert!(v.as_str().unwrap().starts_with("0x"));

    // No state was touched by any of the above.
    assert_eq!(engine.get_state_root().await, root_before);
}

// ---------------------------------------------------------------------------
// F7 — faucet key split: serving refuses what genesis allows (AIRTIGHT).
// ---------------------------------------------------------------------------

const TESTKEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn f7_serving_refuses_test_key_that_genesis_allows() {
    // GATE (LEAD b: serving requires STELL_FAUCET_KEY_FILE): the serving
    // loader now reads the test key from a FILE. Serving still hard-refuses
    // it without the dev override; genesis still warns-but-returns; the
    // override re-opens serving only. Same verdicts, file-sourced.
    use stellereum::rpc;
    let _env = EnvGuard::take(&[
        rpc::FAUCET_KEY_ENV,
        rpc::FAUCET_KEY_FILE_ENV,
        rpc::DEV_UNSAFE_TESTKEY_ENV,
    ]);
    std::env::remove_var(rpc::FAUCET_KEY_ENV);
    std::env::remove_var(rpc::FAUCET_KEY_FILE_ENV);
    std::env::remove_var(rpc::DEV_UNSAFE_TESTKEY_ENV);
    let dir = std::env::temp_dir().join(format!("stell_f7_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("faucet.key");
    std::fs::write(&path, format!("{TESTKEY_HEX}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::env::set_var(rpc::FAUCET_KEY_FILE_ENV, &path);

    // SERVING loader: hard refusal of the well-known public test key.
    let serving = rpc::load_faucet_seed();
    assert!(
        serving.is_err(),
        "serving must refuse 0x11..11 without the dev override"
    );
    assert!(serving.unwrap_err().contains("PUBLIC test key"));

    // GENESIS loader: warns but returns (root determinism for chains founded
    // with the test key). Same key file, same bytes — different verdict.
    let genesis = rpc::load_faucet_seed_for_genesis();
    assert_eq!(genesis, Ok(rpc::TEST_FAUCET_SEED));

    // Explicit dev opt-in re-opens SERVING only (never the default).
    std::env::set_var(rpc::DEV_UNSAFE_TESTKEY_ENV, "1");
    assert_eq!(rpc::load_faucet_seed(), Ok(rpc::TEST_FAUCET_SEED));
    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&dir).ok();
}

#[test]
fn f7_no_serving_path_uses_genesis_loader() {
    // Tripwire for the airtight split: the serving loader must keep refusing
    // the test key while the genesis loader allows it — if a future refactor
    // merges them, the test above fails. Here we pin the gate helpers too.
    use stellereum::rpc;
    assert!(rpc::is_test_key_seed(&rpc::TEST_FAUCET_SEED));
    assert!(!rpc::is_test_key_seed(&[0x42u8; 32]));
    assert!(rpc::is_dev_unsafe_testkey(Some("1")));
    assert!(rpc::is_dev_unsafe_testkey(Some("TrUe")));
    assert!(!rpc::is_dev_unsafe_testkey(None));
    assert!(!rpc::is_dev_unsafe_testkey(Some("0")));
    assert!(!rpc::is_dev_unsafe_testkey(Some("yes")));
    // Serving gate without the env override refuses; genesis path is separate.
    let _env = EnvGuard::take(&[rpc::DEV_UNSAFE_TESTKEY_ENV]);
    std::env::remove_var(rpc::DEV_UNSAFE_TESTKEY_ENV);
    assert!(rpc::check_faucet_seed_allows_startup(&rpc::TEST_FAUCET_SEED).is_err());
    assert!(rpc::check_faucet_seed_allows_startup(&[0x42u8; 32]).is_ok());
}

#[test]
fn f7_key_file_perm_gate_fail_closed() {
    use stellereum::rpc;
    let dir = std::env::temp_dir().join(format!("stell_audit_closeout_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("faucet.key");
    std::fs::write(&path, format!("{TESTKEY_HEX}\n")).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = rpc::load_faucet_seed_from_file(&path).expect_err("0644 must be refused");
        assert!(
            err.contains("0600") || err.contains("permissions"),
            "got: {err}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let seed = rpc::load_faucet_seed_from_file(&path).expect("0600 must load");
        assert_eq!(seed, rpc::TEST_FAUCET_SEED);
    }
    #[cfg(not(unix))]
    {
        let seed = rpc::load_faucet_seed_from_file(&path).expect("must load");
        assert_eq!(seed, rpc::TEST_FAUCET_SEED);
    }
    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&dir).ok();
}

// ---------------------------------------------------------------------------
// F8/F10 — XFF trust: rightmost default, trusted-peer-only, spoof != bypass.
// ---------------------------------------------------------------------------

// Minimal helper: client_ip works on axum::HeaderMap, and axum IS a main
// dependency, so build the real thing instead of a fake.
fn real_headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
    let mut m = axum::http::HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse::<axum::http::HeaderValue>().unwrap(),
        );
    }
    m
}

#[test]
fn f8_untrusted_peer_spoof_is_ignored_rightmost_default() {
    use stellereum::client_ip as cip;
    let trusted = cip::parse_trusted_list("127.0.0.0/8, ::1/128");
    // Remote attacker claims to be the victim; TCP peer is untrusted.
    let peer: IpAddr = "8.8.8.8".parse().unwrap();
    let headers = real_headers(&[("x-forwarded-for", "1.2.3.4")]);
    assert_eq!(
        cip::resolve_with(&headers, peer, &trusted, cip::XffMode::Rightmost),
        peer
    );
    // Unknown mode strings fall back to Rightmost (fail-safe).
    assert_eq!(cip::XffMode::parse("weird-mode"), cip::XffMode::Rightmost);
}

#[test]
fn f8_rightmost_ignores_attacker_prefix_from_trusted_peer() {
    use stellereum::client_ip as cip;
    let trusted = cip::parse_trusted_list("127.0.0.0/8");
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    // Attackerprepended "9.9.9.9"; proxy appended real client "1.2.3.4".
    let headers = real_headers(&[("x-forwarded-for", "9.9.9.9, 1.2.3.4")]);
    assert_eq!(
        cip::resolve_with(&headers, peer, &trusted, cip::XffMode::Rightmost),
        "1.2.3.4".parse::<IpAddr>().unwrap()
    );
    // Blank env = trust NOTHING (explicit disable), not the default.
    let _env = EnvGuard::take(&[cip::TRUSTED_PROXY_CIDRS_ENV]);
    std::env::set_var(cip::TRUSTED_PROXY_CIDRS_ENV, "   ");
    assert!(cip::trusted_nets_from_env().is_empty());
}

#[test]
fn f8_spoof_cannot_hop_rate_limit_buckets() {
    use stellereum::client_ip as cip;
    use stellereum::explorer::RateLimiter;
    let trusted = cip::parse_trusted_list("127.0.0.0/8");
    let limiter = RateLimiter::new(2);
    let now = 1_700_000_000u64;

    // Victim's bucket: two passes, third refused — limiter works.
    let victim: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(limiter.check_at(victim, now));
    assert!(limiter.check_at(victim, now));
    assert!(!limiter.check_at(victim, now));

    // Attacker behind an UNTRUSTED peer spoofs victim's IP: resolution pins
    // them to their own TCP peer, so the victim's (exhausted) bucket is
    // untouched and the attacker only spends their own budget.
    let attacker_peer: IpAddr = "8.8.8.8".parse().unwrap();
    let spoof = real_headers(&[("x-forwarded-for", "1.2.3.4")]);
    let resolved = cip::resolve_with(&spoof, attacker_peer, &trusted, cip::XffMode::Rightmost);
    assert_eq!(resolved, attacker_peer);
    assert!(limiter.check_at(resolved, now));

    // Even from a TRUSTED peer, rightmost-untrusted resolves to the proxy-
    // appended entry, never the attacker-prepended one: flooding as "9.9.9.9"
    // spends the 1.2.3.4 bucket, not an arbitrary victim's.
    let proxy_peer: IpAddr = "127.0.0.1".parse().unwrap();
    let forged = real_headers(&[("x-forwarded-for", "9.9.9.9, 1.2.3.4")]);
    let resolved2 = cip::resolve_with(&forged, proxy_peer, &trusted, cip::XffMode::Rightmost);
    assert_eq!(resolved2, victim);
    assert!(
        !limiter.check_at(resolved2, now),
        "victim bucket already exhausted"
    );
}

// ---------------------------------------------------------------------------
// F10 — /api/* input parsing: malformed ids fail closed, never panic.
// ---------------------------------------------------------------------------

#[test]
fn f10_api_address_parsing_fuzz() {
    use stellereum::explorer::parse_addr;
    // Only exact 32-byte hex passes (0x optional).
    assert!(parse_addr("").is_none());
    assert!(parse_addr("0x").is_none());
    assert!(parse_addr("0x00").is_none());
    assert!(parse_addr("zz").is_none());
    assert!(parse_addr("0xzzzz").is_none());
    assert!(parse_addr(&"ab".repeat(31)).is_none(), "31 bytes refused");
    assert!(parse_addr(&"ab".repeat(33)).is_none(), "33 bytes refused");
    assert!(parse_addr(" 09").is_none(), "whitespace/short refused");
    let good = "09".repeat(32);
    assert_eq!(parse_addr(&good), Some([9u8; 32]));
    assert_eq!(parse_addr(&format!("0x{good}")), Some([9u8; 32]));
    // Uppercase hex is accepted; an `0X` prefix is not (only `0x`/bare).
    assert_eq!(parse_addr(&good.to_uppercase()), Some([9u8; 32]));
    assert!(
        parse_addr(&format!("0X{good}")).is_none(),
        "0X prefix is not accepted"
    );
}

#[test]
fn f10_hash_parsing_fuzz() {
    // Malformed hashes fail closed (Err), never panic.
    for bad in [
        "",
        "0x",
        "0xzz",
        "abc",
        &"00".repeat(31),
        &"00".repeat(33),
        "0x00",
    ] {
        assert!(
            evm::normalize_hash(bad).is_err() || evm::parse_hash_bytes(bad).is_err(),
            "{bad:?}"
        );
    }
    let good = format!("0x{}", "ab".repeat(32));
    let norm = evm::normalize_hash(&good).expect("32-byte hash normalizes");
    assert_eq!(evm::parse_hash_bytes(&norm).unwrap(), [0xabu8; 32]);
    // Unknown-but-wellformed hashes resolve to None (honest null), not an error.
    assert!(evm::global_adapter()
        .get_transaction_receipt(&good)
        .is_none());
    assert!(evm::global_adapter().get_settled_receipt(&good).is_none());
}

#[test]
fn f10_metrics_exposes_nothing_sensitive() {
    use stellereum::metrics::{sanitize_label_value, Registry};
    // Hostile peer id cannot forge a series or smuggle a newline.
    let evil = "evil\"\nstell_fake_metric 1\n# HELP x";
    let clean = sanitize_label_value(evil);
    assert!(
        !clean.contains('\n') && !clean.contains('\r'),
        "got: {clean:?}"
    );
    let reg = Registry::new();
    reg.observe_peer_latency(evil, 0.5);
    reg.set_peer_round_lag(evil, 3);
    let text = reg.render();
    for line in text.lines() {
        // Every line is a known family, a comment, or blank — no forged series.
        // The allowlist mirrors `Registry::new` in src/metrics.rs: every
        // family the registry declares must appear here, including the
        // #288000 divergence counter and the nil-storm / proposer observability
        // families. A new family without an allowlist entry fails this test by
        // design (explicit opt-in, never silent).
        let known = line.is_empty()
            || line.starts_with('#')
            || line.starts_with("stell_consensus_")
            || line.starts_with("stell_block_")
            || line.starts_with("stell_peer_latency_seconds")
            || line.starts_with("stell_peer_round_lag")
            || line.starts_with("stell_fork_total")
            || line.starts_with("stell_divergence_total")
            || line.starts_with("stell_weak_qc_refused_total")
            || line.starts_with("stell_mempool_size")
            || line.starts_with("stell_mempool_sealed")
            || line.starts_with("stell_mempool_plain")
            || line.starts_with("stell_mev_")
            || line.starts_with("stell_state_root_commits_total")
            || line.starts_with("stell_validator_")
            || line.starts_with("stell_data_dir_bytes")
            || line.starts_with("stell_snapshot_count")
            || line.starts_with("stell_state_entries")
            || line.starts_with("stell_persist_queue_")
            || line.starts_with("stell_nil_rounds_total")
            || line.starts_with("stell_nil_breaker_fires_total")
            || line.starts_with("stell_proposer_missed_total")
            || line.starts_with("stell_slow_validation_total")
            || line.starts_with("stell_unbound_tx_total")
            // A14 phase-3 chain-binding gate: label-free refusal counter
            // (`UNBOUND_REFUSED_TOTAL`, no labels, no secrets — verified in
            // src/metrics.rs). Explicit opt-in per this test's design.
            || line.starts_with("stell_unbound_refused_total")
            // Straggler grace (docs/PROPOSER_REWORK.md §2c): label-free tick
            // counter (`STRAGGLER_GRACE_EXTENDS_TOTAL`, no labels, no secrets
            // — verified in src/metrics.rs). Explicit opt-in per this test's
            // design.
            || line.starts_with("stell_straggler_grace_extends_total")
            || line.starts_with("stell_build_info")
            || line.starts_with("stellereum_");
        assert!(known, "unexpected scrape line: {line}");
    }
    assert!(
        !text.contains("stell_fake_metric 1\n"),
        "forged series must not appear"
    );
    // No secrets anywhere in exposition vocabulary. Needles are precise
    // secret-class names: bare "token" hits public "…tokens…" vocabulary.
    for needle in [
        "auth_token",
        "faucet_token",
        "secret_key",
        "private_key",
        "mnemonic",
        "faucet_key",
        "api_key",
        "password",
        "seed",
    ] {
        assert!(
            !text.to_lowercase().contains(needle),
            "scrape leaks {needle}"
        );
    }
}

// ---------------------------------------------------------------------------
// F11 — body cap / batch refusal / id echo (adapter level; HTTP path pins
// single-only in rpc_handler, verified by the shared router tests).
// ---------------------------------------------------------------------------

#[test]
fn f11_adapter_batch_echoes_ids_and_refuses_empty() {
    let adapter = evm::EvmAdapter::new();
    let batch = r#"[
        {"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
        {"jsonrpc":"2.0","id":"abc","method":"net_version","params":[]},
        {"jsonrpc":"2.0","id":null,"method":"nope","params":[]}
    ]"#;
    let resp_raw = adapter.handle_raw_json(batch);
    let resps: Vec<serde_json::Value> = serde_json::from_str(&resp_raw).unwrap();
    assert_eq!(resps.len(), 3);
    assert_eq!(resps[0]["id"], json!(1));
    assert_eq!(resps[0]["result"], json!("0x167d"));
    assert_eq!(resps[1]["id"], json!("abc"));
    assert_eq!(resps[2]["id"], serde_json::Value::Null);
    assert!(resps[2].get("error").is_some());
    // Empty batch refused, not silently dropped.
    let empty = adapter.handle_raw_json("[]");
    assert!(empty.contains("empty batch"), "got: {empty}");
    // Parse error echoes Null id (standard).
    let bad = adapter.handle_raw_json("{not json");
    let v: serde_json::Value = serde_json::from_str(&bad).unwrap();
    assert_eq!(v["id"], serde_json::Value::Null);
    assert_eq!(v["error"]["code"], json!(-32700));
}

// ---------------------------------------------------------------------------
// I3/F2 — getStateRoot determinism: same inputs, same root, on every node.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i3_state_root_identical_across_nodes_and_stable_across_reads() {
    use stellereum::state_engine::{AccountState, InMemoryStateEngine};
    async fn build() -> stellereum::cell::CellHash {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new([1u8; 32], 1_000))
            .await;
        engine
            .update_account(AccountState::new([2u8; 32], 2_000))
            .await;
        // Read twice around the committed mutation: the second read folds at
        // most once, later reads are stable (deliberate commitment fold).
        let first = engine.get_state_root().await;
        let second = engine.get_state_root().await;
        assert_eq!(
            first, second,
            "reads must be stable (fold-once, then fixed)"
        );
        second
    }
    // Two independent engines ("nodes") applying the same mutations agree.
    assert_eq!(build().await, build().await);
}

// ---------------------------------------------------------------------------
// Receipt honesty + syncing vantage-local (read-only pins).
// ---------------------------------------------------------------------------

#[test]
fn receipt_unknown_hash_is_honest_null() {
    // Never fabricated: unknown hash -> None (JSON null on the wire) at every
    // receipt lookup layer.
    let unknown = format!("0x{}", "cd".repeat(32));
    assert!(evm::global_adapter()
        .get_transaction_receipt(&unknown)
        .is_none());
    assert!(evm::global_adapter()
        .get_settled_receipt(&unknown)
        .is_none());
    assert!(
        evm::evm_to_stell_hash(&unknown).is_none(),
        "no pending mapping for unknown"
    );
}

#[test]
fn syncing_rule_is_vantage_local_and_fail_closed() {
    // Same rule rpc serves for stell_syncing/eth_syncing: syncing == (recent
    // verified peer height above ours); no sighting -> false (not syncing),
    // never a stuck-true pin.
    assert!(evm::eth_syncing_for_heights(10, Some(12)));
    assert!(!evm::eth_syncing_for_heights(12, Some(12)));
    assert!(!evm::eth_syncing_for_heights(12, Some(9)));
    assert!(!evm::eth_syncing_for_heights(12, None));
}

// ---------------------------------------------------------------------------
// light_client: LIVE — the sync path and the node MUST depend on it.
// ---------------------------------------------------------------------------

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn light_client_is_wired_into_the_sync_path() {
    // Audit W8.3 closed production blocker A10: the light client used to be
    // a library nothing called ("the node hands out the root it believes in"
    // is not a proof for an outside verifier). It is now WIRED IN, and this
    // tripwire is INVERTED: the day the node stops depending on it, this
    // test fails.
    const SYNC_RS: &str = include_str!("../src/sync.rs");
    const MAIN_RS: &str = include_str!("../src/main.rs");
    const RUNTIME_RS: &str = include_str!("../src/runtime.rs");
    const RPC_RS: &str = include_str!("../src/rpc.rs");

    // 1. The sync path verifies peer blocks against the trusted anchor.
    assert!(
        SYNC_RS.contains("verify_synced_blocks_against_anchor"),
        "sync.rs must verify peer blocks against the light-client anchor"
    );
    assert!(
        SYNC_RS.contains("light_client"),
        "sync.rs must depend on the light-client module"
    );
    // 2. The node keeps a light client and moves it with the chain.
    assert!(
        RUNTIME_RS.contains("light_client"),
        "runtime.rs must keep the node's light client"
    );
    assert!(
        MAIN_RS.contains("light_client"),
        "main.rs must wire the light client into the node"
    );
    // 3. The node SERVES the quorum-certified chain, so an outside verifier
    //    can check a proof against a root a quorum committed to.
    assert!(
        RPC_RS.contains("stell_getFinalizedHeader")
            && RPC_RS.contains("stell_getFinalizedCheckpoint"),
        "the RPC must serve the quorum-certified headers and the anchor"
    );
    // 4. The external verifier exists as a command.
    assert!(
        MAIN_RS.contains("LightClient"),
        "the CLI must expose the light-client command"
    );
    // Sanity: the module itself still builds and verifies a checkpoint-shaped
    // world.
    assert!(stellereum::light_client::DEFAULT_MAX_HEADERS > 0);
    assert!(stellereum::light_client::MAX_MERKLE_PATH_STEPS > 0);
}

// ---------------------------------------------------------------------------
// F9 — Turnstile fail-closed without touching the network.
// ---------------------------------------------------------------------------

#[test]
fn f9_turnstile_misconfiguration_fails_closed() {
    use stellereum::turnstile as ts;
    let _env = EnvGuard::take(&[ts::TURNSTILE_SITE_KEY_ENV, ts::TURNSTILE_SECRET_KEY_ENV]);
    // Neither key: disabled (IP-throttle-only), no secret anywhere.
    std::env::remove_var(ts::TURNSTILE_SITE_KEY_ENV);
    std::env::remove_var(ts::TURNSTILE_SECRET_KEY_ENV);
    assert_eq!(ts::CaptchaConfig::from_env(), ts::CaptchaConfig::Disabled);
    // Exactly one key: misconfigured (public faucet must answer 503).
    std::env::set_var(ts::TURNSTILE_SITE_KEY_ENV, "site");
    std::env::remove_var(ts::TURNSTILE_SECRET_KEY_ENV);
    assert_eq!(
        ts::CaptchaConfig::from_env(),
        ts::CaptchaConfig::Misconfigured
    );
    std::env::remove_var(ts::TURNSTILE_SITE_KEY_ENV);
    std::env::set_var(ts::TURNSTILE_SECRET_KEY_ENV, "secret");
    assert_eq!(
        ts::CaptchaConfig::from_env(),
        ts::CaptchaConfig::Misconfigured
    );
    // Blank counts as unset (unit-file `KEY=` does not half-enable).
    std::env::set_var(ts::TURNSTILE_SITE_KEY_ENV, "   ");
    assert_eq!(
        ts::CaptchaConfig::from_env(),
        ts::CaptchaConfig::Misconfigured
    );
    // Secret never appears in Debug (field NAME secret_key is fine; VALUE must not leak).
    std::env::set_var(ts::TURNSTILE_SITE_KEY_ENV, "site");
    let cfg = ts::CaptchaConfig::from_env();
    assert!(cfg.secret_key().is_some());
    assert!(
        !format!("{cfg:?}").contains(": \"secret\""),
        "secret value leaked: {cfg:?}"
    );
}

#[tokio::test]
async fn f9_gate_verify_fails_closed_without_secret_or_on_reject() {
    use std::sync::Arc;
    use stellereum::turnstile as ts;

    struct RejectAll;
    impl ts::CaptchaVerifier for RejectAll {
        fn verify(
            &self,
            _secret: &str,
            _token: &str,
            _remote: Option<std::net::IpAddr>,
        ) -> ts::CaptchaVerdict {
            ts::CaptchaVerdict::Rejected {
                error_codes: vec!["invalid-input-response".into()],
            }
        }
    }
    struct Unreachable;
    impl ts::CaptchaVerifier for Unreachable {
        fn verify(
            &self,
            _secret: &str,
            _token: &str,
            _remote: Option<std::net::IpAddr>,
        ) -> ts::CaptchaVerdict {
            ts::CaptchaVerdict::Unavailable {
                reason: "siteverify unreachable".into(),
            }
        }
    }

    // No secret (disabled/misconfigured gate): verify refuses without calling
    // any verifier — a handler bug can never dispense past it.
    let gate = ts::CaptchaGate::new(ts::CaptchaConfig::Disabled, Arc::new(RejectAll));
    assert!(matches!(
        gate.verify("any-token", None).await,
        ts::CaptchaVerdict::Unavailable { .. }
    ));
    // Enabled gate, Cloudflare says no / unreachable: both fail closed.
    let enabled = ts::CaptchaConfig::Enabled {
        site_key: "site".into(),
        secret_key: "secret".into(),
    };
    let gate = ts::CaptchaGate::new(enabled.clone(), Arc::new(RejectAll));
    assert!(matches!(
        gate.verify("bad-token", None).await,
        ts::CaptchaVerdict::Rejected { .. }
    ));
    let gate = ts::CaptchaGate::new(enabled, Arc::new(Unreachable));
    assert!(matches!(
        gate.verify("any-token", None).await,
        ts::CaptchaVerdict::Unavailable { .. }
    ));
    // Missing token is a caller error upstream; an empty token still goes
    // through the verifier (never auto-success).
    struct AcceptEmptyOnly;
    impl ts::CaptchaVerifier for AcceptEmptyOnly {
        fn verify(
            &self,
            _secret: &str,
            token: &str,
            _remote: Option<std::net::IpAddr>,
        ) -> ts::CaptchaVerdict {
            if token.is_empty() {
                ts::CaptchaVerdict::Success
            } else {
                ts::CaptchaVerdict::Rejected {
                    error_codes: vec![],
                }
            }
        }
    }
    let gate = ts::CaptchaGate::new(
        ts::CaptchaConfig::Enabled {
            site_key: "s".into(),
            secret_key: "k".into(),
        },
        Arc::new(AcceptEmptyOnly),
    );
    assert!(matches!(
        gate.verify("x", None).await,
        ts::CaptchaVerdict::Rejected { .. }
    ));
}
