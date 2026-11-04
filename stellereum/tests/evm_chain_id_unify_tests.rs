//! M-02 single chain-id source: verification follows `effective_chain_id()`.
//!
//! NEW-FILE-ONLY: extends EVM coverage without touching any shared test.
//! Uses only the public API. Env discipline mirrors the sibling closeout
//! files: Rust runs tests in one binary on threads, so every test that
//! mutates the process environment takes this lock and restores on drop.
//! Other test binaries are separate processes — no cross-file races.

use std::sync::{Mutex, MutexGuard};

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

fn low_s_normalize(s: [u8; 32], recid_byte: u8) -> ([u8; 32], u8) {
    if evm::is_low_s(&s) {
        return (s, recid_byte);
    }
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
    (out, recid_byte ^ 1)
}

fn sign_legacy_for(chain_id: u64, nonce: u64) -> Vec<u8> {
    let key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let unsigned = evm::LegacyTransaction {
        nonce,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some([0x35u8; 20]),
        value: 1_000,
        data: Vec::new(),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain_id),
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[0..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let (s, recid_b) = low_s_normalize(s, recid.to_byte());
    evm::LegacyTransaction {
        v: chain_id * 2 + 35 + recid_b as u64,
        r,
        s,
        ..unsigned
    }
    .encode()
}

fn sign_eip1559_for(chain_id: u64, nonce: u64) -> Vec<u8> {
    let key = k256::ecdsa::SigningKey::from_slice(&[0x55u8; 32]).unwrap();
    let unsigned = evm::Eip1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: Some([0x36u8; 20]),
        value: 2_000,
        data: Vec::new(),
        access_list: Vec::new(),
        y_parity: 0,
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = key.sign_prehash_recoverable(&sighash).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[0..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let (s, y_parity) = low_s_normalize(s, recid.to_byte());
    evm::Eip1559Transaction {
        y_parity,
        v: y_parity as u64,
        r,
        s,
        ..unsigned
    }
    .encode()
}

fn dummy_stell_tx(nonce: u64) -> stellereum::sharding::Transaction {
    stellereum::sharding::Transaction {
        from: [0x11u8; 32],
        to: [0x22u8; 32],
        amount: 7,
        gas_limit: 21_000,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: vec![0u8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

#[test]
fn m02_default_deployment_5757_verifies_and_foreign_refused() {
    let _env = EnvGuard::take(&["STELL_CHAIN_ID"]);
    std::env::remove_var("STELL_CHAIN_ID");
    assert_eq!(evm::effective_chain_id(), 5757);
    // Pinned 5757 vectors still pass (official EIP-155 chain-1 vector stays refused).
    let official = hex::decode("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").unwrap();
    let official_decoded = evm::parse_legacy_transaction(&official).expect("official decodes");
    assert_eq!(official_decoded.chain_id, Some(1));
    assert!(official_decoded.verify_signature().is_err());
    assert!(evm::eth_send_raw_transaction_bytes(&official).is_err());
    // Fresh 5757 legacy + 1559 verify under their own (effective) id.
    let raw = sign_legacy_for(5757, 910_001);
    let decoded = evm::parse_legacy_transaction(&raw).expect("decodes");
    assert_eq!(decoded.chain_id, Some(5757));
    decoded.verify_signature().expect("5757 verifies");
    evm::eth_send_raw_transaction_bytes(&raw).expect("gate admits 5757");
    evm::evm_raw_to_stell_transaction(&raw).expect("settlement maps 5757");
    let raw1559 = sign_eip1559_for(5757, 910_002);
    let d1559 = evm::parse_eip1559_envelope(&raw1559).expect("decodes");
    assert_eq!(d1559.chain_id, 5757);
    d1559.verify_signature().expect("5757 1559 verifies");
    evm::eth_send_raw_transaction_bytes(&raw1559).expect("gate admits 5757 1559");
    // Served views agree with the served identity.
    assert_eq!(evm::eth_chain_id(), "0x167d");
    assert_eq!(evm::net_version(), "5757");
    let view = evm::stell_tx_to_evm(&dummy_stell_tx(910_003), None, None, None);
    let v = serde_json::to_value(&view).unwrap();
    assert_eq!(v["chainId"], serde_json::json!("0x167d"));
}

#[test]
fn m02_custom_chain_verifies_under_own_id_and_mismatch_refused() {
    let _env = EnvGuard::take(&["STELL_CHAIN_ID"]);
    std::env::set_var("STELL_CHAIN_ID", "1234");
    assert_eq!(evm::effective_chain_id(), 1234);
    assert_eq!(evm::eth_chain_id(), "0x4d2");
    assert_eq!(evm::net_version(), "1234");
    // Custom 1234 legacy verifies at every strict layer.
    let raw = sign_legacy_for(1234, 920_001);
    let decoded = evm::parse_legacy_transaction(&raw).expect("decodes");
    assert_eq!(decoded.chain_id, Some(1234));
    decoded.verify_signature().expect("custom verifies");
    let sighash = decoded.signing_hash();
    evm::validate_transaction_signature(&sighash, decoded.v, &decoded.r, &decoded.s)
        .expect("validate follows effective");
    let h = evm::eth_send_raw_transaction_bytes(&raw).expect("gate admits custom");
    assert!(h.starts_with("0x") && h.len() == 66);
    evm::evm_raw_to_stell_transaction(&raw).expect("settlement maps custom");
    // Custom 1234 EIP-1559 verifies too.
    let raw1559 = sign_eip1559_for(1234, 920_002);
    let d1559 = evm::parse_eip1559_envelope(&raw1559).expect("decodes");
    d1559.verify_signature().expect("custom 1559 verifies");
    evm::eth_send_raw_transaction_bytes(&raw1559).expect("gate admits custom 1559");
    // 5757 bytes are now foreign and must be refused (mismatch names 1234).
    let raw5757 = sign_legacy_for(5757, 920_003);
    let d5757 = evm::parse_legacy_transaction(&raw5757).expect("decodes");
    let err = d5757.verify_signature().expect_err("5757 refused under 1234");
    assert_eq!(
        err,
        evm::EvmError::ChainIdMismatch {
            expected: 1234,
            got: 5757
        }
    );
    let gate_err = evm::eth_send_raw_transaction_bytes(&raw5757).expect_err("gate refuses 5757");
    assert!(
        gate_err.message.contains("1234"),
        "gate must name effective chain, got: {}",
        gate_err.message
    );
    // Views follow the effective id as well.
    let view = evm::stell_tx_to_evm(&dummy_stell_tx(920_004), None, None, None);
    let v = serde_json::to_value(&view).unwrap();
    assert_eq!(v["chainId"], serde_json::json!("0x4d2"));
    let adapter = evm::EvmAdapter::new();
    assert_eq!(adapter.chain_id, 1234);
}
