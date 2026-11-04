//! Hunt D1 (wire/proof caps) + D5 (faucet rate persistence).
//!
//! D1: block packing enforces `MAX_BLOCK_WIRE_BYTES` (24MB) and
//! `MAX_BLOCK_PROOF_UNITS` (2048), but mempool admission accepts transactions
//! that can never fit any block. Such poison txs occupy pool slots (and can
//! fee-evict honest ones) while `select_*` skips them forever.
//!
//! D5: the per-IP faucet budget is process-local only; lifetime caps and the
//! nonce are persisted across restarts but the rate-limit buckets are not, so
//! every restart hands a rotating drain a fresh hourly budget.

use stellereum::mempool::Mempool;
use stellereum::rpc::Faucet;
use stellereum::sharding::Transaction;

fn snark_op() -> stellereum::svm::OpCode {
    stellereum::svm::OpCode::SysCallVerifyZkMlAttestation {
        model_id: [0xABu8; 32],
        proof: Box::new(stellereum::zkml_attestation::AttestationProof {
            model_hash: [0x01; 32],
            spec_hash: [0x02; 32],
            public_inputs: vec![],
            public_outputs: vec![],
            proof_bytes: vec![0xCC; 192],
        }),
    }
}

fn payload_tx(ops: Vec<stellereum::svm::OpCode>, nonce: u64) -> Transaction {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
    Transaction::sign_with_payload(&key, [0x99u8; 32], 10, 1_000, nonce, 1, 1, ops)
}

// D1: a single tx carrying more proof work than any block may verify (33 x 64
// = 2112 > 2048) must be refused at admission — it can never be packed.
#[test]
fn d1_proof_heavy_tx_rejected_at_admission() {
    let mut mp = Mempool::new(10_000, 256);
    let tx = payload_tx((0..33).map(|_| snark_op()).collect(), 0);
    assert_eq!(Mempool::count_tx_proof_units(&tx), 33 * 64);
    let r = mp.add_checked(tx, u64::MAX);
    assert!(
        r.is_err(),
        "proof-poison tx (2112 units > 2048 cap) must be rejected"
    );
}

// D1: a single tx whose estimated wire exceeds the whole block wire cap must
// be refused at admission.
#[test]
fn d1_wire_heavy_tx_rejected_at_admission() {
    let mut mp = Mempool::new(10_000, 256);
    let big = stellereum::svm::OpCode::SysCallVerifyZkMlReexec {
        model_id: [0xABu8; 32],
        proof: Box::new(stellereum::zkml::ZkMlProof {
            model_hash: [0x01; 32],
            public_inputs: vec![],
            public_outputs: vec![],
            proof_bytes: vec![0xDD; 25 * 1024 * 1024],
        }),
    };
    let tx = payload_tx(vec![big], 0);
    assert!(Mempool::estimate_tx_wire_bytes(&tx) > Mempool::MAX_BLOCK_WIRE_BYTES);
    let r = mp.add_checked(tx, u64::MAX);
    assert!(r.is_err(), "wire-poison tx (>24MB est) must be rejected");
}

// D1 guard against over-tightening: exactly at the proof cap (32 x 64 = 2048)
// and ordinary transfers must still admit.
#[test]
fn d1_boundary_and_honest_tx_still_admit() {
    let mut mp = Mempool::new(10_000, 256);
    let at_cap = payload_tx((0..32).map(|_| snark_op()).collect(), 0);
    assert_eq!(Mempool::count_tx_proof_units(&at_cap), 2048);
    assert!(
        mp.add_checked(at_cap, u64::MAX).is_ok(),
        "tx exactly at cap must admit"
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
    let honest = Transaction::sign(&key, [0x99u8; 32], 10, 1_000, 1, 1, 1);
    assert!(
        mp.add_checked(honest, u64::MAX).is_ok(),
        "honest tx must admit"
    );
}

// D5: exhausting a source's hourly budget, then "restarting" (fresh Faucet over
// the saved bytes), must NOT hand back a fresh budget.
#[tokio::test]
async fn d5_ip_budget_survives_restart() {
    let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    let t: u64 = 1_800_000_000;
    let old = Faucet::new([0x11u8; 32], 1, 10, 25);
    for _ in 0..stellereum::rpc::FAUCET_IP_MAX_PER_HOUR {
        assert!(
            old.check_ip_throttle(Some(ip), t).await,
            "budget should allow the first 20"
        );
    }
    assert!(
        !old.check_ip_throttle(Some(ip), t).await,
        "21st drip in the hour must be refused"
    );

    let bytes = old.save_bytes().await;
    let new = Faucet::new([0x11u8; 32], 1, 10, 25);
    new.load_bytes(&bytes).await;
    assert!(
        !new.check_ip_throttle(Some(ip), t).await,
        "hourly budget must survive a restart (no fresh 20 after reload)"
    );
    // A different source is unaffected by the exhausted one.
    let other: std::net::IpAddr = "198.51.100.9".parse().unwrap();
    assert!(
        new.check_ip_throttle(Some(other), t).await,
        "unrelated source keeps its budget"
    );
}

// D5: callers without an attributable source share one fallback budget — they
// are throttled, never exempt.
#[tokio::test]
async fn d5_unknown_source_uses_shared_fallback_bucket() {
    let t: u64 = 1_800_000_000;
    let f = Faucet::new([0x11u8; 32], 1, 10, 25);
    for _ in 0..stellereum::rpc::FAUCET_IP_MAX_PER_HOUR {
        assert!(f.check_ip_throttle(None, t).await);
    }
    assert!(
        !f.check_ip_throttle(None, t).await,
        "unknown source must also cap out"
    );
}

// D5: a record written before the rate buckets existed must still enforce its
// lifetime caps after migration (never re-open a capped address).
#[tokio::test]
async fn d5_legacy_state_blob_migrates_caps() {
    // Mirror of the pre-bucket layout: bincode encodes structs as bare field
    // sequences, so this produces byte-identical blobs to the old writer.
    #[derive(serde::Serialize)]
    struct LegacyState {
        next_nonce: u64,
        dispensed: std::collections::HashMap<[u8; 32], u64>,
    }
    let who = [0x42u8; 32];
    let legacy = LegacyState {
        next_nonce: 3,
        dispensed: [(who, 25u64)].into_iter().collect(),
    };
    let bytes = bincode::serialize(&legacy).unwrap();

    let f = Faucet::new([0x11u8; 32], 1, 10, 25);
    f.load_bytes(&bytes).await;
    assert_eq!(f.dispensed_to(who).await, 25, "migrated caps must hold");
    assert!(
        f.build_transfer(who, None, None).await.is_none(),
        "a capped address must stay capped after migration"
    );
    // And the migrated instance still throttles new sources normally.
    let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    assert!(f.check_ip_throttle(Some(ip), 1_800_000_000).await);
}

// D5: buckets older than the previous UTC hour are dead weight — a node that
// was offline for days must not carry them back.
#[tokio::test]
async fn d5_stale_buckets_pruned_on_load() {
    // Same trick: local mirror of the CURRENT layout with a hand-set bucket.
    #[derive(serde::Serialize)]
    struct CurrentState {
        next_nonce: u64,
        dispensed: std::collections::HashMap<[u8; 32], u64>,
        ip_buckets: std::collections::HashMap<String, (u64, u32)>,
    }
    let now_hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 3600)
        .unwrap_or(0);
    let stale = CurrentState {
        next_nonce: 0,
        dispensed: Default::default(),
        ip_buckets: [(
            "203.0.113.7".to_string(),
            (now_hour.saturating_sub(48), 20u32),
        )]
        .into_iter()
        .collect(),
    };
    let bytes = bincode::serialize(&stale).unwrap();
    let f = Faucet::new([0x11u8; 32], 1, 10, 25);
    f.load_bytes(&bytes).await;
    // The dead entry must be gone immediately after the load (before any new
    // drip re-adds a live bucket for the same key).
    let re = f.save_bytes().await;
    assert!(
        re.len() < bytes.len(),
        "pruned state must be smaller than the stale blob"
    );
    // ...and the source itself still works going forward.
    let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    let t = (now_hour + 1) * 3600;
    assert!(
        f.check_ip_throttle(Some(ip), t).await,
        "source keeps a live budget"
    );
}
