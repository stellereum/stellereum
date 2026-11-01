//! Integration and Enforcement Tests for Pure Post-Quantum Mode
//!
//! Verifies:
//! 1. When Pure PQ mode is inactive (default):
//!    - Both legacy Ed25519 and PQ transactions are admitted into mempool and verify.
//!    - Both classical QCs and PQ Micro-QCs verify under consensus.
//! 2. When Pure PQ mode is active:
//!    - Legacy transactions are rejected by mempool with `MempoolError::Malformed`.
//!    - Post-quantum transactions (PQ1 envelope) are admitted.
//! 3. When Pure PQ mode is active:
//!    - Classical Ed25519 QCs are rejected by consensus.
//!    - PQ Micro-QCs (Falcon-512) verify successfully.
//! 4. Thread-safe overrides and environment variable resolution (`STELL_PURE_PQ`).

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::sync::Mutex;
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, derive_sortition_committee, encode_pq_micro_envelope,
    micro_committee_size, register_validator_pq_key, vote_sign_bytes, Height, PqMicroCertificate,
    QuorumCertificate, Round, ValidatorSet, VoteKind, PQ_UQC_MARKER_ID,
};
use stellereum::mempool::{Mempool, MempoolError};
use stellereum::post_quantum::{
    derive_pq_address, is_pure_pq_enforced, set_pure_pq_override, FalconKeypair, DEFAULT_SALT,
};
use stellereum::sharding::Transaction;

/// Guard to prevent concurrent environment/atomic override mutations during tests.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn make_legacy_tx(nonce: u64) -> Transaction {
    let sk = SigningKey::generate(&mut OsRng);
    Transaction::sign(&sk, [2u8; 32], 100, 10_000, nonce, 1, 1)
}

fn make_pq_tx(seed: u8, nonce: u64) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(stellereum::post_quantum::PqScheme::Falcon512, &pk, &salt);
    let mut tx = Transaction {
        from,
        to: [3u8; 32],
        amount: 100,
        gas_limit: 100_000,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = stellereum::post_quantum::PqSignatureEnvelope::new_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        pk,
        sig,
    );
    tx.signature = envelope.encode();
    tx
}

fn make_classical_qc() -> (ValidatorSet, QuorumCertificate) {
    let mut vs = ValidatorSet::new();
    let signers: Vec<SigningKey> = (1..=4).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    for sk in &signers {
        vs.add(sk.verifying_key().to_bytes(), 10);
    }
    let height: Height = 10;
    let round: Round = 1;
    let kind = VoteKind::Precommit;
    let block_hash = Some([0xAA; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);

    // 3 of 4 validators sign (30 power >= 28 quorum power)
    let mut signatures = Vec::new();
    for sk in &signers[0..3] {
        let sig = sk.sign(&msg).to_bytes().to_vec();
        signatures.push((sk.verifying_key().to_bytes(), sig));
    }
    let qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures,
    };
    (vs, qc)
}

fn make_pq_uqc() -> (ValidatorSet, QuorumCertificate) {
    clear_validator_pq_keys_for_tests();
    let mut vs = ValidatorSet::new();
    let mut falcon_keys = Vec::new();
    for i in 0..20u8 {
        // Real keypair: the µQC is verified with FIPS 206 math (the old BLAKE3
        // check-digest shortcut is compiled out of non-test builds), so the
        // committee must sign with genuine Falcon keys.
        let fk = FalconKeypair::generate_from_seed(i + 10);
        let pk = fk.public_key().to_vec();
        let id = derive_pq_address(
            stellereum::post_quantum::PqScheme::Falcon512,
            &pk,
            &DEFAULT_SALT,
        );
        vs.add(id, 10);
        register_validator_pq_key(id, stellereum::post_quantum::PqScheme::Falcon512, pk);
        falcon_keys.push((id, fk));
    }

    let height: Height = 42;
    let round: Round = 1;
    // AUDIT W6.5: the committee size is the SHARED production rule
    // (`micro_committee_size`), not a literal: a test that hard-codes it
    // drifts from the verifier and then fails for the wrong reason.
    let committee_size: u32 = micro_committee_size(vs.len());
    let parent = [0x9u8; 32];
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), committee_size as usize);

    let kind = VoteKind::Precommit;
    let block_hash = Some([0xBB; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);

    let mut signatures = Vec::new();
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    for (i, val_id) in committee.iter().enumerate() {
        let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
        let sig = fk.sign(&msg);
        signatures.push(sig);
        bitmask[i / 8] |= 1 << (i % 8);
    }

    let uqc = PqMicroCertificate {
        scheme: stellereum::post_quantum::PqScheme::Falcon512,
        height,
        round,
        committee_size,
        signers_bitmask: bitmask,
        signatures,
        sortition_parent: parent,
        // Predates the phase-3 VRF seal (mechanical fallout of the new
        // trailing field): legacy draw.
        vrf_beacon: None,
    };

    let payload = encode_pq_micro_envelope(&uqc);
    let qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, payload)],
    };
    (vs, qc)
}

#[test]
fn test_pure_pq_inactive_admits_both_legacy_and_pq() {
    let _guard = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(false));
    assert!(!is_pure_pq_enforced(), "Pure PQ mode must be inactive");

    // 1. Legacy Ed25519 transaction
    let legacy_tx = make_legacy_tx(1);
    assert!(!legacy_tx.is_pq());
    assert!(legacy_tx.verify_signature());

    let mut mp = Mempool::new(100, 100);
    assert!(
        mp.add(legacy_tx).is_ok(),
        "Legacy Ed25519 tx must be admitted when pure PQ is inactive"
    );

    // 2. Post-Quantum transaction
    let pq_tx = make_pq_tx(0x42, 1);
    assert!(pq_tx.is_pq());
    assert!(pq_tx.verify_signature());
    assert!(
        mp.add(pq_tx).is_ok(),
        "PQ Falcon-512 tx must be admitted when pure PQ is inactive"
    );

    // 3. Classical QC and PQ Micro-QC
    let (vs_classical, classical_qc) = make_classical_qc();
    assert!(
        classical_qc.verify_unified(&vs_classical),
        "Classical QC must verify when pure PQ is inactive"
    );

    let (vs_pq, pq_qc) = make_pq_uqc();
    assert!(
        pq_qc.verify_unified(&vs_pq),
        "PQ Micro-QC must verify when pure PQ is inactive"
    );

    set_pure_pq_override(None);
}

#[test]
fn test_pure_pq_active_rejects_legacy_in_mempool() {
    let _guard = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced(), "Pure PQ mode must be enforced");

    let mut mp = Mempool::new(100, 100);

    // Legacy Ed25519 transaction must be rejected
    let legacy_tx = make_legacy_tx(1);
    assert!(!legacy_tx.is_pq());
    let err = mp.add(legacy_tx).unwrap_err();
    assert_eq!(
        err,
        MempoolError::Malformed(
            "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope"
                .to_string()
        ),
        "Classical transaction must be rejected with exact error in pure PQ mode"
    );

    // Post-Quantum transaction must be admitted
    let pq_tx = make_pq_tx(0x55, 1);
    assert!(pq_tx.is_pq());
    assert!(
        mp.add(pq_tx).is_ok(),
        "PQ transaction must be admitted in pure PQ mode"
    );

    set_pure_pq_override(None);
}

#[test]
fn test_pure_pq_active_rejects_classical_qcs_in_consensus() {
    let _guard = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced(), "Pure PQ mode must be enforced");

    // Classical QC must be rejected
    let (vs_classical, classical_qc) = make_classical_qc();
    assert!(
        !classical_qc.verify_unified(&vs_classical),
        "Classical QC must be rejected under pure PQ mode"
    );
    assert!(
        !classical_qc.verify(&vs_classical),
        "Classical QC must fail verify() under pure PQ mode"
    );

    // PQ Micro-QC must verify
    let (vs_pq, pq_qc) = make_pq_uqc();
    assert!(
        pq_qc.verify_unified(&vs_pq),
        "PQ Micro-QC must pass verify_unified under pure PQ mode"
    );
    assert!(
        pq_qc.verify(&vs_pq),
        "PQ Micro-QC must pass verify under pure PQ mode"
    );

    set_pure_pq_override(None);
}

#[test]
fn test_pure_pq_env_and_override_resolution() {
    let _guard = TEST_LOCK.lock().unwrap();

    // 1. Thread-safe override takes priority over env var
    std::env::set_var("STELL_PURE_PQ", "1");
    set_pure_pq_override(Some(false));
    assert!(!is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "0");
    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced());

    // 2. When override is None, resolve from STELL_PURE_PQ env var
    set_pure_pq_override(None);

    std::env::set_var("STELL_PURE_PQ", "1");
    assert!(is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "true");
    assert!(is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "TRUE");
    assert!(is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "always");
    assert!(is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "ALWAYS");
    assert!(is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "0");
    assert!(!is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "false");
    assert!(!is_pure_pq_enforced());

    std::env::set_var("STELL_PURE_PQ", "");
    assert!(!is_pure_pq_enforced());

    std::env::remove_var("STELL_PURE_PQ");
    assert!(!is_pure_pq_enforced());
}
