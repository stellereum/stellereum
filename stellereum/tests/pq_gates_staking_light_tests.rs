//! PQ gate-first tests: staking ED-fallback + slash paths + light-client quorum.
//!
//!mirrors the Phase-2 gate rows P2-10 (staking `get_pq_key`), P2-11 (PQ
//!equivocation evidence) and P2-16 (light-client quorum). Every gate is
//!proved twice: default (non-pure-PQ) behavior is byte-identical to before,
//!and pure-PQ mode fail-closes on classical material.
//!
//!Process-wide override hygiene: the lib (built without `cfg(test)` here)
//!holds the pure-PQ switch in a process-wide atomic, so all tests in this
//!binary serialize on `TEST_LOCK` and reset the override plus the global PQ
//!key registry on every iteration (same pattern as
//!`pure_pq_enforcement_tests.rs`).

use ed25519_dalek::{Signer, SigningKey};
use std::sync::Mutex;
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, register_validator_pq_key, vote_sign_bytes,
    EquivocationEvidence, QuorumCertificate, ValidatorSet, Vote, VoteKind,
};
use stellereum::light_client::LightHeader;
use stellereum::post_quantum::{
    set_pure_pq_override, FalconKeypair, PqScheme, FALCON512_SIG_LEN,
};
use stellereum::staking::{
    CompactPqEquivocationEvidence, StakingError, StakingLedger, DEFAULT_COMMISSION_BPS,
};

/// Serializes every test in this binary: the pure-PQ override is process-wide.
static TEST_LOCK: Mutex<()> = Mutex::new(());

const STELL: u64 = 1_000_000_000;
const BOND: u64 = 5_000 * STELL;
/// 5% of [`BOND`] ([`stellereum::staking::EQUIVOCATION_SLASH_BPS`]).
const BURN_5PC: u64 = 250 * STELL;

fn bonded(vid: [u8; 32]) -> StakingLedger {
    let mut l = StakingLedger::new();
    l.bond(vid, BOND, DEFAULT_COMMISSION_BPS)
        .expect("bond above MIN+buffer floor");
    l
}

fn ed_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Conflicting ed-only vote pair by `sk` (no Falcon half).
fn ed_votes(sk: &SigningKey, h: u64, r: u32) -> (Vote, Vote) {
    let voter = sk.verifying_key().to_bytes();
    let a = Vote::sign(sk, h, r, VoteKind::Prevote, Some([0xAA; 32]));
    let b = Vote::sign(sk, h, r, VoteKind::Prevote, Some([0xBB; 32]));
    assert_eq!(a.voter, voter);
    (a, b)
}

/// Conflicting dual-signed (ed + Falcon envelope) vote pair.
fn falcon_votes(sk: &SigningKey, fk: &FalconKeypair, h: u64, r: u32) -> (Vote, Vote) {
    let a = Vote::sign_with_falcon(sk, fk, h, r, VoteKind::Prevote, Some([0xAA; 32]));
    let b = Vote::sign_with_falcon(sk, fk, h, r, VoteKind::Prevote, Some([0xBB; 32]));
    assert!(a.falcon_signature().is_some());
    assert!(b.falcon_signature().is_some());
    (a, b)
}

fn compact_ed_evidence(sk: &SigningKey, h: u64, r: u32) -> CompactPqEquivocationEvidence {
    let voter = sk.verifying_key().to_bytes();
    let target_a = Some([0xAA; 32]);
    let target_b = Some([0xBB; 32]);
    let msg_a = vote_sign_bytes(h, r, VoteKind::Prevote, &target_a);
    let msg_b = vote_sign_bytes(h, r, VoteKind::Prevote, &target_b);
    CompactPqEquivocationEvidence {
        voter,
        height: h,
        round: r,
        kind: VoteKind::Prevote,
        block_hash_a: target_a,
        signature_a: sk.sign(&msg_a).to_bytes().to_vec(),
        block_hash_b: target_b,
        signature_b: sk.sign(&msg_b).to_bytes().to_vec(),
    }
}

fn compact_falcon_evidence(
    voter: [u8; 32],
    fk: &FalconKeypair,
    h: u64,
    r: u32,
) -> CompactPqEquivocationEvidence {
    let target_a = Some([0xAA; 32]);
    let target_b = Some([0xBB; 32]);
    let msg_a = vote_sign_bytes(h, r, VoteKind::Prevote, &target_a);
    let msg_b = vote_sign_bytes(h, r, VoteKind::Prevote, &target_b);
    let sig_a = fk.sign(&msg_a);
    let sig_b = fk.sign(&msg_b);
    assert_eq!(sig_a.len(), FALCON512_SIG_LEN);
    CompactPqEquivocationEvidence {
        voter,
        height: h,
        round: r,
        kind: VoteKind::Prevote,
        block_hash_a: target_a,
        signature_a: sig_a,
        block_hash_b: target_b,
        signature_b: sig_b,
    }
}

fn light_header(block_hash: [u8; 32], sigs: Vec<([u8; 32], Vec<u8>)>) -> LightHeader {
    LightHeader {
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        block_hash,
        timestamp: 0,
        proposer: [0u8; 32],
        cert: QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: Vec::new(),
        },
        signatures: sigs,
    }
}

// --- P2-10: `get_pq_key` ED-fallback ----------------------------------------

#[test]
fn ed_fallback_present_without_enforcement() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(false));
    clear_validator_pq_keys_for_tests();
    let l = bonded([0x11; 32]);
    assert_eq!(
        l.get_pq_key(&[0x11; 32]),
        Some((PqScheme::Ed25519, [0x11; 32].to_vec()))
    );
    // Unknown validator: None in both modes (no fallback for non-members).
    assert_eq!(l.get_pq_key(&[0xFF; 32]), None);
    set_pure_pq_override(None);
}

#[test]
fn ed_fallback_refused_under_pure_pq() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(true));
    clear_validator_pq_keys_for_tests();
    let l = bonded([0x11; 32]);
    // Member with no registered PQ key: NO classical key material.
    assert_eq!(l.get_pq_key(&[0x11; 32]), None);
    // Non-member: still None.
    assert_eq!(l.get_pq_key(&[0xFF; 32]), None);
    set_pure_pq_override(None);
}

#[test]
fn registered_key_returned_in_both_modes() {
    let _lock = TEST_LOCK.lock().unwrap();
    clear_validator_pq_keys_for_tests();
    let mut l = bonded([0x11; 32]);
    let fk = FalconKeypair::generate_from_seed(11);
    let pk = fk.public_key().to_vec();
    l.register_pq_key([0x11; 32], PqScheme::Falcon512, pk.clone())
        .unwrap();
    for enforced in [false, true] {
        set_pure_pq_override(Some(enforced));
        assert_eq!(
            l.get_pq_key(&[0x11; 32]),
            Some((PqScheme::Falcon512, pk.clone())),
            "registered key must resolve with enforced={enforced}"
        );
    }
    set_pure_pq_override(None);
}

// --- Vote-slash path (`slash_equivocation_verified`, ~staking.rs:2321) ------

#[test]
fn vote_slash_ed_evidence_slashes_without_enforcement() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(false));
    clear_validator_pq_keys_for_tests();
    let sk = ed_key(0x21);
    let voter = sk.verifying_key().to_bytes();
    let mut l = bonded(voter);
    let (a, b) = ed_votes(&sk, 10, 0);
    let ev = EquivocationEvidence::new(voter, a, b);
    assert_eq!(l.slash_equivocation_verified(&ev).unwrap(), BURN_5PC);
    assert_eq!(l.total_stake(&voter), BOND - BURN_5PC);
    set_pure_pq_override(None);
}

#[test]
fn vote_slash_ed_evidence_refused_under_pure_pq() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(true));
    clear_validator_pq_keys_for_tests();
    let sk = ed_key(0x22);
    let voter = sk.verifying_key().to_bytes();
    let mut l = bonded(voter);
    let (a, b) = ed_votes(&sk, 10, 0);
    // Classical-only evidence: refused, no slash computed from it.
    let ev = EquivocationEvidence::new(voter, a, b);
    assert_eq!(l.slash_equivocation_verified(&ev).unwrap(), 0);
    assert_eq!(l.total_stake(&voter), BOND);
    set_pure_pq_override(None);
}

#[test]
fn vote_slash_falcon_evidence_slashes_in_both_modes() {
    let _lock = TEST_LOCK.lock().unwrap();
    for enforced in [false, true] {
        set_pure_pq_override(Some(enforced));
        clear_validator_pq_keys_for_tests();
        let sk = ed_key(0x23);
        let voter = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(0x23);
        // `Vote::verify` resolves the Falcon half through the global registry.
        register_validator_pq_key(voter, PqScheme::Falcon512, fk.public_key().to_vec());
        let mut l = bonded(voter);
        let (a, b) = falcon_votes(&sk, &fk, 10, 0);
        let ev = EquivocationEvidence::new(voter, a, b);
        assert_eq!(
            l.slash_equivocation_verified(&ev).unwrap(),
            BURN_5PC,
            "dual-signed evidence must slash with enforced={enforced}"
        );
        assert_eq!(l.total_stake(&voter), BOND - BURN_5PC);
    }
    clear_validator_pq_keys_for_tests();
    set_pure_pq_override(None);
}

// --- PQ-slash path (`slash_pq_equivocation`, ~staking.rs:2698) --------------

#[test]
fn pq_slash_ed_fallback_slashes_without_enforcement() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(false));
    clear_validator_pq_keys_for_tests();
    let sk = ed_key(0x31);
    let voter = sk.verifying_key().to_bytes();
    let mut l = bonded(voter);
    let ev = compact_ed_evidence(&sk, 20, 0);
    assert_eq!(l.slash_pq_equivocation(&ev, false).unwrap(), BURN_5PC);
    assert_eq!(l.total_stake(&voter), BOND - BURN_5PC);
    set_pure_pq_override(None);
}

#[test]
fn pq_slash_ed_fallback_refused_under_pure_pq() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(true));
    clear_validator_pq_keys_for_tests();
    let sk = ed_key(0x32);
    let voter = sk.verifying_key().to_bytes();
    let mut l = bonded(voter);
    let ev = compact_ed_evidence(&sk, 20, 0);
    // Unregistered validator under pure-PQ: fail-closed error, nothing burns.
    assert_eq!(
        l.slash_pq_equivocation(&ev, false),
        Err(StakingError::InvalidSignature)
    );
    assert_eq!(l.total_stake(&voter), BOND);
    set_pure_pq_override(None);
}

#[test]
fn pq_slash_falcon_happy_in_both_modes() {
    let _lock = TEST_LOCK.lock().unwrap();
    for enforced in [false, true] {
        set_pure_pq_override(Some(enforced));
        clear_validator_pq_keys_for_tests();
        let sk = ed_key(0x33);
        let voter = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(0x33);
        let mut l = bonded(voter);
        l.register_pq_key(voter, PqScheme::Falcon512, fk.public_key().to_vec())
            .unwrap();
        let ev = compact_falcon_evidence(voter, &fk, 20, 0);
        assert_eq!(
            l.slash_pq_equivocation(&ev, false).unwrap(),
            BURN_5PC,
            "Falcon evidence must slash with enforced={enforced}"
        );
        assert_eq!(l.total_stake(&voter), BOND - BURN_5PC);
    }
    set_pure_pq_override(None);
}

#[test]
fn pq_slash_registered_classical_refused_only_under_pure_pq() {
    let _lock = TEST_LOCK.lock().unwrap();
    for enforced in [false, true] {
        set_pure_pq_override(Some(enforced));
        clear_validator_pq_keys_for_tests();
        let sk = ed_key(0x34);
        let voter = sk.verifying_key().to_bytes();
        let mut l = bonded(voter);
        // Explicit classical registration (not the unregistered fallback).
        l.register_pq_key(voter, PqScheme::Ed25519, voter.to_vec())
            .unwrap();
        let ev = compact_ed_evidence(&sk, 20, 0);
        if enforced {
            assert_eq!(
                l.slash_pq_equivocation(&ev, false),
                Err(StakingError::InvalidSignature)
            );
            assert_eq!(l.total_stake(&voter), BOND);
        } else {
            assert_eq!(l.slash_pq_equivocation(&ev, false).unwrap(), BURN_5PC);
        }
    }
    set_pure_pq_override(None);
}

// --- P2-16: light-client quorum (~light_client.rs:582) ----------------------

#[test]
fn light_quorum_ed_counts_without_enforcement() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(false));
    clear_validator_pq_keys_for_tests();
    let sk = ed_key(0x41);
    let val_id = sk.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(val_id, 1)]);
    let block_hash = [0x44; 32];
    let sig = sk.sign(&block_hash).to_bytes().to_vec();
    let header = light_header(block_hash, vec![(val_id, sig)]);
    assert!(header.verify_validator_quorum(&validators).is_ok());
    set_pure_pq_override(None);
}

#[test]
fn light_quorum_ed_refused_under_pure_pq() {
    let _lock = TEST_LOCK.lock().unwrap();
    set_pure_pq_override(Some(true));
    clear_validator_pq_keys_for_tests();
    let sk = ed_key(0x42);
    let val_id = sk.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(val_id, 1)]);
    let block_hash = [0x44; 32];
    let sig = sk.sign(&block_hash).to_bytes().to_vec();
    let header = light_header(block_hash, vec![(val_id, sig)]);
    // Classical-only quorum carries no countable power in pure-PQ.
    assert!(header.verify_validator_quorum(&validators).is_err());
    set_pure_pq_override(None);
}

#[test]
fn light_quorum_falcon_counts_in_both_modes() {
    let _lock = TEST_LOCK.lock().unwrap();
    for enforced in [false, true] {
        set_pure_pq_override(Some(enforced));
        clear_validator_pq_keys_for_tests();
        let fk = FalconKeypair::generate_from_seed(0x43);
        let falcon_id = fk.validator_id();
        let validators = ValidatorSet::from_list(vec![(falcon_id, 1)]);
        register_validator_pq_key(falcon_id, PqScheme::Falcon512, fk.public_key().to_vec());
        let block_hash = [0x45; 32];
        let sig = fk.sign(&block_hash);
        let header = light_header(block_hash, vec![(falcon_id, sig)]);
        assert!(
            header.verify_validator_quorum(&validators).is_ok(),
            "Falcon quorum must verify with enforced={enforced}"
        );
    }
    clear_validator_pq_keys_for_tests();
    set_pure_pq_override(None);
}

#[test]
fn light_quorum_empty_accepted_in_both_modes() {
    let _lock = TEST_LOCK.lock().unwrap();
    for enforced in [false, true] {
        set_pure_pq_override(Some(enforced));
        clear_validator_pq_keys_for_tests();
        let sk = ed_key(0x44);
        let val_id = sk.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(val_id, 1)]);
        let header = light_header([0x46; 32], Vec::new());
        assert!(
            header.verify_validator_quorum(&validators).is_ok(),
            "empty attestation list stays accepted with enforced={enforced}"
        );
    }
    set_pure_pq_override(None);
}
