//! QC_SPLIT producer suites (lib unit tests): full-network decision
//! certificate (C1 split, FIXES §1.7).
//!
//! These pin the producer that was missing when the split gate was added:
//! before it, activating `QC_SPLIT_ACTIVATION_HEIGHT` made the verifier
//! refuse every locally produced µQC while nothing emitted the epoch/CEC
//! certificate finality requires — activation would halt finality.
//!
//! `QC_SPLIT_ACTIVATION_HEIGHT` itself stays `u64::MAX` (frozen off); the
//! ACTIVE branch is driven through the thread-scoped
//! [`set_qc_split_activation_override`] knob, like the project's other gates.
//! The companion integration suite
//! (`tests/qc_split_producer_tests.rs`) proves the same public surface from
//! outside the crate.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use super::*;
use crate::post_quantum::{FalconKeypair, PqScheme};

/// Thread-scoped activation override guard: clears the override on drop.
struct ActivationOverride;

impl ActivationOverride {
    fn at(height: Height) -> Self {
        set_qc_split_activation_override(Some(height));
        Self
    }
}

impl Drop for ActivationOverride {
    fn drop(&mut self) {
        set_qc_split_activation_override(None);
    }
}

fn validator_id(key: &SigningKey) -> ValidatorId {
    key.verifying_key().to_bytes()
}

/// Deterministic Ed + Falcon key sets; every Falcon key is registered in the
/// same committed registry the production resolver reads.
fn key_set(n: u8) -> (Vec<SigningKey>, Vec<FalconKeypair>) {
    let ks: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[0xB0u8.wrapping_add(i); 32]))
        .collect();
    let fks: Vec<FalconKeypair> = ks
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = FalconKeypair::generate_from_seed(0xB0 + i as u8);
            register_validator_pq_key(validator_id(k), PqScheme::Falcon512, fk.public_key.clone());
            fk
        })
        .collect();
    (ks, fks)
}

fn uniform_set(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (validator_id(k), 1)).collect())
}

fn votes_for(
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    height: Height,
    round: Round,
    kind: VoteKind,
    target: Option<BlockHash>,
) -> Vec<Vote> {
    ks.iter()
        .zip(fks.iter())
        .map(|(k, fk)| Vote::sign_with_falcon(k, fk, height, round, kind, target))
        .collect()
}

fn vote_set(
    votes: Vec<Vote>,
    vs: &ValidatorSet,
    height: Height,
    round: Round,
    kind: VoteKind,
) -> VoteSet {
    let mut set = VoteSet::new();
    for vote in votes {
        set.add(vote, vs, height, round, kind)
            .expect("fixture vote must be admitted");
    }
    set
}

fn pq_key_map(ks: &[SigningKey], fks: &[FalconKeypair]) -> PqKeyMap {
    ks.iter()
        .zip(fks.iter())
        .map(|(k, fk)| {
            (
                validator_id(k),
                (PqScheme::Falcon512, fk.public_key.clone()),
            )
        })
        .collect()
}

/// Producer → verifier round trip at the activation height.
#[test]
fn qc_split_producer_verifier_round_trip() {
    const HEIGHT: Height = 10;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = key_set(4);
    let vs = uniform_set(&ks);
    let pq_map = pq_key_map(&ks, &fks);
    let target = Some([0x51u8; 32]);
    let set = vote_set(
        votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target),
        &vs,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );
    assert!(set.quorum_reached(target, &vs), "4-of-4 must hold quorum");

    let qc = produce_decision_certificate(&set, target, &vs, Some(&[0x50u8; 32]))
        .expect("a full-quorum vote set must produce a decision certificate");

    assert_eq!(qc.signatures.len(), 1, "exactly one marker entry");
    assert_eq!(
        qc.signatures[0].0, PQ_QC_MARKER_ID,
        "post-activation decision QC must be the epoch/CEC envelope"
    );
    assert!(
        qc.pq_micro_certificate().is_none(),
        "the CEC is not a µQC subset envelope"
    );

    let cert = decode_pq_epoch_envelope(&qc.signatures[0].1)
        .expect("the marker payload must decode as an epoch envelope");
    assert_eq!(
        cert.committee_size, 4,
        "CEC committee_size is the FULL validator set"
    );
    assert_eq!(
        cert.signed_count(),
        4,
        "every voting validator signs — the full set, not a µQC subset"
    );
    assert_eq!(cert.signatures.len(), 4);

    assert!(
        qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)),
        "verify_with_pq_keys must accept the produced CEC"
    );
    assert!(
        qc.verify(&vs),
        "registry-resolved verify must accept it too"
    );
    assert!(vs.qc_meets_quorum(&qc), "the CEC must carry quorum power");

    let expected: HashSet<ValidatorId> = ks.iter().map(validator_id).collect();
    assert_eq!(
        qc.signers_set(&vs),
        expected,
        "attribution must name exactly the full signer set"
    );
}

/// Height boundary: below the activation the legacy µQC producer/verifier
/// path is unchanged; at and above it the producer emits a CEC and the old
/// µQC path is REFUSED (fail closed).
#[test]
fn qc_split_boundary_switches_kind_and_refuses_micro_qc() {
    const ACTIVATION: Height = 50;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(ACTIVATION);

    let (ks, fks) = key_set(4);
    let vs = uniform_set(&ks);
    let target = Some([0x61u8; 32]);
    let parent = [0x60u8; 32];

    // BELOW the boundary: legacy µQC, accepted.
    let below_height = ACTIVATION - 1;
    assert!(!qc_split_active_at(below_height));
    let below = vote_set(
        votes_for(&ks, &fks, below_height, ROUND, VoteKind::Precommit, target),
        &vs,
        below_height,
        ROUND,
        VoteKind::Precommit,
    );
    let qc_below = produce_decision_certificate(&below, target, &vs, Some(&parent))
        .expect("legacy producer path must still produce a certificate");
    assert!(
        qc_below.pq_micro_certificate().is_some(),
        "below activation the producer keeps the legacy µQC"
    );
    assert_eq!(
        qc_below
            .signatures
            .iter()
            .filter(|(voter, _)| *voter == PQ_UQC_MARKER_ID)
            .count(),
        1,
        "legacy path carries exactly one µQC marker"
    );
    assert!(
        qc_below.verify(&vs),
        "pre-activation µQC must verify (byte-identical legacy behavior)"
    );

    // AT and ABOVE the boundary: CEC from the producer, old-path µQC refused.
    for height in [ACTIVATION, ACTIVATION + 1] {
        assert!(qc_split_active_at(height));
        let set = vote_set(
            votes_for(&ks, &fks, height, ROUND, VoteKind::Precommit, target),
            &vs,
            height,
            ROUND,
            VoteKind::Precommit,
        );

        let qc = produce_decision_certificate(&set, target, &vs, Some(&parent))
            .expect("a full-quorum set must produce a CEC once active");
        assert_eq!(
            qc.signatures[0].0, PQ_QC_MARKER_ID,
            "active producer must emit the epoch/CEC marker at h={height}"
        );
        assert!(qc.verify(&vs), "the produced CEC must verify at h={height}");

        // The same votes through the OLD µQC path: refused at/after the
        // activation height, fail closed.
        let legacy = set
            .certificate_with_parent(target, &vs, Some(&parent))
            .expect("the legacy assembler still builds bytes");
        assert!(
            legacy.pq_micro_certificate().is_some(),
            "fixture must really be a µQC"
        );
        assert!(
            !legacy.verify(&vs),
            "µQC must be REFUSED at activation height h={height}"
        );
        assert!(
            !legacy.verify_unified(&vs),
            "verify_unified must refuse the µQC at h={height} too"
        );
        assert!(
            !vs.qc_meets_quorum(&legacy),
            "power accounting must refuse the µQC at h={height}: attribution is \
             fail-closed under the split, so a decision boundary cannot bypass"
        );
        assert!(
            legacy.signers_set(&vs).is_empty(),
            "a refused µQC attributes nobody"
        );
    }
}

/// Two nodes that admitted the same votes in different arrival orders must
/// produce byte-identical certificates (canonical ordering, no map iteration
/// order in the wire bytes).
#[test]
fn qc_split_producer_is_deterministic_across_admission_order() {
    const HEIGHT: Height = 20;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = key_set(4);
    let vs = uniform_set(&ks);
    let target = Some([0x71u8; 32]);
    // Sign ONCE: determinism is about identical vote bytes, not Falcon's
    // randomized signing.
    let votes = votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target);

    let forward = vote_set(votes.clone(), &vs, HEIGHT, ROUND, VoteKind::Precommit);
    let mut reversed_votes = votes;
    reversed_votes.reverse();
    let reversed = vote_set(reversed_votes, &vs, HEIGHT, ROUND, VoteKind::Precommit);

    let qc_a = produce_decision_certificate(&forward, target, &vs, None)
        .expect("forward set must produce a CEC");
    let qc_b = produce_decision_certificate(&reversed, target, &vs, None)
        .expect("reverse set must produce a CEC");

    assert_eq!(
        qc_a, qc_b,
        "admission order must not change the certificate"
    );
    assert_eq!(
        qc_a.signatures[0].1, qc_b.signatures[0].1,
        "the encoded envelope bytes must be identical across nodes"
    );
    assert!(
        qc_a.verify(&vs) && qc_b.verify(&vs),
        "both builds must verify"
    );
}

/// DoS bound: an oversized signer list is refused BEFORE any signature work.
#[test]
fn qc_split_oversized_signer_list_refused_before_crypto() {
    let (ks, _fks) = key_set(2);
    let vs = uniform_set(&ks);
    let target = Some([0x81u8; 32]);

    // MAX + 1 entries of fake signature bytes. If the producer ran crypto on
    // this list the Falcon verifier would dominate the elapsed time.
    let oversized: Vec<(ValidatorId, Vec<u8>)> = (0..=MAX_COMMIT_CERT_SIGNERS)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            (id, vec![0u8; 8])
        })
        .collect();
    assert_eq!(oversized.len(), MAX_COMMIT_CERT_SIGNERS + 1);

    let started = Instant::now();
    let qc = produce_full_network_certificate_from_signers(
        Height::MAX - 1,
        0,
        VoteKind::Precommit,
        target,
        &vs,
        &oversized,
        None,
    );
    let elapsed = started.elapsed();

    assert!(qc.is_none(), "oversized signer list must be refused");
    assert!(
        elapsed < Duration::from_secs(2),
        "the cap must fire before crypto (took {elapsed:?})"
    );
}

/// An under-quorum aggregate can never produce a full-network QC.
#[test]
fn qc_split_under_quorum_cannot_produce_full_qc() {
    const HEIGHT: Height = 30;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = key_set(4);
    let vs = uniform_set(&ks);
    let target = Some([0x91u8; 32]);

    // 2 of 4 holds 50% — below the 3-of-4 BFT floor.
    let set = vote_set(
        votes_for(
            &ks[..2],
            &fks[..2],
            HEIGHT,
            ROUND,
            VoteKind::Precommit,
            target,
        ),
        &vs,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );
    assert!(!set.quorum_reached(target, &vs));

    assert!(
        produce_full_network_certificate(&set, target, &vs).is_none(),
        "under-quorum votes must never aggregate into a full-network QC"
    );
    assert!(
        produce_decision_certificate(&set, target, &vs, Some(&[0x90u8; 32])).is_none(),
        "the decision producer must refuse an under-quorum set too"
    );

    // Direct signer-list entry point: same refusal with honest signatures.
    let msg = vote_sign_bytes(HEIGHT, ROUND, VoteKind::Precommit, &target);
    let signers: Vec<(ValidatorId, Vec<u8>)> = ks[..2]
        .iter()
        .zip(fks[..2].iter())
        .map(|(k, fk)| (validator_id(k), fk.sign(&msg)))
        .collect();
    assert!(
        produce_full_network_certificate_from_signers(
            HEIGHT,
            ROUND,
            VoteKind::Precommit,
            target,
            &vs,
            &signers,
            None,
        )
        .is_none(),
        "2-of-4 signer power is below pq_full_required_power"
    );
}

/// The explicit PQ-key override path must produce and accept the same
/// certificate shape (rotated-key fixtures rely on it). Also pins that a
/// duplicate signer id is refused (ambiguous aggregate).
#[test]
fn qc_split_explicit_pq_keys_and_duplicate_signer_refusal() {
    const HEIGHT: Height = 40;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = key_set(4);
    let vs = uniform_set(&ks);
    let pq_map = pq_key_map(&ks, &fks);
    let target = Some([0xA1u8; 32]);
    let set = vote_set(
        votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target),
        &vs,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );

    let qc: QuorumCertificate =
        produce_decision_certificate_with_pq_keys(&set, target, &vs, None, Some(&pq_map))
            .expect("explicit-key producer must build the CEC");
    assert!(qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));
    assert!(vs.qc_meets_quorum(&qc));

    // Duplicate signer id: fail closed rather than let an unordered input
    // decide which signature wins.
    let msg = vote_sign_bytes(HEIGHT, ROUND, VoteKind::Precommit, &target);
    let mut signers: Vec<(ValidatorId, Vec<u8>)> = ks
        .iter()
        .zip(fks.iter())
        .map(|(k, fk)| (validator_id(k), fk.sign(&msg)))
        .collect();
    signers.push(signers[0].clone());
    assert!(
        produce_full_network_certificate_from_signers(
            HEIGHT,
            ROUND,
            VoteKind::Precommit,
            target,
            &vs,
            &signers,
            Some(&pq_map),
        )
        .is_none(),
        "a duplicate signer id is an ambiguous aggregate and must be refused"
    );
}
