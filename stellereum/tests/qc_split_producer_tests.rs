//! QC_SPLIT producer suites: the full-network decision certificate (C1 split,
//! FIXES §1.7).
//!
//! Before this producer existed, activating the split made the verifier
//! refuse every locally produced µQC while nothing emitted the epoch/CEC
//! certificate finality requires — i.e. activation would halt finality. These
//! tests pin the producer↔verifier symmetry, the height boundary, determinism
//! and the DoS bound.
//!
//! The gate constant itself stays `u64::MAX` (frozen off); every ACTIVE-branch
//! test drives it through the thread-scoped
//! [`set_qc_split_activation_override`] knob, exactly like the project's other
//! gates (release builds have no override at all).

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use falcon_votes::{falcon_set, fvote};
use stellereum::consensus::{
    decode_pq_epoch_envelope, produce_decision_certificate,
    produce_decision_certificate_with_pq_keys, produce_full_network_certificate,
    produce_full_network_certificate_from_signers, qc_split_active_at, qc_split_required,
    set_qc_split_activation_override, vote_sign_bytes, BlockHash, CommitteeSchedule, Height,
    QuorumCertificate, Round, ValidatorId, ValidatorSet, Vote, VoteKind, VoteSet,
    MAX_COMMIT_CERT_SIGNERS, PQ_QC_MARKER_ID, PQ_UQC_MARKER_ID, QC_SPLIT_BY_SIZE_THRESHOLD,
    QC_SPLIT_ACTIVATION_HEIGHT,
};
use stellereum::consensus::{micro_committee_size, pq_micro_required_power};
use stellereum::post_quantum::{FalconKeypair, PqScheme};

/// Thread-scoped activation override guard: clears the override on drop so a
/// panicking assertion cannot leak a reachable gate into another test on the
/// same thread.
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
        .map(|(k, fk)| fvote(k, fk, height, round, kind, target))
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

fn pq_key_map(
    ks: &[SigningKey],
    fks: &[FalconKeypair],
) -> HashMap<ValidatorId, (PqScheme, Vec<u8>)> {
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

/// The MAXIMAL µQC the old path could ever assemble: every one of the
/// `min(N, 128)` committee seats signs, so it carries the largest signer power
/// a µQC can possibly have.
///
/// At/above `QC_SPLIT_BY_SIZE_THRESHOLD` even this certificate cannot reach
/// the network-anchored two-thirds (review F1), which is why it is the
/// strongest possible fixture for proving the verifier REFUSES a µQC there:
/// the refusal cannot be dismissed as "just too few signers".
fn maximal_micro_qc(
    vs: &ValidatorSet,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    height: Height,
    round: Round,
    target: Option<BlockHash>,
    parent: [u8; 32],
) -> QuorumCertificate {
    use stellereum::consensus::{
        derive_sortition_committee, encode_pq_micro_envelope, PqMicroCertificate,
    };

    let committee_size = micro_committee_size(vs.len());
    let committee = derive_sortition_committee(vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), committee_size as usize);
    let msg = vote_sign_bytes(height, round, VoteKind::Precommit, &target);
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    let mut signatures = Vec::with_capacity(committee.len());
    for (i, id) in committee.iter().enumerate() {
        let pos = ks
            .iter()
            .position(|k| validator_id(k) == *id)
            .expect("every committee member must have a fixture key");
        signatures.push(fks[pos].sign(&msg));
        bitmask[i / 8] |= 1 << (i % 8);
    }
    let uqc = PqMicroCertificate::new(
        PqScheme::Falcon512,
        height,
        round,
        committee_size,
        bitmask,
        signatures,
        parent,
    );
    QuorumCertificate {
        height,
        round,
        kind: VoteKind::Precommit,
        block_hash: target,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
    }
}

/// Producer → verifier round trip at the activation height.
///
/// The produced certificate must be the epoch/CEC envelope under
/// `PQ_QC_MARKER_ID` (never a µQC marker), carry the FULL signer set, verify
/// through `verify_with_pq_keys`, and count toward quorum under the network
/// set.
#[test]
fn producer_verifier_round_trip_at_activation_height() {
    const HEIGHT: Height = 10;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = falcon_set(4);
    let vs = uniform_set(&ks);
    let pq_map = pq_key_map(&ks, &fks);
    let target = Some([0x51u8; 32]);
    let votes = votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target);
    let set = vote_set(votes, &vs, HEIGHT, ROUND, VoteKind::Precommit);
    assert!(set.quorum_reached(target, &vs), "4-of-4 must hold quorum");

    let qc = produce_decision_certificate(&set, target, &vs, Some(&[0x50u8; 32]))
        .expect("a full-quorum vote set must produce a decision certificate");

    assert_eq!(
        qc.signatures.len(),
        1,
        "the decision QC carries exactly one marker entry"
    );
    assert_eq!(
        qc.signatures[0].0, PQ_QC_MARKER_ID,
        "post-activation decision QC must be the epoch/CEC envelope"
    );
    assert!(
        qc.pq_micro_certificate().is_none(),
        "the CEC is not a µQC (no sortition subset envelope)"
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

    // Verification symmetry, both through the explicit key map and the
    // committed registry.
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
fn split_boundary_switches_producer_kind_and_refuses_micro_qc() {
    const ACTIVATION: Height = 50;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(ACTIVATION);

    let (ks, fks) = falcon_set(4);
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
fn producer_is_deterministic_across_vote_admission_order() {
    const HEIGHT: Height = 20;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = falcon_set(4);
    let vs = uniform_set(&ks);
    let target = Some([0x71u8; 32]);
    // Sign ONCE: determinism is about the same vote bytes, not about Falcon's
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
fn oversized_signer_list_is_refused_before_crypto() {
    let (ks, _fks) = falcon_set(2);
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

/// An under-quorum aggregate can never produce a full-network QC — not even
/// with the split active and every available Falcon signature collected.
#[test]
fn under_quorum_vote_set_cannot_produce_a_full_qc() {
    const HEIGHT: Height = 30;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = falcon_set(4);
    let vs = uniform_set(&ks);
    let target = Some([0x91u8; 32]);

    // 2 of 4 holds 50% — below the 3-of-4 BFT floor.
    let votes = votes_for(
        &ks[..2],
        &fks[..2],
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
        target,
    );
    let set = vote_set(votes, &vs, HEIGHT, ROUND, VoteKind::Precommit);
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
    let signers: Vec<(ValidatorId, Vec<u8>)> = ks[..2]
        .iter()
        .zip(fks[..2].iter())
        .map(|(k, fk)| {
            let msg = vote_sign_bytes(HEIGHT, ROUND, VoteKind::Precommit, &target);
            (validator_id(k), fk.sign(&msg))
        })
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
/// certificate shape (rotated-key fixtures rely on it).
#[test]
fn producer_and_verifier_symmetry_with_explicit_pq_keys() {
    const HEIGHT: Height = 40;
    const ROUND: Round = 0;
    let _gate = ActivationOverride::at(HEIGHT);

    let (ks, fks) = falcon_set(4);
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
}

// ===========================================================================
// REVIEW F1 — the size leg: full-network QC by validator COUNT
// ===========================================================================
//
// The three suites below close the "finality cliff": a set at/above
// `QC_SPLIT_BY_SIZE_THRESHOLD` (192) must produce and verify the CEC with the
// governance gate still frozen off, a set below it must keep the legacy µQC
// byte-for-byte, and the exact boundary (191 vs 192) must be the same verdict
// on the producer and on every verifier. No `ActivationOverride` is installed
// in any of them: `qc_split_active_at(HEIGHT)` is asserted FALSE, so the size
// leg is provably the only reason the CEC is selected.

/// Below the threshold AND below the gate: the µQC must be BYTE-identical to
/// the legacy assembler (`VoteSet::certificate_with_parent`), which is what
/// the existing pre-activation pins already verify.
#[test]
fn four_validators_keep_a_byte_identical_micro_qc() {
    const HEIGHT: Height = 3;
    const ROUND: Round = 0;

    // Gate off, count below threshold: the legacy branch is the rule.
    assert!(!qc_split_active_at(HEIGHT));
    assert!(!qc_split_required(HEIGHT, 4));

    let (ks, fks) = falcon_set(4);
    let vs = uniform_set(&ks);
    let target = Some([0x31u8; 32]);
    let parent = [0x30u8; 32];
    let set = vote_set(
        votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target),
        &vs,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );

    let qc = produce_decision_certificate(&set, target, &vs, Some(&parent))
        .expect("4-of-4 below the threshold must produce a decision certificate");
    let legacy = set
        .certificate_with_parent(target, &vs, Some(&parent))
        .expect("the legacy assembler must build the same certificate");

    assert_eq!(
        qc, legacy,
        "below the threshold the producer must be the legacy µQC byte-for-byte"
    );
    assert!(
        qc.pq_micro_certificate().is_some(),
        "the small-set decision certificate must still be the µQC"
    );
    assert_eq!(
        qc.signatures
            .iter()
            .filter(|(voter, _)| *voter == PQ_UQC_MARKER_ID)
            .count(),
        1,
        "exactly one µQC marker"
    );
    assert!(
        qc.signatures.iter().all(|(voter, _)| *voter != PQ_QC_MARKER_ID),
        "no CEC marker below the threshold"
    );
    assert!(qc.verify(&vs), "the µQC must verify");
    assert!(vs.qc_meets_quorum(&qc), "the µQC must carry quorum power");
    assert_eq!(qc.signers_set(&vs).len(), 4);
}

/// The EXACT boundary: 191 is the last size a 128-seat committee can carry
/// (network 2/3 = 128 = the whole committee), 192 the first it cannot
/// (network 2/3 = 129 > 128). Producer and verifiers must agree on both sides.
#[test]
fn producer_and_verifier_agree_at_the_exact_threshold_boundary() {
    const HEIGHT: Height = 5;
    const ROUND: Round = 0;
    const BELOW: usize = QC_SPLIT_BY_SIZE_THRESHOLD - 1; // 191
    const AT: usize = QC_SPLIT_BY_SIZE_THRESHOLD; // 192

    // The cliff this test straddles, in the protocol's own numbers.
    assert_eq!(BELOW, 191);
    assert_eq!(AT, 192);
    assert_eq!(micro_committee_size(BELOW), 128);
    assert_eq!(micro_committee_size(AT), 128);
    assert!(
        pq_micro_required_power(128, BELOW as u64) <= 128,
        "191: a unanimous 128-seat committee can still carry the network"
    );
    assert!(
        pq_micro_required_power(128, AT as u64) > 128,
        "192: the network anchor is out of the committee's reach"
    );
    assert!(!qc_split_active_at(HEIGHT), "governance gate stays off");
    assert!(!qc_split_required(HEIGHT, BELOW));
    assert!(qc_split_required(HEIGHT, AT));

    // One key set: id i <-> seed i, so the 191 set is a subset of the 192 set
    // (the global PQ registry is shared and idempotent for identical keys).
    let (ks, fks) = falcon_set(AT);
    let target = Some([0x41u8; 32]);
    let parent = [0x40u8; 32];

    // ---- 191: µQC produced and verified; a CEC is NOT required. ----
    let vs_below =
        ValidatorSet::from_list(ks[..BELOW].iter().map(|k| (validator_id(k), 1)).collect());
    assert_eq!(vs_below.len(), BELOW);
    let set_below = vote_set(
        votes_for(
            &ks[..BELOW],
            &fks[..BELOW],
            HEIGHT,
            ROUND,
            VoteKind::Precommit,
            target,
        ),
        &vs_below,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );
    assert!(set_below.quorum_reached(target, &vs_below));
    let qc_below = produce_decision_certificate(&set_below, target, &vs_below, Some(&parent))
        .expect("191 validators: the µQC producer must still build a certificate");
    assert!(
        qc_below.pq_micro_certificate().is_some(),
        "191 (< threshold): the producer must emit the µQC"
    );
    assert!(
        qc_below.verify(&vs_below),
        "191: the verifier must accept the µQC the producer emitted"
    );
    assert!(
        qc_below.signatures.iter().all(|(voter, _)| *voter != PQ_QC_MARKER_ID),
        "191: no CEC while below the threshold"
    );

    // ---- 192: CEC produced and verified; the same-shape µQC REFUSED. ----
    let vs_at = uniform_set(&ks);
    assert_eq!(vs_at.len(), AT);
    let set_at = vote_set(
        votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target),
        &vs_at,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );
    assert!(set_at.quorum_reached(target, &vs_at));
    let qc_at = produce_decision_certificate(&set_at, target, &vs_at, Some(&parent))
        .expect("192 validators: the CEC producer must build a certificate");
    assert_eq!(
        qc_at.signatures[0].0, PQ_QC_MARKER_ID,
        "192 (= threshold): the producer must emit the full-network CEC"
    );
    assert!(
        qc_at.pq_micro_certificate().is_none(),
        "192: the decision certificate is not a µQC"
    );
    assert!(
        qc_at.verify(&vs_at),
        "192: the verifier must accept the CEC the producer emitted"
    );
    assert!(
        vs_at.qc_meets_quorum(&qc_at),
        "192: the CEC must carry the network's 2/3"
    );

    // The LEGACY assembler itself refuses to compile a µQC here — even with
    // every validator voting, a 128-seat committee cannot reach the network
    // anchor, so the old producer emits no µQC marker at all. That IS the
    // finality cliff F1 describes.
    let legacy_at = set_at
        .certificate_with_parent(target, &vs_at, Some(&parent))
        .expect("the legacy assembler still builds certificate bytes");
    assert!(
        legacy_at.pq_micro_certificate().is_none(),
        "192: the legacy assembler cannot compile a µQC that would carry quorum"
    );

    // The MAXIMAL µQC (every one of the 128 seats signs) is the strongest
    // certificate the old path could ever produce. It is structurally valid
    // and still REFUSED by every verifier entry point.
    let maximal = maximal_micro_qc(&vs_at, &ks, &fks, HEIGHT, ROUND, target, parent);
    assert!(
        maximal.pq_micro_certificate().is_some(),
        "fixture must really be a µQC"
    );
    assert!(
        !maximal.verify(&vs_at),
        "192: a µQC must be REFUSED at the threshold"
    );
    assert!(!maximal.verify_with_schedule(&vs_at, CommitteeSchedule::ParentHash));
    assert!(!maximal.verify_unified(&vs_at));
    assert!(
        maximal.signers_set(&vs_at).is_empty(),
        "192: a refused µQC attributes NOBODY (the gate, not just the quorum, \
         refuses it — attribution would otherwise name all 128 signers)"
    );
    assert!(
        !vs_at.qc_meets_quorum(&maximal),
        "192: power accounting must refuse the µQC too"
    );
    let (verified, power) = maximal.verify_and_signed_power(&vs_at);
    assert!(
        !verified && power == 0,
        "192: the fused verify+attribute path must agree (got {verified}, {power})"
    );
    assert_eq!(
        vs_at.qc_signed_power(&maximal),
        0,
        "192: qc_signed_power must be zero for a refused µQC"
    );
}

/// The documented decentralization target: 250 validators
/// (`staking::MAX_ACTIVE_VALIDATORS`) must finalize out of the box — full-set
/// CEC, no activation height, no µQC.
#[test]
fn two_hundred_fifty_validators_produce_and_verify_cec_automatically() {
    const HEIGHT: Height = 11;
    const ROUND: Round = 0;
    const N: usize = 250;

    assert_eq!(N, stellereum::staking::MAX_ACTIVE_VALIDATORS);
    // NO activation override anywhere in this test: the gate is off, so the
    // CEC can only be selected through the SIZE leg.
    assert!(!qc_split_active_at(HEIGHT));
    assert!(qc_split_required(HEIGHT, N));
    assert_eq!(micro_committee_size(N), 128);
    assert!(
        pq_micro_required_power(128, N as u64) > 128,
        "250: a µQC is arithmetically unable to reach the network anchor"
    );

    let (ks, fks) = falcon_set(N);
    let vs = uniform_set(&ks);
    let target = Some([0x51u8; 32]);
    let parent = [0x50u8; 32];
    let set = vote_set(
        votes_for(&ks, &fks, HEIGHT, ROUND, VoteKind::Precommit, target),
        &vs,
        HEIGHT,
        ROUND,
        VoteKind::Precommit,
    );

    let qc = produce_decision_certificate(&set, target, &vs, Some(&parent))
        .expect("250-of-250 must produce the full-network decision certificate");
    assert_eq!(
        qc.signatures.len(),
        1,
        "the decision QC carries exactly one marker entry"
    );
    assert_eq!(
        qc.signatures[0].0, PQ_QC_MARKER_ID,
        "250 validators: the producer must emit the CEC automatically"
    );
    let cert = decode_pq_epoch_envelope(&qc.signatures[0].1)
        .expect("the marker payload must decode as an epoch envelope");
    assert_eq!(cert.committee_size as usize, N, "CEC covers the FULL set");
    assert_eq!(cert.signed_count(), N, "every validator signs the CEC");

    assert!(qc.verify(&vs), "the 250-validator CEC must verify");
    assert!(qc.verify_unified(&vs));
    assert!(vs.qc_meets_quorum(&qc));
    assert!(vs.qc_meets_quorum_with_beacon(&qc, None));
    assert_eq!(
        qc.signers_set(&vs).len(),
        N,
        "attribution must name the whole set"
    );
    assert!(qc.binds_to_parent(&parent), "chain binding still holds");

    // The µQC path is dead at this size: a maximal 128-of-250 µQC is
    // structurally valid yet refused, attributing nobody.
    let legacy = set
        .certificate_with_parent(target, &vs, Some(&parent))
        .expect("the legacy assembler still builds certificate bytes");
    assert!(
        legacy.pq_micro_certificate().is_none(),
        "250: the legacy assembler cannot compile a quorum-bearing µQC"
    );
    let maximal = maximal_micro_qc(&vs, &ks, &fks, HEIGHT, ROUND, target, parent);
    assert!(maximal.pq_micro_certificate().is_some());
    assert!(!maximal.verify(&vs), "a 250-set µQC must be REFUSED");
    assert!(maximal.signers_set(&vs).is_empty());
    assert!(!vs.qc_meets_quorum(&maximal));
    assert_eq!(
        QC_SPLIT_ACTIVATION_HEIGHT,
        u64::MAX,
        "gate remains frozen off"
    );
}
