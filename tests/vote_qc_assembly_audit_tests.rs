//! Vote-counting + QC-assembly audit tests (scope: vote-set/QC regions only).
//!
//! Maps exactly how a set of votes becomes (or fails to become) a QC and pins
//! the fail-closed direction of every gate:
//!   * threshold table floor(2n/3)+1 for N=1..7, uniform and skewed power
//!     (power, never headcount; N=3 needs unanimity, N=4 tolerates one fault);
//!   * dedup: a second vote by the same voter counts once;
//!   * round isolation: votes bucketed strictly per round, stale rounds never
//!     complete the current round's QC, equivocating power counted once;
//!   * equivocation: first vote kept, evidence recorded exactly once per pair;
//!   * QC binding: height/round/kind/target tampering fails verification AND
//!     power accounting; a prevote QC for round r never authorizes a precommit
//!     QC in round r' != r;
//!   * envelope branches (µQC/CEC markers): garbage markers contribute
//!     zero power and never rescue a sub-quorum QC.
//!
//! These tests are characterization + regression: they pass against the current
//! implementation and fail loudly if any gate weakens.

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    consensus_quorum_min, BlockHash, HeightConsensus, QuorumCertificate, ValidatorId,
    ValidatorSet, Vote, VoteKind, VoteSet, PQ_QC_MARKER_ID, PQ_UQC_MARKER_ID,
};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n).map(signing_key).collect()
}

fn ids(ks: &[SigningKey]) -> Vec<ValidatorId> {
    ks.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

fn uniform_set(ks: &[SigningKey], power: u64) -> ValidatorSet {
    ValidatorSet::from_list(ids(ks).into_iter().map(|id| (id, power)).collect())
}

fn block_hash(n: u8) -> BlockHash {
    [n; 32]
}

fn prevote(
    key: &SigningKey,
    height: u64,
    round: u32,
    target: Option<BlockHash>,
) -> Vote {
    Vote::sign(key, height, round, VoteKind::Prevote, target)
}

fn precommit(
    key: &SigningKey,
    height: u64,
    round: u32,
    target: Option<BlockHash>,
) -> Vote {
    Vote::sign(key, height, round, VoteKind::Precommit, target)
}

/// Fill `set` with prevotes for `target` from the first `count` keys.
fn add_prevotes(
    set: &mut VoteSet,
    ks: &[SigningKey],
    count: usize,
    height: u64,
    round: u32,
    target: Option<BlockHash>,
    vs: &ValidatorSet,
) {
    for k in ks.iter().take(count) {
        set.add(prevote(k, height, round, target), vs, height, round, VoteKind::Prevote)
            .expect("honest vote must be admitted");
    }
}

// ---------------------------------------------------------------------------
// 1. Threshold table: floor(2n/3)+1, uniform power.
// ---------------------------------------------------------------------------

#[test]
fn threshold_table_uniform_power_n1_to_n7() {
    // (n, expected quorum power at power 1 each)
    let table: [(usize, u64); 7] =
        [(1, 1), (2, 2), (3, 3), (4, 3), (5, 4), (6, 5), (7, 5)];
    for (n, expected_q) in table {
        assert_eq!(
            consensus_quorum_min(n as u64),
            expected_q,
            "floor(2*{n}/3)+1 must be {expected_q}"
        );
        let ks: Vec<SigningKey> = (0..n).map(|i| SigningKey::from_bytes(&[(i + 1) as u8; 32])).collect();
        let vs = uniform_set(&ks, 1);
        assert_eq!(vs.total_power(), n as u64);
        assert_eq!(vs.quorum_power(), expected_q);

        // q-1 votes: no quorum, no certificate (fail-closed below threshold).
        let mut short = VoteSet::new();
        let short_count = (expected_q as usize).saturating_sub(1);
        add_prevotes(&mut short, &ks, short_count, 1, 0, Some(block_hash(9)), &vs);
        assert_eq!(short.power_for(Some(block_hash(9))), short_count as u64);
        assert!(
            short.quorum_target(&vs).is_none(),
            "n={n}: {} of {expected_q} votes must not reach quorum",
            short_count
        );
        assert!(
            short
                .certificate(Some(block_hash(9)), &vs, &[0u8; 32])
                .is_none(),
            "n={n}: no QC below quorum"
        );

        // q votes: quorum + verifiable certificate.
        let mut full = VoteSet::new();
        add_prevotes(&mut full, &ks, expected_q as usize, 1, 0, Some(block_hash(9)), &vs);
        assert_eq!(
            full.quorum_target(&vs),
            Some(Some(block_hash(9))),
            "n={n}: {expected_q} votes must reach quorum"
        );
        let qc = full
            .certificate(Some(block_hash(9)), &vs, &[0u8; 32])
            .expect("n={n}: QC must assemble at quorum");
        assert!(qc.verify(&vs), "n={n}: assembled QC must verify");
        assert!(vs.qc_meets_quorum(&qc), "n={n}: assembled QC must meet quorum");
        assert_eq!(vs.qc_signed_power(&qc), expected_q);
    }
}

#[test]
fn n3_requires_unanimity() {
    // floor(2*3/3)+1 = 3: two of three equal-power validators hold exactly 2/3,
    // which is NOT strictly more than 2/3, so all three are required.
    let ks = keys(3);
    let vs = uniform_set(&ks, 1_000);
    assert_eq!(vs.total_power(), 3_000);
    assert_eq!(vs.quorum_power(), 2_001);
    let mut set = VoteSet::new();
    add_prevotes(&mut set, &ks, 2, 1, 0, Some(block_hash(1)), &vs);
    assert_eq!(set.power_for(Some(block_hash(1))), 2_000);
    assert!(set.quorum_target(&vs).is_none());
    assert!(set.certificate(Some(block_hash(1)), &vs, &[0u8; 32]).is_none());
    set.add(prevote(&ks[2], 1, 0, Some(block_hash(1))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    assert_eq!(set.quorum_target(&vs), Some(Some(block_hash(1))));
}

#[test]
fn n4_tolerates_one_fault() {
    // floor(2*4/3)+1 = 3: three of four suffice, two do not.
    let ks = keys(4);
    let vs = uniform_set(&ks, 1_000);
    assert_eq!(vs.quorum_power(), 2_667);
    let mut set = VoteSet::new();
    add_prevotes(&mut set, &ks, 2, 1, 0, Some(block_hash(1)), &vs);
    assert!(set.quorum_target(&vs).is_none(), "two of four must not suffice");
    set.add(prevote(&ks[2], 1, 0, Some(block_hash(1))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    assert_eq!(set.quorum_target(&vs), Some(Some(block_hash(1))));
}

// ---------------------------------------------------------------------------
// 2. Skewed power: quorum is power-weighted, never a headcount.
// ---------------------------------------------------------------------------

#[test]
fn skewed_power_quorum_is_power_not_headcount() {
    // Powers [5,1,1]: total 7, quorum floor(14/3)+1 = 5.
    let a = signing_key(11);
    let b = signing_key(12);
    let c = signing_key(13);
    let vs = ValidatorSet::from_list(vec![
        (a.verifying_key().to_bytes(), 5),
        (b.verifying_key().to_bytes(), 1),
        (c.verifying_key().to_bytes(), 1),
    ]);
    assert_eq!(vs.total_power(), 7);
    assert_eq!(vs.quorum_power(), 5);

    // The heavy validator alone reaches quorum (one signer is enough).
    let mut heavy = VoteSet::new();
    heavy
        .add(prevote(&a, 1, 0, Some(block_hash(7))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    assert_eq!(heavy.quorum_target(&vs), Some(Some(block_hash(7))));
    let qc = heavy
        .certificate(Some(block_hash(7)), &vs, &[0u8; 32])
        .expect("heavy voter alone must assemble a QC");
    assert!(qc.verify(&vs));
    assert!(vs.qc_meets_quorum(&qc));
    assert_eq!(vs.qc_signed_power(&qc), 5);

    // The two light validators together (two signers, power 2) do not.
    let mut lights = VoteSet::new();
    lights
        .add(prevote(&b, 1, 0, Some(block_hash(7))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    lights
        .add(prevote(&c, 1, 0, Some(block_hash(7))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    assert_eq!(lights.power_for(Some(block_hash(7))), 2);
    assert!(lights.quorum_target(&vs).is_none());
    assert!(lights.certificate(Some(block_hash(7)), &vs, &[0u8; 32]).is_none());
}

#[test]
fn headcount_majority_without_power_is_refused() {
    // Powers [3,1,1,1]: total 6, quorum floor(12/3)+1 = 5. Three light signers
    // are a headcount majority but carry power 3 < 5: fail-closed.
    let ks = keys(4);
    let id = ids(&ks);
    let vs = ValidatorSet::from_list(vec![(id[0], 3), (id[1], 1), (id[2], 1), (id[3], 1)]);
    assert_eq!(vs.quorum_power(), 5);

    let mut three_lights = VoteSet::new();
    for k in &ks[1..] {
        three_lights
            .add(prevote(k, 1, 0, Some(block_hash(3))), &vs, 1, 0, VoteKind::Prevote)
            .unwrap();
    }
    assert!(three_lights.quorum_target(&vs).is_none());
    // Hand-built QC with the same three signatures verifies against nothing:
    // both gates must refuse together.
    let hand_qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(block_hash(3)),
        signatures: three_lights_signatures(&ks[1..], 1, 0, Some(block_hash(3))),
    };
    assert!(!hand_qc.verify(&vs), "3 light signers must not verify at power 3 of 5");
    assert!(!vs.qc_meets_quorum(&hand_qc));
    assert_eq!(vs.qc_signed_power(&hand_qc), 3);

    // Heavy + two lights = power 5: same signer count class, different power.
    let mut enough = VoteSet::new();
    for k in [&ks[0], &ks[1], &ks[2]] {
        enough
            .add(prevote(k, 1, 0, Some(block_hash(3))), &vs, 1, 0, VoteKind::Prevote)
            .unwrap();
    }
    assert_eq!(enough.quorum_target(&vs), Some(Some(block_hash(3))));
    let qc = enough.certificate(Some(block_hash(3)), &vs, &[0u8; 32]).unwrap();
    assert!(qc.verify(&vs));
    assert!(vs.qc_meets_quorum(&qc));
}

fn three_lights_signatures(
    ks: &[SigningKey],
    height: u64,
    round: u32,
    target: Option<BlockHash>,
) -> Vec<(ValidatorId, Vec<u8>)> {
    ks.iter()
        .map(|k| {
            let v = prevote(k, height, round, target);
            (v.voter, v.ed25519_signature().to_vec())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 3. Dedup: a second vote by the same voter counts once.
// ---------------------------------------------------------------------------

#[test]
fn double_vote_for_same_target_counts_once() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut set = VoteSet::new();
    let v1 = prevote(&ks[0], 1, 0, Some(block_hash(1)));
    let v2 = prevote(&ks[0], 1, 0, Some(block_hash(1)));
    set.add(v1, &vs, 1, 0, VoteKind::Prevote).unwrap();
    set.add(v2, &vs, 1, 0, VoteKind::Prevote).unwrap();
    assert_eq!(set.len(), 1, "same voter admitted once");
    assert_eq!(set.power_for(Some(block_hash(1))), 1, "power counted once");
    assert!(set.equivocations().is_empty(), "same target is not equivocation");
    // One voter double-voting must not fabricate a quorum of 3.
    assert!(set.quorum_target(&vs).is_none());
    assert!(set.certificate(Some(block_hash(1)), &vs, &[0u8; 32]).is_none());
}

#[test]
fn double_vote_counts_once_via_batch() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut set = VoteSet::new();
    let votes = vec![
        prevote(&ks[0], 1, 0, Some(block_hash(1))),
        prevote(&ks[0], 1, 0, Some(block_hash(1))),
    ];
    let results = set.add_batch(votes, &vs, 1, 0, VoteKind::Prevote);
    assert!(results.iter().all(|r| r.is_ok()));
    assert_eq!(set.len(), 1);
    assert_eq!(set.power_for(Some(block_hash(1))), 1);
    assert!(set.quorum_target(&vs).is_none());
}

// ---------------------------------------------------------------------------
// 4. Round isolation: strict per-round buckets, no leakage, same-round finality.
// ---------------------------------------------------------------------------

#[test]
fn stale_round_votes_never_complete_current_round_qc() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut hc = HeightConsensus::new(1, vs.clone());

    // Full quorum for block X in round 0.
    for k in &ks[..3] {
        hc.add_prevote(prevote(k, 1, 0, Some(block_hash(1)))).unwrap();
    }
    assert_eq!(
        hc.prevote_set(0).unwrap().quorum_target(&vs),
        Some(Some(block_hash(1)))
    );
    // Round 1 is a different bucket: empty, no quorum.
    assert!(hc.prevote_set(1).is_none());

    // Move to round 1 and add a single round-1 prevote: still no round-1 quorum.
    hc.round = 1;
    hc.add_prevote(prevote(&ks[0], 1, 1, Some(block_hash(1)))).unwrap();
    assert_eq!(hc.prevote_set(1).unwrap().power_for(Some(block_hash(1))), 1);
    assert!(hc.prevote_set(1).unwrap().quorum_target(&vs).is_none());
    // The round-0 quorum is intact in its own bucket and did not leak.
    assert_eq!(
        hc.prevote_set(0).unwrap().quorum_target(&vs),
        Some(Some(block_hash(1)))
    );
}

#[test]
fn late_vote_completes_its_own_round_never_another() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut hc = HeightConsensus::new(1, vs.clone());
    hc.round = 50; // far ahead; late round-0 votes must still land in bucket 0.

    hc.add_prevote(prevote(&ks[0], 1, 0, Some(block_hash(1)))).unwrap();
    hc.add_prevote(prevote(&ks[1], 1, 0, Some(block_hash(1)))).unwrap();
    assert!(hc.prevote_set(0).unwrap().quorum_target(&vs).is_none());
    assert!(hc.prevote_set(50).is_none());

    // The quorum-completing late vote completes round 0 only.
    hc.add_prevote(prevote(&ks[2], 1, 0, Some(block_hash(1)))).unwrap();
    assert_eq!(
        hc.prevote_set(0).unwrap().quorum_target(&vs),
        Some(Some(block_hash(1)))
    );
    assert!(hc.prevote_set(50).is_none(), "round 50 must stay empty");
}

#[test]
fn wrong_height_and_wrong_kind_votes_are_refused() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut hc = HeightConsensus::new(1, vs.clone());

    // Height binding: a vote for another height is rejected, bucket untouched.
    let err = hc
        .add_prevote(prevote(&ks[0], 2, 0, Some(block_hash(1))))
        .unwrap_err();
    assert!(err.contains("out of scope"), "unexpected error: {err}");
    assert!(hc.prevote_set(0).is_none());

    // Kind binding: a precommit is not a prevote.
    let err = hc
        .add_prevote(precommit(&ks[0], 1, 0, Some(block_hash(1))))
        .unwrap_err();
    assert!(err.contains("out of scope"), "unexpected error: {err}");

    // Far-future rounds are refused outright (DoS bound), near rounds accepted.
    let err = hc
        .add_prevote(prevote(&ks[0], 1, 10_000, Some(block_hash(1))))
        .unwrap_err();
    assert!(err.contains("too far ahead"), "unexpected error: {err}");

    // Refused votes leave no bucket behind: no empty VoteSet may materialize
    // to consume the retained-round cap or the scan window.
    assert!(hc.prevote_set(0).is_none());
    assert!(hc.precommit_set(0).is_none());

    // Same fail-closed admission on the precommit path.
    let err = hc
        .add_precommit(precommit(&ks[0], 2, 0, Some(block_hash(1))))
        .unwrap_err();
    assert!(err.contains("out of scope"), "unexpected error: {err}");
    let err = hc
        .add_precommit(prevote(&ks[0], 1, 0, Some(block_hash(1))))
        .unwrap_err();
    assert!(err.contains("out of scope"), "unexpected error: {err}");
    assert!(hc.precommit_set(0).is_none());
    assert!(hc.prevote_set(0).is_none());
}

#[test]
fn precommit_qc_requires_same_round_prevote_qc() {
    // A prevote QC for round 0 must NOT authorize precommits in round 1:
    // finality needs both quorums in the SAME round.
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut hc = HeightConsensus::new(1, vs.clone());

    for k in &ks[..3] {
        hc.add_prevote(prevote(k, 1, 0, Some(block_hash(1)))).unwrap();
    }
    hc.round = 1;
    for k in &ks[..3] {
        hc.add_precommit(precommit(k, 1, 1, Some(block_hash(1)))).unwrap();
    }
    assert!(
        hc.try_precommit_quorum().is_none(),
        "round-1 precommits without a round-1 prevote QC must not decide"
    );
    assert!(hc.decided.is_none());

    // Completing the round-1 prevote QC unlocks the round-1 decision.
    for k in &ks[..3] {
        hc.add_prevote(prevote(k, 1, 1, Some(block_hash(1)))).unwrap();
    }
    assert_eq!(hc.try_precommit_quorum(), Some(block_hash(1)));
    assert_eq!(hc.decided, Some(block_hash(1)));
    assert!(hc.precommit_qc.as_ref().unwrap().verify(&hc.validators));
}

// ---------------------------------------------------------------------------
// 5. Equivocation: first vote kept, power counted once, evidence exactly once.
// ---------------------------------------------------------------------------

#[test]
fn equivocation_first_vote_kept_second_excluded() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut set = VoteSet::new();

    let va = prevote(&ks[0], 1, 0, Some(block_hash(1)));
    let vb = prevote(&ks[0], 1, 0, Some(block_hash(2)));
    set.add(va, &vs, 1, 0, VoteKind::Prevote).unwrap();
    set.add(vb, &vs, 1, 0, VoteKind::Prevote).unwrap();

    assert_eq!(set.len(), 1, "equivocator occupies one seat");
    assert_eq!(set.power_for(Some(block_hash(1))), 1, "first vote keeps its power");
    assert_eq!(set.power_for(Some(block_hash(2))), 0, "second vote counts nothing");
    assert_eq!(set.equivocations().len(), 1, "double-vote recorded once");

    // Two honest votes for B plus the equivocator's excluded second vote:
    // still no quorum for B (fail-closed: excluded, not counted).
    set.add(prevote(&ks[1], 1, 0, Some(block_hash(2))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    set.add(prevote(&ks[2], 1, 0, Some(block_hash(2))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    assert_eq!(set.power_for(Some(block_hash(2))), 2);
    assert!(set.quorum_target(&vs).is_none());
    assert!(set.certificate(Some(block_hash(2)), &vs, &[0u8; 32]).is_none());
}

#[test]
fn equivocation_evidence_does_not_compound_on_rebroadcast() {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut set = VoteSet::new();
    let va = || prevote(&ks[0], 1, 0, Some(block_hash(1)));
    let vb = || prevote(&ks[0], 1, 0, Some(block_hash(2)));
    set.add(va(), &vs, 1, 0, VoteKind::Prevote).unwrap();
    for _ in 0..5 {
        set.add(vb(), &vs, 1, 0, VoteKind::Prevote).unwrap();
    }
    assert_eq!(
        set.equivocations().len(),
        1,
        "rebroadcasting the same pair must not compound evidence"
    );
    assert_eq!(set.power_for(Some(block_hash(1))), 1);
    assert_eq!(set.power_for(Some(block_hash(2))), 0);
}

#[test]
fn equivocator_first_vote_still_counts_toward_honest_quorum() {
    // v0 prevotes A then equivocates to B; v1+v2 honestly prevote A.
    // v0's FIRST vote (A) still counts: power 3 reaches quorum.
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut set = VoteSet::new();
    set.add(prevote(&ks[0], 1, 0, Some(block_hash(1))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    set.add(prevote(&ks[0], 1, 0, Some(block_hash(2))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    set.add(prevote(&ks[1], 1, 0, Some(block_hash(1))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    set.add(prevote(&ks[2], 1, 0, Some(block_hash(1))), &vs, 1, 0, VoteKind::Prevote)
        .unwrap();
    assert_eq!(set.power_for(Some(block_hash(1))), 3);
    assert_eq!(set.quorum_target(&vs), Some(Some(block_hash(1))));
    let qc = set.certificate(Some(block_hash(1)), &vs, &[0u8; 32]).unwrap();
    assert!(qc.verify(&vs));
}

// ---------------------------------------------------------------------------
// 6. QC binding: (height, round, kind, target) tampering fails closed.
// ---------------------------------------------------------------------------

fn assembled_prevote_qc() -> (ValidatorSet, Vec<SigningKey>, QuorumCertificate) {
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let mut set = VoteSet::new();
    add_prevotes(&mut set, &ks, 3, 1, 0, Some(block_hash(1)), &vs);
    let qc = set.certificate(Some(block_hash(1)), &vs, &[0u8; 32]).unwrap();
    assert!(qc.verify(&vs));
    (vs, ks, qc)
}

#[test]
fn qc_round_binding_tampered_round_fails_closed() {
    let (vs, _, mut qc) = assembled_prevote_qc();
    assert_eq!((qc.height, qc.round), (1, 0));
    qc.round = 1; // replay the round-0 QC as if it were for round 1
    assert!(!qc.verify(&vs), "round-tampered QC must not verify");
    assert!(!vs.qc_meets_quorum(&qc));
    assert_eq!(vs.qc_signed_power(&qc), 0);
}

#[test]
fn qc_height_binding_tampered_height_fails_closed() {
    let (vs, _, mut qc) = assembled_prevote_qc();
    qc.height = 2; // replay the height-1 QC at height 2
    assert!(!qc.verify(&vs), "height-tampered QC must not verify");
    assert!(!vs.qc_meets_quorum(&qc));
    assert_eq!(vs.qc_signed_power(&qc), 0);
}

#[test]
fn qc_target_and_kind_binding_tampering_fails_closed() {
    let (vs, _, qc) = assembled_prevote_qc();
    let mut bad_target = qc.clone();
    bad_target.block_hash = Some(block_hash(2));
    assert!(!bad_target.verify(&vs));
    assert!(!vs.qc_meets_quorum(&bad_target));

    let mut bad_kind = qc.clone();
    bad_kind.kind = VoteKind::Precommit; // prevote signatures are not precommits
    assert!(!bad_kind.verify(&vs));
    assert!(!vs.qc_meets_quorum(&bad_kind));

    let mut bad_nil = qc.clone();
    bad_nil.block_hash = None;
    assert!(!bad_nil.verify(&vs));
    assert!(!vs.qc_meets_quorum(&bad_nil));
}

#[test]
fn sub_quorum_qc_fails_both_gates_together() {
    // A hand-assembled 2-of-4 QC must fail verification AND power accounting
    // together (fail-closed direction, no gate disagrees with the other).
    let ks = keys(4);
    let vs = uniform_set(&ks, 1);
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(block_hash(1)),
        signatures: three_lights_signatures(&ks[..2], 1, 0, Some(block_hash(1))),
    };
    assert_eq!(vs.qc_signed_power(&qc), 2);
    assert!(!qc.verify(&vs));
    assert!(!vs.qc_meets_quorum(&qc));
}

// ---------------------------------------------------------------------------
// 7. Envelope branches: markers never mint power, garbage never verifies.
// ---------------------------------------------------------------------------

#[test]
fn classical_qc_carries_no_envelopes_by_default() {
    let (_, _, qc) = assembled_prevote_qc();
    for (voter, _) in &qc.signatures {
        assert_ne!(*voter, PQ_UQC_MARKER_ID, "no µQC envelope expected");
        assert_ne!(*voter, PQ_QC_MARKER_ID, "no CEC envelope expected");
    }
    assert_eq!(qc.signatures.len(), 3);
}

#[test]
fn garbage_envelope_markers_contribute_zero_power() {
    let (vs, _, qc) = assembled_prevote_qc();
    let honest_power = vs.qc_signed_power(&qc);
    assert_eq!(honest_power, 3);

    // Splice garbage behind every marker id: attribution must stay exactly
    // the verified classical power, and verification must be unaffected.
    let mut forged = qc.clone();
    forged.signatures.push((PQ_UQC_MARKER_ID, vec![0u8; 32]));
    forged.signatures.push((PQ_QC_MARKER_ID, vec![0u8; 64]));
    assert!(forged.verify(&vs), "garbage markers must not break the classical quorum");
    assert_eq!(
        vs.qc_signed_power(&forged),
        honest_power,
        "unverifiable markers must contribute zero power"
    );

    // A QC with ONLY garbage markers verifies against nothing.
    let only_garbage = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(block_hash(1)),
        signatures: vec![
            (PQ_UQC_MARKER_ID, vec![0u8; 32]),
            (PQ_QC_MARKER_ID, vec![0u8; 64]),
        ],
    };
    assert!(!only_garbage.verify(&vs));
    assert!(!vs.qc_meets_quorum(&only_garbage));
    assert_eq!(vs.qc_signed_power(&only_garbage), 0);
    assert!(only_garbage.signers_set(&vs).is_empty());
}

// ---------------------------------------------------------------------------
// 8. Empty / zero-power sets fail closed.
// ---------------------------------------------------------------------------

#[test]
fn empty_validator_set_never_forms_a_qc() {
    let empty = ValidatorSet::new();
    assert_eq!(empty.quorum_power(), u64::MAX);
    let outsider = signing_key(99);
    let mut set = VoteSet::new();
    assert!(
        set.add(
            prevote(&outsider, 1, 0, Some(block_hash(1))),
            &empty,
            1,
            0,
            VoteKind::Prevote
        )
        .is_err(),
        "non-member vote must be refused"
    );
    assert!(set.quorum_target(&empty).is_none());
    assert!(set.certificate(Some(block_hash(1)), &empty, &[0u8; 32]).is_none());
}
