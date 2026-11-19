//! # CN-VRF v3 activation wiring (review F2 + F4)
//!
//! The frozen gate stays `CNVRF_V3_ACTIVATION_HEIGHT = u64::MAX`; every test
//! here exercises activation through the documented TEST-ONLY overrides
//! ([`stellereum::runtime::ValidatorRuntime::set_cnvrf_v3_activation_height_for_tests`]
//! and the pure consensus helpers it drives).
//!
//! What is pinned:
//!
//! * **ONE source of truth for "who signs at height H"** — below activation the
//!   byte-identical parent-hash draw, at/after it the epoch-beacon draw, used by
//!   BOTH the decision-certificate producer
//!   (`produce_decision_certificate_with_schedule`) and the verifier
//!   (`QuorumCertificate::verify_with_schedule`). The committee must be a
//!   strict SUBSET of the validator set for the two draws to differ, so the
//!   fixtures use more than `MICRO_COMMITTEE_MAX_SIZE` (128) validators: with a
//!   small set the draw short-circuits to "everyone" and the two schedules are
//!   indistinguishable.
//! * **F2 regression**: a certificate BUILT under the beacon schedule is
//!   REFUSED by the legacy parent-hash verifier (the pre-fix finalize gate),
//!   and a certificate built under the parent-hash schedule is REFUSED by the
//!   beacon verifier. That is the exact "a node refuses its OWN decision
//!   certificate" failure, now impossible because both sides call one helper.
//! * **F3 seed rule**: the producer-side and validator-side derivations of the
//!   first post-activation boundary seed agree (they differed by a bootstrap
//!   beacon before the fix).
//! * **F4 activation-height rule**: an activation height on an epoch boundary
//!   (or inside the freeze lookahead before one) is rejected, so activation can
//!   never land on a boundary whose `epoch_vdf` was never dispatched.
//! * **Light client beacon awareness**: a configured client follows a
//!   beacon-scheduled header; the same header is refused under a schedule whose
//!   epoch does not match (fail closed, never a parent-hash fallback).

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::cn_vrf::{self, EPOCH_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS, V3_LINK_LEN};
use stellereum::consensus::{
    assert_cnvrf_v3_activation_height, cnvrf_v3_activation_height_allowed,
    cnvrf_v3_epoch_of_height, committee_for_height, micro_committee_size,
    produce_decision_certificate_with_schedule, CommitteeSchedule, EpochBeacon, QuorumCertificate,
    ValidatorSet, VoteKind, VoteSet, MICRO_COMMITTEE_MAX_SIZE,
};
use stellereum::light_client::{GenesisAnchor, LightClient, LightHeader};
use stellereum::post_quantum::FalconKeypair;
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;

/// Height used as the activation point in the beacon-schedule tests:
/// `EPOCH_LEN + 1`, i.e. one block into epoch 1. Epoch 1's `H_freeze` is
/// `EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS < EPOCH_LEN + 1`, so it is the
/// BOOTSTRAP epoch (its beacon is `cn_vrf::epoch_bootstrap_beacon`), which is
/// exactly the case that used to make the first boundary unverifiable.
const ACTIVATION: u64 = EPOCH_LEN + 1;

fn chain_id() -> u64 {
    stellereum::zkml::effective_chain_id()
}

/// The epoch beacon `height` is drawn with, as the shared rule derives it with
/// no on-chain beacon recorded yet (bootstrap epoch).
fn bootstrap_schedule(height: u64) -> CommitteeSchedule {
    let epoch = cnvrf_v3_epoch_of_height(height);
    CommitteeSchedule::Beacon(Some(EpochBeacon {
        epoch,
        output: cn_vrf::epoch_bootstrap_beacon(chain_id(), epoch),
    }))
}

/// `MICRO_COMMITTEE_MAX_SIZE + 2` validators: two more than the committee cap,
/// so the sortition committee is a strict subset and the two schedules draw
/// DIFFERENT committees. Built once per test process (Falcon keygen is the
/// expensive part) and shared read-only.
struct BigSet {
    validators: ValidatorSet,
    keys: Vec<SigningKey>,
    falcon: Vec<FalconKeypair>,
}

fn big_set() -> &'static BigSet {
    static SET: OnceLock<BigSet> = OnceLock::new();
    SET.get_or_init(|| {
        let n = MICRO_COMMITTEE_MAX_SIZE as usize + 2;
        let (keys, falcon) = falcon_votes::falcon_set(n);
        let validators = ValidatorSet::from_list(
            keys.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        BigSet {
            validators,
            keys,
            falcon,
        }
    })
}

/// Build the precommit certificate for `(height, round, block)` from every
/// validator in `set`, using `schedule` for the sortition committee.
fn certificate_at(
    set: &BigSet,
    height: u64,
    round: u32,
    block: [u8; 32],
    parent: [u8; 32],
    kind: VoteKind,
    schedule: CommitteeSchedule,
) -> QuorumCertificate {
    let mut votes = VoteSet::new();
    for (sk, fk) in set.keys.iter().zip(set.falcon.iter()) {
        votes
            .add(
                falcon_votes::fvote(sk, fk, height, round, kind, Some(block)),
                &set.validators,
                height,
                round,
                kind,
            )
            .expect("genuine vote admits");
    }
    produce_decision_certificate_with_schedule(
        &votes,
        Some(block),
        &set.validators,
        Some(&parent),
        schedule,
    )
    .expect("the whole set signs, so a certificate must compile")
}

// ---------------------------------------------------------------------------
// F4 — activation-height rule
// ---------------------------------------------------------------------------

#[test]
fn activation_height_rule_forbids_unproducible_epoch_boundaries() {
    // Genesis and the frozen "never" sentinel are always legal.
    assert!(cnvrf_v3_activation_height_allowed(0));
    assert!(cnvrf_v3_activation_height_allowed(u64::MAX));
    // A mid-epoch height whose next H_freeze still runs after activation.
    assert!(cnvrf_v3_activation_height_allowed(1));
    assert!(cnvrf_v3_activation_height_allowed(ACTIVATION));
    // Exactly ON a boundary: the activation block IS the epoch boundary and
    // requires that epoch's beacon, whose H_freeze preceded activation.
    assert!(!cnvrf_v3_activation_height_allowed(EPOCH_LEN));
    assert!(!cnvrf_v3_activation_height_allowed(2 * EPOCH_LEN));
    // Exactly ON the freeze height is the last usable point (the dispatcher
    // runs at that height and activation is `>=`).
    assert!(cnvrf_v3_activation_height_allowed(
        EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS
    ));
    // Inside the freeze lookahead: the next boundary's H_freeze is BEFORE
    // activation, so no beacon is ever dispatched for it.
    for offset in 1..=V3_COMMIT_LOOKAHEAD_BLOCKS {
        assert!(
            !cnvrf_v3_activation_height_allowed(EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS + offset),
            "offset {offset} inside the freeze window of the next boundary must be refused"
        );
    }
    // The documented panic path (what the test-only setter runs).
    let refused = std::panic::catch_unwind(|| assert_cnvrf_v3_activation_height(EPOCH_LEN));
    assert!(refused.is_err(), "activating on a boundary must panic");
    assert_cnvrf_v3_activation_height(ACTIVATION);
}

#[tokio::test]
async fn activation_setter_enforces_the_rule_on_a_real_runtime() {
    let key = SigningKey::from_bytes(&[0x5Au8; 32]);
    let me = key.verifying_key().to_bytes();
    let mut rt = ValidatorRuntime::new(
        key,
        ValidatorSet::from_list(vec![(me, 1)]),
        Arc::new(InMemoryStateEngine::new()),
        1,
    );
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.set_cnvrf_v3_activation_height_for_tests(EPOCH_LEN)
    }));
    assert!(
        refused.is_err(),
        "the setter must refuse an activation height on an epoch boundary"
    );
    // A legal height is accepted and becomes the node's activation height.
    rt.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);
    assert_eq!(rt.cnvrf_v3_activation_height(), ACTIVATION);
}

// ---------------------------------------------------------------------------
// F2 — producer/verifier symmetry at activation
// ---------------------------------------------------------------------------

#[test]
fn producer_and_verifier_share_one_committee_at_activation() {
    let set = big_set();
    let height = ACTIVATION;
    let round = 0u32;
    let block = [0x42u8; 32];
    let parent = [0x11u8; 32];
    let schedule = bootstrap_schedule(height);

    // The fixture is only meaningful when the beacon draw is a strict subset
    // and the two schedules disagree about WHO signs.
    let committee_size = micro_committee_size(set.validators.len());
    assert!(
        (committee_size as usize) < set.validators.len(),
        "fixture must exceed the committee cap ({committee_size} vs {})",
        set.validators.len()
    );
    let beacon_committee = committee_for_height(
        &set.validators,
        height,
        round,
        committee_size,
        Some(&parent),
        schedule,
    );
    let legacy_committee = committee_for_height(
        &set.validators,
        height,
        round,
        committee_size,
        Some(&parent),
        CommitteeSchedule::ParentHash,
    );
    assert_eq!(beacon_committee.len(), committee_size as usize);
    assert_ne!(
        beacon_committee, legacy_committee,
        "the beacon draw must differ from the parent-hash draw for this fixture"
    );

    // Build the certificate exactly as the PRODUCER does at activation.
    let qc = certificate_at(
        set,
        height,
        round,
        block,
        parent,
        VoteKind::Precommit,
        schedule,
    );

    // 1. The node VERIFIES ITS OWN certificate under the same schedule.
    assert!(
        qc.verify_with_schedule(&set.validators, schedule),
        "a certificate built at activation must verify under the beacon schedule (F2)"
    );
    assert!(
        set.validators.qc_signed_power_with_schedule(&qc, schedule)
            >= set.validators.quorum_power(),
        "the beacon-attributed signers must carry quorum power"
    );

    // 2. The legacy (pre-fix) verifier refuses it — this is the bug: the
    //    finalize gate used exactly this draw and rejected the node's own QC.
    assert!(
        !qc.verify(&set.validators),
        "the parent-hash verifier must REFUSE a beacon-drawn certificate (pre-fix behaviour)"
    );

    // 3. Symmetrically, a legacy-drawn certificate is refused by the beacon
    //    verifier: neither side can silently fall back to the other's draw.
    let legacy_qc = certificate_at(
        set,
        height,
        round,
        block,
        parent,
        VoteKind::Precommit,
        CommitteeSchedule::ParentHash,
    );
    assert!(
        legacy_qc.verify(&set.validators),
        "the legacy certificate verifies below activation (byte-identical path)"
    );
    assert!(
        !legacy_qc.verify_with_schedule(&set.validators, schedule),
        "the beacon verifier must refuse a parent-hash-drawn certificate"
    );

    // 4. Fail closed when the epoch beacon is unknown: no parent-hash fallback.
    assert!(
        !qc.verify_with_schedule(&set.validators, CommitteeSchedule::Beacon(None)),
        "an unknown epoch beacon must elect nobody, never fall back to the parent hash"
    );
    // 5. A wrong-epoch beacon is refused as well.
    let wrong_epoch = CommitteeSchedule::Beacon(Some(EpochBeacon {
        epoch: cnvrf_v3_epoch_of_height(height) + 1,
        output: cn_vrf::epoch_bootstrap_beacon(chain_id(), cnvrf_v3_epoch_of_height(height) + 1),
    }));
    assert!(
        !qc.verify_with_schedule(&set.validators, wrong_epoch),
        "a beacon from another epoch must never attribute this height's signers"
    );
}

// ---------------------------------------------------------------------------
// F3 — the seed rule at the first post-activation boundary
// ---------------------------------------------------------------------------

#[test]
fn first_boundary_seed_agrees_between_producer_and_validator() {
    let chain = chain_id();
    let freeze_hash = [0xA7u8; 32];
    let rolling_mix = [0x3Cu8; V3_LINK_LEN];

    // The first boundary under ACTIVATION is block 2*EPOCH_LEN (epoch 2);
    // its predecessor (epoch 1) is the bootstrap epoch.
    let boundary_epoch = 2u64;
    let prev_epoch = boundary_epoch - 1;
    assert!(
        !cn_vrf::epoch_had_vdf(prev_epoch, ACTIVATION),
        "epoch 1's H_freeze ({}) precedes activation {ACTIVATION}",
        cn_vrf::freeze_height_of_epoch(prev_epoch)
    );

    // PRODUCER side (and state-engine side): the committed map has no beacon
    // for the bootstrap epoch, so the shared rule chains its bootstrap output.
    let producer_seed = cn_vrf::epoch_seed(
        chain,
        boundary_epoch,
        None,
        cn_vrf::epoch_had_vdf(prev_epoch, ACTIVATION),
        &freeze_hash,
        &rolling_mix,
    );

    // VALIDATOR side: resolve the predecessor's canonical beacon through the
    // shared resolver (bootstrap because it never ran a VDF), then derive.
    let prev_beacon =
        cn_vrf::epoch_beacon_for(chain, prev_epoch, None, ACTIVATION).expect("bootstrap beacon");
    assert_ne!(
        prev_beacon, [0u8; V3_LINK_LEN],
        "the bootstrap beacon is non-zero"
    );
    let validator_seed = cn_vrf::epoch_raw_seed(
        chain,
        boundary_epoch,
        &prev_beacon,
        &freeze_hash,
        &rolling_mix,
    );
    assert_eq!(
        producer_seed, validator_seed,
        "producer and validator must derive ONE seed at the first boundary (F3)"
    );

    // The pre-fix producer chained ZEROS; that value differs from the fixed
    // one, which is why the boundary could never verify before.
    let pre_fix = cn_vrf::epoch_raw_seed(
        chain,
        boundary_epoch,
        &[0u8; V3_LINK_LEN],
        &freeze_hash,
        &rolling_mix,
    );
    assert_ne!(pre_fix, producer_seed, "the fix must be behaviour-changing");

    // The beacon chain STARTS: epoch 2's seed yields a verifiable MinRoot proof,
    // and the next epoch chains that beacon. (Epoch 1's own beacon is the
    // bootstrap output, which is exactly what the producer chained above.)
    let proof = stellereum::minroot_vdf::eval(&producer_seed, 64, 16);
    let output = stellereum::minroot_vdf::verify(&producer_seed, 64, &proof)
        .expect("the first post-activation MinRoot beacon must verify");
    assert_eq!(
        output,
        stellereum::minroot_vdf::derive_vdf_output(&producer_seed, &proof)
    );

    // Epoch 3's seed chains epoch 2's committed beacon.
    let next_seed = cn_vrf::epoch_seed(
        chain,
        boundary_epoch + 1,
        Some(&output),
        cn_vrf::epoch_had_vdf(boundary_epoch, ACTIVATION),
        &freeze_hash,
        &rolling_mix,
    );
    let next_proof = stellereum::minroot_vdf::eval(&next_seed, 64, 16);
    let next_output = stellereum::minroot_vdf::verify(&next_seed, 64, &next_proof)
        .expect("the beacon chain must continue across the second boundary");
    assert_ne!(next_output, output, "each epoch's beacon must be fresh");
    assert!(
        cn_vrf::epoch_had_vdf(boundary_epoch, ACTIVATION),
        "epoch 2's H_freeze ({}) runs after activation {ACTIVATION}",
        cn_vrf::freeze_height_of_epoch(boundary_epoch)
    );
}

// ---------------------------------------------------------------------------
// Light client — beacon awareness
// ---------------------------------------------------------------------------

#[test]
fn light_client_verifies_under_the_beacon_schedule() {
    let set = big_set();
    let height = ACTIVATION;
    let block = [0x66u8; 32];
    let schedule = bootstrap_schedule(height);
    let qc = certificate_at(
        set,
        height,
        0,
        block,
        [0u8; 32],
        VoteKind::Precommit,
        schedule,
    );

    let header = LightHeader {
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        block_hash: block,
        timestamp: 1_760_000_000,
        proposer: set
            .validators
            .proposer_for_with_schedule(height, 0, schedule)
            .expect("beacon schedule names a proposer"),
        cert: qc.clone(),
        signatures: Vec::new(),
    };

    // The header's finality gate is beacon-aware: the same certificate is
    // accepted under the beacon schedule and refused under the parent-hash one.
    assert!(header
        .verify_with_schedule(&set.validators, schedule)
        .is_ok());
    assert!(
        header
            .verify_with_schedule(&set.validators, CommitteeSchedule::ParentHash)
            .is_err(),
        "the light client must not attribute a beacon certificate through the parent hash"
    );

    let genesis = GenesisAnchor {
        height: 0,
        block_hash: [0u8; 32],
        parent_hash: [0u8; 32],
        state_root: [0u8; 32],
    };

    // A configured client (activation reached) re-anchors on this checkpoint:
    // `advance_to_checkpoint` verifies the certificate under the client's own
    // schedule, deriving the bootstrap beacon itself (nothing recorded).
    let cp =
        stellereum::light_client::Checkpoint::new(height, block, [0u8; 32], [0u8; 32], qc.clone());
    let mut light =
        LightClient::with_genesis_anchor(set.validators.clone(), genesis.clone()).unwrap();
    light.configure_cnvrf_v3(chain_id(), ACTIVATION);
    light
        .advance_to_checkpoint(cp.clone())
        .expect("a beacon-aware light client must follow the first post-activation anchor (F2)");

    // ... and then follows the NEXT header of the same epoch under the beacon.
    let next_block = [0x67u8; 32];
    let next_qc = certificate_at(
        set,
        height + 1,
        0,
        next_block,
        block,
        VoteKind::Precommit,
        schedule,
    );
    let next_header = LightHeader {
        height: height + 1,
        prev_hash: block,
        state_root: [0u8; 32],
        block_hash: next_block,
        timestamp: 1_760_000_001,
        proposer: set
            .validators
            .proposer_for_with_schedule(height + 1, 0, schedule)
            .expect("beacon schedule names a proposer"),
        cert: next_qc,
        signatures: Vec::new(),
    };
    light
        .apply_header(next_header)
        .expect("the beacon-aware light client must follow the next header too");

    // An unconfigured client (frozen gate) keeps the parent-hash schedule and
    // refuses the beacon certificate: fail closed, never a silent fallback.
    let mut legacy = LightClient::with_genesis_anchor(set.validators.clone(), genesis).unwrap();
    assert!(legacy.advance_to_checkpoint(cp).is_err());
}
