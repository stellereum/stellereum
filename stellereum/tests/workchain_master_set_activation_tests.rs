//! Deterministic activation of MASTER-derived validator sets on a workchain.
//!
//! THE BUG THIS PINS. A workchain has no staking registry of its own (its ledger
//! is empty by design); it derives its consensus set from the masterchain's
//! registry, shared process-wide through `ValidatorRuntime::master_staking`.
//! The activation used to be staged at the WORKCHAIN's own `hc.height + 1`
//! boundary, while the masterchain height at which the rotation was adopted is
//! unrelated to the workchain tip. Two workchain nodes that observed the SAME
//! rotation at DIFFERENT local heights therefore staged it at DIFFERENT heights,
//! scheduled different proposers and rejected each other's proposals as "wrong
//! proposer" — finality stopped and no height ever advanced to heal it.
//!
//! THE FIX THIS PINS. The masterchain publishes a deterministic stamp when it
//! derives a set: `(fingerprint of the derived set, master_ledger_height + 1)`.
//! A workchain binds the set it derived to the stamp with the matching
//! fingerprint and uses that boundary verbatim, so every node activates the
//! same rotation at the same height regardless of its own tip. A workchain that
//! cannot find the stamp for the set it derived fail-closes to observer (no
//! votes) instead of guessing.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::{workchain_set_activation_height, ValidatorRuntime};
use stellereum::sharding::{MasterStakingLedger, ShardRegistry, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const WORKCHAIN: u32 = 1;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn bond_floor() -> u64 {
    stellereum::staking::required_bond_floor_nano()
}

fn registry() -> ShardRegistry {
    ShardRegistry::from_ids([MASTERCHAIN_SHARD, WORKCHAIN])
}

fn workchain(
    key: SigningKey,
    config: ValidatorSet,
    master: MasterStakingLedger,
    height: u64,
) -> ValidatorRuntime {
    let mut rt = ValidatorRuntime::new(key, config, Arc::new(InMemoryStateEngine::new()), height)
        .with_shard(WORKCHAIN, registry())
        .with_master_staking(master);
    rt.hc.height = height;
    rt
}

/// The masterchain at `height` adopts a rotation (a newcomer bonds) and
/// publishes its activation stamp for the derived set.
async fn master_rotation(
    master_key: SigningKey,
    config: ValidatorSet,
    master_engine: &Arc<InMemoryStateEngine>,
    height: u64,
    newcomer: [u8; 32],
) -> MasterStakingLedger {
    master_engine
        .staking_write()
        .await
        .bond(newcomer, bond_floor(), 0)
        .expect("the masterchain bond must be accepted");
    let mut master = ValidatorRuntime::new(master_key, config, master_engine.clone(), height)
        .with_shard(MASTERCHAIN_SHARD, registry());
    master.hc.height = height;
    assert!(
        master.refresh_validator_set_from_staking().await,
        "the masterchain must derive the rotated set and publish its activation stamp"
    );
    master_engine.staking_handle()
}

/// REQUIRED PROOF: the same rotation activates at the SAME height on two
/// workchain nodes that start from DIFFERENT workchain heights.
#[tokio::test]
async fn rotation_activates_at_the_same_height_on_differently_lagging_workchains() {
    let master_key = key(11);
    let me = master_key.verifying_key().to_bytes();
    let newcomer = key(12).verifying_key().to_bytes();
    let floor = bond_floor();
    let config = ValidatorSet::from_list(vec![(me, 1)]);
    let master_engine = Arc::new(InMemoryStateEngine::new());
    const MASTER_HEIGHT: u64 = 7;

    let handle = master_rotation(
        master_key.clone(),
        config.clone(),
        &master_engine,
        MASTER_HEIGHT,
        newcomer,
    )
    .await;

    // Two workchains sharing the master registry, at very different tips.
    let mut lagging = workchain(master_key.clone(), config.clone(), handle.clone(), 3);
    let mut ahead = workchain(master_key, config, handle, 20);

    assert!(
        lagging.refresh_validator_set_from_staking().await,
        "the lagging workchain must stage the rotation"
    );
    assert!(
        ahead.refresh_validator_set_from_staking().await,
        "the leading workchain must adopt the rotation"
    );

    let expected = workchain_set_activation_height(MASTER_HEIGHT);
    assert_eq!(expected, MASTER_HEIGHT + 1);

    // The lagging node keeps its previous set until the (shared) boundary...
    assert_eq!(
        lagging.pending_validators.as_ref().map(|(a, _)| *a),
        Some(expected),
        "the boundary is the masterchain datum, not the workchain tip (3 + 1)"
    );
    assert!(
        !lagging
            .validator_set_for_height(expected - 1)
            .validators
            .contains_key(&newcomer),
        "the workchain must not run ahead of the master's set"
    );
    assert_eq!(
        lagging
            .validator_set_for_height(expected)
            .validators
            .get(&newcomer),
        Some(&floor),
        "the workchain answers the rotated set for heights at/above the boundary"
    );

    // The leading node is already past the boundary, so it installs at once —
    // but it records the SAME activation as the lagging node.
    assert!(
        ahead.pending_validators.is_none(),
        "a node past the boundary installs immediately"
    );
    assert_eq!(
        ahead.validator_set_history.back().map(|(a, _)| *a),
        Some(expected),
        "the leading node records the masterchain boundary, not its own tip"
    );
    let boundary_set = lagging.validator_set_for_height(expected);
    assert_eq!(
        ahead
            .validator_set_history
            .back()
            .map(|(_, set)| set.validators.clone()),
        Some(boundary_set.validators.clone()),
        "both nodes adopt the exact same set"
    );

    // Advance the lagging node to the boundary: the two are byte-identical.
    lagging.hc.height = expected;
    lagging.install_due_validator_set();
    lagging.hc.validators = lagging.validators.clone();
    assert!(lagging.pending_validators.is_none());
    assert_eq!(lagging.validators.validators, ahead.validators.validators);
    assert_eq!(
        lagging.hc.validators.validators,
        ahead.hc.validators.validators
    );
    assert!(!lagging.is_validator_set_stale());
    assert!(!ahead.is_validator_set_stale());
}

/// REQUIRED PROOF: a workchain whose tip is BELOW the masterchain's boundary
/// keeps the previous set (it never runs ahead of the master's set) and only
/// switches when it reaches the boundary.
#[tokio::test]
async fn workchain_never_runs_ahead_of_the_master_set() {
    let master_key = key(21);
    let me = master_key.verifying_key().to_bytes();
    let newcomer = key(22).verifying_key().to_bytes();
    let floor = bond_floor();
    let config = ValidatorSet::from_list(vec![(me, 1)]);
    let master_engine = Arc::new(InMemoryStateEngine::new());
    const MASTER_HEIGHT: u64 = 12;

    let handle = master_rotation(
        master_key.clone(),
        config.clone(),
        &master_engine,
        MASTER_HEIGHT,
        newcomer,
    )
    .await;

    let mut wc = workchain(master_key, config, handle, 11);
    let boundary = workchain_set_activation_height(MASTER_HEIGHT);
    assert!(wc.refresh_validator_set_from_staking().await);
    assert_eq!(
        wc.pending_validators.as_ref().map(|(a, _)| *a),
        Some(boundary)
    );
    // The rotation is decided but NOT in force: the old set still governs the
    // heights the workchain is at/behind.
    assert!(
        !wc.validators.validators.contains_key(&newcomer),
        "the workchain must not join the master's next set early"
    );
    assert!(!wc
        .validator_set_for_height(MASTER_HEIGHT)
        .validators
        .contains_key(&newcomer));
    assert_eq!(
        wc.validator_set_for_height(boundary)
            .validators
            .get(&newcomer),
        Some(&floor)
    );

    // One height short of the boundary: still the previous set.
    wc.hc.height = boundary - 1;
    wc.install_due_validator_set();
    wc.hc.validators = wc.validators.clone();
    assert!(!wc.validators.validators.contains_key(&newcomer));

    // At the boundary: the rotation is in force.
    wc.hc.height = boundary;
    assert!(wc.install_due_validator_set());
    wc.hc.validators = wc.validators.clone();
    assert_eq!(wc.validators.validators.get(&newcomer), Some(&floor));
    assert_eq!(wc.hc.validators.validators.get(&newcomer), Some(&floor));
    assert_eq!(
        wc.validator_set_history.back().map(|(a, _)| *a),
        Some(boundary)
    );
}

/// REQUIRED PROOF: the wedge scenario heals WITHOUT moving the height. A
/// workchain wedged above the rotation's boundary installs the master's set in
/// place on the repair timer, and a converged tick is a silent no-op.
#[tokio::test]
async fn wedge_heals_without_moving_the_height() {
    let master_key = key(31);
    let me = master_key.verifying_key().to_bytes();
    let newcomer = key(32).verifying_key().to_bytes();
    let floor = bond_floor();
    let config = ValidatorSet::from_list(vec![(me, 1)]);
    let master_engine = Arc::new(InMemoryStateEngine::new());
    const MASTER_HEIGHT: u64 = 5;
    const WEDGED_HEIGHT: u64 = 40;

    let handle = master_rotation(
        master_key.clone(),
        config.clone(),
        &master_engine,
        MASTER_HEIGHT,
        newcomer,
    )
    .await;

    let mut wc = workchain(master_key, config, handle, WEDGED_HEIGHT);
    let boundary = workchain_set_activation_height(MASTER_HEIGHT);

    assert!(
        wc.refresh_workchain_set_from_master().await,
        "the repair timer must pick the masterchain rotation up"
    );
    assert_eq!(
        wc.hc.height, WEDGED_HEIGHT,
        "the repair must not move the height"
    );
    assert_eq!(
        wc.validators.validators.get(&newcomer),
        Some(&floor),
        "the boundary is already behind the wedged height: install in place"
    );
    assert_eq!(
        wc.validator_set_history.back().map(|(a, _)| *a),
        Some(boundary),
        "the recorded activation is the masterchain boundary"
    );
    assert!(!wc.is_validator_set_stale());

    // Idempotent backstop: a converged tick re-stages nothing and stays quiet.
    assert!(
        !wc.refresh_workchain_set_from_master().await,
        "a converged repair must be a silent no-op"
    );
    assert_eq!(wc.hc.height, WEDGED_HEIGHT);
    assert!(wc.pending_validators.is_none());
}

/// REQUIRED PROOF (fail closed): a workchain that cannot prove which
/// masterchain block defined the set does NOT vote — it never guesses an
/// activation height. Once the masterchain publishes the stamp, it heals.
#[tokio::test]
async fn workchain_fails_closed_without_a_masterchain_stamp() {
    let master_key = key(41);
    let me = master_key.verifying_key().to_bytes();
    let newcomer = key(42).verifying_key().to_bytes();
    let config = ValidatorSet::from_list(vec![(me, 1)]);

    // A ledger that holds a rotated set but was NEVER derived by a masterchain
    // runtime: no stamp exists for its fingerprint.
    let orphan_engine = Arc::new(InMemoryStateEngine::new());
    orphan_engine
        .staking_write()
        .await
        .bond(newcomer, bond_floor(), 0)
        .expect("the bond must be accepted");
    let orphan = orphan_engine.staking_handle();

    let mut wc = workchain(master_key.clone(), config.clone(), orphan, 4);
    assert!(
        !wc.refresh_validator_set_from_staking().await,
        "an unprovable set must not be staged"
    );
    assert!(
        wc.is_validator_set_stale(),
        "the stale flag must be armed (fail-closed observer)"
    );
    assert!(
        !wc.effective_can_vote(true),
        "an observer with an unprovable set must not vote"
    );
    assert!(
        wc.validator_set_stale_reason()
            .is_some_and(|r| r.contains("activation stamp")),
        "the loud reason must name the missing datum"
    );
    assert!(
        wc.pending_validators.is_none(),
        "nothing may be guessed or staged"
    );
    assert!(
        !wc.validators.validators.contains_key(&newcomer),
        "the previous set must stay in force"
    );

    // The masterchain runtime now derives the same ledger at its own height
    // and publishes the stamp; the SAME workchain adopts it at that boundary.
    const MASTER_HEIGHT: u64 = 9;
    let mut master = ValidatorRuntime::new(
        master_key,
        config.clone(),
        orphan_engine.clone(),
        MASTER_HEIGHT,
    )
    .with_shard(MASTERCHAIN_SHARD, registry());
    master.hc.height = MASTER_HEIGHT;
    assert!(master.refresh_validator_set_from_staking().await);

    assert!(
        wc.refresh_validator_set_from_staking().await,
        "a published stamp must heal the observer"
    );
    assert!(!wc.is_validator_set_stale());
    assert!(wc.effective_can_vote(true));
    assert_eq!(
        wc.pending_validators.as_ref().map(|(a, _)| *a),
        Some(workchain_set_activation_height(MASTER_HEIGHT))
    );
}

/// The stamp is CONTENT-addressed, not tip-addressed: repeated uneventful
/// masterchain refreshes keep the original boundary, so a workchain that reads
/// the same registry later binds to the SAME height.
#[tokio::test]
async fn stamp_is_content_addressed_and_stable_across_refreshes() {
    let master_key = key(51);
    let me = master_key.verifying_key().to_bytes();
    let newcomer = key(52).verifying_key().to_bytes();
    let floor = bond_floor();
    let config = ValidatorSet::from_list(vec![(me, 1)]);
    let master_engine = Arc::new(InMemoryStateEngine::new());
    const MASTER_HEIGHT: u64 = 8;

    let handle = master_rotation(
        master_key.clone(),
        config.clone(),
        &master_engine,
        MASTER_HEIGHT,
        newcomer,
    )
    .await;

    // A workchain adopts the rotation at the masterchain boundary.
    let mut wc = workchain(master_key.clone(), config.clone(), handle.clone(), 8);
    assert!(wc.refresh_validator_set_from_staking().await);
    let first = wc.pending_validators.as_ref().map(|(a, _)| *a);
    assert_eq!(first, Some(workchain_set_activation_height(MASTER_HEIGHT)));

    // The masterchain keeps refreshing at LATER heights with the same set.
    for later in [MASTER_HEIGHT + 10, MASTER_HEIGHT + 25] {
        let mut master = ValidatorRuntime::new(
            master_key.clone(),
            config.clone(),
            master_engine.clone(),
            later,
        )
        .with_shard(MASTERCHAIN_SHARD, registry());
        master.hc.height = later;
        // Same ledger → unchanged set: the refresh may stage nothing on the
        // master itself, but it must NOT re-date the published boundary.
        master.refresh_validator_set_from_staking().await;
        let mut probe = workchain(master_key.clone(), config.clone(), handle.clone(), 8);
        assert!(probe.refresh_validator_set_from_staking().await);
        assert_eq!(
            probe.pending_validators.as_ref().map(|(a, _)| *a),
            first,
            "an unchanged set keeps its original activation height"
        );
    }

    let mut probe = workchain(master_key, config, handle, 8);
    assert!(probe.refresh_validator_set_from_staking().await);
    assert_eq!(
        probe
            .validator_set_for_height(workchain_set_activation_height(MASTER_HEIGHT))
            .validators
            .get(&newcomer),
        Some(&floor)
    );
    assert!(!probe.is_validator_set_stale());
}

/// A shared ledger that moved PAST the masterchain's last derivation cannot be
/// paired with the older stamp (content mismatch): the workchain fails closed
/// instead of adopting a set whose adoption block it cannot identify.
#[tokio::test]
async fn workchain_fails_closed_when_the_ledger_moved_past_the_stamp() {
    let master_key = key(61);
    let me = master_key.verifying_key().to_bytes();
    let newcomer = key(62).verifying_key().to_bytes();
    let latecomer = key(63).verifying_key().to_bytes();
    let config = ValidatorSet::from_list(vec![(me, 1)]);
    let master_engine = Arc::new(InMemoryStateEngine::new());
    const MASTER_HEIGHT: u64 = 3;

    let handle = master_rotation(
        master_key.clone(),
        config.clone(),
        &master_engine,
        MASTER_HEIGHT,
        newcomer,
    )
    .await;

    // The ledger moves again — a second bond — but NO masterchain refresh has
    // derived it yet.
    master_engine
        .staking_write()
        .await
        .bond(latecomer, bond_floor(), 0)
        .expect("the second bond must be accepted");

    let mut wc = workchain(master_key, config, handle, MASTER_HEIGHT);
    assert!(
        !wc.refresh_validator_set_from_staking().await,
        "a set the masterchain never derived must not be staged"
    );
    assert!(wc.is_validator_set_stale());
    assert!(!wc.effective_can_vote(true));
    assert!(wc.pending_validators.is_none());
    assert!(
        wc.validator_set_stale_reason()
            .is_some_and(|r| r.contains("has no published activation stamp")),
        "the reason must name the content/stamp mismatch"
    );
}
