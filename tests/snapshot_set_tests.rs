//! F5 set-at-height snapshot binding (KI-13) + strict trust-anchor parser.
//!
//! What is pinned here:
//! * snapshots used as trust anchors MUST commit to the validator set at that
//!   height: [`stellereum::sync::check_snapshot_set_binding`] strict-decodes
//!   the `domains` blob (current shape only — legacy/unknown versions are a
//!   hard refusal, no downgrade) and requires the derived set to be non-empty
//!   and EQUAL to the set that verified the anchor QCs;
//! * [`stellereum::sync::fast_sync_state_with_set_binding`] enforces that gate
//!   BEFORE the target engine is mutated (refusals leave live state untouched),
//!   while plain [`stellereum::sync::fast_sync_state`] keeps its exact
//!   behavior for unbonded/config-set chains;
//! * the `_with_sets` anchor variants verify each height's QC against the set
//!   in force AT THAT height (rotation: single-set verification fail-closes,
//!   per-height verification passes) and refuse unresolvable heights.

use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    decode_domain_snapshot_strict, snapshot_validator_set_strict, DomainSnapshot,
    DomainSnapshotV1,
};
use stellereum::sync::{
    check_snapshot_set_binding, fast_sync_state_with_set_binding,
    verify_snapshot_anchor_tail_with_sets, HeaderLink,
};

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn ledger_for(keys: &[SigningKey]) -> stellereum::staking::StakingLedger {
    let mut l = stellereum::staking::StakingLedger::new();
    for k in keys {
        l.bond(
            k.verifying_key().to_bytes(),
            stellereum::staking::MIN_VALIDATOR_BOND + stellereum::staking::STELL_MIN_BOND_BUFFER,
            0,
        )
        .unwrap();
    }
    l
}

/// A bonded source engine: staking bonded INSIDE the engine so the state root
/// commits to the same ledger the `domains` blob carries.
async fn bonded_source(
    keys: &[SigningKey],
) -> (
    InMemoryStateEngine,
    stellereum::staking::StakingLedger,
    [u8; 32],
    Vec<u8>,
    Vec<u8>,
) {
    let engine = InMemoryStateEngine::new();
    let user = [0x55u8; 32];
    engine
        .update_account(AccountState::new(user, 1_000_000))
        .await;
    {
        let mut staking = engine.staking_write().await;
        for k in keys {
            staking
                .bond(
                    k.verifying_key().to_bytes(),
                    stellereum::staking::MIN_VALIDATOR_BOND
                        + stellereum::staking::STELL_MIN_BOND_BUFFER,
                    0,
                )
                .unwrap();
        }
    }
    let gov = engine.governance_read().await.clone();
    let staking = engine.staking_read().await.clone();
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &staking, &gov).await;
    let domains = bincode::serialize(&dom).unwrap();
    (engine, staking, root, snap, domains)
}

fn domains_bundle(domains: Vec<u8>) -> Vec<(&'static str, Vec<u8>)> {
    vec![("domains", domains)]
}

// ==================== strict parser ====================

#[test]
fn strict_parser_round_trips_the_current_shape() {
    let keys: Vec<SigningKey> = (0..3).map(|i| test_key(0xA0 + i)).collect();
    let ledger = ledger_for(&keys);
    let gov = stellereum::governance::Governance::new();
    let engine = InMemoryStateEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dom = rt.block_on(DomainSnapshot::capture(&engine, &ledger, &gov));
    let bytes = bincode::serialize(&dom).unwrap();
    let back = decode_domain_snapshot_strict(&bytes).expect("current shape must decode strictly");
    assert_eq!(
        back.staking.to_validator_set().validators,
        ledger.to_validator_set().validators,
        "strict decode preserves the staking commitment"
    );
    let resolved = snapshot_validator_set_strict(100, &bytes).expect("set must resolve");
    assert_eq!(
        resolved.validators,
        ledger.to_validator_set().validators,
        "strict set helper derives the set-at-height"
    );
}

#[test]
fn strict_parser_refuses_a_legacy_v1_blob() {
    let keys: Vec<SigningKey> = (0..2).map(|i| test_key(0xB0 + i)).collect();
    let ledger = ledger_for(&keys);
    // A pre-E2 blob: same content, legacy staking shape.
    let old = DomainSnapshotV1 {
        tokens: Default::default(),
        contracts: Default::default(),
        orderbooks: Default::default(),
        pmm: Default::default(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        order_escrow: HashMap::new(),
        staking: stellereum::staking::StakingLedgerV1 {
            validators: ledger.validators.clone(),
            delegations: ledger.delegations.clone(),
            delegator_rewards: ledger.delegator_rewards.clone(),
            unbonding: ledger.unbonding.clone(),
            withdrawable: ledger.withdrawable.clone(),
            total_burned: ledger.total_burned,
        },
        governance: Default::default(),
        oracle: Default::default(),
    };
    let old_bytes = bincode::serialize(&old).unwrap();
    // The lenient local-restore path still upgrades it (boot compat)...
    assert!(
        stellereum::storage::decode_domain_snapshot(&old_bytes).is_ok(),
        "lenient restore keeps booting pre-upgrade data dirs"
    );
    // ...but the trust-anchor path hard-refuses it.
    let err = decode_domain_snapshot_strict(&old_bytes)
        .expect_err("legacy blob must be refused by the strict parser");
    assert!(
        err.contains("legacy or unknown version"),
        "refusal names the legacy cause, got: {err}"
    );
    let err = snapshot_validator_set_strict(100, &old_bytes)
        .expect_err("legacy blob commits to no usable set");
    assert!(err.contains("100"), "error names the height, got: {err}");
}

#[test]
fn strict_parser_refuses_trailing_junk_and_truncation() {
    let dom = DomainSnapshot::default();
    let mut bytes = bincode::serialize(&dom).unwrap();
    bytes.extend_from_slice(&[0xAA; 16]);
    assert!(
        decode_domain_snapshot_strict(&bytes).is_err(),
        "trailing junk after a valid blob must be refused"
    );
    let mut trunc = bincode::serialize(&dom).unwrap();
    trunc.truncate(trunc.len() / 2);
    assert!(
        decode_domain_snapshot_strict(&trunc).is_err(),
        "truncation must be refused"
    );
    assert!(
        decode_domain_snapshot_strict(&[]).is_err(),
        "empty blob must be refused"
    );
}

// ==================== set binding ====================

#[tokio::test]
async fn set_binding_happy_path_installs_the_bound_set() {
    let keys: Vec<SigningKey> = (0..4).map(|i| test_key(0xC0 + i)).collect();
    let (_source, staking, root, snap, domains) = bonded_source(&keys).await;
    let anchor_set = staking.to_validator_set();
    assert!(
        !anchor_set.validators.is_empty(),
        "fixture must bond a real set"
    );

    let target = InMemoryStateEngine::new();
    let bound = fast_sync_state_with_set_binding(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let d = domains.clone();
            async move {
                if kind == "domains" {
                    Some(d)
                } else {
                    None
                }
            }
        },
        100,
        &anchor_set,
    )
    .await
    .expect("matching set must bind");
    assert_eq!(
        bound.validators, anchor_set.validators,
        "the bound set is the set-at-height"
    );
    assert_eq!(target.get_state_root().await, root);
}

#[tokio::test]
async fn set_binding_refuses_a_mismatched_anchor_set() {
    let keys: Vec<SigningKey> = (0..4).map(|i| test_key(0xD0 + i)).collect();
    let (_source, _staking, root, snap, domains) = bonded_source(&keys).await;
    // A DIFFERENT (rotated) set tries to vouch for the same snapshot.
    let other_keys: Vec<SigningKey> = (0..4).map(|i| test_key(0xE0 + i)).collect();
    let other_ledger = ledger_for(&other_keys);
    let other_set = other_ledger.to_validator_set();

    let target = InMemoryStateEngine::new();
    let err = fast_sync_state_with_set_binding(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let d = domains.clone();
            async move {
                if kind == "domains" {
                    Some(d)
                } else {
                    None
                }
            }
        },
        100,
        &other_set,
    )
    .await
    .expect_err("a snapshot bound to another set must be refused");
    assert!(
        err.contains("does not match"),
        "refusal names the set mismatch, got: {err}"
    );
    assert_ne!(
        target.get_state_root().await,
        root,
        "refusal leaves the target untouched"
    );
}

#[tokio::test]
async fn set_binding_refuses_a_snapshot_without_domains() {
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([0x77u8; 32], 500))
        .await;
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let anchor_set = ValidatorSet::from_list(vec![([0x99u8; 32], 1)]);

    let target = InMemoryStateEngine::new();
    let err = fast_sync_state_with_set_binding(
        &target,
        root,
        || async { Some(snap.clone()) },
        |_| async { None },
        100,
        &anchor_set,
    )
    .await
    .expect_err("a snapshot with no set commitment is not a trust anchor");
    assert!(
        err.contains("no `domains` blob"),
        "refusal names the missing commitment, got: {err}"
    );
}

#[test]
fn set_binding_refuses_legacy_and_empty_commitments() {
    let keys: Vec<SigningKey> = (0..2).map(|i| test_key(0xF0 + i)).collect();
    let ledger = ledger_for(&keys);
    let anchor_set = ledger.to_validator_set();

    // Legacy bytes (V1 shape) fail the strict gate before any set comparison.
    let old = DomainSnapshotV1 {
        tokens: Default::default(),
        contracts: Default::default(),
        orderbooks: Default::default(),
        pmm: Default::default(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        order_escrow: HashMap::new(),
        staking: stellereum::staking::StakingLedgerV1 {
            validators: ledger.validators.clone(),
            delegations: ledger.delegations.clone(),
            delegator_rewards: ledger.delegator_rewards.clone(),
            unbonding: ledger.unbonding.clone(),
            withdrawable: ledger.withdrawable.clone(),
            total_burned: ledger.total_burned,
        },
        governance: Default::default(),
        oracle: Default::default(),
    };
    let err = check_snapshot_set_binding(
        100,
        &domains_bundle(bincode::serialize(&old).unwrap()),
        &anchor_set,
    )
    .expect_err("legacy commitment must be refused");
    assert!(
        err.contains("legacy or unknown version"),
        "legacy refusal is explicit, got: {err}"
    );

    // An EMPTY commitment cannot vouch for the next height.
    let empty = bincode::serialize(&DomainSnapshot::default()).unwrap();
    let err = check_snapshot_set_binding(100, &domains_bundle(empty), &anchor_set)
        .expect_err("empty set commitment must be refused");
    assert!(err.contains("EMPTY"), "empty refusal is explicit, got: {err}");

    // An empty ANCHOR set proves nothing, so there is no binding to check.
    let full = bonded_full_domains(&keys);
    let err = check_snapshot_set_binding(
        100,
        &domains_bundle(full),
        &ValidatorSet::new(),
    )
    .expect_err("empty anchor set must be refused");
    assert!(
        err.contains("never quorum-verified"),
        "anchor-emptiness refusal is explicit, got: {err}"
    );
}

fn bonded_full_domains(keys: &[SigningKey]) -> Vec<u8> {
    let ledger = ledger_for(keys);
    let gov = stellereum::governance::Governance::new();
    let engine = InMemoryStateEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dom = rt.block_on(DomainSnapshot::capture(&engine, &ledger, &gov));
    bincode::serialize(&dom).unwrap()
}

// ==================== per-height anchor verification ====================

struct WindowLink {
    height: u64,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
}

fn window_links(hashes: &[[u8; 32]]) -> Vec<WindowLink> {
    hashes
        .iter()
        .enumerate()
        .map(|(i, h)| WindowLink {
            height: (i + 2) as u64, // window covers heights 2,3,4
            block_hash: *h,
            prev_hash: if i == 0 { [0x10u8; 32] } else { hashes[i - 1] },
        })
        .collect()
}

fn qc_for(signers: &[SigningKey], height: u64, block_hash: [u8; 32]) -> QuorumCertificate {
    let sigs = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(block_hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: sigs,
    }
}

fn header_link(
    w: &WindowLink,
    set: &ValidatorSet,
    signers: &[SigningKey],
) -> HeaderLink {
    let proposer = set
        .proposer_for(w.height, 0)
        .expect("non-empty set names a proposer");
    HeaderLink {
        height: w.height,
        block_hash: w.block_hash,
        prev_hash: w.prev_hash,
        state_root: [w.height as u8; 32],
        proposer,
        qc: qc_for(signers, w.height, w.block_hash),
    }
}

#[tokio::test]
async fn anchor_with_sets_threads_rotation_while_single_set_fail_closes() {
    let old_keys: Vec<SigningKey> = (0..3).map(|i| test_key(0x11 + i)).collect();
    let new_keys: Vec<SigningKey> = (1..4).map(|i| test_key(0x11 + i)).collect();
    let old_set = ValidatorSet::from_list(
        old_keys
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let new_set = ValidatorSet::from_list(
        new_keys
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    // Rotation between heights 2 and 3: height 2 vouched by the old set,
    // heights 3..4 by the new set.
    let hashes = [[0xA2u8; 32], [0xA3u8; 32], [0xA4u8; 32]];
    let window = window_links(&hashes);
    let links: Vec<HeaderLink> = window
        .iter()
        .map(|w| {
            if w.height <= 2 {
                header_link(w, &old_set, &old_keys)
            } else {
                header_link(w, &new_set, &new_keys)
            }
        })
        .collect();

    let fetch = |links: Vec<HeaderLink>| {
        move |h: u64| {
            let hit = links.iter().find(|l| l.height == h).cloned();
            async move { hit }
        }
    };

    // Per-height sets: the rotation verifies — the F5 threading.
    let old_c = old_set.clone();
    let new_c = new_set.clone();
    let anchor = verify_snapshot_anchor_tail_with_sets(
        4,
        move |h| {
            if h <= 2 {
                Some(old_c.clone())
            } else {
                Some(new_c.clone())
            }
        },
        fetch(links.clone()),
    )
    .await
    .expect("set-at-height must verify a rotated window");
    assert_eq!(anchor.state_root, [4u8; 32]);
    assert_eq!(anchor.boundary_hash, hashes[1]);

    // Single old set: the rotated heights are not its quorum — refused
    // (fail-closed at the proposer-slot gate first: a rotated-in proposer
    // holds no slot in the stale set; either gate is a refusal, never a
    // skip — the pinned property is the refusal itself).
    let err = stellereum::sync::verify_snapshot_anchor_tail(4, &old_set, fetch(links.clone()))
        .await
        .expect_err("single stale set must refuse rotated QCs");
    assert!(
        err.contains("quorum") || err.contains("no schedule slot"),
        "stale-set refusal is fail-closed, got: {err}"
    );
    // Single new set: the pre-rotation height cannot reach a quorum — refused.
    let err = stellereum::sync::verify_snapshot_anchor_tail(4, &new_set, fetch(links))
        .await
        .expect_err("single new set must refuse pre-rotation QCs");
    assert!(
        err.contains("quorum") || err.contains("no schedule slot"),
        "new-set refusal is fail-closed, got: {err}"
    );
}

#[tokio::test]
async fn anchor_with_sets_refuses_an_unresolvable_height() {
    let keys: Vec<SigningKey> = (0..4).map(|i| test_key(0x21 + i)).collect();
    let set = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let hashes = [[0xB2u8; 32], [0xB3u8; 32], [0xB4u8; 32]];
    let window = window_links(&hashes);
    let links: Vec<HeaderLink> =
        window.iter().map(|w| header_link(w, &set, &keys)).collect();

    let err = verify_snapshot_anchor_tail_with_sets(
        4,
        |h| {
            if h == 3 {
                None // history pruned at exactly the wrong height
            } else {
                Some(set.clone())
            }
        },
        {
            let links = links.clone();
            move |h: u64| {
                let hit = links.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        },
    )
    .await
    .expect_err("an unresolvable height is fail-closed");
    assert!(
        err.contains("no validator set resolvable at height 3"),
        "refusal names the height, got: {err}"
    );
}
