//! RCA pin for the 2026-11-24 halt at height 253 120 (`OPEN_DEFECTS.md`,
//! P0-DOWNTIME-EVIDENCE-HALT).
//!
//! # What the live incident looked like
//!
//! Every node restarted at the finalized tip saw a set of **4 members with
//! power 1 each** and `quorum = 3`, while the tip's embedded precommit-QC
//! attributed **0 of those 3 required power**. `restore_last_decision_from_
//! finalized_block` therefore armed `parent_evidence_missing` on every member
//! and no node would propose: a self-sustaining halt that lasted ~8 hours.
//!
//! # What this file proves (and what it deliberately does NOT claim)
//!
//! The power-1 set is NOT a `to_validator_set()` output. `StakingLedger::
//! to_validator_set` (`staking.rs:2682-2697`) returns `self_bond + delegated`
//! verbatim: no division, no GCD scaling, no `max(1, …)` clamp. With the
//! frozen `MIN_VALIDATOR_BOND = 1_000 * 1e9`, every elected validator carries
//! `>= 1e12` power, and the live journal confirms it
//! (`[48fd69d1:2000000000000, …]`).
//!
//! The power-1 set is the **config-defined bootstrap set**:
//! `node::bootstrap::build_validator_set` adds exactly one unit of power per
//! configured validator (`bootstrap.rs:660-665`), i.e. 4 x 1 for the 4-node
//! `validators:` list. On restart the runtime starts with that set and only
//! then stages the ledger-derived set at `ledger_height + 1`
//! (`validator_set_adoption_height`, `sharding/topology.rs:376-378`).
//! `ValidatorRuntime::validator_set_for_height(H)` then resolves the
//! finalized tip's own height `H` to the `(0, config_set)` history entry
//! (`runtime/consensus_step.rs:2577-2581` and `:2683-2710`), never to the set
//! that actually signed `H`.
//!
//! A certificate produced under the bonded set cannot be attributed under the
//! config set: the µQC carries `committee_size = micro_committee_size(real_n)`
//! and `signers_set_with_beacon_inner` rejects a certificate whose committee
//! size does not match the verifying set (`consensus/types.rs:2560-2566`),
//! naming nobody -> `0` signed power. With the config set's total power of 4
//! the required power is `floor(2*4/3)+1 = 3`: exactly the live
//! `0 of 3 required power` message.
//!
//! Tests 1 and 2 pass today and pin the mechanism; test 3 is the fail-before
//! reproduction of the halt condition (validator-set history is in-memory, so
//! a restart cannot answer for the tip's own height).

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    derive_sortition_committee, encode_pq_micro_envelope, micro_committee_size,
    register_validator_pq_key, vote_sign_bytes, CommitteeSchedule, PqMicroCertificate,
    QuorumCertificate, ValidatorSet, VoteKind, PQ_UQC_MARKER_ID,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::runtime::ValidatorRuntime;
use stellereum::staking::required_bond_floor_nano;
use stellereum::state_engine::InMemoryStateEngine;

/// The live finalized height (OPEN_DEFECTS P0-DOWNTIME-EVIDENCE-HALT).
const TIP: u64 = 253_120;
/// The height a node restarts at after finalizing `TIP`.
const PROPOSE: u64 = TIP + 1;

/// One bond at the documented admission floor (MIN + buffer = 1 100 STELL),
/// the smallest bond a NEW validator can create.
fn bond() -> u64 {
    required_bond_floor_nano()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Falcon half for an Ed key, registered under the Ed validator id exactly
/// like the production FULL-PQ wiring (see `tests/w10_5_activation_race.rs`).
fn fk_for(k: &SigningKey) -> FalconKeypair {
    let fk = FalconKeypair::generate_from_seed(k.to_bytes()[0]);
    register_validator_pq_key(
        k.verifying_key().to_bytes(),
        PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    fk
}

/// The set `build_validator_set` produces from a 4-entry `validators:` list:
/// one unit of voting power per configured validator (`bootstrap.rs:660-665`).
fn config_set(ids: &[[u8; 32]]) -> ValidatorSet {
    ValidatorSet::from_list(ids.iter().map(|id| (*id, 1)).collect())
}

/// A production-shaped µQC (Falcon-512 envelope + `PQ_UQC_MARKER_ID`) over
/// `block_hash` for `height`/`round`, with the committee re-derived from the
/// set the producer was voting under.
fn precommit_qc(
    producer_set: &ValidatorSet,
    signers: &[&SigningKey],
    height: u64,
    round: u32,
    block_hash: [u8; 32],
    parent: &[u8; 32],
) -> QuorumCertificate {
    let k = micro_committee_size(producer_set.len());
    let committee = derive_sortition_committee(producer_set, height, round, k, parent);
    let msg = vote_sign_bytes(height, round, VoteKind::Precommit, &Some(block_hash));
    let mut bitmask = vec![0u8; (k as usize).div_ceil(8)];
    let mut signatures = Vec::new();
    for (i, id) in committee.iter().enumerate() {
        let Some(sk) = signers.iter().find(|s| s.verifying_key().to_bytes() == *id) else {
            continue;
        };
        bitmask[i / 8] |= 1 << (i % 8);
        signatures.push(fk_for(sk).sign(&msg));
    }
    let uqc = PqMicroCertificate::new(
        PqScheme::Falcon512,
        height,
        round,
        k,
        bitmask,
        signatures,
        *parent,
    );
    QuorumCertificate {
        shard_id: 0,
        height,
        round,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
    }
}

/// Bond `members` with real stake on a fresh engine (the ledger a restored
/// node loads from its newest domain snapshot).
async fn engine_with_bonded(members: &[(&SigningKey, u64)]) -> Arc<InMemoryStateEngine> {
    let e = Arc::new(InMemoryStateEngine::new());
    for (k, amount) in members {
        let id = k.verifying_key().to_bytes();
        e.credit_native(&id, amount.saturating_mul(2))
            .await
            .unwrap();
        e.staking_write().await.bond(id, *amount, 0).unwrap();
    }
    e
}

/// 1. The staking derivation itself cannot collapse to power 1.
///
/// Guards against the originally suspected root cause (a `stake / total * N`
/// or GCD normalization collapsing every member to 1, a double/missing
/// `1e9` scaling, or a `max(1, …)` clamp after a lossy division).
#[tokio::test]
async fn bonded_stakes_derive_proportional_power_and_never_collapse_to_one() {
    let keys: Vec<SigningKey> = (1..=4).map(key).collect();
    let members: Vec<(&SigningKey, u64)> = keys.iter().map(|k| (k, bond())).collect();
    let e = engine_with_bonded(&members).await;

    let ledger = e.staking_read().await;
    let vs = ledger.to_validator_set();

    assert_eq!(vs.len(), 4, "four bonded validators must all be elected");
    for k in &keys {
        assert_eq!(
            vs.power_of(&k.verifying_key().to_bytes()),
            bond(),
            "power must be the bonded stake verbatim, not a normalized/clamped value"
        );
    }
    assert_eq!(vs.total_power(), 4 * bond());
    assert!(
        vs.total_power() > 4,
        "a 4-member bonded set must not collapse to the config set's total power of 4"
    );
    assert!(
        vs.quorum_power() > 1,
        "quorum over real bond must never be 1"
    );

    // The power-1/quorum-3 arithmetic belongs ONLY to the config bootstrap
    // set, which is what the live journal printed at every boot
    // (`Consensus: 4 validator(s), quorum power 3`).
    let config = config_set(
        &keys
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect::<Vec<_>>(),
    );
    assert_eq!(config.total_power(), 4);
    assert_eq!(config.quorum_power(), 3);
}

/// 2. The observed `0 of 3 required power` symptom, reproduced exactly.
///
/// The tip-QC was produced under a bonded set whose MEMBER COUNT differed
/// from the 4-member config set (the journal shows the live set stepping
/// down 4 -> 3 -> 2 as members were jailed; the exact count at 253 120 is
/// not recoverable from the retained journal, but ANY count != 4 reproduces
/// the message). The node verifying it resolved the height to the 4-member
/// config set (power 1 each, quorum 3), and attribution is fail-closed on
/// the committee-size mismatch, so it names nobody: 0 of 3.
#[test]
fn power_one_config_set_attributes_zero_of_three_for_a_bonded_set_qc() {
    let keys: Vec<SigningKey> = (1..=4).map(key).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let config = config_set(&ids);

    // Real set at the tip: 3 bonded members (the fourth jailed/absent).
    let bonded =
        ValidatorSet::from_list(ids[..3].iter().map(|id| (*id, bond())).collect::<Vec<_>>());
    assert_eq!(config.len(), 4);
    assert_ne!(
        bonded.len(),
        config.len(),
        "the mechanism under test is the member-count mismatch"
    );

    let parent = [0x11u8; 32];
    let block_hash = [0x22u8; 32];
    let signer_refs: Vec<&SigningKey> = keys[..3].iter().collect();
    let qc = precommit_qc(&bonded, &signer_refs, TIP, 0, block_hash, &parent);

    // The certificate is a genuine quorum under the set that produced it.
    assert!(
        bonded.qc_meets_quorum(&qc),
        "the tip QC must be a real quorum under the bonded set"
    );

    // Under the boot config set the same certificate names nobody:
    // `committee_size` (3) != `micro_committee_size(config.len())` (4) ->
    // `micro_cert_valid_signers_and_committee_with_beacon` returns None.
    let signed = config.qc_signed_power_with_schedule(&qc, CommitteeSchedule::ParentHash);
    assert_eq!(
        signed, 0,
        "attribution under the power-1 config set must be empty (the live '0 of N')"
    );
    assert_eq!(
        config.quorum_power(),
        3,
        "4 members at power 1 require 3: the live '0 of 3 required power'"
    );
    assert!(
        !config.qc_meets_quorum(&qc),
        "the halt verdict: 0 < 3, so restore_last_decision fails closed"
    );
}

/// 3. FAIL-BEFORE: a restart at the finalized tip must still be able to
/// attribute the tip's own QC.
///
/// Shape of the live boot: the runtime is constructed with the config set at
/// the height it will propose at (`TIP + 1`), the restored ledger yields the
/// bonded set, and `refresh_validator_set_from_staking_checked(TIP, TIP)`
/// installs it with activation `TIP + 1`. `validator_set_for_height(TIP)`
/// therefore resolves to the `(0, config_set)` entry -> power 1 each,
/// quorum 3 -> the tip QC scores 0.
///
/// The intended invariant is that the set resolved for a height the node has
/// ALREADY finalized must be able to verify that height's decision proof.
/// Today the validator-set history is in-memory only, so it cannot.
#[ignore = "OPEN (RCA 2026-11-24): validator-set history is not persisted across \
            restart; the finalized tip's height resolves to the boot config set \
            (4 x power 1, quorum 3) and the tip's real QC attributes 0. Fix is a \
            persistent/derived set-history restore, out of scope for this wave."]
#[tokio::test]
async fn restart_at_the_finalized_tip_must_attribute_the_tip_qc() {
    let keys: Vec<SigningKey> = (1..=4).map(key).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();

    // Restored staking ledger: 3 bonded members at the tip (the 4th jailed).
    let members: Vec<(&SigningKey, u64)> = keys[..3].iter().map(|k| (k, bond())).collect();
    let e = engine_with_bonded(&members).await;

    // The QC the finalized tip carries, produced under the bonded set.
    let bonded =
        ValidatorSet::from_list(ids[..3].iter().map(|id| (*id, bond())).collect::<Vec<_>>());
    let qc = precommit_qc(
        &bonded,
        &keys[..3].iter().collect::<Vec<_>>(),
        TIP,
        0,
        [0x22u8; 32],
        &[0x11u8; 32],
    );
    assert!(bonded.qc_meets_quorum(&qc));

    // Boot at the height after the tip, exactly like the live restart.
    let mut rt = ValidatorRuntime::new(keys[0].clone(), config_set(&ids), e.clone(), PROPOSE);
    rt.finalized.push((TIP, [0x22u8; 32]));

    // Restore path: newest domain snapshot == the finalized tip's height.
    assert!(
        rt.refresh_validator_set_from_staking_checked(TIP, TIP)
            .await,
        "the ledger-derived set must be installed"
    );
    assert!(
        rt.validators.total_power() > 4,
        "the in-force set for the NEXT height is the bonded set"
    );

    // The set resolved for the tip's OWN height must still verify its QC.
    let resolved = rt.validator_set_for_height(TIP);
    assert!(
        resolved.qc_meets_quorum(&qc),
        "the finalized tip's own decision proof must remain verifiable after a \
         restart: resolved total power {} (quorum {}), signed 0. The history \
         entry for the tip is the boot config set, not the bonded set that \
         signed it.",
        resolved.total_power(),
        resolved.quorum_power()
    );
}
