//! W10.5 activation-race regression tests (live 2026-10-23 #292785/#292786).
//!
//! Replays the incident shape (powers are multiples of the bond floor F;
//! the live chain used B=1000/C=1500/A=1999 STELL):
//!   * heights H-1 and earlier: validators B (F) + C (F); A is not a member
//!     (as after the pre-incident eject/slash).
//!   * at height H a bond seats A with 2F: the set becomes
//!     A(2F)+B(F)+C(F) = 4F total, quorum floor(8F/3)+1 — A alone (2F) is
//!     below it, the unilateral finalization the incident produced.
//!
//! The three tests pin the three load-bearing rules:
//!   1. `activation_boundary_is_clean_h_plus_one`: every node stages the
//!      change at ledger-height H and switches quorums at the SAME agreed
//!      height H+1 — with identical `validator_set_for_height` answers on
//!      every node. No mid-flight quorum jump, ever.
//!   2. `unilateral_finalization_with_only_the_joiner_power_is_refused`:
//!      a precommit QC carrying only A's power is refused against the set in
//!      force at H+1 (2F < floor(8F/3)+1), both by direct power accounting
//!      and through the adopt path; a quorum QC (A+C) is accepted.
//!   3. `same_block_with_different_qc_subsets_converges`: two nodes apply the
//!      same block (same canonical `last_qc`) but attach different locally
//!      assembled finality QCs ({A,C} vs {A,B,C} — both quorate, as in the
//!      incident) and still commit IDENTICAL post-states, because downtime
//!      is attributed from the proposer-chosen evidence, not the local QC.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const H: u64 = 100;
// Bond floor: MIN_VALIDATOR_BOND (1000 STELL) + buffer (100 STELL). Powers
// below are multiples of the floor so every member is elected; the shape
// mirrors the incident (unilateral joiner power < quorum <= joiner+ally).
fn floor() -> u64 {
    stellereum::staking::required_bond_floor_nano()
}

fn keys() -> (SigningKey, SigningKey, SigningKey) {
    (
        SigningKey::generate(&mut OsRng),
        SigningKey::generate(&mut OsRng),
        SigningKey::generate(&mut OsRng),
    )
}

fn ids_of(ka: &SigningKey, kb: &SigningKey, kc: &SigningKey) -> ([u8; 32], [u8; 32], [u8; 32]) {
    (
        ka.verifying_key().to_bytes(),
        kb.verifying_key().to_bytes(),
        kc.verifying_key().to_bytes(),
    )
}

/// Old set: B(F) + C(F) = 2F, quorum floor(4F/3)+1.
fn old_set(b: [u8; 32], c: [u8; 32]) -> ValidatorSet {
    ValidatorSet::from_list(vec![(b, floor()), (c, floor())])
}

/// Fund + bond B and C on a fresh engine (the pre-join ledger).
async fn engine_with_bc(b: [u8; 32], c: [u8; 32]) -> Arc<InMemoryStateEngine> {
    let e = Arc::new(InMemoryStateEngine::new());
    for (id, amt) in [(b, floor()), (c, floor())] {
        e.credit_native(&id, amt * 2).await.unwrap();
        e.staking_write().await.bond(id, amt, 0).unwrap();
    }
    e
}

fn precommit_qc(
    signers: &[&SigningKey],
    height: u64,
    round: u32,
    block_hash: [u8; 32],
) -> QuorumCertificate {
    let sigs = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, round, VoteKind::Precommit, Some(block_hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: sigs,
    }
}

fn empty_block(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    proposer: [u8; 32],
    last_qc: Option<QuorumCertificate>,
) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer,
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc,
        mmr_epoch_root: [0u8; 32],
        shard_headers: vec![],
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        epoch_key_commitment: [0u8; 32],
    }
}

/// 1. The activation boundary: a join at H takes effect at H+1 on EVERY node.
#[tokio::test]
async fn activation_boundary_is_clean_h_plus_one() {
    let (ka, kb, kc) = keys();
    let (a, b, c) = ids_of(&ka, &kb, &kc);
    // Two nodes, identical ledgers: B + C bonded.
    let e1 = engine_with_bc(b, c).await;
    let e2 = engine_with_bc(b, c).await;
    let old = old_set(b, c);
    assert_eq!(old.quorum_power(), (2 * floor() * 2) / 3 + 1);

    let mut r1 = ValidatorRuntime::new(kb.clone(), old.clone(), e1.clone(), H);
    let mut r2 = ValidatorRuntime::new(kc.clone(), old.clone(), e2.clone(), H);

    // A joins at H with 2F on BOTH ledgers (same chain prefix).
    for e in [&e1, &e2] {
        e.credit_native(&a, 8 * floor()).await.unwrap();
        e.staking_write().await.bond(a, 2 * floor(), 0).unwrap();
    }

    // Both nodes refresh at the same ledger height: the change is STAGED for
    // H+1, never installed mid-flight.
    assert!(r1.refresh_validator_set_from_staking().await);
    assert!(r2.refresh_validator_set_from_staking().await);
    for r in [&r1, &r2] {
        assert_eq!(
            r.validators.validators, old.validators,
            "the in-force set must not jump mid-flight"
        );
        assert_eq!(
            r.pending_validators.as_ref().map(|(a, _)| *a),
            Some(H + 1),
            "the change activates at the next height boundary"
        );
        // ... and the height-pinned answers agree on both nodes:
        assert_eq!(r.validator_set_for_height(H).validators, old.validators);
        let new = r.validator_set_for_height(H + 1);
        assert_eq!(new.total_power(), 4 * floor());
        assert_eq!(new.quorum_power(), (4 * floor() * 2) / 3 + 1);
        assert_eq!(new.power_of(&a), 2 * floor());
    }
    assert_eq!(
        r1.validator_set_for_height(H + 1).validators,
        r2.validator_set_for_height(H + 1).validators,
        "all nodes must agree on the quorum for H+1"
    );

    // Across the boundary both nodes install the identical set.
    r1.hc.height += 1;
    r1.install_due_validator_set();
    r1.hc.validators = r1.validators.clone();
    r2.hc.height += 1;
    r2.install_due_validator_set();
    r2.hc.validators = r2.validators.clone();
    assert_eq!(r1.validators.validators, r2.validators.validators);
    assert_eq!(r1.validators.total_power(), 4 * floor());
}

/// 2. Unilateral finalization with only the joiner's power is REFUSED at H+1.
#[tokio::test]
async fn unilateral_finalization_with_only_the_joiner_power_is_refused() {
    let (ka, kb, kc) = keys();
    let (a, b, c) = ids_of(&ka, &kb, &kc);
    let e = engine_with_bc(b, c).await;
    let old = old_set(b, c);

    // Node B at height H with the old set in force.
    let mut r = ValidatorRuntime::new(kb.clone(), old.clone(), e.clone(), H);

    // A joins at H; the boundary passes; the new set is in force at H+1.
    e.credit_native(&a, 8 * floor()).await.unwrap();
    e.staking_write().await.bond(a, 2 * floor(), 0).unwrap();
    assert!(r.refresh_validator_set_from_staking().await);
    r.hc.height += 1;
    r.install_due_validator_set();
    r.hc.validators = r.validators.clone();
    let in_force = r.validator_set_for_height(H + 1);
    assert_eq!(in_force.total_power(), 4 * floor());
    assert_eq!(in_force.quorum_power(), (4 * floor() * 2) / 3 + 1);

    // The unilateral QC: only A's precommit for a candidate block at H+1.
    let bh = [0x42u8; 32];
    let weak = precommit_qc(&[&ka], H + 1, 0, bh);
    let signed = in_force.qc_signed_power(&weak);
    assert_eq!(signed, 2 * floor(), "only the joiner's power is behind it");
    assert!(
        signed < in_force.quorum_power(),
        "the joiner alone must not reach quorum"
    );
    assert!(
        !in_force.qc_meets_quorum(&weak),
        "a unilateral finalization must never verify"
    );
    // ... and it is refused under the OLD set too (A is not a member there).
    assert!(!old.qc_meets_quorum(&weak));

    // The adopt path refuses it loudly (never finalize, never apply).
    // Parent linkage: the runtime has finalized height H (empty body parent),
    // so the candidate must chain to it with a compatible timestamp.
    let proposer = in_force
        .proposer_for(H + 1, 0)
        .expect("non-empty set schedules");
    let proposer_key = [&ka, &kb, &kc]
        .into_iter()
        .find(|k| k.verifying_key().to_bytes() == proposer)
        .expect("proposer is one of ours");
    let root = e.get_state_root().await;
    let parent = empty_block(H, [0u8; 32], root, proposer, None);
    let parent_hash = parent.compute_hash();
    let parent_qc = precommit_qc(&[&kb, &kc], H, 0, parent_hash);
    r.blocks.insert(parent_hash, parent.clone());
    r.finalized.push((H, parent_hash));
    r.last_decision = Some((H, parent.clone(), parent_qc.clone()));
    // A real proposer embeds the parent QC as canonical downtime evidence.
    let mut blk = empty_block(H + 1, parent_hash, root, proposer, Some(parent_qc.clone()));
    blk.timestamp = parent.timestamp + 1;
    blk.sign_block(proposer_key);
    let bh = blk.compute_hash();
    let weak = precommit_qc(&[&ka], H + 1, 0, bh);
    let err = r
        .adopt_committed(H + 1, blk, weak)
        .await
        .expect_err("unilateral QC must be refused");
    assert!(
        err.contains("quorum"),
        "refusal must name the quorum shortfall, got: {err}"
    );
    assert_eq!(
        r.hc.height,
        H + 1,
        "a refused adopt must not advance the height"
    );

    // The quorate QC (A+C = 3F >= floor(8F/3)+1) IS accepted on the same path.
    let mut blk = empty_block(H + 1, parent_hash, root, proposer, Some(parent_qc));
    blk.timestamp = parent.timestamp + 1;
    blk.sign_block(proposer_key);
    let bh = blk.compute_hash();
    let strong = precommit_qc(&[&ka, &kc], H + 1, 0, bh);
    assert!(in_force.qc_meets_quorum(&strong));
    let decided = r.adopt_committed(H + 1, blk, strong).await;
    assert!(decided.is_ok(), "a quorate QC must adopt: {decided:?}");
    assert_eq!(r.hc.height, H + 2);
    assert_eq!(r.last_decision.as_ref().map(|(h, _, _)| *h), Some(H + 1));
}

/// 3. Same block, different locally-assembled QC subsets -> identical roots.
///
/// Node X finalizes with {A,C} (B's precommit arrived late); node Y with
/// {A,B,C}. Both are quorate under the same set. Pre-W10.5 the transition
/// attributed downtime from the attached subset and the two nodes committed
/// different `missed` counters — a permanent state fork. Now the evidence is
/// the single proposer-chosen `last_qc` both blocks carry, so both converge.
#[tokio::test]
async fn same_block_with_different_qc_subsets_converges() {
    let (ka, kb, kc) = keys();
    let (a, b, c) = ids_of(&ka, &kb, &kc);
    let e1 = engine_with_bc(b, c).await;
    let e2 = engine_with_bc(b, c).await;
    // A is a full member here (the post-join set, as at the incident height).
    for e in [&e1, &e2] {
        e.credit_native(&a, 8 * floor()).await.unwrap();
        e.staking_write().await.bond(a, 2 * floor(), 0).unwrap();
    }

    // Height 1 (genesis child, no evidence) applied identically on both.
    let g1 = e1.get_state_root().await;
    assert_eq!(g1, e2.get_state_root().await);
    let proposer = [0x99u8; 32];
    let b1 = empty_block(1, [0u8; 32], g1, proposer, None);
    let bh1 = b1.compute_hash();
    e1.apply_block_transition(&b1, 0).await;
    e2.apply_block_transition(&b1, 0).await;
    let r1 = e1.get_state_root().await;
    assert_eq!(r1, e2.get_state_root().await, "genesis children must agree");

    // The canonical evidence for height 1: the subset QC {A,C} the proposer saw.
    let evidence = precommit_qc(&[&ka, &kc], 1, 0, bh1);
    // Node X attaches {A,C}; node Y attaches the fuller {A,B,C}. Same block
    // hash either way (the finality QC is excluded from the hash; the
    // canonical evidence is included and identical).
    let mut bx = empty_block(2, bh1, r1, proposer, Some(evidence.clone()));
    bx.precommit_qc = Some(evidence.clone());
    let mut by = empty_block(2, bh1, r1, proposer, Some(evidence.clone()));
    by.precommit_qc = Some(precommit_qc(&[&ka, &kb, &kc], 1, 0, bh1));
    assert_eq!(
        bx.compute_hash(),
        by.compute_hash(),
        "the same evidence must mean the same block"
    );

    e1.apply_block_transition(&bx, 0).await;
    e2.apply_block_transition(&by, 0).await;
    assert_eq!(
        e1.get_state_root().await,
        e2.get_state_root().await,
        "different finality-QC subsets must not fork the state"
    );
    // ... and the attribution is the canonical one: B missed height 1 on BOTH
    // engines (it is absent from the {A,C} evidence), not just on X's.
    for e in [&e1, &e2] {
        let ledger = e.staking_read().await;
        assert_eq!(ledger.validators.get(&b).map(|v| v.missed), Some(1));
        assert_eq!(ledger.validators.get(&a).map(|v| v.missed), Some(0));
        assert_eq!(ledger.validators.get(&c).map(|v| v.missed), Some(0));
    }
}
