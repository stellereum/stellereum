//! HUNT: slashing verdicts are computed from LOCAL gossip, not from the block.
//!
//! Targets:
//!   src/runtime.rs:162-172   apply_equivocation_slashes (evidence = self.hc.equivocations())
//!   src/runtime.rs:610-636   apply_downtime_slashes    (signers = self.hc.precommit_qc.signatures)
//!   src/staking.rs:451-487   note_missed_heights
//!   src/staking.rs:420-434   slash_equivocation
//!
//! src/runtime.rs:605-609 asserts:
//!     "The evidence is the certificate itself, so every node reaches the same
//!      verdict. A local timeout would be neither sound nor deterministic."
//!
//! That is true only for a node that ran the round itself. The certificate is
//! ASSEMBLED FROM WHATEVER VOTES THE NODE HAPPENED TO RECEIVE, and pubsub is
//! explicitly best-effort (src/main.rs:573-579). Two nodes that reached the same
//! quorum therefore hold different certificates, compute different `missed`
//! counters, and -- because `missed` is in the commitment digest
//! (src/commitment.rs:239) -- different STATE ROOTS for the same chain.
//!
//! The attacker chooses the split by choosing gossip delivery.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{ValidatorId, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::Block;
use stellereum::staking::{StakingLedger, MIN_VALIDATOR_BOND};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const N: usize = 4;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}
fn ids(ks: &[SigningKey]) -> Vec<ValidatorId> {
    ks.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

async fn cluster(ks: &[SigningKey], payer: ValidatorId) -> Vec<ValidatorRuntime> {
    let vs = vset(ks);
    let bal = 10_000 * MIN_VALIDATOR_BOND;
    let mut out = Vec::new();
    for k in ks {
        let st = Arc::new(InMemoryStateEngine::new());
        stellereum::runtime::fund_genesis(&st, &vs, bal).await;
        st.update_account(AccountState::new(payer, bal)).await;
        out.push(ValidatorRuntime::new(k.clone(), vs.clone(), st, 1));
    }
    out
}

fn mkblock(k: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: k.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(k);
    b
}

// ===========================================================================
// FINDING 10 (CRITICAL): the downtime verdict depends on gossip, not the block
// ===========================================================================

#[tokio::test]
async fn hunt_finding_10_downtime_verdict_depends_on_which_votes_arrived() {
    let ks = keys(N);
    let idv = ids(&ks);
    let payer = idv[0];
    let mut nodes = cluster(&ks, payer).await;
    let root = nodes[0].state.get_state_root().await;
    // Real block hash (same integrity rule as finding 11 below).
    let blk = mkblock(&ks[0], 1, [0u8; 32], root);
    let bh = blk.compute_hash();

    // Both nodes see a GENUINE quorum for the same block, and both decide it.
    // Node 0 ALSO receives the 4th validator's precommit; node 1 does not. pubsub
    // is best-effort, so this is an ordinary dropped message, not a Byzantine act.
    // A block may only be decided on a prevote quorum for the SAME block, so the
    // prevotes come first. Both nodes prevote the same block, then precommit.
    for k in ks.iter().take(3) {
        nodes[0]
            .on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        nodes[1]
            .on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    for k in ks.iter().take(3) {
        nodes[0]
            .on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
        nodes[1]
            .on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    nodes[0]
        .on_precommit(Vote::sign(&ks[3], 1, 0, VoteKind::Precommit, Some(bh)))
        .unwrap();
    assert_eq!(nodes[0].hc.try_precommit_quorum(), Some(bh));
    assert_eq!(nodes[1].hc.try_precommit_quorum(), Some(bh));
    nodes[0].blocks.insert(bh, blk.clone());
    nodes[1].blocks.insert(bh, blk.clone());

    let cert_a = nodes[0].hc.precommit_qc.clone().unwrap();
    let cert_b = nodes[1].hc.precommit_qc.clone().unwrap();
    println!(
        "[FINDING 10] node 0 certificate: {} signatures; node 1 certificate: {} signatures",
        cert_a.signatures.len(),
        cert_b.signatures.len()
    );
    println!(
        "[FINDING 10] both certificates are genuine: {} / {}",
        cert_a.verify(&nodes[0].validators),
        cert_b.verify(&nodes[1].validators)
    );
    assert!(cert_a.verify(&nodes[0].validators) && cert_b.verify(&nodes[1].validators));
    assert_ne!(
        cert_a.signatures.len(),
        cert_b.signatures.len(),
        "the certificates differ"
    );

    nodes[0].apply_downtime_slashes().await;
    nodes[1].apply_downtime_slashes().await;

    let silent = idv[3];
    let m0 = nodes[0].state.staking_read().await.validators[&silent].missed;
    let m1 = nodes[1].state.staking_read().await.validators[&silent].missed;
    let r0 = nodes[0].state.get_state_root().await;
    let r1 = nodes[1].state.get_state_root().await;
    println!("[FINDING 10] silent validator missed: node0={m0}  node1={m1}");
    assert_eq!(m0, 0, "node 0 saw the 4th precommit and forgave it");
    assert_eq!(m1, 1, "node 1 never heard it and counted a miss");
    assert_ne!(
        r0, r1,
        "SPLIT: same block, same quorum, different state root"
    );
    println!(
        "[FINDING 10] SPLIT CONFIRMED: {} != {}",
        hex::encode(&r0[..8]),
        hex::encode(&r1[..8])
    );
}

// ===========================================================================
// FINDING 11 (CRITICAL, FIXED — audit F4): a double-voter used to pick, per
// node, whether it got slashed because the verdict was driven by local gossip.
// Equivocation slashing is now deferred from all state transitions.
// ===========================================================================

#[tokio::test]
async fn hunt_finding_11_equivocation_is_no_longer_node_local_in_the_transition() {
    let ks = keys(N);
    let idv = ids(&ks);
    let payer = idv[0];
    let mut nodes = cluster(&ks, payer).await;
    let root = nodes[0].state.get_state_root().await;
    // Real block hash (audit 2026-10-06: finalize re-checks that the stored
    // body hashes to the decided hash; a fake key is refused like a
    // corrupted store on a live node).
    let blk = mkblock(&ks[0], 1, [0u8; 32], root);
    let bh = blk.compute_hash();
    let dyvader = ks[3].clone(); // the double-voting validator
    let dvid = dyvader.verifying_key().to_bytes();

    // The honest three prevote, then precommit, the decided block. A block is
    // only decided on a prevote quorum for the same block, so both are needed.
    for n in nodes.iter_mut() {
        for k in ks.iter().take(3) {
            n.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
                .unwrap();
        }
    }
    for n in nodes.iter_mut() {
        for k in ks.iter().take(3) {
            n.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
                .unwrap();
        }
    }
    assert_eq!(nodes[0].hc.try_precommit_quorum(), Some(bh));
    assert_eq!(nodes[1].hc.try_precommit_quorum(), Some(bh));
    nodes[0].blocks.insert(bh, blk.clone());
    nodes[1].blocks.insert(bh, blk.clone());

    // The double-voter sends its FIRST prevote to everyone...
    let v1 = Vote::sign(&dyvader, 1, 0, VoteKind::Prevote, Some(bh));
    // ...and its CONFLICTING second prevote to node 0 only. The attacker picks
    // which node forms the evidence; the block never carries it.
    let v2 = Vote::sign(&dyvader, 1, 0, VoteKind::Prevote, Some([0x99u8; 32]));
    nodes[0].on_prevote(v1.clone()).unwrap();
    nodes[1].on_prevote(v1.clone()).unwrap();
    nodes[0].on_prevote(v2.clone()).unwrap();

    // F4 FIX: node 0 still OBSERVES the double-vote, but the state transition no
    // longer consumes local observations, so the extra gossiped vote cannot move
    // state. Finalize the same height on both and require IDENTICAL roots.
    assert_eq!(
        nodes[0].hc.equivocations().len(),
        1,
        "node 0 must hold the double-vote evidence, or this test is vacuous"
    );
    assert!(
        nodes[1].hc.equivocations().is_empty(),
        "node 1 never saw the conflicting vote"
    );
    let burn0_before = nodes[0].state.staking_read().await.total_burned;
    let burn1_before = nodes[1].state.staking_read().await.total_burned;
    assert_eq!(nodes[0].try_finalize().await, Some(bh));
    assert_eq!(nodes[1].try_finalize().await, Some(bh));
    let burn0 = nodes[0].state.staking_read().await.total_burned - burn0_before;
    let burn1 = nodes[1].state.staking_read().await.total_burned - burn1_before;
    let s0 = nodes[0].state.staking_read().await.validators[&dvid].self_bond;
    let s1 = nodes[1].state.staking_read().await.validators[&dvid].self_bond;
    let r0 = nodes[0].state.get_state_root().await;
    let r1 = nodes[1].state.get_state_root().await;
    println!("[FINDING 11 FIXED] burn: node0={burn0}  node1={burn1}");
    println!("[FINDING 11 FIXED] double-voter self_bond: node0={s0}  node1={s1}");
    assert_eq!(burn0, 0, "F4 FIX: local evidence must not slash");
    assert_eq!(burn1, 0, "F4 FIX: local evidence must not slash");
    assert_eq!(
        s0, s1,
        "F4 FIX: the two nodes agree about the validator's stake"
    );
    assert_eq!(
        r0, r1,
        "F4 FIX: same block => same root, regardless of gossip"
    );
    println!("[FINDING 11 FIXED] ROOTS AGREE: {}", hex::encode(&r0[..8]));
    println!("[FINDING 11 FIXED] a Byzantine double-voter can no longer split the network by choosing gossip.");
}

#[tokio::test]
async fn hunt_finding_11b_equivocation_evidence_is_never_in_the_block() {
    // The certificate broadcast on the wire (ConsensusMsg::Committed) carries
    // only the PRECOMMIT quorum. The equivocation evidence is local to whichever
    // node happened to observe both conflicting votes, and is never gossiped.
    let ks = keys(2);
    let vs = vset(&ks);
    let mut hc = stellereum::consensus::HeightConsensus::new(1, vs);
    let a = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let b = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([2u8; 32]));
    hc.add_prevote(a).unwrap();
    hc.add_prevote(b).unwrap();
    let ev = hc.equivocations();
    println!(
        "[FINDING 11b] local equivocation evidence: {} entries",
        ev.len()
    );
    assert_eq!(ev.len(), 1);
    // The evidence exists only in this process's memory. There is no field on
    // Block (src/sharding.rs:454-464) or QuorumCertificate (src/consensus.rs:292-298)
    // that could carry it, so no peer can ever be shown the proof.
    let cert_fields = std::mem::size_of::<stellereum::consensus::QuorumCertificate>();
    println!("[FINDING 11b] QuorumCertificate has no evidence field (size {cert_fields} bytes, fields: height/round/kind/block_hash/signatures)");
    println!("[FINDING 11b] => slashing for double-vote is NOT consensus-deterministic.");
}

// ===========================================================================
// FINDING 12 (MEDIUM): slash_equivocation verifies nothing about the evidence
// ===========================================================================

#[test]
fn hunt_finding_12_slash_equivocation_trusts_the_caller_supplied_tuple() {
    let mut l = StakingLedger::new();
    let a_key = SigningKey::generate(&mut OsRng);
    let b_key = SigningKey::generate(&mut OsRng);
    let aid = a_key.verifying_key().to_bytes();
    let bid = b_key.verifying_key().to_bytes();
    l.bond(aid, 10 * MIN_VALIDATOR_BOND, 0).unwrap();
    l.bond(bid, 10 * MIN_VALIDATOR_BOND, 0).unwrap();

    // Two votes by TWO DIFFERENT validators. A never equivocated.
    let va = Vote::sign(&a_key, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let vb = Vote::sign(&b_key, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
    assert!(va.verify() && vb.verify());
    assert_ne!(va.voter, vb.voter);
    let before = l.total_stake(&aid);

    // `slash_equivocation` checks only height/round/kind equality and differing
    // block_hash (src/staking.rs:427-432). It never checks
    //   va.voter == vb.voter == `voter`, nor that either signature verifies.
    let burned = l
        .slash_equivocation(&(aid, va.clone(), vb.clone()))
        .unwrap();
    println!(
        "[FINDING 12] burned {burned} from validator {} for a vote it never cast",
        hex::encode(&aid[..6])
    );
    println!(
        "[FINDING 12] A's stake: {before} -> {}",
        l.total_stake(&aid)
    );
    assert!(burned > 0, "A was slashed for B's vote");
    assert!(l.total_stake(&aid) < before);
    // And with two UNSIGNED votes entirely:
    let mut l2 = StakingLedger::new();
    l2.bond(aid, 10 * MIN_VALIDATOR_BOND, 0).unwrap();
    let mut fake_a = va.clone();
    fake_a.signature = vec![0u8; 64];
    let mut fake_b = vb.clone();
    fake_b.signature = vec![0u8; 64];
    let b2 = l2.slash_equivocation(&(aid, fake_a, fake_b)).unwrap();
    println!("[FINDING 12] burned {b2} from two votes whose signatures are 64 zero bytes");
    assert!(b2 > 0, "unsigned 'evidence' burns stake");
    println!("[FINDING 12] The only in-tree caller (runtime.rs:167) is safe; this is a public-API footgun.");
}

// ===========================================================================
// FINDING 13 (HIGH): prevote/precommit divergence is never detected
// ===========================================================================

#[test]
fn hunt_finding_13_prevote_precommit_divergence_escapes_all_slashing() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = stellereum::consensus::HeightConsensus::new(1, vs.clone());
    let id = ks[0].verifying_key().to_bytes();

    // Same height, same round, two DIFFERENT values, two different kinds.
    let pv = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([0xAAu8; 32]));
    let pc = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some([0xBBu8; 32]));
    hc.add_prevote(pv.clone()).unwrap();
    hc.add_precommit(pc.clone()).unwrap();
    assert_eq!(
        hc.equivocations().len(),
        0,
        "NO evidence recorded for prevote/precommit split"
    );
    println!(
        "[FINDING 13] prevote(0xAA..) + precommit(0xBB..) at h=1 r=0 -> {} equivocation records",
        hc.equivocations().len()
    );

    // And the ledger agrees it is not equivocation, because `kind` differs.
    let mut l = StakingLedger::new();
    l.bond(id, 10 * MIN_VALIDATOR_BOND, 0).unwrap();
    let burned = l.slash_equivocation(&(id, pv, pc)).unwrap();
    println!("[FINDING 13] slash_equivocation on that pair burns {burned}");
    assert_eq!(burned, 0, "nothing is punished");
    println!("[FINDING 13] => a validator can prevote A and precommit B with ZERO penalty.");
    println!("[FINDING 13]    Combined: this is a liveness weapon that escapes the entire slashing system.");
}

// ===========================================================================
// FINDING 14 (HIGH): a whale bond invalidates every in-flight certificate
// ===========================================================================

#[tokio::test]
async fn hunt_finding_14_a_single_bond_makes_every_prior_certificate_fail() {
    let ks = keys(N);
    let real_ids = ids(&ks);
    let before = vset(&ks);
    let bh = [0x55u8; 32];

    let mk = |signers: &[usize]| stellereum::consensus::QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: signers
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    };
    let cert = mk(&[0, 1, 2]);
    assert!(cert.verify(&before), "3 of 4 is a quorum before the bond");
    println!(
        "[FINDING 14] before: total={} quorum={}",
        before.total_power(),
        before.quorum_power()
    );

    // A whale bonds and refresh_validator_set_from_staking pulls it in.
    let mut after = before.clone();
    after.add([0xEEu8; 32], 1_000 * MIN_VALIDATOR_BOND);
    println!(
        "[FINDING 14] after a 1000-STELL bond: total={} quorum={}",
        after.total_power(),
        after.quorum_power()
    );
    assert!(
        !cert.verify(&after),
        "the SAME certificate no longer verifies"
    );
    println!("[FINDING 14] cert.verify(after) = {}", cert.verify(&after));
    assert!(!cert.verify(&after));

    // And a validator that UNBONDS loses its power retroactively, so the
    // certificate it already signed stops counting on the next height.
    let mut shrunk = before.clone();
    shrunk.validators.remove(&real_ids[0]);
    assert!(
        !cert.verify(&shrunk),
        "unbonding one signer invalidates the certificate"
    );
    println!(
        "[FINDING 14] after unbonding signer 0: cert.verify = {}",
        cert.verify(&shrunk)
    );
    assert!(!cert.verify(&shrunk));
    println!("[FINDING 14] => quorum is scored with the power at VERIFY time, not at VOTE time.");
    println!("[FINDING 14]    Certificates are not stable across a validator-set change, so");
    println!("[FINDING 14]    adopt_committed/sync can be frozen by one well-funded bond.");

    // The block-sync path cannot even be reached: main.rs:220 refuses outright
    // when quorum_power() == u64::MAX (the empty-set guard).
    let empty = ValidatorSet::new();
    assert_eq!(empty.quorum_power(), u64::MAX);
    println!("[FINDING 14] empty set quorum_power() = u64::MAX (main.rs:220 refuses to sync)");
    // The guard is on `total == 0` only. A set whose total is nonzero but whose
    // quorum is unreachable in practice is NOT caught.
    let mut one = ValidatorSet::new();
    one.add([1u8; 32], 1);
    assert_eq!(
        one.quorum_power(),
        1,
        "a SINGLE validator satisfies its own quorum alone"
    );
    println!(
        "[FINDING 14] single-validator set: quorum_power = {} (a node finalises alone)",
        one.quorum_power()
    );
}

// ===========================================================================
// FINDING 12 FIXED: slash_pq_equivocation cryptographically verifies signatures
// ===========================================================================

#[test]
fn hunt_finding_12_fixed_pq_equivocation_verifies_signatures_and_deduplicates() {
    use ed25519_dalek::Signer;
    use stellereum::staking::{CompactPqEquivocationEvidence, StakingError};

    let mut l = StakingLedger::new();
    let a_key = SigningKey::generate(&mut OsRng);
    let b_key = SigningKey::generate(&mut OsRng);
    let aid = a_key.verifying_key().to_bytes();
    let bid = b_key.verifying_key().to_bytes();
    l.bond(aid, 10 * MIN_VALIDATOR_BOND, 0).unwrap();
    l.bond(bid, 10 * MIN_VALIDATOR_BOND, 0).unwrap();

    let target_a = Some([1u8; 32]);
    let target_b = Some([2u8; 32]);
    let msg_a = stellereum::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &target_a);
    let msg_b = stellereum::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &target_b);

    let sig_a = a_key.sign(&msg_a).to_bytes().to_vec();
    let sig_b = b_key.sign(&msg_b).to_bytes().to_vec();

    // Finding 12 attack: presenting B's signature as evidence against A.
    // In legacy `slash_equivocation`, this burned A's stake.
    // In `slash_pq_equivocation`, this MUST be rejected with InvalidSignature.
    let framed_evidence = CompactPqEquivocationEvidence {
        voter: aid,
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash_a: target_a,
        signature_a: sig_a.clone(),
        block_hash_b: target_b,
        signature_b: sig_b,
    };
    assert_eq!(
        l.slash_pq_equivocation(&framed_evidence, false),
        Err(StakingError::InvalidSignature),
        "F12 FIXED: cannot frame validator A using B's signature"
    );
    assert_eq!(l.total_stake(&aid), 10 * MIN_VALIDATOR_BOND);

    // Two unsigned / fake signatures: rejected with InvalidSignature.
    let fake_evidence = CompactPqEquivocationEvidence {
        voter: aid,
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash_a: target_a,
        signature_a: vec![0u8; 64],
        block_hash_b: target_b,
        signature_b: vec![0u8; 64],
    };
    assert_eq!(
        l.slash_pq_equivocation(&fake_evidence, false),
        Err(StakingError::InvalidSignature),
        "F12 FIXED: fake signatures cannot burn stake"
    );

    // Legitimate equivocation by A (A actually signed both votes):
    let real_sig_b = a_key.sign(&msg_b).to_bytes().to_vec();
    let real_evidence = CompactPqEquivocationEvidence {
        voter: aid,
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash_a: target_a,
        signature_a: sig_a,
        block_hash_b: target_b,
        signature_b: real_sig_b,
    };

    // Slashes 5% on standard: 5% of 10 * MIN_VALIDATOR_BOND
    let burned = l.slash_pq_equivocation(&real_evidence, false).unwrap();
    assert_eq!(burned, (10 * MIN_VALIDATOR_BOND * 500) / 10_000);
    assert_eq!(l.total_stake(&aid), 10 * MIN_VALIDATOR_BOND - burned);

    // Deduplication prevents double slashing:
    let replayed = l.slash_pq_equivocation(&real_evidence, false).unwrap();
    assert_eq!(replayed, 0, "Deduplication must prevent repeat burn");

    // Micro-committee 100% slash and eviction test on B:
    let b_msg_a = stellereum::consensus::vote_sign_bytes(2, 0, VoteKind::Precommit, &target_a);
    let b_msg_b = stellereum::consensus::vote_sign_bytes(2, 0, VoteKind::Precommit, &target_b);
    let b_sig_a = b_key.sign(&b_msg_a).to_bytes().to_vec();
    let b_sig_b = b_key.sign(&b_msg_b).to_bytes().to_vec();
    let b_evidence = CompactPqEquivocationEvidence {
        voter: bid,
        height: 2,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash_a: target_a,
        signature_a: b_sig_a,
        block_hash_b: target_b,
        signature_b: b_sig_b,
    };
    let b_burned = l.slash_pq_equivocation(&b_evidence, true).unwrap();
    assert_eq!(b_burned, 10 * MIN_VALIDATOR_BOND);
    assert_eq!(l.total_stake(&bid), 0);
    assert!(
        !l.validators.contains_key(&bid),
        "Micro-committee equivocator must be evicted"
    );
}
