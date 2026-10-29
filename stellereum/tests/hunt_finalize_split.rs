//! HUNT: finalization paths that reach DIFFERENT state for the SAME certified block.
//!
//! Targets:
//!   src/runtime.rs:638-655  `try_finalize`
//!   src/runtime.rs:690-698  `apply_and_advance` (the adopt_committed path)
//!   src/runtime.rs:610-636  `apply_downtime_slashes`
//!   src/runtime.rs:731-776  `adopt_committed`
//!
//! The chain's state root is the trie root, and the trie carries
//! `commitment_digest` under one key (src/commitment.rs, src/state_engine.rs:760).
//! `staking_digest` commits `missed` and `last_downtime_penalty` per validator
//! (src/commitment.rs:239-240). So any divergence in the staking ledger is a
//! state-root divergence, and a state-root divergence is a chain split that no
//! amount of re-syncing can detect.
//!
//! TWO LEGAL finalization paths exist for the same certified block:
//!   (A) try_finalize  -- the node ran the round itself and has a precommit QC
//!   (B) adopt_committed -- the node was told by a peer and verified the QC
//! They must produce byte-identical state. They do not.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const N: usize = 4;

/// `fund_genesis` bonds `min(MIN_VALIDATOR_BOND, balance)`, so the balance has to
/// be at least MIN_VALIDATOR_BOND (1e12) for ANY validator to end up bonded.
const BONDABLE_BALANCE: u64 = 10_000_000_000_000;

type Ns = Vec<SigningKey>;

fn keys(n: usize) -> Ns {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

async fn funded_state(owner: [u8; 32], bal: u64) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(owner, bal)).await;
    // Bond so the node is in the staking ledger too (the downtime-slash evidence
    // path reads `ledger.validators`).
    {
        let mut l = st.staking_write().await;
        let _ = l.bond(
            owner,
            stellereum::staking::MIN_VALIDATOR_BOND + stellereum::staking::STELL_MIN_BOND_BUFFER,
            0,
        );
    }
    st
}

/// Every node gets its OWN state engine, seeded exactly like `fund_genesis` does
/// in production: funded AND bonded, so the staking ledger really contains all
/// four validators and `note_missed_heights` has an `eligible` set to walk.
/// `payer` is funded too so a transfer in a block actually executes.
async fn cluster(ks: &[SigningKey], payer: ValidatorId, bal: u64) -> Vec<ValidatorRuntime> {
    let vs = vset(ks);
    let mut out = Vec::new();
    for k in ks {
        let st = Arc::new(InMemoryStateEngine::new());
        stellereum::runtime::fund_genesis(&st, &vs, bal).await;
        st.update_account(AccountState::new(payer, bal)).await;
        out.push(ValidatorRuntime::new(k.clone(), vs.clone(), st, 1));
    }
    out
}

fn mkblock(
    proposer_key: &SigningKey,
    h: u64,
    prev: [u8; 32],
    root: [u8; 32],
    txs: Vec<Transaction>,
) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: proposer_key.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(proposer_key);
    b
}

/// A GENUINE 3-of-4 precommit certificate: real keys, real signatures, real
/// `vote_sign_bytes` message. The omitted validator is the "silent" one.
fn genuine_cert(ks: &[SigningKey], signer_idx: &[usize], bh: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: signer_idx
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

fn precommit_for(ks: &[SigningKey], i: usize, bh: [u8; 32]) -> Vote {
    Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh))
}
fn prevote_for(ks: &[SigningKey], i: usize, bh: [u8; 32]) -> Vote {
    Vote::sign(&ks[i], 1, 0, VoteKind::Prevote, Some(bh))
}

// ===========================================================================
// FINDING 2 (CRITICAL): try_finalize finalizes a block the node NEVER received
// ===========================================================================

/// PARKED, and the parking is the point.
///
/// This test demonstrated that a node would finalise a block hash it does not
/// hold, then split its state root from its peers. `try_finalize` now refuses
/// outright, so the attack cannot be staged at all.
///
/// It cannot simply be inverted, because the scenario is built on synthetic block
/// hashes: the "honest" nodes here also do not hold a block under that hash, so
/// with the fix they correctly refuse too, and there is no longer a split to
/// observe. Rewriting it means building real signed blocks and a real prevote
/// round, which is a fresh test rather than an edit to this one.
///
/// The invariant is covered elsewhere: `try_finalize` returning `None` for an
/// absent block, and `hunt_consensus_core.rs` / `hunt_finalize_split.rs`
/// assertions that the height does not advance.
#[tokio::test]
async fn hunt_finding_2_finalize_without_the_block_splits_state() {
    let ks = keys(N);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let to = [0x77u8; 32];
    let mut nodes = cluster(&ks, from, 10_000_000_000_000).await;

    let proposer = nodes
        .iter()
        .position(|n| n.is_proposer())
        .expect("a proposer");
    // Pick a victim that is NOT the proposer, so it never learns the block body.
    let victim = (proposer + 1) % N;
    assert_ne!(
        proposer, victim,
        "the victim must not be the proposer this round"
    );
    let pkey = ks[proposer].clone();
    let pid = pkey.verifying_key().to_bytes();

    // The header must commit to the state it builds on (validate_proposal checks
    // it), and all four nodes start from byte-identical state.
    let genesis_root = nodes[0].state.get_state_root().await;
    let tx = Transaction::sign(&user, to, 1_000, 0, 0, 1, 1);
    let block = mkblock(&pkey, 1, [0u8; 32], genesis_root, vec![tx]);
    let bh = block.compute_hash();

    // In production the proposer keeps its own block (`propose()` inserts it).
    nodes[proposer].blocks.insert(bh, block.clone());

    // Every node EXCEPT the victim receives the proposal (3 of 4 == quorum).
    for (i, n) in nodes.iter_mut().enumerate() {
        if i != proposer && i != victim {
            let er = n.hc.round;
            n.on_proposal(pid, block.clone(), er).await.unwrap();
        }
    }
    // Those three prevote and precommit.
    let signers: Vec<usize> = (0..N).filter(|&i| i != victim).collect();
    assert_eq!(signers.len(), 3);
    for &i in &signers {
        let pv = prevote_for(&ks, i, bh);
        for n in nodes.iter_mut() {
            n.on_prevote(pv.clone()).unwrap();
        }
    }
    let mut precommits = vec![];
    for &i in &signers {
        let pc = precommit_for(&ks, i, bh);
        for n in nodes.iter_mut() {
            n.on_precommit(pc.clone()).unwrap();
        }
        precommits.push(pc);
    }

    // The attacker relays ONLY the precommits to the victim. It has a genuine
    // 3-of-4 precommit quorum but has NEVER seen or validated the block.
    assert!(
        !nodes[victim].blocks.contains_key(&bh),
        "precondition: the victim holds no block"
    );
    let vs = nodes[victim].validators.clone();
    let built = nodes[victim]
        .hc
        .precommit_set(0)
        .unwrap()
        .certificate(Some(bh), &vs, &nodes[victim].hc.parent_hash)
        .expect("victim can build a cert from relayed votes alone");
    assert!(built.verify(&vs));
    println!("[FINDING 2] victim built+verified a 3-of-4 cert from relayed precommits: ok");

    let decided = nodes[victim].try_finalize().await;
    println!(
        "[FINDING 2] victim try_finalize() = {}",
        decided.map(|h| hex::encode(&h[..4])).unwrap_or_default()
    );
    // FIX: a precommit quorum is not a licence to advance a height on a block
    // nobody sent. The node now refuses, and commits to nothing.
    assert_eq!(
        decided, None,
        "a node must not finalise a block hash it does not hold"
    );
    assert_ne!(nodes[victim].finalized.last().copied(), Some((1u64, bh)));
    println!("HUNT-FIXED: phantom block refused");
    assert_eq!(nodes[victim].applied_txs, 0, "the victim applied nothing");

    // The other three have the block and drive a full round - prevotes then
    // precommits - so finalising them is legitimate. (Finalising now requires a
    // prevote quorum for the same block; a precommit quorum alone is not enough.)
    for (i, n) in nodes.iter_mut().enumerate() {
        if i == victim {
            continue;
        }
        for k in ks.iter().take(3) {
            n.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
                .unwrap();
        }
        for k in ks.iter().take(3) {
            n.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
                .unwrap();
        }
        assert_eq!(
            n.try_finalize().await,
            Some(bh),
            "node {i} finalises a real round"
        );
    }

    let mut roots = vec![];
    for (i, n) in nodes.iter().enumerate() {
        let bal = n
            .state
            .get_account(&to)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        let r = n.state.get_state_root().await;
        println!(
            "[FINDING 2] node{i}{} root={} recipient={bal} applied={}",
            if i == victim { " (VICTIM)" } else { "" },
            hex::encode(&r[..6]),
            n.applied_txs
        );
        roots.push(r);
    }
    assert_eq!(
        nodes[victim]
            .state
            .get_account(&to)
            .await
            .map(|a| a.balance),
        None,
        "the victim's recipient account does not even exist"
    );
    assert_eq!(
        nodes[signers[0]]
            .state
            .get_account(&to)
            .await
            .unwrap()
            .balance,
        1_000
    );

    // All three honest nodes agree; the victim does not.
    let honest: Vec<[u8; 32]> = (0..N).filter(|&i| i != victim).map(|i| roots[i]).collect();
    assert!(
        honest.windows(2).all(|w| w[0] == w[1]),
        "the three honest nodes must agree"
    );
    assert_ne!(
        roots[victim], honest[0],
        "SPLIT: nodes finalized the SAME certified block and disagree on the state root"
    );
    println!(
        "[FINDING 2] SPLIT CONFIRMED: victim {} != honest {}",
        hex::encode(&roots[victim][..8]),
        hex::encode(&honest[0][..8])
    );
}

// ===========================================================================
// FINDING 3 (CRITICAL): adopt_committed never runs note_missed_heights
// ===========================================================================

// ===========================================================================
// FINDING 3 (CRITICAL): local-finalize and adopt must slash identically
// ===========================================================================

/// W10.5 canonical-evidence form: downtime is attributed ONLY from the
/// block-carried `last_qc` (height H-1), on EVERY path, through the same
/// `apply_block_transition`. The old form of this test drove a single
/// height-1 block and expected the local path to slash from its own vote
/// observations — but a height-1 block has no parent decision, so its
/// `last_qc` is `None` (genesis child) and the transition deterministically
/// skips attribution on both paths: the `missed == 1` expectation became
/// unsatisfiable the day evidence moved into the block.
///
/// The two-height form below tests the live rule: height 1 finalizes (no
/// evidence, no attribution), then height 2 carries the height-1 QC as its
/// canonical evidence and BOTH paths must mark the silent validator missed
/// and reach the same root.
#[tokio::test]
async fn hunt_finding_3_adopt_path_slashes_identically_to_the_local_path() {
    let ks = keys(N);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let to = [0x88u8; 32];
    // Author each block with the validator the schedule names for its
    // (height, round): the adopt path enforces the proposer slot, so any
    // other choice would be refused before reaching the behaviour this
    // test is about.
    let proposer_for = |h: u64| {
        let want = vset(&ks).proposer_for(h, 0).unwrap();
        ks.iter()
            .find(|k| k.verifying_key().to_bytes() == want)
            .expect("the schedule's proposer is one of our keys")
            .clone()
    };

    // The header must commit to the state it BUILDS ON, so we need the real
    // post-genesis root. Every cluster in this test is funded identically, so one
    // of them gives us that root.
    let probe = cluster(&ks, from, BONDABLE_BALANCE).await;
    let genesis_root = probe[0].state.get_state_root().await;

    // ---------- Height 1 (genesis child: no evidence, no attribution) ----------
    let pkey1 = proposer_for(1);
    let tx = Transaction::sign(&user, to, 10, 0, 0, 1, 1);
    let block1 = mkblock(&pkey1, 1, [0u8; 32], genesis_root, vec![tx]);
    let bh1 = block1.compute_hash();

    // Three of the four validators signed; validator 3 is silent.
    let cert1 = genuine_cert(&ks, &[0, 1, 2], bh1);
    let ids: Vec<ValidatorId> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let silent = ids[3];
    assert!(cert1.verify(&vset(&ks)));
    println!(
        "[FINDING 3] cert1 has {}/4 real signatures; silent validator = {}",
        cert1.signatures.len(),
        hex::encode(&silent[..6])
    );

    // Path A: finalized locally.
    let mut local = cluster(&ks, from, BONDABLE_BALANCE).await;
    for k in ks.iter().take(3) {
        local[0]
            .hc
            .add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh1)))
            .unwrap();
        local[0]
            .hc
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh1)))
            .unwrap();
    }
    assert_eq!(
        local[0].hc.try_precommit_quorum(),
        Some(bh1),
        "3-of-4 precommit quorum at height 1"
    );
    local[0].blocks.insert(bh1, block1.clone());
    assert_eq!(local[0].try_finalize().await, Some(bh1));

    // Path B: adopted from a peer.
    let mut peer = cluster(&ks, from, BONDABLE_BALANCE).await;
    let r1 = peer[1]
        .adopt_committed(1, block1.clone(), cert1.clone())
        .await;
    assert_eq!(r1, Ok(bh1), "the peer commit at height 1 was accepted");

    // Same block, same pre-state, no evidence: both paths skip attribution
    // identically and agree on the root.
    let root_after_1_a = local[0].state.get_state_root().await;
    let root_after_1_b = peer[1].state.get_state_root().await;
    assert_eq!(root_after_1_a, root_after_1_b, "height-1 roots must agree");
    for (tag, rt) in [("local", &local[0]), ("adopt", &peer[1])] {
        assert_eq!(
            rt.state.staking_read().await.validators[&silent].missed,
            0,
            "{tag}: with no canonical evidence for height 1, nothing is attributed"
        );
    }

    // ---------- Height 2 (carries the height-1 QC as canonical evidence) ----------
    let pkey2 = proposer_for(2);
    let mut block2 = mkblock(&pkey2, 2, bh1, root_after_1_a, vec![]);
    block2.last_qc = Some(cert1.clone());
    // Re-sign: the block hash commits to the canonical evidence (among
    // other header fields), so the pre-evidence signature is stale. Clear
    // it first: `sign_block` appends, and a stale proposer signature is
    // dead weight every verifier would trip over.
    block2.validator_signatures.clear();
    block2.sign_block(&pkey2);
    let bh2 = block2.compute_hash();
    let cert2 = QuorumCertificate {
        height: 2,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh2),
        signatures: [0usize, 1, 2]
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], 2, 0, VoteKind::Precommit, Some(bh2));
                (v.voter, v.signature)
            })
            .collect(),
    };

    // Both paths must agree which set decides height 2 (same committed
    // prefix ⇒ same derivation), or the test setup itself is broken.
    let live_set_h2 = local[0].validator_set_for_height(2);
    let peer_set_h2 = peer[1].validator_set_for_height(2);
    assert_eq!(
        live_set_h2.validators, peer_set_h2.validators,
        "both paths must judge height 2 by the same set"
    );
    assert!(
        cert2.verify(&live_set_h2),
        "the height-2 decision QC must verify"
    );

    // Path A: drive a real round at height 2 and finalize locally.
    for k in ks.iter().take(3) {
        local[0]
            .hc
            .add_prevote(Vote::sign(k, 2, 0, VoteKind::Prevote, Some(bh2)))
            .unwrap();
        local[0]
            .hc
            .add_precommit(Vote::sign(k, 2, 0, VoteKind::Precommit, Some(bh2)))
            .unwrap();
    }
    assert_eq!(
        local[0].hc.try_precommit_quorum(),
        Some(bh2),
        "3-of-4 precommit quorum at height 2"
    );
    local[0].blocks.insert(bh2, block2.clone());
    assert_eq!(local[0].try_finalize().await, Some(bh2));

    // Path B: adopt the height-2 commit.
    let r2 = peer[1]
        .adopt_committed(2, block2.clone(), cert2.clone())
        .await;
    assert_eq!(
        r2,
        Ok(bh2),
        "the peer commit at height 2 was accepted: {r2:?}"
    );

    let burn_a = local[0].state.staking_read().await.total_burned;
    let burn_b = peer[1].state.staking_read().await.total_burned;
    let root_a = local[0].state.get_state_root().await;
    let root_b = peer[1].state.get_state_root().await;
    let missed_a = local[0].state.staking_read().await.validators[&silent].missed;
    let missed_b = peer[1].state.staking_read().await.validators[&silent].missed;
    println!(
        "[FINDING 3] Path A (try_finalize): burned={burn_a} silent.missed={missed_a} root={}",
        hex::encode(&root_a[..8])
    );
    println!(
        "[FINDING 3] Path B (adopt_committed): burned={burn_b} silent.missed={missed_b} root={}",
        hex::encode(&root_b[..8])
    );

    assert_eq!(
        missed_a, 1,
        "the local path marked the silent validator missed"
    );
    assert_eq!(
        missed_b, missed_a,
        "FIXED: the adopt path must mark the same missed count"
    );
    assert_eq!(
        burn_a, burn_b,
        "both paths must burn the same coins (here: none yet)"
    );
    assert_eq!(
        root_a, root_b,
        "FIXED: two legal paths over the SAME certified blocks must reach the SAME root"
    );
    println!(
        "[FINDING 3] FIXED: {} == {}",
        hex::encode(&root_a[..8]),
        hex::encode(&root_b[..8])
    );
}

// ===========================================================================
// FINDING 4 (HIGH): adopt_committed does not check block.state_root at all
// ===========================================================================

#[tokio::test]
async fn hunt_finding_4_adopt_committed_binds_the_state_root() {
    let ks = keys(N);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let to = [0x99u8; 32];
    let mut nodes = cluster(&ks, from, BONDABLE_BALANCE).await;
    // Use the validator the schedule actually names for (height 1, round 0), so this
    // test exercises the state-root binding rather than being refused earlier for
    // an unrelated reason.
    let want = nodes[0].validators.proposer_for(1, 0).unwrap();
    let pkey = ks
        .iter()
        .find(|k| k.verifying_key().to_bytes() == want)
        .expect("the schedule's proposer is one of our keys")
        .clone();

    // A block whose header commits to a state root that does not exist anywhere.
    let tx = Transaction::sign(&user, to, 10, 0, 0, 1, 1);
    let block = mkblock(&pkey, 1, [0u8; 32], [0xAB; 32], vec![tx]);
    let bh = block.compute_hash();

    // The LIVE proposal path rejects the very same block...
    let our_root = nodes[1].state.get_state_root().await;
    let e1 = nodes[1].validate_proposal(&block, our_root).unwrap_err();
    println!("[FINDING 4] validate_proposal  -> Err(\"{e1}\")");
    assert!(e1.contains("state root"));

    // ...the PEER-COMMIT path accepts it.
    let cert = genuine_cert(&ks, &[0, 1, 2], bh);
    let _set = nodes[2].validators.clone();
    let r = nodes[2].adopt_committed(1, block.clone(), cert).await;
    println!(
        "[FINDING 4] adopt_committed   -> {:?}",
        r.as_ref()
            .map(|h| hex::encode(&h[..4]))
            .map_err(|e| e.clone())
    );
    // FIXED: adopt_committed now checks the block's state_root against the state it
    // builds on, exactly as validate_proposal does. The parent-link check already
    // forces the block to extend our own finalized head, so our live root is the
    // right comparison. Without it, the adopt path applied blocks to a state the
    // network never committed to and computed a root nobody else had.
    assert!(
        r.is_err(),
        "a block with a fabricated state_root must be refused"
    );
    assert!(
        r.as_ref().unwrap_err().contains("parent state root"),
        "the refusal must name the state root: {:?}",
        r.err()
    );
    assert!(
        nodes[2].finalized.is_empty(),
        "nothing may be finalized from it"
    );
    println!(
        "[FINDING 4] FIXED: header root 0xabab..ab != local root {} was refused",
        hex::encode(&our_root[..6])
    );
}

// ===========================================================================
// FINDING 5 (HIGH): the certificate is verified against a CALLER-SUPPLIED set
// ===========================================================================

#[tokio::test]
async fn hunt_finding_5_adopt_committed_uses_only_the_local_validator_set() {
    let ks = keys(N);
    let real = vset(&ks);
    assert_eq!(real.len(), 4);
    assert_eq!(real.quorum_power(), 3, "the node's real quorum is 3 of 4");

    // The attacker controls ONE key and declares a set in which it is the only
    // validator: total_power = 1 -> quorum_power = 1.
    let attacker = SigningKey::generate(&mut OsRng);
    let forged_set = ValidatorSet::from_list(vec![(attacker.verifying_key().to_bytes(), 1)]);
    assert_eq!(forged_set.quorum_power(), 1);

    let user = SigningKey::generate(&mut OsRng);
    // Deterministic proposer: the schedule names exactly one proposer for
    // (height 1, round 0); the block MUST carry it or the cheap proposer gate
    // (correctly) refuses before the quorum check is ever reached. A fixed
    // ks[i] with random keys made this test 1-in-4 flaky; resolving the
    // scheduled key keeps it deterministically on the QUORUM refusal path.
    let sched = real
        .proposer_for(1, 0)
        .expect("4-member set names a proposer");
    let sched_key = ks
        .iter()
        .find(|k| k.verifying_key().to_bytes() == sched)
        .expect("scheduled proposer is one of ours");
    let block = mkblock(
        sched_key,
        1,
        [0u8; 32],
        [0xDE; 32],
        vec![Transaction::sign(&user, [1u8; 32], 999_999, 0, 0, 1, 1)],
    );
    let bh = block.compute_hash();
    let v = Vote::sign(&attacker, 1, 0, VoteKind::Precommit, Some(bh));
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![(v.voter, v.signature)],
    };
    println!(
        "[FINDING 5] cert.verify(REAL 4-validator set)     = {}",
        cert.verify(&real)
    );
    println!(
        "[FINDING 5] cert.verify(ATTACKER-DECLARED set)   = {}",
        cert.verify(&forged_set)
    );
    assert!(!cert.verify(&real), "worthless against the real set");
    assert!(
        cert.verify(&forged_set),
        "...but valid against a set the CALLER supplied"
    );

    let id = ks[3].verifying_key().to_bytes();
    let state = funded_state(id, 10_000).await;
    let mut rt = ValidatorRuntime::new(ks[3].clone(), real.clone(), state, 1);
    // FIXED: `adopt_committed` no longer takes a validator set at all. It reads
    // `self.validators` internally, so the one-key certificate is measured against
    // the node's real 4-validator set and is worthless. Previously the guarantee
    // held only because of a single call site, while the doc comment and
    // OPERATIONS.md both asserted it as intrinsic to the function.
    let r = rt.adopt_committed(1, block, cert).await;
    println!(
        "[FINDING 5] FIXED: adopt_committed(...) = {}  (node's OWN set has {} validators, quorum {})",
        r.as_ref().map(|h| hex::encode(&h[..4])).unwrap_or_else(|e| format!("Err({e})")),
        real.len(),
        real.quorum_power()
    );
    assert!(
        r.is_err(),
        "a one-key certificate must not finalize anything"
    );
    assert!(
        r.as_ref().unwrap_err().contains("validator quorum"),
        "the refusal must be the quorum check: {:?}",
        r.err()
    );
    assert!(rt.finalized.is_empty());
}
