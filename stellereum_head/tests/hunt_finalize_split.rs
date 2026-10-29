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
use stellereum::consensus::{QuorumCertificate, Vote, VoteKind, ValidatorId, ValidatorSet};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use std::sync::Arc;

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

fn mkblock(proposer_key: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32], txs: Vec<Transaction>) -> Block {
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
        precommit_qc: None,
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

    let proposer = nodes.iter().position(|n| n.is_proposer()).expect("a proposer");
    // Pick a victim that is NOT the proposer, so it never learns the block body.
    let victim = (proposer + 1) % N;
    assert_ne!(proposer, victim, "the victim must not be the proposer this round");
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
        nodes[victim].blocks.get(&bh).is_none(),
        "precondition: the victim holds no block"
    );
    let vs = nodes[victim].validators.clone();
    let built = nodes[victim]
        .hc
        .precommit_set(0)
        .unwrap()
        .certificate(Some(bh), &vs)
        .expect("victim can build a cert from relayed votes alone");
    assert!(built.verify(&vs));
    println!("[FINDING 2] victim built+verified a 3-of-4 cert from relayed precommits: ok");

    let decided = nodes[victim].try_finalize().await;
    println!("[FINDING 2] victim try_finalize() = {}", decided.map(|h| hex::encode(&h[..4])).unwrap_or_default());
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
        assert_eq!(n.try_finalize().await, Some(bh), "node {i} finalises a real round");
    }

    let mut roots = vec![];
    for (i, n) in nodes.iter().enumerate() {
        let bal = n.state.get_account(&to).await.map(|a| a.balance).unwrap_or(0);
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
        nodes[victim].state.get_account(&to).await.map(|a| a.balance),
        None,
        "the victim's recipient account does not even exist"
    );
    assert_eq!(nodes[signers[0]].state.get_account(&to).await.unwrap().balance, 1_000);

    // All three honest nodes agree; the victim does not.
    let honest: Vec<[u8; 32]> = (0..N).filter(|&i| i != victim).map(|i| roots[i]).collect();
    assert!(honest.windows(2).all(|w| w[0] == w[1]), "the three honest nodes must agree");
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

#[tokio::test]
async fn hunt_finding_3_adopt_path_slashes_identically_to_the_local_path() {
    let ks = keys(N);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let to = [0x88u8; 32];
    // Author the block with the validator the schedule names for (1, 0): the adopt
    // path now enforces the proposer slot, so any other choice would be refused
    // before reaching the behaviour this test is about.
    let want = vset(&ks).proposer_for(1, 0).unwrap();
    let pkey = ks
        .iter()
        .find(|k| k.verifying_key().to_bytes() == want)
        .expect("the schedule's proposer is one of our keys")
        .clone();

    // The header must commit to the state it BUILDS ON, so we need the real
    // post-genesis root. Every cluster in this test is funded identically, so one
    // of them gives us that root.
    let probe = cluster(&ks, from, BONDABLE_BALANCE).await;
    let genesis_root = probe[0].state.get_state_root().await;

    let tx = Transaction::sign(&user, to, 10, 0, 0, 1, 1);
    let block = mkblock(&pkey, 1, [0u8; 32], genesis_root, vec![tx]);
    let bh = block.compute_hash();

    // Three of the four validators signed; validator 3 is silent.
    let cert = genuine_cert(&ks, &[0, 1, 2], bh);
    let ids: Vec<ValidatorId> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let silent = ids[3];
    assert!(cert.verify(&vset(&ks)));
    println!("[FINDING 3] cert has {}/4 real signatures; silent validator = {}", cert.signatures.len(), hex::encode(&silent[..6]));

    // ---------- Path A: finalized locally ----------
    let mut local = cluster(&ks, from, BONDABLE_BALANCE).await;
    for &i in &[0usize, 1, 2] {
        local[0].on_precommit(precommit_for(&ks, i, bh)).unwrap();
    }
    // Finalising now needs a prevote quorum for the same block, so drive a real
    // round instead of only precommitting.
    for k in ks.iter().take(3) {
        local[0]
            .hc
            .add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    assert!(local[0].hc.try_prevote_quorum().is_some(), "prevote quorum");
    for k in ks.iter().take(3) {
        local[0]
            .hc
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(local[0].hc.try_precommit_quorum(), Some(bh), "3-of-4 precommit quorum");
    assert!(local[0].hc.precommit_qc.is_some());
    local[0].blocks.insert(bh, block.clone());
    // Drive the REAL local path end to end, so both sides start from the same
    // post-block state before slashing is compared.
    assert_eq!(local[0].try_finalize().await, Some(bh));
    let burn_a = local[0].state.staking_read().await.total_burned;
    let root_a = local[0].state.get_state_root().await;
    let missed_a = local[0].state.staking_read().await.validators[&silent].missed;
    println!(
        "[FINDING 3] Path A (try_finalize): burned={burn_a} silent.missed={missed_a} root={}",
        hex::encode(&root_a[..8])
    );

    // ---------- Path B: adopted from a peer ----------
    let mut peer = cluster(&ks, from, BONDABLE_BALANCE).await;
    let local_set = peer[1].validators.clone();
    let r = peer[1].adopt_committed(1, block.clone(), cert.clone()).await;
    println!("[FINDING 3] Path B (adopt_committed) = {:?}", r.as_ref().map(|h| hex::encode(&h[..4])).map_err(|e| e.clone()));
    assert_eq!(r, Ok(bh), "the peer commit was accepted");
    // FIXED: adopt_committed installs the verified certificate as this height's QC
    // before advancing, so `apply_downtime_slashes` sees the identical signer set
    // the local path formed. Previously precommit_qc was None here and the slash was
    // skipped entirely, splitting the roots.
    assert!(
        peer[1].hc.precommit_qc.is_none(),
        "the fresh HeightConsensus for height 2 starts without a QC, as before"
    );
    let root_b = peer[1].state.get_state_root().await;
    let missed_b = peer[1].state.staking_read().await.validators[&silent].missed;
    let burn_b = peer[1].state.staking_read().await.total_burned;
    println!(
        "[FINDING 3] Path B (adopt_committed): silent.missed={missed_b} root={}",
        hex::encode(&root_b[..8])
    );

    assert_eq!(missed_a, 1, "the local path marked the silent validator missed");
    assert_eq!(
        missed_b, missed_a,
        "FIXED: the adopt path must mark the same missed count"
    );
    assert_eq!(
        root_a, root_b,
        "FIXED: two legal paths over the SAME certified block must reach the SAME root"
    );
    println!("[FINDING 3] FIXED: {} == {}", hex::encode(&root_a[..8]), hex::encode(&root_b[..8]));
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
    let set = nodes[2].validators.clone();
    let r = nodes[2].adopt_committed(1, block.clone(), cert).await;
    println!("[FINDING 4] adopt_committed   -> {:?}", r.as_ref().map(|h| hex::encode(&h[..4])).map_err(|e| e.clone()));
    // FIXED: adopt_committed now checks the block's state_root against the state it
    // builds on, exactly as validate_proposal does. The parent-link check already
    // forces the block to extend our own finalized head, so our live root is the
    // right comparison. Without it, the adopt path applied blocks to a state the
    // network never committed to and computed a root nobody else had.
    assert!(r.is_err(), "a block with a fabricated state_root must be refused");
    assert!(
        r.as_ref().unwrap_err().contains("parent state root"),
        "the refusal must name the state root: {:?}",
        r.err()
    );
    assert!(nodes[2].finalized.is_empty(), "nothing may be finalized from it");
    println!("[FINDING 4] FIXED: header root 0xabab..ab != local root {} was refused",
        hex::encode(&our_root[..6]));
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
    let sched = real.proposer_for(1, 0).expect("4-member set names a proposer");
    let sched_key = ks.iter().find(|k| k.verifying_key().to_bytes() == sched).expect("scheduled proposer is one of ours");
    let block = mkblock(sched_key, 1, [0u8; 32], [0xDE; 32], vec![Transaction::sign(&user, [1u8; 32], 999_999, 0, 0, 1, 1)]);
    let bh = block.compute_hash();
    let v = Vote::sign(&attacker, 1, 0, VoteKind::Precommit, Some(bh));
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![(v.voter, v.signature)],
    };
    println!("[FINDING 5] cert.verify(REAL 4-validator set)     = {}", cert.verify(&real));
    println!("[FINDING 5] cert.verify(ATTACKER-DECLARED set)   = {}", cert.verify(&forged_set));
    assert!(!cert.verify(&real), "worthless against the real set");
    assert!(cert.verify(&forged_set), "...but valid against a set the CALLER supplied");

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
    assert!(r.is_err(), "a one-key certificate must not finalize anything");
    assert!(
        r.as_ref().unwrap_err().contains("validator quorum"),
        "the refusal must be the quorum check: {:?}",
        r.err()
    );
    assert!(rt.finalized.is_empty());
}
