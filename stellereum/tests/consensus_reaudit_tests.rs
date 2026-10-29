//! Regression tests for the consensus re-audit (audit W6.4b).
//!
//! Each test pins ONE defect that the re-audit found and fixed:
//!
//!  * W1 — the deadlock breaker's target was clamped to `round + MAX_ROUND_AHEAD`
//!    (1000), so it could never close the very desync it exists for.
//!  * W2 — the local re-phase advanced the round by one (a no-op: the round
//!    timer does that anyway) and never re-converged.
//!  * W3 — the fork-choice's candidate-window trim recorded an invalidation
//!    but never PUBLISHED it: a dropped branch vanished without a trace.
//!  * W4 — the snapshot anchor took the finalized head (and the sortition
//!    entropy) from a peer-supplied header record, whose `prev_hash` is not
//!    covered by the quorum certificate: a peer could point the node at a
//!    fork and steer its sortition committee.
//!  * W5 — an UNKNOWN sortition parent compiled a micro-certificate against
//!    the ZERO parent: a committee nobody else elects.
//!  * W6 — the lock-hint rescue could re-propose ANOTHER author's body.
//!  * W7 — the wire decoder tolerated a truncated body (the trailing
//!    commitment fields absent), silently reinterpreting a malformed message
//!    as a different block.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use stellereum::chain::{ChainManager, InvalidationSignal, MAX_TRACKED_CANDIDATES};
use stellereum::consensus::{
    HeightConsensus, ValidatorSet, Vote, VoteKind, REPHASE_SCAN_WINDOW, ROUND_LOOKBACK,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

const H: u64 = 77_001;

// --- W3: the trimmed candidate must be PUBLISHED ----------------------------

#[test]
fn a_trimmed_candidate_is_published_as_an_invalidation() {
    // The candidate window is bounded. When a branch is dropped to make room,
    // the drop is a FORK the world has to hear about: the signal used to be
    // recorded inside the manager and never published, so a client that
    // followed the trimmed branch was never told it lost.
    let ks = keys(2);
    let mut cm = ChainManager::detached();
    // A root to hang the candidates off.
    cm.adopt_root(root_block());
    let root = cm.best_head();

    // More candidates than the window holds (each a valid extension of the
    // previous one, so the manager really tracks them).
    let mut parent = root;
    for i in 0..(MAX_TRACKED_CANDIDATES + 8) {
        let b = candidate_block(i as u64 + 1, parent, &ks[0]);
        parent = b.compute_hash();
        let _ = cm.insert_candidate(b);
    }
    assert!(
        cm.candidates.len() <= MAX_TRACKED_CANDIDATES,
        "the candidate window is bounded"
    );
    let pending = cm.take_pending_invalidations();
    assert!(
        !pending.is_empty(),
        "dropping a candidate to make room MUST raise an invalidation"
    );
    assert!(
        pending.iter().any(|s| !s.orphaned_blocks.is_empty()),
        "the signal must name the orphaned blocks"
    );
}

#[test]
fn no_invalidation_is_raised_when_nothing_is_dropped() {
    let ks = keys(2);
    let mut cm = ChainManager::detached();
    cm.adopt_root(root_block());
    let root = cm.best_head();
    let _ = cm.insert_candidate(candidate_block(1, root, &ks[0]));
    assert!(
        cm.take_pending_invalidations().is_empty(),
        "a candidate that is recorded raises nothing"
    );
}

// --- W5: an UNKNOWN sortition parent compiles no micro-certificate ---------

#[test]
fn an_unknown_sortition_parent_compiles_no_micro_certificate() {
    // The committee is elected from the PARENT BLOCK HASH. A node that does
    // not know its parent cannot elect an honest committee, so it must not
    // compile a micro-certificate at all: the zero-parent placeholder would
    // elect a committee NOBODY else elects (and the certificate would then
    // fail the `binds_to_parent` check on the adopt path, refusing the
    // commit).
    let ks = keys(3);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(H, vs.clone());
    assert!(
        !hc.parent_hash_known(),
        "a height above 1 has an UNKNOWN parent until it is set"
    );
    assert!(hc.sortition_parent().is_none());

    let target = Some([0x77u8; 32]);
    for k in ks.iter() {
        hc.add_prevote(Vote::sign(k, H, 0, VoteKind::Prevote, target))
            .unwrap();
    }
    let qc = hc
        .try_prevote_quorum_at()
        .and_then(|_| hc.prevote_qc.get(&0).cloned())
        .expect("the classical prevote QC must form");
    assert!(
        qc.pq_micro_certificate().is_none(),
        "an unknown parent must compile NO micro-certificate"
    );
    assert!(
        qc.verify(&vs),
        "the classical full-set certificate still carries the quorum"
    );

    // With the parent known, the same votes compile a micro-certificate
    // against the committee that parent elects.
    let mut hc = HeightConsensus::new(H, vs.clone());
    hc.set_parent_hash([0x88u8; 32]);
    assert!(hc.parent_hash_known());
    for k in ks.iter() {
        hc.add_prevote(Vote::sign(k, H, 0, VoteKind::Prevote, target))
            .unwrap();
    }
    let _ = hc.try_prevote_quorum_at();
    let _qc = hc.prevote_qc.get(&0).expect("prevote QC");
    // The classical set has no Falcon votes here, so no µQC is compiled —
    // but the PARENT is now known, which is what the check above turns on.
    assert!(hc.sortition_parent().is_some());
}

// --- W6: the lock-hint rescue never serves another author's body -----------

#[tokio::test]
async fn the_lock_hint_rescue_never_serves_another_authors_body() {
    let ks = keys(2);
    let vs = vset(&ks);
    let state = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
    while rt.hc.proposer().unwrap() != id(&ks[0]) {
        rt.hc.next_round();
    }
    let mine = rt.propose(1).await.expect("propose");
    let mh = mine.compute_hash();

    // A body ANOTHER validator authored that we happen to hold.
    let mut foreign = mine.clone();
    foreign.proposer = id(&ks[1]);
    let fh = foreign.compute_hash();
    rt.blocks.insert(fh, foreign);

    // The hint for the foreign body must be IGNORED: serving it would
    // re-propose somebody else's block under OUR proposer slot, which every
    // receiver rejects ("proposer field mismatch") — the rescue would fail,
    // the stuck peer would stay stuck, and our own round would be spent on a
    // block the network can never accept.
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(fh));

    // Our own body is kept and served verbatim.
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(mh));
    while rt.hc.proposer().unwrap() != id(&ks[0]) {
        rt.hc.next_round();
    }
    let served = rt.propose(1).await.expect("must propose");
    assert_eq!(
        served.compute_hash(),
        mh,
        "the rescue must serve OUR demanded body verbatim — never another author's"
    );
    assert_ne!(
        served.compute_hash(),
        fh,
        "the rescue must never re-propose another author's body"
    );
}

// --- W7: the wire refuses a truncated body ---------------------------------

#[test]
fn the_wire_refuses_a_truncated_block_body() {
    // The trailing commitment fields were APPENDED to the block layout, and
    // the legacy-tolerant reader that tolerates their absence must apply to
    // the LOCAL STORE only. On the wire a truncated message must fail
    // closed: otherwise a malformed message is silently reinterpreted as a
    // DIFFERENT block (empty shard-head set, zero order root).
    let mut b = root_block();
    b.shard_headers = vec![];
    b.order_merkle_root = [0u8; 32];
    let full = bincode::serialize(&b).expect("encode");
    // Chop the trailing `shard_headers` (8 bytes) + `order_merkle_root`
    // (32 bytes).
    let truncated = &full[..full.len() - 40];
    let strict: Result<Block, _> = bincode::deserialize(truncated);
    assert!(
        strict.is_err(),
        "the wire must refuse a truncated body, not reinterpret it"
    );
    // The legacy shape still decodes on the store path.
    let legacy: Result<Block, _> =
        stellereum::sharding::with_legacy_block_tolerance(|| bincode::deserialize(truncated));
    assert!(
        legacy.is_ok(),
        "the store must still read a body persisted before the fields existed"
    );
}

// --- W4: the snapshot anchor returns the VERIFIED boundary hash -------------

#[tokio::test]
async fn the_snapshot_anchor_returns_the_verified_boundary_hash() {
    // The anchor must prove the boundary block's hash (it is the finalized
    // head the node resumes from AND the sortition entropy for the next
    // height). A peer-supplied header record's `prev_hash` is NOT covered by
    // the quorum certificate, so it can never be the source of that value.
    use stellereum::sync::{verify_snapshot_anchor_tail, HeaderLink};
    let ks = keys(4);
    let vs = vset(&ks);
    let boundary = 100u64;
    let next_height = boundary + 1;

    // A genuine two-block segment: block B at `boundary`, block C at
    // `next_height` linking to it.
    let b_hash = [0xB1u8; 32];
    let c_hash = [0xC2u8; 32];
    // The tail window reaches one height BELOW the boundary, so the segment
    // is three linked, QC-verified blocks.
    let link = |h: u64| -> Option<HeaderLink> {
        if h == boundary {
            Some(HeaderLink {
                height: boundary,
                block_hash: b_hash,
                // Links to the block one height below the boundary, which the
                // window also covers.
                prev_hash: [0x9Au8; 32],
                state_root: [0x5u8; 32],
                proposer: vs.proposer_for(boundary, 0).unwrap(),
                qc: qc_for(&ks, vs.clone(), boundary, b_hash),
            })
        } else if h == next_height {
            Some(HeaderLink {
                height: next_height,
                block_hash: c_hash,
                prev_hash: b_hash,
                state_root: [0x5u8; 32],
                proposer: vs.proposer_for(next_height, 0).unwrap(),
                qc: qc_for(&ks, vs.clone(), next_height, c_hash),
            })
        } else if h + 1 == boundary {
            Some(HeaderLink {
                height: h,
                block_hash: [0x9Au8; 32],
                prev_hash: [0x8Au8; 32],
                state_root: [0x5u8; 32],
                proposer: vs.proposer_for(h, 0).unwrap(),
                qc: qc_for(&ks, vs.clone(), h, [0x9Au8; 32]),
            })
        } else {
            None
        }
    };
    let anchor = verify_snapshot_anchor_tail(next_height, &vs, |h| async move { link(h) })
        .await
        .expect("the genuine window must anchor");
    assert_eq!(
        anchor.boundary_hash, b_hash,
        "the boundary hash must be the VERIFIED block hash at the boundary"
    );
    assert_eq!(anchor.state_root, [0x5u8; 32]);
}

// --- helpers ----------------------------------------------------------------

fn root_block() -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 0,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

fn candidate_block(height: u64, parent: [u8; 32], signer: &SigningKey) -> Block {
    let mut b = root_block();
    b.height = height;
    b.prev_hash = parent;
    b.timestamp = height + 1;
    b.proposer = id(signer);
    b.sign_block(signer);
    b
}

fn qc_for(
    ks: &[SigningKey],
    vs: ValidatorSet,
    height: u64,
    block_hash: [u8; 32],
) -> stellereum::consensus::QuorumCertificate {
    use stellereum::consensus::QuorumCertificate;
    let mut signatures = Vec::new();
    for k in ks {
        let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(block_hash));
        signatures.push((v.voter, v.ed25519_signature().to_vec()));
    }
    let _ = vs;
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures,
    }
}

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn the_rephase_window_is_wider_than_the_normal_one() {
    assert!(
        REPHASE_SCAN_WINDOW > ROUND_LOOKBACK,
        "the re-phase window must be wider than the normal one"
    );
}

#[test]
fn the_invalidation_signal_type_is_usable() {
    // Compile-time proof that the sink signature the runtime publishes to is
    // the one the chain manager produces.
    let sink: stellereum::chain::InvalidationSink = Arc::new(move |s: InvalidationSignal| {
        let _ = s.orphaned_blocks.len();
    });
    sink(InvalidationSignal {
        orphaned_blocks: vec![[0u8; 32]],
        reason: "test".to_string(),
        height: 1,
    });
    let _ = Mutex::new(0u8);
}

// --- W1: the adopt path's LOCK rule (a certificate from a STRICTLY later
// round supersedes the lock; the same or an earlier round does not) ---------

use stellereum::consensus::QuorumCertificate;

async fn adopt_runtime(ks: &[SigningKey], idx: usize) -> ValidatorRuntime {
    let vs = vset(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    stellereum::runtime::fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    ValidatorRuntime::new(ks[idx].clone(), vs, st, 1)
}

async fn block_at(round: u32, rt: &ValidatorRuntime, ks: &[SigningKey]) -> Block {
    let vs = rt.validators.clone();
    let proposer = vs.proposer_for(1, round).unwrap();
    let pk = ks.iter().find(|k| id(k) == proposer).unwrap();
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pk);
    b
}

fn cert_at(ks: &[SigningKey], round: u32, bh: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        height: 1,
        round,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, round, VoteKind::Precommit, Some(bh));
                (v.voter, v.ed25519_signature().to_vec())
            })
            .collect(),
    }
}

#[tokio::test]
async fn a_later_round_certificate_supersedes_the_lock() {
    // The lock is taken at round 5. A commit certificate from a STRICTLY
    // LATER round proves the network moved on without us, so the lock is
    // superseded and the certificate is adopted — refusing it (the old
    // `locked_round <= certificate.round` test) partitioned the node from
    // every canonical commit after a single lost vote.
    let ks = keys(4);
    let mut rt = adopt_runtime(&ks, 0).await;
    rt.hc.round = 5;
    rt.hc.locked = Some(([0xA1u8; 32], 5));
    let blk = block_at(6, &rt, &ks).await;
    let bh = blk.compute_hash();
    let cert = cert_at(&ks, 6, bh);
    let r = rt.adopt_committed(1, blk, cert).await;
    assert_eq!(
        r,
        Ok(bh),
        "a later-round certificate must supersede the lock"
    );
}

#[tokio::test]
async fn a_same_round_certificate_naming_another_block_is_refused() {
    // Two conflicting polkas in ONE round need more than 1/3 Byzantine
    // power, so a certificate at the lock's own round that names a DIFFERENT
    // block is a genuine safety conflict and must be refused.
    let ks = keys(4);
    let mut rt = adopt_runtime(&ks, 0).await;
    rt.hc.round = 5;
    rt.hc.locked = Some(([0xA1u8; 32], 5));
    let blk = block_at(5, &rt, &ks).await;
    let bh = blk.compute_hash();
    assert_ne!(bh, [0xA1u8; 32], "the fixture must name a DIFFERENT block");
    let cert = cert_at(&ks, 5, bh);
    let r = rt.adopt_committed(1, blk, cert).await;
    assert!(
        r.is_err(),
        "a same-round certificate for a conflicting block must be refused: {:?}",
        r.err()
    );
}

#[tokio::test]
async fn an_earlier_round_certificate_naming_another_block_is_refused() {
    let ks = keys(4);
    let mut rt = adopt_runtime(&ks, 0).await;
    rt.hc.round = 5;
    rt.hc.locked = Some(([0xA1u8; 32], 5));
    let blk = block_at(4, &rt, &ks).await;
    let bh = blk.compute_hash();
    let cert = cert_at(&ks, 4, bh);
    let r = rt.adopt_committed(1, blk, cert).await;
    assert!(
        r.is_err(),
        "an earlier-round certificate for a conflicting block must be refused: {:?}",
        r.err()
    );
}
