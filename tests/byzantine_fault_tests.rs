//! Byzantine fault tolerance: 4-validator in-process cluster tests.
//!
//! QUORUM MATH (assumed throughout):
//!   n = 4, every validator has power 1  =>  total = 4
//!   quorum_power() = floor(2*total/3) + 1 = floor(8/3) + 1 = 3
//!   faults tolerated F = n - quorum = 1.
//! So: any 3 validators finalize; any 2 cannot; 1 faulty (down or
//! equivocating) is survivable. The 2-validator live stand runs on unanimity
//! (quorum 2 of 2, F = 0); these tests prove the 4-set tolerates F = 1.
//!
//! Construction reuses the hunt_* cluster pattern: `keys()`, `vset()`,
//! `cluster()` (fresh funded state engine per node via `fund_genesis`),
//! `mkblock()` signed by the scheduled proposer, `Vote::sign`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const BAL: u64 = 10_000_000_000_000;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

/// Four nodes, each with its OWN funded state engine (nodes never share state).
async fn cluster(ks: &[SigningKey]) -> Vec<ValidatorRuntime> {
    let vs = vset(ks);
    let mut out = Vec::new();
    for k in ks {
        let st = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&st, &vs, BAL).await;
        out.push(ValidatorRuntime::new(k.clone(), vs.clone(), st, 1));
    }
    out
}

fn mkblock(pkey: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000 + h,
        proposer: id(pkey),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pkey);
    b
}

fn idx_of(ks: &[SigningKey], target: [u8; 32]) -> usize {
    ks.iter()
        .position(|k| id(k) == target)
        .expect("proposer is one of our keys")
}

/// Drive one consensus round at the recipients' current height:
/// the scheduled proposer authors the block, `voters` prevote+precommit,
/// everything is delivered to `recipients`, then each recipient finalizes.
/// Returns (block hash, per-recipient finalize outcome).
async fn drive_round(
    nodes: &mut [ValidatorRuntime],
    ks: &[SigningKey],
    voters: &[usize],
    recipients: &[usize],
) -> ([u8; 32], Vec<Option<[u8; 32]>>) {
    let h = nodes[recipients[0]].height();
    for &r in recipients {
        assert_eq!(nodes[r].height(), h, "recipients must share a height");
    }
    let proposer_id = nodes[recipients[0]]
        .validators
        .proposer_for(h, 0)
        .expect("a proposer");
    let pkey = ks[idx_of(ks, proposer_id)].clone();

    // All recipients must agree on the parent state, else the proposal is
    // invalid for someone (validate_proposal checks the header root).
    let root = nodes[recipients[0]].state.get_state_root().await;
    for &r in recipients {
        assert_eq!(
            nodes[r].state.get_state_root().await,
            root,
            "recipients must share a state root before the round"
        );
    }
    let prev = nodes[recipients[0]]
        .finalized
        .last()
        .map(|(_, h)| *h)
        .unwrap_or([0u8; 32]);

    let mut block = mkblock(&pkey, h, prev, root);
    // Canonical downtime evidence (W10.5): production `propose()` embeds the
    // QC that decided the parent (`decided_parent_qc`), and receivers that
    // know the parent decision REFUSE a block that omits it
    // (`check_last_qc_evidence`). A hand-rolled driver must embed it too.
    // Prefer the proposer's own `last_decision`; when the scheduled proposer
    // is itself offline (down/silent tests force this), fall back to any live
    // recipient's decision for the parent — all live nodes agree on it, and
    // an offline proposer has none to offer. Genesis child (h == 1) carries
    // none, exactly like production.
    if h > 1 {
        let evidence = nodes
            .iter()
            .find(|n| n.id == proposer_id)
            .and_then(|n| n.last_decision.clone())
            .and_then(|(dh, _, qc)| if dh + 1 == h { Some(qc) } else { None })
            .or_else(|| {
                recipients
                    .iter()
                    .filter_map(|&r| nodes[r].last_decision.clone())
                    .find(|(dh, _, _)| *dh + 1 == h)
                    .map(|(_, _, qc)| qc)
            });
        block.last_qc = evidence;
        // The block hash commits to the evidence: re-sign after embedding
        // (`sign_block` appends, so clear the pre-evidence signature first).
        block.validator_signatures.clear();
        block.sign_block(&pkey);
    }
    let bh = block.compute_hash();

    // Distribute the proposal (the proposer keeps its own, as propose() does).
    for &r in recipients {
        if nodes[r].id == proposer_id {
            nodes[r].blocks.insert(bh, block.clone());
            nodes[r].hc.receive_proposal(proposer_id, bh).unwrap();
        } else {
            let er = nodes[r].hc.round;
            nodes[r]
                .on_proposal(proposer_id, block.clone(), er)
                .await
                .unwrap();
        }
    }
    // Votes from the live subset go to every recipient; the silent ones simply
    // never send, and nothing is delivered on their behalf.
    for &i in voters {
        let pv = Vote::sign(&ks[i], h, 0, VoteKind::Prevote, Some(bh));
        for &r in recipients {
            nodes[r].on_prevote(pv.clone()).unwrap();
        }
    }
    for &i in voters {
        let pc = Vote::sign(&ks[i], h, 0, VoteKind::Precommit, Some(bh));
        for &r in recipients {
            nodes[r].on_precommit(pc.clone()).unwrap();
        }
    }
    let mut out = Vec::new();
    for &r in recipients {
        out.push(nodes[r].try_finalize().await);
    }
    (bh, out)
}

async fn roots(nodes: &[ValidatorRuntime]) -> Vec<[u8; 32]> {
    let mut r = Vec::new();
    for n in nodes {
        r.push(n.state.get_state_root().await);
    }
    r
}

// Test 1 — 4/4 live: full quorum finalizes, all agree on hash and state root.
#[tokio::test]
async fn bft_4_of_4_finalize_and_agree() {
    let ks = keys(4);
    let vs = vset(&ks);
    assert_eq!(vs.total_power(), 4);
    assert_eq!(vs.quorum_power(), 3, "floor(2*4/3)+1 = 3; F = 4-3 = 1");
    let mut nodes = cluster(&ks).await;

    let all = vec![0usize, 1, 2, 3];
    let (bh, got) = drive_round(&mut nodes, &ks, &all, &all).await;
    for (i, g) in got.iter().enumerate() {
        assert_eq!(*g, Some(bh), "node {i} must finalize the block");
        assert_eq!(nodes[i].finalized, vec![(1u64, bh)]);
        assert_eq!(nodes[i].height(), 2, "node {i} height must advance");
    }
    let r = roots(&nodes).await;
    assert!(
        r.windows(2).all(|w| w[0] == w[1]),
        "all four state roots must agree"
    );
}

// Test 2 — 1 of 4 down: the other three still finalize; heights advance.
#[tokio::test]
async fn bft_1_down_3_finalize_liveness() {
    let ks = keys(4);
    let mut nodes = cluster(&ks).await;
    let proposer = idx_of(&ks, nodes[0].validators.proposer_for(1, 0).unwrap());
    let silent = (proposer + 1) % 4; // never the proposer, so proposals stay valid
    let live: Vec<usize> = (0..4).filter(|&i| i != silent).collect();
    assert_eq!(live.len(), 3, "quorum = 3 with F = 1 down");

    // Height 1 with one silent validator: deliver it no votes, collect none.
    let (bh1, got) = drive_round(&mut nodes, &ks, &live, &live).await;
    for &i in &live {
        assert_eq!(got[live.iter().position(|&x| x == i).unwrap()], Some(bh1));
        assert_eq!(nodes[i].height(), 2, "live node {i} must advance");
    }
    assert_eq!(nodes[silent].height(), 1, "silent node must not advance");
    assert!(nodes[silent].finalized.is_empty());

    // Height 2, still one down: liveness means heights keep advancing.
    let (bh2, got2) = drive_round(&mut nodes, &ks, &live, &live).await;
    for &i in &live {
        assert_eq!(got2[live.iter().position(|&x| x == i).unwrap()], Some(bh2));
        assert_eq!(nodes[i].height(), 3, "live node {i} must advance again");
        assert_eq!(nodes[i].finalized, vec![(1u64, bh1), (2u64, bh2)]);
    }
    let r: Vec<[u8; 32]> = {
        let mut v = Vec::new();
        for &i in &live {
            v.push(nodes[i].state.get_state_root().await);
        }
        v
    };
    assert!(r.windows(2).all(|w| w[0] == w[1]), "live nodes must agree");
}

// Test 3 — 2 of 4 down: only two vote; NOTHING finalizes (safety for F = 1).
#[tokio::test]
async fn bft_2_down_no_finalization() {
    let ks = keys(4);
    let mut nodes = cluster(&ks).await;
    let proposer = idx_of(&ks, nodes[0].validators.proposer_for(1, 0).unwrap());
    // The proposer authors but only two validators vote: 2 < quorum 3.
    let voters = vec![proposer, (proposer + 1) % 4];
    let all = vec![0usize, 1, 2, 3];

    let (_bh, got) = drive_round(&mut nodes, &ks, &voters, &all).await;
    for (i, g) in got.iter().enumerate() {
        assert_eq!(*g, None, "node {i} must NOT finalize on 2 votes");
        assert!(nodes[i].finalized.is_empty(), "node {i} commits nothing");
        assert_eq!(nodes[i].height(), 1, "node {i} height must not advance");
        assert_eq!(nodes[i].hc.decided, None);
    }
}

// Test 4 — recovery: the two silent validators come back, the chain resumes,
// all four converge on the same root.
#[tokio::test]
async fn bft_partition_heals_and_converges() {
    let ks = keys(4);
    let mut nodes = cluster(&ks).await;
    let proposer = idx_of(&ks, nodes[0].validators.proposer_for(1, 0).unwrap());
    let back_half: Vec<usize> = (0..4)
        .filter(|&i| i != proposer && i != (proposer + 1) % 4)
        .collect();
    let first_half = vec![proposer, (proposer + 1) % 4];
    let all = vec![0usize, 1, 2, 3];

    // Partitioned phase: only two vote -> no finalization anywhere.
    let (_bh, got) = drive_round(&mut nodes, &ks, &first_half, &all).await;
    assert!(
        got.iter().all(|g| g.is_none()),
        "partitioned: no quorum yet"
    );
    assert!(nodes.iter().all(|n| n.height() == 1));

    // Heal: the two silent validators' votes are delivered to everyone.
    // (Same height, same round, same block: no rotation happened anywhere
    // because nothing finalized, so every node's set and root still match.)
    let h = 1u64;
    let bh = nodes[0]
        .blocks
        .keys()
        .next()
        .copied()
        .expect("block was proposed");
    for &i in &back_half {
        let pv = Vote::sign(&ks[i], h, 0, VoteKind::Prevote, Some(bh));
        let pc = Vote::sign(&ks[i], h, 0, VoteKind::Precommit, Some(bh));
        for n in nodes.iter_mut() {
            n.on_prevote(pv.clone()).unwrap();
            n.on_precommit(pc.clone()).unwrap();
        }
    }
    for (i, n) in nodes.iter_mut().enumerate() {
        assert_eq!(
            n.try_finalize().await,
            Some(bh),
            "node {i} finalizes after heal"
        );
        assert_eq!(n.height(), 2);
        assert_eq!(n.finalized, vec![(1u64, bh)]);
    }
    let r = roots(&nodes).await;
    assert!(
        r.windows(2).all(|w| w[0] == w[1]),
        "all four converge on one root"
    );

    // The chain resumes: a full round finalizes on all four.
    let (bh2, got2) = drive_round(&mut nodes, &ks, &all, &all).await;
    assert!(
        got2.iter().all(|g| *g == Some(bh2)),
        "chain resumes post-heal"
    );
    for n in &nodes {
        assert_eq!(n.height(), 3);
    }
    let r2 = roots(&nodes).await;
    assert!(
        r2.windows(2).all(|w| w[0] == w[1]),
        "still converged at height 3"
    );
}

// Test 5 — equivocator in a 4-set: one validator double-votes; the honest
// three still finalize, and the evidence is recorded exactly once.
#[tokio::test]
async fn bft_equivocator_does_not_halt_or_multi_slash() {
    let ks = keys(4);
    let mut nodes = cluster(&ks).await;
    let proposer = idx_of(&ks, nodes[0].validators.proposer_for(1, 0).unwrap());
    let equiv = (proposer + 1) % 4; // not the proposer: its votes are noise only
    let honest: Vec<usize> = (0..4).filter(|&i| i != equiv).collect();

    // Honest round first: proposal + honest prevotes/precommits to honest nodes.
    let h = nodes[0].height();
    let proposer_id = nodes[0].validators.proposer_for(h, 0).unwrap();
    let pkey = ks[idx_of(&ks, proposer_id)].clone();
    let root = nodes[honest[0]].state.get_state_root().await;
    let block = mkblock(&pkey, h, [0u8; 32], root);
    let bh = block.compute_hash();
    let fake = [0xEEu8; 32];
    assert_ne!(bh, fake);
    for &r in &honest {
        if nodes[r].id == proposer_id {
            nodes[r].blocks.insert(bh, block.clone());
            nodes[r].hc.receive_proposal(proposer_id, bh).unwrap();
        } else {
            let er = nodes[r].hc.round;
            nodes[r]
                .on_proposal(proposer_id, block.clone(), er)
                .await
                .unwrap();
        }
    }
    for &i in &honest {
        let pv = Vote::sign(&ks[i], h, 0, VoteKind::Prevote, Some(bh));
        let pc = Vote::sign(&ks[i], h, 0, VoteKind::Precommit, Some(bh));
        for &r in &honest {
            nodes[r].on_prevote(pv.clone()).unwrap();
            nodes[r].on_precommit(pc.clone()).unwrap();
        }
    }

    // The equivocator double-prevotes (honest target, then a fake), then
    // "rebroadcasts" the conflicting vote 5 more times. Each honest node must
    // record the equivocation exactly once (the no-dedup fix), not 6 times.
    let eq_id = id(&ks[equiv]);
    let first = Vote::sign(&ks[equiv], h, 0, VoteKind::Prevote, Some(bh));
    let second = Vote::sign(&ks[equiv], h, 0, VoteKind::Prevote, Some(fake));
    for &r in &honest {
        nodes[r].on_prevote(first.clone()).unwrap();
        nodes[r].on_prevote(second.clone()).unwrap();
        for _ in 0..5 {
            nodes[r].on_prevote(second.clone()).unwrap();
        }
        let ev: Vec<_> = nodes[r].hc.equivocations();
        assert_eq!(ev.len(), 1, "node {r}: one equivocation, counted once");
        assert_eq!(ev[0].0, eq_id, "node {r}: evidence names the equivocator");
    }

    // Quorum never needed the equivocator (3 honest >= 3): all three finalize.
    for &r in &honest {
        assert_eq!(
            nodes[r].try_finalize().await,
            Some(bh),
            "honest node {r} finalizes despite the equivocator"
        );
        assert_eq!(nodes[r].height(), 2);
    }
    let rts: Vec<[u8; 32]> = {
        let mut v = Vec::new();
        for &r in &honest {
            v.push(nodes[r].state.get_state_root().await);
        }
        v
    };
    assert!(rts.windows(2).all(|w| w[0] == w[1]), "honest roots agree");
}
