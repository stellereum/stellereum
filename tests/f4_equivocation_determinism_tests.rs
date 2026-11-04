//! Audit finding F4 — equivocation slashing must be a function of the BLOCK,
//! not of which conflicting votes a particular node happened to receive.
//!
//! Before the fix, `apply_equivocation_slashes` iterated `self.hc.equivocations()`:
//! a node that finalized a height locally had observed the double-vote and
//! slashed the offender, while a node that reached the SAME height by adopting,
//! walking, or replaying the block burned nothing. That is a different state root
//! from the same block, i.e. a chain split a single Byzantine double-voter can
//! trigger by choosing gossip delivery.
//!
//! The fix (approach B) removes local-observation equivocation slashing from
//! every state transition; it is deferred until the evidence can travel inside
//! the block as verifiable content. These tests prove the four routes now end on
//! IDENTICAL state roots even when one of them holds double-vote evidence the
//! others never saw.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const BAL: u64 = 10_000_000_000_000;

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

async fn funded(ks: &[SigningKey]) -> Arc<InMemoryStateEngine> {
    let vs = vset(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, BAL).await;
    st
}

fn mkblock(pkey: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: pkey.verifying_key().to_bytes(),
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

fn proposer_key<'a>(ks: &'a [SigningKey], vs: &ValidatorSet, h: u64, r: u32) -> &'a SigningKey {
    let want = vs.proposer_for(h, r).expect("non-empty set has a proposer");
    ks.iter()
        .find(|k| k.verifying_key().to_bytes() == want)
        .expect("schedule proposer is one of our keys")
}

/// A genuine precommit certificate over `bh` signed by every validator in `ks`.
fn full_precommit_qc(ks: &[SigningKey], h: u64, r: u32, bh: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        height: h,
        round: r,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: ks
            .iter()
            .map(|k| {
                let v = Vote::sign(k, h, r, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

#[tokio::test]
async fn f4_all_routes_reach_identical_state_root_with_equivocation_evidence() {
    let ks = keys(4);
    let vs = vset(&ks);
    let idv = ids(&ks);
    let cheater = ks[3].clone();
    let cheater_id = idv[3];

    // Four identical engines: local finalize, adopt, walk, replay.
    let st_a = funded(&ks).await;
    let st_b = funded(&ks).await;
    let st_c = funded(&ks).await;
    let st_d = funded(&ks).await;

    for st in [&st_a, &st_b, &st_c, &st_d] {
        assert_eq!(st.get_state_root().await, st_a.get_state_root().await);
    }

    let root0 = st_a.get_state_root().await;
    let pkey = proposer_key(&ks, &vs, 1, 0).clone();
    let block = mkblock(&pkey, 1, [0u8; 32], root0);
    let bh = block.compute_hash();
    let qc = full_precommit_qc(&ks, 1, 0, bh);
    assert!(qc.verify(&vs), "precondition: certificate is genuine");

    // ---- Route A: LOCAL FINALIZE. Node A additionally observes a CONFLICTING
    // prevote from the cheater, so it genuinely holds equivocation evidence the
    // other routes never see.
    let mut a = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_a.clone(), 1);
    for k in ks.iter() {
        a.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    a.on_prevote(Vote::sign(
        &cheater,
        1,
        0,
        VoteKind::Prevote,
        Some([0x99u8; 32]),
    ))
    .unwrap();
    for k in ks.iter() {
        a.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(
        a.hc.equivocations().len(),
        1,
        "precondition: the local node holds the double-vote evidence"
    );
    assert_eq!(a.hc.try_precommit_quorum(), Some(bh));
    a.blocks.insert(bh, {
        let mut b = block.clone();
        b.precommit_qc = Some(qc.clone());
        b
    });
    assert_eq!(a.try_finalize().await, Some(bh));

    // ---- Route B: ADOPT (a peer hands us the committed block + certificate).
    let mut b = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_b.clone(), 1);
    assert!(
        b.hc.equivocations().is_empty(),
        "precondition: the adopting node never saw the conflicting vote"
    );
    assert_eq!(
        b.adopt_committed(1, block.clone(), qc.clone()).await,
        Ok(bh)
    );

    // ---- Route C: WALK (main.rs sync path: install the block's QC, advance).
    let mut c = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_c.clone(), 1);
    c.hc.precommit_qc = Some(qc.clone());
    c.blocks.insert(bh, block.clone());
    c.apply_and_advance(bh, &block).await;

    // ---- Route D: REPLAY (startup healing behind head).
    let mut d = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_d.clone(), 1);
    let block_with_qc = {
        let mut x = block.clone();
        x.precommit_qc = Some(qc.clone());
        x
    };
    d.replay_historical_block(&block_with_qc)
        .await
        .expect("replay must accept the genuine block");

    // ---- Determinism: every route must land on the SAME root.
    let ra = a.state_root().await;
    let rb = b.state_root().await;
    let rc = c.state_root().await;
    let rd = d.state_root().await;
    println!(
        "[F4] roots: local={} adopt={} walk={} replay={}",
        hex::encode(&ra[..8]),
        hex::encode(&rb[..8]),
        hex::encode(&rc[..8]),
        hex::encode(&rd[..8]),
    );
    assert_eq!(ra, rb, "F4: local finalize vs adopt differ");
    assert_eq!(ra, rc, "F4: local finalize vs walk differ");
    assert_eq!(ra, rd, "F4: local finalize vs replay differ");

    // And the offender was NOT slashed by local gossip on any route, which is the
    // whole point: the verdict no longer depends on who saw the double-vote.
    for (name, st) in [
        ("local", &st_a),
        ("adopt", &st_b),
        ("walk", &st_c),
        ("replay", &st_d),
    ] {
        let l = st.staking_read().await;
        assert_eq!(l.total_burned, 0, "F4: {name} route burned stake");
        assert_eq!(
            l.validators[&cheater_id].total_slashed, 0,
            "F4: {name} route slashed the double-voter from local evidence"
        );
        assert_eq!(
            l.validators[&cheater_id].self_bond,
            BAL.min(stellereum::runtime::GENESIS_VALIDATOR_BOND),
            "F4: {name} route altered the offender's bond"
        );
    }
    assert_eq!(ra, rb);
}

/// The transition must not consume local equivocation evidence even when the
/// node holds it: recording a double-vote and running the FULL finalize
/// transition leaves the offender's bond and the global burn counter untouched.
#[tokio::test]
async fn f4_local_finalize_ignores_observed_equivocation() {
    let ks = keys(4);
    let vs = vset(&ks);
    let cheater = ks[3].clone();
    let cheater_id = cheater.verifying_key().to_bytes();
    let st = funded(&ks).await;

    let root0 = st.get_state_root().await;
    let pkey = proposer_key(&ks, &vs, 1, 0).clone();
    let block = mkblock(&pkey, 1, [0u8; 32], root0);
    let bh = block.compute_hash();
    let qc = full_precommit_qc(&ks, 1, 0, bh);

    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);
    // A quorum prevotes the block...
    for k in ks.iter() {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    // ...and the cheater ALSO sends a conflicting second prevote, observed
    // locally. The first prevote stays counted for quorum; the second is
    // recorded as evidence.
    rt.on_prevote(Vote::sign(
        &cheater,
        1,
        0,
        VoteKind::Prevote,
        Some([0x77u8; 32]),
    ))
    .unwrap();
    let victim_evidence = rt.hc.equivocations();
    assert_eq!(victim_evidence.len(), 1);
    assert!(victim_evidence[0].1.verify() && victim_evidence[0].2.verify());

    for k in ks.iter() {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(rt.hc.try_precommit_quorum(), Some(bh));
    rt.blocks.insert(bh, {
        let mut x = block.clone();
        x.precommit_qc = Some(qc);
        x
    });
    assert_eq!(rt.try_finalize().await, Some(bh));

    let l = st.staking_read().await;
    assert_eq!(l.total_burned, 0, "F4: local evidence must not burn");
    assert_eq!(l.validators[&cheater_id].total_slashed, 0);
}
