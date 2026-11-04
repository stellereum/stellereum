//! `None` downtime evidence must mean the same thing on every apply path.
//!
//! LIVE (2026-10-25, masterchain stalls #304133 / #304395): the same block
//! hash finalized with DIFFERENT post-state roots on different nodes
//! (`DIVERGENCE height=... same finalized hash, different post-state`), the
//! cluster split 2-2 with neither side holding quorum, and both chains
//! stalled. The blocks at the fork point carried `last_qc: None` — proposed
//! by nodes restored/healed without finalizing since, which know no parent
//! decision (`ValidatorRuntime::decided_parent_qc`).
//!
//! The live finalize path (`try_finalize` -> `apply_block_fees_rewards` ->
//! `InMemoryStateEngine::apply_block_transition`) treats `None` evidence as
//! a deterministic SKIP (no height's downtime is attributed). The replay
//! path (`ValidatorRuntime::replay_historical_block`), used by startup
//! healing and catch-up, applied a LEGACY fallback for the exact same
//! `None` blocks: `state.apply_downtime_slash(height,
//! block.precommit_qc)` — burning stake from a LOCALLY-observed finality QC
//! subset. Same block bytes, different post-state roots by route: a replay
//! forks off the live chain on the first `None`-evidence block whose QC
//! omits any validator parked at the miss threshold.
//!
//! These tests pin the parity: a `None`-evidence block with a 3-of-4 QC
//! (one silent validator one miss short of the threshold) applied through
//! all four routes — local finalize, adopt, walk, replay — must land on
//! IDENTICAL state roots with NOTHING burned. Fails before the fix (replay
//! burns, the other three skip), passes after (replay skips like live).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::{DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND, STAKING_POOL};
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

/// Four byte-identical engines: genesis-funded, staking pool funded (the
/// slash debit is real coins), and the silent validator parked ONE miss
/// short of the downtime threshold — so the FIRST certificate that
/// attributes downtime burns, and any route that skips attribution lands
/// on a visibly different root.
async fn parked_engines(ks: &[SigningKey], silent: &[u8; 32]) -> Vec<Arc<InMemoryStateEngine>> {
    let vs = vset(ks);
    let mut out = Vec::new();
    for _ in 0..4 {
        let st = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&st, &vs, BAL).await;
        st.credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("pool credit");
        {
            let mut l = st.staking_write().await;
            let rec = l.validators.get_mut(silent).expect("silent is bonded");
            rec.missed = DOWNTIME_MISS_THRESHOLD - 1;
            rec.last_downtime_penalty = 0;
        }
        out.push(st);
    }
    let root0 = out[0].get_state_root().await;
    for (i, e) in out.iter().enumerate() {
        assert_eq!(
            e.get_state_root().await,
            root0,
            "precondition: engine {i} must start byte-identical to engine 0"
        );
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
        timestamp: 1_000,
        proposer: pkey.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        // Post-upgrade resynced-proposer shape: the proposer knew no parent
        // decision, so no canonical evidence travels with the block.
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pkey);
    b
}

/// A genuine 3-of-4 precommit QC over `bh` (the silent validator omitted).
fn three_of_four_qc(ks: &[SigningKey], h: u64, r: u32, bh: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        height: h,
        round: r,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: ks[..3]
            .iter()
            .map(|k| {
                let v = Vote::sign(k, h, r, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

#[tokio::test]
async fn none_evidence_block_reaches_identical_roots_on_all_four_routes() {
    let ks = keys(4);
    let vs = vset(&ks);
    let silent_id = ks[3].verifying_key().to_bytes();

    let engines = parked_engines(&ks, &silent_id).await;
    let (st_live, st_adopt, st_walk, st_replay) = (
        engines[0].clone(),
        engines[1].clone(),
        engines[2].clone(),
        engines[3].clone(),
    );

    let root0 = st_live.get_state_root().await;
    let pkey = vs
        .proposer_for(1, 0)
        .and_then(|want| ks.iter().find(|k| k.verifying_key().to_bytes() == want))
        .cloned()
        .expect("schedule proposer is one of our keys");
    let block = mkblock(&pkey, 1, [0u8; 32], root0);
    let bh = block.compute_hash();
    let qc = three_of_four_qc(&ks, 1, 0, bh);
    assert!(
        qc.verify(&vs),
        "precondition: 3-of-4 certificate is genuine"
    );

    // ---- Route LIVE: local finalize. ----
    let mut live = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_live.clone(), 1);
    for k in ks[..3].iter() {
        live.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .expect("prevote accepted");
        live.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .expect("precommit accepted");
    }
    assert_eq!(live.hc.try_precommit_quorum(), Some(bh));
    live.blocks.insert(bh, {
        let mut b = block.clone();
        b.precommit_qc = Some(qc.clone());
        b
    });
    assert_eq!(live.try_finalize().await, Some(bh));

    // ---- Route ADOPT: a peer hands us the committed block + certificate. ----
    let mut adopt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_adopt.clone(), 1);
    assert_eq!(
        adopt.adopt_committed(1, block.clone(), qc.clone()).await,
        Ok(bh)
    );

    // ---- Route WALK: sync path, install the QC and advance. ----
    let mut walk = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_walk.clone(), 1);
    walk.hc.precommit_qc = Some(qc.clone());
    walk.blocks.insert(bh, block.clone());
    walk.apply_and_advance(bh, &block).await;

    // ---- Route REPLAY: startup healing behind head. ----
    let mut replay = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st_replay.clone(), 1);
    replay
        .replay_historical_block(&{
            let mut x = block.clone();
            x.precommit_qc = Some(qc.clone());
            x
        })
        .await
        .expect("replay must accept the genuine block");

    // ---- Parity: every route must land on the SAME root ... ----
    let (rl, ra, rw, rr) = (
        st_live.get_state_root().await,
        st_adopt.get_state_root().await,
        st_walk.get_state_root().await,
        st_replay.get_state_root().await,
    );
    println!(
        "[none-evidence] roots: live={} adopt={} walk={} replay={}",
        hex::encode(&rl[..8]),
        hex::encode(&ra[..8]),
        hex::encode(&rw[..8]),
        hex::encode(&rr[..8]),
    );
    assert_eq!(
        rl, ra,
        "live finalize vs adopt differ on a None-evidence block"
    );
    assert_eq!(
        rl, rw,
        "live finalize vs walk differ on a None-evidence block"
    );
    assert_eq!(
        rl, rr,
        "live finalize vs REPLAY differ on a None-evidence block: \
         replay applies legacy downtime slash while live skips (same-hash fork)"
    );

    // ---- ... with NOTHING burned anywhere: `None` evidence attributes no height. ----
    for (name, st) in [
        ("live", &st_live),
        ("adopt", &st_adopt),
        ("walk", &st_walk),
        ("replay", &st_replay),
    ] {
        let l = st.staking_read().await;
        assert_eq!(
            l.total_burned, 0,
            "{name} route burned stake on None evidence"
        );
        let rec = l.validators.get(&silent_id).expect("silent still bonded");
        assert_eq!(
            rec.missed,
            DOWNTIME_MISS_THRESHOLD - 1,
            "{name} route moved the silent validator's miss counter on None evidence"
        );
    }
}
