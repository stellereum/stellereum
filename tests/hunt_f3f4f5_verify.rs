//! VERIFY-ONLY: sync-surface HIGHs F3 / F4 / F5 (reported fixed-or-open).
//!
//! READ-ONLY wrt `src/` — this file only *calls* public guards, it duplicates
//! no implementation.
//!
//! * F3(a) advertised-body desync — FIXED (`collect_missing_blocks` rejects a
//!   body that does not hash to the requested key, src/sync.rs:48-55).
//! * F3(b) advertised-head desync — FIXED (`walked_head_anchor` re-anchors on
//!   the WALKED tail, src/sync.rs:229-253). NOTE: the A1 QC-hardening of the
//!   snapshot anchor (`verify_finality_for_header`, `HeaderLink::{proposer,qc}`,
//!   `max_span`) is in-progress work by another engineer on this branch
//!   (uncommitted `M src/sync.rs`); this file deliberately does NOT cover it.
//! * F4 equivocation-slash wiring gap — FIXED as "unwired by design":
//!   `apply_equivocation_slashes` exists but is called from NO state-transition
//!   path (`try_finalize` / `apply_and_advance` / `replay_historical_block` /
//!   adopt / walk); determinism is preserved by not slashing until evidence
//!   travels in-block (hardfork, src/runtime.rs:745-776 + §10.52 handoff note).
//! * F5 height-pinned validator set — STILL OPEN (documented limitation +
//!   `TODO(F5)` at src/sync.rs:270-281). The PoC below is `#[ignore]`d.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::MIN_VALIDATOR_BOND;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{collect_missing_blocks, validate_sync_chain, walked_head_anchor};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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

/// Plain signed block (no QC): enough for the walk / anchor guards.
fn bare_block(k: &SigningKey, h: u64, prev: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: [h as u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: h,
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

/// Full QC-carrying block from the CURRENT set's schedule proposer (passes
/// `validate_sync_chain`, incl. the F8 proposer-schedule gate).
fn qc_block(
    ks: &[SigningKey],
    vs: &ValidatorSet,
    h: u64,
    prev: [u8; 32],
    state_root: [u8; 32],
) -> Block {
    let want = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
    let pkey = ks
        .iter()
        .find(|k| k.verifying_key().to_bytes() == want)
        .expect("schedule proposer is one of our keys");
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: h,
        proposer: want,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pkey);
    let hash = b.compute_hash();
    let sigs = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, h, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(stellereum::consensus::QuorumCertificate {
        height: h,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: sigs,
    });
    b
}

// ---------------------------------------------------------------------------
// F3(a) FIXED: fetch-boundary hash check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f3a_fixed_mismatched_body_rejected_at_fetch_boundary() {
    let k = keys(1);
    let mut prev = [0u8; 32];
    let mut blocks = Vec::new();
    for h in 0..=3u64 {
        let b = bare_block(&k[0], h, prev);
        prev = b.compute_hash();
        blocks.push(b);
    }
    let map: HashMap<[u8; 32], Block> = blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect();
    let genesis = blocks[0].compute_hash();
    let head = blocks[3].compute_hash();

    // Honest fetch walks ancestor-first.
    let got = collect_missing_blocks(head, genesis, 100, |h| {
        let b = map.get(&h).cloned();
        async move { b }
    })
    .await
    .expect("honest walk must succeed");
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].height, 1);

    // Poisoned fetch: every key serves block #1's body. Must be refused.
    let impostor = blocks[1].clone();
    let err = collect_missing_blocks(head, genesis, 100, move |_h| {
        let b = impostor.clone();
        async move { Some(b) }
    })
    .await
    .expect_err("F3(a): body filed under the wrong hash must be refused");
    assert!(
        err.contains("does not hash"),
        "F3(a) guard names the mismatch: {err}"
    );
    println!("[F3(a) FIXED] {err}");
}

// ---------------------------------------------------------------------------
// F3(b) FIXED: walked-tail anchor (A1 QC-hardening owned by another engineer)
// ---------------------------------------------------------------------------

#[test]
fn f3b_fixed_advertised_head_must_equal_walked_tail() {
    let k = keys(1);
    let mut prev = [0u8; 32];
    let mut blocks = Vec::new();
    for h in 0..=5u64 {
        let b = bare_block(&k[0], h, prev);
        prev = b.compute_hash();
        blocks.push(b);
    }
    let head_hash = blocks[5].compute_hash();

    // Peer advertises a height above what it served: refuse, do not re-anchor.
    let err = walked_head_anchor(&blocks, head_hash, 9)
        .expect_err("F3(b): advertised height above walked head must be refused");
    assert!(err.contains("advertised"), "names the desync: {err}");

    // Walked tail not hashing to the advertised head: refuse.
    let err2 = walked_head_anchor(&blocks, [0xABu8; 32], 5)
        .expect_err("F3(b): hash mismatch must be refused");
    assert!(err2.contains("does not hash"), "names the mismatch: {err2}");

    // Honest case re-anchors on walked height + 1 (never on the claim).
    assert_eq!(walked_head_anchor(&blocks, head_hash, 5).unwrap(), 6);
    println!("[F3(b) FIXED] desync refused; honest anchor = 6");
}

// ---------------------------------------------------------------------------
// F4 FIXED (unwired by design): asymmetric local evidence, identical roots
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f4_fixed_no_path_slashes_on_local_equivocation_evidence() {
    let ks = keys(4);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let bal = 10_000 * MIN_VALIDATOR_BOND;
    let mut nodes = Vec::new();
    for k in &ks {
        let st = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&st, &vs, bal).await;
        st.update_account(AccountState::new(payer, bal)).await;
        nodes.push(ValidatorRuntime::new(k.clone(), vs.clone(), st, 1));
    }
    let root = nodes[0].state.get_state_root().await;
    let blk = bare_block(&ks[0], 1, [0u8; 32]);
    // Commit to the live root like other F4 tests do (F3.2 parent binding).
    let mut blk = blk;
    blk.state_root = root;
    blk.sign_block(&ks[0]);
    let bh = blk.compute_hash();

    for n in nodes.iter_mut() {
        for k in ks.iter().take(3) {
            n.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
                .unwrap();
        }
        for k in ks.iter().take(3) {
            n.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
                .unwrap();
        }
    }
    nodes[0].blocks.insert(bh, blk.clone());
    nodes[1].blocks.insert(bh, blk.clone());

    // Attacker shows the conflicting vote ONLY to node 0.
    let v1 = Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some(bh));
    let v2 = Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some([0x99u8; 32]));
    nodes[0].on_prevote(v1.clone()).unwrap();
    nodes[1].on_prevote(v1.clone()).unwrap();
    nodes[0].on_prevote(v2.clone()).unwrap();

    assert_eq!(
        nodes[0].hc.equivocations().len(),
        1,
        "precondition: node 0 holds the double-vote evidence"
    );
    assert!(
        nodes[1].hc.equivocations().is_empty(),
        "precondition: node 1 never saw the conflict"
    );

    let burn0_before = nodes[0].state.staking_read().await.total_burned;
    let burn1_before = nodes[1].state.staking_read().await.total_burned;
    assert_eq!(nodes[0].try_finalize().await, Some(bh));
    assert_eq!(nodes[1].try_finalize().await, Some(bh));
    let burn0 = nodes[0].state.staking_read().await.total_burned - burn0_before;
    let burn1 = nodes[1].state.staking_read().await.total_burned - burn1_before;
    let s0 =
        nodes[0].state.staking_read().await.validators[&ks[3].verifying_key().to_bytes()].self_bond;
    let s1 =
        nodes[1].state.staking_read().await.validators[&ks[3].verifying_key().to_bytes()].self_bond;
    let r0 = nodes[0].state.get_state_root().await;
    let r1 = nodes[1].state.get_state_root().await;

    assert_eq!(burn0, 0, "F4: local evidence must not slash on finalize");
    assert_eq!(burn1, 0, "F4: no-evidence path burns nothing");
    assert_eq!(s0, s1, "F4: both nodes agree on the double-voter's bond");
    assert_eq!(r0, r1, "F4: same block => same root regardless of gossip");
    println!("[F4 FIXED] burn 0/0, roots agree {}", hex::encode(&r0[..8]));
}

// ---------------------------------------------------------------------------
// F5 STILL OPEN: QC checked against the CALLER's (current) set, not set-at-height
// ---------------------------------------------------------------------------

/// PoC of the documented residual (src/sync.rs `TODO(F5)`): a quorum of the
/// CURRENT set can vouch for ANY old heights and `validate_sync_chain`
/// accepts — history is malleable by whoever holds power NOW. Two competing
/// chains for heights 8..=9, both fully signed by the current set, BOTH pass.
#[tokio::test]
#[ignore = "F5 OPEN (TODO(F5) src/sync.rs:270-281): documents the residual — \
current-set quorum vouches for old heights. Ignored so it cannot gate CI \
until per-height set snapshots land."]
async fn f5_open_current_quorum_rewrites_old_heights() {
    let ks = keys(4);
    let current = vset(&ks);
    let anchor = [0u8; 32]; // our finalized hash before height 8

    let a8 = qc_block(&ks, &current, 8, anchor, [0xAAu8; 32]);
    let a8h = a8.compute_hash();
    let chain_a = vec![a8, qc_block(&ks, &current, 9, a8h, [0xAAu8; 32])];
    let b8 = qc_block(&ks, &current, 8, anchor, [0xBBu8; 32]);
    let b8h = b8.compute_hash();
    let chain_b = vec![b8, qc_block(&ks, &current, 9, b8h, [0xBBu8; 32])];
    assert_ne!(
        chain_a[1].compute_hash(),
        chain_b[1].compute_hash(),
        "precondition: competing histories"
    );

    // THE HOLE: both validate under the current set — nothing pins QCs to
    // the set that held power at heights 8..=9.
    assert!(
        validate_sync_chain(&chain_a, 8, anchor, &current).is_ok(),
        "chain A (current set) validates"
    );
    assert!(
        validate_sync_chain(&chain_b, 8, anchor, &current).is_ok(),
        "F5 HOLE: competing chain B (same current set, different bodies) \
         ALSO validates — old heights are whatever the current quorum says"
    );
    println!("[F5 OPEN] current quorum rewrites heights 8..=9 at will");
}
