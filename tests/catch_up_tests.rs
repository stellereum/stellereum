//! Catch-up: a node that fell behind must be able to replay the gap and land on
//! exactly the same state as its peer.
//!
//! This is the mechanism behind the fix for the two-machine stand, where a
//! one-block height skew deadlocked the pair permanently: both nodes sat in view
//! changes at their own heights, each rejecting the other's proposal as
//! `wrong height`, and the only recovery was a coordinated wipe of both data
//! directories.
//!
//! The pieces are `collect_missing_blocks` (walk `prev_hash` back to our own
//! finalized block), `validate_sync_chain` (refuse a fork, refuse a chain
//! without a real quorum), and then applying each block after checking that its
//! header commits to the state root we actually hold. These tests pin that
//! sequence end to end, including the cases that must NOT be accepted.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use stellereum::cell::CellHash;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{collect_missing_blocks, validate_sync_chain};

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

async fn state_with_funds(who: [u8; 32], bal: u64) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(who, bal)).await;
    st
}

/// Build `n` empty blocks on top of `base`, each signed by enough of `ks` to carry
/// a real quorum, and each committing to the state root in force *before* it.
async fn build_chain(ks: &[SigningKey], base: &Arc<InMemoryStateEngine>, n: u64) -> Vec<Block> {
    let vs = vset(ks);
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let root = base.get_state_root().await;
        // F8: the proposer must be the one the deterministic schedule names for
        // (height, round); validate_sync_chain now enforces it.
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer = ks
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member")
            .clone();
        let mut b = Block {
            shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000 + h,
            proposer: proposer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&proposer);
        // Real quorum, carried as the block's precommit QC: validate_sync_chain must
        // be able to tell a genuine history from a single-peer forgery, and it checks
        // the attached QC -- not extra block-hash signatures, which prove nothing
        // about agreement (votes are over vote_sign_bytes, a different message).
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, h, bh);
        let _ = &vs;
        prev = b.compute_hash();
        out.push(b);
    }
    out
}

/// Attach a genuine precommit QC from `ks` for block `b` at `height`.
fn attach_quorum(b: &mut Block, ks: &[SigningKey], height: u64, bh: [u8; 32]) {
    let sigs = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    });
}

fn store(blocks: &[Block]) -> HashMap<[u8; 32], Block> {
    blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect()
}

/// The catch-up sequence as the node performs it.
async fn catch_up(
    blocks: &[Block],
    our_state: &Arc<InMemoryStateEngine>,
    our_last: [u8; 32],
    first_height: u64,
    validators: &ValidatorSet,
) -> Result<u64, String> {
    let head = blocks.last().ok_or("empty chain")?.compute_hash();
    let map = store(blocks);
    let missing = collect_missing_blocks(head, our_last, 100_000, move |h| {
        let m = map.clone();
        async move { m.get(&h).cloned() }
    })
    .await?;
    if missing.is_empty() {
        return Ok(0);
    }
    let first = missing[0].height;
    if first != first_height {
        return Err(format!(
            "first synced height {first} != expected {first_height}"
        ));
    }
    validate_sync_chain(&missing, first, our_last, validators)?;
    for b in &missing {
        let root_before = our_state.get_state_root().await;
        if root_before != b.state_root {
            return Err(format!(
                "block {} commits to {} but our state is {}",
                b.height,
                hex::encode(b.state_root),
                hex::encode(root_before)
            ));
        }
        our_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }
    Ok(missing.len() as u64)
}

#[tokio::test]
async fn a_lagging_node_replays_the_gap_and_lands_on_the_peers_state_root() {
    let ks = keys(4);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &base, 12).await;

    // We are stuck three blocks behind, which is the smallest skew that used to
    // deadlock the pair for good.
    let we_have = 9u64;
    let our_last = blocks[(we_have - 1) as usize].compute_hash();
    let our_state = state_with_funds(payer, 1_000_000_000_000).await;
    // Our root must match the chain we are rejoining, so replay the prefix.
    for b in blocks.iter().take(we_have as usize) {
        assert_eq!(
            our_state.get_state_root().await,
            b.state_root,
            "prefix replay must reproduce the chain's roots"
        );
        our_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }

    let n = catch_up(&blocks, &our_state, our_last, we_have + 1, &vs)
        .await
        .expect("catch-up must succeed");
    assert_eq!(n, 3, "exactly the three missing blocks are replayed");

    let peer_root = blocks.last().unwrap().state_root;
    let our_root: CellHash = our_state.get_state_root().await;
    assert_eq!(
        our_root, peer_root,
        "after catch-up the lagging node's state root equals its peer's"
    );
}

#[tokio::test]
async fn a_gap_of_one_block_is_enough_to_recover() {
    let ks = keys(3);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &base, 5).await;

    let our_last = blocks[3].compute_hash(); // we have 4 of 5
    let our_state = state_with_funds(payer, 1_000_000_000_000).await;
    for b in blocks.iter().take(4) {
        our_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }

    let n = catch_up(&blocks, &our_state, our_last, 5, &vs)
        .await
        .expect("a one-block gap must heal");
    assert_eq!(n, 1);
    assert_eq!(
        our_state.get_state_root().await,
        blocks.last().unwrap().state_root
    );
}

#[tokio::test]
async fn catch_up_refuses_a_chain_that_forks_before_our_finalized_block() {
    let ks = keys(4);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let honest = build_chain(&ks, &base, 10).await;

    // A peer hands us a history that replaces block 6, so it no longer links to
    // the last block we finalized. This is the fork the guard exists for.
    let mut forked = honest[..5].to_vec();
    let root = base.get_state_root().await;
    let proposer = ks[0].clone();
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: 6,
        prev_hash: [0xAB; 32], // not our block 5
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 2_000,
        proposer: proposer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(&proposer);
    let bh = b.compute_hash();
    attach_quorum(&mut b, &ks, 6, bh);
    forked.push(b);
    forked.extend(honest[6..].iter().cloned());

    let our_last = honest[4].compute_hash();
    let our_state = state_with_funds(payer, 1_000_000_000_000).await;
    for blk in honest.iter().take(5) {
        our_state
            .apply_block_parallel_fees(&blk.transactions, blk.timestamp)
            .await;
    }
    let before = our_state.get_state_root().await;

    let res = catch_up(&forked, &our_state, our_last, 6, &vs).await;
    assert!(res.is_err(), "a fork must be refused: {res:?}");
    assert_eq!(
        our_state.get_state_root().await,
        before,
        "a refused chain must leave our state untouched"
    );
}

#[tokio::test]
async fn catch_up_refuses_a_chain_with_no_real_quorum() {
    let ks = keys(4);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &base, 6).await;

    // One peer signs everything. The forgery replaces the whole decision proof
    // with a single-signer's QC: one member cannot reach a 4-member quorum, no
    // matter how the block-signature list looks.
    let liar = ks[1].clone();
    let mut forged = blocks.clone();
    for b in forged.iter_mut().skip(3) {
        let bh = b.compute_hash();
        let v = Vote::sign(&liar, b.height, 0, VoteKind::Precommit, Some(bh));
        b.precommit_qc = Some(QuorumCertificate {
            height: b.height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: vec![(v.voter, v.signature)],
        });
    }

    let our_last = blocks[2].compute_hash();
    let our_state = state_with_funds(payer, 1_000_000_000_000).await;
    for b in blocks.iter().take(3) {
        our_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }
    let before = our_state.get_state_root().await;

    let res = catch_up(&forged, &our_state, our_last, 4, &vs).await;
    assert!(
        res.is_err(),
        "a single-signer history must be refused: {res:?}"
    );
    assert_eq!(our_state.get_state_root().await, before);
}

#[tokio::test]
async fn catch_up_refuses_a_block_whose_header_disagrees_with_our_state() {
    let ks = keys(3);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let mut blocks = build_chain(&ks, &base, 5).await;

    // Our node holds a different state than the header claims, so replaying
    // would corrupt consensus. The root check has to catch it.
    let our_last = blocks[1].compute_hash();
    blocks[2].state_root = [0xDE; 32];

    let our_state = state_with_funds(payer, 1_000_000_000_000).await;
    for b in blocks.iter().take(2) {
        our_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }
    let before = our_state.get_state_root().await;

    let res = catch_up(&blocks, &our_state, our_last, 3, &vs).await;
    assert!(
        res.is_err(),
        "a state-root disagreement must be refused: {res:?}"
    );
    assert_eq!(our_state.get_state_root().await, before);
}

#[tokio::test]
async fn a_missing_body_in_the_middle_is_reported_not_silently_skipped() {
    // This is the live failure mode on the two-machine stand: the head pointer is
    // discoverable but a block body was never published to the DHT. The node has
    // to say so rather than advance a partial chain.
    let ks = keys(3);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &base, 6).await;

    let head = blocks.last().unwrap().compute_hash();
    let our_last = blocks[1].compute_hash();
    let full = store(&blocks);
    let missing_hash = blocks[3].compute_hash();
    let partial: HashMap<[u8; 32], Block> = full
        .iter()
        .filter(|(h, _)| **h != missing_hash)
        .map(|(h, b)| (*h, b.clone()))
        .collect();

    let err = collect_missing_blocks(head, our_last, 1000, move |h| {
        let p = partial.clone();
        async move { p.get(&h).cloned() }
    })
    .await
    .expect_err("a hole in the middle must be an error, not a short chain");

    assert!(
        err.contains("missing block") || err.contains("missing"),
        "the error must name the missing block: {err}"
    );
    assert!(err.contains(&hex::encode(missing_hash)[..16]));
    let _ = vs;
    let _ = Transaction::sign;
}
