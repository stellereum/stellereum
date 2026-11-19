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
use stellereum::consensus::{
    register_validator_pq_key, QuorumCertificate, ValidatorSet, Vote, VoteKind, VoteSet,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{collect_missing_blocks, validate_sync_chain};

type Ns = Vec<SigningKey>;

fn keys(n: usize) -> Ns {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

/// FULL-PQ: deterministic Falcon companions for `ks` (stable within a test:
/// re-deriving per call would re-register and invalidate in-flight votes).
/// Registered globally (keyed by ed id — distinct tests use distinct ed ids).
fn fks_for(ks: &[SigningKey]) -> Vec<FalconKeypair> {
    ks.iter()
        .enumerate()
        .map(|(i, _)| FalconKeypair::generate_from_seed(i as u8))
        .collect()
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
async fn build_chain(
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    base: &Arc<InMemoryStateEngine>,
    n: u64,
) -> Vec<Block> {
    let vs = vset(ks);
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let root = base.get_state_root().await;
        // F8: the proposer must be the one the deterministic schedule names for
        // (height, round); validate_sync_chain now enforces it.
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer_idx = ks
            .iter()
            .position(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member");
        let proposer = ks[proposer_idx].clone();
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
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        // FULL-PQ: the proposal signature is verified Falcon-only by
        // `consensus::verify_proposer_signature`, so the block carries both
        // halves (Ed id + registered Falcon half).
        b.sign_block_with_falcon(&proposer, &fks[proposer_idx]);
        // Real quorum, carried as the block's precommit QC: validate_sync_chain must
        // be able to tell a genuine history from a single-peer forgery, and it checks
        // the attached QC -- not extra block-hash signatures, which prove nothing
        // about agreement (votes are over vote_sign_bytes, a different message).
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, fks, &vs, h, bh, prev);
        let _ = &vs;
        prev = b.compute_hash();
        out.push(b);
    }
    out
}

/// Attach a genuine Falcon µQC precommit certificate for block `b`.
/// FULL-PQ: votes carry the Falcon half and the QC is compiled by the same
/// committee path production uses (not a raw ed list, which carries no power).
fn attach_quorum(
    b: &mut Block,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    bh: [u8; 32],
    parent: [u8; 32],
) {
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let mut set = VoteSet::new();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        let v = Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(bh));
        set.add(v, vs, height, 0, VoteKind::Precommit)
            .expect("genuine vote admits");
    }
    b.precommit_qc = set.certificate_with_parent(Some(bh), vs, Some(&parent));
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
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &fks, &base, 12).await;

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
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &fks, &base, 5).await;

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
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let honest = build_chain(&ks, &fks, &base, 10).await;

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
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block_with_falcon(&proposer, &fks[0]);
    let bh = b.compute_hash();
    attach_quorum(&mut b, &ks, &fks, &vs, 6, bh, [0xAB; 32]);
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
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &fks, &base, 6).await;

    // One peer signs everything. The forgery replaces the whole decision proof
    // with a single-signer's QC: one member cannot reach a 4-member quorum, no
    // matter how the block-signature list looks.
    let liar = ks[1].clone();
    let mut forged = blocks.clone();
    for b in forged.iter_mut().skip(3) {
        let bh = b.compute_hash();
        let v = Vote::sign(&liar, b.height, 0, VoteKind::Precommit, Some(bh));
        b.precommit_qc = Some(QuorumCertificate {
            shard_id: 0,
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
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let mut blocks = build_chain(&ks, &fks, &base, 5).await;

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
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = state_with_funds(payer, 1_000_000_000_000).await;
    let blocks = build_chain(&ks, &fks, &base, 6).await;

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

// ============================================================================
// Event-driven catch-up (2026-11-18): push-based propagation
// ============================================================================
//
// The catch-up machine used to be a POLL: every `STELL_CATCHUP_INTERVAL_MS`
// (2-3 s) the node asked the DHT whether any peer was ahead. With a dead peer
// in the table one such query could burn the whole `STELL_CATCHUP_BUDGET_MS`
// (measured live: 15 s on every tick). The architecture is now "react to what
// peers tell you":
//
//   * a finalized block is PUSHED to every directly connected peer (see
//     `node::sync::spawn_committed_push`), so a lagging peer RECEIVES the
//     `Committed` instead of discovering it by polling;
//   * a verified `Committed`/`Proposal`/`Vote` naming a height above ours (or a
//     peer head pointer above ours) latches an IMMEDIATE catch-up attempt;
//   * the periodic timer is a 30 s BACKSTOP for a node already known to be
//     behind, and is skipped ENTIRELY when no peer is known to be ahead.
//
// The REAL policy file is included by path (the `upgrade_halt_tests.rs`
// precedent), so these pin the shipped predicates, not a copy.
#[path = "../src/node/policy.rs"]
#[allow(dead_code)]
mod catchup_policy;

mod event_driven_catchup {
    use super::catchup_policy::{
        catchup_action, inbound_names_ahead, node_is_at_tip, should_probe_dht_head, CatchupAction,
        CATCHUP_INTERVAL_DEFAULT_MS, REACTIVE_CATCHUP_MIN_GAP_MS,
    };
    use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
    use stellereum::consensus_net::ConsensusMsg;
    use stellereum::sharding::Block;

    fn committed_at(height: u64) -> ConsensusMsg {
        let block = Block {
            height,
            ..Default::default()
        };
        let hash = block.compute_hash();
        ConsensusMsg::Committed {
            height,
            block,
            certificate: QuorumCertificate {
                shard_id: 0,
                height,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(hash),
                signatures: Vec::new(),
            },
        }
    }

    #[test]
    fn committed_for_a_higher_height_schedules_catchup_immediately() {
        // A pushed commit for height 101 while we are at 100.
        let msg = committed_at(101);
        assert_eq!(
            inbound_names_ahead(100, &msg),
            Some(101),
            "a commit above our height must be recognised as ahead evidence"
        );
        // The reactive latch runs on the NEXT tick: 500 ms after the previous
        // attempt, with the 30 s backstop still 29.5 s away.
        assert_eq!(
            catchup_action(
                true,
                REACTIVE_CATCHUP_MIN_GAP_MS,
                CATCHUP_INTERVAL_DEFAULT_MS,
                false
            ),
            CatchupAction::Run,
            "reactive evidence must not wait for the backstop timer"
        );
        // Same decision even if the last attempt was long ago: the trigger is
        // the message, not the clock.
        assert_eq!(
            catchup_action(
                true,
                5 * CATCHUP_INTERVAL_DEFAULT_MS,
                CATCHUP_INTERVAL_DEFAULT_MS,
                false
            ),
            CatchupAction::Run
        );
        // A burst of commits does not turn the tick into a DHT storm: below
        // the reactive floor the latch waits for the next tick.
        assert_eq!(
            catchup_action(true, 0, CATCHUP_INTERVAL_DEFAULT_MS, false),
            CatchupAction::Wait
        );
    }

    #[test]
    fn a_node_at_the_tip_skips_the_periodic_dht_probe() {
        // No peer known to be ahead: our tip is also the tallest height any
        // verified message / head pointer named.
        assert!(node_is_at_tip(100, 100, Some(100)));
        assert!(node_is_at_tip(100, 0, None));
        // The backstop fires but the DHT is NOT probed.
        assert_eq!(
            catchup_action(
                false,
                CATCHUP_INTERVAL_DEFAULT_MS,
                CATCHUP_INTERVAL_DEFAULT_MS,
                true
            ),
            CatchupAction::SkipAtTip
        );
        // …and the head-read predicate is never even consulted at the tip: the
        // SkipAtTip decision short-circuits the whole pass. (When a pass DOES
        // run, a hint at our tip still needs the DHT read; an ahead hint skips
        // it — see the sync suite.)
        assert_eq!(
            catchup_action(
                false,
                CATCHUP_INTERVAL_DEFAULT_MS,
                CATCHUP_INTERVAL_DEFAULT_MS,
                true
            ),
            CatchupAction::SkipAtTip
        );
        // Just before the interval the backstop simply waits.
        assert_eq!(
            catchup_action(
                false,
                CATCHUP_INTERVAL_DEFAULT_MS - 1,
                CATCHUP_INTERVAL_DEFAULT_MS,
                true
            ),
            CatchupAction::Wait
        );
    }

    #[test]
    fn a_node_behind_catches_up_on_the_next_commit_not_the_next_timer() {
        // Peer is 3 ahead and PUSHES a commit at 103.
        let msg = committed_at(103);
        assert_eq!(inbound_names_ahead(100, &msg), Some(103));
        assert!(
            !node_is_at_tip(100, 103, Some(103)),
            "a named height ahead means not at tip"
        );
        // One tick later (500 ms) the attempt is already allowed, with the
        // 30 s backstop nowhere near due.
        assert_eq!(
            catchup_action(
                true,
                REACTIVE_CATCHUP_MIN_GAP_MS,
                CATCHUP_INTERVAL_DEFAULT_MS,
                false
            ),
            CatchupAction::Run
        );
        // The head pointer the push planted is enough: no blind DHT read.
        assert!(!should_probe_dht_head(100, Some((103, [7u8; 32]))));
        // If the walk had failed and only the persistent hint remained, the
        // backstop may retry once it is due — but not before.
        assert_eq!(
            catchup_action(false, 0, CATCHUP_INTERVAL_DEFAULT_MS, false),
            CatchupAction::Wait
        );
        assert_eq!(
            catchup_action(
                false,
                CATCHUP_INTERVAL_DEFAULT_MS,
                CATCHUP_INTERVAL_DEFAULT_MS,
                false
            ),
            CatchupAction::Run
        );
    }

    #[test]
    fn commits_proposals_and_votes_all_name_ahead_heights() {
        // Committed.
        assert_eq!(inbound_names_ahead(100, &committed_at(105)), Some(105));
        // Proposal.
        let proposal = ConsensusMsg::Proposal {
            height: 106,
            round: 0,
            block: Block {
                height: 106,
                ..Default::default()
            },
        };
        assert_eq!(inbound_names_ahead(100, &proposal), Some(106));
        // Vote (signature is irrelevant to the arithmetic helper; the driver
        // only acts on it AFTER verification).
        let vote = ConsensusMsg::Vote {
            vote: Vote::signed_with([3u8; 32], 107, 0, VoteKind::Prevote, None, vec![0u8; 64]),
            locked: None,
        };
        assert_eq!(inbound_names_ahead(100, &vote), Some(107));
    }

    #[test]
    fn at_or_below_our_height_is_not_ahead_evidence() {
        // A rebroadcast of the height we already hold must not wake catch-up.
        assert_eq!(inbound_names_ahead(100, &committed_at(100)), None);
        assert_eq!(inbound_names_ahead(100, &committed_at(99)), None);
        // …nor may it make the node look behind.
        assert!(node_is_at_tip(100, 100, Some(100)));
        // A message with no height names nothing.
        assert_eq!(
            inbound_names_ahead(100, &ConsensusMsg::Batch(Vec::new())),
            None
        );
    }

    #[test]
    fn backstop_interval_default_is_thirty_seconds() {
        // Documents the deliberate change from 2000 ms: the timer is a
        // last-resort recheck, not the liveness mechanism.
        assert_eq!(CATCHUP_INTERVAL_DEFAULT_MS, 30_000);
        let reactive = std::hint::black_box(REACTIVE_CATCHUP_MIN_GAP_MS);
        let backstop = std::hint::black_box(CATCHUP_INTERVAL_DEFAULT_MS);
        assert!(
            reactive < backstop,
            "reactive must be far faster than the backstop"
        );
    }
}

// ============================================================================
// Pacing at the current block tempo (2026-11-19): the catch-up PASS BUDGET.
// ============================================================================
//
// The chain now produces a block roughly every 240 ms. A node that is behind
// retries on the reactive floor (500 ms), so a pass that admits only ~one WAN
// body fetch per attempt can fetch at most ~2 blocks/s while the chain grows at
// ~4 blocks/s: the gap never closes, and snapshot-sync (tens of MB) can never
// fit at all. The budget therefore scales with the known gap; the configured
// value is only the at-tip floor.
mod catchup_pass_budget_is_tempo_aware {
    // The REAL policy file, already included by path above.
    use super::catchup_policy::{catchup_pass_budget_ms, CATCHUP_BUDGET_DEFAULT_MS};
    use stellereum::sync::LIVE_ADOPT_GAP_THRESHOLD;

    /// Current live chain tempo (block interval) and the reactive retry floor.
    const BLOCK_TEMPO_MS: u64 = 240;
    const REACTIVE_RETRY_MS: u64 = 500;
    /// A WAN round trip a body fetch has to pay (measured: 100-400 ms).
    const WAN_RTT_MS: u64 = 400;

    #[test]
    fn at_tip_keeps_the_small_floor() {
        // No gap evidence: the blind probe must not hold a healthy tick.
        assert_eq!(
            catchup_pass_budget_ms(CATCHUP_BUDGET_DEFAULT_MS, 0),
            CATCHUP_BUDGET_DEFAULT_MS,
        );
        // ...but even the floor must fit a head read plus one body fetch over
        // a WAN link, or the smallest possible catch-up (one block behind)
        // times out forever. 250 ms could not do this.
        // (`black_box`: a value pin must not be optimized into a tautology.)
        let floor = std::hint::black_box(CATCHUP_BUDGET_DEFAULT_MS);
        assert!(
            floor >= 2 * WAN_RTT_MS + BLOCK_TEMPO_MS,
            "the catch-up floor must fit two WAN round trips + one block \
             (got {floor}ms)"
        );
        // And it must stay well under the backstop interval: the floor is a
        // per-attempt cap, not a reason to idle.
        assert!(floor < 30_000);
    }

    #[test]
    fn a_behind_pass_outruns_the_chain() {
        // Smallest burst a node outside the live-adopt window must clear in
        // one pass. At 240 ms/block this is ~4 s of chain; the flat 250 ms
        // budget covered about one body.
        let burst = LIVE_ADOPT_GAP_THRESHOLD + 1;
        let needed_ms = burst * BLOCK_TEMPO_MS;
        let budget = catchup_pass_budget_ms(CATCHUP_BUDGET_DEFAULT_MS, burst);
        assert!(
            budget >= needed_ms,
            "one pass must clear a {burst}-block burst at {BLOCK_TEMPO_MS}ms/block \
             (needs {needed_ms}ms, got {budget}ms)"
        );
        // And it must clear it in well under one retry interval's worth of
        // blocks, or the node still loses ground: per retry period the chain
        // grows REACTIVE_RETRY_MS / BLOCK_TEMPO_MS blocks.
        let grown_per_retry = REACTIVE_RETRY_MS.div_ceil(BLOCK_TEMPO_MS);
        let budget_blocks = budget / BLOCK_TEMPO_MS;
        assert!(
            budget_blocks > grown_per_retry,
            "a pass must fetch more blocks ({budget_blocks}) than the chain grows \
             between retries ({grown_per_retry})"
        );
    }

    #[test]
    fn snapshot_territory_gets_the_long_budget() {
        // >100 behind: only a snapshot can bridge it, and it needs minutes.
        assert!(catchup_pass_budget_ms(CATCHUP_BUDGET_DEFAULT_MS, 101) >= 180_000);
        // A walkable gap gets the medium budget.
        assert!(catchup_pass_budget_ms(CATCHUP_BUDGET_DEFAULT_MS, 100) >= 30_000);
        // Monotone in the gap: more evidence never shortens the pass.
        let mut prev = 0;
        for gap in [0u64, 1, 16, 100, 101, 1_000, 10_000] {
            let b = catchup_pass_budget_ms(CATCHUP_BUDGET_DEFAULT_MS, gap);
            assert!(b >= prev, "budget must not shrink as the gap grows");
            prev = b;
        }
    }
}

// ============================================================================
// A SUCCESSFUL pass that stopped short must stay reactive (2026-11-19).
// ============================================================================
//
// `try_catch_up` can advance us to a snapshot boundary (or part of the walk)
// and still return `Some`: the verified evidence that scheduled the pass is
// then STILL ahead. That path `continue`s the tick loop, so the end-of-tick
// persistent-evidence re-arm does not run. Without an explicit re-arm here the
// node drops to the 30 s backstop for a walk it could finish on the next
// reactive tick — at a 240 ms block tempo the head moves 125 blocks in that
// window, so the "short remainder" is never closed.
mod successful_pass_rearms_the_latch {
    use super::catchup_policy::catchup_still_behind;

    #[test]
    fn partial_snapshot_advance_keeps_the_next_walk_reactive() {
        // Snapshot-sync landed on boundary 1200; the verified head hint is
        // 1500. The remaining 300 heights are the body walk's job.
        assert!(catchup_still_behind(1200, Some((1500, [7u8; 32])), 1200));
        // Vote/proposal evidence (no hint) is equally persistent.
        assert!(catchup_still_behind(1200, None, 1210));
    }

    #[test]
    fn reaching_the_named_head_does_not_spin() {
        assert!(!catchup_still_behind(1500, Some((1500, [7u8; 32])), 1500));
        assert!(!catchup_still_behind(1500, None, 1500));
        // A hint BELOW our tip is stale evidence, never a re-arm.
        assert!(!catchup_still_behind(1500, Some((1499, [7u8; 32])), 1400));
    }
}

// ============================================================================
// The at-tip blind probe is the DETECTION latency for a silent behind node.
// ============================================================================
//
// "At tip" is inferred from the absence of ahead evidence, so a node that
// stopped RECEIVING pushes (one-way loss, DHT-only follower) is invisible to
// the reactive path. The blind probe is its only rescue, which makes the probe
// window a wall-clock latency: at the current ~240 ms block tempo the old
// 600 s value is 2 500 blocks, several snapshot generations of lag.
mod blind_probe_tracks_the_block_tempo {
    use super::catchup_policy::{
        snapshot_interval, AT_TIP_PROBE_INTERVAL_MS, CATCHUP_INTERVAL_DEFAULT_MS,
    };

    const BLOCK_TEMPO_MS: u64 = 240;

    #[test]
    fn a_silent_behind_node_is_discovered_within_one_snapshot_generation() {
        // One snapshot generation (the configured cadence; default 1000).
        let generation_blocks = snapshot_interval();
        let blocks = AT_TIP_PROBE_INTERVAL_MS / BLOCK_TEMPO_MS;
        assert!(
            blocks <= generation_blocks,
            "the at-tip blind probe must fire within one snapshot generation \
             ({blocks} blocks at {BLOCK_TEMPO_MS}ms > {generation_blocks})"
        );
        // It stays a last resort: never more frequent than the known-behind
        // backstop, so an idle node does not poll the DHT.
        assert!(
            std::hint::black_box(AT_TIP_PROBE_INTERVAL_MS)
                >= std::hint::black_box(CATCHUP_INTERVAL_DEFAULT_MS)
        );
    }
}
