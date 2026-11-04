//! Transport-audit small fixes: one regression test per item.
//!
//! 1. `maybe_prune_retained` resolves its header-index lookup through the
//!    shared `fetch_sem` lane (no unbounded direct `fetch_blob`). The lane
//!    itself is private, so this pins the public contract around it: the
//!    prune pass is bounded per run and the fetch lane cap is sane.
//! 2. `Committed` bypasses the peer failure-cooldown skip (the cheap live
//!    catch-up path must not starve 60s); votes/proposals stay skippable.
//! 3. EVM statics: `eth_syncing` follows live heights (same rule as
//!    `stell_syncing`); `net_peerCount` / `net_listening` / `eth_gasPrice`
//!    stay honestly testnet-known defaults with a shared live formatter.

use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
use stellereum::consensus_net::{committed_bypasses_skip, ConsensusMsg};
use stellereum::evm_adapter::{eth_syncing_for_heights, format_peer_count_hex};
use stellereum::network::{prune_batch, prune_below_exclusive};
use stellereum::sharding::Block;

fn sample_block() -> Block {
    Block {
        shard_id: 0,
        height: 9,
        prev_hash: [1u8; 32],
        state_root: [2u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 123,
        proposer: [3u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

fn sample_commit() -> ConsensusMsg {
    ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: QuorumCertificate {
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    }
}

// --- 1. prune stays bounded (the permit lane caps concurrent streams) --------

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn prune_pass_is_bounded_per_run_and_respects_keep() {
    // A huge backlog drains gradually: each pass touches at most the per-run
    // cap, so one pass can never open an unbounded burst of index fetches.
    let (batch, _next) = prune_batch(0, 100_000, 64);
    assert!(
        batch.len() <= 64,
        "one pass must stay capped, got {}",
        batch.len()
    );
    // Retention floor: nothing below `tip - KEEP` is pruned.
    assert_eq!(prune_below_exclusive(10_000, 8_000), 2_000);
    assert_eq!(
        prune_below_exclusive(100, 8_000),
        0,
        "tip inside KEEP prunes nothing"
    );
    // The shared fetch lane the prune now uses is bounded and sane.
    assert!(stellereum::sync::FETCH_MAX_CONCURRENCY >= 1);
    assert!(stellereum::sync::FETCH_MAX_CONCURRENCY <= 64);
}

// --- 2. Committed bypasses peer-skip; votes/proposals do not ---------------

#[test]
fn committed_bypasses_skip_while_votes_and_proposals_do_not() {
    assert!(committed_bypasses_skip(&sample_commit()));
    let proposal = ConsensusMsg::Proposal {
        height: 9,
        round: 0,
        block: sample_block(),
    };
    assert!(!committed_bypasses_skip(&proposal));
    let vote = ConsensusMsg::Vote {
        vote: Vote {
            height: 9,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: None,
            voter: [7u8; 32],
            signature: vec![0u8; 64],
        },
        locked: None,
    };
    assert!(!committed_bypasses_skip(&vote));
    // A batch wrapper is never itself the live path (batches bypass only via
    // their members on the broadcast path).
    assert!(!committed_bypasses_skip(&ConsensusMsg::Batch(vec![
        sample_commit()
    ])));
}

// --- 3. EVM statics: live syncing rule, honest testnet-known defaults -------

#[test]
fn eth_syncing_follows_live_heights_like_stell_syncing() {
    assert!(
        !eth_syncing_for_heights(42, None),
        "no sighting means in sync"
    );
    assert!(
        !eth_syncing_for_heights(42, Some(42)),
        "peer at our height means in sync"
    );
    assert!(
        !eth_syncing_for_heights(42, Some(7)),
        "peer behind us means in sync"
    );
    assert!(
        eth_syncing_for_heights(42, Some(43)),
        "peer ahead means syncing"
    );
}

#[test]
fn peer_count_formatter_agrees_with_testnet_default() {
    assert_eq!(
        format_peer_count_hex(2),
        stellereum::evm_adapter::net_peer_count()
    );
    assert_eq!(format_peer_count_hex(2), "0x2");
    assert_eq!(format_peer_count_hex(0), "0x0");
}
