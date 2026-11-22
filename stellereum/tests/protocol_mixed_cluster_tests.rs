//! Mixed-version fleet: a 3-validator cluster finalizes while one member
//! cannot decode compact proposals and therefore receives the FULL `Proposal`
//! (dual-emit).
//!
//! Two layers are pinned together:
//! 1. the REAL 3-node `ValidatorRuntime` cluster finalizes (the consensus
//!    suite's deterministic rig), so the capability policy cannot be bought
//!    with liveness;
//! 2. for the very same block shape, the non-capable node's wire form is the
//!    full `Proposal` (all txs inline), the capable nodes' compact form
//!    resolves back to the identical block hash, and both representations
//!    round-trip through the production codec.

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::ConsensusCluster;
use stellereum::consensus_net::compact_prop::Resolution;
use stellereum::consensus_net::{
    open_compact_proposal, short_id_index_for, ConsensusMsg, MAX_CONSENSUS_MSG,
};
use stellereum::protocol::{peer_receives_compact, proposal_for_peer, Capabilities, CAPABILITIES};
use stellereum::sharding::{Block, Transaction};

const BUDGET_MS: u64 = 240_000;

fn tx(seed: u64) -> Transaction {
    Transaction {
        from: [seed as u8; 32],
        to: [0xAAu8; 32],
        amount: 1_000 + seed,
        gas_limit: 21_000,
        nonce: seed,
        source_shard: 0,
        target_shard: 0,
        signature: vec![0u8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

#[tokio::test]
async fn three_node_mixed_cluster_finalizes_and_non_capable_peer_gets_full_proposal() {
    // ---- (1) REAL consensus: three validators finalize, deterministically.
    let mut cluster = ConsensusCluster::new(3, &[1, 1, 1]);
    cluster.seed_transactions(3).await;
    let report = cluster.run_until(3, BUDGET_MS).await;

    assert!(
        report.best_height >= 3,
        "the 3-node mixed-capability fleet must finalize.\n{}",
        report.diagnostics()
    );
    assert_eq!(
        report.common_height,
        report.best_height,
        "every node must reach the same height.\n{}",
        report.diagnostics()
    );
    for node in &report.nodes {
        assert!(
            node.prevotes_cast > 0 && node.precommits_cast > 0,
            "node {} never voted.\n{}",
            node.index,
            report.diagnostics()
        );
    }

    // ---- (2) The fleet's capability matrix, for the same proposal shape.
    // Node A/B are current (COMPACT_GOSSIP); node C is the mixed-fleet peer
    // that never negotiated it.
    let capable = CAPABILITIES;
    let non_capable = Capabilities::MESH_DIRECT; // explicitly NOT COMPACT_GOSSIP
    assert!(peer_receives_compact(capable));
    assert!(!peer_receives_compact(non_capable));

    let block = Block::new_for_test(0, 4, [0x11u8; 32], [0x22u8; 32], (0..64).map(tx).collect())
        .with_proposer([0x33u8; 32])
        .with_timestamp(1_700_000_004);

    // Non-capable peer: FULL `Proposal` with every tx inline.
    let full = proposal_for_peer(&block, 0, non_capable);
    let bytes = full.encode().expect("full proposal encodes");
    assert!(bytes.len() <= MAX_CONSENSUS_MSG);
    let decoded_full = ConsensusMsg::decode(&bytes).expect("full proposal decodes");
    match decoded_full {
        ConsensusMsg::Proposal {
            height,
            round,
            block: got,
        } => {
            assert_eq!((height, round), (block.height, 0));
            assert_eq!(got.compute_hash(), block.compute_hash());
            assert_eq!(got.transactions.len(), block.transactions.len());
        }
        other => panic!("non-capable peer received {other:?}, expected full Proposal"),
    }

    // Capable peers: compact announcement resolves to the SAME block.
    let compact = proposal_for_peer(&block, 0, capable);
    let compact_wire = compact.encode().expect("compact proposal encodes");
    let proposal = match ConsensusMsg::decode(&compact_wire).expect("compact decodes") {
        ConsensusMsg::CompactProposal { proposal } => proposal,
        other => panic!("capable peer received {other:?}, expected CompactProposal"),
    };
    let mut resolver = open_compact_proposal(proposal).expect("resolver opens");
    let index = short_id_index_for(
        &resolver.proposal().header,
        block.transactions.iter().cloned(),
    );
    match resolver.resolve_against(&index).expect("resolve") {
        Resolution::Complete(rebuilt) => assert_eq!(
            rebuilt.compute_hash(),
            block.compute_hash(),
            "compact and full representations must be the same block"
        ),
        other => panic!("expected a complete body, got {other:?}"),
    }
}
