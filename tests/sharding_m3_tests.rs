//! Sharding milestone M3 (§5 core): shared-sequencer-adjacent two-phase
//! atomicity — ack/bounce protocol over `Block.cross_shard_out`.
//!
//! M2 proved one-way source-burn + target-mint. M3 proves the return path:
//!
//!  1. Happy path: target consumes, publishes an ack; the source commits the
//!     ack record and the transfer COMPLETES (no bounce may ever follow).
//!  2. Failure path: target never consumes; after a deterministic TIMEOUT in
//!     heights (`CROSS_SHARD_TIMEOUT_HEIGHTS`) the source commits a
//!     bounce-back record refunding `tx.amount` to `tx.from` — exactly once.
//!  3. Replay of an ack/bounce (same bytes, or a rebuilt carrier) is refused
//!     at proposal, at validation, and at apply; two independent shards
//!     applying the same bounce derive the same root.
//!  4. Control records carry NO Merkle proof and are refused if they do (the
//!     engine would otherwise credit `tx.to` on the source — a mint).
//!
//! No new `Block`/`Transaction` fields anywhere: kinds ride the pre-existing
//! `source_shard`/`target_shard` direction + `bounce`/`bounced` flags.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    bounce_eligible, Block, CrossShardKey, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, CROSS_SHARD_TIMEOUT_HEIGHTS, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

async fn sharded_pair(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard1_funding {
        s1.update_account(AccountState::new(*addr, *bal)).await;
    }
    ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    )
}

async fn balance(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    sc.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

fn block_of(sc: &ShardedCluster, shard: u32, bh: [u8; 32]) -> Block {
    sc.shard(shard).nodes[0]
        .blocks
        .get(&bh)
        .cloned()
        .expect("block body retained")
}

/// Produce one outbound transfer on the source shard and return its tx hash.
async fn produce_transfer(
    sc: &mut ShardedCluster,
    sender: &SigningKey,
    to: [u8; 32],
    ts: u64,
) -> [u8; 32] {
    let tx = Transaction::sign(sender, to, 100, 10, 0, SHARD0, SHARD1);
    let txh = tx.compute_tx_hash();
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx).await;
    let bh = sc.run_height(SHARD0, ts).await;
    let blk = block_of(sc, SHARD0, bh);
    assert_eq!(blk.cross_shard_out.len(), 1);
    assert!(blk.cross_shard_out[0].is_transfer());
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&txh),
        Some(1)
    );
    txh
}

/// The timeout rule is pure heights, never seconds.
#[tokio::test]
async fn timeout_rule_is_in_heights_not_seconds() {
    assert_eq!(CROSS_SHARD_TIMEOUT_HEIGHTS, 64);
    assert!(!bounce_eligible(1, 1));
    assert!(!bounce_eligible(1, 64));
    assert!(bounce_eligible(1, 65));
    assert!(bounce_eligible(1, 10_000));
    assert!(!bounce_eligible(100, 163));
    assert!(bounce_eligible(100, 164));
    // Saturating, never wraps on absurd heights.
    assert!(bounce_eligible(1, u64::MAX));
}

/// Kind encoding uses only pre-existing fields: direction + flags.
#[tokio::test]
async fn message_kinds_come_from_direction_and_flags_only() {
    let a = key(21);
    let b = key(22);
    let tx = Transaction::sign(&a, b.verifying_key().to_bytes(), 10, 1, 0, SHARD0, SHARD1);
    let transfer = stellereum::sharding::CrossShardMessage::new(
        SHARD0,
        SHARD1,
        tx.clone(),
        [0u8; 32],
        [1u8; 32],
        None,
    );
    assert!(transfer.is_transfer());
    assert!(!transfer.is_ack() && !transfer.is_bounce());
    let ack = stellereum::sharding::CrossShardMessage::new_ack(tx.clone(), [2u8; 32]);
    assert!(ack.is_ack());
    assert!(!ack.is_transfer() && !ack.is_bounce());
    assert!(
        ack.merkle_inclusion_proof.is_none(),
        "control records carry no proof"
    );
    let bounce = stellereum::sharding::CrossShardMessage::new_bounce(tx.clone(), [3u8; 32]);
    assert!(bounce.is_bounce());
    assert!(!bounce.is_transfer() && !bounce.is_ack());
    assert!(
        bounce.merkle_inclusion_proof.is_none(),
        "control records carry no proof"
    );
    // A transfer-shaped record with flags set is Unknown (fail closed).
    let mut weird = transfer.clone();
    weird.bounced = true;
    assert!(!weird.is_transfer() && !weird.is_ack() && !weird.is_bounce());
}

/// Happy path: consume -> ack -> source commits the ack -> transfer completes
/// -> no bounce is ever admitted afterwards (even past the timeout).
#[tokio::test]
async fn ack_flow_completes_transfer_and_blocks_any_later_bounce() {
    let validator = key(1);
    let sender = key(2);
    let recipient = key(3);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let txh = produce_transfer(&mut sc, &sender, recipient_addr, 1).await;

    // Target consumes: recipient credited, ack published to the transport.
    sc.run_height(SHARD1, 2).await;
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 100);
    let inbound0 = sc.transport.fetch_cross_shard_inbound(SHARD0).await;
    assert_eq!(inbound0.len(), 1, "target must publish exactly one ack");
    assert!(inbound0[0].is_ack());
    assert_eq!(inbound0[0].tx.compute_tx_hash(), txh);
    let ack_bytes = inbound0[0].clone();

    // Source commits the ack record: no value moves, transfer completes.
    let bh = sc.run_height(SHARD0, 3).await;
    let blk = block_of(&sc, SHARD0, bh);
    assert!(
        blk.cross_shard_out
            .iter()
            .any(|m| m.is_ack() && m.tx.compute_tx_hash() == txh),
        "source must commit the ack record"
    );
    assert!(sc.shard(SHARD0).nodes[0].is_transfer_completed(&txh));
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);
    // Consumed KV entries are pruned: nothing lingers for the source shard.
    assert!(sc
        .transport
        .fetch_cross_shard_inbound(SHARD0)
        .await
        .is_empty());

    // Past the timeout, no bounce may be constructed for a completed transfer.
    let mut saw_bounce = false;
    for h in 3..=(3 + CROSS_SHARD_TIMEOUT_HEIGHTS + 2) {
        let bh = sc.run_height(SHARD0, 100 + h).await;
        let blk = block_of(&sc, SHARD0, bh);
        saw_bounce |= blk.cross_shard_out.iter().any(|m| m.is_bounce());
    }
    assert!(!saw_bounce, "a completed transfer must never bounce");
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 100);

    // Replaying the consumed ack is refused at proposal (filtered) and at
    // validation (forged block rejected).
    sc.transport
        .broadcast_cross_shard(&ack_bytes)
        .await
        .unwrap();
    let bh = sc.run_height(SHARD0, 999).await;
    let blk = block_of(&sc, SHARD0, bh);
    assert!(
        blk.cross_shard_out
            .iter()
            .all(|m| m.msg_id != ack_bytes.msg_id),
        "a consumed ack must not be re-included"
    );
    let node = &sc.shard(SHARD0).nodes[0];
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD0,
        height: node.height(),
        prev_hash: node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![ack_bytes.clone()],
        timestamp: 1_000,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    forged.sign_block(&validator);
    let err = node
        .validate_proposal(&forged, root)
        .expect_err("replayed ack must be refused");
    assert!(
        err.contains("replayed") || err.contains("completed"),
        "{err}"
    );
    let _ = CrossShardKey::of(&ack_bytes);
}

/// Failure path: the target never consumes; at produce_height + TIMEOUT the
/// source commits a bounce-back refunding `tx.amount` to `tx.from`, exactly
/// once — and a second carrier for the same transaction cannot refund again.
#[tokio::test]
async fn bounce_on_failure_refunds_sender_after_timeout_exactly_once() {
    let validator = key(11);
    let sender = key(12);
    let recipient = key(13);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let txh = produce_transfer(&mut sc, &sender, recipient_addr, 1).await;
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);

    // Target NEVER runs: heights 2..=64 carry no bounce (timeout not reached).
    for h in 2..(1 + CROSS_SHARD_TIMEOUT_HEIGHTS) {
        let bh = sc.run_height(SHARD0, 10 + h).await;
        let blk = block_of(&sc, SHARD0, bh);
        assert!(
            blk.cross_shard_out.iter().all(|m| !m.is_bounce()),
            "no bounce before height {}",
            1 + CROSS_SHARD_TIMEOUT_HEIGHTS
        );
    }
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);

    // Height 65 == 1 + TIMEOUT: the bounce commits and refunds the amount
    // (gas stays with the source proposer — only `amount` is refunded).
    let bh = sc
        .run_height(SHARD0, 10 + 1 + CROSS_SHARD_TIMEOUT_HEIGHTS)
        .await;
    let blk = block_of(&sc, SHARD0, bh);
    let bounce = blk
        .cross_shard_out
        .iter()
        .find(|m| m.is_bounce())
        .expect("timeout bounce must commit")
        .clone();
    assert_eq!(bounce.tx.compute_tx_hash(), txh);
    assert!(sc.shard(SHARD0).nodes[0].is_transfer_completed(&txh));
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 10);
    // The recipient never got anything anywhere (target never consumed).
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 0);

    // Replaying the consumed bounce is filtered; a rebuilt second carrier for
    // the same transaction is refused (completion guard, not just msg_id).
    sc.transport.broadcast_cross_shard(&bounce).await.unwrap();
    let rebuilt = stellereum::sharding::CrossShardMessage::new_bounce(bounce.tx.clone(), [9u8; 32]);
    sc.transport.broadcast_cross_shard(&rebuilt).await.unwrap();
    let bh2 = sc.run_height(SHARD0, 999).await;
    let blk2 = block_of(&sc, SHARD0, bh2);
    assert!(
        blk2.cross_shard_out.iter().all(|m| !m.is_bounce()),
        "no second refund for a completed transfer"
    );
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 10);
    let node = &sc.shard(SHARD0).nodes[0];
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD0,
        height: node.height(),
        prev_hash: node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![rebuilt],
        timestamp: 1_000,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    forged.sign_block(&validator);
    let err = node
        .validate_proposal(&forged, root)
        .expect_err("second bounce must be refused");
    assert!(
        err.contains("completed") || err.contains("replayed") || err.contains("linkage"),
        "{err}"
    );
}

/// A proof-carrying control record is refused: the engine would credit
/// `tx.to` on the source shard for it (a mint), so proposal and validation
/// must fail closed before it can be committed.
#[tokio::test]
async fn proof_carrying_ack_or_bounce_is_refused() {
    let validator = key(31);
    let sender = key(32);
    let recipient = key(33);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    produce_transfer(&mut sc, &sender, recipient_addr, 1).await;
    // Steal the genuine transfer's proof onto a bounce-shaped record.
    let src_bh = sc.shard(SHARD0).nodes[0]
        .finalized
        .last()
        .map(|(_, h)| *h)
        .unwrap();
    let transfer = block_of(&sc, SHARD0, src_bh).cross_shard_out[0].clone();
    assert!(transfer.merkle_inclusion_proof.is_some());
    let mut evil =
        stellereum::sharding::CrossShardMessage::new_bounce(transfer.tx.clone(), [7u8; 32]);
    evil.merkle_inclusion_proof = transfer.merkle_inclusion_proof.clone();
    assert!(evil.is_bounce(), "shape must still classify as bounce");

    // Proposal filters it (never committed)...
    sc.transport.broadcast_cross_shard(&evil).await.unwrap();
    let bh = sc.run_height(SHARD0, 50).await;
    let blk = block_of(&sc, SHARD0, bh);
    assert!(
        blk.cross_shard_out.iter().all(|m| m.msg_id != evil.msg_id),
        "a proof-carrying bounce must never be proposed"
    );
    // ...and validation refuses a forged block carrying it.
    let node = &sc.shard(SHARD0).nodes[0];
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD0,
        height: node.height(),
        prev_hash: node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![evil],
        timestamp: 51,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    forged.sign_block(&validator);
    assert!(node.validate_proposal(&forged, root).is_err());
    // No mint happened on the source shard either way.
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);
}

/// Two independently-run source shards, fed the same transfer and the same
/// timeout walk, derive the SAME state root (bounce determinism).
#[tokio::test]
async fn two_independent_sources_applying_the_same_bounce_derive_the_same_root() {
    let mut roots = Vec::new();
    for _ in 0..2 {
        let validator = key(41);
        let sender = key(42);
        let recipient = key(43);
        let sender_addr = sender.verifying_key().to_bytes();
        let recipient_addr = recipient.verifying_key().to_bytes();
        let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
        produce_transfer(&mut sc, &sender, recipient_addr, 1).await;
        for h in 2..=(1 + CROSS_SHARD_TIMEOUT_HEIGHTS) {
            sc.run_height(SHARD0, 10 + h).await;
        }
        let bounce_block = sc.shard(SHARD0).nodes[0]
            .blocks
            .values()
            .find(|b| b.cross_shard_out.iter().any(|m| m.is_bounce()))
            .expect("bounce must have committed");
        assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 10);
        roots.push((
            sc.shard(SHARD0).nodes[0].state_root().await,
            bounce_block.compute_hash(),
        ));
    }
    assert_eq!(
        roots[0], roots[1],
        "independent shards must converge on root AND bounce block hash"
    );
}
