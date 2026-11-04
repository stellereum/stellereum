//! Sequencer milestone M3 (§5 core): deterministic shared sequencing +
//! the L2 batch interface + consumed-KV pruning.
//!
//!  1. `SharedSequencer::assign_from_block` derives global sequence numbers
//!     from COMMITTED block content under the ordering rule
//!     `(source_height, source_shard, msg_id)` — no clock, no operator, no
//!     network. Two sequencers replaying the same finalized blocks derive
//!     identical assignments however the carrier vecs were ordered.
//!  2. The watermark advances only from finalized blocks, monotonically.
//!  3. `L2Sequencer`: append-only admission (contiguous indices, payload-hash
//!     binding, signature checks) with canonical `(l2_id, batch_index)`
//!     inclusion order. DA/bridging is out of scope.
//!  4. `CrossShardTransport::prune_consumed` drops consumed KV entries,
//!     idempotently.

use ed25519_dalek::SigningKey;
use stellereum::network::CrossShardTransport;
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardMessage, L2Batch, L2Sequencer, SharedSequencer, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn tx_with_nonce(signer: &SigningKey, to: [u8; 32], nonce: u64, s: u32, t: u32) -> Transaction {
    Transaction::sign(signer, to, 10, 1, nonce, s, t)
}

fn msg_for(tx: Transaction, finalized: [u8; 32]) -> CrossShardMessage {
    CrossShardMessage::new(
        tx.source_shard,
        tx.target_shard,
        tx,
        [0u8; 32],
        finalized,
        None,
    )
}

fn blank_block(shard: u32, height: u64, out: Vec<CrossShardMessage>) -> Block {
    Block {
        shard_id: shard,
        height,
        prev_hash: [height as u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: out,
        timestamp: height,
        proposer: [0xAAu8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

/// The ordering rule, pinned: within and across blocks, records sort by
/// `(source_height, source_shard, msg_id)`; sequence numbers follow that
/// order and are independent of carrier-vec order.
#[test]
fn sequencer_order_comes_from_blocks_not_carrier_order() {
    let a = key(1);
    let b = key(2);
    let to = [9u8; 32];

    // Block on shard 0 at height 5 with two messages (crafted out of order).
    let m1 = msg_for(tx_with_nonce(&a, to, 0, SHARD0, SHARD1), [0xA1u8; 32]);
    let m2 = msg_for(tx_with_nonce(&a, to, 1, SHARD0, SHARD1), [0xA2u8; 32]);
    // Block on shard 1 at height 3 with one message (lower height: sequences first).
    let m3 = msg_for(tx_with_nonce(&b, to, 0, SHARD1, SHARD0), [0xB1u8; 32]);

    let b0 = blank_block(SHARD0, 5, vec![m2.clone(), m1.clone()]);
    let b1 = blank_block(SHARD1, 3, vec![m3.clone()]);

    let mut seq = SharedSequencer::new();
    // Feed in (height, shard) order: the canonical finalized order.
    let got1 = seq.assign_from_block(&b1);
    let got0 = seq.assign_from_block(&b0);
    assert_eq!(got1.len(), 1);
    assert_eq!(got0.len(), 2);
    // Shard-1 height-3 message sequences before either shard-0 height-5 one.
    assert!(got1[0].0 < got0[0].0 && got1[0].0 < got0[1].0);
    // Within the block: (source_shard, msg_id) order, NOT carrier-vec order.
    let mut ids = vec![m1.msg_id, m2.msg_id];
    ids.sort();
    let assigned: Vec<[u8; 32]> = got0.iter().map(|(_, k)| k.msg_id).collect();
    assert_eq!(
        assigned, ids,
        "assignment must follow (source_shard, msg_id), not vec order"
    );
    assert!(
        got0[0].0 + 1 == got0[1].0,
        "sequence numbers are contiguous"
    );

    // Replaying the same blocks on a fresh sequencer reproduces everything.
    let mut seq2 = SharedSequencer::new();
    let r1 = seq2.assign_from_block(&b1);
    let r0 = seq2.assign_from_block(&b0);
    assert_eq!(r1, got1);
    assert_eq!(r0, got0);
    assert_eq!(seq2.next_sequence(), seq.next_sequence());
    assert_eq!(seq2.watermark(), seq.watermark());

    // Re-assigning is idempotent: no new numbers, same mapping.
    let again = seq.assign_from_block(&b0);
    assert_eq!(again, got0);
    assert_eq!(seq.next_sequence(), seq2.next_sequence());

    // Every assignment is reachable by key.
    for (s, k) in got0.iter().chain(got1.iter()) {
        assert_eq!(seq.sequence_of(k), Some(*s));
    }
    assert_eq!(
        seq.sequence_of(&CrossShardKey {
            source_shard: 9,
            finalized_in_block: [0u8; 32],
            msg_id: [0u8; 32]
        }),
        None
    );
}

/// The watermark advances only from finalized blocks, monotonically.
#[test]
fn sequencer_watermark_advances_monotonically_from_finalized_blocks_only() {
    let mut seq = SharedSequencer::new();
    assert!(seq.watermark().is_empty());
    seq.note_finalized(SHARD0, 10);
    seq.note_finalized(SHARD1, 4);
    assert_eq!(seq.watermark().get(&SHARD0), Some(&10));
    assert_eq!(seq.watermark().get(&SHARD1), Some(&4));
    // Stale heights never move it backwards.
    seq.note_finalized(SHARD0, 7);
    assert_eq!(seq.watermark().get(&SHARD0), Some(&10));
    // Assigning a block advances its shard's watermark to the block height.
    let b = blank_block(SHARD1, 9, vec![]);
    seq.assign_from_block(&b);
    assert_eq!(seq.watermark().get(&SHARD1), Some(&9));
}

/// L2 admission: contiguous indices only, payload-hash bound, sigs verified.
#[test]
fn l2_submit_is_append_only_hash_bound_and_signature_checked() {
    let user = key(11);
    let to = [7u8; 32];
    let mut l2 = L2Sequencer::new();
    assert_eq!(l2.expected_index(3), 0);

    // Gap rejected: index 1 before index 0.
    let batch1 = L2Batch::new(3, 1, vec![tx_with_nonce(&user, to, 0, SHARD0, SHARD0)]);
    assert!(l2.submit_batch(batch1).is_err());
    assert_eq!(l2.pending_len(), 0);

    // Index 0 accepted.
    let batch0 = L2Batch::new(3, 0, vec![tx_with_nonce(&user, to, 0, SHARD0, SHARD0)]);
    l2.submit_batch(batch0)
        .expect("first batch must be admitted");
    assert_eq!(l2.expected_index(3), 1);

    // Duplicate index rejected.
    let dup = L2Batch::new(3, 0, vec![tx_with_nonce(&user, to, 1, SHARD0, SHARD0)]);
    assert!(l2.submit_batch(dup).is_err());

    // Tampered payload hash rejected.
    let mut tampered = L2Batch::new(3, 1, vec![tx_with_nonce(&user, to, 1, SHARD0, SHARD0)]);
    tampered.payload_hash = [0xFFu8; 32];
    assert!(l2.submit_batch(tampered).is_err());

    // Reordered txs change the binding hash: rebuild binds the new order, so
    // submit the swapped batch under the right index — it is a DIFFERENT
    // batch and must verify on its own hash.
    let t1 = tx_with_nonce(&user, to, 1, SHARD0, SHARD0);
    let t2 = tx_with_nonce(&user, to, 2, SHARD0, SHARD0);
    let swapped = L2Batch::new(3, 1, vec![t2.clone(), t1.clone()]);
    assert_eq!(swapped.payload_hash, L2Batch::payload_hash_of(&[t2, t1]));
    l2.submit_batch(swapped)
        .expect("correctly-bound batch admitted");

    // Bad signature rejected.
    let mut bad = tx_with_nonce(&user, to, 3, SHARD0, SHARD0);
    bad.signature[0] ^= 0xFF;
    let bad_batch = L2Batch::new(4, 0, vec![bad]);
    assert!(l2.submit_batch(bad_batch).is_err());

    // Empty batch rejected.
    let empty = L2Batch::new(4, 0, vec![]);
    assert!(l2.submit_batch(empty).is_err());
}

/// L2 ordering guarantee: canonical `(l2_id, batch_index)` FIFO; inclusion
/// marks prune pending deterministically and only move forward.
#[test]
fn l2_inclusion_order_is_canonical_and_marks_prune_forward_only() {
    let user = key(21);
    let to = [7u8; 32];
    let mut l2 = L2Sequencer::new();
    for l2_id in [7u32, 5u32] {
        for idx in 0..3u64 {
            let tx = tx_with_nonce(&user, to, (l2_id as u64) * 10 + idx, SHARD0, SHARD0);
            l2.submit_batch(L2Batch::new(l2_id, idx, vec![tx])).unwrap();
        }
    }
    // Canonical order regardless of submission order: l2 5 first, then l2 7.
    let order: Vec<(u32, u64)> = l2
        .batches_for_inclusion(100)
        .iter()
        .map(|b| (b.l2_id, b.batch_index))
        .collect();
    assert_eq!(order, vec![(5, 0), (5, 1), (5, 2), (7, 0), (7, 1), (7, 2)]);
    // Limit takes a prefix (ordering preserved for partial pulls).
    assert_eq!(l2.batches_for_inclusion(2).len(), 2);
    // Marking included prunes pending and records the watermark...
    l2.mark_included(5, 1);
    assert_eq!(l2.included_count(5), 2);
    let rest: Vec<(u32, u64)> = l2
        .batches_for_inclusion(100)
        .iter()
        .map(|b| (b.l2_id, b.batch_index))
        .collect();
    assert_eq!(rest, vec![(5, 2), (7, 0), (7, 1), (7, 2)]);
    // ...and a stale mark never rewinds or resurrects.
    l2.mark_included(5, 0);
    assert_eq!(l2.included_count(5), 2);
    assert_eq!(l2.batches_for_inclusion(100).len(), 4);
    // Other L2s are untouched.
    assert_eq!(l2.included_count(7), 0);
}

/// Consumed-KV pruning: drops exactly the consumed ids, idempotently.
#[tokio::test]
async fn transport_prune_consumed_drops_only_consumed_ids_idempotently() {
    let user = key(31);
    let to = [7u8; 32];
    let t = CrossShardTransport::local();
    let m1 = msg_for(tx_with_nonce(&user, to, 0, SHARD0, SHARD1), [0x11u8; 32]);
    let m2 = msg_for(tx_with_nonce(&user, to, 1, SHARD0, SHARD1), [0x12u8; 32]);
    t.broadcast_cross_shard(&m1).await.unwrap();
    t.broadcast_cross_shard(&m2).await.unwrap();
    assert_eq!(t.fetch_cross_shard_inbound(SHARD1).await.len(), 2);

    // Pruning nothing is a no-op.
    assert_eq!(t.prune_consumed(SHARD1, &[]).await, 0);
    // Prune one: only it goes.
    assert_eq!(t.prune_consumed(SHARD1, &[m1.msg_id]).await, 1);
    let rest = t.fetch_cross_shard_inbound(SHARD1).await;
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].msg_id, m2.msg_id);
    // Re-pruning is idempotent, and other shards are untouched.
    assert_eq!(t.prune_consumed(SHARD1, &[m1.msg_id]).await, 0);
    assert_eq!(t.prune_consumed(SHARD0, &[m2.msg_id]).await, 0);
    assert_eq!(t.prune_consumed(SHARD1, &[m2.msg_id]).await, 1);
    assert!(t.fetch_cross_shard_inbound(SHARD1).await.is_empty());
}
