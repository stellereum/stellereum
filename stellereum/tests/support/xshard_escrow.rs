//! Test support: build a GENUINE, escrow-backed legacy cross-shard message.
//!
//! XSHARD-01: an inbound legacy credit is paid only against proof of the
//! SOURCE-side escrow/debit (`xshard_escrow_state_key(tx_hash)`) at a state
//! root anchored to a locally finalized source header. The one-step legacy
//! producer publishes a transfer in the same block that escrows it, so it can
//! only anchor to its parent's root (which predates the escrow) and its
//! credit is REFUSED. This helper builds the two-step form the gate accepts:
//! apply the escrow block (a real debit), then prove the escrow leaf the source
//! wrote.
//!
//! Every helper here is deterministic (fixed timestamps, no wall clock), so
//! replayed state roots match across independently built fixtures.

use std::sync::{Arc, RwLock};

use stellereum::sharding::{Block, CrossShardMessage, FinalizedHeaderRegistry, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// Apply `tx` as an ESCROW on a fresh source engine and return a message that
/// carries the source's escrow/debit proof, anchored in `registry`.
///
/// The anchor is keyed by the transaction hash itself (unique per transfer),
/// so several fixtures can share one registry without overwriting each other.
pub async fn escrow_backed_message(
    tx: &Transaction,
    registry: &Arc<RwLock<FinalizedHeaderRegistry>>,
) -> CrossShardMessage {
    let tx_hash = tx.compute_tx_hash();
    let source = Arc::new(InMemoryStateEngine::new());
    source.enable_cross_shard();
    source
        .update_account(AccountState::new(tx.from, 1_000))
        .await;
    if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(&tx.from) {
        use stellereum::post_quantum::DEFAULT_SALT;
        source
            .pin_pubkey(tx.from, scheme, &pk, &DEFAULT_SALT)
            .await
            .expect("PQ sender must pin");
    }
    let pre_root = source.get_state_root().await;
    // The anchor id is the transaction hash: unique, deterministic, and never
    // confused with a real block hash in these fixtures.
    let anchor_block = tx_hash;
    let placeholder = CrossShardMessage::new(
        tx.source_shard,
        tx.target_shard,
        tx.clone(),
        pre_root,
        anchor_block,
        None,
    );

    let escrow_block = Block {
        shard_id: tx.source_shard,
        height: 1,
        prev_hash: anchor_block,
        state_root: pre_root,
        transactions: vec![tx.clone()],
        cross_shard_out: vec![placeholder],
        timestamp: 1,
        proposer: [0x11u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    };
    let out = source.apply_block_transition(&escrow_block, 0).await;
    assert_eq!(out.status, vec![true], "the escrow tx must apply");
    let post_root = source.get_state_root().await;
    assert_eq!(
        source.get_account(&tx.from).await.map(|a| a.balance),
        Some(1_000 - tx.amount - tx.gas_limit),
        "the source debited the sender (the escrow is real)"
    );

    let proof = source
        .get_legacy_escrow_proof(&tx_hash)
        .await
        .expect("the source recorded the escrow/debit leaf");
    registry.write().expect("registry lock").note_finalized(
        tx.source_shard,
        anchor_block,
        post_root,
    );

    let msg = CrossShardMessage::new(
        tx.source_shard,
        tx.target_shard,
        tx.clone(),
        post_root,
        anchor_block,
        Some(proof),
    );
    assert!(
        msg.verify_escrow_proof(),
        "precondition: the escrow proof verifies"
    );
    msg
}

/// A carrier block that delivers exactly `msgs` to `shard_id`.
pub fn carrier(shard_id: u32, height: u64, msgs: Vec<CrossShardMessage>) -> Block {
    Block {
        shard_id,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: msgs,
        timestamp: 1,
        proposer: [0x11u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }
}
