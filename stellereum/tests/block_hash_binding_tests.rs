//! The block hash MUST commit to every consensus-relevant transaction field.
//! If it did not, a Byzantine proposer could produce two distinct block bodies
//! under one voted hash, and validators would finalize different state.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::sharding::{Block, CrossShardMessage, Transaction, MASTERCHAIN_SHARD};
use stellereum::svm::OpCode;

fn mk(sk: &SigningKey, txs: Vec<Transaction>, cross: Vec<CrossShardMessage>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: cross,
        timestamp: 7,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(sk);
    b
}

#[test]
fn block_hash_binds_payload_nonce_gas_and_shards() {
    let sk = SigningKey::generate(&mut OsRng);
    let user = SigningKey::generate(&mut OsRng);
    let to = [9u8; 32];

    let base = Transaction::sign(&user, to, 100, 5, 0, 1, 1);
    let b0 = mk(&sk, vec![base.clone()], vec![]);

    // payload differs
    let with_payload =
        Transaction::sign_with_payload(&user, to, 100, 5, 0, 1, 1, vec![OpCode::Nop]);
    assert_ne!(
        b0.compute_hash(),
        mk(&sk, vec![with_payload], vec![]).compute_hash(),
        "payload must be bound into the block hash"
    );

    // nonce differs
    let other_nonce = Transaction::sign(&user, to, 100, 5, 1, 1, 1);
    assert_ne!(
        b0.compute_hash(),
        mk(&sk, vec![other_nonce], vec![]).compute_hash(),
        "nonce must be bound into the block hash"
    );

    // gas_limit differs
    let other_gas = Transaction::sign(&user, to, 100, 9, 0, 1, 1);
    assert_ne!(
        b0.compute_hash(),
        mk(&sk, vec![other_gas], vec![]).compute_hash(),
        "gas_limit must be bound into the block hash"
    );

    // target shard differs
    let other_shard = Transaction::sign(&user, to, 100, 5, 0, 1, 2);
    assert_ne!(
        b0.compute_hash(),
        mk(&sk, vec![other_shard], vec![]).compute_hash(),
        "target shard must be bound into the block hash"
    );

    // deterministic for identical content
    assert_eq!(
        b0.compute_hash(),
        mk(&sk, vec![base], vec![]).compute_hash()
    );
}

#[test]
fn block_hash_binds_cross_shard_messages() {
    let sk = SigningKey::generate(&mut OsRng);
    let user = SigningKey::generate(&mut OsRng);

    let tx = Transaction::sign(&user, [9u8; 32], 10, 0, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);

    let empty = mk(&sk, vec![], vec![]);
    let with_msg = mk(&sk, vec![], vec![msg]);
    assert_ne!(
        empty.compute_hash(),
        with_msg.compute_hash(),
        "cross-shard messages must be bound into the block hash"
    );
}

#[test]
fn block_hash_is_independent_of_validator_signatures() {
    // Signatures sign the hash, so the hash must not depend on them (otherwise
    // the signature would be self-referential).
    let sk = SigningKey::generate(&mut OsRng);
    let mut b = mk(&sk, vec![], vec![]);
    let h1 = b.compute_hash();
    b.sign_block(&sk);
    b.sign_block(&sk);
    assert_eq!(
        h1,
        b.compute_hash(),
        "hash must not change when signatures are added"
    );
}
