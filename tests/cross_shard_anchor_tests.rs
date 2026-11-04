//! C1 anchored inclusion: a cross-shard message is consumable only when its
//! `source_state_root` is the root of a LOCALLY-FINALIZED source block
//! (looked up by the `finalized_in_block` hash the message commits to).
//! A self-attested root (attacker trie + valid-for-that-root proof) fails
//! the anchor even though its proof math checks out.

use ed25519_dalek::SigningKey;
use stellereum::cell::PatriciaTrie;
use stellereum::sharding::Transaction;
use stellereum::sharding::{
    CrossShardMessage, FinalizedHeaderRegistry, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A message whose proof is REAL (built from a trie) for the claimed root.
fn honest_message() -> (CrossShardMessage, [u8; 32], [u8; 32]) {
    let sender = key(2);
    let from = sender.verifying_key().to_bytes();
    let mut trie = PatriciaTrie::new();
    let mut value = Vec::with_capacity(16);
    value.extend_from_slice(&10_000u64.to_be_bytes());
    value.extend_from_slice(&7u64.to_be_bytes()); // nonce
    trie.insert(&from, &value);
    let root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&from).expect("proof exists");
    let tx = Transaction::sign(
        &sender,
        [0x33u8; 32],
        1_000,
        280_000,
        7,
        MASTERCHAIN_SHARD,
        BASE_WORKCHAIN_SHARD_INITIAL,
    );
    let block_hash = [0xABu8; 32];
    let mut msg = CrossShardMessage::new(
        MASTERCHAIN_SHARD,
        BASE_WORKCHAIN_SHARD_INITIAL,
        tx,
        root,
        block_hash,
        Some(proof),
    );
    msg.source_balance = 10_000;
    (msg, block_hash, root)
}

#[test]
fn anchored_accepts_committed_header_with_valid_proof() {
    let (msg, hash, root) = honest_message();
    // Sanity: the proof itself verifies (precondition, not the fix).
    assert!(msg.verify_inclusion_strict());
    // Unanchored contexts fail closed.
    assert!(!msg.verify_anchored(None));
    let empty = FinalizedHeaderRegistry::default();
    assert!(
        !msg.verify_anchored(Some(&empty)),
        "unknown hash fails closed"
    );

    let mut reg = FinalizedHeaderRegistry::default();
    reg.note_finalized(MASTERCHAIN_SHARD, hash, root);
    assert!(
        msg.verify_anchored(Some(&reg)),
        "committed header + valid proof verifies"
    );
}

#[test]
fn anchored_rejects_self_attested_root_with_valid_proof() {
    // Attacker trie: own root, valid-for-that-root proof, victim's tx bytes.
    let (mut msg, _hash, _root) = honest_message();
    let attacker = key(9);
    let mut evil = PatriciaTrie::new();
    // Attacker funds THEMSELVES hugely in their own trie...
    let mut value = Vec::with_capacity(16);
    value.extend_from_slice(&u64::MAX.to_be_bytes());
    value.extend_from_slice(&0u64.to_be_bytes());
    let evil_from = attacker.verifying_key().to_bytes();
    evil.insert(&evil_from, &value);
    let evil_root = evil.root_hash();
    // ...but the message still names the victim's tx. The proof must be for
    // the SENDER leaf the message will check (tx.from), which the attacker
    // cannot produce for the victim — so instead they swap the whole claim:
    // re-point the message root at their trie. Anchor check must still fail
    // because no committed header carries evil_root.
    msg.source_state_root = evil_root;
    let mut reg = FinalizedHeaderRegistry::default();
    // Honest header registered; evil root anchored nowhere.
    reg.note_finalized(MASTERCHAIN_SHARD, [0xABu8; 32], [0xCDu8; 32]);
    assert!(
        !msg.verify_anchored(Some(&reg)),
        "C1: self-attested root must not verify without a committed header"
    );
}

#[test]
fn anchored_rejects_wrong_shard_header() {
    let (msg, hash, root) = honest_message();
    let mut reg = FinalizedHeaderRegistry::default();
    // Same hash+root, but recorded under the WRONG shard: shard confusion
    // must not verify.
    reg.note_finalized(BASE_WORKCHAIN_SHARD_INITIAL, hash, root);
    assert!(
        !msg.verify_anchored(Some(&reg)),
        "shard mismatch must fail closed"
    );
}

#[test]
fn registry_anchor_holds_mirror() {
    let reg = FinalizedHeaderRegistry::default();
    assert!(!reg.anchor_holds(MASTERCHAIN_SHARD, &[1u8; 32], &[2u8; 32]));
    let mut reg = reg;
    reg.note_finalized(MASTERCHAIN_SHARD, [1u8; 32], [2u8; 32]);
    assert!(reg.anchor_holds(MASTERCHAIN_SHARD, &[1u8; 32], &[2u8; 32]));
    assert!(!reg.anchor_holds(BASE_WORKCHAIN_SHARD_INITIAL, &[1u8; 32], &[2u8; 32]));
    assert!(!reg.anchor_holds(MASTERCHAIN_SHARD, &[1u8; 32], &[3u8; 32]));
}
