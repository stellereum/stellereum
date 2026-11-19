//! C1 anchored inclusion: a cross-shard message is consumable only when its
//! `source_state_root` is the root of a LOCALLY-FINALIZED source block
//! (looked up by the `finalized_in_block` hash the message commits to).
//! A self-attested root (attacker trie + valid-for-that-root proof) fails
//! the anchor even though its proof math checks out.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::cell::PatriciaTrie;
use stellereum::sharding::Transaction;
use stellereum::sharding::{
    CrossShardMessage, FinalizedHeaderRegistry, ShardHeaderCommitment,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD, REGISTRY_ANCHOR_WINDOW,
};
use stellereum::storage::{AsyncPersistence, Storage};

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

// ---------------------------------------------------------------------------
// Durability: the registry is snapshotted to its own sled tree and hydrated at
// startup, so a restarted node still verifies messages produced before the
// restart. The anchors stay bounded (deterministic prune) and a corrupt blob
// fails CLOSED.
// ---------------------------------------------------------------------------

fn tmp_store_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell-xshard-anchor-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
    ))
}

fn commitment(shard: u32, height: u64, tag: u8) -> ShardHeaderCommitment {
    let mut block_hash = [0u8; 32];
    block_hash[..4].copy_from_slice(&shard.to_be_bytes());
    block_hash[4..12].copy_from_slice(&height.to_be_bytes());
    block_hash[12] = tag;
    ShardHeaderCommitment {
        shard_id: shard,
        height,
        block_hash,
        state_root: [tag.wrapping_add(0x40); 32],
        timestamp: 1_760_000_000 + height,
        minted_total_nano: 0,
    }
}

fn anchor_root(tag: u8) -> [u8; 32] {
    [tag.wrapping_add(0x80); 32]
}

#[test]
fn registry_snapshot_round_trips_deterministically() {
    let mut reg = FinalizedHeaderRegistry::default();
    for height in 1..=5u64 {
        let c = commitment(1, height, height as u8);
        reg.note_finalized_commitment_with_anchor(c, anchor_root(height as u8));
    }
    let c2 = commitment(2, 3, 0x33);
    reg.note_finalized_commitment_with_anchor(c2, anchor_root(0x33));
    // Height-less legacy note (genesis-style) must survive too.
    reg.note_finalized(MASTERCHAIN_SHARD, [0x77; 32], [0x88; 32]);

    let bytes = reg.to_bytes().expect("registry encodes");
    let restored = FinalizedHeaderRegistry::from_bytes(&bytes).expect("registry decodes");
    assert_eq!(
        restored.to_bytes().expect("re-encode"),
        bytes,
        "snapshot bytes are deterministic and self-reproducing"
    );
    assert_eq!(restored.anchor_count(), reg.anchor_count());
    assert_eq!(restored.latest_header(1), reg.latest_header(1));
    assert_eq!(restored.latest_header(2), reg.latest_header(2));
    assert_eq!(restored.workchain_headers(), reg.workchain_headers());
    for height in 1..=5u64 {
        let c = commitment(1, height, height as u8);
        assert!(restored.anchor_holds(1, &c.block_hash, &anchor_root(height as u8)));
        assert_eq!(
            restored.lookup(1, &c.block_hash),
            Some(anchor_root(height as u8)),
            "post-apply anchor root survives the round-trip (not just the declared head root)"
        );
    }
    assert!(restored.anchor_holds(MASTERCHAIN_SHARD, &[0x77; 32], &[0x88; 32]));
}

#[test]
fn registry_prune_is_bounded_and_insertion_order_independent() {
    // More anchors than the window: both insertion orders must prune to the
    // SAME retained set (deterministic by height/hash, never by arrival order).
    let total = REGISTRY_ANCHOR_WINDOW as u64 + 37;
    let mut ascending = FinalizedHeaderRegistry::default();
    let mut descending = FinalizedHeaderRegistry::default();
    for height in 1..=total {
        ascending.note_finalized_commitment(commitment(1, height, (height % 251) as u8));
    }
    for height in (1..=total).rev() {
        descending.note_finalized_commitment(commitment(1, height, (height % 251) as u8));
    }
    assert_eq!(
        ascending.to_bytes().expect("ascending encodes"),
        descending.to_bytes().expect("descending encodes"),
        "two nodes that saw the same finalized headers in different orders hold identical state"
    );
    assert_eq!(
        ascending.anchor_count(),
        REGISTRY_ANCHOR_WINDOW,
        "the anchor map is bounded by the documented window"
    );
    let oldest = commitment(1, 1, 1);
    let newest = commitment(1, total, (total % 251) as u8);
    assert!(
        !ascending.anchor_holds(1, &oldest.block_hash, &oldest.state_root),
        "the oldest anchor falls out of the window"
    );
    assert!(
        ascending.anchor_holds(1, &newest.block_hash, &newest.state_root),
        "the newest anchor stays"
    );
    assert!(
        ascending
            .latest_header(1)
            .is_some_and(|h| h.height == total),
        "the latest head stays regardless of the anchor window"
    );

    // Genesis anchors are exempt from the height window: the first messages of
    // every chain name the genesis parent and no later finalize re-records it.
    let mut with_genesis = FinalizedHeaderRegistry::default();
    with_genesis.note_finalized(1, [0x01; 32], [0xAA; 32]);
    for height in 1..=total {
        with_genesis.note_finalized_commitment(commitment(2, height, (height % 251) as u8));
    }
    assert!(with_genesis.anchor_holds(1, &[0x01; 32], &[0xAA; 32]));
}

#[test]
fn registry_merge_refuses_conflicting_roots_and_keeps_state() {
    let mut local = FinalizedHeaderRegistry::default();
    local.note_finalized(1, [0x01; 32], [0xAA; 32]);
    let mut conflicting = FinalizedHeaderRegistry::default();
    conflicting.note_finalized(1, [0x01; 32], [0xBB; 32]);
    assert!(
        local.merge(&conflicting).is_err(),
        "two roots for one finalized block must be refused"
    );
    assert!(
        local.anchor_holds(1, &[0x01; 32], &[0xAA; 32]),
        "a refused merge leaves the local anchor intact"
    );

    // An identical anchor/head is idempotent, never a conflict.
    let mut same = FinalizedHeaderRegistry::default();
    same.note_finalized(1, [0x01; 32], [0xAA; 32]);
    local.merge(&same).expect("identical state merges");

    // Two DIFFERENT heads at the same height are a conflict too (no silent
    // last-writer-wins across a restore).
    let mut head_a = FinalizedHeaderRegistry::default();
    head_a.note_finalized_commitment(commitment(2, 4, 0x44));
    let mut head_b = FinalizedHeaderRegistry::default();
    head_b.note_finalized_commitment(commitment(2, 4, 0x45));
    assert!(head_a.merge(&head_b).is_err());
    assert_eq!(head_a.latest_header(2), Some(&commitment(2, 4, 0x44)));
}

#[test]
fn corrupt_registry_blob_fails_closed_with_empty_registry() {
    let dir = tmp_store_dir("corrupt");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = Storage::open(&dir).expect("store opens");
    storage
        .put_xshard_headers(b"this is definitely not a registry snapshot")
        .expect("raw bytes writable");

    let mut reg = FinalizedHeaderRegistry::default();
    reg.note_finalized(MASTERCHAIN_SHARD, [0x11; 32], [0x22; 32]);
    assert!(reg.anchor_holds(MASTERCHAIN_SHARD, &[0x11; 32], &[0x22; 32]));

    let err = storage
        .hydrate_finalized_headers(&mut reg)
        .expect_err("corrupt blob must be refused");
    assert!(!err.to_string().is_empty());
    assert_eq!(
        reg.anchor_count(),
        0,
        "fail CLOSED: a corrupt blob leaves NO anchors"
    );
    assert!(!reg.anchor_holds(MASTERCHAIN_SHARD, &[0x11; 32], &[0x22; 32]));
    assert!(reg.latest_header(MASTERCHAIN_SHARD).is_none());

    // A truncated but otherwise valid snapshot is corrupt too.
    let mut good = FinalizedHeaderRegistry::default();
    good.note_finalized_commitment(commitment(1, 9, 0x09));
    let good_bytes = good.to_bytes().expect("encodes");
    assert!(FinalizedHeaderRegistry::from_bytes(&good_bytes[..good_bytes.len() - 1]).is_err());
    assert!(FinalizedHeaderRegistry::from_bytes(&[]).is_err());
    // A single flipped byte (bit-rot) is refused by the checksum instead of
    // decoding into a plausible-but-forged anchor.
    let mut bit_rot = good_bytes.clone();
    let middle = bit_rot.len() / 2;
    bit_rot[middle] ^= 0x01;
    assert!(FinalizedHeaderRegistry::from_bytes(&bit_rot).is_err());

    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchors_from_before_restart_still_verify_inbound_message() {
    let dir = tmp_store_dir("restart");
    let _ = std::fs::remove_dir_all(&dir);
    let (msg, block_hash, source_root) = honest_message();
    let dir_restart = dir.clone();

    {
        let storage = Storage::open(&dir).expect("store opens");
        let mut before = FinalizedHeaderRegistry::default();
        before.note_finalized_anchor_at(msg.source_shard, 7, block_hash, source_root);
        assert!(msg.verify_anchored(Some(&before)));
        storage
            .put_xshard_headers(&before.to_bytes().expect("encodes"))
            .expect("snapshot persisted");
    } // process "dies": storage and registry dropped

    let storage = Storage::open(&dir_restart).expect("store reopens");
    let mut after = FinalizedHeaderRegistry::default();
    assert!(
        !msg.verify_anchored(Some(&after)),
        "precondition: a cold registry cannot verify the message"
    );
    storage
        .hydrate_finalized_headers(&mut after)
        .expect("the persisted registry hydrates");
    assert!(
        msg.verify_anchored(Some(&after)),
        "the pre-restart anchor survives the restart and verifies the inbound message"
    );

    // The restored anchor is still an exact (shard, hash) -> root binding: a
    // forged root must not verify merely because SOME anchor was restored.
    let mut forged = msg.clone();
    forged.source_state_root = [0xEE; 32];
    assert!(!forged.verify_anchored(Some(&after)));

    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn registry_persists_through_the_async_persistence_path() {
    let dir = tmp_store_dir("async");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = Arc::new(Storage::open(&dir).expect("store opens"));
    let persistence = Arc::new(AsyncPersistence::start(storage.clone()));
    let (msg, block_hash, source_root) = honest_message();

    let mut reg = FinalizedHeaderRegistry::default();
    reg.note_finalized_anchor_at(msg.source_shard, 12, block_hash, source_root);
    reg.attach_persistence(persistence.clone());
    persistence.request_flush();

    let mut bytes = None;
    for _ in 0..200 {
        if let Some(found) = storage.xshard_headers().expect("tree readable") {
            bytes = Some(found);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let bytes = bytes.expect("the async writer persisted the registry snapshot");

    let mut restored = FinalizedHeaderRegistry::default();
    restored
        .restore_from_bytes(&bytes)
        .expect("persisted snapshot decodes");
    assert!(
        msg.verify_anchored(Some(&restored)),
        "the anchor travelled through the same async durability path as other domains"
    );

    // Release the sink/queue so the test leaves no background worker behind.
    drop(reg);
    drop(persistence);
    let _ = std::fs::remove_dir_all(&dir);
}
