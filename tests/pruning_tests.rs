//! P1 (a): disk pruning and archive mode.
//!
//! The block store had no retention path at all: every finalized block was
//! written and nothing was ever deleted. A node that had been running
//! unthrottled held ~2.9 GB on disk, and the two `prune_*_below` functions that
//! do exist had no callers.
//!
//! The property that matters is not "does disk shrink" but "does the retained
//! part still describe the same chain". Pruning a block whose child is also
//! pruned would leave a suffix that no longer links back to genesis, so every
//! test below checks the surviving prefix, not just the counts.

use ed25519_dalek::SigningKey;
use stellereum::sharding::Transaction;
use stellereum::storage::{BlockHeaderRecord, RetentionConfig, Storage};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-prune-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn tx(nonce: u64) -> Transaction {
    let key = SigningKey::from_bytes(&[1u8; 32]);
    Transaction::sign(&key, [0xEE; 32], 1, 0, nonce, 0, 0)
}

fn chain(store: &Storage, n: u64) -> Vec<stellereum::storage::BlockHash> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..n {
        let __order_txs = vec![tx(0)];
        let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
        let b = stellereum::sharding::Block {
            shard_id: 1,
            height: h,
            prev_hash: prev,
            state_root: [h as u8; 32],
            timestamp: 1_700_000_000 + h,
            proposer: [1u8; 32],
            transactions: __order_txs,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cross_shard_out: vec![],
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
        };
        prev = store.put_block(&b).expect("persist block");
        out.push(prev);
    }
    out
}

#[test]
fn archive_is_the_default_so_nothing_is_destroyed_by_accident() {
    let d = RetentionConfig::default();
    assert!(
        d.archive,
        "dropping a block body is irreversible; opt in, don't default in"
    );
    assert!(d.keep_blocks > 0);
}

#[test]
fn every_block_writes_a_header_record() {
    let dir = tmpdir("hdr");
    let store = Storage::open(&dir).expect("open");
    let hashes = chain(&store, 12);

    assert_eq!(
        store.header_count().expect("count"),
        12,
        "one header per block"
    );
    for h in 0..12u64 {
        let rec = store.header_at(h).expect("read").expect("header exists");
        assert_eq!(rec.height, h);
        assert_eq!(
            rec.block_hash, hashes[h as usize],
            "header must carry the real block hash"
        );
        assert_eq!(rec.tx_count, 1);
    }
    // The header must chain: each record's prev_hash is the one before it.
    for h in 1..12u64 {
        let prev_rec = store.header_at(h - 1).unwrap().unwrap();
        let rec = store.header_at(h).unwrap().unwrap();
        assert_eq!(
            rec.prev_hash, prev_rec.block_hash,
            "headers must link at height {h}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn header_record_survives_pruning_of_the_body() {
    let dir = tmpdir("survive");
    let store = Storage::open(&dir).expect("open");
    chain(&store, 20);

    store.prune_blocks_below(10).expect("prune");
    assert!(
        store.block_count().expect("blocks") < 20,
        "bodies must actually go"
    );
    assert_eq!(
        store.header_count().expect("headers"),
        20,
        "the chain must still be walkable after the bodies are gone"
    );
    assert!(
        store.header_at(0).expect("read").is_some(),
        "oldest header must remain"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pruning_never_orphans_the_retained_suffix() {
    // The bug this pins: removing a block but keeping its child leaves a suffix
    // whose prev_hash points at a hash nobody can produce any more.
    let dir = tmpdir("orphan");
    let store = Storage::open(&dir).expect("open");
    let hashes = chain(&store, 20);

    // keep_from=5 must retain bodies from height 4 upward, so that the block at
    // height 5 still finds its parent at height 4.
    store.prune_blocks_below(5).expect("prune");
    for h in 4..20u64 {
        let rec = store.header_at(h).unwrap().unwrap();
        assert!(
            store.get_block(&rec.block_hash).expect("read").is_some(),
            "body at {h} must survive"
        );
    }
    assert!(
        store.get_block(&hashes[0]).expect("read").is_none(),
        "an old body should have been dropped"
    );
    // The retained window starts at 4, and 4's predecessor is 3, so 4 is the
    // boundary: everything from 4 up is intact and walks back to 3.
    let boundary = store.header_at(4).unwrap().unwrap();
    assert_eq!(
        boundary.prev_hash, hashes[3],
        "boundary block keeps a resolvable parent link"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pruning_is_idempotent_and_bounded() {
    let dir = tmpdir("idem");
    let store = Storage::open(&dir).expect("open");
    chain(&store, 10);

    let a = store.prune_blocks_below(5).expect("prune");
    let b = store.prune_blocks_below(5).expect("prune again");
    assert!(a > 0, "the first pass must do the work");
    assert_eq!(
        b, 0,
        "a second pass with the same cursor must remove nothing"
    );
    assert!(
        !store.has_blocks_below(5).expect("check"),
        "nothing should remain eligible"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pruning_reports_whether_more_remains() {
    // The flusher is the only writer, so it needs to know whether to schedule
    // another pass instead of scanning the whole tree inline.
    let dir = tmpdir("more");
    let store = Storage::open(&dir).expect("open");
    chain(&store, 30);
    assert!(
        store.has_blocks_below(20).expect("check"),
        "30 blocks, cursor 20"
    );

    // A cursor beyond the tip makes every body removable, including the tip's:
    // the boundary rule only requires that a block's CHILD survives, and the tip
    // has none. Headers still describe the whole chain.
    assert!(
        store.has_blocks_below(31).expect("check"),
        "cursor 31 > tip 29"
    );
    assert_eq!(
        store.prune_blocks_below(31).expect("prune"),
        30,
        "all 30 bodies go, headers stay"
    );

    // The case that used to report "more to do" forever: with the cursor at 1
    // nothing is removable, because height 0 is a boundary whose successor is
    // the first kept block.
    assert!(
        !store.has_blocks_below(1).expect("check"),
        "cursor 1 leaves only the boundary, so there is nothing to do"
    );
    assert_eq!(
        store.prune_blocks_below(1).expect("prune"),
        0,
        "and pruning is a no-op"
    );
    assert_eq!(
        store.header_count().expect("headers"),
        30,
        "the chain is still walkable"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn state_snapshots_keep_a_ring_and_never_the_newest() {
    // `load_state_into` reads only the newest snapshot. Pruning must be strictly
    // below the cursor, never at or above it, or a restart silently comes up
    // with no state and no validators.
    let dir = tmpdir("ring");
    let store = Storage::open(&dir).expect("open");
    for h in [0u64, 100, 200, 300, 400, 500] {
        store.put_state(h, &h.to_be_bytes()).expect("put state");
        store.put_domains(h, &h.to_be_bytes()).expect("put domains");
    }

    let keep = 300u64;
    store.prune_state_below(keep).expect("prune state");
    store.prune_domains_below(keep).expect("prune domains");

    let (newest_state, _) = store
        .latest_state()
        .expect("latest state")
        .expect("present");
    let (newest_domains, _) = store
        .latest_domains()
        .expect("latest domains")
        .expect("present");
    assert_eq!(
        newest_state, 500,
        "the newest state snapshot must survive pruning"
    );
    assert_eq!(
        newest_domains, 500,
        "the newest domain snapshot must survive pruning"
    );
    assert!(
        newest_domains > keep,
        "pruning must be strictly below the cursor"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn block_store_survives_a_reopen() {
    let dir = tmpdir("reopen");
    {
        let store = Storage::open(&dir).expect("open");
        let hashes = chain(&store, 6);
        store.set_finalized(5, &hashes[5]).expect("set finalized");
        store.prune_blocks_below(3).expect("prune");
        store.flush().expect("flush");
    }
    let store = Storage::open(&dir).expect("reopen");
    let (height, hash) = store.finalized().expect("read finalized").expect("present");
    assert_eq!(height, 5);
    assert_eq!(hash, store.header_at(5).unwrap().unwrap().block_hash);
    assert_eq!(
        store.header_count().expect("headers"),
        6,
        "headers persist across restart"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn stored_entries_shrinks_after_pruning() {
    // The metric an operator can actually watch.
    let dir = tmpdir("metric");
    let store = Storage::open(&dir).expect("open");
    chain(&store, 20);
    let before = store.stored_block_entries();
    store.prune_blocks_below(15).expect("prune");
    let after = store.stored_block_entries();
    assert!(after < before, "entries {before} -> {after} must shrink");
    assert!(after > 0, "the retained window must still hold data");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn header_record_fields_match_the_block() {
    let dir = tmpdir("fields");
    let _ = Storage::open(&dir).expect("open");
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let __order_txs = vec![Transaction::sign(&key, [1u8; 32], 5, 7, 0, 0, 0)];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
    let b = stellereum::sharding::Block {
        shard_id: 1,
        height: 42,
        prev_hash: [7u8; 32],
        state_root: [3u8; 32],
        timestamp: 1_700_000_123,
        proposer: key.verifying_key().to_bytes(),
        transactions: __order_txs,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cross_shard_out: vec![],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    let rec = BlockHeaderRecord::of(&b);
    assert_eq!(rec.height, 42);
    assert_eq!(rec.prev_hash, [7u8; 32]);
    assert_eq!(rec.state_root, [3u8; 32]);
    assert_eq!(rec.proposer, key.verifying_key().to_bytes());
    assert_eq!(rec.timestamp, 1_700_000_123);
    assert_eq!(rec.tx_count, 1);
    assert_eq!(rec.gas_used, 7, "gas_used must be the sum of tx gas");
    assert_eq!(rec.block_hash, b.compute_hash());
    std::fs::remove_dir_all(&dir).ok();
}
