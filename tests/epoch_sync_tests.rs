//! Epoch-scoped sync: a wiped node must not see the previous chain, and two
//! networks must not contaminate each other — while legitimate catch-up inside
//! one epoch keeps working.
//!
//! Background (src/network.rs `EpochTag`, src/consensus_net.rs topics): every
//! published blob name and both pubsub topics are scoped to a chain epoch
//! derived from the genesis fingerprint. Two properties must hold at once:
//! (1) a node must NEVER follow a foreign epoch's data, (2) the epoch must
//! NEVER block legitimate catch-up within its own chain.
//!
//! ## Why these tests look the way they do
//!
//! `P2pNetworkAdapter` holds an `Arc<infnode::node::Node>`, and `Node::new`
//! opens a sled database and binds a libp2p listener, so the adapter CANNOT be
//! constructed in-process (see tests/retro_publish_tests.rs for the same
//! reasoning). The epoch-sensitive logic is therefore driven through:
//! - the REAL public name helpers (`EpochTag`, `block_body_blob_name`,
//!   `consensus_topic`, `tx_topic`),
//! - a `FakeEpochStore` that mirrors the adapter's publish/fetch semantics
//!   (payload formats, fail-closed `None` reads) keyed by epoch-scoped names,
//! - the REAL sync primitives (`collect_missing_blocks`, `validate_sync_chain`,
//!   `fast_sync_state`) for the catch-up path.
//!
//! The head/header/header-index/snapshot name helpers in src/network.rs are
//! private (`fn head_name`, `fn header_name`, `fn header_index_name`,
//! `fn snapshot_name`; see src/network.rs:60-81), so this file mirrors their
//! exact format strings in `mirror_*` functions. To keep that mirror honest,
//! the body mirror is pinned byte-for-byte against the REAL public helper
//! `block_body_blob_name` on every input used: if src/network.rs changes its
//! convention, Test 1 fails explicitly instead of testing a stale copy.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::consensus_net::{consensus_topic, tx_topic};
use stellereum::network::{
    block_body_blob_name, EpochTag, BUCKET_STELLEREUM_BLOCKS, BUCKET_STELLEREUM_HEAD,
    BUCKET_STELLEREUM_HEADERS, BUCKET_STELLEREUM_STATE,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::BlockHeaderRecord;
use stellereum::sync::{collect_missing_blocks, fast_sync_state, validate_sync_chain};

// ==================== Name mirrors (src/network.rs:60-81) ====================
//
// Byte-exact copies of the private helpers, parameterized by epoch. The body
// mirror is checked against the real `block_body_blob_name` in Test 1, so any
// drift between this file and src/network.rs is a loud failure, not a silent
// re-implementation.

fn mirror_head_name(epoch: &EpochTag, shard_id: u32) -> String {
    format!("{}_shard_{shard_id}_head", epoch.as_str())
}

fn mirror_header_name(epoch: &EpochTag, height: u64) -> String {
    format!("{}_h_{height}", epoch.as_str())
}

fn mirror_header_index_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_hi_{shard_id}_{height}", epoch.as_str())
}

fn mirror_block_name(epoch: &EpochTag, hash_hex: &str) -> String {
    format!("{}_blk_{hash_hex}", epoch.as_str())
}

fn mirror_snapshot_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_snap_{shard_id}_{height}", epoch.as_str())
}

fn epoch_a() -> EpochTag {
    EpochTag::from_genesis(&[0x11u8; 32])
}

fn epoch_b() -> EpochTag {
    EpochTag::from_genesis(&[0x22u8; 32])
}

// ==================== FakeEpochStore ====================
//
// Mirrors `P2pNetworkAdapter` publish/fetch semantics (payload formats and
// fail-closed `None` reads) against an in-memory blob map, namespaced by the
// epoch exactly the way the adapter namespaces the DHT. Bodies use the REAL
// `block_body_blob_name` helper, so body isolation is tested against
// production naming, not a mirror.

#[derive(Default)]
struct FakeEpochStore {
    blobs: RefCell<HashMap<(String, String), Vec<u8>>>,
}

impl FakeEpochStore {
    fn put(&self, bucket: &str, name: &str, bytes: Vec<u8>) {
        self.blobs
            .borrow_mut()
            .insert((bucket.to_string(), name.to_string()), bytes);
    }

    fn get(&self, bucket: &str, name: &str) -> Option<Vec<u8>> {
        self.blobs
            .borrow()
            .get(&(bucket.to_string(), name.to_string()))
            .cloned()
    }

    // ---- head (mirrors publish_head / fetch_head) ----
    fn publish_head(&self, epoch: &EpochTag, shard_id: u32, height: u64, hash: [u8; 32]) {
        let payload = format!("{height}:{}", hex::encode(hash));
        self.put(
            BUCKET_STELLEREUM_HEAD,
            &mirror_head_name(epoch, shard_id),
            payload.into_bytes(),
        );
    }

    fn fetch_head(&self, epoch: &EpochTag, shard_id: u32) -> Option<(u64, [u8; 32])> {
        let bytes = self.get(BUCKET_STELLEREUM_HEAD, &mirror_head_name(epoch, shard_id))?;
        let s = String::from_utf8(bytes).ok()?;
        let mut it = s.split(':');
        let height = it.next()?.parse::<u64>().ok()?;
        let raw = hex::decode(it.next()?).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw);
        Some((height, hash))
    }

    // ---- headers (mirrors persist_block_header / fetch_head_hash / fetch_block_header) ----
    fn persist_header(&self, epoch: &EpochTag, shard_id: u32, block: &Block) {
        let rec = BlockHeaderRecord::of(block);
        if let Ok(bytes) = bincode::serialize(&rec) {
            self.put(
                BUCKET_STELLEREUM_HEADERS,
                &mirror_header_name(epoch, block.height),
                bytes,
            );
            let idx = format!("{}:{}", block.height, hex::encode(block.compute_hash()));
            self.put(
                BUCKET_STELLEREUM_HEADERS,
                &mirror_header_index_name(epoch, shard_id, block.height),
                idx.into_bytes(),
            );
        }
    }

    fn fetch_head_hash(&self, epoch: &EpochTag, shard_id: u32, height: u64) -> Option<[u8; 32]> {
        let bytes = self.get(
            BUCKET_STELLEREUM_HEADERS,
            &mirror_header_index_name(epoch, shard_id, height),
        )?;
        let s = String::from_utf8(bytes).ok()?;
        let (_h, hash_hex) = s.split_once(':')?;
        let raw = hex::decode(hash_hex).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Some(out)
    }

    fn fetch_header(
        &self,
        epoch: &EpochTag,
        height: u64,
        expected_hash: [u8; 32],
    ) -> Option<BlockHeaderRecord> {
        let bytes = self.get(
            BUCKET_STELLEREUM_HEADERS,
            &mirror_header_name(epoch, height),
        )?;
        let rec: BlockHeaderRecord = bincode::deserialize(&bytes).ok()?;
        if rec.height != height || rec.block_hash != expected_hash {
            return None;
        }
        Some(rec)
    }

    // ---- snapshot (mirrors persist_state_snapshot / fetch_state_snapshot) ----
    fn persist_snapshot(&self, epoch: &EpochTag, shard_id: u32, height: u64, data: &[u8]) {
        self.put(
            BUCKET_STELLEREUM_STATE,
            &mirror_snapshot_name(epoch, shard_id, height),
            data.to_vec(),
        );
    }

    fn fetch_snapshot(&self, epoch: &EpochTag, shard_id: u32, height: u64) -> Option<Vec<u8>> {
        self.get(
            BUCKET_STELLEREUM_STATE,
            &mirror_snapshot_name(epoch, shard_id, height),
        )
    }

    // ---- body (REAL production naming via block_body_blob_name) ----
    fn persist_body(&self, epoch: &EpochTag, block: &Block) {
        let hash = block.compute_hash();
        let bytes = bincode::serialize(block).expect("block must serialize");
        self.put(
            BUCKET_STELLEREUM_BLOCKS,
            &block_body_blob_name(epoch, &hash),
            bytes,
        );
    }

    fn fetch_body(&self, epoch: &EpochTag, hash: &[u8; 32]) -> Option<Block> {
        let bytes = self.get(BUCKET_STELLEREUM_BLOCKS, &block_body_blob_name(epoch, hash))?;
        bincode::deserialize(&bytes).ok()
    }
}

// ==================== Quorum chain + catch-up helpers ====================

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn attach_quorum(b: &mut Block, ks: &[SigningKey], height: u64, bh: [u8; 32]) {
    let sigs = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    });
}

async fn build_chain(ks: &[SigningKey], base: &Arc<InMemoryStateEngine>, n: u64) -> Vec<Block> {
    let vs = vset(ks);
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let root = base.get_state_root().await;
        // F8: proposer must match the deterministic schedule.
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer = ks
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member")
            .clone();
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
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
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&proposer);
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, h, bh);
        prev = b.compute_hash();
        out.push(b);
    }
    out
}

// The catch-up sequence as the node performs it: walk prev_hash back to our
// own finalized block, refuse forks and quorum-less histories, then replay
// with a per-block state-root check. Mirrors tests/catch_up_tests.rs.
async fn catch_up(
    blocks: &[Block],
    our_state: &Arc<InMemoryStateEngine>,
    our_last: [u8; 32],
    first_height: u64,
    validators: &ValidatorSet,
) -> Result<u64, String> {
    let head = blocks.last().ok_or("empty chain")?.compute_hash();
    let map: HashMap<[u8; 32], Block> = blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect();
    let missing = collect_missing_blocks(head, our_last, 100_000, move |h| {
        let m = map.clone();
        async move { m.get(&h).cloned() }
    })
    .await?;
    if missing.is_empty() {
        return Ok(0);
    }
    if missing[0].height != first_height {
        return Err(format!(
            "first synced height {} != expected {first_height}",
            missing[0].height
        ));
    }
    validate_sync_chain(&missing, first_height, our_last, validators)?;
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

// ==================== Test 1: epoch isolation of names ====================

#[test]
fn epoch_isolation_of_names_disjoint_and_deterministic() {
    let a = epoch_a();
    let b = epoch_b();
    assert_ne!(a, b, "precondition: the two test epochs must differ");

    let shards = [0u32, 1, 7];
    let heights: Vec<u64> = (1..=32).collect();
    // Deterministic hash-hex sweep: no randomness, covers many distinct bodies.
    let hashes: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();

    let mut names_a: HashSet<String> = HashSet::new();
    let mut names_b: HashSet<String> = HashSet::new();
    // Per-kind sets so a failure names exactly which isolation broke.
    let mut overlap_by_kind: Vec<(&str, Vec<String>)> = Vec::new();

    let mut collect = |kind: &'static str, sa: &mut HashSet<String>, sb: &mut HashSet<String>| {
        let overlap: Vec<String> = sa.intersection(sb).cloned().collect();
        overlap_by_kind.push((kind, overlap));
    };

    let mut head_a = HashSet::new();
    let mut head_b = HashSet::new();
    let mut header_a = HashSet::new();
    let mut header_b = HashSet::new();
    let mut index_a = HashSet::new();
    let mut index_b = HashSet::new();
    let mut body_a = HashSet::new();
    let mut body_b = HashSet::new();
    let mut snap_a = HashSet::new();
    let mut snap_b = HashSet::new();

    for &shard in &shards {
        for &h in &heights {
            head_a.insert(mirror_head_name(&a, shard));
            head_b.insert(mirror_head_name(&b, shard));
            header_a.insert(mirror_header_name(&a, h));
            header_b.insert(mirror_header_name(&b, h));
            index_a.insert(mirror_header_index_name(&a, shard, h));
            index_b.insert(mirror_header_index_name(&b, shard, h));
            snap_a.insert(mirror_snapshot_name(&a, shard, h));
            snap_b.insert(mirror_snapshot_name(&b, shard, h));
        }
    }
    for h in &hashes {
        let hx = hex::encode(h);
        // Body isolation is asserted against the REAL production helper.
        body_a.insert(block_body_blob_name(&a, h));
        body_b.insert(block_body_blob_name(&b, h));
        // ...and the mirror must agree with production on every input, so a
        // drift between this file and src/network.rs is a loud failure.
        assert_eq!(
            mirror_block_name(&a, &hx),
            block_body_blob_name(&a, h),
            "epoch isolation BROKE (test mirror drifted from src/network.rs for epoch A body naming)"
        );
        assert_eq!(
            mirror_block_name(&b, &hx),
            block_body_blob_name(&b, h),
            "epoch isolation BROKE (test mirror drifted from src/network.rs for epoch B body naming)"
        );
    }

    collect("head", &mut head_a, &mut head_b);
    collect("header", &mut header_a, &mut header_b);
    collect("header-index", &mut index_a, &mut index_b);
    collect("body", &mut body_a, &mut body_b);
    collect("snapshot", &mut snap_a, &mut snap_b);

    for (kind, overlap) in &overlap_by_kind {
        assert!(
            overlap.is_empty(),
            "epoch isolation BROKE: {kind} blob names overlap across epochs, e.g. {overlap:?}"
        );
    }

    names_a.extend(head_a.iter().cloned());
    names_a.extend(header_a.iter().cloned());
    names_a.extend(index_a.iter().cloned());
    names_a.extend(body_a.iter().cloned());
    names_a.extend(snap_a.iter().cloned());
    names_b.extend(head_b.iter().cloned());
    names_b.extend(header_b.iter().cloned());
    names_b.extend(index_b.iter().cloned());
    names_b.extend(body_b.iter().cloned());
    names_b.extend(snap_b.iter().cloned());
    let total_overlap: Vec<&String> = names_a.intersection(&names_b).collect();
    assert!(
        total_overlap.is_empty(),
        "epoch isolation BROKE: blob-name sets overlap across epochs: {total_overlap:?}"
    );

    // Determinism: identical inputs reproduce identical names.
    let a2 = EpochTag::from_genesis(&[0x11u8; 32]);
    assert_eq!(
        a, a2,
        "the same genesis fingerprint must always name the same epoch"
    );
    for &shard in &shards {
        for &h in &[1u64, 17, 32] {
            assert_eq!(mirror_head_name(&a, shard), mirror_head_name(&a2, shard));
            assert_eq!(mirror_header_name(&a, h), mirror_header_name(&a2, h));
            assert_eq!(
                mirror_header_index_name(&a, shard, h),
                mirror_header_index_name(&a2, shard, h)
            );
            assert_eq!(
                mirror_snapshot_name(&a, shard, h),
                mirror_snapshot_name(&a2, shard, h)
            );
        }
    }
    for h in &hashes {
        assert_eq!(block_body_blob_name(&a, h), block_body_blob_name(&a2, h));
    }
}

// ==================== Test 2: cross-epoch invisibility ====================

#[tokio::test]
async fn cross_epoch_reader_finds_nothing_from_foreign_epoch() {
    let epoch_store = epoch_a(); // the chain that published
    let epoch_reader = epoch_b(); // the wiped / foreign chain reading
    let net = FakeEpochStore::default();

    let ks = keys(3);
    let base = Arc::new(InMemoryStateEngine::new());
    base.update_account(AccountState::new([0x55u8; 32], 777_000))
        .await;
    let blocks = build_chain(&ks, &base, 6).await;
    let snap = base.create_snapshot().await;

    // Epoch A publishes head + headers + snapshot + bodies.
    let shard = MASTERCHAIN_SHARD;
    for blk in &blocks {
        net.persist_header(&epoch_store, shard, blk);
        net.persist_body(&epoch_store, blk);
    }
    let tip = blocks.last().unwrap();
    net.publish_head(&epoch_store, shard, tip.height, tip.compute_hash());
    net.persist_snapshot(&epoch_store, shard, 1, &snap);

    // Control: the publishing epoch sees everything (the store is not empty,
    // so "reader finds nothing" below is a real isolation result).
    let (head_h, head_hash) = net
        .fetch_head(&epoch_store, shard)
        .expect("control: epoch A must see its own head");
    assert_eq!(head_h, tip.height);
    assert_eq!(head_hash, tip.compute_hash());

    // A reader scoped to epoch B finds NOTHING: each read returns None rather
    // than erroring or leaking foreign data.
    assert!(
        net.fetch_head(&epoch_reader, shard).is_none(),
        "epoch isolation BROKE: cross-epoch head fetch leaked (reader saw epoch A's head pointer)"
    );
    for blk in &blocks {
        let h = blk.compute_hash();
        assert!(
            net.fetch_head_hash(&epoch_reader, shard, blk.height)
                .is_none(),
            "epoch isolation BROKE: cross-epoch header-index fetch leaked at height {}",
            blk.height
        );
        assert!(
            net.fetch_header(&epoch_reader, blk.height, h).is_none(),
            "epoch isolation BROKE: cross-epoch header fetch leaked at height {}",
            blk.height
        );
        assert!(
            net.fetch_body(&epoch_reader, &h).is_none(),
            "epoch isolation BROKE: cross-epoch body fetch leaked for block {}",
            hex::encode(h)
        );
    }
    assert!(
        net.fetch_snapshot(&epoch_reader, shard, 1).is_none(),
        "epoch isolation BROKE: cross-epoch snapshot fetch leaked"
    );
}

// ==================== Test 3: same-epoch catch-up unaffected ====================

#[tokio::test]
async fn same_epoch_catch_up_succeeds_and_lands_on_peer_root() {
    let epoch = epoch_a();
    let net = FakeEpochStore::default();

    let ks = keys(4);
    let vs = vset(&ks);
    let payer = ks[0].verifying_key().to_bytes();
    let base = Arc::new(InMemoryStateEngine::new());
    base.update_account(AccountState::new(payer, 1_000_000_000_000))
        .await;
    let blocks = build_chain(&ks, &base, 8).await;
    let snap = base.create_snapshot().await;
    let peer_root = blocks.last().unwrap().state_root;

    // Publish head + headers + snapshot + bodies under ONE epoch.
    let shard = MASTERCHAIN_SHARD;
    for blk in &blocks {
        net.persist_header(&epoch, shard, blk);
        net.persist_body(&epoch, blk);
    }
    let tip = blocks.last().unwrap();
    let tip_hash = tip.compute_hash();
    net.publish_head(&epoch, shard, tip.height, tip_hash);
    net.persist_snapshot(&epoch, shard, 1, &snap);

    // We are three blocks behind; replay the prefix so our root matches.
    let we_have = 5u64;
    let our_last = blocks[(we_have - 1) as usize].compute_hash();
    let our_state = Arc::new(InMemoryStateEngine::new());
    our_state
        .update_account(AccountState::new(payer, 1_000_000_000_000))
        .await;
    for blk in blocks.iter().take(we_have as usize) {
        assert_eq!(
            our_state.get_state_root().await,
            blk.state_root,
            "epoch refactor broke the normal path: prefix replay diverged before catch-up"
        );
        our_state
            .apply_block_parallel_fees(&blk.transactions, blk.timestamp)
            .await;
    }

    // The catch-up sequence a node runs: discover the head, walk prev_hash via
    // epoch-scoped body fetches, validate, then root-checked replay.
    let (head_h, head_hash) = net
        .fetch_head(&epoch, shard)
        .expect("epoch refactor broke the normal path: same-epoch head fetch returned None");
    assert_eq!((head_h, head_hash), (tip.height, tip_hash));

    let map: HashMap<[u8; 32], Block> = blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect();
    let fetch = |h: [u8; 32]| {
        let m = map.clone();
        let store_blobs = net.blobs.borrow().clone();
        async move {
            // Resolve through the epoch-scoped body name, exactly like
            // adapter.fetch_block: only bodies published under OUR epoch exist.
            let name = block_body_blob_name(&epoch_a(), &h);
            let bytes = store_blobs.get(&(BUCKET_STELLEREUM_BLOCKS.to_string(), name))?;
            let blk: Block = bincode::deserialize(bytes).ok()?;
            let _ = m;
            Some(blk)
        }
    };
    let missing = collect_missing_blocks(head_hash, our_last, 100_000, fetch)
        .await
        .expect("epoch refactor broke the normal path: collect_missing_blocks failed same-epoch");
    assert_eq!(
        missing.len(),
        3,
        "exactly the three missing blocks are expected"
    );
    validate_sync_chain(&missing, we_have + 1, our_last, &vs)
        .expect("epoch refactor broke the normal path: validate_sync_chain failed same-epoch");

    // Root-checked replay of the fetched bodies, plus the snapshot check: the
    // snapshot must restore to the header-committed root (poisoning guard).
    let target = Arc::new(InMemoryStateEngine::new());
    target
        .update_account(AccountState::new(payer, 1_000_000_000_000))
        .await;
    let snap_bytes = net
        .fetch_snapshot(&epoch, shard, 1)
        .expect("epoch refactor broke the normal path: same-epoch snapshot fetch returned None");
    fast_sync_state(
        &target,
        base.get_state_root().await,
        || async { Some(snap_bytes.clone()) },
        /* fetch_domain */ |_| async { None },
    )
    .await
    .expect("epoch refactor broke the normal path: same-epoch snapshot failed root check");
    assert_eq!(
        target.get_state_root().await,
        peer_root,
        "epoch refactor broke the normal path: snapshot did not land on the peer root"
    );

    let n = catch_up(&blocks, &our_state, our_last, we_have + 1, &vs)
        .await
        .expect("epoch refactor broke the normal path: catch-up sequence failed same-epoch");
    assert_eq!(n, 3);
    assert_eq!(
        our_state.get_state_root().await,
        peer_root,
        "epoch refactor broke the normal path: catch-up did not land on the peer root"
    );
}

// ==================== Test 4: topic isolation ====================

#[test]
fn topic_isolation_across_epochs_and_message_kinds() {
    let a = epoch_a();
    let b = epoch_b();

    let ca = consensus_topic(a.as_str());
    let cb = consensus_topic(b.as_str());
    let ta = tx_topic(a.as_str());
    let tb = tx_topic(b.as_str());

    assert_ne!(
        ca, cb,
        "topic isolation BROKE: two epochs share a consensus topic ({ca})"
    );
    assert_ne!(
        ta, tb,
        "topic isolation BROKE: two epochs share a tx-gossip topic ({ta})"
    );
    assert_ne!(
        ca, ta,
        "topic isolation BROKE: consensus and tx traffic share one topic ({ca})"
    );
    assert_ne!(
        cb, tb,
        "topic isolation BROKE: consensus and tx traffic share one topic ({cb})"
    );
    assert_eq!(
        ca,
        consensus_topic(a.as_str()),
        "same epoch must reuse its topic"
    );
    assert_eq!(ta, tx_topic(a.as_str()), "same epoch must reuse its topic");

    // A message published under epoch A's topic is not visible under epoch B's
    // subscription name. No live network needed: visibility IS the topic name,
    // so an in-process topic -> messages map proves the property.
    let mut bus: HashMap<String, Vec<String>> = HashMap::new();
    bus.entry(ca.clone())
        .or_default()
        .push("proposal#1".to_string());
    bus.entry(ta.clone())
        .or_default()
        .push("tx:deadbeef".to_string());

    let got_b: &[String] = bus.get(&cb).map(Vec::as_slice).unwrap_or(&[]);
    assert!(
        got_b.is_empty(),
        "topic isolation BROKE: epoch B's consensus subscription sees epoch A's message: {got_b:?}"
    );
    let got_tb: &[String] = bus.get(&tb).map(Vec::as_slice).unwrap_or(&[]);
    assert!(
        got_tb.is_empty(),
        "topic isolation BROKE: epoch B's tx subscription sees epoch A's message: {got_tb:?}"
    );
    assert_eq!(
        bus.get(&ca).map(Vec::as_slice).unwrap_or(&[]),
        &["proposal#1".to_string()],
        "same-topic delivery must keep working within one epoch"
    );
    // Message kinds stay separated within one epoch too.
    let consensus_inbox = bus.get(&ca).cloned().unwrap_or_default();
    assert!(
        !consensus_inbox.iter().any(|m| m.starts_with("tx:")),
        "topic isolation BROKE: tx gossip visible on the consensus topic"
    );
}

// ==================== Test 5: default/empty epoch is well-formed ====================

#[test]
fn default_epoch_is_well_formed_and_distinct_from_any_real_epoch() {
    let d = EpochTag::default();
    assert!(
        !d.as_str().is_empty(),
        "default-epoch isolation BROKE: empty tag produces degenerate names"
    );

    // Pre-genesis publishes produce valid, non-colliding names.
    let heads: HashSet<String> = [0u32, 1, 7]
        .iter()
        .map(|&s| mirror_head_name(&d, s))
        .collect();
    assert_eq!(
        heads.len(),
        3,
        "default-epoch head names must not collide across shards"
    );
    for n in &heads {
        assert!(
            !n.is_empty() && !n.starts_with('_'),
            "ill-formed default head name: {n:?}"
        );
    }
    let headers: HashSet<String> = [1u64, 2, 100]
        .iter()
        .map(|&h| mirror_header_name(&d, h))
        .collect();
    assert_eq!(
        headers.len(),
        3,
        "default-epoch header names must not collide across heights"
    );
    for h in (1u64..=8).map(|i| [i as u8; 32]) {
        let name = block_body_blob_name(&d, &h);
        assert!(
            !name.is_empty() && !name.starts_with('_'),
            "ill-formed default body name: {name:?}"
        );
    }

    // Switching from default to a real epoch changes EVERY name: no silent
    // aliasing between "no epoch yet" and a real chain.
    let real = epoch_a();
    assert_ne!(
        d, real,
        "precondition: default must differ from a real epoch tag"
    );
    for &shard in &[0u32, 1, 7] {
        assert_ne!(
            mirror_head_name(&d, shard),
            mirror_head_name(&real, shard),
            "default/real aliasing BROKE: head name identical for shard {shard}"
        );
        for &h in &[1u64, 2, 100] {
            assert_ne!(
                mirror_header_name(&d, h),
                mirror_header_name(&real, h),
                "default/real aliasing BROKE: header name identical at height {h}"
            );
            assert_ne!(
                mirror_header_index_name(&d, shard, h),
                mirror_header_index_name(&real, shard, h),
                "default/real aliasing BROKE: header-index name identical at {shard}/{h}"
            );
            assert_ne!(
                mirror_snapshot_name(&d, shard, h),
                mirror_snapshot_name(&real, shard, h),
                "default/real aliasing BROKE: snapshot name identical at {shard}/{h}"
            );
        }
    }
    for h in (0u8..8).map(|i| [i; 32]) {
        assert_ne!(
            block_body_blob_name(&d, &h),
            block_body_blob_name(&real, &h),
            "default/real aliasing BROKE: body name identical for block {}",
            hex::encode(h)
        );
    }
    assert_ne!(
        consensus_topic(d.as_str()),
        consensus_topic(real.as_str()),
        "default/real aliasing BROKE: consensus topic identical"
    );
    assert_ne!(
        tx_topic(d.as_str()),
        tx_topic(real.as_str()),
        "default/real aliasing BROKE: tx topic identical"
    );

    // And pre-genesis data round-trips under the default epoch but stays
    // invisible under the real one.
    let net = FakeEpochStore::default();
    let hash = [0x9du8; 32];
    net.put(
        BUCKET_STELLEREUM_BLOCKS,
        &block_body_blob_name(&d, &hash),
        b"default-body".to_vec(),
    );
    assert!(
        net.get(BUCKET_STELLEREUM_BLOCKS, &block_body_blob_name(&d, &hash))
            .is_some(),
        "default-epoch publish must be readable under the default epoch"
    );
    assert!(
        net.get(
            BUCKET_STELLEREUM_BLOCKS,
            &block_body_blob_name(&real, &hash)
        )
        .is_none(),
        "default/real aliasing BROKE: default-epoch body visible under the real epoch"
    );
}
