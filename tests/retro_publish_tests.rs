//! Retro-publish: making bodies that were finalized long ago fetchable again.
//!
//! The live-stand failure these tests pin down: a node 1007 blocks behind asked
//! the network for its history and `collect_missing_blocks` aborted with
//! `block sync: missing block <hash>`. Nothing was wrong with the walk. The body
//! simply was not on the DHT, because the only code that ever puts a body there
//! is `P2pNetworkAdapter::broadcast_block`, which runs at the instant of
//! finalization. Every block finalized by an earlier run — or before this
//! publishing existed — lives only in that node's local disk store, so a fresh
//! or lagging node has no way to ever fetch it and the catch-up is impossible by
//! construction, however far ahead the advertised head is.
//!
//! `retro_publish_block` / `retro_publish_block_by_hash` / `retro_publish_blocks`
//! push that history back out after the fact, writing ONLY the body.
//!
//! ## Why these are pure-logic tests
//!
//! `P2pNetworkAdapter` holds an `Arc<infnode::node::Node>`, and `Node::new` opens
//! a sled database and binds a libp2p listener, so the adapter CANNOT be
//! constructed in a unit test — there is no DHT to publish into. The publish is
//! therefore expressed as DATA — a `PublishWrite` plan from
//! `plan_block_body_publish` — and the bounded-chunking / failure-accounting logic
//! is extracted into a free helper, `retro_publish_chunk`, that takes the
//! transport as a caller-supplied closure. `P2pNetworkAdapter::retro_publish_blocks`
//! is a thin wrapper that builds the same plan and hands that same helper the
//! real DHT. These tests drive those EXACT two items against a `FakeNet` that
//! mirrors `store_blob` / `fetch_block` / `get_latest_shard_height`, so the
//! behaviour under test is the behaviour the live path has rather than a
//! re-implementation of it — in particular the bound cannot drift between the
//! test and the method, and the "writes no head pointer" claim is checked against
//! the plan's actual contents instead of against a comment.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use stellereum::network::{
    block_body_blob_name, plan_block_body_publish, plan_block_body_publish_bytes,
    retro_publish_chunk, EpochTag, PublishWrite, RetroPublishReport, BUCKET_STELLEREUM_BLOCKS,
    PREFIX_BLOCK_HASH, PREFIX_LATEST_HEIGHT,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

/// A stand-in for the DHT: what `store_blob` would keep and what `get_local_kv`
/// would return. Only the surface a body publish touches is modelled, and each
/// method mirrors its network.rs counterpart closely enough that the assertions
/// mean something. Interior mutability keeps the fake borrowable from inside the
/// `async move` block a publish closure owns.
#[derive(Default)]
struct FakeNet {
    /// (bucket, name) -> bytes, like the blob store.
    blobs: RefCell<HashMap<(String, String), Vec<u8>>>,
    /// Local DHT KV. `get_latest_shard_height` reads ONLY from here.
    kv: RefCell<HashMap<String, String>>,
}

impl FakeNet {
    /// Mirror of `P2pNetworkAdapter::apply_publish_plan`.
    ///
    /// `stored == 0` stands for infnode reporting that the blob reached neither
    /// local storage nor a replica — the condition under which the body exists
    /// on nobody's disk, which is exactly what this feature exists to repair.
    async fn apply(
        &self,
        writes: &[PublishWrite],
        stored: &dyn Fn(&PublishWrite) -> usize,
    ) -> Result<(), String> {
        for w in writes {
            if stored(w) == 0 {
                return Err(format!(
                    "block body {}/{} reached no local chunk and no replica",
                    w.bucket, w.name
                ));
            }
            self.blobs
                .borrow_mut()
                .insert((w.bucket.to_string(), w.name.clone()), w.bytes.clone());
            for (k, v) in &w.kv {
                self.kv.borrow_mut().insert(k.clone(), v.clone());
            }
        }
        Ok(())
    }

    /// Mirror of `P2pNetworkAdapter::fetch_block`: same bucket, same name, same
    /// decode. A body published under any other convention is invisible here —
    /// which is the failure the bucket/name assertion guards.
    fn fetch_block(&self, block_hash: &[u8; 32]) -> Option<Block> {
        // Must use the SAME name helper the writer uses. Keying this off the bare
        // hash is precisely the split that made a published body unfetchable.
        let name = block_body_blob_name(&EpochTag::default(), block_hash);
        let blobs = self.blobs.borrow();
        let bytes = blobs.get(&(BUCKET_STELLEREUM_BLOCKS.to_string(), name))?;
        bincode::deserialize(bytes).ok()
    }

    /// Mirror of `P2pNetworkAdapter::get_latest_shard_height`: read
    /// `stell:height:<shard>` out of local KV and parse "<height>:<hash>".
    fn latest_shard_height(&self, shard_id: u32) -> Option<(u64, [u8; 32])> {
        let key = format!("{}{}", PREFIX_LATEST_HEIGHT, shard_id);
        let val = self.kv.borrow().get(&key)?.clone();
        let parts: Vec<&str> = val.split(':').collect();
        if parts.len() == 2 {
            let height = parts[0].parse::<u64>().ok()?;
            let raw = hex::decode(parts[1]).ok()?;
            if raw.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&raw);
                return Some((height, hash));
            }
        }
        None
    }
}

/// One bounded pass over `iter`, publishing bodies into `net`.
///
/// This is the publish step `P2pNetworkAdapter::retro_publish_blocks` performs,
/// rebuilt against `FakeNet`. The closure is handed to `retro_publish_chunk`
/// INLINE — as the live method does, so its argument type is inferred from the
/// iterator instead of being erased behind a `dyn` — which means the chunking,
/// the bound and the failure accounting under test are the production ones.
async fn publish_pass<'a, I>(
    iter: &mut I,
    max: usize,
    net: &'a FakeNet,
    stored: &'a dyn Fn(&PublishWrite) -> usize,
) -> RetroPublishReport
where
    I: Iterator<Item = &'a Block>,
{
    let mut iter = iter;
    retro_publish_chunk(&mut iter, max, |b| async move {
        match plan_block_body_publish(&EpochTag::default(), b) {
            Ok(writes) => net.apply(&writes, stored).await,
            Err(e) => Err(e),
        }
    })
    .await
}

/// Every chunk reached storage: the healthy case.
fn all_stored(_: &PublishWrite) -> usize {
    1
}

/// No chunk reached anywhere: the total-failure case.
fn none_stored(_: &PublishWrite) -> usize {
    0
}

/// A chain of `n` properly-signed blocks on the masterchain shard.
fn chain(n: u64) -> Vec<Block> {
    let sk = SigningKey::generate(&mut OsRng);
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            // Distinct per height, so every block really has its own hash and
            // the name assertions cannot pass by coincidence.
            state_root: [h as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&sk);
        prev = b.compute_hash();
        out.push(b);
    }
    out
}

/// A body published by hash is retrievable by `fetch_block`, byte for byte.
///
/// This is the whole point of the feature: without it a node 1000 blocks behind
/// reaches the `prev_hash` walk, asks for a body nobody ever put on the DHT, and
/// dies with `block sync: missing block`.
#[tokio::test]
async fn retro_published_body_is_retrievable_by_fetch_block() {
    let blocks = chain(3);
    let net = FakeNet::default();

    for b in &blocks {
        // The single-block method applies exactly this plan.
        net.apply(
            &plan_block_body_publish(&EpochTag::default(), b).unwrap(),
            &all_stored,
        )
        .await
        .unwrap();
    }

    for b in &blocks {
        let hash = b.compute_hash();
        let got = net.fetch_block(&hash).unwrap_or_else(|| {
            panic!(
                "fetch_block must find a retro-published body: {}",
                hex::encode(hash)
            )
        });

        // Identical bytes. `Block` has no `PartialEq` and does not need one: the
        // hash commits to every field, so an equal hash is an equal block — and
        // the field-by-field checks below keep that honest.
        let sent = bincode::serialize(b).unwrap();
        let read_back = bincode::serialize(&got).unwrap();
        assert_eq!(
            hex::encode(&sent),
            hex::encode(&read_back),
            "the body must round-trip through the wire bytes unchanged"
        );
        assert_eq!(
            got.compute_hash(),
            hash,
            "a round-tripped body re-hashes to its own key"
        );
        assert_eq!(got.height, b.height);
        assert_eq!(got.shard_id, b.shard_id);
        assert_eq!(got.state_root, b.state_root);
        assert_eq!(got.prev_hash, b.prev_hash);
        assert_eq!(got.timestamp, b.timestamp);
        assert_eq!(got.proposer, b.proposer);
        assert_eq!(got.validator_signatures, b.validator_signatures);
        assert!(
            got.verify_proposer_signature(),
            "the body survived the round trip intact"
        );
    }
}

/// The publish uses the same bucket + name as `broadcast_block`, so it is
/// discoverable by the very code path that could not find it before.
///
/// `fetch_block` looks a body up as
/// `fetch_blob(BUCKET_STELLEREUM_BLOCKS, hex::encode(hash))`. If either half of
/// that convention drifts, a retro-published body lands in a slot nobody reads
/// and the original `block sync: missing block` failure returns wearing a new
/// hat — so pin the convention here instead of trusting a comment to hold it.
#[test]
fn retro_publish_uses_the_fetch_block_bucket_and_name() {
    let blocks = chain(2);

    for b in &blocks {
        let hash = b.compute_hash();
        let writes = plan_block_body_publish(&EpochTag::default(), b).unwrap();
        assert_eq!(writes.len(), 1, "a body publish is exactly one blob write");

        let w = &writes[0];
        assert_eq!(
            w.bucket, BUCKET_STELLEREUM_BLOCKS,
            "same bucket as fetch_block"
        );
        // The name is epoch-scoped, and this is the regression that matters: the
        // writer and the reader must agree. A previous split had `broadcast_block`
        // writing an epoch-scoped name while the retro-publish path wrote the bare
        // hash, so the same block landed in two different slots and neither side
        // could find the other's body.
        assert_eq!(
            w.name,
            format!("genesis_blk_{}", hex::encode(hash)),
            "the planned name must be the epoch-scoped one fetch_block looks up"
        );
        assert_eq!(
            w.name,
            block_body_blob_name(&EpochTag::default(), &hash),
            "the name helper and the on-the-wire name must be the same string"
        );
        assert_eq!(
            w.bytes,
            bincode::serialize(b).unwrap(),
            "the same bincode encoding broadcast_block writes"
        );

        // The hash-addressed entry point plans the identical write, so a caller
        // driving it from a disk scan gets the same slot `fetch_block` reads.
        let by_hash = plan_block_body_publish_bytes(&EpochTag::default(), hash, &w.bytes).unwrap();
        assert_eq!(by_hash, *w, "publishing by hash must plan the same write");
    }
}

/// THE SAFETY PROPERTY: a retro-publish must not move the advertised head.
///
/// `broadcast_block` does two things beyond storing the body: it writes
/// `stell:height:<shard>` (the head pointer every peer reads) and
/// `stell:block:<hash>` (the block-hash KV index). Replaying either from a node
/// that is behind would advertise a height from the middle of its own stale
/// chain, so every peer — including the node trying to catch up — would watch the
/// network's head rewind and lose the very tip it is trying to reach. The body is
/// what the lagging peer is missing; the pointer is not.
#[tokio::test]
async fn retro_publish_never_moves_the_advertised_head() {
    let blocks = chain(5);
    let net = FakeNet::default();

    // Before anything, this node has advertised nothing.
    assert_eq!(
        net.latest_shard_height(MASTERCHAIN_SHARD),
        None,
        "precondition: no head pointer has been written yet"
    );

    // Retro-publish the recent history: single publishes, then a batched pass.
    for b in &blocks {
        net.apply(
            &plan_block_body_publish(&EpochTag::default(), b).unwrap(),
            &all_stored,
        )
        .await
        .unwrap();
    }
    let mut it = blocks.iter();
    let report = publish_pass(&mut it, 3, &net, &all_stored).await;
    assert_eq!(report.published, 3, "the batch did publish");

    // The bodies are out there...
    for b in &blocks {
        assert!(
            net.fetch_block(&b.compute_hash()).is_some(),
            "height {} body must be published",
            b.height
        );
    }
    // ...and the head pointer is exactly where it was: untouched.
    assert_eq!(
        net.latest_shard_height(MASTERCHAIN_SHARD),
        None,
        "a retro-publish must not write the shard height pointer"
    );
    let keys: Vec<String> = net.kv.borrow().keys().cloned().collect();
    assert!(
        keys.is_empty(),
        "a retro-publish must write no local KV at all, found: {keys:?}"
    );
    assert!(
        !keys
            .iter()
            .any(|k| k.starts_with(PREFIX_LATEST_HEIGHT) || k.starts_with(PREFIX_BLOCK_HASH)),
        "neither the head pointer nor the block-hash index may be written by a re-publish"
    );

    // Control: the model is not vacuously reporting "None". Write the head
    // pointer the way `broadcast_block` does and the very same reader now reports
    // it — which is precisely the rewind this design refuses to cause.
    let head = blocks.last().unwrap();
    let head_hash = head.compute_hash();
    net.kv.borrow_mut().insert(
        format!("{}{}", PREFIX_LATEST_HEIGHT, head.shard_id),
        format!("{}:{}", head.height, hex::encode(head_hash)),
    );
    assert_eq!(
        net.latest_shard_height(head.shard_id),
        Some((head.height, head_hash)),
        "the reader is sensitive to the head key, so 'still None' is a real result"
    );
}

/// A STALE node's re-publish must not lower a head that is already higher.
///
/// The regression this guards is the one the safety property is really about: a
/// node 1000 blocks behind re-publishing its own history writes
/// `stell:height:<shard>` = a height from the middle of its chain, and every
/// peer — the catching node included — then believes the network's head is a
/// thousand blocks lower than it is. The pointer must come out byte-identical
/// after a pass over stale blocks.
#[tokio::test]
async fn a_stale_nodes_republish_leaves_a_higher_head_exactly_where_it_is() {
    let stale = chain(10);
    let net = FakeNet::default();

    // The network's real head, at height 5000 — published by a node that is
    // ahead of us. This node is the stale one.
    let real_height = 5_000u64;
    let real_hash = [0x77u8; 32];
    net.kv.borrow_mut().insert(
        format!("{}{}", PREFIX_LATEST_HEIGHT, MASTERCHAIN_SHARD),
        format!("{}:{}", real_height, hex::encode(real_hash)),
    );

    // This node retro-publishes everything it has, repeatedly, in bounded
    // passes, exactly as the periodic job does.
    let mut it = stale.iter();
    loop {
        let report = publish_pass(&mut it, 4, &net, &all_stored).await;
        assert_eq!(report.failed, 0);
        if !report.maybe_more {
            break;
        }
    }
    assert_eq!(
        net.blobs.borrow().len(),
        10,
        "all ten stale bodies went out"
    );

    assert_eq!(
        net.latest_shard_height(MASTERCHAIN_SHARD),
        Some((real_height, real_hash)),
        "the advertised head must be untouched by a re-publish of older blocks"
    );
    // And the bodies really are fetchable, which is the whole point of doing it.
    for b in &stale {
        assert!(net.fetch_block(&b.compute_hash()).is_some());
    }
}

/// The pass is bounded: offer more blocks than the bound and it publishes
/// exactly the bound, never more, and reports that more may remain so the caller
/// schedules another pass.
#[tokio::test]
async fn batch_publish_respects_its_bound() {
    let blocks = chain(10);
    let net = FakeNet::default();

    let mut it = blocks.iter();
    let first = publish_pass(&mut it, 4, &net, &all_stored).await;

    assert_eq!(first.attempted, 4, "exactly the bound is attempted");
    assert_eq!(first.published, 4, "exactly the bound is published");
    assert_eq!(first.failed, 0);
    assert!(
        first.maybe_more,
        "a full window means the caller should come back"
    );
    assert_eq!(
        net.blobs.borrow().len(),
        4,
        "and no more bodies reached the network than the bound allows"
    );

    // The next pass continues where the first stopped, and the whole chain ends
    // up covered, so a lagging peer's backwards walk finds every link.
    let second = publish_pass(&mut it, 4, &net, &all_stored).await;
    assert_eq!(second.attempted, 4);
    assert_eq!(second.published, 4);
    let third = publish_pass(&mut it, 4, &net, &all_stored).await;
    assert_eq!(third.attempted, 2, "the tail is the remainder");
    assert_eq!(third.published, 2);
    assert!(
        !third.maybe_more,
        "a short pass means the iterator is drained"
    );

    assert_eq!(net.blobs.borrow().len(), 10, "every block got published");
    for b in &blocks {
        assert!(
            net.fetch_block(&b.compute_hash()).is_some(),
            "height {}",
            b.height
        );
    }

    // A bound larger than the input is not a licence to invent work.
    let mut over_it = blocks.iter();
    let over = publish_pass(&mut over_it, 1_000, &net, &all_stored).await;
    assert_eq!(over.attempted, 10);
    assert_eq!(over.published, 10);
    assert!(!over.maybe_more);

    // A zero bound is a no-op pass and reports "no more", so a caller looping on
    // `maybe_more` can never spin.
    let mut none_it = blocks.iter();
    let zero = publish_pass(&mut none_it, 0, &net, &all_stored).await;
    assert_eq!(zero, RetroPublishReport::default());
    assert!(!zero.maybe_more);
    assert_eq!(zero.attempted, 0);
}

/// One unfetchable body in the batch does not stop the rest, and the failure is
/// reported rather than swallowed.
///
/// The unfetchable case is the real one: a node in pruning mode whose local block
/// store no longer holds a body, or a blob the DHT refused to accept. If one of
/// those aborted the pass then the N-1 bodies that would have unblock the
/// lagging peer would be lost with it — and the next pass would meet the same
/// block first and abort again, forever.
#[tokio::test]
async fn one_unfetchable_block_does_not_stop_the_batch_and_is_reported() {
    let blocks = chain(6);
    let net = FakeNet::default();

    // Heights 2 and 5 are on nobody's disk. `stored == 0` is how FakeNet models
    // that, identified by recovering the height from the body about to publish.
    let absent: HashSet<u64> = [2u64, 5].into_iter().collect();
    let two_missing = |w: &PublishWrite| -> usize {
        match bincode::deserialize::<Block>(&w.bytes) {
            Ok(b) if absent.contains(&b.height) => 0,
            _ => 1,
        }
    };

    let mut it = blocks.iter();
    let report = publish_pass(&mut it, 6, &net, &two_missing).await;

    assert_eq!(
        report.attempted, 6,
        "every block in the window was attempted"
    );
    assert_eq!(
        report.published, 4,
        "the four retrievable bodies still went out"
    );
    assert_eq!(
        report.failed, 2,
        "and the two that could not be are counted, not hidden"
    );
    assert!(report.maybe_more, "the window filled, so more may remain");
    assert_eq!(
        report.published + report.failed,
        report.attempted,
        "every attempt is accounted for"
    );
    let first = report
        .first_error
        .clone()
        .expect("a failure must carry its reason, not just its count");
    assert!(
        first.contains("reached no local chunk and no replica"),
        "the reason must say what went wrong, got: {first}"
    );

    // The survivors are genuinely retrievable, so the peer's walk can proceed
    // past the gap this pass could not fill.
    for b in &blocks {
        assert_eq!(
            net.fetch_block(&b.compute_hash()).is_some(),
            !absent.contains(&b.height),
            "height {} presence",
            b.height
        );
    }

    // A wholly broken transport fails every item and reports every failure: the
    // pass must not look successful merely because it did not panic.
    let mut broken_it = blocks.iter();
    let broken = publish_pass(&mut broken_it, 6, &net, &none_stored).await;
    assert_eq!(broken.attempted, 6);
    assert_eq!(broken.published, 0);
    assert_eq!(broken.failed, 6, "six failures, none hidden");
    assert!(broken.first_error.is_some());
    assert_eq!(broken.published + broken.failed, broken.attempted);

    // And a later failing pass does not retract what an earlier one published.
    assert_eq!(net.blobs.borrow().len(), 4);
}

/// A body that does not hash to the address it is published under is refused —
/// and refusing it does not stop the bodies around it.
///
/// The DHT name IS the hash, so filing a body under a hash it does not compute to
/// permanently poisons that slot: `fetch_block` hands it to whoever asked for
/// that hash as if it were their block, and their `prev_hash` walk then follows a
/// chain that does not exist. A wrong body is therefore worse than an absent one,
/// and it has to be reported rather than quietly stored.
#[tokio::test]
async fn a_body_that_does_not_hash_to_its_address_is_refused_and_reported() {
    let blocks = chain(4);
    let net = FakeNet::default();
    let bad_height = 3u64;
    let bogus = [0xABu8; 32];

    let mut it = blocks.iter();
    let report = retro_publish_chunk(&mut it, 4, |b| {
        let net = &net;
        async move {
            let bytes = bincode::serialize(b).unwrap();
            // Height 3 is addressed as a hash it does not compute to, modelling
            // a disk scan that hands back the wrong body.
            let address = if b.height == bad_height {
                bogus
            } else {
                b.compute_hash()
            };
            match plan_block_body_publish_bytes(&EpochTag::default(), address, &bytes) {
                Ok(write) => {
                    let writes = [write];
                    net.apply(&writes, &all_stored).await
                }
                Err(e) => Err(e),
            }
        }
    })
    .await;

    assert_eq!(report.attempted, 4);
    assert_eq!(
        report.published, 3,
        "the three honest bodies still went out"
    );
    assert_eq!(
        report.failed, 1,
        "the mismatched body is counted, not hidden"
    );
    let first = report
        .first_error
        .clone()
        .expect("a reason must be reported");
    assert!(
        first.contains("hashes to") && first.contains("addressed as"),
        "the reason must name the mismatch, got: {first}"
    );

    // Nothing was written under the bogus address, and the honest bodies are
    // retrievable by their own hashes.
    let blobs = net.blobs.borrow();
    assert_eq!(blobs.len(), 3, "no slot for the rejected body");
    assert!(
        !blobs.contains_key(&(BUCKET_STELLEREUM_BLOCKS.to_string(), hex::encode(bogus))),
        "a body that fails its own hash check must never reach the network"
    );
    drop(blobs);
    for b in &blocks {
        if b.height == bad_height {
            assert!(net.fetch_block(&b.compute_hash()).is_none());
        } else {
            assert!(
                net.fetch_block(&b.compute_hash()).is_some(),
                "height {}",
                b.height
            );
        }
    }

    // Garbage that is not a block at all is refused the same way, with no panic.
    let err = plan_block_body_publish_bytes(&EpochTag::default(), [1u8; 32], &[0xff, 0x00, 0x7f])
        .unwrap_err();
    assert!(
        err.contains("deserialize failed"),
        "undecodable bytes must be refused, got: {err}"
    );
}
