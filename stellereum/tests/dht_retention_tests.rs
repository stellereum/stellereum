//! DHT retention: the kv.json growth driver and its bound.
//!
//! Live measurement: ~1MB/min growth, 99.6% of keys `stell_headers/*` and
//! `stell_blocks/*` (three blob manifests per finalized height — one body plus
//! a header and a height→hash index — that never expired). At 42k+ heights
//! that is 127k+ kv entries / ~85MB, and serializing the whole map (~1.3s)
//! re-creates the OOM pressure (MemoryMax=2G) the persist path just stopped
//! paying per write.
//!
//! Retention is height-based: the publisher deletes its own publishes below
//! `finalized − KEEP` (`maybe_prune_retained`, planned by `plan_retained_prune`
//! as inspectable data — the same pattern as `PublishWrite`), and every
//! body/header blob carries a generous TTL so replicas and strays die in the
//! sweep. The head pointer and state snapshots stay forever.
//!
//! Like `retro_publish_tests.rs`, these are pure-logic tests: there is no live
//! DHT here, so a `FakeDht` models exactly the keyspace the publish/prune paths
//! touch (manifest keys `{bucket}:{name}` plus the per-hash kv index), and the
//! assertions are about the KEY SET — which is precisely what kv.json growth
//! is. Blob-byte execution (`delete_blob_local`) is covered by infnode's own
//! `retention_ttl_and_local_prune` test against a real `Node`.

use std::collections::HashSet;
use stellereum::network::{
    dht_blob_ttl_ms, parse_keep_blocks, plan_retained_prune, prune_batch, prune_below_exclusive,
    EpochTag, BUCKET_STELLEREUM_BLOCKS, BUCKET_STELLEREUM_HEAD, BUCKET_STELLEREUM_HEADERS,
    BUCKET_STELLEREUM_STATE, PREFIX_BLOCK_HASH, PREFIX_LATEST_HEIGHT, STELL_DHT_FOREVER_TTL_MS,
};

/// The DHT keyspace slice the chain publisher touches: blob manifests
/// (`{bucket}:{name}`) plus the small local kv indices `broadcast_block`
/// writes. Mirrors `Node::blob_manifest_key` naming.
#[derive(Default)]
struct FakeDht {
    manifests: HashSet<String>,
    kv: HashSet<String>,
}

impl FakeDht {
    fn mkey(bucket: &str, name: &str) -> String {
        format!("{bucket}:{name}")
    }

    /// Mirror of one finalized height's publishes: body + header + index
    /// manifests, the per-hash kv entry, and the (overwritten, one-per-shard)
    /// height pointer.
    fn publish_height(&mut self, epoch: &EpochTag, shard: u32, height: u64, hash_hex: &str) {
        self.manifests.insert(Self::mkey(
            BUCKET_STELLEREUM_BLOCKS,
            &format!("{}_blk_{hash_hex}", epoch.as_str()),
        ));
        self.manifests.insert(Self::mkey(
            BUCKET_STELLEREUM_HEADERS,
            &format!("{}_h_{height}", epoch.as_str()),
        ));
        self.manifests.insert(Self::mkey(
            BUCKET_STELLEREUM_HEADERS,
            &format!("{}_hi_{shard}_{height}", epoch.as_str()),
        ));
        self.kv.insert(format!("{PREFIX_BLOCK_HASH}{hash_hex}"));
        // Height pointer: overwritten in place, never grows.
        self.kv.retain(|k| !k.starts_with(PREFIX_LATEST_HEIGHT));
        self.kv.insert(format!("{PREFIX_LATEST_HEIGHT}{shard}"));
    }

    fn publish_head(&mut self, epoch: &EpochTag, shard: u32) {
        self.manifests.insert(Self::mkey(
            BUCKET_STELLEREUM_HEAD,
            &format!("{}_shard_{shard}_head", epoch.as_str()),
        ));
    }

    fn publish_snapshot(&mut self, epoch: &EpochTag, shard: u32, height: u64) {
        self.manifests.insert(Self::mkey(
            BUCKET_STELLEREUM_STATE,
            &format!("{}_snap_{shard}_{height}", epoch.as_str()),
        ));
    }

    /// Mirror of `maybe_prune_retained`'s execution: apply prune plans for a
    /// batch of heights. Returns manifests remaining.
    fn apply_prune_batch(
        &mut self,
        epoch: &EpochTag,
        shard: u32,
        heights: &[u64],
        hash_of: &dyn Fn(u64) -> Option<String>,
    ) {
        for h in heights {
            let plan = plan_retained_prune(epoch, shard, *h, hash_of(*h).as_deref());
            for (bucket, name) in &plan.blobs {
                self.manifests.remove(&Self::mkey(bucket, name));
            }
            for k in &plan.kv {
                self.kv.remove(k);
            }
        }
    }

    fn stell_entry_count(&self) -> usize {
        self.manifests
            .iter()
            .filter(|k| k.contains("stell_"))
            .count()
            + self.kv.len()
    }
}

fn hash_hex_for(height: u64) -> String {
    format!("{:064x}", height.wrapping_mul(0x9E3779B97F4A7C15))
}

#[test]
fn steady_state_is_bounded_by_keep_not_by_chain_length() {
    // Live shape: KEEP=8000, chain far beyond it.
    let keep = parse_keep_blocks(Some("8000".into()));
    let epoch = EpochTag::from_genesis(&[0x11u8; 32]);
    let shard = 0u32;
    let mut dht = FakeDht::default();
    let mut cursor = 0u64;

    // Publish 42_000 heights the way the finalize path does (body + header +
    // index every height, head every height, snapshot every 100), pruning as
    // `maybe_prune_retained` would after each header publish.
    for h in 1..=42_000u64 {
        let hh = hash_hex_for(h);
        dht.publish_height(&epoch, shard, h, &hh);
        dht.publish_head(&epoch, shard);
        if h % 100 == 0 {
            dht.publish_snapshot(&epoch, shard, h);
        }
        let bound = prune_below_exclusive(h, keep);
        if bound > cursor {
            let (batch, next) = prune_batch(cursor, bound, 512);
            dht.apply_prune_batch(&epoch, shard, &batch, &|x| Some(hash_hex_for(x)));
            cursor = next;
        }
    }

    // Everything below finalized−KEEP is gone; the window, the head and the
    // snapshots remain. 3 manifests/height in the window + snapshots (1/100
    // heights, forever) + head + height pointer.
    let remaining_manifests = dht.manifests.len();
    let window = 8000usize * 3;
    let snapshots = 420usize;
    let head = 1usize;
    assert!(
        remaining_manifests <= window + snapshots + head,
        "steady state bounded: {remaining_manifests} manifests (window {window} + snapshots {snapshots} + head)"
    );
    assert!(
        remaining_manifests >= window,
        "the KEEP window itself is intact: {remaining_manifests}"
    );
    // No height pointer or per-hash kv leak: exactly one height key, and no
    // `stell:block:` entry below the window.
    let height_keys: Vec<_> = dht
        .kv
        .iter()
        .filter(|k| k.starts_with(PREFIX_LATEST_HEIGHT))
        .collect();
    assert_eq!(height_keys.len(), 1, "one height pointer per shard");
    assert!(
        dht.kv
            .iter()
            .filter(|k| k.starts_with(PREFIX_BLOCK_HASH))
            .count()
            <= 8000,
        "per-hash kv entries bounded by the window too"
    );
    // Sanity against the pre-fix behaviour: without pruning this would be
    // 42_000 × 3 manifests + 42_000 per-hash kv entries ≈ 168k and growing.
    // Steady state is ~24k window manifests + ~8k window kv + 420 snapshots +
    // head/height pointer ≈ 32.5k entries (≈22MB at ~670B/entry), bounded.
    assert!(dht.stell_entry_count() < 35_000, "bounded, not 127k+");
}

#[test]
fn prune_never_touches_head_snapshot_or_height_pointer() {
    let epoch = EpochTag::from_genesis(&[0xABu8; 32]);
    // Sweep every height of a small chain through the planner, including the
    // no-index fallback (hash unknown → TTL backstop owns the body).
    for h in 1..=500u64 {
        for with_hash in [true, false] {
            let plan =
                plan_retained_prune(&epoch, 0, h, with_hash.then(|| hash_hex_for(h)).as_deref());
            for (_, name) in &plan.blobs {
                assert!(!name.contains("_head"), "head pointer forever (h={h})");
                assert!(!name.contains("_snap_"), "snapshots forever (h={h})");
            }
            for k in &plan.kv {
                assert!(
                    !k.starts_with(PREFIX_LATEST_HEIGHT),
                    "height pointer stays (h={h})"
                );
            }
        }
    }
}

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn ttl_backstop_covers_what_height_prune_cannot() {
    // The window TTL is generous (prune wins on any live chain) but finite, so
    // the sweep still collects: replica copies on peers, pre-index heights
    // whose hash is unknown, offline-node leftovers.
    let ttl = dht_blob_ttl_ms(8000);
    assert!(ttl < STELL_DHT_FOREVER_TTL_MS, "window blobs DO expire");
    assert!(ttl <= 30 * 24 * 3600 * 1000, "clamped so expiry is real");
    assert!(
        ttl >= 7 * 24 * 3600 * 1000,
        "generous enough that prune wins first"
    );
    // Head/snapshot TTL is effectively forever and survives every sweep.
    assert!(STELL_DHT_FOREVER_TTL_MS > 30 * 24 * 3600 * 1000);
}
